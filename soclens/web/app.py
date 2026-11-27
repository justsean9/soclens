"""Starlette ASGI application factory for the standalone SOCLens Web UI."""

from __future__ import annotations

import contextlib
import json
import mimetypes
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import anyio
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from soclens import __version__
from soclens.tui.logging_bridge import LOG_LEVEL_OPTIONS, LOG_SOURCE_OPTIONS, source_matches_filter
from soclens.web.api_admin import ADMIN_ROUTES
from soclens.web.api_ai import AI_ROUTES
from soclens.web.api_settings import SETTINGS_ROUTES
from soclens.web.api_workbenches import WORKBENCH_ROUTES
from soclens.web.security import (
    SecurityMiddleware,
    WebSession,
    build_session_cookie_header,
    redact_web_payload,
)
from soclens.web.sse import create_events_stream_response
from soclens.web.state import WebRuntimeState

STATIC_DIR = Path(__file__).resolve().parent / "static"
_IMAGE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]+$")


async def _parse_json_body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"Invalid JSON payload: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("JSON request body must be an object.")
    return parsed


async def index_endpoint(request: Request) -> Response:
    index_path = (STATIC_DIR / "index.html").resolve()
    if not index_path.is_file():
        return HTMLResponse("<h1>SOCLens Web UI assets missing</h1>", status_code=404)
    return FileResponse(
        index_path,
        media_type="text/html; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


async def static_file_endpoint(request: Request) -> Response:
    raw_path = str(request.path_params.get("path") or "")
    decoded = unquote(raw_path)
    if (
        not decoded
        or "\x00" in decoded
        or "\\" in decoded
        or decoded.startswith("/")
        or ".." in Path(decoded).parts
    ):
        return JSONResponse({"ok": False, "error": "Invalid static asset path."}, status_code=403)

    static_root = STATIC_DIR.resolve()
    candidate = (static_root / decoded).resolve()
    if not candidate.is_relative_to(static_root):
        return JSONResponse({"ok": False, "error": "Path traversal denied."}, status_code=403)
    if not candidate.is_file():
        return JSONResponse({"ok": False, "error": "Static asset not found."}, status_code=404)

    media_type, _ = mimetypes.guess_type(str(candidate))
    if candidate.suffix.lower() == ".js":
        media_type = "application/javascript; charset=utf-8"
    elif candidate.suffix.lower() == ".css":
        media_type = "text/css; charset=utf-8"
    elif candidate.suffix.lower() == ".html":
        media_type = "text/html; charset=utf-8"
    elif media_type is None:
        media_type = "application/octet-stream"

    return FileResponse(
        candidate,
        media_type=media_type,
        headers={"Cache-Control": "no-store"},
    )


async def auth_exchange_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    token = str(body.get("token") or "").strip()
    session = runtime.auth_manager.exchange_token(token)
    if session is None:
        return JSONResponse(
            {"ok": False, "error": "Invalid or missing bootstrap token."},
            status_code=401,
            headers={"Cache-Control": "no-store"},
        )

    response = JSONResponse(
        {
            "ok": True,
            "csrf_token": session.csrf_token,
            "admin_enabled": runtime.admin_enabled,
            "version": __version__,
        },
        status_code=200,
        headers={"Cache-Control": "no-store"},
    )
    response.headers.append("Set-Cookie", build_session_cookie_header(session.session_id))
    return response


async def auth_session_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    session: WebSession | None = getattr(request.state, "web_session", None)
    if session is None:
        return JSONResponse({"ok": False, "error": "No active session."}, status_code=401)
    return JSONResponse(
        {
            "ok": True,
            "csrf_token": session.csrf_token,
            "admin_enabled": runtime.admin_enabled,
            "version": __version__,
        },
        headers={"Cache-Control": "no-store"},
    )


async def status_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    payload = await anyio.to_thread.run_sync(runtime.get_status_payload)
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


async def shutdown_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    await anyio.to_thread.run_sync(runtime.request_shutdown)
    return JSONResponse(
        {"ok": True, "shutting_down": True},
        status_code=200,
        headers={"Cache-Control": "no-store"},
    )


async def events_stream_endpoint(request: Request) -> Response:
    runtime: WebRuntimeState = request.app.state.runtime
    return create_events_stream_response(request, runtime)


async def alerts_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    qp = request.query_params
    source = str(qp.get("source") or "rf_alerts_24h").strip()
    q = str(qp.get("q") or "").strip()

    def _run() -> dict[str, Any]:
        entry = runtime.alert_cache.get(source)
        items: list[dict[str, Any]] = []
        fetched_at: float | None = None
        age_label = "not cached"
        meta: dict[str, Any] = {}
        if entry is not None:
            items = [dict(x) for x in entry.items]
            fetched_at = entry.fetched_at
            age_label = entry.age_label()
            meta = dict(entry.meta)
        if q:
            q_low = q.lower()
            filtered = [it for it in items if q_low in json.dumps(it, default=str).lower()]
            if not filtered:
                hist = runtime.storage.search_alerts_history(q, source=source or None, limit=100)
                filtered = hist
            items = filtered
        return dict(
            redact_web_payload(
                {
                    "ok": True,
                    "source": source,
                    "items": items,
                    "count": len(items),
                    "fetched_at": fetched_at,
                    "age_label": age_label,
                    "meta": meta,
                }
            )
        )

    return JSONResponse(await anyio.to_thread.run_sync(_run))


async def alert_image_endpoint(request: Request) -> Response:
    runtime: WebRuntimeState = request.app.state.runtime
    image_key = str(request.path_params.get("image_key") or "").strip()
    if (
        not image_key
        or ".." in image_key
        or not _IMAGE_KEY_RE.fullmatch(image_key)
    ):
        return JSONResponse({"ok": False, "error": "Invalid image key."}, status_code=404)

    def _load() -> bytes | None:
        raw = runtime.alert_cache.get_image_bytes(image_key)
        if raw:
            return raw
        prep = runtime.alert_cache.get_prepared_image(image_key)
        if isinstance(prep, dict):
            b = prep.get("bytes") or prep.get("cropped_png")
            if isinstance(b, (bytes, bytearray)):
                return bytes(b)
        return None

    img_bytes = await anyio.to_thread.run_sync(_load)
    if not img_bytes:
        return JSONResponse({"ok": False, "error": "Alert image not found."}, status_code=404)

    return Response(
        content=img_bytes,
        status_code=200,
        media_type="image/png",
        headers={"Cache-Control": "private, no-store"},
    )


async def logs_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    qp = request.query_params
    source = str(qp.get("source") or "all").strip() or "all"
    level = str(qp.get("level") or "ALL").strip().upper() or "ALL"
    q = str(qp.get("q") or "").strip().lower()
    try:
        limit = max(1, min(int(qp.get("limit") or 500), 2000))
    except ValueError:
        limit = 500

    def _run() -> dict[str, Any]:
        entries = runtime.log_store.snapshot()
        rows: list[dict[str, Any]] = []
        for entry in entries:
            if source != "all" and not source_matches_filter(entry.source, source):
                continue
            if level != "ALL" and entry.level != level:
                continue
            if q and q not in entry.message.lower() and q not in entry.logger_name.lower():
                continue
            rows.append(
                {
                    "timestamp": entry.timestamp,
                    "level": entry.level,
                    "source": entry.source,
                    "logger_name": entry.logger_name,
                    "message": entry.message,
                    "created_utc": entry.created_utc.isoformat() if entry.created_utc else None,
                }
            )
        total, warnings, errors = runtime.log_store.counts()
        return dict(
            redact_web_payload(
                {
                    "ok": True,
                    "entries": rows[-limit:],
                    "counts": {"total": total, "warning": warnings, "error": errors},
                    "sources": [list(opt) for opt in LOG_SOURCE_OPTIONS],
                    "levels": [list(opt) for opt in LOG_LEVEL_OPTIONS],
                }
            )
        )

    return JSONResponse(await anyio.to_thread.run_sync(_run))


async def logs_clear_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    await anyio.to_thread.run_sync(runtime.log_store.clear)
    return JSONResponse({"ok": True})


async def get_workspace_layout_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime

    def _run() -> dict[str, Any]:
        loaded = runtime.storage.load_workspace_layout(profile_name=runtime.web_layout_profile)
        return {"ok": True, **loaded, "profile_name": runtime.web_layout_profile}

    return JSONResponse(await anyio.to_thread.run_sync(_run))


async def post_workspace_layout_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    mode = str(body.get("mode") or "tiling").strip() or "tiling"
    state = body.get("state") if isinstance(body.get("state"), dict) else {}

    def _run() -> dict[str, Any]:
        saved = runtime.storage.save_workspace_layout(
            mode=mode,
            state=state,
            profile_name=runtime.web_layout_profile,
        )
        return {"ok": True, **saved, "profile_name": runtime.web_layout_profile}

    return JSONResponse(await anyio.to_thread.run_sync(_run))


def create_app(
    workspace_dir: Path | str | None = None,
    admin_enabled: bool = False,
    bootstrap_token: str | None = None,
    session_state: Any = None,
    *,
    dry_run: bool = False,
    bound_port: int | None = None,
) -> Starlette:
    """Create and configure the standalone SOCLens Starlette ASGI application."""
    runtime = WebRuntimeState(
        workspace_dir=workspace_dir,
        admin_enabled=admin_enabled,
        bootstrap_token=bootstrap_token,
        dry_run=dry_run,
        session_state=session_state,
    )

    @contextlib.asynccontextmanager
    async def _lifespan(app: Starlette) -> AsyncIterator[None]:
        try:
            yield
        finally:
            rt = getattr(getattr(app, "state", None), "runtime", None)
            if rt is not None:
                rt.cleanup()

    routes: list[Route] = [
        Route("/", index_endpoint, methods=["GET"]),
        Route("/static/{path:path}", static_file_endpoint, methods=["GET"]),
        Route("/api/auth/exchange", auth_exchange_endpoint, methods=["POST"]),
        Route("/api/auth/session", auth_session_endpoint, methods=["GET"]),
        Route("/api/status", status_endpoint, methods=["GET"]),
        Route("/api/shutdown", shutdown_endpoint, methods=["POST"]),
        Route("/api/events/stream", events_stream_endpoint, methods=["GET"]),
        Route("/api/alerts", alerts_endpoint, methods=["GET"]),
        Route("/api/alerts/image/{image_key:str}", alert_image_endpoint, methods=["GET"]),
        Route("/api/logs", logs_endpoint, methods=["GET"]),
        Route("/api/logs/clear", logs_clear_endpoint, methods=["POST"]),
        Route("/api/workspace/layout", get_workspace_layout_endpoint, methods=["GET"]),
        Route("/api/workspace/layout", post_workspace_layout_endpoint, methods=["POST"]),
        Route("/api/workspace-layout", get_workspace_layout_endpoint, methods=["GET"]),
        Route("/api/workspace-layout", post_workspace_layout_endpoint, methods=["POST"]),
        *SETTINGS_ROUTES,
        *AI_ROUTES,
        *WORKBENCH_ROUTES,
        *ADMIN_ROUTES,
    ]

    app = Starlette(
        debug=False,
        routes=routes,
        middleware=[
            Middleware(
                SecurityMiddleware,
                auth_manager=runtime.auth_manager,
                bound_port=bound_port,
            )
        ],
        lifespan=_lifespan,
    )
    app.state.runtime = runtime
    return app
