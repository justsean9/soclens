"""Admin-only (--admin) web endpoints for Dashboard, Watchlists, Brand Logos, Sigma, and Bundle."""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from soclens.bundler import create_bundle
from soclens.config import (
    format_ssl_verify_status,
    get_local_llm_config,
    get_proxy_summary,
    get_rf_token,
    get_sentinelone_config,
    get_splunk_config,
)
from soclens.logos.brand_sync import (
    analyze_brand_sync_issues,
    execute_domain_brand_sync,
    load_brand_sync_state,
    validate_domain_brand_sync,
)
from soclens.settings import get_settings_storage_info
from soclens.sigma import (
    SIGMA_PIPELINES,
    convert_sigma_rule,
    export_rules_to_splunk,
    load_rules,
    search_rules,
)
from soclens.splunk import SplunkValidator, parse_savedsearches_files
from soclens.tui.screens.dashboard import _API_SURFACES
from soclens.web.security import redact_web_payload
from soclens.web.state import WebRuntimeState


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


def _require_admin(runtime: WebRuntimeState) -> JSONResponse | None:
    if not runtime.admin_enabled:
        return JSONResponse(
            {"ok": False, "error": "Admin mode (--admin) is required for this endpoint."},
            status_code=403,
        )
    return None


async def admin_dashboard_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    denied = _require_admin(runtime)
    if denied is not None:
        return denied

    if request.method.upper() == "POST":
        try:
            body = await _parse_json_body(request)
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
        action = str(body.get("action") or "").strip()
        if action == "toggle_ssl":
            if not bool(body.get("double_confirmed")):
                return JSONResponse({"ok": False, "error": "Double confirmation required."}, status_code=400)
            insecure = bool(body.get("insecure", False))
            resolved = runtime.set_insecure_ssl(insecure)
            return JSONResponse({"ok": True, "verify_ssl": resolved})
        if action == "check_splunk":
            def _check_sp() -> dict[str, Any]:
                cfg = get_splunk_config(required=False)
                if not cfg.has_auth:
                    return {"ok": False, "error": "Splunk is not configured."}
                ok = SplunkValidator(
                    host=cfg.host,
                    token=cfg.token,
                    username=cfg.username,
                    password=cfg.password,
                    app=cfg.app,
                    verify_ssl=cfg.verify_ssl,
                ).check_connection()
                return {"ok": bool(ok)}
            return JSONResponse(await anyio.to_thread.run_sync(_check_sp))
        return JSONResponse({"ok": False, "error": f"Unknown dashboard action: {action}"}, status_code=400)

    def _collect() -> dict[str, Any]:
        err_log_path = runtime.workspace_dir / "logs" / "rf_api_errors.jsonl"
        errors: list[dict[str, Any]] = []
        if err_log_path.is_file():
            try:
                for line in err_log_path.read_text(encoding="utf-8").splitlines()[-200:]:
                    if line.strip():
                        errors.append(json.loads(line))
            except Exception:
                pass
        wh_dir = runtime.workspace_dir / "wheelhouse"
        wheel_count = len(list(wh_dir.glob("*.whl"))) if wh_dir.is_dir() else 0
        s1_cfg = get_sentinelone_config(required=False)
        sp_cfg = get_splunk_config(required=False)
        llm_cfg = get_local_llm_config()
        st_info = get_settings_storage_info()
        return redact_web_payload(
            {
                "ok": True,
                "diagnostics": {
                    "python_version": platform.python_version(),
                    "platform": platform.platform(),
                    "workspace_dir": str(runtime.workspace_dir),
                    "storage_dialect": runtime.storage.dialect,
                    "rf_configured": bool(get_rf_token(required=False)),
                    "splunk_configured": bool(sp_cfg.has_auth),
                    "sentinelone_configured": bool(s1_cfg.has_auth),
                    "llm_provider": llm_cfg.provider,
                    "llm_model": llm_cfg.model,
                    "ssl_status": format_ssl_verify_status(runtime.get_effective_verify_ssl()),
                    "proxy_summary": get_proxy_summary(),
                    "settings_path": str(st_info.get("path") or ""),
                    "wheelhouse_wheels": wheel_count,
                },
                "api_surfaces": [
                    {"family": f, "endpoint": e, "auth": a, "surface": s}
                    for f, e, a, s in _API_SURFACES
                ],
                "api_errors": list(reversed(errors)),
            }
        )

    return JSONResponse(await anyio.to_thread.run_sync(_collect))


async def admin_watchlists_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    denied = _require_admin(runtime)
    if denied is not None:
        return denied

    if request.method.upper() == "GET":
        list_id = str(request.query_params.get("list_id") or "").strip()

        def _get() -> tuple[dict[str, Any], int]:
            rf = runtime.get_rf_client()
            if rf is None:
                return {"ok": True, "configured": False, "lists": [], "entities": []}, 200
            try:
                if list_id:
                    entities = rf.get_watchlist_entities(list_id)
                    return {"ok": True, "configured": True, "list_id": list_id, "entities": redact_web_payload(entities)}, 200
                lists = rf.get_watchlists()
                return {"ok": True, "configured": True, "lists": redact_web_payload(lists)}, 200
            except Exception as exc:
                return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

        payload, status = await anyio.to_thread.run_sync(_get)
        return JSONResponse(payload, status_code=status)

    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    action = str(body.get("action") or "").strip()
    if not bool(body.get("double_confirmed")):
        return JSONResponse({"ok": False, "error": "Double confirmation is required for watchlist mutations."}, status_code=400)
    if runtime.dry_run:
        return JSONResponse({"ok": True, "dry_run": True, "action": action, "message": "Dry-run: watchlist mutation skipped."})

    def _post() -> tuple[dict[str, Any], int]:
        rf = runtime.get_rf_client()
        if rf is None:
            return {"ok": False, "error": "Recorded Future token is not configured."}, 400
        try:
            if action == "create_list":
                res = rf.create_list(str(body.get("name") or ""), str(body.get("list_type") or "entity"))
                return {"ok": True, "result": redact_web_payload(res)}, 200
            list_id = str(body.get("list_id") or "").strip()
            entity = str(body.get("entity") or "").strip()
            if not list_id or not entity:
                return {"ok": False, "error": "list_id and entity are required."}, 400
            if action == "add_entity":
                res = rf.add_entity(list_id, entity)
                return {"ok": True, "result": redact_web_payload(res)}, 200
            if action == "remove_entity":
                res = rf.remove_entity(list_id, entity)
                return {"ok": True, "result": redact_web_payload(res)}, 200
            return {"ok": False, "error": f"Unknown watchlist action: {action}"}, 400
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

    payload, status = await anyio.to_thread.run_sync(_post)
    return JSONResponse(payload, status_code=status)


async def admin_brand_logos_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    denied = _require_admin(runtime)
    if denied is not None:
        return denied

    if request.method.upper() == "GET":
        def _get() -> dict[str, Any]:
            state_path = runtime.workspace_dir / "brand_sync_state.json"
            state = load_brand_sync_state(state_path) if state_path.is_file() else {}
            report = analyze_brand_sync_issues(state=state)
            return redact_web_payload(
                {
                    "ok": True,
                    "state": state,
                    "issues": report.to_dict() if hasattr(report, "to_dict") else {},
                }
            )
        return JSONResponse(await anyio.to_thread.run_sync(_get))

    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    action = str(body.get("action") or "validate").strip()
    list_id = str(body.get("list_id") or "").strip()
    raw_domains = body.get("domains") or []
    domains = (
        [str(d).strip() for d in raw_domains if str(d).strip()]
        if isinstance(raw_domains, list)
        else [d.strip() for d in str(raw_domains).splitlines() if d.strip()]
    )

    if action == "sync" and not bool(body.get("double_confirmed")):
        return JSONResponse({"ok": False, "error": "Double confirmation required for brand logo sync."}, status_code=400)

    def _run() -> tuple[dict[str, Any], int]:
        rf = runtime.get_rf_client()
        if rf is None:
            return {"ok": False, "error": "Recorded Future token is not configured."}, 400
        try:
            if action == "sync":
                ok = execute_domain_brand_sync(
                    rf,
                    list_id,
                    domains,
                    dry_run=runtime.dry_run or bool(body.get("dry_run", False)),
                    workspace_dir=runtime.workspace_dir,
                )
                return {"ok": bool(ok), "action": action}, 200
            ok = validate_domain_brand_sync(
                rf,
                list_id,
                domains,
                workspace_dir=runtime.workspace_dir,
            )
            return {"ok": bool(ok), "action": "validate"}, 200
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def admin_sigma_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    denied = _require_admin(runtime)
    if denied is not None:
        return denied

    if request.method.upper() == "GET":
        q = str(request.query_params.get("q") or "").strip()
        refresh = str(request.query_params.get("refresh") or "").lower() in ("1", "true", "yes")

        def _get() -> tuple[dict[str, Any], int]:
            try:
                rf = runtime.get_rf_client() if refresh else None
                rules = load_rules(rf, refresh=refresh, cache_dir=runtime.workspace_dir)
                if q:
                    rules = search_rules(rules, q)
                return {
                    "ok": True,
                    "rules": redact_web_payload(rules[:200]),
                    "total": len(rules),
                    "pipelines": list(SIGMA_PIPELINES),
                }, 200
            except Exception as exc:
                return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

        payload, status = await anyio.to_thread.run_sync(_get)
        return JSONResponse(payload, status_code=status)

    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    action = str(body.get("action") or "convert").strip()

    def _post() -> tuple[dict[str, Any], int]:
        try:
            if action == "convert":
                rule = body.get("rule")
                if not rule:
                    return {"ok": False, "error": "Rule payload is required."}, 400
                converted = convert_sigma_rule(
                    rule,
                    pipeline=str(body.get("pipeline") or "").strip() or None,
                    default_index=str(body.get("default_index") or "").strip() or None,
                )
                return {"ok": True, "converted": redact_web_payload(converted)}, 200
            if action == "export":
                if not bool(body.get("double_confirmed")):
                    return {"ok": False, "error": "Double confirmation required to export Sigma rules."}, 400
                raw_rules = body.get("rules")
                rules: list[dict[str, Any]] = (
                    [r for r in raw_rules if isinstance(r, dict)]
                    if isinstance(raw_rules, list)
                    else []
                )
                out_name = Path(str(body.get("output_path") or "sigma_savedsearches.conf")).name
                out_path = runtime.workspace_dir / "reports" / out_name
                out_path.parent.mkdir(parents=True, exist_ok=True)
                res = export_rules_to_splunk(rules, out_path)
                return {"ok": True, "output_path": str(out_path), "result": redact_web_payload(res)}, 200
            return {"ok": False, "error": f"Unknown sigma action: {action}"}, 400
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

    payload, status = await anyio.to_thread.run_sync(_post)
    return JSONResponse(payload, status_code=status)


async def admin_splunk_bundle_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    denied = _require_admin(runtime)
    if denied is not None:
        return denied

    if request.method.upper() == "GET":
        wh_dir = runtime.workspace_dir / "wheelhouse"
        has_wh = wh_dir.is_dir() and any(wh_dir.glob("*.whl"))
        return JSONResponse(
            {
                "ok": True,
                "workspace_dir": str(runtime.workspace_dir),
                "has_local_wheelhouse": has_wh,
                "platforms": ["current", "all", "pure", "win_amd64", "manylinux2014_x86_64", "macosx_arm64"],
            }
        )

    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    action = str(body.get("action") or "validate").strip()

    def _run() -> tuple[dict[str, Any], int]:
        try:
            if action == "build":
                if not bool(body.get("double_confirmed")):
                    return {"ok": False, "error": "Double confirmation required to build deployment bundle."}, 400
                target_plat = str(body.get("target_platform") or "current").strip()
                plat_arg = None if target_plat == "current" else target_plat
                wheelhouse = bool(body.get("wheelhouse", False))
                raw_out = str(body.get("output_path") or "").strip()
                out_name = Path(raw_out).name if raw_out else "soclens-bundle.zip"
                out_path = runtime.workspace_dir / "bundles" / out_name
                created = create_bundle(
                    runtime.workspace_dir,
                    output_path=out_path,
                    wheelhouse=wheelhouse,
                    target_platform=plat_arg,
                )
                return {"ok": True, "bundle_path": str(created), "size_bytes": created.stat().st_size}, 200

            conf_pattern = str(body.get("conf_path") or "savedsearches.conf").strip()
            searches = parse_savedsearches_files(str(runtime.workspace_dir / conf_pattern))
            dry_run = bool(body.get("dry_run", True)) or runtime.dry_run
            if dry_run:
                return {"ok": True, "dry_run": True, "searches": redact_web_payload(searches)}, 200
            cfg = get_splunk_config(required=False)
            if not cfg.has_auth:
                return {"ok": False, "error": "Splunk credentials are not configured."}, 400
            validator = SplunkValidator(
                host=cfg.host,
                token=cfg.token,
                username=cfg.username,
                password=cfg.password,
                app=cfg.app,
                verify_ssl=cfg.verify_ssl,
            )
            earliest = str(body.get("earliest") or "-7d").strip()
            latest = str(body.get("latest") or "now").strip()
            results = [validator.run_single_search(s, earliest, latest) for s in searches]
            return {"ok": True, "results": redact_web_payload(results)}, 200
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


ADMIN_ROUTES: list[Route] = [
    Route("/api/admin/dashboard", admin_dashboard_endpoint, methods=["GET", "POST"]),
    Route("/api/admin/watchlists", admin_watchlists_endpoint, methods=["GET", "POST"]),
    Route("/api/admin/brand-logos", admin_brand_logos_endpoint, methods=["GET", "POST"]),
    Route("/api/admin/sigma", admin_sigma_endpoint, methods=["GET", "POST"]),
    Route("/api/admin/splunk-bundle", admin_splunk_bundle_endpoint, methods=["GET", "POST"]),
]
