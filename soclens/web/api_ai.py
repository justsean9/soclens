"""AI chat SSE streaming, investigations, policy/kill-switch, audit, and learning routes."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from collections.abc import AsyncIterator
from typing import Any

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from soclens.agent_policy import InvestigationMode
from soclens.agent_tools import READONLY_TOOL_NAMES
from soclens.config import get_local_llm_config
from soclens.event_tracker import UniqueEvent
from soclens.llm import (
    SOC_PROMPT_TEMPLATES,
    discover_available_ai_models,
)
from soclens.settings import LLM_PROVIDER_CHOICES
from soclens.web.security import StreamingSecretRedactor, redact_web_payload
from soclens.web.sse import format_sse
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


def _entry_to_dict(entry: Any) -> dict[str, Any]:
    if dataclasses.is_dataclass(entry) and not isinstance(entry, type):
        data = dataclasses.asdict(entry)
    elif isinstance(entry, dict):
        data = dict(entry)
    else:
        data = {"value": str(entry)}
    return dict(redact_web_payload(data))


async def ai_chat_stream_endpoint(request: Request) -> Any:
    runtime: WebRuntimeState = request.app.state.runtime

    if request.method.upper() != "POST":
        return JSONResponse(
            {"ok": False, "error": "Method not allowed; use POST with X-SOCLens-Token."},
            status_code=405,
        )

    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    user_prompt = str(body.get("prompt") or body.get("user_prompt") or "").strip()
    attached_context = str(body.get("attached_context") or "").strip() or None
    attached_title = str(body.get("attached_title") or "").strip() or None
    session_id = str(body.get("session_id") or "chat-1").strip() or "chat-1"
    provider = str(body.get("provider") or "").strip() or None
    model = str(body.get("model") or "").strip() or None
    mode_raw = str(body.get("mode") or "").strip().lower()
    if "enable_tools" in body:
        enable_tools = bool(body.get("enable_tools"))
    else:
        enable_tools = mode_raw != "ask_only"
    history_raw = body.get("history")
    history = [h for h in history_raw if isinstance(h, dict)] if isinstance(history_raw, list) else []

    if not user_prompt and not attached_context:
        return JSONResponse(
            {"ok": False, "error": "Enter a prompt or attach context before sending."},
            status_code=400,
        )

    lower_prompt = user_prompt.lower()
    if lower_prompt == "/learn":
        return JSONResponse(
            {"ok": False, "error": "Usage: /learn <lesson text>"},
            status_code=400,
        )

    if lower_prompt.startswith("/learn") and len(user_prompt) > 6 and user_prompt[6].isspace():
        lesson = user_prompt[6:].strip()
        if not lesson:
            return JSONResponse(
                {"ok": False, "error": "Usage: /learn <lesson text>"},
                status_code=400,
            )
        first_line = lesson.splitlines()[0].strip()[:80] or "Manual SOC Learning"
        confirm_learn = bool(body.get("confirm_learn", False))

        async def _learn_stream() -> AsyncIterator[str]:
            if confirm_learn:
                try:
                    created = await anyio.to_thread.run_sync(
                        lambda: runtime.learning_manager.submit_manual_learn(
                            title=first_line,
                            content=lesson,
                            category=str(body.get("category") or "environment_fact"),
                            tags=tuple(body.get("tags") or ()),
                            actor="web-analyst",
                        )
                    )
                    entry_dict = _entry_to_dict(created)
                    yield format_sse("learn_saved", {"ok": True, "entry": entry_dict})
                    yield format_sse(
                        "done",
                        dict(
                            redact_web_payload(
                                {
                                    "ok": True,
                                    "status": "completed",
                                    "session_id": session_id,
                                    "content": f"Saved learning: {entry_dict.get('title', first_line)}",
                                }
                            )
                        ),
                    )
                except ValueError as exc:
                    yield format_sse("error", {"ok": False, "error": str(redact_web_payload(str(exc)))})
            else:
                yield format_sse(
                    "learn_preview",
                    dict(
                        redact_web_payload(
                            {
                                "title": first_line,
                                "content": lesson,
                                "category": "environment_fact",
                                "session_id": session_id,
                            }
                        )
                    ),
                )
                yield format_sse(
                    "done",
                    dict(
                        redact_web_payload(
                            {
                                "ok": True,
                                "status": "learn_preview",
                                "session_id": session_id,
                                "content": f"Ready to teach: {first_line}",
                            }
                        )
                    ),
                )

        return StreamingResponse(
            _learn_stream(),
            status_code=200,
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache, no-store", "X-Accel-Buffering": "no"},
        )

    template_key = str(body.get("template") or "").strip().lower()
    effective_prompt = user_prompt
    template_system_prompt: str | None = None
    if template_key and template_key in SOC_PROMPT_TEMPLATES and template_key != "freeform":
        tmpl = SOC_PROMPT_TEMPLATES[template_key]
        if isinstance(tmpl, dict):
            user_prefix = str(tmpl.get("user_prefix") or "")
            if user_prefix:
                effective_prompt = (
                    f"{user_prefix}{user_prompt}" if user_prompt else user_prefix.strip()
                )
            sys_override = str(tmpl.get("system_prompt") or "").strip()
            if sys_override:
                template_system_prompt = sys_override

    async def _chat_event_generator() -> AsyncIterator[str]:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[tuple[str, Any] | None] = asyncio.Queue()
        safe_session_id = str(redact_web_payload(session_id))
        stream_redactor = StreamingSecretRedactor()

        def _push(ev_type: str, data: Any) -> None:
            if not loop.is_closed():
                loop.call_soon_threadsafe(queue.put_nowait, (ev_type, data))

        def _emit_token_text(safe_tok: str) -> None:
            if not safe_tok:
                return
            payload = {"token": safe_tok, "session_id": safe_session_id}
            _push("token", payload)
            runtime.sse_bus.publish("ai_token", payload)

        def _on_token(tok: str) -> None:
            if not tok:
                return
            _emit_token_text(stream_redactor.feed(str(tok)))

        def _on_tool(ev: dict[str, Any]) -> None:
            safe_ev = dict(redact_web_payload({**ev, "session_id": safe_session_id}))
            _push("tool", safe_ev)
            runtime.sse_bus.publish("tool_event", safe_ev)

        def _run_chat() -> None:
            try:
                res = runtime.ai_orchestrator.chat(
                    user_prompt=effective_prompt,
                    history=history,
                    attached_context=attached_context,
                    attached_title=attached_title,
                    session_id=session_id,
                    provider=provider,
                    model=model,
                    system_prompt_override=template_system_prompt,
                    enable_tools=enable_tools,
                    stop_event=runtime.shutdown_event,
                    stream_callback=_on_token,
                    tool_event_callback=_on_tool,
                )
                _emit_token_text(stream_redactor.flush())
                done_payload = _entry_to_dict(res)
                done_payload["ok"] = res.status != "error"
                if res.status == "error" and res.error:
                    _push(
                        "error",
                        {**done_payload, "ok": False, "error": str(redact_web_payload(res.error))},
                    )
                else:
                    _push("done", done_payload)
            except Exception as exc:
                _emit_token_text(stream_redactor.flush())
                _push(
                    "error",
                    {
                        "ok": False,
                        "error": str(redact_web_payload(str(exc))),
                        "session_id": safe_session_id,
                    },
                )
            finally:
                if not loop.is_closed():
                    loop.call_soon_threadsafe(queue.put_nowait, None)

        async with anyio.create_task_group() as tg:
            tg.start_soon(anyio.to_thread.run_sync, _run_chat)
            while True:
                item = await queue.get()
                if item is None:
                    break
                ev_type, ev_data = item
                yield format_sse(ev_type, ev_data)

    return StreamingResponse(
        _chat_event_generator(),
        status_code=200,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def ai_investigate_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    event_key = str(body.get("event_key") or "").strip()
    event_context = str(body.get("event_context") or "").strip()
    if not event_key:
        event_key = "web_ad_hoc::manual"
    if not event_context and not body.get("question"):
        return JSONResponse(
            {"ok": False, "error": "Provide 'event_context' or 'question' for investigation."},
            status_code=400,
        )

    raw_mode = str(body.get("mode") or "ask_only").strip()
    mode: InvestigationMode = (
        "full_investigation" if raw_mode == "full_investigation" else "ask_only"
    )
    question = str(body.get("question") or "").strip()
    provider = str(body.get("provider") or "").strip() or None
    model = str(body.get("model") or "").strip() or None

    def _run() -> dict[str, Any]:
        def _on_tool(ev: dict[str, Any]) -> None:
            safe_ev = dict(redact_web_payload({**ev, "event_key": event_key}))
            runtime.sse_bus.publish("tool_event", safe_ev)

        res = runtime.ai_orchestrator.investigate(
            event_key=event_key,
            event_context=event_context,
            mode=mode,
            question=question,
            provider=provider,
            model=model,
            stop_event=runtime.shutdown_event,
            tool_event_callback=_on_tool,
        )
        raw_meta = body.get("metadata")
        metadata_dict: dict[str, Any] = dict(raw_meta) if isinstance(raw_meta, dict) else {}
        ev_obj = UniqueEvent(
            event_key=event_key,
            source_kind=str(body.get("source_kind") or "splunk_es"),  # type: ignore[arg-type]
            native_id=str(body.get("native_id") or event_key),
            scope=str(body.get("scope") or "default"),
            title=str(body.get("title") or event_key),
            severity=str(body.get("severity") or ""),
            status=str(body.get("status") or ""),
            timestamp=res.timestamp,
            summary=event_context[:500],
            metadata=metadata_dict,
        )
        try:
            runtime.event_ai_store.attach_ai_response(ev_obj, res)
        except Exception:
            pass
        res_dict = _entry_to_dict(res)
        triage_payload = redact_web_payload(
            {
                "event_key": event_key,
                "run_id": res.run_id,
                "status": res.status,
                "mode": res.mode,
                "provider": res.provider,
                "model": res.model,
            }
        )
        runtime.sse_bus.publish(
            "triage_update",
            dict(triage_payload) if isinstance(triage_payload, dict) else {},
        )
        return {"ok": res.status != "error", "result": res_dict}

    payload = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload)


async def ai_panels_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    event_key = str(request.query_params.get("event_key") or "").strip() or None
    investigated_only = str(request.query_params.get("investigated_only") or "").strip().lower() in (
        "1",
        "true",
        "yes",
    )

    def _run() -> dict[str, Any]:
        if event_key:
            panels = runtime.event_ai_store.get_panels(event_key)
            panel_dicts = [_entry_to_dict(p) for p in panels]
            ev = runtime.event_ai_store.get_event(event_key)
            return {
                "ok": True,
                "event_key": event_key,
                "event": _entry_to_dict(ev) if ev is not None else None,
                "panels": panel_dicts,
            }

        events = runtime.event_ai_store.list_events(investigated_only=investigated_only)
        all_panels: list[dict[str, Any]] = []
        event_rows: list[dict[str, Any]] = []
        for ev in events:
            ev_dict = _entry_to_dict(ev)
            panels = runtime.event_ai_store.get_panels(ev.event_key)
            p_dicts = [_entry_to_dict(p) for p in panels]
            ev_dict["panels"] = p_dicts
            event_rows.append(ev_dict)
            all_panels.extend(p_dicts)
        return {
            "ok": True,
            "events": event_rows,
            "panels": all_panels,
        }

    return JSONResponse(await anyio.to_thread.run_sync(_run))


async def get_ai_policy_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime

    def _run() -> dict[str, Any]:
        pol = runtime.ai_policy_store.load()
        return {
            "ok": True,
            "policy": _entry_to_dict(pol),
            "readonly_tools": sorted(READONLY_TOOL_NAMES),
        }

    return JSONResponse(await anyio.to_thread.run_sync(_run))


async def update_ai_policy_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    def _run() -> tuple[dict[str, Any], int]:
        allowed_fields = {
            "background_triage_enabled",
            "cross_search_enabled",
            "splunk_search_enabled",
            "splunk_es_enabled",
            "sentinelone_enabled",
            "recorded_future_enabled",
            "watchlists_osint_enabled",
            "local_db_enabled",
            "disabled_tools",
            "max_tool_steps",
            "max_identical_tool_calls",
            "max_same_tool_failures",
            "ai_kill_switch_active",
            "kill_switch_visible",
            "kill_switch_confirm_engage",
            "kill_switch_confirm_resume",
            "kill_switch_persist_across_restarts",
            "kill_switch_label",
            "kill_switch_hotkey",
            "learning_mode",
        }
        updates = {k: v for k, v in body.items() if k in allowed_fields}
        if not updates:
            return {"ok": False, "error": "No valid policy fields supplied."}, 400
        if "kill_switch" in body and "ai_kill_switch_active" not in updates:
            updates["ai_kill_switch_active"] = bool(body["kill_switch"])
        if "ai_kill_switch_active" in updates:
            runtime.set_ai_kill_switch(bool(updates.pop("ai_kill_switch_active")))
        if updates:
            updated = runtime.ai_policy_store.update(**updates)
        else:
            updated = runtime.ai_policy_store.load()
        runtime.sse_bus.publish(
            "ai_policy_updated",
            {"ai_kill_switch_active": updated.ai_kill_switch_active, "learning_mode": updated.learning_mode},
        )
        return {
            "ok": True,
            "policy": _entry_to_dict(updated),
            "readonly_tools": sorted(READONLY_TOOL_NAMES),
        }, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def ai_kill_switch_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    if "active" in body:
        target = bool(body["active"])
    else:
        target = not runtime.is_ai_killed()

    res = await anyio.to_thread.run_sync(lambda: runtime.set_ai_kill_switch(target))
    return JSONResponse({"ok": True, **res})


async def ai_models_endpoint(request: Request) -> JSONResponse:
    probe = str(request.query_params.get("probe") or "").strip().lower() in ("1", "true", "yes")
    selected_provider = str(request.query_params.get("provider") or "").strip() or None

    def _run() -> dict[str, Any]:
        cfg = get_local_llm_config()
        discovered: list[dict[str, Any]] = []
        if probe:
            for item in discover_available_ai_models(
                selected_provider=selected_provider,
                stop_event=request.app.state.runtime.shutdown_event,
            ):
                discovered.append(_entry_to_dict(item))
        return {
            "ok": True,
            "default_provider": cfg.provider,
            "default_model": cfg.model,
            "providers": list(LLM_PROVIDER_CHOICES),
            "templates": [
                {"id": k, "label": str(v.get("label") or k)}
                for k, v in SOC_PROMPT_TEMPLATES.items()
                if isinstance(v, dict)
            ],
            "discovered": discovered,
        }

    return JSONResponse(await anyio.to_thread.run_sync(_run))


async def audit_log_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    qp = request.query_params
    event_key = qp.get("event_key") or None
    run_id = qp.get("run_id") or None
    event_type = qp.get("event_type") or None
    blocked_only = str(qp.get("blocked_only") or "").strip().lower() in ("1", "true", "yes")
    try:
        limit = max(1, min(int(qp.get("limit") or 200), 1000))
    except ValueError:
        limit = 200

    def _run() -> dict[str, Any]:
        entries = runtime.ai_audit_store.query(
            event_key=event_key,
            run_id=run_id,
            event_type=event_type,
            blocked_only=blocked_only,
            limit=limit,
        )
        return {
            "ok": True,
            "entries": [_entry_to_dict(e) for e in entries],
        }

    return JSONResponse(await anyio.to_thread.run_sync(_run))


async def knowledge_list_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    qp = request.query_params
    status = qp.get("status") or None
    category = qp.get("category") or None
    source = qp.get("source") or None
    q = (qp.get("q") or "").strip().lower()
    try:
        limit = max(1, min(int(qp.get("limit") or 200), 1000))
    except ValueError:
        limit = 200

    def _run() -> dict[str, Any]:
        entries = runtime.learning_manager.list_entries(
            status=status,  # type: ignore[arg-type]
            category=category,  # type: ignore[arg-type]
            source=source,  # type: ignore[arg-type]
            limit=limit,
        )
        rows = [_entry_to_dict(e) for e in entries]
        if q:
            rows = [
                r
                for r in rows
                if q in str(r.get("title", "")).lower()
                or q in str(r.get("content", "")).lower()
                or q in " ".join(str(t) for t in (r.get("tags") or [])).lower()
            ]
        return {
            "ok": True,
            "learning_mode": runtime.learning_manager.get_learning_mode(),
            "entries": rows,
        }

    return JSONResponse(await anyio.to_thread.run_sync(_run))


async def knowledge_learn_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    title = str(body.get("title") or "").strip()
    content = str(body.get("content") or body.get("lesson") or "").strip()
    if not title and content:
        title = content.splitlines()[0].strip()[:80]
    category = str(body.get("category") or "environment_fact").strip() or "environment_fact"
    raw_tags = body.get("tags") or ()
    tags = tuple(str(t).strip() for t in raw_tags if str(t).strip()) if isinstance(raw_tags, list) else ()
    actor = str(body.get("actor") or "web-analyst").strip() or "web-analyst"

    def _run() -> tuple[dict[str, Any], int]:
        try:
            entry = runtime.learning_manager.submit_manual_learn(
                title=title,
                content=content,
                category=category,  # type: ignore[arg-type]
                tags=tags,
                actor=actor,
            )
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}, 400
        return {"ok": True, "entry": _entry_to_dict(entry)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def knowledge_scan_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    text = str(body.get("text") or body.get("content") or "")
    res = await anyio.to_thread.run_sync(lambda: runtime.learning_manager.scan_candidate(text))
    return JSONResponse({"ok": True, "guard": _entry_to_dict(res)})


async def knowledge_approve_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    entry_id = str(request.path_params.get("entry_id") or "").strip()
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    actor = str(body.get("actor") or "web-analyst").strip() or "web-analyst"

    def _run() -> tuple[dict[str, Any], int]:
        try:
            entry = runtime.learning_manager.approve_entry(entry_id, actor=actor)
        except KeyError:
            return {"ok": False, "error": f"Learning entry not found: {entry_id}"}, 404
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}, 400
        return {"ok": True, "entry": _entry_to_dict(entry)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def knowledge_pin_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    entry_id = str(request.path_params.get("entry_id") or "").strip()
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    pinned = bool(body.get("pinned", True))
    actor = str(body.get("actor") or "web-analyst").strip() or "web-analyst"

    def _run() -> tuple[dict[str, Any], int]:
        try:
            entry = runtime.learning_manager.pin_entry(entry_id, pinned=pinned, actor=actor)
        except KeyError:
            return {"ok": False, "error": f"Learning entry not found: {entry_id}"}, 404
        return {"ok": True, "entry": _entry_to_dict(entry)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def knowledge_rollback_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    entry_id = str(request.path_params.get("entry_id") or "").strip()
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    actor = str(body.get("actor") or "web-analyst").strip() or "web-analyst"

    def _run() -> tuple[dict[str, Any], int]:
        try:
            entry = runtime.learning_manager.rollback_entry(entry_id, actor=actor)
        except KeyError:
            return {"ok": False, "error": f"Learning entry not found: {entry_id}"}, 404
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}, 400
        return {"ok": True, "entry": _entry_to_dict(entry)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def knowledge_edit_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    entry_id = str(request.path_params.get("entry_id") or "").strip()
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    actor = str(body.get("actor") or "web-analyst").strip() or "web-analyst"
    raw_tags = body.get("tags")
    tags = tuple(str(t).strip() for t in raw_tags if str(t).strip()) if isinstance(raw_tags, list) else None

    def _run() -> tuple[dict[str, Any], int]:
        try:
            entry = runtime.learning_manager.edit_entry(
                entry_id,
                title=body.get("title"),
                content=body.get("content"),
                category=body.get("category"),
                tags=tags,
                actor=actor,
            )
        except KeyError:
            return {"ok": False, "error": f"Learning entry not found: {entry_id}"}, 404
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}, 400
        return {"ok": True, "entry": _entry_to_dict(entry)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def knowledge_delete_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    entry_id = str(request.path_params.get("entry_id") or "").strip()

    def _run() -> tuple[dict[str, Any], int]:
        try:
            deleted = runtime.learning_manager.delete_entry(entry_id, actor="web-analyst")
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}, 400
        if not deleted:
            return {"ok": False, "error": f"Learning entry not found: {entry_id}"}, 404
        return {"ok": True, "deleted": True, "entry_id": entry_id}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def knowledge_revisions_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    entry_id = str(request.path_params.get("entry_id") or "").strip()

    def _run() -> dict[str, Any]:
        revs = runtime.learning_manager.get_revisions(entry_id)
        return {"ok": True, "entry_id": entry_id, "revisions": redact_web_payload(revs)}

    return JSONResponse(await anyio.to_thread.run_sync(_run))


async def knowledge_reload_base_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime

    def _run() -> dict[str, Any]:
        entries = runtime.learning_manager.load_base_knowledge(runtime.workspace_dir)
        return {"ok": True, "count": len(entries), "entries": [_entry_to_dict(e) for e in entries]}

    return JSONResponse(await anyio.to_thread.run_sync(_run))


AI_ROUTES: list[Route] = [
    Route("/api/ai/chat/stream", ai_chat_stream_endpoint, methods=["POST"]),
    Route("/api/ai/investigate", ai_investigate_endpoint, methods=["POST"]),
    Route("/api/ai/panels", ai_panels_endpoint, methods=["GET"]),
    Route("/api/events/panels", ai_panels_endpoint, methods=["GET"]),
    Route("/api/events", ai_panels_endpoint, methods=["GET"]),
    Route("/api/ai/policy", get_ai_policy_endpoint, methods=["GET"]),
    Route("/api/ai/policy", update_ai_policy_endpoint, methods=["POST", "PATCH"]),
    Route("/api/ai/kill-switch", ai_kill_switch_endpoint, methods=["POST"]),
    Route("/api/ai/models", ai_models_endpoint, methods=["GET"]),
    Route("/api/audit", audit_log_endpoint, methods=["GET"]),
    Route("/api/ai/audit", audit_log_endpoint, methods=["GET"]),
    Route("/api/knowledge", knowledge_list_endpoint, methods=["GET"]),
    Route("/api/learnings", knowledge_list_endpoint, methods=["GET"]),
    Route("/api/knowledge/learn", knowledge_learn_endpoint, methods=["POST"]),
    Route("/api/learnings/learn", knowledge_learn_endpoint, methods=["POST"]),
    Route("/api/knowledge/scan", knowledge_scan_endpoint, methods=["POST"]),
    Route("/api/learnings/scan", knowledge_scan_endpoint, methods=["POST"]),
    Route("/api/knowledge/reload-base", knowledge_reload_base_endpoint, methods=["POST"]),
    Route("/api/learnings/reload-base", knowledge_reload_base_endpoint, methods=["POST"]),
    Route("/api/knowledge/{entry_id}/approve", knowledge_approve_endpoint, methods=["POST"]),
    Route("/api/learnings/{entry_id}/approve", knowledge_approve_endpoint, methods=["POST"]),
    Route("/api/knowledge/{entry_id}/pin", knowledge_pin_endpoint, methods=["POST"]),
    Route("/api/learnings/{entry_id}/pin", knowledge_pin_endpoint, methods=["POST"]),
    Route("/api/knowledge/{entry_id}/rollback", knowledge_rollback_endpoint, methods=["POST"]),
    Route("/api/learnings/{entry_id}/rollback", knowledge_rollback_endpoint, methods=["POST"]),
    Route("/api/knowledge/{entry_id}/edit", knowledge_edit_endpoint, methods=["POST", "PATCH"]),
    Route("/api/learnings/{entry_id}/edit", knowledge_edit_endpoint, methods=["POST", "PATCH"]),
    Route("/api/knowledge/{entry_id}/revisions", knowledge_revisions_endpoint, methods=["GET"]),
    Route("/api/learnings/{entry_id}/revisions", knowledge_revisions_endpoint, methods=["GET"]),
    Route("/api/knowledge/{entry_id}", knowledge_delete_endpoint, methods=["DELETE"]),
    Route("/api/learnings/{entry_id}", knowledge_delete_endpoint, methods=["DELETE"]),
]
