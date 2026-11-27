"""Analyst workbench API routes (Research, Splunk, Splunk ES, SentinelOne, RF, Local DB)."""

from __future__ import annotations

import json
from typing import Any

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from soclens.agent_tools import validate_readonly_spl
from soclens.alert_cache import (
    CACHE_SOURCE_ES,
    CACHE_SOURCE_RF,
    CACHE_SOURCE_RF_PLAYBOOK,
    CACHE_SOURCE_S1,
)
from soclens.osint import OSINT_SOURCE_CATALOG
from soclens.research import OSINT_MODULES, RESEARCH_MODULES, research_target
from soclens.splunk_es import NOTABLE_STATUS_LABELS
from soclens.splunk_rf_enrichment import SplunkRFEnricher
from soclens.tui.filters import (
    BUILTIN_RF_PRESETS,
    S1_PRESETS_BY_VIEW,
    SPLUNK_ES_PRESETS,
    SPLUNK_TIME_PRESETS,
    TIMEFRAME_OPTIONS,
)
from soclens.tui.rf_formatters import (
    extract_alerts_v3,
    extract_playbook_alerts,
    normalize_alert_v3,
    normalize_playbook_alert,
)
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


def _filter_items(items: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    q = (query or "").strip().lower()
    if not q:
        return items
    matched: list[dict[str, Any]] = []
    for item in items:
        blob = json.dumps(item, default=str).lower()
        if q in blob:
            matched.append(item)
    return matched


async def research_sources_endpoint(request: Request) -> JSONResponse:
    sources = [
        {
            "id": spec.key,
            "label": spec.title,
            "short_name": spec.short_name,
            "category": spec.category,
            "tier": spec.tier,
            "description": spec.description,
        }
        for spec in OSINT_SOURCE_CATALOG
    ]
    return JSONResponse(
        {
            "ok": True,
            "rf_modules": list(RESEARCH_MODULES),
            "osint_modules": list(OSINT_MODULES),
            "osint_sources": sources,
        }
    )


async def research_run_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    target = str(body.get("target") or body.get("query") or "").strip()
    if not target:
        return JSONResponse({"ok": False, "error": "Target indicator or query is required."}, status_code=400)

    include_rf = bool(body.get("include_rf", True))
    include_osint = bool(body.get("include_osint", True))
    modules = body.get("modules") if isinstance(body.get("modules"), list) else None
    osint_sources = body.get("osint_sources") if isinstance(body.get("osint_sources"), list) else None
    explicit_type = str(body.get("explicit_type") or "").strip() or None
    links_timeframe = str(body.get("links_timeframe") or "-30d").strip() or "-30d"
    links_scope = str(body.get("links_scope") or "medium").strip() or "medium"
    deep = bool(body.get("deep", False))
    try:
        limit = max(1, min(int(body.get("limit") or 20), 100))
    except (TypeError, ValueError):
        limit = 20

    def _run() -> tuple[dict[str, Any], int]:
        rf_client = runtime.get_rf_client() if include_rf else None
        osint_client = runtime.get_osint_client() if include_osint else None
        try:
            dossier = research_target(
                rf_client,
                target,
                explicit_type=explicit_type,
                modules=modules,
                deep=deep,
                links_scope=links_scope,
                links_timeframe=links_timeframe,
                limit=limit,
                include_rf=include_rf and rf_client is not None,
                include_osint=include_osint,
                osint_sources=osint_sources,
                osint_client=osint_client,
                workspace_dir=runtime.workspace_dir,
                access_registry=runtime.api_access,
            )
            dossier_dict = dossier.to_dict() if hasattr(dossier, "to_dict") else {}
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return {"ok": True, "dossier": redact_web_payload(dossier_dict)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def splunk_search_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    spl = str(body.get("spl") or body.get("query") or "").strip()
    if not spl:
        return JSONResponse({"ok": False, "error": "SPL query is required."}, status_code=400)

    allowed, reason = validate_readonly_spl(spl)
    if not allowed:
        return JSONResponse(
            {"ok": False, "blocked": True, "error": f"Read-only SPL policy blocked query: {reason}"},
            status_code=400,
        )

    earliest = str(body.get("earliest") or "-24h").strip() or "-24h"
    latest = str(body.get("latest") or "now").strip() or "now"
    app = str(body.get("app") or "").strip() or None
    try:
        count = max(1, min(int(body.get("count") or body.get("limit") or 100), 1000))
        offset = max(0, int(body.get("offset") or 0))
    except (TypeError, ValueError):
        count, offset = 100, 0

    def _run() -> tuple[dict[str, Any], int]:
        client = runtime.get_splunk_client()
        if client is None:
            return {"ok": False, "error": "Splunk is not configured."}, 400
        try:
            result = client.run_search(
                spl,
                earliest=earliest,
                latest=latest,
                app=app,
                count=count,
                offset=offset,
            )
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return {"ok": True, "result": redact_web_payload(result)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def splunk_metadata_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    kind = str(request.path_params.get("kind") or "indexes").strip()

    def _run() -> tuple[dict[str, Any], int]:
        client = runtime.get_splunk_client()
        if client is None:
            return {
                "ok": True,
                "configured": False,
                "items": [],
                "time_presets": list(SPLUNK_TIME_PRESETS),
            }, 200
        try:
            if kind == "saved-searches":
                items = client.list_saved_searches()
            else:
                items = client.list_indexes()
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return {
            "ok": True,
            "configured": True,
            "items": redact_web_payload(items),
            "time_presets": list(SPLUNK_TIME_PRESETS),
        }, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def splunk_es_notables_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    if request.method.upper() == "POST":
        try:
            body = await _parse_json_body(request)
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    else:
        qp = request.query_params
        body = {
            "view": qp.get("view") or "notables",
            "earliest": qp.get("earliest") or "-24h",
            "latest": qp.get("latest") or "now",
            "urgency": qp.get("urgency") or None,
            "status": qp.get("status") or None,
            "q": qp.get("q") or "",
            "live": str(qp.get("live") or "").lower() in ("1", "true", "yes"),
        }

    view = str(body.get("view") or "notables").strip()
    q = str(body.get("q") or "").strip()
    live = bool(body.get("live", False))

    def _run() -> tuple[dict[str, Any], int]:
        es = runtime.get_splunk_es_client()
        if es is None or (not live and view == "notables"):
            cached = runtime.alert_cache.get(CACHE_SOURCE_ES)
            if cached is not None and not live:
                items = _filter_items([dict(x) for x in cached.items], q)
                return {
                    "ok": True,
                    "source": "cache",
                    "view": view,
                    "items": redact_web_payload(items),
                    "presets": list(SPLUNK_ES_PRESETS),
                    "status_labels": dict(NOTABLE_STATUS_LABELS),
                }, 200
            if es is None:
                return {
                    "ok": True,
                    "source": "unconfigured",
                    "view": view,
                    "items": [],
                    "presets": list(SPLUNK_ES_PRESETS),
                    "status_labels": dict(NOTABLE_STATUS_LABELS),
                }, 200

        try:
            if view == "correlations":
                items = es.list_correlation_searches()
            elif view == "threat_intel":
                collection = str(body.get("collection") or "ip_intel").strip() or "ip_intel"
                items = es.query_threat_intel(collection)
            elif view == "risk":
                items = es.list_risk_events(
                    earliest=str(body.get("earliest") or "-24h"),
                    latest=str(body.get("latest") or "now"),
                )
            elif view == "assets_identities":
                entity = q or str(body.get("entity") or "")
                kind = str(body.get("entity_kind") or "assets")
                if not entity:
                    items = []
                elif kind == "identities":
                    items = es.lookup_identity(entity)
                else:
                    items = es.lookup_asset(entity)
            else:
                items = es.list_notables(
                    earliest=str(body.get("earliest") or "-24h"),
                    latest=str(body.get("latest") or "now"),
                    urgency=body.get("urgency") or None,
                    status=body.get("status") or None,
                    search_text=q or None,
                    limit=int(body.get("limit") or 100),
                )
                runtime.alert_cache.put(CACHE_SOURCE_ES, items, timeframe="last_24h")
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

        filtered = _filter_items([dict(x) for x in items], q) if view != "notables" else items
        return {
            "ok": True,
            "source": "live",
            "view": view,
            "items": redact_web_payload(filtered),
            "presets": list(SPLUNK_ES_PRESETS),
            "status_labels": dict(NOTABLE_STATUS_LABELS),
        }, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def splunk_es_action_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    action = str(request.path_params.get("action") or "").strip()
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    if runtime.dry_run:
        return JSONResponse({"ok": True, "dry_run": True, "action": action, "message": "Dry-run: ES mutation skipped."})

    def _run() -> tuple[dict[str, Any], int]:
        es = runtime.get_splunk_es_client()
        if es is None:
            return {"ok": False, "error": "Splunk ES is not configured."}, 400
        try:
            if action == "triage":
                if not bool(body.get("double_confirmed")):
                    return {"ok": False, "error": "Double confirmation required for Splunk ES triage."}, 400
                event_id = str(body.get("event_id") or "").strip()
                if not event_id:
                    return {"ok": False, "error": "event_id is required."}, 400
                res = es.update_notable(
                    [event_id],
                    status=body.get("status"),
                    urgency=body.get("urgency"),
                    owner=body.get("owner"),
                    comment=body.get("comment"),
                )
                return {"ok": True, "result": redact_web_payload(res)}, 200
            if action == "enrich-rf":
                rf = runtime.get_rf_client()
                if rf is None:
                    return {"ok": False, "error": "Recorded Future token is not configured."}, 400
                enricher = SplunkRFEnricher(rf)
                raw_events = body.get("events")
                events: list[dict[str, Any]] = (
                    [e for e in raw_events if isinstance(e, dict)]
                    if isinstance(raw_events, list)
                    else []
                )
                enriched = enricher.enrich_events(events)
                return {"ok": True, "result": redact_web_payload(enriched)}, 200
            if action == "correlation-toggle":
                if not runtime.admin_enabled:
                    return {"ok": False, "error": "Admin mode (--admin) required to toggle correlation searches."}, 403
                if not bool(body.get("double_confirmed")):
                    return {"ok": False, "error": "Double confirmation required."}, 400
                name = str(body.get("name") or "").strip()
                enabled = bool(body.get("enabled", True))
                res = es.set_correlation_search_enabled(name, enabled=enabled)
                return {"ok": True, "result": redact_web_payload(res)}, 200
            return {"ok": False, "error": f"Unknown Splunk ES action: {action}"}, 404
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def s1_threats_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    qp = request.query_params
    q = str(qp.get("q") or "").strip()
    live = str(qp.get("live") or "").lower() in ("1", "true", "yes")
    source_kind = str(qp.get("source") or "threats").strip()

    def _run() -> tuple[dict[str, Any], int]:
        s1 = runtime.get_s1_client()
        if s1 is None or (not live and source_kind == "threats"):
            cached = runtime.alert_cache.get(CACHE_SOURCE_S1)
            if cached is not None and not live:
                items = _filter_items([dict(x) for x in cached.items], q)
                return {
                    "ok": True,
                    "source": "cache",
                    "items": redact_web_payload(items),
                    "presets": dict(S1_PRESETS_BY_VIEW),
                }, 200
            if s1 is None:
                return {
                    "ok": True,
                    "source": "unconfigured",
                    "items": [],
                    "presets": dict(S1_PRESETS_BY_VIEW),
                }, 200

        try:
            if source_kind == "cloud":
                items = s1.list_cloud_alerts(query=q or None, limit=100)
            elif source_kind == "unified":
                items = s1.list_unified_alerts(query=q or None, limit=100)
            else:
                items = s1.list_threats(query=q or None, limit=100)
                runtime.alert_cache.put(CACHE_SOURCE_S1, items, timeframe="last_24h")
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

        return {
            "ok": True,
            "source": "live",
            "items": redact_web_payload(items),
            "presets": dict(S1_PRESETS_BY_VIEW),
        }, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def s1_agents_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    qp = request.query_params
    q = str(qp.get("q") or "").strip() or None

    def _run() -> tuple[dict[str, Any], int]:
        s1 = runtime.get_s1_client()
        if s1 is None:
            return {"ok": True, "source": "unconfigured", "items": []}, 200
        try:
            items = s1.list_agents(query=q, limit=100)
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return {"ok": True, "source": "live", "items": redact_web_payload(items)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def s1_subview_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    view = str(request.path_params.get("view") or "").strip()

    def _run() -> tuple[dict[str, Any], int]:
        s1 = runtime.get_s1_client()
        if s1 is None:
            return {"ok": True, "source": "unconfigured", "items": []}, 200
        try:
            if view == "sites":
                items = s1.list_sites()
            elif view == "exclusions":
                items = s1.list_exclusions()
            elif view == "blocklist":
                items = s1.list_blocklist()
            elif view == "users":
                items = s1.list_users()
            elif view == "activities":
                items = s1.list_activities(limit=100)
            else:
                return {"ok": False, "error": f"Unknown S1 view: {view}"}, 404
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return {"ok": True, "view": view, "items": redact_web_payload(items)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def s1_action_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    action = str(body.get("action") or "").strip()
    if not action:
        return JSONResponse({"ok": False, "error": "Missing SentinelOne action."}, status_code=400)

    admin_only_actions = {
        "disconnect",
        "connect",
        "reboot",
        "uninstall",
        "decommission",
        "kill",
        "quarantine",
        "remediate",
        "rollback",
        "create_exclusion",
        "delete_exclusions",
        "add_to_blocklist",
        "remove_from_blocklist",
        "delete_site",
        "expire_site",
        "delete_user",
    }
    if action in admin_only_actions and not runtime.admin_enabled:
        return JSONResponse(
            {"ok": False, "error": f"Admin mode (--admin) is required for action {action!r}."},
            status_code=403,
        )
    if action in admin_only_actions and not bool(body.get("double_confirmed")):
        return JSONResponse(
            {"ok": False, "error": "Double confirmation is required for high-impact SentinelOne actions."},
            status_code=400,
        )
    if runtime.dry_run:
        return JSONResponse({"ok": True, "dry_run": True, "action": action, "message": "Dry-run: S1 action skipped."})

    def _run() -> tuple[dict[str, Any], int]:
        s1 = runtime.get_s1_client()
        if s1 is None:
            return {"ok": False, "error": "SentinelOne is not configured."}, 400
        raw_ids = body.get("ids")
        target_ids: list[str] = (
            [str(i) for i in raw_ids if str(i).strip()]
            if isinstance(raw_ids, list)
            else []
        )
        try:
            if action == "disconnect":
                res = s1.disconnect_agent(target_ids)
            elif action == "connect":
                res = s1.connect_agent(target_ids)
            elif action == "initiate_scan":
                res = s1.initiate_scan(target_ids)
            elif action == "update_threat_verdict":
                res = s1.update_threat_verdict(target_ids, str(body.get("verdict") or "true_positive"))
            elif action == "update_threat_status":
                res = s1.update_threat_incident_status(target_ids, str(body.get("status") or "in_progress"))
            elif action in ("kill", "quarantine", "remediate", "rollback"):
                res = s1.mitigate_threat(target_ids, action)
            else:
                return {"ok": False, "error": f"Unsupported SentinelOne action: {action}"}, 400
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return {"ok": True, "action": action, "result": redact_web_payload(res)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def rf_alerts_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    qp = request.query_params
    mode = str(qp.get("mode") or "alerts_v3").strip()
    q = str(qp.get("q") or "").strip()
    live = str(qp.get("live") or "").lower() in ("1", "true", "yes")

    def _run() -> tuple[dict[str, Any], int]:
        if mode == "playbook":
            cached = runtime.alert_cache.get(CACHE_SOURCE_RF_PLAYBOOK)
            if cached is not None and not live:
                items = _filter_items([dict(x) for x in cached.items], q)
                return {
                    "ok": True,
                    "source": "cache",
                    "mode": mode,
                    "items": redact_web_payload(items),
                    "image_keys": cached.meta.get("image_keys", {}),
                    "presets": list(BUILTIN_RF_PRESETS),
                }, 200
            rf = runtime.get_rf_client()
            if rf is None:
                return {"ok": True, "source": "unconfigured", "mode": mode, "items": [], "presets": list(BUILTIN_RF_PRESETS)}, 200
            try:
                data = rf.search_playbook_alerts(limit=100)
                raw_items, total = extract_playbook_alerts(data)
                items = [normalize_playbook_alert(x) for x in raw_items]
                runtime.alert_cache.put(CACHE_SOURCE_RF_PLAYBOOK, items, timeframe="last_24h", meta={"total": total})
                return {
                    "ok": True,
                    "source": "live",
                    "mode": mode,
                    "items": redact_web_payload(_filter_items(items, q)),
                    "presets": list(BUILTIN_RF_PRESETS),
                }, 200
            except Exception as exc:
                return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

        if mode == "cases":
            rf = runtime.get_rf_client()
            if rf is None:
                return {"ok": True, "source": "unconfigured", "mode": mode, "items": []}, 200
            try:
                data = rf.search_cases(limit=50)
                raw_data = data.get("data") if isinstance(data, dict) else None
                items = (
                    [x for x in raw_data if isinstance(x, dict)]
                    if isinstance(raw_data, list)
                    else []
                )
                return {"ok": True, "source": "live", "mode": mode, "items": redact_web_payload(_filter_items(items, q))}, 200
            except Exception as exc:
                return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

        cached = runtime.alert_cache.get(CACHE_SOURCE_RF)
        if cached is not None and not live:
            items = _filter_items([dict(x) for x in cached.items], q)
            return {
                "ok": True,
                "source": "cache",
                "mode": "alerts_v3",
                "items": redact_web_payload(items),
                "presets": list(BUILTIN_RF_PRESETS),
                "timeframes": list(TIMEFRAME_OPTIONS),
            }, 200
        rf = runtime.get_rf_client()
        if rf is None:
            return {
                "ok": True,
                "source": "unconfigured",
                "mode": "alerts_v3",
                "items": [],
                "presets": list(BUILTIN_RF_PRESETS),
                "timeframes": list(TIMEFRAME_OPTIONS),
            }, 200
        try:
            data = rf.search_alerts_v3(limit=100)
            raw_items, total = extract_alerts_v3(data)
            items = [normalize_alert_v3(x) for x in raw_items]
            runtime.alert_cache.put(CACHE_SOURCE_RF, items, timeframe="last_24h", meta={"total": total})
            return {
                "ok": True,
                "source": "live",
                "mode": "alerts_v3",
                "items": redact_web_payload(_filter_items(items, q)),
                "presets": list(BUILTIN_RF_PRESETS),
                "timeframes": list(TIMEFRAME_OPTIONS),
            }, 200
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def rf_lookup_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    entity_type = str(body.get("entity_type") or "ip").strip()
    value = str(body.get("value") or "").strip()
    if not value:
        return JSONResponse({"ok": False, "error": "Entity value is required."}, status_code=400)

    def _run() -> tuple[dict[str, Any], int]:
        rf = runtime.get_rf_client()
        if rf is None:
            return {"ok": False, "error": "Recorded Future is not configured."}, 400
        try:
            res = rf.v2_lookup(entity_type, value)
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return {"ok": True, "result": redact_web_payload(res)}, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def local_iocs_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    qp = request.query_params
    ioc = str(qp.get("ioc") or qp.get("q") or "").strip()
    try:
        limit = max(1, min(int(qp.get("limit") or 50), 200))
    except ValueError:
        limit = 50

    def _run() -> dict[str, Any]:
        sightings = (
            runtime.storage.lookup_ioc_sightings(ioc, limit=limit)
            if ioc
            else []
        )
        alerts = (
            runtime.storage.search_alerts_history(ioc, limit=limit)
            if ioc
            else []
        )
        return {
            "ok": True,
            "query": ioc,
            "sightings": redact_web_payload(sightings),
            "alerts_history": redact_web_payload(alerts),
        }

    return JSONResponse(await anyio.to_thread.run_sync(_run))


WORKBENCH_ROUTES: list[Route] = [
    Route("/api/research/sources", research_sources_endpoint, methods=["GET"]),
    Route("/api/research", research_run_endpoint, methods=["POST"]),
    Route("/api/research/run", research_run_endpoint, methods=["POST"]),
    Route("/api/splunk/search", splunk_search_endpoint, methods=["POST"]),
    Route("/api/splunk/{kind:str}", splunk_metadata_endpoint, methods=["GET"]),
    Route("/api/splunk-es/notables", splunk_es_notables_endpoint, methods=["GET", "POST"]),
    Route("/api/splunk-es/{action:str}", splunk_es_action_endpoint, methods=["POST"]),
    Route("/api/sentinelone/threats", s1_threats_endpoint, methods=["GET"]),
    Route("/api/sentinelone/agents", s1_agents_endpoint, methods=["GET"]),
    Route("/api/sentinelone/action", s1_action_endpoint, methods=["POST"]),
    Route("/api/sentinelone/{view:str}", s1_subview_endpoint, methods=["GET"]),
    Route("/api/rf/alerts", rf_alerts_endpoint, methods=["GET"]),
    Route("/api/rf/lookup", rf_lookup_endpoint, methods=["POST"]),
    Route("/api/local/iocs", local_iocs_endpoint, methods=["GET"]),
]
