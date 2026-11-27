"""Settings, in-memory Vault unlock, profile, and database configuration routes."""

from __future__ import annotations

import json
from typing import Any

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from soclens.config import (
    ConfigurationError,
    get_database_config,
    get_local_llm_config,
    get_sentinelone_config,
    get_splunk_config,
    hydrate_secrets_from_store,
)
from soclens.llm import LocalLLMClient
from soclens.osint import OSINTClient
from soclens.sentinelone import SentinelOneClient
from soclens.settings import (
    SETTING_CATEGORIES,
    SETTING_SPECS,
    clear_profile_settings,
    clear_unlocked_keys,
    delete_profile,
    describe_all_settings,
    get_active_profile_name,
    get_profile_settings,
    get_setting_with_source,
    get_settings_storage_info,
    inspect_settings_encryption,
    is_settings_locked,
    list_profiles,
    lock_settings,
    resolve_setting_key,
    save_profile_settings,
    set_active_profile,
    set_session_overrides,
    unlock_settings,
    validate_settings_values,
)
from soclens.splunk import SplunkValidator
from soclens.storage import _sanitize_db_error, test_db_connection
from soclens.web.security import (
    is_sensitive_setting_key,
    redact_web_payload,
    sanitize_settings_items_for_web,
)
from soclens.web.state import WebRuntimeState

_DB_REBIND_KEYS: frozenset[str] = frozenset(
    {
        "db_backend",
        "db_sqlite_path",
        "db_dsn",
        "db_host",
        "db_port",
        "db_name",
        "db_user",
        "db_password",
        "db_ssl_mode",
        "db_ssl_ca",
        "db_ssl_cert",
        "db_ssl_key",
        "db_pool_size",
        "db_max_overflow",
        "db_retention_days",
        "workstation_id",
        "analyst_id",
    }
)


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


def _build_sanitized_settings_snapshot(
    runtime: WebRuntimeState,
    *,
    profile: str | None = None,
) -> dict[str, Any]:
    locked = is_settings_locked()
    encryption = inspect_settings_encryption()
    storage_info = get_settings_storage_info()
    active_profile = get_active_profile_name()
    target_profile = profile or active_profile
    profiles = list_profiles()

    raw_items = describe_all_settings(reveal=False, profile=target_profile)
    raw_lookup: dict[str, tuple[str | None, bool]] = {}
    saved_map = get_profile_settings(profile=target_profile)
    for spec in SETTING_SPECS:
        val, _src = get_setting_with_source(spec.key, profile=target_profile)
        has_saved = bool(str(saved_map.get(spec.key) or "").strip())
        raw_lookup[spec.key] = (val, has_saved)

    sanitized_items = sanitize_settings_items_for_web(raw_items, raw_lookup=raw_lookup)
    db_cfg = runtime.storage.config
    db_summary = {
        "backend": db_cfg.backend,
        "dialect": runtime.storage.dialect,
        "sqlite_path": str(db_cfg.sqlite_path) if db_cfg.sqlite_path else "",
        "host": db_cfg.host or "",
        "port": db_cfg.port,
        "name": db_cfg.database or "",
        "user": db_cfg.username or "",
        "password_configured": bool(db_cfg.password),
        "dsn_configured": bool(db_cfg.dsn),
        "ssl_mode": db_cfg.ssl_mode or "",
        "pool_size": db_cfg.pool_size,
        "max_overflow": db_cfg.max_overflow,
        "retention_days": db_cfg.retention_days,
        "workstation_id": db_cfg.workstation_id,
        "profile_name": db_cfg.profile_name,
        "analyst_id": db_cfg.analyst_id,
        "storage_ok": runtime.storage_error is None,
        "storage_error": runtime.storage_error,
    }
    return redact_web_payload(
        {
            "ok": True,
            "locked": locked,
            "storage_ok": runtime.storage_error is None,
            "storage_error": runtime.storage_error,
            "encryption": {
                "encrypted": bool(encryption.get("encrypted", False)),
                "mode": encryption.get("mode"),
                "locked": locked,
                "kdf": encryption.get("kdf"),
            },
            "active_profile": active_profile,
            "profile": target_profile,
            "profiles": profiles,
            "storage_info": {
                "path": str(storage_info.get("path") or ""),
                "exists": bool(storage_info.get("exists", False)),
                "locked": locked,
            },
            "categories": [{"id": cid, "label": clabel} for cid, clabel in SETTING_CATEGORIES],
            "settings": sanitized_items,
            "db_config": db_summary,
        }
    )


async def get_settings_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    profile = request.query_params.get("profile") or None
    payload = await anyio.to_thread.run_sync(
        lambda: _build_sanitized_settings_snapshot(runtime, profile=profile)
    )
    return JSONResponse(payload)


async def post_settings_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    def _apply() -> tuple[dict[str, Any], int]:
        if bool(body.get("lock")):
            lock_settings()
            clear_unlocked_keys(mark_locked=True)
            snap = _build_sanitized_settings_snapshot(runtime)
            snap["message"] = "Settings locked in process memory."
            return snap, 200

        if "unlock_passphrase" in body:
            passphrase = str(body.get("unlock_passphrase") or "")
            try:
                unlock_settings(passphrase)
            except Exception as exc:
                return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
            try:
                runtime.rebind_storage_from_settings()
            except Exception:
                pass
            snap = _build_sanitized_settings_snapshot(runtime)
            snap["message"] = "Settings unlocked in process memory."
            return snap, 200

        session_overrides = body.get("session_overrides")
        if isinstance(session_overrides, dict):
            cleaned_sess: dict[str, str | None] = {}
            for k, v in session_overrides.items():
                canon = resolve_setting_key(str(k)) or str(k).strip()
                if is_sensitive_setting_key(canon) and str(v or "").strip() == "********":
                    continue
                cleaned_sess[canon] = None if v is None or str(v).strip() == "" else str(v)
            if cleaned_sess:
                set_session_overrides(cleaned_sess, vault_hydrated=False)
                if any(k in _DB_REBIND_KEYS for k in cleaned_sess):
                    try:
                        runtime.rebind_storage_from_settings()
                    except Exception:
                        pass
            snap = _build_sanitized_settings_snapshot(runtime)
            snap["message"] = "Session overrides updated in process memory."
            return snap, 200

        raw_updates = body.get("settings")
        if raw_updates is None and any(resolve_setting_key(k) for k in body):
            raw_updates = {k: v for k, v in body.items() if resolve_setting_key(k)}

        if not isinstance(raw_updates, dict):
            return {"ok": False, "error": "Expected 'settings', 'unlock_passphrase', or 'lock'."}, 400

        target_profile = str(body.get("profile") or "").strip() or None
        existing_saved = get_profile_settings(profile=target_profile)
        to_save: dict[str, str | None] = {}
        for raw_key, raw_val in raw_updates.items():
            resolved_key = resolve_setting_key(str(raw_key))
            if resolved_key is None:
                return {"ok": False, "error": f"Unknown setting key: {raw_key!r}"}, 400
            val_str = "" if raw_val is None else str(raw_val).strip()
            if val_str == "********" and is_sensitive_setting_key(resolved_key):
                if resolved_key in existing_saved:
                    saved_v = existing_saved[resolved_key]
                    to_save[resolved_key] = str(saved_v) if saved_v is not None else None
                continue
            to_save[resolved_key] = val_str if val_str else None

        validation_errors = validate_settings_values(
            {k: v for k, v in to_save.items() if v is not None}
        )
        if validation_errors:
            msg = "; ".join(f"{k}: {err}" for k, err in validation_errors)
            return {"ok": False, "error": msg}, 400

        try:
            save_profile_settings(to_save, profile=target_profile, replace=False)
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400

        if any(k in _DB_REBIND_KEYS for k in to_save):
            try:
                runtime.rebind_storage_from_settings()
            except Exception as exc:
                return {"ok": False, "error": f"Saved settings, but DB rebind failed: {redact_web_payload(str(exc))}"}, 400

        snap = _build_sanitized_settings_snapshot(runtime, profile=target_profile)
        snap["message"] = "Settings saved."
        return snap, 200

    payload, status = await anyio.to_thread.run_sync(_apply)
    return JSONResponse(payload, status_code=status)


async def unlock_settings_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    def _run() -> tuple[dict[str, Any], int]:
        passphrase = body.get("passphrase")
        if passphrase is None:
            passphrase = body.get("unlock_passphrase")
        try:
            unlock_settings(str(passphrase) if passphrase is not None else None)
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        try:
            runtime.rebind_storage_from_settings()
        except Exception:
            pass
        return _build_sanitized_settings_snapshot(runtime), 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def lock_settings_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime

    def _run() -> dict[str, Any]:
        lock_settings()
        clear_unlocked_keys(mark_locked=True)
        return _build_sanitized_settings_snapshot(runtime)

    payload = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload)


async def test_db_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    def _run() -> dict[str, Any]:
        overrides: dict[str, Any] = {"workspace_dir": runtime.workspace_dir}
        key_map = {
            "backend": "backend",
            "db_backend": "backend",
            "sqlite_path": "sqlite_path",
            "db_sqlite_path": "sqlite_path",
            "dsn": "dsn",
            "db_dsn": "dsn",
            "host": "host",
            "db_host": "host",
            "port": "port",
            "db_port": "port",
            "name": "database",
            "database": "database",
            "db_name": "database",
            "user": "username",
            "username": "username",
            "db_user": "username",
            "password": "password",
            "db_password": "password",
            "ssl_mode": "ssl_mode",
            "db_ssl_mode": "ssl_mode",
            "ssl_ca": "ssl_ca",
            "db_ssl_ca": "ssl_ca",
            "ssl_cert": "ssl_cert",
            "db_ssl_cert": "ssl_cert",
            "ssl_key": "ssl_key",
            "db_ssl_key": "ssl_key",
            "pool_size": "pool_size",
            "db_pool_size": "pool_size",
            "max_overflow": "max_overflow",
            "db_max_overflow": "max_overflow",
            "retention_days": "retention_days",
            "db_retention_days": "retention_days",
        }
        for src_key, dst_key in key_map.items():
            if src_key not in body:
                continue
            val = body.get(src_key)
            if val is None or str(val).strip() == "":
                continue
            if dst_key in ("password", "dsn") and str(val).strip() == "********":
                continue
            if dst_key in ("port", "pool_size", "max_overflow", "retention_days"):
                try:
                    if isinstance(val, bool):
                        raise ValueError("Boolean is not a valid integer")
                    overrides[dst_key] = int(val)
                except (TypeError, ValueError):
                    return {
                        "ok": False,
                        "dialect": str(body.get("backend") or "sqlite"),
                        "version": "",
                        "error": f"Invalid integer for {src_key}.",
                    }
            else:
                overrides[dst_key] = str(val).strip()

        try:
            cfg = get_database_config(**overrides)
        except (ConfigurationError, ValueError) as exc:
            err_text = _sanitize_db_error(exc)
            pw_val = str(overrides.get("password") or "")
            if pw_val:
                err_text = err_text.replace(pw_val, "<REDACTED>")
            return dict(
                redact_web_payload(
                    {
                        "ok": False,
                        "dialect": str(overrides.get("backend") or body.get("backend") or "sqlite"),
                        "version": "",
                        "error": err_text,
                    }
                )
            )
        res = test_db_connection(cfg)
        return dict(redact_web_payload(res))

    payload = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload)


async def list_profiles_endpoint(request: Request) -> JSONResponse:
    def _run() -> dict[str, Any]:
        return {
            "ok": True,
            "active_profile": get_active_profile_name(),
            "profiles": list_profiles(),
        }

    return JSONResponse(await anyio.to_thread.run_sync(_run))


async def activate_profile_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    profile = str(body.get("profile") or "").strip()
    if not profile:
        return JSONResponse({"ok": False, "error": "Missing profile name."}, status_code=400)

    def _run() -> tuple[dict[str, Any], int]:
        try:
            set_active_profile(profile, create=bool(body.get("create", True)))
            runtime.rebind_storage_from_settings()
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return _build_sanitized_settings_snapshot(runtime), 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def delete_profile_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    profile = str(body.get("profile") or "").strip()
    if not profile:
        return JSONResponse({"ok": False, "error": "Missing profile name."}, status_code=400)

    def _run() -> tuple[dict[str, Any], int]:
        try:
            delete_profile(profile)
            runtime.rebind_storage_from_settings()
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return _build_sanitized_settings_snapshot(runtime), 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def clear_profile_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    profile = str(body.get("profile") or "").strip() or None

    def _run() -> tuple[dict[str, Any], int]:
        try:
            clear_profile_settings(profile=profile)
            runtime.rebind_storage_from_settings()
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return _build_sanitized_settings_snapshot(runtime), 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def hydrate_secrets_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime
    try:
        body = await _parse_json_body(request)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    force = bool(body.get("force", True))
    overwrite = bool(body.get("overwrite_existing", False))

    def _run() -> tuple[dict[str, Any], int]:
        try:
            hydrated = hydrate_secrets_from_store(force=force, overwrite_existing=overwrite)
            runtime.rebind_storage_from_settings()
        except Exception as exc:
            return {"ok": False, "error": str(redact_web_payload(str(exc)))}, 400
        return {
            "ok": True,
            "hydrated_keys": sorted(hydrated.keys()),
            "count": len(hydrated),
        }, 200

    payload, status = await anyio.to_thread.run_sync(_run)
    return JSONResponse(payload, status_code=status)


async def test_connections_endpoint(request: Request) -> JSONResponse:
    runtime: WebRuntimeState = request.app.state.runtime

    def _run() -> dict[str, Any]:
        results: dict[str, Any] = {}
        try:
            rf = runtime.get_rf_client()
            if rf is None:
                results["recorded_future"] = {"ok": False, "error": "RF token not configured."}
            else:
                ok = rf.check_connection() if hasattr(rf, "check_connection") else True
                results["recorded_future"] = {"ok": bool(ok)}
        except Exception as exc:
            results["recorded_future"] = {"ok": False, "error": str(redact_web_payload(str(exc)))}

        try:
            cfg = get_splunk_config(required=False)
            if not cfg.has_auth:
                results["splunk"] = {"ok": False, "error": "Splunk credentials not configured."}
            else:
                ok_sp = SplunkValidator(
                    host=cfg.host,
                    token=cfg.token,
                    username=cfg.username,
                    password=cfg.password,
                    app=cfg.app,
                    verify_ssl=cfg.verify_ssl,
                ).check_connection()
                results["splunk"] = {"ok": bool(ok_sp)}
        except Exception as exc:
            results["splunk"] = {"ok": False, "error": str(redact_web_payload(str(exc)))}

        try:
            s1_cfg = get_sentinelone_config(required=False)
            if not s1_cfg.has_auth:
                results["sentinelone"] = {"ok": False, "error": "SentinelOne credentials not configured."}
            else:
                s1 = runtime.get_s1_client() or SentinelOneClient(config=s1_cfg)
                results["sentinelone"] = dict(redact_web_payload(s1.check_connection()))
        except Exception as exc:
            results["sentinelone"] = {"ok": False, "error": str(redact_web_payload(str(exc)))}

        try:
            llm_cfg = get_local_llm_config()
            llm = LocalLLMClient(llm_cfg)
            results["ai"] = dict(redact_web_payload(llm.check_connection()))
        except (ConfigurationError, Exception) as exc:
            results["ai"] = {"ok": False, "error": str(redact_web_payload(str(exc)))}

        try:
            results["database"] = dict(redact_web_payload(test_db_connection(runtime.storage.config)))
        except Exception as exc:
            results["database"] = {"ok": False, "error": str(redact_web_payload(str(exc)))}

        try:
            osint = runtime.get_osint_client() or OSINTClient()
            results["osint"] = {"ok": True, "enabled": bool(osint)}
        except Exception as exc:
            results["osint"] = {"ok": False, "error": str(redact_web_payload(str(exc)))}

        return {"ok": True, "results": results}

    return JSONResponse(await anyio.to_thread.run_sync(_run))


SETTINGS_ROUTES: list[Route] = [
    Route("/api/settings", get_settings_endpoint, methods=["GET"]),
    Route("/api/settings", post_settings_endpoint, methods=["POST"]),
    Route("/api/settings/unlock", unlock_settings_endpoint, methods=["POST"]),
    Route("/api/settings/lock", lock_settings_endpoint, methods=["POST"]),
    Route("/api/settings/test-db", test_db_endpoint, methods=["POST"]),
    Route("/api/settings/profiles", list_profiles_endpoint, methods=["GET"]),
    Route("/api/settings/profiles/activate", activate_profile_endpoint, methods=["POST"]),
    Route("/api/settings/profiles/delete", delete_profile_endpoint, methods=["POST"]),
    Route("/api/settings/profiles/clear", clear_profile_endpoint, methods=["POST"]),
    Route("/api/settings/hydrate-secrets", hydrate_secrets_endpoint, methods=["POST"]),
    Route("/api/settings/test-connections", test_connections_endpoint, methods=["POST"]),
]
