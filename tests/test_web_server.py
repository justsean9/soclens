"""Unit and live-server integration tests for the SOCLens standalone Web ASGI backend."""

from __future__ import annotations

import asyncio
import gc
import http.client
import json
import logging
import threading
import time
import weakref
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from soclens.agent_tools import READONLY_TOOL_NAMES
from soclens.client import RecordedFutureClient
from soclens.storage import StorageManager
from soclens.tui.logging_bridge import TuiLogHandler
from soclens.web import create_app, run_web_server


class ASGIResponse:
    def __init__(self, status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
        self.status = status
        self.raw_headers = headers
        self.body = body

    @property
    def headers(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in self.raw_headers:
            out[k.decode("latin-1").lower()] = v.decode("latin-1")
        return out

    @property
    def set_cookies(self) -> list[str]:
        return [
            v.decode("latin-1")
            for k, v in self.raw_headers
            if k.decode("latin-1").lower() == "set-cookie"
        ]

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


async def _call_asgi(
    app: Any,
    method: str,
    path: str,
    *,
    headers: Mapping[str, str] | None = None,
    json_body: Any = None,
    query_string: str = "",
    include_default_host: bool = True,
) -> ASGIResponse:
    req_headers: list[tuple[bytes, bytes]] = []
    if headers:
        has_host = False
        for k, v in headers.items():
            if k.lower() == "host":
                has_host = True
            req_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
        if include_default_host and not has_host:
            req_headers.insert(0, (b"host", b"127.0.0.1:8765"))
    elif include_default_host:
        req_headers.append((b"host", b"127.0.0.1:8765"))

    body_bytes = b""
    if json_body is not None:
        body_bytes = json.dumps(json_body).encode("utf-8")
        req_headers.append((b"content-type", b"application/json"))
        req_headers.append((b"content-length", str(len(body_bytes)).encode("ascii")))

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": query_string.encode("ascii"),
        "root_path": "",
        "headers": req_headers,
        "client": ("127.0.0.1", 54321),
        "server": ("127.0.0.1", 8765),
    }

    sent_once = False
    disconnect_waiter = asyncio.Event()

    async def receive() -> dict[str, Any]:
        nonlocal sent_once
        if not sent_once:
            sent_once = True
            return {"type": "http.request", "body": body_bytes, "more_body": False}
        await disconnect_waiter.wait()
        return {"type": "http.disconnect"}

    status_code = 500
    resp_headers: list[tuple[bytes, bytes]] = []
    chunks: list[bytes] = []

    async def send(message: dict[str, Any]) -> None:
        nonlocal status_code, resp_headers
        if message["type"] == "http.response.start":
            status_code = int(message["status"])
            resp_headers = list(message.get("headers") or [])
        elif message["type"] == "http.response.body":
            chunks.append(bytes(message.get("body") or b""))

    await app(scope, receive, send)
    return ASGIResponse(status_code, resp_headers, b"".join(chunks))


def _auth_headers(app: Any, token: str) -> dict[str, str]:
    res = asyncio.run(
        _call_asgi(
            app,
            "POST",
            "/api/auth/exchange",
            json_body={"token": token},
        )
    )
    assert res.status == 200
    data = res.json()
    assert data["ok"] is True
    cookie_pair = res.set_cookies[0].split(";", 1)[0]
    return {
        "Host": "127.0.0.1:8765",
        "Cookie": cookie_pair,
        "X-SOCLens-Token": data["csrf_token"],
    }


def test_create_app_initializes_synchronously_without_lifespan(tmp_path: Path) -> None:
    app = create_app(workspace_dir=tmp_path, bootstrap_token="test-token-123")
    try:
        runtime = app.state.runtime
        assert (tmp_path / ".soclens_cache" / "soclens.db").is_file()
        assert runtime.web_layout_profile.endswith("::web")

        index_res = asyncio.run(_call_asgi(app, "GET", "/"))
        assert index_res.status == 200
        assert "SOCLens" in index_res.text
        assert index_res.headers.get("cache-control") == "no-store"

        hdrs = _auth_headers(app, "test-token-123")
        status_res = asyncio.run(_call_asgi(app, "GET", "/api/status", headers=hdrs))
        assert status_res.status == 200
        status_json = status_res.json()
        assert status_json["ok"] is True
        assert status_json["admin_enabled"] is False
        assert status_json["dialect"] == "sqlite"
    finally:
        app.state.runtime.cleanup()


def test_web_workspace_layout_does_not_collide_with_tui(tmp_path: Path) -> None:
    app = create_app(workspace_dir=tmp_path, bootstrap_token="layout-tok")
    try:
        runtime = app.state.runtime
        storage: StorageManager = runtime.storage
        storage.save_workspace_layout(mode="tabbed", state={"tui": True})

        hdrs = _auth_headers(app, "layout-tok")
        save_res = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/workspace/layout",
                headers=hdrs,
                json_body={"mode": "tiling", "state": {"workspaces": {"1": {"type": "leaf"}}}},
            )
        )
        assert save_res.status == 200

        tui_loaded = storage.load_workspace_layout()
        web_loaded = asyncio.run(_call_asgi(app, "GET", "/api/workspace/layout", headers=hdrs)).json()
        assert tui_loaded["mode"] == "tabbed"
        assert tui_loaded["state"] == {"tui": True}
        assert web_loaded["mode"] == "tiling"
        assert web_loaded["profile_name"].endswith("::web")
    finally:
        app.state.runtime.cleanup()


def test_alerts_and_image_endpoint_validation(tmp_path: Path) -> None:
    app = create_app(workspace_dir=tmp_path, bootstrap_token="img-tok")
    try:
        runtime = app.state.runtime
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        runtime.alert_cache.put(
            "rf_playbook_24h",
            [{"id": "pb-1", "title": "Domain Abuse"}],
            meta={"image_keys": {"pb-1": [["domain_abuse", "img1", "domain_abuse__pb-1__img1"]]}},
        )
        runtime.alert_cache.put_image_bytes("domain_abuse__pb-1__img1", png_bytes)

        hdrs = _auth_headers(app, "img-tok")
        alerts_res = asyncio.run(
            _call_asgi(
                app,
                "GET",
                "/api/alerts",
                query_string="source=rf_playbook_24h",
                headers=hdrs,
            )
        )
        assert alerts_res.status == 200
        assert len(alerts_res.json()["items"]) == 1

        img_res = asyncio.run(
            _call_asgi(
                app,
                "GET",
                "/api/alerts/image/domain_abuse__pb-1__img1",
                headers=hdrs,
            )
        )
        assert img_res.status == 200
        assert img_res.body == png_bytes
        assert img_res.headers.get("content-type") == "image/png"
        assert "no-store" in img_res.headers.get("cache-control", "")

        for bad_key in ("missing-img", "bad;key", "..etc..passwd"):
            bad_res = asyncio.run(
                _call_asgi(app, "GET", f"/api/alerts/image/{bad_key}", headers=hdrs)
            )
            assert bad_res.status == 404
    finally:
        app.state.runtime.cleanup()


def test_splunk_search_enforces_readonly_spl(tmp_path: Path) -> None:
    class _DummySplunk:
        def __init__(self) -> None:
            self.queries: list[str] = []

        def run_search(self, spl: str, **_kwargs: Any) -> dict[str, Any]:
            self.queries.append(spl)
            return {"results": [{"host": "srv-1", "count": "3"}]}

    dummy_splunk = _DummySplunk()
    app = create_app(
        workspace_dir=tmp_path,
        bootstrap_token="spl-tok",
        session_state={"splunk_client": dummy_splunk},
    )
    try:
        hdrs = _auth_headers(app, "spl-tok")
        blocked = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/splunk/search",
                headers=hdrs,
                json_body={"spl": "index=* | outputlookup evil.csv"},
            )
        )
        assert blocked.status == 400
        assert blocked.json()["blocked"] is True
        assert dummy_splunk.queries == []

        allowed = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/splunk/search",
                headers=hdrs,
                json_body={"spl": "search index=main | head 5"},
            )
        )
        assert allowed.status == 200
        assert len(dummy_splunk.queries) == 1
    finally:
        app.state.runtime.cleanup()


def test_admin_endpoints_gated_and_knowledge_lifecycle(tmp_path: Path) -> None:
    user_app = create_app(workspace_dir=tmp_path / "u", admin_enabled=False, bootstrap_token="u-tok")
    try:
        u_hdrs = _auth_headers(user_app, "u-tok")
        denied = asyncio.run(_call_asgi(user_app, "GET", "/api/admin/dashboard", headers=u_hdrs))
        assert denied.status == 403
    finally:
        user_app.state.runtime.cleanup()

    admin_app = create_app(workspace_dir=tmp_path / "a", admin_enabled=True, bootstrap_token="a-tok")
    try:
        a_hdrs = _auth_headers(admin_app, "a-tok")
        dash = asyncio.run(_call_asgi(admin_app, "GET", "/api/admin/dashboard", headers=a_hdrs))
        assert dash.status == 200
        assert dash.json()["ok"] is True

        pol = asyncio.run(_call_asgi(admin_app, "GET", "/api/ai/policy", headers=a_hdrs)).json()
        assert set(pol["readonly_tools"]) == set(READONLY_TOOL_NAMES)

        learned = asyncio.run(
            _call_asgi(
                admin_app,
                "POST",
                "/api/knowledge/learn",
                headers=a_hdrs,
                json_body={
                    "title": "Internal Bastion Host",
                    "content": "bastion-01.corp.local is authorized for jump sessions.",
                    "category": "environment_fact",
                },
            )
        )
        assert learned.status == 200
        entry_id = learned.json()["entry"]["id"]

        pinned = asyncio.run(
            _call_asgi(
                admin_app,
                "POST",
                f"/api/knowledge/{entry_id}/pin",
                headers=a_hdrs,
                json_body={"pinned": True},
            )
        )
        assert pinned.status == 200
        assert pinned.json()["entry"]["pinned"] is True

        listed = asyncio.run(_call_asgi(admin_app, "GET", "/api/knowledge", headers=a_hdrs)).json()
        assert any(e["id"] == entry_id for e in listed["entries"])

        audit = asyncio.run(_call_asgi(admin_app, "GET", "/api/audit", headers=a_hdrs)).json()
        assert len(audit["entries"]) >= 1
    finally:
        admin_app.state.runtime.cleanup()


def test_settings_test_db_and_live_uvicorn_shutdown(tmp_path: Path) -> None:
    ready_info: dict[str, Any] = {}
    ready_event = threading.Event()

    def _on_ready(port: int, url: str, runtime: Any) -> None:
        ready_info["port"] = port
        ready_info["url"] = url
        ready_info["runtime"] = runtime
        ready_event.set()

    server_thread = threading.Thread(
        target=run_web_server,
        kwargs={
            "port": 0,
            "open_browser": False,
            "admin": False,
            "workspace_dir": tmp_path,
            "bootstrap_token": "live-tok-999",
            "session_state": {"rf_client": RecordedFutureClient(api_token="rf-test")},
            "on_ready": _on_ready,
        },
        daemon=True,
    )
    server_thread.start()
    assert ready_event.wait(timeout=8.0)
    port = int(ready_info["port"])
    assert port > 0

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        conn.request(
            "POST",
            "/api/auth/exchange",
            body=json.dumps({"token": "live-tok-999"}),
            headers={"Content-Type": "application/json"},
        )
        ex_resp = conn.getresponse()
        ex_body = json.loads(ex_resp.read().decode("utf-8"))
        assert ex_resp.status == 200
        cookie_hdr = ex_resp.getheader("Set-Cookie") or ""
        assert "HttpOnly" in cookie_hdr and "SameSite=Strict" in cookie_hdr
        cookie_val = cookie_hdr.split(";", 1)[0]
        csrf = ex_body["csrf_token"]

        conn.request(
            "POST",
            "/api/settings/test-db",
            body=json.dumps({"backend": "sqlite", "sqlite_path": str(tmp_path / "probe.db")}),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie_val,
                "X-SOCLens-Token": csrf,
            },
        )
        db_resp = conn.getresponse()
        db_json = json.loads(db_resp.read().decode("utf-8"))
        assert db_resp.status == 200
        assert db_json["ok"] is True
        assert db_json["dialect"] == "sqlite"

        conn.request(
            "POST",
            "/api/shutdown",
            body="{}",
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie_val,
                "X-SOCLens-Token": csrf,
            },
        )
        sd_resp = conn.getresponse()
        assert sd_resp.status == 200
        assert json.loads(sd_resp.read().decode("utf-8"))["shutting_down"] is True
    finally:
        conn.close()

    server_thread.join(timeout=5.0)
    assert not server_thread.is_alive()
    time.sleep(0.05)


def test_create_app_and_unlock_survive_unreachable_external_db(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    from soclens.settings import (
        encrypt_settings_store,
        invalidate_settings_cache,
        lock_settings,
        save_profile_settings,
    )

    db_pw = "UnreachableDbSecret99!"
    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(tmp_path / "settings.json"))
    invalidate_settings_cache()

    save_profile_settings(
        {
            "db_backend": "postgres",
            "db_dsn": f"postgresql+pg8000://soc:{db_pw}@127.0.0.1:1/soclens",
            "rf_api_token": "rf-vault-secret-123",
        }
    )
    encrypt_settings_store(mode="passphrase", passphrase="VaultPass!23")
    lock_settings()

    monkeypatch.setenv(
        "DATABASE_URL",
        f"postgresql+pg8000://soc:{db_pw}@127.0.0.1:1/soclens",
    )
    app = create_app(workspace_dir=tmp_path, bootstrap_token="degraded-tok")
    try:
        runtime = app.state.runtime
        assert runtime.storage_error is not None
        assert db_pw not in runtime.storage_error

        hdrs = _auth_headers(app, "degraded-tok")
        status_res = asyncio.run(_call_asgi(app, "GET", "/api/status", headers=hdrs))
        assert status_res.status == 200
        status_json = status_res.json()
        assert status_json["ok"] is True
        assert status_json["storage_ok"] is False
        assert db_pw not in status_res.text

        unlock_res = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/settings/unlock",
                headers=hdrs,
                json_body={"passphrase": "VaultPass!23"},
            )
        )
        assert unlock_res.status == 200
        unlock_json = unlock_res.json()
        assert unlock_json["locked"] is False
        assert unlock_json["storage_ok"] is False
        assert db_pw not in unlock_res.text
        assert "rf-vault-secret-123" not in unlock_res.text
    finally:
        app.state.runtime.cleanup()


def test_test_db_endpoint_maps_name_and_user_and_handles_invalid_config(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    from tests.db_test_helpers import install_mock_db_drivers

    install_mock_db_drivers(monkeypatch)
    app = create_app(workspace_dir=tmp_path, bootstrap_token="testdb-tok")
    try:
        hdrs = _auth_headers(app, "testdb-tok")

        captured_cfgs: list[Any] = []
        import soclens.web.api_settings as api_settings_mod

        orig_test_db = api_settings_mod.test_db_connection

        def _spy_test_db(cfg: Any) -> dict[str, Any]:
            captured_cfgs.append(cfg)
            return orig_test_db(cfg)

        monkeypatch.setattr(api_settings_mod, "test_db_connection", _spy_test_db)

        pg_res = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/settings/test-db",
                headers=hdrs,
                json_body={
                    "backend": "postgres",
                    "host": "127.0.0.1",
                    "port": 5432,
                    "name": "soclens",
                    "user": "soc",
                    "password": "pw",
                },
            )
        )
        assert pg_res.status == 200
        pg_json = pg_res.json()
        assert pg_json["ok"] is True
        assert pg_json["dialect"] == "postgres"
        assert captured_cfgs[-1].database == "soclens"
        assert captured_cfgs[-1].username == "soc"

        for bad_body in (
            {"backend": "postgres", "port": 0},
            {"backend": "oracle", "host": "127.0.0.1"},
            {"backend": "postgres", "port": True},
        ):
            bad_res = asyncio.run(
                _call_asgi(
                    app,
                    "POST",
                    "/api/settings/test-db",
                    headers=hdrs,
                    json_body=bad_body,
                )
            )
            assert bad_res.status == 200
            assert bad_res.json()["ok"] is False
            assert bad_res.json()["error"]
    finally:
        app.state.runtime.cleanup()


def test_admin_watchlists_add_remove_and_es_bundle_validation(tmp_path: Path) -> None:
    class _SpyRF(RecordedFutureClient):
        def __init__(self) -> None:
            super().__init__(api_token="rf-spy-tok")
            self.calls: list[tuple[str, str, Any]] = []

        def _request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
            self.calls.append((method, endpoint, kwargs.get("json_data")))

            class _Resp:
                status_code = 200

                def json(self) -> dict[str, Any]:
                    return {"result": "ok"}

            return _Resp()

    class _SpyES:
        def __init__(self) -> None:
            self.toggles: list[tuple[str, bool]] = []

        def set_correlation_search_enabled(self, name: str, *, enabled: bool) -> dict[str, Any]:
            self.toggles.append((name, enabled))
            return {"name": name, "enabled": enabled}

    spy_rf = _SpyRF()
    spy_es = _SpyES()
    app = create_app(
        workspace_dir=tmp_path,
        admin_enabled=True,
        bootstrap_token="wl-tok",
        session_state={"rf_client": spy_rf, "splunk_es_client": spy_es},
    )
    try:
        hdrs = _auth_headers(app, "wl-tok")

        add_dom = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/admin/watchlists",
                headers=hdrs,
                json_body={
                    "action": "add_entity",
                    "list_id": "wl-123",
                    "entity": "evil.example",
                    "double_confirmed": True,
                },
            )
        )
        assert add_dom.status == 200
        assert spy_rf.calls[-1][1] == "/list/wl-123/entity/add"
        assert spy_rf.calls[-1][2] == {
            "entity": {"type": "InternetDomainName", "name": "evil.example"}
        }

        add_ip = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/admin/watchlists",
                headers=hdrs,
                json_body={
                    "action": "add_entity",
                    "list_id": "wl-123",
                    "entity": "198.51.100.10",
                    "double_confirmed": True,
                },
            )
        )
        assert add_ip.status == 200
        assert spy_rf.calls[-1][2] == {"entity": {"type": "IpAddress", "name": "198.51.100.10"}}

        add_id = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/admin/watchlists",
                headers=hdrs,
                json_body={
                    "action": "add_entity",
                    "list_id": "wl-123",
                    "entity": "idn:evil.example",
                    "double_confirmed": True,
                },
            )
        )
        assert add_id.status == 200
        assert spy_rf.calls[-1][2] == {"entity": {"id": "idn:evil.example"}}

        rem_dom = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/admin/watchlists",
                headers=hdrs,
                json_body={
                    "action": "remove_entity",
                    "list_id": "wl-123",
                    "entity": "evil.example",
                    "double_confirmed": True,
                },
            )
        )
        assert rem_dom.status == 200
        assert spy_rf.calls[-1][1] == "/list/wl-123/entity/remove"
        assert spy_rf.calls[-1][2] == {
            "entity": {"type": "InternetDomainName", "name": "evil.example"}
        }

        bad_corr = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/splunk-es/correlation-toggle",
                headers=hdrs,
                json_body={"name": "   ", "enabled": True, "double_confirmed": True},
            )
        )
        assert bad_corr.status == 400
        assert spy_es.toggles == []

        bad_conf = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/admin/splunk-bundle",
                headers=hdrs,
                json_body={"action": "validate", "conf_path": "../../etc/passwd"},
            )
        )
        assert bad_conf.status == 400
    finally:
        app.state.runtime.cleanup()


def test_create_app_discarded_without_lifespan_detaches_handler_and_disposes_storage_without_gc(
    tmp_path: Path,
) -> None:
    pkg_logger = logging.getLogger("soclens")
    before = sum(isinstance(h, TuiLogHandler) for h in pkg_logger.handlers)

    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        app = create_app(workspace_dir=tmp_path, bootstrap_token="gc-probe-tok")
        during = sum(isinstance(h, TuiLogHandler) for h in pkg_logger.handlers)
        assert during == before + 1

        rt_ref = weakref.ref(app.state.runtime)
        storage = app.state.runtime.storage
        assert storage._engine is not None

        del app
        assert rt_ref() is None
        after = sum(isinstance(h, TuiLogHandler) for h in pkg_logger.handlers)
        assert after == before
        assert storage._engine is None
    finally:
        if gc_was_enabled:
            gc.enable()


def test_create_app_without_lifespan_captures_logs_and_sse_then_detaches_on_delete(
    tmp_path: Path,
) -> None:
    pkg_logger = logging.getLogger("soclens")
    web_logger = logging.getLogger("soclens.web")
    before = sum(isinstance(h, TuiLogHandler) for h in pkg_logger.handlers)

    app = create_app(workspace_dir=tmp_path, bootstrap_token="log-sse-tok")
    rt_ref = weakref.ref(app.state.runtime)
    storage = app.state.runtime.storage
    hdrs = _auth_headers(app, "log-sse-tok")

    async def _stream_log_event(asgi_app: Any) -> str:
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/events/stream",
            "raw_path": b"/api/events/stream",
            "query_string": b"",
            "root_path": "",
            "headers": [
                (k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in hdrs.items()
            ],
            "client": ("127.0.0.1", 54321),
            "server": ("127.0.0.1", 8765),
        }
        chunks: list[bytes] = []
        sent_req = False
        disconnect_ev = asyncio.Event()
        got_log_ev = asyncio.Event()
        got_initial_ev = asyncio.Event()

        async def receive() -> dict[str, Any]:
            nonlocal sent_req
            if not sent_req:
                sent_req = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await disconnect_ev.wait()
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.body":
                body = bytes(message.get("body") or b"")
                if body:
                    chunks.append(body)
                    joined = b"".join(chunks).decode("utf-8", errors="replace")
                    if "event: status" in joined:
                        got_initial_ev.set()
                    if "event: log" in joined and "live-log-probe-xyz" in joined:
                        got_log_ev.set()

        task = asyncio.create_task(asgi_app(scope, receive, send))
        try:
            await asyncio.wait_for(got_initial_ev.wait(), timeout=5.0)
            web_logger.warning("live-log-probe-xyz")
            await asyncio.wait_for(got_log_ev.wait(), timeout=5.0)
        finally:
            disconnect_ev.set()
            await asyncio.wait_for(task, timeout=5.0)
        return b"".join(chunks).decode("utf-8", errors="replace")

    sse_text = asyncio.run(_stream_log_event(app))
    assert "event: log" in sse_text
    assert "live-log-probe-xyz" in sse_text

    logs_res = asyncio.run(_call_asgi(app, "GET", "/api/logs", headers=hdrs))
    assert logs_res.status == 200
    assert any("live-log-probe-xyz" in str(e.get("message", "")) for e in logs_res.json()["entries"])

    del app
    gc.collect()
    assert rt_ref() is None
    assert sum(isinstance(h, TuiLogHandler) for h in pkg_logger.handlers) == before
    assert storage._engine is None


def test_web_lifespan_and_cleanup_remain_idempotent(tmp_path: Path) -> None:
    pkg_logger = logging.getLogger("soclens")
    before = sum(isinstance(h, TuiLogHandler) for h in pkg_logger.handlers)

    app = create_app(workspace_dir=tmp_path, bootstrap_token="life-tok")
    runtime = app.state.runtime
    storage = runtime.storage
    assert sum(isinstance(h, TuiLogHandler) for h in pkg_logger.handlers) == before + 1

    async def _run_lifespan(asgi_app: Any) -> None:
        async with asgi_app.router.lifespan_context(asgi_app):
            res = await _call_asgi(asgi_app, "GET", "/")
            assert res.status == 200

    asyncio.run(_run_lifespan(app))
    assert runtime.shutdown_event.is_set()
    assert sum(isinstance(h, TuiLogHandler) for h in pkg_logger.handlers) == before
    assert storage._engine is None

    # Repeated cleanup() and subsequent deletion are safe no-ops
    runtime.cleanup()
    runtime.cleanup()
    del runtime
    del app
    gc.collect()
    assert sum(isinstance(h, TuiLogHandler) for h in pkg_logger.handlers) == before
