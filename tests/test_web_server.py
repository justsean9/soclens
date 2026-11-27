"""Unit and live-server integration tests for the SOCLens standalone Web ASGI backend."""

from __future__ import annotations

import asyncio
import http.client
import json
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from soclens.agent_tools import READONLY_TOOL_NAMES
from soclens.client import RecordedFutureClient
from soclens.storage import StorageManager
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
