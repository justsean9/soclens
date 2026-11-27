"""Security middleware, secret masking, and SSE streaming tests for SOCLens Web."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from soclens.agent_audit import AuditLogStore
from soclens.agent_orchestrator import SocAgentOrchestrator
from soclens.agent_policy import AIPolicyStore
from soclens.agent_tools import ReadOnlyToolRegistry, ReadOnlyToolSpec
from soclens.config import LocalLLMConfig
from soclens.settings import save_profile_settings
from soclens.storage import DatabaseConfig, StorageManager
from soclens.web import create_app
from tests.test_web_server import _auth_headers, _call_asgi


def test_host_origin_sec_fetch_and_csrf_guards(tmp_path: Path) -> None:
    app = create_app(workspace_dir=tmp_path, bootstrap_token="sec-tok", bound_port=8765)
    try:
        # Missing / invalid / foreign Host headers rejected
        for bad_host in ("evil.example:8765", "127.0.0.1.evil.example:8765", "192.168.1.50:8765", "127.0.0.1:9999"):
            res = asyncio.run(_call_asgi(app, "GET", "/", headers={"Host": bad_host}))
            assert res.status in (400, 403), f"Expected rejection for Host={bad_host}, got {res.status}"

        no_host = asyncio.run(
            _call_asgi(
                app,
                "GET",
                "/",
                headers={"User-Agent": "probe"},
                include_default_host=False,
            )
        )
        assert no_host.status == 400

        # Origin & Sec-Fetch-Site checks
        for bad_origin in ("null", "https://attacker.example", "http://evil.local:8765", "http://127.0.0.1:9999"):
            res = asyncio.run(
                _call_asgi(app, "GET", "/", headers={"Host": "127.0.0.1:8765", "Origin": bad_origin})
            )
            assert res.status == 403

        cross_site = asyncio.run(
            _call_asgi(
                app,
                "GET",
                "/",
                headers={"Host": "127.0.0.1:8765", "Sec-Fetch-Site": "cross-site"},
            )
        )
        assert cross_site.status == 403

        # Unauthenticated /api/status rejected
        unauth = asyncio.run(_call_asgi(app, "GET", "/api/status", headers={"Host": "127.0.0.1:8765"}))
        assert unauth.status == 401

        tampered = asyncio.run(
            _call_asgi(
                app,
                "GET",
                "/api/status",
                headers={"Host": "127.0.0.1:8765", "Cookie": "soclens_session=tampered.invalid"},
            )
        )
        assert tampered.status == 401

        # Missing/bad CSRF rejected on POST
        hdrs = _auth_headers(app, "sec-tok")
        no_csrf = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/logs/clear",
                headers={"Host": "127.0.0.1:8765", "Cookie": hdrs["Cookie"]},
                json_body={},
            )
        )
        assert no_csrf.status == 403

        bad_csrf = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/logs/clear",
                headers={
                    "Host": "127.0.0.1:8765",
                    "Cookie": hdrs["Cookie"],
                    "X-SOCLens-Token": "wrong-csrf",
                },
                json_body={},
            )
        )
        assert bad_csrf.status == 403
    finally:
        app.state.runtime.cleanup()


def test_settings_api_never_leaks_secrets_partial_chars_or_vault_refs(tmp_path: Path) -> None:
    rf_secret = "rf-super-secret-token-987654"
    db_pass = "UltraSecretDbPassword!42"
    dsn_secret = "postgresql+pg8000://socuser:DsnPass99@db.internal:5432/soclens"
    vault_ref = "vault://kv/soclens/prod/rf_api_token"
    proxy_url = "http://proxyuser:ProxyPass77@proxy.corp.local:8080"

    save_profile_settings(
        {
            "rf_api_token": rf_secret,
            "db_password": db_pass,
            "db_dsn": dsn_secret,
            "vault_secret_map": json.dumps({"rf_api_token": vault_ref}),
            "https_proxy": proxy_url,
        }
    )

    storage = StorageManager(DatabaseConfig(sqlite_path=tmp_path / "test.db"))
    storage.ensure_schema()
    app = create_app(
        workspace_dir=tmp_path,
        bootstrap_token="mask-tok",
        session_state={"storage": storage},
    )
    try:
        hdrs = _auth_headers(app, "mask-tok")
        res = asyncio.run(_call_asgi(app, "GET", "/api/settings", headers=hdrs))
        assert res.status == 200
        raw_text = res.text

        # Neither full secrets, partial mask_secret() substrings, nor vault:// refs may appear
        for forbidden in (
            rf_secret,
            "rf-s",
            "7654",
            db_pass,
            "Ultr",
            "d!42",
            "DsnPass99",
            "ProxyPass77",
            "vault://",
            vault_ref,
        ):
            assert forbidden not in raw_text, f"Secret fragment {forbidden!r} leaked in /api/settings"

        items_by_key = {item["key"]: item for item in res.json()["settings"]}
        assert items_by_key["rf_api_token"]["value"] == "********"
        assert items_by_key["rf_api_token"]["configured"] is True
        assert items_by_key["vault_secret_map"]["value"] == "********"
        assert items_by_key["db_password"]["value"] == "********"
    finally:
        app.state.runtime.cleanup()


def test_sse_events_and_ai_chat_streaming(tmp_path: Path) -> None:
    class _StreamingMockLLM:
        config = LocalLLMConfig(provider="ollama", model="llama3.2")
        provider = "ollama"
        model = "llama3.2"

        def chat(self, messages: Any, **_kwargs: Any) -> dict[str, Any]:
            cb = _kwargs.get("stream_callback")
            if callable(cb):
                cb("Hello ")
                cb("SOC!")
            return {
                "content": "Hello SOC!",
                "provider": "ollama",
                "model": "llama3.2",
                "tool_calls": [],
            }

    app = create_app(
        workspace_dir=tmp_path,
        bootstrap_token="sse-tok",
        session_state={"llm_client": _StreamingMockLLM()},
    )
    try:
        hdrs = _auth_headers(app, "sse-tok")

        # Finite SSE status stream
        ev_res = asyncio.run(
            _call_asgi(app, "GET", "/api/events/stream", query_string="once=1", headers=hdrs)
        )
        assert ev_res.status == 200
        assert "text/event-stream" in ev_res.headers.get("content-type", "")
        assert "event: status" in ev_res.text

        # Empty prompt rejected cleanly with 400
        empty_res = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/ai/chat/stream",
                headers=hdrs,
                json_body={"prompt": "   "},
            )
        )
        assert empty_res.status == 400

        # /learn preview SSE
        learn_res = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/ai/chat/stream",
                headers=hdrs,
                json_body={"prompt": "/learn index=wineventlog holds Windows Security logs"},
            )
        )
        assert learn_res.status == 200
        assert "event: learn_preview" in learn_res.text

        # Streaming AI chat tokens
        chat_res = asyncio.run(
            _call_asgi(
                app,
                "POST",
                "/api/ai/chat/stream",
                headers=hdrs,
                json_body={"prompt": "Summarize triage findings", "enable_tools": False},
            )
        )
        assert chat_res.status == 200
        assert "event: token" in chat_res.text
        assert "Hello " in chat_res.text
        assert "event: done" in chat_res.text
    finally:
        app.state.runtime.cleanup()


def test_orchestrator_investigate_forwards_tool_event_callback(tmp_path: Path) -> None:
    registry = ReadOnlyToolRegistry()
    registry.register(
        ReadOnlyToolSpec(
            name="local_search_alerts_history",
            description="Search local alert history",
            source_category="local_db",
            parameters_schema={"type": "object", "properties": {"query": {"type": "string"}}},
            handler=lambda _args: {"items": [{"id": "a1"}]},
            readonly=True,
        )
    )

    class _ToolCallingLLM:
        config = LocalLLMConfig(provider="openai", model="gpt-4o-mini")
        provider = "openai"
        model = "gpt-4o-mini"

        def __init__(self) -> None:
            self.turn = 0

        def chat(self, _messages: Any, **_kwargs: Any) -> dict[str, Any]:
            self.turn += 1
            if self.turn == 1:
                return {
                    "content": "",
                    "provider": "openai",
                    "model": "gpt-4o-mini",
                    "tool_calls": [
                        {"id": "tc1", "name": "local_search_alerts_history", "arguments": {"query": "evil"}}
                    ],
                }
            return {"content": "Done.", "provider": "openai", "model": "gpt-4o-mini", "tool_calls": []}

    orch = SocAgentOrchestrator(
        registry=registry,
        policy_store=AIPolicyStore(path=tmp_path / "policy.json"),
        audit_store=AuditLogStore(path=tmp_path / "audit.jsonl"),
        llm_client_factory=lambda: _ToolCallingLLM(),
    )
    seen_events: list[dict[str, Any]] = []
    res = orch.investigate(
        event_key="ev-1",
        event_context="Suspicious activity",
        mode="full_investigation",
        question="Check history",
        provider="openai",
        tool_event_callback=seen_events.append,
    )
    assert res.status == "completed"
    assert any(ev.get("tool_name") == "local_search_alerts_history" for ev in seen_events)
