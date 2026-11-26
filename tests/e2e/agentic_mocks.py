"""Offline mock HTTP servers, correlated SOC fixtures, and Pilot helpers for Agentic SOC E2E tests."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import time
import urllib.parse
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

import pytest

import tests.e2e.conftest as _e2e_conftest
import tests.e2e.v21_mocks as _v21_mocks
from soclens.osint import OSINTClient
from soclens.settings import clear_session_overrides, invalidate_settings_cache
from tests.e2e.v21_mocks import _BaseV21MockServer, _header_ci, _now_iso

# Re-export existing backend server fixtures so test modules can declare them directly
# without modifying tests/e2e/conftest.py or tests/e2e/v21_mocks.py.
v21_workspace = _v21_mocks.v21_workspace
mock_rf_server = _e2e_conftest.mock_rf_server
mock_splunk_es_server = _v21_mocks.mock_splunk_es_server
mock_s1_server = _v21_mocks.mock_s1_server

_AGENTIC_ENV_PREFIXES: tuple[str, ...] = (
    "SOCLENS_MS_COPILOT_",
    "MS_COPILOT_",
    "SOCLENS_MS_SECURITY_COPILOT_",
    "SOCLENS_OSINT_",
)

_AGENTIC_ENV_KEYS: frozenset[str] = frozenset(
    {
        "SOCLENS_LLM_VISIBLE_PROVIDERS",
        "RF_LLM_API_KEY",
        "RF_LLM_TIMEOUT",
        "RF_LLM_TEMPERATURE",
        "RF_LLM_MAX_TOKENS",
        "RF_LLM_VERIFY_SSL",
        "SOCLENS_ALERT_CACHE_REFRESH_SECONDS",
    }
)

_MUTATING_SPL_COMMANDS_RE_CACHE: re.Pattern[str] | None = None


def _get_mutating_spl_commands_re() -> re.Pattern[str]:
    """Build the mutating SPL command regex lazily from ``soclens.agent_tools``."""
    global _MUTATING_SPL_COMMANDS_RE_CACHE
    if _MUTATING_SPL_COMMANDS_RE_CACHE is None:
        from soclens.agent_tools import FORBIDDEN_SPL_COMMANDS

        _MUTATING_SPL_COMMANDS_RE_CACHE = re.compile(
            r"(?:^|\||\[)\s*(?:"
            + "|".join(re.escape(cmd) for cmd in sorted(FORBIDDEN_SPL_COMMANDS, key=len, reverse=True))
            + r")\b",
            re.IGNORECASE,
        )
    return _MUTATING_SPL_COMMANDS_RE_CACHE


@pytest.fixture
def agentic_workspace(
    v21_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """Extend ``v21_workspace`` by scrubbing Copilot, LLM, OSINT, and cache refresh env vars."""
    for key in list(os.environ):
        if key.startswith(_AGENTIC_ENV_PREFIXES) or key in _AGENTIC_ENV_KEYS:
            monkeypatch.delenv(key, raising=False)
    # Preserve tests/conftest.py offline default unless mock_osint_server enables it.
    monkeypatch.setenv("SOCLENS_OSINT_ENABLED", "false")
    clear_session_overrides()
    invalidate_settings_cache()
    try:
        yield v21_workspace
    finally:
        clear_session_overrides()
        invalidate_settings_cache()


class MockAgenticLLMAndCopilotServer(_BaseV21MockServer):
    """Unified localhost HTTP mock serving all 7 SOCLens LLM and Copilot providers.

    Supported providers & routes:
    - ``ollama``: ``GET /api/tags``, ``POST /api/chat`` (native ``tool_calls`` + ``<tool_call>`` + NDJSON)
    - ``openai``: ``GET /v1/models``, ``POST /v1/chat/completions`` (native ``tool_calls`` + ``<tool_call>`` + SSE)
    - ``gemini``: ``GET /v1beta/models``, ``POST /v1beta/models/{m}:generateContent``,
      ``POST /v1beta/models/{m}:streamGenerateContent?alt=sse`` (native ``functionCall`` + ``<tool_call>`` + SSE)
    - ``m365_copilot``: ``GET /graph/beta/me``, ``POST /graph/beta/copilot/conversations``,
      ``POST .../chat``, ``POST .../chatOverStream`` (SSE)
    - ``copilot_studio`` (D2E): ``POST /copilotstudio/.../bots/{bot}/conversations``,
      ``POST /copilotstudio/.../bots/{bot}/conversations/{id}`` (SSE)
    - ``copilot_directline``: ``GET /powerplatform/directline/token``,
      ``POST /v3/directline/tokens/generate``, ``POST /v3/directline/conversations``,
      ``GET|POST /v3/directline/conversations/{id}/activities``
    - ``security_copilot``: ``GET /graph/beta/security/securityCopilot/workspaces/{ws}``,
      ``POST .../sessions``, ``POST .../prompts``, ``POST .../evaluations``, ``GET .../evaluations/{eid}``
    """

    def __init__(self) -> None:
        self._responder: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        super().__init__()
        self.ollama_base_url: str = self.base_url
        self.openai_base_url: str = f"{self.base_url}/v1"
        self.gemini_base_url: str = f"{self.base_url}/v1beta"
        self.graph_base_url: str = f"{self.base_url}/graph/beta"
        self.directline_base_url: str = f"{self.base_url}/v3/directline"
        self.directline_token_endpoint: str = f"{self.base_url}/powerplatform/directline/token"
        self.d2e_url: str = (
            f"{self.base_url}/copilotstudio/agenticruntime/3p/dataverse-backed/"
            "authenticated/bots/soc-agent/conversations?api-version=2022-03-01-preview"
        )
        self.d2e_unauth_url: str = (
            f"{self.base_url}/copilotstudio/agenticruntime/3p/dataverse-backed/"
            "bots/soc-agent/conversations?api-version=2022-03-01-preview"
        )

    def _reset_state_locked(self) -> None:
        self._responder = None
        self.state = {
            "ollama_models": [
                {"name": "llama3.2:latest", "model": "llama3.2:latest", "size": 2048000000},
                {"name": "qwen2.5:14b", "model": "qwen2.5:14b", "size": 8192000000},
            ],
            "openai_models": [
                {"id": "qwen2.5-coder:7b", "object": "model", "owned_by": "local.example.test"},
                {"id": "gpt-4o-mini", "object": "model", "owned_by": "local.example.test"},
            ],
            "gemini_models": [
                {
                    "name": "models/gemini-2.5-flash",
                    "displayName": "Gemini 2.5 Flash",
                    "supportedGenerationMethods": ["generateContent", "countTokens"],
                },
                {
                    "name": "models/gemini-2.5-pro",
                    "displayName": "Gemini 2.5 Pro",
                    "supportedGenerationMethods": ["generateContent", "countTokens"],
                },
                {
                    "name": "models/text-embedding-004",
                    "displayName": "Text Embedding 004",
                    "supportedGenerationMethods": ["embedContent"],
                },
            ],
            "required_api_key": None,
            "required_bearer_token": None,
            "queued_turns": [],
            "turn_counter": 0,
            "conv_counter": 0,
            "m365_conversations": {},
            "d2e_conversations": {},
            "dl_tokens": set(),
            "dl_conversations": {},
            "sc_sessions": {},
            "sc_prompts": {},
            "sc_evaluations": {},
            "sc_eval_polls_before_done": 1,
            "default_reply": "SOCLens synthetic agentic investigation summary.",
        }

    def set_required_api_key(self, key: str | None) -> None:
        with self._lock:
            self.state["required_api_key"] = key

    def set_required_bearer_token(self, token: str | None) -> None:
        with self._lock:
            self.state["required_bearer_token"] = token

    def set_security_copilot_polls(self, polls_running: int) -> None:
        with self._lock:
            self.state["sc_eval_polls_before_done"] = max(0, int(polls_running))

    def set_responder(
        self,
        fn: Callable[[dict[str, Any]], dict[str, Any]] | None,
    ) -> None:
        with self._lock:
            self._responder = fn

    def queue_scripted_turn(
        self,
        *,
        provider: str | None = None,
        content: str = "",
        tool_calls: list[dict[str, Any]] | None = None,
        chunks: list[str] | None = None,
        status_code: int = 200,
        error_body: Any = None,
    ) -> None:
        """Queue a deterministic turn response (native tool_calls and/or text/<tool_call>)."""
        with self._lock:
            self.state["queued_turns"].append(
                {
                    "provider": provider,
                    "content": content,
                    "tool_calls": copy.deepcopy(tool_calls) if tool_calls is not None else None,
                    "chunks": list(chunks) if chunks is not None else None,
                    "status_code": int(status_code),
                    "error_body": copy.deepcopy(error_body),
                }
            )

    def clear_scripted_turns(self) -> None:
        with self._lock:
            self.state["queued_turns"].clear()

    def configure_provider(
        self,
        monkeypatch: pytest.MonkeyPatch,
        provider: str,
        *,
        model: str | None = None,
        token: str = "e2e-ms-copilot-token-opaque-001",
        api_key: str = "e2e-openai-api-key-001",
        workspace: str = "default",
        poll_interval: float = 0.1,
    ) -> None:
        """Configure environment variables so ``get_local_llm_config`` targets this mock server."""
        monkeypatch.setenv("RF_LLM_PROVIDER", provider)
        if model is not None:
            monkeypatch.setenv("RF_LLM_MODEL", model)
        elif provider == "ollama":
            monkeypatch.setenv("RF_LLM_MODEL", "llama3.2:latest")
        elif provider == "openai":
            monkeypatch.setenv("RF_LLM_MODEL", "qwen2.5-coder:7b")
        elif provider == "gemini":
            monkeypatch.setenv("RF_LLM_MODEL", "gemini-2.5-flash")
        else:
            monkeypatch.delenv("RF_LLM_MODEL", raising=False)

        if provider == "ollama":
            monkeypatch.setenv("RF_LLM_BASE_URL", self.ollama_base_url)
        elif provider == "openai":
            monkeypatch.setenv("RF_LLM_BASE_URL", self.openai_base_url)
            monkeypatch.setenv("RF_LLM_API_KEY", api_key)
        elif provider == "gemini":
            monkeypatch.setenv("GEMINI_BASE_URL", self.gemini_base_url)
            monkeypatch.setenv("GEMINI_API_KEY", api_key)
        elif provider == "m365_copilot":
            monkeypatch.setenv("SOCLENS_MS_COPILOT_GRAPH_URL", self.graph_base_url)
            monkeypatch.setenv("SOCLENS_MS_COPILOT_TOKEN", token)
            monkeypatch.setenv("SOCLENS_MS_COPILOT_AUTH_MODE", "token")
        elif provider == "security_copilot":
            monkeypatch.setenv("SOCLENS_MS_COPILOT_GRAPH_URL", self.graph_base_url)
            monkeypatch.setenv("SOCLENS_MS_COPILOT_TOKEN", token)
            monkeypatch.setenv("SOCLENS_MS_COPILOT_AUTH_MODE", "token")
            monkeypatch.setenv("SOCLENS_MS_SECURITY_COPILOT_WORKSPACE", workspace)
            monkeypatch.setenv("SOCLENS_MS_SECURITY_COPILOT_POLL_INTERVAL", str(poll_interval))
        elif provider == "copilot_directline":
            monkeypatch.setenv("SOCLENS_MS_COPILOT_DIRECTLINE_URL", self.directline_base_url)
            monkeypatch.setenv("SOCLENS_MS_COPILOT_TOKEN_ENDPOINT", self.directline_token_endpoint)
            monkeypatch.delenv("SOCLENS_MS_COPILOT_DIRECTLINE_SECRET", raising=False)
        elif provider == "copilot_studio":
            monkeypatch.setenv("SOCLENS_MS_COPILOT_TOKEN_ENDPOINT", self.d2e_url)
            monkeypatch.setenv("SOCLENS_MS_COPILOT_TOKEN", token)
            monkeypatch.setenv("SOCLENS_MS_COPILOT_AUTH_MODE", "token")
        else:
            raise ValueError(f"Unsupported test provider: {provider}")
        invalidate_settings_cache()

    def chat_requests(self, provider: str | None = None) -> list[dict[str, Any]]:
        """Return logged LLM/Copilot turn requests, optionally filtered by provider."""
        with self._lock:
            out: list[dict[str, Any]] = []
            for req in self.requests_log:
                if not req.get("is_turn"):
                    continue
                if provider is not None and req.get("provider") != provider:
                    continue
                out.append(copy.deepcopy(req))
            return out

    @staticmethod
    def _extract_reply_text(reply: Mapping[str, Any]) -> str:
        text = str(reply.get("content") or "")
        if not text and reply.get("chunks"):
            text = "".join(str(c) for c in reply["chunks"])
        return text

    @staticmethod
    def _format_tool_call_tags(tool_calls: Sequence[Mapping[str, Any]]) -> str:
        blocks: list[str] = []
        for tc in tool_calls:
            fn = tc.get("function") if isinstance(tc.get("function"), Mapping) else tc
            name = str(fn.get("name") or "")
            raw_args = fn.get("arguments")
            if isinstance(raw_args, str):
                try:
                    args_obj = json.loads(raw_args)
                except ValueError:
                    args_obj = {}
            elif isinstance(raw_args, Mapping):
                args_obj = dict(raw_args)
            else:
                args_obj = {}
            payload = {"name": name, "arguments": args_obj}
            blocks.append(f"<tool_call>\n{json.dumps(payload)}\n</tool_call>")
        return "\n".join(blocks)

    def _resolve_turn_reply_locked(
        self,
        *,
        provider: str,
        path: str,
        messages: list[dict[str, Any]],
        turn_text: str,
        tools: list[Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        self.state["turn_counter"] += 1
        turn_idx = int(self.state["turn_counter"])

        # Annotate the latest request_log entry with parsed turn metadata.
        if self.requests_log:
            entry = self.requests_log[-1]
            entry["is_turn"] = True
            entry["provider"] = provider
            entry["tools"] = copy.deepcopy(tools)
            entry["messages"] = copy.deepcopy(messages)
            entry["turn_text"] = turn_text

        queued: list[dict[str, Any]] = self.state["queued_turns"]
        for idx, item in enumerate(queued):
            target_prov = item.get("provider")
            if target_prov is None or target_prov == provider:
                queued.pop(idx)
                return item

        if self._responder is not None:
            ctx = {
                "provider": provider,
                "path": path,
                "messages": copy.deepcopy(messages),
                "turn_text": turn_text,
                "tools": copy.deepcopy(tools),
                "headers": dict(headers),
                "turn_index": turn_idx,
            }
            resp = self._responder(ctx)
            return dict(resp)

        # Default heuristic: summarize tool results if observed, otherwise default reply.
        combined = turn_text or "\n".join(str(m.get("content") or "") for m in messages)
        has_tool_result = any(
            m.get("role") == "tool" for m in messages if isinstance(m, Mapping)
        ) or ("tool_result" in combined.lower() or "[tool result" in combined.lower())
        if has_tool_result:
            snippet = combined[-320:].replace("\n", " ").strip()
            return {
                "status_code": 200,
                "content": f"Investigation complete based on tool observations: {snippet}",
                "tool_calls": None,
            }
        return {
            "status_code": 200,
            "content": str(self.state["default_reply"]),
            "tool_calls": None,
        }

    def _send_sse(
        self,
        handler: BaseHTTPRequestHandler,
        status_code: int,
        events_text: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        raw = events_text.encode("utf-8")
        self._send_raw(handler, status_code, raw, "text/event-stream", headers)

    def _check_bearer_locked(self, headers: dict[str, str]) -> bool:
        req_tok = self.state.get("required_bearer_token")
        auth = _header_ci(headers, "Authorization")
        if req_tok:
            return auth.startswith("Bearer ") and auth[7:].strip() == req_tok
        return auth.startswith("Bearer ") and bool(auth[7:].strip())

    def _check_directline_bearer_locked(self, headers: dict[str, str]) -> bool:
        if self._check_bearer_locked(headers):
            return True
        auth = _header_ci(headers, "Authorization")
        if auth.startswith("Bearer "):
            tok = auth[7:].strip()
            return bool(tok) and tok in self.state["dl_tokens"]
        return False

    def _handle_request(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> None:
        with self._lock:
            # --- 1. Ollama ---
            if path == "/api/tags" and method == "GET":
                self._send_json(handler, 200, {"models": copy.deepcopy(self.state["ollama_models"])})
                return

            if path == "/api/chat" and method == "POST":
                body = json_body if isinstance(json_body, dict) else {}
                messages = body.get("messages")
                if not isinstance(messages, list) or not messages:
                    self._send_json(handler, 400, {"error": "messages must not be empty"})
                    return
                model = str(body.get("model") or "llama3.2:latest")
                stream = bool(body.get("stream", False))
                tools = list(body.get("tools") or []) if isinstance(body.get("tools"), list) else []
                reply = self._resolve_turn_reply_locked(
                    provider="ollama",
                    path=path,
                    messages=messages,
                    turn_text=str(messages[-1].get("content") or ""),
                    tools=tools,
                    headers=headers,
                )
                status = int(reply.get("status_code") or 200)
                if status >= 400:
                    self._send_json(handler, status, reply.get("error_body") or {"error": f"HTTP {status}"})
                    return

                content = self._extract_reply_text(reply)
                raw_tcs = reply.get("tool_calls")
                msg_obj: dict[str, Any] = {"role": "assistant", "content": content}
                if raw_tcs:
                    if tools:
                        ollama_tcs = []
                        for tc in raw_tcs:
                            fn = tc.get("function") if isinstance(tc.get("function"), Mapping) else tc
                            args = fn.get("arguments")
                            if isinstance(args, str):
                                try:
                                    args = json.loads(args)
                                except ValueError:
                                    args = {}
                            ollama_tcs.append(
                                {"function": {"name": str(fn.get("name") or ""), "arguments": args or {}}}
                            )
                        msg_obj["tool_calls"] = ollama_tcs
                    else:
                        tag_text = self._format_tool_call_tags(raw_tcs)
                        msg_obj["content"] = f"{content}\n{tag_text}".strip() if content else tag_text

                if not stream:
                    self._send_json(
                        handler,
                        200,
                        {"model": model, "created_at": _now_iso(), "message": msg_obj, "done": True},
                    )
                    return

                chunks = list(reply.get("chunks") or [msg_obj["content"]])
                lines = [
                    json.dumps(
                        {
                            "model": model,
                            "created_at": _now_iso(),
                            "message": {"role": "assistant", "content": ch},
                            "done": False,
                        }
                    )
                    for ch in chunks
                ]
                done_msg: dict[str, Any] = {"role": "assistant", "content": ""}
                if "tool_calls" in msg_obj:
                    done_msg["tool_calls"] = msg_obj["tool_calls"]
                lines.append(
                    json.dumps(
                        {"model": model, "created_at": _now_iso(), "message": done_msg, "done": True}
                    )
                )
                self._send_raw(handler, 200, ("\n".join(lines) + "\n").encode("utf-8"), "application/x-ndjson")
                return

            # --- 2. OpenAI-Compatible ---
            if path.startswith("/v1/"):
                req_key = self.state.get("required_api_key")
                if req_key:
                    auth = _header_ci(headers, "Authorization")
                    if not auth.startswith("Bearer ") or auth[7:].strip() != req_key:
                        self._send_json(
                            handler,
                            401,
                            {"error": {"message": "Invalid API key", "type": "authentication_error"}},
                        )
                        return

                if path == "/v1/models" and method == "GET":
                    self._send_json(
                        handler,
                        200,
                        {"object": "list", "data": copy.deepcopy(self.state["openai_models"])},
                    )
                    return

                if path == "/v1/chat/completions" and method == "POST":
                    body = json_body if isinstance(json_body, dict) else {}
                    messages = body.get("messages")
                    if not isinstance(messages, list) or not messages:
                        self._send_json(handler, 400, {"error": {"message": "messages required"}})
                        return
                    model = str(body.get("model") or "qwen2.5-coder:7b")
                    stream = bool(body.get("stream", False))
                    tools = list(body.get("tools") or []) if isinstance(body.get("tools"), list) else []
                    reply = self._resolve_turn_reply_locked(
                        provider="openai",
                        path=path,
                        messages=messages,
                        turn_text=str(messages[-1].get("content") or ""),
                        tools=tools,
                        headers=headers,
                    )
                    status = int(reply.get("status_code") or 200)
                    if status >= 400:
                        self._send_json(
                            handler,
                            status,
                            reply.get("error_body") or {"error": {"message": f"HTTP {status}"}},
                        )
                        return

                    content = self._extract_reply_text(reply)
                    raw_tcs = reply.get("tool_calls")
                    msg_obj = {"role": "assistant", "content": content}
                    finish_reason = "stop"
                    if raw_tcs:
                        if tools:
                            oai_tcs = []
                            for idx, tc in enumerate(raw_tcs, start=1):
                                fn = tc.get("function") if isinstance(tc.get("function"), Mapping) else tc
                                args = fn.get("arguments")
                                args_str = args if isinstance(args, str) else json.dumps(args or {})
                                oai_tcs.append(
                                    {
                                        "id": str(tc.get("id") or f"call_{idx}"),
                                        "type": "function",
                                        "function": {
                                            "name": str(fn.get("name") or ""),
                                            "arguments": args_str,
                                        },
                                    }
                                )
                            msg_obj["tool_calls"] = oai_tcs
                            finish_reason = "tool_calls"
                        else:
                            tag_text = self._format_tool_call_tags(raw_tcs)
                            msg_obj["content"] = f"{content}\n{tag_text}".strip() if content else tag_text

                    if not stream:
                        self._send_json(
                            handler,
                            200,
                            {
                                "id": f"chatcmpl-{self.state['turn_counter']}",
                                "object": "chat.completion",
                                "model": model,
                                "choices": [
                                    {"index": 0, "message": msg_obj, "finish_reason": finish_reason}
                                ],
                            },
                        )
                        return

                    raw_chunks = reply.get("chunks")
                    content_str = str(msg_obj.get("content") or "")
                    if raw_chunks is not None:
                        chunks = list(raw_chunks)
                    elif content_str or not msg_obj.get("tool_calls"):
                        chunks = [content_str]
                    else:
                        chunks = []

                    events = [
                        "data: "
                        + json.dumps(
                            {
                                "id": f"chatcmpl-{self.state['turn_counter']}",
                                "object": "chat.completion.chunk",
                                "model": model,
                                "choices": [{"index": 0, "delta": {"content": ch}, "finish_reason": None}],
                            }
                        )
                        for ch in chunks
                    ]
                    for tc_idx, tc in enumerate(msg_obj.get("tool_calls") or []):
                        events.append(
                            "data: "
                            + json.dumps(
                                {
                                    "id": f"chatcmpl-{self.state['turn_counter']}",
                                    "object": "chat.completion.chunk",
                                    "model": model,
                                    "choices": [
                                        {
                                            "index": 0,
                                            "delta": {
                                                "role": "assistant",
                                                "tool_calls": [{"index": tc_idx, **tc}],
                                            },
                                            "finish_reason": None,
                                        }
                                    ],
                                }
                            )
                        )
                    events.append(
                        "data: "
                        + json.dumps(
                            {
                                "id": f"chatcmpl-{self.state['turn_counter']}",
                                "object": "chat.completion.chunk",
                                "model": model,
                                "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
                            }
                        )
                    )
                    events.append("data: [DONE]")
                    self._send_sse(handler, 200, "\n\n".join(events) + "\n\n")
                    return

            # --- 2b. Google Gemini REST API ---
            if path == "/v1beta/models" or path.startswith("/v1beta/models/"):
                req_key = self.state.get("required_api_key")
                if req_key:
                    got_key = headers.get("x-goog-api-key", "")
                    if got_key != req_key:
                        self._send_json(
                            handler,
                            401,
                            {"error": {"code": 401, "message": "API key not valid."}},
                        )
                        return

                if path == "/v1beta/models" and method == "GET":
                    self._send_json(
                        handler,
                        200,
                        {"models": copy.deepcopy(self.state["gemini_models"])},
                    )
                    return

                if (
                    path.startswith("/v1beta/models/")
                    and method == "POST"
                    and (path.endswith(":generateContent") or path.endswith(":streamGenerateContent"))
                ):
                    body = json_body if isinstance(json_body, dict) else {}
                    contents = body.get("contents")
                    if not isinstance(contents, list) or not contents:
                        self._send_json(
                            handler, 400, {"error": {"message": "contents required"}}
                        )
                        return
                    is_stream = path.endswith(":streamGenerateContent")
                    suffix = ":streamGenerateContent" if is_stream else ":generateContent"
                    model_id = path[len("/v1beta/models/") : -len(suffix)] or "gemini-2.5-flash"
                    raw_tools = body.get("tools")
                    tools_list = list(raw_tools) if isinstance(raw_tools, list) else []
                    last_parts = contents[-1].get("parts") if isinstance(contents[-1], Mapping) else []
                    turn_text = ""
                    if isinstance(last_parts, list) and last_parts:
                        first_part = last_parts[0]
                        if isinstance(first_part, Mapping):
                            turn_text = str(first_part.get("text") or first_part.get("functionResponse") or "")
                    reply = self._resolve_turn_reply_locked(
                        provider="gemini",
                        path=path,
                        messages=contents,
                        turn_text=turn_text,
                        tools=tools_list,
                        headers=headers,
                    )
                    status = int(reply.get("status_code") or 200)
                    if status >= 400:
                        self._send_json(
                            handler,
                            status,
                            reply.get("error_body") or {"error": {"message": f"HTTP {status}"}},
                        )
                        return

                    content_str = self._extract_reply_text(reply)
                    raw_tcs = reply.get("tool_calls")
                    parts_out: list[dict[str, Any]] = []
                    if raw_tcs:
                        if tools_list:
                            if content_str:
                                parts_out.append({"text": content_str})
                            for tc in raw_tcs:
                                fn = (
                                    tc.get("function")
                                    if isinstance(tc.get("function"), Mapping)
                                    else tc
                                )
                                raw_args = fn.get("arguments")
                                if isinstance(raw_args, Mapping):
                                    args_obj = dict(raw_args)
                                elif isinstance(raw_args, str) and raw_args.strip():
                                    try:
                                        args_obj = json.loads(raw_args)
                                    except ValueError:
                                        args_obj = {}
                                else:
                                    args_obj = {}
                                parts_out.append(
                                    {
                                        "functionCall": {
                                            "name": str(fn.get("name") or ""),
                                            "args": args_obj,
                                        }
                                    }
                                )
                        else:
                            tag_text = self._format_tool_call_tags(raw_tcs)
                            merged = f"{content_str}\n{tag_text}".strip() if content_str else tag_text
                            parts_out.append({"text": merged})
                    else:
                        parts_out.append({"text": content_str})

                    if not is_stream:
                        self._send_json(
                            handler,
                            200,
                            {
                                "modelVersion": model_id,
                                "candidates": [
                                    {
                                        "content": {"role": "model", "parts": parts_out},
                                        "finishReason": "STOP",
                                    }
                                ],
                            },
                        )
                        return

                    raw_chunks = reply.get("chunks")
                    sse_events: list[str] = []
                    if raw_chunks is not None:
                        for ch in raw_chunks:
                            sse_events.append(
                                "data: "
                                + json.dumps(
                                    {
                                        "modelVersion": model_id,
                                        "candidates": [
                                            {"content": {"role": "model", "parts": [{"text": ch}]}}
                                        ],
                                    }
                                )
                            )
                        sse_events.append(
                            "data: "
                            + json.dumps(
                                {
                                    "modelVersion": model_id,
                                    "candidates": [
                                        {
                                            "content": {"role": "model", "parts": []},
                                            "finishReason": "STOP",
                                        }
                                    ],
                                }
                            )
                        )
                    else:
                        sse_events.append(
                            "data: "
                            + json.dumps(
                                {
                                    "modelVersion": model_id,
                                    "candidates": [
                                        {
                                            "content": {"role": "model", "parts": parts_out},
                                            "finishReason": "STOP",
                                        }
                                    ],
                                }
                            )
                        )
                    self._send_sse(handler, 200, "\n\n".join(sse_events) + "\n\n")
                    return

            # --- 3. Microsoft Graph Beta (M365 Copilot & Security Copilot) ---
            if path.startswith("/graph/beta/"):
                if not self._check_bearer_locked(headers):
                    self._send_json(
                        handler,
                        401,
                        {"error": {"code": "InvalidAuthenticationToken", "message": "Unauthorized"}},
                    )
                    return

                subpath = path[len("/graph/beta") :]

                if subpath == "/me" and method == "GET":
                    self._send_json(
                        handler,
                        200,
                        {"userPrincipalName": "soc.analyst@example.test", "displayName": "SOC Analyst"},
                    )
                    return

                if subpath == "/copilot/conversations" and method == "POST":
                    self.state["conv_counter"] += 1
                    cid = f"m365-conv-{self.state['conv_counter']}"
                    self.state["m365_conversations"][cid] = {"id": cid, "turns": []}
                    self._send_json(handler, 201, {"id": cid})
                    return

                m_m365 = re.match(r"^/copilot/conversations/([^/]+)/(chat|chatOverStream)$", subpath)
                if m_m365 and method == "POST":
                    cid = urllib.parse.unquote(m_m365.group(1))
                    mode_ep = m_m365.group(2)
                    conv = self.state["m365_conversations"].get(cid)
                    if conv is None:
                        self._send_json(handler, 404, {"error": {"message": f"Unknown conversation {cid}"}})
                        return
                    body = json_body if isinstance(json_body, dict) else {}
                    turn_text = str(((body.get("message") or {}) if isinstance(body.get("message"), Mapping) else {}).get("text") or "")
                    conv["turns"].append({"role": "user", "content": turn_text})
                    reply = self._resolve_turn_reply_locked(
                        provider="m365_copilot",
                        path=path,
                        messages=conv["turns"],
                        turn_text=turn_text,
                        tools=[],
                        headers=headers,
                    )
                    status = int(reply.get("status_code") or 200)
                    if status >= 400:
                        self._send_json(
                            handler, status, reply.get("error_body") or {"error": {"message": f"HTTP {status}"}}
                        )
                        return
                    text = self._extract_reply_text(reply)
                    if reply.get("tool_calls"):
                        tags = self._format_tool_call_tags(reply["tool_calls"])
                        text = f"{text}\n{tags}".strip() if text else tags
                    conv["turns"].append({"role": "assistant", "content": text})

                    if mode_ep == "chatOverStream":
                        chunks = list(reply.get("chunks") or [text])
                        cum = ""
                        sse_lines: list[str] = []
                        for ch in chunks:
                            cum += ch
                            sse_lines.append("data: " + json.dumps({"text": cum}))
                        sse_lines.append("data: [DONE]")
                        self._send_sse(handler, 200, "\n\n".join(sse_lines) + "\n\n")
                        return

                    self._send_json(
                        handler,
                        200,
                        {
                            "id": cid,
                            "messages": [
                                {
                                    "@odata.type": "#microsoft.graph.copilotConversationRequestMessage",
                                    "text": turn_text,
                                },
                                {
                                    "@odata.type": "#microsoft.graph.copilotConversationResponseMessage",
                                    "text": text,
                                    "attributions": [],
                                },
                            ],
                        },
                    )
                    return

                # Security Copilot
                m_ws = re.match(r"^/security/securityCopilot/workspaces/([^/]+)$", subpath)
                if m_ws and method == "GET":
                    ws = urllib.parse.unquote(m_ws.group(1))
                    self._send_json(handler, 200, {"id": ws, "displayName": f"SOC Workspace ({ws})"})
                    return

                m_sess = re.match(r"^/security/securityCopilot/workspaces/([^/]+)/sessions$", subpath)
                if m_sess and method == "POST":
                    ws = urllib.parse.unquote(m_sess.group(1))
                    self.state["conv_counter"] += 1
                    sid = f"sc-sess-{self.state['conv_counter']}"
                    self.state["sc_sessions"][sid] = {"id": sid, "workspace": ws, "turns": []}
                    self._send_json(handler, 201, {"id": sid})
                    return

                m_prompt = re.match(
                    r"^/security/securityCopilot/workspaces/([^/]+)/sessions/([^/]+)/prompts$",
                    subpath,
                )
                if m_prompt and method == "POST":
                    sid = urllib.parse.unquote(m_prompt.group(2))
                    sess = self.state["sc_sessions"].get(sid)
                    if sess is None:
                        self._send_json(handler, 404, {"error": {"message": f"Unknown session {sid}"}})
                        return
                    body = json_body if isinstance(json_body, dict) else {}
                    turn_text = str(body.get("content") or "")
                    sess["turns"].append({"role": "user", "content": turn_text})
                    self.state["conv_counter"] += 1
                    pid = f"sc-prompt-{self.state['conv_counter']}"
                    reply = self._resolve_turn_reply_locked(
                        provider="security_copilot",
                        path=path,
                        messages=sess["turns"],
                        turn_text=turn_text,
                        tools=[],
                        headers=headers,
                    )
                    status = int(reply.get("status_code") or 200)
                    if status >= 400:
                        self._send_json(
                            handler, status, reply.get("error_body") or {"error": {"message": f"HTTP {status}"}}
                        )
                        return
                    text = self._extract_reply_text(reply)
                    if reply.get("tool_calls"):
                        tags = self._format_tool_call_tags(reply["tool_calls"])
                        text = f"{text}\n{tags}".strip() if text else tags
                    sess["turns"].append({"role": "assistant", "content": text})
                    self.state["sc_prompts"][pid] = {"id": pid, "session_id": sid, "reply_text": text}
                    self._send_json(handler, 201, {"id": pid, "content": turn_text})
                    return

                m_eval_create = re.match(
                    r"^/security/securityCopilot/workspaces/[^/]+/sessions/[^/]+/prompts/([^/]+)/evaluations$",
                    subpath,
                )
                if m_eval_create and method == "POST":
                    pid = urllib.parse.unquote(m_eval_create.group(1))
                    prompt_rec = self.state["sc_prompts"].get(pid)
                    if prompt_rec is None:
                        self._send_json(handler, 404, {"error": {"message": f"Unknown prompt {pid}"}})
                        return
                    self.state["conv_counter"] += 1
                    eid = f"sc-eval-{self.state['conv_counter']}"
                    polls_needed = int(self.state.get("sc_eval_polls_before_done", 1))
                    eval_rec = {
                        "id": eid,
                        "polls": 0,
                        "polls_needed": polls_needed,
                        "reply_text": prompt_rec["reply_text"],
                    }
                    self.state["sc_evaluations"][eid] = eval_rec
                    init_state = "completed" if polls_needed <= 0 else "running"
                    resp_obj: dict[str, Any] = {"id": eid, "state": init_state}
                    if init_state == "completed":
                        resp_obj["result"] = {"content": prompt_rec["reply_text"]}
                    self._send_json(handler, 201, resp_obj)
                    return

                m_eval_get = re.match(
                    r"^/security/securityCopilot/workspaces/[^/]+/sessions/[^/]+/prompts/[^/]+/evaluations/([^/]+)$",
                    subpath,
                )
                if m_eval_get and method == "GET":
                    eid = urllib.parse.unquote(m_eval_get.group(1))
                    ev = self.state["sc_evaluations"].get(eid)
                    if ev is None:
                        self._send_json(handler, 404, {"error": {"message": f"Unknown eval {eid}"}})
                        return
                    ev["polls"] += 1
                    if ev["polls"] < ev["polls_needed"]:
                        self._send_json(handler, 200, {"id": eid, "state": "running"})
                        return
                    self._send_json(
                        handler,
                        200,
                        {"id": eid, "state": "completed", "result": {"content": ev["reply_text"]}},
                    )
                    return

            # --- 4. Copilot Studio Direct-to-Engine (D2E) ---
            if path.startswith("/copilotstudio/"):
                if "/authenticated/" in path and not self._check_bearer_locked(headers):
                    self._send_json(handler, 401, {"error": {"message": "Unauthorized D2E request"}})
                    return
                if path.endswith("/conversations") and method == "POST":
                    self.state["conv_counter"] += 1
                    cid = f"d2e-conv-{self.state['conv_counter']}"
                    self.state["d2e_conversations"][cid] = {"id": cid, "turns": []}
                    sse_body = "\n".join(
                        [
                            "event: activity",
                            "data: " + json.dumps({"type": "event", "conversation": {"id": cid}}),
                            "",
                            "data: [DONE]",
                            "",
                        ]
                    )
                    self._send_sse(handler, 200, sse_body, headers={"x-ms-conversationid": cid})
                    return

                m_d2e_turn = re.match(r"^(/copilotstudio/.+/conversations)/([^/]+)$", path)
                if m_d2e_turn and method == "POST":
                    cid = urllib.parse.unquote(m_d2e_turn.group(2))
                    conv = self.state["d2e_conversations"].get(cid)
                    if conv is None:
                        self._send_json(handler, 404, {"error": {"message": f"Unknown D2E conversation {cid}"}})
                        return
                    body = json_body if isinstance(json_body, dict) else {}
                    act = body.get("activity") if isinstance(body.get("activity"), Mapping) else {}
                    turn_text = str(act.get("text") or "")
                    conv["turns"].append({"role": "user", "content": turn_text})
                    reply = self._resolve_turn_reply_locked(
                        provider="copilot_studio",
                        path=path,
                        messages=conv["turns"],
                        turn_text=turn_text,
                        tools=[],
                        headers=headers,
                    )
                    status = int(reply.get("status_code") or 200)
                    if status >= 400:
                        self._send_json(
                            handler, status, reply.get("error_body") or {"error": {"message": f"HTTP {status}"}}
                        )
                        return
                    text = self._extract_reply_text(reply)
                    if reply.get("tool_calls"):
                        tags = self._format_tool_call_tags(reply["tool_calls"])
                        text = f"{text}\n{tags}".strip() if text else tags
                    conv["turns"].append({"role": "assistant", "content": text})
                    sse_parts = [
                        "event: activity",
                        "data: " + json.dumps({"type": "typing"}),
                        "",
                    ]
                    if reply.get("chunks"):
                        for ch in reply["chunks"]:
                            ch_s = str(ch)
                            if ch_s:
                                sse_parts.extend(
                                    [
                                        "event: activity",
                                        "data: "
                                        + json.dumps(
                                            {
                                                "type": "message",
                                                "from": {"role": "bot"},
                                                "text": ch_s,
                                                "channelData": {"streamType": "streaming"},
                                            }
                                        ),
                                        "",
                                    ]
                                )
                    sse_parts.extend(
                        [
                            "event: activity",
                            "data: "
                            + json.dumps(
                                {
                                    "type": "message",
                                    "from": {"role": "bot"},
                                    "text": text,
                                    "channelData": {"streamType": "final"},
                                }
                            ),
                            "",
                            "data: [DONE]",
                            "",
                        ]
                    )
                    sse_body = "\n".join(sse_parts)
                    self._send_sse(handler, 200, sse_body, headers={"x-ms-conversationid": cid})
                    return

            # --- 5. Copilot Direct Line v3 ---
            if path == "/powerplatform/directline/token" and method == "GET":
                self.state["conv_counter"] += 1
                tok = f"dl-tok-{self.state['conv_counter']}"
                self.state["dl_tokens"].add(tok)
                self._send_json(handler, 200, {"token": tok, "expires_in": 3600})
                return

            if path == "/v3/directline/tokens/generate" and method == "POST":
                if not self._check_bearer_locked(headers):
                    self._send_json(handler, 401, {"error": {"message": "Invalid Direct Line secret"}})
                    return
                self.state["conv_counter"] += 1
                tok = f"dl-tok-{self.state['conv_counter']}"
                self.state["dl_tokens"].add(tok)
                self._send_json(handler, 200, {"token": tok, "expires_in": 3600})
                return

            if path == "/v3/directline/conversations" and method == "POST":
                if not self._check_directline_bearer_locked(headers):
                    self._send_json(handler, 401, {"error": {"message": "Unauthorized Direct Line"}})
                    return
                self.state["conv_counter"] += 1
                cid = f"dl-conv-{self.state['conv_counter']}"
                ctok = f"dl-conv-tok-{self.state['conv_counter']}"
                self.state["dl_tokens"].add(ctok)
                self.state["dl_conversations"][cid] = {
                    "id": cid,
                    "activities": [],
                    "turns": [],
                }
                self._send_json(handler, 201, {"conversationId": cid, "token": ctok})
                return

            m_dl_act = re.match(r"^/v3/directline/conversations/([^/]+)/activities$", path)
            if m_dl_act:
                if not self._check_directline_bearer_locked(headers):
                    self._send_json(handler, 401, {"error": {"message": "Unauthorized Direct Line"}})
                    return
                cid = urllib.parse.unquote(m_dl_act.group(1))
                conv = self.state["dl_conversations"].get(cid)
                if conv is None:
                    self._send_json(handler, 404, {"error": {"message": f"Unknown conversation {cid}"}})
                    return
                if method == "POST":
                    body = json_body if isinstance(json_body, dict) else {}
                    turn_text = str(body.get("text") or "")
                    conv["turns"].append({"role": "user", "content": turn_text})
                    conv["activities"].append(copy.deepcopy(body))
                    reply = self._resolve_turn_reply_locked(
                        provider="copilot_directline",
                        path=path,
                        messages=conv["turns"],
                        turn_text=turn_text,
                        tools=[],
                        headers=headers,
                    )
                    status = int(reply.get("status_code") or 200)
                    if status >= 400:
                        self._send_json(
                            handler, status, reply.get("error_body") or {"error": {"message": f"HTTP {status}"}}
                        )
                        return
                    text = self._extract_reply_text(reply)
                    if reply.get("tool_calls"):
                        tags = self._format_tool_call_tags(reply["tool_calls"])
                        text = f"{text}\n{tags}".strip() if text else tags
                    conv["turns"].append({"role": "assistant", "content": text})
                    act_id = f"act-{len(conv['activities']) + 1}"
                    conv["activities"].append(
                        {
                            "id": f"{act_id}-bot",
                            "type": "message",
                            "from": {"id": "soc-copilot-bot", "name": "Copilot Studio Agent"},
                            "text": text,
                        }
                    )
                    self._send_json(handler, 200, {"id": act_id})
                    return

                if method == "GET":
                    raw_wm = (query.get("watermark") or [""])[0].strip()
                    try:
                        wm = int(raw_wm) if raw_wm else 0
                    except ValueError:
                        wm = 0
                    all_acts = conv["activities"]
                    slice_acts = copy.deepcopy(all_acts[wm:])
                    self._send_json(
                        handler,
                        200,
                        {"watermark": str(len(all_acts)), "activities": slice_acts},
                    )
                    return

        self._send_json(handler, 404, {"error": f"Unknown mock LLM/Copilot route: {method} {path}"})


class MockOSINTServer(_BaseV21MockServer):
    """Offline localhost HTTP mock for SOCLens ``OSINTClient`` endpoints."""

    PUBLIC_TEST_IP: str = "93.184.216.34"

    def _reset_state_locked(self) -> None:
        today_str = datetime.now(UTC).strftime("%Y-%m-%d")
        shodan_tpl = {
            "ports": [443, 8443],
            "hostnames": ["c2.evil-actor.test"],
            "tags": ["vpn", "c2"],
            "vulns": ["CVE-2024-3400"],
            "cpes": ["cpe:/o:paloaltonetworks:pan-os"],
        }
        geoip_tpl = {
            "success": True,
            "country": "Netherlands",
            "country_code": "NL",
            "city": "Amsterdam",
            "connection": {"asn": 64512, "org": "Bulletproof Hosting AS64512"},
        }
        greynoise_tpl = {
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "name": "Known Scanner",
            "last_seen": today_str,
        }
        otx_tpl = {
            "pulse_info": {
                "count": 2,
                "pulses": [
                    {
                        "id": "pulse-1",
                        "name": "CVE-2024-3400 Active Exploitation C2",
                        "adversary": "UTA0218",
                        "tags": ["cve-2024-3400", "c2"],
                    }
                ],
            }
        }
        self.state = {
            "cves": {
                "CVE-2024-3400": {
                    "cveMetadata": {"cveId": "CVE-2024-3400", "state": "PUBLISHED"},
                    "containers": {
                        "cna": {
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "value": "PAN-OS GlobalProtect command injection exploited in the wild.",
                                }
                            ],
                            "metrics": [
                                {"cvssV3_1": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                            ],
                        }
                    },
                }
            },
            "epss": {
                "CVE-2024-3400": {"cve": "CVE-2024-3400", "epss": "0.97420", "percentile": "0.99910"}
            },
            "kev": [
                {
                    "cveID": "CVE-2024-3400",
                    "vendorProject": "Palo Alto Networks",
                    "product": "PAN-OS",
                    "vulnerabilityName": "PAN-OS GlobalProtect Command Injection",
                    "dateAdded": "2024-04-12",
                    "dueDate": "2024-04-19",
                }
            ],
            "shodan": {
                "198.51.100.10": {"ip": "198.51.100.10", **copy.deepcopy(shodan_tpl)},
                self.PUBLIC_TEST_IP: {"ip": self.PUBLIC_TEST_IP, **copy.deepcopy(shodan_tpl)},
            },
            "geoip": {
                "198.51.100.10": {"ip": "198.51.100.10", **copy.deepcopy(geoip_tpl)},
                self.PUBLIC_TEST_IP: {"ip": self.PUBLIC_TEST_IP, **copy.deepcopy(geoip_tpl)},
            },
            "greynoise": {
                "198.51.100.10": {"ip": "198.51.100.10", **copy.deepcopy(greynoise_tpl)},
                self.PUBLIC_TEST_IP: {"ip": self.PUBLIC_TEST_IP, **copy.deepcopy(greynoise_tpl)},
            },
            "otx": {
                "198.51.100.10": copy.deepcopy(otx_tpl),
                self.PUBLIC_TEST_IP: copy.deepcopy(otx_tpl),
            },
        }

    def endpoints_map(self) -> dict[str, str]:
        """Return an ``OSINTClient(endpoints=...)`` mapping pointing 100% to localhost."""
        return {
            "doh_primary": f"{self.base_url}/doh",
            "doh_fallback": f"{self.base_url}/doh",
            "rdap": f"{self.base_url}/rdap",
            "geoip": f"{self.base_url}/geoip",
            "ripestat": f"{self.base_url}/ripestat",
            "shodan_internetdb": f"{self.base_url}/shodan",
            "crtsh": f"{self.base_url}/crtsh",
            "urlscan": f"{self.base_url}/urlscan",
            "dshield": f"{self.base_url}/dshield",
            "wayback": f"{self.base_url}/wayback",
            "otx": f"{self.base_url}/otx",
            "greynoise": f"{self.base_url}/greynoise",
            "hashlookup": f"{self.base_url}/hashlookup",
            "cveawg": f"{self.base_url}/cveawg",
            "epss": f"{self.base_url}/epss",
            "cisa_kev": f"{self.base_url}/cisa_kev",
            "virustotal": f"{self.base_url}/virustotal",
            "abuseipdb": f"{self.base_url}/abuseipdb",
            "threatfox": f"{self.base_url}/threatfox",
            "urlhaus": f"{self.base_url}/urlhaus",
            "malwarebazaar": f"{self.base_url}/malwarebazaar",
        }

    def make_client(self, workspace_dir: Path | None = None) -> OSINTClient:
        return OSINTClient(endpoints=self.endpoints_map(), workspace_dir=workspace_dir)

    def _handle_request(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> None:
        with self._lock:
            if path.startswith("/cveawg/"):
                cve = urllib.parse.unquote(path[len("/cveawg/") :]).upper()
                rec = self.state["cves"].get(cve)
                if rec is None:
                    self._send_json(handler, 404, {"error": "CVE not found"})
                    return
                self._send_json(handler, 200, copy.deepcopy(rec))
                return

            if path == "/epss":
                cve = (query.get("cve") or [""])[0].upper()
                rec = self.state["epss"].get(cve)
                self._send_json(handler, 200, {"data": [copy.deepcopy(rec)] if rec else []})
                return

            if path == "/cisa_kev":
                self._send_json(handler, 200, {"vulnerabilities": copy.deepcopy(self.state["kev"])})
                return

            if path.startswith("/shodan/"):
                ip = urllib.parse.unquote(path[len("/shodan/") :])
                rec = self.state["shodan"].get(ip)
                if rec is None:
                    self._send_json(handler, 404, {"detail": "No information available"})
                    return
                self._send_json(handler, 200, copy.deepcopy(rec))
                return

            if path.startswith("/geoip/"):
                ip = urllib.parse.unquote(path[len("/geoip/") :])
                rec = self.state["geoip"].get(ip)
                if rec is None:
                    self._send_json(handler, 200, {"success": False, "ip": ip, "message": "Not found"})
                    return
                self._send_json(handler, 200, copy.deepcopy(rec))
                return

            if path.startswith("/greynoise/"):
                ip = urllib.parse.unquote(path[len("/greynoise/") :])
                rec = self.state["greynoise"].get(ip)
                if rec is None:
                    self._send_json(handler, 404, {"message": "IP not observed"})
                    return
                self._send_json(handler, 200, copy.deepcopy(rec))
                return

            if path.startswith("/otx/indicators/"):
                parts = path[len("/otx/indicators/") :].split("/")
                ind = urllib.parse.unquote(parts[1]) if len(parts) >= 2 else ""
                if parts[-1] == "passive_dns":
                    self._send_json(handler, 200, {"passive_dns": []})
                    return
                rec = self.state["otx"].get(ind)
                if rec is None:
                    self._send_json(handler, 404, {"detail": "Not found"})
                    return
                self._send_json(handler, 200, copy.deepcopy(rec))
                return

            if path == "/doh":
                name = (query.get("name") or ["example.test"])[0]
                self._send_json(
                    handler,
                    200,
                    {
                        "Status": 0,
                        "AD": False,
                        "Answer": [{"name": name, "type": 1, "TTL": 60, "data": self.PUBLIC_TEST_IP}],
                    },
                )
                return

            # Return empty/not-found JSON safely for secondary sources so full enrich completes offline.
            self._send_json(handler, 404, {"error": f"No mock OSINT record for {path}"})


@pytest.fixture
def mock_agentic_llm_server(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[MockAgenticLLMAndCopilotServer]:
    server = MockAgenticLLMAndCopilotServer()
    server.configure_provider(monkeypatch, "ollama", model="llama3.2:latest")
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def mock_osint_server(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[MockOSINTServer]:
    server = MockOSINTServer()
    monkeypatch.setenv("SOCLENS_OSINT_ENABLED", "true")
    invalidate_settings_cache()
    try:
        yield server
    finally:
        server.close()


def build_correlated_soc_scenario(
    rf_server: Any,
    es_server: Any,
    s1_server: Any,
) -> dict[str, str]:
    """Seed correlated IOCs (198.51.100.10, CVE-2024-3400, wkstn-1001-01.example.test) across RF/ES/S1."""
    cve_id = "CVE-2024-3400"
    ioc_ip = "198.51.100.10"
    hostname = "wkstn-1001-01.example.test"
    rf_alert_id = "alert-v3-cve3400"
    rf_pb_id = "pb-1"

    with rf_server._lock:
        rf_server.state["v2_entities"][("vulnerability", cve_id)] = {
            "entity": {"id": f"cve:{cve_id}", "name": cve_id, "type": "CyberVulnerability"},
            "risk": {
                "score": 99,
                "level": 5,
                "criticalityLabel": "Very Critical",
                "riskString": "5/5",
                "evidenceDetails": [
                    {
                        "rule": "Active Exploitation in the Wild",
                        "evidenceString": f"{cve_id} actively exploited from {ioc_ip}",
                    }
                ],
            },
            "cvss": {"score": 10.0},
            "intelCard": f"https://app.recordedfuture.com/live/sc/entity/cve%3A{cve_id}",
        }
        rf_server.state["v2_entities"][("ip", ioc_ip)] = {
            "entity": {"id": f"ip:{ioc_ip}", "name": ioc_ip, "type": "IpAddress"},
            "risk": {
                "score": 89,
                "level": 4,
                "criticalityLabel": "Critical",
                "riskString": "4/5",
                "evidenceDetails": [
                    {"rule": "Recent C2 Infrastructure", "evidenceString": f"Observed exploiting {cve_id}"}
                ],
            },
            "intelCard": f"https://app.recordedfuture.com/live/sc/entity/ip%3A{ioc_ip}",
        }
        existing_ids = {a["id"] for a in rf_server.state["alerts_v3"]}
        if rf_alert_id not in existing_ids:
            rf_server.state["alerts_v3"].insert(
                0,
                {
                    "id": rf_alert_id,
                    "title": f"Active {cve_id} Exploitation via {ioc_ip}",
                    "type": "WatchedEntityAlert",
                    "triggered": _now_iso(),
                    "statusInPortal": "New",
                    "assignee": None,
                    "priority": "High",
                    "alertRule": {"id": "rule-cve-3400", "name": "Perimeter CVE Exploitation"},
                    "review": {"status_in_portal": "New", "priority": "High", "assignee": None},
                    "hits": [
                        {
                            "id": "hit-3400-1",
                            "primary_entity": {
                                "id": f"ip:{ioc_ip}",
                                "name": ioc_ip,
                                "type": "IpAddress",
                            },
                            "entities": [
                                {
                                    "id": f"cve:{cve_id}",
                                    "name": cve_id,
                                    "type": "CyberVulnerability",
                                }
                            ],
                        }
                    ],
                    "ai_insights": {
                        "text": f"IP {ioc_ip} observed targeting edge gateway with {cve_id} against {hostname}."
                    },
                },
            )

    with es_server._lock:
        es_server.state["default_job_results"] = [
            {
                "_time": _now_iso(),
                "src": ioc_ip,
                "dest": hostname,
                "cve": cve_id,
                "action": "allowed",
                "tenant_id": "1001",
                "sourcetype": "pan:traffic",
            }
        ]
        es_findings = es_server.state.get("findings") or []
        es_event_id = str(es_findings[0].get("event_id") or "fnd-1001-a") if es_findings else "fnd-1001-a"

    with s1_server._lock:
        def _parse_ts(val: Any) -> datetime | None:
            if not isinstance(val, str) or not val.strip():
                return None
            raw = val.strip()
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(raw)
                return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
            except ValueError:
                return None

        parsed_ts: list[datetime] = []
        for item in (s1_server.state.get("threats") or []):
            ti = item.get("threatInfo") if isinstance(item, dict) else None
            if isinstance(ti, dict):
                dt = _parse_ts(ti.get("createdAt"))
                if dt is not None:
                    parsed_ts.append(dt)
        for item in (s1_server.state.get("cloud_alerts") or []):
            if isinstance(item, dict):
                dt = _parse_ts(item.get("createdAt"))
                if dt is not None:
                    parsed_ts.append(dt)
        if parsed_ts:
            anchor = max(parsed_ts)
            shift = datetime.now(UTC) - anchor - timedelta(seconds=60)
            for item in (s1_server.state.get("threats") or []):
                ti = item.get("threatInfo") if isinstance(item, dict) else None
                if isinstance(ti, dict):
                    dt = _parse_ts(ti.get("createdAt"))
                    if dt is not None:
                        ti["createdAt"] = (dt + shift).strftime("%Y-%m-%dT%H:%M:%SZ")
            for item in (s1_server.state.get("cloud_alerts") or []):
                if isinstance(item, dict):
                    dt = _parse_ts(item.get("createdAt"))
                    if dt is not None:
                        shifted = (dt + shift).strftime("%Y-%m-%dT%H:%M:%SZ")
                        item["createdAt"] = shifted
                        ai = item.get("alertInfo")
                        if isinstance(ai, dict) and "createdAt" in ai:
                            ai["createdAt"] = shifted
            for tl_list in (s1_server.state.get("timelines") or {}).values():
                if isinstance(tl_list, list):
                    for ev in tl_list:
                        if isinstance(ev, dict):
                            dt = _parse_ts(ev.get("createdAt"))
                            if dt is not None:
                                ev["createdAt"] = (dt + shift).strftime("%Y-%m-%dT%H:%M:%SZ")

        threats = s1_server.state.get("threats") or []
        s1_threat_id = str(threats[0].get("id") or "thr-1001-1") if threats else "thr-1001-1"
        cloud_alerts = s1_server.state.get("cloud_alerts") or []
        s1_cloud_id = str(cloud_alerts[0].get("id") or "cld-1001-1") if cloud_alerts else "cld-1001-1"

    return {
        "cve_id": cve_id,
        "ip": ioc_ip,
        "hostname": hostname,
        "rf_alert_id": rf_alert_id,
        "rf_playbook_id": rf_pb_id,
        "s1_threat_id": s1_threat_id,
        "s1_cloud_alert_id": s1_cloud_id,
        "es_event_id": es_event_id,
    }


def assert_zero_mutating_http_requests(
    *,
    rf_server: Any | None = None,
    s1_server: Any | None = None,
    es_server: Any | None = None,
) -> None:
    """Assert that zero mutating, remediation, or token-minting HTTP requests hit backend mock servers."""
    violations: list[str] = []

    if rf_server is not None:
        rf_forbidden = re.compile(
            r"^(?:/alert/v2/update|/case/(?:create|update|assignees)|/list/create|/list/[^/]+/entity/(?:add|remove|tags)|/api/v0/samples)$"
        )
        for req in list(rf_server.requests_log):
            method = str(req.get("method") or "").upper()
            path = str(req.get("path") or "")
            if method in {"PUT", "PATCH", "DELETE"}:
                violations.append(f"RF {method} {path}")
            elif method == "POST" and rf_forbidden.match(path):
                violations.append(f"RF {method} {path}")

    if s1_server is not None:
        for req in list(s1_server.requests_log):
            method = str(req.get("method") or "").upper()
            path = str(req.get("path") or "")
            if method != "GET":
                violations.append(f"S1 {method} {path}")
            elif path.endswith("/token") or "/token?" in path:
                violations.append(f"S1 {method} {path} (token access)")

    if es_server is not None:
        mc_prefix = "/servicesNS/nobody/missioncontrol/public/v2"
        for req in list(es_server.requests_log):
            method = str(req.get("method") or "").upper()
            path = str(req.get("path") or "")
            if method in {"PUT", "PATCH", "DELETE"}:
                violations.append(f"ES {method} {path}")
                continue
            if method == "POST":
                if path.endswith("/search/jobs"):
                    form = req.get("form") or {}
                    spl = str((form.get("search") or [""])[0])
                    if _get_mutating_spl_commands_re().search(spl):
                        violations.append(f"ES mutating SPL in POST {path}: {spl!r}")
                elif path.startswith(mc_prefix) and path.endswith("/findings/hybrid"):
                    # Hybrid read query is read-only.
                    continue
                else:
                    violations.append(f"ES {method} {path}")

    if violations:
        raise AssertionError(
            "Detected forbidden mutating/remediation HTTP requests:\n"
            + "\n".join(f" - {v}" for v in violations)
        )


# ==============================================================================
# Textual Pilot Helpers
# ==============================================================================


def make_agentic_app(
    workspace_dir: Path,
    *,
    initial_tab: str = "tab-rf-intel",
    dry_run: bool = False,
    preload_alerts: bool = False,
    osint_client: OSINTClient | None = None,
    alert_cache_refresh_seconds: float = 0,
) -> Any:
    """Construct a ``SocLensApp`` isolated to ``workspace_dir`` for Pilot E2E tests."""
    from soclens.tui import create_app

    return create_app(
        dry_run=dry_run,
        initial_tab=initial_tab,
        workspace_dir=workspace_dir,
        view_mode="user",
        no_secret_store=True,
        preload_alerts=preload_alerts,
        osint_client=osint_client,
        alert_cache_refresh_seconds=alert_cache_refresh_seconds,
    )


async def switch_tab_and_wait(app: Any, pilot: Any, tab_id: str) -> Any:
    """Activate ``tab_id`` on ``#main-tabs`` and await lazy pane mounting."""
    from textual.widgets import TabbedContent

    tabs = app.query_one("#main-tabs", TabbedContent)
    tabs.active = tab_id
    await pilot.pause()
    if hasattr(app, "ensure_tab_mounted"):
        await app.ensure_tab_mounted(tab_id)
    await pilot.pause()
    return app


def select_table_row_containing(table: Any, needle: str) -> int:
    """Find the first row containing ``needle`` and move the table cursor to it."""
    lowered = needle.lower()
    for idx, row_key in enumerate(table.rows.keys()):
        cells = table.get_row(row_key)
        joined = " ".join(
            c.plain if hasattr(c, "plain") else str(c) for c in cells
        ).lower()
        if lowered in joined:
            table.move_cursor(row=idx)
            return idx
    raise AssertionError(f"Row containing {needle!r} not found in table #{table.id}")


async def right_click_table_row(
    app: Any,
    pilot: Any,
    table_selector: str,
    row_index: int = 0,
) -> Any:
    """Move cursor to ``row_index`` and send a right-click (button=3) on that row."""
    from textual.widgets import DataTable

    table = app.query_one(table_selector, DataTable)
    assert table.row_count > row_index, f"Expected >{row_index} rows in {table_selector}"
    table.move_cursor(row=row_index)
    await pilot.pause()
    header_rows = int(getattr(table, "header_height", 1) or 1)
    y_offset = 1 + header_rows + row_index
    await pilot.click(table_selector, offset=(4, y_offset), button=3)
    await pilot.pause()
    return app.screen


def richlog_text(app: Any, selector: str) -> str:
    """Extract plain text from a ``RichLog`` / ``SelectableRichLog`` widget."""
    from textual.widgets import RichLog

    log = app.query_one(selector, RichLog)
    return "\n".join(line.text for line in log.lines)


async def async_wait_until(
    predicate: Callable[[], bool],
    *,
    timeout: float = 5.0,
    interval: float = 0.05,
    pilot: Any = None,
) -> None:
    """Poll ``predicate`` asynchronously up to ``timeout`` seconds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        if pilot is not None:
            await pilot.pause()
        await asyncio.sleep(interval)
    assert predicate(), f"Condition timed out after {timeout:.1f}s"
