"""Offline unit tests for Microsoft Copilot (M365 Chat, Direct Line, Security Copilot) integration."""

from __future__ import annotations

import base64
import json
import subprocess
import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from soclens.config import get_local_llm_config, parse_copilot_agent_presets
from soclens.copilot import (
    CopilotDirectLineTransport,
    CopilotTokenResolver,
    extract_activity_text,
    extract_m365_reply_text,
    inspect_jwt_expiry,
)
from soclens.llm import LocalLLMClient, LocalLLMConnectionError, LocalLLMError


def _make_jwt(exp: float, upn: str = "analyst@contoso.com") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
    payload = (
        base64.urlsafe_b64encode(json.dumps({"exp": exp, "upn": upn}).encode())
        .decode()
        .rstrip("=")
    )
    return f"{header}.{payload}.sig"


def _fake_response(
    status_code: int = 200,
    json_data: Any = None,
    lines: list[str] | None = None,
    text: str = "",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text or (json.dumps(json_data) if json_data is not None else "")
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("no json")
    if lines is not None:
        resp.iter_lines.return_value = iter(lines)
    return resp


def test_inspect_jwt_expiry_and_token_resolver_expired() -> None:
    future_jwt = _make_jwt(time.time() + 3600)
    info = inspect_jwt_expiry(future_jwt)
    assert info["is_jwt"] is True
    assert info["expired"] is False
    assert info["upn"] == "analyst@contoso.com"

    expired_jwt = _make_jwt(time.time() - 600)
    resolver = CopilotTokenResolver(auth_mode="token", bearer_token=expired_jwt)
    with pytest.raises(RuntimeError, match="expired"):
        resolver.get_token()


def test_token_resolver_az_cli_caches_token() -> None:
    future_exp = int(time.time() + 1800)
    proc = subprocess.CompletedProcess(
        args=["az"],
        returncode=0,
        stdout=json.dumps({"accessToken": "tok-az-123", "expires_on": future_exp}),
        stderr="",
    )
    resolver = CopilotTokenResolver(auth_mode="az_cli")
    with patch("soclens.copilot.subprocess.run", return_value=proc) as mock_run:
        assert resolver.get_token() == "tok-az-123"
        assert resolver.get_token() == "tok-az-123"
        assert mock_run.call_count == 1


def test_extract_activity_text_adaptive_card_and_citations() -> None:
    activity = {
        "type": "message",
        "text": "Alert triaged as High severity.",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard",
                    "body": [
                        {"type": "TextBlock", "text": "Containment Plan"},
                        {
                            "type": "FactSet",
                            "facts": [{"title": "Host", "value": "WIN-SOC-01"}],
                        },
                    ],
                },
            }
        ],
        "entities": [
            {"name": "MITRE T1059.001", "url": "https://attack.mitre.org/techniques/T1059/001/"}
        ],
    }
    rendered = extract_activity_text(activity)
    assert "Alert triaged as High severity." in rendered
    assert "Containment Plan" in rendered
    assert "**Host**: WIN-SOC-01" in rendered
    assert "[MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/)" in rendered


def test_extract_m365_reply_text_with_attributions() -> None:
    payload = {
        "messages": [
            {"@odata.type": "#microsoft.graph.copilotConversationRequestMessage", "text": "Hello"},
            {
                "@odata.type": "#microsoft.graph.copilotConversationResponseMessage",
                "text": "Encoded PowerShell observed on WIN-01.",
                "attributions": [
                    {
                        "title": "SOC Playbook",
                        "seeMoreWebUrl": "https://contoso.sharepoint.com/sites/soc/playbook",
                    }
                ],
            },
        ]
    }
    rendered = extract_m365_reply_text(payload)
    assert "Encoded PowerShell observed on WIN-01." in rendered
    assert "[SOC Playbook](https://contoso.sharepoint.com/sites/soc/playbook)" in rendered


def test_m365_copilot_chat_and_sse_streaming() -> None:
    session = MagicMock()
    session.request.side_effect = [
        _fake_response(201, {"id": "conv-m365-1"}),
        _fake_response(
            200,
            {
                "messages": [
                    {
                        "@odata.type": "#microsoft.graph.copilotConversationResponseMessage",
                        "text": "First turn reply.",
                    }
                ]
            },
        ),
        _fake_response(
            200,
            lines=[
                'data: {"text": "Streaming "}',
                'data: {"text": "Streaming reply!"}',
                "data: [DONE]",
            ],
        ),
    ]
    cfg = get_local_llm_config(
        provider="m365_copilot",
        ms_bearer_token=_make_jwt(time.time() + 3600),
    )
    with LocalLLMClient(config=cfg, session=session) as client:
        res1 = client.chat([{"role": "user", "content": "Triage host WIN-01"}])
        assert res1["provider"] == "m365_copilot"
        assert res1["conversation_id"] == "conv-m365-1"
        assert "First turn reply." in res1["content"]

        deltas: list[str] = []
        res2 = client.chat(
            [{"role": "user", "content": "Next steps?"}],
            stream_callback=deltas.append,
        )
        assert res2["conversation_id"] == "conv-m365-1"
        assert res2["content"] == "Streaming reply!"
        assert "".join(deltas) == "Streaming reply!"


def test_copilot_directline_token_endpoint_and_polling() -> None:
    session = MagicMock()
    session.request.side_effect = [
        # 1. GET token endpoint
        _fake_response(200, {"token": "dl-tok-1"}),
        # 2. POST /conversations
        _fake_response(201, {"conversationId": "dl-conv-42", "token": "dl-tok-2"}),
        # 3. GET initial greeting drain
        _fake_response(200, {"watermark": "0", "activities": []}),
        # 4. POST user activity
        _fake_response(200, {"id": "act-1"}),
        # 5. GET activities poll 1 (typing only)
        _fake_response(
            200,
            {
                "watermark": "1",
                "activities": [
                    {"type": "message", "from": {"id": "soclens-analyst"}, "text": "Hi"},
                    {"type": "typing", "from": {"id": "bot"}},
                ],
            },
        ),
        # 6. GET activities poll 2 (bot reply)
        _fake_response(
            200,
            {
                "watermark": "2",
                "activities": [
                    {"type": "message", "from": {"id": "bot"}, "text": "IOC is malicious (score 89)."}
                ],
            },
        ),
    ]
    cfg = get_local_llm_config(
        provider="copilot_directline",
        ms_token_endpoint="https://env.api.powerplatform.com/directline/token?api-version=2022-03-01-preview",
    )
    transport = CopilotDirectLineTransport(
        cfg,
        session,
        stop_event=threading.Event(),
        error_factory=LocalLLMError,
        connection_error_factory=LocalLLMConnectionError,
        poll_interval=0.01,
    )
    res = transport.send_turn("Check 198.51.100.10")
    assert res["conversation_id"] == "dl-conv-42"
    assert "IOC is malicious (score 89)." in res["content"]


def test_security_copilot_session_prompt_and_evaluation_polling() -> None:
    session = MagicMock()
    session.request.side_effect = [
        # 1. POST /sessions
        _fake_response(201, {"id": "sc-sess-99"}),
        # 2. POST /prompts
        _fake_response(201, {"id": "sc-prompt-1"}),
        # 3. POST /evaluations
        _fake_response(201, {"id": "sc-eval-1", "state": "running"}),
        # 4. GET /evaluations/{id} -> completed
        _fake_response(
            200,
            {
                "id": "sc-eval-1",
                "state": "completed",
                "result": {"content": "Defender detected EncodedCommand execution on WIN-01."},
            },
        ),
    ]
    cfg = get_local_llm_config(
        provider="security_copilot",
        ms_bearer_token=_make_jwt(time.time() + 3600),
        ms_security_workspace="default",
        ms_security_poll_interval=0.01,
    )
    with LocalLLMClient(config=cfg, session=session) as client:
        res = client.analyze_with_template("triage_alert", "Alert: EncodedCommand on WIN-01")
        assert res["provider"] == "security_copilot"
        assert res["conversation_id"] == "sc-sess-99"
        assert "Defender detected EncodedCommand" in res["content"]


def test_named_agent_presets_and_client_resolution() -> None:
    raw_presets = json.dumps(
        [
            {"name": "Enterprise Chat", "provider": "m365_copilot", "web_grounding": False},
            {
                "name": "SOC Triage Agent",
                "provider": "copilot_directline",
                "token_endpoint": "https://env.api.powerplatform.com/token",
            },
            {
                "name": "SecCopilot Prod",
                "provider": "security_copilot",
                "workspace": "soc-ws-1",
            },
        ]
    )
    presets = parse_copilot_agent_presets(raw_presets)
    assert len(presets) == 3
    assert presets[0].web_grounding is False
    assert presets[1].provider == "copilot_directline"
    assert presets[2].workspace == "soc-ws-1"

    cfg = get_local_llm_config(provider="ollama", agent_presets=presets)
    with LocalLLMClient(config=cfg, agent_name="SecCopilot Prod") as client:
        assert client.provider == "security_copilot"
        assert client.config.ms_security_workspace == "soc-ws-1"
        assert "SecCopilot Prod" in client.list_models()
