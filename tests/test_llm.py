"""Unit tests for LocalLLMConfig, LocalLLMClient (Ollama & OpenAI), and `soclens llm` CLI."""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from soclens import cli
from soclens.config import (
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OPENAI_BASE_URL,
    ConfigurationError,
    ConfiguredSession,
    LocalLLMConfig,
    PivotPayload,
    get_local_llm_config,
    hydrate_secrets_from_store,
)
from soclens.llm import (
    SOC_PROMPT_TEMPLATES,
    LocalLLMClient,
    LocalLLMConfigError,
    LocalLLMConnectionError,
    LocalLLMError,
    build_copilot_prompt,
    format_llm_copilot_context,
)
from soclens.settings import (
    clear_session_overrides,
    invalidate_settings_cache,
    save_profile_settings,
    set_session_overrides,
)


def _mock_response(
    status_code: int = 200,
    json_body: Any = None,
    text_body: str = "",
    lines: list[str] | None = None,
) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text_body
    if json_body is not None:
        resp.json.return_value = json_body
    else:
        resp.json.side_effect = ValueError("No JSON body")
    if lines is not None:
        resp.iter_lines.return_value = iter(lines)
    return resp


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


def test_local_llm_config_defaults_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "RF_LLM_PROVIDER",
        "RF_LLM_BASE_URL",
        "RF_LLM_MODEL",
        "RF_LLM_API_KEY",
        "RF_LLM_TIMEOUT",
        "RF_LLM_VERIFY_SSL",
        "RF_LLM_TEMPERATURE",
        "RF_LLM_MAX_TOKENS",
    ):
        monkeypatch.delenv(var, raising=False)

    cfg = get_local_llm_config()
    assert isinstance(cfg, LocalLLMConfig)
    assert cfg.provider == "ollama"
    assert cfg.base_url == DEFAULT_OLLAMA_BASE_URL
    assert cfg.model is None
    assert cfg.api_key is None
    assert cfg.timeout == 120.0
    assert cfg.verify_ssl is True
    assert cfg.temperature == 0.2
    assert cfg.max_tokens is None

    monkeypatch.setenv("RF_LLM_PROVIDER", "openai")
    monkeypatch.setenv("RF_LLM_MODEL", "qwen2.5-coder")
    monkeypatch.setenv("RF_LLM_API_KEY", "sk-local-secret")
    monkeypatch.setenv("RF_LLM_TIMEOUT", "45.5")
    monkeypatch.setenv("RF_LLM_VERIFY_SSL", "false")
    monkeypatch.setenv("RF_LLM_TEMPERATURE", "0.7")
    monkeypatch.setenv("RF_LLM_MAX_TOKENS", "1024")

    openai_cfg = get_local_llm_config()
    assert openai_cfg.provider == "openai"
    assert openai_cfg.base_url == DEFAULT_OPENAI_BASE_URL
    assert openai_cfg.model == "qwen2.5-coder"
    assert openai_cfg.api_key == "sk-local-secret"
    assert "sk-local-secret" not in repr(openai_cfg)
    assert openai_cfg.timeout == 45.5
    assert openai_cfg.verify_ssl is False
    assert openai_cfg.temperature == 0.7
    assert openai_cfg.max_tokens == 1024


def test_local_llm_config_validation_errors() -> None:
    with pytest.raises(ConfigurationError):
        get_local_llm_config(provider="unknown-provider")
    with pytest.raises(ConfigurationError):
        get_local_llm_config(timeout="-5")
    with pytest.raises(ConfigurationError):
        get_local_llm_config(temperature="3.5")
    with pytest.raises(ConfigurationError):
        get_local_llm_config(max_tokens="0")


# ---------------------------------------------------------------------------
# Ollama client tests
# ---------------------------------------------------------------------------


def test_ollama_list_models_and_check_connection() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _mock_response(
        200,
        json_body={
            "models": [
                {"name": "llama3.2:latest"},
                {"name": "qwen2.5:14b"},
                {"name": "llama3.2:latest"},
            ]
        },
    )

    with LocalLLMClient(provider="ollama", base_url="http://127.0.0.1:11434", session=session) as llm:
        models = llm.list_models()
        assert models == ["llama3.2:latest", "qwen2.5:14b"]

        status = llm.check_connection()
        assert status["ok"] is True
        assert status["provider"] == "ollama"
        assert status["models"] == ["llama3.2:latest", "qwen2.5:14b"]
        assert status["error"] is None

    call_kwargs = session.request.call_args.kwargs
    assert call_kwargs["url"] == "http://127.0.0.1:11434/api/tags"
    assert call_kwargs["method"] == "GET"


def test_ollama_chat_non_streaming() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _mock_response(
        200,
        json_body={
            "model": "llama3.2",
            "message": {"role": "assistant", "content": "Suspicious PowerShell detected."},
            "done": True,
        },
    )

    with LocalLLMClient(provider="ollama", model="llama3.2", session=session) as llm:
        res = llm.chat(
            [{"role": "user", "content": "Analyze this alert."}],
            system_prompt="Be concise.",
            max_tokens=256,
        )

    assert res["content"] == "Suspicious PowerShell detected."
    assert res["model"] == "llama3.2"
    assert res["provider"] == "ollama"
    assert res["done"] is True
    payload = session.request.call_args.kwargs["json"]
    assert payload["stream"] is False
    assert payload["options"]["num_predict"] == 256
    assert payload["messages"][0] == {"role": "system", "content": "Be concise."}


def test_ollama_chat_streaming_ndjson() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _mock_response(
        200,
        lines=[
            json.dumps({"model": "llama3.2", "message": {"content": "Hello "}, "done": False}),
            json.dumps({"model": "llama3.2", "message": {"content": "SOC!"}, "done": True}),
        ],
    )
    chunks: list[str] = []

    with LocalLLMClient(provider="ollama", model="llama3.2", session=session) as llm:
        res = llm.chat(
            [{"role": "user", "content": "Say hi"}],
            stream_callback=chunks.append,
        )

    assert chunks == ["Hello ", "SOC!"]
    assert res["content"] == "Hello SOC!"
    assert res["done"] is True


# ---------------------------------------------------------------------------
# OpenAI-compatible client tests
# ---------------------------------------------------------------------------


def test_openai_compatible_models_and_non_streaming_chat() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _mock_response(200, json_body={"data": [{"id": "mistral-7b"}, {"id": "codellama"}]}),
        _mock_response(
            200,
            json_body={
                "model": "mistral-7b",
                "choices": [{"message": {"role": "assistant", "content": "SPL looks good."}}],
            },
        ),
    ]

    with LocalLLMClient(
        provider="openai",
        base_url="http://127.0.0.1:1234",
        model="mistral-7b",
        api_key="sk-test",
        session=session,
    ) as llm:
        models = llm.list_models()
        assert models == ["mistral-7b", "codellama"]
        res = llm.chat([{"role": "user", "content": "Review SPL"}])
        assert res["content"] == "SPL looks good."
        assert res["provider"] == "openai"

    first_call = session.request.call_args_list[0].kwargs
    assert first_call["url"] == "http://127.0.0.1:1234/v1/models"
    assert first_call["headers"]["Authorization"] == "Bearer sk-test"
    second_call = session.request.call_args_list[1].kwargs
    assert second_call["url"] == "http://127.0.0.1:1234/v1/chat/completions"


def test_openai_compatible_avoids_duplicate_v1_and_streams_sse() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _mock_response(
        200,
        lines=[
            'data: {"model":"local-llm","choices":[{"delta":{"content":"Part 1 "},"finish_reason":null}]}',
            'data: {"model":"local-llm","choices":[{"delta":{"content":"Part 2"},"finish_reason":"stop"}]}',
            "data: [DONE]",
        ],
    )
    chunks: list[str] = []

    with LocalLLMClient(
        provider="openai",
        base_url="http://127.0.0.1:1234/v1",
        model="local-llm",
        session=session,
    ) as llm:
        res = llm.chat([{"role": "user", "content": "Stream"}], stream_callback=chunks.append)

    assert session.request.call_args.kwargs["url"] == "http://127.0.0.1:1234/v1/chat/completions"
    assert chunks == ["Part 1 ", "Part 2"]
    assert res["content"] == "Part 1 Part 2"
    assert res["done"] is True


# ---------------------------------------------------------------------------
# Retries, errors, cancellation, and templates
# ---------------------------------------------------------------------------


def test_transient_retry_and_connection_error() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _mock_response(503, json_body={"error": "loading model"}),
        _mock_response(200, json_body={"models": [{"name": "llama3.2"}]}),
    ]

    with LocalLLMClient(
        provider="ollama",
        session=session,
        max_retries=2,
        backoff_base=0.0,
    ) as llm:
        assert llm.list_models() == ["llama3.2"]
    assert session.request.call_count == 2

    # Exhausted connection error -> LocalLLMConnectionError and check_connection ok=False
    fail_session = MagicMock(spec=requests.Session)
    fail_session.request.side_effect = requests.ConnectionError("Connection refused")
    with LocalLLMClient(
        provider="ollama",
        session=fail_session,
        max_retries=1,
        backoff_base=0.0,
    ) as llm:
        with pytest.raises(LocalLLMConnectionError):
            llm.list_models()
        status = llm.check_connection()
        assert status["ok"] is False
        assert "Connection refused" in str(status["error"])


def test_missing_model_and_stop_event_cancellation() -> None:
    session = MagicMock(spec=requests.Session)
    with LocalLLMClient(provider="ollama", model=None, session=session) as llm:
        with pytest.raises(LocalLLMConfigError):
            llm.chat([{"role": "user", "content": "hello"}])

    stop = threading.Event()
    stop.set()
    with LocalLLMClient(provider="ollama", model="llama3.2", stop_event=stop, session=session) as llm:
        with pytest.raises(LocalLLMError, match="cancelled"):
            llm.chat([{"role": "user", "content": "hello"}])


def test_analyze_with_templates() -> None:
    assert {"freeform", "explain_sigma", "triage_alert", "summarize_ioc", "spl_helper"} <= set(
        SOC_PROMPT_TEMPLATES.keys()
    )

    session = MagicMock(spec=requests.Session)
    session.request.return_value = _mock_response(
        200,
        json_body={
            "model": "llama3.2",
            "message": {"role": "assistant", "content": "Rule detects encoded PowerShell."},
            "done": True,
        },
    )
    with LocalLLMClient(provider="ollama", model="llama3.2", session=session) as llm:
        res = llm.analyze_with_template(
            "explain_sigma",
            "title: Encoded PowerShell\ndetection:\n  selection: '-enc'",
            extra_instruction="Include Splunk tuning tips.",
        )
        assert "PowerShell" in res["content"]
        sent_messages = session.request.call_args.kwargs["json"]["messages"]
        assert sent_messages[0]["role"] == "system"
        assert "Include Splunk tuning tips." in sent_messages[1]["content"]

        with pytest.raises(LocalLLMConfigError):
            llm.analyze_with_template("nonexistent_template", "content")


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


def test_cli_llm_status_models_chat_and_explain_sigma(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_llm = MagicMock(spec=LocalLLMClient)
    mock_llm.__enter__.return_value = mock_llm
    mock_llm.__exit__.return_value = None
    mock_llm.provider = "ollama"
    mock_llm.base_url = "http://127.0.0.1:11434"
    mock_llm.check_connection.return_value = {
        "ok": True,
        "provider": "ollama",
        "base_url": "http://127.0.0.1:11434",
        "models": ["llama3.2"],
        "error": None,
    }
    mock_llm.list_models.return_value = ["llama3.2", "qwen2.5"]
    mock_llm.chat.return_value = {
        "content": "SOC reply",
        "model": "llama3.2",
        "provider": "ollama",
        "done": True,
        "raw": {},
    }
    mock_llm.analyze_with_template.return_value = {
        "content": "Sigma explanation",
        "model": "llama3.2",
        "provider": "ollama",
        "done": True,
        "raw": {},
    }

    with patch.object(cli, "_build_llm_client", return_value=mock_llm):
        # 1. status --json
        monkeypatch.setattr(sys, "argv", ["soclens", "llm", "status", "--json"])
        cli.main()
        out = json.loads(capsys.readouterr().out)
        assert out["ok"] is True
        assert out["models"] == ["llama3.2"]

        # 2. models --json
        monkeypatch.setattr(sys, "argv", ["soclens", "llm", "models", "--json"])
        cli.main()
        out = json.loads(capsys.readouterr().out)
        assert out["models"] == ["llama3.2", "qwen2.5"]

        # 3. chat --prompt --model --json
        monkeypatch.setattr(
            sys,
            "argv",
            ["soclens", "llm", "chat", "--prompt", "What is T1059?", "--model", "llama3.2", "--json"],
        )
        cli.main()
        out = json.loads(capsys.readouterr().out)
        assert out["content"] == "SOC reply"

        # 4. explain-sigma --file
        sigma_file = tmp_path / "rule.yml"
        sigma_file.write_text("title: Test Rule\nlevel: high\n", encoding="utf-8")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "soclens",
                "llm",
                "explain-sigma",
                "--file",
                str(sigma_file),
                "--model",
                "llama3.2",
                "--json",
            ],
        )
        cli.main()
        out = json.loads(capsys.readouterr().out)
        assert out["rule_title"] == "rule.yml"
        assert out["content"] == "Sigma explanation"

        # 5. explain-sigma --rule-id
        with (
            patch.object(cli, "_build_rf_client", return_value=MagicMock()),
            patch.object(
                cli,
                "load_rules",
                return_value=[
                    {
                        "rule_id": "rf-sigma-123",
                        "title": "Encoded PowerShell",
                        "level": "high",
                        "content": "title: Encoded PowerShell\nlevel: high\n",
                    }
                ],
            ),
        ):
            monkeypatch.setattr(
                sys,
                "argv",
                [
                    "soclens",
                    "llm",
                    "explain-sigma",
                    "--rule-id",
                    "rf-sigma-123",
                    "--model",
                    "llama3.2",
                    "--json",
                ],
            )
            cli.main()
            out = json.loads(capsys.readouterr().out)
            assert out["rule_title"] == "Encoded PowerShell"
            assert out["content"] == "Sigma explanation"


# ---------------------------------------------------------------------------
# ConfiguredSession, vault rf_llm_api_key, CA bundle, and Copilot helpers
# ---------------------------------------------------------------------------


def test_local_llm_client_uses_configured_session_and_proxy_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(tmp_path / "settings.json"))
    invalidate_settings_cache()
    clear_session_overrides()
    try:
        set_session_overrides(
            {
                "https_proxy": "http://proxy.example.test:8443",
                "no_proxy": "127.0.0.1,localhost",
            }
        )
        with patch.object(ConfiguredSession, "close", autospec=True) as mock_close:
            client = LocalLLMClient(provider="ollama", base_url="http://127.0.0.1:11434")
            assert isinstance(client.session, ConfiguredSession)
            merged = client.session.merge_environment_settings(
                url="https://llm.remote.example.test/api/tags",
                proxies={},
                stream=False,
                verify=True,
                cert=None,
            )
            assert merged["proxies"]["https"] == "http://proxy.example.test:8443"
            client.close()
            assert mock_close.call_count == 1

        # Injected external session is not closed by client.close()
        external = MagicMock(spec=requests.Session)
        ext_client = LocalLLMClient(provider="ollama", session=external)
        ext_client.close()
        external.close.assert_not_called()
    finally:
        clear_session_overrides()
        invalidate_settings_cache()


def test_local_llm_config_resolves_rf_llm_api_key_from_session_and_ca_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(tmp_path / "settings.json"))
    monkeypatch.delenv("RF_LLM_API_KEY", raising=False)
    monkeypatch.delenv("RF_LLM_VERIFY_SSL", raising=False)
    invalidate_settings_cache()
    clear_session_overrides()
    try:
        set_session_overrides({"rf_llm_api_key": "vault-llm-key-001"}, vault_hydrated=True)
        cfg = get_local_llm_config(provider="openai")
        assert cfg.api_key == "vault-llm-key-001"
        assert "vault-llm-key-001" not in repr(cfg)

        # Env var takes precedence over saved setting and over hydrate(overwrite_existing=False)
        clear_session_overrides()
        save_profile_settings({"rf_llm_api_key": "saved-llm-key"})
        monkeypatch.setenv("RF_LLM_API_KEY", "env-llm-key-999")
        assert get_local_llm_config(provider="openai").api_key == "env-llm-key-999"
        assert hydrate_secrets_from_store(force=True, overwrite_existing=False) == {}
        assert get_local_llm_config(provider="openai").api_key == "env-llm-key-999"

        ca_file = tmp_path / "corp-ca.pem"
        ca_file.write_text("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n", encoding="utf-8")
        monkeypatch.setenv("RF_LLM_VERIFY_SSL", str(ca_file))
        with LocalLLMClient(provider="openai", model="qwen2.5") as ca_client:
            assert ca_client.session.verify == str(ca_file)
    finally:
        clear_session_overrides()
        invalidate_settings_cache()


def test_copilot_prompt_builders_attack_chain_and_closing_note() -> None:
    assert "summarize_attack_chain" in SOC_PROMPT_TEMPLATES
    assert "draft_closing_note" in SOC_PROMPT_TEMPLATES

    full_payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-llm",
        tenant_id="1001",
        hostname="wkstn-1001-01.example.test",
        es_finding={"event_id": "fnd-1", "rule_title": "Encoded PowerShell"},
        s1_threat={"id": "thr-1", "threatName": "Mimikatz.Win64"},
        rf_enrichment={"rf_max_risk_score": 92},
    )
    rendered_full = format_llm_copilot_context(full_payload)
    assert "Tenant 1001" in rendered_full
    assert "fnd-1" in rendered_full
    assert "thr-1" in rendered_full
    assert "92" in rendered_full

    partial_payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-llm",
        tenant_id="1002",
        es_finding={"event_id": "fnd-2"},
        s1_threat=None,
        rf_enrichment=None,
    )
    rendered_partial = format_llm_copilot_context(partial_payload)
    assert "## Splunk ES Finding" in rendered_partial
    assert "SentinelOne Threat" not in rendered_partial
    assert "Recorded Future Enrichment" not in rendered_partial
    assert "```json\nnull\n```" not in rendered_partial

    sys_prompt, user_msg = build_copilot_prompt(
        "summarize_attack_chain",
        full_payload,
        extra_instruction="Highlight lateral movement.",
    )
    assert "attack-chain" in sys_prompt.lower()
    assert "fnd-1" in user_msg
    assert "Highlight lateral movement." in user_msg

    for empty_ctx in (
        "",
        "   ",
        {},
        PivotPayload(source_tab="tab-splunk-es", target_tab="tab-llm"),
    ):
        with pytest.raises(LocalLLMConfigError):
            format_llm_copilot_context(empty_ctx)

    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _mock_response(
            200,
            json_body={
                "model": "llama3.2",
                "message": {"role": "assistant", "content": "Attack chain summary output"},
                "done": True,
            },
        ),
        _mock_response(
            200,
            json_body={
                "model": "llama3.2",
                "message": {"role": "assistant", "content": "Closing note draft output"},
                "done": True,
            },
        ),
    ]
    with LocalLLMClient(provider="ollama", model="llama3.2", session=session) as llm:
        r_chain = llm.summarize_attack_chain(full_payload)
        r_close = llm.draft_closing_note(full_payload)

    assert r_chain["content"] == "Attack chain summary output"
    assert r_close["content"] == "Closing note draft output"
    assert session.request.call_count == 2
    first_messages = session.request.call_args_list[0].kwargs["json"]["messages"]
    second_messages = session.request.call_args_list[1].kwargs["json"]["messages"]
    assert "fnd-1" in first_messages[1]["content"]
    assert "thr-1" in second_messages[1]["content"]
    assert "92" in second_messages[1]["content"]


def test_openai_v1_normalization_and_401_auth_error_handling() -> None:
    for raw_url in (
        "http://127.0.0.1:1234",
        "http://127.0.0.1:1234/",
        "http://127.0.0.1:1234/v1",
        "http://127.0.0.1:1234/v1/",
        "http://127.0.0.1:1234/v1/chat/completions",
    ):
        session = MagicMock(spec=requests.Session)
        session.request.side_effect = [
            _mock_response(200, json_body={"data": [{"id": "qwen2.5"}]}),
            _mock_response(
                200,
                json_body={
                    "model": "qwen2.5",
                    "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                },
            ),
        ]
        with LocalLLMClient(
            provider="openai",
            base_url=raw_url,
            model="qwen2.5",
            api_key="sk-canary-secret-999",
            session=session,
        ) as llm:
            assert llm.list_models() == ["qwen2.5"]
            res = llm.chat([{"role": "user", "content": "ping"}])
            assert res["content"] == "ok"
        assert session.request.call_args_list[0].kwargs["url"] == "http://127.0.0.1:1234/v1/models"
        assert session.request.call_args_list[1].kwargs["url"] == "http://127.0.0.1:1234/v1/chat/completions"

    # HTTP 401 should fail immediately without retries and never leak api_key
    auth_session = MagicMock(spec=requests.Session)
    auth_session.request.return_value = _mock_response(
        401,
        json_body={"error": {"message": "Invalid bearer token"}},
    )
    canary_key = "sk-bad-canary-token-777"
    with LocalLLMClient(
        provider="openai",
        base_url="http://127.0.0.1:1234/v1",
        model="qwen2.5",
        api_key=canary_key,
        max_retries=2,
        backoff_base=0.0,
        session=auth_session,
    ) as llm_401:
        with pytest.raises(LocalLLMError) as exc_info:
            llm_401.chat([{"role": "user", "content": "ping"}])
        assert exc_info.value.status_code == 401
        assert canary_key not in str(exc_info.value)
        assert auth_session.request.call_count == 1


def test_format_llm_copilot_context_renders_spl_query() -> None:
    payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-llm",
        spl_query="index=main | head 5",
    )
    rendered = format_llm_copilot_context(payload)
    assert "## Splunk Query" in rendered
    assert "index=main | head 5" in rendered

    with pytest.raises(LocalLLMConfigError):
        format_llm_copilot_context(
            PivotPayload(
                source_tab="tab-splunk-es",
                target_tab="tab-llm",
                spl_query="   ",
            )
        )


# ---------------------------------------------------------------------------
# Google Gemini API tests
# ---------------------------------------------------------------------------


def test_gemini_config_defaults_aliases_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from soclens.config import DEFAULT_GEMINI_BASE_URL

    for var in (
        "RF_LLM_PROVIDER",
        "RF_LLM_BASE_URL",
        "RF_LLM_MODEL",
        "RF_LLM_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "SOCLENS_GEMINI_API_KEY",
        "GEMINI_MODEL",
        "GEMINI_BASE_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    invalidate_settings_cache()

    monkeypatch.setenv("RF_LLM_PROVIDER", "google-gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyTestSecretKey1234567890abcdef")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")
    invalidate_settings_cache()

    cfg = get_local_llm_config()
    assert cfg.provider == "gemini"
    assert cfg.base_url == DEFAULT_GEMINI_BASE_URL
    assert cfg.model == "gemini-2.5-flash"
    assert cfg.api_key == "AIzaSyTestSecretKey1234567890abcdef"
    assert "AIzaSyTestSecretKey1234567890abcdef" not in repr(cfg)

    # Explicit alias normalization
    for alias in ("gemini", "google", "google_gemini", "gemini-api", "gemini_api"):
        assert get_local_llm_config(provider=alias).provider == "gemini"

    # Custom GEMINI_BASE_URL takes precedence over default
    monkeypatch.setenv("GEMINI_BASE_URL", "https://proxy.corp.local/gemini/v1beta")
    assert get_local_llm_config(provider="gemini").base_url == "https://proxy.corp.local/gemini/v1beta"


def test_gemini_list_models_pagination_and_filtering() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _mock_response(
            200,
            json_body={
                "models": [
                    {
                        "name": "models/gemini-2.5-flash",
                        "supportedGenerationMethods": ["generateContent", "countTokens"],
                    },
                    {
                        "name": "models/text-embedding-004",
                        "supportedGenerationMethods": ["embedContent"],
                    },
                ],
                "nextPageToken": "page-2",
            },
        ),
        _mock_response(
            200,
            json_body={
                "models": [
                    {
                        "name": "models/gemini-2.5-pro",
                        "supportedGenerationMethods": ["generateContent"],
                    },
                ],
            },
        ),
    ]

    with LocalLLMClient(
        provider="gemini",
        base_url="https://generativelanguage.googleapis.com",
        api_key="AIzaSyCanaryModelListKey0123456789",
        session=session,
    ) as llm:
        models = llm.list_models()

    assert models == ["gemini-2.5-flash", "gemini-2.5-pro"]
    first = session.request.call_args_list[0].kwargs
    second = session.request.call_args_list[1].kwargs
    assert first["url"] == "https://generativelanguage.googleapis.com/v1beta/models"
    assert first["headers"]["x-goog-api-key"] == "AIzaSyCanaryModelListKey0123456789"
    assert "AIzaSy" not in first["url"]
    assert second["url"] == "https://generativelanguage.googleapis.com/v1beta/models?pageToken=page-2"


def test_gemini_chat_non_streaming_thinking_filter_and_streaming_sse() -> None:
    # Non-streaming with systemInstruction and thinking part skipped
    session = MagicMock(spec=requests.Session)
    session.request.return_value = _mock_response(
        200,
        json_body={
            "modelVersion": "gemini-2.5-flash-001",
            "candidates": [
                {
                    "content": {
                        "role": "model",
                        "parts": [
                            {"text": "Internal reasoning...", "thought": True},
                            {"text": "IOC 198.51.100.5 is high risk."},
                        ],
                    },
                    "finishReason": "STOP",
                }
            ],
        },
    )

    with LocalLLMClient(
        provider="gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        model="models/gemini-2.5-flash",
        api_key="AIzaSyCanaryChatKey01234567890abcd",
        session=session,
    ) as llm:
        res = llm.chat(
            [{"role": "user", "content": "Analyze 198.51.100.5"}],
            system_prompt="Be concise.",
            temperature=0.3,
            max_tokens=512,
        )

    assert res["content"] == "IOC 198.51.100.5 is high risk."
    assert res["model"] == "gemini-2.5-flash-001"
    assert res["provider"] == "gemini"
    assert res["done"] is True
    req = session.request.call_args.kwargs
    assert req["url"] == "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    assert req["headers"]["x-goog-api-key"] == "AIzaSyCanaryChatKey01234567890abcd"
    body = req["json"]
    assert body["systemInstruction"] == {"parts": [{"text": "Be concise."}]}
    assert body["generationConfig"] == {"temperature": 0.3, "maxOutputTokens": 512}
    assert body["contents"] == [{"role": "user", "parts": [{"text": "Analyze 198.51.100.5"}]}]

    # Streaming SSE
    stream_session = MagicMock(spec=requests.Session)
    stream_session.request.return_value = _mock_response(
        200,
        lines=[
            'data: {"modelVersion":"gemini-2.5-flash","candidates":[{"content":{"role":"model","parts":[{"text":"Step 1. "}]}}]}',
            'data: {"modelVersion":"gemini-2.5-flash","candidates":[{"content":{"role":"model","parts":[{"text":"Step 2."}]},"finishReason":"STOP"}]}',
        ],
    )
    chunks: list[str] = []
    with LocalLLMClient(
        provider="gemini",
        model="gemini-2.5-flash",
        api_key="AIzaSyStreamKey01234567890abcdefgh",
        session=stream_session,
    ) as llm_s:
        s_res = llm_s.chat(
            [{"role": "user", "content": "Stream triage"}],
            stream_callback=chunks.append,
        )

    assert stream_session.request.call_args.kwargs["url"] == (
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
    )
    assert chunks == ["Step 1. ", "Step 2."]
    assert s_res["content"] == "Step 1. Step 2."
    assert s_res["done"] is True


def test_gemini_native_tool_calling_schema_sanitization_and_roundtrip() -> None:
    session = MagicMock(spec=requests.Session)
    session.request.side_effect = [
        _mock_response(
            200,
            json_body={
                "modelVersion": "gemini-2.5-flash",
                "candidates": [
                    {
                        "content": {
                            "role": "model",
                            "parts": [
                                {
                                    "functionCall": {
                                        "name": "rf_lookup_ioc",
                                        "args": {"entity_type": "ip", "value": "198.51.100.5"},
                                    },
                                    "thoughtSignature": "sig-abc-123",
                                }
                            ],
                        },
                        "finishReason": "STOP",
                    }
                ],
            },
        ),
        _mock_response(
            200,
            json_body={
                "modelVersion": "gemini-2.5-flash",
                "candidates": [
                    {
                        "content": {
                            "role": "model",
                            "parts": [{"text": "Risk score is 89."}],
                        },
                        "finishReason": "STOP",
                    }
                ],
            },
        ),
    ]

    tools = [
        {
            "type": "function",
            "function": {
                "name": "rf_lookup_ioc",
                "description": "Look up an IOC in Recorded Future.",
                "parameters": {
                    "$schema": "http://json-schema.org/draft-07/schema#",
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "entity_type": {"type": "string", "enum": ["ip", "domain"]},
                        "value": {"type": ["string", "null"], "default": ""},
                    },
                    "required": ["entity_type", "value"],
                },
            },
        }
    ]

    with LocalLLMClient(
        provider="gemini",
        model="gemini-2.5-flash",
        api_key="AIzaSyToolTestKey01234567890abcdef",
        session=session,
    ) as llm:
        turn1 = llm.chat(
            [{"role": "user", "content": "Check IP 198.51.100.5"}],
            tools=tools,
            tool_choice="auto",
        )
        assert len(turn1["tool_calls"]) == 1
        tc = turn1["tool_calls"][0]
        assert tc["function"]["name"] == "rf_lookup_ioc"
        assert json.loads(tc["function"]["arguments"]) == {
            "entity_type": "ip",
            "value": "198.51.100.5",
        }
        assert tc["thoughtSignature"] == "sig-abc-123"

        # Verify schema sanitization on Turn 1 request
        req1_body = session.request.call_args_list[0].kwargs["json"]
        decl = req1_body["tools"][0]["functionDeclarations"][0]
        assert "$schema" not in decl["parameters"]
        assert "additionalProperties" not in decl["parameters"]
        assert decl["parameters"]["properties"]["value"] == {"type": "string", "nullable": True}
        assert req1_body["toolConfig"] == {"functionCallingConfig": {"mode": "AUTO"}}

        # Turn 2: pass assistant tool_calls + tool result back
        turn2 = llm.chat(
            [
                {"role": "user", "content": "Check IP 198.51.100.5"},
                {"role": "assistant", "content": "", "tool_calls": turn1["tool_calls"]},
                {
                    "role": "tool",
                    "name": "rf_lookup_ioc",
                    "tool_call_id": tc["id"],
                    "content": json.dumps({"risk_score": 89}),
                },
            ],
            tools=tools,
        )
        assert turn2["content"] == "Risk score is 89."

    req2_contents = session.request.call_args_list[1].kwargs["json"]["contents"]
    assert req2_contents[1]["role"] == "model"
    assert req2_contents[1]["parts"][0]["functionCall"] == {
        "name": "rf_lookup_ioc",
        "args": {"entity_type": "ip", "value": "198.51.100.5"},
    }
    assert req2_contents[1]["parts"][0]["thoughtSignature"] == "sig-abc-123"
    assert req2_contents[2] == {
        "role": "user",
        "parts": [{"functionResponse": {"name": "rf_lookup_ioc", "response": {"risk_score": 89}}}],
    }


def test_gemini_prompt_blocked_and_audit_redaction() -> None:
    from soclens.agent_audit import redact_sensitive_data

    session = MagicMock(spec=requests.Session)
    session.request.return_value = _mock_response(
        200,
        json_body={"promptFeedback": {"blockReason": "SAFETY"}},
    )
    with LocalLLMClient(
        provider="gemini",
        model="gemini-2.5-flash",
        api_key="AIzaSyBlockedCanary0123456789abcde",
        session=session,
    ) as llm:
        with pytest.raises(LocalLLMError, match="SAFETY"):
            llm.chat([{"role": "user", "content": "test"}])

    redacted = redact_sensitive_data(
        {
            "gemini_api_key": "AIzaSyAuditLeakTest0123456789abcde",
            "headers": {"x-goog-api-key": "AIzaSyAuditLeakTest0123456789abcde"},
            "note": "leaked AIzaSyAuditLeakTest0123456789abcde in text",
        }
    )
    assert "AIzaSyAuditLeakTest" not in json.dumps(redacted)


def test_cli_llm_gemini_status_and_chat(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_llm = MagicMock(spec=LocalLLMClient)
    fake_llm.__enter__.return_value = fake_llm
    fake_llm.__exit__.return_value = None
    fake_llm.check_connection.return_value = {
        "ok": True,
        "provider": "gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "models": ["gemini-2.5-flash", "gemini-2.5-pro"],
        "error": None,
    }
    fake_llm.chat.return_value = {
        "content": "Gemini triage summary.",
        "model": "gemini-2.5-flash",
        "provider": "gemini",
        "done": True,
        "raw": {},
    }

    with patch("soclens.cli.LocalLLMClient", return_value=fake_llm):
        monkeypatch.setattr(
            sys, "argv", ["soclens", "llm", "status", "--provider", "gemini", "--json"]
        )
        cli.main()
        out = json.loads(capsys.readouterr().out)
        assert out["ok"] is True
        assert out["provider"] == "gemini"
        assert "gemini-2.5-flash" in out["models"]

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "soclens",
                "llm",
                "chat",
                "--provider",
                "gemini",
                "--model",
                "gemini-2.5-flash",
                "--prompt",
                "Summarize IOC",
                "--json",
            ],
        )
        cli.main()
        chat_out = json.loads(capsys.readouterr().out)
        assert chat_out["content"] == "Gemini triage summary."
        assert chat_out["provider"] == "gemini"


def test_cli_llm_chat_with_tools_flag_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from tests.e2e.agentic_mocks import MockAgenticLLMAndCopilotServer

    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(tmp_path / "settings.json"))
    clear_session_overrides()
    invalidate_settings_cache()

    fake_splunk = MagicMock()
    fake_splunk.run_search.return_value = [{"host": "cli-host-01", "count": 7}]

    with MockAgenticLLMAndCopilotServer() as server:
        server.configure_provider(monkeypatch, "openai")
        monkeypatch.setenv("SPLUNK_HOST", "https://splunk.local:8089")
        monkeypatch.setenv("SPLUNK_TOKEN", "cli-splunk-token")

        server.queue_scripted_turn(
            provider="openai",
            tool_calls=[{"name": "splunk_search", "arguments": {"spl": "index=main | head 5"}}],
        )
        server.queue_scripted_turn(
            provider="openai",
            content="CLI tools summary: 7 events on cli-host-01.",
        )

        with patch("soclens.splunk.SplunkClient", return_value=fake_splunk):
            monkeypatch.setattr(
                sys,
                "argv",
                [
                    "soclens",
                    "llm",
                    "chat",
                    "--provider",
                    "openai",
                    "--prompt",
                    "Find recent events in Splunk",
                    "--tools",
                    "--workspace",
                    str(tmp_path),
                    "--json",
                ],
            )
            cli.main()

        out = json.loads(capsys.readouterr().out)
        assert out["provider"] == "openai"
        assert "cli-host-01" in out["content"]
        assert len(out["tool_calls"]) == 1
        assert out["tool_calls"][0]["tool_name"] == "splunk_search"
        assert out["tool_calls"][0]["ok"] is True
        assert out["blocked_actions"] == []
        assert out["run_id"]
        assert (tmp_path / ".soclens_cache" / "ai_audit.jsonl").is_file()


def test_cli_llm_kill_policy_and_max_tool_steps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from tests.e2e.agentic_mocks import MockAgenticLLMAndCopilotServer

    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(tmp_path / "settings.json"))
    clear_session_overrides()
    invalidate_settings_cache()

    # 1. Configure policy via `soclens llm policy`
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "soclens",
            "llm",
            "policy",
            "--max-tool-steps",
            "180",
            "--max-identical-calls",
            "4",
            "--max-tool-failures",
            "12",
            "--kill-hotkey",
            "f11",
            "--kill-label",
            "STOP AI",
            "--workspace",
            str(tmp_path),
            "--json",
        ],
    )
    cli.main()
    pol_out = json.loads(capsys.readouterr().out)
    assert pol_out["max_tool_steps"] == 180
    assert pol_out["max_identical_tool_calls"] == 4
    assert pol_out["max_same_tool_failures"] == 12
    assert pol_out["kill_switch_hotkey"] == "f11"
    assert pol_out["kill_switch_label"] == "STOP AI"

    # 2. Engage kill switch via `soclens llm kill --on`
    monkeypatch.setattr(
        sys,
        "argv",
        ["soclens", "llm", "kill", "--on", "--workspace", str(tmp_path), "--json"],
    )
    cli.main()
    kill_on_out = json.loads(capsys.readouterr().out)
    assert kill_on_out["ai_kill_switch_active"] is True

    monkeypatch.setattr(
        sys,
        "argv",
        ["soclens", "llm", "kill", "--status", "--workspace", str(tmp_path), "--json"],
    )
    cli.main()
    status_out = json.loads(capsys.readouterr().out)
    assert status_out["ai_kill_switch_active"] is True

    # While killed, `llm chat` refuses cleanly with non-zero exit
    with MockAgenticLLMAndCopilotServer() as server:
        server.configure_provider(monkeypatch, "openai")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "soclens",
                "llm",
                "chat",
                "--provider",
                "openai",
                "--prompt",
                "Should fail when killed",
                "--workspace",
                str(tmp_path),
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
        assert exc_info.value.code != 0
        capsys.readouterr()

        # 3. Disengage kill switch -> `llm chat --tools --max-tool-steps 12` succeeds
        monkeypatch.setattr(
            sys,
            "argv",
            ["soclens", "llm", "kill", "--off", "--workspace", str(tmp_path), "--json"],
        )
        cli.main()
        kill_off_out = json.loads(capsys.readouterr().out)
        assert kill_off_out["ai_kill_switch_active"] is False

        server.queue_scripted_turn(provider="openai", content="Resumed CLI chat OK.")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "soclens",
                "llm",
                "chat",
                "--provider",
                "openai",
                "--prompt",
                "Resume check",
                "--tools",
                "--max-tool-steps",
                "12",
                "--workspace",
                str(tmp_path),
                "--json",
            ],
        )
        cli.main()
        resumed_out = json.loads(capsys.readouterr().out)
        assert resumed_out["content"] == "Resumed CLI chat OK."


def test_saved_llm_provider_model_base_url_and_gemini_default_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.config import DEFAULT_GEMINI_BASE_URL, DEFAULT_GEMINI_MODEL

    for var in (
        "RF_LLM_PROVIDER",
        "RF_LLM_BASE_URL",
        "RF_LLM_MODEL",
        "GEMINI_MODEL",
        "GEMINI_BASE_URL",
        "SOCLENS_LLM_VISIBLE_PROVIDERS",
    ):
        monkeypatch.delenv(var, raising=False)
    settings_path = tmp_path / "settings.json"
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(settings_path))
    clear_session_overrides()
    invalidate_settings_cache()

    # 1. With llm_visible_providers="gemini" and NO model set, Gemini defaults to gemini-2.5-flash
    save_profile_settings(
        {"llm_visible_providers": "gemini", "gemini_api_key": "AIzaSySavedOnlyKey123456"},
        settings_path=settings_path,
    )
    invalidate_settings_cache()
    gemini_auto = get_local_llm_config()
    assert gemini_auto.provider == "gemini"
    assert gemini_auto.model == DEFAULT_GEMINI_MODEL
    assert gemini_auto.base_url == DEFAULT_GEMINI_BASE_URL

    # 2. Explicit saved rf_llm_provider, rf_llm_model, and rf_llm_base_url take effect cleanly
    save_profile_settings(
        {
            "rf_llm_provider": "gemini",
            "rf_llm_model": "gemini-2.5-pro",
            "rf_llm_base_url": "https://gemini-proxy.corp.local/v1beta",
        },
        settings_path=settings_path,
    )
    invalidate_settings_cache()
    gemini_saved = get_local_llm_config()
    assert gemini_saved.provider == "gemini"
    assert gemini_saved.model == "gemini-2.5-pro"
    assert gemini_saved.base_url == "https://gemini-proxy.corp.local/v1beta"

    # 3. An Ollama/OpenAI saved rf_llm_base_url must NOT override Gemini's default endpoint
    save_profile_settings(
        {
            "rf_llm_provider": "ollama",
            "rf_llm_model": "llama3.2:latest",
            "rf_llm_base_url": "http://ollama.corp.local:11434",
        },
        settings_path=settings_path,
    )
    invalidate_settings_cache()
    ollama_cfg = get_local_llm_config()
    assert ollama_cfg.provider == "ollama"
    assert ollama_cfg.model == "llama3.2:latest"
    assert ollama_cfg.base_url == "http://ollama.corp.local:11434"

    gemini_override = get_local_llm_config(provider="gemini")
    assert gemini_override.provider == "gemini"
    assert gemini_override.base_url == DEFAULT_GEMINI_BASE_URL

    # 4. Explicit GEMINI_MODEL env var overrides DEFAULT_GEMINI_MODEL when rf_llm_model is cleared
    save_profile_settings({"rf_llm_model": None}, settings_path=settings_path)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.0-flash")
    invalidate_settings_cache()
    assert get_local_llm_config(provider="gemini").model == "gemini-2.0-flash"



