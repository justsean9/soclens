"""Unit tests for soclens.config."""

from __future__ import annotations

import io
import json
import logging
import os
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from soclens.config import (
    UI_VIEW_ADMIN,
    UI_VIEW_USER,
    ConfigurationError,
    SplunkConfig,
    configure_logging,
    ensure_utf8_console,
    format_ssl_verify_status,
    get_proxy_summary,
    get_rf_asi_key,
    get_rf_pfi_token,
    get_rf_riskrecon_token,
    get_rf_sandbox_token,
    get_rf_token,
    get_rf_verify_ssl,
    get_splunk_config,
    get_ui_view_mode,
    get_workspace_dir,
    has_rf_ssl_env_override,
    parse_ssl_verify,
    record_api_error,
)


def test_get_workspace_dir_resolution_priority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cwd_dir = tmp_path / "cwd_ws"
    env_dir = tmp_path / "env_ws"
    explicit_dir = tmp_path / "explicit_ws"
    cwd_dir.mkdir()
    env_dir.mkdir()
    explicit_dir.mkdir()

    monkeypatch.chdir(cwd_dir)
    monkeypatch.delenv("SOCLENS_HOME", raising=False)
    assert get_workspace_dir() == cwd_dir.resolve()

    monkeypatch.setenv("SOCLENS_HOME", str(env_dir))
    assert get_workspace_dir() == env_dir.resolve()

    assert get_workspace_dir(explicit_dir) == explicit_dir.resolve()
    assert get_workspace_dir("   ") == env_dir.resolve()


def test_get_rf_token_precedence_and_validation() -> None:
    with patch.dict(
        os.environ,
        {"RF_API_TOKEN": "rf_tok", "RECORDED_FUTURE_API_KEY": "legacy_tok"},
        clear=True,
    ):
        assert get_rf_token() == "rf_tok"
        assert get_rf_token(explicit="  explicit_tok  ") == "explicit_tok"

    with patch.dict(os.environ, {"RECORDED_FUTURE_API_KEY": "legacy_tok"}, clear=True):
        assert get_rf_token() == "legacy_tok"

    with patch.dict(os.environ, {"RF_API_TOKEN": "   "}, clear=True):
        assert get_rf_token(required=False) is None
        with pytest.raises(ConfigurationError) as exc_info:
            get_rf_token(required=True)
        assert isinstance(exc_info.value, ValueError)


def test_get_rf_sandbox_token_precedence() -> None:
    with patch.dict(
        os.environ,
        {"RF_SANDBOX_TOKEN": "sb_tok", "RF_API_TOKEN": "core_tok"},
        clear=True,
    ):
        assert get_rf_sandbox_token() == "sb_tok"
        assert get_rf_sandbox_token(explicit="explicit_sb") == "explicit_sb"

    with patch.dict(os.environ, {"RF_API_TOKEN": "core_tok"}, clear=True):
        assert get_rf_sandbox_token(default_core_token="arg_core") == "arg_core"
        assert get_rf_sandbox_token() == "core_tok"

    with patch.dict(os.environ, {}, clear=True):
        assert get_rf_sandbox_token(required=False) is None
        with pytest.raises(ConfigurationError):
            get_rf_sandbox_token(required=True)


def test_get_rf_external_platform_tokens() -> None:
    with patch.dict(
        os.environ,
        {"RF_ASI_API_KEY": "asi_primary", "SECURITYTRAILS_API_KEY": "st_fallback"},
        clear=True,
    ):
        assert get_rf_asi_key() == "asi_primary"
        assert get_rf_asi_key(explicit="  explicit_asi ") == "explicit_asi"

    with patch.dict(os.environ, {"SECURITYTRAILS_API_KEY": "st_fallback"}, clear=True):
        assert get_rf_asi_key() == "st_fallback"

    with patch.dict(os.environ, {}, clear=True):
        assert get_rf_asi_key(required=False) is None
        with pytest.raises(ConfigurationError):
            get_rf_asi_key(required=True)

    with patch.dict(
        os.environ,
        {"RF_PFI_TOKEN": "pfi_tok", "RF_API_TOKEN": "core_tok"},
        clear=True,
    ):
        assert get_rf_pfi_token() == "pfi_tok"
        assert get_rf_pfi_token(explicit="explicit_pfi") == "explicit_pfi"

    with patch.dict(os.environ, {"RF_API_TOKEN": "core_tok"}, clear=True):
        assert get_rf_pfi_token(default_core_token="arg_core") == "arg_core"
        assert get_rf_pfi_token() == "core_tok"

    with patch.dict(os.environ, {}, clear=True):
        assert get_rf_pfi_token(required=False) is None
        with pytest.raises(ConfigurationError):
            get_rf_pfi_token(required=True)

    with patch.dict(
        os.environ,
        {"RF_RISKRECON_TOKEN": "rr_primary", "RISKRECON_API_TOKEN": "rr_fallback"},
        clear=True,
    ):
        assert get_rf_riskrecon_token() == "rr_primary"
        assert get_rf_riskrecon_token(explicit="explicit_rr") == "explicit_rr"

    with patch.dict(os.environ, {"RISKRECON_API_TOKEN": "rr_fallback"}, clear=True):
        assert get_rf_riskrecon_token() == "rr_fallback"

    with patch.dict(os.environ, {}, clear=True):
        assert get_rf_riskrecon_token(required=False) is None
        with pytest.raises(ConfigurationError):
            get_rf_riskrecon_token(required=True)


def test_get_splunk_config_defaults_and_env() -> None:
    with patch.dict(os.environ, {}, clear=True):
        cfg = get_splunk_config()
        assert isinstance(cfg, SplunkConfig)
        assert cfg.host == "https://127.0.0.1:8089"
        assert cfg.app == "SplunkEnterpriseSecuritySuite"
        assert cfg.verify_ssl is False
        assert cfg.has_auth is False
        with pytest.raises(ConfigurationError):
            get_splunk_config(required=True)

    with patch.dict(
        os.environ,
        {
            "SPLUNK_HOST": "splunk.internal:8089/",
            "SPLUNK_TOKEN": "tok_123",
            "SPLUNK_APP": "CustomES",
            "SPLUNK_VERIFY_SSL": "true",
        },
        clear=True,
    ):
        cfg = get_splunk_config(required=True)
        assert cfg.host == "https://splunk.internal:8089"
        assert cfg.token == "tok_123"
        assert cfg.app == "CustomES"
        assert cfg.verify_ssl is True
        assert cfg.has_auth is True

    with patch.dict(
        os.environ,
        {
            "SPLUNK_HOST": "http://localhost:8089",
            "SPLUNK_USERNAME": "admin",
            "SPLUNK_PASSWORD": "secret",
            "SPLUNK_VERIFY_SSL": "/etc/ssl/ca.pem",
        },
        clear=True,
    ):
        cfg = get_splunk_config(required=True)
        assert cfg.host == "http://localhost:8089"
        assert cfg.verify_ssl == "/etc/ssl/ca.pem"
        assert cfg.has_auth is True


def test_ensure_utf8_console_handles_mock_and_non_utf8_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_out = MagicMock()
    mock_out.encoding = "cp1252"
    mock_err = io.StringIO()

    monkeypatch.setattr("sys.stdout", mock_out)
    monkeypatch.setattr("sys.stderr", mock_err)
    ensure_utf8_console()
    mock_out.reconfigure.assert_called_once_with(encoding="utf-8", errors="replace")

    failing_out = MagicMock()
    failing_out.encoding = "cp1252"
    failing_out.reconfigure.side_effect = OSError("cannot reconfigure")
    monkeypatch.setattr("sys.stdout", failing_out)
    monkeypatch.setattr("sys.stderr", None)
    ensure_utf8_console()


def test_configure_logging_idempotent_and_file_output(tmp_path: Path) -> None:
    buf = io.StringIO()
    log_path = tmp_path / "nested" / "app.log"

    logger_1 = configure_logging(level="DEBUG", log_file=log_path, stream=buf)
    logger_2 = configure_logging(level=logging.INFO, log_file=log_path, stream=buf)
    assert logger_1 is logger_2

    logger_2.info("hello utf8 café")
    for handler in logger_2.handlers:
        handler.flush()

    lines = [line for line in buf.getvalue().splitlines() if "hello utf8" in line]
    assert len(lines) == 1
    assert "hello utf8 café" in log_path.read_text(encoding="utf-8")

    with pytest.raises(ConfigurationError):
        configure_logging(level="NOT_A_REAL_LEVEL")

    for invalid_bool in (True, False):
        with pytest.raises(ConfigurationError) as exc_info:
            configure_logging(level=invalid_bool)
        assert isinstance(exc_info.value, ValueError)


def test_record_api_error_thread_safe_jsonl(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"

    def worker(idx: int) -> None:
        record_api_error(
            {
                "endpoint": f"/v2/ip/{idx}",
                "method": "GET",
                "status_code": 400,
                "traceId": f"trace-{idx}",
                "message": "Invalid IP",
                "reason": "bad_request",
                "category": "connect_v2",
            },
            log_dir=log_dir,
        )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    jsonl_file = log_dir / "rf_api_errors.jsonl"
    assert jsonl_file.exists()
    lines = jsonl_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 10
    parsed = [json.loads(line) for line in lines]
    assert {item["trace_id"] for item in parsed} == {f"trace-{i}" for i in range(10)}
    assert all("timestamp" in item for item in parsed)


def test_parse_ssl_verify_and_get_rf_verify_ssl_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert parse_ssl_verify(None, default=True) is True
    assert parse_ssl_verify(None, default=False) is False
    assert parse_ssl_verify("", default=True) is True
    assert parse_ssl_verify(Path("/etc/ssl/corp.pem")) == "/etc/ssl/corp.pem"
    for falsy in ("0", "false", "FALSE", "no", "off"):
        assert parse_ssl_verify(falsy, default=True) is False
    for truthy in ("1", "true", "TRUE", "yes", "on"):
        assert parse_ssl_verify(truthy, default=False) is True
    assert parse_ssl_verify("/etc/ssl/custom-ca.pem") == "/etc/ssl/custom-ca.pem"

    for key in ("RF_VERIFY_SSL", "RF_INSECURE_SSL", "SOCLENS_INSECURE_SSL", "RF_CA_BUNDLE"):
        monkeypatch.delenv(key, raising=False)

    assert has_rf_ssl_env_override() is False
    assert get_rf_verify_ssl() is True

    monkeypatch.setenv("RF_CA_BUNDLE", "/etc/ssl/rf-ca.pem")
    assert has_rf_ssl_env_override() is True
    assert get_rf_verify_ssl() == "/etc/ssl/rf-ca.pem"

    monkeypatch.setenv("SOCLENS_INSECURE_SSL", "1")
    assert get_rf_verify_ssl() is False

    monkeypatch.setenv("RF_INSECURE_SSL", "false")
    monkeypatch.delenv("SOCLENS_INSECURE_SSL", raising=False)
    assert get_rf_verify_ssl() is True

    monkeypatch.setenv("RF_INSECURE_SSL", "true")
    assert get_rf_verify_ssl() is False

    # RF_VERIFY_SSL overrides RF_INSECURE_SSL and RF_CA_BUNDLE
    monkeypatch.setenv("RF_VERIFY_SSL", "/etc/ssl/override.pem")
    assert get_rf_verify_ssl() == "/etc/ssl/override.pem"
    monkeypatch.setenv("RF_VERIFY_SSL", "false")
    assert get_rf_verify_ssl() is False
    monkeypatch.setenv("RF_VERIFY_SSL", "true")
    assert get_rf_verify_ssl() is True

    # Explicit overrides beat environment
    monkeypatch.setenv("RF_VERIFY_SSL", "true")
    assert get_rf_verify_ssl(insecure=True) is False
    assert get_rf_verify_ssl(ca_bundle="/tmp/explicit-ca.pem") == "/tmp/explicit-ca.pem"
    assert get_rf_verify_ssl(explicit=False) is False
    assert get_rf_verify_ssl(insecure=False) is True


def test_get_proxy_summary_masks_credentials_and_format_ssl_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    ):
        monkeypatch.delenv(key, raising=False)

    assert get_proxy_summary() == "None (Direct)"
    assert format_ssl_verify_status(True) == "Enabled (Verified)"
    assert format_ssl_verify_status(False) == "INSECURE (Disabled - Proxy Mode)"
    assert format_ssl_verify_status("/etc/ssl/corp.pem") == "Custom CA (/etc/ssl/corp.pem)"

    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/etc/ssl/requests-ca.pem")
    assert format_ssl_verify_status(True) == "Enabled (Env CA: /etc/ssl/requests-ca.pem)"

    monkeypatch.setenv("HTTPS_PROXY", "http://alice:s3cr3t!@proxy.corp.local:8080")
    monkeypatch.setenv("http_proxy", "http://proxy2.corp.local:3128")
    summary = get_proxy_summary()
    assert "alice" not in summary
    assert "s3cr3t!" not in summary
    assert "HTTPS=http://***@proxy.corp.local:8080" in summary
    assert "HTTP=http://proxy2.corp.local:3128" in summary


def test_get_ui_view_mode_resolution_and_validation() -> None:
    with patch.dict(os.environ, {}, clear=True):
        assert get_ui_view_mode() == UI_VIEW_USER
        assert get_ui_view_mode("  ADMIN ") == UI_VIEW_ADMIN
        assert get_ui_view_mode("user") == UI_VIEW_USER

    with patch.dict(os.environ, {"SOCLENS_UI_VIEW": "admin"}, clear=True):
        assert get_ui_view_mode() == UI_VIEW_ADMIN
        assert get_ui_view_mode("user") == UI_VIEW_USER

    with patch.dict(os.environ, {"SOCLENS_UI_VIEW": "bogus"}, clear=True):
        with pytest.raises(ConfigurationError):
            get_ui_view_mode()

    with pytest.raises(ConfigurationError):
        get_ui_view_mode("superuser")
