"""Tier 2 opaque-box boundary, negative, and corner-case E2E tests for F1-F6."""

from __future__ import annotations

import io
import json
import logging
import re
import socket
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import requests

if TYPE_CHECKING:
    from tests.e2e.conftest import MockRFServer

pytestmark = [pytest.mark.e2e, pytest.mark.tier2]

REPO_ROOT = Path(__file__).resolve().parents[2]
REVIEW_DOC_PATH = REPO_ROOT / "docs" / "RF_API_REVIEW.md"


def _read_review_doc() -> str:
    return REVIEW_DOC_PATH.read_text(encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    assert path.is_file(), f"Expected JSONL log file at {path}"
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def _lower_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


# ==============================================================================
# F1: RF API Review Document — Boundary & Structural Checks
# ==============================================================================


@pytest.mark.feature("F1")
def test_f1_review_doc_discrepancies_against_legacy_rf_md() -> None:
    content = _read_review_doc()
    for expected in (
        "RF-DOCS-2026Q1",
        "RF-DOCS-2026Q4",
        "8 distinct schemas",
        "/dark_web_brand",
        "/social_media_impersonation",
        "/alert/v3",
        'updated: {"after", "before"}',
        "next_offset",
        '"companybydomain"',
    ):
        assert expected in content


@pytest.mark.feature("F1")
def test_f1_review_doc_all_21_list_types_and_client_parity() -> None:
    from soclens.client import LIST_TYPES, ListType
    from tests.e2e.conftest import ALL_LIST_TYPES

    content = _read_review_doc()
    assert "21 list types" in content
    assert len(LIST_TYPES) == 21
    assert len(ListType) == 21
    assert set(LIST_TYPES) == set(ALL_LIST_TYPES)


@pytest.mark.feature("F1")
def test_f1_review_doc_watchlist_limits_and_auto_resolution() -> None:
    from soclens.client import AUTO_RESOLVED_ENTITY_TYPES, MAX_ENTITY_TAGS, WATCHLIST_DEFAULT_LIMIT

    content = _read_review_doc()
    for expected in (
        "1,000 entities",
        "15,000",
        "Meta Company Impersonation",
        "limit of 1",
        "1 entity per request",
        ">= 900",
        "IpAddress",
        "InternetDomainName",
        "Hash",
        "CyberVulnerability",
    ):
        assert expected in content
    assert WATCHLIST_DEFAULT_LIMIT == 1000
    assert MAX_ENTITY_TAGS == 9
    assert set(AUTO_RESOLVED_ENTITY_TYPES.values()) == {
        "IpAddress",
        "InternetDomainName",
        "Hash",
        "CyberVulnerability",
    }


@pytest.mark.feature("F1")
def test_f1_review_doc_no_hardcoded_secrets_or_live_tokens() -> None:
    targets = [
        REVIEW_DOC_PATH,
        REPO_ROOT / "soclens" / "config.py",
        REPO_ROOT / "soclens" / "client.py",
    ]
    secret_patterns = (
        re.compile(r"X-RFToken:\s*[0-9a-fA-F]{24,}"),
        re.compile(r"Authorization:\s*Bearer\s+[0-9a-fA-F]{24,}"),
        re.compile(r'(?:RF_API_TOKEN|RECORDED_FUTURE_API_KEY)\s*=\s*["\'][A-Za-z0-9_-]{16,}["\']'),
    )
    apikey_file = REPO_ROOT / "apikey.key"
    live_key = apikey_file.read_text(encoding="utf-8").strip() if apikey_file.is_file() else ""

    for path in targets:
        text = path.read_text(encoding="utf-8")
        for pat in secret_patterns:
            assert not pat.search(text), f"Potential hardcoded secret in {path}: {pat.pattern}"
        if live_key and len(live_key) >= 12:
            assert live_key not in text, f"apikey.key secret leaked in {path}"


@pytest.mark.feature("F1")
def test_f1_review_doc_markdown_tables_well_formed() -> None:
    content = _read_review_doc()
    assert "TBD" not in content
    assert "TODO" not in content

    lines = content.splitlines()
    tables: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip().startswith("|"):
            current.append(line.strip())
        elif current:
            tables.append(current)
            current = []
    if current:
        tables.append(current)

    assert len(tables) >= 5
    for table in tables:
        assert len(table) >= 3, f"Incomplete markdown table: {table}"
        col_counts = [len(re.split(r"(?<!\\)\|", row.strip("|"))) for row in table]
        assert col_counts[0] >= 2
        assert len(set(col_counts)) == 1, f"Mismatched columns in table: {table[0]}"
        assert re.fullmatch(r"[\|\-\:\s]+", table[1]), f"Invalid separator row: {table[1]}"


@pytest.mark.feature("F1")
def test_f1_review_doc_all_21_surfaces_enumerated() -> None:
    content = _read_review_doc()
    sec22_match = re.search(
        r"### 2\.2 Complete 21-Surface API Directory\n\n(.*?)\n---",
        content,
        flags=re.DOTALL,
    )
    assert sec22_match is not None
    rows = [
        line.strip()
        for line in sec22_match.group(1).splitlines()
        if line.strip().startswith("|")
        and not line.strip().startswith("|---")
        and "# | API Family" not in line
    ]
    assert len(rows) == 21
    numbers: list[int] = []
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert len(cells) == 6
        assert all(cells)
        numbers.append(int(cells[0]))
    assert numbers == list(range(1, 22))


# ==============================================================================
# F2: Cross-Platform Config & traceId Persistence — Boundary & Negative
# ==============================================================================


@pytest.mark.feature("F2")
def test_f2_missing_and_whitespace_tokens_raise_config_error(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    run_cli: Callable[..., Any],
) -> None:
    from soclens.config import (
        ConfigurationError,
        get_rf_sandbox_token,
        get_rf_token,
        get_splunk_config,
    )

    assert e2e_workspace.is_dir()
    monkeypatch.setenv("RF_API_TOKEN", "   ")
    monkeypatch.setenv("RECORDED_FUTURE_API_KEY", "\t\n")
    monkeypatch.setenv("RF_SANDBOX_TOKEN", "  ")
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("SPLUNK_USERNAME", raising=False)
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)

    assert issubclass(ConfigurationError, ValueError)
    with pytest.raises(ConfigurationError):
        get_rf_token(required=True)
    assert get_rf_token(required=False) is None

    with pytest.raises(ConfigurationError):
        get_rf_sandbox_token(required=True)
    with pytest.raises(ConfigurationError):
        get_splunk_config(required=True)

    proc = run_cli(
        ["watchlist", "list"],
        env={"RF_API_TOKEN": "", "RECORDED_FUTURE_API_KEY": ""},
    )
    assert proc.returncode != 0


@pytest.mark.feature("F2")
def test_f2_invalid_and_whitespace_soclens_home_handling(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient
    from soclens.config import get_workspace_dir, record_api_error

    assert mock_rf_server.port > 0
    monkeypatch.setenv("SOCLENS_HOME", "   \t  ")
    assert get_workspace_dir() == e2e_workspace.resolve()

    blocking_file = e2e_workspace / "not_a_directory.txt"
    blocking_file.write_text("file-blocker", encoding="utf-8")
    monkeypatch.setenv("SOCLENS_HOME", str(blocking_file))

    with pytest.raises(OSError):
        record_api_error({"endpoint": "/test", "status_code": 500})

    client = RecordedFutureClient(error_log_dir=blocking_file)
    with pytest.raises(RecordedFutureAPIError) as exc_info:
        client.v2_lookup("ip", "10.255.255.254")
    assert exc_info.value.status_code == 404


@pytest.mark.feature("F2")
def test_f2_splunk_verify_ssl_variants_and_host_normalization(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.config import get_splunk_config

    assert e2e_workspace.is_dir()
    for truthy in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("SPLUNK_VERIFY_SSL", truthy)
        assert get_splunk_config().verify_ssl is True

    for falsy in ("0", "false", "FALSE", "no", "off", "   "):
        monkeypatch.setenv("SPLUNK_VERIFY_SSL", falsy)
        assert get_splunk_config().verify_ssl is False

    monkeypatch.setenv("SPLUNK_VERIFY_SSL", "/etc/ssl/certs/splunk-ca.pem")
    assert get_splunk_config().verify_ssl == "/etc/ssl/certs/splunk-ca.pem"

    assert get_splunk_config(host="splunk.corp:8089///").host == "https://splunk.corp:8089"
    assert get_splunk_config(host="http://splunk.local:8089/").host == "http://splunk.local:8089"


@pytest.mark.feature("F2")
def test_f2_configure_logging_invalid_levels_and_idempotency(
    e2e_workspace: Path,
) -> None:
    from soclens.config import ConfigurationError, configure_logging

    for bad_level in ("BOGUS_LEVEL", True, False):
        with pytest.raises(ConfigurationError):
            configure_logging(level=bad_level)  # type: ignore[arg-type]

    stream = io.StringIO()
    log_rel = Path("logs") / "idempotent.log"
    for _ in range(3):
        pkg_logger = configure_logging(
            level="INFO",
            log_file=log_rel,
            workspace_dir=e2e_workspace,
            stream=stream,
        )

    pkg_logger.info("single-emission-check")
    for handler in list(pkg_logger.handlers):
        handler.flush()

    assert stream.getvalue().count("single-emission-check") == 1
    file_text = (e2e_workspace / log_rel).read_text(encoding="utf-8")
    assert file_text.count("single-emission-check") == 1


@pytest.mark.feature("F2")
def test_f2_ensure_utf8_console_none_cp1252_and_failing_stream(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.config import ensure_utf8_console

    assert e2e_workspace.is_dir()

    class _Cp1252Stream:
        encoding = "cp1252"

        def __init__(self) -> None:
            self.calls: list[tuple[str | None, str | None]] = []

        def reconfigure(self, *, encoding: str | None = None, errors: str | None = None) -> None:
            self.calls.append((encoding, errors))

    class _FailingStream:
        encoding = "cp1252"

        def reconfigure(self, *, encoding: str | None = None, errors: str | None = None) -> None:
            raise OSError("reconfigure unsupported")

    monkeypatch.setattr("sys.stdout", None)
    monkeypatch.setattr("sys.stderr", io.StringIO())
    ensure_utf8_console()

    cp_stream = _Cp1252Stream()
    monkeypatch.setattr("sys.stdout", cp_stream)
    monkeypatch.setattr("sys.stderr", _FailingStream())
    ensure_utf8_console()

    assert cp_stream.calls == [("utf-8", "replace")]


@pytest.mark.feature("F2")
def test_f2_record_api_error_concurrent_threads_and_trace_id(
    e2e_workspace: Path,
) -> None:
    from soclens.config import record_api_error

    errors: list[Exception] = []

    def _worker(idx: int) -> None:
        try:
            key = "traceId" if idx % 2 == 0 else "trace_id"
            record_api_error(
                {
                    "endpoint": f"/v2/ip/198.51.100.{idx}",
                    "method": "GET",
                    "status_code": 404,
                    key: f"trace-{idx}",
                    "message": "Not found",
                    "reason": "NotFound",
                    "category": "connect_v2",
                },
                workspace_dir=e2e_workspace,
            )
        except Exception as exc:  # pragma: no cover - asserted empty below
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors
    entries = _read_jsonl(e2e_workspace / "logs" / "rf_api_errors.jsonl")
    assert len(entries) == 16
    assert {entry["trace_id"] for entry in entries} == {f"trace-{i}" for i in range(16)}
    assert all("traceId" not in entry for entry in entries)


# ==============================================================================
# F3: Hardened RF HTTP Client — Boundary & Negative
# ==============================================================================


@pytest.mark.feature("F3")
def test_f3_429_exceeding_max_retries_raises_rate_limit_error(
    mock_rf_server: MockRFServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.client import RecordedFutureClient, RecordedFutureRateLimitError

    sleep_calls: list[float] = []
    client = RecordedFutureClient()
    with monkeypatch.context() as mp:
        mp.setattr("soclens.client.time.sleep", sleep_calls.append)
        mock_rf_server.set_fault(
            "/v2/ip/",
            429,
            body={"error": {"status": 429, "message": "Too many requests", "reason": "RateLimit"}, "traceId": "rl-429"},
            headers={"Retry-After": "4"},
        )
        with pytest.raises(RecordedFutureRateLimitError) as exc_info:
            client.v2_lookup("ip", "198.51.100.10")

        assert exc_info.value.status_code == 429
        assert exc_info.value.retry_after == 4.0
        assert exc_info.value.trace_id == "rl-429"
        assert len(mock_rf_server.requests_log) == 5
        assert sleep_calls == [4.0, 4.0, 4.0, 4.0]

    # Also verify Retry-After: "0" real-sleep exhaustion without monkeypatching sleep
    mock_rf_server.clear_faults()
    mock_rf_server.requests_log.clear()
    mock_rf_server.set_fault("/v2/ip/", 429, headers={"Retry-After": "0"})
    with pytest.raises(RecordedFutureRateLimitError) as exc_zero:
        client.v2_lookup("ip", "198.51.100.10")
    assert exc_zero.value.retry_after == 0.0
    assert len(mock_rf_server.requests_log) == 5


@pytest.mark.feature("F3")
def test_f3_429_without_retry_after_backoff_and_http_date_parse(
    mock_rf_server: MockRFServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.client import (
        RecordedFutureClient,
        RecordedFutureRateLimitError,
        parse_retry_after,
    )

    sleep_calls: list[float] = []
    monkeypatch.setattr("soclens.client.time.sleep", sleep_calls.append)

    mock_rf_server.set_fault("/v2/ip/", 429)
    client = RecordedFutureClient()
    with pytest.raises(RecordedFutureRateLimitError) as exc_info:
        client.v2_lookup("ip", "198.51.100.10")

    assert exc_info.value.retry_after is None
    assert len(sleep_calls) == 4
    assert all(0.0 < d <= 60.0 * 1.25 for d in sleep_calls)
    assert sleep_calls[3] > sleep_calls[0]

    future_hdr = format_datetime(datetime.now(UTC) + timedelta(seconds=15), usegmt=True)
    parsed_future = parse_retry_after({"Retry-After": future_hdr})
    assert parsed_future is not None
    assert 0.0 < parsed_future <= 16.0

    past_hdr = format_datetime(datetime.now(UTC) - timedelta(seconds=30), usegmt=True)
    assert parse_retry_after({"retry-after": past_hdr}) == 0.0
    assert parse_retry_after({"Retry-After": "inf"}) is None
    assert parse_retry_after({"Retry-After": "-inf"}) is None
    assert parse_retry_after({"Retry-After": "NaN"}) is None


@pytest.mark.feature("F3")
def test_f3_sandbox_string_error_on_400_and_500_no_attr_error(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    monkeypatch.setattr("soclens.client.time.sleep", lambda _s: None)
    client = RecordedFutureClient()

    mock_rf_server.queue_fault(
        "/api/v0/samples/",
        400,
        body={"error": "BAD_REQUEST", "message": "Bad sample ID"},
    )
    with pytest.raises(RecordedFutureAPIError) as exc_400:
        client.sandbox_get_sample("bad")
    assert exc_400.value.status_code == 400
    assert exc_400.value.reason == "BAD_REQUEST"

    mock_rf_server.set_fault(
        "/api/v0/samples/",
        500,
        body={"error": "SERVER_ERROR", "message": "Sandbox internal fault"},
    )
    with pytest.raises(RecordedFutureAPIError) as exc_500:
        client.sandbox_get_sample("sample-1")
    assert exc_500.value.status_code == 500
    assert exc_500.value.reason == "SERVER_ERROR"

    entries = _read_jsonl(e2e_workspace / "logs" / "rf_api_errors.jsonl")
    assert [e["category"] for e in entries] == ["sandbox_v0", "sandbox_v0"]


@pytest.mark.feature("F3")
def test_f3_malformed_v2_and_non_json_logged_with_trace_id(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    monkeypatch.setattr("soclens.client.time.sleep", lambda _s: None)
    client = RecordedFutureClient()

    mock_rf_server.queue_fault(
        "/v2/ip/",
        400,
        body={"error": "NOT_A_DICT", "traceId": "t-str"},
    )
    with pytest.raises(RecordedFutureAPIError) as exc_400:
        client.v2_lookup("ip", "198.51.100.10")
    assert exc_400.value.status_code == 400
    assert exc_400.value.trace_id == "t-str"

    mock_rf_server.set_fault(
        "/v2/ip/",
        502,
        body="<html><body>502 Bad Gateway</body></html>",
        headers={"trace-id": "hdr-502"},
    )
    with pytest.raises(RecordedFutureAPIError) as exc_502:
        client.v2_lookup("ip", "198.51.100.10")
    assert exc_502.value.status_code == 502
    assert exc_502.value.trace_id == "hdr-502"

    mock_rf_server.clear_faults()
    mock_rf_server.queue_fault("/v2/ip/", 200, body="{bad-json")
    with pytest.raises(RecordedFutureAPIError) as exc_bad_json:
        client.v2_lookup("ip", "198.51.100.10")
    assert exc_bad_json.value.status_code == 200
    assert exc_bad_json.value.reason == "invalid_json"

    entries = _read_jsonl(e2e_workspace / "logs" / "rf_api_errors.jsonl")
    assert len(entries) == 2
    assert entries[0]["trace_id"] == "t-str"
    assert entries[1]["trace_id"] == "hdr-502"


@pytest.mark.feature("F3")
def test_f3_network_connection_error_retries_and_logs(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    sleep_calls: list[float] = []
    monkeypatch.setattr("soclens.client.time.sleep", sleep_calls.append)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        dead_port = sock.getsockname()[1]

    client = RecordedFutureClient(base_url=f"http://127.0.0.1:{dead_port}")
    with pytest.raises(RecordedFutureAPIError) as exc_info:
        client.get_list_info("report:brand-image-default")

    assert exc_info.value.status_code is None
    assert exc_info.value.reason == "network_error"
    assert len(sleep_calls) == 4

    entries = _read_jsonl(e2e_workspace / "logs" / "rf_api_errors.jsonl")
    assert len(entries) == 1
    assert entries[0]["category"] == "network_error"
    assert entries[0]["status_code"] is None


@pytest.mark.feature("F3")
def test_f3_cli_exits_nonzero_on_401_403_429_and_500(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    monkeypatch: pytest.MonkeyPatch,
    run_cli: Callable[..., Any],
) -> None:
    from soclens.client import RecordedFutureAPIError

    proc_401 = run_cli(["watchlist", "list"], env={"RF_API_TOKEN": "invalid-cli-token"})
    assert proc_401.returncode != 0

    mock_rf_server.queue_fault(
        "/list/search",
        403,
        body={"message": "Missing API privileges", "status_code": 403, "trace_id": "cli-403"},
    )
    proc_403 = run_cli(["watchlist", "list"])
    assert proc_403.returncode != 0

    mock_rf_server.set_fault("/list/", 429, headers={"Retry-After": "0"})
    proc_429 = run_cli(
        ["watchlist", "add", "report:brand-image-default", "Hash", "a" * 64],
        env={"SOCLENS_AUTO_APPROVE": "1"},
    )
    assert proc_429.returncode != 0

    # Exercise 500 via cli.main() with fast sleep to avoid ~35s subprocess backoff timeout
    mock_rf_server.clear_faults()
    mock_rf_server.set_fault("/list/search", 500)
    monkeypatch.setattr("soclens.client.time.sleep", lambda _s: None)
    monkeypatch.setattr("sys.argv", ["soclens", "watchlist", "list"])

    from soclens import cli

    with pytest.raises((RecordedFutureAPIError, SystemExit)) as exc_500:
        cli.main()
    if isinstance(exc_500.value, SystemExit):
        assert exc_500.value.code != 0

    entries = _read_jsonl(e2e_workspace / "logs" / "rf_api_errors.jsonl")
    statuses = [e["status_code"] for e in entries]
    assert 401 in statuses
    assert 403 in statuses
    assert 429 in statuses
    assert 500 in statuses


# ==============================================================================
# F4: Complete Lists & Watchlists API — Boundary & Negative
# ==============================================================================


@pytest.mark.feature("F4")
def test_f4_empty_and_missing_list_404_and_invalid_inputs(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()
    assert client.get_watchlist_entities("report:brand-image-default") == []
    assert client.get_list_status("report:brand-image-default")["size"] == 0

    for call in (
        lambda: client.get_list_info("report:missing"),
        lambda: client.get_list_status("report:missing"),
        lambda: client.get_watchlist_entities("report:missing"),
        lambda: client.add_entity("report:missing", "Hash", "a" * 64),
        lambda: client.remove_entity("report:missing", "hash:" + ("a" * 64)),
    ):
        with pytest.raises(RecordedFutureAPIError) as exc_info:
            call()
        assert exc_info.value.status_code == 404

    with pytest.raises(ValueError):
        client.create_list("   ", "domain")
    with pytest.raises(ValueError):
        client.create_list("Invalid Type List", "nonexistent_list_type")
    with pytest.raises(ValueError):
        client.get_list_info("   ")
    with pytest.raises(ValueError):
        client.add_entity("report:brand-image-default", "Hash", "   ")


@pytest.mark.feature("F4")
def test_f4_capacity_warning_at_900_and_1000_plus_entities(
    mock_rf_server: MockRFServer,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    items_900 = [
        {"entity": {"id": f"hash:{i:064x}", "type": "Hash", "name": f"{i:064x}"}}
        for i in range(900)
    ]
    list_900 = mock_rf_server.seed_list("Warn 900", "hash", entities=items_900)

    with caplog.at_level(logging.WARNING, logger="soclens.client"):
        caplog.clear()
        status = client.get_list_status(list_900["id"])
        assert status["size"] == 900
        assert any("approaching" in rec.message.lower() for rec in caplog.records)

        caplog.clear()
        entities = client.get_watchlist_entities(list_900["id"])
        assert len(entities) == 900
        assert any("900" in rec.message for rec in caplog.records)

    items_1001 = items_900 + [
        {"entity": {"id": f"hash:{i:064x}", "type": "Hash", "name": f"{i:064x}"}}
        for i in range(900, 1001)
    ]
    list_1001 = mock_rf_server.seed_list("Over 1000", "hash", entities=items_1001)

    with caplog.at_level(logging.WARNING, logger="soclens.client"):
        caplog.clear()
        client.add_entity(list_1001["id"], "Hash", "f" * 64, check_limit=True)
        assert any("1000" in rec.message for rec in caplog.records)

        caplog.clear()
        client.add_entity(list_1001["id"], "Hash", "e" * 64, current_size=1001)
        assert any("1000" in rec.message for rec in caplog.records)


@pytest.mark.feature("F4")
def test_f4_replace_entity_tags_0_9_and_over_9_error(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    client = RecordedFutureClient()
    company_list = mock_rf_server.seed_list(
        "Tag Boundary List",
        "company",
        entities=[{"entity": {"id": "company:abc123", "type": "Company", "name": "Acme Bank"}}],
    )
    list_id = company_list["id"]

    res_empty = client.replace_entity_tags(list_id, "company:abc123", [])
    assert res_empty["operation"]["status"] in ("tags_updated", "tags_unchanged")

    nine_tags = [f"tag-{i}" for i in range(9)]
    res_nine = client.replace_entity_tags(list_id, "company:abc123", nine_tags)
    assert res_nine["operation"]["status"] == "tags_updated"

    req_count_before = len(mock_rf_server.requests_log)
    with pytest.raises(ValueError):
        client.replace_entity_tags(list_id, "company:abc123", [f"tag-{i}" for i in range(10)])
    assert len(mock_rf_server.requests_log) == req_count_before

    raw_resp = requests.post(
        f"{mock_rf_server.base_url}/list/{list_id}/entity/tags",
        headers={"X-RFToken": "test-rf-token"},
        json={"entity": {"id": "company:abc123"}, "tags": [f"t{i}" for i in range(10)]},
        timeout=5,
    )
    assert raw_resp.status_code == 400

    with pytest.raises(RecordedFutureAPIError) as exc_missing:
        client.replace_entity_tags(list_id, "company:unknown", ["t1"])
    assert exc_missing.value.status_code == 404


@pytest.mark.feature("F4")
def test_f4_get_watchlists_limit_clamping_and_deduplication(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    seeded = mock_rf_server.seed_list("Dedup Watch List", "domain")
    client = RecordedFutureClient()

    all_lists = client.get_watchlists(limit=500)
    ids = [item["id"] for item in all_lists]
    assert ids.count(seeded["id"]) == 1
    assert ids.count("report:brand-image-default") == 1
    assert len(mock_rf_server.requests_log) == 22
    assert all(entry["body_json"]["limit"] == 100 for entry in mock_rf_server.requests_log)

    mock_rf_server.requests_log.clear()
    minimal = client.get_watchlists(limit=0, include_all_types=False)
    assert len(minimal) >= 1
    assert mock_rf_server.requests_log[0]["body_json"]["limit"] == 1


@pytest.mark.feature("F4")
def test_f4_remove_entity_unchanged_and_cli_dry_run_guard(
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., Any],
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    rem = client.remove_entity("report:brand-image-default", "hash:" + ("0" * 64))
    assert rem["result"] == "unchanged"

    mock_rf_server.requests_log.clear()
    proc = run_cli(
        ["watchlist", "add", "report:brand-image-default", "Hash", "a" * 64],
    )
    assert proc.returncode == 0
    assert "DRY RUN" in proc.stdout or "DRY-RUN" in proc.stdout
    assert mock_rf_server.requests_log == []


@pytest.mark.feature("F4")
def test_f4_resolve_true_entity_not_found_raises_404(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    client = RecordedFutureClient()
    created = client.create_list("Unresolved Entity List", "company")
    list_id = created["id"]
    mock_rf_server.requests_log.clear()

    with pytest.raises(RecordedFutureAPIError) as exc_info:
        client.add_entity(list_id, "Company", "NoSuchCompany999", resolve=True)

    assert exc_info.value.status_code == 404
    assert exc_info.value.reason == "entity_not_found"
    paths = [entry["path"] for entry in mock_rf_server.requests_log]
    assert paths == ["/entity-match/match"]


# ==============================================================================
# F5: Detection Rules Schema Fix — Boundary & Negative
# ==============================================================================


@pytest.mark.feature("F5")
def test_f5_empty_detection_rule_results_returns_empty_list(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    assert client.search_detection_rules(title="NoSuchRule999") == []
    assert len(mock_rf_server.requests_log) == 1


@pytest.mark.feature("F5")
def test_f5_multipage_cursor_termination_and_cycle_guard(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    # Part 1: 5 rules at limit=2 -> 2 + 2 + 1 pages
    for idx in range(3, 6):
        mock_rf_server.state["detection_rules"].append(
            {
                "id": f"doc:sigma-{idx}",
                "type": "sigma",
                "title": f"Extra Sigma {idx}",
                "created": "2026-10-18T00:00:00Z",
                "updated": "2026-10-18T00:00:00Z",
                "entities": [],
                "rules": [{"file_name": f"extra_{idx}.yml", "content": "title: Extra\n"}],
            }
        )

    client = RecordedFutureClient()
    rules = client.search_detection_rules(limit=2)
    assert len(rules) == 5
    assert len(mock_rf_server.requests_log) == 3

    # Part 2: Repeating next_offset="1" must stop via seen_offsets without infinite loop
    mock_rf_server.requests_log.clear()
    for _ in range(2):
        mock_rf_server.queue_fault(
            "/detection-rule/search",
            200,
            body={
                "count": 1,
                "total_count": 2,
                "result": [{"id": "doc:loop", "type": "sigma", "title": "Loop", "rules": []}],
                "next_offset": "1",
            },
        )
    looped = client.search_detection_rules(limit=1)
    assert len(looped) == 2
    assert len(mock_rf_server.requests_log) == 2


@pytest.mark.feature("F5")
def test_f5_limit_less_than_one_clamped(mock_rf_server: MockRFServer) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    res_zero = client.search_detection_rules(limit=0)
    res_neg = client.search_detection_rules(limit=-5)

    assert len(res_zero) == 2
    assert len(res_neg) == 2
    sent_limits = [entry["body_json"]["limit"] for entry in mock_rf_server.requests_log]
    assert all(lim == 1 for lim in sent_limits)


@pytest.mark.feature("F5")
def test_f5_legacy_operator_payload_rejected_by_mock_rf_server(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()
    with pytest.raises(RecordedFutureAPIError) as exc_info:
        client._request(
            "POST",
            "/detection-rule/search",
            json_data={
                "filter": {
                    "types": ["sigma"],
                    "updated": {"operator": "gt", "value": "2026-01-01T00:00:00Z"},
                },
                "limit": 10,
            },
        )
    assert exc_info.value.status_code == 400


@pytest.mark.feature("F5")
def test_f5_mid_pagination_500_raises_instead_of_partial_results(
    mock_rf_server: MockRFServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    monkeypatch.setattr("soclens.client.time.sleep", lambda _s: None)
    mock_rf_server.queue_fault(
        "/detection-rule/search",
        200,
        body={
            "count": 1,
            "total_count": 2,
            "result": [{"id": "doc:p1", "type": "sigma", "title": "Page1", "rules": []}],
            "next_offset": "1",
        },
    )
    mock_rf_server.set_fault("/detection-rule/search", 500)

    client = RecordedFutureClient()
    with pytest.raises(RecordedFutureAPIError) as exc_info:
        client.search_detection_rules(limit=1)
    assert exc_info.value.status_code == 500


@pytest.mark.feature("F5")
def test_f5_non_dict_or_invalid_json_handled_safely(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    client = RecordedFutureClient()
    mock_rf_server.queue_fault("/detection-rule/search", 200, body="{invalid-json")
    with pytest.raises(RecordedFutureAPIError) as exc_info:
        client.search_detection_rules()
    assert exc_info.value.reason == "invalid_json"

    mock_rf_server.queue_fault("/detection-rule/search", 200, body=[])
    assert client.search_detection_rules() == []


# ==============================================================================
# F6: Expanded SOC APIs — Boundary & Negative
# ==============================================================================


@pytest.mark.feature("F6")
def test_f6_soar_empty_and_over_1000_ioc_and_invalid_context(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    client = RecordedFutureClient()
    with pytest.raises(ValueError):
        client.soar_enrich({})
    with pytest.raises(ValueError):
        client.soar_enrich({"ip": []})

    ok_iocs = {"ip": [f"198.51.{i // 250}.{i % 250}" for i in range(1000)]}
    res_1000 = client.soar_enrich(ok_iocs)
    assert len(res_1000["data"]["results"]) == 1000

    req_count_before = len(mock_rf_server.requests_log)
    too_many = {"ip": [f"198.51.{i // 250}.{i % 250}" for i in range(1001)]}
    with pytest.raises(ValueError):
        client.soar_enrich(too_many)
    assert len(mock_rf_server.requests_log) == req_count_before

    with pytest.raises(RecordedFutureAPIError) as exc_ctx:
        client.soar_triage("unknown_ctx", {"ip": ["198.51.100.10"]})
    assert exc_ctx.value.status_code == 404


@pytest.mark.feature("F6")
def test_f6_sandbox_wrong_auth_header_and_wrong_bearer_rejected(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAuthError, RecordedFutureClient

    bad_sb_client = RecordedFutureClient(api_token="test-rf-token", sandbox_token="wrong-bearer")
    with pytest.raises(RecordedFutureAuthError) as exc_info:
        bad_sb_client.sandbox_search("suspicious")
    assert exc_info.value.status_code == 401
    assert exc_info.value.permission_type == "unauthorized"

    raw_resp = requests.get(
        f"{mock_rf_server.sandbox_base_url}/search",
        headers={"X-RFToken": "test-rf-token"},
        timeout=5,
    )
    assert raw_resp.status_code == 401
    assert raw_resp.json()["error"] == "UNAUTHORIZED"


@pytest.mark.feature("F6")
def test_f6_v2_url_percent_encoding_and_unsupported_types(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    mock_rf_server.state["v2_entities"][("url", "url:http://evil.com/a/b")] = {
        "entity": {"id": "url:http://evil.com/a/b", "name": "http://evil.com/a/b", "type": "URL"},
        "risk": {"score": 85, "level": 4, "riskString": "4/10", "evidenceDetails": []},
    }
    client = RecordedFutureClient()

    res_raw = client.v2_lookup("url", "http://evil.com/a/b")
    assert res_raw["data"]["risk"]["score"] == 85
    assert mock_rf_server.requests_log[-1]["path"] == "/v2/url/url:http%3A%2F%2Fevil.com%2Fa%2Fb"

    res_pre = client.v2_lookup("url", "url:http%3A%2F%2Fevil.com%2Fa%2Fb")
    assert res_pre["data"]["risk"]["score"] == 85
    assert mock_rf_server.requests_log[-1]["path"] == "/v2/url/url:http%3A%2F%2Fevil.com%2Fa%2Fb"

    with pytest.raises(ValueError):
        client.v2_lookup("attacker", "threatactor:1")
    with pytest.raises(ValueError):
        client.v2_risklist("company")


@pytest.mark.feature("F6")
def test_f6_playbook_category_mapping_and_http_200_error(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    mock_rf_server.state["playbook_alerts"]["pb-dw"] = {
        "playbook_alert_id": "pb-dw",
        "category": "dark_web_brand",
        "priority": "High",
        "status": "New",
        "title": "Dark web brand mention",
    }
    mock_rf_server.state["playbook_alerts"]["pb-sm"] = {
        "playbook_alert_id": "pb-sm",
        "category": "social_media_impersonation",
        "priority": "Medium",
        "status": "New",
        "title": "Social impersonation",
    }

    client = RecordedFutureClient()
    dw = client.get_playbook_alert("dark_web", "pb-dw")
    assert dw["data"]["category"] == "dark_web_brand"
    assert mock_rf_server.requests_log[-1]["path"] == "/playbook-alert/dark_web_brand/pb-dw"

    sm = client.get_playbook_alert("socmed_impersonation", "pb-sm")
    assert sm["data"]["category"] == "social_media_impersonation"
    assert (
        mock_rf_server.requests_log[-1]["path"]
        == "/playbook-alert/social_media_impersonation/pb-sm"
    )

    with pytest.raises(ValueError):
        client.get_playbook_alert("invalid_category", "pb-1")

    mock_rf_server.queue_fault(
        "/playbook-alert/search",
        200,
        body={"status": {"status_code": "Error", "status_message": "Invalid filter"}},
    )
    with pytest.raises(RecordedFutureAPIError) as exc_200:
        client.search_playbook_alerts()
    assert exc_200.value.status_code == 200
    assert "Invalid filter" in exc_200.value.message


@pytest.mark.feature("F6")
def test_f6_alerts_v3_1000_cap_and_cases_pagination_and_empty_title(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    client = RecordedFutureClient()
    with pytest.raises(ValueError):
        client.search_alerts_v3(limit=600, offset=401)
    with pytest.raises(ValueError):
        client.search_alerts_v3(limit=0)
    with pytest.raises(ValueError):
        client.search_alerts_v3(offset=-1)

    ok_alerts = client.search_alerts_v3(limit=500, offset=500)
    assert "data" in ok_alerts

    client.create_case(title="Case Two")
    client.create_case(title="Case Three")
    all_cases = client.search_cases(limit=1, paginate=True)
    assert len(all_cases["data"]) == 3

    with pytest.raises(RecordedFutureAPIError) as exc_case:
        client.create_case(title="   ")
    assert exc_case.value.status_code == 400


@pytest.mark.feature("F6")
def test_f6_entity_match_unknown_type_and_empty_query_validation(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()
    assert client.entity_match("Acme", types=["UnknownType"]) == []

    for call in (
        lambda: client.entity_match("   "),
        lambda: client.sandbox_search("   "),
        lambda: client.lookup_cases([]),
        lambda: client.get_list_info(" "),
    ):
        with pytest.raises(ValueError):
            call()
