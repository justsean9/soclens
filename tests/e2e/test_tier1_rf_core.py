"""Tier 1 opaque-box E2E tests for Core RF API Review, Config, Client, Lists, Detection Rules, and Expanded SOC APIs (F1-F6)."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import requests

if TYPE_CHECKING:
    from tests.e2e.conftest import MockRFServer

pytestmark = [pytest.mark.e2e, pytest.mark.tier1]

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
# F1: RF API Review Document
# ==============================================================================


@pytest.mark.feature("F1")
def test_f1_review_doc_exists_and_authoritative_sources() -> None:
    assert REVIEW_DOC_PATH.is_file()
    content = _read_review_doc()
    assert len(content) > 2000
    for marker in (
        "RF.md",
        "RF-DOCS-2026Q1",
        "docs.recordedfuture.com/llms.txt",
        "reference/llms.txt",
        "llm-instructions.md",
        "RF-DOCS-2026Q4",
        "api-entitlements.md",
    ):
        assert marker in content


@pytest.mark.feature("F1")
def test_f1_review_doc_auth_schemes_and_base_urls() -> None:
    content = _read_review_doc()
    for expected in (
        "https://api.recordedfuture.com",
        "https://sandbox.recordedfuture.com/api/v0",
        "X-RFToken",
        "Authorization: Bearer",
        "RF_API_TOKEN",
        "RECORDED_FUTURE_API_KEY",
        "RF_SANDBOX_TOKEN",
        "apikey:",
        "taxii2",
    ):
        assert expected in content


@pytest.mark.feature("F1")
def test_f1_review_doc_rate_limits_and_403_boundaries() -> None:
    content = _read_review_doc()
    for expected in (
        "1,000 requests per 60 seconds",
        "429 Too Many Requests",
        "Retry-After",
        "Missing API privileges",
        "missing_api_privileges",
        "Missing Data permissions",
        "missing_data_permissions",
    ):
        assert expected in content


@pytest.mark.feature("F1")
def test_f1_review_doc_brand_image_hash_schema() -> None:
    content = _read_review_doc()
    for expected in (
        'type: "brand"',
        "`Hash`",
        "hash:",
        "SHA-256",
        "No perceptual hash (`pHash`, `dHash`, `aHash`)",
        "context.annotation",
        "domain_abuse",
        "malicious_sites",
        "DrpAsset.ImageHash",
        "MaliciousSitesLogoHashChange",
    ):
        assert expected in content


@pytest.mark.feature("F1")
def test_f1_review_doc_error_schemas_and_trace_id() -> None:
    content = _read_review_doc()
    assert "### 5.1 All 8 Error Payload Schemas" in content
    for expected in (
        "traceId",
        "trace_id",
        "trace-id",
        "`error` is a `str`, NOT a `dict`",
        "status_code",
        "logs/rf_api_errors.jsonl",
    ):
        assert expected in content


@pytest.mark.feature("F1")
def test_f1_review_doc_toolkit_coverage_matrix_parity() -> None:
    from soclens.client import RecordedFutureClient

    content = _read_review_doc()
    sec71_match = re.search(
        r"### 7\.1 .*?\n(.*?)\n### 7\.2",
        content,
        flags=re.DOTALL,
    )
    assert sec71_match is not None
    table_body = sec71_match.group(1)
    client_methods: list[str] = []
    for row in table_body.splitlines():
        if not row.startswith("|") or row.startswith("|---") or "RF API Family" in row:
            continue
        cells = [c.strip() for c in row.strip("|").split("|")]
        if len(cells) == 3:
            methods_cell = re.sub(r"\([^)]*\)", "", cells[2])
            client_methods.extend(re.findall(r"`([a-z0-9_]+)`", methods_cell))

    assert len(client_methods) >= 25
    for method_name in client_methods:
        attr = getattr(RecordedFutureClient, method_name, None)
        assert callable(attr), f"Documented method RecordedFutureClient.{method_name} missing"
    assert "### 7.3 Tier 3 — Documented Peripheral Surfaces" in content


# ==============================================================================
# F2: Cross-Platform Config & traceId Persistence
# ==============================================================================


@pytest.mark.feature("F2")
def test_f2_workspace_dir_resolution_and_never_site_packages(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import soclens
    from soclens.config import get_workspace_dir

    pkg_root = Path(soclens.__file__).resolve().parent

    resolved_default = get_workspace_dir()
    assert resolved_default == e2e_workspace.resolve()
    assert pkg_root not in resolved_default.parents and resolved_default != pkg_root
    assert "site-packages" not in resolved_default.parts

    custom_env = e2e_workspace / "env_home"
    custom_env.mkdir()
    monkeypatch.setenv("SOCLENS_HOME", str(custom_env))
    assert get_workspace_dir() == custom_env.resolve()

    explicit_dir = e2e_workspace / "explicit_home"
    explicit_dir.mkdir()
    assert get_workspace_dir(explicit_dir) == explicit_dir.resolve()


@pytest.mark.feature("F2")
def test_f2_rf_token_precedence_and_fallback(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.config import get_rf_sandbox_token, get_rf_token

    assert e2e_workspace.is_dir()
    assert get_rf_token(explicit="explicit-tok") == "explicit-tok"
    assert get_rf_token() == "test-rf-token"

    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.setenv("RECORDED_FUTURE_API_KEY", "legacy-key")
    assert get_rf_token() == "legacy-key"

    assert get_rf_sandbox_token(explicit="sb-explicit") == "sb-explicit"
    assert get_rf_sandbox_token() == "test-sandbox-token"

    monkeypatch.delenv("RF_SANDBOX_TOKEN", raising=False)
    assert get_rf_sandbox_token(default_core_token="core-fallback") == "core-fallback"
    assert get_rf_sandbox_token() == "legacy-key"


@pytest.mark.feature("F2")
def test_f2_splunk_config_defaults_and_env_overrides(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.config import get_splunk_config

    assert e2e_workspace.is_dir()
    monkeypatch.delenv("SPLUNK_HOST", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("SPLUNK_APP", raising=False)
    monkeypatch.delenv("SPLUNK_VERIFY_SSL", raising=False)

    defaults = get_splunk_config()
    assert defaults.host == "https://127.0.0.1:8089"
    assert defaults.app == "SplunkEnterpriseSecuritySuite"
    assert defaults.verify_ssl is False
    assert defaults.has_auth is False

    monkeypatch.setenv("SPLUNK_HOST", "splunk.internal:8089/")
    monkeypatch.setenv("SPLUNK_USERNAME", "soc_user")
    monkeypatch.setenv("SPLUNK_PASSWORD", "soc_pass")
    monkeypatch.setenv("SPLUNK_APP", "CustomES")
    monkeypatch.setenv("SPLUNK_VERIFY_SSL", "true")

    overridden = get_splunk_config(required=True)
    assert overridden.host == "https://splunk.internal:8089"
    assert overridden.username == "soc_user"
    assert overridden.password == "soc_pass"
    assert overridden.app == "CustomES"
    assert overridden.verify_ssl is True
    assert overridden.has_auth is True


@pytest.mark.feature("F2")
def test_f2_ensure_utf8_console_and_configure_logging(e2e_workspace: Path) -> None:
    from soclens.config import configure_logging, ensure_utf8_console

    ensure_utf8_console()
    rel_log = Path("logs") / "soc_utf8.log"
    pkg_logger = configure_logging(level="DEBUG", log_file=rel_log, workspace_dir=e2e_workspace)
    pkg_logger.info("UTF-8 check: café — ✓")
    for handler in list(pkg_logger.handlers):
        handler.flush()

    log_path = e2e_workspace / rel_log
    assert log_path.is_file()
    text = log_path.read_text(encoding="utf-8")
    assert "UTF-8 check: café — ✓" in text


@pytest.mark.feature("F2")
def test_f2_record_api_error_persists_trace_id_on_http_error(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()
    with pytest.raises(RecordedFutureAPIError) as exc_info:
        client.v2_lookup("ip", "10.255.255.254")

    assert exc_info.value.status_code == 404
    assert exc_info.value.trace_id
    log_path = e2e_workspace / "logs" / "rf_api_errors.jsonl"
    entries = _read_jsonl(log_path)
    assert len(entries) == 1
    rec = entries[0]
    assert rec["status_code"] == 404
    assert rec["trace_id"] == exc_info.value.trace_id
    assert rec["category"] == "connect_v2"
    assert rec["endpoint"] == "/v2/ip/10.255.255.254"
    assert rec["timestamp"].endswith("Z")


@pytest.mark.feature("F2")
def test_f2_cli_error_logs_trace_id_and_exits_nonzero(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., Any],
) -> None:
    assert mock_rf_server.port > 0
    proc = run_cli(["watchlist", "entities", "report:missing"])
    assert proc.returncode != 0

    log_path = e2e_workspace / "logs" / "rf_api_errors.jsonl"
    entries = _read_jsonl(log_path)
    assert len(entries) == 1
    assert entries[0]["status_code"] == 404
    assert entries[0]["endpoint"] == "/list/report:missing/entities"
    assert entries[0]["trace_id"]


# ==============================================================================
# F3: Hardened RF HTTP Client
# ==============================================================================


@pytest.mark.feature("F3")
def test_f3_session_reuse_and_auth_headers(mock_rf_server: MockRFServer) -> None:
    from soclens.client import RecordedFutureClient

    session = requests.Session()
    client = RecordedFutureClient(session=session)
    assert client.session is session

    info = client.get_list_info("report:brand-image-default")
    assert info["id"] == "report:brand-image-default"
    sample = client.sandbox_get_sample("sample-1")
    assert sample["id"] == "sample-1"

    assert len(mock_rf_server.requests_log) == 2
    core_hdrs = _lower_headers(mock_rf_server.requests_log[0]["headers"])
    sb_hdrs = _lower_headers(mock_rf_server.requests_log[1]["headers"])

    assert core_hdrs.get("x-rftoken") == "test-rf-token"
    assert "authorization" not in core_hdrs
    assert sb_hdrs.get("authorization") == "Bearer test-sandbox-token"
    assert "x-rftoken" not in sb_hdrs


@pytest.mark.feature("F3")
def test_f3_429_retry_after_recovery_against_mock_rf_server(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    mock_rf_server.queue_fault("/v2/ip/", 429, headers={"Retry-After": "0.01"}, count=2)
    client = RecordedFutureClient()
    res = client.v2_lookup("ip", "198.51.100.10")

    assert res["data"]["entity"]["name"] == "198.51.100.10"
    assert len(mock_rf_server.requests_log) == 3


@pytest.mark.feature("F3")
def test_f3_5xx_retry_recovery_against_mock_rf_server(
    mock_rf_server: MockRFServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.client import RecordedFutureClient

    sleep_calls: list[float] = []
    monkeypatch.setattr("soclens.client.time.sleep", sleep_calls.append)

    mock_rf_server.queue_fault("/list/", 503, count=1)
    mock_rf_server.queue_fault("/list/", 502, count=1)

    client = RecordedFutureClient()
    info = client.get_list_info("report:brand-image-default")
    assert info["id"] == "report:brand-image-default"
    assert len(mock_rf_server.requests_log) == 3
    assert len(sleep_calls) == 2


@pytest.mark.feature("F3")
def test_f3_401_and_403_permission_classification(mock_rf_server: MockRFServer) -> None:
    from soclens.client import RecordedFutureAuthError, RecordedFutureClient

    bad_client = RecordedFutureClient(api_token="wrong-token")
    with pytest.raises(RecordedFutureAuthError) as exc_401:
        bad_client.get_list_info("report:brand-image-default")
    assert exc_401.value.status_code == 401
    assert exc_401.value.permission_type == "unauthorized"

    client = RecordedFutureClient()
    mock_rf_server.queue_fault(
        "/v2/ip/",
        403,
        body={
            "error": {"status": 403, "message": "Missing API privileges", "reason": "Forbidden"},
            "traceId": "trace-mod-403",
        },
    )
    with pytest.raises(RecordedFutureAuthError) as exc_mod:
        client.v2_lookup("ip", "198.51.100.10")
    assert exc_mod.value.status_code == 403
    assert exc_mod.value.permission_type == "missing_api_privileges"
    assert exc_mod.value.trace_id == "trace-mod-403"

    mock_rf_server.queue_fault(
        "/v2/ip/",
        403,
        body={
            "error": {"status": 403, "message": "Missing Data permissions", "reason": "Forbidden"},
            "traceId": "trace-data-403",
        },
    )
    with pytest.raises(RecordedFutureAuthError) as exc_data:
        client.v2_lookup("ip", "198.51.100.10")
    assert exc_data.value.status_code == 403
    assert exc_data.value.permission_type == "missing_data_permissions"
    assert exc_data.value.trace_id == "trace-data-403"


@pytest.mark.feature("F3")
def test_f3_v2_and_sandbox_error_logging_with_trace_id(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()

    with pytest.raises(RecordedFutureAPIError) as exc_v2:
        client.v2_lookup("ip", "10.255.255.254")
    assert exc_v2.value.trace_id
    assert client.last_trace_id == exc_v2.value.trace_id

    mock_rf_server.queue_fault(
        "/api/v0/samples/",
        400,
        body={"error": "BAD_REQUEST", "message": "Invalid sample identifier"},
        headers={"trace-id": "sb-hdr-400"},
    )
    with pytest.raises(RecordedFutureAPIError) as exc_sb:
        client.sandbox_get_sample("bad-id")
    assert exc_sb.value.status_code == 400
    assert client.last_trace_id == "sb-hdr-400"

    entries = _read_jsonl(e2e_workspace / "logs" / "rf_api_errors.jsonl")
    categories = [e["category"] for e in entries]
    assert categories == ["connect_v2", "sandbox_v0"]
    assert entries[1]["reason"] == "BAD_REQUEST"
    assert entries[1]["trace_id"] == "sb-hdr-400"


@pytest.mark.feature("F3")
def test_f3_client_raises_typed_errors_never_returns_empty_list(
    mock_rf_server: MockRFServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    monkeypatch.setattr("soclens.client.time.sleep", lambda _s: None)
    client = RecordedFutureClient()

    with pytest.raises(RecordedFutureAPIError) as exc_404:
        client.get_watchlist_entities("report:does-not-exist")
    assert exc_404.value.status_code == 404

    mock_rf_server.set_fault("/detection-rule/search", 500)
    with pytest.raises(RecordedFutureAPIError) as exc_500:
        client.search_detection_rules()
    assert exc_500.value.status_code == 500


# ==============================================================================
# F4: Complete Lists & Watchlists API
# ==============================================================================


@pytest.mark.feature("F4")
def test_f4_all_21_list_types_supported_and_searchable(mock_rf_server: MockRFServer) -> None:
    from soclens.client import LIST_TYPES, ListType, RecordedFutureClient
    from tests.e2e.conftest import ALL_LIST_TYPES

    assert len(LIST_TYPES) == 21
    assert len(ListType) == 21
    assert set(LIST_TYPES) == set(ALL_LIST_TYPES)

    client = RecordedFutureClient()
    for ltype in ("text", "industry_peer", "supplier", "executive", "custom"):
        created = client.create_list(f"Test {ltype} List", ltype)
        assert created["type"] == ltype

    lists = client.get_watchlists()
    names = [item["name"] for item in lists]
    assert names == sorted(names, key=str.lower)
    assert "Brand Image" in names
    for ltype in ("text", "industry_peer", "supplier", "executive", "custom"):
        assert f"Test {ltype} List" in names
    assert len(mock_rf_server.requests_log) >= 22


@pytest.mark.feature("F4")
def test_f4_list_info_status_and_entities_crud(mock_rf_server: MockRFServer) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()
    created = client.create_list("SOC Domains Watch List", "domain")
    list_id = created["id"]

    info = client.get_list_info(list_id)
    assert info["name"] == "SOC Domains Watch List"
    assert info["type"] == "domain"

    status_before = client.get_list_status(list_id)
    assert status_before["size"] == 0
    assert status_before["status"] == "ready"

    add_res = client.add_entity(list_id, "InternetDomainName", "bad-actor.invalid")
    assert add_res["result"] == "added"

    entities = client.get_watchlist_entities(list_id)
    assert len(entities) == 1
    assert entities[0]["entity"]["id"] == "idn:bad-actor.invalid"

    status_after = client.get_list_status(list_id)
    assert status_after["size"] == 1

    rem_res = client.remove_entity(list_id, "idn:bad-actor.invalid")
    assert rem_res["result"] == "removed"
    assert client.get_watchlist_entities(list_id) == []


@pytest.mark.feature("F4")
def test_f4_add_entity_context_update_and_unchanged_semantics(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()
    list_id = "report:brand-image-default"
    sha = "a" * 64

    first = client.add_entity(
        list_id,
        "Hash",
        sha,
        context={"annotation": "Alpha primary logo", "domain": "brand-alpha.local"},
    )
    assert first["result"] == "added"

    second = client.add_entity(
        list_id,
        "Hash",
        sha,
        context={"annotation": "Alpha primary logo", "domain": "brand-alpha.local"},
    )
    assert second["result"] == "unchanged"

    third = client.add_entity(
        list_id,
        "Hash",
        sha,
        context={"annotation": "Alpha updated logo"},
    )
    assert third["result"] == "updated"

    entities = client.get_watchlist_entities(list_id)
    assert len(entities) == 1
    assert entities[0]["context"] == {"annotation": "Alpha updated logo"}


@pytest.mark.feature("F4")
def test_f4_text_entries_and_entities_with_tags_and_replace_tags(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    text_list = mock_rf_server.seed_list(
        "IOC Text Feed",
        "text",
        text_entries=["malicious-term-1", "malicious-term-2"],
    )
    assert client.get_text_entries(text_list["id"]) == [
        "malicious-term-1",
        "malicious-term-2",
    ]

    company_list = mock_rf_server.seed_list(
        "Monitored Suppliers",
        "company",
        entities=[
            {
                "entity": {"id": "company:abc123", "type": "Company", "name": "Acme Bank"},
                "tags": ["Tier1"],
            }
        ],
    )
    tagged = client.get_entities_with_tags(company_list["id"])
    assert len(tagged) == 1
    assert tagged[0]["tags"][0]["name"] == "Tier1"

    upd = client.replace_entity_tags(
        company_list["id"],
        "company:abc123",
        ["Critical", "Finance"],
    )
    assert upd["operation"]["status"] == "tags_updated"

    unchanged = client.replace_entity_tags(
        company_list["id"],
        "company:abc123",
        ["Critical", "Finance"],
    )
    assert unchanged["operation"]["status"] == "tags_unchanged"


@pytest.mark.feature("F4")
def test_f4_entity_id_heuristic_and_resolve_via_entity_match(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    created = client.create_list("Heuristic Test List", "entity")
    list_id = created["id"]

    client.add_entity(list_id, "Company", "B81SP6")
    client.add_entity(list_id, "Company", "CrowdStrike")
    client.add_entity(list_id, "Technology", "SAP")
    client.add_entity(list_id, "URL", "https://evil.example/login")
    client.add_entity(list_id, "IPAddress", "198.51.100.10")
    client.add_entity(list_id, "Company", "Acme Bank", resolve=True)

    add_bodies = [
        entry["body_json"]["entity"]
        for entry in mock_rf_server.requests_log
        if entry["path"] == f"/list/{list_id}/entity/add"
    ]
    assert add_bodies[0] == {"id": "B81SP6"}
    assert add_bodies[1] == {"type": "Company", "name": "CrowdStrike"}
    assert add_bodies[2] == {"type": "Technology", "name": "SAP"}
    assert add_bodies[3] == {"type": "URL", "name": "https://evil.example/login"}
    assert add_bodies[4] == {"type": "IpAddress", "name": "198.51.100.10"}
    assert add_bodies[5] == {"id": "company:abc123"}

    match_reqs = [
        entry for entry in mock_rf_server.requests_log if entry["path"] == "/entity-match/match"
    ]
    assert len(match_reqs) == 1
    assert match_reqs[0]["body_json"]["name"] == "Acme Bank"


@pytest.mark.feature("F4")
def test_f4_cli_watchlist_list_entities_add_remove(
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., Any],
) -> None:
    from soclens.client import RecordedFutureClient

    seeded = mock_rf_server.seed_list("Acme Watch List", "domain")
    list_id = seeded["id"]

    proc_list = run_cli(["watchlist", "list"])
    assert proc_list.returncode == 0
    assert "Acme Watch List" in proc_list.stdout

    proc_add = run_cli(
        ["watchlist", "add", list_id, "InternetDomainName", "phish.example"],
        env={"SOCLENS_AUTO_APPROVE": "1"},
    )
    assert proc_add.returncode == 0

    proc_entities = run_cli(["watchlist", "entities", list_id])
    assert proc_entities.returncode == 0
    assert "phish.example" in proc_entities.stdout

    proc_remove = run_cli(
        ["watchlist", "remove", list_id, "idn:phish.example"],
        env={"SOCLENS_AUTO_APPROVE": "1"},
    )
    assert proc_remove.returncode == 0

    client = RecordedFutureClient()
    assert client.get_watchlist_entities(list_id) == []


@pytest.mark.feature("F4")
def test_f4_remove_non_auto_resolved_company_via_client_cli_and_tui(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., Any],
) -> None:
    import asyncio

    from textual.widgets import DataTable, OptionList

    from soclens.client import RecordedFutureClient
    from soclens.tui import ConfirmActionModal, ContextMenuModal, create_app

    seeded = mock_rf_server.seed_list(
        "Monitored Companies",
        "company",
        list_id="report:fOqHJL",
        entities=[
            {
                "entity": {
                    "id": "iuiKOZ",
                    "type": "Company",
                    "name": "Colonial Federal Savings Bank",
                },
                "context": {"annotation": "1015"},
            },
            {
                "entity": {
                    "id": "lqJmC-",
                    "type": "Company",
                    "name": "Acme Credit Union",
                },
                "context": {"annotation": "1015"},
            },
            {
                "entity": {
                    "id": "mNpQrS",
                    "type": "Company",
                    "name": "Third Regional Bank",
                },
                "context": {"annotation": "1015"},
            },
        ],
    )
    list_id = seeded["id"]

    # 1. Confirm MockRFServer rejects non-auto-resolved {type, name} payloads with HTTP 400 Invalid entity
    raw_bad = requests.post(
        f"{mock_rf_server.base_url}/list/{list_id}/entity/remove",
        headers={"X-RFToken": "test-rf-token"},
        json={"entity": {"type": "Company", "name": "Colonial Federal Savings Bank"}},
        timeout=5,
    )
    assert raw_bad.status_code == 400
    assert "Invalid entity:" in raw_bad.json()["message"]

    # 2. Client removes first Company by (type="Company", name=...) -> resolves to {"id": "iuiKOZ"}
    client = RecordedFutureClient(error_log_dir=e2e_workspace / "logs")
    res_client = client.remove_entity(
        list_id,
        "Colonial Federal Savings Bank",
        entity_type="Company",
    )
    assert res_client["result"] == "removed"
    remaining_ids = [e["entity"]["id"] for e in client.get_watchlist_entities(list_id)]
    assert "iuiKOZ" not in remaining_ids

    # 3. CLI removes second Company by (type="Company", name=...) end-to-end
    proc_cli = run_cli(
        ["watchlist", "remove", list_id, "Company", "Acme Credit Union"],
        env={"SOCLENS_AUTO_APPROVE": "1"},
    )
    assert proc_cli.returncode == 0, f"stderr={proc_cli.stderr}"
    remaining_ids = [e["entity"]["id"] for e in client.get_watchlist_entities(list_id)]
    assert "lqJmC-" not in remaining_ids

    # 4. TUI WatchlistsPane right-click removal against live client + MockRFServer succeeds with zero HTTP 400s
    mock_rf_server.requests_log.clear()
    app = create_app(
        client=client,
        dry_run=False,
        initial_tab="tab-watchlists",
        workspace_dir=e2e_workspace,
    )
    tui_status_after = ""

    async def _run_tui() -> None:
        nonlocal tui_status_after
        from textual.widgets import Static

        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            lists_table = app.query_one("#wl-lists-table", DataTable)
            target_row = 0
            for idx in range(lists_table.row_count):
                row_key = str(getattr(lists_table.ordered_rows[idx].key, "value", ""))
                row_vals = [str(cell) for cell in lists_table.get_row_at(idx)]
                if row_key == list_id or list_id in row_vals or "Monitored Companies" in row_vals:
                    target_row = idx
                    break
            lists_table.move_cursor(row=target_row, column=0)
            lists_table.focus()
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()

            ent_table = app.query_one("#wl-entities-table", DataTable)
            assert ent_table.row_count == 1
            await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            opts = app.screen.query_one("#ctx-menu-options", OptionList)
            opts.highlighted = opts.get_option_index("remove_entity")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            tui_status_after = str(app.query_one("#wl-status", Static).render())

    asyncio.run(_run_tui())

    assert client.get_watchlist_entities(list_id) == []
    remove_reqs = [
        r for r in mock_rf_server.requests_log if r["path"] == f"/list/{list_id}/entity/remove"
    ]
    assert len(remove_reqs) == 1
    assert remove_reqs[0]["body_json"] == {"entity": {"id": "mNpQrS"}}
    assert client.last_trace_id is None
    assert not (e2e_workspace / "logs" / "rf_api_errors.jsonl").exists()
    assert "removed" in tui_status_after.lower() or "loaded 0" in tui_status_after.lower()


# ==============================================================================
# F5: Detection Rules Schema Fix
# ==============================================================================


@pytest.mark.feature("F5")
def test_f5_search_detection_rules_uses_result_not_results(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()
    rules = client.search_detection_rules()

    assert len(rules) == 2
    assert all(r["type"] == "sigma" for r in rules)
    assert all("rules" in r and r["rules"][0]["content"] for r in rules)


@pytest.mark.feature("F5")
def test_f5_search_detection_rules_days_uses_updated_after_iso8601(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    rules = client.search_detection_rules(days=3650)
    assert len(rules) == 2

    req_body = mock_rf_server.requests_log[-1]["body_json"]
    updated_filter = req_body["filter"]["updated"]
    assert "after" in updated_filter
    assert "operator" not in updated_filter
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", updated_filter["after"])


@pytest.mark.feature("F5")
def test_f5_search_detection_rules_multipage_offset_pagination(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    rules = client.search_detection_rules(limit=1)

    assert len(rules) == 2
    assert {r["id"] for r in rules} == {"doc:sigma-1", "doc:sigma-2"}
    reqs = [
        entry["body_json"]
        for entry in mock_rf_server.requests_log
        if entry["path"] == "/detection-rule/search"
    ]
    assert len(reqs) == 2
    assert "offset" not in reqs[0]
    assert reqs[1]["offset"] == "1"
    assert "cursor" not in reqs[1]


@pytest.mark.feature("F5")
def test_f5_search_detection_rules_filters_types_title_entities_doc_id(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()

    yara_rules = client.search_detection_rules(rule_types=["yara"])
    assert [r["id"] for r in yara_rules] == ["doc:yara-1"]

    by_title = client.search_detection_rules(title="Certutil")
    assert [r["id"] for r in by_title] == ["doc:sigma-2"]

    by_entity = client.search_detection_rules(entities=["mitre:T1059.001"])
    assert [r["id"] for r in by_entity] == ["doc:sigma-1"]

    by_doc = client.search_detection_rules(doc_id="doc:sigma-1", tagged_entities=True)
    assert [r["id"] for r in by_doc] == ["doc:sigma-1"]
    assert mock_rf_server.requests_log[-1]["body_json"]["tagged_entities"] is True


@pytest.mark.feature("F5")
def test_f5_detection_rule_relation_entities_and_types(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()

    entities = client.get_detection_rule_entities()
    assert any(item["id"] == "mitre:T1059.001" for item in entities)

    entity_types = client.get_detection_rule_entity_types()
    assert "MitreAttackIdentifier" in entity_types
    assert "Malware" in entity_types


@pytest.mark.feature("F5")
def test_f5_sigma_load_rules_with_days_via_mock_rf_server(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.sigma import load_rules

    assert mock_rf_server.port > 0
    repo_cache = REPO_ROOT / "sigma_rules_cache.json"
    repo_cache_before = repo_cache.read_bytes() if repo_cache.exists() else None

    client = RecordedFutureClient()
    rules = load_rules(client, days=3650, cache_dir=e2e_workspace)

    assert len(rules) == 2
    assert all("content" in r and "rule_id" in r for r in rules)
    assert not (e2e_workspace / "sigma_rules_cache.json").exists()
    if repo_cache_before is not None:
        assert repo_cache.read_bytes() == repo_cache_before
    else:
        assert not repo_cache.exists()


# ==============================================================================
# F6: Expanded SOC APIs
# ==============================================================================


@pytest.mark.feature("F6")
def test_f6_entity_match_and_entity_lookup(mock_rf_server: MockRFServer) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()

    matches = client.entity_match("Acme", types=["Company"])
    assert len(matches) == 1
    assert matches[0]["id"] == "company:abc123"

    detail = client.entity_lookup("company:abc123")
    assert detail["name"] == "Acme Bank"
    assert "Acme Financial" in detail["aliases"]


@pytest.mark.feature("F6")
def test_f6_soar_enrich_contexts_and_triage(mock_rf_server: MockRFServer) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()

    enriched = client.soar_enrich(
        {"ip": ["198.51.100.10"], "companybydomain": ["example.com"]}
    )
    results = enriched["data"]["results"]
    assert len(results) == 2
    ip_entry = next(r for r in results if r["entity"]["type"] == "ip")
    assert ip_entry["risk"]["score"] == 72

    contexts = client.soar_get_contexts()
    assert any(c["name"] == "phishing" for c in contexts["contexts"])

    triage = client.soar_triage("phishing", {"domain": ["evil.invalid", "benign.example"]})
    triage_map = {r["entity"]["name"]: r for r in triage["data"]["results"]}
    assert triage_map["evil.invalid"]["verdict"] is True
    assert triage_map["benign.example"]["verdict"] is False


@pytest.mark.feature("F6")
def test_f6_connect_v2_lookups_search_riskrules_risklist(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()

    ip_data = client.v2_lookup("ip", "198.51.100.10")
    assert ip_data["data"]["risk"]["score"] == 75

    dom_data = client.v2_lookup("domain", "example.com")
    assert dom_data["data"]["entity"]["id"] == "idn:example.com"

    comp_data = client.v2_company_by_domain("example.com")
    assert comp_data["data"]["entity"]["name"] == "Acme Bank"

    search_res = client.v2_search("ip")
    assert len(search_res["data"]["results"]) >= 1

    rules_res = client.v2_riskrules("ip")
    assert rules_res["data"]["results"][0]["name"] == "recentC2"

    stat_headers = client.v2_stat_risklist("ip")
    assert _lower_headers(stat_headers).get("etag") == '"ip-v1"'

    risklist_csv = client.v2_risklist("ip")
    assert isinstance(risklist_csv, str)
    assert "Name,Risk" in risklist_csv
    assert "198.51.100.10" in risklist_csv


@pytest.mark.feature("F6")
def test_f6_playbook_alerts_lifecycle_and_png_image_retrieval(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()

    searched = client.search_playbook_alerts(categories=["domain_abuse", "malicious_sites"])
    assert len(searched["data"]) == 2

    preview = client.get_playbook_alert_preview("pb-1")
    assert preview["data"]["category"] == "domain_abuse"

    detail = client.get_playbook_alert("domain_abuse", "pb-1")
    assets = detail["data"]["panel_evidence_summary"]["assets"]
    assert any(a.get("type") == "image_hash" and a["hash_id"].startswith("hash:") for a in assets)

    updated = client.update_playbook_alert("pb-1", status="InProgress", assignee="soc-lead")
    assert updated["data"]["status"] == "InProgress"
    assert updated["data"]["assignee"] == "soc-lead"

    png_bytes = client.get_playbook_alert_image("domain_abuse", "pb-1", "screenshot-1")
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")


@pytest.mark.feature("F6")
def test_f6_alerts_v3_and_v2_update_and_cases_crud(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    assert mock_rf_server.port > 0
    client = RecordedFutureClient()

    alerts = client.search_alerts_v3()
    assert alerts["data"]["results"][0]["id"] == "alert-v3-1"

    alert_detail = client.get_alert_v3("alert-v3-1")
    assert alert_detail["data"]["title"] == "Brand Logo Match Detected"

    hits = client.get_alert_v3_hits(["hit-1"])
    assert hits["data"]["hits"][0]["id"] == "hit-1"

    upd_alerts = client.update_alerts_v2([{"id": "alert-v3-1", "statusInPortal": "Resolved"}])
    assert upd_alerts["success"] == ["alert-v3-1"]

    cases = client.search_cases()
    assert len(cases["data"]) >= 1

    created = client.create_case(title="Brand Phishing Escalation", priority="High")
    case_id = created["id"]

    looked_up = client.lookup_cases([case_id])
    assert looked_up["data"][0]["title"] == "Brand Phishing Escalation"

    updated_case = client.update_case(case_id, status="Closed")
    assert updated_case["status"] == "Closed"


@pytest.mark.feature("F6")
def test_f6_sandbox_v0_search_sample_and_overview_bearer_auth(
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()

    search_res = client.sandbox_search("suspicious.exe")
    assert search_res["samples"][0]["id"] == "sample-1"

    sample = client.sandbox_get_sample("sample-1")
    assert sample["score"] == 8

    overview = client.sandbox_get_overview("sample-1")
    assert overview["sample"]["id"] == "sample-1"

    assert len(mock_rf_server.requests_log) == 3
    for entry in mock_rf_server.requests_log:
        hdrs = _lower_headers(entry["headers"])
        assert hdrs.get("authorization") == "Bearer test-sandbox-token"
        assert "x-rftoken" not in hdrs
