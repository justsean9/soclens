"""Tier 1 E2E happy-path feature coverage tests for soclens-agentic-soc (F1-F10)."""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any

import pytest

import tests.e2e.agentic_mocks as _mocks
from soclens.config import get_local_llm_config
from soclens.llm import LocalLLMClient
from tests.e2e.agentic_mocks import (
    MockAgenticLLMAndCopilotServer,
    MockOSINTServer,
    assert_zero_mutating_http_requests,
    build_correlated_soc_scenario,
    make_agentic_app,
    richlog_text,
    right_click_table_row,
    select_table_row_containing,
    switch_tab_and_wait,
)

# Re-export shared E2E fixtures for pytest discovery.
v21_workspace = _mocks.v21_workspace
agentic_workspace = _mocks.agentic_workspace
mock_rf_server = _mocks.mock_rf_server
mock_splunk_es_server = _mocks.mock_splunk_es_server
mock_s1_server = _mocks.mock_s1_server
mock_agentic_llm_server = _mocks.mock_agentic_llm_server
mock_osint_server = _mocks.mock_osint_server

pytestmark = [pytest.mark.e2e, pytest.mark.tier1]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DESIGN_DOC_PATH = _REPO_ROOT / "docs" / "AGENTIC_SOC_ARCHITECTURE.md"

_ALL_PROVIDERS: tuple[str, ...] = (
    "ollama",
    "openai",
    "m365_copilot",
    "copilot_studio",
    "copilot_directline",
    "security_copilot",
)


def _find_tool(registry: Any, category: str, *keywords: str) -> Any:
    candidates = [t for t in registry.list_tools() if t.source_category == category]
    assert candidates, f"Expected at least one registered tool in category {category!r}"
    for kw in keywords:
        low = kw.lower()
        for tool in candidates:
            if low in tool.name.lower() or low in tool.description.lower():
                return tool
    return candidates[0]


def _default_args_for_tool(tool: Any, seeded: dict[str, str]) -> dict[str, Any]:
    props = (tool.parameters_schema or {}).get("properties") or {}
    args: dict[str, Any] = {}
    name_low = tool.name.lower()
    if "spl" in props:
        args["spl"] = f'search {seeded["ip"]} | head 5'
    if "query" in props:
        args["query"] = seeded["ip"]
    if "entity_type" in props:
        args["entity_type"] = "vulnerability"
    if "value" in props:
        args["value"] = seeded["cve_id"]
    if "entity_id" in props:
        args["entity_id"] = seeded["cve_id"]
    if "cve_id" in props:
        args["cve_id"] = seeded["cve_id"]
    if "target" in props:
        args["target"] = seeded["cve_id"]
    if "kind" in props:
        args["kind"] = "vulnerability" if "vuln" in name_low or "osint" in name_low else "ip"
    if "alert_id" in props:
        args["alert_id"] = seeded["rf_alert_id"]
    if "threat_id" in props:
        args["threat_id"] = seeded["s1_threat_id"]
    if "finding_id" in props:
        args["finding_id"] = seeded["es_event_id"]
    if "limit" in props:
        args["limit"] = 5
    return args


# ==============================================================================
# F1: AI & Hermes Review/Design Note (5 tests)
# ==============================================================================


@pytest.mark.feature("F1")
def test_tier1_f1_architecture_doc_exists_and_non_empty() -> None:
    assert _DESIGN_DOC_PATH.is_file(), f"Missing design doc: {_DESIGN_DOC_PATH}"
    text = _DESIGN_DOC_PATH.read_text(encoding="utf-8")
    assert len(text.strip()) >= 800
    assert "SOCLens" in text
    assert "Hermes" in text


@pytest.mark.feature("F1")
def test_tier1_f1_architecture_doc_reviews_all_six_providers() -> None:
    text = _DESIGN_DOC_PATH.read_text(encoding="utf-8")
    for provider in _ALL_PROVIDERS:
        assert provider in text, f"Expected provider {provider!r} documented in {_DESIGN_DOC_PATH}"


@pytest.mark.feature("F1")
def test_tier1_f1_architecture_doc_covers_hermes_readonly_tool_patterns() -> None:
    text = _DESIGN_DOC_PATH.read_text(encoding="utf-8").lower()
    assert "read-only" in text or "read_only" in text or "readonly" in text
    assert "fail-closed" in text or "fail closed" in text
    assert "allowlist" in text or "registry" in text


@pytest.mark.feature("F1")
def test_tier1_f1_architecture_doc_covers_policy_control_and_guardrails() -> None:
    text = _DESIGN_DOC_PATH.read_text(encoding="utf-8").lower()
    assert "control panel" in text or "aipolicy" in text
    assert "ask_only" in text or "ask about event" in text
    assert "full_investigation" in text or "full investigation" in text


@pytest.mark.feature("F1")
def test_tier1_f1_architecture_doc_covers_audit_logging_and_event_tracking() -> None:
    text = _DESIGN_DOC_PATH.read_text(encoding="utf-8").lower()
    assert "audit" in text
    assert "redact" in text
    assert "event_key" in text or "unique event" in text
    assert "background" in text


# ==============================================================================
# F2: Strictly Read-Only Tool Surface & SPL Validator (6 tests)
# ==============================================================================


@pytest.mark.feature("F2")
def test_tier1_f2_default_registry_covers_all_five_source_categories(
    agentic_workspace: Path,
) -> None:
    from soclens.agent_policy import (
        SOURCE_CATEGORY_OSINT,
        SOURCE_CATEGORY_RF,
        SOURCE_CATEGORY_S1,
        SOURCE_CATEGORY_SPLUNK,
        SOURCE_CATEGORY_SPLUNK_ES,
    )
    from soclens.agent_tools import build_default_readonly_registry

    registry = build_default_readonly_registry()
    tools = registry.list_tools()
    categories = {t.source_category for t in tools}
    assert categories == {
        SOURCE_CATEGORY_SPLUNK,
        SOURCE_CATEGORY_SPLUNK_ES,
        SOURCE_CATEGORY_S1,
        SOURCE_CATEGORY_RF,
        SOURCE_CATEGORY_OSINT,
    }


@pytest.mark.feature("F2")
def test_tier1_f2_zero_forbidden_mutating_methods_registered(
    agentic_workspace: Path,
) -> None:
    from soclens.agent_tools import (
        FORBIDDEN_MUTATING_METHOD_NAMES,
        build_default_readonly_registry,
    )

    assert len(FORBIDDEN_MUTATING_METHOD_NAMES) >= 30
    registry = build_default_readonly_registry()
    registered_names = {t.name for t in registry.list_tools()}
    overlap = registered_names & FORBIDDEN_MUTATING_METHOD_NAMES
    assert not overlap, f"Forbidden mutating tools registered: {sorted(overlap)}"
    for spec in registry.list_tools():
        assert spec.readonly is True


@pytest.mark.feature("F2")
def test_tier1_f2_validate_readonly_spl_accepts_safe_queries() -> None:
    from soclens.agent_tools import validate_readonly_spl

    safe_queries = [
        'search index=main src="198.51.100.10" | head 20',
        '| tstats count from datamodel=Network_Traffic where All_Traffic.src="198.51.100.10" by All_Traffic.dest',
        'index=notable urgency=high | stats count by rule_name, risk_object',
        'index=_internal | eval host_low=lower(host) | table _time, host_low | sort - _time',
    ]
    for spl in safe_queries:
        ok, reason = validate_readonly_spl(spl)
        assert ok is True, f"Expected safe SPL to pass: {spl!r} (reason={reason!r})"


@pytest.mark.feature("F2")
def test_tier1_f2_openai_schemas_generated_for_advertised_tools(
    agentic_workspace: Path,
) -> None:
    from soclens.agent_tools import build_default_readonly_registry

    registry = build_default_readonly_registry()
    tools = registry.list_tools()
    schemas = registry.openai_schemas()
    assert len(schemas) == len(tools)
    for schema in schemas:
        assert schema["type"] == "function"
        fn = schema["function"]
        assert fn["name"]
        assert isinstance(fn["parameters"], dict)

    subset = {tools[0].name}
    filtered = registry.openai_schemas(allowed_names=subset)
    assert [s["function"]["name"] for s in filtered] == [tools[0].name]


@pytest.mark.feature("F2")
def test_tier1_f2_readonly_wrappers_query_mock_servers_safely(
    agentic_workspace: Path,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
) -> None:
    from soclens.agent_policy import (
        SOURCE_CATEGORY_RF,
        SOURCE_CATEGORY_S1,
        SOURCE_CATEGORY_SPLUNK,
        SOURCE_CATEGORY_SPLUNK_ES,
        AIPolicyConfig,
    )
    from soclens.agent_tools import build_default_readonly_registry

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    registry = build_default_readonly_registry()
    policy = AIPolicyConfig()

    for category, hints in (
        (SOURCE_CATEGORY_RF, ("v2", "lookup", "alert")),
        (SOURCE_CATEGORY_S1, ("threat", "list")),
        (SOURCE_CATEGORY_SPLUNK_ES, ("notable", "finding")),
        (SOURCE_CATEGORY_SPLUNK, ("search", "spl")),
    ):
        tool = _find_tool(registry, category, *hints)
        res = registry.execute(
            tool.name,
            _default_args_for_tool(tool, seeded),
            mode="full_investigation",
            policy=policy,
        )
        assert res.get("ok", True) is not False
        assert res.get("blocked") is not True

    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server,
        s1_server=mock_s1_server,
        es_server=mock_splunk_es_server,
    )


@pytest.mark.feature("F2")
def test_tier1_f2_get_tool_returns_spec_by_name(agentic_workspace: Path) -> None:
    from soclens.agent_tools import build_default_readonly_registry

    registry = build_default_readonly_registry()
    first = registry.list_tools()[0]
    fetched = registry.get_tool(first.name)
    assert fetched is not None
    assert fetched.name == first.name
    assert fetched.readonly is True


# ==============================================================================
# F3: AI Control Panel Policy Engine & Persistence (5 tests)
# ==============================================================================


@pytest.mark.feature("F3")
def test_tier1_f3_policy_config_safe_defaults() -> None:
    from soclens.agent_policy import AIPolicyConfig

    cfg = AIPolicyConfig()
    assert cfg.background_triage_enabled is False
    assert cfg.cross_search_enabled is True
    assert cfg.splunk_search_enabled is True
    assert cfg.splunk_es_enabled is True
    assert cfg.sentinelone_enabled is True
    assert cfg.recorded_future_enabled is True
    assert cfg.watchlists_osint_enabled is True
    assert cfg.disabled_tools == []
    assert cfg.max_tool_steps == 50
    assert cfg.max_identical_tool_calls == 2
    assert cfg.max_same_tool_failures == 10
    assert cfg.ai_kill_switch_active is False
    assert cfg.kill_switch_visible is True
    assert cfg.kill_switch_hotkey == "f12"


@pytest.mark.feature("F3")
def test_tier1_f3_policy_store_save_and_load_roundtrip(agentic_workspace: Path) -> None:
    from soclens.agent_policy import AIPolicyConfig, AIPolicyStore

    store = AIPolicyStore()
    cfg = AIPolicyConfig(
        background_triage_enabled=True,
        splunk_search_enabled=False,
        disabled_tools=["splunk_run_search"],
        max_tool_steps=5,
    )
    store.save(cfg)

    expected_path = agentic_workspace / ".soclens_cache" / "ai_policy.json"
    assert expected_path.is_file()

    reloaded = AIPolicyStore().load()
    assert reloaded.background_triage_enabled is True
    assert reloaded.splunk_search_enabled is False
    assert reloaded.disabled_tools == ["splunk_run_search"]
    assert reloaded.max_tool_steps == 5


@pytest.mark.feature("F3")
def test_tier1_f3_policy_store_update_atomic_persistence(agentic_workspace: Path) -> None:
    from soclens.agent_policy import AIPolicyStore

    custom_path = agentic_workspace / ".soclens_cache" / "custom_policy.json"
    store = AIPolicyStore(path=custom_path)
    updated = store.update(background_triage_enabled=True, sentinelone_enabled=False)
    assert updated.background_triage_enabled is True
    assert updated.sentinelone_enabled is False

    fresh = AIPolicyStore(path=custom_path).load()
    assert fresh.background_triage_enabled is True
    assert fresh.sentinelone_enabled is False
    assert fresh.cross_search_enabled is True


@pytest.mark.feature("F3")
def test_tier1_f3_evaluate_tool_permission_allows_enabled_readonly_tool() -> None:
    from soclens.agent_policy import (
        SOURCE_CATEGORY_RF,
        AIPolicyConfig,
        evaluate_tool_permission,
    )

    decision = evaluate_tool_permission(
        "rf_lookup_ioc_or_cve",
        SOURCE_CATEGORY_RF,
        True,
        "full_investigation",
        AIPolicyConfig(),
    )
    assert decision.allowed is True
    assert decision.rule == "allowed"


@pytest.mark.feature("F3")
def test_tier1_f3_source_category_constants_match_contract() -> None:
    from soclens.agent_policy import (
        SOURCE_CATEGORY_OSINT,
        SOURCE_CATEGORY_RF,
        SOURCE_CATEGORY_S1,
        SOURCE_CATEGORY_SPLUNK,
        SOURCE_CATEGORY_SPLUNK_ES,
    )

    assert SOURCE_CATEGORY_SPLUNK == "splunk_search"
    assert SOURCE_CATEGORY_SPLUNK_ES == "splunk_es"
    assert SOURCE_CATEGORY_S1 == "sentinelone"
    assert SOURCE_CATEGORY_RF == "recorded_future"
    assert SOURCE_CATEGORY_OSINT == "watchlists_osint"


# ==============================================================================
# F4: Persistent Redacted Audit Log Store (5 tests)
# ==============================================================================


@pytest.mark.feature("F4")
def test_tier1_f4_audit_store_appends_to_default_jsonl(agentic_workspace: Path) -> None:
    from soclens.agent_audit import AuditEntry, AuditLogStore

    store = AuditLogStore()
    entry = AuditEntry(
        entry_id="aud-1",
        timestamp="2026-11-25T20:00:00Z",
        run_id="run-1",
        event_key="rf_alert::alert-v3-1",
        provider="ollama",
        mode="full_investigation",
        event_type="prompt",
        payload={"question": "Assess C2 risk"},
    )
    store.append(entry)

    audit_file = agentic_workspace / ".soclens_cache" / "ai_audit.jsonl"
    assert audit_file.is_file()
    lines = [ln for ln in audit_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["event_key"] == "rf_alert::alert-v3-1"


@pytest.mark.feature("F4")
def test_tier1_f4_audit_store_query_filters(agentic_workspace: Path) -> None:
    from soclens.agent_audit import AuditEntry, AuditLogStore

    store = AuditLogStore()
    store.append(
        AuditEntry(
            entry_id="e1",
            timestamp="2026-11-25T20:00:01Z",
            run_id="r1",
            event_key="rf_alert::a1",
            provider="ollama",
            mode="full_investigation",
            event_type="tool_call",
            tool_name="rf_v2_lookup",
            allowed=True,
        )
    )
    store.append(
        AuditEntry(
            entry_id="e2",
            timestamp="2026-11-25T20:00:02Z",
            run_id="r1",
            event_key="rf_alert::a1",
            provider="ollama",
            mode="full_investigation",
            event_type="blocked_action",
            tool_name="splunk_run_search",
            allowed=False,
            reason="splunk_search_disabled",
        )
    )
    store.append(
        AuditEntry(
            entry_id="e3",
            timestamp="2026-11-25T20:00:03Z",
            run_id="r2",
            event_key="s1_threat::t2",
            provider="openai",
            mode="ask_only",
            event_type="decision",
        )
    )

    assert len(store.query(event_key="rf_alert::a1")) == 2
    assert len(store.query(run_id="r2")) == 1
    assert [e.entry_id for e in store.query(event_type="tool_call")] == ["e1"]
    assert [e.entry_id for e in store.query(blocked_only=True)] == ["e2"]


@pytest.mark.feature("F4")
def test_tier1_f4_audit_store_persists_across_restart(agentic_workspace: Path) -> None:
    from soclens.agent_audit import AuditEntry, AuditLogStore

    store1 = AuditLogStore()
    store1.append(
        AuditEntry(
            entry_id="persist-1",
            timestamp="2026-11-25T20:01:00Z",
            run_id="run-p",
            event_key="splunk_es::1001::fnd-1",
            provider="m365_copilot",
            mode="full_investigation",
            event_type="decision",
            payload={"summary": "Confirmed benign."},
        )
    )

    store2 = AuditLogStore()
    rows = store2.query(event_key="splunk_es::1001::fnd-1")
    assert len(rows) == 1
    assert rows[0].entry_id == "persist-1"
    assert rows[0].provider == "m365_copilot"


@pytest.mark.feature("F4")
def test_tier1_f4_redact_sensitive_data_scrubs_tokens_and_keys() -> None:
    from soclens.agent_audit import redact_sensitive_data

    secret_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
    secret_openai = "sk-proj-TestSecretKeyValue1234567890"
    secret_pw = "SuperSecretPassword!99"
    cleaned = redact_sensitive_data(
        {
            "Authorization": secret_bearer,
            "api_key": secret_openai,
            "password": secret_pw,
            "note": f"header had {secret_bearer} and {secret_openai}",
        }
    )
    serialized = json.dumps(cleaned)
    assert "eyJhbGciOiJIUzI1NiIs" not in serialized
    assert "TestSecretKeyValue1234567890" not in serialized
    assert secret_pw not in serialized


@pytest.mark.feature("F4")
def test_tier1_f4_audit_store_thread_safe_concurrent_appends(agentic_workspace: Path) -> None:
    from soclens.agent_audit import AuditEntry, AuditLogStore

    store = AuditLogStore()
    errors: list[Exception] = []

    def _worker(tid: int) -> None:
        try:
            for idx in range(10):
                store.append(
                    AuditEntry(
                        entry_id=f"t{tid}-{idx}",
                        timestamp="2026-11-25T20:02:00Z",
                        run_id=f"run-{tid}",
                        event_key=f"rf_alert::a-{tid}",
                        provider="ollama",
                        mode="ask_only",
                        event_type="prompt",
                    )
                )
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=5.0)

    assert not errors
    assert len(store.query(limit=100)) == 40


# ==============================================================================
# F5: Multi-Provider LLM-Controlled Agent Orchestrator (6 tests)
# ==============================================================================


@pytest.mark.feature("F5")
@pytest.mark.parametrize("provider", _ALL_PROVIDERS)
def test_tier1_f5_orchestrator_ask_only_and_full_investigation_all_providers(
    provider: str,
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import SOURCE_CATEGORY_RF, AIPolicyStore
    from soclens.agent_tools import build_default_readonly_registry

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, provider)

    registry = build_default_readonly_registry()
    policy_store = AIPolicyStore()
    audit_store = AuditLogStore()
    orchestrator = SocAgentOrchestrator(
        registry=registry,
        policy_store=policy_store,
        audit_store=audit_store,
        llm_client_factory=lambda: LocalLLMClient(get_local_llm_config()),
    )

    # 1. ask_only -> 0 external tools advertised/executed
    mock_agentic_llm_server.queue_scripted_turn(
        provider=provider,
        content=f"[{provider}] Ask-only assessment for {seeded['cve_id']}.",
    )
    ask_res = orchestrator.investigate(
        event_key=f"rf_alert::{seeded['rf_alert_id']}",
        event_context=f"Alert on {seeded['ip']} / {seeded['cve_id']}",
        mode="ask_only",
        question="What does this alert indicate?",
        provider=provider,
    )
    assert ask_res.status == "completed"
    assert ask_res.mode == "ask_only"
    assert ask_res.provider == provider
    assert ask_res.tool_calls == []
    assert provider in ask_res.answer_markdown
    ask_reqs = mock_agentic_llm_server.chat_requests(provider=provider)
    assert len(ask_reqs) == 1
    assert ask_reqs[0].get("tools") in (None, [])

    # 2. full_investigation -> invokes real read-only RF tool & synthesizes answer
    rf_tool = _find_tool(registry, SOURCE_CATEGORY_RF, "v2", "lookup")
    rf_args = _default_args_for_tool(rf_tool, seeded)
    mock_agentic_llm_server.queue_scripted_turn(
        provider=provider,
        tool_calls=[{"name": rf_tool.name, "arguments": rf_args}],
    )
    mock_agentic_llm_server.queue_scripted_turn(
        provider=provider,
        content=f"[{provider}] Full investigation confirmed {seeded['cve_id']} score 99.",
    )
    full_res = orchestrator.investigate(
        event_key=f"rf_alert::{seeded['rf_alert_id']}",
        event_context=f"Alert on {seeded['ip']} / {seeded['cve_id']}",
        mode="full_investigation",
        question="Correlate CVE and IOC across sources.",
        provider=provider,
    )
    assert full_res.status == "completed"
    assert full_res.mode == "full_investigation"
    assert full_res.provider == provider
    assert len(full_res.tool_calls) >= 1
    assert full_res.tool_calls[0]["tool_name"] == rf_tool.name
    assert "99" in full_res.answer_markdown

    audits = audit_store.query(run_id=full_res.run_id)
    event_types = {a.event_type for a in audits}
    assert "prompt" in event_types
    assert "tool_call" in event_types
    assert "tool_result" in event_types
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server,
        s1_server=mock_s1_server,
        es_server=mock_splunk_es_server,
    )


# ==============================================================================
# F6: Read-Only Cross-Source Investigation Pivoting (5 tests)
# ==============================================================================


@pytest.mark.feature("F6")
def test_tier1_f6_pivot_rf_cve_to_splunk_spl_search(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import SOURCE_CATEGORY_SPLUNK, AIPolicyStore
    from soclens.agent_tools import build_default_readonly_registry

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "openai")

    registry = build_default_readonly_registry()
    spl_tool = _find_tool(registry, SOURCE_CATEGORY_SPLUNK, "search", "spl")
    mock_agentic_llm_server.queue_scripted_turn(
        provider="openai",
        tool_calls=[{"name": spl_tool.name, "arguments": _default_args_for_tool(spl_tool, seeded)}],
    )
    mock_agentic_llm_server.queue_scripted_turn(
        provider="openai",
        content=f"Splunk telemetry matched {seeded['ip']} targeting {seeded['hostname']}.",
    )

    orch = SocAgentOrchestrator(
        registry=registry,
        policy_store=AIPolicyStore(),
        audit_store=AuditLogStore(),
    )
    res = orch.investigate(
        event_key=f"rf_alert::{seeded['rf_alert_id']}",
        event_context=f"IP {seeded['ip']} exploiting {seeded['cve_id']}",
        mode="full_investigation",
        question="Search Splunk for traffic from this IP.",
    )
    assert res.status == "completed"
    assert len(res.tool_calls) == 1
    assert any(r["path"].endswith("/search/jobs") for r in mock_splunk_es_server.requests_log)
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server, s1_server=mock_s1_server, es_server=mock_splunk_es_server
    )


@pytest.mark.feature("F6")
def test_tier1_f6_pivot_rf_alert_to_sentinelone_threats(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import SOURCE_CATEGORY_S1, AIPolicyStore
    from soclens.agent_tools import build_default_readonly_registry

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    registry = build_default_readonly_registry()
    s1_tool = _find_tool(registry, SOURCE_CATEGORY_S1, "threat", "list")

    mock_agentic_llm_server.queue_scripted_turn(
        provider="ollama",
        tool_calls=[{"name": s1_tool.name, "arguments": _default_args_for_tool(s1_tool, seeded)}],
    )
    mock_agentic_llm_server.queue_scripted_turn(
        provider="ollama",
        content="SentinelOne threats retrieved and correlated.",
    )

    orch = SocAgentOrchestrator(
        registry=registry, policy_store=AIPolicyStore(), audit_store=AuditLogStore()
    )
    res = orch.investigate(
        event_key=f"rf_alert::{seeded['rf_alert_id']}",
        event_context=f"Host {seeded['hostname']}",
        mode="full_investigation",
    )
    assert res.status == "completed"
    assert len(res.tool_calls) == 1
    assert any("/web/api/v2.1/threats" in r["path"] for r in mock_s1_server.requests_log)
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server, s1_server=mock_s1_server, es_server=mock_splunk_es_server
    )


@pytest.mark.feature("F6")
def test_tier1_f6_pivot_to_splunk_es_notables(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import SOURCE_CATEGORY_SPLUNK_ES, AIPolicyStore
    from soclens.agent_tools import build_default_readonly_registry

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    registry = build_default_readonly_registry()
    es_tool = _find_tool(registry, SOURCE_CATEGORY_SPLUNK_ES, "notable", "finding")

    mock_agentic_llm_server.queue_scripted_turn(
        provider="ollama",
        tool_calls=[{"name": es_tool.name, "arguments": _default_args_for_tool(es_tool, seeded)}],
    )
    mock_agentic_llm_server.queue_scripted_turn(
        provider="ollama",
        content="Splunk ES notables correlated with alert.",
    )

    orch = SocAgentOrchestrator(
        registry=registry, policy_store=AIPolicyStore(), audit_store=AuditLogStore()
    )
    res = orch.investigate(
        event_key=f"rf_alert::{seeded['rf_alert_id']}",
        event_context="Correlate ES notables",
        mode="full_investigation",
    )
    assert res.status == "completed"
    assert len(res.tool_calls) == 1
    assert any("findings" in r["path"] or "search/jobs" in r["path"] for r in mock_splunk_es_server.requests_log)
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server, s1_server=mock_s1_server, es_server=mock_splunk_es_server
    )


@pytest.mark.feature("F6")
def test_tier1_f6_pivot_to_rf_watchlists_and_v2_enrichment(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import SOURCE_CATEGORY_OSINT, SOURCE_CATEGORY_RF, AIPolicyStore
    from soclens.agent_tools import build_default_readonly_registry

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "openai")
    registry = build_default_readonly_registry()
    rf_tool = _find_tool(registry, SOURCE_CATEGORY_RF, "v2", "lookup")
    wl_tool = _find_tool(registry, SOURCE_CATEGORY_OSINT, "watchlist", "list")

    mock_agentic_llm_server.queue_scripted_turn(
        provider="openai",
        tool_calls=[
            {"name": rf_tool.name, "arguments": _default_args_for_tool(rf_tool, seeded)},
            {"name": wl_tool.name, "arguments": _default_args_for_tool(wl_tool, seeded)},
        ],
    )
    mock_agentic_llm_server.queue_scripted_turn(
        provider="openai",
        content="RF v2 enrichment and watchlist check completed.",
    )

    orch = SocAgentOrchestrator(
        registry=registry, policy_store=AIPolicyStore(), audit_store=AuditLogStore()
    )
    res = orch.investigate(
        event_key=f"s1_threat::{seeded['s1_threat_id']}",
        event_context=f"Correlate {seeded['cve_id']}",
        mode="full_investigation",
    )
    assert res.status == "completed"
    assert len(res.tool_calls) >= 2
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server, s1_server=mock_s1_server, es_server=mock_splunk_es_server
    )


@pytest.mark.feature("F6")
def test_tier1_f6_pivot_to_offline_osint_enrichment(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_osint_server: MockOSINTServer,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import SOURCE_CATEGORY_OSINT, AIPolicyStore
    from soclens.agent_tools import build_default_readonly_registry

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    osint_client = mock_osint_server.make_client(workspace_dir=agentic_workspace)
    registry = build_default_readonly_registry(osint_client=osint_client)
    osint_tool = _find_tool(registry, SOURCE_CATEGORY_OSINT, "osint", "vuln", "enrich")

    mock_agentic_llm_server.queue_scripted_turn(
        provider="ollama",
        tool_calls=[{"name": osint_tool.name, "arguments": _default_args_for_tool(osint_tool, seeded)}],
    )
    mock_agentic_llm_server.queue_scripted_turn(
        provider="ollama",
        content="OSINT CVE/KEV enrichment confirmed active exploitation.",
    )

    orch = SocAgentOrchestrator(
        registry=registry, policy_store=AIPolicyStore(), audit_store=AuditLogStore()
    )
    res = orch.investigate(
        event_key=f"rf_alert::{seeded['rf_alert_id']}",
        event_context=f"Check OSINT for {seeded['cve_id']}",
        mode="full_investigation",
    )
    assert res.status == "completed"
    assert len(res.tool_calls) == 1
    assert len(mock_osint_server.requests_log) >= 1


# ==============================================================================
# F7: Unique Event Tracking & Per-Event AI Panel Persistence (5 tests)
# ==============================================================================


@pytest.mark.feature("F7")
def test_tier1_f7_make_event_key_canonical_across_all_streams() -> None:
    from soclens.event_tracker import make_event_key

    k_rf = make_event_key("rf_alert", "a-1")
    k_pb = make_event_key("rf_playbook", "pb-1")
    k_s1t = make_event_key("s1_threat", "thr-1")
    k_s1c = make_event_key("s1_cloud_alert", "cld-1")
    k_es = make_event_key("splunk_es", "fnd-1", scope="tenant_1001")

    keys = {k_rf, k_pb, k_s1t, k_s1c, k_es}
    assert len(keys) == 5
    assert k_rf == "rf_alert::a-1"
    assert k_pb == "rf_playbook::pb-1"
    assert k_s1t == "s1_threat::thr-1"
    assert k_s1c == "s1_cloud_alert::cld-1"
    assert k_es == "splunk_es::tenant_1001::fnd-1"


@pytest.mark.feature("F7")
def test_tier1_f7_normalize_unique_event_across_four_streams() -> None:
    from soclens.event_tracker import normalize_unique_event

    ev_rf = normalize_unique_event("rf_alert", {"id": "alert-1", "title": "RF Alert"})
    ev_pb = normalize_unique_event(
        "rf_playbook", {"playbook_alert_id": "pb-1", "title": "PB Alert", "category": "domain_abuse"}
    )
    ev_s1 = normalize_unique_event(
        "s1_threat",
        {"id": "thr-1", "threatInfo": {"threatName": "Mimikatz"}, "agentRealtimeInfo": {"agentComputerName": "host1"}},
    )
    ev_es = normalize_unique_event(
        "splunk_es",
        {"event_id": "fnd-1", "rule_title": "Brute Force", "tenant_id": "1001"},
        scope="1001",
    )

    assert ev_rf.event_key.startswith("rf_alert::")
    assert ev_pb.event_key.startswith("rf_playbook::")
    assert ev_s1.event_key.startswith("s1_threat::")
    assert ev_es.event_key.startswith("splunk_es::")


@pytest.mark.feature("F7")
def test_tier1_f7_event_ai_store_upsert_and_mark_seen_batch(agentic_workspace: Path) -> None:
    from soclens.event_tracker import EventAIStore, normalize_unique_event

    store = EventAIStore()
    ev1 = normalize_unique_event("rf_alert", {"id": "a1", "title": "First"})
    ev2 = normalize_unique_event("rf_alert", {"id": "a2", "title": "Second"})

    assert store.upsert_event(ev1) is True
    assert store.upsert_event(ev1) is False

    unseen = store.mark_seen_batch([ev1, ev2])
    assert [e.event_key for e in unseen] == [ev2.event_key]
    assert store.mark_seen_batch([ev1, ev2]) == []


@pytest.mark.feature("F7")
def test_tier1_f7_attach_ai_response_persists_to_disk(agentic_workspace: Path) -> None:
    from soclens.agent_orchestrator import InvestigationResult
    from soclens.event_tracker import EventAIStore, normalize_unique_event

    store = EventAIStore()
    ev = normalize_unique_event("s1_threat", {"id": "thr-99", "title": "Ransomware"})
    result = InvestigationResult(
        run_id="run-99",
        event_key=ev.event_key,
        mode="full_investigation",
        provider="ollama",
        model="llama3.2:latest",
        question="Analyze threat",
        answer_markdown="Confirmed malicious binary.",
        tool_calls=[{"tool_name": "s1_list_threats"}],
        blocked_actions=[],
        status="completed",
        timestamp="2026-11-25T20:15:00Z",
    )
    entry = store.attach_ai_response(ev, result, auto_triggered=False)
    assert entry.run_id == "run-99"
    assert store.has_investigation(ev.event_key) is True

    panel_file = agentic_workspace / ".soclens_cache" / "event_ai_panels.json"
    assert panel_file.is_file()


@pytest.mark.feature("F7")
def test_tier1_f7_event_ai_store_reloads_panels_across_restart(agentic_workspace: Path) -> None:
    from soclens.agent_orchestrator import InvestigationResult
    from soclens.event_tracker import EventAIStore, normalize_unique_event

    ev = normalize_unique_event("rf_playbook", {"playbook_alert_id": "pb-7", "title": "Lookalike"})
    store1 = EventAIStore()
    store1.attach_ai_response(
        ev,
        InvestigationResult(
            run_id="run-pb-7",
            event_key=ev.event_key,
            mode="ask_only",
            provider="m365_copilot",
            model="M365 Copilot Chat",
            question="Summarize",
            answer_markdown="Lookalike domain targets login page.",
            tool_calls=[],
            blocked_actions=[],
            status="completed",
            timestamp="2026-11-25T20:16:00Z",
        ),
    )

    store2 = EventAIStore()
    assert store2.has_investigation(ev.event_key) is True
    panels = store2.get_panels(ev.event_key)
    assert len(panels) == 1
    assert "Lookalike domain" in panels[0].answer_markdown


# ==============================================================================
# F8: Background Triage Queue for Newly Flowing Events (5 tests)
# ==============================================================================


@pytest.mark.feature("F8")
def test_tier1_f8_background_triage_processes_unseen_event_when_enabled(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import AIPolicyStore
    from soclens.agent_tools import build_default_readonly_registry
    from soclens.event_tracker import BackgroundTriageQueue, EventAIStore, normalize_unique_event

    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    mock_agentic_llm_server.queue_scripted_turn(
        provider="ollama",
        content="Background triage summary: low false-positive risk.",
    )

    policy_store = AIPolicyStore()
    policy_store.update(background_triage_enabled=True)
    audit_store = AuditLogStore()
    event_store = EventAIStore()
    orch = SocAgentOrchestrator(
        registry=build_default_readonly_registry(),
        policy_store=policy_store,
        audit_store=audit_store,
    )
    done_evt = threading.Event()
    queue = BackgroundTriageQueue(
        orchestrator=orch,
        policy_store=policy_store,
        event_store=event_store,
        on_complete=lambda _ev, _res: done_evt.set(),
    )
    queue.start()
    try:
        ev = normalize_unique_event("rf_alert", {"id": "bg-alert-1", "title": "New C2 Hit"})
        queued = queue.enqueue_batch([ev])
        assert len(queued) == 1
        assert done_evt.wait(timeout=5.0)
        panels = event_store.get_panels(ev.event_key)
        assert len(panels) == 1
        assert panels[0].auto_triggered is True
    finally:
        queue.stop()


@pytest.mark.feature("F8")
def test_tier1_f8_background_triage_records_audit_entries(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import AIPolicyStore
    from soclens.agent_tools import build_default_readonly_registry
    from soclens.event_tracker import BackgroundTriageQueue, EventAIStore, normalize_unique_event

    mock_agentic_llm_server.configure_provider(monkeypatch, "openai")
    mock_agentic_llm_server.queue_scripted_turn(provider="openai", content="Auto triage done.")

    policy_store = AIPolicyStore()
    policy_store.update(background_triage_enabled=True)
    audit_store = AuditLogStore()
    event_store = EventAIStore()
    orch = SocAgentOrchestrator(
        registry=build_default_readonly_registry(),
        policy_store=policy_store,
        audit_store=audit_store,
    )
    done_evt = threading.Event()
    queue = BackgroundTriageQueue(
        orchestrator=orch,
        policy_store=policy_store,
        event_store=event_store,
        on_complete=lambda _ev, _res: done_evt.set(),
    )
    queue.start()
    try:
        ev = normalize_unique_event("s1_threat", {"id": "bg-thr-1", "title": "Suspicious Script"})
        queue.enqueue_batch([ev])
        assert done_evt.wait(timeout=5.0)
        entries = audit_store.query(event_key=ev.event_key)
        assert len(entries) >= 1
    finally:
        queue.stop()


@pytest.mark.feature("F8")
def test_tier1_f8_background_triage_non_blocking_for_caller(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import AIPolicyStore
    from soclens.agent_tools import build_default_readonly_registry
    from soclens.event_tracker import BackgroundTriageQueue, EventAIStore, normalize_unique_event

    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    mock_agentic_llm_server.queue_fault("/api/chat", 200, body={"model": "llama3.2:latest", "message": {"role": "assistant", "content": "Delayed ok"}, "done": True}, delay_seconds=0.2)

    policy_store = AIPolicyStore()
    policy_store.update(background_triage_enabled=True)
    event_store = EventAIStore()
    orch = SocAgentOrchestrator(
        registry=build_default_readonly_registry(),
        policy_store=policy_store,
        audit_store=AuditLogStore(),
    )
    done_evt = threading.Event()
    queue = BackgroundTriageQueue(
        orchestrator=orch,
        policy_store=policy_store,
        event_store=event_store,
        on_complete=lambda _ev, _res: done_evt.set(),
    )
    queue.start()
    try:
        import time

        t0 = time.perf_counter()
        ev = normalize_unique_event("rf_alert", {"id": "bg-async-1", "title": "Async Test"})
        queue.enqueue_batch([ev])
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.15, f"enqueue_batch blocked caller for {elapsed:.3f}s"
        assert done_evt.wait(timeout=5.0)
    finally:
        queue.stop()


@pytest.mark.feature("F8")
def test_tier1_f8_background_triage_multiple_events_in_batch(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import AIPolicyStore
    from soclens.agent_tools import build_default_readonly_registry
    from soclens.event_tracker import BackgroundTriageQueue, EventAIStore, normalize_unique_event

    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    policy_store = AIPolicyStore()
    policy_store.update(background_triage_enabled=True)
    event_store = EventAIStore()
    orch = SocAgentOrchestrator(
        registry=build_default_readonly_registry(),
        policy_store=policy_store,
        audit_store=AuditLogStore(),
    )
    completed: list[str] = []
    done_evt = threading.Event()

    def _on_done(ev: Any, _res: Any) -> None:
        completed.append(ev.event_key)
        if len(completed) >= 3:
            done_evt.set()

    queue = BackgroundTriageQueue(
        orchestrator=orch,
        policy_store=policy_store,
        event_store=event_store,
        on_complete=_on_done,
    )
    queue.start()
    try:
        events = [
            normalize_unique_event("rf_alert", {"id": "b1", "title": "One"}),
            normalize_unique_event("rf_playbook", {"playbook_alert_id": "b2", "title": "Two"}),
            normalize_unique_event("splunk_es", {"event_id": "b3", "rule_title": "Three"}, scope="1001"),
        ]
        queue.enqueue_batch(events)
        assert done_evt.wait(timeout=5.0)
        for ev in events:
            assert event_store.has_investigation(ev.event_key)
    finally:
        queue.stop()


@pytest.mark.feature("F8")
def test_tier1_f8_app_preloader_triggers_background_triage_when_enabled(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_policy import AIPolicyStore

    build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    AIPolicyStore().update(background_triage_enabled=True)

    app = make_agentic_app(agentic_workspace, initial_tab="tab-rf-intel", preload_alerts=True)

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await _mocks.async_wait_until(
                lambda: len(mock_agentic_llm_server.chat_requests()) >= 1,
                timeout=6.0,
                pilot=pilot,
            )
            assert len(app.event_ai_store.query_investigated_keys() if hasattr(app.event_ai_store, "query_investigated_keys") else mock_agentic_llm_server.chat_requests()) >= 1

    asyncio.run(_run())


# ==============================================================================
# F9: TUI Per-Event AI Panels, Buttons & Right-Click Actions (5 tests)
# ==============================================================================


@pytest.mark.feature("F9")
def test_tier1_f9_event_ai_panel_mounted_on_three_event_panes(
    agentic_workspace: Path,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
) -> None:
    from soclens.tui.ai_widgets import EventAIPanelWidget

    app = make_agentic_app(agentic_workspace, initial_tab="tab-rf-intel")

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            rf_pane = app.query_one("RFIntelPane")
            assert rf_pane.query_one(EventAIPanelWidget) is not None
            assert rf_pane.query_one("#btn-ai-ask-event") is not None
            assert rf_pane.query_one("#btn-ai-full-investigate") is not None

            await switch_tab_and_wait(app, pilot, "tab-sentinelone")
            s1_pane = app.query_one("SentinelOnePane")
            assert s1_pane.query_one(EventAIPanelWidget) is not None

            await switch_tab_and_wait(app, pilot, "tab-splunk-es")
            es_pane = app.query_one("SplunkESPane")
            assert es_pane.query_one(EventAIPanelWidget) is not None

    asyncio.run(_run())


@pytest.mark.feature("F9")
def test_tier1_f9_ask_event_button_and_modal_triggers_ask_only(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from textual.widgets import DataTable, Input

    from soclens.tui.ai_widgets import AskEventAIModal

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    mock_agentic_llm_server.queue_scripted_turn(
        provider="ollama",
        content="Ask-only reply: CVE-2024-3400 requires immediate perimeter check.",
    )

    app = make_agentic_app(agentic_workspace, initial_tab="tab-rf-intel")

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = app.query_one("#rf-results-table", DataTable)
            select_table_row_containing(table, seeded["cve_id"])
            await pilot.pause()

            await pilot.click("#btn-ai-ask-event")
            await pilot.pause()
            assert isinstance(app.screen, AskEventAIModal)
            app.screen.query_one("#ask-ai-input", Input).value = "Summarize this CVE alert"
            await pilot.click("#ask-ai-submit")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            reqs = mock_agentic_llm_server.chat_requests(provider="ollama")
            assert len(reqs) == 1
            assert reqs[0].get("tools") in (None, [])
            panels = app.event_ai_store.get_panels(f"rf_alert::{seeded['rf_alert_id']}")
            assert len(panels) == 1
            assert panels[0].mode == "ask_only"

    asyncio.run(_run())


@pytest.mark.feature("F9")
def test_tier1_f9_full_investigate_button_runs_cross_search(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from textual.widgets import DataTable

    from soclens.agent_policy import SOURCE_CATEGORY_RF

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "openai")

    app = make_agentic_app(agentic_workspace, initial_tab="tab-rf-intel")
    rf_tool = _find_tool(app.ai_tool_registry, SOURCE_CATEGORY_RF, "v2", "lookup")
    mock_agentic_llm_server.queue_scripted_turn(
        provider="openai",
        tool_calls=[{"name": rf_tool.name, "arguments": _default_args_for_tool(rf_tool, seeded)}],
    )
    mock_agentic_llm_server.queue_scripted_turn(
        provider="openai",
        content="Full investigation confirmed critical CVE risk 99.",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = app.query_one("#rf-results-table", DataTable)
            select_table_row_containing(table, seeded["cve_id"])
            await pilot.pause()

            await pilot.click("#btn-ai-full-investigate")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            panels = app.event_ai_store.get_panels(f"rf_alert::{seeded['rf_alert_id']}")
            assert len(panels) == 1
            assert panels[0].mode == "full_investigation"
            assert len(panels[0].tool_calls) >= 1

    asyncio.run(_run())


@pytest.mark.feature("F9")
def test_tier1_f9_right_click_table_row_surfaces_ai_actions(
    agentic_workspace: Path,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
) -> None:
    from textual.widgets import OptionList

    from soclens.tui.modals import ContextMenuModal

    build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    app = make_agentic_app(agentic_workspace, initial_tab="tab-rf-intel")

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            screen = await right_click_table_row(app, pilot, "#rf-results-table", row_index=0)
            assert isinstance(screen, ContextMenuModal)
            opts = screen.query_one("#ctx-menu-options", OptionList)
            prompts = [str(opts.get_option_at_index(i).prompt).lower() for i in range(opts.option_count)]
            assert any("ask" in p for p in prompts), f"Missing Ask AI option in {prompts}"
            assert any("full" in p or "investigat" in p for p in prompts), (
                f"Missing Full investigation option in {prompts}"
            )

    asyncio.run(_run())


@pytest.mark.feature("F9")
def test_tier1_f9_investigated_panel_restores_in_tui_after_restart(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from textual.widgets import DataTable, Input

    from soclens.tui.ai_widgets import AskEventAIModal

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    mock_agentic_llm_server.queue_scripted_turn(
        provider="ollama",
        content="Persisted-Marker-7741: Active C2 confirmed.",
    )

    app1 = make_agentic_app(agentic_workspace, initial_tab="tab-rf-intel")

    async def _run1() -> None:
        async with app1.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await app1.workers.wait_for_complete()
            await pilot.pause()
            select_table_row_containing(app1.query_one("#rf-results-table", DataTable), seeded["cve_id"])
            await pilot.pause()
            await pilot.click("#btn-ai-ask-event")
            await pilot.pause()
            assert isinstance(app1.screen, AskEventAIModal)
            app1.screen.query_one("#ask-ai-input", Input).value = "Check persistence"
            await pilot.click("#ask-ai-submit")
            await pilot.pause()
            await app1.workers.wait_for_complete()

    asyncio.run(_run1())

    app2 = make_agentic_app(agentic_workspace, initial_tab="tab-rf-intel")

    async def _run2() -> None:
        async with app2.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await app2.workers.wait_for_complete()
            await pilot.pause()
            select_table_row_containing(app2.query_one("#rf-results-table", DataTable), seeded["cve_id"])
            await pilot.pause()
            assert app2.event_ai_store.has_investigation(f"rf_alert::{seeded['rf_alert_id']}")
            panel = app2.query_one("RFIntelPane").query_one("EventAIPanelWidget")
            panel_text = "\n".join(line.text for line in panel.query_one("RichLog").lines)
            assert "Persisted-Marker-7741" in panel_text

    asyncio.run(_run2())


# ==============================================================================
# F10: TUI AI Control Panel & Audit Log View (5 tests)
# ==============================================================================


@pytest.mark.feature("F10")
def test_tier1_f10_llm_pane_exposes_subtabs(agentic_workspace: Path) -> None:
    from textual.widgets import TabbedContent

    app = make_agentic_app(agentic_workspace, initial_tab="tab-llm")

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            subtabs = app.query_one("#llm-subtabs", TabbedContent)
            assert subtabs.get_pane("llm-tab-chat") is not None
            assert subtabs.get_pane("llm-tab-control-panel") is not None
            assert subtabs.get_pane("llm-tab-audit-log") is not None

    asyncio.run(_run())


@pytest.mark.feature("F10")
def test_tier1_f10_control_panel_toggles_persist_to_policy_store(agentic_workspace: Path) -> None:
    from textual.widgets import Switch, TabbedContent

    from soclens.agent_policy import AIPolicyStore

    app = make_agentic_app(agentic_workspace, initial_tab="tab-llm")

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            subtabs = app.query_one("#llm-subtabs", TabbedContent)
            subtabs.active = "llm-tab-control-panel"
            await pilot.pause()

            bg_sw = app.query_one("#ai-ctrl-background-triage", Switch)
            spl_sw = app.query_one("#ai-ctrl-splunk-search", Switch)
            bg_sw.value = True
            spl_sw.value = False
            await pilot.pause()

            loaded = AIPolicyStore().load()
            assert loaded.background_triage_enabled is True
            assert loaded.splunk_search_enabled is False

    asyncio.run(_run())


@pytest.mark.feature("F10")
def test_tier1_f10_control_panel_reflects_persisted_policy_on_restart(agentic_workspace: Path) -> None:
    from textual.widgets import Switch, TabbedContent

    from soclens.agent_policy import AIPolicyStore

    AIPolicyStore().update(background_triage_enabled=True, sentinelone_enabled=False)
    app = make_agentic_app(agentic_workspace, initial_tab="tab-llm")

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app.query_one("#llm-subtabs", TabbedContent).active = "llm-tab-control-panel"
            await pilot.pause()

            assert app.query_one("#ai-ctrl-background-triage", Switch).value is True
            assert app.query_one("#ai-ctrl-sentinelone", Switch).value is False
            assert app.query_one("#ai-ctrl-cross-search", Switch).value is True

    asyncio.run(_run())


@pytest.mark.feature("F10")
def test_tier1_f10_audit_log_view_displays_recorded_entries(agentic_workspace: Path) -> None:
    from textual.widgets import DataTable, TabbedContent

    from soclens.agent_audit import AuditEntry, AuditLogStore

    store = AuditLogStore()
    store.append(
        AuditEntry(
            entry_id="tui-aud-1",
            timestamp="2026-11-25T20:20:00Z",
            run_id="run-tui-1",
            event_key="rf_alert::a-1",
            provider="ollama",
            mode="full_investigation",
            event_type="tool_call",
            tool_name="rf_v2_lookup",
            allowed=True,
        )
    )

    app = make_agentic_app(agentic_workspace, initial_tab="tab-llm")

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app.query_one("#llm-subtabs", TabbedContent).active = "llm-tab-audit-log"
            await pilot.pause()
            await pilot.click("#ai-audit-refresh")
            await pilot.pause()

            table = app.query_one("#ai-audit-table", DataTable)
            assert table.row_count >= 1

    asyncio.run(_run())


@pytest.mark.feature("F10")
def test_tier1_f10_audit_log_filter_blocked_shows_only_blocked(agentic_workspace: Path) -> None:
    from textual.widgets import DataTable, Switch, TabbedContent

    from soclens.agent_audit import AuditEntry, AuditLogStore

    store = AuditLogStore()
    store.append(
        AuditEntry(
            entry_id="aud-ok",
            timestamp="2026-11-25T20:21:00Z",
            run_id="r-filt",
            event_key="rf_alert::a-1",
            provider="ollama",
            mode="full_investigation",
            event_type="tool_call",
            tool_name="rf_v2_lookup",
            allowed=True,
        )
    )
    store.append(
        AuditEntry(
            entry_id="aud-blk",
            timestamp="2026-11-25T20:21:01Z",
            run_id="r-filt",
            event_key="rf_alert::a-1",
            provider="ollama",
            mode="full_investigation",
            event_type="blocked_action",
            tool_name="splunk_run_search",
            allowed=False,
            reason="splunk_search_disabled",
        )
    )

    app = make_agentic_app(agentic_workspace, initial_tab="tab-llm")

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app.query_one("#llm-subtabs", TabbedContent).active = "llm-tab-audit-log"
            await pilot.pause()
            await pilot.click("#ai-audit-refresh")
            await pilot.pause()

            table = app.query_one("#ai-audit-table", DataTable)
            assert table.row_count == 2

            # Toggle blocked-only filter (handles Switch or Checkbox/Button via Switch value)
            filt = app.query_one("#ai-audit-filter-blocked")
            if isinstance(filt, Switch):
                filt.value = True
            else:
                await pilot.click("#ai-audit-filter-blocked")
            await pilot.pause()
            assert table.row_count == 1
            # Verify richlog_text helper is exercised cleanly if detail widget is populated
            _ = richlog_text(app, "#ai-audit-detail")

    asyncio.run(_run())
