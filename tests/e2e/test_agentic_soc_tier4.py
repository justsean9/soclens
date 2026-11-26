"""Tier 4 E2E full real-world SOC analyst scenarios for soclens-agentic-soc."""

from __future__ import annotations

import asyncio
import json
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
    async_wait_until,
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

pytestmark = [pytest.mark.e2e, pytest.mark.tier4]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DESIGN_DOC_PATH = _REPO_ROOT / "docs" / "AGENTIC_SOC_ARCHITECTURE.md"


def _find_tool(registry: Any, category: str, *keywords: str) -> Any:
    candidates = [t for t in registry.list_tools() if t.source_category == category]
    assert candidates, f"Expected registered tool in {category!r}"
    for kw in keywords:
        low = kw.lower()
        for tool in candidates:
            if low in tool.name.lower() or low in tool.description.lower():
                return tool
    return candidates[0]


# ==============================================================================
# Scenario 1: RF CVE-2024-3400 Cross-Source Hunt & App Restart
# ==============================================================================


@pytest.mark.feature("F2")
@pytest.mark.feature("F4")
@pytest.mark.feature("F5")
@pytest.mark.feature("F6")
@pytest.mark.feature("F7")
@pytest.mark.feature("F9")
@pytest.mark.feature("F10")
def test_tier4_scenario1_rf_cve_cross_source_hunt_and_app_restart(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_osint_server: MockOSINTServer,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from textual.widgets import DataTable, TabbedContent

    from soclens.agent_policy import (
        SOURCE_CATEGORY_OSINT,
        SOURCE_CATEGORY_RF,
        SOURCE_CATEGORY_S1,
        SOURCE_CATEGORY_SPLUNK,
        SOURCE_CATEGORY_SPLUNK_ES,
    )

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "openai")
    osint_client = mock_osint_server.make_client(workspace_dir=agentic_workspace)

    app1 = make_agentic_app(
        agentic_workspace, initial_tab="tab-rf-intel", osint_client=osint_client
    )
    rf_tool = _find_tool(app1.ai_tool_registry, SOURCE_CATEGORY_RF, "v2", "lookup")
    spl_tool = _find_tool(app1.ai_tool_registry, SOURCE_CATEGORY_SPLUNK, "search", "spl")
    es_tool = _find_tool(app1.ai_tool_registry, SOURCE_CATEGORY_SPLUNK_ES, "notable", "finding")
    s1_tool = _find_tool(app1.ai_tool_registry, SOURCE_CATEGORY_S1, "threat", "list")
    osint_tool = _find_tool(app1.ai_tool_registry, SOURCE_CATEGORY_OSINT, "osint", "vuln", "enrich")

    mock_agentic_llm_server.queue_scripted_turn(
        provider="openai",
        tool_calls=[
            {"name": rf_tool.name, "arguments": {"entity_type": "vulnerability", "value": seeded["cve_id"]}},
            {"name": spl_tool.name, "arguments": {"spl": f'search src="{seeded["ip"]}" | head 10'}},
        ],
    )
    mock_agentic_llm_server.queue_scripted_turn(
        provider="openai",
        tool_calls=[
            {"name": es_tool.name, "arguments": {"limit": 5}},
            {"name": s1_tool.name, "arguments": {"limit": 5}},
            {"name": osint_tool.name, "arguments": {"target": seeded["cve_id"], "kind": "vulnerability"}},
        ],
    )
    mock_agentic_llm_server.queue_scripted_turn(
        provider="openai",
        content=(
            f"Correlated Hunt Report [T4-S1]: {seeded['cve_id']} actively exploited from "
            f"{seeded['ip']} targeting {seeded['hostname']}."
        ),
    )

    async def _session1() -> None:
        async with app1.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await app1.workers.wait_for_complete()
            await pilot.pause()
            select_table_row_containing(
                app1.query_one("#rf-results-table", DataTable), seeded["cve_id"]
            )
            await pilot.pause()
            await pilot.click("#btn-ai-full-investigate")
            await pilot.pause()
            await app1.workers.wait_for_complete()
            await pilot.pause()

    asyncio.run(_session1())

    # Relaunch SocLensApp on the same workspace_dir -> panel and redacted audit log restore
    app2 = make_agentic_app(
        agentic_workspace, initial_tab="tab-rf-intel", osint_client=osint_client
    )

    async def _session2() -> None:
        async with app2.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await app2.workers.wait_for_complete()
            await pilot.pause()
            select_table_row_containing(
                app2.query_one("#rf-results-table", DataTable), seeded["cve_id"]
            )
            await pilot.pause()
            panel = app2.query_one("RFIntelPane").query_one("EventAIPanelWidget")
            panel_text = "\n".join(line.text for line in panel.query_one("RichLog").lines)
            assert "T4-S1" in panel_text

            await switch_tab_and_wait(app2, pilot, "tab-llm")
            app2.query_one("#llm-subtabs", TabbedContent).active = "llm-tab-audit-log"
            await pilot.pause()
            await pilot.click("#ai-audit-refresh")
            await pilot.pause()
            assert app2.query_one("#ai-audit-table", DataTable).row_count >= 5

    asyncio.run(_session2())
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server, s1_server=mock_s1_server, es_server=mock_splunk_es_server
    )


# ==============================================================================
# Scenario 2: SOC Shift Handoff — Multi-Stream Right-Click Q&A + Full Investigation
# ==============================================================================


@pytest.mark.feature("F5")
@pytest.mark.feature("F6")
@pytest.mark.feature("F7")
@pytest.mark.feature("F9")
def test_tier4_scenario2_multi_stream_right_click_qa_and_full_investigation(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from textual.widgets import DataTable, Input, OptionList

    from soclens.agent_policy import SOURCE_CATEGORY_RF
    from soclens.tui.ai_widgets import AskEventAIModal
    from soclens.tui.modals import ContextMenuModal

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    app = make_agentic_app(agentic_workspace, initial_tab="tab-rf-intel")
    rf_tool = _find_tool(app.ai_tool_registry, SOURCE_CATEGORY_RF, "v2", "lookup")

    async def _pick_ctx_option(pilot: Any, keyword: str) -> None:
        assert isinstance(app.screen, ContextMenuModal)
        opts = app.screen.query_one("#ctx-menu-options", OptionList)
        idx = next(
            i
            for i in range(opts.option_count)
            if keyword in str(opts.get_option_at_index(i).prompt).lower()
        )
        opts.highlighted = idx
        await pilot.press("enter")
        await pilot.pause()

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()

            # 1. RF Playbook Alert: right-click ask_only -> right-click full_investigation
            await pilot.click("#rf-pb-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            pb_row = select_table_row_containing(
                app.query_one("#rf-results-table", DataTable), "Lookalike"
            )
            mock_agentic_llm_server.queue_scripted_turn(
                provider="ollama", content="PB AskOnly answer."
            )
            await right_click_table_row(app, pilot, "#rf-results-table", row_index=pb_row)
            await _pick_ctx_option(pilot, "ask")
            if isinstance(app.screen, AskEventAIModal):
                app.screen.query_one("#ask-ai-input", Input).value = "Is domain spoofed?"
                await pilot.click("#ask-ai-submit")
            await app.workers.wait_for_complete()
            await pilot.pause()

            mock_agentic_llm_server.queue_scripted_turn(
                provider="ollama",
                tool_calls=[{"name": rf_tool.name, "arguments": {"entity_type": "ip", "value": seeded["ip"]}}],
            )
            mock_agentic_llm_server.queue_scripted_turn(
                provider="ollama", content="PB FullInv correlated."
            )
            await right_click_table_row(app, pilot, "#rf-results-table", row_index=pb_row)
            await _pick_ctx_option(pilot, "full")
            await app.workers.wait_for_complete()
            await pilot.pause()
            rf_panel = app.query_one("RFIntelPane").query_one("EventAIPanelWidget")
            assert "PB FullInv correlated." in "\n".join(
                line.text for line in rf_panel.query_one("RichLog").lines
            )

            # 2. SentinelOne Threat: right-click ask_only + full_investigation button
            await switch_tab_and_wait(app, pilot, "tab-sentinelone")
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_agentic_llm_server.queue_scripted_turn(provider="ollama", content="S1 AskOnly.")
            s1_row = select_table_row_containing(
                app.query_one("#s1-table", DataTable), "srv-1001-db"
            )
            await right_click_table_row(app, pilot, "#s1-table", row_index=s1_row)
            await _pick_ctx_option(pilot, "ask")
            if isinstance(app.screen, AskEventAIModal):
                app.screen.query_one("#ask-ai-input", Input).value = "Explain process."
                await pilot.click("#ask-ai-submit")
            await app.workers.wait_for_complete()
            await pilot.pause()

            mock_agentic_llm_server.queue_scripted_turn(
                provider="ollama",
                tool_calls=[{"name": rf_tool.name, "arguments": {"entity_type": "ip", "value": seeded["ip"]}}],
            )
            mock_agentic_llm_server.queue_scripted_turn(provider="ollama", content="S1 FullInv.")
            await pilot.click("SentinelOnePane #btn-ai-full-investigate")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1_panel = app.query_one("SentinelOnePane").query_one("EventAIPanelWidget")
            assert "S1 FullInv." in "\n".join(
                line.text for line in s1_panel.query_one("RichLog").lines
            )

            # 3. Splunk ES Notable: right-click ask_only + full_investigation button
            await switch_tab_and_wait(app, pilot, "tab-splunk-es")
            await pilot.click("#es-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_agentic_llm_server.queue_scripted_turn(provider="ollama", content="ES AskOnly.")
            es_row = select_table_row_containing(
                app.query_one("#es-table", DataTable), "LSASS Memory Access"
            )
            await right_click_table_row(app, pilot, "#es-table", row_index=es_row)
            await _pick_ctx_option(pilot, "ask")
            if isinstance(app.screen, AskEventAIModal):
                app.screen.query_one("#ask-ai-input", Input).value = "Summarize notable."
                await pilot.click("#ask-ai-submit")
            await app.workers.wait_for_complete()
            await pilot.pause()

            mock_agentic_llm_server.queue_scripted_turn(provider="ollama", content="ES FullInv.")
            await pilot.click("SplunkESPane #btn-ai-full-investigate")
            await app.workers.wait_for_complete()
            await pilot.pause()
            es_panel = app.query_one("SplunkESPane").query_one("EventAIPanelWidget")
            assert "ES FullInv." in "\n".join(
                line.text for line in es_panel.query_one("RichLog").lines
            )

            assert len(app.event_ai_store.get_panels(f"rf_playbook::{seeded['rf_playbook_id']}")) == 2
            assert len(app.event_ai_store.get_panels(f"s1_threat::{seeded['s1_threat_id']}")) == 2
            assert len(app.event_ai_store.get_panels(f"splunk_es::1001::{seeded['es_event_id']}")) == 2

    asyncio.run(_run())
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server, s1_server=mock_s1_server, es_server=mock_splunk_es_server
    )


# ==============================================================================
# Scenario 3: Live Preloader Background Triage & Non-Stalling TUI
# ==============================================================================


@pytest.mark.feature("F3")
@pytest.mark.feature("F4")
@pytest.mark.feature("F7")
@pytest.mark.feature("F8")
@pytest.mark.feature("F9")
@pytest.mark.feature("F10")
def test_tier4_scenario3_live_preloader_background_triage_non_stalling_tui(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from textual.widgets import DataTable, Switch, TabbedContent

    from soclens.agent_policy import AIPolicyStore

    build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "ollama")
    AIPolicyStore().update(background_triage_enabled=True)

    app = make_agentic_app(agentic_workspace, initial_tab="tab-llm", preload_alerts=True)

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app.query_one("#llm-subtabs", TabbedContent).active = "llm-tab-control-panel"
            await pilot.pause()
            assert app.query_one("#ai-ctrl-background-triage", Switch).value is True

            # Navigate tabs smoothly while preloader & background triage execute
            await switch_tab_and_wait(app, pilot, "tab-rf-intel")
            await switch_tab_and_wait(app, pilot, "tab-sentinelone")
            await switch_tab_and_wait(app, pilot, "tab-splunk-es")
            await app.workers.wait_for_complete()

            await async_wait_until(
                lambda: len(mock_agentic_llm_server.chat_requests()) >= 1,
                timeout=8.0,
                pilot=pilot,
            )

            await switch_tab_and_wait(app, pilot, "tab-llm")
            app.query_one("#llm-subtabs", TabbedContent).active = "llm-tab-audit-log"
            await pilot.pause()
            await pilot.click("#ai-audit-refresh")
            await pilot.pause()
            assert app.query_one("#ai-audit-table", DataTable).row_count >= 1

    asyncio.run(_run())
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server, s1_server=mock_s1_server, es_server=mock_splunk_es_server
    )


# ==============================================================================
# Scenario 4: Policy Lockdown & Prompt-Injection Containment
# ==============================================================================


@pytest.mark.feature("F2")
@pytest.mark.feature("F3")
@pytest.mark.feature("F4")
@pytest.mark.feature("F5")
@pytest.mark.feature("F6")
@pytest.mark.feature("F10")
def test_tier4_scenario4_policy_lockdown_and_prompt_injection_containment(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from textual.widgets import DataTable, Switch, TabbedContent

    from soclens.agent_policy import SOURCE_CATEGORY_S1, SOURCE_CATEGORY_SPLUNK

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    mock_agentic_llm_server.configure_provider(monkeypatch, "m365_copilot")
    app = make_agentic_app(agentic_workspace, initial_tab="tab-llm")

    spl_tool = _find_tool(app.ai_tool_registry, SOURCE_CATEGORY_SPLUNK, "search", "spl")
    s1_tool = _find_tool(app.ai_tool_registry, SOURCE_CATEGORY_S1, "threat", "list")

    # Malicious prompt-injection sequence: SPL exfil + mutating S1 + disabled S1 read
    mock_agentic_llm_server.queue_scripted_turn(
        provider="m365_copilot",
        tool_calls=[
            {"name": spl_tool.name, "arguments": {"spl": "index=main | outputlookup exfil.csv"}},
            {"name": "mitigate_threat", "arguments": {"threat_id": seeded["s1_threat_id"]}},
            {"name": s1_tool.name, "arguments": {"limit": 5}},
        ],
    )
    mock_agentic_llm_server.queue_scripted_turn(
        provider="m365_copilot",
        content="All dangerous or policy-disabled actions were contained.",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app.query_one("#llm-subtabs", TabbedContent).active = "llm-tab-control-panel"
            await pilot.pause()
            app.query_one("#ai-ctrl-splunk-search", Switch).value = False
            app.query_one("#ai-ctrl-sentinelone", Switch).value = False
            await pilot.pause()

            await switch_tab_and_wait(app, pilot, "tab-rf-intel")
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            select_table_row_containing(
                app.query_one("#rf-results-table", DataTable), seeded["cve_id"]
            )
            await pilot.pause()
            await pilot.click("#btn-ai-full-investigate")
            await app.workers.wait_for_complete()
            await pilot.pause()

            await switch_tab_and_wait(app, pilot, "tab-llm")
            app.query_one("#llm-subtabs", TabbedContent).active = "llm-tab-audit-log"
            await pilot.pause()
            await pilot.click("#ai-audit-refresh")
            await pilot.pause()

            filt = app.query_one("#ai-audit-filter-blocked")
            if isinstance(filt, Switch):
                filt.value = True
            else:
                await pilot.click("#ai-audit-filter-blocked")
            await pilot.pause()
            table = app.query_one("#ai-audit-table", DataTable)
            assert table.row_count >= 2
            table.move_cursor(row=0)
            table.action_select_cursor()
            await pilot.pause()
            assert richlog_text(app, "#ai-audit-detail").strip()

    asyncio.run(_run())
    assert [r for r in mock_splunk_es_server.requests_log if r["path"].endswith("/search/jobs")] == []
    assert mock_s1_server.requests_log == []
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server, s1_server=mock_s1_server, es_server=mock_splunk_es_server
    )


# ==============================================================================
# Scenario 5: Enterprise Microsoft Copilot Multi-Provider Rotation
# ==============================================================================


@pytest.mark.feature("F4")
@pytest.mark.feature("F5")
@pytest.mark.feature("F6")
@pytest.mark.feature("F7")
def test_tier4_scenario5_enterprise_microsoft_copilot_provider_rotation(
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
    from soclens.event_tracker import EventAIStore, normalize_unique_event

    seeded = build_correlated_soc_scenario(mock_rf_server, mock_splunk_es_server, mock_s1_server)
    canary_token = "e2e-enterprise-canary-secret-token-4455"
    registry = build_default_readonly_registry()
    rf_tool = _find_tool(registry, SOURCE_CATEGORY_RF, "v2", "lookup")
    policy_store = AIPolicyStore()
    audit_store = AuditLogStore()
    event_store = EventAIStore()
    orch = SocAgentOrchestrator(
        registry=registry,
        policy_store=policy_store,
        audit_store=audit_store,
        llm_client_factory=lambda: LocalLLMClient(get_local_llm_config()),
    )

    ev = normalize_unique_event("rf_alert", {"id": seeded["rf_alert_id"], "title": "Copilot Rotation"})
    copilot_providers = (
        "m365_copilot",
        "copilot_studio",
        "copilot_directline",
        "security_copilot",
    )
    for prov in copilot_providers:
        mock_agentic_llm_server.configure_provider(monkeypatch, prov, token=canary_token)
        mock_agentic_llm_server.queue_scripted_turn(
            provider=prov,
            tool_calls=[{"name": rf_tool.name, "arguments": {"entity_type": "ip", "value": seeded["ip"]}}],
        )
        mock_agentic_llm_server.queue_scripted_turn(
            provider=prov,
            content=f"{prov}: IP {seeded['ip']} risk 89 confirmed.",
        )
        res = orch.investigate(
            event_key=ev.event_key,
            event_context=f"Check {seeded['ip']} (auth={canary_token})",
            mode="full_investigation",
            provider=prov,
        )
        assert res.status == "completed"
        assert len(res.tool_calls) == 1
        event_store.attach_ai_response(ev, res)

    reloaded_panels = EventAIStore().get_panels(ev.event_key)
    assert [p.provider for p in reloaded_panels] == list(copilot_providers)
    raw_audit = (agentic_workspace / ".soclens_cache" / "ai_audit.jsonl").read_text(encoding="utf-8")
    assert canary_token not in raw_audit
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server, s1_server=mock_s1_server, es_server=mock_splunk_es_server
    )


# ==============================================================================
# Scenario 6: Architecture & Governance End-to-End Compliance Audit
# ==============================================================================


@pytest.mark.feature("F1")
@pytest.mark.feature("F2")
@pytest.mark.feature("F3")
@pytest.mark.feature("F4")
@pytest.mark.feature("F7")
def test_tier4_scenario6_architecture_and_governance_compliance_audit(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_rf_server: Any,
    mock_splunk_es_server: Any,
    mock_s1_server: Any,
    mock_agentic_llm_server: MockAgenticLLMAndCopilotServer,
) -> None:
    from soclens.agent_audit import AuditLogStore
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import AIPolicyStore
    from soclens.agent_tools import FORBIDDEN_MUTATING_METHOD_NAMES, build_default_readonly_registry
    from soclens.event_tracker import EventAIStore, normalize_unique_event

    assert _DESIGN_DOC_PATH.is_file()
    doc_text = _DESIGN_DOC_PATH.read_text(encoding="utf-8")
    assert len(doc_text.strip()) >= 800

    registry = build_default_readonly_registry()
    tools = registry.list_tools()
    assert tools
    assert all(t.readonly is True for t in tools)
    assert not ({t.name for t in tools} & FORBIDDEN_MUTATING_METHOD_NAMES)

    secret_canary = "sk-compliance-canary-009988"
    mock_agentic_llm_server.configure_provider(monkeypatch, "openai", api_key=secret_canary)
    mock_agentic_llm_server.queue_scripted_turn(
        provider="openai", content="Governance compliance check completed."
    )

    policy_store = AIPolicyStore()
    policy_store.update(background_triage_enabled=False, splunk_search_enabled=True)
    audit_store = AuditLogStore()
    event_store = EventAIStore()

    ev = normalize_unique_event("rf_alert", {"id": "comp-1", "title": "Compliance Alert"})
    orch = SocAgentOrchestrator(registry=registry, policy_store=policy_store, audit_store=audit_store)
    res = orch.investigate(
        event_key=ev.event_key,
        event_context=f"Payload with Bearer {secret_canary}",
        mode="ask_only",
        question="Verify compliance",
    )
    event_store.attach_ai_response(ev, res)

    cache_dir = agentic_workspace / ".soclens_cache"
    for fname in ("ai_policy.json", "ai_audit.jsonl", "event_ai_panels.json"):
        fpath = cache_dir / fname
        assert fpath.is_file(), f"Expected persistence file {fpath}"
        content = fpath.read_text(encoding="utf-8")
        assert secret_canary not in content, f"Secret canary leaked in {fname}!"

    # Validate JSON integrity of ai_policy.json and event_ai_panels.json
    json.loads((cache_dir / "ai_policy.json").read_text(encoding="utf-8"))
    json.loads((cache_dir / "event_ai_panels.json").read_text(encoding="utf-8"))
    assert_zero_mutating_http_requests(
        rf_server=mock_rf_server, s1_server=mock_s1_server, es_server=mock_splunk_es_server
    )
