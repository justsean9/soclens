"""Comprehensive Textual Pilot unit and integration tests for Milestone M4 Agentic SOC TUI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    DataTable,
    Input,
    OptionList,
    RichLog,
    Select,
    Static,
    Switch,
    TabbedContent,
)

from soclens.agent_audit import AuditEntry
from soclens.agent_orchestrator import InvestigationResult
from soclens.alert_cache import (
    CACHE_SOURCE_ES,
    CACHE_SOURCE_RF,
    CACHE_SOURCE_RF_PLAYBOOK,
    CACHE_SOURCE_S1,
)
from soclens.event_tracker import normalize_unique_event
from soclens.tui.ai_widgets import (
    AIControlPanelWidget,
    AskEventAIModal,
    AuditLogViewWidget,
    EventAIPanelWidget,
)
from soclens.tui.app import create_app
from soclens.tui.modals import ContextMenuModal
from soclens.tui.rf_formatters import normalize_alert_v3, normalize_playbook_alert
from soclens.tui.screens.llm import LocalLLMPane
from soclens.tui.screens.rf_intel import RFIntelPane
from soclens.tui.screens.sentinelone import SentinelOnePane
from soclens.tui.screens.splunk_es import SplunkESPane


def _richlog_text(log: RichLog) -> str:
    return "\n".join(str(line.text) for line in log.lines)


def _make_rf_alert(alert_id: str = "rf-alert-1", title: str = "Suspicious C2 IP") -> dict[str, Any]:
    return normalize_alert_v3(
        {
            "id": alert_id,
            "title": title,
            "priority": "High",
            "statusInPortal": "New",
            "rule": {"id": "rule-c2", "name": "C2 Communication"},
            "type": "ip_alert",
            "entities": [{"entity": {"id": "ip:198.51.100.42", "name": "198.51.100.42"}}],
            "hits": [{"document_id": "doc-1"}],
            "triggered": "2026-11-26T00:00:00Z",
        }
    )


def _make_rf_playbook(pb_id: str = "pb-alert-1", title: str = "Lookalike Domain") -> dict[str, Any]:
    return normalize_playbook_alert(
        {
            "playbook_alert_id": pb_id,
            "category": "domain_abuse",
            "title": title,
            "panel_status": {
                "priority": "High",
                "status": "New",
                "entity_name": "evil-soclens.example",
                "updated": "2026-11-26T00:00:00Z",
            },
            "panel_evidence_summary": {"targets": ["evil-soclens.example"]},
        }
    )


def _make_s1_threat(threat_id: str = "s1-thr-1", name: str = "Trojan.Generic") -> dict[str, Any]:
    return {
        "id": threat_id,
        "threatInfo": {
            "threatId": threat_id,
            "threatName": name,
            "classification": "Malware",
            "confidenceLevel": "malicious",
            "incidentStatus": "unresolved",
            "mitigationStatus": "active",
            "sha1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
            "createdAt": "2026-11-26T00:00:00Z",
        },
        "agentRealtimeInfo": {
            "agentComputerName": "FIN-WKSTN-07",
            "siteId": "site-1",
            "siteName": "MDR-ACME",
        },
    }


def _make_s1_cloud_alert(alert_id: str = "s1-cld-1", name: str = "Cloud STAR Rule") -> dict[str, Any]:
    return {
        "id": alert_id,
        "source_kind": "s1_cloud_alert",
        "alertInfo": {
            "alertId": alert_id,
            "ruleName": name,
            "incidentStatus": "UNRESOLVED",
            "createdAt": "2026-11-26T00:00:00Z",
        },
        "ruleInfo": {"name": name, "severity": "High"},
        "agentDetectionInfo": {
            "agentComputerName": "CLOUD-VM-01",
            "siteId": "site-2",
            "siteName": "MDR-CLOUD",
        },
    }


def _make_es_notable(
    event_id: str = "fnd-1001-a",
    tenant_id: str = "1001",
    title: str = "Brute Force Detected",
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "finding_id": event_id,
        "tenant_id": tenant_id,
        "rule_title": title,
        "rule_name": title,
        "title": title,
        "urgency": "high",
        "status_label": "New",
        "owner": "unassigned",
        "risk_object": "srv-auth-01",
        "risk_score": 80,
        "_time": "2026-11-26T00:00:00Z",
    }


class _FakeLLMClient:
    """Fake LLM client driving ask_only (0 tools) and full_investigation (cross-search)."""

    def __init__(self, *, provider: str = "openai", model: str = "gpt-4o-mini") -> None:
        self.provider = provider
        self.model = model
        self.config = MagicMock(
            provider=provider,
            model=model,
            base_url="https://mock.llm.local/v1",
            timeout=10.0,
            verify_ssl=True,
            temperature=0.0,
            max_tokens=512,
            api_key="",
            ms_auth_mode="token",
            ms_bearer_token="",
            ms_graph_base_url="",
            ms_web_grounding=False,
            ms_directline_url="",
            ms_token_endpoint="",
        )
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str | None = None,
        system_prompt: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        _ = kwargs
        return self.chat_turn(
            messages,
            tools=tools,
            system_prompt=system_prompt,
            model=model,
        )

    def chat_turn(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
        model: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        _ = kwargs
        call_idx = len(self.calls)
        self.calls.append({"messages": messages, "tools": tools, "system_prompt": system_prompt})
        has_tool_result = any(m.get("role") == "tool" for m in messages)
        if tools and not has_tool_result:
            return {
                "content": "",
                "model": model or self.model,
                "provider": self.provider,
                "tool_calls": [
                    {
                        "id": f"call_{call_idx + 1}",
                        "name": "osint_enrich_target",
                        "arguments": {"target": "evil-soclens.example"},
                    }
                ],
                "raw": {},
            }
        mode_hint = "Full cross-source verdict" if tools else "Event-only answer"
        return {
            "content": f"{mode_hint} for run #{call_idx + 1}: corroborated indicators.",
            "model": model or self.model,
            "provider": self.provider,
            "tool_calls": [],
            "raw": {},
        }

    def close(self) -> None:
        return None


def test_app_eager_agentic_init_and_clean_shutdown(tmp_path: Path) -> None:
    osint_mock = MagicMock()
    app = create_app(
        client=MagicMock(),
        s1_client=MagicMock(),
        osint_client=osint_mock,
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )
    assert app.ai_policy_store.path == tmp_path / ".soclens_cache" / "ai_policy.json"
    assert app.ai_audit_store.path == tmp_path / ".soclens_cache" / "ai_audit.jsonl"
    assert app.event_ai_store.path == tmp_path / ".soclens_cache" / "event_ai_panels.json"
    assert len(app.ai_tool_registry.list_tools()) >= 20
    assert app.ai_orchestrator is not None
    assert app.background_triage_queue is not None

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            worker = app.background_triage_queue._worker
            assert worker is not None and worker.is_alive()
        assert app.background_triage_queue._stopped is True

    asyncio.run(_run())


def test_all_four_streams_ask_only_and_full_investigation_and_isolation(tmp_path: Path) -> None:
    fake_llm = _FakeLLMClient()
    fake_osint = MagicMock()
    fake_osint.enrich_target.return_value = {"dns": {"domain": "evil-soclens.example"}}

    app = create_app(
        client=MagicMock(),
        s1_client=MagicMock(),
        osint_client=fake_osint,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )
    app.llm_client = fake_llm

    rf_alert = _make_rf_alert("rf-a-1", "C2 Beaconing")
    rf_alert_2 = _make_rf_alert("rf-a-2", "Second RF Alert")
    rf_pb = _make_rf_playbook("pb-1", "Brand Lookalike")
    s1_thr = _make_s1_threat("thr-1", "Mimikatz.Exec")
    s1_cld = _make_s1_cloud_alert("cld-1", "AWS IAM Escalation")
    es_not = _make_es_notable("es-1", "1001", "Brute Force Login")

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()

            # 1. RF Alerts v3: ask_only via panel button -> 0 external tools, panel displays reply
            rf_pane = app.query_one(RFIntelPane)
            rf_pane._datasets["alerts_v3"] = [rf_alert, rf_alert_2]
            rf_pane._active_mode = "alerts_v3"
            rf_pane._render_view(schedule_auto_enrich=False)
            await pilot.pause()

            rf_panel = rf_pane.query_one("#rf-ai-panel", EventAIPanelWidget)
            assert rf_panel.current_event_key == "rf_alert::rf-a-1"
            await pilot.click("#rf-ai-panel #btn-ai-ask-event")
            await pilot.pause()
            assert isinstance(app.screen, AskEventAIModal)
            app.screen.query_one("#ask-ai-input", Input).value = "Summarize this alert"
            await pilot.click("#ask-ai-submit")
            await app.workers.wait_for_complete()
            await pilot.pause()

            rf_log = _richlog_text(rf_panel.query_one(RichLog))
            assert "Event-only answer" in rf_log
            assert fake_osint.enrich_target.call_count == 0

            # Switching to second RF alert clears the first alert's AI text
            rf_table = rf_pane.query_one("#rf-results-table", DataTable)
            rf_table.move_cursor(row=1)
            await pilot.pause()
            assert rf_panel.current_event_key == "rf_alert::rf-a-2"
            assert "Event-only answer" not in _richlog_text(rf_panel.query_one(RichLog))

            # 2. RF Playbook Alert: right-click col 0 -> Full AI Investigation
            rf_pane._datasets["playbook"] = [rf_pb]
            rf_pane._active_mode = "playbook"
            rf_pane._render_view(schedule_auto_enrich=False)
            await pilot.pause()
            header_rows = int(getattr(rf_table, "header_height", 1) or 1)
            await pilot.click("#rf-results-table", offset=(4, 1 + header_rows), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            opts = app.screen.query_one("#ctx-menu-options", OptionList)
            prompts = [str(opts.get_option_at_index(i).prompt) for i in range(opts.option_count)]
            full_idx = next(i for i, p in enumerate(prompts) if "Full AI Investigation" in p)
            opts.highlighted = full_idx
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert rf_panel.current_event_key == "rf_playbook::pb-1"
            assert "Full cross-source verdict" in _richlog_text(rf_panel.query_one(RichLog))
            assert fake_osint.enrich_target.call_count >= 1

            # 3. SentinelOne Threat & Cloud Alert: [m] shortcut + right-click col 0
            app.activate_tab("tab-sentinelone")
            await pilot.pause()
            await app.ensure_tab_mounted("tab-sentinelone")
            await pilot.pause()
            s1_pane = app.query_one(SentinelOnePane)
            s1_pane._current_view = "threats"
            s1_pane._records = [s1_thr, s1_cld]
            s1_pane._apply_local_filter()
            await pilot.pause()

            s1_panel = s1_pane.query_one("#s1-ai-panel", EventAIPanelWidget)
            assert s1_panel.current_event_key is not None
            s1_table = s1_pane.query_one("#s1-table", DataTable)
            s1_table.focus()
            await pilot.pause()
            await pilot.press("m")
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            app.screen.dismiss("ai_full_investigate")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert "Full cross-source verdict" in _richlog_text(s1_panel.query_one(RichLog))

            # Select second S1 row (cloud alert) -> right-click col 0 opens AI menu (not 3-item pivot)
            s1_hdr = int(getattr(s1_table, "header_height", 1) or 1)
            await pilot.click("#s1-table", offset=(4, 1 + s1_hdr + 1), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            s1_opts = app.screen.query_one("#ctx-menu-options", OptionList)
            assert any(
                "Ask AI" in str(s1_opts.get_option_at_index(i).prompt)
                for i in range(s1_opts.option_count)
            )
            app.screen.dismiss(None)
            await pilot.pause()

            # 4. Splunk ES Notable: right-click col 0 ('[ ]') -> Ask AI
            app.activate_tab("tab-splunk-es")
            await pilot.pause()
            await app.ensure_tab_mounted("tab-splunk-es")
            await pilot.pause()
            es_pane = app.query_one(SplunkESPane)
            es_pane._populate_table(
                [es_not],
                es_pane._get_notable_columns(),
                header_label="Notable Events",
            )
            await pilot.pause()
            es_table = es_pane.query_one("#es-table", DataTable)
            es_hdr = int(getattr(es_table, "header_height", 1) or 1)
            await pilot.click("#es-table", offset=(4, 1 + es_hdr), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            es_opts = app.screen.query_one("#ctx-menu-options", OptionList)
            es_prompts = [
                str(es_opts.get_option_at_index(i).prompt) for i in range(es_opts.option_count)
            ]
            ask_idx = next(i for i, p in enumerate(es_prompts) if "Ask AI" in p)
            es_opts.highlighted = ask_idx
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, AskEventAIModal)
            app.screen.query_one("#ask-ai-input", Input).value = "Is brute force confirmed?"
            await pilot.click("#ask-ai-submit")
            await app.workers.wait_for_complete()
            await pilot.pause()

            es_panel = es_pane.query_one("#es-ai-panel", EventAIPanelWidget)
            assert es_panel.current_event_key == "splunk_es::1001::es-1"
            assert "Event-only answer" in _richlog_text(es_panel.query_one(RichLog))

    asyncio.run(_run())


def test_modal_edge_cases_header_right_click_and_no_row_guard(tmp_path: Path) -> None:
    fake_llm = _FakeLLMClient()
    app = create_app(
        client=MagicMock(),
        s1_client=MagicMock(),
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )
    app.llm_client = fake_llm

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            rf_pane = app.query_one(RFIntelPane)

            # 1. Clicking AI buttons with no event selected does nothing gracefully
            await pilot.click("#rf-ai-panel #btn-ai-ask-event")
            await pilot.pause()
            assert not isinstance(app.screen, AskEventAIModal)
            await pilot.click("#rf-ai-panel #btn-ai-full-investigate")
            await pilot.pause()
            assert len(fake_llm.calls) == 0

            # 2. Right-clicking table header/border (y=0) or status bar opens NO ContextMenuModal
            await pilot.click("#rf-status", offset=(2, 0), button=3)
            await pilot.pause()
            assert not isinstance(app.screen, ContextMenuModal)
            await pilot.click("#rf-results-table", offset=(4, 0), button=3)
            await pilot.pause()
            assert not isinstance(app.screen, ContextMenuModal)

            # 3. AskEventAIModal empty-input validation + cancel (Escape and button)
            rf_pane._datasets["alerts_v3"] = [_make_rf_alert("rf-edge-1")]
            rf_pane._active_mode = "alerts_v3"
            rf_pane._render_view(schedule_auto_enrich=False)
            await pilot.pause()

            await pilot.click("#rf-ai-panel #btn-ai-ask-event")
            await pilot.pause()
            assert isinstance(app.screen, AskEventAIModal)
            app.screen.query_one("#ask-ai-input", Input).value = "   "
            await pilot.click("#ask-ai-submit")
            await pilot.pause()
            assert isinstance(app.screen, AskEventAIModal)
            assert "Please enter a question" in str(
                app.screen.query_one("#ask-ai-error", Static).render()
            )
            await pilot.click("#ask-ai-cancel")
            await pilot.pause()
            assert not isinstance(app.screen, AskEventAIModal)
            assert len(fake_llm.calls) == 0

            # Escape key cancels AskEventAIModal
            await pilot.click("#rf-ai-panel #btn-ai-ask-event")
            await pilot.pause()
            assert isinstance(app.screen, AskEventAIModal)
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, AskEventAIModal)
            assert len(fake_llm.calls) == 0

    asyncio.run(_run())


def test_ask_modal_on_mount_teardown_guard() -> None:
    modal = AskEventAIModal(event_title="Test", event_key="rf_alert::1")
    fake_app = MagicMock()
    fake_app.is_running = False
    fake_app._exit = False
    with patch.object(AskEventAIModal, "app", new=fake_app):
        with patch.object(modal, "query_one") as q_mock:
            modal.on_mount()
            q_mock.assert_not_called()

    fake_app.is_running = True
    fake_app._exit = True
    with patch.object(AskEventAIModal, "app", new=fake_app):
        with patch.object(modal, "query_one") as q_mock:
            modal.on_mount()
            q_mock.assert_not_called()


def test_event_ai_panel_persistence_across_restart(tmp_path: Path) -> None:
    raw_alert = _make_rf_alert("rf-persist-1", "Persistent Alert")
    app1 = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )
    app1.llm_client = _FakeLLMClient()

    async def _run_first() -> None:
        async with app1.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            ev = normalize_unique_event("rf_alert", raw_alert)
            app1.trigger_event_ai_investigation(ev, "ask_only", question="Persist check?")
            await app1.workers.wait_for_complete()
            await pilot.pause()
            assert app1.event_ai_store.has_investigation(ev.event_key)

    asyncio.run(_run_first())

    # Restart app pointing at same workspace_dir with 0 LLM calls
    second_llm = _FakeLLMClient()
    app2 = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )
    app2.llm_client = second_llm

    async def _run_second() -> None:
        async with app2.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            rf_pane = app2.query_one(RFIntelPane)
            rf_pane._datasets["alerts_v3"] = [raw_alert]
            rf_pane._active_mode = "alerts_v3"
            rf_pane._render_view(schedule_auto_enrich=False)
            await pilot.pause()
            rf_panel = rf_pane.query_one("#rf-ai-panel", EventAIPanelWidget)
            assert "Event-only answer" in _richlog_text(rf_panel.query_one(RichLog))
            assert len(second_llm.calls) == 0

    asyncio.run(_run_second())


def test_control_panel_toggles_per_tool_overrides_and_audit_log_view(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )
    # Seed an audit entry containing sensitive values and a blocked action
    app.ai_audit_store.append(
        AuditEntry(
            entry_id="",
            timestamp="2026-11-26T00:00:01Z",
            run_id="run-blocked-1",
            event_key="rf_alert::99",
            provider="openai",
            mode="full_investigation",
            event_type="blocked_action",
            tool_name="splunk_search",
            allowed=False,
            reason="Blocked because Authorization: Bearer super-secret-token-value",
            payload={"api_key": "secret-xyz-123", "spl": "index=main | outputcsv bad.csv"},
        )
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            llm_pane = app.query_one(LocalLLMPane)
            subtabs = llm_pane.query_one("#llm-subtabs", TabbedContent)
            assert subtabs.active == "llm-tab-chat"

            # Sync without user changes must produce 0 policy_change entries
            subtabs.active = "llm-tab-control-panel"
            await pilot.pause()
            assert len(app.ai_audit_store.query(event_type="policy_change")) == 0

            # Toggle switches and verify persistence + policy_change audit
            ctrl = llm_pane.query_one(AIControlPanelWidget)
            ctrl.query_one("#ai-ctrl-background-triage", Switch).value = True
            ctrl.query_one("#ai-ctrl-splunk-search", Switch).value = False
            await pilot.pause()

            reloaded = app.ai_policy_store.load()
            assert reloaded.background_triage_enabled is True
            assert reloaded.splunk_search_enabled is False
            policy_entries = app.ai_audit_store.query(event_type="policy_change")
            assert len(policy_entries) == 2

            # Toggle per-tool override inside collapsed Collapsible
            tools_col = ctrl.query_one("#ai-ctrl-tools-collapsible", Collapsible)
            assert tools_col.collapsed is True
            first_tool_name = app.ai_tool_registry.list_tools()[0].name
            ctrl.query_one(f"#ai-ctrl-tool-{first_tool_name}", Checkbox).value = False
            await pilot.pause()
            assert first_tool_name in app.ai_policy_store.load().disabled_tools

            # Switch to Audit Log tab, refresh, filter blocked-only, and inspect redacted detail
            subtabs.active = "llm-tab-audit-log"
            await pilot.pause()
            audit_view = llm_pane.query_one(AuditLogViewWidget)
            await pilot.click("#ai-audit-refresh")
            await pilot.pause()
            audit_table = audit_view.query_one("#ai-audit-table", DataTable)
            assert audit_table.row_count >= 4

            audit_view.query_one("#ai-audit-filter-blocked", Switch).value = True
            await pilot.pause()
            assert audit_table.row_count == 1
            audit_table.move_cursor(row=0)
            audit_table.action_select_cursor()
            await pilot.pause()
            detail_txt = _richlog_text(audit_view.query_one("#ai-audit-detail", RichLog))
            assert "splunk_search" in detail_txt
            assert "<REDACTED>" in detail_txt
            assert "super-secret-token-value" not in detail_txt
            assert "secret-xyz-123" not in detail_txt

    asyncio.run(_run())


def test_background_triage_preloader_hook_enabled_vs_disabled(tmp_path: Path) -> None:
    # 1. Disabled (default): _notify_cache_updated performs 0 LLM calls
    llm_disabled = _FakeLLMClient()
    osint_disabled = MagicMock()
    app_off = create_app(
        client=MagicMock(),
        osint_client=osint_disabled,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path / "off",
        no_secret_store=True,
        preload_alerts=False,
    )
    app_off.llm_client = llm_disabled

    async def _run_off() -> None:
        async with app_off.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app_off.alert_cache.put(CACHE_SOURCE_RF, [_make_rf_alert("bg-off-1")])
            app_off._notify_cache_updated(CACHE_SOURCE_RF, 1)
            await pilot.pause()
            app_off.background_triage_queue.wait_idle(timeout=2.0)
            assert len(llm_disabled.calls) == 0
            assert not app_off.event_ai_store.has_investigation("rf_alert::bg-off-1")

    asyncio.run(_run_off())

    # 2. Enabled: _notify_cache_updated enqueues unseen events across streams and persists [AUTO]
    llm_enabled = _FakeLLMClient()
    osint_enabled = MagicMock()
    osint_enabled.enrich_target.return_value = {"dns": {"ok": True}}
    ws_on = tmp_path / "on"
    app_on = create_app(
        client=MagicMock(),
        osint_client=osint_enabled,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=ws_on,
        no_secret_store=True,
        preload_alerts=False,
    )
    app_on.llm_client = llm_enabled
    app_on.ai_policy_store.update(background_triage_enabled=True)

    async def _run_on() -> None:
        async with app_on.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app_on.alert_cache.put(CACHE_SOURCE_RF, [_make_rf_alert("bg-on-rf")])
            app_on.alert_cache.put(CACHE_SOURCE_RF_PLAYBOOK, [_make_rf_playbook("bg-on-pb")])
            app_on.alert_cache.put(CACHE_SOURCE_S1, [_make_s1_threat("bg-on-s1")])
            app_on.alert_cache.put(CACHE_SOURCE_ES, [_make_es_notable("bg-on-es", "1001")])

            for src in (CACHE_SOURCE_RF, CACHE_SOURCE_RF_PLAYBOOK, CACHE_SOURCE_S1, CACHE_SOURCE_ES):
                app_on._notify_cache_updated(src, 1)

            assert app_on.background_triage_queue.wait_idle(timeout=5.0)
            await pilot.pause()
            for key in (
                "rf_alert::bg-on-rf",
                "rf_playbook::bg-on-pb",
                "s1_threat::bg-on-s1",
                "splunk_es::1001::bg-on-es",
            ):
                assert app_on.event_ai_store.has_investigation(key)
                panels = app_on.event_ai_store.get_panels(key)
                assert len(panels) == 1
                assert panels[0].auto_triggered is True

            # Verify RF panel auto-refreshed on UI thread with [AUTO] marker
            rf_panel = app_on.query_one("#rf-ai-panel", EventAIPanelWidget)
            assert "[AUTO]" in _richlog_text(rf_panel.query_one(RichLog))

    asyncio.run(_run_on())


def test_event_ai_panels_80x24_hidden_and_resize_visible_bounds(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        s1_client=MagicMock(),
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            # At 80x24, EventAIPanelWidget is hidden so detail RichLogs retain space
            assert app.query_one("#rf-ai-panel", EventAIPanelWidget).display is False

            app.activate_tab("tab-llm")
            await pilot.pause()
            await app.ensure_tab_mounted("tab-llm")
            await pilot.pause()
            llm_reg = app.query_one("#llm-transcript", RichLog).region
            assert llm_reg.width > 0 and llm_reg.height > 0 and llm_reg.bottom <= 24

            # Resize to (150, 42): all 3 event AI panels visible and buttons clickable inside viewport
            await pilot.resize_terminal(150, 42)
            await pilot.pause()
            for tab_id, panel_sel in (
                ("tab-rf-intel", "#rf-ai-panel"),
                ("tab-sentinelone", "#s1-ai-panel"),
                ("tab-splunk-es", "#es-ai-panel"),
            ):
                app.activate_tab(tab_id)
                await pilot.pause()
                await app.ensure_tab_mounted(tab_id)
                await pilot.pause()
                panel = app.query_one(panel_sel, EventAIPanelWidget)
                assert panel.display is True
                ask_btn = panel.query_one("#btn-ai-ask-event", Button)
                full_btn = panel.query_one("#btn-ai-full-investigate", Button)
                assert 0 <= ask_btn.region.y and ask_btn.region.bottom <= 42
                assert 0 <= full_btn.region.y and full_btn.region.bottom <= 42
                assert ask_btn.region.right <= 150 and full_btn.region.right <= 150

    asyncio.run(_run())


def test_event_ai_panel_widget_renders_errors_and_tool_metadata(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )
    raw = _make_rf_alert("rf-err-1", "Error Render Test")
    ev = normalize_unique_event("rf_alert", raw)
    app.event_ai_store.attach_ai_response(
        ev,
        InvestigationResult(
            run_id="run-err-1",
            event_key=ev.event_key,
            mode="full_investigation",
            provider="security_copilot",
            model="Security Copilot",
            question="Investigate error path",
            answer_markdown="Partial findings before halt.",
            tool_calls=[{"tool_name": "rf_lookup_ioc", "arguments": {"value": "1.2.3.4"}}],
            blocked_actions=[{"tool_name": "splunk_search", "reason": "cross_search_disabled"}],
            status="error",
            error="Simulated timeout",
            timestamp="2026-11-26T00:10:00Z",
        ),
        auto_triggered=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            rf_pane = app.query_one(RFIntelPane)
            rf_pane._datasets["alerts_v3"] = [raw]
            rf_pane._active_mode = "alerts_v3"
            rf_pane._render_view(schedule_auto_enrich=False)
            await pilot.pause()

            txt = _richlog_text(rf_pane.query_one("#rf-ai-panel", EventAIPanelWidget).query_one(RichLog))
            assert "[AUTO]" in txt
            assert "security_copilot" in txt
            assert "Partial findings before halt." in txt
            assert "rf_lookup_ioc" in txt
            assert "cross_search_disabled" in txt
            assert "Simulated timeout" in txt

    asyncio.run(_run())


def test_json_stores_created_under_workspace_dir(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            llm_pane = app.query_one(LocalLLMPane)
            llm_pane.query_one("#llm-subtabs", TabbedContent).active = "llm-tab-control-panel"
            await pilot.pause()
            llm_pane.query_one("#ai-ctrl-cross-search", Switch).value = False
            await pilot.pause()

    asyncio.run(_run())
    policy_data = json.loads((tmp_path / ".soclens_cache" / "ai_policy.json").read_text("utf-8"))
    assert policy_data["cross_search_enabled"] is False


def test_reload_settings_rebinds_ai_stores_and_respects_custom_injected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.agent_policy import AIPolicyStore
    from soclens.settings import invalidate_settings_cache

    ws1 = tmp_path / "ws1"
    ws2 = tmp_path / "ws2"
    ws1.mkdir()
    ws2.mkdir()
    monkeypatch.setenv("SOCLENS_HOME", str(ws1))
    monkeypatch.delenv("SOCLENS_WORKSPACE", raising=False)
    invalidate_settings_cache()

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=None,
        no_secret_store=True,
        preload_alerts=False,
    )
    assert app.ai_policy_store.path == ws1 / ".soclens_cache" / "ai_policy.json"

    async def _run_rebind() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            monkeypatch.setenv("SOCLENS_HOME", str(ws2))
            app.reload_settings()
            await pilot.pause()
            assert app.workspace_dir == ws2
            assert app.ai_policy_store.path == ws2 / ".soclens_cache" / "ai_policy.json"
            assert app.ai_audit_store.path == ws2 / ".soclens_cache" / "ai_audit.jsonl"
            assert app.event_ai_store.path == ws2 / ".soclens_cache" / "event_ai_panels.json"

    asyncio.run(_run_rebind())

    # Custom-injected workspace_dir or custom-replaced AI store must NOT be rebound
    custom_policy = AIPolicyStore(tmp_path / "custom_policy.json")
    app_custom = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=ws1,
        no_secret_store=True,
        preload_alerts=False,
    )
    app_custom.ai_policy_store = custom_policy
    monkeypatch.setenv("SOCLENS_HOME", str(ws2))
    app_custom.reload_settings()
    assert app_custom.workspace_dir == ws1
    assert app_custom.ai_policy_store.path == tmp_path / "custom_policy.json"


def test_freeform_chat_tui_uses_readonly_tools_toggle_and_audit_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import (
        SOURCE_CATEGORY_RF,
        SOURCE_CATEGORY_SPLUNK,
    )
    from soclens.agent_tools import ReadOnlyToolRegistry, ReadOnlyToolSpec
    from tests.e2e.agentic_mocks import MockAgenticLLMAndCopilotServer

    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(tmp_path / "settings.json"))

    reg = ReadOnlyToolRegistry()
    splunk_calls: list[str] = []
    rf_calls: list[str] = []
    reg.register(
        ReadOnlyToolSpec(
            name="splunk_search",
            source_category=SOURCE_CATEGORY_SPLUNK,
            description="Read-only Splunk SPL search",
            parameters_schema={
                "type": "object",
                "properties": {"spl": {"type": "string"}},
                "required": ["spl"],
            },
            handler=lambda args: (
                splunk_calls.append(str(args.get("spl") or ""))
                or {"rows": [{"host": "srv-web-01", "count": 4}]}
            ),
            readonly=True,
        )
    )
    reg.register(
        ReadOnlyToolSpec(
            name="rf_lookup_ioc",
            source_category=SOURCE_CATEGORY_RF,
            description="Read-only Recorded Future IOC lookup",
            parameters_schema={
                "type": "object",
                "properties": {
                    "entity_type": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["entity_type", "value"],
            },
            handler=lambda args: (
                rf_calls.append(str(args.get("value") or ""))
                or {"entity": args.get("value"), "risk_score": 91}
            ),
            readonly=True,
        )
    )

    with MockAgenticLLMAndCopilotServer() as server:
        server.configure_provider(monkeypatch, "openai")

        app = create_app(
            client=MagicMock(),
            dry_run=True,
            initial_tab="tab-llm",
            workspace_dir=tmp_path,
            no_secret_store=True,
            preload_alerts=False,
        )
        app.ai_tool_registry = reg
        app.ai_orchestrator = SocAgentOrchestrator(
            registry=reg,
            policy_store=app.ai_policy_store,
            audit_store=app.ai_audit_store,
        )

        async def _run() -> None:
            async with app.run_test(size=(140, 40)) as pilot:
                await pilot.pause()
                llm_pane = app.query_one(LocalLLMPane)
                toggle_btn = llm_pane.query_one("#llm-tools-toggle-btn", Button)
                assert "Tools: ON" in str(toggle_btn.label)

                # 1. Freeform prompt triggers both RF and Splunk read-only tools
                server.queue_scripted_turn(
                    provider="openai",
                    tool_calls=[
                        {"name": "rf_lookup_ioc", "arguments": {"entity_type": "ip", "value": "203.0.113.5"}},
                        {"name": "splunk_search", "arguments": {"spl": "index=main 203.0.113.5 | head 5"}},
                    ],
                )
                server.queue_scripted_turn(
                    provider="openai",
                    content="Freeform finding: 203.0.113.5 has RF risk 91 and 4 Splunk hits on srv-web-01.",
                )

                llm_pane.query_one("#llm-prompt", Input).value = "Check 203.0.113.5 across RF and Splunk"
                llm_pane.query_one("#llm-send-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                transcript = _richlog_text(llm_pane.query_one("#llm-transcript", RichLog))
                assert "[Tool 1] rf_lookup_ioc -> OK" in transcript
                assert "[Tool 2] splunk_search -> OK" in transcript
                assert "RF risk 91 and 4 Splunk hits" in transcript
                assert rf_calls == ["203.0.113.5"]
                assert len(splunk_calls) == 1

                # 2. Disabling Splunk in AI Control Panel blocks Splunk in freeform chat
                subtabs = llm_pane.query_one("#llm-subtabs", TabbedContent)
                subtabs.active = "llm-tab-control-panel"
                await pilot.pause()
                llm_pane.query_one("#ai-ctrl-splunk-search", Switch).value = False
                await pilot.pause()
                subtabs.active = "llm-tab-chat"
                await pilot.pause()

                server.queue_scripted_turn(
                    provider="openai",
                    tool_calls=[
                        {"name": "splunk_search", "arguments": {"spl": "index=main | head 1"}},
                    ],
                )
                server.queue_scripted_turn(
                    provider="openai",
                    content="Splunk search was blocked by AI Control Panel policy.",
                )
                llm_pane.query_one("#llm-prompt", Input).value = "Run a Splunk search"
                llm_pane.query_one("#llm-send-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                transcript2 = _richlog_text(llm_pane.query_one("#llm-transcript", RichLog))
                assert "[Tool Blocked] splunk_search" in transcript2
                assert len(splunk_calls) == 1  # unchanged!

                # 3. Per-session Tools: OFF toggle isolates Chat 2 from Chat 1
                llm_pane.query_one("#llm-new-chat-btn", Button).press()
                await pilot.pause()
                assert "Tools: ON" in str(toggle_btn.label)
                toggle_btn.press()
                await pilot.pause()
                assert "Tools: OFF" in str(toggle_btn.label)

                server.queue_scripted_turn(
                    provider="openai",
                    tool_calls=[
                        {"name": "rf_lookup_ioc", "arguments": {"entity_type": "ip", "value": "1.1.1.1"}},
                    ],
                )
                server.queue_scripted_turn(
                    provider="openai",
                    content="Chat-only reply without tools.",
                )
                llm_pane.query_one("#llm-prompt", Input).value = "Check 1.1.1.1"
                llm_pane.query_one("#llm-send-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert rf_calls == ["203.0.113.5"]  # unchanged in Tools: OFF mode

                # Switching back to Chat 1 restores Tools: ON
                llm_pane.query_one("#llm-session-select", Select).value = "chat-1"
                await pilot.pause()
                assert "Tools: ON" in str(toggle_btn.label)

                # 4. Audit Log view shows freeform_chat entries and blocked_action
                subtabs.active = "llm-tab-audit-log"
                await pilot.pause()
                await pilot.click("#ai-audit-refresh")
                await pilot.pause()
                audit_entries = app.ai_audit_store.query(event_key="freeform_chat::chat-1")
                assert any(e.event_type == "tool_result" and e.tool_name == "rf_lookup_ioc" for e in audit_entries)
                assert any(e.event_type == "blocked_action" and e.tool_name == "splunk_search" for e in audit_entries)

        asyncio.run(_run())


def test_freeform_chat_tools_toggle_fits_80x24_layout(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            llm_pane = app.query_one(LocalLLMPane)
            for widget_id in (
                "#llm-session-select",
                "#llm-new-chat-btn",
                "#llm-close-chat-btn",
                "#llm-tools-toggle-btn",
                "#llm-transcript",
                "#llm-prompt",
            ):
                w = llm_pane.query_one(widget_id)
                assert w.region.width > 0 and w.region.height > 0
                assert w.region.right <= 80
                assert w.region.bottom <= 24

    asyncio.run(_run())


def test_kill_switch_visible_and_within_bounds_across_all_13_dashboards(
    tmp_path: Path,
) -> None:
    from soclens.tui.app import ALL_TABS, USER_VIEW_TABS

    app = create_app(
        client=MagicMock(),
        s1_client=MagicMock(),
        dry_run=True,
        view_mode="user",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            for tab_id in USER_VIEW_TABS:
                app.activate_tab(tab_id)
                await pilot.pause()
                btn = app.query_one("#ai-kill-switch-btn", Button)
                assert btn.display is True
                assert btn.region.height == 1
                assert btn.region.width > 0
                assert btn.region.right <= 150
                assert "KILL AI" in str(btn.label)

            app.set_view_mode("admin")
            await pilot.pause()
            for width, height in ((80, 24), (150, 42)):
                await pilot.resize_terminal(width, height)
                await pilot.pause()
                for tab_id in ALL_TABS:
                    app.activate_tab(tab_id)
                    await pilot.pause()
                    btn = app.query_one("#ai-kill-switch-btn", Button)
                    assert btn.display is True
                    assert btn.region.height == 1
                    assert btn.region.width > 0
                    assert btn.region.right <= width

    asyncio.run(_run())


def test_kill_switch_one_click_and_f12_hotkey_halts_all_ai_and_resumes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading

    from soclens.agent_orchestrator import SocAgentOrchestrator
    from soclens.agent_policy import SOURCE_CATEGORY_RF
    from soclens.agent_tools import ReadOnlyToolRegistry, ReadOnlyToolSpec
    from tests.e2e.agentic_mocks import MockAgenticLLMAndCopilotServer

    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(tmp_path / "settings.json"))

    tool_entered = threading.Event()
    tool_release = threading.Event()
    reg = ReadOnlyToolRegistry()
    reg.register(
        ReadOnlyToolSpec(
            name="rf_lookup_ioc",
            source_category=SOURCE_CATEGORY_RF,
            description="Read-only IOC lookup",
            parameters_schema={"type": "object", "properties": {"value": {"type": "string"}}},
            handler=lambda args: (
                tool_entered.set(),
                tool_release.wait(timeout=3.0),
                {"val": args.get("value")},
            )[-1],
            readonly=True,
        )
    )

    with MockAgenticLLMAndCopilotServer() as server:
        server.configure_provider(monkeypatch, "openai")
        app = create_app(
            client=MagicMock(),
            dry_run=True,
            initial_tab="tab-llm",
            workspace_dir=tmp_path,
            no_secret_store=True,
            preload_alerts=False,
        )
        app.ai_tool_registry = reg
        app.ai_orchestrator = SocAgentOrchestrator(
            registry=reg,
            policy_store=app.ai_policy_store,
            audit_store=app.ai_audit_store,
        )

        async def _run() -> None:
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                llm_pane = app.query_one(LocalLLMPane)

                # Start an active freeform tool-using chat that blocks inside rf_lookup_ioc
                server.queue_scripted_turn(
                    provider="openai",
                    tool_calls=[{"name": "rf_lookup_ioc", "arguments": {"value": "198.51.100.7"}}],
                )
                llm_pane.query_one("#llm-prompt", Input).value = "Check 198.51.100.7"
                llm_pane.query_one("#llm-send-btn", Button).press()
                await pilot.pause()
                assert await asyncio.to_thread(tool_entered.wait, 3.0)

                # 1-click global kill button halts everything immediately
                await pilot.click("#ai-kill-switch-btn")
                tool_release.set()
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert app.is_ai_killed() is True
                assert app.ai_policy_store.load().ai_kill_switch_active is True
                assert "AI HALTED" in str(app.query_one("#ai-kill-switch-btn", Button).label)
                assert "AI HALTED" in app.sub_title
                assert "HALTED BY AI KILL SWITCH" in _richlog_text(
                    llm_pane.query_one("#llm-transcript", RichLog)
                )
                assert any(
                    e.event_type == "policy_change" and e.tool_name == "ai_kill_switch"
                    for e in app.ai_audit_store.query(event_type="policy_change")
                )

                # While halted, freeform send, template send, and event AI buttons perform 0 LLM calls
                reqs_before = len(server.chat_requests(provider="openai"))
                llm_pane.query_one("#llm-prompt", Input).value = "Blocked prompt"
                llm_pane.query_one("#llm-send-btn", Button).press()
                await pilot.pause()
                assert len(server.chat_requests(provider="openai")) == reqs_before

                # Switch to RF Intel tab -> Ask AI & Full Investigate blocked cleanly
                app.activate_tab("tab-rf-intel")
                await pilot.pause()
                await app.ensure_tab_mounted("tab-rf-intel")
                await pilot.pause()
                rf_pane = app.query_one(RFIntelPane)
                rf_pane._datasets["alerts_v3"] = [_make_rf_alert("rf-ks-1")]
                rf_pane._active_mode = "alerts_v3"
                rf_pane._render_view(schedule_auto_enrich=False)
                await pilot.pause()
                await pilot.click("#rf-ai-panel #btn-ai-ask-event")
                await pilot.pause()
                assert not isinstance(app.screen, AskEventAIModal)
                await pilot.click("#rf-ai-panel #btn-ai-full-investigate")
                await pilot.pause()
                assert len(server.chat_requests(provider="openai")) == reqs_before

                # Click kill button again -> resumes AI actions
                await pilot.click("#ai-kill-switch-btn")
                await pilot.pause()
                assert app.is_ai_killed() is False
                assert "KILL AI" in str(app.query_one("#ai-kill-switch-btn", Button).label)

                # Priority hotkey F12 works even while focused inside an Input widget
                app.activate_tab("tab-llm")
                await pilot.pause()
                llm_pane.query_one("#llm-prompt", Input).focus()
                await pilot.pause()
                await pilot.press("f12")
                await pilot.pause()
                assert app.is_ai_killed() is True
                await pilot.press("f12")
                await pilot.pause()
                assert app.is_ai_killed() is False

        asyncio.run(_run())


def test_kill_switch_configurability_confirm_modals_visibility_hotkey_and_restart(
    tmp_path: Path,
) -> None:
    from soclens.tui.modals import ConfirmActionModal

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )
    app.ai_policy_store.update(
        kill_switch_label="STOP AI",
        kill_switch_hotkey="f11",
        kill_switch_visible=False,
        kill_switch_confirm_engage=True,
        kill_switch_confirm_resume=True,
        kill_switch_persist_across_restarts=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            btn = app.query_one("#ai-kill-switch-btn", Button)
            # Hidden when kill_switch_visible=False and not halted
            assert btn.display is False
            assert "STOP AI [F11]" in str(btn.label)

            # Old F12 hotkey is ignored; configured F11 triggers ConfirmActionModal
            await pilot.press("f12")
            await pilot.pause()
            assert not isinstance(app.screen, ConfirmActionModal)
            assert app.is_ai_killed() is False

            await pilot.press("f11")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            # Cancel keeps AI active
            await pilot.click("#confirm-cancel-btn")
            await pilot.pause()
            assert app.is_ai_killed() is False

            # Approve engages kill switch and forces button visible
            await pilot.press("f11")
            await pilot.pause()
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            assert app.is_ai_killed() is True
            assert btn.display is True
            assert "AI HALTED [F11]" in str(btn.label)

            # Resume confirmation modal: cancel keeps halted, approve resumes
            await pilot.click("#ai-kill-switch-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-cancel-btn")
            await pilot.pause()
            assert app.is_ai_killed() is True

    asyncio.run(_run())

    # Restart with persist=True -> still halted on startup
    app_persist = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )
    assert app_persist.is_ai_killed() is True

    # Restart with persist=False -> auto-clears halted state on startup
    app_persist.ai_policy_store.update(kill_switch_persist_across_restarts=False)
    app_clear = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )
    assert app_clear.is_ai_killed() is False


def test_control_panel_tool_limits_presets_and_settings_sync(tmp_path: Path) -> None:
    from soclens.tui.screens.settings import SettingsPane

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            llm_pane = app.query_one(LocalLLMPane)
            llm_pane.query_one("#llm-subtabs", TabbedContent).active = "llm-tab-control-panel"
            await pilot.pause()
            ctrl = llm_pane.query_one(AIControlPanelWidget)

            # Click 250 preset button
            await pilot.click("#ai-ctrl-preset-steps-250")
            await pilot.pause()
            assert app.ai_policy_store.load().max_tool_steps == 250

            # Enter custom limits and Save Limits
            ctrl.query_one("#ai-ctrl-max-tool-steps", Input).value = "300"
            ctrl.query_one("#ai-ctrl-max-identical-calls", Input).value = "6"
            ctrl.query_one("#ai-ctrl-max-tool-failures", Input).value = "25"
            await pilot.click("#ai-ctrl-save-limits")
            await pilot.pause()

            pol = app.ai_policy_store.load()
            assert pol.max_tool_steps == 300
            assert pol.max_identical_tool_calls == 6
            assert pol.max_same_tool_failures == 25

            # Switch to Settings -> AI & LLM Settings reflects 300/6/25
            app.activate_tab("tab-settings")
            await pilot.pause()
            await app.ensure_tab_mounted("tab-settings")
            await pilot.pause()
            settings_pane = app.query_one(SettingsPane)
            settings_pane.select_category("cat-ai")
            await pilot.pause()
            assert settings_pane.query_one("#set-ai-max-tool-steps", Input).value == "300"
            assert settings_pane.query_one("#set-ai-max-identical-calls", Input).value == "6"
            assert settings_pane.query_one("#set-ai-max-tool-failures", Input).value == "25"

            # Edit label and max steps in Settings and save -> syncs live to global bar
            settings_pane.query_one("#set-ai-max-tool-steps", Input).value = "120"
            settings_pane.query_one("#set-ai-kill-label", Input).value = "ABORT AI"
            await pilot.click("#settings-save-btn")
            await pilot.pause()
            assert app.ai_policy_store.load().max_tool_steps == 120
            assert "ABORT AI" in str(app.query_one("#ai-kill-switch-btn", Button).label)

    asyncio.run(_run())


def test_settings_llm_defaults_gemini_autofallback_and_active_session_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.config import DEFAULT_GEMINI_MODEL, get_local_llm_config
    from soclens.settings import (
        clear_session_overrides,
        invalidate_settings_cache,
        save_profile_settings,
    )
    from soclens.tui.screens.settings import SettingsPane

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
    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    clear_session_overrides()
    invalidate_settings_cache()

    # Scenario A: User only selected "Google Gemini API Only" and saved API key (no RF_LLM_MODEL)
    save_profile_settings(
        {"llm_visible_providers": "gemini", "gemini_api_key": "AIzaSyTestKeyForTui123456"},
        settings_path=settings_path,
    )
    invalidate_settings_cache()

    app_gemini = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )

    async def _run_gemini_and_settings() -> None:
        async with app_gemini.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            # Full Investigate / Ask AI client must auto-resolve Gemini default model instead of failing
            llm_client = app_gemini._get_ai_llm_client()
            assert llm_client.config.provider == "gemini"
            assert llm_client.config.model == DEFAULT_GEMINI_MODEL

            # Configure Default AI Provider + Model in Settings -> Save -> verifies persistence
            settings_pane = app_gemini.query_one(SettingsPane)
            settings_pane.select_category("cat-ai")
            await pilot.pause()
            settings_pane.query_one("#set-rf-llm-provider", Select).value = "gemini"
            settings_pane.query_one("#set-rf-llm-model", Input).value = "gemini-2.5-pro"
            settings_pane.query_one("#set-rf-llm-base-url", Input).value = "https://proxy.example/v1beta"
            await pilot.click("#settings-save-btn")
            await pilot.pause()

            invalidate_settings_cache()
            cfg = get_local_llm_config()
            assert cfg.provider == "gemini"
            assert cfg.model == "gemini-2.5-pro"
            assert cfg.base_url == "https://proxy.example/v1beta"

    asyncio.run(_run_gemini_and_settings())

    # Scenario B: Active session model in AI Analyst tab acts as fallback when no default model saved
    clear_session_overrides()
    save_profile_settings(
        {
            "llm_visible_providers": None,
            "rf_llm_provider": None,
            "rf_llm_model": None,
            "rf_llm_base_url": None,
        },
        settings_path=settings_path,
    )
    invalidate_settings_cache()

    app_ollama = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
        no_secret_store=True,
        preload_alerts=False,
    )

    async def _run_session_fallback() -> None:
        async with app_ollama.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            llm_pane = app_ollama.query_one(LocalLLMPane)
            sess = llm_pane._active_session
            sess.provider = "ollama"
            sess.model = "qwen2.5-coder:7b"
            client = app_ollama._get_ai_llm_client()
            assert client.config.provider == "ollama"
            assert client.config.model == "qwen2.5-coder:7b"

    asyncio.run(_run_session_fallback())


def test_ai_settings_page_queries_available_ais_and_picks_default_model_from_dropdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.config import get_local_llm_config
    from soclens.settings import (
        clear_session_overrides,
        invalidate_settings_cache,
    )
    from soclens.tui.screens.settings import SettingsPane
    from tests.e2e.agentic_mocks import MockAgenticLLMAndCopilotServer

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
        "SOCLENS_LLM_VISIBLE_PROVIDERS",
    ):
        monkeypatch.delenv(var, raising=False)

    settings_path = tmp_path / "settings.json"
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(settings_path))
    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    clear_session_overrides()
    invalidate_settings_cache()

    with MockAgenticLLMAndCopilotServer() as server:
        monkeypatch.setenv("GEMINI_BASE_URL", server.gemini_base_url)

        app = create_app(
            client=MagicMock(),
            dry_run=True,
            initial_tab="tab-settings",
            workspace_dir=tmp_path,
            no_secret_store=True,
            preload_alerts=False,
        )

        async def _run() -> None:
            async with app.run_test(size=(140, 42)) as pilot:
                await pilot.pause()
                settings_pane = app.query_one(SettingsPane)
                settings_pane.select_category("cat-ai")
                await pilot.pause()

                # Provide an Ollama base URL + a Gemini API key, then query all available AIs
                settings_pane.query_one("#set-rf-llm-provider", Select).value = "ollama"
                settings_pane.query_one("#set-rf-llm-base-url", Input).value = server.ollama_base_url
                settings_pane.query_one("#set-gemini-api-key", Input).value = "AIzaSyLiveQueryKey123456"
                await pilot.pause()

                await pilot.click("#settings-refresh-ai-models-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                status_text = str(settings_pane.query_one("#settings-ai-models-status", Static).content)
                assert "Ollama: 2 model(s)" in status_text
                assert "Gemini: 2 model(s)" in status_text

                # Dropdown contains queried models from both available AIs
                model_sel = settings_pane.query_one("#set-rf-llm-model-select", Select)
                option_vals = [val for _lbl, val in model_sel._options]
                assert "ollama::llama3.2:latest" in option_vals
                assert "ollama::qwen2.5:14b" in option_vals
                assert "gemini::gemini-2.5-flash" in option_vals
                assert "gemini::gemini-2.5-pro" in option_vals

                # Pick a queried Gemini model from dropdown -> auto-syncs input AND provider!
                model_sel.value = "gemini::gemini-2.5-pro"
                await pilot.pause()
                assert settings_pane.query_one("#set-rf-llm-model", Input).value == "gemini-2.5-pro"
                assert settings_pane.query_one("#set-rf-llm-provider", Select).value == "gemini"

                # Save Settings -> get_local_llm_config() reflects chosen provider & model
                await pilot.click("#settings-save-btn")
                await pilot.pause()

                invalidate_settings_cache()
                cfg = get_local_llm_config()
                assert cfg.provider == "gemini"
                assert cfg.model == "gemini-2.5-pro"

        asyncio.run(_run())





