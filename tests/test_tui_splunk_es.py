"""Textual Pilot tests for SplunkESPane, SplunkNotableTriageModal, ConfirmActionModal, and dry-run."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from textual.widgets import DataTable, Input, Select, Static

from soclens.tui.app import create_app
from soclens.tui.modals import ConfirmActionModal, SplunkNotableTriageModal
from soclens.tui.screens.splunk_es import SplunkESPane


def _make_fake_es_client() -> MagicMock:
    es = MagicMock()
    es.__enter__.return_value = es
    es.__exit__.return_value = None
    es.list_notables.return_value = [
        {
            "event_id": "notable-001",
            "rule_name": "RF High Risk C2 IP",
            "urgency": "high",
            "status": 1,
            "status_label": "New",
            "owner": "unassigned",
            "disposition": "",
            "security_domain": "network",
            "src": "198.51.100.42",
            "dest": "10.10.0.5",
            "user": "jdoe",
            "risk_score": "90",
            "_time": "2026-11-24T12:00:00Z",
            "raw": {"event_id": "notable-001", "rule_name": "RF High Risk C2 IP"},
        }
    ]
    es.update_notable.return_value = {"success": True}
    es.list_correlation_searches.return_value = [
        {
            "name": "Network - RF High Risk C2 IP - Rule",
            "label": "RF High Risk C2 IP",
            "app": "SplunkEnterpriseSecuritySuite",
            "description": "Detects RF high risk C2 IPs",
            "search": "index=firewall | lookup rf_ip_risklist",
            "cron_schedule": "*/15 * * * *",
            "disabled": False,
            "enabled": True,
            "action_notable": True,
            "action_risk": False,
            "security_domain": "network",
            "severity": "high",
            "raw": {"action.notable": "1"},
        }
    ]
    es.set_correlation_search_enabled.return_value = {
        "name": "Network - RF High Risk C2 IP - Rule",
        "enabled": False,
        "disabled": True,
    }
    es.query_threat_intel.return_value = [
        {"_key": "ti-1", "ip": "198.51.100.42", "description": "RF C2", "threat_key": "rf_ip"}
    ]
    es.lookup_asset.return_value = [
        {"ip": "10.10.0.5", "nt_host": "web01", "priority": "high", "owner": "secops"}
    ]
    es.lookup_identity.return_value = [
        {"identity": "jdoe", "email": "jdoe@corp.local", "priority": "medium"}
    ]
    es.list_risk_events.return_value = [
        {
            "_time": "2026-11-24T11:55:00Z",
            "risk_object": "web01",
            "risk_object_type": "system",
            "risk_score": "75",
            "search_name": "RF RBA Detection",
            "risk_message": "High risk indicator hit",
        }
    ]
    return es


def test_tui_splunk_es_views_and_triage_modal(tmp_path: Path) -> None:
    fake_es = _make_fake_es_client()
    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(140, 40)) as pilot:
                await pilot.pause()

                # 1. Load Notable Events
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                table = app.query_one("#es-table", DataTable)
                assert table.row_count == 1
                assert "RF High Risk C2 IP" in [str(c) for c in table.get_row_at(0)]

                # 2. Open SplunkNotableTriageModal and submit update
                await pilot.click("#es-triage-btn")
                await pilot.pause()
                assert isinstance(app.screen, SplunkNotableTriageModal)

                app.screen.query_one("#es-triage-status-select", Select).value = "in_progress"
                app.screen.query_one("#es-triage-urgency-select", Select).value = "critical"
                app.screen.query_one("#es-triage-owner-input", Input).value = "analyst1"
                app.screen.query_one("#es-triage-disposition-select", Select).value = "true_positive"
                app.screen.query_one("#es-triage-comment-input", Input).value = "Triaging C2 hit"
                await pilot.click("#es-triage-apply-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                fake_es.update_notable.assert_called_once_with(
                    ["notable-001"],
                    status="in_progress",
                    urgency="critical",
                    owner="analyst1",
                    disposition="true_positive",
                    comment="Triaging C2 hit",
                )

                # 3. Switch to Correlation Searches & toggle with ConfirmActionModal
                app.query_one("#es-view-select", Select).value = "correlations"
                await pilot.pause()
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 1
                assert "Network - RF High Risk C2 IP - Rule" in [
                    str(c) for c in table.get_row_at(0)
                ]

                await pilot.click("#es-toggle-corr-btn")
                await pilot.pause()
                assert isinstance(app.screen, ConfirmActionModal)
                await pilot.click("#confirm-approve-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                fake_es.set_correlation_search_enabled.assert_called_once_with(
                    "Network - RF High Risk C2 IP - Rule", False
                )

                # 4. Switch to Threat Intel
                app.query_one("#es-view-select", Select).value = "threat_intel"
                await pilot.pause()
                await pilot.click("#es-load-ti-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 1
                assert "198.51.100.42" in [str(c) for c in table.get_row_at(0)]

                # 5. Switch to Assets & Identities
                app.query_one("#es-view-select", Select).value = "assets_identities"
                await pilot.pause()
                await pilot.click("#es-lookup-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 1
                assert "web01" in [str(c) for c in table.get_row_at(0)]

                app.query_one("#es-entity-kind-select", Select).value = "identities"
                await pilot.pause()
                await pilot.click("#es-lookup-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 1
                assert "jdoe" in [str(c) for c in table.get_row_at(0)]

                # 6. Switch to Risk Events (RBA)
                app.query_one("#es-view-select", Select).value = "risk"
                await pilot.pause()
                await pilot.click("#es-lookup-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 1
                assert "RF RBA Detection" in [str(c) for c in table.get_row_at(0)]

    asyncio.run(_run())


def test_tui_splunk_es_dry_run_blocks_mutations(tmp_path: Path) -> None:
    fake_es = _make_fake_es_client()
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(140, 40)) as pilot:
                await pilot.pause()

                # Load notables and attempt triage in dry-run
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                await pilot.click("#es-triage-btn")
                await pilot.pause()
                status = str(app.query_one("#es-status", Static).render())
                assert "DRY-RUN" in status
                fake_es.update_notable.assert_not_called()

                # Load correlations and attempt toggle in dry-run
                app.query_one("#es-view-select", Select).value = "correlations"
                await pilot.pause()
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                await pilot.click("#es-toggle-corr-btn")
                await pilot.pause()
                status = str(app.query_one("#es-status", Static).render())
                assert "DRY-RUN" in status
                fake_es.set_correlation_search_enabled.assert_not_called()

    asyncio.run(_run())


def _richlog_text(log: Any) -> str:
    return "\n".join(line.text for line in log.lines)


def _make_mc_fake_es() -> MagicMock:
    es = MagicMock()
    es.__enter__.return_value = es
    es.__exit__.return_value = None
    items = [
        {
            "event_id": "mc-1@@notable@@1",
            "finding_id": "mc-1@@notable@@1",
            "rule_title": "MC C2 Beacon",
            "rule_name": "mc_c2_beacon",
            "rule_description": "Outbound C2 beacon",
            "urgency": "critical",
            "status": 1,
            "status_label": "New",
            "owner": "unassigned",
            "disposition": "Undetermined",
            "security_domain": "network",
            "src": "198.51.100.10",
            "dest": "10.0.0.5",
            "user": "jdoe",
            "risk_score": "85",
            "orig_sid": "sid_orig_1",
            "orig_rid": "0",
            "tenant_id": "ACME",
            "custom_fields": {"tenant_id": "ACME", "snow_ticket": "INC100", "org_unit": "Finance"},
            "item_type": "finding",
            "is_investigation": False,
            "source_backend": "mc_v2",
            "_time": "2026-11-24T12:00:00Z",
            "raw": {
                "event_id": "mc-1@@notable@@1",
                "tenant_id": "ACME",
                "snow_ticket": "INC100",
                "org_unit": "Finance",
                "dest_host": "ws-01",
                "_raw": "beacon to 198.51.100.10",
            },
        },
        {
            "event_id": "mc-2@@notable@@2",
            "finding_id": "mc-2@@notable@@2",
            "rule_title": "Beta Host Alert",
            "rule_name": "beta_host_alert",
            "urgency": "medium",
            "status": 2,
            "status_label": "In Progress",
            "owner": "alice",
            "disposition": "True Positive - Suspicious Activity",
            "security_domain": "endpoint",
            "src": "10.0.0.20",
            "dest": "10.0.0.30",
            "user": "bob",
            "risk_score": "40",
            "tenant_id": "BETA",
            "custom_fields": {"tenant_id": "BETA", "snow_ticket": "INC200"},
            "item_type": "finding",
            "is_investigation": False,
            "source_backend": "mc_v2",
            "_time": "2026-11-24T11:00:00Z",
            "raw": {"event_id": "mc-2@@notable@@2", "tenant_id": "BETA", "snow_ticket": "INC200"},
        },
    ]
    inv_items = [
        {
            "event_id": "inv-guid-1",
            "investigation_guid": "inv-guid-1",
            "name": "Existing Investigation",
            "rule_title": "Existing Investigation",
            "urgency": "high",
            "status_label": "In Progress",
            "tenant_id": "ACME",
            "is_investigation": True,
            "item_type": "investigation",
            "_time": "2026-11-24T12:10:00Z",
            "raw": {"investigation_guid": "inv-guid-1"},
        }
    ]

    def _hybrid_query(**kwargs: Any) -> dict[str, Any]:
        if kwargs.get("item_type") == "investigations":
            return {
                "items": inv_items,
                "total": len(inv_items),
                "offset": 0,
                "limit": 100,
                "source_backend": "mc_v2",
            }
        return {
            "items": items,
            "total": len(items),
            "offset": 0,
            "limit": 100,
            "source_backend": "mc_v2",
        }

    es.query_findings_hybrid.side_effect = _hybrid_query
    es.list_investigations.return_value = inv_items
    es.triage_findings_hybrid.return_value = {"backend": "mc_v2", "updated_ids": ["mc-1@@notable@@1"]}
    es.create_investigation.return_value = {"investigation_guid": "inv-new-1"}
    es.add_findings_to_investigation.return_value = {"investigation_guid": "inv-guid-1"}
    es.list_modaction_invocations.return_value = [
        {"_time": "2026-11-24T12:01:00Z", "action_label": "Risk Analysis", "action_status": "success", "action_mode": "adhoc", "user": "alice"}
    ]
    es.list_adaptive_response_actions.return_value = [
        {"name": "risk", "label": "Risk Analysis", "supports_adhoc": True, "required_params": []}
    ]
    es.dispatch_adaptive_response.return_value = {"success": True}
    es.create_finding.return_value = {"finding_id": "manual-new-1"}
    es.create_note.return_value = {"id": "note-new-1"}
    es.list_notes.return_value = {"items": [{"author": "alice", "content": "Investigating"}], "total": 1}
    es.get_history.return_value = {"items": [{"_time": "2026-11-24T12:02:00Z", "user": "alice", "message": "Created"}], "total": 1}
    return es


def test_tui_splunk_es_tenant_custom_fields_and_rollup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from textual.widgets import RichLog

    monkeypatch.setenv("SPLUNK_ES_CUSTOM_FIELDS", "snow_ticket")
    fake_es = _make_mc_fake_es()
    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                app.query_one("#es-auto-enrich-cb").value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                table = app.query_one("#es-table", DataTable)
                assert table.row_count == 2
                row0 = [str(c) for c in table.get_row_at(0)]
                assert "ACME" in row0
                assert "INC100" in row0

                hdr = str(app.query_one("#es-detail-header", Static).render())
                assert "[Tenant: ACME]" in hdr

                # Switch Inspector to Metadata & Custom tab
                await pilot.click("#es-insp-tab-metadata")
                await pilot.pause()
                detail_txt = _richlog_text(app.query_one("#es-detail", RichLog))
                assert "Custom / Org Fields" in detail_txt
                assert "INC100" in detail_txt
                assert "Finance" in detail_txt

                # Filter with tenant_id:ACME structured search
                app.query_one("#es-search-input", Input).value = "tenant_id:ACME"
                await pilot.pause()
                assert table.row_count == 1

                app.query_one("#es-search-input", Input).value = ""
                await pilot.pause()
                assert table.row_count == 2

                # Group by Tenant rollup mode
                await pilot.click("#es-group-tenant-btn")
                await pilot.pause()
                assert table.row_count == 4  # 2 tenant header rows + 2 findings
                group_row = [str(c) for c in table.get_row_at(0)]
                assert any("Tenant ACME:" in cell for cell in group_row)

    asyncio.run(_run())


def test_tui_splunk_es_queue_pills_saved_views_autorefresh_and_stepping(
    tmp_path: Path,
) -> None:
    from soclens.tui.screens.es_modals import ESSavedViewModal

    fake_es = _make_mc_fake_es()
    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                pane = app.query_one(SplunkESPane)
                app.query_one("#es-auto-enrich-cb").value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                # Toggle sparkline strip
                await pilot.click("#es-sparkline-toggle-btn")
                await pilot.pause()
                strip = app.query_one("#es-sparkline-strip", Static)
                assert strip.display is True
                assert "Timeline [" in str(strip.render())

                # Step Next > and < Prev
                await pilot.click("#es-next-finding-btn")
                await pilot.pause()
                assert "BETA" in str(app.query_one("#es-detail-header", Static).render())
                await pilot.click("#es-prev-finding-btn")
                await pilot.pause()
                assert "ACME" in str(app.query_one("#es-detail-header", Static).render())

                # Multi-select pauses auto-refresh and reveals bulk bar
                await pilot.click("#es-auto-refresh-btn")
                await pilot.pause()
                assert pane._is_auto_refresh_paused() is False

                await pilot.click("#es-select-page-btn")
                await pilot.pause()
                assert app.query_one("#es-bulk-bar").display is True
                assert pane._is_auto_refresh_paused() is True

                await pilot.click("#es-deselect-btn")
                await pilot.pause()
                assert app.query_one("#es-bulk-bar").display is False

                # Save custom view and delete it
                await pilot.click("#es-save-view-btn")
                await pilot.pause()
                assert isinstance(app.screen, ESSavedViewModal)
                app.screen.query_one("#es-saved-view-name-input", Input).value = "My ACME Queue"
                await pilot.click("#es-saved-view-save-btn")
                await pilot.pause()
                assert "custom_my_acme_queue" in pane._custom_views

                await pilot.click("#es-del-view-btn")
                await pilot.pause()
                assert "custom_my_acme_queue" not in pane._custom_views

                # Switch item type pill to Investigations
                await pilot.click("#es-type-investigations-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                table = app.query_one("#es-table", DataTable)
                assert table.row_count == 1
                assert "Existing Investigation" in [str(c) for c in table.get_row_at(0)]

    asyncio.run(_run())


def test_tui_splunk_es_bulk_modals_and_80x24_layout(tmp_path: Path) -> None:
    from soclens.tui.screens.es_modals import (
        ESAdaptiveResponseModal,
        ESBulkTriageModal,
        ESCreateFindingModal,
        ESInvestigationModal,
        ESNoteModal,
    )

    fake_es = _make_mc_fake_es()
    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                app.query_one("#es-auto-enrich-cb").value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                # 1. Select row and run ESBulkTriageModal
                await pilot.click("#es-select-page-btn")
                await pilot.pause()
                await pilot.click("#es-bulk-triage-btn")
                await pilot.pause()
                assert isinstance(app.screen, ESBulkTriageModal)
                app.screen.query_one("#es-bulk-status-select", Select).value = "In Progress"
                app.screen.query_one("#es-bulk-note-input", Input).value = "Escalated"
                await pilot.click("#es-bulk-apply-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                fake_es.triage_findings_hybrid.assert_called()

                # 2. Open ESInvestigationModal and create investigation
                await pilot.click("#es-new-inv-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert isinstance(app.screen, ESInvestigationModal)
                app.screen.query_one("#es-inv-name-input", Input).value = "New Case 1"
                await pilot.click("#es-inv-submit-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                fake_es.create_investigation.assert_called_once()

                # 3. Open ESAdaptiveResponseModal and dispatch
                await pilot.click("#es-insp-ar-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert isinstance(app.screen, ESAdaptiveResponseModal)
                app.screen.query_one("#es-ar-params-input", Input).value = "risk_score=30"
                await pilot.click("#es-ar-dispatch-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                fake_es.dispatch_adaptive_response.assert_called_once()

                # 4. Open ESCreateFindingModal and submit
                await pilot.click("#es-create-finding-btn")
                await pilot.pause()
                assert isinstance(app.screen, ESCreateFindingModal)
                app.screen.query_one("#es-create-title-input", Input).value = "Manual Finding 1"
                app.screen.query_one("#es-create-tenant-input", Input).value = "ACME"
                await pilot.click("#es-create-submit-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                fake_es.create_finding.assert_called_once()

                # 5. Verify 80x24 clip-free bounds on every modal in es_modals.py
                await pilot.resize_terminal(80, 24)
                await pilot.pause()
                for modal, dialog_id, btn_id in (
                    (ESBulkTriageModal(event_ids=["e1"], dry_run=True), "#es-bulk-dialog", "#es-bulk-apply-btn"),
                    (ESInvestigationModal(finding_ids=["e1"], dry_run=True), "#es-inv-dialog", "#es-inv-submit-btn"),
                    (ESAdaptiveResponseModal(event_id="e1", orig_sid="s1", orig_rid="0", dry_run=True), "#es-ar-dialog", "#es-ar-dispatch-btn"),
                    (ESCreateFindingModal(dry_run=True), "#es-create-dialog", "#es-create-submit-btn"),
                    (ESNoteModal(event_id="e1", dry_run=True), "#es-note-dialog", "#es-note-submit-btn"),
                ):
                    app.push_screen(modal)
                    await pilot.pause()
                    dialog = app.screen.query_one(dialog_id)
                    btn = app.screen.query_one(btn_id)
                    assert dialog.region.width <= 80
                    assert dialog.region.height <= 24
                    assert btn.region.y + btn.region.height <= 24
                    await pilot.press("escape")
                    await pilot.pause()

    asyncio.run(_run())


def test_tui_splunk_es_pivots_accept_and_emit(tmp_path: Path) -> None:
    from soclens.config import PivotPayload

    fake_es = _make_mc_fake_es()
    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                pane = app.query_one(SplunkESPane)
                app.query_one("#es-auto-enrich-cb").value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                emitted: list[PivotPayload] = []
                app.dispatch_pivot = lambda payload: emitted.append(payload) or True  # type: ignore[attr-defined]

                # Pivot to F8 with orig_sid -> auto_run=True
                await pilot.click("#es-insp-pivot-search-btn")
                await pilot.pause()
                assert emitted[-1].target_tab == "tab-splunk-search"
                assert emitted[-1].orig_sid == "sid_orig_1"
                assert emitted[-1].auto_run is True

                # Pivot to F8 without orig_sid -> auto_run=False
                pane._displayed_rows[0]["orig_sid"] = ""
                if isinstance(pane._displayed_rows[0].get("raw"), dict):
                    pane._displayed_rows[0]["raw"].pop("orig_sid", None)
                await pilot.click("#es-insp-pivot-search-btn")
                await pilot.pause()
                assert emitted[-1].orig_sid is None
                assert emitted[-1].auto_run is False

                # Pivot to F7 Copilot -> bundled ES + Tenant context, auto_run=False
                await pilot.click("#es-insp-pivot-llm-btn")
                await pilot.pause()
                assert emitted[-1].target_tab == "tab-llm"
                assert emitted[-1].tenant_id == "ACME"
                assert emitted[-1].es_finding is not None
                assert emitted[-1].auto_run is False

                # Incoming accept_pivot from SentinelOne
                pane.accept_pivot(
                    PivotPayload(
                        source_tab="tab-sentinelone",
                        target_tab="tab-splunk-es",
                        tenant_id="ACME",
                        hostname="ws-01",
                        auto_run=True,
                    )
                )
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert "tenant_id:ACME" in app.query_one("#es-search-input", Input).value

    asyncio.run(_run())


def test_tui_splunk_es_pane_80x24_no_clipping_and_inspector_visible(tmp_path: Path) -> None:
    from textual.widget import Widget
    from textual.widgets import Button, Checkbox, RichLog

    def _is_actually_visible(widget: Widget) -> bool:
        for anc in widget.ancestors_with_self:
            if isinstance(anc, Widget) and not anc.display:
                return False
        return True

    fake_es = _make_mc_fake_es()
    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(80, 24)) as pilot:
                await pilot.pause()
                app.query_one("#es-auto-enrich-cb", Checkbox).value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                await pilot.click("#es-select-page-btn")
                await pilot.pause()

                pane = app.query_one(SplunkESPane)
                assert pane.has_class("es-compact")
                assert app.query_one("#es-bulk-bar").display is True

                checked = 0
                for widget in pane.query("*"):
                    if isinstance(
                        widget, (Button, Select, Input, Checkbox, DataTable, RichLog)
                    ) and _is_actually_visible(widget):
                        checked += 1
                        reg = widget.region
                        assert reg.x >= 0, f"{widget.id} x={reg.x} < 0"
                        assert reg.y >= 0, f"{widget.id} y={reg.y} < 0"
                        assert reg.x + reg.width <= 80, (
                            f"{widget.id} right={reg.x + reg.width} > 80 ({reg})"
                        )
                        assert reg.y + reg.height <= 24, (
                            f"{widget.id} bottom={reg.y + reg.height} > 24 ({reg})"
                        )
                        assert reg.width > 0, f"{widget.id} width <= 0"
                        assert reg.height > 0, f"{widget.id} height <= 0"

                assert checked > 40
                table_reg = app.query_one("#es-table", DataTable).region
                detail_reg = app.query_one("#es-detail", RichLog).region
                assert table_reg.height > 0 and table_reg.y + table_reg.height <= 24
                assert detail_reg.height > 0 and detail_reg.y + detail_reg.height <= 24

    asyncio.run(_run())


def test_tui_splunk_es_forwards_structured_and_custom_filters_to_hybrid(
    tmp_path: Path,
) -> None:
    from textual.widgets import Checkbox

    from soclens.config import PivotPayload

    fake_es = _make_mc_fake_es()
    captured_calls: list[dict[str, Any]] = []
    orig_side_effect = fake_es.query_findings_hybrid.side_effect

    def _capture_hybrid(**kwargs: Any) -> dict[str, Any]:
        captured_calls.append(dict(kwargs))
        return orig_side_effect(**kwargs)

    fake_es.query_findings_hybrid.side_effect = _capture_hybrid

    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(140, 40)) as pilot:
                await pilot.pause()
                pane = app.query_one(SplunkESPane)
                app.query_one("#es-auto-enrich-cb", Checkbox).value = False
                app.query_one("#es-filter-owner", Input).value = "alice"
                app.query_one("#es-filter-domain", Input).value = "network"
                app.query_one("#es-filter-min-score", Input).value = "50"
                app.query_one("#es-search-input", Input).value = (
                    "tenant_id:ACME snow_ticket:INC100 beacon"
                )
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert captured_calls
                last = captured_calls[-1]
                assert last["tenant_id"] == "ACME"
                assert last["owner"] == "alice"
                assert last["security_domain"] == "network"
                assert last["min_risk_score"] == 50.0
                assert last["search_text"] == "beacon"
                assert last["custom_filters"] == {"snow_ticket": "INC100"}

                # Pivot also forwards tenant_id and free indicator
                app.query_one("#es-filter-owner", Input).value = ""
                app.query_one("#es-filter-domain", Input).value = ""
                app.query_one("#es-filter-min-score", Input).value = ""
                pane.accept_pivot(
                    PivotPayload(
                        source_tab="tab-sentinelone",
                        target_tab="tab-splunk-es",
                        tenant_id="BETA",
                        hostname="ws-99",
                        auto_run=True,
                    )
                )
                await app.workers.wait_for_complete()
                await pilot.pause()
                piv_call = captured_calls[-1]
                assert piv_call["tenant_id"] == "BETA"
                assert piv_call["search_text"] == "ws-99"

    asyncio.run(_run())


def test_tui_splunk_es_mixed_case_pinned_field_and_grouped_pagination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from textual.widgets import Checkbox

    monkeypatch.setenv("SPLUNK_ES_CUSTOM_FIELDS", "snow_ticket")
    fake_es = MagicMock()
    fake_es.__enter__.return_value = fake_es
    fake_es.__exit__.return_value = None
    fake_es.list_notables.return_value = [
        {
            "event_id": "e-1",
            "rule_name": "Rule ACME",
            "urgency": "high",
            "status": 1,
            "status_label": "New",
            "tenant_id": "ACME",
            "Snow_Ticket": "INC777",
            "raw": {"event_id": "e-1", "Snow_Ticket": "INC777"},
        },
        {
            "event_id": "e-2",
            "rule_name": "Rule BETA",
            "urgency": "medium",
            "status": 1,
            "status_label": "New",
            "tenant_id": "BETA",
            "Snow_Ticket": "INC888",
            "raw": {"event_id": "e-2", "Snow_Ticket": "INC888"},
        },
    ]

    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                pane = app.query_one(SplunkESPane)
                app.query_one("#es-auto-enrich-cb", Checkbox).value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                table = app.query_one("#es-table", DataTable)
                row0 = [str(c) for c in table.get_row_at(0)]
                assert "INC777" in row0

                # Group by Tenant with page_size=2 -> 2 headers + 2 findings = 4 display items (2 pages)
                pane._page_size = 2
                await pilot.click("#es-group-tenant-btn")
                await pilot.pause()
                assert "Page 1/2" in str(app.query_one("#es-page-label", Static).render())
                await pilot.click("#es-next-page-btn")
                await pilot.pause()
                assert "Page 2/2" in str(app.query_one("#es-page-label", Static).render())

    asyncio.run(_run())


def test_tui_splunk_es_note_modal_rf_checkbox_and_enrich_seq_guard(
    tmp_path: Path,
) -> None:
    from textual.widgets import Checkbox

    from soclens.splunk_es import SplunkESClient
    from soclens.tui.screens.es_modals import ESNoteModal

    fake_rf = MagicMock()
    fake_rf.token = "rf-tok"
    fake_rf.soar_enrich.return_value = {"data": []}

    app = create_app(
        client=fake_rf,
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(SplunkESPane)

            # 1. ESNoteModal disables dual-post when has_rf_data=False and enables when True
            app.push_screen(ESNoteModal(event_id="e1", has_rf_data=False))
            await pilot.pause()
            cb_disabled = app.screen.query_one("#es-note-dual-rf-cb", Checkbox)
            assert cb_disabled.disabled is True
            assert "no RF data" in str(cb_disabled.label)
            await pilot.press("escape")
            await pilot.pause()

            app.push_screen(ESNoteModal(event_id="e1", has_rf_data=True))
            await pilot.pause()
            cb_enabled = app.screen.query_one("#es-note-dual-rf-cb", Checkbox)
            assert cb_enabled.disabled is False
            await pilot.press("escape")
            await pilot.pause()

            # 2. _post_note_worker passes use_mc_v2=True for SplunkESClient
            mock_splunk_client = MagicMock()
            mock_splunk_client.host = "https://splunk.local:8089"
            mock_splunk_client.app = "SplunkEnterpriseSecuritySuite"
            real_es = SplunkESClient(splunk_client=mock_splunk_client)
            real_es.create_note = MagicMock(return_value={"id": "n-1"})  # type: ignore[method-assign]
            with (
                patch.object(SplunkESPane, "_build_es_client", return_value=real_es),
                patch("soclens.tui.screens.splunk_es.write_enrichment_to_notable") as mock_write,
            ):
                pane._post_note_worker(
                    "ev-1",
                    {"event_id": "ev-1", "_time": "2026-11-24T12:00:00Z", "rf_observables": []},
                    {"content": "Note body", "title": None, "dual_post_rf": True},
                )
                await app.workers.wait_for_complete()
                await pilot.pause()
                mock_write.assert_called_once()
                assert mock_write.call_args.kwargs["use_mc_v2"] is True

            # 3. _enrich_notables_worker ignores stale sequence completion
            pane._current_view = "notables"
            pane._request_seq = 5
            stale_row = [{"event_id": "stale-1", "title": "Stale", "rf_observables": []}]
            fresh_row = [{"event_id": "fresh-1", "title": "Fresh"}]
            pane._populate_table(fresh_row, pane._get_notable_columns(), header_label="Notable Events")

            def _advance_and_enrich(rows: list[dict[str, Any]], **kwargs: Any) -> list[dict[str, Any]]:
                pane._request_seq = 6
                return stale_row

            pane._get_rf_enricher().enrich_events = _advance_and_enrich  # type: ignore[method-assign]
            pane._enrich_notables_worker(
                seq=5,
                rows=[dict(fresh_row[0])],
                row_index=None,
                field_map=None,
                include_private_ips=False,
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert [r["event_id"] for r in pane._raw_rows] == ["fresh-1"]

    asyncio.run(_run())


def test_tui_splunk_es_80x24_long_status_and_banners_clamp_and_restore(tmp_path: Path) -> None:
    from textual.widget import Widget
    from textual.widgets import Button, Checkbox, RichLog

    def _is_actually_visible(widget: Widget) -> bool:
        for anc in widget.ancestors_with_self:
            if isinstance(anc, Widget) and not anc.display:
                return False
        return True

    fake_es = _make_mc_fake_es()
    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(80, 24)) as pilot:
                await pilot.pause()
                app.query_one("#es-auto-enrich-cb", Checkbox).value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                pane = app.query_one(SplunkESPane)
                assert pane.has_class("es-compact")

                long_err = "[ERROR] " + ("long error message word " * 15)
                pane.set_status(long_err)
                pane.query_one("#es-summary-bar", Static).update("Summary " + ("banner word " * 15))
                pane.query_one("#es-table-header", Static).update("Table Header " + ("long title " * 12))
                pane.query_one("#es-detail-header", Static).update("Detail Header " + ("long title " * 12))
                await pilot.pause()

                for bar_id in (
                    "#es-status",
                    "#es-summary-bar",
                    "#es-table-header",
                    "#es-detail-header",
                ):
                    assert pane.query_one(bar_id, Static).region.height == 1, (
                        f"{bar_id} expanded beyond 1 line"
                    )

                for widget in pane.query("*"):
                    if isinstance(
                        widget, (Button, Select, Input, Checkbox, DataTable, RichLog)
                    ) and _is_actually_visible(widget):
                        reg = widget.region
                        assert reg.x >= 0 and reg.x + reg.width <= 80, (
                            f"{widget.id} out of horizontal bounds: {reg}"
                        )
                        assert reg.y >= 0 and reg.y + reg.height <= 24, (
                            f"{widget.id} out of vertical bounds: {reg}"
                        )
                        assert reg.width > 0 and reg.height > 0, (
                            f"{widget.id} collapsed: {reg}"
                        )

                insp_actions = pane.query_one("#es-inspector-actions").region
                assert insp_actions.y + insp_actions.height <= 24
                assert pane.query_one("#es-table", DataTable).region.y + pane.query_one("#es-table", DataTable).region.height <= 24
                assert pane.query_one("#es-detail", RichLog).region.y + pane.query_one("#es-detail", RichLog).region.height <= 24

                # Resize to large viewport and verify inline styles are cleared
                await pilot.resize_terminal(140, 40)
                await pilot.pause()
                assert not pane.has_class("es-compact")
                for bar_id in (
                    "#es-status",
                    "#es-summary-bar",
                    "#es-sparkline-strip",
                    "#es-table-header",
                    "#es-detail-header",
                ):
                    w = pane.query_one(bar_id, Static)
                    assert w.styles.inline.get_rule("height") is None
                    assert w.styles.inline.get_rule("max_height") is None
                    assert w.styles.inline.get_rule("overflow_y") is None

    asyncio.run(_run())


def test_tui_splunk_es_item_type_pill_reloads_from_investigations_and_pivot_hostname(
    tmp_path: Path,
) -> None:
    from textual.widgets import Checkbox

    fake_es = _make_mc_fake_es()
    finding_items = [
        dict(fake_es.query_findings_hybrid(item_type="all")["items"][0]),
        dict(fake_es.query_findings_hybrid(item_type="all")["items"][1]),
    ]
    group_item = {
        "event_id": "grp-1@@finding_group@@1",
        "finding_id": "grp-1@@finding_group@@1",
        "rule_title": "Grouped Host Risk",
        "rule_name": "grouped_host_risk",
        "urgency": "high",
        "status": 1,
        "status_label": "New",
        "owner": "unassigned",
        "tenant_id": "ACME",
        "item_type": "finding_group",
        "is_investigation": False,
        "source_backend": "mc_v2",
        "_time": "2026-11-24T12:05:00Z",
        "raw": {"event_id": "grp-1@@finding_group@@1", "tenant_id": "ACME"},
    }
    inv_items = list(fake_es.list_investigations.return_value)
    query_calls: list[str] = []

    def _query_side_effect(**kwargs: Any) -> dict[str, Any]:
        itype = str(kwargs.get("item_type") or "all")
        query_calls.append(itype)
        if itype == "investigations":
            rows = inv_items
        elif itype == "findings":
            rows = finding_items
        elif itype == "finding_groups":
            rows = [group_item]
        else:
            rows = [*finding_items, group_item]
        return {
            "items": rows,
            "total": len(rows),
            "offset": 0,
            "limit": 100,
            "source_backend": "mc_v2",
        }

    fake_es.query_findings_hybrid.side_effect = _query_side_effect

    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                pane = app.query_one(SplunkESPane)
                app.query_one("#es-auto-enrich-cb", Checkbox).value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                table = app.query_one("#es-table", DataTable)
                assert query_calls == ["all"]
                assert pane._loaded_item_type == "all"
                assert table.row_count == 3

                # Client-side filter from "all" -> "findings" -> "all" does not reload
                await pilot.click("#es-type-findings-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert query_calls == ["all"]
                assert table.row_count == 2

                await pilot.click("#es-type-all-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert query_calls == ["all"]
                assert table.row_count == 3

                # Switch to Investigations (reloads)
                await pilot.click("#es-type-investigations-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert query_calls == ["all", "investigations"]
                assert pane._loaded_item_type == "investigations"
                assert table.row_count == 1
                assert "Existing Investigation" in [str(c) for c in table.get_row_at(0)]

                # Switch back to Findings WITHOUT clicking #es-refresh-btn -> reloads!
                await pilot.click("#es-type-findings-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert query_calls == ["all", "investigations", "findings"]
                assert pane._loaded_item_type == "findings"
                assert table.row_count == 2

                # Switch from Findings -> All WITHOUT clicking #es-refresh-btn -> reloads!
                await pilot.click("#es-type-all-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert query_calls == ["all", "investigations", "findings", "all"]
                assert pane._loaded_item_type == "all"
                assert table.row_count == 3

                # Switch to Investigations, then Clear Filters WITHOUT clicking #es-refresh-btn -> reloads!
                await pilot.click("#es-type-investigations-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 1
                await pilot.click("#es-clear-filter-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert query_calls == [
                    "all",
                    "investigations",
                    "findings",
                    "all",
                    "investigations",
                    "all",
                ]
                assert table.row_count == 3

                # Verify _build_pivot_payload hostname fallback from risk_object
                p_host = pane._build_pivot_payload(
                    "tab-sentinelone",
                    {
                        "risk_object": "wkstn-1001-01.example.test",
                        "risk_object_type": "system",
                        "src": "198.51.100.10",
                    },
                )
                assert p_host.hostname == "wkstn-1001-01.example.test"

                p_ip = pane._build_pivot_payload(
                    "tab-sentinelone",
                    {
                        "risk_object": "203.0.113.45",
                        "risk_object_type": "system",
                        "src": "198.51.100.10",
                    },
                )
                assert p_ip.hostname is None

                p_user = pane._build_pivot_payload(
                    "tab-sentinelone",
                    {
                        "risk_object": "jdoe@example.test",
                        "risk_object_type": "user",
                        "src": "198.51.100.10",
                    },
                )
                assert p_user.hostname is None

    asyncio.run(_run())


def test_tui_splunk_es_preset_reload_from_investigations_and_pivot_user_dash(
    tmp_path: Path,
) -> None:
    from textual.widgets import Checkbox

    from soclens.config import get_splunk_es_tenant_settings

    fake_es = _make_mc_fake_es()
    finding_items = [
        dict(fake_es.query_findings_hybrid(item_type="all")["items"][0]),
        dict(fake_es.query_findings_hybrid(item_type="all")["items"][1]),
    ]
    inv_items = list(fake_es.list_investigations.return_value)
    inv_rows_ref: list[list[dict[str, Any]]] = [inv_items]
    query_calls: list[str] = []

    def _query_side_effect(**kwargs: Any) -> dict[str, Any]:
        itype = str(kwargs.get("item_type") or "all")
        query_calls.append(itype)
        rows = inv_rows_ref[0] if itype == "investigations" else finding_items
        return {
            "items": rows,
            "total": len(rows),
            "offset": 0,
            "limit": 100,
            "source_backend": "mc_v2",
        }

    fake_es.query_findings_hybrid.side_effect = _query_side_effect

    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                pane = app.query_one(SplunkESPane)
                app.query_one("#es-auto-enrich-cb", Checkbox).value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                table = app.query_one("#es-table", DataTable)
                assert query_calls == ["all"]

                # Switch to non-empty investigations, then built-in preset "active_24h"
                await pilot.click("#es-type-investigations-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert pane._loaded_item_type == "investigations"
                assert table.row_count == 1

                app.query_one("#es-preset-select", Select).value = "active_24h"
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert query_calls == ["all", "investigations", "all"]
                assert pane._item_type == "all"
                assert pane._loaded_item_type == "all"
                assert table.row_count >= 1

                # Switch to EMPTY investigations (0 rows), then built-in preset "all"
                inv_rows_ref[0] = []
                await pilot.click("#es-type-investigations-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert pane._loaded_item_type == "investigations"
                assert table.row_count == 0

                app.query_one("#es-preset-select", Select).value = "all"
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert query_calls == ["all", "investigations", "all", "investigations", "all"]
                assert pane._item_type == "all"
                assert pane._loaded_item_type == "all"
                assert table.row_count == 2

                # Placeholder "-" in dest_host must not become hostname
                p_dash = pane._build_pivot_payload(
                    "tab-sentinelone",
                    {"dest_host": "-", "src": "198.51.100.10"},
                )
                assert p_dash.hostname is None

                # Local username placed into row["entity"] by _prepare_notable_display_row
                prepared = pane._prepare_notable_display_row(
                    {"event_id": "e1", "user": "jdoe"},
                    (),
                    get_splunk_es_tenant_settings(),
                )
                assert prepared["entity"] == "jdoe"
                p_local_user = pane._build_pivot_payload("tab-sentinelone", prepared)
                assert p_local_user.hostname is None

                # DOMAIN\user string must not become hostname
                p_dom_user = pane._build_pivot_payload(
                    "tab-sentinelone",
                    {"risk_object": r"CORP\jdoe", "src": "198.51.100.10"},
                )
                assert p_dom_user.hostname is None

    asyncio.run(_run())


def test_es_modals_on_mount_shutdown_guard_and_ar_close_btn(tmp_path: Path) -> None:
    from unittest.mock import PropertyMock

    from textual.widgets import Button

    from soclens.tui.screens.es_modals import (
        ESAdaptiveResponseModal,
        ESBulkTriageModal,
        ESCreateFindingModal,
        ESInvestigationModal,
        ESNoteModal,
        ESSavedViewModal,
    )

    modals = [
        ESBulkTriageModal(event_ids=["e1"], dry_run=True),
        ESInvestigationModal(finding_ids=["e1"], dry_run=True),
        ESAdaptiveResponseModal(event_id="e1", orig_sid="s1", orig_rid="0", dry_run=True),
        ESCreateFindingModal(dry_run=True),
        ESSavedViewModal(default_name="My View"),
        ESNoteModal(event_id="e1", dry_run=True),
    ]
    for fake_app in (
        MagicMock(is_running=False, _exit=False),
        MagicMock(is_running=True, _exit=True),
    ):
        for modal in modals:
            with patch.object(type(modal), "app", new_callable=PropertyMock, return_value=fake_app):
                modal.on_mount()

    fake_es = _make_mc_fake_es()
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(80, 24)) as pilot:
                await pilot.pause()
                dismissed: list[dict[str, Any] | None] = []
                ar_modal = ESAdaptiveResponseModal(
                    event_id="e1",
                    orig_sid="s1",
                    orig_rid="0",
                    available_actions=[{"name": "ping", "label": "Ping Host"}],
                    dry_run=True,
                )
                await app.push_screen(ar_modal, dismissed.append)
                await pilot.pause()
                assert app.screen is ar_modal
                assert app.focused is ar_modal.query_one("#es-ar-action-select", Select)
                ar_modal.query_one("#es-ar-close-btn", Button).press()
                await pilot.pause()
                assert dismissed == [None]

    asyncio.run(_run())

