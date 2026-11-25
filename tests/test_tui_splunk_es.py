"""Textual Pilot tests for SplunkESPane, SplunkNotableTriageModal, ConfirmActionModal, and dry-run."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

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
