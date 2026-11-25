"""Textual Pilot tests for SentinelOnePane, SentinelOne modals, and safety guardrails."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

from textual.widgets import Button, Input, Select

from soclens.tui.app import create_app
from soclens.tui.modals import (
    ConfirmActionModal,
    S1AddBlocklistModal,
    S1CreateExclusionModal,
    S1ThreatTriageModal,
)
from soclens.tui.screens.base import DoubleClickDataTable
from soclens.tui.screens.sentinelone import SentinelOnePane


def _make_mock_s1_client() -> MagicMock:
    s1 = MagicMock()
    s1.console_url = "https://tenant.sentinelone.net"
    s1.check_connection.return_value = {"build": "24.2.1"}
    s1.list_agents.return_value = [
        {
            "id": "ag-101",
            "computerName": "FIN-WKSTN-01",
            "osName": "Windows 11",
            "lastIpToMgmt": "10.0.1.25",
            "networkStatus": "connected",
            "infected": True,
            "siteName": "Finance",
        }
    ]
    s1.list_threats.return_value = [
        {
            "id": "th-202",
            "threatInfo": {
                "threatName": "CobaltStrike.Beacon",
                "analystVerdict": "undefined",
                "incidentStatus": "unresolved",
                "mitigationStatus": "active",
                "createdAt": "2026-11-24T10:00:00Z",
            },
            "agentRealtimeInfo": {"agentComputerName": "FIN-WKSTN-01"},
        }
    ]
    s1.list_exclusions.return_value = [
        {
            "id": "ex-303",
            "type": "path",
            "osType": "windows",
            "value": r"C:\Tools\audit.exe",
            "mode": "suppress",
            "description": "SOC tool",
        }
    ]
    s1.list_blocklist.return_value = [
        {
            "id": "bl-404",
            "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "osType": "windows",
            "source": "soclens",
            "description": "Known malware",
        }
    ]
    s1.list_sites.return_value = [
        {"id": "site-1", "name": "Finance", "state": "active", "updatedAt": "2026-11-24T00:00:00Z"}
    ]
    s1.list_activities.return_value = [
        {
            "id": "act-1",
            "primaryDescription": "Agent isolated",
            "siteName": "Finance",
            "createdAt": "2026-11-24T12:00:00Z",
        }
    ]
    s1.disconnect_agent.return_value = {"data": {"affected": 1}}
    s1.mitigate_threat.return_value = {"data": {"affected": 1}}
    s1.update_threat_verdict.return_value = {"data": {"affected": 1}}
    s1.update_threat_incident_status.return_value = {"data": {"affected": 1}}
    s1.add_threat_note.return_value = {"data": {"affected": 1}}
    s1.create_exclusion.return_value = {"data": {"id": "ex-new"}}
    s1.delete_exclusions.return_value = {"data": {"affected": 1}}
    s1.add_to_blocklist.return_value = {"data": {"id": "bl-new"}}
    s1.remove_from_blocklist.return_value = {"data": {"affected": 1}}
    return s1


def test_s1_pane_views_and_refresh(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            table = pane.query_one("#s1-table", DoubleClickDataTable)

            # Endpoints view refresh
            await pilot.click("#s1-refresh-btn")
            await pilot.pause(0.2)
            assert table.row_count == 1
            s1.list_agents.assert_called_once()

            # Switch to Threats view
            pane.query_one("#s1-view-select", Select).value = "threats"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause(0.2)
            assert table.row_count == 1
            s1.list_threats.assert_called_once()

            # Switch to Exclusions view
            pane.query_one("#s1-view-select", Select).value = "exclusions"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause(0.2)
            assert table.row_count == 1
            s1.list_exclusions.assert_called_once()

            # Switch to Blocklist view
            pane.query_one("#s1-view-select", Select).value = "blocklist"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause(0.2)
            assert table.row_count == 1
            s1.list_blocklist.assert_called_once()

            # Switch to Sites & Activities view
            pane.query_one("#s1-view-select", Select).value = "sites_activities"
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause(0.2)
            assert table.row_count == 1
            s1.list_sites.assert_called_once()

            await pilot.click("#s1-activities-btn")
            await pilot.pause(0.2)
            assert table.row_count == 1
            s1.list_activities.assert_called_once()

    asyncio.run(_run())


def test_s1_confirm_action_modal_guardrail_cancel_and_approve(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause(0.2)

            # Click Isolate -> ConfirmActionModal must open; Cancel blocks API call
            await pilot.click("#s1-isolate-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-cancel-btn")
            await pilot.pause(0.1)
            s1.disconnect_agent.assert_not_called()

            # Click Isolate again -> Approve executes disconnect_agent
            await pilot.click("#s1-isolate-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause(0.2)
            s1.disconnect_agent.assert_called_once_with(["ag-101"])

    asyncio.run(_run())


def test_s1_threat_triage_modal_applies_verdict_status_and_note(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            pane.query_one("#s1-view-select", Select).value = "threats"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause(0.2)

            await pilot.click("#s1-triage-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1ThreatTriageModal)

            app.screen.query_one("#s1-triage-verdict-select", Select).value = "true_positive"
            app.screen.query_one("#s1-triage-status-select", Select).value = "resolved"
            app.screen.query_one("#s1-triage-note-input", Input).value = "Contained by SOC"
            await pilot.click("#s1-triage-apply-btn")
            await pilot.pause(0.2)

            s1.update_threat_verdict.assert_called_once_with(["th-202"], "true_positive")
            s1.update_threat_incident_status.assert_called_once_with(["th-202"], "resolved")
            s1.add_threat_note.assert_called_once_with("th-202", "Contained by SOC")

    asyncio.run(_run())


def test_s1_exclusion_and_blocklist_modals(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)

            # Create exclusion modal
            pane.query_one("#s1-view-select", Select).value = "exclusions"
            await pilot.pause()
            await pilot.click("#s1-create-excl-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1CreateExclusionModal)
            app.screen.query_one("#s1-excl-value-input", Input).value = r"C:\Safe\app.exe"
            app.screen.query_one("#s1-excl-desc-input", Input).value = "Verified internal tool"
            await pilot.click("#s1-excl-create-btn")
            await pilot.pause(0.2)
            s1.create_exclusion.assert_called_once()

            # Add blocklist modal
            pane.query_one("#s1-view-select", Select).value = "blocklist"
            await pilot.pause()
            await pilot.click("#s1-add-block-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1AddBlocklistModal)
            valid_sha1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
            app.screen.query_one("#s1-block-hash-input", Input).value = valid_sha1
            app.screen.query_one("#s1-block-desc-input", Input).value = "Malicious payload"
            await pilot.click("#s1-block-add-btn")
            await pilot.pause(0.2)
            s1.add_to_blocklist.assert_called_once_with(
                valid_sha1,
                os_type="windows",
                description="Malicious payload",
            )

    asyncio.run(_run())


def test_s1_dry_run_blocks_all_active_and_destructive_actions(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            await pilot.click("#s1-refresh-btn")
            await pilot.pause(0.2)

            # Isolate blocked in dry-run without opening ConfirmActionModal or calling API
            await pilot.click("#s1-isolate-btn")
            await pilot.pause(0.1)
            assert not isinstance(app.screen, ConfirmActionModal)
            s1.disconnect_agent.assert_not_called()

            # Switch to threats and test Quarantine + Triage in dry-run
            pane.query_one("#s1-view-select", Select).value = "threats"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause(0.2)

            await pilot.click("#s1-quarantine-btn")
            await pilot.pause(0.1)
            assert not isinstance(app.screen, ConfirmActionModal)
            s1.mitigate_threat.assert_not_called()

            # Triage modal opens with dry-run banner, applying does NOT call API
            await pilot.click("#s1-triage-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1ThreatTriageModal)
            app.screen.query_one("#s1-triage-verdict-select", Select).value = "false_positive"
            app.screen.query_one("#s1-triage-apply-btn", Button).press()
            await pilot.pause(0.2)
            s1.update_threat_verdict.assert_not_called()

    asyncio.run(_run())
