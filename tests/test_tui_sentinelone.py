"""Textual Pilot tests for SentinelOnePane, SentinelOne modals, and safety guardrails."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

from textual.widgets import Button, Checkbox, Input, Select, Static

from soclens.tui.app import create_app
from soclens.tui.modals import (
    ConfirmActionModal,
    S1AddBlocklistModal,
    S1CreateExclusionModal,
    S1ThreatTriageModal,
)
from soclens.tui.pivot import PivotPayload
from soclens.tui.screens.base import DoubleClickDataTable
from soclens.tui.screens.s1_modals import (
    CloneExclusionsModal,
    ConfirmDeleteSiteModal,
    S1EditExclusionModal,
    S1MoveAgentModal,
    S1SiteModal,
    S1SitePolicyModal,
    S1UserModal,
)
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
    s1.add_threat_to_exclusions.return_value = {"data": {"affected": 1}}
    s1.create_exclusion.return_value = {"data": {"id": "ex-new"}}
    s1.delete_exclusions.return_value = {"data": {"affected": 1}}
    s1.add_to_blocklist.return_value = {"data": {"id": "bl-new"}}
    s1.remove_from_blocklist.return_value = {"data": {"affected": 1}}
    s1.list_cloud_alerts.return_value = [
        {
            "id": "ca-505",
            "alertInfo": {
                "alertId": "ca-505",
                "incidentStatus": "UNRESOLVED",
                "analystVerdict": "UNDEFINED",
                "createdAt": "2026-11-24T13:00:00Z",
            },
            "ruleInfo": {"name": "STAR: Unusual Script", "severity": "High"},
            "agentDetectionInfo": {
                "siteId": "site-1",
                "siteName": "MDR-1234",
                "agentComputerName": "FIN-WKSTN-01",
            },
        }
    ]
    s1.normalize_alert.side_effect = lambda rec, **kw: {
        "id": rec.get("id", "ca-505"),
        "recordType": "cloud_alert",
        "title": rec.get("ruleInfo", {}).get("name", "Cloud Alert"),
        "severity": "High",
        "incidentStatus": "unresolved",
        "analystVerdict": "undefined",
        "mitigationStatus": "cloud_alert",
        "siteId": "site-1",
        "siteName": "MDR-1234",
        "tier": "MDR",
        "tenantId": "1234",
        "computerName": "FIN-WKSTN-01",
        "sha1": "",
        "createdAt": "2026-11-24T13:00:00Z",
    }
    s1.list_users.return_value = [
        {
            "id": "usr-1",
            "fullName": "SOC Admin",
            "email": "soc@example.com",
            "scope": "account",
            "twoFaEnabled": True,
        }
    ]
    s1.list_service_users.return_value = [
        {
            "id": "svc-1",
            "name": "soclens-automation",
            "scope": "site",
            "expirationDate": "2027-12-31T00:00:00Z",
        }
    ]
    s1.list_rbac_roles.return_value = [
        {"id": "role-1", "name": "IR Team", "scope": "site", "predefinedRole": True}
    ]
    s1.delete_site.return_value = {"data": {"success": True}}
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
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_agents.assert_called_once()

            # Switch to Threats view
            pane.query_one("#s1-view-select", Select).value = "threats"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_threats.assert_called_once()

            # Switch to Exclusions view
            pane.query_one("#s1-view-select", Select).value = "exclusions"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_exclusions.assert_called_once()

            # Switch to Blocklist view
            pane.query_one("#s1-view-select", Select).value = "blocklist"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_blocklist.assert_called_once()

            # Switch to Sites & Activities view
            pane.query_one("#s1-view-select", Select).value = "sites_activities"
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_sites.assert_called_once()

            await pilot.click("#s1-activities-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
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
            await app.workers.wait_for_complete()
            await pilot.pause()

            # Click Isolate -> ConfirmActionModal must open; Cancel blocks API call
            await pilot.click("#s1-isolate-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-cancel-btn")
            await pilot.pause()
            s1.disconnect_agent.assert_not_called()

            # Click Isolate again -> Approve executes disconnect_agent
            await pilot.click("#s1-isolate-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
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
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-triage-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1ThreatTriageModal)

            app.screen.query_one("#s1-triage-verdict-select", Select).value = "true_positive"
            app.screen.query_one("#s1-triage-status-select", Select).value = "resolved"
            app.screen.query_one("#s1-triage-note-input", Input).value = "Contained by SOC"
            await pilot.click("#s1-triage-apply-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

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

            # In default User View, exclusion and blocklist mutations must be blocked
            pane.query_one("#s1-view-select", Select).value = "exclusions"
            await pilot.pause()
            await pilot.click("#s1-create-excl-btn")
            await pilot.pause()
            assert not isinstance(app.screen, S1CreateExclusionModal)
            s1.create_exclusion.assert_not_called()

            pane.query_one("#s1-view-select", Select).value = "blocklist"
            await pilot.pause()
            await pilot.click("#s1-add-block-btn")
            await pilot.pause()
            assert not isinstance(app.screen, S1AddBlocklistModal)
            s1.add_to_blocklist.assert_not_called()

            # Toggle Admin View (F2) -> exclusion & blocklist modals execute cleanly
            await pilot.press("f2")
            await pilot.pause()
            assert app.is_admin_view is True

            # Create exclusion modal
            pane.query_one("#s1-view-select", Select).value = "exclusions"
            await pilot.pause()
            await pilot.click("#s1-create-excl-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1CreateExclusionModal)
            app.screen.query_one("#s1-excl-value-input", Input).value = r"C:\Safe\app.exe"
            app.screen.query_one("#s1-excl-desc-input", Input).value = "Verified internal tool"
            await pilot.click("#s1-excl-create-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
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
            await app.workers.wait_for_complete()
            await pilot.pause()
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
            await app.workers.wait_for_complete()
            await pilot.pause()

            # Isolate blocked in dry-run without opening ConfirmActionModal or calling API
            await pilot.click("#s1-isolate-btn")
            await pilot.pause()
            assert not isinstance(app.screen, ConfirmActionModal)
            s1.disconnect_agent.assert_not_called()

            # Switch to threats and test Quarantine + Triage in dry-run
            pane.query_one("#s1-view-select", Select).value = "threats"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-quarantine-btn")
            await pilot.pause()
            assert not isinstance(app.screen, ConfirmActionModal)
            s1.mitigate_threat.assert_not_called()

            # Triage modal opens with dry-run banner, applying does NOT call API
            await pilot.click("#s1-triage-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1ThreatTriageModal)
            app.screen.query_one("#s1-triage-verdict-select", Select).value = "false_positive"
            app.screen.query_one("#s1-triage-apply-btn", Button).press()
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1.update_threat_verdict.assert_not_called()

    asyncio.run(_run())


def test_s1_all_five_subworkbenches_read_only_in_user_view(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            table = pane.query_one("#s1-table", DoubleClickDataTable)

            # 1: Alerts & Threats (Endpoint + Cloud)
            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_threats.assert_called_once()

            pane.query_one("#s1-alert-source-select", Select).value = "cloud"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_cloud_alerts.assert_called_once()

            # 2: Sites Admin (read-only list in User View)
            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_sites.assert_called_once()

            # 3: Users & RBAC (Console, Service, Roles read-only in User View)
            await pilot.click("#s1-wb-users-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_users.assert_called_once()

            pane.query_one("#s1-users-mode-select", Select).value = "service"
            await pilot.pause()
            await pilot.click("#s1-users-load-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1.list_service_users.assert_called_once()

            pane.query_one("#s1-users-mode-select", Select).value = "roles"
            await pilot.pause()
            await pilot.click("#s1-users-load-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1.list_rbac_roles.assert_called_once()

            # 4: Exclusions & Clone (read-only list in User View)
            await pilot.click("#s1-wb-exclusions-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_exclusions.assert_called_once()

            # 5: Agents & Blocklist
            await pilot.click("#s1-wb-agents-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            s1.list_agents.assert_called_once()

    asyncio.run(_run())


def test_s1_admin_view_gating_and_confirm_delete_site_modal(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    s1.list_sites.return_value = [
        {"id": "site-mdr", "name": "MDR-1234", "state": "active", "activeLicenses": 12}
    ]
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()

            # User View blocks Move Site & Decommission on Agents
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.click("#s1-move-agent-btn")
            await pilot.click("#s1-decommission-btn")
            await pilot.pause()
            s1.move_agents_to_site.assert_not_called()
            s1.decommission_agents.assert_not_called()

            # User View blocks Site Create & Delete
            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.click("#s1-site-create-btn")
            await pilot.click("#s1-site-delete-btn")
            await pilot.pause()
            assert not isinstance(app.screen, ConfirmDeleteSiteModal)
            s1.delete_site.assert_not_called()

            # Toggle Admin View (F2) -> Delete Site opens ConfirmDeleteSiteModal
            await pilot.press("f2")
            await pilot.pause()
            await pilot.click("#s1-site-delete-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmDeleteSiteModal)

            # Wrong site name keeps modal open and blocks delete_site
            app.screen.query_one("#s1-del-site-confirm-input", Input).value = "MDR-wrong"
            await pilot.click("#s1-del-site-approve-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmDeleteSiteModal)
            s1.delete_site.assert_not_called()

            # Exact site name unlocks deletion
            app.screen.query_one("#s1-del-site-confirm-input", Input).value = "MDR-1234"
            await pilot.click("#s1-del-site-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1.delete_site.assert_called_once_with(
                "site-mdr",
                confirm_site_name="MDR-1234",
                expected_site_name="MDR-1234",
            )

    asyncio.run(_run())


def test_s1_tier_filter_pills_and_four_grouping_modes(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    shared_sha1 = "a" * 40
    s1.list_threats.return_value = [
        {
            "id": "th-mdr",
            "threatInfo": {
                "threatName": "SharedDropper",
                "sha1": shared_sha1,
                "incidentStatus": "unresolved",
                "confidenceLevel": "malicious",
            },
            "agentRealtimeInfo": {
                "siteId": "s-mdr",
                "siteName": "MDR-1234",
                "agentComputerName": "MDR-HOST-01",
            },
        },
        {
            "id": "th-mssp",
            "threatInfo": {
                "threatName": "SharedDropper",
                "sha1": shared_sha1,
                "incidentStatus": "unresolved",
                "confidenceLevel": "malicious",
            },
            "agentRealtimeInfo": {
                "siteId": "s-mssp",
                "siteName": "MSSP-8298",
                "agentComputerName": "MSSP-HOST-02",
            },
        },
        {
            "id": "th-other",
            "threatInfo": {
                "threatName": "OtherAlert",
                "sha1": "b" * 40,
                "incidentStatus": "resolved",
            },
            "agentRealtimeInfo": {
                "siteId": "s-other",
                "siteName": "Default site",
                "agentComputerName": "LAB-HOST-03",
            },
        },
    ]
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
            table = pane.query_one("#s1-table", DoubleClickDataTable)

            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 3

            # Tier pills filter accurately
            await pilot.click("#s1-tier-mdr-btn")
            await pilot.pause()
            assert table.row_count == 1
            await pilot.click("#s1-tier-mssp-btn")
            await pilot.pause()
            assert table.row_count == 1
            await pilot.click("#s1-tier-other-btn")
            await pilot.pause()
            assert table.row_count == 1
            await pilot.click("#s1-tier-all-btn")
            await pilot.pause()
            assert table.row_count == 3

            # Mode 2: Service Tier grouping (3 groups)
            pane.query_one("#s1-grouping-select", Select).value = "tier"
            await pilot.pause()
            assert table.row_count == 3
            assert len(pane._table_rows) == 3
            assert all(r.get("_is_group_header") for r in pane._table_rows)

            # Mode 3: Site grouping (3 sites)
            pane.query_one("#s1-grouping-select", Select).value = "site"
            await pilot.pause()
            assert table.row_count == 3

            # Mode 4: Tier + SHA1 grouping keeps MDR and MSSP strictly partitioned!
            pane.query_one("#s1-grouping-select", Select).value = "tier_hash"
            await pilot.pause()
            assert table.row_count == 3
            group_labels = [r.get("_group_label") for r in pane._table_rows]
            assert f"MDR | {shared_sha1}" in group_labels
            assert f"MSSP | {shared_sha1}" in group_labels

            # Selecting / activating first group header expands its rows
            pane._expanded_groups.add(str(pane._table_rows[0]["_group_key"]))
            pane._apply_local_filter()
            await pilot.pause()
            assert table.row_count == 4

    asyncio.run(_run())


def test_s1_clone_exclusions_modal_dry_run_diff_and_execute(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    s1.list_sites.return_value = [
        {"id": "site-100", "name": "MDR-100", "state": "active"},
        {"id": "site-200", "name": "MDR-200", "state": "active"},
    ]
    s1.plan_clone_exclusions.return_value = {
        "source_site_id": "site-100",
        "source_site_name": "MDR-100",
        "target_site_id": "site-200",
        "will_create": [
            {
                "source": {"type": "path", "value": r"C:\Tools\new.exe"},
                "payload": {
                    "exclusion_type": "path",
                    "os_type": "windows",
                    "value": r"C:\Tools\new.exe",
                    "mode": "suppress",
                    "description": "Approved [Cloned from MDR-100]",
                },
            }
        ],
        "skipped_duplicate": [{"source": {"type": "path", "value": r"C:\Tools\dup.exe"}}],
        "inherited_from_account": [{"source": {"type": "white_hash", "value": "a" * 40}}],
        "counts": {
            "will_create": 1,
            "skipped_duplicate": 1,
            "inherited_from_account": 1,
        },
    }
    s1.clone_exclusions.return_value = {
        "counts": {
            "created": 1,
            "skipped_duplicate": 1,
            "inherited_from_account": 1,
            "failed": 0,
        }
    }

    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            # Load sites first so selector is populated
            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-wb-exclusions-btn")
            await pilot.pause()
            await pilot.click("#s1-clone-excl-btn")
            await pilot.pause()
            assert isinstance(app.screen, CloneExclusionsModal)

            app.screen.query_one("#s1-clone-src-select", Select).value = "site-100"
            app.screen.query_one("#s1-clone-dst-select", Select).value = "site-200"
            await pilot.click("#s1-clone-preview-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1.plan_clone_exclusions.assert_called_once()

            await pilot.click("#s1-clone-apply-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1.clone_exclusions.assert_called_once()
            call_kwargs = s1.clone_exclusions.call_args.kwargs
            assert call_kwargs["dry_run"] is False
            assert call_kwargs["requests_per_second"] == 15.0

    asyncio.run(_run())


def test_s1_pivot_bus_accept_and_emit(tmp_path: Path) -> None:
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

            # Accept incoming pivot from Splunk ES with SHA1 + tier
            incoming = PivotPayload(
                source_tab="tab-splunk-es",
                target_tab="tab-sentinelone",
                tenant_id="1234",
                tier="MDR",
                sha1="a" * 40,
                auto_run=True,
            )
            pane.accept_pivot(incoming)
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane._current_view == "threats"
            assert pane._tier_filter == "MDR"
            assert pane.query_one("#s1-filter-input", Input).value == "a" * 40
            s1.list_threats.assert_called_once()

            # Emit pivots via app.dispatch_pivot
            dispatched: list[PivotPayload] = []
            app.dispatch_pivot = lambda payload: dispatched.append(payload) or True  # type: ignore[method-assign]
            pane._selected_record = {
                "id": "th-pivot",
                "threatInfo": {"sha1": "c" * 40, "threatName": "Mimikatz"},
                "agentRealtimeInfo": {
                    "siteId": "site-mdr",
                    "siteName": "MDR-1234",
                    "agentComputerName": "FIN-WKSTN-01",
                },
            }
            for target in (
                "tab-splunk-es",
                "tab-splunk-search",
                "tab-rf-intel",
                "tab-research",
                "tab-llm",
            ):
                pane._emit_pivot_target(target)

            assert [p.target_tab for p in dispatched] == [
                "tab-splunk-es",
                "tab-splunk-search",
                "tab-rf-intel",
                "tab-research",
                "tab-llm",
            ]
            assert dispatched[0].tenant_id == "1234"
            assert dispatched[0].tier == "MDR"
            assert dispatched[1].auto_run is False  # Splunk Search never auto-runs
            assert dispatched[4].auto_run is False  # LLM never auto-sends

    asyncio.run(_run())


def test_s1_action_bars_single_visible_and_80x24_bounds(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            action_bars = (
                "#s1-actions-endpoints",
                "#s1-actions-threats",
                "#s1-actions-exclusions",
                "#s1-actions-blocklist",
                "#s1-actions-sites",
                "#s1-actions-users",
            )
            for view in (
                "endpoints",
                "threats",
                "exclusions",
                "blocklist",
                "sites_activities",
                "users_rbac",
            ):
                pane.query_one("#s1-view-select", Select).value = view
                await pilot.pause()
                visible_bars = [sel for sel in action_bars if pane.query_one(sel).display]
                assert len(visible_bars) == 1, f"{view} visible bars={visible_bars}"
                for w in pane.walk_children():
                    if not w.display:
                        continue
                    if any(not getattr(anc, "display", True) for anc in w.ancestors):
                        continue
                    if w.id in ("s1-detail-pane", "s1-detail-header", "s1-detail-log", "s1-workspace"):
                        continue
                    r = w.region
                    assert r.x >= 0 and r.y >= 0, f"{view} {w.id} negative origin {r}"
                    assert r.right <= 80, f"{view} {w.id} clipped right {r}"
                    assert r.bottom <= 24, f"{view} {w.id} clipped bottom {r}"

            sites = [{"id": "s1", "name": "MDR-100"}, {"id": "s2", "name": "MSSP-200"}]
            modals = [
                ConfirmDeleteSiteModal(site_id="s1", site_name="MDR-100"),
                CloneExclusionsModal(sites=sites),
                S1SiteModal(mode="create", sites=sites),
                S1SitePolicyModal(site_id="s1", site_name="MDR-100", policy={"a": 1}, sites=sites),
                S1UserModal(mode="create", kind="console", sites=sites),
                S1MoveAgentModal(agent_summary="ag-1", sites=sites),
                S1EditExclusionModal(
                    exclusion={"id": "e1", "type": "path", "osType": "windows", "value": r"C:\a"}
                ),
            ]
            for modal in modals:
                app.push_screen(modal)
                await pilot.pause()
                scr = app.screen
                for w in scr.walk_children():
                    if not w.display:
                        continue
                    if any(anc.id and anc.id.endswith("-scroll") for anc in w.ancestors):
                        continue
                    r = w.region
                    assert r.x >= 0 and r.y >= 0, f"{type(modal).__name__} {w.id} negative {r}"
                    assert r.right <= 80, f"{type(modal).__name__} {w.id} clipped right {r}"
                    assert r.bottom <= 24, f"{type(modal).__name__} {w.id} clipped bottom {r}"
                app.pop_screen()
                await pilot.pause()

    asyncio.run(_run())


def test_s1_live_admin_badge_and_modal_edge_validation(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            badge = pane.query_one("#s1-admin-badge", Static)
            assert "User View" in str(badge.render())

            # F2 immediately updates #s1-admin-badge without clicking Refresh
            await pilot.press("f2")
            await pilot.pause()
            assert "Admin View: ON" in str(badge.render())

            await pilot.press("f2")
            await pilot.pause()
            assert "User View" in str(badge.render())

            # ConfirmDeleteSiteModal must reject leading/trailing whitespace
            dismissed: list[bool | None] = []
            app.push_screen(
                ConfirmDeleteSiteModal(site_id="s1", site_name="MDR-100"),
                dismissed.append,
            )
            await pilot.pause()
            for bad in (" MDR-100", "MDR-100 ", "mdr-100"):
                app.screen.query_one("#s1-del-site-confirm-input", Input).value = bad
                await pilot.click("#s1-del-site-approve-btn")
                await pilot.pause()
                assert isinstance(app.screen, ConfirmDeleteSiteModal)
            app.screen.query_one("#s1-del-site-confirm-input", Input).value = "MDR-100"
            await pilot.click("#s1-del-site-approve-btn")
            await pilot.pause()
            assert dismissed == [True]

            # CloneExclusionsModal must reject NaN / inf RPS
            clone_dismissed: list[dict[str, object] | None] = []
            app.push_screen(
                CloneExclusionsModal(
                    sites=[{"id": "s1", "name": "MDR-100"}, {"id": "s2", "name": "MDR-200"}]
                ),
                clone_dismissed.append,
            )
            await pilot.pause()
            for bad_rps in ("nan", "inf", "0"):
                app.screen.query_one("#s1-clone-rps-input", Input).value = bad_rps
                await pilot.click("#s1-clone-apply-btn")
                await pilot.pause()
                assert isinstance(app.screen, CloneExclusionsModal)
            app.pop_screen()
            await pilot.pause()

    asyncio.run(_run())


def test_s1_pivot_edge_cases_row_kind_guards_and_mixed_group_triage(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    shared_sha1 = "a" * 40
    s1.list_unified_alerts.return_value = [
        {
            "id": "th-mix-1",
            "recordType": "threat",
            "title": "MixedThreat",
            "sha1": shared_sha1,
            "tier": "MDR",
            "siteId": "s-mdr",
            "siteName": "MDR-100",
            "incidentStatus": "unresolved",
            "analystVerdict": "undefined",
        },
        {
            "id": "ca-mix-1",
            "recordType": "cloud_alert",
            "title": "MixedCloud",
            "sha1": shared_sha1,
            "tier": "MDR",
            "siteId": "s-mdr",
            "siteName": "MDR-100",
            "incidentStatus": "unresolved",
            "analystVerdict": "undefined",
        },
    ]
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)

            # Pivot edge cases: lowercase tier, whitespace sha1, stale site_id reset
            pane.accept_pivot(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-sentinelone",
                    tier="mdr",
                    sha1="   ",
                    site_id="s-1",
                    hostname="HOST-1",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane._current_view == "endpoints"
            assert pane._tier_filter == "MDR"
            assert pane._selected_site_ids == {"s-1"}

            pane.accept_pivot(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-sentinelone",
                    tier="mssp",
                    site_id="   ",
                    hostname="HOST-2",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane._tier_filter == "MSSP"
            assert pane._selected_site_ids == set()

            # Activity row must be blocked by Site Delete / Edit handlers
            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-activities-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.click("#s1-site-delete-btn")
            await pilot.click("#s1-site-edit-btn")
            await pilot.pause()
            assert not isinstance(app.screen, (ConfirmDeleteSiteModal, S1SiteModal))
            s1.delete_site.assert_not_called()

            # RBAC Role row must be blocked by User Delete / Edit handlers
            await pilot.click("#s1-wb-users-btn")
            await pilot.pause()
            pane.query_one("#s1-users-mode-select", Select).value = "roles"
            await pilot.pause()
            await pilot.click("#s1-users-load-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.click("#s1-user-delete-btn")
            await pilot.click("#s1-user-edit-btn")
            await pilot.pause()
            assert not isinstance(app.screen, (ConfirmActionModal, S1UserModal))
            s1.delete_user.assert_not_called()

            # Mixed tier_hash group partitions threat vs cloud_alert cleanly
            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-clear-filter-btn")
            await pilot.pause()
            pane.query_one("#s1-alert-source-select", Select).value = "unified"
            pane.query_one("#s1-grouping-select", Select).value = "tier_hash"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-triage-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1ThreatTriageModal)
            app.screen.query_one("#s1-triage-verdict-select", Select).value = "true_positive"
            app.screen.query_one("#s1-triage-status-select", Select).value = "resolved"
            app.screen.query_one("#s1-triage-note-input", Input).value = "Triaged group"
            await pilot.click("#s1-triage-apply-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            s1.update_threat_verdict.assert_called_once_with(["th-mix-1"], "true_positive")
            s1.update_cloud_alert_verdict.assert_called_once_with(["ca-mix-1"], "true_positive")
            s1.update_threat_incident_status.assert_called_once_with(["th-mix-1"], "resolved")
            s1.update_cloud_alert_incident_status.assert_called_once_with(
                ["ca-mix-1"], "resolved"
            )
            s1.add_threat_note.assert_called_once_with("th-mix-1", "Triaged group")

            # Mitigate Kill on mixed group only sends endpoint threat ID
            await pilot.click("#s1-kill-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1.mitigate_threat.assert_called_once_with(["th-mix-1"], "kill")

    asyncio.run(_run())


def test_s1_threat_exclude_guards_cloud_alerts_and_partitions_mixed_group(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    shared_sha1 = "b" * 40
    s1.list_unified_alerts.return_value = [
        {
            "id": "ca-only-1",
            "recordType": "cloud_alert",
            "title": "PureCloudAlert",
            "sha1": "c" * 40,
            "tier": "MDR",
            "siteId": "s-mdr",
            "siteName": "MDR-100",
            "incidentStatus": "unresolved",
            "analystVerdict": "undefined",
        },
        {
            "id": "ca-mix-head",
            "recordType": "cloud_alert",
            "title": "MixedGroupCloudFirst",
            "sha1": shared_sha1,
            "tier": "MDR",
            "siteId": "s-mdr",
            "siteName": "MDR-100",
            "incidentStatus": "unresolved",
            "analystVerdict": "undefined",
        },
        {
            "id": "th-mix-a",
            "recordType": "threat",
            "title": "MixedThreatA",
            "sha1": shared_sha1,
            "tier": "MDR",
            "siteId": "s-mdr",
            "siteName": "MDR-100",
            "incidentStatus": "unresolved",
            "analystVerdict": "undefined",
        },
        {
            "id": "th-mix-b",
            "recordType": "threat",
            "title": "MixedThreatB",
            "sha1": shared_sha1,
            "tier": "MDR",
            "siteId": "s-mdr",
            "siteName": "MDR-100",
            "incidentStatus": "unresolved",
            "analystVerdict": "undefined",
        },
    ]
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)

            # 1: Pure cloud_alert row (single row selected) must NOT open ConfirmActionModal
            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            pane.query_one("#s1-alert-source-select", Select).value = "cloud"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-threat-exclude-btn")
            await pilot.pause()
            assert not isinstance(app.screen, ConfirmActionModal)
            s1.add_threat_to_exclusions.assert_not_called()

            # 2: Mixed tier_hash group (with cloud_alert first in group) passes all ep_ids only
            pane.query_one("#s1-alert-source-select", Select).value = "unified"
            pane.query_one("#s1-grouping-select", Select).value = "tier_hash"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = pane.query_one("#s1-table", DoubleClickDataTable)
            # First group has pure cloud alert (ca-only-1), second group has mixed (ca-mix-head, th-mix-a, th-mix-b)
            # Test group 0 (pure cloud_alert group) first, then move to group 1 (mixed group)
            table.move_cursor(row=0)
            await pilot.pause()
            assert pane._selected_record is not None
            assert len(pane._selected_record.get("_group_records", [])) == 1
            await pilot.click("#s1-threat-exclude-btn")
            await pilot.pause()
            assert not isinstance(app.screen, ConfirmActionModal)
            s1.add_threat_to_exclusions.assert_not_called()

            table.move_cursor(row=1)
            await pilot.pause()
            assert pane._selected_record is not None
            assert len(pane._selected_record.get("_group_records", [])) == 3
            await pilot.click("#s1-threat-exclude-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1.add_threat_to_exclusions.assert_called_once_with(["th-mix-a", "th-mix-b"])

    asyncio.run(_run())


def test_s1_threat_exclude_worker_normalizes_and_guards_blank_ids(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            status = pane.query_one("#s1-status", Static)

            for empty_input in ([], "", "   ", ["", "   "], None, b"th-1"):
                worker = pane._threat_exclude_worker(empty_input)  # type: ignore[arg-type]
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert worker.error is None
                s1.add_threat_to_exclusions.assert_not_called()
                assert "No valid endpoint threat IDs selected to exclude." in str(status.render())

            worker = pane._threat_exclude_worker(["  th-1 ", "", "th-2"])
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert worker.error is None
            s1.add_threat_to_exclusions.assert_called_once_with(["th-1", "th-2"])

    asyncio.run(_run())


def test_s1_triage_threat_worker_guards_none_bytes_and_normalizes_ids(tmp_path: Path) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            status = pane.query_one("#s1-status", Static)

            for empty_ids in ([None, "  "], ["  "], [], None, b"th-1"):
                worker = pane._triage_threat_worker(
                    empty_ids,  # type: ignore[arg-type]
                    "true_positive",
                    "resolved",
                    "note",
                )
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert worker.error is None
                s1.update_threat_verdict.assert_not_called()
                s1.update_cloud_alert_verdict.assert_not_called()
                s1.update_threat_incident_status.assert_not_called()
                s1.update_cloud_alert_incident_status.assert_not_called()
                s1.add_threat_note.assert_not_called()
                assert "No valid alert or threat IDs selected to triage." in str(status.render())

            worker = pane._triage_threat_worker(
                ["  th-1 ", None, ""],  # type: ignore[list-item]
                "true_positive",
                "resolved",
                "Confirmed",
                cloud_alert_ids=[" ca-1 ", None],  # type: ignore[list-item]
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert worker.error is None
            s1.update_threat_verdict.assert_called_once_with(["th-1"], "true_positive")
            s1.update_cloud_alert_verdict.assert_called_once_with(["ca-1"], "true_positive")
            s1.update_threat_incident_status.assert_called_once_with(["th-1"], "resolved")
            s1.update_cloud_alert_incident_status.assert_called_once_with(["ca-1"], "resolved")
            s1.add_threat_note.assert_called_once_with("th-1", "Confirmed")

    asyncio.run(_run())


def test_s1_user_modal_edit_preserves_scope_roles_and_site_modal_rejects_unicode_digits(
    tmp_path: Path,
) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)

            # 1: S1UserModal(mode="edit") pre-populates existing roleId & site ID even when omitted from options
            captured: list[dict[str, object] | None] = []
            app.push_screen(
                S1UserModal(
                    mode="edit",
                    kind="console",
                    user={
                        "id": "u-1",
                        "fullName": "Analyst",
                        "email": "a@example.com",
                        "scope": "site",
                        "scopeRoles": [
                            {"id": "site-1", "roleId": "role-ir", "roleName": "IR Team"}
                        ],
                        "twoFaEnabled": True,
                    },
                    roles=[],
                    sites=[],
                ),
                captured.append,
            )
            await pilot.pause()
            assert isinstance(app.screen, S1UserModal)
            assert app.screen.query_one("#s1-user-role-select", Select).value == "role-ir"
            assert app.screen.query_one("#s1-user-site-select", Select).value == "site-1"
            await pilot.click("#s1-user-save-btn")
            await pilot.pause()
            assert len(captured) == 1
            assert captured[0] is not None
            assert captured[0]["role_id"] == "role-ir"
            assert captured[0]["target_site_ids"] == ["site-1"]

            # 2: _user_mutation_worker(mode="edit") preserves sanitized scopeRoles when role_id/template empty
            worker = pane._user_mutation_worker(
                {
                    "mode": "edit",
                    "kind": "console",
                    "user_id": "u-1",
                    "name": "Analyst Updated",
                    "email": "a@example.com",
                    "scope": "site",
                    "role_id": "",
                    "template_user_id": "",
                    "target_site_ids": [],
                    "two_fa_enabled": True,
                    "existing_scope_roles": [
                        {"id": "site-1", "roleId": "role-ir", "name": "Ignored"}
                    ],
                }
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert worker.error is None
            s1.update_user.assert_called_once_with(
                "u-1",
                scope="site",
                scope_roles=[{"roleId": "role-ir", "id": "site-1"}],
                full_name="Analyst Updated",
                email="a@example.com",
                two_fa_enabled=True,
            )

            # 3: S1SiteModal rejects Unicode non-ASCII digits like "²" with a validation message
            app.push_screen(S1SiteModal(mode="create", sites=[]))
            await pilot.pause()
            assert isinstance(app.screen, S1SiteModal)
            app.screen.query_one("#s1-site-name-input", Input).value = "MDR-999"
            app.screen.query_one("#s1-site-unlimited-cb", Checkbox).value = False
            app.screen.query_one("#s1-site-licenses-input", Input).value = "²"
            await pilot.click("#s1-site-save-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1SiteModal)
            err_text = str(app.screen.query_one("#s1-site-error", Static).render())
            assert "valid integer license count" in err_text
            await pilot.click("#s1-site-cancel-btn")
            await pilot.pause()

            # 4: _is_cloud_alert_record detects raw ruleInfo-only Cloud/STAR records
            assert pane._is_cloud_alert_record({"id": "ca-raw", "ruleInfo": {"name": "STAR rule"}})
            assert not pane._is_cloud_alert_record(
                {"id": "th-raw", "ruleInfo": {"name": "x"}, "threatInfo": {"threatName": "Mal"}}
            )

    asyncio.run(_run())


def test_s1_add_blocklist_worker_passes_selected_site_ids_and_pivot_host_entity(
    tmp_path: Path,
) -> None:
    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)

            # 1: Non-empty _selected_site_ids scopes add_to_blocklist with sorted site_ids
            pane._selected_site_ids = {"100102"}
            valid_sha1 = "b94a8fe5ccb19ba61c4c0873d391e987982fbbd4"
            worker = pane._add_blocklist_worker(
                {
                    "value": valid_sha1,
                    "os_type": "windows",
                    "description": "Site-scoped block",
                }
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert worker.error is None
            s1.add_to_blocklist.assert_called_once_with(
                valid_sha1,
                os_type="windows",
                description="Site-scoped block",
                site_ids=["100102"],
            )

            # 2: accept_pivot treats non-IP host-typed entity as hostname before src_ip
            pane.accept_pivot(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-sentinelone",
                    entity="wkstn-1001-01.example.test",
                    entity_type="system",
                    src_ip="198.51.100.10",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane.query_one("#s1-filter-input", Input).value == "wkstn-1001-01.example.test"

            # 3: accept_pivot does NOT treat IP or user email entity as hostname before src_ip
            pane.accept_pivot(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-sentinelone",
                    entity="203.0.113.45",
                    entity_type="system",
                    src_ip="198.51.100.10",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane.query_one("#s1-filter-input", Input).value == "198.51.100.10"

            pane.accept_pivot(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-sentinelone",
                    entity="jdoe@example.test",
                    entity_type="user",
                    src_ip="198.51.100.10",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane.query_one("#s1-filter-input", Input).value == "198.51.100.10"

            # 4: accept_pivot ignores "-" placeholder values and falls back to src_ip / dest_ip
            pane.accept_pivot(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-sentinelone",
                    hostname=None,
                    entity="-",
                    entity_type="system",
                    src_ip="10.0.0.5",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane.query_one("#s1-filter-input", Input).value == "10.0.0.5"

            pane.accept_pivot(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-sentinelone",
                    hostname="-",
                    entity="-",
                    entity_type="system",
                    src_ip="-",
                    dest_ip="10.0.0.8",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane.query_one("#s1-filter-input", Input).value == "10.0.0.8"

            # 5: handle_add_blocklist modal flow snapshots selected site_ids on UI thread
            s1.add_to_blocklist.reset_mock()
            pane._selected_site_ids = {"100102", "100101"}
            pane.query_one("#s1-view-select", Select).value = "blocklist"
            await pilot.pause()
            await pilot.click("#s1-add-block-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1AddBlocklistModal)
            sha1_ui = "c94a8fe5ccb19ba61c4c0873d391e987982fbbd5"
            app.screen.query_one("#s1-block-hash-input", Input).value = sha1_ui
            app.screen.query_one("#s1-block-desc-input", Input).value = "UI scoped block"
            await pilot.click("#s1-block-add-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1.add_to_blocklist.assert_called_once_with(
                sha1_ui,
                os_type="windows",
                description="UI scoped block",
                site_ids=["100101", "100102"],
            )

    asyncio.run(_run())


def test_s1_modals_on_mount_shutdown_guard_and_normal_focus(tmp_path: Path) -> None:
    from unittest.mock import PropertyMock, patch

    sites = [{"id": "s1", "name": "MDR-100"}, {"id": "s2", "name": "MSSP-200"}]
    modals = [
        ConfirmDeleteSiteModal(site_id="s1", site_name="MDR-100"),
        CloneExclusionsModal(sites=sites),
        S1SiteModal(mode="create", sites=sites),
        S1SitePolicyModal(site_id="s1", site_name="MDR-100", policy={"a": 1}, sites=sites),
        S1UserModal(mode="edit", kind="console", user={"id": "u1"}, sites=sites),
        S1MoveAgentModal(agent_summary="ag-1", sites=sites),
        S1EditExclusionModal(
            exclusion={"id": "e1", "type": "path", "osType": "windows", "value": r"C:\a"}
        ),
    ]
    for fake_app in (
        MagicMock(is_running=False, _exit=False),
        MagicMock(is_running=True, _exit=True),
    ):
        for modal in modals:
            with patch.object(type(modal), "app", new_callable=PropertyMock, return_value=fake_app):
                modal.on_mount()

    s1 = _make_mock_s1_client()
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            del_modal = ConfirmDeleteSiteModal(site_id="s1", site_name="MDR-100", dry_run=True)
            await app.push_screen(del_modal)
            await pilot.pause()
            assert app.screen is del_modal
            assert app.focused is del_modal.query_one("#s1-del-site-cancel-btn", Button)
            del_modal.query_one("#s1-del-site-cancel-btn", Button).press()
            await pilot.pause()

    asyncio.run(_run())





