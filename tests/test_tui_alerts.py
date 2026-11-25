"""Pilot and unit tests for Alerts on-screen auto-enrichment and multi-status filtering."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from textual.widgets import Button, DataTable, Static

from soclens.tui import create_app
from soclens.tui.rf_formatters import normalize_status_key, status_matches_filter


def test_status_normalization_and_multi_status_matching() -> None:
    assert normalize_status_key("InProgress") == "inprogress"
    assert normalize_status_key("In Progress") == "inprogress"
    assert normalize_status_key("in_progress") == "inprogress"
    assert normalize_status_key("in-progress") == "inprogress"

    assert status_matches_filter("New", []) is True
    assert status_matches_filter("In Progress", ["InProgress"]) is True
    assert status_matches_filter("in_progress", ["InProgress", "Pending"]) is True
    assert status_matches_filter("Pending", ["New", "InProgress"]) is False
    assert status_matches_filter("Resolved", ["New", "Resolved"]) is True


def test_tui_alerts_multi_status_filter_client_and_server_queries(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.api_token = "tok-alerts"

    all_alerts = [
        {
            "id": "al-new",
            "title": "New Critical Alert",
            "type": "ENTITY_MATCH",
            "review": {"priority": "High", "status_in_portal": "New", "assignee": "alice"},
            "rule": {"id": "r1", "name": "Rule 1"},
            "log": {"triggered": "2026-11-24T12:00:00Z"},
            "hits": [],
        },
        {
            "id": "al-inprog",
            "title": "In Progress Investigation",
            "type": "ENTITY_MATCH",
            "review": {"priority": "Moderate", "status_in_portal": "In Progress", "assignee": "bob"},
            "rule": {"id": "r2", "name": "Rule 2"},
            "log": {"triggered": "2026-11-24T11:00:00Z"},
            "hits": [],
        },
        {
            "id": "al-pending",
            "title": "Pending Review Hit",
            "type": "ENTITY_MATCH",
            "review": {"priority": "Low", "status_in_portal": "Pending", "assignee": "carol"},
            "rule": {"id": "r3", "name": "Rule 3"},
            "log": {"triggered": "2026-11-24T10:00:00Z"},
            "hits": [],
        },
        {
            "id": "al-resolved",
            "title": "Resolved Old Hit",
            "type": "ENTITY_MATCH",
            "review": {"priority": "Low", "status_in_portal": "Resolved", "assignee": "dan"},
            "rule": {"id": "r4", "name": "Rule 4"},
            "log": {"triggered": "2026-11-23T09:00:00Z"},
            "hits": [],
        },
    ]

    def _search_v3(**kwargs: Any) -> dict[str, Any]:
        st = kwargs.get("status_in_portal")
        if st is None:
            return {"data": all_alerts, "counts": {"returned": len(all_alerts), "total": len(all_alerts)}}
        matched = [
            it
            for it in all_alerts
            if normalize_status_key(it["review"]["status_in_portal"]) == normalize_status_key(st)
        ]
        return {"data": matched, "counts": {"returned": len(matched), "total": len(matched)}}

    mock_client.search_alerts_v3.side_effect = _search_v3
    mock_client.search_playbook_alerts.return_value = {
        "data": [
            {
                "playbook_alert_id": "pb-1",
                "category": "domain_abuse",
                "status": "New",
                "priority": "High",
                "title": "lookalike-new.test",
                "assignee": "alice",
            },
            {
                "playbook_alert_id": "pb-2",
                "category": "malicious_sites",
                "status": "InProgress",
                "priority": "Moderate",
                "title": "malware-inprog.test",
                "assignee": "bob",
            },
        ],
        "counts": {"returned": 2, "total": 2},
    }
    mock_client.search_cases.return_value = {
        "data": [
            {"id": "c-1", "title": "Open Case", "status": "Open", "priority": "High", "assignee": "bob", "description": "desc"},
            {"id": "c-2", "title": "Closed Case", "status": "Closed", "priority": "Low", "assignee": "eve", "description": "done"},
        ],
        "total_count": 2,
    }

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 38)) as pilot:
            await pilot.pause()

            # Load all Alerts v3 (4 rows)
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            table = app.query_one("#rf-results-table", DataTable)
            assert table.row_count == 4

            # Select InProgress + Pending simultaneously -> normalizes "In Progress" AND shows both!
            await pilot.click("#rf-st-inprogress")
            await pilot.pause()
            assert table.row_count == 1
            assert "In Progress Investigation" in [str(c) for c in table.get_row_at(0)]

            await pilot.click("#rf-st-pending")
            await pilot.pause()
            assert table.row_count == 2
            titles = [str(table.get_row_at(i)[3]) for i in range(table.row_count)]
            assert "In Progress Investigation" in titles
            assert "Pending Review Hit" in titles
            assert "Resolved Old Hit" not in titles
            assert app.query_one("#rf-st-all", Button).variant == "default"
            assert app.query_one("#rf-st-inprogress", Button).variant == "primary"
            assert app.query_one("#rf-st-pending", Button).variant == "primary"

            # Reloading Alerts v3 with multi-status active sends status_in_portal per selected status
            mock_client.search_alerts_v3.reset_mock()
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            called_statuses = {
                call.kwargs.get("status_in_portal")
                for call in mock_client.search_alerts_v3.call_args_list
            }
            assert called_statuses == {"InProgress", "Pending"}
            assert table.row_count == 2

            # Playbook Alerts sends statuses=["InProgress", "Pending"] server-side
            await pilot.click("#rf-pb-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            pb_kwargs = mock_client.search_playbook_alerts.call_args.kwargs
            assert pb_kwargs["statuses"] == ["InProgress", "Pending"]
            assert table.row_count == 1
            assert "malware-inprog.test" in [str(c) for c in table.get_row_at(0)]

            # Clicking All restores both playbook alerts; selecting Open on Cases filters Cases
            await pilot.click("#rf-st-all")
            await pilot.pause()
            assert table.row_count == 2
            assert app.query_one("#rf-st-all", Button).variant == "primary"

            await pilot.click("#rf-st-open")
            await pilot.pause()
            await pilot.click("#rf-cases-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.search_cases.call_args.kwargs["statuses"] == ["Open"]
            assert table.row_count == 1
            assert "Open Case" in [str(c) for c in table.get_row_at(0)]

    asyncio.run(_run())


def test_tui_alerts_auto_enrich_on_screen_assignee_and_toggle(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.api_token = "tok-enrich"

    mock_client.search_alerts_v3.return_value = {
        "data": [
            {
                "id": "al-missing",
                "title": "Unenriched Classic Hit",
                "type": "ENTITY_MATCH",
                "review": {"priority": "High", "status_in_portal": "New"},
                "rule": {"id": "r1", "name": "Rule Alpha"},
                "log": {"triggered": "2026-11-24T12:00:00Z"},
                "hits": [],
            }
        ],
        "counts": {"returned": 1, "total": 1},
    }
    mock_client.get_alert_v3.return_value = {
        "data": {
            "id": "al-missing",
            "title": "Unenriched Classic Hit",
            "review": {"priority": "High", "status_in_portal": "InProgress", "assignee": "alice_soc"},
            "rule": {"id": "r1", "name": "Rule Alpha"},
            "log": {"triggered": "2026-11-24T12:00:00Z"},
            "hits": [],
        }
    }

    mock_client.search_playbook_alerts.return_value = {
        "data": [
            {
                "playbook_alert_id": "pb-enr-1",
                "category": "domain_abuse",
                "status": "New",
                "priority": "High",
                "title": "phish-login.example",
            }
        ],
        "counts": {"returned": 1, "total": 1},
    }
    mock_client.get_playbook_alert.return_value = {
        "status": {"status_code": "Ok"},
        "data": {
            "playbook_alert_id": "pb-enr-1",
            "panel_status": {
                "status": "InProgress",
                "priority": "High",
                "assignee_name": "bob_analyst",
                "entity_name": "phish-login.example",
                "targets": ["mybank.com"],
            },
            "panel_evidence_summary": {"screenshots": ["shot-should-not-download"]},
        },
    }

    mock_client.search_cases.return_value = {
        "data": [{"id": "case-enr-1", "title": "Incident Case", "status": "Open", "priority": "High"}],
        "total_count": 1,
    }
    mock_client.lookup_cases.return_value = {
        "data": [
            {
                "id": "case-enr-1",
                "title": "Incident Case",
                "status": "Open",
                "priority": "High",
                "assignee": "carol_ir",
                "description": "Auto-loaded incident context",
            }
        ]
    }

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()

            # 1. Alerts v3 automatically fetches detail for unassigned visible alert -> shows Assignee column
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_alert_v3.assert_called_once_with("al-missing")
            table = app.query_one("#rf-results-table", DataTable)
            row_vals = [str(c) for c in table.get_row_at(0)]
            assert "alice_soc" in row_vals
            assert "InProgress" in row_vals

            # 2. Playbook Alerts automatically preloads full details and precaches screenshots
            await pilot.click("#rf-pb-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_playbook_alert.assert_called_once_with(
                "domain_abuse", "pb-enr-1"
            )
            mock_client.get_playbook_alert_image.assert_called_once_with(
                "domain_abuse", "pb-enr-1", "shot-should-not-download"
            )
            pb_row = [str(c) for c in table.get_row_at(0)]
            assert "bob_analyst" in pb_row
            assert "InProgress" in pb_row

            # 3. Cases automatically batch-enriches assignee & description via lookup_cases
            await pilot.click("#rf-cases-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.lookup_cases.assert_called_once_with(["case-enr-1"])
            assert "carol_ir" in [str(c) for c in table.get_row_at(0)]

            # 4. Turning Auto-Enrich OFF prevents automatic detail calls on reload
            await pilot.click("#rf-auto-enrich-btn")
            await pilot.pause()
            assert "OFF" in str(app.query_one("#rf-auto-enrich-btn", Button).label)
            mock_client.get_alert_v3.reset_mock()
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.get_alert_v3.call_count == 0
            assert "paused" in str(app.query_one("#rf-status", Static).render()).lower() or "Loaded" in str(
                app.query_one("#rf-status", Static).render()
            )

    asyncio.run(_run())
