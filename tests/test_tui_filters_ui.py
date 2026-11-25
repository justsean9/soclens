"""Comprehensive unit and Pilot tests for TUI timeframes, filter facets, presets, and UI layout."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from textual.widgets import Button, Collapsible, DataTable, Input, RichLog, Select, Static

from soclens.tui import SaveFilterPresetModal, create_app
from soclens.tui.filters import (
    BUILTIN_RF_PRESETS,
    FilterPreset,
    assignee_matches_filter,
    build_alerts_v3_triggered_param,
    build_case_date_range,
    build_playbook_date_range,
    compute_timeframe_bounds,
    delete_custom_rf_preset,
    extract_item_timestamp,
    get_all_rf_presets,
    load_custom_rf_presets,
    map_priority_for_cases,
    map_priority_for_playbook,
    priority_matches_filter,
    save_custom_rf_preset,
    sort_rf_items,
    timeframe_label,
    timestamp_matches_timeframe,
)
from soclens.tui.logging_bridge import LogEntry
from soclens.tui.screens.base import extract_richlog_text
from soclens.tui.screens.dashboard import DashboardPane
from soclens.tui.screens.logs import LogsPane
from soclens.tui.screens.research import ResearchPane
from soclens.tui.screens.sigma import SigmaPane
from soclens.tui.screens.splunk_bundle import SplunkBundlePane
from soclens.tui.screens.splunk_es import SplunkESPane
from soclens.tui.screens.splunk_search import SplunkSearchPane


def _iso_hours_ago(hours: float, *, now: datetime | None = None) -> str:
    ref = (now or datetime.now(UTC)).astimezone(UTC)
    return (ref - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Unit tests: soclens.tui.filters
# ---------------------------------------------------------------------------


def test_compute_timeframe_bounds_and_matching() -> None:
    fixed_now = datetime(2026, 11, 24, 18, 0, 0, tzinfo=UTC)
    assert compute_timeframe_bounds("any", now_utc=fixed_now) == (None, None)

    start_24h, end_24h = compute_timeframe_bounds("last_24h", now_utc=fixed_now)
    assert start_24h == fixed_now - timedelta(hours=24)
    assert end_24h is None

    start_old7, end_old7 = compute_timeframe_bounds("older_7d", now_utc=fixed_now)
    assert start_old7 is None
    assert end_old7 == fixed_now - timedelta(days=7)

    assert timestamp_matches_timeframe("2026-11-24T12:00:00Z", "last_24h", now_utc=fixed_now) is True
    assert timestamp_matches_timeframe("2026-11-22T12:00:00Z", "last_24h", now_utc=fixed_now) is False
    assert timestamp_matches_timeframe("2026-11-20T12:00:00Z", "last_7d", now_utc=fixed_now) is True
    assert timestamp_matches_timeframe("2026-11-10T12:00:00Z", "last_7d", now_utc=fixed_now) is False

    # Older > 7d and Older > 30d cleanup filters
    assert timestamp_matches_timeframe("2026-11-10T12:00:00Z", "older_7d", now_utc=fixed_now) is True
    assert timestamp_matches_timeframe("2026-11-20T12:00:00Z", "older_7d", now_utc=fixed_now) is False
    assert timestamp_matches_timeframe("2026-10-01T12:00:00Z", "older_30d", now_utc=fixed_now) is True
    assert timestamp_matches_timeframe("2026-11-10T12:00:00Z", "older_30d", now_utc=fixed_now) is False

    # Custom date bounds (ISO date inclusive end-of-day, relative tokens, invalid ts)
    assert (
        timestamp_matches_timeframe(
            "2026-11-15T23:30:00Z",
            "custom",
            date_from="2026-11-10",
            date_to="2026-11-15",
            now_utc=fixed_now,
        )
        is True
    )
    assert (
        timestamp_matches_timeframe(
            "2026-11-22T12:00:00Z",
            "custom",
            date_from="-3d",
            date_to="-1d",
            now_utc=fixed_now,
        )
        is True
    )
    assert timestamp_matches_timeframe("not-a-timestamp", "last_7d", now_utc=fixed_now) is False
    assert timestamp_matches_timeframe("", "any", now_utc=fixed_now) is True
    assert "Older > 7d" == timeframe_label("older_7d")


def test_priority_assignee_sorting_and_server_builders() -> None:
    assert priority_matches_filter("Critical", "high_crit") is True
    assert priority_matches_filter("High", "high_crit") is True
    assert priority_matches_filter("Moderate", "high_crit") is False
    assert priority_matches_filter("Medium", "moderate") is True
    assert priority_matches_filter("Informational", "low_info") is True
    assert priority_matches_filter("Critical", "critical") is True

    assert assignee_matches_filter("Unassigned", "unassigned") is True
    assert assignee_matches_filter("", "unassigned") is True
    assert assignee_matches_filter("alice@corp.local", "unassigned") is False
    assert assignee_matches_filter("alice@corp.local", "assigned") is True
    assert assignee_matches_filter("alice@corp.local", "ALICE@corp.local") is True

    items = [
        {"id": "1", "priority": "Low", "status": "Resolved", "triggered": "2026-11-24T08:00:00Z"},
        {"id": "2", "priority": "Critical", "status": "New", "triggered": "2026-11-22T08:00:00Z"},
        {"id": "3", "priority": "High", "status": "InProgress", "triggered": "2026-11-24T12:00:00Z"},
    ]
    assert [it["id"] for it in sort_rf_items(items, "alerts_v3", "newest")] == ["3", "1", "2"]
    assert [it["id"] for it in sort_rf_items(items, "alerts_v3", "oldest")] == ["2", "1", "3"]
    assert [it["id"] for it in sort_rf_items(items, "alerts_v3", "priority_desc")] == ["2", "3", "1"]
    assert [it["id"] for it in sort_rf_items(items, "alerts_v3", "status")] == ["2", "3", "1"]
    assert extract_item_timestamp(items[0], "alerts_v3", "created") == "2026-11-24T08:00:00Z"

    fixed_now = datetime(2026, 11, 24, 18, 0, 0, tzinfo=UTC)
    assert build_alerts_v3_triggered_param("any", now_utc=fixed_now) is None
    assert (
        build_alerts_v3_triggered_param("last_24h", now_utc=fixed_now)
        == "[2026-11-23T18:00:00Z,]"
    )
    assert (
        build_alerts_v3_triggered_param("older_7d", now_utc=fixed_now)
        == "[,2026-11-17T18:00:00Z]"
    )
    assert build_playbook_date_range("last_7d", now_utc=fixed_now) == {
        "from": "2026-11-17T18:00:00Z"
    }
    assert build_case_date_range("older_30d", now_utc=fixed_now) == {
        "before": "2026-10-25T18:00:00Z"
    }
    assert map_priority_for_playbook("high_crit") == ["High"]
    assert map_priority_for_cases("high_crit") == ["Critical", "High"]
    assert map_priority_for_cases("any") is None


def test_custom_preset_persistence_roundtrip(tmp_path: Path) -> None:
    assert load_custom_rf_presets(workspace_dir=tmp_path) == []
    preset = FilterPreset(
        id="custom_shift_triage",
        label="Shift Triage (High 48h)",
        statuses=("New", "InProgress"),
        priority="high_crit",
        timeframe="last_48h",
        assignee="unassigned",
        sort_by="priority_desc",
    )
    saved = save_custom_rf_preset(preset, workspace_dir=tmp_path)
    assert len(saved) == 1
    assert saved[0].label == "Shift Triage (High 48h)"

    all_presets = get_all_rf_presets(workspace_dir=tmp_path)
    assert len(all_presets) == len(BUILTIN_RF_PRESETS) + 1
    assert all_presets[-1].id == "custom_shift_triage"

    # Attempt to overwrite a built-in ID creates a custom ID rather than clobbering
    clobber_attempt = FilterPreset(id="active_7d", label="My Active 7d")
    after_second = save_custom_rf_preset(clobber_attempt, workspace_dir=tmp_path)
    assert all(p.id != "active_7d" for p in after_second)

    remaining = delete_custom_rf_preset("custom_shift_triage", workspace_dir=tmp_path)
    assert all(p.id != "custom_shift_triage" for p in remaining)


# ---------------------------------------------------------------------------
# Pilot tests: RFIntelPane presets, timeframes, facets & custom preset modal
# ---------------------------------------------------------------------------


def test_tui_rf_intel_presets_cleanup_filters_and_custom_preset(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.api_token = "tok-rf-filters"

    sample_alerts = [
        {
            "id": "al-fresh-24h",
            "title": "Fresh C2 Beacon",
            "type": "ENTITY_MATCH",
            "review": {"priority": "High", "status_in_portal": "New", "assignee": "alice"},
            "rule": {"id": "r1", "name": "C2 Alert Rule"},
            "log": {"triggered": _iso_hours_ago(6)},
            "hits": [],
        },
        {
            "id": "al-active-3d",
            "title": "Active Phishing Infra",
            "type": "ENTITY_MATCH",
            "review": {
                "priority": "Moderate",
                "status_in_portal": "In Progress",
                "assignee": "bob",
            },
            "rule": {"id": "r2", "name": "Phishing Infra"},
            "log": {"triggered": _iso_hours_ago(72)},
            "hits": [],
        },
        {
            "id": "al-old-new-10d",
            "title": "Stale New Vulnerability",
            "type": "ENTITY_MATCH",
            "review": {"priority": "Low", "status_in_portal": "New", "assignee": "Unassigned"},
            "rule": {"id": "r3", "name": "Vuln Watch"},
            "log": {"triggered": _iso_hours_ago(240)},
            "hits": [],
        },
        {
            "id": "al-stale-new-35d",
            "title": "Very Old Unassigned Alert",
            "type": "ENTITY_MATCH",
            "review": {"priority": "Critical", "status_in_portal": "New", "assignee": ""},
            "rule": {"id": "r4", "name": "Legacy Leak"},
            "log": {"triggered": _iso_hours_ago(35 * 24)},
            "hits": [],
        },
    ]

    mock_client.search_alerts_v3.return_value = {
        "data": sample_alerts,
        "counts": {"returned": len(sample_alerts), "total": len(sample_alerts)},
    }

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()

            # Toggle Auto-Enrich OFF first so Load stays focused on alerts_v3 search
            await pilot.click("#rf-auto-enrich-btn")
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            # Default load ("all" preset): omitted optional server filter kwargs
            first_call_kwargs = mock_client.search_alerts_v3.call_args_list[0].kwargs
            assert first_call_kwargs == {"limit": 20}

            table = app.query_one("#rf-results-table", DataTable)
            assert table.row_count == 4

            # Active triage preset: New + InProgress (Last 7d) -> fresh-24h & active-3d
            preset_sel = app.query_one("#rf-preset-select", Select)
            preset_sel.value = "active_7d"
            await pilot.pause()
            assert table.row_count == 2
            summary_txt = str(app.query_one("#rf-summary-bar", Static).render())
            assert "View:" in summary_txt

            # Cleanup preset: Old New (>7d) -> old-new-10d & stale-new-35d
            preset_sel.value = "cleanup_old_new_7d"
            await pilot.pause()
            assert table.row_count == 2

            # Cleanup preset: Stale New (>30d) -> stale-new-35d
            preset_sel.value = "cleanup_old_new_30d"
            await pilot.pause()
            assert table.row_count == 1
            row_vals = [str(c) for c in table.get_row_at(0)]
            assert any("Very Old Unassigned Alert" in c for c in row_vals)

            # Save View modal persists a custom preset
            await pilot.click("#rf-save-preset-btn")
            await pilot.pause()
            assert isinstance(app.screen, SaveFilterPresetModal)
            app.screen.query_one("#preset-name-input", Input).value = "My Stale Criticals"
            await pilot.click("#preset-save-btn")
            await pilot.pause()

            saved = load_custom_rf_presets(workspace_dir=tmp_path)
            assert len(saved) == 1
            assert saved[0].label == "My Stale Criticals"
            assert str(preset_sel.value) == saved[0].id

            # Delete custom preset from advanced panel
            app.query_one("#rf-filter-collapsible", Collapsible).collapsed = False
            await pilot.pause()
            del_btn = app.query_one("#rf-delete-preset-btn", Button)
            assert del_btn.disabled is False
            await pilot.click("#rf-delete-preset-btn")
            await pilot.pause()
            assert load_custom_rf_presets(workspace_dir=tmp_path) == []

            # Fetch Filtered sends server-side timeframe kwarg when non-default
            mock_client.search_alerts_v3.reset_mock()
            app.query_one("#rf-timeframe-filter", Select).value = "last_7d"
            await pilot.pause()
            await pilot.click("#rf-apply-server-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            filtered_kwargs = mock_client.search_alerts_v3.call_args.kwargs
            assert "triggered" in filtered_kwargs

            # Reset filters restores all rows and resets controls to defaults
            await pilot.click("#rf-reset-filters-btn")
            await pilot.pause()
            assert table.row_count == 4
            assert str(app.query_one("#rf-timeframe-filter", Select).value) == "any"
            assert str(app.query_one("#rf-priority-filter", Select).value) == "any"

    asyncio.run(_run())


def test_tui_rf_intel_playbook_and_cases_server_filters(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.api_token = "tok-rf-pb-cases"
    mock_client.search_playbook_alerts.return_value = {"data": []}
    mock_client.search_cases.return_value = {"data": []}

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            app.query_one("#rf-preset-select", Select).value = "high_crit_active_7d"
            await pilot.pause()

            await pilot.click("#rf-pb-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            pb_kwargs = mock_client.search_playbook_alerts.call_args.kwargs
            assert "updated_range" in pb_kwargs
            assert pb_kwargs["priorities"] == ["High"]

            await pilot.click("#rf-cases-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            case_kwargs = mock_client.search_cases.call_args.kwargs
            assert "modified" in case_kwargs
            assert case_kwargs["priorities"] == ["Critical", "High"]

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Pilot tests: SplunkES, SentinelOne, SplunkSearch, Research, Logs, Dashboard, Sigma, Bundle
# ---------------------------------------------------------------------------


def test_tui_splunk_es_presets_and_cleanup_timeframe(tmp_path: Path) -> None:
    es = MagicMock()
    es.__enter__.return_value = es
    es.__exit__.return_value = None
    es.list_notables.return_value = [
        {
            "event_id": "n-new-24h",
            "rule_name": "Fresh High C2",
            "urgency": "high",
            "status": 1,
            "status_label": "New",
            "owner": "unassigned",
            "_time": _iso_hours_ago(3),
        },
        {
            "event_id": "n-inprog-3d",
            "rule_name": "Active Investigation",
            "urgency": "medium",
            "status": 2,
            "status_label": "In Progress",
            "owner": "alice",
            "_time": _iso_hours_ago(72),
        },
        {
            "event_id": "n-old-new-12d",
            "rule_name": "Stale Notable Cleanup",
            "urgency": "low",
            "status": 1,
            "status_label": "New",
            "owner": "unassigned",
            "_time": _iso_hours_ago(12 * 24),
        },
    ]

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=es):
            async with app.run_test(size=(140, 40)) as pilot:
                await pilot.pause()
                app.query_one("#es-auto-enrich-cb").value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                table = app.query_one("#es-table", DataTable)
                assert table.row_count == 3

                preset_sel = app.query_one("#es-preset-select", Select)
                preset_sel.value = "active_7d"
                await pilot.pause()
                assert app.query_one("#es-earliest-input", Input).value == "-7d"
                assert table.row_count == 2

                preset_sel.value = "cleanup_old_new_7d"
                await pilot.pause()
                assert app.query_one("#es-earliest-input", Input).value == "-30d"
                assert str(app.query_one("#es-timeframe-select", Select).value) == "older_7d"
                assert table.row_count == 1
                assert "Stale Notable Cleanup" in [str(c) for c in table.get_row_at(0)]

                await pilot.click("#es-clear-filter-btn")
                await pilot.pause()
                assert table.row_count == 3

    asyncio.run(_run())


def test_tui_sentinelone_view_presets_and_timeframes(tmp_path: Path) -> None:
    s1 = MagicMock()
    s1.console_url = "https://tenant.sentinelone.net"
    s1.list_agents.return_value = [
        {
            "id": "ag-1",
            "computerName": "HOST-INF",
            "osName": "Windows 11",
            "lastIpToMgmt": "10.0.0.10",
            "networkStatus": "connected",
            "infected": True,
            "siteName": "Corp",
        },
        {
            "id": "ag-2",
            "computerName": "HOST-OK",
            "osName": "Linux",
            "lastIpToMgmt": "10.0.0.11",
            "networkStatus": "connected",
            "infected": False,
            "siteName": "Corp",
        },
    ]
    s1.list_threats.return_value = [
        {
            "id": "th-fresh",
            "threatInfo": {
                "threatName": "FreshMalware",
                "analystVerdict": "undefined",
                "incidentStatus": "unresolved",
                "mitigationStatus": "active",
                "createdAt": _iso_hours_ago(4),
            },
            "agentRealtimeInfo": {"agentComputerName": "HOST-INF"},
        },
        {
            "id": "th-stale",
            "threatInfo": {
                "threatName": "OldUnresolvedThreat",
                "analystVerdict": "true_positive",
                "incidentStatus": "unresolved",
                "mitigationStatus": "active",
                "createdAt": _iso_hours_ago(15 * 24),
            },
            "agentRealtimeInfo": {"agentComputerName": "HOST-INF"},
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
            await pilot.click("#s1-tier-all-btn")
            await pilot.click("#s1-wb-agents-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = app.query_one("#s1-table", DataTable)
            assert table.row_count == 2

            app.query_one("#s1-preset-select", Select).value = "infected"
            await pilot.pause()
            assert table.row_count == 1
            assert "HOST-INF" in [str(c) for c in table.get_row_at(0)]

            app.query_one("#s1-view-select", Select).value = "threats"
            await pilot.pause()
            app.query_one("#s1-timeframe-select", Select).value = "any"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 2
            assert app.query_one("#s1-timeframe-select", Select).display is True

            app.query_one("#s1-preset-select", Select).value = "cleanup_old_7d"
            await pilot.pause()
            assert table.row_count == 1
            assert "OldUnresolvedThreat" in [str(c) for c in table.get_row_at(0)]

            await pilot.click("#s1-clear-filter-btn")
            await pilot.pause()
            app.query_one("#s1-timeframe-select", Select).value = "any"
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 2

    asyncio.run(_run())


def test_tui_splunk_search_expanded_presets_and_live_filter(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-splunk-search",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SplunkSearchPane)

            preset = app.query_one("#splunk-search-preset", Select)
            preset.value = "-48h"
            await pilot.pause()
            assert app.query_one("#splunk-search-earliest", Input).value == "-48h"

            app.query_one("#splunk-search-earliest", Input).value = "-30d"
            await pilot.pause()
            assert str(preset.value) == "-30d"

            pane._populate_results_table(
                [
                    {"_time": "2026-11-24T12:00:00Z", "host": "fw01", "action": "blocked"},
                    {"_time": "2026-11-24T11:00:00Z", "host": "db02", "action": "allowed"},
                ],
                ["_time", "host", "action"],
            )
            await pilot.pause()
            table = app.query_one("#splunk-search-table", DataTable)
            assert table.row_count == 2

            filter_inp = app.query_one("#splunk-search-filter-input", Input)
            filter_inp.value = "fw01"
            await pilot.pause()
            assert table.row_count == 1

            filter_inp.value = ""
            await pilot.pause()
            assert table.row_count == 2

    asyncio.run(_run())


def test_tui_research_timeframe_sync_and_category_filter(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(ResearchPane)
            pane._all_findings = [
                {"category": "Actor", "title": "APT29", "detail": "Actor profile", "search_blob": "apt29"},
                {"category": "Rule", "title": "C2 Rule", "detail": "Sigma hit", "search_blob": "c2 rule"},
                {"category": "Alert", "title": "Active Hit", "detail": "Open alert", "search_blob": "active hit"},
            ]
            pane._render_master_table()
            await pilot.pause()

            table = app.query_one("#res-table", DataTable)
            assert table.row_count == 3

            app.query_one("#res-options-collapsible", Collapsible).collapsed = False
            await pilot.pause()

            app.query_one("#res-timeframe-preset", Select).value = "-7d"
            await pilot.pause()
            assert app.query_one("#res-links-timeframe", Input).value == "-7d"

            app.query_one("#res-links-timeframe", Input).value = "-90d"
            await pilot.pause()
            assert str(app.query_one("#res-timeframe-preset", Select).value) == "-90d"

            app.query_one("#res-category-filter", Select).value = "Actor"
            await pilot.pause()
            assert table.row_count == 1

            await pilot.click("#res-clear-filter-btn")
            await pilot.pause()
            assert table.row_count == 3

    asyncio.run(_run())


def test_tui_logs_timeframe_filter_and_80col_bounds(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-logs",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            now_utc = datetime.now(UTC)
            app.log_store.append(
                LogEntry(
                    timestamp="10:00:00",
                    level="INFO",
                    source="tui",
                    logger_name="test",
                    message="STALE_ENTRY_2H_AGO",
                    created_utc=now_utc - timedelta(hours=2),
                )
            )
            app.log_store.append(
                LogEntry(
                    timestamp="12:00:00",
                    level="WARNING",
                    source="tui",
                    logger_name="test",
                    message="FRESH_ENTRY_NOW",
                    created_utc=now_utc - timedelta(seconds=30),
                )
            )
            pane = app.query_one(LogsPane)
            pane.rebuild_view()
            await pilot.pause()

            log_widget = app.query_one("#app-log", RichLog)
            full_text = extract_richlog_text(log_widget)
            assert "STALE_ENTRY_2H_AGO" in full_text
            assert "FRESH_ENTRY_NOW" in full_text

            app.query_one("#logs-timeframe-select", Select).value = "last_5m"
            await pilot.pause()
            filtered_text = extract_richlog_text(log_widget)
            assert "FRESH_ENTRY_NOW" in filtered_text
            assert "STALE_ENTRY_2H_AGO" not in filtered_text

            for widget_id in (
                "#logs-source-select",
                "#logs-level-select",
                "#logs-timeframe-select",
                "#logs-filter-input",
                "#logs-autoscroll-btn",
                "#logs-tz-btn",
            ):
                region = app.query_one(widget_id).region
                assert region.right <= 80, f"{widget_id} overflowed 80 cols: {region}"

    asyncio.run(_run())


def test_tui_dashboard_split_layout_and_error_filters(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    err_lines = [
        json.dumps(
            {
                "timestamp": _iso_hours_ago(2),
                "status_code": 429,
                "endpoint": "/v2/alert/search",
                "trace_id": "trace-fresh-429",
                "message": "Rate limit exceeded",
            }
        ),
        json.dumps(
            {
                "timestamp": _iso_hours_ago(20 * 24),
                "status_code": 500,
                "endpoint": "/case/search",
                "trace_id": "trace-old-500",
                "message": "Legacy server fault",
            }
        ),
    ]
    (logs_dir / "rf_api_errors.jsonl").write_text("\n".join(err_lines) + "\n", encoding="utf-8")

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-dashboard",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(DashboardPane)
            workspace = pane.query_one("#dash-workspace")
            assert workspace.has_class("split-horizontal")
            api_table = pane.query_one("#dash-apis-table", DataTable)
            assert api_table.region.y >= 0
            assert api_table.region.y < 36

            err_table = pane.query_one("#dash-errors-table", DataTable)
            assert err_table.row_count == 2

            pane.query_one("#dash-error-timeframe", Select).value = "last_24h"
            await pilot.pause()
            assert err_table.row_count == 1
            assert "trace-fresh-429" in [str(c) for c in err_table.get_row_at(0)]

            pane.query_one("#dash-error-timeframe", Select).value = "any"
            await pilot.pause()
            pane.query_one("#dash-error-filter", Input).value = "trace-old-500"
            await pilot.pause()
            assert err_table.row_count == 1
            assert "trace-old-500" in [str(c) for c in err_table.get_row_at(0)]

    asyncio.run(_run())


def test_tui_sigma_level_filter_and_bundle_time_preset_sync(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-sigma",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            sigma_pane = app.query_one(SigmaPane)
            sample_rules: list[dict[str, Any]] = [
                {"rule_id": "sig-1", "level": "critical", "index": "win", "title": "Crit Rule", "file_name": "a.yml"},
                {"rule_id": "sig-2", "level": "high", "index": "win", "title": "High Rule", "file_name": "b.yml"},
                {"rule_id": "sig-3", "level": "low", "index": "win", "title": "Low Rule", "file_name": "c.yml"},
            ]
            sigma_pane._rules = sample_rules
            sigma_pane._populate_table(sample_rules)
            await pilot.pause()

            sig_table = app.query_one("#sigma-table", DataTable)
            assert sig_table.row_count == 3

            app.query_one("#sigma-level-filter", Select).value = "critical"
            await pilot.pause()
            assert sig_table.row_count == 1
            assert str(sig_table.get_row_at(0)[0]) == "sig-1"

            app.query_one("#sigma-export-collapsible", Collapsible).collapsed = False
            await pilot.pause()
            app.query_one("#sigma-time-preset", Select).value = "30"
            await pilot.pause()
            assert app.query_one("#sigma-days-input", Input).value == "30"

            # Verify SplunkBundlePane timeframe preset sync
            tabs = app.query_one("#main-tabs")
            tabs.active = "tab-splunk-bundle"
            await pilot.pause()
            bundle_pane = app.query_one(SplunkBundlePane)
            bundle_pane.query_one("#splunk-bundle-time-preset", Select).value = "-30d"
            await pilot.pause()
            assert bundle_pane.query_one("#splunk-earliest", Input).value == "-30d"
            assert bundle_pane.query_one("#splunk-latest", Input).value == "now"

    asyncio.run(_run())
