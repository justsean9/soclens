"""Pilot integration tests for the clean search-first Research Workbench TUI tab."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

from textual.widgets import Collapsible, DataTable, Input, TabbedContent

from soclens.client import RecordedFutureAuthError
from soclens.tui import create_app
from soclens.tui.screens.research import ResearchPane
from soclens.tui.screens.rf_intel import RFIntelPane
from soclens.tui.screens.watchlists import WatchlistsPane


def _build_research_mock_client() -> MagicMock:
    client = MagicMock()
    client.asi_api_key = None
    client.riskrecon_token = None
    client._stop_event = None

    client.get_watchlists.return_value = []
    client.entity_match.return_value = [
        {"id": "O7NRMb", "name": "BlueBravo", "type": "Organization"}
    ]
    client.entity_lookup.side_effect = lambda eid: {
        "id": eid,
        "name": eid.split(":", 1)[1] if ":" in eid else eid,
        "type": "InternetDomainName" if eid.startswith("idn:") else "IpAddress",
    }
    client.v2_search.return_value = {"data": {"results": []}}
    client.v2_company_by_domain.side_effect = RecordedFutureAuthError(
        403, "Company API not licensed", permission_type="missing_api_privileges"
    )
    client.search_threat_actors.return_value = {
        "data": [
            {
                "id": "O7NRMb",
                "type": "Organization",
                "attributes": {"name": "BlueBravo", "common_names": ["APT29"]},
            }
        ]
    }
    client.get_threat_actor_map.return_value = {
        "data": {"threat_map": [{"id": "O7NRMb", "name": "BlueBravo", "links_count": 12}]}
    }
    client.get_malware_threat_map.return_value = {"data": {"threat_map": []}}
    client.v2_lookup.return_value = {
        "data": {
            "entity": {"id": "ip:8.8.8.8", "name": "8.8.8.8", "type": "IpAddress"},
            "risk": {
                "score": 45,
                "riskString": "2/117",
                "criticalityLabel": "Unusual",
                "riskSummary": "DNS resolver checked for threat pivots.",
                "evidenceDetails": [
                    {
                        "criticalityLabel": "Unusual",
                        "rule": "Historical Sighting",
                        "evidenceString": "Referenced in threat reporting",
                    }
                ],
            },
            "relatedEntities": [],
        }
    }
    client.soar_enrich.return_value = {
        "data": {"results": [{"entity": {"id": "ip:8.8.8.8", "name": "8.8.8.8"}, "risk": {"score": 45}}]}
    }
    client.links_search.return_value = {
        "data": [
            {
                "entity": {"id": "ip:8.8.8.8"},
                "links": [
                    {
                        "id": "idn:pivot.example",
                        "name": "pivot.example",
                        "type": "type:InternetDomainName",
                        "risk": {"score": 88},
                        "sections": [{"name": "Indicators"}],
                    }
                ],
            }
        ]
    }
    client.search_analyst_notes.return_value = {
        "data": [
            {
                "id": "note:123",
                "attributes": {
                    "title": "Sample Insikt Note",
                    "published": "2026-11-22T00:00:00Z",
                    "text": "Short summary",
                    "topic": [{"id": "TXSFt1", "name": "Cyber Threat Analysis"}],
                    "note_entities": [],
                },
            }
        ]
    }
    client.lookup_analyst_note.return_value = {
        "id": "note:123",
        "attributes": {
            "title": "Sample Insikt Note",
            "published": "2026-11-22T00:00:00Z",
            "text": "Full detailed analyst prose loaded on drilldown.",
            "topic": [{"id": "TXSFt1", "name": "Cyber Threat Analysis"}],
        },
    }
    client.search_detection_rules.return_value = [
        {"id": "rule1", "title": "Cobalt Strike Beacon", "type": "sigma", "updated": "2026-11-20T00:00:00Z"}
    ]
    client.malware_intel_query_iocs.return_value = {"data": []}
    client.malware_intel_query_nl.return_value = {"data": []}
    # Simulate 403 on risk_history & identity to ensure TUI never surfaces API plumbing errors in Findings
    client.search_risk_history.side_effect = RecordedFutureAuthError(
        403, "Access requires Risk Api privilege", permission_type="missing_api_privileges"
    )
    client.identity_ip_lookup.side_effect = RecordedFutureAuthError(
        403, "User does not have access", permission_type="missing_api_privileges"
    )
    client.identity_lookup.side_effect = RecordedFutureAuthError(
        403, "User does not have access", permission_type="missing_api_privileges"
    )
    client.identity_search.side_effect = RecordedFutureAuthError(
        403, "User does not have access", permission_type="missing_api_privileges"
    )
    client.search_alerts_v3.return_value = {"data": []}
    client.search_playbook_alerts.return_value = {"data": []}
    client.search_collective_insights.side_effect = RecordedFutureAuthError(
        403, "Not enough privileges", permission_type="missing_api_privileges"
    )
    client.sandbox_search.return_value = {"samples": []}
    return client


def test_tui_research_search_findings_pivot_history_and_export(tmp_path: Path) -> None:
    client = _build_research_mock_client()
    app = create_app(client=client, dry_run=True, workspace_dir=tmp_path)

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.press("7")
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-research"

            pane = app.query_one(ResearchPane)
            # No API surface select or API check buttons exist in the simplified search-first UI
            assert not list(pane.query("#res-surface-select"))
            assert not list(pane.query("#res-master-view"))
            assert not list(pane.query("#res-caps-btn"))

            # Pre-search example rows are populated
            table = pane.query_one("#res-table", DataTable)
            assert table.row_count == 4

            # Enter query in search bar and submit
            search_inp = pane.query_one("#res-target-input", Input)
            search_inp.value = "8.8.8.8"
            await pilot.click("#res-investigate-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert pane._current_dossier is not None
            assert pane._current_dossier.target.canonical_name == "8.8.8.8"
            # Row 0 = Summary, plus Report, Related, Rule — ZERO API section or not_entitled rows!
            categories = [str(row.get("category")) for row in pane._visible_rows]
            assert categories[0] == "Summary"
            assert "Report" in categories
            assert "Related" in categories
            assert "Rule" in categories
            visible_text = " ".join(
                f"{r.get('category', '')} {r.get('title', '')} {r.get('detail', '')} {r.get('search_blob', '')}"
                for r in pane._visible_rows
            ).lower()
            assert "not_entitled" not in visible_text
            assert "api section" not in visible_text
            assert "403" not in visible_text

            # Toggle options collapsible via / and close via escape
            await pilot.press("slash")
            await pilot.pause()
            assert pane.query_one("#res-options-collapsible", Collapsible).collapsed is False
            await pilot.press("escape")
            await pilot.pause()
            assert pane.query_one("#res-options-collapsible", Collapsible).collapsed is True

            # Filter findings down to Report
            pane.query_one("#res-filter-input", Input).value = "Sample Insikt Note"
            await pilot.pause()
            assert len(pane._visible_rows) == 1
            assert pane._visible_rows[0]["kind"] == "note"

            # Press Enter on Report row -> drills down via lookup_analyst_note
            table.focus()
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            client.lookup_analyst_note.assert_called_once_with("note:123", serialization="full")

            # Clear filter and toggle Raw JSON via j
            pane.query_one("#res-filter-input", Input).value = ""
            await pilot.pause()
            await pilot.press("j")
            await pilot.pause()
            assert pane._detail_mode == "json"
            await pilot.press("j")
            await pilot.pause()
            assert pane._detail_mode == "overview"

            # Select the Related row and pivot via 'p'
            related_idx = next(
                idx for idx, row in enumerate(pane._visible_rows) if row.get("kind") == "pivot"
            )
            table.move_cursor(row=related_idx, column=0, animate=False)
            await pilot.pause()
            await pilot.press("p")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane._current_dossier is not None
            assert pane._current_dossier.target.entity_id == "idn:pivot.example"

            # Back ([) restores cached 8.8.8.8 without re-calling v2_lookup
            calls_before_back = client.v2_lookup.call_count
            await pilot.press("[")
            await pilot.pause()
            assert pane._current_dossier.target.canonical_name == "8.8.8.8"
            assert client.v2_lookup.call_count == calls_before_back

            # Forward (]) restores cached pivot.example
            await pilot.press("]")
            await pilot.pause()
            assert pane._current_dossier.target.entity_id == "idn:pivot.example"

            # Export MD and JSON (open Filter & Options drawer to click Export JSON)
            await pilot.click("#res-export-md-btn")
            await pilot.press("slash")
            await pilot.pause()
            await pilot.click("#res-export-json-btn")
            await pilot.pause()
            reports_dir = tmp_path / "reports"
            assert list(reports_dir.glob("*.md"))
            assert list(reports_dir.glob("*.json"))

    asyncio.run(_run())


def test_tui_research_example_click_and_cross_tab_pivots(tmp_path: Path) -> None:
    client = _build_research_mock_client()
    app = create_app(client=client, dry_run=True, initial_tab="tab-research", workspace_dir=tmp_path)

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(ResearchPane)
            table = pane.query_one("#res-table", DataTable)

            # Pressing Enter on first Example Search ("APT29") immediately runs a search
            table.focus()
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane._current_dossier is not None
            assert pane._current_dossier.target.raw_query == "APT29"

            # Cross-tab jumps from Watchlists and RF Intel
            wl_pane = await app.ensure_tab_mounted("tab-watchlists")
            assert isinstance(wl_pane, WatchlistsPane)
            wl_pane._research_entity_in_research_tab("IpAddress", "8.8.8.8")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-research"
            assert pane._current_dossier.target.canonical_name == "8.8.8.8"

            rf_pane = await app.ensure_tab_mounted("tab-rf-intel")
            assert isinstance(rf_pane, RFIntelPane)
            rf_pane._research_in_research_tab("idn:pivot.example", "domain")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane._current_dossier.target.entity_id == "idn:pivot.example"

    asyncio.run(_run())


def test_tui_research_instant_type_to_search(tmp_path: Path) -> None:
    client = _build_research_mock_client()
    app = create_app(client=client, dry_run=True, workspace_dir=tmp_path, view_mode="admin")

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            # Switch to Research tab (focus starts on ContentTabs, outside ResearchPane)
            await pilot.press("7")
            await pilot.pause()
            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-research"

            pane = app.query_one(ResearchPane)
            search_inp = pane.query_one("#res-target-input", Input)
            table = pane.query_one("#res-table", DataTable)
            options_collapsible = pane.query_one("#res-options-collapsible", Collapsible)
            filter_inp = pane.query_one("#res-filter-input", Input)

            # Typing before any search has run works even for 'p' / 'j' (non-dossier keys)
            await pilot.press("p", "a", "y")
            await pilot.pause()
            assert app.focused is search_inp
            assert search_inp.value == "pay"

            # Escape returns focus to the findings table; typing continues cleanly
            await pilot.press("escape")
            await pilot.pause()
            assert app.focused is table

            # Clear draft and verify instant type-to-search from ContentTabs (outside ResearchPane)
            search_inp.value = ""
            await pilot.press("1")
            await pilot.pause()
            assert tabs.active == "tab-dashboard"
            await pilot.press("7")
            await pilot.pause()
            assert tabs.active == "tab-research"

            # Typing "apt29" immediately focuses search bar with "apt29", Enter submits & focuses table
            await pilot.press("a", "p", "t", "2", "9")
            await pilot.pause()
            assert app.focused is search_inp
            assert search_inp.value == "apt29"
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane._current_dossier is not None
            assert pane._current_dossier.target.raw_query == "apt29"
            assert app.focused is table

            # With dossier loaded & focus on table, number keys still switch tabs and j toggles JSON
            await pilot.press("8")
            await pilot.pause()
            assert tabs.active == "tab-logs"
            await pilot.press("7")
            await pilot.pause()
            assert tabs.active == "tab-research"
            table.focus()
            await pilot.pause()
            await pilot.press("j")
            await pilot.pause()
            assert pane._detail_mode == "json"
            await pilot.press("j")
            await pilot.pause()
            assert pane._detail_mode == "overview"

            # Typing a new search ("cobalt") while results are shown replaces old submitted query
            await pilot.press("c", "o", "b", "a", "l", "t")
            await pilot.pause()
            assert app.focused is search_inp
            assert search_inp.value == "cobalt"

            # Down arrow moves focus to findings table; Backspace trims search bar & refocuses it
            await pilot.press("down")
            await pilot.pause()
            assert app.focused is table
            await pilot.press("backspace")
            await pilot.pause()
            assert app.focused is search_inp
            assert search_inp.value == "cobal"

            # Escape moves focus to table; opening Options via '/' lets user type in #res-filter-input
            await pilot.press("escape")
            await pilot.pause()
            assert app.focused is table
            await pilot.press("slash")
            await pilot.pause()
            assert options_collapsible.collapsed is False
            await pilot.press("r", "e", "p")
            await pilot.pause()
            assert app.focused is filter_inp
            assert filter_inp.value == "rep"
            assert search_inp.value == "cobal"

    asyncio.run(_run())
