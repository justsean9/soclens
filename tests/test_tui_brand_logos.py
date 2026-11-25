"""Unit and Pilot tests for Brand Hash List & Watchlist Domain selection in the TUI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from textual.containers import Container, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Input,
    OptionList,
    RichLog,
    Select,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
)

from soclens.client import RecordedFutureAuthError, RecordedFutureClient
from soclens.tui import ContextMenuModal, create_app
from soclens.tui.screens.brand_logos import (
    BRAND_HASH_FETCH_TYPES,
    filter_brand_hash_lists,
    filter_domain_watchlists,
    format_watchlist_option_label,
)


def _select_option_values(select: Select[Any]) -> list[str]:
    return [val for _label, val in getattr(select, "_options", []) if isinstance(val, str)]


def _select_option_labels(select: Select[Any]) -> list[str]:
    return [str(label) for label, val in getattr(select, "_options", []) if isinstance(val, str)]


def _selection_option_values(sel_list: SelectionList[Any]) -> list[str]:
    return [str(sel_list.get_option_at_index(i).value) for i in range(sel_list.option_count)]


def _select_context_option_by_id(app: Any, option_id: str) -> None:
    opts = app.screen.query_one("#ctx-menu-options", OptionList)
    opts.highlighted = opts.get_option_index(option_id)


def _rich_log_text(app: Any, selector: str = "#app-log") -> str:
    log_widget = app.query_one(selector, RichLog)
    return "\n".join(line.text for line in log_widget.lines)


def test_brand_hash_list_filtering_and_ranking() -> None:
    raw_lists = [
        {"id": "report:ent-1", "type": "entity", "name": "Abuse.ch: Feodo IP Blocklist"},
        {"id": "report:brand-name-1", "type": "brand", "name": "Brand Names Watch List"},
        {"id": "report:domain-wl-1", "type": "domain", "name": "Domain Watch List"},
        {"id": "report:dom-a", "type": "domain", "name": "Alpha Domain List"},
        {"id": "report:h3", "type": "hash", "name": "General Hash Watch List"},
        {"id": "report:brand-image-default", "type": "brand", "name": "Brand Image"},
        {"id": "report:h2", "type": "hash", "name": "Client Logo Hashes"},
        {"id": "report:brand-hash-1", "type": "hash", "name": "Brand Image Watch List"},
        {"id": "report:brand-hash-1", "type": "hash", "name": "Duplicate Brand Image"},
        {"id": "", "type": "hash", "name": "Missing ID"},
        {"type": "hash", "name": "No ID Key"},
    ]

    brand_lists = filter_brand_hash_lists(raw_lists)
    assert [item["id"] for item in brand_lists] == [
        "report:brand-hash-1",
        "report:h2",
        "report:h3",
        "report:brand-image-default",
    ]

    domain_lists = filter_domain_watchlists(
        raw_lists + [{"id": "report:domain-wl-1", "type": "domain", "name": "Dup"}]
    )
    assert [item["id"] for item in domain_lists] == ["report:dom-a", "report:domain-wl-1"]

    assert (
        format_watchlist_option_label(
            {"id": "report:brand-hash-1", "type": "hash", "name": "Brand Image Watch List"}
        )
        == "Brand Image Watch List (report:brand-hash-1) [hash]"
    )
    assert (
        format_watchlist_option_label({"id": "report:c1", "name": "Custom List"})
        == "Custom List (report:c1)"
    )
    assert (
        format_watchlist_option_label({"id": "report:noname", "type": "hash"})
        == "report:noname [hash]"
    )
    assert format_watchlist_option_label({"id": "report:plain"}) == "report:plain"


def test_tui_brand_logos_auto_loads_and_picks_brand_hash_lists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soclens.tui.screens.brand_logos as brand_mod

    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:ent-1", "type": "entity", "name": "Abuse.ch: Feodo IP Blocklist"},
        {"id": "report:brand-name-1", "type": "brand", "name": "Brand Names Watch List"},
        {"id": "report:domain-wl-1", "type": "domain", "name": "Domain Watch List"},
        {"id": "report:dom-2", "type": "domain", "name": "Secondary Domains"},
        {"id": "report:h2", "type": "hash", "name": "Client Logo Hashes"},
        {"id": "report:brand-hash-1", "type": "hash", "name": "Brand Image Watch List"},
    ]
    sample_hash = "a" * 64
    entities_by_list: dict[str, list[dict[str, Any]]] = {
        "report:domain-wl-1": [
            {"entity": {"id": "idn:gamma.test", "type": "InternetDomainName", "name": "gamma.test"}, "context": {}},
            {"entity": {"id": "idn:alpha.test", "type": "InternetDomainName", "name": "alpha.test"}, "context": {}},
            {"entity": {"id": "idn:dead.test", "type": "InternetDomainName", "name": "dead.test"}, "context": {"annotation": "noninternet"}},
            {"entity": {"id": "idn:beta.test", "type": "InternetDomainName", "name": "beta.test"}, "context": {}},
        ],
        "report:dom-2": [
            {"entity": {"id": "idn:epsilon.test", "type": "InternetDomainName", "name": "epsilon.test"}, "context": {}},
            {"entity": {"id": "idn:delta.test", "type": "InternetDomainName", "name": "delta.test"}, "context": {}},
        ],
        "report:h2": [
            {
                "entity": {"id": f"hash:{sample_hash}", "type": "Hash", "name": sample_hash},
                "status": "ready",
                "context": {"domain": "acme.test", "domains": ["acme.test"]},
            }
        ],
    }
    mock_client.get_watchlist_entities.side_effect = lambda lid: entities_by_list.get(lid, [])

    delta_calls: list[tuple[str, list[str]]] = []

    def _fake_delta(
        _client: Any,
        list_id: str,
        domains: list[str],
        **_kwargs: Any,
    ) -> tuple[dict[str, Any], dict[str, Any], list[str], list[dict[str, Any]], dict[str, str], dict[str, list[str]]]:
        delta_calls.append((list_id, list(domains)))
        return (
            {sample_hash: {"domain": domains[0]}},
            {},
            [sample_hash],
            [],
            {},
            {},
        )

    monkeypatch.setattr(brand_mod, "calculate_brand_sync_delta", _fake_delta)

    app = create_app(
        client=mock_client, dry_run=True, workspace_dir=tmp_path, view_mode="admin"
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            assert mock_client.get_watchlists.call_count == 0

            # Switching to Tab 3 auto-loads brand hash lists, domain lists, and primary domain checklist
            await pilot.press("3")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert len(app.query("#brand-log")) == 0
            assert mock_client.get_watchlists.call_count == 1
            mock_client.get_watchlists.assert_called_with(list_types=BRAND_HASH_FETCH_TYPES)

            brand_select = app.query_one("#brand-list-select", Select)
            brand_input = app.query_one("#brand-list-id", Input)
            assert _select_option_values(brand_select) == ["report:brand-hash-1", "report:h2"]
            labels = _select_option_labels(brand_select)
            assert all("Brand Names Watch List" not in lbl for lbl in labels)
            assert all("Feodo" not in lbl for lbl in labels)
            assert brand_select.value == "report:brand-hash-1"
            assert brand_input.value == "report:brand-hash-1"

            src_select = app.query_one("#brand-source-list-select", Select)
            src_input = app.query_one("#brand-source-list", Input)
            assert _select_option_values(src_select) == ["report:domain-wl-1", "report:dom-2"]
            assert src_select.value == "report:domain-wl-1"
            assert src_input.value == "report:domain-wl-1"

            dom_list = app.query_one("#brand-domain-selection", SelectionList)
            dom_header = app.query_one("#brand-domains-header", Static)
            assert _selection_option_values(dom_list) == ["alpha.test", "beta.test", "gamma.test"]
            assert list(dom_list.selected) == ["alpha.test", "beta.test", "gamma.test"]
            assert "3/3 selected" in str(dom_header.render())

            # Switching away and back does not re-fetch automatically
            await pilot.press("1")
            await pilot.pause()
            await pilot.press("3")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.get_watchlists.call_count == 1

            # Reload button and 'r' binding re-fetch lists while preserving domain checklist state
            await pilot.click("#brand-reload-lists-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.get_watchlists.call_count == 2

            brand_table = app.query_one("#brand-table", DataTable)
            brand_table.focus()
            await pilot.pause()
            await pilot.press("r")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.get_watchlists.call_count == 3

            # Picking second brand hash list syncs Input
            brand_select.value = "report:h2"
            await pilot.pause()
            assert brand_input.value == "report:h2"

            # Deselect All -> 0/3 selected, Validate refuses cleanly without calling delta
            await pilot.click("#brand-domains-none-btn")
            await pilot.pause()
            assert list(dom_list.selected) == []
            assert "0/3 selected" in str(dom_header.render())

            await pilot.click("#brand-validate-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert delta_calls == []
            assert "No domains selected" in str(app.query_one("#brand-status", Static).render())

            # Select All -> 3/3 selected, Validate runs with all 3 domains
            await pilot.click("#brand-domains-all-btn")
            await pilot.pause()
            assert list(dom_list.selected) == ["alpha.test", "beta.test", "gamma.test"]
            assert "3/3 selected" in str(dom_header.render())

            await pilot.click("#brand-validate-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert delta_calls[-1] == ("report:h2", ["alpha.test", "beta.test", "gamma.test"])

            # Deselect single domain -> Validate runs ONLY with remaining 2 domains
            dom_list.deselect("beta.test")
            await pilot.pause()
            assert "2/3 selected" in str(dom_header.render())

            # Reload Lists does NOT clobber the user's partial domain deselection
            await pilot.click("#brand-reload-lists-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert list(dom_list.selected) == ["alpha.test", "gamma.test"]

            await pilot.click("#brand-validate-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert delta_calls[-1] == ("report:h2", ["alpha.test", "gamma.test"])

            # Filter domains preserves hidden selections and scopes filtered Select/Deselect All
            dom_filter = app.query_one("#brand-domain-filter", Input)
            dom_filter.value = "beta"
            await pilot.pause()
            assert _selection_option_values(dom_list) == ["beta.test"]
            assert list(dom_list.selected) == []
            assert "2/3 selected, showing 1" in str(dom_header.render())

            # Select visible match while filtered, then verify hidden alpha & gamma remain selected
            await pilot.click("#brand-domains-all-btn")
            await pilot.pause()
            assert list(dom_list.selected) == ["beta.test"]
            assert "3/3 selected, showing 1" in str(dom_header.render())

            # Deselect visible match while filtered -> hidden alpha & gamma stay selected (2/3)
            await pilot.click("#brand-domains-none-btn")
            await pilot.pause()
            assert list(dom_list.selected) == []
            assert "2/3 selected, showing 1" in str(dom_header.render())

            # Select visible match again, clear filter -> all 3 selected
            dom_list.select("beta.test")
            await pilot.pause()
            dom_filter.value = ""
            await pilot.pause()
            assert _selection_option_values(dom_list) == ["alpha.test", "beta.test", "gamma.test"]
            assert list(dom_list.selected) == ["alpha.test", "beta.test", "gamma.test"]

            # Switching domain watchlist automatically loads the new watchlist's domains
            src_select.value = "report:dom-2"
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert src_input.value == "report:dom-2"
            assert _selection_option_values(dom_list) == ["delta.test", "epsilon.test"]
            assert list(dom_list.selected) == ["delta.test", "epsilon.test"]
            assert "2/2 selected" in str(dom_header.render())

            # Manual domains override takes precedence when set, then reverts when cleared
            manual_domains = app.query_one("#brand-domains", Input)
            manual_domains.value = "manual-override.test"
            await pilot.click("#brand-validate-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert delta_calls[-1] == ("report:h2", ["manual-override.test"])
            manual_domains.value = ""

            # View Hashes loads entities for picked brand hash list into #brand-table
            await pilot.click("#brand-view-hashes-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_watchlist_entities.assert_any_call("report:h2")
            assert brand_table.row_count == 1
            row_cells = [str(c) for c in brand_table.get_row_at(0)]
            assert "acme.test" in row_cells
            assert sample_hash in row_cells
            header_text = str(app.query_one("#brand-table-header", Static).render())
            assert "Client Logo Hashes (report:h2)" in header_text

            # Typing manual ID clears Select to Select.NULL and survives Reload Lists
            brand_input.value = "report:manual-99"
            await pilot.pause()
            assert brand_select.value is Select.NULL

            await pilot.click("#brand-reload-lists-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert brand_input.value == "report:manual-99"
            assert brand_select.value is Select.NULL

    asyncio.run(_run())


def test_tui_brand_logos_prefers_state_list_id_and_handles_missing_token_and_403(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_ws = tmp_path / "with_state"
    state_ws.mkdir(parents=True, exist_ok=True)
    (state_ws / "brand_sync_state.json").write_text(
        json.dumps({"version": 1, "list_id": "report:h2", "domains": {}}),
        encoding="utf-8",
    )

    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:brand-hash-1", "type": "hash", "name": "Brand Image Watch List"},
        {"id": "report:h2", "type": "hash", "name": "Client Logo Hashes"},
    ]
    app_state = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-brand-logos",
        workspace_dir=state_ws,
    )

    async def _run_state() -> None:
        async with app_state.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app_state.workers.wait_for_complete()
            await pilot.pause()
            assert app_state.query_one("#brand-list-select", Select).value == "report:h2"
            assert app_state.query_one("#brand-list-id", Input).value == "report:h2"

    asyncio.run(_run_state())

    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)
    no_tok_client = RecordedFutureClient(api_token=None)
    app_no_tok = create_app(
        client=no_tok_client,
        dry_run=True,
        initial_tab="tab-brand-logos",
        workspace_dir=tmp_path,
    )

    async def _run_no_tok() -> None:
        async with app_no_tok.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app_no_tok.workers.wait_for_complete()
            await pilot.pause()
            status_text = str(app_no_tok.query_one("#brand-status", Static).render())
            assert "RF_API_TOKEN not configured" in status_text

    asyncio.run(_run_no_tok())

    err_client = MagicMock()
    err_client.get_watchlists.side_effect = RecordedFutureAuthError(
        403,
        "Missing API privileges",
        trace_id="brand-trace-403",
        permission_type="missing_api_privileges",
    )
    app_err = create_app(
        client=err_client,
        dry_run=True,
        initial_tab="tab-brand-logos",
        workspace_dir=tmp_path,
    )

    async def _run_err() -> None:
        async with app_err.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app_err.workers.wait_for_complete()
            await pilot.pause()
            assert app_err.is_running
            status_text = str(app_err.query_one("#brand-status", Static).render())
            await pilot.press("8")
            await pilot.pause()
            log_text = _rich_log_text(app_err)
            assert "403" in status_text
            assert "brand-trace-403" in status_text
            assert "brand-trace-403" in log_text

    asyncio.run(_run_err())


def test_tui_watchlists_context_menu_pivots_to_brand_logos(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:brand-hash-1", "type": "hash", "name": "Brand Image Watch List"},
        {"id": "report:domain-wl-1", "type": "domain", "name": "Domain Watch List"},
    ]
    mock_client.get_watchlist_entities.side_effect = lambda lid: (
        [
            {"entity": {"id": "idn:alpha.test", "type": "InternetDomainName", "name": "alpha.test"}, "context": {}},
            {"entity": {"id": "idn:beta.test", "type": "InternetDomainName", "name": "beta.test"}, "context": {}},
        ]
        if lid == "report:domain-wl-1"
        else []
    )

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-watchlists",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            # Right-click row 0 (hash list) -> Use in Brand Logos Tab
            await pilot.click("#wl-lists-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "send_brand_logos")
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()

            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-brand-logos"
            assert app.query_one("#brand-list-id", Input).value == "report:brand-hash-1"
            assert app.query_one("#brand-list-select", Select).value == "report:brand-hash-1"

            # Return to Watchlists tab, right-click row 1 (domain list) -> Use as Domain Source
            tabs.active = "tab-watchlists"
            await pilot.pause()
            await pilot.click("#wl-lists-table", offset=(4, 3), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "send_brand_source")
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert tabs.active == "tab-brand-logos"
            assert app.query_one("#brand-source-list", Input).value == "report:domain-wl-1"
            assert app.query_one("#brand-source-list-select", Select).value == "report:domain-wl-1"
            dom_list = app.query_one("#brand-domain-selection", SelectionList)
            assert _selection_option_values(dom_list) == ["alpha.test", "beta.test"]
            assert list(dom_list.selected) == ["alpha.test", "beta.test"]

    asyncio.run(_run())


def test_tui_brand_logos_layout_fits_80x24_and_scales(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:brand-hash-1", "type": "hash", "name": "Brand Image Watch List"},
        {"id": "report:domain-wl-1", "type": "domain", "name": "Domain Watch List"},
    ]
    mock_client.get_watchlist_entities.return_value = [
        {"entity": {"id": "idn:alpha.test", "type": "InternetDomainName", "name": "alpha.test"}, "context": {}},
        {"entity": {"id": "idn:beta.test", "type": "InternetDomainName", "name": "beta.test"}, "context": {}},
    ]

    async def _measure(width: int, height: int) -> tuple[int, int]:
        app = create_app(
            client=mock_client,
            dry_run=True,
            initial_tab="tab-brand-logos",
            workspace_dir=tmp_path,
        )
        async with app.run_test(size=(width, height)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            pane = app.query_one("#tab-brand-logos", TabPane)
            for wid, wtype in (
                ("#brand-list-select", Select),
                ("#brand-list-id", Input),
                ("#brand-reload-lists-btn", Button),
                ("#brand-source-list-select", Select),
                ("#brand-source-list", Input),
                ("#brand-load-domains-btn", Button),
                ("#brand-validate-btn", Button),
                ("#brand-sync-btn", Button),
                ("#brand-view-hashes-btn", Button),
                ("#brand-state-btn", Button),
                ("#brand-view-logs-btn", Button),
                ("#brand-domains-all-btn", Button),
                ("#brand-domains-none-btn", Button),
                ("#brand-domain-sort-btn", Button),
                ("#brand-domain-filter", Input),
                ("#brand-issues-summary", Static),
                ("#brand-sort-cycle-btn", Button),
                ("#brand-sort-dir-btn", Button),
                ("#brand-dashboard-select", Select),
                ("#brand-results-filter", Input),
                ("#brand-issues-btn", Button),
                ("#brand-select-issues-btn", Button),
            ):
                widget = app.query_one(wid, wtype)
                assert widget.region.height >= 1, f"{wid} collapsed vertically at {(width, height)}"
                assert widget.region.right <= pane.region.right, (
                    f"{wid} clipped horizontally at {(width, height)}: "
                    f"{widget.region} vs pane {pane.region}"
                )

            assert app.query_one("#brand-list-select", Select).region.width >= 20
            assert app.query_one("#brand-source-list-select", Select).region.width >= 20

            ws_box = app.query_one("#brand-workspace", Container)
            dom_pane = app.query_one("#brand-domains-pane", Vertical)
            res_pane = app.query_one("#brand-results-pane", Vertical)
            if width >= 130:
                assert ws_box.has_class("split-horizontal")
                assert res_pane.region.x > dom_pane.region.x
            else:
                assert not ws_box.has_class("split-horizontal")
                assert res_pane.region.y > dom_pane.region.y

            table = app.query_one("#brand-table", DataTable)
            return table.region.width, table.region.height

    small_w, small_h = asyncio.run(_measure(80, 24))
    med_w, med_h = asyncio.run(_measure(120, 36))
    large_w, large_h = asyncio.run(_measure(180, 52))

    assert large_w > small_w
    assert med_h > small_h
    assert large_h > med_h


def test_tui_brand_logos_sorting_and_issue_dashboards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soclens.tui.screens.brand_logos as brand_mod

    shared_sha = "1" * 64
    unique_sha = "2" * 64
    extra_sha = "3" * 64
    state_payload = {
        "version": 1,
        "list_id": "report:wl_hash_01",
        "domains": {
            "ten-hashes.test": {
                "consecutive_failures": 0,
                "hashes": [f"{i:064x}" for i in range(10)],
                "last_error": None,
            },
            "two-hashes.test": {
                "consecutive_failures": 0,
                "hashes": [shared_sha, unique_sha],
                "last_error": None,
            },
            "silent-zero.test": {
                "consecutive_failures": 0,
                "hashes": [],
                "last_error": None,
            },
            "conn-err.test": {
                "consecutive_failures": 3,
                "hashes": [],
                "last_error": "Connection timed out",
            },
            "shared-peer.test": {
                "consecutive_failures": 0,
                "hashes": [shared_sha],
                "last_error": None,
            },
        },
    }
    (tmp_path / "brand_sync_state.json").write_text(
        json.dumps(state_payload),
        encoding="utf-8",
    )

    mock_client = MagicMock()
    mock_client.api_token = "tok"
    mock_client.get_watchlists.return_value = [
        {"id": "report:wl_hash_01", "type": "hash", "name": "Brand Image Watch List"},
        {"id": "report:wl_dom_01", "type": "domain", "name": "Domain Watch List"},
    ]
    mock_client.get_watchlist_entities.side_effect = lambda lid: (
        [
            {"entity": {"id": f"idn:{d}", "type": "InternetDomainName", "name": d}, "context": {}}
            for d in (
                "ten-hashes.test",
                "two-hashes.test",
                "silent-zero.test",
                "conn-err.test",
                "shared-peer.test",
                "never-synced.test",
            )
        ]
        if lid == "report:wl_dom_01"
        else []
    )

    def _fake_delta(
        _client: Any,
        _list_id: str,
        _domains: list[str],
        **_kwargs: Any,
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        list[str],
        list[dict[str, Any]],
        dict[str, str],
        dict[str, list[str]],
    ]:
        return (
            {extra_sha: {"domain": "two-hashes.test", "domains": ["two-hashes.test"]}},
            {},
            [extra_sha],
            [],
            {"conn-err.test": "HTTP 403"},
            {"img-err.test": ["Invalid PNG CRC"]},
        )

    monkeypatch.setattr(brand_mod, "calculate_brand_sync_delta", _fake_delta)

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-brand-logos",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 44)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            summary_text = str(app.query_one("#brand-issues-summary", Static).render())
            assert "Total" in summary_text or "Domains: 6" in summary_text
            assert "Missing Hashes: 3" in summary_text
            assert "1 silent" in summary_text
            assert "1 err" in summary_text
            assert "Shared: 1" in summary_text

            # 1. Clickable DataTable headers sort numerically on Hashes (0 < 2 < 10)
            brand_table = app.query_one("#brand-table", DataTable)
            hashes_col_x = sum(
                c.width + 2 * brand_table.cell_padding
                for c in list(brand_table.columns.values())[:2]
            ) + 2
            await pilot.click("#brand-table", offset=(hashes_col_x, 1))
            await pilot.pause()
            hash_counts_asc = [
                int(brand_table.get_row_at(r)[2]) for r in range(brand_table.row_count)
            ]
            assert hash_counts_asc == sorted(hash_counts_asc)
            assert hash_counts_asc[0] == 0
            assert hash_counts_asc[-1] == 10
            col_labels = [c.label.plain for c in brand_table.columns.values()]
            assert any("Hashes ^" in lbl for lbl in col_labels)

            # Second click flips to descending (10 -> 0)
            await pilot.click("#brand-table", offset=(hashes_col_x, 1))
            await pilot.pause()
            hash_counts_desc = [
                int(brand_table.get_row_at(r)[2]) for r in range(brand_table.row_count)
            ]
            assert hash_counts_desc == sorted(hash_counts_desc, reverse=True)
            assert hash_counts_desc[0] == 10

            # Toolbar sort direction & F6 cycling
            await pilot.click("#brand-sort-dir-btn")
            await pilot.pause()
            assert str(app.query_one("#brand-sort-dir-btn", Button).label) == "Asc ^"
            brand_table.focus()
            await pilot.press("f6")
            await pilot.pause()
            assert "Failures" in str(app.query_one("#brand-sort-cycle-btn", Button).label)

            # 2. Watchlist domain checklist sorting button cycles Z-A, 0-Hash, Errors, Checked
            dom_list = app.query_one("#brand-domain-selection", SelectionList)
            assert _selection_option_values(dom_list)[0] == "conn-err.test"
            await pilot.click("#brand-domain-sort-btn")  # Z-A v
            await pilot.pause(0.25)
            assert _selection_option_values(dom_list)[0] == "two-hashes.test"
            await pilot.click("#brand-domain-sort-btn")  # 0-Hash
            await pilot.pause(0.25)
            first_three = set(_selection_option_values(dom_list)[:3])
            assert first_three == {"conn-err.test", "never-synced.test", "silent-zero.test"}
            await pilot.click("#brand-domain-sort-btn")  # Errors
            await pilot.pause(0.25)
            assert _selection_option_values(dom_list)[0] == "conn-err.test"

            # 3. Switch to Missing Hashes dashboard via Issues button
            await pilot.click("#brand-issues-btn")
            await pilot.pause()
            dash_select = app.query_one("#brand-dashboard-select", Select)
            assert dash_select.value == "issue:missing_hashes"
            missing_domains = [
                str(brand_table.get_row_at(r)[0]) for r in range(brand_table.row_count)
            ]
            assert set(missing_domains) == {
                "conn-err.test",
                "never-synced.test",
                "silent-zero.test",
            }

            # Filter within Missing Hashes dashboard
            res_filter = app.query_one("#brand-results-filter", Input)
            res_filter.value = "silent"
            await pilot.pause()
            assert brand_table.row_count == 1
            assert str(brand_table.get_row_at(0)[0]) == "silent-zero.test"
            res_filter.value = ""
            await pilot.pause()
            assert brand_table.row_count == 3

            # Use Issues selects ONLY the 3 missing-hash domains in the checklist
            await pilot.click("#brand-select-issues-btn")
            await pilot.pause()
            assert set(dom_list.selected) == {
                "conn-err.test",
                "never-synced.test",
                "silent-zero.test",
            }

            # Switch to Silent Zero Hashes, Grace Failures, and Duplicate Hashes dashboards
            dash_select.value = "issue:silent_zero_hashes"
            await pilot.pause()
            assert [str(brand_table.get_row_at(r)[0]) for r in range(brand_table.row_count)] == [
                "silent-zero.test"
            ]
            dash_select.value = "issue:failing_grace"
            await pilot.pause()
            assert str(brand_table.get_row_at(0)[0]) == "conn-err.test"
            assert "GRACE EXCEEDED" in str(brand_table.get_row_at(0)[1])
            dash_select.value = "issue:duplicate_hashes"
            await pilot.pause()
            assert "SHARED (2 DOMAINS)" in str(brand_table.get_row_at(0)[1])

            # 4. Run Validate (Dry-Run) with manual domains including image error & silent zero
            app.query_one("#brand-domains", Input).value = (
                "two-hashes.test,conn-err.test,img-err.test,silent-zero.test"
            )
            await pilot.click("#brand-validate-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            # Image Errors dashboard now surfaces img-err.test
            dash_select.value = "issue:image_errors"
            await pilot.pause()
            assert [str(brand_table.get_row_at(r)[0]) for r in range(brand_table.row_count)] == [
                "img-err.test"
            ]
            assert "Invalid PNG CRC" in str(brand_table.get_row_at(0)[3])

    asyncio.run(_run())


def test_tui_brand_logos_right_click_table_and_checklist_single_domain_sync(
    tmp_path: Path,
) -> None:
    state_payload = {
        "list_id": "report:wl_hash_01",
        "domains": {
            "conn-err.test": {
                "hashes": [],
                "consecutive_failures": 2,
                "last_error": "HTTP 403 Forbidden",
            },
            "silent-zero.test": {
                "hashes": [],
                "consecutive_failures": 0,
            },
            "two-hashes.test": {
                "hashes": ["hash:" + ("c" * 64)],
                "consecutive_failures": 0,
            },
        },
    }
    (tmp_path / "brand_sync_state.json").write_text(
        json.dumps(state_payload), encoding="utf-8"
    )

    mock_client = MagicMock()
    mock_client.api_token = "tok-test"
    mock_client.get_watchlists.return_value = [
        {"id": "report:wl_hash_01", "type": "hash", "name": "Brand Image Watch List"},
        {"id": "report:wl_dom_01", "type": "domain", "name": "Domain Watch List"},
    ]
    mock_client.get_watchlist_entities.side_effect = lambda lid: (
        [
            {"entity": {"id": "idn:conn-err.test", "type": "InternetDomainName", "name": "conn-err.test"}},
            {"entity": {"id": "idn:silent-zero.test", "type": "InternetDomainName", "name": "silent-zero.test"}},
            {"entity": {"id": "idn:two-hashes.test", "type": "InternetDomainName", "name": "two-hashes.test"}},
        ]
        if lid == "report:wl_dom_01"
        else []
    )

    app = create_app(
        client=mock_client,
        dry_run=False,
        initial_tab="tab-brand-logos",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with (
            patch(
                "soclens.tui.screens.brand_logos.calculate_brand_sync_delta",
                return_value=({}, {}, {}, [], {}, {}),
            ) as mock_delta,
            patch(
                "soclens.tui.screens.brand_logos.execute_domain_brand_sync",
                return_value=True,
            ) as mock_exec,
        ):
            async with app.run_test(size=(150, 44)) as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                dom_list = app.query_one("#brand-domain-selection", SelectionList)
                brand_table = app.query_one("#brand-table", DataTable)
                assert set(dom_list.selected) == {
                    "conn-err.test",
                    "silent-zero.test",
                    "two-hashes.test",
                }

                # Switch to Missing Hashes dashboard (2 rows: conn-err.test, silent-zero.test)
                await pilot.click("#brand-issues-btn")
                await pilot.pause()
                assert brand_table.row_count == 2

                # 1. Right-click row 0 in #brand-table -> Validate single domain only
                await pilot.click("#brand-table", offset=(4, 2), button=3)
                await pilot.pause()
                assert isinstance(app.screen, ContextMenuModal)
                opts = app.screen.query_one("#ctx-menu-options", OptionList)
                opt_ids = [
                    str(opts.get_option_at_index(i).id)
                    for i in range(opts.option_count)
                ]
                assert opt_ids[:3] == [
                    "sync_single_domain",
                    "validate_single_domain",
                    "select_single_domain",
                ]
                assert "conn-err.test" in str(opts.get_option_at_index(0).prompt)
                _select_context_option_by_id(app, "validate_single_domain")
                await pilot.press("enter")
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert mock_delta.call_count == 1
                assert mock_delta.call_args.args[2] == ["conn-err.test"]
                assert mock_exec.call_count == 0
                assert set(dom_list.selected) == {
                    "conn-err.test",
                    "silent-zero.test",
                    "two-hashes.test",
                }

                # 2. Switch back to Missing Hashes and right-click row 1 -> Sync single domain only
                await pilot.click("#brand-issues-btn")
                await pilot.pause()
                await pilot.click("#brand-table", offset=(4, 3), button=3)
                await pilot.pause()
                assert isinstance(app.screen, ContextMenuModal)
                opts = app.screen.query_one("#ctx-menu-options", OptionList)
                assert "silent-zero.test" in str(opts.get_option_at_index(0).prompt)
                _select_context_option_by_id(app, "sync_single_domain")
                await pilot.press("enter")
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert mock_delta.call_count == 2
                assert mock_delta.call_args.args[2] == ["silent-zero.test"]
                assert mock_exec.call_count == 1
                assert mock_exec.call_args.args[2] == ["silent-zero.test"]
                assert set(dom_list.selected) == {
                    "conn-err.test",
                    "silent-zero.test",
                    "two-hashes.test",
                }

                # 3. Right-click inside #brand-domain-selection (row 0 at y=1 inside border)
                await pilot.click("#brand-domain-selection", offset=(6, 1), button=3)
                await pilot.pause()
                assert isinstance(app.screen, ContextMenuModal)
                checklist_opts = app.screen.query_one("#ctx-menu-options", OptionList)
                assert "conn-err.test" in str(checklist_opts.get_option_at_index(0).prompt)
                _select_context_option_by_id(app, "select_single_domain")
                await pilot.press("enter")
                await pilot.pause()

                assert list(dom_list.selected) == ["conn-err.test"]

                # 4. Right-clicking pane empty area does not include single-domain options
                await pilot.click("#brand-status", offset=(2, 0), button=3)
                await pilot.pause()
                assert isinstance(app.screen, ContextMenuModal)
                empty_opts = app.screen.query_one("#ctx-menu-options", OptionList)
                empty_ids = [
                    str(empty_opts.get_option_at_index(i).id)
                    for i in range(empty_opts.option_count)
                ]
                assert "sync_single_domain" not in empty_ids
                await pilot.press("escape")
                await pilot.pause()

    asyncio.run(_run())


