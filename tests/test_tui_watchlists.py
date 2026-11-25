"""Dedicated Pilot tests for Watchlists Name-first columns, copyable IDs, and expanded drill-down."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

from textual.containers import Vertical
from textual.widgets import DataTable, Input, OptionList, Static

from soclens.tui import ContextMenuModal, create_app


def _col_keys(table: DataTable[object]) -> list[str]:
    return [
        str(col.key.value if col.key.value is not None else col.key)
        for col in table.ordered_columns
    ]


def _select_context_option_by_id(app: object, option_id: str) -> None:
    opts = app.screen.query_one("#ctx-menu-options", OptionList)  # type: ignore[attr-defined]
    opts.highlighted = opts.get_option_index(option_id)


def test_tui_watchlists_names_columns_copy_id_and_back_navigation(
    tmp_path: Path,
) -> None:
    mock_client = MagicMock()
    mock_client.api_token = "tok-wl"
    mock_client.get_watchlists.return_value = [
        {"id": "report:wl_ent_01", "type": "entity", "name": "Executive VIP Protection List"},
        {"id": "report:wl_hash_01", "type": "hash", "name": "Brand Image Hashes"},
    ]
    mock_client.get_watchlist_entities.return_value = [
        {
            "entity": {
                "id": "idn:lookalike-bank.example",
                "type": "InternetDomainName",
                "name": "lookalike-bank.example",
            },
            "status": "ready",
            "context": {"annotation": "brand impersonation"},
        },
        {
            "entity": {
                "id": "hash:" + ("a" * 64),
                "type": "Hash",
                "name": "",
            },
            "status": "ready",
            "context": {"annotation": "fallback ID when name empty"},
        },
    ]

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-watchlists",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        copied: list[str] = []
        with patch.object(app, "copy_to_clipboard", side_effect=copied.append):
            async with app.run_test(size=(110, 36)) as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                lists_table = app.query_one("#wl-lists-table", DataTable)
                ent_table = app.query_one("#wl-entities-table", DataTable)
                lists_pane = app.query_one("#wl-lists-pane", Vertical)
                ent_pane = app.query_one("#wl-entities-pane", Vertical)

                # Browse table shows only Name & Type (no List ID column clutter)
                assert _col_keys(lists_table) == ["name", "type"]
                assert [str(c) for c in lists_table.get_row_at(0)] == [
                    "Executive VIP Protection List",
                    "entity",
                ]
                assert not lists_pane.has_class("wl-hidden")
                assert ent_pane.has_class("wl-hidden")

                # Copy List ID via browse button and F4 shortcut (row 1 = Brand Image Hashes)
                await pilot.click("#wl-copy-id-btn")
                await pilot.pause()
                assert copied[-1] == "report:wl_ent_01"
                assert "report:wl_ent_01" in str(app.query_one("#wl-status", Static).render())

                lists_table.focus()
                await pilot.press("down", "f4")
                await pilot.pause()
                assert copied[-1] == "report:wl_hash_01"

                # Right-click context menu still works on browse list & has Copy List ID
                await pilot.click("#wl-lists-table", offset=(4, 2), button=3)
                await pilot.pause()
                assert isinstance(app.screen, ContextMenuModal)
                _select_context_option_by_id(app, "copy_list_id")
                await pilot.press("enter")
                await pilot.pause()
                assert copied[-1] == "report:wl_ent_01"

                # Filtering watchlists still matches List ID even when ID column is hidden
                wl_search = app.query_one("#wl-search-input", Input)
                wl_search.value = "wl_hash_01"
                await pilot.pause()
                assert lists_table.row_count == 1
                assert str(lists_table.get_row_at(0)[0]) == "Brand Image Hashes"
                wl_search.value = ""
                await pilot.pause()
                assert lists_table.row_count == 2

                # Single-click expands Entity List full-width & hides Watchlists finder
                await pilot.click("#wl-lists-table", offset=(4, 2))
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert lists_pane.has_class("wl-hidden")
                assert not ent_pane.has_class("wl-hidden")
                assert ent_table.region.width >= 95
                assert _col_keys(ent_table) == ["name", "type", "status", "annotation"]
                assert str(ent_table.get_row_at(0)[0]) == "lookalike-bank.example"
                assert str(ent_table.get_row_at(1)[0]) == "hash:" + ("a" * 64)

                # Copy List ID from expanded entity view + right-click Copy Entity ID
                await pilot.click("#wl-entities-copy-id-btn")
                await pilot.pause()
                assert copied[-1] == "report:wl_ent_01"

                await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
                await pilot.pause()
                assert isinstance(app.screen, ContextMenuModal)
                _select_context_option_by_id(app, "copy_entity_id")
                await pilot.press("enter")
                await pilot.pause()
                assert copied[-1] == "idn:lookalike-bank.example"

                # Escape when filter is collapsed/clear navigates back to Watchlists
                ent_table.focus()
                await pilot.press("escape")
                await pilot.pause()
                assert not lists_pane.has_class("wl-hidden")
                assert ent_pane.has_class("wl-hidden")

                # Open row 1 via single click -> Backspace (when entity filter empty) navigates back
                await pilot.click("#wl-lists-table", offset=(4, 3))
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert not ent_pane.has_class("wl-hidden")
                ent_table.focus()
                await pilot.press("backspace")
                await pilot.pause()
                assert not lists_pane.has_class("wl-hidden")
                assert ent_pane.has_class("wl-hidden")

                # Open again -> context menu '<- Back to Watchlists' navigates back
                await pilot.click("#wl-lists-table", offset=(4, 2))
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert not ent_pane.has_class("wl-hidden")
                await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
                await pilot.pause()
                _select_context_option_by_id(app, "back_to_lists")
                await pilot.press("enter")
                await pilot.pause()
                assert not lists_pane.has_class("wl-hidden")

    asyncio.run(_run())
