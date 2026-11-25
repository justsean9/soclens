"""Unit and Pilot integration tests for the Windows-compatible Textual TUI."""

from __future__ import annotations

import ast
import asyncio
import configparser
import io
import json
import struct
import zlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.color import ColorSystem
from rich.console import Console
from textual.containers import Container, Vertical
from textual.widgets import (
    Button,
    Collapsible,
    DataTable,
    Input,
    OptionList,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from soclens.client import RecordedFutureAPIError, RecordedFutureAuthError, RecordedFutureClient
from soclens.tui import (
    ConfirmActionModal,
    ContextMenuModal,
    CreateCaseModal,
    ScreenshotViewerModal,
    SocLensApp,
    TriageItemModal,
    create_app,
)
from soclens.tui.image_render import (
    DecodedImage,
    auto_crop_margins,
    build_kitty_delete_sequence,
    build_kitty_upload_sequence,
    decode_image,
    detect_terminal_graphics_protocol,
    encode_png,
    open_image_in_native_viewer,
    render_image_halfblock,
    render_kitty_placeholder_grid,
)
from soclens.tui.rf_formatters import (
    extract_alerts_v3,
    extract_sandbox_samples,
    normalize_alert_v3,
    normalize_playbook_alert,
    normalize_v2_record,
    render_alert_v3_detail,
    render_playbook_alert_detail,
    render_v2_intel_card,
)

POSIX_ONLY_MODULES = frozenset(
    {"fcntl", "termios", "tty", "pty", "pwd", "grp", "resource", "curses", "syslog", "posix"}
)


def test_tui_ast_windows_compatibility() -> None:
    tui_root = Path(__file__).resolve().parents[1] / "soclens" / "tui"
    py_files = sorted(tui_root.rglob("*.py"))
    assert py_files

    for py_file in py_files:
        src = py_file.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(py_file))
        assert not [ch for ch in src if ord(ch) > 0x1F000], f"Emoji found in {py_file}"

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in POSIX_ONLY_MODULES
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in POSIX_ONLY_MODULES
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "os" and node.func.attr in {"system", "fork", "killpg"}:
                        raise AssertionError(f"Unsafe os.{node.func.attr} in {py_file}")
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        raise AssertionError(f"shell=True in {py_file}")


def test_tui_mounts_six_tabs_and_switches_via_keys(tmp_path: Path) -> None:
    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
    assert isinstance(app, SocLensApp)
    assert app.view_mode == "user"

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            tabbed = app.query_one("#main-tabs", TabbedContent)
            panes = list(tabbed.query(TabPane))
            assert [p.id for p in panes] == [
                "tab-dashboard",
                "tab-watchlists",
                "tab-brand-logos",
                "tab-rf-intel",
                "tab-sigma",
                "tab-splunk-bundle",
                "tab-research",
                "tab-logs",
                "tab-sentinelone",
                "tab-llm",
                "tab-splunk-search",
                "tab-splunk-es",
                "tab-settings",
            ]
            # Default User view starts on Research and exposes all 8 User View tabs
            assert tabbed.active == "tab-research"
            for key, expected in (
                ("4", "tab-rf-intel"),
                ("8", "tab-logs"),
                ("9", "tab-sentinelone"),
                ("0", "tab-settings"),
                ("f7", "tab-llm"),
                ("f8", "tab-splunk-search"),
                ("f9", "tab-splunk-es"),
                ("f10", "tab-settings"),
                ("7", "tab-research"),
            ):
                await pilot.press(key)
                await pilot.pause()
                assert tabbed.active == expected
            # Admin-only keys are disabled in User view
            for blocked_key in ("1", "2", "3", "5", "6"):
                await pilot.press(blocked_key)
                await pilot.pause()
                assert tabbed.active == "tab-research"

            # F2 toggles Admin view, unlocking all 13 tabs
            await pilot.press("f2")
            await pilot.pause()
            assert app.view_mode == "admin"
            for key, expected in (
                ("2", "tab-watchlists"),
                ("3", "tab-brand-logos"),
                ("4", "tab-rf-intel"),
                ("5", "tab-sigma"),
                ("6", "tab-splunk-bundle"),
                ("7", "tab-research"),
                ("8", "tab-logs"),
                ("9", "tab-sentinelone"),
                ("0", "tab-settings"),
                ("f7", "tab-llm"),
                ("f8", "tab-splunk-search"),
                ("f9", "tab-splunk-es"),
                ("f10", "tab-settings"),
                ("1", "tab-dashboard"),
            ):
                await pilot.press(key)
                await pilot.pause()
                assert tabbed.active == expected
            await pilot.press("q")
            await pilot.pause()
            assert not app.is_running

    asyncio.run(_run())


def test_tui_dry_run_prevents_watchlist_mutations(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:brand-1", "type": "brand", "name": "Brand Image Watch List"}
    ]
    app = create_app(
        client=mock_client, dry_run=True, workspace_dir=tmp_path, view_mode="admin"
    )

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            tabbed = app.query_one("#main-tabs", TabbedContent)
            tabbed.active = "tab-watchlists"
            await pilot.pause()

            app.query_one("#wl-target-list-id", Input).value = "report:brand-1"
            app.query_one("#wl-ent-value", Input).value = "evil.example"
            app.query_one("#wl-create-name", Input).value = "New Test List"

            for btn_id in ("#wl-add-btn", "#wl-remove-btn", "#wl-create-btn"):
                await pilot.click(btn_id)
                await pilot.pause()
            await app.workers.wait_for_complete()

    asyncio.run(_run())
    mock_client.add_entity.assert_not_called()
    mock_client.remove_entity.assert_not_called()
    mock_client.create_list.assert_not_called()


def test_tui_loads_watchlists_and_sigma_cache(tmp_path: Path) -> None:
    cache_path = tmp_path / "sigma_rules_cache.json"
    cache_path.write_text(
        json.dumps(
            [
                {
                    "rule_id": "doc:sigma-test",
                    "title": "Suspicious PowerShell Runner",
                    "file_name": "ps_runner.yml",
                    "level": "high",
                    "index": "*wineventlog",
                    "content": "title: Suspicious PowerShell Runner\nlevel: high\n",
                }
            ]
        ),
        encoding="utf-8",
    )

    mock_client = MagicMock()
    mock_client.api_token = "tok"
    mock_client.get_watchlists.return_value = [
        {"id": "report:wl-1", "type": "brand", "name": "TUI Seeded Watchlist"}
    ]
    app = create_app(
        client=mock_client, dry_run=True, workspace_dir=tmp_path, view_mode="admin"
    )

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            tabbed = app.query_one("#main-tabs", TabbedContent)

            tabbed.active = "tab-watchlists"
            await pilot.pause()
            await pilot.click("#wl-load-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            wl_table = app.query_one("#wl-lists-table", DataTable)
            assert wl_table.row_count == 1
            assert "TUI Seeded Watchlist" in [str(c) for c in wl_table.get_row_at(0)]

            tabbed.active = "tab-sigma"
            await pilot.pause()
            await pilot.click("#sigma-load-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            sigma_table = app.query_one("#sigma-table", DataTable)
            assert sigma_table.row_count == 1
            assert "Suspicious PowerShell Runner" in [str(c) for c in sigma_table.get_row_at(0)]

    asyncio.run(_run())


def test_tui_rf_error_and_invalid_inputs_handled_gracefully(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("SPLUNK_USERNAME", raising=False)
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)

    mock_client = MagicMock()
    mock_client.get_watchlists.side_effect = RecordedFutureAuthError(
        403,
        "Missing API privileges",
        trace_id="unit-trace-403",
        permission_type="missing_api_privileges",
    )
    app = create_app(
        client=mock_client, dry_run=False, workspace_dir=tmp_path, view_mode="admin"
    )

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            tabbed = app.query_one("#main-tabs", TabbedContent)

            tabbed.active = "tab-watchlists"
            await pilot.pause()
            await pilot.click("#wl-load-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            status_text = str(app.query_one("#wl-status", Static).render())
            assert "403" in status_text
            assert "unit-trace-403" in status_text

            tabbed.active = "tab-rf-intel"
            await pilot.pause()
            app.query_one("#rf-limit-input", Input).value = "not-a-number"
            app.query_one("#rf-query-input", Input).value = "Cobalt Strike"
            await pilot.click("#rf-match-btn")
            await pilot.pause()
            assert "Invalid numeric limit" in str(app.query_one("#rf-status", Static).render())

            tabbed.active = "tab-dashboard"
            await pilot.pause()
            await pilot.click("#dash-splunk-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.is_running
            assert isinstance(app.query_one("#dash-splunk-btn", Button), Button)

    asyncio.run(_run())


def test_tui_fills_screen_across_terminal_sizes(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": f"report:wl-{i}", "type": "brand" if i % 2 == 0 else "domain", "name": f"List {i}"}
        for i in range(12)
    ]
    mock_client.get_watchlist_entities.return_value = []

    app = create_app(
        client=mock_client, dry_run=True, workspace_dir=tmp_path, view_mode="admin"
    )

    async def _measure_all() -> dict[str, dict[str, tuple[int, int, int, int]]]:
        all_metrics: dict[str, dict[str, tuple[int, int, int, int]]] = {}
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            tabs = app.query_one("#main-tabs", TabbedContent)
            for size_key, (width, height) in (
                ("small", (80, 24)),
                ("medium", (120, 36)),
                ("large", (180, 52)),
            ):
                if (width, height) != (80, 24):
                    await pilot.resize_terminal(width, height)
                    await pilot.pause()
                metrics: dict[str, tuple[int, int, int, int]] = {}
                for tab_id, selector in (
                    ("tab-dashboard", "#dash-apis-table"),
                    ("tab-watchlists", "#wl-lists-table"),
                    ("tab-brand-logos", "#brand-table"),
                    ("tab-rf-intel", "#rf-log"),
                    ("tab-sigma", "#sigma-table"),
                    ("tab-splunk-bundle", "#splunk-results-table"),
                    ("tab-research", "#res-detail-log"),
                    ("tab-logs", "#app-log"),
                    ("tab-sentinelone", "#s1-table"),
                    ("tab-llm", "#llm-transcript"),
                    ("tab-splunk-search", "#splunk-search-table"),
                    ("tab-splunk-es", "#es-table"),
                    ("tab-settings", "#settings-form-pane"),
                ):
                    tabs.active = tab_id
                    await pilot.pause()
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    pane = app.query_one(f"#{tab_id}", TabPane)
                    target = app.query_one(selector)
                    metrics[tab_id] = (
                        pane.region.width,
                        pane.region.height,
                        target.region.width,
                        target.region.height,
                    )
                    assert pane.region.width == width
                    assert pane.region.height >= height - 5

                tabs.active = "tab-rf-intel"
                await pilot.pause()
                rf_ws = app.query_one("#rf-workspace", Container)
                rf_res_pane = app.query_one("#rf-results-pane", Vertical)
                rf_det_pane = app.query_one("#rf-detail-pane", Vertical)
                rf_table = app.query_one("#rf-results-table", DataTable)
                metrics["rf-table"] = (
                    rf_res_pane.region.width,
                    rf_res_pane.region.height,
                    rf_table.region.width,
                    rf_table.region.height,
                )
                if width >= 130:
                    assert rf_ws.has_class("split-horizontal")
                    assert rf_det_pane.region.x > rf_res_pane.region.x
                else:
                    assert not rf_ws.has_class("split-horizontal")
                    assert rf_det_pane.region.y > rf_res_pane.region.y
                rf_col_total = sum(c.width for c in rf_table.columns.values())
                assert rf_col_total >= rf_table.region.width - 14

                tabs.active = "tab-watchlists"
                await pilot.pause()
                ws_box = app.query_one("#wl-workspace", Container)
                wl_pane = app.query_one("#wl-lists-pane", Vertical)
                ent_pane = app.query_one("#wl-entities-pane", Vertical)
                wl_table = app.query_one("#wl-lists-table", DataTable)
                assert not ws_box.has_class("split-horizontal")
                assert not wl_pane.has_class("wl-hidden")
                assert ent_pane.has_class("wl-hidden")
                assert wl_table.region.width >= width - 12
                col_total = sum(c.width for c in wl_table.columns.values())
                assert col_total >= wl_table.region.width - 14
                all_metrics[size_key] = metrics
        return all_metrics

    measured = asyncio.run(_measure_all())
    small, medium, large = measured["small"], measured["medium"], measured["large"]

    for tab_id in small:
        assert large[tab_id][2] > small[tab_id][2], f"{tab_id} width did not scale"
        assert large[tab_id][3] > small[tab_id][3], f"{tab_id} height did not scale"
        assert medium[tab_id][3] > small[tab_id][3], f"{tab_id} medium height did not scale"


def test_tui_watchlists_auto_load_on_tab_activate_and_initial_tab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:auto-1", "type": "brand", "name": "Auto Loaded Brand List"},
        {"id": "report:auto-2", "type": "domain", "name": "Auto Loaded Domain List"},
    ]

    app_default = create_app(
        client=mock_client, dry_run=True, workspace_dir=tmp_path, view_mode="admin"
    )

    async def _run_switch() -> None:
        async with app_default.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            assert mock_client.get_watchlists.call_count == 0
            await pilot.press("2")
            await app_default.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.get_watchlists.call_count == 1
            table = app_default.query_one("#wl-lists-table", DataTable)
            assert table.row_count == 2
            assert "Auto Loaded Brand List" in [str(c) for c in table.get_row_at(0)]

            await pilot.press("1")
            await pilot.pause()
            await pilot.press("2")
            await app_default.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.get_watchlists.call_count == 1

            await pilot.click("#wl-load-btn")
            await app_default.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.get_watchlists.call_count == 2

    asyncio.run(_run_switch())

    mock_client.get_watchlists.reset_mock()
    app_direct = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-watchlists",
        workspace_dir=tmp_path,
    )

    async def _run_direct() -> None:
        async with app_direct.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app_direct.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.get_watchlists.call_count == 1
            table = app_direct.query_one("#wl-lists-table", DataTable)
            assert table.row_count == 2

    asyncio.run(_run_direct())

    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)
    no_tok_client = RecordedFutureClient(api_token=None)
    app_no_tok = create_app(
        client=no_tok_client,
        dry_run=True,
        initial_tab="tab-watchlists",
        workspace_dir=tmp_path,
    )

    async def _run_no_token() -> None:
        async with app_no_tok.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app_no_tok.workers.wait_for_complete()
            await pilot.pause()
            status_text = str(app_no_tok.query_one("#wl-status", Static).render())
            assert "RF_API_TOKEN not configured" in status_text

    asyncio.run(_run_no_token())


def test_tui_watchlists_double_click_and_enter_loads_entities(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:wl-0", "type": "brand", "name": "Alpha Brand"},
        {"id": "report:wl-1", "type": "domain", "name": "Beta Domains"},
        {"id": "report:wl-2", "type": "ip", "name": "Gamma IPs"},
    ]
    entities_by_list = {
        "report:wl-0": [
            {
                "entity": {"id": "hash:111", "type": "Hash", "name": "111"},
                "status": "ready",
                "context": {"annotation": "alpha logo"},
            }
        ],
        "report:wl-1": [
            {
                "entity": {"id": "idn:evil.test", "type": "InternetDomainName", "name": "evil.test"},
                "status": "ready",
                "context": {"annotation": "phishing domain"},
            },
            {
                "entity": {"id": "idn:bad.test", "type": "InternetDomainName", "name": "bad.test"},
                "status": "ready",
                "context": {"annotation": "c2 domain"},
            },
        ],
        "report:wl-2": [
            {
                "entity": {"id": "ip:198.51.100.1", "type": "IpAddress", "name": "198.51.100.1"},
                "status": "ready",
                "context": {"annotation": "scanner"},
            }
        ],
    }
    mock_client.get_watchlist_entities.side_effect = lambda lid: entities_by_list[lid]

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
            assert mock_client.get_watchlist_entities.call_count == 0

            wl_pane = app.query_one("#wl-lists-pane", Vertical)
            ent_pane = app.query_one("#wl-entities-pane", Vertical)
            ent_table = app.query_one("#wl-entities-table", DataTable)
            assert not wl_pane.has_class("wl-hidden")
            assert ent_pane.has_class("wl-hidden")

            # Single left-click immediately expands the entity list view
            await pilot.click("#wl-lists-table", offset=(4, 2))
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_watchlist_entities.assert_called_with("report:wl-0")
            assert wl_pane.has_class("wl-hidden")
            assert not ent_pane.has_class("wl-hidden")
            assert ent_table.row_count == 1
            assert "alpha logo" in [str(c) for c in ent_table.get_row_at(0)]
            header_text = str(app.query_one("#wl-entities-header", Static).render())
            assert "Alpha Brand" in header_text
            assert "report:wl-0" not in header_text

            # Top Back button returns to Watchlists finder
            await pilot.click("#wl-back-btn")
            await pilot.pause()
            assert not wl_pane.has_class("wl-hidden")
            assert ent_pane.has_class("wl-hidden")

            # Keyboard Down highlights without leaving browse view; Enter expands entities
            call_count_before = mock_client.get_watchlist_entities.call_count
            await pilot.press("down")
            await pilot.pause()
            assert mock_client.get_watchlist_entities.call_count == call_count_before
            assert app.query_one("#wl-target-list-id", Input).value == "report:wl-1"
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_watchlist_entities.assert_called_with("report:wl-1")
            assert ent_table.row_count == 2
            assert "evil.test" in [str(c) for c in ent_table.get_row_at(0)]

            # Bottom Back button returns to Watchlists finder; clicking row 2 expands Gamma IPs
            await pilot.click("#wl-back-bottom-btn")
            await pilot.pause()
            assert not wl_pane.has_class("wl-hidden")
            await pilot.click("#wl-lists-table", offset=(4, 4))
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_watchlist_entities.assert_called_with("report:wl-2")
            assert ent_table.row_count == 1
            assert "198.51.100.1" in [str(c) for c in ent_table.get_row_at(0)]
            assert "Gamma IPs" in str(app.query_one("#wl-entities-header", Static).render())

    asyncio.run(_run())


def test_tui_watchlists_expandable_search_and_filter(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:wl-1", "type": "brand", "name": "Alpha Brand"},
        {"id": "report:wl-2", "type": "domain", "name": "Beta Phishing Domains"},
        {"id": "report:wl-3", "type": "ip", "name": "Gamma C2 IPs"},
    ]
    mock_client.get_watchlist_entities.return_value = [
        {
            "entity": {"id": "idn:alpha.test", "type": "InternetDomainName", "name": "alpha.test"},
            "status": "ready",
            "context": {"annotation": "primary brand"},
        },
        {
            "entity": {"id": "idn:beta.test", "type": "InternetDomainName", "name": "beta.test"},
            "status": "ready",
            "context": {"annotation": "phishing lure"},
        },
    ]

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

            collapsible = app.query_one("#wl-filter-collapsible", Collapsible)
            lists_table = app.query_one("#wl-lists-table", DataTable)
            ent_table = app.query_one("#wl-entities-table", DataTable)

            assert collapsible.collapsed is True
            assert collapsible.region.height == 1
            assert lists_table.row_count == 3

            await pilot.press("slash")
            await pilot.pause()
            assert collapsible.collapsed is False
            assert collapsible.region.height > 1
            assert app.focused is not None
            assert app.focused.id == "wl-search-input"

            search_input = app.query_one("#wl-search-input", Input)
            search_input.value = "Beta"
            await pilot.pause()
            assert lists_table.row_count == 1
            assert "Beta Phishing Domains" in [str(c) for c in lists_table.get_row_at(0)]
            assert mock_client.get_watchlists.call_count == 1

            search_input.value = ""
            await pilot.pause()
            app.query_one("#wl-type-filter", Select).value = "ip"
            await pilot.pause()
            assert lists_table.row_count == 1
            assert "Gamma C2 IPs" in [str(c) for c in lists_table.get_row_at(0)]
            assert mock_client.get_watchlists.call_count == 1

            await pilot.click("#wl-lists-table", offset=(4, 2), times=2)
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert ent_table.row_count == 2

            ent_search = app.query_one("#wl-entity-search-input", Input)
            ent_search.value = "lure"
            await pilot.pause()
            assert ent_table.row_count == 1
            assert "beta.test" in [str(c) for c in ent_table.get_row_at(0)]

            await pilot.click("#wl-clear-filter-btn")
            await pilot.pause()
            assert lists_table.row_count == 3
            assert ent_table.row_count == 2
            assert str(app.query_one("#wl-type-filter", Select).value) == "all"

            await pilot.press("escape")
            await pilot.pause()
            assert collapsible.collapsed is True
            assert collapsible.region.height == 1

    asyncio.run(_run())


def _select_context_option_by_id(app: SocLensApp, option_id: str) -> None:
    opts = app.screen.query_one("#ctx-menu-options", OptionList)
    opts.highlighted = opts.get_option_index(option_id)


def test_tui_watchlists_right_click_context_menu_load_and_interact(tmp_path: Path) -> None:
    mock_client = MagicMock()
    lists_payload = [
        {"id": "report:wl-0", "type": "brand", "name": "Alpha Brand"},
        {"id": "report:wl-1", "type": "domain", "name": "Beta Domains"},
    ]
    call_idx = {"n": 0}

    def _get_lists(*_args: object, **_kwargs: object) -> list[dict[str, str]]:
        call_idx["n"] += 1
        return [] if call_idx["n"] == 1 else lists_payload

    mock_client.get_watchlists.side_effect = _get_lists
    mock_client.get_watchlist_entities.return_value = [
        {
            "entity": {"id": "idn:evil.test", "type": "InternetDomainName", "name": "evil.test"},
            "status": "ready",
            "context": {"annotation": "phishing"},
        }
    ]
    mock_client.get_list_info.return_value = {
        "id": "report:wl-1",
        "type": "domain",
        "name": "Beta Domains",
    }
    mock_client.get_list_status.return_value = {"size": 1, "status": "ready"}
    mock_client.v2_lookup.return_value = {"data": {"risk": {"score": 89}}}

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

            lists_table = app.query_one("#wl-lists-table", DataTable)
            ent_table = app.query_one("#wl-entities-table", DataTable)
            assert lists_table.row_count == 0

            await pilot.click("#wl-lists-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            await pilot.click("#ctx-menu-options", offset=(2, 0))
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert lists_table.row_count == 2

            await pilot.click("#wl-lists-table", offset=(4, 3), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "inspect_info")
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_list_info.assert_called_once_with("report:wl-1")
            mock_client.get_list_status.assert_called_once_with("report:wl-1")
            assert "Beta Domains" in str(app.query_one("#wl-status", Static).render())

            await pilot.click("#wl-lists-table", offset=(4, 3), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            assert app.query_one("#wl-target-list-id", Input).value == "report:wl-1"
            await pilot.click("#ctx-menu-options", offset=(2, 0))
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_watchlist_entities.assert_called_with("report:wl-1")
            assert ent_table.row_count == 1
            assert "evil.test" in [str(c) for c in ent_table.get_row_at(0)]

            await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "lookup_intel")
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-rf-intel"
            assert str(app.query_one("#rf-v2-type", Select).value) == "domain"
            assert app.query_one("#rf-ioc-input", Input).value == "evil.test"
            mock_client.v2_lookup.assert_called_once()
            call_args, call_kwargs = mock_client.v2_lookup.call_args
            assert call_args == ("domain", "evil.test")
            assert "risk" in call_kwargs.get("fields", [])
            rf_table = app.query_one("#rf-results-table", DataTable)
            assert rf_table.row_count == 1
            row_vals = [str(c) for c in rf_table.get_row_at(0)]
            assert "evil.test" in row_vals
            assert "89" in row_vals

            await pilot.press("2")
            await pilot.pause()
            await pilot.click("#wl-back-btn")
            await pilot.pause()
            await pilot.click("#wl-lists-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, ContextMenuModal)

            await pilot.click("#wl-lists-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            await pilot.click(offset=(1, 1))
            await pilot.pause()
            assert not isinstance(app.screen, ContextMenuModal)

    asyncio.run(_run())


def test_tui_delete_entity_always_requires_approval_prompt(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:wl-1", "type": "domain", "name": "Protected Domains"}
    ]
    mock_client.get_watchlist_entities.return_value = [
        {
            "entity": {"id": "idn:evil.test", "type": "InternetDomainName", "name": "evil.test"},
            "status": "ready",
            "context": {"annotation": "c2"},
        }
    ]
    mock_client.remove_entity.return_value = {"result": "removed"}

    app = create_app(
        client=mock_client,
        dry_run=False,
        initial_tab="tab-watchlists",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            app.query_one("#wl-target-list-id", Input).value = "report:wl-1"
            app.query_one("#wl-ent-type", Input).value = "InternetDomainName"
            app.query_one("#wl-ent-value", Input).value = "evil.test"

            await pilot.click("#wl-remove-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            assert app.focused is not None
            assert app.focused.id == "confirm-cancel-btn"
            mock_client.remove_entity.assert_not_called()

            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert not isinstance(app.screen, ConfirmActionModal)
            mock_client.remove_entity.assert_not_called()

            await pilot.click("#wl-remove-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.press("escape")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.remove_entity.assert_not_called()

            await pilot.click("#wl-remove-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.remove_entity.call_count == 1

            await pilot.click("#wl-lists-table", offset=(4, 2), times=2)
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "remove_entity")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            assert mock_client.remove_entity.call_count == 1

            await pilot.click("#confirm-cancel-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.remove_entity.call_count == 1

            await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
            await pilot.pause()
            _select_context_option_by_id(app, "remove_entity")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert mock_client.remove_entity.call_count == 2

    asyncio.run(_run())


def test_tui_brand_sync_deletion_requires_approval_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soclens.tui.screens.brand_logos as brand_mod

    stale_hash = "b" * 64
    new_hash = "a" * 64
    monkeypatch.setattr(
        brand_mod,
        "calculate_brand_sync_delta",
        lambda *_a, **_kw: (
            {new_hash: {"domain": "acme.test"}},
            {stale_hash: {"entity": {"id": f"hash:{stale_hash}", "name": stale_hash}}},
            [new_hash],
            [{"id": f"hash:{stale_hash}", "name": stale_hash}],
            {},
            {},
        ),
    )
    execute_mock = MagicMock(return_value=True)
    monkeypatch.setattr(brand_mod, "execute_domain_brand_sync", execute_mock)

    app = create_app(
        client=MagicMock(),
        dry_run=False,
        initial_tab="tab-brand-logos",
        workspace_dir=tmp_path,
    )

    async def _wait_for_confirm_modal(pilot: object) -> None:
        for _ in range(40):
            await pilot.pause(0.05)  # type: ignore[attr-defined]
            if isinstance(app.screen, ConfirmActionModal):
                return
        raise AssertionError("Timed out waiting for ConfirmActionModal")

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.query_one("#brand-list-id", Input).value = "report:brand-1"
            app.query_one("#brand-domains", Input).value = "acme.test"

            await pilot.click("#brand-sync-btn")
            await _wait_for_confirm_modal(pilot)
            execute_mock.assert_not_called()

            await pilot.click("#confirm-cancel-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            execute_mock.assert_not_called()
            assert "cancelled" in str(app.query_one("#brand-status", Static).render()).lower()

            await pilot.click("#brand-sync-btn")
            await _wait_for_confirm_modal(pilot)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            execute_mock.assert_called_once()

    asyncio.run(_run())


def test_tui_other_tabs_right_click_menus(tmp_path: Path) -> None:
    cache_path = tmp_path / "sigma_rules_cache.json"
    cache_path.write_text(
        json.dumps(
            [
                {
                    "rule_id": "doc:sigma-rc",
                    "title": "Right Click Sigma Rule",
                    "file_name": "rc.yml",
                    "level": "high",
                    "index": "*wineventlog",
                    "content": "title: Right Click Sigma Rule\n",
                }
            ]
        ),
        encoding="utf-8",
    )
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = []
    app = create_app(
        client=mock_client, dry_run=True, workspace_dir=tmp_path, view_mode="admin"
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()

            await pilot.click("#dash-apis-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "open_watchlists")
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-watchlists"

            await pilot.press("5")
            await pilot.pause()
            await pilot.click("#sigma-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "load_cached")
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            sigma_table = app.query_one("#sigma-table", DataTable)
            assert sigma_table.row_count == 1
            assert "Right Click Sigma Rule" in [str(c) for c in sigma_table.get_row_at(0)]

    asyncio.run(_run())


def _rich_log_text(app: SocLensApp, selector: str = "#rf-log") -> str:
    log_widget = app.query_one(selector, RichLog)
    return "\n".join(line.text for line in log_widget.lines)


def _render_to_str(renderable: object) -> str:
    buf = io.StringIO()
    console = Console(file=buf, width=100, force_terminal=False, no_color=True)
    console.print(renderable)
    return buf.getvalue()


def test_rf_formatters_live_and_mock_schemas_and_markup_safety() -> None:
    live_alerts_payload = {
        "data": [
            {
                "id": "al-live-1",
                "title": "Lookalike [APT29] on hxxp://evil[.]test/login",
                "type": "ENTITY_MATCH",
                "review": {
                    "priority": "High",
                    "status_in_portal": "New",
                    "assignee": "analyst@soc.local",
                    "note": "Check [!] tags",
                },
                "rule": {"id": "rule-1", "name": "Brand [Abuse] Rule"},
                "log": {"triggered": "2026-11-24T12:00:00Z"},
                "ai_insights": {"text": "Suspicious activity [confirmed]"},
                "hits": [
                    {
                        "id": "hit-1",
                        "document": {"title": "Pastebin [Leak]", "url": "https://evil.test/[1]"},
                        "entities": [{"id": "idn:evil.test", "name": "evil.test"}],
                        "fragment": "Found token [secret] on hxxp://evil[.]test",
                    }
                ],
            }
        ],
        "counts": {"returned": 1, "total": 42},
    }
    mock_alerts_payload = {
        "data": {
            "results": [
                {
                    "id": "alert-v3-1",
                    "title": "Brand Logo Match Detected",
                    "triggered": "2026-10-22T01:00:00Z",
                    "statusInPortal": "New",
                    "assignee": None,
                    "alertRule": {"id": "rule-1", "name": "Brand Monitoring"},
                }
            ]
        },
        "counts": {"returned": 1, "total": 1},
    }

    live_items, live_total = extract_alerts_v3(live_alerts_payload)
    assert len(live_items) == 1 and live_total == 42
    norm_live = normalize_alert_v3(live_items[0])
    assert norm_live["status"] == "New"
    assert norm_live["priority"] == "High"
    assert norm_live["rule_name"] == "Brand [Abuse] Rule"
    assert norm_live["hits_count"] == 1
    rendered_live = _render_to_str(render_alert_v3_detail(norm_live))
    assert "Lookalike [APT29]" in rendered_live
    assert "Suspicious activity [confirmed]" in rendered_live
    assert "Pastebin [Leak]" in rendered_live

    mock_items, mock_total = extract_alerts_v3(mock_alerts_payload)
    assert len(mock_items) == 1 and mock_total == 1
    norm_mock = normalize_alert_v3(mock_items[0])
    assert norm_mock["rule_name"] == "Brand Monitoring"
    assert norm_mock["status"] == "New"

    pb_detail_item = {
        "playbook_alert_id": "pb-101",
        "category": "malicious_sites",
        "panel_status": {
            "status": "InProgress",
            "priority": "High",
            "risk_score": 88,
            "entity_name": "lookalike[.]invalid",
            "targets": ["brand.com"],
        },
        "panel_evidence_summary": {
            "explanation": "Matched watched logo hash [hash]",
            "url": "hxxp://lookalike[.]invalid/login",
            "assets": [{"type": "image_hash", "hash_id": "hash:" + ("a" * 64)}],
            "hashes": ["hash:" + ("b" * 64)],
            "screenshots": ["shot-1"],
        },
        "panel_evidence_dns": {"ip_list": ["198.51.100.5"]},
        "panel_evidence_whois": {"body": [{"key": "Registrar", "value": "ExampleReg [Test]"}]},
    }
    norm_pb = normalize_playbook_alert(pb_detail_item)
    assert len(norm_pb["logo_hashes"]) == 2
    assert norm_pb["screenshot_ids"] == ["shot-1"]
    rendered_pb = _render_to_str(render_playbook_alert_detail(norm_pb, full_detail=pb_detail_item))
    assert "a" * 64 in rendered_pb
    assert "198.51.100.5" in rendered_pb
    assert "ExampleReg [Test]" in rendered_pb

    v2_norm = normalize_v2_record(
        "ip",
        "198.51.100.10",
        {
            "data": {
                "entity": {"id": "ip:198.51.100.10", "name": "198.51.100.10", "type": "IpAddress"},
                "risk": {
                    "score": 82,
                    "criticalityLabel": "High",
                    "riskString": "4/10",
                    "evidenceDetails": [
                        {
                            "criticality": 3,
                            "rule": "Recent C2 [Botnet]",
                            "evidenceString": "Seen communicating with [host]",
                            "timestamp": "2026-11-24T01:00:00Z",
                        }
                    ],
                },
                "location": {
                    "organization": "Evil Host [ASN]",
                    "asn": "AS64500",
                    "location": {"city": "TestCity", "country": "US"},
                },
            }
        },
    )
    rendered_v2 = _render_to_str(render_v2_intel_card(v2_norm))
    assert "82/99" in rendered_v2
    assert "Recent C2 [Botnet]" in rendered_v2
    assert "AS64500" in rendered_v2

    assert len(extract_sandbox_samples({"samples": [{"id": "s1"}]})) == 1
    assert len(extract_sandbox_samples({"data": [{"id": "s2"}]})) == 1


def test_tui_rf_intel_alerts_playbook_cases_overview_and_json_toggle(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.search_alerts_v3.return_value = {
        "data": [
            {
                "id": "al-1",
                "title": "C2 Beacon Detected",
                "type": "ENTITY_MATCH",
                "review": {"priority": "High", "status_in_portal": "New", "assignee": "alice"},
                "rule": {"id": "r1", "name": "C2 Outbound Rule"},
                "log": {"triggered": "2026-11-24T10:00:00Z"},
                "hits": [
                    {
                        "id": "h1",
                        "entities": [{"id": "ip:198.51.100.10", "name": "198.51.100.10"}],
                        "fragment": "Outbound beacon observed",
                    }
                ],
            },
            {
                "id": "al-2",
                "title": "Resolved Noise Alert",
                "type": "ENTITY_MATCH",
                "review": {"priority": "Low", "status_in_portal": "Resolved"},
                "rule": {"id": "r2", "name": "Low Rule"},
                "log": {"triggered": "2026-11-23T10:00:00Z"},
                "hits": [],
            },
        ],
        "counts": {"returned": 2, "total": 2},
    }
    mock_client.get_alert_v3.return_value = {
        "data": {
            "id": "al-1",
            "title": "C2 Beacon Detected",
            "review": {"priority": "High", "status_in_portal": "New", "assignee": "alice"},
            "rule": {"id": "r1", "name": "C2 Outbound Rule"},
            "ai_insights": {"text": "Deep AI Insight: Known C2 infrastructure"},
            "hits": [],
        }
    }
    mock_client.search_playbook_alerts.return_value = {
        "data": [
            {
                "playbook_alert_id": "pb-1",
                "category": "domain_abuse",
                "priority": "High",
                "status": "New",
                "title": "Lookalike Bank Portal",
            }
        ],
        "counts": {"returned": 1, "total": 1},
    }
    mock_client.get_playbook_alert.return_value = {
        "status": {"status_code": "Ok"},
        "data": {
            "playbook_alert_id": "pb-1",
            "panel_status": {
                "status": "New",
                "priority": "High",
                "risk_score": 91,
                "targets": ["mybank.example"],
            },
            "panel_evidence_summary": {
                "explanation": "Matched official logo SHA-256",
                "assets": [{"type": "image_hash", "hash_id": "hash:" + ("f" * 64)}],
                "screenshots": ["shot-pb-1"],
            },
        },
    }
    mock_client.search_cases.return_value = {
        "data": [
            {
                "id": "case-1",
                "title": "Phishing Investigation",
                "status": "Open",
                "priority": "High",
                "assignee": "bob",
            }
        ],
        "total_count": 1,
    }
    mock_client.lookup_cases.return_value = {
        "data": [
            {
                "id": "case-1",
                "title": "Phishing Investigation",
                "status": "Open",
                "priority": "High",
                "description": "Full case description from lookup",
                "log": [{"created": "2026-11-24T09:00:00Z", "author": "bob", "message": "Opened"}],
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
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()

            # Welcome view shown initially (no unsolicited API calls)
            assert mock_client.search_alerts_v3.call_count == 0
            assert "Available Workflows" in _rich_log_text(app)

            # 1. Load Alerts v3 -> structured DataTable & Overview inspector (NOT raw JSON)
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = app.query_one("#rf-results-table", DataTable)
            assert table.row_count == 2
            assert "C2 Beacon Detected" in [str(c) for c in table.get_row_at(0)]
            assert "Alerts v3: 2" in str(app.query_one("#rf-summary-bar", Static).render())

            overview_text = _rich_log_text(app)
            assert "C2 Beacon Detected" in overview_text
            assert "C2 Outbound Rule" in overview_text
            assert '"status_in_portal":' not in overview_text

            # Toggle Raw JSON via button and back via 'j' key
            await pilot.click("#rf-view-json-btn")
            await pilot.pause()
            json_text = _rich_log_text(app)
            assert '"status_in_portal": "New"' in json_text

            await pilot.press("j")
            await pilot.pause()
            assert '"status_in_portal": "New"' not in _rich_log_text(app)

            # Filter drawer toggle via '/' and instant filtering
            collapsible = app.query_one("#rf-filter-collapsible", Collapsible)
            assert collapsible.collapsed is True
            await pilot.press("slash")
            await pilot.pause()
            assert collapsible.collapsed is False
            app.query_one("#rf-table-filter", Input).value = "Beacon"
            await pilot.pause()
            assert table.row_count == 1
            await pilot.click("#rf-clear-filter-btn")
            await pilot.pause()
            assert table.row_count == 2
            await pilot.press("escape")
            await pilot.pause()
            assert collapsible.collapsed is True

            # Enter on Alert v3 triggers deep detail fetch (auto-enrich may also have enriched unassigned rows)
            table.focus()
            await pilot.pause()
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_alert_v3.assert_any_call("al-1")
            assert "Deep AI Insight" in _rich_log_text(app)

            # 2. Load Playbook Alerts + Deep Detail
            await pilot.click("#rf-pb-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            assert "Lookalike Bank Portal" in [str(c) for c in table.get_row_at(0)]
            await pilot.click("#rf-fetch-detail-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_playbook_alert.assert_any_call("domain_abuse", "pb-1")
            assert "domain_abuse" in [str(c) for c in table.get_row_at(0)]
            pb_text = _rich_log_text(app)
            assert "domain_abuse" in pb_text
            assert "Playbook Alert [-]" not in pb_text
            assert "f" * 32 in pb_text
            assert "shot-pb-1" in pb_text

            # 3. Load Cases + Deep Detail + switch back to cached Alerts v3 via Select
            await pilot.click("#rf-cases-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            await pilot.click("#rf-fetch-detail-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.lookup_cases.assert_any_call(["case-1"])
            assert "Full case description from lookup" in _rich_log_text(app)

            app.query_one("#rf-view-select", Select).value = "alerts_v3"
            await pilot.pause()
            assert table.row_count == 2
            assert "C2 Beacon Detected" in [str(c) for c in table.get_row_at(0)]

    asyncio.run(_run())


def test_tui_rf_intel_v2_soar_entity_match_and_sandbox_views(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.v2_lookup.side_effect = [
        {
            "data": {
                "entity": {"id": "ip:198.51.100.10", "name": "198.51.100.10", "type": "IpAddress"},
                "risk": {
                    "score": 85,
                    "criticalityLabel": "High",
                    "riskString": "4/10",
                    "evidenceDetails": [{"criticality": 3, "rule": "Recent C2", "evidenceString": "C2 hit"}],
                },
                "location": {"asn": "AS64512", "organization": "TestISP"},
            }
        },
        {
            "data": {
                "entity": {"id": "idn:bad.example", "name": "bad.example", "type": "InternetDomainName"},
                "risk": {"score": 45, "criticalityLabel": "Medium", "riskString": "2/10", "evidenceDetails": []},
            }
        },
    ]
    mock_client.v2_company_by_domain.return_value = {
        "data": {
            "entity": {"id": "company:c1", "name": "Acme Corp", "type": "Company"},
            "risk": {"score": 12, "criticalityLabel": "Low", "riskString": "1/10", "evidenceDetails": []},
        }
    }
    mock_client.soar_enrich.return_value = {
        "data": {
            "results": [
                {
                    "entity": {"id": "ip:198.51.100.10", "name": "198.51.100.10", "type": "ip"},
                    "risk": {
                        "score": 77,
                        "level": 3,
                        "context": {"phishing": {"score": 70}},
                        "rule": {"evidence": [{"rule": "Sighting Rule"}]},
                    },
                }
            ]
        }
    }
    mock_client.soar_triage.return_value = {
        "data": {
            "context": "phishing",
            "results": [
                {
                    "entity": {"id": "domain:evil.test", "name": "evil.test", "type": "domain"},
                    "verdict": True,
                    "score": 88,
                    "context": "phishing",
                }
            ],
        }
    }
    mock_client.entity_match.return_value = [
        {"id": "company:abc", "type": "Company", "name": "Acme Bank"}
    ]
    mock_client.entity_lookup.return_value = {
        "id": "company:abc",
        "type": "Company",
        "name": "Acme Bank",
        "aliases": ["Acme Financial"],
    }
    mock_client.sandbox_search.return_value = {
        "samples": [
            {
                "id": "sb-1",
                "status": "reported",
                "score": 9,
                "target": "dropper.exe",
                "sha256": "d" * 64,
                "submitted": "2026-11-24T08:00:00Z",
            }
        ]
    }
    mock_client.sandbox_get_overview.return_value = {
        "sample": {"id": "sb-1", "status": "reported", "score": 9, "target": "dropper.exe", "sha256": "d" * 64},
        "signatures": [{"score": 9, "name": "CobaltStrike Beacon", "ttp": ["T1071"], "desc": "Beacon config"}],
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
            table = app.query_one("#rf-results-table", DataTable)

            # Accumulate two Connect v2 lookups + Company by domain
            app.query_one("#rf-v2-type", Select).value = "ip"
            app.query_one("#rf-ioc-input", Input).value = "198.51.100.10"
            await pilot.click("#rf-lookup-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            assert "AS64512" in _rich_log_text(app)

            app.query_one("#rf-v2-type", Select).value = "domain"
            app.query_one("#rf-ioc-input", Input).value = "bad.example"
            await pilot.pause()
            await pilot.click("#rf-lookup-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 2

            # Expand filter/tools drawer to access Company by Domain and SOAR Triage
            await pilot.press("slash")
            await pilot.pause()

            app.query_one("#rf-ioc-input", Input).value = "acme.example"
            await pilot.click("#rf-company-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 3
            assert "Acme Corp" in _rich_log_text(app)

            # SOAR Enrich + SOAR Triage
            app.query_one("#rf-v2-type", Select).value = "ip"
            app.query_one("#rf-ioc-input", Input).value = "198.51.100.10"
            await pilot.click("#rf-enrich-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            assert "Sighting Rule" in _rich_log_text(app)

            await pilot.click("#rf-triage-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert "MALICIOUS" in _rich_log_text(app)

            # Entity Match + Deep Entity Lookup
            app.query_one("#rf-query-input", Input).value = "Acme"
            await pilot.click("#rf-match-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            await pilot.click("#rf-fetch-detail-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.entity_lookup.assert_called_once_with("company:abc")
            assert "Acme Financial" in _rich_log_text(app)

            # Sandbox Search + Overview Signatures
            app.query_one("#rf-query-input", Input).value = "dropper"
            await pilot.click("#rf-sandbox-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1
            await pilot.pause()
            await pilot.click("#rf-fetch-detail-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.sandbox_get_overview.assert_called_once_with("sb-1")
            assert "CobaltStrike Beacon" in _rich_log_text(app)

    asyncio.run(_run())


def test_tui_rf_intel_triage_create_case_and_context_pivots(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.search_alerts_v3.return_value = {
        "data": [
            {
                "id": "al-triage-1",
                "title": "Suspicious Domain Hit",
                "review": {"priority": "High", "status_in_portal": "New"},
                "rule": {"name": "Domain Rule"},
                "hits": [{"entities": [{"id": "idn:evil.test", "name": "evil.test"}]}],
            }
        ],
        "counts": {"returned": 1, "total": 1},
    }
    mock_client.update_alerts_v2.return_value = {"success": ["al-triage-1"], "error": []}
    mock_client.create_case.return_value = {
        "id": "case-99",
        "title": "Suspicious Domain Hit",
        "status": "Open",
        "priority": "High",
    }
    mock_client.entity_match.return_value = [
        {"id": "idn:pivot.test", "type": "InternetDomainName", "name": "pivot.test"}
    ]
    mock_client.v2_lookup.return_value = {
        "data": {
            "entity": {"id": "idn:pivot.test", "name": "pivot.test", "type": "InternetDomainName"},
            "risk": {"score": 66, "criticalityLabel": "High", "riskString": "3/10", "evidenceDetails": []},
        }
    }

    # 1. Dry-run prevents mutations on Triage & Create Case
    dry_app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )

    async def _run_dry() -> None:
        async with dry_app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await dry_app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#rf-triage-status-btn")
            await pilot.pause()
            assert isinstance(dry_app.screen, TriageItemModal)
            dry_app.screen.query_one("#triage-status-select", Select).value = "Resolved"
            await pilot.click("#triage-apply-btn")
            await dry_app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.update_alerts_v2.assert_not_called()

            await pilot.click("#rf-results-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(dry_app.screen, ContextMenuModal)
            _select_context_option_by_id(dry_app, "create_case")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(dry_app.screen, CreateCaseModal)
            await pilot.click("#case-create-btn")
            await dry_app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.create_case.assert_not_called()

    asyncio.run(_run_dry())

    # 2. Live mode applies Triage update, creates Case, and pivots from Entity Match -> v2 & Watchlists
    live_app = create_app(
        client=mock_client,
        dry_run=False,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
        view_mode="admin",
    )

    async def _run_live() -> None:
        async with live_app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await live_app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.press("t")
            await pilot.pause()
            assert isinstance(live_app.screen, TriageItemModal)
            live_app.screen.query_one("#triage-status-select", Select).value = "Resolved"
            live_app.screen.query_one("#triage-assignee-input", Input).value = "soc_lead"
            await pilot.click("#triage-apply-btn")
            await live_app.workers.wait_for_complete()
            await pilot.pause()

            mock_client.update_alerts_v2.assert_called_once_with(
                [{"id": "al-triage-1", "statusInPortal": "Resolved", "assignee": "soc_lead"}]
            )
            table = live_app.query_one("#rf-results-table", DataTable)
            assert "Resolved" in [str(c) for c in table.get_row_at(0)]

            await pilot.click("#rf-results-table", offset=(4, 2), button=3)
            await pilot.pause()
            _select_context_option_by_id(live_app, "create_case")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(live_app.screen, CreateCaseModal)
            await pilot.click("#case-create-btn")
            await live_app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.create_case.assert_called_once()

            # Entity Match -> right-click pivot to Connect v2 -> right-click Send to Watchlists
            live_app.query_one("#rf-query-input", Input).value = "pivot.test"
            await pilot.click("#rf-match-btn")
            await live_app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#rf-results-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(live_app.screen, ContextMenuModal)
            _select_context_option_by_id(live_app, "pivot_v2")
            await pilot.press("enter")
            await live_app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.v2_lookup.assert_called_once()
            assert "pivot.test" in _rich_log_text(live_app)

            await pilot.click("#rf-results-table", offset=(4, 2), button=3)
            await pilot.pause()
            _select_context_option_by_id(live_app, "send_watchlist")
            await pilot.press("enter")
            await live_app.workers.wait_for_complete()
            await pilot.pause()
            assert live_app.query_one("#main-tabs", TabbedContent).active == "tab-watchlists"
            assert live_app.query_one("#wl-ent-value", Input).value == "pivot.test"

    asyncio.run(_run_live())


def _make_test_png(width: int, height: int, *, color_type: int = 2) -> bytes:
    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I4s", len(data), ctype) + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    chunks = [_chunk(b"IHDR", ihdr)]
    raw = bytearray()
    if color_type == 3:
        chunks.append(_chunk(b"PLTE", bytes([220, 40, 40, 30, 120, 220])))
        chunks.append(_chunk(b"tRNS", bytes([255, 180])))
        for y in range(height):
            raw.append(0)
            raw.extend([(y % 2)] * width)
    elif color_type == 6:
        for y in range(height):
            raw.append(0)
            for x in range(width):
                raw.extend((40, 180, 90, 255 if (x + y) % 2 == 0 else 128))
    else:
        for _ in range(height):
            raw.append(0)
            raw.extend([200, 60, 40] * width)
    chunks.append(_chunk(b"IDAT", zlib.compress(bytes(raw))))
    chunks.append(_chunk(b"IEND", b""))
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks)


def test_image_render_pure_python_png_and_halfblock() -> None:
    for ctype in (2, 3, 6):
        png_bytes = _make_test_png(24, 16, color_type=ctype)
        decoded = decode_image(png_bytes)
        assert decoded.width == 24
        assert decoded.height == 16
        assert len(decoded.rgb_rows) == 16
        rendered = render_image_halfblock(decoded, max_width=20, max_height=8)
        assert "\u2580" in rendered.plain
        assert not [ch for ch in rendered.plain if ord(ch) > 0x1F000]

    with pytest.raises(ValueError):
        decode_image(b"not-a-png")


def test_rf_formatters_live_playbook_dns_whois_logs_and_dark_web_zero_raw_dicts() -> None:
    pb_live_domain_abuse = {
        "playbook_alert_id": "task:8dfdcd30",
        "category": "domain_abuse",
        "panel_status": {
            "status": "New",
            "priority": "Informational",
            "risk_score": 0,
            "entity_name": "trtbrand.example",
            "attackers": ["idn:trtbrand.example"],
            "case_rule_label": "DomainAbuse",
        },
        "panel_evidence_summary": {
            "explanation": "Domain registered matching *examplebrand*",
            "cause": "similar_domains",
            "resolved_record_list": [
                {
                    "entity": "ip:172.67.215.221",
                    "risk_score": 27,
                    "criticality": "Medium",
                    "record_type": "A",
                    "context_list": [],
                }
            ],
            "screenshots": [],
        },
        "panel_evidence_dns": {
            "ip_list": [
                {
                    "entity": "ip:172.67.215.221",
                    "risk_score": 27,
                    "criticality": "Medium",
                    "record_type": "A",
                    "context_list": [],
                }
            ],
            "ns_list": [
                {
                    "entity": "idn:austin.ns.cloudflare.com",
                    "risk_score": 10,
                    "criticality": "Low",
                    "record_type": "NS",
                    "context_list": [],
                }
            ],
        },
        "panel_evidence_whois": {
            "body": [
                {
                    "provider": "whois",
                    "entity": "idn:trtbrand.example",
                    "attribute": "attr:whois",
                    "value": {
                        "status": "addPeriod clientTransferProhibited",
                        "nameServers": ["idn:austin.ns.cloudflare.com"],
                        "registrarName": "Cloudflare, Inc.",
                        "updatedDate": "2026-11-24T00:00:00.000Z",
                        "createdDate": "2026-11-24T00:00:00.000Z",
                        "expiresDate": "2027-11-24T00:00:00.000Z",
                        "privateRegistration": False,
                    },
                },
                {
                    "provider": "whois",
                    "entity": "idn:trtbrand.example",
                    "attribute": "attr:whoisContacts",
                    "value": {
                        "city": "DATA REDACTED",
                        "name": "DATA REDACTED",
                        "state": "005",
                        "country": "Taiwan",
                        "telephone": "+1.4153197517",
                        "type": "registrant",
                    },
                },
                {
                    "provider": "whois",
                    "entity": "idn:trtbrand.example",
                    "attribute": "attr:whoisContacts",
                    "value": {"type": "technicalContact"},
                },
                {
                    "provider": "whois",
                    "entity": "idn:trtbrand.example",
                    "attribute": "attr:whoisContacts",
                    "value": {"type": "administrativeContact"},
                },
            ]
        },
        "panel_log_v2": [
            {
                "id": "uuid:1",
                "created": "2026-11-24T15:04:33.750Z",
                "changes": [
                    {
                        "type": "whois_change",
                        "domain": "trtbrand.example",
                        "new_record": {
                            "registrar_name": "Cloudflare, Inc.",
                            "name_servers": ["austin.ns.cloudflare.com"],
                        },
                        "added_contacts": [{"type": "registrant"}],
                        "removed_contacts": [],
                    }
                ],
            },
            {
                "id": "uuid:2",
                "created": "2026-11-24T15:03:22.806Z",
                "changes": [
                    {
                        "type": "attacker_added_change",
                        "attacker": "trtbrand.example",
                        "cause": "similar_domains",
                        "similar_domains_keywords": ["*examplebrand*"],
                    }
                ],
            },
        ],
    }

    norm = normalize_playbook_alert(pb_live_domain_abuse)
    rendered = _render_to_str(render_playbook_alert_detail(norm, full_detail=pb_live_domain_abuse))
    for expected in (
        "172.67.215.221",
        "27",
        "Medium",
        "austin.ns.cloudflare.com",
        "Cloudflare, Inc.",
        "Taiwan",
        "+1.4153197517",
        "Redacted: Name, City",
        "Technical, Administrative",
        "WHOIS updated for trtbrand.example",
        "Attacker added: trtbrand.example",
    ):
        assert expected in rendered
    for forbidden in ("{'entity':", "{'status':", "{'type':", "Field", "{'type': 'whois_change'"):
        assert forbidden not in rendered

    pb_dark_web = {
        "playbook_alert_id": "task:dw-1",
        "category": "dark_web",
        "panel_status": {"status": "InProgress", "priority": "Informational", "assignee_name": "Ryan"},
        "panel_evidence_summary": {
            "matched_assets": [{"type": "company", "entity_id": "company:example123", "name": "Example Bank"}],
            "assessments": [{"name": "General Telegram Mention", "criticality": "Informational"}],
            "details": {"type": "telegram_mention", "telegram_channel_title": "Test Channel"},
        },
        "panel_triage": {
            "rationale": "Only mentioned incidentally.",
            "assessment": {"name": "General Telegram Mention", "criticality": "Informational"},
        },
        "panel_cached_content": {
            "title": "Test Channel",
            "downloaded": "2026-11-24T09:46:16.349Z",
            "original_url": "https://t.me/test/1",
            "content": "Sample cached telegram message body",
        },
        "panel_log_v2": [
            {
                "id": "uuid:log-1",
                "author_name": "Ryan",
                "created": "2026-11-24T13:19:42.668Z",
                "changes": [{"type": "status_change", "old": "New", "new": "InProgress"}],
            }
        ],
    }
    norm_dw = normalize_playbook_alert(pb_dark_web)
    rendered_dw = _render_to_str(render_playbook_alert_detail(norm_dw, full_detail=pb_dark_web))
    for expected in (
        "General Telegram Mention",
        "Only mentioned incidentally.",
        "Example Bank",
        "Test Channel",
        "Sample cached telegram message body",
        "Status: New -> InProgress",
    ):
        assert expected in rendered_dw
    assert "{'status_change'" not in rendered_dw


def test_tui_playbook_auto_downloads_screenshots_renders_inline_and_opens_modal(
    tmp_path: Path,
) -> None:
    png_1 = _make_test_png(48, 32, color_type=2)
    png_2 = _make_test_png(32, 24, color_type=3)

    mock_client = MagicMock()
    mock_client.search_playbook_alerts.return_value = {
        "data": [
            {
                "playbook_alert_id": "pb-shot-1",
                "category": "domain_abuse",
                "priority": "High",
                "status": "New",
                "title": "lookalike.example",
            },
            {
                "playbook_alert_id": "pb-vuln-404",
                "category": "cyber_vulnerability",
                "priority": "Moderate",
                "status": "InProgress",
                "title": "CVE-2026-9999",
            },
        ],
        "counts": {"returned": 2, "total": 2},
    }
    def _get_pb_alert(
        category: str, alert_id: str, panels: list[str] | None = None
    ) -> dict[str, object]:
        if alert_id == "pb-shot-1":
            return {
                "status": {"status_code": "Ok"},
                "data": {
                    "playbook_alert_id": "pb-shot-1",
                    "panel_status": {
                        "status": "New",
                        "priority": "High",
                        "entity_name": "lookalike.example",
                        "assignee_name": "pb_owner",
                    },
                    "panel_evidence_summary": {
                        "explanation": "Screenshot captured",
                        "screenshots": [
                            {
                                "image_id": "img:shot-1",
                                "availability": "Available",
                                "created": "2026-11-24T15:12:00Z",
                                "tag": "Domain for sale",
                            },
                            {
                                "image_id": "img:shot-2",
                                "availability": "Available",
                                "created": "2026-11-24T15:03:00Z",
                            },
                        ],
                    },
                },
            }
        raise RecordedFutureAPIError(
            404, "Not found", endpoint=f"/playbook-alert/{category}/{alert_id}"
        )

    mock_client.get_playbook_alert.side_effect = _get_pb_alert
    mock_client.get_playbook_alert_preview.return_value = {
        "status": {"status_code": "Ok"},
        "data": {
            "playbook_alert_id": "pb-vuln-404",
            "category": "cyber_vulnerability",
            "status": "InProgress",
            "priority": "Moderate",
            "title": "CVE-2026-9999",
        },
    }
    mock_client.get_playbook_alert_image.side_effect = [png_1, png_2]

    app = create_app(
        client=mock_client,
        dry_run=False,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 44)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-pb-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            images_btn = app.query_one("#rf-images-btn", Button)
            assert images_btn.disabled is True

            await pilot.click("#rf-fetch-detail-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert mock_client.get_playbook_alert_image.call_count == 2
            mock_client.get_playbook_alert_image.assert_any_call(
                "domain_abuse", "pb-shot-1", "img:shot-1"
            )
            mock_client.get_playbook_alert_image.assert_any_call(
                "domain_abuse", "pb-shot-1", "img:shot-2"
            )
            rendered_log = _rich_log_text(app)
            assert "\u2580" in rendered_log
            assert "48x32" in rendered_log
            assert "Domain for sale" in rendered_log
            assert images_btn.disabled is False
            assert "Images (2)" in str(images_btn.label)

            # Open fullscreen ScreenshotViewerModal, cycle Next, Save PNG from cache, and close
            await pilot.click("#rf-images-btn")
            await pilot.pause()
            assert isinstance(app.screen, ScreenshotViewerModal)
            assert "Screenshot 1 of 2" in str(app.screen.query_one("#shot-viewer-header", Static).render())

            await pilot.click("#shot-next-btn")
            await pilot.pause()
            assert "Screenshot 2 of 2" in str(app.screen.query_one("#shot-viewer-header", Static).render())

            await pilot.click("#shot-save-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert not isinstance(app.screen, ScreenshotViewerModal)
            saved_files = list((tmp_path / "screenshots").glob("*.png"))
            assert len(saved_files) == 1
            assert saved_files[0].read_bytes() == png_2
            # Save used cached bytes without a 3rd network download
            assert mock_client.get_playbook_alert_image.call_count == 2

            # Verify HTTP 404 fallback to get_playbook_alert_preview on row 2 (cyber_vulnerability)
            table = app.query_one("#rf-results-table", DataTable)
            table.focus()
            await pilot.press("down", "enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.get_playbook_alert_preview.assert_any_call("pb-vuln-404")
            assert "CVE-2026-9999" in _rich_log_text(app)

    asyncio.run(_run())


def _make_bordered_content_png(width: int = 200, height: int = 150) -> bytes:
    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I4s", len(data), ctype) + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        for x in range(width):
            # Colored 40x30 box at (40..80, 40..70) plus a 1px vertical dark line at x=160
            if 40 <= y < 70 and 40 <= x < 80:
                raw.extend((30, 90, 210))
            elif y == 55 and x == 160 or (40 <= y < 70 and x == 160):
                raw.extend((20, 20, 20))
            else:
                raw.extend((255, 255, 255))
    idat = zlib.compress(bytes(raw))
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def test_image_render_encode_png_and_auto_crop_margins() -> None:
    bordered_png = _make_bordered_content_png(200, 150)
    img = decode_image(bordered_png)
    cropped, crop_box = auto_crop_margins(img)
    assert crop_box is not None
    x0, y0, x1, y1 = crop_box
    # Must contain both the box (x=40) and the 1px vertical line (x=160)
    assert x0 <= 40
    assert x1 >= 161
    assert y0 <= 40
    assert y1 >= 70
    # Must trim more than 50% of the 200x150 white canvas
    assert cropped.width * cropped.height < (200 * 150) * 0.5

    # Round-trip encode_png -> decode_image preserves cropped dimensions & pixels
    re_png = encode_png(cropped)
    round_trip = decode_image(re_png)
    assert round_trip.width == cropped.width
    assert round_trip.height == cropped.height
    assert round_trip.rgb_rows == cropped.rgb_rows
    # Confirm 1px dark line at relative x=(160 - x0), y=(55 - y0) survived intact
    rel_x = 160 - x0
    rel_y = 55 - y0
    line_row = round_trip.rgb_rows[rel_y]
    assert (line_row[rel_x * 3], line_row[rel_x * 3 + 1], line_row[rel_x * 3 + 2]) == (20, 20, 20)

    # Uniform solid image -> unchanged
    solid_png = _make_test_png(64, 48, color_type=2)
    solid_img = decode_image(solid_png)
    same_solid, solid_box = auto_crop_margins(solid_img)
    assert solid_box is None
    assert same_solid is solid_img

    # Full-bleed checkerboard with mixed border pixels -> unchanged
    rows = []
    for y in range(40):
        r = bytearray()
        for x in range(40):
            r.extend((10, 20, 30) if (x + y) % 2 == 0 else (230, 240, 250))
        rows.append(bytes(r))
    checker = DecodedImage(width=40, height=40, color_type=2, bit_depth=8, raw_size=40 * 40 * 3, rgb_rows=rows)
    same_checker, checker_box = auto_crop_margins(checker)
    assert checker_box is None
    assert same_checker is checker


def test_image_render_kitty_tgp_detection_and_protocol() -> None:
    from rich.cells import cell_len as rich_cell_len
    from textual._cells import cell_len as textual_cell_len

    assert detect_terminal_graphics_protocol({"KITTY_WINDOW_ID": "1"}, is_headless=False) == "kitty"
    assert (
        detect_terminal_graphics_protocol({"GHOSTTY_RESOURCES_DIR": "/usr/share/ghostty"}, is_headless=False)
        == "kitty"
    )
    assert detect_terminal_graphics_protocol({"TERM": "xterm-ghostty"}, is_headless=False) == "kitty"
    assert detect_terminal_graphics_protocol({"TERM": "xterm-256color"}, is_headless=False) == "halfblock"
    assert (
        detect_terminal_graphics_protocol({"KITTY_WINDOW_ID": "1", "TMUX": "/tmp/tmux"}, is_headless=False)
        == "halfblock"
    )
    assert detect_terminal_graphics_protocol({"KITTY_WINDOW_ID": "1"}, is_headless=True) == "halfblock"
    assert (
        detect_terminal_graphics_protocol(
            {"TERM": "xterm-256color", "RF_TUI_IMAGE_PROTOCOL": "kitty"},
            is_headless=True,
        )
        == "kitty"
    )
    assert (
        detect_terminal_graphics_protocol(
            {"WT_SESSION": "1"},
            is_headless=False,
            platform_name="win32",
        )
        == "sixel"
    )
    assert (
        detect_terminal_graphics_protocol(
            {"TERM_PROGRAM": "iTerm.app"},
            is_headless=False,
        )
        == "iterm2"
    )
    assert (
        detect_terminal_graphics_protocol(
            {"WEZTERM_PANE": "1"},
            is_headless=False,
            platform_name="win32",
        )
        == "iterm2"
    )
    assert (
        detect_terminal_graphics_protocol(
            {},
            is_headless=False,
            platform_name="win32",
        )
        == "halfblock"
    )

    small_png = _make_test_png(16, 12, color_type=2)
    with pytest.raises(ValueError, match="valid PNG"):
        build_kitty_upload_sequence(b"not-a-png", image_id=0x524601, cols=4, rows=4)

    single_seq = build_kitty_upload_sequence(small_png, image_id=0x524601, cols=10, rows=5)
    assert "a=t,f=100,i=5391873,q=2;" in single_seq
    assert "a=p,U=1,i=5391873,c=10,r=5,q=2;\x1b\\" in single_seq

    # Multi-chunk (> 10 KB binary -> > 13 KB base64)
    noisy_png = b"\x89PNG\r\n\x1a\n" + bytes((i * 37) & 0xFF for i in range(11_000))
    multi_seq = build_kitty_upload_sequence(noisy_png, image_id=0x524602, cols=20, rows=8)
    apcs = [part for part in multi_seq.split("\x1b_G") if part]
    assert len(apcs) >= 4
    assert "a=t,f=100,i=5391874,q=2,m=1;" in apcs[0]
    for mid in apcs[1:-2]:
        assert mid.startswith("m=1,q=2;")
        payload = mid.split(";", 1)[1].split("\x1b\\", 1)[0]
        assert len(payload) == 4096
        assert len(payload) % 4 == 0
    assert apcs[-2].startswith("m=0,q=2;")
    assert "a=p,U=1,i=5391874,c=20,r=8,q=2;\x1b\\" in apcs[-1]

    tmux_seq = build_kitty_upload_sequence(
        small_png, image_id=0x524603, cols=4, rows=3, tmux_passthrough=True
    )
    assert tmux_seq.startswith("\x1bPtmux;\x1b\x1b_G")
    del_seq = build_kitty_delete_sequence(0x524603)
    assert del_seq == "\x1b_Ga=d,d=I,i=5391875,q=2;\x1b\\"

    grid = render_kitty_placeholder_grid(image_id=0x524601, cols=12, rows=6)
    assert grid.no_wrap is True
    assert grid.overflow == "crop"
    lines = grid.split("\n")
    assert len(lines) == 6
    for line in lines:
        assert rich_cell_len(line.plain) == 12
        assert textual_cell_len(line.plain) == 12
        assert line.spans[0].style is not None
        style_obj = line.spans[0].style
        assert style_obj.color is not None
        assert style_obj.color.get_truecolor() == (0x52, 0x46, 0x01)


def test_image_render_open_in_native_viewer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import soclens.tui.image_render as img_mod

    png_bytes = _make_test_png(16, 16, color_type=2)
    monkeypatch.setattr(img_mod.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(img_mod.sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(img_mod.shutil, "which", lambda cmd: "/usr/bin/xdg-open" if cmd == "xdg-open" else None)

    popen_mock = MagicMock()
    monkeypatch.setattr(img_mod.subprocess, "Popen", popen_mock)

    out_path = open_image_in_native_viewer(png_bytes, image_id="img:shot/1")
    assert out_path.is_file()
    assert out_path.read_bytes() == png_bytes
    popen_mock.assert_called_once()
    args, kwargs = popen_mock.call_args
    assert args[0] == ["/usr/bin/xdg-open", str(out_path)]
    assert kwargs.get("shell", False) is False


def test_tui_screenshot_viewer_crop_zoom_mode_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soclens.tui.modals as modals_mod

    bordered_png = _make_bordered_content_png(200, 150)
    opened_calls: list[tuple[bytes, str]] = []

    def _fake_open(raw_bytes: bytes, *, image_id: str) -> Path:
        opened_calls.append((raw_bytes, image_id))
        return tmp_path / f"{image_id}.png"

    monkeypatch.setattr(modals_mod, "open_image_in_native_viewer", _fake_open)

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
    shots = [
        {
            "image_id": "img:border-test",
            "meta": {"created": "2026-11-24T15:12:00Z", "tag": "Phishing"},
            "raw_bytes": bordered_png,
        }
    ]

    async def _run() -> None:
        # 1) Default headless behavior: Halfblock only, blurred by default, no manual mode button
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            modal = ScreenshotViewerModal(title="evil.test", screenshots=shots, dry_run=True)
            app.push_screen(modal)
            await pilot.pause()

            meta_bar = modal.query_one("#shot-viewer-meta", Static)
            blur_btn = modal.query_one("#shot-blur-btn", Button)
            crop_btn = modal.query_one("#shot-crop-btn", Button)
            canvas = modal.query_one("#shot-viewer-canvas", RichLog)

            assert len(modal.query("#shot-mode-btn")) == 0
            assert "Cropped:" in str(meta_bar.render())
            assert "BLURRED" in str(meta_bar.render())
            assert "Blur: ON" in str(blur_btn.label)
            assert "Crop: Auto" in str(crop_btn.label)
            assert "\U0010eeee" not in "".join(strip.text for strip in canvas.lines)

            # Open OS Viewer while blurred sends blurred bytes
            await pilot.click("#shot-open-btn")
            await pilot.pause()
            assert isinstance(app.screen, ScreenshotViewerModal)
            assert len(opened_calls) == 1
            blur_bytes, blur_id = opened_calls[0]
            assert blur_id == "img:border-test_blurred"
            assert blur_bytes.startswith(b"\x89PNG\r\n\x1a\n")
            assert blur_bytes != bordered_png

            # Toggle Blur OFF -> reveals original bytes on Open Viewer
            await pilot.click("#shot-blur-btn")
            await pilot.pause()
            assert "Blur: OFF" in str(blur_btn.label)
            assert "BLURRED" not in str(meta_bar.render())
            await pilot.click("#shot-open-btn")
            await pilot.pause()
            assert opened_calls[1] == (bordered_png, "img:border-test")

            # Toggle Crop -> Full Page -> Auto-crop
            await pilot.click("#shot-crop-btn")
            await pilot.pause()
            assert "Full Page" in str(meta_bar.render())
            assert "Crop: Full" in str(crop_btn.label)

            await pilot.click("#shot-crop-btn")
            await pilot.pause()
            assert "Cropped:" in str(meta_bar.render())

            # Zoom in and out
            await pilot.click("#shot-zoom-in-btn")
            await pilot.pause()
            assert "Zoom: 1.5x" in str(meta_bar.render())

            await pilot.click("#shot-zoom-out-btn")
            await pilot.pause()
            assert "Zoom:" not in str(meta_bar.render())

        # 2) Kitty-capable terminal auto-renders Kitty HD + starts blurred
        monkeypatch.setattr(modals_mod, "detect_terminal_graphics_protocol", lambda *a, **k: "kitty")
        monkeypatch.setattr(modals_mod, "write_terminal_graphics", lambda *a, **k: True)
        app2 = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
        app2.console._color_system = ColorSystem.TRUECOLOR
        async with app2.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            modal = ScreenshotViewerModal(title="evil.test", screenshots=shots, dry_run=True)
            app2.push_screen(modal)
            await pilot.pause()

            meta_bar = modal.query_one("#shot-viewer-meta", Static)
            blur_btn = modal.query_one("#shot-blur-btn", Button)
            canvas = modal.query_one("#shot-viewer-canvas", RichLog)

            assert len(modal.query("#shot-mode-btn")) == 0
            assert "Mode: Kitty HD" in str(meta_bar.render())
            assert "BLURRED" in str(meta_bar.render())
            assert "Blur: ON" in str(blur_btn.label)
            assert "\U0010eeee" in "".join(strip.text for strip in canvas.lines)

            await pilot.press("b")
            await pilot.pause()
            assert "Blur: OFF" in str(blur_btn.label)
            assert "BLURRED" not in str(meta_bar.render())
            assert "Mode: Kitty HD" in str(meta_bar.render())
            assert "\U0010eeee" in "".join(strip.text for strip in canvas.lines)

    asyncio.run(_run())


def _datatable_header_click_offset(table: DataTable[object], col_key: str) -> tuple[int, int]:
    """Return local (x, y) offset inside ``table`` targeting the column header cell."""
    x_pos = 1  # account for 1-cell solid border on left edge
    for col in table.ordered_columns:
        key = col.key.value if col.key.value is not None else str(col.key)
        width = col.get_render_width(table)
        if key == col_key:
            return (x_pos + max(1, width // 2), 1)
        x_pos += width
    raise AssertionError(f"Column '{col_key}' not found in DataTable")


def test_tui_watchlists_sort_entities_and_lists(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:wl-3", "type": "ip", "name": "Gamma IPs"},
        {"id": "report:wl-1", "type": "brand", "name": "Alpha Brand"},
        {"id": "report:wl-2", "type": "domain", "name": "Beta Domains"},
    ]
    mock_client.get_watchlist_entities.return_value = [
        {
            "entity": {"id": "idn:zeta.com", "type": "InternetDomainName", "name": "zeta.com"},
            "status": "ready",
            "context": {"annotation": "Zeta domain"},
        },
        {
            "entity": {"id": "idn:irisbank.com", "type": "InternetDomainName", "name": "irisbank.com"},
            "status": "added",
            "context": {"annotation": ""},
        },
        {
            "entity": {"id": "hash:1111", "type": "Hash", "name": "alpha-logo"},
            "status": "ready",
            "context": {"annotation": "Alpha logo"},
        },
        {
            "entity": {"id": "ip:198.51.100.5", "type": "IpAddress", "name": "198.51.100.5"},
            "status": "pending",
            "context": None,
        },
    ]

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-watchlists",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            lists_table = app.query_one("#wl-lists-table", DataTable)
            ent_table = app.query_one("#wl-entities-table", DataTable)

            # Initial watchlist order matches API response (columns: Name, Type)
            assert [str(lists_table.get_row_at(i)[0]) for i in range(3)] == [
                "Gamma IPs",
                "Alpha Brand",
                "Beta Domains",
            ]

            # Click Name header on Watchlists table -> ascending, then descending
            await pilot.click(
                "#wl-lists-table",
                offset=_datatable_header_click_offset(lists_table, "name"),
            )
            await pilot.pause()
            assert [str(lists_table.get_row_at(i)[0]) for i in range(3)] == [
                "Alpha Brand",
                "Beta Domains",
                "Gamma IPs",
            ]
            assert "Name ^" in str(lists_table.columns[lists_table.ordered_columns[0].key].label)

            await pilot.click(
                "#wl-lists-table",
                offset=_datatable_header_click_offset(lists_table, "name"),
            )
            await pilot.pause()
            assert [str(lists_table.get_row_at(i)[0]) for i in range(3)] == [
                "Gamma IPs",
                "Beta Domains",
                "Alpha Brand",
            ]
            assert "Name v" in str(lists_table.columns[lists_table.ordered_columns[0].key].label)

            # Click Type header on Watchlists table -> ascending
            await pilot.click(
                "#wl-lists-table",
                offset=_datatable_header_click_offset(lists_table, "type"),
            )
            await pilot.pause()
            assert [str(lists_table.get_row_at(i)[1]) for i in range(3)] == ["brand", "domain", "ip"]

            # Click row 1 ("Beta Domains", report:wl-2) to expand entities in default API order
            await pilot.click("#wl-lists-table", offset=(4, 3))
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(4)] == [
                "zeta.com",
                "irisbank.com",
                "alpha-logo",
                "198.51.100.5",
            ]

            # Click Name header on Entities table -> ascending, then click again -> descending
            await pilot.click(
                "#wl-entities-table",
                offset=_datatable_header_click_offset(ent_table, "name"),
            )
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(4)] == [
                "198.51.100.5",
                "alpha-logo",
                "irisbank.com",
                "zeta.com",
            ]
            assert "Sorted entities by Name (ascending)" in str(
                app.query_one("#wl-status", Static).render()
            )
            assert str(app.query_one("#wl-entity-sort-select", Select).value) == "name"
            assert "Sort: Name" in str(app.query_one("#wl-sort-cycle-btn", Button).label)
            assert "Asc ^" in str(app.query_one("#wl-sort-dir-btn", Button).label)

            await pilot.click(
                "#wl-entities-table",
                offset=_datatable_header_click_offset(ent_table, "name"),
            )
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(4)] == [
                "zeta.com",
                "irisbank.com",
                "alpha-logo",
                "198.51.100.5",
            ]
            assert "Desc v" in str(app.query_one("#wl-sort-dir-btn", Button).label)

            # Toggle direction via toolbar button
            await pilot.click("#wl-sort-dir-btn")
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(4)] == [
                "198.51.100.5",
                "alpha-logo",
                "irisbank.com",
                "zeta.com",
            ]

            # Click Annotation header -> ascending (non-empty first, empty last)
            await pilot.click(
                "#wl-entities-table",
                offset=_datatable_header_click_offset(ent_table, "annotation"),
            )
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(4)] == [
                "alpha-logo",
                "zeta.com",
                "198.51.100.5",
                "irisbank.com",
            ]

            # Click Type and Status headers
            await pilot.click(
                "#wl-entities-table",
                offset=_datatable_header_click_offset(ent_table, "type"),
            )
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[1]) for i in range(4)] == [
                "Hash",
                "InternetDomainName",
                "InternetDomainName",
                "IpAddress",
            ]

            await pilot.click(
                "#wl-entities-table",
                offset=_datatable_header_click_offset(ent_table, "status"),
            )
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[2]) for i in range(4)] == [
                "added",
                "pending",
                "ready",
                "ready",
            ]

            # Change Select dropdown -> syncs table & toolbar buttons
            app.query_one("#wl-entity-sort-select", Select).value = "name"
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(4)] == [
                "198.51.100.5",
                "alpha-logo",
                "irisbank.com",
                "zeta.com",
            ]

            # Press F6 to advance cycle (name -> id) and verify Entity ID order, then click Sort Cycle button (id -> type)
            await pilot.press("f6")
            await pilot.pause()
            assert str(app.query_one("#wl-entity-sort-select", Select).value) == "id"
            assert [str(ent_table.get_row_at(i)[0]) for i in range(4)] == [
                "alpha-logo",
                "irisbank.com",
                "zeta.com",
                "198.51.100.5",
            ]
            await pilot.click("#wl-sort-cycle-btn")
            await pilot.pause()
            assert str(app.query_one("#wl-entity-sort-select", Select).value) == "type"

            # Right-click context menu sort options + reset
            await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "sort_name")
            await pilot.press("enter")
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(4)] == [
                "198.51.100.5",
                "alpha-logo",
                "irisbank.com",
                "zeta.com",
            ]

            await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
            await pilot.pause()
            _select_context_option_by_id(app, "toggle_sort_dir")
            await pilot.press("enter")
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(4)] == [
                "zeta.com",
                "irisbank.com",
                "alpha-logo",
                "198.51.100.5",
            ]

            # Sorting works together with active entity filtering
            app.query_one("#wl-entity-search-input", Input).value = "InternetDomainName"
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(2)] == [
                "zeta.com",
                "irisbank.com",
            ]

            # Reset sort via context menu restores original API order
            await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
            await pilot.pause()
            _select_context_option_by_id(app, "reset_sort")
            await pilot.press("enter")
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(2)] == [
                "zeta.com",
                "irisbank.com",
            ]
            app.query_one("#wl-entity-search-input", Input).value = ""
            await pilot.pause()
            assert [str(ent_table.get_row_at(i)[0]) for i in range(4)] == [
                "zeta.com",
                "irisbank.com",
                "alpha-logo",
                "198.51.100.5",
            ]

    asyncio.run(_run())


def test_tui_watchlists_type_to_filter_entities_and_lists(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:wl-1", "type": "brand", "name": "Alpha Brand"},
        {"id": "report:wl-2", "type": "domain", "name": "Bank Domains"},
        {"id": "report:wl-3", "type": "ip", "name": "Gamma IPs"},
    ]
    mock_client.get_watchlist_entities.return_value = [
        {
            "entity": {"id": "idn:acmecorp.example", "type": "InternetDomainName", "name": "acmecorp.example"},
            "status": "ready",
            "context": {"annotation": "primary"},
        },
        {
            "entity": {"id": "idn:irisbank.com", "type": "InternetDomainName", "name": "irisbank.com"},
            "status": "ready",
            "context": {"annotation": "member bank"},
        },
        {
            "entity": {
                "id": "idn:ridgebank.com",
                "type": "InternetDomainName",
                "name": "ridgebank.com",
            },
            "status": "ready",
            "context": {"annotation": "member bank"},
        },
        {
            "entity": {"id": "idn:metrobank.com", "type": "InternetDomainName", "name": "metrobank.com"},
            "status": "ready",
            "context": {"annotation": "member bank"},
        },
        {
            "entity": {
                "id": "idn:quartzbank.com",
                "type": "InternetDomainName",
                "name": "quartzbank.com",
            },
            "status": "ready",
            "context": {"annotation": "member bank"},
        },
        {
            "entity": {"id": "idn:1stexample.com", "type": "InternetDomainName", "name": "1stexample.com"},
            "status": "ready",
            "context": {"annotation": "member bank"},
        },
    ]

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-watchlists",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            collapsible = app.query_one("#wl-filter-collapsible", Collapsible)
            lists_table = app.query_one("#wl-lists-table", DataTable)
            ent_table = app.query_one("#wl-entities-table", DataTable)
            wl_search = app.query_one("#wl-search-input", Input)
            ent_search = app.query_one("#wl-entity-search-input", Input)

            assert collapsible.collapsed is True
            assert lists_table.row_count == 3

            # Before entities are loaded, typing filters the watchlists table directly
            await pilot.press("b", "a", "n", "k")
            await pilot.pause()
            assert collapsible.collapsed is False
            assert app.focused is wl_search
            assert wl_search.value == "bank"
            assert lists_table.row_count == 1
            assert "Bank Domains" in [str(c) for c in lists_table.get_row_at(0)]

            # Escape collapses drawer, second Escape clears watchlist filter
            await pilot.press("escape")
            await pilot.pause()
            assert collapsible.collapsed is True
            assert lists_table.row_count == 1
            await pilot.press("escape")
            await pilot.pause()
            assert wl_search.value == ""
            assert lists_table.row_count == 3

            # Number tab switch still works when not focused on entities table
            await pilot.press("1")
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-dashboard"
            await pilot.press("2")
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-watchlists"

            # Click "Bank Domains" (row 1) -> expands entities view and focuses entities table
            await pilot.click("#wl-lists-table", offset=(4, 3))
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert ent_table.row_count == 6
            assert not app.query_one("#wl-entities-pane", Vertical).has_class("wl-hidden")

            # Start typing "irisbank.com" directly while entities are expanded (even with 'm' at the end)
            await pilot.press("i", "r", "i", "s", "b", "a", "n", "k", ".", "c", "o", "m")
            await pilot.pause()
            assert not isinstance(app.screen, ContextMenuModal)
            assert collapsible.collapsed is False
            assert app.focused is ent_search
            assert ent_search.value == "irisbank.com"
            assert ent_table.row_count == 1
            assert str(ent_table.get_row_at(0)[0]) == "irisbank.com"

            # Down or Enter moves focus into entities table; Escape collapses drawer keeping filter
            await pilot.press("down")
            await pilot.pause()
            assert app.focused is ent_table
            await pilot.press("escape")
            await pilot.pause()
            assert collapsible.collapsed is True
            assert ent_table.row_count == 1

            # Second Escape clears entity filter and restores all 6 entities
            await pilot.press("escape")
            await pilot.pause()
            assert ent_search.value == ""
            assert ent_table.row_count == 6

            # When focused on entities table, typing reserved letters (q, r, m, 1) filters entities
            # instead of quitting, reloading, opening menu, or switching tabs
            ent_table.focus()
            await pilot.pause()
            for seq, expected_domain in (
                (("q", "u", "a", "r", "t", "z"), "quartzbank.com"),
                (("r", "i", "d", "g", "e"), "ridgebank.com"),
                (("m", "e", "t", "r", "o"), "metrobank.com"),
                (("1", "s", "t"), "1stexample.com"),
            ):
                await pilot.press(*seq)
                await pilot.pause()
                assert app.is_running
                assert app.query_one("#main-tabs", TabbedContent).active == "tab-watchlists"
                assert not isinstance(app.screen, ContextMenuModal)
                assert ent_table.row_count == 1
                assert str(ent_table.get_row_at(0)[0]) == expected_domain
                await pilot.press("escape")
                await pilot.pause()
                await pilot.press("escape")
                await pilot.pause()
                assert ent_table.row_count == 6
                assert app.focused is ent_table

            # Test Enter from search box focuses entities table, and Backspace from entities table trims filter
            await pilot.press("i", "r", "i")
            await pilot.pause()
            assert ent_search.value == "iri"
            await pilot.press("enter")
            await pilot.pause()
            assert app.focused is ent_table
            await pilot.press("escape")  # collapse drawer
            await pilot.pause()
            assert collapsible.collapsed is True
            assert app.focused is ent_table

            await pilot.press("backspace")
            await pilot.pause()
            assert collapsible.collapsed is False
            assert app.focused is ent_search
            assert ent_search.value == "ir"

            # Typing inside another Input (e.g., #wl-ent-value) must NOT be intercepted
            ent_val_in = app.query_one("#wl-ent-value", Input)
            ent_val_in.focus()
            await pilot.pause()
            await pilot.press("e", "v", "i", "l")
            await pilot.pause()
            assert ent_val_in.value == "evil"
            assert ent_search.value == "ir"

    asyncio.run(_run())


def test_tui_sigma_custom_indexes_table_fields_and_preview(tmp_path: Path) -> None:
    cache_path = tmp_path / "sigma_rules_cache.json"
    cache_path.write_text(
        json.dumps(
            [
                {
                    "rule_id": "doc:sigma-win",
                    "title": "Security Whoami",
                    "file_name": "sec_whoami.yml",
                    "level": "high",
                    "product": "windows",
                    "service": "security",
                    "category": None,
                    "index": "*wineventlog",
                    "mitre_techniques": ["T1033"],
                    "content": (
                        "title: Security Whoami\n"
                        "level: high\n"
                        "logsource:\n"
                        "  product: windows\n"
                        "  service: security\n"
                        "detection:\n"
                        "  selection:\n"
                        "    EventID: 4688\n"
                        "    CommandLine|contains: whoami\n"
                        "  condition: selection\n"
                        "tags:\n"
                        "  - attack.t1033\n"
                    ),
                },
                {
                    "rule_id": "doc:sigma-aws",
                    "title": "AWS Login",
                    "file_name": "aws_login.yml",
                    "level": "medium",
                    "product": "aws",
                    "service": "cloudtrail",
                    "category": None,
                    "index": "*aws",
                    "mitre_techniques": [],
                    "content": (
                        "title: AWS Login\n"
                        "level: medium\n"
                        "logsource:\n"
                        "  product: aws\n"
                        "  service: cloudtrail\n"
                        "detection:\n"
                        "  selection:\n"
                        "    eventName: ConsoleLogin\n"
                        "  condition: selection\n"
                    ),
                },
            ]
        ),
        encoding="utf-8",
    )

    mock_client = MagicMock()
    mock_client.api_token = "tok"
    app = create_app(
        client=mock_client,
        dry_run=False,
        initial_tab="tab-sigma",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause()

            await pilot.click("#sigma-load-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            sigma_table = app.query_one("#sigma-table", DataTable)
            assert sigma_table.row_count == 2
            assert str(sigma_table.get_row_at(0)[2]) == "*wineventlog"
            assert str(sigma_table.get_row_at(1)[2]) == "*aws"

            # Expand custom export panel and configure custom index map, table fields, suppress fields & field map
            col = app.query_one("#sigma-export-collapsible", Collapsible)
            col.collapsed = False
            await pilot.pause()

            app.query_one("#sigma-index-map", Input).value = "windows:security=win_sec,aws=cloud_aws"
            app.query_one("#sigma-custom-table-fields", Input).value = "tenant_id,env"
            app.query_one("#sigma-custom-suppress-fields", Input).value = "tenant_id"
            app.query_one("#sigma-field-map", Input).value = "CommandLine=proc_cmd"
            app.query_one("#sigma-export-path", Input).value = "custom_rules.conf"
            app.query_one("#sigma-pipeline-select", Select).value = "splunk_windows"

            # Submitting index map updates resolved Index column in #sigma-table
            app.query_one("#sigma-index-map", Input).focus()
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            assert str(sigma_table.get_row_at(0)[2]) == "win_sec"
            assert str(sigma_table.get_row_at(1)[2]) == "cloud_aws"

            # Preview first rule via button -> generates proper Splunk stanza in #sigma-log
            await pilot.click("#sigma-preview-btn")
            await pilot.pause()
            log_text = _rich_log_text(app, selector="#sigma-log")
            assert "index=win_sec" in log_text
            assert "EventCode=4688" in log_text
            assert 'proc_cmd="*whoami*"' in log_text
            assert "tenant_id env" in log_text
            assert "alert.suppress.fields = tenant_id,host,User" in log_text

            # Preview second rule via right-click context menu
            await pilot.click("#sigma-table", offset=(4, 3), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "preview_splunk")
            await pilot.press("enter")
            await pilot.pause()
            log_text_after = _rich_log_text(app, selector="#sigma-log")
            assert "index=cloud_aws" in log_text_after
            assert 'eventName="ConsoleLogin"' in log_text_after

            # Export to Splunk creates split files with custom indexes and custom table fields
            await pilot.click("#sigma-export-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            win_conf = tmp_path / "custom_rules_win_sec.conf"
            aws_conf = tmp_path / "custom_rules_cloud_aws.conf"
            assert win_conf.is_file()
            assert aws_conf.is_file()

            cp_win = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
            cp_win.read_string(win_conf.read_text(encoding="utf-8"))
            sec_win = cp_win[cp_win.sections()[0]]
            assert "index=win_sec" in sec_win["search"]
            assert "EventCode=4688" in sec_win["search"]
            assert 'proc_cmd="*whoami*"' in sec_win["search"]
            assert "| table " in sec_win["search"]
            assert sec_win["search"].endswith("tenant_id env")
            assert sec_win["alert.suppress.fields"] == "tenant_id,host,User"

            cp_aws = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
            cp_aws.read_string(aws_conf.read_text(encoding="utf-8"))
            sec_aws = cp_aws[cp_aws.sections()[0]]
            assert "index=cloud_aws" in sec_aws["search"]
            assert sec_aws["search"].endswith("tenant_id env")
            assert sec_aws["alert.suppress.fields"] == "tenant_id,userIdentity.arn,eventName"

    asyncio.run(_run())


def test_tui_dashboard_insecure_ssl_toggle_and_proxy_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for key in ("RF_VERIFY_SSL", "RF_INSECURE_SSL", "SOCLENS_INSECURE_SSL", "RF_CA_BUNDLE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://user:topsecret@proxy.corp.local:8080")

    client = RecordedFutureClient(api_token="tok", error_log_dir=tmp_path / "logs")
    assert client.verify_ssl is True
    app = create_app(
        client=client, dry_run=False, workspace_dir=tmp_path, view_mode="admin"
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            summary_widget = app.query_one("#dash-env-summary", Static)
            ssl_btn = app.query_one("#dash-ssl-btn", Button)

            summary_text = str(summary_widget.render())
            assert "RF/Web SSL Verify: Enabled (Verified)" in summary_text
            assert "HTTPS=http://***@proxy.corp.local:8080" in summary_text
            assert "topsecret" not in summary_text
            assert str(ssl_btn.label) == "Insecure SSL: OFF"
            assert "INSECURE SSL" not in app.sub_title

            # Toggle insecure SSL ON via Dashboard button
            await pilot.click("#dash-ssl-btn")
            await pilot.pause()
            assert client.verify_ssl is False
            assert client.session.verify is False
            assert app.get_effective_verify_ssl() is False
            assert str(ssl_btn.label) == "Insecure SSL: ON"
            assert "INSECURE SSL (Proxy Mode)" in app.sub_title
            assert "INSECURE (Disabled - Proxy Mode)" in str(summary_widget.render())

            # Toggle insecure SSL back OFF (wait past Textual's 0.2s button active cooldown)
            await pilot.pause()
            await pilot.click("#dash-ssl-btn")
            await pilot.pause()
            assert client.verify_ssl is True
            assert client.session.verify is True
            assert app.get_effective_verify_ssl() is True
            assert str(ssl_btn.label) == "Insecure SSL: OFF"
            assert "INSECURE SSL" not in app.sub_title

    asyncio.run(_run())

    # Launching with insecure client starts TUI immediately in Insecure Proxy Mode
    insecure_client = RecordedFutureClient(
        api_token="tok",
        verify_ssl=False,
        error_log_dir=tmp_path / "logs",
    )
    insecure_app = create_app(
        client=insecure_client,
        dry_run=True,
        workspace_dir=tmp_path,
        view_mode="admin",
    )

    async def _run_initial_insecure() -> None:
        async with insecure_app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            ssl_btn = insecure_app.query_one("#dash-ssl-btn", Button)
            assert str(ssl_btn.label) == "Insecure SSL: ON"
            assert "Admin View" in insecure_app.sub_title
            assert "DRY-RUN MODE (Read-Only) | INSECURE SSL (Proxy Mode)" in insecure_app.sub_title

    asyncio.run(_run_initial_insecure())


def test_tui_remove_company_entity_uses_rf_id_across_all_paths(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.get_watchlists.return_value = [
        {"id": "report:fOqHJL", "type": "company", "name": "Monitored Companies"}
    ]
    mock_client.get_watchlist_entities.return_value = [
        {
            "entity": {
                "id": "iuiKOZ",
                "type": "Company",
                "name": "Colonial Federal Savings Bank",
            },
            "status": "ready",
            "context": {"annotation": "1015"},
        },
        {
            "entity": {
                "id": "cmp:dup1",
                "type": "Company",
                "name": "Duplicate Bank",
            },
            "status": "ready",
            "context": {"annotation": "dup-a"},
        },
        {
            "entity": {
                "id": "cmp:dup2",
                "type": "Company",
                "name": "Duplicate Bank",
            },
            "status": "ready",
            "context": {"annotation": "dup-b"},
        },
    ]
    mock_client.remove_entity.return_value = {"result": "removed"}

    app = create_app(
        client=mock_client,
        dry_run=False,
        initial_tab="tab-watchlists",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            # Load entities for report:fOqHJL
            await pilot.click("#wl-lists-table", offset=(4, 2), times=2)
            await app.workers.wait_for_complete()
            await pilot.pause()

            # 1. Right-click Company row -> modal displays name & ID, approve calls remove_entity(..., "iuiKOZ", is_id=True)
            await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "remove_entity")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            body_txt = " ".join(str(s.render()) for s in app.screen.query(Static))
            assert "Colonial Federal Savings Bank" in body_txt
            assert "iuiKOZ" in body_txt
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.remove_entity.assert_called_with("report:fOqHJL", "iuiKOZ", is_id=True)

            # 2. Double-click Company row -> populates #wl-ent-type & #wl-ent-value, clicking #wl-remove-btn uses ID
            mock_client.remove_entity.reset_mock()
            await pilot.click("#wl-entities-table", offset=(4, 2), times=2)
            await pilot.pause()
            assert app.query_one("#wl-ent-type", Input).value == "Company"
            assert app.query_one("#wl-ent-value", Input).value == "Colonial Federal Savings Bank"
            await pilot.click("#wl-remove-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.remove_entity.assert_called_with("report:fOqHJL", "iuiKOZ", is_id=True)

            # 3. Typing opaque ID or exact name while #wl-ent-type has stale default "InternetDomainName"
            for manual_val in ("iuiKOZ", "Colonial Federal Savings Bank"):
                mock_client.remove_entity.reset_mock()
                app.query_one("#wl-ent-type", Input).value = "InternetDomainName"
                app.query_one("#wl-ent-value", Input).value = manual_val
                await pilot.click("#wl-remove-btn")
                await pilot.pause()
                assert isinstance(app.screen, ConfirmActionModal)
                await pilot.click("#confirm-approve-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                mock_client.remove_entity.assert_called_with("report:fOqHJL", "iuiKOZ", is_id=True)

            # 4. Filter by annotation "1015" and right-click filtered row -> removes "iuiKOZ" with is_id=True
            mock_client.remove_entity.reset_mock()
            app.query_one("#wl-entity-search-input", Input).value = "1015"
            await pilot.pause()
            assert app.query_one("#wl-entities-table", DataTable).row_count == 1
            await pilot.click("#wl-entities-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "remove_entity")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_client.remove_entity.assert_called_with("report:fOqHJL", "iuiKOZ", is_id=True)

            # 5. Ambiguous duplicate names typed into form -> refused with status message, no remove_entity call
            mock_client.remove_entity.reset_mock()
            app.query_one("#wl-entity-search-input", Input).value = ""
            app.query_one("#wl-ent-type", Input).value = "Company"
            app.query_one("#wl-ent-value", Input).value = "Duplicate Bank"
            await pilot.click("#wl-remove-btn")
            await pilot.pause()
            assert not isinstance(app.screen, ConfirmActionModal)
            mock_client.remove_entity.assert_not_called()
            status_txt = str(app.query_one("#wl-status", Static).render())
            assert "Multiple loaded entities match" in status_txt

    asyncio.run(_run())

