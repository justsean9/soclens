"""Unit and Pilot tests for User (default) vs Admin UI view modes and toggles."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from textual.containers import Horizontal
from textual.widgets import (
    Button,
    Input,
    OptionList,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from soclens.cli import build_parser, main, run_unified_tui
from soclens.config import UI_VIEW_ADMIN, UI_VIEW_USER, ConfigurationError
from soclens.tui import (
    ADMIN_ONLY_TABS,
    ALL_TABS,
    USER_VIEW_TABS,
    ContextMenuModal,
    create_app,
)
from soclens.tui.screens.research import ResearchPane
from soclens.tui.screens.rf_intel import RFIntelPane


def _select_context_option_by_id(app: object, option_id: str) -> None:
    opts = app.screen.query_one("#ctx-menu-options", OptionList)  # type: ignore[attr-defined]
    opts.highlighted = opts.get_option_index(option_id)


def test_tui_default_user_view_hides_admin_tabs_and_blocks_admin_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SOCLENS_UI_VIEW", raising=False)
    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
    assert app.view_mode == UI_VIEW_USER
    assert app.is_admin_view is False
    assert app.visible_tab_ids == USER_VIEW_TABS
    assert "User View" in app.sub_title

    async def _run() -> None:
        async with app.run_test(size=(130, 38)) as pilot:
            await pilot.pause()
            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-research"

            for tid in USER_VIEW_TABS:
                tab_btn = tabs.get_tab(tid)
                assert not tab_btn.has_class("-hidden"), f"{tid} should be visible in User view"
            for tid in ADMIN_ONLY_TABS:
                tab_btn = tabs.get_tab(tid)
                assert tab_btn.has_class("-hidden"), f"{tid} should be hidden in User view"

            assert str(app.query_one("#view-mode-select", Select).value) == UI_VIEW_USER
            assert "OFF" in str(app.query_one("#view-mode-toggle-btn", Button).label)
            assert "User" in str(app.query_one("#view-mode-label", Static).render())

            # Allowed user keys switch among all 8 User View tabs
            for key, expected_tab in (
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
                assert tabs.active == expected_tab

            # Admin-only keys are disabled in User view
            for blocked_key in ("1", "2", "3", "5", "6"):
                await pilot.press(blocked_key)
                await pilot.pause()
                assert tabs.active == "tab-research"

    asyncio.run(_run())


def test_tui_admin_toggle_button_select_and_f2_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SOCLENS_UI_VIEW", raising=False)
    mock_client = MagicMock()
    mock_client.api_token = ""
    app = create_app(client=mock_client, dry_run=True, workspace_dir=tmp_path)

    async def _run() -> None:
        async with app.run_test(size=(130, 38)) as pilot:
            await pilot.pause()
            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-research"

            # Switch to RF Intel so _last_user_tab becomes tab-rf-intel
            await pilot.press("4")
            await pilot.pause()
            assert tabs.active == "tab-rf-intel"

            # Click Admin toggle button -> enables Admin view and shows all 8 tabs
            await pilot.click("#view-mode-toggle-btn")
            await pilot.pause()
            assert app.view_mode == UI_VIEW_ADMIN
            assert app.is_admin_view is True
            assert "Admin View" in app.sub_title
            assert "ON" in str(app.query_one("#view-mode-toggle-btn", Button).label)
            assert str(app.query_one("#view-mode-select", Select).value) == UI_VIEW_ADMIN
            for tid in ALL_TABS:
                assert not tabs.get_tab(tid).has_class("-hidden")

            # Navigate to Admin-only Brand Logos tab ('3') and Dashboard ('1')
            await pilot.press("3")
            await pilot.pause()
            assert tabs.active == "tab-brand-logos"
            await pilot.press("1")
            await pilot.pause()
            assert tabs.active == "tab-dashboard"

            # Press F2 while standing on Admin-only tab -> switches back to _last_user_tab
            await pilot.press("f2")
            await pilot.pause()
            assert app.view_mode == UI_VIEW_USER
            assert tabs.active == "tab-rf-intel"
            for tid in ADMIN_ONLY_TABS:
                assert tabs.get_tab(tid).has_class("-hidden")

            # Change Select directly to Admin and back to User
            view_select = app.query_one("#view-mode-select", Select)
            view_select.value = UI_VIEW_ADMIN
            await pilot.pause()
            assert app.is_admin_view is True
            await pilot.press("5")
            await pilot.pause()
            assert tabs.active == "tab-sigma"

            view_select.value = UI_VIEW_USER
            await pilot.pause()
            assert app.is_admin_view is False
            assert tabs.active == "tab-rf-intel"

    asyncio.run(_run())


def test_tui_user_vs_admin_context_menus_hide_watchlist_pivots(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.search_alerts_v3.return_value = {
        "data": [
            {
                "id": "al-view-1",
                "title": "Suspicious Domain Hit",
                "type": "ENTITY_MATCH",
                "review": {"priority": "High", "status_in_portal": "New"},
                "rule": {"id": "r1", "name": "Domain Rule"},
                "log": {"triggered": "2026-11-24T10:00:00Z"},
                "hits": [
                    {
                        "id": "h1",
                        "entities": [
                            {
                                "id": "idn:bad.example",
                                "name": "bad.example",
                                "type": "InternetDomainName",
                            }
                        ],
                        "fragment": "Suspicious domain observed",
                    }
                ],
            }
        ]
    }
    app = create_app(client=mock_client, dry_run=True, workspace_dir=tmp_path)

    async def _run() -> None:
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()

            # Research tab (default User view): no Send Entity to Watchlists option
            res_pane = app.query_one(ResearchPane)
            res_table = res_pane.query_one("#res-table")
            res_table.focus()
            await pilot.click("#res-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            res_opts = app.screen.query_one("#ctx-menu-options", OptionList)
            res_ids = [
                str(res_opts.get_option_at_index(i).id)
                for i in range(res_opts.option_count)
            ]
            assert "send_watchlist" not in res_ids
            assert "send_rf_intel" in res_ids
            await pilot.press("escape")
            await pilot.pause()

            # RF Intel tab (User view): no Send to Watchlists option
            await pilot.press("4")
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            rf_pane = app.query_one(RFIntelPane)
            rf_pane.query_one("#rf-results-table").focus()
            await pilot.click("#rf-results-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            rf_opts = app.screen.query_one("#ctx-menu-options", OptionList)
            rf_ids = [
                str(rf_opts.get_option_at_index(i).id)
                for i in range(rf_opts.option_count)
            ]
            assert "send_watchlist" not in rf_ids
            assert "deep_research" in rf_ids
            await pilot.press("escape")
            await pilot.pause()

            # Enable Admin view -> Send to Watchlists reappears
            await pilot.press("f2")
            await pilot.pause()
            await pilot.click("#rf-results-table", offset=(4, 2), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            rf_admin_opts = app.screen.query_one("#ctx-menu-options", OptionList)
            rf_admin_ids = [
                str(rf_admin_opts.get_option_at_index(i).id)
                for i in range(rf_admin_opts.option_count)
            ]
            assert "send_watchlist" in rf_admin_ids
            _select_context_option_by_id(app, "send_watchlist")
            await pilot.press("enter")
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-watchlists"
            assert app.query_one("#wl-ent-value", Input).value == "bad.example"

    asyncio.run(_run())


def test_tui_view_mode_initial_tab_and_env_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SOCLENS_UI_VIEW", raising=False)
    app_auto = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-watchlists",
        workspace_dir=tmp_path,
    )
    assert app_auto.view_mode == UI_VIEW_ADMIN
    assert app_auto.initial_tab == "tab-watchlists"

    app_forced_user = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-watchlists",
        view_mode="user",
        workspace_dir=tmp_path,
    )
    assert app_forced_user.view_mode == UI_VIEW_USER
    assert app_forced_user.initial_tab == "tab-research"

    monkeypatch.setenv("SOCLENS_UI_VIEW", "admin")
    app_env = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
    assert app_env.view_mode == UI_VIEW_ADMIN
    assert app_env.initial_tab == "tab-dashboard"

    with pytest.raises(ConfigurationError):
        create_app(client=MagicMock(), dry_run=True, view_mode="invalid", workspace_dir=tmp_path)


def test_cli_view_mode_flags_and_forwarding() -> None:
    parser = build_parser()
    args_admin = parser.parse_args(["tui", "--admin"])
    assert args_admin.command == "tui"
    assert args_admin.admin is True

    args_view = parser.parse_args(["--view", "admin", "--tui"])
    assert args_view.tui is True
    assert args_view.view == "admin"

    with patch("soclens.cli.RecordedFutureClient") as mock_client_cls:
        with patch("soclens.tui.create_app") as mock_create_app:
            run_unified_tui(mock_client_cls.return_value, dry_run=True, view_mode="admin")
            mock_create_app.assert_called_once_with(
                client=mock_client_cls.return_value,
                dry_run=True,
                initial_tab=None,
                workspace_dir=None,
                view_mode="admin",
            )

    with patch("soclens.cli.run_unified_tui") as mock_tui:
        with patch("soclens.cli.RecordedFutureClient") as mock_client_cls:
            with patch("sys.argv", ["soclens", "tui", "--admin", "--dry-run"]):
                main()
            mock_tui.assert_called_once_with(
                mock_client_cls.return_value, dry_run=True, view_mode="admin"
            )

    with patch("soclens.cli.run_unified_tui") as mock_tui:
        with patch("soclens.cli.RecordedFutureClient") as mock_client_cls:
            with patch("sys.argv", ["soclens", "--view", "user", "--tui"]):
                main()
            mock_tui.assert_called_once_with(
                mock_client_cls.return_value, dry_run=False, view_mode="user"
            )


def test_tui_view_mode_bar_layout_bounds_user_and_admin(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        view_mode=UI_VIEW_USER,
        workspace_dir=tmp_path,
    )

    async def _check() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            for mode in (UI_VIEW_USER, UI_VIEW_ADMIN):
                app.set_view_mode(mode)
                for w, h in ((80, 24), (120, 36), (180, 52)):
                    await pilot.resize_terminal(w, h)
                    await pilot.pause()
                    bar = app.query_one("#view-mode-bar", Horizontal)
                    assert bar.region.height == 1
                    assert bar.region.right <= w
                    for wid, wtype in (
                        ("#view-mode-label", Static),
                        ("#view-mode-select", Select),
                        ("#view-mode-toggle-btn", Button),
                    ):
                        widget = app.query_one(wid, wtype)
                        assert widget.region.height >= 1
                        assert widget.region.right <= bar.region.right
                    active_pane = app.query_one(
                        f"#{app.query_one('#main-tabs', TabbedContent).active}",
                        TabPane,
                    )
                    assert active_pane.region.height >= h - 5

    asyncio.run(_check())
