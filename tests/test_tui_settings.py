"""Pilot TUI tests for the Settings & Credentials tab and live reload across panes."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from textual.widgets import (
    Checkbox,
    Collapsible,
    ContentSwitcher,
    Input,
    OptionList,
    Select,
    Static,
    TabbedContent,
)

import soclens.settings as settings_mod
from soclens.client import RecordedFutureClient
from soclens.config import get_rf_verify_ssl, get_sentinelone_config, get_splunk_config
from soclens.tui import ConfirmActionModal, create_app
from soclens.tui.screens import SettingsPane


def test_tui_open_settings_via_keys_dashboard_button_and_context_menu(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(), dry_run=True, workspace_dir=tmp_path, view_mode="admin"
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 40)) as pilot:
            await pilot.pause()
            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-dashboard"

            await pilot.press("0")
            await pilot.pause()
            assert tabs.active == "tab-settings"

            await pilot.press("1")
            await pilot.pause()
            assert tabs.active == "tab-dashboard"

            await pilot.click("#dash-settings-btn")
            await pilot.pause()
            assert tabs.active == "tab-settings"

            await pilot.press("1")
            await pilot.pause()
            await pilot.press("f10")
            await pilot.pause()
            assert tabs.active == "tab-settings"

    asyncio.run(_run())


def test_tui_settings_zero_env_save_live_reloads_client_dashboard_and_watchlists(
    tmp_path: Path,
) -> None:
    with patch.dict(os.environ, {}, clear=True):
        app = create_app(dry_run=True, workspace_dir=tmp_path, view_mode="admin")

        async def _run() -> None:
            async with app.run_test(size=(130, 40)) as pilot:
                await pilot.pause()
                dash_summary = str(app.query_one("#dash-env-summary", Static).content)
                assert "Missing" in dash_summary

                # Open Watchlists first with missing token -> shows missing status
                tabs = app.query_one("#main-tabs", TabbedContent)
                tabs.active = "tab-watchlists"
                await pilot.pause()
                assert "RF_API_TOKEN not configured" in str(
                    app.query_one("#wl-status", Static).content
                )

                # Switch to Settings via '0'
                await pilot.press("0")
                await pilot.pause()
                assert tabs.active == "tab-settings"

                # Fill RF, Splunk, SentinelOne, SSL proxy mode
                app.query_one("#set-rf-api-token", Input).value = "ui-rf-token-1234"
                app.query_one("#set-splunk-host", Input).value = "https://splunk.ui.local:8089"
                app.query_one("#set-splunk-token", Input).value = "ui-splunk-token"
                app.query_one("#set-splunk-app", Input).value = "CustomESApp"
                app.query_one("#set-s1-console-url", Input).value = "https://s1.ui.local"
                app.query_one("#set-s1-api-token", Input).value = "ui-s1-token"
                app.query_one("#set-rf-verify-ssl", Select).value = "false"
                await pilot.pause()

                await pilot.click("#settings-save-btn")
                await pilot.pause()

                # Persisted cleanly to per-user settings file
                saved = settings_mod.get_profile_settings()
                assert saved["rf_api_token"] == "ui-rf-token-1234"
                assert saved["splunk_host"] == "https://splunk.ui.local:8089"
                assert saved["splunk_token"] == "ui-splunk-token"
                assert saved["splunk_app"] == "CustomESApp"
                assert saved["s1_console_url"] == "https://s1.ui.local"
                assert saved["s1_api_token"] == "ui-s1-token"
                assert saved["rf_verify_ssl"] == "false"

                # Live app state updated without restart
                assert isinstance(app.client, RecordedFutureClient)
                assert app.client.api_token == "ui-rf-token-1234"
                assert app.client.verify_ssl is False
                assert "INSECURE SSL" in app.sub_title
                assert get_splunk_config(required=True).app == "CustomESApp"
                assert get_sentinelone_config(required=True).console_url == "https://s1.ui.local"

                # Dashboard updated live
                new_dash = str(app.query_one("#dash-env-summary", Static).content)
                assert "Set (settings)" in new_dash
                assert "CustomESApp" in new_dash

                # Watchlists auto-load gate reset so switching back attempts load
                wl_pane = app.query_one("WatchlistsPane")
                assert wl_pane._auto_load_started is False

                # Splunk & Bundle tab picks up updated Splunk app when activated
                tabs.active = "tab-splunk-bundle"
                await pilot.pause()
                assert app.query_one("#splunk-app", Input).value == "CustomESApp"

        asyncio.run(_run())


def test_tui_settings_show_secrets_categories_and_validation_focus(tmp_path: Path) -> None:
    app = create_app(client=MagicMock(), dry_run=True, initial_tab="tab-settings", workspace_dir=tmp_path)

    async def _run() -> None:
        async with app.run_test(size=(130, 40)) as pilot:
            await pilot.pause()
            # Show Secrets toggles password mode on all secret inputs
            secret_ids = (
                "#set-rf-api-token",
                "#set-rf-sandbox-token",
                "#set-splunk-token",
                "#set-splunk-password",
                "#set-s1-api-token",
            )
            for sid in secret_ids:
                assert app.query_one(sid, Input).password is True

            cb = app.query_one("#settings-show-secrets", Checkbox)
            cb.value = True
            await pilot.pause()
            for sid in secret_ids:
                assert app.query_one(sid, Input).password is False

            cb.value = False
            await pilot.pause()
            for sid in secret_ids:
                assert app.query_one(sid, Input).password is True

            # Category switching
            cat_list = app.query_one("#settings-category-list", OptionList)
            switcher = app.query_one("#settings-category-switcher", ContentSwitcher)
            for idx, expected_cat in enumerate(
                ("cat-rf", "cat-splunk", "cat-s1", "cat-network", "cat-workspace", "cat-profiles")
            ):
                cat_list.highlighted = idx
                await pilot.pause()
                assert switcher.current == expected_cat

            # Invalid base URL switches to cat-rf, opens collapsible, prevents save
            cat_list.highlighted = 5
            await pilot.pause()
            app.query_one("#set-rf-base-url", Input).value = "invalid-url"
            await pilot.click("#settings-save-btn")
            await pilot.pause()
            assert switcher.current == "cat-rf"
            assert app.query_one("#settings-rf-urls-collapsible", Collapsible).collapsed is False
            assert "Validation error" in str(app.query_one("#settings-status", Static).content)
            assert "rf_base_url" not in settings_mod.get_profile_settings()

    asyncio.run(_run())


def test_tui_settings_import_env_and_shell_env_conflict_session_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RF_API_TOKEN", "env-token-alpha")
    monkeypatch.setenv("SPLUNK_TOKEN", "env-splunk-beta")
    app = create_app(dry_run=True, initial_tab="tab-settings", workspace_dir=tmp_path)

    async def _run() -> None:
        async with app.run_test(size=(130, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#settings-import-env-btn")
            await pilot.pause()
            assert app.query_one("#set-rf-api-token", Input).value == "env-token-alpha"
            assert app.query_one("#set-splunk-token", Input).value == "env-splunk-beta"
            saved = settings_mod.get_profile_settings()
            assert saved["rf_api_token"] == "env-token-alpha"
            assert saved["splunk_token"] == "env-splunk-beta"

            # Now user edits RF token in UI to override shell env in this session
            app.query_one("#set-rf-api-token", Input).value = "ui-override-token"
            await pilot.click("#settings-save-btn")
            await pilot.pause()

            assert os.environ["RF_API_TOKEN"] == "env-token-alpha"  # os.environ NOT mutated
            assert app.client.api_token == "ui-override-token"
            assert "session" in str(app.query_one("#settings-status", Static).content).lower()

        # Session override is cleaned up on unmount
        assert settings_mod.get_session_override("rf_api_token") == (False, None)
        assert get_rf_verify_ssl() is True

    asyncio.run(_run())


def test_tui_settings_profiles_and_confirm_clear_delete(tmp_path: Path) -> None:
    app = create_app(client=MagicMock(), dry_run=False, initial_tab="tab-settings", workspace_dir=tmp_path)

    async def _run() -> None:
        async with app.run_test(size=(130, 40)) as pilot:
            await pilot.pause()
            # Create and switch to 'lab' profile
            app.query_one("#settings-category-list", OptionList).highlighted = 5
            await pilot.pause()
            app.query_one("#set-new-profile-input", Input).value = "lab"
            await pilot.click("#settings-create-profile-btn")
            await pilot.pause()
            assert settings_mod.get_active_profile_name() == "lab"

            # Save a value into 'lab'
            app.query_one("#set-rf-api-token", Input).value = "lab-secret"
            await pilot.click("#settings-save-btn")
            await pilot.pause()
            assert settings_mod.get_profile_settings(profile="lab")["rf_api_token"] == "lab-secret"

            # Clear profile requires ConfirmActionModal; cancel keeps data, approve wipes it
            await pilot.click("#settings-clear-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-cancel-btn")
            await pilot.pause()
            assert settings_mod.get_profile_settings(profile="lab")["rf_api_token"] == "lab-secret"

            await pilot.click("#settings-clear-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            assert settings_mod.get_profile_settings(profile="lab") == {}

            # Delete 'lab' profile requires ConfirmActionModal
            app.query_one("#settings-category-list", OptionList).highlighted = 5
            await pilot.pause()
            await pilot.click("#settings-delete-profile-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            assert settings_mod.list_profiles() == ["default"]
            assert settings_mod.get_active_profile_name() == "default"

    asyncio.run(_run())


def test_tui_settings_connection_tests_and_responsive_layout(tmp_path: Path) -> None:
    mock_rf = MagicMock()
    mock_rf.check_connection.return_value = {"connected": True, "sample_lists": 3}
    mock_s1 = MagicMock()
    mock_s1.check_connection.return_value = {"version": "24.1"}
    app = create_app(
        client=mock_rf,
        s1_client=mock_s1,
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
    )

    async def _run_all() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            ws = app.query_one("#settings-workspace")
            assert not ws.has_class("split-horizontal")

            await pilot.resize_terminal(150, 42)
            await pilot.pause()
            assert ws.has_class("split-horizontal")

            pane = app.query_one(SettingsPane)
            app.query_one("#set-rf-api-token", Input).value = "rf-tok"
            app.query_one("#set-s1-console-url", Input).value = "https://s1.local"
            app.query_one("#set-s1-api-token", Input).value = "s1-tok"
            await pilot.click("#settings-test-rf-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert "RF connected" in str(app.query_one("#settings-status", Static).content)

            app.query_one("#settings-category-list", OptionList).highlighted = 2
            await pilot.pause()
            await pilot.click("#settings-test-s1-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert "SentinelOne OK" in str(app.query_one("#settings-status", Static).content)

            with patch("soclens.tui.screens.settings.SplunkValidator") as mock_sp:
                mock_sp.return_value.__enter__.return_value.check_connection.return_value = True
                app.query_one("#set-splunk-token", Input).value = "sp-tok"
                app.query_one("#settings-category-list", OptionList).highlighted = 1
                await pilot.pause()
                await pilot.click("#settings-test-splunk-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert "Splunk OK" in str(app.query_one("#settings-status", Static).content)

                await pilot.click("#settings-test-all-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                status_all = str(app.query_one("#settings-status", Static).content)
                assert "RF connected" in status_all
                assert "Splunk OK" in status_all
                assert "SentinelOne OK" in status_all

            assert isinstance(pane, SettingsPane)

    asyncio.run(_run_all())
