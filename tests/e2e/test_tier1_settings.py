"""Tier 1 E2E tests for zero-env per-user Settings CLI and TUI configuration."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.e2e.conftest import MockRFServer, MockSplunkServer


def _scrub_rf_splunk_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key == "SOCLENS_SETTINGS_FILE" or key == "SOCLENS_HOME":
            continue
        if key.startswith(("RF_", "SPLUNK_")) or key in (
            "RECORDED_FUTURE_API_KEY",
            "RECORDED_FUTURE_SANDBOX_TOKEN",
        ):
            monkeypatch.delenv(key, raising=False)


@pytest.mark.e2e
@pytest.mark.tier1
def test_e2e_cli_zero_env_configured_via_settings(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    rf_server = MockRFServer()
    splunk_server = MockSplunkServer()
    try:
        _scrub_rf_splunk_env(monkeypatch)

        # Confirm zero-env watchlist query fails cleanly before configuring settings
        fail_proc = run_cli(["watchlist", "list"])
        assert fail_proc.returncode != 0

        # Configure RF & Splunk entirely via `soclens settings set`
        for key, val in (
            ("rf_api_token", "test-rf-token"),
            ("rf_base_url", rf_server.base_url),
            ("splunk_host", splunk_server.base_url),
            ("splunk_token", "test-splunk-token"),
            ("splunk_app", "SplunkEnterpriseSecuritySuite"),
        ):
            set_proc = run_cli(["settings", "set", key, val, "--json"])
            assert set_proc.returncode == 0, set_proc.stderr

        wl_proc = run_cli(["--json", "watchlist", "list"])
        assert wl_proc.returncode == 0, f"stdout={wl_proc.stdout}\nstderr={wl_proc.stderr}"
        lists_payload = json.loads(wl_proc.stdout)
        assert isinstance(lists_payload, list) and len(lists_payload) >= 1

        conf_path = e2e_workspace / "savedsearches.conf"
        conf_path.write_text(
            '[RF Test Rule]\nsearch = index=main | head 1\ndispatch.earliest_time = -15m\n',
            encoding="utf-8",
        )
        val_proc = run_cli(["validate", "--input", str(conf_path), "--json"])
        assert val_proc.returncode == 0, f"stdout={val_proc.stdout}\nstderr={val_proc.stderr}"
    finally:
        rf_server.close()
        splunk_server.close()


@pytest.mark.e2e
@pytest.mark.tier1
def test_e2e_tui_zero_env_settings_save_and_live_queries(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from textual.widgets import Input, OptionList, Static, TabbedContent

    from soclens.tui import create_app

    rf_server = MockRFServer()
    splunk_server = MockSplunkServer()
    try:
        _scrub_rf_splunk_env(monkeypatch)
        # Ensure we use a fresh subprocess-safe local client inside TUI
        app = create_app(dry_run=True, workspace_dir=e2e_workspace, view_mode="admin")

        async def _run() -> None:
            async with app.run_test(size=(140, 42)) as pilot:
                await pilot.pause()
                assert app.client.api_token is None

                await pilot.press("0")
                await pilot.pause()
                tabs = app.query_one("#main-tabs", TabbedContent)
                assert tabs.active == "tab-settings"

                app.query_one("#set-rf-api-token", Input).value = "test-rf-token"
                app.query_one("#set-rf-base-url", Input).value = rf_server.base_url
                app.query_one("#set-splunk-host", Input).value = splunk_server.base_url
                app.query_one("#set-splunk-token", Input).value = "test-splunk-token"
                await pilot.click("#settings-save-btn")
                await pilot.pause()

                await pilot.click("#settings-test-rf-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert "RF OK" in str(app.query_one("#settings-status", Static).content)

                app.query_one("#settings-category-list", OptionList).highlighted = 1
                await pilot.pause()
                await pilot.click("#settings-test-splunk-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert "Splunk OK" in str(app.query_one("#settings-status", Static).content)

                # Switch to Watchlists tab and confirm auto-load fetches live lists
                await pilot.press("2")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert len(app.query_one("WatchlistsPane")._all_watchlists) >= 1

                # Clean exit
                assert sys.version_info >= (3, 12)

        asyncio.run(_run())
    finally:
        rf_server.close()
        splunk_server.close()
