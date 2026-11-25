"""Unit and Textual Pilot tests for cross-platform TUI clipboard & CopyTextModal."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from textual.widgets import DataTable, Input, OptionList, Static, TextArea

from soclens.tui import ContextMenuModal, CopyTextModal, create_app
from soclens.tui.clipboard import (
    ClipboardResult,
    copy_text_to_clipboard,
    paste_text_from_clipboard,
)
from soclens.tui.screens.brand_logos import BrandLogosPane
from soclens.tui.screens.logs import LogsPane
from soclens.tui.screens.research import ResearchPane
from soclens.tui.screens.rf_intel import RFIntelPane
from soclens.tui.screens.sigma import SigmaPane
from soclens.tui.screens.splunk_bundle import SplunkBundlePane
from soclens.tui.screens.watchlists import WatchlistsPane

SAMPLE_SIGMA_YAML = """title: Suspicious PowerShell Encoded Command
id: 11111111-2222-3333-4444-555555555555
description: Detects PowerShell with encoded command flag.
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
"""


# ---------------------------------------------------------------------------
# Unit tests for soclens/tui/clipboard.py
# ---------------------------------------------------------------------------


def test_copy_windows_clip_and_osc52(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("soclens.tui.clipboard.sys.platform", "win32")
    monkeypatch.setattr(
        "soclens.tui.clipboard.shutil.which",
        lambda name: "C:\\Windows\\System32\\clip.exe" if name == "clip.exe" else None,
    )
    called_cmds: list[list[str]] = []

    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        called_cmds.append(cmd)
        assert kwargs["input"] == "hello windows"
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["timeout"] == 2.0
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("soclens.tui.clipboard.subprocess.run", _fake_run)
    app = MagicMock()
    res = copy_text_to_clipboard("hello windows", app=app)
    assert res == ClipboardResult(
        success=True, method="clip.exe+osc52", char_count=13, error=None
    )
    assert called_cmds == [["C:\\Windows\\System32\\clip.exe"]]
    app.copy_to_clipboard.assert_called_once_with("hello windows")


def test_copy_macos_pbcopy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("soclens.tui.clipboard.sys.platform", "darwin")
    monkeypatch.setattr(
        "soclens.tui.clipboard.shutil.which",
        lambda name: "/usr/bin/pbcopy" if name == "pbcopy" else None,
    )

    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert cmd == ["/usr/bin/pbcopy"]
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("soclens.tui.clipboard.subprocess.run", _fake_run)
    res = copy_text_to_clipboard("hello mac", app=None)
    assert res.success is True
    assert res.method == "pbcopy"
    assert res.char_count == 9


def test_copy_linux_wayland_and_x11_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("soclens.tui.clipboard.sys.platform", "linux")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-1")
    monkeypatch.setattr(
        "soclens.tui.clipboard.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in {"wl-copy", "xclip", "xsel"} else None,
    )
    seen: list[list[str]] = []

    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("soclens.tui.clipboard.subprocess.run", _fake_run)
    res = copy_text_to_clipboard("wayland text")
    assert res.success is True
    assert res.method == "wl-copy"
    assert seen == [["/usr/bin/wl-copy"]]

    # Without WAYLAND_DISPLAY, falls back to xclip then xsel
    seen.clear()
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        "soclens.tui.clipboard.shutil.which",
        lambda name: "/usr/bin/xsel" if name == "xsel" else None,
    )
    res2 = copy_text_to_clipboard("x11 text")
    assert res2.success is True
    assert res2.method == "xsel"
    assert seen == [["/usr/bin/xsel", "--clipboard", "--input"]]


def test_copy_osc52_fallback_when_no_native_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("soclens.tui.clipboard.sys.platform", "linux")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr("soclens.tui.clipboard.shutil.which", lambda _name: None)

    app = MagicMock()
    res = copy_text_to_clipboard("ssh session text", app=app)
    assert res.success is True
    assert res.method == "osc52"
    assert res.char_count == 16
    app.copy_to_clipboard.assert_called_once_with("ssh session text")


def test_copy_failure_resilience(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("soclens.tui.clipboard.sys.platform", "linux")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        "soclens.tui.clipboard.shutil.which",
        lambda name: "/usr/bin/xclip" if name == "xclip" else None,
    )

    def _boom(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd, 2.0)

    monkeypatch.setattr("soclens.tui.clipboard.subprocess.run", _boom)

    app = MagicMock()
    app.copy_to_clipboard.side_effect = RuntimeError("osc52 unsupported")
    res = copy_text_to_clipboard("fail gracefully", app=app)
    assert res.success is False
    assert res.method == "none"
    assert res.char_count == 15
    assert res.error is not None
    assert "xclip" in res.error


def test_paste_text_from_clipboard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("soclens.tui.clipboard.sys.platform", "darwin")
    monkeypatch.setattr(
        "soclens.tui.clipboard.shutil.which",
        lambda name: "/usr/bin/pbpaste" if name == "pbpaste" else None,
    )
    monkeypatch.setattr(
        "soclens.tui.clipboard.subprocess.run",
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, "pasted-ioc", ""),
    )
    assert paste_text_from_clipboard() == "pasted-ioc"

    # Error returns None safely
    def _fail(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise OSError("no display")

    monkeypatch.setattr("soclens.tui.clipboard.subprocess.run", _fail)
    assert paste_text_from_clipboard() is None


# ---------------------------------------------------------------------------
# Textual Pilot tests
# ---------------------------------------------------------------------------


def _select_context_option(app: Any, option_id: str) -> None:
    opts = app.screen.query_one("#ctx-menu-options", OptionList)
    opts.highlighted = opts.get_option_index(option_id)


def test_copy_text_modal_controls_and_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied_payloads: list[str] = []

    def _fake_copy(text: str, app: Any = None) -> ClipboardResult:
        copied_payloads.append(text)
        return ClipboardResult(success=True, method="mock", char_count=len(text))

    monkeypatch.setattr("soclens.tui.modals.copy_text_to_clipboard", _fake_copy)
    monkeypatch.setattr("soclens.tui.screens.base.copy_text_to_clipboard", _fake_copy)

    async def _run() -> None:
        app = create_app(
            client=MagicMock(),
            dry_run=True,
            initial_tab="tab-sigma",
            workspace_dir=tmp_path,
        )
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(SigmaPane)
            pane.open_copy_modal(
                "index=*wineventlog CommandLine=\"*-EncodedCommand*\"\n| table _time host",
                title="Test SPL Query",
                language="spl",
            )
            await pilot.pause()
            assert isinstance(app.screen, CopyTextModal)

            ta = app.screen.query_one("#copy-modal-textarea", TextArea)
            assert ta.read_only is True
            assert ta.soft_wrap is True
            assert "EncodedCommand" in ta.text

            meta = str(app.screen.query_one("#copy-modal-meta", Static).render())
            assert "2 line(s)" in meta

            # Copy All
            await pilot.click("#copy-modal-copy-btn")
            await pilot.pause()
            assert len(copied_payloads) == 1
            assert "EncodedCommand" in copied_payloads[0]

            # Toggle Wrap
            await pilot.click("#copy-modal-wrap-btn")
            await pilot.pause()
            assert ta.soft_wrap is False

            # Save to File
            await pilot.click("#copy-modal-save-btn")
            await pilot.pause()
            exported = list((tmp_path / "exports").glob("test_spl_query_*.spl"))
            assert len(exported) == 1
            assert "EncodedCommand" in exported[0].read_text(encoding="utf-8")

            # Close via Escape
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, CopyTextModal)

    asyncio.run(_run())


def test_sigma_pane_copy_buttons_bindings_and_context_menu(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied: list[str] = []

    def _fake_copy(text: str, app: Any = None) -> ClipboardResult:
        copied.append(text)
        return ClipboardResult(success=True, method="mock", char_count=len(text))

    monkeypatch.setattr("soclens.tui.screens.base.copy_text_to_clipboard", _fake_copy)
    monkeypatch.setattr("soclens.tui.modals.copy_text_to_clipboard", _fake_copy)

    async def _run() -> None:
        app = create_app(
            client=MagicMock(),
            dry_run=True,
            initial_tab="tab-sigma",
            workspace_dir=tmp_path,
        )
        async with app.run_test(size=(130, 38)) as pilot:
            await pilot.pause()
            pane = app.query_one(SigmaPane)
            sample_rule = {
                "rule_id": "sigma-ps-001",
                "level": "high",
                "index": "*wineventlog",
                "title": "Suspicious PowerShell Encoded Command",
                "file_name": "ps_encoded.yml",
                "content": SAMPLE_SIGMA_YAML,
            }
            pane._rules = [sample_rule]
            pane._populate_table([sample_rule])
            await pilot.pause()

            assert pane._last_raw_yaml == SAMPLE_SIGMA_YAML
            assert "index=*wineventlog" in pane._last_spl_query
            assert "[Recorded Future Sigma (Automated) - Suspicious PowerShell Encoded Command]" in pane._last_stanza_text

            # Copy SPL button
            await pilot.click("#sigma-copy-spl-btn")
            await pilot.pause()
            assert copied[-1] == pane._last_spl_query

            # Copy Stanza button
            await pilot.click("#sigma-copy-stanza-btn")
            await pilot.pause()
            assert copied[-1] == pane._last_stanza_text

            # Copy YAML button
            await pilot.click("#sigma-copy-yaml-btn")
            await pilot.pause()
            assert copied[-1] == SAMPLE_SIGMA_YAML

            # Copyable View button opens CopyTextModal
            await pilot.click("#sigma-copy-modal-btn")
            await pilot.pause()
            assert isinstance(app.screen, CopyTextModal)
            await pilot.click("#copy-modal-close-btn")
            await pilot.pause()
            assert not isinstance(app.screen, CopyTextModal)

            # Typing 'c', 'y', 'v' inside Input must NOT trigger copy/modal actions
            search_input = pane.query_one("#sigma-query-input", Input)
            search_input.focus()
            await pilot.pause()
            before_count = len(copied)
            await pilot.press("c", "y", "v")
            await pilot.pause()
            assert search_input.value == "cyv"
            assert len(copied) == before_count
            assert not isinstance(app.screen, CopyTextModal)

            # Focus table -> 'c' copies SPL, 'y' copies stanza, 'v' opens CopyTextModal
            pane.query_one("#sigma-table", DataTable).focus()
            await pilot.pause()
            await pilot.press("c")
            await pilot.pause()
            assert copied[-1] == pane._last_spl_query

            await pilot.press("y")
            await pilot.pause()
            assert copied[-1] == pane._last_stanza_text

            await pilot.press("v")
            await pilot.pause()
            assert isinstance(app.screen, CopyTextModal)
            await pilot.press("q")
            await pilot.pause()
            assert not isinstance(app.screen, CopyTextModal)

            # Copyable View opens CopyTextModal via button
            await pilot.click("#sigma-copy-modal-btn")
            await pilot.pause()
            assert isinstance(app.screen, CopyTextModal)
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(_run())


def test_cross_pane_copy_and_modal_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied: list[str] = []

    def _fake_copy(text: str, app: Any = None) -> ClipboardResult:
        copied.append(text)
        return ClipboardResult(success=True, method="mock", char_count=len(text))

    monkeypatch.setattr("soclens.tui.screens.base.copy_text_to_clipboard", _fake_copy)
    monkeypatch.setattr("soclens.tui.modals.copy_text_to_clipboard", _fake_copy)

    async def _run() -> None:
        app = create_app(
            client=MagicMock(),
            dry_run=True,
            initial_tab="tab-rf-intel",
            workspace_dir=tmp_path,
            view_mode="admin",
        )
        async with app.run_test(size=(130, 38)) as pilot:
            await pilot.pause()

            # 1. RF Intel Pane: Copy Detail button + context menu
            rf_pane = app.query_one(RFIntelPane)
            await pilot.click("#rf-copy-detail-btn")
            await pilot.pause()
            assert len(copied) >= 1
            assert copied[-1] != ""

            rf_pane._open_pane_context_menu(origin=(5, 5))
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option(app, "open_copy_view")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, CopyTextModal)
            await pilot.press("escape")
            await pilot.pause()

            # 2. Research Pane: Copy Detail button
            app.action_switch_tab("tab-research")
            await pilot.pause()
            res_pane = app.query_one(ResearchPane)
            before = len(copied)
            await pilot.click("#res-copy-detail-btn")
            await pilot.pause()
            assert len(copied) == before + 1
            assert res_pane is not None

            # 3. Watchlists Pane: context menu Copy Watchlist ID
            app.action_switch_tab("tab-watchlists")
            await pilot.pause()
            wl_pane = app.query_one(WatchlistsPane)
            wl_pane._open_watchlist_menu(
                {"id": "report:wl-123", "type": "domain", "name": "Corp Domains"},
                origin=(5, 5),
            )
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option(app, "copy_list_id")
            await pilot.press("enter")
            await pilot.pause()
            assert copied[-1] == "report:wl-123"

            # 4. Brand Logos Pane: table row text extraction
            app.action_switch_tab("tab-brand-logos")
            await pilot.pause()
            brand_pane = app.query_one(BrandLogosPane)
            brand_table = brand_pane.query_one("#brand-table", DataTable)
            brand_table.clear()
            sha256_sample = "a" * 64
            brand_table.add_row("example.com", "synced", "1", sha256_sample)
            from soclens.tui.screens.base import extract_table_row_text

            row_txt = extract_table_row_text(brand_table, row_index=0)
            assert "example.com" in row_txt
            assert sha256_sample in row_txt

            # 5. Splunk & Bundle Pane: selected stanza extraction
            app.action_switch_tab("tab-splunk-bundle")
            await pilot.pause()
            splunk_pane = app.query_one(SplunkBundlePane)
            splunk_pane._last_searches = [
                {
                    "stanza": "RF Test Detection",
                    "file": "savedsearches.conf",
                    "search": "index=*wineventlog EventCode=4688",
                }
            ]
            splunk_table = splunk_pane.query_one("#splunk-results-table", DataTable)
            splunk_table.add_row("RF Test Detection", "savedsearches.conf", "DRY-RUN", "-", "")
            stanza_text, _title = splunk_pane._selected_stanza_or_row_text(row_index=0)
            assert "[RF Test Detection]" in stanza_text
            assert "index=*wineventlog EventCode=4688" in stanza_text

            # 6. Logs Pane: Copy Visible Logs button
            app.action_switch_tab("tab-logs")
            await pilot.pause()
            app.record_log("Clipboard verification entry", level="INFO", source="tui")
            await pilot.pause()
            logs_pane = app.query_one(LogsPane)
            logs_pane.rebuild_view()
            await pilot.pause()
            await pilot.click("#logs-copy-btn")
            await pilot.pause()
            assert "Clipboard verification entry" in copied[-1]
            assert json.dumps({"ok": True})  # sanity

    asyncio.run(_run())
