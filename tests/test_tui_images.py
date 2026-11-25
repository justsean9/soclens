"""Tests for Windows-safe image rendering, default OS viewer toggle, and detail right-click open."""

from __future__ import annotations

import asyncio
import json
import struct
import zlib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from rich.color import ColorSystem
from textual.widgets import Button, OptionList, RichLog, Static

from soclens.cli import build_parser, main
from soclens.config import (
    IMAGE_VIEWER_OS,
    IMAGE_VIEWER_TUI,
    ConfigurationError,
    get_image_viewer_mode,
    load_tui_settings,
    normalize_image_viewer_mode,
    save_tui_settings,
)
from soclens.tui import ContextMenuModal, ScreenshotViewerModal, SocLensApp, create_app
from soclens.tui.image_render import (
    _detect_image_extension,
    blur_decoded_image,
    blur_image_bytes,
    build_iterm2_overlay_sequence,
    build_sixel_overlay_sequence,
    can_emit_kitty_truecolor,
    compute_terminal_cell_grid,
    decode_image,
    detect_terminal_graphics_protocol,
    encode_sixel,
    format_graphics_protocol_status,
    get_recommended_image_viewer_mode,
    has_native_pixel_graphics,
    is_multiplexer_session,
    is_no_color_environment,
    is_truecolor_kitty_env,
    is_windows_terminal_environment,
    open_image_in_native_viewer,
    parse_terminal_graphics_probe,
    render_screenshot_panel,
    reset_terminal_probe_cache,
    set_terminal_probe_result,
    stage_screenshot_file,
)


def _make_png(
    width: int,
    height: int,
    *,
    rgb: tuple[int, int, int] = (30, 120, 220),
) -> bytes:
    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I4s", len(data), ctype) + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = b"\x00" + bytes(rgb) * width
    idat = zlib.compress(row * height)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )


def _select_context_option_by_id(app: SocLensApp, option_id: str) -> None:
    opts = app.screen.query_one("#ctx-menu-options", OptionList)
    opts.highlighted = opts.get_option_index(option_id)


def _find_richlog_line(log_widget: RichLog, needle: str) -> int:
    for idx, strip in enumerate(log_widget.lines):
        if needle in strip.text:
            return idx
    raise AssertionError(f"Text {needle!r} not found in RichLog")


def _make_playbook_client(png_1: bytes, png_2: bytes) -> MagicMock:
    mock_client = MagicMock()
    mock_client.search_playbook_alerts.return_value = {
        "data": [
            {
                "playbook_alert_id": "pb-shot-1",
                "category": "domain_abuse",
                "priority": "High",
                "status": "New",
                "title": "lookalike.example",
            }
        ],
        "counts": {"returned": 1, "total": 1},
    }
    mock_client.get_playbook_alert.return_value = {
        "status": {"status_code": "Ok"},
        "data": {
            "playbook_alert_id": "pb-shot-1",
            "panel_status": {
                "status": "New",
                "priority": "High",
                "entity_name": "lookalike.example",
            },
            "panel_evidence_summary": {
                "explanation": "Screenshot captured on impersonation site",
                "screenshots": [
                    {
                        "image_id": "img:shot-1",
                        "availability": "Available",
                        "created": "2026-11-24T15:12:00Z",
                        "tag": "Login page",
                    },
                    {
                        "image_id": "img:shot-2",
                        "availability": "Available",
                        "created": "2026-11-24T15:03:00Z",
                        "tag": "Secondary view",
                    },
                ],
            },
        },
    }

    def _fetch_img(_category: str, _alert_id: str, image_id: str) -> bytes:
        return png_2 if image_id == "img:shot-2" else png_1

    mock_client.get_playbook_alert_image.side_effect = _fetch_img
    return mock_client


# ------------------------------------------------------------------
# 1. Windows Kitty HD Protections
# ------------------------------------------------------------------


def test_windows_terminal_detection_and_kitty_disabled() -> None:
    assert is_windows_terminal_environment({}, platform_name="win32") is True
    assert is_windows_terminal_environment({}, platform_name="cygwin") is True
    assert is_windows_terminal_environment({}, platform_name="msys") is True
    assert is_windows_terminal_environment({"WT_SESSION": "abc-123"}, platform_name="linux") is True
    assert is_windows_terminal_environment({"WT_PROFILE_ID": "{guid}"}, platform_name="linux") is True
    assert is_windows_terminal_environment({"ConEmuPID": "4242"}, platform_name="linux") is True
    assert is_windows_terminal_environment({"TERM": "xterm-256color"}, platform_name="linux") is False

    # Windows Terminal v1.22+ supports Sixel even when Kitty/Ghostty vars leak
    assert (
        detect_terminal_graphics_protocol(
            {"WT_SESSION": "abc-123"},
            is_headless=False,
            platform_name="win32",
        )
        == "sixel"
    )
    assert (
        detect_terminal_graphics_protocol(
            {"KITTY_WINDOW_ID": "1", "WT_SESSION": "1"},
            is_headless=False,
            platform_name="linux",
        )
        == "sixel"
    )
    assert (
        has_native_pixel_graphics(
            {"WT_PROFILE_ID": "{guid}"},
            is_headless=False,
            platform_name="win32",
        )
        is True
    )
    assert (
        get_recommended_image_viewer_mode(
            {"WT_SESSION": "1"},
            is_headless=False,
            platform_name="win32",
        )
        == "tui"
    )
    assert (
        format_graphics_protocol_status(
            {"WT_SESSION": "1"},
            is_headless=False,
            platform_name="win32",
        )
        == "Sixel HD"
    )

    # Classic Windows conhost / PowerShell has no inline pixel protocol -> OS viewer default
    assert (
        detect_terminal_graphics_protocol(
            {"KITTY_WINDOW_ID": "1", "TERM": "xterm-kitty"},
            is_headless=False,
            platform_name="win32",
        )
        == "halfblock"
    )
    assert (
        has_native_pixel_graphics({}, is_headless=False, platform_name="win32") is False
    )
    assert (
        get_recommended_image_viewer_mode({}, is_headless=False, platform_name="win32")
        == "os"
    )
    assert (
        format_graphics_protocol_status({}, is_headless=False, platform_name="win32")
        == "Halfblock (OS Viewer)"
    )

    # macOS Terminal.app has no inline pixel protocol -> OS viewer default
    assert (
        detect_terminal_graphics_protocol(
            {"TERM_PROGRAM": "Apple_Terminal"},
            is_headless=False,
            platform_name="darwin",
        )
        == "halfblock"
    )
    assert (
        get_recommended_image_viewer_mode(
            {"TERM_PROGRAM": "Apple_Terminal"},
            is_headless=False,
            platform_name="darwin",
        )
        == "os"
    )

    # iTerm2 & WezTerm (macOS/Linux/Windows) use OSC 1337 iTerm2 HD
    assert (
        detect_terminal_graphics_protocol(
            {"TERM_PROGRAM": "iTerm.app"},
            is_headless=False,
            platform_name="darwin",
        )
        == "iterm2"
    )
    assert (
        detect_terminal_graphics_protocol(
            {"TERM_PROGRAM": "WezTerm", "WEZTERM_PANE": "0"},
            is_headless=False,
            platform_name="win32",
        )
        == "iterm2"
    )
    assert (
        format_graphics_protocol_status(
            {"ITERM_SESSION_ID": "w0t0p0:1"},
            is_headless=False,
            platform_name="darwin",
        )
        == "iTerm2 HD"
    )

    # VS Code launched inside Windows Terminal / iTerm2 stays Halfblock unless probed
    assert (
        detect_terminal_graphics_protocol(
            {"WT_SESSION": "1", "TERM_PROGRAM": "vscode", "VSCODE_PID": "99"},
            is_headless=False,
            platform_name="win32",
        )
        == "halfblock"
    )
    assert (
        detect_terminal_graphics_protocol(
            {"ITERM_SESSION_ID": "1", "TERM_PROGRAM": "vscode"},
            is_headless=False,
            platform_name="darwin",
        )
        == "halfblock"
    )

    # Explicit RF_TUI_IMAGE_PROTOCOL overrides win everywhere
    for forced in ("kitty", "iterm2", "sixel", "halfblock"):
        assert (
            detect_terminal_graphics_protocol(
                {"RF_TUI_IMAGE_PROTOCOL": forced},
                is_headless=False,
                platform_name="win32",
            )
            == forced
        )

    assert format_graphics_protocol_status({"TERM": "xterm-256color"}, is_headless=True, platform_name="linux") == "Halfblock"


def test_screenshot_modal_disables_kitty_toggle_on_windows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import soclens.tui.modals as modals_mod

    monkeypatch.setattr(modals_mod, "detect_terminal_graphics_protocol", lambda *a, **k: "halfblock")
    png_bytes = _make_png(64, 48)
    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
    shots = [{"image_id": "img:win-test", "meta": {}, "raw_bytes": png_bytes}]

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            modal = ScreenshotViewerModal(title="win.test", screenshots=shots, dry_run=True)
            app.push_screen(modal)
            await pilot.pause()

            assert len(modal.query("#shot-mode-btn")) == 0
            open_btn = modal.query_one("#shot-open-btn", Button)
            blur_btn = modal.query_one("#shot-blur-btn", Button)
            meta_bar = modal.query_one("#shot-viewer-meta", Static)

            assert open_btn.variant == "primary"
            assert "Blur: ON" in str(blur_btn.label)
            assert "BLURRED" in str(meta_bar.render())
            assert "Mode: Halfblock" in str(meta_bar.render())
            assert "[o] Open Viewer" in str(meta_bar.render())
            assert "[g]" not in str(meta_bar.render())

            # Pressing 'g' no longer switches protocols
            await pilot.press("g")
            await pilot.pause()
            assert modal._protocol == "halfblock"
            assert "Mode: Halfblock" in str(meta_bar.render())

    asyncio.run(_run())


# ------------------------------------------------------------------
# 2. OS Native Viewer Staging & Resilience
# ------------------------------------------------------------------


def test_detect_image_extension_and_stage_lock_resilience(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import soclens.tui.image_render as img_mod

    assert _detect_image_extension(b"\x89PNG\r\n\x1a\n...") == ".png"
    assert _detect_image_extension(b"\xff\xd8\xff\xe0...") == ".jpg"
    assert _detect_image_extension(b"GIF89a...") == ".gif"
    assert _detect_image_extension(b"RIFF1234WEBP...") == ".webp"
    assert _detect_image_extension(b"BM1234...") == ".bmp"
    assert _detect_image_extension(b"unknown-bytes") == ".png"

    monkeypatch.setattr(img_mod.tempfile, "gettempdir", lambda: str(tmp_path))

    long_id = "img:" + ("a" * 160)
    staged_long = stage_screenshot_file(b"\xff\xd8\xff\xe0jpeg-data", image_id=long_id)
    assert staged_long.suffix == ".jpg"
    assert len(staged_long.stem) <= 80
    assert staged_long.read_bytes() == b"\xff\xd8\xff\xe0jpeg-data"

    # Simulate Windows file lock PermissionError on existing path
    locked_bytes_v1 = _make_png(12, 12, rgb=(10, 20, 30))
    locked_bytes_v2 = _make_png(12, 12, rgb=(200, 30, 40))
    first_path = stage_screenshot_file(locked_bytes_v1, image_id="locked_shot")

    orig_write_bytes = Path.write_bytes

    def _fail_first_write(self_path: Path, data: bytes) -> int:
        if self_path == first_path:
            raise PermissionError("File locked by Photos.exe")
        return orig_write_bytes(self_path, data)

    monkeypatch.setattr(Path, "write_bytes", _fail_first_write)

    # Identical bytes -> reuses existing locked file path
    reused = stage_screenshot_file(locked_bytes_v1, image_id="locked_shot")
    assert reused == first_path

    # Different bytes -> stages to unique non-locked path
    fallback = stage_screenshot_file(locked_bytes_v2, image_id="locked_shot")
    assert fallback != first_path
    assert fallback.read_bytes() == locked_bytes_v2


def test_open_image_in_native_viewer_win32_startfile_and_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import soclens.tui.image_render as img_mod

    monkeypatch.setattr(img_mod.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(img_mod.sys, "platform", "win32")

    started: list[str] = []
    monkeypatch.setattr(img_mod.os, "startfile", lambda p: started.append(p), raising=False)
    png_bytes = _make_png(16, 16)
    out = open_image_in_native_viewer(png_bytes, image_id="win-shot")
    assert out.is_file()
    assert started == [str(out)]

    def _boom(_p: str) -> None:
        raise OSError("No file association")

    monkeypatch.setattr(img_mod.os, "startfile", _boom, raising=False)
    with pytest.raises(RuntimeError, match="Unable to open OS image viewer"):
        open_image_in_native_viewer(png_bytes, image_id="win-shot-err")


# ------------------------------------------------------------------
# 3. Config, Workspace Persistence & CLI Flags
# ------------------------------------------------------------------


def test_image_viewer_config_precedence_and_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOCLENS_IMAGE_VIEWER", raising=False)
    monkeypatch.delenv("RF_TUI_OPEN_IMAGES_IN_OS_VIEWER", raising=False)

    assert normalize_image_viewer_mode("OS_Viewer") == IMAGE_VIEWER_OS
    assert normalize_image_viewer_mode("native") == IMAGE_VIEWER_OS
    assert normalize_image_viewer_mode("modal") == IMAGE_VIEWER_TUI
    with pytest.raises(ConfigurationError, match="Invalid image viewer mode"):
        normalize_image_viewer_mode("invalid-mode")

    # Default when nothing is set
    assert get_image_viewer_mode(workspace_dir=tmp_path) == IMAGE_VIEWER_TUI

    # Corrupt settings file is ignored gracefully
    settings_file = tmp_path / ".soclens_tui_settings.json"
    settings_file.write_text("{not-json", encoding="utf-8")
    assert load_tui_settings(tmp_path) == {}
    assert get_image_viewer_mode(workspace_dir=tmp_path) == IMAGE_VIEWER_TUI

    # Save merges unrelated keys and persists
    settings_file.write_text(json.dumps({"other_key": 42}), encoding="utf-8")
    save_tui_settings({"image_viewer": "os"}, workspace_dir=tmp_path)
    loaded = load_tui_settings(tmp_path)
    assert loaded == {"other_key": 42, "image_viewer": "os"}
    assert get_image_viewer_mode(workspace_dir=tmp_path) == IMAGE_VIEWER_OS

    # Env vars override persisted file, and explicit overrides env vars
    monkeypatch.setenv("RF_TUI_OPEN_IMAGES_IN_OS_VIEWER", "false")
    assert get_image_viewer_mode(workspace_dir=tmp_path) == IMAGE_VIEWER_TUI

    monkeypatch.setenv("SOCLENS_IMAGE_VIEWER", "os")
    assert get_image_viewer_mode(workspace_dir=tmp_path) == IMAGE_VIEWER_OS
    assert get_image_viewer_mode("tui", workspace_dir=tmp_path) == IMAGE_VIEWER_TUI

    monkeypatch.delenv("SOCLENS_IMAGE_VIEWER", raising=False)
    monkeypatch.setenv("RF_TUI_OPEN_IMAGES_IN_OS_VIEWER", "maybe")
    with pytest.raises(ConfigurationError, match="RF_TUI_OPEN_IMAGES_IN_OS_VIEWER"):
        get_image_viewer_mode(workspace_dir=tmp_path)


def test_cli_image_viewer_flags_forwarded_to_run_unified_tui(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = build_parser()
    args_1 = parser.parse_args(["--os-image-viewer", "--tui"])
    assert args_1.os_image_viewer is True

    args_2 = parser.parse_args(["tui", "--image-viewer", "os"])
    assert args_2.image_viewer == "os"

    captured: list[dict[str, Any]] = []

    def _fake_run_tui(client: Any, dry_run: bool = False, **kwargs: Any) -> None:
        captured.append({"client": client, "dry_run": dry_run, "kwargs": kwargs})

    import soclens.cli as cli_mod

    monkeypatch.setattr(cli_mod, "RecordedFutureClient", MagicMock())
    monkeypatch.setattr(cli_mod, "run_unified_tui", _fake_run_tui)

    monkeypatch.setattr("sys.argv", ["soclens", "tui", "--os-image-viewer"])
    main()
    assert captured[-1]["kwargs"]["image_viewer"] == "os"

    monkeypatch.setattr("sys.argv", ["soclens", "--image-viewer", "tui", "--tui"])
    main()
    assert captured[-1]["kwargs"]["image_viewer"] == "tui"


# ------------------------------------------------------------------
# 4. Default OS Viewer Toggle & End-to-End Pilot Flows
# ------------------------------------------------------------------


def test_tui_toggle_os_viewer_default_persists_and_opens_directly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import soclens.tui.modals as modals_mod
    import soclens.tui.screens.rf_intel as rf_intel_mod

    monkeypatch.delenv("SOCLENS_IMAGE_VIEWER", raising=False)
    monkeypatch.delenv("RF_TUI_OPEN_IMAGES_IN_OS_VIEWER", raising=False)

    png_1 = _make_png(48, 32, rgb=(220, 40, 40))
    png_2 = _make_png(48, 32, rgb=(40, 200, 60))
    opened_calls: list[tuple[bytes, str]] = []
    staged_calls: list[tuple[bytes, str]] = []

    def _fake_open(raw_bytes: bytes, *, image_id: str) -> Path:
        opened_calls.append((raw_bytes, image_id))
        return tmp_path / f"{image_id}.png"

    def _fake_stage(raw_bytes: bytes, *, image_id: str) -> Path:
        staged_calls.append((raw_bytes, image_id))
        return tmp_path / f"{image_id}.png"

    monkeypatch.setattr(rf_intel_mod, "open_image_in_native_viewer", _fake_open)
    monkeypatch.setattr(rf_intel_mod, "stage_screenshot_file", _fake_stage)
    monkeypatch.setattr(modals_mod, "open_image_in_native_viewer", _fake_open)

    mock_client = _make_playbook_client(png_1, png_2)
    app = create_app(
        client=mock_client,
        dry_run=False,
        initial_tab="tab-dashboard",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 44)) as pilot:
            await pilot.pause()

            # Default starts as TUI modal
            dash_btn = app.query_one("#dash-image-viewer-btn", Button)
            assert "Image Viewer: TUI" in str(dash_btn.label)
            assert app.open_images_in_os_viewer is False

            # Toggle on Dashboard -> persists and syncs RF Intel controls
            await pilot.click("#dash-image-viewer-btn")
            await pilot.pause()
            assert app.open_images_in_os_viewer is True
            assert "Image Viewer: OS" in str(dash_btn.label)
            assert "OS Image Viewer (Default)" in str(
                app.query_one("#dash-env-summary", Static).render()
            )
            assert load_tui_settings(tmp_path).get("image_viewer") == "os"

            # Switch to RF Intel tab, load Playbook Alerts & Deep Detail
            await pilot.press("4")
            await pilot.pause()
            rf_default_btn = app.query_one("#rf-os-viewer-default-btn", Button)
            assert "OS Viewer Default: ON" in str(rf_default_btn.label)

            await pilot.click("#rf-pb-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#rf-fetch-detail-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            images_btn = app.query_one("#rf-images-btn", Button)
            assert "Images (2) (OS)" in str(images_btn.label)

            # With OS default ON and blur ON by default, clicking Images opens blurred copy in OS viewer
            await pilot.click("#rf-images-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert not isinstance(app.screen, ScreenshotViewerModal)
            assert len(opened_calls) == 1
            blur_b1, blur_id1 = opened_calls[0]
            assert blur_id1 == "img:shot-1_blurred"
            assert blur_b1.startswith(b"\x89PNG\r\n\x1a\n")
            assert blur_b1 != png_1
            assert any(sid == "img:shot-2_blurred" and b != png_2 for b, sid in staged_calls)

            # Pressing 'v' also opens blurred copy directly in OS viewer
            await pilot.press("v")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert not isinstance(app.screen, ScreenshotViewerModal)
            assert len(opened_calls) == 2

            # Toggle back to TUI via RF Intel button inside / drawer, then verify 'o' opens OS viewer
            await pilot.press("slash")
            await pilot.pause()
            await pilot.click("#rf-os-viewer-default-btn")
            await pilot.pause()
            assert app.open_images_in_os_viewer is False
            assert load_tui_settings(tmp_path).get("image_viewer") == "tui"
            assert "Images (2)" in str(images_btn.label)
            assert "(OS)" not in str(images_btn.label)

            # Pressing 'v' now opens TUI ScreenshotViewerModal; pressing 'o' inside opens OS viewer
            await pilot.press("v")
            await pilot.pause()
            assert isinstance(app.screen, ScreenshotViewerModal)

            # Toggle OS default ON from inside modal button
            await pilot.click("#shot-os-default-btn")
            await pilot.pause()
            assert app.open_images_in_os_viewer is True
            assert "OS Default: ON" in str(
                app.screen.query_one("#shot-os-default-btn", Button).label
            )

            # Right-click inside ScreenshotViewerModal -> toggle OS default OFF and back ON
            await pilot.click("#shot-viewer-canvas", offset=(6, 4), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "toggle_os_default")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ScreenshotViewerModal)
            assert app.open_images_in_os_viewer is False
            assert "OS Default: OFF" in str(
                app.screen.query_one("#shot-os-default-btn", Button).label
            )

            await pilot.click("#shot-os-default-btn")
            await pilot.pause()
            assert app.open_images_in_os_viewer is True

            # Close modal, then test 'o' blurred and 'b' -> 'o' unblurred on RF Intel
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, ScreenshotViewerModal)

            await pilot.press("o")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert len(opened_calls) == 3
            assert opened_calls[2][1] == "img:shot-1_blurred"

            await pilot.press("b")
            await pilot.pause()
            assert app.blur_images is False
            assert "Blur: OFF" in str(app.query_one("#rf-blur-images-btn", Button).label)

            await pilot.press("o")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert opened_calls[3] == (png_1, "img:shot-1")

    asyncio.run(_run())

    # Fresh app instance reloads persisted "os" setting automatically
    reloaded_app = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
    assert reloaded_app.open_images_in_os_viewer is True


# ------------------------------------------------------------------
# 5. Right-Click Open on Right Side (Details Pane & Inline Images)
# ------------------------------------------------------------------


def test_tui_right_click_on_right_details_pane_and_inline_images(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import soclens.tui.screens.rf_intel as rf_intel_mod

    monkeypatch.delenv("SOCLENS_IMAGE_VIEWER", raising=False)
    monkeypatch.delenv("RF_TUI_OPEN_IMAGES_IN_OS_VIEWER", raising=False)

    png_1 = _make_png(48, 32, rgb=(220, 40, 40))
    png_2 = _make_png(48, 32, rgb=(40, 80, 220))
    opened_calls: list[tuple[bytes, str]] = []

    def _fake_open(raw_bytes: bytes, *, image_id: str) -> Path:
        opened_calls.append((raw_bytes, image_id))
        return tmp_path / f"{image_id}.png"

    monkeypatch.setattr(rf_intel_mod, "open_image_in_native_viewer", _fake_open)
    monkeypatch.setattr(rf_intel_mod, "stage_screenshot_file", lambda b, *, image_id: tmp_path / f"{image_id}.png")

    mock_client = _make_playbook_client(png_1, png_2)
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
            await pilot.click("#rf-fetch-detail-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            log_widget = app.query_one("#rf-log", RichLog)

            # 1) Right-click directly on Screenshot 2/2 inside #rf-log
            shot2_line = _find_richlog_line(log_widget, "Screenshot 2/2")
            log_widget.scroll_to(y=max(0, shot2_line - 2), animate=False)
            await pilot.pause()
            scr_reg = log_widget.scrollable_content_region
            shot2_screen_y = scr_reg.y + (shot2_line - int(round(log_widget.scroll_y))) + 1
            await pilot.click(offset=(scr_reg.x + 8, shot2_screen_y), button=3)
            await pilot.pause()

            assert isinstance(app.screen, ContextMenuModal)
            opts = app.screen.query_one("#ctx-menu-options", OptionList)
            first_option = opts.get_option_at_index(0)
            assert first_option.id == "open_screenshot"
            assert "2/2" in str(first_option.prompt)

            # Selecting open_screenshot opens blurred copy of png_2 while blur is ON
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert len(opened_calls) == 1
            assert opened_calls[0][1] == "img:shot-2_blurred"
            assert opened_calls[0][0] != png_2
            assert opened_calls[0][0].startswith(b"\x89PNG\r\n\x1a\n")

            # Right-click Screenshot 2/2 -> Open Unblurred Screenshot opens exact unmodified png_2
            await pilot.click(offset=(scr_reg.x + 8, shot2_screen_y), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "open_screenshot_unblurred")
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert opened_calls[1] == (png_2, "img:shot-2")

            # 2) Right-click Screenshot 2/2 -> View Screenshot 2/2 in TUI Modal opens at index 1 (2 of 2)
            await pilot.click(offset=(scr_reg.x + 8, shot2_screen_y), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "view_screenshots")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ScreenshotViewerModal)
            assert "Screenshot 2 of 2" in str(
                app.screen.query_one("#shot-viewer-header", Static).render()
            )
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, ScreenshotViewerModal)

            # 3) Right-click Screenshot 2/2 -> Save Screenshot 2/2 PNG ALWAYS saves exact unmodified png_2
            await pilot.click(offset=(scr_reg.x + 8, shot2_screen_y), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "save_screenshot")
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            saved_files = list((tmp_path / "screenshots").glob("*.png"))
            assert len(saved_files) == 1
            assert saved_files[0].read_bytes() == png_2

            # 4) Right-click on general details text (outside screenshot panels) opens item menu (NOT pane menu)
            detail_line = _find_richlog_line(log_widget, "Playbook ID")
            log_widget.scroll_to(y=max(0, detail_line), animate=False)
            await pilot.pause()
            scr_reg = log_widget.scrollable_content_region
            detail_screen_y = scr_reg.y + (detail_line - int(round(log_widget.scroll_y)))
            await pilot.click(offset=(scr_reg.x + 8, detail_screen_y), button=3)
            await pilot.pause()

            assert isinstance(app.screen, ContextMenuModal)
            menu_title = str(app.screen.query_one("#ctx-menu-title", Static).render())
            assert "RF Intel Actions" not in menu_title
            opts = app.screen.query_one("#ctx-menu-options", OptionList)
            assert opts.get_option_at_index(0).id == "open_screenshot"
            assert "2/2" not in str(opts.get_option_at_index(0).prompt)

            # Choose Open All Screenshots (2) while blur ON -> blurred copies
            _select_context_option_by_id(app, "open_all_screenshots")
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert [cid for _, cid in opened_calls[2:4]] == [
                "img:shot-1_blurred",
                "img:shot-2_blurred",
            ]

            # Toggle blur OFF via context menu -> Open All Screenshots now sends exact unmodified bytes
            await pilot.click(offset=(scr_reg.x + 8, detail_screen_y), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            _select_context_option_by_id(app, "toggle_image_blur")
            await pilot.press("enter")
            await pilot.pause()
            assert app.blur_images is False

            await pilot.click(offset=(scr_reg.x + 8, detail_screen_y), button=3)
            await pilot.pause()
            _select_context_option_by_id(app, "open_all_screenshots")
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert opened_calls[4:] == [(png_1, "img:shot-1"), (png_2, "img:shot-2")]

    asyncio.run(_run())


def test_tui_right_click_details_pane_for_non_playbook_alert(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_client.search_alerts_v3.return_value = {
        "data": [
            {
                "id": "alert-v3-1",
                "title": "Suspicious IP Beacon",
                "priority": "High",
                "status": "New",
                "rule": {"name": "C2 Watch"},
                "hits_count": 3,
                "triggered": "2026-11-24T12:00:00Z",
            }
        ],
        "counts": {"returned": 1, "total": 1},
    }

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 44)) as pilot:
            await pilot.pause()
            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            log_widget = app.query_one("#rf-log", RichLog)
            scr_reg = log_widget.scrollable_content_region
            await pilot.click(offset=(scr_reg.x + 8, scr_reg.y + 1), button=3)
            await pilot.pause()

            assert isinstance(app.screen, ContextMenuModal)
            menu_title = str(app.screen.query_one("#ctx-menu-title", Static).render())
            assert "Suspicious IP Beacon" in menu_title
            opts = app.screen.query_one("#ctx-menu-options", OptionList)
            option_ids = [opts.get_option_at_index(i).id for i in range(opts.option_count)]
            assert "deep_detail" in option_ids
            assert "triage" in option_ids

    asyncio.run(_run())


# ------------------------------------------------------------------
# 6. Kitty HD Env-Leak Guards, Live Probe Parser, Truecolor & Fallbacks
# ------------------------------------------------------------------


def test_kitty_env_leak_and_unsupported_terminal_guards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leaked_ghostty = {
        "GHOSTTY_RESOURCES_DIR": "/Applications/Ghostty.app/Contents/Resources/ghostty",
        "TERM": "xterm-ghostty",
    }
    leaked_kitty = {
        "KITTY_WINDOW_ID": "1",
        "TERM": "xterm-kitty",
    }

    non_pixel_overlays: list[dict[str, str]] = [
        {"TERM_PROGRAM": "vscode"},
        {"VSCODE_PID": "1234"},
        {"VSCODE_INJECTION": "1"},
        {"CURSOR_TRACE_ID": "trace-1"},
        {"TERM_PROGRAM": "Apple_Terminal"},
        {"ALACRITTY_SOCKET": "/tmp/alacritty.sock"},
        {"GNOME_TERMINAL_SCREEN": "/org/gnome/Terminal/screen/1"},
        {"VTE_VERSION": "7600"},
        {"WARP_IS_LOCAL_SHELL_SESSION": "1"},
        {"TERMINAL_EMULATOR": "JetBrains-JediTerm"},
        {"ZELLIJ": "0"},
        {"TMUX": "/tmp/tmux-1000/default,1,0"},
        {"STY": "1234.pts-0.host"},
        {"NO_COLOR": "1"},
        {"TERM": "dumb"},
        {"TERM": "st-256color"},
    ]
    iterm2_overlays: list[dict[str, str]] = [
        {"TERM_PROGRAM": "iTerm.app"},
        {"ITERM_SESSION_ID": "w0t0p0:1"},
        {"TERM_PROGRAM": "WezTerm"},
        {"WEZTERM_PANE": "0"},
        {"WEZTERM_EXECUTABLE": "/usr/bin/wezterm"},
    ]
    sixel_overlays: list[dict[str, str]] = [
        {"KONSOLE_VERSION": "240502"},
        {"TERM": "foot"},
    ]

    for base in (leaked_ghostty, leaked_kitty):
        for overlay in non_pixel_overlays:
            env = {**base, **overlay}
            assert (
                detect_terminal_graphics_protocol(env, is_headless=False, platform_name="darwin")
                == "halfblock"
            ), f"Expected halfblock for {env!r}"
        for overlay in iterm2_overlays:
            env = {**base, **overlay}
            assert (
                detect_terminal_graphics_protocol(env, is_headless=False, platform_name="darwin")
                == "iterm2"
            ), f"Expected iterm2 for {env!r}"
        for overlay in sixel_overlays:
            env = {**base, **overlay}
            assert (
                detect_terminal_graphics_protocol(env, is_headless=False, platform_name="darwin")
                == "sixel"
            ), f"Expected sixel for {env!r}"

    assert is_multiplexer_session({"ZELLIJ": "0"}) is True
    assert is_no_color_environment({"NO_COLOR": ""}) is True

    # Persisted setting rf_tui_image_protocol="halfblock" forces halfblock
    monkeypatch.setenv("KITTY_WINDOW_ID", "1")
    monkeypatch.delenv("RF_TUI_IMAGE_PROTOCOL", raising=False)
    monkeypatch.setattr("soclens.tui.image_render.get_tui_image_protocol", lambda: "halfblock")
    assert detect_terminal_graphics_protocol(is_headless=False) == "halfblock"


def test_kitty_live_probe_response_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    ssh_env = {"TERM": "xterm-256color"}

    # Genuine Kitty / Ghostty over SSH
    assert (
        parse_terminal_graphics_probe(
            b"\x1b_Gi=31;OK\x1b\\\x1bP>|kitty(0.36.4)\x1b\\\x1b[?62;c",
            env=ssh_env,
        )
        == "kitty"
    )
    assert (
        parse_terminal_graphics_probe(
            b"\x1b_Gi=31;OK\x1b\\\x1bP>|ghostty 1.4.0\x1b\\\x1b[?62;22c",
            env=ssh_env,
        )
        == "kitty"
    )

    # Terminals that speak iTerm2 OSC 1337
    assert (
        parse_terminal_graphics_probe(
            b"\x1b_Gi=31;OK\x1b\\\x1bP>|WezTerm 20240203-110809\x1b\\\x1b[?65;c",
            env={"TERM": "xterm-256color", "KITTY_WINDOW_ID": "1"},
        )
        == "iterm2"
    )
    assert (
        parse_terminal_graphics_probe(
            b"\x1b_Gi=31;OK\x1b\\\x1bP>|iTerm2 3.5.0\x1b\\\x1b[?62;c",
            env=ssh_env,
        )
        == "iterm2"
    )
    assert parse_terminal_graphics_probe(b"\x1bP>|mintty 3.7.1\x1b\\\x1b[?62;4c", env=ssh_env) == "iterm2"

    # VS Code with image support enabled (DA1 ;4;) vs disabled
    assert (
        parse_terminal_graphics_probe(
            b"\x1bP>|vscode 1.96.0\x1b\\\x1b[?62;4c",
            env=ssh_env,
        )
        == "iterm2"
    )
    assert (
        parse_terminal_graphics_probe(
            b"\x1bP>|vscode 1.96.0\x1b\\\x1b[?62;c",
            env=ssh_env,
        )
        == "halfblock"
    )

    # Konsole / XTerm VT340 / Windows Terminal over SSH reporting DA1 ;4; -> sixel
    assert (
        parse_terminal_graphics_probe(
            b"\x1b_Gi=31;OK\x1b\\\x1bP>|Konsole 24.05.2\x1b\\\x1b[?62;4;22c",
            env=ssh_env,
        )
        == "sixel"
    )
    assert parse_terminal_graphics_probe(b"\x1b[?61;4c", env=ssh_env) == "sixel"

    # tmux / non-pixel terminals without ;4; -> halfblock
    assert (
        parse_terminal_graphics_probe(
            b"\x1b_Gi=31;OK\x1b\\\x1bP>|tmux 3.4\x1b\\\x1b[?62;c",
            env=ssh_env,
        )
        == "halfblock"
    )
    assert parse_terminal_graphics_probe(b"\x1b[?1;2c", env=ssh_env) == "halfblock"
    assert parse_terminal_graphics_probe(b"", env={"TERM": "xterm-ghostty"}) == "halfblock"

    # probe_result overrides env heuristics cleanly
    assert detect_terminal_graphics_protocol(ssh_env, is_headless=False, probe_result="kitty") == "kitty"
    assert detect_terminal_graphics_protocol(ssh_env, is_headless=False, probe_result="sixel") == "sixel"
    assert detect_terminal_graphics_protocol(ssh_env, is_headless=False, probe_result="iterm2") == "iterm2"
    assert (
        detect_terminal_graphics_protocol(
            {"GHOSTTY_RESOURCES_DIR": "/usr/share/ghostty"},
            is_headless=False,
            probe_result="halfblock",
        )
        == "halfblock"
    )

    for key in (
        "RF_TUI_IMAGE_PROTOCOL",
        "NO_COLOR",
        "TMUX",
        "STY",
        "ZELLIJ",
        "TERM_PROGRAM",
        "VSCODE_PID",
        "KITTY_WINDOW_ID",
        "GHOSTTY_RESOURCES_DIR",
        "WT_SESSION",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr("soclens.tui.image_render.get_tui_image_protocol", lambda: "")

    try:
        set_terminal_probe_result("kitty")
        assert detect_terminal_graphics_protocol(is_headless=False) == "kitty"
        assert detect_terminal_graphics_protocol({"TERM": "xterm-256color"}, is_headless=False) == "halfblock"
    finally:
        reset_terminal_probe_cache()


def test_kitty_truecolor_enforcement_and_app_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StubApp:
        def __init__(self, *, no_color: bool, color_system: Any) -> None:
            self.no_color = no_color
            self.console = MagicMock()
            self.console._color_system = color_system

    assert can_emit_kitty_truecolor(_StubApp(no_color=False, color_system=ColorSystem.TRUECOLOR)) is True
    assert can_emit_kitty_truecolor(_StubApp(no_color=False, color_system=ColorSystem.EIGHT_BIT)) is False
    assert can_emit_kitty_truecolor(_StubApp(no_color=False, color_system=ColorSystem.STANDARD)) is False
    assert can_emit_kitty_truecolor(_StubApp(no_color=False, color_system=None)) is False
    assert can_emit_kitty_truecolor(_StubApp(no_color=True, color_system=ColorSystem.TRUECOLOR)) is False
    assert can_emit_kitty_truecolor(env={"NO_COLOR": "1"}) is False

    assert is_truecolor_kitty_env({"TERM": "xterm-ghostty"}) is True
    assert is_truecolor_kitty_env({"TERM": "xterm-kitty"}) is True
    assert is_truecolor_kitty_env({"TERM": "xterm-ghostty", "NO_COLOR": "1"}) is False
    assert is_truecolor_kitty_env({"TERM": "xterm-ghostty", "TERM_PROGRAM": "vscode"}) is False

    # SocLensApp.__init__ upgrades Rich's downgraded color system for Ghostty & Kitty
    for term_val in ("xterm-ghostty", "xterm-kitty"):
        monkeypatch.setenv("TERM", term_val)
        monkeypatch.delenv("COLORTERM", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM_PROGRAM", raising=False)
        monkeypatch.delenv("VSCODE_PID", raising=False)
        monkeypatch.delenv("TMUX", raising=False)
        app = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
        assert app.console._color_system == ColorSystem.TRUECOLOR

    # NO_COLOR=1 must prevent truecolor upgrade
    monkeypatch.setenv("TERM", "xterm-ghostty")
    monkeypatch.setenv("NO_COLOR", "1")
    app_nc = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
    assert app_nc.no_color is True
    assert app_nc.console._color_system != ColorSystem.TRUECOLOR


def test_screenshot_modal_kitty_fallback_aspect_and_notice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import base64
    import re

    import soclens.tui.modals as modals_mod

    wide_png = _make_png(400, 100)
    shots = [{"image_id": "img:wide", "meta": {}, "raw_bytes": wide_png}]

    # 1) When write_terminal_graphics returns False, Kitty modal MUST fall back to Halfblock with zero U+10EEEE
    monkeypatch.setattr(modals_mod, "detect_terminal_graphics_protocol", lambda *a, **k: "kitty")
    monkeypatch.setattr(modals_mod, "write_terminal_graphics", lambda *a, **k: False)
    app_fail = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
    app_fail.console._color_system = ColorSystem.TRUECOLOR

    async def _run_fallback() -> None:
        async with app_fail.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            modal = ScreenshotViewerModal(title="fallback.test", screenshots=shots, dry_run=True)
            app_fail.push_screen(modal)
            await pilot.pause(0.25)

            canvas = modal.query_one("#shot-viewer-canvas", RichLog)
            meta_bar = modal.query_one("#shot-viewer-meta", Static)
            assert "Mode: Halfblock" in str(meta_bar.render())
            assert "\U0010eeee" not in "".join(strip.text for strip in canvas.lines)

    asyncio.run(_run_fallback())

    # 2) Kitty auto-mode uploads blurred PNG first, uses aspect-preserving grid, and uploads raw PNG on unblur
    captured_grid: list[tuple[int, int]] = []
    captured_uploads: list[bytes] = []
    captured_seqs: list[str] = []

    def _capture_build(
        png_bytes: bytes,
        *,
        image_id: int,
        cols: int,
        rows: int,
        tmux_passthrough: bool = False,
    ) -> str:
        from soclens.tui.image_render import build_kitty_upload_sequence

        captured_grid.append((cols, rows))
        captured_uploads.append(png_bytes)
        seq = build_kitty_upload_sequence(
            png_bytes,
            image_id=image_id,
            cols=cols,
            rows=rows,
            tmux_passthrough=tmux_passthrough,
        )
        captured_seqs.append(seq)
        return seq

    monkeypatch.setattr(modals_mod, "build_kitty_upload_sequence", _capture_build)
    monkeypatch.setattr(modals_mod, "write_terminal_graphics", lambda *a, **k: True)
    monkeypatch.setattr(modals_mod, "get_terminal_cell_aspect", lambda default=0.5: 0.5)

    app_ok = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)
    app_ok.console._color_system = ColorSystem.TRUECOLOR

    async def _run_aspect() -> None:
        async with app_ok.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            modal = ScreenshotViewerModal(title="aspect.test", screenshots=shots, dry_run=True)
            app_ok.push_screen(modal)
            await pilot.pause(0.25)

            canvas = modal.query_one("#shot-viewer-canvas", RichLog)
            avail_w = canvas.scrollable_content_region.width
            avail_h = canvas.scrollable_content_region.height
            expected_cols, expected_rows = compute_terminal_cell_grid(
                400,
                100,
                max_cols=max(4, min(255, avail_w - 2)),
                max_rows=max(4, min(255, avail_h)),
                cell_aspect=0.5,
            )

            assert captured_grid[0] == (expected_cols, expected_rows)
            assert expected_rows < avail_h
            assert captured_uploads[0] != wide_png
            assert captured_uploads[0].startswith(b"\x89PNG\r\n\x1a\n")
            assert any(";\\x1b\\" in s.replace("\x1b", "\\x1b") for s in captured_seqs)
            assert "\U0010eeee" in "".join(strip.text for strip in canvas.lines)

            # Unblur uploads exact original bytes in the same cell geometry (zero grid jitter)
            await pilot.press("b")
            await pilot.pause(0.25)
            assert captured_grid[-1] == (expected_cols, expected_rows)
            assert captured_uploads[-1] == wide_png

    asyncio.run(_run_aspect())

    # 3) Sixel & iTerm2 overlay dispatch and fallback on write failure
    for proto, pattern in (
        ("sixel", r"^\x1b7\x1b\[\d+;\d+H\x1bP0;1q.*\x1b\\\x1b8$"),
        ("iterm2", r"^\x1b7\x1b\[\d+;\d+H\x1b\]1337;File=inline=1;size=\d+.*\x07\x1b8$"),
    ):
        monkeypatch.setattr(modals_mod, "detect_terminal_graphics_protocol", lambda *a, p=proto, **k: p)
        emitted: list[str] = []
        monkeypatch.setattr(modals_mod, "write_terminal_graphics", lambda app, seq, buf=emitted: buf.append(seq) or True)
        app_ov = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)

        async def _run_overlay(expected_proto: str = proto, regex: str = pattern) -> None:
            async with app_ov.run_test(size=(120, 36)) as pilot:
                await pilot.pause()
                modal = ScreenshotViewerModal(title="overlay.test", screenshots=shots, dry_run=True)
                app_ov.push_screen(modal)
                await pilot.pause()
                expected_label = "Sixel HD" if expected_proto == "sixel" else "iTerm2 HD"
                meta_bar = modal.query_one("#shot-viewer-meta", Static)
                for _ in range(60):
                    if f"Mode: {expected_label}" in str(meta_bar.render()):
                        break
                    await pilot.pause(0.05)

                assert f"Mode: {expected_label}" in str(meta_bar.render())
                assert emitted
                assert re.search(regex, emitted[-1], re.DOTALL)
                if expected_proto == "iterm2":
                    assert base64.b64encode(wide_png).decode("ascii") not in emitted[-1]

        asyncio.run(_run_overlay())

        monkeypatch.setattr(modals_mod, "write_terminal_graphics", lambda *a, **k: False)
        app_ov_fail = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)

        async def _run_overlay_fail() -> None:
            async with app_ov_fail.run_test(size=(120, 36)) as pilot:
                await pilot.pause()
                modal = ScreenshotViewerModal(title="overlayfail.test", screenshots=shots, dry_run=True)
                app_ov_fail.push_screen(modal)
                await pilot.pause()
                meta_bar = modal.query_one("#shot-viewer-meta", Static)
                for _ in range(60):
                    if "Mode: Halfblock" in str(meta_bar.render()):
                        break
                    await pilot.pause(0.05)
                assert "Mode: Halfblock" in str(meta_bar.render())

        asyncio.run(_run_overlay_fail())


def test_rf_intel_inline_kitty_safety_and_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import soclens.tui.screens.rf_intel as rf_intel_mod
    from soclens.tui.screens.rf_intel import RFIntelPane

    png_bytes = _make_png(320, 160)
    decoded = decode_image(png_bytes)

    # 1) Non-truecolor console blocks inline Kitty upload completely
    write_calls: list[str] = []
    monkeypatch.setattr(rf_intel_mod, "detect_terminal_graphics_protocol", lambda *a, **k: "kitty")
    monkeypatch.setattr(
        rf_intel_mod,
        "write_terminal_graphics",
        lambda app, seq: write_calls.append(seq) or True,
    )

    app_8bit = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )
    app_8bit.console._color_system = ColorSystem.EIGHT_BIT

    async def _run_8bit() -> None:
        async with app_8bit.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app_8bit.query_one(RFIntelPane)
            pane._image_cache[("domain_abuse", "pb-1", "img:1")] = {
                "bytes": png_bytes,
                "decoded": decoded,
            }
            sc_map = pane._prepare_inline_screenshots("domain_abuse", "pb-1", ["img:1"], 80)
            assert "kitty_placeholder" not in sc_map["img:1"]
            assert write_calls == []

    asyncio.run(_run_8bit())

    # 2) Truecolor + failed write falls back cleanly without kitty_placeholder
    monkeypatch.setattr(rf_intel_mod, "write_terminal_graphics", lambda app, seq: False)
    app_ok = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )
    app_ok.console._color_system = ColorSystem.TRUECOLOR

    async def _run_fail_write() -> None:
        async with app_ok.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app_ok.query_one(RFIntelPane)
            pane._image_cache[("domain_abuse", "pb-2", "img:2")] = {
                "bytes": png_bytes,
                "decoded": decoded,
            }
            sc_map = pane._prepare_inline_screenshots("domain_abuse", "pb-2", ["img:2"], 22)
            assert "kitty_placeholder" not in sc_map["img:2"]

    asyncio.run(_run_fail_write())

    # 3) Truecolor + successful write clamps narrow panel width and renders placeholder panel
    monkeypatch.setattr(rf_intel_mod, "write_terminal_graphics", lambda app, seq: True)
    monkeypatch.setattr(rf_intel_mod, "get_terminal_cell_aspect", lambda default=0.5: 0.5)

    async def _run_ok() -> None:
        async with app_ok.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app_ok.query_one(RFIntelPane)
            pane._image_cache[("domain_abuse", "pb-3", "img:3")] = {
                "bytes": png_bytes,
                "decoded": decoded,
            }
            sc_map = pane._prepare_inline_screenshots("domain_abuse", "pb-3", ["img:3"], 22)
            kid, cols, rows = sc_map["img:3"]["kitty_placeholder"]
            assert kid >= 0x524601
            assert cols <= 16  # 22 - 6 = 16 (never forced >= 20!)
            assert rows >= 2
            panel = render_screenshot_panel(
                image_id="img:3",
                render_width=22,
                decoded=decoded,
                kitty_placeholder=(kid, cols, rows),
            )
            assert panel.title is not None
            assert panel.subtitle is not None
            assert "Blurred ([b] to reveal)" in panel.subtitle.plain

    asyncio.run(_run_ok())


# ------------------------------------------------------------------
# 7. Sixel/iTerm2 Encoders, Privacy Blur, & Smart OS Viewer Default
# ------------------------------------------------------------------


def test_sixel_and_iterm2_pure_python_encoders() -> None:
    png_bytes = _make_png(48, 36, rgb=(210, 90, 40))
    img = decode_image(png_bytes)

    sixel = encode_sixel(img, max_width=48, max_height=36)
    assert sixel.startswith("\x1bP0;1q")
    assert sixel.endswith("\x1b\\")
    assert '"1;1;48;36' in sixel

    ov_sixel = build_sixel_overlay_sequence(sixel, row=4, col=7)
    assert ov_sixel.startswith("\x1b7\x1b[4;7H\x1bP0;1q")
    assert ov_sixel.endswith("\x1b\\\x1b8")

    tmux_sixel = build_sixel_overlay_sequence(sixel, row=2, col=3, tmux_passthrough=True)
    assert tmux_sixel.startswith("\x1b7\x1b[2;3H\x1bPtmux;\x1b\x1bP0;1q")
    assert tmux_sixel.endswith("\x1b8")

    ov_iterm = build_iterm2_overlay_sequence(png_bytes, row=5, col=8, cols=20, rows=8)
    assert ov_iterm.startswith("\x1b7\x1b[5;8H\x1b]1337;File=inline=1;")
    assert ";width=20;height=8;preserveAspectRatio=1:" in ov_iterm
    assert ov_iterm.endswith("\x07\x1b8")

    tmux_iterm = build_iterm2_overlay_sequence(
        png_bytes, row=1, col=1, cols=10, rows=4, tmux_passthrough=True
    )
    assert "\x1bPtmux;\x1b\x1b]1337;File=" in tmux_iterm

    with pytest.raises(ValueError, match="Invalid Sixel"):
        build_sixel_overlay_sequence("bad", row=1, col=1)
    with pytest.raises(ValueError, match="valid PNG"):
        build_iterm2_overlay_sequence(b"bad", row=1, col=1, cols=2, rows=2)


def _make_checkerboard_png(width: int = 80, height: int = 80) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        for x in range(width):
            val = 250 if ((x // 4 + y // 4) % 2 == 0) else 10
            raw.extend((val, val, val))
    idat = zlib.compress(bytes(raw))

    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I4s", len(data), ctype) + data + struct.pack(">I", crc)

    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )


def test_blur_reduces_high_frequency_contrast_and_preserves_png() -> None:
    raw_png = _make_checkerboard_png(80, 60)
    orig = decode_image(raw_png)

    blurred_img = blur_decoded_image(orig)
    assert (blurred_img.width, blurred_img.height) == (80, 60)

    def _adjacent_delta_sum(img_obj: Any) -> int:
        total = 0
        for row in img_obj.rgb_rows:
            for col_idx in range(img_obj.width - 1):
                p = col_idx * 3
                total += abs(row[p] - row[p + 3])
        return total

    assert _adjacent_delta_sum(blurred_img) < _adjacent_delta_sum(orig) * 0.25

    blurred_png = blur_image_bytes(raw_png)
    assert blurred_png.startswith(b"\x89PNG\r\n\x1a\n")
    assert blurred_png != raw_png
    redecoded = decode_image(blurred_png)
    assert (redecoded.width, redecoded.height) == (80, 60)


def test_smart_os_viewer_default_on_non_pixel_terminals_and_explicit_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOCLENS_IMAGE_VIEWER", raising=False)
    monkeypatch.delenv("RF_TUI_OPEN_IMAGES_IN_OS_VIEWER", raising=False)
    monkeypatch.delenv("RF_TUI_IMAGE_PROTOCOL", raising=False)
    for var in (
        "KITTY_WINDOW_ID",
        "GHOSTTY_RESOURCES_DIR",
        "ITERM_SESSION_ID",
        "WEZTERM_PANE",
        "WEZTERM_EXECUTABLE",
        "WT_SESSION",
        "WT_PROFILE_ID",
        "KONSOLE_VERSION",
        "KONSOLE_DBUS_SESSION",
        "TMUX",
        "STY",
        "ZELLIJ",
        "NO_COLOR",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr("soclens.tui.image_render.get_tui_image_protocol", lambda: "")
    reset_terminal_probe_cache()

    # 1) Non-headless Apple Terminal with no explicit preference defaults to OS Viewer
    monkeypatch.setenv("TERM_PROGRAM", "Apple_Terminal")
    app_os = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)

    async def _run_os_default() -> None:
        async with app_os.run_test(size=(120, 36)) as pilot:
            monkeypatch.setattr(type(app_os), "is_headless", property(lambda self: False))
            app_os.on_mount()
            await pilot.pause()
            assert app_os.open_images_in_os_viewer is True

    asyncio.run(_run_os_default())

    # 2) Explicit "tui" preference overrides smart OS default
    ws_explicit = tmp_path / "explicit_tui"
    ws_explicit.mkdir()
    save_tui_settings({"image_viewer": IMAGE_VIEWER_TUI}, ws_explicit)
    app_tui = create_app(client=MagicMock(), dry_run=True, workspace_dir=ws_explicit)

    async def _run_explicit_tui() -> None:
        async with app_tui.run_test(size=(120, 36)) as pilot:
            monkeypatch.setattr(type(app_tui), "is_headless", property(lambda self: False))
            app_tui.on_mount()
            await pilot.pause()
            assert app_tui.open_images_in_os_viewer is False

    asyncio.run(_run_explicit_tui())

    # 3) Pixel-capable terminal (Windows Terminal Sixel / Kitty / iTerm2) keeps TUI modal default
    ws_pixel = tmp_path / "pixel_term"
    ws_pixel.mkdir()
    monkeypatch.delenv("TERM_PROGRAM", raising=False)
    monkeypatch.setenv("WT_SESSION", "wt-session-1")
    app_pixel = create_app(client=MagicMock(), dry_run=True, workspace_dir=ws_pixel)

    async def _run_pixel() -> None:
        async with app_pixel.run_test(size=(120, 36)) as pilot:
            monkeypatch.setattr(type(app_pixel), "is_headless", property(lambda self: False))
            app_pixel.on_mount()
            await pilot.pause()
            assert app_pixel.open_images_in_os_viewer is False

    asyncio.run(_run_pixel())


def test_rf_intel_inline_blur_toggle_and_kitty_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import soclens.tui.screens.rf_intel as rf_intel_mod
    from soclens.tui.screens.rf_intel import RFIntelPane

    png_bytes = _make_checkerboard_png(80, 60)
    decoded = decode_image(png_bytes)
    uploaded: list[bytes] = []

    monkeypatch.setattr(rf_intel_mod, "detect_terminal_graphics_protocol", lambda *a, **k: "kitty")
    monkeypatch.setattr(rf_intel_mod, "write_terminal_graphics", lambda *a, **k: True)

    def _cap_build(
        data: bytes,
        *,
        image_id: int,
        cols: int,
        rows: int,
        tmux_passthrough: bool = False,
    ) -> str:
        from soclens.tui.image_render import build_kitty_upload_sequence

        uploaded.append(data)
        return build_kitty_upload_sequence(
            data, image_id=image_id, cols=cols, rows=rows, tmux_passthrough=tmux_passthrough
        )

    monkeypatch.setattr(rf_intel_mod, "build_kitty_upload_sequence", _cap_build)

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )
    app.console._color_system = ColorSystem.TRUECOLOR

    async def _run() -> None:
        async with app.run_test(size=(130, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(RFIntelPane)
            blur_btn = pane.query_one("#rf-blur-images-btn", Button)
            assert app.blur_images is True
            assert "Blur: ON" in str(blur_btn.label)

            pane._image_cache[("domain_abuse", "pb-blur", "img:b1")] = {
                "bytes": png_bytes,
                "decoded": decoded,
            }
            sc_blurred = pane._prepare_inline_screenshots("domain_abuse", "pb-blur", ["img:b1"], 80)
            assert sc_blurred["img:b1"]["blurred"] is True
            assert len(uploaded) == 1
            assert uploaded[0] != png_bytes

            await pilot.click("#rf-blur-images-btn")
            await pilot.pause()
            assert app.blur_images is False
            assert "Blur: OFF" in str(blur_btn.label)

            sc_unblurred = pane._prepare_inline_screenshots("domain_abuse", "pb-blur", ["img:b1"], 80)
            assert sc_unblurred["img:b1"]["blurred"] is False
            assert len(uploaded) == 2
            # If cropped, it may re-encode, otherwise exact original bytes; never equal to blurred bytes
            assert uploaded[1] != uploaded[0]

    asyncio.run(_run())
