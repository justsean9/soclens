"""Launcher fallback, static offline asset, and path-traversal tests for SOCLens Web."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import pytest

import soclens.web.launcher as launcher_mod
from soclens.web import create_app, launch_app_window, run_web_server
from tests.test_web_server import _call_asgi

STATIC_DIR = Path(__file__).resolve().parent.parent / "soclens" / "web" / "static"


def test_launch_app_window_prefers_edge_then_chrome_then_browser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Any] = []

    class _FakeProc:
        pass

    monkeypatch.setattr(
        launcher_mod.shutil,
        "which",
        lambda name: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
        if name == "msedge.exe"
        else None,
    )
    monkeypatch.setattr(
        launcher_mod.subprocess,
        "Popen",
        lambda cmd, **_kw: calls.append(("popen", cmd)) or _FakeProc(),
    )
    monkeypatch.setattr(
        launcher_mod.webbrowser,
        "open",
        lambda url: calls.append(("webbrowser", url)) or True,
    )

    url = "http://127.0.0.1:8765/#token=abc"
    assert launch_app_window(url) is True
    assert calls[0][0] == "popen"
    assert f"--app={url}" in calls[0][1]

    # Fallback to Chrome when Edge missing
    calls.clear()
    monkeypatch.setattr(
        launcher_mod.shutil,
        "which",
        lambda name: "/usr/bin/google-chrome" if name == "google-chrome" else None,
    )
    monkeypatch.setattr(launcher_mod, "_find_edge_executable", lambda: None)
    assert launch_app_window(url) is True
    assert calls[0][0] == "popen"
    assert calls[0][1][0] == "/usr/bin/google-chrome"
    assert f"--app={url}" in calls[0][1]

    # Fallback to webbrowser.open if Popen raises OSError
    calls.clear()

    def _raise_oserror(*_args: Any, **_kw: Any) -> Any:
        raise OSError("spawn blocked")

    monkeypatch.setattr(launcher_mod.subprocess, "Popen", _raise_oserror)
    assert launch_app_window(url) is True
    assert calls == [("webbrowser", url)]


def test_run_web_server_validates_port_and_host() -> None:
    for bad_port in (-1, 65536, True):
        with pytest.raises(ValueError):
            run_web_server(port=bad_port, open_browser=False)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        run_web_server(port=0, host="0.0.0.0", open_browser=False)


def test_static_assets_are_100_percent_offline_and_secret_free(tmp_path: Path) -> None:
    assert (STATIC_DIR / "index.html").is_file()
    assert (STATIC_DIR / "styles.css").is_file()
    assert (STATIC_DIR / "api.js").is_file()
    assert (STATIC_DIR / "tiling.js").is_file()
    assert (STATIC_DIR / "tiles.js").is_file()
    assert (STATIC_DIR / "app.js").is_file()
    assert not (STATIC_DIR / ".gitkeep").exists()

    external_url_re = re.compile(r"(?:https?|wss?)://", re.IGNORECASE)
    storage_secret_re = re.compile(
        r"(?:localStorage|sessionStorage)\.setItem\([^)]*(?:token|secret|password|api_key|vault)",
        re.IGNORECASE,
    )

    combined_js = ""
    combined_css = ""
    for file_path in sorted(STATIC_DIR.rglob("*")):
        if not file_path.is_file():
            continue
        text = file_path.read_text(encoding="utf-8")
        assert not external_url_re.search(text), f"External URL found in {file_path}"
        assert not storage_secret_re.search(text), f"Secret stored in web storage in {file_path}"
        if file_path.suffix == ".js":
            combined_js += "\n" + text
        elif file_path.suffix == ".css":
            combined_css += "\n" + text

    # Required UX features & shortcuts
    assert "blur(14px)" in combined_css
    assert "BroadcastChannel" in combined_js
    assert "EventSource" in combined_js
    assert "Raw JSON" in combined_js
    assert "Double Confirmation" in combined_js
    for key in ('"v"', '"s"', '"z"', '"q"', '"h"', '"j"', '"k"', '"l"', '"1"', '"5"', '"k"'):
        assert key in combined_js

    # Static path traversal protection
    app = create_app(workspace_dir=tmp_path, bootstrap_token="static-tok")
    try:
        for bad_path in (
            "/static/../../settings.json",
            "/static/%2e%2e/app.py",
            "/static/..\\app.py",
        ):
            res = asyncio.run(_call_asgi(app, "GET", bad_path))
            assert res.status in (403, 404)
    finally:
        app.state.runtime.cleanup()
