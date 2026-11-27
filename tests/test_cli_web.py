"""CLI wiring tests for ``soclens web`` and PowerShell launcher."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

import soclens.web as soclens_web
from soclens import cli


def test_cli_parser_accepts_web_flags() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(
        ["web", "--port", "8765", "--no-browser", "--admin", "--workspace", "/tmp/ws", "--dry-run"]
    )
    assert args.command == "web"
    assert args.port == 8765
    assert args.no_browser is True
    assert args.admin is True
    assert args.workspace == "/tmp/ws"
    assert args.dry_run is True


def test_cli_main_dispatches_web_subcommand(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, Any] = {}

    def _fake_run_web_server(**kwargs: Any) -> int:
        captured.update(kwargs)
        return int(kwargs.get("port") or 8765)

    monkeypatch.setattr(soclens_web, "run_web_server", _fake_run_web_server)
    monkeypatch.setattr(cli, "_ensure_cli_settings_unlocked", lambda _args: None)
    monkeypatch.setattr(cli, "_maybe_hydrate_startup_secrets", lambda _args: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "soclens",
            "web",
            "--port",
            "8765",
            "--no-browser",
            "--admin",
            "--workspace",
            str(tmp_path),
        ],
    )

    cli.main()
    assert captured["port"] == 8765
    assert captured["open_browser"] is False
    assert captured["admin"] is True
    assert captured["workspace_dir"] == str(tmp_path)


def test_soclens_ps1_contains_no_exe_or_daemon_references() -> None:
    ps1 = (Path(__file__).resolve().parent.parent / "soclens.ps1").read_text(encoding="utf-8")
    assert "soclens.exe" not in ps1.lower()
    assert "soclens.cli" in ps1
