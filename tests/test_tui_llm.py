"""Textual Pilot tests for LocalLLMPane, tab switching, chat, and Sigma pivot."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from textual.widgets import Button, Input, RichLog, Select, Static, TabbedContent

from soclens.llm import LocalLLMClient
from soclens.tui.app import create_app
from soclens.tui.screens.llm import LocalLLMPane
from soclens.tui.screens.sigma import SigmaPane


def _richlog_text(log: RichLog) -> str:
    return "\n".join(str(line.text) for line in log.lines)


def test_tui_llm_tab_switch_and_dashboard_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RF_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("RF_LLM_BASE_URL", "http://127.0.0.1:11434")
    monkeypatch.setenv("RF_LLM_MODEL", "llama3.2:latest")

    app = create_app(
        client=MagicMock(), dry_run=True, workspace_dir=tmp_path, view_mode="admin"
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            dash_summary = str(app.query_one("#dash-env-summary", Static).render())
            assert "Local LLM: ollama (http://127.0.0.1:11434) | Model: llama3.2:latest" in dash_summary

            await pilot.press("f7")
            await pilot.pause()
            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-llm"
            pane = app.query_one(LocalLLMPane)
            assert pane.query_one("#llm-provider-select", Select).value == "ollama"
            assert pane.query_one("#llm-model-input", Input).value == "llama3.2:latest"

    asyncio.run(_run())


def test_tui_llm_refresh_models_chat_and_clear(tmp_path: Path) -> None:
    mock_llm = MagicMock(spec=LocalLLMClient)
    mock_llm.__enter__.return_value = mock_llm
    mock_llm.__exit__.return_value = None
    mock_llm.list_models.return_value = ["llama3.2:latest", "qwen2.5:14b"]
    mock_llm.check_connection.return_value = {
        "ok": True,
        "provider": "ollama",
        "base_url": "http://127.0.0.1:11434",
        "models": ["llama3.2:latest", "qwen2.5:14b"],
        "error": None,
    }
    mock_llm.chat.return_value = {
        "content": "PowerShell -enc indicates base64-encoded command execution.",
        "model": "llama3.2:latest",
        "provider": "ollama",
        "done": True,
        "raw": {},
    }

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch("soclens.tui.screens.llm.LocalLLMClient", return_value=mock_llm):
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                pane = app.query_one(LocalLLMPane)

                # Refresh models
                pane.query_one("#llm-refresh-models-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert pane.query_one("#llm-model-input", Input).value == "llama3.2:latest"
                assert "Loaded 2 model(s)" in str(pane.query_one("#llm-status", Static).render())

                # Send a chat prompt
                pane.query_one("#llm-prompt", Input).value = "Explain PowerShell -enc"
                pane.query_one("#llm-send-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                transcript = _richlog_text(pane.query_one("#llm-transcript", RichLog))
                assert "Explain PowerShell -enc" in transcript
                assert "base64-encoded command execution" in transcript
                assert mock_llm.chat.call_count == 1

                # Clear transcript
                pane.query_one("#llm-clear-btn", Button).press()
                await pilot.pause()
                assert _richlog_text(pane.query_one("#llm-transcript", RichLog)) == ""

    asyncio.run(_run())


def test_tui_sigma_pivot_to_local_llm(tmp_path: Path) -> None:
    sample_rules = [
        {
            "rule_id": "sigma-ps-001",
            "level": "high",
            "index": "windows",
            "title": "Suspicious Encoded PowerShell",
            "file_name": "encoded_ps.yml",
            "content": "title: Suspicious Encoded PowerShell\nlevel: high\ndetection:\n  selection: '-enc'\n",
        }
    ]
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-sigma",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch("soclens.tui.screens.sigma.load_rules", return_value=sample_rules):
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                sigma_pane = app.query_one(SigmaPane)
                sigma_pane.query_one("#sigma-load-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                sigma_pane.query_one("#sigma-explain-llm-btn", Button).press()
                await pilot.pause()

                tabs = app.query_one("#main-tabs", TabbedContent)
                assert tabs.active == "tab-llm"

                llm_pane = app.query_one(LocalLLMPane)
                assert llm_pane.query_one("#llm-template-select", Select).value == "explain_sigma"
                badge = llm_pane.query_one("#llm-context-badge", Static)
                assert badge.display is True
                assert "Suspicious Encoded PowerShell" in str(badge.render())

    asyncio.run(_run())
