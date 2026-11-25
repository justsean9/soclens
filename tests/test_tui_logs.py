"""Tests for centralized TUI logging, stdio/warning capture, and the dedicated Logs tab."""

from __future__ import annotations

import asyncio
import io
import logging
import sys
import threading
import warnings
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from textual.widgets import (
    Button,
    DataTable,
    Input,
    OptionList,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from soclens import cli
from soclens.config import configure_logging
from soclens.research import ResearchDossier, ResolvedTarget
from soclens.tui import ContextMenuModal, create_app
from soclens.tui.logging_bridge import TuiLogHandler
from soclens.tui.screens.logs import LogsPane


def _rich_log_text(app: Any, selector: str = "#app-log") -> str:
    log_widget = app.query_one(selector, RichLog)
    return "\n".join(line.text for line in log_widget.lines)


def _select_context_option_by_id(app: Any, option_id: str) -> None:
    opts = app.screen.query_one("#ctx-menu-options", OptionList)
    opts.highlighted = opts.get_option_index(option_id)


def test_configure_logging_enable_console_false_and_cli_tui_no_console_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pkg_logger = logging.getLogger("soclens")
    log_file = tmp_path / "logs" / "file_only.log"
    try:
        configure_logging(level="INFO", log_file=log_file, enable_console=False)
        console_handlers = [
            h
            for h in pkg_logger.handlers
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        ]
        file_handlers = [h for h in pkg_logger.handlers if isinstance(h, logging.FileHandler)]
        assert console_handlers == []
        assert len(file_handlers) == 1

        pkg_logger.info("file-only check")
        for h in file_handlers:
            h.flush()
        assert "file-only check" in log_file.read_text(encoding="utf-8")

        calls: list[dict[str, Any]] = []

        def _fake_configure_logging(*args: Any, **kwargs: Any) -> logging.Logger:
            calls.append({"args": args, "kwargs": kwargs})
            return pkg_logger

        monkeypatch.setattr(cli, "configure_logging", _fake_configure_logging)
        monkeypatch.setattr(cli, "RecordedFutureClient", MagicMock())
        monkeypatch.setattr(cli, "run_unified_tui", MagicMock())

        monkeypatch.setattr(sys, "argv", ["soclens", "--tui"])
        cli.main()
        assert calls[-1]["kwargs"]["enable_console"] is False

        monkeypatch.setattr(cli, "_handle_watchlist", MagicMock(return_value=0))
        monkeypatch.setattr(sys, "argv", ["soclens", "watchlist", "interactive"])
        cli.main()
        assert calls[-1]["kwargs"]["enable_console"] is False

        monkeypatch.setattr(sys, "argv", ["soclens", "watchlist", "list"])
        cli.main()
        assert calls[-1]["kwargs"]["enable_console"] is True
    finally:
        for h in list(pkg_logger.handlers):
            if getattr(h, "_soclens_managed", False):
                pkg_logger.removeHandler(h)
                h.close()


def test_tui_logging_bridge_prevents_console_bleed_and_restores_handlers(tmp_path: Path) -> None:
    fake_stderr = io.StringIO()
    pkg_logger = configure_logging(level="INFO", stream=fake_stderr)
    root_logger = logging.getLogger()

    try:
        app = create_app(client=MagicMock(), dry_run=True, workspace_dir=tmp_path)

        async def _run() -> None:
            async with app.run_test(size=(120, 36)) as pilot:
                await pilot.pause()

                def _emit_from_worker() -> None:
                    logging.getLogger("soclens.logos.extractor").warning(
                        "Domain 'meadowbankonline.example' redirected cross-domain to 'abcslot-company.com' (https://abcslot-company.com/)"
                    )
                    logging.getLogger("soclens.research").warning("Research fallback warning")
                    logging.getLogger("soclens.client").warning("Client retry trace_id=trace-999")
                    print("stdout line during tui")
                    print("stderr line during tui", file=sys.stderr)
                    warnings.warn("Sample runtime UserWarning", UserWarning, stacklevel=1)

                worker = threading.Thread(target=_emit_from_worker)
                worker.start()
                worker.join(timeout=5.0)

                for _ in range(10):
                    await pilot.pause(0.02)

                # Nothing bled into the original StreamHandler while the TUI was mounted.
                assert fake_stderr.getvalue() == ""

                await pilot.press("8")
                await pilot.pause()
                assert app.query_one("#main-tabs", TabbedContent).active == "tab-logs"

                log_text = _rich_log_text(app)
                assert "meadowbankonline.example" in log_text
                assert "Research fallback warning" in log_text
                assert "trace-999" in log_text
                assert "stdout line during tui" in log_text
                assert "stderr line during tui" in log_text
                assert "Sample runtime UserWarning" in log_text

        asyncio.run(_run())

        # After unmount, TUI handlers are gone and original console StreamHandler is restored.
        assert not any(isinstance(h, TuiLogHandler) for h in pkg_logger.handlers)
        assert not any(isinstance(h, TuiLogHandler) for h in root_logger.handlers)
        logging.getLogger("soclens.logos.extractor").warning("post-exit console restored")
        assert "post-exit console restored" in fake_stderr.getvalue()
    finally:
        for h in list(pkg_logger.handlers):
            if getattr(h, "_soclens_managed", False):
                pkg_logger.removeHandler(h)
                h.close()


def test_tui_brand_sync_streams_logs_to_separate_page_with_live_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soclens.logos.brand_sync as brand_sync_mod

    fake_stderr = io.StringIO()
    pkg_logger = configure_logging(level="INFO", stream=fake_stderr)

    mock_client = MagicMock()
    mock_client.api_token = "tok"
    mock_client.get_watchlists.return_value = [
        {"id": "report:brand-hash-1", "type": "hash", "name": "Brand Image Watch List"},
        {"id": "report:domain-wl-1", "type": "domain", "name": "Domain Watch List"},
    ]
    mock_client.get_watchlist_entities.side_effect = lambda lid: (
        [
            {"entity": {"id": "idn:alpha.test", "type": "InternetDomainName", "name": "alpha.test"}, "context": {}},
            {"entity": {"id": "idn:meadowbankonline.example", "type": "InternetDomainName", "name": "meadowbankonline.example"}, "context": {}},
        ]
        if lid == "report:domain-wl-1"
        else []
    )

    sample_hash_a = "a" * 64
    sample_hash_b = "b" * 64

    def _fake_hasher(
        domain: str, idx: int, total: int, **_kwargs: Any
    ) -> tuple[list[dict[str, str]], int, str | None, list[str], list[dict[str, Any]]]:
        print(f"[{idx}/{total}] Processing {domain}...")
        if domain == "meadowbankonline.example":
            logging.getLogger("soclens.logos.extractor").warning(
                "Domain 'meadowbankonline.example' redirected cross-domain to 'abcslot-company.com'"
            )
            return (
                [{"sha256": sample_hash_b, "image_url": f"https://{domain}/logo.png"}],
                1,
                None,
                [],
                [{"domain": domain, "status": "included"}],
            )
        return (
            [{"sha256": sample_hash_a, "image_url": f"https://{domain}/logo.png"}],
            1,
            None,
            [],
            [{"domain": domain, "status": "included"}],
        )

    monkeypatch.setattr(brand_sync_mod, "get_domain_image_hash", _fake_hasher)

    try:
        app = create_app(
            client=mock_client,
            dry_run=True,
            initial_tab="tab-brand-logos",
            workspace_dir=tmp_path,
        )

        async def _run() -> None:
            async with app.run_test(size=(140, 42)) as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert len(app.query("#brand-log")) == 0

                await pilot.click("#brand-validate-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert fake_stderr.getvalue() == ""
                brand_table = app.query_one("#brand-table", DataTable)
                assert brand_table.row_count == 2
                status_text = str(app.query_one("#brand-status", Static).render())
                assert "[DRY-RUN]" in status_text

                await pilot.click("#brand-view-logs-btn")
                await pilot.pause()

                assert app.query_one("#main-tabs", TabbedContent).active == "tab-logs"
                assert app.query_one("#logs-source-select", Select).value == "brand_sync"
                log_text = _rich_log_text(app)
                assert "meadowbankonline.example" in log_text
                assert "Processing alpha.test" in log_text
                assert "Starting brand logo validation" in log_text

        asyncio.run(_run())
    finally:
        for h in list(pkg_logger.handlers):
            if getattr(h, "_soclens_managed", False):
                pkg_logger.removeHandler(h)
                h.close()


def test_tui_research_and_other_tabs_capture_stdout_and_hide_inline_activity_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soclens.tui.screens.research as research_screen_mod
    import soclens.tui.screens.sigma as sigma_screen_mod
    import soclens.tui.screens.watchlists as wl_screen_mod

    fake_stderr = io.StringIO()
    pkg_logger = configure_logging(level="INFO", stream=fake_stderr)

    def _fake_research_target(
        _client: Any, query: str, **_kwargs: Any
    ) -> ResearchDossier:
        print(f"Research stdout probe for {query}")
        print(f"Research stderr probe for {query}", file=sys.stderr)
        logging.getLogger("soclens.research").warning("Research logger warning")
        logging.getLogger("soclens.client").warning("Client warning during research")
        return ResearchDossier(
            target=ResolvedTarget(
                raw_query=query,
                detected_kind="ip",
                entity_id=f"ip:{query}",
                canonical_name=query,
            ),
            generated_at="2026-11-24T00:00:00Z",
            risk_score=12,
        )

    def _fake_export_watchlist(_client: Any, list_id: str, dest: Any, **_kwargs: Any) -> bool:
        print(f"[+] Watchlist successfully exported: {list_id} -> {dest}")
        return True

    def _fake_load_rules(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        print("Sigma rules cache stdout message")
        return [
            {
                "rule_id": "doc:sigma-1",
                "title": "Test Sigma Rule",
                "file_name": "test.yml",
                "level": "medium",
                "index": "*win",
                "content": "title: Test Sigma Rule\n",
            }
        ]

    monkeypatch.setattr(research_screen_mod, "research_target", _fake_research_target)
    monkeypatch.setattr(wl_screen_mod, "export_watchlist", _fake_export_watchlist)
    monkeypatch.setattr(sigma_screen_mod, "load_rules", _fake_load_rules)

    mock_client = MagicMock()
    mock_client.api_token = "tok"
    mock_client.get_watchlists.return_value = []
    mock_client.get_watchlist_entities.return_value = []

    try:
        app = create_app(
            client=mock_client, dry_run=True, workspace_dir=tmp_path, view_mode="admin"
        )

        async def _run() -> None:
            async with app.run_test(size=(140, 42)) as pilot:
                await pilot.pause()

                # Activity compact-logs removed from operational tabs; detail/YAML viewers preserved.
                for tid in (
                    "tab-watchlists",
                    "tab-brand-logos",
                    "tab-rf-intel",
                    "tab-sigma",
                    "tab-splunk-bundle",
                    "tab-research",
                    "tab-logs",
                ):
                    await app.ensure_tab_mounted(tid)
                for removed_id in ("#dash-log", "#wl-log", "#brand-log", "#splunk-log", "#res-log"):
                    assert len(app.query(removed_id)) == 0
                for kept_id in ("#res-detail-log", "#rf-log", "#sigma-log", "#app-log"):
                    assert len(app.query(kept_id)) == 1

                # 1. Research tab worker captures stdout/stderr/logger under research & api
                await pilot.press("7")
                await pilot.pause()
                app.query_one("#res-target-input", Input).value = "8.8.8.8"
                await pilot.click("#res-investigate-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                # 2. Watchlists export captures stdout under watchlists
                await pilot.press("2")
                await pilot.pause()
                app.query_one("#wl-target-list-id", Input).value = "report:wl-1"
                app.query_one("#wl-export-path", Input).value = "out.csv"
                await pilot.click("#wl-export-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                # 3. Sigma load captures stdout under sigma
                await pilot.press("5")
                await pilot.pause()
                await pilot.click("#sigma-load-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert fake_stderr.getvalue() == ""

                # Switch to Logs tab and inspect by source filter
                await pilot.press("8")
                await pilot.pause()
                logs_pane = app.query_one(LogsPane)

                logs_pane.set_source_filter("research")
                await pilot.pause()
                res_text = _rich_log_text(app)
                assert "Research stdout probe for 8.8.8.8" in res_text
                assert "Research stderr probe for 8.8.8.8" in res_text
                assert "Research logger warning" in res_text

                logs_pane.set_source_filter("api")
                await pilot.pause()
                assert "Client warning during research" in _rich_log_text(app)

                logs_pane.set_source_filter("watchlists")
                await pilot.pause()
                assert "Watchlist successfully exported" in _rich_log_text(app)

                logs_pane.set_source_filter("sigma")
                await pilot.pause()
                assert "Sigma rules cache stdout message" in _rich_log_text(app)

        asyncio.run(_run())
    finally:
        for h in list(pkg_logger.handlers):
            if getattr(h, "_soclens_managed", False):
                pkg_logger.removeHandler(h)
                h.close()


def test_tui_logs_pane_filters_clear_export_and_responsive_layout(tmp_path: Path) -> None:
    app = create_app(client=MagicMock(), dry_run=True, initial_tab="tab-logs", workspace_dir=tmp_path)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.record_log("Brand info message", level="INFO", source="brand_sync", logger_name="brand_sync")
            app.record_log("Brand error timeout", level="ERROR", source="brand_sync", logger_name="extractor")
            app.record_log("Research query note", level="WARNING", source="research", logger_name="research")
            app.record_log("Dashboard snapshot", level="INFO", source="dashboard", logger_name="DashboardPane")
            app.record_log("RF Intel error card", level="ERROR", source="rf_intel", logger_name="RFIntelPane")
            app.record_log("Debug noise", level="DEBUG", source="system", logger_name="system")
            await pilot.pause()

            logs_pane = app.query_one(LogsPane)
            all_text = _rich_log_text(app)
            assert "Brand info message" in all_text
            assert "Research query note" in all_text
            assert "Dashboard snapshot" in all_text
            assert "Debug noise" in all_text

            # App / TUI filter surfaces dashboard & rf_intel entries
            logs_pane.set_source_filter("tui")
            await pilot.pause()
            tui_text = _rich_log_text(app)
            assert "Dashboard snapshot" in tui_text
            assert "RF Intel error card" in tui_text
            assert "Brand info message" not in tui_text

            # Brand Sync quick button
            await pilot.pause()
            await pilot.click("#logs-brand-btn")
            await pilot.pause()
            assert app.query_one("#logs-source-select", Select).value == "brand_sync"
            brand_text = _rich_log_text(app)
            assert "Brand info message" in brand_text
            assert "Brand error timeout" in brand_text
            assert "Dashboard snapshot" not in brand_text

            # Errors Only quick button
            await pilot.pause()
            await pilot.click("#logs-errors-btn")
            await pilot.pause()
            assert app.query_one("#logs-level-select", Select).value == "ERROR"
            assert "Brand error timeout" in _rich_log_text(app)
            assert "Brand info message" not in _rich_log_text(app)

            # Toggle back off + text filter via / and escape
            await pilot.pause()
            await pilot.click("#logs-errors-btn")
            await pilot.pause()
            await pilot.click("#logs-brand-btn")
            await pilot.pause()
            await pilot.press("slash")
            await pilot.pause()
            filter_input = app.query_one("#logs-filter-input", Input)
            assert app.focused is filter_input
            filter_input.value = "Research query"
            await pilot.pause()
            assert "Research query note" in _rich_log_text(app)
            assert "Brand info message" not in _rich_log_text(app)

            await pilot.press("escape")
            await pilot.pause()
            assert filter_input.value == ""

            # Auto-scroll toggle
            scroll_btn = app.query_one("#logs-autoscroll-btn", Button)
            assert "ON" in str(scroll_btn.label)
            await pilot.pause()
            await pilot.click("#logs-autoscroll-btn")
            await pilot.pause()
            assert "OFF" in str(scroll_btn.label)
            assert app.query_one("#app-log", RichLog).auto_scroll is False
            await pilot.pause()
            await pilot.click("#logs-autoscroll-btn")
            await pilot.pause()
            assert "ON" in str(scroll_btn.label)

            # Export Log
            await pilot.click("#logs-export-btn")
            await pilot.pause()
            exported_files = list((tmp_path / "logs").glob("tui_session_*.log"))
            assert len(exported_files) == 1
            exported_content = exported_files[0].read_text(encoding="utf-8")
            assert "Brand error timeout" in exported_content
            assert "Research query note" in exported_content

            # Right-clicking #app-log without highlighted text opens no context menu; filter via Select
            await pilot.click("#app-log", offset=(4, 2), button=3)
            await pilot.pause()
            assert not isinstance(app.screen, ContextMenuModal)
            app.query_one("#logs-source-select", Select).value = "research"
            await pilot.pause()
            assert app.query_one("#logs-source-select", Select).value == "research"
            assert "Research query note" in _rich_log_text(app)

            # Clear Log
            await pilot.click("#logs-clear-btn")
            await pilot.pause()
            assert _rich_log_text(app) == ""
            assert app.log_store.counts() == (0, 0, 0)

            for width, height in ((80, 24), (120, 36), (180, 52)):
                await pilot.resize_terminal(width, height)
                await pilot.pause()
                pane = app.query_one("#tab-logs", TabPane)
                for wid, wtype in (
                    ("#logs-source-select", Select),
                    ("#logs-level-select", Select),
                    ("#logs-filter-input", Input),
                    ("#logs-autoscroll-btn", Button),
                    ("#logs-clear-btn", Button),
                    ("#logs-export-btn", Button),
                    ("#logs-errors-btn", Button),
                    ("#logs-brand-btn", Button),
                    ("#app-log", RichLog),
                ):
                    widget = app.query_one(wid, wtype)
                    assert widget.region.height >= 1, f"{wid} collapsed at {(width, height)}"
                    assert widget.region.right <= pane.region.right, (
                        f"{wid} clipped horizontally at {(width, height)}: "
                        f"{widget.region} vs {pane.region}"
                    )

    asyncio.run(_run())
