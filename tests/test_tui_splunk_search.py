"""Textual Pilot tests for SplunkSearchPane and Sigma -> Splunk Search pivot."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from textual.widgets import Button, DataTable, Input, Select, Static, TabbedContent, TextArea

from soclens.tui.app import create_app
from soclens.tui.screens.splunk_search import SplunkSearchPane

_SAMPLE_SIGMA_YAML = """title: Suspicious Encoded PowerShell
id: 12345678-1234-1234-1234-1234567890ab
status: test
logsource:
    product: windows
    service: powershell
detection:
    selection:
        ScriptBlockText|contains: '-EncodedCommand'
    condition: selection
level: high
"""


def _make_fake_splunk_client() -> MagicMock:
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = None

    def _run_search(spl: str, **kwargs: Any) -> dict[str, Any]:
        progress_cb = kwargs.get("progress_cb")
        if callable(progress_cb):
            progress_cb(
                {
                    "sid": "sid_tui_1",
                    "dispatch_state": "DONE",
                    "done_progress": 1.0,
                    "result_count": 4,
                    "event_count": 4,
                    "scan_count": 20,
                    "duration": 0.55,
                    "is_done": True,
                }
            )
        return {
            "sid": "sid_tui_1",
            "query": spl,
            "status": "success",
            "result_count": 4,
            "event_count": 4,
            "scan_count": 20,
            "duration": 0.55,
            "fields": ["_time", "host", "src_ip", "_raw"],
            "results": [
                {
                    "_time": "2026-01-01T00:00:00Z",
                    "host": "fw01",
                    "src_ip": "198.51.100.1",
                    "_raw": "event 1",
                },
                {
                    "_time": "2026-01-01T00:01:00Z",
                    "host": "fw02",
                    "src_ip": "198.51.100.2",
                    "_raw": "event 2",
                },
            ],
            "error_message": None,
            "messages": [],
        }

    client.run_search.side_effect = _run_search
    client.get_job_results.return_value = {
        "sid": "sid_tui_1",
        "fields": ["_time", "host", "src_ip", "_raw"],
        "results": [
            {
                "_time": "2026-01-01T00:02:00Z",
                "host": "fw03",
                "src_ip": "198.51.100.3",
                "_raw": "event 3",
            },
            {
                "_time": "2026-01-01T00:03:00Z",
                "host": "fw04",
                "src_ip": "198.51.100.4",
                "_raw": "event 4",
            },
        ],
        "count": 2,
        "offset": 2,
    }
    client.cancel_job.return_value = True
    client.list_saved_searches.return_value = [
        {
            "name": "RF Threat Match",
            "app": "SplunkEnterpriseSecuritySuite",
            "search": "index=firewall | stats count by src_ip",
            "cron_schedule": "*/15 * * * *",
            "earliest_time": "-15m",
            "latest_time": "now",
            "disabled": False,
        }
    ]
    client.list_indexes.return_value = [
        {
            "name": "firewall",
            "total_event_count": 4200,
            "current_db_size_mb": 12.5,
            "datatype": "event",
            "disabled": False,
        }
    ]
    return client


def test_tui_splunk_search_run_paginate_and_export(tmp_path: Path) -> None:
    fake_splunk = _make_fake_splunk_client()
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-splunk-search",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkSearchPane, "_build_splunk_client", return_value=fake_splunk):
            async with app.run_test(size=(140, 40)) as pilot:
                await pilot.pause()
                pane = app.query_one(SplunkSearchPane)
                pane.load_query("index=firewall | head 4")
                app.query_one("#splunk-search-limit", Input).value = "2"

                # Preset updates earliest/latest
                preset = app.query_one("#splunk-search-preset", Select)
                preset.value = "-1h"
                await pilot.pause()
                assert app.query_one("#splunk-search-earliest", Input).value == "-1h"
                assert app.query_one("#splunk-search-latest", Input).value == "now"

                # Run search
                await pilot.click("#splunk-search-run-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                table = app.query_one("#splunk-search-table", DataTable)
                assert table.row_count == 2
                assert "fw01" in [str(c) for c in table.get_row_at(0)]
                status = str(app.query_one("#splunk-search-status", Static).render())
                assert "sid_tui_1" in status
                assert "Results: 4" in status

                # Paginate Next
                next_btn = app.query_one("#splunk-search-next-btn", Button)
                assert next_btn.disabled is False
                await pilot.click("#splunk-search-next-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                fake_splunk.get_job_results.assert_called_with("sid_tui_1", count=2, offset=2)
                assert "fw03" in [str(c) for c in table.get_row_at(0)]
                page_info = str(app.query_one("#splunk-search-page-info", Static).render())
                assert "Results 3-4 of 4" in page_info

                # Export JSON and CSV
                await pilot.click("#splunk-search-export-json-btn")
                await pilot.pause()
                await pilot.click("#splunk-search-export-csv-btn")
                await pilot.pause()

                json_files = list(tmp_path.glob("splunk_results_*.json"))
                csv_files = list(tmp_path.glob("splunk_results_*.csv"))
                assert len(json_files) == 1
                assert len(csv_files) == 1
                exported = json.loads(json_files[0].read_text(encoding="utf-8"))
                assert len(exported) == 2
                assert exported[0]["host"] == "fw03"

                # Cancel button invokes cancel_job
                await pilot.click("#splunk-search-cancel-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                fake_splunk.cancel_job.assert_called_with("sid_tui_1")

    asyncio.run(_run())


def test_tui_splunk_saved_searches_and_indexes(tmp_path: Path) -> None:
    fake_splunk = _make_fake_splunk_client()
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-splunk-search",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkSearchPane, "_build_splunk_client", return_value=fake_splunk):
            async with app.run_test(size=(130, 36)) as pilot:
                await pilot.pause()
                await pilot.click("#splunk-search-saved-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                table = app.query_one("#splunk-search-table", DataTable)
                assert table.row_count == 1
                assert "RF Threat Match" in [str(c) for c in table.get_row_at(0)]

                # Load indexes
                await pilot.click("#splunk-search-indexes-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 1
                assert "firewall" in [str(c) for c in table.get_row_at(0)]

    asyncio.run(_run())


def test_tui_sigma_pivot_to_splunk_search(tmp_path: Path) -> None:
    cache_path = tmp_path / "sigma_rules_cache.json"
    cache_path.write_text(
        json.dumps(
            [
                {
                    "rule_id": "doc:sigma-ps-1",
                    "title": "Suspicious Encoded PowerShell",
                    "file_name": "encoded_ps.yml",
                    "level": "high",
                    "index": "*wineventlog",
                    "content": _SAMPLE_SIGMA_YAML,
                }
            ]
        ),
        encoding="utf-8",
    )
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-sigma",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 36)) as pilot:
            await pilot.pause()
            await pilot.click("#sigma-load-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#sigma-run-splunk-btn")
            await pilot.pause()

            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-splunk-search"
            spl_text = app.query_one("#splunk-search-spl", TextArea).text
            assert "index=*wineventlog" in spl_text
            assert "EncodedCommand" in spl_text

    asyncio.run(_run())
