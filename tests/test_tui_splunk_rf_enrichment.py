"""Textual Pilot tests for Recorded Future enrichment in SplunkESPane and SplunkSearchPane."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from textual.widgets import Checkbox, DataTable, Input, RichLog, Static

from soclens.tui.app import create_app
from soclens.tui.modals import ConfirmActionModal
from soclens.tui.screens.splunk_es import SplunkESPane
from soclens.tui.screens.splunk_search import SplunkSearchPane


def _richlog_text(log: RichLog) -> str:
    return "\n".join(line.text for line in log.lines)


def _make_fake_rf_client() -> MagicMock:
    rf = MagicMock()
    rf.token = "test-rf-token"
    rf.soar_enrich.return_value = {
        "data": [
            {
                "entity": {
                    "id": "ip:185.220.101.1",
                    "name": "185.220.101.1",
                    "type": "IpAddress",
                },
                "risk": {
                    "score": 93,
                    "level": 5,
                    "evidenceDetails": [
                        {
                            "rule": "Active C2 Server",
                            "criticality": 5,
                            "evidenceString": "Recent C2 beacon sighting",
                        }
                    ],
                },
                "links": {
                    "portal": "https://app.recordedfuture.com/live/sc/entity/ip:185.220.101.1"
                },
            },
            {
                "entity": {
                    "id": "ip:10.10.0.5",
                    "name": "10.10.0.5",
                    "type": "IpAddress",
                },
                "risk": {
                    "score": 15,
                    "level": 2,
                    "evidenceDetails": [{"rule": "Internal Sighting"}],
                },
            },
        ]
    }
    return rf


def _make_fake_es_client() -> MagicMock:
    es = MagicMock()
    es.__enter__.return_value = es
    es.__exit__.return_value = None
    es.list_notables.return_value = [
        {
            "event_id": "notable-rf-1",
            "rule_name": "RF High Risk C2 IP",
            "urgency": "high",
            "status": 1,
            "status_label": "New",
            "owner": "unassigned",
            "disposition": "",
            "security_domain": "network",
            "src": "185.220.101.1",
            "dest": "10.10.0.5",
            "user": "jdoe",
            "risk_score": "90",
            "_time": "2026-11-24T12:00:00Z",
            "raw": {
                "event_id": "notable-rf-1",
                "custom_c2_ip": "185.220.101.1",
            },
        }
    ]
    es.update_notable.return_value = {"success": True}
    return es


def test_tui_splunk_es_auto_enrich_and_post_comment_flow(tmp_path: Path) -> None:
    fake_es = _make_fake_es_client()
    fake_rf = _make_fake_rf_client()
    app = create_app(
        client=fake_rf,
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()

                # Auto-Enrich RF is enabled by default
                assert app.query_one("#es-auto-enrich-cb", Checkbox).value is True

                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                table = app.query_one("#es-table", DataTable)
                assert table.row_count == 1
                row_vals = [str(c) for c in table.get_row_at(0)]
                assert "93" in row_vals
                assert "Very Malicious" in row_vals
                assert "src=185.220.101.1" in row_vals

                detail_txt = _richlog_text(app.query_one("#es-detail", RichLog))
                assert "Recorded Future Enrichment" in detail_txt
                assert "93/99" in detail_txt
                assert "Active C2 Server" in detail_txt

                # Post RF Comment triggers ConfirmActionModal and writes comment on approval
                await pilot.click("#es-post-rf-comment-btn")
                await pilot.pause()
                assert isinstance(app.screen, ConfirmActionModal)
                await pilot.click("#confirm-approve-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                fake_es.update_notable.assert_called_once()
                call_args, call_kwargs = fake_es.update_notable.call_args
                assert call_args == (["notable-rf-1"],)
                assert "93/99 (Very Malicious)" in call_kwargs["comment"]

    asyncio.run(_run())


def test_tui_splunk_es_manual_enrich_override_and_dry_run_comment(tmp_path: Path) -> None:
    fake_es = _make_fake_es_client()
    fake_es.list_notables.return_value = [
        {
            "event_id": "notable-rf-2",
            "rule_name": "Custom Field C2",
            "urgency": "medium",
            "status": 1,
            "status_label": "New",
            "owner": "unassigned",
            "disposition": "",
            "security_domain": "network",
            "src": "",
            "dest": "10.10.0.5",
            "user": "jdoe",
            "risk_score": "50",
            "_time": "2026-11-24T12:10:00Z",
            "raw": {"custom_c2_ip": "185.220.101.1"},
        }
    ]
    fake_rf = _make_fake_rf_client()
    app = create_app(
        client=fake_rf,
        dry_run=True,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkESPane, "_build_es_client", return_value=fake_es):
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()

                # Turn off Auto-Enrich RF and refresh
                app.query_one("#es-auto-enrich-cb", Checkbox).value = False
                await pilot.click("#es-refresh-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                fake_rf.soar_enrich.assert_not_called()

                # Set custom field map override and include private IPs, then click Enrich Selected
                app.query_one("#es-rf-field-map-input", Input).value = "ip=custom_c2_ip,dest"
                app.query_one("#es-private-ips-cb", Checkbox).value = True
                await pilot.click("#es-enrich-selected-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert fake_rf.soar_enrich.call_count == 1
                table = app.query_one("#es-table", DataTable)
                row_vals = [str(c) for c in table.get_row_at(0)]
                assert "93" in row_vals
                assert "custom_c2_ip=185.220.101.1" in row_vals

                # Enrich All also works cleanly
                await pilot.click("#es-enrich-all-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                # Dry-run blocks Post RF Comment
                await pilot.click("#es-post-rf-comment-btn")
                await pilot.pause()
                status = str(app.query_one("#es-status", Static).render())
                assert "DRY-RUN" in status
                fake_es.update_notable.assert_not_called()

    asyncio.run(_run())


def test_tui_splunk_search_enrich_results_with_rf(tmp_path: Path) -> None:
    fake_splunk = MagicMock()
    fake_splunk.__enter__.return_value = fake_splunk
    fake_splunk.__exit__.return_value = None

    def _run_search(spl: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "sid": "sid_rf_1",
            "query": spl,
            "status": "success",
            "result_count": 1,
            "event_count": 1,
            "scan_count": 10,
            "duration": 0.25,
            "fields": ["_time", "host", "src_ip", "_raw"],
            "results": [
                {
                    "_time": "2026-11-24T12:00:00Z",
                    "host": "fw01",
                    "src_ip": "185.220.101.1",
                    "_raw": "blocked connection",
                }
            ],
            "error_message": None,
            "messages": [],
        }

    fake_splunk.run_search.side_effect = _run_search
    fake_rf = _make_fake_rf_client()

    app = create_app(
        client=fake_rf,
        dry_run=True,
        initial_tab="tab-splunk-search",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch.object(SplunkSearchPane, "_build_splunk_client", return_value=fake_splunk):
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                pane = app.query_one(SplunkSearchPane)
                pane.load_query("index=firewall | head 5")

                await pilot.click("#splunk-search-run-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                await pilot.click("#splunk-search-rf-enrich-btn")
                await app.workers.wait_for_complete()
                await pilot.pause()

                status = str(app.query_one("#splunk-search-status", Static).render())
                assert "93/99" in status
                assert "1/1" in status

                detail_txt = _richlog_text(app.query_one("#splunk-search-detail", RichLog))
                assert "Recorded Future Enrichment" in detail_txt
                assert "Active C2 Server" in detail_txt
                assert "185.220.101.1" in detail_txt

    asyncio.run(_run())
