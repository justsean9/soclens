"""Unit tests for SplunkClient search/job/metadata methods, export helpers, and CLI commands."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

import soclens.cli as cli_mod
from soclens.splunk import (
    SplunkClient,
    SplunkValidator,
    export_results_csv,
    export_results_json,
)


def _make_response(
    status_code: int,
    payload: object = None,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    if payload is None:
        resp.json.side_effect = ValueError("No JSON body")
        resp.text = ""
    elif isinstance(payload, str):
        resp.json.side_effect = ValueError("Invalid JSON")
        resp.text = payload
    else:
        resp.json.return_value = payload
        resp.text = json.dumps(payload)
    return resp


class TestSplunkClient:
    def test_validator_is_subclass_of_client(self) -> None:
        assert issubclass(SplunkValidator, SplunkClient)

    def test_run_search_success_with_progress_cb(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("soclens.splunk.time.sleep", lambda _: None)
        session = MagicMock(spec=requests.Session)
        session.request.side_effect = [
            _make_response(201, {"sid": "sid_999"}),
            _make_response(
                200,
                {
                    "entry": [
                        {
                            "content": {
                                "isDone": False,
                                "dispatchState": "RUNNING",
                                "doneProgress": 0.45,
                                "resultCount": 1,
                                "eventCount": 50,
                                "scanCount": 200,
                                "runDuration": 0.4,
                            }
                        }
                    ]
                },
            ),
            _make_response(
                200,
                {
                    "messages": [{"type": "INFO", "text": "Search completed cleanly"}],
                    "entry": [
                        {
                            "content": {
                                "isDone": True,
                                "dispatchState": "DONE",
                                "doneProgress": 1.0,
                                "resultCount": 2,
                                "eventCount": 120,
                                "scanCount": 500,
                                "runDuration": 1.25,
                            }
                        }
                    ],
                },
            ),
            _make_response(
                200,
                {
                    "fields": [{"name": "_time"}, {"name": "host"}, {"name": "_raw"}],
                    "results": [
                        {"_time": "2026-01-01T00:00:00Z", "host": "web01", "_raw": "err 1"},
                        {"_time": "2026-01-01T00:01:00Z", "host": "web02", "_raw": "err 2"},
                    ],
                },
            ),
        ]

        progress_updates: list[dict[str, object]] = []
        with SplunkClient(
            host="https://splunk.local:8089",
            token="tok",
            app="search",
            verify_ssl=False,
            session=session,
            poll_interval=0.05,
        ) as client:
            res = client.run_search(
                "index=main error",
                earliest="-1h",
                latest="now",
                count=10,
                offset=0,
                progress_cb=progress_updates.append,
            )

        assert res["status"] == "success"
        assert res["sid"] == "sid_999"
        assert res["query"] == "index=main error"
        assert res["result_count"] == 2
        assert res["event_count"] == 120
        assert res["scan_count"] == 500
        assert res["duration"] == 1.25
        assert res["fields"] == ["_time", "host", "_raw"]
        assert len(res["results"]) == 2
        assert res["error_message"] is None
        assert res["messages"] == ["Search completed cleanly"]
        assert len(progress_updates) == 2
        assert progress_updates[0]["dispatch_state"] == "RUNNING"
        assert progress_updates[1]["dispatch_state"] == "DONE"

    def test_run_search_empty_query_and_http_error(self) -> None:
        session = MagicMock(spec=requests.Session)
        client = SplunkClient(host="https://splunk.local:8089", token="tok", session=session)

        empty = client.run_search("   ")
        assert empty["status"] == "failed"
        assert empty["error_message"] == "Empty search query."
        session.request.assert_not_called()

        session.request.return_value = _make_response(
            400, {"messages": [{"type": "FATAL", "text": "Unknown command 'bogus'"}]}
        )
        bad = client.run_search("index=main | bogus")
        assert bad["status"] == "failed"
        assert "HTTP 400" in str(bad["error_message"])
        assert bad["messages"] == ["Unknown command 'bogus'"]

    def test_get_job_results_pagination_and_error(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.request.return_value = _make_response(
            200,
            {
                "results": [
                    {"host": "h3", "status": "200"},
                    {"host": "h4", "status": "500", "extra": "x"},
                ]
            },
        )
        client = SplunkClient(host="https://splunk.local:8089", token="tok", session=session)
        page = client.get_job_results("sid_1", count=2, offset=2)
        assert page["sid"] == "sid_1"
        assert page["count"] == 2
        assert page["offset"] == 2
        assert page["fields"] == ["host", "status", "extra"]
        assert len(page["results"]) == 2
        called_url = session.request.call_args.args[1]
        assert "count=2&offset=2" in called_url

        session.request.return_value = _make_response(404, {"messages": [{"text": "Unknown sid"}]})
        with pytest.raises(RuntimeError, match="HTTP 404"):
            client.get_job_results("missing_sid")

    def test_cancel_job(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.request.return_value = _make_response(200, {"messages": [{"text": "cancelled"}]})
        client = SplunkClient(host="https://splunk.local:8089", token="tok", session=session)
        assert client.cancel_job("sid/1") is True
        assert session.request.call_args.kwargs["data"] == {"action": "cancel"}

        session.request.return_value = _make_response(404, "not found")
        assert client.cancel_job("sid/1") is False
        assert client.cancel_job("   ") is False

    def test_list_indexes(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.request.return_value = _make_response(
            200,
            {
                "entry": [
                    {
                        "name": "main",
                        "content": {
                            "totalEventCount": "1500",
                            "currentDBSizeMB": "42.5",
                            "datatype": "event",
                            "disabled": False,
                            "minTime": "2025-01-01T00:00:00Z",
                            "maxTime": "2026-01-01T00:00:00Z",
                        },
                    },
                    {
                        "name": "notable",
                        "content": {
                            "totalEventCount": 25,
                            "currentDBSizeMB": 1.2,
                            "datatype": "event",
                            "disabled": "0",
                        },
                    },
                ]
            },
        )
        client = SplunkClient(host="https://splunk.local:8089", token="tok", session=session)
        indexes = client.list_indexes()
        assert len(indexes) == 2
        assert indexes[0]["name"] == "main"
        assert indexes[0]["total_event_count"] == 1500
        assert indexes[0]["current_db_size_mb"] == 42.5
        assert indexes[1]["disabled"] is False
        assert "/services/data/indexes?output_mode=json&count=0" in session.request.call_args.args[1]

    def test_list_saved_searches_and_filter(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.request.return_value = _make_response(
            200,
            {
                "entry": [
                    {
                        "name": "RF High Risk IP Hits",
                        "acl": {"app": "SplunkEnterpriseSecuritySuite"},
                        "content": {
                            "search": "index=firewall | lookup rf_ip_risklist",
                            "description": "Matches RF risk list",
                            "cron_schedule": "*/15 * * * *",
                            "dispatch.earliest_time": "-15m",
                            "dispatch.latest_time": "now",
                            "disabled": False,
                            "is_scheduled": True,
                        },
                    },
                    {
                        "name": "System Health Check",
                        "acl": {"app": "search"},
                        "content": {
                            "search": "index=_internal | stats count",
                            "description": "Internal health",
                            "disabled": True,
                        },
                    },
                ]
            },
        )
        client = SplunkClient(host="https://splunk.local:8089", token="tok", session=session)
        all_saved = client.list_saved_searches(app="SplunkEnterpriseSecuritySuite")
        assert len(all_saved) == 2
        assert all_saved[0]["name"] == "RF High Risk IP Hits"
        assert all_saved[0]["is_scheduled"] is True

        filtered = client.list_saved_searches(search_filter="risklist")
        assert len(filtered) == 1
        assert filtered[0]["name"] == "RF High Risk IP Hits"

    def test_dispatch_saved_search(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.request.side_effect = [
            _make_response(201, {"sid": "sid_saved_1"}),
            _make_response(
                200,
                {
                    "entry": [
                        {
                            "content": {
                                "isDone": True,
                                "dispatchState": "DONE",
                                "resultCount": 1,
                                "eventCount": 3,
                                "scanCount": 10,
                                "runDuration": 0.3,
                                "eventSearch": "search index=firewall",
                            }
                        }
                    ]
                },
            ),
            _make_response(
                200,
                {
                    "fields": [{"name": "src_ip"}],
                    "results": [{"src_ip": "198.51.100.10"}],
                },
            ),
        ]
        client = SplunkClient(host="https://splunk.local:8089", token="tok", session=session)
        res = client.dispatch_saved_search(
            "RF High Risk IP Hits",
            earliest="-1h",
            latest="now",
            count=25,
        )
        assert res["status"] == "success"
        assert res["sid"] == "sid_saved_1"
        assert res["name"] == "RF High Risk IP Hits"
        assert res["results"] == [{"src_ip": "198.51.100.10"}]
        dispatch_call = session.request.call_args_list[0]
        assert "/saved/searches/RF%20High%20Risk%20IP%20Hits/dispatch?output_mode=json" in (
            dispatch_call.args[1]
        )
        assert dispatch_call.kwargs["data"] == {
            "dispatch.earliest_time": "-1h",
            "dispatch.latest_time": "now",
        }


class TestSplunkExports:
    def test_export_results_json_and_csv(self, tmp_path: Path) -> None:
        rows = [
            {"_time": "2026-01-01", "host": "h1", "tags": ["a", "b"], "meta": {"k": 1}},
            {"_time": "2026-01-02", "host": "h2", "tags": [], "meta": None},
        ]
        json_path = export_results_json(rows, tmp_path / "out" / "results.json")
        assert json_path.is_file()
        assert json.loads(json_path.read_text(encoding="utf-8")) == rows

        csv_path = export_results_csv(
            rows,
            tmp_path / "out" / "results.csv",
            fields=["_time", "host", "tags", "meta"],
        )
        assert csv_path.is_file()
        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            parsed = list(csv.DictReader(handle))
        assert len(parsed) == 2
        assert parsed[0]["tags"] == "a; b"
        assert parsed[0]["meta"] == '{"k": 1}'
        assert parsed[1]["meta"] == ""


class TestSplunkCLI:
    def test_cli_splunk_check_search_indexes_saved_dispatch(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("SPLUNK_HOST", "https://splunk.local:8089")
        monkeypatch.setenv("SPLUNK_TOKEN", "tok")

        fake_client = MagicMock(spec=SplunkClient)
        fake_client.__enter__.return_value = fake_client
        fake_client.__exit__.return_value = None
        fake_client.host = "https://splunk.local:8089"
        fake_client.app = "SplunkEnterpriseSecuritySuite"
        fake_client.check_connection.return_value = True
        fake_client.run_search.return_value = {
            "sid": "sid_cli_1",
            "query": "index=main | head 2",
            "status": "success",
            "result_count": 1,
            "event_count": 1,
            "scan_count": 5,
            "duration": 0.42,
            "fields": ["host", "msg"],
            "results": [{"host": "srv1", "msg": "ok"}],
            "error_message": None,
            "messages": [],
        }
        fake_client.list_indexes.return_value = [
            {
                "name": "main",
                "total_event_count": 100,
                "current_db_size_mb": 2.5,
                "datatype": "event",
                "disabled": False,
            }
        ]
        fake_client.list_saved_searches.return_value = [
            {
                "name": "Alert One",
                "app": "search",
                "search": "index=main",
                "cron_schedule": "0 * * * *",
                "disabled": False,
            }
        ]
        fake_client.dispatch_saved_search.return_value = {
            "sid": "sid_disp_1",
            "name": "Alert One",
            "query": "index=main",
            "status": "success",
            "result_count": 1,
            "event_count": 1,
            "scan_count": 2,
            "duration": 0.15,
            "fields": ["host"],
            "results": [{"host": "srv1"}],
            "error_message": None,
            "messages": [],
        }

        with patch.object(cli_mod, "_build_splunk_client_from_args", return_value=fake_client):
            # 1. check --json
            monkeypatch.setattr("sys.argv", ["soclens", "splunk", "check", "--json"])
            cli_mod.main()
            out = json.loads(capsys.readouterr().out)
            assert out["connected"] is True

            # 2. search --format csv --output
            csv_out = tmp_path / "cli_export.csv"
            monkeypatch.setattr(
                "sys.argv",
                [
                    "soclens",
                    "splunk",
                    "search",
                    "index=main | head 2",
                    "--earliest",
                    "-24h",
                    "--latest",
                    "now",
                    "--count",
                    "50",
                    "--format",
                    "csv",
                    "--output",
                    str(csv_out),
                ],
            )
            cli_mod.main()
            captured = capsys.readouterr().out
            assert "host,msg" in captured
            assert "srv1,ok" in captured
            assert csv_out.is_file()

            # 3. search --format table
            monkeypatch.setattr(
                "sys.argv",
                ["soclens", "splunk", "search", "index=main | head 2", "--format", "table"],
            )
            cli_mod.main()
            table_out = capsys.readouterr().out
            assert "sid_cli_1" in table_out
            assert "srv1" in table_out

            # 4. indexes --json
            monkeypatch.setattr("sys.argv", ["soclens", "splunk", "indexes", "--json"])
            cli_mod.main()
            idx_out = json.loads(capsys.readouterr().out)
            assert idx_out["count"] == 1
            assert idx_out["indexes"][0]["name"] == "main"

            # 5. saved-searches --filter
            monkeypatch.setattr(
                "sys.argv",
                ["soclens", "splunk", "saved-searches", "--app", "search", "--filter", "Alert", "--json"],
            )
            cli_mod.main()
            ss_out = json.loads(capsys.readouterr().out)
            assert ss_out["count"] == 1
            fake_client.list_saved_searches.assert_called_with(
                app="search", search_filter="Alert", count=100
            )

            # 6. dispatch --json
            monkeypatch.setattr(
                "sys.argv",
                [
                    "soclens",
                    "splunk",
                    "dispatch",
                    "Alert One",
                    "--earliest",
                    "-1h",
                    "--latest",
                    "now",
                    "--json",
                ],
            )
            cli_mod.main()
            disp_out = json.loads(capsys.readouterr().out)
            assert disp_out["sid"] == "sid_disp_1"
            fake_client.dispatch_saved_search.assert_called_with(
                "Alert One",
                app=None,
                earliest="-1h",
                latest="now",
                count=100,
                timeout=180,
            )
