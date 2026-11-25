from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

import soclens.splunk as splunk_mod
from soclens.config import ConfigurationError
from soclens.splunk import SplunkValidator, parse_savedsearches_files


def _make_response(status_code: int, payload: object = None, headers: dict | None = None) -> MagicMock:
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
        resp.text = str(payload)
    return resp


class TestSplunkValidator:
    def test_init_uses_get_splunk_config_defaults(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SPLUNK_HOST", "splunk.internal:8089/")
        monkeypatch.setenv("SPLUNK_TOKEN", "env_token")
        monkeypatch.delenv("SPLUNK_APP", raising=False)
        monkeypatch.setenv("SPLUNK_VERIFY_SSL", "true")

        v = SplunkValidator()
        try:
            assert v.host == "https://splunk.internal:8089"
            assert v.token == "env_token"
            assert v.app == "SplunkEnterpriseSecuritySuite"
            assert v.verify_ssl is True
            assert v.headers["Authorization"] == "Bearer env_token"
        finally:
            v.close()

        monkeypatch.setenv("SPLUNK_VERIFY_SSL", "/etc/ssl/splunk.pem")
        v_ca = SplunkValidator()
        try:
            assert v_ca.verify_ssl == "/etc/ssl/splunk.pem"
        finally:
            v_ca.close()

    def test_init_explicit_overrides_and_missing_creds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
        monkeypatch.delenv("SPLUNK_USERNAME", raising=False)
        monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)

        with pytest.raises(ConfigurationError) as exc_info:
            SplunkValidator(host="https://splunk.local:8089")
        assert isinstance(exc_info.value, ValueError)

        monkeypatch.setenv("SPLUNK_APP", "EnterpriseSecurity")
        v = SplunkValidator(token="tok", verify_ssl=False)
        try:
            assert v.app == "EnterpriseSecurity"
            assert v.verify_ssl is False
        finally:
            v.close()

    def test_ssl_warning_suppression_conditional(self) -> None:
        session = MagicMock(spec=requests.Session)
        with patch.object(splunk_mod, "_SSL_WARNINGS_SUPPRESSED", False):
            with patch("soclens.splunk.urllib3.disable_warnings") as mock_disable:
                SplunkValidator(
                    host="localhost:8089",
                    token="tok",
                    verify_ssl=True,
                    session=session,
                )
                mock_disable.assert_not_called()

                SplunkValidator(
                    host="localhost:8089",
                    token="tok",
                    verify_ssl="/ca/cert.pem",
                    session=session,
                )
                mock_disable.assert_not_called()

                SplunkValidator(
                    host="localhost:8089",
                    token="tok",
                    verify_ssl=False,
                    session=session,
                )
                mock_disable.assert_called_once()

    def test_check_connection_success_fallback_and_retries(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.request.return_value = _make_response(
            200, {"entry": [{"content": {"version": "10.2.0"}}]}
        )
        v = SplunkValidator(
            host="localhost:8089",
            token="tok",
            verify_ssl=False,
            session=session,
            backoff_base=0.0,
        )
        assert v.check_connection() is True
        session.request.assert_called_once()

        session.request.reset_mock()
        session.request.side_effect = [
            _make_response(401, "Unauthorized"),
            _make_response(200, {"entry": [{"content": {"username": "soc_admin"}}]}),
        ]
        assert v.check_connection() is True
        assert session.request.call_count == 2

        session.request.reset_mock()
        session.request.side_effect = [_make_response(500, "Internal error")] * 10
        v_short = SplunkValidator(
            host="localhost:8089",
            token="tok",
            verify_ssl=False,
            session=session,
            max_retries=1,
            backoff_base=0.0,
        )
        assert v_short.check_connection() is False

    @pytest.mark.parametrize(
        ("raw_query", "expected_sent"),
        [
            ("index=test error", "search index=test error"),
            ("  | tstats count", "| tstats count"),
            ("  SEARCH index=main", "SEARCH index=main"),
            ("search\nindex=main", "search\nindex=main"),
            ('searchmatch("foo")', 'search searchmatch("foo")'),
            ("search_id=1", "search search_id=1"),
            ("search=foo", "search search=foo"),
        ],
    )
    def test_run_single_search_success_and_query_normalization(
        self, raw_query: str, expected_sent: str
    ) -> None:
        session = MagicMock(spec=requests.Session)
        session.request.side_effect = [
            _make_response(201, {"sid": "sid_12345"}),
            _make_response(
                200,
                {
                    "entry": [
                        {
                            "content": {
                                "isDone": True,
                                "dispatchState": "DONE",
                                "resultCount": "5",
                                "eventCount": "100",
                                "runDuration": "0.5",
                            }
                        }
                    ]
                },
            ),
            _make_response(200, {"results": [{"_raw": "event payload"}]}),
        ]
        v = SplunkValidator(
            host="localhost:8089",
            token="tok",
            app="search",
            verify_ssl=False,
            session=session,
            backoff_base=0.0,
        )
        res = v.run_single_search(
            {"stanza": "Test Search", "search": raw_query, "file": "savedsearches.conf"},
            "-7d",
            "now",
        )
        assert res["status"] == "success"
        assert res["trigger_count"] == 5
        assert res["scan_count"] == 100
        assert res["duration"] == 0.5
        assert len(res["sample_results"]) == 1
        post_call = session.request.call_args_list[0]
        assert post_call.kwargs["data"]["search"] == expected_sent

    def test_run_single_search_rejects_empty_query(self) -> None:
        session = MagicMock(spec=requests.Session)
        v = SplunkValidator(host="localhost:8089", token="tok", session=session)
        res = v.run_single_search({"stanza": "Empty", "search": "   ", "file": "a.conf"}, "-1h", "now")
        assert res["status"] == "failed"
        assert res["error_message"] == "Empty search query."
        session.request.assert_not_called()

    def test_run_single_search_timeout_cancels_exact_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = MagicMock(spec=requests.Session)
        session.request.side_effect = [
            _make_response(201, {"sid": "sid/special 1"}),
            _make_response(200, {"entry": [{"content": {"isDone": False, "dispatchState": "RUNNING"}}]}),
            _make_response(200, {"messages": [{"text": "cancelled"}]}),
        ]

        ticks = iter([0.0, 0.1, 0.2, 5.0])
        monkeypatch.setattr("soclens.splunk.time.monotonic", lambda: next(ticks))
        monkeypatch.setattr("soclens.splunk.time.sleep", lambda _: None)

        v = SplunkValidator(
            host="https://splunk.local:8089",
            token="tok",
            verify_ssl=False,
            session=session,
            poll_interval=0.1,
        )
        res = v.run_single_search(
            {"stanza": "Slow", "search": "index=main", "file": "saved.conf"},
            "-1h",
            "now",
            timeout=1,
        )
        assert res["status"] == "failed"
        assert "timed out after 1 seconds" in str(res["error_message"])
        cancel_call = session.request.call_args_list[-1]
        assert cancel_call.args[0] == "POST"
        assert (
            cancel_call.args[1]
            == "https://splunk.local:8089/services/search/jobs/sid%2Fspecial%201/control?output_mode=json"
        )
        assert cancel_call.kwargs["data"] == {"action": "cancel"}

    def test_run_single_search_transient_retries_and_cancelled_state(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("soclens.splunk.time.sleep", lambda _: None)
        session = MagicMock(spec=requests.Session)
        session.request.side_effect = [
            requests.exceptions.ConnectionError("blip"),
            _make_response(429, "slow down", headers={"Retry-After": "0"}),
            _make_response(201, {"sid": "sid_retry"}),
            _make_response(503, "busy"),
            _make_response(
                200,
                {
                    "entry": [
                        {
                            "content": {
                                "isDone": True,
                                "dispatchState": "DONE",
                                "resultCount": 0,
                                "eventCount": 10,
                                "runDuration": 0.2,
                            }
                        }
                    ]
                },
            ),
        ]
        v = SplunkValidator(
            host="localhost:8089",
            token="tok",
            session=session,
            max_retries=3,
            backoff_base=0.0,
        )
        res = v.run_single_search(
            {"stanza": "Retry Search", "search": "index=main", "file": "saved.conf"},
            "-1h",
            "now",
            timeout=30,
        )
        assert res["status"] == "success"
        assert res["scan_count"] == 10

        # Non-retryable 400 fails immediately without retry
        session.request.reset_mock()
        session.request.side_effect = [
            _make_response(400, {"messages": [{"text": "Syntax error"}]})
        ]
        res_400 = v.run_single_search(
            {"stanza": "Bad SPL", "search": "index=main | invalid", "file": "saved.conf"},
            "-1h",
            "now",
        )
        assert res_400["status"] == "failed"
        assert "HTTP 400" in str(res_400["error_message"])
        assert session.request.call_count == 1

        # CANCELLED dispatchState is reported as failed
        session.request.reset_mock()
        session.request.side_effect = [
            _make_response(201, {"sid": "sid_cancel"}),
            _make_response(
                200,
                {
                    "entry": [
                        {
                            "content": {
                                "isDone": True,
                                "dispatchState": "CANCELLED",
                            }
                        }
                    ]
                },
            ),
        ]
        res_cancelled = v.run_single_search(
            {"stanza": "Cancelled Search", "search": "index=main", "file": "saved.conf"},
            "-1h",
            "now",
        )
        assert res_cancelled["status"] == "failed"
        assert "CANCELLED" in str(res_cancelled["error_message"])

    def test_run_single_search_concurrent_threads(self) -> None:
        session = MagicMock(spec=requests.Session)

        def fake_request(method: str, url: str, **kwargs: object) -> MagicMock:
            if method == "POST" and "/search/jobs?" in url:
                return _make_response(201, {"sid": "sid_thread"})
            return _make_response(
                200,
                {
                    "entry": [
                        {
                            "content": {
                                "isDone": True,
                                "dispatchState": "DONE",
                                "resultCount": 0,
                                "eventCount": 1,
                                "runDuration": 0.1,
                            }
                        }
                    ]
                },
            )

        session.request.side_effect = fake_request
        v = SplunkValidator(host="localhost:8089", token="tok", session=session)
        searches = [
            {"stanza": f"S{i}", "search": f"index=main id={i}", "file": "saved.conf"}
            for i in range(6)
        ]
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(
                executor.map(lambda s: v.run_single_search(s, "-1h", "now"), searches)
            )
        assert all(r["status"] == "success" for r in results)

    def test_parse_savedsearches_files_real_and_edge_cases(self, tmp_path: Path) -> None:
        conf_a = tmp_path / "savedsearches_a.conf"
        conf_a.write_text(
            "\ufeff[Stanza 1]\n"
            "search = index=test_index \\\n"
            "  sourcetype=syslog \\\n"
            "  | stats count\n"
            "description\n"
            "\n"
            "[Null Search]\n"
            "search\n"
            "description = ignored\n"
            "\n"
            "[Empty Search]\n"
            "search =    \n"
            "description = ignored\n",
            encoding="utf-8",
        )
        conf_b = tmp_path / "savedsearches_b.conf"
        conf_b.write_text(
            "[Stanza 2]\n"
            "search = | tstats count\n"
            "description = Custom description\n",
            encoding="utf-8",
        )

        searches = parse_savedsearches_files(tmp_path / "savedsearches_*.conf")
        assert len(searches) == 2
        assert searches[0]["stanza"] == "Stanza 1"
        assert searches[0]["search"] == "index=test_index sourcetype=syslog | stats count"
        assert searches[0]["description"] == "No description provided."
        assert searches[0]["file"] == "savedsearches_a.conf"

        assert searches[1]["stanza"] == "Stanza 2"
        assert searches[1]["search"] == "| tstats count"
        assert searches[1]["description"] == "Custom description"
        assert searches[1]["file"] == "savedsearches_b.conf"

        dir_searches = parse_savedsearches_files(tmp_path)
        assert len(dir_searches) == 2
