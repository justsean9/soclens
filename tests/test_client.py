"""Offline mocked unit tests for soclens.client (F3, F4, F5, F6)."""

from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
import warnings
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests
import urllib3

import soclens.config as config_mod
from soclens.client import (
    LIST_TYPES,
    ListType,
    RecordedFutureAPIError,
    RecordedFutureAuthError,
    RecordedFutureClient,
    RecordedFutureError,
    RecordedFutureRateLimitError,
    parse_retry_after,
)
from soclens.config import ConfigurationError


def _make_response(
    status_code: int = 200,
    json_data: object = None,
    *,
    headers: dict[str, str] | None = None,
    text: str = "",
    content: bytes = b"",
    json_error: Exception | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = text
    resp.content = content
    if json_error is not None:
        resp.json.side_effect = json_error
    else:
        resp.json.return_value = json_data
    return resp


class TestRecordedFutureClient(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.log_dir = Path(self._tmpdir.name) / "logs"
        self.mock_session = MagicMock(spec=requests.Session)
        self.api_token = "test_api_key_123"
        self.client = RecordedFutureClient(
            api_token=self.api_token,
            sandbox_token="test_sb_tok",
            session=self.mock_session,
            error_log_dir=self.log_dir,
        )

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    # ------------------------------------------------------------------
    # Initialization & Headers (F2 / F3)
    # ------------------------------------------------------------------
    def test_init_from_argument(self) -> None:
        client = RecordedFutureClient(api_token="custom_key", error_log_dir=self.log_dir)
        self.assertEqual(client.api_token, "custom_key")
        self.assertEqual(client.base_url, RecordedFutureClient.CORE_BASE_URL)

    @patch.dict(os.environ, {"RECORDED_FUTURE_API_KEY": "env_key"}, clear=True)
    def test_init_from_env_recorded_future(self) -> None:
        client = RecordedFutureClient(error_log_dir=self.log_dir)
        self.assertEqual(client.api_token, "env_key")

    @patch.dict(os.environ, {"RF_API_TOKEN": "rf_env_key"}, clear=True)
    def test_init_from_env_rf_token(self) -> None:
        client = RecordedFutureClient(error_log_dir=self.log_dir)
        self.assertEqual(client.api_token, "rf_env_key")

    @patch.dict(os.environ, {}, clear=True)
    def test_init_does_not_raise_without_token(self) -> None:
        client = RecordedFutureClient(error_log_dir=self.log_dir)
        self.assertIsNone(client.api_token)
        with self.assertRaises(ConfigurationError) as ctx:
            client._get_headers()
        self.assertIsInstance(ctx.exception, ValueError)
        with self.assertRaises(ConfigurationError):
            client._get_headers(is_sandbox=True)

    def test_get_headers_core_and_sandbox(self) -> None:
        headers = self.client._get_headers()
        self.assertEqual(headers["X-RFToken"], self.api_token)
        self.assertEqual(headers["Content-Type"], "application/json")

        sb_headers = self.client._get_headers(is_sandbox=True)
        self.assertEqual(sb_headers["Authorization"], "Bearer test_sb_tok")

    # ------------------------------------------------------------------
    # HTTP, Retries, Rate Limit, 403 Classification & traceId Logging (F3)
    # ------------------------------------------------------------------
    def test_request_uses_session_and_returns_response(self) -> None:
        self.mock_session.request.return_value = _make_response(200, {"status": "ok"})
        response = self.client._request("GET", "/test-endpoint")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        self.mock_session.request.assert_called_once()

    @patch("soclens.client.time.sleep")
    def test_request_429_retry_after_numeric_and_http_date(self, mock_sleep: MagicMock) -> None:
        resp_429 = _make_response(429, {"message": "Too many"}, headers={"Retry-After": "3"})
        resp_200 = _make_response(200, {"status": "ok"})
        self.mock_session.request.side_effect = [resp_429, resp_200]

        response = self.client._request("GET", "/test-endpoint")
        self.assertEqual(response.status_code, 200)
        mock_sleep.assert_called_once_with(3.0)

        future_dt = datetime.now(UTC) + timedelta(seconds=12)
        parsed = parse_retry_after({"retry-after": format_datetime(future_dt)})
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertGreaterEqual(parsed, 9.0)
        self.assertLessEqual(parsed, 13.0)

    @patch("soclens.client.random.uniform", return_value=1.0)
    @patch("soclens.client.time.sleep")
    def test_request_429_exponential_backoff_and_exhaustion(
        self, mock_sleep: MagicMock, _mock_rand: MagicMock
    ) -> None:
        resp_429 = _make_response(
            429,
            {"message": "Rate limit exceeded", "trace_id": "trace-429"},
            headers={"Retry-After": "4"},
        )
        self.mock_session.request.side_effect = [resp_429, resp_429, resp_429]

        with self.assertRaises(RecordedFutureRateLimitError) as ctx:
            self.client._request("GET", "/test-endpoint", retries=3, backoff=2.0)

        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(ctx.exception.retry_after, 4.0)
        self.assertEqual(ctx.exception.trace_id, "trace-429")
        # 3 attempts -> only 2 sleeps (never sleep after final failed attempt)
        self.assertEqual(mock_sleep.call_count, 2)

    @patch("soclens.client.random.uniform", return_value=1.0)
    @patch("soclens.client.time.sleep")
    def test_request_5xx_retry_and_exhaustion(
        self, mock_sleep: MagicMock, _mock_rand: MagicMock
    ) -> None:
        resp_503 = _make_response(503, {"message": "Upstream unavailable"})
        resp_200 = _make_response(200, {"ok": True})
        self.mock_session.request.side_effect = [resp_503, resp_200]
        res = self.client._request("GET", "/v2/ip/8.8.8.8", retries=2, backoff=1.5)
        self.assertEqual(res.status_code, 200)
        mock_sleep.assert_called_once_with(1.5)

        self.mock_session.reset_mock()
        mock_sleep.reset_mock()
        resp_502 = _make_response(502, {"message": "Bad gateway", "trace_id": "trace-502"})
        self.mock_session.request.side_effect = [resp_502, resp_502]
        with self.assertRaises(RecordedFutureAPIError) as ctx:
            self.client._request("GET", "/v2/ip/8.8.8.8", retries=2, backoff=1.0)
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(ctx.exception.trace_id, "trace-502")
        self.assertEqual(mock_sleep.call_count, 1)

    @patch("soclens.client.random.uniform", return_value=1.0)
    @patch("soclens.client.time.sleep")
    def test_request_network_error_retry_and_exhaustion(
        self, mock_sleep: MagicMock, _mock_rand: MagicMock
    ) -> None:
        self.mock_session.request.side_effect = requests.exceptions.ConnectionError(
            "Connection refused"
        )
        with self.assertRaises(RecordedFutureAPIError) as ctx:
            self.client._request("GET", "/test-endpoint", retries=2, backoff=1.0)

        self.assertIsNone(ctx.exception.status_code)
        self.assertEqual(ctx.exception.reason, "network_error")
        self.assertEqual(self.mock_session.request.call_count, 2)
        self.assertEqual(mock_sleep.call_count, 1)

        err_file = self.log_dir / "rf_api_errors.jsonl"
        self.assertTrue(err_file.exists())
        record = json.loads(err_file.read_text(encoding="utf-8").strip())
        self.assertEqual(record["category"], "network_error")

    def test_request_401_and_403_classification(self) -> None:
        self.mock_session.request.return_value = _make_response(
            401, {"message": "Invalid token", "trace_id": "t-401"}
        )
        with self.assertRaises(RecordedFutureAuthError) as ctx_401:
            self.client._request("GET", "/list/x/info")
        self.assertEqual(ctx_401.exception.permission_type, "unauthorized")

        self.mock_session.request.return_value = _make_response(
            403,
            {
                "error": {
                    "status": 403,
                    "message": "Missing API privileges for Brand Intelligence",
                    "reason": "Forbidden",
                },
                "traceId": "t-403-priv",
            },
        )
        with self.assertRaises(RecordedFutureAuthError) as ctx_priv:
            self.client._request("GET", "/v2/domain/example.com")
        self.assertEqual(ctx_priv.exception.permission_type, "missing_api_privileges")
        self.assertEqual(ctx_priv.exception.trace_id, "t-403-priv")

        self.mock_session.request.return_value = _make_response(
            403,
            {"message": "Missing Data permissions for group A", "status_code": 403},
        )
        with self.assertRaises(RecordedFutureAuthError) as ctx_data:
            self.client._request("GET", "/list/restricted/entities")
        self.assertEqual(ctx_data.exception.permission_type, "missing_data_permissions")

    def test_log_api_error_all_schemas_and_jsonl_persistence(self) -> None:
        # 1. Connect v2
        v2_resp = _make_response(
            400,
            {
                "error": {"status": 400, "message": "Bad Request", "reason": "Invalid syntax"},
                "traceId": "trace-uuid-12345",
            },
        )
        self.client._log_api_error("/v2/ip/bad", v2_resp, method="GET")
        self.assertEqual(self.client.last_trace_id, "trace-uuid-12345")

        # 2. Sandbox string error (must NOT raise AttributeError!)
        sb_resp = _make_response(
            400, {"error": "BAD_REQUEST", "message": "Invalid query syntax"}
        )
        meta_sb = self.client._log_api_error("/search", sb_resp, method="GET")
        self.assertEqual(meta_sb["reason"], "BAD_REQUEST")
        self.assertEqual(meta_sb["message"], "Invalid query syntax")

        # 3. Playbook Alert status dict
        pb_resp = _make_response(
            400, {"status": {"status_code": "Error", "status_message": "Unknown category"}}
        )
        meta_pb = self.client._log_api_error("/playbook-alert/search", pb_resp)
        self.assertEqual(meta_pb["message"], "Unknown category")

        # 4. Collective Insights header trace-id + non-JSON + unconfigured MagicMock
        ci_resp = _make_response(
            500, {"message": "Ingest error"}, headers={"trace-id": "hdr-trace-9"}
        )
        meta_ci = self.client._log_api_error("/collective-insights/detections", ci_resp)
        self.assertEqual(meta_ci["trace_id"], "hdr-trace-9")

        raw_resp = _make_response(502, json_error=ValueError("not json"), text="<html>502</html>")
        meta_raw = self.client._log_api_error("/raw", raw_resp)
        self.assertEqual(meta_raw["message"], "<html>502</html>")

        bare_mock = MagicMock()
        bare_mock.status_code = 400
        self.client._log_api_error("/mock", bare_mock)

        err_file = self.log_dir / "rf_api_errors.jsonl"
        lines = err_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 6)

    # ------------------------------------------------------------------
    # Complete Lists & Watchlists API (F4)
    # ------------------------------------------------------------------
    def test_list_type_enum_has_all_21_values(self) -> None:
        self.assertEqual(len(LIST_TYPES), 21)
        self.assertEqual(len(ListType), 21)
        self.assertIn("brand", LIST_TYPES)
        self.assertIn("industry_peer", LIST_TYPES)
        self.assertIn("executive", LIST_TYPES)

    def test_get_watchlists_all_21_types_and_dedup(self) -> None:
        self.mock_session.request.return_value = _make_response(
            200,
            [
                {"id": "list_1", "name": "Suspicious Watch List", "type": "ip"},
                {"id": "list_2", "name": "alpha Brand List", "type": "brand"},
            ],
        )
        watchlists = self.client.get_watchlists()
        self.assertEqual(self.mock_session.request.call_count, 22)
        self.assertEqual([w["name"] for w in watchlists], ["alpha Brand List", "Suspicious Watch List"])

    def test_get_watchlists_filtered_by_types_and_name(self) -> None:
        self.mock_session.request.return_value = _make_response(
            200, [{"id": "list_b", "name": "Brands", "type": "brand"}]
        )
        res = self.client.get_watchlists(list_types=[ListType.BRAND], name="Brands")
        self.assertEqual(len(res), 1)
        self.mock_session.request.assert_called_once()
        sent_json = self.mock_session.request.call_args.kwargs["json"]
        self.assertEqual(sent_json, {"type": "brand", "limit": 100, "name": "Brands"})

    def test_create_list_and_info_and_status(self) -> None:
        with self.assertRaises(ValueError):
            self.client.create_list("   ", "brand")
        with self.assertRaises(ValueError):
            self.client.create_list("Test", "not_a_list_type")

        self.mock_session.request.return_value = _make_response(
            200, {"id": "report:abc", "name": "Brand Logos", "type": "brand"}
        )
        created = self.client.create_list("Brand Logos", ListType.BRAND)
        self.assertEqual(created["id"], "report:abc")

        self.mock_session.request.return_value = _make_response(
            200, {"id": "report:abc", "name": "Brand Logos"}
        )
        info = self.client.get_list_info("report:abc")
        self.assertEqual(info["name"], "Brand Logos")

        self.mock_session.request.return_value = _make_response(
            200, {"size": 950, "status": "ready"}
        )
        with self.assertLogs("soclens.client", level="WARNING") as cm:
            status = self.client.get_list_status("report:abc")
        self.assertEqual(status["size"], 950)
        self.assertTrue(any("approaching" in msg for msg in cm.output))

    def test_get_watchlist_entities_success_warns_and_raises_on_error(self) -> None:
        entities_payload = [
            {"entity": {"id": f"hash:{i:064x}", "type": "Hash", "name": f"{i:064x}"}}
            for i in range(905)
        ]
        self.mock_session.request.return_value = _make_response(200, entities_payload)
        with self.assertLogs("soclens.client", level="WARNING"):
            entities = self.client.get_watchlist_entities("list_1")
        self.assertEqual(len(entities), 905)

        self.mock_session.request.return_value = _make_response(
            404, {"message": "List not found", "status_code": 404, "trace_id": "t-404"}
        )
        with self.assertRaises(RecordedFutureError):
            self.client.get_watchlist_entities("missing_list")

    def test_add_entity_returns_result_dict_and_supports_context(self) -> None:
        self.mock_session.request.return_value = _make_response(200, {"result": "added"})
        res = self.client.add_entity(
            "list_1",
            "InternetDomainName",
            "good.com",
            context={"annotation": "Owned brand domain"},
        )
        self.assertEqual(res, {"result": "added"})
        self.assertTrue(res)
        sent = self.mock_session.request.call_args.kwargs["json"]
        self.assertEqual(sent["entity"], {"type": "InternetDomainName", "name": "good.com"})
        self.assertEqual(sent["context"], {"annotation": "Owned brand domain"})

        # Fallback when response.json() is unconfigured/non-dict
        bare = MagicMock()
        bare.status_code = 200
        self.mock_session.request.return_value = bare
        res2 = self.client.add_entity("list_1", "Hash", name="a" * 64)
        self.assertEqual(res2, {"result": "added"})

    def test_add_entity_id_heuristic_comprehensive(self) -> None:
        self.mock_session.request.return_value = _make_response(200, {"result": "added"})

        # Opaque RF IDs -> {"id": ...}
        for opaque in ("B81SP6", "cE30"):
            self.client.add_entity("list_1", "Product", opaque)
            sent = self.mock_session.request.call_args.kwargs["json"]
            self.assertEqual(sent["entity"], {"id": opaque})

        # Prefixed RF IDs -> {"id": ...}
        for prefixed in ("idn:bad.com", "ip:1.2.3.4", "hash:" + "a" * 64, "asn:AS123", "report:xyz"):
            self.client.add_entity("list_1", "InternetDomainName", prefixed)
            sent = self.mock_session.request.call_args.kwargs["json"]
            self.assertEqual(sent["entity"], {"id": prefixed})

        # URLs must NOT be treated as prefix IDs
        self.client.add_entity("list_1", "URL", "https://example.com/login")
        sent_url = self.mock_session.request.call_args.kwargs["json"]
        self.assertEqual(sent_url["entity"], {"type": "URL", "name": "https://example.com/login"})

        # Human names must NOT be misclassified as RF IDs
        for human in ("SAP", "F5-VPN", "CrowdStrike", "good.com"):
            self.client.add_entity("list_1", "Product", human)
            sent = self.mock_session.request.call_args.kwargs["json"]
            self.assertEqual(sent["entity"], {"type": "Product", "name": human})

        # Auto-resolved type casing normalization
        self.client.add_entity("list_1", "IPAddress", "8.8.8.8")
        sent_ip = self.mock_session.request.call_args.kwargs["json"]
        self.assertEqual(sent_ip["entity"], {"type": "IpAddress", "name": "8.8.8.8"})

        # Optional resolve=True calls entity_match
        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = [
            _make_response(200, [{"id": "B81SP6", "name": "SAP", "type": "Product"}]),
            _make_response(200, {"result": "added"}),
        ]
        self.client.add_entity("list_1", "Product", "SAP", resolve=True)
        self.assertEqual(self.mock_session.request.call_count, 2)
        last_sent = self.mock_session.request.call_args.kwargs["json"]
        self.assertEqual(last_sent["entity"], {"id": "B81SP6"})

    def test_add_entity_limit_warning_without_extra_http_call(self) -> None:
        self.mock_session.request.return_value = _make_response(200, {"result": "added"})
        with self.assertLogs("soclens.client", level="WARNING"):
            self.client.add_entity("list_1", "Hash", "b" * 64, current_size=950)
        self.mock_session.request.assert_called_once()

        self.mock_session.reset_mock()
        self.mock_session.request.side_effect = [
            _make_response(200, {"size": 1000, "status": "ready"}),
            _make_response(200, {"result": "added"}),
        ]
        with self.assertLogs("soclens.client", level="WARNING"):
            self.client.add_entity("list_1", "Hash", "b" * 64, check_limit=True)
        self.assertEqual(self.mock_session.request.call_count, 2)

    def test_remove_entity_and_tags_and_text_entries(self) -> None:
        self.mock_session.request.return_value = _make_response(200, {"result": "removed"})
        res = self.client.remove_entity("list_1", "ent_id_123")
        self.assertEqual(res, {"result": "removed"})
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["json"],
            {"entity": {"id": "ent_id_123"}},
        )

        self.client.remove_entity("list_1", "bad.com", "InternetDomainName")
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["json"],
            {"entity": {"type": "InternetDomainName", "name": "bad.com"}},
        )

        self.mock_session.request.return_value = _make_response(200, ["keyword1", "keyword2"])
        self.assertEqual(self.client.get_text_entries("list_t"), ["keyword1", "keyword2"])

        self.mock_session.request.return_value = _make_response(
            200, [{"entity": {"id": "cmp_1"}, "tags": [{"id": "t1", "name": "Vendor"}]}]
        )
        tagged = self.client.get_entities_with_tags("list_c")
        self.assertEqual(len(tagged), 1)

        with self.assertRaises(ValueError):
            self.client.replace_entity_tags("list_c", "cmp_1", [f"t{i}" for i in range(10)])

        self.mock_session.request.return_value = _make_response(
            200, {"entity_id": "cmp_1", "operation": {"status": "tags_updated"}}
        )
        tag_res = self.client.replace_entity_tags("list_c", {"id": "cmp_1"}, ["Vendor"])
        self.assertEqual(tag_res["operation"]["status"], "tags_updated")

    # ------------------------------------------------------------------
    # Detection Rules Schema Fix (F5)
    # ------------------------------------------------------------------
    def test_search_detection_rules_pagination_and_schema(self) -> None:
        resp_1 = _make_response(
            200,
            {
                "count": 1,
                "total_count": 2,
                "result": [{"id": "rule_1", "title": "Detect A"}],
                "next_offset": "tok_page_2",
            },
        )
        resp_2 = _make_response(
            200,
            {
                "count": 1,
                "total_count": 2,
                "result": [{"id": "rule_2", "title": "Detect B"}],
                "next_offset": None,
            },
        )
        self.mock_session.request.side_effect = [resp_1, resp_2]

        rules = self.client.search_detection_rules()
        self.assertEqual(len(rules), 2)
        self.assertEqual([r["id"] for r in rules], ["rule_1", "rule_2"])
        second_payload = self.mock_session.request.call_args_list[1].kwargs["json"]
        self.assertEqual(second_payload["offset"], "tok_page_2")
        self.assertNotIn("cursor", second_payload)

    def test_search_detection_rules_with_days_and_filters(self) -> None:
        self.mock_session.request.return_value = _make_response(
            200, {"count": 0, "total_count": 0, "result": [], "next_offset": None}
        )
        rules = self.client.search_detection_rules(
            days=7,
            rule_types=["sigma", "yara"],
            entities=["ent:1"],
            title="Mimikatz",
            doc_id="doc:123",
            tagged_entities=True,
        )
        self.assertEqual(rules, [])
        sent = self.mock_session.request.call_args.kwargs["json"]
        self.assertIn("after", sent["filter"]["updated"])
        self.assertNotIn("operator", sent["filter"]["updated"])
        self.assertEqual(sent["filter"]["types"], ["sigma", "yara"])
        self.assertEqual(sent["filter"]["entities"], ["ent:1"])
        self.assertEqual(sent["filter"]["title"], "Mimikatz")
        self.assertEqual(sent["filter"]["doc_id"], "doc:123")
        self.assertTrue(sent["tagged_entities"])

    def test_search_detection_rules_raises_on_error(self) -> None:
        resp_1 = _make_response(
            200, {"result": [{"id": "rule_1"}], "next_offset": "tok2"}
        )
        resp_err = _make_response(
            500, {"message": "Internal error", "status_code": 500, "trace_id": "t-500"}
        )
        self.mock_session.request.side_effect = [resp_1, resp_err, resp_err, resp_err, resp_err, resp_err]
        with patch("soclens.client.time.sleep"):
            with self.assertRaises(RecordedFutureError):
                self.client.search_detection_rules()

    # ------------------------------------------------------------------
    # Expanded SOC APIs (F6)
    # ------------------------------------------------------------------
    def test_entity_match_and_lookup(self) -> None:
        self.mock_session.request.return_value = _make_response(
            200, [{"id": "B81SP6", "name": "SAP", "type": "Company"}]
        )
        matches = self.client.entity_match("SAP", types=["Company"], limit=5)
        self.assertEqual(matches[0]["id"], "B81SP6")

        self.mock_session.request.return_value = _make_response(
            200, {"data": {"id": "B81SP6", "name": "SAP", "type": "Company"}}
        )
        detail = self.client.entity_lookup("B81SP6")
        self.assertEqual(detail["data"]["name"], "SAP")

    def test_soar_enrich_and_triage(self) -> None:
        with self.assertRaises(ValueError):
            self.client.soar_enrich({})
        with self.assertRaises(ValueError):
            self.client.soar_enrich({"ip": [f"10.0.0.{i}" for i in range(1001)]})

        self.mock_session.request.return_value = _make_response(
            200, {"data": {"results": []}, "counts": {"returned": 0, "total": 1}}
        )
        res = self.client.soar_enrich({"ip": ["8.8.8.8"], "companybydomain": ["example.com"]})
        self.assertIn("data", res)
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["params"], {"metadata": "false"}
        )

        self.mock_session.request.return_value = _make_response(
            200, {"phishing": {"threshold": 65}}
        )
        self.assertIn("phishing", self.client.soar_get_contexts())

        self.mock_session.request.return_value = _make_response(
            200, {"data": {"triage": {"verdict": True}}}
        )
        triage = self.client.soar_triage(
            "phishing",
            {"domain": ["evil.example"]},
            threshold=65,
            threshold_type="min",
            fmt="phantom",
        )
        self.assertTrue(triage["data"]["triage"]["verdict"])

    def test_v2_lookup_and_risklist_and_company_by_domain(self) -> None:
        self.mock_session.request.return_value = _make_response(
            200, {"data": {"risk": {"score": 89}}}
        )
        self.client.v2_lookup("url", "http://evil.com/a/b?q=1", fields=["entity", "risk"])
        called_url = self.mock_session.request.call_args.kwargs["url"]
        self.assertTrue(
            called_url.endswith("/v2/url/url:http%3A%2F%2Fevil.com%2Fa%2Fb%3Fq%3D1")
        )

        self.mock_session.request.return_value = _make_response(
            200, {"data": {"entity": {"name": "Example Corp"}}}
        )
        cmp_res = self.client.v2_company_by_domain("example.com")
        self.assertEqual(cmp_res["data"]["entity"]["name"], "Example Corp")

        self.mock_session.request.return_value = _make_response(200, text="Name,Risk\n1.2.3.4,90")
        csv_text = self.client.v2_risklist("ip", fmt="csv/splunk")
        self.assertIsInstance(csv_text, str)

        self.mock_session.request.return_value = _make_response(200, content=b"\x1f\x8b\x08")
        gz_bytes = self.client.v2_risklist("domain", gzip=True)
        self.assertIsInstance(gz_bytes, bytes)

        self.mock_session.request.return_value = _make_response(
            200, {"type": "bundle", "objects": []}
        )
        stix_json = self.client.v2_risklist(
            "hash", fmt="application/stix+json;version=2.1"
        )
        self.assertIsInstance(stix_json, dict)

        self.mock_session.request.return_value = _make_response(
            200, headers={"ETag": '"abc123"'}
        )
        stat_hdrs = self.client.v2_stat_risklist("ip")
        self.assertEqual(stat_hdrs["ETag"], '"abc123"')

    def test_playbook_alerts_search_detail_category_mapping_and_image(self) -> None:
        self.mock_session.request.return_value = _make_response(
            200,
            {
                "status": {"status_code": "Ok", "status_message": ""},
                "data": [{"playbook_alert_id": "pb-1", "category": "domain_abuse"}],
                "counts": {"returned": 1, "total": 1},
            },
        )
        pb_search = self.client.search_playbook_alerts(categories=["domain_abuse"])
        self.assertEqual(len(pb_search["data"]), 1)

        # Verify dark_web -> dark_web_brand and socmed_impersonation -> social_media_impersonation
        self.mock_session.request.return_value = _make_response(
            200, {"status": {"status_code": "Ok"}, "data": {"id": "pb-dw"}}
        )
        self.client.get_playbook_alert("dark_web", "pb-dw", panels=["summary"])
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/playbook-alert/dark_web_brand/pb-dw"
            )
        )

        self.client.get_playbook_alert("socmed_impersonation", "pb-sm")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/playbook-alert/social_media_impersonation/pb-sm"
            )
        )

        # cyber_vulnerability maps to /playbook-alert/vulnerability/{id}
        self.client.get_playbook_alert("cyber_vulnerability", "pb-vuln")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/playbook-alert/vulnerability/pb-vuln"
            )
        )

        # Error status_code inside HTTP 200 raises RecordedFutureAPIError
        self.mock_session.request.return_value = _make_response(
            200, {"status": {"status_code": "Error", "status_message": "Not found"}}
        )
        with self.assertRaises(RecordedFutureAPIError):
            self.client.get_playbook_alert("malicious_sites", "pb-missing")

        # Image bytes (domain_abuse uses category image endpoint; dark_web uses /alert/v3/image)
        self.mock_session.request.return_value = _make_response(200, content=b"\x89PNG\r\n\x1a\n")
        img_bytes = self.client.get_playbook_alert_image("domain_abuse", "pb-1", "img-9")
        self.assertTrue(img_bytes.startswith(b"\x89PNG"))

        dw_img = self.client.get_playbook_alert_image("dark_web", "pb-dw", "img:abc-123")
        self.assertTrue(dw_img.startswith(b"\x89PNG"))
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith("/alert/v3/image")
        )
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["params"],
            {"id": "img:abc-123"},
        )

    def test_alerts_v3_and_cases_and_sandbox(self) -> None:
        with self.assertRaises(ValueError):
            self.client.search_alerts_v3(limit=600, offset=500)

        self.mock_session.request.return_value = _make_response(
            200, {"data": [{"id": "alert-1"}], "counts": {"returned": 1, "total": 1}}
        )
        alerts = self.client.search_alerts_v3(
            status_in_portal="New", limit=10, offset=20, tagged_text=True
        )
        self.assertEqual(len(alerts["data"]), 1)
        call_kw = self.mock_session.request.call_args.kwargs
        self.assertTrue(call_kw["url"].endswith("/alert/v3"))
        self.assertEqual(call_kw["params"]["from"], 20)
        self.assertEqual(call_kw["params"]["statusInPortal"], "New")

        # Cases pagination + PUT update
        self.mock_session.request.side_effect = [
            _make_response(
                200,
                {
                    "status": {"status_code": "Ok"},
                    "data": [{"id": "case-1"}],
                    "next_offset": "c2",
                },
            ),
            _make_response(
                200,
                {
                    "status": {"status_code": "Ok"},
                    "data": [{"id": "case-2"}],
                    "next_offset": None,
                },
            ),
        ]
        cases = self.client.search_cases(paginate=True)
        self.assertEqual(len(cases["data"]), 2)

        self.mock_session.request.side_effect = None
        self.mock_session.request.return_value = _make_response(
            200, {"status": {"status_code": "Ok"}}
        )
        self.client.update_case("case-1", status="InProgress")
        self.assertEqual(self.mock_session.request.call_args.kwargs["method"], "PUT")

        # Sandbox search & sample (Bearer auth + sandbox base URL)
        self.mock_session.request.return_value = _make_response(
            200, {"data": [{"id": "sample-1"}], "next": None}
        )
        sb_res = self.client.sandbox_search("family:emotet", limit=25)
        self.assertEqual(sb_res["data"][0]["id"], "sample-1")
        sb_call = self.mock_session.request.call_args.kwargs
        self.assertTrue(sb_call["url"].startswith(RecordedFutureClient.SANDBOX_BASE_URL))
        self.assertEqual(sb_call["headers"]["Authorization"], "Bearer test_sb_tok")

        self.mock_session.request.return_value = _make_response(
            200, {"id": "sample-1", "status": "reported"}
        )
        sample = self.client.sandbox_get_sample("sample-1")
        self.assertEqual(sample["status"], "reported")

    def test_additional_f5_f6_methods_coverage(self) -> None:
        self.mock_session.request.return_value = _make_response(
            200, [{"id": "ent:1", "type": "Product", "name": "Apache", "display_name": "Apache"}]
        )
        self.assertEqual(len(self.client.get_detection_rule_entities()), 1)
        self.assertEqual(len(self.client.get_detection_rule_entity_types()), 1)

        self.mock_session.request.return_value = _make_response(
            200, {"data": {"results": [{"name": "c2"}]}}
        )
        self.assertIn("data", self.client.v2_riskrules("ip"))
        self.assertIn("data", self.client.v2_search("domain", limit=10))

        self.mock_session.request.return_value = _make_response(
            200, {"status": {"status_code": "Ok"}, "data": {"playbook_alert_id": "pb-1"}}
        )
        self.assertEqual(
            self.client.get_playbook_alert_preview("pb-1")["data"]["playbook_alert_id"], "pb-1"
        )

        self.mock_session.request.return_value = _make_response(
            200, {"status_code": "Error", "status_message": "Invalid status"}
        )
        with self.assertRaises(RecordedFutureAPIError):
            self.client.update_playbook_alert("pb-1", status="Invalid")

        self.mock_session.request.return_value = _make_response(
            200, {"data": {"id": "alert-1"}}
        )
        self.assertEqual(self.client.get_alert_v3("alert-1")["data"]["id"], "alert-1")

        self.mock_session.request.return_value = _make_response(
            200, {"data": [{"id": "hit-1"}]}
        )
        self.assertEqual(self.client.get_alert_v3_hits(["hit-1"])["data"][0]["id"], "hit-1")

        self.mock_session.request.return_value = _make_response(
            200, {"success": ["alert-1"], "error": []}
        )
        self.assertEqual(
            self.client.update_alerts_v2([{"id": "alert-1", "statusInPortal": "Resolved"}])["success"],
            ["alert-1"],
        )

        self.mock_session.request.return_value = _make_response(
            200, {"status": {"status_code": "Ok"}, "data": [{"id": "case-1"}]}
        )
        self.assertEqual(self.client.lookup_cases(["case-1"])["data"][0]["id"], "case-1")
        self.assertEqual(
            self.client.create_case(title="Brand abuse", status="New")["status"]["status_code"],
            "Ok",
        )

        self.mock_session.request.return_value = _make_response(
            200, {"analysis": {"score": 9}, "sample": {"id": "sample-1"}}
        )
        overview = self.client.sandbox_get_overview("sample-1")
        self.assertEqual(overview["analysis"]["score"], 9)

    def test_v2_lookup_url_encoding_with_encoded_query_and_preencoded_url(self) -> None:
        self.mock_session.request.return_value = _make_response(200, {"data": {}})

        # Raw URL containing %2F in query string must still be percent-encoded
        self.client.v2_lookup(
            "url", "http://evil.com/login?next=https%3A%2F%2Fvictim.com%2Fauth"
        )
        encoded_call_url = self.mock_session.request.call_args.kwargs["url"]
        tail = encoded_call_url.split("/v2/url/", 1)[1]
        self.assertNotIn("://", tail)
        self.assertNotIn("/", tail)
        self.assertEqual(
            tail,
            "url:http%3A%2F%2Fevil.com%2Flogin%3Fnext%3Dhttps%253A%252F%252Fvictim.com%252Fauth",
        )

        # Already-encoded URL with url: prefix must NOT be double-encoded
        self.client.v2_lookup("url", "url:http%3A%2F%2Fevil.com%2Fa%2Fb")
        preencoded_call_url = self.mock_session.request.call_args.kwargs["url"]
        self.assertTrue(
            preencoded_call_url.endswith("/v2/url/url:http%3A%2F%2Fevil.com%2Fa%2Fb")
        )
        self.assertNotIn("%252F", preencoded_call_url)

    def test_parse_retry_after_rejects_non_finite_values(self) -> None:
        for val in ("inf", "-inf", "Infinity", "-Infinity", "NaN", "nan"):
            self.assertIsNone(parse_retry_after({"Retry-After": val}))

    @patch.dict(
        os.environ,
        {"RF_API_TOKEN": "tok", "RF_BASE_URL": "   ", "RF_SANDBOX_BASE_URL": "\t \n"},
        clear=True,
    )
    def test_init_strips_whitespace_base_urls(self) -> None:
        client = RecordedFutureClient(error_log_dir=self.log_dir)
        self.assertEqual(client.core_base_url, RecordedFutureClient.CORE_BASE_URL)
        self.assertEqual(client.sandbox_base_url, RecordedFutureClient.SANDBOX_BASE_URL)

    def test_log_api_error_handles_string_detail(self) -> None:
        resp = _make_response(404, {"detail": "Not Found"})
        meta = self.client._log_api_error("/asi/v1/projects", resp, method="GET")
        self.assertEqual(meta["message"], "Not Found")
        self.assertEqual(meta["category"], "validation_detail")

    def test_build_entity_ref_strips_name_and_resolves_digit_names(self) -> None:
        self.mock_session.request.return_value = _make_response(200, {"result": "added"})
        self.client.add_entity("list_1", "InternetDomainName", "  good.com  ")
        sent = self.mock_session.request.call_args.kwargs["json"]
        self.assertEqual(sent["entity"], {"type": "InternetDomainName", "name": "good.com"})

        # resolve=True should resolve "Log4j" and "APT28" via entity_match instead of heuristic ID
        for name, expected_id in (("Log4j", "sw:log4j"), ("APT28", "ta:apt28")):
            self.mock_session.request.reset_mock()
            self.mock_session.request.side_effect = [
                _make_response(200, [{"id": expected_id, "name": name}]),
                _make_response(200, {"result": "added"}),
            ]
            self.client.add_entity("list_1", "Product", name, resolve=True)
            self.assertEqual(self.mock_session.request.call_count, 2)
            self.assertEqual(
                self.mock_session.request.call_args.kwargs["json"]["entity"],
                {"id": expected_id},
            )

        # resolve=True still treats explicit RF_ID_PREFIXES as IDs without calling entity_match
        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = None
        self.mock_session.request.return_value = _make_response(200, {"result": "added"})
        self.client.add_entity("list_1", "Product", "report:abc", resolve=True)
        self.mock_session.request.assert_called_once()
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["json"]["entity"],
            {"id": "report:abc"},
        )

    def test_single_resource_getters_validate_non_empty_ids(self) -> None:
        invalid_calls = [
            lambda: self.client.get_list_info(""),
            lambda: self.client.get_list_status("   "),
            lambda: self.client.get_watchlist_entities(""),
            lambda: self.client.get_text_entries("  "),
            lambda: self.client.get_entities_with_tags(""),
            lambda: self.client.entity_lookup("  "),
            lambda: self.client.get_playbook_alert_preview(""),
            lambda: self.client.get_playbook_alert("domain_abuse", "  "),
            lambda: self.client.update_playbook_alert("   ", status="Resolved"),
            lambda: self.client.get_playbook_alert_image("domain_abuse", "", "img-1"),
            lambda: self.client.get_playbook_alert_image("domain_abuse", "pb-1", "   "),
            lambda: self.client.get_alert_v3(""),
            lambda: self.client.sandbox_get_sample("  "),
            lambda: self.client.sandbox_get_overview(""),
        ]
        for call in invalid_calls:
            with self.assertRaises(ValueError):
                call()

    def test_v2_search_fields_normalization_and_playbook_category_case(self) -> None:
        self.mock_session.request.return_value = _make_response(200, {"data": {"results": []}})
        self.client.v2_search("domain", fields=["entity", "risk"], limit=5)
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["params"],
            {"fields": "entity,risk", "limit": 5},
        )
        self.client.v2_search("domain", fields=[], limit=5)
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["params"],
            {"limit": 5},
        )

        self.mock_session.request.return_value = _make_response(
            200, {"status": {"status_code": "Ok"}, "data": {"id": "pb-dw"}}
        )
        self.client.get_playbook_alert(" DARK_WEB ", "pb-dw")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/playbook-alert/dark_web_brand/pb-dw"
            )
        )

        self.mock_session.request.return_value = _make_response(200, content=b"\x89PNG\r\n\x1a\n")
        self.client.get_playbook_alert_image(" SocMed_Impersonation ", "pb-sm", "img-1")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/playbook-alert/social_media_impersonation/pb-sm/image/img-1"
            )
        )

    def test_ssl_verification_configuration_and_runtime_toggle(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            default_client = RecordedFutureClient(
                api_token="tok",
                session=MagicMock(spec=requests.Session),
                error_log_dir=self.log_dir,
            )
            self.assertTrue(default_client.verify_ssl)

        with patch.dict(os.environ, {"RF_VERIFY_SSL": "false"}, clear=True):
            with patch.object(config_mod, "_SSL_WARNINGS_SUPPRESSED", False):
                with patch("soclens.config.urllib3.disable_warnings") as mock_disable:
                    sess = MagicMock(spec=requests.Session)
                    env_client = RecordedFutureClient(
                        api_token="tok",
                        session=sess,
                        error_log_dir=self.log_dir,
                    )
                    self.assertFalse(env_client.verify_ssl)
                    self.assertFalse(sess.verify)
                    mock_disable.assert_called_once()

        with patch.dict(os.environ, {"RF_CA_BUNDLE": "/etc/ssl/corp.pem"}, clear=True):
            ca_client = RecordedFutureClient(
                api_token="tok",
                session=MagicMock(spec=requests.Session),
                error_log_dir=self.log_dir,
            )
            self.assertEqual(ca_client.verify_ssl, "/etc/ssl/corp.pem")

        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.request.return_value = _make_response(200, {"ok": True})
        client = RecordedFutureClient(
            api_token="tok",
            session=mock_sess,
            error_log_dir=self.log_dir,
            insecure=True,
        )
        self.assertFalse(client.verify_ssl)
        client._request("GET", "/test-ssl")
        self.assertIs(mock_sess.request.call_args.kwargs["verify"], False)

        self.assertTrue(client.set_verify_ssl(True))
        self.assertTrue(client.verify_ssl)
        self.assertTrue(mock_sess.verify)
        client._request("GET", "/test-ssl")
        self.assertIs(mock_sess.request.call_args.kwargs["verify"], True)

    @patch("soclens.client.time.sleep")
    def test_ssl_error_fails_fast_with_proxy_guidance(self, mock_sleep: MagicMock) -> None:
        self.mock_session.request.side_effect = requests.exceptions.SSLError(
            "CERTIFICATE_VERIFY_FAILED: self signed certificate in certificate chain"
        )
        with self.assertRaises(RecordedFutureAPIError) as ctx:
            self.client._request("GET", "/v2/ip/8.8.8.8", retries=4, backoff=1.0)

        self.assertEqual(ctx.exception.reason, "ssl_error")
        self.assertIn("--insecure", str(ctx.exception))
        self.assertIn("RF_VERIFY_SSL=false", str(ctx.exception))
        self.assertEqual(self.mock_session.request.call_count, 1)
        mock_sleep.assert_not_called()

        err_file = self.log_dir / "rf_api_errors.jsonl"
        record = json.loads(err_file.read_text(encoding="utf-8").strip().splitlines()[-1])
        self.assertEqual(record["category"], "ssl_error")
        self.assertEqual(record["reason"], "ssl_error")

    def test_self_signed_https_proxy_server_end_to_end(self) -> None:
        openssl_bin = shutil.which("openssl")
        if not openssl_bin:
            self.skipTest("openssl binary not available")

        cert_path = Path(self._tmpdir.name) / "proxy.crt"
        key_path = Path(self._tmpdir.name) / "proxy.key"
        subprocess.run(
            [
                openssl_bin,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                body = json.dumps({"id": "report:ssl-ok", "name": "SSL Proxy OK"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
        port = httpd.server_address[1]
        thread = threading.Thread(
            target=httpd.serve_forever,
            kwargs={"poll_interval": 0.005},
            daemon=True,
        )
        thread.start()

        https_url = f"https://127.0.0.1:{port}"
        try:
            with patch.dict(os.environ, {}, clear=True):
                strict_client = RecordedFutureClient(
                    base_url=https_url,
                    api_token="tok",
                    error_log_dir=self.log_dir,
                )
                with self.assertRaises(RecordedFutureAPIError) as exc_ctx:
                    strict_client.get_list_info("report:ssl-ok")
                self.assertEqual(exc_ctx.exception.reason, "ssl_error")

                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always", urllib3.exceptions.InsecureRequestWarning)
                    with patch.object(config_mod, "_SSL_WARNINGS_SUPPRESSED", False):
                        insecure_client = RecordedFutureClient(
                            base_url=https_url,
                            api_token="tok",
                            verify_ssl=False,
                            error_log_dir=self.log_dir,
                        )
                        info_insecure = insecure_client.get_list_info("report:ssl-ok")
                self.assertEqual(info_insecure["id"], "report:ssl-ok")
                insecure_warnings = [
                    w
                    for w in caught
                    if issubclass(w.category, urllib3.exceptions.InsecureRequestWarning)
                ]
                self.assertEqual(insecure_warnings, [])

                ca_client = RecordedFutureClient(
                    base_url=https_url,
                    api_token="tok",
                    verify_ssl=str(cert_path),
                    error_log_dir=self.log_dir,
                )
                info_ca = ca_client.get_list_info("report:ssl-ok")
                self.assertEqual(info_ca["name"], "SSL Proxy OK")
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2.0)

    def test_remove_entity_resolves_non_auto_resolved_types_and_validates_list_id(self) -> None:
        # 1. Company removed by name resolves via GET /list/{id}/entities to opaque digitless/hyphenated ID
        for opaque_id in ("iuiKOZ", "lqJmC-"):
            self.mock_session.request.reset_mock()
            self.mock_session.request.side_effect = [
                _make_response(
                    200,
                    [
                        {
                            "entity": {
                                "id": opaque_id,
                                "type": "Company",
                                "name": "Colonial Federal Savings Bank",
                            },
                            "context": {"annotation": "1015"},
                        }
                    ],
                ),
                _make_response(200, {"result": "removed"}),
            ]
            res = self.client.remove_entity(
                "report:fOqHJL",
                "Colonial Federal Savings Bank",
                entity_type="Company",
            )
            self.assertEqual(res, {"result": "removed"})
            self.assertEqual(self.mock_session.request.call_count, 2)
            self.assertEqual(
                self.mock_session.request.call_args_list[0].kwargs["method"],
                "GET",
            )
            self.assertTrue(
                self.mock_session.request.call_args_list[0]
                .kwargs["url"]
                .endswith("/list/report:fOqHJL/entities")
            )
            self.assertEqual(
                self.mock_session.request.call_args_list[1].kwargs["json"],
                {"entity": {"id": opaque_id}},
            )

        # 2. Removing a Company by digitless opaque ID with entity_type="Company" resolves via list members
        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = [
            _make_response(
                200,
                [
                    {
                        "entity": {
                            "id": "iuiKOZ",
                            "type": "Company",
                            "name": "Colonial Federal Savings Bank",
                        },
                        "context": {"annotation": "1015"},
                    }
                ],
            ),
            _make_response(200, {"result": "removed"}),
        ]
        res_by_id = self.client.remove_entity("report:fOqHJL", "iuiKOZ", entity_type="Company")
        self.assertEqual(res_by_id, {"result": "removed"})
        self.assertEqual(self.mock_session.request.call_count, 2)
        self.assertEqual(
            self.mock_session.request.call_args_list[1].kwargs["json"],
            {"entity": {"id": "iuiKOZ"}},
        )

        # 3. Company absent from list falls back to entity_match (returns unchanged cleanly)
        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = [
            _make_response(200, []),
            _make_response(200, [{"id": "iuiKOZ", "name": "Colonial Federal Savings Bank", "type": "Company"}]),
            _make_response(200, {"result": "unchanged"}),
        ]
        res_fallback = self.client.remove_entity(
            "report:fOqHJL",
            "Colonial Federal Savings Bank",
            entity_type="Company",
        )
        self.assertEqual(res_fallback, {"result": "unchanged"})
        self.assertEqual(self.mock_session.request.call_count, 3)
        self.assertEqual(
            self.mock_session.request.call_args_list[2].kwargs["json"],
            {"entity": {"id": "iuiKOZ"}},
        )

        # 4. Unresolvable Company in both list and entity_match raises RecordedFutureAPIError(404)
        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = [
            _make_response(200, []),
            _make_response(200, []),
        ]
        with self.assertRaises(RecordedFutureAPIError) as exc_404:
            self.client.remove_entity(
                "report:fOqHJL",
                "Nonexistent Bank Corp",
                entity_type="Company",
            )
        self.assertEqual(exc_404.exception.status_code, 404)
        self.assertEqual(exc_404.exception.reason, "entity_not_found")

        # 5. Ambiguous duplicate entity names in list raises ValueError without deleting
        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = [
            _make_response(
                200,
                [
                    {"entity": {"id": "cmp:1", "type": "Company", "name": "Acme Bank"}},
                    {"entity": {"id": "cmp:2", "type": "Company", "name": "Acme Bank"}},
                ],
            ),
        ]
        with self.assertRaises(ValueError):
            self.client.remove_entity("report:fOqHJL", "Acme Bank", entity_type="Company")
        self.mock_session.request.assert_called_once()

        # 6. URL absent from list resolves via ENTITY_ID_PREFIXES to {"id": "url:..."}
        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = [
            _make_response(200, []),
            _make_response(200, []),
            _make_response(200, {"result": "unchanged"}),
        ]
        res_url = self.client.remove_entity(
            "report:fOqHJL",
            "https://evil.example/login",
            entity_type="URL",
        )
        self.assertEqual(res_url, {"result": "unchanged"})
        self.assertEqual(
            self.mock_session.request.call_args_list[2].kwargs["json"],
            {"entity": {"id": "url:https://evil.example/login"}},
        )

        # 7. is_id=True bypasses list lookup in 1 call; resolve=False preserves raw _build_entity_ref
        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = None
        self.mock_session.request.return_value = _make_response(200, {"result": "removed"})
        self.client.remove_entity("report:fOqHJL", "iuiKOZ", entity_type="Company", is_id=True)
        self.mock_session.request.assert_called_once()
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["json"],
            {"entity": {"id": "iuiKOZ"}},
        )

        self.mock_session.request.reset_mock()
        self.client.remove_entity(
            "report:fOqHJL",
            "Colonial Federal Savings Bank",
            entity_type="Company",
            resolve=False,
        )
        self.mock_session.request.assert_called_once()
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["json"],
            {"entity": {"type": "Company", "name": "Colonial Federal Savings Bank"}},
        )

        # 8. list_id whitespace/empty validation & URL quoting for add_entity, remove_entity, replace_entity_tags
        for bad_call in (
            lambda: self.client.add_entity("   ", "InternetDomainName", "bad.com"),
            lambda: self.client.remove_entity("   ", "idn:bad.com"),
            lambda: self.client.replace_entity_tags("   ", "cmp_1", ["tag1"]),
        ):
            with self.assertRaises(ValueError):
                bad_call()

        self.mock_session.request.reset_mock()
        self.client.add_entity("  report:wl/1  ", "InternetDomainName", "bad.com")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/list/report:wl%2F1/entity/add"
            )
        )
        self.client.remove_entity("  report:wl/1  ", "idn:bad.com")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/list/report:wl%2F1/entity/remove"
            )
        )
        self.client.replace_entity_tags("  report:wl/1  ", {"id": "cmp_1"}, ["tag1"])
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/list/report:wl%2F1/entity/tags"
            )
        )

    def test_proxysg_trailing_slash_for_domain_url_and_entity_paths(self) -> None:
        self.mock_session.request.return_value = _make_response(200, {"data": {}})

        # Connect v2 domain lookups always include trailing '/' to avoid ProxySG
        # blocking '.com' / '.sh' / '.zip' paths as executable downloads.
        self.client.v2_lookup("domain", "example.com", fields=["entity", "risk"])
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith("/v2/domain/example.com/")
        )

        # User-supplied trailing '/' on a domain is normalized without '%2F' or '//'.
        self.client.v2_lookup("domain", "example.com/")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith("/v2/domain/example.com/")
        )

        self.client.v2_lookup("domain", "idn:example.com")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/v2/domain/idn:example.com/"
            )
        )

        # Company-by-domain also ends in a domain TLD and gets a trailing '/'.
        self.client.v2_company_by_domain("example.com")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/v2/company/by_domain/example.com/"
            )
        )
        self.client.v2_company_by_domain("example.com/")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/v2/company/by_domain/example.com/"
            )
        )

        # URL lookups whose encoded path ends in a TLD/file extension (e.g. '.com', '.exe')
        # get a trailing '/', while non-extension paths stay unchanged.
        self.client.v2_lookup("url", "https://example.com")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/v2/url/url:https%3A%2F%2Fexample.com/"
            )
        )
        self.client.v2_lookup("url", "https://evil.org/dropper.exe")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/v2/url/url:https%3A%2F%2Fevil.org%2Fdropper.exe/"
            )
        )

        # IP lookups do NOT receive a trailing '/' (numeric octet, not file extension).
        self.client.v2_lookup("ip", "8.8.8.8")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith("/v2/ip/8.8.8.8")
        )

        # Entity lookup appends '/' for domain/email/url IDs ending in extensions,
        # but leaves opaque IDs untouched.
        self.client.entity_lookup("idn:example.com")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/entity-match/entity/idn:example.com/"
            )
        )
        self.client.entity_lookup("idn:example.com/")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/entity-match/entity/idn:example.com/"
            )
        )
        self.client.entity_lookup("email:analyst@example.com")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/entity-match/entity/email:analyst%40example.com/"
            )
        )
        self.client.entity_lookup("company:abc123")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/entity-match/entity/company:abc123"
            )
        )

    def test_classify_403_detects_proxysg_html_block_page(self) -> None:
        self.mock_session.request.return_value = _make_response(
            403,
            text="<html><head><title>Access Denied</title></head><body>ProxySG policy_denied: .com executable blocked</body></html>",
        )
        with self.assertRaises(RecordedFutureAuthError) as ctx:
            self.client._request("GET", "/v2/domain/example.com")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.permission_type, "proxy_blocked")


if __name__ == "__main__":
    unittest.main()
