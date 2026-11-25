"""Offline mocked unit tests for all RecordedFutureClient research APIs."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import requests

from soclens.client import RecordedFutureClient
from soclens.config import ConfigurationError


def _resp(
    status_code: int = 200,
    json_data: object = None,
    *,
    text: str = "",
    content: bytes = b"",
    headers: dict[str, str] | None = None,
) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data
    r.text = text
    r.content = content
    r.headers = headers or {}
    return r


class TestClientResearchAPIs(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.log_dir = Path(self._tmp.name) / "logs"
        self.mock_session = MagicMock(spec=requests.Session)
        self.client = RecordedFutureClient(
            api_token="core_tok",
            sandbox_token="sb_tok",
            asi_api_key="asi_key",
            pfi_token="pfi_tok",
            riskrecon_token="rr_tok",
            session=self.mock_session,
            error_log_dir=self.log_dir,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_auth_modes_and_missing_credentials(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            bare = RecordedFutureClient(error_log_dir=self.log_dir)
            with self.assertRaises(ConfigurationError):
                bare._get_headers(auth_mode="asi")
            with self.assertRaises(ConfigurationError):
                bare._get_headers(auth_mode="pfi")
            with self.assertRaises(ConfigurationError):
                bare._get_headers(auth_mode="riskrecon")
            with self.assertRaises(ConfigurationError):
                bare._get_headers(auth_mode="taxii2")

        self.assertEqual(self.client._get_headers(auth_mode="asi")["apikey"], "asi_key")
        self.assertEqual(self.client._get_headers(auth_mode="pfi")["X-RFToken"], "pfi_tok")
        self.assertEqual(
            self.client._get_headers(auth_mode="riskrecon")["Authorization"],
            "Bearer rr_tok",
        )
        self.assertEqual(
            self.client._get_headers(auth_mode="taxii2")["Accept"],
            "application/taxii+json;version=2.1",
        )

    def test_v2_fields_and_extensions(self) -> None:
        self.mock_session.request.return_value = _resp(
            200, {"data": {"results": ["entity", "risk"]}}
        )
        res = self.client.v2_fields("ip")
        self.assertEqual(res["data"]["results"], ["entity", "risk"])
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["url"],
            "https://api.recordedfuture.com/v2/ip/fields",
        )

        self.mock_session.request.return_value = _resp(200, {"data": {"greynoise": {}}})
        ext = self.client.v2_lookup_extension(
            "url", "https://evil.example/a/b", "active_bitdefender", metadata=True
        )
        self.assertIn("data", ext)
        call_kw = self.mock_session.request.call_args.kwargs
        self.assertIn("/v2/url/url:https%3A%2F%2Fevil.example%2Fa%2Fb/extension/active_bitdefender", call_kw["url"])
        self.assertEqual(call_kw["params"], {"metadata": "true"})

        with self.assertRaises(ValueError):
            self.client.v2_lookup_extension("company", "id1", "any")

    def test_links_graph_search_and_metadata(self) -> None:
        self.mock_session.request.return_value = _resp(200, {"data": [{"links": []}]})
        self.client.links_search(
            ["ip:8.8.8.8"],
            sections=["sec1"],
            entity_types=["type:InternetDomainName"],
            sources=["technical"],
            timeframe="-7d",
            events=["type:MalwareAnalysis"],
            connected_entities=["idn:google.com"],
            search_scope="large",
            per_entity_type=15,
        )
        kw = self.mock_session.request.call_args.kwargs
        self.assertEqual(kw["method"], "POST")
        self.assertTrue(kw["url"].endswith("/links/search"))
        self.assertEqual(kw["json"]["limits"], {"search_scope": "large", "per_entity_type": 15})
        self.assertEqual(kw["json"]["filters"]["technical"]["timeframe"], "-7d")

        self.mock_session.request.return_value = _resp(200, {"data": []})
        self.client.links_metadata_entities()
        self.assertTrue(self.mock_session.request.call_args.kwargs["url"].endswith("/links/metadata/entities"))
        self.client.links_metadata_events()
        self.assertTrue(self.mock_session.request.call_args.kwargs["url"].endswith("/links/metadata/events"))
        self.client.links_metadata_sections()
        self.assertTrue(self.mock_session.request.call_args.kwargs["url"].endswith("/links/metadata/sections"))

    def test_analyst_notes_search_pagination_lookup_and_export(self) -> None:
        self.mock_session.request.side_effect = [
            _resp(200, {"data": [{"id": "note:1"}], "next_offset": "cur1"}),
            _resp(200, {"data": [{"id": "note:2"}]}),
        ]
        res = self.client.search_analyst_notes(
            topic="Flash Report", published="-7d", paginate=True, limit=10
        )
        self.assertEqual(len(res["data"]), 2)
        first_body = self.mock_session.request.call_args_list[0].kwargs["json"]
        second_body = self.mock_session.request.call_args_list[1].kwargs["json"]
        self.assertEqual(first_body["topic"], "TXSFt0")
        self.assertEqual(second_body["from"], "cur1")

        self.mock_session.request.side_effect = None
        self.mock_session.request.return_value = _resp(200, {"id": "note:1", "attributes": {"title": "T"}})
        note = self.client.lookup_analyst_note("note:1", tagged_text=True, escape_html=True)
        self.assertEqual(note["id"], "note:1")
        self.assertEqual(self.mock_session.request.call_args.kwargs["method"], "POST")
        self.assertTrue(self.mock_session.request.call_args.kwargs["url"].endswith("/analyst-note/lookup/note:1"))

        self.mock_session.request.return_value = _resp(200, content=b"PDFBYTES")
        self.assertEqual(self.client.get_analyst_note_attachment("note:1"), b"PDFBYTES")
        self.assertEqual(self.client.export_analyst_note("note:1", "pdf"), b"PDFBYTES")
        with self.assertRaises(ValueError):
            self.client.export_analyst_note("note:1", "docx")

    def test_threat_maps_and_actors(self) -> None:
        self.mock_session.request.return_value = _resp(200, {"data": []})
        self.client.get_threat_maps()
        self.assertTrue(self.mock_session.request.call_args.kwargs["url"].endswith("/threat/maps"))

        self.client.get_threat_actor_map(actors=["O7NRMb"])
        self.assertTrue(self.mock_session.request.call_args.kwargs["url"].endswith("/threat/map/actors"))

        self.client.get_threat_actor_map(org_id="uhash:123", watchlists=["report:abc"])
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith("/threat/map/uhash:123/actors")
        )

        self.mock_session.request.side_effect = [
            _resp(200, {"data": [{"id": "A1"}], "next_offset": "o1"}),
            _resp(200, {"data": [{"id": "A2"}]}),
        ]
        actors = self.client.search_threat_actors(name="APT29", limit=5, paginate=True)
        self.assertEqual(len(actors["data"]), 2)

        self.mock_session.request.side_effect = None
        self.mock_session.request.return_value = _resp(200, {"data": []})
        self.client.get_threat_actor_categories()
        self.client.get_malware_threat_map(org_id="uhash:123", malware=["Yzaz0L"])
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith("/threat/map/uhash:123/malware")
        )
        self.client.get_malware_categories()

    def test_malware_intelligence_endpoints_and_date_clamping(self) -> None:
        self.mock_session.request.return_value = _resp(200, {"data": [{"name": "deadbeef"}]})
        self.client.malware_intel_query(
            "dynamic.network.flows.dst_port == 443",
            field="sha256",
            start_date="2020-01-01",
        )
        body = self.mock_session.request.call_args.kwargs["json"]
        self.assertEqual(body["start_date"], "2023-11-01")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith("/malware-intelligence/v1/query")
        )

        self.client.malware_intel_query_nl("cobalt strike c2", field="ip_address")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith("/malware-intelligence/v1/query_nl")
        )

        self.client.malware_intel_query_iocs(ip_list=["1.2.3.4"], operator="and")
        self.assertEqual(self.mock_session.request.call_args.kwargs["json"]["operator"], "and")

        self.client.malware_intel_sandbox_reports("a" * 64, "family:cobalt")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith("/malware-intelligence/v1/reports")
        )

        with self.assertRaises(ValueError):
            self.client.malware_intel_query("x", field="bad_field")
        with self.assertRaises(ValueError):
            self.client.malware_intel_query_iocs()

    def test_risk_identity_collective_and_fusion(self) -> None:
        self.mock_session.request.return_value = _resp(200, {"data": []})
        self.client.search_risk_history(["ip:8.8.8.8"], start_date="2026-01-01", end_date="2026-02-01")
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["json"],
            {"entities": ["ip:8.8.8.8"], "from": "2026-01-01", "to": "2026-02-01"},
        )
        self.client.get_active_company_risk_rule("B_E7B", "openPort", limit=10, offset=5)
        self.assertTrue(self.mock_session.request.call_args.kwargs["url"].endswith("/risk/active/rule"))

        self.mock_session.request.return_value = _resp(200, {"identities": []})
        self.client.identity_detections(domains=["example.com"], novel_only=True, malware_only=True)
        self.client.identity_search(domains=["example.com"], domain_types=["Email"])
        self.client.identity_lookup(subjects=["user@example.com"])
        self.client.identity_password_lookup([{"algorithm": "SHA1", "prefix": "14659"}])
        self.client.identity_hostname_lookup("vpn.example.com")
        self.client.identity_ip_lookup(ip="198.51.100.1")
        self.client.identity_incident_report("stealer_log_1")
        self.client.identity_dump_metadata(names=["linkedin"])

        self.mock_session.request.return_value = _resp(200, {"data": []})
        self.client.search_collective_insights(filters={"indicator_type": "ip"})
        self.client.list_collective_insights_exclusions("uhash:org1")

        self.mock_session.request.return_value = _resp(
            200, {"files": []}, headers={"ETag": '"etag1"'}, content=b"col1,col2\n"
        )
        self.client.fusion_list_directory("public/Anomali")
        self.assertTrue(
            self.mock_session.request.call_args.kwargs["url"].endswith(
                "/fusion/v3/files/directory/%2Fpublic%2FAnomali"
            )
        )
        hdrs = self.client.fusion_stat_file("/public/feed.csv")
        self.assertEqual(hdrs["ETag"], '"etag1"')
        self.assertEqual(self.client.fusion_get_file("/public/feed.csv"), b"col1,col2\n")

    def test_sandbox_alerts_cases_ato_taxii2_and_external_platforms(self) -> None:
        self.mock_session.request.return_value = _resp(200, {"data": []}, content=b"PNG")
        self.client.sandbox_list_samples(subset="public", limit=10)
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["headers"]["Authorization"],
            "Bearer sb_tok",
        )
        self.client.sandbox_get_summary("smp1")
        self.client.sandbox_get_static_report("smp1")
        self.client.sandbox_get_dynamic_report("smp1", "behavioral1")
        self.client.sandbox_get_url_scan_report("smp1")
        self.assertEqual(self.client.sandbox_get_url_scan_screenshot("smp1"), b"PNG")
        self.client.sandbox_list_yara_rules()
        self.client.sandbox_get_yara_rule("rule.yar")

        self.client.search_alert_rules(freetext="ransomware")
        self.assertEqual(self.client.get_alert_v3_image("img:1"), b"PNG")
        self.client.get_playbook_alert_metadata()
        self.client.get_case_eligible_assignees("case1", text="alice")

        self.mock_session.request.return_value = _resp(200, [{"id": "src1"}])
        self.assertEqual(self.client.ato_list_sources(), [{"id": "src1"}])
        self.mock_session.request.return_value = _resp(200, {"items": []})
        self.client.ato_query_profiles("hunting")
        self.client.ato_get_profile_indicators("detection", "prof1")
        self.client.ato_get_profile_rules("prevention", "prof1")

        self.mock_session.request.return_value = _resp(200, {"title": "TAXII"})
        self.client.taxii2_discover()
        kw = self.mock_session.request.call_args.kwargs
        self.assertEqual(kw["auth"], ("", "core_tok"))
        self.assertEqual(kw["headers"]["Accept"], "application/taxii+json;version=2.1")
        self.client.taxii2_get_collections("large")
        self.client.taxii2_get_objects("col1", api_root="default", limit=50)

        # ASI
        self.mock_session.request.return_value = _resp(200, {"data": []})
        self.client.asi_list_projects()
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["url"],
            "https://api.securitytrails.com/v2/projects",
        )
        self.assertEqual(self.mock_session.request.call_args.kwargs["headers"]["apikey"], "asi_key")
        self.client.asi_find_assets("proj1", apex="example.com")
        self.client.asi_search_assets("proj1", filter_obj={"quick_search": {}})
        self.client.asi_read_asset("proj1", "example.com")
        self.client.asi_list_asset_exposures("proj1", "example.com")
        self.client.asi_list_exposures("proj1", filter_cve_id="CVE-2021-44228")
        self.client.asi_get_exposure_assets("proj1", "sig1")
        self.client.asi_list_signatures("proj1")
        self.client.asi_get_signature("proj1", "sig1")

        # PFI
        self.client.pfi_list_tasks()
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["url"],
            "https://pfi.regemini.com/api/v1/task/list",
        )
        self.client.pfi_get_task_status("task1")
        self.client.pfi_query_pipeline("cards_full", dry_run=True)
        self.assertEqual(self.mock_session.request.call_args.kwargs["method"], "PUT")
        self.mock_session.request.return_value = _resp(200, text='{"a": 1}\n{"a": 2}\n')
        ndjson = self.client.pfi_pickup_data("task1", fmt="json")
        self.assertEqual(ndjson, [{"a": 1}, {"a": 2}])
        self.assertEqual(self.mock_session.request.call_args.kwargs["method"], "POST")
        self.assertTrue(self.mock_session.request.call_args.kwargs["url"].endswith("/file/task1"))

        # RiskRecon
        self.mock_session.request.return_value = _resp(200, [{"toe_id": "t1"}])
        self.assertEqual(self.client.riskrecon_list_toes(), [{"toe_id": "t1"}])
        self.assertEqual(
            self.mock_session.request.call_args.kwargs["headers"]["Authorization"],
            "Bearer rr_tok",
        )
        self.client.riskrecon_lookup_by_domain("example.com")
        self.client.riskrecon_lookup_by_cve("CVE-2021-44228")
        self.mock_session.request.return_value = _resp(200, {"data": []})
        self.client.riskrecon_get_ratings("t1")
        self.client.riskrecon_get_findings("t1", severity="critical")
        self.client.riskrecon_get_breach_events()
        self.mock_session.request.return_value = _resp(200, [{"ip_addr": "1.1.1.1"}])
        self.assertEqual(self.client.riskrecon_get_hosts("t1"), [{"ip_addr": "1.1.1.1"}])

    def test_search_detection_rules_paginate_toggle(self) -> None:
        self.mock_session.request.side_effect = [
            _resp(200, {"result": [{"id": "rule-1"}], "next_offset": "cursor-1"}),
            _resp(200, {"result": [{"id": "rule-2"}]}),
        ]
        single_page = self.client.search_detection_rules(
            rule_types=["sigma"],
            limit=1,
            paginate=False,
        )
        self.assertEqual(single_page, [{"id": "rule-1"}])
        self.assertEqual(self.mock_session.request.call_count, 1)

        self.mock_session.request.reset_mock()
        self.mock_session.request.side_effect = [
            _resp(200, {"result": [{"id": "rule-1"}], "next_offset": "cursor-1"}),
            _resp(200, {"result": [{"id": "rule-2"}]}),
        ]
        all_pages = self.client.search_detection_rules(
            rule_types=["sigma"],
            limit=1,
        )
        self.assertEqual(all_pages, [{"id": "rule-1"}, {"id": "rule-2"}])
        self.assertEqual(self.mock_session.request.call_count, 2)
        second_payload = self.mock_session.request.call_args_list[1].kwargs["json"]
        self.assertEqual(second_payload.get("offset"), "cursor-1")
