"""Unit tests for Splunk ES -> Recorded Future field mapping, batch enrichment, and CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from soclens import cli
from soclens.splunk_rf_enrichment import (
    DEFAULT_SPLUNK_RF_FIELD_MAP,
    ExtractedObservable,
    SplunkRFEnricher,
    extract_observables_from_event,
    format_notable_rf_comment,
    is_public_ip,
    load_splunk_rf_field_map,
    write_enrichment_to_notable,
)


class TestFieldMapAndIPHelpers:
    def test_load_default_field_map(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RF_SPLUNK_FIELD_MAP", raising=False)
        fmap = load_splunk_rf_field_map()
        assert set(fmap.keys()) == set(DEFAULT_SPLUNK_RF_FIELD_MAP.keys())
        assert "src_ip" in fmap["ip"]
        assert "dns_query" in fmap["domain"]
        assert "request_url" in fmap["url"]
        assert "sha256" in fmap["hash"]
        assert "cve" in fmap["vulnerability"]

    def test_load_field_map_env_string_and_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RF_SPLUNK_FIELD_MAP", "ip=src_ip,client_ip;domain=dns_query")
        fmap = load_splunk_rf_field_map()
        assert fmap["ip"] == ["src_ip", "client_ip"]
        assert fmap["domain"] == ["dns_query"]
        assert fmap["hash"] == list(DEFAULT_SPLUNK_RF_FIELD_MAP["hash"])

        overridden = load_splunk_rf_field_map({"ip": ["custom_ip"], "cve": ["vuln_id"]})
        assert overridden["ip"] == ["custom_ip"]
        assert overridden["domain"] == ["dns_query"]
        assert overridden["vulnerability"] == ["vuln_id"]

    def test_load_field_map_env_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "RF_SPLUNK_FIELD_MAP",
            json.dumps({"ip": ["edge_ip", "edge_ip"], "url": ["full_url"]}),
        )
        fmap = load_splunk_rf_field_map()
        assert fmap["ip"] == ["edge_ip"]
        assert fmap["url"] == ["full_url"]

    def test_load_field_map_invalid_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RF_SPLUNK_FIELD_MAP", raising=False)
        with pytest.raises(ValueError, match="Unsupported IOC type"):
            load_splunk_rf_field_map("unknown_type=foo")
        with pytest.raises(ValueError, match="Invalid field mapping segment"):
            load_splunk_rf_field_map("malformed_without_equals")
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_splunk_rf_field_map("{bad json")

    @pytest.mark.parametrize(
        ("addr", "expected"),
        [
            ("185.220.101.1", True),
            ("8.8.8.8", True),
            ("2606:4700:4700::1111", True),
            ("10.0.0.1", False),
            ("172.16.0.5", False),
            ("192.168.1.10", False),
            ("127.0.0.1", False),
            ("169.254.1.1", False),
            ("100.64.0.1", False),
            ("224.0.0.1", False),
            ("0.0.0.0", False),
            ("::1", False),
            ("fe80::1", False),
            ("fc00::1", False),
            ("not-an-ip", False),
            ("", False),
        ],
    )
    def test_is_public_ip(self, addr: str, expected: bool) -> None:
        assert is_public_ip(addr) is expected


class TestExtractObservables:
    def test_extracts_top_level_and_raw_deduplicated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("RF_SPLUNK_FIELD_MAP", raising=False)
        sha256 = "a" * 64
        event = {
            "event_id": "notable-1",
            "src": "185.220.101.1",
            "dest": "10.0.0.5",
            "raw": {
                "src_ip": "185.220.101.1",
                "client_ip": ["1.1.1.1", "192.168.1.2"],
                "dns_query": "Evil-C2.Example.COM.",
                "http_url": "https://evil-c2.example.com/beacon?id=1",
                "sha256": sha256.upper(),
                "cve": "cve-2024-3094",
                "dest_host": "localhost",
            },
        }
        obs = extract_observables_from_event(event)
        assert obs == [
            ExtractedObservable("ip", "185.220.101.1", "src"),
            ExtractedObservable("ip", "1.1.1.1", "client_ip"),
            ExtractedObservable("domain", "evil-c2.example.com", "dns_query"),
            ExtractedObservable("url", "https://evil-c2.example.com/beacon?id=1", "http_url"),
            ExtractedObservable("hash", sha256, "sha256"),
            ExtractedObservable("vulnerability", "CVE-2024-3094", "cve"),
        ]

    def test_include_private_ips_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RF_SPLUNK_FIELD_MAP", raising=False)
        event = {"src": "10.10.0.5", "dest": "192.168.1.50"}
        assert extract_observables_from_event(event, include_private_ips=False) == []
        obs = extract_observables_from_event(event, include_private_ips=True)
        assert obs == [
            ExtractedObservable("ip", "10.10.0.5", "src"),
            ExtractedObservable("ip", "192.168.1.50", "dest"),
        ]

    def test_custom_field_map_and_comma_multivalue(self) -> None:
        event = {"custom_ips": "8.8.8.8, 1.1.1.1", "custom_domain": "bad.example.org"}
        obs = extract_observables_from_event(
            event,
            field_map={"ip": ["custom_ips"], "domain": ["custom_domain"]},
        )
        assert obs == [
            ExtractedObservable("ip", "8.8.8.8", "custom_ips"),
            ExtractedObservable("ip", "1.1.1.1", "custom_ips"),
            ExtractedObservable("domain", "bad.example.org", "custom_domain"),
        ]


class TestSplunkRFEnricher:
    def test_batch_enrich_parses_data_list_and_caches(self) -> None:
        rf = MagicMock()
        rf.soar_enrich.side_effect = [
            {
                "data": [
                    {
                        "entity": {
                            "id": "ip:185.220.101.1",
                            "name": "185.220.101.1",
                            "type": "IpAddress",
                        },
                        "risk": {
                            "score": 92,
                            "level": 5,
                            "evidenceDetails": [
                                {
                                    "rule": "Active C2 Server",
                                    "criticality": 5,
                                    "evidenceString": "Observed C2 traffic",
                                }
                            ],
                        },
                        "links": {
                            "portal": "https://app.recordedfuture.com/live/sc/entity/ip:185.220.101.1"
                        },
                    },
                    {
                        "entity": {
                            "id": "idn:evil.example.com",
                            "name": "evil.example.com",
                            "type": "InternetDomainName",
                        },
                        "risk": {
                            "score": 68,
                            "level": 4,
                            "rules": [{"rule": "Recently Linked to Malware"}],
                        },
                    },
                ]
            },
            {
                "data": {
                    "results": [
                        {
                            "entity": {
                                "id": "ip:8.8.8.8",
                                "name": "8.8.8.8",
                                "type": "ip",
                            },
                            "risk": {
                                "score": 0,
                                "level": 1,
                                "evidenceDetails": [],
                            },
                        }
                    ]
                }
            },
        ]

        enricher = SplunkRFEnricher(rf, cache_ttl_seconds=300.0, batch_size=2)
        events = [
            {
                "event_id": "notable-1",
                "src": "185.220.101.1",
                "raw": {"dns_query": "evil.example.com"},
            },
            {
                "event_id": "notable-2",
                "src": "8.8.8.8",
                "dest": "10.0.0.1",
            },
            {
                "event_id": "notable-3",
                "src": "10.0.0.99",
            },
        ]

        enriched = enricher.enrich_events(events)
        assert rf.soar_enrich.call_count == 2
        # Original dicts must not be mutated
        assert "rf_max_risk_score" not in events[0]

        ev0 = enriched[0]
        assert ev0["rf_max_risk_score"] == 92
        assert ev0["rf_criticality_label"] == "Very Malicious"
        assert ev0["rf_top_ioc"] == "185.220.101.1"
        assert ev0["rf_top_field"] == "src=185.220.101.1"
        assert ev0["rf_rules_triggered"] == 2
        assert "Active C2 Server" in ev0["rf_evidence_summary"]
        assert len(ev0["rf_observables"]) == 2
        assert (
            ev0["rf_observables"][0]["intel_card_url"]
            == "https://app.recordedfuture.com/live/sc/entity/ip:185.220.101.1"
        )

        ev1 = enriched[1]
        assert ev1["rf_max_risk_score"] == 0
        assert ev1["rf_criticality_label"] == "Benign"
        assert ev1["rf_top_field"] == "src=8.8.8.8"

        ev2 = enriched[2]
        assert ev2["rf_max_risk_score"] is None
        assert ev2["rf_criticality_label"] == "No Data"
        assert ev2["rf_observables"] == []

        # Second call hits TTL cache with zero additional API requests
        enriched_again = enricher.enrich_events(events)
        assert rf.soar_enrich.call_count == 2
        assert enriched_again[0]["rf_max_risk_score"] == 92

    def test_comment_formatting_and_write_back_with_dry_run(self) -> None:
        enriched_ev = {
            "event_id": "notable-99",
            "rf_max_risk_score": 88,
            "rf_criticality_label": "Malicious",
            "rf_top_ioc": "185.220.101.1",
            "rf_top_field": "src_ip=185.220.101.1",
            "rf_rules_triggered": 1,
            "rf_evidence_summary": "Active C2 Server",
            "rf_observables": [
                {
                    "source_field": "src_ip",
                    "ioc_type": "ip",
                    "value": "185.220.101.1",
                    "risk_score": 88,
                    "criticality_label": "Malicious",
                    "evidence": [{"rule": "Active C2 Server", "evidence": "C2 hit"}],
                    "intel_card_url": "https://app.recordedfuture.com/live/sc/entity/ip:185.220.101.1",
                }
            ],
        }
        comment = format_notable_rf_comment(enriched_ev)
        assert "88/99 (Malicious)" in comment
        assert "src_ip=185.220.101.1" in comment
        assert "Active C2 Server" in comment

        es = MagicMock()
        es.update_notable.return_value = {"success": True}

        dry_res = write_enrichment_to_notable(es, "notable-99", enriched_ev, dry_run=True)
        assert dry_res["dry_run"] is True
        assert "88/99" in dry_res["comment"]
        es.update_notable.assert_not_called()

        live_res = write_enrichment_to_notable(es, "notable-99", enriched_ev, dry_run=False)
        assert live_res["dry_run"] is False
        es.update_notable.assert_called_once_with(["notable-99"], comment=comment)


class TestSplunkESEnrichCLI:
    def _make_fake_es(self) -> MagicMock:
        es = MagicMock()
        es.app = "SplunkEnterpriseSecuritySuite"
        es.__enter__.return_value = es
        es.__exit__.return_value = None
        es.list_notables.return_value = [
            {
                "event_id": "notable-cli-1",
                "rule_name": "RF C2 Beacon",
                "urgency": "high",
                "status": 1,
                "status_label": "New",
                "owner": "unassigned",
                "src": "185.220.101.1",
                "dest": "10.0.0.5",
                "_time": "2026-11-24T12:00:00Z",
                "raw": {"src_ip": "185.220.101.1"},
            }
        ]
        es.client = MagicMock()
        es.client.run_search.return_value = {
            "status": "success",
            "results": [{"_time": "2026-11-24T12:00:00Z", "custom_ip": "185.220.101.1"}],
        }
        es.update_notable.return_value = {"success": True}
        return es

    def _make_fake_rf(self) -> MagicMock:
        rf = MagicMock()
        rf.soar_enrich.return_value = {
            "data": [
                {
                    "entity": {"id": "ip:185.220.101.1", "name": "185.220.101.1", "type": "ip"},
                    "risk": {
                        "score": 91,
                        "level": 5,
                        "evidenceDetails": [{"rule": "Active C2 Server"}],
                    },
                }
            ]
        }
        return rf

    def test_cli_splunk_es_enrich_json_and_dry_run_comments(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        fake_es = self._make_fake_es()
        fake_rf = self._make_fake_rf()
        out_file = tmp_path / "enriched.json"

        argv = [
            "soclens",
            "splunk",
            "es",
            "enrich",
            "--earliest",
            "-12h",
            "--urgency",
            "high",
            "--write-comments",
            "--dry-run",
            "--format",
            "json",
            "--output",
            str(out_file),
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(cli, "_build_splunk_es_client_from_args", return_value=fake_es),
            patch.object(cli, "_build_rf_client", return_value=fake_rf),
        ):
            cli.main()

        captured = capsys.readouterr()
        payload: dict[str, Any] = json.loads(captured.out)
        assert payload["count"] == 1
        assert payload["enriched_count"] == 1
        assert payload["events"][0]["rf_max_risk_score"] == 91
        assert payload["events"][0]["rf_criticality_label"] == "Very Malicious"
        assert payload["comments"][0]["dry_run"] is True
        fake_es.update_notable.assert_not_called()
        assert out_file.exists()

    def test_cli_splunk_es_enrich_custom_spl_field_map_and_csv(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        fake_es = self._make_fake_es()
        fake_rf = self._make_fake_rf()

        argv = [
            "soclens",
            "splunk",
            "es",
            "enrich",
            "--spl",
            "index=firewall | head 5",
            "--field-map",
            "ip=custom_ip",
            "--format",
            "csv",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(cli, "_build_splunk_es_client_from_args", return_value=fake_es),
            patch.object(cli, "_build_rf_client", return_value=fake_rf),
        ):
            cli.main()

        out = capsys.readouterr().out
        assert "rf_max_risk_score" in out
        assert "91" in out
        assert "custom_ip=185.220.101.1" in out
        fake_es.client.run_search.assert_called_once()

    def test_cli_splunk_es_enrich_write_comments_live_and_table(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        fake_es = self._make_fake_es()
        fake_rf = self._make_fake_rf()

        argv = [
            "soclens",
            "splunk",
            "es",
            "enrich",
            "--write-comments",
            "--format",
            "table",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(cli, "_build_splunk_es_client_from_args", return_value=fake_es),
            patch.object(cli, "_build_rf_client", return_value=fake_rf),
        ):
            cli.main()

        out = capsys.readouterr().out
        assert "RF C2 Beacon" in out
        assert "Very Malicious" in out
        assert "Posted RF enrichment comment(s) for 1 notable(s)." in out
        fake_es.update_notable.assert_called_once()
