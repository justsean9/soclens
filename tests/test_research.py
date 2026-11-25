"""Offline unit tests for soclens.research target resolution, dossier engine & exports."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from soclens.client import RecordedFutureAPIError, RecordedFutureAuthError
from soclens.config import ConfigurationError
from soclens.research import (
    classify_research_target,
    export_dossier_json,
    export_dossier_markdown,
    probe_api_capabilities,
    render_dossier_markdown,
    research_target,
    resolve_research_target,
)


def test_classify_research_target_all_kinds() -> None:
    with pytest.raises(ValueError):
        classify_research_target("   ")

    assert classify_research_target("8.8.8.8").entity_id == "ip:8.8.8.8"
    assert classify_research_target("2001:4860:4860::8888").detected_kind == "ip"
    dom = classify_research_target("Example.COM")
    assert (dom.detected_kind, dom.entity_id, dom.v2_type) == ("domain", "idn:example.com", "domain")

    h_sha256 = "a" * 64
    assert classify_research_target(h_sha256).entity_id == f"hash:{h_sha256}"
    assert classify_research_target("b" * 40).detected_kind == "hash"
    assert classify_research_target("c" * 32).detected_kind == "hash"

    u = classify_research_target("https://bad.example/login.php")
    assert (u.detected_kind, u.extracted_domain) == ("url", "bad.example")

    cve = classify_research_target("cve-2021-44228")
    assert (cve.detected_kind, cve.canonical_name, cve.entity_id) == (
        "vulnerability",
        "CVE-2021-44228",
        None,
    )

    em = classify_research_target("alice@example.org")
    assert (em.detected_kind, em.entity_id, em.extracted_domain) == (
        "email",
        "email:alice@example.org",
        "example.org",
    )

    assert classify_research_target("T1566.002").entity_id == "mitre:T1566.002"
    assert classify_research_target("TA0001").entity_id == "mitre:TA0001"
    assert classify_research_target("AS15169").entity_id == "asn:AS15169"
    assert classify_research_target("bitcoin:13d650aaf08f").detected_kind == "entity_id"
    assert classify_research_target("Cobalt Strike", explicit_type="malware").detected_kind == "malware"
    assert classify_research_target("APT29", explicit_type="actor").detected_kind == "actor"
    assert classify_research_target("Microsoft", explicit_type="company").detected_kind == "company"
    assert classify_research_target("LockBit ransomware").detected_kind == "text"


def test_resolve_research_target_cve_actor_malware_and_fallback() -> None:
    client = MagicMock()
    client.entity_match.return_value = [
        {"id": "JLHNoH", "name": "CVE-2021-44228", "type": "CyberVulnerability"}
    ]
    res_cve = resolve_research_target(client, "CVE-2021-44228")
    assert res_cve.entity_id == "JLHNoH"
    assert res_cve.v2_lookup_id == "JLHNoH"

    # Fallback to v2_search when entity_match returns empty
    client.entity_match.return_value = []
    client.v2_search.return_value = {
        "data": {"results": [{"entity": {"id": "lVuFZE", "name": "CVE-2021-45046", "type": "CyberVulnerability"}}]}
    }
    res_cve2 = resolve_research_target(client, "CVE-2021-45046")
    assert res_cve2.entity_id == "lVuFZE"

    # Threat actor resolution via search_threat_actors
    client.search_threat_actors.return_value = {
        "data": [
            {
                "id": "O7NRMb",
                "type": "Organization",
                "attributes": {"name": "BlueBravo", "common_names": ["APT29", "Midnight Blizzard"]},
            }
        ]
    }
    res_actor = resolve_research_target(client, "APT29", explicit_type="actor")
    assert res_actor.entity_id == "O7NRMb"
    assert res_actor.canonical_name == "BlueBravo"
    assert "APT29" in res_actor.aliases

    # Opaque entity_id lookup
    client.entity_lookup.return_value = {
        "id": "Yzaz0L",
        "name": "AsyncRAT",
        "type": "Malware",
        "aliases": ["AsyncRAT"],
    }
    res_eid = resolve_research_target(client, "Yzaz0L", explicit_type="entity_id")
    assert res_eid.detected_kind == "malware"
    assert res_eid.v2_type == "malware"


def test_research_target_dossier_fanout_fallback_and_pivots(tmp_path: Path) -> None:
    client = MagicMock()
    client.asi_api_key = None
    client.riskrecon_token = None
    client._stop_event = None

    # Simulate HTTP 400 on rich v2 fields followed by successful fallback fields
    client.v2_lookup.side_effect = [
        RecordedFutureAPIError(400, "Unknown field", endpoint="/v2/ip/8.8.8.8"),
        {
            "data": {
                "entity": {"id": "ip:8.8.8.8", "name": "8.8.8.8", "type": "IpAddress"},
                "risk": {
                    "score": 65,
                    "riskString": "3/117",
                    "criticalityLabel": "Suspicious",
                    "riskSummary": "Observed in recent threat telemetry.",
                    "evidenceDetails": [
                        {"criticalityLabel": "Suspicious", "rule": "Historical C2", "evidenceString": "Seen in sample"}
                    ],
                },
                "relatedEntities": [
                    {
                        "type": "RelatedIpAddress",
                        "entities": [{"entity": {"id": "ip:1.2.3.4", "name": "1.2.3.4", "type": "IpAddress"}, "score": 80}],
                    }
                ],
            }
        },
    ]
    client.soar_enrich.return_value = {"data": {"results": [{"entity": {"id": "ip:8.8.8.8"}, "risk": {"score": 65}}]}}
    # Live links shape: data is a list
    client.links_search.return_value = {
        "data": [
            {
                "entity": {"id": "ip:8.8.8.8"},
                "links": [
                    {
                        "id": "idn:evil.example",
                        "name": "evil.example",
                        "type": "type:InternetDomainName",
                        "risk": {"score": 92},
                        "sections": [{"name": "Indicators"}],
                    }
                ],
            }
        ]
    }
    client.search_analyst_notes.return_value = {
        "data": [
            {
                "id": "note:1",
                "attributes": {
                    "title": "Campaign Note",
                    "published": "2026-11-20T00:00:00Z",
                    "text": "Sample text",
                    "topic": [{"id": "TXSFt1", "name": "Cyber Threat Analysis"}],
                    "note_entities": [{"id": "Yzaz0L", "name": "AsyncRAT", "type": "Malware"}],
                },
            }
        ]
    }
    client.search_detection_rules.return_value = [{"id": "rule1", "title": "Sigma Rule 1", "type": "sigma"}]
    client.malware_intel_query_iocs.return_value = {"data": [{"name": "a" * 64, "risk_score": 85}]}
    client.search_risk_history.side_effect = RecordedFutureAuthError(
        403, "Access requires Risk Api privilege", permission_type="missing_api_privileges"
    )
    client.identity_ip_lookup.side_effect = RecordedFutureAuthError(
        403, "User does not have access", permission_type="missing_api_privileges"
    )
    client.search_alerts_v3.return_value = {"data": [{"id": "alert1", "title": "Alert 1"}]}
    client.search_playbook_alerts.return_value = {"data": []}
    client.search_collective_insights.side_effect = ConfigurationError("Not set")
    client.sandbox_search.side_effect = RecordedFutureAPIError(500, "Backend timeout")
    client.v2_lookup_extension.return_value = {"data": {"classification": "benign"}}

    dossier = research_target(client, "8.8.8.8", deep=True)
    assert dossier.risk_score == 65
    assert dossier.sections["v2_intel"].status == "ok"
    assert dossier.sections["links"].status == "ok"
    assert dossier.sections["analyst_notes"].status == "ok"
    assert dossier.sections["risk_history"].status == "not_entitled"
    assert dossier.sections["collective_insights"].status == "not_configured"
    assert dossier.sections["sandbox"].status == "error"
    assert dossier.sections["extensions"].status == "ok"
    assert dossier.sections["asi"].status == "skipped"

    # Pivots ranked by risk score descending (evil.example 92 -> sha256 85 -> 1.2.3.4 80 -> AsyncRAT None)
    assert [p.entity_id for p in dossier.pivots][:3] == [
        "idn:evil.example",
        f"hash:{'a' * 64}",
        "ip:1.2.3.4",
    ]

    md = render_dossier_markdown(dossier)
    assert "# Recorded Future Threat Research Dossier: 8.8.8.8" in md
    assert "evil.example" in md
    assert "Campaign Note" in md

    md_path = export_dossier_markdown(dossier, tmp_path / "out" / "report.md")
    json_path = export_dossier_json(dossier, tmp_path / "out" / "report.json")
    assert md_path.is_file()
    assert json_path.is_file()
    parsed = json.loads(json_path.read_text(encoding="utf-8"))
    assert parsed["risk_score"] == 65


def test_probe_api_capabilities_classifies_all_states() -> None:
    client = MagicMock()
    client.v2_company_by_domain.side_effect = RecordedFutureAuthError(
        403, "Missing Data permissions", permission_type="missing_data_permissions"
    )
    client.asi_list_projects.side_effect = ConfigurationError("ASI key missing")
    client.sandbox_list_samples.side_effect = RecordedFutureAPIError(502, "Bad gateway")

    rows = probe_api_capabilities(client)
    by_family = {r["family"]: r for r in rows}
    assert by_family["Connect v2 (IP/Domain/Hash/URL)"]["status"] == "available"
    assert by_family["Connect v2 (Company by Domain)"]["status"] == "not_entitled"
    assert by_family["Attack Surface Intelligence (ASI)"]["status"] == "not_configured"
    assert by_family["Sandbox v0"]["status"] == "error"
