#!/usr/bin/env python3
"""Generate sanitized SVG screenshots of the SOCLens Textual TUI for README.md."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from textual.widgets import Button, DataTable, Input, RichLog, Select

import soclens.settings as settings_mod
from soclens.client import RecordedFutureAuthError
from soclens.config import OSINTConfig
from soclens.osint import OSINT_SOURCES_BY_KEY, OSINTClient, OSINTSectionOutcome
from soclens.tui.app import create_app
from soclens.tui.screens.llm import LocalLLMPane
from soclens.tui.screens.research import ResearchPane
from soclens.tui.screens.rf_intel import RFIntelPane
from soclens.tui.screens.sentinelone import SentinelOnePane
from soclens.tui.screens.sigma import SigmaPane
from soclens.tui.screens.splunk_es import SplunkESPane

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "docs" / "screenshots"
TERMINAL_SIZE = (165, 44)


def _demo_env(base_env: dict[str, str], settings_path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ"):
        if key in base_env:
            env[key] = base_env[key]
    env.update(
        {
            "TERM": "xterm-256color",
            "COLORTERM": "truecolor",
            "SOCLENS_SETTINGS_FILE": str(settings_path),
            "SOCLENS_TIMEZONE": "UTC",
            "RF_API_TOKEN": "demo-rf-token-placeholder",
            "SPLUNK_HOST": "https://splunk-es.example.local:8089",
            "SPLUNK_TOKEN": "demo-splunk-token-placeholder",
            "SPLUNK_APP": "SplunkEnterpriseSecuritySuite",
            "S1_CONSOLE_URL": "https://soc-demo.sentinelone.net",
            "S1_API_TOKEN": "demo-s1-token-placeholder",
            "RF_LLM_PROVIDER": "ollama",
            "RF_LLM_BASE_URL": "http://127.0.0.1:11434",
            "RF_LLM_MODEL": "qwen2.5:14b",
            "SOCLENS_OSINT_ENABLED": "true",
            "VT_API_KEY": "demo-vt-free-key",
            "ABUSEIPDB_API_KEY": "demo-abuseipdb-free-key",
            "ABUSECH_AUTH_KEY": "demo-abusech-free-key",
        }
    )
    return env


def _seed_api_errors(workspace_dir: Path) -> None:
    logs_dir = workspace_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    entries = [
        {
            "timestamp": "2026-11-25T12:14:05Z",
            "status_code": 429,
            "endpoint": "/v2/ip/search",
            "trace_id": "rf-tr-88a1c042",
            "message": "Rate limit exceeded; automatic exponential backoff retry succeeded",
        },
        {
            "timestamp": "2026-11-25T12:18:32Z",
            "status_code": 403,
            "endpoint": "/identity/credentials/search",
            "trace_id": "rf-tr-91b7e210",
            "message": "Module not entitled on demo token (skipped gracefully)",
        },
        {
            "timestamp": "2026-11-25T12:24:11Z",
            "status_code": 502,
            "endpoint": "/playbook-alert/search",
            "trace_id": "rf-tr-7c4d0399",
            "message": "Upstream gateway timeout; recovered on retry #1",
        },
    ]
    jsonl_path = logs_dir / "rf_api_errors.jsonl"
    jsonl_path.write_text(
        "\n".join(json.dumps(entry) for entry in entries) + "\n",
        encoding="utf-8",
    )


def _build_mock_rf_client() -> MagicMock:
    client = MagicMock()
    client.api_token = "demo-rf-token-placeholder"
    client.verify_ssl = True
    client.asi_api_key = None
    client.riskrecon_token = None
    client._stop_event = None
    client.get_watchlists.return_value = []

    client.entity_match.return_value = [
        {"id": "ip:198.51.100.42", "name": "198.51.100.42", "type": "IpAddress"}
    ]
    client.entity_lookup.side_effect = lambda eid: {
        "id": eid,
        "name": eid.split(":", 1)[1] if ":" in eid else eid,
        "type": "InternetDomainName" if eid.startswith("idn:") else "IpAddress",
    }
    client.v2_search.return_value = {"data": {"results": []}}
    client.v2_company_by_domain.side_effect = RecordedFutureAuthError(
        403, "Company API not licensed", permission_type="missing_api_privileges"
    )
    client.v2_lookup.return_value = {
        "data": {
            "entity": {"id": "ip:198.51.100.42", "name": "198.51.100.42", "type": "IpAddress"},
            "risk": {
                "score": 89,
                "riskString": "7/99",
                "criticalityLabel": "Very Malicious",
                "riskSummary": (
                    "Active Cobalt Strike C2 infrastructure observed communicating with "
                    "enterprise endpoints over HTTPS (port 443)."
                ),
                "evidenceDetails": [
                    {
                        "criticalityLabel": "Very Malicious",
                        "rule": "Cobalt Strike C2 Server",
                        "evidenceString": "Active TeamServer beacon configuration detected on port 443.",
                    },
                    {
                        "criticalityLabel": "Malicious",
                        "rule": "Positive Malware Verdict",
                        "evidenceString": "Associated with 4 payload hashes in Sandbox v0 telemetry.",
                    },
                    {
                        "criticalityLabel": "Suspicious",
                        "rule": "Recent Threat Research Reporting",
                        "evidenceString": "Referenced in 2 Insikt Group threat notes in last 14 days.",
                    },
                ],
            },
            "relatedEntities": [],
        }
    }
    client.soar_enrich.return_value = {
        "data": {
            "results": [
                {
                    "entity": {"id": "ip:198.51.100.42", "name": "198.51.100.42"},
                    "risk": {"score": 89},
                }
            ]
        }
    }
    client.links_search.return_value = {
        "data": [
            {
                "entity": {"id": "ip:198.51.100.42"},
                "links": [
                    {
                        "id": "idn:c2-update.example",
                        "name": "c2-update.example",
                        "type": "type:InternetDomainName",
                        "risk": {"score": 92},
                        "sections": [{"name": "Indicators"}],
                    },
                    {
                        "id": "idn:cdn-stage.example",
                        "name": "cdn-stage.example",
                        "type": "type:InternetDomainName",
                        "risk": {"score": 78},
                        "sections": [{"name": "Indicators"}],
                    },
                ],
            }
        ]
    }
    client.search_analyst_notes.return_value = {
        "data": [
            {
                "id": "note:insikt-2026-441",
                "attributes": {
                    "title": "Insikt Group: Cobalt Strike Malleable C2 Infrastructure Clusters",
                    "published": "2026-11-23T14:00:00Z",
                    "text": (
                        "Clusters of Cobalt Strike teamservers using lookalike CDN staging "
                        "domains (c2-update.example, cdn-stage.example) and encoded PowerShell loaders."
                    ),
                    "topic": [{"id": "TXSFt1", "name": "Malware & C2 Analysis"}],
                    "note_entities": [],
                },
            },
            {
                "id": "note:insikt-2026-418",
                "attributes": {
                    "title": "Q4 Credential Access & Beacon Staging TTPs",
                    "published": "2026-11-18T09:30:00Z",
                    "text": "Observed initial access via phishing followed by LSASS access and HTTPS C2.",
                    "topic": [{"id": "TXSFt2", "name": "Threat Actor TTPs"}],
                    "note_entities": [],
                },
            },
        ]
    }
    client.lookup_analyst_note.return_value = {
        "id": "note:insikt-2026-441",
        "attributes": {
            "title": "Insikt Group: Cobalt Strike Malleable C2 Infrastructure Clusters",
            "published": "2026-11-23T14:00:00Z",
            "text": (
                "Clusters of Cobalt Strike teamservers using lookalike CDN staging "
                "domains (c2-update.example, cdn-stage.example) and encoded PowerShell loaders."
            ),
            "topic": [{"id": "TXSFt1", "name": "Malware & C2 Analysis"}],
        },
    }
    client.search_detection_rules.return_value = [
        {
            "id": "rule-cs-beacon",
            "title": "Cobalt Strike HTTPS Beacon Jitter Detection",
            "type": "sigma",
            "updated": "2026-11-22T00:00:00Z",
        },
        {
            "id": "rule-ps-loader",
            "title": "Encoded PowerShell Stager YARA Signature",
            "type": "yara",
            "updated": "2026-11-20T00:00:00Z",
        },
    ]
    client.search_threat_actors.return_value = {"data": []}
    client.get_threat_actor_map.return_value = {"data": {"threat_map": []}}
    client.get_malware_threat_map.return_value = {"data": {"threat_map": []}}
    client.malware_intel_query_iocs.return_value = {"data": []}
    client.malware_intel_query_nl.return_value = {"data": []}
    client.search_risk_history.side_effect = RecordedFutureAuthError(
        403, "Access requires Risk Api privilege", permission_type="missing_api_privileges"
    )
    client.identity_ip_lookup.side_effect = RecordedFutureAuthError(
        403, "User does not have access", permission_type="missing_api_privileges"
    )
    client.identity_lookup.side_effect = RecordedFutureAuthError(
        403, "User does not have access", permission_type="missing_api_privileges"
    )
    client.identity_search.side_effect = RecordedFutureAuthError(
        403, "User does not have access", permission_type="missing_api_privileges"
    )
    client.search_collective_insights.side_effect = RecordedFutureAuthError(
        403, "Not enough privileges", permission_type="missing_api_privileges"
    )
    client.sandbox_search.return_value = {"samples": []}

    alerts = [
        {
            "id": "al-9001",
            "title": "Active Cobalt Strike C2 Beacon — 198.51.100.42",
            "type": "ENTITY_MATCH",
            "review": {
                "priority": "Critical",
                "status_in_portal": "New",
                "assignee": "analyst_demo",
                "note": "Correlated with Splunk ES notable fnd-1001-a on WKSTN-FIN-01.",
            },
            "rule": {"id": "rule-c2-01", "name": "High-Risk C2 Communication (Enterprise)"},
            "log": {"triggered": "2026-11-25T12:15:00Z"},
            "url": {"portal": "https://app.recordedfuture.com/live/sc/alert/al-9001"},
            "hits": [
                {
                    "id": "hit-1",
                    "primary_entity": {"id": "ip:198.51.100.42", "name": "198.51.100.42", "type": "IpAddress"},
                    "entities": [
                        {"id": "ip:198.51.100.42", "name": "198.51.100.42", "type": "IpAddress"},
                        {"id": "idn:c2-update.example", "name": "c2-update.example", "type": "InternetDomainName"},
                    ],
                    "fragment": "Outbound TLS beacon from 10.20.4.18 to 198.51.100.42:443 (SNI: c2-update.example).",
                }
            ],
        },
        {
            "id": "al-9002",
            "title": "Lookalike Phishing Domain Registered — portal-auth-verify.example",
            "type": "ENTITY_MATCH",
            "review": {"priority": "High", "status_in_portal": "In Progress", "assignee": "soc_triage"},
            "rule": {"id": "rule-brand-02", "name": "Brand Impersonation & Domain Watchlist"},
            "log": {"triggered": "2026-11-25T11:42:00Z"},
            "hits": [
                {
                    "id": "hit-2",
                    "primary_entity": {
                        "id": "idn:portal-auth-verify.example",
                        "name": "portal-auth-verify.example",
                        "type": "InternetDomainName",
                    },
                    "entities": [],
                    "fragment": "Newly registered domain matching brand keyword and TLS cert pattern.",
                }
            ],
        },
        {
            "id": "al-9003",
            "title": "Exploited Vulnerability Chatter — CVE-2024-3400",
            "type": "ENTITY_MATCH",
            "review": {"priority": "High", "status_in_portal": "New", "assignee": "vuln_ops"},
            "rule": {"id": "rule-cve-03", "name": "Critical Perimeter CVE Exploitation"},
            "log": {"triggered": "2026-11-25T10:20:00Z"},
            "hits": [],
        },
        {
            "id": "al-9004",
            "title": "Malicious Payload Dropper SHA-256 — 203.0.113.77",
            "type": "ENTITY_MATCH",
            "review": {"priority": "Moderate", "status_in_portal": "Pending", "assignee": "ir_lead"},
            "rule": {"id": "rule-mal-04", "name": "Sandbox Malware Dropper Telemetry"},
            "log": {"triggered": "2026-11-25T09:05:00Z"},
            "hits": [],
        },
        {
            "id": "al-9005",
            "title": "Credential Exposure Mention on Dark Web Forum",
            "type": "ENTITY_MATCH",
            "review": {"priority": "Moderate", "status_in_portal": "In Progress", "assignee": "analyst_demo"},
            "rule": {"id": "rule-id-05", "name": "Corporate Domain Identity Exposure"},
            "log": {"triggered": "2026-11-25T08:11:00Z"},
            "hits": [],
        },
        {
            "id": "al-9006",
            "title": "Suspicious ASN Routing Anomaly — AS64512",
            "type": "ENTITY_MATCH",
            "review": {"priority": "Low", "status_in_portal": "Pending", "assignee": "net_sec"},
            "rule": {"id": "rule-net-06", "name": "BGP & Infrastructure Watchlist"},
            "log": {"triggered": "2026-11-25T06:40:00Z"},
            "hits": [],
        },
    ]

    def _search_alerts_v3(**_kwargs: Any) -> dict[str, Any]:
        return {"data": alerts, "counts": {"returned": len(alerts), "total": len(alerts)}}

    def _get_alert_v3(alert_id: str) -> dict[str, Any]:
        for item in alerts:
            if item["id"] == alert_id:
                return {"data": item}
        return {"data": alerts[0]}

    client.search_alerts_v3.side_effect = _search_alerts_v3
    client.get_alert_v3.side_effect = _get_alert_v3
    client.search_playbook_alerts.return_value = {"data": [], "counts": {"returned": 0, "total": 0}}
    client.search_cases.return_value = {"data": [], "total_count": 0}
    return client


def _build_mock_osint_client() -> OSINTClient:
    """Offline mock OSINTClient for deterministic unified RF + OSINT screenshots."""
    cfg = OSINTConfig(
        enabled=True,
        timeout=8.0,
        vt_api_key="demo-vt-free-key",
        abuseipdb_api_key="demo-abuseipdb-free-key",
        abusech_api_key="demo-abusech-free-key",
    )

    class _DemoOSINTClient(OSINTClient):
        def enrich_target(
            self,
            target: str,
            kind: str,
            *,
            extracted_domain: str | None = None,
            sources: Any = None,
        ) -> dict[str, OSINTSectionOutcome]:
            _ = (target, kind, extracted_domain)
            outcomes: dict[str, OSINTSectionOutcome] = {
                "osint_rdap": OSINTSectionOutcome(
                    key="osint_rdap",
                    title=OSINT_SOURCES_BY_KEY["osint_rdap"].title,
                    status="ok",
                    status_code=200,
                    message="BPH-NET-EU | NL | 198.51.100.0/24",
                    count=1,
                    elapsed_ms=215.0,
                    data={
                        "queried": "198.51.100.42",
                        "kind": "ip",
                        "name": "BPH-NET-EU",
                        "handle": "NET-198-51-100-0-1",
                        "registrar": "RIPE NCC",
                        "registrant": "Bulletproof Hosting BV",
                        "country": "NL",
                        "cidrs": ["198.51.100.0/24"],
                        "created": "2025-10-04T00:00:00Z",
                        "abuse_email": "abuse@bph-net.example",
                    },
                ),
                "osint_dns": OSINTSectionOutcome(
                    key="osint_dns",
                    title=OSINT_SOURCES_BY_KEY["osint_dns"].title,
                    status="ok",
                    status_code=200,
                    message="PTR: c2-edge.example",
                    count=1,
                    elapsed_ms=68.0,
                    data={"queried": "198.51.100.42", "kind": "ip", "ptr": ["c2-edge.example"]},
                ),
                "osint_geoip": OSINTSectionOutcome(
                    key="osint_geoip",
                    title=OSINT_SOURCES_BY_KEY["osint_geoip"].title,
                    status="ok",
                    status_code=200,
                    message="Amsterdam, North Holland, NL | AS64512 | Bulletproof Hosting BV",
                    count=1,
                    elapsed_ms=112.0,
                    data={
                        "ip": "198.51.100.42",
                        "city": "Amsterdam",
                        "region": "North Holland",
                        "country": "Netherlands",
                        "country_code": "NL",
                        "asn": "AS64512",
                        "org": "Bulletproof Hosting BV",
                        "isp": "Bulletproof Hosting BV",
                        "timezone": "Europe/Amsterdam",
                    },
                ),
                "osint_bgp": OSINTSectionOutcome(
                    key="osint_bgp",
                    title=OSINT_SOURCES_BY_KEY["osint_bgp"].title,
                    status="ok",
                    status_code=200,
                    message="198.51.100.0/24 | AS64512 | BPH-NET-AS",
                    count=1,
                    elapsed_ms=184.0,
                    data={
                        "ip": "198.51.100.42",
                        "prefix": "198.51.100.0/24",
                        "asns": ["AS64512"],
                        "holder": "BPH-NET-AS Bulletproof Hosting BV",
                        "abuse_contacts": ["abuse@bph-net.example"],
                    },
                ),
                "osint_shodan": OSINTSectionOutcome(
                    key="osint_shodan",
                    title=OSINT_SOURCES_BY_KEY["osint_shodan"].title,
                    status="ok",
                    status_code=200,
                    message="3 port(s) (80, 443, 50050) | 1 CVE(s) | tags: c2",
                    count=3,
                    elapsed_ms=94.0,
                    data={
                        "ip": "198.51.100.42",
                        "ports": [80, 443, 50050],
                        "port_services": [
                            {"port": 80, "service": "HTTP"},
                            {"port": 443, "service": "HTTPS"},
                            {"port": 50050, "service": "Cobalt Strike"},
                        ],
                        "cpes": ["cpe:/a:nginx:nginx:1.24.0"],
                        "vulns": ["CVE-2024-3400"],
                        "hostnames": ["c2-update.example", "cdn-stage.example"],
                        "tags": ["c2", "cloud"],
                    },
                ),
                "osint_virustotal": OSINTSectionOutcome(
                    key="osint_virustotal",
                    title=OSINT_SOURCES_BY_KEY["osint_virustotal"].title,
                    status="ok",
                    status_code=200,
                    message="14/94 malicious, 2 suspicious | rep -62",
                    count=14,
                    elapsed_ms=295.0,
                    data={
                        "malicious": 14,
                        "suspicious": 2,
                        "harmless": 66,
                        "undetected": 12,
                        "total_engines": 94,
                        "reputation": -62,
                        "suggested_threat_label": "trojan.cobaltstrike/beacon",
                        "flagged_engines": [
                            {"engine": "CrowdStrike", "category": "malicious", "result": "malware"},
                            {"engine": "BitDefender", "category": "malicious", "result": "c2"},
                            {"engine": "Fortinet", "category": "malicious", "result": "malicious"},
                        ],
                        "gui_url": "https://www.virustotal.com/gui/ip-address/198.51.100.42",
                    },
                ),
                "osint_abuseipdb": OSINTSectionOutcome(
                    key="osint_abuseipdb",
                    title=OSINT_SOURCES_BY_KEY["osint_abuseipdb"].title,
                    status="ok",
                    status_code=200,
                    message="Abuse Score: 88% | 47 report(s) | TOR EXIT",
                    count=47,
                    elapsed_ms=230.0,
                    data={
                        "ip": "198.51.100.42",
                        "abuse_confidence_score": 88,
                        "total_reports": 47,
                        "distinct_users": 14,
                        "is_tor": True,
                        "is_whitelisted": False,
                        "country_code": "NL",
                        "usage_type": "Data Center/Web Hosting/Transit",
                        "isp": "Bulletproof Hosting BV",
                        "last_reported_at": "2026-11-25T11:20:00Z",
                    },
                ),
                "osint_abusech": OSINTSectionOutcome(
                    key="osint_abusech",
                    title=OSINT_SOURCES_BY_KEY["osint_abusech"].title,
                    status="ok",
                    status_code=200,
                    message="ThreatFox: 2 (Cobalt Strike) | URLhaus: 1 URL(s)",
                    count=3,
                    elapsed_ms=340.0,
                    data={
                        "threatfox": [
                            {
                                "malware_printable": "Cobalt Strike",
                                "threat_type": "botnet_cc",
                                "confidence_level": 100,
                                "first_seen": "2026-11-22 10:00:00 UTC",
                                "tags": ["c2", "teamserver"],
                            }
                        ],
                        "urlhaus": {"query_status": "ok", "url_status": "online"},
                        "urlhaus_urls": [
                            {
                                "url": "https://198.51.100.42/updates/stage.bin",
                                "url_status": "online",
                                "threat": "malware_download",
                            }
                        ],
                        "malwarebazaar": [],
                        "total_hits": 3,
                    },
                ),
                "osint_otx": OSINTSectionOutcome(
                    key="osint_otx",
                    title=OSINT_SOURCES_BY_KEY["osint_otx"].title,
                    status="ok",
                    status_code=200,
                    message="5 pulse(s) | malware: Cobalt Strike | 6 passive DNS",
                    count=5,
                    elapsed_ms=390.0,
                    data={
                        "pulse_count": 5,
                        "malware_families": ["Cobalt Strike"],
                        "adversaries": ["FIN7"],
                        "tags": ["cobaltstrike", "c2", "https-beacon"],
                        "pulses": [
                            {
                                "name": "Cobalt Strike Malleable C2 Cluster Q4 2026",
                                "modified": "2026-11-24T08:00:00Z",
                                "adversary": "FIN7",
                                "tags": ["c2", "cobaltstrike"],
                            }
                        ],
                        "passive_dns": [
                            {"hostname": "c2-update.example", "record_type": "A", "last": "2026-11-25"}
                        ],
                    },
                ),
                "osint_greynoise": OSINTSectionOutcome(
                    key="osint_greynoise",
                    title=OSINT_SOURCES_BY_KEY["osint_greynoise"].title,
                    status="ok",
                    status_code=200,
                    message="NOISE (malicious) | Cobalt Strike TeamServer",
                    count=1,
                    elapsed_ms=135.0,
                    data={
                        "ip": "198.51.100.42",
                        "noise": True,
                        "riot": False,
                        "classification": "malicious",
                        "name": "Cobalt Strike TeamServer",
                        "last_seen": "2026-11-25",
                        "link": "https://viz.greynoise.io/ip/198.51.100.42",
                    },
                ),
                "osint_dshield": OSINTSectionOutcome(
                    key="osint_dshield",
                    title=OSINT_SOURCES_BY_KEY["osint_dshield"].title,
                    status="ok",
                    status_code=200,
                    message="240 report(s) | 48 target(s) attacked | feeds: block, cobaltstrike",
                    count=240,
                    elapsed_ms=178.0,
                    data={
                        "ip": "198.51.100.42",
                        "count": 240,
                        "attacks": 48,
                        "maxdate": "2026-11-25",
                        "mindate": "2026-11-12",
                        "threatfeeds": ["block", "cobaltstrike"],
                    },
                ),
                "osint_urlscan": OSINTSectionOutcome(
                    key="osint_urlscan",
                    title=OSINT_SOURCES_BY_KEY["osint_urlscan"].title,
                    status="ok",
                    status_code=200,
                    message="12 scan(s) | 3 malicious",
                    count=12,
                    elapsed_ms=265.0,
                    data={
                        "total": 12,
                        "malicious_count": 3,
                        "scans": [
                            {
                                "time": "2026-11-24T19:12:00Z",
                                "url": "https://c2-update.example/login",
                                "domain": "c2-update.example",
                                "status": "200",
                                "server": "nginx",
                                "malicious": True,
                                "result_url": "https://urlscan.io/result/demo-scan-1/",
                            }
                        ],
                    },
                ),
            }
            if sources is not None:
                allowed = set(sources)
                outcomes = {k: v for k, v in outcomes.items() if k in allowed}
            return outcomes

    return _DemoOSINTClient(cfg)


def _build_mock_es_client() -> MagicMock:
    es = MagicMock()
    es.__enter__.return_value = es
    es.__exit__.return_value = None
    es.list_users.return_value = [
        {"username": "analyst_demo", "realname": "SOC Analyst"},
        {"username": "ir_lead", "realname": "Incident Response Lead"},
    ]
    es.get_current_user.return_value = "analyst_demo"

    findings = [
        {
            "event_id": "fnd-1001-a",
            "finding_id": "fnd-1001-a@@notable@@1001",
            "_time": "2026-11-25T12:15:00Z",
            "create_time": "2026-11-25T12:15:00Z",
            "update_time": "2026-11-25T12:18:00Z",
            "tenant_id": "TENANT-01",
            "urgency": "critical",
            "severity": "critical",
            "status": "1",
            "status_label": "New",
            "status_name": "New",
            "owner": "unassigned",
            "owner_realname": "unassigned",
            "disposition": "disposition:6",
            "disposition_label": "Undetermined",
            "disposition_name": "Undetermined",
            "rule_name": "ES_Outbound_CobaltStrike_C2",
            "rule_title": "Outbound Cobalt Strike C2 Beacon from WKSTN-FIN-01",
            "rule_description": "Endpoint initiated periodic TLS beacons to high-risk RF IP 198.51.100.42.",
            "security_domain": "network",
            "risk_object": "WKSTN-FIN-01.example.local",
            "risk_object_type": "system",
            "risk_score": "95",
            "src": "10.20.4.18",
            "dest": "198.51.100.42",
            "user": "jdoe@example.local",
            "orig_sid": "1700000100.11",
            "orig_rid": "0",
            "notable_type": "notable",
            "case_id": "CASE-2026-101",
        },
        {
            "event_id": "fnd-1001-b",
            "finding_id": "fnd-1001-b@@notable@@1002",
            "_time": "2026-11-25T11:50:00Z",
            "create_time": "2026-11-25T11:50:00Z",
            "update_time": "2026-11-25T11:58:00Z",
            "tenant_id": "TENANT-01",
            "urgency": "high",
            "severity": "high",
            "status": "2",
            "status_label": "In Progress",
            "status_name": "In Progress",
            "owner": "analyst_demo",
            "owner_realname": "SOC Analyst",
            "disposition": "disposition:1",
            "disposition_label": "True Positive - Suspicious Activity",
            "disposition_name": "True Positive - Suspicious Activity",
            "rule_name": "ES_Suspicious_LSASS_Access",
            "rule_title": "LSASS Credential Memory Read on WKSTN-FIN-01",
            "rule_description": "Unsigned binary requested PROCESS_VM_READ on lsass.exe.",
            "security_domain": "endpoint",
            "risk_object": "WKSTN-FIN-01.example.local",
            "risk_object_type": "system",
            "risk_score": "85",
            "src": "10.20.4.18",
            "dest": "10.20.1.10",
            "user": "jdoe@example.local",
            "notable_type": "notable",
        },
        {
            "event_id": "fnd-1001-c",
            "finding_id": "fnd-1001-c@@notable@@1003",
            "_time": "2026-11-25T11:12:00Z",
            "tenant_id": "TENANT-02",
            "urgency": "high",
            "severity": "high",
            "status": "1",
            "status_label": "New",
            "status_name": "New",
            "owner": "unassigned",
            "disposition_label": "Undetermined",
            "rule_name": "ES_Encoded_PowerShell_Loader",
            "rule_title": "Encoded PowerShell Execution on SRV-APP-04",
            "rule_description": "Detected powershell.exe invoked with -EncodedCommand and web download cradle.",
            "security_domain": "endpoint",
            "risk_object": "SRV-APP-04.example.local",
            "risk_object_type": "system",
            "risk_score": "78",
            "src": "10.20.8.44",
            "dest": "203.0.113.77",
            "user": "svc_deploy@example.local",
            "notable_type": "notable",
        },
        {
            "event_id": "fnd-1001-d",
            "finding_id": "fnd-1001-d@@notable@@1004",
            "_time": "2026-11-25T10:30:00Z",
            "tenant_id": "TENANT-01",
            "urgency": "medium",
            "severity": "medium",
            "status": "2",
            "status_label": "In Progress",
            "status_name": "In Progress",
            "owner": "ir_lead",
            "disposition_label": "Undetermined",
            "rule_name": "ES_RBA_Threshold_Exceeded",
            "rule_title": "24h Risk Score Threshold Exceeded for jdoe@example.local",
            "rule_description": "Cumulative identity risk exceeded 100 across 3 correlation rules.",
            "security_domain": "identity",
            "risk_object": "jdoe@example.local",
            "risk_object_type": "user",
            "risk_score": "110",
            "user": "jdoe@example.local",
            "notable_type": "notable",
        },
        {
            "event_id": "fnd-1001-e",
            "finding_id": "fnd-1001-e@@notable@@1005",
            "_time": "2026-11-25T09:45:00Z",
            "tenant_id": "TENANT-03",
            "urgency": "medium",
            "severity": "medium",
            "status": "3",
            "status_label": "Pending",
            "status_name": "Pending",
            "owner": "analyst_demo",
            "disposition_label": "Benign Positive - Confirmed Activity",
            "rule_name": "ES_Impossible_Travel_Login",
            "rule_title": "Anomalous SSO Authentication from 203.0.113.90",
            "rule_description": "VPN authentication outside baseline ASN.",
            "security_domain": "access",
            "risk_object": "asmith@example.local",
            "risk_object_type": "user",
            "risk_score": "55",
            "src": "203.0.113.90",
            "user": "asmith@example.local",
            "notable_type": "notable",
        },
    ]

    es.query_findings_hybrid.return_value = {
        "items": findings,
        "source_backend": "mc_v2",
        "total": len(findings),
    }
    es.list_notables.return_value = findings
    es.get_finding_notes.return_value = []
    es.list_finding_notes.return_value = []
    es.get_finding_detail.return_value = findings[0]
    return es


def _build_mock_s1_client() -> MagicMock:
    s1 = MagicMock()
    s1.console_url = "https://soc-demo.sentinelone.net"
    s1.check_connection.return_value = {"build": "24.2.1"}
    s1.list_sites.return_value = [
        {"id": "site-101", "name": "CORP-HQ", "state": "active", "updatedAt": "2026-11-25T00:00:00Z"},
        {"id": "site-102", "name": "MDR-1042", "state": "active", "updatedAt": "2026-11-25T00:00:00Z"},
    ]
    s1.list_agents.return_value = [
        {
            "id": "ag-101",
            "computerName": "WKSTN-FIN-01",
            "osName": "Windows 11 Enterprise",
            "lastIpToMgmt": "10.20.4.18",
            "networkStatus": "connected",
            "infected": True,
            "siteName": "CORP-HQ",
        }
    ]
    s1.list_threats.return_value = [
        {
            "id": "th-9001",
            "threatInfo": {
                "threatName": "CobaltStrike.Beacon",
                "classification": "Trojan",
                "confidenceLevel": "malicious",
                "analystVerdict": "true_positive",
                "incidentStatus": "in_progress",
                "mitigationStatus": "mitigated",
                "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                "filePath": r"C:\Users\jdoe\AppData\Local\Temp\svchost_upd.exe",
                "createdAt": "2026-11-25T12:14:00Z",
            },
            "agentRealtimeInfo": {
                "agentComputerName": "WKSTN-FIN-01",
                "siteName": "CORP-HQ",
                "agentOsName": "Windows 11 Enterprise",
                "agentNetworkStatus": "connected",
            },
            "agentDetectionInfo": {
                "agentIpV4": "10.20.4.18",
                "agentLastLoggedInUserName": "jdoe",
                "siteName": "CORP-HQ",
            },
        },
        {
            "id": "th-9002",
            "threatInfo": {
                "threatName": "PowerShell.EncodedLoader",
                "classification": "Hacktool",
                "confidenceLevel": "malicious",
                "analystVerdict": "undefined",
                "incidentStatus": "unresolved",
                "mitigationStatus": "active",
                "sha256": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
                "filePath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "createdAt": "2026-11-25T11:48:00Z",
            },
            "agentRealtimeInfo": {
                "agentComputerName": "SRV-APP-04",
                "siteName": "MDR-1042",
                "agentOsName": "Windows Server 2022",
            },
            "agentDetectionInfo": {"agentIpV4": "10.20.8.44", "siteName": "MDR-1042"},
        },
        {
            "id": "th-9003",
            "threatInfo": {
                "threatName": "Mimikatz.CredentialDump",
                "classification": "Hacktool",
                "confidenceLevel": "malicious",
                "analystVerdict": "true_positive",
                "incidentStatus": "unresolved",
                "mitigationStatus": "mitigated",
                "createdAt": "2026-11-25T11:20:00Z",
            },
            "agentRealtimeInfo": {"agentComputerName": "WKSTN-FIN-01", "siteName": "CORP-HQ"},
            "agentDetectionInfo": {"agentIpV4": "10.20.4.18", "siteName": "CORP-HQ"},
        },
        {
            "id": "th-9004",
            "threatInfo": {
                "threatName": "Lsass.MemoryAccess",
                "classification": "Suspicious Behavior",
                "confidenceLevel": "suspicious",
                "analystVerdict": "undefined",
                "incidentStatus": "unresolved",
                "mitigationStatus": "active",
                "createdAt": "2026-11-25T10:05:00Z",
            },
            "agentRealtimeInfo": {"agentComputerName": "WKSTN-ENG-12", "siteName": "CORP-HQ"},
            "agentDetectionInfo": {"agentIpV4": "10.20.5.61", "siteName": "CORP-HQ"},
        },
        {
            "id": "th-9005",
            "threatInfo": {
                "threatName": "Suspicious.ScheduledTask",
                "classification": "Persistence",
                "confidenceLevel": "suspicious",
                "analystVerdict": "false_positive",
                "incidentStatus": "resolved",
                "mitigationStatus": "mitigated",
                "createdAt": "2026-11-25T08:40:00Z",
            },
            "agentRealtimeInfo": {"agentComputerName": "SRV-CI-02", "siteName": "MDR-1042"},
            "agentDetectionInfo": {"agentIpV4": "10.20.9.14", "siteName": "MDR-1042"},
        },
    ]
    return s1


def _build_sample_sigma_rules() -> list[dict[str, Any]]:
    ps_yaml = """title: Encoded PowerShell Download Cradle
id: 7a8b9c0d-1111-4222-8333-444455556666
status: stable
description: Detects powershell.exe launched with base64 encoded command flags and web request indicators.
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\\powershell.exe'
    selection_cli:
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - 'DownloadString'
    condition: selection_img and selection_cli
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""
    lsass_yaml = """title: LSASS Memory Dump Access
id: 1b2c3d4e-2222-4333-8444-555566667777
status: stable
description: Detects suspicious process access targeting lsass.exe memory.
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
    condition: selection
level: critical
"""
    certutil_yaml = """title: Certutil Remote Payload Download
id: 2c3d4e5f-3333-4444-8555-666677778888
status: test
description: Detects certutil.exe downloading remote binaries via urlcache.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains|all:
            - 'urlcache'
            - 'http'
    condition: selection
level: high
"""
    schtask_yaml = """title: Suspicious Scheduled Task Creation
id: 3d4e5f6a-4444-4555-8666-777788889999
status: stable
description: Detects schtasks.exe creating persistence tasks from user temp paths.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains:
            - '/create'
            - '\\AppData\\Local\\Temp\\'
    condition: selection
level: medium
"""
    return [
        {
            "rule_id": "rf-sig-001",
            "level": "high",
            "index": "windows:process_creation",
            "title": "Encoded PowerShell Download Cradle",
            "file_name": "encoded_powershell_cradle.yml",
            "updated": "2026-11-24T00:00:00Z",
            "content": ps_yaml,
        },
        {
            "rule_id": "rf-sig-002",
            "level": "critical",
            "index": "windows:process_access",
            "title": "LSASS Memory Dump Access",
            "file_name": "lsass_memory_dump.yml",
            "updated": "2026-11-23T00:00:00Z",
            "content": lsass_yaml,
        },
        {
            "rule_id": "rf-sig-003",
            "level": "high",
            "index": "windows:process_creation",
            "title": "Certutil Remote Payload Download",
            "file_name": "certutil_remote_download.yml",
            "updated": "2026-11-21T00:00:00Z",
            "content": certutil_yaml,
        },
        {
            "rule_id": "rf-sig-004",
            "level": "medium",
            "index": "windows:process_creation",
            "title": "Suspicious Scheduled Task Creation",
            "file_name": "suspicious_scheduled_task.yml",
            "updated": "2026-11-19T00:00:00Z",
            "content": schtask_yaml,
        },
    ]


def _build_mock_llm_client() -> MagicMock:
    mock_llm = MagicMock()
    mock_llm.__enter__.return_value = mock_llm
    mock_llm.__exit__.return_value = None
    mock_llm.list_models.return_value = ["qwen2.5:14b", "llama3.2:latest", "deepseek-r1:14b"]
    mock_llm.check_connection.return_value = {
        "ok": True,
        "provider": "ollama",
        "base_url": "http://127.0.0.1:11434",
        "models": ["qwen2.5:14b", "llama3.2:latest", "deepseek-r1:14b"],
        "error": None,
    }
    mock_llm.chat.return_value = {
        "content": (
            "1. Immediate Triage (WKSTN-FIN-01 / 10.20.4.18):\n"
            "   - Decode the base64 PowerShell command line safely offline; check for IEX / Net.WebClient.\n"
            "   - Confirm host isolation in SentinelOne and preserve volatile memory before reboot.\n"
            "   - Pivot on Cobalt Strike C2 IP 198.51.100.42 (RF Risk 89/99) and domain c2-update.example.\n\n"
            "2. Splunk Hunt Query:\n"
            "   index=win_sec OR index=net_proxy (dest_ip=\"198.51.100.42\" OR query=\"c2-update.example\" "
            "OR CommandLine=\"*-enc*\") | stats count earliest(_time) latest(_time) by host, user, src, dest_ip"
        ),
        "model": "qwen2.5:14b",
        "provider": "ollama",
        "done": True,
        "raw": {},
    }
    return mock_llm


def _sanitize_svg(svg_path: Path, workspace_dir: Path, settings_path: Path) -> None:
    text = svg_path.read_text(encoding="utf-8")
    replacements = {
        str(settings_path): "~/.config/soclens/settings.json",
        str(workspace_dir): "/opt/soclens",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    svg_path.write_text(text, encoding="utf-8")


async def _capture_all(workspace_dir: Path, settings_path: Path) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rf_client = _build_mock_rf_client()
    osint_client = _build_mock_osint_client()
    s1_client = _build_mock_s1_client()
    es_client = _build_mock_es_client()
    llm_client = _build_mock_llm_client()
    sigma_rules = _build_sample_sigma_rules()

    # 1. Research tab (Unified Recorded Future + Free Passive OSINT)
    app = create_app(
        client=rf_client,
        osint_client=osint_client,
        s1_client=s1_client,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=workspace_dir,
    )
    async with app.run_test(size=TERMINAL_SIZE) as pilot:
        await pilot.pause(0.15)
        pane = app.query_one(ResearchPane)
        pane.query_one("#res-target-input", Input).value = "198.51.100.42"
        await pilot.click("#res-investigate-btn")
        await app.workers.wait_for_complete()
        await pilot.pause(0.2)
        pane.query_one("#res-table", DataTable).move_cursor(row=0, column=0, animate=False)
        await pilot.pause(0.15)
        app.save_screenshot(filename="research.svg", path=str(OUT_DIR))

    # 2. RF Intel & Alerts tab
    app = create_app(
        client=rf_client,
        s1_client=s1_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=workspace_dir,
    )
    async with app.run_test(size=TERMINAL_SIZE) as pilot:
        await pilot.pause(0.15)
        await pilot.click("#rf-alerts-btn")
        await app.workers.wait_for_complete()
        await pilot.pause(0.2)
        rf_pane = app.query_one(RFIntelPane)
        table = rf_pane.query_one("#rf-results-table", DataTable)
        table.focus()
        table.move_cursor(row=0, column=0, animate=False)
        await pilot.pause(0.1)
        await pilot.press("enter")
        await app.workers.wait_for_complete()
        await pilot.pause(0.2)
        app.save_screenshot(filename="rf-intel.svg", path=str(OUT_DIR))

    # 3. Splunk ES tab
    app = create_app(
        client=rf_client,
        s1_client=s1_client,
        dry_run=True,
        initial_tab="tab-splunk-es",
        workspace_dir=workspace_dir,
    )
    with patch.object(SplunkESPane, "_build_es_client", return_value=es_client):
        async with app.run_test(size=TERMINAL_SIZE) as pilot:
            await pilot.pause(0.15)
            await pilot.click("#es-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause(0.2)
            es_table = app.query_one("#es-table", DataTable)
            es_table.focus()
            es_table.move_cursor(row=0, column=0, animate=False)
            await pilot.pause(0.2)
            app.save_screenshot(filename="splunk-es.svg", path=str(OUT_DIR))

    # 4. SentinelOne tab
    app = create_app(
        client=rf_client,
        s1_client=s1_client,
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=workspace_dir,
    )
    async with app.run_test(size=TERMINAL_SIZE) as pilot:
        await pilot.pause(0.15)
        s1_pane = app.query_one(SentinelOnePane)
        s1_pane.query_one("#s1-view-select", Select).value = "threats"
        await pilot.pause(0.1)
        await pilot.click("#s1-refresh-btn")
        await app.workers.wait_for_complete()
        await pilot.pause(0.2)
        s1_table = s1_pane.query_one("#s1-table", DataTable)
        s1_table.focus()
        s1_table.move_cursor(row=0, column=0, animate=False)
        await pilot.pause(0.2)
        app.save_screenshot(filename="sentinelone.svg", path=str(OUT_DIR))

    # 5. Sigma Rules tab (Admin View)
    app = create_app(
        client=rf_client,
        s1_client=s1_client,
        dry_run=True,
        view_mode="admin",
        initial_tab="tab-sigma",
        workspace_dir=workspace_dir,
    )
    with patch("soclens.tui.screens.sigma.load_rules", return_value=sigma_rules):
        async with app.run_test(size=TERMINAL_SIZE) as pilot:
            await pilot.pause(0.15)
            sigma_pane = app.query_one(SigmaPane)
            sigma_pane.query_one("#sigma-load-btn", Button).press()
            await app.workers.wait_for_complete()
            await pilot.pause(0.2)
            sig_table = sigma_pane.query_one("#sigma-table", DataTable)
            sig_table.focus()
            sig_table.move_cursor(row=0, column=0, animate=False)
            await pilot.pause(0.15)
            sigma_pane.query_one("#sigma-preview-btn", Button).press()
            await pilot.pause(0.15)
            sigma_log = sigma_pane.query_one("#sigma-log", RichLog)
            sigma_log.scroll_to(y=1, animate=False)
            await pilot.pause(0.15)
            app.save_screenshot(filename="sigma-rules.svg", path=str(OUT_DIR))

    # 6. Local LLM tab
    app = create_app(
        client=rf_client,
        s1_client=s1_client,
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=workspace_dir,
    )
    with patch("soclens.tui.screens.llm.LocalLLMClient", return_value=llm_client):
        async with app.run_test(size=TERMINAL_SIZE) as pilot:
            await pilot.pause(0.15)
            llm_pane = app.query_one(LocalLLMPane)
            llm_pane.query_one("#llm-refresh-models-btn", Button).press()
            await app.workers.wait_for_complete()
            await pilot.pause(0.15)
            llm_pane.query_one("#llm-prompt", Input).value = (
                "Triage PowerShell -enc launching beacon to 198.51.100.42 and suggest Splunk SPL"
            )
            llm_pane.query_one("#llm-send-btn", Button).press()
            await app.workers.wait_for_complete()
            await pilot.pause(0.2)
            app.save_screenshot(filename="local-llm.svg", path=str(OUT_DIR))

    # 7. Dashboard & Diagnostics tab (Admin View — All 13 Tabs)
    app = create_app(
        client=rf_client,
        s1_client=s1_client,
        dry_run=True,
        view_mode="admin",
        initial_tab="tab-dashboard",
        workspace_dir=workspace_dir,
    )
    with patch(
        "soclens.tui.screens.dashboard.get_settings_storage_info",
        return_value={"path": "~/.config/soclens/settings.json", "active_profile": "default"},
    ):
        async with app.run_test(size=TERMINAL_SIZE) as pilot:
            await pilot.pause(0.15)
            await pilot.click("#dash-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause(0.2)
            app.save_screenshot(filename="dashboard-admin.svg", path=str(OUT_DIR))

    for svg_file in sorted(OUT_DIR.glob("*.svg")):
        _sanitize_svg(svg_file, workspace_dir, settings_path)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="soclens-demo-") as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        workspace_dir = tmp_dir / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        _seed_api_errors(workspace_dir)

        settings_path = tmp_dir / "config" / "settings.json"
        demo_env = _demo_env(dict(os.environ), settings_path)

        orig_override = settings_mod._DEFAULT_SETTINGS_PATH_OVERRIDE
        settings_mod._DEFAULT_SETTINGS_PATH_OVERRIDE = settings_path
        settings_mod.clear_session_overrides()
        settings_mod.invalidate_settings_cache()
        try:
            with patch.dict(os.environ, demo_env, clear=True):
                asyncio.run(_capture_all(workspace_dir, settings_path))
        finally:
            settings_mod._DEFAULT_SETTINGS_PATH_OVERRIDE = orig_override
            settings_mod.clear_session_overrides()
            settings_mod.invalidate_settings_cache()

    generated = sorted(OUT_DIR.glob("*.svg"))
    print(f"Generated {len(generated)} SVG screenshot(s) in {OUT_DIR}:")
    for path in generated:
        print(f"  - {path.relative_to(REPO_ROOT)} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
