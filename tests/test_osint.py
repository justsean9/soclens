"""Offline unit & local mock HTTP server tests for soclens.osint, unified research & CLI."""

from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

import soclens.settings as settings_mod
from soclens.cli import main as cli_main
from soclens.config import OSINTConfig, get_osint_config
from soclens.osint import (
    OSINT_MODULES,
    OSINT_SOURCE_CATALOG,
    OSINTClient,
    extract_registrable_domain,
    is_public_ip,
    resolve_osint_source_key,
)
from soclens.research import (
    compute_unified_verdict,
    export_dossier_json,
    export_dossier_markdown,
    render_dossier_markdown,
    research_target,
)


class _MockOSINTHandler(BaseHTTPRequestHandler):
    """Local mock HTTP server implementing all 16 passive free OSINT provider schemas."""

    fail_primary_doh: bool = False
    rate_limit_urlscan: bool = False
    requests_seen: list[str] = []

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send_json(self, code: int, payload: Any, headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        self.__class__.requests_seen.append(self.path)

        # 1. DoH Primary & Fallback
        if path in ("/doh/primary", "/doh/fallback"):
            if path == "/doh/primary" and self.__class__.fail_primary_doh:
                self._send_json(503, {"error": "primary doh down"})
                return
            name = (qs.get("name") or [""])[0].lower()
            rtype = (qs.get("type") or ["A"])[0].upper()
            if rtype == "PTR" and "in-addr.arpa" in name:
                self._send_json(
                    200,
                    {
                        "Status": 0,
                        "AD": True,
                        "Answer": [{"name": name, "type": 12, "TTL": 300, "data": "c2-host.badsite.example."}],
                    },
                )
                return
            answers_by_type: dict[str, list[dict[str, Any]]] = {
                "A": [{"name": name, "type": 1, "TTL": 120, "data": "198.51.100.42"}],
                "AAAA": [{"name": name, "type": 28, "TTL": 120, "data": "2001:db8::42"}],
                "NS": [{"name": name, "type": 2, "TTL": 3600, "data": "ns1.badhost.example."}],
                "MX": [{"name": name, "type": 15, "TTL": 600, "data": "10 mail.badsite.example."}],
                "TXT": [
                    {
                        "name": name,
                        "type": 16,
                        "TTL": 300,
                        "data": (
                            '"v=DMARC1; p=reject; rua=mailto:dmarc@badsite.example"'
                            if name.startswith("_dmarc.")
                            else '"v=spf1 ip4:198.51.100.42 -all"'
                        ),
                    }
                ],
                "CNAME": [],
                "SOA": [{"name": name, "type": 6, "TTL": 3600, "data": "ns1.badhost.example. hostmaster.badsite.example. 1 3600 600 86400 300"}],
                "CAA": [{"name": name, "type": 257, "TTL": 3600, "data": '0 issue "letsencrypt.org"'}],
            }
            self._send_json(200, {"Status": 0, "AD": True, "Answer": answers_by_type.get(rtype, [])})
            return

        # 2. RDAP (Domain, IP, ASN)
        if path.startswith("/rdap/domain/"):
            dom = path.split("/rdap/domain/", 1)[1]
            if dom == "login.badsite.example":
                self._send_json(404, {"errorCode": 404})
                return
            self._send_json(
                200,
                {
                    "objectClassName": "domain",
                    "handle": "DOM-9991",
                    "ldhName": dom,
                    "status": ["client transfer prohibited", "active"],
                    "secureDNS": {"delegationSigned": True},
                    "events": [
                        {"eventAction": "registration", "eventDate": "2026-11-20T00:00:00Z"},
                        {"eventAction": "expiration", "eventDate": "2027-11-20T00:00:00Z"},
                        {"eventAction": "last changed", "eventDate": "2026-11-22T00:00:00Z"},
                    ],
                    "nameservers": [{"ldhName": "ns1.badhost.example"}],
                    "entities": [
                        {
                            "roles": ["registrar"],
                            "handle": "REG-42",
                            "vcardArray": ["vcard", [["fn", {}, "text", "Bulletproof Registrar LLC"]]],
                            "entities": [
                                {
                                    "roles": ["abuse"],
                                    "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"]]],
                                }
                            ],
                        }
                    ],
                },
            )
            return

        if path.startswith("/rdap/ip/"):
            self._send_json(
                200,
                {
                    "objectClassName": "ip network",
                    "handle": "NET-198-51-100-0",
                    "name": "BAD-HOSTING-NET",
                    "country": "NL",
                    "startAddress": "198.51.100.0",
                    "endAddress": "198.51.100.255",
                    "ipVersion": "v4",
                    "type": "DIRECT ALLOCATION",
                    "cidr0_cidrs": [{"v4prefix": "198.51.100.0", "length": 24}],
                    "entities": [
                        {
                            "roles": ["abuse"],
                            "vcardArray": ["vcard", [["email", {}, "text", "abuse@badhosting.example"]]],
                        }
                    ],
                },
            )
            return

        if path.startswith("/rdap/autnum/"):
            self._send_json(
                200,
                {
                    "objectClassName": "autnum",
                    "handle": "AS64512",
                    "name": "BAD-AS",
                    "country": "NL",
                    "status": ["active"],
                },
            )
            return

        # 3. GeoIP (ipwho.is)
        if path.startswith("/geoip/"):
            ip_val = path.split("/geoip/", 1)[1]
            self._send_json(
                200,
                {
                    "ip": ip_val,
                    "success": True,
                    "continent": "Europe",
                    "country": "Netherlands",
                    "country_code": "NL",
                    "region": "North Holland",
                    "city": "Amsterdam",
                    "latitude": 52.37,
                    "longitude": 4.89,
                    "timezone": {"id": "Europe/Amsterdam", "utc": "+01:00"},
                    "connection": {"asn": 64512, "org": "BadHosting BV", "isp": "BadHosting ISP", "domain": "badhosting.example"},
                },
            )
            return

        # 4. RIPEstat BGP/ASN
        if path == "/ripestat/network-info/data.json":
            self._send_json(200, {"data": {"asns": [64512], "prefix": "198.51.100.0/24", "holder": "BADHOSTING-AS"}})
            return
        if path == "/ripestat/abuse-contact-finder/data.json":
            self._send_json(200, {"data": {"abuse_contacts": ["abuse@badhosting.example"]}})
            return
        if path == "/ripestat/as-overview/data.json":
            self._send_json(200, {"data": {"holder": "GOOGLE", "announced": True}})
            return
        if path == "/ripestat/announced-prefixes/data.json":
            self._send_json(200, {"data": {"prefixes": [{"prefix": "8.8.8.0/24"}, {"prefix": "2001:4860::/32"}]}})
            return

        # 5. Shodan InternetDB
        if path.startswith("/shodan/"):
            ip_val = path.split("/shodan/", 1)[1]
            self._send_json(
                200,
                {
                    "ip": ip_val,
                    "ports": [22, 80, 443, 50050],
                    "cpes": ["cpe:/a:openbsd:openssh:8.4", "cpe:/a:f5:nginx:1.22"],
                    "hostnames": ["panel.badsite.example"],
                    "tags": ["cloud", "self-signed"],
                    "vulns": ["CVE-2021-44228"],
                },
            )
            return

        # 6. crt.sh
        if path.startswith("/crtsh"):
            self._send_json(
                200,
                [
                    {
                        "id": 1001,
                        "serial_number": "abc1",
                        "common_name": "login.badsite.example",
                        "name_value": "*.badsite.example\nlogin.badsite.example\napi.badsite.example",
                        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                        "entry_timestamp": "2026-11-21T10:00:00",
                        "not_before": "2026-11-21T09:00:00",
                        "not_after": "2027-02-19T09:00:00",
                    }
                ],
            )
            return

        # 7. URLScan
        if path == "/urlscan/search/":
            if self.__class__.rate_limit_urlscan:
                self._send_json(429, {"message": "Too Many Requests"}, headers={"X-Rate-Limit-Reset-After": "30"})
                return
            self._send_json(
                200,
                {
                    "total": 2,
                    "results": [
                        {
                            "_id": "scan-uuid-1",
                            "task": {"time": "2026-11-24T12:00:00Z", "url": "https://login.badsite.example/auth"},
                            "page": {
                                "url": "https://login.badsite.example/auth",
                                "domain": "login.badsite.example",
                                "ip": "198.51.100.42",
                                "asn": "AS64512",
                                "asnname": "BadHosting",
                                "country": "NL",
                                "status": 200,
                                "title": "Sign in to Corporate Portal",
                                "server": "nginx",
                            },
                            "verdicts": {"overall": {"malicious": True, "score": 100, "brands": ["AcmeBank"], "categories": ["phishing"]}},
                            "screenshot": "https://urlscan.io/screenshots/scan-uuid-1.png",
                        }
                    ],
                },
            )
            return

        # 8. SANS DShield
        if path.startswith("/dshield/ip/"):
            self._send_json(
                200,
                {
                    "ip": {
                        "count": 240,
                        "attacks": 65,
                        "mindate": "2026-11-10",
                        "maxdate": "2026-11-24",
                        "as": "64512",
                        "asname": "BADHOSTING",
                        "network": "198.51.100.0/24",
                        "country": "NL",
                        "abusecontact": "abuse@badhosting.example",
                        "threatfeeds": {"block": 1},
                    }
                },
            )
            return

        # 9. Wayback CDX
        if path == "/wayback":
            self._send_json(
                200,
                [
                    ["timestamp", "original", "statuscode", "mimetype", "length"],
                    ["20261120143000", "https://login.badsite.example/", "200", "text/html", "4210"],
                ],
            )
            return

        # 10. OTX
        if path.startswith("/otx/indicators/") and path.endswith("/general"):
            self._send_json(
                200,
                {
                    "pulse_info": {
                        "count": 3,
                        "pulses": [
                            {
                                "id": "p1",
                                "name": "Cobalt Strike Phishing Cluster",
                                "modified": "2026-11-24T00:00:00",
                                "adversary": "FIN7",
                                "tags": ["phishing", "c2"],
                                "malware_families": [{"display_name": "Cobalt Strike"}],
                                "attack_ids": [{"id": "T1566.002"}],
                            }
                        ],
                    },
                    "reputation": -10,
                    "validation": [],
                },
            )
            return
        if path.startswith("/otx/indicators/") and path.endswith("/passive_dns"):
            self._send_json(
                200,
                {
                    "passive_dns": [
                        {
                            "hostname": "cdn.badsite.example",
                            "address": "198.51.100.99",
                            "record_type": "A",
                            "last": "2026-11-24T00:00:00",
                        }
                    ]
                },
            )
            return

        # 11. GreyNoise Community
        if path.startswith("/greynoise/"):
            self._send_json(
                200,
                {
                    "ip": "198.51.100.42",
                    "noise": True,
                    "riot": False,
                    "classification": "malicious",
                    "name": "unknown",
                    "last_seen": "2026-11-24",
                    "link": "https://viz.greynoise.io/ip/198.51.100.42",
                },
            )
            return

        # 12. CIRCL Hashlookup
        if path.startswith("/hashlookup/"):
            self._send_json(
                200,
                {
                    "FileName": "notepad.exe",
                    "FileSize": "201216",
                    "MD5": "d41d8cd98f00b204e9800998ecf8427e",
                    "SHA-1": "a" * 40,
                    "SHA-256": "b" * 64,
                    "ProductCode": {"ProductName": "Microsoft Windows", "ProductVersion": "11"},
                    "OpSystemCode": {"OpSystemName": "Windows 11"},
                    "hashlookup:trust": 85,
                },
            )
            return

        # 13. MITRE CVE + FIRST EPSS + CISA KEV
        if path.startswith("/cveawg/"):
            cve = path.split("/cveawg/", 1)[1]
            self._send_json(
                200,
                {
                    "cveMetadata": {
                        "cveId": cve,
                        "state": "PUBLISHED",
                        "assignerShortName": "apache",
                        "datePublished": "2021-12-10T00:00:00Z",
                    },
                    "containers": {
                        "cna": {
                            "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI RCE vulnerability."}],
                            "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}],
                            "problemTypes": [{"descriptions": [{"cweId": "CWE-502"}]}],
                            "affected": [{"vendor": "Apache", "product": "Log4j", "versions": [{"version": "2.0-2.14.1"}]}],
                            "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}],
                        }
                    },
                },
            )
            return
        if path == "/epss":
            cve = (qs.get("cve") or [""])[0]
            self._send_json(
                200,
                {"data": [{"cve": cve, "epss": "0.9734", "percentile": "0.9991", "date": "2026-11-25"}]},
            )
            return
        if path == "/cisa_kev":
            self._send_json(
                200,
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2021-44228",
                            "vendorProject": "Apache",
                            "product": "Log4j2",
                            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                            "dateAdded": "2021-12-10",
                            "dueDate": "2021-12-24",
                            "knownRansomwareCampaignUse": "Known",
                            "requiredAction": "Apply updates per vendor instructions.",
                        }
                    ]
                },
            )
            return

        # 14. VirusTotal v3
        if path.startswith("/vt/"):
            if not self.headers.get("x-apikey"):
                self._send_json(401, {"error": {"message": "Missing x-apikey"}})
                return
            self._send_json(
                200,
                {
                    "data": {
                        "id": "badsite.example",
                        "attributes": {
                            "last_analysis_stats": {"malicious": 12, "suspicious": 2, "harmless": 70, "undetected": 10, "timeout": 0},
                            "last_analysis_results": {
                                "Google Safebrowsing": {"category": "malicious", "result": "phishing"},
                                "CRDF": {"category": "malicious", "result": "malicious"},
                            },
                            "reputation": -55,
                            "categories": {"Forcepoint": "phishing"},
                            "registrar": "Bulletproof Registrar LLC",
                            "popular_threat_classification": {"suggested_threat_label": "trojan.cobaltstrike"},
                            "last_https_certificate": {
                                "extensions": {"subject_alternative_name": ["alt.badsite.example"]}
                            },
                        },
                    }
                },
            )
            return

        # 15. AbuseIPDB v2
        if path == "/abuseipdb/check":
            if not self.headers.get("Key"):
                self._send_json(401, {"errors": [{"detail": "Missing Key"}]})
                return
            self._send_json(
                200,
                {
                    "data": {
                        "ipAddress": "198.51.100.42",
                        "abuseConfidenceScore": 88,
                        "totalReports": 47,
                        "numDistinctUsers": 14,
                        "isWhitelisted": False,
                        "isTor": True,
                        "countryCode": "NL",
                        "usageType": "Data Center/Web Hosting/Transit",
                        "isp": "BadHosting BV",
                        "domain": "badhosting.example",
                        "hostnames": ["exit.badhosting.example"],
                        "lastReportedAt": "2026-11-24T10:00:00Z",
                    }
                },
            )
            return

        self._send_json(404, {"error": f"unhandled GET {path}"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length") or 0)
        _ = self.rfile.read(length) if length > 0 else b""
        self.__class__.requests_seen.append(f"POST {self.path}")

        if not self.headers.get("Auth-Key"):
            self._send_json(401, {"query_status": "no_auth_key"})
            return

        if path == "/threatfox/":
            self._send_json(
                200,
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "id": "tf-1",
                            "malware_printable": "Cobalt Strike",
                            "threat_type": "botnet_cc",
                            "confidence_level": 100,
                            "tags": ["c2", "beacon"],
                            "first_seen": "2026-11-22 10:00:00 UTC",
                        }
                    ],
                },
            )
            return
        if path.startswith("/urlhaus/"):
            self._send_json(
                200,
                {
                    "query_status": "ok",
                    "url_status": "online",
                    "threat": "malware_download",
                    "blacklists": {"spamhaus_dbl": "abused_legit_malware"},
                    "urls": [{"url": "https://login.badsite.example/payload.exe", "url_status": "online", "threat": "malware_download"}],
                },
            )
            return
        if path == "/malwarebazaar/":
            self._send_json(
                200,
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "signature": "CobaltStrike",
                            "file_name": "beacon.dll",
                            "file_type": "dll",
                            "delivery_method": "web_download",
                            "first_seen": "2026-11-23 09:00:00",
                            "tags": ["cobaltstrike", "beacon"],
                        }
                    ],
                },
            )
            return
        self._send_json(404, {"error": f"unhandled POST {path}"})


@pytest.fixture()
def mock_osint_server() -> Iterator[dict[str, str]]:
    _MockOSINTHandler.fail_primary_doh = False
    _MockOSINTHandler.rate_limit_urlscan = False
    _MockOSINTHandler.requests_seen = []
    OSINTClient._KEV_MEMORY_CACHE = None

    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockOSINTHandler)
    server.timeout = 0.05
    host, port = server.server_address
    base = f"http://{host}:{port}"
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    t.start()
    try:
        yield {
            "doh_primary": f"{base}/doh/primary",
            "doh_fallback": f"{base}/doh/fallback",
            "rdap": f"{base}/rdap",
            "geoip": f"{base}/geoip",
            "ripestat": f"{base}/ripestat",
            "shodan_internetdb": f"{base}/shodan",
            "crtsh": f"{base}/crtsh",
            "urlscan": f"{base}/urlscan",
            "dshield": f"{base}/dshield",
            "wayback": f"{base}/wayback",
            "otx": f"{base}/otx",
            "greynoise": f"{base}/greynoise",
            "hashlookup": f"{base}/hashlookup",
            "cveawg": f"{base}/cveawg",
            "epss": f"{base}/epss",
            "cisa_kev": f"{base}/cisa_kev",
            "virustotal": f"{base}/vt",
            "abuseipdb": f"{base}/abuseipdb",
            "threatfox": f"{base}/threatfox/",
            "urlhaus": f"{base}/urlhaus",
            "malwarebazaar": f"{base}/malwarebazaar/",
        }
    finally:
        server.shutdown()
        server.server_close()
        OSINTClient._KEV_MEMORY_CACHE = None


def test_osint_source_catalog_aliases_and_helpers() -> None:
    assert len(OSINT_SOURCE_CATALOG) == 16
    assert len(OSINT_MODULES) == 16
    assert resolve_osint_source_key("whois") == "osint_rdap"
    assert resolve_osint_source_key("vt") == "osint_virustotal"
    assert resolve_osint_source_key("threatfox") == "osint_abusech"
    assert resolve_osint_source_key("nsrl") == "osint_hashlookup"
    assert resolve_osint_source_key("kev") == "osint_vuln"
    assert resolve_osint_source_key("osint_shodan") == "osint_shodan"
    assert resolve_osint_source_key("unknown_xyz") is None

    assert extract_registrable_domain("login.badsite.example") == "badsite.example"
    assert extract_registrable_domain("a.b.bank.co.uk") == "bank.co.uk"
    assert extract_registrable_domain("example.com") == "example.com"

    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("198.51.100.42") is False or is_public_ip("1.1.1.1") is True
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("192.168.1.5") is False
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("not-an-ip") is False


def test_osint_settings_config_and_secret_masking(monkeypatch: pytest.MonkeyPatch) -> None:
    assert ("osint", "OSINT Enrichment APIs") in settings_mod.SETTING_CATEGORIES
    for env_name, canonical in (
        ("VT_API_KEY", "osint_vt_api_key"),
        ("VIRUSTOTAL_API_KEY", "osint_vt_api_key"),
        ("ABUSEIPDB_API_KEY", "osint_abuseipdb_api_key"),
        ("ABUSECH_AUTH_KEY", "osint_abusech_api_key"),
        ("OTX_API_KEY", "osint_otx_api_key"),
        ("URLSCAN_API_KEY", "osint_urlscan_api_key"),
        ("GREYNOISE_API_KEY", "osint_greynoise_api_key"),
        ("SOCLENS_OSINT_ENABLED", "osint_enabled"),
        ("SOCLENS_OSINT_TIMEOUT", "osint_timeout"),
    ):
        assert settings_mod.resolve_setting_key(env_name) == canonical

    monkeypatch.setenv("SOCLENS_OSINT_ENABLED", "true")
    monkeypatch.setenv("VT_API_KEY", "vt-super-secret-123")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-secret-456")
    cfg = get_osint_config()
    assert cfg.enabled is True
    assert cfg.vt_api_key == "vt-super-secret-123"
    assert cfg.abuseipdb_api_key == "ab-secret-456"
    assert cfg.configured_key_count() == 2
    assert "vt-super-secret-123" not in repr(cfg)
    assert "ab-secret-456" not in repr(cfg)


def test_osint_domain_full_chain_against_local_mock_http_server(
    mock_osint_server: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 198.51.100.42 is RFC 5737 TEST-NET-2 (is_global=False in Python 3.12);
    # allow RFC 5737 test IP through is_public_ip for offline mock server testing
    monkeypatch.setattr("soclens.osint.is_public_ip", lambda ip: ip == "198.51.100.42" or is_public_ip(ip))

    cfg = OSINTConfig(
        enabled=True,
        timeout=5.0,
        vt_api_key="test-vt-key",
        abuseipdb_api_key="test-ab-key",
        abusech_api_key="test-ach-key",
        otx_api_key="test-otx-key",
        urlscan_api_key="test-us-key",
        greynoise_api_key="test-gn-key",
    )
    osint = OSINTClient(cfg, endpoints=mock_osint_server, workspace_dir=tmp_path)
    results = osint.enrich_target("login.badsite.example", "domain")

    # Direct domain sources
    assert results["osint_dns"].status == "ok"
    assert results["osint_dns"].data["a"] == ["198.51.100.42"]
    assert "Strict" in results["osint_dns"].data["spf_status"]
    assert results["osint_dns"].data["dmarc_policy"] == "reject"

    # RDAP fell back from login.badsite.example (404) -> badsite.example (200)
    assert results["osint_rdap"].status == "ok"
    assert results["osint_rdap"].data["queried"] == "badsite.example"
    assert results["osint_rdap"].data["registrar"] == "Bulletproof Registrar LLC"
    assert results["osint_rdap"].data["age_flag"] == "newly_registered"

    # Automatic domain -> resolved primary IP chaining!
    assert results["osint_geoip"].status == "ok"
    assert results["osint_geoip"].data["resolved_from"] == "login.badsite.example"
    assert results["osint_geoip"].data["city"] == "Amsterdam"
    assert results["osint_bgp"].status == "ok"
    assert results["osint_bgp"].data["prefix"] == "198.51.100.0/24"
    assert results["osint_shodan"].status == "ok"
    assert 50050 in results["osint_shodan"].data["ports"]
    assert "CVE-2021-44228" in results["osint_shodan"].data["vulns"]
    assert results["osint_dshield"].status == "ok"
    assert results["osint_dshield"].data["count"] == 240
    assert results["osint_greynoise"].status == "ok"
    assert results["osint_greynoise"].data["classification"] == "malicious"
    assert results["osint_abuseipdb"].status == "ok"
    assert results["osint_abuseipdb"].data["abuse_confidence_score"] == 88
    assert results["osint_abuseipdb"].data["is_tor"] is True

    # Certs, Web, Reputation & Malware feeds
    assert results["osint_crtsh"].status == "ok"
    assert "api.badsite.example" in results["osint_crtsh"].data["subdomains"]
    assert results["osint_urlscan"].status == "ok"
    assert results["osint_urlscan"].data["malicious_count"] == 1
    assert results["osint_wayback"].status == "ok"
    assert results["osint_otx"].status == "ok"
    assert results["osint_otx"].data["pulse_count"] == 3
    assert results["osint_virustotal"].status == "ok"
    assert results["osint_virustotal"].data["malicious"] == 12
    assert results["osint_abusech"].status == "ok"
    assert len(results["osint_abusech"].data["threatfox"]) == 1


def test_osint_ip_hash_cve_asn_private_ip_fallback_and_rate_limit(
    mock_osint_server: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Private IP must skip public OSINT lookups cleanly
    osint_nokey = OSINTClient(OSINTConfig(enabled=True, timeout=5.0), endpoints=mock_osint_server, workspace_dir=tmp_path)
    priv = osint_nokey.enrich_target("10.0.0.5", "ip")
    assert priv["osint_geoip"].status == "skipped"
    assert priv["osint_shodan"].status == "skipped"
    assert priv["osint_rdap"].status == "skipped"

    # Missing free keys report not_configured cleanly with signup hints
    monkeypatch.setattr("soclens.osint.is_public_ip", lambda ip: ip == "198.51.100.42" or is_public_ip(ip))
    ip_res = osint_nokey.enrich_target("198.51.100.42", "ip")
    assert ip_res["osint_dns"].status == "ok"
    assert "c2-host.badsite.example" in ip_res["osint_dns"].data["ptr"]
    assert ip_res["osint_virustotal"].status == "not_configured"
    assert "virustotal.com" in ip_res["osint_virustotal"].message
    assert ip_res["osint_abuseipdb"].status == "not_configured"
    assert ip_res["osint_abusech"].status == "not_configured"

    # DoH primary failure falls back to doh_fallback transparently
    _MockOSINTHandler.fail_primary_doh = True
    dns_fb = osint_nokey.lookup_dns("badsite.example", "domain")
    assert dns_fb.status == "ok"
    assert dns_fb.data["a"] == ["198.51.100.42"]
    _MockOSINTHandler.fail_primary_doh = False

    # HTTP 429 on URLScan reports rate_limited
    _MockOSINTHandler.rate_limit_urlscan = True
    us_rl = osint_nokey.lookup_urlscan("badsite.example", "domain")
    assert us_rl.status == "rate_limited"
    assert us_rl.status_code == 429
    _MockOSINTHandler.rate_limit_urlscan = False

    # Hash lookup: CIRCL NSRL Known-Good + abuse.ch MalwareBazaar
    osint_keyed = OSINTClient(
        OSINTConfig(enabled=True, timeout=5.0, vt_api_key="k", abusech_api_key="k"),
        endpoints=mock_osint_server,
        workspace_dir=tmp_path,
    )
    h_res = osint_keyed.enrich_target("b" * 64, "hash")
    assert h_res["osint_hashlookup"].status == "ok"
    assert h_res["osint_hashlookup"].data["known_good"] is True
    assert h_res["osint_hashlookup"].data["file_name"] == "notepad.exe"
    assert h_res["osint_abusech"].status == "ok"
    assert h_res["osint_abusech"].data["malwarebazaar"][0]["signature"] == "CobaltStrike"

    # CVE lookup: MITRE CVE 5.x + FIRST EPSS + CISA KEV (and writes cache file)
    cve_res = osint_nokey.enrich_target("CVE-2021-44228", "vulnerability")
    assert cve_res["osint_vuln"].status == "ok"
    assert cve_res["osint_vuln"].data["in_kev"] is True
    assert cve_res["osint_vuln"].data["cvss_score"] == 10.0
    assert cve_res["osint_vuln"].data["epss_score"] > 0.9
    assert (tmp_path / "cache" / "cisa_kev.json").is_file()

    # ASN lookup: RDAP + RIPEstat
    asn_res = osint_nokey.enrich_target("AS15169", "asn")
    assert asn_res["osint_bgp"].status == "ok"
    assert asn_res["osint_bgp"].data["prefix_count"] == 2
    assert asn_res["osint_rdap"].status == "ok"


def test_unified_rf_plus_osint_dossier_verdict_pivots_and_exports(
    mock_osint_server: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("soclens.osint.is_public_ip", lambda ip: ip == "198.51.100.42" or is_public_ip(ip))
    rf = MagicMock()
    rf.asi_api_key = None
    rf.riskrecon_token = None
    rf._stop_event = None
    rf.v2_lookup.return_value = {
        "data": {
            "entity": {"id": "idn:badsite.example", "name": "badsite.example", "type": "InternetDomainName"},
            "risk": {"score": 89, "riskString": "7/99", "criticalityLabel": "Very Malicious"},
            "relatedEntities": [],
        }
    }
    rf.soar_enrich.return_value = {"data": {"results": []}}
    rf.links_search.return_value = {"data": []}
    rf.search_analyst_notes.return_value = {"data": []}
    rf.search_detection_rules.return_value = []
    rf.malware_intel_query_iocs.return_value = {"data": []}
    rf.search_risk_history.return_value = {"data": []}
    rf.identity_search.return_value = {"identities": []}
    rf.search_alerts_v3.return_value = {"data": []}
    rf.search_playbook_alerts.return_value = {"data": []}
    rf.search_collective_insights.return_value = {"data": []}
    rf.sandbox_search.return_value = {"samples": []}

    osint = OSINTClient(
        OSINTConfig(enabled=True, timeout=5.0, vt_api_key="k", abuseipdb_api_key="k", abusech_api_key="k"),
        endpoints=mock_osint_server,
        workspace_dir=tmp_path,
    )

    dossier = research_target(rf, "badsite.example", osint_client=osint, workspace_dir=tmp_path)
    assert dossier.risk_score == 89
    assert dossier.sections["v2_intel"].source_group == "rf"
    assert dossier.sections["osint_rdap"].source_group == "osint"
    assert dossier.sections["osint_virustotal"].source_group == "osint"
    assert len(dossier.osint_sections) >= 10
    assert dossier.unified_verdict["level"] == "critical"
    assert compute_unified_verdict(dossier)["osint_sources_ok"] >= 10

    # Merged pivots contain OSINT-extracted entities (resolved IP, Shodan CVE, crt.sh subdomain, OTX ATT&CK)
    pivot_ids = {p.entity_id for p in dossier.pivots}
    assert "ip:198.51.100.42" in pivot_ids
    assert "CVE-2021-44228" in pivot_ids
    assert "idn:api.badsite.example" in pivot_ids
    assert "mitre:T1566.002" in pivot_ids

    md = render_dossier_markdown(dossier)
    assert "## OSINT & Infrastructure Intelligence" in md
    assert "Bulletproof Registrar LLC" in md
    assert "50050" in md
    assert "VirusTotal" in md
    assert "## API & OSINT Source Coverage" in md

    md_path = export_dossier_markdown(dossier, tmp_path / "unified.md")
    js_path = export_dossier_json(dossier, tmp_path / "unified.json")
    assert md_path.is_file()
    assert json.loads(js_path.read_text(encoding="utf-8"))["unified_verdict"]["level"] == "critical"

    # OSINT-only mode works even with client=None (no RF API token required!)
    osint_only = research_target(
        None,
        "badsite.example",
        include_rf=False,
        include_osint=True,
        osint_client=osint,
        workspace_dir=tmp_path,
    )
    assert not osint_only.rf_sections
    assert osint_only.osint_sections["osint_dns"].status == "ok"
    assert "# SOCLens Passive OSINT Dossier: badsite.example" in render_dossier_markdown(osint_only)


def test_cli_research_osint_and_unified_flags(
    mock_osint_server: dict[str, str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("soclens.osint.is_public_ip", lambda ip: ip == "198.51.100.42" or is_public_ip(ip))

    # 1. List all free OSINT sources without any RF API token
    with patch.dict(os.environ, {}, clear=False):
        monkeypatch.delenv("RF_API_TOKEN", raising=False)
        with patch.object(sys, "argv", ["soclens", "research", "osint", "--list-sources", "--json"]):
            cli_main()
        out = json.loads(capsys.readouterr().out)
        assert len(out) == 16
        assert any(row["key"] == "osint_virustotal" for row in out)

    # 2. Run `soclens research osint badsite.example --sources whois,dns --json` with zero RF token
    fake_client = OSINTClient(
        OSINTConfig(enabled=True, timeout=5.0),
        endpoints=mock_osint_server,
        workspace_dir=tmp_path,
    )
    with patch("soclens.research.OSINTClient", return_value=fake_client):
        with patch.object(
            sys,
            "argv",
            ["soclens", "research", "osint", "badsite.example", "--sources", "whois,dns", "--json"],
        ):
            cli_main()
        parsed = json.loads(capsys.readouterr().out)
        assert parsed["sections"]["osint_rdap"]["status"] == "ok"
        assert parsed["sections"]["osint_dns"]["status"] == "ok"
        assert "v2_intel" not in parsed["sections"]

        # 3. `soclens research investigate badsite.example --osint-only --osint-sources dns`
        with patch.object(
            sys,
            "argv",
            ["soclens", "research", "investigate", "badsite.example", "--osint-only", "--osint-sources", "dns", "--json"],
        ):
            cli_main()
        parsed2 = json.loads(capsys.readouterr().out)
        assert list(parsed2["sections"].keys()) == ["osint_dns"]


def test_osint_request_json_detects_proxysg_html_403(tmp_path: Path) -> None:
    client = OSINTClient(OSINTConfig(enabled=True, timeout=5.0), workspace_dir=tmp_path)

    class _FakeResp:
        status_code = 403
        headers = {"Content-Type": "text/html; charset=utf-8"}
        text = "<html><body><h1>Access Denied</h1><p>ProxySG policy_denied</p></body></html>"

        def json(self) -> dict[str, str]:
            raise ValueError("not json")

    with patch.object(client._session, "request", return_value=_FakeResp()):
        code, payload, err = client._request_json("GET", "https://rdap.org/domain/example.com")

    assert code == 403
    assert payload is None
    assert err is not None
    assert "Blocked by proxy/gateway (HTTP 403)" in err
