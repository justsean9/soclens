"""Passive multi-source free OSINT enrichment engine for SOCLens Threat Research.

All default providers are 100% passive (never initiate direct connections to target
hosts or domains), honor SOCLens proxy/SSL/CA settings via ``ConfiguredSession``,
and support cooperative cancellation and per-source timeouts.
"""

from __future__ import annotations

import base64
import concurrent.futures
import functools
import ipaddress
import json
import logging
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import requests

from soclens.config import (
    ConfiguredSession,
    OSINTConfig,
    get_osint_config,
    get_workspace_dir,
    suppress_insecure_ssl_warnings,
)

logger = logging.getLogger("soclens.osint")

_USER_AGENT = "SOCLens-OSINT/2.1 (+https://github.com/justsean9/soclens)"

_TWO_LEVEL_PUBLIC_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "me.uk",
        "net.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "co.jp",
        "or.jp",
        "ne.jp",
        "go.jp",
        "ac.jp",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "co.in",
        "net.in",
        "org.in",
        "gov.in",
        "co.za",
        "org.za",
        "com.mx",
        "org.mx",
        "com.sg",
        "com.hk",
        "com.tw",
        "com.cn",
        "com.tr",
        "co.kr",
        "co.il",
        "com.ar",
        "com.co",
        "com.pe",
        "com.ua",
        "com.pl",
        "com.es",
        "co.id",
        "com.my",
        "com.ph",
        "com.vn",
        "co.th",
        "com.sa",
        "com.eg",
        "com.ng",
    }
)

_WELL_KNOWN_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    123: "NTP",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE/VPN",
    587: "Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    2049: "NFS",
    2222: "SSH-Alt",
    3306: "MySQL",
    3389: "RDP",
    4443: "HTTPS-Alt",
    5060: "SIP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM-SSL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "Web/Admin",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    50050: "CobaltStrike?",
}

_DNS_RCODE_NAMES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

_DNS_TYPE_NUM_TO_NAME: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    257: "CAA",
}

_HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ASN_NUM_RE = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)


@dataclass(frozen=True)
class OSINTSourceSpec:
    """Metadata describing a free passive OSINT source."""

    key: str
    short_name: str
    title: str
    category: str
    tier: str  # free_no_key | free_optional_key | free_api_key
    supported_kinds: tuple[str, ...]
    description: str
    setting_key: str | None = None
    signup_url: str = ""
    chains_resolved_ip: bool = False


OSINT_SOURCE_CATALOG: tuple[OSINTSourceSpec, ...] = (
    OSINTSourceSpec(
        key="osint_rdap",
        short_name="RDAP",
        title="WHOIS / RDAP Registration",
        category="WHOIS",
        tier="free_no_key",
        supported_kinds=("domain", "url", "ip", "asn", "email"),
        description="Official IANA RDAP registrar, domain age (NRD alerts), status, abuse contacts & IP netblocks.",
        signup_url="https://about.rdap.org/",
    ),
    OSINTSourceSpec(
        key="osint_dns",
        short_name="DoH",
        title="DNS & Email Auth (DoH)",
        category="DNS",
        tier="free_no_key",
        supported_kinds=("domain", "url", "ip", "email"),
        description="Cloudflare/Google DoH records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, PTR), SPF, DMARC & DNSSEC.",
        signup_url="https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
    ),
    OSINTSourceSpec(
        key="osint_geoip",
        short_name="GeoIP",
        title="IP Geolocation & ISP (ipwho.is)",
        category="Network",
        tier="free_no_key",
        supported_kinds=("ip", "domain", "url"),
        description="Country, city, timezone, ISP, organization & ASN for IPs and domain hosting IPs.",
        signup_url="https://ipwhois.io/",
        chains_resolved_ip=True,
    ),
    OSINTSourceSpec(
        key="osint_bgp",
        short_name="BGP/ASN",
        title="BGP Routing & ASN (RIPEstat)",
        category="Network",
        tier="free_no_key",
        supported_kinds=("ip", "asn", "domain", "url"),
        description="RIPEstat originating BGP prefix, AS holder, announced prefixes & abuse contacts.",
        signup_url="https://stat.ripe.net/",
        chains_resolved_ip=True,
    ),
    OSINTSourceSpec(
        key="osint_shodan",
        short_name="Shodan",
        title="Shodan InternetDB (Ports & CVEs)",
        category="Network",
        tier="free_no_key",
        supported_kinds=("ip", "domain", "url"),
        description="Free keyless Shodan open ports, services/CPEs, known CVEs, hostnames & infrastructure tags.",
        signup_url="https://internetdb.shodan.io/",
        chains_resolved_ip=True,
    ),
    OSINTSourceSpec(
        key="osint_crtsh",
        short_name="crt.sh",
        title="Certificate Transparency (crt.sh)",
        category="Certificates",
        tier="free_no_key",
        supported_kinds=("domain", "url", "email"),
        description="Passive TLS certificate history, certificate authorities & discovered subdomains/SANs.",
        signup_url="https://crt.sh/",
    ),
    OSINTSourceSpec(
        key="osint_urlscan",
        short_name="URLScan",
        title="URLScan.io Public Web Scans",
        category="Web Intel",
        tier="free_optional_key",
        supported_kinds=("domain", "ip", "url", "hash"),
        description="Historical web scans, phishing/malicious verdicts, page titles, servers & screenshot links.",
        setting_key="osint_urlscan_api_key",
        signup_url="https://urlscan.io/user/signup",
    ),
    OSINTSourceSpec(
        key="osint_dshield",
        short_name="DShield",
        title="SANS ISC / DShield",
        category="Reputation",
        tier="free_no_key",
        supported_kinds=("ip", "domain", "url"),
        description="Global DShield sensor attack counts, distinct targets attacked, threat feeds & first/last seen.",
        signup_url="https://isc.sans.edu/",
        chains_resolved_ip=True,
    ),
    OSINTSourceSpec(
        key="osint_wayback",
        short_name="Wayback",
        title="Wayback Machine Archive",
        category="Web Intel",
        tier="free_no_key",
        supported_kinds=("domain", "url"),
        description="Internet Archive historical snapshots & safe passive archive links without touching live sites.",
        signup_url="https://web.archive.org/",
    ),
    OSINTSourceSpec(
        key="osint_otx",
        short_name="OTX",
        title="AlienVault / LevelBlue OTX",
        category="Reputation",
        tier="free_optional_key",
        supported_kinds=("ip", "domain", "url", "hash", "vulnerability"),
        description="Community threat pulses, adversaries, malware families, ATT&CK IDs & passive DNS.",
        setting_key="osint_otx_api_key",
        signup_url="https://otx.alienvault.com/",
    ),
    OSINTSourceSpec(
        key="osint_greynoise",
        short_name="GreyNoise",
        title="GreyNoise Community",
        category="Reputation",
        tier="free_optional_key",
        supported_kinds=("ip", "domain", "url"),
        description="Internet mass-scanner (Noise) vs benign business service (RIOT) classification.",
        setting_key="osint_greynoise_api_key",
        signup_url="https://viz.greynoise.io/signup",
        chains_resolved_ip=True,
    ),
    OSINTSourceSpec(
        key="osint_hashlookup",
        short_name="NSRL",
        title="CIRCL Hashlookup (NSRL Known-Good)",
        category="File Intel",
        tier="free_no_key",
        supported_kinds=("hash",),
        description="Instant NIST NSRL & OS software known-good file hash verification & trust scoring.",
        signup_url="https://hashlookup.circl.lu/",
    ),
    OSINTSourceSpec(
        key="osint_vuln",
        short_name="CVE/KEV",
        title="MITRE CVE + FIRST EPSS + CISA KEV",
        category="Vulnerability",
        tier="free_no_key",
        supported_kinds=("vulnerability",),
        description="Authoritative CVE 5.x CVSS/CWEs, FIRST exploit prediction (EPSS) & CISA KEV active-exploit status.",
        signup_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ),
    OSINTSourceSpec(
        key="osint_virustotal",
        short_name="VirusTotal",
        title="VirusTotal v3",
        category="Reputation",
        tier="free_api_key",
        supported_kinds=("ip", "domain", "url", "hash"),
        description="Multi-AV vendor verdicts, reputation, categories, cert SANs & threat classification (free key).",
        setting_key="osint_vt_api_key",
        signup_url="https://www.virustotal.com/gui/join-us",
    ),
    OSINTSourceSpec(
        key="osint_abuseipdb",
        short_name="AbuseIPDB",
        title="AbuseIPDB v2",
        category="Reputation",
        tier="free_api_key",
        supported_kinds=("ip", "domain", "url"),
        description="Crowdsourced IP abuse confidence score (0-100%), report counts, Tor & usage type (free key).",
        setting_key="osint_abuseipdb_api_key",
        signup_url="https://www.abuseipdb.com/register",
        chains_resolved_ip=True,
    ),
    OSINTSourceSpec(
        key="osint_abusech",
        short_name="abuse.ch",
        title="abuse.ch (ThreatFox / URLhaus / MalwareBazaar)",
        category="Reputation",
        tier="free_api_key",
        supported_kinds=("ip", "domain", "url", "hash"),
        description="One free Auth-Key unlocks ThreatFox C2 IOCs, URLhaus malicious URLs & MalwareBazaar hashes.",
        setting_key="osint_abusech_api_key",
        signup_url="https://auth.abuse.ch/",
    ),
)

OSINT_SOURCES_BY_KEY: dict[str, OSINTSourceSpec] = {
    spec.key: spec for spec in OSINT_SOURCE_CATALOG
}
OSINT_MODULES: tuple[str, ...] = tuple(spec.key for spec in OSINT_SOURCE_CATALOG)
OSINT_NO_KEY_MODULES: tuple[str, ...] = tuple(
    spec.key for spec in OSINT_SOURCE_CATALOG if spec.tier in ("free_no_key", "free_optional_key")
)

# Short user-friendly CLI aliases (e.g. --osint-sources dns,whois,vt,shodan)
OSINT_SOURCE_ALIASES: dict[str, str] = {
    "whois": "osint_rdap",
    "rdap": "osint_rdap",
    "dns": "osint_dns",
    "doh": "osint_dns",
    "geoip": "osint_geoip",
    "geo": "osint_geoip",
    "ipwhois": "osint_geoip",
    "bgp": "osint_bgp",
    "asn": "osint_bgp",
    "ripestat": "osint_bgp",
    "shodan": "osint_shodan",
    "internetdb": "osint_shodan",
    "crtsh": "osint_crtsh",
    "crt": "osint_crtsh",
    "certs": "osint_crtsh",
    "urlscan": "osint_urlscan",
    "dshield": "osint_dshield",
    "sans": "osint_dshield",
    "wayback": "osint_wayback",
    "archive": "osint_wayback",
    "otx": "osint_otx",
    "alienvault": "osint_otx",
    "greynoise": "osint_greynoise",
    "gn": "osint_greynoise",
    "hashlookup": "osint_hashlookup",
    "nsrl": "osint_hashlookup",
    "circl": "osint_hashlookup",
    "vuln": "osint_vuln",
    "cve": "osint_vuln",
    "kev": "osint_vuln",
    "epss": "osint_vuln",
    "vt": "osint_virustotal",
    "virustotal": "osint_virustotal",
    "abuseipdb": "osint_abuseipdb",
    "abusech": "osint_abusech",
    "threatfox": "osint_abusech",
    "urlhaus": "osint_abusech",
    "malwarebazaar": "osint_abusech",
}


def resolve_osint_source_key(name: str) -> str | None:
    """Resolve a canonical ``osint_*`` key or friendly alias (e.g. ``vt``, ``whois``)."""
    clean = name.strip().lower()
    if not clean:
        return None
    if clean in OSINT_SOURCES_BY_KEY:
        return clean
    if f"osint_{clean}" in OSINT_SOURCES_BY_KEY:
        return f"osint_{clean}"
    return OSINT_SOURCE_ALIASES.get(clean)


def extract_registrable_domain(domain: str) -> str:
    """Extract the likely registrable apex domain for RDAP/WHOIS fallback."""
    clean = domain.strip().lower().rstrip(".")
    parts = [p for p in clean.split(".") if p]
    if len(parts) <= 2:
        return clean
    last_two = ".".join(parts[-2:])
    if last_two in _TWO_LEVEL_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def is_public_ip(value: str) -> bool:
    """Return True if ``value`` is a valid globally routable IP address."""
    try:
        ip_obj = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return bool(ip_obj.is_global)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _parse_iso_datetime(raw: str | None) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        for fmt in ("%Y-%m-%d", "%Y%m%d%H%M%S"):
            try:
                return datetime.strptime(text[: len(fmt.replace("%Y", "2020").replace("%m", "01").replace("%d", "01").replace("%H", "00").replace("%M", "00").replace("%S", "00"))], fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
        return None


def _format_wayback_ts(ts: str) -> str:
    clean = ts.strip()
    if len(clean) >= 14 and clean[:14].isdigit():
        return f"{clean[0:4]}-{clean[4:6]}-{clean[6:8]}T{clean[8:10]}:{clean[10:12]}:{clean[12:14]}Z"
    if len(clean) >= 8 and clean[:8].isdigit():
        return f"{clean[0:4]}-{clean[4:6]}-{clean[6:8]}"
    return clean


def _parse_vcard(vcard_array: Any) -> dict[str, str]:
    """Parse RFC 7095 jCard ``vcardArray`` into flat contact fields."""
    info: dict[str, str] = {}
    if (
        not isinstance(vcard_array, list)
        or len(vcard_array) < 2
        or not isinstance(vcard_array[1], list)
    ):
        return info
    for prop in vcard_array[1]:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        pname = str(prop[0]).strip().lower()
        val = prop[3]
        if isinstance(val, list):
            flat = ", ".join(str(x).strip() for x in val if x and str(x).strip())
        else:
            flat = str(val).strip() if val is not None else ""
        if not flat:
            continue
        if pname == "fn" and "name" not in info:
            info["name"] = flat
        elif pname == "org" and "org" not in info:
            info["org"] = flat
        elif pname == "email" and "email" not in info:
            info["email"] = flat
        elif pname == "tel" and "phone" not in info:
            info["phone"] = flat.replace("tel:", "")
        elif pname == "adr" and "address" not in info:
            info["address"] = flat
    return info


def _collect_rdap_entities(
    entities: Any,
    out: list[dict[str, Any]],
) -> None:
    if not isinstance(entities, list):
        return
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = [str(r).strip().lower() for r in (ent.get("roles") or []) if r]
        contact = _parse_vcard(ent.get("vcardArray"))
        handle = str(ent.get("handle") or "").strip()
        pub_ids = [
            f"{p.get('type')}: {p.get('identifier')}"
            for p in (ent.get("publicIds") or [])
            if isinstance(p, dict) and p.get("identifier")
        ]
        if roles or contact or handle:
            out.append(
                {
                    "roles": roles,
                    "handle": handle,
                    "name": contact.get("name") or contact.get("org") or handle,
                    "org": contact.get("org") or "",
                    "email": contact.get("email") or "",
                    "phone": contact.get("phone") or "",
                    "public_ids": pub_ids,
                }
            )
        nested = ent.get("entities")
        if isinstance(nested, list) and nested:
            _collect_rdap_entities(nested, out)


@dataclass
class OSINTSectionOutcome:
    """Normalized outcome returned by an individual passive OSINT source lookup."""

    key: str
    title: str
    status: str  # ok | empty | not_configured | rate_limited | error | skipped
    status_code: int | None = None
    message: str = ""
    count: int = 0
    elapsed_ms: float = 0.0
    data: Any = None
    pivots: list[dict[str, Any]] = field(default_factory=list)


class OSINTClient:
    """Passive, proxy-aware, multi-source free OSINT lookup client."""

    DEFAULT_ENDPOINTS: dict[str, str] = {
        "doh_primary": "https://cloudflare-dns.com/dns-query",
        "doh_fallback": "https://dns.google/resolve",
        "rdap": "https://rdap.org",
        "geoip": "https://ipwho.is",
        "ripestat": "https://stat.ripe.net/data",
        "shodan_internetdb": "https://internetdb.shodan.io",
        "crtsh": "https://crt.sh",
        "urlscan": "https://urlscan.io/api/v1",
        "dshield": "https://isc.sans.edu/api",
        "wayback": "https://web.archive.org/cdx/search/cdx",
        "otx": "https://otx.alienvault.com/api/v1",
        "greynoise": "https://api.greynoise.io/v3/community",
        "hashlookup": "https://hashlookup.circl.lu/lookup",
        "cveawg": "https://cveawg.mitre.org/api/cve",
        "epss": "https://api.first.org/data/v1/epss",
        "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "virustotal": "https://www.virustotal.com/api/v3",
        "abuseipdb": "https://api.abuseipdb.com/api/v2",
        "threatfox": "https://threatfox-api.abuse.ch/api/v1/",
        "urlhaus": "https://urlhaus-api.abuse.ch/api/v1",
        "malwarebazaar": "https://mb-api.abuse.ch/api/v1/",
    }

    _KEV_LOCK = threading.Lock()
    _KEV_MEMORY_CACHE: tuple[float, dict[str, dict[str, Any]]] | None = None

    def __init__(
        self,
        config: OSINTConfig | None = None,
        *,
        session: requests.Session | None = None,
        endpoints: Mapping[str, str] | None = None,
        workspace_dir: Path | str | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        self.config: OSINTConfig = config if config is not None else get_osint_config()
        self.endpoints: dict[str, str] = dict(self.DEFAULT_ENDPOINTS)
        if endpoints:
            self.endpoints.update({k: v.rstrip("/") for k, v in endpoints.items()})
        self.workspace_dir: Path | None = (
            Path(workspace_dir).expanduser().resolve() if workspace_dir is not None else None
        )
        self._stop_event = stop_event
        if session is not None:
            self._session = session
        else:
            sess = ConfiguredSession()
            sess.headers.update({"User-Agent": _USER_AGENT, "Accept": "application/json"})
            self._session = sess
        if self.config.verify_ssl is False:
            suppress_insecure_ssl_warnings()

    @property
    def timeout(self) -> float:
        return self.config.timeout

    def _is_cancelled(self) -> bool:
        return self._stop_event is not None and self._stop_event.is_set()

    def _key_for_source(self, source_key: str) -> str | None:
        key_map: dict[str, str | None] = {
            "osint_virustotal": self.config.vt_api_key,
            "osint_abuseipdb": self.config.abuseipdb_api_key,
            "osint_abusech": self.config.abusech_api_key,
            "osint_otx": self.config.otx_api_key,
            "osint_urlscan": self.config.urlscan_api_key,
            "osint_greynoise": self.config.greynoise_api_key,
        }
        return key_map.get(source_key)

    def source_availability(self) -> list[dict[str, Any]]:
        """Return status summary of all free OSINT sources for UI and CLI inspection."""
        rows: list[dict[str, Any]] = []
        for spec in OSINT_SOURCE_CATALOG:
            api_key = self._key_for_source(spec.key)
            if spec.tier == "free_no_key":
                state = "ready"
                note = "Free (No API key required)"
            elif spec.tier == "free_optional_key":
                state = "key_configured" if api_key else "ready"
                note = (
                    "Free key configured (higher limits)"
                    if api_key
                    else "Free public tier ready (optional free key in Settings)"
                )
            else:
                state = "key_configured" if api_key else "needs_free_key"
                note = (
                    "Free API key configured"
                    if api_key
                    else f"Add free API key in Settings ({spec.signup_url})"
                )
            rows.append(
                {
                    "key": spec.key,
                    "short_name": spec.short_name,
                    "title": spec.title,
                    "category": spec.category,
                    "tier": spec.tier,
                    "state": state,
                    "configured": state in ("ready", "key_configured"),
                    "has_key": bool(api_key),
                    "setting_key": spec.setting_key,
                    "supported_kinds": list(spec.supported_kinds),
                    "description": spec.description,
                    "signup_url": spec.signup_url,
                    "note": note,
                }
            )
        return rows

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        json_body: Any = None,
        data: Any = None,
        timeout: float | None = None,
        allow_404: bool = False,
    ) -> tuple[int, Any, str | None]:
        """Execute an HTTP request and return ``(status_code, parsed_json_or_None, error_msg)``."""
        if self._is_cancelled():
            return 0, None, "Cancelled"
        req_headers = {"User-Agent": _USER_AGENT}
        if headers:
            req_headers.update(headers)
        try:
            resp = self._session.request(
                method,
                url,
                params=params,
                headers=req_headers,
                json=json_body,
                data=data,
                timeout=timeout or self.timeout,
                verify=self.config.verify_ssl,
            )
        except requests.Timeout:
            return 0, None, f"Timed out after {timeout or self.timeout:.1f}s"
        except requests.RequestException as exc:
            return 0, None, str(exc)

        code = int(resp.status_code)
        if code == 404 and allow_404:
            return 404, None, None
        if code == 429:
            retry = resp.headers.get("Retry-After") or resp.headers.get("X-Rate-Limit-Reset-After")
            hint = f" (retry after {retry}s)" if retry else ""
            return 429, None, f"Rate limited (HTTP 429){hint}"
        if code in (401, 403):
            return code, None, f"Authentication required / denied (HTTP {code})"
        if code >= 400:
            snippet = (resp.text or "").strip().replace("\n", " ")[:160]
            return code, None, f"HTTP {code}: {snippet}" if snippet else f"HTTP {code}"
        try:
            return code, resp.json(), None
        except ValueError:
            return code, None, "Response was not valid JSON"

    # ------------------------------------------------------------------
    # 1. DNS & Email Security (DoH)
    # ------------------------------------------------------------------

    def _doh_query(self, name: str, rtype: str) -> tuple[int | None, dict[str, Any] | None, str | None]:
        """Query Cloudflare DoH JSON with automatic fallback to Google DoH."""
        primary = self.endpoints["doh_primary"]
        code, payload, err = self._request_json(
            "GET",
            primary,
            params={"name": name, "type": rtype},
            headers={"Accept": "application/dns-json"},
            timeout=min(self.timeout, 6.0),
        )
        if err is None and isinstance(payload, dict):
            return code, payload, None

        fallback = self.endpoints["doh_fallback"]
        if fallback and fallback != primary:
            code2, payload2, err2 = self._request_json(
                "GET",
                fallback,
                params={"name": name, "type": rtype},
                headers={"Accept": "application/json"},
                timeout=min(self.timeout, 6.0),
            )
            if err2 is None and isinstance(payload2, dict):
                return code2, payload2, None
            return code2, None, err2 or err
        return code, None, err

    def lookup_dns(self, target: str, kind: str) -> OSINTSectionOutcome:
        """Resolve DNS records, reverse PTR, DNSSEC, and SPF/DMARC email posture via DoH."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_dns"]
        pivots: list[dict[str, Any]] = []

        if kind == "ip":
            try:
                ip_obj = ipaddress.ip_address(target.strip())
            except ValueError:
                return OSINTSectionOutcome(
                    key=spec.key, title=spec.title, status="skipped", message="Invalid IP address."
                )
            rev_name = ip_obj.reverse_pointer
            code, payload, err = self._doh_query(rev_name, "PTR")
            elapsed = round((time.perf_counter() - started) * 1000.0, 2)
            if err or not isinstance(payload, dict):
                return OSINTSectionOutcome(
                    key=spec.key,
                    title=spec.title,
                    status="error",
                    status_code=code or None,
                    message=err or "Reverse DNS query failed.",
                    elapsed_ms=elapsed,
                )
            rcode_num = int(payload.get("Status", 0))
            rcode = _DNS_RCODE_NAMES.get(rcode_num, str(rcode_num))
            answers = [
                a for a in (payload.get("Answer") or []) if isinstance(a, dict)
            ]
            ptrs: list[str] = []
            records: list[dict[str, Any]] = []
            for ans in answers:
                val = str(ans.get("data") or "").strip().rstrip(".")
                if not val:
                    continue
                ptrs.append(val)
                records.append(
                    {
                        "type": "PTR",
                        "name": str(ans.get("name") or rev_name).rstrip("."),
                        "ttl": ans.get("TTL"),
                        "value": val,
                    }
                )
                if "." in val:
                    pivots.append(
                        {
                            "entity_id": f"idn:{val.lower()}",
                            "name": val.lower(),
                            "entity_type": "InternetDomainName",
                            "source_section": spec.key,
                            "relationship": "Reverse DNS (PTR)",
                            "pivot_kind": "domain",
                        }
                    )
            data = {
                "query": target,
                "reverse_pointer": rev_name,
                "rcode": rcode,
                "dnssec": bool(payload.get("AD")),
                "ptr": ptrs,
                "records": records,
            }
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="ok" if ptrs else "empty",
                status_code=200,
                message=f"PTR: {', '.join(ptrs[:3])}" if ptrs else f"No PTR record ({rcode}).",
                count=len(ptrs),
                elapsed_ms=elapsed,
                data=data,
                pivots=pivots,
            )

        domain = target.strip().lower().rstrip(".")
        if kind == "url":
            host = urlparse(target).hostname
            domain = host.lower().rstrip(".") if host else ""
        elif kind == "email" and "@" in domain:
            domain = domain.split("@", 1)[1].strip()
        if not domain or "." not in domain:
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message=f"DNS skipped for {kind}."
            )

        queries: list[tuple[str, str]] = [
            (domain, "A"),
            (domain, "AAAA"),
            (domain, "NS"),
            (domain, "MX"),
            (domain, "TXT"),
            (domain, "CNAME"),
            (domain, "SOA"),
            (domain, "CAA"),
            (f"_dmarc.{domain}", "TXT"),
        ]
        raw_results: dict[tuple[str, str], tuple[int | None, dict[str, Any] | None, str | None]] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            fmap = {pool.submit(self._doh_query, qname, qtype): (qname, qtype) for qname, qtype in queries}
            for fut in concurrent.futures.as_completed(fmap):
                raw_results[fmap[fut]] = fut.result()

        records_by_type: dict[str, list[str]] = {}
        flat_records: list[dict[str, Any]] = []
        dmarc_records: list[str] = []
        any_success = False
        rcode_num = 0
        dnssec = False
        first_err: str | None = None

        for (qname, qtype), (_code, payload, err) in raw_results.items():
            if err or not isinstance(payload, dict):
                if first_err is None and err:
                    first_err = err
                continue
            any_success = True
            if qname == domain and qtype == "A":
                rcode_num = int(payload.get("Status", 0))
                dnssec = bool(payload.get("AD"))
            elif payload.get("AD"):
                dnssec = True
            for ans in payload.get("Answer") or []:
                if not isinstance(ans, dict):
                    continue
                ans_type = _DNS_TYPE_NUM_TO_NAME.get(int(ans.get("type", 0)), qtype)
                val = str(ans.get("data") or "").strip()
                if not val:
                    continue
                if qname.startswith("_dmarc."):
                    cleaned_txt = val.strip('"')
                    if cleaned_txt not in dmarc_records:
                        dmarc_records.append(cleaned_txt)
                    flat_records.append(
                        {"type": "DMARC", "name": qname, "ttl": ans.get("TTL"), "value": cleaned_txt}
                    )
                    continue
                cleaned = val.strip('"') if ans_type == "TXT" else val.rstrip(".")
                records_by_type.setdefault(ans_type, [])
                if cleaned not in records_by_type[ans_type]:
                    records_by_type[ans_type].append(cleaned)
                flat_records.append(
                    {
                        "type": ans_type,
                        "name": str(ans.get("name") or qname).rstrip("."),
                        "ttl": ans.get("TTL"),
                        "value": cleaned,
                    }
                )

        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if not any_success:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                message=first_err or "DoH DNS resolution failed.",
                elapsed_ms=elapsed,
            )

        a_records = records_by_type.get("A", [])
        aaaa_records = records_by_type.get("AAAA", [])
        ns_records = records_by_type.get("NS", [])
        mx_records = records_by_type.get("MX", [])
        txt_records = records_by_type.get("TXT", [])
        cname_records = records_by_type.get("CNAME", [])

        # Email security analysis (SPF & DMARC)
        spf_record = next((t for t in txt_records if t.lower().startswith("v=spf1")), "")
        if not spf_record:
            spf_status = "Missing"
        elif "-all" in spf_record.lower():
            spf_status = "Strict (-all hardfail)"
        elif "~all" in spf_record.lower():
            spf_status = "Softfail (~all)"
        elif "+all" in spf_record.lower():
            spf_status = "Permissive (+all — weak!)"
        else:
            spf_status = "Present"

        dmarc_record = next((d for d in dmarc_records if "v=dmarc1" in d.lower()), "")
        dmarc_policy = "Missing"
        if dmarc_record:
            m_pol = re.search(r"(?:^|[;\s])p\s*=\s*([a-zA-Z]+)", dmarc_record, re.IGNORECASE)
            dmarc_policy = m_pol.group(1).lower() if m_pol else "present"

        # Extract actionable pivots
        for ip_val in a_records[:6] + aaaa_records[:4]:
            try:
                ipaddress.ip_address(ip_val)
            except ValueError:
                continue
            pivots.append(
                {
                    "entity_id": f"ip:{ip_val}",
                    "name": ip_val,
                    "entity_type": "IpAddress",
                    "source_section": spec.key,
                    "relationship": f"DNS {'AAAA' if ':' in ip_val else 'A'} Record",
                    "pivot_kind": "ip",
                }
            )
        for ns_val in ns_records[:4]:
            clean_ns = ns_val.lower().rstrip(".")
            if "." in clean_ns:
                pivots.append(
                    {
                        "entity_id": f"idn:{clean_ns}",
                        "name": clean_ns,
                        "entity_type": "InternetDomainName",
                        "source_section": spec.key,
                        "relationship": "Authoritative Nameserver (NS)",
                        "pivot_kind": "domain",
                    }
                )
        for mx_val in mx_records[:4]:
            mx_host = mx_val.split()[-1].lower().rstrip(".")
            if "." in mx_host and mx_host != domain:
                pivots.append(
                    {
                        "entity_id": f"idn:{mx_host}",
                        "name": mx_host,
                        "entity_type": "InternetDomainName",
                        "source_section": spec.key,
                        "relationship": "Mail Exchanger (MX)",
                        "pivot_kind": "domain",
                    }
                )
        for cn_val in cname_records[:3]:
            clean_cn = cn_val.lower().rstrip(".")
            if "." in clean_cn and clean_cn != domain:
                pivots.append(
                    {
                        "entity_id": f"idn:{clean_cn}",
                        "name": clean_cn,
                        "entity_type": "InternetDomainName",
                        "source_section": spec.key,
                        "relationship": "CNAME Target",
                        "pivot_kind": "domain",
                    }
                )

        rcode = _DNS_RCODE_NAMES.get(rcode_num, str(rcode_num))
        data = {
            "domain": domain,
            "rcode": rcode,
            "dnssec": dnssec,
            "a": a_records,
            "aaaa": aaaa_records,
            "ns": ns_records,
            "mx": mx_records,
            "txt": txt_records,
            "cname": cname_records,
            "soa": records_by_type.get("SOA", []),
            "caa": records_by_type.get("CAA", []),
            "spf": spf_record,
            "spf_status": spf_status,
            "dmarc": dmarc_record,
            "dmarc_policy": dmarc_policy,
            "records": flat_records,
        }
        total_cnt = len(flat_records)
        summary_bits = []
        if a_records:
            summary_bits.append(f"A: {', '.join(a_records[:2])}")
        if rcode == "NXDOMAIN":
            summary_bits.append("NXDOMAIN")
        summary_bits.append(f"{total_cnt} record(s)")
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok" if (total_cnt > 0 or rcode == "NXDOMAIN") else "empty",
            status_code=200,
            message=" | ".join(summary_bits),
            count=max(total_cnt, 1 if rcode == "NXDOMAIN" else 0),
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots,
        )

    # ------------------------------------------------------------------
    # 2. WHOIS / RDAP (IANA Bootstrap)
    # ------------------------------------------------------------------

    def lookup_rdap(self, target: str, kind: str) -> OSINTSectionOutcome:
        """Query official IANA RDAP for domain, IP netblock, or ASN registration data."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_rdap"]
        base = self.endpoints["rdap"]
        pivots: list[dict[str, Any]] = []

        if kind == "ip":
            if not is_public_ip(target):
                return OSINTSectionOutcome(
                    key=spec.key,
                    title=spec.title,
                    status="skipped",
                    message="Private / non-routable IP address.",
                )
            url = f"{base}/ip/{quote(target.strip(), safe='')}"
            code, payload, err = self._request_json("GET", url, allow_404=True)
            queried = target.strip()
        elif kind == "asn":
            m_asn = _ASN_NUM_RE.match(target.strip())
            if not m_asn:
                return OSINTSectionOutcome(
                    key=spec.key, title=spec.title, status="skipped", message="Invalid ASN."
                )
            asn_num = m_asn.group(1)
            url = f"{base}/autnum/{asn_num}"
            code, payload, err = self._request_json("GET", url, allow_404=True)
            queried = f"AS{asn_num}"
        elif kind in ("domain", "url", "email"):
            dom = target.strip().lower().rstrip(".")
            if kind == "url":
                host = urlparse(target).hostname
                dom = host.lower().rstrip(".") if host else ""
            elif kind == "email" and "@" in dom:
                dom = dom.split("@", 1)[1].strip()
            if not dom or "." not in dom:
                return OSINTSectionOutcome(
                    key=spec.key, title=spec.title, status="skipped", message="No domain to query."
                )
            queried = dom
            code, payload, err = self._request_json(
                "GET", f"{base}/domain/{quote(dom, safe='')}", allow_404=True
            )
            apex = extract_registrable_domain(dom)
            if (code == 404 or not isinstance(payload, dict)) and apex != dom:
                queried = apex
                code, payload, err = self._request_json(
                    "GET", f"{base}/domain/{quote(apex, safe='')}", allow_404=True
                )
        else:
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message=f"RDAP skipped for {kind}."
            )

        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if code == 404 and err is None:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=404,
                message=f"No RDAP registration record found for {queried}.",
                elapsed_ms=elapsed,
            )
        if err or not isinstance(payload, dict):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                status_code=code or None,
                message=err or "RDAP lookup failed.",
                elapsed_ms=elapsed,
            )

        events_map: dict[str, str] = {}
        for ev in payload.get("events") or []:
            if isinstance(ev, dict) and ev.get("eventAction") and ev.get("eventDate"):
                action = str(ev["eventAction"]).strip().lower()
                events_map[action] = str(ev["eventDate"]).strip()

        created = events_map.get("registration") or events_map.get("created") or ""
        expires = events_map.get("expiration") or ""
        updated = events_map.get("last changed") or events_map.get("last update of rdap database") or ""

        age_days: int | None = None
        age_flag = ""
        created_dt = _parse_iso_datetime(created)
        if created_dt is not None:
            age_days = max(0, (datetime.now(UTC) - created_dt).days)
            if age_days <= 30:
                age_flag = "newly_registered"
            elif age_days <= 90:
                age_flag = "recent"
            else:
                age_flag = "established"

        contacts: list[dict[str, Any]] = []
        _collect_rdap_entities(payload.get("entities"), contacts)

        registrar = ""
        registrant = ""
        abuse_email = ""
        for ent in contacts:
            roles = set(ent.get("roles") or [])
            if "registrar" in roles and not registrar:
                registrar = str(ent.get("name") or ent.get("org") or ent.get("handle") or "")
            if ("registrant" in roles or "administrative" in roles) and not registrant:
                registrant = str(ent.get("org") or ent.get("name") or "")
            if "abuse" in roles and ent.get("email") and not abuse_email:
                abuse_email = str(ent["email"])
        if not abuse_email:
            for ent in contacts:
                if ent.get("email"):
                    abuse_email = str(ent["email"])
                    break

        nameservers: list[str] = []
        for ns in payload.get("nameservers") or []:
            if isinstance(ns, dict) and ns.get("ldhName"):
                ns_name = str(ns["ldhName"]).strip().lower().rstrip(".")
                if ns_name and ns_name not in nameservers:
                    nameservers.append(ns_name)

        cidrs: list[str] = []
        for cidr_obj in payload.get("cidr0_cidrs") or []:
            if isinstance(cidr_obj, dict):
                v4 = cidr_obj.get("v4prefix")
                v6 = cidr_obj.get("v6prefix")
                length = cidr_obj.get("length")
                if v4 and length is not None:
                    cidrs.append(f"{v4}/{length}")
                elif v6 and length is not None:
                    cidrs.append(f"{v6}/{length}")

        statuses = [str(s) for s in (payload.get("status") or []) if s]
        sec_dns = _as_dict(payload.get("secureDNS"))

        data: dict[str, Any] = {
            "object_class": str(payload.get("objectClassName") or kind),
            "queried": queried,
            "handle": str(payload.get("handle") or ""),
            "name": str(payload.get("ldhName") or payload.get("name") or queried),
            "registrar": registrar,
            "registrant": registrant,
            "abuse_email": abuse_email,
            "created": created,
            "updated": updated,
            "expires": expires,
            "age_days": age_days,
            "age_flag": age_flag,
            "statuses": statuses,
            "nameservers": nameservers,
            "dnssec_signed": sec_dns.get("delegationSigned"),
            "country": str(payload.get("country") or ""),
            "start_address": str(payload.get("startAddress") or ""),
            "end_address": str(payload.get("endAddress") or ""),
            "ip_version": str(payload.get("ipVersion") or ""),
            "network_type": str(payload.get("type") or ""),
            "cidrs": cidrs,
            "contacts": contacts[:10],
        }

        if abuse_email and "@" in abuse_email:
            pivots.append(
                {
                    "entity_id": f"email:{abuse_email.lower()}",
                    "name": abuse_email.lower(),
                    "entity_type": "EmailAddress",
                    "source_section": spec.key,
                    "relationship": "RDAP Abuse Contact",
                    "pivot_kind": "email",
                }
            )
        for ns_val in nameservers[:4]:
            pivots.append(
                {
                    "entity_id": f"idn:{ns_val}",
                    "name": ns_val,
                    "entity_type": "InternetDomainName",
                    "source_section": spec.key,
                    "relationship": "RDAP Nameserver",
                    "pivot_kind": "domain",
                }
            )

        summary_bits: list[str] = []
        if registrar:
            summary_bits.append(registrar)
        elif data["name"] and kind == "ip":
            summary_bits.append(data["name"])
        if age_days is not None and kind in ("domain", "url", "email"):
            nrd_tag = " [NEWLY REGISTERED!]" if age_flag == "newly_registered" else ""
            summary_bits.append(f"Age {age_days}d{nrd_tag}")
        if data["country"]:
            summary_bits.append(data["country"])
        if cidrs:
            summary_bits.append(cidrs[0])

        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=code,
            message=" | ".join(summary_bits) or f"RDAP record retrieved for {queried}.",
            count=1,
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots,
        )

    # ------------------------------------------------------------------
    # 3. IP Geolocation & ISP (ipwho.is)
    # ------------------------------------------------------------------

    def lookup_geoip(
        self,
        ip_value: str,
        *,
        resolved_from: str | None = None,
    ) -> OSINTSectionOutcome:
        """Fetch free HTTPS IP geolocation, ISP, org & ASN from ipwho.is."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_geoip"]
        if not is_public_ip(ip_value):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="skipped",
                message="Private / non-routable IP address.",
            )
        url = f"{self.endpoints['geoip']}/{quote(ip_value.strip(), safe='')}"
        code, payload, err = self._request_json("GET", url)
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if err or not isinstance(payload, dict):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                status_code=code or None,
                message=err or "GeoIP lookup failed.",
                elapsed_ms=elapsed,
            )
        if payload.get("success") is False:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=code,
                message=str(payload.get("message") or "GeoIP lookup returned no data."),
                elapsed_ms=elapsed,
            )

        conn = _as_dict(payload.get("connection"))
        tz_obj = _as_dict(payload.get("timezone"))
        asn_num = conn.get("asn")
        asn_str = f"AS{asn_num}" if asn_num else ""

        data = {
            "ip": str(payload.get("ip") or ip_value),
            "resolved_from": resolved_from or "",
            "continent": str(payload.get("continent") or ""),
            "country": str(payload.get("country") or ""),
            "country_code": str(payload.get("country_code") or ""),
            "region": str(payload.get("region") or ""),
            "city": str(payload.get("city") or ""),
            "latitude": payload.get("latitude"),
            "longitude": payload.get("longitude"),
            "timezone": str(tz_obj.get("id") or ""),
            "utc_offset": str(tz_obj.get("utc") or ""),
            "asn": asn_str,
            "org": str(conn.get("org") or ""),
            "isp": str(conn.get("isp") or ""),
            "domain": str(conn.get("domain") or ""),
        }
        pivots: list[dict[str, Any]] = []
        if asn_str:
            pivots.append(
                {
                    "entity_id": f"asn:{asn_str}",
                    "name": asn_str,
                    "entity_type": "ASNumber",
                    "source_section": spec.key,
                    "relationship": f"Hosting ASN ({data['org'] or data['isp'] or 'GeoIP'})",
                    "pivot_kind": "asn",
                }
            )

        loc = ", ".join(p for p in (data["city"], data["region"], data["country_code"] or data["country"]) if p)
        isp = data["org"] or data["isp"]
        msg = " | ".join(p for p in (loc, asn_str, isp) if p)
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=code,
            message=msg or "GeoIP retrieved.",
            count=1,
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots,
        )

    # ------------------------------------------------------------------
    # 4. BGP / ASN Routing (RIPEstat)
    # ------------------------------------------------------------------

    def lookup_bgp(
        self,
        target: str,
        kind: str,
        *,
        resolved_from: str | None = None,
    ) -> OSINTSectionOutcome:
        """Query RIPEstat official Data API for BGP prefix, ASN holder & abuse contacts."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_bgp"]
        base = self.endpoints["ripestat"]
        pivots: list[dict[str, Any]] = []

        if kind == "asn":
            m_asn = _ASN_NUM_RE.match(target.strip())
            if not m_asn:
                return OSINTSectionOutcome(
                    key=spec.key, title=spec.title, status="skipped", message="Invalid ASN."
                )
            asn_label = f"AS{m_asn.group(1)}"
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                f_ov = pool.submit(
                    self._request_json,
                    "GET",
                    f"{base}/as-overview/data.json",
                    params={"resource": asn_label},
                )
                f_pf = pool.submit(
                    self._request_json,
                    "GET",
                    f"{base}/announced-prefixes/data.json",
                    params={"resource": asn_label},
                )
                f_ab = pool.submit(
                    self._request_json,
                    "GET",
                    f"{base}/abuse-contact-finder/data.json",
                    params={"resource": asn_label},
                )
                c_ov, p_ov, e_ov = f_ov.result()
                _c_pf, p_pf, _e_pf = f_pf.result()
                _c_ab, p_ab, _e_ab = f_ab.result()

            elapsed = round((time.perf_counter() - started) * 1000.0, 2)
            if e_ov or not isinstance(p_ov, dict):
                return OSINTSectionOutcome(
                    key=spec.key,
                    title=spec.title,
                    status="error",
                    status_code=c_ov or None,
                    message=e_ov or "RIPEstat ASN lookup failed.",
                    elapsed_ms=elapsed,
                )
            ov_data = _as_dict(p_ov.get("data"))
            pf_data = _as_dict(_as_dict(p_pf).get("data"))
            ab_data = _as_dict(_as_dict(p_ab).get("data"))

            raw_prefixes = [
                str(item.get("prefix"))
                for item in (pf_data.get("prefixes") or [])
                if isinstance(item, dict) and item.get("prefix")
            ]
            v4_pf = [p for p in raw_prefixes if ":" not in p]
            v6_pf = [p for p in raw_prefixes if ":" in p]
            abuse = [str(a) for a in (ab_data.get("abuse_contacts") or []) if a]
            holder = str(ov_data.get("holder") or "")
            data: dict[str, Any] = {
                "mode": "asn",
                "asn": asn_label,
                "holder": holder,
                "announced": bool(ov_data.get("announced", True)),
                "block": _as_dict(ov_data.get("block")),
                "prefix_count": len(raw_prefixes),
                "ipv4_count": len(v4_pf),
                "ipv6_count": len(v6_pf),
                "ipv4_prefixes": v4_pf[:25],
                "ipv6_prefixes": v6_pf[:15],
                "abuse_contacts": abuse,
            }
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="ok",
                status_code=c_ov,
                message=f"{asn_label} ({holder or 'Unknown'}) | {len(raw_prefixes)} announced prefix(es)",
                count=max(1, len(raw_prefixes)),
                elapsed_ms=elapsed,
                data=data,
                pivots=pivots,
            )

        # IP mode
        if not is_public_ip(target):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="skipped",
                message="Private / non-routable IP address.",
            )
        ip_clean = target.strip()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f_net = pool.submit(
                self._request_json,
                "GET",
                f"{base}/network-info/data.json",
                params={"resource": ip_clean},
            )
            f_ab = pool.submit(
                self._request_json,
                "GET",
                f"{base}/abuse-contact-finder/data.json",
                params={"resource": ip_clean},
            )
            c_net, p_net, e_net = f_net.result()
            _c_ab, p_ab, _e_ab = f_ab.result()

        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if e_net or not isinstance(p_net, dict):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                status_code=c_net or None,
                message=e_net or "RIPEstat network-info lookup failed.",
                elapsed_ms=elapsed,
            )
        net_data = _as_dict(p_net.get("data"))
        ab_data = _as_dict(_as_dict(p_ab).get("data"))

        raw_asns = [str(a) for a in (net_data.get("asns") or []) if a is not None]
        asns = [a if a.upper().startswith("AS") else f"AS{a}" for a in raw_asns]
        prefix = str(net_data.get("prefix") or "")
        holder = str(net_data.get("holder") or "")
        abuse = [str(a) for a in (ab_data.get("abuse_contacts") or []) if a]
        holder_info = _as_dict(ab_data.get("holder_info"))
        if not holder and holder_info:
            holder = str(holder_info.get("name") or "")

        for asn_str in asns[:3]:
            pivots.append(
                {
                    "entity_id": f"asn:{asn_str}",
                    "name": asn_str,
                    "entity_type": "ASNumber",
                    "source_section": spec.key,
                    "relationship": f"BGP Origin ASN ({prefix or 'RIPEstat'})",
                    "pivot_kind": "asn",
                }
            )
        for ab_email in abuse[:2]:
            if "@" in ab_email:
                pivots.append(
                    {
                        "entity_id": f"email:{ab_email.lower()}",
                        "name": ab_email.lower(),
                        "entity_type": "EmailAddress",
                        "source_section": spec.key,
                        "relationship": "RIPEstat Abuse Contact",
                        "pivot_kind": "email",
                    }
                )

        data = {
            "mode": "ip",
            "ip": ip_clean,
            "resolved_from": resolved_from or "",
            "prefix": prefix,
            "asns": asns,
            "holder": holder,
            "abuse_contacts": abuse,
        }
        has_info = bool(prefix or asns or abuse)
        msg = " | ".join(p for p in (prefix, ", ".join(asns), holder) if p)
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok" if has_info else "empty",
            status_code=c_net,
            message=msg or "No BGP routing announcement found.",
            count=1 if has_info else 0,
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots,
        )

    # ------------------------------------------------------------------
    # 5. Shodan InternetDB (Free, No Key)
    # ------------------------------------------------------------------

    def lookup_shodan(
        self,
        ip_value: str,
        *,
        resolved_from: str | None = None,
    ) -> OSINTSectionOutcome:
        """Query Shodan InternetDB for open ports, CPEs, known CVEs, hostnames & tags."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_shodan"]
        if not is_public_ip(ip_value):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="skipped",
                message="Private / non-routable IP address.",
            )
        ip_clean = ip_value.strip()
        url = f"{self.endpoints['shodan_internetdb']}/{quote(ip_clean, safe='')}"
        code, payload, err = self._request_json("GET", url, allow_404=True)
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if code == 404 and err is None:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=404,
                message="No open ports or services indexed in Shodan InternetDB.",
                elapsed_ms=elapsed,
            )
        if err or not isinstance(payload, dict):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                status_code=code or None,
                message=err or "Shodan InternetDB lookup failed.",
                elapsed_ms=elapsed,
            )

        ports = sorted(int(p) for p in (payload.get("ports") or []) if isinstance(p, int))
        port_services = [
            {"port": p, "service": _WELL_KNOWN_PORTS.get(p, "Unknown")} for p in ports
        ]
        cpes = [str(c) for c in (payload.get("cpes") or []) if c]
        vulns = [str(v).upper() for v in (payload.get("vulns") or []) if v]
        hostnames = [str(h).lower().rstrip(".") for h in (payload.get("hostnames") or []) if h]
        tags = [str(t) for t in (payload.get("tags") or []) if t]

        pivots: list[dict[str, Any]] = []
        for cve in vulns[:15]:
            if _CVE_RE.match(cve):
                pivots.append(
                    {
                        "entity_id": cve,
                        "name": cve,
                        "entity_type": "CyberVulnerability",
                        "source_section": spec.key,
                        "relationship": f"Shodan Detected CVE on {ip_clean}",
                        "pivot_kind": "vulnerability",
                    }
                )
        for hn in hostnames[:10]:
            if "." in hn:
                pivots.append(
                    {
                        "entity_id": f"idn:{hn}",
                        "name": hn,
                        "entity_type": "InternetDomainName",
                        "source_section": spec.key,
                        "relationship": f"Shodan Hostname on {ip_clean}",
                        "pivot_kind": "domain",
                    }
                )

        data = {
            "ip": ip_clean,
            "resolved_from": resolved_from or "",
            "ports": ports,
            "port_services": port_services,
            "cpes": cpes,
            "vulns": vulns,
            "hostnames": hostnames,
            "tags": tags,
        }
        has_data = bool(ports or cpes or vulns or hostnames or tags)
        bits = [f"{len(ports)} port(s)"]
        if ports:
            bits[-1] += f" ({', '.join(str(p) for p in ports[:6])}{'...' if len(ports) > 6 else ''})"
        if vulns:
            bits.append(f"{len(vulns)} CVE(s)")
        if tags:
            bits.append(f"tags: {', '.join(tags[:4])}")
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok" if has_data else "empty",
            status_code=code,
            message=" | ".join(bits) if has_data else "No Shodan metadata returned.",
            count=max(len(ports), 1 if has_data else 0),
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots,
        )

    # ------------------------------------------------------------------
    # 6. Certificate Transparency (crt.sh)
    # ------------------------------------------------------------------

    def lookup_crtsh(self, domain: str) -> OSINTSectionOutcome:
        """Query crt.sh Certificate Transparency logs for TLS certs & discovered subdomains."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_crtsh"]
        clean_dom = domain.strip().lower().rstrip(".")
        if not clean_dom or "." not in clean_dom:
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message="Invalid domain."
            )
        url = f"{self.endpoints['crtsh']}/"
        code, payload, err = self._request_json(
            "GET",
            url,
            params={"q": clean_dom, "output": "json"},
            timeout=max(self.timeout, 10.0),
        )
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if err or not isinstance(payload, list):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                status_code=code or None,
                message=err or "crt.sh query failed.",
                elapsed_ms=elapsed,
            )
        if not payload:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=code,
                message=f"No Certificate Transparency logs found for {clean_dom}.",
                elapsed_ms=elapsed,
            )

        subdomains: set[str] = set()
        issuers: set[str] = set()
        timestamps: list[str] = []
        recent_certs: list[dict[str, Any]] = []
        seen_serials: set[str] = set()

        for entry in payload[:500]:
            if not isinstance(entry, dict):
                continue
            issuer_raw = str(entry.get("issuer_name") or "")
            m_org = re.search(r"O=([^,]+)", issuer_raw)
            m_cn = re.search(r"CN=([^,]+)", issuer_raw)
            issuer_clean = (m_org.group(1) if m_org else (m_cn.group(1) if m_cn else issuer_raw)).strip()
            if issuer_clean:
                issuers.add(issuer_clean)
            ts = str(entry.get("entry_timestamp") or entry.get("not_before") or "").strip()
            if ts:
                timestamps.append(ts)
            name_val = str(entry.get("name_value") or entry.get("common_name") or "")
            for line in name_val.splitlines():
                cand = line.strip().lower().lstrip("*.")
                if cand and "." in cand and " " not in cand and "@" not in cand:
                    subdomains.add(cand)
            serial = str(entry.get("serial_number") or entry.get("id") or "")
            if serial not in seen_serials and len(recent_certs) < 15:
                seen_serials.add(serial)
                recent_certs.append(
                    {
                        "id": entry.get("id"),
                        "common_name": str(entry.get("common_name") or ""),
                        "issuer": issuer_clean,
                        "not_before": str(entry.get("not_before") or ""),
                        "not_after": str(entry.get("not_after") or ""),
                        "logged": ts,
                    }
                )

        sorted_subs = sorted(s for s in subdomains if s != clean_dom)
        timestamps.sort()
        pivots: list[dict[str, Any]] = [
            {
                "entity_id": f"idn:{sub}",
                "name": sub,
                "entity_type": "InternetDomainName",
                "source_section": spec.key,
                "relationship": "Certificate Transparency SAN / Subdomain",
                "pivot_kind": "domain",
            }
            for sub in sorted_subs[:15]
        ]

        data = {
            "domain": clean_dom,
            "total_certs": len(payload),
            "unique_subdomains_count": len(sorted_subs),
            "subdomains": sorted_subs[:80],
            "issuers": sorted(issuers)[:15],
            "earliest_cert": timestamps[0] if timestamps else "",
            "latest_cert": timestamps[-1] if timestamps else "",
            "recent_certs": recent_certs,
        }
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=code,
            message=f"{len(payload)} cert(s) | {len(sorted_subs)} subdomain(s) | {', '.join(sorted(issuers)[:2]) or 'CT logs'}",
            count=len(payload),
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots,
        )

    # ------------------------------------------------------------------
    # 7. URLScan.io Public Search (Free, Optional Key)
    # ------------------------------------------------------------------

    def lookup_urlscan(self, target: str, kind: str) -> OSINTSectionOutcome:
        """Query URLScan.io public search API for historical web scans & verdicts."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_urlscan"]
        clean = target.strip()
        if kind == "domain":
            q = f"domain:{clean.lower()}"
        elif kind == "ip":
            if not is_public_ip(clean):
                return OSINTSectionOutcome(
                    key=spec.key, title=spec.title, status="skipped", message="Private IP."
                )
            q = f"page.ip:{clean}"
        elif kind == "url":
            host = urlparse(clean).hostname
            q = f"domain:{host.lower()}" if host else f'page.url:"{clean}"'
        elif kind == "hash" and len(clean) == 64:
            q = f"hash:{clean.lower()}"
        else:
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message=f"URLScan skipped for {kind}."
            )

        headers: dict[str, str] = {}
        if self.config.urlscan_api_key:
            headers["API-Key"] = self.config.urlscan_api_key

        code, payload, err = self._request_json(
            "GET",
            f"{self.endpoints['urlscan']}/search/",
            params={"q": q, "size": 10},
            headers=headers,
        )
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if code == 429:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="rate_limited",
                status_code=429,
                message=err or "URLScan rate limit reached (add free API key in Settings).",
                elapsed_ms=elapsed,
            )
        if err or not isinstance(payload, dict):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                status_code=code or None,
                message=err or "URLScan search failed.",
                elapsed_ms=elapsed,
            )

        results = [r for r in (payload.get("results") or []) if isinstance(r, dict)]
        total = int(payload.get("total") or len(results))
        if not results:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=code,
                message="No public URLScan.io captures found.",
                elapsed_ms=elapsed,
            )

        scans: list[dict[str, Any]] = []
        malicious_count = 0
        brands: set[str] = set()
        categories: set[str] = set()
        pivots: list[dict[str, Any]] = []
        seen_pivot_ids: set[str] = set()

        for res in results[:10]:
            task = _as_dict(res.get("task"))
            page = _as_dict(res.get("page"))
            verdicts = _as_dict(res.get("verdicts"))
            overall = _as_dict(verdicts.get("overall"))
            is_mal = bool(overall.get("malicious"))
            if is_mal:
                malicious_count += 1
            for b in overall.get("brands") or []:
                if b:
                    brands.add(str(b))
            for cat in overall.get("categories") or []:
                if cat:
                    categories.add(str(cat))
            scan_id = str(res.get("_id") or task.get("uuid") or "")
            page_ip = str(page.get("ip") or "")
            page_dom = str(page.get("domain") or "").lower()
            scans.append(
                {
                    "id": scan_id,
                    "time": str(task.get("time") or ""),
                    "url": str(page.get("url") or task.get("url") or ""),
                    "domain": page_dom,
                    "ip": page_ip,
                    "asn": str(page.get("asn") or ""),
                    "asnname": str(page.get("asnname") or ""),
                    "country": str(page.get("country") or ""),
                    "status": page.get("status"),
                    "title": str(page.get("title") or ""),
                    "server": str(page.get("server") or ""),
                    "tls_issuer": str(page.get("tlsIssuer") or ""),
                    "malicious": is_mal,
                    "score": overall.get("score"),
                    "report_url": f"https://urlscan.io/result/{scan_id}/" if scan_id else "",
                    "screenshot_url": str(res.get("screenshot") or ""),
                }
            )
            if page_ip and is_public_ip(page_ip) and f"ip:{page_ip}" not in seen_pivot_ids:
                seen_pivot_ids.add(f"ip:{page_ip}")
                pivots.append(
                    {
                        "entity_id": f"ip:{page_ip}",
                        "name": page_ip,
                        "entity_type": "IpAddress",
                        "source_section": spec.key,
                        "relationship": "URLScan Hosting IP",
                        "pivot_kind": "ip",
                    }
                )
            if page_dom and "." in page_dom and f"idn:{page_dom}" not in seen_pivot_ids:
                seen_pivot_ids.add(f"idn:{page_dom}")
                pivots.append(
                    {
                        "entity_id": f"idn:{page_dom}",
                        "name": page_dom,
                        "entity_type": "InternetDomainName",
                        "source_section": spec.key,
                        "relationship": "URLScan Captured Domain",
                        "pivot_kind": "domain",
                    }
                )

        data = {
            "query": q,
            "total": total,
            "malicious_count": malicious_count,
            "brands": sorted(brands),
            "categories": sorted(categories),
            "scans": scans,
        }
        mal_str = f" | {malicious_count} MALICIOUS" if malicious_count else ""
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=code,
            message=f"{total} scan(s){mal_str}",
            count=len(scans),
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots[:10],
        )

    # ------------------------------------------------------------------
    # 8. SANS ISC / DShield (Free, No Key)
    # ------------------------------------------------------------------

    def lookup_dshield(
        self,
        ip_value: str,
        *,
        resolved_from: str | None = None,
    ) -> OSINTSectionOutcome:
        """Query SANS Internet Storm Center / DShield IP sensor reports."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_dshield"]
        if not is_public_ip(ip_value):
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message="Private IP."
            )
        ip_clean = ip_value.strip()
        code, payload, err = self._request_json(
            "GET",
            f"{self.endpoints['dshield']}/ip/{quote(ip_clean, safe='')}",
            params={"json": ""},
        )
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if err or not isinstance(payload, dict):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                status_code=code or None,
                message=err or "SANS DShield lookup failed.",
                elapsed_ms=elapsed,
            )
        ip_obj = _as_dict(payload.get("ip"))
        if not ip_obj:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=code,
                message="No SANS DShield data returned.",
                elapsed_ms=elapsed,
            )

        def _int_or_zero(v: Any) -> int:
            try:
                return int(v) if v not in (None, "") else 0
            except (TypeError, ValueError):
                return 0

        count_reports = _int_or_zero(ip_obj.get("count"))
        attacks = _int_or_zero(ip_obj.get("attacks"))
        feeds_raw = ip_obj.get("threatfeeds")
        feeds: list[str] = []
        if isinstance(feeds_raw, dict):
            feeds = [str(k) for k in feeds_raw.keys()]
        elif isinstance(feeds_raw, list):
            feeds = [str(x) for x in feeds_raw if x]

        data = {
            "ip": ip_clean,
            "resolved_from": resolved_from or "",
            "count": count_reports,
            "attacks": attacks,
            "maxrisk": ip_obj.get("maxrisk"),
            "first_seen": str(ip_obj.get("mindate") or ""),
            "last_seen": str(ip_obj.get("maxdate") or ""),
            "updated": str(ip_obj.get("updated") or ""),
            "as": str(ip_obj.get("as") or "").strip(),
            "asname": str(ip_obj.get("asname") or "").strip(),
            "network": str(ip_obj.get("network") or "").strip(),
            "country": str(ip_obj.get("ascountry") or ip_obj.get("country") or "").strip(),
            "abusecontact": str(ip_obj.get("asabusecontact") or ip_obj.get("abusecontact") or "").strip(),
            "threatfeeds": feeds,
            "comment": str(ip_obj.get("comment") or "").strip(),
        }
        has_activity = bool(count_reports or attacks or feeds)
        if has_activity:
            msg = f"{count_reports} report(s) | {attacks} target(s) attacked"
            if feeds:
                msg += f" | feeds: {', '.join(feeds[:3])}"
        else:
            msg = "No DShield scanner attacks observed"
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok" if has_activity else "empty",
            status_code=code,
            message=msg,
            count=count_reports if has_activity else 0,
            elapsed_ms=elapsed,
            data=data,
        )

    # ------------------------------------------------------------------
    # 9. Wayback Machine Archive (Free, No Key)
    # ------------------------------------------------------------------

    def lookup_wayback(self, target: str, kind: str) -> OSINTSectionOutcome:
        """Query Wayback Machine CDX API for passive historical website snapshots."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_wayback"]
        if kind not in ("domain", "url"):
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message=f"Wayback skipped for {kind}."
            )
        query_url = target.strip()
        code, payload, err = self._request_json(
            "GET",
            self.endpoints["wayback"],
            params={
                "url": query_url,
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype,length",
                "limit": "-8",
                "fastLatest": "true",
            },
            timeout=max(self.timeout, 10.0),
        )
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if err or not isinstance(payload, list):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                status_code=code or None,
                message=err or "Wayback CDX query failed.",
                elapsed_ms=elapsed,
            )
        if len(payload) <= 1:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=code,
                message="No Wayback Machine archive snapshots found.",
                elapsed_ms=elapsed,
            )
        header = [str(h) for h in payload[0]] if isinstance(payload[0], list) else []
        snapshots: list[dict[str, Any]] = []
        for row in payload[1:]:
            if not isinstance(row, list):
                continue
            rec = {header[i]: str(row[i]) for i in range(min(len(header), len(row)))}
            raw_ts = rec.get("timestamp", "")
            orig = rec.get("original", query_url)
            snapshots.append(
                {
                    "timestamp": raw_ts,
                    "date": _format_wayback_ts(raw_ts),
                    "original": orig,
                    "statuscode": rec.get("statuscode", "-"),
                    "mimetype": rec.get("mimetype", "-"),
                    "length": rec.get("length", "-"),
                    "archive_url": f"https://web.archive.org/web/{raw_ts}/{orig}" if raw_ts else "",
                }
            )
        snapshots.reverse()  # newest first
        latest = snapshots[0]["date"] if snapshots else ""
        data = {
            "query": query_url,
            "snapshot_count": len(snapshots),
            "latest_capture": latest,
            "snapshots": snapshots,
        }
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=code,
            message=f"{len(snapshots)} recent snapshot(s) | Latest: {latest[:10]}",
            count=len(snapshots),
            elapsed_ms=elapsed,
            data=data,
        )

    # ------------------------------------------------------------------
    # 10. AlienVault / LevelBlue OTX (Free, Optional Key)
    # ------------------------------------------------------------------

    def lookup_otx(self, target: str, kind: str) -> OSINTSectionOutcome:
        """Query AlienVault / LevelBlue OTX for threat pulses & passive DNS."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_otx"]
        clean = target.strip()

        if kind == "ip":
            if not is_public_ip(clean):
                return OSINTSectionOutcome(
                    key=spec.key, title=spec.title, status="skipped", message="Private IP."
                )
            ip_obj = ipaddress.ip_address(clean)
            ind_type = "IPv6" if ip_obj.version == 6 else "IPv4"
            ind_val = clean
        elif kind == "domain":
            ind_type = "domain"
            ind_val = clean.lower()
        elif kind == "url":
            ind_type = "url"
            ind_val = clean
        elif kind == "hash":
            ind_type = "file"
            ind_val = clean.lower()
        elif kind == "vulnerability":
            ind_type = "cve"
            ind_val = clean.upper()
        else:
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message=f"OTX skipped for {kind}."
            )

        headers: dict[str, str] = {}
        if self.config.otx_api_key:
            headers["X-OTX-API-KEY"] = self.config.otx_api_key

        base = self.endpoints["otx"]
        gen_url = f"{base}/indicators/{ind_type}/{quote(ind_val, safe='')}/general"
        code, payload, err = self._request_json("GET", gen_url, headers=headers, allow_404=True)
        if code == 404 and err is None:
            elapsed = round((time.perf_counter() - started) * 1000.0, 2)
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=404,
                message="Not found in AlienVault OTX.",
                elapsed_ms=elapsed,
            )
        if code in (401, 403) and not self.config.otx_api_key:
            elapsed = round((time.perf_counter() - started) * 1000.0, 2)
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="not_configured",
                status_code=code,
                message="Add free OTX API key in Settings (otx.alienvault.com) to unlock.",
                elapsed_ms=elapsed,
            )
        if err or not isinstance(payload, dict):
            elapsed = round((time.perf_counter() - started) * 1000.0, 2)
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="rate_limited" if code == 429 else "error",
                status_code=code or None,
                message=err or "OTX lookup failed.",
                elapsed_ms=elapsed,
            )

        # Optional passive DNS for IP/domain
        passive_dns: list[dict[str, Any]] = []
        if kind in ("ip", "domain") and not self._is_cancelled():
            pdns_url = f"{base}/indicators/{ind_type}/{quote(ind_val, safe='')}/passive_dns"
            _pc, pdns_payload, _pe = self._request_json(
                "GET", pdns_url, headers=headers, timeout=min(self.timeout, 5.0), allow_404=True
            )
            if isinstance(pdns_payload, dict):
                for row in (pdns_payload.get("passive_dns") or [])[:20]:
                    if isinstance(row, dict):
                        passive_dns.append(
                            {
                                "hostname": str(row.get("hostname") or ""),
                                "address": str(row.get("address") or ""),
                                "record_type": str(row.get("record_type") or ""),
                                "first": str(row.get("first") or ""),
                                "last": str(row.get("last") or ""),
                            }
                        )

        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        pulse_info = _as_dict(payload.get("pulse_info"))
        pulse_count = int(pulse_info.get("count") or 0)
        raw_pulses = [p for p in (pulse_info.get("pulses") or []) if isinstance(p, dict)]

        pulses: list[dict[str, Any]] = []
        adversaries: set[str] = set()
        malware_families: set[str] = set()
        attack_ids: set[str] = set()
        all_tags: set[str] = set()

        for p in raw_pulses[:15]:
            adv = str(p.get("adversary") or "").strip()
            if adv:
                adversaries.add(adv)
            p_tags = [str(tg) for tg in (p.get("tags") or []) if tg]
            all_tags.update(p_tags[:10])
            for mf in p.get("malware_families") or []:
                if isinstance(mf, dict) and mf.get("display_name"):
                    malware_families.add(str(mf["display_name"]))
                elif isinstance(mf, str) and mf:
                    malware_families.add(mf)
            for aid in p.get("attack_ids") or []:
                if isinstance(aid, dict) and aid.get("id"):
                    attack_ids.add(str(aid["id"]))
                elif isinstance(aid, str) and aid:
                    attack_ids.add(aid)
            pulses.append(
                {
                    "id": str(p.get("id") or ""),
                    "name": str(p.get("name") or "OTX Pulse"),
                    "modified": str(p.get("modified") or p.get("created") or ""),
                    "adversary": adv,
                    "tags": p_tags[:8],
                    "tlp": str(p.get("TLP") or p.get("tlp") or ""),
                }
            )

        validations = [
            f"{v.get('name')}: {v.get('message')}"
            for v in (payload.get("validation") or [])
            if isinstance(v, dict) and v.get("name")
        ]

        pivots: list[dict[str, Any]] = []
        seen_piv: set[str] = set()
        for pd in passive_dns[:10]:
            hn = pd.get("hostname", "").strip().lower().rstrip(".")
            addr = pd.get("address", "").strip()
            if kind == "ip" and hn and "." in hn and f"idn:{hn}" not in seen_piv:
                seen_piv.add(f"idn:{hn}")
                pivots.append(
                    {
                        "entity_id": f"idn:{hn}",
                        "name": hn,
                        "entity_type": "InternetDomainName",
                        "source_section": spec.key,
                        "relationship": "OTX Passive DNS Hostname",
                        "pivot_kind": "domain",
                    }
                )
            elif kind == "domain" and addr and is_public_ip(addr) and f"ip:{addr}" not in seen_piv:
                seen_piv.add(f"ip:{addr}")
                pivots.append(
                    {
                        "entity_id": f"ip:{addr}",
                        "name": addr,
                        "entity_type": "IpAddress",
                        "source_section": spec.key,
                        "relationship": "OTX Passive DNS IP",
                        "pivot_kind": "ip",
                    }
                )
        for mitre in sorted(attack_ids)[:6]:
            pivots.append(
                {
                    "entity_id": f"mitre:{mitre.upper()}",
                    "name": mitre.upper(),
                    "entity_type": "MitreAttackIdentifier",
                    "source_section": spec.key,
                    "relationship": "OTX Pulse ATT&CK Technique",
                    "pivot_kind": "mitre",
                }
            )

        data = {
            "indicator": ind_val,
            "indicator_type": ind_type,
            "pulse_count": pulse_count,
            "reputation": payload.get("reputation"),
            "country_name": str(payload.get("country_name") or ""),
            "asn": str(payload.get("asn") or ""),
            "validations": validations,
            "adversaries": sorted(adversaries),
            "malware_families": sorted(malware_families),
            "attack_ids": sorted(attack_ids),
            "tags": sorted(all_tags)[:20],
            "pulses": pulses,
            "passive_dns": passive_dns,
            "gui_url": f"https://otx.alienvault.com/indicator/{ind_type.lower()}/{quote(ind_val, safe='')}",
        }
        has_data = bool(pulse_count or passive_dns or validations)
        msg_bits = [f"{pulse_count} pulse(s)"]
        if malware_families:
            msg_bits.append(f"malware: {', '.join(sorted(malware_families)[:3])}")
        if passive_dns:
            msg_bits.append(f"{len(passive_dns)} passive DNS")
        if validations:
            msg_bits.append("validated/whitelisted")
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok" if has_data else "empty",
            status_code=code,
            message=" | ".join(msg_bits) if has_data else "0 OTX pulses found.",
            count=max(pulse_count, len(passive_dns), 1 if validations else 0),
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots,
        )

    # ------------------------------------------------------------------
    # 11. GreyNoise Community (Free, Optional Key)
    # ------------------------------------------------------------------

    def lookup_greynoise(
        self,
        ip_value: str,
        *,
        resolved_from: str | None = None,
    ) -> OSINTSectionOutcome:
        """Query GreyNoise Community API for Noise (scanner) / RIOT (benign) status."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_greynoise"]
        if not is_public_ip(ip_value):
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message="Private IP."
            )
        ip_clean = ip_value.strip()
        headers: dict[str, str] = {"Accept": "application/json"}
        if self.config.greynoise_api_key:
            headers["key"] = self.config.greynoise_api_key

        code, payload, err = self._request_json(
            "GET",
            f"{self.endpoints['greynoise']}/{quote(ip_clean, safe='')}",
            headers=headers,
            allow_404=True,
        )
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if code == 404 and err is None:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=404,
                message="IP not observed in GreyNoise Noise or RIOT datasets.",
                elapsed_ms=elapsed,
            )
        if code in (401, 403, 429) and not self.config.greynoise_api_key:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="not_configured" if code in (401, 403) else "rate_limited",
                status_code=code,
                message="Add free GreyNoise Community key in Settings (viz.greynoise.io/signup).",
                elapsed_ms=elapsed,
            )
        if err or not isinstance(payload, dict):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="rate_limited" if code == 429 else "error",
                status_code=code or None,
                message=err or "GreyNoise lookup failed.",
                elapsed_ms=elapsed,
            )

        noise = bool(payload.get("noise"))
        riot = bool(payload.get("riot"))
        classification = str(payload.get("classification") or "unknown")
        name = str(payload.get("name") or "")
        data = {
            "ip": ip_clean,
            "resolved_from": resolved_from or "",
            "noise": noise,
            "riot": riot,
            "classification": classification,
            "name": name,
            "last_seen": str(payload.get("last_seen") or ""),
            "link": str(payload.get("link") or f"https://viz.greynoise.io/ip/{ip_clean}"),
            "message": str(payload.get("message") or ""),
        }
        flags: list[str] = []
        if riot:
            flags.append(f"RIOT Benign ({name or 'Known Service'})")
        if noise:
            flags.append("Internet Mass Scanner")
        if classification and classification != "unknown":
            flags.append(classification.upper())
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=code,
            message=" | ".join(flags) or "Observed in GreyNoise",
            count=1,
            elapsed_ms=elapsed,
            data=data,
        )

    # ------------------------------------------------------------------
    # 12. CIRCL Hashlookup / NSRL (Free, No Key)
    # ------------------------------------------------------------------

    def lookup_hashlookup(self, file_hash: str) -> OSINTSectionOutcome:
        """Check file hash against CIRCL Hashlookup (NSRL known-good software database)."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_hashlookup"]
        clean = file_hash.strip().lower()
        if not _HEX_HASH_RE.match(clean):
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message="Not an MD5/SHA1/SHA256 hash."
            )
        algo = {32: "md5", 40: "sha1", 64: "sha256"}[len(clean)]
        code, payload, err = self._request_json(
            "GET",
            f"{self.endpoints['hashlookup']}/{algo}/{clean}",
            allow_404=True,
        )
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if code == 404 or (err is None and isinstance(payload, dict) and not payload):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=code,
                message="Not present in CIRCL/NSRL known-good software catalog.",
                elapsed_ms=elapsed,
            )
        if err or not isinstance(payload, dict):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                status_code=code or None,
                message=err or "CIRCL Hashlookup query failed.",
                elapsed_ms=elapsed,
            )

        prod = _as_dict(payload.get("ProductCode"))
        os_info = _as_dict(payload.get("OpSystemCode"))
        trust = payload.get("hashlookup:trust")
        file_name = str(payload.get("FileName") or "")
        product_name = str(prod.get("ProductName") or payload.get("ProductName") or "")
        data = {
            "known_good": True,
            "file_name": file_name,
            "file_size": str(payload.get("FileSize") or ""),
            "product_name": product_name,
            "product_version": str(prod.get("ProductVersion") or ""),
            "os_name": str(os_info.get("OpSystemName") or ""),
            "trust": trust,
            "md5": str(payload.get("MD5") or ""),
            "sha1": str(payload.get("SHA-1") or ""),
            "sha256": str(payload.get("SHA-256") or ""),
            "crc32": str(payload.get("CRC32") or ""),
            "source": str(payload.get("source") or "NSRL"),
        }
        label = product_name or file_name or "Known-good software"
        trust_str = f" (trust {trust}/100)" if trust is not None else ""
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=code,
            message=f"NSRL Known-Good: {label}{trust_str}",
            count=1,
            elapsed_ms=elapsed,
            data=data,
        )

    # ------------------------------------------------------------------
    # 13. MITRE CVE 5.x + FIRST EPSS + CISA KEV (All Free, No Key)
    # ------------------------------------------------------------------

    def _load_cisa_kev_index(self) -> dict[str, dict[str, Any]]:
        """Load CISA KEV catalog keyed by CVE ID with 24-hour memory & disk cache."""
        now = time.time()
        with self._KEV_LOCK:
            if (
                self._KEV_MEMORY_CACHE is not None
                and (now - self._KEV_MEMORY_CACHE[0]) < 86400
            ):
                return self._KEV_MEMORY_CACHE[1]

        cache_path: Path | None = None
        try:
            ws = self.workspace_dir or get_workspace_dir()
            cache_path = ws / "cache" / "cisa_kev.json"
            if cache_path.is_file() and (now - cache_path.stat().st_mtime) < 86400:
                loaded = json.loads(cache_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("vulnerabilities"), list):
                    idx = {
                        str(v.get("cveID", "")).upper(): v
                        for v in loaded["vulnerabilities"]
                        if isinstance(v, dict) and v.get("cveID")
                    }
                    with self._KEV_LOCK:
                        self._KEV_MEMORY_CACHE = (now, idx)
                    return idx
        except Exception:
            pass

        _code, payload, err = self._request_json(
            "GET",
            self.endpoints["cisa_kev"],
            timeout=max(self.timeout, 10.0),
        )
        if err or not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            return {}
        idx = {
            str(v.get("cveID", "")).upper(): v
            for v in payload["vulnerabilities"]
            if isinstance(v, dict) and v.get("cveID")
        }
        with self._KEV_LOCK:
            self._KEV_MEMORY_CACHE = (now, idx)
        if cache_path is not None:
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(json.dumps(payload), encoding="utf-8")
            except OSError:
                pass
        return idx

    def lookup_vuln(self, cve_id: str) -> OSINTSectionOutcome:
        """Query MITRE CVE AWG 5.x, FIRST EPSS, and CISA KEV concurrently for a CVE."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_vuln"]
        cve = cve_id.strip().upper()
        if not _CVE_RE.match(cve):
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message="Not a CVE identifier."
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            f_cve = pool.submit(
                self._request_json,
                "GET",
                f"{self.endpoints['cveawg']}/{quote(cve, safe='')}",
                allow_404=True,
            )
            f_epss = pool.submit(
                self._request_json,
                "GET",
                self.endpoints["epss"],
                params={"cve": cve},
            )
            f_kev = pool.submit(self._load_cisa_kev_index)
            c_cve, p_cve, e_cve = f_cve.result()
            _c_ep, p_ep, _e_ep = f_epss.result()
            kev_idx = f_kev.result()

        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        kev_entry = kev_idx.get(cve) if isinstance(kev_idx, dict) else None

        epss_score: float | None = None
        epss_pct: float | None = None
        epss_date = ""
        if isinstance(p_ep, dict):
            ep_rows = p_ep.get("data") or []
            if isinstance(ep_rows, list) and ep_rows and isinstance(ep_rows[0], dict):
                try:
                    epss_score = float(ep_rows[0]["epss"])
                except (KeyError, TypeError, ValueError):
                    pass
                try:
                    epss_pct = float(ep_rows[0]["percentile"])
                except (KeyError, TypeError, ValueError):
                    pass
                epss_date = str(ep_rows[0].get("date") or "")

        cve_meta: dict[str, Any] = {}
        description = ""
        cvss_score: float | None = None
        cvss_severity = ""
        cvss_vector = ""
        cvss_version = ""
        cwes: list[str] = []
        affected: list[dict[str, str]] = []
        references: list[str] = []

        if isinstance(p_cve, dict):
            cve_meta = _as_dict(p_cve.get("cveMetadata"))
            containers = _as_dict(p_cve.get("containers"))
            cna = _as_dict(containers.get("cna"))
            adp_list = [a for a in (containers.get("adp") or []) if isinstance(a, dict)]

            for desc in cna.get("descriptions") or []:
                if isinstance(desc, dict) and desc.get("value"):
                    if str(desc.get("lang") or "").lower().startswith("en") or not description:
                        description = str(desc["value"]).strip()
                        if str(desc.get("lang") or "").lower().startswith("en"):
                            break

            metric_blocks = list(cna.get("metrics") or [])
            for adp in adp_list:
                metric_blocks.extend(adp.get("metrics") or [])
            for m in metric_blocks:
                if not isinstance(m, dict):
                    continue
                for mk in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                    obj = m.get(mk)
                    if isinstance(obj, dict) and obj.get("baseScore") is not None:
                        try:
                            cvss_score = float(obj["baseScore"])
                        except (TypeError, ValueError):
                            pass
                        cvss_severity = str(obj.get("baseSeverity") or "")
                        cvss_vector = str(obj.get("vectorString") or "")
                        cvss_version = str(obj.get("version") or mk)
                        break
                if cvss_score is not None:
                    break

            for pt in cna.get("problemTypes") or []:
                if not isinstance(pt, dict):
                    continue
                for pd in pt.get("descriptions") or []:
                    if isinstance(pd, dict):
                        cwe_val = str(pd.get("cweId") or pd.get("description") or "").strip()
                        if cwe_val and cwe_val not in cwes:
                            cwes.append(cwe_val)

            for aff in (cna.get("affected") or [])[:12]:
                if not isinstance(aff, dict):
                    continue
                versions = [
                    str(v.get("version") or v.get("lessThan") or "")
                    for v in (aff.get("versions") or [])[:4]
                    if isinstance(v, dict)
                ]
                affected.append(
                    {
                        "vendor": str(aff.get("vendor") or "-"),
                        "product": str(aff.get("product") or "-"),
                        "versions": ", ".join(v for v in versions if v) or str(aff.get("defaultStatus") or "-"),
                    }
                )

            for ref in (cna.get("references") or [])[:12]:
                if isinstance(ref, dict) and ref.get("url"):
                    references.append(str(ref["url"]))

        has_any = bool(cve_meta or epss_score is not None or kev_entry)
        if not has_any and e_cve:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="error",
                status_code=c_cve or None,
                message=e_cve,
                elapsed_ms=elapsed,
            )
        if not has_any:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=c_cve or 404,
                message=f"No CVE/EPSS/KEV records found for {cve}.",
                elapsed_ms=elapsed,
            )

        data = {
            "cve_id": cve,
            "state": str(cve_meta.get("state") or ""),
            "assigner": str(cve_meta.get("assignerShortName") or ""),
            "date_published": str(cve_meta.get("datePublished") or ""),
            "date_updated": str(cve_meta.get("dateUpdated") or ""),
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "cvss_version": cvss_version,
            "cwes": cwes[:8],
            "description": description,
            "affected": affected,
            "references": references,
            "epss_score": epss_score,
            "epss_percentile": epss_pct,
            "epss_date": epss_date,
            "in_kev": kev_entry is not None,
            "kev": kev_entry or {},
        }
        bits: list[str] = []
        if kev_entry is not None:
            ransom = str(kev_entry.get("knownRansomwareCampaignUse") or "")
            bits.append(f"CISA KEV ACTIVE EXPLOIT{f' (Ransomware: {ransom})' if ransom == 'Known' else ''}")
        if cvss_score is not None:
            bits.append(f"CVSS {cvss_score} ({cvss_severity or 'N/A'})")
        if epss_score is not None:
            bits.append(f"EPSS {epss_score * 100:.1f}%")
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=200,
            message=" | ".join(bits) or f"CVE record retrieved for {cve}.",
            count=1,
            elapsed_ms=elapsed,
            data=data,
        )

    # ------------------------------------------------------------------
    # 14. VirusTotal v3 (Free API Key)
    # ------------------------------------------------------------------

    def lookup_virustotal(self, target: str, kind: str) -> OSINTSectionOutcome:
        """Query VirusTotal API v3 for IP, domain, URL, or file hash detections."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_virustotal"]
        api_key = self.config.vt_api_key
        if not api_key:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="not_configured",
                message="Add free VirusTotal API key in Settings (virustotal.com/gui/join-us).",
            )

        clean = target.strip()
        if kind == "ip":
            if not is_public_ip(clean):
                return OSINTSectionOutcome(
                    key=spec.key, title=spec.title, status="skipped", message="Private IP."
                )
            path = f"ip_addresses/{quote(clean, safe='')}"
            gui_url = f"https://www.virustotal.com/gui/ip-address/{quote(clean, safe='')}"
        elif kind == "domain":
            dom = clean.lower()
            path = f"domains/{quote(dom, safe='')}"
            gui_url = f"https://www.virustotal.com/gui/domain/{quote(dom, safe='')}"
        elif kind == "hash":
            h = clean.lower()
            path = f"files/{quote(h, safe='')}"
            gui_url = f"https://www.virustotal.com/gui/file/{quote(h, safe='')}"
        elif kind == "url":
            url_id = base64.urlsafe_b64encode(clean.encode("utf-8")).decode("ascii").rstrip("=")
            path = f"urls/{url_id}"
            gui_url = f"https://www.virustotal.com/gui/url/{url_id}"
        else:
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message=f"VirusTotal skipped for {kind}."
            )

        code, payload, err = self._request_json(
            "GET",
            f"{self.endpoints['virustotal']}/{path}",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            allow_404=True,
        )
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if code == 404 and err is None:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=404,
                message="No VirusTotal record found for this indicator.",
                elapsed_ms=elapsed,
            )
        if err or not isinstance(payload, dict):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="rate_limited" if code == 429 else "error",
                status_code=code or None,
                message=err or "VirusTotal lookup failed.",
                elapsed_ms=elapsed,
            )

        data_obj = _as_dict(payload.get("data"))
        attrs = _as_dict(data_obj.get("attributes"))
        stats = _as_dict(attrs.get("last_analysis_stats"))
        mal = int(stats.get("malicious") or 0)
        susp = int(stats.get("suspicious") or 0)
        harm = int(stats.get("harmless") or 0)
        undet = int(stats.get("undetected") or 0)
        timeout_c = int(stats.get("timeout") or 0)
        total_engines = mal + susp + harm + undet + timeout_c

        results_map = _as_dict(attrs.get("last_analysis_results"))
        flagging: list[dict[str, str]] = []
        for eng_name, res_obj in results_map.items():
            if not isinstance(res_obj, dict):
                continue
            cat = str(res_obj.get("category") or "")
            if cat in ("malicious", "suspicious"):
                flagging.append(
                    {
                        "engine": str(eng_name),
                        "category": cat,
                        "result": str(res_obj.get("result") or cat),
                    }
                )
        flagging.sort(key=lambda x: (x["category"] != "malicious", x["engine"].lower()))

        categories_raw = _as_dict(attrs.get("categories"))
        categories = sorted({str(v) for v in categories_raw.values() if v})[:8]

        cert = _as_dict(attrs.get("last_https_certificate"))
        cert_exts = _as_dict(cert.get("extensions"))
        cert_sans = [str(s).lower().lstrip("*.") for s in (cert_exts.get("subject_alternative_name") or []) if s]

        pivots: list[dict[str, Any]] = []
        for san in cert_sans[:8]:
            if "." in san and san != clean.lower():
                pivots.append(
                    {
                        "entity_id": f"idn:{san}",
                        "name": san,
                        "entity_type": "InternetDomainName",
                        "source_section": spec.key,
                        "relationship": "VirusTotal HTTPS Cert SAN",
                        "pivot_kind": "domain",
                    }
                )

        pop_threat = attrs.get("popular_threat_classification")
        threat_label = (
            str(pop_threat.get("suggested_threat_label") or "")
            if isinstance(pop_threat, dict)
            else ""
        )
        creation_ts = attrs.get("creation_date")
        creation_iso = (
            datetime.fromtimestamp(int(creation_ts), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            if isinstance(creation_ts, (int, float))
            else ""
        )

        data = {
            "indicator": clean,
            "kind": kind,
            "malicious": mal,
            "suspicious": susp,
            "harmless": harm,
            "undetected": undet,
            "total_engines": total_engines,
            "reputation": attrs.get("reputation"),
            "categories": categories,
            "tags": [str(t) for t in (attrs.get("tags") or [])[:12]],
            "registrar": str(attrs.get("registrar") or ""),
            "creation_date": creation_iso,
            "as_owner": str(attrs.get("as_owner") or ""),
            "asn": f"AS{attrs['asn']}" if attrs.get("asn") else "",
            "country": str(attrs.get("country") or ""),
            "network": str(attrs.get("network") or ""),
            "meaningful_name": str(attrs.get("meaningful_name") or ""),
            "type_description": str(attrs.get("type_description") or ""),
            "size": attrs.get("size"),
            "threat_label": threat_label,
            "flagging_vendors": flagging[:25],
            "cert_sans": cert_sans[:15],
            "gui_url": gui_url,
        }
        msg = f"{mal}/{total_engines} malicious"
        if susp:
            msg += f", {susp} suspicious"
        if threat_label:
            msg += f" ({threat_label})"
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=code,
            message=msg,
            count=max(1, mal + susp),
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots,
        )

    # ------------------------------------------------------------------
    # 15. AbuseIPDB v2 (Free API Key)
    # ------------------------------------------------------------------

    def lookup_abuseipdb(
        self,
        ip_value: str,
        *,
        resolved_from: str | None = None,
    ) -> OSINTSectionOutcome:
        """Query AbuseIPDB v2 for IP abuse confidence score and crowdsourced reports."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_abuseipdb"]
        if not is_public_ip(ip_value):
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message="Private IP."
            )
        api_key = self.config.abuseipdb_api_key
        if not api_key:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="not_configured",
                message="Add free AbuseIPDB API key in Settings (abuseipdb.com/register).",
            )
        ip_clean = ip_value.strip()
        code, payload, err = self._request_json(
            "GET",
            f"{self.endpoints['abuseipdb']}/check",
            params={"ipAddress": ip_clean, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        if err or not isinstance(payload, dict):
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="rate_limited" if code == 429 else "error",
                status_code=code or None,
                message=err or "AbuseIPDB lookup failed.",
                elapsed_ms=elapsed,
            )
        d = _as_dict(payload.get("data"))
        score = int(d.get("abuseConfidenceScore") or 0)
        total_reports = int(d.get("totalReports") or 0)
        hostnames = [str(h).lower().rstrip(".") for h in (d.get("hostnames") or []) if h]
        domain = str(d.get("domain") or "").lower().rstrip(".")

        pivots: list[dict[str, Any]] = []
        for hn in hostnames[:6]:
            if "." in hn:
                pivots.append(
                    {
                        "entity_id": f"idn:{hn}",
                        "name": hn,
                        "entity_type": "InternetDomainName",
                        "source_section": spec.key,
                        "relationship": "AbuseIPDB Hostname",
                        "pivot_kind": "domain",
                    }
                )

        data = {
            "ip": ip_clean,
            "resolved_from": resolved_from or "",
            "abuse_confidence_score": score,
            "total_reports": total_reports,
            "distinct_users": int(d.get("numDistinctUsers") or 0),
            "is_whitelisted": bool(d.get("isWhitelisted")),
            "is_tor": bool(d.get("isTor")),
            "country_code": str(d.get("countryCode") or ""),
            "usage_type": str(d.get("usageType") or ""),
            "isp": str(d.get("isp") or ""),
            "domain": domain,
            "hostnames": hostnames,
            "last_reported_at": str(d.get("lastReportedAt") or ""),
        }
        flags = [f"Abuse Score: {score}%", f"{total_reports} report(s)"]
        if data["is_tor"]:
            flags.append("TOR EXIT")
        if data["is_whitelisted"]:
            flags.append("Whitelisted")
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=code,
            message=" | ".join(flags),
            count=max(1, total_reports),
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots,
        )

    # ------------------------------------------------------------------
    # 16. abuse.ch Suite (ThreatFox + URLhaus + MalwareBazaar — 1 Free Key)
    # ------------------------------------------------------------------

    def lookup_abusech(self, target: str, kind: str) -> OSINTSectionOutcome:
        """Query abuse.ch ThreatFox, URLhaus, and MalwareBazaar using one free Auth-Key."""
        started = time.perf_counter()
        spec = OSINT_SOURCES_BY_KEY["osint_abusech"]
        if kind not in ("ip", "domain", "url", "hash"):
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message=f"abuse.ch skipped for {kind}."
            )
        if kind == "ip" and not is_public_ip(target):
            return OSINTSectionOutcome(
                key=spec.key, title=spec.title, status="skipped", message="Private IP."
            )
        api_key = self.config.abusech_api_key
        if not api_key:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="not_configured",
                message="Add free abuse.ch Auth-Key in Settings (auth.abuse.ch) for ThreatFox/URLhaus/MalwareBazaar.",
            )

        clean = target.strip()
        auth_headers = {"Auth-Key": api_key}

        def _query_threatfox() -> list[dict[str, Any]]:
            body = (
                {"query": "search_hash", "hash": clean.lower()}
                if kind == "hash"
                else {"query": "search_ioc", "search_term": clean}
            )
            _c, p, _e = self._request_json(
                "POST", f"{self.endpoints['threatfox']}/", headers=auth_headers, json_body=body
            )
            if isinstance(p, dict) and p.get("query_status") == "ok" and isinstance(p.get("data"), list):
                return [x for x in p["data"] if isinstance(x, dict)][:15]
            return []

        def _query_urlhaus() -> dict[str, Any]:
            uh_base = self.endpoints["urlhaus"]
            if kind == "url":
                _c, p, _e = self._request_json(
                    "POST", f"{uh_base}/url/", headers=auth_headers, data={"url": clean}
                )
            elif kind in ("domain", "ip"):
                _c, p, _e = self._request_json(
                    "POST", f"{uh_base}/host/", headers=auth_headers, data={"host": clean.lower()}
                )
            elif kind == "hash":
                field_name = "sha256_hash" if len(clean) == 64 else ("md5_hash" if len(clean) == 32 else None)
                if not field_name:
                    return {}
                _c, p, _e = self._request_json(
                    "POST", f"{uh_base}/payload/", headers=auth_headers, data={field_name: clean.lower()}
                )
            else:
                return {}
            if isinstance(p, dict) and p.get("query_status") == "ok":
                return p
            return {}

        def _query_malwarebazaar() -> list[dict[str, Any]]:
            if kind != "hash":
                return []
            _c, p, _e = self._request_json(
                "POST",
                f"{self.endpoints['malwarebazaar']}/",
                headers=auth_headers,
                data={"query": "get_info", "hash": clean.lower()},
            )
            if isinstance(p, dict) and p.get("query_status") == "ok" and isinstance(p.get("data"), list):
                return [x for x in p["data"] if isinstance(x, dict)][:5]
            return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            f_tf = pool.submit(_query_threatfox)
            f_uh = pool.submit(_query_urlhaus)
            f_mb = pool.submit(_query_malwarebazaar)
            tf_hits = f_tf.result()
            uh_data = f_uh.result()
            mb_hits = f_mb.result()

        elapsed = round((time.perf_counter() - started) * 1000.0, 2)
        uh_urls = [u for u in (uh_data.get("urls") or []) if isinstance(u, dict)] if uh_data else []
        total_hits = len(tf_hits) + len(mb_hits) + (len(uh_urls) if uh_urls else (1 if uh_data else 0))

        pivots: list[dict[str, Any]] = []
        seen_piv: set[str] = set()
        for hit in tf_hits[:6]:
            mal_name = str(hit.get("malware_printable") or hit.get("malware") or "").strip()
            if mal_name and f"mal:{mal_name.lower()}" not in seen_piv:
                seen_piv.add(f"mal:{mal_name.lower()}")
                pivots.append(
                    {
                        "entity_id": f"malware:{mal_name}",
                        "name": mal_name,
                        "entity_type": "Malware",
                        "source_section": spec.key,
                        "relationship": f"ThreatFox ({hit.get('threat_type') or 'IOC'})",
                        "pivot_kind": "malware",
                    }
                )
        for u in uh_urls[:6]:
            u_val = str(u.get("url") or "").strip()
            if u_val and f"url:{u_val}" not in seen_piv:
                seen_piv.add(f"url:{u_val}")
                pivots.append(
                    {
                        "entity_id": f"url:{u_val}",
                        "name": u_val,
                        "entity_type": "URL",
                        "source_section": spec.key,
                        "relationship": f"URLhaus ({u.get('url_status') or 'listed'})",
                        "pivot_kind": "url",
                    }
                )

        if total_hits == 0:
            return OSINTSectionOutcome(
                key=spec.key,
                title=spec.title,
                status="empty",
                status_code=200,
                message="No matches across ThreatFox, URLhaus, or MalwareBazaar.",
                elapsed_ms=elapsed,
            )

        data = {
            "indicator": clean,
            "kind": kind,
            "threatfox": tf_hits,
            "urlhaus": uh_data,
            "malwarebazaar": mb_hits,
        }
        parts: list[str] = []
        if tf_hits:
            fams = sorted({str(h.get("malware_printable") or h.get("malware") or "IOC") for h in tf_hits})
            parts.append(f"ThreatFox: {len(tf_hits)} ({', '.join(fams[:2])})")
        if uh_data:
            uh_cnt = len(uh_urls) or 1
            parts.append(f"URLhaus: {uh_cnt} hit(s)")
        if mb_hits:
            sig = str(mb_hits[0].get("signature") or "Matched")
            parts.append(f"MalwareBazaar: {sig}")
        return OSINTSectionOutcome(
            key=spec.key,
            title=spec.title,
            status="ok",
            status_code=200,
            message=" | ".join(parts),
            count=total_hits,
            elapsed_ms=elapsed,
            data=data,
            pivots=pivots,
        )

    # ------------------------------------------------------------------
    # Orchestrator: Run All Applicable Free OSINT Sources Concurrently
    # ------------------------------------------------------------------

    def enrich_target(
        self,
        target: str,
        kind: str,
        *,
        extracted_domain: str | None = None,
        sources: Iterable[str] | None = None,
    ) -> dict[str, OSINTSectionOutcome]:
        """Run all applicable passive OSINT sources concurrently, chaining domain->IP intel."""
        clean = target.strip()
        if not clean:
            return {}

        if sources is not None:
            selected: set[str] = set()
            for raw_src in sources:
                resolved = resolve_osint_source_key(raw_src)
                if resolved:
                    selected.add(resolved)
        else:
            selected = set(OSINT_MODULES)

        dom_for_lookup = (extracted_domain or (clean if kind == "domain" else "")).strip().lower()
        outcomes: dict[str, OSINTSectionOutcome] = {}

        # Stage 1: Direct queries for this target kind (run DNS early so domains can chain IP intel)
        stage1_tasks: dict[str, Callable[[], OSINTSectionOutcome]] = {}
        ip_chain_sources: list[str] = []

        for spec in OSINT_SOURCE_CATALOG:
            if spec.key not in selected:
                continue
            if kind not in spec.supported_kinds:
                continue
            if spec.chains_resolved_ip and kind in ("domain", "url"):
                ip_chain_sources.append(spec.key)
                continue

            if spec.key == "osint_dns":
                stage1_tasks[spec.key] = lambda: self.lookup_dns(clean, kind)
            elif spec.key == "osint_rdap":
                stage1_tasks[spec.key] = lambda: self.lookup_rdap(clean, kind)
            elif spec.key == "osint_geoip" and kind == "ip":
                stage1_tasks[spec.key] = lambda: self.lookup_geoip(clean)
            elif spec.key == "osint_bgp" and kind in ("ip", "asn"):
                stage1_tasks[spec.key] = lambda: self.lookup_bgp(clean, kind)
            elif spec.key == "osint_shodan" and kind == "ip":
                stage1_tasks[spec.key] = lambda: self.lookup_shodan(clean)
            elif spec.key == "osint_crtsh" and dom_for_lookup:
                stage1_tasks[spec.key] = lambda d=dom_for_lookup: self.lookup_crtsh(d)  # type: ignore[misc]
            elif spec.key == "osint_urlscan":
                stage1_tasks[spec.key] = lambda: self.lookup_urlscan(clean, kind)
            elif spec.key == "osint_dshield" and kind == "ip":
                stage1_tasks[spec.key] = lambda: self.lookup_dshield(clean)
            elif spec.key == "osint_wayback" and kind in ("domain", "url"):
                stage1_tasks[spec.key] = lambda: self.lookup_wayback(clean, kind)
            elif spec.key == "osint_otx":
                stage1_tasks[spec.key] = lambda: self.lookup_otx(clean, kind)
            elif spec.key == "osint_greynoise" and kind == "ip":
                stage1_tasks[spec.key] = lambda: self.lookup_greynoise(clean)
            elif spec.key == "osint_hashlookup" and kind == "hash":
                stage1_tasks[spec.key] = lambda: self.lookup_hashlookup(clean)
            elif spec.key == "osint_vuln" and kind == "vulnerability":
                stage1_tasks[spec.key] = lambda: self.lookup_vuln(clean)
            elif spec.key == "osint_virustotal":
                stage1_tasks[spec.key] = lambda: self.lookup_virustotal(clean, kind)
            elif spec.key == "osint_abuseipdb" and kind == "ip":
                stage1_tasks[spec.key] = lambda: self.lookup_abuseipdb(clean)
            elif spec.key == "osint_abusech":
                stage1_tasks[spec.key] = lambda: self.lookup_abusech(clean, kind)

        def _safe_call(key: str, fn: Callable[[], OSINTSectionOutcome]) -> OSINTSectionOutcome:
            try:
                return fn()
            except Exception as exc:
                spec = OSINT_SOURCES_BY_KEY[key]
                return OSINTSectionOutcome(
                    key=key, title=spec.title, status="error", message=str(exc)
                )

        # If we need IP chaining for a domain/URL, kick off DNS first inside the same executor
        # and immediately launch IP-chained sources once DNS resolves a primary public IP!
        resolved_primary_ip: str | None = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futs: dict[concurrent.futures.Future[OSINTSectionOutcome], str] = {}
            dns_fut: concurrent.futures.Future[OSINTSectionOutcome] | None = None
            for k, fn in stage1_tasks.items():
                fut = pool.submit(_safe_call, k, fn)
                futs[fut] = k
                if k == "osint_dns":
                    dns_fut = fut

            # Wait for DNS first (fast DoH) if domain/url needs IP-chained enrichment
            if dns_fut is not None and ip_chain_sources and not self._is_cancelled():
                dns_res = dns_fut.result()
                outcomes["osint_dns"] = dns_res
                futs.pop(dns_fut, None)
                if isinstance(dns_res.data, dict):
                    candidates = list(dns_res.data.get("a") or []) + list(dns_res.data.get("aaaa") or [])
                    resolved_primary_ip = next((ip for ip in candidates if is_public_ip(ip)), None)
                if resolved_primary_ip:
                    ip_val = resolved_primary_ip
                    src_dom = dom_for_lookup or clean
                    chain_map: dict[str, Callable[[], OSINTSectionOutcome]] = {
                        "osint_geoip": functools.partial(self.lookup_geoip, ip_val, resolved_from=src_dom),
                        "osint_bgp": functools.partial(self.lookup_bgp, ip_val, "ip", resolved_from=src_dom),
                        "osint_shodan": functools.partial(self.lookup_shodan, ip_val, resolved_from=src_dom),
                        "osint_dshield": functools.partial(self.lookup_dshield, ip_val, resolved_from=src_dom),
                        "osint_greynoise": functools.partial(self.lookup_greynoise, ip_val, resolved_from=src_dom),
                        "osint_abuseipdb": functools.partial(self.lookup_abuseipdb, ip_val, resolved_from=src_dom),
                    }
                    for ck in ip_chain_sources:
                        fn_c = chain_map.get(ck)
                        if fn_c is not None:
                            futs[pool.submit(_safe_call, ck, fn_c)] = ck
                else:
                    for ck in ip_chain_sources:
                        sp = OSINT_SOURCES_BY_KEY[ck]
                        outcomes[ck] = OSINTSectionOutcome(
                            key=ck,
                            title=sp.title,
                            status="skipped",
                            message="Domain did not resolve to a public IP.",
                        )

            for fut in concurrent.futures.as_completed(list(futs.keys())):
                k = futs[fut]
                if self._is_cancelled():
                    break
                outcomes[k] = fut.result()

        # Preserve canonical catalog ordering
        ordered: dict[str, OSINTSectionOutcome] = {}
        for spec in OSINT_SOURCE_CATALOG:
            if spec.key in outcomes:
                ordered[spec.key] = outcomes[spec.key]
        return ordered

    def test_connectivity(self) -> dict[str, Any]:
        """Quick read-only connectivity check for keyless OSINT (DoH + Shodan) & key summary."""
        dns_res = self.lookup_dns("1.1.1.1", "ip")
        shodan_res = self.lookup_shodan("1.1.1.1")
        avail = self.source_availability()
        ready_cnt = sum(1 for row in avail if row["configured"])
        key_cnt = sum(1 for row in avail if row["has_key"])
        return {
            "ok": dns_res.status in ("ok", "empty") or shodan_res.status in ("ok", "empty"),
            "doh_status": dns_res.status,
            "shodan_status": shodan_res.status,
            "ready_sources": ready_cnt,
            "total_sources": len(avail),
            "configured_keys": key_cnt,
        }
