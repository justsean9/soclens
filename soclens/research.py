"""Cross-API Threat Research, Target Resolution, Pivot Extraction & Reporting Engine."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import logging
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from soclens.client import (
    ENTITY_ID_PREFIXES,
    V2_EXTENSION_CATALOG,
    RecordedFutureAuthError,
    RecordedFutureClient,
    RecordedFutureError,
)
from soclens.config import ConfigurationError

logger = logging.getLogger("soclens.research")

RESEARCH_MODULES: tuple[str, ...] = (
    "v2_intel",
    "soar",
    "links",
    "analyst_notes",
    "threat_actors",
    "threat_map",
    "detection_rules",
    "malware_intel",
    "risk_history",
    "identity",
    "alerts",
    "playbook_alerts",
    "collective_insights",
    "sandbox",
    "extensions",
    "asi",
    "riskrecon",
)

_DEFAULT_MODULES: tuple[str, ...] = tuple(
    m for m in RESEARCH_MODULES if m != "extensions"
)

_SECTION_TITLES: dict[str, str] = {
    "v2_intel": "Connect v2 Intelligence Card",
    "soar": "SOAR v3 Enrichment",
    "links": "Links Relationship Graph",
    "analyst_notes": "Insikt & Enterprise Analyst Notes",
    "threat_actors": "Threat Actor Profiles",
    "threat_map": "Organizational Threat Map",
    "detection_rules": "Detection Rules (Sigma/YARA/Snort)",
    "malware_intel": "Malware Intelligence Corpus",
    "risk_history": "Risk History Timeline",
    "identity": "Identity & Credential Intelligence",
    "alerts": "Classic Alerts v3",
    "playbook_alerts": "Playbook Alerts",
    "collective_insights": "Collective Insights Telemetry",
    "sandbox": "Recorded Future Sandbox v0",
    "extensions": "Connect v2 3rd-Party Extensions",
    "asi": "Attack Surface Intelligence (ASI)",
    "riskrecon": "RiskRecon Posture & Findings",
}

_V2_RICH_FIELDS: dict[str, list[str]] = {
    "ip": [
        "entity",
        "risk",
        "riskMapping",
        "timestamps",
        "intelCard",
        "aiInsights",
        "analystNotes",
        "relatedEntities",
        "sightings",
        "counts",
        "metrics",
        "threatLists",
        "location",
        "dnsPortCert",
    ],
    "domain": [
        "entity",
        "risk",
        "riskMapping",
        "timestamps",
        "intelCard",
        "aiInsights",
        "analystNotes",
        "relatedEntities",
        "sightings",
        "counts",
        "metrics",
        "threatLists",
    ],
    "hash": [
        "entity",
        "risk",
        "riskMapping",
        "timestamps",
        "intelCard",
        "aiInsights",
        "analystNotes",
        "relatedEntities",
        "sightings",
        "counts",
        "metrics",
        "threatLists",
        "hashAlgorithm",
        "fileHashes",
    ],
    "url": [
        "entity",
        "risk",
        "riskMapping",
        "timestamps",
        "intelCard",
        "aiInsights",
        "analystNotes",
        "relatedEntities",
        "sightings",
        "counts",
        "metrics",
    ],
    "vulnerability": [
        "entity",
        "risk",
        "riskMapping",
        "timestamps",
        "intelCard",
        "aiInsights",
        "analystNotes",
        "relatedEntities",
        "sightings",
        "counts",
        "metrics",
        "threatLists",
        "commonNames",
        "cvss",
        "cvssv3",
        "cvssRatings",
        "nvdDescription",
        "nvdReferences",
        "lifecycleStage",
        "linkedMalware",
        "cpe",
    ],
    "malware": [
        "entity",
        "timestamps",
        "intelCard",
        "aiInsights",
        "analystNotes",
        "relatedEntities",
        "sightings",
        "counts",
        "metrics",
        "categories",
    ],
    "company": [
        "entity",
        "risk",
        "riskMapping",
        "timestamps",
        "intelCard",
        "aiInsights",
        "analystNotes",
        "relatedEntities",
        "sightings",
        "counts",
        "metrics",
        "threatLists",
        "curated",
    ],
}

_V2_FALLBACK_FIELDS: dict[str, list[str]] = {
    "ip": ["entity", "risk", "timestamps", "intelCard", "threatLists", "counts", "location", "relatedEntities"],
    "domain": ["entity", "risk", "timestamps", "intelCard", "threatLists", "counts", "relatedEntities"],
    "hash": ["entity", "risk", "timestamps", "intelCard", "threatLists", "counts", "hashAlgorithm", "relatedEntities"],
    "url": ["entity", "risk", "timestamps", "intelCard", "counts", "relatedEntities"],
    "vulnerability": ["entity", "risk", "timestamps", "intelCard", "cvss", "nvdDescription", "lifecycleStage", "counts", "relatedEntities"],
    "malware": ["entity", "timestamps", "intelCard", "counts", "relatedEntities", "categories"],
    "company": ["entity", "risk", "timestamps", "intelCard", "counts", "relatedEntities"],
}

_DEFAULT_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "ip": ("GreyNoiseIntelligence", "Censys", "active_ip_geo"),
    "domain": ("active_security_trails", "cisco_umbrella", "domaintools_iris"),
    "hash": ("active_polyswarm", "SentinelOne", "CarbonBlack"),
    "url": ("active_bitdefender", "mandiant", "inquest"),
    "vulnerability": ("epss", "shodan", "reversinglabs"),
    "malware": ("mandiant", "reversinglabs", "hunter_malware"),
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)$")
_MITRE_RE = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|TA\d{4})$", re.IGNORECASE)
_ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

_RF_TYPE_TO_PIVOT_KIND: dict[str, str] = {
    "ipaddress": "ip",
    "internetdomainname": "domain",
    "hash": "hash",
    "url": "url",
    "cybervulnerability": "vulnerability",
    "malware": "malware",
    "company": "company",
    "organization": "actor",
    "threatactor": "actor",
    "emailaddress": "email",
    "mitreattackidentifier": "mitre",
    "asnumber": "asn",
}

_RF_TYPE_TO_V2_TYPE: dict[str, str] = {
    "ipaddress": "ip",
    "internetdomainname": "domain",
    "hash": "hash",
    "url": "url",
    "cybervulnerability": "vulnerability",
    "malware": "malware",
    "company": "company",
}


@dataclass
class ResolvedTarget:
    """Normalized research target across Recorded Future entity representations."""

    raw_query: str
    detected_kind: str
    entity_id: str | None
    canonical_name: str
    rf_type: str | None = None
    v2_type: str | None = None
    v2_lookup_id: str | None = None
    aliases: list[str] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    extracted_domain: str | None = None


@dataclass
class ResearchPivot:
    """Linked entity discovered during research that can be investigated next."""

    entity_id: str
    name: str
    entity_type: str
    source_section: str
    risk_score: int | None = None
    relationship: str = ""
    pivot_kind: str = "auto"


@dataclass
class ResearchSectionResult:
    """Result envelope for a single Recorded Future API section in a dossier."""

    key: str
    title: str
    status: str  # ok | empty | not_entitled | not_configured | error | skipped
    status_code: int | None = None
    permission_type: str | None = None
    message: str = ""
    count: int = 0
    elapsed_ms: float = 0.0
    data: Any = None
    pivots: list[ResearchPivot] = field(default_factory=list)


@dataclass
class ResearchDossier:
    """Complete multi-API Recorded Future research dossier for a target."""

    target: ResolvedTarget
    generated_at: str
    risk_score: int | None = None
    risk_string: str = ""
    criticality_label: str = ""
    ai_summary: str = ""
    sections: dict[str, ResearchSectionResult] = field(default_factory=dict)
    pivots: list[ResearchPivot] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete dossier into JSON-friendly dictionaries."""
        return asdict(self)


def _strip_prefix(value: str) -> str:
    lower = value.lower()
    for prefix in sorted(ENTITY_ID_PREFIXES.values(), key=len, reverse=True):
        if lower.startswith(prefix):
            return value[len(prefix) :].strip()
    for prefix in ("vuln:", "company:", "malware:", "threatactor:"):
        if lower.startswith(prefix):
            return value[len(prefix) :].strip()
    return value.strip()


def _infer_pivot_kind(entity_type: str, entity_id: str) -> str:
    clean_type = entity_type.replace("type:", "").strip().lower()
    if clean_type in _RF_TYPE_TO_PIVOT_KIND:
        return _RF_TYPE_TO_PIVOT_KIND[clean_type]
    low_id = entity_id.strip().lower()
    if low_id.startswith("ip:"):
        return "ip"
    if low_id.startswith("idn:"):
        return "domain"
    if low_id.startswith("hash:"):
        return "hash"
    if low_id.startswith("url:"):
        return "url"
    if low_id.startswith("mitre:"):
        return "mitre"
    if low_id.startswith("asn:"):
        return "asn"
    if low_id.startswith("email:"):
        return "email"
    return "auto"


def classify_research_target(
    raw_query: str, explicit_type: str | None = None
) -> ResolvedTarget:
    """Classify a user query or RF entity ID into a normalized ``ResolvedTarget``."""
    clean = raw_query.strip() if isinstance(raw_query, str) else ""
    if not clean:
        raise ValueError("Research target cannot be empty.")

    forced = (explicit_type or "auto").strip().lower()
    if forced == "cve":
        forced = "vulnerability"

    lower = clean.lower()
    if forced in ("auto", ""):
        if lower.startswith("ip:"):
            val = clean[3:].strip()
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="ip",
                entity_id=f"ip:{val}",
                canonical_name=val,
                rf_type="IpAddress",
                v2_type="ip",
                v2_lookup_id=val,
            )
        if lower.startswith("idn:"):
            val = clean[4:].strip().lower()
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="domain",
                entity_id=f"idn:{val}",
                canonical_name=val,
                rf_type="InternetDomainName",
                v2_type="domain",
                v2_lookup_id=val,
                extracted_domain=val,
            )
        if lower.startswith("hash:"):
            val = clean[5:].strip().lower()
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="hash",
                entity_id=f"hash:{val}",
                canonical_name=val,
                rf_type="Hash",
                v2_type="hash",
                v2_lookup_id=val,
            )
        if lower.startswith("url:"):
            val = clean[4:].strip()
            host = urlparse(val).hostname
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="url",
                entity_id=f"url:{val}",
                canonical_name=val,
                rf_type="URL",
                v2_type="url",
                v2_lookup_id=f"url:{val}",
                extracted_domain=host.lower() if host else None,
            )
        if lower.startswith("mitre:"):
            val = clean[6:].strip().upper()
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="mitre",
                entity_id=f"mitre:{val}",
                canonical_name=val,
                rf_type="MitreAttackIdentifier",
            )
        if lower.startswith("asn:"):
            val = clean[4:].strip().upper()
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="asn",
                entity_id=f"asn:{val}",
                canonical_name=val,
                rf_type="ASNumber",
            )
        if lower.startswith("email:"):
            val = clean[6:].strip().lower()
            dom = val.split("@", 1)[1] if "@" in val else None
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="email",
                entity_id=f"email:{val}",
                canonical_name=val,
                rf_type="EmailAddress",
                extracted_domain=dom,
            )

        known_other_prefixes = tuple(
            p
            for p in ENTITY_ID_PREFIXES.values()
            if p not in ("ip:", "idn:", "hash:", "url:", "mitre:", "asn:", "email:")
        ) + ("vuln:", "company:", "malware:", "threatactor:")
        if lower.startswith(known_other_prefixes):
            val = _strip_prefix(clean)
            if lower.startswith("vuln:"):
                return ResolvedTarget(
                    raw_query=clean,
                    detected_kind="vulnerability",
                    entity_id=clean,
                    canonical_name=val,
                    rf_type="CyberVulnerability",
                    v2_type="vulnerability",
                    v2_lookup_id=clean,
                )
            if lower.startswith("company:"):
                return ResolvedTarget(
                    raw_query=clean,
                    detected_kind="company",
                    entity_id=clean,
                    canonical_name=val,
                    rf_type="Company",
                    v2_type="company",
                    v2_lookup_id=clean,
                )
            if lower.startswith("malware:"):
                return ResolvedTarget(
                    raw_query=clean,
                    detected_kind="malware",
                    entity_id=clean,
                    canonical_name=val,
                    rf_type="Malware",
                    v2_type="malware",
                    v2_lookup_id=clean,
                )
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="entity_id",
                entity_id=clean,
                canonical_name=val,
            )

        # Infer by syntax when no prefix was provided
        if lower.startswith(("http://", "https://")):
            host = urlparse(clean).hostname
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="url",
                entity_id=f"url:{clean}",
                canonical_name=clean,
                rf_type="URL",
                v2_type="url",
                v2_lookup_id=f"url:{clean}",
                extracted_domain=host.lower() if host else None,
            )
        try:
            ip_obj = ipaddress.ip_address(clean)
            ip_str = str(ip_obj)
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="ip",
                entity_id=f"ip:{ip_str}",
                canonical_name=ip_str,
                rf_type="IpAddress",
                v2_type="ip",
                v2_lookup_id=ip_str,
            )
        except ValueError:
            pass

        if _CVE_RE.match(clean):
            cve_norm = clean.upper()
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="vulnerability",
                entity_id=None,
                canonical_name=cve_norm,
                rf_type="CyberVulnerability",
                v2_type="vulnerability",
                v2_lookup_id=None,
            )
        if _HEX_HASH_RE.match(clean):
            h_norm = clean.lower()
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="hash",
                entity_id=f"hash:{h_norm}",
                canonical_name=h_norm,
                rf_type="Hash",
                v2_type="hash",
                v2_lookup_id=h_norm,
            )
        email_match = _EMAIL_RE.match(clean)
        if email_match:
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="email",
                entity_id=f"email:{clean.lower()}",
                canonical_name=clean.lower(),
                rf_type="EmailAddress",
                extracted_domain=email_match.group(1).lower(),
            )
        if _MITRE_RE.match(clean):
            code = clean.upper()
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="mitre",
                entity_id=f"mitre:{code}",
                canonical_name=code,
                rf_type="MitreAttackIdentifier",
            )
        if _ASN_RE.match(clean):
            asn = clean.upper()
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="asn",
                entity_id=f"asn:{asn}",
                canonical_name=asn,
                rf_type="ASNumber",
            )
        if _DOMAIN_RE.match(clean):
            dom = clean.lower()
            return ResolvedTarget(
                raw_query=clean,
                detected_kind="domain",
                entity_id=f"idn:{dom}",
                canonical_name=dom,
                rf_type="InternetDomainName",
                v2_type="domain",
                v2_lookup_id=dom,
                extracted_domain=dom,
            )
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="text",
            entity_id=None,
            canonical_name=clean,
        )

    # Explicit type handling
    val = _strip_prefix(clean)
    if forced == "ip":
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="ip",
            entity_id=f"ip:{val}",
            canonical_name=val,
            rf_type="IpAddress",
            v2_type="ip",
            v2_lookup_id=val,
        )
    if forced == "domain":
        dom = val.lower()
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="domain",
            entity_id=f"idn:{dom}",
            canonical_name=dom,
            rf_type="InternetDomainName",
            v2_type="domain",
            v2_lookup_id=dom,
            extracted_domain=dom,
        )
    if forced == "hash":
        h_val = val.lower()
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="hash",
            entity_id=f"hash:{h_val}",
            canonical_name=h_val,
            rf_type="Hash",
            v2_type="hash",
            v2_lookup_id=h_val,
        )
    if forced == "url":
        host = urlparse(val).hostname
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="url",
            entity_id=f"url:{val}",
            canonical_name=val,
            rf_type="URL",
            v2_type="url",
            v2_lookup_id=f"url:{val}",
            extracted_domain=host.lower() if host else None,
        )
    if forced == "vulnerability":
        is_opaque = (
            not _CVE_RE.match(clean)
            and ":" not in clean
            and len(clean) in range(4, 16)
            and any(c.isdigit() or c in "-_" for c in clean)
        )
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="vulnerability",
            entity_id=clean if is_opaque else None,
            canonical_name=clean.upper() if _CVE_RE.match(clean) else val,
            rf_type="CyberVulnerability",
            v2_type="vulnerability",
            v2_lookup_id=clean if is_opaque else None,
        )
    if forced == "malware":
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="malware",
            entity_id=None,
            canonical_name=val,
            rf_type="Malware",
            v2_type="malware",
            v2_lookup_id=None,
        )
    if forced == "actor":
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="actor",
            entity_id=None,
            canonical_name=val,
            rf_type="Organization",
        )
    if forced == "company":
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="company",
            entity_id=None,
            canonical_name=val,
            rf_type="Company",
            v2_type="company",
            v2_lookup_id=None,
        )
    if forced == "email":
        em = val.lower()
        dom = em.split("@", 1)[1] if "@" in em else None
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="email",
            entity_id=f"email:{em}",
            canonical_name=em,
            rf_type="EmailAddress",
            extracted_domain=dom,
        )
    if forced == "mitre":
        code = val.upper()
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="mitre",
            entity_id=f"mitre:{code}",
            canonical_name=code,
            rf_type="MitreAttackIdentifier",
        )
    if forced == "asn":
        asn = val.upper()
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="asn",
            entity_id=f"asn:{asn}",
            canonical_name=asn,
            rf_type="ASNumber",
        )
    if forced == "entity_id":
        return ResolvedTarget(
            raw_query=clean,
            detected_kind="entity_id",
            entity_id=clean,
            canonical_name=val,
        )
    return ResolvedTarget(
        raw_query=clean,
        detected_kind="text",
        entity_id=None,
        canonical_name=clean,
    )


def _pick_best_candidate(
    query: str, candidates: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if not candidates:
        return None
    q_low = query.strip().lower()
    for cand in candidates:
        name = str(cand.get("name") or "").strip().lower()
        if name == q_low:
            return cand
        for alias in cand.get("aliases") or []:
            if str(alias).strip().lower() == q_low:
                return cand
    return candidates[0]


def resolve_research_target(
    client: RecordedFutureClient,
    raw_query: str,
    explicit_type: str | None = None,
) -> ResolvedTarget:
    """Resolve opaque RF entity IDs and aliases via Entity Match / Search APIs."""
    target = classify_research_target(raw_query, explicit_type=explicit_type)
    kind = target.detected_kind

    if kind in ("ip", "domain", "hash", "url"):
        return target

    if kind == "entity_id" and target.entity_id:
        try:
            meta = client.entity_lookup(target.entity_id)
            if isinstance(meta, dict) and meta:
                target.canonical_name = str(meta.get("name") or target.canonical_name)
                rf_type = str(meta.get("type") or "")
                if rf_type:
                    target.rf_type = rf_type
                    v2_mapped = _RF_TYPE_TO_V2_TYPE.get(rf_type.lower())
                    if v2_mapped:
                        target.v2_type = v2_mapped
                        target.v2_lookup_id = target.entity_id
                    mapped_kind = _RF_TYPE_TO_PIVOT_KIND.get(rf_type.lower())
                    if mapped_kind:
                        target.detected_kind = mapped_kind
                target.aliases = [str(a) for a in (meta.get("aliases") or []) if a]
        except Exception as exc:
            logger.debug("Entity lookup skipped for %s: %s", target.entity_id, exc)
        return target

    if kind == "vulnerability" and not target.entity_id:
        candidates: list[dict[str, Any]] = []
        try:
            matches = client.entity_match(
                target.canonical_name, types=["CyberVulnerability"], limit=5
            )
            if isinstance(matches, list):
                candidates.extend(m for m in matches if isinstance(m, dict))
        except Exception as exc:
            logger.debug("Entity match failed for CVE %s: %s", target.canonical_name, exc)

        if not candidates:
            try:
                srch = client.v2_search(
                    "vulnerability", freetext=target.canonical_name, limit=5
                )
                for row in (srch.get("data") or {}).get("results") or []:
                    ent = row.get("entity") if isinstance(row, dict) else None
                    if isinstance(ent, dict) and ent.get("id"):
                        candidates.append(ent)
            except Exception as exc:
                logger.debug("v2 vuln search fallback failed: %s", exc)

        target.candidates = candidates
        best = _pick_best_candidate(target.canonical_name, candidates)
        if best and best.get("id"):
            target.entity_id = str(best["id"])
            target.v2_lookup_id = target.entity_id
            target.canonical_name = str(best.get("name") or target.canonical_name)
            target.rf_type = str(best.get("type") or "CyberVulnerability")
        return target

    if kind == "actor":
        candidates = []
        aliases: list[str] = []
        try:
            actor_res = client.search_threat_actors(name=target.raw_query, limit=10)
            for item in actor_res.get("data") or []:
                if not isinstance(item, dict):
                    continue
                attrs = item.get("attributes") or {}
                item_aliases = [
                    str(a)
                    for a in (attrs.get("common_names") or []) + (attrs.get("alias") or [])
                    if a
                ]
                candidates.append(
                    {
                        "id": item.get("id"),
                        "type": item.get("type") or "Organization",
                        "name": attrs.get("name") or item.get("id"),
                        "aliases": item_aliases,
                    }
                )
        except Exception as exc:
            logger.debug("Threat actor search failed during resolution: %s", exc)

        if not candidates:
            try:
                matches = client.entity_match(target.raw_query, limit=10)
                if isinstance(matches, list):
                    candidates.extend(m for m in matches if isinstance(m, dict))
            except Exception as exc:
                logger.debug("Entity match failed for actor %s: %s", target.raw_query, exc)

        target.candidates = candidates
        best = _pick_best_candidate(target.raw_query, candidates)
        if best and best.get("id"):
            target.entity_id = str(best["id"])
            target.canonical_name = str(best.get("name") or target.canonical_name)
            target.rf_type = str(best.get("type") or "Organization")
            aliases = [str(a) for a in (best.get("aliases") or []) if a]
            target.aliases = aliases
        return target

    if kind == "malware":
        candidates = []
        try:
            matches = client.entity_match(target.raw_query, types=["Malware"], limit=10)
            if isinstance(matches, list):
                candidates.extend(m for m in matches if isinstance(m, dict))
        except Exception as exc:
            logger.debug("Entity match failed for malware %s: %s", target.raw_query, exc)

        if not candidates:
            try:
                srch = client.v2_search("malware", freetext=target.raw_query, limit=10)
                for row in (srch.get("data") or {}).get("results") or []:
                    ent = row.get("entity") if isinstance(row, dict) else None
                    if isinstance(ent, dict) and ent.get("id"):
                        candidates.append(ent)
            except Exception as exc:
                logger.debug("v2 malware search fallback failed: %s", exc)

        target.candidates = candidates
        best = _pick_best_candidate(target.raw_query, candidates)
        if best and best.get("id"):
            target.entity_id = str(best["id"])
            target.v2_lookup_id = target.entity_id
            target.canonical_name = str(best.get("name") or target.canonical_name)
            target.rf_type = str(best.get("type") or "Malware")
        return target

    if kind == "company":
        candidates = []
        try:
            matches = client.entity_match(
                target.raw_query, types=["Company", "Organization"], limit=10
            )
            if isinstance(matches, list):
                candidates.extend(m for m in matches if isinstance(m, dict))
        except Exception as exc:
            logger.debug("Entity match failed for company %s: %s", target.raw_query, exc)
        target.candidates = candidates
        best = _pick_best_candidate(target.raw_query, candidates)
        if best and best.get("id"):
            target.entity_id = str(best["id"])
            target.v2_lookup_id = target.entity_id
            target.canonical_name = str(best.get("name") or target.canonical_name)
            target.rf_type = str(best.get("type") or "Company")
        return target

    if kind == "text":
        candidates = []
        try:
            actor_res = client.search_threat_actors(name=target.raw_query, limit=5)
            for item in actor_res.get("data") or []:
                if not isinstance(item, dict):
                    continue
                attrs = item.get("attributes") or {}
                item_aliases = [
                    str(a)
                    for a in (attrs.get("common_names") or []) + (attrs.get("alias") or [])
                    if a
                ]
                candidates.append(
                    {
                        "id": item.get("id"),
                        "type": item.get("type") or "Organization",
                        "name": attrs.get("name") or item.get("id"),
                        "aliases": item_aliases,
                        "_from_actor_search": True,
                    }
                )
        except Exception as exc:
            logger.debug("Actor search skipped during text resolution: %s", exc)

        try:
            matches = client.entity_match(target.raw_query, limit=15)
            if isinstance(matches, list):
                seen_ids = {str(c.get("id")) for c in candidates if c.get("id")}
                for m in matches:
                    if isinstance(m, dict) and str(m.get("id")) not in seen_ids:
                        candidates.append(m)
        except Exception as exc:
            logger.debug("Entity match skipped during text resolution: %s", exc)

        target.candidates = candidates
        best = _pick_best_candidate(target.raw_query, candidates)
        if best and best.get("id"):
            target.entity_id = str(best["id"])
            target.canonical_name = str(best.get("name") or target.canonical_name)
            rf_type = str(best.get("type") or "")
            target.rf_type = rf_type or None
            target.aliases = [str(a) for a in (best.get("aliases") or []) if a]
            if best.get("_from_actor_search"):
                target.detected_kind = "actor"
            else:
                v2_mapped = _RF_TYPE_TO_V2_TYPE.get(rf_type.lower())
                if v2_mapped:
                    target.v2_type = v2_mapped
                    target.v2_lookup_id = target.entity_id
                mapped_kind = _RF_TYPE_TO_PIVOT_KIND.get(rf_type.lower())
                if mapped_kind:
                    target.detected_kind = mapped_kind
        return target

    # mitre / asn / email: try entity_lookup to enrich aliases when available
    if target.entity_id:
        try:
            meta = client.entity_lookup(target.entity_id)
            if isinstance(meta, dict) and meta.get("name"):
                target.canonical_name = str(meta["name"])
                target.aliases = [str(a) for a in (meta.get("aliases") or []) if a]
        except Exception:
            pass
    return target


def _safe_run_section(
    key: str,
    fn: Callable[[], tuple[Any, int, list[ResearchPivot], str]],
) -> ResearchSectionResult:
    title = _SECTION_TITLES.get(key, key)
    started = time.perf_counter()
    try:
        data, count, pivots, msg = fn()
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        status = "ok" if count > 0 else "empty"
        return ResearchSectionResult(
            key=key,
            title=title,
            status=status,
            message=msg or (f"{count} result(s)" if count else "No records returned."),
            count=count,
            elapsed_ms=round(elapsed_ms, 2),
            data=data,
            pivots=pivots,
        )
    except RecordedFutureAuthError as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return ResearchSectionResult(
            key=key,
            title=title,
            status="not_entitled",
            status_code=exc.status_code,
            permission_type=exc.permission_type,
            message=str(exc),
            elapsed_ms=round(elapsed_ms, 2),
        )
    except ConfigurationError as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return ResearchSectionResult(
            key=key,
            title=title,
            status="not_configured",
            message=str(exc),
            elapsed_ms=round(elapsed_ms, 2),
        )
    except RecordedFutureError as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return ResearchSectionResult(
            key=key,
            title=title,
            status="error",
            status_code=exc.status_code,
            message=str(exc),
            elapsed_ms=round(elapsed_ms, 2),
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return ResearchSectionResult(
            key=key,
            title=title,
            status="error",
            message=str(exc),
            elapsed_ms=round(elapsed_ms, 2),
        )


def _skipped_section(key: str, reason: str) -> ResearchSectionResult:
    return ResearchSectionResult(
        key=key,
        title=_SECTION_TITLES.get(key, key),
        status="skipped",
        message=reason,
    )


def _extract_v2_pivots(data_block: dict[str, Any]) -> list[ResearchPivot]:
    pivots: list[ResearchPivot] = []
    for rel_group in data_block.get("relatedEntities") or []:
        if not isinstance(rel_group, dict):
            continue
        rel_type = str(rel_group.get("type") or "Related")
        for item in rel_group.get("entities") or []:
            if not isinstance(item, dict):
                continue
            ent = item.get("entity") if isinstance(item.get("entity"), dict) else item
            if not isinstance(ent, dict):
                continue
            eid = str(ent.get("id") or "").strip()
            name = str(ent.get("name") or eid).strip()
            etype = str(ent.get("type") or rel_type).strip()
            if not eid:
                continue
            score = item.get("score") if isinstance(item.get("score"), int) else None
            pivots.append(
                ResearchPivot(
                    entity_id=eid,
                    name=name,
                    entity_type=etype,
                    source_section="v2_intel",
                    risk_score=score,
                    relationship=rel_type,
                    pivot_kind=_infer_pivot_kind(etype, eid),
                )
            )
    return pivots


def _extract_links_pivots(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[ResearchPivot]]:
    raw_data = payload.get("data")
    groups: list[dict[str, Any]] = []
    if isinstance(raw_data, list):
        groups = [g for g in raw_data if isinstance(g, dict)]
    elif isinstance(raw_data, dict):
        groups = [raw_data]

    flat_links: list[dict[str, Any]] = []
    pivots: list[ResearchPivot] = []
    for grp in groups:
        for link in grp.get("links") or []:
            if not isinstance(link, dict):
                continue
            flat_links.append(link)
            eid = str(link.get("id") or "").strip()
            if not eid:
                continue
            name = str(link.get("name") or eid).strip()
            etype = str(link.get("type") or "").replace("type:", "").strip()
            raw_risk = link.get("risk")
            risk_obj: dict[str, Any] = raw_risk if isinstance(raw_risk, dict) else {}
            score = risk_obj.get("score") if isinstance(risk_obj.get("score"), int) else None
            secs = [
                str(s.get("name") or s.get("id") or "")
                for s in (link.get("sections") or [])
                if isinstance(s, dict)
            ]
            pivots.append(
                ResearchPivot(
                    entity_id=eid,
                    name=name,
                    entity_type=etype or "Entity",
                    source_section="links",
                    risk_score=score,
                    relationship=", ".join(s for s in secs if s) or "Linked",
                    pivot_kind=_infer_pivot_kind(etype, eid),
                )
            )
    return flat_links, pivots


def _extract_note_pivots(notes: list[dict[str, Any]]) -> list[ResearchPivot]:
    pivots: list[ResearchPivot] = []
    for note in notes:
        if not isinstance(note, dict):
            continue
        raw_attrs = note.get("attributes")
        attrs: dict[str, Any] = raw_attrs if isinstance(raw_attrs, dict) else {}
        title = str(attrs.get("title") or note.get("id") or "Analyst Note")
        for key, rel in (("note_entities", "Mentioned in Note"), ("context_entities", "Note Context")):
            for ent in attrs.get(key) or []:
                if not isinstance(ent, dict):
                    continue
                eid = str(ent.get("id") or "").strip()
                if not eid:
                    continue
                etype = str(ent.get("type") or "Entity").strip()
                name = str(ent.get("name") or eid).strip()
                pivots.append(
                    ResearchPivot(
                        entity_id=eid,
                        name=name,
                        entity_type=etype,
                        source_section="analyst_notes",
                        relationship=f"{rel}: {title[:45]}",
                        pivot_kind=_infer_pivot_kind(etype, eid),
                    )
                )
    return pivots


def _deduplicate_pivots(
    pivots: Iterable[ResearchPivot], *, exclude_entity_id: str | None
) -> list[ResearchPivot]:
    excl = (exclude_entity_id or "").strip().lower()
    merged: dict[str, ResearchPivot] = {}
    for p in pivots:
        eid_low = p.entity_id.strip().lower()
        if not eid_low or (excl and eid_low == excl):
            continue
        existing = merged.get(eid_low)
        if existing is None:
            merged[eid_low] = ResearchPivot(
                entity_id=p.entity_id,
                name=p.name,
                entity_type=p.entity_type,
                source_section=p.source_section,
                risk_score=p.risk_score,
                relationship=p.relationship,
                pivot_kind=p.pivot_kind,
            )
        else:
            if existing.risk_score is None and p.risk_score is not None:
                existing.risk_score = p.risk_score
            elif (
                existing.risk_score is not None
                and p.risk_score is not None
                and p.risk_score > existing.risk_score
            ):
                existing.risk_score = p.risk_score
            if p.source_section and p.source_section not in existing.source_section:
                existing.source_section = f"{existing.source_section}, {p.source_section}"
            if p.relationship and p.relationship not in existing.relationship:
                existing.relationship = (
                    f"{existing.relationship}; {p.relationship}"
                    if existing.relationship
                    else p.relationship
                )
    out = list(merged.values())
    out.sort(
        key=lambda x: (
            x.risk_score is not None,
            x.risk_score if x.risk_score is not None else -1,
            x.name.lower(),
        ),
        reverse=True,
    )
    return out


def research_target(
    client: RecordedFutureClient,
    raw_query: str,
    *,
    explicit_type: str | None = None,
    modules: Iterable[str] | None = None,
    deep: bool = False,
    extensions: Iterable[str] | None = None,
    links_scope: str = "medium",
    links_timeframe: str = "-30d",
    limit: int = 20,
) -> ResearchDossier:
    """Execute a comprehensive cross-API Recorded Future research dossier."""
    target = resolve_research_target(client, raw_query, explicit_type=explicit_type)
    requested_modules: tuple[str, ...]
    if modules is not None:
        requested_modules = tuple(m.strip().lower() for m in modules if m and m.strip())
    elif deep or extensions is not None:
        requested_modules = RESEARCH_MODULES
    else:
        requested_modules = _DEFAULT_MODULES

    clean_val = _strip_prefix(target.canonical_name)
    ext_list = [e.strip() for e in extensions if e and e.strip()] if extensions else []

    def _run_v2() -> tuple[Any, int, list[ResearchPivot], str]:
        if not target.v2_type or not target.v2_lookup_id:
            return None, 0, [], f"No Connect v2 lookup type for {target.detected_kind}."
        fields = _V2_RICH_FIELDS.get(target.v2_type)
        try:
            payload = client.v2_lookup(
                target.v2_type, target.v2_lookup_id, fields=fields
            )
        except RecordedFutureError as exc:
            if exc.status_code == 400:
                fallback = _V2_FALLBACK_FIELDS.get(target.v2_type)
                payload = client.v2_lookup(
                    target.v2_type, target.v2_lookup_id, fields=fallback
                )
            else:
                raise
        data_block = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        result_obj: dict[str, Any] = {"lookup": payload}
        pivots = _extract_v2_pivots(data_block) if isinstance(data_block, dict) else []

        dom = target.extracted_domain
        if dom and target.v2_type in ("domain", "url"):
            try:
                comp = client.v2_company_by_domain(dom)
                result_obj["company_by_domain"] = comp
            except RecordedFutureError as comp_exc:
                result_obj["company_by_domain_note"] = str(comp_exc)
        count = 1 if data_block else 0
        return result_obj, count, pivots, f"Connect v2 {target.v2_type} lookup retrieved."

    def _run_soar() -> tuple[Any, int, list[ResearchPivot], str]:
        if target.v2_type not in ("ip", "domain", "hash", "url", "vulnerability"):
            return None, 0, [], f"SOAR v3 does not enrich {target.detected_kind}."
        ioc_val = target.canonical_name if target.v2_type == "vulnerability" else clean_val
        res = client.soar_enrich({target.v2_type: [ioc_val]})
        data_obj = res.get("data")
        if isinstance(data_obj, list):
            items = data_obj
        elif isinstance(data_obj, dict):
            items = data_obj.get("results") or []
        else:
            items = res.get("results") or []
        return res, len(items), [], f"SOAR v3 returned {len(items)} record(s)."

    def _run_links() -> tuple[Any, int, list[ResearchPivot], str]:
        if not target.entity_id:
            return None, 0, [], "No resolved RF entity ID for Links search."
        res = client.links_search(
            [target.entity_id],
            search_scope=links_scope,
            timeframe=links_timeframe,
            per_entity_type=max(5, limit),
        )
        flat_links, pivots = _extract_links_pivots(res)
        return res, len(flat_links), pivots, f"Found {len(flat_links)} validated link(s)."

    def _run_notes() -> tuple[Any, int, list[ResearchPivot], str]:
        if target.entity_id:
            res = client.search_analyst_notes(
                entity=target.entity_id, limit=limit, serialization="full"
            )
            notes = res.get("data") or []
            if not notes and target.detected_kind in ("text", "actor", "malware", "company"):
                res = client.search_analyst_notes(
                    title=target.canonical_name, limit=limit, serialization="full"
                )
        else:
            res = client.search_analyst_notes(
                title=target.raw_query, limit=limit, serialization="full"
            )
        notes = res.get("data") or []
        pivots = _extract_note_pivots(notes) if isinstance(notes, list) else []
        return res, len(notes), pivots, f"Found {len(notes)} Analyst Note(s)."

    def _run_actors() -> tuple[Any, int, list[ResearchPivot], str]:
        if target.detected_kind not in ("actor", "text") and target.rf_type != "Organization":
            return None, 0, [], f"Threat Actor search skipped for {target.detected_kind}."
        res = client.search_threat_actors(name=target.raw_query, limit=limit)
        items = res.get("data") or []
        pivots: list[ResearchPivot] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            eid = str(item.get("id") or "")
            attrs = item.get("attributes") or {}
            name = str(attrs.get("name") or eid)
            if eid:
                pivots.append(
                    ResearchPivot(
                        entity_id=eid,
                        name=name,
                        entity_type=str(item.get("type") or "Organization"),
                        source_section="threat_actors",
                        relationship="Threat Actor Match",
                        pivot_kind="actor",
                    )
                )
        return res, len(items), pivots, f"Matched {len(items)} Threat Actor(s)."

    def _run_threat_map() -> tuple[Any, int, list[ResearchPivot], str]:
        if target.detected_kind == "actor" or target.rf_type == "Organization":
            actors_arg = [target.entity_id] if target.entity_id else None
            res = client.get_threat_actor_map(actors=actors_arg)
            tmap = (res.get("data") or {}).get("threat_map") or []
            return res, len(tmap), [], f"Actor Threat Map returned {len(tmap)} entry/entries."
        if target.detected_kind == "malware" or target.rf_type == "Malware":
            mal_arg = [target.entity_id] if target.entity_id else None
            res = client.get_malware_threat_map(malware=mal_arg)
            tmap = (res.get("data") or {}).get("threat_map") or []
            return res, len(tmap), [], f"Malware Threat Map returned {len(tmap)} entry/entries."
        return None, 0, [], f"Threat Map is scoped to actors/malware (target is {target.detected_kind})."

    def _run_detection_rules() -> tuple[Any, int, list[ResearchPivot], str]:
        rules: list[dict[str, Any]] = []
        rule_limit = min(limit, 50)
        if target.entity_id:
            rules = client.search_detection_rules(
                rule_types=["sigma", "yara", "snort"],
                entities=[target.entity_id],
                limit=rule_limit,
                paginate=False,
            )
        if not rules and target.detected_kind in (
            "malware",
            "actor",
            "vulnerability",
            "mitre",
            "text",
        ):
            rules = client.search_detection_rules(
                rule_types=["sigma", "yara", "snort"],
                title=target.canonical_name,
                limit=rule_limit,
                paginate=False,
            )
        return rules, len(rules), [], f"Found {len(rules)} detection rule(s)."

    def _run_malware_intel() -> tuple[Any, int, list[ResearchPivot], str]:
        if target.detected_kind == "hash" and len(clean_val) == 64:
            res = client.malware_intel_query_iocs(sha256_list=[clean_val], field="sha256")
        elif target.detected_kind == "ip":
            res = client.malware_intel_query_iocs(ip_list=[clean_val], field="sha256")
        elif target.detected_kind == "domain":
            res = client.malware_intel_query_iocs(domain_list=[clean_val], field="sha256")
        elif target.detected_kind == "url":
            res = client.malware_intel_query_iocs(url_list=[clean_val], field="sha256")
        elif target.detected_kind in ("malware", "actor", "mitre", "text"):
            res = client.malware_intel_query_nl(target.canonical_name, field="sha256")
        else:
            return None, 0, [], f"Malware Intelligence skipped for {target.detected_kind}."
        items = res.get("data") or []
        pivots: list[ResearchPivot] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            sha = str(item.get("name") or "").strip()
            if sha and len(sha) == 64:
                pivots.append(
                    ResearchPivot(
                        entity_id=f"hash:{sha}",
                        name=sha,
                        entity_type="Hash",
                        source_section="malware_intel",
                        risk_score=item.get("risk_score") if isinstance(item.get("risk_score"), int) else None,
                        relationship="Malware Intel Sample",
                        pivot_kind="hash",
                    )
                )
        return res, len(items), pivots, f"Malware Intelligence returned {len(items)} artifact(s)."

    def _run_risk_history() -> tuple[Any, int, list[ResearchPivot], str]:
        if not target.entity_id:
            return None, 0, [], "No resolved RF entity ID for Risk History."
        res = client.search_risk_history([target.entity_id])
        items = res.get("data") or []
        return res, len(items), [], f"Risk History returned {len(items)} timeline(s)."

    def _run_identity() -> tuple[Any, int, list[ResearchPivot], str]:
        dom = target.extracted_domain
        if target.detected_kind == "domain" or (target.detected_kind == "url" and dom):
            res = client.identity_search(domains=[dom or clean_val], limit=limit)
            items = res.get("identities") or []
        elif target.detected_kind == "email":
            res = client.identity_lookup(subjects=[clean_val], limit=limit)
            items = res.get("identities") or []
        elif target.detected_kind == "ip":
            res = client.identity_ip_lookup(ip=clean_val, limit=limit)
            items = res.get("identities") or []
        else:
            return None, 0, [], f"Identity Intelligence skipped for {target.detected_kind}."
        return res, len(items), [], f"Identity Intelligence returned {len(items)} exposure(s)."

    def _run_alerts() -> tuple[Any, int, list[ResearchPivot], str]:
        res = client.search_alerts_v3(
            freetext=target.canonical_name or target.raw_query, limit=min(limit, 20)
        )
        data_obj = res.get("data")
        if isinstance(data_obj, list):
            items = data_obj
        elif isinstance(data_obj, dict):
            items = data_obj.get("results") or []
        else:
            items = []
        return res, len(items), [], f"Found {len(items)} Alert v3 hit(s)."

    def _run_playbook_alerts() -> tuple[Any, int, list[ResearchPivot], str]:
        if not target.entity_id:
            return None, 0, [], "No resolved RF entity ID for Playbook Alerts."
        res = client.search_playbook_alerts(
            entities=[target.entity_id], limit=min(limit, 20)
        )
        items = res.get("data") or []
        return res, len(items), [], f"Found {len(items)} Playbook Alert(s)."

    def _run_collective_insights() -> tuple[Any, int, list[ResearchPivot], str]:
        filters: dict[str, Any] | None = None
        if target.detected_kind == "malware":
            filters = {"associated_threats": {"malware": {"name": target.canonical_name}}}
        elif target.detected_kind == "actor":
            filters = {"associated_threats": {"threat_actor": {"name": target.canonical_name}}}
        elif target.detected_kind == "mitre":
            filters = {"associated_threats": {"mitre_code": {"name": target.canonical_name}}}
        res = client.search_collective_insights(filters=filters, limit=min(limit, 20))
        items = res.get("data") or []
        return res, len(items), [], f"Collective Insights returned {len(items)} event(s)."

    def _run_sandbox() -> tuple[Any, int, list[ResearchPivot], str]:
        if target.detected_kind == "hash":
            if len(clean_val) == 32:
                sb_q = f"md5:{clean_val}"
            elif len(clean_val) == 40:
                sb_q = f"sha1:{clean_val}"
            else:
                sb_q = f"sha256:{clean_val}"
        elif target.detected_kind == "ip":
            sb_q = f"ip:{clean_val}"
        elif target.detected_kind == "domain":
            sb_q = f"domain:{clean_val}"
        elif target.detected_kind == "url":
            sb_q = f'url:"{clean_val}"'
        elif target.detected_kind == "malware":
            sb_q = f"family:{target.canonical_name.lower()}"
        else:
            sb_q = target.canonical_name
        res = client.sandbox_search(sb_q, limit=min(limit, 20))
        samples = res.get("samples") or res.get("data") or []
        return res, len(samples), [], f"Sandbox returned {len(samples)} sample(s)."

    def _run_extensions() -> tuple[Any, int, list[ResearchPivot], str]:
        if not target.v2_type or not target.v2_lookup_id or target.v2_type not in V2_EXTENSION_CATALOG:
            return None, 0, [], f"Connect v2 extensions unavailable for {target.detected_kind}."
        chosen = ext_list or list(_DEFAULT_EXTENSIONS.get(target.v2_type, ()))
        if not chosen:
            return None, 0, [], "No extensions configured."
        out: dict[str, Any] = {}
        auth_err: RecordedFutureAuthError | None = None
        for ext_name in chosen:
            try:
                out[ext_name] = client.v2_lookup_extension(
                    target.v2_type, target.v2_lookup_id, ext_name
                )
            except RecordedFutureAuthError as exc:
                auth_err = exc
                out[ext_name] = {"error": str(exc), "status_code": exc.status_code}
            except RecordedFutureError as exc:
                out[ext_name] = {"error": str(exc), "status_code": exc.status_code}
        ok_count = sum(1 for v in out.values() if isinstance(v, dict) and "error" not in v)
        if ok_count == 0 and auth_err is not None:
            raise auth_err
        return out, ok_count, [], f"Queried {len(chosen)} extension(s); {ok_count} succeeded."

    def _run_asi() -> tuple[Any, int, list[ResearchPivot], str]:
        if not client.asi_api_key:
            raise ConfigurationError("RF_ASI_API_KEY / SECURITYTRAILS_API_KEY not set.")
        if target.detected_kind not in ("ip", "domain", "url", "vulnerability"):
            return None, 0, [], f"ASI skipped for {target.detected_kind}."
        proj_res = client.asi_list_projects()
        projects = proj_res.get("data") or []
        if not projects:
            return {"projects": []}, 0, [], "No ASI projects accessible."
        proj_id = str(projects[0].get("id") or "")
        if target.detected_kind == "ip":
            res = client.asi_find_assets(proj_id, referenced_ip=clean_val, limit=limit)
        elif target.detected_kind in ("domain", "url"):
            dom = target.extracted_domain or clean_val
            res = client.asi_find_assets(proj_id, apex=dom, limit=limit)
        else:
            res = client.asi_list_exposures(proj_id, filter_cve_id=target.canonical_name, limit=limit)
        rows = res.get("data") or []
        return res, len(rows), [], f"ASI project '{proj_id}' returned {len(rows)} record(s)."

    def _run_riskrecon() -> tuple[Any, int, list[ResearchPivot], str]:
        if not client.riskrecon_token:
            raise ConfigurationError("RF_RISKRECON_TOKEN / RISKRECON_API_TOKEN not set.")
        if target.detected_kind in ("domain", "url"):
            dom = target.extracted_domain or clean_val
            res = client.riskrecon_lookup_by_domain(dom)
        elif target.detected_kind == "vulnerability":
            res = client.riskrecon_lookup_by_cve(target.canonical_name)
        else:
            return None, 0, [], f"RiskRecon skipped for {target.detected_kind}."
        return res, len(res), [], f"RiskRecon returned {len(res)} TOE(s)."

    handlers: dict[str, Callable[[], tuple[Any, int, list[ResearchPivot], str]]] = {
        "v2_intel": _run_v2,
        "soar": _run_soar,
        "links": _run_links,
        "analyst_notes": _run_notes,
        "threat_actors": _run_actors,
        "threat_map": _run_threat_map,
        "detection_rules": _run_detection_rules,
        "malware_intel": _run_malware_intel,
        "risk_history": _run_risk_history,
        "identity": _run_identity,
        "alerts": _run_alerts,
        "playbook_alerts": _run_playbook_alerts,
        "collective_insights": _run_collective_insights,
        "sandbox": _run_sandbox,
        "extensions": _run_extensions,
        "asi": _run_asi,
        "riskrecon": _run_riskrecon,
    }

    sections: dict[str, ResearchSectionResult] = {}
    tasks: list[tuple[str, Callable[[], tuple[Any, int, list[ResearchPivot], str]]]] = []

    for mod_key in requested_modules:
        if mod_key not in handlers:
            continue
        if mod_key == "asi" and not client.asi_api_key and modules is None:
            sections[mod_key] = _skipped_section(
                mod_key, "ASI not configured (set RF_ASI_API_KEY to enable)."
            )
            continue
        if mod_key == "riskrecon" and not client.riskrecon_token and modules is None:
            sections[mod_key] = _skipped_section(
                mod_key, "RiskRecon not configured (set RF_RISKRECON_TOKEN to enable)."
            )
            continue
        tasks.append((mod_key, handlers[mod_key]))

    stop_ev = getattr(client, "_stop_event", None)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_map = {
            executor.submit(_safe_run_section, key, fn): key for key, fn in tasks
        }
        for fut in concurrent.futures.as_completed(future_map):
            key = future_map[fut]
            if stop_ev is not None and stop_ev.is_set():
                break
            sections[key] = fut.result()

    # Preserve canonical section order
    ordered_sections: dict[str, ResearchSectionResult] = {}
    for key in RESEARCH_MODULES:
        if key in sections:
            ordered_sections[key] = sections[key]

    risk_score: int | None = None
    risk_string = ""
    criticality_label = ""
    ai_summary = ""

    v2_sec = ordered_sections.get("v2_intel")
    if v2_sec and isinstance(v2_sec.data, dict):
        lookup = v2_sec.data.get("lookup")
        if isinstance(lookup, dict):
            d = lookup.get("data") if isinstance(lookup.get("data"), dict) else lookup
            if isinstance(d, dict):
                raw_risk = d.get("risk")
                risk_obj: dict[str, Any] = raw_risk if isinstance(raw_risk, dict) else {}
                if isinstance(risk_obj.get("score"), int):
                    risk_score = risk_obj["score"]
                risk_string = str(risk_obj.get("riskString") or "")
                criticality_label = str(risk_obj.get("criticalityLabel") or "")
                raw_ai = d.get("aiInsights")
                ai_obj: dict[str, Any] = raw_ai if isinstance(raw_ai, dict) else {}
                ai_summary = str(ai_obj.get("text") or risk_obj.get("riskSummary") or "")

    if risk_score is None:
        soar_sec = ordered_sections.get("soar")
        if soar_sec and isinstance(soar_sec.data, dict):
            s_data = soar_sec.data.get("data")
            if isinstance(s_data, list):
                res_list = s_data
            elif isinstance(s_data, dict):
                res_list = s_data.get("results") or []
            else:
                res_list = soar_sec.data.get("results") or []
            if res_list and isinstance(res_list[0], dict):
                r_obj = res_list[0].get("risk") or {}
                if isinstance(r_obj.get("score"), int):
                    risk_score = r_obj["score"]
                if not risk_string and r_obj.get("riskString"):
                    risk_string = str(r_obj["riskString"])

    all_pivots: list[ResearchPivot] = []
    for sec in ordered_sections.values():
        all_pivots.extend(sec.pivots)
    for cand in target.candidates:
        if not isinstance(cand, dict):
            continue
        cid = str(cand.get("id") or "").strip()
        if not cid:
            continue
        cname = str(cand.get("name") or cid).strip()
        ctype = str(cand.get("type") or "Entity").strip()
        all_pivots.append(
            ResearchPivot(
                entity_id=cid,
                name=cname,
                entity_type=ctype,
                source_section="entity_match",
                relationship="Matching Entity",
                pivot_kind=_infer_pivot_kind(ctype, cid),
            )
        )
    deduped_pivots = _deduplicate_pivots(
        all_pivots, exclude_entity_id=target.entity_id
    )

    return ResearchDossier(
        target=target,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        risk_score=risk_score,
        risk_string=risk_string,
        criticality_label=criticality_label,
        ai_summary=ai_summary,
        sections=ordered_sections,
        pivots=deduped_pivots,
    )


def probe_api_capabilities(client: RecordedFutureClient) -> list[dict[str, Any]]:
    """Safely probe read-only Recorded Future API surfaces to inspect token entitlements."""
    probes: list[tuple[str, str, Callable[[], Any]]] = [
        (
            "Lists & Watchlists",
            "/list/search",
            lambda: client.get_watchlists(list_types=["domain"], limit=1),
        ),
        (
            "Entity Match",
            "/entity-match/match",
            lambda: client.entity_match("APT29", limit=1),
        ),
        (
            "Connect v2 (IP/Domain/Hash/URL)",
            "/v2/ip/8.8.8.8",
            lambda: client.v2_lookup("ip", "8.8.8.8", fields=["entity", "risk"]),
        ),
        (
            "Connect v2 (Vulnerability)",
            "/v2/vulnerability/search",
            lambda: client.v2_search("vulnerability", freetext="CVE-2021-44228", limit=1),
        ),
        (
            "Connect v2 (Company by Domain)",
            "/v2/company/by_domain",
            lambda: client.v2_company_by_domain("google.com"),
        ),
        (
            "SOAR API v3",
            "/soar/v3/triage/contexts",
            lambda: client.soar_get_contexts(),
        ),
        (
            "Links Graph",
            "/links/metadata/entities",
            lambda: client.links_metadata_entities(),
        ),
        (
            "Analyst Notes",
            "/analyst-note/search",
            lambda: client.search_analyst_notes(limit=1, serialization="min"),
        ),
        (
            "Threat Maps & Actors",
            "/threat/maps",
            lambda: client.get_threat_maps(),
        ),
        (
            "Detection Rules (Sigma/YARA/Snort)",
            "/detection-rule/search",
            lambda: client.search_detection_rules(
                rule_types=["sigma"], limit=1, paginate=False
            ),
        ),
        (
            "Malware Intelligence",
            "/malware-intelligence/v1/query",
            lambda: client.malware_intel_query(
                "dynamic.network.flows.dst_port == 443", field="sha256"
            ),
        ),
        (
            "Alerts v3",
            "/alert/v3",
            lambda: client.search_alerts_v3(limit=1),
        ),
        (
            "Alert Rules v2",
            "/alert/v2/rule",
            lambda: client.search_alert_rules(limit=1),
        ),
        (
            "Playbook Alerts",
            "/playbook-alert/metadata/common",
            lambda: client.get_playbook_alert_metadata(),
        ),
        (
            "Cases",
            "/case/search",
            lambda: client.search_cases(limit=1),
        ),
        (
            "Risk History",
            "/risk/history",
            lambda: client.search_risk_history(["ip:8.8.8.8"]),
        ),
        (
            "Identity Intelligence",
            "/identity/metadata/dump/search",
            lambda: client.identity_dump_metadata(names=["linkedin"], limit=1),
        ),
        (
            "Collective Insights",
            "/collective-insights/search",
            lambda: client.search_collective_insights(limit=1),
        ),
        (
            "Fusion v3",
            "/fusion/v3/files/directory/%2Fpublic",
            lambda: client.fusion_list_directory("/public"),
        ),
        (
            "Autonomous Threat Operations",
            "/autonomous-threat-operations/v1/sources",
            lambda: client.ato_list_sources(),
        ),
        (
            "STIX / TAXII 2.1",
            "/taxii2/",
            lambda: client.taxii2_discover(),
        ),
        (
            "Sandbox v0",
            "sandbox.recordedfuture.com/api/v0/samples",
            lambda: client.sandbox_list_samples(limit=1),
        ),
        (
            "Attack Surface Intelligence (ASI)",
            "api.securitytrails.com/v2/projects",
            lambda: client.asi_list_projects(),
        ),
        (
            "Payment Fraud Intelligence (PFI)",
            "pfi.regemini.com/api/v1/task/list",
            lambda: client.pfi_list_tasks(),
        ),
        (
            "RiskRecon",
            "api.riskrecon.com/v1/toes",
            lambda: client.riskrecon_list_toes(),
        ),
    ]

    def _run_probe(idx: int, family: str, endpoint: str, fn: Callable[[], Any]) -> tuple[int, dict[str, Any]]:
        started = time.perf_counter()
        try:
            fn()
            return idx, {
                "family": family,
                "endpoint": endpoint,
                "status": "available",
                "status_code": 200,
                "detail": "Accessible with current credentials.",
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
            }
        except ConfigurationError as exc:
            return idx, {
                "family": family,
                "endpoint": endpoint,
                "status": "not_configured",
                "status_code": None,
                "detail": str(exc),
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
            }
        except RecordedFutureAuthError as exc:
            return idx, {
                "family": family,
                "endpoint": endpoint,
                "status": "not_entitled",
                "status_code": exc.status_code,
                "detail": f"{exc.permission_type}: {exc.message}",
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
            }
        except RecordedFutureError as exc:
            return idx, {
                "family": family,
                "endpoint": endpoint,
                "status": "error",
                "status_code": exc.status_code,
                "detail": str(exc),
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
            }
        except Exception as exc:
            return idx, {
                "family": family,
                "endpoint": endpoint,
                "status": "error",
                "status_code": None,
                "detail": str(exc),
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
            }

    results: dict[int, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futs = [
            executor.submit(_run_probe, idx, fam, ep, fn)
            for idx, (fam, ep, fn) in enumerate(probes)
        ]
        for fut in concurrent.futures.as_completed(futs):
            idx, rec = fut.result()
            results[idx] = rec
    return [results[i] for i in range(len(probes))]


def render_dossier_markdown(dossier: ResearchDossier) -> str:
    """Render a ``ResearchDossier`` as a structured Markdown threat research report."""
    t = dossier.target
    lines: list[str] = [
        f"# Recorded Future Threat Research Dossier: {t.canonical_name}",
        "",
        f"- **Raw Query:** `{t.raw_query}`",
        f"- **Detected Kind:** `{t.detected_kind}`",
        f"- **Entity ID:** `{t.entity_id or 'Unresolved'}`",
        f"- **Entity Type:** `{t.rf_type or 'N/A'}`",
        f"- **Generated At:** `{dossier.generated_at}`",
    ]
    if dossier.risk_score is not None:
        crit = f" ({dossier.criticality_label})" if dossier.criticality_label else ""
        rstr = f" [{dossier.risk_string}]" if dossier.risk_string else ""
        lines.append(f"- **Risk Score:** **{dossier.risk_score}/99**{crit}{rstr}")
    if t.aliases:
        lines.append(f"- **Aliases:** {', '.join(t.aliases[:15])}")
    if dossier.ai_summary:
        lines.extend(["", "## Executive Summary / AI Insights", "", dossier.ai_summary])

    # Triggered risk rules
    v2_sec = dossier.sections.get("v2_intel")
    if v2_sec and isinstance(v2_sec.data, dict):
        lookup = v2_sec.data.get("lookup") or {}
        d = lookup.get("data") if isinstance(lookup.get("data"), dict) else lookup
        risk_obj = d.get("risk") if isinstance(d, dict) else {}
        evidence = risk_obj.get("evidenceDetails") if isinstance(risk_obj, dict) else []
        if evidence:
            lines.extend(["", "## Triggered Risk Rules", "", "| Criticality | Rule | Evidence |", "|---|---|---|"])
            for ev in evidence[:20]:
                if not isinstance(ev, dict):
                    continue
                crit = ev.get("criticalityLabel") or ev.get("criticality") or "-"
                rule = str(ev.get("rule") or "-").replace("|", "\\|")
                ev_str = str(ev.get("evidenceString") or "-").replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {crit} | {rule} | {ev_str[:180]} |")

    # Linked Entities / Pivots
    if dossier.pivots:
        lines.extend(
            [
                "",
                "## Linked Entities & Pivots",
                "",
                "| Entity | Type | ID | Risk | Sources | Relationship |",
                "|---|---|---|---|---|---|",
            ]
        )
        for p in dossier.pivots[:30]:
            score_str = str(p.risk_score) if p.risk_score is not None else "-"
            lines.append(
                f"| {p.name.replace('|', '\\|')} | {p.entity_type} | `{p.entity_id}` | "
                f"{score_str} | {p.source_section} | {p.relationship.replace('|', '\\|')[:100]} |"
            )

    # Analyst Notes
    notes_sec = dossier.sections.get("analyst_notes")
    if notes_sec and isinstance(notes_sec.data, dict):
        notes = notes_sec.data.get("data") or []
        if notes:
            lines.extend(["", "## Analyst Notes", ""])
            for note in notes[:15]:
                if not isinstance(note, dict):
                    continue
                attrs = note.get("attributes") or {}
                title = attrs.get("title") or note.get("id")
                pub = attrs.get("published") or "-"
                topic_names = [
                    str(tp.get("name") or tp.get("id"))
                    for tp in (attrs.get("topic") or [])
                    if isinstance(tp, dict)
                ]
                lines.append(f"### {title}")
                lines.append(f"- **ID:** `{note.get('id')}` | **Published:** {pub} | **Topics:** {', '.join(topic_names) or '-'}")
                text_body = str(attrs.get("text") or "").strip()
                if text_body:
                    lines.extend(["", text_body[:1200] + ("..." if len(text_body) > 1200 else ""), ""])

    # Detection Rules
    rules_sec = dossier.sections.get("detection_rules")
    if rules_sec and isinstance(rules_sec.data, list) and rules_sec.data:
        lines.extend(["", "## Detection Rules", ""])
        for rule in rules_sec.data[:15]:
            if not isinstance(rule, dict):
                continue
            lines.append(
                f"- **{rule.get('title') or rule.get('id')}** "
                f"(type: `{rule.get('type', 'unknown')}`, updated: {rule.get('updated', '-')})"
            )

    # Section Status Matrix
    lines.extend(
        [
            "",
            "## API Surface Coverage",
            "",
            "| Section | Status | HTTP | Count | Elapsed (ms) | Notes |",
            "|---|---|---|---|---|---|",
        ]
    )
    for sec in dossier.sections.values():
        code_str = str(sec.status_code) if sec.status_code is not None else "-"
        lines.append(
            f"| {sec.title} | `{sec.status}` | {code_str} | {sec.count} | {sec.elapsed_ms:.1f} | "
            f"{sec.message.replace('|', '\\|')[:120]} |"
        )
    lines.append("")
    return "\n".join(lines)


def export_dossier_markdown(dossier: ResearchDossier, output_path: Path | str) -> Path:
    """Write a ``ResearchDossier`` Markdown report to disk cross-platform."""
    dest = Path(output_path).expanduser().resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(render_dossier_markdown(dossier), encoding="utf-8")
    return dest


def export_dossier_json(dossier: ResearchDossier, output_path: Path | str) -> Path:
    """Write a ``ResearchDossier`` JSON report to disk cross-platform."""
    dest = Path(output_path).expanduser().resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(dossier.to_dict(), indent=2, default=str), encoding="utf-8")
    return dest
