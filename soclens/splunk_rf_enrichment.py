"""Automated Recorded Future IOC field mapping and batch SOAR enrichment for Splunk ES."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

from soclens.client import MAX_SOAR_IOCS, RecordedFutureClient
from soclens.splunk_es import SplunkESClient

DEFAULT_SPLUNK_RF_FIELD_MAP: dict[str, tuple[str, ...]] = {
    "ip": (
        "src",
        "src_ip",
        "src_translated_ip",
        "dest",
        "dest_ip",
        "dst_ip",
        "dest_translated_ip",
        "client_ip",
        "dvc_ip",
        "nat_src_ip",
        "nat_dest_ip",
        "risk_object",
    ),
    "domain": (
        "domain",
        "query",
        "dest_host",
        "src_host",
        "url_domain",
        "http_host",
        "dns_query",
    ),
    "url": (
        "url",
        "uri",
        "http_url",
        "request_url",
    ),
    "hash": (
        "file_hash",
        "sha256",
        "sha1",
        "md5",
        "process_hash",
        "parent_process_hash",
    ),
    "vulnerability": (
        "cve",
        "signature_id",
    ),
}

_CANONICAL_IOC_TYPES: tuple[str, ...] = ("ip", "domain", "url", "hash", "vulnerability")

_IOC_TYPE_ALIASES: dict[str, str] = {
    "ip": "ip",
    "ipaddress": "ip",
    "ip_address": "ip",
    "domain": "domain",
    "internetdomainname": "domain",
    "idn": "domain",
    "url": "url",
    "hash": "hash",
    "filehash": "hash",
    "vulnerability": "vulnerability",
    "cybervulnerability": "vulnerability",
    "cve": "vulnerability",
}

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")
_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass(frozen=True)
class ExtractedObservable:
    """A validated IOC extracted from a Splunk event or ES notable."""

    ioc_type: str
    value: str
    source_field: str


def _canonicalize_ioc_type(raw_type: str) -> str:
    key = str(raw_type).strip().lower().replace("-", "_")
    canonical = _IOC_TYPE_ALIASES.get(key)
    if canonical is None:
        raise ValueError(
            f"Unsupported IOC type '{raw_type}'. "
            f"Valid types: {', '.join(_CANONICAL_IOC_TYPES)}."
        )
    return canonical


def _dedupe_fields(fields: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in fields:
        clean = str(raw).strip()
        if clean and clean not in seen:
            seen.add(clean)
            out.append(clean)
    return out


def _parse_field_map_spec(spec: Mapping[str, Sequence[str]] | str) -> dict[str, list[str]]:
    """Parse a JSON string, ``type=f1,f2;...`` string, or mapping dict into field lists."""
    parsed: dict[str, list[str]] = {}
    if isinstance(spec, Mapping):
        for raw_key, raw_fields in spec.items():
            ioc_type = _canonicalize_ioc_type(raw_key)
            if isinstance(raw_fields, str):
                fields = [part.strip() for part in raw_fields.split(",") if part.strip()]
            else:
                fields = [str(f).strip() for f in raw_fields if str(f).strip()]
            parsed[ioc_type] = _dedupe_fields(fields)
        return parsed

    raw_text = str(spec).strip()
    if not raw_text:
        return {}

    if raw_text.startswith("{"):
        try:
            loaded = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON field mapping specification: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ValueError("JSON field mapping specification must be a JSON object.")
        return _parse_field_map_spec(loaded)

    for segment in raw_text.split(";"):
        clean_seg = segment.strip()
        if not clean_seg:
            continue
        if "=" not in clean_seg:
            raise ValueError(
                f"Invalid field mapping segment '{clean_seg}'. "
                "Expected 'type=field1,field2' format."
            )
        raw_key, raw_vals = clean_seg.split("=", 1)
        ioc_type = _canonicalize_ioc_type(raw_key)
        fields = [part.strip() for part in raw_vals.split(",") if part.strip()]
        parsed[ioc_type] = _dedupe_fields(fields)
    return parsed


def load_splunk_rf_field_map(
    override: Mapping[str, Sequence[str]] | str | None = None,
) -> dict[str, list[str]]:
    """Load the effective Splunk-to-Recorded Future IOC field mapping.

    Starts from ``DEFAULT_SPLUNK_RF_FIELD_MAP``, applies ``RF_SPLUNK_FIELD_MAP``
    from the environment if set (JSON object or ``ip=src_ip,client_ip;domain=dns_query``),
    and finally applies any explicit ``override``.
    """
    effective: dict[str, list[str]] = {
        ioc_type: list(fields) for ioc_type, fields in DEFAULT_SPLUNK_RF_FIELD_MAP.items()
    }

    env_spec = os.environ.get("RF_SPLUNK_FIELD_MAP", "").strip()
    if env_spec:
        for ioc_type, fields in _parse_field_map_spec(env_spec).items():
            effective[ioc_type] = fields

    if override is not None:
        if isinstance(override, str):
            if override.strip():
                for ioc_type, fields in _parse_field_map_spec(override).items():
                    effective[ioc_type] = fields
        else:
            for ioc_type, fields in _parse_field_map_spec(override).items():
                effective[ioc_type] = fields

    return effective


def is_public_ip(value: str) -> bool:
    """Return True if ``value`` is a valid globally routable public IPv4/IPv6 address."""
    clean = str(value or "").strip()
    if not clean:
        return False
    try:
        ip = ipaddress.ip_address(clean)
    except ValueError:
        return False
    return bool(
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_reserved
        and not ip.is_multicast
        and not ip.is_unspecified
    )


def _normalize_ip(value: str, *, include_private_ips: bool) -> str | None:
    clean = value.strip()
    if not clean:
        return None
    try:
        ip = ipaddress.ip_address(clean)
    except ValueError:
        return None
    canonical = str(ip)
    if not include_private_ips and not is_public_ip(canonical):
        return None
    return canonical


def _normalize_domain(value: str) -> str | None:
    clean = value.strip().rstrip(".").lower()
    if not clean or len(clean) > 253 or "." not in clean:
        return None
    if any(ch.isspace() for ch in clean) or "://" in clean or "/" in clean or ":" in clean:
        return None
    try:
        ipaddress.ip_address(clean)
        return None
    except ValueError:
        pass
    labels = clean.split(".")
    if len(labels) < 2:
        return None
    if not _TLD_RE.match(labels[-1]):
        return None
    if not all(_DOMAIN_LABEL_RE.match(label) for label in labels):
        return None
    return clean


def _normalize_url(value: str) -> str | None:
    clean = value.strip()
    if not clean or any(ch.isspace() for ch in clean):
        return None
    parsed = urlsplit(clean)
    if parsed.scheme.lower() not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return clean


def _normalize_hash(value: str) -> str | None:
    clean = value.strip()
    if not _HASH_RE.match(clean):
        return None
    return clean.lower()


def _normalize_vulnerability(value: str) -> str | None:
    clean = value.strip()
    if not _CVE_RE.match(clean):
        return None
    return clean.upper()


def _validate_observable(
    ioc_type: str,
    raw_value: str,
    *,
    include_private_ips: bool,
) -> str | None:
    if ioc_type == "ip":
        return _normalize_ip(raw_value, include_private_ips=include_private_ips)
    if ioc_type == "domain":
        return _normalize_domain(raw_value)
    if ioc_type == "url":
        return _normalize_url(raw_value)
    if ioc_type == "hash":
        return _normalize_hash(raw_value)
    if ioc_type == "vulnerability":
        return _normalize_vulnerability(raw_value)
    return None


def _iter_candidate_strings(raw_value: Any, *, split_commas: bool) -> list[str]:
    if raw_value is None or isinstance(raw_value, (bool, dict)):
        return []
    if isinstance(raw_value, (list, tuple, set)):
        items: list[str] = []
        for elem in raw_value:
            items.extend(_iter_candidate_strings(elem, split_commas=split_commas))
        return items
    text = str(raw_value).strip()
    if not text:
        return []
    if split_commas and "," in text:
        return [part.strip() for part in text.split(",") if part.strip()]
    return [text]


def extract_observables_from_event(
    event: dict[str, Any],
    *,
    field_map: Mapping[str, Sequence[str]] | None = None,
    include_private_ips: bool = False,
) -> list[ExtractedObservable]:
    """Extract and validate deduplicated IOC observables from a Splunk event or ES notable.

    Inspects both top-level event keys and nested ``event.get("raw", {})`` fields,
    handles scalar and multivalue list fields, and deduplicates ``(ioc_type, value)``.
    """
    if not isinstance(event, dict):
        return []

    effective_map: dict[str, list[str]]
    if field_map is None:
        effective_map = load_splunk_rf_field_map()
    else:
        effective_map = _parse_field_map_spec(field_map)

    raw_nested = event.get("raw")
    raw_dict = raw_nested if isinstance(raw_nested, dict) else {}

    extracted: list[ExtractedObservable] = []
    seen: set[tuple[str, str]] = set()

    for ioc_type in _CANONICAL_IOC_TYPES:
        fields = effective_map.get(ioc_type, ())
        split_commas = ioc_type != "url"
        for field_name in fields:
            sources: list[Any] = []
            if field_name in event:
                sources.append(event.get(field_name))
            if field_name in raw_dict:
                sources.append(raw_dict.get(field_name))

            for raw_val in sources:
                for candidate in _iter_candidate_strings(raw_val, split_commas=split_commas):
                    normalized = _validate_observable(
                        ioc_type,
                        candidate,
                        include_private_ips=include_private_ips,
                    )
                    if normalized is None:
                        continue
                    key = (ioc_type, normalized)
                    if key in seen:
                        continue
                    seen.add(key)
                    extracted.append(
                        ExtractedObservable(
                            ioc_type=ioc_type,
                            value=normalized,
                            source_field=field_name,
                        )
                    )

    return extracted


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _criticality_from_risk(
    score: int | None,
    level: int | None,
    explicit_label: str = "",
) -> str:
    clean_label = explicit_label.strip()
    if clean_label:
        return clean_label
    if score is not None:
        if score >= 90:
            return "Very Malicious"
        if score >= 65:
            return "Malicious"
        if score >= 25:
            return "Suspicious"
        if score >= 5:
            return "Unusual"
        return "Benign"
    if level is not None:
        if level >= 5:
            return "Very Malicious"
        if level == 4:
            return "Malicious"
        if level == 3:
            return "Suspicious"
        if level == 2:
            return "Unusual"
        if level == 1:
            return "Benign"
    return "No Data"


def _extract_soar_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, list):
            return [item for item in results if isinstance(item, dict)]
    results = payload.get("results")
    if isinstance(results, list):
        return [item for item in results if isinstance(item, dict)]
    return []


def _extract_intel_card_url(item: dict[str, Any], entity: dict[str, Any]) -> str:
    links = item.get("links")
    if isinstance(links, dict):
        for key in ("portal", "intelCard", "intel_card", "web", "self"):
            val = links.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    elif isinstance(links, list):
        for entry in links:
            if isinstance(entry, dict):
                href = entry.get("href") or entry.get("url")
                if isinstance(href, str) and href.strip():
                    return href.strip()
            elif isinstance(entry, str) and entry.strip():
                return entry.strip()

    for key in ("intelCard", "intel_card"):
        val = entity.get(key) or item.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()

    entity_id = str(entity.get("id") or "").strip()
    if entity_id:
        return f"https://app.recordedfuture.com/live/sc/entity/{quote(entity_id, safe=':')}"
    return ""


def _normalize_soar_evidence(risk: dict[str, Any]) -> list[dict[str, Any]]:
    raw_evidence: Any = None
    rule_block = risk.get("rule")
    if isinstance(rule_block, dict) and isinstance(rule_block.get("evidence"), list):
        raw_evidence = rule_block.get("evidence")
    elif isinstance(risk.get("evidenceDetails"), list):
        raw_evidence = risk.get("evidenceDetails")
    elif isinstance(risk.get("rules"), list):
        raw_evidence = risk.get("rules")

    normalized: list[dict[str, Any]] = []
    if not isinstance(raw_evidence, list):
        return normalized

    for entry in raw_evidence:
        if isinstance(entry, dict):
            rule_name = str(entry.get("rule") or entry.get("name") or "").strip()
            evidence_str = str(
                entry.get("evidenceString")
                or entry.get("description")
                or entry.get("evidence")
                or ""
            ).strip()
            criticality = _as_int(entry.get("criticality"))
            crit_label = str(entry.get("criticalityLabel") or "").strip()
            normalized.append(
                {
                    "rule": rule_name,
                    "criticality": criticality,
                    "criticality_label": crit_label,
                    "evidence": evidence_str,
                }
            )
        elif isinstance(entry, str) and entry.strip():
            normalized.append(
                {
                    "rule": entry.strip(),
                    "criticality": None,
                    "criticality_label": "",
                    "evidence": "",
                }
            )
    return normalized


def _infer_ioc_type_from_entity(entity: dict[str, Any], item: dict[str, Any]) -> str | None:
    raw_type = str(entity.get("type") or item.get("type") or "").strip()
    if raw_type:
        key = raw_type.lower().replace("-", "_")
        if key in _IOC_TYPE_ALIASES:
            return _IOC_TYPE_ALIASES[key]
    entity_id = str(entity.get("id") or item.get("id") or "").strip()
    if ":" in entity_id:
        prefix = entity_id.split(":", 1)[0].strip().lower()
        if prefix in _IOC_TYPE_ALIASES:
            return _IOC_TYPE_ALIASES[prefix]
    return None


def _normalize_ioc_key_value(ioc_type: str, value: str) -> str:
    clean = value.strip()
    if ioc_type == "domain":
        return clean.rstrip(".").lower()
    if ioc_type == "hash":
        return clean.lower()
    if ioc_type == "vulnerability":
        return clean.upper()
    if ioc_type == "ip":
        try:
            return str(ipaddress.ip_address(clean))
        except ValueError:
            return clean
    return clean


def _parse_soar_enrichment_payload(payload: Any) -> dict[tuple[str, str], dict[str, Any]]:
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for item in _extract_soar_items(payload):
        entity_raw = item.get("entity")
        entity = entity_raw if isinstance(entity_raw, dict) else {}
        risk_raw = item.get("risk")
        risk = risk_raw if isinstance(risk_raw, dict) else {}

        ioc_type = _infer_ioc_type_from_entity(entity, item)
        if ioc_type is None:
            continue

        score = _as_int(risk.get("score") if "score" in risk else item.get("score"))
        level = _as_int(risk.get("level") if "level" in risk else item.get("level"))
        explicit_label = str(
            risk.get("criticalityLabel")
            or risk.get("criticality_label")
            or item.get("criticalityLabel")
            or ""
        )
        criticality_label = _criticality_from_risk(score, level, explicit_label)
        evidence = _normalize_soar_evidence(risk)
        intel_card_url = _extract_intel_card_url(item, entity)

        rules_count_val = _as_int(risk.get("rules")) if not isinstance(risk.get("rules"), list) else None
        rules_triggered = rules_count_val if rules_count_val is not None else len(evidence)

        record: dict[str, Any] = {
            "risk_score": score,
            "risk_level": level,
            "criticality_label": criticality_label,
            "evidence": evidence,
            "rules_triggered": rules_triggered,
            "intel_card_url": intel_card_url,
        }

        candidates: list[str] = []
        name_val = str(entity.get("name") or item.get("name") or "").strip()
        if name_val:
            candidates.append(name_val)
        id_val = str(entity.get("id") or item.get("id") or "").strip()
        if id_val:
            candidates.append(id_val)
            if ":" in id_val:
                candidates.append(id_val.split(":", 1)[1].strip())

        for cand in candidates:
            if not cand:
                continue
            norm_val = _normalize_ioc_key_value(ioc_type, cand)
            records[(ioc_type, norm_val)] = record

    return records


def _empty_rf_record() -> dict[str, Any]:
    return {
        "risk_score": None,
        "risk_level": None,
        "criticality_label": "No Data",
        "evidence": [],
        "rules_triggered": 0,
        "intel_card_url": "",
    }


def format_notable_rf_comment(enriched_event: dict[str, Any]) -> str:
    """Format a concise SOC-ready Splunk ES notable comment from RF enrichment results."""
    observables = enriched_event.get("rf_observables")
    if not isinstance(observables, list) or not observables:
        return "[Recorded Future] No enrichable IOCs mapped from this notable event."

    max_score = enriched_event.get("rf_max_risk_score")
    crit_label = str(enriched_event.get("rf_criticality_label") or "No Data")
    score_txt = f"{max_score}/99" if max_score is not None else "N/A"
    top_field = str(enriched_event.get("rf_top_field") or "").strip()

    header = f"[Recorded Future Enrichment] Max Risk: {score_txt} ({crit_label})"
    if top_field:
        header += f" | Top IOC: {top_field}"

    lines: list[str] = [header]
    ranked = sorted(
        observables,
        key=lambda o: (
            -1 if o.get("risk_score") is None else int(o["risk_score"]),
            len(o.get("evidence") or []),
        ),
        reverse=True,
    )

    for obs in ranked[:5]:
        src_field = str(obs.get("source_field") or obs.get("ioc_type") or "ioc")
        val = str(obs.get("value") or "")
        obs_score = obs.get("risk_score")
        obs_score_txt = f"{obs_score}/99" if obs_score is not None else "N/A"
        obs_crit = str(obs.get("criticality_label") or "No Data")
        ev_list = obs.get("evidence") if isinstance(obs.get("evidence"), list) else []
        rule_names = [
            str(ev.get("rule")).strip()
            for ev in ev_list
            if isinstance(ev, dict) and str(ev.get("rule") or "").strip()
        ]
        line = f"- {src_field}={val} [{obs.get('ioc_type', '')}]: {obs_score_txt} ({obs_crit})"
        if rule_names:
            line += f" | Rules: {', '.join(rule_names[:3])}"
        intel_url = str(obs.get("intel_card_url") or "").strip()
        if intel_url:
            line += f" | {intel_url}"
        lines.append(line)

    if len(ranked) > 5:
        lines.append(f"... and {len(ranked) - 5} additional mapped observable(s).")

    return "\n".join(lines)


def write_enrichment_to_notable(
    es_client: SplunkESClient,
    event_id: str,
    enriched_event: dict[str, Any],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Post a formatted Recorded Future enrichment comment to a Splunk ES notable event."""
    clean_id = str(event_id or "").strip()
    if not clean_id:
        raise ValueError("Notable event_id is required to write enrichment comment.")

    comment = format_notable_rf_comment(enriched_event)
    if dry_run:
        return {
            "dry_run": True,
            "event_id": clean_id,
            "comment": comment,
        }

    result = es_client.update_notable([clean_id], comment=comment)
    return {
        "dry_run": False,
        "event_id": clean_id,
        "comment": comment,
        "result": result,
    }


class SplunkRFEnricher:
    """Batch Recorded Future SOAR v3 enricher with thread-safe TTL caching for Splunk events."""

    def __init__(
        self,
        rf_client: RecordedFutureClient,
        *,
        cache_ttl_seconds: float = 300.0,
        batch_size: int = 50,
        field_map: Mapping[str, Sequence[str]] | str | None = None,
        include_private_ips: bool = False,
    ) -> None:
        self.rf_client = rf_client
        self.cache_ttl_seconds = max(0.0, float(cache_ttl_seconds))
        self.batch_size = max(1, min(int(batch_size), MAX_SOAR_IOCS))
        self.field_map = load_splunk_rf_field_map(field_map)
        self.include_private_ips = bool(include_private_ips)
        self._cache_lock = threading.Lock()
        self._cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}

    @property
    def cache_size(self) -> int:
        """Return the number of currently stored cache entries."""
        with self._cache_lock:
            return len(self._cache)

    def clear_cache(self) -> None:
        """Evict all cached IOC enrichment records."""
        with self._cache_lock:
            self._cache.clear()

    def _get_cached(self, key: tuple[str, str], now: float) -> dict[str, Any] | None:
        if self.cache_ttl_seconds <= 0.0:
            return None
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            expires_at, record = entry
            if now >= expires_at:
                self._cache.pop(key, None)
                return None
            return record

    def _put_cached(self, records: dict[tuple[str, str], dict[str, Any]], now: float) -> None:
        if self.cache_ttl_seconds <= 0.0 or not records:
            return
        expires_at = now + self.cache_ttl_seconds
        with self._cache_lock:
            for key, record in records.items():
                self._cache[key] = (expires_at, record)

    def _fetch_uncached(self, uncached: list[tuple[str, str]]) -> dict[tuple[str, str], dict[str, Any]]:
        fetched: dict[tuple[str, str], dict[str, Any]] = {}
        for idx in range(0, len(uncached), self.batch_size):
            chunk = uncached[idx : idx + self.batch_size]
            grouped: dict[str, list[str]] = {}
            for ioc_type, value in chunk:
                grouped.setdefault(ioc_type, []).append(value)

            payload = self.rf_client.soar_enrich(grouped)
            parsed = _parse_soar_enrichment_payload(payload)
            for key in chunk:
                fetched[key] = parsed.get(key, _empty_rf_record())
        return fetched

    def enrich_events(
        self,
        events: list[dict[str, Any]],
        *,
        field_map: Mapping[str, Sequence[str]] | str | None = None,
        include_private_ips: bool | None = None,
    ) -> list[dict[str, Any]]:
        """Extract IOCs from events, batch-enrich uncached IOCs via SOAR v3, and return enriched copies."""
        if not events:
            return []

        effective_map = (
            self.field_map
            if field_map is None
            else load_splunk_rf_field_map(field_map)
        )
        use_private = (
            self.include_private_ips
            if include_private_ips is None
            else bool(include_private_ips)
        )

        extracted_per_event: list[list[ExtractedObservable]] = [
            extract_observables_from_event(
                event,
                field_map=effective_map,
                include_private_ips=use_private,
            )
            for event in events
        ]

        now = time.monotonic()
        resolved: dict[tuple[str, str], dict[str, Any]] = {}
        uncached: list[tuple[str, str]] = []
        uncached_seen: set[tuple[str, str]] = set()

        for observables in extracted_per_event:
            for obs in observables:
                key = (obs.ioc_type, obs.value)
                if key in resolved or key in uncached_seen:
                    continue
                cached = self._get_cached(key, now)
                if cached is not None:
                    resolved[key] = cached
                else:
                    uncached_seen.add(key)
                    uncached.append(key)

        if uncached:
            fetched = self._fetch_uncached(uncached)
            resolved.update(fetched)
            self._put_cached(fetched, time.monotonic())

        enriched_events: list[dict[str, Any]] = []
        for event, observables in zip(events, extracted_per_event, strict=True):
            copy_ev = dict(event)
            rf_observables: list[dict[str, Any]] = []
            max_score: int | None = None
            top_crit = "No Data"
            top_ioc = ""
            top_field = ""
            total_rules = 0
            evidence_rules: list[str] = []
            seen_rules: set[str] = set()

            for obs in observables:
                rec = resolved.get((obs.ioc_type, obs.value), _empty_rf_record())
                score = rec.get("risk_score")
                crit = str(rec.get("criticality_label") or "No Data")
                ev_list = list(rec.get("evidence") or [])
                rules_triggered = int(rec.get("rules_triggered") or len(ev_list))
                intel_url = str(rec.get("intel_card_url") or "")

                rf_observables.append(
                    {
                        "source_field": obs.source_field,
                        "ioc_type": obs.ioc_type,
                        "value": obs.value,
                        "risk_score": score,
                        "criticality_label": crit,
                        "evidence": ev_list,
                        "intel_card_url": intel_url,
                    }
                )
                total_rules += rules_triggered

                for ev_item in ev_list:
                    if isinstance(ev_item, dict):
                        rule_name = str(ev_item.get("rule") or "").strip()
                        if rule_name and rule_name not in seen_rules:
                            seen_rules.add(rule_name)
                            evidence_rules.append(rule_name)

                if score is not None and (max_score is None or score > max_score):
                    max_score = score
                    top_crit = crit
                    top_ioc = obs.value
                    top_field = f"{obs.source_field}={obs.value}"
                elif max_score is None and not top_ioc:
                    top_crit = crit
                    top_ioc = obs.value
                    top_field = f"{obs.source_field}={obs.value}"

            copy_ev["rf_max_risk_score"] = max_score
            copy_ev["rf_criticality_label"] = top_crit if rf_observables else "No Data"
            copy_ev["rf_top_ioc"] = top_ioc
            copy_ev["rf_top_field"] = top_field
            copy_ev["rf_rules_triggered"] = total_rules
            copy_ev["rf_evidence_summary"] = "; ".join(evidence_rules[:3])
            copy_ev["rf_observables"] = rf_observables
            enriched_events.append(copy_ev)

        return enriched_events

    @staticmethod
    def format_notable_rf_comment(enriched_event: dict[str, Any]) -> str:
        """Format a concise SOC-ready Splunk ES notable comment from RF enrichment results."""
        return format_notable_rf_comment(enriched_event)

    @staticmethod
    def write_enrichment_to_notable(
        es_client: SplunkESClient,
        event_id: str,
        enriched_event: dict[str, Any],
        *,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Post a formatted Recorded Future enrichment comment to a Splunk ES notable event."""
        return write_enrichment_to_notable(
            es_client,
            event_id,
            enriched_event,
            dry_run=dry_run,
        )
