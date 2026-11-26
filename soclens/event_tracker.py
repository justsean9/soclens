"""Canonical unique event tracking, per-event AI panel persistence, and background triage."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from soclens.agent_audit import redact_sensitive_data
from soclens.agent_orchestrator import InvestigationResult
from soclens.agent_policy import VALID_INVESTIGATION_MODES, AIPolicyStore, InvestigationMode
from soclens.config import get_workspace_dir
from soclens.splunk_es import extract_finding_tenant

logger = logging.getLogger("soclens.event_tracker")

EventSourceKind = Literal[
    "rf_alert",
    "rf_playbook",
    "s1_threat",
    "s1_cloud_alert",
    "splunk_es",
]

VALID_EVENT_SOURCE_KINDS: frozenset[str] = frozenset(
    {
        "rf_alert",
        "rf_playbook",
        "s1_threat",
        "s1_cloud_alert",
        "splunk_es",
    }
)

DEFAULT_BACKGROUND_TRIAGE_QUESTION: str = (
    "Perform an automatic read-only SOC triage of this newly observed event, "
    "assess severity and false-positive likelihood, and corroborate IOCs/hosts "
    "across enabled read-only sources."
)

CACHE_SOURCE_TO_EVENT_KIND: dict[str, EventSourceKind] = {
    "rf_alerts_24h": "rf_alert",
    "rf_playbook_24h": "rf_playbook",
    "es_notables_24h": "splunk_es",
    "s1_threats_24h": "s1_threat",
}

_UNTRUSTED_CLOSE_RE = re.compile(
    r"</\s*untrusted_event_context(?:\s*/?>)?",
    re.IGNORECASE,
)
_BINARY_METADATA_KEYS: frozenset[str] = frozenset({"images", "raw", "binary", "bytes"})
_MAX_METADATA_STR_LEN = 2000
_MAX_METADATA_LIST_ITEMS = 25


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _escape_key_segment(value: str) -> str:
    """Bijectively escape key-delimiter characters so segments never collide across '::'."""
    return value.replace("%", "%25").replace(":", "%3A")


def _normalize_scope(scope: Any) -> str:
    if scope is None or isinstance(scope, bool):
        return "default"
    clean = str(scope).strip()
    if not clean or clean == "-":
        return "default"
    return clean


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _first_str(*values: Any, ignore_dash: bool = True) -> str:
    for val in values:
        if val is None or isinstance(val, (bool, dict, list, tuple, set, bytes, bytearray)):
            continue
        cleaned = str(val).strip()
        if not cleaned:
            continue
        if ignore_dash and cleaned == "-":
            continue
        return cleaned
    return ""


def _bounded_str_list(items: Any, *, limit: int = _MAX_METADATA_LIST_ITEMS) -> list[str]:
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        if isinstance(item, Mapping):
            candidate = _first_str(
                item.get("name"),
                item.get("id"),
                item.get("value"),
                item.get("target"),
                item.get("url"),
                item.get("label"),
            )
        else:
            candidate = _first_str(item, ignore_dash=False)
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        result.append(candidate[:500])
        if len(result) >= limit:
            break
    return result


def _sanitize_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 6:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        if len(cleaned) > _MAX_METADATA_STR_LEN:
            cleaned = cleaned[:_MAX_METADATA_STR_LEN] + "...[truncated]"
        return str(redact_sensitive_data(cleaned))
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key_str = str(k).strip()
            if not key_str or key_str.lower() in _BINARY_METADATA_KEYS:
                continue
            sanitized = _sanitize_value(v, depth=depth + 1)
            if sanitized in (None, "", [], {}):
                continue
            out[key_str] = sanitized
        return redact_sensitive_data(out)
    if isinstance(value, (list, tuple)):
        items: list[Any] = []
        for item in value[:_MAX_METADATA_LIST_ITEMS]:
            sanitized = _sanitize_value(item, depth=depth + 1)
            if sanitized not in (None, "", [], {}):
                items.append(sanitized)
        return items
    return str(redact_sensitive_data(str(value)[:_MAX_METADATA_STR_LEN]))


def _sanitize_metadata(raw_meta: Mapping[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, val in raw_meta.items():
        key_str = str(key).strip()
        if not key_str or key_str.lower() in _BINARY_METADATA_KEYS:
            continue
        sanitized = _sanitize_value(val, depth=0)
        if sanitized in (None, "", [], {}, "-"):
            continue
        cleaned[key_str] = sanitized
    redacted = redact_sensitive_data(cleaned)
    return dict(redacted) if isinstance(redacted, Mapping) else {}


def _redact_text(text: str) -> str:
    if not text:
        return ""
    return str(redact_sensitive_data(text))


def make_event_key(
    source_kind: EventSourceKind,
    native_id: str,
    scope: str = "default",
) -> str:
    """Construct a collision-free canonical key for a SOC event across all streams."""
    if not isinstance(source_kind, str) or source_kind not in VALID_EVENT_SOURCE_KINDS:
        raise ValueError(f"Unsupported event source kind: {source_kind!r}")

    if native_id is None or isinstance(native_id, bool):
        clean_id = ""
    else:
        clean_id = str(native_id).strip()
    if not clean_id:
        raise ValueError("native_id must be a non-empty string")

    clean_scope = _normalize_scope(scope)
    esc_id = _escape_key_segment(clean_id)
    esc_scope = _escape_key_segment(clean_scope)

    if source_kind == "splunk_es":
        return f"splunk_es::{esc_scope}::{esc_id}"
    if clean_scope != "default":
        return f"{source_kind}::{esc_scope}::{esc_id}"
    return f"{source_kind}::{esc_id}"


def infer_s1_source_kind(raw: Mapping[str, Any]) -> EventSourceKind:
    """Infer whether a SentinelOne record is ``s1_cloud_alert`` or ``s1_threat``."""
    if not isinstance(raw, Mapping):
        return "s1_threat"

    explicit_kind = _first_str(raw.get("source_kind"), raw.get("recordType"), ignore_dash=False)
    if explicit_kind in {"s1_cloud_alert", "cloud_alert"}:
        return "s1_cloud_alert"
    if explicit_kind in {"s1_threat", "threat"}:
        return "s1_threat"
    if _first_str(raw.get("mitigationStatus"), ignore_dash=False).lower() == "cloud_alert":
        return "s1_cloud_alert"

    raw_inner = _as_mapping(raw.get("raw"))
    if (
        _as_mapping(raw.get("alertInfo"))
        or _as_mapping(raw.get("ruleInfo"))
        or _as_mapping(raw_inner.get("alertInfo"))
        or _as_mapping(raw_inner.get("ruleInfo"))
    ):
        return "s1_cloud_alert"
    return "s1_threat"


@dataclass(frozen=True)
class UniqueEvent:
    """Canonical representation of a unique SOC alert, threat, or notable event."""

    event_key: str
    source_kind: EventSourceKind
    native_id: str
    scope: str = "default"
    title: str = ""
    severity: str = ""
    status: str = ""
    timestamp: str = ""
    summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_llm_context(self, max_chars: int = 16_000) -> str:
        """Serialize event telemetry into bounded, redacted, injection-safe LLM context."""
        if max_chars <= 0:
            return ""

        lines: list[str] = [
            f"Event Key: {self.event_key}",
            f"Source Kind: {self.source_kind}",
            f"Native ID: {self.native_id}",
            f"Scope: {self.scope}",
        ]
        if self.title:
            lines.append(f"Title: {self.title}")
        if self.severity:
            lines.append(f"Severity: {self.severity}")
        if self.status:
            lines.append(f"Status: {self.status}")
        if self.timestamp:
            lines.append(f"Timestamp: {self.timestamp}")
        if self.summary:
            lines.append(f"Summary: {self.summary}")

        safe_meta = _sanitize_metadata(self.metadata)
        if safe_meta:
            lines.append("Metadata:")
            for key, val in safe_meta.items():
                if isinstance(val, (dict, list)):
                    formatted = json.dumps(val, ensure_ascii=False, sort_keys=True)
                else:
                    formatted = str(val)
                lines.append(f"  - {key}: {formatted}")

        combined = _redact_text("\n".join(lines))
        safe_text = _UNTRUSTED_CLOSE_RE.sub("[escaped:/untrusted_event_context]", combined)
        if len(safe_text) <= max_chars:
            return safe_text
        suffix = "\n...[truncated]"
        if max_chars <= len(suffix):
            return safe_text[:max_chars]
        return safe_text[: max_chars - len(suffix)] + suffix

    def to_context_text(self, max_chars: int = 16_000) -> str:
        """Alias for ``to_llm_context``."""
        return self.to_llm_context(max_chars=max_chars)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a redacted JSON-compatible dictionary."""
        return {
            "event_key": self.event_key,
            "source_kind": self.source_kind,
            "native_id": self.native_id,
            "scope": self.scope,
            "title": _redact_text(self.title),
            "severity": _redact_text(self.severity),
            "status": _redact_text(self.status),
            "timestamp": _redact_text(self.timestamp),
            "summary": _redact_text(self.summary),
            "metadata": _sanitize_metadata(self.metadata),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> UniqueEvent | None:
        """Reconstruct a ``UniqueEvent`` from persisted JSON, returning ``None`` if invalid."""
        if not isinstance(raw, Mapping):
            return None

        source_raw = raw.get("source_kind")
        if not isinstance(source_raw, str) or source_raw not in VALID_EVENT_SOURCE_KINDS:
            return None
        source_kind = cast(EventSourceKind, source_raw)

        native_id = _first_str(raw.get("native_id"), ignore_dash=False)
        if not native_id:
            return None

        scope = _normalize_scope(raw.get("scope"))
        raw_key = _first_str(raw.get("event_key"), ignore_dash=False)
        event_key = raw_key or make_event_key(source_kind, native_id, scope=scope)

        raw_meta = raw.get("metadata")
        metadata = _sanitize_metadata(raw_meta) if isinstance(raw_meta, Mapping) else {}

        return cls(
            event_key=event_key,
            source_kind=source_kind,
            native_id=native_id,
            scope=scope,
            title=_redact_text(_first_str(raw.get("title"), ignore_dash=False)),
            severity=_redact_text(_first_str(raw.get("severity"), ignore_dash=False)),
            status=_redact_text(_first_str(raw.get("status"), ignore_dash=False)),
            timestamp=_redact_text(_first_str(raw.get("timestamp"), ignore_dash=False)),
            summary=_redact_text(_first_str(raw.get("summary"), ignore_dash=False)),
            metadata=metadata,
        )


def _extract_rf_alert_entities(raw: Mapping[str, Any], raw_inner: Mapping[str, Any]) -> tuple[str, list[str], int]:
    hits = _as_list(raw.get("hits")) or _as_list(raw_inner.get("hits"))
    primary = _first_str(raw.get("primary_entity"))
    entities: list[str] = []
    seen: set[str] = set()

    def _add_entity(val: Any) -> None:
        label = _first_str(val)
        if label and label not in seen and len(entities) < 15:
            seen.add(label)
            entities.append(label)

    if primary:
        _add_entity(primary)

    for hit in hits:
        hit_map = _as_mapping(hit)
        prim_map = _as_mapping(hit_map.get("primary_entity"))
        prim_val = _first_str(prim_map.get("name"), prim_map.get("id"))
        if prim_val:
            if not primary:
                primary = prim_val
            _add_entity(prim_val)
        for ent in _as_list(hit_map.get("entities")):
            ent_map = _as_mapping(ent)
            _add_entity(_first_str(ent_map.get("name"), ent_map.get("id")))

    for ent in _as_list(raw.get("enriched_entities")) or _as_list(raw_inner.get("enriched_entities")):
        ent_map = _as_mapping(ent)
        inner_ent = _as_mapping(ent_map.get("entity")) or ent_map
        ent_val = _first_str(inner_ent.get("name"), inner_ent.get("id"))
        if ent_val:
            if not primary:
                primary = ent_val
            _add_entity(ent_val)

    hits_count_raw = raw.get("hits_count")
    hits_count = hits_count_raw if isinstance(hits_count_raw, int) else len(hits)
    return primary, entities, hits_count


def _extract_rf_alert(raw: Mapping[str, Any], scope: str) -> UniqueEvent:
    raw_inner = _as_mapping(raw.get("raw"))
    review = _as_mapping(raw.get("review")) or _as_mapping(raw_inner.get("review"))
    rule = (
        _as_mapping(raw.get("rule"))
        or _as_mapping(raw.get("alertRule"))
        or _as_mapping(raw_inner.get("rule"))
        or _as_mapping(raw_inner.get("alertRule"))
    )
    log = _as_mapping(raw.get("log")) or _as_mapping(raw_inner.get("log"))
    url_obj = _as_mapping(raw.get("url")) or _as_mapping(raw_inner.get("url"))
    org_obj = _as_mapping(raw.get("owner_organisation_details")) or _as_mapping(
        raw_inner.get("owner_organisation_details")
    )

    ai_val = raw.get("ai_insights")
    ai_map = _as_mapping(ai_val)
    ai_inner_map = _as_mapping(raw_inner.get("ai_insights"))
    if isinstance(ai_val, str) and ai_val.strip():
        ai_text = ai_val.strip()
    else:
        ai_text = _first_str(
            ai_map.get("text"),
            ai_map.get("comment"),
            ai_inner_map.get("text"),
            ai_inner_map.get("comment"),
        )

    native_id = _first_str(raw.get("id"), raw_inner.get("id"), ignore_dash=False)
    if not native_id:
        raise ValueError("Recorded Future alert payload missing required 'id'")

    eff_scope = _normalize_scope(scope)
    rule_name = _first_str(raw.get("rule_name"), rule.get("name"), rule.get("label"))
    rule_id = _first_str(raw.get("rule_id"), rule.get("id"))
    title = _first_str(raw.get("title"), raw_inner.get("title"), rule_name, native_id)
    severity = _first_str(
        raw.get("priority"),
        review.get("priority"),
        raw.get("severity"),
        raw_inner.get("priority"),
    )
    status = _first_str(
        raw.get("status"),
        review.get("status_in_portal"),
        raw.get("statusInPortal"),
        review.get("status"),
        raw_inner.get("statusInPortal"),
    )
    timestamp = _first_str(
        raw.get("triggered"),
        log.get("triggered"),
        raw.get("status_date"),
        log.get("status_date"),
        raw_inner.get("triggered"),
    )
    assignee = _first_str(raw.get("assignee"), review.get("assignee"))
    if not assignee and isinstance(review.get("assignee"), Mapping):
        assignee = _first_str(
            _as_mapping(review.get("assignee")).get("name"),
            _as_mapping(review.get("assignee")).get("email"),
        )
    note = _first_str(raw.get("note"), review.get("note"), raw_inner.get("note"))
    org_name = _first_str(
        raw.get("org_name"),
        org_obj.get("enterprise_name"),
        raw.get("organisation_name"),
        raw_inner.get("organisation_name"),
    )
    portal_url = _first_str(
        raw.get("portal_url"),
        url_obj.get("portal"),
        raw.get("portalUrl"),
        raw_inner.get("portalUrl"),
    )
    primary_entity, entities, hits_count = _extract_rf_alert_entities(raw, raw_inner)

    summary_parts = [p for p in (ai_text, note) if p]
    if not summary_parts:
        if rule_name:
            summary_parts.append(f"Rule: {rule_name}")
        if primary_entity:
            summary_parts.append(f"Primary Entity: {primary_entity}")
    summary = _redact_text(" | ".join(summary_parts))

    metadata = _sanitize_metadata(
        {
            "type": _first_str(raw.get("type"), raw_inner.get("type")),
            "rule_id": rule_id,
            "rule_name": rule_name,
            "primary_entity": primary_entity,
            "entities": entities,
            "hits_count": hits_count if hits_count > 0 else None,
            "ai_insights": ai_text,
            "assignee": assignee,
            "org_name": org_name,
            "portal_url": portal_url,
            "note": note,
        }
    )

    return UniqueEvent(
        event_key=make_event_key("rf_alert", native_id, scope=eff_scope),
        source_kind="rf_alert",
        native_id=native_id,
        scope=eff_scope,
        title=_redact_text(title),
        severity=_redact_text(severity),
        status=_redact_text(status),
        timestamp=_redact_text(timestamp),
        summary=summary,
        metadata=metadata,
    )


def _extract_rf_playbook(raw: Mapping[str, Any], scope: str) -> UniqueEvent:
    raw_inner = _as_mapping(raw.get("raw"))
    pstatus = _as_mapping(raw.get("panel_status")) or _as_mapping(raw_inner.get("panel_status"))
    ev = _as_mapping(raw.get("panel_evidence_summary")) or _as_mapping(
        raw_inner.get("panel_evidence_summary")
    )
    alert_rule = (
        _as_mapping(raw.get("alert_rule"))
        or _as_mapping(pstatus.get("alert_rule"))
        or _as_mapping(raw_inner.get("alert_rule"))
    )

    native_id = _first_str(
        raw.get("playbook_alert_id"),
        raw.get("id"),
        raw_inner.get("playbook_alert_id"),
        raw_inner.get("id"),
        ignore_dash=False,
    )
    if not native_id:
        raise ValueError("Recorded Future Playbook alert payload missing required ID")

    eff_scope = _normalize_scope(scope)
    category = _first_str(raw.get("category"), pstatus.get("category"), raw_inner.get("category"))
    rule_name = _first_str(
        raw.get("rule_name"),
        alert_rule.get("label"),
        alert_rule.get("name"),
        pstatus.get("case_rule_label"),
        raw.get("rule_id"),
    )
    entity_name = _first_str(raw.get("entity_name"), pstatus.get("entity_name"))
    title = _first_str(raw.get("title"), raw_inner.get("title"), entity_name, rule_name, native_id)

    risk_score = raw.get("risk_score") if raw.get("risk_score") is not None else pstatus.get("risk_score")
    if isinstance(risk_score, bool):
        risk_score = None
    severity = _first_str(
        raw.get("priority"),
        pstatus.get("priority"),
        raw.get("severity"),
        f"risk:{risk_score}" if risk_score is not None and str(risk_score).strip() else "",
    )
    status = _first_str(raw.get("status"), pstatus.get("status"), raw_inner.get("status"))
    timestamp = _first_str(
        raw.get("updated"),
        pstatus.get("updated"),
        raw.get("created"),
        pstatus.get("created"),
        raw_inner.get("updated"),
        raw_inner.get("created"),
    )
    assignee = _first_str(raw.get("assignee"), pstatus.get("assignee_name"), pstatus.get("assignee"))
    targets = _bounded_str_list(raw.get("targets") or pstatus.get("targets") or ev.get("targets"))
    attackers = _bounded_str_list(raw.get("attackers") or pstatus.get("attackers"))
    actions_taken = _bounded_str_list(raw.get("actions_taken") or pstatus.get("actions_taken"))
    evidence_urls = _bounded_str_list(ev.get("url") if isinstance(ev.get("url"), list) else [ev.get("url")])
    brands = _bounded_str_list(ev.get("brands"))

    summary_parts: list[str] = []
    if category:
        summary_parts.append(f"Category: {category}")
    if entity_name:
        summary_parts.append(f"Entity: {entity_name}")
    if targets:
        summary_parts.append(f"Targets: {', '.join(targets[:5])}")
    if risk_score is not None and str(risk_score).strip():
        summary_parts.append(f"Risk Score: {risk_score}")
    summary = _redact_text(" | ".join(summary_parts))

    metadata = _sanitize_metadata(
        {
            "category": category,
            "rule_name": rule_name,
            "entity_name": entity_name,
            "risk_score": risk_score,
            "assignee": assignee,
            "targets": targets,
            "attackers": attackers,
            "actions_taken": actions_taken,
            "evidence_urls": evidence_urls,
            "brands": brands,
            "summary_note": _first_str(ev.get("summary"), raw.get("summary")),
        }
    )

    return UniqueEvent(
        event_key=make_event_key("rf_playbook", native_id, scope=eff_scope),
        source_kind="rf_playbook",
        native_id=native_id,
        scope=eff_scope,
        title=_redact_text(title),
        severity=_redact_text(severity),
        status=_redact_text(status),
        timestamp=_redact_text(timestamp),
        summary=summary,
        metadata=metadata,
    )


def _extract_s1_threat(raw: Mapping[str, Any], scope: str) -> UniqueEvent:
    raw_inner = _as_mapping(raw.get("raw"))
    tinfo = _as_mapping(raw.get("threatInfo")) or _as_mapping(raw_inner.get("threatInfo"))
    agent_rt = _as_mapping(raw.get("agentRealtimeInfo")) or _as_mapping(
        raw_inner.get("agentRealtimeInfo")
    )
    agent_det = _as_mapping(raw.get("agentDetectionInfo")) or _as_mapping(
        raw_inner.get("agentDetectionInfo")
    )
    proc = _as_mapping(raw.get("sourceProcessInfo")) or _as_mapping(
        raw_inner.get("sourceProcessInfo")
    )

    native_id = _first_str(
        raw.get("id"),
        tinfo.get("threatId"),
        raw_inner.get("id"),
        ignore_dash=False,
    )
    if not native_id:
        raise ValueError("SentinelOne threat payload missing required 'id'")

    eff_scope = _normalize_scope(scope)
    title = _first_str(
        raw.get("title"),
        tinfo.get("threatName"),
        raw.get("threatName"),
        raw_inner.get("threatName"),
        native_id,
    )
    severity = _first_str(
        raw.get("severity"),
        raw.get("confidenceLevel"),
        tinfo.get("confidenceLevel"),
        raw_inner.get("severity"),
    )
    status = _first_str(
        raw.get("incidentStatus"),
        tinfo.get("incidentStatus"),
        raw.get("status"),
        raw_inner.get("incidentStatus"),
    )
    timestamp = _first_str(
        raw.get("createdAt"),
        tinfo.get("createdAt"),
        raw.get("updatedAt"),
        tinfo.get("updatedAt"),
        raw_inner.get("createdAt"),
    )
    hostname = _first_str(
        raw.get("computerName"),
        agent_rt.get("agentComputerName"),
        agent_det.get("agentComputerName"),
        raw.get("agentComputerName"),
    )
    classification = _first_str(raw.get("classification"), tinfo.get("classification"))
    file_path = _first_str(raw.get("filePath"), tinfo.get("filePath"), proc.get("filePath"))
    command_line = _first_str(
        raw.get("commandLine"),
        proc.get("commandline"),
        proc.get("commandLine"),
        tinfo.get("originatorProcess"),
    )
    sha1 = _first_str(raw.get("sha1"), tinfo.get("sha1"), proc.get("fileHashSha1"))
    sha256 = _first_str(raw.get("sha256"), tinfo.get("sha256"), proc.get("fileHashSha256"))
    md5 = _first_str(raw.get("md5"), tinfo.get("md5"))
    username = _first_str(
        raw.get("username"),
        proc.get("user"),
        agent_rt.get("agentLastLoggedInUserName"),
        tinfo.get("processUser"),
    )
    site_id = _first_str(raw.get("siteId"), agent_rt.get("siteId"), agent_det.get("siteId"))
    site_name = _first_str(
        raw.get("siteName"), agent_rt.get("siteName"), agent_det.get("siteName")
    )
    account_id = _first_str(
        raw.get("accountId"), agent_rt.get("accountId"), agent_det.get("accountId")
    )
    tenant_id = _first_str(raw.get("tenantId"))

    indicators_raw = _as_list(raw.get("indicators")) or _as_list(raw_inner.get("indicators"))
    indicators: list[str] = []
    for ind in indicators_raw[:10]:
        if isinstance(ind, Mapping):
            label = _first_str(ind.get("description"), ind.get("category"), ind.get("tactics"))
        else:
            label = _first_str(ind)
        if label:
            indicators.append(label[:300])

    summary_parts = []
    if hostname:
        summary_parts.append(f"Host: {hostname}")
    if classification:
        summary_parts.append(f"Classification: {classification}")
    if file_path:
        summary_parts.append(f"File: {file_path}")
    summary = _redact_text(" | ".join(summary_parts))

    metadata = _sanitize_metadata(
        {
            "hostname": hostname,
            "classification": classification,
            "confidence_level": _first_str(raw.get("confidenceLevel"), tinfo.get("confidenceLevel")),
            "analyst_verdict": _first_str(raw.get("analystVerdict"), tinfo.get("analystVerdict")),
            "mitigation_status": _first_str(
                raw.get("mitigationStatus"), tinfo.get("mitigationStatus")
            ),
            "file_path": file_path,
            "command_line": command_line,
            "sha1": sha1,
            "sha256": sha256,
            "md5": md5,
            "username": username,
            "site_id": site_id,
            "site_name": site_name,
            "account_id": account_id,
            "tenant_id": tenant_id,
            "external_ip": _first_str(agent_det.get("externalIp"), agent_det.get("agentIpV4")),
            "indicators": indicators,
        }
    )

    return UniqueEvent(
        event_key=make_event_key("s1_threat", native_id, scope=eff_scope),
        source_kind="s1_threat",
        native_id=native_id,
        scope=eff_scope,
        title=_redact_text(title),
        severity=_redact_text(severity),
        status=_redact_text(status),
        timestamp=_redact_text(timestamp),
        summary=summary,
        metadata=metadata,
    )


def _extract_s1_cloud_alert(raw: Mapping[str, Any], scope: str) -> UniqueEvent:
    raw_inner = _as_mapping(raw.get("raw"))
    ainfo = _as_mapping(raw.get("alertInfo")) or _as_mapping(raw_inner.get("alertInfo"))
    rinfo = _as_mapping(raw.get("ruleInfo")) or _as_mapping(raw_inner.get("ruleInfo"))
    agent_rt = _as_mapping(raw.get("agentRealtimeInfo")) or _as_mapping(
        raw_inner.get("agentRealtimeInfo")
    )
    agent_det = _as_mapping(raw.get("agentDetectionInfo")) or _as_mapping(
        raw_inner.get("agentDetectionInfo")
    )
    proc = _as_mapping(raw.get("sourceProcessInfo")) or _as_mapping(
        raw_inner.get("sourceProcessInfo")
    )
    k8s = _as_mapping(raw.get("kubernetesInfo")) or _as_mapping(raw_inner.get("kubernetesInfo"))
    container = _as_mapping(raw.get("containerInfo")) or _as_mapping(raw_inner.get("containerInfo"))

    native_id = _first_str(
        raw.get("id"),
        ainfo.get("alertId"),
        raw_inner.get("id"),
        ignore_dash=False,
    )
    if not native_id:
        raise ValueError("SentinelOne cloud alert payload missing required 'id'")

    eff_scope = _normalize_scope(scope)
    rule_name = _first_str(rinfo.get("name"), raw.get("ruleName"))
    title = _first_str(
        raw.get("title"),
        rule_name,
        ainfo.get("alertName"),
        raw.get("threatName"),
        native_id,
    )
    severity = _first_str(
        raw.get("severity"),
        rinfo.get("severity"),
        raw.get("confidenceLevel"),
    )
    status = _first_str(
        raw.get("incidentStatus"),
        ainfo.get("incidentStatus"),
        raw.get("status"),
    )
    timestamp = _first_str(
        raw.get("createdAt"),
        ainfo.get("createdAt"),
        ainfo.get("reportedAt"),
        raw.get("updatedAt"),
    )
    hostname = _first_str(
        raw.get("computerName"),
        agent_det.get("agentComputerName"),
        agent_rt.get("agentComputerName"),
        raw.get("agentComputerName"),
    )
    rule_description = _first_str(rinfo.get("description"), raw.get("description"))

    summary_parts = []
    if hostname:
        summary_parts.append(f"Host: {hostname}")
    if rule_description:
        summary_parts.append(rule_description)
    summary = _redact_text(" | ".join(summary_parts))

    metadata = _sanitize_metadata(
        {
            "rule_name": rule_name,
            "rule_description": rule_description,
            "hostname": hostname,
            "analyst_verdict": _first_str(raw.get("analystVerdict"), ainfo.get("analystVerdict")),
            "file_path": _first_str(raw.get("filePath"), proc.get("filePath")),
            "command_line": _first_str(
                raw.get("commandLine"), proc.get("commandline"), proc.get("commandLine")
            ),
            "sha1": _first_str(raw.get("sha1"), proc.get("fileHashSha1")),
            "sha256": _first_str(raw.get("sha256"), proc.get("fileHashSha256")),
            "username": _first_str(
                raw.get("username"), proc.get("user"), agent_rt.get("agentLastLoggedInUserName")
            ),
            "site_id": _first_str(raw.get("siteId"), agent_det.get("siteId"), agent_rt.get("siteId")),
            "site_name": _first_str(
                raw.get("siteName"), agent_det.get("siteName"), agent_rt.get("siteName")
            ),
            "account_id": _first_str(
                raw.get("accountId"), agent_det.get("accountId"), agent_rt.get("accountId")
            ),
            "tenant_id": _first_str(raw.get("tenantId")),
            "kubernetes": k8s if k8s else None,
            "container": container if container else None,
        }
    )

    return UniqueEvent(
        event_key=make_event_key("s1_cloud_alert", native_id, scope=eff_scope),
        source_kind="s1_cloud_alert",
        native_id=native_id,
        scope=eff_scope,
        title=_redact_text(title),
        severity=_redact_text(severity),
        status=_redact_text(status),
        timestamp=_redact_text(timestamp),
        summary=summary,
        metadata=metadata,
    )


def _resolve_splunk_es_scope(
    raw: Mapping[str, Any],
    raw_inner: Mapping[str, Any],
    explicit_scope: str,
) -> str:
    norm_explicit = _normalize_scope(explicit_scope)
    if norm_explicit != "default":
        return norm_explicit

    extracted = extract_finding_tenant(raw)
    norm_extracted = _normalize_scope(extracted)
    if norm_extracted != "default":
        return norm_extracted

    # Handle UI display rows where top-level tenant_id was replaced with "-"
    for key in ("tenant_id", "org_id", "client_code", "customer_id"):
        for container in (raw, _as_mapping(raw.get("custom_fields")), raw_inner):
            for rec_k, rec_v in container.items():
                if isinstance(rec_k, str) and rec_k.casefold() == key:
                    candidate = _normalize_scope(rec_v)
                    if candidate != "default":
                        return candidate

    if raw_inner:
        inner_extracted = _normalize_scope(extract_finding_tenant(raw_inner))
        if inner_extracted != "default":
            return inner_extracted

    return "default"


def _extract_splunk_es(raw: Mapping[str, Any], scope: str) -> UniqueEvent:
    raw_inner = _as_mapping(raw.get("raw"))
    native_id = _first_str(
        raw.get("event_id"),
        raw.get("finding_id"),
        raw.get("investigation_guid"),
        raw.get("investigation_id"),
        raw.get("rule_id"),
        raw.get("id"),
        raw_inner.get("event_id"),
        raw_inner.get("finding_id"),
        raw_inner.get("investigation_guid"),
        raw_inner.get("investigation_id"),
        raw_inner.get("rule_id"),
        raw_inner.get("id"),
        ignore_dash=False,
    )
    if not native_id:
        raise ValueError("Splunk ES payload missing required event/finding/investigation ID")

    eff_scope = _resolve_splunk_es_scope(raw, raw_inner, scope)
    rule_name = _first_str(raw.get("rule_name"), raw.get("search_name"), raw_inner.get("rule_name"))
    title = _first_str(
        raw.get("rule_title"),
        raw.get("title"),
        rule_name,
        raw.get("name"),
        raw_inner.get("rule_title"),
        native_id,
    )
    severity = _first_str(
        raw.get("urgency"),
        raw.get("severity"),
        raw_inner.get("urgency"),
        raw_inner.get("severity"),
    )
    status = _first_str(
        raw.get("status_label"),
        raw.get("status_name"),
        raw.get("status"),
        raw_inner.get("status_label"),
        raw_inner.get("status"),
    )
    timestamp = _first_str(
        raw.get("_time"),
        raw.get("update_time"),
        raw.get("create_time"),
        raw.get("orig_time"),
        raw_inner.get("_time"),
    )
    rule_description = _first_str(
        raw.get("rule_description"),
        raw.get("orig_rule_description"),
        raw.get("description"),
        raw_inner.get("rule_description"),
    )
    risk_object = _first_str(raw.get("risk_object"), raw.get("normalized_risk_object"))
    src = _first_str(raw.get("src"), raw.get("src_ip"))
    dest = _first_str(raw.get("dest"), raw.get("dest_ip"))
    user = _first_str(raw.get("user"), raw.get("src_user"))
    entity = _first_str(raw.get("entity"), risk_object, src, dest, user)

    summary_parts = []
    if rule_description:
        summary_parts.append(rule_description)
    if entity:
        summary_parts.append(f"Entity: {entity}")
    summary = _redact_text(" | ".join(summary_parts))

    custom_fields_raw = raw.get("custom_fields")
    custom_fields = (
        _sanitize_metadata(custom_fields_raw) if isinstance(custom_fields_raw, Mapping) else None
    )

    metadata = _sanitize_metadata(
        {
            "tenant_id": eff_scope if eff_scope != "default" else _first_str(raw.get("tenant_id")),
            "rule_name": rule_name,
            "rule_description": rule_description,
            "security_domain": _first_str(
                raw.get("security_domain"), raw.get("orig_security_domain")
            ),
            "risk_object": risk_object,
            "risk_object_type": _first_str(raw.get("risk_object_type")),
            "risk_score": _first_str(raw.get("risk_score")),
            "src": src,
            "dest": dest,
            "user": user,
            "entity": entity,
            "owner": _first_str(raw.get("owner")),
            "disposition": _first_str(raw.get("disposition_label"), raw.get("disposition")),
            "notable_type": _first_str(raw.get("notable_type")),
            "item_type": _first_str(raw.get("item_type")),
            "orig_sid": _first_str(raw.get("orig_sid")),
            "orig_rid": _first_str(raw.get("orig_rid")),
            "custom_fields": custom_fields,
        }
    )

    return UniqueEvent(
        event_key=make_event_key("splunk_es", native_id, scope=eff_scope),
        source_kind="splunk_es",
        native_id=native_id,
        scope=eff_scope,
        title=_redact_text(title),
        severity=_redact_text(severity),
        status=_redact_text(status),
        timestamp=_redact_text(timestamp),
        summary=summary,
        metadata=metadata,
    )


def normalize_unique_event(
    source_kind: EventSourceKind,
    raw: Mapping[str, Any],
    scope: str = "default",
) -> UniqueEvent:
    """Normalize a raw or pre-normalized SOC event dict into a canonical ``UniqueEvent``."""
    if not isinstance(source_kind, str) or source_kind not in VALID_EVENT_SOURCE_KINDS:
        raise ValueError(f"Unsupported event source kind: {source_kind!r}")
    if not isinstance(raw, Mapping):
        raise TypeError(f"raw event payload must be a Mapping, got {type(raw).__name__}")

    if source_kind == "rf_alert":
        return _extract_rf_alert(raw, scope)
    if source_kind == "rf_playbook":
        return _extract_rf_playbook(raw, scope)
    if source_kind == "s1_threat":
        return _extract_s1_threat(raw, scope)
    if source_kind == "s1_cloud_alert":
        return _extract_s1_cloud_alert(raw, scope)
    return _extract_splunk_es(raw, scope)


@dataclass(frozen=True)
class EventAIPanelEntry:
    """One persisted AI response / investigation panel attached to a ``UniqueEvent``."""

    entry_id: str
    run_id: str
    timestamp: str
    mode: InvestigationMode
    provider: str
    model: str
    question: str
    answer_markdown: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    blocked_actions: list[dict[str, Any]] = field(default_factory=list)
    status: str = "completed"
    auto_triggered: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize entry into a redacted JSON-friendly dictionary."""
        sanitized_tools = _sanitize_list_of_mappings(self.tool_calls)
        sanitized_blocked = _sanitize_list_of_mappings(self.blocked_actions)
        return {
            "entry_id": self.entry_id,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "mode": self.mode,
            "provider": _redact_text(self.provider),
            "model": _redact_text(self.model),
            "question": _redact_text(self.question),
            "answer_markdown": _redact_text(self.answer_markdown),
            "tool_calls": sanitized_tools,
            "blocked_actions": sanitized_blocked,
            "status": self.status,
            "auto_triggered": bool(self.auto_triggered),
            "error": _redact_text(self.error),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> EventAIPanelEntry | None:
        """Reconstruct an ``EventAIPanelEntry`` from JSON, returning ``None`` if invalid."""
        if not isinstance(raw, Mapping):
            return None

        mode_raw = raw.get("mode")
        if not isinstance(mode_raw, str) or mode_raw not in VALID_INVESTIGATION_MODES:
            return None
        mode = cast(InvestigationMode, mode_raw)

        run_id = _first_str(raw.get("run_id"), ignore_dash=False)
        if not run_id:
            return None

        entry_id = _first_str(raw.get("entry_id"), ignore_dash=False) or uuid.uuid4().hex[:16]
        timestamp = _first_str(raw.get("timestamp"), ignore_dash=False) or _utc_now_iso()

        tool_calls_raw = raw.get("tool_calls")
        tool_calls = _sanitize_list_of_mappings(
            tool_calls_raw if isinstance(tool_calls_raw, list) else []
        )

        blocked_raw = raw.get("blocked_actions")
        blocked_actions = _sanitize_list_of_mappings(
            blocked_raw if isinstance(blocked_raw, list) else []
        )

        return cls(
            entry_id=entry_id,
            run_id=run_id,
            timestamp=timestamp,
            mode=mode,
            provider=_redact_text(_first_str(raw.get("provider"), ignore_dash=False)),
            model=_redact_text(_first_str(raw.get("model"), ignore_dash=False)),
            question=_redact_text(str(raw.get("question") or "")),
            answer_markdown=_redact_text(str(raw.get("answer_markdown") or "")),
            tool_calls=tool_calls,
            blocked_actions=blocked_actions,
            status=_first_str(raw.get("status"), ignore_dash=False) or "completed",
            auto_triggered=bool(raw.get("auto_triggered", False)),
            error=_redact_text(str(raw.get("error") or "")),
        )


def _sanitize_list_of_mappings(items: Sequence[Any]) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        redacted = redact_sensitive_data(dict(item))
        if isinstance(redacted, Mapping):
            sanitized.append(dict(redacted))
    return sanitized


_STORE_LOCKS_GUARD = threading.Lock()
_STORE_LOCKS: dict[Path, threading.RLock] = {}


def _resolve_store_path(path: Path) -> Path:
    expanded = path.expanduser()
    try:
        return expanded.resolve()
    except OSError:
        try:
            return Path(os.path.abspath(os.fspath(expanded)))
        except OSError:
            return expanded.absolute()


def _get_store_lock(path: Path) -> threading.RLock:
    resolved = _resolve_store_path(path)
    with _STORE_LOCKS_GUARD:
        lock = _STORE_LOCKS.get(resolved)
        if lock is None:
            lock = threading.RLock()
            _STORE_LOCKS[resolved] = lock
        return lock


def _atomic_write_text(path: Path, text: str, *, prefix: str) -> None:
    target = _resolve_store_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=prefix,
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            fh.flush()
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


class EventAIStore:
    """Thread-safe, atomically persisted store for unique events and attached AI panels."""

    def __init__(self, path: Path | str | None = None) -> None:
        if path is not None:
            self._path = _resolve_store_path(Path(path))
        else:
            self._path = _resolve_store_path(
                get_workspace_dir() / ".soclens_cache" / "event_ai_panels.json"
            )
        self._lock = _get_store_lock(self._path)
        self._events: dict[str, UniqueEvent] = {}
        self._panels: dict[str, list[EventAIPanelEntry]] = {}
        self._last_digest: bytes | None = None
        with self._lock:
            self._reload_if_needed_locked(force=True)

    @property
    def path(self) -> Path:
        return self._path

    def rebind_path(self, path: Path | str) -> None:
        """Thread-safely rebind this event store to a new JSON file path and reload."""
        new_path = _resolve_store_path(Path(path))
        new_lock = _get_store_lock(new_path)
        old_lock = self._lock
        if old_lock is new_lock:
            with old_lock:
                self._path = new_path
                self._last_digest = None
                self._reload_if_needed_locked(force=True)
            return
        first_lock, second_lock = (
            (old_lock, new_lock) if id(old_lock) < id(new_lock) else (new_lock, old_lock)
        )
        with first_lock:
            with second_lock:
                self._path = new_path
                self._lock = new_lock
                self._events = {}
                self._panels = {}
                self._last_digest = None
                self._reload_if_needed_locked(force=True)

    def _reload_if_needed_locked(self, *, force: bool = False) -> None:
        try:
            raw_bytes = self._path.read_bytes()
        except OSError:
            self._events = {}
            self._panels = {}
            self._last_digest = None
            return

        digest = hashlib.sha256(raw_bytes).digest()
        if not force and self._last_digest == digest:
            return

        try:
            raw_text = raw_bytes.decode("utf-8")
            if not raw_text.strip():
                self._events = {}
                self._panels = {}
                self._last_digest = digest
                return
            payload = json.loads(raw_text)
        except ValueError as exc:
            logger.warning(
                "Failed to load event AI panels from %s (%s); recovering with empty store.",
                self._path,
                exc,
            )
            self._events = {}
            self._panels = {}
            self._last_digest = digest
            return

        if not isinstance(payload, Mapping):
            logger.warning(
                "Event AI panels file %s contained non-mapping payload (%s); resetting.",
                self._path,
                type(payload).__name__,
            )
            self._events = {}
            self._panels = {}
            self._last_digest = digest
            return

        events_raw = payload.get("events")
        new_events: dict[str, UniqueEvent] = {}
        new_panels: dict[str, list[EventAIPanelEntry]] = {}
        if isinstance(events_raw, Mapping):
            for rec in events_raw.values():
                if not isinstance(rec, Mapping):
                    continue
                ev_candidate = rec.get("event")
                ev_raw: Mapping[str, Any] = (
                    ev_candidate if isinstance(ev_candidate, Mapping) else rec
                )
                ev = UniqueEvent.from_dict(ev_raw)
                if ev is None:
                    continue
                panels_raw = rec.get("panels")
                panels: list[EventAIPanelEntry] = []
                if isinstance(panels_raw, list):
                    for p_raw in panels_raw:
                        if isinstance(p_raw, Mapping):
                            entry = EventAIPanelEntry.from_dict(p_raw)
                            if entry is not None:
                                panels.append(entry)
                new_events[ev.event_key] = ev
                new_panels[ev.event_key] = panels

        self._events = new_events
        self._panels = new_panels
        self._last_digest = digest

    def _save_locked(self) -> None:
        payload = {
            "version": 1,
            "events": {
                key: {
                    "event": ev.to_dict(),
                    "panels": [p.to_dict() for p in self._panels.get(key, [])],
                }
                for key, ev in self._events.items()
            },
        }
        serialized = json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n"
        _atomic_write_text(self._path, serialized, prefix=".event_ai_panels.")
        self._last_digest = hashlib.sha256(serialized.encode("utf-8")).digest()

    @staticmethod
    def _sanitize_event(event: UniqueEvent) -> UniqueEvent:
        return UniqueEvent(
            event_key=event.event_key,
            source_kind=event.source_kind,
            native_id=event.native_id,
            scope=_normalize_scope(event.scope),
            title=_redact_text(event.title),
            severity=_redact_text(event.severity),
            status=_redact_text(event.status),
            timestamp=_redact_text(event.timestamp),
            summary=_redact_text(event.summary),
            metadata=_sanitize_metadata(event.metadata),
        )

    def upsert_event(self, event: UniqueEvent) -> bool:
        """Record a unique event if unseen. Returns ``True`` if newly seen, else ``False``."""
        sanitized = self._sanitize_event(event)
        with self._lock:
            self._reload_if_needed_locked()
            is_new = sanitized.event_key not in self._events
            self._events[sanitized.event_key] = sanitized
            self._panels.setdefault(sanitized.event_key, [])
            if is_new:
                self._save_locked()
            return is_new

    def mark_seen_batch(self, events: Sequence[UniqueEvent]) -> list[UniqueEvent]:
        """Deduplicate ``events`` in-batch and against persisted state; return newly seen only."""
        if not events:
            return []
        with self._lock:
            self._reload_if_needed_locked()
            newly_seen: list[UniqueEvent] = []
            seen_in_batch: set[str] = set()
            for raw_ev in events:
                ev = self._sanitize_event(raw_ev)
                if ev.event_key in seen_in_batch:
                    continue
                seen_in_batch.add(ev.event_key)
                if ev.event_key in self._events:
                    continue
                self._events[ev.event_key] = ev
                self._panels.setdefault(ev.event_key, [])
                newly_seen.append(ev)
            if newly_seen:
                self._save_locked()
            return newly_seen

    def attach_ai_response(
        self,
        event: UniqueEvent,
        result: InvestigationResult,
        *,
        auto_triggered: bool = False,
    ) -> EventAIPanelEntry:
        """Attach an ``InvestigationResult`` panel to ``event`` and persist atomically."""
        sanitized_event = self._sanitize_event(event)
        entry = EventAIPanelEntry(
            entry_id=uuid.uuid4().hex[:16],
            run_id=str(result.run_id or uuid.uuid4().hex[:16]),
            timestamp=str(result.timestamp or _utc_now_iso()),
            mode=result.mode,
            provider=_redact_text(str(result.provider or "")),
            model=_redact_text(str(result.model or "")),
            question=_redact_text(str(result.question or "")),
            answer_markdown=_redact_text(str(result.answer_markdown or "")),
            tool_calls=_sanitize_list_of_mappings(result.tool_calls or []),
            blocked_actions=_sanitize_list_of_mappings(result.blocked_actions or []),
            status=str(result.status or "completed"),
            auto_triggered=bool(auto_triggered),
            error=_redact_text(str(result.error or "")),
        )
        with self._lock:
            self._reload_if_needed_locked()
            self._events[sanitized_event.event_key] = sanitized_event
            panel_list = self._panels.setdefault(sanitized_event.event_key, [])
            panel_list.append(entry)
            self._save_locked()
        return entry

    def get_panels(self, event_key: str) -> list[EventAIPanelEntry]:
        """Return all persisted AI panels for ``event_key`` in chronological order."""
        with self._lock:
            self._reload_if_needed_locked()
            return list(self._panels.get(event_key, []))

    def has_investigation(self, event_key: str) -> bool:
        """Return ``True`` if at least one AI panel is attached to ``event_key``."""
        with self._lock:
            self._reload_if_needed_locked()
            return bool(self._panels.get(event_key))

    def query_investigated_keys(self) -> list[str]:
        """Return all event keys that currently have one or more attached AI panels."""
        with self._lock:
            self._reload_if_needed_locked()
            return [key for key, panels in self._panels.items() if panels]

    def is_seen(self, event_key: str) -> bool:
        """Return ``True`` if ``event_key`` has already been tracked/seen."""
        with self._lock:
            self._reload_if_needed_locked()
            return event_key in self._events

    def get_event(self, event_key: str) -> UniqueEvent | None:
        """Return the stored ``UniqueEvent`` for ``event_key``, or ``None``."""
        with self._lock:
            self._reload_if_needed_locked()
            return self._events.get(event_key)

    def list_events(self, *, investigated_only: bool = False) -> list[UniqueEvent]:
        """List stored unique events, optionally filtered to those with AI panels."""
        with self._lock:
            self._reload_if_needed_locked()
            if not investigated_only:
                return list(self._events.values())
            return [
                ev
                for key, ev in self._events.items()
                if self._panels.get(key)
            ]

    def unmark_seen(self, event_key: str) -> bool:
        """Remove ``event_key`` from seen tracking only if it has no attached AI panels."""
        if not event_key:
            return False
        with self._lock:
            self._reload_if_needed_locked()
            if event_key not in self._events:
                return False
            if self._panels.get(event_key):
                return False
            self._events.pop(event_key, None)
            self._panels.pop(event_key, None)
            self._save_locked()
            return True

    def clear(self, event_key: str | None = None) -> None:
        """Clear a single event or the entire store and persist atomically."""
        with self._lock:
            self._reload_if_needed_locked()
            if event_key is None:
                self._events.clear()
                self._panels.clear()
                self._save_locked()
                return
            existed = event_key in self._events or event_key in self._panels
            self._events.pop(event_key, None)
            self._panels.pop(event_key, None)
            if existed:
                self._save_locked()


def normalize_cache_batch(
    cache_source: str,
    items: Sequence[Mapping[str, Any]],
    *,
    scope: str = "default",
) -> list[UniqueEvent]:
    """Normalize ``AlertCacheStore`` records for ``cache_source`` into ``UniqueEvent``s."""
    base_kind = CACHE_SOURCE_TO_EVENT_KIND.get(cache_source)
    if base_kind is None:
        return []

    normalized: list[UniqueEvent] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        eff_kind: EventSourceKind = (
            infer_s1_source_kind(item) if cache_source == "s1_threats_24h" else base_kind
        )
        item_scope = scope
        if eff_kind == "splunk_es" and _normalize_scope(scope) == "default":
            candidate = _normalize_scope(item.get("tenant_id"))
            if candidate != "default":
                item_scope = candidate
        try:
            normalized.append(normalize_unique_event(eff_kind, item, scope=item_scope))
        except (TypeError, ValueError) as exc:
            logger.debug("Skipping un-normalizable %s item: %s", cache_source, exc)
    return normalized


class BackgroundTriageQueue:
    """Thread-safe async worker queue for policy-gated background SOC triage."""

    def __init__(
        self,
        orchestrator: Any,
        policy_store: AIPolicyStore,
        event_store: EventAIStore,
        on_complete: Callable[[UniqueEvent, InvestigationResult], None] | None = None,
        question: str = DEFAULT_BACKGROUND_TRIAGE_QUESTION,
        provider: str | None = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._policy_store = policy_store
        self._event_store = event_store
        self._on_complete = on_complete
        self._question = question
        self._provider = provider

        self._cond = threading.Condition()
        self._enqueue_lock = threading.Lock()
        self._pending: deque[UniqueEvent] = deque()
        self._pending_keys: set[str] = set()
        self._in_progress_key: str | None = None
        self._in_progress_gen: int | None = None
        self._stopped = False
        self._stop_event = threading.Event()
        self._generation = 0
        self._worker: threading.Thread | None = None
        self._active_workers: list[threading.Thread] = []

    def start(self) -> None:
        """Start the background triage worker thread (idempotent)."""
        with self._cond:
            if self._worker is not None and self._worker.is_alive() and not self._stopped:
                return
            prev_workers = [w for w in self._active_workers if w.is_alive()]
            self._generation += 1
            generation = self._generation
            stop_event = threading.Event()
            self._stopped = False
            self._stop_event = stop_event
            worker = threading.Thread(
                target=self._worker_loop,
                args=(generation, stop_event, prev_workers),
                name=f"soclens-bg-triage-{generation}",
                daemon=True,
            )
            self._worker = worker
            self._active_workers = [*prev_workers, worker]
            worker.start()
            if self._pending:
                self._cond.notify_all()

    def _safe_unmark_seen(self, event_key: str) -> None:
        try:
            self._event_store.unmark_seen(event_key)
        except Exception:
            logger.exception("Failed to unmark seen event %s", event_key)

    def enqueue_batch(self, events: Sequence[UniqueEvent]) -> list[UniqueEvent]:
        """Queue newly flowing events when background triage is enabled; non-blocking."""
        if not events:
            return []
        with self._cond:
            if self._stopped:
                return []

        policy = self._policy_store.load()
        if policy.ai_kill_switch_active or not policy.background_triage_enabled:
            return []

        with self._enqueue_lock:
            policy = self._policy_store.load()
            if policy.ai_kill_switch_active or not policy.background_triage_enabled:
                return []
            unseen = self._event_store.mark_seen_batch(events)
            if not unseen:
                return []

            eligible = [
                ev for ev in unseen if not self._event_store.has_investigation(ev.event_key)
            ]
            if not eligible:
                return []

            queued: list[UniqueEvent] = []
            stopped_during_enqueue = False
            with self._cond:
                if self._stopped:
                    stopped_during_enqueue = True
                else:
                    for ev in eligible:
                        in_progress_same = (
                            ev.event_key == self._in_progress_key
                            and self._in_progress_gen == self._generation
                        )
                        if ev.event_key in self._pending_keys or in_progress_same:
                            continue
                        self._pending.append(ev)
                        self._pending_keys.add(ev.event_key)
                        queued.append(ev)
                    if queued:
                        self._cond.notify_all()
            if stopped_during_enqueue:
                for ev in eligible:
                    self._safe_unmark_seen(ev.event_key)
                return []
            return queued

    def enqueue_raw_batch(
        self,
        source_kind: EventSourceKind,
        items: Sequence[Mapping[str, Any]],
        *,
        scope: str = "default",
    ) -> list[UniqueEvent]:
        """Normalize raw payloads for ``source_kind`` and submit via ``enqueue_batch``."""
        if source_kind not in VALID_EVENT_SOURCE_KINDS:
            return []
        normalized: list[UniqueEvent] = []
        for item in items:
            if not isinstance(item, Mapping):
                continue
            try:
                normalized.append(normalize_unique_event(source_kind, item, scope=scope))
            except (TypeError, ValueError) as exc:
                logger.debug("Skipping malformed %s item in enqueue_raw_batch: %s", source_kind, exc)
        return self.enqueue_batch(normalized)

    def enqueue_cache_batch(
        self,
        cache_source: str,
        items: Sequence[Mapping[str, Any]],
        *,
        scope: str = "default",
    ) -> list[UniqueEvent]:
        """Normalize ``AlertCacheStore`` items for ``cache_source`` and submit to queue."""
        normalized = normalize_cache_batch(cache_source, items, scope=scope)
        return self.enqueue_batch(normalized)

    def pending_count(self) -> int:
        """Return count of queued + in-progress triage events."""
        with self._cond:
            return len(self._pending) + (1 if self._in_progress_key is not None else 0)

    def wait_idle(self, timeout: float | None = None) -> bool:
        """Block until the queue is empty and no event is currently in progress."""
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        with self._cond:
            current = threading.current_thread()
            if current is self._worker or current in self._active_workers:
                return False
            while self._pending or self._in_progress_key is not None:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self._cond.wait(timeout=remaining)
                else:
                    self._cond.wait()
            return True

    def halt_and_drain(self, timeout: float = 0.2) -> int:
        """Immediately halt active background triage and clear pending queued events."""
        count = self.pending_count()
        self.stop(timeout=timeout)
        return count

    def stop(self, timeout: float = 5.0) -> None:
        """Signal shutdown, clear pending items, and wait up to ``timeout`` seconds."""
        with self._cond:
            self._stop_event.set()
            self._stopped = True
            cleared_events = list(self._pending)
            self._pending.clear()
            self._pending_keys.clear()
            self._cond.notify_all()
            worker = self._worker

        for ev in cleared_events:
            self._safe_unmark_seen(ev.event_key)

        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=max(0.0, timeout))

        with self._cond:
            self._active_workers = [w for w in self._active_workers if w.is_alive()]
            if self._worker is worker and (worker is None or not worker.is_alive()):
                self._worker = None
            self._cond.notify_all()

    def _worker_loop(
        self,
        generation: int,
        stop_event: threading.Event,
        prev_workers: Sequence[threading.Thread] = (),
    ) -> None:
        try:
            for prev in prev_workers:
                if prev is threading.current_thread():
                    continue
                while prev.is_alive():
                    if stop_event.is_set():
                        return
                    with self._cond:
                        if self._generation != generation:
                            return
                    prev.join(timeout=0.05)

            while True:
                with self._cond:
                    while (
                        not self._pending
                        and not stop_event.is_set()
                        and self._generation == generation
                    ):
                        self._cond.wait()
                    if stop_event.is_set() or self._generation != generation:
                        return
                    event = self._pending.popleft()
                    self._pending_keys.discard(event.event_key)
                    self._in_progress_key = event.event_key
                    self._in_progress_gen = generation

                try:
                    with self._cond:
                        stale_gen = self._generation != generation
                    if stop_event.is_set() or stale_gen:
                        self._safe_unmark_seen(event.event_key)
                        return
                    policy = self._policy_store.load()
                    if policy.ai_kill_switch_active or not policy.background_triage_enabled:
                        self._safe_unmark_seen(event.event_key)
                        continue

                    try:
                        result = self._orchestrator.investigate(
                            event_key=event.event_key,
                            event_context=event.to_llm_context(),
                            mode="full_investigation",
                            question=self._question,
                            provider=self._provider,
                            stop_event=stop_event,
                            auto_triggered=True,
                        )
                    except Exception as exc:
                        logger.exception("Background triage failed for %s", event.event_key)
                        result = InvestigationResult(
                            run_id=uuid.uuid4().hex,
                            event_key=event.event_key,
                            mode="full_investigation",
                            provider=self._provider or "unknown",
                            model="",
                            question=self._question,
                            answer_markdown="",
                            tool_calls=[],
                            blocked_actions=[],
                            status="error",
                            error=str(exc),
                            timestamp=_utc_now_iso(),
                        )

                    if result.status != "cancelled" and not stop_event.is_set():
                        try:
                            self._event_store.attach_ai_response(event, result, auto_triggered=True)
                        except Exception:
                            logger.exception(
                                "Failed to persist background triage response for %s",
                                event.event_key,
                            )

                        if self._on_complete is not None:
                            try:
                                self._on_complete(event, result)
                            except Exception:
                                logger.exception(
                                    "Background triage on_complete callback failed for %s",
                                    event.event_key,
                                )
                    else:
                        self._safe_unmark_seen(event.event_key)
                finally:
                    with self._cond:
                        if self._in_progress_gen == generation:
                            self._in_progress_key = None
                            self._in_progress_gen = None
                        self._cond.notify_all()
        finally:
            with self._cond:
                current = threading.current_thread()
                self._active_workers = [
                    w for w in self._active_workers if w is not current and w.is_alive()
                ]
                if self._worker is current and (
                    stop_event.is_set() or self._generation != generation
                ):
                    self._worker = None
                self._cond.notify_all()


__all__ = [
    "BackgroundTriageQueue",
    "CACHE_SOURCE_TO_EVENT_KIND",
    "DEFAULT_BACKGROUND_TRIAGE_QUESTION",
    "EventAIPanelEntry",
    "EventAIStore",
    "EventSourceKind",
    "UniqueEvent",
    "VALID_EVENT_SOURCE_KINDS",
    "infer_s1_source_kind",
    "make_event_key",
    "normalize_cache_batch",
    "normalize_unique_event",
]
