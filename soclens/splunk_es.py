"""Splunk Enterprise Security (ES) REST API, Mission Control v2, and SPL client."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Self
from urllib.parse import quote

import requests

from soclens.config import SplunkESTenantConfig, get_splunk_es_tenant_settings
from soclens.settings import get_effective_setting, save_profile_settings
from soclens.splunk import (
    SplunkClient,
    _extract_splunk_message_list,
    _extract_splunk_messages,
    _safe_bool,
)

logger = logging.getLogger("soclens.splunk_es")

SPLUNK_ES_APP = "SplunkEnterpriseSecuritySuite"
SPLUNK_TI_APP = "DA-ESS-ThreatIntelligence"
MC_V2_BASE_PATH = "/servicesNS/nobody/missioncontrol/public/v2"

NOTABLE_STATUS_MAP: dict[str, int] = {
    "new": 1,
    "in_progress": 2,
    "pending": 3,
    "resolved": 4,
    "closed": 5,
}

NOTABLE_STATUS_LABELS: dict[int, str] = {
    1: "New",
    2: "In Progress",
    3: "Pending",
    4: "Resolved",
    5: "Closed",
}

NOTABLE_URGENCIES: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
)

NOTABLE_DISPOSITIONS: tuple[tuple[str, str], ...] = (
    ("True Positive", "true_positive"),
    ("Benign Positive", "benign_positive"),
    ("False Positive", "false_positive"),
    ("Undetermined", "undetermined"),
)

MC_FINDING_STATUSES: tuple[str, ...] = (
    "New",
    "In Progress",
    "Pending",
    "Resolved",
    "Closed",
    "Unassigned",
)

MC_DISPOSITIONS: tuple[tuple[str, str], ...] = (
    ("Undetermined", "disposition:6"),
    ("True Positive - Suspicious Activity", "disposition:1"),
    ("Benign Positive - Suspicious But Expected", "disposition:2"),
    ("False Positive - Incorrect Analytic Logic", "disposition:3"),
    ("False Positive - Inaccurate Data", "disposition:4"),
    ("Other", "disposition:5"),
    ("Unassigned", "Unassigned"),
)

_LEGACY_TO_MC_DISPOSITION: dict[str, str] = {
    "true_positive": "disposition:1",
    "true positive": "disposition:1",
    "true positive - suspicious activity": "disposition:1",
    "disposition:1": "disposition:1",
    "benign_positive": "disposition:2",
    "benign positive": "disposition:2",
    "benign positive - suspicious but expected": "disposition:2",
    "disposition:2": "disposition:2",
    "false_positive": "disposition:3",
    "false positive": "disposition:3",
    "false positive - incorrect analytic logic": "disposition:3",
    "disposition:3": "disposition:3",
    "false positive - inaccurate data": "disposition:4",
    "disposition:4": "disposition:4",
    "other": "disposition:5",
    "disposition:5": "disposition:5",
    "undetermined": "disposition:6",
    "disposition:6": "disposition:6",
    "unassigned": "Unassigned",
}

_MC_TO_LEGACY_DISPOSITION: dict[str, str] = {
    "disposition:1": "true_positive",
    "true positive - suspicious activity": "true_positive",
    "true_positive": "true_positive",
    "disposition:2": "benign_positive",
    "benign positive - suspicious but expected": "benign_positive",
    "benign_positive": "benign_positive",
    "disposition:3": "false_positive",
    "false positive - incorrect analytic logic": "false_positive",
    "disposition:4": "false_positive",
    "false positive - inaccurate data": "false_positive",
    "false_positive": "false_positive",
    "disposition:5": "undetermined",
    "other": "undetermined",
    "disposition:6": "undetermined",
    "undetermined": "undetermined",
}

_DISPOSITION_LABELS: dict[str, str] = {
    "disposition:1": "True Positive - Suspicious Activity",
    "true_positive": "True Positive - Suspicious Activity",
    "disposition:2": "Benign Positive - Suspicious But Expected",
    "benign_positive": "Benign Positive - Suspicious But Expected",
    "disposition:3": "False Positive - Incorrect Analytic Logic",
    "false_positive": "False Positive - Incorrect Analytic Logic",
    "disposition:4": "False Positive - Inaccurate Data",
    "disposition:5": "Other",
    "disposition:6": "Undetermined",
    "undetermined": "Undetermined",
    "unassigned": "Unassigned",
}

MC_VALID_FINDINGS_QUERY_PARAMS: frozenset[str] = frozenset(
    {
        "finding_ids",
        "urgency",
        "status",
        "owner",
        "disposition",
        "limit",
        "offset",
        "sort",
        "fields",
        "earliest",
        "latest",
        "rule_title",
        "search_format",
        "search_finding_groups",
    }
)

MC_RISK_ENTITY_TYPES: tuple[str, ...] = (
    "user",
    "system",
    "hash_values",
    "host_artifacts",
    "tools",
    "others",
)

THREAT_INTEL_COLLECTIONS: tuple[str, ...] = (
    "ip_intel",
    "domain_intel",
    "file_intel",
    "http_intel",
    "email_intel",
    "user_intel",
    "process_intel",
    "certificate_intel",
)

_STANDARD_INTERNAL_FIELDS: frozenset[str] = frozenset(
    {
        "event_id",
        "finding_id",
        "rule_id",
        "rule_name",
        "rule_title",
        "rule_description",
        "orig_rule_title",
        "orig_rule_description",
        "orig_sid",
        "orig_rid",
        "orig_action_name",
        "orig_queue_id",
        "orig_time",
        "status",
        "status_label",
        "status_name",
        "status_group",
        "status_default",
        "status_description",
        "status_end",
        "disposition",
        "disposition_id",
        "disposition_label",
        "disposition_name",
        "disposition_default",
        "disposition_description",
        "urgency",
        "severity",
        "severities",
        "owner",
        "owner_realname",
        "security_domain",
        "orig_security_domain",
        "risk_score",
        "risk_object",
        "risk_object_type",
        "risk_event_count",
        "notable_type",
        "is_investigation",
        "investigation_guid",
        "investigation_id",
        "investigation_type",
        "sensitivity",
        "suppressed",
        "queue_id",
        "extract_artifacts",
        "update_time",
        "create_time",
        "search_name",
        "source_event_id",
        "source_guid",
        "app_name",
        "agent_response_progress_key",
        "investigation_profiles",
        "eventtype",
        "linecount",
        "punct",
        "splunk_server",
        "splunk_server_group",
        "timestartpos",
        "timeendpos",
        "time",
        "index",
        "host",
        "source",
        "sourcetype",
        "src",
        "src_ip",
        "src_user",
        "dest",
        "dest_ip",
        "user",
        "domain",
        "dvc",
        "count",
        "count_findings",
        "event_names",
        "priority",
        "raw",
        "custom_fields",
        "source_backend",
        "item_type",
        "title",
        "entity",
        "name",
        "description",
    }
)


class SplunkESError(RuntimeError):
    """Raised when a Splunk Enterprise Security REST or SPL operation fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        endpoint: str | None = None,
        messages: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.endpoint = endpoint
        self.messages: list[str] = list(messages or [])


def _escape_spl_string(value: str) -> str:
    """Escape a string value for safe interpolation inside double-quoted SPL literals."""
    cleaned = " ".join(str(value).splitlines()).strip()
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def _stringify_field(value: Any) -> str:
    """Normalize scalar or multivalue Splunk result fields to a clean string."""
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item).strip() for item in value if item is not None and str(item).strip())
    return str(value).strip()


def normalize_notable_status(status: int | str) -> int:
    """Normalize a notable status integer or label into its Splunk ES integer status ID."""
    if isinstance(status, bool):
        raise ValueError(f"Invalid notable status: {status!r}")
    if isinstance(status, int):
        if status in NOTABLE_STATUS_LABELS:
            return status
        raise ValueError(
            f"Unsupported notable status code {status}. "
            f"Valid codes: {sorted(NOTABLE_STATUS_LABELS)}."
        )
    raw = str(status).strip()
    if not raw:
        raise ValueError("Notable status cannot be empty.")
    if raw.isdigit():
        code = int(raw)
        if code in NOTABLE_STATUS_LABELS:
            return code
        raise ValueError(
            f"Unsupported notable status code {code}. "
            f"Valid codes: {sorted(NOTABLE_STATUS_LABELS)}."
        )
    key = raw.lower().replace("-", "_").replace(" ", "_")
    if key in NOTABLE_STATUS_MAP:
        return NOTABLE_STATUS_MAP[key]
    raise ValueError(
        f"Unsupported notable status '{status}'. "
        f"Valid values: {', '.join(NOTABLE_STATUS_MAP)}."
    )


def notable_status_label(status: int | str | None, fallback: str = "") -> str:
    """Resolve a human-readable Splunk ES notable status label."""
    if status is None or str(status).strip() == "":
        return fallback
    try:
        code = normalize_notable_status(status)
        return NOTABLE_STATUS_LABELS[code]
    except ValueError:
        return fallback or str(status).strip()


def normalize_mc_disposition(disposition: str | None, *, for_mc_v2: bool = True) -> str | None:
    """Normalize a disposition ID, legacy slug, or human label for MC v2 or ``notable_update``."""
    if disposition is None:
        return None
    raw = str(disposition).strip()
    if not raw:
        return None
    low = raw.lower()
    if for_mc_v2:
        return _LEGACY_TO_MC_DISPOSITION.get(low, raw)
    return _MC_TO_LEGACY_DISPOSITION.get(low, raw)


def disposition_label(disposition: str | None, fallback: str = "") -> str:
    """Resolve a human-readable Splunk ES disposition label."""
    if not disposition or not str(disposition).strip():
        return fallback
    raw = str(disposition).strip()
    return _DISPOSITION_LABELS.get(raw.lower(), fallback or raw)


def extract_finding_tenant(
    record: Mapping[str, Any],
    tenant_cfg: SplunkESTenantConfig | None = None,
) -> str | None:
    """Extract tenant identifier case-insensitively across top-level, raw, custom_fields, fields, and event."""
    if not isinstance(record, Mapping):
        return None
    cfg = tenant_cfg or get_splunk_es_tenant_settings()
    val = cfg.extract_tenant(record)
    if val is not None:
        return val
    for nested_key in ("custom_fields", "raw"):
        nested = record.get(nested_key)
        if isinstance(nested, Mapping):
            val = cfg.extract_tenant(nested)
            if val is not None:
                return val
    return None


def _is_internal_or_standard_es_field(key: str, *, pinned_lower: frozenset[str]) -> bool:
    low = key.casefold()
    if low in pinned_lower:
        return False
    if key.startswith("_") or low.startswith(("date_", "tag::", "drilldown_", "info_", "rf_")):
        return True
    return low in _STANDARD_INTERNAL_FIELDS


def extract_custom_fields(
    record: Mapping[str, Any],
    *,
    pinned_fields: Sequence[str] = (),
    discovered_fields: Sequence[Mapping[str, str]] | Sequence[str] = (),
) -> dict[str, Any]:
    """Extract non-internal custom/org fields from a finding, investigation, or notable row."""
    if not isinstance(record, Mapping):
        return {}

    pinned_canonical: dict[str, str] = {}
    for pinned in pinned_fields:
        clean_p = str(pinned).strip()
        if clean_p and clean_p.casefold() not in pinned_canonical:
            pinned_canonical[clean_p.casefold()] = clean_p
    pinned_lower = frozenset(pinned_canonical.keys())

    discovered_lower: set[str] = set()
    for item in discovered_fields:
        if isinstance(item, Mapping):
            fname = str(item.get("field") or "").strip()
        else:
            fname = str(item).strip()
        if fname:
            discovered_lower.add(fname.casefold())

    out: dict[str, Any] = {}
    seen_lower: set[str] = set()

    explicit_cf = record.get("custom_fields")
    if isinstance(explicit_cf, Mapping):
        for k, v in explicit_cf.items():
            key_str = str(k).strip()
            if not key_str or v is None or v == "":
                continue
            low = key_str.casefold()
            if low in seen_lower:
                continue
            if not _is_internal_or_standard_es_field(key_str, pinned_lower=pinned_lower):
                target_key = pinned_canonical.get(low, key_str)
                out[target_key] = v
                seen_lower.add(low)

    raw_block = record.get("raw")
    containers: list[Mapping[str, Any]] = [record]
    if isinstance(raw_block, Mapping):
        containers.append(raw_block)

    for container in containers:
        for k, v in container.items():
            key_str = str(k).strip()
            if not key_str or v is None or v == "" or v == []:
                continue
            low = key_str.casefold()
            if low in seen_lower:
                continue
            if _is_internal_or_standard_es_field(key_str, pinned_lower=pinned_lower):
                continue
            target_key = pinned_canonical.get(low, key_str)
            out[target_key] = v
            seen_lower.add(low)

    # Ensure explicitly discovered or pinned non-standard keys present in containers are captured
    for low_p, clean_p in pinned_canonical.items():
        if low_p in seen_lower:
            continue
        for container in containers:
            for k, v in container.items():
                if isinstance(k, str) and k.casefold() == low_p and v is not None and v != "":
                    out[clean_p] = v
                    seen_lower.add(low_p)
                    break
            if low_p in seen_lower:
                break

    _ = discovered_lower
    return out


def normalize_finding(
    row: Mapping[str, Any],
    *,
    tenant_cfg: SplunkESTenantConfig | None = None,
    pinned_fields: Sequence[str] | None = None,
    source_backend: str = "mc_v2",
) -> dict[str, Any]:
    """Normalize a Mission Control v2 finding or 7.x notable into a unified dictionary."""
    cfg = tenant_cfg or get_splunk_es_tenant_settings()
    effective_pinned = tuple(pinned_fields) if pinned_fields is not None else cfg.custom_fields

    raw_status = row.get("status")
    status_val: int | str = ""
    if raw_status is not None and str(raw_status).strip() != "":
        try:
            status_val = normalize_notable_status(raw_status)
        except ValueError:
            status_val = _stringify_field(raw_status)

    explicit_label = _stringify_field(row.get("status_label") or row.get("status_name"))
    label = explicit_label or notable_status_label(status_val, fallback="Unknown")
    if status_val == "" and explicit_label:
        try:
            status_val = normalize_notable_status(explicit_label)
        except ValueError:
            status_val = explicit_label

    raw_disp_id = _stringify_field(row.get("disposition"))
    explicit_disp_lbl = _stringify_field(row.get("disposition_label") or row.get("disposition_name"))
    disp_label = explicit_disp_lbl or disposition_label(raw_disp_id, fallback=raw_disp_id)

    rule_name = _stringify_field(row.get("rule_name") or row.get("search_name") or row.get("rule_title"))
    rule_title = _stringify_field(row.get("rule_title") or row.get("rule_name") or row.get("search_name"))
    event_id = _stringify_field(row.get("event_id") or row.get("finding_id") or row.get("rule_id"))

    is_inv = _safe_bool(row.get("is_investigation"), False)
    notable_type = _stringify_field(row.get("notable_type")).lower()
    if is_inv or notable_type == "investigation":
        item_type = "investigation"
    elif notable_type in {"finding_group", "findinggroup", "group"}:
        item_type = "finding_group"
    else:
        item_type = "finding"

    src = _stringify_field(row.get("src") or row.get("src_ip"))
    dest = _stringify_field(row.get("dest") or row.get("dest_ip"))
    user = _stringify_field(row.get("user") or row.get("src_user"))
    risk_object = _stringify_field(row.get("risk_object") or row.get("normalized_risk_object"))
    entity = risk_object or src or dest or user or _stringify_field(row.get("domain"))

    tenant_val = extract_finding_tenant(row, cfg) or ""
    custom_fields = extract_custom_fields(row, pinned_fields=effective_pinned)
    if tenant_val and cfg.tenant_field not in custom_fields:
        custom_fields[cfg.tenant_field] = tenant_val

    return {
        "event_id": event_id,
        "finding_id": event_id,
        "rule_name": rule_name,
        "rule_title": rule_title,
        "title": rule_title or rule_name,
        "rule_description": _stringify_field(row.get("rule_description") or row.get("orig_rule_description")),
        "urgency": _stringify_field(row.get("urgency")).lower(),
        "severity": _stringify_field(row.get("severity")).lower(),
        "status": status_val,
        "status_label": label,
        "status_group": _stringify_field(row.get("status_group")),
        "owner": _stringify_field(row.get("owner")) or "unassigned",
        "owner_realname": _stringify_field(row.get("owner_realname")),
        "disposition": disp_label or raw_disp_id,
        "disposition_id": raw_disp_id,
        "disposition_label": disp_label,
        "security_domain": _stringify_field(row.get("security_domain") or row.get("orig_security_domain")),
        "src": src,
        "dest": dest,
        "user": user,
        "risk_score": _stringify_field(row.get("risk_score")),
        "risk_object": risk_object,
        "risk_object_type": _stringify_field(row.get("risk_object_type")),
        "entity": entity,
        "orig_sid": _stringify_field(row.get("orig_sid")),
        "orig_rid": _stringify_field(row.get("orig_rid")),
        "notable_type": notable_type or "notable",
        "is_investigation": is_inv,
        "suppressed": _safe_bool(row.get("suppressed"), False),
        "queue_id": _stringify_field(row.get("queue_id")),
        "item_type": item_type,
        "tenant_id": tenant_val,
        "custom_fields": custom_fields,
        "source_backend": source_backend,
        "_time": _stringify_field(row.get("_time") or row.get("update_time") or row.get("create_time")),
        "raw": dict(row),
    }


def normalize_investigation(
    row: Mapping[str, Any],
    *,
    tenant_cfg: SplunkESTenantConfig | None = None,
    pinned_fields: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Normalize a Mission Control v2 investigation into the unified queue dictionary."""
    cfg = tenant_cfg or get_splunk_es_tenant_settings()
    effective_pinned = tuple(pinned_fields) if pinned_fields is not None else cfg.custom_fields
    inv_id = _stringify_field(row.get("investigation_guid") or row.get("investigation_id") or row.get("id"))
    name = _stringify_field(row.get("name") or row.get("rule_title") or inv_id)
    raw_status = row.get("status")
    status_lbl = _stringify_field(row.get("status_name") or row.get("status_label"))
    if not status_lbl and raw_status is not None:
        status_lbl = notable_status_label(raw_status, fallback=str(raw_status))
    disp_id = _stringify_field(row.get("disposition"))
    disp_lbl = _stringify_field(row.get("disposition_name") or row.get("disposition_label")) or disposition_label(
        disp_id, fallback=disp_id
    )
    risk_obj = _stringify_field(row.get("normalized_risk_object") or row.get("risk_object"))
    tenant_val = extract_finding_tenant(row, cfg) or ""
    custom_fields = extract_custom_fields(row, pinned_fields=effective_pinned)
    if tenant_val and cfg.tenant_field not in custom_fields:
        custom_fields[cfg.tenant_field] = tenant_val

    return {
        "event_id": inv_id,
        "investigation_guid": inv_id,
        "investigation_id": inv_id,
        "name": name,
        "rule_name": name,
        "rule_title": name,
        "title": name,
        "rule_description": _stringify_field(row.get("description")),
        "urgency": _stringify_field(row.get("urgency")).lower(),
        "severity": _stringify_field(row.get("severity")).lower(),
        "status": raw_status if raw_status is not None else status_lbl,
        "status_label": status_lbl or "New",
        "owner": _stringify_field(row.get("owner")) or "unassigned",
        "disposition": disp_lbl or disp_id,
        "disposition_id": disp_id,
        "disposition_label": disp_lbl,
        "sensitivity": _stringify_field(row.get("sensitivity")),
        "investigation_type": _stringify_field(row.get("investigation_type")),
        "count_findings": row.get("count_findings", 0),
        "security_domain": _stringify_field(row.get("security_domain")),
        "src": _stringify_field(row.get("src") or row.get("src_ip")),
        "dest": _stringify_field(row.get("dest") or row.get("dest_ip")),
        "user": _stringify_field(row.get("user")),
        "risk_score": _stringify_field(row.get("risk_score")),
        "risk_object": risk_obj,
        "risk_object_type": _stringify_field(row.get("risk_object_type")),
        "entity": risk_obj,
        "queue_id": _stringify_field(row.get("queue_id")),
        "is_investigation": True,
        "suppressed": False,
        "item_type": "investigation",
        "tenant_id": tenant_val,
        "custom_fields": custom_fields,
        "source_backend": "mc_v2",
        "_time": _stringify_field(row.get("update_time") or row.get("create_time") or row.get("_time")),
        "raw": dict(row),
    }


def _normalize_notable_row(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a raw `` `notable` `` SPL result row into a consistent dictionary."""
    raw_status = row.get("status")
    status_val: int | str = ""
    if raw_status is not None and str(raw_status).strip() != "":
        try:
            status_val = normalize_notable_status(raw_status)
        except ValueError:
            status_val = _stringify_field(raw_status)

    explicit_label = _stringify_field(row.get("status_label"))
    label = explicit_label or notable_status_label(status_val, fallback="Unknown")
    rule_name = _stringify_field(row.get("rule_name") or row.get("search_name"))
    rule_title = _stringify_field(row.get("rule_title") or rule_name)
    tenant_cfg = get_splunk_es_tenant_settings()
    tenant_val = extract_finding_tenant(row, tenant_cfg) or ""
    custom_fields = extract_custom_fields(row, pinned_fields=tenant_cfg.custom_fields)

    return {
        "event_id": _stringify_field(row.get("event_id") or row.get("rule_id")),
        "rule_name": rule_name,
        "rule_title": rule_title,
        "title": rule_title or rule_name,
        "urgency": _stringify_field(row.get("urgency")).lower(),
        "status": status_val,
        "status_label": label,
        "owner": _stringify_field(row.get("owner")) or "unassigned",
        "disposition": _stringify_field(row.get("disposition_label") or row.get("disposition")),
        "security_domain": _stringify_field(row.get("security_domain")),
        "src": _stringify_field(row.get("src") or row.get("src_ip")),
        "dest": _stringify_field(row.get("dest") or row.get("dest_ip")),
        "user": _stringify_field(row.get("user") or row.get("src_user")),
        "risk_score": _stringify_field(row.get("risk_score")),
        "orig_sid": _stringify_field(row.get("orig_sid")),
        "orig_rid": _stringify_field(row.get("orig_rid")),
        "tenant_id": tenant_val,
        "custom_fields": custom_fields,
        "source_backend": "spl_fallback",
        "_time": _stringify_field(row.get("_time")),
        "raw": dict(row),
    }


def load_splunk_es_saved_views(
    *,
    settings_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Load custom saved Splunk ES queue views from ``splunk_es_saved_views`` setting."""
    raw = get_effective_setting("splunk_es_saved_views", settings_path=settings_path)
    if not raw or not raw.strip():
        return []
    try:
        loaded: Any = json.loads(raw)
    except ValueError:
        return []

    items: list[dict[str, Any]] = []
    if isinstance(loaded, list):
        for entry in loaded:
            if isinstance(entry, dict) and str(entry.get("id") or entry.get("label") or "").strip():
                items.append(dict(entry))
    elif isinstance(loaded, dict):
        for view_id, entry in loaded.items():
            if isinstance(entry, dict):
                copy_entry = dict(entry)
                copy_entry.setdefault("id", str(view_id))
                items.append(copy_entry)
    return items


def save_splunk_es_saved_view(
    view: Mapping[str, Any],
    *,
    settings_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Persist or update a custom Splunk ES queue view in ``splunk_es_saved_views``."""
    view_id = str(view.get("id") or "").strip()
    label = str(view.get("label") or view_id).strip()
    if not view_id:
        raise ValueError("Saved view 'id' is required.")
    clean_view = dict(view)
    clean_view["id"] = view_id
    clean_view["label"] = label

    existing = load_splunk_es_saved_views(settings_path=settings_path)
    updated = [item for item in existing if str(item.get("id") or "") != view_id]
    updated.append(clean_view)
    serialized = json.dumps(updated, separators=(",", ":"), ensure_ascii=False)
    save_profile_settings({"splunk_es_saved_views": serialized}, settings_path=settings_path)
    return updated


def delete_splunk_es_saved_view(
    view_id: str,
    *,
    settings_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Remove a custom Splunk ES queue view by ID from ``splunk_es_saved_views``."""
    clean_id = str(view_id).strip()
    existing = load_splunk_es_saved_views(settings_path=settings_path)
    updated = [item for item in existing if str(item.get("id") or "") != clean_id]
    serialized = json.dumps(updated, separators=(",", ":"), ensure_ascii=False) if updated else None
    save_profile_settings({"splunk_es_saved_views": serialized}, settings_path=settings_path)
    return updated


def _validate_threat_collection(collection: str) -> str:
    """Validate and return a Splunk ES Threat Intelligence KV Store collection name."""
    clean = str(collection).strip()
    if clean not in THREAT_INTEL_COLLECTIONS:
        raise ValueError(
            f"Unsupported threat intelligence collection '{collection}'. "
            f"Valid collections: {', '.join(THREAT_INTEL_COLLECTIONS)}."
        )
    return clean


def _raise_for_es_response(response: requests.Response, endpoint: str, action: str) -> None:
    """Raise ``SplunkESError`` with parsed Splunk REST or MC v2 error messages on HTTP error."""
    messages: list[str] = []
    err_msg = ""
    try:
        payload = response.json()
        if isinstance(payload, dict):
            messages = _extract_splunk_message_list(payload)
            err_msg = _extract_splunk_messages(payload)
            if not err_msg:
                mc_msg = payload.get("message")
                mc_code = payload.get("code")
                req_id = payload.get("request_id")
                parts = [str(mc_msg)] if mc_msg else []
                if mc_code:
                    parts.append(f"code={mc_code}")
                if req_id:
                    parts.append(f"request_id={req_id}")
                results = payload.get("results")
                if isinstance(results, list) and results:
                    row_errs = [
                        str(r.get("error"))
                        for r in results
                        if isinstance(r, dict) and r.get("error")
                    ]
                    if row_errs:
                        messages.extend(row_errs)
                        parts.append(f"errors={'; '.join(row_errs[:5])}")
                err_msg = " | ".join(parts)
            if not err_msg:
                err_msg = response.text
        else:
            err_msg = response.text
    except ValueError:
        err_msg = response.text
    raise SplunkESError(
        f"Failed to {action} (HTTP {response.status_code}): {err_msg}",
        status_code=response.status_code,
        endpoint=endpoint,
        messages=messages,
    )


class SplunkESClient:
    """Splunk Enterprise Security (ES) REST, Mission Control v2, and SPL client."""

    def __init__(
        self,
        *,
        splunk_client: SplunkClient | None = None,
        host: str | None = None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        app: str | None = SPLUNK_ES_APP,
        verify_ssl: bool | str | None = None,
        session: requests.Session | None = None,
        request_timeout: float = 15.0,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        poll_interval: float = 2.0,
        stop_event: threading.Event | None = None,
    ) -> None:
        if splunk_client is not None:
            self.client = splunk_client
            self._owns_client = False
            self.app = (app or splunk_client.app or SPLUNK_ES_APP).strip()
            self.stop_event: threading.Event | None = stop_event or getattr(
                splunk_client, "stop_event", None
            )
        else:
            target_app = (app or SPLUNK_ES_APP).strip() or SPLUNK_ES_APP
            self.client = SplunkClient(
                host=host,
                token=token,
                username=username,
                password=password,
                app=target_app,
                verify_ssl=verify_ssl,
                session=session,
                request_timeout=request_timeout,
                max_retries=max_retries,
                backoff_base=backoff_base,
                poll_interval=poll_interval,
                stop_event=stop_event,
            )
            self._owns_client = True
            self.app = self.client.app
            self.stop_event = getattr(self.client, "stop_event", stop_event)
        self.host = self.client.host
        self._discovered_custom_fields: list[dict[str, str]] | None = None

    def close(self) -> None:
        """Close the underlying ``SplunkClient`` if owned by this ES client."""
        if self._owns_client:
            self.client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Notable Events
    # ------------------------------------------------------------------

    def list_notables(
        self,
        *,
        earliest: str = "-24h",
        latest: str = "now",
        urgency: str | None = None,
        status: str | None = None,
        owner: str | None = None,
        rule_name: str | None = None,
        search_text: str | None = None,
        limit: int = 100,
        timeout: int = 120,
    ) -> list[dict[str, Any]]:
        """Query Splunk ES Notable Events using the `` `notable` `` SPL macro."""
        safe_limit = max(1, int(limit))
        clauses: list[str] = ["`notable`"]

        if urgency and urgency.strip():
            clean_urgency = urgency.strip().lower()
            if clean_urgency not in NOTABLE_URGENCIES:
                raise ValueError(
                    f"Unsupported urgency '{urgency}'. "
                    f"Valid urgencies: {', '.join(NOTABLE_URGENCIES)}."
                )
            clauses.append(f'| search urgency="{_escape_spl_string(clean_urgency)}"')

        if status is not None and str(status).strip():
            status_code = normalize_notable_status(status)
            status_lbl = NOTABLE_STATUS_LABELS[status_code]
            clauses.append(
                f'| search (status={status_code} OR status_label="{_escape_spl_string(status_lbl)}")'
            )

        if owner and owner.strip():
            clauses.append(f'| search owner="{_escape_spl_string(owner)}"')

        if rule_name and rule_name.strip():
            clauses.append(f'| search rule_name="*{_escape_spl_string(rule_name)}*"')

        if search_text and search_text.strip():
            clauses.append(f'| search "*{_escape_spl_string(search_text)}*"')

        clauses.append(f"| head {safe_limit}")
        spl = " ".join(clauses)

        res = self.client.run_search(
            spl,
            earliest=earliest,
            latest=latest,
            app=self.app,
            count=safe_limit,
            timeout=timeout,
        )
        if res.get("status") != "success":
            raise SplunkESError(
                str(res.get("error_message") or "Failed to query Splunk ES notable events."),
                messages=list(res.get("messages") or []),
            )
        rows = res.get("results") or []
        return [_normalize_notable_row(row) for row in rows if isinstance(row, dict)]

    def update_notable(
        self,
        event_ids: list[str],
        *,
        status: int | str | None = None,
        urgency: str | None = None,
        owner: str | None = None,
        disposition: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Update one or more Splunk ES notable events via ``/services/notable_update``."""
        clean_ids = [str(eid).strip() for eid in event_ids if str(eid).strip()]
        if not clean_ids:
            raise ValueError("At least one notable event_id is required.")

        payload: dict[str, Any] = {"ruleUIDs": clean_ids}
        has_mutation = False

        if status is not None and str(status).strip() != "":
            payload["status"] = str(normalize_notable_status(status))
            has_mutation = True

        if urgency is not None and urgency.strip():
            clean_urgency = urgency.strip().lower()
            if clean_urgency not in NOTABLE_URGENCIES:
                raise ValueError(
                    f"Unsupported urgency '{urgency}'. "
                    f"Valid urgencies: {', '.join(NOTABLE_URGENCIES)}."
                )
            payload["urgency"] = clean_urgency
            has_mutation = True

        if owner is not None and owner.strip():
            payload["newOwner"] = owner.strip()
            has_mutation = True

        if disposition is not None and disposition.strip():
            payload["disposition"] = disposition.strip()
            has_mutation = True

        if comment is not None and comment.strip():
            payload["comment"] = comment.strip()
            has_mutation = True

        if not has_mutation:
            raise ValueError(
                "At least one update field (status, urgency, owner, disposition, or comment) "
                "must be provided."
            )

        endpoint = "/services/notable_update?output_mode=json"
        response = self.client._request("POST", endpoint, data=payload)
        if response.status_code not in (200, 201):
            _raise_for_es_response(response, endpoint, "update notable event(s)")

        try:
            body = response.json()
        except ValueError:
            body = {"success": True, "ruleUIDs": clean_ids}
        if not isinstance(body, dict):
            return {"success": True, "ruleUIDs": clean_ids, "response": body}
        return body

    # ------------------------------------------------------------------
    # Correlation Searches
    # ------------------------------------------------------------------

    def list_correlation_searches(
        self,
        search_filter: str | None = None,
        count: int = 200,
    ) -> list[dict[str, Any]]:
        """List Splunk ES correlation searches from saved searches."""
        safe_count = max(0, int(count))
        endpoint = (
            f"/servicesNS/nobody/{SPLUNK_ES_APP}/saved/searches"
            f"?output_mode=json&count={safe_count}"
        )
        response = self.client._request("GET", endpoint)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, "list correlation searches")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned when listing correlation searches: {exc}",
                endpoint=endpoint,
            ) from exc

        entries = payload.get("entry", []) if isinstance(payload, dict) else []
        needle = search_filter.strip().lower() if search_filter else ""
        results: list[dict[str, Any]] = []

        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                content = entry.get("content")
                if not isinstance(content, dict):
                    content = {}
                acl = entry.get("acl")
                if not isinstance(acl, dict):
                    acl = {}

                action_notable = _safe_bool(content.get("action.notable"), False)
                action_risk = _safe_bool(content.get("action.risk"), False)
                corr_enabled = _safe_bool(content.get("action.correlationsearch.enabled"), False)
                if not (action_notable or action_risk or corr_enabled):
                    continue

                name = str(entry.get("name") or "")
                label = str(content.get("action.correlationsearch.label") or name)
                description = str(content.get("description") or "")
                search_spl = str(content.get("search") or "")

                if needle and not (
                    needle in name.lower()
                    or needle in label.lower()
                    or needle in description.lower()
                    or needle in search_spl.lower()
                ):
                    continue

                disabled = _safe_bool(content.get("disabled"), False)
                results.append(
                    {
                        "name": name,
                        "label": label,
                        "app": str(acl.get("app") or SPLUNK_ES_APP),
                        "description": description,
                        "search": search_spl,
                        "cron_schedule": str(content.get("cron_schedule") or ""),
                        "disabled": disabled,
                        "enabled": not disabled,
                        "action_notable": action_notable,
                        "action_risk": action_risk,
                        "security_domain": str(
                            content.get("action.notable.param.security_domain") or ""
                        ),
                        "severity": str(content.get("action.notable.param.severity") or ""),
                        "raw": content,
                    }
                )
        return results

    def set_correlation_search_enabled(self, name: str, enabled: bool) -> dict[str, Any]:
        """Enable or disable a Splunk ES correlation search by name."""
        clean_name = str(name).strip()
        if not clean_name:
            raise ValueError("Correlation search name is required.")
        quoted_name = quote(clean_name, safe="")
        endpoint = (
            f"/servicesNS/nobody/{SPLUNK_ES_APP}/saved/searches/{quoted_name}?output_mode=json"
        )
        disabled_val = "0" if enabled else "1"
        response = self.client._request("POST", endpoint, data={"disabled": disabled_val})
        if response.status_code not in (200, 201):
            _raise_for_es_response(
                response,
                endpoint,
                f"{'enable' if enabled else 'disable'} correlation search '{clean_name}'",
            )
        try:
            body = response.json()
        except ValueError:
            body = {}
        return {
            "name": clean_name,
            "enabled": bool(enabled),
            "disabled": not bool(enabled),
            "response": body,
        }

    # ------------------------------------------------------------------
    # Threat Intelligence KV Store
    # ------------------------------------------------------------------

    def list_threat_collections(self) -> tuple[str, ...]:
        """Return supported Splunk ES Threat Intelligence KV Store collection names."""
        return THREAT_INTEL_COLLECTIONS

    def query_threat_intel(
        self,
        collection: str,
        *,
        query: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query entries from a Splunk ES Threat Intelligence KV Store collection."""
        clean_col = _validate_threat_collection(collection)
        endpoint = (
            f"/servicesNS/nobody/{SPLUNK_TI_APP}/storage/collections/data/{clean_col}"
        )
        params: dict[str, Any] = {}
        safe_limit = max(0, int(limit))
        if safe_limit > 0:
            params["limit"] = safe_limit
        if query is not None:
            params["query"] = json.dumps(query, ensure_ascii=False)

        response = self.client._request("GET", endpoint, params=params or None)
        if response.status_code != 200:
            _raise_for_es_response(
                response,
                endpoint,
                f"query threat intelligence collection '{clean_col}'",
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned from threat intel collection '{clean_col}': {exc}",
                endpoint=endpoint,
            ) from exc

        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        return []

    def add_threat_intel_entry(
        self,
        collection: str,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        """Insert a single indicator entry into a Splunk ES Threat Intel KV Store collection."""
        clean_col = _validate_threat_collection(collection)
        if not isinstance(entry, dict) or not entry:
            raise ValueError("Threat intelligence entry must be a non-empty dictionary.")

        endpoint = (
            f"/servicesNS/nobody/{SPLUNK_TI_APP}/storage/collections/data/{clean_col}"
        )
        response = self.client._request("POST", endpoint, json=entry)
        if response.status_code not in (200, 201):
            _raise_for_es_response(
                response,
                endpoint,
                f"add threat intelligence entry to '{clean_col}'",
            )
        try:
            body = response.json()
        except ValueError:
            body = {}
        if isinstance(body, dict):
            return body
        return {"response": body}

    # ------------------------------------------------------------------
    # Assets, Identities & Risk-Based Alerting (RBA)
    # ------------------------------------------------------------------

    def lookup_asset(self, query: str = "", limit: int = 50) -> list[dict[str, Any]]:
        """Search the Splunk ES ``asset_lookup_by_str`` lookup table."""
        safe_limit = max(1, int(limit))
        spl = "| inputlookup asset_lookup_by_str"
        if query and query.strip():
            spl += f' | search "*{_escape_spl_string(query)}*"'
        spl += f" | head {safe_limit}"

        res = self.client.run_search(
            spl,
            earliest="-24h",
            latest="now",
            app=self.app,
            count=safe_limit,
        )
        if res.get("status") != "success":
            raise SplunkESError(
                str(res.get("error_message") or "Failed to lookup Splunk ES assets."),
                messages=list(res.get("messages") or []),
            )
        return [row for row in (res.get("results") or []) if isinstance(row, dict)]

    def lookup_identity(self, query: str = "", limit: int = 50) -> list[dict[str, Any]]:
        """Search the Splunk ES ``identity_lookup_expanded`` lookup table."""
        safe_limit = max(1, int(limit))
        spl = "| inputlookup identity_lookup_expanded"
        if query and query.strip():
            spl += f' | search "*{_escape_spl_string(query)}*"'
        spl += f" | head {safe_limit}"

        res = self.client.run_search(
            spl,
            earliest="-24h",
            latest="now",
            app=self.app,
            count=safe_limit,
        )
        if res.get("status") != "success":
            raise SplunkESError(
                str(res.get("error_message") or "Failed to lookup Splunk ES identities."),
                messages=list(res.get("messages") or []),
            )
        return [row for row in (res.get("results") or []) if isinstance(row, dict)]

    def list_risk_events(
        self,
        *,
        risk_object: str | None = None,
        earliest: str = "-24h",
        latest: str = "now",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query Splunk ES Risk-Based Alerting (RBA) events from ``index=risk``."""
        safe_limit = max(1, int(limit))
        spl = "search index=risk"
        if risk_object and risk_object.strip():
            spl += f' risk_object="{_escape_spl_string(risk_object)}"'
        spl += f" | head {safe_limit}"

        res = self.client.run_search(
            spl,
            earliest=earliest,
            latest=latest,
            app=self.app,
            count=safe_limit,
        )
        if res.get("status") != "success":
            raise SplunkESError(
                str(res.get("error_message") or "Failed to query Splunk ES risk events."),
                messages=list(res.get("messages") or []),
            )
        return [row for row in (res.get("results") or []) if isinstance(row, dict)]

    # ------------------------------------------------------------------
    # ES 8.6 Mission Control v2 Helpers & Dynamic Custom Fields
    # ------------------------------------------------------------------

    @staticmethod
    def _mc_path(subpath: str) -> str:
        clean = subpath if subpath.startswith("/") else f"/{subpath}"
        return f"{MC_V2_BASE_PATH}{clean}"

    @staticmethod
    def _encode_id(item_id: str) -> str:
        clean = str(item_id or "").strip()
        if not clean:
            raise ValueError("Item ID is required.")
        return quote(clean, safe="")

    @staticmethod
    def _format_additional_fields(
        additional_fields: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None,
    ) -> list[dict[str, str]] | None:
        if additional_fields is None:
            return None
        formatted: list[dict[str, str]] = []
        if isinstance(additional_fields, Mapping):
            for key, value in additional_fields.items():
                k = str(key).strip()
                if k and value is not None:
                    formatted.append({"name": k, "value": str(value)})
        else:
            for item in additional_fields:
                if isinstance(item, Mapping):
                    name = str(item.get("name") or item.get("field") or "").strip()
                    val = item.get("value")
                    if name and val is not None:
                        formatted.append({"name": name, "value": str(val)})
        return formatted or None

    def discover_custom_fields(self, *, force_refresh: bool = False) -> list[dict[str, str]]:
        """Discover registered notable ``event_attributes`` from ES conf REST endpoints.

        Probes ``conf-incident_review/incident_review`` first, falling back on HTTP 404
        to ``conf-log_review/incident_review``. Gracefully returns ``[]`` on 403/404 or
        malformed payloads.
        """
        if not force_refresh and self._discovered_custom_fields is not None:
            return list(self._discovered_custom_fields)

        endpoints = (
            "/servicesNS/-/-/configs/conf-incident_review/incident_review?output_mode=json",
            "/servicesNS/-/-/configs/conf-log_review/incident_review?output_mode=json",
        )
        raw_attrs: Any = None
        for idx, endpoint in enumerate(endpoints):
            try:
                response = self.client._request("GET", endpoint)
            except requests.exceptions.RequestException as exc:
                logger.debug("Custom field discovery failed on %s: %s", endpoint, exc)
                self._discovered_custom_fields = []
                return []

            if response.status_code == 404 and idx == 0:
                continue
            if response.status_code in (403, 404):
                self._discovered_custom_fields = []
                return []
            if response.status_code != 200:
                logger.debug(
                    "Custom field discovery returned HTTP %d on %s",
                    response.status_code,
                    endpoint,
                )
                self._discovered_custom_fields = []
                return []

            try:
                payload = response.json()
            except ValueError:
                self._discovered_custom_fields = []
                return []

            entries = payload.get("entry") if isinstance(payload, dict) else None
            if isinstance(entries, list) and entries and isinstance(entries[0], dict):
                content = entries[0].get("content")
                if isinstance(content, dict) and "event_attributes" in content:
                    raw_attrs = content.get("event_attributes")
                    break

        parsed: list[dict[str, str]] = []
        if isinstance(raw_attrs, str):
            stripped = raw_attrs.strip()
            if stripped:
                try:
                    raw_attrs = json.loads(stripped)
                except ValueError:
                    raw_attrs = None
        if isinstance(raw_attrs, list):
            seen: set[str] = set()
            for entry in raw_attrs:
                if not isinstance(entry, Mapping):
                    continue
                field = str(entry.get("field") or entry.get("name") or "").strip()
                if not field or field in seen:
                    continue
                seen.add(field)
                label = str(entry.get("label") or field).strip() or field
                parsed.append({"field": field, "label": label})

        self._discovered_custom_fields = parsed
        return list(parsed)

    # ------------------------------------------------------------------
    # ES 8.6 Mission Control v2 Findings, Investigations, Notes & History
    # ------------------------------------------------------------------

    def list_findings(
        self,
        *,
        finding_ids: Sequence[str] | str | None = None,
        urgency: str | None = None,
        status: str | int | None = None,
        owner: str | None = None,
        disposition: str | None = None,
        earliest: str | None = None,
        latest: str | None = None,
        rule_title: str | None = None,
        limit: int = 100,
        offset: int = 0,
        sort: str | None = None,
        fields: Sequence[str] | str | None = None,
        search_format: bool | None = None,
        search_finding_groups: bool | None = None,
        normalize: bool = True,
    ) -> dict[str, Any]:
        """Query Mission Control v2 ``GET /public/v2/findings`` with documented query params only."""
        endpoint = self._mc_path("/findings")
        params: dict[str, Any] = {
            "limit": max(1, int(limit)),
            "offset": max(0, int(offset)),
        }
        if finding_ids is not None:
            params["finding_ids"] = (
                finding_ids if isinstance(finding_ids, str) else ",".join(finding_ids)
            )
        if urgency and str(urgency).strip():
            params["urgency"] = str(urgency).strip().lower()
        if status is not None and str(status).strip():
            params["status"] = str(status).strip()
        if owner and str(owner).strip():
            params["owner"] = str(owner).strip()
        if disposition and str(disposition).strip():
            params["disposition"] = str(disposition).strip()
        if earliest and str(earliest).strip():
            params["earliest"] = str(earliest).strip()
        if latest and str(latest).strip():
            params["latest"] = str(latest).strip()
        if rule_title and str(rule_title).strip():
            params["rule_title"] = str(rule_title).strip()
        if sort and str(sort).strip():
            params["sort"] = str(sort).strip()
        if fields is not None:
            params["fields"] = fields if isinstance(fields, str) else ",".join(fields)
        if search_format is not None:
            params["search_format"] = "true" if search_format else "false"
        if search_finding_groups is not None:
            params["search_finding_groups"] = "true" if search_finding_groups else "false"

        response = self.client._request("GET", endpoint, params=params)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, "list Mission Control v2 findings")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned from Mission Control v2 findings: {exc}",
                endpoint=endpoint,
            ) from exc

        raw_items: list[dict[str, Any]] = []
        total = 0
        resp_offset = max(0, int(offset))
        resp_limit = max(1, int(limit))
        if isinstance(payload, dict):
            if isinstance(payload.get("items"), list):
                raw_items = [row for row in payload["items"] if isinstance(row, dict)]
                total = int(payload.get("total", len(raw_items)) or 0)
                resp_offset = int(payload.get("offset", resp_offset) or 0)
                resp_limit = int(payload.get("limit", resp_limit) or resp_limit)
            elif isinstance(payload.get("entry"), list):
                for entry in payload["entry"]:
                    if isinstance(entry, dict) and isinstance(entry.get("content"), dict):
                        raw_items.append(entry["content"])
                total = len(raw_items)
        elif isinstance(payload, list):
            raw_items = [row for row in payload if isinstance(row, dict)]
            total = len(raw_items)

        tenant_cfg = get_splunk_es_tenant_settings()
        items = (
            [
                normalize_finding(
                    row,
                    tenant_cfg=tenant_cfg,
                    pinned_fields=tenant_cfg.custom_fields,
                    source_backend="mc_v2",
                )
                for row in raw_items
            ]
            if normalize
            else raw_items
        )
        return {
            "items": items,
            "offset": resp_offset,
            "limit": resp_limit,
            "total": total,
        }

    def get_finding(
        self,
        finding_id: str,
        *,
        earliest: str | None = None,
        latest: str | None = None,
        fields: Sequence[str] | str | None = None,
        search_format: bool | None = None,
        normalize: bool = True,
    ) -> dict[str, Any]:
        """Fetch a single Mission Control v2 finding by ID (URL-encoding ``@@``)."""
        encoded_id = self._encode_id(finding_id)
        endpoint = self._mc_path(f"/findings/{encoded_id}")
        params: dict[str, Any] = {}
        if earliest and str(earliest).strip():
            params["earliest"] = str(earliest).strip()
        if latest and str(latest).strip():
            params["latest"] = str(latest).strip()
        if fields is not None:
            params["fields"] = fields if isinstance(fields, str) else ",".join(fields)
        if search_format is not None:
            params["search_format"] = "true" if search_format else "false"

        response = self.client._request("GET", endpoint, params=params or None)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, f"get finding '{finding_id}'")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned for finding '{finding_id}': {exc}",
                endpoint=endpoint,
            ) from exc

        if not isinstance(payload, dict):
            return {"raw": payload}
        if normalize:
            tenant_cfg = get_splunk_es_tenant_settings()
            return normalize_finding(
                payload,
                tenant_cfg=tenant_cfg,
                pinned_fields=tenant_cfg.custom_fields,
                source_backend="mc_v2",
            )
        return payload

    def create_finding(
        self,
        *,
        rule_title: str,
        security_domain: str = "threat",
        rule_description: str | None = None,
        urgency: str | None = None,
        status: str | int | None = None,
        owner: str | None = None,
        disposition: str | None = None,
        risk_object: str | None = None,
        risk_object_type: str | None = None,
        risk_score: float | int | None = None,
        queue_id: str | None = None,
        source: str | None = None,
        additional_fields: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        """Create a manual finding via ``POST /public/v2/findings``."""
        clean_title = str(rule_title or "").strip()
        if not clean_title:
            raise ValueError("rule_title is required to create a finding.")
        clean_domain = str(security_domain or "threat").strip() or "threat"

        body: dict[str, Any] = {
            "rule_title": clean_title,
            "security_domain": clean_domain,
        }
        if rule_description and str(rule_description).strip():
            body["rule_description"] = str(rule_description).strip()
        if urgency and str(urgency).strip():
            body["urgency"] = str(urgency).strip().lower()
        if status is not None and str(status).strip():
            body["status"] = str(status).strip()
        if owner and str(owner).strip():
            body["owner"] = str(owner).strip()
        if disposition and str(disposition).strip():
            norm_disp = normalize_mc_disposition(disposition, for_mc_v2=True)
            if norm_disp:
                body["disposition"] = norm_disp
        if risk_object and str(risk_object).strip():
            body["risk_object"] = str(risk_object).strip()
        if risk_object_type and str(risk_object_type).strip():
            body["risk_object_type"] = str(risk_object_type).strip()
        if risk_score is not None:
            body["risk_score"] = risk_score
        if queue_id and str(queue_id).strip():
            body["queue_id"] = str(queue_id).strip()
        if source and str(source).strip():
            body["source"] = str(source).strip()

        formatted_fields = self._format_additional_fields(additional_fields)
        if formatted_fields is not None:
            body["additional_fields"] = formatted_fields

        for extra_k, extra_v in extra.items():
            if extra_v is not None:
                body[extra_k] = extra_v

        endpoint = self._mc_path("/findings")
        response = self.client._request("POST", endpoint, json=body)
        if response.status_code not in (200, 201):
            _raise_for_es_response(response, endpoint, "create finding")
        try:
            payload = response.json()
        except ValueError:
            payload = {"finding_id": ""}
        return payload if isinstance(payload, dict) else {"response": payload}

    def bulk_create_findings(self, findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        """Bulk-create up to 500 manual findings via ``POST /public/v2/findings/bulk_create``."""
        items = list(findings)
        if not items:
            raise ValueError("At least one finding payload is required for bulk_create.")
        if len(items) > 500:
            raise ValueError("Mission Control v2 bulk_create supports at most 500 findings.")

        payload_list: list[dict[str, Any]] = []
        for item in items:
            entry = dict(item)
            if "additional_fields" in entry:
                formatted = self._format_additional_fields(entry.get("additional_fields"))
                if formatted is not None:
                    entry["additional_fields"] = formatted
                else:
                    entry.pop("additional_fields", None)
            payload_list.append(entry)

        endpoint = self._mc_path("/findings/bulk_create")
        response = self.client._request("POST", endpoint, json=payload_list)
        if response.status_code not in (200, 201):
            _raise_for_es_response(response, endpoint, "bulk-create findings")
        try:
            data = response.json()
        except ValueError:
            data = {"status": "success", "created": len(payload_list), "failed": 0}
        return data if isinstance(data, dict) else {"response": data}

    def list_investigations(
        self,
        *,
        ids: Sequence[str] | str | None = None,
        limit: int = 100,
        offset: int = 0,
        sort: str | None = None,
        disposition: str | None = None,
        status: str | None = None,
        owner: str | None = None,
        urgency: str | None = None,
        sensitivity: str | None = None,
        normalized_risk_object: str | None = None,
        risk_object_type: str | None = None,
        create_time_min: str | None = None,
        create_time_max: str | None = None,
        update_time_min: str | None = None,
        update_time_max: str | None = None,
        normalize: bool = True,
    ) -> list[dict[str, Any]]:
        """List Mission Control v2 investigations, handling bare JSON ``list`` responses."""
        endpoint = self._mc_path("/investigations")
        params: dict[str, Any] = {
            "limit": max(1, int(limit)),
            "offset": max(0, int(offset)),
        }
        if ids is not None:
            params["ids"] = ids if isinstance(ids, str) else ",".join(ids)
        for key, val in (
            ("sort", sort),
            ("disposition", disposition),
            ("status", status),
            ("owner", owner),
            ("urgency", urgency),
            ("sensitivity", sensitivity),
            ("normalized_risk_object", normalized_risk_object),
            ("risk_object_type", risk_object_type),
            ("create_time_min", create_time_min),
            ("create_time_max", create_time_max),
            ("update_time_min", update_time_min),
            ("update_time_max", update_time_max),
        ):
            if val is not None and str(val).strip():
                params[key] = str(val).strip()

        response = self.client._request("GET", endpoint, params=params)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, "list Mission Control v2 investigations")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned from investigations endpoint: {exc}",
                endpoint=endpoint,
            ) from exc

        if isinstance(payload, list):
            raw_list = [row for row in payload if isinstance(row, dict)]
        elif isinstance(payload, dict) and isinstance(payload.get("items"), list):
            raw_list = [row for row in payload["items"] if isinstance(row, dict)]
        else:
            raw_list = []

        if not normalize:
            return raw_list
        tenant_cfg = get_splunk_es_tenant_settings()
        return [
            normalize_investigation(
                row,
                tenant_cfg=tenant_cfg,
                pinned_fields=tenant_cfg.custom_fields,
            )
            for row in raw_list
        ]

    def create_investigation(
        self,
        name: str,
        *,
        description: str | None = None,
        investigation_type: str | None = None,
        status: str | None = None,
        disposition: str | None = None,
        owner: str | None = None,
        urgency: str | None = None,
        sensitivity: str | None = None,
        finding_ids: Sequence[str] | None = None,
        finding_times: Sequence[str] | None = None,
        queue_id: str | None = None,
        ensure_enriched: bool | None = None,
    ) -> dict[str, Any]:
        """Create a Mission Control v2 investigation via ``POST /public/v2/investigations``."""
        clean_name = str(name or "").strip()
        if not clean_name:
            raise ValueError("Investigation name is required.")
        body: dict[str, Any] = {"name": clean_name}
        for key, val in (
            ("description", description),
            ("investigation_type", investigation_type),
            ("status", status),
            ("owner", owner),
            ("sensitivity", sensitivity),
            ("queue_id", queue_id),
        ):
            if val is not None and str(val).strip():
                body[key] = str(val).strip()
        if urgency and str(urgency).strip():
            body["urgency"] = str(urgency).strip().lower()
        if disposition and str(disposition).strip():
            norm_disp = normalize_mc_disposition(disposition, for_mc_v2=True)
            if norm_disp:
                body["disposition"] = norm_disp
        if finding_ids is not None:
            body["finding_ids"] = [str(fid).strip() for fid in finding_ids if str(fid).strip()]
        if finding_times is not None:
            body["finding_times"] = [str(ft).strip() for ft in finding_times if str(ft).strip()]

        params: dict[str, Any] = {}
        if ensure_enriched is not None:
            params["ensure_enriched"] = "true" if ensure_enriched else "false"

        endpoint = self._mc_path("/investigations")
        response = self.client._request("POST", endpoint, params=params or None, json=body)
        if response.status_code not in (200, 201):
            _raise_for_es_response(response, endpoint, f"create investigation '{clean_name}'")
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        return payload if isinstance(payload, dict) else {"response": payload}

    def update_investigation(
        self,
        investigation_id: str,
        *,
        finding_time: str | None = None,
        name: str | None = None,
        description: str | None = None,
        status: str | None = None,
        owner: str | None = None,
        urgency: str | None = None,
        sensitivity: str | None = None,
        investigation_type: str | None = None,
        queue_id: str | None = None,
        investigation_note: Mapping[str, Any] | str | None = None,
    ) -> dict[str, Any]:
        """Update an investigation or finding via ``POST /public/v2/investigations/{id}``."""
        encoded_id = self._encode_id(investigation_id)
        endpoint = self._mc_path(f"/investigations/{encoded_id}")
        params: dict[str, Any] = {}
        if finding_time and str(finding_time).strip():
            params["finding_time"] = str(finding_time).strip()

        body: dict[str, Any] = {}
        for key, val in (
            ("name", name),
            ("description", description),
            ("status", status),
            ("owner", owner),
            ("sensitivity", sensitivity),
            ("investigation_type", investigation_type),
            ("queue_id", queue_id),
        ):
            if val is not None and str(val).strip():
                body[key] = str(val).strip()
        if urgency and str(urgency).strip():
            body["urgency"] = str(urgency).strip().lower()
        if investigation_note is not None:
            if isinstance(investigation_note, Mapping):
                body["investigation_note"] = dict(investigation_note)
            elif str(investigation_note).strip():
                body["investigation_note"] = {"content": str(investigation_note).strip()}

        if not body:
            raise ValueError("At least one investigation update field is required.")

        response = self.client._request("POST", endpoint, params=params or None, json=body)
        if response.status_code not in (200, 201):
            _raise_for_es_response(response, endpoint, f"update investigation '{investigation_id}'")
        try:
            payload = response.json()
        except ValueError:
            payload = {"investigation_guid": investigation_id}
        return payload if isinstance(payload, dict) else {"response": payload}

    def add_findings_to_investigation(
        self,
        investigation_id: str,
        finding_ids: Sequence[str],
        finding_times: Sequence[str] | None = None,
        *,
        ensure_enriched: bool | None = None,
    ) -> dict[str, Any]:
        """Attach findings to an existing investigation via ``POST /public/v2/investigations/{id}/findings``."""
        clean_fids = [str(fid).strip() for fid in finding_ids if str(fid).strip()]
        if not clean_fids:
            raise ValueError("At least one finding_id is required.")
        clean_times = (
            [str(ft).strip() for ft in finding_times]
            if finding_times is not None
            else [""] * len(clean_fids)
        )
        encoded_id = self._encode_id(investigation_id)
        endpoint = self._mc_path(f"/investigations/{encoded_id}/findings")
        params: dict[str, Any] = {}
        if ensure_enriched is not None:
            params["ensure_enriched"] = "true" if ensure_enriched else "false"
        body: dict[str, Any] = {
            "finding_ids": clean_fids,
            "finding_times": clean_times,
        }
        response = self.client._request("POST", endpoint, params=params or None, json=body)
        if response.status_code not in (200, 201):
            _raise_for_es_response(
                response,
                endpoint,
                f"add findings to investigation '{investigation_id}'",
            )
        try:
            payload = response.json()
        except ValueError:
            payload = {"investigation_guid": investigation_id}
        return payload if isinstance(payload, dict) else {"response": payload}

    def bulk_update_findings(
        self,
        *,
        record_ids: Sequence[str] | None = None,
        aq_sid: str | None = None,
        earliest: str | None = None,
        latest: str | None = None,
        status: str | int | None = None,
        urgency: str | None = None,
        owner: str | None = None,
        disposition: str | None = None,
        sensitivity: str | None = None,
        queue_id: str | None = None,
        investigation_note: Mapping[str, Any] | str | None = None,
        name: str | None = None,
        description: str | None = None,
    ) -> list[dict[str, Any]]:
        """Bulk-update findings or investigations via ``POST /public/v2/investigations/bulk_update``."""
        clean_ids = [str(rid).strip() for rid in (record_ids or ()) if str(rid).strip()]
        clean_sid = str(aq_sid or "").strip()
        if bool(clean_ids) == bool(clean_sid):
            raise ValueError("Provide either 'record_ids' or 'aq_sid' (mutually exclusive).")

        body: dict[str, Any] = {}
        if clean_ids:
            body["record_ids"] = clean_ids
        else:
            body["aq_sid"] = clean_sid

        if earliest and str(earliest).strip():
            body["earliest"] = str(earliest).strip()
        if latest and str(latest).strip():
            body["latest"] = str(latest).strip()

        has_mutation = False
        if status is not None and str(status).strip() != "":
            status_str = str(status).strip()
            try:
                body["status"] = NOTABLE_STATUS_LABELS[normalize_notable_status(status_str)]
            except ValueError:
                body["status"] = status_str
            has_mutation = True
        if urgency and str(urgency).strip():
            clean_urg = str(urgency).strip().lower()
            if clean_urg not in NOTABLE_URGENCIES:
                raise ValueError(f"Unsupported urgency '{urgency}'.")
            body["urgency"] = clean_urg
            has_mutation = True
        if owner and str(owner).strip():
            body["owner"] = str(owner).strip()
            has_mutation = True
        if disposition and str(disposition).strip():
            norm_disp = normalize_mc_disposition(disposition, for_mc_v2=True)
            if norm_disp:
                body["disposition"] = norm_disp
                has_mutation = True
        for key, val in (
            ("sensitivity", sensitivity),
            ("queue_id", queue_id),
            ("name", name),
            ("description", description),
        ):
            if val is not None and str(val).strip():
                body[key] = str(val).strip()
                has_mutation = True
        if investigation_note is not None:
            if isinstance(investigation_note, Mapping):
                body["investigation_note"] = dict(investigation_note)
                has_mutation = True
            elif str(investigation_note).strip():
                body["investigation_note"] = {"content": str(investigation_note).strip()}
                has_mutation = True

        if not has_mutation:
            raise ValueError("At least one bulk update field or note must be provided.")

        endpoint = self._mc_path("/investigations/bulk_update")
        response = self.client._request("POST", endpoint, json=body)
        if response.status_code not in (200, 201, 202):
            _raise_for_es_response(response, endpoint, "bulk update findings/investigations")
        try:
            payload = response.json()
        except ValueError:
            return [{"id": rid} for rid in clean_ids]
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("results"), list):
            return [row for row in payload["results"] if isinstance(row, dict)]
        return [{"response": payload}]

    def list_notes(
        self,
        record_id: str,
        *,
        finding_time: str | None = None,
        search: str | None = None,
        note_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
        sort: str | None = None,
    ) -> dict[str, Any]:
        """List Markdown notes on a finding or investigation (URL-encoding ``@@``)."""
        encoded_id = self._encode_id(record_id)
        endpoint = self._mc_path(f"/investigations/{encoded_id}/notes")
        params: dict[str, Any] = {
            "limit": max(1, int(limit)),
            "offset": max(0, int(offset)),
        }
        if finding_time and str(finding_time).strip():
            params["finding_time"] = str(finding_time).strip()
        if search and str(search).strip():
            params["search"] = str(search).strip()
        if note_type and str(note_type).strip():
            params["type"] = str(note_type).strip()
        if sort and str(sort).strip():
            params["sort"] = str(sort).strip()

        response = self.client._request("GET", endpoint, params=params)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, f"list notes for '{record_id}'")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(f"Invalid JSON returned for notes: {exc}", endpoint=endpoint) from exc
        if isinstance(payload, dict):
            return {
                "items": [row for row in (payload.get("items") or []) if isinstance(row, dict)],
                "offset": int(payload.get("offset", offset) or 0),
                "limit": int(payload.get("limit", limit) or limit),
                "total": int(payload.get("total", 0) or 0),
                "has_skipped_comments": bool(payload.get("has_skipped_comments", False)),
            }
        return {"items": [], "offset": 0, "limit": limit, "total": 0, "has_skipped_comments": False}

    def create_note(
        self,
        record_id: str,
        content: str,
        *,
        title: str | None = None,
        files: Sequence[Mapping[str, Any]] | None = None,
        finding_time: str | None = None,
    ) -> dict[str, Any]:
        """Create a Markdown note on a finding or investigation."""
        clean_content = str(content or "").strip()
        if not clean_content:
            raise ValueError("Note content is required.")
        encoded_id = self._encode_id(record_id)
        endpoint = self._mc_path(f"/investigations/{encoded_id}/notes")
        params: dict[str, Any] = {}
        if finding_time and str(finding_time).strip():
            params["finding_time"] = str(finding_time).strip()
        body: dict[str, Any] = {"content": clean_content}
        if title and str(title).strip():
            body["title"] = str(title).strip()
        if files:
            body["files"] = [dict(f) for f in files]

        response = self.client._request("POST", endpoint, params=params or None, json=body)
        if response.status_code not in (200, 201):
            _raise_for_es_response(response, endpoint, f"create note on '{record_id}'")
        try:
            payload = response.json()
        except ValueError:
            payload = {"content": clean_content}
        return payload if isinstance(payload, dict) else {"response": payload}

    def update_note(
        self,
        record_id: str,
        note_id: str,
        *,
        title: str | None = None,
        content: str | None = None,
        files: Sequence[Mapping[str, Any]] | None = None,
        finding_time: str | None = None,
    ) -> dict[str, Any]:
        """Update an existing note on a finding or investigation."""
        encoded_id = self._encode_id(record_id)
        encoded_note = self._encode_id(note_id)
        endpoint = self._mc_path(f"/investigations/{encoded_id}/notes/{encoded_note}")
        params: dict[str, Any] = {}
        if finding_time and str(finding_time).strip():
            params["finding_time"] = str(finding_time).strip()
        body: dict[str, Any] = {}
        if title is not None:
            body["title"] = str(title)
        if content is not None:
            body["content"] = str(content)
        if files is not None:
            body["files"] = [dict(f) for f in files]
        if not body:
            raise ValueError("At least one note field must be provided.")

        response = self.client._request("POST", endpoint, params=params or None, json=body)
        if response.status_code not in (200, 201):
            _raise_for_es_response(response, endpoint, f"update note '{note_id}'")
        try:
            payload = response.json()
        except ValueError:
            payload = {"id": note_id}
        return payload if isinstance(payload, dict) else {"response": payload}

    def delete_note(
        self,
        record_id: str,
        note_id: str,
        *,
        finding_time: str | None = None,
    ) -> dict[str, Any]:
        """Delete a note on a finding or investigation."""
        encoded_id = self._encode_id(record_id)
        encoded_note = self._encode_id(note_id)
        endpoint = self._mc_path(f"/investigations/{encoded_id}/notes/{encoded_note}")
        params: dict[str, Any] = {}
        if finding_time and str(finding_time).strip():
            params["finding_time"] = str(finding_time).strip()

        response = self.client._request("DELETE", endpoint, params=params or None)
        if response.status_code not in (200, 204):
            _raise_for_es_response(response, endpoint, f"delete note '{note_id}'")
        return {"deleted": True, "note_id": note_id}

    def get_history(
        self,
        record_id: str,
        *,
        finding_time: str | None = None,
        limit: int = 100,
        offset: int = 0,
        exclude_sources: Sequence[str] | str | None = None,
        include_findings: bool | None = None,
    ) -> dict[str, Any]:
        """Fetch audit history for a finding or investigation (URL-encoding ``@@``)."""
        encoded_id = self._encode_id(record_id)
        endpoint = self._mc_path(f"/investigations/{encoded_id}/history")
        params: dict[str, Any] = {
            "limit": max(1, min(1000, int(limit))),
            "offset": max(0, int(offset)),
        }
        if finding_time and str(finding_time).strip():
            params["finding_time"] = str(finding_time).strip()
        if exclude_sources is not None:
            params["exclude_sources"] = (
                exclude_sources if isinstance(exclude_sources, str) else ",".join(exclude_sources)
            )
        if include_findings is not None:
            params["include_findings"] = "true" if include_findings else "false"

        response = self.client._request("GET", endpoint, params=params)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, f"get history for '{record_id}'")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned for history: {exc}",
                endpoint=endpoint,
            ) from exc
        if isinstance(payload, dict):
            return {
                "items": [row for row in (payload.get("items") or []) if isinstance(row, dict)],
                "offset": int(payload.get("offset", offset) or 0),
                "limit": int(payload.get("limit", limit) or limit),
                "total": int(payload.get("total", 0) or 0),
            }
        return {"items": [], "offset": 0, "limit": limit, "total": 0}

    def list_queues(self) -> dict[str, Any]:
        """List Mission Control v2 queues via ``GET /public/v2/queues``."""
        endpoint = self._mc_path("/queues")
        response = self.client._request("GET", endpoint)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, "list queues")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(f"Invalid JSON returned for queues: {exc}", endpoint=endpoint) from exc
        if isinstance(payload, dict):
            return {
                "queues": [q for q in (payload.get("queues") or []) if isinstance(q, dict)],
                "last_updated_time": payload.get("last_updated_time"),
            }
        return {"queues": [], "last_updated_time": None}

    def get_asset(self, asset_id: str) -> dict[str, Any]:
        """Fetch an asset record via ``GET /public/v2/assets/{id}``."""
        encoded_id = self._encode_id(asset_id)
        endpoint = self._mc_path(f"/assets/{encoded_id}")
        response = self.client._request("GET", endpoint)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, f"get asset '{asset_id}'")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(f"Invalid JSON returned for asset: {exc}", endpoint=endpoint) from exc
        return payload if isinstance(payload, dict) else {"raw": payload}

    def get_identity(self, identity_id: str) -> dict[str, Any]:
        """Fetch an identity record via ``GET /public/v2/identity/{id}``."""
        encoded_id = self._encode_id(identity_id)
        endpoint = self._mc_path(f"/identity/{encoded_id}")
        response = self.client._request("GET", endpoint)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, f"get identity '{identity_id}'")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(f"Invalid JSON returned for identity: {exc}", endpoint=endpoint) from exc
        return payload if isinstance(payload, dict) else {"raw": payload}

    def get_risk_scores(
        self,
        entity: str,
        *,
        entity_type: str | None = None,
        earliest: str | None = None,
        latest: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query Mission Control v2 risk scores via ``GET /public/v2/risks/risk_scores/{entity}``."""
        encoded_entity = self._encode_id(entity)
        endpoint = self._mc_path(f"/risks/risk_scores/{encoded_entity}")
        params: dict[str, Any] = {
            "limit": max(1, int(limit)),
            "offset": max(0, int(offset)),
        }
        if entity_type and str(entity_type).strip():
            params["entity_type"] = str(entity_type).strip()
        if earliest and str(earliest).strip():
            params["earliest"] = str(earliest).strip()
        if latest and str(latest).strip():
            params["latest"] = str(latest).strip()

        response = self.client._request("GET", endpoint, params=params)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, f"get risk scores for '{entity}'")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned for risk scores: {exc}",
                endpoint=endpoint,
            ) from exc
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("items"), list):
            return [row for row in payload["items"] if isinstance(row, dict)]
        return []

    def update_risk_score(
        self,
        entity: str,
        risk_modifier: float | int,
        *,
        entity_type: str = "system",
    ) -> dict[str, Any]:
        """Modify an entity's risk score via ``POST /public/v2/risks/risk_scores/{entity}``."""
        clean_type = str(entity_type or "system").strip()
        if clean_type not in MC_RISK_ENTITY_TYPES:
            raise ValueError(
                f"Unsupported risk entity_type '{entity_type}'. "
                f"Valid types: {', '.join(MC_RISK_ENTITY_TYPES)}."
            )
        encoded_entity = self._encode_id(entity)
        endpoint = self._mc_path(f"/risks/risk_scores/{encoded_entity}")
        body = {"risk_modifier": risk_modifier, "entity_type": clean_type}
        response = self.client._request("POST", endpoint, json=body)
        if response.status_code not in (200, 201):
            _raise_for_es_response(response, endpoint, f"update risk score for '{entity}'")
        try:
            payload = response.json()
        except ValueError:
            payload = {"message": "Risk score updated"}
        return payload if isinstance(payload, dict) else {"response": payload}

    # ------------------------------------------------------------------
    # Hybrid ES 8.6 MC v2 Primary + 7.x SPL / notable_update Fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_client_filters(
        item: Mapping[str, Any],
        *,
        tenant_id: str | None = None,
        security_domain: str | None = None,
        severity: str | None = None,
        entity: str | None = None,
        src: str | None = None,
        dest: str | None = None,
        user: str | None = None,
        file_hash: str | None = None,
        min_risk_score: float | None = None,
        rule_name: str | None = None,
        search_text: str | None = None,
        custom_filters: Mapping[str, str] | None = None,
    ) -> bool:
        if tenant_id and str(tenant_id).strip():
            needle = str(tenant_id).strip().casefold()
            item_tenant = str(item.get("tenant_id") or "").strip().casefold()
            if needle not in item_tenant:
                return False
        if security_domain and str(security_domain).strip():
            if str(security_domain).strip().casefold() not in str(
                item.get("security_domain") or ""
            ).casefold():
                return False
        if severity and str(severity).strip():
            if str(severity).strip().casefold() != str(item.get("severity") or "").strip().casefold():
                return False
        if entity and str(entity).strip():
            ent_needle = str(entity).strip().casefold()
            candidates = " ".join(
                str(item.get(k) or "")
                for k in ("entity", "risk_object", "src", "dest", "user")
            ).casefold()
            if ent_needle not in candidates:
                return False
        if src and str(src).strip():
            if str(src).strip().casefold() not in str(item.get("src") or "").casefold():
                return False
        if dest and str(dest).strip():
            if str(dest).strip().casefold() not in str(item.get("dest") or "").casefold():
                return False
        if user and str(user).strip():
            if str(user).strip().casefold() not in str(item.get("user") or "").casefold():
                return False
        if file_hash and str(file_hash).strip():
            fh_needle = str(file_hash).strip().casefold()
            raw_val_fh = item.get("raw")
            raw_obj_fh: Mapping[str, Any] = raw_val_fh if isinstance(raw_val_fh, Mapping) else {}
            cf_val_fh = item.get("custom_fields")
            cf_obj_fh: Mapping[str, Any] = cf_val_fh if isinstance(cf_val_fh, Mapping) else {}
            fh_blob = " ".join(
                str(src_map.get(k) or "")
                for src_map in (item, raw_obj_fh, cf_obj_fh)
                for k in ("file_hash", "sha256", "sha1", "md5")
            ).casefold()
            if fh_needle not in fh_blob:
                return False
        if min_risk_score is not None:
            raw_score = item.get("risk_score")
            try:
                score_val = float(raw_score) if raw_score not in (None, "") else -1.0
            except (TypeError, ValueError):
                score_val = -1.0
            if score_val < float(min_risk_score):
                return False
        if rule_name and str(rule_name).strip():
            rn_needle = str(rule_name).strip().casefold()
            title_blob = f"{item.get('rule_title', '')} {item.get('rule_name', '')}".casefold()
            if rn_needle not in title_blob:
                return False
        if custom_filters:
            raw_val_cf = item.get("raw")
            raw_obj_cf: Mapping[str, Any] = raw_val_cf if isinstance(raw_val_cf, Mapping) else {}
            cf_val_cf = item.get("custom_fields")
            cf_obj_cf: Mapping[str, Any] = cf_val_cf if isinstance(cf_val_cf, Mapping) else {}
            for cf_key, cf_val in custom_filters.items():
                target_k = str(cf_key).strip().casefold()
                target_v = str(cf_val).strip().casefold()
                if not target_k or not target_v:
                    continue
                found_val = ""
                for container in (cf_obj_cf, item, raw_obj_cf):
                    for k, v in container.items():
                        if isinstance(k, str) and k.casefold() == target_k and v is not None:
                            found_val = _stringify_field(v).casefold()
                            break
                    if found_val:
                        break
                if target_v not in found_val:
                    return False
        if search_text and str(search_text).strip():
            q = str(search_text).strip().casefold()
            top_blob = " ".join(
                str(v) for k, v in item.items() if k != "raw" and v is not None
            ).casefold()
            if q not in top_blob:
                raw_obj = item.get("raw")
                raw_blob = json.dumps(raw_obj, default=str).casefold() if raw_obj else ""
                if q not in raw_blob:
                    return False
        return True

    def _query_notables_spl_extended(
        self,
        *,
        earliest: str = "-24h",
        latest: str = "now",
        urgency: str | None = None,
        status: str | None = None,
        owner: str | None = None,
        disposition: str | None = None,
        rule_name: str | None = None,
        search_text: str | None = None,
        tenant_id: str | None = None,
        orig_sid: str | None = None,
        raw_query: str | None = None,
        custom_filters: Mapping[str, str] | None = None,
        limit: int = 100,
        timeout: int = 120,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, int(limit))
        clauses: list[str] = ["`notable`"]

        if urgency and urgency.strip():
            clean_urgency = urgency.strip().lower()
            if clean_urgency not in NOTABLE_URGENCIES:
                raise ValueError(f"Unsupported urgency '{urgency}'.")
            clauses.append(f'| search urgency="{_escape_spl_string(clean_urgency)}"')
        if status is not None and str(status).strip():
            status_code = normalize_notable_status(status)
            status_lbl = NOTABLE_STATUS_LABELS[status_code]
            clauses.append(
                f'| search (status={status_code} OR status_label="{_escape_spl_string(status_lbl)}")'
            )
        if owner and owner.strip():
            clauses.append(f'| search owner="{_escape_spl_string(owner)}"')
        if disposition and disposition.strip():
            legacy_disp = normalize_mc_disposition(disposition, for_mc_v2=False) or disposition.strip()
            disp_lbl = (
                _DISPOSITION_LABELS.get(disposition.strip().lower())
                or disposition_label(legacy_disp, fallback=disposition.strip())
            )
            clauses.append(
                f'| search (disposition="{_escape_spl_string(legacy_disp)}" '
                f'OR disposition_label="*{_escape_spl_string(disp_lbl)}*")'
            )
        if rule_name and rule_name.strip():
            clauses.append(
                f'| search (rule_name="*{_escape_spl_string(rule_name)}*" '
                f'OR rule_title="*{_escape_spl_string(rule_name)}*")'
            )
        if orig_sid and orig_sid.strip():
            clauses.append(f'| search orig_sid="{_escape_spl_string(orig_sid)}"')
        if raw_query and raw_query.strip():
            clauses.append(f'| search _raw="*{_escape_spl_string(raw_query)}*"')
        if tenant_id and tenant_id.strip():
            cfg = get_splunk_es_tenant_settings()
            esc_tenant = _escape_spl_string(tenant_id)
            tenant_or = " OR ".join(f'{k}="{esc_tenant}"' for k in cfg.all_tenant_keys)
            clauses.append(f"| search ({tenant_or})")
        if custom_filters:
            for cf_k, cf_v in custom_filters.items():
                clean_k = "".join(ch for ch in str(cf_k) if ch.isalnum() or ch in ("_", "."))
                if clean_k and str(cf_v).strip():
                    clauses.append(f'| search {clean_k}="*{_escape_spl_string(str(cf_v))}*"')
        if search_text and search_text.strip():
            clauses.append(f'| search "*{_escape_spl_string(search_text)}*"')

        clauses.append(f"| head {safe_limit}")
        spl = " ".join(clauses)
        res = self.client.run_search(
            spl,
            earliest=earliest,
            latest=latest,
            app=self.app,
            count=safe_limit,
            timeout=timeout,
        )
        if res.get("status") != "success":
            raise SplunkESError(
                str(res.get("error_message") or "Failed to query Splunk ES notable events."),
                messages=list(res.get("messages") or []),
            )
        rows = res.get("results") or []
        tenant_cfg = get_splunk_es_tenant_settings()
        return [
            normalize_finding(
                row,
                tenant_cfg=tenant_cfg,
                pinned_fields=tenant_cfg.custom_fields,
                source_backend="spl_fallback",
            )
            for row in rows
            if isinstance(row, dict)
        ]

    def query_findings_hybrid(
        self,
        *,
        earliest: str = "-24h",
        latest: str = "now",
        urgency: str | None = None,
        status: str | None = None,
        owner: str | None = None,
        disposition: str | None = None,
        rule_name: str | None = None,
        search_text: str | None = None,
        tenant_id: str | None = None,
        security_domain: str | None = None,
        severity: str | None = None,
        entity: str | None = None,
        src: str | None = None,
        dest: str | None = None,
        user: str | None = None,
        file_hash: str | None = None,
        min_risk_score: float | None = None,
        orig_sid: str | None = None,
        raw_query: str | None = None,
        custom_filters: Mapping[str, str] | None = None,
        item_type: str = "all",
        limit: int = 100,
        offset: int = 0,
        sort: str | None = None,
        use_spl: bool = False,
        include_investigations: bool = False,
    ) -> dict[str, Any]:
        """Hybrid ES 8.6 MC v2 primary + 7.x SPL `` `notable` `` fallback query coordinator.

        Mission Control v2 ``/findings`` silently ignores unknown query parameters such as
        ``tenant_id``, ``_raw``, ``orig_sid``, or custom fields. This coordinator NEVER passes
        those parameters to MC v2: SPL-only filters (``_raw``, ``orig_sid``) route directly to
        SPL `` `notable` ``, while client-side filters paginate MC v2 pages and filter locally,
        falling back to SPL on HTTP 404.
        """
        safe_limit = max(1, int(limit))
        safe_offset = max(0, int(offset))
        clean_type = str(item_type or "all").strip().lower()

        has_spl_only = bool(
            use_spl
            or (raw_query and raw_query.strip())
            or (orig_sid and orig_sid.strip())
        )
        has_client_filters = any(
            [
                bool(tenant_id and tenant_id.strip()),
                bool(security_domain and security_domain.strip()),
                bool(severity and severity.strip()),
                bool(entity and entity.strip()),
                bool(src and src.strip()),
                bool(dest and dest.strip()),
                bool(user and user.strip()),
                bool(file_hash and file_hash.strip()),
                min_risk_score is not None,
                bool(search_text and search_text.strip()),
                bool(custom_filters),
            ]
        )

        if has_spl_only:
            spl_items = self._query_notables_spl_extended(
                earliest=earliest,
                latest=latest,
                urgency=urgency,
                status=status,
                owner=owner,
                disposition=disposition,
                rule_name=rule_name,
                search_text=search_text,
                tenant_id=tenant_id,
                orig_sid=orig_sid,
                raw_query=raw_query,
                custom_filters=custom_filters,
                limit=safe_limit,
            )
            filtered_spl = [
                it
                for it in spl_items
                if self._matches_client_filters(
                    it,
                    tenant_id=tenant_id,
                    security_domain=security_domain,
                    severity=severity,
                    entity=entity,
                    src=src,
                    dest=dest,
                    user=user,
                    file_hash=file_hash,
                    min_risk_score=min_risk_score,
                    rule_name=rule_name,
                    search_text=search_text,
                    custom_filters=custom_filters,
                )
            ]
            return {
                "items": filtered_spl,
                "offset": 0,
                "limit": safe_limit,
                "total": len(filtered_spl),
                "source_backend": "spl_fallback",
            }

        try:
            collected: list[dict[str, Any]] = []
            total = 0

            if clean_type == "investigations":
                mc_disp = normalize_mc_disposition(disposition, for_mc_v2=True)
                if not has_client_filters:
                    invs = self.list_investigations(
                        limit=safe_limit,
                        offset=safe_offset,
                        sort=sort,
                        disposition=mc_disp,
                        status=status,
                        owner=owner,
                        urgency=urgency,
                    )
                    collected.extend(invs)
                    total = len(invs)
                else:
                    page_size = min(max(safe_limit * 2, 100), 200)
                    cur_offset = 0
                    max_pages = 5
                    for _ in range(max_pages):
                        invs = self.list_investigations(
                            limit=page_size,
                            offset=cur_offset,
                            sort=sort,
                            disposition=mc_disp,
                            status=status,
                            owner=owner,
                            urgency=urgency,
                        )
                        collected.extend(invs)
                        cur_offset += len(invs)
                        if not invs or len(invs) < page_size:
                            break
                    total = len(collected)
            else:
                search_groups: bool | None = None
                if clean_type == "finding_groups":
                    search_groups = True
                elif clean_type == "findings":
                    search_groups = False

                mc_disp = normalize_mc_disposition(disposition, for_mc_v2=True)
                if not has_client_filters:
                    page = self.list_findings(
                        urgency=urgency,
                        status=status,
                        owner=owner,
                        disposition=mc_disp,
                        earliest=earliest,
                        latest=latest,
                        rule_title=rule_name,
                        limit=safe_limit,
                        offset=safe_offset,
                        sort=sort,
                        search_finding_groups=search_groups,
                    )
                    collected.extend(page["items"])
                    total = int(page.get("total", len(collected)))
                else:
                    # Paginate MC v2 pages and filter client-side (MC v2 ignores unknown params)
                    page_size = min(max(safe_limit * 2, 100), 200)
                    cur_offset = 0
                    max_pages = 5
                    for _ in range(max_pages):
                        page = self.list_findings(
                            urgency=urgency,
                            status=status,
                            owner=owner,
                            disposition=mc_disp,
                            earliest=earliest,
                            latest=latest,
                            rule_title=rule_name,
                            limit=page_size,
                            offset=cur_offset,
                            sort=sort,
                            search_finding_groups=search_groups,
                        )
                        page_items = page["items"]
                        collected.extend(page_items)
                        total = int(page.get("total", len(collected)))
                        cur_offset += len(page_items)
                        if not page_items or cur_offset >= total or len(page_items) < page_size:
                            break

                if clean_type == "all" and include_investigations:
                    try:
                        invs = self.list_investigations(
                            limit=50,
                            offset=0,
                            urgency=urgency,
                            status=status,
                            owner=owner,
                        )
                        existing_ids = {str(it.get("event_id") or "") for it in collected}
                        for inv in invs:
                            if str(inv.get("event_id") or "") not in existing_ids:
                                collected.append(inv)
                    except SplunkESError:
                        pass

            if has_client_filters:
                filtered = [
                    it
                    for it in collected
                    if self._matches_client_filters(
                        it,
                        tenant_id=tenant_id,
                        security_domain=security_domain,
                        severity=severity,
                        entity=entity,
                        src=src,
                        dest=dest,
                        user=user,
                        file_hash=file_hash,
                        min_risk_score=min_risk_score,
                        rule_name=rule_name,
                        search_text=search_text,
                        custom_filters=custom_filters,
                    )
                ]
                paged = filtered[safe_offset : safe_offset + safe_limit]
                return {
                    "items": paged,
                    "offset": safe_offset,
                    "limit": safe_limit,
                    "total": len(filtered),
                    "source_backend": "mc_v2",
                }

            return {
                "items": collected[:safe_limit],
                "offset": safe_offset,
                "limit": safe_limit,
                "total": total,
                "source_backend": "mc_v2",
            }
        except SplunkESError as exc:
            if exc.status_code != 404:
                raise
            logger.info("Mission Control v2 endpoint returned 404; falling back to SPL `notable`.")
            spl_items = self._query_notables_spl_extended(
                earliest=earliest,
                latest=latest,
                urgency=urgency,
                status=status,
                owner=owner,
                disposition=disposition,
                rule_name=rule_name,
                search_text=search_text,
                tenant_id=tenant_id,
                custom_filters=custom_filters,
                limit=safe_limit,
            )
            filtered_spl = [
                it
                for it in spl_items
                if self._matches_client_filters(
                    it,
                    tenant_id=tenant_id,
                    security_domain=security_domain,
                    severity=severity,
                    entity=entity,
                    src=src,
                    dest=dest,
                    user=user,
                    file_hash=file_hash,
                    min_risk_score=min_risk_score,
                    rule_name=rule_name,
                    search_text=search_text,
                    custom_filters=custom_filters,
                )
            ]
            return {
                "items": filtered_spl,
                "offset": 0,
                "limit": safe_limit,
                "total": len(filtered_spl),
                "source_backend": "spl_fallback",
            }

    def triage_findings_hybrid(
        self,
        record_ids: Sequence[str],
        *,
        status: int | str | None = None,
        urgency: str | None = None,
        owner: str | None = None,
        disposition: str | None = None,
        sensitivity: str | None = None,
        queue_id: str | None = None,
        note: str | None = None,
        earliest: str | None = None,
        latest: str | None = None,
    ) -> dict[str, Any]:
        """Triage one or more findings/investigations via MC v2 ``bulk_update`` with 404 fallback."""
        clean_ids = [str(rid).strip() for rid in record_ids if str(rid).strip()]
        if not clean_ids:
            raise ValueError("At least one record ID is required.")
        try:
            results = self.bulk_update_findings(
                record_ids=clean_ids,
                earliest=earliest,
                latest=latest,
                status=status,
                urgency=urgency,
                owner=owner,
                disposition=disposition,
                sensitivity=sensitivity,
                queue_id=queue_id,
                investigation_note=note,
            )
            return {"backend": "mc_v2", "results": results, "updated_ids": clean_ids}
        except SplunkESError as exc:
            if exc.status_code != 404:
                raise
            legacy_disp = normalize_mc_disposition(disposition, for_mc_v2=False)
            legacy_status = status
            if isinstance(legacy_status, str) and legacy_status.strip().lower() == "unassigned":
                legacy_status = None
            res = self.update_notable(
                clean_ids,
                status=legacy_status,
                urgency=urgency,
                owner=owner,
                disposition=legacy_disp,
                comment=note,
            )
            return {"backend": "notable_update", "result": res, "updated_ids": clean_ids}

    # ------------------------------------------------------------------
    # Splunk Users & Adaptive Response (Modular Action Invocations/Dispatch)
    # ------------------------------------------------------------------

    def list_users(self, *, count: int = 200) -> list[dict[str, Any]]:
        """List Splunk users for owner assignment pickers."""
        return self.client.list_users(count=count)

    def get_current_user(self) -> str:
        """Return the current authenticated Splunk username."""
        return self.client.get_current_user()

    def list_modaction_invocations(self, sid: str, rid: str) -> list[dict[str, Any]]:
        """List Adaptive Response modular action invocations for ``(sid, rid)``."""
        clean_sid = str(sid or "").strip()
        clean_rid = str(rid or "").strip()
        if not clean_sid or not clean_rid:
            return []

        endpoint = (
            "/servicesNS/nobody/SA-ThreatIntelligence/alerts/modaction_invocations"
            f"?output_mode=json&sid={quote(clean_sid, safe='')}&rid={quote(clean_rid, safe='')}"
        )
        response = self.client._request("GET", endpoint)
        if response.status_code == 404:
            return []
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, "list Adaptive Response invocations")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned from modaction_invocations: {exc}",
                endpoint=endpoint,
            ) from exc
        responses = payload.get("responses") if isinstance(payload, dict) else None
        if isinstance(responses, list):
            return [row for row in responses if isinstance(row, dict)]
        return []

    def list_adaptive_response_actions(
        self,
        *,
        adhoc_only: bool = True,
        count: int = 100,
    ) -> list[dict[str, Any]]:
        """List available Splunk ES Adaptive Response actions parsing ``param._cam``."""
        safe_count = max(0, int(count))
        endpoint = f"/servicesNS/-/-/alerts/alert_actions?output_mode=json&count={safe_count}"
        response = self.client._request("GET", endpoint)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, "list Adaptive Response actions")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned from alert_actions: {exc}",
                endpoint=endpoint,
            ) from exc

        entries = payload.get("entry") if isinstance(payload, dict) else None
        actions: list[dict[str, Any]] = []
        if not isinstance(entries, list):
            return actions

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            content = entry.get("content")
            if not name or not isinstance(content, dict):
                continue

            raw_cam = content.get("param._cam")
            cam: dict[str, Any] = {}
            if isinstance(raw_cam, str) and raw_cam.strip():
                try:
                    loaded_cam = json.loads(raw_cam)
                    if isinstance(loaded_cam, dict):
                        cam = loaded_cam
                except ValueError:
                    cam = {}
            elif isinstance(raw_cam, dict):
                cam = raw_cam

            supports_adhoc = _safe_bool(cam.get("supports_adhoc"), False)
            if adhoc_only and not supports_adhoc:
                continue

            default_params: dict[str, str] = {}
            for k, v in content.items():
                if isinstance(k, str) and k.startswith("param.") and k != "param._cam":
                    param_key = k[len("param.") :]
                    if v is not None:
                        default_params[param_key] = str(v)

            actions.append(
                {
                    "name": name,
                    "label": str(content.get("label") or name).strip(),
                    "description": str(content.get("description") or "").strip(),
                    "supports_adhoc": supports_adhoc,
                    "category": cam.get("category") or [],
                    "task": cam.get("task") or [],
                    "required_params": list(cam.get("required_params") or []),
                    "field_name_params": list(cam.get("field_name_params") or []),
                    "default_params": default_params,
                }
            )
        return actions

    def dispatch_adaptive_response(
        self,
        action_name: str,
        *,
        sid: str,
        rid: str,
        params: Mapping[str, Any] | None = None,
        index: str | None = None,
    ) -> dict[str, Any]:
        """Dispatch an ad-hoc Adaptive Response action via ``POST /services/alerts/modaction_adhoc``."""
        clean_action = str(action_name or "").strip()
        clean_sid = str(sid or "").strip()
        clean_rid = str(rid or "").strip()
        if not clean_action:
            raise ValueError("Adaptive Response action_name is required.")
        if not clean_sid or not clean_rid:
            raise ValueError("Both sid and rid are required for ad-hoc Adaptive Response dispatch.")

        form_data: dict[str, str] = {
            "action_name": clean_action,
            "sid": clean_sid,
            "rid": clean_rid,
        }
        if index and str(index).strip():
            form_data["index"] = str(index).strip()
        if params:
            for k, v in params.items():
                key = str(k).strip()
                if not key or v is None:
                    continue
                if key.startswith("param."):
                    form_data[key] = str(v)
                else:
                    form_data[f"param.{key}"] = str(v)

        endpoint = "/services/alerts/modaction_adhoc?output_mode=json"
        response = self.client._request("POST", endpoint, data=form_data)
        if response.status_code not in (200, 201, 202):
            _raise_for_es_response(
                response,
                endpoint,
                f"dispatch Adaptive Response action '{clean_action}'",
            )
        try:
            body = response.json()
        except ValueError:
            body = {"success": True, "action_name": clean_action, "sid": clean_sid, "rid": clean_rid}
        return body if isinstance(body, dict) else {"response": body}
