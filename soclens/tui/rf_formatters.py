"""Schema-resilient normalizers and Rich renderables for the RF Intel & Alerts TUI."""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Sequence
from typing import Any

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from soclens.tui.image_render import render_screenshot_panel
from soclens.tui.pivot import make_pivot_text


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and (stripped.isdigit() or (stripped.startswith("-") and stripped[1:].isdigit())):
            return int(stripped)
    return None


def _extract_person(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("name", "email", "username", "id"):
            cand = value.get(key)
            if isinstance(cand, str) and cand.strip():
                return cand.strip()
    return str(value).strip()


_STRIP_PREFIXES: tuple[str, ...] = ("ip:", "idn:", "hash:", "url:", "uuid:")
_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")


def strip_rf_prefix(value: Any) -> str:
    """Strip Recorded Future type prefixes (``ip:``, ``idn:``, ``hash:``) for display."""
    text = _as_str(value).strip()
    lower = text.lower()
    for prefix in _STRIP_PREFIXES:
        if lower.startswith(prefix):
            return text[len(prefix) :].strip()
    return text


def _pretty_label(raw_key: str) -> str:
    spaced = _CAMEL_RE.sub(r"\1 \2", raw_key.replace("_", " "))
    return " ".join(w.capitalize() for w in spaced.split())


def format_timestamp(ts: Any) -> str:
    """Format an ISO-8601 timestamp compactly in the active timezone for tables and cards."""
    from soclens.timezone import format_iso_timestamp

    return format_iso_timestamp(ts)


def format_date_or_ts(ts: Any) -> str:
    """Format midnight ISO dates as ``YYYY-MM-DD`` and timestamps in the active timezone."""
    from soclens.timezone import format_iso_date_or_timestamp

    return format_iso_date_or_timestamp(ts)


def format_kv_summary(value: Any, *, max_items: int = 6) -> str:
    """Format arbitrary nested dict/list values cleanly without Python dict reprs."""
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        clean = strip_rf_prefix(value)
        if not clean:
            return "-"
        if _ISO_DATE_RE.match(clean):
            return format_date_or_ts(clean)
        return clean
    if isinstance(value, list):
        items = [
            format_kv_summary(v, max_items=max_items)
            for v in value
            if v not in (None, "", [], {})
        ]
        items = [it for it in items if it and it != "-"]
        if not items:
            return "-"
        shown = items[:max_items]
        suffix = f" (+{len(items) - max_items} more)" if len(items) > max_items else ""
        return ", ".join(shown) + suffix
    if isinstance(value, dict):
        parts: list[str] = []
        for k, v in value.items():
            if v in (None, "", [], {}):
                continue
            val_str = format_kv_summary(v, max_items=max_items)
            if val_str and val_str != "-":
                parts.append(f"{_pretty_label(str(k))}: {val_str}")
            if len(parts) >= max_items:
                break
        return " | ".join(parts) if parts else "-"
    return str(value)


def truncate_text(value: Any, max_len: int = 60) -> str:
    """Collapse whitespace and truncate text cleanly with an ASCII ellipsis."""
    text = " ".join(_as_str(value).split())
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def risk_color(score: int | None) -> str:
    """Map a 0-99 Recorded Future risk score to a Rich style string."""
    if score is None:
        return "dim"
    if score >= 90:
        return "bold red"
    if score >= 65:
        return "bold dark_orange"
    if score >= 25:
        return "bold yellow"
    if score >= 5:
        return "cyan"
    return "green"


def sandbox_score_color(score: int | None) -> str:
    """Map a 0-10 Sandbox score to a Rich style string."""
    if score is None:
        return "dim"
    if score >= 8:
        return "bold red"
    if score >= 5:
        return "bold yellow"
    if score >= 2:
        return "cyan"
    return "green"


def priority_text(priority: Any) -> Text:
    """Style a priority value safely as a Rich Text cell."""
    val = _as_str(priority).strip() or "-"
    low = val.lower()
    if low in {"critical", "high", "urgent"}:
        style = "bold red"
    elif low in {"moderate", "medium", "warn"}:
        style = "bold yellow"
    elif low in {"low", "informational", "info"}:
        style = "cyan"
    else:
        style = "dim"
    return Text(val, style=style)


def status_text(status: Any) -> Text:
    """Style an alert/case/sample status value safely as a Rich Text cell."""
    val = _as_str(status).strip() or "-"
    low = val.lower()
    if low in {"new", "open", "pending"}:
        style = "bold cyan"
    elif low in {"inprogress", "in_progress", "in progress", "running", "assigned"}:
        style = "bold yellow"
    elif low in {"resolved", "closed", "reported", "done"}:
        style = "green"
    elif low in {"dismissed", "false_positive", "failed", "error"}:
        style = "dim" if low in {"dismissed", "false_positive"} else "bold red"
    else:
        style = "white"
    return Text(val, style=style)


STATUS_FILTER_CHOICES: tuple[tuple[str, str], ...] = (
    ("New", "New"),
    ("InProg", "InProgress"),
    ("Pending", "Pending"),
    ("Assigned", "Assigned"),
    ("Open", "Open"),
    ("Actionable", "Actionable"),
    ("Resolved", "Resolved"),
    ("Dismissed", "Dismissed"),
    ("Closed", "Closed"),
)

PLAYBOOK_API_STATUS_MAP: dict[str, str] = {
    "new": "New",
    "inprogress": "InProgress",
    "pending": "Pending",
    "dismissed": "Dismissed",
    "resolved": "Resolved",
}


def normalize_status_key(value: Any) -> str:
    """Normalize alert/case status names across casing, spaces, underscores, and hyphens."""
    raw = _as_str(value).strip().lower()
    return re.sub(r"[\s_-]+", "", raw)


def status_matches_filter(item_status: Any, selected_statuses: Collection[str]) -> bool:
    """Return True if ``item_status`` matches any status in ``selected_statuses`` (empty = all)."""
    if not selected_statuses:
        return True
    normalized_selected = {
        normalize_status_key(st) for st in selected_statuses if normalize_status_key(st)
    }
    if not normalized_selected:
        return True
    return normalize_status_key(item_status) in normalized_selected


def score_text(score: int | None, max_score: int = 99) -> Text:
    """Render a numeric score with severity color."""
    if score is None:
        return Text("-", style="dim")
    style = sandbox_score_color(score) if max_score <= 10 else risk_color(score)
    return Text(str(score), style=style)


def risk_gauge(score: int | None, max_score: int = 99, width: int = 16) -> Text:
    """Build an ASCII bar gauge like ``[############----] 75/99``."""
    if score is None:
        return Text("[" + "-" * width + "] N/A", style="dim")
    bounded = max(0, min(score, max_score))
    filled = int(round((bounded / max_score) * width)) if max_score > 0 else 0
    bar = "#" * filled + "-" * max(0, width - filled)
    style = sandbox_score_color(score) if max_score <= 10 else risk_color(score)
    return Text(f"[{bar}] {score}/{max_score}", style=style)


# ---------------------------------------------------------------------------
# Payload Extractors (support both live RF API & mock E2E schemas)
# ---------------------------------------------------------------------------


def extract_alerts_v3(payload: Any) -> tuple[list[dict[str, Any]], int | None]:
    """Extract classic Alerts v3 items and optional total count."""
    if isinstance(payload, list):
        items = [x for x in payload if isinstance(x, dict)]
        return items, len(items)
    if not isinstance(payload, dict):
        return [], None
    data = payload.get("data")
    extracted: list[dict[str, Any]] = []
    if isinstance(data, list):
        extracted = [x for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        res = data.get("results")
        if isinstance(res, list):
            extracted = [x for x in res if isinstance(x, dict)]
    counts = _as_dict(payload.get("counts"))
    total = _as_int(counts.get("total"))
    return extracted, total


def extract_playbook_alerts(payload: Any) -> tuple[list[dict[str, Any]], int | None]:
    """Extract Playbook Alert search rows and optional total count."""
    if isinstance(payload, list):
        items = [x for x in payload if isinstance(x, dict)]
        return items, len(items)
    if not isinstance(payload, dict):
        return [], None
    raw_data = payload.get("data")
    items = [x for x in raw_data if isinstance(x, dict)] if isinstance(raw_data, list) else []
    counts = _as_dict(payload.get("counts"))
    total = _as_int(counts.get("total"))
    return items, total


def extract_cases(payload: Any) -> tuple[list[dict[str, Any]], int | None]:
    """Extract Case search rows and optional total count."""
    if isinstance(payload, list):
        items = [x for x in payload if isinstance(x, dict)]
        return items, len(items)
    if not isinstance(payload, dict):
        return [], None
    raw_data = payload.get("data")
    items = [x for x in raw_data if isinstance(x, dict)] if isinstance(raw_data, list) else []
    counts = _as_dict(payload.get("counts"))
    total = _as_int(payload.get("total_count"))
    if total is None:
        total = _as_int(counts.get("total"))
    return items, total


def extract_soar_results(payload: Any) -> list[dict[str, Any]]:
    """Extract SOAR v3 enrichment/triage results."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, list):
            return [x for x in results if isinstance(x, dict)]
        if "triage" in data and isinstance(data["triage"], dict):
            return [data["triage"]]
    elif isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    results = payload.get("results")
    if isinstance(results, list):
        return [x for x in results if isinstance(x, dict)]
    return []


def extract_sandbox_samples(payload: Any) -> list[dict[str, Any]]:
    """Extract Sandbox v0 search sample records from either ``samples`` or ``data``."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("samples", "data"):
        val = payload.get(key)
        if isinstance(val, list):
            return [x for x in val if isinstance(x, dict)]
    return []


# ---------------------------------------------------------------------------
# Normalizers
# ---------------------------------------------------------------------------


def _first_entity_label(item: dict[str, Any]) -> str:
    for hit in _as_list(item.get("hits")):
        hit_d = _as_dict(hit)
        prim = _as_dict(hit_d.get("primary_entity"))
        if prim.get("name") or prim.get("id"):
            return _as_str(prim.get("name") or prim.get("id"))
        for ent in _as_list(hit_d.get("entities")):
            ent_d = _as_dict(ent)
            if ent_d.get("name") or ent_d.get("id"):
                return _as_str(ent_d.get("name") or ent_d.get("id"))
    for ent in _as_list(item.get("enriched_entities")):
        ent_d = _as_dict(ent)
        entity_inner = _as_dict(ent_d.get("entity")) or ent_d
        if entity_inner.get("name") or entity_inner.get("id"):
            return _as_str(entity_inner.get("name") or entity_inner.get("id"))
    for trig in _as_list(item.get("triggered_by")):
        trig_d = _as_dict(trig)
        ref = _as_str(trig_d.get("reference_id"))
        if ref:
            return ref
    return ""


def normalize_alert_v3(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize a classic Alert v3 record across live & mock schemas."""
    review = _as_dict(item.get("review"))
    rule = _as_dict(item.get("rule")) or _as_dict(item.get("alertRule"))
    log = _as_dict(item.get("log"))
    url_obj = _as_dict(item.get("url"))
    ai = _as_dict(item.get("ai_insights"))
    org_obj = _as_dict(item.get("owner_organisation_details"))

    status = _as_str(
        review.get("status_in_portal")
        or item.get("statusInPortal")
        or review.get("status")
        or item.get("status")
        or "New"
    )
    priority = _as_str(review.get("priority") or item.get("priority") or "-")
    assignee = _extract_person(review.get("assignee") if "assignee" in review else item.get("assignee"))
    note = _as_str(review.get("note") or item.get("note"))
    rule_name = _as_str(rule.get("name") or rule.get("label") or "-")
    rule_id = _as_str(rule.get("id"))
    triggered = _as_str(log.get("triggered") or item.get("triggered"))
    status_date = _as_str(log.get("status_date"))
    portal_url = _as_str(url_obj.get("portal") or item.get("portalUrl"))
    hits = [h for h in _as_list(item.get("hits")) if isinstance(h, dict)]
    ai_text = _as_str(ai.get("text") or ai.get("comment")).strip()
    org_name = _as_str(org_obj.get("enterprise_name") or item.get("organisation_name"))

    return {
        "kind": "alerts_v3",
        "id": _as_str(item.get("id")),
        "title": _as_str(item.get("title") or rule_name or item.get("id")),
        "type": _as_str(item.get("type") or "-"),
        "status": status,
        "priority": priority,
        "assignee": assignee,
        "note": note,
        "rule_name": rule_name,
        "rule_id": rule_id,
        "triggered": triggered,
        "status_date": status_date,
        "portal_url": portal_url,
        "hits": hits,
        "hits_count": len(hits),
        "ai_insights": ai_text,
        "org_name": org_name,
        "primary_entity": _first_entity_label(item),
        "raw": item,
    }


def extract_playbook_screenshots(ev: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract normalized, deduplicated screenshot metadata entries from Playbook evidence."""
    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for key in ("screenshots", "screenshot_ids", "screenshot_mentions"):
        for sc in _as_list(ev.get(key)):
            if isinstance(sc, str) and sc.strip():
                img_id = sc.strip()
                if img_id in seen_ids:
                    continue
                seen_ids.add(img_id)
                entries.append(
                    {
                        "image_id": img_id,
                        "description": "",
                        "created": "",
                        "availability": "",
                        "tag": "",
                    }
                )
            elif isinstance(sc, dict):
                raw_id = sc.get("image_id") or sc.get("id") or sc.get("screenshot_id")
                img_id = _as_str(raw_id).strip()
                if not img_id or img_id in seen_ids:
                    continue
                seen_ids.add(img_id)
                entries.append(
                    {
                        "image_id": img_id,
                        "description": _as_str(sc.get("description")).strip(),
                        "created": _as_str(sc.get("created")).strip(),
                        "availability": _as_str(sc.get("availability")).strip(),
                        "tag": _as_str(sc.get("tag")).strip(),
                    }
                )
    return entries


def _extract_pb_logo_and_screenshots(
    ev: dict[str, Any],
) -> tuple[list[str], list[str], list[str], list[dict[str, Any]]]:
    logo_hashes: list[str] = []
    logotypes: list[str] = []

    for asset in _as_list(ev.get("assets")):
        if not isinstance(asset, dict):
            continue
        atype = _as_str(asset.get("type")).lower()
        if atype == "image_hash" and asset.get("hash_id"):
            logo_hashes.append(_as_str(asset["hash_id"]))
        elif atype == "logotype" and asset.get("logotype_id"):
            logotypes.append(_as_str(asset["logotype_id"]))

    for h in _as_list(ev.get("hashes")):
        hs = _as_str(h).strip()
        if hs and hs not in logo_hashes:
            logo_hashes.append(hs)

    screenshots_meta = extract_playbook_screenshots(ev)
    screenshot_ids = [
        sc["image_id"]
        for sc in screenshots_meta
        if sc.get("availability", "").lower() != "unavailable"
    ]

    return logo_hashes, logotypes, screenshot_ids, screenshots_meta


def normalize_playbook_alert(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Playbook Alert from search summary or category detail."""
    pstatus = _as_dict(item.get("panel_status"))
    ev = _as_dict(item.get("panel_evidence_summary"))
    alert_rule = _as_dict(item.get("alert_rule")) or _as_dict(pstatus.get("alert_rule"))

    aid = _as_str(item.get("playbook_alert_id") or item.get("id"))
    category = _as_str(item.get("category") or pstatus.get("category") or "-")
    status = _as_str(item.get("status") or pstatus.get("status") or "New")
    priority = _as_str(item.get("priority") or pstatus.get("priority") or "-")
    rule_name = _as_str(
        alert_rule.get("label")
        or alert_rule.get("name")
        or pstatus.get("case_rule_label")
        or item.get("rule_id")
        or "-"
    )
    title = _as_str(item.get("title") or pstatus.get("entity_name") or rule_name or aid)
    assignee = _extract_person(
        item.get("assignee")
        if item.get("assignee") is not None
        else (pstatus.get("assignee_name") or pstatus.get("assignee"))
    )
    created = _as_str(item.get("created") or pstatus.get("created"))
    updated = _as_str(item.get("updated") or pstatus.get("updated") or created)
    risk_score = _as_int(pstatus.get("risk_score") if "risk_score" in pstatus else item.get("risk_score"))
    entity_name = _as_str(pstatus.get("entity_name") or item.get("entity_name"))

    targets_raw = pstatus.get("targets") if pstatus.get("targets") else ev.get("targets")
    targets = [_as_str(t) for t in _as_list(targets_raw) if t]
    attackers = [_as_str(a) for a in _as_list(pstatus.get("attackers")) if a]
    actions_taken = [
        _as_str(a) for a in _as_list(item.get("actions_taken") or pstatus.get("actions_taken")) if a
    ]
    logo_hashes, logotypes, screenshot_ids, screenshots_meta = _extract_pb_logo_and_screenshots(ev)

    return {
        "kind": "playbook",
        "id": aid,
        "category": category,
        "status": status,
        "priority": priority,
        "title": title,
        "rule_name": rule_name,
        "assignee": assignee,
        "created": created,
        "updated": updated,
        "risk_score": risk_score,
        "entity_name": entity_name,
        "targets": targets,
        "attackers": attackers,
        "actions_taken": actions_taken,
        "logo_hashes": logo_hashes,
        "logotypes": logotypes,
        "screenshot_ids": screenshot_ids,
        "screenshots_meta": screenshots_meta,
        "raw": item,
    }


def normalize_case(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Case record from ``/case/search`` or ``/case/lookup``."""
    summary = _as_dict(item.get("summary"))
    details = _as_dict(item.get("details"))
    cid = _as_str(item.get("id") or summary.get("id"))
    title = _as_str(item.get("title") or item.get("name") or summary.get("title") or cid)
    status = _as_str(item.get("status") or summary.get("status") or "Open")
    priority = _as_str(item.get("priority") or summary.get("priority") or "-")
    assignee = _extract_person(
        item.get("assignee") if "assignee" in item else summary.get("assignee")
    )
    created = _as_str(item.get("created") or summary.get("created"))
    updated = _as_str(
        item.get("updated") or item.get("modified") or summary.get("modified") or created
    )
    description = _as_str(
        item.get("description") or details.get("description") or summary.get("description")
    )
    log_entries = [x for x in _as_list(item.get("log")) if isinstance(x, dict)]

    return {
        "kind": "cases",
        "id": cid,
        "title": title,
        "status": status,
        "priority": priority,
        "assignee": assignee,
        "created": created,
        "updated": updated,
        "description": description,
        "log": log_entries,
        "raw": item,
    }


def normalize_v2_record(
    entity_type: str, query_value: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Normalize a Connect v2 lookup or company-by-domain payload."""
    data = _as_dict(payload.get("data")) if isinstance(payload.get("data"), dict) else payload
    ent = _as_dict(data.get("entity"))
    risk = _as_dict(data.get("risk"))
    timestamps = _as_dict(data.get("timestamps"))
    evidence = [e for e in _as_list(risk.get("evidenceDetails")) if isinstance(e, dict)]
    threat_lists = [t for t in _as_list(data.get("threatLists")) if isinstance(t, dict)]
    counts = [c for c in _as_list(data.get("counts")) if isinstance(c, dict)]
    related = [r for r in _as_list(data.get("relatedEntities")) if isinstance(r, dict)]

    score = _as_int(risk.get("score"))
    rules_count = _as_int(risk.get("rules"))
    if rules_count is None and evidence:
        rules_count = len(evidence)

    ent_id = _as_str(ent.get("id") or query_value)
    ent_name = _as_str(ent.get("name") or query_value)
    rf_type = _as_str(ent.get("type") or entity_type)

    return {
        "kind": "intel_v2",
        "id": ent_id,
        "entity_type": entity_type,
        "query_value": query_value,
        "name": ent_name,
        "rf_type": rf_type,
        "risk_score": score,
        "risk_level": _as_int(risk.get("criticality") if "criticality" in risk else risk.get("level")),
        "risk_string": _as_str(risk.get("riskString")),
        "risk_summary": _as_str(risk.get("riskSummary")),
        "criticality_label": _as_str(risk.get("criticalityLabel") or "-"),
        "rules_count": rules_count if rules_count is not None else 0,
        "evidence_details": evidence,
        "threat_lists": threat_lists,
        "timestamps": timestamps,
        "intel_card": _as_str(data.get("intelCard")),
        "location": _as_dict(data.get("location")),
        "hash_algorithm": _as_str(data.get("hashAlgorithm")),
        "cvss": _as_dict(data.get("cvss")),
        "nvd_description": _as_str(data.get("nvdDescription")),
        "lifecycle_stage": _as_str(data.get("lifecycleStage")),
        "counts": counts,
        "related_entities": related,
        "raw": payload,
    }


def normalize_soar_item(
    item: dict[str, Any], *, mode: str = "enrich", context: str = ""
) -> dict[str, Any]:
    """Normalize a single SOAR v3 enrichment or triage result item."""
    ent = _as_dict(item.get("entity"))
    risk = _as_dict(item.get("risk"))
    rule_obj = _as_dict(risk.get("rule"))
    risk_contexts = _as_dict(risk.get("context"))

    evidence_raw = rule_obj.get("evidence") if rule_obj.get("evidence") else risk.get("evidenceDetails")
    evidence = [e for e in _as_list(evidence_raw) if isinstance(e, dict)]

    score = _as_int(risk.get("score") if "score" in risk else item.get("score"))
    level = _as_int(risk.get("level") if "level" in risk else item.get("level"))
    verdict_val = item.get("verdict")
    if isinstance(verdict_val, bool):
        verdict = "MALICIOUS" if verdict_val else "BENIGN"
    elif isinstance(verdict_val, dict):
        verdict = _as_str(verdict_val.get("label") or verdict_val.get("verdict") or "-")
    elif verdict_val is not None:
        verdict = _as_str(verdict_val)
    else:
        verdict = "-"

    top_rule = ""
    if evidence:
        first_ev = evidence[0]
        top_rule = _as_str(first_ev.get("rule") or first_ev.get("name") or "")

    return {
        "kind": "soar",
        "mode": mode,
        "id": _as_str(ent.get("id") or item.get("id")),
        "type": _as_str(ent.get("type") or item.get("type") or "-"),
        "name": _as_str(ent.get("name") or ent.get("id") or "-"),
        "score": score,
        "level": level,
        "verdict": verdict,
        "context": _as_str(context or item.get("context") or "-"),
        "risk_contexts": risk_contexts,
        "evidence": evidence,
        "top_rule": top_rule,
        "raw": item,
    }


def normalize_entity_match(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize an Entity Match candidate."""
    aliases = [_as_str(a) for a in _as_list(item.get("aliases")) if a]
    return {
        "kind": "entity_match",
        "id": _as_str(item.get("id")),
        "type": _as_str(item.get("type") or "-"),
        "name": _as_str(item.get("name") or item.get("id")),
        "aliases": aliases,
        "raw": item,
    }


def normalize_sandbox_sample(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Sandbox v0 search sample or overview payload."""
    sample_block = _as_dict(item.get("sample"))
    analysis_block = _as_dict(item.get("analysis"))
    src = sample_block or item

    score = _as_int(
        src.get("score") if "score" in src else analysis_block.get("score")
    )
    family_raw = src.get("family") or analysis_block.get("family") or []
    if isinstance(family_raw, list):
        families = [_as_str(f) for f in family_raw if f]
    elif family_raw:
        families = [_as_str(family_raw)]
    else:
        families = []

    tags_raw = src.get("tags") or analysis_block.get("tags") or []
    tags = [_as_str(t) for t in _as_list(tags_raw) if t]

    return {
        "kind": "sandbox",
        "id": _as_str(src.get("id") or item.get("id")),
        "score": score,
        "status": _as_str(src.get("status") or "-"),
        "target": _as_str(src.get("target") or src.get("filename") or src.get("url") or "-"),
        "sample_kind": _as_str(src.get("kind") or "-"),
        "sha256": _as_str(src.get("sha256")),
        "md5": _as_str(src.get("md5")),
        "submitted": _as_str(src.get("submitted") or src.get("created")),
        "completed": _as_str(src.get("completed")),
        "families": families,
        "tags": tags,
        "raw": item,
    }


# ---------------------------------------------------------------------------
# Summary Strip Builder
# ---------------------------------------------------------------------------


def build_summary_bar_text(
    view_mode: str,
    total_loaded: int,
    filtered_count: int,
    total_remote: int | None,
    items: list[dict[str, Any]],
    *,
    active_filter_summary: str = "",
) -> Text:
    """Build a compact single-line KPI strip with active filter badge and shortcut hints."""
    count_str = (
        f"{filtered_count}/{total_loaded}"
        if filtered_count != total_loaded
        else f"{total_loaded}"
    )
    if total_remote is not None and total_remote > total_loaded:
        count_str += f" (of {total_remote})"

    metrics: list[tuple[str, str]] = []
    if view_mode == "welcome":
        metrics.append(("Ready - load Alerts, Playbook Alerts, Cases, or run an IOC lookup", "dim"))
    elif view_mode in ("alerts_v3", "playbook", "cases"):
        label = {"alerts_v3": "Alerts v3", "playbook": "Playbook Alerts", "cases": "Cases"}[view_mode]
        new_cnt = sum(
            1 for it in items if str(it.get("status") or "").lower() in {"new", "open"}
        )
        prog_cnt = sum(
            1
            for it in items
            if str(it.get("status") or "").lower() in {"inprogress", "in_progress", "pending"}
        )
        high_cnt = sum(
            1
            for it in items
            if str(it.get("priority") or "").lower() in {"high", "critical"}
        )
        metrics.append((f"{label}: {count_str}", "bold cyan"))
        metrics.append((f"New/Open: {new_cnt}", "cyan"))
        metrics.append((f"Active: {prog_cnt}", "yellow"))
        metrics.append((f"High/Crit: {high_cnt}", "bold red" if high_cnt else "dim"))
    elif view_mode == "intel_v2":
        high_cnt = sum(1 for it in items if (it.get("risk_score") or 0) >= 65)
        metrics.append((f"IOC Intel (v2): {count_str}", "bold cyan"))
        metrics.append((f"High Risk (>=65): {high_cnt}", "bold red" if high_cnt else "green"))
    elif view_mode == "soar":
        high_cnt = sum(1 for it in items if (it.get("score") or 0) >= 65)
        metrics.append((f"SOAR Results: {count_str}", "bold cyan"))
        metrics.append((f"High Risk (>=65): {high_cnt}", "bold red" if high_cnt else "green"))
    elif view_mode == "entity_match":
        metrics.append((f"Entity Matches: {count_str}", "bold cyan"))
    elif view_mode == "sandbox":
        mal_cnt = sum(1 for it in items if (it.get("score") or 0) >= 7)
        metrics.append((f"Sandbox Samples: {count_str}", "bold cyan"))
        metrics.append((f"Score >=7: {mal_cnt}", "bold red" if mal_cnt else "green"))

    if active_filter_summary.strip():
        metrics.append((f"View: {active_filter_summary.strip()}", "bold magenta"))

    bar = Text()
    for idx, (label, style) in enumerate(metrics):
        if idx > 0:
            bar.append("  |  ", style="dim")
        bar.append(label, style=style)

    bar.append("   ::   [/] More  [r] Reload  [Enter] Detail  [t] Triage  [j] JSON  [m] Menu", style="dim")
    return bar


# ---------------------------------------------------------------------------
# Rich Renderables
# ---------------------------------------------------------------------------


def _kv_table(rows: Sequence[tuple[str, str | Text]], *, title: str | None = None) -> Table:
    table = Table(
        box=None,
        show_header=False,
        expand=True,
        padding=(0, 1),
        title=Text(title, style="bold cyan") if title else None,
        title_justify="left",
    )
    table.add_column("Field", style="bold dim", width=18, no_wrap=True)
    table.add_column("Value", overflow="fold")
    for k, v in rows:
        cell = v if isinstance(v, Text) else Text(_as_str(v) or "-")
        table.add_row(Text(k, style="bold dim"), make_pivot_text(cell, field=k))
    return table


def render_welcome_view() -> Group:
    """Render an actionable quick-start guide when no dataset has been loaded yet."""
    intro = Panel(
        Text.assemble(
            ("Recorded Future Threat Intelligence & Alert Triage Workbench\n", "bold cyan"),
            (
                "Select an operation above to inspect structured tables, risk gauges, "
                "evidence rules, brand logo hashes, and deep alert/case details.",
                "white",
            ),
        ),
        title=Text("RF Intel & Alerts Overview", style="bold cyan"),
        border_style="cyan",
        box=box.ROUNDED,
    )

    workflows = Table(
        box=box.SIMPLE_HEAD,
        expand=True,
        title=Text("Available Workflows", style="bold white"),
        title_justify="left",
    )
    workflows.add_column("Workflow", style="bold cyan", width=22, no_wrap=True)
    workflows.add_column("Action", overflow="fold")
    workflows.add_column("Interactive Capabilities", overflow="fold")

    workflows.add_row(
        Text("Alerts v3 & Playbooks", style="bold cyan"),
        Text("Click Load Alerts v3 or Load Playbook Alerts"),
        Text("View priority, rule, logo hashes; Enter for deep detail; [t] Triage; create Case"),
    )
    workflows.add_row(
        Text("Cases", style="bold cyan"),
        Text("Click Load Cases"),
        Text("Inspect investigation cases, audit logs, and update status/priority/assignee"),
    )
    workflows.add_row(
        Text("Connect v2 & Company", style="bold cyan"),
        Text("Pick IOC type + value -> v2 Lookup (or [/] -> Company by Domain)"),
        Text("Full Intelligence Card with risk gauge, evidence rules, threat lists, geolocation"),
    )
    workflows.add_row(
        Text("SOAR v3 Enrich/Triage", style="bold cyan"),
        Text("Comma-separated IOCs -> SOAR Enrich (or [/] -> SOAR Triage)"),
        Text("Batch risk scoring, context verdicts, and one-click Connect v2 pivot"),
    )
    workflows.add_row(
        Text("Entity Match & Sandbox", style="bold cyan"),
        Text("Enter query -> Entity Match or Search Sandbox"),
        Text("Disambiguate RF entities -> pivot to Watchlists/v2; inspect Sandbox signatures"),
    )

    keys = Panel(
        Text(
            "Shortcuts: [/] Filter & Tools   [Enter / Double-Click] Fetch Deep Detail   "
            "[t] Triage Status   [j] Toggle Raw JSON   [m / Right-Click] Context Menu",
            style="dim",
        ),
        border_style="dim",
        box=box.ROUNDED,
    )
    return Group(intro, workflows, keys)


def render_raw_json(payload: Any, *, title: str = "Raw JSON Payload") -> Panel:
    """Render formatted JSON using Rich Syntax inside a safe Panel."""
    formatted = json.dumps(payload, indent=2, default=str)
    syntax = Syntax(formatted, "json", theme="ansi_dark", word_wrap=True)
    return Panel(
        syntax,
        title=Text(title, style="bold yellow"),
        border_style="yellow",
        box=box.ROUNDED,
    )


def render_error_panel(context: str, detail: str) -> Panel:
    """Render an operator-friendly error panel for failed API calls."""
    return Panel(
        Text(detail, style="white"),
        title=Text(f"ERROR: {context}", style="bold red"),
        border_style="red",
        box=box.ROUNDED,
    )


def render_alert_v3_detail(
    norm: dict[str, Any], full_detail: dict[str, Any] | None = None
) -> Group:
    """Render a structured classic Alert v3 inspector view."""
    effective = normalize_alert_v3(full_detail) if full_detail else norm
    raw = _as_dict(effective.get("raw"))

    rows: list[tuple[str, str | Text]] = [
        ("Alert ID", effective["id"] or "-"),
        ("Title", effective["title"] or "-"),
        ("Status", status_text(effective["status"])),
        ("Priority", priority_text(effective["priority"])),
        ("Rule", effective["rule_name"] or "-"),
        ("Type", effective["type"] or "-"),
        ("Assignee", effective["assignee"] or "Unassigned"),
        ("Triggered", format_timestamp(effective["triggered"])),
        ("Primary Entity", strip_rf_prefix(effective["primary_entity"]) or "-"),
    ]
    log_obj = _as_dict(raw.get("log"))
    if effective.get("status_date") or log_obj.get("status_change_by"):
        st_parts = [format_timestamp(effective.get("status_date"))]
        if log_obj.get("status_change_by"):
            st_parts.append(f"by {log_obj['status_change_by']}")
        rows.append(("Status Updated", " ".join(p for p in st_parts if p and p != "-")))
    if effective.get("org_name"):
        rows.append(("Organization", effective["org_name"]))
    if effective.get("portal_url"):
        rows.append(("Portal URL", effective["portal_url"]))
    if effective.get("note"):
        rows.append(("Review Note", effective["note"]))

    renderables: list[RenderableType] = [
        Panel(
            _kv_table(rows),
            title=Text(f"Alert v3: {truncate_text(effective['title'], 56)}", style="bold cyan"),
            border_style="cyan",
            box=box.ROUNDED,
        )
    ]

    if effective.get("ai_insights"):
        renderables.append(
            Panel(
                Text(effective["ai_insights"]),
                title=Text("AI Insights", style="bold magenta"),
                border_style="magenta",
                box=box.ROUNDED,
            )
        )

    hits = effective.get("hits") or []
    if hits:
        hits_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Triggering Hits ({len(hits)})", style="bold white"),
            title_justify="left",
        )
        hits_table.add_column("Source / Document", style="cyan", ratio=2, overflow="fold")
        hits_table.add_column("Entities", style="yellow", ratio=2, overflow="fold")
        hits_table.add_column("Fragment", ratio=3, overflow="fold")
        for hit in hits[:25]:
            doc = _as_dict(hit.get("document"))
            src = _as_dict(doc.get("source"))
            doc_label = _as_str(doc.get("title") or src.get("name") or doc.get("url") or hit.get("id"))
            if doc.get("url") and doc.get("title"):
                doc_label = f"{doc['title']} ({doc['url']})"
            ents: list[str] = []
            for e in _as_list(hit.get("entities")):
                ed = _as_dict(e)
                label = strip_rf_prefix(ed.get("name") or ed.get("id"))
                if label and label not in ents:
                    ents.append(label)
            frag = truncate_text(hit.get("fragment") or "-", 200)
            hits_table.add_row(
                Text(truncate_text(doc_label, 80)),
                Text(", ".join(ents[:6]) if ents else "-"),
                Text(frag),
            )
        renderables.append(hits_table)
    else:
        trig_by = _as_list(raw.get("triggered_by"))
        if trig_by:
            renderables.append(
                Panel(
                    Text(
                        "References: "
                        + ", ".join(_as_str(_as_dict(t).get("reference_id")) for t in trig_by[:10])
                    ),
                    title=Text("Triggered References", style="bold white"),
                    border_style="dim",
                )
            )
        else:
            renderables.append(
                Panel(
                    Text("No hit fragments attached. Press Enter / Deep Detail to fetch full alert.", style="dim"),
                    border_style="dim",
                )
            )

    enriched = [e for e in _as_list(raw.get("enriched_entities")) if isinstance(e, dict)]
    if enriched:
        enr_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Enriched Entities ({len(enriched)})", style="bold white"),
            title_justify="left",
        )
        enr_table.add_column("Entity", style="cyan", ratio=2, overflow="fold")
        enr_table.add_column("Type", width=16)
        enr_table.add_column("Evidence / References", ratio=3, overflow="fold")
        for item in enriched[:15]:
            ent = _as_dict(item.get("entity"))
            ent_name = strip_rf_prefix(ent.get("name") or ent.get("id") or "")
            ent_type = _as_str(ent.get("type") or "-")
            ev_list = [_as_dict(x) for x in _as_list(item.get("evidence")) if isinstance(x, dict)]
            refs = [_as_dict(x) for x in _as_list(item.get("references")) if isinstance(x, dict)]
            summary_parts: list[str] = []
            if ev_list:
                summary_parts.append(
                    ", ".join(_as_str(e.get("rule") or format_kv_summary(e)) for e in ev_list[:3])
                )
            if refs:
                ref_ents: list[str] = []
                for ref in refs[:3]:
                    for re_item in _as_list(ref.get("entities"))[:4]:
                        rd = _as_dict(re_item)
                        rn = strip_rf_prefix(rd.get("name") or rd.get("id"))
                        if rn and rn not in ref_ents:
                            ref_ents.append(rn)
                if ref_ents:
                    summary_parts.append("Related: " + ", ".join(ref_ents[:6]))
            if not ent_name and refs:
                ent_name = "Document Entities"
            enr_table.add_row(
                Text(ent_name or "-"),
                Text(ent_type),
                Text(" | ".join(summary_parts) if summary_parts else "-"),
            )
        renderables.append(enr_table)

    return Group(*renderables)


_DNS_LIST_KEYS: tuple[tuple[str, str], ...] = (
    ("ip_list", "A"),
    ("aaaa_list", "AAAA"),
    ("mx_list", "MX"),
    ("ns_list", "NS"),
    ("cname_list", "CNAME"),
    ("txt_list", "TXT"),
)

_WHOIS_CONTACT_ROLES: dict[str, tuple[str, str]] = {
    "registrant": ("Registrant", "Registrant"),
    "technicalcontact": ("Technical Contact", "Technical"),
    "administrativecontact": ("Admin Contact", "Administrative"),
    "billingcontact": ("Billing Contact", "Billing"),
}


def _collect_playbook_dns_rows(
    ev: dict[str, Any], dns: dict[str, Any]
) -> list[tuple[str, str, int | None, str, str]]:
    rows: list[tuple[str, str, int | None, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(rec: Any, default_type: str) -> None:
        if isinstance(rec, dict):
            rtype = _as_str(rec.get("record_type") or rec.get("type") or default_type).upper()
            host = strip_rf_prefix(
                rec.get("entity") or rec.get("ip") or rec.get("name") or rec.get("value") or ""
            )
            risk = _as_int(rec.get("risk_score"))
            crit = _as_str(rec.get("criticality") or "-").strip() or "-"
            ctx_list = [_as_str(c) for c in _as_list(rec.get("context_list")) if c]
            ctx = ", ".join(ctx_list) if ctx_list else "-"
        else:
            rtype = default_type.upper()
            host = strip_rf_prefix(rec)
            risk = None
            crit = "-"
            ctx = "-"
        if not host:
            return
        dedup_key = (rtype, host.lower())
        if dedup_key in seen:
            return
        seen.add(dedup_key)
        rows.append((rtype, host, risk, crit, ctx))

    for rec in _as_list(ev.get("resolved_record_list")):
        _add(rec, "RECORD")
    for key, rtype in _DNS_LIST_KEYS:
        for rec in _as_list(dns.get(key)):
            _add(rec, rtype)

    return rows


def _is_redacted(val: Any) -> bool:
    s = _as_str(val).strip().upper()
    return s in {"DATA REDACTED", "REDACTED FOR PRIVACY", "REDACTED"} or "DATA REDACTED" in s


def _build_whois_rows(whois_body: list[dict[str, Any]]) -> list[tuple[str, str | Text]]:
    rows: list[tuple[str, str | Text]] = []
    empty_contacts: list[str] = []

    for entry in whois_body[:16]:
        attr = _as_str(entry.get("attribute")).lower()
        val = entry.get("value")

        if isinstance(val, dict):
            is_reg = attr == "attr:whois" or any(
                k in val for k in ("registrarName", "registrar_name", "nameServers", "expiresDate")
            )
            is_contact = attr == "attr:whoiscontacts" or ("type" in val and not is_reg)
            if is_reg:
                reg = _as_str(val.get("registrarName") or val.get("registrar_name"))
                if reg:
                    rows.append(("Registrar", reg))
                if val.get("createdDate") or val.get("created"):
                    rows.append(
                        ("Created", format_date_or_ts(val.get("createdDate") or val.get("created")))
                    )
                if val.get("updatedDate") or val.get("updated"):
                    rows.append(
                        ("Updated", format_date_or_ts(val.get("updatedDate") or val.get("updated")))
                    )
                if val.get("expiresDate") or val.get("expires"):
                    rows.append(
                        ("Expires", format_date_or_ts(val.get("expiresDate") or val.get("expires")))
                    )
                if "privateRegistration" in val or "private_registration" in val:
                    priv = val.get("privateRegistration", val.get("private_registration"))
                    rows.append(("Private Reg", "Yes" if priv else "No"))
                status_raw = val.get("status")
                if isinstance(status_raw, list):
                    rows.append(("Status", ", ".join(_as_str(s) for s in status_raw if s) or "-"))
                elif isinstance(status_raw, str) and status_raw.strip():
                    rows.append(("Status", ", ".join(status_raw.split())))
                ns_list = val.get("nameServers") or val.get("name_servers")
                if isinstance(ns_list, list) and ns_list:
                    rows.append(
                        ("Name Servers", ", ".join(strip_rf_prefix(ns) for ns in ns_list if ns))
                    )
                continue

            if is_contact:
                raw_role = _as_str(val.get("type") or "contact")
                role_label, short_role = _WHOIS_CONTACT_ROLES.get(
                    raw_role.lower(), (_pretty_label(raw_role), _pretty_label(raw_role))
                )
                shown_parts: list[str] = []
                redacted_fields: list[str] = []
                field_order = (
                    ("name", "Name"),
                    ("organization", "Org"),
                    ("org", "Org"),
                    ("email", "Email"),
                    ("telephone", "Tel"),
                    ("street1", "Street"),
                    ("city", "City"),
                    ("state", "State"),
                    ("postalCode", "Postal"),
                    ("postal_code", "Postal"),
                    ("country", "Country"),
                    ("countryCode", "CC"),
                )
                seen_labels: set[str] = set()
                for fkey, flabel in field_order:
                    fval = val.get(fkey)
                    if fval in (None, "") or flabel in seen_labels:
                        continue
                    seen_labels.add(flabel)
                    if _is_redacted(fval):
                        redacted_fields.append(flabel)
                    else:
                        shown_parts.append(f"{flabel}: {_as_str(fval)}")

                if not shown_parts and not redacted_fields:
                    if short_role not in empty_contacts:
                        empty_contacts.append(short_role)
                else:
                    summary = " | ".join(shown_parts)
                    if redacted_fields:
                        red_note = f"(Redacted: {', '.join(redacted_fields)})"
                        summary = f"{summary}  {red_note}" if summary else red_note
                    rows.append((role_label, summary))
                continue

            rows.append((_pretty_label(attr or "WHOIS"), format_kv_summary(val)))
        elif "key" in entry or "label" in entry:
            label = _as_str(entry.get("key") or entry.get("label") or "Field")
            rows.append((label, format_kv_summary(val)))
        else:
            rows.append(("Record", format_kv_summary(entry)))

    if empty_contacts:
        rows.append(
            ("Empty Contacts", Text(", ".join(empty_contacts) + " (no details)", style="dim"))
        )
    return rows


def _format_single_playbook_change(chg: dict[str, Any]) -> str:
    ctype = _as_str(chg.get("type")).lower()
    if ctype == "whois_change":
        dom = strip_rf_prefix(chg.get("domain") or "")
        new_rec = _as_dict(chg.get("new_record"))
        parts: list[str] = []
        if new_rec.get("registrar_name") or new_rec.get("registrarName"):
            parts.append(f"Registrar: {new_rec.get('registrar_name') or new_rec.get('registrarName')}")
        ns = new_rec.get("name_servers") or new_rec.get("nameServers")
        if isinstance(ns, list) and ns:
            parts.append(f"NS: {', '.join(strip_rf_prefix(x) for x in ns[:3])}")
        added_c = _as_list(chg.get("added_contacts"))
        if added_c:
            parts.append(f"+{len(added_c)} contact(s)")
        removed_c = _as_list(chg.get("removed_contacts"))
        if removed_c:
            parts.append(f"-{len(removed_c)} contact(s)")
        detail = "; ".join(parts)
        prefix = f"WHOIS updated for {dom}" if dom else "WHOIS updated"
        return f"{prefix} ({detail})" if detail else prefix

    if ctype == "attacker_added_change":
        att = strip_rf_prefix(chg.get("attacker") or "")
        cause = _as_str(chg.get("cause") or "").replace("_", " ")
        kws = [_as_str(k) for k in _as_list(chg.get("similar_domains_keywords")) if k]
        extras = [p for p in (f"cause: {cause}" if cause else "", f"keywords: {', '.join(kws)}" if kws else "") if p]
        head = f"Attacker added: {att}" if att else "Attacker added"
        return f"{head} ({'; '.join(extras)})" if extras else head

    if ctype == "status_change":
        old_v = _as_str(chg.get("old") or "-")
        new_v = _as_str(chg.get("new") or "-")
        acts = [_as_str(a) for a in _as_list(chg.get("actions_taken")) if a]
        msg = f"Status: {old_v} -> {new_v}"
        if acts:
            msg += f" (actions: {', '.join(acts)})"
        return msg

    if ctype == "priority_change":
        return f"Priority: {_as_str(chg.get('old') or '-')} -> {_as_str(chg.get('new') or '-')}"

    if ctype == "assignee_change":
        return f"Assignee: {_as_str(chg.get('old') or 'Unassigned')} -> {_as_str(chg.get('new') or 'Unassigned')}"

    if ctype in {"dns_change", "ip_change", "ns_change", "mx_change", "screenshot_added", "logo_hash_change"}:
        label = _pretty_label(ctype)
        rest = {k: v for k, v in chg.items() if k != "type"}
        summary = format_kv_summary(rest, max_items=4)
        return f"{label}: {summary}" if summary != "-" else label

    return format_kv_summary(chg, max_items=5)


def _format_playbook_log_entry(entry: dict[str, Any]) -> tuple[str, str, str]:
    ts = format_timestamp(entry.get("created") or entry.get("modified"))
    actor = _as_str(
        entry.get("author_name") or entry.get("actor_name") or entry.get("action_priority") or "-"
    )

    changes_list = [c for c in _as_list(entry.get("changes")) if isinstance(c, dict)]
    if not changes_list and isinstance(entry.get("changes"), dict):
        changes_dict = _as_dict(entry.get("changes"))
        changes_list = [v for v in changes_dict.values() if isinstance(v, dict)]
    if not changes_list:
        ctx = _as_dict(entry.get("context"))
        changes_list = [c for c in _as_list(ctx.get("changes")) if isinstance(c, dict)]

    if changes_list:
        summaries = [_format_single_playbook_change(c) for c in changes_list[:4]]
        if len(changes_list) > 4:
            summaries.append(f"+{len(changes_list) - 4} more change(s)")
        return ts, actor, "; ".join(summaries)

    ctx = _as_dict(entry.get("context"))
    if ctx:
        return ts, actor, format_kv_summary(ctx, max_items=5)

    note = _as_str(entry.get("message") or entry.get("note") or entry.get("action") or "")
    if note:
        return ts, actor, note

    rest = {
        k: v
        for k, v in entry.items()
        if k not in {"id", "created", "modified", "author_name", "author_id", "actor_name", "actor_id", "action_priority"}
    }
    return ts, actor, format_kv_summary(rest, max_items=4)


def render_playbook_alert_detail(
    norm: dict[str, Any],
    full_detail: dict[str, Any] | None = None,
    *,
    screenshots_cache: dict[str, dict[str, Any]] | None = None,
    render_width: int = 84,
    os_viewer_default: bool = False,
    blur_images: bool = True,
) -> Group:
    """Render a Playbook Alert inspector highlighting evidence, DNS, WHOIS, logs, and screenshots."""
    effective = normalize_playbook_alert(full_detail) if full_detail else norm
    if full_detail:
        if effective.get("category") == "-" and norm.get("category"):
            effective["category"] = norm["category"]
        if not full_detail.get("title") and norm.get("title"):
            effective["title"] = norm["title"]
    raw = _as_dict(effective.get("raw"))
    pstatus = _as_dict(raw.get("panel_status"))
    ev = _as_dict(raw.get("panel_evidence_summary"))
    dns = _as_dict(raw.get("panel_evidence_dns"))
    whois = _as_dict(raw.get("panel_evidence_whois"))
    triage = _as_dict(raw.get("panel_triage"))
    cached_content = _as_dict(raw.get("panel_cached_content"))

    rows: list[tuple[str, str | Text]] = [
        ("Playbook ID", effective["id"] or "-"),
        ("Category", effective["category"] or "-"),
        ("Status", status_text(effective["status"])),
        ("Priority", priority_text(effective["priority"])),
        ("Rule", effective["rule_name"] or "-"),
        ("Assignee", effective["assignee"] or "Unassigned"),
        ("Created", format_timestamp(effective["created"])),
        ("Updated", format_timestamp(effective["updated"])),
    ]
    if effective.get("risk_score") is not None:
        rows.append(("Risk Score", risk_gauge(effective["risk_score"])))
    if effective.get("entity_name"):
        rows.append(("Entity", strip_rf_prefix(effective["entity_name"])))
    if effective.get("targets"):
        rows.append(("Target(s)", ", ".join(strip_rf_prefix(t) for t in effective["targets"])))
    if effective.get("attackers"):
        rows.append(("Attacker(s)", ", ".join(strip_rf_prefix(a) for a in effective["attackers"])))
    ctx_tags = [_as_str(c) for c in _as_list(pstatus.get("context_list") or raw.get("context_list")) if c]
    if ctx_tags:
        rows.append(("Context Tags", ", ".join(ctx_tags)))
    if effective.get("actions_taken"):
        rows.append(("Actions Taken", ", ".join(effective["actions_taken"])))

    renderables: list[RenderableType] = [
        Panel(
            _kv_table(rows),
            title=Text(
                f"Playbook Alert [{effective['category']}]: {truncate_text(effective['title'], 48)}",
                style="bold cyan",
            ),
            border_style="cyan",
            box=box.ROUNDED,
        )
    ]

    # Triage / Assessments / Matched Assets (e.g. Dark Web Brand)
    assessments = [a for a in _as_list(ev.get("assessments")) if isinstance(a, dict)]
    matched_assets = [m for m in _as_list(ev.get("matched_assets")) if isinstance(m, dict)]
    if triage or assessments or matched_assets:
        triage_rows: list[tuple[str, str | Text]] = []
        t_assess = _as_dict(triage.get("assessment"))
        if t_assess:
            a_name = _as_str(t_assess.get("name") or "-")
            a_crit = _as_str(t_assess.get("criticality") or "")
            triage_rows.append(
                ("Assessment", f"{a_name} ({a_crit})" if a_crit else a_name)
            )
        elif assessments:
            first_a = assessments[0]
            a_name = _as_str(first_a.get("name") or "-")
            a_crit = _as_str(first_a.get("criticality") or "")
            triage_rows.append(
                ("Assessment", f"{a_name} ({a_crit})" if a_crit else a_name)
            )
        if triage.get("rationale"):
            triage_rows.append(("Rationale", _as_str(triage["rationale"])))
        if matched_assets:
            asset_labels = [
                f"{_pretty_label(_as_str(m.get('type') or 'asset'))}: {_as_str(m.get('name') or m.get('entity_id'))}"
                for m in matched_assets[:8]
            ]
            triage_rows.append(("Matched Assets", ", ".join(asset_labels)))
        if triage_rows:
            renderables.append(
                Panel(
                    _kv_table(triage_rows),
                    title=Text("Triage & Matched Assets", style="bold magenta"),
                    border_style="magenta",
                    box=box.ROUNDED,
                )
            )

    # Brand Logo Hash / Evidence Summary
    ev_rows: list[tuple[str, str | Text]] = []
    if ev.get("explanation"):
        ev_rows.append(("Explanation", _as_str(ev["explanation"])))
    if ev.get("cause"):
        ev_rows.append(("Cause", _as_str(ev["cause"])))
    if ev.get("url"):
        ev_rows.append(("Matched URL", _as_str(ev["url"])))
    if ev.get("brands"):
        ev_rows.append(("Brands", ", ".join(_as_str(b) for b in _as_list(ev["brands"]))))
    if effective.get("logo_hashes"):
        ev_rows.append(
            (
                "Logo Hashes",
                Text("\n".join(strip_rf_prefix(h) for h in effective["logo_hashes"]), style="bold yellow"),
            )
        )
    if effective.get("logotypes"):
        ev_rows.append(("Logotypes", ", ".join(effective["logotypes"])))
    ev_details = _as_dict(ev.get("details"))
    if ev_details:
        for dk, dv in list(ev_details.items())[:8]:
            if dv not in (None, "", [], {}):
                ev_rows.append((_pretty_label(_as_str(dk)), format_kv_summary(dv)))

    if ev_rows:
        renderables.append(
            Panel(
                _kv_table(ev_rows),
                title=Text("Evidence & Brand Logo Matches", style="bold yellow"),
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
    elif not full_detail:
        renderables.append(
            Panel(
                Text(
                    "Summary view loaded. Press Enter or click 'Deep Detail' to fetch DNS, WHOIS, "
                    "screenshots, logo hashes, and activity logs.",
                    style="dim",
                ),
                border_style="dim",
            )
        )

    # Cached Content (e.g. dark_web)
    if cached_content:
        cc_rows: list[tuple[str, str | Text]] = []
        if cached_content.get("title"):
            cc_rows.append(("Title", _as_str(cached_content["title"])))
        if cached_content.get("original_url"):
            cc_rows.append(("Source URL", _as_str(cached_content["original_url"])))
        if cached_content.get("downloaded"):
            cc_rows.append(("Downloaded", format_timestamp(cached_content["downloaded"])))
        content_body = _as_str(cached_content.get("content")).strip()
        if content_body:
            preview = content_body[:1000]
            if len(content_body) > 1000:
                preview += f"\n... ({len(content_body)} chars total; toggle Raw JSON for full text)"
            cc_rows.append(("Content", preview))
        if cc_rows:
            renderables.append(
                Panel(
                    _kv_table(cc_rows),
                    title=Text("Cached Content", style="bold white"),
                    border_style="blue",
                    box=box.ROUNDED,
                )
            )

    # Unified DNS & Resolved Infrastructure Table
    dns_entries = _collect_playbook_dns_rows(ev, dns)
    if dns_entries:
        dns_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"DNS & Resolved Infrastructure ({len(dns_entries)})", style="bold white"),
            title_justify="left",
        )
        dns_table.add_column("Type", style="cyan", width=7, no_wrap=True)
        dns_table.add_column("Host / IP", ratio=3, overflow="fold")
        dns_table.add_column("Risk", width=6, justify="right")
        dns_table.add_column("Criticality", width=13, no_wrap=True)
        dns_table.add_column("Context", style="dim", ratio=2, overflow="fold")
        for rtype, host, r_score, crit, ctx_str in dns_entries[:25]:
            dns_table.add_row(
                Text(rtype, style="cyan"),
                Text(host),
                score_text(r_score, max_score=99),
                priority_text(crit),
                Text(ctx_str),
            )
        renderables.append(dns_table)

    # Structured WHOIS Registration Panel
    whois_body = [w for w in _as_list(whois.get("body")) if isinstance(w, dict)]
    if whois_body:
        whois_rows = _build_whois_rows(whois_body)
        if whois_rows:
            renderables.append(
                Panel(
                    _kv_table(whois_rows),
                    title=Text("WHOIS Registration", style="bold white"),
                    border_style="blue",
                    box=box.ROUNDED,
                )
            )

    # Inline Screenshots
    sc_meta_list = effective.get("screenshots_meta") or extract_playbook_screenshots(ev)
    if sc_meta_list:
        available_sc = [
            sc
            for sc in sc_meta_list
            if sc.get("availability", "").lower() != "unavailable"
        ]
        shown_sc = available_sc[:4] if available_sc else sc_meta_list[:2]
        total_sc = len(shown_sc)
        for idx, sc_meta in enumerate(shown_sc, start=1):
            img_id = sc_meta["image_id"]
            if sc_meta.get("availability", "").lower() == "unavailable":
                renderables.append(
                    render_screenshot_panel(
                        image_id=img_id,
                        render_width=render_width,
                        max_rows=18,
                        meta=sc_meta,
                        error="Marked unavailable by Recorded Future",
                        index=idx,
                        total=total_sc,
                    )
                )
                continue
            cache_entry = (screenshots_cache or {}).get(img_id, {})
            renderables.append(
                render_screenshot_panel(
                    image_id=img_id,
                    render_width=render_width,
                    max_rows=18,
                    meta=sc_meta,
                    decoded=cache_entry.get("decoded"),
                    raw_bytes=cache_entry.get("bytes"),
                    loading=bool(cache_entry.get("loading")),
                    error=cache_entry.get("error"),
                    index=idx,
                    total=total_sc,
                    auto_crop=not bool(cache_entry.get("crop_checked")),
                    kitty_placeholder=cache_entry.get("kitty_placeholder"),
                    crop_box=cache_entry.get("crop_box"),
                    blurred=bool(cache_entry.get("blurred", blur_images)),
                    pre_blurred=bool(cache_entry.get("pre_blurred", False)),
                )
            )
        if os_viewer_default:
            action_hint = (
                "Press [v] or click Images to open in OS viewer | [b] Blur/Reveal | "
                "Right-click here -> Open / TUI Modal / Save PNG"
            )
        else:
            action_hint = (
                "Press [v] or click Images for viewer | [o] Open in OS viewer | "
                "[b] Blur/Reveal | Right-click here -> Open / Save PNG"
            )
        if len(available_sc) > len(shown_sc):
            renderables.append(
                Text(
                    f"+{len(available_sc) - len(shown_sc)} more screenshot(s) available. {action_hint}",
                    style="dim",
                )
            )
        else:
            renderables.append(Text(action_hint, style="dim"))

    # Human-Readable Activity Log (prefer panel_log_v2, fallback to panel_log)
    logs_src = _as_list(raw.get("panel_log_v2")) or _as_list(raw.get("panel_log"))
    logs = [entry for entry in logs_src if isinstance(entry, dict)]
    if logs:
        log_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Activity Log ({len(logs)})", style="bold white"),
            title_justify="left",
        )
        log_table.add_column("Timestamp", width=18, style="dim", no_wrap=True)
        log_table.add_column("Actor / Priority", width=18, style="cyan", overflow="fold")
        log_table.add_column("Event Summary", overflow="fold")
        for entry in logs[:15]:
            ts, actor, summary = _format_playbook_log_entry(entry)
            log_table.add_row(Text(ts), Text(actor), Text(truncate_text(summary, 220)))
        renderables.append(log_table)

    return Group(*renderables)


def render_case_detail(
    norm: dict[str, Any], full_detail: dict[str, Any] | None = None
) -> Group:
    """Render an investigation Case detail panel."""
    effective = normalize_case(full_detail) if full_detail else norm
    raw = _as_dict(effective.get("raw"))

    rows: list[tuple[str, str | Text]] = [
        ("Case ID", effective["id"] or "-"),
        ("Title", effective["title"] or "-"),
        ("Status", status_text(effective["status"])),
        ("Priority", priority_text(effective["priority"])),
        ("Assignee", effective["assignee"] or "Unassigned"),
        ("Created", format_timestamp(effective["created"])),
        ("Updated", format_timestamp(effective["updated"])),
    ]
    renderables: list[RenderableType] = [
        Panel(
            _kv_table(rows),
            title=Text(f"Case: {truncate_text(effective['title'], 56)}", style="bold cyan"),
            border_style="cyan",
            box=box.ROUNDED,
        )
    ]

    desc = effective.get("description") or ""
    if desc:
        renderables.append(
            Panel(
                Text(desc),
                title=Text("Description", style="bold white"),
                border_style="blue",
                box=box.ROUNDED,
            )
        )

    details = _as_dict(raw.get("details"))
    extra_details = {
        k: v for k, v in details.items() if k != "description" and v not in (None, "", [], {})
    }
    if extra_details:
        det_rows = [(_pretty_label(str(k)), format_kv_summary(v)) for k, v in list(extra_details.items())[:10]]
        renderables.append(
            Panel(
                _kv_table(det_rows),
                title=Text("Case Details", style="bold white"),
                border_style="blue",
                box=box.ROUNDED,
            )
        )

    logs = effective.get("log") or [x for x in _as_list(raw.get("log")) if isinstance(x, dict)]
    if logs:
        log_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Case Log ({len(logs)})", style="bold white"),
            title_justify="left",
        )
        log_table.add_column("Timestamp", width=18, style="dim")
        log_table.add_column("Author", width=20, style="cyan")
        log_table.add_column("Entry", overflow="fold")
        for entry in logs[:15]:
            ts = format_timestamp(entry.get("created") or entry.get("timestamp"))
            author = _extract_person(entry.get("author") or entry.get("user")) or "-"
            msg = _as_str(entry.get("message") or entry.get("note") or entry.get("change"))
            if not msg:
                msg = format_kv_summary(entry, max_items=5)
            log_table.add_row(Text(ts), Text(author), Text(truncate_text(msg, 140)))
        renderables.append(log_table)

    return Group(*renderables)


def render_v2_intel_card(norm: dict[str, Any]) -> Group:
    """Render a Connect API v2 Intelligence Card with risk gauge, rules, and context."""
    rows: list[tuple[str, str | Text]] = [
        ("Entity", f"{norm['name']} ({norm['rf_type']})"),
        ("Entity ID", norm["id"] or "-"),
        ("Risk Score", risk_gauge(norm.get("risk_score"))),
        (
            "Criticality",
            Text(
                f"{norm.get('criticality_label') or '-'} (Risk String: {norm.get('risk_string') or '-'})",
                style=risk_color(norm.get("risk_score")),
            ),
        ),
        ("Rules Triggered", str(norm.get("rules_count", 0))),
    ]
    ts = _as_dict(norm.get("timestamps"))
    if ts.get("firstSeen") or ts.get("lastSeen"):
        rows.append(
            (
                "Sightings Window",
                f"First: {format_timestamp(ts.get('firstSeen'))} | Last: {format_timestamp(ts.get('lastSeen'))}",
            )
        )
    if norm.get("hash_algorithm"):
        rows.append(("Hash Algorithm", norm["hash_algorithm"]))
    if norm.get("lifecycle_stage"):
        rows.append(("Lifecycle Stage", norm["lifecycle_stage"]))
    if norm.get("risk_summary"):
        rows.append(("Summary", norm["risk_summary"]))
    if norm.get("intel_card"):
        rows.append(("IntelCard URL", norm["intel_card"]))

    renderables: list[RenderableType] = [
        Panel(
            _kv_table(rows),
            title=Text(
                f"Intelligence Card: {norm['name']} [{norm['rf_type']}]",
                style="bold cyan",
            ),
            border_style=risk_color(norm.get("risk_score")).replace("bold ", "") or "cyan",
            box=box.ROUNDED,
        )
    ]

    # IP Geolocation / ASN
    loc_root = _as_dict(norm.get("location"))
    if loc_root:
        geo = _as_dict(loc_root.get("location"))
        cidr = _as_dict(loc_root.get("cidr"))
        loc_rows: list[tuple[str, str | Text]] = []
        if loc_root.get("organization"):
            loc_rows.append(("Organization", _as_str(loc_root["organization"])))
        if loc_root.get("asn"):
            loc_rows.append(("ASN", _as_str(loc_root["asn"])))
        if cidr.get("name") or cidr.get("id"):
            loc_rows.append(("CIDR", _as_str(cidr.get("name") or cidr.get("id"))))
        geo_parts = [
            _as_str(geo.get(k))
            for k in ("city", "country", "continent")
            if geo.get(k)
        ]
        if geo_parts:
            loc_rows.append(("Location", ", ".join(geo_parts)))
        if loc_rows:
            renderables.append(
                Panel(
                    _kv_table(loc_rows),
                    title=Text("Network & Geolocation", style="bold white"),
                    border_style="blue",
                    box=box.ROUNDED,
                )
            )

    # Vulnerability CVSS & NVD description
    cvss = _as_dict(norm.get("cvss"))
    if cvss or norm.get("nvd_description"):
        vuln_rows: list[tuple[str, str | Text]] = []
        if cvss:
            cvss_str = (
                f"Score: {cvss.get('score', '-')} | Version: {cvss.get('version', '-')} | "
                f"Vector: {cvss.get('vectorString', cvss.get('vector', '-'))}"
            )
            vuln_rows.append(("CVSS", cvss_str))
        if norm.get("nvd_description"):
            vuln_rows.append(("NVD Description", norm["nvd_description"]))
        renderables.append(
            Panel(
                _kv_table(vuln_rows),
                title=Text("Vulnerability Details", style="bold white"),
                border_style="blue",
                box=box.ROUNDED,
            )
        )

    # Triggered Risk Rules
    ev_list = norm.get("evidence_details") or []
    if ev_list:
        ev_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Triggered Risk Rules ({len(ev_list)})", style="bold white"),
            title_justify="left",
        )
        ev_table.add_column("Crit", width=6, justify="right")
        ev_table.add_column("Rule", style="bold yellow", ratio=2, overflow="fold")
        ev_table.add_column("Evidence", ratio=3, overflow="fold")
        ev_table.add_column("Timestamp", width=18, style="dim")
        for ev in ev_list[:20]:
            crit = _as_int(ev.get("criticality"))
            ev_table.add_row(
                Text(str(crit) if crit is not None else "-", style=priority_text(ev.get("criticalityLabel")).style),
                Text(_as_str(ev.get("rule") or ev.get("criticalityLabel") or "-")),
                Text(truncate_text(ev.get("evidenceString") or "-", 140)),
                Text(format_timestamp(ev.get("timestamp"))),
            )
        renderables.append(ev_table)

    # Threat Lists
    tlists = norm.get("threat_lists") or []
    if tlists:
        tl_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Threat Lists ({len(tlists)})", style="bold white"),
            title_justify="left",
        )
        tl_table.add_column("Threat List", style="cyan", ratio=2, overflow="fold")
        tl_table.add_column("Description", ratio=3, overflow="fold")
        for tl in tlists[:15]:
            tl_table.add_row(
                Text(_as_str(tl.get("name") or tl.get("id") or "-")),
                Text(truncate_text(tl.get("description") or "-", 120)),
            )
        renderables.append(tl_table)

    # Related entities (if Deep Detail fetched)
    related = norm.get("related_entities") or []
    if related:
        rel_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Related Entities ({len(related)} groups)", style="bold white"),
            title_justify="left",
        )
        rel_table.add_column("Relation Type", style="cyan", width=26)
        rel_table.add_column("Top Entities", overflow="fold")
        for rel in related[:12]:
            rtype = _as_str(rel.get("type") or "-")
            ents = _as_list(rel.get("entities"))
            names = []
            for entry in ents[:8]:
                ed = _as_dict(entry)
                inner = _as_dict(ed.get("entity")) or ed
                n = _as_str(inner.get("name") or inner.get("id"))
                if n:
                    names.append(n)
            rel_table.add_row(Text(rtype), Text(", ".join(names) if names else "-"))
        renderables.append(rel_table)

    return Group(*renderables)


def render_soar_detail(norm: dict[str, Any]) -> Group:
    """Render a SOAR v3 enrichment or triage item inspector."""
    rows: list[tuple[str, str | Text]] = [
        ("IOC", f"{norm['name']} ({norm['type']})"),
        ("Entity ID", norm["id"] or "-"),
        ("Risk Score", risk_gauge(norm.get("score"))),
        ("Risk Level", str(norm.get("level") if norm.get("level") is not None else "-")),
    ]
    if norm.get("mode") == "triage" or norm.get("verdict") != "-":
        v_str = _as_str(norm.get("verdict"))
        v_style = "bold red" if v_str.upper() == "MALICIOUS" else "green"
        rows.append(("Triage Verdict", Text(v_str, style=v_style)))
        rows.append(("Context", norm.get("context") or "-"))

    renderables: list[RenderableType] = [
        Panel(
            _kv_table(rows),
            title=Text(f"SOAR v3: {norm['name']}", style="bold cyan"),
            border_style="cyan",
            box=box.ROUNDED,
        )
    ]

    ctx_map = _as_dict(norm.get("risk_contexts"))
    if ctx_map:
        ctx_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text("Context Risk Scores", style="bold white"),
            title_justify="left",
        )
        ctx_table.add_column("Context", style="cyan", width=20)
        ctx_table.add_column("Score", width=18)
        for cname, cdata in sorted(ctx_map.items()):
            cdict = _as_dict(cdata)
            cscore = _as_int(cdict.get("score") if cdict else cdata)
            ctx_table.add_row(Text(cname), risk_gauge(cscore))
        renderables.append(ctx_table)

    ev_list = norm.get("evidence") or []
    if ev_list:
        ev_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Rule Evidence ({len(ev_list)})", style="bold white"),
            title_justify="left",
        )
        ev_table.add_column("Rule", style="bold yellow", ratio=2, overflow="fold")
        ev_table.add_column("Evidence / Mitigations", ratio=3, overflow="fold")
        for ev in ev_list[:20]:
            ev_table.add_row(
                Text(_as_str(ev.get("rule") or ev.get("name") or "-")),
                Text(
                    truncate_text(
                        ev.get("evidenceString") or ev.get("description") or ev.get("mitigation") or "-",
                        140,
                    )
                ),
            )
        renderables.append(ev_table)

    return Group(*renderables)


def render_entity_match_detail(
    norm: dict[str, Any], full_detail: dict[str, Any] | None = None
) -> Group:
    """Render an Entity Match / Entity Lookup candidate card."""
    source = full_detail if full_detail else norm.get("raw") or {}
    src_data = _as_dict(source.get("data")) if isinstance(source.get("data"), dict) else _as_dict(source)
    aliases = [_as_str(a) for a in _as_list(src_data.get("aliases") or norm.get("aliases")) if a]

    rows: list[tuple[str, str | Text]] = [
        ("Entity ID", _as_str(src_data.get("id") or norm["id"]) or "-"),
        ("Name", _as_str(src_data.get("name") or norm["name"]) or "-"),
        ("Type", _as_str(src_data.get("type") or norm["type"]) or "-"),
        ("Aliases", ", ".join(aliases) if aliases else "-"),
    ]
    for extra_key in ("description", "common_names", "curated"):
        if src_data.get(extra_key) is not None and src_data.get(extra_key) != "":
            rows.append(
                (extra_key.replace("_", " ").title(), truncate_text(format_kv_summary(src_data[extra_key]), 160))
            )

    hint = Panel(
        Text(
            "Tip: Press Enter / Deep Detail to fetch full aliases via /entity-match/entity/{id}, "
            "or right-click to pivot to Connect v2 Lookup or Watchlists.",
            style="dim",
        ),
        border_style="dim",
        box=box.ROUNDED,
    )
    return Group(
        Panel(
            _kv_table(rows),
            title=Text(f"Entity Match: {norm['name']}", style="bold cyan"),
            border_style="cyan",
            box=box.ROUNDED,
        ),
        hint,
    )


def render_sandbox_detail(
    norm: dict[str, Any], full_detail: dict[str, Any] | None = None
) -> Group:
    """Render a Sandbox v0 sample card and overview signatures."""
    effective = normalize_sandbox_sample(full_detail) if full_detail else norm
    raw = _as_dict(full_detail if full_detail else effective.get("raw"))

    rows: list[tuple[str, str | Text]] = [
        ("Sample ID", effective["id"] or "-"),
        ("Target", effective["target"] or "-"),
        ("Status", status_text(effective["status"])),
        ("Sandbox Score", risk_gauge(effective.get("score"), max_score=10)),
        ("Kind", effective.get("sample_kind") or "-"),
        ("SHA-256", effective.get("sha256") or "-"),
        ("MD5", effective.get("md5") or "-"),
        ("Families", ", ".join(effective.get("families") or []) or "-"),
        ("Tags", ", ".join(effective.get("tags") or []) or "-"),
        ("Submitted", format_timestamp(effective.get("submitted"))),
    ]

    renderables: list[RenderableType] = [
        Panel(
            _kv_table(rows),
            title=Text(
                f"Sandbox Sample: {truncate_text(effective['target'], 52)}",
                style="bold cyan",
            ),
            border_style="cyan",
            box=box.ROUNDED,
        )
    ]

    signatures = [s for s in _as_list(raw.get("signatures")) if isinstance(s, dict)]
    if signatures:
        sig_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Behavioral Signatures ({len(signatures)})", style="bold white"),
            title_justify="left",
        )
        sig_table.add_column("Score", width=7, justify="right")
        sig_table.add_column("Signature", style="bold yellow", ratio=2, overflow="fold")
        sig_table.add_column("TTPs / Tags", style="cyan", ratio=1, overflow="fold")
        sig_table.add_column("Description", ratio=2, overflow="fold")
        for sig in signatures[:25]:
            s_score = _as_int(sig.get("score"))
            ttps = ", ".join(_as_str(t) for t in _as_list(sig.get("ttp") or sig.get("tags")))
            sig_table.add_row(
                score_text(s_score, max_score=10),
                Text(_as_str(sig.get("name") or "-")),
                Text(ttps or "-"),
                Text(truncate_text(sig.get("desc") or sig.get("description") or "-", 120)),
            )
        renderables.append(sig_table)

    targets = [t for t in _as_list(raw.get("targets")) if isinstance(t, dict)]
    tasks = [t for t in _as_list(raw.get("tasks")) if isinstance(t, dict)]
    if targets:
        tgt_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Sample Targets ({len(targets)})", style="bold white"),
            title_justify="left",
        )
        tgt_table.add_column("Target", style="cyan", ratio=2, overflow="fold")
        tgt_table.add_column("Score", width=7, justify="right")
        tgt_table.add_column("Family / Tags", ratio=2, overflow="fold")
        for tgt in targets[:15]:
            t_label = _as_str(tgt.get("target") or tgt.get("filename") or tgt.get("url") or tgt.get("id") or "-")
            t_score = _as_int(tgt.get("score"))
            t_tags = format_kv_summary(tgt.get("family") or tgt.get("tags"))
            tgt_table.add_row(Text(t_label), score_text(t_score, max_score=10), Text(t_tags))
        renderables.append(tgt_table)
    elif tasks:
        task_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            title=Text(f"Analysis Tasks ({len(tasks)})", style="bold white"),
            title_justify="left",
        )
        task_table.add_column("Task", style="cyan", width=18)
        task_table.add_column("Score", width=7, justify="right")
        task_table.add_column("Status / Target", overflow="fold")
        for tsk in tasks[:15]:
            task_table.add_row(
                Text(_as_str(tsk.get("kind") or tsk.get("id") or "-")),
                score_text(_as_int(tsk.get("score")), max_score=10),
                Text(format_kv_summary({k: v for k, v in tsk.items() if k not in {"kind", "id", "score"}})),
            )
        renderables.append(task_table)

    if not signatures and not targets and not tasks and not full_detail:
        renderables.append(
            Panel(
                Text("Press Enter or click 'Deep Detail' to fetch sample overview.json & signatures.", style="dim"),
                border_style="dim",
            )
        )

    return Group(*renderables)
