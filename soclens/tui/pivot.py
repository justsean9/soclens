"""Cross-workbench Pivot Bus payload contract and safe query/context helpers."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from rich.style import Style
from rich.text import Text

from soclens.config import PivotPayload, extract_tenant_from_site_name

__all__ = [
    "PivotPayload",
    "build_keyword_spl",
    "build_spl_from_pivot",
    "emit_pivot",
    "extract_pivot_from_click",
    "extract_tenant_from_site_name",
    "format_copilot_context",
    "is_clickable_known_field",
    "join_pivot_texts",
    "make_pivot_text",
]

_NON_SEARCHABLE_VALUES: frozenset[str] = frozenset(
    {
        "-",
        "n/a",
        "none",
        "unassigned",
        "unknown",
        "[ ]",
        "[x]",
        "✓",
        "✗",
        "yes",
        "no",
        "true",
        "false",
    }
)

_FREE_TEXT_OR_NON_SEARCH_FIELDS: frozenset[str] = frozenset(
    {
        # Free-text / prose / raw dumps (user must highlight exact substring)
        "raw event",
        "_raw",
        "raw",
        "description",
        "rule description",
        "explanation",
        "rationale",
        "content",
        "note",
        "notes",
        "ai insights",
        "summary",
        "evidence summary",
        "message",
        "comment",
        "comments",
        "fragment",
        "details",
        "detail",
        "output",
        "log",
        "event summary",
        "entry",
        "evidence",
        "evidence / mitigations",
        "evidence / references",
        "classification",
        "detection source",
        "detection engines",
        # Scalar status / badges / timestamps / counts / UI columns
        "status",
        "incident status",
        "mitigation status",
        "network status",
        "priority",
        "urgency",
        "severity",
        "confidence / severity",
        "analyst verdict",
        "verdict",
        "triage verdict",
        "service tier",
        "tier",
        "alert type",
        "created",
        "updated",
        "expires",
        "downloaded",
        "time",
        "timestamp",
        "last active",
        "registered",
        "last updated",
        "sightings window",
        "file size",
        "size",
        "risk score",
        "risk level",
        "risk",
        "score",
        "criticality",
        "rules triggered",
        "private reg",
        "empty contacts",
        "actions taken",
        "count",
        "hits",
        "hits count",
        "sel",
        "#",
        "selected",
        "age",
        "state",
        "infected",
        "active threats",
        "scan status",
        "mitigation mode",
        "is up to date",
        "is decommissioned",
        "api family",
        "endpoint base",
        "auth header",
        "toolkit surface",
    }
)


def is_clickable_known_field(field: str, value: str) -> bool:
    """Return True when ``(field, value)`` is a structured searchable field, not free text."""
    clean_val = str(value or "").strip()
    if not clean_val or clean_val.lower() in _NON_SEARCHABLE_VALUES:
        return False
    if "\n" in clean_val or len(clean_val) > 180:
        return False
    norm_field = " ".join(str(field or "").strip().lower().split())
    if norm_field in _FREE_TEXT_OR_NON_SEARCH_FIELDS:
        return False
    return True


def _has_pivot_spans(text: Text) -> bool:
    for sp in text.spans:
        if isinstance(sp.style, Style) and sp.style.meta and sp.style.meta.get("pivot_value"):
            return True
    return False


def _spl_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_keyword_spl(keyword: str) -> str:
    """Build a universal Splunk keyword search query ``index=* "<keyword>"``."""
    clean = str(keyword or "").strip()
    if not clean:
        return "index=*"
    return f"index=* {_spl_quote(clean)}"


def make_pivot_text(value: str | Text, *, field: str = "") -> Text:
    """Attach right-click search metadata (``pivot_field``/``pivot_value``) to known fields."""
    text = value.copy() if isinstance(value, Text) else Text(str(value))
    if _has_pivot_spans(text):
        return text
    plain = text.plain.strip()
    if is_clickable_known_field(field, plain):
        text.stylize(Style(meta={"pivot_field": field, "pivot_value": plain}))
    return text


def join_pivot_texts(
    values: Sequence[str],
    *,
    field: str,
    sep: str = ", ",
    style: str | Style = "",
) -> Text:
    """Join multiple structured values so each individual item can be right-clicked."""
    cleaned = [str(v).strip() for v in values if str(v).strip() and str(v).strip() != "-"]
    if not cleaned:
        return Text("-")
    out = Text()
    for idx, item in enumerate(cleaned):
        if idx > 0:
            out.append(sep)
        tok = Text(item, style=style) if style else Text(item)
        out.append_text(make_pivot_text(tok, field=field))
    return out


def extract_pivot_from_click(event: Any) -> tuple[str, str] | None:
    """Extract ``(field_label, value)`` from a Textual click event's Rich style metadata."""
    style = getattr(event, "style", None)
    meta = getattr(style, "meta", None) if style is not None else None
    if not isinstance(meta, dict):
        return None
    raw_val = str(meta.get("pivot_value") or "").strip()
    if not raw_val or raw_val == "-":
        return None
    raw_field = str(meta.get("pivot_field") or "Value").strip() or "Value"
    return raw_field, raw_val


def build_spl_from_pivot(payload: PivotPayload) -> tuple[str, bool]:
    """Build ``(spl_query, auto_run)`` for ``SplunkSearchPane`` (``F8``).

    Safety invariant: ``auto_run`` is ``True`` ONLY for ``orig_sid`` drilldowns
    (``| loadjob <sid>``); arbitrary/generated SPL always loads with ``auto_run=False``.
    """
    if payload.orig_sid and payload.orig_sid.strip():
        sid = payload.orig_sid.strip()
        return f"| loadjob {_spl_quote(sid)}", True

    if payload.spl_query and payload.spl_query.strip():
        return payload.spl_query.strip(), False

    terms: list[str] = []
    if payload.tenant_id and payload.tenant_id.strip():
        terms.append(f"tenant_id={_spl_quote(payload.tenant_id.strip())}")
    for field_name, val in (
        ("src", payload.src_ip),
        ("dest", payload.dest_ip),
        ("host", payload.hostname),
        ("user", payload.username),
        ("file_hash", payload.sha256 or payload.sha1),
    ):
        if val and val.strip():
            terms.append(f"{field_name}={_spl_quote(val.strip())}")
    if not terms and payload.entity and payload.entity.strip():
        terms.append(_spl_quote(payload.entity.strip()))
    query = f"search {' OR '.join(terms)}" if terms else "search *"
    return query, False


def format_copilot_context(payload: PivotPayload) -> tuple[str, str]:
    """Format bundled ``[ES + Tenant + S1 + RF]`` context for ``LocalLLMPane`` (``F7``)."""
    title_parts = ["SOC Triage Pivot"]
    if payload.tenant_id:
        title_parts.append(f"Tenant {payload.tenant_id}")
    if payload.hostname:
        title_parts.append(payload.hostname)
    elif payload.entity:
        title_parts.append(payload.entity)
    title = " | ".join(title_parts)

    sections: list[str] = [f"# {title}"]
    if payload.summary and payload.summary.strip():
        sections.append(f"## Summary\n{payload.summary.strip()}")

    scope_lines: list[str] = []
    for label, val in (
        ("Source Tab", payload.source_tab),
        ("Tenant ID", payload.tenant_id),
        ("Tier", payload.tier),
        ("Site Name", payload.site_name),
        ("Site ID", payload.site_id),
        ("Earliest", payload.earliest),
        ("Latest", payload.latest),
    ):
        if val:
            scope_lines.append(f"- **{label}**: {val}")
    if scope_lines:
        sections.append("## Tenant & Scope\n" + "\n".join(scope_lines))

    ioc_lines: list[str] = []
    for label, val in (
        ("Entity", payload.entity),
        ("Entity Type", payload.entity_type),
        ("Hostname", payload.hostname),
        ("Username", payload.username),
        ("Source IP", payload.src_ip),
        ("Destination IP", payload.dest_ip),
        ("SHA-1", payload.sha1),
        ("SHA-256", payload.sha256),
        ("Original SID", payload.orig_sid),
    ):
        if val:
            ioc_lines.append(f"- **{label}**: `{val}`")
    if ioc_lines:
        sections.append("## Indicators & Entities\n" + "\n".join(ioc_lines))

    if payload.spl_query and payload.spl_query.strip():
        sections.append(f"## Splunk Query\n```spl\n{payload.spl_query.strip()}\n```")

    for heading, blob in (
        ("Splunk ES Finding", payload.es_finding),
        ("SentinelOne Threat / Context", payload.s1_threat),
        ("Recorded Future Enrichment", payload.rf_enrichment),
    ):
        if blob:
            rendered = json.dumps(blob, indent=2, ensure_ascii=False, default=str)
            sections.append(f"## {heading}\n```json\n{rendered}\n```")

    return title, "\n\n".join(sections)


def emit_pivot(app: Any, payload: PivotPayload) -> bool:
    """Emit a ``PivotPayload`` via ``SocLensApp.dispatch_pivot`` or v2.0.0 hooks."""
    dispatcher = getattr(app, "dispatch_pivot", None)
    if callable(dispatcher):
        return bool(dispatcher(payload))

    if payload.target_tab == "tab-splunk-search":
        fn = getattr(app, "open_splunk_search", None)
        if callable(fn):
            spl, auto_run = build_spl_from_pivot(payload)
            fn(spl, auto_run=auto_run)
            return True
    elif payload.target_tab == "tab-llm":
        fn = getattr(app, "open_llm_with_context", None)
        if callable(fn):
            title, content = format_copilot_context(payload)
            fn(title, content, template="triage_alert", auto_send=False)
            return True
    return False
