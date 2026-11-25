"""Cross-workbench Pivot Bus payload contract and safe query/context helpers."""

from __future__ import annotations

import json
from typing import Any

from soclens.config import PivotPayload, extract_tenant_from_site_name

__all__ = [
    "PivotPayload",
    "build_spl_from_pivot",
    "emit_pivot",
    "extract_tenant_from_site_name",
    "format_copilot_context",
]


def _spl_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


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
