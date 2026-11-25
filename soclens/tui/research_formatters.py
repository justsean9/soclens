"""Clean search-first Rich renderables for the Threat Research Workbench TUI."""

from __future__ import annotations

import json
from typing import Any

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from soclens.research import ResearchDossier, ResearchPivot
from soclens.tui.rf_formatters import (
    format_date_or_ts,
    format_kv_summary,
    format_timestamp,
    normalize_alert_v3,
    normalize_playbook_alert,
    normalize_sandbox_sample,
    render_alert_v3_detail,
    render_playbook_alert_detail,
    render_raw_json,
    render_sandbox_detail,
    risk_color,
    risk_gauge,
    score_text,
    truncate_text,
)

_KIND_LABELS: dict[str, str] = {
    "ip": "IP Address",
    "domain": "Domain",
    "hash": "File Hash",
    "url": "URL",
    "vulnerability": "Vulnerability (CVE)",
    "malware": "Malware",
    "actor": "Threat Actor",
    "company": "Company",
    "email": "Email Address",
    "mitre": "MITRE ATT&CK",
    "asn": "ASN",
    "entity_id": "Entity",
    "text": "Topic / Keyword",
}


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


def _kv_table(rows: list[tuple[str, str | Text]], *, title: str | None = None) -> Table:
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
        table.add_row(Text(k, style="bold dim"), cell)
    return table


def _friendly_kind(kind: str) -> str:
    return _KIND_LABELS.get(kind.strip().lower(), kind or "Search")


def _extract_v2_data(dossier: ResearchDossier) -> tuple[dict[str, Any], dict[str, Any]]:
    v2_sec = dossier.sections.get("v2_intel")
    if not v2_sec or not isinstance(v2_sec.data, dict):
        return {}, {}
    lookup = _as_dict(v2_sec.data.get("lookup"))
    data_block = _as_dict(lookup.get("data")) or lookup
    comp = _as_dict(v2_sec.data.get("company_by_domain"))
    comp_data = _as_dict(comp.get("data")) or comp
    return data_block, comp_data


def _extract_alerts_list(dossier: ResearchDossier) -> list[dict[str, Any]]:
    sec = dossier.sections.get("alerts")
    if not sec or not isinstance(sec.data, dict):
        return []
    raw_d = sec.data.get("data")
    if isinstance(raw_d, list):
        return [x for x in raw_d if isinstance(x, dict)]
    if isinstance(raw_d, dict):
        return [x for x in _as_list(raw_d.get("results")) if isinstance(x, dict)]
    return []


def render_research_welcome() -> Group:
    """Render a clean search-first welcome guide without API implementation details."""
    intro = Panel(
        Text.from_markup(
            "[bold cyan]Threat Research[/bold cyan]\n"
            "Just start typing anywhere on this tab (or click the search bar above) to search any "
            "indicator, vulnerability, malware family, threat actor, MITRE ATT&CK technique, or keyword, "
            "then press [bold]Enter[/bold].\n\n"
            "[bold]Shortcuts:[/bold]  [cyan]Enter[/cyan] Search / Open   "
            "[cyan]p[/cyan] Search Selected Entity   [cyan][ / ][/cyan] Back / Forward   "
            "[cyan]/[/cyan] Filter & Options   [cyan]j[/cyan] Raw JSON   [cyan]m[/cyan] Menu"
        ),
        border_style="cyan",
        padding=(0, 1),
    )
    examples = Table(box=box.SIMPLE, expand=True, title="Example Searches (double-click to run)", title_justify="left")
    examples.add_column("Category", style="bold cyan", width=18)
    examples.add_column("Query", style="bold", width=22)
    examples.add_column("What You Get", overflow="fold")
    for cat, q, desc in (
        ("Threat Actor", "APT29", "Aliases, threat map scores, reports, related infrastructure & rules"),
        ("Vulnerability", "CVE-2021-44228", "CVSS/lifecycle details, exploit risk rules, reports & detection rules"),
        ("Malware", "Cobalt Strike", "Family profile, threat map prevalence, threat reports & Sigma/YARA rules"),
        ("IP / Domain", "8.8.8.8", "Risk score & evidence, geolocation, linked entities, reports & alerts"),
    ):
        examples.add_row(cat, q, desc)
    return Group(intro, examples)


def build_research_findings(dossier: ResearchDossier) -> list[dict[str, Any]]:
    """Build a flat, user-friendly list of clickable intelligence findings."""
    t = dossier.target
    brief_detail_parts: list[str] = [_friendly_kind(t.detected_kind)]
    if dossier.risk_score is not None:
        brief_detail_parts.append(f"Risk {dossier.risk_score}/99")
    if dossier.criticality_label:
        brief_detail_parts.append(dossier.criticality_label)

    findings: list[dict[str, Any]] = [
        {
            "kind": "brief",
            "category": "Summary",
            "title": f"{t.canonical_name} - Intelligence Brief",
            "detail": " | ".join(brief_detail_parts),
            "risk_score": dossier.risk_score,
            "payload": dossier,
            "search_blob": f"summary brief {t.canonical_name} {t.detected_kind} {' '.join(t.aliases)}".lower(),
        }
    ]

    # Threat Reports (Analyst Notes)
    notes_sec = dossier.sections.get("analyst_notes")
    if notes_sec and isinstance(notes_sec.data, dict):
        for note in _as_list(notes_sec.data.get("data")):
            if not isinstance(note, dict):
                continue
            attrs = _as_dict(note.get("attributes"))
            title = _as_str(attrs.get("title") or note.get("id") or "Threat Report")
            pub = format_date_or_ts(attrs.get("published"))
            topics = [
                _as_str(tp.get("name") or tp.get("id"))
                for tp in _as_list(attrs.get("topic"))
                if isinstance(tp, dict)
            ]
            detail = f"{pub} | {', '.join(tp for tp in topics if tp)}" if topics else pub
            findings.append(
                {
                    "kind": "note",
                    "category": "Report",
                    "title": title,
                    "detail": detail,
                    "note_id": _as_str(note.get("id")),
                    "payload": note,
                    "search_blob": f"report {title} {detail}".lower(),
                }
            )

    # Threat Actors
    actors_sec = dossier.sections.get("threat_actors")
    if actors_sec and isinstance(actors_sec.data, dict):
        for actor in _as_list(actors_sec.data.get("data")):
            if not isinstance(actor, dict):
                continue
            attrs = _as_dict(actor.get("attributes"))
            name = _as_str(attrs.get("name") or actor.get("id") or "Actor")
            aliases = [
                _as_str(a)
                for a in (_as_list(attrs.get("common_names")) + _as_list(attrs.get("alias")))
                if a
            ]
            eid = _as_str(actor.get("id"))
            findings.append(
                {
                    "kind": "actor",
                    "category": "Actor",
                    "title": name,
                    "detail": ", ".join(aliases[:4]) or "Threat Actor Profile",
                    "pivot_target": eid or name,
                    "pivot_kind": "actor",
                    "payload": actor,
                    "search_blob": f"actor {name} {' '.join(aliases)}".lower(),
                }
            )

    # Threat Map Signals
    tm_sec = dossier.sections.get("threat_map")
    if tm_sec and isinstance(tm_sec.data, dict):
        for entry in _as_list(_as_dict(tm_sec.data.get("data")).get("threat_map")):
            if not isinstance(entry, dict):
                continue
            name = _as_str(entry.get("name") or entry.get("id") or "Threat Map")
            s_a = entry.get("intent") if "intent" in entry else entry.get("prevalence")
            s_label = "Intent" if "intent" in entry else "Prevalence"
            opp = entry.get("opportunity")
            detail = f"{s_label}: {s_a if s_a is not None else '-'} | Opportunity: {opp if opp is not None else '-'}"
            findings.append(
                {
                    "kind": "actor",
                    "category": "Threat Map",
                    "title": name,
                    "detail": detail,
                    "pivot_target": _as_str(entry.get("id") or name),
                    "pivot_kind": "auto",
                    "payload": entry,
                    "search_blob": f"threat map {name} {detail}".lower(),
                }
            )

    # Related Entities (Pivots)
    for piv in dossier.pivots:
        risk_str = f"Risk {piv.risk_score}" if piv.risk_score is not None else ""
        detail_parts = [piv.entity_type, risk_str, piv.relationship]
        detail = " | ".join(part for part in detail_parts if part)
        findings.append(
            {
                "kind": "pivot",
                "category": "Related",
                "title": piv.name,
                "detail": detail,
                "risk_score": piv.risk_score,
                "pivot_target": piv.entity_id,
                "pivot_kind": piv.pivot_kind,
                "payload": piv,
                "search_blob": f"related {piv.name} {piv.entity_id} {piv.entity_type} {piv.relationship}".lower(),
            }
        )

    # Detection Rules
    rules_sec = dossier.sections.get("detection_rules")
    if rules_sec and isinstance(rules_sec.data, list):
        for rule in rules_sec.data:
            if not isinstance(rule, dict):
                continue
            r_title = _as_str(rule.get("title") or rule.get("id") or "Detection Rule")
            r_type = _as_str(rule.get("type") or "rule").upper()
            upd = format_date_or_ts(rule.get("updated"))
            findings.append(
                {
                    "kind": "rule",
                    "category": "Rule",
                    "title": r_title,
                    "detail": f"{r_type} | Updated {upd}",
                    "payload": rule,
                    "search_blob": f"rule {r_title} {r_type} {upd}".lower(),
                }
            )

    # Alerts v3
    for al in _extract_alerts_list(dossier):
        norm = normalize_alert_v3(al)
        findings.append(
            {
                "kind": "alert_v3",
                "category": "Alert",
                "title": norm.get("title") or norm.get("id") or "Alert",
                "detail": f"{norm.get('priority', '-')} | {norm.get('status', '-')} | {format_date_or_ts(norm.get('triggered'))}",
                "payload": al,
                "search_blob": f"alert {norm.get('title')} {norm.get('rule_name')} {norm.get('status')}".lower(),
            }
        )

    # Playbook Alerts
    pb_sec = dossier.sections.get("playbook_alerts")
    if pb_sec and isinstance(pb_sec.data, dict):
        for pb in _as_list(pb_sec.data.get("data")):
            if not isinstance(pb, dict):
                continue
            norm = normalize_playbook_alert(pb)
            findings.append(
                {
                    "kind": "playbook",
                    "category": "Alert",
                    "title": norm.get("title") or norm.get("id") or "Playbook Alert",
                    "detail": f"{norm.get('category', '-')} | {norm.get('priority', '-')} | {norm.get('status', '-')}",
                    "payload": pb,
                    "search_blob": f"playbook alert {norm.get('title')} {norm.get('category')}".lower(),
                }
            )

    # Malware Intelligence Corpus Samples
    mi_sec = dossier.sections.get("malware_intel")
    if mi_sec and isinstance(mi_sec.data, dict):
        for item in _as_list(mi_sec.data.get("data")):
            if not isinstance(item, dict):
                continue
            name = _as_str(item.get("name") or "-")
            r_score = item.get("risk_score")
            s_score = item.get("sandbox_score")
            tags = ", ".join(_as_str(tg) for tg in _as_list(item.get("tags"))[:4])
            detail_parts = []
            if r_score is not None:
                detail_parts.append(f"Risk {r_score}")
            if s_score is not None:
                detail_parts.append(f"Sandbox {s_score}/10")
            if item.get("count") is not None:
                detail_parts.append(f"{item['count']} sample(s)")
            if tags:
                detail_parts.append(tags)
            findings.append(
                {
                    "kind": "malware_sample",
                    "category": "Sample",
                    "title": name,
                    "detail": " | ".join(detail_parts) or "Malware Sample",
                    "pivot_target": f"hash:{name}" if len(name) == 64 else name,
                    "pivot_kind": "hash" if len(name) == 64 else "auto",
                    "payload": item,
                    "search_blob": f"sample {name} {tags}".lower(),
                }
            )

    # Sandbox Samples
    sb_sec = dossier.sections.get("sandbox")
    if sb_sec and isinstance(sb_sec.data, dict):
        raw_samples = sb_sec.data.get("samples") or sb_sec.data.get("data")
        for smp in _as_list(raw_samples):
            if not isinstance(smp, dict):
                continue
            norm = normalize_sandbox_sample(smp)
            title = norm.get("target") or norm.get("sha256") or norm.get("id") or "Sample"
            piv_target = _as_str(norm.get("sha256") or norm.get("target") or "")
            findings.append(
                {
                    "kind": "sandbox",
                    "category": "Sample",
                    "title": title,
                    "detail": f"Score {norm.get('score') if norm.get('score') is not None else '-'}/10 | {norm.get('status', '-')}",
                    "pivot_target": piv_target or None,
                    "pivot_kind": "hash" if norm.get("sha256") else "auto",
                    "payload": smp,
                    "search_blob": f"sandbox {title} {norm.get('sha256')} {' '.join(norm.get('families') or [])}".lower(),
                }
            )

    # Risk History
    rh_sec = dossier.sections.get("risk_history")
    if rh_sec and isinstance(rh_sec.data, dict):
        for hist in _as_list(rh_sec.data.get("data")):
            if not isinstance(hist, dict):
                continue
            ent = _as_dict(hist.get("entity"))
            scores = _as_list(hist.get("scores"))
            rules = _as_list(hist.get("risk_rules"))
            findings.append(
                {
                    "kind": "structured",
                    "category": "History",
                    "title": f"Risk Timeline: {_as_str(ent.get('name') or t.canonical_name)}",
                    "detail": f"{len(scores)} score changes | {len(rules)} rule events",
                    "payload": hist,
                    "search_blob": f"risk history {ent.get('name')}".lower(),
                }
            )

    # Identity Exposures
    id_sec = dossier.sections.get("identity")
    if id_sec and isinstance(id_sec.data, dict):
        for exp in _as_list(id_sec.data.get("identities") or id_sec.data.get("detections")):
            if not isinstance(exp, dict):
                continue
            ident = _as_dict(exp.get("identity"))
            subj = _as_str(ident.get("subject") or exp.get("subject") or "Exposed Account")
            cnt = exp.get("count")
            findings.append(
                {
                    "kind": "structured",
                    "category": "Exposure",
                    "title": subj,
                    "detail": f"{cnt} exposure(s)" if cnt is not None else _as_str(exp.get("type") or "Credential Exposure"),
                    "payload": exp,
                    "search_blob": f"exposure {subj}".lower(),
                }
            )

    # Attack Surface (ASI) & RiskRecon
    asi_sec = dossier.sections.get("asi")
    if asi_sec and isinstance(asi_sec.data, dict):
        for asset in _as_list(asi_sec.data.get("data")):
            if not isinstance(asset, dict):
                continue
            name = _as_str(asset.get("name") or asset.get("id") or asset.get("signature", {}).get("name") or "Asset")
            findings.append(
                {
                    "kind": "structured",
                    "category": "Attack Surface",
                    "title": name,
                    "detail": f"Score: {asset.get('exposure_score', '-')}",
                    "payload": asset,
                    "search_blob": f"attack surface {name}".lower(),
                }
            )

    rr_sec = dossier.sections.get("riskrecon")
    if rr_sec and isinstance(rr_sec.data, list):
        for toe in rr_sec.data:
            if not isinstance(toe, dict):
                continue
            name = _as_str(toe.get("toe_name") or toe.get("company_name") or toe.get("toe_id") or "Organization")
            findings.append(
                {
                    "kind": "structured",
                    "category": "Third Party",
                    "title": name,
                    "detail": _as_str(toe.get("hq_location") or toe.get("subscription_level") or "RiskRecon"),
                    "payload": toe,
                    "search_blob": f"riskrecon {name}".lower(),
                }
            )

    # 3rd-Party Extensions (only non-error responses)
    ext_sec = dossier.sections.get("extensions")
    if ext_sec and isinstance(ext_sec.data, dict):
        for ext_name, ext_payload in ext_sec.data.items():
            if isinstance(ext_payload, dict) and "error" not in ext_payload:
                findings.append(
                    {
                        "kind": "structured",
                        "category": "Context",
                        "title": f"{ext_name} Context",
                        "detail": truncate_text(format_kv_summary(ext_payload.get("data") or ext_payload, max_items=4), 60),
                        "payload": ext_payload,
                        "search_blob": f"extension context {ext_name}".lower(),
                    }
                )

    return findings


def build_search_summary_bar(
    dossier: ResearchDossier | None,
    total_findings: int,
    visible_findings: int,
) -> Text:
    """Build a concise analyst-friendly KPI bar without API plumbing metrics."""
    bar = Text()
    if dossier is None:
        bar.append("Ready - enter any indicator, CVE, malware, actor, or topic to search", style="dim")
    else:
        t = dossier.target
        bar.append(f"{t.canonical_name} ({_friendly_kind(t.detected_kind)})", style="bold cyan")
        if dossier.risk_score is not None:
            bar.append("  |  ", style="dim")
            bar.append(f"Risk: {dossier.risk_score}/99", style=risk_color(dossier.risk_score))
        notes_cnt = 0
        notes_sec = dossier.sections.get("analyst_notes")
        if notes_sec and isinstance(notes_sec.data, dict):
            notes_cnt = len(_as_list(notes_sec.data.get("data")))
        rules_cnt = 0
        rules_sec = dossier.sections.get("detection_rules")
        if rules_sec and isinstance(rules_sec.data, list):
            rules_cnt = len(rules_sec.data)
        bar.append("  |  ", style="dim")
        bar.append(f"Related: {len(dossier.pivots)}", style="cyan")
        bar.append("  |  ", style="dim")
        bar.append(f"Reports: {notes_cnt}", style="cyan")
        bar.append("  |  ", style="dim")
        bar.append(f"Rules: {rules_cnt}", style="cyan")
        if visible_findings != total_findings:
            bar.append(f"  |  Shown: {visible_findings}/{total_findings}", style="yellow")

    bar.append("   ::   [Enter] Open/Search  [p] Pivot  [[] Back  []] Fwd  [/] Options  [j] JSON", style="dim")
    return bar


def render_search_brief(dossier: ResearchDossier) -> Group:
    """Render a clean, unified Threat Intelligence Brief for the user's search."""
    t = dossier.target
    v2_data, comp_data = _extract_v2_data(dossier)
    risk_obj = _as_dict(v2_data.get("risk"))
    timestamps = _as_dict(v2_data.get("timestamps"))
    location = _as_dict(v2_data.get("location"))

    rows: list[tuple[str, str | Text]] = [
        ("Target", t.canonical_name),
        ("Type", _friendly_kind(t.detected_kind)),
    ]
    if t.entity_id:
        rows.append(("Entity ID", t.entity_id))
    if dossier.risk_score is not None:
        rows.append(("Risk Score", risk_gauge(dossier.risk_score)))
        if dossier.criticality_label or dossier.risk_string:
            rows.append(
                (
                    "Severity",
                    f"{dossier.criticality_label or '-'} ({dossier.risk_string or '-'})",
                )
            )
    if t.aliases:
        rows.append(("Aliases", ", ".join(t.aliases[:12])))
    if timestamps.get("firstSeen") or timestamps.get("lastSeen"):
        rows.append(
            (
                "Observed",
                f"First: {format_timestamp(timestamps.get('firstSeen'))}  |  Last: {format_timestamp(timestamps.get('lastSeen'))}",
            )
        )
    if location:
        loc_parts = [
            _as_str(location.get("city")),
            _as_str(location.get("country")),
            _as_str(_as_dict(location.get("asn")).get("name") or location.get("organization")),
        ]
        loc_str = ", ".join(p for p in loc_parts if p)
        if loc_str:
            rows.append(("Location / ASN", loc_str))

    cvss = _as_dict(v2_data.get("cvssv3") or v2_data.get("cvss"))
    if cvss.get("score") is not None or v2_data.get("lifecycleStage"):
        cvss_str = f"CVSS {cvss.get('score', '-')}" if cvss else "-"
        life = _as_str(v2_data.get("lifecycleStage") or "-")
        rows.append(("Vulnerability", f"{cvss_str}  |  Lifecycle: {life}"))
    if v2_data.get("nvdDescription"):
        rows.append(("NVD Summary", truncate_text(v2_data.get("nvdDescription"), 280)))
    if comp_data and "error" not in comp_data:
        comp_name = _as_str(_as_dict(comp_data.get("entity")).get("name") or comp_data.get("name"))
        if comp_name:
            rows.append(("Owner", comp_name))

    threat_lists = [
        _as_str(tl.get("name") or tl.get("id"))
        for tl in _as_list(v2_data.get("threatLists"))
        if isinstance(tl, dict)
    ]
    if threat_lists:
        rows.append(("Threat Lists", ", ".join(x for x in threat_lists[:8] if x)))

    if v2_data.get("intelCard"):
        rows.append(("Portal Link", _as_str(v2_data.get("intelCard"))))

    parts: list[Any] = [
        Panel(_kv_table(rows), title=f"Intelligence Brief: {t.canonical_name}", border_style="cyan", padding=(0, 1))
    ]

    if dossier.ai_summary:
        parts.append(
            Panel(
                Text(dossier.ai_summary),
                title="Summary",
                border_style="blue",
                padding=(0, 1),
            )
        )

    evidence = [e for e in _as_list(risk_obj.get("evidenceDetails")) if isinstance(e, dict)]
    if evidence:
        ev_tbl = Table(box=box.SIMPLE, expand=True, title=f"Risk Rules & Evidence ({len(evidence)})", title_justify="left")
        ev_tbl.add_column("Criticality", style="bold", width=13)
        ev_tbl.add_column("Rule", style="cyan", width=28)
        ev_tbl.add_column("Evidence", overflow="fold")
        for ev in evidence[:15]:
            ev_tbl.add_row(
                _as_str(ev.get("criticalityLabel") or ev.get("criticality") or "-"),
                _as_str(ev.get("rule") or "-"),
                truncate_text(ev.get("evidenceString") or "-", 140),
            )
        parts.append(ev_tbl)

    # Threat Map scores if present
    tm_sec = dossier.sections.get("threat_map")
    tm_items = (
        [x for x in _as_list(_as_dict(_as_dict(tm_sec.data).get("data")).get("threat_map")) if isinstance(x, dict)]
        if tm_sec
        else []
    )
    if tm_items:
        tm_tbl = Table(box=box.SIMPLE, expand=True, title="Threat Map Relevance", title_justify="left")
        tm_tbl.add_column("Name", style="bold")
        tm_tbl.add_column("Intent / Prevalence", justify="right", width=20)
        tm_tbl.add_column("Opportunity", justify="right", width=14)
        for item in tm_items[:10]:
            s_a = item.get("intent") if "intent" in item else item.get("prevalence")
            tm_tbl.add_row(
                _as_str(item.get("name") or "-"),
                str(s_a if s_a is not None else "-"),
                str(item.get("opportunity") if item.get("opportunity") is not None else "-"),
            )
        parts.append(tm_tbl)

    # Top related entities
    if dossier.pivots:
        piv_tbl = Table(
            box=box.SIMPLE,
            expand=True,
            title=f"Related Entities ({len(dossier.pivots)} total - select on left to inspect or pivot)",
            title_justify="left",
        )
        piv_tbl.add_column("Entity", style="bold", width=28)
        piv_tbl.add_column("Type", style="cyan", width=18)
        piv_tbl.add_column("Risk", justify="right", width=6)
        piv_tbl.add_column("Relationship", overflow="fold")
        for piv in dossier.pivots[:12]:
            piv_tbl.add_row(
                truncate_text(piv.name, 28),
                piv.entity_type,
                score_text(piv.risk_score),
                truncate_text(piv.relationship or "-", 52),
            )
        parts.append(piv_tbl)

    # Top Threat Reports
    notes_sec = dossier.sections.get("analyst_notes")
    notes = (
        [n for n in _as_list(_as_dict(notes_sec.data).get("data")) if isinstance(n, dict)]
        if notes_sec
        else []
    )
    if notes:
        notes_tbl = Table(box=box.SIMPLE, expand=True, title=f"Threat Reports ({len(notes)})", title_justify="left")
        notes_tbl.add_column("Published", width=12)
        notes_tbl.add_column("Title", style="bold", overflow="fold")
        notes_tbl.add_column("Topics", width=24)
        for n in notes[:8]:
            attrs = _as_dict(n.get("attributes"))
            tps = ", ".join(
                _as_str(tp.get("name") or tp.get("id"))
                for tp in _as_list(attrs.get("topic"))
                if isinstance(tp, dict)
            )
            notes_tbl.add_row(
                format_date_or_ts(attrs.get("published"))[:10],
                _as_str(attrs.get("title") or n.get("id") or "-"),
                truncate_text(tps or "-", 24),
            )
        parts.append(notes_tbl)

    # Detection rules & alerts summary if present
    rules_sec = dossier.sections.get("detection_rules")
    rules = rules_sec.data if rules_sec and isinstance(rules_sec.data, list) else []
    alerts = _extract_alerts_list(dossier)
    if rules or alerts:
        extra_rows: list[tuple[str, str | Text]] = []
        if rules:
            extra_rows.append(
                (
                    "Detection Rules",
                    f"{len(rules)} rule(s): "
                    + ", ".join(_as_str(r.get("title") or r.get("id")) for r in rules[:4] if isinstance(r, dict)),
                )
            )
        if alerts:
            extra_rows.append(("Matching Alerts", f"{len(alerts)} alert(s) found (select Alert rows on left for details)"))
        parts.append(Panel(_kv_table(extra_rows), title="Detections & Alerts", border_style="dim", padding=(0, 1)))

    # Empty state if nothing at all came back
    has_any_data = bool(
        v2_data
        or dossier.ai_summary
        or dossier.pivots
        or notes
        or tm_items
        or rules
        or alerts
        or any(s.status == "ok" and s.count > 0 for s in dossier.sections.values())
    )
    if not has_any_data:
        parts.append(
            Panel(
                Text(
                    f"No intelligence records were found for '{t.raw_query}'. "
                    "Try searching by a specific domain, IP, CVE, hash, malware name, or threat actor alias."
                ),
                border_style="yellow",
                padding=(0, 1),
            )
        )

    return Group(*parts)


def render_pivot_detail(pivot: ResearchPivot) -> Group:
    """Render detail panel for a selected related entity."""
    rows: list[tuple[str, str | Text]] = [
        ("Entity", pivot.name),
        ("Type", pivot.entity_type),
        ("ID", pivot.entity_id),
        ("Risk Score", risk_gauge(pivot.risk_score) if pivot.risk_score is not None else Text("-", style="dim")),
        ("Relationship", pivot.relationship or "-"),
    ]
    return Group(
        Panel(
            _kv_table(rows),
            title="Related Entity (Press Enter or 'p' to Search This Entity)",
            border_style="cyan",
            padding=(0, 1),
        )
    )


def render_analyst_note_detail(note: dict[str, Any]) -> Group:
    """Render a Recorded Future Analyst Note cleanly."""
    attrs = _as_dict(note.get("attributes")) or note
    src = _as_dict(note.get("source"))
    topics = [
        _as_str(t.get("name") or t.get("id"))
        for t in _as_list(attrs.get("topic"))
        if isinstance(t, dict)
    ]
    labels = [
        _as_str(lb.get("name") or lb.get("id"))
        for lb in _as_list(attrs.get("labels"))
        if isinstance(lb, dict)
    ]
    rows: list[tuple[str, str | Text]] = [
        ("Title", _as_str(attrs.get("title") or note.get("id") or "-")),
        ("Published", format_timestamp(attrs.get("published"))),
        ("Source", _as_str(src.get("name") or src.get("id") or "-")),
        ("Topics", ", ".join(t for t in topics if t) or "-"),
        ("Labels", ", ".join(lb for lb in labels if lb) or "-"),
    ]
    parts: list[Any] = [
        Panel(_kv_table(rows), title="Threat Report", border_style="cyan", padding=(0, 1))
    ]

    text_body = _as_str(attrs.get("text")).strip()
    if text_body:
        parts.append(
            Panel(
                Text(text_body[:6000] + ("\n...[truncated]" if len(text_body) > 6000 else "")),
                title="Report Content",
                border_style="blue",
                padding=(0, 1),
            )
        )

    entities = [e for e in _as_list(attrs.get("note_entities")) if isinstance(e, dict)]
    if entities:
        tbl = Table(box=box.SIMPLE, expand=True, title=f"Mentioned Entities ({len(entities)})", title_justify="left")
        tbl.add_column("Name", style="bold")
        tbl.add_column("Type", style="cyan", width=20)
        for ent in entities[:20]:
            tbl.add_row(_as_str(ent.get("name") or "-"), _as_str(ent.get("type") or "-"))
        parts.append(tbl)

    val_urls = [u for u in _as_list(attrs.get("validation_urls")) if isinstance(u, dict)]
    if val_urls:
        url_lines = "\n".join(_as_str(u.get("name") or u.get("id")) for u in val_urls[:10])
        parts.append(Panel(Text(url_lines), title="References", border_style="dim", padding=(0, 1)))

    return Group(*parts)


def render_threat_actor_detail(item: dict[str, Any]) -> Group:
    """Render a Threat Actor profile or Threat Map entry."""
    attrs = _as_dict(item.get("attributes"))
    name = _as_str(attrs.get("name") or item.get("name") or item.get("id") or "-")
    common_names = [_as_str(x) for x in _as_list(attrs.get("common_names") or item.get("common_names")) if x]
    aliases = [_as_str(x) for x in _as_list(attrs.get("alias") or item.get("alias")) if x]
    cats = [
        _as_str(c.get("name") or c.get("id")) if isinstance(c, dict) else _as_str(c)
        for c in _as_list(attrs.get("categories") or item.get("categories"))
    ]
    rows: list[tuple[str, str | Text]] = [
        ("Name", name),
        ("Entity ID", _as_str(item.get("id") or "-")),
        ("Categories", ", ".join(c for c in cats if c) or "-"),
        ("Common Names", ", ".join(common_names[:10]) or "-"),
        ("Aliases", ", ".join(aliases[:12]) or "-"),
    ]
    if "intent" in item or "prevalence" in item or "opportunity" in item:
        if "intent" in item:
            rows.append(("Intent Score", f"{item.get('intent', '-')}/100"))
        if "prevalence" in item:
            rows.append(("Prevalence", f"{item.get('prevalence', '-')}/100"))
        rows.append(("Opportunity", f"{item.get('opportunity', '-')}/100"))

    parts: list[Any] = [
        Panel(_kv_table(rows), title="Threat Actor / Threat Map", border_style="cyan", padding=(0, 1))
    ]

    logs = [lg for lg in _as_list(item.get("log_entries")) if isinstance(lg, dict)]
    if logs:
        tbl = Table(box=box.SIMPLE, expand=True, title=f"Signals ({len(logs)})", title_justify="left")
        tbl.add_column("Axis", width=12)
        tbl.add_column("Severity", width=8, justify="right")
        tbl.add_column("Indicator / Technique", overflow="fold")
        tbl.add_column("Date", width=12)
        for lg in logs[:20]:
            ent = _as_dict(lg.get("entity"))
            tbl.add_row(
                _as_str(lg.get("axis") or "-"),
                _as_str(lg.get("severity") or "-"),
                _as_str(ent.get("name") or ent.get("id") or "-"),
                format_timestamp(lg.get("date"))[:10],
            )
        parts.append(tbl)
    return Group(*parts)


def render_finding_detail(
    finding: dict[str, Any], dossier: ResearchDossier | None = None
) -> Group:
    """Render detailed Rich panels for any selected search finding row."""
    kind = _as_str(finding.get("kind"))
    payload = finding.get("payload")

    if kind == "brief":
        target_dossier = payload if isinstance(payload, ResearchDossier) else dossier
        if target_dossier is not None:
            return render_search_brief(target_dossier)
        return render_research_welcome()

    if kind == "note" and isinstance(payload, dict):
        return render_analyst_note_detail(payload)

    if kind == "pivot" and isinstance(payload, ResearchPivot):
        return render_pivot_detail(payload)

    if kind == "actor" and isinstance(payload, dict):
        return render_threat_actor_detail(payload)

    if kind == "rule" and isinstance(payload, dict):
        r_title = _as_str(payload.get("title") or payload.get("id") or "Detection Rule")
        r_type = _as_str(payload.get("type") or "sigma")
        r_body = _as_str(payload.get("rules") or payload.get("content") or payload.get("rule") or "")
        rows: list[tuple[str, str | Text]] = [
            ("Title", r_title),
            ("Type", r_type.upper()),
            ("File", _as_str(payload.get("file_name") or "-")),
            ("Updated", format_timestamp(payload.get("updated"))),
        ]
        parts: list[Any] = [Panel(_kv_table(rows), title="Detection Rule", border_style="cyan", padding=(0, 1))]
        if r_body:
            lexer = "yaml" if r_type.lower() == "sigma" else "text"
            parts.append(Panel(Syntax(r_body[:6000], lexer, word_wrap=True), title="Rule Content", border_style="blue"))
        return Group(*parts)

    if kind == "alert_v3" and isinstance(payload, dict):
        return render_alert_v3_detail(normalize_alert_v3(payload))

    if kind == "playbook" and isinstance(payload, dict):
        return render_playbook_alert_detail(normalize_playbook_alert(payload))

    if kind == "sandbox" and isinstance(payload, dict):
        return render_sandbox_detail(normalize_sandbox_sample(payload))

    if kind == "malware_sample" and isinstance(payload, dict):
        rows = [
            ("SHA-256 / Artifact", _as_str(payload.get("name") or "-")),
            ("Samples Observed", _as_str(payload.get("count") or "-")),
            ("Risk Score", risk_gauge(payload["risk_score"]) if isinstance(payload.get("risk_score"), int) else Text("-", style="dim")),
            ("Sandbox Score", f"{payload['sandbox_score']}/10" if payload.get("sandbox_score") is not None else "-"),
            ("Tags", ", ".join(_as_str(x) for x in _as_list(payload.get("tags"))) or "-"),
            ("File Types", ", ".join(_as_str(x) for x in _as_list(payload.get("file_extensions"))) or "-"),
        ]
        return Group(Panel(_kv_table(rows), title="Malware Sample", border_style="cyan", padding=(0, 1)))

    formatted = json.dumps(payload, indent=2, default=str)
    if len(formatted) > 10000:
        formatted = formatted[:10000] + "\n... [truncated]"
    return Group(
        Panel(
            Syntax(formatted, "json", word_wrap=True),
            title=_as_str(finding.get("title") or "Details"),
            border_style="cyan",
        )
    )


def render_research_json(payload: Any) -> Panel:
    """Render raw JSON safely via shared Rich formatter."""
    return render_raw_json(payload)
