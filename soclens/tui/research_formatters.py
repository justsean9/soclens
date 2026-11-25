"""Unified Recorded Future + Passive OSINT Rich renderables for the Research Workbench TUI."""

from __future__ import annotations

import json
from typing import Any

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from soclens.osint import OSINT_SOURCE_CATALOG, OSINT_SOURCES_BY_KEY, OSINTClient
from soclens.research import ResearchDossier, ResearchPivot, compute_unified_verdict
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

_VERDICT_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "bold dark_orange",
    "medium": "bold yellow",
    "low": "cyan",
    "benign": "bold green",
    "unknown": "dim",
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
        from soclens.tui.pivot import make_pivot_text

        table.add_row(Text(k, style="bold dim"), make_pivot_text(cell, field=k))
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


def _percent_gauge(
    value: float | int | None,
    *,
    max_value: float = 100.0,
    width: int = 16,
    invert_good: bool = False,
    suffix: str = "%",
) -> Text:
    if value is None:
        return Text("[" + "-" * width + "] N/A", style="dim")
    ratio = max(0.0, min(1.0, float(value) / max_value if max_value > 0 else 0.0))
    filled = int(round(ratio * width))
    bar = "#" * filled + "-" * max(0, width - filled)
    if invert_good:
        style = "bold green" if ratio >= 0.5 else ("yellow" if ratio >= 0.25 else "red")
    else:
        style = (
            "bold red"
            if ratio >= 0.75
            else ("bold dark_orange" if ratio >= 0.4 else ("bold yellow" if ratio >= 0.15 else "green"))
        )
    val_str = f"{value:.1f}{suffix}" if isinstance(value, float) else f"{value}{suffix}"
    return Text(f"[{bar}] {val_str}", style=style)


def render_research_welcome(*, osint_client: OSINTClient | None = None) -> Group:
    """Render a clean search-first welcome guide showcasing unified RF + Free OSINT sources."""
    intro = Panel(
        Text.from_markup(
            "[bold cyan]Unified Threat Research (Recorded Future + Passive OSINT)[/bold cyan]\n"
            "Start typing anywhere on this tab (or click the search bar above) to investigate any "
            "[bold]domain[/bold] (e.g. [cyan]badsite.com[/cyan]), [bold]IP[/bold], [bold]URL[/bold], "
            "[bold]hash[/bold], [bold]CVE[/bold], [bold]ASN[/bold], [bold]email[/bold], "
            "[bold]malware[/bold], or [bold]threat actor[/bold] in one pane of glass.\n"
            "[dim]All OSINT queries are 100% passive (zero direct connections to the target).[/dim]\n\n"
            "[bold]Shortcuts:[/bold]  [cyan]Enter[/cyan] Search / Open   "
            "[cyan]p[/cyan] Pivot Selected   [cyan]s[/cyan] OSINT Sources   "
            "[cyan][ / ][/cyan] Back / Fwd   [cyan]/[/cyan] Filter & Options   "
            "[cyan]j[/cyan] JSON   [cyan]m[/cyan] Menu"
        ),
        border_style="cyan",
        padding=(0, 1),
    )

    examples = Table(
        box=box.SIMPLE,
        expand=True,
        title="Example Searches (double-click or press Enter to run)",
        title_justify="left",
    )
    examples.add_column("Category", style="bold cyan", width=16)
    examples.add_column("Query", style="bold", width=20)
    examples.add_column("Unified RF + OSINT Data Returned", overflow="fold")
    for cat, q, desc in (
        ("Threat Actor", "APT29", "RF actor profile, aliases, threat map, Insikt reports & Sigma/YARA rules"),
        ("Vulnerability", "CVE-2021-44228", "RF CVSS/rules + MITRE CVE 5.x, FIRST EPSS probability & CISA KEV active-exploit"),
        ("Malware", "Cobalt Strike", "RF family profile, threat map, sandbox samples, reports & detection rules"),
        ("IP / Domain", "8.8.8.8", "RF risk & links + WHOIS/RDAP, DNS/PTR, GeoIP, BGP/ASN, Shodan ports/CVEs, DShield, OTX & VT"),
    ):
        examples.add_row(cat, q, desc)

    # Free OSINT Source Catalog showcase
    try:
        client = osint_client if osint_client is not None else OSINTClient()
        avail = client.source_availability()
    except Exception:
        avail = []

    parts: list[Any] = [intro, examples]
    if avail:
        ready_cnt = sum(1 for row in avail if row["configured"])
        src_tbl = Table(
            box=box.SIMPLE,
            expand=True,
            title=f"Integrated Free Passive OSINT Sources ({ready_cnt}/{len(avail)} Ready — click 'Sources' to toggle or 'Settings' for optional free keys)",
            title_justify="left",
        )
        src_tbl.add_column("Source", style="bold", width=22)
        src_tbl.add_column("Tier", width=15)
        src_tbl.add_column("IOC Types", style="cyan", width=22)
        src_tbl.add_column("Status", width=22)
        for row in avail:
            tier_lbl = {
                "free_no_key": Text("Free (No Key)", style="green"),
                "free_optional_key": Text("Free (+Opt Key)", style="cyan"),
                "free_api_key": Text("Free API Key", style="yellow"),
            }.get(str(row["tier"]), Text("Free", style="green"))
            state = str(row["state"])
            if state == "key_configured":
                st_cell = Text("Ready (Key Set)", style="bold green")
            elif state == "ready":
                st_cell = Text("Ready Now", style="green")
            else:
                st_cell = Text("Add Free Key (Settings)", style="yellow")
            kinds = ", ".join(str(k).upper() if k in ("ip", "url", "asn") else str(k).title() for k in row["supported_kinds"])
            src_tbl.add_row(str(row["short_name"]) + f" ({row['category']})", tier_lbl, kinds, st_cell)
        parts.append(src_tbl)

    return Group(*parts)


def build_research_findings(dossier: ResearchDossier) -> list[dict[str, Any]]:
    """Build a unified, clickable list of Recorded Future + OSINT findings."""
    t = dossier.target
    verdict = dossier.unified_verdict or compute_unified_verdict(dossier)

    brief_detail_parts: list[str] = [_friendly_kind(t.detected_kind)]
    if dossier.risk_score is not None:
        brief_detail_parts.append(f"RF {dossier.risk_score}/99")
    if dossier.criticality_label:
        brief_detail_parts.append(dossier.criticality_label)
    osint_ok = int(verdict.get("osint_sources_ok") or 0)
    osint_tot = int(verdict.get("osint_sources_total") or 0)
    if osint_tot > 0:
        brief_detail_parts.append(f"OSINT {osint_ok}/{osint_tot}")

    findings: list[dict[str, Any]] = [
        {
            "kind": "brief",
            "category": "Summary",
            "source_group": "unified",
            "source_label": "Unified",
            "title": f"{t.canonical_name} - Intelligence Brief",
            "detail": " | ".join(brief_detail_parts),
            "risk_score": dossier.risk_score,
            "payload": dossier,
            "search_blob": f"summary brief unified {t.canonical_name} {t.detected_kind} {' '.join(t.aliases)}".lower(),
        }
    ]

    # OSINT Section Findings (only populated sections with clean analyst summaries)
    for sec in dossier.osint_sections.values():
        if sec.status != "ok" or not sec.data:
            continue
        spec = OSINT_SOURCES_BY_KEY.get(sec.key)
        cat = spec.category if spec else "OSINT"
        short_lbl = spec.short_name if spec else "OSINT"
        findings.append(
            {
                "kind": "osint_section",
                "section_key": sec.key,
                "category": cat,
                "source_group": "osint",
                "source_label": short_lbl,
                "title": sec.message or sec.title,
                "detail": sec.title,
                "payload": sec.data,
                "search_blob": f"osint {cat} {short_lbl} {sec.title} {sec.message}".lower(),
            }
        )

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
                    "source_group": "rf",
                    "source_label": "RF",
                    "title": title,
                    "detail": detail,
                    "note_id": _as_str(note.get("id")),
                    "payload": note,
                    "search_blob": f"report rf {title} {detail}".lower(),
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
                    "source_group": "rf",
                    "source_label": "RF",
                    "title": name,
                    "detail": ", ".join(aliases[:4]) or "Threat Actor Profile",
                    "pivot_target": eid or name,
                    "pivot_kind": "actor",
                    "payload": actor,
                    "search_blob": f"actor rf {name} {' '.join(aliases)}".lower(),
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
                    "source_group": "rf",
                    "source_label": "RF",
                    "title": name,
                    "detail": detail,
                    "pivot_target": _as_str(entry.get("id") or name),
                    "pivot_kind": "auto",
                    "payload": entry,
                    "search_blob": f"threat map rf {name} {detail}".lower(),
                }
            )

    # Related Entities (Unified RF + OSINT Pivots)
    for piv in dossier.pivots:
        risk_str = f"Risk {piv.risk_score}" if piv.risk_score is not None else ""
        detail_parts = [piv.entity_type, risk_str, piv.relationship]
        detail = " | ".join(part for part in detail_parts if part)
        is_osint_piv = piv.source_section.startswith("osint_")
        first_src = piv.source_section.split(",")[0].strip()
        piv_src_lbl = (
            OSINT_SOURCES_BY_KEY[first_src].short_name
            if first_src in OSINT_SOURCES_BY_KEY
            else "RF"
        )
        findings.append(
            {
                "kind": "pivot",
                "category": "Related",
                "source_group": "osint" if is_osint_piv else "rf",
                "source_label": piv_src_lbl,
                "title": piv.name,
                "detail": detail,
                "risk_score": piv.risk_score,
                "pivot_target": piv.entity_id,
                "pivot_kind": piv.pivot_kind,
                "payload": piv,
                "search_blob": f"related {piv_src_lbl} {piv.name} {piv.entity_id} {piv.entity_type} {piv.relationship}".lower(),
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
                    "source_group": "rf",
                    "source_label": "RF",
                    "title": r_title,
                    "detail": f"{r_type} | Updated {upd}",
                    "payload": rule,
                    "search_blob": f"rule rf {r_title} {r_type} {upd}".lower(),
                }
            )

    # Alerts v3
    for al in _extract_alerts_list(dossier):
        norm = normalize_alert_v3(al)
        findings.append(
            {
                "kind": "alert_v3",
                "category": "Alert",
                "source_group": "rf",
                "source_label": "RF",
                "title": norm.get("title") or norm.get("id") or "Alert",
                "detail": f"{norm.get('priority', '-')} | {norm.get('status', '-')} | {format_date_or_ts(norm.get('triggered'))}",
                "payload": al,
                "search_blob": f"alert rf {norm.get('title')} {norm.get('rule_name')} {norm.get('status')}".lower(),
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
                    "source_group": "rf",
                    "source_label": "RF",
                    "title": norm.get("title") or norm.get("id") or "Playbook Alert",
                    "detail": f"{norm.get('category', '-')} | {norm.get('priority', '-')} | {norm.get('status', '-')}",
                    "payload": pb,
                    "search_blob": f"playbook alert rf {norm.get('title')} {norm.get('category')}".lower(),
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
                    "source_group": "rf",
                    "source_label": "RF",
                    "title": name,
                    "detail": " | ".join(detail_parts) or "Malware Sample",
                    "pivot_target": f"hash:{name}" if len(name) == 64 else name,
                    "pivot_kind": "hash" if len(name) == 64 else "auto",
                    "payload": item,
                    "search_blob": f"sample rf {name} {tags}".lower(),
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
                    "source_group": "rf",
                    "source_label": "RF",
                    "title": title,
                    "detail": f"Score {norm.get('score') if norm.get('score') is not None else '-'}/10 | {norm.get('status', '-')}",
                    "pivot_target": piv_target or None,
                    "pivot_kind": "hash" if norm.get("sha256") else "auto",
                    "payload": smp,
                    "search_blob": f"sandbox rf {title} {norm.get('sha256')} {' '.join(norm.get('families') or [])}".lower(),
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
                    "source_group": "rf",
                    "source_label": "RF",
                    "title": f"Risk Timeline: {_as_str(ent.get('name') or t.canonical_name)}",
                    "detail": f"{len(scores)} score changes | {len(rules)} rule events",
                    "payload": hist,
                    "search_blob": f"risk history rf {ent.get('name')}".lower(),
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
                    "source_group": "rf",
                    "source_label": "RF",
                    "title": subj,
                    "detail": f"{cnt} exposure(s)" if cnt is not None else _as_str(exp.get("type") or "Credential Exposure"),
                    "payload": exp,
                    "search_blob": f"exposure rf {subj}".lower(),
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
                    "source_group": "rf",
                    "source_label": "ASI",
                    "title": name,
                    "detail": f"Score: {asset.get('exposure_score', '-')}",
                    "payload": asset,
                    "search_blob": f"attack surface asi {name}".lower(),
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
                    "source_group": "rf",
                    "source_label": "RiskRecon",
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
                        "source_group": "rf",
                        "source_label": "RF Ext",
                        "title": f"{ext_name} Context",
                        "detail": truncate_text(format_kv_summary(ext_payload.get("data") or ext_payload, max_items=4), 60),
                        "payload": ext_payload,
                        "search_blob": f"extension context {ext_name}".lower(),
                    }
                )

    # OSINT Source Coverage & Free Keys Matrix row (when OSINT ran)
    if dossier.osint_sections:
        ok_cnt = sum(1 for s in dossier.osint_sections.values() if s.status == "ok")
        clean_cnt = sum(1 for s in dossier.osint_sections.values() if s.status == "empty")
        need_key_cnt = sum(1 for s in dossier.osint_sections.values() if s.status == "not_configured")
        cov_parts = [f"{ok_cnt} hit(s)", f"{clean_cnt} clean"]
        if need_key_cnt:
            cov_parts.append(f"{need_key_cnt} optional free key(s)")
        findings.append(
            {
                "kind": "osint_sources",
                "category": "Sources",
                "source_group": "osint",
                "source_label": "Coverage",
                "title": "OSINT Source Coverage & Free Keys",
                "detail": " | ".join(cov_parts),
                "payload": {k: s.message for k, s in dossier.osint_sections.items()},
                "search_blob": "osint sources coverage free keys virustotal abuseipdb abuse.ch whois dns shodan",
            }
        )

    return findings


def build_search_summary_bar(
    dossier: ResearchDossier | None,
    total_findings: int,
    visible_findings: int,
) -> Text:
    """Build a concise single-line unified RF + OSINT KPI bar."""
    bar = Text()
    if dossier is None:
        bar.append("Ready — search any domain, IP, URL, hash, CVE, ASN, actor, or topic (RF + Free OSINT)", style="dim")
    else:
        t = dossier.target
        verdict = dossier.unified_verdict or compute_unified_verdict(dossier)
        bar.append(f"{t.canonical_name} ({_friendly_kind(t.detected_kind)})", style="bold cyan")
        if verdict.get("level") and verdict["level"] != "unknown":
            bar.append("  |  ", style="dim")
            bar.append(str(verdict.get("label", "")), style=_VERDICT_STYLES.get(str(verdict["level"]), "white"))
        if dossier.risk_score is not None:
            bar.append("  |  ", style="dim")
            bar.append(f"RF: {dossier.risk_score}/99", style=risk_color(dossier.risk_score))
        vt_sec = dossier.sections.get("osint_virustotal")
        if vt_sec and vt_sec.status == "ok" and isinstance(vt_sec.data, dict):
            mal = int(vt_sec.data.get("malicious") or 0)
            tot = int(vt_sec.data.get("total_engines") or 0)
            bar.append("  |  ", style="dim")
            bar.append(f"VT: {mal}/{tot}", style="bold red" if mal else "green")
        if dossier.osint_sections:
            osint_ok = sum(1 for s in dossier.osint_sections.values() if s.status == "ok")
            bar.append("  |  ", style="dim")
            bar.append(f"OSINT: {osint_ok}/{len(dossier.osint_sections)}", style="green" if osint_ok else "dim")
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
        if notes_cnt:
            bar.append("  |  ", style="dim")
            bar.append(f"Reports: {notes_cnt}", style="cyan")
        if rules_cnt:
            bar.append("  |  ", style="dim")
            bar.append(f"Rules: {rules_cnt}", style="cyan")
        if visible_findings != total_findings:
            bar.append(f"  |  Shown: {visible_findings}/{total_findings}", style="yellow")

    bar.append("   ::   [Enter] Open  [p] Pivot  [s] Sources  [[] Back  []] Fwd  [/] Options  [j] JSON", style="dim")
    return bar


def _build_osint_snapshot_rows(dossier: ResearchDossier) -> list[tuple[str, str | Text]]:
    """Build compact single-pane-of-glass OSINT rows for the main Intelligence Brief."""
    rows: list[tuple[str, str | Text]] = []

    rdap = dossier.sections.get("osint_rdap")
    if rdap and rdap.status == "ok" and isinstance(rdap.data, dict):
        d = rdap.data
        txt = Text()
        pieces: list[tuple[str, str]] = []
        if d.get("registrar"):
            pieces.append((str(d["registrar"]), "bold"))
        if d.get("created"):
            created_str = format_date_or_ts(d["created"])[:10]
            age = d.get("age_days")
            flag = d.get("age_flag")
            if isinstance(age, int):
                age_style = "bold red" if flag == "newly_registered" else ("bold yellow" if flag == "recent" else "green")
                nrd = " [NRD!]" if flag == "newly_registered" else ""
                pieces.append((f"Created {created_str} ({age}d{nrd})", age_style))
            else:
                pieces.append((f"Created {created_str}", "white"))
        if d.get("expires"):
            pieces.append((f"Exp {format_date_or_ts(d['expires'])[:10]}", "dim"))
        if d.get("cidrs"):
            pieces.append((f"CIDR {', '.join(d['cidrs'][:2])}", "cyan"))
        elif d.get("start_address") and d.get("end_address"):
            pieces.append((f"{d['start_address']} - {d['end_address']}", "cyan"))
        if d.get("abuse_email"):
            pieces.append((f"Abuse: {d['abuse_email']}", "dim"))
        for idx, (val, st) in enumerate(pieces):
            if idx:
                txt.append("  |  ", style="dim")
            txt.append(val, style=st)
        if pieces:
            rows.append(("WHOIS / RDAP", txt))

    dns = dossier.sections.get("osint_dns")
    if dns and dns.status == "ok" and isinstance(dns.data, dict):
        d = dns.data
        dns_bits: list[str] = []
        if d.get("a"):
            dns_bits.append(f"A: {', '.join(d['a'][:3])}")
        if d.get("aaaa"):
            dns_bits.append(f"AAAA: {d['aaaa'][0]}")
        if d.get("ptr"):
            dns_bits.append(f"PTR: {', '.join(d['ptr'][:2])}")
        if d.get("mx"):
            mx_clean = [str(m).split()[-1] for m in d["mx"][:2]]
            dns_bits.append(f"MX: {', '.join(mx_clean)}")
        if d.get("ns"):
            dns_bits.append(f"NS: {', '.join(d['ns'][:2])}")
        if d.get("spf_status"):
            dns_bits.append(f"SPF: {d['spf_status']}")
        if d.get("dmarc_policy"):
            dns_bits.append(f"DMARC: {d['dmarc_policy']}")
        if d.get("rcode") == "NXDOMAIN":
            dns_bits.insert(0, "NXDOMAIN")
        rows.append(("DNS & Email", "  |  ".join(dns_bits) or dns.message))

    geo = dossier.sections.get("osint_geoip")
    bgp = dossier.sections.get("osint_bgp")
    net_bits: list[str] = []
    if geo and geo.status == "ok" and isinstance(geo.data, dict):
        gd = geo.data
        loc = ", ".join(p for p in (gd.get("city"), gd.get("region"), gd.get("country_code") or gd.get("country")) if p)
        if loc:
            net_bits.append(loc)
        if gd.get("org") or gd.get("isp"):
            net_bits.append(str(gd.get("org") or gd.get("isp")))
        if gd.get("resolved_from"):
            net_bits.insert(0, f"Host IP {gd.get('ip')}")
    if bgp and bgp.status == "ok" and isinstance(bgp.data, dict):
        bd = bgp.data
        if bd.get("prefix"):
            net_bits.append(f"BGP {bd['prefix']}")
        if bd.get("asns"):
            net_bits.append(", ".join(bd["asns"][:2]))
        if bd.get("mode") == "asn" and bd.get("prefix_count"):
            net_bits.append(f"{bd['prefix_count']} announced prefixes ({bd.get('holder') or '-'})")
    if net_bits:
        rows.append(("Network / BGP", "  |  ".join(net_bits)))

    shodan = dossier.sections.get("osint_shodan")
    if shodan and shodan.status == "ok" and isinstance(shodan.data, dict):
        sd = shodan.data
        txt = Text()
        ports = sd.get("port_services") or []
        if ports:
            port_str = ", ".join(
                f"{p['port']}/{p['service']}" if p.get("service") != "Unknown" else str(p["port"])
                for p in ports[:8]
            )
            if len(ports) > 8:
                port_str += f" (+{len(ports) - 8})"
            txt.append(f"Ports: {port_str}", style="cyan")
        elif sd.get("ports"):
            raw_ports = [str(p) for p in (sd.get("ports") or [])[:8]]
            port_str = ", ".join(raw_ports)
            if len(sd.get("ports") or []) > 8:
                port_str += f" (+{len(sd['ports']) - 8})"
            txt.append(f"Ports: {port_str}", style="cyan")
        vulns = sd.get("vulns") or []
        if vulns:
            if txt.plain:
                txt.append("  |  ", style="dim")
            txt.append(f"CVEs ({len(vulns)}): {', '.join(vulns[:4])}", style="bold red")
        tags = sd.get("tags") or []
        if tags:
            if txt.plain:
                txt.append("  |  ", style="dim")
            txt.append(f"Tags: {', '.join(tags[:5])}", style="yellow")
        if txt.plain:
            rows.append(("Shodan Surface", txt))

    crt = dossier.sections.get("osint_crtsh")
    if crt and crt.status == "ok" and isinstance(crt.data, dict):
        cd = crt.data
        issuers = ", ".join((cd.get("issuers") or [])[:2])
        rows.append(
            (
                "TLS Certs (crt.sh)",
                f"{cd.get('total_certs', 0)} cert(s)  |  {cd.get('unique_subdomains_count', 0)} subdomain(s)"
                + (f"  |  CA: {issuers}" if issuers else ""),
            )
        )

    us = dossier.sections.get("osint_urlscan")
    wb = dossier.sections.get("osint_wayback")
    web_bits: list[str] = []
    if us and us.status == "ok" and isinstance(us.data, dict):
        mal = int(us.data.get("malicious_count") or 0)
        tot = int(us.data.get("total") or 0)
        web_bits.append(f"URLScan: {tot} scan(s)" + (f" ({mal} MALICIOUS)" if mal else ""))
    if wb and wb.status == "ok" and isinstance(wb.data, dict):
        web_bits.append(f"Wayback: {wb.data.get('snapshot_count', 0)} snapshots (latest {str(wb.data.get('latest_capture') or '')[:10]})")
    if web_bits:
        rows.append(("Web & Archive", "  |  ".join(web_bits)))

    vt = dossier.sections.get("osint_virustotal")
    if vt and vt.status == "ok" and isinstance(vt.data, dict):
        vd = vt.data
        mal = int(vd.get("malicious") or 0)
        susp = int(vd.get("suspicious") or 0)
        tot = int(vd.get("total_engines") or 0)
        v_txt = Text(
            f"{mal}/{tot} malicious" + (f", {susp} suspicious" if susp else ""),
            style="bold red" if mal else ("bold yellow" if susp else "bold green"),
        )
        threat_lbl = vd.get("threat_label") or vd.get("suggested_threat_label")
        if threat_lbl:
            v_txt.append(f"  |  {threat_lbl}", style="bold red")
        if vd.get("categories"):
            v_txt.append(f"  |  {', '.join(vd['categories'][:3])}", style="dim")
        rows.append(("VirusTotal v3", v_txt))

    for key, label in (
        ("osint_abuseipdb", "AbuseIPDB"),
        ("osint_abusech", "abuse.ch"),
        ("osint_otx", "AlienVault OTX"),
        ("osint_greynoise", "GreyNoise"),
        ("osint_dshield", "SANS DShield"),
        ("osint_hashlookup", "NSRL Known-Good"),
        ("osint_vuln", "CVE / EPSS / KEV"),
    ):
        sec = dossier.sections.get(key)
        if sec and sec.status == "ok":
            rows.append((label, sec.message))

    return rows


def _build_source_coverage_strip(dossier: ResearchDossier) -> Text:
    """Build a compact visual source badge strip showing all queried RF & OSINT sources."""
    strip = Text()
    rf_ok = sum(1 for s in dossier.rf_sections.values() if s.status == "ok")
    if dossier.rf_sections:
        if rf_ok > 0:
            strip.append(f"✓ RF ({rf_ok})", style="bold green")
        elif any(s.status == "not_configured" for s in dossier.rf_sections.values()):
            strip.append("⚙ RF (unconfigured)", style="yellow")
        else:
            strip.append("○ RF (0 hits)", style="dim")

    for key, sec in dossier.osint_sections.items():
        spec = OSINT_SOURCES_BY_KEY.get(key)
        lbl = spec.short_name if spec else key
        if strip.plain:
            strip.append("  ", style="dim")
        if sec.status == "ok":
            strip.append(f"✓ {lbl}", style="bold green")
        elif sec.status == "empty":
            strip.append(f"○ {lbl}", style="dim")
        elif sec.status == "not_configured":
            strip.append(f"⚙ {lbl} (free key)", style="yellow")
        elif sec.status == "rate_limited":
            strip.append(f"! {lbl} (429)", style="yellow")
        elif sec.status == "skipped":
            strip.append(f"- {lbl}", style="dim")
        else:
            strip.append(f"✗ {lbl}", style="red")
    return strip


def render_search_brief(dossier: ResearchDossier) -> Group:
    """Render a unified single-pane-of-glass Threat Intelligence Brief (RF + Passive OSINT)."""
    t = dossier.target
    verdict = dossier.unified_verdict or compute_unified_verdict(dossier)
    v2_data, comp_data = _extract_v2_data(dossier)
    risk_obj = _as_dict(v2_data.get("risk"))
    timestamps = _as_dict(v2_data.get("timestamps"))
    location = _as_dict(v2_data.get("location"))

    rows: list[tuple[str, str | Text]] = [
        ("Target", t.canonical_name),
        ("Type", _friendly_kind(t.detected_kind)),
    ]
    if verdict.get("label"):
        v_lvl = str(verdict.get("level") or "unknown")
        v_txt = Text(str(verdict["label"]), style=_VERDICT_STYLES.get(v_lvl, "white"))
        if verdict.get("summary"):
            v_txt.append(f"  —  {verdict['summary']}", style="white")
        rows.append(("Unified Verdict", v_txt))
    if t.entity_id:
        rows.append(("Entity ID", t.entity_id))
    if dossier.risk_score is not None:
        rows.append(("RF Risk Score", risk_gauge(dossier.risk_score)))
        if dossier.criticality_label or dossier.risk_string:
            rows.append(
                (
                    "RF Severity",
                    f"{dossier.criticality_label or '-'} ({dossier.risk_string or '-'})",
                )
            )
    if t.aliases:
        rows.append(("Aliases", ", ".join(t.aliases[:12])))
    if timestamps.get("firstSeen") or timestamps.get("lastSeen"):
        rows.append(
            (
                "RF Observed",
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
            rows.append(("RF Location / ASN", loc_str))

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
        rows.append(("RF Portal Link", _as_str(v2_data.get("intelCard"))))

    border_style = {
        "critical": "red",
        "high": "dark_orange",
        "medium": "yellow",
        "benign": "green",
    }.get(str(verdict.get("level") or ""), "cyan")

    parts: list[Any] = [
        Panel(
            _kv_table(rows),
            title=f"Unified Intelligence Brief: {t.canonical_name}",
            border_style=border_style,
            padding=(0, 1),
        )
    ]

    # OSINT Infrastructure & Reputation Snapshot right in the brief!
    osint_rows = _build_osint_snapshot_rows(dossier)
    if osint_rows:
        parts.append(
            Panel(
                _kv_table(osint_rows),
                title="Passive OSINT & Infrastructure Intelligence (select left rows for full breakdown)",
                border_style="green",
                padding=(0, 1),
            )
        )

    if dossier.osint_sections:
        parts.append(
            Panel(
                _build_source_coverage_strip(dossier),
                title="Source Coverage (✓ Hit  ○ Clean  ⚙ Optional Free Key in Settings  - N/A)",
                border_style="dim",
                padding=(0, 1),
            )
        )

    if dossier.ai_summary:
        parts.append(
            Panel(
                Text(dossier.ai_summary),
                title="Recorded Future Summary",
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

    # Top related entities (merged RF + OSINT pivots)
    if dossier.pivots:
        piv_tbl = Table(
            box=box.SIMPLE,
            expand=True,
            title=f"Related Entities & Pivots ({len(dossier.pivots)} total — select on left & press Enter or 'p' to pivot)",
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
        or osint_rows
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


# ---------------------------------------------------------------------------
# Dedicated Rich Detail Renderers for Passive OSINT Sources
# ---------------------------------------------------------------------------


def render_osint_section_detail(
    section_key: str,
    data: dict[str, Any],
    dossier: ResearchDossier | None = None,
) -> Group:
    """Render structured, analyst-friendly Rich panels for any passive OSINT section."""
    _ = dossier
    if section_key == "osint_rdap":
        return _render_rdap_detail(data)
    if section_key == "osint_dns":
        return _render_dns_detail(data)
    if section_key == "osint_geoip":
        return _render_geoip_detail(data)
    if section_key == "osint_bgp":
        return _render_bgp_detail(data)
    if section_key == "osint_shodan":
        return _render_shodan_detail(data)
    if section_key == "osint_crtsh":
        return _render_crtsh_detail(data)
    if section_key == "osint_urlscan":
        return _render_urlscan_detail(data)
    if section_key == "osint_dshield":
        return _render_dshield_detail(data)
    if section_key == "osint_wayback":
        return _render_wayback_detail(data)
    if section_key == "osint_otx":
        return _render_otx_detail(data)
    if section_key == "osint_greynoise":
        return _render_greynoise_detail(data)
    if section_key == "osint_hashlookup":
        return _render_hashlookup_detail(data)
    if section_key == "osint_vuln":
        return _render_vuln_detail(data)
    if section_key == "osint_virustotal":
        return _render_virustotal_detail(data)
    if section_key == "osint_abuseipdb":
        return _render_abuseipdb_detail(data)
    if section_key == "osint_abusech":
        return _render_abusech_detail(data)

    formatted = json.dumps(data, indent=2, default=str)[:10000]
    return Group(Panel(Syntax(formatted, "json", word_wrap=True), title=section_key, border_style="cyan"))


def _render_rdap_detail(d: dict[str, Any]) -> Group:
    age = d.get("age_days")
    flag = d.get("age_flag")
    age_cell: str | Text = "-"
    if isinstance(age, int):
        style = "bold red" if flag == "newly_registered" else ("bold yellow" if flag == "recent" else "green")
        tag = " (NEWLY REGISTERED DOMAIN!)" if flag == "newly_registered" else (" (Recent)" if flag == "recent" else "")
        age_cell = Text(f"{age:,} day(s){tag}", style=style)

    rows: list[tuple[str, str | Text]] = [
        ("Queried Object", _as_str(d.get("name") or d.get("queried") or "-")),
        ("Object Class", _as_str(d.get("object_class") or "-")),
        ("Registry Handle", _as_str(d.get("handle") or "-")),
        ("Registrar", _as_str(d.get("registrar") or "-")),
        ("Registrant", _as_str(d.get("registrant") or "-")),
        ("Abuse Contact", _as_str(d.get("abuse_email") or "-")),
        ("Registered", format_timestamp(d.get("created")) if d.get("created") else "-"),
        ("Domain Age", age_cell),
        ("Last Updated", format_timestamp(d.get("updated")) if d.get("updated") else "-"),
        ("Expiration", format_timestamp(d.get("expires")) if d.get("expires") else "-"),
        ("DNSSEC Signed", "Yes" if d.get("dnssec_signed") else ("No" if d.get("dnssec_signed") is False else "-")),
        ("Status Flags", ", ".join(_as_str(s) for s in _as_list(d.get("statuses"))) or "-"),
    ]
    if d.get("cidrs") or d.get("start_address"):
        cidr_str = ", ".join(_as_str(c) for c in _as_list(d.get("cidrs")))
        rng = f"{d.get('start_address')} - {d.get('end_address')}" if d.get("start_address") else ""
        rows.append(("IP Netblock", " | ".join(p for p in (cidr_str, rng, _as_str(d.get("network_type"))) if p)))
    if d.get("country"):
        rows.append(("Country", _as_str(d["country"])))
    if d.get("nameservers"):
        rows.append(("Nameservers", ", ".join(_as_str(n) for n in _as_list(d.get("nameservers")))))

    parts: list[Any] = [Panel(_kv_table(rows), title="WHOIS / RDAP Registration Record", border_style="cyan", padding=(0, 1))]
    contacts = [c for c in _as_list(d.get("contacts")) if isinstance(c, dict)]
    if contacts:
        ctbl = Table(box=box.SIMPLE, expand=True, title=f"Registry Contacts ({len(contacts)})", title_justify="left")
        ctbl.add_column("Roles", style="cyan", width=20)
        ctbl.add_column("Name / Org", style="bold", width=26)
        ctbl.add_column("Email", width=28)
        ctbl.add_column("Phone / Handle", overflow="fold")
        for c in contacts:
            ctbl.add_row(
                ", ".join(_as_str(r) for r in _as_list(c.get("roles"))) or "-",
                _as_str(c.get("name") or c.get("org") or "-"),
                _as_str(c.get("email") or "-"),
                _as_str(c.get("phone") or c.get("handle") or "-"),
            )
        parts.append(ctbl)
    return Group(*parts)


def _render_dns_detail(d: dict[str, Any]) -> Group:
    rcode = _as_str(d.get("rcode") or "NOERROR")
    rcode_cell = Text(rcode, style="bold red" if rcode == "NXDOMAIN" else "green")
    rows: list[tuple[str, str | Text]] = [
        ("Query", _as_str(d.get("domain") or d.get("query") or "-")),
        ("Status (RCODE)", rcode_cell),
        ("DNSSEC Validated", Text("Yes (AD)", style="green") if d.get("dnssec") else Text("No", style="dim")),
    ]
    if d.get("reverse_pointer"):
        rows.append(("Reverse Pointer", _as_str(d["reverse_pointer"])))
        rows.append(("PTR Hostnames", ", ".join(_as_str(p) for p in _as_list(d.get("ptr"))) or "-"))
    else:
        spf_st = _as_str(d.get("spf_status") or "-")
        spf_style = "green" if "Strict" in spf_st else ("bold red" if "Permissive" in spf_st or "Missing" in spf_st else "yellow")
        rows.append(("SPF Posture", Text(spf_st, style=spf_style)))
        if d.get("spf"):
            rows.append(("SPF Record", _as_str(d["spf"])))
        dm_pol = _as_str(d.get("dmarc_policy") or "-")
        dm_style = "green" if dm_pol in ("reject", "quarantine") else ("yellow" if dm_pol == "none" else "red")
        rows.append(("DMARC Policy", Text(dm_pol.upper() if dm_pol != "-" else "-", style=dm_style)))
        if d.get("dmarc"):
            rows.append(("DMARC Record", _as_str(d["dmarc"])))

    parts: list[Any] = [Panel(_kv_table(rows), title="DNS & Email Authentication Posture (DoH)", border_style="cyan", padding=(0, 1))]
    records = [r for r in _as_list(d.get("records")) if isinstance(r, dict)]
    if records:
        rtbl = Table(box=box.SIMPLE, expand=True, title=f"Resolved DNS Records ({len(records)})", title_justify="left")
        rtbl.add_column("Type", style="bold cyan", width=8)
        rtbl.add_column("TTL", justify="right", width=7)
        rtbl.add_column("Value", overflow="fold")
        for r in records[:40]:
            rtbl.add_row(_as_str(r.get("type") or "-"), _as_str(r.get("ttl") or "-"), _as_str(r.get("value") or "-"))
        parts.append(rtbl)
    return Group(*parts)


def _render_geoip_detail(d: dict[str, Any]) -> Group:
    rows: list[tuple[str, str | Text]] = [
        ("IP Address", _as_str(d.get("ip") or "-")),
    ]
    if d.get("resolved_from"):
        rows.append(("Resolved From", _as_str(d["resolved_from"])))
    coords = (
        f"{d['latitude']}, {d['longitude']}"
        if d.get("latitude") is not None and d.get("longitude") is not None
        else "-"
    )
    rows.extend(
        [
            ("Location", ", ".join(p for p in (_as_str(d.get("city")), _as_str(d.get("region")), _as_str(d.get("country"))) if p) or "-"),
            ("Country Code", _as_str(d.get("country_code") or "-")),
            ("Coordinates", coords),
            ("Timezone", f"{d.get('timezone') or '-'} ({d.get('utc_offset') or '-'})"),
            ("ASN", _as_str(d.get("asn") or "-")),
            ("Organization", _as_str(d.get("org") or "-")),
            ("ISP", _as_str(d.get("isp") or "-")),
            ("ISP Domain", _as_str(d.get("domain") or "-")),
        ]
    )
    return Group(Panel(_kv_table(rows), title="IP Geolocation & Network (ipwho.is)", border_style="cyan", padding=(0, 1)))


def _render_bgp_detail(d: dict[str, Any]) -> Group:
    rows: list[tuple[str, str | Text]] = []
    if d.get("mode") == "asn":
        rows.extend(
            [
                ("ASN", _as_str(d.get("asn") or "-")),
                ("AS Holder", _as_str(d.get("holder") or "-")),
                ("Announced", "Yes" if d.get("announced") else "No"),
                ("Prefixes Total", f"{d.get('prefix_count', 0)} (IPv4: {d.get('ipv4_count', 0)}, IPv6: {d.get('ipv6_count', 0)})"),
                ("Abuse Contacts", ", ".join(_as_str(a) for a in _as_list(d.get("abuse_contacts"))) or "-"),
            ]
        )
    else:
        rows.append(("IP Address", _as_str(d.get("ip") or "-")))
        if d.get("resolved_from"):
            rows.append(("Resolved From", _as_str(d["resolved_from"])))
        rows.extend(
            [
                ("BGP Prefix", _as_str(d.get("prefix") or "-")),
                ("Origin ASN(s)", ", ".join(_as_str(a) for a in _as_list(d.get("asns"))) or "-"),
                ("AS Holder", _as_str(d.get("holder") or "-")),
                ("Abuse Contacts", ", ".join(_as_str(a) for a in _as_list(d.get("abuse_contacts"))) or "-"),
            ]
        )
    parts: list[Any] = [Panel(_kv_table(rows), title="BGP Routing & ASN Intelligence (RIPEstat)", border_style="cyan", padding=(0, 1))]
    v4_pf = _as_list(d.get("ipv4_prefixes"))
    v6_pf = _as_list(d.get("ipv6_prefixes"))
    if v4_pf or v6_pf:
        ptbl = Table(box=box.SIMPLE, expand=True, title="Sample Announced Prefixes", title_justify="left")
        ptbl.add_column("Family", style="cyan", width=8)
        ptbl.add_column("CIDR Prefix", style="bold")
        for p in v4_pf[:15]:
            ptbl.add_row("IPv4", _as_str(p))
        for p in v6_pf[:10]:
            ptbl.add_row("IPv6", _as_str(p))
        parts.append(ptbl)
    return Group(*parts)


def _render_shodan_detail(d: dict[str, Any]) -> Group:
    ports = [p for p in _as_list(d.get("port_services")) if isinstance(p, dict)]
    vulns = [_as_str(v) for v in _as_list(d.get("vulns")) if v]
    cpes = [_as_str(c) for c in _as_list(d.get("cpes")) if c]
    hostnames = [_as_str(h) for h in _as_list(d.get("hostnames")) if h]
    tags = [_as_str(t) for t in _as_list(d.get("tags")) if t]

    rows: list[tuple[str, str | Text]] = [("Target IP", _as_str(d.get("ip") or "-"))]
    if d.get("resolved_from"):
        rows.append(("Resolved From", _as_str(d["resolved_from"])))
    rows.extend(
        [
            ("Open Ports", f"{len(ports)} exposed port(s)"),
            ("Tags", Text(", ".join(tags), style="bold yellow") if tags else Text("-", style="dim")),
            ("Hostnames", ", ".join(hostnames[:8]) or "-"),
            ("Known CVEs", Text(f"{len(vulns)} CVE(s) detected", style="bold red") if vulns else Text("None indexed", style="green")),
        ]
    )
    parts: list[Any] = [Panel(_kv_table(rows), title="Shodan InternetDB Attack Surface (Free)", border_style="cyan", padding=(0, 1))]
    if ports:
        ptbl = Table(box=box.SIMPLE, expand=True, title=f"Exposed Ports ({len(ports)})", title_justify="left")
        ptbl.add_column("Port", style="bold cyan", width=10, justify="right")
        ptbl.add_column("Likely Service", style="bold")
        for p in ports[:30]:
            svc = _as_str(p.get("service") or "Unknown")
            st = "bold red" if p.get("port") in (23, 445, 3389, 5900, 50050) else "white"
            ptbl.add_row(str(p.get("port")), Text(svc, style=st))
        parts.append(ptbl)
    if vulns:
        parts.append(Panel(Text(", ".join(vulns)), title=f"Associated CVEs ({len(vulns)} — pivot via Related rows)", border_style="red", padding=(0, 1)))
    if cpes:
        parts.append(Panel(Text("\n".join(cpes[:20])), title=f"Detected Software / CPEs ({len(cpes)})", border_style="blue", padding=(0, 1)))
    return Group(*parts)


def _render_crtsh_detail(d: dict[str, Any]) -> Group:
    subs = [_as_str(s) for s in _as_list(d.get("subdomains")) if s]
    issuers = [_as_str(i) for i in _as_list(d.get("issuers")) if i]
    rows: list[tuple[str, str | Text]] = [
        ("Domain", _as_str(d.get("domain") or "-")),
        ("Certificates Logged", str(d.get("total_certs", 0))),
        ("Unique Subdomains", str(d.get("unique_subdomains_count", len(subs)))),
        ("Issuing CAs", ", ".join(issuers[:8]) or "-"),
        ("Earliest Cert", format_date_or_ts(d.get("earliest_cert")) if d.get("earliest_cert") else "-"),
        ("Latest Cert", format_date_or_ts(d.get("latest_cert")) if d.get("latest_cert") else "-"),
    ]
    parts: list[Any] = [Panel(_kv_table(rows), title="Certificate Transparency Logs (crt.sh)", border_style="cyan", padding=(0, 1))]
    if subs:
        parts.append(
            Panel(
                Text(", ".join(subs[:50]) + (f"\n... (+{len(subs) - 50} more)" if len(subs) > 50 else "")),
                title=f"Discovered Subdomains / SANs ({len(subs)})",
                border_style="blue",
                padding=(0, 1),
            )
        )
    certs = [c for c in _as_list(d.get("recent_certs")) if isinstance(c, dict)]
    if certs:
        ctbl = Table(box=box.SIMPLE, expand=True, title="Recent Certificates", title_justify="left")
        ctbl.add_column("Not Before", width=12)
        ctbl.add_column("Not After", width=12)
        ctbl.add_column("Common Name", style="bold", overflow="fold")
        ctbl.add_column("Issuer", style="cyan", width=24)
        for c in certs[:12]:
            ctbl.add_row(
                format_date_or_ts(c.get("not_before"))[:10],
                format_date_or_ts(c.get("not_after"))[:10],
                _as_str(c.get("common_name") or "-"),
                truncate_text(c.get("issuer") or "-", 24),
            )
        parts.append(ctbl)
    return Group(*parts)


def _render_urlscan_detail(d: dict[str, Any]) -> Group:
    mal = int(d.get("malicious_count") or 0)
    rows: list[tuple[str, str | Text]] = [
        ("Query", _as_str(d.get("query") or "-")),
        ("Total Public Scans", str(d.get("total", 0))),
        ("Malicious Verdicts", Text(f"{mal} MALICIOUS", style="bold red") if mal else Text("0 malicious", style="green")),
        ("Targeted Brands", ", ".join(_as_str(b) for b in _as_list(d.get("brands"))) or "-"),
        ("Categories", ", ".join(_as_str(c) for c in _as_list(d.get("categories"))) or "-"),
    ]
    parts: list[Any] = [Panel(_kv_table(rows), title="URLScan.io Public Web Intelligence", border_style="red" if mal else "cyan", padding=(0, 1))]
    scans = [s for s in _as_list(d.get("scans")) if isinstance(s, dict)]
    if scans:
        stbl = Table(box=box.SIMPLE, expand=True, title=f"Recent Public Scans ({len(scans)})", title_justify="left")
        stbl.add_column("Date", width=11)
        stbl.add_column("HTTP", width=5, justify="right")
        stbl.add_column("Verdict", width=10)
        stbl.add_column("IP / Country", width=20)
        stbl.add_column("Title / Server / Report", overflow="fold")
        for s in scans[:10]:
            ver = Text("MALICIOUS", style="bold red") if s.get("malicious") else Text("Clean", style="green")
            ip_c = f"{s.get('ip') or '-'} ({s.get('country') or '-'})"
            meta = " | ".join(p for p in (_as_str(s.get("title")), _as_str(s.get("server")), _as_str(s.get("report_url"))) if p)
            stbl.add_row(format_date_or_ts(s.get("time"))[:10], _as_str(s.get("status") or "-"), ver, ip_c, meta or "-")
        parts.append(stbl)
    return Group(*parts)


def _render_dshield_detail(d: dict[str, Any]) -> Group:
    cnt = int(d.get("count") or 0)
    att = int(d.get("attacks") or 0)
    rows: list[tuple[str, str | Text]] = [("IP Address", _as_str(d.get("ip") or "-"))]
    if d.get("resolved_from"):
        rows.append(("Resolved From", _as_str(d["resolved_from"])))
    rows.extend(
        [
            ("Sensor Reports", Text(f"{cnt:,}", style="bold red" if cnt >= 100 else ("yellow" if cnt else "green"))),
            ("Targets Attacked", Text(f"{att:,}", style="bold red" if att >= 50 else ("yellow" if att else "green"))),
            ("First / Last Seen", f"{d.get('first_seen') or '-'}  |  {d.get('last_seen') or '-'}"),
            ("Threat Feeds", ", ".join(_as_str(f) for f in _as_list(d.get("threatfeeds"))) or "-"),
            ("ASN / Name", f"AS{d.get('as') or '-'} ({d.get('asname') or '-'})"),
            ("Network / Country", f"{d.get('network') or '-'} ({d.get('country') or '-'})"),
            ("Abuse Contact", _as_str(d.get("abusecontact") or "-")),
        ]
    )
    return Group(Panel(_kv_table(rows), title="SANS ISC / DShield Sensor Telemetry", border_style="yellow" if cnt else "cyan", padding=(0, 1)))


def _render_wayback_detail(d: dict[str, Any]) -> Group:
    rows: list[tuple[str, str | Text]] = [
        ("Target", _as_str(d.get("query") or "-")),
        ("Recent Captures", str(d.get("snapshot_count", 0))),
        ("Latest Snapshot", format_timestamp(d.get("latest_capture")) if d.get("latest_capture") else "-"),
    ]
    parts: list[Any] = [Panel(_kv_table(rows), title="Wayback Machine Passive Archive", border_style="cyan", padding=(0, 1))]
    snaps = [s for s in _as_list(d.get("snapshots")) if isinstance(s, dict)]
    if snaps:
        tbl = Table(box=box.SIMPLE, expand=True, title="Safe Passive Archive Links", title_justify="left")
        tbl.add_column("Captured", width=18)
        tbl.add_column("HTTP", width=5, justify="right")
        tbl.add_column("MIME", width=16)
        tbl.add_column("Archive URL", overflow="fold")
        for s in snaps[:10]:
            tbl.add_row(
                format_timestamp(s.get("date"))[:16],
                _as_str(s.get("statuscode") or "-"),
                truncate_text(s.get("mimetype") or "-", 16),
                _as_str(s.get("archive_url") or s.get("original") or "-"),
            )
        parts.append(tbl)
    return Group(*parts)


def _render_otx_detail(d: dict[str, Any]) -> Group:
    p_cnt = int(d.get("pulse_count") or 0)
    rows: list[tuple[str, str | Text]] = [
        ("Indicator", f"{d.get('indicator') or '-'} ({d.get('indicator_type') or '-'})"),
        ("Threat Pulses", Text(str(p_cnt), style="bold red" if p_cnt >= 10 else ("bold yellow" if p_cnt else "green"))),
        ("Adversaries", ", ".join(_as_str(a) for a in _as_list(d.get("adversaries"))) or "-"),
        ("Malware Families", ", ".join(_as_str(m) for m in _as_list(d.get("malware_families"))) or "-"),
        ("MITRE ATT&CK", ", ".join(_as_str(a) for a in _as_list(d.get("attack_ids"))) or "-"),
        ("Tags", ", ".join(_as_str(t) for t in _as_list(d.get("tags"))[:12]) or "-"),
        ("Validations", ", ".join(_as_str(v) for v in _as_list(d.get("validations"))[:4]) or "-"),
        ("OTX Link", _as_str(d.get("gui_url") or "-")),
    ]
    parts: list[Any] = [Panel(_kv_table(rows), title="AlienVault / LevelBlue OTX Threat Intel", border_style="yellow" if p_cnt else "cyan", padding=(0, 1))]
    pulses = [p for p in _as_list(d.get("pulses")) if isinstance(p, dict)]
    if pulses:
        ptbl = Table(box=box.SIMPLE, expand=True, title=f"Community Threat Pulses ({len(pulses)} shown of {p_cnt})", title_justify="left")
        ptbl.add_column("Modified", width=11)
        ptbl.add_column("Pulse Name", style="bold", overflow="fold")
        ptbl.add_column("Adversary / Tags", width=26)
        for p in pulses[:12]:
            meta = ", ".join(x for x in [_as_str(p.get("adversary"))] + [_as_str(t) for t in _as_list(p.get("tags"))[:3]] if x)
            ptbl.add_row(format_date_or_ts(p.get("modified"))[:10], _as_str(p.get("name") or "-"), truncate_text(meta or "-", 26))
        parts.append(ptbl)
    pdns = [r for r in _as_list(d.get("passive_dns")) if isinstance(r, dict)]
    if pdns:
        dtbl = Table(box=box.SIMPLE, expand=True, title=f"OTX Passive DNS ({len(pdns)})", title_justify="left")
        dtbl.add_column("Type", style="cyan", width=6)
        dtbl.add_column("Hostname", style="bold", overflow="fold")
        dtbl.add_column("Address", width=18)
        dtbl.add_column("Last Seen", width=11)
        for r in pdns[:15]:
            dtbl.add_row(_as_str(r.get("record_type") or "-"), _as_str(r.get("hostname") or "-"), _as_str(r.get("address") or "-"), format_date_or_ts(r.get("last"))[:10])
        parts.append(dtbl)
    return Group(*parts)


def _render_greynoise_detail(d: dict[str, Any]) -> Group:
    cls = _as_str(d.get("classification") or "unknown").lower()
    cls_style = "bold red" if cls == "malicious" else ("bold green" if cls == "benign" else "yellow")
    rows: list[tuple[str, str | Text]] = [("IP Address", _as_str(d.get("ip") or "-"))]
    if d.get("resolved_from"):
        rows.append(("Resolved From", _as_str(d["resolved_from"])))
    rows.extend(
        [
            ("Classification", Text(cls.upper(), style=cls_style)),
            ("RIOT (Known Benign)", Text("YES — Known Business Service", style="bold green") if d.get("riot") else Text("No", style="dim")),
            ("Noise (Mass Scanner)", Text("YES — Internet Scanner", style="bold yellow") if d.get("noise") else Text("No", style="dim")),
            ("Entity / Actor", _as_str(d.get("name") or "-")),
            ("Last Seen", _as_str(d.get("last_seen") or "-")),
            ("Visualizer Link", _as_str(d.get("link") or "-")),
        ]
    )
    return Group(Panel(_kv_table(rows), title="GreyNoise Community Context", border_style="red" if cls == "malicious" else ("green" if d.get("riot") else "cyan"), padding=(0, 1)))


def _render_hashlookup_detail(d: dict[str, Any]) -> Group:
    trust = d.get("trust")
    rows: list[tuple[str, str | Text]] = [
        ("Verdict", Text("KNOWN-GOOD SOFTWARE (NSRL / CIRCL)", style="bold green")),
        ("Trust Score", _percent_gauge(trust, max_value=100.0, invert_good=True, suffix="/100")),
        ("Filename", _as_str(d.get("file_name") or "-")),
        ("Product", f"{d.get('product_name') or '-'} {d.get('product_version') or ''}".strip()),
        ("Operating System", _as_str(d.get("os_name") or "-")),
        ("File Size", f"{d.get('file_size') or '-'} bytes"),
        ("SHA-256", _as_str(d.get("sha256") or "-")),
        ("SHA-1", _as_str(d.get("sha1") or "-")),
        ("MD5", _as_str(d.get("md5") or "-")),
        ("Source", _as_str(d.get("source") or "NSRL")),
    ]
    return Group(Panel(_kv_table(rows), title="CIRCL Hashlookup (NSRL Known-Good Verification)", border_style="green", padding=(0, 1)))


def _render_vuln_detail(d: dict[str, Any]) -> Group:
    in_kev = bool(d.get("in_kev"))
    kev = _as_dict(d.get("kev"))
    epss = d.get("epss_score")
    epss_pct = d.get("epss_percentile")
    cvss = d.get("cvss_score")

    parts: list[Any] = []
    if in_kev:
        kev_rows: list[tuple[str, str | Text]] = [
            ("Status", Text("ACTIVELY EXPLOITED IN THE WILD (CISA KEV)", style="bold red")),
            ("Name", _as_str(kev.get("vulnerabilityName") or "-")),
            ("Vendor / Product", f"{kev.get('vendorProject') or '-'} / {kev.get('product') or '-'}"),
            ("Ransomware Use", Text(_as_str(kev.get("knownRansomwareCampaignUse") or "Unknown"), style="bold red" if kev.get("knownRansomwareCampaignUse") == "Known" else "yellow")),
            ("Added / Due Date", f"{kev.get('dateAdded') or '-'}  |  Due: {kev.get('dueDate') or '-'}"),
            ("Required Action", _as_str(kev.get("requiredAction") or "-")),
        ]
        parts.append(Panel(_kv_table(kev_rows), title="CISA Known Exploited Vulnerability (KEV)", border_style="red", padding=(0, 1)))

    rows: list[tuple[str, str | Text]] = [
        ("CVE ID", _as_str(d.get("cve_id") or "-")),
        ("State / Assigner", f"{d.get('state') or '-'} ({d.get('assigner') or '-'})"),
        ("CVSS Score", _percent_gauge(cvss, max_value=10.0, suffix=f"/10 ({d.get('cvss_severity') or '-'})") if cvss is not None else Text("-", style="dim")),
        ("CVSS Vector", _as_str(d.get("cvss_vector") or "-")),
        (
            "FIRST EPSS",
            _percent_gauge(round(epss * 100.0, 2), max_value=100.0, suffix=f"% (P{(epss_pct or 0) * 100:.1f})")
            if isinstance(epss, float)
            else Text("-", style="dim"),
        ),
        ("CISA KEV Listed", Text("YES — Actively Exploited", style="bold red") if in_kev else Text("No", style="green")),
        ("CWEs", ", ".join(_as_str(c) for c in _as_list(d.get("cwes"))) or "-"),
        ("Published / Updated", f"{format_date_or_ts(d.get('date_published'))[:10]}  |  {format_date_or_ts(d.get('date_updated'))[:10]}"),
    ]
    parts.append(Panel(_kv_table(rows), title="MITRE CVE 5.x + FIRST EPSS Intelligence", border_style="cyan", padding=(0, 1)))
    if d.get("description"):
        parts.append(Panel(Text(_as_str(d["description"])), title="Vulnerability Description", border_style="blue", padding=(0, 1)))

    affected = [a for a in _as_list(d.get("affected")) if isinstance(a, dict)]
    if affected:
        atbl = Table(box=box.SIMPLE, expand=True, title=f"Affected Products ({len(affected)})", title_justify="left")
        atbl.add_column("Vendor", style="bold", width=22)
        atbl.add_column("Product", style="cyan", width=24)
        atbl.add_column("Versions", overflow="fold")
        for a in affected[:10]:
            atbl.add_row(_as_str(a.get("vendor") or "-"), _as_str(a.get("product") or "-"), _as_str(a.get("versions") or "-"))
        parts.append(atbl)

    refs = [_as_str(r) for r in _as_list(d.get("references")) if r]
    if refs:
        parts.append(Panel(Text("\n".join(refs[:10])), title="Advisory References", border_style="dim", padding=(0, 1)))
    return Group(*parts)


def _render_virustotal_detail(d: dict[str, Any]) -> Group:
    mal = int(d.get("malicious") or 0)
    susp = int(d.get("suspicious") or 0)
    harm = int(d.get("harmless") or 0)
    undet = int(d.get("undetected") or 0)
    tot = int(d.get("total_engines") or 0)

    rows: list[tuple[str, str | Text]] = [
        ("Indicator", f"{d.get('indicator') or '-'} ({d.get('kind') or '-'})"),
        ("Detection Ratio", _percent_gauge(mal, max_value=float(max(tot, 1)), suffix=f"/{tot} malicious")),
        ("Breakdown", f"Malicious: {mal}  |  Suspicious: {susp}  |  Harmless: {harm}  |  Undetected: {undet}"),
        ("Reputation", _as_str(d.get("reputation")) if d.get("reputation") is not None else "-"),
    ]
    if d.get("threat_label"):
        rows.append(("Threat Label", Text(_as_str(d["threat_label"]), style="bold red")))
    if d.get("categories"):
        rows.append(("Categories", ", ".join(_as_str(c) for c in _as_list(d.get("categories")))))
    if d.get("registrar"):
        rows.append(("Registrar", _as_str(d["registrar"])))
    if d.get("creation_date"):
        rows.append(("Created", format_date_or_ts(d["creation_date"])))
    if d.get("asn") or d.get("as_owner"):
        rows.append(("ASN / Owner", f"{d.get('asn') or '-'} ({d.get('as_owner') or '-'})"))
    if d.get("meaningful_name") or d.get("type_description"):
        rows.append(("File Info", f"{d.get('meaningful_name') or '-'} | {d.get('type_description') or '-'} ({d.get('size') or '-'} bytes)"))
    if d.get("tags"):
        rows.append(("Tags", ", ".join(_as_str(t) for t in _as_list(d.get("tags")))))
    if d.get("gui_url"):
        rows.append(("VirusTotal GUI", _as_str(d["gui_url"])))

    parts: list[Any] = [Panel(_kv_table(rows), title="VirusTotal v3 Multi-AV Verdict", border_style="red" if mal else "green", padding=(0, 1))]
    flagging = [f for f in _as_list(d.get("flagging_vendors")) if isinstance(f, dict)]
    if flagging:
        ftbl = Table(box=box.SIMPLE, expand=True, title=f"Flagging Security Vendors ({len(flagging)})", title_justify="left")
        ftbl.add_column("Vendor / Engine", style="bold", width=24)
        ftbl.add_column("Category", width=12)
        ftbl.add_column("Detection", overflow="fold")
        for f in flagging[:20]:
            cat = _as_str(f.get("category") or "-")
            ftbl.add_row(_as_str(f.get("engine") or "-"), Text(cat.upper(), style="bold red" if cat == "malicious" else "yellow"), _as_str(f.get("result") or "-"))
        parts.append(ftbl)
    return Group(*parts)


def _render_abuseipdb_detail(d: dict[str, Any]) -> Group:
    score = int(d.get("abuse_confidence_score") or 0)
    rows: list[tuple[str, str | Text]] = [("IP Address", _as_str(d.get("ip") or "-"))]
    if d.get("resolved_from"):
        rows.append(("Resolved From", _as_str(d["resolved_from"])))
    rows.extend(
        [
            ("Abuse Confidence", _percent_gauge(score, max_value=100.0, suffix="%")),
            ("Reports (90d)", f"{d.get('total_reports', 0)} report(s) from {d.get('distinct_users', 0)} distinct reporter(s)"),
            ("Tor Exit Node", Text("YES — TOR EXIT", style="bold red") if d.get("is_tor") else Text("No", style="dim")),
            ("Whitelisted", Text("Yes (Trusted)", style="bold green") if d.get("is_whitelisted") else Text("No", style="dim")),
            ("ISP / Usage Type", f"{d.get('isp') or '-'}  |  {d.get('usage_type') or '-'}"),
            ("Country / Domain", f"{d.get('country_code') or '-'}  |  {d.get('domain') or '-'}"),
            ("Hostnames", ", ".join(_as_str(h) for h in _as_list(d.get("hostnames"))[:6]) or "-"),
            ("Last Reported", format_timestamp(d.get("last_reported_at")) if d.get("last_reported_at") else "-"),
        ]
    )
    return Group(Panel(_kv_table(rows), title="AbuseIPDB v2 Reputation", border_style="red" if score >= 50 else ("yellow" if score >= 15 else "green"), padding=(0, 1)))


def _render_abusech_detail(d: dict[str, Any]) -> Group:
    tf_hits = [x for x in _as_list(d.get("threatfox")) if isinstance(x, dict)]
    uh = _as_dict(d.get("urlhaus"))
    mb_hits = [x for x in _as_list(d.get("malwarebazaar")) if isinstance(x, dict)]

    parts: list[Any] = []
    if tf_hits:
        tbl = Table(box=box.SIMPLE, expand=True, title=f"ThreatFox IOC Matches ({len(tf_hits)})", title_justify="left")
        tbl.add_column("Malware", style="bold red", width=20)
        tbl.add_column("Threat Type", style="cyan", width=18)
        tbl.add_column("Conf", width=6, justify="right")
        tbl.add_column("Tags / First Seen", overflow="fold")
        for h in tf_hits[:12]:
            tags = ", ".join(_as_str(t) for t in _as_list(h.get("tags"))[:4])
            tbl.add_row(
                _as_str(h.get("malware_printable") or h.get("malware") or "-"),
                _as_str(h.get("threat_type") or "-"),
                f"{h.get('confidence_level', '-')}%",
                f"{tags} | {h.get('first_seen') or '-'}".strip(" |"),
            )
        parts.append(tbl)

    if uh:
        uh_urls = [u for u in _as_list(uh.get("urls")) if isinstance(u, dict)]
        bl = _as_dict(uh.get("blacklists"))
        uh_rows: list[tuple[str, str | Text]] = [
            ("URLhaus Status", _as_str(uh.get("url_status") or f"{len(uh_urls)} URL(s) listed")),
            ("Threat", _as_str(uh.get("threat") or "-")),
            ("Blacklists", format_kv_summary(bl) if bl else "-"),
            ("URLhaus Reference", _as_str(uh.get("urlhaus_reference") or "-")),
        ]
        parts.append(Panel(_kv_table(uh_rows), title="URLhaus Malicious Hosting Intel", border_style="red", padding=(0, 1)))
        if uh_urls:
            utbl = Table(box=box.SIMPLE, expand=True, title=f"Hosted Malicious URLs ({len(uh_urls)})", title_justify="left")
            utbl.add_column("Status", width=10)
            utbl.add_column("Threat", width=18)
            utbl.add_column("URL", overflow="fold")
            for u in uh_urls[:10]:
                st = _as_str(u.get("url_status") or "-")
                utbl.add_row(Text(st, style="bold red" if st == "online" else "dim"), _as_str(u.get("threat") or "-"), _as_str(u.get("url") or "-"))
            parts.append(utbl)

    if mb_hits:
        sample = mb_hits[0]
        mb_rows: list[tuple[str, str | Text]] = [
            ("Malware Signature", Text(_as_str(sample.get("signature") or "Unknown"), style="bold red")),
            ("File Name / Type", f"{sample.get('file_name') or '-'} ({sample.get('file_type') or '-'})"),
            ("Delivery Method", _as_str(sample.get("delivery_method") or "-")),
            ("First Seen", _as_str(sample.get("first_seen") or "-")),
            ("Tags", ", ".join(_as_str(t) for t in _as_list(sample.get("tags"))) or "-"),
            ("Imphash", _as_str(sample.get("imphash") or "-")),
            ("SSDeep", truncate_text(sample.get("ssdeep") or "-", 60)),
        ]
        parts.append(Panel(_kv_table(mb_rows), title="MalwareBazaar Sample Intelligence", border_style="red", padding=(0, 1)))

    if not parts:
        parts.append(Panel(Text("No abuse.ch matches returned."), title="abuse.ch Suite", border_style="dim"))
    return Group(*parts)


def render_osint_sources_matrix(dossier: ResearchDossier) -> Group:
    """Render full OSINT + RF source coverage table with free API key upgrade guidance."""
    tbl = Table(
        box=box.SIMPLE,
        expand=True,
        title=f"Unified Source Coverage for {dossier.target.canonical_name}",
        title_justify="left",
    )
    tbl.add_column("Source", style="bold", width=26)
    tbl.add_column("Tier", width=15)
    tbl.add_column("Status", width=14)
    tbl.add_column("Latency", justify="right", width=9)
    tbl.add_column("Summary / Free Setup Hint", overflow="fold")

    # Recorded Future summary row
    rf_secs = list(dossier.rf_sections.values())
    if rf_secs:
        rf_ok = sum(1 for s in rf_secs if s.status == "ok")
        rf_ms = max((s.elapsed_ms for s in rf_secs), default=0.0)
        if rf_ok > 0:
            rf_st = Text(f"OK ({rf_ok})", style="bold green")
            rf_note = f"{rf_ok} RF API surface(s) returned data"
        elif any(s.status == "not_configured" for s in rf_secs):
            rf_st = Text("No Token", style="yellow")
            rf_note = "Configure RF_API_TOKEN in Settings to merge Recorded Future intel"
        else:
            rf_st = Text("Clean / 0", style="dim")
            rf_note = "No matching Recorded Future records"
        tbl.add_row("Recorded Future Suite", Text("Enterprise", style="cyan"), rf_st, f"{rf_ms:.0f}ms", rf_note)

    for spec in OSINT_SOURCE_CATALOG:
        sec = dossier.osint_sections.get(spec.key)
        tier_txt = {
            "free_no_key": Text("Free (No Key)", style="green"),
            "free_optional_key": Text("Free (+Opt Key)", style="cyan"),
            "free_api_key": Text("Free API Key", style="yellow"),
        }.get(spec.tier, Text("Free", style="green"))

        if sec is None:
            st_txt = Text("N/A", style="dim")
            ms_str = "-"
            note = f"Applies to: {', '.join(spec.supported_kinds)}"
        else:
            st_map = {
                "ok": Text("HIT", style="bold green"),
                "empty": Text("Clean / 0", style="dim"),
                "not_configured": Text("Add Free Key", style="yellow"),
                "rate_limited": Text("Rate Limit", style="yellow"),
                "skipped": Text("Skipped", style="dim"),
                "error": Text("Error", style="red"),
            }
            st_txt = st_map.get(sec.status, Text(sec.status, style="dim"))
            ms_str = f"{sec.elapsed_ms:.0f}ms" if sec.elapsed_ms > 0 else "-"
            note = sec.message
        tbl.add_row(spec.title, tier_txt, st_txt, ms_str, note)

    tip = Panel(
        Text.from_markup(
            "[bold]Unlock even more free threat intel:[/bold] Press [cyan]s[/cyan] (or click [bold]Sources[/bold]) "
            "to toggle passive OSINT sources, or open [bold]Settings (0 / F10) -> OSINT Free API Keys[/bold] "
            "to add free keys for VirusTotal, AbuseIPDB, abuse.ch (ThreatFox + URLhaus + MalwareBazaar), OTX, URLScan & GreyNoise."
        ),
        border_style="cyan",
        padding=(0, 1),
    )
    return Group(tbl, tip)


def render_pivot_detail(pivot: ResearchPivot) -> Group:
    """Render detail panel for a selected related entity."""
    rows: list[tuple[str, str | Text]] = [
        ("Entity", pivot.name),
        ("Type", pivot.entity_type),
        ("ID", pivot.entity_id),
        ("Risk Score", risk_gauge(pivot.risk_score) if pivot.risk_score is not None else Text("-", style="dim")),
        ("Source", pivot.source_section or "-"),
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

    if kind == "osint_section" and isinstance(payload, dict):
        return render_osint_section_detail(_as_str(finding.get("section_key")), payload, dossier)

    if kind == "osint_sources" and dossier is not None:
        return render_osint_sources_matrix(dossier)

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
