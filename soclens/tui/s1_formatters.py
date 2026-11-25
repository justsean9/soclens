"""Human-readable Rich renderables for SentinelOne records and site policies."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from soclens.timezone import format_iso_timestamp
from soclens.tui.rf_formatters import render_raw_json, truncate_text

_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")

_KEY_LABEL_OVERRIDES: dict[str, str] = {
    "id": "ID",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "md5": "MD5",
    "osType": "OS Type",
    "osName": "Operating System",
    "osRevision": "OS Version",
    "osArch": "Architecture",
    "lastIpToMgmt": "Management IP",
    "externalIp": "External IP",
    "computerName": "Hostname",
    "agentComputerName": "Hostname",
    "agentVersion": "Agent Version",
    "networkStatus": "Network Status",
    "twoFaEnabled": "2FA Enabled",
    "twoFaStatus": "2FA Status",
    "siteId": "Site ID",
    "siteName": "Site Name",
    "accountId": "Account ID",
    "accountName": "Account Name",
    "groupId": "Group ID",
    "groupName": "Group Name",
    "tenantId": "Tenant Code",
    "sku": "SKU",
    "ip": "IP Address",
    "mitreTactics": "MITRE Tactics",
    "mitreTechniques": "MITRE Techniques",
    "threatName": "Threat Name",
    "analystVerdict": "Analyst Verdict",
    "incidentStatus": "Incident Status",
    "mitigationStatus": "Mitigation Status",
    "confidenceLevel": "Confidence",
    "filePath": "File Path",
    "fileSize": "File Size",
    "fileVerificationType": "File Verification",
    "originatorProcess": "Originator Process",
    "processUser": "Process User",
    "storyline": "Storyline ID",
    "createdAt": "Created",
    "updatedAt": "Updated",
    "reportedAt": "Reported",
    "lastActiveDate": "Last Active",
    "registeredAt": "Registered",
    "dateJoined": "Date Joined",
    "lastLogin": "Last Login",
    "expirationDate": "Expiration",
    "predefinedRole": "Predefined Role",
}


def pretty_s1_label(key: str) -> str:
    """Convert a camelCase or snake_case SentinelOne field name into a human-readable label."""
    if key in _KEY_LABEL_OVERRIDES:
        return _KEY_LABEL_OVERRIDES[key]
    spaced = _CAMEL_RE.sub(r"\1 \2", key.replace("_", " "))
    words = spaced.split()
    out: list[str] = []
    for w in words:
        low = w.lower()
        if low in {"id", "ip", "os", "sha1", "sha256", "md5", "url", "dns", "sku", "2fa", "rbac", "api", "edr", "mdr", "mssp"}:
            out.append(low.upper())
        else:
            out.append(w.capitalize())
    return " ".join(out) if out else key


def format_s1_value(value: Any, *, max_items: int = 8) -> str:
    """Format any SentinelOne scalar, timestamp, list, or nested dict without raw JSON."""
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        clean = value.strip()
        if not clean:
            return "-"
        if _ISO_TS_RE.match(clean):
            return format_iso_timestamp(clean)
        return clean
    if isinstance(value, Mapping):
        parts: list[str] = []
        for k, v in value.items():
            if str(k).startswith("_") or v in (None, "", [], {}):
                continue
            rendered = format_s1_value(v, max_items=4)
            if rendered and rendered != "-":
                parts.append(f"{pretty_s1_label(str(k))}: {rendered}")
            if len(parts) >= max_items:
                break
        if not parts:
            return "-"
        suffix = f" (+{len(value) - len(parts)} more)" if len(value) > len(parts) else ""
        return "; ".join(parts) + suffix
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items: list[str] = []
        for item in value:
            if item in (None, "", [], {}):
                continue
            rendered = format_s1_value(item, max_items=4)
            if rendered and rendered != "-":
                items.append(rendered)
            if len(items) >= max_items:
                break
        if not items:
            return "-"
        suffix = f" (+{len(value) - len(items)} more)" if len(value) > len(items) else ""
        return ", ".join(items) + suffix
    return str(value)


def _kv_table(rows: Sequence[tuple[str, str | Text]]) -> Table:
    tbl = Table.grid(padding=(0, 2), expand=True)
    tbl.add_column(style="bold cyan", no_wrap=True, min_width=16)
    tbl.add_column(ratio=1, overflow="fold")
    for label, val in rows:
        if isinstance(val, Text):
            if val.plain.strip() in ("", "-"):
                continue
            tbl.add_row(label, val)
        else:
            clean = str(val or "").strip()
            if not clean or clean == "-":
                continue
            tbl.add_row(label, Text(clean))
    return tbl


def _badge_text(value: Any, *, kind: str = "generic") -> Text:
    raw = str(value or "-").strip()
    low = raw.lower()
    display = raw.replace("_", " ").title() if raw != "-" else "-"
    if kind == "verdict":
        style = {
            "true_positive": "bold red",
            "suspicious": "bold yellow",
            "false_positive": "bold green",
            "undefined": "dim",
        }.get(low, "white")
        return Text(display, style=style)
    if kind == "status":
        style = {
            "unresolved": "bold red",
            "in_progress": "bold yellow",
            "resolved": "bold green",
            "active": "bold red",
            "mitigated": "bold green",
            "connected": "bold green",
            "disconnected": "bold red",
        }.get(low, "cyan")
        return Text(display, style=style)
    if kind == "severity":
        style = {
            "critical": "bold red",
            "malicious": "bold red",
            "high": "bold red",
            "medium": "bold yellow",
            "suspicious": "bold yellow",
            "low": "cyan",
            "info": "dim",
        }.get(low, "white")
        return Text(display, style=style)
    if kind == "tier":
        style = {
            "mdr": "bold magenta",
            "mssp": "bold cyan",
        }.get(low, "dim")
        return Text(raw.upper() if low in {"mdr", "mssp"} else display, style=style)
    return Text(display)


def _as_dict(val: Any) -> dict[str, Any]:
    return dict(val) if isinstance(val, Mapping) else {}


def _as_list(val: Any) -> list[Any]:
    return list(val) if isinstance(val, list) else []


def _format_bytes(size: Any) -> str:
    try:
        num = int(size)
    except (TypeError, ValueError):
        return str(size) if size not in (None, "") else "-"
    if num < 1024:
        return f"{num} B"
    if num < 1024 * 1024:
        return f"{num / 1024:.1f} KB"
    if num < 1024 * 1024 * 1024:
        return f"{num / (1024 * 1024):.1f} MB"
    return f"{num / (1024 * 1024 * 1024):.2f} GB"


def _render_threat_detail(
    rec: Mapping[str, Any],
    *,
    tier: str,
    tenant_id: str | None,
    site_id: str,
    site_name: str,
) -> Group:
    tinfo = _as_dict(rec.get("threatInfo"))
    rt = _as_dict(rec.get("agentRealtimeInfo"))
    det = _as_dict(rec.get("agentDetectionInfo"))
    ainfo = _as_dict(rec.get("alertInfo"))
    rinfo = _as_dict(rec.get("ruleInfo"))
    sproc = _as_dict(rec.get("sourceProcessInfo"))
    tproc = _as_dict(rec.get("targetProcessInfo"))
    k8s = _as_dict(rec.get("kubernetesInfo"))
    container = _as_dict(rec.get("containerInfo"))

    is_cloud = bool(rec.get("recordType") == "cloud_alert" or ainfo or (rinfo and not tinfo))
    title = str(
        rec.get("title")
        or tinfo.get("threatName")
        or rinfo.get("name")
        or rec.get("threatName")
        or rec.get("id")
        or "SentinelOne Alert"
    )
    verdict = rec.get("analystVerdict") or tinfo.get("analystVerdict") or ainfo.get("analystVerdict")
    inc_status = rec.get("incidentStatus") or tinfo.get("incidentStatus") or ainfo.get("incidentStatus")
    mit_status = rec.get("mitigationStatus") or tinfo.get("mitigationStatus")
    confidence = (
        rec.get("severity")
        or rinfo.get("severity")
        or tinfo.get("confidenceLevel")
    )
    created = rec.get("createdAt") or tinfo.get("createdAt") or ainfo.get("createdAt")
    updated = rec.get("updatedAt") or tinfo.get("updatedAt") or ainfo.get("updatedAt")

    overview_rows: list[tuple[str, str | Text]] = [
        ("Alert ID", str(rec.get("id") or ainfo.get("alertId") or "-")),
        ("Threat / Rule", title),
        ("Alert Type", "Cloud / STAR Alert" if is_cloud else "Endpoint Threat"),
        ("Service Tier", _badge_text(tier or "Other", kind="tier")),
    ]
    if tenant_id:
        overview_rows.append(("Tenant Code", tenant_id))
    if site_name or site_id:
        overview_rows.append(("Site", f"{site_name or '-'} ({site_id or '-'})"))
    if confidence:
        overview_rows.append(("Confidence / Severity", _badge_text(confidence, kind="severity")))
    if verdict:
        overview_rows.append(("Analyst Verdict", _badge_text(verdict, kind="verdict")))
    if inc_status:
        overview_rows.append(("Incident Status", _badge_text(inc_status, kind="status")))
    if mit_status:
        overview_rows.append(("Mitigation Status", _badge_text(mit_status, kind="status")))
    classification = tinfo.get("classification") or rinfo.get("description")
    if classification:
        overview_rows.append(("Classification", str(classification)))
    if tinfo.get("classificationSource"):
        overview_rows.append(("Detection Source", str(tinfo.get("classificationSource"))))
    engines = tinfo.get("engines") or tinfo.get("detectionEngines")
    if engines:
        overview_rows.append(("Detection Engines", format_s1_value(engines)))
    if created:
        overview_rows.append(("Created", format_s1_value(created)))
    if updated and updated != created:
        overview_rows.append(("Updated", format_s1_value(updated)))

    renderables: list[RenderableType] = [
        Panel(
            _kv_table(overview_rows),
            title=Text(f"SentinelOne Alert: {truncate_text(title, 56)}", style="bold cyan"),
            border_style="cyan",
            box=box.ROUNDED,
        )
    ]

    # Endpoint & Process Context
    hostname = (
        rec.get("computerName")
        or rt.get("agentComputerName")
        or det.get("agentComputerName")
        or rec.get("agentComputerName")
    )
    os_name = rt.get("agentOsName") or det.get("agentOsName") or rt.get("agentOsType")
    ip_addr = (
        det.get("agentIpV4")
        or det.get("externalIp")
        or rt.get("agentNetworkStatus")
    )
    user_name = (
        det.get("agentLastLoggedInUserName")
        or tinfo.get("processUser")
        or sproc.get("user")
    )
    file_path = tinfo.get("filePath") or sproc.get("filePath")
    cmd_line = (
        tinfo.get("commandLine")
        or sproc.get("commandline")
        or sproc.get("commandLine")
        or tproc.get("commandline")
    )
    sha1 = rec.get("sha1") or tinfo.get("sha1") or sproc.get("fileHashSha1")
    sha256 = tinfo.get("sha256") or sproc.get("fileHashSha256")
    md5 = tinfo.get("md5") or sproc.get("fileHashMd5")

    ctx_rows: list[tuple[str, str | Text]] = []
    if hostname:
        ctx_rows.append(("Hostname", str(hostname)))
    if os_name:
        ctx_rows.append(("Operating System", str(os_name)))
    if det.get("agentDomain"):
        ctx_rows.append(("Domain", str(det.get("agentDomain"))))
    if ip_addr and ip_addr != rt.get("agentNetworkStatus"):
        ctx_rows.append(("IP Address", str(ip_addr)))
    if rt.get("agentNetworkStatus"):
        ctx_rows.append(("Network Status", _badge_text(rt.get("agentNetworkStatus"), kind="status")))
    if user_name:
        ctx_rows.append(("User", str(user_name)))
    if file_path:
        ctx_rows.append(("File Path", str(file_path)))
    if tinfo.get("fileSize") not in (None, ""):
        ctx_rows.append(("File Size", _format_bytes(tinfo.get("fileSize"))))
    if tinfo.get("originatorProcess") or sproc.get("name"):
        ctx_rows.append(("Process", str(tinfo.get("originatorProcess") or sproc.get("name"))))
    if cmd_line:
        ctx_rows.append(("Command Line", str(cmd_line)))
    if sha1:
        ctx_rows.append(("SHA-1", str(sha1)))
    if sha256:
        ctx_rows.append(("SHA-256", str(sha256)))
    if md5:
        ctx_rows.append(("MD5", str(md5)))
    if tinfo.get("publisherName") or sproc.get("publisherName"):
        ctx_rows.append(("Publisher", str(tinfo.get("publisherName") or sproc.get("publisherName"))))
    if tinfo.get("storyline") or sproc.get("storyline"):
        ctx_rows.append(("Storyline ID", str(tinfo.get("storyline") or sproc.get("storyline"))))
    if ctx_rows:
        renderables.append(
            Panel(
                _kv_table(ctx_rows),
                title=Text("Endpoint & Process Context", style="bold white"),
                border_style="blue",
                box=box.ROUNDED,
            )
        )

    # Indicators & MITRE
    indicators = _as_list(rec.get("indicators"))
    if indicators:
        ind_tbl = Table(box=box.SIMPLE_HEAD, expand=True)
        ind_tbl.add_column("Category", style="cyan", ratio=2, overflow="fold")
        ind_tbl.add_column("Description", ratio=4, overflow="fold")
        ind_tbl.add_column("MITRE / Tactics", style="yellow", ratio=2, overflow="fold")
        for ind in indicators[:12]:
            if isinstance(ind, Mapping):
                cat = str(ind.get("category") or ind.get("tactics") or "-")
                desc = str(ind.get("description") or ind.get("name") or "-")
                tactics = format_s1_value(ind.get("tactics") or ind.get("ids"))
                ind_tbl.add_row(cat, desc, tactics)
            else:
                ind_tbl.add_row("-", str(ind), "-")
        renderables.append(
            Panel(
                ind_tbl,
                title=Text(f"Behavioral Indicators ({len(indicators)})", style="bold yellow"),
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    # Cloud / Kubernetes / Container metadata
    cloud_rows: list[tuple[str, str | Text]] = []
    for k, v in k8s.items():
        if v not in (None, "", [], {}):
            cloud_rows.append((f"K8s {pretty_s1_label(str(k))}", format_s1_value(v)))
    for k, v in container.items():
        if v not in (None, "", [], {}):
            cloud_rows.append((f"Container {pretty_s1_label(str(k))}", format_s1_value(v)))
    if cloud_rows:
        renderables.append(
            Panel(
                _kv_table(cloud_rows[:12]),
                title=Text("Cloud / Container Context", style="bold magenta"),
                border_style="magenta",
                box=box.ROUNDED,
            )
        )

    return Group(*renderables)


def _render_endpoint_detail(
    rec: Mapping[str, Any],
    *,
    tier: str,
    tenant_id: str | None,
    site_id: str,
    site_name: str,
) -> Group:
    hostname = str(rec.get("computerName") or rec.get("id") or "Endpoint")
    overview_rows: list[tuple[str, str | Text]] = [
        ("Agent ID", str(rec.get("id") or "-")),
        ("Hostname", hostname),
        ("Service Tier", _badge_text(tier or "Other", kind="tier")),
    ]
    if tenant_id:
        overview_rows.append(("Tenant Code", tenant_id))
    if site_name or site_id:
        overview_rows.append(("Site", f"{site_name or '-'} ({site_id or '-'})"))
    if rec.get("groupName"):
        overview_rows.append(("Group", str(rec.get("groupName"))))
    if rec.get("domain"):
        overview_rows.append(("Domain", str(rec.get("domain"))))
    overview_rows.append(("Network Status", _badge_text(rec.get("networkStatus") or "-", kind="status")))
    infected = bool(rec.get("infected"))
    overview_rows.append(
        ("Infected", Text("YES (Active Threat)", style="bold red") if infected else Text("No", style="bold green"))
    )
    if rec.get("activeThreats") not in (None, ""):
        overview_rows.append(("Active Threats", str(rec.get("activeThreats"))))
    if rec.get("lastActiveDate"):
        overview_rows.append(("Last Active", format_s1_value(rec.get("lastActiveDate"))))
    if rec.get("registeredAt"):
        overview_rows.append(("Registered", format_s1_value(rec.get("registeredAt"))))

    sys_rows: list[tuple[str, str | Text]] = []
    for key in (
        "osName",
        "osRevision",
        "osType",
        "osArch",
        "agentVersion",
        "lastIpToMgmt",
        "externalIp",
        "lastLoggedInUserName",
        "machineType",
        "modelName",
        "scanStatus",
        "mitigationMode",
        "mitigationModeSuspicious",
        "isUpToDate",
        "isDecommissioned",
    ):
        val = rec.get(key)
        if val not in (None, "", [], {}):
            sys_rows.append((pretty_s1_label(key), format_s1_value(val)))

    renderables: list[RenderableType] = [
        Panel(
            _kv_table(overview_rows),
            title=Text(f"Endpoint: {truncate_text(hostname, 56)}", style="bold cyan"),
            border_style="cyan",
            box=box.ROUNDED,
        )
    ]
    if sys_rows:
        renderables.append(
            Panel(
                _kv_table(sys_rows),
                title=Text("System, Network & Agent Details", style="bold white"),
                border_style="blue",
                box=box.ROUNDED,
            )
        )
    return Group(*renderables)


def _render_generic_s1_detail(
    title: str,
    rec: Mapping[str, Any],
    *,
    tier: str,
    tenant_id: str | None,
    site_id: str,
    site_name: str,
    preferred_keys: Sequence[str] = (),
) -> Group:
    rows: list[tuple[str, str | Text]] = []
    if tier and tier != "Other":
        rows.append(("Service Tier", _badge_text(tier, kind="tier")))
    if tenant_id:
        rows.append(("Tenant Code", tenant_id))
    if site_name or site_id:
        rows.append(("Site", f"{site_name or '-'} ({site_id or '-'})"))

    seen: set[str] = {"tier", "tenantId", "siteId", "siteName"}
    for key in preferred_keys:
        if key in seen or key not in rec:
            continue
        val = rec.get(key)
        if val in (None, "", [], {}):
            continue
        seen.add(key)
        rows.append((pretty_s1_label(key), format_s1_value(val)))

    for key, val in rec.items():
        kstr = str(key)
        if kstr.startswith("_") or kstr in seen or val in (None, "", [], {}):
            continue
        seen.add(kstr)
        rows.append((pretty_s1_label(kstr), format_s1_value(val)))

    return Group(
        Panel(
            _kv_table(rows),
            title=Text(truncate_text(title, 64), style="bold cyan"),
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def render_s1_record_detail(
    view: str,
    rec: Mapping[str, Any],
    *,
    tier: str = "",
    tenant_id: str | None = None,
    site_id: str = "",
    site_name: str = "",
) -> Group:
    """Render a SentinelOne record into human-readable Rich panels (no raw JSON)."""
    if view == "threats":
        return _render_threat_detail(
            rec, tier=tier, tenant_id=tenant_id, site_id=site_id, site_name=site_name
        )
    if view == "endpoints":
        return _render_endpoint_detail(
            rec, tier=tier, tenant_id=tenant_id, site_id=site_id, site_name=site_name
        )
    if view == "exclusions":
        return _render_generic_s1_detail(
            f"Exclusion: {rec.get('value') or rec.get('id') or '-'}",
            rec,
            tier=tier,
            tenant_id=tenant_id,
            site_id=site_id,
            site_name=site_name,
            preferred_keys=(
                "id",
                "type",
                "osType",
                "value",
                "mode",
                "scope",
                "pathExclusionType",
                "description",
                "source",
                "userName",
                "createdAt",
                "updatedAt",
            ),
        )
    if view == "blocklist":
        return _render_generic_s1_detail(
            f"Blocklist Entry: {rec.get('value') or rec.get('id') or '-'}",
            rec,
            tier=tier,
            tenant_id=tenant_id,
            site_id=site_id,
            site_name=site_name,
            preferred_keys=("id", "value", "osType", "source", "scope", "description", "createdAt", "updatedAt"),
        )
    if view == "users_rbac":
        kind = str(rec.get("_s1_user_kind") or "User")
        label = str(rec.get("fullName") or rec.get("name") or rec.get("email") or rec.get("id") or "-")
        return _render_generic_s1_detail(
            f"{kind}: {label}",
            rec,
            tier=tier,
            tenant_id=tenant_id,
            site_id=site_id,
            site_name=site_name,
            preferred_keys=(
                "id",
                "fullName",
                "name",
                "email",
                "scope",
                "scopeRoles",
                "twoFaEnabled",
                "twoFaStatus",
                "predefinedRole",
                "lastLogin",
                "dateJoined",
                "expirationDate",
                "description",
            ),
        )
    if rec.get("_s1_kind") == "activity":
        return _render_generic_s1_detail(
            f"Activity: {rec.get('primaryDescription') or rec.get('activityType') or rec.get('id') or '-'}",
            rec,
            tier=tier,
            tenant_id=tenant_id,
            site_id=site_id,
            site_name=site_name,
            preferred_keys=(
                "id",
                "primaryDescription",
                "secondaryDescription",
                "activityType",
                "userId",
                "agentId",
                "threatId",
                "accountName",
                "createdAt",
            ),
        )
    return _render_generic_s1_detail(
        f"Site: {rec.get('name') or rec.get('id') or '-'}",
        rec,
        tier=tier,
        tenant_id=tenant_id,
        site_id=site_id,
        site_name=site_name,
        preferred_keys=(
            "id",
            "name",
            "state",
            "sku",
            "siteType",
            "usageType",
            "activeLicenses",
            "totalLicenses",
            "unlimitedLicenses",
            "expiration",
            "accountName",
            "createdAt",
            "updatedAt",
        ),
    )


def render_s1_policy_detail(
    policy: Mapping[str, Any],
    *,
    site_name: str = "",
    site_id: str = "",
) -> Group:
    """Render a SentinelOne site policy into human-readable Rich panels."""
    if not policy:
        return Group(
            Panel(Text("No policy settings returned.", style="dim"), title="Site Policy", border_style="cyan")
        )

    core_keys = (
        "mitigationMode",
        "mitigationModeSuspicious",
        "monitorOnExecute",
        "monitorOnWrite",
        "antiTamperingOn",
        "snapshotsOn",
        "networkQuarantineOn",
        "ioc",
        "autoImmuneOn",
        "autoDecommissionOn",
        "autoDecommissionDays",
        "inheritedFrom",
        "updatedAt",
    )
    core_rows: list[tuple[str, str | Text]] = []
    other_rows: list[tuple[str, str | Text]] = []
    nested_panels: list[RenderableType] = []

    seen: set[str] = set()
    for k in core_keys:
        if k in policy and policy[k] not in (None, "", [], {}):
            seen.add(k)
            core_rows.append((pretty_s1_label(k), format_s1_value(policy[k])))

    for k, v in sorted(policy.items()):
        if k in seen or v in (None, "", [], {}):
            continue
        if isinstance(v, Mapping):
            sub_rows = [
                (pretty_s1_label(str(sk)), format_s1_value(sv))
                for sk, sv in v.items()
                if sv not in (None, "", [], {})
            ]
            if sub_rows:
                nested_panels.append(
                    Panel(
                        _kv_table(sub_rows),
                        title=Text(pretty_s1_label(str(k)), style="bold white"),
                        border_style="blue",
                        box=box.ROUNDED,
                    )
                )
        else:
            other_rows.append((pretty_s1_label(str(k)), format_s1_value(v)))

    title = f"Site Policy: {site_name} ({site_id})" if site_name else "Site Policy"
    renderables: list[RenderableType] = []
    if core_rows:
        renderables.append(
            Panel(
                _kv_table(core_rows),
                title=Text(title, style="bold cyan"),
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
    renderables.extend(nested_panels)
    if other_rows:
        renderables.append(
            Panel(
                _kv_table(other_rows),
                title=Text("Additional Policy Settings", style="bold white"),
                border_style="dim",
                box=box.ROUNDED,
            )
        )
    return Group(*renderables) if renderables else Group(Panel(Text("Empty policy.", style="dim")))


__all__ = [
    "format_s1_value",
    "pretty_s1_label",
    "render_s1_policy_detail",
    "render_s1_record_detail",
    "render_raw_json",
]
