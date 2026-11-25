"""Unified, cross-platform CLI entrypoint for the SOCLens."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import csv
import io
import json
import logging
import os
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soclens import __version__
from soclens.bundler import create_bundle
from soclens.client import (
    ANALYST_NOTE_TOPICS,
    LIST_TYPES,
    MALWARE_INTEL_FIELDS,
    PFI_PIPELINES,
    PLAYBOOK_CATEGORY_PATH_MAP,
    V2_EXTENSION_CATALOG,
    RecordedFutureAuthError,
    RecordedFutureClient,
    RecordedFutureError,
    RecordedFutureRateLimitError,
)
from soclens.config import (
    IMAGE_VIEWER_MODES,
    UI_VIEW_MODES,
    ConfigurationError,
    configure_logging,
    ensure_utf8_console,
    get_auto_approve,
    get_sentinelone_config,
    get_splunk_config,
    get_workspace_dir,
)
from soclens.llm import SOC_PROMPT_TEMPLATES, LocalLLMClient, LocalLLMError
from soclens.logos.brand_sync import (
    BRAND_ROW_SORT_FIELDS,
    BRAND_SYNC_ISSUE_CATEGORIES,
    BRAND_SYNC_ISSUE_LABELS,
    DEFAULT_STATE_FILENAME,
    SyncLockError,
    analyze_brand_sync_issues,
    execute_domain_brand_sync,
    filter_brand_issues,
    get_domains_from_watchlist,
    load_brand_sync_state,
    resolve_state_path,
    run_continuous_brand_sync,
    sort_brand_issues,
    validate_domain_brand_sync,
)
from soclens.logos.extractor import load_domains_file
from soclens.research import (
    RESEARCH_MODULES,
    export_dossier_json,
    export_dossier_markdown,
    probe_api_capabilities,
    render_dossier_markdown,
    research_target,
)
from soclens.sentinelone import (
    ANALYST_VERDICTS,
    EXCLUSION_TYPES,
    INCIDENT_STATUSES,
    MITIGATION_ACTIONS,
    OS_TYPES,
    SentinelOneAuthError,
    SentinelOneClient,
    SentinelOneError,
    SentinelOneRateLimitError,
)
from soclens.settings import (
    SETTING_SPECS_BY_KEY,
    clear_profile_settings,
    collect_env_importable_settings,
    delete_profile,
    describe_all_settings,
    format_setting_display,
    get_active_profile_name,
    get_settings_storage_info,
    list_profiles,
    resolve_setting_key,
    save_profile_settings,
    set_active_profile,
    validate_profile_name,
    validate_settings_values,
)
from soclens.sigma import (
    SIGMA_OUTPUT_FORMATS,
    SIGMA_PIPELINES,
    SigmaConfigurationError,
    SigmaConversionConfig,
    convert_sigma_rule,
    export_rules_to_splunk,
    interactive_loop,
    load_rules,
    load_sigma_config,
    parse_field_list,
    parse_key_value_mapping,
    print_rule,
    search_rules,
)
from soclens.splunk import (
    SplunkClient,
    SplunkValidator,
    export_results_csv,
    export_results_json,
    parse_savedsearches_files,
)
from soclens.splunk_es import (
    NOTABLE_STATUS_MAP,
    NOTABLE_URGENCIES,
    SPLUNK_ES_APP,
    THREAT_INTEL_COLLECTIONS,
    SplunkESClient,
    SplunkESError,
)
from soclens.splunk_rf_enrichment import (
    SplunkRFEnricher,
    load_splunk_rf_field_map,
    write_enrichment_to_notable,
)
from soclens.watchlist import (
    export_watchlist,
    filter_watchlist_entities,
    sort_watchlist_entities,
    validate_domains_live_status,
)

logger = logging.getLogger("soclens.cli")

_NEGATIVE_VALUE_FLAGS = frozenset(
    {
        "--earliest",
        "--latest",
        "--earliest-time",
        "--latest-time",
        "--days",
        "--concurrency",
        "--timeout",
        "--interval",
        "--max-runs",
        "--grace-failures",
        "--timeframe",
        "--links-timeframe",
        "--published",
        "--from",
        "--to",
        "--start-date",
        "--end-date",
    }
)

_RF_API_CATALOG: tuple[dict[str, str], ...] = (
    {
        "family": "Lists & Watchlists",
        "base_path": "/list/*",
        "auth": "X-RFToken",
        "cli": "soclens watchlist {list,create,info,status,entities,add,remove,sync,export,tags,replace-tags,text-entries,sync-logos,validate-logos,brand-issues}",
    },
    {
        "family": "Entity Match & Lookup",
        "base_path": "/entity-match/*",
        "auth": "X-RFToken",
        "cli": "soclens rf entity-match <name> | soclens rf entity-lookup <id>",
    },
    {
        "family": "Connect API v2 & Extensions",
        "base_path": "/v2/{ip,domain,hash,url,vulnerability,malware,company}/*",
        "auth": "X-RFToken",
        "cli": "soclens rf {lookup,company,risklist,riskrules,search,fields,extension}",
    },
    {
        "family": "SOAR API v3",
        "base_path": "/soar/v3/{enrichment,triage/contexts}",
        "auth": "X-RFToken",
        "cli": "soclens rf {enrich,triage,contexts}",
    },
    {
        "family": "Detection Rules (Sigma/YARA/Snort)",
        "base_path": "/detection-rule/*",
        "auth": "X-RFToken",
        "cli": "soclens sigma | soclens research rules",
    },
    {
        "family": "Playbook Alerts (Brand/DRP)",
        "base_path": "/playbook-alert/*",
        "auth": "X-RFToken",
        "cli": "soclens rf playbook-alerts",
    },
    {
        "family": "Alerts v3 & v2",
        "base_path": "/alert/{v3,v2/rule,v2/update}",
        "auth": "X-RFToken",
        "cli": "soclens rf alerts | soclens research rules --alert-rules",
    },
    {
        "family": "Cases",
        "base_path": "/case/*",
        "auth": "X-RFToken",
        "cli": "soclens rf cases",
    },
    {
        "family": "Recorded Future Sandbox v0",
        "base_path": "sandbox.recordedfuture.com/api/v0/*",
        "auth": "Authorization: Bearer",
        "cli": "soclens rf sandbox | soclens research sandbox",
    },
    {
        "family": "Links Graph",
        "base_path": "/links/*",
        "auth": "X-RFToken",
        "cli": "soclens research links",
    },
    {
        "family": "Analyst Notes",
        "base_path": "/analyst-note/*",
        "auth": "X-RFToken",
        "cli": "soclens research notes",
    },
    {
        "family": "Threat Maps & Threat Actors",
        "base_path": "/threat/*",
        "auth": "X-RFToken",
        "cli": "soclens research actors | soclens research malware --map",
    },
    {
        "family": "Malware Intelligence",
        "base_path": "/malware-intelligence/v1/*",
        "auth": "X-RFToken",
        "cli": "soclens research malware",
    },
    {
        "family": "Risk History & Active Rules",
        "base_path": "/risk/*",
        "auth": "X-RFToken",
        "cli": "soclens research risk",
    },
    {
        "family": "Identity Intelligence",
        "base_path": "/identity/*",
        "auth": "X-RFToken",
        "cli": "soclens research identity",
    },
    {
        "family": "Collective Insights",
        "base_path": "/collective-insights/*",
        "auth": "X-RFToken",
        "cli": "soclens research collective-insights",
    },
    {
        "family": "Fusion v3",
        "base_path": "/fusion/v3/*",
        "auth": "X-RFToken",
        "cli": "soclens research fusion",
    },
    {
        "family": "Autonomous Threat Operations (ATO)",
        "base_path": "/autonomous-threat-operations/v1/*",
        "auth": "X-RFToken",
        "cli": "soclens research ato",
    },
    {
        "family": "STIX / TAXII 2.1",
        "base_path": "/taxii2/*",
        "auth": "Basic :token",
        "cli": "soclens research taxii2",
    },
    {
        "family": "Attack Surface Intelligence (ASI)",
        "base_path": "api.securitytrails.com/v2/*",
        "auth": "apikey",
        "cli": "soclens research asi",
    },
    {
        "family": "Payment Fraud Intelligence (PFI)",
        "base_path": "pfi.regemini.com/api/v1/*",
        "auth": "X-RFToken",
        "cli": "soclens research pfi",
    },
    {
        "family": "RiskRecon",
        "base_path": "api.riskrecon.com/v1/*",
        "auth": "Authorization: Bearer",
        "cli": "soclens research riskrecon",
    },
)


def clear_screen() -> None:
    """Clear the terminal safely using ANSI escape sequences."""
    print("\033[2J\033[H", end="", flush=True)


def format_context(context: dict[str, Any] | None) -> str:
    """Format a watchlist entity context mapping into a concise display string."""
    if not context:
        return "N/A"
    return ", ".join(f"{k}: {v}" for k, v in context.items())


def is_auto_approved() -> bool:
    """Return True when ``SOCLENS_AUTO_APPROVE`` or saved setting permits non-interactive mutations."""
    return get_auto_approve()


def _emit_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, default=str))


def _mutation_succeeded(result: Any) -> bool:
    if isinstance(result, dict):
        status = str(result.get("result", "ok")).strip().lower()
        return status not in {"error", "failed", "failure"}
    return bool(result)


def _resolve_write_dry_run(args: argparse.Namespace, global_dry_run: bool) -> tuple[bool, bool]:
    """Return ``(effective_dry_run, auto_approve_downgraded)`` for mutating CLI commands."""
    explicit_dry = bool(global_dry_run or getattr(args, "dry_run", False))
    if explicit_dry:
        return True, False
    if not is_auto_approved():
        return True, True
    return False, False


def _run_quiet_if_json(use_json: bool, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run helper functions that print prose, suppressing stdout when ``--json`` is active."""
    if not use_json:
        return fn(*args, **kwargs)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return fn(*args, **kwargs)


def _split_csv_arg(values: list[str] | str | None) -> list[str]:
    if not values:
        return []
    raw_items = [values] if isinstance(values, str) else values
    out: list[str] = []
    for item in raw_items:
        for part in str(item).split(","):
            cleaned = part.strip()
            if cleaned:
                out.append(cleaned)
    return out


def _collect_iocs_from_args(args: argparse.Namespace) -> dict[str, list[str]]:
    iocs: dict[str, list[str]] = {}
    mapping = (
        ("ip", getattr(args, "ip", None)),
        ("domain", getattr(args, "domain", None)),
        ("hash", getattr(args, "hash", None)),
        ("url", getattr(args, "url", None)),
        ("vulnerability", getattr(args, "vulnerability", None)),
    )
    for key, raw in mapping:
        parsed = _split_csv_arg(raw)
        if parsed:
            iocs[key] = parsed
    return iocs


def load_csv_entities(
    csv_path: str | Path,
    default_type: str = "InternetDomainName",
) -> list[dict[str, str]]:
    """Load target watchlist entities from a CSV file with flexible header detection."""
    path = Path(csv_path).expanduser()
    if not path.is_file():
        print(f"[-] CSV file not found: {path}", file=sys.stderr)
        return []

    entities: list[dict[str, str]] = []
    try:
        with path.open(mode="r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            first_row = next(reader, None)
            if not first_row:
                return []

            is_header = False
            id_idx = 0
            type_idx = -1

            lower_headers = [h.strip().lower() for h in first_row]
            header_keywords = {
                "name",
                "type",
                "id",
                "entity id",
                "entity_id",
                "context",
                "value",
                "entity_name",
                "domain",
            }
            if any(h in header_keywords for h in lower_headers):
                is_header = True
                for opt in ("entity id", "entity_id", "id", "name", "value", "domain"):
                    if opt in lower_headers:
                        id_idx = lower_headers.index(opt)
                        break
                for opt in ("type", "entity_type", "entity type"):
                    if opt in lower_headers:
                        type_idx = lower_headers.index(opt)
                        break

            def _process_row(row: list[str]) -> dict[str, str] | None:
                if not row or len(row) <= id_idx:
                    return None
                val = row[id_idx].strip()
                if not val:
                    return None
                if val.lower() in (
                    "domain",
                    "domain name",
                    "domain_name",
                    "entity",
                    "entity name",
                    "entity_id",
                    "entity id",
                    "name",
                    "type",
                    "id",
                    "context",
                    "value",
                ):
                    return None

                val_type = default_type
                if type_idx != -1 and len(row) > type_idx:
                    val_type = row[type_idx].strip() or default_type

                if ":" in val:
                    prefix, remainder = val.split(":", 1)
                    prefix_map = {
                        "hash": "Hash",
                        "ip": "IPAddress",
                        "domain": "InternetDomainName",
                        "idn": "InternetDomainName",
                        "vulnerability": "Vulnerability",
                        "cve": "Vulnerability",
                    }
                    if prefix.lower() in prefix_map:
                        val = remainder.strip()
                        val_type = prefix_map[prefix.lower()]

                return {"name": val, "type": val_type}

            if not is_header:
                first_item = _process_row(first_row)
                if first_item:
                    entities.append(first_item)

            for row in reader:
                item = _process_row(row)
                if item:
                    entities.append(item)
    except Exception as exc:
        print(f"[-] Error reading CSV file '{path}': {exc}", file=sys.stderr)
        return []

    return entities


def execute_delta_sync(
    client: RecordedFutureClient,
    list_id: str,
    csv_path: str | Path,
    entity_type: str,
    dry_run: bool = False,
    interactive: bool = False,
    force_remove: bool = False,
) -> bool:
    """Delta-sync entities from a CSV file into a Recorded Future watchlist."""
    new_entities = load_csv_entities(csv_path, default_type=entity_type)
    if not new_entities:
        print("[-] No valid entities loaded from CSV. Aborting sync.", file=sys.stderr)
        return False

    print(f"[*] Starting delta sync from '{csv_path}' to watchlist '{list_id}'...")
    print(f"[*] Default Entity Type: {entity_type}")
    print(f"[*] Read {len(new_entities)} target entity/entities from CSV.")
    if dry_run:
        print("[*] DRY RUN MODE ENABLED. No changes will be written to the API.")

    existing_entries = client.get_watchlist_entities(list_id)
    existing_map: dict[str, dict[str, Any]] = {}
    for entry in existing_entries:
        ent = entry.get("entity", {}) or {}
        name = str(ent.get("name", "")).strip().lower()
        ent_id = str(ent.get("id", "")).strip().lower()
        if name:
            existing_map[name] = entry
        if ent_id:
            existing_map[ent_id] = entry

    print(f"[*] Watchlist currently contains {len(existing_entries)} entity/entities.")

    new_set = {item["name"].strip().lower() for item in new_entities}
    to_add = [item for item in new_entities if item["name"].strip().lower() not in existing_map]

    to_remove: list[dict[str, Any]] = []
    for entry in existing_entries:
        ent = entry.get("entity", {}) or {}
        name = str(ent.get("name", "")).strip().lower()
        ent_id = str(ent.get("id", "")).strip().lower()
        in_new_set = (name in new_set) or (ent_id in new_set)
        if not in_new_set:
            ctx = entry.get("context", {}) or {}
            if force_remove or ctx.get("source") == "automated-watchlist-manager":
                to_remove.append(ent)

    print(f"[*] Delta calculated: {len(to_add)} to add, {len(to_remove)} to remove.")

    if interactive and not dry_run:
        if to_add:
            print("\nEntities to ADD:")
            for item in to_add:
                print(f"  + {item['name']} ({item['type']})")
        if to_remove:
            print("\nEntities to REMOVE:")
            for ent in to_remove:
                print(f"  - {ent.get('name')} (ID: {ent.get('id')})")

        confirm1 = input("\nApply these changes to the watchlist? (y/N): ").strip().lower()
        if confirm1 != "y":
            print("[-] Sync cancelled.")
            return False

        confirm2 = input("WARNING: This will affect the entire watchlist. Type 'CONFIRM' to proceed: ").strip()
        if confirm2 != "CONFIRM":
            print("[-] Sync cancelled.")
            return False

    removed_count = 0
    for ent in to_remove:
        if dry_run:
            print(f"[DRY-RUN] Would remove entity '{ent.get('name')}' (ID: {ent.get('id')})")
            removed_count += 1
        else:
            res = client.remove_entity(list_id, str(ent.get("id", "")))
            if _mutation_succeeded(res):
                print(f"[+] Removed entity '{ent.get('name')}'")
                removed_count += 1

    added_count = 0
    for item in to_add:
        name = item["name"]
        val_type = item["type"]
        if dry_run:
            print(f"[DRY-RUN] Would add entity '{name}' (Type: {val_type})")
            added_count += 1
        else:
            context = {
                "annotation": "Automated sync: Bulk replace from CSV",
                "source": "automated-watchlist-manager",
                "sync_time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            res = client.add_entity(list_id, val_type, name, context=context)
            if _mutation_succeeded(res):
                print(f"[+] Added entity '{name}' (Type: {val_type})")
                added_count += 1

    if dry_run:
        print(
            f"[+] Dry Run finished. Would have added: {added_count}/{len(to_add)}, "
            f"removed: {removed_count}/{len(to_remove)}"
        )
    else:
        print(
            f"[+] Sync finished. Added: {added_count}/{len(to_add)}, "
            f"Removed: {removed_count}/{len(to_remove)}"
        )
    return True


def run_unified_tui(
    client: RecordedFutureClient | None = None,
    dry_run: bool = False,
    *,
    initial_tab: str | None = None,
    workspace_dir: Path | str | None = None,
    image_viewer: str | None = None,
    view_mode: str | None = None,
) -> None:
    """Launch the cross-platform Textual Terminal User Interface."""
    from soclens.tui import create_app
    from soclens.tui.image_render import probe_terminal_graphics_support

    try:
        probe_terminal_graphics_support()
    except Exception:
        pass

    create_kwargs: dict[str, Any] = {
        "client": client,
        "dry_run": dry_run,
        "initial_tab": initial_tab,
        "workspace_dir": workspace_dir,
    }
    if image_viewer is not None:
        create_kwargs["image_viewer"] = image_viewer
    if view_mode is not None:
        create_kwargs["view_mode"] = view_mode
    app = create_app(**create_kwargs)
    app.run()


def _preprocess_negative_args(raw_args: list[str]) -> list[str]:
    """Attach negative numeric/relative time values to known options via ``--flag=val``."""
    processed: list[str] = []
    idx = 0
    while idx < len(raw_args):
        arg = raw_args[idx]
        if arg in _NEGATIVE_VALUE_FLAGS and idx + 1 < len(raw_args):
            next_arg = raw_args[idx + 1]
            if next_arg.startswith("-") and not next_arg.startswith("--"):
                processed.append(f"{arg}={next_arg}")
                idx += 2
                continue
        processed.append(arg)
        idx += 1
    return processed


def build_parser() -> argparse.ArgumentParser:
    """Build the unified CLI argument parser for ``soclens``."""
    parser = argparse.ArgumentParser(
        prog="soclens",
        description="SOCLens",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--dry-run",
        "-d",
        action="store_true",
        default=False,
        help="Global dry-run mode (read-only, no API write operations)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit machine-readable JSON output where supported",
    )
    parser.add_argument(
        "--timezone",
        "--tz",
        default=None,
        help="Display timezone for timestamps (e.g. UTC, local, America/New_York, UTC-05:00)",
    )
    parser.add_argument(
        "--tui",
        "-t",
        action="store_true",
        default=False,
        help="Launch interactive TUI mode",
    )
    parser.add_argument(
        "--image-viewer",
        choices=IMAGE_VIEWER_MODES,
        default=None,
        help="Default TUI image viewer ('tui' modal or 'os' native OS viewer)",
    )
    parser.add_argument(
        "--os-image-viewer",
        action="store_true",
        default=False,
        help="Open screenshots in the OS native image viewer by default",
    )
    parser.add_argument(
        "--view",
        choices=UI_VIEW_MODES,
        default=None,
        help="TUI view mode ('user' default or 'admin' for all tabs)",
    )
    parser.add_argument(
        "--admin",
        action="store_true",
        default=False,
        help="Launch TUI in Admin view (all tabs visible)",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        "--no-verify-ssl",
        dest="insecure",
        action="store_true",
        default=False,
        help="Disable SSL certificate verification for HTTPS requests (for corporate/internal proxy usage)",
    )
    parser.add_argument(
        "--ca-bundle",
        dest="ca_bundle",
        default=None,
        help="Path to custom CA certificate bundle PEM file for HTTPS requests (overrides RF_CA_BUNDLE)",
    )
    subparsers = parser.add_subparsers(dest="command", required=False, help="Subcommand to execute")

    # 1. Watchlist subcommand
    wl_parser = subparsers.add_parser("watchlist", help="Manage Recorded Future lists & watchlists")
    wl_subparsers = wl_parser.add_subparsers(dest="subcommand")

    wl_list = wl_subparsers.add_parser("list", help="Search and list Recorded Future lists")
    wl_list.add_argument("--type", choices=LIST_TYPES, default=None, help="Filter by RF list type")
    wl_list.add_argument("--name", default=None, help="Filter by list name substring")
    wl_list.add_argument("--limit", type=int, default=100, help="Max items per type query (1-100)")
    wl_list.add_argument(
        "--watch-list-only",
        action="store_true",
        default=False,
        help="Only show lists ending with 'Watch List'",
    )
    wl_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    wl_create = wl_subparsers.add_parser("create", help="Create a new Recorded Future list")
    wl_create.add_argument("name", help="Name for the new list")
    wl_create.add_argument(
        "--type",
        choices=LIST_TYPES,
        default="entity",
        help="Recorded Future list type (default: entity)",
    )
    wl_create.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    wl_create.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    wl_info = wl_subparsers.add_parser("info", help="Retrieve metadata for a specific list")
    wl_info.add_argument("list_id", help="The list ID (e.g. report:abc123)")
    wl_info.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    wl_status = wl_subparsers.add_parser("status", help="Retrieve status and size for a specific list")
    wl_status.add_argument("list_id", help="The list ID (e.g. report:abc123)")
    wl_status.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    ent_parser = wl_subparsers.add_parser("entities", help="List entities of a specific watchlist")
    ent_parser.add_argument("list_id", help="The watchlist ID (e.g. report:abc123)")
    ent_parser.add_argument(
        "--sort",
        choices=["none", "name", "id", "type", "status", "annotation"],
        default="none",
        help="Sort entities by column (default: none / API order)",
    )
    ent_parser.add_argument(
        "--desc",
        "--descending",
        dest="descending",
        action="store_true",
        default=False,
        help="Sort in descending order (when --sort is active)",
    )
    ent_parser.add_argument(
        "-f",
        "--filter",
        dest="filter_query",
        default=None,
        help="Case-insensitive substring filter across entity ID, type, status, name, and annotation",
    )
    ent_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    wl_text = wl_subparsers.add_parser("text-entries", help="List text entries of a text-type list")
    wl_text.add_argument("list_id", help="The list ID")
    wl_text.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    wl_tags = wl_subparsers.add_parser("tags", help="List entities with tags on a company list")
    wl_tags.add_argument("list_id", help="The list ID")
    wl_tags.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    wl_rtags = wl_subparsers.add_parser("replace-tags", help="Replace tags on a company list entity")
    wl_rtags.add_argument("list_id", help="The company list ID")
    wl_rtags.add_argument("entity", help="Entity ID or name")
    wl_rtags.add_argument("--tags", required=True, help="Comma-separated list of tags (max 9)")
    wl_rtags.add_argument("--entity-type", default=None, help="Optional entity type")
    wl_rtags.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    wl_rtags.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    add_parser = wl_subparsers.add_parser("add", help="Add a single entity to a watchlist")
    add_parser.add_argument("list_id", help="The watchlist ID")
    add_parser.add_argument("entity_type", help="Recorded Future entity type (e.g. InternetDomainName)")
    add_parser.add_argument("name", help="The entity value/name or RF entity ID")
    add_parser.add_argument("--annotation", default=None, help="Optional context annotation")
    add_parser.add_argument("--resolve", action="store_true", default=False, help="Resolve via entity-match")
    add_parser.add_argument("--is-id", action="store_true", default=False, help="Treat value as raw RF ID")
    add_parser.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    add_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rem_parser = wl_subparsers.add_parser("remove", help="Remove an entity from a watchlist")
    rem_parser.add_argument("list_id", help="The watchlist ID")
    rem_parser.add_argument("entity_id", help="Entity ID or entity type (when 3rd arg provided)")
    rem_parser.add_argument(
        "entity_value",
        nargs="?",
        default=None,
        help="Optional entity value when specifying <entity_type> <entity_value>",
    )
    rem_parser.add_argument(
        "--is-id",
        action="store_true",
        default=False,
        help="Treat entity argument as raw RF entity ID",
    )
    rem_parser.add_argument(
        "--no-resolve",
        action="store_true",
        default=False,
        help="Skip entity ID resolution via watchlist lookup / entity-match",
    )
    rem_parser.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    rem_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    sync_parser = wl_subparsers.add_parser("sync", help="Delta-sync entities from a CSV file to a watchlist")
    sync_parser.add_argument("list_id", help="The watchlist ID")
    sync_parser.add_argument("csv_path", help="Path to the CSV file")
    sync_parser.add_argument(
        "--type",
        default="InternetDomainName",
        help="Recorded Future entity type (default: InternetDomainName)",
    )
    sync_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Perform a dry run without API modifications",
    )
    sync_parser.add_argument(
        "--force-remove",
        action="store_true",
        default=False,
        help="Remove all entities not in CSV, even those not added by automated sync",
    )
    sync_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    export_parser = wl_subparsers.add_parser("export", help="Export entities from a watchlist to a file")
    export_parser.add_argument("list_id", help="The watchlist ID")
    export_parser.add_argument("output_path", nargs="?", default=None, help="Output file path")
    export_parser.add_argument("-o", "--output", dest="output_flag", default=None, help="Output file path")
    export_parser.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Format to save the exported file (default: csv)",
    )
    export_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    wl_subparsers.add_parser("interactive", help="Start the interactive TUI watchlist manager")

    liveness_parser = wl_subparsers.add_parser(
        "validate-liveness", help="Validate DNS liveness of all domains in a watchlist"
    )
    liveness_parser.add_argument("list_id", help="The watchlist ID")
    liveness_parser.add_argument(
        "--interactive", action="store_true", help="Prompt to tag offline domains as non-internet"
    )
    liveness_parser.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    liveness_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    sync_logos_parser = wl_subparsers.add_parser(
        "sync-logos", help="Sync brand logo image hashes of domains to a brand image watchlist"
    )
    sync_logos_parser.add_argument("list_id", help="The brand image (hash) watchlist ID")
    sync_logos_parser.add_argument("--domains", help="Comma-separated list of domains to query and sync")
    sync_logos_parser.add_argument("--domains-file", help="File path containing a list of domains")
    sync_logos_parser.add_argument("--source-list-id", help="Source domain watchlist ID to extract domains from")
    sync_logos_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Perform a dry run without API modifications",
    )
    sync_logos_parser.add_argument(
        "--output-locations",
        default="discovered_images.json",
        help="Path to save discovered image locations JSON (default: discovered_images.json; empty to skip)",
    )
    sync_logos_parser.add_argument(
        "--ignore-hashes-file",
        help="Path to file containing hashes (MD5, SHA-1, SHA-256) to ignore/tune out",
    )
    sync_logos_parser.add_argument("--ignore-hashes", help="Comma-separated list of hashes to ignore/tune out")
    sync_logos_parser.add_argument(
        "--watch",
        action="store_true",
        default=False,
        help="Run unattended continuous brand logo sync loop",
    )
    sync_logos_parser.add_argument(
        "--interval",
        type=float,
        default=3600.0,
        help="Polling interval in seconds for --watch mode (default: 3600.0)",
    )
    sync_logos_parser.add_argument(
        "--max-runs",
        type=int,
        default=None,
        help="Maximum iterations for --watch mode before exiting",
    )
    sync_logos_parser.add_argument("--state-file", default=None, help="Path to brand_sync_state.json")
    sync_logos_parser.add_argument("--lock-file", default=None, help="Path to lockfile for --watch mode")
    sync_logos_parser.add_argument(
        "--grace-failures",
        type=int,
        default=3,
        help="Consecutive domain failures before pruning hashes (default: 3)",
    )
    sync_logos_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    val_logos_parser = wl_subparsers.add_parser(
        "validate-logos", help="Validate/dry-run sync of brand logo image hashes of domains to a watchlist"
    )
    val_logos_parser.add_argument("list_id", help="The brand image (hash) watchlist ID")
    val_logos_parser.add_argument("--domains", help="Comma-separated list of domains to query")
    val_logos_parser.add_argument("--domains-file", help="File path containing a list of domains")
    val_logos_parser.add_argument("--source-list-id", help="Source domain watchlist ID to extract domains from")
    val_logos_parser.add_argument(
        "--output-locations",
        default="discovered_images.json",
        help="Path to save discovered image locations JSON (default: discovered_images.json; empty to skip)",
    )
    val_logos_parser.add_argument(
        "--ignore-hashes-file",
        help="Path to file containing hashes (MD5, SHA-1, SHA-256) to ignore/tune out",
    )
    val_logos_parser.add_argument("--ignore-hashes", help="Comma-separated list of hashes to ignore/tune out")
    val_logos_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    brand_issues_parser = wl_subparsers.add_parser(
        "brand-issues",
        help="Inspect sorted Brand Sync issues (missing hashes, errors, grace risk, duplicate hashes)",
    )
    brand_issues_parser.add_argument(
        "--list-id",
        default=None,
        help="Optional Brand Hash watchlist ID to cross-reference live entities",
    )
    brand_issues_parser.add_argument(
        "--source-list-id",
        default=None,
        help="Optional Domain watchlist ID to detect never-synced domains",
    )
    brand_issues_parser.add_argument(
        "--state-file",
        default=DEFAULT_STATE_FILENAME,
        help=f"Brand sync state JSON file path (default: {DEFAULT_STATE_FILENAME})",
    )
    brand_issues_parser.add_argument(
        "--category",
        choices=BRAND_SYNC_ISSUE_CATEGORIES,
        default="all",
        help="Issue dashboard category to display (default: all)",
    )
    brand_issues_parser.add_argument(
        "--sort",
        choices=BRAND_ROW_SORT_FIELDS,
        default="severity",
        help="Sort issues by field (default: severity)",
    )
    brand_issues_parser.add_argument(
        "--desc",
        action="store_true",
        default=False,
        help="Sort descending",
    )
    brand_issues_parser.add_argument(
        "--filter",
        "-f",
        dest="filter_query",
        default=None,
        help="Filter issues by domain, status, or reason text",
    )
    brand_issues_parser.add_argument(
        "--grace-failures",
        type=int,
        default=3,
        help="Failure threshold used to flag grace-period risk (default: 3)",
    )
    brand_issues_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    # 2. Recorded Future SOC APIs subcommand
    rf_parser = subparsers.add_parser("rf", help="Query Recorded Future SOC APIs (Entity Match, v2, SOAR, Alerts, Cases, Sandbox)")
    rf_subparsers = rf_parser.add_subparsers(dest="rf_subcommand")

    rf_apis = rf_subparsers.add_parser("apis", help="Show documented Recorded Future API families and CLI mappings")
    rf_apis.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_match = rf_subparsers.add_parser(
        "entity-match", aliases=["match"], help="Resolve entity names to Recorded Future entity IDs"
    )
    rf_match.add_argument("name", help="Name or term to match")
    rf_match.add_argument("--types", default=None, help="Comma-separated entity types (e.g. Company,Malware)")
    rf_match.add_argument("--limit", type=int, default=10, help="Max results (default: 10)")
    rf_match.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_elookup = rf_subparsers.add_parser("entity-lookup", help="Fetch metadata for an RF entity ID")
    rf_elookup.add_argument("entity_id", help="Recorded Future entity ID")
    rf_elookup.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_lookup = rf_subparsers.add_parser("lookup", help="Connect API v2 single-entity lookup")
    rf_lookup.add_argument("entity_type", help="Entity type (ip, domain, hash, url, vulnerability, malware, company)")
    rf_lookup.add_argument("entity_id", help="Entity value or ID")
    rf_lookup.add_argument("--fields", default=None, help="Comma-separated v2 fields")
    rf_lookup.add_argument("--metadata", action="store_true", default=False, help="Include field metadata")
    rf_lookup.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_company = rf_subparsers.add_parser("company", help="Connect API v2 company-by-domain lookup")
    rf_company.add_argument("domain", help="Domain name to resolve to owning company")
    rf_company.add_argument("--fields", default=None, help="Comma-separated v2 fields")
    rf_company.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_search = rf_subparsers.add_parser("search", help="Connect API v2 entity search")
    rf_search.add_argument("entity_type", help="Entity type (ip, domain, hash, url, vulnerability, company)")
    rf_search.add_argument("--freetext", default=None, help="Free-text search filter")
    rf_search.add_argument("--risk-score", default=None, help="Risk score filter (e.g. '[65,100]')")
    rf_search.add_argument("--limit", type=int, default=20, help="Result limit")
    rf_search.add_argument("--fields", default=None, help="Comma-separated fields")
    rf_search.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_risklist = rf_subparsers.add_parser("risklist", help="Fetch or stat a Connect v2 Risk List")
    rf_risklist.add_argument("entity_type", help="Risk list type (ip, domain, hash, url, vulnerability)")
    rf_risklist.add_argument("--format", default="csv/splunk", help="Format (default: csv/splunk)")
    rf_risklist.add_argument("--list-name", default=None, help="Optional risk list name")
    rf_risklist.add_argument("--output", "-o", default=None, help="Optional file path to save risk list")
    rf_risklist.add_argument("--stat", action="store_true", default=False, help="HEAD check ETag/Last-Modified only")
    rf_risklist.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_riskrules = rf_subparsers.add_parser("riskrules", help="List Connect v2 risk rules for an entity type")
    rf_riskrules.add_argument("entity_type", help="Entity type (ip, domain, hash, url, vulnerability, company)")
    rf_riskrules.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_enrich = rf_subparsers.add_parser("enrich", help="SOAR v3 batch IOC enrichment")
    rf_enrich.add_argument("--ip", action="append", default=None, help="IP address(es)")
    rf_enrich.add_argument("--domain", action="append", default=None, help="Domain(s)")
    rf_enrich.add_argument("--hash", action="append", default=None, help="Hash(es)")
    rf_enrich.add_argument("--url", action="append", default=None, help="URL(s)")
    rf_enrich.add_argument("--vulnerability", action="append", default=None, help="CVE(s)")
    rf_enrich.add_argument("--metadata", action="store_true", default=False, help="Include metadata")
    rf_enrich.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_triage = rf_subparsers.add_parser("triage", help="SOAR v3 context triage")
    rf_triage.add_argument("context", help="Triage context name (e.g. phishing, malware, c2)")
    rf_triage.add_argument("--ip", action="append", default=None, help="IP address(es)")
    rf_triage.add_argument("--domain", action="append", default=None, help="Domain(s)")
    rf_triage.add_argument("--hash", action="append", default=None, help="Hash(es)")
    rf_triage.add_argument("--url", action="append", default=None, help="URL(s)")
    rf_triage.add_argument("--vulnerability", action="append", default=None, help="CVE(s)")
    rf_triage.add_argument("--threshold", type=int, default=None, help="Custom risk score threshold")
    rf_triage.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_contexts = rf_subparsers.add_parser("contexts", help="List available SOAR v3 triage contexts")
    rf_contexts.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_alerts = rf_subparsers.add_parser("alerts", help="Search classic Alerts v3")
    rf_alerts.add_argument("--limit", type=int, default=20, help="Max alerts (1-1000)")
    rf_alerts.add_argument("--offset", type=int, default=0, help="Starting offset")
    rf_alerts.add_argument("--status", default=None, help="Status filter (statusInPortal)")
    rf_alerts.add_argument("--triggered", default=None, help="Triggered range filter")
    rf_alerts.add_argument("--rule", default=None, help="Alert rule ID filter")
    rf_alerts.add_argument("--freetext", default=None, help="Free-text filter")
    rf_alerts.add_argument("--alert-id", default=None, help="Fetch single Alert v3 detail by ID")
    rf_alerts.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_pb = rf_subparsers.add_parser("playbook-alerts", help="Search or inspect Playbook Alerts")
    rf_pb.add_argument(
        "--categories",
        default="domain_abuse,malicious_sites",
        help=f"Comma-separated categories (known: {', '.join(sorted(PLAYBOOK_CATEGORY_PATH_MAP))})",
    )
    rf_pb.add_argument("--statuses", default=None, help="Comma-separated status filters")
    rf_pb.add_argument("--limit", type=int, default=20, help="Max results")
    rf_pb.add_argument("--alert-id", default=None, help="Inspect specific Playbook Alert ID")
    rf_pb.add_argument("--category", default="domain_abuse", help="Category for --alert-id lookup")
    rf_pb.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_cases = rf_subparsers.add_parser("cases", help="Search or inspect Recorded Future Cases")
    rf_cases.add_argument("--statuses", default=None, help="Comma-separated status filters")
    rf_cases.add_argument("--priorities", default=None, help="Comma-separated priority filters")
    rf_cases.add_argument("--limit", type=int, default=20, help="Max results")
    rf_cases.add_argument("--case-id", default=None, help="Lookup specific case ID")
    rf_cases.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_sb = rf_subparsers.add_parser("sandbox", help="Search or inspect Recorded Future Sandbox samples")
    rf_sb.add_argument("--query", default=None, help="Sandbox search query")
    rf_sb.add_argument("--sample-id", default=None, help="Fetch sample status/overview")
    rf_sb.add_argument("--overview", action="store_true", default=False, help="Fetch full overview.json for --sample-id")
    rf_sb.add_argument("--limit", type=int, default=20, help="Max search results")
    rf_sb.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_fields = rf_subparsers.add_parser("fields", help="List available Connect v2 fields for an entity type")
    rf_fields.add_argument("entity_type", help="Entity type (ip, domain, hash, url, vulnerability, company, malware)")
    rf_fields.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    rf_ext = rf_subparsers.add_parser("extension", help="Query Connect v2 third-party Intelligence Card extensions")
    rf_ext.add_argument("entity_type", nargs="?", default=None, help="Entity type (ip, domain, hash, url, vulnerability, malware)")
    rf_ext.add_argument("entity_id", nargs="?", default=None, help="Entity value or RF ID")
    rf_ext.add_argument("extension", nargs="?", default=None, help="Extension name")
    rf_ext.add_argument("--list", action="store_true", default=False, help="List documented extensions per entity type")
    rf_ext.add_argument("--metadata", action="store_true", default=False, help="Include extension metadata")
    rf_ext.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    # 3. Threat Research subcommand (all Recorded Future APIs)
    res_parser = subparsers.add_parser(
        "research",
        help="Run comprehensive multi-API Recorded Future threat research & surface queries",
    )
    res_subparsers = res_parser.add_subparsers(dest="research_subcommand")

    res_inv = res_subparsers.add_parser(
        "investigate",
        aliases=["dossier"],
        help="Run a full cross-API threat research dossier on any indicator, CVE, malware, actor, or text",
    )
    res_inv.add_argument("target", help="IP, domain, hash, URL, CVE, malware, threat actor, MITRE ID, or text")
    res_inv.add_argument(
        "--type",
        choices=[
            "auto",
            "ip",
            "domain",
            "hash",
            "url",
            "vulnerability",
            "malware",
            "actor",
            "company",
            "email",
            "mitre",
            "asn",
            "entity_id",
            "text",
        ],
        default="auto",
        help="Explicit target type override (default: auto-detect)",
    )
    res_inv.add_argument(
        "--modules",
        action="append",
        default=None,
        help=f"Comma-separated research modules (available: {', '.join(RESEARCH_MODULES)})",
    )
    res_inv.add_argument("--deep", action="store_true", default=False, help="Include Connect v2 extensions")
    res_inv.add_argument("--extensions", action="append", default=None, help="Specific v2 extensions to query")
    res_inv.add_argument(
        "--links-scope",
        choices=["small", "medium", "large"],
        default="medium",
        help="Links Graph search depth (default: medium)",
    )
    res_inv.add_argument("--links-timeframe", default="-30d", help="Links Graph technical timeframe (default: -30d)")
    res_inv.add_argument("--limit", type=int, default=20, help="Result limit per API surface (default: 20)")
    res_inv.add_argument("-o", "--output", default=None, help="Optional output file path (.md or .json)")
    res_inv.add_argument(
        "--format",
        choices=["markdown", "json"],
        default=None,
        help="Output file format when --output is set (default: infer from suffix or markdown)",
    )
    res_inv.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_caps = res_subparsers.add_parser("capabilities", help="Probe token entitlements across all Recorded Future APIs")
    res_caps.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_links = res_subparsers.add_parser("links", help="Query the Recorded Future Links relationship graph")
    res_links.add_argument("entities", nargs="*", help="Entity ID(s) or IOCs to query")
    res_links.add_argument("--types", action="append", default=None, help="Filter linked entity types (e.g. type:IpAddress)")
    res_links.add_argument("--sections", action="append", default=None, help="Filter link section IDs")
    res_links.add_argument("--sources", action="append", default=None, help="Filter sources: technical, insikt")
    res_links.add_argument("--timeframe", default="-30d", help="Technical timeframe (default: -30d)")
    res_links.add_argument("--scope", choices=["small", "medium", "large"], default="medium", help="Search scope")
    res_links.add_argument("--connected", action="append", default=None, help="Filter by connected entities")
    res_links.add_argument("--per-type", type=int, default=25, help="Max results per entity type (default: 25)")
    res_links.add_argument(
        "--metadata",
        choices=["entities", "events", "sections"],
        default=None,
        help="Retrieve Links metadata instead of searching",
    )
    res_links.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_notes = res_subparsers.add_parser("notes", help="Search, inspect, or export Insikt & Enterprise Analyst Notes")
    res_notes.add_argument("--entity", default=None, help="Filter by entity ID")
    res_notes.add_argument("--topic", default=None, help="Topic name or RF topic ID")
    res_notes.add_argument("--title", default=None, help="Filter by title substring")
    res_notes.add_argument("--label", default=None, help="Filter by label")
    res_notes.add_argument("--source", default=None, help="Filter by source ID")
    res_notes.add_argument("--published", default=None, help="Published after date (e.g. -30d or 2026-01-01)")
    res_notes.add_argument("--enterprise-only", action="store_true", default=False, help="Enterprise-authored notes only")
    res_notes.add_argument("--note-id", default=None, help="Lookup specific Analyst Note ID")
    res_notes.add_argument("--serialization", choices=["id", "min", "full"], default="full", help="Serialization depth")
    res_notes.add_argument("--export", choices=["html", "pdf"], default=None, help="Export --note-id as html or pdf")
    res_notes.add_argument("--attachment", action="store_true", default=False, help="Download attachment for --note-id")
    res_notes.add_argument("-o", "--output", default=None, help="Output file path for --export or --attachment")
    res_notes.add_argument("--topics", action="store_true", default=False, help="List all 37 Analyst Note topics and IDs")
    res_notes.add_argument("--limit", type=int, default=20, help="Max results (default: 20)")
    res_notes.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_actors = res_subparsers.add_parser("actors", help="Search Threat Actors and query Threat Actor Threat Maps")
    res_actors.add_argument("--query", default=None, help="Actor name/prefix search (supports exact:, prefix:, infix:)")
    res_actors.add_argument("--map", action="store_true", default=False, help="Fetch organizational Threat Actor Threat Map")
    res_actors.add_argument("--org-id", default=None, help="Optional multi-org Threat Map orgId")
    res_actors.add_argument("--categories", action="store_true", default=False, help="List Threat Actor categories")
    res_actors.add_argument("--threat-maps", action="store_true", default=False, help="List available Threat Maps")
    res_actors.add_argument("--limit", type=int, default=25, help="Max results (default: 25)")
    res_actors.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_mal = res_subparsers.add_parser("malware", help="Research malware via Malware Intelligence, Threat Maps & Connect v2")
    res_mal.add_argument("--query", default=None, help="Malware Intelligence query string")
    res_mal.add_argument("--nl", action="store_true", default=False, help="Use natural-language Malware Intel query")
    res_mal.add_argument("--iocs", action="store_true", default=False, help="Query Malware Intel by IOC lists")
    res_mal.add_argument("--ip", action="append", default=None, help="IP IOC(s) for --iocs")
    res_mal.add_argument("--domain", action="append", default=None, help="Domain IOC(s) for --iocs")
    res_mal.add_argument("--hash", action="append", default=None, help="SHA-256 hash(es) for --iocs")
    res_mal.add_argument("--url", action="append", default=None, help="URL IOC(s) for --iocs")
    res_mal.add_argument("--operator", choices=["or", "and"], default="or", help="IOC boolean operator (default: or)")
    res_mal.add_argument(
        "--field",
        choices=list(MALWARE_INTEL_FIELDS),
        default="sha256",
        help="Malware Intel aggregation field (default: sha256)",
    )
    res_mal.add_argument("--start-date", default=None, help="Start date YYYY-MM-DD (default: 90d ago, min 2023-11-01)")
    res_mal.add_argument("--end-date", default=None, help="Optional end date YYYY-MM-DD")
    res_mal.add_argument("--reports-sha256", default=None, help="Fetch sandbox reports for SHA-256")
    res_mal.add_argument("--map", action="store_true", default=False, help="Fetch organizational Malware Threat Map")
    res_mal.add_argument("--org-id", default=None, help="Optional multi-org Threat Map orgId")
    res_mal.add_argument("--categories", action="store_true", default=False, help="List Malware categories")
    res_mal.add_argument("--v2-search", default=None, help="Search Malware entities via Connect v2")
    res_mal.add_argument("--v2-lookup", default=None, help="Lookup Malware entity ID via Connect v2")
    res_mal.add_argument("--limit", type=int, default=25, help="Max results (default: 25)")
    res_mal.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_risk = res_subparsers.add_parser("risk", help="Query Risk History timelines and active company risk rule evidence")
    res_risk.add_argument("--history", nargs="+", default=None, help="Entity ID(s) for Risk History timeline")
    res_risk.add_argument("--from", dest="from_date", default=None, help="Start date/time for Risk History")
    res_risk.add_argument("--to", dest="to_date", default=None, help="End date/time for Risk History")
    res_risk.add_argument("--company", default=None, help="Company entity ID for active risk rule evidence")
    res_risk.add_argument("--rule", default=None, help="Risk rule alias (e.g. openPort)")
    res_risk.add_argument("--limit", type=int, default=50, help="Max evidence records (default: 50)")
    res_risk.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_ident = res_subparsers.add_parser("identity", help="Query Identity & Credential Intelligence")
    res_ident.add_argument("--domains", action="append", default=None, help="Domain(s) for credential search")
    res_ident.add_argument("--subjects", action="append", default=None, help="Email/username subjects for lookup")
    res_ident.add_argument("--hostname", default=None, help="Hostname lookup")
    res_ident.add_argument("--ip", default=None, help="IP address lookup")
    res_ident.add_argument("--password-hash", default=None, help="Password hash or 5-char prefix lookup")
    res_ident.add_argument("--algorithm", default="SHA1", help="Hash algorithm for --password-hash (default: SHA1)")
    res_ident.add_argument("--dump", action="append", default=None, help="Search breach dump metadata by name")
    res_ident.add_argument("--incident-source", default=None, help="Incident report for malware log source")
    res_ident.add_argument("--detections", action="store_true", default=False, help="Fetch identity detections")
    res_ident.add_argument("--novel-only", action="store_true", default=False, help="Filter detections to novel exposures")
    res_ident.add_argument("--malware-only", action="store_true", default=False, help="Filter detections to stealer malware")
    res_ident.add_argument("--limit", type=int, default=25, help="Max results (default: 25)")
    res_ident.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_ext = res_subparsers.add_parser("extension", help="Query Connect v2 third-party extensions")
    res_ext.add_argument("entity_type", nargs="?", default=None, help="Entity type (ip, domain, hash, url, vulnerability, malware)")
    res_ext.add_argument("entity_id", nargs="?", default=None, help="Entity value or RF ID")
    res_ext.add_argument("extension", nargs="?", default=None, help="Extension name")
    res_ext.add_argument("--list", action="store_true", default=False, help="List supported extensions")
    res_ext.add_argument("--metadata", action="store_true", default=False, help="Include extension metadata")
    res_ext.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_rules = res_subparsers.add_parser("rules", help="Search Insikt Detection Rules (Sigma/YARA/Snort) & Alert Rules")
    res_rules.add_argument("--entity", action="append", default=None, help="Filter by RF entity ID(s)")
    res_rules.add_argument("--title", default=None, help="Filter by rule title substring")
    res_rules.add_argument("--types", default="sigma,yara,snort", help="Comma-separated rule types (default: sigma,yara,snort)")
    res_rules.add_argument("--days", type=int, default=None, help="Rules updated in last N days")
    res_rules.add_argument("--entities-list", action="store_true", default=False, help="List entities linked to detection rules")
    res_rules.add_argument("--entity-types", action="store_true", default=False, help="List entity types in detection rules")
    res_rules.add_argument("--alert-rules", default=None, nargs="?", const="", help="Search classic Alert Rules (optional freetext)")
    res_rules.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")
    res_rules.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_ci = res_subparsers.add_parser("collective-insights", help="Search Collective Insights enriched detections & exclusions")
    res_ci.add_argument("--malware", default=None, help="Filter by malware name")
    res_ci.add_argument("--actor", default=None, help="Filter by threat actor name")
    res_ci.add_argument("--mitre", default=None, help="Filter by MITRE ATT&CK code")
    res_ci.add_argument("--indicator-type", default=None, help="Filter by indicator type")
    res_ci.add_argument("--from", dest="from_date", default=None, help="Start detection time")
    res_ci.add_argument("--to", dest="to_date", default=None, help="End detection time")
    res_ci.add_argument("--exclusions-org", default=None, help="List exclusion items for organization ID")
    res_ci.add_argument("--limit", type=int, default=25, help="Max results (default: 25)")
    res_ci.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_fusion = res_subparsers.add_parser("fusion", help="Browse, stat, and download Fusion v3 datasets")
    res_fusion.add_argument("--ls", default=None, nargs="?", const="/public", help="List Fusion directory (default: /public)")
    res_fusion.add_argument("--stat", default=None, help="HEAD check Fusion file metadata")
    res_fusion.add_argument("--get", default=None, help="Download Fusion file path")
    res_fusion.add_argument("-o", "--output", default=None, help="Output file path for --get")
    res_fusion.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_taxii = res_subparsers.add_parser("taxii2", help="Explore STIX / TAXII 2.1 feeds")
    res_taxii.add_argument("--discover", action="store_true", default=False, help="Discover TAXII 2.1 server & roots")
    res_taxii.add_argument("--collections", action="store_true", default=False, help="List collections under --root")
    res_taxii.add_argument("--objects", default=None, help="Fetch STIX 2.1 objects from collection ID")
    res_taxii.add_argument("--root", default="default", choices=["default", "large", "opencti", "test"], help="TAXII API root")
    res_taxii.add_argument("--added-after", default=None, help="ISO timestamp filter")
    res_taxii.add_argument("--limit", type=int, default=50, help="Max objects (1-1000, default: 50)")
    res_taxii.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_ato = res_subparsers.add_parser("ato", help="Query Autonomous Threat Operations sources, profiles, indicators & rules")
    res_ato.add_argument("--sources", action="store_true", default=False, help="List custom ATO intelligence sources")
    res_ato.add_argument("--profiles", choices=["hunting", "detection", "prevention"], default=None, help="Query ATO profiles by kind")
    res_ato.add_argument("--indicators", default=None, help="Fetch indicators for ATO profile ID")
    res_ato.add_argument("--rules", default=None, help="Fetch detection rules for ATO profile ID")
    res_ato.add_argument("--kind", choices=["detection", "prevention"], default="detection", help="Profile kind for --indicators/--rules")
    res_ato.add_argument("--limit", type=int, default=50, help="Max indicators (default: 50)")
    res_ato.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_sb = res_subparsers.add_parser("sandbox", help="Deep research on Recorded Future Sandbox v0 reports & YARA rules")
    res_sb.add_argument("--query", default=None, help="Search sandbox samples")
    res_sb.add_argument("--list", choices=["owned", "org", "public"], default=None, help="List sandbox submissions by scope")
    res_sb.add_argument("--sample-id", default=None, help="Sample ID to inspect")
    res_sb.add_argument(
        "--report",
        choices=["overview", "summary", "static", "dynamic", "urlscan"],
        default="overview",
        help="Report type for --sample-id (default: overview)",
    )
    res_sb.add_argument("--task-id", default="behavioral1", help="Task ID for --report dynamic (default: behavioral1)")
    res_sb.add_argument("--screenshot", action="store_true", default=False, help="Download URL scan screenshot PNG")
    res_sb.add_argument("-o", "--output", default=None, help="Output file path for --screenshot")
    res_sb.add_argument("--yara", action="store_true", default=False, help="List custom Sandbox YARA rules")
    res_sb.add_argument("--yara-rule", default=None, help="Fetch source for named Sandbox YARA rule")
    res_sb.add_argument("--limit", type=int, default=20, help="Max results (default: 20)")
    res_sb.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_asi = res_subparsers.add_parser("asi", help="Query Attack Surface Intelligence (ASI) projects, assets & exposures")
    res_asi.add_argument("--projects", action="store_true", default=False, help="List ASI projects")
    res_asi.add_argument("--assets", default=None, help="Find assets in ASI project ID")
    res_asi.add_argument("--asset", nargs=2, metavar=("PROJECT_ID", "ASSET_ID"), default=None, help="Read single ASI asset")
    res_asi.add_argument("--asset-exposures", nargs=2, metavar=("PROJECT_ID", "ASSET_ID"), default=None, help="List exposures for asset")
    res_asi.add_argument("--exposures", default=None, help="List exposure signatures in project ID")
    res_asi.add_argument("--signatures", default=None, help="List catalog signatures in project ID")
    res_asi.add_argument("--asset-type", default=None, help="Filter assets by type")
    res_asi.add_argument("--apex", default=None, help="Filter assets by apex domain")
    res_asi.add_argument("--severity", default=None, help="Filter by severity (informational, moderate, critical)")
    res_asi.add_argument("--cve", default=None, help="Filter exposures/signatures by CVE ID")
    res_asi.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")
    res_asi.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_pfi = res_subparsers.add_parser("pfi", help="Query Payment Fraud Intelligence (PFI) tasks and pipelines")
    res_pfi.add_argument("--tasks", action="store_true", default=False, help="List queued PFI tasks")
    res_pfi.add_argument("--status", default=None, help="Check PFI task status by ID")
    res_pfi.add_argument(
        "--preview",
        default=None,
        help=f"Dry-run record count for pipeline ({', '.join(PFI_PIPELINES)})",
    )
    res_pfi.add_argument("--query", default=None, help="Optional PFI pipeline query string")
    res_pfi.add_argument("--from", dest="from_date", default="now-7d/d", help="Elasticsearch range start (default: now-7d/d)")
    res_pfi.add_argument("--to", dest="to_date", default="now/d", help="Elasticsearch range end (default: now/d)")
    res_pfi.add_argument("--pickup", default=None, help="Download completed PFI task output by ID")
    res_pfi.add_argument("--format", choices=["json", "csv"], default="json", help="Format for --pickup (default: json)")
    res_pfi.add_argument("--columns", default=None, help="Comma-separated columns for --pickup")
    res_pfi.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    res_rr = res_subparsers.add_parser("riskrecon", help="Query RiskRecon third-party posture, ratings & findings")
    res_rr.add_argument("--toes", action="store_true", default=False, help="List RiskRecon TOEs")
    res_rr.add_argument("--domain", default=None, help="Lookup RiskRecon TOE by domain")
    res_rr.add_argument("--cve", default=None, help="Lookup RiskRecon TOEs affected by CVE")
    res_rr.add_argument("--ratings", default=None, help="Get ratings for TOE ID")
    res_rr.add_argument("--findings", default=None, help="Get paginated findings for TOE ID")
    res_rr.add_argument("--severity", default=None, help="Severity filter for --findings")
    res_rr.add_argument("--hosts", default=None, help="Get discovered hosts for TOE ID")
    res_rr.add_argument("--breaches", action="store_true", default=False, help="List portfolio breach events")
    res_rr.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    # 3. Sigma rules subcommand
    sig_parser = subparsers.add_parser("sigma", help="Search and convert Recorded Future Sigma rules to Splunk stanzas")
    sig_parser.add_argument("query", nargs="?", default=None, help="Optional search query to run immediately")
    sig_parser.add_argument("--refresh", action="store_true", help="Force refresh cached rules from Recorded Future API")
    sig_parser.add_argument("--export", action="store_true", help="Generate Splunk savedsearches.conf stanzas from rules")
    sig_parser.add_argument("--days", type=int, default=None, help="Process rules updated in the last N days")
    sig_parser.add_argument("--output", type=str, default="savedsearches.conf", help="Output file path (default: savedsearches.conf)")
    sig_parser.add_argument(
        "--mode", type=str, choices=["overwrite", "append"], default="overwrite", help="Output write mode (default: overwrite)"
    )
    sig_parser.add_argument("--cron-schedule", type=str, default="0 * * * *", help="Cron schedule for stanzas")
    sig_parser.add_argument("--earliest-time", type=str, default="-70m", help="Dispatch earliest time (default: -70m)")
    sig_parser.add_argument("--latest-time", type=str, default="-10m", help="Dispatch latest time (default: -10m)")
    sig_parser.add_argument("--suppress-period", type=str, default="86400s", help="Throttling suppression period")
    sig_parser.add_argument("--suppress-fields", type=str, default=None, help="Override throttling suppress fields")
    sig_parser.add_argument("--table-fields", type=str, default=None, help="Override trailing table fields")
    sig_parser.add_argument(
        "--index",
        dest="index_override",
        type=str,
        default=None,
        help="Global custom Splunk index override (supports comma-separated multi-index)",
    )
    sig_parser.add_argument(
        "--index-map",
        action="append",
        default=None,
        help="Custom logsource=index mapping (e.g. windows=win_sec,aws=cloud_aws or JSON; repeatable)",
    )
    sig_parser.add_argument(
        "--default-index",
        type=str,
        default=None,
        help="Fallback Splunk index for unmapped logsources (replaces '*')",
    )
    sig_parser.add_argument(
        "--custom-table-fields",
        "--extra-table-fields",
        dest="custom_table_fields",
        type=str,
        default=None,
        help="Custom fields appended to trailing '| table' while keeping logsource defaults",
    )
    sig_parser.add_argument(
        "--table-fields-map",
        action="append",
        default=None,
        help="Per-logsource table field mapping (e.g. 'windows=_time host User org_id'; repeatable)",
    )
    sig_parser.add_argument(
        "--custom-suppress-fields",
        type=str,
        default=None,
        help="Custom fields added to alert.suppress.fields",
    )
    sig_parser.add_argument(
        "--suppress-fields-map",
        action="append",
        default=None,
        help="Per-logsource suppression field mapping (repeatable)",
    )
    sig_parser.add_argument(
        "--field-map",
        action="append",
        default=None,
        help="Sigma-to-Splunk field rename mapping (e.g. CommandLine=process,User=user; repeatable)",
    )
    sig_parser.add_argument(
        "--sourcetype-map",
        action="append",
        default=None,
        help="Per-logsource Splunk sourcetype mapping (e.g. windows:security=WinEventLog:Security; repeatable)",
    )
    sig_parser.add_argument(
        "--pipeline",
        choices=list(SIGMA_PIPELINES),
        default=None,
        help="pySigma Splunk processing pipeline (default: splunk_windows)",
    )
    sig_parser.add_argument(
        "--pipeline-file",
        type=str,
        default=None,
        help="Path to a custom pySigma YAML processing pipeline file",
    )
    sig_parser.add_argument(
        "--output-format",
        choices=list(SIGMA_OUTPUT_FORMATS),
        default=None,
        help="pySigma Splunk output format (default or data_model)",
    )
    sig_parser.add_argument(
        "--sigma-config",
        type=str,
        default=None,
        help="Path to JSON or YAML Sigma conversion configuration profile",
    )
    sig_parser.add_argument(
        "--no-split",
        action="store_true",
        default=False,
        help="Write all stanzas into the single --output file instead of splitting by index",
    )
    sig_parser.add_argument(
        "--no-rule-fields",
        action="store_true",
        default=False,
        help="Do not auto-merge Sigma YAML 'fields:' entries into '| table'",
    )
    sig_parser.add_argument(
        "--convert-file",
        action="append",
        default=None,
        help="Convert local Sigma YAML rule file(s) offline without Recorded Future API access",
    )
    sig_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    # 4. Validate subcommand
    val_parser = subparsers.add_parser("validate", help="Validate savedsearches.conf stanzas against Splunk REST API")
    val_parser.add_argument(
        "--input", type=str, default="savedsearches.conf", help="Saved searches input file path or glob pattern"
    )
    val_parser.add_argument("--earliest", type=str, default="-7d", help="Earliest lookback period (default: -7d)")
    val_parser.add_argument("--latest", type=str, default="now", help="Latest boundary (default: now)")
    val_parser.add_argument("--concurrency", type=int, default=5, help="Max concurrent search jobs (default: 5)")
    val_parser.add_argument("--timeout", type=int, default=180, help="Search job timeout in seconds (default: 180)")
    val_parser.add_argument("--host", type=str, default=None, help="Splunk Host URL")
    val_parser.add_argument("--token", type=str, default=None, help="Splunk Bearer Token")
    val_parser.add_argument("--username", type=str, default=None, help="Splunk Basic Auth Username")
    val_parser.add_argument("--password", type=str, default=None, help="Splunk Basic Auth Password")
    val_parser.add_argument(
        "--app",
        type=str,
        default=None,
        help="Splunk app namespace (default: SPLUNK_APP or SplunkEnterpriseSecuritySuite)",
    )
    val_parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates (default: False)")
    val_parser.add_argument(
        "--output", type=str, default="validation_results.json", help="Output validation report JSON"
    )
    val_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Parse configurations without running searches",
    )
    val_parser.add_argument("--background", action="store_true", help="Run validation in a detached background process")
    val_parser.add_argument("--log-file", type=str, default=None, help="File to write execution logs to")
    val_parser.add_argument("--status-file", type=str, default=None, help="JSON file to write progress status updates to")
    val_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    # 5. Splunk REST API subcommand group
    splunk_parser = subparsers.add_parser(
        "splunk",
        help="Query Splunk Search Head REST API (check, search, indexes, saved-searches, dispatch)",
    )
    splunk_subparsers = splunk_parser.add_subparsers(dest="subcommand", required=True)

    def _add_splunk_conn_args(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--host", type=str, default=None, help="Splunk Host URL")
        sub.add_argument("--token", type=str, default=None, help="Splunk Bearer Token")
        sub.add_argument("--username", type=str, default=None, help="Splunk Basic Auth Username")
        sub.add_argument("--password", type=str, default=None, help="Splunk Basic Auth Password")
        sub.add_argument(
            "--app",
            type=str,
            default=None,
            help="Splunk app namespace (default: SPLUNK_APP or SplunkEnterpriseSecuritySuite)",
        )
        sub.add_argument(
            "--verify-ssl",
            action="store_true",
            default=False,
            help="Verify SSL certificates (default: False)",
        )
        sub.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    sp_check = splunk_subparsers.add_parser("check", help="Check Splunk REST API connectivity")
    _add_splunk_conn_args(sp_check)

    sp_search = splunk_subparsers.add_parser("search", help="Run an ad-hoc SPL search job")
    sp_search.add_argument("spl", help="SPL search query string")
    sp_search.add_argument(
        "--earliest", type=str, default="-24h", help="Earliest time bound (default: -24h)"
    )
    sp_search.add_argument(
        "--latest", type=str, default="now", help="Latest time bound (default: now)"
    )
    sp_search.add_argument(
        "--count", type=int, default=100, help="Max results to fetch (default: 100)"
    )
    sp_search.add_argument(
        "--offset", type=int, default=0, help="Result pagination offset (default: 0)"
    )
    sp_search.add_argument(
        "--timeout", type=int, default=180, help="Search job timeout in seconds (default: 180)"
    )
    sp_search.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="Output format (default: table)",
    )
    sp_search.add_argument(
        "-o", "--output", type=str, default=None, help="Optional export file path (JSON or CSV)"
    )
    _add_splunk_conn_args(sp_search)

    sp_indexes = splunk_subparsers.add_parser("indexes", help="List accessible Splunk indexes")
    _add_splunk_conn_args(sp_indexes)

    sp_saved = splunk_subparsers.add_parser("saved-searches", help="List Splunk saved searches")
    sp_saved.add_argument(
        "--filter",
        type=str,
        default=None,
        help="Case-insensitive filter on saved search name, SPL, or description",
    )
    sp_saved.add_argument(
        "--count", type=int, default=100, help="Max saved searches to list (default: 100)"
    )
    _add_splunk_conn_args(sp_saved)

    sp_dispatch = splunk_subparsers.add_parser(
        "dispatch", help="Dispatch a Splunk saved search by name"
    )
    sp_dispatch.add_argument("name", help="Saved search name")
    sp_dispatch.add_argument(
        "--earliest", type=str, default=None, help="Optional earliest time override"
    )
    sp_dispatch.add_argument(
        "--latest", type=str, default=None, help="Optional latest time override"
    )
    sp_dispatch.add_argument(
        "--count", type=int, default=100, help="Max results to fetch (default: 100)"
    )
    sp_dispatch.add_argument(
        "--timeout", type=int, default=180, help="Search job timeout in seconds (default: 180)"
    )
    sp_dispatch.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="Output format (default: table)",
    )
    sp_dispatch.add_argument(
        "-o", "--output", type=str, default=None, help="Optional export file path (JSON or CSV)"
    )
    _add_splunk_conn_args(sp_dispatch)

    # 5b. Splunk Enterprise Security (ES) subgroup
    sp_es = splunk_subparsers.add_parser(
        "es",
        help="Splunk Enterprise Security (ES) operations (notables, correlations, threat-intel, assets, identities, risk)",
    )
    es_subparsers = sp_es.add_subparsers(dest="es_subcommand", required=True)

    es_notables = es_subparsers.add_parser("notables", help="List Splunk ES notable events")
    es_notables.add_argument(
        "--earliest", type=str, default="-24h", help="Earliest time bound (default: -24h)"
    )
    es_notables.add_argument(
        "--latest", type=str, default="now", help="Latest time bound (default: now)"
    )
    es_notables.add_argument(
        "--urgency",
        choices=NOTABLE_URGENCIES,
        default=None,
        help="Filter by notable urgency",
    )
    es_notables.add_argument(
        "--status",
        type=str,
        default=None,
        help=f"Filter by notable status ({', '.join(NOTABLE_STATUS_MAP)} or numeric ID 1-5)",
    )
    es_notables.add_argument("--owner", type=str, default=None, help="Filter by notable owner")
    es_notables.add_argument(
        "--rule-name", type=str, default=None, help="Filter by correlation rule name substring"
    )
    es_notables.add_argument(
        "--search-text", type=str, default=None, help="Free-text filter across notable fields"
    )
    es_notables.add_argument(
        "--limit", type=int, default=100, help="Max notable events to return (default: 100)"
    )
    es_notables.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_notables)

    es_update = es_subparsers.add_parser(
        "update-notable", help="Update status, urgency, owner, disposition, or comment on a notable"
    )
    es_update.add_argument("event_id", help="Notable event_id (ruleUID)")
    es_update.add_argument(
        "--status",
        type=str,
        default=None,
        help=f"New status ({', '.join(NOTABLE_STATUS_MAP)} or 1-5)",
    )
    es_update.add_argument(
        "--urgency",
        choices=NOTABLE_URGENCIES,
        default=None,
        help="New urgency level",
    )
    es_update.add_argument("--owner", type=str, default=None, help="New notable owner")
    es_update.add_argument("--disposition", type=str, default=None, help="New notable disposition")
    es_update.add_argument("--comment", type=str, default=None, help="Triage audit comment")
    es_update.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Preview update without modifying Splunk ES",
    )
    _add_splunk_conn_args(es_update)

    es_corr = es_subparsers.add_parser(
        "correlations", help="List Splunk ES correlation searches"
    )
    es_corr.add_argument(
        "--filter",
        type=str,
        default=None,
        help="Case-insensitive filter across name, label, description, or SPL",
    )
    es_corr.add_argument(
        "--count", type=int, default=200, help="Max saved searches to inspect (default: 200)"
    )
    es_corr.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_corr)

    es_toggle = es_subparsers.add_parser(
        "toggle-correlation", help="Enable or disable a Splunk ES correlation search"
    )
    es_toggle.add_argument("name", help="Exact correlation search name")
    es_toggle_group = es_toggle.add_mutually_exclusive_group(required=True)
    es_toggle_group.add_argument(
        "--enable", action="store_true", default=False, help="Enable the correlation search"
    )
    es_toggle_group.add_argument(
        "--disable", action="store_true", default=False, help="Disable the correlation search"
    )
    es_toggle.add_argument(
        "-y",
        "--yes",
        action="store_true",
        default=False,
        help="Skip interactive confirmation prompt",
    )
    es_toggle.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Preview change without modifying Splunk ES",
    )
    _add_splunk_conn_args(es_toggle)

    es_ti = es_subparsers.add_parser(
        "threat-intel", help="Query a Splunk ES Threat Intelligence KV Store collection"
    )
    es_ti.add_argument(
        "collection",
        choices=THREAT_INTEL_COLLECTIONS,
        help="Threat Intelligence KV Store collection name",
    )
    es_ti.add_argument(
        "--limit", type=int, default=100, help="Max entries to return (default: 100)"
    )
    es_ti.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_ti)

    es_assets = es_subparsers.add_parser("assets", help="Lookup Splunk ES assets")
    es_assets.add_argument("--query", type=str, default="", help="Optional asset search query")
    es_assets.add_argument(
        "--limit", type=int, default=50, help="Max assets to return (default: 50)"
    )
    es_assets.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_assets)

    es_identities = es_subparsers.add_parser("identities", help="Lookup Splunk ES identities")
    es_identities.add_argument(
        "--query", type=str, default="", help="Optional identity search query"
    )
    es_identities.add_argument(
        "--limit", type=int, default=50, help="Max identities to return (default: 50)"
    )
    es_identities.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_identities)

    es_risk = es_subparsers.add_parser(
        "risk", help="Query Splunk ES Risk-Based Alerting (RBA) events"
    )
    es_risk.add_argument(
        "--risk-object", type=str, default=None, help="Optional risk_object filter"
    )
    es_risk.add_argument(
        "--earliest", type=str, default="-24h", help="Earliest time bound (default: -24h)"
    )
    es_risk.add_argument(
        "--latest", type=str, default="now", help="Latest time bound (default: now)"
    )
    es_risk.add_argument(
        "--limit", type=int, default=100, help="Max risk events to return (default: 100)"
    )
    es_risk.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_risk)

    es_enrich = es_subparsers.add_parser(
        "enrich",
        help="Enrich Splunk ES notable events or custom SPL results with Recorded Future SOAR v3",
    )
    es_enrich.add_argument(
        "--earliest", type=str, default="-24h", help="Earliest time bound (default: -24h)"
    )
    es_enrich.add_argument(
        "--latest", type=str, default="now", help="Latest time bound (default: now)"
    )
    es_enrich.add_argument(
        "--urgency",
        choices=NOTABLE_URGENCIES,
        default=None,
        help="Filter notables by urgency (ignored when --spl is set)",
    )
    es_enrich.add_argument(
        "--status",
        type=str,
        default=None,
        help=f"Filter notables by status ({', '.join(NOTABLE_STATUS_MAP)} or 1-5; ignored when --spl is set)",
    )
    es_enrich.add_argument(
        "--spl",
        type=str,
        default=None,
        help="Optional custom SPL query to enrich instead of querying `notable`",
    )
    es_enrich.add_argument(
        "--field-map",
        type=str,
        default=None,
        help="Custom Splunk->RF field mapping override (JSON or 'ip=src_ip,dest_ip;domain=dns_query')",
    )
    es_enrich.add_argument(
        "--include-private-ips",
        action="store_true",
        default=False,
        help="Include RFC1918 / non-public IP addresses during IOC extraction",
    )
    es_enrich.add_argument(
        "--write-comments",
        action="store_true",
        default=False,
        help="Post formatted Recorded Future enrichment comments back to Splunk ES notables",
    )
    es_enrich.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Preview notable comment write-backs without mutating Splunk ES",
    )
    es_enrich.add_argument(
        "--limit", type=int, default=100, help="Max events/notables to fetch (default: 100)"
    )
    es_enrich.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="Output format (default: table)",
    )
    es_enrich.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Optional file path to export enriched results (JSON or CSV)",
    )
    _add_splunk_conn_args(es_enrich)

    # 6. Bundle subcommand
    bundle_parser = subparsers.add_parser("bundle", help="Build an air-gapped deployment ZIP bundle")
    bundle_parser.add_argument("--workspace", default=None, help="Workspace directory (default: SOCLENS_HOME or CWD)")
    bundle_parser.add_argument("-o", "--output", default=None, help="Output ZIP file path or directory")
    bundle_parser.add_argument(
        "--wheelhouse",
        action="store_true",
        default=False,
        help=(
            "Include an offline wheelhouse inside the ZIP (reuses local wheelhouse/ offline "
            "when present, or downloads/stages dependencies)"
        ),
    )
    bundle_parser.add_argument(
        "--target-platform",
        default=None,
        help="Target platform tag (e.g. 'all', 'pure', 'win_amd64', 'manylinux2014_x86_64')",
    )
    bundle_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    # 6. TUI subcommand
    tui_parser = subparsers.add_parser("tui", help="Launch the Windows-compatible interactive Textual TUI")
    tui_parser.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Read-only dry-run mode")
    tui_parser.add_argument("--workspace", default=None, help="Workspace directory override")
    tui_parser.add_argument(
        "--image-viewer",
        choices=IMAGE_VIEWER_MODES,
        default=argparse.SUPPRESS,
        help="Default TUI image viewer ('tui' modal or 'os' native OS viewer)",
    )
    tui_parser.add_argument(
        "--os-image-viewer",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Open screenshots in the OS native image viewer by default",
    )
    tui_parser.add_argument(
        "--view",
        choices=UI_VIEW_MODES,
        default=argparse.SUPPRESS,
        help="TUI view mode ('user' default or 'admin' for all tabs)",
    )
    tui_parser.add_argument(
        "--admin",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Launch TUI in Admin view (all tabs visible)",
    )

    # 7. SentinelOne Management API v2.1 subcommands
    s1_parser = subparsers.add_parser(
        "s1",
        help="SentinelOne Management API v2.1 endpoint, threat, exclusion, and blocklist operations",
    )
    s1_parser.add_argument("--url", "--console-url", dest="s1_url", default=None, help="SentinelOne console URL")
    s1_parser.add_argument("--token", "--api-token", dest="s1_token", default=None, help="SentinelOne API token")
    s1_parser.add_argument("--account-id", dest="s1_account_id", default=None, help="Default SentinelOne account ID")
    s1_parser.add_argument("--site-id", dest="s1_site_id", default=None, help="Default SentinelOne site ID")
    s1_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    s1_sub = s1_parser.add_subparsers(dest="s1_command")

    p_s1_status = s1_sub.add_parser("status", help="Check SentinelOne API connectivity and console info")
    p_s1_status.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_agents = s1_sub.add_parser("agents", help="List and filter SentinelOne agents/endpoints")
    p_s1_agents.add_argument("--query", default=None, help="Free-text search query")
    p_s1_agents.add_argument("--computer-name", default=None, help="Filter by hostname substring")
    p_s1_agents.add_argument("--infected", action="store_true", default=None, help="Only infected endpoints")
    p_s1_agents.add_argument("--active", action="store_true", default=None, help="Only active endpoints")
    p_s1_agents.add_argument("--network-status", default=None, help="Filter by network status")
    p_s1_agents.add_argument("--os-type", default=None, choices=sorted(OS_TYPES), help="Filter by OS type")
    p_s1_agents.add_argument("--limit", type=int, default=100, help="Maximum agents to return")
    p_s1_agents.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    for cmd_name, cmd_help in (
        ("isolate", "Network-isolate (disconnect) one or more SentinelOne endpoints"),
        ("reconnect", "Reconnect one or more isolated SentinelOne endpoints"),
        ("reboot", "Restart one or more SentinelOne endpoints"),
    ):
        p_act = s1_sub.add_parser(cmd_name, help=cmd_help)
        p_act.add_argument("agent_ids", nargs="+", help="One or more SentinelOne agent IDs")
        p_act.add_argument("--yes", action="store_true", default=False, help="Approve active response action")
        p_act.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without executing")
        p_act.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_scan = s1_sub.add_parser("scan", help="Initiate or abort a full disk scan on endpoints")
    p_s1_scan.add_argument("agent_ids", nargs="+", help="One or more SentinelOne agent IDs")
    p_s1_scan.add_argument("--abort", action="store_true", default=False, help="Abort an in-progress scan")
    p_s1_scan.add_argument("--yes", action="store_true", default=False, help="Approve active response action")
    p_s1_scan.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without executing")
    p_s1_scan.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_threats = s1_sub.add_parser("threats", help="List SentinelOne threats or fetch a threat timeline")
    p_s1_threats.add_argument("--query", default=None, help="Free-text search query")
    p_s1_threats.add_argument("--status", default=None, choices=sorted(INCIDENT_STATUSES), help="Incident status filter")
    p_s1_threats.add_argument("--verdict", default=None, choices=sorted(ANALYST_VERDICTS), help="Analyst verdict filter")
    p_s1_threats.add_argument("--computer-name", default=None, help="Filter by endpoint hostname")
    p_s1_threats.add_argument("--timeline", default=None, help="Fetch timeline events for a specific threat ID")
    p_s1_threats.add_argument("--limit", type=int, default=100, help="Maximum threats to return")
    p_s1_threats.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_triage = s1_sub.add_parser("triage", help="Update threat verdict, incident status, and/or add a note")
    p_s1_triage.add_argument("threat_ids", nargs="+", help="One or more SentinelOne threat IDs")
    p_s1_triage.add_argument("--verdict", default=None, choices=sorted(ANALYST_VERDICTS), help="Analyst verdict")
    p_s1_triage.add_argument("--status", default=None, choices=sorted(INCIDENT_STATUSES), help="Incident status")
    p_s1_triage.add_argument("--note", default=None, help="Optional analyst note to attach")
    p_s1_triage.add_argument("--yes", action="store_true", default=False, help="Approve threat triage mutation")
    p_s1_triage.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without executing")
    p_s1_triage.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_mitigate = s1_sub.add_parser("mitigate", help="Execute a mitigation action on one or more threats")
    p_s1_mitigate.add_argument("threat_ids", nargs="+", help="One or more SentinelOne threat IDs")
    p_s1_mitigate.add_argument(
        "--action",
        required=True,
        choices=sorted(MITIGATION_ACTIONS),
        help="Mitigation action (kill, quarantine, remediate, rollback, un-quarantine)",
    )
    p_s1_mitigate.add_argument("--yes", action="store_true", default=False, help="Approve threat mitigation action")
    p_s1_mitigate.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without executing")
    p_s1_mitigate.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_excl = s1_sub.add_parser("exclusions", help="List, create, or delete SentinelOne exclusions")
    p_s1_excl.add_argument("--create", action="store_true", default=False, help="Create a new exclusion")
    p_s1_excl.add_argument("--delete", nargs="+", default=None, help="Delete one or more exclusion IDs")
    p_s1_excl.add_argument("--type", dest="exclusion_type", default=None, choices=sorted(EXCLUSION_TYPES), help="Exclusion type")
    p_s1_excl.add_argument("--os-type", default="windows", choices=sorted(OS_TYPES), help="OS type")
    p_s1_excl.add_argument("--value", default=None, help="Exclusion value (path, hash, signer, etc.)")
    p_s1_excl.add_argument("--description", default="", help="Exclusion description")
    p_s1_excl.add_argument("--mode", default="suppress", help="Exclusion mode (default: suppress)")
    p_s1_excl.add_argument("--query", default=None, help="Filter listed exclusions by value substring")
    p_s1_excl.add_argument("--limit", type=int, default=100, help="Maximum exclusions to return")
    p_s1_excl.add_argument("--yes", action="store_true", default=False, help="Approve create/delete mutation")
    p_s1_excl.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without executing")
    p_s1_excl.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_block = s1_sub.add_parser("blocklist", help="List, add, or remove SentinelOne SHA-1 blocklist entries")
    p_s1_block.add_argument("--add", dest="add_hash", default=None, help="SHA-1 hash to add to blocklist")
    p_s1_block.add_argument("--remove", nargs="+", default=None, help="Blocklist entry ID(s) to remove")
    p_s1_block.add_argument("--os-type", default="windows", choices=sorted(OS_TYPES), help="OS type")
    p_s1_block.add_argument("--description", default="", help="Blocklist entry description")
    p_s1_block.add_argument("--query", default=None, help="Filter listed entries by hash substring")
    p_s1_block.add_argument("--limit", type=int, default=100, help="Maximum entries to return")
    p_s1_block.add_argument("--yes", action="store_true", default=False, help="Approve add/remove mutation")
    p_s1_block.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without executing")
    p_s1_block.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_sites = s1_sub.add_parser("sites", help="List SentinelOne sites, accounts, or groups")
    p_s1_sites.add_argument("--accounts", action="store_true", default=False, help="List accounts instead of sites")
    p_s1_sites.add_argument("--groups", action="store_true", default=False, help="List groups instead of sites")
    p_s1_sites.add_argument("--query", default=None, help="Search query")
    p_s1_sites.add_argument("--limit", type=int, default=100, help="Maximum items to return")
    p_s1_sites.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_act = s1_sub.add_parser("activities", help="List SentinelOne audit/activity logs")
    p_s1_act.add_argument("--agent-id", default=None, help="Filter by agent ID")
    p_s1_act.add_argument("--threat-id", default=None, help="Filter by threat ID")
    p_s1_act.add_argument("--query", default=None, help="Filter by description substring")
    p_s1_act.add_argument("--limit", type=int, default=100, help="Maximum activities to return")
    p_s1_act.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    # 7. Local LLM subcommand
    llm_parser = subparsers.add_parser(
        "llm",
        help="Interact with a local LLM (Ollama or OpenAI-compatible server)",
    )
    llm_subparsers = llm_parser.add_subparsers(dest="llm_subcommand", metavar="SUBCOMMAND")

    def _add_llm_conn_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--provider",
            choices=["ollama", "openai"],
            default=None,
            help="Local LLM provider (default: RF_LLM_PROVIDER or ollama)",
        )
        p.add_argument(
            "--base-url",
            default=None,
            help="Local LLM base URL (default: RF_LLM_BASE_URL or provider default)",
        )
        p.add_argument("--api-key", default=None, help="Optional API key for OpenAI-compatible servers")
        p.add_argument("--timeout", type=float, default=None, help="HTTP timeout in seconds")
        p.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    llm_status = llm_subparsers.add_parser("status", help="Check local LLM connectivity and available models")
    _add_llm_conn_args(llm_status)

    llm_models = llm_subparsers.add_parser("models", help="List available models on the local LLM server")
    _add_llm_conn_args(llm_models)

    llm_chat = llm_subparsers.add_parser("chat", help="Send a prompt or file to the local LLM")
    _add_llm_conn_args(llm_chat)
    llm_chat.add_argument("--prompt", default=None, help="User prompt text")
    llm_chat.add_argument("--system", default=None, help="Optional system prompt override")
    llm_chat.add_argument("--model", default=None, help="Model name (default: RF_LLM_MODEL)")
    llm_chat.add_argument(
        "--template",
        choices=list(SOC_PROMPT_TEMPLATES.keys()),
        default="freeform",
        help="SOC prompt template (default: freeform)",
    )
    llm_chat.add_argument("--file", default=None, help="Optional file path to include as analysis content")
    llm_chat.add_argument("--temperature", type=float, default=None, help="Sampling temperature (0.0-2.0)")
    llm_chat.add_argument("--max-tokens", type=int, default=None, help="Optional max output tokens")

    llm_sigma = llm_subparsers.add_parser(
        "explain-sigma",
        help="Explain a Sigma rule from a YAML file or cached RF rule ID using the local LLM",
    )
    _add_llm_conn_args(llm_sigma)
    llm_sigma.add_argument("--file", default=None, help="Path to a Sigma YAML or SPL rule file")
    llm_sigma.add_argument("--rule-id", default=None, help="Cached Sigma rule ID to look up and explain")
    llm_sigma.add_argument("--model", default=None, help="Model name (default: RF_LLM_MODEL)")
    llm_sigma.add_argument("--workspace", default=None, help="Workspace directory for cached Sigma rules")

    # 8. Per-user settings & profile management subcommands
    settings_parser = subparsers.add_parser(
        "settings",
        help="Manage per-user saved credentials, tool settings, and named profiles",
    )
    settings_parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="JSON output",
    )
    settings_sub = settings_parser.add_subparsers(dest="settings_command")

    p_set_path = settings_sub.add_parser("path", help="Show the resolved per-user settings file path and status")
    p_set_path.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_show = settings_sub.add_parser("show", help="Display effective settings and value sources")
    p_set_show.add_argument("--reveal", action="store_true", default=False, help="Reveal secret tokens/passwords")
    p_set_show.add_argument("--profile", default=None, help="Inspect a specific settings profile")
    p_set_show.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_set = settings_sub.add_parser("set", help="Save a credential or setting to your per-user profile")
    p_set_set.add_argument("key", help="Setting key or env var alias (e.g. rf_api_token or RF_API_TOKEN)")
    p_set_set.add_argument("value", help="Value to persist")
    p_set_set.add_argument("--profile", default=None, help="Target settings profile (default: active)")
    p_set_set.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without saving")
    p_set_set.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_unset = settings_sub.add_parser("unset", help="Remove a saved setting from a profile")
    p_set_unset.add_argument("key", help="Setting key or env var alias to remove")
    p_set_unset.add_argument("--profile", default=None, help="Target settings profile (default: active)")
    p_set_unset.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without saving")
    p_set_unset.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_imp = settings_sub.add_parser("import-env", help="Import currently set environment variables into saved settings")
    p_set_imp.add_argument("--profile", default=None, help="Target settings profile (default: active)")
    p_set_imp.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without saving")
    p_set_imp.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_profs = settings_sub.add_parser("profiles", help="List available settings profiles")
    p_set_profs.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_use = settings_sub.add_parser("use", help="Switch the active settings profile")
    p_set_use.add_argument("profile", help="Profile name to activate")
    p_set_use.add_argument(
        "--no-create",
        action="store_true",
        default=False,
        help="Fail if the profile does not already exist",
    )
    p_set_use.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without saving")
    p_set_use.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_del = settings_sub.add_parser("delete-profile", help="Delete a non-default settings profile")
    p_set_del.add_argument("profile", help="Profile name to delete")
    p_set_del.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without saving")
    p_set_del.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_reset = settings_sub.add_parser("reset", help="Clear all saved values in a settings profile")
    p_set_reset.add_argument("--profile", default=None, help="Target profile to clear (default: active)")
    p_set_reset.add_argument("--yes", action="store_true", default=False, help="Approve clearing saved profile values")
    p_set_reset.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without modifying")
    p_set_reset.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    _attach_ssl_flags_recursive(parser)
    return parser


def _attach_ssl_flags_recursive(
    parser: argparse.ArgumentParser,
    _seen: set[int] | None = None,
) -> None:
    """Attach SSL proxy flags to all subparsers so flags work before or after subcommands."""
    if _seen is None:
        _seen = {id(parser)}
    for action in getattr(parser, "_actions", ()):
        choices = getattr(action, "choices", None)
        if not isinstance(choices, dict):
            continue
        for subparser in choices.values():
            if not isinstance(subparser, argparse.ArgumentParser):
                continue
            sub_id = id(subparser)
            if sub_id in _seen:
                continue
            _seen.add(sub_id)
            subparser.add_argument(
                "-k",
                "--insecure",
                "--no-verify-ssl",
                dest="insecure",
                action="store_true",
                default=argparse.SUPPRESS,
                help=argparse.SUPPRESS,
            )
            subparser.add_argument(
                "--ca-bundle",
                dest="ca_bundle",
                default=argparse.SUPPRESS,
                help=argparse.SUPPRESS,
            )
            _attach_ssl_flags_recursive(subparser, _seen)


def _handle_watchlist(
    args: argparse.Namespace,
    client: RecordedFutureClient,
    *,
    global_dry_run: bool,
    use_json: bool,
) -> int:
    sub = args.subcommand or "interactive"
    if sub == "interactive":
        run_unified_tui(client, dry_run=global_dry_run, initial_tab="tab-watchlists")
        return 0

    if sub == "list":
        watchlists = client.get_watchlists(
            list_types=args.type,
            name=args.name,
            limit=args.limit,
        )
        if args.watch_list_only:
            watchlists = [
                lst
                for lst in watchlists
                if str(lst.get("name", "")).strip().lower().endswith("watch list")
            ]
        if use_json:
            _emit_json(watchlists)
            return 0
        if not watchlists:
            print("No matching Recorded Future lists found.")
            return 0
        print(f"Successfully retrieved {len(watchlists)} list(s):\n")
        print(f"{'ID':<24} | {'Type':<14} | {'Name'}")
        print("-" * 72)
        for lst in watchlists:
            print(f"{str(lst.get('id', 'N/A')):<24} | {str(lst.get('type', 'N/A')):<14} | {lst.get('name', 'N/A')}")
        return 0

    if sub == "create":
        dry_run_val, auto_warn = _resolve_write_dry_run(args, global_dry_run)
        if dry_run_val:
            if auto_warn and not use_json:
                print("[!] Warning: SOCLENS_AUTO_APPROVE is not set. Running in DRY RUN mode.")
            payload = {"dry_run": True, "action": "create", "name": args.name, "type": args.type}
            if use_json:
                _emit_json(payload)
            else:
                print(f"[DRY-RUN] Would create list '{args.name}' (type={args.type})")
            return 0
        created = client.create_list(args.name, args.type)
        if use_json:
            _emit_json(created)
        else:
            print(f"[+] Created list '{created.get('name', args.name)}' (ID: {created.get('id')}, type: {created.get('type', args.type)})")
        return 0

    if sub == "info":
        info = client.get_list_info(args.list_id)
        if use_json:
            _emit_json(info)
        else:
            print(f"List ID: {info.get('id', args.list_id)}")
            for k, v in info.items():
                if k != "id":
                    print(f"  {k}: {v}")
        return 0

    if sub == "status":
        status = client.get_list_status(args.list_id)
        if use_json:
            _emit_json(status)
        else:
            print(f"List Status ({args.list_id}):")
            for k, v in status.items():
                print(f"  {k}: {v}")
        return 0

    if sub == "entities":
        entries = client.get_watchlist_entities(args.list_id)
        total_count = len(entries)
        filter_query = getattr(args, "filter_query", None)
        if filter_query:
            entries = filter_watchlist_entities(entries, str(filter_query))
        sort_by = str(getattr(args, "sort", "none") or "none")
        if sort_by != "none":
            entries = sort_watchlist_entities(
                entries,
                sort_by=sort_by,
                descending=bool(getattr(args, "descending", False)),
            )
        if use_json:
            _emit_json(entries)
            return 0
        if not entries:
            if total_count > 0 and filter_query:
                print(
                    f"No entities matched filter '{filter_query}' in watchlist '{args.list_id}' "
                    f"({total_count} total)."
                )
            else:
                print(f"Watchlist '{args.list_id}' is empty.")
            return 0
        count_note = (
            f"{len(entries)} of {total_count}"
            if filter_query and len(entries) != total_count
            else f"{len(entries)}"
        )
        print(f"Successfully retrieved {count_note} entity/entities from '{args.list_id}':\n")
        print(f"{'Entity ID':<24} | {'Type':<18} | {'Status':<10} | {'Name':<25} | {'Context'}")
        print("-" * 96)
        for entry in entries:
            entity = entry.get("entity", {}) or {}
            status = entry.get("status", "N/A")
            context_str = format_context(entry.get("context"))
            print(
                f"{str(entity.get('id', 'N/A')):<24} | {str(entity.get('type', 'N/A')):<18} | "
                f"{str(status):<10} | {str(entity.get('name', 'N/A')):<25} | {context_str}"
            )
        return 0

    if sub == "text-entries":
        items = client.get_text_entries(args.list_id)
        if use_json:
            _emit_json(items)
        else:
            for item in items:
                print(item)
        return 0

    if sub == "tags":
        tagged = client.get_entities_with_tags(args.list_id)
        if use_json:
            _emit_json(tagged)
        else:
            for row in tagged:
                ent = row.get("entity", {}) or {}
                tags = [str(t.get("name", t)) if isinstance(t, dict) else str(t) for t in (row.get("tags") or [])]
                print(f"{ent.get('id', 'N/A')} ({ent.get('name', 'N/A')}): {', '.join(tags) or 'none'}")
        return 0

    if sub == "replace-tags":
        tags_list = _split_csv_arg(args.tags)
        dry_run_val, auto_warn = _resolve_write_dry_run(args, global_dry_run)
        if dry_run_val:
            if auto_warn and not use_json:
                print("[!] Warning: SOCLENS_AUTO_APPROVE is not set. Running in DRY RUN mode.")
            payload = {"dry_run": True, "list_id": args.list_id, "entity": args.entity, "tags": tags_list}
            if use_json:
                _emit_json(payload)
            else:
                print(f"[DRY-RUN] Would replace tags on '{args.entity}' in '{args.list_id}': {tags_list}")
            return 0
        res = client.replace_entity_tags(args.list_id, args.entity, tags_list, entity_type=args.entity_type)
        if use_json:
            _emit_json(res)
        else:
            print(f"[+] Updated tags on '{args.entity}' in '{args.list_id}'.")
        return 0

    if sub == "add":
        dry_run_val, auto_warn = _resolve_write_dry_run(args, global_dry_run)
        if dry_run_val:
            if auto_warn and not use_json:
                print("[!] Warning: SOCLENS_AUTO_APPROVE is not set. Running in DRY RUN mode: Would have added entity.")
            if use_json:
                _emit_json(
                    {
                        "dry_run": True,
                        "action": "add",
                        "list_id": args.list_id,
                        "entity_type": args.entity_type,
                        "name": args.name,
                    }
                )
            else:
                print(
                    f"[DRY-RUN] Would have added entity '{args.name}' of type "
                    f"'{args.entity_type}' to watchlist '{args.list_id}'"
                )
            return 0

        add_kwargs: dict[str, Any] = {}
        if args.annotation is not None:
            add_kwargs["context"] = {"annotation": args.annotation}
        if args.resolve:
            add_kwargs["resolve"] = True
        if args.is_id:
            add_kwargs["is_id"] = True

        res = client.add_entity(args.list_id, args.entity_type, args.name, **add_kwargs)
        if not _mutation_succeeded(res):
            print(f"[-] Failed to add entity to watchlist '{args.list_id}'", file=sys.stderr)
            return 1
        if use_json:
            _emit_json({"list_id": args.list_id, "entity_type": args.entity_type, "name": args.name, "response": res})
        else:
            print(f"[+] Successfully added entity '{args.name}' to watchlist '{args.list_id}'")
        return 0

    if sub == "remove":
        dry_run_val, auto_warn = _resolve_write_dry_run(args, global_dry_run)
        target_desc = f"{args.entity_id}:{args.entity_value}" if args.entity_value else args.entity_id
        if dry_run_val:
            if auto_warn and not use_json:
                print("[!] Warning: SOCLENS_AUTO_APPROVE is not set. Running in DRY RUN mode: Would have removed entity.")
            if use_json:
                _emit_json({"dry_run": True, "action": "remove", "list_id": args.list_id, "target": target_desc})
            else:
                print(f"[DRY-RUN] Would have removed entity '{target_desc}' from watchlist '{args.list_id}'")
            return 0

        rem_kwargs: dict[str, Any] = {}
        if getattr(args, "is_id", False):
            rem_kwargs["is_id"] = True
        if getattr(args, "no_resolve", False):
            rem_kwargs["resolve"] = False

        if args.entity_value is not None:
            res = client.remove_entity(
                args.list_id,
                args.entity_value,
                entity_type=args.entity_id,
                **rem_kwargs,
            )
        else:
            res = client.remove_entity(args.list_id, args.entity_id, **rem_kwargs)
        if not _mutation_succeeded(res):
            print(f"[-] Failed to remove entity from watchlist '{args.list_id}'", file=sys.stderr)
            return 1
        if use_json:
            _emit_json({"list_id": args.list_id, "target": target_desc, "response": res})
        elif isinstance(res, dict) and str(res.get("result", "")).strip().lower() == "unchanged":
            print(
                f"[*] Entity '{target_desc}' was not present in watchlist '{args.list_id}' (unchanged)"
            )
        else:
            print(f"[+] Successfully removed entity '{target_desc}' from watchlist '{args.list_id}'")
        return 0

    if sub == "sync":
        dry_run_val, auto_warn = _resolve_write_dry_run(args, global_dry_run)
        if auto_warn and not use_json:
            print("[!] Warning: SOCLENS_AUTO_APPROVE is not set. Bypassing write operations and running in DRY RUN mode.")
        ok = _run_quiet_if_json(
            use_json,
            execute_delta_sync,
            client,
            args.list_id,
            args.csv_path,
            args.type,
            dry_run=dry_run_val,
            interactive=False,
            force_remove=args.force_remove,
        )
        if not ok:
            return 1
        if use_json:
            _emit_json({"status": "ok", "list_id": args.list_id, "csv_path": args.csv_path, "dry_run": dry_run_val})
        return 0

    if sub == "export":
        dest_path = args.output_flag or args.output_path
        if not dest_path:
            print("[-] Output path is required for watchlist export.", file=sys.stderr)
            return 1
        ok = _run_quiet_if_json(
            use_json,
            export_watchlist,
            client,
            args.list_id,
            dest_path,
            file_format=args.format,
        )
        if not ok:
            return 1
        if use_json:
            _emit_json({"status": "ok", "list_id": args.list_id, "output_path": str(dest_path), "format": args.format})
        return 0

    if sub == "validate-liveness":
        dry_run_val, _ = _resolve_write_dry_run(args, global_dry_run)
        ok = _run_quiet_if_json(
            use_json,
            validate_domains_live_status,
            client,
            args.list_id,
            interactive=args.interactive,
            dry_run=dry_run_val,
        )
        if not ok:
            return 1
        if use_json:
            _emit_json({"status": "ok", "list_id": args.list_id, "dry_run": dry_run_val})
        return 0

    if sub in ("sync-logos", "validate-logos"):
        if sub == "sync-logos":
            if args.interval < 0:
                print("[-] --interval must be >= 0.", file=sys.stderr)
                return 1
            if args.max_runs is not None and args.max_runs < 1:
                print("[-] --max-runs must be >= 1.", file=sys.stderr)
                return 1
            if args.grace_failures < 1:
                print("[-] --grace-failures must be >= 1.", file=sys.stderr)
                return 1

        if args.domains_file:
            df_path = Path(args.domains_file).expanduser()
            if not df_path.is_file():
                print(f"[-] Domains file not found: {df_path}", file=sys.stderr)
                return 1

        domains: list[str] = []
        if args.source_list_id:
            domains = get_domains_from_watchlist(client, args.source_list_id)
        elif args.domains_file:
            domains = load_domains_file(args.domains_file)
        elif args.domains:
            domains = [d.strip() for d in args.domains.split(",") if d.strip()]

        if not domains:
            print("[-] No valid domains found from --domains, --domains-file, or --source-list-id.", file=sys.stderr)
            return 1

        extra_hashes = [h.strip() for h in args.ignore_hashes.split(",") if h.strip()] if args.ignore_hashes else None
        ignore_hashes_file = args.ignore_hashes_file
        raw_out_locs = args.output_locations
        output_locations_file = (
            raw_out_locs.strip() if isinstance(raw_out_locs, str) and raw_out_locs.strip() else None
        )

        if sub == "sync-logos":
            dry_run_val, auto_warn = _resolve_write_dry_run(args, global_dry_run)
            if auto_warn and not use_json:
                print("[!] Warning: SOCLENS_AUTO_APPROVE is not set. Bypassing write operations and running in DRY RUN mode.")

            if args.watch:
                summary = _run_quiet_if_json(
                    use_json,
                    run_continuous_brand_sync,
                    client,
                    args.list_id,
                    domains=domains if not args.source_list_id and not args.domains_file else None,
                    source_list_id=args.source_list_id,
                    domains_file=args.domains_file,
                    dry_run=dry_run_val,
                    output_locations_file=output_locations_file,
                    ignore_hashes_file=ignore_hashes_file,
                    extra_hashes=extra_hashes,
                    interval_seconds=args.interval,
                    max_runs=args.max_runs,
                    state_file=args.state_file,
                    lock_file=args.lock_file,
                    state_grace_failures=args.grace_failures,
                    workspace_dir=get_workspace_dir(),
                )
                if use_json:
                    _emit_json(summary)
                else:
                    print(
                        f"[*] Continuous brand sync finished: attempted={summary['runs_attempted']}, "
                        f"succeeded={summary['runs_succeeded']}, failed={summary['runs_failed']}"
                    )
                return 0 if summary.get("runs_failed", 0) == 0 else 1

            sync_kwargs: dict[str, Any] = {
                "dry_run": dry_run_val,
                "output_locations_file": output_locations_file,
                "ignore_hashes_file": ignore_hashes_file,
                "extra_hashes": extra_hashes,
            }
            if args.state_file is not None:
                sync_kwargs["state_file"] = args.state_file
            if args.grace_failures != 3:
                sync_kwargs["state_grace_failures"] = args.grace_failures

            ok = _run_quiet_if_json(
                use_json,
                execute_domain_brand_sync,
                client,
                args.list_id,
                domains,
                **sync_kwargs,
            )
            if not ok:
                return 1
            if use_json:
                _emit_json(
                    {
                        "status": "ok",
                        "list_id": args.list_id,
                        "domains": domains,
                        "dry_run": dry_run_val,
                        "output_locations": output_locations_file,
                    }
                )
            return 0

        ok = _run_quiet_if_json(
            use_json,
            validate_domain_brand_sync,
            client,
            args.list_id,
            domains,
            output_locations_file=output_locations_file,
            ignore_hashes_file=ignore_hashes_file,
            extra_hashes=extra_hashes,
        )
        if not ok:
            return 1
        if use_json:
            _emit_json(
                {
                    "status": "ok",
                    "list_id": args.list_id,
                    "domains": domains,
                    "dry_run": True,
                    "output_locations": output_locations_file,
                }
            )
        return 0

    if sub == "brand-issues":
        if args.grace_failures < 1:
            print("[-] --grace-failures must be >= 1.", file=sys.stderr)
            return 1
        ws_dir = get_workspace_dir()
        state_path = resolve_state_path(args.state_file, ws_dir)
        state = load_brand_sync_state(state_path)
        wl_domains = (
            _run_quiet_if_json(use_json, get_domains_from_watchlist, client, args.source_list_id)
            if args.source_list_id
            else None
        )
        existing_entries = (
            client.get_watchlist_entities(args.list_id) if args.list_id else None
        )
        report = analyze_brand_sync_issues(
            state=state,
            watchlist_domains=wl_domains,
            existing_entries=existing_entries,
            grace_failures=args.grace_failures,
        )
        filtered = filter_brand_issues(
            report.issues,
            category=args.category,
            query=args.filter_query or "",
        )
        ordered = sort_brand_issues(
            filtered,
            sort_by=args.sort,
            descending=bool(args.desc),
        )
        if use_json:
            _emit_json(
                {
                    "state_file": str(state_path),
                    "category": args.category,
                    "sort": args.sort,
                    "descending": bool(args.desc),
                    "filter": args.filter_query,
                    "filtered_count": len(ordered),
                    "report": report.to_dict(),
                    "issues": [issue.to_dict() for issue in ordered],
                }
            )
            return 0

        cat_label = BRAND_SYNC_ISSUE_LABELS.get(args.category, args.category)
        print(
            f"[*] Brand Sync Health ({state_path}): total={report.total_domains} | "
            f"healthy={report.healthy_domains} | missing_hashes={report.missing_hashes_count} "
            f"(silent={report.silent_zero_hashes_count}, domain_err={report.domain_errors_count}) | "
            f"img_err={report.image_errors_count} | grace_risk={report.failing_grace_count} | "
            f"shared_hashes={report.duplicate_hashes_count}"
        )
        print(
            f"[*] Dashboard '{cat_label}' ({len(ordered)} issue(s), sort={args.sort}, "
            f"order={'desc' if args.desc else 'asc'}):"
        )
        if not ordered:
            print("    (no matching issues)")
            return 0
        print(f"    {'DOMAIN / KEY':<34} {'STATUS':<22} {'HASHES':>6} {'FAILS':>5}  DETAIL")
        print(f"    {'-' * 34} {'-' * 22} {'-' * 6} {'-' * 5}  {'-' * 40}")
        for issue in ordered:
            print(
                f"    {issue.domain:<34} {issue.status:<22} "
                f"{issue.hash_count:>6} {issue.consecutive_failures:>5}  {issue.reason}"
            )
        return 0

    print(f"[-] Unknown watchlist subcommand: {sub}", file=sys.stderr)
    return 1


def _handle_rf(args: argparse.Namespace, client: RecordedFutureClient, *, use_json: bool) -> int:
    sub = args.rf_subcommand
    if not sub:
        print("Specify an `rf` subcommand (run `soclens rf --help` for options).", file=sys.stderr)
        return 1

    if sub == "apis":
        if use_json:
            _emit_json(list(_RF_API_CATALOG))
            return 0
        print(f"{'API Family':<32} | {'Auth':<20} | {'Base Path'}")
        print("-" * 88)
        for item in _RF_API_CATALOG:
            print(f"{item['family']:<32} | {item['auth']:<20} | {item['base_path']}")
        return 0

    if sub in ("entity-match", "match"):
        types = _split_csv_arg(args.types) or None
        matches = client.entity_match(args.name, types=types, limit=args.limit)
        if use_json:
            _emit_json(matches)
            return 0
        if not matches:
            print(f"No entities matched '{args.name}'.")
            return 0
        for m in matches:
            print(f"{m.get('id', 'N/A'):<28} | {m.get('type', 'N/A'):<16} | {m.get('name', 'N/A')}")
        return 0

    if sub == "entity-lookup":
        data = client.entity_lookup(args.entity_id)
        _emit_json(data)
        return 0

    if sub == "lookup":
        fields = _split_csv_arg(args.fields) or None
        data = client.v2_lookup(args.entity_type, args.entity_id, fields=fields, metadata=args.metadata)
        if use_json:
            _emit_json(data)
        else:
            ent = (data.get("data") or {}).get("entity") or {}
            risk = (data.get("data") or {}).get("risk") or {}
            print(
                f"Entity: {ent.get('name', args.entity_id)} ({ent.get('id', 'N/A')}) | "
                f"Risk Score: {risk.get('score', 'N/A')} ({risk.get('riskString', 'N/A')})"
            )
            if not risk and data:
                _emit_json(data)
        return 0

    if sub == "company":
        fields = _split_csv_arg(args.fields) or None
        data = client.v2_company_by_domain(args.domain, fields=fields)
        _emit_json(data)
        return 0

    if sub == "search":
        params: dict[str, Any] = {"limit": args.limit}
        if args.freetext:
            params["freetext"] = args.freetext
        if args.risk_score:
            params["riskScore"] = args.risk_score
        if args.fields:
            params["fields"] = _split_csv_arg(args.fields)
        data = client.v2_search(args.entity_type, **params)
        _emit_json(data)
        return 0

    if sub == "risklist":
        if args.stat:
            headers = client.v2_stat_risklist(args.entity_type, fmt=args.format, list_name=args.list_name)
            _emit_json(headers)
            return 0
        content = client.v2_risklist(args.entity_type, fmt=args.format, list_name=args.list_name)
        if args.output:
            out_path = Path(args.output).expanduser()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                out_path.write_bytes(content)
            elif isinstance(content, dict):
                out_path.write_text(json.dumps(content, indent=2), encoding="utf-8")
            else:
                out_path.write_text(str(content), encoding="utf-8")
            if use_json:
                _emit_json({"output_path": str(out_path), "entity_type": args.entity_type})
            else:
                print(f"[+] Risk list written to {out_path}")
            return 0
        if isinstance(content, dict):
            _emit_json(content)
        elif isinstance(content, bytes):
            sys.stdout.buffer.write(content)
        else:
            print(content)
        return 0

    if sub == "riskrules":
        data = client.v2_riskrules(args.entity_type)
        _emit_json(data)
        return 0

    if sub == "enrich":
        iocs = _collect_iocs_from_args(args)
        data = client.soar_enrich(iocs, metadata=args.metadata)
        if use_json:
            _emit_json(data)
        else:
            results = (data.get("data") or {}).get("results") or []
            if not results:
                _emit_json(data)
            else:
                for item in results:
                    ent = item.get("entity") or {}
                    risk = item.get("risk") or {}
                    print(f"{ent.get('name', ent.get('id', 'N/A')):<32} | Score: {risk.get('score', 'N/A')}")
        return 0

    if sub == "triage":
        iocs = _collect_iocs_from_args(args)
        data = client.soar_triage(args.context, iocs, threshold=args.threshold)
        _emit_json(data)
        return 0

    if sub == "contexts":
        data = client.soar_get_contexts()
        _emit_json(data)
        return 0

    if sub == "alerts":
        if args.alert_id:
            data = client.get_alert_v3(args.alert_id)
        else:
            data = client.search_alerts_v3(
                triggered=args.triggered,
                status_in_portal=args.status,
                alert_rule=args.rule,
                freetext=args.freetext,
                limit=args.limit,
                offset=args.offset,
            )
        _emit_json(data)
        return 0

    if sub == "playbook-alerts":
        if args.alert_id:
            data = client.get_playbook_alert(args.category, args.alert_id)
        else:
            cats = _split_csv_arg(args.categories) or None
            statuses = _split_csv_arg(args.statuses) or None
            data = client.search_playbook_alerts(categories=cats, statuses=statuses, limit=args.limit)
        _emit_json(data)
        return 0

    if sub == "cases":
        if args.case_id:
            data = client.lookup_cases([args.case_id])
        else:
            statuses = _split_csv_arg(args.statuses) or None
            priorities = _split_csv_arg(args.priorities) or None
            data = client.search_cases(statuses=statuses, priorities=priorities, limit=args.limit)
        _emit_json(data)
        return 0

    if sub == "sandbox":
        if args.sample_id:
            data = (
                client.sandbox_get_overview(args.sample_id)
                if args.overview
                else client.sandbox_get_sample(args.sample_id)
            )
        elif args.query:
            data = client.sandbox_search(args.query, limit=args.limit)
        else:
            print("[-] Provide --query or --sample-id for `rf sandbox`.", file=sys.stderr)
            return 1
        _emit_json(data)
        return 0

    if sub == "fields":
        data = client.v2_fields(args.entity_type)
        _emit_json(data)
        return 0

    if sub == "extension":
        if args.list or not (args.entity_type and args.entity_id and args.extension):
            if use_json:
                _emit_json(V2_EXTENSION_CATALOG)
            else:
                for etype, ext_names in V2_EXTENSION_CATALOG.items():
                    print(f"{etype:<14}: {', '.join(ext_names)}")
            return 0 if args.list else 1
        data = client.v2_lookup_extension(
            args.entity_type,
            args.entity_id,
            args.extension,
            metadata=args.metadata,
        )
        _emit_json(data)
        return 0

    print(f"[-] Unknown rf subcommand: {sub}", file=sys.stderr)
    return 1


def _write_binary_output(data: bytes, output_path: str | None, *, default_label: str) -> None:
    if output_path:
        dest = Path(output_path).expanduser().resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        print(f"[+] Wrote {len(data)} bytes ({default_label}) to {dest}")
        return
    try:
        print(data.decode("utf-8"))
    except UnicodeDecodeError:
        print(f"[*] Received {len(data)} binary bytes ({default_label}); pass -o/--output to save.")


def _handle_research(args: argparse.Namespace, client: RecordedFutureClient, *, use_json: bool) -> int:
    sub = args.research_subcommand
    if not sub:
        print("Specify a `research` subcommand (run `soclens research --help` for options).", file=sys.stderr)
        return 1

    if sub in ("investigate", "dossier"):
        mods = _split_csv_arg(args.modules) or None
        exts = _split_csv_arg(args.extensions) or None
        dossier = research_target(
            client,
            args.target,
            explicit_type=args.type,
            modules=mods,
            deep=bool(args.deep),
            extensions=exts,
            links_scope=args.links_scope,
            links_timeframe=args.links_timeframe,
            limit=args.limit,
        )
        if args.output:
            fmt = args.format or ("json" if str(args.output).lower().endswith(".json") else "markdown")
            written = (
                export_dossier_json(dossier, args.output)
                if fmt == "json"
                else export_dossier_markdown(dossier, args.output)
            )
            if not use_json:
                print(f"[+] Dossier written to {written}")
        if use_json:
            _emit_json(dossier.to_dict())
        else:
            print(render_dossier_markdown(dossier))
        return 0

    if sub == "capabilities":
        rows = probe_api_capabilities(client)
        if use_json:
            _emit_json(rows)
            return 0
        print(f"{'API Family':<34} | {'Status':<14} | {'HTTP':<4} | {'ms':>7} | {'Detail'}")
        print("-" * 100)
        for row in rows:
            code = str(row.get("status_code") or "-")
            print(
                f"{str(row.get('family', '')):<34} | {str(row.get('status', '')):<14} | "
                f"{code:<4} | {float(row.get('elapsed_ms', 0.0)):>7.1f} | {row.get('detail', '')}"
            )
        return 0

    if sub == "links":
        if args.metadata == "entities":
            _emit_json(client.links_metadata_entities())
            return 0
        if args.metadata == "events":
            _emit_json(client.links_metadata_events())
            return 0
        if args.metadata == "sections":
            _emit_json(client.links_metadata_sections())
            return 0
        if not args.entities:
            print("[-] Provide at least one entity ID or use --metadata for `research links`.", file=sys.stderr)
            return 1
        data = client.links_search(
            list(args.entities),
            sections=_split_csv_arg(args.sections) or None,
            entity_types=_split_csv_arg(args.types) or None,
            sources=_split_csv_arg(args.sources) or None,
            timeframe=args.timeframe,
            connected_entities=_split_csv_arg(args.connected) or None,
            search_scope=args.scope,
            per_entity_type=args.per_type,
        )
        _emit_json(data)
        return 0

    if sub == "notes":
        if args.topics:
            if use_json:
                _emit_json(ANALYST_NOTE_TOPICS)
            else:
                for topic_name, topic_id in sorted(ANALYST_NOTE_TOPICS.items()):
                    print(f"{topic_id:<10} | {topic_name}")
            return 0
        if args.note_id and args.export:
            blob = client.export_analyst_note(args.note_id, fmt=args.export)
            if use_json:
                _emit_json({"note_id": args.note_id, "format": args.export, "bytes": len(blob)})
            else:
                _write_binary_output(blob, args.output, default_label=f"note {args.export}")
            return 0
        if args.note_id and args.attachment:
            blob = client.get_analyst_note_attachment(args.note_id)
            if use_json:
                _emit_json({"note_id": args.note_id, "bytes": len(blob)})
            else:
                _write_binary_output(blob, args.output, default_label="note attachment")
            return 0
        if args.note_id:
            data = client.lookup_analyst_note(args.note_id, serialization=args.serialization)
            _emit_json(data)
            return 0
        data = client.search_analyst_notes(
            entity=args.entity,
            topic=args.topic,
            title=args.title,
            label=args.label,
            source=args.source,
            published=args.published,
            serialization=args.serialization,
            enterprise_only=bool(args.enterprise_only),
            limit=args.limit,
        )
        _emit_json(data)
        return 0

    if sub == "actors":
        if args.threat_maps:
            _emit_json(client.get_threat_maps())
            return 0
        if args.categories:
            _emit_json(client.get_threat_actor_categories())
            return 0
        if args.map:
            _emit_json(client.get_threat_actor_map(org_id=args.org_id))
            return 0
        _emit_json(client.search_threat_actors(name=args.query, limit=args.limit))
        return 0

    if sub == "malware":
        if args.categories:
            _emit_json(client.get_malware_categories())
            return 0
        if args.map:
            _emit_json(client.get_malware_threat_map(org_id=args.org_id))
            return 0
        if args.v2_search:
            _emit_json(client.v2_search("malware", freetext=args.v2_search, limit=args.limit))
            return 0
        if args.v2_lookup:
            _emit_json(client.v2_lookup("malware", args.v2_lookup))
            return 0
        if args.reports_sha256:
            q_val = args.query or f"static.sha256 == '{args.reports_sha256}'"
            _emit_json(
                client.malware_intel_sandbox_reports(
                    args.reports_sha256,
                    q_val,
                    start_date=args.start_date,
                    end_date=args.end_date,
                    limit=args.limit,
                )
            )
            return 0
        if args.iocs:
            iocs = _collect_iocs_from_args(args)
            _emit_json(
                client.malware_intel_query_iocs(
                    sha256_list=iocs.get("hash"),
                    ip_list=iocs.get("ip"),
                    domain_list=iocs.get("domain"),
                    url_list=iocs.get("url"),
                    field=args.field,
                    operator=args.operator,
                    start_date=args.start_date,
                    end_date=args.end_date,
                )
            )
            return 0
        if args.query:
            fn = client.malware_intel_query_nl if args.nl else client.malware_intel_query
            _emit_json(
                fn(
                    args.query,
                    field=args.field,
                    start_date=args.start_date,
                    end_date=args.end_date,
                )
            )
            return 0
        print("[-] Specify a query or flag for `research malware` (see --help).", file=sys.stderr)
        return 1

    if sub == "risk":
        if args.company and args.rule:
            _emit_json(
                client.get_active_company_risk_rule(
                    args.company, args.rule, limit=args.limit
                )
            )
            return 0
        if args.history:
            _emit_json(
                client.search_risk_history(
                    list(args.history),
                    start_date=args.from_date,
                    end_date=args.to_date,
                )
            )
            return 0
        print("[-] Provide --history <entities...> or --company + --rule for `research risk`.", file=sys.stderr)
        return 1

    if sub == "identity":
        if args.detections:
            _emit_json(
                client.identity_detections(
                    domains=_split_csv_arg(args.domains) or None,
                    novel_only=True if args.novel_only else None,
                    malware_only=True if args.malware_only else None,
                    limit=args.limit,
                )
            )
            return 0
        if args.domains:
            _emit_json(client.identity_search(domains=_split_csv_arg(args.domains), limit=args.limit))
            return 0
        if args.subjects:
            _emit_json(client.identity_lookup(subjects=_split_csv_arg(args.subjects), limit=args.limit))
            return 0
        if args.hostname:
            _emit_json(client.identity_hostname_lookup(args.hostname, limit=args.limit))
            return 0
        if args.ip:
            _emit_json(client.identity_ip_lookup(ip=args.ip, limit=args.limit))
            return 0
        if args.password_hash:
            key = "prefix" if len(args.password_hash.strip()) == 5 else "hash"
            _emit_json(
                client.identity_password_lookup(
                    [{"algorithm": args.algorithm, key: args.password_hash.strip()}]
                )
            )
            return 0
        if args.incident_source:
            _emit_json(client.identity_incident_report(args.incident_source, limit=args.limit))
            return 0
        if args.dump is not None:
            _emit_json(client.identity_dump_metadata(names=_split_csv_arg(args.dump), limit=args.limit))
            return 0
        print("[-] Provide an Identity Intelligence query option (see --help).", file=sys.stderr)
        return 1

    if sub == "extension":
        if args.list or not (args.entity_type and args.entity_id and args.extension):
            if use_json:
                _emit_json(V2_EXTENSION_CATALOG)
            else:
                for etype, ext_names in V2_EXTENSION_CATALOG.items():
                    print(f"{etype:<14}: {', '.join(ext_names)}")
            return 0 if args.list else 1
        _emit_json(
            client.v2_lookup_extension(
                args.entity_type,
                args.entity_id,
                args.extension,
                metadata=args.metadata,
            )
        )
        return 0

    if sub == "rules":
        if args.entities_list:
            _emit_json(client.get_detection_rule_entities())
            return 0
        if args.entity_types:
            _emit_json(client.get_detection_rule_entity_types())
            return 0
        if args.alert_rules is not None:
            _emit_json(
                client.search_alert_rules(
                    freetext=args.alert_rules or None,
                    limit=args.limit,
                )
            )
            return 0
        rtypes = _split_csv_arg(args.types) or ["sigma", "yara", "snort"]
        entities = _split_csv_arg(args.entity) or None
        _emit_json(
            client.search_detection_rules(
                days=args.days,
                rule_types=rtypes,
                entities=entities,
                title=args.title,
                limit=args.limit,
            )
        )
        return 0

    if sub == "collective-insights":
        if args.exclusions_org:
            _emit_json(
                client.list_collective_insights_exclusions(
                    args.exclusions_org, limit=args.limit
                )
            )
            return 0
        filt: dict[str, Any] = {}
        assoc: dict[str, Any] = {}
        if args.malware:
            assoc["malware"] = {"name": args.malware}
        if args.actor:
            assoc["threat_actor"] = {"name": args.actor}
        if args.mitre:
            assoc["mitre_code"] = {"name": args.mitre}
        if assoc:
            filt["associated_threats"] = assoc
        if args.indicator_type:
            filt["indicator_type"] = args.indicator_type
        if args.from_date or args.to_date:
            det_time: dict[str, str] = {}
            if args.from_date:
                det_time["from"] = args.from_date
            if args.to_date:
                det_time["to"] = args.to_date
            filt["detection_time"] = det_time
        _emit_json(
            client.search_collective_insights(
                filters=filt or None, limit=args.limit
            )
        )
        return 0

    if sub == "fusion":
        if args.stat:
            _emit_json(client.fusion_stat_file(args.stat))
            return 0
        if args.get:
            blob = client.fusion_get_file(args.get)
            if use_json:
                _emit_json({"path": args.get, "bytes": len(blob)})
            else:
                _write_binary_output(blob, args.output, default_label=f"fusion {args.get}")
            return 0
        ls_path = args.ls or "/public"
        _emit_json(client.fusion_list_directory(ls_path))
        return 0

    if sub == "taxii2":
        if args.objects:
            _emit_json(
                client.taxii2_get_objects(
                    args.objects,
                    api_root=args.root,
                    limit=args.limit,
                    added_after=args.added_after,
                )
            )
            return 0
        if args.collections:
            _emit_json(client.taxii2_get_collections(api_root=args.root))
            return 0
        _emit_json(client.taxii2_discover())
        return 0

    if sub == "ato":
        if args.sources:
            _emit_json(client.ato_list_sources())
            return 0
        if args.indicators:
            _emit_json(
                client.ato_get_profile_indicators(
                    args.kind, args.indicators, limit=args.limit
                )
            )
            return 0
        if args.rules:
            _emit_json(client.ato_get_profile_rules(args.kind, args.rules))
            return 0
        kind = args.profiles or "detection"
        _emit_json(client.ato_query_profiles(kind=kind))
        return 0

    if sub == "sandbox":
        if args.yara:
            _emit_json(client.sandbox_list_yara_rules())
            return 0
        if args.yara_rule:
            _emit_json(client.sandbox_get_yara_rule(args.yara_rule))
            return 0
        if args.list:
            _emit_json(client.sandbox_list_samples(subset=args.list, limit=args.limit))
            return 0
        if args.sample_id and args.screenshot:
            blob = client.sandbox_get_url_scan_screenshot(args.sample_id)
            if use_json:
                _emit_json({"sample_id": args.sample_id, "bytes": len(blob)})
            else:
                _write_binary_output(blob, args.output, default_label="sandbox screenshot")
            return 0
        if args.sample_id:
            if args.report == "summary":
                _emit_json(client.sandbox_get_summary(args.sample_id))
            elif args.report == "static":
                _emit_json(client.sandbox_get_static_report(args.sample_id))
            elif args.report == "dynamic":
                _emit_json(
                    client.sandbox_get_dynamic_report(args.sample_id, task_id=args.task_id)
                )
            elif args.report == "urlscan":
                _emit_json(client.sandbox_get_url_scan_report(args.sample_id))
            else:
                _emit_json(client.sandbox_get_overview(args.sample_id))
            return 0
        if args.query:
            _emit_json(client.sandbox_search(args.query, limit=args.limit))
            return 0
        print("[-] Specify a query, --list, --sample-id, or --yara for `research sandbox`.", file=sys.stderr)
        return 1

    if sub == "asi":
        if args.asset:
            _emit_json(client.asi_read_asset(args.asset[0], args.asset[1]))
            return 0
        if args.asset_exposures:
            _emit_json(
                client.asi_list_asset_exposures(
                    args.asset_exposures[0], args.asset_exposures[1]
                )
            )
            return 0
        if args.assets:
            _emit_json(
                client.asi_find_assets(
                    args.assets,
                    asset_type=args.asset_type,
                    apex=args.apex,
                    exposure_severity=args.severity,
                    limit=args.limit,
                )
            )
            return 0
        if args.exposures:
            _emit_json(
                client.asi_list_exposures(
                    args.exposures,
                    filter_cve_id=args.cve,
                    filter_severity=args.severity,
                    limit=args.limit,
                )
            )
            return 0
        if args.signatures:
            _emit_json(
                client.asi_list_signatures(
                    args.signatures,
                    filter_cve_id=args.cve,
                    filter_severity_exact=args.severity,
                    limit=args.limit,
                )
            )
            return 0
        _emit_json(client.asi_list_projects())
        return 0

    if sub == "pfi":
        if args.status:
            _emit_json(client.pfi_get_task_status(args.status))
            return 0
        if args.preview:
            _emit_json(
                client.pfi_query_pipeline(
                    args.preview,
                    query=args.query,
                    from_date=args.from_date,
                    to_date=args.to_date,
                    dry_run=True,
                )
            )
            return 0
        if args.pickup:
            cols = _split_csv_arg(args.columns) or None
            out = client.pfi_pickup_data(args.pickup, fmt=args.format, columns=cols)
            if isinstance(out, str):
                print(out)
            else:
                _emit_json(out)
            return 0
        _emit_json(client.pfi_list_tasks())
        return 0

    if sub == "riskrecon":
        if args.domain:
            _emit_json(client.riskrecon_lookup_by_domain(args.domain))
            return 0
        if args.cve:
            _emit_json(client.riskrecon_lookup_by_cve(args.cve))
            return 0
        if args.ratings:
            _emit_json(client.riskrecon_get_ratings(args.ratings))
            return 0
        if args.findings:
            _emit_json(client.riskrecon_get_findings(args.findings, severity=args.severity))
            return 0
        if args.hosts:
            _emit_json(client.riskrecon_get_hosts(args.hosts))
            return 0
        if args.breaches:
            _emit_json(client.riskrecon_get_breach_events())
            return 0
        _emit_json(client.riskrecon_list_toes())
        return 0

    print(f"[-] Unknown research subcommand: {sub}", file=sys.stderr)
    return 1


def _build_sigma_config_from_args(args: argparse.Namespace) -> SigmaConversionConfig:
    """Layer CLI arguments onto a loaded ``SigmaConversionConfig`` profile."""
    sigma_config_path = getattr(args, "sigma_config", None)
    cfg = load_sigma_config(sigma_config_path)

    if getattr(args, "index_override", None) is not None:
        cfg.index_override = str(args.index_override).strip() or None
    if getattr(args, "index_map", None):
        cfg.index_map.update(parse_key_value_mapping(args.index_map, lowercase_keys=True))
    if getattr(args, "default_index", None) is not None:
        cfg.default_index = str(args.default_index).strip() or None

    if getattr(args, "table_fields", None) is not None:
        cfg.table_fields = str(args.table_fields).strip()
    if getattr(args, "custom_table_fields", None) is not None:
        extra = parse_field_list(args.custom_table_fields)
        for fld in extra:
            if fld not in cfg.custom_table_fields:
                cfg.custom_table_fields.append(fld)
    if getattr(args, "table_fields_map", None):
        cfg.table_fields_map.update(
            parse_key_value_mapping(args.table_fields_map, lowercase_keys=True)
        )

    if getattr(args, "suppress_fields", None) is not None:
        cfg.suppress_fields = str(args.suppress_fields).strip()
    if getattr(args, "custom_suppress_fields", None) is not None:
        extra_sup = parse_field_list(args.custom_suppress_fields)
        for fld in extra_sup:
            if fld not in cfg.custom_suppress_fields:
                cfg.custom_suppress_fields.append(fld)
    if getattr(args, "suppress_fields_map", None):
        cfg.suppress_fields_map.update(
            parse_key_value_mapping(args.suppress_fields_map, lowercase_keys=True)
        )

    if getattr(args, "field_map", None):
        cfg.field_map.update(parse_key_value_mapping(args.field_map, lowercase_keys=False))
    if getattr(args, "sourcetype_map", None):
        cfg.sourcetype_map.update(
            parse_key_value_mapping(args.sourcetype_map, lowercase_keys=True)
        )

    pipeline_arg = getattr(args, "pipeline", None)
    output_format_arg = getattr(args, "output_format", None)
    if pipeline_arg is not None:
        cfg.pipeline = pipeline_arg
        if output_format_arg is None:
            cfg.output_format = "data_model" if pipeline_arg == "splunk_cim" else "default"
    if getattr(args, "pipeline_file", None) is not None:
        cfg.pipeline_path = str(args.pipeline_file).strip() or None
    if output_format_arg is not None:
        cfg.output_format = output_format_arg

    if getattr(args, "no_split", False):
        cfg.split_by_index = False
    if getattr(args, "no_rule_fields", False):
        cfg.include_rule_fields = False

    has_profile = sigma_config_path is not None
    if not has_profile or args.mode != "overwrite":
        cfg.write_mode = args.mode
    if not has_profile or args.cron_schedule != "0 * * * *":
        cfg.cron_schedule = args.cron_schedule
    if not has_profile or args.earliest_time != "-70m":
        cfg.earliest_time = args.earliest_time
    if not has_profile or args.latest_time != "-10m":
        cfg.latest_time = args.latest_time
    if not has_profile or args.suppress_period != "86400s":
        cfg.suppress_period = args.suppress_period

    return cfg


def _handle_sigma(args: argparse.Namespace, client: RecordedFutureClient, *, use_json: bool) -> int:
    workspace_dir = get_workspace_dir()
    cfg = _build_sigma_config_from_args(args)

    convert_files = getattr(args, "convert_file", None) or []
    if convert_files:
        local_rules: list[dict[str, Any]] = []
        for raw_path in convert_files:
            file_path = Path(raw_path).expanduser()
            if not file_path.is_file():
                raise FileNotFoundError(f"Sigma rule file not found: {file_path}")
            local_rules.append(
                {
                    "rule_id": file_path.stem,
                    "file_name": file_path.name,
                    "content": file_path.read_text(encoding="utf-8"),
                }
            )

        if args.export:
            summary = _run_quiet_if_json(
                use_json,
                export_rules_to_splunk,
                local_rules,
                output_path=args.output,
                config=cfg,
            )
            if use_json:
                _emit_json(
                    {
                        "status": "ok",
                        "rules_processed": len(local_rules),
                        "output": str(args.output),
                        "mode": cfg.write_mode,
                        "pipeline": cfg.pipeline,
                        "output_format": cfg.output_format,
                        **(summary if isinstance(summary, dict) else {}),
                    }
                )
            return 0

        converted_items = [convert_sigma_rule(item, config=cfg) for item in local_rules]
        if use_json:
            _emit_json(converted_items[0] if len(converted_items) == 1 else converted_items)
            return 0

        for item in converted_items:
            print("\n".join(item["stanzas"]))
        return 0

    rules = _run_quiet_if_json(
        use_json,
        load_rules,
        client,
        refresh=args.refresh,
        days=args.days,
        cache_dir=workspace_dir,
    )

    if args.export:
        target_rules = search_rules(rules, args.query) if args.query else rules
        summary = _run_quiet_if_json(
            use_json,
            export_rules_to_splunk,
            target_rules,
            output_path=args.output,
            config=cfg,
        )
        if use_json:
            _emit_json(
                {
                    "status": "ok",
                    "rules_processed": len(target_rules),
                    "output": str(args.output),
                    "mode": cfg.write_mode,
                    "pipeline": cfg.pipeline,
                    "output_format": cfg.output_format,
                    **(summary if isinstance(summary, dict) else {}),
                }
            )
        return 0

    if args.query:
        matches = search_rules(rules, args.query)
        if use_json:
            _emit_json(matches)
            return 0
        if not matches:
            print(f"No rules found matching '{args.query}'.")
            return 0
        if len(matches) == 1:
            print_rule(matches[0])
            return 0
        print(f"Found {len(matches)} matching rules:")
        for idx, rule in enumerate(matches[:15]):
            print(f"  {idx + 1:2d}. {rule.get('title')} ({rule.get('file_name')})")
        if len(matches) > 15:
            print(f"  ... and {len(matches) - 15} more matches.")
        if not sys.stdin.isatty():
            return 0
        while True:
            choice = input(f"\nSelect a number to view (1-{min(len(matches), 15)}), or press Enter to exit: ").strip()
            if not choice:
                break
            try:
                num = int(choice)
                if 1 <= num <= min(len(matches), 15):
                    print_rule(matches[num - 1])
                    break
            except ValueError:
                pass
        return 0

    if use_json:
        _emit_json(rules)
        return 0
    if not sys.stdin.isatty():
        print(f"Loaded {len(rules)} Sigma rules.")
        return 0
    interactive_loop(rules, client, cache_dir=workspace_dir)
    return 0


def _write_validation_status(
    status_file: str | None,
    *,
    status: str,
    total: int,
    completed: int,
    successful: int,
    triggered: int,
    failed: int,
) -> None:
    if not status_file:
        return
    try:
        path = Path(status_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "pid": os.getpid(),
            "status": status,
            "timestamp": datetime.now(UTC).isoformat(),
            "total_searches": total,
            "completed": completed,
            "successful": successful,
            "triggered": triggered,
            "failed": failed,
            "progress_percent": round((completed / total) * 100, 2) if total > 0 else 0.0,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to write status file '%s': %s", status_file, exc)


def _handle_validate(
    args: argparse.Namespace,
    processed_args: list[str],
    *,
    global_dry_run: bool,
    use_json: bool,
) -> int:
    raw_ca_bundle = getattr(args, "ca_bundle", None)
    clean_ca_bundle = (
        raw_ca_bundle.strip() if isinstance(raw_ca_bundle, str) and raw_ca_bundle.strip() else None
    )
    if bool(getattr(args, "insecure", False)) and bool(getattr(args, "verify_ssl", False)):
        if use_json:
            _emit_cli_error(
                ValueError("Cannot specify both --insecure and --verify-ssl."),
                use_json=True,
            )
        else:
            print("[-] Cannot specify both --insecure and --verify-ssl.", file=sys.stderr)
        return 1

    if args.background:
        child_args = [arg for arg in processed_args if arg != "--background"]
        log_file_path = Path(args.log_file or "validate_savedsearches.log").expanduser()
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        if "--log-file" not in child_args and not any(a.startswith("--log-file=") for a in child_args):
            child_args.extend(["--log-file", str(log_file_path)])

        cmd = [sys.executable, "-m", "soclens.cli", *child_args]
        with log_file_path.open("a", encoding="utf-8") as log_handle:
            if os.name == "nt":
                creation_flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
                    subprocess, "CREATE_NEW_PROCESS_GROUP", 0
                )
                proc = subprocess.Popen(
                    cmd,
                    stdout=log_handle,
                    stderr=log_handle,
                    creationflags=creation_flags,
                    close_fds=True,
                )
            else:
                proc = subprocess.Popen(
                    cmd,
                    stdout=log_handle,
                    stderr=log_handle,
                    start_new_session=True,
                    close_fds=True,
                )

        if use_json:
            _emit_json({"pid": proc.pid, "log_file": str(log_file_path.resolve()), "status": "started"})
        else:
            print(f"[+] Spawned validation job in background (PID: {proc.pid}).")
            print(f"[+] Output logs will be written to: {log_file_path.resolve()}")
        return 0

    orig_stdout = sys.stdout
    orig_stderr = sys.stderr
    opened_log: io.TextIOWrapper | Any | None = None
    try:
        if args.log_file:
            log_path = Path(args.log_file).expanduser()
            log_path.parent.mkdir(parents=True, exist_ok=True)
            opened_log = log_path.open("a", encoding="utf-8")
            sys.stdout = opened_log
            sys.stderr = opened_log

        dry_run_val = bool(global_dry_run or getattr(args, "dry_run", False))
        if not use_json:
            print("=== Starting Splunk Saved Searches Validation ===")

        searches = _run_quiet_if_json(use_json, parse_savedsearches_files, args.input)
        if not searches:
            _write_validation_status(
                args.status_file,
                status="failed",
                total=0,
                completed=0,
                successful=0,
                triggered=0,
                failed=0,
            )
            print(f"[-] No saved searches found matching: {args.input}", file=sys.stderr)
            return 1

        if dry_run_val:
            if use_json:
                _emit_json({"dry_run": True, "total_searches": len(searches), "searches": searches})
                return 0
            print("--- DRY RUN MODE ACTIVE ---")
            for idx, search in enumerate(searches, 1):
                print(f"Search {idx}/{len(searches)}: [{search['stanza']}] in {search['file']}")
                print(f"  Query: {search['search']}")
            print("--- DRY RUN COMPLETED ---")
            return 0

        splunk_verify: bool | str | None
        if bool(getattr(args, "insecure", False)):
            splunk_verify = False
        elif clean_ca_bundle is not None:
            splunk_verify = clean_ca_bundle
        elif args.verify_ssl:
            splunk_verify = True
        else:
            splunk_verify = None

        resolved_cfg = get_splunk_config(
            host=args.host,
            token=args.token,
            username=args.username,
            password=args.password,
            app=args.app,
            verify_ssl=splunk_verify,
            required=True,
        )

        with SplunkValidator(
            host=resolved_cfg.host,
            token=resolved_cfg.token,
            username=resolved_cfg.username,
            password=resolved_cfg.password,
            app=resolved_cfg.app,
            verify_ssl=resolved_cfg.verify_ssl,
        ) as validator:
            if not use_json:
                print(f"Testing connectivity to Splunk Search Head: {validator.host}")
            if not validator.check_connection():
                _write_validation_status(
                    args.status_file,
                    status="failed",
                    total=len(searches),
                    completed=0,
                    successful=0,
                    triggered=0,
                    failed=len(searches),
                )
                print("[ERROR] Could not establish connection to Splunk REST API. Exiting.", file=sys.stderr)
                return 1

            total_searches = len(searches)
            completed_count = 0
            successful_count = 0
            triggered_count = 0
            failed_count = 0
            validation_results: list[dict[str, Any]] = []

            _write_validation_status(
                args.status_file,
                status="running",
                total=total_searches,
                completed=0,
                successful=0,
                triggered=0,
                failed=0,
            )

            if not use_json:
                print(f"Starting execution of {total_searches} searches with concurrency={args.concurrency}")
                print(f"Lookback window: {args.earliest} to {args.latest}")

            start_time = datetime.now(UTC)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
                futures_to_search = {
                    executor.submit(
                        validator.run_single_search,
                        s,
                        args.earliest,
                        args.latest,
                        args.timeout,
                    ): s
                    for s in searches
                }
                for future in concurrent.futures.as_completed(futures_to_search):
                    search_info = futures_to_search[future]
                    try:
                        res = future.result()
                    except Exception as exc:
                        res = {
                            "stanza": search_info["stanza"],
                            "query": search_info["search"],
                            "file": search_info["file"],
                            "status": "failed",
                            "trigger_count": 0,
                            "scan_count": 0,
                            "duration": 0.0,
                            "error_message": f"Thread exception: {exc}",
                            "sample_results": [],
                        }

                    completed_count += 1
                    if res["status"] == "success":
                        successful_count += 1
                        if res["trigger_count"] > 0:
                            triggered_count += 1
                    else:
                        failed_count += 1
                    validation_results.append(res)

                    if not use_json:
                        ind = "SUCCESS" if res["status"] == "success" else "FAILED"
                        trig = (
                            f" ({res['trigger_count']} triggers)"
                            if res["status"] == "success" and res["trigger_count"] > 0
                            else ""
                        )
                        print(f"Progress: [{completed_count}/{total_searches}] - {ind}{trig} - {res['stanza']}")
                        if res.get("error_message"):
                            print(f"  [!] Error: {res['error_message']}")

                    _write_validation_status(
                        args.status_file,
                        status="running",
                        total=total_searches,
                        completed=completed_count,
                        successful=successful_count,
                        triggered=triggered_count,
                        failed=failed_count,
                    )

            end_time = datetime.now(UTC)
            duration = (end_time - start_time).total_seconds()
            _write_validation_status(
                args.status_file,
                status="completed",
                total=total_searches,
                completed=completed_count,
                successful=successful_count,
                triggered=triggered_count,
                failed=failed_count,
            )

            report = {
                "summary": {
                    "total_searches": total_searches,
                    "completed": completed_count,
                    "successful": successful_count,
                    "triggered": triggered_count,
                    "failed": failed_count,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "duration_seconds": duration,
                },
                "results": validation_results,
            }

            out_path = Path(args.output).expanduser()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

            if use_json:
                _emit_json(report)
                return 0

            print(f"[SUCCESS] JSON validation report written to: {out_path.resolve()}")
            print("\n" + "=" * 50)
            print("V A L I D A T I O N   S U M M A R Y")
            print("=" * 50)
            print(f"Total Searches Executed: {total_searches}")
            print(f"Successful Execution:   {successful_count} ({(successful_count / total_searches) * 100:.1f}%)")
            print(f"Triggered Searches:     {triggered_count}")
            print(f"Failed Searches:        {failed_count} ({(failed_count / total_searches) * 100:.1f}%)")
            print(f"Total Execution Time:   {duration:.2f} seconds")
            print("=" * 50)
            return 0
    finally:
        sys.stdout = orig_stdout
        sys.stderr = orig_stderr
        if opened_log is not None:
            opened_log.close()


def _build_llm_client(args: argparse.Namespace) -> LocalLLMClient:
    """Instantiate ``LocalLLMClient`` applying CLI connection and SSL overrides."""
    verify_ssl: bool | str | None = None
    if bool(getattr(args, "insecure", False)):
        verify_ssl = False
    else:
        ca_bundle = getattr(args, "ca_bundle", None)
        if isinstance(ca_bundle, str) and ca_bundle.strip():
            verify_ssl = ca_bundle.strip()
    return LocalLLMClient(
        provider=getattr(args, "provider", None),
        base_url=getattr(args, "base_url", None),
        model=getattr(args, "model", None),
        api_key=getattr(args, "api_key", None),
        timeout=getattr(args, "timeout", None),
        verify_ssl=verify_ssl,
        temperature=getattr(args, "temperature", None),
        max_tokens=getattr(args, "max_tokens", None),
    )


def _handle_llm(args: argparse.Namespace, *, use_json: bool) -> int:
    subcmd = getattr(args, "llm_subcommand", None)
    if not subcmd:
        print("[-] Missing llm subcommand. Use: status, models, chat, explain-sigma", file=sys.stderr)
        return 1

    with _build_llm_client(args) as llm:
        if subcmd == "status":
            status = llm.check_connection()
            if use_json:
                _emit_json(status)
            else:
                state = "OK" if status["ok"] else "UNREACHABLE"
                print(f"Local LLM Status: {state}")
                print(f"Provider: {status['provider']}")
                print(f"Base URL: {status['base_url']}")
                print(f"Models ({len(status['models'])}): {', '.join(status['models']) or 'None'}")
                if status.get("error"):
                    print(f"Error: {status['error']}", file=sys.stderr)
            return 0 if status["ok"] else 1

        if subcmd == "models":
            models = llm.list_models()
            if use_json:
                _emit_json(
                    {
                        "provider": llm.provider,
                        "base_url": llm.base_url,
                        "models": models,
                    }
                )
            else:
                if not models:
                    print(f"No models reported by {llm.provider} at {llm.base_url}.")
                else:
                    for name in models:
                        print(name)
            return 0

        if subcmd == "chat":
            prompt_text = (getattr(args, "prompt", None) or "").strip()
            file_arg = getattr(args, "file", None)
            file_content = ""
            if file_arg:
                file_path = Path(file_arg).expanduser()
                if not file_path.is_file():
                    raise FileNotFoundError(f"Input file not found: {file_path}")
                file_content = file_path.read_text(encoding="utf-8")

            if not prompt_text and not file_content:
                raise ValueError("Provide --prompt and/or --file for 'llm chat'.")

            template_key = getattr(args, "template", "freeform") or "freeform"
            system_override = getattr(args, "system", None)

            if system_override:
                combined = (
                    f"{file_content.strip()}\n\n{prompt_text}".strip()
                    if file_content and prompt_text
                    else (file_content.strip() or prompt_text)
                )
                result = llm.chat(
                    [{"role": "user", "content": combined}],
                    model=getattr(args, "model", None),
                    system_prompt=system_override,
                )
            elif file_content:
                result = llm.analyze_with_template(
                    template_key,
                    file_content,
                    extra_instruction=prompt_text,
                    model=getattr(args, "model", None),
                )
            elif template_key != "freeform":
                result = llm.analyze_with_template(
                    template_key,
                    prompt_text,
                    model=getattr(args, "model", None),
                )
            else:
                result = llm.chat(
                    [{"role": "user", "content": prompt_text}],
                    model=getattr(args, "model", None),
                    system_prompt=SOC_PROMPT_TEMPLATES["freeform"]["system_prompt"],
                )

            if use_json:
                _emit_json(
                    {
                        "provider": result["provider"],
                        "model": result["model"],
                        "done": result["done"],
                        "content": result["content"],
                    }
                )
            else:
                print(result["content"])
            return 0

        if subcmd == "explain-sigma":
            file_arg = getattr(args, "file", None)
            rule_id = getattr(args, "rule_id", None)
            if not file_arg and not rule_id:
                raise ValueError("Specify either --file or --rule-id for 'llm explain-sigma'.")

            rule_title = ""
            rule_content = ""
            if file_arg:
                file_path = Path(file_arg).expanduser()
                if not file_path.is_file():
                    raise FileNotFoundError(f"Sigma rule file not found: {file_path}")
                rule_title = file_path.name
                rule_content = file_path.read_text(encoding="utf-8")
            else:
                workspace = get_workspace_dir(getattr(args, "workspace", None))
                rf_client = _build_rf_client(args)
                rules = _run_quiet_if_json(
                    use_json,
                    load_rules,
                    rf_client,
                    refresh=False,
                    cache_dir=workspace,
                )
                target_id = str(rule_id).strip().lower()
                match = next(
                    (
                        r
                        for r in rules
                        if str(r.get("rule_id") or "").strip().lower() == target_id
                    ),
                    None,
                )
                if match is None:
                    match = next(
                        (
                            r
                            for r in rules
                            if target_id in str(r.get("rule_id") or "").strip().lower()
                        ),
                        None,
                    )
                if match is None:
                    raise ValueError(f"No cached Sigma rule matching rule ID '{rule_id}'.")
                rule_title = str(match.get("title") or rule_id)
                rule_content = str(match.get("content") or "").strip()
                if not rule_content:
                    rule_content = f"Rule ID: {match.get('rule_id')}\nTitle: {rule_title}"

            result = llm.analyze_with_template(
                "explain_sigma",
                rule_content,
                model=getattr(args, "model", None),
            )
            if use_json:
                _emit_json(
                    {
                        "rule_title": rule_title,
                        "provider": result["provider"],
                        "model": result["model"],
                        "done": result["done"],
                        "content": result["content"],
                    }
                )
            else:
                print(result["content"])
            return 0

    return 1


def _build_splunk_client_from_args(args: argparse.Namespace) -> SplunkClient:
    raw_ca = getattr(args, "ca_bundle", None)
    clean_ca = raw_ca.strip() if isinstance(raw_ca, str) and raw_ca.strip() else None
    splunk_verify: bool | str | None
    if bool(getattr(args, "insecure", False)):
        splunk_verify = False
    elif clean_ca is not None:
        splunk_verify = clean_ca
    elif bool(getattr(args, "verify_ssl", False)):
        splunk_verify = True
    else:
        splunk_verify = None

    resolved_cfg = get_splunk_config(
        host=getattr(args, "host", None),
        token=getattr(args, "token", None),
        username=getattr(args, "username", None),
        password=getattr(args, "password", None),
        app=getattr(args, "app", None),
        verify_ssl=splunk_verify,
        required=True,
    )
    return SplunkClient(
        host=resolved_cfg.host,
        token=resolved_cfg.token,
        username=resolved_cfg.username,
        password=resolved_cfg.password,
        app=resolved_cfg.app,
        verify_ssl=resolved_cfg.verify_ssl,
    )


def _format_splunk_cell_cli(value: Any, max_len: int = 60) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        text = ", ".join(str(v) for v in value)
    elif isinstance(value, dict):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value)
    text = " ".join(text.splitlines()).strip()
    if len(text) > max_len:
        return f"{text[: max_len - 1]}..."
    return text


def _emit_splunk_results_output(
    result: dict[str, Any],
    *,
    fmt: str,
    output_path: str | None,
    use_json: bool,
) -> int:
    rows: list[dict[str, Any]] = list(result.get("results") or [])
    fields: list[str] = list(result.get("fields") or [])

    if result.get("status") != "success":
        if use_json or fmt == "json":
            _emit_json(result)
        else:
            print(f"[ERROR] Splunk search failed: {result.get('error_message')}", file=sys.stderr)
        return 1

    if output_path:
        out_p = Path(output_path)
        if fmt == "csv" or (fmt != "json" and out_p.suffix.lower() == ".csv"):
            written = export_results_csv(rows, out_p, fields=fields)
        else:
            written = export_results_json(rows, out_p)
        if not use_json and fmt != "json":
            print(f"Exported {len(rows)} result(s) to {written}", file=sys.stderr)

    if use_json or fmt == "json":
        _emit_json(result)
        return 0

    if fmt == "csv":
        fieldnames = fields or (list(rows[0].keys()) if rows else [])
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        if fieldnames:
            writer.writeheader()
            for row in rows:
                formatted_row: dict[str, str] = {}
                for k in fieldnames:
                    val = row.get(k)
                    if isinstance(val, list):
                        formatted_row[k] = "; ".join(str(v) for v in val)
                    elif isinstance(val, dict):
                        formatted_row[k] = json.dumps(val, ensure_ascii=False, sort_keys=True)
                    elif val is None:
                        formatted_row[k] = ""
                    else:
                        formatted_row[k] = str(val)
                writer.writerow(formatted_row)
        sys.stdout.write(buf.getvalue())
        return 0

    # Default: human-readable table
    print(
        f"SID: {result.get('sid')} | Results: {result.get('result_count', len(rows))} | "
        f"Events: {result.get('event_count', 0)} | Duration: {result.get('duration', 0.0):.2f}s"
    )
    if not rows:
        print("(No results returned)")
        return 0

    cols = (fields or list(rows[0].keys()))[:10]
    widths = [
        min(60, max(len(c), *(len(_format_splunk_cell_cli(r.get(c))) for r in rows)))
        for c in cols
    ]
    header = " | ".join(c.ljust(w) for c, w in zip(cols, widths, strict=False))
    sep = "-+-".join("-" * w for w in widths)
    print(header)
    print(sep)
    for row in rows:
        print(
            " | ".join(
                _format_splunk_cell_cli(row.get(c)).ljust(w)
                for c, w in zip(cols, widths, strict=False)
            )
        )
    return 0


def _build_splunk_es_client_from_args(args: argparse.Namespace) -> SplunkESClient:
    splunk_client = _build_splunk_client_from_args(args)
    target_app = getattr(args, "app", None) or SPLUNK_ES_APP
    es_client = SplunkESClient(splunk_client=splunk_client, app=target_app)
    es_client._owns_client = True
    return es_client


def _print_cli_table(rows: list[dict[str, Any]], cols: list[str]) -> None:
    if not rows:
        print("(No results returned)")
        return
    selected_cols = cols[:10]
    widths = [
        min(60, max(len(c), *(len(_format_splunk_cell_cli(r.get(c))) for r in rows)))
        for c in selected_cols
    ]
    header = " | ".join(c.ljust(w) for c, w in zip(selected_cols, widths, strict=False))
    sep = "-+-".join("-" * w for w in widths)
    print(header)
    print(sep)
    for row in rows:
        print(
            " | ".join(
                _format_splunk_cell_cli(row.get(c)).ljust(w)
                for c, w in zip(selected_cols, widths, strict=False)
            )
        )


def _handle_splunk_es(
    args: argparse.Namespace,
    *,
    global_dry_run: bool,
    use_json: bool,
) -> int:
    es_sub = args.es_subcommand
    effective_dry_run = bool(global_dry_run or getattr(args, "dry_run", False))
    emit_json = bool(use_json or getattr(args, "format", None) == "json")

    if es_sub == "update-notable" and effective_dry_run:
        preview = {
            "dry_run": True,
            "event_id": args.event_id,
            "status": args.status,
            "urgency": args.urgency,
            "owner": args.owner,
            "disposition": args.disposition,
            "comment": args.comment,
        }
        if emit_json:
            _emit_json(preview)
        else:
            print(f"[DRY-RUN] Would update Splunk ES notable '{args.event_id}': {preview}")
        return 0

    if es_sub == "toggle-correlation":
        target_enabled = bool(args.enable)
        action_verb = "enable" if target_enabled else "disable"
        if effective_dry_run:
            preview = {
                "dry_run": True,
                "name": args.name,
                "enabled": target_enabled,
            }
            if emit_json:
                _emit_json(preview)
            else:
                print(
                    f"[DRY-RUN] Would {action_verb} Splunk ES correlation search '{args.name}'."
                )
            return 0
        if not bool(getattr(args, "yes", False)):
            if sys.stdin.isatty():
                answer = input(
                    f"Confirm {action_verb} correlation search '{args.name}'? [y/N]: "
                ).strip().lower()
                if answer not in ("y", "yes"):
                    print("Cancelled.")
                    return 1
            else:
                print(
                    f"[-] Refusing to {action_verb} correlation search '{args.name}' without --yes in non-interactive mode.",
                    file=sys.stderr,
                )
                return 1

    with _build_splunk_es_client_from_args(args) as es:
        if es_sub == "notables":
            notables = es.list_notables(
                earliest=args.earliest,
                latest=args.latest,
                urgency=args.urgency,
                status=args.status,
                owner=args.owner,
                rule_name=args.rule_name,
                search_text=args.search_text,
                limit=args.limit,
            )
            if emit_json:
                _emit_json({"count": len(notables), "notables": notables})
                return 0
            _print_cli_table(
                notables,
                ["_time", "event_id", "urgency", "status_label", "rule_name", "owner", "src", "dest"],
            )
            return 0

        if es_sub == "update-notable":
            resp = es.update_notable(
                [args.event_id],
                status=args.status,
                urgency=args.urgency,
                owner=args.owner,
                disposition=args.disposition,
                comment=args.comment,
            )
            if emit_json:
                _emit_json({"event_id": args.event_id, "result": resp})
            else:
                print(f"[+] Updated Splunk ES notable '{args.event_id}'.")
            return 0

        if es_sub == "correlations":
            items = es.list_correlation_searches(
                search_filter=args.filter,
                count=args.count,
            )
            if emit_json:
                _emit_json({"count": len(items), "correlations": items})
                return 0
            _print_cli_table(
                items,
                ["name", "enabled", "severity", "security_domain", "cron_schedule", "action_notable", "action_risk"],
            )
            return 0

        if es_sub == "toggle-correlation":
            target_enabled = bool(args.enable)
            result = es.set_correlation_search_enabled(args.name, target_enabled)
            if emit_json:
                _emit_json(result)
            else:
                state = "enabled" if target_enabled else "disabled"
                print(f"[+] Correlation search '{args.name}' is now {state}.")
            return 0

        if es_sub == "threat-intel":
            entries = es.query_threat_intel(args.collection, limit=args.limit)
            if emit_json:
                _emit_json({"collection": args.collection, "count": len(entries), "entries": entries})
                return 0
            cols = list(entries[0].keys()) if entries else []
            _print_cli_table(entries, cols)
            return 0

        if es_sub == "assets":
            assets = es.lookup_asset(query=args.query, limit=args.limit)
            if emit_json:
                _emit_json({"count": len(assets), "assets": assets})
                return 0
            cols = list(assets[0].keys()) if assets else []
            _print_cli_table(assets, cols)
            return 0

        if es_sub == "identities":
            identities = es.lookup_identity(query=args.query, limit=args.limit)
            if emit_json:
                _emit_json({"count": len(identities), "identities": identities})
                return 0
            cols = list(identities[0].keys()) if identities else []
            _print_cli_table(identities, cols)
            return 0

        if es_sub == "risk":
            events = es.list_risk_events(
                risk_object=args.risk_object,
                earliest=args.earliest,
                latest=args.latest,
                limit=args.limit,
            )
            if emit_json:
                _emit_json({"count": len(events), "risk_events": events})
                return 0
            cols = list(events[0].keys()) if events else []
            _print_cli_table(events, cols)
            return 0

        if es_sub == "enrich":
            field_map = load_splunk_rf_field_map(getattr(args, "field_map", None))
            custom_spl = str(getattr(args, "spl", None) or "").strip()
            if custom_spl:
                res = es.client.run_search(
                    custom_spl,
                    earliest=args.earliest,
                    latest=args.latest,
                    app=es.app,
                    count=max(1, int(args.limit)),
                )
                if res.get("status") != "success":
                    raise SplunkESError(
                        str(res.get("error_message") or "Failed to run Splunk SPL query for enrichment."),
                        messages=list(res.get("messages") or []),
                    )
                raw_events = [r for r in (res.get("results") or []) if isinstance(r, dict)]
            else:
                raw_events = es.list_notables(
                    earliest=args.earliest,
                    latest=args.latest,
                    urgency=args.urgency,
                    status=args.status,
                    limit=args.limit,
                )

            rf_client = _build_rf_client(args)
            enricher = SplunkRFEnricher(
                rf_client,
                field_map=field_map,
                include_private_ips=bool(args.include_private_ips),
            )
            enriched = enricher.enrich_events(raw_events)

            comment_results: list[dict[str, Any]] = []
            if bool(args.write_comments):
                for ev in enriched:
                    event_id = str(ev.get("event_id") or "").strip()
                    if not event_id or not ev.get("rf_observables"):
                        continue
                    comment_results.append(
                        write_enrichment_to_notable(
                            es,
                            event_id,
                            ev,
                            dry_run=effective_dry_run,
                        )
                    )

            fmt = str(getattr(args, "format", "table") or "table")
            output_path = getattr(args, "output", None)
            export_cols = [
                "_time",
                "event_id",
                "urgency",
                "rule_name",
                "src",
                "dest",
                "rf_max_risk_score",
                "rf_criticality_label",
                "rf_top_field",
                "rf_rules_triggered",
                "rf_evidence_summary",
            ]
            if output_path:
                out_p = Path(output_path)
                if fmt == "csv" or (fmt != "json" and out_p.suffix.lower() == ".csv"):
                    csv_cols = [c for c in export_cols if any(c in r for r in enriched)]
                    if not csv_cols and enriched:
                        csv_cols = [k for k in enriched[0] if k not in ("raw", "rf_observables")]
                    written = export_results_csv(enriched, out_p, fields=csv_cols)
                else:
                    written = export_results_json(enriched, out_p)
                if not emit_json and fmt != "csv":
                    print(f"[+] Exported {len(enriched)} enriched event(s) to {written}", file=sys.stderr)

            enriched_count = sum(1 for ev in enriched if ev.get("rf_observables"))
            if emit_json:
                payload: dict[str, Any] = {
                    "count": len(enriched),
                    "enriched_count": enriched_count,
                    "events": enriched,
                }
                if bool(args.write_comments):
                    payload["comments"] = comment_results
                _emit_json(payload)
                return 0

            if fmt == "csv":
                csv_cols = [c for c in export_cols if any(c in r for r in enriched)]
                if not csv_cols and enriched:
                    csv_cols = [k for k in enriched[0] if k not in ("raw", "rf_observables")]
                buf = io.StringIO()
                writer = csv.DictWriter(buf, fieldnames=csv_cols, extrasaction="ignore")
                if csv_cols:
                    writer.writeheader()
                    for row in enriched:
                        formatted_row: dict[str, str] = {}
                        for col in csv_cols:
                            val = row.get(col)
                            formatted_row[col] = "" if val is None else str(val)
                        writer.writerow(formatted_row)
                sys.stdout.write(buf.getvalue())
                return 0

            table_cols = [
                c
                for c in (
                    "_time",
                    "event_id",
                    "urgency",
                    "rule_name",
                    "rf_max_risk_score",
                    "rf_criticality_label",
                    "rf_top_field",
                    "rf_evidence_summary",
                )
                if any(c in r for r in enriched)
            ]
            if not table_cols and enriched:
                table_cols = [k for k in enriched[0] if k not in ("raw", "rf_observables")][:8]
            _print_cli_table(enriched, table_cols)
            if bool(args.write_comments):
                prefix = "[DRY-RUN] Previewed" if effective_dry_run else "[+] Posted"
                print(f"{prefix} RF enrichment comment(s) for {len(comment_results)} notable(s).")
            return 0

    return 1


def _handle_splunk(
    args: argparse.Namespace,
    *,
    global_dry_run: bool = False,
    use_json: bool,
) -> int:
    sub = args.subcommand
    if sub == "es":
        return _handle_splunk_es(args, global_dry_run=global_dry_run, use_json=use_json)
    with _build_splunk_client_from_args(args) as splunk:
        if sub == "check":
            ok = splunk.check_connection()
            if use_json:
                _emit_json({"connected": ok, "host": splunk.host, "app": splunk.app})
            elif ok:
                print(f"[+] Connected to Splunk REST API: {splunk.host} (app={splunk.app})")
            else:
                print(f"[-] Failed to connect to Splunk REST API: {splunk.host}", file=sys.stderr)
            return 0 if ok else 1

        if sub == "search":
            result = splunk.run_search(
                args.spl,
                earliest=args.earliest,
                latest=args.latest,
                app=args.app,
                count=args.count,
                offset=args.offset,
                timeout=args.timeout,
            )
            return _emit_splunk_results_output(
                result,
                fmt=args.format,
                output_path=args.output,
                use_json=use_json,
            )

        if sub == "indexes":
            indexes = splunk.list_indexes()
            if use_json:
                _emit_json({"count": len(indexes), "indexes": indexes})
                return 0
            if not indexes:
                print("(No indexes found)")
                return 0
            print(f"{'NAME':<28} {'EVENTS':>12} {'SIZE_MB':>10} {'TYPE':<10} {'DISABLED'}")
            print("-" * 74)
            for idx in indexes:
                print(
                    f"{str(idx.get('name', '')):<28} "
                    f"{int(idx.get('total_event_count', 0)):>12} "
                    f"{float(idx.get('current_db_size_mb', 0.0)):>10.2f} "
                    f"{str(idx.get('datatype', '')):<10} "
                    f"{idx.get('disabled', False)}"
                )
            return 0

        if sub == "saved-searches":
            saved = splunk.list_saved_searches(
                app=args.app,
                search_filter=args.filter,
                count=args.count,
            )
            if use_json:
                _emit_json({"count": len(saved), "saved_searches": saved})
                return 0
            if not saved:
                print("(No saved searches found)")
                return 0
            print(f"{'NAME':<40} {'APP':<28} {'CRON':<16} {'DISABLED'}")
            print("-" * 96)
            for item in saved:
                print(
                    f"{_format_splunk_cell_cli(item.get('name', ''), 40):<40} "
                    f"{_format_splunk_cell_cli(item.get('app', ''), 28):<28} "
                    f"{_format_splunk_cell_cli(item.get('cron_schedule', ''), 16):<16} "
                    f"{item.get('disabled', False)}"
                )
            return 0

        if sub == "dispatch":
            result = splunk.dispatch_saved_search(
                args.name,
                app=args.app,
                earliest=args.earliest,
                latest=args.latest,
                count=args.count,
                timeout=args.timeout,
            )
            return _emit_splunk_results_output(
                result,
                fmt=args.format,
                output_path=args.output,
                use_json=use_json,
            )

    return 1


def _handle_bundle(args: argparse.Namespace, *, use_json: bool) -> int:
    workspace = get_workspace_dir(args.workspace)
    bundle_path = _run_quiet_if_json(
        use_json,
        create_bundle,
        workspace,
        output_path=args.output,
        wheelhouse=args.wheelhouse,
        target_platform=args.target_platform,
    )
    if use_json:
        _emit_json(
            {
                "status": "ok",
                "output_path": str(bundle_path),
                "workspace": str(workspace),
                "wheelhouse": bool(args.wheelhouse),
                "target_platform": args.target_platform or "current",
            }
        )
    else:
        print(f"[+] Bundle created successfully: {bundle_path}")
    return 0


def _build_s1_client(args: argparse.Namespace) -> SentinelOneClient:
    """Instantiate ``SentinelOneClient`` from CLI overrides and environment config."""
    verify_ssl: bool | str | None = None
    if bool(getattr(args, "insecure", False)):
        verify_ssl = False
    else:
        ca_bundle = getattr(args, "ca_bundle", None)
        if isinstance(ca_bundle, str) and ca_bundle.strip():
            verify_ssl = ca_bundle.strip()

    cfg = get_sentinelone_config(
        console_url=getattr(args, "s1_url", None),
        api_token=getattr(args, "s1_token", None),
        account_id=getattr(args, "s1_account_id", None),
        site_id=getattr(args, "s1_site_id", None),
        verify_ssl=verify_ssl,
        required=True,
    )
    return SentinelOneClient(config=cfg)


def _check_s1_write_guard(
    args: argparse.Namespace,
    *,
    global_dry_run: bool,
    use_json: bool,
    action: str,
    target: dict[str, Any],
) -> tuple[bool, int]:
    """Enforce ``--dry-run`` and ``--yes`` / ``SOCLENS_AUTO_APPROVE`` for S1 write actions.

    Returns ``(proceed, exit_code)``.
    """
    is_dry = bool(global_dry_run or getattr(args, "dry_run", False))
    if is_dry:
        payload = {"dry_run": True, "action": action, **target}
        if use_json:
            _emit_json(payload)
        else:
            print(f"[DRY-RUN] Would execute SentinelOne action '{action}': {json.dumps(target, default=str)}")
        return False, 0

    if not (bool(getattr(args, "yes", False)) or is_auto_approved()):
        msg = (
            f"Approval required for SentinelOne active/destructive action '{action}'. "
            "Pass --yes or set SOCLENS_AUTO_APPROVE=true (or use --dry-run to preview)."
        )
        if use_json:
            print(json.dumps({"error": msg, "action": action, "approval_required": True}, indent=2), file=sys.stderr)
        else:
            print(f"[-] {msg}", file=sys.stderr)
        return False, 1

    return True, 0


def _handle_s1(
    args: argparse.Namespace,
    *,
    global_dry_run: bool,
    use_json: bool,
) -> int:
    subcmd = getattr(args, "s1_command", None)
    if not subcmd:
        print(
            "Usage: soclens s1 {status,agents,isolate,reconnect,scan,reboot,threats,triage,mitigate,exclusions,blocklist,sites,activities}",
            file=sys.stderr,
        )
        return 1

    # Guard mutating commands before requiring live network calls when in dry-run or unapproved
    if subcmd in ("isolate", "reconnect", "reboot"):
        ids = _split_csv_arg(args.agent_ids)
        proceed, rc = _check_s1_write_guard(
            args,
            global_dry_run=global_dry_run,
            use_json=use_json,
            action=subcmd,
            target={"agent_ids": ids},
        )
        if not proceed:
            return rc
        with _build_s1_client(args) as client:
            if subcmd == "isolate":
                res = client.disconnect_agent(ids)
            elif subcmd == "reconnect":
                res = client.connect_agent(ids)
            else:
                res = client.reboot_agent(ids)
        if use_json:
            _emit_json(res)
        else:
            affected = res.get("data", {}).get("affected") if isinstance(res.get("data"), dict) else len(ids)
            print(f"[+] SentinelOne '{subcmd}' executed on {len(ids)} agent(s) (affected={affected}).")
        return 0

    if subcmd == "scan":
        ids = _split_csv_arg(args.agent_ids)
        action = "abort-scan" if args.abort else "initiate-scan"
        proceed, rc = _check_s1_write_guard(
            args,
            global_dry_run=global_dry_run,
            use_json=use_json,
            action=action,
            target={"agent_ids": ids},
        )
        if not proceed:
            return rc
        with _build_s1_client(args) as client:
            res = client.abort_scan(ids) if args.abort else client.initiate_scan(ids)
        if use_json:
            _emit_json(res)
        else:
            affected = res.get("data", {}).get("affected") if isinstance(res.get("data"), dict) else len(ids)
            print(f"[+] SentinelOne '{action}' executed on {len(ids)} agent(s) (affected={affected}).")
        return 0

    if subcmd == "triage":
        ids = _split_csv_arg(args.threat_ids)
        if not any((args.verdict, args.status, args.note)):
            raise ValueError("Provide at least one of --verdict, --status, or --note for triage.")
        proceed, rc = _check_s1_write_guard(
            args,
            global_dry_run=global_dry_run,
            use_json=use_json,
            action="triage",
            target={
                "threat_ids": ids,
                "verdict": args.verdict,
                "status": args.status,
                "note": args.note,
            },
        )
        if not proceed:
            return rc
        results: dict[str, Any] = {"threat_ids": ids}
        with _build_s1_client(args) as client:
            if args.verdict:
                results["verdict"] = client.update_threat_verdict(ids, args.verdict)
            if args.status:
                results["status"] = client.update_threat_incident_status(ids, args.status)
            if args.note:
                results["notes"] = [client.add_threat_note(tid, args.note) for tid in ids]
        if use_json:
            _emit_json(results)
        else:
            print(f"[+] Triaged {len(ids)} SentinelOne threat(s).")
        return 0

    if subcmd == "mitigate":
        ids = _split_csv_arg(args.threat_ids)
        proceed, rc = _check_s1_write_guard(
            args,
            global_dry_run=global_dry_run,
            use_json=use_json,
            action=f"mitigate:{args.action}",
            target={"threat_ids": ids, "mitigation_action": args.action},
        )
        if not proceed:
            return rc
        with _build_s1_client(args) as client:
            res = client.mitigate_threat(ids, args.action)
        if use_json:
            _emit_json(res)
        else:
            affected = res.get("data", {}).get("affected") if isinstance(res.get("data"), dict) else len(ids)
            print(f"[+] SentinelOne mitigation '{args.action}' executed (affected={affected}).")
        return 0

    if subcmd == "exclusions":
        if args.create:
            if not args.exclusion_type or not args.value:
                raise ValueError("--create requires --type and --value.")
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="create-exclusion",
                target={
                    "type": args.exclusion_type,
                    "os_type": args.os_type,
                    "value": args.value,
                    "mode": args.mode,
                    "description": args.description,
                },
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.create_exclusion(
                    exclusion_type=args.exclusion_type,
                    os_type=args.os_type,
                    value=args.value,
                    description=args.description,
                    mode=args.mode,
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Created SentinelOne {args.exclusion_type} exclusion: {args.value}")
            return 0

        if args.delete:
            del_ids = _split_csv_arg(args.delete)
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="delete-exclusions",
                target={"ids": del_ids, "type": args.exclusion_type},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.delete_exclusions(del_ids, exclusion_type=args.exclusion_type)
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Deleted {len(del_ids)} SentinelOne exclusion(s).")
            return 0

        with _build_s1_client(args) as client:
            items = client.list_exclusions(
                exclusion_type=args.exclusion_type,
                query=args.query,
                limit=args.limit,
            )
        if use_json:
            _emit_json(items)
        else:
            print(f"[+] SentinelOne exclusions ({len(items)}):")
            for item in items:
                print(
                    f"  - {item.get('id')} | {item.get('type')} | {item.get('osType')} | "
                    f"{item.get('value')} | {item.get('description', '')}"
                )
        return 0

    if subcmd == "blocklist":
        if args.add_hash:
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="add-blocklist",
                target={
                    "sha1_hash": args.add_hash,
                    "os_type": args.os_type,
                    "description": args.description,
                },
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.add_to_blocklist(
                    args.add_hash,
                    os_type=args.os_type,
                    description=args.description,
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Added SHA-1 {args.add_hash} to SentinelOne blocklist.")
            return 0

        if args.remove:
            rem_ids = _split_csv_arg(args.remove)
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="remove-blocklist",
                target={"ids": rem_ids},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.remove_from_blocklist(rem_ids)
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Removed {len(rem_ids)} SentinelOne blocklist entry(ies).")
            return 0

        with _build_s1_client(args) as client:
            items = client.list_blocklist(query=args.query, limit=args.limit)
        if use_json:
            _emit_json(items)
        else:
            print(f"[+] SentinelOne blocklist entries ({len(items)}):")
            for item in items:
                print(
                    f"  - {item.get('id')} | {item.get('value')} | {item.get('osType')} | "
                    f"{item.get('description', '')}"
                )
        return 0

    # Read-only commands
    with _build_s1_client(args) as client:
        if subcmd == "status":
            info = client.check_connection()
            if use_json:
                _emit_json({"console_url": client.console_url, "status": "connected", "info": info})
            else:
                print(f"[+] SentinelOne connected: {client.console_url} (build={info.get('build', '-')})")
            return 0

        if subcmd == "agents":
            agents = client.list_agents(
                query=args.query,
                computer_name=args.computer_name,
                infected=args.infected,
                is_active=args.active,
                network_status=args.network_status,
                os_types=args.os_type,
                limit=args.limit,
            )
            if use_json:
                _emit_json(agents)
            else:
                print(f"[+] SentinelOne agents ({len(agents)}):")
                for ag in agents:
                    print(
                        f"  - {ag.get('id')} | {ag.get('computerName')} | {ag.get('osType')} | "
                        f"net={ag.get('networkStatus')} | infected={ag.get('infected')}"
                    )
            return 0

        if subcmd == "threats":
            if args.timeline:
                events = client.get_threat_timeline(args.timeline, limit=args.limit)
                if use_json:
                    _emit_json(events)
                else:
                    print(f"[+] Threat {args.timeline} timeline ({len(events)} event(s)):")
                    for ev in events:
                        print(f"  - {ev.get('createdAt')} | {ev.get('primaryDescription', '')}")
                return 0
            threats = client.list_threats(
                query=args.query,
                incident_statuses=args.status,
                analyst_verdicts=args.verdict,
                computer_name=args.computer_name,
                limit=args.limit,
            )
            if use_json:
                _emit_json(threats)
            else:
                print(f"[+] SentinelOne threats ({len(threats)}):")
                for th in threats:
                    raw_tinfo = th.get("threatInfo")
                    tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
                    print(
                        f"  - {th.get('id')} | {tinfo.get('threatName', th.get('threatName', '-'))} | "
                        f"verdict={tinfo.get('analystVerdict', '-')} | status={tinfo.get('incidentStatus', '-')}"
                    )
            return 0

        if subcmd == "sites":
            if args.accounts:
                items = client.list_accounts(query=args.query, limit=args.limit)
                kind = "accounts"
            elif args.groups:
                items = client.list_groups(query=args.query, limit=args.limit)
                kind = "groups"
            else:
                items = client.list_sites(query=args.query, limit=args.limit)
                kind = "sites"
            if use_json:
                _emit_json(items)
            else:
                print(f"[+] SentinelOne {kind} ({len(items)}):")
                for item in items:
                    print(f"  - {item.get('id')} | {item.get('name')} | {item.get('state', '')}")
            return 0

        if subcmd == "activities":
            acts = client.list_activities(
                agent_ids=args.agent_id,
                threat_ids=args.threat_id,
                query=args.query,
                limit=args.limit,
            )
            if use_json:
                _emit_json(acts)
            else:
                print(f"[+] SentinelOne activities ({len(acts)}):")
                for act in acts:
                    print(f"  - {act.get('createdAt')} | {act.get('primaryDescription', '')}")
            return 0

    return 1


def _handle_settings(
    args: argparse.Namespace,
    *,
    global_dry_run: bool,
    use_json: bool,
) -> int:
    subcmd = getattr(args, "settings_command", None)
    if not subcmd:
        msg = "Usage: soclens settings {path,show,set,unset,import-env,profiles,use,delete-profile,reset}"
        if use_json:
            print(json.dumps({"error": msg}, indent=2), file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1

    is_dry = bool(global_dry_run or getattr(args, "dry_run", False))

    if subcmd == "path":
        info = get_settings_storage_info()
        if use_json:
            _emit_json(info)
        else:
            print(f"Settings File : {info['path']}")
            print(f"Exists        : {'Yes' if info['exists'] else 'No'}")
            print(f"Permissions   : {info['permissions']}")
            print(f"Active Profile: {info['active_profile']} ({info['profile_count']} total)")
            if info.get("load_error"):
                print(f"Load Warning  : {info['load_error']}")
        return 0

    if subcmd == "show":
        target_profile = getattr(args, "profile", None)
        if target_profile is not None:
            target_profile = validate_profile_name(target_profile)
        else:
            target_profile = get_active_profile_name()
        reveal = bool(getattr(args, "reveal", False))
        items = describe_all_settings(reveal=reveal, profile=target_profile)
        storage = get_settings_storage_info()
        if use_json:
            _emit_json({"storage": storage, "profile": target_profile, "settings": items})
        else:
            print(f"Active Profile: {target_profile} | File: {storage['path']}")
            print("-" * 108)
            print(f"{'Key':<32} | {'Value':<32} | {'Source':<22} | {'Env Alias'}")
            print("-" * 108)
            for item in items:
                val_disp = item["value"] or "<unset>"
                env_disp = ", ".join(item["env_vars"])
                print(
                    f"{item['key']:<32} | {val_disp[:32]:<32} | "
                    f"{item['source'][:22]:<22} | {env_disp}"
                )
        return 0

    if subcmd == "set":
        canon = resolve_setting_key(args.key)
        if canon is None:
            raise ValueError(
                f"Unknown setting key: {args.key!r}. Run 'soclens settings show' to list valid keys."
            )
        target_profile = getattr(args, "profile", None)
        if target_profile is not None:
            target_profile = validate_profile_name(target_profile)
        else:
            target_profile = get_active_profile_name()

        errors = validate_settings_values({canon: args.value})
        if errors:
            raise ValueError(errors[0][1])

        spec = SETTING_SPECS_BY_KEY[canon]
        masked_preview = format_setting_display(canon, args.value, reveal=False)
        if is_dry:
            payload = {
                "dry_run": True,
                "action": "set",
                "key": canon,
                "profile": target_profile,
                "value": masked_preview,
            }
            if use_json:
                _emit_json(payload)
            else:
                print(
                    f"[DRY-RUN] Would save '{canon}' in profile '{target_profile}' "
                    f"(value={masked_preview})."
                )
            return 0

        path = save_profile_settings({canon: args.value}, profile=target_profile)
        result_payload = {
            "saved": True,
            "key": canon,
            "profile": target_profile,
            "value": masked_preview,
            "path": str(path),
            "secret": spec.secret,
        }
        if use_json:
            _emit_json(result_payload)
        else:
            if spec.secret:
                print(
                    f"[+] Saved secret '{canon}' ({masked_preview}) to profile '{target_profile}' "
                    f"at {path}."
                )
            else:
                print(
                    f"[+] Saved '{canon}' = {masked_preview!r} to profile '{target_profile}' "
                    f"at {path}."
                )
        return 0

    if subcmd == "unset":
        canon = resolve_setting_key(args.key)
        if canon is None:
            raise ValueError(
                f"Unknown setting key: {args.key!r}. Run 'soclens settings show' to list valid keys."
            )
        target_profile = getattr(args, "profile", None)
        if target_profile is not None:
            target_profile = validate_profile_name(target_profile)
        else:
            target_profile = get_active_profile_name()

        if is_dry:
            payload = {
                "dry_run": True,
                "action": "unset",
                "key": canon,
                "profile": target_profile,
            }
            if use_json:
                _emit_json(payload)
            else:
                print(f"[DRY-RUN] Would remove '{canon}' from profile '{target_profile}'.")
            return 0

        path = save_profile_settings({canon: None}, profile=target_profile)
        if use_json:
            _emit_json({"unset": True, "key": canon, "profile": target_profile, "path": str(path)})
        else:
            print(f"[+] Removed '{canon}' from profile '{target_profile}' ({path}).")
        return 0

    if subcmd == "import-env":
        target_profile = getattr(args, "profile", None)
        if target_profile is not None:
            target_profile = validate_profile_name(target_profile)
        else:
            target_profile = get_active_profile_name()
        imported = collect_env_importable_settings()
        if not imported:
            if use_json:
                _emit_json({"imported": [], "count": 0, "profile": target_profile})
            else:
                print("[*] No recognized environment variables are currently set.")
            return 0
        errors = validate_settings_values(imported)
        if errors:
            raise ValueError(errors[0][1])

        imported_keys = sorted(imported.keys())
        if is_dry:
            if use_json:
                _emit_json(
                    {
                        "dry_run": True,
                        "action": "import-env",
                        "profile": target_profile,
                        "keys": imported_keys,
                        "count": len(imported_keys),
                    }
                )
            else:
                print(
                    f"[DRY-RUN] Would import {len(imported_keys)} setting(s) into profile "
                    f"'{target_profile}': {', '.join(imported_keys)}"
                )
            return 0

        path = save_profile_settings(imported, profile=target_profile)
        if use_json:
            _emit_json(
                {
                    "imported": imported_keys,
                    "count": len(imported_keys),
                    "profile": target_profile,
                    "path": str(path),
                }
            )
        else:
            print(
                f"[+] Imported {len(imported_keys)} setting(s) into profile '{target_profile}' "
                f"({path}): {', '.join(imported_keys)}"
            )
        return 0

    if subcmd == "profiles":
        profiles = list_profiles()
        active = get_active_profile_name()
        if use_json:
            _emit_json({"active_profile": active, "profiles": profiles})
        else:
            print("Settings Profiles:")
            for name in profiles:
                marker = "*" if name == active else " "
                print(f"  {marker} {name}")
        return 0

    if subcmd == "use":
        target_profile = validate_profile_name(args.profile)
        create = not bool(getattr(args, "no_create", False))
        if is_dry:
            if use_json:
                _emit_json({"dry_run": True, "action": "use", "profile": target_profile})
            else:
                print(f"[DRY-RUN] Would switch active profile to '{target_profile}'.")
            return 0
        try:
            path = set_active_profile(target_profile, create=create)
        except KeyError as exc:
            raise ValueError(str(exc)) from exc
        if use_json:
            _emit_json({"active_profile": target_profile, "path": str(path)})
        else:
            print(f"[+] Active profile set to '{target_profile}' ({path}).")
        return 0

    if subcmd == "delete-profile":
        target_profile = validate_profile_name(args.profile)
        if is_dry:
            if use_json:
                _emit_json({"dry_run": True, "action": "delete-profile", "profile": target_profile})
            else:
                print(f"[DRY-RUN] Would delete profile '{target_profile}'.")
            return 0
        try:
            path = delete_profile(target_profile)
        except KeyError as exc:
            raise ValueError(str(exc)) from exc
        active = get_active_profile_name()
        if use_json:
            _emit_json({"deleted": target_profile, "active_profile": active, "path": str(path)})
        else:
            print(f"[+] Deleted profile '{target_profile}' (active: '{active}').")
        return 0

    if subcmd == "reset":
        target_profile = getattr(args, "profile", None)
        if target_profile is not None:
            target_profile = validate_profile_name(target_profile)
        else:
            target_profile = get_active_profile_name()
        if is_dry:
            if use_json:
                _emit_json({"dry_run": True, "action": "reset", "profile": target_profile})
            else:
                print(f"[DRY-RUN] Would clear all saved settings in profile '{target_profile}'.")
            return 0
        if not (bool(getattr(args, "yes", False)) or is_auto_approved()):
            msg = (
                f"Approval required to clear saved settings in profile '{target_profile}'. "
                "Pass --yes or set SOCLENS_AUTO_APPROVE=true (or use --dry-run to preview)."
            )
            if use_json:
                print(
                    json.dumps(
                        {"error": msg, "action": "reset", "approval_required": True},
                        indent=2,
                    ),
                    file=sys.stderr,
                )
            else:
                print(f"[-] {msg}", file=sys.stderr)
            return 1
        path = clear_profile_settings(profile=target_profile)
        if use_json:
            _emit_json({"reset": True, "profile": target_profile, "path": str(path)})
        else:
            print(f"[+] Cleared all saved settings in profile '{target_profile}' ({path}).")
        return 0

    return 1


def _emit_cli_error(exc: Exception, *, use_json: bool) -> None:
    if isinstance(exc, RecordedFutureError):
        payload: dict[str, Any] = {
            "error": str(exc),
            "status_code": exc.status_code,
            "trace_id": exc.trace_id,
            "reason": exc.reason,
            "endpoint": exc.endpoint,
        }
        if isinstance(exc, RecordedFutureAuthError):
            payload["permission_type"] = exc.permission_type
        if isinstance(exc, RecordedFutureRateLimitError):
            payload["retry_after"] = exc.retry_after
        if use_json:
            print(json.dumps(payload, indent=2, default=str), file=sys.stderr)
        else:
            trace_note = f" [trace_id={exc.trace_id}]" if exc.trace_id else ""
            print(f"[-] Recorded Future API error{trace_note}: {exc}", file=sys.stderr)
        return

    if isinstance(exc, SentinelOneError):
        s1_payload: dict[str, Any] = {
            "error": str(exc),
            "status_code": exc.status_code,
            "endpoint": exc.endpoint,
            "errors": exc.errors,
        }
        if isinstance(exc, SentinelOneAuthError):
            s1_payload["reason"] = exc.reason
        if isinstance(exc, SentinelOneRateLimitError):
            s1_payload["retry_after"] = exc.retry_after
        if use_json:
            print(json.dumps(s1_payload, indent=2, default=str), file=sys.stderr)
        else:
            print(f"[-] SentinelOne API error: {exc}", file=sys.stderr)
        return

    if use_json:
        print(json.dumps({"error": str(exc), "type": type(exc).__name__}), file=sys.stderr)
    else:
        print(f"[-] Error: {exc}", file=sys.stderr)


def _build_rf_client(args: argparse.Namespace) -> RecordedFutureClient:
    """Instantiate ``RecordedFutureClient`` applying CLI SSL overrides when provided."""
    if bool(getattr(args, "insecure", False)):
        return RecordedFutureClient(verify_ssl=False)
    ca_bundle = getattr(args, "ca_bundle", None)
    if isinstance(ca_bundle, str) and ca_bundle.strip():
        return RecordedFutureClient(verify_ssl=ca_bundle.strip())
    return RecordedFutureClient()


def main() -> None:
    """Primary CLI entrypoint for ``soclens`` and ``python -m soclens.cli``."""
    ensure_utf8_console()

    processed_args = _preprocess_negative_args(sys.argv[1:])
    parser = build_parser()
    args = parser.parse_args(processed_args)

    tz_arg = getattr(args, "timezone", None)
    if tz_arg:
        from soclens.timezone import set_active_timezone

        try:
            set_active_timezone(tz_arg)
        except ConfigurationError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            sys.exit(2)

    global_dry_run = bool(getattr(args, "dry_run", False))
    use_json = bool(getattr(args, "json", False))
    raw_ca_bundle = getattr(args, "ca_bundle", None)
    clean_ca_bundle = (
        raw_ca_bundle.strip() if isinstance(raw_ca_bundle, str) and raw_ca_bundle.strip() else None
    )
    if bool(getattr(args, "insecure", False)) and clean_ca_bundle is not None:
        _emit_cli_error(
            ValueError("Cannot specify both --insecure and --ca-bundle."),
            use_json=use_json,
        )
        sys.exit(1)

    is_tui = bool(args.tui or args.command is None or args.command == "tui")
    is_interactive_wl = (
        args.command == "watchlist" and getattr(args, "subcommand", None) == "interactive"
    )
    configure_logging(enable_console=not (is_tui or is_interactive_wl))

    try:
        if is_tui:
            client = _build_rf_client(args)
            resolved_image_viewer: str | None = (
                "os"
                if bool(getattr(args, "os_image_viewer", False))
                else getattr(args, "image_viewer", None)
            )
            resolved_view: str | None = (
                "admin" if bool(getattr(args, "admin", False)) else getattr(args, "view", None)
            )
            tui_kwargs: dict[str, Any] = {}
            if resolved_image_viewer is not None:
                tui_kwargs["image_viewer"] = resolved_image_viewer
            if resolved_view is not None:
                tui_kwargs["view_mode"] = resolved_view
            if args.command == "tui":
                tui_dry = bool(global_dry_run or getattr(args, "dry_run", False))
                ws_arg = getattr(args, "workspace", None)
                if ws_arg is not None:
                    tui_kwargs["workspace_dir"] = ws_arg
                run_unified_tui(client, dry_run=tui_dry, **tui_kwargs)
            else:
                run_unified_tui(client, dry_run=global_dry_run, **tui_kwargs)
            return

        if args.command == "watchlist":
            client = _build_rf_client(args)
            rc = _handle_watchlist(args, client, global_dry_run=global_dry_run, use_json=use_json)
        elif args.command == "rf":
            client = _build_rf_client(args)
            rc = _handle_rf(args, client, use_json=use_json)
        elif args.command == "research":
            client = _build_rf_client(args)
            rc = _handle_research(args, client, use_json=use_json)
        elif args.command == "sigma":
            client = _build_rf_client(args)
            rc = _handle_sigma(args, client, use_json=use_json)
        elif args.command == "validate":
            rc = _handle_validate(
                args,
                processed_args,
                global_dry_run=global_dry_run,
                use_json=use_json,
            )
        elif args.command == "splunk":
            rc = _handle_splunk(args, global_dry_run=global_dry_run, use_json=use_json)
        elif args.command == "bundle":
            rc = _handle_bundle(args, use_json=use_json)
        elif args.command == "s1":
            rc = _handle_s1(args, global_dry_run=global_dry_run, use_json=use_json)
        elif args.command == "llm":
            rc = _handle_llm(args, use_json=use_json)
        elif args.command == "settings":
            rc = _handle_settings(args, global_dry_run=global_dry_run, use_json=use_json)
        else:
            parser.print_help()
            rc = 1

        if rc != 0:
            sys.exit(rc)
    except (
        ConfigurationError,
        LocalLLMError,
        RecordedFutureError,
        SentinelOneError,
        SigmaConfigurationError,
        SplunkESError,
        SyncLockError,
        FileNotFoundError,
        NotADirectoryError,
        ValueError,
        RuntimeError,
    ) as exc:
        _emit_cli_error(exc, use_json=use_json)
        sys.exit(1)


if __name__ == "__main__":
    main()
