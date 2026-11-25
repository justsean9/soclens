"""Unified, cross-platform CLI entrypoint for the SOCLens."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import csv
import getpass
import inspect
import io
import json
import logging
import math
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
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
    SecretStoreConfig,
    configure_logging,
    ensure_utf8_console,
    get_auto_approve,
    get_secret_store_config,
    get_sentinelone_config,
    get_splunk_config,
    get_splunk_es_tenant_settings,
    get_workspace_dir,
    hydrate_secrets_from_store,
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
from soclens.osint import OSINT_MODULES, OSINTClient
from soclens.research import (
    ALL_RESEARCH_MODULES,
    export_dossier_json,
    export_dossier_markdown,
    probe_api_capabilities,
    render_dossier_markdown,
    research_target,
)
from soclens.secret_stores import (
    SecretStoreError,
    build_secret_store_provider,
    parse_secret_ref,
)
from soclens.sentinelone import (
    ANALYST_VERDICTS,
    CLOUD_ALERT_SCOPES,
    CLOUD_ALERT_SEVERITIES,
    EXCLUSION_ACTIONS,
    EXCLUSION_MODES,
    EXCLUSION_TYPES,
    INCIDENT_STATUSES,
    MAX_EXCLUSION_CLONE_RPS,
    MITIGATION_ACTIONS,
    OS_TYPES,
    PATH_EXCLUSION_TYPES,
    SITE_POLICY_SOURCES,
    SITE_SKUS,
    SITE_TYPES,
    SITE_USAGE_TYPES,
    USER_SCOPES,
    SentinelOneAuthError,
    SentinelOneClient,
    SentinelOneError,
    SentinelOneRateLimitError,
)
from soclens.settings import (
    ENCRYPTION_MODE_OS_KEYSTORE,
    ENCRYPTION_MODE_PASSPHRASE,
    MIN_PASSPHRASE_LENGTH,
    SECRET_MANAGED_SETTING_KEYS,
    SETTING_SPECS_BY_KEY,
    SUPPORTED_ENCRYPTION_MODES,
    SUPPORTED_SECRET_PROVIDERS,
    SettingsCryptoError,
    SettingsLockedError,
    clear_profile_settings,
    collect_env_importable_settings,
    delete_profile,
    describe_all_settings,
    encrypt_settings_store,
    format_setting_display,
    get_active_profile_name,
    get_env_override_for_setting,
    get_saved_setting,
    get_session_override,
    get_settings_storage_info,
    inspect_settings_encryption,
    is_settings_locked,
    list_profiles,
    lock_settings,
    mask_secret,
    parse_vault_secret_map,
    resolve_setting_key,
    rotate_settings_key,
    save_profile_settings,
    serialize_vault_secret_map,
    set_active_profile,
    set_session_overrides,
    unlock_settings,
    validate_profile_name,
    validate_settings_values,
)
from soclens.settings_crypto import get_env_passphrase
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
    MC_FINDING_STATUSES,
    NOTABLE_STATUS_MAP,
    NOTABLE_URGENCIES,
    SPLUNK_ES_APP,
    THREAT_INTEL_COLLECTIONS,
    SplunkESClient,
    SplunkESError,
    extract_finding_tenant,
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


def _callable_accepts_kwarg(fn: Callable[..., Any], kwarg: str) -> bool:
    """Return True if ``fn`` accepts keyword argument ``kwarg`` or ``**kwargs``."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    return kwarg in sig.parameters or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )


def run_unified_tui(
    client: RecordedFutureClient | None = None,
    dry_run: bool = False,
    *,
    initial_tab: str | None = None,
    workspace_dir: Path | str | None = None,
    image_viewer: str | None = None,
    view_mode: str | None = None,
    no_secret_store: bool = False,
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
    if no_secret_store and _callable_accepts_kwarg(create_app, "no_secret_store"):
        create_kwargs["no_secret_store"] = True
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
    parser.add_argument(
        "--no-secret-store",
        dest="no_secret_store",
        action="store_true",
        default=False,
        help="Skip external secret manager / PAM hydration (use env vars or manual settings only)",
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
        help=f"Comma-separated RF or OSINT modules (available: {', '.join(ALL_RESEARCH_MODULES)})",
    )
    res_inv.add_argument("--no-osint", action="store_true", default=False, help="Disable passive free OSINT enrichment (RF only)")
    res_inv.add_argument("--osint-only", action="store_true", default=False, help="Run passive free OSINT only (no RF API token required)")
    res_inv.add_argument(
        "--osint-sources",
        action="append",
        default=None,
        help=f"Comma-separated OSINT sources or aliases (e.g. whois,dns,shodan,vt,otx; available: {', '.join(OSINT_MODULES)})",
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

    res_osint = res_subparsers.add_parser(
        "osint",
        help="Run passive free OSINT enrichment (WHOIS/RDAP, DNS/DoH, GeoIP, BGP, Shodan, crt.sh, VT, OTX, etc.) without needing an RF token",
    )
    res_osint.add_argument("target", nargs="?", default=None, help="Domain, IP, URL, hash, CVE, ASN, or email to enrich")
    res_osint.add_argument(
        "--type",
        choices=["auto", "ip", "domain", "hash", "url", "vulnerability", "asn", "email"],
        default="auto",
        help="Explicit target type override (default: auto-detect)",
    )
    res_osint.add_argument(
        "--sources",
        action="append",
        default=None,
        help="Comma-separated OSINT sources or aliases (e.g. whois,dns,shodan,vt,otx,abuseipdb,abusech)",
    )
    res_osint.add_argument(
        "--list-sources",
        action="store_true",
        default=False,
        help="List all built-in free passive OSINT sources, tiers, and key configuration status",
    )
    res_osint.add_argument("-o", "--output", default=None, help="Optional output file path (.md or .json)")
    res_osint.add_argument(
        "--format",
        choices=["markdown", "json"],
        default=None,
        help="Output file format when --output is set (default: infer from suffix or markdown)",
    )
    res_osint.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

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

    def _add_splunk_conn_args(
        sub: argparse.ArgumentParser,
        *,
        suppress_defaults: bool = False,
    ) -> None:
        opt_default: Any = argparse.SUPPRESS if suppress_defaults else None
        verify_default: Any = argparse.SUPPRESS if suppress_defaults else False
        sub.add_argument("--host", type=str, default=opt_default, help="Splunk Host URL")
        sub.add_argument("--token", type=str, default=opt_default, help="Splunk Bearer Token")
        sub.add_argument(
            "--username", type=str, default=opt_default, help="Splunk Basic Auth Username"
        )
        sub.add_argument(
            "--password", type=str, default=opt_default, help="Splunk Basic Auth Password"
        )
        sub.add_argument(
            "--app",
            type=str,
            default=opt_default,
            help="Splunk app namespace (default: SPLUNK_APP or SplunkEnterpriseSecuritySuite)",
        )
        sub.add_argument(
            "--verify-ssl",
            action="store_true",
            default=verify_default,
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
        "--tenant", type=str, default=None, help="Filter by resolved tenant ID"
    )
    es_notables.add_argument(
        "--use-v2",
        action="store_true",
        default=False,
        help="Use ES 8.6 Mission Control v2 hybrid backend",
    )
    es_notables.add_argument(
        "--disposition", type=str, default=None, help="Filter by notable/finding disposition"
    )
    es_notables.add_argument(
        "--item-type",
        choices=("all", "findings", "finding_groups", "investigations"),
        default="all",
        help="MC v2 queue item type filter (default: all)",
    )
    es_notables.add_argument(
        "--security-domain", type=str, default=None, help="Filter by security domain"
    )
    es_notables.add_argument("--severity", type=str, default=None, help="Filter by severity")
    es_notables.add_argument("--entity", type=str, default=None, help="Filter by entity/risk_object")
    es_notables.add_argument("--src", type=str, default=None, help="Filter by source IP/host")
    es_notables.add_argument("--dest", type=str, default=None, help="Filter by destination IP/host")
    es_notables.add_argument("--user", type=str, default=None, help="Filter by user")
    es_notables.add_argument("--file-hash", type=str, default=None, help="Filter by file hash")
    es_notables.add_argument(
        "--min-risk-score", type=float, default=None, help="Filter by minimum risk score"
    )
    es_notables.add_argument("--orig-sid", type=str, default=None, help="Filter by orig_sid (SPL)")
    es_notables.add_argument(
        "--raw-query", type=str, default=None, help="Raw text / _raw SPL filter"
    )
    es_notables.add_argument(
        "--include-investigations",
        action="store_true",
        default=False,
        help="Include MC v2 investigations alongside findings",
    )
    es_notables.add_argument(
        "--offset", type=int, default=0, help="Pagination offset (default: 0)"
    )
    es_notables.add_argument("--sort", type=str, default=None, help="Sort specification")
    es_notables.add_argument(
        "--use-spl",
        action="store_true",
        default=False,
        help="Force SPL `notable` fallback backend",
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
        "--use-v2",
        action="store_true",
        default=False,
        help="Use MC v2 bulk_update hybrid endpoint (with 404 fallback)",
    )
    es_update.add_argument("--sensitivity", type=str, default=None, help="MC v2 sensitivity level")
    es_update.add_argument("--queue-id", type=str, default=None, help="MC v2 queue ID")
    es_update.add_argument("--earliest", type=str, default=None, help="MC v2 earliest time hint")
    es_update.add_argument("--latest", type=str, default=None, help="MC v2 latest time hint")
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
        "--tenant",
        type=str,
        default=None,
        help="Filter notables by resolved tenant ID before enrichment",
    )
    es_enrich.add_argument(
        "--use-v2",
        action="store_true",
        default=False,
        help="Use ES 8.6 Mission Control v2 hybrid backend when fetching notables",
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

    # 5c. Splunk ES 8.6 Mission Control v2 & Adaptive Response subcommands
    es_inv = es_subparsers.add_parser(
        "investigations",
        help="List, create, update, or attach findings to Splunk ES Mission Control v2 investigations",
    )
    es_inv.add_argument("--tenant", type=str, default=None, help="Filter investigations by tenant ID")
    es_inv.add_argument("--status", type=str, default=None, help="Filter by status")
    es_inv.add_argument(
        "--urgency", choices=NOTABLE_URGENCIES, default=None, help="Filter by urgency"
    )
    es_inv.add_argument("--owner", type=str, default=None, help="Filter by owner")
    es_inv.add_argument("--disposition", type=str, default=None, help="Filter by disposition")
    es_inv.add_argument("--ids", type=str, default=None, help="Comma-separated investigation IDs")
    es_inv.add_argument("--limit", type=int, default=100, help="Max investigations (default: 100)")
    es_inv.add_argument("--offset", type=int, default=0, help="Pagination offset (default: 0)")
    es_inv.add_argument("--sort", type=str, default=None, help="Sort specification")
    es_inv.add_argument(
        "--format", choices=("table", "json"), default="table", help="Output format (default: table)"
    )
    _add_splunk_conn_args(es_inv)
    es_inv_sub = es_inv.add_subparsers(dest="inv_action")

    es_inv_list = es_inv_sub.add_parser("list", help="List Mission Control v2 investigations")
    es_inv_list.add_argument(
        "--tenant", type=str, default=argparse.SUPPRESS, help="Filter by tenant ID"
    )
    es_inv_list.add_argument(
        "--status", type=str, default=argparse.SUPPRESS, help="Filter by status"
    )
    es_inv_list.add_argument(
        "--urgency",
        choices=NOTABLE_URGENCIES,
        default=argparse.SUPPRESS,
        help="Filter by urgency",
    )
    es_inv_list.add_argument(
        "--owner", type=str, default=argparse.SUPPRESS, help="Filter by owner"
    )
    es_inv_list.add_argument(
        "--disposition", type=str, default=argparse.SUPPRESS, help="Filter by disposition"
    )
    es_inv_list.add_argument(
        "--ids", type=str, default=argparse.SUPPRESS, help="Comma-separated investigation IDs"
    )
    es_inv_list.add_argument(
        "--limit",
        type=int,
        default=argparse.SUPPRESS,
        help="Max investigations (default: 100)",
    )
    es_inv_list.add_argument(
        "--offset",
        type=int,
        default=argparse.SUPPRESS,
        help="Pagination offset (default: 0)",
    )
    es_inv_list.add_argument(
        "--sort", type=str, default=argparse.SUPPRESS, help="Sort specification"
    )
    es_inv_list.add_argument(
        "--format",
        choices=("table", "json"),
        default=argparse.SUPPRESS,
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_inv_list, suppress_defaults=True)

    es_inv_create = es_inv_sub.add_parser("create", help="Create a Mission Control v2 investigation")
    es_inv_create.add_argument("--name", required=True, help="Investigation name/title")
    es_inv_create.add_argument("--description", default=None, help="Investigation description")
    es_inv_create.add_argument(
        "--type", dest="investigation_type", default=None, help="Investigation type"
    )
    es_inv_create.add_argument(
        "--status",
        default=argparse.SUPPRESS,
        help=f"Status ({', '.join(MC_FINDING_STATUSES)})",
    )
    es_inv_create.add_argument("--disposition", default=argparse.SUPPRESS, help="Disposition")
    es_inv_create.add_argument("--owner", default=argparse.SUPPRESS, help="Assigned owner")
    es_inv_create.add_argument(
        "--urgency",
        choices=NOTABLE_URGENCIES,
        default=argparse.SUPPRESS,
        help="Urgency level",
    )
    es_inv_create.add_argument("--sensitivity", default=None, help="Sensitivity level")
    es_inv_create.add_argument(
        "--finding-ids", action="append", default=None, help="Finding IDs to attach (comma/repeatable)"
    )
    es_inv_create.add_argument(
        "--finding-times", action="append", default=None, help="Matching finding_times"
    )
    es_inv_create.add_argument("--queue-id", default=None, help="Queue ID")
    es_inv_create.add_argument(
        "--ensure-enriched",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Ensure findings are enriched",
    )
    es_inv_create.add_argument("--yes", action="store_true", default=False, help="Approve creation")
    es_inv_create.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    es_inv_create.add_argument(
        "--format",
        choices=("table", "json"),
        default=argparse.SUPPRESS,
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_inv_create, suppress_defaults=True)

    es_inv_update = es_inv_sub.add_parser("update", help="Update a Mission Control v2 investigation")
    es_inv_update.add_argument("investigation_id", help="Investigation GUID/ID")
    es_inv_update.add_argument("--finding-time", default=None, help="Optional finding_time query param")
    es_inv_update.add_argument("--name", default=None, help="Updated name")
    es_inv_update.add_argument("--description", default=None, help="Updated description")
    es_inv_update.add_argument("--status", default=argparse.SUPPRESS, help="Updated status")
    es_inv_update.add_argument("--owner", default=argparse.SUPPRESS, help="Updated owner")
    es_inv_update.add_argument(
        "--urgency",
        choices=NOTABLE_URGENCIES,
        default=argparse.SUPPRESS,
        help="Updated urgency",
    )
    es_inv_update.add_argument("--sensitivity", default=None, help="Updated sensitivity")
    es_inv_update.add_argument(
        "--type", dest="investigation_type", default=None, help="Updated investigation type"
    )
    es_inv_update.add_argument("--queue-id", default=None, help="Updated queue ID")
    es_inv_update.add_argument("--note", default=None, help="Investigation note text")
    es_inv_update.add_argument("--yes", action="store_true", default=False, help="Approve update")
    es_inv_update.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    es_inv_update.add_argument(
        "--format",
        choices=("table", "json"),
        default=argparse.SUPPRESS,
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_inv_update, suppress_defaults=True)

    es_inv_attach = es_inv_sub.add_parser(
        "add-findings",
        aliases=["attach"],
        help="Attach findings to an existing investigation",
    )
    es_inv_attach.add_argument("investigation_id", help="Target investigation GUID/ID")
    es_inv_attach.add_argument("finding_ids", nargs="+", help="One or more finding IDs to attach")
    es_inv_attach.add_argument(
        "--finding-times", action="append", default=None, help="Optional matching finding_times"
    )
    es_inv_attach.add_argument(
        "--ensure-enriched",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Ensure findings are enriched",
    )
    es_inv_attach.add_argument("--yes", action="store_true", default=False, help="Approve mutation")
    es_inv_attach.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    es_inv_attach.add_argument(
        "--format",
        choices=("table", "json"),
        default=argparse.SUPPRESS,
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_inv_attach, suppress_defaults=True)

    es_notes = es_subparsers.add_parser(
        "notes", help="List, create, update, or delete Mission Control v2 notes"
    )
    es_notes.add_argument("--record-id", default=None, help="Finding or investigation ID")
    es_notes.add_argument("--finding-time", default=None, help="Optional finding_time")
    es_notes.add_argument("--search", default=None, help="Filter notes by search text")
    es_notes.add_argument("--type", dest="note_type", default=None, help="Filter by note type")
    es_notes.add_argument("--limit", type=int, default=50, help="Max notes (default: 50)")
    es_notes.add_argument("--offset", type=int, default=0, help="Pagination offset")
    es_notes.add_argument("--sort", default=None, help="Sort specification")
    es_notes.add_argument(
        "--format", choices=("table", "json"), default="table", help="Output format (default: table)"
    )
    _add_splunk_conn_args(es_notes)
    es_notes_sub = es_notes.add_subparsers(dest="notes_action")

    es_notes_list = es_notes_sub.add_parser("list", help="List notes on a finding or investigation")
    es_notes_list.add_argument("record_id", help="Finding or investigation ID")
    es_notes_list.add_argument(
        "--finding-time", default=argparse.SUPPRESS, help="Optional finding_time"
    )
    es_notes_list.add_argument(
        "--search", default=argparse.SUPPRESS, help="Filter notes by search text"
    )
    es_notes_list.add_argument(
        "--type", dest="note_type", default=argparse.SUPPRESS, help="Filter by note type"
    )
    es_notes_list.add_argument(
        "--limit", type=int, default=argparse.SUPPRESS, help="Max notes (default: 50)"
    )
    es_notes_list.add_argument(
        "--offset", type=int, default=argparse.SUPPRESS, help="Pagination offset"
    )
    es_notes_list.add_argument("--sort", default=argparse.SUPPRESS, help="Sort specification")
    es_notes_list.add_argument(
        "--format",
        choices=("table", "json"),
        default=argparse.SUPPRESS,
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_notes_list, suppress_defaults=True)

    es_notes_create = es_notes_sub.add_parser("create", help="Create a Markdown note")
    es_notes_create.add_argument("record_id", help="Finding or investigation ID")
    es_notes_create.add_argument("--content", required=True, help="Markdown note content")
    es_notes_create.add_argument("--title", default=None, help="Optional note title")
    es_notes_create.add_argument(
        "--finding-time", default=argparse.SUPPRESS, help="Optional finding_time"
    )
    es_notes_create.add_argument("--yes", action="store_true", default=False, help="Approve creation")
    es_notes_create.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    es_notes_create.add_argument(
        "--format",
        choices=("table", "json"),
        default=argparse.SUPPRESS,
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_notes_create, suppress_defaults=True)

    es_notes_update = es_notes_sub.add_parser("update", help="Update an existing note")
    es_notes_update.add_argument("record_id", help="Finding or investigation ID")
    es_notes_update.add_argument("note_id", help="Note ID")
    es_notes_update.add_argument("--title", default=None, help="Updated note title")
    es_notes_update.add_argument("--content", default=None, help="Updated note content")
    es_notes_update.add_argument(
        "--finding-time", default=argparse.SUPPRESS, help="Optional finding_time"
    )
    es_notes_update.add_argument("--yes", action="store_true", default=False, help="Approve update")
    es_notes_update.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    es_notes_update.add_argument(
        "--format",
        choices=("table", "json"),
        default=argparse.SUPPRESS,
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_notes_update, suppress_defaults=True)

    es_notes_del = es_notes_sub.add_parser("delete", help="Delete a note")
    es_notes_del.add_argument("record_id", help="Finding or investigation ID")
    es_notes_del.add_argument("note_id", help="Note ID")
    es_notes_del.add_argument(
        "--finding-time", default=argparse.SUPPRESS, help="Optional finding_time"
    )
    es_notes_del.add_argument("--yes", action="store_true", default=False, help="Approve deletion")
    es_notes_del.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    es_notes_del.add_argument(
        "--format",
        choices=("table", "json"),
        default=argparse.SUPPRESS,
        help="Output format (default: table)",
    )
    _add_splunk_conn_args(es_notes_del, suppress_defaults=True)

    es_history = es_subparsers.add_parser(
        "history", help="Fetch Mission Control v2 audit history for a finding or investigation"
    )
    es_history.add_argument("record_id", help="Finding or investigation ID")
    es_history.add_argument("--finding-time", default=None, help="Optional finding_time")
    es_history.add_argument("--limit", type=int, default=100, help="Max entries (default: 100)")
    es_history.add_argument("--offset", type=int, default=0, help="Pagination offset")
    es_history.add_argument(
        "--exclude-sources", default=None, help="Comma-separated source exclusions"
    )
    es_history.add_argument(
        "--include-findings",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Include linked findings history",
    )
    es_history.add_argument(
        "--format", choices=("table", "json"), default="table", help="Output format (default: table)"
    )
    _add_splunk_conn_args(es_history)

    es_ar_inv = es_subparsers.add_parser(
        "ar-invocations", help="List Adaptive Response modular action invocations"
    )
    es_ar_inv.add_argument("--sid", required=True, help="Originating Splunk search ID (orig_sid)")
    es_ar_inv.add_argument("--rid", required=True, help="Originating result ID (orig_rid)")
    es_ar_inv.add_argument(
        "--format", choices=("table", "json"), default="table", help="Output format (default: table)"
    )
    _add_splunk_conn_args(es_ar_inv)

    es_ar_disp = es_subparsers.add_parser(
        "ar-dispatch", help="List available or dispatch ad-hoc Adaptive Response actions"
    )
    es_ar_disp.add_argument(
        "--list", action="store_true", default=False, help="List available Adaptive Response actions"
    )
    es_ar_disp.add_argument(
        "--all-actions",
        action="store_true",
        default=False,
        help="Include non-adhoc alert actions when using --list",
    )
    es_ar_disp.add_argument("--action", default=None, help="Adaptive Response action name")
    es_ar_disp.add_argument("--sid", default=None, help="Notable orig_sid")
    es_ar_disp.add_argument("--rid", default=None, help="Notable orig_rid")
    es_ar_disp.add_argument(
        "--param",
        action="append",
        default=None,
        help="Action parameter as key=value (repeatable)",
    )
    es_ar_disp.add_argument(
        "--params-json", default=None, help="JSON object of action parameters"
    )
    es_ar_disp.add_argument("--index", default=None, help="Optional target index")
    es_ar_disp.add_argument("--yes", action="store_true", default=False, help="Approve dispatch")
    es_ar_disp.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    es_ar_disp.add_argument(
        "--format", choices=("table", "json"), default="table", help="Output format (default: table)"
    )
    _add_splunk_conn_args(es_ar_disp)

    es_cf = es_subparsers.add_parser(
        "custom-fields",
        help="Inspect tenant settings and auto-discovered Splunk ES custom event_attributes",
    )
    es_cf.add_argument(
        "--refresh", action="store_true", default=False, help="Force refresh from Splunk ES"
    )
    es_cf.add_argument(
        "--offline",
        action="store_true",
        default=False,
        help="Show local tenant/pinned custom field settings without querying Splunk ES",
    )
    es_cf.add_argument(
        "--format", choices=("table", "json"), default="table", help="Output format (default: table)"
    )
    _add_splunk_conn_args(es_cf)

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

    p_s1_agents = s1_sub.add_parser("agents", help="List or manage SentinelOne agents/endpoints")
    p_s1_agents.add_argument("--query", default=None, help="Free-text search query")
    p_s1_agents.add_argument("--computer-name", default=None, help="Filter by hostname substring")
    p_s1_agents.add_argument("--infected", action="store_true", default=None, help="Only infected endpoints")
    p_s1_agents.add_argument("--active", action="store_true", default=None, help="Only active endpoints")
    p_s1_agents.add_argument("--network-status", default=None, help="Filter by network status")
    p_s1_agents.add_argument("--os-type", default=None, choices=sorted(OS_TYPES), help="Filter by OS type")
    p_s1_agents.add_argument("--account-id", default=None, help="Filter by account ID(s)")
    p_s1_agents.add_argument("--site-id", default=None, help="Filter by site ID(s)")
    p_s1_agents.add_argument("--group-id", default=None, help="Filter by group ID(s)")
    p_s1_agents.add_argument("--limit", type=int, default=100, help="Maximum agents to return")
    p_s1_agents.add_argument("--move-to-site", dest="move_to_site", default=None, help="Move --ids to target site ID (Admin)")
    p_s1_agents.add_argument("--decommission", action="store_true", default=False, help="Decommission --ids (Admin)")
    p_s1_agents.add_argument("--fetch-logs", action="store_true", default=False, help="Fetch diagnostic logs for --ids")
    p_s1_agents.add_argument("--ids", nargs="+", default=None, help="Agent ID(s) for flag-mode actions")
    p_s1_agents.add_argument("--yes", action="store_true", default=False, help="Approve agent action")
    p_s1_agents.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without executing")
    p_s1_agents.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    agents_sub = p_s1_agents.add_subparsers(dest="agents_action")

    p_s1_ag_list = agents_sub.add_parser("list", help="List and filter SentinelOne agents")
    p_s1_ag_list.add_argument("--query", default=argparse.SUPPRESS, help="Free-text search query")
    p_s1_ag_list.add_argument("--computer-name", default=argparse.SUPPRESS, help="Filter by hostname substring")
    p_s1_ag_list.add_argument("--infected", action="store_true", default=argparse.SUPPRESS, help="Only infected endpoints")
    p_s1_ag_list.add_argument("--active", action="store_true", default=argparse.SUPPRESS, help="Only active endpoints")
    p_s1_ag_list.add_argument("--network-status", default=argparse.SUPPRESS, help="Filter by network status")
    p_s1_ag_list.add_argument("--os-type", default=argparse.SUPPRESS, choices=sorted(OS_TYPES), help="Filter by OS type")
    p_s1_ag_list.add_argument("--account-id", default=argparse.SUPPRESS, help="Filter by account ID(s)")
    p_s1_ag_list.add_argument("--site-id", default=argparse.SUPPRESS, help="Filter by site ID(s)")
    p_s1_ag_list.add_argument("--group-id", default=argparse.SUPPRESS, help="Filter by group ID(s)")
    p_s1_ag_list.add_argument("--limit", type=int, default=argparse.SUPPRESS, help="Maximum agents to return")
    p_s1_ag_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_ag_logs = agents_sub.add_parser("fetch-logs", help="Fetch diagnostic logs from endpoints")
    p_s1_ag_logs.add_argument("agent_ids", nargs="+", help="One or more SentinelOne agent IDs")
    p_s1_ag_logs.add_argument("--no-agent-logs", action="store_true", default=False, help="Exclude agent logs")
    p_s1_ag_logs.add_argument("--no-customer-logs", action="store_true", default=False, help="Exclude customer-facing logs")
    p_s1_ag_logs.add_argument("--platform-logs", action="store_true", default=False, help="Include platform logs")
    p_s1_ag_logs.add_argument("--yes", action="store_true", default=False, help="Approve log fetch")
    p_s1_ag_logs.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_s1_ag_logs.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_ag_decomm = agents_sub.add_parser("decommission", help="Decommission offline/retired endpoints (Admin)")
    p_s1_ag_decomm.add_argument("agent_ids", nargs="+", help="One or more SentinelOne agent IDs")
    p_s1_ag_decomm.add_argument("--yes", action="store_true", default=False, help="Approve decommission")
    p_s1_ag_decomm.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_s1_ag_decomm.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_ag_move = agents_sub.add_parser("move-to-site", help="Move endpoints to another site (Admin)")
    p_s1_ag_move.add_argument("agent_ids", nargs="+", help="One or more SentinelOne agent IDs")
    p_s1_ag_move.add_argument("--to-site", "--target-site", dest="target_site", required=True, help="Target site ID")
    p_s1_ag_move.add_argument("--yes", action="store_true", default=False, help="Approve move")
    p_s1_ag_move.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_s1_ag_move.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

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

    p_s1_excl = s1_sub.add_parser("exclusions", help="List, manage, validate, or clone SentinelOne exclusions")
    p_s1_excl.add_argument("--create", action="store_true", default=False, help="Create a new exclusion (Admin)")
    p_s1_excl.add_argument("--delete", nargs="+", default=None, help="Delete one or more exclusion IDs (Admin)")
    p_s1_excl.add_argument("--type", dest="exclusion_type", default=None, choices=sorted(EXCLUSION_TYPES), help="Exclusion type")
    p_s1_excl.add_argument("--os-type", default="windows", choices=sorted(OS_TYPES), help="OS type")
    p_s1_excl.add_argument("--value", default=None, help="Exclusion value (path, hash, signer, etc.)")
    p_s1_excl.add_argument("--description", default="", help="Exclusion description")
    p_s1_excl.add_argument("--mode", default="suppress", choices=sorted(EXCLUSION_MODES), help="Exclusion mode (default: suppress)")
    p_s1_excl.add_argument("--path-exclusion-type", default=None, choices=sorted(PATH_EXCLUSION_TYPES), help="Path exclusion scope")
    p_s1_excl.add_argument("--actions", default=None, help=f"Comma-separated actions ({', '.join(sorted(EXCLUSION_ACTIONS))})")
    p_s1_excl.add_argument("--account-id", default=None, help="Account ID scope(s)")
    p_s1_excl.add_argument("--site-id", default=None, help="Site ID scope(s)")
    p_s1_excl.add_argument("--group-id", default=None, help="Group ID scope(s)")
    p_s1_excl.add_argument("--query", default=None, help="Filter listed exclusions by value substring")
    p_s1_excl.add_argument("--limit", type=int, default=100, help="Maximum exclusions to return")
    p_s1_excl.add_argument("--yes", action="store_true", default=False, help="Approve create/delete mutation")
    p_s1_excl.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without executing")
    p_s1_excl.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    excl_sub = p_s1_excl.add_subparsers(dest="exclusions_action")

    p_excl_list = excl_sub.add_parser("list", help="List SentinelOne exclusions")
    p_excl_list.add_argument("--type", dest="exclusion_type", default=argparse.SUPPRESS, choices=sorted(EXCLUSION_TYPES), help="Exclusion type")
    p_excl_list.add_argument("--os-type", dest="filter_os_type", default=None, help="Filter OS type(s)")
    p_excl_list.add_argument("--query", default=argparse.SUPPRESS, help="Filter by value substring")
    p_excl_list.add_argument("--account-id", default=argparse.SUPPRESS, help="Account ID scope(s)")
    p_excl_list.add_argument("--site-id", default=argparse.SUPPRESS, help="Site ID scope(s)")
    p_excl_list.add_argument("--group-id", default=argparse.SUPPRESS, help="Group ID scope(s)")
    p_excl_list.add_argument("--include-parents", action=argparse.BooleanOptionalAction, default=None, help="Include parent exclusions")
    p_excl_list.add_argument("--include-children", action=argparse.BooleanOptionalAction, default=None, help="Include child exclusions")
    p_excl_list.add_argument("--modes", default=None, help="Comma-separated modes filter")
    p_excl_list.add_argument("--scopes", default=None, help="Comma-separated scopes filter")
    p_excl_list.add_argument("--limit", type=int, default=argparse.SUPPRESS, help="Maximum exclusions to return")
    p_excl_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_excl_create = excl_sub.add_parser("create", help="Create a scoped SentinelOne exclusion (Admin)")
    p_excl_create.add_argument("--type", dest="exclusion_type", required=True, choices=sorted(EXCLUSION_TYPES), help="Exclusion type")
    p_excl_create.add_argument("--os-type", default="windows", choices=sorted(OS_TYPES), help="OS type")
    p_excl_create.add_argument("--value", required=True, help="Exclusion value")
    p_excl_create.add_argument("--description", default="", help="Exclusion description")
    p_excl_create.add_argument("--mode", default="suppress", choices=sorted(EXCLUSION_MODES), help="Exclusion mode")
    p_excl_create.add_argument("--path-exclusion-type", default=None, choices=sorted(PATH_EXCLUSION_TYPES), help="Path exclusion type")
    p_excl_create.add_argument("--actions", default=None, help="Comma-separated exclusion actions")
    p_excl_create.add_argument("--account-id", default=None, help="Account ID scope(s)")
    p_excl_create.add_argument("--site-id", default=None, help="Site ID scope(s)")
    p_excl_create.add_argument("--group-id", default=None, help="Group ID scope(s)")
    p_excl_create.add_argument("--yes", action="store_true", default=False, help="Approve creation")
    p_excl_create.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_excl_create.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_excl_update = excl_sub.add_parser("update", help="Update an existing SentinelOne exclusion (Admin)")
    p_excl_update.add_argument("exclusion_id", help="Exclusion ID")
    p_excl_update.add_argument("--type", dest="exclusion_type", required=True, choices=sorted(EXCLUSION_TYPES), help="Exclusion type")
    p_excl_update.add_argument("--os-type", required=True, choices=sorted(OS_TYPES), help="OS type")
    p_excl_update.add_argument("--value", default=None, help="Updated value")
    p_excl_update.add_argument("--description", default=None, help="Updated description")
    p_excl_update.add_argument("--mode", default=None, choices=sorted(EXCLUSION_MODES), help="Updated mode")
    p_excl_update.add_argument("--path-exclusion-type", default=None, choices=sorted(PATH_EXCLUSION_TYPES), help="Updated path exclusion type")
    p_excl_update.add_argument("--actions", default=None, help="Updated comma-separated actions")
    p_excl_update.add_argument("--yes", action="store_true", default=False, help="Approve update")
    p_excl_update.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_excl_update.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_excl_delete = excl_sub.add_parser("delete", help="Delete one or more SentinelOne exclusions (Admin)")
    p_excl_delete.add_argument("ids", nargs="+", help="Exclusion ID(s) to delete")
    p_excl_delete.add_argument("--type", dest="exclusion_type", default=None, choices=sorted(EXCLUSION_TYPES), help="Exclusion type")
    p_excl_delete.add_argument("--yes", action="store_true", default=False, help="Approve deletion")
    p_excl_delete.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_excl_delete.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_excl_validate = excl_sub.add_parser("validate", help="Validate a SentinelOne exclusion before creation")
    p_excl_validate.add_argument("--type", dest="exclusion_type", required=True, choices=sorted(EXCLUSION_TYPES | {"hash"}), help="Exclusion type")
    p_excl_validate.add_argument("--os-type", default="windows", choices=sorted(OS_TYPES), help="OS type")
    p_excl_validate.add_argument("--value", required=True, help="Exclusion value")
    p_excl_validate.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_excl_clone = excl_sub.add_parser("clone", help="Clone site exclusions between sites with rate-limit pacing (Admin)")
    p_excl_clone.add_argument("--from-site", required=True, help="Source site ID")
    p_excl_clone.add_argument("--to-site", required=True, help="Target site ID")
    p_excl_clone.add_argument("--source-site-name", default=None, help="Source site label for provenance note")
    p_excl_clone.add_argument("--include-source-parents", action="store_true", default=False, help="Include inherited account/global source exclusions")
    p_excl_clone.add_argument("--rate-limit", type=float, default=MAX_EXCLUSION_CLONE_RPS, help="Max create requests/sec (capped at 15.0)")
    p_excl_clone.add_argument("--stop-on-error", action="store_true", default=False, help="Abort immediately on first failed exclusion")
    p_excl_clone.add_argument("--limit", type=int, default=5000, help="Max exclusions to scan (default: 5000)")
    p_excl_clone.add_argument("--yes", action="store_true", default=False, help="Approve exclusion cloning")
    p_excl_clone.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview diff without POSTing")
    p_excl_clone.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_block = s1_sub.add_parser("blocklist", help="List, add, update, or remove SentinelOne SHA-1 blocklist entries")
    p_s1_block.add_argument("--add", dest="add_hash", default=None, help="SHA-1 hash to add to blocklist (Admin)")
    p_s1_block.add_argument("--remove", nargs="+", default=None, help="Blocklist entry ID(s) to remove (Admin)")
    p_s1_block.add_argument("--os-type", default="windows", choices=sorted(OS_TYPES), help="OS type")
    p_s1_block.add_argument("--description", default="", help="Blocklist entry description")
    p_s1_block.add_argument("--source", default="soclens", help="Blocklist entry source")
    p_s1_block.add_argument("--account-id", default=None, help="Account ID scope(s)")
    p_s1_block.add_argument("--site-id", default=None, help="Site ID scope(s)")
    p_s1_block.add_argument("--group-id", default=None, help="Group ID scope(s)")
    p_s1_block.add_argument("--query", default=None, help="Filter listed entries by hash substring")
    p_s1_block.add_argument("--limit", type=int, default=100, help="Maximum entries to return")
    p_s1_block.add_argument("--yes", action="store_true", default=False, help="Approve add/remove mutation")
    p_s1_block.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without executing")
    p_s1_block.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    block_sub = p_s1_block.add_subparsers(dest="blocklist_action")

    p_blk_list = block_sub.add_parser("list", help="List SHA-1 blocklist entries")
    p_blk_list.add_argument("--os-type", dest="filter_os_type", default=None, help="Filter OS type(s)")
    p_blk_list.add_argument("--account-id", default=argparse.SUPPRESS, help="Account ID scope(s)")
    p_blk_list.add_argument("--site-id", default=argparse.SUPPRESS, help="Site ID scope(s)")
    p_blk_list.add_argument("--query", default=argparse.SUPPRESS, help="Filter by hash substring")
    p_blk_list.add_argument("--limit", type=int, default=argparse.SUPPRESS, help="Maximum entries to return")
    p_blk_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_blk_add = block_sub.add_parser("add", help="Add a SHA-1 hash to the blocklist (Admin)")
    p_blk_add.add_argument("sha1_hash", help="40-char SHA-1 hash")
    p_blk_add.add_argument("--os-type", default="windows", choices=sorted(OS_TYPES), help="OS type")
    p_blk_add.add_argument("--description", default="", help="Description")
    p_blk_add.add_argument("--source", default="soclens", help="Source")
    p_blk_add.add_argument("--account-id", default=None, help="Account ID scope(s)")
    p_blk_add.add_argument("--site-id", default=None, help="Site ID scope(s)")
    p_blk_add.add_argument("--group-id", default=None, help="Group ID scope(s)")
    p_blk_add.add_argument("--yes", action="store_true", default=False, help="Approve mutation")
    p_blk_add.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_blk_add.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_blk_upd = block_sub.add_parser("update", help="Update a blocklist entry (Admin)")
    p_blk_upd.add_argument("entry_id", help="Blocklist entry ID")
    p_blk_upd.add_argument("--sha1", required=True, help="40-char SHA-1 hash")
    p_blk_upd.add_argument("--os-type", default="windows", choices=sorted(OS_TYPES), help="OS type")
    p_blk_upd.add_argument("--description", default="", help="Description")
    p_blk_upd.add_argument("--source", default="soclens", help="Source")
    p_blk_upd.add_argument("--account-id", default=None, help="Account ID scope(s)")
    p_blk_upd.add_argument("--site-id", default=None, help="Site ID scope(s)")
    p_blk_upd.add_argument("--group-id", default=None, help="Group ID scope(s)")
    p_blk_upd.add_argument("--yes", action="store_true", default=False, help="Approve mutation")
    p_blk_upd.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_blk_upd.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_blk_rem = block_sub.add_parser("remove", help="Remove blocklist entry ID(s) (Admin)")
    p_blk_rem.add_argument("ids", nargs="+", help="Blocklist entry ID(s)")
    p_blk_rem.add_argument("--yes", action="store_true", default=False, help="Approve mutation")
    p_blk_rem.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_blk_rem.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_sites = s1_sub.add_parser("sites", help="List or administer SentinelOne sites, accounts, and groups")
    p_s1_sites.add_argument("--accounts", action="store_true", default=False, help="List accounts instead of sites")
    p_s1_sites.add_argument("--groups", action="store_true", default=False, help="List groups instead of sites")
    p_s1_sites.add_argument("--tier", default=None, help="Filter sites by resolved service tier (e.g. MDR, MSSP, Other)")
    p_s1_sites.add_argument("--query", default=None, help="Search query")
    p_s1_sites.add_argument("--limit", type=int, default=100, help="Maximum items to return")
    p_s1_sites.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    sites_sub = p_s1_sites.add_subparsers(dest="sites_action")

    p_site_list = sites_sub.add_parser("list", help="List SentinelOne sites, accounts, or groups")
    p_site_list.add_argument("--accounts", action="store_true", default=argparse.SUPPRESS, help="List accounts")
    p_site_list.add_argument("--groups", action="store_true", default=argparse.SUPPRESS, help="List groups")
    p_site_list.add_argument("--account-id", default=None, help="Filter sites/groups by account ID(s)")
    p_site_list.add_argument("--site-id", default=None, help="Filter groups by site ID(s)")
    p_site_list.add_argument("--tier", default=argparse.SUPPRESS, help="Filter sites by tier")
    p_site_list.add_argument("--query", default=argparse.SUPPRESS, help="Search query")
    p_site_list.add_argument("--limit", type=int, default=argparse.SUPPRESS, help="Maximum items to return")
    p_site_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_create = sites_sub.add_parser("create", help="Create a new SentinelOne site (Admin)")
    p_site_create.add_argument("--name", required=True, help="Site name")
    p_site_create.add_argument("--account-id", default=None, help="Parent account ID")
    p_site_create.add_argument("--site-type", default="Paid", choices=sorted(SITE_TYPES), help="Site type")
    p_site_create.add_argument("--licenses", "--total-licenses", dest="total_licenses", type=int, default=None, help="Total licenses")
    p_site_create.add_argument("--unlimited-licenses", action="store_true", default=None, help="Unlimited licenses")
    p_site_create.add_argument("--no-unlimited-expiration", action="store_true", default=False, help="Require explicit expiration date")
    p_site_create.add_argument("--expiration", default=None, help="Expiration timestamp (ISO 8601)")
    p_site_create.add_argument("--inherit-account-expiration", action=argparse.BooleanOptionalAction, default=None, help="Inherit account expiration")
    p_site_create.add_argument("--sku", default=None, choices=sorted(SITE_SKUS), help="Site SKU")
    p_site_create.add_argument("--suite", default=None, choices=sorted(SITE_SKUS), help="Site suite")
    p_site_create.add_argument("--description", default="", help="Site description")
    p_site_create.add_argument("--no-inherits", action="store_true", default=False, help="Do not inherit parent policy")
    p_site_create.add_argument("--usage-type", default=None, choices=sorted(SITE_USAGE_TYPES), help="Usage type")
    p_site_create.add_argument("--external-id", default=None, help="External/CRM tenant ID")
    p_site_create.add_argument("--policy-json", default=None, help="Custom policy JSON or file path")
    p_site_create.add_argument("--copy-policy-from", default=None, help="Source site ID to copy policy from")
    p_site_create.add_argument("--clone-exclusions-from", default=None, help="Source site ID to clone exclusions from")
    p_site_create.add_argument("--yes", action="store_true", default=False, help="Approve site creation")
    p_site_create.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_site_create.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_edit = sites_sub.add_parser("edit", help="Edit an existing SentinelOne site (Admin)")
    p_site_edit.add_argument("site_id", help="Target site ID")
    p_site_edit.add_argument("--name", default=None, help="New site name")
    p_site_edit.add_argument("--site-type", default=None, choices=sorted(SITE_TYPES), help="Site type")
    p_site_edit.add_argument("--licenses", "--total-licenses", dest="total_licenses", type=int, default=None, help="Total licenses")
    p_site_edit.add_argument("--unlimited-licenses", action=argparse.BooleanOptionalAction, default=None, help="Unlimited licenses")
    p_site_edit.add_argument("--unlimited-expiration", action=argparse.BooleanOptionalAction, default=None, help="Unlimited expiration")
    p_site_edit.add_argument("--expiration", default=None, help="Expiration timestamp")
    p_site_edit.add_argument("--inherit-account-expiration", action=argparse.BooleanOptionalAction, default=None, help="Inherit account expiration")
    p_site_edit.add_argument("--sku", default=None, choices=sorted(SITE_SKUS), help="Site SKU")
    p_site_edit.add_argument("--description", default=None, help="Description")
    p_site_edit.add_argument("--usage-type", default=None, choices=sorted(SITE_USAGE_TYPES), help="Usage type")
    p_site_edit.add_argument("--external-id", default=None, help="External ID")
    p_site_edit.add_argument("--policy-json", default=None, help="Policy JSON or file path")
    p_site_edit.add_argument("--yes", action="store_true", default=False, help="Approve site update")
    p_site_edit.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_site_edit.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_dup = sites_sub.add_parser("duplicate", help="Duplicate an existing SentinelOne site (Admin)")
    p_site_dup.add_argument("source_site_id", help="Numeric source site ID")
    p_site_dup.add_argument("--name", required=True, help="New site name")
    p_site_dup.add_argument("--policy-source", default="copy_source_site", choices=sorted(SITE_POLICY_SOURCES), help="Policy source")
    p_site_dup.add_argument("--copy-users", action="store_true", default=False, help="Copy site users")
    p_site_dup.add_argument("--licenses", "--total-licenses", dest="total_licenses", type=int, default=None, help="Total licenses")
    p_site_dup.add_argument("--unlimited-licenses", action=argparse.BooleanOptionalAction, default=None, help="Unlimited licenses")
    p_site_dup.add_argument("--policy-json", default=None, help="Custom policy JSON or file path")
    p_site_dup.add_argument("--yes", action="store_true", default=False, help="Approve site duplication")
    p_site_dup.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_site_dup.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_expire = sites_sub.add_parser("expire", help="Expire a SentinelOne site immediately (Admin)")
    p_site_expire.add_argument("site_id", help="Target site ID")
    p_site_expire.add_argument("--yes", action="store_true", default=False, help="Approve expiration")
    p_site_expire.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_site_expire.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_react = sites_sub.add_parser("reactivate", help="Reactivate an expired SentinelOne site (Admin)")
    p_site_react.add_argument("site_id", help="Target site ID")
    p_site_react.add_argument("--unlimited", action=argparse.BooleanOptionalAction, default=True, help="Set unlimited expiration")
    p_site_react.add_argument("--expiration", default=None, help="Optional expiration timestamp")
    p_site_react.add_argument("--yes", action="store_true", default=False, help="Approve reactivation")
    p_site_react.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_site_react.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_rot = sites_sub.add_parser("rotate-token", help="Rotate a site registration token (Admin)")
    p_site_rot.add_argument("site_id", help="Target site ID")
    p_site_rot.add_argument("--yes", action="store_true", default=False, help="Approve token rotation")
    p_site_rot.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_site_rot.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_regen = sites_sub.add_parser("regenerate-key", help="Regenerate a site registration key (Admin)")
    p_site_regen.add_argument("site_id", help="Target site ID")
    p_site_regen.add_argument("--yes", action="store_true", default=False, help="Approve key regeneration")
    p_site_regen.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_site_regen.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_pol = sites_sub.add_parser("policy", help="Inspect, update, or revert a site policy")
    site_pol_sub = p_site_pol.add_subparsers(dest="policy_action")
    p_site_pol_get = site_pol_sub.add_parser("get", help="Fetch site policy")
    p_site_pol_get.add_argument("site_id", help="Site ID")
    p_site_pol_get.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_pol_upd = site_pol_sub.add_parser("update", help="Update site policy (Admin)")
    p_site_pol_upd.add_argument("site_id", help="Site ID")
    p_site_pol_upd.add_argument("--policy-json", required=True, help="Policy JSON string or file path")
    p_site_pol_upd.add_argument("--yes", action="store_true", default=False, help="Approve policy update")
    p_site_pol_upd.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_site_pol_upd.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_pol_rev = site_pol_sub.add_parser("revert", help="Revert site policy to parent account (Admin)")
    p_site_pol_rev.add_argument("site_id", help="Site ID")
    p_site_pol_rev.add_argument("--yes", action="store_true", default=False, help="Approve policy revert")
    p_site_pol_rev.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_site_pol_rev.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_site_del = sites_sub.add_parser("delete", help="Delete a SentinelOne site (Admin + exact --confirm-name)")
    p_site_del.add_argument("site_id", help="Target site ID")
    p_site_del.add_argument("--confirm-name", default=None, help="Exact site name required for confirmation")
    p_site_del.add_argument("--yes", action="store_true", default=False, help="Approve site deletion")
    p_site_del.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_site_del.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_users = s1_sub.add_parser("users", help="List and administer SentinelOne console users")
    p_s1_users.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    users_sub = p_s1_users.add_subparsers(dest="users_action")

    p_usr_list = users_sub.add_parser("list", help="List SentinelOne console users")
    p_usr_list.add_argument("--query", default=None, help="Search query")
    p_usr_list.add_argument("--email", default=None, help="Filter by email")
    p_usr_list.add_argument("--name", "--full-name", dest="full_name", default=None, help="Filter by full name")
    p_usr_list.add_argument("--account-id", default=None, help="Filter by account ID(s)")
    p_usr_list.add_argument("--site-id", default=None, help="Filter by site ID(s)")
    p_usr_list.add_argument("--role-id", default=None, help="Filter by role ID(s)")
    p_usr_list.add_argument("--limit", type=int, default=100, help="Maximum users to return")
    p_usr_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_usr_create = users_sub.add_parser("create", help="Create a SentinelOne console user (Admin)")
    p_usr_create.add_argument("--email", required=True, help="User email address")
    p_usr_create.add_argument("--name", "--full-name", dest="full_name", required=True, help="User full name")
    p_usr_create.add_argument("--scope", default=None, choices=sorted(USER_SCOPES), help="RBAC scope (tenant, account, site)")
    p_usr_create.add_argument("--site-id", default=None, help="Target site ID(s)")
    p_usr_create.add_argument("--account-id", default=None, help="Target account ID(s)")
    p_usr_create.add_argument("--role-id", default=None, help="RBAC role ID")
    p_usr_create.add_argument("--role-name", default=None, help="RBAC role name")
    p_usr_create.add_argument("--scope-roles-json", default=None, help="Raw scopeRoles JSON array")
    p_usr_create.add_argument("--clone-from", default=None, help="Source user ID to clone RBAC permissions from")
    p_usr_create.add_argument("--password", default=None, help="Optional initial password")
    p_usr_create.add_argument("--two-fa", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable 2FA")
    p_usr_create.add_argument("--allow-remote-shell", action=argparse.BooleanOptionalAction, default=None, help="Allow remote shell")
    p_usr_create.add_argument("--yes", action="store_true", default=False, help="Approve user creation")
    p_usr_create.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_usr_create.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_usr_edit = users_sub.add_parser("edit", help="Edit an existing SentinelOne console user (Admin)")
    p_usr_edit.add_argument("user_id", help="Target user ID")
    p_usr_edit.add_argument("--scope", default=None, choices=sorted(USER_SCOPES), help="RBAC scope")
    p_usr_edit.add_argument("--site-id", default=None, help="Target site ID(s)")
    p_usr_edit.add_argument("--account-id", default=None, help="Target account ID(s)")
    p_usr_edit.add_argument("--role-id", default=None, help="RBAC role ID")
    p_usr_edit.add_argument("--role-name", default=None, help="RBAC role name")
    p_usr_edit.add_argument("--scope-roles-json", default=None, help="Raw scopeRoles JSON array")
    p_usr_edit.add_argument("--name", "--full-name", dest="full_name", default=None, help="Updated full name")
    p_usr_edit.add_argument("--email", default=None, help="Updated email")
    p_usr_edit.add_argument("--two-fa", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable 2FA")
    p_usr_edit.add_argument("--can-generate-token", action=argparse.BooleanOptionalAction, default=None, help="Allow API token generation")
    p_usr_edit.add_argument("--yes", action="store_true", default=False, help="Approve user update")
    p_usr_edit.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_usr_edit.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_usr_clone = users_sub.add_parser("clone", help="Clone RBAC permissions from an existing user (Admin)")
    p_usr_clone.add_argument("source_user_id", help="Source user ID")
    p_usr_clone.add_argument("--target-user", default=None, help="Existing target user ID to update")
    p_usr_clone.add_argument("--email", default=None, help="Email for newly created user")
    p_usr_clone.add_argument("--name", "--full-name", dest="full_name", default=None, help="Full name for newly created user")
    p_usr_clone.add_argument("--to-site", action="append", default=None, help="Target site ID(s) to re-scope cloned roles")
    p_usr_clone.add_argument("--service-user", action="store_true", default=False, help="Source ID is a service user")
    p_usr_clone.add_argument("--yes", action="store_true", default=False, help="Approve cloning mutation")
    p_usr_clone.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_usr_clone.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_usr_rpw = users_sub.add_parser("reset-password", help="Send password reset email(s) (Admin)")
    p_usr_rpw.add_argument("user_ids", nargs="+", help="User ID(s)")
    p_usr_rpw.add_argument("--yes", action="store_true", default=False, help="Approve action")
    p_usr_rpw.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_usr_rpw.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_usr_r2fa = users_sub.add_parser("reset-2fa", help="Reset or delete 2FA for user(s) (Admin)")
    p_usr_r2fa.add_argument("user_ids", nargs="+", help="User ID(s)")
    p_usr_r2fa.add_argument("--enroll", action="store_true", default=False, help="Trigger 2FA re-enrollment")
    p_usr_r2fa.add_argument("--delete-2fa", action="store_true", default=False, help="Delete 2FA configuration")
    p_usr_r2fa.add_argument("--yes", action="store_true", default=False, help="Approve action")
    p_usr_r2fa.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_usr_r2fa.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_usr_logout = users_sub.add_parser("logout", help="Log out current SentinelOne API user session (Admin)")
    p_usr_logout.add_argument("--yes", action="store_true", default=False, help="Approve logout")
    p_usr_logout.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_usr_logout.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_usr_del = users_sub.add_parser("delete", help="Delete one or more SentinelOne console users (Admin)")
    p_usr_del.add_argument("user_ids", nargs="+", help="User ID(s)")
    p_usr_del.add_argument("--yes", action="store_true", default=False, help="Approve deletion")
    p_usr_del.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_usr_del.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_su = s1_sub.add_parser("service-users", help="List and administer SentinelOne service users")
    p_s1_su.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    su_sub = p_s1_su.add_subparsers(dest="service_users_action")

    p_su_list = su_sub.add_parser("list", help="List SentinelOne service users")
    p_su_list.add_argument("--query", default=None, help="Search query")
    p_su_list.add_argument("--account-id", default=None, help="Filter by account ID(s)")
    p_su_list.add_argument("--site-id", default=None, help="Filter by site ID(s)")
    p_su_list.add_argument("--role-id", default=None, help="Filter by role ID(s)")
    p_su_list.add_argument("--limit", type=int, default=100, help="Maximum service users to return")
    p_su_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_su_create = su_sub.add_parser("create", help="Create a SentinelOne service user (Admin)")
    p_su_create.add_argument("--name", required=True, help="Service user name")
    p_su_create.add_argument("--expiration-date", required=True, help="Token expiration date (YYYY-MM-DD or ISO 8601)")
    p_su_create.add_argument("--scope", default=None, choices=sorted(USER_SCOPES), help="RBAC scope")
    p_su_create.add_argument("--site-id", default=None, help="Target site ID(s)")
    p_su_create.add_argument("--account-id", default=None, help="Target account ID(s)")
    p_su_create.add_argument("--role-id", default=None, help="RBAC role ID")
    p_su_create.add_argument("--role-name", default=None, help="RBAC role name")
    p_su_create.add_argument("--scope-roles-json", default=None, help="Raw scopeRoles JSON array")
    p_su_create.add_argument("--description", default=None, help="Optional description")
    p_su_create.add_argument("--force-legacy", action=argparse.BooleanOptionalAction, default=None, help="Use legacy token format")
    p_su_create.add_argument("--yes", action="store_true", default=False, help="Approve creation")
    p_su_create.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_su_create.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_su_edit = su_sub.add_parser("edit", help="Update a SentinelOne service user (Admin)")
    p_su_edit.add_argument("service_user_id", help="Service user ID")
    p_su_edit.add_argument("--description", default=None, help="Updated description")
    p_su_edit.add_argument("--scope", default=None, choices=sorted(USER_SCOPES), help="Updated scope")
    p_su_edit.add_argument("--site-id", default=None, help="Target site ID(s)")
    p_su_edit.add_argument("--account-id", default=None, help="Target account ID(s)")
    p_su_edit.add_argument("--role-id", default=None, help="RBAC role ID")
    p_su_edit.add_argument("--role-name", default=None, help="RBAC role name")
    p_su_edit.add_argument("--scope-roles-json", default=None, help="Raw scopeRoles JSON array")
    p_su_edit.add_argument("--yes", action="store_true", default=False, help="Approve update")
    p_su_edit.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_su_edit.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_su_del = su_sub.add_parser("delete", help="Delete one or more SentinelOne service users (Admin)")
    p_su_del.add_argument("service_user_ids", nargs="+", help="Service user ID(s)")
    p_su_del.add_argument("--yes", action="store_true", default=False, help="Approve deletion")
    p_su_del.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_su_del.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_su_tok = su_sub.add_parser("token", help="Generate a new API token for a service user (Admin)")
    p_su_tok.add_argument("service_user_id", help="Service user ID")
    p_su_tok.add_argument("--expiration-date", required=True, help="Expiration date (YYYY-MM-DD or ISO 8601)")
    p_su_tok.add_argument("--yes", action="store_true", default=False, help="Approve token generation")
    p_su_tok.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_su_tok.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_roles = s1_sub.add_parser("roles", help="List SentinelOne RBAC roles")
    p_s1_roles.add_argument("--account-id", default=None, help="Filter by account ID(s)")
    p_s1_roles.add_argument("--site-id", default=None, help="Filter by site ID(s)")
    p_s1_roles.add_argument("--group-id", default=None, help="Filter by group ID(s)")
    p_s1_roles.add_argument("--include-parents", action=argparse.BooleanOptionalAction, default=None, help="Include parent roles")
    p_s1_roles.add_argument("--include-children", action=argparse.BooleanOptionalAction, default=None, help="Include child roles")
    p_s1_roles.add_argument("--predefined-role", action=argparse.BooleanOptionalAction, default=None, help="Filter predefined roles")
    p_s1_roles.add_argument("--name", default=None, help="Filter by exact role name")
    p_s1_roles.add_argument("--query", default=None, help="Search query")
    p_s1_roles.add_argument("--limit", type=int, default=100, help="Maximum roles to return")
    p_s1_roles.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    roles_sub = p_s1_roles.add_subparsers(dest="roles_action")
    p_roles_list = roles_sub.add_parser("list", help="List SentinelOne RBAC roles")
    p_roles_list.add_argument("--account-id", default=argparse.SUPPRESS, help="Filter by account ID(s)")
    p_roles_list.add_argument("--site-id", default=argparse.SUPPRESS, help="Filter by site ID(s)")
    p_roles_list.add_argument("--group-id", default=argparse.SUPPRESS, help="Filter by group ID(s)")
    p_roles_list.add_argument("--include-parents", action=argparse.BooleanOptionalAction, default=argparse.SUPPRESS, help="Include parent roles")
    p_roles_list.add_argument("--include-children", action=argparse.BooleanOptionalAction, default=argparse.SUPPRESS, help="Include child roles")
    p_roles_list.add_argument("--predefined-role", action=argparse.BooleanOptionalAction, default=argparse.SUPPRESS, help="Filter predefined roles")
    p_roles_list.add_argument("--name", default=argparse.SUPPRESS, help="Filter by role name")
    p_roles_list.add_argument("--query", default=argparse.SUPPRESS, help="Search query")
    p_roles_list.add_argument("--limit", type=int, default=argparse.SUPPRESS, help="Maximum roles")
    p_roles_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_s1_ca = s1_sub.add_parser("cloud-alerts", help="List and triage SentinelOne Cloud/STAR detection alerts")
    p_s1_ca.add_argument("--query", default=None, help="Search query")
    p_s1_ca.add_argument("--status", default=None, help=f"Incident status ({', '.join(sorted(INCIDENT_STATUSES))})")
    p_s1_ca.add_argument("--verdict", default=None, help=f"Analyst verdict ({', '.join(sorted(ANALYST_VERDICTS))})")
    p_s1_ca.add_argument("--severity", default=None, help=f"Severity ({', '.join(sorted(CLOUD_ALERT_SEVERITIES))})")
    p_s1_ca.add_argument("--scope", default=None, help=f"Scope ({', '.join(sorted(CLOUD_ALERT_SCOPES))})")
    p_s1_ca.add_argument("--os-type", default=None, help="Filter OS type(s)")
    p_s1_ca.add_argument("--rule-name", default=None, help="Filter by rule name substring")
    p_s1_ca.add_argument("--computer-name", default=None, help="Filter by agent hostname")
    p_s1_ca.add_argument("--sha1", default=None, help="Filter by process SHA-1")
    p_s1_ca.add_argument("--account-id", default=None, help="Account ID(s)")
    p_s1_ca.add_argument("--site-id", default=None, help="Site ID(s)")
    p_s1_ca.add_argument("--group-id", default=None, help="Group ID(s)")
    p_s1_ca.add_argument("--limit", type=int, default=100, help="Maximum alerts to return")
    p_s1_ca.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    ca_sub = p_s1_ca.add_subparsers(dest="cloud_alerts_action")

    p_ca_list = ca_sub.add_parser("list", help="List SentinelOne Cloud/STAR alerts")
    p_ca_list.add_argument("--query", default=argparse.SUPPRESS, help="Search query")
    p_ca_list.add_argument("--status", default=argparse.SUPPRESS, help="Incident status filter")
    p_ca_list.add_argument("--verdict", default=argparse.SUPPRESS, help="Analyst verdict filter")
    p_ca_list.add_argument("--severity", default=argparse.SUPPRESS, help="Severity filter")
    p_ca_list.add_argument("--scope", default=argparse.SUPPRESS, help="Scope filter")
    p_ca_list.add_argument("--os-type", default=argparse.SUPPRESS, help="OS type filter")
    p_ca_list.add_argument("--rule-name", default=argparse.SUPPRESS, help="Rule name substring")
    p_ca_list.add_argument("--computer-name", default=argparse.SUPPRESS, help="Agent hostname")
    p_ca_list.add_argument("--sha1", default=argparse.SUPPRESS, help="Process SHA-1")
    p_ca_list.add_argument("--account-id", default=argparse.SUPPRESS, help="Account ID(s)")
    p_ca_list.add_argument("--site-id", default=argparse.SUPPRESS, help="Site ID(s)")
    p_ca_list.add_argument("--group-id", default=argparse.SUPPRESS, help="Group ID(s)")
    p_ca_list.add_argument("--limit", type=int, default=argparse.SUPPRESS, help="Maximum alerts")
    p_ca_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_ca_verd = ca_sub.add_parser("verdict", help="Update analyst verdict on Cloud/STAR alert(s)")
    p_ca_verd.add_argument("alert_ids", nargs="+", help="Alert ID(s)")
    p_ca_verd.add_argument("--verdict", required=True, choices=sorted(ANALYST_VERDICTS), help="Analyst verdict")
    p_ca_verd.add_argument("--yes", action="store_true", default=False, help="Approve update")
    p_ca_verd.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_ca_verd.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_ca_stat = ca_sub.add_parser("incident-status", help="Update incident status on Cloud/STAR alert(s)")
    p_ca_stat.add_argument("alert_ids", nargs="+", help="Alert ID(s)")
    p_ca_stat.add_argument("--status", required=True, choices=sorted(INCIDENT_STATUSES), help="Incident status")
    p_ca_stat.add_argument("--yes", action="store_true", default=False, help="Approve update")
    p_ca_stat.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Dry run")
    p_ca_stat.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

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

    p_set_enc = settings_sub.add_parser(
        "encrypt",
        help="Encrypt plaintext settings.json or switch between OS keystore and master passphrase mode",
    )
    p_set_enc.add_argument(
        "--mode",
        choices=list(SUPPORTED_ENCRYPTION_MODES),
        default=None,
        help="Encryption mode: 'os_keystore' (auto-unlock) or 'passphrase' (Master Passphrase)",
    )
    p_set_enc.add_argument(
        "--passphrase",
        action="store_true",
        default=False,
        help="Shortcut for --mode passphrase (prompts interactively or reads SOCLENS_SETTINGS_PASSPHRASE)",
    )
    p_set_enc.add_argument(
        "--passphrase-env",
        default=None,
        help="Environment variable holding the target master passphrase (for non-interactive use)",
    )
    p_set_enc.add_argument(
        "--current-passphrase-env",
        default=None,
        help="Environment variable holding the current master passphrase when switching from passphrase mode",
    )
    p_set_enc.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without modifying")
    p_set_enc.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_unlock = settings_sub.add_parser(
        "unlock",
        help="Verify and unlock a passphrase-encrypted settings.json file",
    )
    p_set_unlock.add_argument(
        "--passphrase-env",
        default=None,
        help="Environment variable holding the master passphrase",
    )
    p_set_unlock.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_lock = settings_sub.add_parser(
        "lock",
        help="Clear cached decryption keys from memory and report settings lock status",
    )
    p_set_lock.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_set_rekey = settings_sub.add_parser(
        "rekey",
        help="Rotate the AES-256-GCM data encryption key (and optionally passphrase or OS master KEK)",
    )
    p_set_rekey.add_argument(
        "--new-passphrase",
        action="store_true",
        default=False,
        help="Prompt for a new master passphrase (or read --new-passphrase-env)",
    )
    p_set_rekey.add_argument(
        "--rotate-kek",
        action="store_true",
        default=False,
        help="Also generate a brand-new OS keystore / keyfile master key-wrapping key",
    )
    p_set_rekey.add_argument(
        "--passphrase-env",
        default=None,
        help="Environment variable holding the current master passphrase",
    )
    p_set_rekey.add_argument(
        "--new-passphrase-env",
        default=None,
        help="Environment variable holding the new master passphrase",
    )
    p_set_rekey.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without modifying")
    p_set_rekey.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    # 9. Secret manager / PAM integration subcommands
    secrets_parser = subparsers.add_parser(
        "secrets",
        help="Test, browse, map, and hydrate credentials from an external secret manager / PAM",
    )
    secrets_parser.add_argument(
        "--provider",
        choices=[p for p in SUPPORTED_SECRET_PROVIDERS if p != "none"],
        default=None,
        help="Override configured secret store provider",
    )
    secrets_parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="JSON output",
    )
    secrets_sub = secrets_parser.add_subparsers(dest="secrets_command")

    p_sec_test = secrets_sub.add_parser("test", help="Verify secret store connectivity and auth")
    p_sec_test.add_argument(
        "--provider",
        choices=[p for p in SUPPORTED_SECRET_PROVIDERS if p != "none"],
        default=argparse.SUPPRESS,
        help="Override configured secret store provider",
    )
    p_sec_test.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_sec_list = secrets_sub.add_parser("list", help="Search/list selectable secret entries")
    p_sec_list.add_argument("--search", default="", help="Optional substring filter")
    p_sec_list.add_argument("--limit", type=int, default=100, help="Maximum entries (default: 100)")
    p_sec_list.add_argument(
        "--provider",
        choices=[p for p in SUPPORTED_SECRET_PROVIDERS if p != "none"],
        default=argparse.SUPPRESS,
        help="Override configured secret store provider",
    )
    p_sec_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_sec_fields = secrets_sub.add_parser("fields", help="Inspect available fields for a secret/item ID")
    p_sec_fields.add_argument("secret_id", help="Secret ID, Vault path, or canonical vault reference")
    p_sec_fields.add_argument(
        "--reveal",
        action="store_true",
        default=False,
        help="Fetch and display plaintext field values (masked by default)",
    )
    p_sec_fields.add_argument(
        "--provider",
        choices=[p for p in SUPPORTED_SECRET_PROVIDERS if p != "none"],
        default=argparse.SUPPRESS,
        help="Override configured secret store provider",
    )
    p_sec_fields.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_sec_map = secrets_sub.add_parser("map", help="Bind a SOCLens secret setting key to a vault reference")
    p_sec_map.add_argument("setting_key", help="Secret-managed setting key or env alias (e.g. rf_api_token)")
    p_sec_map.add_argument("vault_ref", help="Canonical vault reference (<provider>:<item_id>:<field_key>)")
    p_sec_map.add_argument("--profile", default=None, help="Target settings profile (default: active)")
    p_sec_map.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without saving")
    p_sec_map.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_sec_unmap = secrets_sub.add_parser("unmap", help="Remove a vault reference mapping for a setting key")
    p_sec_unmap.add_argument("setting_key", help="Secret-managed setting key or env alias")
    p_sec_unmap.add_argument("--profile", default=None, help="Target settings profile (default: active)")
    p_sec_unmap.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without saving")
    p_sec_unmap.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    p_sec_pull = secrets_sub.add_parser("pull", help="Hydrate mapped secrets into process-local memory")
    p_sec_pull.add_argument("--force", action="store_true", default=False, help="Re-hydrate session overrides")
    p_sec_pull.add_argument(
        "--overwrite-existing",
        action="store_true",
        default=False,
        help="Hydrate even when shell environment variables are set",
    )
    p_sec_pull.add_argument(
        "--provider",
        choices=[p for p in SUPPORTED_SECRET_PROVIDERS if p != "none"],
        default=argparse.SUPPRESS,
        help="Override configured secret store provider",
    )
    p_sec_pull.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help="Preview without fetching")
    p_sec_pull.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")

    _attach_ssl_flags_recursive(parser)
    return parser


def _attach_ssl_flags_recursive(
    parser: argparse.ArgumentParser,
    _seen: set[int] | None = None,
) -> None:
    """Attach global flags to all subparsers so flags work before or after subcommands."""
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
            opt_actions = getattr(subparser, "_option_string_actions", {})
            if "--insecure" not in opt_actions and "-k" not in opt_actions:
                subparser.add_argument(
                    "-k",
                    "--insecure",
                    "--no-verify-ssl",
                    dest="insecure",
                    action="store_true",
                    default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS,
                )
            if "--ca-bundle" not in opt_actions:
                subparser.add_argument(
                    "--ca-bundle",
                    dest="ca_bundle",
                    default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS,
                )
            if "--no-secret-store" not in opt_actions:
                subparser.add_argument(
                    "--no-secret-store",
                    dest="no_secret_store",
                    action="store_true",
                    default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS,
                )
            if "--admin" not in opt_actions:
                subparser.add_argument(
                    "--admin",
                    dest="admin",
                    action="store_true",
                    default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS,
                )
            if "--json" not in opt_actions:
                subparser.add_argument(
                    "--json",
                    dest="json",
                    action="store_true",
                    default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS,
                )
            if "--dry-run" not in opt_actions:
                subparser.add_argument(
                    "--dry-run",
                    dest="dry_run",
                    action="store_true",
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
        if bool(getattr(args, "no_secret_store", False)):
            run_unified_tui(
                client,
                dry_run=global_dry_run,
                initial_tab="tab-watchlists",
                no_secret_store=True,
            )
        else:
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


def _handle_research(
    args: argparse.Namespace,
    client: RecordedFutureClient | None,
    *,
    use_json: bool,
) -> int:
    sub = args.research_subcommand
    if not sub:
        print("Specify a `research` subcommand (run `soclens research --help` for options).", file=sys.stderr)
        return 1

    if sub == "osint":
        if getattr(args, "list_sources", False):
            rows = OSINTClient().source_availability()
            if use_json:
                _emit_json(rows)
                return 0
            print(f"{'Source':<44} | {'Tier':<17} | {'Status':<16} | {'Note'}")
            print("-" * 116)
            for row in rows:
                print(
                    f"{str(row['title']):<44} | {str(row['tier']):<17} | "
                    f"{str(row['state']):<16} | {row['note']}"
                )
            return 0
        if not args.target:
            print("[-] Provide a target or pass `--list-sources` for `research osint`.", file=sys.stderr)
            return 1
        osint_srcs = _split_csv_arg(args.sources) or None
        dossier = research_target(
            None,
            args.target,
            explicit_type=args.type,
            include_rf=False,
            include_osint=True,
            osint_sources=osint_srcs,
        )
        if args.output:
            fmt = args.format or ("json" if str(args.output).lower().endswith(".json") else "markdown")
            written = (
                export_dossier_json(dossier, args.output)
                if fmt == "json"
                else export_dossier_markdown(dossier, args.output)
            )
            if not use_json:
                print(f"[+] OSINT dossier written to {written}")
        if use_json:
            _emit_json(dossier.to_dict())
        else:
            print(render_dossier_markdown(dossier))
        return 0

    if sub in ("investigate", "dossier"):
        mods = _split_csv_arg(args.modules) or None
        exts = _split_csv_arg(args.extensions) or None
        osint_srcs = _split_csv_arg(getattr(args, "osint_sources", None)) or None
        osint_only = bool(getattr(args, "osint_only", False))
        no_osint = bool(getattr(args, "no_osint", False))
        kwargs: dict[str, Any] = {
            "explicit_type": args.type,
            "modules": mods,
            "deep": bool(args.deep),
            "extensions": exts,
            "links_scope": args.links_scope,
            "links_timeframe": args.links_timeframe,
            "limit": args.limit,
        }
        if osint_only:
            kwargs["include_rf"] = False
            kwargs["include_osint"] = True
        elif no_osint:
            kwargs["include_osint"] = False
        if osint_srcs is not None:
            kwargs["osint_sources"] = osint_srcs
        dossier = research_target(
            None if osint_only else client,
            args.target,
            **kwargs,
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

    if client is None:
        client = RecordedFutureClient()

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


def _parse_json_mapping_arg(raw: str | None, *, flag_name: str) -> dict[str, Any] | None:
    """Parse a CLI JSON object string or file path into a ``dict``."""
    if raw is None:
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    text = cleaned
    if not cleaned.startswith("{"):
        path = Path(cleaned[1:] if cleaned.startswith("@") else cleaned).expanduser()
        if path.is_file():
            text = path.read_text(encoding="utf-8")
    try:
        loaded: Any = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"Invalid JSON for {flag_name}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"{flag_name} must decode to a JSON object.")
    return loaded


def _parse_json_list_arg(raw: str | None, *, flag_name: str) -> list[dict[str, Any]] | None:
    """Parse a CLI JSON array of objects into ``list[dict[str, Any]]``."""
    if raw is None:
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    try:
        loaded: Any = json.loads(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid JSON for {flag_name}: {exc}") from exc
    if not isinstance(loaded, list) or not all(isinstance(item, dict) for item in loaded):
        raise ValueError(f"{flag_name} must decode to a JSON array of objects.")
    return loaded


def _parse_kv_params(
    param_items: list[str] | None,
    params_json: str | None,
) -> dict[str, Any]:
    """Combine ``--params-json`` and repeatable ``--param key=value`` options."""
    merged: dict[str, Any] = {}
    parsed_json = _parse_json_mapping_arg(params_json, flag_name="--params-json")
    if parsed_json:
        merged.update(parsed_json)
    for item in param_items or ():
        if "=" not in item:
            raise ValueError(f"Invalid --param {item!r}. Expected 'key=value' format.")
        key, val = item.split("=", 1)
        clean_k = key.strip()
        if not clean_k:
            raise ValueError(f"Invalid --param {item!r}. Key must be non-empty.")
        merged[clean_k] = val
    return merged


def _check_es_write_guard(
    args: argparse.Namespace,
    *,
    global_dry_run: bool,
    emit_json: bool,
    action: str,
    target: dict[str, Any],
) -> tuple[bool, int]:
    """Enforce ``--dry-run`` and ``--yes`` / ``SOCLENS_AUTO_APPROVE`` for ES v2.1 writes."""
    is_dry = bool(global_dry_run or getattr(args, "dry_run", False))
    if is_dry:
        payload = {"dry_run": True, "action": action, **target}
        if emit_json:
            _emit_json(payload)
        else:
            print(f"[DRY-RUN] Would execute Splunk ES action '{action}': {json.dumps(target, default=str)}")
        return False, 0

    if not (bool(getattr(args, "yes", False)) or is_auto_approved()):
        msg = (
            f"Approval required for Splunk ES write action '{action}'. "
            "Pass --yes or set SOCLENS_AUTO_APPROVE=true (or use --dry-run to preview)."
        )
        if emit_json:
            print(json.dumps({"error": msg, "action": action, "approval_required": True}, indent=2), file=sys.stderr)
        else:
            print(f"[-] {msg}", file=sys.stderr)
        return False, 1

    return True, 0


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
        preview: dict[str, Any] = {
            "dry_run": True,
            "event_id": args.event_id,
            "status": args.status,
            "urgency": args.urgency,
            "owner": args.owner,
            "disposition": args.disposition,
            "comment": args.comment,
        }
        if bool(getattr(args, "use_v2", False)):
            preview["use_v2"] = True
        if getattr(args, "sensitivity", None) is not None:
            preview["sensitivity"] = args.sensitivity
        if getattr(args, "queue_id", None) is not None:
            preview["queue_id"] = args.queue_id
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

    if es_sub == "custom-fields" and bool(getattr(args, "offline", False)):
        tenant_cfg = get_splunk_es_tenant_settings()
        payload_cf: dict[str, Any] = {
            "tenant_field": tenant_cfg.tenant_field,
            "tenant_aliases": list(tenant_cfg.tenant_aliases),
            "pinned_custom_fields": list(tenant_cfg.custom_fields),
            "discovered_fields": [],
            "offline": True,
        }
        if emit_json:
            _emit_json(payload_cf)
        else:
            print(f"Tenant Field  : {tenant_cfg.tenant_field}")
            print(f"Tenant Aliases: {', '.join(tenant_cfg.tenant_aliases)}")
            print(f"Pinned Fields : {', '.join(tenant_cfg.custom_fields) or '(none)'}")
        return 0

    if es_sub == "investigations":
        inv_act = getattr(args, "inv_action", None) or "list"
        if inv_act == "create":
            fids = _split_csv_arg(getattr(args, "finding_ids", None))
            ftimes = _split_csv_arg(getattr(args, "finding_times", None))
            proceed, rc = _check_es_write_guard(
                args,
                global_dry_run=global_dry_run,
                emit_json=emit_json,
                action="create-investigation",
                target={"name": args.name, "finding_ids": fids},
            )
            if not proceed:
                return rc
            with _build_splunk_es_client_from_args(args) as es:
                created_inv = es.create_investigation(
                    args.name,
                    description=args.description,
                    investigation_type=args.investigation_type,
                    status=args.status,
                    disposition=args.disposition,
                    owner=args.owner,
                    urgency=args.urgency,
                    sensitivity=args.sensitivity,
                    finding_ids=fids or None,
                    finding_times=ftimes or None,
                    queue_id=args.queue_id,
                    ensure_enriched=args.ensure_enriched,
                )
            if emit_json:
                _emit_json(created_inv)
            else:
                print(
                    f"[+] Created Splunk ES investigation '{created_inv.get('name', args.name)}' "
                    f"(id={created_inv.get('investigation_guid') or created_inv.get('id', '-')})."
                )
            return 0

        if inv_act == "update":
            proceed, rc = _check_es_write_guard(
                args,
                global_dry_run=global_dry_run,
                emit_json=emit_json,
                action="update-investigation",
                target={"investigation_id": args.investigation_id},
            )
            if not proceed:
                return rc
            with _build_splunk_es_client_from_args(args) as es:
                updated_inv = es.update_investigation(
                    args.investigation_id,
                    finding_time=args.finding_time,
                    name=args.name,
                    description=args.description,
                    status=args.status,
                    owner=args.owner,
                    urgency=args.urgency,
                    sensitivity=args.sensitivity,
                    investigation_type=args.investigation_type,
                    queue_id=args.queue_id,
                    investigation_note=args.note,
                )
            if emit_json:
                _emit_json(updated_inv)
            else:
                print(f"[+] Updated Splunk ES investigation '{args.investigation_id}'.")
            return 0

        if inv_act in ("add-findings", "attach"):
            fids = _split_csv_arg(args.finding_ids)
            ftimes = _split_csv_arg(getattr(args, "finding_times", None))
            proceed, rc = _check_es_write_guard(
                args,
                global_dry_run=global_dry_run,
                emit_json=emit_json,
                action="add-findings-to-investigation",
                target={"investigation_id": args.investigation_id, "finding_ids": fids},
            )
            if not proceed:
                return rc
            with _build_splunk_es_client_from_args(args) as es:
                attached = es.add_findings_to_investigation(
                    args.investigation_id,
                    fids,
                    finding_times=ftimes or None,
                    ensure_enriched=args.ensure_enriched,
                )
            if emit_json:
                _emit_json(attached)
            else:
                print(f"[+] Attached {len(fids)} finding(s) to investigation '{args.investigation_id}'.")
            return 0

    if es_sub == "notes":
        notes_act = getattr(args, "notes_action", None) or "list"
        if notes_act == "create":
            proceed, rc = _check_es_write_guard(
                args,
                global_dry_run=global_dry_run,
                emit_json=emit_json,
                action="create-note",
                target={"record_id": args.record_id, "title": args.title},
            )
            if not proceed:
                return rc
            with _build_splunk_es_client_from_args(args) as es:
                note_res = es.create_note(
                    args.record_id,
                    args.content,
                    title=args.title,
                    finding_time=args.finding_time,
                )
            if emit_json:
                _emit_json(note_res)
            else:
                print(f"[+] Created note on '{args.record_id}'.")
            return 0

        if notes_act == "update":
            proceed, rc = _check_es_write_guard(
                args,
                global_dry_run=global_dry_run,
                emit_json=emit_json,
                action="update-note",
                target={"record_id": args.record_id, "note_id": args.note_id},
            )
            if not proceed:
                return rc
            with _build_splunk_es_client_from_args(args) as es:
                note_res = es.update_note(
                    args.record_id,
                    args.note_id,
                    title=args.title,
                    content=args.content,
                    finding_time=args.finding_time,
                )
            if emit_json:
                _emit_json(note_res)
            else:
                print(f"[+] Updated note '{args.note_id}' on '{args.record_id}'.")
            return 0

        if notes_act == "delete":
            proceed, rc = _check_es_write_guard(
                args,
                global_dry_run=global_dry_run,
                emit_json=emit_json,
                action="delete-note",
                target={"record_id": args.record_id, "note_id": args.note_id},
            )
            if not proceed:
                return rc
            with _build_splunk_es_client_from_args(args) as es:
                del_res = es.delete_note(
                    args.record_id,
                    args.note_id,
                    finding_time=args.finding_time,
                )
            if emit_json:
                _emit_json(del_res)
            else:
                print(f"[+] Deleted note '{args.note_id}' from '{args.record_id}'.")
            return 0

    if es_sub == "ar-dispatch" and not bool(getattr(args, "list", False)):
        action_name = str(getattr(args, "action", None) or "").strip()
        sid_val = str(getattr(args, "sid", None) or "").strip()
        rid_val = str(getattr(args, "rid", None) or "").strip()
        if not action_name or not sid_val or not rid_val:
            raise ValueError(
                "Specify --list to browse actions, or provide --action, --sid, and --rid to dispatch."
            )
        ar_params = _parse_kv_params(getattr(args, "param", None), getattr(args, "params_json", None))
        proceed, rc = _check_es_write_guard(
            args,
            global_dry_run=global_dry_run,
            emit_json=emit_json,
            action="ar-dispatch",
            target={
                "action_name": action_name,
                "sid": sid_val,
                "rid": rid_val,
                "params": ar_params,
                "index": getattr(args, "index", None),
            },
        )
        if not proceed:
            return rc
        with _build_splunk_es_client_from_args(args) as es:
            disp_res = es.dispatch_adaptive_response(
                action_name,
                sid=sid_val,
                rid=rid_val,
                params=ar_params or None,
                index=getattr(args, "index", None),
            )
        if emit_json:
            _emit_json(disp_res)
        else:
            print(f"[+] Dispatched Adaptive Response action '{action_name}' (sid={sid_val}, rid={rid_val}).")
        return 0

    with _build_splunk_es_client_from_args(args) as es:
        if es_sub == "notables":
            use_hybrid = any(
                [
                    bool(getattr(args, "use_v2", False)),
                    bool(getattr(args, "tenant", None)),
                    bool(getattr(args, "disposition", None)),
                    getattr(args, "item_type", "all") != "all",
                    bool(getattr(args, "security_domain", None)),
                    bool(getattr(args, "severity", None)),
                    bool(getattr(args, "entity", None)),
                    bool(getattr(args, "src", None)),
                    bool(getattr(args, "dest", None)),
                    bool(getattr(args, "user", None)),
                    bool(getattr(args, "file_hash", None)),
                    getattr(args, "min_risk_score", None) is not None,
                    bool(getattr(args, "orig_sid", None)),
                    bool(getattr(args, "raw_query", None)),
                    bool(getattr(args, "include_investigations", False)),
                    int(getattr(args, "offset", 0) or 0) != 0,
                    bool(getattr(args, "sort", None)),
                    bool(getattr(args, "use_spl", False)),
                ]
            )
            if use_hybrid:
                hybrid_res = es.query_findings_hybrid(
                    earliest=args.earliest,
                    latest=args.latest,
                    urgency=args.urgency,
                    status=args.status,
                    owner=args.owner,
                    disposition=getattr(args, "disposition", None),
                    rule_name=args.rule_name,
                    search_text=args.search_text,
                    tenant_id=getattr(args, "tenant", None),
                    security_domain=getattr(args, "security_domain", None),
                    severity=getattr(args, "severity", None),
                    entity=getattr(args, "entity", None),
                    src=getattr(args, "src", None),
                    dest=getattr(args, "dest", None),
                    user=getattr(args, "user", None),
                    file_hash=getattr(args, "file_hash", None),
                    min_risk_score=getattr(args, "min_risk_score", None),
                    orig_sid=getattr(args, "orig_sid", None),
                    raw_query=getattr(args, "raw_query", None),
                    item_type=getattr(args, "item_type", "all"),
                    limit=args.limit,
                    offset=int(getattr(args, "offset", 0) or 0),
                    sort=getattr(args, "sort", None),
                    use_spl=bool(getattr(args, "use_spl", False)),
                    include_investigations=bool(getattr(args, "include_investigations", False)),
                )
                notables = list(hybrid_res.get("items") or [])
                if emit_json:
                    _emit_json(
                        {
                            "count": len(notables),
                            "total": hybrid_res.get("total", len(notables)),
                            "offset": hybrid_res.get("offset", 0),
                            "limit": hybrid_res.get("limit", args.limit),
                            "source_backend": hybrid_res.get("source_backend", "mc_v2"),
                            "notables": notables,
                        }
                    )
                    return 0
                _print_cli_table(
                    notables,
                    [
                        "_time",
                        "event_id",
                        "tenant_id",
                        "urgency",
                        "status_label",
                        "rule_name",
                        "owner",
                        "src",
                        "dest",
                    ],
                )
                return 0

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
            use_v2_triage = bool(
                getattr(args, "use_v2", False)
                or getattr(args, "sensitivity", None) is not None
                or getattr(args, "queue_id", None) is not None
            )
            if use_v2_triage:
                resp = es.triage_findings_hybrid(
                    [args.event_id],
                    status=args.status,
                    urgency=args.urgency,
                    owner=args.owner,
                    disposition=args.disposition,
                    sensitivity=getattr(args, "sensitivity", None),
                    queue_id=getattr(args, "queue_id", None),
                    note=args.comment,
                    earliest=getattr(args, "earliest", None),
                    latest=getattr(args, "latest", None),
                )
            else:
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

        if es_sub == "investigations":
            tenant_filter = str(getattr(args, "tenant", None) or "").strip()
            raw_inv_limit = getattr(args, "limit", 100)
            raw_inv_offset = getattr(args, "offset", 0)
            invs = es.list_investigations(
                ids=_split_csv_arg(getattr(args, "ids", None)) or None,
                limit=100 if raw_inv_limit is None else int(raw_inv_limit),
                offset=0 if raw_inv_offset is None else int(raw_inv_offset),
                sort=getattr(args, "sort", None),
                disposition=getattr(args, "disposition", None),
                status=getattr(args, "status", None),
                owner=getattr(args, "owner", None),
                urgency=getattr(args, "urgency", None),
            )
            if tenant_filter:
                tenant_cfg = get_splunk_es_tenant_settings()
                want_low = tenant_filter.casefold()
                invs = [
                    inv
                    for inv in invs
                    if (
                        str(extract_finding_tenant(inv, tenant_cfg) or inv.get("tenant_id") or "")
                        .strip()
                        .casefold()
                        == want_low
                    )
                ]
            if emit_json:
                _emit_json({"count": len(invs), "investigations": invs})
                return 0
            _print_cli_table(
                invs,
                [
                    "event_id",
                    "tenant_id",
                    "name",
                    "status_label",
                    "urgency",
                    "owner",
                    "disposition_label",
                ],
            )
            return 0

        if es_sub == "notes":
            record_id = str(getattr(args, "record_id", None) or "").strip()
            if not record_id:
                raise ValueError("--record-id is required (or use 'notes list <record_id>').")
            raw_notes_limit = getattr(args, "limit", 50)
            raw_notes_offset = getattr(args, "offset", 0)
            notes_res = es.list_notes(
                record_id,
                finding_time=getattr(args, "finding_time", None),
                search=getattr(args, "search", None),
                note_type=getattr(args, "note_type", None),
                limit=50 if raw_notes_limit is None else int(raw_notes_limit),
                offset=0 if raw_notes_offset is None else int(raw_notes_offset),
                sort=getattr(args, "sort", None),
            )
            if emit_json:
                _emit_json({"record_id": record_id, **notes_res})
                return 0
            _print_cli_table(
                list(notes_res.get("items") or []),
                ["id", "title", "author", "create_time", "content"],
            )
            return 0

        if es_sub == "history":
            hist = es.get_history(
                args.record_id,
                finding_time=args.finding_time,
                limit=args.limit,
                offset=args.offset,
                exclude_sources=_split_csv_arg(args.exclude_sources) or None,
                include_findings=args.include_findings,
            )
            if emit_json:
                _emit_json({"record_id": args.record_id, **hist})
                return 0
            _print_cli_table(
                list(hist.get("items") or []),
                ["time", "author", "action", "field", "old_value", "new_value", "source"],
            )
            return 0

        if es_sub == "ar-invocations":
            invs_ar = es.list_modaction_invocations(args.sid, args.rid)
            if emit_json:
                _emit_json(
                    {
                        "sid": args.sid,
                        "rid": args.rid,
                        "count": len(invs_ar),
                        "invocations": invs_ar,
                    }
                )
                return 0
            cols = list(invs_ar[0].keys()) if invs_ar else ["action_name", "status", "sid", "rid"]
            _print_cli_table(invs_ar, cols)
            return 0

        if es_sub == "ar-dispatch":
            actions = es.list_adaptive_response_actions(
                adhoc_only=not bool(getattr(args, "all_actions", False)),
            )
            if emit_json:
                _emit_json({"count": len(actions), "actions": actions})
                return 0
            _print_cli_table(
                actions,
                ["name", "label", "supports_adhoc", "required_params", "description"],
            )
            return 0

        if es_sub == "custom-fields":
            tenant_cfg = get_splunk_es_tenant_settings()
            discovered = es.discover_custom_fields(force_refresh=bool(getattr(args, "refresh", False)))
            if emit_json:
                _emit_json(
                    {
                        "tenant_field": tenant_cfg.tenant_field,
                        "tenant_aliases": list(tenant_cfg.tenant_aliases),
                        "pinned_custom_fields": list(tenant_cfg.custom_fields),
                        "discovered_fields": discovered,
                        "offline": False,
                    }
                )
                return 0
            print(f"Tenant Field  : {tenant_cfg.tenant_field}")
            print(f"Tenant Aliases: {', '.join(tenant_cfg.tenant_aliases)}")
            print(f"Pinned Fields : {', '.join(tenant_cfg.custom_fields) or '(none)'}")
            _print_cli_table(discovered, ["field", "label"])
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
            elif getattr(args, "tenant", None) or bool(getattr(args, "use_v2", False)):
                hybrid_res = es.query_findings_hybrid(
                    earliest=args.earliest,
                    latest=args.latest,
                    urgency=args.urgency,
                    status=args.status,
                    tenant_id=getattr(args, "tenant", None),
                    limit=args.limit,
                )
                raw_events = list(hybrid_res.get("items") or [])
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


def _check_s1_admin_guard(
    args: argparse.Namespace,
    *,
    use_json: bool,
    action: str,
) -> tuple[bool, int]:
    """Enforce ``--admin`` (or ``--view admin``) for SentinelOne administrative mutations."""
    if bool(getattr(args, "admin", False)) or getattr(args, "view", None) == "admin":
        return True, 0
    msg = (
        f"Admin mode required for SentinelOne administrative action '{action}'. "
        "Pass --admin to authorize administrative mutations."
    )
    if use_json:
        print(
            json.dumps(
                {"error": msg, "action": action, "admin_required": True},
                indent=2,
            ),
            file=sys.stderr,
        )
    else:
        print(f"[-] {msg}", file=sys.stderr)
    return False, 1


def _resolve_s1_scope_and_roles(
    args: argparse.Namespace,
    *,
    client: SentinelOneClient | None = None,
    default_scope: str | None = None,
) -> tuple[str, list[dict[str, Any]] | None]:
    """Resolve ``(scope, scopeRoles)`` from CLI flags or ``--clone-from``."""
    raw_scope = getattr(args, "scope", None)
    site_ids = _split_csv_arg(getattr(args, "site_id", None) or getattr(args, "s1_site_id", None))
    account_ids = _split_csv_arg(
        getattr(args, "account_id", None) or getattr(args, "s1_account_id", None)
    )
    if raw_scope:
        scope = str(raw_scope).strip().lower()
    elif site_ids:
        scope = "site"
    elif account_ids:
        scope = "account"
    else:
        scope = (default_scope or "tenant").strip().lower()

    scope_roles_json = getattr(args, "scope_roles_json", None)
    if scope_roles_json:
        parsed_roles = _parse_json_list_arg(scope_roles_json, flag_name="--scope-roles-json")
        return scope, parsed_roles

    clone_from = getattr(args, "clone_from", None)
    if clone_from and client is not None:
        cloned = client.clone_user_permissions(
            str(clone_from),
            target_site_ids=site_ids or None,
        )
        resolved_scope = str(raw_scope or cloned.get("scope") or scope).strip().lower()
        raw_cloned_roles = cloned.get("scopeRoles")
        roles_list = (
            [dict(r) for r in raw_cloned_roles if isinstance(r, dict)]
            if isinstance(raw_cloned_roles, list)
            else None
        )
        return resolved_scope, roles_list

    role_id = getattr(args, "role_id", None)
    role_name = getattr(args, "role_name", None)
    if role_id or role_name:
        template: dict[str, Any] = {}
        if role_id:
            template["roleId"] = str(role_id).strip()
        elif role_name:
            template["roleName"] = str(role_name).strip()
        if scope == "site" and site_ids:
            return scope, [{"id": sid, **template} for sid in site_ids]
        if scope == "account" and account_ids:
            return scope, [{"id": aid, **template} for aid in account_ids]
        return scope, [template]

    return scope, None


def _handle_s1(
    args: argparse.Namespace,
    *,
    global_dry_run: bool,
    use_json: bool,
) -> int:
    subcmd = getattr(args, "s1_command", None)
    if not subcmd:
        print(
            "Usage: soclens s1 {status,agents,isolate,reconnect,scan,reboot,threats,triage,mitigate,exclusions,blocklist,sites,users,service-users,roles,cloud-alerts,activities}",
            file=sys.stderr,
        )
        return 1

    # Ops active response commands (no --admin required, --yes/--dry-run enforced)
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

    if subcmd == "agents":
        ag_action = getattr(args, "agents_action", None)
        flag_ids = _split_csv_arg(getattr(args, "ids", None))
        if ag_action is None and (
            getattr(args, "move_to_site", None)
            or bool(getattr(args, "decommission", False))
            or bool(getattr(args, "fetch_logs", False))
        ):
            if not flag_ids:
                raise ValueError("--ids is required with --move-to-site, --decommission, or --fetch-logs.")
            if getattr(args, "move_to_site", None):
                ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="agents-move-to-site")
                if not ok_admin:
                    return rc
                proceed, rc = _check_s1_write_guard(
                    args,
                    global_dry_run=global_dry_run,
                    use_json=use_json,
                    action="agents-move-to-site",
                    target={"agent_ids": flag_ids, "target_site_id": args.move_to_site},
                )
                if not proceed:
                    return rc
                with _build_s1_client(args) as client:
                    res = client.move_agents_to_site(flag_ids, args.move_to_site)
                if use_json:
                    _emit_json(res)
                else:
                    print(f"[+] Moved {len(flag_ids)} SentinelOne agent(s) to site '{args.move_to_site}'.")
                return 0

            if bool(getattr(args, "decommission", False)):
                ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="agents-decommission")
                if not ok_admin:
                    return rc
                proceed, rc = _check_s1_write_guard(
                    args,
                    global_dry_run=global_dry_run,
                    use_json=use_json,
                    action="agents-decommission",
                    target={"agent_ids": flag_ids},
                )
                if not proceed:
                    return rc
                with _build_s1_client(args) as client:
                    res = client.decommission_agents(flag_ids)
                if use_json:
                    _emit_json(res)
                else:
                    print(f"[+] Decommissioned {len(flag_ids)} SentinelOne agent(s).")
                return 0

            if bool(getattr(args, "fetch_logs", False)):
                proceed, rc = _check_s1_write_guard(
                    args,
                    global_dry_run=global_dry_run,
                    use_json=use_json,
                    action="agents-fetch-logs",
                    target={"agent_ids": flag_ids},
                )
                if not proceed:
                    return rc
                with _build_s1_client(args) as client:
                    res = client.fetch_agent_logs(flag_ids)
                if use_json:
                    _emit_json(res)
                else:
                    print(f"[+] Requested diagnostic logs for {len(flag_ids)} SentinelOne agent(s).")
                return 0

        if ag_action == "fetch-logs":
            ids = _split_csv_arg(args.agent_ids)
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="agents-fetch-logs",
                target={"agent_ids": ids},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.fetch_agent_logs(
                    ids,
                    agent_logs=not bool(args.no_agent_logs),
                    customer_facing_logs=not bool(args.no_customer_logs),
                    platform_logs=bool(args.platform_logs),
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Requested diagnostic logs for {len(ids)} SentinelOne agent(s).")
            return 0

        if ag_action == "decommission":
            ids = _split_csv_arg(args.agent_ids)
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="agents-decommission")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="agents-decommission",
                target={"agent_ids": ids},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.decommission_agents(ids)
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Decommissioned {len(ids)} SentinelOne agent(s).")
            return 0

        if ag_action == "move-to-site":
            ids = _split_csv_arg(args.agent_ids)
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="agents-move-to-site")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="agents-move-to-site",
                target={"agent_ids": ids, "target_site_id": args.target_site},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.move_agents_to_site(ids, args.target_site)
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Moved {len(ids)} SentinelOne agent(s) to site '{args.target_site}'.")
            return 0

        # Read-only list (legacy `s1 agents` or `s1 agents list`)
        with _build_s1_client(args) as client:
            list_kwargs: dict[str, Any] = {
                "query": getattr(args, "query", None),
                "computer_name": getattr(args, "computer_name", None),
                "infected": getattr(args, "infected", None),
                "is_active": getattr(args, "active", None),
                "network_status": getattr(args, "network_status", None),
                "os_types": getattr(args, "os_type", None),
                "limit": getattr(args, "limit", 100),
            }
            if getattr(args, "account_id", None):
                list_kwargs["account_ids"] = _split_csv_arg(args.account_id)
            if getattr(args, "site_id", None):
                list_kwargs["site_ids"] = _split_csv_arg(args.site_id)
            if getattr(args, "group_id", None):
                list_kwargs["group_ids"] = _split_csv_arg(args.group_id)
            agents = client.list_agents(**list_kwargs)
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

    if subcmd == "cloud-alerts":
        ca_act = getattr(args, "cloud_alerts_action", None) or "list"
        if ca_act == "verdict":
            ids = _split_csv_arg(args.alert_ids)
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="cloud-alert-verdict",
                target={"alert_ids": ids, "verdict": args.verdict},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.update_cloud_alert_verdict(ids, args.verdict)
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Updated verdict to '{args.verdict}' on {len(ids)} Cloud alert(s).")
            return 0

        if ca_act == "incident-status":
            ids = _split_csv_arg(args.alert_ids)
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="cloud-alert-incident-status",
                target={"alert_ids": ids, "status": args.status},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.update_cloud_alert_incident_status(ids, args.status)
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Updated incident status to '{args.status}' on {len(ids)} Cloud alert(s).")
            return 0

        with _build_s1_client(args) as client:
            alerts = client.list_cloud_alerts(
                query=getattr(args, "query", None),
                incident_statuses=_split_csv_arg(getattr(args, "status", None)) or None,
                analyst_verdicts=_split_csv_arg(getattr(args, "verdict", None)) or None,
                severities=_split_csv_arg(getattr(args, "severity", None)) or None,
                scopes=_split_csv_arg(getattr(args, "scope", None)) or None,
                os_types=_split_csv_arg(getattr(args, "os_type", None)) or None,
                rule_name=getattr(args, "rule_name", None),
                computer_name=getattr(args, "computer_name", None),
                sha1=getattr(args, "sha1", None),
                account_ids=_split_csv_arg(getattr(args, "account_id", None)) or None,
                site_ids=_split_csv_arg(getattr(args, "site_id", None)) or None,
                group_ids=_split_csv_arg(getattr(args, "group_id", None)) or None,
                limit=getattr(args, "limit", 100),
            )
        if use_json:
            _emit_json(alerts)
        else:
            print(f"[+] SentinelOne Cloud/STAR alerts ({len(alerts)}):")
            for al in alerts:
                print(
                    f"  - {al.get('id')} | {al.get('ruleName', '-')} | "
                    f"sev={al.get('severity', '-')} | status={al.get('incidentStatus', '-')}"
                )
        return 0

    if subcmd == "exclusions":
        excl_act = getattr(args, "exclusions_action", None)
        if excl_act == "clone":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="clone-exclusions")
            if not ok_admin:
                return rc
            rps = float(args.rate_limit)
            if not math.isfinite(rps) or rps <= 0:
                raise ValueError("--rate-limit must be a finite positive number.")
            is_dry = bool(global_dry_run or getattr(args, "dry_run", False))
            if is_dry:
                with _build_s1_client(args) as client:
                    plan = client.clone_exclusions(
                        args.from_site,
                        args.to_site,
                        source_site_name=args.source_site_name,
                        dry_run=True,
                        requests_per_second=rps,
                        include_source_parents=bool(args.include_source_parents),
                        continue_on_error=not bool(args.stop_on_error),
                        limit=args.limit,
                    )
                if use_json:
                    _emit_json(plan)
                else:
                    counts = plan.get("counts", {})
                    print(
                        f"[DRY-RUN] Exclusion clone {args.from_site} -> {args.to_site}: "
                        f"will_create={counts.get('will_create', 0)}, "
                        f"skipped_duplicate={counts.get('skipped_duplicate', 0)}, "
                        f"inherited_from_account={counts.get('inherited_from_account', 0)}"
                    )
                return 0

            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=False,
                use_json=use_json,
                action="clone-exclusions",
                target={"from_site": args.from_site, "to_site": args.to_site, "rate_limit": rps},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.clone_exclusions(
                    args.from_site,
                    args.to_site,
                    source_site_name=args.source_site_name,
                    dry_run=False,
                    requests_per_second=rps,
                    include_source_parents=bool(args.include_source_parents),
                    continue_on_error=not bool(args.stop_on_error),
                    limit=args.limit,
                )
            if use_json:
                _emit_json(res)
            else:
                counts = res.get("counts", {})
                print(
                    f"[+] Cloned exclusions {args.from_site} -> {args.to_site}: "
                    f"created={counts.get('created', 0)}, failed={counts.get('failed', 0)}"
                )
            return 0

        if excl_act == "validate":
            with _build_s1_client(args) as client:
                val_res = client.validate_exclusion(
                    exclusion_type=args.exclusion_type,
                    os_type=args.os_type,
                    value=args.value,
                )
            if use_json:
                _emit_json(val_res)
            else:
                print(f"[+] Exclusion validation result: {val_res}")
            return 0

        if excl_act == "create" or (excl_act is None and bool(getattr(args, "create", False))):
            if not args.exclusion_type or not args.value:
                raise ValueError("--create / create requires --type and --value.")
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="create-exclusion")
            if not ok_admin:
                return rc
            site_scopes = _split_csv_arg(getattr(args, "site_id", None) or getattr(args, "s1_site_id", None))
            acc_scopes = _split_csv_arg(getattr(args, "account_id", None) or getattr(args, "s1_account_id", None))
            grp_scopes = _split_csv_arg(getattr(args, "group_id", None))
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
                    "site_ids": site_scopes,
                    "account_ids": acc_scopes,
                    "group_ids": grp_scopes,
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
                    path_exclusion_type=getattr(args, "path_exclusion_type", None),
                    actions=_split_csv_arg(getattr(args, "actions", None)) or None,
                    account_ids=acc_scopes or None,
                    site_ids=site_scopes or None,
                    group_ids=grp_scopes or None,
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Created SentinelOne {args.exclusion_type} exclusion: {args.value}")
            return 0

        if excl_act == "update":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="update-exclusion")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="update-exclusion",
                target={"exclusion_id": args.exclusion_id, "type": args.exclusion_type},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.update_exclusion(
                    args.exclusion_id,
                    exclusion_type=args.exclusion_type,
                    os_type=args.os_type,
                    value=args.value,
                    description=args.description,
                    mode=args.mode,
                    path_exclusion_type=args.path_exclusion_type,
                    actions=_split_csv_arg(args.actions) or None,
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Updated SentinelOne exclusion '{args.exclusion_id}'.")
            return 0

        if excl_act == "delete" or (excl_act is None and bool(getattr(args, "delete", None))):
            del_ids = _split_csv_arg(args.ids if excl_act == "delete" else args.delete)
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="delete-exclusions")
            if not ok_admin:
                return rc
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

        # Read-only exclusions list (`s1 exclusions` or `s1 exclusions list`)
        with _build_s1_client(args) as client:
            excl_kwargs: dict[str, Any] = {
                "exclusion_type": getattr(args, "exclusion_type", None),
                "query": getattr(args, "query", None),
                "limit": getattr(args, "limit", 100),
            }
            if getattr(args, "filter_os_type", None):
                excl_kwargs["os_types"] = _split_csv_arg(args.filter_os_type)
            if getattr(args, "account_id", None):
                excl_kwargs["account_ids"] = _split_csv_arg(args.account_id)
            if getattr(args, "site_id", None):
                excl_kwargs["site_ids"] = _split_csv_arg(args.site_id)
            if getattr(args, "group_id", None):
                excl_kwargs["group_ids"] = _split_csv_arg(args.group_id)
            if getattr(args, "include_parents", None) is not None:
                excl_kwargs["include_parents"] = args.include_parents
            if getattr(args, "include_children", None) is not None:
                excl_kwargs["include_children"] = args.include_children
            if getattr(args, "modes", None):
                excl_kwargs["modes"] = _split_csv_arg(args.modes)
            if getattr(args, "scopes", None):
                excl_kwargs["scopes"] = _split_csv_arg(args.scopes)
            items = client.list_exclusions(**excl_kwargs)
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
        blk_act = getattr(args, "blocklist_action", None)
        if blk_act == "add" or (blk_act is None and bool(getattr(args, "add_hash", None))):
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="add-blocklist")
            if not ok_admin:
                return rc
            sha1_val = args.sha1_hash if blk_act == "add" else args.add_hash
            site_scopes = _split_csv_arg(getattr(args, "site_id", None) or getattr(args, "s1_site_id", None))
            acc_scopes = _split_csv_arg(getattr(args, "account_id", None) or getattr(args, "s1_account_id", None))
            grp_scopes = _split_csv_arg(getattr(args, "group_id", None))
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="add-blocklist",
                target={
                    "sha1_hash": sha1_val,
                    "os_type": args.os_type,
                    "description": args.description,
                },
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.add_to_blocklist(
                    sha1_val,
                    os_type=args.os_type,
                    description=args.description,
                    source=getattr(args, "source", "soclens"),
                    account_ids=acc_scopes or None,
                    site_ids=site_scopes or None,
                    group_ids=grp_scopes or None,
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Added SHA-1 {sha1_val} to SentinelOne blocklist.")
            return 0

        if blk_act == "update":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="update-blocklist")
            if not ok_admin:
                return rc
            site_scopes = _split_csv_arg(getattr(args, "site_id", None) or getattr(args, "s1_site_id", None))
            acc_scopes = _split_csv_arg(getattr(args, "account_id", None) or getattr(args, "s1_account_id", None))
            grp_scopes = _split_csv_arg(getattr(args, "group_id", None))
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="update-blocklist",
                target={"entry_id": args.entry_id, "sha1_hash": args.sha1},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.update_blocklist(
                    args.entry_id,
                    sha1_hash=args.sha1,
                    os_type=args.os_type,
                    description=args.description,
                    source=args.source,
                    account_ids=acc_scopes or None,
                    site_ids=site_scopes or None,
                    group_ids=grp_scopes or None,
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Updated SentinelOne blocklist entry '{args.entry_id}'.")
            return 0

        if blk_act == "remove" or (blk_act is None and bool(getattr(args, "remove", None))):
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="remove-blocklist")
            if not ok_admin:
                return rc
            rem_ids = _split_csv_arg(args.ids if blk_act == "remove" else args.remove)
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
            blk_kwargs: dict[str, Any] = {
                "query": getattr(args, "query", None),
                "limit": getattr(args, "limit", 100),
            }
            if getattr(args, "filter_os_type", None):
                blk_kwargs["os_types"] = _split_csv_arg(args.filter_os_type)
            if getattr(args, "account_id", None):
                blk_kwargs["account_ids"] = _split_csv_arg(args.account_id)
            if getattr(args, "site_id", None):
                blk_kwargs["site_ids"] = _split_csv_arg(args.site_id)
            items = client.list_blocklist(**blk_kwargs)
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

    if subcmd == "sites":
        site_act = getattr(args, "sites_action", None)
        if site_act == "create":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="create-site")
            if not ok_admin:
                return rc
            policy_dict = _parse_json_mapping_arg(args.policy_json, flag_name="--policy-json")
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="create-site",
                target={
                    "name": args.name,
                    "account_id": args.account_id or getattr(args, "s1_account_id", None),
                    "site_type": args.site_type,
                    "total_licenses": args.total_licenses,
                    "copy_policy_from": args.copy_policy_from,
                    "clone_exclusions_from": args.clone_exclusions_from,
                },
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                created_site = client.create_site(
                    name=args.name,
                    account_id=args.account_id or getattr(args, "s1_account_id", None),
                    site_type=args.site_type,
                    total_licenses=args.total_licenses,
                    unlimited_licenses=args.unlimited_licenses,
                    unlimited_expiration=not bool(args.no_unlimited_expiration),
                    expiration=args.expiration,
                    inherit_account_expiration=args.inherit_account_expiration,
                    sku=args.sku,
                    suite=args.suite,
                    description=args.description,
                    inherits=not bool(args.no_inherits),
                    usage_type=args.usage_type,
                    external_id=args.external_id,
                    policy=policy_dict,
                    copy_policy_from_site_id=args.copy_policy_from,
                    clone_exclusions_from_site_id=args.clone_exclusions_from,
                )
            if use_json:
                _emit_json(created_site)
            else:
                print(
                    f"[+] Created SentinelOne site '{created_site.get('name', args.name)}' "
                    f"(id={created_site.get('id', '-')})."
                )
            return 0

        if site_act == "edit":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="edit-site")
            if not ok_admin:
                return rc
            policy_dict = _parse_json_mapping_arg(args.policy_json, flag_name="--policy-json")
            edit_fields: dict[str, Any] = {
                "name": args.name,
                "site_type": args.site_type,
                "total_licenses": args.total_licenses,
                "unlimited_licenses": args.unlimited_licenses,
                "unlimited_expiration": args.unlimited_expiration,
                "expiration": args.expiration,
                "inherit_account_expiration": args.inherit_account_expiration,
                "sku": args.sku,
                "description": args.description,
                "usage_type": args.usage_type,
                "external_id": args.external_id,
                "policy": policy_dict,
            }
            if not any(v is not None for v in edit_fields.values()):
                raise ValueError("Provide at least one field to edit on the site.")
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="edit-site",
                target={"site_id": args.site_id},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                updated_site = client.update_site(args.site_id, **edit_fields)
            if use_json:
                _emit_json(updated_site)
            else:
                print(f"[+] Updated SentinelOne site '{args.site_id}'.")
            return 0

        if site_act == "duplicate":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="duplicate-site")
            if not ok_admin:
                return rc
            policy_dict = _parse_json_mapping_arg(args.policy_json, flag_name="--policy-json")
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="duplicate-site",
                target={"source_site_id": args.source_site_id, "name": args.name},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                dup_site = client.duplicate_site(
                    args.source_site_id,
                    args.name,
                    policy_source=args.policy_source,
                    copy_users=bool(args.copy_users),
                    total_licenses=args.total_licenses,
                    unlimited_licenses=args.unlimited_licenses,
                    policy=policy_dict,
                )
            if use_json:
                _emit_json(dup_site)
            else:
                print(
                    f"[+] Duplicated SentinelOne site '{args.source_site_id}' -> "
                    f"'{dup_site.get('name', args.name)}' (id={dup_site.get('id', '-')})."
                )
            return 0

        if site_act == "expire":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="expire-site")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="expire-site",
                target={"site_id": args.site_id},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.expire_site(args.site_id)
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Expired SentinelOne site '{args.site_id}'.")
            return 0

        if site_act == "reactivate":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="reactivate-site")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="reactivate-site",
                target={"site_id": args.site_id, "unlimited": bool(args.unlimited)},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.reactivate_site(
                    args.site_id,
                    unlimited=bool(args.unlimited),
                    expiration=args.expiration,
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Reactivated SentinelOne site '{args.site_id}'.")
            return 0

        if site_act in ("rotate-token", "regenerate-key"):
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action=site_act)
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action=site_act,
                target={"site_id": args.site_id},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = (
                    client.rotate_site_token(args.site_id)
                    if site_act == "rotate-token"
                    else client.regenerate_site_key(args.site_id)
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Executed '{site_act}' for SentinelOne site '{args.site_id}'.")
            return 0

        if site_act == "policy":
            pol_act = getattr(args, "policy_action", None)
            if not pol_act:
                print("Usage: soclens s1 sites policy {get,update,revert} <site_id>", file=sys.stderr)
                return 1
            if pol_act == "get":
                with _build_s1_client(args) as client:
                    pol = client.get_site_policy(args.site_id)
                if use_json:
                    _emit_json(pol)
                else:
                    print(f"[+] Policy for SentinelOne site '{args.site_id}':")
                    _emit_json(pol)
                return 0
            if pol_act == "update":
                ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="update-site-policy")
                if not ok_admin:
                    return rc
                pol_payload = _parse_json_mapping_arg(args.policy_json, flag_name="--policy-json")
                if not pol_payload:
                    raise ValueError("--policy-json must be a non-empty JSON object.")
                proceed, rc = _check_s1_write_guard(
                    args,
                    global_dry_run=global_dry_run,
                    use_json=use_json,
                    action="update-site-policy",
                    target={"site_id": args.site_id},
                )
                if not proceed:
                    return rc
                with _build_s1_client(args) as client:
                    res = client.update_site_policy(args.site_id, pol_payload)
                if use_json:
                    _emit_json(res)
                else:
                    print(f"[+] Updated policy for SentinelOne site '{args.site_id}'.")
                return 0
            if pol_act == "revert":
                ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="revert-site-policy")
                if not ok_admin:
                    return rc
                proceed, rc = _check_s1_write_guard(
                    args,
                    global_dry_run=global_dry_run,
                    use_json=use_json,
                    action="revert-site-policy",
                    target={"site_id": args.site_id},
                )
                if not proceed:
                    return rc
                with _build_s1_client(args) as client:
                    res = client.revert_site_policy(args.site_id)
                if use_json:
                    _emit_json(res)
                else:
                    print(f"[+] Reverted policy for SentinelOne site '{args.site_id}'.")
                return 0

        if site_act == "delete":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="delete-site")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="delete-site",
                target={"site_id": args.site_id, "confirm_name": args.confirm_name},
            )
            if not proceed:
                return rc
            confirm_name = getattr(args, "confirm_name", None)
            if not isinstance(confirm_name, str) or not confirm_name.strip():
                raise ValueError(
                    "Site deletion requires --confirm-name matching the exact SentinelOne site name."
                )
            with _build_s1_client(args) as client:
                site = client.get_site(args.site_id)
                raw_name = site.get("name") if isinstance(site, Mapping) else None
                expected_name = str(raw_name) if raw_name is not None else ""
                if (expected_name or (isinstance(site, Mapping) and "name" in site)) and confirm_name != expected_name:
                    raise ValueError(
                        f"Site deletion confirmation name mismatch: expected {expected_name!r}, "
                        f"got {confirm_name!r}."
                    )
                res = client.delete_site(
                    args.site_id,
                    confirm_site_name=confirm_name,
                    expected_site_name=expected_name,
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Deleted SentinelOne site '{expected_name}' (id={args.site_id}).")
            return 0

        # Read-only list (`s1 sites` or `s1 sites list`)
        with _build_s1_client(args) as client:
            if bool(getattr(args, "accounts", False)):
                items = client.list_accounts(query=args.query, limit=args.limit)
                kind = "accounts"
            elif bool(getattr(args, "groups", False)):
                grp_kwargs: dict[str, Any] = {"query": args.query, "limit": args.limit}
                if getattr(args, "account_id", None):
                    grp_kwargs["account_ids"] = _split_csv_arg(args.account_id)
                if getattr(args, "site_id", None):
                    grp_kwargs["site_ids"] = _split_csv_arg(args.site_id)
                items = client.list_groups(**grp_kwargs)
                kind = "groups"
            else:
                site_kwargs: dict[str, Any] = {"query": args.query, "limit": args.limit}
                if getattr(args, "account_id", None):
                    site_kwargs["account_ids"] = _split_csv_arg(args.account_id)
                items = client.list_sites(**site_kwargs)
                tier_filter = getattr(args, "tier", None)
                if tier_filter:
                    items = client.enrich_sites_with_tiers(items)
                    want_tier = str(tier_filter).strip().casefold()
                    items = [
                        it
                        for it in items
                        if str(it.get("tier") or "").strip().casefold() == want_tier
                    ]
                kind = "sites"
        if use_json:
            _emit_json(items)
        else:
            print(f"[+] SentinelOne {kind} ({len(items)}):")
            for item in items:
                print(f"  - {item.get('id')} | {item.get('name')} | {item.get('state', '')}")
        return 0

    if subcmd == "users":
        usr_act = getattr(args, "users_action", None) or "list"
        if usr_act == "create":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="create-user")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="create-user",
                target={
                    "email": args.email,
                    "full_name": args.full_name,
                    "scope": args.scope,
                    "site_id": args.site_id,
                    "clone_from": args.clone_from,
                },
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                scope, scope_roles = _resolve_s1_scope_and_roles(args, client=client)
                created_usr = client.create_user(
                    email=args.email,
                    full_name=args.full_name,
                    scope=scope,
                    scope_roles=scope_roles,
                    password=args.password,
                    two_fa_enabled=args.two_fa,
                    allow_remote_shell=args.allow_remote_shell,
                )
            if use_json:
                _emit_json(created_usr)
            else:
                print(
                    f"[+] Created SentinelOne user '{created_usr.get('email', args.email)}' "
                    f"(id={created_usr.get('id', '-')})."
                )
            return 0

        if usr_act == "edit":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="edit-user")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="edit-user",
                target={"user_id": args.user_id, "scope": args.scope},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                existing: Mapping[str, Any] | None = None
                default_scope: str | None = None
                if not args.scope and not args.site_id and not args.account_id:
                    fetched = client.get_user(args.user_id)
                    if isinstance(fetched, Mapping):
                        existing = fetched
                        raw_existing_scope = fetched.get("scope")
                        if isinstance(raw_existing_scope, str) and raw_existing_scope.strip():
                            default_scope = raw_existing_scope.strip().lower()
                scope, scope_roles = _resolve_s1_scope_and_roles(
                    args, client=client, default_scope=default_scope
                )
                if scope_roles is None:
                    if existing is None:
                        fetched = client.get_user(args.user_id)
                        if isinstance(fetched, Mapping):
                            existing = fetched
                    if isinstance(existing, Mapping):
                        raw_existing_scope = existing.get("scope")
                        existing_scope = (
                            raw_existing_scope.strip().lower()
                            if isinstance(raw_existing_scope, str) and raw_existing_scope.strip()
                            else ""
                        )
                        if not args.scope and not args.site_id and not args.account_id and existing_scope:
                            scope = existing_scope
                        existing_roles = existing.get("scopeRoles")
                        changing_to_tenant = bool(
                            args.scope and scope == "tenant" and existing_scope != "tenant"
                        )
                        if isinstance(existing_roles, list) and not changing_to_tenant:
                            scope_roles = [
                                dict(r) for r in existing_roles if isinstance(r, Mapping)
                            ]
                updated_usr = client.update_user(
                    args.user_id,
                    scope=scope,
                    scope_roles=scope_roles,
                    full_name=args.full_name,
                    email=args.email,
                    two_fa_enabled=args.two_fa,
                    can_generate_api_token=args.can_generate_token,
                )
            if use_json:
                _emit_json(updated_usr)
            else:
                print(f"[+] Updated SentinelOne user '{args.user_id}'.")
            return 0

        if usr_act == "clone":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="clone-user")
            if not ok_admin:
                return rc
            if not args.target_user and not (args.email and args.full_name):
                raise ValueError(
                    "Specify --target-user <id> or both --email and --name to clone user permissions."
                )
            target_sites = _split_csv_arg(args.to_site) or None
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="clone-user",
                target={
                    "source_user_id": args.source_user_id,
                    "target_user": args.target_user,
                    "email": args.email,
                    "target_sites": target_sites,
                },
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                cloned = client.clone_user_permissions(
                    args.source_user_id,
                    target_site_ids=target_sites,
                    service_user=bool(args.service_user),
                )
                if args.target_user:
                    res = client.update_user(
                        args.target_user,
                        scope=cloned["scope"],
                        scope_roles=cloned["scopeRoles"],
                    )
                else:
                    res = client.create_user(
                        email=args.email,
                        full_name=args.full_name,
                        scope=cloned["scope"],
                        scope_roles=cloned["scopeRoles"],
                    )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Cloned RBAC permissions from '{args.source_user_id}'.")
            return 0

        if usr_act == "reset-password":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="reset-password")
            if not ok_admin:
                return rc
            ids = _split_csv_arg(args.user_ids)
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="reset-password",
                target={"user_ids": ids},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.send_reset_password_email(ids)
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Sent password reset email(s) to {len(ids)} user(s).")
            return 0

        if usr_act == "reset-2fa":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="reset-2fa")
            if not ok_admin:
                return rc
            ids = _split_csv_arg(args.user_ids)
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="delete-2fa" if args.delete_2fa else "reset-2fa",
                target={"user_ids": ids, "enroll": bool(args.enroll)},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = (
                    client.delete_2fa(ids)
                    if bool(args.delete_2fa)
                    else client.reset_2fa(ids, enroll=bool(args.enroll))
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Updated 2FA for {len(ids)} SentinelOne user(s).")
            return 0

        if usr_act == "logout":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="logout-user")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="logout-user",
                target={},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.logout_user()
            if use_json:
                _emit_json(res)
            else:
                print("[+] Logged out current SentinelOne API user session.")
            return 0

        if usr_act == "delete":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="delete-users")
            if not ok_admin:
                return rc
            ids = _split_csv_arg(args.user_ids)
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="delete-users",
                target={"user_ids": ids},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.delete_user(ids[0]) if len(ids) == 1 else client.delete_users(ids)
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Deleted {len(ids)} SentinelOne user(s).")
            return 0

        with _build_s1_client(args) as client:
            users = client.list_users(
                query=getattr(args, "query", None),
                email=getattr(args, "email", None),
                full_name=getattr(args, "full_name", None),
                account_ids=_split_csv_arg(getattr(args, "account_id", None)) or None,
                site_ids=_split_csv_arg(getattr(args, "site_id", None)) or None,
                role_ids=_split_csv_arg(getattr(args, "role_id", None)) or None,
                limit=getattr(args, "limit", 100),
            )
        if use_json:
            _emit_json(users)
        else:
            print(f"[+] SentinelOne console users ({len(users)}):")
            for usr in users:
                print(
                    f"  - {usr.get('id')} | {usr.get('email', '-')} | "
                    f"{usr.get('fullName', '-')} | scope={usr.get('scope', '-')}"
                )
        return 0

    if subcmd == "service-users":
        su_act = getattr(args, "service_users_action", None) or "list"
        if su_act == "create":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="create-service-user")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="create-service-user",
                target={
                    "name": args.name,
                    "expiration_date": args.expiration_date,
                    "scope": args.scope,
                },
            )
            if not proceed:
                return rc
            scope, scope_roles = _resolve_s1_scope_and_roles(args)
            with _build_s1_client(args) as client:
                created_su = client.create_service_user(
                    name=args.name,
                    scope=scope,
                    expiration_date=args.expiration_date,
                    description=args.description,
                    scope_roles=scope_roles,
                    force_legacy=args.force_legacy,
                )
            if use_json:
                _emit_json(created_su)
            else:
                print(
                    f"[+] Created SentinelOne service user '{created_su.get('name', args.name)}' "
                    f"(id={created_su.get('id', '-')})."
                )
            return 0

        if su_act == "edit":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="edit-service-user")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="edit-service-user",
                target={"service_user_id": args.service_user_id},
            )
            if not proceed:
                return rc
            scope_val: str | None = args.scope
            scope_roles_val: list[dict[str, Any]] | None = None
            if (
                args.scope is not None
                or args.scope_roles_json is not None
                or args.role_id is not None
                or args.role_name is not None
            ):
                resolved_scope, scope_roles_val = _resolve_s1_scope_and_roles(args)
                scope_val = resolved_scope
            with _build_s1_client(args) as client:
                updated_su = client.update_service_user(
                    args.service_user_id,
                    description=args.description,
                    scope=scope_val,
                    scope_roles=scope_roles_val,
                )
            if use_json:
                _emit_json(updated_su)
            else:
                print(f"[+] Updated SentinelOne service user '{args.service_user_id}'.")
            return 0

        if su_act == "delete":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="delete-service-users")
            if not ok_admin:
                return rc
            ids = _split_csv_arg(args.service_user_ids)
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="delete-service-users",
                target={"service_user_ids": ids},
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = (
                    client.delete_service_user(ids[0])
                    if len(ids) == 1
                    else client.delete_service_users(ids)
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Deleted {len(ids)} SentinelOne service user(s).")
            return 0

        if su_act == "token":
            ok_admin, rc = _check_s1_admin_guard(args, use_json=use_json, action="generate-service-user-token")
            if not ok_admin:
                return rc
            proceed, rc = _check_s1_write_guard(
                args,
                global_dry_run=global_dry_run,
                use_json=use_json,
                action="generate-service-user-token",
                target={
                    "service_user_id": args.service_user_id,
                    "expiration_date": args.expiration_date,
                },
            )
            if not proceed:
                return rc
            with _build_s1_client(args) as client:
                res = client.generate_service_user_token(
                    args.service_user_id,
                    expiration_date=args.expiration_date,
                )
            if use_json:
                _emit_json(res)
            else:
                print(f"[+] Generated API token for service user '{args.service_user_id}'.")
            return 0

        with _build_s1_client(args) as client:
            sus = client.list_service_users(
                query=getattr(args, "query", None),
                account_ids=_split_csv_arg(getattr(args, "account_id", None)) or None,
                site_ids=_split_csv_arg(getattr(args, "site_id", None)) or None,
                role_ids=_split_csv_arg(getattr(args, "role_id", None)) or None,
                limit=getattr(args, "limit", 100),
            )
        if use_json:
            _emit_json(sus)
        else:
            print(f"[+] SentinelOne service users ({len(sus)}):")
            for su in sus:
                print(
                    f"  - {su.get('id')} | {su.get('name', '-')} | "
                    f"scope={su.get('scope', '-')} | expires={su.get('expirationDate', '-')}"
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

        if subcmd == "roles":
            roles = client.list_rbac_roles(
                account_ids=_split_csv_arg(getattr(args, "account_id", None)) or None,
                site_ids=_split_csv_arg(getattr(args, "site_id", None)) or None,
                group_ids=_split_csv_arg(getattr(args, "group_id", None)) or None,
                include_parents=getattr(args, "include_parents", None),
                include_children=getattr(args, "include_children", None),
                predefined_role=getattr(args, "predefined_role", None),
                name=getattr(args, "name", None),
                query=getattr(args, "query", None),
                limit=getattr(args, "limit", 100),
            )
            if use_json:
                _emit_json(roles)
            else:
                print(f"[+] SentinelOne RBAC roles ({len(roles)}):")
                for role in roles:
                    print(f"  - {role.get('id')} | {role.get('name')} | predefined={role.get('predefinedRole', False)}")
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


def _read_cli_passphrase(
    prompt: str,
    *,
    env_var: str | None = None,
    allow_default_env: bool = True,
    confirm: bool = False,
) -> str:
    """Resolve a master passphrase securely via env var or interactive TTY ``getpass``."""
    if env_var:
        val = os.environ.get(env_var)
        if not val:
            raise ValueError(f"Environment variable '{env_var}' is unset or empty.")
        return val

    if allow_default_env:
        env_val = get_env_passphrase()
        if env_val:
            return env_val

    if not sys.stdin.isatty():
        raise SettingsLockedError(
            "Master passphrase is required in non-interactive mode. "
            "Set SOCLENS_SETTINGS_PASSPHRASE (or SOCLENS_SETTINGS_PASSPHRASE_FILE) or pass --passphrase-env."
        )

    entered = getpass.getpass(prompt, stream=sys.stderr)
    if not entered:
        raise ValueError("Master passphrase cannot be empty.")
    if confirm:
        if len(entered) < MIN_PASSPHRASE_LENGTH:
            raise ValueError(
                f"Master passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters long."
            )
        again = getpass.getpass("Confirm master passphrase: ", stream=sys.stderr)
        if entered != again:
            raise ValueError("Passphrases do not match.")
    return entered


def _ensure_cli_settings_unlocked(args: argparse.Namespace) -> None:
    """Unlock passphrase-protected settings via env var or interactive TTY prompt when needed."""
    cmd = getattr(args, "command", None)
    if cmd == "bundle":
        return
    if cmd == "settings":
        subcmd = getattr(args, "settings_command", None)
        if subcmd in (None, "path", "lock", "encrypt", "unlock", "rekey"):
            return

    if not is_settings_locked():
        return

    try:
        unlock_settings()
        return
    except SettingsLockedError:
        pass

    if sys.stdin.isatty():
        pw = _read_cli_passphrase("Enter SOCLens settings master passphrase: ", allow_default_env=False)
        unlock_settings(passphrase=pw)
        return

    if cmd in ("settings", "secrets"):
        raise SettingsLockedError(
            "Settings file is encrypted with a master passphrase and is locked. "
            "Set SOCLENS_SETTINGS_PASSPHRASE (or SOCLENS_SETTINGS_PASSPHRASE_FILE) or run interactively."
        )


def _handle_settings(
    args: argparse.Namespace,
    *,
    global_dry_run: bool,
    use_json: bool,
) -> int:
    subcmd = getattr(args, "settings_command", None)
    if not subcmd:
        msg = (
            "Usage: soclens settings "
            "{path,show,set,unset,import-env,profiles,use,delete-profile,reset,encrypt,unlock,lock,rekey}"
        )
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
            print(f"Encryption    : {info.get('encryption_summary') or 'Unknown'}")
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

    if subcmd == "encrypt":
        raw_mode = getattr(args, "mode", None)
        if bool(getattr(args, "passphrase", False)):
            if raw_mode and raw_mode != ENCRYPTION_MODE_PASSPHRASE:
                raise ValueError("Cannot combine --passphrase with --mode os_keystore.")
            target_mode = ENCRYPTION_MODE_PASSPHRASE
        else:
            target_mode = raw_mode or ENCRYPTION_MODE_OS_KEYSTORE

        enc_before = inspect_settings_encryption()
        if is_dry:
            payload = {
                "dry_run": True,
                "action": "encrypt",
                "target_mode": target_mode,
                "current_mode": enc_before.get("encryption_mode"),
                "encrypted": bool(enc_before.get("encrypted", False)),
            }
            if use_json:
                _emit_json(payload)
            else:
                print(
                    f"[DRY-RUN] Would encrypt settings store with AES-256-GCM "
                    f"(mode={target_mode}, current={enc_before.get('encryption_mode')})."
                )
            return 0

        current_pw: str | None = None
        cur_env: str | None = getattr(args, "current_passphrase_env", None)
        if enc_before.get("locked"):
            current_pw = _read_cli_passphrase(
                "Enter current SOCLens settings master passphrase: ",
                env_var=cur_env,
                allow_default_env=True,
                confirm=False,
            )

        enc_new_pw: str | None = None
        if target_mode == ENCRYPTION_MODE_PASSPHRASE:
            pw_env = getattr(args, "passphrase_env", None)
            enc_new_pw = _read_cli_passphrase(
                "Enter new SOCLens settings master passphrase: ",
                env_var=pw_env,
                allow_default_env=not bool(enc_before.get("locked")),
                confirm=True,
            )

        info = encrypt_settings_store(
            mode=target_mode,
            passphrase=enc_new_pw,
            current_passphrase=current_pw,
        )
        if use_json:
            _emit_json({"encrypted": True, "storage": info})
        else:
            print(f"[+] Settings encrypted ({info['encryption_summary']}) at {info['path']}.")
        return 0

    if subcmd == "unlock":
        enc_before = inspect_settings_encryption()
        pw_env = getattr(args, "passphrase_env", None)
        passphrase: str | None = None
        if enc_before.get("encryption_mode") == ENCRYPTION_MODE_PASSPHRASE:
            if pw_env:
                passphrase = _read_cli_passphrase(
                    "Enter SOCLens settings master passphrase: ",
                    env_var=pw_env,
                    allow_default_env=False,
                )
            elif enc_before.get("locked"):
                passphrase = _read_cli_passphrase(
                    "Enter SOCLens settings master passphrase: ",
                    allow_default_env=True,
                )
        unlock_settings(passphrase=passphrase)
        info = get_settings_storage_info()
        if use_json:
            _emit_json({"unlocked": True, "storage": info})
        else:
            print(
                f"[+] Settings unlocked ({info['encryption_summary']}) — "
                f"active profile '{info['active_profile']}' ({info['profile_count']} profile(s))."
            )
        return 0

    if subcmd == "lock":
        locked = lock_settings()
        info = get_settings_storage_info()
        if use_json:
            _emit_json({"locked": locked, "storage": info})
        else:
            if locked:
                print(f"[+] Settings locked ({info['path']}).")
            else:
                print(
                    f"[*] Cleared in-memory settings cache. Note: '{info['path']}' uses "
                    f"{info['key_backend_label']} (auto-unlock). Run 'soclens settings encrypt --passphrase' "
                    "to require a master passphrase."
                )
        return 0

    if subcmd == "rekey":
        enc_before = inspect_settings_encryption()
        want_new_pw = bool(getattr(args, "new_passphrase", False) or getattr(args, "new_passphrase_env", None))
        rotate_kek = bool(getattr(args, "rotate_kek", False))
        if is_dry:
            payload = {
                "dry_run": True,
                "action": "rekey",
                "current_mode": enc_before.get("encryption_mode"),
                "new_passphrase": want_new_pw,
                "rotate_kek": rotate_kek,
            }
            if use_json:
                _emit_json(payload)
            else:
                print(
                    f"[DRY-RUN] Would rotate settings AES-256-GCM encryption key "
                    f"(mode={enc_before.get('encryption_mode')}, rotate_kek={rotate_kek}, "
                    f"new_passphrase={want_new_pw})."
                )
            return 0

        cur_pw: str | None = None
        if enc_before.get("encryption_mode") == ENCRYPTION_MODE_PASSPHRASE:
            pw_env = getattr(args, "passphrase_env", None)
            if enc_before.get("locked") or not want_new_pw or pw_env:
                cur_pw = _read_cli_passphrase(
                    "Enter current SOCLens settings master passphrase: ",
                    env_var=pw_env,
                    allow_default_env=True,
                )

        new_pw: str | None = None
        if want_new_pw:
            new_pw_env = getattr(args, "new_passphrase_env", None)
            new_pw = _read_cli_passphrase(
                "Enter new SOCLens settings master passphrase: ",
                env_var=new_pw_env,
                allow_default_env=False,
                confirm=True,
            )

        info = rotate_settings_key(
            passphrase=cur_pw,
            new_passphrase=new_pw,
            rotate_kek=rotate_kek,
        )
        if use_json:
            _emit_json({"rekeyed": True, "rotate_kek": rotate_kek, "storage": info})
        else:
            print(f"[+] Rotated settings encryption key ({info['encryption_summary']}) at {info['path']}.")
        return 0

    return 1


def _build_secret_store_config_from_args(args: argparse.Namespace) -> SecretStoreConfig:
    """Resolve ``SecretStoreConfig`` applying CLI provider and SSL overrides when set."""
    verify_ssl: bool | str | None = None
    if bool(getattr(args, "insecure", False)):
        verify_ssl = False
    else:
        ca_bundle = getattr(args, "ca_bundle", None)
        if isinstance(ca_bundle, str) and ca_bundle.strip():
            verify_ssl = ca_bundle.strip()
    return get_secret_store_config(
        provider=getattr(args, "provider", None),
        verify_ssl=verify_ssl,
    )


def _require_enabled_secret_store(cfg: SecretStoreConfig) -> SecretStoreConfig:
    """Ensure a secret store provider is configured before executing live vault commands."""
    if not cfg.is_enabled:
        raise ConfigurationError(
            "Secret store provider is disabled ('none'). "
            "Configure 'secret_provider' via 'soclens settings set secret_provider <provider>'."
        )
    return cfg


def _maybe_hydrate_startup_secrets(args: argparse.Namespace) -> None:
    """Gracefully hydrate mapped secrets before non-TUI service commands."""
    if bool(getattr(args, "no_secret_store", False)):
        return
    try:
        cfg = get_secret_store_config()
        if not cfg.is_enabled or not cfg.secret_map:
            return
        hydrate_secrets_from_store(overwrite_existing=False)
    except (SecretStoreError, ConfigurationError, OSError) as exc:
        logger.warning("Secret store startup hydration skipped: %s", exc)


def _handle_secrets(
    args: argparse.Namespace,
    *,
    global_dry_run: bool,
    use_json: bool,
) -> int:
    subcmd = getattr(args, "secrets_command", None)
    if not subcmd:
        msg = "Usage: soclens secrets {test,list,fields,map,unmap,pull}"
        if use_json:
            print(json.dumps({"error": msg}, indent=2), file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1

    is_dry = bool(global_dry_run or getattr(args, "dry_run", False))

    if subcmd == "test":
        cfg = _require_enabled_secret_store(_build_secret_store_config_from_args(args))
        with build_secret_store_provider(cfg) as provider:
            info = provider.test_connection()
        if use_json:
            _emit_json(info)
        else:
            print(f"[+] Secret store connection OK: provider={cfg.provider}")
        return 0

    if subcmd == "list":
        cfg = _require_enabled_secret_store(_build_secret_store_config_from_args(args))
        limit = int(args.limit)
        if limit < 1:
            raise ValueError("--limit must be at least 1.")
        with build_secret_store_provider(cfg) as provider:
            entries = provider.list_secrets(query=args.search or "", limit=limit)
        serialized_entries = [
            {
                "ref": e.ref,
                "display_label": e.display_label,
                "provider": e.provider,
                "item_id": e.item_id,
                "field_key": e.field_key,
                "item_title": e.item_title,
                "path": e.path,
                "is_secret": e.is_secret,
            }
            for e in entries
        ]
        if use_json:
            _emit_json(
                {
                    "provider": cfg.provider,
                    "count": len(serialized_entries),
                    "entries": serialized_entries,
                }
            )
            return 0
        if not serialized_entries:
            print("(No secrets found)")
            return 0
        _print_cli_table(serialized_entries, ["ref", "item_title", "field_key", "path"])
        return 0

    if subcmd == "fields":
        cfg = _require_enabled_secret_store(_build_secret_store_config_from_args(args))
        reveal = bool(getattr(args, "reveal", False))
        with build_secret_store_provider(cfg) as provider:
            entries = provider.list_secret_fields(args.secret_id)
            revealed_map: dict[str, str] = {}
            if reveal and entries:
                revealed_map = provider.resolve_mapped_settings({e.ref: e.ref for e in entries})
        rows: list[dict[str, Any]] = []
        for entry in entries:
            if reveal:
                val_disp = revealed_map.get(entry.ref, "")
                masked = False
            else:
                val_disp = "***" if entry.is_secret else ""
                masked = True
            rows.append(
                {
                    "ref": entry.ref,
                    "field_key": entry.field_key,
                    "item_id": entry.item_id,
                    "item_title": entry.item_title,
                    "is_secret": entry.is_secret,
                    "masked": masked,
                    "value": val_disp,
                }
            )
        if use_json:
            _emit_json(
                {
                    "provider": cfg.provider,
                    "secret_id": args.secret_id,
                    "count": len(rows),
                    "revealed": reveal,
                    "fields": rows,
                }
            )
            return 0
        if not rows:
            print("(No fields found)")
            return 0
        disp_rows = [
            {
                "field_key": r["field_key"],
                "ref": r["ref"],
                "value": r["value"] if reveal else ("[MASKED]" if r["is_secret"] else ""),
            }
            for r in rows
        ]
        _print_cli_table(disp_rows, ["field_key", "ref", "value"])
        return 0

    if subcmd == "map":
        canon = resolve_setting_key(args.setting_key)
        if canon is None or canon not in SECRET_MANAGED_SETTING_KEYS:
            valid = ", ".join(SECRET_MANAGED_SETTING_KEYS)
            raise ValueError(
                f"Setting {args.setting_key!r} is not a secret-managed credential key. "
                f"Supported keys: {valid}."
            )
        parse_secret_ref(args.vault_ref)
        target_profile = getattr(args, "profile", None)
        if target_profile is not None:
            target_profile = validate_profile_name(target_profile)
        else:
            target_profile = get_active_profile_name()

        current_map = parse_vault_secret_map(
            get_saved_setting("vault_secret_map", profile=target_profile),
            strict=False,
        )
        cleaned_ref = args.vault_ref.strip()
        current_map[canon] = cleaned_ref
        serialized_map = serialize_vault_secret_map(current_map)
        errors = validate_settings_values({"vault_secret_map": serialized_map})
        if errors:
            raise ValueError(errors[0][1])

        if is_dry:
            payload = {
                "dry_run": True,
                "action": "map",
                "key": canon,
                "ref": cleaned_ref,
                "profile": target_profile,
                "vault_secret_map": current_map,
            }
            if use_json:
                _emit_json(payload)
            else:
                print(f"[DRY-RUN] Would map '{canon}' -> '{cleaned_ref}' in profile '{target_profile}'.")
            return 0

        path = save_profile_settings({"vault_secret_map": serialized_map}, profile=target_profile)
        if use_json:
            _emit_json(
                {
                    "mapped": True,
                    "key": canon,
                    "ref": cleaned_ref,
                    "profile": target_profile,
                    "path": str(path),
                    "vault_secret_map": current_map,
                }
            )
        else:
            print(f"[+] Mapped '{canon}' -> '{cleaned_ref}' in profile '{target_profile}' ({path}).")
        return 0

    if subcmd == "unmap":
        canon = resolve_setting_key(args.setting_key)
        if canon is None or canon not in SECRET_MANAGED_SETTING_KEYS:
            valid = ", ".join(SECRET_MANAGED_SETTING_KEYS)
            raise ValueError(
                f"Setting {args.setting_key!r} is not a secret-managed credential key. "
                f"Supported keys: {valid}."
            )
        target_profile = getattr(args, "profile", None)
        if target_profile is not None:
            target_profile = validate_profile_name(target_profile)
        else:
            target_profile = get_active_profile_name()

        current_map = parse_vault_secret_map(
            get_saved_setting("vault_secret_map", profile=target_profile),
            strict=False,
        )
        previous_ref = current_map.pop(canon, None)
        unmap_serialized = serialize_vault_secret_map(current_map)

        if is_dry:
            payload = {
                "dry_run": True,
                "action": "unmap",
                "key": canon,
                "was_mapped": previous_ref is not None,
                "previous_ref": previous_ref,
                "profile": target_profile,
                "vault_secret_map": current_map,
            }
            if use_json:
                _emit_json(payload)
            else:
                print(f"[DRY-RUN] Would unmap '{canon}' from profile '{target_profile}'.")
            return 0

        path = save_profile_settings(
            {"vault_secret_map": unmap_serialized or None},
            profile=target_profile,
        )
        if use_json:
            _emit_json(
                {
                    "unmapped": True,
                    "key": canon,
                    "was_mapped": previous_ref is not None,
                    "previous_ref": previous_ref,
                    "profile": target_profile,
                    "path": str(path),
                    "vault_secret_map": current_map,
                }
            )
        else:
            print(f"[+] Unmapped '{canon}' in profile '{target_profile}' ({path}).")
        return 0

    if subcmd == "pull":
        cfg = _require_enabled_secret_store(_build_secret_store_config_from_args(args))
        if not cfg.secret_map:
            if use_json:
                _emit_json(
                    {
                        "provider": cfg.provider,
                        "count": 0,
                        "pulled": {},
                        "persisted_to_disk": False,
                    }
                )
            else:
                print("[*] No vault_secret_map entries configured.")
            return 0

        force_flag = bool(getattr(args, "force", False))
        overwrite_flag = bool(getattr(args, "overwrite_existing", False))
        target_map: dict[str, str] = {}
        for setting_key, ref in cfg.secret_map.items():
            if setting_key not in SECRET_MANAGED_SETTING_KEYS:
                continue
            if not overwrite_flag and get_env_override_for_setting(setting_key) is not None:
                continue
            if not force_flag:
                has_sess, sess_val = get_session_override(setting_key)
                if has_sess and sess_val is not None:
                    continue
            target_map[setting_key] = ref

        if is_dry:
            dry_keys = sorted(target_map.keys())
            if use_json:
                _emit_json(
                    {
                        "dry_run": True,
                        "action": "pull",
                        "provider": cfg.provider,
                        "count": len(dry_keys),
                        "keys": dry_keys,
                        "mappings": {k: target_map[k] for k in dry_keys},
                        "persisted_to_disk": False,
                    }
                )
            else:
                print(
                    f"[DRY-RUN] Would hydrate {len(dry_keys)} secret(s) from '{cfg.provider}' "
                    f"into memory: {', '.join(dry_keys) or '(none)'}"
                )
            return 0

        has_cli_override = bool(
            getattr(args, "provider", None) is not None
            or bool(getattr(args, "insecure", False))
            or (
                isinstance(getattr(args, "ca_bundle", None), str)
                and str(getattr(args, "ca_bundle", "")).strip()
            )
        )
        if has_cli_override:
            to_apply: dict[str, str] = {}
            if target_map:
                with build_secret_store_provider(cfg) as provider:
                    resolved = provider.resolve_mapped_settings(target_map)
                for setting_key, secret_val in resolved.items():
                    if setting_key not in SECRET_MANAGED_SETTING_KEYS:
                        continue
                    cleaned = str(secret_val or "").strip()
                    if not cleaned:
                        continue
                    if not overwrite_flag and get_env_override_for_setting(setting_key) is not None:
                        continue
                    to_apply[setting_key] = cleaned
                if to_apply:
                    set_session_overrides(to_apply, vault_hydrated=True)
            pulled_masked = {k: mask_secret(v) for k, v in to_apply.items()}
        else:
            pulled_masked = hydrate_secrets_from_store(
                force=force_flag,
                overwrite_existing=overwrite_flag,
            )

        if use_json:
            _emit_json(
                {
                    "provider": cfg.provider,
                    "count": len(pulled_masked),
                    "pulled": pulled_masked,
                    "persisted_to_disk": False,
                }
            )
        else:
            if not pulled_masked:
                print("[*] No secrets hydrated (all mapped keys skipped by env/session precedence).")
            else:
                print(f"[+] Hydrated {len(pulled_masked)} secret(s) into process memory from '{cfg.provider}':")
                for k, mval in sorted(pulled_masked.items()):
                    print(f"  - {k}: {mval}")
        return 0

    return 1


def _emit_cli_error(exc: Exception, *, use_json: bool) -> None:
    if isinstance(exc, SecretStoreError):
        sec_payload: dict[str, Any] = {
            "error": str(exc),
            "provider": exc.provider,
            "status_code": exc.status_code,
            "endpoint": exc.endpoint,
            "reason": exc.reason,
            "type": type(exc).__name__,
        }
        if use_json:
            print(json.dumps(sec_payload, indent=2, default=str), file=sys.stderr)
        else:
            print(f"[-] Secret Store error ({exc.provider or 'unknown'}): {exc}", file=sys.stderr)
        return

    if isinstance(exc, SplunkESError):
        es_payload: dict[str, Any] = {
            "error": str(exc),
            "status_code": exc.status_code,
            "endpoint": exc.endpoint,
            "messages": exc.messages,
            "type": type(exc).__name__,
        }
        if use_json:
            print(json.dumps(es_payload, indent=2, default=str), file=sys.stderr)
        else:
            print(f"[-] Splunk ES error: {exc}", file=sys.stderr)
        return

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

    if isinstance(exc, SettingsCryptoError):
        crypto_payload: dict[str, Any] = {
            "error": str(exc),
            "type": type(exc).__name__,
            "locked": isinstance(exc, SettingsLockedError),
        }
        if isinstance(exc, SettingsLockedError):
            crypto_payload["hint"] = (
                "Set SOCLENS_SETTINGS_PASSPHRASE (or SOCLENS_SETTINGS_PASSPHRASE_FILE) "
                "or run interactively to unlock."
            )
        if use_json:
            print(json.dumps(crypto_payload, indent=2), file=sys.stderr)
        else:
            print(f"[-] Settings encryption error: {exc}", file=sys.stderr)
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
            if bool(getattr(args, "no_secret_store", False)):
                tui_kwargs["no_secret_store"] = True
            if args.command == "tui":
                tui_dry = bool(global_dry_run or getattr(args, "dry_run", False))
                ws_arg = getattr(args, "workspace", None)
                if ws_arg is not None:
                    tui_kwargs["workspace_dir"] = ws_arg
                run_unified_tui(client, dry_run=tui_dry, **tui_kwargs)
            else:
                run_unified_tui(client, dry_run=global_dry_run, **tui_kwargs)
            return

        _ensure_cli_settings_unlocked(args)

        if args.command in (
            "watchlist",
            "rf",
            "research",
            "sigma",
            "validate",
            "splunk",
            "s1",
            "llm",
        ) and not is_interactive_wl:
            _maybe_hydrate_startup_secrets(args)

        if args.command == "watchlist":
            client = _build_rf_client(args)
            rc = _handle_watchlist(args, client, global_dry_run=global_dry_run, use_json=use_json)
        elif args.command == "rf":
            client = _build_rf_client(args)
            rc = _handle_rf(args, client, use_json=use_json)
        elif args.command == "research":
            needs_rf_client = not (
                getattr(args, "research_subcommand", None) == "osint"
                or bool(getattr(args, "osint_only", False))
            )
            res_client = _build_rf_client(args) if needs_rf_client else None
            rc = _handle_research(args, res_client, use_json=use_json)
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
        elif args.command == "secrets":
            rc = _handle_secrets(args, global_dry_run=global_dry_run, use_json=use_json)
        else:
            parser.print_help()
            rc = 1

        if rc != 0:
            sys.exit(rc)
    except (
        ConfigurationError,
        LocalLLMError,
        RecordedFutureError,
        SecretStoreError,
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
