"""Generic watchlist helpers, domain liveness checks, and backward-compatible logos facade."""

from __future__ import annotations

import csv
import json
import logging
import socket
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import requests

from soclens.client import RecordedFutureClient, RecordedFutureError
from soclens.logos.brand_sync import (
    DEFAULT_LOCK_FILENAME,
    DEFAULT_STATE_FILENAME,
    SyncLock,
    SyncLockError,
    apply_brand_sync_delta,
    extract_domains_from_watchlist_entities,
    get_domains_from_watchlist,
    is_pid_alive,
    load_brand_sync_state,
    resolve_state_path,
    save_brand_sync_state,
    save_discovered_locations,
)
from soclens.logos.brand_sync import (
    calculate_brand_sync_delta as _logos_calculate_brand_sync_delta,
)
from soclens.logos.brand_sync import (
    execute_domain_brand_sync as _logos_execute_domain_brand_sync,
)
from soclens.logos.brand_sync import (
    run_continuous_brand_sync as _logos_run_continuous_brand_sync,
)
from soclens.logos.brand_sync import (
    validate_domain_brand_sync as _logos_validate_domain_brand_sync,
)
from soclens.logos.extractor import (
    DEFAULT_IGNORED_DOMAINS,
    EXCLUSION_KEYWORDS,
    PROMO_KEYWORDS,
    THIRD_PARTY_BADGE_HOSTS,
    UI_ICON_KEYWORDS,
    DomainExtractionResult,
    ExtractedLogo,
    ExtractorConfig,
    ImageInfo,
    decode_data_uri,
    extract_domain_logos,
    extract_domains_logos,
    is_excluded_image,
    is_ignored_domain,
    is_noise_match,
    load_domain_overrides,
    load_domains_file,
    normalize_text,
    parse_image_info,
    parse_srcset,
    validate_image_bytes,
)
from soclens.logos.extractor import (
    get_domain_image_hash as _logos_get_domain_image_hash,
)
from soclens.logos.hashing import (
    DEFAULT_IGNORED_HASHES,
    VALID_HASH_LENGTHS,
    canonicalize_inline_svg,
    canonicalize_svg,
    compute_image_hashes,
    compute_inline_svg_hashes,
    load_ignored_hashes,
    match_ignored_hash,
    normalize_hash,
)

logger = logging.getLogger("soclens.watchlist")

ENTITY_SORT_FIELDS: tuple[str, ...] = ("name", "id", "type", "status", "annotation")
WATCHLIST_SORT_FIELDS: tuple[str, ...] = ("name", "id", "type")

_ENTITY_SORT_ALIASES: dict[str, str] = {
    "none": "none",
    "default": "none",
    "name": "name",
    "entity": "name",
    "id": "id",
    "entity_id": "id",
    "type": "type",
    "entity_type": "type",
    "status": "status",
    "annotation": "annotation",
    "context": "annotation",
}

_WATCHLIST_SORT_ALIASES: dict[str, str] = {
    "none": "none",
    "default": "none",
    "name": "name",
    "id": "id",
    "list_id": "id",
    "type": "type",
}


def _safe_str(value: Any) -> str:
    return "" if value is None else str(value)


def _extract_entity_fields(entry: Mapping[str, Any]) -> dict[str, str]:
    raw_ent = entry.get("entity")
    ent: Mapping[str, Any] = raw_ent if isinstance(raw_ent, Mapping) else {}
    raw_ctx = entry.get("context")
    ctx: Mapping[str, Any] = raw_ctx if isinstance(raw_ctx, Mapping) else {}
    return {
        "id": _safe_str(ent.get("id")),
        "type": _safe_str(ent.get("type")),
        "status": _safe_str(entry.get("status")),
        "name": _safe_str(ent.get("name")),
        "annotation": _safe_str(ctx.get("annotation")),
        "domain": _safe_str(ctx.get("domain")),
        "source": _safe_str(ctx.get("source")),
        "image_url": _safe_str(ctx.get("image_url")),
    }


def _sort_records(
    records: Sequence[dict[str, Any]],
    *,
    sort_by: str,
    aliases: Mapping[str, str],
    field_extractor: Callable[[dict[str, Any]], tuple[str, str, str]],
    descending: bool,
) -> list[dict[str, Any]]:
    """Sort records case-insensitively with empty primary values placed last."""
    normalized_key = aliases.get(sort_by.strip().lower())
    if normalized_key is None:
        valid = ", ".join(sorted(set(aliases.keys())))
        raise ValueError(f"Unsupported sort field '{sort_by}'. Valid options: {valid}")
    if normalized_key == "none":
        return list(records)

    non_empty: list[tuple[str, tuple[str, str, int], dict[str, Any]]] = []
    empty: list[tuple[tuple[str, str, int], dict[str, Any]]] = []
    for idx, rec in enumerate(records):
        primary_raw, name_raw, id_raw = field_extractor(rec)
        primary_cf = primary_raw.strip().casefold()
        tie_key = (name_raw.strip().casefold(), id_raw.strip().casefold(), idx)
        if primary_cf:
            non_empty.append((primary_cf, tie_key, rec))
        else:
            empty.append((tie_key, rec))

    non_empty.sort(key=lambda item: item[1])
    non_empty.sort(key=lambda item: item[0], reverse=descending)
    empty.sort(key=lambda item: item[0])
    return [item[2] for item in non_empty] + [item[1] for item in empty]


def filter_watchlist_entities(
    entries: Sequence[dict[str, Any]],
    query: str,
) -> list[dict[str, Any]]:
    """Filter watchlist entity entries using case-insensitive multi-token matching."""
    tokens = query.strip().casefold().split()
    if not tokens:
        return list(entries)

    filtered: list[dict[str, Any]] = []
    for entry in entries:
        fields = _extract_entity_fields(entry)
        haystack = " ".join(
            (
                fields["id"],
                fields["type"],
                fields["status"],
                fields["name"],
                fields["annotation"],
                fields["domain"],
                fields["source"],
                fields["image_url"],
            )
        ).casefold()
        if all(tok in haystack for tok in tokens):
            filtered.append(entry)
    return filtered


def sort_watchlist_entities(
    entries: Sequence[dict[str, Any]],
    *,
    sort_by: str = "name",
    descending: bool = False,
) -> list[dict[str, Any]]:
    """Sort watchlist entity entries by ``name``, ``id``, ``type``, ``status``, or ``annotation``."""
    canonical = _ENTITY_SORT_ALIASES.get(sort_by.strip().lower(), sort_by)

    def _extract(entry: dict[str, Any]) -> tuple[str, str, str]:
        fields = _extract_entity_fields(entry)
        primary = fields.get(canonical, "")
        return primary, fields["name"], fields["id"]

    return _sort_records(
        entries,
        sort_by=sort_by,
        aliases=_ENTITY_SORT_ALIASES,
        field_extractor=_extract,
        descending=descending,
    )


def sort_watchlists(
    watchlists: Sequence[dict[str, Any]],
    *,
    sort_by: str = "name",
    descending: bool = False,
) -> list[dict[str, Any]]:
    """Sort watchlist summary objects by ``name``, ``id``, or ``type``."""
    canonical = _WATCHLIST_SORT_ALIASES.get(sort_by.strip().lower(), sort_by)

    def _extract(item: dict[str, Any]) -> tuple[str, str, str]:
        name_val = _safe_str(item.get("name"))
        id_val = _safe_str(item.get("id"))
        type_val = _safe_str(item.get("type"))
        primary = {"name": name_val, "id": id_val, "type": type_val}.get(canonical, "")
        return primary, name_val, id_val

    return _sort_records(
        watchlists,
        sort_by=sort_by,
        aliases=_WATCHLIST_SORT_ALIASES,
        field_extractor=_extract,
        descending=descending,
    )

_ORIG_REQUESTS_GET = requests.get


class _PatchedRequestsSession:
    """Minimal Session-like adapter forwarding ``.get`` to monkeypatched ``requests.get``."""

    def __init__(self, get_fn: Callable[..., requests.Response]) -> None:
        self._get_fn = get_fn

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        # Preserve legacy tests expecting stream-agnostic calls on requests.get
        kwargs.pop("stream", None)
        return self._get_fn(url, **kwargs)

    def close(self) -> None:
        return None


def get_domain_image_hash(
    domain: str,
    idx: int = 1,
    total: int = 1,
    ignored_hashes: Mapping[str, str] | None = None,
    *,
    config: ExtractorConfig | None = None,
    session: requests.Session | None = None,
) -> tuple[list[dict[str, str]], int, str | None, list[str], list[dict[str, Any]]]:
    """Backward-compatible wrapper forwarding monkeypatched ``soclens.watchlist.requests.get``."""
    active_session: Any = session
    if active_session is None and requests.get is not _ORIG_REQUESTS_GET:
        active_session = _PatchedRequestsSession(requests.get)
    return _logos_get_domain_image_hash(
        domain=domain,
        idx=idx,
        total=total,
        ignored_hashes=ignored_hashes,
        config=config,
        session=active_session,
    )


_ORIG_GET_DOMAIN_IMAGE_HASH = get_domain_image_hash


def _resolve_compat_hasher(
    image_hasher: Callable[..., Any] | None,
) -> Callable[..., Any] | None:
    if image_hasher is not None:
        return image_hasher
    if (
        get_domain_image_hash is not _ORIG_GET_DOMAIN_IMAGE_HASH
        or requests.get is not _ORIG_REQUESTS_GET
    ):
        return get_domain_image_hash
    return None


def validate_domain_brand_sync(
    client: RecordedFutureClient,
    list_id: str,
    domains: list[str],
    output_locations_file: str | Path | None = "discovered_images.json",
    ignored_hashes: dict[str, str] | None = None,
    ignore_hashes_file: str | Path | None = None,
    extra_hashes: list[str] | str | None = None,
    *,
    workspace_dir: str | Path | None = None,
    image_hasher: Callable[..., Any] | None = None,
    extractor_config: ExtractorConfig | None = None,
) -> bool:
    """Validate domains brand images against watchlist with hash tuning support."""
    kwargs: dict[str, Any] = {
        "output_locations_file": output_locations_file,
        "ignored_hashes": ignored_hashes,
        "ignore_hashes_file": ignore_hashes_file,
        "extra_hashes": extra_hashes,
        "workspace_dir": workspace_dir,
        "image_hasher": _resolve_compat_hasher(image_hasher),
    }
    if extractor_config is not None:
        kwargs["extractor_config"] = extractor_config
    return _logos_validate_domain_brand_sync(
        client,
        list_id,
        domains,
        **kwargs,
    )


def calculate_brand_sync_delta(
    client: RecordedFutureClient,
    list_id: str,
    domains: list[str],
    output_locations_file: str | Path | None = "discovered_images.json",
    ignored_hashes: dict[str, str] | None = None,
    ignore_hashes_file: str | Path | None = None,
    extra_hashes: list[str] | str | None = None,
    *,
    scoped_domains: Iterable[str] | None = None,
    failed_domains: Iterable[str] | None = None,
    state_grace_failures: int = 3,
    state_file: str | Path | None = DEFAULT_STATE_FILENAME,
    workspace_dir: str | Path | None = None,
    image_hasher: Callable[..., Any] | None = None,
    extractor_config: ExtractorConfig | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    list[str],
    list[dict[str, Any]],
    dict[str, str],
    dict[str, list[str]],
]:
    """Compute brand sync delta while preserving ``soclens.watchlist.get_domain_image_hash`` patching."""
    kwargs: dict[str, Any] = {
        "output_locations_file": output_locations_file,
        "ignored_hashes": ignored_hashes,
        "ignore_hashes_file": ignore_hashes_file,
        "extra_hashes": extra_hashes,
        "scoped_domains": scoped_domains,
        "failed_domains": failed_domains,
        "state_grace_failures": state_grace_failures,
        "state_file": state_file,
        "workspace_dir": workspace_dir,
        "image_hasher": _resolve_compat_hasher(image_hasher),
    }
    if extractor_config is not None:
        kwargs["extractor_config"] = extractor_config
    return _logos_calculate_brand_sync_delta(
        client,
        list_id,
        domains,
        **kwargs,
    )


def execute_domain_brand_sync(
    client: RecordedFutureClient,
    list_id: str,
    domains: list[str],
    dry_run: bool = False,
    output_locations_file: str | Path | None = "discovered_images.json",
    ignored_hashes: dict[str, str] | None = None,
    ignore_hashes_file: str | Path | None = None,
    extra_hashes: list[str] | str | None = None,
    *,
    scoped_domains: Iterable[str] | None = None,
    failed_domains: Iterable[str] | None = None,
    state_grace_failures: int = 3,
    state_file: str | Path | None = DEFAULT_STATE_FILENAME,
    workspace_dir: str | Path | None = None,
    image_hasher: Callable[..., Any] | None = None,
    extractor_config: ExtractorConfig | None = None,
) -> bool:
    """Execute brand sync while preserving ``soclens.watchlist.get_domain_image_hash`` patching."""
    kwargs: dict[str, Any] = {
        "dry_run": dry_run,
        "output_locations_file": output_locations_file,
        "ignored_hashes": ignored_hashes,
        "ignore_hashes_file": ignore_hashes_file,
        "extra_hashes": extra_hashes,
        "scoped_domains": scoped_domains,
        "failed_domains": failed_domains,
        "state_grace_failures": state_grace_failures,
        "state_file": state_file,
        "workspace_dir": workspace_dir,
        "image_hasher": _resolve_compat_hasher(image_hasher),
    }
    if extractor_config is not None:
        kwargs["extractor_config"] = extractor_config
    return _logos_execute_domain_brand_sync(
        client,
        list_id,
        domains,
        **kwargs,
    )


def run_continuous_brand_sync(
    client: RecordedFutureClient,
    list_id: str,
    domains: list[str] | None = None,
    *,
    image_hasher: Callable[..., Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Delegate continuous brand sync while forwarding ``get_domain_image_hash``."""
    return _logos_run_continuous_brand_sync(
        client,
        list_id,
        domains,
        image_hasher=_resolve_compat_hasher(image_hasher),
        **kwargs,
    )


def validate_domains_live_status(
    client: RecordedFutureClient,
    list_id: str,
    interactive: bool = False,
    dry_run: bool = False,
) -> bool:
    """Validate domain DNS liveness and optionally mark offline ones as ``noninternet``."""
    print(f"[*] Fetching entities from watchlist {list_id}...")
    try:
        existing_entries = client.get_watchlist_entities(list_id)
    except RecordedFutureError as exc:
        logger.error(
            "Failed to fetch entities for liveness validation on '%s' (trace_id=%s): %s",
            list_id,
            exc.trace_id,
            exc,
        )
        print(f"[-] Failed to fetch entities from watchlist '{list_id}': {exc}", file=sys.stderr)
        return False

    domains_to_check: list[dict[str, Any]] = []
    for entry in existing_entries:
        ent = entry.get("entity", {}) or {}
        if str(ent.get("type", "")).lower() == "internetdomainname":
            name = str(ent.get("name", "")).strip().lower()
            context = dict(entry.get("context", {}) or {})
            annotation = str(context.get("annotation", "")).lower()

            if "noninternet" in annotation:
                continue

            if name:
                domains_to_check.append(
                    {
                        "name": name,
                        "id": ent.get("id"),
                        "context": context,
                    }
                )

    if not domains_to_check:
        print("[-] No untagged InternetDomainName entities found in watchlist to check.")
        return True

    print(f"[*] Checking DNS liveness for {len(domains_to_check)} domain(s)...")

    live_domains: list[dict[str, Any]] = []
    offline_domains: list[dict[str, Any]] = []

    for idx, d_info in enumerate(domains_to_check, 1):
        domain = d_info["name"]
        print(f"    [{idx}/{len(domains_to_check)}] {domain} ", end="", flush=True)
        try:
            ip = socket.gethostbyname(domain)
            if ip.startswith("127.") or ip == "0.0.0.0":
                print(f"- OFFLINE (Sinkholed/Localhost: {ip})")
                offline_domains.append(d_info)
            else:
                print(f"- LIVE ({ip})")
                live_domains.append(d_info)
        except socket.gaierror:
            print("- OFFLINE (No DNS resolution)")
            offline_domains.append(d_info)

    print("\n" + "=" * 40)
    print(" LIVENESS REPORT")
    print("=" * 40)
    print(f"[+] LIVE: {len(live_domains)}")
    print(f"[-] OFFLINE: {len(offline_domains)}")

    if not offline_domains:
        print("[*] All checked domains are live. Nothing to update.")
        return True

    if interactive:
        print("\nOffline Domains:")
        for i, d in enumerate(offline_domains, 1):
            print(f"  {i}. {d['name']}")

        print(
            "\nEnter indices to tag as 'noninternet' (comma-separated, e.g., 1,3,4), "
            "'all', or 'none':"
        )
        choice = input("> ").strip().lower()

        selected: list[dict[str, Any]] = []
        if choice == "none" or not choice:
            print("[*] No domains selected. Exiting.")
            return True
        if choice == "all":
            selected = offline_domains
        else:
            for p in choice.split(","):
                p_clean = p.strip()
                if p_clean.isdigit():
                    idx = int(p_clean) - 1
                    if 0 <= idx < len(offline_domains):
                        selected.append(offline_domains[idx])

        if selected:
            print(f"\n[*] The following {len(selected)} domain(s) will be tagged as 'noninternet':")
            for d in selected:
                print(f"  - {d['name']}")

            confirm = input("\nConfirm tagging these domain(s)? (y/N): ").strip().lower()
            if confirm != "y":
                print("[-] Update cancelled.")
                return True

            print(f"[*] Proceeding to tag {len(selected)} domains as 'noninternet'...")
            for d in selected:
                new_context = dict(d["context"])
                existing_annot = new_context.get("annotation", "")
                if existing_annot:
                    new_context["annotation"] = f"{existing_annot} [noninternet]"
                else:
                    new_context["annotation"] = "noninternet"

                if dry_run:
                    print(
                        f"[DRY-RUN] Would tag domain '{d['name']}' "
                        f"with context annotation '{new_context['annotation']}'"
                    )
                else:
                    client.add_entity(
                        list_id, "InternetDomainName", d["name"], context=new_context
                    )

    return True


def export_watchlist(
    client: RecordedFutureClient,
    list_id: str,
    output_path: str | Path,
    file_format: str = "csv",
) -> bool:
    """Export all entities from a watchlist to a CSV or JSON file."""
    print(f"[*] Fetching entities from watchlist '{list_id}'...")
    try:
        entries = client.get_watchlist_entities(list_id)
    except RecordedFutureError as exc:
        logger.error(
            "Failed to fetch entities for export from '%s' (trace_id=%s): %s",
            list_id,
            exc.trace_id,
            exc,
        )
        print(f"[-] Failed to fetch entities from watchlist '{list_id}': {exc}", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"[-] Failed to fetch entities from watchlist '{list_id}': {exc}", file=sys.stderr)
        return False

    if not entries:
        print(f"[*] Watchlist '{list_id}' is empty.")

    dest = Path(output_path).expanduser()
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if file_format.lower() == "json":
            with dest.open("w", encoding="utf-8") as fh:
                json.dump(entries, fh, indent=2)
            print(f"[+] Watchlist successfully exported to JSON: {dest}")
            return True

        with dest.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                ["name", "type", "id", "annotation", "source", "domain", "image_url", "sync_time"]
            )
            for entry in entries:
                ent = entry.get("entity", {}) or {}
                ctx = entry.get("context", {}) or {}
                writer.writerow(
                    [
                        ent.get("name", ""),
                        ent.get("type", ""),
                        ent.get("id", ""),
                        ctx.get("annotation", ""),
                        ctx.get("source", ""),
                        ctx.get("domain", ""),
                        ctx.get("image_url", ""),
                        ctx.get("sync_time", ""),
                    ]
                )
        print(f"[+] Watchlist successfully exported to CSV: {dest}")
        return True
    except Exception as exc:
        print(f"[-] Failed to write watchlist to '{dest}': {exc}", file=sys.stderr)
        return False


__all__ = [
    "DEFAULT_IGNORED_DOMAINS",
    "DEFAULT_IGNORED_HASHES",
    "DEFAULT_LOCK_FILENAME",
    "DEFAULT_STATE_FILENAME",
    "ENTITY_SORT_FIELDS",
    "EXCLUSION_KEYWORDS",
    "PROMO_KEYWORDS",
    "THIRD_PARTY_BADGE_HOSTS",
    "UI_ICON_KEYWORDS",
    "VALID_HASH_LENGTHS",
    "WATCHLIST_SORT_FIELDS",
    "DomainExtractionResult",
    "ExtractedLogo",
    "ExtractorConfig",
    "ImageInfo",
    "SyncLock",
    "SyncLockError",
    "apply_brand_sync_delta",
    "calculate_brand_sync_delta",
    "canonicalize_inline_svg",
    "canonicalize_svg",
    "compute_image_hashes",
    "compute_inline_svg_hashes",
    "decode_data_uri",
    "execute_domain_brand_sync",
    "export_watchlist",
    "extract_domain_logos",
    "extract_domains_from_watchlist_entities",
    "extract_domains_logos",
    "filter_watchlist_entities",
    "get_domain_image_hash",
    "get_domains_from_watchlist",
    "is_excluded_image",
    "is_ignored_domain",
    "is_noise_match",
    "is_pid_alive",
    "load_brand_sync_state",
    "load_domain_overrides",
    "load_domains_file",
    "load_ignored_hashes",
    "match_ignored_hash",
    "normalize_hash",
    "normalize_text",
    "parse_image_info",
    "parse_srcset",
    "resolve_state_path",
    "run_continuous_brand_sync",
    "save_brand_sync_state",
    "save_discovered_locations",
    "sort_watchlist_entities",
    "sort_watchlists",
    "validate_domain_brand_sync",
    "validate_domains_live_status",
    "validate_image_bytes",
]
