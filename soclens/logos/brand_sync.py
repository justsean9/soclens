"""Idempotent, non-destructive brand logo delta sync, state persistence, locking, and watch loop."""

from __future__ import annotations

import ctypes
import json
import logging
import os
import re
import signal
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soclens.client import (
    WATCHLIST_DEFAULT_LIMIT,
    WATCHLIST_WARNING_THRESHOLD,
    RecordedFutureAuthError,
    RecordedFutureClient,
    RecordedFutureError,
    RecordedFutureRateLimitError,
)
from soclens.config import get_workspace_dir, has_rf_ssl_config_override, has_rf_ssl_env_override
from soclens.logos.extractor import (
    ExtractorConfig,
    extract_domains_logos,
    get_domain_image_hash,
    is_ignored_domain,
    load_domains_file,
)
from soclens.logos.hashing import load_ignored_hashes, match_ignored_hash

_ORIG_GET_DOMAIN_IMAGE_HASH = get_domain_image_hash

logger = logging.getLogger("soclens.logos.brand_sync")

DEFAULT_STATE_FILENAME = "brand_sync_state.json"
DEFAULT_LOCK_FILENAME = ".brand_sync.lock"
BRAND_SYNC_ISSUE_CATEGORIES: tuple[str, ...] = (
    "all",
    "missing_hashes",
    "silent_zero_hashes",
    "domain_errors",
    "image_errors",
    "failing_grace",
    "duplicate_hashes",
)
BRAND_SYNC_ISSUE_LABELS: dict[str, str] = {
    "all": "All Issues",
    "missing_hashes": "Missing Hashes (0)",
    "silent_zero_hashes": "Zero Hashes (No Error)",
    "domain_errors": "Domain / HTTP / Bot Errors",
    "image_errors": "Image Fetch / Validation Errors",
    "failing_grace": "Repeated Failures (Grace Risk)",
    "duplicate_hashes": "Shared / Duplicate Hashes",
}
BRAND_ROW_SORT_FIELDS: tuple[str, ...] = (
    "none",
    "domain",
    "status",
    "hashes",
    "failures",
    "detail",
    "severity",
)
BRAND_DOMAIN_SORT_FIELDS: tuple[str, ...] = (
    "domain",
    "hashes",
    "failures",
    "selected",
    "issues",
)
_BRAND_ROW_SORT_ALIASES: dict[str, str] = {
    "none": "none",
    "default": "none",
    "domain": "domain",
    "key": "domain",
    "status": "status",
    "hashes": "hashes",
    "hash_count": "hashes",
    "count": "hashes",
    "failures": "failures",
    "consecutive_failures": "failures",
    "detail": "detail",
    "reason": "detail",
    "severity": "severity",
}
_ANNOTATION_DOMAINS_RE = re.compile(
    r"brand image for\s+([a-zA-Z0-9.-]+(?::\d+)?(?:\s*,\s*[a-zA-Z0-9.-]+(?::\d+)?)*)",
    re.IGNORECASE,
)


class SyncLockError(RuntimeError):
    """Raised when an active brand sync process already holds the lockfile."""


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_pid_alive(pid: int) -> bool:
    """Return True if a process with ``pid`` appears alive on POSIX or Windows."""
    if not isinstance(pid, int) or pid <= 0:
        return False

    if os.name == "nt":
        win_dll_cls = getattr(ctypes, "WinDLL", None)
        if win_dll_cls is None:
            return False
        kernel32 = win_dll_cls("kernel32", use_last_error=True)
        c_void_p = ctypes.c_void_p
        c_ulong = ctypes.c_ulong
        c_int = ctypes.c_int

        open_process = kernel32.OpenProcess
        open_process.argtypes = [c_ulong, c_int, c_ulong]
        open_process.restype = c_void_p

        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = [c_void_p, ctypes.POINTER(c_ulong)]
        get_exit_code.restype = c_int

        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [c_void_p]
        close_handle.restype = c_int

        process_query_limited_information = 0x1000
        still_active = 259
        error_access_denied = 5
        handle = open_process(process_query_limited_information, 0, pid)
        if not handle:
            get_last_error = getattr(ctypes, "get_last_error", None)
            err = get_last_error() if callable(get_last_error) else 0
            return bool(err == error_access_denied)
        try:
            exit_code = c_ulong()
            if get_exit_code(handle, ctypes.byref(exit_code)):
                return bool(exit_code.value == still_active)
            return False
        finally:
            close_handle(handle)

    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


class SyncLock:
    """Cross-platform atomic lockfile using ``O_CREAT | O_EXCL`` with stale-PID recovery."""

    def __init__(self, lock_path: str | Path, stale_seconds: float = 7200.0) -> None:
        self.lock_path = Path(lock_path).expanduser()
        self.stale_seconds = stale_seconds
        self._acquired = False
        self._owner_pid: int | None = None

    def acquire(self) -> None:
        """Acquire the lockfile, recovering stale locks or raising ``SyncLockError``."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        current_host = socket.gethostname()
        current_pid = os.getpid()

        for _ in range(3):
            try:
                fd = os.open(
                    self.lock_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o644,
                )
            except FileExistsError:
                is_stale, holder_pid = self._inspect_existing_lock(current_host)
                if is_stale:
                    logger.warning(
                        "Removing stale brand sync lock at '%s' (previous PID: %s)",
                        self.lock_path,
                        holder_pid,
                    )
                    self.lock_path.unlink(missing_ok=True)
                    continue
                raise SyncLockError(
                    f"Brand sync lock held by PID {holder_pid} at {self.lock_path}"
                )

            payload = json.dumps(
                {
                    "pid": current_pid,
                    "hostname": current_host,
                    "acquired_at": _utc_now_iso(),
                    "epoch": time.time(),
                }
            ).encode("utf-8")
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            self._acquired = True
            self._owner_pid = current_pid
            return

        raise SyncLockError(f"Failed to acquire brand sync lock at {self.lock_path}")

    def _inspect_existing_lock(self, current_host: str) -> tuple[bool, Any]:
        now = time.time()
        try:
            stat_info = self.lock_path.stat()
            mtime = stat_info.st_mtime
        except FileNotFoundError:
            return True, None

        try:
            raw = self.lock_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except Exception:
            if (now - mtime) > 5.0:
                return True, "unknown"
            return False, "unknown"

        if not isinstance(data, dict):
            return ((now - mtime) > 5.0), "unknown"

        holder_pid = data.get("pid")
        holder_host = data.get("hostname")
        raw_epoch = data.get("epoch")
        lock_time = float(raw_epoch) if isinstance(raw_epoch, (int, float)) else mtime

        if (now - lock_time) > self.stale_seconds:
            return True, holder_pid

        if (
            holder_host == current_host
            and isinstance(holder_pid, int)
            and not is_pid_alive(holder_pid)
        ):
            return True, holder_pid

        return False, holder_pid

    def release(self) -> None:
        """Release the lockfile if still owned by the current process."""
        if not self._acquired:
            return
        try:
            if self.lock_path.exists():
                try:
                    data = json.loads(self.lock_path.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and data.get("pid") not in (None, self._owner_pid):
                        return
                except Exception:
                    pass
                self.lock_path.unlink(missing_ok=True)
        finally:
            self._acquired = False
            self._owner_pid = None

    def __enter__(self) -> SyncLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()


def _default_state() -> dict[str, Any]:
    return {
        "version": 1,
        "list_id": None,
        "updated_at": None,
        "runs_completed": 0,
        "last_run": None,
        "domains": {},
    }


def resolve_state_path(
    state_file: str | Path | None = None,
    workspace_dir: str | Path | None = None,
) -> Path:
    """Resolve the path to ``brand_sync_state.json`` cross-platform."""
    if state_file is not None and str(state_file).strip():
        candidate = Path(str(state_file).strip()).expanduser()
        if not candidate.is_absolute() and (
            workspace_dir is not None or candidate == Path(DEFAULT_STATE_FILENAME)
        ):
            return get_workspace_dir(workspace_dir) / candidate
        return candidate
    return get_workspace_dir(workspace_dir) / DEFAULT_STATE_FILENAME


def load_brand_sync_state(state_path: str | Path) -> dict[str, Any]:
    """Load persisted brand sync state from disk, returning defaults if missing or corrupt."""
    path = Path(state_path).expanduser()
    if not path.is_file():
        return _default_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            return _default_state()
        state = _default_state()
        state.update(data)
        if not isinstance(state.get("domains"), dict):
            state["domains"] = {}
        return state
    except Exception as exc:
        logger.warning("Corrupt brand sync state at '%s' (%s); starting fresh.", path, exc)
        return _default_state()


def save_brand_sync_state(state: Mapping[str, Any], state_path: str | Path) -> Path:
    """Atomically persist brand sync state to disk via temporary file + ``os.replace``."""
    path = Path(state_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    serialized = json.dumps(state, indent=2, sort_keys=False)
    try:
        with tmp_path.open("w", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
    return path


def save_discovered_locations(
    locations: list[dict[str, Any]],
    file_path: str | Path | None,
) -> None:
    """Save discovered image location diagnostics to JSON, skipping when ``file_path`` is None."""
    if not file_path:
        return
    path = Path(file_path).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(locations, fh, indent=2)
        print(f"[*] Discovered image locations saved to '{path}'")
    except Exception as exc:
        print(f"[-] Failed to save discovered image locations to '{path}': {exc}", file=sys.stderr)


def extract_domains_from_watchlist_entities(
    client: RecordedFutureClient,
    list_id: str,
    *,
    raise_on_error: bool = False,
) -> list[str]:
    """Extract unique domains from watchlist entities and brand-sync contexts."""
    print(f"[*] Extracting domains from watchlist '{list_id}' entities context...")
    try:
        entities = client.get_watchlist_entities(list_id)
    except RecordedFutureError as exc:
        print(f"[-] Failed to fetch entities from watchlist '{list_id}': {exc}", file=sys.stderr)
        if raise_on_error:
            raise
        return []
    except Exception as exc:
        print(f"[-] Failed to fetch entities from watchlist '{list_id}': {exc}", file=sys.stderr)
        if raise_on_error:
            raise
        return []

    extracted_domains: set[str] = set()
    for entry in entities:
        ent = entry.get("entity", {}) or {}
        if str(ent.get("type", "")).lower() == "internetdomainname":
            name = str(ent.get("name", "")).strip().lower()
            if name and not is_ignored_domain(name):
                extracted_domains.add(name)
            continue

        ctx = entry.get("context", {}) or {}
        ctx_domains = ctx.get("domains")
        if isinstance(ctx_domains, Iterable) and not isinstance(ctx_domains, (str, bytes)):
            for d in ctx_domains:
                d_clean = str(d).strip().lower()
                if d_clean and not is_ignored_domain(d_clean):
                    extracted_domains.add(d_clean)

        domain = ctx.get("domain")
        if domain:
            domain_clean = str(domain).strip().lower()
            if domain_clean and not is_ignored_domain(domain_clean):
                extracted_domains.add(domain_clean)
        elif not ctx_domains:
            annotation = str(ctx.get("annotation", "")).lower()
            match = _ANNOTATION_DOMAINS_RE.search(annotation)
            if match:
                for part in match.group(1).split(","):
                    domain_clean = part.strip().rstrip(".").lower()
                    if (
                        domain_clean
                        and "." in domain_clean
                        and " " not in domain_clean
                        and not is_ignored_domain(domain_clean)
                    ):
                        extracted_domains.add(domain_clean)

    domains = sorted(extracted_domains)
    print(f"[*] Extracted {len(domains)} unique domain(s) from watchlist.")
    return domains


def _extract_entry_domains(
    entry: Mapping[str, Any],
    sha256: str,
    state_hash_owners: Mapping[str, set[str]],
) -> set[str]:
    owners: set[str] = set()
    ctx = entry.get("context", {}) or {}

    raw_domains = ctx.get("domains")
    if isinstance(raw_domains, Iterable) and not isinstance(raw_domains, (str, bytes)):
        for d in raw_domains:
            clean = str(d).strip().lower()
            if clean:
                owners.add(clean)

    single_domain = ctx.get("domain")
    if isinstance(single_domain, str) and single_domain.strip():
        owners.add(single_domain.strip().lower())

    annotation = str(ctx.get("annotation", ""))
    if annotation:
        match = _ANNOTATION_DOMAINS_RE.search(annotation)
        if match:
            for part in match.group(1).split(","):
                clean = part.strip().rstrip(".").lower()
                if clean and "." in clean and " " not in clean:
                    owners.add(clean)

    if sha256 in state_hash_owners:
        owners.update(state_hash_owners[sha256])

    return owners


def _warn_watchlist_capacity(projected_count: int, list_id: str) -> None:
    if projected_count >= WATCHLIST_DEFAULT_LIMIT:
        msg = (
            f"Watchlist '{list_id}' projected size is {projected_count} "
            f"(>= {WATCHLIST_DEFAULT_LIMIT} entity default limit); additions may be rejected."
        )
        logger.warning(msg)
        print(f"[!] WARNING: {msg}")
    elif projected_count >= WATCHLIST_WARNING_THRESHOLD:
        msg = (
            f"Watchlist '{list_id}' projected size is {projected_count} "
            f"(approaching {WATCHLIST_DEFAULT_LIMIT}-entity default limit)."
        )
        logger.warning(msg)
        print(f"[!] WARNING: {msg}")


def _normalize_domain_list(domains: Iterable[str]) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in domains:
        dom = str(raw).strip().lower()
        if not dom or is_ignored_domain(dom):
            continue
        if dom not in seen:
            seen.add(dom)
            cleaned.append(dom)
    return cleaned


def _resolve_extractor_config(
    client: RecordedFutureClient,
    extractor_config: ExtractorConfig | None,
) -> ExtractorConfig | None:
    if extractor_config is not None:
        return extractor_config
    client_verify = getattr(client, "verify_ssl", None)
    if isinstance(client_verify, (bool, str)):
        if client_verify is not True:
            return ExtractorConfig(verify_ssl=client_verify)
        if has_rf_ssl_env_override() or has_rf_ssl_config_override():
            return ExtractorConfig(verify_ssl=True)
    return None


def _extract_domains_for_sync(
    clean_domains: list[str],
    ignored_hashes: Mapping[str, str],
    image_hasher: Callable[..., Any] | None = None,
    *,
    progress_callback: Callable[..., Any] | None = None,
    extractor_config: ExtractorConfig | None = None,
) -> list[
    tuple[
        str,
        tuple[list[dict[str, str]], int, str | None, list[str], list[dict[str, Any]]],
    ]
]:
    total_domains = len(clean_domains)
    if image_hasher is None and get_domain_image_hash is _ORIG_GET_DOMAIN_IMAGE_HASH and total_domains > 1:
        extract_kwargs: dict[str, Any] = {"ignored_hashes": ignored_hashes}
        if extractor_config is not None:
            extract_kwargs["config"] = extractor_config
        if progress_callback is not None:
            extract_kwargs["progress_callback"] = progress_callback
        results = extract_domains_logos(clean_domains, **extract_kwargs)
        return [
            (dom, res.to_legacy_tuple())
            for dom, res in zip(clean_domains, results, strict=True)
        ]

    hasher = image_hasher if image_hasher is not None else get_domain_image_hash
    extracted: list[
        tuple[
            str,
            tuple[list[dict[str, str]], int, str | None, list[str], list[dict[str, Any]]],
        ]
    ] = []
    for idx, domain in enumerate(clean_domains, 1):
        if extractor_config is not None:
            try:
                res = hasher(
                    domain,
                    idx,
                    total_domains,
                    ignored_hashes=ignored_hashes,
                    config=extractor_config,
                )
            except TypeError as exc:
                if "config" not in str(exc):
                    raise
                res = hasher(domain, idx, total_domains, ignored_hashes=ignored_hashes)
        else:
            res = hasher(domain, idx, total_domains, ignored_hashes=ignored_hashes)
        extracted.append((domain, res))
        if progress_callback is not None:
            try:
                progress_callback(idx, total_domains, domain, res)
            except Exception:
                pass
    return extracted


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
    progress_callback: Callable[..., Any] | None = None,
    extractor_config: ExtractorConfig | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    list[str],
    list[dict[str, Any]],
    dict[str, str],
    dict[str, list[str]],
]:
    """Scrape domains and compute non-destructive, domain-scoped delta updates.

    Returns the 6-tuple:
    ``(target_hashes, existing_map, to_add, to_remove, domain_errors, image_errors)``.
    """
    if not domains:
        domains = extract_domains_from_watchlist_entities(
            client, list_id, raise_on_error=True
        )

    clean_domains = _normalize_domain_list(domains)
    if ignored_hashes is None:
        ignored_hashes = load_ignored_hashes(
            file_path=ignore_hashes_file,
            extra_hashes=extra_hashes,
            workspace_dir=workspace_dir,
        )

    target_hashes: dict[str, Any] = {}
    all_domain_errors: dict[str, str] = {}
    all_image_errors: dict[str, list[str]] = {}
    all_discovered_locations: list[dict[str, Any]] = []
    hash_domains_map: dict[str, list[str]] = {}
    succeeded_domains: set[str] = set()
    effective_failed_domains: set[str] = {
        str(d).strip().lower() for d in (failed_domains or ()) if str(d).strip()
    }
    resolved_cfg = _resolve_extractor_config(client, extractor_config)

    for domain, (hashes_list, _queried, domain_err, img_errs, disc_locs) in _extract_domains_for_sync(
        clean_domains,
        ignored_hashes,
        image_hasher,
        progress_callback=progress_callback,
        extractor_config=resolved_cfg,
    ):
        all_discovered_locations.extend(disc_locs)

        if domain_err:
            all_domain_errors[domain] = domain_err
        if img_errs:
            all_image_errors[domain] = img_errs

        has_excluded = any(loc.get("status") == "excluded" for loc in disc_locs)
        if domain_err or (img_errs and not hashes_list) or (not hashes_list and not has_excluded):
            effective_failed_domains.add(domain)
        else:
            succeeded_domains.add(domain)

        for hashes in hashes_list:
            sha256 = str(hashes["sha256"]).strip().lower()
            hash_domains_map.setdefault(sha256, [])
            if domain not in hash_domains_map[sha256]:
                hash_domains_map[sha256].append(domain)

            if sha256 not in target_hashes:
                target_hashes[sha256] = {
                    "domain": domain,
                    "domains": [domain],
                    "image_url": hashes["image_url"],
                    "image_urls": {domain: hashes["image_url"]},
                    "type": "SHA-256",
                }
            else:
                if domain not in target_hashes[sha256]["domains"]:
                    target_hashes[sha256]["domains"].append(domain)
                    target_hashes[sha256]["domains"].sort()
                target_hashes[sha256]["image_urls"][domain] = hashes["image_url"]

    if output_locations_file:
        save_discovered_locations(all_discovered_locations, output_locations_file)

    duplicates = {h: doms for h, doms in hash_domains_map.items() if len(doms) > 1}
    if duplicates:
        print("\n[!] DUPLICATE SHA-256 HASHES DETECTED ACROSS DOMAINS:")
        for h, doms in sorted(duplicates.items()):
            print(f"    - {h}")
            print(f"      Domains ({len(doms)}): {', '.join(sorted(doms))}")
        print(
            "    [i] Tip: If these domains are unrelated, this hash may be shared vendor/CMS noise. "
            "Add it to ignored_hashes.txt to tune out."
        )

    existing_entries = client.get_watchlist_entities(list_id)
    existing_map: dict[str, dict[str, Any]] = {}
    for entry in existing_entries:
        ent = entry.get("entity", {}) or {}
        ent_type = str(ent.get("type", "")).strip().lower()
        if ent_type and ent_type != "hash":
            continue
        name = str(ent.get("name", "")).strip().lower()
        if name:
            existing_map[name] = entry

    effective_scoped: set[str] = (
        {str(d).strip().lower() for d in scoped_domains if str(d).strip()}
        if scoped_domains is not None
        else set(clean_domains)
    )

    state: dict[str, Any] = _default_state()
    if state_file is not None and str(state_file).strip():
        state_path = resolve_state_path(state_file, workspace_dir)
        if state_path.is_file():
            state = load_brand_sync_state(state_path)

    state_hash_owners: dict[str, set[str]] = {}
    for dom_name, dom_info in state.get("domains", {}).items():
        if isinstance(dom_info, dict):
            for h in dom_info.get("hashes", []):
                clean_h = str(h).strip().lower()
                if clean_h:
                    state_hash_owners.setdefault(clean_h, set()).add(dom_name.lower())

    to_add = [sha256 for sha256 in target_hashes if sha256 not in existing_map]
    to_remove: list[dict[str, Any]] = []

    for name, entry in existing_map.items():
        matched_ignored, ignored_reason = match_ignored_hash(name, ignored_hashes)
        if matched_ignored is not None:
            print(
                f"[*] Watchlist entity '{name}' matches tuned-out hash ({ignored_reason}). "
                "Marking for removal."
            )
            to_remove.append(entry.get("entity", {}))
            continue

        if name not in target_hashes:
            ctx = entry.get("context", {}) or {}
            if ctx.get("source") != "automated-watchlist-manager":
                continue

            owners = _extract_entry_domains(entry, name, state_hash_owners)
            if owners:
                # Never prune if any owning domain is outside the current run scope.
                if any(owner not in effective_scoped for owner in owners):
                    continue

                # Never prune if any owning domain failed and has not exceeded grace period.
                protected_by_failure = False
                for owner in owners:
                    if owner in effective_failed_domains:
                        prev_failures = int(
                            state.get("domains", {}).get(owner, {}).get("consecutive_failures", 0)
                        )
                        next_failures = prev_failures + 1
                        if state_grace_failures <= 0 or next_failures < state_grace_failures:
                            protected_by_failure = True
                            break
                if protected_by_failure:
                    continue

                to_remove.append(entry.get("entity", {}))
            else:
                # Unattributed automated entity (e.g., legacy entries without domain metadata):
                # only remove on an unscoped, error-free run that produced active hashes.
                if (
                    scoped_domains is None
                    and not effective_failed_domains
                    and bool(target_hashes)
                ):
                    to_remove.append(entry.get("entity", {}))

    return target_hashes, existing_map, to_add, to_remove, all_domain_errors, all_image_errors


def apply_brand_sync_delta(
    client: RecordedFutureClient,
    list_id: str,
    target_hashes: dict[str, Any],
    to_add: list[str],
    to_remove: list[dict[str, Any]],
    dry_run: bool = False,
    *,
    existing_count: int | None = None,
) -> tuple[int, int]:
    """Apply additions and removals to the Recorded Future brand watchlist."""
    if existing_count is not None:
        projected = max(0, existing_count - len(to_remove) + len(to_add))
        _warn_watchlist_capacity(projected, list_id)

    removed_count = 0
    for ent in to_remove:
        ent_id = ent.get("id")
        ent_name = ent.get("name")
        if dry_run:
            print(f"[DRY-RUN] Would remove stale image hash '{ent_name}' (ID: {ent_id})")
            removed_count += 1
            continue
        try:
            if ent_id:
                res = client.remove_entity(list_id, str(ent_id))
            elif ent_name:
                res = client.remove_entity(list_id, str(ent_name), entity_type="Hash")
            else:
                continue
            if res:
                print(f"[+] Removed entity '{ent_name or ent_id}'")
                removed_count += 1
        except (RecordedFutureAuthError, RecordedFutureRateLimitError) as exc:
            logger.error(
                "Aborting entity removals on list '%s' (trace_id=%s): %s",
                list_id,
                exc.trace_id,
                exc,
            )
            print(f"[-] Error removing entity from '{list_id}': {exc}", file=sys.stderr)
            break
        except RecordedFutureError as exc:
            logger.warning(
                "Failed to remove entity '%s' from '%s' (trace_id=%s): %s",
                ent_name or ent_id,
                list_id,
                exc.trace_id,
                exc,
            )
            print(f"[-] Failed to remove entity '{ent_name or ent_id}': {exc}", file=sys.stderr)

    added_count = 0
    for sha256 in to_add:
        domain_info = target_hashes[sha256]
        domain = domain_info["domain"]
        domains_list = list(domain_info.get("domains") or [domain])
        image_url = domain_info["image_url"]
        if dry_run:
            print(
                f"[DRY-RUN] Would add image hash '{sha256}' "
                f"(Domain: {', '.join(domains_list)}, URL: {image_url})"
            )
            added_count += 1
            continue

        domain_label = domain if len(domains_list) == 1 else ", ".join(domains_list)
        context: dict[str, Any] = {
            "annotation": f"Automated sync: Brand image for {domain_label} (URL: {image_url})",
            "source": "automated-watchlist-manager",
            "domain": domain,
            "domains": domains_list,
            "image_url": image_url,
            "sync_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        try:
            if client.add_entity(list_id, "Hash", sha256, context=context):
                print(f"[+] Added entity '{sha256}'")
                added_count += 1
        except (RecordedFutureAuthError, RecordedFutureRateLimitError) as exc:
            logger.error(
                "Aborting entity additions on list '%s' (trace_id=%s): %s",
                list_id,
                exc.trace_id,
                exc,
            )
            print(f"[-] Error adding entity to '{list_id}': {exc}", file=sys.stderr)
            break
        except RecordedFutureError as exc:
            logger.warning(
                "Failed to add entity '%s' to '%s' (trace_id=%s): %s",
                sha256,
                list_id,
                exc.trace_id,
                exc,
            )
            print(f"[-] Failed to add entity '{sha256}': {exc}", file=sys.stderr)

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

    return added_count, removed_count


def _update_state_after_sync(
    state_path: Path,
    list_id: str,
    domains: list[str],
    target_hashes: Mapping[str, Any],
    domain_errors: Mapping[str, str],
    image_errors: Mapping[str, list[str]],
    added_count: int,
    removed_count: int,
) -> None:
    state = load_brand_sync_state(state_path)
    now_iso = _utc_now_iso()
    state["list_id"] = list_id
    state["updated_at"] = now_iso
    state["runs_completed"] = int(state.get("runs_completed", 0)) + 1

    domain_hashes: dict[str, list[str]] = {d: [] for d in domains}
    for sha256, info in target_hashes.items():
        owners = info.get("domains") or [info.get("domain")]
        for d in owners:
            if d in domain_hashes and sha256 not in domain_hashes[d]:
                domain_hashes[d].append(sha256)

    domains_state = state.setdefault("domains", {})
    for d in domains:
        prev = domains_state.get(d, {})
        if not isinstance(prev, dict):
            prev = {}
        found_hashes = sorted(domain_hashes.get(d, []))
        d_err = domain_errors.get(d)
        i_errs = image_errors.get(d, [])
        failed = bool(d_err) or (bool(i_errs) and not found_hashes)

        if failed:
            consecutive = int(prev.get("consecutive_failures", 0)) + 1
            domains_state[d] = {
                "last_attempt": now_iso,
                "last_success": prev.get("last_success"),
                "consecutive_failures": consecutive,
                "hashes": prev.get("hashes", []),
                "last_error": d_err or "; ".join(i_errs),
            }
        else:
            domains_state[d] = {
                "last_attempt": now_iso,
                "last_success": now_iso,
                "consecutive_failures": 0,
                "hashes": found_hashes,
                "last_error": None,
            }

    state["last_run"] = {
        "timestamp": now_iso,
        "domains_count": len(domains),
        "target_hashes": len(target_hashes),
        "added": added_count,
        "removed": removed_count,
        "domain_errors": dict(domain_errors),
    }
    save_brand_sync_state(state, state_path)


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
    progress_callback: Callable[..., Any] | None = None,
    extractor_config: ExtractorConfig | None = None,
) -> bool:
    """Execute non-destructive delta sync based on brand images of target domains."""
    resolved_domains = list(domains)
    resolved_cfg = _resolve_extractor_config(client, extractor_config)
    try:
        delta_kwargs: dict[str, Any] = {
            "output_locations_file": output_locations_file,
            "ignored_hashes": ignored_hashes,
            "ignore_hashes_file": ignore_hashes_file,
            "extra_hashes": extra_hashes,
            "scoped_domains": scoped_domains,
            "failed_domains": failed_domains,
            "state_grace_failures": state_grace_failures,
            "state_file": state_file,
            "workspace_dir": workspace_dir,
            "image_hasher": image_hasher,
        }
        if progress_callback is not None:
            delta_kwargs["progress_callback"] = progress_callback
        if resolved_cfg is not None:
            delta_kwargs["extractor_config"] = resolved_cfg
        target_hashes, existing_map, to_add, to_remove, domain_errors, image_errors = (
            calculate_brand_sync_delta(
                client,
                list_id,
                resolved_domains,
                **delta_kwargs,
            )
        )
    except RecordedFutureError as exc:
        logger.error(
            "Brand sync aborted due to Recorded Future API error (trace_id=%s): %s",
            exc.trace_id,
            exc,
        )
        print(f"[-] Recorded Future API error during brand sync: {exc}", file=sys.stderr)
        return False

    print("\n" + "=" * 40)
    print(" SYNC SUMMARY")
    print("=" * 40)
    print(f"[*] Successfully resolved {len(target_hashes)} active brand image hash(es) from domains.")

    if domain_errors:
        print("\n[!] Domain connection failures:")
        for dom, err in domain_errors.items():
            print(f"    - {dom}: {err}")

    if image_errors:
        print("\n[!] Image fetch failures:")
        for dom, errs in image_errors.items():
            print(f"    - {dom}: {len(errs)} error(s)")
            for e in errs:
                print(f"        * {e}")

    if not target_hashes and not to_remove:
        print(
            "\n[-] FAILED to fetch/calculate brand image hashes for any domain. "
            "Sync aborted to prevent clearing the watchlist.",
            file=sys.stderr,
        )
        if not dry_run and state_file is not None and str(state_file).strip():
            clean_doms = _normalize_domain_list(resolved_domains)
            if clean_doms:
                _update_state_after_sync(
                    resolve_state_path(state_file, workspace_dir),
                    list_id,
                    clean_doms,
                    target_hashes,
                    domain_errors,
                    image_errors,
                    0,
                    0,
                )
        return False

    print(f"[*] Watchlist currently contains {len(existing_map)} entity/entities.")
    print(f"[*] Delta calculated: {len(to_add)} to add, {len(to_remove)} to remove.")

    added_count, removed_count = apply_brand_sync_delta(
        client,
        list_id,
        target_hashes,
        to_add,
        to_remove,
        dry_run=dry_run,
        existing_count=len(existing_map),
    )

    if not dry_run and state_file is not None and str(state_file).strip():
        clean_doms = _normalize_domain_list(
            resolved_domains
            if resolved_domains
            else sorted(
                {
                    d
                    for info in target_hashes.values()
                    for d in (info.get("domains") or [info.get("domain")])
                    if d
                }
                | set(domain_errors.keys())
            )
        )
        _update_state_after_sync(
            resolve_state_path(state_file, workspace_dir),
            list_id,
            clean_doms,
            target_hashes,
            domain_errors,
            image_errors,
            added_count,
            removed_count,
        )

    return True


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
    """Validate domain brand images against a watchlist without modifying the list."""
    if not domains:
        try:
            domains = extract_domains_from_watchlist_entities(
                client, list_id, raise_on_error=True
            )
        except RecordedFutureError as exc:
            logger.error("Could not fetch watchlist '%s' (trace_id=%s): %s", list_id, exc.trace_id, exc)
            print(f"[-] Could not fetch entities from watchlist '{list_id}': {exc}", file=sys.stderr)
            return False

    clean_domains = _normalize_domain_list(domains)
    if not clean_domains:
        print("[-] No domains specified or found in watchlist for validation.", file=sys.stderr)
        return False

    if ignored_hashes is None:
        ignored_hashes = load_ignored_hashes(
            file_path=ignore_hashes_file,
            extra_hashes=extra_hashes,
            workspace_dir=workspace_dir,
        )

    total_domains = len(clean_domains)
    print(f"\n[*] Starting validation for {total_domains} domain(s)...")

    target_hashes: dict[str, Any] = {}
    all_discovered_locations: list[dict[str, Any]] = []
    hash_domains_map: dict[str, list[str]] = {}
    domain_errors: dict[str, str] = {}
    image_errors: dict[str, list[str]] = {}
    failed_domains: list[str] = []
    resolved_cfg = _resolve_extractor_config(client, extractor_config)

    for domain, (hashes_list, _queried, domain_err, img_errs, disc_locs) in _extract_domains_for_sync(
        clean_domains, ignored_hashes, image_hasher, extractor_config=resolved_cfg
    ):
        all_discovered_locations.extend(disc_locs)

        if domain_err:
            domain_errors[domain] = domain_err
        if img_errs:
            image_errors[domain] = img_errs

        if not hashes_list:
            failed_domains.append(domain)

        for hashes in hashes_list:
            sha256 = str(hashes["sha256"]).strip().lower()
            hash_domains_map.setdefault(sha256, [])
            if domain not in hash_domains_map[sha256]:
                hash_domains_map[sha256].append(domain)

            if sha256 not in target_hashes:
                target_hashes[sha256] = {
                    "domain": domain,
                    "domains": [domain],
                    "image_url": hashes["image_url"],
                    "type": "SHA-256",
                }
            elif domain not in target_hashes[sha256]["domains"]:
                target_hashes[sha256]["domains"].append(domain)
                target_hashes[sha256]["domains"].sort()

    if output_locations_file:
        save_discovered_locations(all_discovered_locations, output_locations_file)

    duplicates = {h: doms for h, doms in hash_domains_map.items() if len(doms) > 1}
    if duplicates:
        print("\n[!] DUPLICATE SHA-256 HASHES DETECTED ACROSS DOMAINS:")
        for h, doms in sorted(duplicates.items()):
            print(f"    - {h}")
            print(f"      Domains ({len(doms)}): {', '.join(sorted(doms))}")

    print(f"\n[*] Successfully fetched {len(target_hashes)} active brand image SHA-256 hash(es) from domains.")

    print(f"[*] Fetching entities from watchlist {list_id}...")
    try:
        existing_entries = client.get_watchlist_entities(list_id)
    except RecordedFutureError as exc:
        logger.error("Could not fetch watchlist '%s' (trace_id=%s): %s", list_id, exc.trace_id, exc)
        print(f"[-] Could not fetch entities from watchlist '{list_id}': {exc}", file=sys.stderr)
        return False

    existing_hashes: dict[str, dict[str, Any]] = {}
    for entry in existing_entries:
        ent = entry.get("entity", {}) or {}
        if str(ent.get("type", "")).lower() == "hash":
            name = str(ent.get("name", "")).strip().lower()
            if name:
                existing_hashes[name] = ent

    print(f"[*] Watchlist currently contains {len(existing_hashes)} 'Hash' entities.")

    matched = set(target_hashes.keys()).intersection(existing_hashes.keys())
    missing = set(target_hashes.keys()) - set(existing_hashes.keys())
    orphans = set(existing_hashes.keys()) - set(target_hashes.keys())

    print("\n" + "=" * 40)
    print(" VALIDATION REPORT")
    print("=" * 40)
    print(f"\n[+] MATCHED HASHES: {len(matched)}")
    for h in sorted(matched):
        info = target_hashes[h]
        print(f"    - {h} ({info['type']} for {info['domain']})")

    print(f"\n[-] MISSING HASHES (On Domain, Not In List): {len(missing)}")
    for h in sorted(missing):
        info = target_hashes[h]
        print(f"    - {h} ({info['type']} for {info['domain']}, URL: {info['image_url']})")

    print(f"\n[!] DOMAINS WITH NO ACTIVE IMAGES: {len(failed_domains)}")
    for dom in sorted(failed_domains):
        err = domain_errors.get(dom)
        img_err_list = image_errors.get(dom, [])
        if err:
            print(f"    - {dom} (Connection failed: {err})")
        elif img_err_list:
            print(f"    - {dom} (Failed to download/hash image(s): {', '.join(img_err_list)})")
        else:
            print(f"    - {dom} (No suitable images found or all were excluded)")

    print(f"\n[!] ORPHANED HASHES (In List, Not On Domain): {len(orphans)}")
    for h in sorted(orphans):
        print(f"    - {h} (ID: {existing_hashes[h].get('id', 'N/A')})")

    print("\n" + "=" * 40)
    return True


def get_domains_from_watchlist(client: RecordedFutureClient, list_id: str) -> list[str]:
    """Extract live domain names from a Recorded Future watchlist, skipping noninternet."""
    print(f"[*] Fetching entities from source watchlist {list_id}...")
    entities = client.get_watchlist_entities(list_id)
    domains: list[str] = []
    skipped = 0
    for entry in entities:
        ent = entry.get("entity", {}) or {}
        name = str(ent.get("name", "")).strip()
        context = entry.get("context", {}) or {}
        annotation = str(context.get("annotation", "")).lower()

        if "noninternet" in annotation:
            skipped += 1
            continue

        if name and "." in name and " " not in name and not is_ignored_domain(name):
            domains.append(name)

    print(
        f"[*] Extracted {len(domains)} domain(s) from watchlist "
        f"(Skipped {skipped} non-internet domain(s))."
    )
    return domains


def run_continuous_brand_sync(
    client: RecordedFutureClient,
    list_id: str,
    domains: list[str] | None = None,
    *,
    source_list_id: str | None = None,
    domains_file: str | Path | None = None,
    dry_run: bool = False,
    output_locations_file: str | Path | None = "discovered_images.json",
    ignored_hashes: dict[str, str] | None = None,
    ignore_hashes_file: str | Path | None = None,
    extra_hashes: list[str] | str | None = None,
    interval_seconds: float = 3600.0,
    max_runs: int | None = None,
    state_file: str | Path | None = None,
    lock_file: str | Path | None = None,
    state_grace_failures: int = 3,
    stop_event: threading.Event | None = None,
    workspace_dir: str | Path | None = None,
    on_run_complete: Callable[[dict[str, Any]], None] | None = None,
    image_hasher: Callable[..., Any] | None = None,
    extractor_config: ExtractorConfig | None = None,
) -> dict[str, Any]:
    """Run brand logo sync unattended in a locked, signal-safe continuous loop."""
    state_path = resolve_state_path(state_file, workspace_dir)
    lock_path = (
        Path(lock_file).expanduser()
        if lock_file is not None and str(lock_file).strip()
        else get_workspace_dir(workspace_dir) / DEFAULT_LOCK_FILENAME
    )
    event = stop_event if stop_event is not None else threading.Event()

    is_main = threading.current_thread() is threading.main_thread()
    previous_handlers: dict[int, Any] = {}

    def _signal_handler(signum: int, _frame: Any) -> None:
        logger.info("Received signal %s; stopping continuous brand sync gracefully.", signum)
        event.set()

    if is_main:
        for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            sig = getattr(signal, sig_name, None)
            if sig is not None:
                try:
                    previous_handlers[sig] = signal.getsignal(sig)
                    signal.signal(sig, _signal_handler)
                except (ValueError, OSError):
                    pass

    runs_attempted = 0
    runs_succeeded = 0
    runs_failed = 0
    last_error: str | None = None

    try:
        with SyncLock(lock_path):
            while not event.is_set():
                if max_runs is not None and runs_attempted >= max_runs:
                    break

                runs_attempted += 1
                run_error: str | None = None
                run_ok = False

                try:
                    active_domains: list[str] = []
                    if source_list_id:
                        active_domains = get_domains_from_watchlist(client, source_list_id)
                    elif domains_file is not None:
                        active_domains = load_domains_file(domains_file)
                    elif domains:
                        active_domains = list(domains)

                    run_kwargs: dict[str, Any] = {
                        "dry_run": dry_run,
                        "output_locations_file": output_locations_file,
                        "ignored_hashes": ignored_hashes,
                        "ignore_hashes_file": ignore_hashes_file,
                        "extra_hashes": extra_hashes,
                        "state_grace_failures": state_grace_failures,
                        "state_file": state_path,
                        "workspace_dir": workspace_dir,
                        "image_hasher": image_hasher,
                    }
                    iter_cfg = _resolve_extractor_config(client, extractor_config)
                    if iter_cfg is not None:
                        run_kwargs["extractor_config"] = iter_cfg
                    run_ok = execute_domain_brand_sync(
                        client,
                        list_id,
                        active_domains,
                        **run_kwargs,
                    )
                    if not run_ok:
                        run_error = "Brand sync returned False"
                except RecordedFutureError as exc:
                    run_ok = False
                    run_error = str(exc)
                    logger.warning(
                        "Transient RF API error in continuous sync (trace_id=%s): %s",
                        exc.trace_id,
                        exc,
                    )
                except Exception as exc:
                    run_ok = False
                    run_error = str(exc)
                    logger.exception("Unexpected error in continuous brand sync: %s", exc)

                if run_ok:
                    runs_succeeded += 1
                else:
                    runs_failed += 1
                    last_error = run_error

                if on_run_complete is not None:
                    on_run_complete(
                        {
                            "run": runs_attempted,
                            "success": run_ok,
                            "error": run_error,
                            "timestamp": _utc_now_iso(),
                        }
                    )

                if max_runs is not None and runs_attempted >= max_runs:
                    break
                if event.is_set():
                    break

                event.wait(timeout=max(0.0, float(interval_seconds)))
    finally:
        if is_main:
            for sig, prev in previous_handlers.items():
                try:
                    signal.signal(sig, prev)
                except (ValueError, OSError):
                    pass

    return {
        "runs_attempted": runs_attempted,
        "runs_succeeded": runs_succeeded,
        "runs_failed": runs_failed,
        "stopped": event.is_set(),
        "state_file": str(state_path),
        "lock_file": str(lock_path),
        "last_error": last_error,
    }


@dataclass(frozen=True)
class BrandSyncIssue:
    """Structured issue diagnostic record produced from Brand Sync state, runs, or watchlists."""

    category: str
    categories: tuple[str, ...]
    severity: str
    severity_rank: int
    domain: str
    hash_count: int
    consecutive_failures: int
    status: str
    reason: str
    last_attempt: str = ""
    last_success: str = ""
    sha256: str = ""
    domains: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize issue record into a JSON-friendly dictionary."""
        return {
            "category": self.category,
            "categories": list(self.categories),
            "severity": self.severity,
            "severity_rank": self.severity_rank,
            "domain": self.domain,
            "hash_count": self.hash_count,
            "consecutive_failures": self.consecutive_failures,
            "status": self.status,
            "reason": self.reason,
            "last_attempt": self.last_attempt,
            "last_success": self.last_success,
            "sha256": self.sha256,
            "domains": list(self.domains),
        }


@dataclass(frozen=True)
class BrandSyncIssuesReport:
    """Aggregated health summary and categorized issues across Brand Sync domains."""

    source: str
    total_domains: int
    healthy_domains: int
    missing_hashes_count: int
    silent_zero_hashes_count: int
    domain_errors_count: int
    image_errors_count: int
    failing_grace_count: int
    duplicate_hashes_count: int
    never_synced_count: int
    issues: tuple[BrandSyncIssue, ...]
    category_counts: dict[str, int]
    domain_hash_counts: dict[str, int]
    domain_failure_counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        """Serialize report summary and issues into a JSON-friendly dictionary."""
        return {
            "source": self.source,
            "total_domains": self.total_domains,
            "healthy_domains": self.healthy_domains,
            "missing_hashes_count": self.missing_hashes_count,
            "silent_zero_hashes_count": self.silent_zero_hashes_count,
            "domain_errors_count": self.domain_errors_count,
            "image_errors_count": self.image_errors_count,
            "failing_grace_count": self.failing_grace_count,
            "duplicate_hashes_count": self.duplicate_hashes_count,
            "never_synced_count": self.never_synced_count,
            "category_counts": dict(self.category_counts),
            "domain_hash_counts": dict(self.domain_hash_counts),
            "domain_failure_counts": dict(self.domain_failure_counts),
            "issues": [issue.to_dict() for issue in self.issues],
        }


def analyze_brand_sync_issues(
    *,
    state: Mapping[str, Any] | None = None,
    watchlist_domains: Iterable[str] | None = None,
    target_hashes: Mapping[str, Any] | None = None,
    existing_entries: Sequence[Mapping[str, Any]] | None = None,
    domain_errors: Mapping[str, str] | None = None,
    image_errors: Mapping[str, Sequence[str]] | None = None,
    scoped_domains: Iterable[str] | None = None,
    grace_failures: int = 3,
) -> BrandSyncIssuesReport:
    """Analyze brand sync state, watchlist coverage, and live run errors into typed issue dashboards."""
    raw_domains_val = state.get("domains") if isinstance(state, Mapping) else None
    raw_state_domains: Mapping[str, Any] = (
        raw_domains_val if isinstance(raw_domains_val, Mapping) else {}
    )
    has_live_run = (
        target_hashes is not None
        or scoped_domains is not None
        or domain_errors is not None
        or image_errors is not None
    )
    has_state = bool(raw_state_domains)
    has_audit = watchlist_domains is not None or existing_entries is not None

    active_sources = sum(1 for flag in (has_live_run, has_state, has_audit) if flag)
    if active_sources > 1:
        source = "combined"
    elif has_live_run:
        source = "sync_run"
    elif has_audit:
        source = "watchlist_audit"
    else:
        source = "state"

    records: dict[str, dict[str, Any]] = {}

    def _ensure_rec(dom: str) -> dict[str, Any]:
        clean = dom.strip().lower()
        if clean not in records:
            records[clean] = {
                "hashes": set(),
                "failures": 0,
                "domain_error": "",
                "image_errors": [],
                "last_attempt": "",
                "last_success": "",
                "never_synced": False,
            }
        return records[clean]

    state_hash_owners: dict[str, set[str]] = {}
    for raw_dom, raw_info in raw_state_domains.items():
        dom = str(raw_dom).strip().lower()
        if not dom:
            continue
        info: Mapping[str, Any] = raw_info if isinstance(raw_info, Mapping) else {}
        rec = _ensure_rec(dom)
        hashes_set = {
            str(h).strip().lower() for h in (info.get("hashes") or []) if str(h).strip()
        }
        rec["hashes"] = hashes_set
        for h in hashes_set:
            state_hash_owners.setdefault(h, set()).add(dom)
        rec["failures"] = int(info.get("consecutive_failures") or 0)
        rec["domain_error"] = str(info.get("last_error") or "").strip()
        rec["last_attempt"] = str(info.get("last_attempt") or "").strip()
        rec["last_success"] = str(info.get("last_success") or "").strip()

    if existing_entries is not None:
        for entry in existing_entries:
            if not isinstance(entry, Mapping):
                continue
            ent = entry.get("entity")
            ent_map: Mapping[str, Any] = ent if isinstance(ent, Mapping) else {}
            ent_type = str(ent_map.get("type") or "").strip().lower()
            if ent_type and ent_type != "hash":
                continue
            sha = str(ent_map.get("name") or "").strip().lower()
            if not sha:
                continue
            owners = _extract_entry_domains(entry, sha, state_hash_owners)
            for owner in owners:
                owner_clean = owner.strip().lower()
                if owner_clean:
                    _ensure_rec(owner_clean)["hashes"].add(sha)

    if has_live_run:
        run_domain_hashes: dict[str, set[str]] = {}
        for sha_raw, meta in (target_hashes or {}).items():
            sha = str(sha_raw).strip().lower()
            if not sha:
                continue
            meta_map: Mapping[str, Any] = meta if isinstance(meta, Mapping) else {}
            target_owners = meta_map.get("domains") or (
                [meta_map.get("domain")] if meta_map.get("domain") else []
            )
            for owner in target_owners:
                owner_clean = str(owner).strip().lower()
                if owner_clean:
                    run_domain_hashes.setdefault(owner_clean, set()).add(sha)

        run_dom_errors: dict[str, str] = {
            str(k).strip().lower(): str(v).strip()
            for k, v in (domain_errors or {}).items()
            if str(k).strip()
        }
        run_img_errors: dict[str, list[str]] = {
            str(k).strip().lower(): [str(e).strip() for e in (v or []) if str(e).strip()]
            for k, v in (image_errors or {}).items()
            if str(k).strip()
        }

        run_scope: set[str] = {
            str(d).strip().lower() for d in (scoped_domains or ()) if str(d).strip()
        }
        run_scope.update(run_domain_hashes.keys())
        run_scope.update(run_dom_errors.keys())
        run_scope.update(run_img_errors.keys())

        for dom in run_scope:
            rec = _ensure_rec(dom)
            found = run_domain_hashes.get(dom, set())
            d_err = run_dom_errors.get(dom, "")
            i_errs = run_img_errors.get(dom, [])
            rec["hashes"] = set(found)
            rec["domain_error"] = d_err
            rec["image_errors"] = list(i_errs)
            rec["never_synced"] = False
            if d_err or (i_errs and not found):
                rec["failures"] = max(int(rec["failures"]), 1)
            elif found:
                rec["failures"] = 0

    if watchlist_domains is not None:
        for raw_dom in watchlist_domains:
            dom = str(raw_dom).strip().lower()
            if not dom or is_ignored_domain(dom):
                continue
            if dom not in records:
                rec = _ensure_rec(dom)
                rec["never_synced"] = True

    hash_to_domains: dict[str, set[str]] = {}
    domain_hash_counts: dict[str, int] = {}
    domain_failure_counts: dict[str, int] = {}
    issues_list: list[BrandSyncIssue] = []
    healthy_domains = 0
    never_synced_count = 0

    for dom in sorted(records):
        rec = records[dom]
        hashes_set = rec["hashes"]
        hash_count = len(hashes_set)
        failures = int(rec["failures"])
        d_err = str(rec["domain_error"]).strip()
        i_errs = list(rec["image_errors"])
        never_synced = bool(rec["never_synced"])

        domain_hash_counts[dom] = hash_count
        domain_failure_counts[dom] = failures
        for h in hashes_set:
            hash_to_domains.setdefault(h, set()).add(dom)

        cats: list[str] = []
        if hash_count == 0:
            cats.append("missing_hashes")
        if never_synced:
            never_synced_count += 1
        if hash_count == 0 and not never_synced and not d_err and not i_errs and failures == 0:
            cats.append("silent_zero_hashes")
        if d_err:
            cats.append("domain_errors")
        if i_errs:
            cats.append("image_errors")
        if failures >= 1:
            cats.append("failing_grace")

        if not cats:
            healthy_domains += 1
            continue

        grace_limit = max(1, int(grace_failures))
        if never_synced:
            status = "NEVER SYNCED"
            reason = "In domain watchlist with 0 tracked hashes (not yet synced)"
        elif hash_count == 0:
            if failures >= grace_limit:
                status = "GRACE EXCEEDED"
            elif d_err:
                status = "NO HASHES (ERR)"
            elif i_errs:
                status = "NO HASHES (IMG ERR)"
            else:
                status = "NO HASHES (0 LOGOS)"

            reason_parts: list[str] = []
            if d_err:
                reason_parts.append(d_err)
            if i_errs:
                reason_parts.append(f"Image errors ({len(i_errs)}): {'; '.join(i_errs)}")
            if reason_parts:
                reason = "0 hashes | " + " | ".join(reason_parts)
            elif failures >= 1:
                reason = f"0 brand image hashes ({failures} consecutive failure(s))"
            else:
                reason = "0 brand image hashes extracted (no HTTP/connection error recorded)"
        else:
            if failures >= grace_limit:
                status = "GRACE EXCEEDED"
            elif failures >= 1:
                status = f"FAILING ({failures}/{grace_limit})"
            elif d_err:
                status = "DOMAIN ERROR"
            else:
                status = f"IMG ERR ({len(i_errs)})"

            reason_parts = []
            if d_err:
                reason_parts.append(d_err)
            if i_errs:
                reason_parts.append(f"Image errors ({len(i_errs)}): {'; '.join(i_errs)}")
            reason = " | ".join(reason_parts) if reason_parts else f"{failures} consecutive failure(s)"

        if hash_count == 0 or failures >= grace_limit:
            severity = "critical"
            severity_rank = 0
        elif d_err or failures >= 2:
            severity = "high"
            severity_rank = 1
        else:
            severity = "medium"
            severity_rank = 2

        issues_list.append(
            BrandSyncIssue(
                category=cats[0],
                categories=tuple(cats),
                severity=severity,
                severity_rank=severity_rank,
                domain=dom,
                hash_count=hash_count,
                consecutive_failures=failures,
                status=status,
                reason=reason,
                last_attempt=str(rec["last_attempt"]),
                last_success=str(rec["last_success"]),
            )
        )

    for sha, doms_set in sorted(hash_to_domains.items()):
        if len(doms_set) > 1:
            sorted_doms = tuple(sorted(doms_set))
            issues_list.append(
                BrandSyncIssue(
                    category="duplicate_hashes",
                    categories=("duplicate_hashes",),
                    severity="low",
                    severity_rank=3,
                    domain=f"{sha[:16]}...",
                    hash_count=len(sorted_doms),
                    consecutive_failures=0,
                    status=f"SHARED ({len(sorted_doms)} DOMAINS)",
                    reason=f"Shared across {len(sorted_doms)} domains: {', '.join(sorted_doms)}",
                    sha256=sha,
                    domains=sorted_doms,
                )
            )

    issues_list.sort(
        key=lambda item: (
            item.severity_rank,
            -item.consecutive_failures,
            item.hash_count,
            item.domain.lower(),
        )
    )

    category_counts: dict[str, int] = {"all": len(issues_list)}
    for cat in BRAND_SYNC_ISSUE_CATEGORIES:
        if cat == "all":
            continue
        category_counts[cat] = sum(1 for item in issues_list if cat in item.categories)

    return BrandSyncIssuesReport(
        source=source,
        total_domains=len(records),
        healthy_domains=healthy_domains,
        missing_hashes_count=category_counts["missing_hashes"],
        silent_zero_hashes_count=category_counts["silent_zero_hashes"],
        domain_errors_count=category_counts["domain_errors"],
        image_errors_count=category_counts["image_errors"],
        failing_grace_count=category_counts["failing_grace"],
        duplicate_hashes_count=category_counts["duplicate_hashes"],
        never_synced_count=never_synced_count,
        issues=tuple(issues_list),
        category_counts=category_counts,
        domain_hash_counts=domain_hash_counts,
        domain_failure_counts=domain_failure_counts,
    )


def sort_brand_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    sort_by: str = "domain",
    descending: bool = False,
) -> list[dict[str, Any]]:
    """Sort Brand Logos table row dictionaries by text or numeric columns."""
    canonical = _BRAND_ROW_SORT_ALIASES.get(sort_by.strip().lower())
    if canonical is None:
        valid = ", ".join(BRAND_ROW_SORT_FIELDS)
        raise ValueError(f"Unsupported brand sort field '{sort_by}'. Valid options: {valid}")
    materialized = [dict(row) for row in rows]
    if canonical == "none":
        return materialized

    if canonical in ("hashes", "failures", "severity"):
        numeric_rows: list[tuple[int, tuple[str, str, int], dict[str, Any]]] = []
        missing_rows: list[tuple[tuple[str, str, int], dict[str, Any]]] = []
        key_name = {
            "hashes": "hash_count",
            "failures": "consecutive_failures",
            "severity": "severity_rank",
        }[canonical]

        for idx, row in enumerate(materialized):
            tie = (
                str(row.get("domain") or "").strip().casefold(),
                str(row.get("status") or "").strip().casefold(),
                idx,
            )
            raw_val = row.get(key_name)
            if isinstance(raw_val, bool) or raw_val is None or raw_val == "":
                missing_rows.append((tie, row))
            else:
                try:
                    numeric_rows.append((int(raw_val), tie, row))
                except (TypeError, ValueError):
                    missing_rows.append((tie, row))

        numeric_rows.sort(key=lambda item: item[1])
        numeric_rows.sort(key=lambda item: item[0], reverse=descending)
        missing_rows.sort(key=lambda item: item[0])
        return [item[2] for item in numeric_rows] + [item[1] for item in missing_rows]

    non_empty: list[tuple[str, tuple[str, str, int], dict[str, Any]]] = []
    empty: list[tuple[tuple[str, str, int], dict[str, Any]]] = []
    for idx, row in enumerate(materialized):
        raw = str(row.get(canonical) or "").strip()
        tie = (
            str(row.get("domain") or "").strip().casefold(),
            str(row.get("status") or "").strip().casefold(),
            idx,
        )
        if raw:
            non_empty.append((raw.casefold(), tie, row))
        else:
            empty.append((tie, row))

    non_empty.sort(key=lambda item: item[1])
    non_empty.sort(key=lambda item: item[0], reverse=descending)
    empty.sort(key=lambda item: item[0])
    return [item[2] for item in non_empty] + [item[1] for item in empty]


def sort_brand_issues(
    issues: Sequence[BrandSyncIssue],
    *,
    sort_by: str = "severity",
    descending: bool = False,
) -> list[BrandSyncIssue]:
    """Sort ``BrandSyncIssue`` records by ``severity``, ``domain``, ``status``, ``hashes``, ``failures``, or ``detail``."""
    canonical = _BRAND_ROW_SORT_ALIASES.get(sort_by.strip().lower())
    if canonical is None:
        valid = ", ".join(BRAND_ROW_SORT_FIELDS)
        raise ValueError(f"Unsupported brand issue sort field '{sort_by}'. Valid options: {valid}")
    if canonical == "none":
        return list(issues)

    indexed = [
        {
            "_idx": idx,
            "domain": issue.domain,
            "status": issue.status,
            "hash_count": issue.hash_count,
            "consecutive_failures": issue.consecutive_failures,
            "detail": issue.reason,
            "severity_rank": issue.severity_rank,
        }
        for idx, issue in enumerate(issues)
    ]
    ordered = sort_brand_rows(indexed, sort_by=canonical, descending=descending)
    return [issues[int(row["_idx"])] for row in ordered]


def filter_brand_issues(
    issues: Sequence[BrandSyncIssue],
    *,
    category: str = "all",
    query: str = "",
) -> list[BrandSyncIssue]:
    """Filter ``BrandSyncIssue`` records by issue category and case-insensitive search tokens."""
    clean_cat = category.strip().lower() or "all"
    if clean_cat not in BRAND_SYNC_ISSUE_CATEGORIES:
        valid = ", ".join(BRAND_SYNC_ISSUE_CATEGORIES)
        raise ValueError(f"Unsupported brand issue category '{category}'. Valid options: {valid}")
    tokens = query.strip().casefold().split()

    filtered: list[BrandSyncIssue] = []
    for issue in issues:
        if clean_cat != "all" and clean_cat not in issue.categories:
            continue
        if tokens:
            haystack = " ".join(
                (
                    issue.domain,
                    issue.status,
                    issue.reason,
                    issue.sha256,
                    " ".join(issue.domains),
                    " ".join(issue.categories),
                )
            ).casefold()
            if not all(tok in haystack for tok in tokens):
                continue
        filtered.append(issue)
    return filtered


def sort_brand_domains(
    domains: Sequence[str],
    *,
    sort_by: str = "domain",
    descending: bool = False,
    state_domains: Mapping[str, Mapping[str, Any]] | None = None,
    hash_counts: Mapping[str, int] | None = None,
    failure_counts: Mapping[str, int] | None = None,
    selected_domains: set[str] | None = None,
) -> list[str]:
    """Sort watchlist domain strings by domain name, hash count, failure count, selection, or issue status."""
    key_mode = sort_by.strip().lower()
    if key_mode not in BRAND_DOMAIN_SORT_FIELDS:
        valid = ", ".join(BRAND_DOMAIN_SORT_FIELDS)
        raise ValueError(f"Unsupported domain sort field '{sort_by}'. Valid options: {valid}")

    resolved_hashes: dict[str, int] = {
        str(k).strip().lower(): int(v) for k, v in (hash_counts or {}).items()
    }
    resolved_failures: dict[str, int] = {
        str(k).strip().lower(): int(v) for k, v in (failure_counts or {}).items()
    }
    if state_domains:
        for raw_dom, raw_info in state_domains.items():
            dom = str(raw_dom).strip().lower()
            if not dom or not isinstance(raw_info, Mapping):
                continue
            if dom not in resolved_hashes:
                resolved_hashes[dom] = len(raw_info.get("hashes") or [])
            if dom not in resolved_failures:
                resolved_failures[dom] = int(raw_info.get("consecutive_failures") or 0)

    selected_cf = {d.strip().lower() for d in (selected_domains or set())}

    def _sort_key(dom: str) -> tuple[Any, ...]:
        dom_cf = dom.strip().lower()
        h_cnt = resolved_hashes.get(dom_cf, 0)
        f_cnt = resolved_failures.get(dom_cf, 0)
        is_sel = 1 if dom_cf in selected_cf else 0
        if key_mode == "domain":
            return (dom_cf,)
        if key_mode == "hashes":
            return (h_cnt, dom_cf)
        if key_mode == "failures":
            return (f_cnt, -h_cnt, dom_cf)
        if key_mode == "selected":
            return (is_sel, dom_cf)
        has_issue = 0 if (h_cnt == 0 or f_cnt > 0) else 1
        return (has_issue, -f_cnt, h_cnt, dom_cf)

    ordered = sorted(domains, key=_sort_key)
    if descending:
        if key_mode == "domain":
            ordered.sort(key=lambda d: d.strip().lower(), reverse=True)
        elif key_mode == "hashes":
            ordered.sort(key=lambda d: (resolved_hashes.get(d.strip().lower(), 0),), reverse=True)
        elif key_mode == "failures":
            ordered.sort(
                key=lambda d: (
                    resolved_failures.get(d.strip().lower(), 0),
                    -resolved_hashes.get(d.strip().lower(), 0),
                ),
                reverse=True,
            )
        elif key_mode == "selected":
            ordered.sort(
                key=lambda d: (1 if d.strip().lower() in selected_cf else 0,),
                reverse=True,
            )
        else:
            ordered.reverse()
    return ordered
