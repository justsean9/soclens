"""Persistent per-credential API access / entitlement denial registry."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

logger = logging.getLogger("soclens.api_access")

_PROXY_MARKERS: tuple[str, ...] = (
    "<html",
    "<!doctype html",
    "proxysg",
    "blue coat",
    "bluecoat",
    "edge swg",
    "policy_denied",
    "symantec web security",
)

_RF_PREFIX_CAPABILITY_MAP: tuple[tuple[str, str], ...] = (
    ("/collective-insights/", "collective_insights"),
    ("/risk/", "risk_history"),
    ("/identity/", "identity"),
    ("/v2/company/", "v2_company"),
    ("/malware-intelligence/", "malware_intel"),
    ("/detection-rule/", "detection_rules"),
    ("/analyst-note/", "analyst_notes"),
    ("/links/", "links"),
    ("/threat/", "threat_maps"),
    ("/alert/", "alerts_v3"),
    ("/playbook-alert/", "playbook_alerts"),
    ("/case/", "cases"),
    ("/soar/v3/", "soar_v3"),
    ("/autonomous-threat-operations/", "ato"),
    ("/fusion/", "fusion"),
    ("/taxii2/", "taxii2"),
    ("/v1/toes", "riskrecon"),
    ("/projects", "asi"),
)


def credential_fingerprint(*parts: str | None) -> str:
    """Return a short non-reversible SHA-256 fingerprint of credential material."""
    cleaned = [str(p).strip() for p in parts if p is not None and str(p).strip()]
    if not cleaned:
        return "unconfigured"
    digest = hashlib.sha256("\0".join(cleaned).encode("utf-8")).hexdigest()
    return digest[:12]


def is_permanent_access_denial(
    status_code: int | None,
    *,
    permission_type: str = "",
    message: str = "",
) -> bool:
    """Return True for HTTP 401/403 entitlement or credential failures (excluding proxy blocks)."""
    if status_code == 401:
        return True
    if status_code != 403:
        return False
    perm = str(permission_type or "").strip().lower()
    if perm == "proxy_blocked":
        return False
    msg_low = str(message or "").lower()
    if any(marker in msg_low for marker in _PROXY_MARKERS):
        return False
    return True


def classify_rf_endpoint_capability(
    endpoint: str,
    *,
    auth_mode: str | None = None,
    category: str | None = None,
) -> str | None:
    """Map an API endpoint + auth mode/category to a canonical capability key."""
    mode_low = str(auth_mode or "").strip().lower()
    cat_low = str(category or "").strip().lower()
    ep = str(endpoint or "").strip().lower()

    if mode_low == "sandbox" or cat_low == "sandbox_v0" or ep == "/search" or ep.startswith("/samples"):
        return "sandbox_v0"
    if mode_low == "asi":
        return "asi"
    if mode_low == "pfi":
        return "pfi"
    if mode_low == "riskrecon":
        return "riskrecon"
    if mode_low == "taxii2":
        return "taxii2"

    for prefix, cap in _RF_PREFIX_CAPABILITY_MAP:
        if ep.startswith(prefix) or ep == prefix.rstrip("/"):
            return cap
    return None


class ApiAccessRegistry:
    """Thread-safe persisted registry caching API access denials per credential fingerprint."""

    def __init__(self, state_path: Path | str | None = None) -> None:
        self._lock = threading.RLock()
        self._io_lock = threading.Lock()
        self._state_path: Path | None = Path(state_path) if state_path is not None else None
        self._entries: dict[str, dict[str, Any]] = {}
        self._loaded: bool = False
        if self._state_path is not None and self._state_path.is_file():
            self.load()

    @property
    def state_path(self) -> Path | None:
        return self._state_path

    def rebind_path(self, state_path: Path | str | None) -> None:
        """Thread-safely rebind API access registry path and reload state."""
        new_path = Path(state_path) if state_path is not None else None
        with self._io_lock:
            with self._lock:
                self._state_path = new_path
                self._entries.clear()
                self._loaded = False
        if new_path is not None and new_path.is_file():
            self.load()

    def load(self) -> int:
        """Load persisted capability access records from disk."""
        if self._state_path is None or not self._state_path.is_file():
            return 0
        try:
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.debug("Skipping unreadable api_access file %s: %s", self._state_path, exc)
            return 0
        raw_caps = raw.get("capabilities") if isinstance(raw, Mapping) else None
        if not isinstance(raw_caps, Mapping):
            return 0
        loaded: dict[str, dict[str, Any]] = {}
        for cap, rec in raw_caps.items():
            if not isinstance(cap, str) or not isinstance(rec, Mapping):
                continue
            loaded[cap] = {
                "status": str(rec.get("status") or ""),
                "status_code": rec.get("status_code"),
                "reason": str(rec.get("reason") or ""),
                "permission_type": str(rec.get("permission_type") or ""),
                "credential_fp": str(rec.get("credential_fp") or ""),
                "updated_at": float(rec.get("updated_at") or 0.0),
            }
        with self._lock:
            for cap, rec in loaded.items():
                existing = self._entries.get(cap)
                if existing is None or rec["updated_at"] > float(existing.get("updated_at") or 0.0):
                    self._entries[cap] = rec
            self._loaded = True
        return len(loaded)

    def _persist(self, snapshot: dict[str, dict[str, Any]]) -> None:
        if self._state_path is None:
            return
        try:
            payload = json.dumps({"capabilities": snapshot}, ensure_ascii=False, indent=2)
            with self._io_lock:
                self._state_path.parent.mkdir(parents=True, exist_ok=True)
                fd, tmp_name = tempfile.mkstemp(
                    prefix=".api_access.",
                    suffix=".tmp",
                    dir=str(self._state_path.parent),
                )
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        fh.write(payload)
                    os.replace(tmp_name, self._state_path)
                except Exception:
                    try:
                        os.unlink(tmp_name)
                    except OSError:
                        pass
                    raise
        except Exception as exc:
            logger.debug("Failed to persist api_access registry: %s", exc)

    def get_denial(self, capability: str, *, credential_fp: str) -> dict[str, Any] | None:
        """Return cached denial record if ``capability`` was denied for ``credential_fp``."""
        if not capability or not credential_fp:
            return None
        with self._lock:
            rec = self._entries.get(capability)
        if not rec:
            return None
        if rec.get("status") != "denied":
            return None
        if rec.get("credential_fp") != credential_fp:
            return None
        return dict(rec)

    def is_denied(self, capability: str, *, credential_fp: str) -> bool:
        """Return True if ``capability`` is cached as denied for ``credential_fp``."""
        return self.get_denial(capability, credential_fp=credential_fp) is not None

    def record_denial(
        self,
        capability: str,
        *,
        credential_fp: str,
        status_code: int | None,
        reason: str,
        permission_type: str = "",
    ) -> None:
        """Persist an access denial for ``capability`` tied to ``credential_fp``."""
        if not capability or not credential_fp:
            return
        entry = {
            "status": "denied",
            "status_code": status_code,
            "reason": str(reason or "Access denied").strip()[:240],
            "permission_type": str(permission_type or "").strip(),
            "credential_fp": credential_fp,
            "updated_at": time.time(),
        }
        with self._lock:
            self._entries[capability] = entry
            snapshot = {k: dict(v) for k, v in self._entries.items()}
        self._persist(snapshot)
        logger.info(
            "Cached API access denial for %s (HTTP %s, fp=%s): %s",
            capability,
            status_code,
            credential_fp,
            entry["reason"],
        )

    def record_available(self, capability: str, *, credential_fp: str) -> None:
        """Mark ``capability`` available for ``credential_fp`` (clearing prior denial)."""
        if not capability or not credential_fp:
            return
        with self._lock:
            existing = self._entries.get(capability)
            if (
                existing is not None
                and existing.get("status") == "available"
                and existing.get("credential_fp") == credential_fp
            ):
                return
            self._entries[capability] = {
                "status": "available",
                "status_code": 200,
                "reason": "Accessible",
                "permission_type": "",
                "credential_fp": credential_fp,
                "updated_at": time.time(),
            }
            snapshot = {k: dict(v) for k, v in self._entries.items()}
        self._persist(snapshot)

    def clear(self, capability: str | None = None) -> None:
        """Clear one capability or all capabilities from memory and disk."""
        with self._lock:
            if capability is None:
                self._entries.clear()
            else:
                self._entries.pop(capability, None)
            snapshot = {k: dict(v) for k, v in self._entries.items()}
        if capability is None and self._state_path is not None:
            with self._io_lock:
                if self._state_path.is_file():
                    try:
                        self._state_path.unlink()
                    except OSError:
                        pass
        else:
            self._persist(snapshot)

    def snapshot(self) -> dict[str, dict[str, Any]]:
        """Return a shallow copy of all capability access records."""
        with self._lock:
            return {k: dict(v) for k, v in self._entries.items()}

    def seed_from_error_log(
        self,
        log_path: Path | str,
        *,
        rf_core_fp: str,
        rf_sandbox_fp: str = "",
        max_age_seconds: float = 86400.0,
    ) -> int:
        """Seed missing denial entries from recent 401/403 records in ``rf_api_errors.jsonl``."""
        path = Path(log_path)
        if not path.is_file():
            return 0
        now = time.time()
        cutoff = now - max(0.0, float(max_age_seconds))
        candidates: dict[str, dict[str, Any]] = {}
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            logger.debug("Unable to read error log %s: %s", path, exc)
            return 0

        for line in lines[-500:]:
            raw_line = line.strip()
            if not raw_line:
                continue
            try:
                rec = json.loads(raw_line)
            except ValueError:
                continue
            if not isinstance(rec, Mapping):
                continue
            status_code = rec.get("status_code")
            if not isinstance(status_code, int):
                continue
            msg = str(rec.get("message") or "")
            reason = str(rec.get("reason") or "")
            if not is_permanent_access_denial(status_code, message=msg):
                continue
            ts_str = str(rec.get("timestamp") or "").strip()
            ts_val = now
            if ts_str:
                try:
                    from soclens.timezone import parse_iso_datetime

                    parsed = parse_iso_datetime(ts_str)
                    if parsed is not None:
                        ts_val = parsed[0].timestamp()
                        if ts_val < cutoff:
                            continue
                except Exception:
                    pass
            cat = str(rec.get("category") or "")
            cap = classify_rf_endpoint_capability(str(rec.get("endpoint") or ""), category=cat)
            if not cap:
                continue
            if cap == "sandbox_v0":
                fp = rf_sandbox_fp or rf_core_fp
            elif cap in {"asi", "pfi", "riskrecon"}:
                continue
            else:
                fp = rf_core_fp
            if not fp or fp == "unconfigured":
                continue
            candidates[cap] = {
                "status": "denied",
                "status_code": status_code,
                "reason": msg or reason or f"HTTP {status_code}",
                "permission_type": reason,
                "credential_fp": fp,
                "updated_at": ts_val,
            }

        if not candidates:
            return 0

        seeded = 0
        with self._lock:
            for cap, entry in candidates.items():
                existing = self._entries.get(cap)
                if existing is not None and existing.get("credential_fp") == entry["credential_fp"]:
                    # Never overwrite an explicit available/newer record for the same credential
                    continue
                self._entries[cap] = entry
                seeded += 1
            snapshot = {k: dict(v) for k, v in self._entries.items()} if seeded else None

        if snapshot is not None:
            self._persist(snapshot)
            logger.info("Seeded %d API access denial(s) from %s.", seeded, path)
        return seeded
