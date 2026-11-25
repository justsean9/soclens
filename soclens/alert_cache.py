"""Thread-safe local disk & memory cache for preloaded 24-hour SOC alerts."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soclens.settings import get_setting_with_source

logger = logging.getLogger("soclens.alert_cache")

CACHE_SOURCE_RF = "rf_alerts_24h"
CACHE_SOURCE_ES = "es_notables_24h"
CACHE_SOURCE_S1 = "s1_threats_24h"

ALL_CACHE_SOURCES: tuple[str, ...] = (
    CACHE_SOURCE_RF,
    CACHE_SOURCE_ES,
    CACHE_SOURCE_S1,
)

DEFAULT_ALERT_CACHE_REFRESH_SECONDS: int = 300
MIN_ALERT_CACHE_REFRESH_SECONDS: int = 30


def get_alert_cache_refresh_seconds(default: int = DEFAULT_ALERT_CACHE_REFRESH_SECONDS) -> int:
    """Resolve background alert-cache refresh interval in seconds (0 disables)."""
    raw: Any = os.environ.get("SOCLENS_ALERT_CACHE_REFRESH_SECONDS")
    if raw is None or not str(raw).strip():
        raw, _src = get_setting_with_source("alert_cache_refresh_seconds")
    if raw is None or not str(raw).strip():
        return default
    try:
        val = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    if val <= 0:
        return 0
    return max(MIN_ALERT_CACHE_REFRESH_SECONDS, val)


def format_cache_age(fetched_at: float, *, now: float | None = None) -> str:
    """Format a cache entry's age as a compact human-readable label."""
    ref = time.time() if now is None else now
    delta = max(0, int(ref - fetched_at))
    if delta < 45:
        return "just now"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        hours = delta // 3600
        mins = (delta % 3600) // 60
        return f"{hours}h {mins}m ago" if mins else f"{hours}h ago"
    return f"{delta // 86400}d ago"


@dataclass
class AlertCacheEntry:
    """In-memory and on-disk snapshot of a preloaded alert queue."""

    source: str
    items: list[dict[str, Any]]
    fetched_at: float
    timeframe: str = "last_24h"
    meta: dict[str, Any] = field(default_factory=dict)

    def age_seconds(self, *, now: float | None = None) -> float:
        ref = time.time() if now is None else now
        return max(0.0, ref - self.fetched_at)

    def age_label(self, *, now: float | None = None) -> str:
        return format_cache_age(self.fetched_at, now=now)

    def to_payload(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "timeframe": self.timeframe,
            "fetched_at": self.fetched_at,
            "fetched_at_iso": datetime.fromtimestamp(self.fetched_at, tz=UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "meta": dict(self.meta),
            "items": self.items,
        }

    @classmethod
    def from_payload(cls, raw: Mapping[str, Any], *, fallback_source: str) -> AlertCacheEntry | None:
        raw_items = raw.get("items")
        if not isinstance(raw_items, list):
            return None
        items = [dict(it) for it in raw_items if isinstance(it, Mapping)]
        try:
            fetched_at = float(raw.get("fetched_at") or 0.0)
        except (TypeError, ValueError):
            fetched_at = 0.0
        source = str(raw.get("source") or fallback_source).strip() or fallback_source
        timeframe = str(raw.get("timeframe") or "last_24h").strip() or "last_24h"
        raw_meta = raw.get("meta")
        meta = dict(raw_meta) if isinstance(raw_meta, Mapping) else {}
        return cls(
            source=source,
            items=items,
            fetched_at=fetched_at,
            timeframe=timeframe,
            meta=meta,
        )


class AlertCacheStore:
    """Thread-safe local disk + memory cache for last-24h RF, Splunk ES, and S1 alerts."""

    def __init__(self, cache_dir: Path | str | None = None) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, AlertCacheEntry] = {}
        self._cache_dir: Path | None = Path(cache_dir) if cache_dir is not None else None
        if self._cache_dir is not None:
            self.load_from_disk()

    @property
    def cache_dir(self) -> Path | None:
        return self._cache_dir

    def _entry_path(self, source: str) -> Path | None:
        if self._cache_dir is None:
            return None
        safe_name = "".join(ch if ch.isalnum() or ch in ("_", "-") else "_" for ch in source)
        return self._cache_dir / f"{safe_name}.json"

    def load_from_disk(self) -> int:
        """Warm in-memory entries from any existing local cache files."""
        if self._cache_dir is None or not self._cache_dir.is_dir():
            return 0
        loaded = 0
        for source in ALL_CACHE_SOURCES:
            path = self._entry_path(source)
            if path is None or not path.is_file():
                continue
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(raw, Mapping):
                    continue
                entry = AlertCacheEntry.from_payload(raw, fallback_source=source)
                if entry is not None:
                    with self._lock:
                        self._entries[source] = entry
                    loaded += 1
            except Exception as exc:
                logger.debug("Skipping unreadable alert cache file %s: %s", path, exc)
        return loaded

    def get(
        self,
        source: str,
        *,
        max_age_seconds: float | None = None,
    ) -> AlertCacheEntry | None:
        """Return a shallow copy of the cached entry for ``source`` if present and fresh."""
        with self._lock:
            entry = self._entries.get(source)
            if entry is None:
                return None
            if max_age_seconds is not None and entry.age_seconds() > max_age_seconds:
                return None
            return AlertCacheEntry(
                source=entry.source,
                items=[dict(it) for it in entry.items],
                fetched_at=entry.fetched_at,
                timeframe=entry.timeframe,
                meta=dict(entry.meta),
            )

    def put(
        self,
        source: str,
        items: Sequence[Mapping[str, Any]],
        *,
        timeframe: str = "last_24h",
        meta: Mapping[str, Any] | None = None,
        fetched_at: float | None = None,
    ) -> AlertCacheEntry:
        """Store ``items`` in memory and atomically persist them to disk."""
        ts = time.time() if fetched_at is None else float(fetched_at)
        entry = AlertCacheEntry(
            source=source,
            items=[dict(it) for it in items],
            fetched_at=ts,
            timeframe=timeframe,
            meta=dict(meta) if meta else {},
        )
        with self._lock:
            self._entries[source] = entry
            self._persist_entry(entry)
        return entry

    def _persist_entry(self, entry: AlertCacheEntry) -> None:
        path = self._entry_path(entry.source)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            serialized = json.dumps(entry.to_payload(), ensure_ascii=False, default=str)
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{entry.source}.",
                suffix=".tmp",
                dir=str(path.parent),
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(serialized)
                os.replace(tmp_name, path)
            except Exception:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except Exception as exc:
            logger.debug("Failed to persist alert cache %s: %s", entry.source, exc)

    def is_stale(self, source: str, max_age_seconds: float) -> bool:
        """Return True if ``source`` is absent or older than ``max_age_seconds``."""
        with self._lock:
            entry = self._entries.get(source)
            if entry is None:
                return True
            return entry.age_seconds() >= max_age_seconds

    def clear(self, source: str | None = None) -> None:
        """Clear one source or all sources from memory and disk."""
        with self._lock:
            targets = [source] if source is not None else list(self._entries.keys())
            for key in targets:
                self._entries.pop(key, None)
                path = self._entry_path(key)
                if path is not None and path.is_file():
                    try:
                        path.unlink()
                    except OSError:
                        pass
