"""Thread-safe TUI logging bridge, source classifier, and ring-buffer log store."""

from __future__ import annotations

import logging
import sys
import threading
import warnings
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_LOG_ENTRIES = 5000

LOG_SOURCE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("All Sources", "all"),
    ("Brand Sync", "brand_sync"),
    ("Research", "research"),
    ("RF API", "api"),
    ("Watchlists", "watchlists"),
    ("Sigma", "sigma"),
    ("Splunk & Bundle", "splunk"),
    ("App / TUI", "tui"),
    ("System / Stdio", "system"),
)

LOG_LEVEL_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Level: ALL", "ALL"),
    ("Level: INFO+", "INFO"),
    ("Level: WARN+", "WARNING"),
    ("Level: ERROR", "ERROR"),
)

LOG_LEVEL_RANK: dict[str, int] = {
    "ALL": 0,
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
}

_BRAND_SYNC_MESSAGE_CUES: tuple[str, ...] = (
    "processing ",
    "skipping ignored domain",
    "cross-domain redirect",
    "successfully downloaded and hashed",
    "duplicate sha-256",
    "sync summary",
    "brand image",
    "ignored hashes",
    "extracting domains from watchlist",
    "would add image hash",
    "would remove stale image hash",
    "delta calculated",
    "watchlist currently contains",
    "added entity",
    "removed entity",
)


@dataclass(frozen=True)
class LogEntry:
    """Single immutable log entry stored by the TUI application log buffer."""

    timestamp: str
    level: str
    source: str
    logger_name: str
    message: str
    created_utc: datetime | None = None


def _canonical_level(level: str | int) -> str:
    if isinstance(level, int):
        if level >= logging.ERROR:
            return "ERROR"
        if level >= logging.WARNING:
            return "WARNING"
        if level >= logging.INFO:
            return "INFO"
        return "DEBUG"
    upper = level.strip().upper()
    if upper in ("CRITICAL", "FATAL", "ERROR", "ERR"):
        return "ERROR"
    if upper in ("WARNING", "WARN"):
        return "WARNING"
    if upper in ("DEBUG", "TRACE"):
        return "DEBUG"
    return "INFO"


def source_matches_filter(entry_source: str, filter_source: str) -> bool:
    """Return True when ``entry_source`` matches the active ``filter_source`` selection."""
    if not filter_source or filter_source == "all":
        return True
    if filter_source == "tui":
        return entry_source in {"tui", "dashboard", "rf_intel"}
    return entry_source == filter_source


def classify_log_source(
    logger_name: str,
    message: str = "",
    *,
    default_source: str = "system",
    active_source: str | None = None,
    brand_sync_active: bool = False,
) -> str:
    """Classify a logger name or print line into a canonical TUI log source."""
    lname = logger_name.strip().lower()
    if (
        lname.startswith("soclens.logos")
        or "brand_sync" in lname
        or "brand_logos" in lname
        or "brandlogospane" in lname
    ):
        return "brand_sync"
    if lname.startswith("soclens.research") or lname == "research" or "researchpane" in lname:
        return "research"
    if lname.startswith("soclens.client"):
        return "api"
    if lname.startswith("soclens.watchlist") or "watchlistspane" in lname or lname == "watchlists":
        return "watchlists"
    if lname.startswith("soclens.sigma") or "sigmapane" in lname or lname == "sigma":
        return "sigma"
    if (
        lname.startswith("soclens.splunk")
        or lname.startswith("soclens.bundler")
        or "splunk" in lname
    ):
        return "splunk"
    if (
        "dashboard" in lname
        or "rf_intel" in lname
        or "rfintel" in lname
        or "logspane" in lname
        or lname == "tui"
        or lname.startswith("soclens.tui")
    ):
        return "tui"

    msg_lower = message.lower()
    if active_source:
        return active_source
    if brand_sync_active or any(cue in msg_lower for cue in _BRAND_SYNC_MESSAGE_CUES):
        return "brand_sync"

    if lname in ("stdout", "stderr", "warnings", "root", ""):
        return default_source

    if lname.startswith("soclens"):
        return default_source if default_source != "system" else "tui"

    return default_source


def infer_print_level(message: str, *, stderr: bool = False) -> str:
    """Infer a canonical log level from captured stdout/stderr print output."""
    stripped = message.lstrip()
    upper = stripped.upper()
    if stderr or stripped.startswith("[-]") or upper.startswith("[ERROR]"):
        return "ERROR"
    if (
        stripped.startswith("[!]")
        or upper.startswith("[WARNING]")
        or stripped.startswith("Warning:")
    ):
        return "WARNING"
    return "INFO"


class AppLogStore:
    """Thread-safe bounded ring buffer of TUI log entries with lock-free listener notifications."""

    def __init__(self, maxlen: int = MAX_LOG_ENTRIES) -> None:
        self._entries: deque[LogEntry] = deque(maxlen=maxlen)
        self._lock = threading.RLock()
        self._on_entry: Callable[[LogEntry], None] | None = None
        self._total_count = 0
        self._warning_count = 0
        self._error_count = 0

    def set_on_entry(self, callback: Callable[[LogEntry], None] | None) -> None:
        """Register or clear the callback invoked whenever a new entry is appended."""
        with self._lock:
            self._on_entry = callback

    def append(self, entry: LogEntry) -> LogEntry:
        """Append a ``LogEntry`` and notify any listener outside the store lock."""
        norm_level = _canonical_level(entry.level)
        created_utc = entry.created_utc or datetime.now(UTC)
        normalized = LogEntry(
            timestamp=entry.timestamp or created_utc.strftime("%H:%M:%S"),
            level=norm_level,
            source=entry.source or "system",
            logger_name=entry.logger_name or "app",
            message=entry.message,
            created_utc=created_utc,
        )
        with self._lock:
            self._entries.append(normalized)
            self._total_count += 1
            if norm_level == "WARNING":
                self._warning_count += 1
            elif norm_level == "ERROR":
                self._error_count += 1
            cb = self._on_entry

        if cb is not None:
            try:
                cb(normalized)
            except Exception:
                pass
        return normalized

    def snapshot(self) -> list[LogEntry]:
        """Return a thread-safe shallow copy of buffered log entries."""
        with self._lock:
            return list(self._entries)

    def counts(self) -> tuple[int, int, int]:
        """Return ``(buffered_count, warning_count, error_count)``."""
        with self._lock:
            return len(self._entries), self._warning_count, self._error_count

    def clear(self) -> None:
        """Clear all stored log entries and reset counters."""
        with self._lock:
            self._entries.clear()
            self._total_count = 0
            self._warning_count = 0
            self._error_count = 0


class TuiLogHandler(logging.Handler):
    """Non-blocking ``logging.Handler`` routing formatted records into ``AppLogStore``."""

    def __init__(
        self,
        store: AppLogStore,
        *,
        ignore_prefixes: tuple[str, ...] = (),
        min_level: int = logging.NOTSET,
        active_source_fn: Callable[[], str | None] | None = None,
    ) -> None:
        super().__init__(level=min_level)
        self._store = store
        self._ignore_prefixes = ignore_prefixes
        self._min_level = min_level
        self._active_source_fn = active_source_fn
        self._exc_formatter = logging.Formatter()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            for prefix in self._ignore_prefixes:
                if record.name == prefix or record.name.startswith(f"{prefix}."):
                    return
            if record.levelno < self._min_level:
                return

            msg = record.getMessage()
            if record.exc_info:
                exc_text = record.exc_text or self._exc_formatter.formatException(record.exc_info)
                if exc_text:
                    msg = f"{msg}\n{exc_text}" if msg else exc_text
            if record.stack_info:
                msg = f"{msg}\n{record.stack_info}" if msg else str(record.stack_info)

            if not msg.strip():
                return

            active_source = self._active_source_fn() if self._active_source_fn else None
            source = classify_log_source(
                record.name,
                msg,
                default_source="system",
                active_source=active_source,
                brand_sync_active=(active_source == "brand_sync"),
            )
            created_utc = datetime.fromtimestamp(record.created, tz=UTC)
            timestamp = created_utc.strftime("%H:%M:%S")
            self._store.append(
                LogEntry(
                    timestamp=timestamp,
                    level=_canonical_level(record.levelno),
                    source=source,
                    logger_name=record.name or "root",
                    message=msg,
                    created_utc=created_utc,
                )
            )
        except Exception:
            # Never emit fallback errors to sys.stderr while the TUI owns the terminal.
            return


def _collect_console_streams(app: Any) -> list[Any]:
    candidates = [
        sys.stdout,
        sys.stderr,
        sys.__stdout__,
        sys.__stderr__,
        getattr(app, "_original_stdout", None),
        getattr(app, "_original_stderr", None),
    ]
    return [stream for stream in candidates if stream is not None]


def _is_console_stream(stream: Any, console_streams: list[Any]) -> bool:
    if stream is None:
        return False
    if any(stream is candidate for candidate in console_streams):
        return True
    if getattr(stream, "name", None) in ("<stdout>", "<stderr>"):
        return True
    isatty_fn = getattr(stream, "isatty", None)
    if callable(isatty_fn):
        try:
            return bool(isatty_fn())
        except Exception:
            return False
    return False


def _is_console_stream_handler(handler: logging.Handler, console_streams: list[Any]) -> bool:
    if not isinstance(handler, logging.StreamHandler) or isinstance(handler, logging.FileHandler):
        return False
    if getattr(handler, "_soclens_managed", False):
        return True
    stream = getattr(handler, "stream", None)
    return _is_console_stream(stream, console_streams)


class TuiLoggingBridge:
    """Temporarily suspends console stream handlers/warnings while the TUI is mounted."""

    def __init__(
        self,
        store: AppLogStore,
        *,
        active_source_fn: Callable[[], str | None] | None = None,
    ) -> None:
        self._store = store
        self._active_source_fn = active_source_fn
        self._lock = threading.RLock()
        self._installed = False
        self._suspended_handlers: list[tuple[logging.Logger, logging.Handler]] = []
        self._rf_handler: TuiLogHandler | None = None
        self._root_handler: TuiLogHandler | None = None
        self._saved_rf_level: int | None = None
        self._orig_showwarning: Callable[..., Any] | None = None
        self._console_streams: list[Any] = []

    def install(self, app: Any) -> None:
        """Install TUI handlers and suspend terminal console stream handlers idempotently."""
        with self._lock:
            if self._installed:
                return

            console_streams = _collect_console_streams(app)
            self._console_streams = console_streams

            root_logger = logging.getLogger()
            rf_logger = logging.getLogger("soclens")
            candidate_loggers: list[logging.Logger] = [root_logger, rf_logger]
            seen_ids = {id(root_logger), id(rf_logger)}

            for maybe_logger in list(logging.Logger.manager.loggerDict.values()):
                if isinstance(maybe_logger, logging.Logger) and id(maybe_logger) not in seen_ids:
                    candidate_loggers.append(maybe_logger)
                    seen_ids.add(id(maybe_logger))

            suspended: list[tuple[logging.Logger, logging.Handler]] = []
            for logger_obj in candidate_loggers:
                for handler in list(logger_obj.handlers):
                    if isinstance(handler, TuiLogHandler):
                        continue
                    if _is_console_stream_handler(handler, console_streams):
                        logger_obj.removeHandler(handler)
                        suspended.append((logger_obj, handler))
            self._suspended_handlers = suspended

            self._saved_rf_level = rf_logger.level
            if rf_logger.level == logging.NOTSET or rf_logger.level > logging.INFO:
                rf_logger.setLevel(logging.INFO)

            self._rf_handler = TuiLogHandler(
                self._store,
                min_level=logging.NOTSET,
                active_source_fn=self._active_source_fn,
            )
            rf_logger.addHandler(self._rf_handler)

            self._root_handler = TuiLogHandler(
                self._store,
                ignore_prefixes=("soclens",),
                min_level=logging.WARNING,
                active_source_fn=self._active_source_fn,
            )
            root_logger.addHandler(self._root_handler)

            orig_showwarning = warnings.showwarning
            self._orig_showwarning = orig_showwarning

            def _tui_showwarning(
                message: Warning | str,
                category: type[Warning],
                filename: str,
                lineno: int,
                file: Any = None,
                line: str | None = None,
            ) -> Any:
                if file is not None and not _is_console_stream(file, self._console_streams):
                    return orig_showwarning(
                        message,
                        category,
                        filename,
                        lineno,
                        file=file,
                        line=line,
                    )
                formatted = warnings.formatwarning(
                    message, category, filename, lineno, line=line
                ).strip()
                if not formatted:
                    formatted = f"{category.__name__}: {message} ({Path(filename).name}:{lineno})"
                active_source = self._active_source_fn() if self._active_source_fn else None
                self._store.append(
                    LogEntry(
                        timestamp=datetime.now().strftime("%H:%M:%S"),
                        level="WARNING",
                        source=active_source or "system",
                        logger_name="warnings",
                        message=formatted,
                    )
                )
                return None

            warnings.showwarning = _tui_showwarning
            self._installed = True

    def uninstall(self) -> None:
        """Detach TUI handlers and restore previously suspended console handlers and warnings."""
        with self._lock:
            if not self._installed:
                return

            if self._orig_showwarning is not None:
                warnings.showwarning = self._orig_showwarning
                self._orig_showwarning = None

            rf_logger = logging.getLogger("soclens")
            root_logger = logging.getLogger()

            if self._rf_handler is not None:
                rf_logger.removeHandler(self._rf_handler)
                self._rf_handler.close()
                self._rf_handler = None

            if self._root_handler is not None:
                root_logger.removeHandler(self._root_handler)
                self._root_handler.close()
                self._root_handler = None

            if self._saved_rf_level is not None:
                rf_logger.setLevel(self._saved_rf_level)
                self._saved_rf_level = None

            for logger_obj, handler in self._suspended_handlers:
                if handler not in logger_obj.handlers:
                    logger_obj.addHandler(handler)
            self._suspended_handlers = []
            self._console_streams = []
            self._installed = False
