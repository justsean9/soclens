"""Unified multi-dialect SQLAlchemy 2.0 storage backend for SOCLens.

Supports local embedded SQLite (WAL mode + FTS5 + JSON1) by default, as well as
optional shared external PostgreSQL (``pg8000``), MySQL/MariaDB (``PyMySQL``),
and custom SQLAlchemy DSNs with TLS/SSL and connection pooling.

Security invariant: ``settings.json``, API keys, DB passwords, and Vault
references are NEVER persisted in any database table. All alert payloads,
Event AI panels, audit entries, and SOC learnings pass ``redact_sensitive_data``
before persistence.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote, quote_plus

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    and_,
    create_engine,
    delete,
    event,
    insert,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.engine import URL, CursorResult, Engine, RowMapping, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from soclens.agent_audit import VALID_AUDIT_EVENT_TYPES, AuditEntry, redact_sensitive_data
from soclens.config import get_workspace_dir

_PyList = list

logger = logging.getLogger("soclens.storage")

SUPPORTED_DB_BACKENDS: tuple[str, ...] = ("sqlite", "postgres", "mysql", "custom")
DEFAULT_RETENTION_DAYS: int = 90
SCHEMA_VERSION: int = 1

_BACKEND_ALIASES: dict[str, str] = {
    "sqlite": "sqlite",
    "sqlite3": "sqlite",
    "postgres": "postgres",
    "postgresql": "postgres",
    "pg": "postgres",
    "pg8000": "postgres",
    "mysql": "mysql",
    "mariadb": "mysql",
    "pymysql": "mysql",
    "custom": "custom",
}

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_CIDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:3[0-2]|[12]?\d)\b"
)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24})\b"
)
_FTS_TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]+")
_MYSQL_BOOL_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
_NON_DOMAIN_TLDS: frozenset[str] = frozenset(
    {"exe", "dll", "ps1", "bat", "cmd", "sh", "py", "json", "jsonl", "log", "txt", "bin", "png", "jpg", "pdf", "zip", "csv"}
)

# ---------------------------------------------------------------------------
# SQLAlchemy Core Schema Definition
# ---------------------------------------------------------------------------

METADATA = MetaData()

schema_migrations_table = Table(
    "schema_migrations",
    METADATA,
    Column("version", Integer, primary_key=True),
    Column("name", String(128), nullable=False),
    Column("applied_at", Float, nullable=False),
)

alert_snapshots_table = Table(
    "alert_snapshots",
    METADATA,
    Column("source", String(64), primary_key=True),
    Column("timeframe", String(64), nullable=False, default="last_24h"),
    Column("fetched_at", Float, nullable=False),
    Column("meta_json", Text, nullable=False, default="{}"),
    Column("items_json", Text, nullable=False, default="[]"),
    Column("updated_at", Float, nullable=False),
)

alerts_history_table = Table(
    "alerts_history",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("source", String(64), nullable=False, index=True),
    Column("alert_id", String(256), nullable=False, index=True),
    Column("title", Text, nullable=False, default=""),
    Column("severity", String(64), nullable=False, default=""),
    Column("status", String(64), nullable=False, default=""),
    Column("occurred_at", Float, nullable=False, index=True),
    Column("fetched_at", Float, nullable=False, index=True),
    Column("payload_json", Text, nullable=False, default="{}"),
    Column("search_text", Text, nullable=False, default=""),
    UniqueConstraint("source", "alert_id", name="uq_alerts_history_source_alert_id"),
)

ioc_sightings_table = Table(
    "ioc_sightings",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("indicator_norm", String(512), nullable=False, index=True),
    Column("indicator_raw", String(512), nullable=False),
    Column("indicator_type", String(64), nullable=False, index=True),
    Column("source", String(64), nullable=False),
    Column("event_key", String(512), nullable=False),
    Column("sighting_count", Integer, nullable=False, default=1),
    Column("first_seen_at", Float, nullable=False),
    Column("last_seen_at", Float, nullable=False, index=True),
    Column("context_json", Text, nullable=False, default="{}"),
    UniqueConstraint("indicator_norm", "source", "event_key", name="uq_ioc_sighting_norm_src_ev"),
)

unique_events_table = Table(
    "unique_events",
    METADATA,
    Column("event_key", String(512), primary_key=True),
    Column("source_kind", String(64), nullable=False, index=True),
    Column("native_id", String(256), nullable=False, default=""),
    Column("scope", String(128), nullable=False, default="default"),
    Column("title", Text, nullable=False, default=""),
    Column("severity", String(64), nullable=False, default=""),
    Column("status", String(64), nullable=False, default=""),
    Column("event_timestamp", String(64), nullable=False, default=""),
    Column("summary", Text, nullable=False, default=""),
    Column("metadata_json", Text, nullable=False, default="{}"),
    Column("updated_at", Float, nullable=False, index=True),
)

event_ai_panels_table = Table(
    "event_ai_panels",
    METADATA,
    Column("entry_id", String(128), primary_key=True),
    Column("event_key", String(512), nullable=False, index=True),
    Column("run_id", String(128), nullable=False, default=""),
    Column("panel_timestamp", String(64), nullable=False, default=""),
    Column("created_at", Float, nullable=False, index=True),
    Column("mode", String(64), nullable=False, default="ask_only"),
    Column("provider", String(64), nullable=False, default=""),
    Column("model", String(128), nullable=False, default=""),
    Column("question", Text, nullable=False, default=""),
    Column("answer_markdown", Text, nullable=False, default=""),
    Column("tool_calls_json", Text, nullable=False, default="[]"),
    Column("blocked_actions_json", Text, nullable=False, default="[]"),
    Column("status", String(64), nullable=False, default="completed"),
    Column("auto_triggered", Boolean, nullable=False, default=False),
    Column("error", Text, nullable=False, default=""),
)

audit_logs_table = Table(
    "audit_logs",
    METADATA,
    Column("entry_id", String(128), primary_key=True),
    Column("timestamp", String(64), nullable=False),
    Column("created_at", Float, nullable=False, index=True),
    Column("run_id", String(128), nullable=False, default="", index=True),
    Column("event_key", String(512), nullable=False, default="", index=True),
    Column("provider", String(64), nullable=False, default=""),
    Column("mode", String(64), nullable=False, default=""),
    Column("event_type", String(64), nullable=False, index=True),
    Column("tool_name", String(128), nullable=False, default=""),
    Column("allowed", Boolean, nullable=True),
    Column("reason", Text, nullable=False, default=""),
    Column("payload_json", Text, nullable=False, default="{}"),
    Column("analyst_id", String(128), nullable=False, default=""),
    Column("workstation_id", String(128), nullable=False, default=""),
)

ai_policies_table = Table(
    "ai_policies",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("workstation_id", String(128), nullable=False),
    Column("profile_name", String(128), nullable=False),
    Column("policy_json", Text, nullable=False, default="{}"),
    Column("updated_at", Float, nullable=False),
    UniqueConstraint("workstation_id", "profile_name", name="uq_ai_policy_ws_prof"),
)

workspace_layouts_table = Table(
    "workspace_layouts",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("workstation_id", String(128), nullable=False),
    Column("profile_name", String(128), nullable=False),
    Column("mode", String(32), nullable=False, default="tabbed"),
    Column("state_json", Text, nullable=False, default="{}"),
    Column("updated_at", Float, nullable=False),
    UniqueConstraint("workstation_id", "profile_name", name="uq_workspace_layout_ws_prof"),
)

soc_learnings_table = Table(
    "soc_learnings",
    METADATA,
    Column("id", String(128), primary_key=True),
    Column("fingerprint", String(256), nullable=False, index=True),
    Column("category", String(64), nullable=False, default="environment_fact", index=True),
    Column("title", Text, nullable=False, default=""),
    Column("content", Text, nullable=False, default=""),
    Column("source", String(64), nullable=False, default="manual_learn", index=True),
    Column("status", String(32), nullable=False, default="active", index=True),
    Column("confidence", Float, nullable=False, default=1.0),
    Column("seen_count", Integer, nullable=False, default=1),
    Column("use_count", Integer, nullable=False, default=0),
    Column("pinned", Boolean, nullable=False, default=False),
    Column("tags_json", Text, nullable=False, default="[]"),
    Column("tags_text", Text, nullable=False, default=""),
    Column("created_by", String(128), nullable=False, default=""),
    Column("created_at", Float, nullable=False, index=True),
    Column("updated_at", Float, nullable=False, index=True),
)

soc_learning_revisions_table = Table(
    "soc_learning_revisions",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("learning_id", String(128), nullable=False, index=True),
    Column("revision_no", Integer, nullable=False, default=1),
    Column("action", String(64), nullable=False, default="create"),
    Column("actor", String(128), nullable=False, default=""),
    Column("previous_content", Text, nullable=False, default=""),
    Column("new_content", Text, nullable=False, default=""),
    Column("previous_status", String(32), nullable=False, default=""),
    Column("new_status", String(32), nullable=False, default=""),
    Column("snapshot_json", Text, nullable=False, default="{}"),
    Column("created_at", Float, nullable=False, index=True),
)

Index("ix_alerts_history_source_occ", alerts_history_table.c.source, alerts_history_table.c.occurred_at)
Index("ix_audit_logs_created_seq", audit_logs_table.c.created_at, audit_logs_table.c.entry_id)


# ---------------------------------------------------------------------------
# Helpers: Environment, Masking, Sanitization, Parsing & IOC Extraction
# ---------------------------------------------------------------------------


def _safe_getuser() -> str:
    try:
        return getpass.getuser() or "analyst"
    except Exception:
        return "analyst"


def _safe_hostname() -> str:
    try:
        return socket.gethostname() or "default-workstation"
    except Exception:
        return "default-workstation"


def _resolve_default_profile() -> str:
    env_prof = (os.environ.get("SOCLENS_PROFILE") or "").strip()
    if env_prof:
        return env_prof
    try:
        from soclens.settings import get_active_profile_name

        return get_active_profile_name() or "default"
    except Exception:
        return "default"


def _mask_dsn(raw_dsn: str | None) -> str:
    if not raw_dsn:
        return ""
    try:
        parsed = make_url(raw_dsn)
        return parsed.render_as_string(hide_password=True)
    except Exception:
        return str(redact_sensitive_data(raw_dsn))


def _sanitize_db_error(exc: BaseException | str, cfg: DatabaseConfig | None = None) -> str:
    text_err = str(exc or "Database connection error.")
    secrets_to_scrub: list[str] = []
    if cfg is not None:
        if cfg.password:
            secrets_to_scrub.extend(
                [cfg.password, quote(cfg.password, safe=""), quote_plus(cfg.password)]
            )
        if cfg.dsn:
            try:
                parsed = make_url(cfg.dsn)
                if parsed.password:
                    secrets_to_scrub.extend(
                        [
                            parsed.password,
                            quote(parsed.password, safe=""),
                            quote_plus(parsed.password),
                        ]
                    )
            except Exception:
                pass
    for sec in secrets_to_scrub:
        if sec:
            text_err = text_err.replace(sec, "<REDACTED>")
    return str(redact_sensitive_data(text_err))


def _escape_like_pattern(value: str, escape_char: str = "|") -> str:
    return (
        value.replace(escape_char, escape_char * 2)
        .replace("%", f"{escape_char}%")
        .replace("_", f"{escape_char}_")
    )


def _parse_timestamp_epoch(raw: Any, *, fallback: float) -> float:
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        val = float(raw)
        if val > 1e12:
            val /= 1000.0
        return val if val > 0 else fallback
    if isinstance(raw, str):
        cleaned = raw.strip()
        if not cleaned:
            return fallback
        try:
            num = float(cleaned)
            if num > 1e12:
                num /= 1000.0
            return num if num > 0 else fallback
        except ValueError:
            pass
        iso = cleaned[:-1] + "+00:00" if cleaned.endswith("Z") else cleaned
        try:
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.timestamp()
        except ValueError:
            return fallback
    return fallback


def _json_dumps_safe(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _flatten_search_strings(value: Any, *, _depth: int = 0) -> list[str]:
    if _depth > 8 or value is None:
        return []
    if isinstance(value, bool):
        return []
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if isinstance(value, Mapping):
        parts: list[str] = []
        for k, v in value.items():
            key_str = str(k).strip()
            if key_str:
                parts.append(key_str)
            parts.extend(_flatten_search_strings(v, _depth=_depth + 1))
        return parts
    if isinstance(value, (list, tuple, set)):
        parts = []
        for item in value:
            parts.extend(_flatten_search_strings(item, _depth=_depth + 1))
        return parts
    return [str(value)]


def _extract_iocs_from_value(
    value: Any,
    *,
    _depth: int = 0,
    _key_hint: str = "",
) -> list[tuple[str, str]]:
    """Extract ``[(indicator_raw, indicator_type), ...]`` deterministically."""
    if _depth > 8 or value is None:
        return []
    found: list[tuple[str, str]] = []
    if isinstance(value, str):
        text_val = value.strip()
        if not text_val:
            return []
        for cidr in _CIDR_RE.findall(text_val):
            found.append((cidr, "cidr"))
        for ip in _IPV4_RE.findall(text_val):
            found.append((ip, "ip"))
        for cve in _CVE_RE.findall(text_val):
            found.append((cve.upper(), "cve"))
        for sha256 in _SHA256_RE.findall(text_val):
            found.append((sha256.lower(), "hash"))
        low_hint = _key_hint.lower()
        if any(tok in low_hint for tok in ("domain", "host", "dest", "entity", "name", "url")):
            for dom in _DOMAIN_RE.findall(text_val):
                tld = dom.rsplit(".", 1)[-1].lower()
                if tld not in _NON_DOMAIN_TLDS:
                    found.append((dom.lower(), "domain"))
        return found
    if isinstance(value, Mapping):
        for raw_k, raw_v in value.items():
            found.extend(_extract_iocs_from_value(raw_v, _depth=_depth + 1, _key_hint=str(raw_k)))
        return found
    if isinstance(value, (list, tuple, set)):
        for item in value:
            found.extend(_extract_iocs_from_value(item, _depth=_depth + 1, _key_hint=_key_hint))
        return found
    return []


def _dedupe_iocs(pairs: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for raw, kind in pairs:
        norm = raw.strip().lower()
        if not norm:
            continue
        key = (norm, kind)
        if key not in seen:
            seen.add(key)
            out.append((raw.strip(), kind))
    return out


# ---------------------------------------------------------------------------
# Configuration & Connection Builder
# ---------------------------------------------------------------------------


@dataclass
class DatabaseConfig:
    """Multi-dialect database configuration (credentials masked in ``repr``)."""

    backend: str = "sqlite"
    sqlite_path: Path | str | None = None
    dsn: str | None = None
    host: str = ""
    port: int | None = None
    database: str = ""
    username: str = ""
    password: str = field(default="", repr=False)
    ssl_mode: str = ""
    ssl_ca: str | None = None
    ssl_cert: str | None = None
    ssl_key: str | None = None
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: float = 30.0
    pool_recycle: int = 1800
    retention_days: int = DEFAULT_RETENTION_DAYS
    workstation_id: str = ""
    profile_name: str = ""
    analyst_id: str = ""

    def __post_init__(self) -> None:
        raw_backend = str(self.backend or "sqlite").strip().lower()
        normalized_backend = _BACKEND_ALIASES.get(raw_backend)
        if normalized_backend is None:
            raise ValueError(
                f"Unsupported database backend {raw_backend!r}. "
                "Expected sqlite, postgres, mysql, or custom."
            )
        self.backend = normalized_backend

        if self.sqlite_path is None or not str(self.sqlite_path).strip():
            resolved_sqlite = get_workspace_dir() / ".soclens_cache" / "soclens.db"
        else:
            raw_sp = str(self.sqlite_path).strip()
            resolved_sqlite = (
                Path(raw_sp) if raw_sp == ":memory:" else Path(raw_sp).expanduser()
            )
        self.sqlite_path = resolved_sqlite

        self.host = str(self.host or "").strip()
        if self.port is not None:
            if isinstance(self.port, bool):
                raise ValueError("Database port must be an integer.")
            self.port = int(self.port)
            if self.port <= 0 or self.port > 65535:
                raise ValueError(f"Database port out of range: {self.port}")
        self.database = str(self.database or "").strip()
        self.username = str(self.username or "").strip()
        self.password = "" if self.password is None else str(self.password)

        self.ssl_mode = str(self.ssl_mode or "").strip().lower()
        self.ssl_ca = str(self.ssl_ca).strip() if self.ssl_ca and str(self.ssl_ca).strip() else None
        self.ssl_cert = (
            str(self.ssl_cert).strip() if self.ssl_cert and str(self.ssl_cert).strip() else None
        )
        self.ssl_key = (
            str(self.ssl_key).strip() if self.ssl_key and str(self.ssl_key).strip() else None
        )

        self.pool_size = max(1, int(self.pool_size))
        self.max_overflow = max(0, int(self.max_overflow))
        self.pool_timeout = max(1.0, float(self.pool_timeout))
        self.pool_recycle = max(30, int(self.pool_recycle))
        self.retention_days = int(self.retention_days)

        self.workstation_id = (
            str(self.workstation_id or "").strip()
            or (os.environ.get("SOCLENS_WORKSTATION_ID") or "").strip()
            or _safe_hostname()
        )
        self.profile_name = (
            str(self.profile_name or "").strip()
            or _resolve_default_profile()
        )
        self.analyst_id = (
            str(self.analyst_id or "").strip()
            or (os.environ.get("SOCLENS_ANALYST_ID") or "").strip()
            or _safe_getuser()
        )

        raw_dsn = str(self.dsn).strip() if self.dsn is not None else ""
        if self.backend == "custom":
            if not raw_dsn:
                raise ValueError("Custom database backend requires a non-empty SQLAlchemy DSN.")
            self.dsn = raw_dsn
        elif raw_dsn:
            self.dsn = self._normalize_driver_dsn(raw_dsn)
        elif self.backend == "sqlite":
            if str(self.sqlite_path) == ":memory:":
                self.dsn = "sqlite:///:memory:"
            else:
                self.dsn = f"sqlite:///{self.sqlite_path.as_posix()}"
        elif self.backend == "postgres":
            url_obj = URL.create(
                drivername="postgresql+pg8000",
                username=self.username or None,
                password=self.password or None,
                host=self.host or "127.0.0.1",
                port=self.port or 5432,
                database=self.database or "soclens",
            )
            self.dsn = url_obj.render_as_string(hide_password=False)
        elif self.backend == "mysql":
            url_obj = URL.create(
                drivername="mysql+pymysql",
                username=self.username or None,
                password=self.password or None,
                host=self.host or "127.0.0.1",
                port=self.port or 3306,
                database=self.database or "soclens",
            )
            self.dsn = url_obj.render_as_string(hide_password=False)

    @staticmethod
    def _normalize_driver_dsn(raw_dsn: str) -> str:
        low = raw_dsn.lower()
        if low.startswith("postgres://"):
            return "postgresql+pg8000://" + raw_dsn[len("postgres://") :]
        if low.startswith("postgresql://"):
            return "postgresql+pg8000://" + raw_dsn[len("postgresql://") :]
        if low.startswith("mysql://"):
            return "mysql+pymysql://" + raw_dsn[len("mysql://") :]
        if low.startswith("mariadb://"):
            return "mysql+pymysql://" + raw_dsn[len("mariadb://") :]
        return raw_dsn

    def effective_dialect(self) -> str:
        """Return normalized logical dialect: ``sqlite``, ``postgres``, or ``mysql``."""
        low = (self.dsn or "").strip().lower()
        if low.startswith(("postgresql", "postgres")):
            return "postgres"
        if low.startswith(("mysql", "mariadb")):
            return "mysql"
        if low.startswith("sqlite"):
            return "sqlite"
        if self.backend in {"sqlite", "postgres", "mysql"}:
            return self.backend
        return "sqlite"

    def __repr__(self) -> str:
        return (
            "DatabaseConfig("
            f"backend={self.backend!r}, "
            f"sqlite_path={self.sqlite_path!r}, "
            f"dsn={_mask_dsn(self.dsn)!r}, "
            f"ssl_mode={self.ssl_mode!r}, "
            f"pool_size={self.pool_size}, "
            f"max_overflow={self.max_overflow}, "
            f"retention_days={self.retention_days}, "
            f"workstation_id={self.workstation_id!r}, "
            f"profile_name={self.profile_name!r}, "
            f"analyst_id={self.analyst_id!r})"
        )


def _validate_pem_path(path_str: str | None, label: str) -> str | None:
    if not path_str:
        return None
    p = Path(path_str).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"{label} file not found: {p}")
    return str(p)


def _build_ssl_context(cfg: DatabaseConfig) -> ssl.SSLContext | None:
    ca_file = _validate_pem_path(cfg.ssl_ca, "TLS CA")
    cert_file = _validate_pem_path(cfg.ssl_cert, "TLS client certificate")
    key_file = _validate_pem_path(cfg.ssl_key, "TLS client key")
    mode = cfg.ssl_mode

    if not ca_file and not cert_file and mode not in {"require", "verify-ca", "verify-full"}:
        return None

    if ca_file:
        ctx = ssl.create_default_context(cafile=ca_file)
    else:
        ctx = ssl.create_default_context()

    if mode == "verify-full":
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif mode == "verify-ca":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif mode == "require":
        if ca_file:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    elif ca_file:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

    if cert_file:
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

    return ctx


def _build_engine_for_config(cfg: DatabaseConfig) -> tuple[Engine, str]:
    raw_dsn = cfg.dsn or ""
    if not raw_dsn:
        raise ValueError("Database DSN is empty.")
    try:
        url_obj = make_url(raw_dsn)
    except Exception as exc:
        raise ValueError(f"Invalid database DSN: {_sanitize_db_error(exc, cfg)}") from exc

    dialect = cfg.effective_dialect()
    if dialect == "sqlite":
        db_name = url_obj.database or ""
        is_memory = db_name in {"", ":memory:"} or "mode=memory" in raw_dsn.lower()
        if not is_memory and db_name:
            Path(db_name).expanduser().parent.mkdir(parents=True, exist_ok=True)
        connect_args: dict[str, Any] = {"timeout": 10.0, "check_same_thread": False}
        if is_memory:
            engine = create_engine(url_obj, connect_args=connect_args, future=True)
        else:
            engine = create_engine(
                url_obj,
                connect_args=connect_args,
                pool_size=cfg.pool_size,
                max_overflow=cfg.max_overflow,
                pool_timeout=cfg.pool_timeout,
                pool_recycle=cfg.pool_recycle,
                pool_pre_ping=True,
                future=True,
            )

        @event.listens_for(engine, "connect")
        def _configure_sqlite_pragmas(dbapi_conn: Any, _conn_record: Any) -> None:
            cursor = dbapi_conn.cursor()
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=5000")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

        return engine, "sqlite"

    if dialect == "postgres":
        ssl_ctx = _build_ssl_context(cfg)
        pg_connect_args: dict[str, Any] = {}
        if ssl_ctx is not None:
            pg_connect_args["ssl_context"] = ssl_ctx
        engine = create_engine(
            url_obj,
            connect_args=pg_connect_args,
            pool_size=cfg.pool_size,
            max_overflow=cfg.max_overflow,
            pool_timeout=cfg.pool_timeout,
            pool_recycle=cfg.pool_recycle,
            pool_pre_ping=True,
            future=True,
        )
        return engine, "postgres"

    if dialect == "mysql":
        ssl_ctx = _build_ssl_context(cfg)
        mysql_connect_args: dict[str, Any] = {}
        ssl_dict: dict[str, Any] = {}
        if cfg.ssl_ca:
            ssl_dict["ca"] = str(Path(cfg.ssl_ca).expanduser())
        if cfg.ssl_cert:
            ssl_dict["cert"] = str(Path(cfg.ssl_cert).expanduser())
        if cfg.ssl_key:
            ssl_dict["key"] = str(Path(cfg.ssl_key).expanduser())
        if cfg.ssl_mode in {"verify-ca", "verify-full"}:
            ssl_dict["check_hostname"] = cfg.ssl_mode == "verify-full"
        if ssl_dict:
            mysql_connect_args["ssl"] = ssl_dict
        elif ssl_ctx is not None:
            mysql_connect_args["ssl"] = {"check_hostname": False}
        engine = create_engine(
            url_obj,
            connect_args=mysql_connect_args,
            pool_size=cfg.pool_size,
            max_overflow=cfg.max_overflow,
            pool_timeout=cfg.pool_timeout,
            pool_recycle=cfg.pool_recycle,
            pool_pre_ping=True,
            future=True,
        )
        return engine, "mysql"

    engine = create_engine(
        url_obj,
        pool_size=cfg.pool_size,
        max_overflow=cfg.max_overflow,
        pool_timeout=cfg.pool_timeout,
        pool_recycle=cfg.pool_recycle,
        pool_pre_ping=True,
        future=True,
    )
    return engine, dialect


def test_db_connection(cfg: DatabaseConfig) -> dict[str, Any]:
    """Validate database configuration and execute a live connection/version probe."""
    dialect = cfg.effective_dialect() if isinstance(cfg, DatabaseConfig) else "unknown"
    engine: Engine | None = None
    try:
        engine, dialect = _build_engine_for_config(cfg)
        with engine.connect() as conn:
            if dialect == "sqlite":
                ver = str(conn.execute(text("SELECT sqlite_version()")).scalar_one() or "")
            elif dialect == "postgres":
                ver = str(conn.execute(text("SELECT version()")).scalar_one() or "")
            elif dialect == "mysql":
                ver = str(conn.execute(text("SELECT @@version")).scalar_one() or "")
            else:
                conn.execute(text("SELECT 1"))
                ver = "connected"
        return {
            "ok": True,
            "dialect": dialect,
            "version": ver,
            "error": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "dialect": dialect,
            "version": "",
            "error": _sanitize_db_error(exc, cfg),
        }
    finally:
        if engine is not None:
            try:
                engine.dispose()
            except Exception:
                pass


setattr(test_db_connection, "__test__", False)


class _TestConnectionDescriptor:
    """Allow ``StorageManager.test_connection(cfg)`` as static AND ``stor.test_connection([cfg])``."""

    def __get__(
        self,
        instance: StorageManager | None,
        owner: type[StorageManager] | None = None,
    ) -> Callable[..., dict[str, Any]]:
        if instance is None:
            return test_db_connection

        def _bound(cfg: DatabaseConfig | None = None) -> dict[str, Any]:
            return test_db_connection(instance.config if cfg is None else cfg)

        return _bound


# ---------------------------------------------------------------------------
# StorageManager & SOCLearningStore
# ---------------------------------------------------------------------------


class StorageManager:
    """Unified multi-dialect persistence manager for SOCLens."""

    test_connection = _TestConnectionDescriptor()

    def __init__(self, config: DatabaseConfig | None = None) -> None:
        self._config = config if config is not None else DatabaseConfig()
        self._lock = threading.RLock()
        self._engine: Engine | None = None
        self._dialect: str = self._config.effective_dialect()
        self._session_factory: sessionmaker[Session] | None = None
        self._schema_initialized: bool = False

    @property
    def config(self) -> DatabaseConfig:
        return self._config

    @property
    def dialect(self) -> str:
        return self._dialect

    def get_engine(self) -> Engine:
        """Lazily build and return the underlying SQLAlchemy ``Engine``."""
        with self._lock:
            if self._engine is None:
                engine, dialect = _build_engine_for_config(self._config)
                self._engine = engine
                self._dialect = dialect
                self._session_factory = sessionmaker(
                    bind=engine,
                    expire_on_commit=False,
                    future=True,
                )
            return self._engine

    def dispose(self) -> None:
        """Dispose the SQLAlchemy connection pool safely."""
        with self._lock:
            if self._engine is not None:
                try:
                    self._engine.dispose()
                finally:
                    self._engine = None
                    self._session_factory = None
                    self._schema_initialized = False

    def rebind_config(self, config: DatabaseConfig) -> None:
        """Rebind storage configuration in-place, disposing old engine if DSN changed."""
        with self._lock:
            dsn_changed = (
                config.dsn != self._config.dsn
                or config.backend != self._config.backend
                or config.ssl_mode != self._config.ssl_mode
                or config.ssl_ca != self._config.ssl_ca
            )
            self._config = config
            self._dialect = config.effective_dialect()
            if dsn_changed and self._engine is not None:
                self.dispose()

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Yield a transactional SQLAlchemy ``Session`` (commits on exit, rolls back on error)."""
        engine = self.get_engine()
        with self._lock:
            factory = self._session_factory
        assert factory is not None
        sess = factory()
        committed = False
        try:
            yield sess
            sess.commit()
            committed = True
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()
        if committed and engine.dialect.name == "sqlite":
            try:
                with engine.connect() as ckpt_conn:
                    ckpt_conn.exec_driver_sql("PRAGMA wal_checkpoint(PASSIVE)")
            except SQLAlchemyError:
                pass

    def ensure_schema(self) -> None:
        """Idempotently create core tables, dialect FTS/FULLTEXT indexes, and migration row."""
        with self._lock:
            engine = self.get_engine()
            METADATA.create_all(engine)
            with engine.begin() as conn:
                if self._dialect == "sqlite":
                    conn.execute(
                        text(
                            "CREATE VIRTUAL TABLE IF NOT EXISTS alerts_history_fts USING fts5("
                            "alert_row_id UNINDEXED, "
                            "source UNINDEXED, "
                            "alert_id UNINDEXED, "
                            "title, "
                            "search_text)"
                        )
                    )
                    conn.execute(
                        text(
                            "CREATE VIRTUAL TABLE IF NOT EXISTS soc_learnings_fts USING fts5("
                            "learning_id UNINDEXED, "
                            "title, "
                            "content, "
                            "tags_text)"
                        )
                    )
                elif self._dialect == "mysql":
                    for ddl in (
                        "CREATE FULLTEXT INDEX idx_alerts_history_ft ON alerts_history (title, search_text)",
                        "CREATE FULLTEXT INDEX idx_soc_learnings_ft ON soc_learnings (title, content)",
                    ):
                        try:
                            conn.execute(text(ddl))
                        except SQLAlchemyError:
                            pass

                existing_ver = conn.execute(
                    select(schema_migrations_table.c.version).where(
                        schema_migrations_table.c.version == SCHEMA_VERSION
                    )
                ).first()
                if existing_ver is None:
                    try:
                        conn.execute(
                            insert(schema_migrations_table).values(
                                version=SCHEMA_VERSION,
                                name="initial_schema_v1",
                                applied_at=time.time(),
                            )
                        )
                    except SQLAlchemyError:
                        pass
            self._schema_initialized = True

    def _ensure_ready(self) -> None:
        if not self._schema_initialized:
            self.ensure_schema()

    # ------------------------------------------------------------------
    # Alert Snapshots, Historical Alerts & IOC/CVE Sightings
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_alert_id(item: Mapping[str, Any], index: int) -> str:
        for key in ("id", "finding_id", "event_id", "playbook_alert_id", "alert_id", "threat_id"):
            val = item.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()[:256]
        digest = hashlib.sha256(_json_dumps_safe(item).encode("utf-8", errors="ignore")).hexdigest()[:24]
        return f"item-{index}-{digest}"

    @staticmethod
    def _extract_alert_title(item: Mapping[str, Any]) -> str:
        for key in ("title", "rule_name", "rule_title", "threatName", "name", "summary"):
            val = item.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return ""

    @staticmethod
    def _extract_alert_severity(item: Mapping[str, Any]) -> str:
        for key in ("severity", "priority", "urgency", "confidenceLevel", "risk_score"):
            val = item.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()[:64]
        return ""

    @staticmethod
    def _extract_alert_status(item: Mapping[str, Any]) -> str:
        for key in ("status", "incidentStatus", "state"):
            val = item.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()[:64]
        return ""

    @staticmethod
    def _extract_alert_occurred_at(item: Mapping[str, Any], *, fetched_at: float) -> float:
        for key in ("triggered", "created", "createdAt", "time", "_time", "timestamp", "updated"):
            if key in item and item.get(key) is not None:
                parsed = _parse_timestamp_epoch(item.get(key), fallback=-1.0)
                if parsed > 0:
                    return parsed
        return fetched_at

    def get_alerts_snapshot(self, source: str) -> dict[str, Any] | None:
        """Return latest snapshot dict for ``source`` or ``None`` if absent."""
        self._ensure_ready()
        clean_src = str(source or "").strip()
        if not clean_src:
            return None
        with self.session() as sess:
            row = sess.execute(
                select(alert_snapshots_table).where(alert_snapshots_table.c.source == clean_src)
            ).mappings().first()
        if row is None:
            return None
        try:
            items = json.loads(row["items_json"] or "[]")
        except ValueError:
            items = []
        try:
            meta = json.loads(row["meta_json"] or "{}")
        except ValueError:
            meta = {}
        return {
            "source": row["source"],
            "timeframe": row["timeframe"],
            "fetched_at": float(row["fetched_at"]),
            "meta": meta if isinstance(meta, dict) else {},
            "items": items if isinstance(items, list) else [],
        }

    def upsert_alerts_snapshot(
        self,
        source: str,
        items: Sequence[Mapping[str, Any]],
        *,
        timeframe: str = "last_24h",
        meta: Mapping[str, Any] | None = None,
        fetched_at: float | None = None,
    ) -> int:
        """Persist redacted alert snapshot, rolling historical records, and IOC/CVE sightings."""
        self._ensure_ready()
        clean_src = str(source or "").strip()
        if not clean_src:
            return 0
        ts = float(fetched_at) if fetched_at is not None else time.time()
        now = time.time()

        redacted_items_raw = redact_sensitive_data([dict(it) for it in items if isinstance(it, Mapping)])
        redacted_items: list[dict[str, Any]] = (
            [dict(it) for it in redacted_items_raw if isinstance(it, Mapping)]
            if isinstance(redacted_items_raw, list)
            else []
        )
        redacted_meta_raw = redact_sensitive_data(dict(meta) if meta else {})
        redacted_meta: dict[str, Any] = (
            dict(redacted_meta_raw) if isinstance(redacted_meta_raw, Mapping) else {}
        )

        items_json = _json_dumps_safe(redacted_items)
        meta_json = _json_dumps_safe(redacted_meta)

        extracted_iocs: list[tuple[str, str, str]] = []
        with self._lock:
            with self.session() as sess:
                existing_snap = sess.execute(
                    text("SELECT source, fetched_at FROM alert_snapshots WHERE source = :src"),
                    {"src": clean_src},
                ).first()
                is_same_fetched_at = (
                    existing_snap is not None
                    and existing_snap[1] is not None
                    and abs(float(existing_snap[1]) - ts) < 1e-6
                )
                if existing_snap is None:
                    sess.execute(
                        insert(alert_snapshots_table).values(
                            source=clean_src,
                            timeframe=str(timeframe or "last_24h"),
                            fetched_at=ts,
                            meta_json=meta_json,
                            items_json=items_json,
                            updated_at=now,
                        )
                    )
                else:
                    sess.execute(
                        update(alert_snapshots_table)
                        .where(alert_snapshots_table.c.source == clean_src)
                        .values(
                            timeframe=str(timeframe or "last_24h"),
                            fetched_at=ts,
                            meta_json=meta_json,
                            items_json=items_json,
                            updated_at=now,
                        )
                    )

                for idx, item in enumerate(redacted_items):
                    alert_id = self._extract_alert_id(item, idx)
                    title = self._extract_alert_title(item)
                    severity = self._extract_alert_severity(item)
                    status = self._extract_alert_status(item)
                    occurred_at = self._extract_alert_occurred_at(item, fetched_at=ts)
                    payload_json = _json_dumps_safe(item)
                    search_text = " ".join(_flatten_search_strings(item))

                    existing_row = sess.execute(
                        select(alerts_history_table.c.id).where(
                            and_(
                                alerts_history_table.c.source == clean_src,
                                alerts_history_table.c.alert_id == alert_id,
                            )
                        )
                    ).first()
                    if existing_row is None:
                        res = cast(
                            CursorResult[Any],
                            sess.execute(
                                insert(alerts_history_table).values(
                                    source=clean_src,
                                    alert_id=alert_id,
                                    title=title,
                                    severity=severity,
                                    status=status,
                                    occurred_at=occurred_at,
                                    fetched_at=ts,
                                    payload_json=payload_json,
                                    search_text=search_text,
                                )
                            ),
                        )
                        row_id = int(res.inserted_primary_key[0]) if res.inserted_primary_key else 0
                    else:
                        row_id = int(existing_row[0])
                        sess.execute(
                            update(alerts_history_table)
                            .where(alerts_history_table.c.id == row_id)
                            .values(
                                title=title,
                                severity=severity,
                                status=status,
                                occurred_at=occurred_at,
                                fetched_at=ts,
                                payload_json=payload_json,
                                search_text=search_text,
                            )
                        )

                    if self._dialect == "sqlite" and row_id:
                        sess.execute(
                            text("DELETE FROM alerts_history_fts WHERE alert_row_id = :rid"),
                            {"rid": row_id},
                        )
                        sess.execute(
                            text(
                                "INSERT INTO alerts_history_fts "
                                "(alert_row_id, source, alert_id, title, search_text) "
                                "VALUES (:rid, :src, :aid, :title, :stext)"
                            ),
                            {
                                "rid": row_id,
                                "src": clean_src,
                                "aid": alert_id,
                                "title": title,
                                "stext": search_text,
                            },
                        )

                    ev_key = f"{clean_src}::{alert_id}"
                    for ind_raw, ind_type in _dedupe_iocs(_extract_iocs_from_value(item)):
                        extracted_iocs.append((ind_raw, ind_type, ev_key))

                if extracted_iocs:
                    deduped_iocs: list[tuple[str, str, str, str]] = []
                    seen_ioc_keys: set[tuple[str, str]] = set()
                    for ind_raw, ind_type, ev_key in extracted_iocs:
                        raw_ind = str(ind_raw or "").strip()
                        norm_ind = raw_ind.lower()
                        if not norm_ind:
                            continue
                        dedup_key = (norm_ind, ev_key)
                        if dedup_key in seen_ioc_keys:
                            continue
                        seen_ioc_keys.add(dedup_key)
                        clean_type = str(ind_type or "").strip().lower() or "ioc"
                        deduped_iocs.append((norm_ind, raw_ind, clean_type, ev_key))

                    norm_inds = sorted({entry[0] for entry in deduped_iocs})
                    existing_by_key: dict[tuple[str, str], RowMapping] = {}
                    ioc_cols = (
                        (
                            ioc_sightings_table.c.id,
                            ioc_sightings_table.c.indicator_norm,
                            ioc_sightings_table.c.event_key,
                            ioc_sightings_table.c.sighting_count,
                        )
                        if self._dialect == "postgres"
                        else (
                            ioc_sightings_table.c.id,
                            ioc_sightings_table.c.indicator_norm,
                            ioc_sightings_table.c.event_key,
                            ioc_sightings_table.c.sighting_count,
                            ioc_sightings_table.c.first_seen_at,
                            ioc_sightings_table.c.last_seen_at,
                        )
                    )
                    for chunk_start in range(0, len(norm_inds), 400):
                        chunk = norm_inds[chunk_start : chunk_start + 400]
                        existing_rows = sess.execute(
                            select(*ioc_cols).where(
                                and_(
                                    ioc_sightings_table.c.source == clean_src,
                                    ioc_sightings_table.c.indicator_norm.in_(chunk),
                                )
                            )
                        ).mappings().all()
                        for r in existing_rows:
                            existing_by_key[(str(r["indicator_norm"]), str(r["event_key"]))] = r

                    to_insert: list[dict[str, Any]] = []
                    for norm_ind, raw_ind, clean_type, ev_key in deduped_iocs:
                        existing_ioc = existing_by_key.get((norm_ind, ev_key))
                        if existing_ioc is None:
                            to_insert.append(
                                {
                                    "indicator_norm": norm_ind,
                                    "indicator_raw": raw_ind,
                                    "indicator_type": clean_type,
                                    "source": clean_src,
                                    "event_key": ev_key,
                                    "sighting_count": 1,
                                    "first_seen_at": ts,
                                    "last_seen_at": ts,
                                    "context_json": "{}",
                                }
                            )
                        else:
                            raw_prev_last = existing_ioc.get("last_seen_at")
                            prev_last = float(raw_prev_last) if raw_prev_last is not None else ts
                            if (
                                is_same_fetched_at
                                and raw_prev_last is not None
                                and abs(prev_last - ts) < 1e-6
                            ):
                                continue
                            new_count = int(existing_ioc["sighting_count"] or 0) + 1
                            raw_first = existing_ioc.get("first_seen_at")
                            first_seen = (
                                min(float(raw_first), ts) if raw_first is not None else ts
                            )
                            last_seen = max(prev_last, ts)
                            update_vals: dict[str, Any] = {
                                "indicator_raw": raw_ind,
                                "indicator_type": clean_type,
                                "sighting_count": new_count,
                                "last_seen_at": last_seen,
                            }
                            if raw_first is not None:
                                update_vals["first_seen_at"] = first_seen
                            sess.execute(
                                update(ioc_sightings_table)
                                .where(ioc_sightings_table.c.id == existing_ioc["id"])
                                .values(**update_vals)
                            )
                    if to_insert:
                        sess.execute(insert(ioc_sightings_table), to_insert)

        return len(redacted_items)

    def delete_alerts_snapshot(self, source: str | None = None) -> None:
        """Delete cached snapshot rows for ``source`` or all sources (history remains)."""
        self._ensure_ready()
        with self._lock:
            with self.session() as sess:
                if source is None:
                    sess.execute(delete(alert_snapshots_table))
                else:
                    sess.execute(
                        delete(alert_snapshots_table).where(
                            alert_snapshots_table.c.source == str(source).strip()
                        )
                    )

    @staticmethod
    def _row_to_alert_result(row: Mapping[Any, Any]) -> dict[str, Any]:
        payload: dict[str, Any]
        try:
            loaded = json.loads(row.get("payload_json") or "{}")
            payload = dict(loaded) if isinstance(loaded, Mapping) else {}
        except ValueError:
            payload = {}
        result: dict[str, Any] = dict(payload)
        result.setdefault("id", row.get("alert_id"))
        result["source"] = row.get("source")
        result["alert_id"] = row.get("alert_id")
        if row.get("title"):
            result.setdefault("title", row.get("title"))
        if row.get("severity"):
            result.setdefault("severity", row.get("severity"))
        if row.get("status"):
            result.setdefault("status", row.get("status"))
        result["occurred_at"] = float(row.get("occurred_at") or 0.0)
        result["fetched_at"] = float(row.get("fetched_at") or 0.0)
        return result

    def search_alerts_history(
        self,
        query: str,
        *,
        source: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Dialect-aware FTS/keyword search across historical alerts."""
        clean_q = (query or "").strip()
        if not clean_q:
            return []
        eff_limit = max(1, min(int(limit), 500))
        clean_src = str(source).strip() if source and str(source).strip() else None
        self._ensure_ready()

        rows: list[RowMapping] = []
        with self.session() as sess:
            if self._dialect == "sqlite":
                tokens = _FTS_TOKEN_RE.findall(clean_q)
                if tokens:
                    fts_expr = " AND ".join(f'"{tok}"' for tok in tokens[:8])
                    sql_str = (
                        "SELECT h.id, h.source, h.alert_id, h.title, h.severity, h.status, "
                        "h.occurred_at, h.fetched_at, h.payload_json "
                        "FROM alerts_history h "
                        "JOIN alerts_history_fts f ON f.alert_row_id = h.id "
                        "WHERE alerts_history_fts MATCH :fts_q "
                    )
                    params: dict[str, Any] = {"fts_q": fts_expr, "lim": eff_limit}
                    if clean_src is not None:
                        sql_str += "AND h.source = :src "
                        params["src"] = clean_src
                    sql_str += "ORDER BY h.occurred_at DESC LIMIT :lim"
                    try:
                        rows = list(sess.execute(text(sql_str), params).mappings().all())
                    except SQLAlchemyError:
                        rows = []
                if not rows:
                    like_pat = f"%{_escape_like_pattern(clean_q)}%"
                    stmt = select(alerts_history_table).where(
                        or_(
                            alerts_history_table.c.title.like(like_pat, escape="|"),
                            alerts_history_table.c.search_text.like(like_pat, escape="|"),
                            alerts_history_table.c.alert_id.like(like_pat, escape="|"),
                        )
                    )
                    if clean_src is not None:
                        stmt = stmt.where(alerts_history_table.c.source == clean_src)
                    stmt = stmt.order_by(alerts_history_table.c.occurred_at.desc()).limit(eff_limit)
                    rows = list(sess.execute(stmt).mappings().all())

            elif self._dialect == "postgres":
                like_pat = f"%{_escape_like_pattern(clean_q)}%"
                sql_pg = (
                    "SELECT id, source, alert_id, title, severity, status, "
                    "occurred_at, fetched_at, payload_json "
                    "FROM alerts_history "
                    "WHERE (to_tsvector('english', coalesce(title, '') || ' ' || coalesce(search_text, '')) "
                    "@@ plainto_tsquery('english', :q) "
                    "OR title ILIKE :like_pat ESCAPE '|' "
                    "OR search_text ILIKE :like_pat ESCAPE '|') "
                )
                params_pg: dict[str, Any] = {
                    "q": clean_q,
                    "like_pat": like_pat,
                    "lim": eff_limit,
                }
                if clean_src is not None:
                    sql_pg += "AND source = :src "
                    params_pg["src"] = clean_src
                sql_pg += "ORDER BY occurred_at DESC LIMIT :lim"
                rows = list(sess.execute(text(sql_pg), params_pg).mappings().all())

            elif self._dialect == "mysql":
                like_pat = f"%{_escape_like_pattern(clean_q)}%"
                bool_tokens = _MYSQL_BOOL_TOKEN_RE.findall(clean_q)
                if bool_tokens:
                    bool_q = " ".join(f"+{tok}*" for tok in bool_tokens[:8])
                    sql_mysql = (
                        "SELECT id, source, alert_id, title, severity, status, "
                        "occurred_at, fetched_at, payload_json "
                        "FROM alerts_history "
                        "WHERE (MATCH(title, search_text) AGAINST (:mq IN BOOLEAN MODE) "
                        "OR title LIKE :like_pat ESCAPE '|' "
                        "OR search_text LIKE :like_pat ESCAPE '|') "
                    )
                    params_mysql: dict[str, Any] = {
                        "mq": bool_q,
                        "like_pat": like_pat,
                        "lim": eff_limit,
                    }
                else:
                    sql_mysql = (
                        "SELECT id, source, alert_id, title, severity, status, "
                        "occurred_at, fetched_at, payload_json "
                        "FROM alerts_history "
                        "WHERE (title LIKE :like_pat ESCAPE '|' "
                        "OR search_text LIKE :like_pat ESCAPE '|') "
                    )
                    params_mysql = {
                        "like_pat": like_pat,
                        "lim": eff_limit,
                    }
                if clean_src is not None:
                    sql_mysql += "AND source = :src "
                    params_mysql["src"] = clean_src
                sql_mysql += "ORDER BY occurred_at DESC LIMIT :lim"
                rows = list(sess.execute(text(sql_mysql), params_mysql).mappings().all())

            else:
                like_pat = f"%{_escape_like_pattern(clean_q)}%"
                stmt = select(alerts_history_table).where(
                    or_(
                        alerts_history_table.c.title.like(like_pat, escape="|"),
                        alerts_history_table.c.search_text.like(like_pat, escape="|"),
                    )
                )
                if clean_src is not None:
                    stmt = stmt.where(alerts_history_table.c.source == clean_src)
                stmt = stmt.order_by(alerts_history_table.c.occurred_at.desc()).limit(eff_limit)
                rows = list(sess.execute(stmt).mappings().all())

        return [self._row_to_alert_result(r) for r in rows]

    def upsert_ioc_sighting(
        self,
        *,
        indicator: str,
        indicator_type: str = "",
        source: str = "",
        event_key: str = "",
        context: Mapping[str, Any] | None = None,
        seen_at: float | None = None,
    ) -> dict[str, Any]:
        """Record or increment an extracted IOC/CVE sighting (case-normalized)."""
        self._ensure_ready()
        raw_ind = str(indicator or "").strip()
        norm_ind = raw_ind.lower()
        if not norm_ind:
            return {}
        clean_type = str(indicator_type or "").strip().lower() or "ioc"
        clean_src = str(source or "").strip() or "unknown"
        clean_ev = str(event_key or "").strip() or ""
        ts = float(seen_at) if seen_at is not None else time.time()

        redacted_ctx_raw = redact_sensitive_data(dict(context) if context else {})
        redacted_ctx: dict[str, Any] = (
            dict(redacted_ctx_raw) if isinstance(redacted_ctx_raw, Mapping) else {}
        )
        ctx_json = _json_dumps_safe(redacted_ctx)

        with self._lock:
            with self.session() as sess:
                existing = sess.execute(
                    select(ioc_sightings_table).where(
                        and_(
                            ioc_sightings_table.c.indicator_norm == norm_ind,
                            ioc_sightings_table.c.source == clean_src,
                            ioc_sightings_table.c.event_key == clean_ev,
                        )
                    )
                ).mappings().first()
                if existing is None:
                    sess.execute(
                        insert(ioc_sightings_table).values(
                            indicator_norm=norm_ind,
                            indicator_raw=raw_ind,
                            indicator_type=clean_type,
                            source=clean_src,
                            event_key=clean_ev,
                            sighting_count=1,
                            first_seen_at=ts,
                            last_seen_at=ts,
                            context_json=ctx_json,
                        )
                    )
                    count = 1
                    first_seen = ts
                    last_seen = ts
                else:
                    count = int(existing["sighting_count"] or 0) + 1
                    first_seen = min(float(existing["first_seen_at"]), ts)
                    last_seen = max(float(existing["last_seen_at"]), ts)
                    sess.execute(
                        update(ioc_sightings_table)
                        .where(ioc_sightings_table.c.id == existing["id"])
                        .values(
                            indicator_raw=raw_ind,
                            indicator_type=clean_type,
                            sighting_count=count,
                            first_seen_at=first_seen,
                            last_seen_at=last_seen,
                            context_json=ctx_json if redacted_ctx else existing["context_json"],
                        )
                    )
        return {
            "indicator": raw_ind,
            "indicator_norm": norm_ind,
            "indicator_type": clean_type,
            "source": clean_src,
            "event_key": clean_ev,
            "sighting_count": count,
            "count": count,
            "first_seen_at": first_seen,
            "last_seen_at": last_seen,
            "context": redacted_ctx,
        }

    def lookup_ioc_sightings(
        self,
        indicator: str,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Case-insensitive lookup of IOC/CVE sightings."""
        clean_ind = (indicator or "").strip().lower()
        if not clean_ind:
            return []
        eff_limit = max(1, min(int(limit), 500))
        self._ensure_ready()

        with self.session() as sess:
            rows = sess.execute(
                select(ioc_sightings_table)
                .where(ioc_sightings_table.c.indicator_norm == clean_ind)
                .order_by(ioc_sightings_table.c.last_seen_at.desc())
                .limit(eff_limit)
            ).mappings().all()

        results: list[dict[str, Any]] = []
        for row in rows:
            try:
                ctx = json.loads(row.get("context_json") or "{}")
            except ValueError:
                ctx = {}
            cnt = int(row.get("sighting_count") or 1)
            results.append(
                {
                    "indicator": row["indicator_raw"],
                    "indicator_norm": row["indicator_norm"],
                    "indicator_type": row["indicator_type"],
                    "source": row["source"],
                    "event_key": row["event_key"],
                    "sighting_count": cnt,
                    "count": cnt,
                    "first_seen_at": float(row["first_seen_at"]),
                    "last_seen_at": float(row["last_seen_at"]),
                    "context": ctx if isinstance(ctx, dict) else {},
                }
            )
        return results

    # ------------------------------------------------------------------
    # Unique Events & Event AI Panels
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitize_event_payload(event_dict: Mapping[str, Any]) -> dict[str, Any]:
        redacted_raw = redact_sensitive_data(dict(event_dict))
        return dict(redacted_raw) if isinstance(redacted_raw, Mapping) else {}

    def upsert_unique_event(
        self,
        event_dict: Mapping[str, Any],
        *,
        updated_at: float | None = None,
    ) -> bool:
        """Upsert a ``UniqueEvent`` dictionary. Returns ``True`` if newly inserted."""
        self._ensure_ready()
        clean = self._sanitize_event_payload(event_dict)
        ev_key = str(clean.get("event_key") or "").strip()
        if not ev_key:
            return False
        now = float(updated_at) if updated_at is not None else time.time()
        meta_raw = clean.get("metadata")
        meta = dict(meta_raw) if isinstance(meta_raw, Mapping) else {}
        meta.pop("images", None)

        with self._lock:
            with self.session() as sess:
                existing = sess.execute(
                    select(unique_events_table.c.event_key).where(
                        unique_events_table.c.event_key == ev_key
                    )
                ).first()
                values = {
                    "source_kind": str(clean.get("source_kind") or "")[:64],
                    "native_id": str(clean.get("native_id") or "")[:256],
                    "scope": str(clean.get("scope") or "default")[:128],
                    "title": str(clean.get("title") or ""),
                    "severity": str(clean.get("severity") or "")[:64],
                    "status": str(clean.get("status") or "")[:64],
                    "event_timestamp": str(clean.get("timestamp") or "")[:64],
                    "summary": str(clean.get("summary") or ""),
                    "metadata_json": _json_dumps_safe(meta),
                    "updated_at": now,
                }
                if existing is None:
                    sess.execute(insert(unique_events_table).values(event_key=ev_key, **values))
                    is_new = True
                else:
                    sess.execute(
                        update(unique_events_table)
                        .where(unique_events_table.c.event_key == ev_key)
                        .values(**values)
                    )
                    is_new = False

        for ind_raw, ind_type in _dedupe_iocs(_extract_iocs_from_value(clean)):
            self.upsert_ioc_sighting(
                indicator=ind_raw,
                indicator_type=ind_type,
                source=str(clean.get("source_kind") or "event"),
                event_key=ev_key,
                seen_at=now,
            )
        return is_new

    def mark_events_seen_batch(self, events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Insert unseen events in batch; return newly inserted event dicts."""
        self._ensure_ready()
        if not events:
            return []
        newly_seen: list[dict[str, Any]] = []
        seen_in_batch: set[str] = set()
        now = time.time()
        with self._lock:
            with self.session() as sess:
                existing_keys = {
                    str(r[0])
                    for r in sess.execute(select(unique_events_table.c.event_key)).all()
                }
                for raw_ev in events:
                    clean = self._sanitize_event_payload(raw_ev)
                    ev_key = str(clean.get("event_key") or "").strip()
                    if not ev_key or ev_key in seen_in_batch or ev_key in existing_keys:
                        continue
                    seen_in_batch.add(ev_key)
                    existing_keys.add(ev_key)
                    meta_raw = clean.get("metadata")
                    meta = dict(meta_raw) if isinstance(meta_raw, Mapping) else {}
                    meta.pop("images", None)
                    sess.execute(
                        insert(unique_events_table).values(
                            event_key=ev_key,
                            source_kind=str(clean.get("source_kind") or "")[:64],
                            native_id=str(clean.get("native_id") or "")[:256],
                            scope=str(clean.get("scope") or "default")[:128],
                            title=str(clean.get("title") or ""),
                            severity=str(clean.get("severity") or "")[:64],
                            status=str(clean.get("status") or "")[:64],
                            event_timestamp=str(clean.get("timestamp") or "")[:64],
                            summary=str(clean.get("summary") or ""),
                            metadata_json=_json_dumps_safe(meta),
                            updated_at=now,
                        )
                    )
                    newly_seen.append(clean)
        return newly_seen

    def add_event_panel(
        self,
        event_key: str,
        panel_dict: Mapping[str, Any],
        *,
        event_dict: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Insert or update an Event AI panel entry (idempotent by ``entry_id``)."""
        self._ensure_ready()
        clean_key = str(event_key or "").strip()
        if not clean_key:
            raise ValueError("event_key must be non-empty.")
        if event_dict is not None:
            self.upsert_unique_event(event_dict)

        redacted_raw = redact_sensitive_data(dict(panel_dict))
        clean = dict(redacted_raw) if isinstance(redacted_raw, Mapping) else {}
        entry_id = str(clean.get("entry_id") or "").strip() or uuid.uuid4().hex[:16]
        panel_ts = str(clean.get("timestamp") or "").strip() or datetime.now(UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        created_at = _parse_timestamp_epoch(panel_ts, fallback=time.time())
        tool_calls = clean.get("tool_calls")
        blocked_actions = clean.get("blocked_actions")

        row_values = {
            "event_key": clean_key,
            "run_id": str(clean.get("run_id") or "")[:128],
            "panel_timestamp": panel_ts[:64],
            "created_at": created_at,
            "mode": str(clean.get("mode") or "ask_only")[:64],
            "provider": str(clean.get("provider") or "")[:64],
            "model": str(clean.get("model") or "")[:128],
            "question": str(clean.get("question") or ""),
            "answer_markdown": str(clean.get("answer_markdown") or ""),
            "tool_calls_json": _json_dumps_safe(
                list(tool_calls) if isinstance(tool_calls, list) else []
            ),
            "blocked_actions_json": _json_dumps_safe(
                list(blocked_actions) if isinstance(blocked_actions, list) else []
            ),
            "status": str(clean.get("status") or "completed")[:64],
            "auto_triggered": bool(clean.get("auto_triggered", False)),
            "error": str(clean.get("error") or ""),
        }
        with self._lock:
            with self.session() as sess:
                existing = sess.execute(
                    select(event_ai_panels_table.c.entry_id).where(
                        event_ai_panels_table.c.entry_id == entry_id
                    )
                ).first()
                if existing is None:
                    # Ensure deterministic insertion ordering when multiple panels are
                    # recorded within the same 1-second ISO timestamp window.
                    same_sec_rows = sess.execute(
                        select(event_ai_panels_table.c.created_at)
                        .where(
                            and_(
                                event_ai_panels_table.c.event_key == clean_key,
                                event_ai_panels_table.c.created_at >= created_at,
                                event_ai_panels_table.c.created_at < created_at + 0.999,
                            )
                        )
                        .order_by(event_ai_panels_table.c.created_at.desc())
                        .limit(1)
                    ).first()
                    if same_sec_rows is not None and same_sec_rows[0] is not None:
                        row_values["created_at"] = min(
                            created_at + 0.999,
                            max(created_at, float(same_sec_rows[0]) + 1e-4),
                        )
                    sess.execute(
                        insert(event_ai_panels_table).values(entry_id=entry_id, **row_values)
                    )
                else:
                    sess.execute(
                        update(event_ai_panels_table)
                        .where(event_ai_panels_table.c.entry_id == entry_id)
                        .values(**row_values)
                    )
        return {
            "entry_id": entry_id,
            "run_id": row_values["run_id"],
            "timestamp": panel_ts,
            "mode": row_values["mode"],
            "provider": row_values["provider"],
            "model": row_values["model"],
            "question": row_values["question"],
            "answer_markdown": row_values["answer_markdown"],
            "tool_calls": list(tool_calls) if isinstance(tool_calls, list) else [],
            "blocked_actions": list(blocked_actions) if isinstance(blocked_actions, list) else [],
            "status": row_values["status"],
            "auto_triggered": row_values["auto_triggered"],
            "error": row_values["error"],
        }

    def get_event_panels(self, event_key: str) -> list[dict[str, Any]]:
        """Return persisted Event AI panels for ``event_key`` in chronological order."""
        clean_key = str(event_key or "").strip()
        if not clean_key:
            return []
        self._ensure_ready()
        with self.session() as sess:
            rows = sess.execute(
                select(event_ai_panels_table)
                .where(event_ai_panels_table.c.event_key == clean_key)
                .order_by(event_ai_panels_table.c.created_at.asc(), event_ai_panels_table.c.entry_id.asc())
            ).mappings().all()
        panels: list[dict[str, Any]] = []
        for row in rows:
            try:
                tcs = json.loads(row.get("tool_calls_json") or "[]")
            except ValueError:
                tcs = []
            try:
                blks = json.loads(row.get("blocked_actions_json") or "[]")
            except ValueError:
                blks = []
            panels.append(
                {
                    "entry_id": row["entry_id"],
                    "run_id": row["run_id"],
                    "timestamp": row["panel_timestamp"],
                    "mode": row["mode"],
                    "provider": row["provider"],
                    "model": row["model"],
                    "question": row["question"],
                    "answer_markdown": row["answer_markdown"],
                    "tool_calls": tcs if isinstance(tcs, list) else [],
                    "blocked_actions": blks if isinstance(blks, list) else [],
                    "status": row["status"],
                    "auto_triggered": bool(row["auto_triggered"]),
                    "error": row["error"],
                }
            )
        return panels

    def has_investigation(self, event_key: str) -> bool:
        clean_key = str(event_key or "").strip()
        if not clean_key:
            return False
        self._ensure_ready()
        with self.session() as sess:
            row = sess.execute(
                select(event_ai_panels_table.c.entry_id)
                .where(event_ai_panels_table.c.event_key == clean_key)
                .limit(1)
            ).first()
        return row is not None

    def query_investigated_keys(self) -> list[str]:
        self._ensure_ready()
        with self.session() as sess:
            rows = sess.execute(
                select(event_ai_panels_table.c.event_key).distinct()
            ).all()
        return [str(r[0]) for r in rows if r[0]]

    def get_unique_event(self, event_key: str) -> dict[str, Any] | None:
        clean_key = str(event_key or "").strip()
        if not clean_key:
            return None
        self._ensure_ready()
        with self.session() as sess:
            row = sess.execute(
                select(unique_events_table).where(unique_events_table.c.event_key == clean_key)
            ).mappings().first()
        if row is None:
            return None
        return self._row_to_unique_event_dict(row)

    @staticmethod
    def _row_to_unique_event_dict(row: Mapping[Any, Any]) -> dict[str, Any]:
        try:
            meta = json.loads(row.get("metadata_json") or "{}")
        except ValueError:
            meta = {}
        return {
            "event_key": row["event_key"],
            "source_kind": row["source_kind"],
            "native_id": row["native_id"],
            "scope": row["scope"],
            "title": row["title"],
            "severity": row["severity"],
            "status": row["status"],
            "timestamp": row["event_timestamp"],
            "summary": row["summary"],
            "metadata": meta if isinstance(meta, dict) else {},
        }

    def list_unique_events(self, *, investigated_only: bool = False) -> list[dict[str, Any]]:
        self._ensure_ready()
        with self.session() as sess:
            if not investigated_only:
                rows = sess.execute(
                    select(unique_events_table).order_by(unique_events_table.c.updated_at.asc())
                ).mappings().all()
            else:
                investigated = set(self.query_investigated_keys())
                if not investigated:
                    return []
                rows = sess.execute(
                    select(unique_events_table)
                    .where(unique_events_table.c.event_key.in_(investigated))
                    .order_by(unique_events_table.c.updated_at.asc())
                ).mappings().all()
        return [self._row_to_unique_event_dict(r) for r in rows]

    def unmark_unique_event(self, event_key: str) -> bool:
        clean_key = str(event_key or "").strip()
        if not clean_key:
            return False
        self._ensure_ready()
        with self._lock:
            with self.session() as sess:
                has_panels = sess.execute(
                    select(event_ai_panels_table.c.entry_id)
                    .where(event_ai_panels_table.c.event_key == clean_key)
                    .limit(1)
                ).first()
                if has_panels is not None:
                    return False
                res = cast(
                    CursorResult[Any],
                    sess.execute(
                        delete(unique_events_table).where(unique_events_table.c.event_key == clean_key)
                    ),
                )
                return bool(res.rowcount and res.rowcount > 0)

    def clear_events_and_panels(self, event_key: str | None = None) -> None:
        self._ensure_ready()
        with self._lock:
            with self.session() as sess:
                if event_key is None:
                    sess.execute(delete(event_ai_panels_table))
                    sess.execute(delete(unique_events_table))
                else:
                    clean_key = str(event_key).strip()
                    sess.execute(
                        delete(event_ai_panels_table).where(
                            event_ai_panels_table.c.event_key == clean_key
                        )
                    )
                    sess.execute(
                        delete(unique_events_table).where(
                            unique_events_table.c.event_key == clean_key
                        )
                    )

    # ------------------------------------------------------------------
    # Audit Log Persistence (Tagged with analyst_id & workstation_id)
    # ------------------------------------------------------------------

    def append_audit_entry(self, entry: AuditEntry) -> AuditEntry:
        """Redact sensitive values, tag analyst/workstation, and insert idempotently."""
        self._ensure_ready()
        entry_id = entry.entry_id.strip() if isinstance(entry.entry_id, str) else ""
        if not entry_id:
            entry_id = uuid.uuid4().hex[:16]

        timestamp = entry.timestamp.strip() if isinstance(entry.timestamp, str) else ""
        if not timestamp:
            timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        created_at = _parse_timestamp_epoch(timestamp, fallback=time.time())

        raw_payload = dict(entry.payload) if isinstance(entry.payload, Mapping) else {}
        redacted_payload_obj = redact_sensitive_data(raw_payload)
        redacted_payload: dict[str, Any] = (
            dict(redacted_payload_obj) if isinstance(redacted_payload_obj, Mapping) else {}
        )

        analyst_id = (
            getattr(entry, "analyst_id", "") or ""
        ).strip() or self._config.analyst_id
        workstation_id = (
            getattr(entry, "workstation_id", "") or ""
        ).strip() or self._config.workstation_id

        sanitized = AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            run_id=str(entry.run_id or ""),
            event_key=str(redact_sensitive_data(entry.event_key or "")),
            provider=str(redact_sensitive_data(entry.provider or "")),
            mode=str(entry.mode or ""),
            event_type=entry.event_type,
            tool_name=str(redact_sensitive_data(entry.tool_name or "")),
            allowed=entry.allowed,
            reason=str(redact_sensitive_data(entry.reason or "")),
            payload=redacted_payload,
            analyst_id=str(redact_sensitive_data(analyst_id)),
            workstation_id=str(redact_sensitive_data(workstation_id)),
        )

        with self._lock:
            with self.session() as sess:
                existing = sess.execute(
                    select(audit_logs_table.c.entry_id).where(
                        audit_logs_table.c.entry_id == sanitized.entry_id
                    )
                ).first()
                if existing is None:
                    sess.execute(
                        insert(audit_logs_table).values(
                            entry_id=sanitized.entry_id,
                            timestamp=sanitized.timestamp,
                            created_at=created_at,
                            run_id=sanitized.run_id[:128],
                            event_key=sanitized.event_key[:512],
                            provider=sanitized.provider[:64],
                            mode=sanitized.mode[:64],
                            event_type=sanitized.event_type[:64],
                            tool_name=sanitized.tool_name[:128],
                            allowed=sanitized.allowed,
                            reason=sanitized.reason,
                            payload_json=_json_dumps_safe(sanitized.payload),
                            analyst_id=sanitized.analyst_id[:128],
                            workstation_id=sanitized.workstation_id[:128],
                        )
                    )
        return sanitized

    def query_audit_entries(
        self,
        *,
        event_key: str | None = None,
        run_id: str | None = None,
        event_type: str | None = None,
        blocked_only: bool = False,
        limit: int = 500,
    ) -> list[AuditEntry]:
        """Query persisted audit log entries with optional filters."""
        if limit <= 0:
            return []
        self._ensure_ready()

        stmt = select(audit_logs_table)
        if event_key is not None:
            stmt = stmt.where(audit_logs_table.c.event_key == event_key)
        if run_id is not None:
            stmt = stmt.where(audit_logs_table.c.run_id == run_id)
        if event_type is not None:
            stmt = stmt.where(audit_logs_table.c.event_type == event_type)
        if blocked_only:
            stmt = stmt.where(
                or_(
                    audit_logs_table.c.event_type == "blocked_action",
                    audit_logs_table.c.allowed.is_(False),
                )
            )
        stmt = stmt.order_by(
            audit_logs_table.c.created_at.desc(),
            audit_logs_table.c.entry_id.desc(),
        ).limit(int(limit))

        with self.session() as sess:
            rows = list(sess.execute(stmt).mappings().all())

        rows.reverse()
        entries: list[AuditEntry] = []
        for row in rows:
            ev_type_raw = str(row.get("event_type") or "")
            if ev_type_raw not in VALID_AUDIT_EVENT_TYPES:
                continue
            try:
                payload = json.loads(row.get("payload_json") or "{}")
            except ValueError:
                payload = {}
            entry = AuditEntry.from_dict(
                {
                    "entry_id": row["entry_id"],
                    "timestamp": row["timestamp"],
                    "run_id": row["run_id"],
                    "event_key": row["event_key"],
                    "provider": row["provider"],
                    "mode": row["mode"],
                    "event_type": ev_type_raw,
                    "tool_name": row["tool_name"],
                    "allowed": row["allowed"],
                    "reason": row["reason"],
                    "payload": payload if isinstance(payload, dict) else {},
                    "analyst_id": row.get("analyst_id") or "",
                    "workstation_id": row.get("workstation_id") or "",
                }
            )
            if entry is not None:
                entries.append(entry)
        return entries

    # ------------------------------------------------------------------
    # Workstation + Profile Scoped AI Policy & Workspace Layouts
    # ------------------------------------------------------------------

    def load_ai_policy(
        self,
        *,
        workstation_id: str | None = None,
        profile_name: str | None = None,
    ) -> dict[str, Any] | None:
        """Load AI policy dict for ``(workstation_id, profile_name)`` or ``None``."""
        self._ensure_ready()
        ws = (workstation_id or self._config.workstation_id).strip() or "default-workstation"
        prof = (profile_name or self._config.profile_name).strip() or "default"
        with self.session() as sess:
            row = sess.execute(
                select(ai_policies_table.c.policy_json).where(
                    and_(
                        ai_policies_table.c.workstation_id == ws,
                        ai_policies_table.c.profile_name == prof,
                    )
                )
            ).first()
        if row is None or not row[0]:
            return None
        try:
            loaded = json.loads(row[0])
            return dict(loaded) if isinstance(loaded, Mapping) else None
        except ValueError:
            return None

    def save_ai_policy(
        self,
        policy_dict: Mapping[str, Any],
        *,
        workstation_id: str | None = None,
        profile_name: str | None = None,
    ) -> None:
        """Persist AI policy dict scoped to ``(workstation_id, profile_name)``."""
        self._ensure_ready()
        ws = (workstation_id or self._config.workstation_id).strip() or "default-workstation"
        prof = (profile_name or self._config.profile_name).strip() or "default"
        redacted_raw = redact_sensitive_data(dict(policy_dict))
        clean = dict(redacted_raw) if isinstance(redacted_raw, Mapping) else {}
        policy_json = _json_dumps_safe(clean)
        now = time.time()

        with self._lock:
            with self.session() as sess:
                existing = sess.execute(
                    select(ai_policies_table.c.id).where(
                        and_(
                            ai_policies_table.c.workstation_id == ws,
                            ai_policies_table.c.profile_name == prof,
                        )
                    )
                ).first()
                if existing is None:
                    sess.execute(
                        insert(ai_policies_table).values(
                            workstation_id=ws,
                            profile_name=prof,
                            policy_json=policy_json,
                            updated_at=now,
                        )
                    )
                else:
                    sess.execute(
                        update(ai_policies_table)
                        .where(ai_policies_table.c.id == existing[0])
                        .values(policy_json=policy_json, updated_at=now)
                    )

    def save_workspace_layout(
        self,
        *,
        mode: str = "tabbed",
        state: Mapping[str, Any] | None = None,
        workstation_id: str | None = None,
        profile_name: str | None = None,
    ) -> dict[str, Any]:
        """Persist TUI/Web BSP workspace mode & layout scoped to ``(workstation_id, profile_name)``."""
        self._ensure_ready()
        ws = (workstation_id or self._config.workstation_id).strip() or "default-workstation"
        prof = (profile_name or self._config.profile_name).strip() or "default"
        clean_mode = "tiling" if str(mode or "").strip().lower() == "tiling" else "tabbed"
        redacted_state_raw = redact_sensitive_data(dict(state) if state else {})
        clean_state: dict[str, Any] = (
            dict(redacted_state_raw) if isinstance(redacted_state_raw, Mapping) else {}
        )
        state_json = _json_dumps_safe(clean_state)
        now = time.time()

        with self._lock:
            with self.session() as sess:
                existing = sess.execute(
                    select(workspace_layouts_table.c.id).where(
                        and_(
                            workspace_layouts_table.c.workstation_id == ws,
                            workspace_layouts_table.c.profile_name == prof,
                        )
                    )
                ).first()
                if existing is None:
                    sess.execute(
                        insert(workspace_layouts_table).values(
                            workstation_id=ws,
                            profile_name=prof,
                            mode=clean_mode,
                            state_json=state_json,
                            updated_at=now,
                        )
                    )
                else:
                    sess.execute(
                        update(workspace_layouts_table)
                        .where(workspace_layouts_table.c.id == existing[0])
                        .values(mode=clean_mode, state_json=state_json, updated_at=now)
                    )
        return {
            "mode": clean_mode,
            "state": clean_state,
            "workstation_id": ws,
            "profile_name": prof,
            "updated_at": now,
        }

    def load_workspace_layout(
        self,
        *,
        workstation_id: str | None = None,
        profile_name: str | None = None,
    ) -> dict[str, Any]:
        """Load workspace mode & layout scoped to ``(workstation_id, profile_name)``."""
        self._ensure_ready()
        ws = (workstation_id or self._config.workstation_id).strip() or "default-workstation"
        prof = (profile_name or self._config.profile_name).strip() or "default"
        with self.session() as sess:
            row = sess.execute(
                select(workspace_layouts_table).where(
                    and_(
                        workspace_layouts_table.c.workstation_id == ws,
                        workspace_layouts_table.c.profile_name == prof,
                    )
                )
            ).mappings().first()
        if row is None:
            return {
                "mode": "tabbed",
                "state": {},
                "workstation_id": ws,
                "profile_name": prof,
                "updated_at": 0.0,
            }
        try:
            state = json.loads(row["state_json"] or "{}")
        except ValueError:
            state = {}
        return {
            "mode": "tiling" if str(row["mode"]).strip().lower() == "tiling" else "tabbed",
            "state": state if isinstance(state, dict) else {},
            "workstation_id": ws,
            "profile_name": prof,
            "updated_at": float(row["updated_at"]),
        }

    # ------------------------------------------------------------------
    # Global SOC Learnings Repository (M2/M3 Compatible)
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_learning_dict(row: Mapping[Any, Any]) -> dict[str, Any]:
        try:
            tags = json.loads(row.get("tags_json") or "[]")
        except ValueError:
            tags = []
        return {
            "id": row["id"],
            "fingerprint": row["fingerprint"],
            "category": row["category"],
            "title": row["title"],
            "content": row["content"],
            "source": row["source"],
            "status": row["status"],
            "confidence": float(row["confidence"]),
            "seen_count": int(row["seen_count"]),
            "use_count": int(row["use_count"]),
            "pinned": bool(row["pinned"]),
            "tags": [str(t) for t in tags] if isinstance(tags, list) else [],
            "created_by": row["created_by"],
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    def upsert_learning(
        self,
        *,
        entry_id: str | None = None,
        fingerprint: str | None = None,
        category: str = "environment_fact",
        title: str = "",
        content: str = "",
        source: str = "manual_learn",
        status: str = "active",
        confidence: float = 1.0,
        seen_count: int = 1,
        use_count: int = 0,
        pinned: bool = False,
        tags: Sequence[str] | None = None,
        created_by: str = "",
        created_at: float | None = None,
        updated_at: float | None = None,
        dedupe_by_fingerprint: bool = False,
    ) -> dict[str, Any]:
        """Insert or update a SOC learning entry (globally shared, redacted)."""
        self._ensure_ready()
        now = time.time()
        clean_title = str(
            redact_sensitive_data(title or "", preserve_env_var_refs=True)
        ).strip()
        clean_content = str(
            redact_sensitive_data(content or "", preserve_env_var_refs=True)
        ).strip()
        clean_tags_raw = redact_sensitive_data(
            list(tags) if tags else [],
            preserve_env_var_refs=True,
        )
        clean_tags = (
            [str(t).strip() for t in clean_tags_raw if str(t).strip()]
            if isinstance(clean_tags_raw, list)
            else []
        )
        tags_text = " ".join(clean_tags)
        explicit_eid = (entry_id or "").strip()
        fp = (fingerprint or "").strip() or hashlib.sha256(
            f"{category}:{clean_title.lower()}:{clean_content.lower()}".encode()
        ).hexdigest()[:32]
        c_at = float(created_at) if created_at is not None else now
        u_at = float(updated_at) if updated_at is not None else now

        with self._lock:
            with self.session() as sess:
                existing = None
                eid = explicit_eid
                if eid:
                    existing = sess.execute(
                        select(soc_learnings_table).where(soc_learnings_table.c.id == eid)
                    ).mappings().first()
                elif dedupe_by_fingerprint:
                    existing = sess.execute(
                        select(soc_learnings_table).where(
                            soc_learnings_table.c.fingerprint == fp[:256]
                        )
                    ).mappings().first()
                    if existing is not None:
                        eid = str(existing["id"])
                if not eid:
                    eid = uuid.uuid4().hex[:16]
                values = {
                    "fingerprint": fp[:256],
                    "category": str(category or "environment_fact")[:64],
                    "title": clean_title,
                    "content": clean_content,
                    "source": str(source or "manual_learn")[:64],
                    "status": str(status or "active")[:32],
                    "confidence": float(confidence),
                    "seen_count": max(1, int(seen_count)),
                    "use_count": max(0, int(use_count)),
                    "pinned": bool(pinned),
                    "tags_json": _json_dumps_safe(clean_tags),
                    "tags_text": tags_text,
                    "created_by": str(redact_sensitive_data(created_by or self._config.analyst_id))[:128],
                    "updated_at": u_at,
                }
                if existing is None:
                    sess.execute(
                        insert(soc_learnings_table).values(
                            id=eid,
                            created_at=c_at,
                            **values,
                        )
                    )
                else:
                    sess.execute(
                        update(soc_learnings_table)
                        .where(soc_learnings_table.c.id == eid)
                        .values(**values)
                    )

                if self._dialect == "sqlite":
                    sess.execute(
                        text("DELETE FROM soc_learnings_fts WHERE learning_id = :lid"),
                        {"lid": eid},
                    )
                    sess.execute(
                        text(
                            "INSERT INTO soc_learnings_fts (learning_id, title, content, tags_text) "
                            "VALUES (:lid, :title, :content, :tags)"
                        ),
                        {
                            "lid": eid,
                            "title": clean_title,
                            "content": clean_content,
                            "tags": tags_text,
                        },
                    )
                saved = sess.execute(
                    select(soc_learnings_table).where(soc_learnings_table.c.id == eid)
                ).mappings().one()
        return self._row_to_learning_dict(saved)

    def get_learning(self, learning_id: str) -> dict[str, Any] | None:
        clean_id = str(learning_id or "").strip()
        if not clean_id:
            return None
        self._ensure_ready()
        with self.session() as sess:
            row = sess.execute(
                select(soc_learnings_table).where(soc_learnings_table.c.id == clean_id)
            ).mappings().first()
        return self._row_to_learning_dict(row) if row is not None else None

    def get_learning_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        clean_fp = str(fingerprint or "").strip()
        if not clean_fp:
            return None
        self._ensure_ready()
        with self.session() as sess:
            row = sess.execute(
                select(soc_learnings_table).where(soc_learnings_table.c.fingerprint == clean_fp)
            ).mappings().first()
        return self._row_to_learning_dict(row) if row is not None else None

    def list_learnings(
        self,
        *,
        status: str | None = None,
        category: str | None = None,
        source: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        self._ensure_ready()
        stmt = select(soc_learnings_table)
        if status is not None:
            stmt = stmt.where(soc_learnings_table.c.status == str(status).strip())
        if category is not None:
            stmt = stmt.where(soc_learnings_table.c.category == str(category).strip())
        if source is not None:
            stmt = stmt.where(soc_learnings_table.c.source == str(source).strip())
        stmt = stmt.order_by(
            soc_learnings_table.c.pinned.desc(),
            soc_learnings_table.c.confidence.desc(),
            soc_learnings_table.c.updated_at.desc(),
        ).limit(int(limit))
        with self.session() as sess:
            rows = sess.execute(stmt).mappings().all()
        return [self._row_to_learning_dict(r) for r in rows]

    def search_learnings(
        self,
        query: str,
        *,
        status: str | None = "active",
        category: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Dialect-aware FTS/keyword search over global SOC learnings."""
        clean_q = (query or "").strip()
        if not clean_q:
            return []
        eff_limit = max(1, min(int(limit), 200))
        clean_status = str(status).strip() if status is not None and str(status).strip() else None
        clean_cat = str(category).strip() if category is not None and str(category).strip() else None
        self._ensure_ready()

        rows: list[RowMapping] = []
        with self.session() as sess:
            if self._dialect == "sqlite":
                tokens = _FTS_TOKEN_RE.findall(clean_q)
                if tokens:
                    fts_expr = " AND ".join(f'"{tok}"' for tok in tokens[:8])
                    sql_str = (
                        "SELECT l.* FROM soc_learnings l "
                        "JOIN soc_learnings_fts f ON f.learning_id = l.id "
                        "WHERE soc_learnings_fts MATCH :fts_q "
                    )
                    params: dict[str, Any] = {"fts_q": fts_expr, "lim": eff_limit}
                    if clean_status is not None:
                        sql_str += "AND l.status = :st "
                        params["st"] = clean_status
                    if clean_cat is not None:
                        sql_str += "AND l.category = :cat "
                        params["cat"] = clean_cat
                    sql_str += "ORDER BY l.pinned DESC, l.confidence DESC, l.updated_at DESC LIMIT :lim"
                    try:
                        rows = list(sess.execute(text(sql_str), params).mappings().all())
                    except SQLAlchemyError:
                        rows = []
                if not rows:
                    like_pat = f"%{_escape_like_pattern(clean_q)}%"
                    stmt = select(soc_learnings_table).where(
                        or_(
                            soc_learnings_table.c.title.like(like_pat, escape="|"),
                            soc_learnings_table.c.content.like(like_pat, escape="|"),
                            soc_learnings_table.c.tags_text.like(like_pat, escape="|"),
                        )
                    )
                    if clean_status is not None:
                        stmt = stmt.where(soc_learnings_table.c.status == clean_status)
                    if clean_cat is not None:
                        stmt = stmt.where(soc_learnings_table.c.category == clean_cat)
                    stmt = stmt.order_by(
                        soc_learnings_table.c.pinned.desc(),
                        soc_learnings_table.c.confidence.desc(),
                        soc_learnings_table.c.updated_at.desc(),
                    ).limit(eff_limit)
                    rows = list(sess.execute(stmt).mappings().all())

            elif self._dialect == "postgres":
                like_pat = f"%{_escape_like_pattern(clean_q)}%"
                sql_pg = (
                    "SELECT * FROM soc_learnings "
                    "WHERE (to_tsvector('english', coalesce(title, '') || ' ' || coalesce(content, '') || ' ' || coalesce(tags_text, '')) "
                    "@@ plainto_tsquery('english', :q) "
                    "OR title ILIKE :like_pat ESCAPE '|' "
                    "OR content ILIKE :like_pat ESCAPE '|' "
                    "OR tags_text ILIKE :like_pat ESCAPE '|') "
                )
                params_pg: dict[str, Any] = {"q": clean_q, "like_pat": like_pat, "lim": eff_limit}
                if clean_status is not None:
                    sql_pg += "AND status = :st "
                    params_pg["st"] = clean_status
                if clean_cat is not None:
                    sql_pg += "AND category = :cat "
                    params_pg["cat"] = clean_cat
                sql_pg += "ORDER BY pinned DESC, confidence DESC, updated_at DESC LIMIT :lim"
                rows = list(sess.execute(text(sql_pg), params_pg).mappings().all())

            elif self._dialect == "mysql":
                like_pat = f"%{_escape_like_pattern(clean_q)}%"
                bool_tokens = _MYSQL_BOOL_TOKEN_RE.findall(clean_q)
                if bool_tokens:
                    bool_q = " ".join(f"+{tok}*" for tok in bool_tokens[:8])
                    sql_mysql = (
                        "SELECT * FROM soc_learnings "
                        "WHERE (MATCH(title, content) AGAINST (:mq IN BOOLEAN MODE) "
                        "OR title LIKE :like_pat ESCAPE '|' "
                        "OR content LIKE :like_pat ESCAPE '|' "
                        "OR tags_text LIKE :like_pat ESCAPE '|') "
                    )
                    params_mysql: dict[str, Any] = {"mq": bool_q, "like_pat": like_pat, "lim": eff_limit}
                else:
                    sql_mysql = (
                        "SELECT * FROM soc_learnings "
                        "WHERE (title LIKE :like_pat ESCAPE '|' "
                        "OR content LIKE :like_pat ESCAPE '|' "
                        "OR tags_text LIKE :like_pat ESCAPE '|') "
                    )
                    params_mysql = {"like_pat": like_pat, "lim": eff_limit}
                if clean_status is not None:
                    sql_mysql += "AND status = :st "
                    params_mysql["st"] = clean_status
                if clean_cat is not None:
                    sql_mysql += "AND category = :cat "
                    params_mysql["cat"] = clean_cat
                sql_mysql += "ORDER BY pinned DESC, confidence DESC, updated_at DESC LIMIT :lim"
                rows = list(sess.execute(text(sql_mysql), params_mysql).mappings().all())

            else:
                like_pat = f"%{_escape_like_pattern(clean_q)}%"
                stmt = select(soc_learnings_table).where(
                    or_(
                        soc_learnings_table.c.title.like(like_pat, escape="|"),
                        soc_learnings_table.c.content.like(like_pat, escape="|"),
                        soc_learnings_table.c.tags_text.like(like_pat, escape="|"),
                    )
                )
                if clean_status is not None:
                    stmt = stmt.where(soc_learnings_table.c.status == clean_status)
                if clean_cat is not None:
                    stmt = stmt.where(soc_learnings_table.c.category == clean_cat)
                stmt = stmt.order_by(
                    soc_learnings_table.c.pinned.desc(),
                    soc_learnings_table.c.confidence.desc(),
                    soc_learnings_table.c.updated_at.desc(),
                ).limit(eff_limit)
                rows = list(sess.execute(stmt).mappings().all())

        return [self._row_to_learning_dict(r) for r in rows]

    def increment_learning_use(self, learning_id: str, delta: int = 1) -> bool:
        """Increment ``use_count`` on a SOC learning entry without altering its content."""
        clean_id = str(learning_id or "").strip()
        step = max(1, int(delta))
        if not clean_id:
            return False
        self._ensure_ready()
        with self._lock:
            with self.session() as sess:
                res = cast(
                    CursorResult[Any],
                    sess.execute(
                        update(soc_learnings_table)
                        .where(soc_learnings_table.c.id == clean_id)
                        .values(use_count=soc_learnings_table.c.use_count + step)
                    ),
                )
                return bool(res.rowcount and res.rowcount > 0)

    def delete_learning(self, learning_id: str) -> bool:
        clean_id = str(learning_id or "").strip()
        if not clean_id:
            return False
        self._ensure_ready()
        with self._lock:
            with self.session() as sess:
                res = cast(
                    CursorResult[Any],
                    sess.execute(
                        delete(soc_learnings_table).where(soc_learnings_table.c.id == clean_id)
                    ),
                )
                if self._dialect == "sqlite":
                    sess.execute(
                        text("DELETE FROM soc_learnings_fts WHERE learning_id = :lid"),
                        {"lid": clean_id},
                    )
                return bool(res.rowcount and res.rowcount > 0)

    def record_learning_revision(
        self,
        *,
        learning_id: str,
        action: str,
        actor: str = "",
        previous_content: str = "",
        new_content: str = "",
        previous_status: str = "",
        new_status: str = "",
        snapshot: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append an immutable revision entry for learning rollback & auditability."""
        self._ensure_ready()
        clean_id = str(learning_id or "").strip()
        now = time.time()
        redacted_snap_raw = redact_sensitive_data(
            dict(snapshot) if snapshot else {},
            preserve_env_var_refs=True,
        )
        redacted_snap = dict(redacted_snap_raw) if isinstance(redacted_snap_raw, Mapping) else {}
        with self._lock:
            with self.session() as sess:
                prev_rev = sess.execute(
                    select(soc_learning_revisions_table.c.revision_no)
                    .where(soc_learning_revisions_table.c.learning_id == clean_id)
                    .order_by(soc_learning_revisions_table.c.revision_no.desc())
                    .limit(1)
                ).first()
                next_rev = int(prev_rev[0]) + 1 if prev_rev is not None else 1
                sess.execute(
                    insert(soc_learning_revisions_table).values(
                        learning_id=clean_id,
                        revision_no=next_rev,
                        action=str(action or "edit")[:64],
                        actor=str(redact_sensitive_data(actor or self._config.analyst_id))[:128],
                        previous_content=str(
                            redact_sensitive_data(previous_content or "", preserve_env_var_refs=True)
                        ),
                        new_content=str(
                            redact_sensitive_data(new_content or "", preserve_env_var_refs=True)
                        ),
                        previous_status=str(previous_status or "")[:32],
                        new_status=str(new_status or "")[:32],
                        snapshot_json=_json_dumps_safe(redacted_snap),
                        created_at=now,
                    )
                )
        return {
            "learning_id": clean_id,
            "revision_no": next_rev,
            "action": action,
            "created_at": now,
        }

    def get_learning_revisions(self, learning_id: str) -> list[dict[str, Any]]:
        clean_id = str(learning_id or "").strip()
        if not clean_id:
            return []
        self._ensure_ready()
        with self.session() as sess:
            rows = sess.execute(
                select(soc_learning_revisions_table)
                .where(soc_learning_revisions_table.c.learning_id == clean_id)
                .order_by(soc_learning_revisions_table.c.revision_no.desc())
            ).mappings().all()
        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                snap = json.loads(row.get("snapshot_json") or "{}")
            except ValueError:
                snap = {}
            out.append(
                {
                    "learning_id": row["learning_id"],
                    "revision_no": int(row["revision_no"]),
                    "action": row["action"],
                    "actor": row["actor"],
                    "previous_content": row["previous_content"],
                    "new_content": row["new_content"],
                    "previous_status": row["previous_status"],
                    "new_status": row["new_status"],
                    "snapshot": snap if isinstance(snap, dict) else {},
                    "created_at": float(row["created_at"]),
                }
            )
        return out

    # ------------------------------------------------------------------
    # Idempotent Legacy File Migration & Rolling Retention Pruning
    # ------------------------------------------------------------------

    def migrate_legacy_files(self, cache_dir: Path | str) -> dict[str, int]:
        """Idempotently import ``alerts/*.json``, ``event_ai_panels.json``, ``ai_policy.json``, ``ai_audit.jsonl``."""
        self._ensure_ready()
        root = Path(cache_dir).expanduser()
        counts: dict[str, int] = {
            "alerts_sources": 0,
            "alert_items": 0,
            "events": 0,
            "panels": 0,
            "policies": 0,
            "audits": 0,
        }
        if not root.exists():
            return counts

        alerts_dir = root if root.name == "alerts" else (root / "alerts")
        if alerts_dir.is_dir():
            for json_path in sorted(alerts_dir.glob("*.json")):
                if json_path.name == "unavailable_images.json":
                    continue
                try:
                    raw_text = json_path.read_text(encoding="utf-8", errors="replace").strip()
                    if not raw_text:
                        continue
                    parsed = json.loads(raw_text)
                except Exception as exc:
                    logger.debug("Skipping unreadable legacy alert cache %s: %s", json_path, exc)
                    continue
                if not isinstance(parsed, Mapping):
                    continue
                raw_items = parsed.get("items")
                if not isinstance(raw_items, list):
                    continue
                source_name = str(parsed.get("source") or json_path.stem).strip() or json_path.stem
                timeframe = str(parsed.get("timeframe") or "last_24h").strip() or "last_24h"
                meta = parsed.get("meta")
                try:
                    fetched_at = float(parsed.get("fetched_at") or json_path.stat().st_mtime)
                except (TypeError, ValueError, OSError):
                    fetched_at = time.time()
                valid_items = [it for it in raw_items if isinstance(it, Mapping)]
                if self.get_alerts_snapshot(source_name) is None:
                    self.upsert_alerts_snapshot(
                        source_name,
                        valid_items,
                        timeframe=timeframe,
                        meta=meta if isinstance(meta, Mapping) else None,
                        fetched_at=fetched_at,
                    )
                    counts["alerts_sources"] += 1
                    counts["alert_items"] += len(valid_items)

        panels_path = root / "event_ai_panels.json"
        if panels_path.is_file():
            try:
                raw_text = panels_path.read_text(encoding="utf-8", errors="replace").strip()
                parsed_panels = json.loads(raw_text) if raw_text else None
            except Exception as exc:
                logger.debug("Skipping corrupt legacy event_ai_panels.json %s: %s", panels_path, exc)
                parsed_panels = None
            if isinstance(parsed_panels, Mapping):
                events_raw = parsed_panels.get("events")
                if isinstance(events_raw, Mapping):
                    for map_key, rec in events_raw.items():
                        if not isinstance(rec, Mapping):
                            continue
                        ev_candidate = rec.get("event")
                        ev_raw: Mapping[str, Any] = (
                            ev_candidate if isinstance(ev_candidate, Mapping) else rec
                        )
                        ev_dict = dict(ev_raw)
                        ev_key = str(ev_dict.get("event_key") or map_key or "").strip()
                        if not ev_key:
                            continue
                        ev_dict["event_key"] = ev_key
                        if self.get_unique_event(ev_key) is None:
                            if self.upsert_unique_event(ev_dict):
                                counts["events"] += 1
                        panels_raw = rec.get("panels")
                        if isinstance(panels_raw, list):
                            existing_ids = {
                                str(p.get("entry_id") or "")
                                for p in self.get_event_panels(ev_key)
                            }
                            for p_raw in panels_raw:
                                if not isinstance(p_raw, Mapping):
                                    continue
                                pid = str(p_raw.get("entry_id") or "").strip()
                                if pid and pid in existing_ids:
                                    continue
                                self.add_event_panel(ev_key, p_raw)
                                if pid:
                                    existing_ids.add(pid)
                                counts["panels"] += 1

        policy_path = root / "ai_policy.json"
        if policy_path.is_file():
            try:
                raw_text = policy_path.read_text(encoding="utf-8", errors="replace").strip()
                parsed_policy = json.loads(raw_text) if raw_text else None
            except Exception as exc:
                logger.debug("Skipping corrupt legacy ai_policy.json %s: %s", policy_path, exc)
                parsed_policy = None
            if isinstance(parsed_policy, Mapping) and self.load_ai_policy() is None:
                from soclens.agent_policy import AIPolicyConfig

                normalized_pol = AIPolicyConfig.from_dict(parsed_policy)
                self.save_ai_policy(normalized_pol.to_dict())
                counts["policies"] += 1

        audit_path = root / "ai_audit.jsonl"
        if audit_path.is_file():
            try:
                lines = audit_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as exc:
                logger.debug("Skipping unreadable legacy ai_audit.jsonl %s: %s", audit_path, exc)
                lines = []
            parsed_entries: list[AuditEntry] = []
            seen_file_ids: set[str] = set()
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    raw_obj = json.loads(stripped)
                except ValueError:
                    continue
                if not isinstance(raw_obj, Mapping):
                    continue
                entry = AuditEntry.from_dict(raw_obj)
                if entry is None:
                    continue
                eid = entry.entry_id.strip() if isinstance(entry.entry_id, str) else ""
                if not eid:
                    eid = uuid.uuid4().hex[:16]
                if eid in seen_file_ids:
                    continue
                seen_file_ids.add(eid)
                parsed_entries.append(
                    AuditEntry(
                        entry_id=eid,
                        timestamp=entry.timestamp,
                        run_id=entry.run_id,
                        event_key=entry.event_key,
                        provider=entry.provider,
                        mode=entry.mode,
                        event_type=entry.event_type,
                        tool_name=entry.tool_name,
                        allowed=entry.allowed,
                        reason=entry.reason,
                        payload=entry.payload,
                        analyst_id=entry.analyst_id,
                        workstation_id=entry.workstation_id,
                    )
                )
            if parsed_entries:
                with self._lock:
                    with self.session() as sess:
                        existing_audit_ids = {
                            str(r[0])
                            for r in sess.execute(select(audit_logs_table.c.entry_id)).all()
                        }
                        audit_rows: list[dict[str, Any]] = []
                        for entry in parsed_entries:
                            if entry.entry_id in existing_audit_ids:
                                continue
                            existing_audit_ids.add(entry.entry_id)
                            ts_str = (
                                entry.timestamp.strip()
                                if isinstance(entry.timestamp, str)
                                else ""
                            )
                            if not ts_str:
                                ts_str = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                            created_at = _parse_timestamp_epoch(ts_str, fallback=time.time())
                            raw_payload = (
                                dict(entry.payload)
                                if isinstance(entry.payload, Mapping)
                                else {}
                            )
                            redacted_payload_obj = redact_sensitive_data(raw_payload)
                            redacted_payload: dict[str, Any] = (
                                dict(redacted_payload_obj)
                                if isinstance(redacted_payload_obj, Mapping)
                                else {}
                            )
                            analyst_id = (
                                getattr(entry, "analyst_id", "") or ""
                            ).strip() or self._config.analyst_id
                            workstation_id = (
                                getattr(entry, "workstation_id", "") or ""
                            ).strip() or self._config.workstation_id
                            audit_rows.append(
                                {
                                    "entry_id": entry.entry_id,
                                    "timestamp": ts_str,
                                    "created_at": created_at,
                                    "run_id": str(entry.run_id or "")[:128],
                                    "event_key": str(
                                        redact_sensitive_data(entry.event_key or "")
                                    )[:512],
                                    "provider": str(
                                        redact_sensitive_data(entry.provider or "")
                                    )[:64],
                                    "mode": str(entry.mode or "")[:64],
                                    "event_type": entry.event_type[:64],
                                    "tool_name": str(
                                        redact_sensitive_data(entry.tool_name or "")
                                    )[:128],
                                    "allowed": entry.allowed,
                                    "reason": str(redact_sensitive_data(entry.reason or "")),
                                    "payload_json": _json_dumps_safe(redacted_payload),
                                    "analyst_id": str(redact_sensitive_data(analyst_id))[:128],
                                    "workstation_id": str(
                                        redact_sensitive_data(workstation_id)
                                    )[:128],
                                }
                            )
                        if audit_rows:
                            sess.execute(insert(audit_logs_table), audit_rows)
                            counts["audits"] += len(audit_rows)

        return counts

    def prune_expired(self, *, retention_days: int | None = None) -> dict[str, int]:
        """Prune historical alerts, IOC sightings, panels, and audit logs older than ``retention_days``.

        Never deletes ``soc_learnings`` with ``source == "base_seed"`` or ``pinned == True``.
        """
        eff_days = self._config.retention_days if retention_days is None else int(retention_days)
        if eff_days <= 0:
            return {
                "alerts_history": 0,
                "ioc_sightings": 0,
                "event_ai_panels": 0,
                "unique_events": 0,
                "audit_logs": 0,
            }
        self._ensure_ready()
        cutoff = time.time() - (eff_days * 86400.0)
        deleted_counts: dict[str, int] = {}

        with self._lock:
            with self.session() as sess:
                if self._dialect == "sqlite":
                    expired_alert_ids = [
                        int(r[0])
                        for r in sess.execute(
                            select(alerts_history_table.c.id).where(
                                alerts_history_table.c.fetched_at < cutoff
                            )
                        ).all()
                    ]
                    if expired_alert_ids:
                        for rid in expired_alert_ids:
                            sess.execute(
                                text("DELETE FROM alerts_history_fts WHERE alert_row_id = :rid"),
                                {"rid": rid},
                            )
                res_alerts = cast(
                    CursorResult[Any],
                    sess.execute(
                        delete(alerts_history_table).where(alerts_history_table.c.fetched_at < cutoff)
                    ),
                )
                deleted_counts["alerts_history"] = int(res_alerts.rowcount or 0)

                res_iocs = cast(
                    CursorResult[Any],
                    sess.execute(
                        delete(ioc_sightings_table).where(ioc_sightings_table.c.last_seen_at < cutoff)
                    ),
                )
                deleted_counts["ioc_sightings"] = int(res_iocs.rowcount or 0)

                res_panels = cast(
                    CursorResult[Any],
                    sess.execute(
                        delete(event_ai_panels_table).where(event_ai_panels_table.c.created_at < cutoff)
                    ),
                )
                deleted_counts["event_ai_panels"] = int(res_panels.rowcount or 0)

                remaining_panel_keys = select(event_ai_panels_table.c.event_key).distinct()
                res_events = cast(
                    CursorResult[Any],
                    sess.execute(
                        delete(unique_events_table).where(
                            and_(
                                unique_events_table.c.updated_at < cutoff,
                                ~unique_events_table.c.event_key.in_(remaining_panel_keys),
                            )
                        )
                    ),
                )
                deleted_counts["unique_events"] = int(res_events.rowcount or 0)

                res_audits = cast(
                    CursorResult[Any],
                    sess.execute(
                        delete(audit_logs_table).where(audit_logs_table.c.created_at < cutoff)
                    ),
                )
                deleted_counts["audit_logs"] = int(res_audits.rowcount or 0)

        return deleted_counts


class SOCLearningStore:
    """Global storage-backed repository wrapper for SOC learnings and revisions."""

    def __init__(self, storage: StorageManager) -> None:
        self._storage = storage

    @property
    def storage(self) -> StorageManager:
        return self._storage

    def upsert(self, **kwargs: Any) -> dict[str, Any]:
        return self._storage.upsert_learning(**kwargs)

    def get(self, learning_id: str) -> dict[str, Any] | None:
        return self._storage.get_learning(learning_id)

    def get_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        return self._storage.get_learning_by_fingerprint(fingerprint)

    def list(
        self,
        *,
        status: str | None = None,
        category: str | None = None,
        source: str | None = None,
        limit: int = 200,
    ) -> _PyList[dict[str, Any]]:
        return self._storage.list_learnings(
            status=status,
            category=category,
            source=source,
            limit=limit,
        )

    def search(
        self,
        query: str,
        *,
        status: str | None = "active",
        category: str | None = None,
        limit: int = 10,
    ) -> _PyList[dict[str, Any]]:
        return self._storage.search_learnings(
            query,
            status=status,
            category=category,
            limit=limit,
        )

    def delete(self, learning_id: str) -> bool:
        return self._storage.delete_learning(learning_id)

    def increment_use(self, learning_id: str, delta: int = 1) -> bool:
        return self._storage.increment_learning_use(learning_id, delta=delta)

    def record_revision(self, **kwargs: Any) -> dict[str, Any]:
        return self._storage.record_learning_revision(**kwargs)

    def get_revisions(self, learning_id: str) -> _PyList[dict[str, Any]]:
        return self._storage.get_learning_revisions(learning_id)


__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "METADATA",
    "SCHEMA_VERSION",
    "SOCLearningStore",
    "SUPPORTED_DB_BACKENDS",
    "StorageManager",
    "DatabaseConfig",
    "test_db_connection",
]
