"""Offline mock harnesses, workspace seeders, and ASGI/TUI helpers for 4-pillar E2E tests."""

from __future__ import annotations

import asyncio
import codecs
import json
import os
import queue
import re
import shutil
import struct
import subprocess
import sys
import threading
import types
import urllib.parse
import weakref
import webbrowser
import zlib
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import tests.e2e.agentic_mocks as _agentic_mocks
import tests.e2e.conftest as _e2e_conftest
from soclens.settings import clear_session_overrides, invalidate_settings_cache
from tests.e2e.agentic_mocks import (
    MockAgenticLLMAndCopilotServer,
    MockOSINTServer,
    assert_zero_mutating_http_requests,
    async_wait_until,
    build_correlated_soc_scenario,
    richlog_text,
    right_click_table_row,
    select_table_row_containing,
)

# Re-export upstream fixtures without modifying conftest.py, v21_mocks.py, or agentic_mocks.py.
v21_workspace = _agentic_mocks.v21_workspace
agentic_workspace = _agentic_mocks.agentic_workspace
mock_rf_server = _e2e_conftest.mock_rf_server
mock_splunk_es_server = _agentic_mocks.mock_splunk_es_server
mock_s1_server = _agentic_mocks.mock_s1_server
mock_agentic_llm_server = _agentic_mocks.mock_agentic_llm_server
mock_osint_server = _agentic_mocks.mock_osint_server
run_cli = _e2e_conftest.run_cli

__all__ = [
    "LauncherRecorder",
    "MockAgenticLLMAndCopilotServer",
    "MockDBAPIDriver",
    "MockDBConnection",
    "MockDBCursor",
    "MockOSINTServer",
    "MockPopenProcess",
    "activate_pane_for_test",
    "agentic_workspace",
    "assert_zero_mutating_http_requests",
    "async_wait_until",
    "build_correlated_soc_scenario",
    "create_web_test_client",
    "exchange_web_auth",
    "extract_llm_request_text",
    "get_workspace_host",
    "install_mock_db_drivers",
    "install_mock_launcher",
    "make_pillar_app",
    "make_sample_ca_cert_pem",
    "make_sample_png_bytes",
    "mock_agentic_llm_server",
    "mock_osint_server",
    "mock_rf_server",
    "mock_s1_server",
    "mock_splunk_es_server",
    "parse_sse_stream",
    "pillar_workspace",
    "press_tile_key",
    "richlog_text",
    "right_click_table_row",
    "run_cli",
    "seed_knowledge_files",
    "seed_legacy_cache_files",
    "select_table_row_containing",
    "v21_workspace",
]

_PILLAR_ENV_PREFIXES: tuple[str, ...] = (
    "SOCLENS_DB_",
    "SOCLENS_WEB_",
    "SOCLENS_LEARNING_",
)

_PILLAR_ENV_KEYS: frozenset[str] = frozenset(
    {
        "DATABASE_URL",
        "SOCLENS_AI_MAX_TOOL_STEPS",
        "SOCLENS_WORKSTATION_ID",
        "SOCLENS_PROFILE",
        "SOCLENS_ANALYST_ID",
    }
)


_TRACKED_WEB_APPS: list[weakref.ref[Any]] = []


@pytest.fixture
def pillar_workspace(
    agentic_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """Extend ``agentic_workspace`` with 4-pillar env scrubbing and knowledge directories."""
    for key in list(os.environ):
        if key.startswith(_PILLAR_ENV_PREFIXES) or key in _PILLAR_ENV_KEYS:
            monkeypatch.delenv(key, raising=False)
    (agentic_workspace / ".soclens_cache" / "knowledge" / "playbooks").mkdir(
        parents=True,
        exist_ok=True,
    )
    clear_session_overrides()
    invalidate_settings_cache()
    try:
        yield agentic_workspace
    finally:
        while _TRACKED_WEB_APPS:
            app_ref = _TRACKED_WEB_APPS.pop()
            app_obj = app_ref()
            if app_obj is None:
                continue
            state = getattr(app_obj, "state", None)
            runtime = getattr(state, "runtime", None) if state is not None else None
            cleanup = getattr(runtime, "cleanup", None) if runtime is not None else None
            if callable(cleanup):
                cleanup()
        clear_session_overrides()
        invalidate_settings_cache()


# ==============================================================================
# Legacy Cache, PNG & Knowledge Seeders
# ==============================================================================


def make_sample_ca_cert_pem() -> str:
    """Generate a valid self-signed X.509 CA certificate PEM for TLS connection tests."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "soclens-mock-ca.internal.example")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def make_sample_png_bytes(width: int = 2, height: int = 2) -> bytes:
    """Return a valid minimal RGBA PNG byte payload for RF playbook screenshot tests."""

    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack("!I", len(data)) + tag + data + struct.pack("!I", crc)

    raw_rows = b"".join(b"\x00" + (b"\x2f\x81\xf7\xff" * width) for _ in range(height))
    ihdr = struct.pack("!IIBBBBB", width, height, 8, 6, 0, 0, 0)
    idat = zlib.compress(raw_rows)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def seed_legacy_cache_files(
    workspace_dir: Path,
    *,
    now_epoch: float | None = None,
    include_images: bool = True,
) -> dict[str, Any]:
    """Seed realistic legacy ``.soclens_cache/*.json`` and ``ai_audit.jsonl`` files."""
    base_time = float(now_epoch) if now_epoch is not None else datetime.now(UTC).timestamp()
    recent_dt = datetime.fromtimestamp(base_time, tz=UTC) - timedelta(minutes=15)
    recent_iso = recent_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    cache_root = workspace_dir / ".soclens_cache"
    alerts_dir = cache_root / "alerts"
    images_dir = alerts_dir / "images"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    if include_images:
        images_dir.mkdir(parents=True, exist_ok=True)

    rf_alert_id = "rf-alert-1001"
    rf_playbook_id = "rf-pb-2001"
    es_finding_id = "es-notable-3001"
    s1_threat_id = "s1-threat-4001"
    sample_ip = "203.0.113.42"
    sample_cve = "CVE-2024-3094"
    sample_domain = "c2-beacon.soc-test.example"

    rf_alerts_payload = {
        "source": "rf_alerts_24h",
        "timeframe": "last_24h",
        "fetched_at": base_time - 60.0,
        "fetched_at_iso": recent_iso,
        "meta": {"seeded": True},
        "items": [
            {
                "id": rf_alert_id,
                "title": f"High Risk C2 Communication to {sample_ip}",
                "severity": "High",
                "status": "New",
                "triggered": recent_iso,
                "rule": {"name": "Suspicious Outbound C2"},
                "entities": [
                    {"name": sample_ip, "type": "IpAddress"},
                    {"name": sample_cve, "type": "Vulnerability"},
                ],
                "summary": f"Host srv-app-01.corp.example contacted {sample_ip} ({sample_domain}).",
            }
        ],
    }

    image_key = f"{rf_playbook_id}_screenshot_1"
    rf_playbook_payload = {
        "source": "rf_playbook_24h",
        "timeframe": "last_24h",
        "fetched_at": base_time - 45.0,
        "fetched_at_iso": recent_iso,
        "meta": {"seeded": True},
        "items": [
            {
                "playbook_alert_id": rf_playbook_id,
                "title": f"Domain Abuse Playbook Alert: {sample_domain}",
                "priority": "High",
                "status": "New",
                "created": recent_iso,
                "category": "domain_abuse",
                "panel_evidence_summary": {
                    "screenshot_keys": [image_key],
                    "domain": sample_domain,
                },
            }
        ],
    }

    es_notables_payload = {
        "source": "es_notables_24h",
        "timeframe": "last_24h",
        "fetched_at": base_time - 30.0,
        "fetched_at_iso": recent_iso,
        "meta": {"seeded": True},
        "items": [
            {
                "finding_id": es_finding_id,
                "event_id": es_finding_id,
                "rule_name": "Suspicious PowerShell Encoded Command",
                "urgency": "high",
                "status": "new",
                "src_ip": sample_ip,
                "dest": "wkstn-014.corp.example",
                "time": recent_iso,
            }
        ],
    }

    s1_threats_payload = {
        "source": "s1_threats_24h",
        "timeframe": "last_24h",
        "fetched_at": base_time - 15.0,
        "fetched_at_iso": recent_iso,
        "meta": {"seeded": True},
        "items": [
            {
                "id": s1_threat_id,
                "threatName": "Trojan.Generic.SOCLensTest",
                "confidenceLevel": "malicious",
                "incidentStatus": "unresolved",
                "createdAt": recent_iso,
                "computerName": "wkstn-014.corp.example",
                "siteName": "Prod-Workstations",
                "externalIp": sample_ip,
                "sha256": "a" * 64,
            }
        ],
    }

    (alerts_dir / "rf_alerts_24h.json").write_text(
        json.dumps(rf_alerts_payload, indent=2) + "\n", encoding="utf-8"
    )
    (alerts_dir / "rf_playbook_24h.json").write_text(
        json.dumps(rf_playbook_payload, indent=2) + "\n", encoding="utf-8"
    )
    (alerts_dir / "es_notables_24h.json").write_text(
        json.dumps(es_notables_payload, indent=2) + "\n", encoding="utf-8"
    )
    (alerts_dir / "s1_threats_24h.json").write_text(
        json.dumps(s1_threats_payload, indent=2) + "\n", encoding="utf-8"
    )

    image_path: Path | None = None
    if include_images:
        image_path = images_dir / f"{image_key}.bin"
        image_path.write_bytes(make_sample_png_bytes())
        (alerts_dir / "unavailable_images.json").write_text("[]\n", encoding="utf-8")

    event_key = f"splunk_es:default:{es_finding_id}"
    event_ai_payload = {
        "version": 1,
        "events": {
            event_key: {
                "event": {
                    "event_key": event_key,
                    "source_kind": "splunk_es",
                    "native_id": es_finding_id,
                    "scope": "default",
                    "title": "Suspicious PowerShell Encoded Command",
                    "severity": "high",
                    "status": "new",
                    "timestamp": recent_iso,
                    "summary": f"Observed traffic to {sample_ip} and {sample_cve}",
                    "metadata": {"src_ip": sample_ip, "cve": sample_cve},
                },
                "panels": [
                    {
                        "entry_id": "panel-seed-001",
                        "run_id": "run-seed-001",
                        "timestamp": recent_iso,
                        "mode": "full_investigation",
                        "provider": "ollama",
                        "model": "qwen2.5:14b",
                        "question": "Triage this notable finding.",
                        "answer_markdown": f"Legacy panel confirmed {sample_ip} sighting.",
                        "tool_calls": [{"name": "rf_lookup_ioc_or_cve", "ok": True}],
                        "blocked_actions": [],
                        "status": "completed",
                        "auto_triggered": False,
                        "error": "",
                    }
                ],
            }
        },
    }
    (cache_root / "event_ai_panels.json").write_text(
        json.dumps(event_ai_payload, indent=2) + "\n", encoding="utf-8"
    )

    ai_policy_payload = {
        "background_triage_enabled": False,
        "cross_search_enabled": True,
        "splunk_search_enabled": True,
        "splunk_es_enabled": True,
        "sentinelone_enabled": True,
        "recorded_future_enabled": True,
        "watchlists_osint_enabled": True,
        "disabled_tools": ["osint_enrich_target"],
        "max_tool_steps": 30,
        "max_identical_tool_calls": 2,
        "max_same_tool_failures": 5,
        "ai_kill_switch_active": False,
    }
    (cache_root / "ai_policy.json").write_text(
        json.dumps(ai_policy_payload, indent=2) + "\n", encoding="utf-8"
    )

    audit_lines = [
        json.dumps(
            {
                "entry_id": "audit-seed-001",
                "timestamp": recent_iso,
                "run_id": "run-seed-001",
                "event_key": event_key,
                "provider": "ollama",
                "mode": "full_investigation",
                "event_type": "decision",
                "tool_name": "",
                "allowed": True,
                "reason": "Legacy audit entry migrated cleanly.",
                "payload": {"ip": sample_ip},
            }
        )
    ]
    (cache_root / "ai_audit.jsonl").write_text("\n".join(audit_lines) + "\n", encoding="utf-8")

    return {
        "cache_dir": cache_root,
        "alerts_dir": alerts_dir,
        "image_key": image_key,
        "image_path": image_path,
        "rf_alert_id": rf_alert_id,
        "rf_playbook_id": rf_playbook_id,
        "es_finding_id": es_finding_id,
        "s1_threat_id": s1_threat_id,
        "event_key": event_key,
        "sample_ip": sample_ip,
        "sample_cve": sample_cve,
        "sample_domain": sample_domain,
    }


def seed_knowledge_files(
    workspace_dir: Path,
    *,
    base_markdown: str | None = None,
    playbooks: Mapping[str, str] | None = None,
    with_bom: bool = False,
) -> dict[str, Any]:
    """Seed ``.soclens_cache/knowledge/BASE_ENVIRONMENT.md`` and ``playbooks/*.md``."""
    knowledge_dir = workspace_dir / ".soclens_cache" / "knowledge"
    playbooks_dir = knowledge_dir / "playbooks"
    playbooks_dir.mkdir(parents=True, exist_ok=True)

    encoding = "utf-8-sig" if with_bom else "utf-8"
    base_text = base_markdown or (
        "# Organization Base Environment\n\n"
        "- Internal CIDRs: 10.20.0.0/16, 172.24.0.0/16\n"
        "- Critical Assets: dc-core-01.corp.example, vault-prod-01.corp.example\n"
        "- Splunk Indexes: edr_prod (SentinelOne), wineventlog (Windows), proxy_egress (Zscaler)\n"
        "- SentinelOne Sites: Prod-Servers, Prod-Workstations, Lab-Isolated\n"
        "- Benign Admin Tools: CyberArk EPM (epm_agent.exe), SCCM (ccmexec.exe)\n"
        "- Escalation Rule: Page Tier-3 IR lead on any confirmed domain controller credential access.\n"
    )
    base_path = knowledge_dir / "BASE_ENVIRONMENT.md"
    base_path.write_text(base_text, encoding=encoding)

    default_playbooks = playbooks or {
        "lateral_movement.md": (
            "# Lateral Movement Playbook\n\n"
            "When investigating PsExec, WMI, or SMB lateral movement:\n"
            "1. Check Splunk index `wineventlog` for EventCode 4624 (LogonType 3) and 7045.\n"
            "2. Correlate source hostname in SentinelOne `Prod-Servers` site.\n"
            "3. Verify whether CyberArk EPM (`epm_agent.exe`) authorized the elevation.\n"
        ),
        "phishing_triage.md": (
            "# Phishing Triage Playbook\n\n"
            "When investigating suspicious email attachments or URLs:\n"
            "1. Inspect proxy egress logs in index `proxy_egress`.\n"
            "2. Check Recorded Future watchlists for domain/IP risk scores.\n"
        ),
    }

    pb_paths: dict[str, Path] = {}
    for filename, content in default_playbooks.items():
        pb_path = playbooks_dir / filename
        pb_path.write_text(content, encoding=encoding)
        pb_paths[filename] = pb_path

    return {
        "knowledge_dir": knowledge_dir,
        "base_path": base_path,
        "playbooks": pb_paths,
    }


# ==============================================================================
# Mock DB-API 2.0 Drivers & TLS Helpers (pg8000 & PyMySQL)
# ==============================================================================


class MockDBError(Exception):
    """Base DB-API 2.0 mock exception."""


class MockDBInterfaceError(MockDBError):
    """DB-API 2.0 InterfaceError."""


class MockDBDatabaseError(MockDBError):
    """DB-API 2.0 DatabaseError."""


class MockDBOperationalError(MockDBDatabaseError):
    """DB-API 2.0 OperationalError."""


class MockDBProgrammingError(MockDBDatabaseError):
    """DB-API 2.0 ProgrammingError."""


def _skip_sql_noncode(sql: str, idx: int) -> tuple[int, bool]:
    """Advance past a SQL string literal, quoted identifier, or comment starting at ``idx``."""
    n = len(sql)
    ch = sql[idx]
    if ch in ("'", '"', "`"):
        quote = ch
        i = idx + 1
        while i < n:
            c = sql[i]
            if c == "\\" and quote == "'" and i + 1 < n:
                i += 2
                continue
            if c == quote:
                if i + 1 < n and sql[i + 1] == quote:
                    i += 2
                    continue
                return i + 1, True
            i += 1
        return n, True
    if ch == "[":
        end = sql.find("]", idx + 1)
        return (end + 1 if end != -1 else n), True
    if ch == "-" and idx + 1 < n and sql[idx + 1] == "-":
        nl = sql.find("\n", idx + 2)
        return (nl + 1 if nl != -1 else n), True
    if ch == "/" and idx + 1 < n and sql[idx + 1] == "*":
        end = sql.find("*/", idx + 2)
        return (end + 2 if end != -1 else n), True
    return idx, False


def _read_sql_word(sql: str, idx: int) -> tuple[str, int]:
    """Read an ASCII identifier/keyword token starting at ``idx``."""
    n = len(sql)
    end = idx
    while end < n and (sql[end].isalnum() or sql[end] in ("_", "$")):
        end += 1
    return sql[idx:end], end


def _split_top_level_csv(sql: str) -> list[str]:
    """Split a SQL list on commas at parenthesis/quote depth 0."""
    items: list[str] = []
    depth = 0
    start = 0
    i = 0
    n = len(sql)
    while i < n:
        next_i, skipped = _skip_sql_noncode(sql, i)
        if skipped:
            i = next_i
            continue
        ch = sql[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            part = sql[start:i].strip()
            if part:
                items.append(part)
            start = i + 1
        i += 1
    tail = sql[start:].strip()
    if tail:
        items.append(tail)
    return items


def _extract_projection_name(expr: str) -> str:
    """Extract the column or alias name from a single SELECT/RETURNING expression."""
    s = expr.strip()
    if not s:
        return "result"

    depth = 0
    i = 0
    n = len(s)
    last_as_after: int | None = None
    last_ws_parts: list[str] = []
    part_start = 0
    while i < n:
        next_i, skipped = _skip_sql_noncode(s, i)
        if skipped:
            i = next_i
            continue
        ch = s[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0:
            if ch.isspace():
                seg = s[part_start:i].strip()
                if seg:
                    last_ws_parts.append(seg)
                part_start = i + 1
                i += 1
                continue
            if (ch.isalpha() or ch == "_") and (i == 0 or not (s[i - 1].isalnum() or s[i - 1] == "_")):
                word, end = _read_sql_word(s, i)
                if word.lower() == "as" and (end == n or s[end].isspace() or s[end] in ('"', "`", "[")):
                    last_as_after = end
                i = end
                continue
        i += 1
    tail_seg = s[part_start:].strip()
    if tail_seg:
        last_ws_parts.append(tail_seg)

    if last_as_after is not None:
        alias = s[last_as_after:].strip().strip('"`[]')
        if alias:
            return alias

    target = last_ws_parts[-1] if last_ws_parts else s
    # Split dotted identifier outside quotes at depth 0, taking the trailing column name.
    dots: list[int] = []
    ti = 0
    tn = len(target)
    tdepth = 0
    while ti < tn:
        next_ti, skipped = _skip_sql_noncode(target, ti)
        if skipped:
            ti = next_ti
            continue
        if target[ti] == "(":
            tdepth += 1
        elif target[ti] == ")":
            tdepth = max(0, tdepth - 1)
        elif target[ti] == "." and tdepth == 0:
            dots.append(ti)
        ti += 1
    col = target[dots[-1] + 1 :] if dots else target
    cleaned = col.strip().strip('"`[]')
    return cleaned or "result"


def _extract_select_projection(sql: str) -> tuple[list[str], list[str], bool]:
    """Parse projection expressions, column names, and GROUP BY presence for SELECT/WITH."""
    n = len(sql)
    depth = 0
    i = 0
    select_end: int | None = None
    while i < n:
        next_i, skipped = _skip_sql_noncode(sql, i)
        if skipped:
            i = next_i
            continue
        ch = sql[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0 and (ch.isalpha() or ch == "_"):
            word, end = _read_sql_word(sql, i)
            if word.lower() == "select":
                select_end = end
                break
            i = end
            continue
        i += 1

    if select_end is None:
        return [], ["result"], False

    i = select_end
    while i < n:
        if sql[i].isspace():
            i += 1
            continue
        if sql.startswith("--", i) or sql.startswith("/*", i):
            next_i, _ = _skip_sql_noncode(sql, i)
            i = next_i
            continue
        if sql[i].isalpha() or sql[i] == "_":
            word, end = _read_sql_word(sql, i)
            if word.lower() in ("distinct", "all"):
                i = end
                continue
        break

    proj_start = i
    proj_end = n
    stop_keywords = {
        "from",
        "where",
        "group",
        "having",
        "order",
        "limit",
        "offset",
        "fetch",
        "for",
        "union",
        "intersect",
        "except",
        "window",
        "into",
    }
    depth = 0
    while i < n:
        next_i, skipped = _skip_sql_noncode(sql, i)
        if skipped:
            i = next_i
            continue
        ch = sql[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0:
            if ch == ";":
                proj_end = i
                break
            if (ch.isalpha() or ch == "_") and (i == 0 or not (sql[i - 1].isalnum() or sql[i - 1] == "_")):
                word, end = _read_sql_word(sql, i)
                if word.lower() in stop_keywords:
                    proj_end = i
                    break
                i = end
                continue
        i += 1

    raw_items = _split_top_level_csv(sql[proj_start:proj_end])
    cols = [_extract_projection_name(item) for item in raw_items]
    if not cols or cols == ["*"] or any(c == "*" or c.endswith(".*") for c in cols):
        cols = ["result"]

    has_group_by = False
    depth = 0
    gi = proj_end
    while gi < n:
        next_gi, skipped = _skip_sql_noncode(sql, gi)
        if skipped:
            gi = next_gi
            continue
        ch = sql[gi]
        if ch == "(":
            depth += 1
            gi += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            gi += 1
            continue
        if depth == 0 and (ch.isalpha() or ch == "_") and (gi == 0 or not (sql[gi - 1].isalnum() or sql[gi - 1] == "_")):
            word, end = _read_sql_word(sql, gi)
            if word.lower() == "group":
                k = end
                while k < n and sql[k].isspace():
                    k += 1
                if k < n and (sql[k].isalpha() or sql[k] == "_"):
                    next_word, _ = _read_sql_word(sql, k)
                    if next_word.lower() == "by":
                        has_group_by = True
                        break
            gi = end
            continue
        gi += 1

    return raw_items, cols, has_group_by


def _split_returning_clause(sql: str) -> tuple[str, str] | None:
    """Split on the last top-level RETURNING keyword outside quotes/comments."""
    n = len(sql)
    depth = 0
    i = 0
    last_pos: int | None = None
    while i < n:
        next_i, skipped = _skip_sql_noncode(sql, i)
        if skipped:
            i = next_i
            continue
        ch = sql[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0 and (ch.isalpha() or ch == "_") and (i == 0 or not (sql[i - 1].isalnum() or sql[i - 1] == "_")):
            word, end = _read_sql_word(sql, i)
            if word.lower() == "returning":
                last_pos = i
            i = end
            continue
        i += 1
    if last_pos is None:
        return None
    return sql[:last_pos], sql[last_pos + len("returning") :]


def _count_insert_value_tuples(sql_before_returning: str) -> int:
    """Count top-level ``(...)`` value tuples in an INSERT VALUES / insertmanyvalues query."""
    n = len(sql_before_returning)
    depth = 0
    i = 0
    values_end: int | None = None
    values_depth = 0
    while i < n:
        next_i, skipped = _skip_sql_noncode(sql_before_returning, i)
        if skipped:
            i = next_i
            continue
        ch = sql_before_returning[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if (ch.isalpha() or ch == "_") and (
            i == 0 or not (sql_before_returning[i - 1].isalnum() or sql_before_returning[i - 1] == "_")
        ):
            word, end = _read_sql_word(sql_before_returning, i)
            if word.lower() == "values":
                k = end
                while k < n:
                    if sql_before_returning[k].isspace():
                        k += 1
                        continue
                    next_k, skipped_k = _skip_sql_noncode(sql_before_returning, k)
                    if skipped_k:
                        k = next_k
                        continue
                    break
                if k < n and sql_before_returning[k] == "(":
                    values_end = k
                    values_depth = depth
                    break
            i = end
            continue
        i += 1

    if values_end is None:
        return 1

    count = 0
    i = values_end
    depth = values_depth
    while i < n:
        if sql_before_returning[i].isspace():
            i += 1
            continue
        next_i, skipped = _skip_sql_noncode(sql_before_returning, i)
        if skipped:
            i = next_i
            continue
        ch = sql_before_returning[i]
        if ch == "(" and depth == values_depth:
            count += 1
            depth += 1
            i += 1
            while i < n and depth > values_depth:
                next_inner, skipped_inner = _skip_sql_noncode(sql_before_returning, i)
                if skipped_inner:
                    i = next_inner
                    continue
                if sql_before_returning[i] == "(":
                    depth += 1
                elif sql_before_returning[i] == ")":
                    depth -= 1
                i += 1
            while i < n:
                if sql_before_returning[i].isspace():
                    i += 1
                    continue
                next_sep, skipped_sep = _skip_sql_noncode(sql_before_returning, i)
                if skipped_sep:
                    i = next_sep
                    continue
                break
            if i < n and sql_before_returning[i] == ",":
                i += 1
                continue
            break
        break

    return max(1, count)


class MockDBCursor:
    """Lightweight DB-API 2.0 cursor recording queries and returning dialect probe rows."""

    def __init__(self, connection: MockDBConnection) -> None:
        self._conn = connection
        self._rows: list[tuple[Any, ...]] = []
        self._idx = 0
        self.description: list[tuple[Any, ...]] | None = None
        self.rowcount: int = -1
        self.lastrowid: int | None = None
        self.arraysize: int = 1
        self.closed: bool = False

    def execute(self, operation: str, parameters: Any = None) -> MockDBCursor:
        sql = str(operation or "")
        self._conn.driver.executed_sql.append((sql, parameters))
        lowered = " ".join(sql.lower().split())

        if self._conn.driver.query_responder is not None:
            custom = self._conn.driver.query_responder(sql, parameters)
            if custom is not None:
                cols, rows = custom
                self.description = [(c, None, None, None, None, None, None) for c in cols]
                self._rows = [tuple(r) for r in rows]
                self._idx = 0
                self.rowcount = len(self._rows)
                return self

        if (
            "pg_catalog.version()" in lowered
            or "select version()" in lowered
            or "select @@version" in lowered
        ):
            ver = (
                "PostgreSQL 16.4 on x86_64-pc-linux-gnu"
                if self._conn.driver.dialect == "postgres"
                else "8.0.39"
            )
            self.description = [("version", None, None, None, None, None, None)]
            self._rows = [(ver,)]
        elif "standard_conforming_strings" in lowered:
            self.description = [("standard_conforming_strings", None, None, None, None, None, None)]
            self._rows = [("on",)]
        elif "show transaction isolation level" in lowered:
            self.description = [("transaction_isolation", None, None, None, None, None, None)]
            self._rows = [("read committed",)]
        elif "show transaction_read_only" in lowered:
            self.description = [("transaction_read_only", None, None, None, None, None, None)]
            self._rows = [("off",)]
        elif "show transaction_deferrable" in lowered:
            self.description = [("transaction_deferrable", None, None, None, None, None, None)]
            self._rows = [("off",)]
        elif "@@tx_isolation" in lowered or "@@transaction_isolation" in lowered:
            col = "tx_isolation" if "@@tx_isolation" in lowered else "transaction_isolation"
            self.description = [(col, None, None, None, None, None, None)]
            self._rows = [("REPEATABLE-READ",)]
        elif "@@lower_case_table_names" in lowered:
            self.description = [("@@lower_case_table_names", None, None, None, None, None, None)]
            self._rows = [(0,)]
        elif "@@sql_mode" in lowered:
            self.description = [("@@sql_mode", None, None, None, None, None, None)]
            self._rows = [("STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION",)]
        elif "current_schema" in lowered:
            self.description = [("current_schema", None, None, None, None, None, None)]
            self._rows = [("public",)]
        elif "select database()" in lowered:
            self.description = [("database()", None, None, None, None, None, None)]
            self._rows = [(self._conn.kwargs.get("database") or "soclens_db",)]
        elif "show variables" in lowered or "show sql_mode" in lowered:
            self.description = [
                ("Variable_name", None, None, None, None, None, None),
                ("Value", None, None, None, None, None, None),
            ]
            if "lower_case_table_names" in lowered:
                self._rows = [("lower_case_table_names", "0")]
            else:
                self._rows = [("sql_mode", "STRICT_TRANS_TABLES")]
        elif "show tables" in lowered or "show full tables" in lowered:
            self.description = [("Tables_in_soclens_db", None, None, None, None, None, None)]
            self._rows = []
        elif (
            lowered.startswith("describe ")
            or "show create table" in lowered
            or "pg_catalog.pg_class" in lowered
            or "pg_tables" in lowered
            or "information_schema" in lowered
            or lowered.startswith("show ")
        ):
            self.description = [("col", None, None, None, None, None, None)]
            self._rows = []
        elif (returning_split := _split_returning_clause(sql)) is not None:
            before_returning, returning_part = returning_split
            ret_items = _split_top_level_csv(returning_part)
            ret_cols = [_extract_projection_name(c) for c in ret_items] or ["id"]
            n_rows = _count_insert_value_tuples(before_returning) if lowered.startswith("insert ") else 1
            self.description = [(col_name, None, None, None, None, None, None) for col_name in ret_cols]
            base_id = self._conn.driver.allocate_rowids(n_rows)
            self.lastrowid = base_id + n_rows - 1
            self._rows = [tuple(base_id + offset for _ in ret_cols) for offset in range(n_rows)]
            self._idx = 0
            self.rowcount = n_rows
            return self
        elif re.match(r"^select\s+1(?:\s+from\s+dual)?\s*;?$", lowered):
            self.description = [("col1", None, None, None, None, None, None)]
            self._rows = [(1,)]
        elif lowered.startswith(("select ", "with ")):
            raw_items, cols, has_group_by = _extract_select_projection(sql)
            self.description = [(col_name, None, None, None, None, None, None) for col_name in cols]
            if (
                len(raw_items) == 1
                and not has_group_by
                and re.match(r"^count\s*\(", raw_items[0].strip(), re.IGNORECASE)
            ):
                self._rows = [(0,)]
            else:
                self._rows = []
        elif lowered.startswith("insert "):
            n_rows = _count_insert_value_tuples(sql)
            base_id = self._conn.driver.allocate_rowids(n_rows)
            self.lastrowid = base_id + n_rows - 1
            self.description = None
            self._rows = []
            self._idx = 0
            self.rowcount = n_rows
            return self
        else:
            self.description = None
            self._rows = []

        self._idx = 0
        self.rowcount = len(self._rows) if self.description is not None else 0
        return self

    def executemany(self, operation: str, seq_of_parameters: Sequence[Any]) -> MockDBCursor:
        for params in seq_of_parameters:
            self.execute(operation, params)
        return self

    def fetchone(self) -> tuple[Any, ...] | None:
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    def fetchmany(self, size: int | None = None) -> list[tuple[Any, ...]]:
        count = self.arraysize if size is None else max(0, int(size))
        end = self._idx + count
        batch = self._rows[self._idx : end]
        self._idx = min(len(self._rows), end)
        return list(batch)

    def fetchall(self) -> list[tuple[Any, ...]]:
        rest = self._rows[self._idx :]
        self._idx = len(self._rows)
        return list(rest)

    def setinputsizes(self, sizes: Any) -> None:
        return None

    def setoutputsize(self, size: Any, column: Any = None) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> MockDBCursor:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def __iter__(self) -> Iterator[tuple[Any, ...]]:
        return iter(self.fetchall())


class MockDBConnection:
    """Lightweight DB-API 2.0 connection capturing TLS/SSL parameters and transactions."""

    def __init__(self, driver: MockDBAPIDriver, kwargs: dict[str, Any]) -> None:
        self.driver = driver
        self.dialect = driver.dialect
        self.kwargs = dict(kwargs)
        self.closed = False
        self._autocommit = False
        self.committed = 0
        self.rolled_back = 0
        if self.dialect == "postgres":
            self.autocommit: Any = False
            self.py_types: dict[Any, int] = {
                str: 25,
                bytes: 17,
                int: 23,
                float: 701,
                bool: 16,
            }
        else:
            self.autocommit = self._set_autocommit

    def _set_autocommit(self, value: bool) -> None:
        self._autocommit = bool(value)

    def get_autocommit(self) -> bool:
        if self.dialect == "postgres":
            return bool(self.autocommit)
        return self._autocommit

    def character_set_name(self) -> str:
        return str(self.kwargs.get("charset") or "utf8mb4")

    def register_in_adapter(self, oid: int, fn: Any) -> None:
        return None

    def cursor(self, *args: Any, **kwargs: Any) -> MockDBCursor:
        return MockDBCursor(self)

    def commit(self) -> None:
        self.committed += 1

    def rollback(self) -> None:
        self.rolled_back += 1

    def ping(self, reconnect: bool = True) -> None:
        return None

    def select_db(self, db: str) -> None:
        self.kwargs["database"] = db

    def set_character_set(self, charset: str) -> None:
        self.kwargs["charset"] = charset

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> MockDBConnection:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


@dataclass
class MockDBAPIDriver:
    """Mock DB-API 2.0 module shim for ``pg8000`` or ``pymysql``."""

    dialect: str
    apilevel: str = "2.0"
    threadsafety: int = 1
    paramstyle: str = "format"
    __version__: str = "1.31.2"
    Error: type[Exception] = MockDBError
    InterfaceError: type[Exception] = MockDBInterfaceError
    DatabaseError: type[Exception] = MockDBDatabaseError
    OperationalError: type[Exception] = MockDBOperationalError
    ProgrammingError: type[Exception] = MockDBProgrammingError
    connect_calls: list[dict[str, Any]] = field(default_factory=list)
    executed_sql: list[tuple[str, Any]] = field(default_factory=list)
    connections: list[MockDBConnection] = field(default_factory=list)
    query_responder: Callable[[str, Any], tuple[list[str], list[tuple[Any, ...]]] | None] | None = None
    fail_on_connect: Exception | None = None
    _next_rowid: int = field(default=1, init=False, repr=False)

    def allocate_rowids(self, count: int = 1) -> int:
        base = self._next_rowid
        self._next_rowid += max(1, count)
        return base

    def connect(self, *args: Any, **kwargs: Any) -> MockDBConnection:
        if self.fail_on_connect is not None:
            raise self.fail_on_connect
        recorded = dict(kwargs)
        if args:
            recorded["_positional_args"] = list(args)
        self.connect_calls.append(recorded)
        conn = MockDBConnection(self, recorded)
        self.connections.append(conn)
        return conn


def install_mock_db_drivers(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pg_responder: Callable[[str, Any], tuple[list[str], list[tuple[Any, ...]]] | None] | None = None,
    mysql_responder: Callable[[str, Any], tuple[list[str], list[tuple[Any, ...]]] | None] | None = None,
) -> dict[str, MockDBAPIDriver]:
    """Inject mock ``pg8000`` and ``pymysql`` DB-API 2.0 modules into ``sys.modules`` via monkeypatch."""
    pg_driver = MockDBAPIDriver(
        dialect="postgres",
        paramstyle="format",
        __version__="1.31.2",
        query_responder=pg_responder,
    )
    mysql_driver = MockDBAPIDriver(
        dialect="mysql",
        paramstyle="pyformat",
        __version__="1.1.1",
        query_responder=mysql_responder,
    )

    def _build_module(name: str, drv: MockDBAPIDriver) -> types.ModuleType:
        mod = types.ModuleType(name)
        mod.apilevel = drv.apilevel  # type: ignore[attr-defined]
        mod.threadsafety = drv.threadsafety  # type: ignore[attr-defined]
        mod.paramstyle = drv.paramstyle  # type: ignore[attr-defined]
        mod.__version__ = drv.__version__  # type: ignore[attr-defined]
        mod.version_info = tuple(int(part) for part in drv.__version__.split("."))  # type: ignore[attr-defined]
        mod.connect = drv.connect  # type: ignore[attr-defined]
        mod.Connection = MockDBConnection  # type: ignore[attr-defined]
        mod.Cursor = MockDBCursor  # type: ignore[attr-defined]
        mod.Error = drv.Error  # type: ignore[attr-defined]
        mod.InterfaceError = drv.InterfaceError  # type: ignore[attr-defined]
        mod.DatabaseError = drv.DatabaseError  # type: ignore[attr-defined]
        mod.OperationalError = drv.OperationalError  # type: ignore[attr-defined]
        mod.ProgrammingError = drv.ProgrammingError  # type: ignore[attr-defined]
        mod.Binary = bytes  # type: ignore[attr-defined]
        return mod

    pg_mod = _build_module("pg8000", pg_driver)
    pg_dbapi_mod = _build_module("pg8000.dbapi", pg_driver)
    pg_native_mod = _build_module("pg8000.native", pg_driver)
    pg_exc_mod = types.ModuleType("pg8000.exceptions")
    pg_exc_mod.Error = pg_driver.Error  # type: ignore[attr-defined]
    pg_exc_mod.InterfaceError = pg_driver.InterfaceError  # type: ignore[attr-defined]
    pg_exc_mod.DatabaseError = pg_driver.DatabaseError  # type: ignore[attr-defined]
    pg_mod.dbapi = pg_dbapi_mod  # type: ignore[attr-defined]
    pg_mod.native = pg_native_mod  # type: ignore[attr-defined]
    pg_mod.exceptions = pg_exc_mod  # type: ignore[attr-defined]

    mysql_mod = _build_module("pymysql", mysql_driver)
    mysql_mod.VERSION_STRING = mysql_driver.__version__  # type: ignore[attr-defined]
    mysql_cursors_mod = types.ModuleType("pymysql.cursors")

    class _MockDictCursor(MockDBCursor):
        pass

    mysql_cursors_mod.Cursor = MockDBCursor  # type: ignore[attr-defined]
    mysql_cursors_mod.DictCursor = _MockDictCursor  # type: ignore[attr-defined]
    mysql_cursors_mod.SSCursor = MockDBCursor  # type: ignore[attr-defined]
    mysql_err_mod = types.ModuleType("pymysql.err")
    mysql_err_mod.Error = mysql_driver.Error  # type: ignore[attr-defined]
    mysql_err_mod.OperationalError = mysql_driver.OperationalError  # type: ignore[attr-defined]
    mysql_err_mod.ProgrammingError = mysql_driver.ProgrammingError  # type: ignore[attr-defined]
    mysql_mod.cursors = mysql_cursors_mod  # type: ignore[attr-defined]
    mysql_mod.err = mysql_err_mod  # type: ignore[attr-defined]

    for mod_name, mod_obj in (
        ("pg8000", pg_mod),
        ("pg8000.dbapi", pg_dbapi_mod),
        ("pg8000.native", pg_native_mod),
        ("pg8000.exceptions", pg_exc_mod),
        ("pymysql", mysql_mod),
        ("pymysql.cursors", mysql_cursors_mod),
        ("pymysql.err", mysql_err_mod),
    ):
        monkeypatch.setitem(sys.modules, mod_name, mod_obj)

    return {"postgres": pg_driver, "mysql": mysql_driver}


# ==============================================================================
# Mock Browser / Edge --app Launcher & Subprocess Helpers
# ==============================================================================


class MockPopenProcess:
    """Stub process handle returned by mocked ``subprocess.Popen``."""

    def __init__(self, cmd: Any, kwargs: dict[str, Any], pid: int = 42420) -> None:
        self.cmd = list(cmd) if isinstance(cmd, (list, tuple)) else cmd
        self.kwargs = dict(kwargs)
        self.pid = pid
        self.returncode: int | None = None
        self.terminated = False

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def kill(self) -> None:
        self.terminated = True
        self.returncode = -9


@dataclass
class LauncherRecorder:
    """Captures mocked browser discovery, ``subprocess.Popen``, and ``webbrowser.open`` calls."""

    which_calls: list[str] = field(default_factory=list)
    popen_calls: list[MockPopenProcess] = field(default_factory=list)
    webbrowser_calls: list[str] = field(default_factory=list)

    @property
    def all_commands(self) -> list[Any]:
        return [proc.cmd for proc in self.popen_calls]


def install_mock_launcher(
    monkeypatch: pytest.MonkeyPatch,
    *,
    available_binaries: Mapping[str, str | None] | None = None,
    target_module: Any | None = None,
) -> LauncherRecorder:
    """Stub ``shutil.which``, ``subprocess.Popen``, and ``webbrowser.open*`` safely."""
    recorder = LauncherRecorder()
    binary_map = {k.lower(): v for k, v in (available_binaries or {}).items()}

    def _fake_which(name: str, mode: int = os.F_OK | os.X_OK, path: str | None = None) -> str | None:
        recorder.which_calls.append(name)
        low = name.lower()
        if low in binary_map:
            return binary_map[low]
        stem = Path(low).name
        return binary_map.get(stem)

    def _fake_popen(cmd: Any, *args: Any, **kwargs: Any) -> MockPopenProcess:
        proc = MockPopenProcess(cmd, kwargs, pid=42420 + len(recorder.popen_calls))
        recorder.popen_calls.append(proc)
        return proc

    def _fake_webbrowser_open(url: str, new: int = 0, autoraise: bool = True) -> bool:
        recorder.webbrowser_calls.append(url)
        return True

    monkeypatch.setattr(shutil, "which", _fake_which)
    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(webbrowser, "open", _fake_webbrowser_open)
    monkeypatch.setattr(webbrowser, "open_new", lambda url: _fake_webbrowser_open(url, new=1))
    monkeypatch.setattr(webbrowser, "open_new_tab", lambda url: _fake_webbrowser_open(url, new=2))

    if target_module is not None:
        if hasattr(target_module, "shutil"):
            monkeypatch.setattr(target_module.shutil, "which", _fake_which)
        if hasattr(target_module, "subprocess"):
            monkeypatch.setattr(target_module.subprocess, "Popen", _fake_popen)
        if hasattr(target_module, "webbrowser"):
            monkeypatch.setattr(target_module.webbrowser, "open", _fake_webbrowser_open)
        if hasattr(target_module, "Popen"):
            monkeypatch.setattr(target_module, "Popen", _fake_popen)
        if hasattr(target_module, "which"):
            monkeypatch.setattr(target_module, "which", _fake_which)

    return recorder


# ==============================================================================
# ASGI / SSE & Textual Pilot Helpers
# ==============================================================================


def extract_llm_request_text(req: Mapping[str, Any]) -> str:
    """Safely extract searchable text from a logged LLM/Copilot turn request (bytes-safe)."""
    parts: list[str] = []
    messages = req.get("messages")
    if messages is not None:
        parts.append(json.dumps(messages, ensure_ascii=False, default=str))
    turn_text = req.get("turn_text")
    if turn_text:
        parts.append(str(turn_text))
    raw_bytes = req.get("body_bytes")
    if isinstance(raw_bytes, (bytes, bytearray)):
        parts.append(bytes(raw_bytes).decode("utf-8", errors="replace"))
    elif raw_bytes is not None:
        parts.append(str(raw_bytes))
    json_body = req.get("json_body")
    if json_body is not None:
        parts.append(json.dumps(json_body, ensure_ascii=False, default=str))
    if not parts:
        parts.append(json.dumps(dict(req), ensure_ascii=False, default=str))
    return "\n".join(parts)


def parse_sse_stream(raw_text: str) -> list[dict[str, Any]]:
    """Parse ``text/event-stream`` payloads into structured event dictionaries."""
    events: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    data_lines: list[str] = []

    def _flush() -> None:
        nonlocal current, data_lines
        if not current and not data_lines:
            return
        raw_data = "\n".join(data_lines)
        parsed: Any = raw_data
        if raw_data:
            try:
                parsed = json.loads(raw_data)
            except ValueError:
                parsed = raw_data
        current["data"] = raw_data
        current["json"] = parsed
        events.append(current)
        current = {}
        data_lines = []

    for line in raw_text.splitlines():
        if not line.strip():
            _flush()
            continue
        if line.startswith(":"):
            continue
        if ":" in line:
            field_name, field_val = line.split(":", 1)
            val = field_val.lstrip(" ")
        else:
            field_name, val = line, ""
        if field_name == "data":
            data_lines.append(val)
        elif field_name in {"event", "id", "retry"}:
            current[field_name] = val

    _flush()
    return events


class _CaseInsensitiveHeaders(Mapping[str, str]):
    """Case-insensitive HTTP header container preserving multi-value headers."""

    def __init__(self, raw_headers: Sequence[tuple[bytes, bytes]] | Sequence[tuple[str, str]]) -> None:
        self._raw: list[tuple[str, str]] = []
        self._by_lower: dict[str, list[str]] = {}
        for k, v in raw_headers:
            ks = k.decode("latin-1") if isinstance(k, (bytes, bytearray)) else str(k)
            vs = v.decode("latin-1") if isinstance(v, (bytes, bytearray)) else str(v)
            self._raw.append((ks, vs))
            self._by_lower.setdefault(ks.lower(), []).append(vs)

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        vals = self._by_lower.get(key.lower())
        if not vals:
            return default
        return ", ".join(vals)

    def getlist(self, key: str) -> list[str]:
        return list(self._by_lower.get(key.lower(), []))

    def get_list(self, key: str, split_commas: bool = False) -> list[str]:
        vals = self.getlist(key)
        if not split_commas:
            return vals
        out: list[str] = []
        for item in vals:
            out.extend(part.strip() for part in item.split(",") if part.strip())
        return out

    def __getitem__(self, key: str) -> str:
        vals = self._by_lower.get(key.lower())
        if not vals:
            raise KeyError(key)
        return ", ".join(vals)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key.lower() in self._by_lower

    def __iter__(self) -> Iterator[str]:
        return iter(self._by_lower.keys())

    def __len__(self) -> int:
        return len(self._by_lower)

    def items(self) -> list[tuple[str, str]]:  # type: ignore[override]
        return [(k, ", ".join(vals)) for k, vals in self._by_lower.items()]


@dataclass
class ASGIWebResponse:
    """In-process ASGI HTTP response matching the ``TestClient`` response interface."""

    status_code: int
    headers: _CaseInsensitiveHeaders
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


class ASGIStreamResponse:
    """Incremental streaming response backed by a live in-process ASGI worker."""

    def __init__(
        self,
        *,
        status_code: int,
        headers: _CaseInsensitiveHeaders,
        chunk_queue: queue.Queue[tuple[str, Any]],
        close_cb: Callable[[], None],
    ) -> None:
        self.status_code = status_code
        self.headers = headers
        self._queue = chunk_queue
        self._close_cb = close_cb
        self._exhausted = False
        self._collected: list[bytes] = []

    def iter_bytes(self) -> Iterator[bytes]:
        if self._exhausted:
            return
        try:
            while True:
                kind, payload = self._queue.get(timeout=5.0)
                if kind == "body":
                    chunk, more_body = payload
                    if chunk:
                        self._collected.append(chunk)
                        yield chunk
                    if not more_body:
                        self._exhausted = True
                        break
                elif kind == "done":
                    self._exhausted = True
                    if payload is not None:
                        raise payload
                    break
        except queue.Empty as exc:
            raise TimeoutError("Timed out waiting for ASGI stream chunk") from exc
        finally:
            self._close_cb()

    def iter_text(self) -> Iterator[str]:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        for chunk in self.iter_bytes():
            text = decoder.decode(chunk, final=False)
            if text:
                yield text
        tail = decoder.decode(b"", final=True)
        if tail:
            yield tail

    def iter_lines(self) -> Iterator[str]:
        buf = ""
        for text_chunk in self.iter_text():
            buf += text_chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                yield line.rstrip("\r")
        if buf:
            yield buf.rstrip("\r")

    def read(self) -> bytes:
        for _ in self.iter_bytes():
            pass
        return b"".join(self._collected)


class ASGIWebTestClient:
    """In-process ASGI 3.0 HTTP/SSE test client (no ``httpx``/``starlette.testclient``)."""

    def __init__(self, app: Any, *, host: str = "127.0.0.1:8765") -> None:
        self.app = app
        self.host = host
        self.cookies: dict[str, str] = {}
        if ":" in host and not host.startswith("["):
            srv_host, srv_port_str = host.rsplit(":", 1)
            try:
                srv_port = int(srv_port_str)
            except ValueError:
                srv_host, srv_port = host, 80
        else:
            srv_host, srv_port = host, 80
        self._server = (srv_host, srv_port)

    def close(self) -> None:
        """Clean up the underlying ASGI runtime state if present."""
        state = getattr(self.app, "state", None)
        runtime = getattr(state, "runtime", None) if state is not None else None
        cleanup = getattr(runtime, "cleanup", None) if runtime is not None else None
        if callable(cleanup):
            cleanup()

    def __enter__(self) -> ASGIWebTestClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _absorb_set_cookies(self, headers: _CaseInsensitiveHeaders) -> None:
        for raw_cookie in headers.getlist("set-cookie"):
            first_pair = raw_cookie.split(";", 1)[0].strip()
            if "=" not in first_pair:
                continue
            cname, cval = first_pair.split("=", 1)
            cname = cname.strip()
            cval = cval.strip()
            attrs = [part.strip().lower() for part in raw_cookie.split(";")[1:]]
            if "max-age=0" in attrs or cval == "":
                self.cookies.pop(cname, None)
            else:
                self.cookies[cname] = cval

    def _build_scope_and_body(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
        json_body: Any = None,
        data: Any = None,
        headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
    ) -> tuple[dict[str, Any], bytes]:
        if json_body is not None and data is not None:
            raise ValueError("Cannot pass both 'json' and 'data' to ASGIWebTestClient")

        parsed = urllib.parse.urlsplit(path)
        req_path = urllib.parse.unquote(parsed.path or "/")
        raw_path = (parsed.path or "/").encode("ascii", errors="ignore")
        query_str = parsed.query
        if params is not None:
            extra_q = urllib.parse.urlencode(params, doseq=True)
            if extra_q:
                query_str = f"{query_str}&{extra_q}" if query_str else extra_q
        query_bytes = query_str.encode("ascii", errors="ignore")

        raw_headers: list[tuple[bytes, bytes]] = []
        seen_lower: set[str] = set()
        if headers is not None:
            items = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
            for k, v in items:
                kl = str(k).lower()
                seen_lower.add(kl)
                raw_headers.append((kl.encode("latin-1"), str(v).encode("latin-1")))

        if "host" not in seen_lower:
            raw_headers.insert(0, (b"host", self.host.encode("latin-1")))

        if "cookie" not in seen_lower and self.cookies:
            cookie_hdr = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            raw_headers.append((b"cookie", cookie_hdr.encode("latin-1")))

        body_bytes = b""
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode("utf-8")
            if "content-type" not in seen_lower:
                raw_headers.append((b"content-type", b"application/json"))
        elif data is not None:
            if isinstance(data, (bytes, bytearray)):
                body_bytes = bytes(data)
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
            elif isinstance(data, Mapping):
                body_bytes = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
                if "content-type" not in seen_lower:
                    raw_headers.append((b"content-type", b"application/x-www-form-urlencoded"))
            else:
                body_bytes = bytes(data)

        if body_bytes and "content-length" not in seen_lower:
            raw_headers.append((b"content-length", str(len(body_bytes)).encode("ascii")))

        scope: dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": req_path,
            "raw_path": raw_path,
            "query_string": query_bytes,
            "root_path": "",
            "headers": raw_headers,
            "client": ("127.0.0.1", 54321),
            "server": self._server,
        }
        return scope, body_bytes

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
        json: Any = None,
        data: Any = None,
        headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
        timeout: float = 15.0,
    ) -> ASGIWebResponse:
        scope, body_bytes = self._build_scope_and_body(
            method,
            path,
            params=params,
            json_body=json,
            data=data,
            headers=headers,
        )
        result_box: dict[str, Any] = {}
        error_box: list[BaseException] = []

        async def _invoke() -> tuple[int, list[tuple[bytes, bytes]], bytes]:
            status_code = 500
            resp_headers: list[tuple[bytes, bytes]] = []
            chunks: list[bytes] = []
            req_sent = False
            done_event = asyncio.Event()

            async def receive() -> dict[str, Any]:
                nonlocal req_sent
                if not req_sent:
                    req_sent = True
                    return {"type": "http.request", "body": body_bytes, "more_body": False}
                await done_event.wait()
                return {"type": "http.disconnect"}

            async def send(message: Mapping[str, Any]) -> None:
                nonlocal status_code, resp_headers
                msg_type = message.get("type")
                if msg_type == "http.response.start":
                    status_code = int(message.get("status", 500))
                    resp_headers = [
                        (bytes(k), bytes(v)) for k, v in message.get("headers", [])
                    ]
                elif msg_type == "http.response.body":
                    chunk = bytes(message.get("body") or b"")
                    if chunk:
                        chunks.append(chunk)
                    if not bool(message.get("more_body", False)):
                        done_event.set()

            try:
                await asyncio.wait_for(self.app(scope, receive, send), timeout=timeout)
            finally:
                done_event.set()
            return status_code, resp_headers, b"".join(chunks)

        def _worker() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                status_code, resp_headers, body = loop.run_until_complete(_invoke())
                result_box["status"] = status_code
                result_box["headers"] = resp_headers
                result_box["body"] = body
            except BaseException as exc:  # noqa: BLE001
                error_box.append(exc)
            finally:
                loop.close()

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        thread.join(timeout=timeout + 2.0)
        if thread.is_alive():
            raise TimeoutError(f"ASGI request {method.upper()} {path} did not complete in {timeout}s")
        if error_box:
            raise error_box[0]

        parsed_headers = _CaseInsensitiveHeaders(result_box["headers"])
        self._absorb_set_cookies(parsed_headers)
        return ASGIWebResponse(
            status_code=result_box["status"],
            headers=parsed_headers,
            content=result_box["body"],
        )

    @contextmanager
    def stream(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
        json: Any = None,
        data: Any = None,
        headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
        timeout: float = 10.0,
    ) -> Iterator[ASGIStreamResponse]:
        scope, body_bytes = self._build_scope_and_body(
            method,
            path,
            params=params,
            json_body=json,
            data=data,
            headers=headers,
        )
        msg_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        loop_ready = threading.Event()
        state: dict[str, Any] = {
            "loop": None,
            "disconnect_event": None,
            "task": None,
            "closed": False,
        }

        def _worker() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            disconnect_event = asyncio.Event()
            state["loop"] = loop
            state["disconnect_event"] = disconnect_event
            loop_ready.set()

            req_sent = False

            async def receive() -> dict[str, Any]:
                nonlocal req_sent
                if not req_sent:
                    req_sent = True
                    return {"type": "http.request", "body": body_bytes, "more_body": False}
                await disconnect_event.wait()
                return {"type": "http.disconnect"}

            async def send(message: Mapping[str, Any]) -> None:
                msg_type = message.get("type")
                if msg_type == "http.response.start":
                    status_code = int(message.get("status", 500))
                    raw_hdrs = [(bytes(k), bytes(v)) for k, v in message.get("headers", [])]
                    msg_queue.put(("start", (status_code, raw_hdrs)))
                elif msg_type == "http.response.body":
                    chunk = bytes(message.get("body") or b"")
                    more = bool(message.get("more_body", False))
                    msg_queue.put(("body", (chunk, more)))
                    if not more:
                        disconnect_event.set()

            async def _runner() -> None:
                exc_to_report: BaseException | None = None
                try:
                    await self.app(scope, receive, send)
                except asyncio.CancelledError:
                    exc_to_report = None
                except BaseException as exc:  # noqa: BLE001
                    exc_to_report = exc
                finally:
                    msg_queue.put(("done", exc_to_report))

            task = loop.create_task(_runner())
            state["task"] = task
            try:
                loop.run_until_complete(task)
            finally:
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for t in pending:
                    t.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.close()

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        loop_ready.wait(timeout=timeout)

        def _close_stream() -> None:
            if state["closed"]:
                return
            state["closed"] = True
            loop = state.get("loop")
            disconnect_event = state.get("disconnect_event")
            task = state.get("task")
            if loop is not None and not loop.is_closed():
                if disconnect_event is not None:
                    try:
                        loop.call_soon_threadsafe(disconnect_event.set)
                    except RuntimeError:
                        pass
                thread.join(timeout=0.5)
                if thread.is_alive() and task is not None:
                    try:
                        loop.call_soon_threadsafe(task.cancel)
                    except RuntimeError:
                        pass
            thread.join(timeout=2.0)

        try:
            kind, payload = msg_queue.get(timeout=timeout)
        except queue.Empty as exc:
            _close_stream()
            raise TimeoutError(f"Timed out waiting for ASGI response start on {path}") from exc

        if kind == "done":
            _close_stream()
            if payload is not None:
                raise payload
            raise RuntimeError(f"ASGI app exited before sending http.response.start for {path}")

        status_code, raw_hdrs = payload
        parsed_headers = _CaseInsensitiveHeaders(raw_hdrs)
        self._absorb_set_cookies(parsed_headers)
        stream_resp = ASGIStreamResponse(
            status_code=status_code,
            headers=parsed_headers,
            chunk_queue=msg_queue,
            close_cb=_close_stream,
        )
        try:
            yield stream_resp
        finally:
            _close_stream()

    def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
        headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
    ) -> ASGIWebResponse:
        return self.request("GET", path, params=params, headers=headers)

    def post(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
        json: Any = None,
        data: Any = None,
        headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
    ) -> ASGIWebResponse:
        return self.request("POST", path, params=params, json=json, data=data, headers=headers)

    def put(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
        json: Any = None,
        data: Any = None,
        headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
    ) -> ASGIWebResponse:
        return self.request("PUT", path, params=params, json=json, data=data, headers=headers)

    def delete(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
        json: Any = None,
        data: Any = None,
        headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
    ) -> ASGIWebResponse:
        return self.request("DELETE", path, params=params, json=json, data=data, headers=headers)


def create_web_test_client(
    workspace_dir: Path,
    *,
    admin_enabled: bool = False,
    bootstrap_token: str | None = None,
    session_state: Any = None,
    host: str = "127.0.0.1:8765",
) -> tuple[ASGIWebTestClient, Any, str]:
    """Lazily instantiate ``soclens.web.create_app`` and an in-process ASGI 3.0 test client."""
    import secrets

    from soclens.web import create_app

    token = bootstrap_token or secrets.token_urlsafe(32)
    app = create_app(
        workspace_dir=workspace_dir,
        admin_enabled=admin_enabled,
        bootstrap_token=token,
        session_state=session_state,
    )
    _TRACKED_WEB_APPS.append(weakref.ref(app))
    client = ASGIWebTestClient(app, host=host)
    return client, app, token


def exchange_web_auth(
    client: Any,
    bootstrap_token: str,
    *,
    origin: str | None = None,
) -> dict[str, str]:
    """Exchange the 256-bit bootstrap token for a session cookie + CSRF header."""
    headers: dict[str, str] = {}
    if origin:
        headers["Origin"] = origin
    resp = client.post(
        "/api/auth/exchange",
        json={"token": bootstrap_token},
        headers=headers,
    )
    assert resp.status_code == 200, f"Auth exchange failed ({resp.status_code}): {resp.text}"
    body = resp.json()
    csrf = str(body.get("csrf_token") or body.get("token") or "").strip()
    assert csrf, f"Expected csrf_token in auth exchange payload: {body!r}"
    return {"X-SOCLens-Token": csrf}


def make_pillar_app(
    workspace_dir: Path,
    *,
    initial_tab: str = "tab-rf-intel",
    dry_run: bool = False,
    view_mode: str = "user",
    preload_alerts: bool = False,
    alert_cache_refresh_seconds: float = 0,
    **kwargs: Any,
) -> Any:
    """Construct an isolated ``SocLensApp`` with background preloading disabled."""
    from soclens.tui import create_app

    return create_app(
        dry_run=dry_run,
        initial_tab=initial_tab,
        workspace_dir=workspace_dir,
        view_mode=view_mode,
        no_secret_store=True,
        preload_alerts=preload_alerts,
        alert_cache_refresh_seconds=alert_cache_refresh_seconds,
        **kwargs,
    )


def get_workspace_host(app: Any) -> Any:
    """Locate the mounted ``WorkspaceHost`` widget on ``SocLensApp``."""
    from soclens.tui.tiling import WorkspaceHost

    return app.query_one(WorkspaceHost)


async def press_tile_key(pilot: Any, key: str, *, pauses: int = 2) -> None:
    """Press a tiling keybinding and drain UI events."""
    await pilot.press(key)
    for _ in range(max(1, pauses)):
        await pilot.pause()


async def activate_pane_for_test(app: Any, pilot: Any, pane_id: str) -> Any:
    """Activate ``pane_id`` via ``WorkspaceHost`` (or fallback ``activate_tab``)."""
    from soclens.tui.tiling import WorkspaceHost

    hosts = list(app.query(WorkspaceHost))
    if hosts:
        host = hosts[0]
        result = host.switch_to_pane(pane_id)
        if hasattr(result, "__await__"):
            await result
    elif hasattr(app, "activate_tab"):
        app.activate_tab(pane_id)
    await pilot.pause()
    if hasattr(app, "ensure_tab_mounted"):
        await app.ensure_tab_mounted(pane_id)
    await pilot.pause()
    return app
