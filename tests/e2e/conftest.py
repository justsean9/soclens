"""Shared pytest fixtures and local mock HTTP servers for E2E tests."""

from __future__ import annotations

import base64
import copy
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from tests.e2e.fixtures.assets import make_png
from tests.e2e.fixtures.brand_sites import BrandSiteProfile, RouteSpec, build_default_brand_sites

ALL_LIST_TYPES: tuple[str, ...] = (
    "entity",
    "source",
    "text",
    "custom",
    "ip",
    "domain",
    "tech_stack",
    "industry",
    "brand",
    "partner",
    "industry_peer",
    "location",
    "supplier",
    "vulnerability",
    "company",
    "hash",
    "operation",
    "attacker",
    "target",
    "method",
    "executive",
)

_ENTITY_PREFIX_MAP: dict[str, str] = {
    "Hash": "hash",
    "InternetDomainName": "idn",
    "IpAddress": "ip",
    "IPAddress": "ip",
    "CyberVulnerability": "cve",
    "Company": "company",
    "Organization": "org",
}


def pytest_configure(config: pytest.Config) -> None:
    """Register custom E2E markers so ``--strict-markers`` succeeds cleanly."""
    config.addinivalue_line("markers", "e2e: End-to-end opaque-box test")
    config.addinivalue_line("markers", "tier1: Tier 1 core contract test")
    config.addinivalue_line("markers", "tier2: Tier 2 boundary and negative test")
    config.addinivalue_line("markers", "tier3: Tier 3 pairwise combination test")
    config.addinivalue_line("markers", "tier4: Tier 4 real-world SOC scenario test")
    config.addinivalue_line("markers", "feature(name): Feature ID marker (F1..F16)")


@dataclass
class FaultSpec:
    """Scripted HTTP fault entry for mock servers."""

    path_prefix: str
    status_code: int
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    method: str | None = None
    domain: str | None = None
    delay_seconds: float = 0.0
    remaining: int | None = 1  # None means persistent until cleared


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_dt(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _resolve_entity_identity(entity_obj: dict[str, Any]) -> tuple[str, str, str]:
    raw_id = entity_obj.get("id")
    if isinstance(raw_id, str) and raw_id.strip():
        eid = raw_id.strip()
        if ":" in eid:
            prefix, rest = eid.split(":", 1)
            default_type = {
                "hash": "Hash",
                "idn": "InternetDomainName",
                "ip": "IpAddress",
                "cve": "CyberVulnerability",
                "company": "Company",
                "org": "Organization",
            }.get(prefix.lower(), "Entity")
            etype = str(entity_obj.get("type") or default_type)
            ename = str(entity_obj.get("name") or rest)
        else:
            etype = str(entity_obj.get("type") or "Entity")
            ename = str(entity_obj.get("name") or eid)
        return eid, etype, ename

    etype = str(entity_obj.get("type") or "Entity")
    ename = str(entity_obj.get("name") or "")
    prefix = _ENTITY_PREFIX_MAP.get(etype, etype.lower())
    eid = ename if ename.startswith(f"{prefix}:") else f"{prefix}:{ename}"
    return eid, etype, ename


def _parse_int_param(
    mapping: Mapping[str, Any],
    key: str,
    *,
    default: int,
    min_value: int = 0,
) -> int:
    if key not in mapping:
        return default
    raw = mapping[key]
    if raw is None or isinstance(raw, bool):
        raise ValueError(f"Invalid {key}: expected integer >= {min_value}")
    if isinstance(raw, int):
        val = raw
    elif isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            raise ValueError(f"Invalid {key}: empty integer value")
        val = int(stripped)
    else:
        raise ValueError(f"Invalid {key}: expected integer >= {min_value}")
    if val < min_value:
        raise ValueError(f"Invalid {key}: must be >= {min_value}")
    return val


def _parse_query_int(
    query: Mapping[str, list[str]],
    key: str,
    *,
    default: int,
    min_value: int = 0,
) -> int:
    if key not in query:
        return default
    values = query[key]
    if not values:
        raise ValueError(f"Invalid {key}: empty query value")
    raw = values[0].strip()
    if not raw:
        raise ValueError(f"Invalid {key}: empty query value")
    val = int(raw)
    if val < min_value:
        raise ValueError(f"Invalid {key}: must be >= {min_value}")
    return val


def _default_rf_error_body(path: str, status_code: int, message: str, reason: str) -> dict[str, Any]:
    trace_id = str(uuid.uuid4())
    if path.startswith("/api/v0"):
        return {"error": reason.upper().replace(" ", "_"), "message": message}
    if path.startswith("/v2"):
        return {
            "error": {
                "status": status_code,
                "message": message,
                "reason": reason,
            },
            "traceId": trace_id,
        }
    return {
        "message": message,
        "status_code": status_code,
        "trace_id": trace_id,
    }


class MockRFServer:
    """Stateful local Recorded Future mock HTTP server."""

    def __init__(
        self,
        valid_rf_tokens: Iterable[str] | None = None,
        valid_sandbox_tokens: Iterable[str] | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self.valid_rf_tokens: set[str] = (
            set(valid_rf_tokens) if valid_rf_tokens is not None else {"test-rf-token"}
        )
        self.valid_sandbox_tokens: set[str] = (
            set(valid_sandbox_tokens)
            if valid_sandbox_tokens is not None
            else {"test-sandbox-token", "test-rf-token"}
        )
        self.requests_log: list[dict[str, Any]] = []
        self._fault_queue: list[FaultSpec] = []
        self._persistent_faults: list[FaultSpec] = []
        self.state: dict[str, Any] = {}
        self._reset_state_locked()

        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _handle(self, method: str) -> None:
                server_ref._dispatch(self, method)

            def do_GET(self) -> None:
                self._handle("GET")

            def do_POST(self) -> None:
                self._handle("POST")

            def do_PUT(self) -> None:
                self._handle("PUT")

            def do_DELETE(self) -> None:
                self._handle("DELETE")

            def do_HEAD(self) -> None:
                self._handle("HEAD")

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port: int = self._httpd.server_address[1]
        self.base_url: str = f"http://127.0.0.1:{self.port}"
        self.sandbox_base_url: str = f"http://127.0.0.1:{self.port}/api/v0"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._httpd.shutdown()
        self._thread.join(timeout=5.0)
        self._httpd.server_close()

    def _reset_state_locked(self) -> None:
        self.state = {
            "lists": {},
            "detection_rules": [
                {
                    "id": "doc:sigma-1",
                    "type": "sigma",
                    "title": "Suspicious PowerShell Encoded Command",
                    "description": "Detects encoded PowerShell command lines.",
                    "created": "2026-01-10T00:00:00Z",
                    "updated": "2026-10-01T12:00:00Z",
                    "entities": [{"id": "mitre:T1059.001", "name": "PowerShell", "type": "MitreAttackIdentifier"}],
                    "rules": [
                        {
                            "name": "Suspicious PowerShell Encoded Command",
                            "file_name": "powershell_encoded.yml",
                            "content": (
                                "title: Suspicious PowerShell Encoded Command\n"
                                "id: 11111111-1111-1111-1111-111111111111\n"
                                "status: experimental\n"
                                "logsource:\n"
                                "  category: process_creation\n"
                                "  product: windows\n"
                                "detection:\n"
                                "  selection:\n"
                                "    CommandLine|contains: '-EncodedCommand'\n"
                                "  condition: selection\n"
                            ),
                        }
                    ],
                },
                {
                    "id": "doc:sigma-2",
                    "type": "sigma",
                    "title": "Suspicious Certutil Download",
                    "description": "Detects certutil.exe downloading remote payloads.",
                    "created": "2026-02-15T00:00:00Z",
                    "updated": "2026-10-15T08:30:00Z",
                    "entities": [{"id": "mitre:T1105", "name": "Ingress Tool Transfer", "type": "MitreAttackIdentifier"}],
                    "rules": [
                        {
                            "name": "Suspicious Certutil Download",
                            "file_name": "certutil_download.yml",
                            "content": (
                                "title: Suspicious Certutil Download\n"
                                "id: 22222222-2222-2222-2222-222222222222\n"
                                "status: experimental\n"
                                "logsource:\n"
                                "  category: process_creation\n"
                                "  product: windows\n"
                                "detection:\n"
                                "  selection:\n"
                                "    Image|endswith: '\\certutil.exe'\n"
                                "  condition: selection\n"
                            ),
                        }
                    ],
                },
                {
                    "id": "doc:yara-1",
                    "type": "yara",
                    "title": "Example YARA Rule",
                    "description": "Sample YARA detection rule.",
                    "created": "2026-03-01T00:00:00Z",
                    "updated": "2026-10-20T00:00:00Z",
                    "entities": [],
                    "rules": [{"name": "Example YARA", "content": "rule Example { condition: true }"}],
                },
            ],
            "detection_rule_entities": [
                {"id": "mitre:T1059.001", "name": "PowerShell", "type": "MitreAttackIdentifier"},
                {"id": "mitre:T1105", "name": "Ingress Tool Transfer", "type": "MitreAttackIdentifier"},
            ],
            "detection_rule_types": ["MitreAttackIdentifier", "Malware", "ThreatActor"],
            "entity_matches": [
                {"id": "company:abc123", "name": "Acme Bank", "type": "Company", "aliases": ["Acme Financial"]},
                {"id": "idn:example.com", "name": "example.com", "type": "InternetDomainName", "aliases": []},
                {"id": "ip:198.51.100.10", "name": "198.51.100.10", "type": "IpAddress", "aliases": []},
            ],
            "soar_triage_contexts": {
                "malware": {"name": "malware", "threshold": 65},
                "phishing": {"name": "phishing", "threshold": 60},
                "c2": {"name": "c2", "threshold": 70},
            },
            "v2_entities": {
                ("ip", "198.51.100.10"): {
                    "entity": {"id": "ip:198.51.100.10", "name": "198.51.100.10", "type": "IpAddress"},
                    "risk": {"score": 75, "level": 3, "riskString": "3/10", "evidenceDetails": []},
                    "intelCard": "https://app.recordedfuture.com/live/sc/entity/ip%3A198.51.100.10",
                },
                ("domain", "idn:example.com"): {
                    "entity": {"id": "idn:example.com", "name": "example.com", "type": "InternetDomainName"},
                    "risk": {"score": 15, "level": 1, "riskString": "1/10", "evidenceDetails": []},
                    "intelCard": "https://app.recordedfuture.com/live/sc/entity/idn%3Aexample.com",
                },
                ("company", "by_domain:example.com"): {
                    "entity": {"id": "company:abc123", "name": "Acme Bank", "type": "Company"},
                    "risk": {"score": 5, "level": 0, "riskString": "0/10", "evidenceDetails": []},
                },
            },
            "v2_risklists": {
                "ip": "Name,Risk,RiskString,EvidenceDetails\n198.51.100.10,75,3/10,\"[]\"\n",
                "domain": "Name,Risk,RiskString,EvidenceDetails\nphish.invalid,89,4/10,\"[]\"\n",
                "hash": "Name,Risk,RiskString,EvidenceDetails\n" + ("a" * 64) + ",90,5/10,\"[]\"\n",
            },
            "v2_riskrules": {
                "ip": [{"name": "recentC2", "description": "Recent C2", "criticality": 3}],
                "domain": [{"name": "recentPhishing", "description": "Recent Phishing", "criticality": 3}],
            },
            "playbook_alerts": {
                "pb-1": {
                    "playbook_alert_id": "pb-1",
                    "category": "domain_abuse",
                    "priority": "High",
                    "status": "New",
                    "assignee": None,
                    "title": "Lookalike domain abusing Brand Alpha logo",
                    "panel_evidence_summary": {
                        "targets": ["brand-alpha.local"],
                        "assets": [
                            {
                                "type": "image_hash",
                                "hash_id": "hash:" + ("b" * 64),
                            },
                            {
                                "type": "logotype",
                                "logotype_id": "iC8hIQ",
                            },
                        ],
                    },
                    "images": {"screenshot-1": make_png(120, 40, (200, 40, 40, 255))},
                },
                "pb-2": {
                    "playbook_alert_id": "pb-2",
                    "category": "malicious_sites",
                    "priority": "High",
                    "status": "InProgress",
                    "assignee": "soc-analyst",
                    "title": "Malicious site logo hash change",
                    "panel_evidence_summary": {
                        "url": "http://lookalike-alpha.invalid/login",
                        "scan": "uuid:scan-1",
                        "hashes": ["hash:" + ("c" * 64)],
                        "brands": ["Alpha Bank"],
                        "type": "logo_hash_change",
                    },
                    "images": {"screenshot-2": make_png(160, 60, (180, 50, 50, 255))},
                },
            },
            "alerts_v3": [
                {
                    "id": "alert-v3-1",
                    "title": "Brand Logo Match Detected",
                    "triggered": "2026-10-22T01:00:00Z",
                    "statusInPortal": "New",
                    "assignee": None,
                    "alertRule": {"id": "rule-1", "name": "Brand Monitoring"},
                }
            ],
            "cases": {
                "case-1": {
                    "id": "case-1",
                    "title": "Brand Impersonation Investigation",
                    "name": "Brand Impersonation Investigation",
                    "status": "Open",
                    "priority": "High",
                    "description": "Investigating lookalike site",
                    "created": "2026-10-21T00:00:00Z",
                }
            },
            "sandbox_samples": {
                "sample-1": {
                    "id": "sample-1",
                    "status": "reported",
                    "score": 8,
                    "target": "suspicious.exe",
                    "sha256": "d" * 64,
                }
            },
        }
        self._seed_list_locked("Brand Image", "brand", list_id="report:brand-image-default")

    def _seed_list_locked(
        self,
        name: str,
        list_type: str,
        list_id: str | None = None,
        entities: list[dict[str, Any]] | None = None,
        text_entries: list[str] | None = None,
    ) -> dict[str, Any]:
        lid = list_id or f"report:{uuid.uuid4().hex[:8]}"
        now = _now_iso()
        info = {
            "id": lid,
            "name": name,
            "type": list_type,
            "created": now,
            "updated": now,
            "owner_name": "SOC Automation",
            "organisation_name": "E2E Test Org",
        }
        stored_entities: dict[str, dict[str, Any]] = {}
        tags_by_entity: dict[str, list[str]] = {}
        for item in entities or []:
            ent_obj = item.get("entity", item)
            eid, etype, ename = _resolve_entity_identity(ent_obj)
            stored_entities[eid] = {
                "entity": {"id": eid, "type": etype, "name": ename},
                "context": copy.deepcopy(item.get("context") or {}),
                "status": item.get("status", "ready"),
                "added": item.get("added", now),
            }
            if "tags" in item:
                tags_by_entity[eid] = list(item["tags"])
        self.state["lists"][lid] = {
            "info": info,
            "entities": stored_entities,
            "text_entries": list(text_entries or []),
            "tags_by_entity": tags_by_entity,
        }
        return copy.deepcopy(info)

    def reset(self) -> None:
        with self._lock:
            self.requests_log.clear()
            self._fault_queue.clear()
            self._persistent_faults.clear()
            self._reset_state_locked()

    def seed_list(
        self,
        name: str,
        list_type: str,
        list_id: str | None = None,
        entities: list[dict[str, Any]] | None = None,
        text_entries: list[str] | None = None,
    ) -> dict[str, Any]:
        """Seed or overwrite a mock list across any of the 21 ListTypes."""
        if list_type not in ALL_LIST_TYPES:
            raise ValueError(f"Unsupported ListType: {list_type!r}")
        with self._lock:
            return self._seed_list_locked(
                name=name,
                list_type=list_type,
                list_id=list_id,
                entities=entities,
                text_entries=text_entries,
            )

    def queue_fault(
        self,
        path_prefix: str,
        status_code: int,
        body: Any = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
        count: int = 1,
    ) -> None:
        """Queue ``count`` transient fault responses for ``path_prefix``."""
        with self._lock:
            self._fault_queue.append(
                FaultSpec(
                    path_prefix=path_prefix,
                    status_code=status_code,
                    body=body,
                    headers=dict(headers or {}),
                    method=method.upper() if method else None,
                    remaining=count,
                )
            )

    def set_fault(
        self,
        path_prefix: str,
        status_code: int,
        body: Any = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
    ) -> None:
        """Register a persistent fault response until ``clear_faults()``."""
        with self._lock:
            self._persistent_faults.append(
                FaultSpec(
                    path_prefix=path_prefix,
                    status_code=status_code,
                    body=body,
                    headers=dict(headers or {}),
                    method=method.upper() if method else None,
                    remaining=None,
                )
            )

    def clear_faults(self) -> None:
        with self._lock:
            self._fault_queue.clear()
            self._persistent_faults.clear()

    def _pop_fault_locked(self, method: str, path: str) -> FaultSpec | None:
        for idx, spec in enumerate(self._fault_queue):
            if path.startswith(spec.path_prefix) and (spec.method is None or spec.method == method):
                if spec.remaining is not None:
                    spec.remaining -= 1
                    if spec.remaining <= 0:
                        self._fault_queue.pop(idx)
                return spec
        for spec in self._persistent_faults:
            if path.startswith(spec.path_prefix) and (spec.method is None or spec.method == method):
                return spec
        return None

    def _send_json(
        self,
        handler: BaseHTTPRequestHandler,
        status_code: int,
        payload: Any,
        headers: dict[str, str] | None = None,
        head_only: bool = False,
    ) -> None:
        raw = json.dumps(payload).encode("utf-8")
        handler.send_response(status_code)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            handler.send_header(k, v)
        handler.end_headers()
        if not head_only:
            handler.wfile.write(raw)

    def _send_bytes(
        self,
        handler: BaseHTTPRequestHandler,
        status_code: int,
        raw: bytes,
        content_type: str,
        headers: dict[str, str] | None = None,
        head_only: bool = False,
    ) -> None:
        handler.send_response(status_code)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            handler.send_header(k, v)
        handler.end_headers()
        if not head_only:
            handler.wfile.write(raw)

    def _dispatch(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        parsed = urllib.parse.urlsplit(handler.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        try:
            content_len = int(handler.headers.get("Content-Length") or "0")
        except ValueError:
            self._send_json(
                handler,
                400,
                _default_rf_error_body(path, 400, "Invalid Content-Length header", "Bad Request"),
                head_only=(method == "HEAD"),
            )
            return
        body_bytes = handler.rfile.read(content_len) if content_len > 0 else b""
        body_json: Any = None
        if body_bytes:
            try:
                body_json = json.loads(body_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                body_json = None

        headers_dict = {k: v for k, v in handler.headers.items()}
        is_head = method == "HEAD"

        with self._lock:
            self.requests_log.append(
                {
                    "method": method,
                    "path": path,
                    "raw_path": handler.path,
                    "query": query,
                    "headers": headers_dict,
                    "body_json": body_json,
                    "body_bytes": body_bytes,
                }
            )
            fault = self._pop_fault_locked(method, path)

        if fault is not None:
            fault_body = (
                fault.body
                if fault.body is not None
                else _default_rf_error_body(
                    path,
                    fault.status_code,
                    f"Injected HTTP {fault.status_code}",
                    f"HTTP_{fault.status_code}",
                )
            )
            if isinstance(fault_body, (dict, list)):
                self._send_json(handler, fault.status_code, fault_body, fault.headers, is_head)
            else:
                self._send_bytes(
                    handler,
                    fault.status_code,
                    str(fault_body).encode("utf-8"),
                    "text/plain; charset=utf-8",
                    fault.headers,
                    is_head,
                )
            return

        # Auth boundary enforcement: Bearer on /api/v0/* vs X-RFToken on Core routes.
        if path.startswith("/api/v0"):
            auth_hdr = handler.headers.get("Authorization", "")
            sb_token = auth_hdr[7:].strip() if auth_hdr.startswith("Bearer ") else ""
            if not sb_token or sb_token not in self.valid_sandbox_tokens:
                self._send_json(
                    handler,
                    401,
                    {"error": "UNAUTHORIZED", "message": "Missing or invalid Bearer token"},
                    head_only=is_head,
                )
                return
        else:
            rf_token = handler.headers.get("X-RFToken", "").strip()
            if not rf_token or rf_token not in self.valid_rf_tokens:
                self._send_json(
                    handler,
                    401,
                    _default_rf_error_body(path, 401, "Missing or invalid X-RFToken header", "Unauthorized"),
                    head_only=is_head,
                )
                return

        with self._lock:
            status_code, payload, resp_headers, raw_content_type = self._route_locked(
                method, path, query, body_json, body_bytes
            )

        if raw_content_type is not None:
            raw_bytes = payload if isinstance(payload, bytes) else str(payload).encode("utf-8")
            self._send_bytes(handler, status_code, raw_bytes, raw_content_type, resp_headers, is_head)
        else:
            self._send_json(handler, status_code, payload, resp_headers, is_head)

    def _route_locked(
        self,
        method: str,
        path: str,
        query: dict[str, list[str]],
        body_json: Any,
        body_bytes: bytes,
    ) -> tuple[int, Any, dict[str, str], str | None]:
        # 1. Lists API
        if path == "/list/create" and method == "POST":
            if not isinstance(body_json, dict) or not body_json.get("name") or not body_json.get("type"):
                return 400, _default_rf_error_body(path, 400, "Missing name or type", "Bad Request"), {}, None
            list_type = str(body_json["type"])
            if list_type not in ALL_LIST_TYPES:
                return 400, _default_rf_error_body(path, 400, f"Invalid list type: {list_type}", "Bad Request"), {}, None
            info = self._seed_list_locked(name=str(body_json["name"]), list_type=list_type)
            return 200, info, {}, None

        if path == "/list/search" and method == "POST":
            payload = body_json if isinstance(body_json, dict) else {}
            name_filter = str(payload.get("name", "")).lower()
            type_filter = payload.get("type")
            if type_filter is not None and type_filter not in ALL_LIST_TYPES:
                return 400, _default_rf_error_body(path, 400, f"Invalid list type: {type_filter}", "Bad Request"), {}, None
            try:
                limit = _parse_int_param(payload, "limit", default=25, min_value=1)
            except ValueError as exc:
                return 400, _default_rf_error_body(path, 400, str(exc), "Bad Request"), {}, None
            results: list[dict[str, Any]] = []
            for entry in self.state["lists"].values():
                info = entry["info"]
                if type_filter and info["type"] != type_filter:
                    continue
                if name_filter and name_filter not in info["name"].lower():
                    continue
                results.append(copy.deepcopy(info))
            return 200, results[: min(limit, 100)], {}, None

        if path.startswith("/list/"):
            parts = [urllib.parse.unquote(p) for p in path[len("/list/") :].split("/")]
            if len(parts) >= 2:
                list_id = parts[0]
                sub = "/".join(parts[1:])
                list_obj = self.state["lists"].get(list_id)
                if list_obj is None:
                    return 404, _default_rf_error_body(path, 404, f"List {list_id} not found", "Not Found"), {}, None

                if sub == "info" and method == "GET":
                    return 200, copy.deepcopy(list_obj["info"]), {}, None

                if sub == "status" and method == "GET":
                    size = len(list_obj["entities"]) if list_obj["info"]["type"] != "text" else len(list_obj["text_entries"])
                    return 200, {"size": size, "status": "ready"}, {}, None

                if sub == "entities" and method == "GET":
                    return 200, copy.deepcopy(list(list_obj["entities"].values())), {}, None

                if sub == "textEntries" and method == "GET":
                    return 200, list(list_obj["text_entries"]), {}, None

                if sub == "entitiesWithTags" and method == "GET":
                    tagged_items: list[dict[str, Any]] = []
                    for eid, ent in list_obj["entities"].items():
                        item = copy.deepcopy(ent)
                        tags = list_obj["tags_by_entity"].get(eid, [])
                        item["tags"] = [
                            {"id": f"enum:EntityListTag:{tag}", "name": tag} for tag in tags
                        ]
                        tagged_items.append(item)
                    return 200, tagged_items, {}, None

                if sub == "entity/add" and method == "POST":
                    if not isinstance(body_json, dict) or not isinstance(body_json.get("entity"), dict):
                        return 400, _default_rf_error_body(path, 400, "Missing entity object", "Bad Request"), {}, None
                    eid, etype, ename = _resolve_entity_identity(body_json["entity"])
                    if not ename and not body_json["entity"].get("id"):
                        return 400, _default_rf_error_body(path, 400, "Empty entity name/id", "Bad Request"), {}, None
                    new_ctx = copy.deepcopy(body_json.get("context") or {})
                    existing = list_obj["entities"].get(eid)
                    if existing is None:
                        list_obj["entities"][eid] = {
                            "entity": {"id": eid, "type": etype, "name": ename},
                            "context": new_ctx,
                            "status": "ready",
                            "added": _now_iso(),
                        }
                        list_obj["info"]["updated"] = _now_iso()
                        return 200, {"result": "added"}, {}, None
                    if body_json.get("context") is not None and existing.get("context") != new_ctx:
                        existing["context"] = new_ctx
                        list_obj["info"]["updated"] = _now_iso()
                        return 200, {"result": "updated"}, {}, None
                    return 200, {"result": "unchanged"}, {}, None

                if sub == "entity/remove" and method == "POST":
                    if not isinstance(body_json, dict) or not isinstance(body_json.get("entity"), dict):
                        return 400, _default_rf_error_body(path, 400, "Missing entity object", "Bad Request"), {}, None
                    ent_obj = body_json["entity"]
                    raw_id = ent_obj.get("id")
                    if not (isinstance(raw_id, str) and raw_id.strip()):
                        raw_type = str(ent_obj.get("type") or "").strip().lower()
                        if raw_type not in {"ipaddress", "internetdomainname", "hash", "cybervulnerability"}:
                            return (
                                400,
                                _default_rf_error_body(
                                    path,
                                    400,
                                    f"Invalid entity:\n{json.dumps(ent_obj, separators=(',', ':'))}",
                                    "Bad Request",
                                ),
                                {},
                                None,
                            )
                    eid, _, _ = _resolve_entity_identity(ent_obj)
                    if eid in list_obj["entities"]:
                        del list_obj["entities"][eid]
                        list_obj["tags_by_entity"].pop(eid, None)
                        list_obj["info"]["updated"] = _now_iso()
                        return 200, {"result": "removed"}, {}, None
                    return 200, {"result": "unchanged"}, {}, None

                if sub == "entity/tags" and method == "POST":
                    if not isinstance(body_json, dict) or not isinstance(body_json.get("entity"), dict):
                        return 400, _default_rf_error_body(path, 400, "Missing entity object", "Bad Request"), {}, None
                    tags = body_json.get("tags")
                    if not isinstance(tags, list) or len(tags) > 9:
                        return 400, _default_rf_error_body(path, 400, "tags must be a list of at most 9 strings", "Bad Request"), {}, None
                    eid, _, _ = _resolve_entity_identity(body_json["entity"])
                    if eid not in list_obj["entities"]:
                        return 404, _default_rf_error_body(path, 404, f"Entity {eid} not in list", "Not Found"), {}, None
                    norm_tags = [str(t) for t in tags]
                    prev = list_obj["tags_by_entity"].get(eid, [])
                    list_obj["tags_by_entity"][eid] = norm_tags
                    op_status = "tags_unchanged" if prev == norm_tags else "tags_updated"
                    return 200, {"entity_id": eid, "operation": {"status": op_status}}, {}, None

        # 2. Detection Rules API
        if path == "/detection-rule/search" and method == "POST":
            payload = body_json if isinstance(body_json, dict) else {}
            filter_obj = payload.get("filter") or {}
            if not isinstance(filter_obj, dict):
                return 400, _default_rf_error_body(path, 400, "filter must be an object", "Bad Request"), {}, None

            for date_key in ("updated", "created"):
                if date_key in filter_obj:
                    dr = filter_obj[date_key]
                    if not isinstance(dr, dict) or "operator" in dr or not any(k in dr for k in ("after", "before")):
                        return (
                            400,
                            _default_rf_error_body(
                                path,
                                400,
                                f"Invalid filter.{date_key}: expected DateTimeRange with 'after'/'before'",
                                "Bad Request",
                            ),
                            {},
                            None,
                        )
                    for bound in ("after", "before"):
                        if bound in dr and dr[bound] is not None:
                            try:
                                _parse_iso_dt(str(dr[bound]))
                            except ValueError:
                                return (
                                    400,
                                    _default_rf_error_body(path, 400, f"Invalid ISO8601 datetime in filter.{date_key}.{bound}", "Bad Request"),
                                    {},
                                    None,
                                )

            rules = list(self.state["detection_rules"])
            types_filter = filter_obj.get("types")
            if types_filter:
                allowed = {str(t).lower() for t in types_filter}
                rules = [r for r in rules if r["type"].lower() in allowed]
            title_filter = filter_obj.get("title")
            if title_filter:
                tf = str(title_filter).lower()
                rules = [r for r in rules if tf in r["title"].lower()]
            doc_id = filter_obj.get("doc_id")
            if doc_id:
                rules = [r for r in rules if r["id"] == doc_id]
            entities_filter = filter_obj.get("entities")
            if entities_filter:
                wanted = set(entities_filter)
                rules = [
                    r for r in rules if any(e["id"] in wanted for e in r.get("entities", []))
                ]
            if "updated" in filter_obj:
                upd = filter_obj["updated"]
                if upd.get("after"):
                    after_dt = _parse_iso_dt(str(upd["after"]))
                    rules = [r for r in rules if _parse_iso_dt(r["updated"]) >= after_dt]
                if upd.get("before"):
                    before_dt = _parse_iso_dt(str(upd["before"]))
                    rules = [r for r in rules if _parse_iso_dt(r["updated"]) <= before_dt]

            try:
                limit = _parse_int_param(payload, "limit", default=10, min_value=1)
                start = _parse_int_param(payload, "offset", default=0, min_value=0)
            except ValueError as exc:
                return 400, _default_rf_error_body(path, 400, str(exc), "Bad Request"), {}, None
            page = rules[start : start + limit]
            next_offset = str(start + limit) if (start + limit) < len(rules) else None
            resp: dict[str, Any] = {
                "count": len(page),
                "total_count": len(rules),
                "result": copy.deepcopy(page),
            }
            if next_offset is not None:
                resp["next_offset"] = next_offset
            return 200, resp, {}, None

        if path == "/detection-rule-relation/entity/list" and method == "GET":
            return 200, copy.deepcopy(self.state["detection_rule_entities"]), {}, None

        if path == "/detection-rule-relation/entity/types" and method == "GET":
            return 200, list(self.state["detection_rule_types"]), {}, None

        # 3. Entity Match API
        if path == "/entity-match/match" and method == "POST":
            if not isinstance(body_json, dict) or not body_json.get("name"):
                return 400, _default_rf_error_body(path, 400, "Missing required 'name'", "Bad Request"), {}, None
            name_q = str(body_json["name"]).lower()
            types_q = body_json.get("type")
            try:
                limit = min(_parse_int_param(body_json, "limit", default=10, min_value=1), 100)
            except ValueError as exc:
                return 400, _default_rf_error_body(path, 400, str(exc), "Bad Request"), {}, None
            matched = []
            for ent in self.state["entity_matches"]:
                if types_q is not None and ent["type"] not in types_q:
                    continue
                if name_q in ent["name"].lower() or any(name_q in a.lower() for a in ent.get("aliases", [])):
                    matched.append({"id": ent["id"], "name": ent["name"], "type": ent["type"]})
            return 200, matched[:limit], {}, None

        if path.startswith("/entity-match/entity/") and method == "GET":
            eid = urllib.parse.unquote(path[len("/entity-match/entity/") :])
            for ent in self.state["entity_matches"]:
                if ent["id"] == eid:
                    return 200, copy.deepcopy(ent), {}, None
            return 404, _default_rf_error_body(path, 404, f"Entity {eid} not found", "Not Found"), {}, None

        # 4. SOAR v3 API
        if path == "/soar/v3/enrichment" and method == "POST":
            payload = body_json if isinstance(body_json, dict) else {}
            soar_results: list[dict[str, Any]] = []
            for ioc_type, values in payload.items():
                if not isinstance(values, list):
                    continue
                for val in values:
                    soar_results.append(
                        {
                            "entity": {"id": f"{ioc_type}:{val}", "name": val, "type": ioc_type},
                            "risk": {
                                "score": 72 if "evil" in str(val) or "198.51.100" in str(val) else 10,
                                "level": 3 if "evil" in str(val) else 1,
                                "context": {"phishing": {"score": 70}, "malware": {"score": 45}},
                                "rule": {"evidence": [{"rule": "Recent Threat Sighting"}]},
                            },
                        }
                    )
            return 200, {"data": {"results": soar_results}}, {}, None

        if path == "/soar/v3/triage/contexts" and method == "GET":
            return 200, {"contexts": copy.deepcopy(list(self.state["soar_triage_contexts"].values()))}, {}, None

        if path.startswith("/soar/v3/triage/contexts/") and method == "POST":
            ctx_name = urllib.parse.unquote(path[len("/soar/v3/triage/contexts/") :])
            if ctx_name not in self.state["soar_triage_contexts"]:
                return 404, _default_rf_error_body(path, 404, f"Unknown context: {ctx_name}", "Not Found"), {}, None
            payload = body_json if isinstance(body_json, dict) else {}
            triage_results: list[dict[str, Any]] = []
            for ioc_type, values in payload.items():
                if not isinstance(values, list):
                    continue
                for val in values:
                    malicious = "evil" in str(val) or "198.51.100" in str(val)
                    triage_results.append(
                        {
                            "entity": {"id": f"{ioc_type}:{val}", "name": val, "type": ioc_type},
                            "verdict": malicious,
                            "score": 80 if malicious else 5,
                            "context": ctx_name,
                        }
                    )
            return 200, {"data": {"context": ctx_name, "results": triage_results}}, {}, None

        # 5. Connect API v2
        if path.startswith("/v2/"):
            parts = [urllib.parse.unquote(p) for p in path[len("/v2/") :].split("/")]
            if len(parts) == 3 and parts[0] == "company" and parts[1] == "by_domain" and method == "GET":
                domain = parts[2]
                entry = self.state["v2_entities"].get(("company", f"by_domain:{domain}"))
                if entry is None:
                    return 404, _default_rf_error_body(path, 404, f"Company not found for {domain}", "Not Found"), {}, None
                return 200, {"data": copy.deepcopy(entry)}, {}, None

            if len(parts) == 2:
                etype, action_or_id = parts
                if action_or_id == "search" and method == "GET":
                    matches = [
                        copy.deepcopy(v)
                        for (k_type, _), v in self.state["v2_entities"].items()
                        if k_type == etype
                    ]
                    return 200, {"data": {"results": matches}}, {}, None
                if action_or_id == "risklist" and method in ("GET", "HEAD"):
                    csv_data = self.state["v2_risklists"].get(
                        etype, "Name,Risk,RiskString,EvidenceDetails\n"
                    )
                    return 200, csv_data.encode("utf-8"), {"ETag": f'"{etype}-v1"'}, "text/csv; charset=utf-8"
                if action_or_id == "riskrules" and method == "GET":
                    rules_list = self.state["v2_riskrules"].get(etype, [])
                    return 200, {"data": {"results": copy.deepcopy(rules_list)}}, {}, None
                if method == "GET":
                    entry = self.state["v2_entities"].get((etype, action_or_id))
                    if entry is None and etype == "ip":
                        alt_id = (
                            action_or_id[3:]
                            if action_or_id.startswith("ip:")
                            else f"ip:{action_or_id}"
                        )
                        entry = self.state["v2_entities"].get((etype, alt_id))
                    elif entry is None and etype == "domain":
                        alt_id = (
                            action_or_id[4:]
                            if action_or_id.startswith("idn:")
                            else f"idn:{action_or_id}"
                        )
                        entry = self.state["v2_entities"].get((etype, alt_id))
                    if entry is None:
                        return 404, _default_rf_error_body(path, 404, f"{etype} {action_or_id} not found", "Not Found"), {}, None
                    return 200, {"data": copy.deepcopy(entry)}, {}, None

        # 6. Playbook Alerts
        if path == "/playbook-alert/search" and method == "POST":
            payload = body_json if isinstance(body_json, dict) else {}
            try:
                limit = _parse_int_param(payload, "limit", default=100, min_value=1)
                start = _parse_int_param(payload, "offset", default=0, min_value=0)
            except ValueError as exc:
                return 400, _default_rf_error_body(path, 400, str(exc), "Bad Request"), {}, None
            cats = payload.get("category")
            alerts = [
                {
                    "playbook_alert_id": a["playbook_alert_id"],
                    "category": a["category"],
                    "priority": a["priority"],
                    "status": a["status"],
                    "assignee": a["assignee"],
                    "title": a["title"],
                }
                for a in self.state["playbook_alerts"].values()
                if not cats or a["category"] in cats
            ]
            page = alerts[start : start + limit]
            next_offset = str(start + limit) if (start + limit) < len(alerts) else None
            pb_resp: dict[str, Any] = {
                "data": page,
                "counts": {"returned": len(page), "total": len(alerts)},
                "status": {"status_code": "Ok", "status_message": "Success"},
            }
            if next_offset is not None:
                pb_resp["next_offset"] = next_offset
            return 200, pb_resp, {}, None

        if path.startswith("/playbook-alert/common/"):
            aid = urllib.parse.unquote(path[len("/playbook-alert/common/") :])
            alert = self.state["playbook_alerts"].get(aid)
            if alert is None:
                return 404, _default_rf_error_body(path, 404, f"Playbook alert {aid} not found", "Not Found"), {}, None
            if method == "GET":
                return 200, {"data": {k: v for k, v in alert.items() if k != "images"}, "status": {"status_code": "Ok", "status_message": "Success"}}, {}, None
            if method == "PUT" and isinstance(body_json, dict):
                for key in ("status", "priority", "assignee"):
                    if key in body_json:
                        alert[key] = body_json[key]
                return 200, {"data": {k: v for k, v in alert.items() if k != "images"}, "status": {"status_code": "Ok", "status_message": "Success"}}, {}, None

        if path.startswith("/playbook-alert/"):
            parts = [urllib.parse.unquote(p) for p in path[len("/playbook-alert/") :].split("/")]
            if len(parts) == 4 and parts[2] == "image" and method == "GET":
                cat, aid, _, img_id = parts
                alert = self.state["playbook_alerts"].get(aid)
                if alert is None or alert["category"] != cat:
                    return 404, _default_rf_error_body(path, 404, "Playbook alert not found", "Not Found"), {}, None
                img_bytes = alert.get("images", {}).get(img_id) or make_png(120, 40)
                return 200, img_bytes, {}, "image/png"
            if len(parts) == 2 and method in ("GET", "POST"):
                cat, aid = parts
                alert = self.state["playbook_alerts"].get(aid)
                if alert is None or alert["category"] != cat:
                    return 404, _default_rf_error_body(path, 404, "Playbook alert not found", "Not Found"), {}, None
                detail = {k: v for k, v in alert.items() if k != "images"}
                return 200, {"data": detail, "status": {"status_code": "Ok", "status_message": "Success"}}, {}, None

        # 7. Alerts v3 & Alerts v2 update
        if path == "/alert/v3" and method == "GET":
            try:
                limit = min(_parse_query_int(query, "limit", default=100, min_value=1), 1000)
                if "from" in query:
                    start = _parse_query_int(query, "from", default=0, min_value=0)
                else:
                    start = _parse_query_int(query, "offset", default=0, min_value=0)
            except ValueError as exc:
                return 400, _default_rf_error_body(path, 400, str(exc), "Bad Request"), {}, None
            all_alerts = list(self.state["alerts_v3"])
            page = copy.deepcopy(all_alerts[start : start + limit])
            return 200, {"data": {"results": page}, "counts": {"returned": len(page), "total": len(all_alerts)}}, {}, None

        if path == "/alert/v3/hits" and method == "GET":
            raw_ids = (query.get("ids") or [""])[0]
            hit_ids = [hid.strip() for hid in raw_ids.split(",") if hid.strip()]
            if not hit_ids:
                return 400, _default_rf_error_body(path, 400, "Missing required 'ids' query parameter", "Bad Request"), {}, None
            hits = [
                {
                    "id": hid,
                    "alert_id": "alert-v3-1",
                    "entity": {"id": "idn:example.com", "name": "example.com", "type": "InternetDomainName"},
                }
                for hid in hit_ids
            ]
            return 200, {"data": {"results": hits, "hits": hits}, "counts": {"returned": len(hits), "total": len(hits)}}, {}, None

        if path.startswith("/alert/v3/") and method == "GET":
            aid = urllib.parse.unquote(path[len("/alert/v3/") :])
            for alert in self.state["alerts_v3"]:
                if alert["id"] == aid:
                    return 200, {"data": copy.deepcopy(alert)}, {}, None
            return 404, _default_rf_error_body(path, 404, f"Alert {aid} not found", "Not Found"), {}, None

        if path == "/alert/v2/update" and method == "POST":
            if not isinstance(body_json, list):
                return 400, _default_rf_error_body(path, 400, "Expected JSON array of alert updates", "Bad Request"), {}, None
            success: list[str] = []
            errors: list[dict[str, Any]] = []
            by_id = {a["id"]: a for a in self.state["alerts_v3"]}
            for item in body_json:
                if not isinstance(item, dict) or not item.get("id"):
                    errors.append({"error": "Missing alert id"})
                    continue
                aid = str(item["id"])
                alert = by_id.get(aid)
                if alert is None:
                    errors.append({"id": aid, "error": "Alert not found"})
                    continue
                if "statusInPortal" in item:
                    alert["statusInPortal"] = item["statusInPortal"]
                if "assignee" in item:
                    alert["assignee"] = item["assignee"]
                success.append(aid)
            return 200, {"success": success, "error": errors}, {}, None

        # 8. Cases API
        if path == "/case/search" and method == "POST":
            payload = body_json if isinstance(body_json, dict) else {}
            try:
                limit = min(_parse_int_param(payload, "limit", default=100, min_value=1), 100)
                start = _parse_int_param(payload, "offset", default=0, min_value=0)
            except ValueError as exc:
                return 400, _default_rf_error_body(path, 400, str(exc), "Bad Request"), {}, None
            cases_list = list(self.state["cases"].values())
            statuses_filter = payload.get("statuses")
            if isinstance(statuses_filter, list) and statuses_filter:
                wanted_statuses = {str(s) for s in statuses_filter}
                cases_list = [c for c in cases_list if c.get("status") in wanted_statuses]
            priorities_filter = payload.get("priorities")
            if isinstance(priorities_filter, list) and priorities_filter:
                wanted_priorities = {str(p) for p in priorities_filter}
                cases_list = [c for c in cases_list if c.get("priority") in wanted_priorities]
            page = cases_list[start : start + limit]
            next_offset = str(start + limit) if (start + limit) < len(cases_list) else None
            case_resp: dict[str, Any] = {
                "data": copy.deepcopy(page),
                "total_count": len(cases_list),
                "status": {"status_code": "Ok", "status_message": "Success"},
            }
            if next_offset is not None:
                case_resp["next_offset"] = next_offset
            return 200, case_resp, {}, None

        if path == "/case/lookup" and method == "POST":
            payload = body_json if isinstance(body_json, dict) else {}
            raw_case_ids = payload.get("ids")
            if isinstance(raw_case_ids, list):
                requested_ids = [str(cid).strip() for cid in raw_case_ids if str(cid).strip()]
            elif payload.get("id"):
                requested_ids = [str(payload["id"]).strip()]
            else:
                requested_ids = []
            if not requested_ids:
                return 400, _default_rf_error_body(path, 400, "Missing case ids", "Bad Request"), {}, None
            found_cases: list[dict[str, Any]] = []
            for cid in requested_ids:
                case = self.state["cases"].get(cid)
                if case is None:
                    return 404, _default_rf_error_body(path, 404, f"Case {cid} not found", "Not Found"), {}, None
                found_cases.append(copy.deepcopy(case))
            return (
                200,
                {
                    "status": {"status_code": "Ok", "status_message": "Success"},
                    "data": found_cases,
                },
                {},
                None,
            )

        if path == "/case/create" and method == "POST":
            if not isinstance(body_json, dict):
                return 400, _default_rf_error_body(path, 400, "Missing case title", "Bad Request"), {}, None
            raw_title = body_json.get("title") if body_json.get("title") is not None else body_json.get("name")
            if not isinstance(raw_title, str) or not raw_title.strip():
                return 400, _default_rf_error_body(path, 400, "Missing case title", "Bad Request"), {}, None
            cid = f"case-{len(self.state['cases']) + 1}"
            clean_title = raw_title.strip()
            case_obj: dict[str, Any] = {
                "id": cid,
                "title": clean_title,
                "name": clean_title,
                "status": body_json.get("status", "Open"),
                "priority": body_json.get("priority", "Medium"),
                "description": body_json.get("description", ""),
                "created": _now_iso(),
            }
            if "assignee" in body_json:
                case_obj["assignee"] = body_json["assignee"]
            self.state["cases"][cid] = case_obj
            return 200, copy.deepcopy(case_obj), {}, None

        if path == "/case/update" and method in ("PUT", "POST"):
            if not isinstance(body_json, dict) or not body_json.get("id"):
                return 400, _default_rf_error_body(path, 400, "Missing case id", "Bad Request"), {}, None
            cid = str(body_json["id"])
            case_obj = self.state["cases"].get(cid)
            if case_obj is None:
                return 404, _default_rf_error_body(path, 404, f"Case {cid} not found", "Not Found"), {}, None
            for k in ("title", "name", "status", "priority", "description", "assignee"):
                if k in body_json:
                    case_obj[k] = body_json[k]
            if "title" in body_json and "name" not in body_json:
                case_obj["name"] = body_json["title"]
            elif "name" in body_json and "title" not in body_json:
                case_obj["title"] = body_json["name"]
            return 200, copy.deepcopy(case_obj), {}, None

        # 9. Sandbox v0 API
        if path == "/api/v0/search" and method == "GET":
            q = (query.get("query") or [""])[0].lower()
            samples = [
                copy.deepcopy(s)
                for s in self.state["sandbox_samples"].values()
                if not q or q in s["target"].lower() or q in s["sha256"].lower()
            ]
            return 200, {"samples": samples}, {}, None

        if path == "/api/v0/samples" and method == "POST":
            sid = f"sample-{len(self.state['sandbox_samples']) + 1}"
            sample_obj = {
                "id": sid,
                "status": "pending",
                "score": 0,
                "target": (body_json or {}).get("filename", "uploaded.bin") if isinstance(body_json, dict) else "uploaded.bin",
                "sha256": "e" * 64,
                "size": len(body_bytes),
            }
            self.state["sandbox_samples"][sid] = sample_obj
            return 200, copy.deepcopy(sample_obj), {}, None

        if path.startswith("/api/v0/samples/") and method == "GET":
            rest = path[len("/api/v0/samples/") :]
            if rest.endswith("/overview.json"):
                sid = urllib.parse.unquote(rest[: -len("/overview.json")])
                sample = self.state["sandbox_samples"].get(sid)
                if sample is None:
                    return 404, {"error": "NOT_FOUND", "message": f"Sample {sid} not found"}, {}, None
                return 200, {"sample": copy.deepcopy(sample), "signatures": [], "targets": []}, {}, None
            sid = urllib.parse.unquote(rest)
            sample = self.state["sandbox_samples"].get(sid)
            if sample is None:
                return 404, {"error": "NOT_FOUND", "message": f"Sample {sid} not found"}, {}, None
            return 200, copy.deepcopy(sample), {}, None

        return 404, _default_rf_error_body(path, 404, f"No mock route for {method} {path}", "Not Found"), {}, None


class MockSplunkServer:
    """Stateful local Splunk REST API mock HTTP server."""

    def __init__(self, valid_tokens: Iterable[str] | None = None) -> None:
        self._lock = threading.Lock()
        self.valid_tokens: set[str] = (
            set(valid_tokens) if valid_tokens is not None else {"test-splunk-token"}
        )
        self.requests_log: list[dict[str, Any]] = []
        self._fault_queue: list[FaultSpec] = []
        self._persistent_faults: list[FaultSpec] = []
        self.state: dict[str, Any] = {
            "saved_searches": [
                {
                    "name": "RF_Sigma_Example",
                    "content": {"search": "index=main | head 5", "disabled": False},
                }
            ],
            "jobs": {},
            "default_job_mode": "done",  # "done" | "queued_then_done" | "failed" | "stuck_queued"
            "job_results": [{"_time": "2026-10-22T00:00:00Z", "count": "1"}],
        }
        self._job_counter = 0

        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                server_ref._dispatch(self, "GET")

            def do_POST(self) -> None:
                server_ref._dispatch(self, "POST")

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port: int = self._httpd.server_address[1]
        self.base_url: str = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._httpd.shutdown()
        self._thread.join(timeout=5.0)
        self._httpd.server_close()

    def set_job_behavior(
        self,
        mode: str = "done",
        results: list[dict[str, Any]] | None = None,
    ) -> None:
        with self._lock:
            self.state["default_job_mode"] = mode
            if results is not None:
                self.state["job_results"] = list(results)

    def queue_fault(
        self,
        path_prefix: str,
        status_code: int,
        body: Any = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
        count: int = 1,
    ) -> None:
        with self._lock:
            self._fault_queue.append(
                FaultSpec(
                    path_prefix=path_prefix,
                    status_code=status_code,
                    body=body,
                    headers=dict(headers or {}),
                    method=method.upper() if method else None,
                    remaining=count,
                )
            )

    def set_fault(
        self,
        path_prefix: str,
        status_code: int,
        body: Any = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
    ) -> None:
        with self._lock:
            self._persistent_faults.append(
                FaultSpec(
                    path_prefix=path_prefix,
                    status_code=status_code,
                    body=body,
                    headers=dict(headers or {}),
                    method=method.upper() if method else None,
                    remaining=None,
                )
            )

    def clear_faults(self) -> None:
        with self._lock:
            self._fault_queue.clear()
            self._persistent_faults.clear()

    def _pop_fault_locked(self, method: str, path: str) -> FaultSpec | None:
        for idx, spec in enumerate(self._fault_queue):
            if path.startswith(spec.path_prefix) and (spec.method is None or spec.method == method):
                if spec.remaining is not None:
                    spec.remaining -= 1
                    if spec.remaining <= 0:
                        self._fault_queue.pop(idx)
                return spec
        for spec in self._persistent_faults:
            if path.startswith(spec.path_prefix) and (spec.method is None or spec.method == method):
                return spec
        return None

    def _send_json(
        self,
        handler: BaseHTTPRequestHandler,
        status_code: int,
        payload: Any,
        headers: dict[str, str] | None = None,
    ) -> None:
        raw = json.dumps(payload).encode("utf-8")
        handler.send_response(status_code)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            handler.send_header(k, v)
        handler.end_headers()
        handler.wfile.write(raw)

    def _dispatch(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        parsed = urllib.parse.urlsplit(handler.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        try:
            content_len = int(handler.headers.get("Content-Length") or "0")
        except ValueError:
            self._send_json(
                handler,
                400,
                {"messages": [{"type": "ERROR", "text": "Invalid Content-Length header"}]},
            )
            return
        body_bytes = handler.rfile.read(content_len) if content_len > 0 else b""
        form_data = urllib.parse.parse_qs(body_bytes.decode("utf-8", errors="replace")) if body_bytes else {}
        headers_dict = {k: v for k, v in handler.headers.items()}

        with self._lock:
            self.requests_log.append(
                {
                    "method": method,
                    "path": path,
                    "raw_path": handler.path,
                    "query": query,
                    "headers": headers_dict,
                    "form": form_data,
                    "body_bytes": body_bytes,
                }
            )
            fault = self._pop_fault_locked(method, path)

        if fault is not None:
            body = fault.body if fault.body is not None else {"messages": [{"type": "ERROR", "text": f"HTTP {fault.status_code}"}]}
            self._send_json(handler, fault.status_code, body, fault.headers)
            return

        auth = handler.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            bearer_token = auth[7:].strip()
            if not bearer_token or bearer_token not in self.valid_tokens:
                self._send_json(
                    handler,
                    401,
                    {"messages": [{"type": "ERROR", "text": "Invalid Bearer token"}]},
                )
                return
        elif auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:].strip(), validate=True).decode("utf-8")
                if ":" not in decoded:
                    raise ValueError("Invalid basic auth")
                username, password = decoded.split(":", 1)
                if not username.strip() or not password.strip():
                    raise ValueError("Empty username or password")
            except Exception:
                self._send_json(
                    handler,
                    401,
                    {"messages": [{"type": "ERROR", "text": "Invalid Basic credentials"}]},
                )
                return
        else:
            self._send_json(
                handler,
                401,
                {"messages": [{"type": "ERROR", "text": "Unauthorized"}]},
            )
            return

        with self._lock:
            status_code, payload = self._route_locked(method, path, query, form_data)
        self._send_json(handler, status_code, payload)

    def _route_locked(
        self,
        method: str,
        path: str,
        query: dict[str, list[str]],
        form_data: dict[str, list[str]],
    ) -> tuple[int, Any]:
        if path == "/services/server/info" and method == "GET":
            return 200, {"entry": [{"content": {"version": "10.2.0", "serverName": "mock-splunk"}}]}

        if path == "/services/authentication/currentcontext" and method == "GET":
            return 200, {"entry": [{"content": {"username": "soc_validator", "roles": ["admin"]}}]}

        if path.startswith("/servicesNS/"):
            parts = path[len("/servicesNS/") :].split("/")
            # /servicesNS/{owner}/{app}/saved/searches
            if len(parts) == 4 and parts[2] == "saved" and parts[3] == "searches":
                app = parts[1]
                if method == "GET":
                    return 200, {
                        "entry": [
                            {**copy.deepcopy(item), "acl": {"app": app}}
                            for item in self.state["saved_searches"]
                        ]
                    }
                if method == "POST":
                    name = (form_data.get("name") or ["unnamed_search"])[0]
                    search_spl = (form_data.get("search") or [""])[0]
                    entry = {"name": name, "content": {"search": search_spl, "disabled": False}}
                    self.state["saved_searches"].append(entry)
                    return 201, {"entry": [copy.deepcopy(entry)]}

            # /servicesNS/{owner}/{app}/search/jobs
            if len(parts) == 4 and parts[2] == "search" and parts[3] == "jobs" and method == "POST":
                app = parts[1]
                self._job_counter += 1
                sid = f"1700000000.{self._job_counter}"
                search_spl = (form_data.get("search") or [""])[0]
                self.state["jobs"][sid] = {
                    "sid": sid,
                    "app": app,
                    "search": search_spl,
                    "mode": self.state["default_job_mode"],
                    "polls": 0,
                    "cancelled": False,
                }
                return 201, {"sid": sid}

        if path.startswith("/services/search/jobs/"):
            rest = path[len("/services/search/jobs/") :]
            parts = rest.split("/")
            sid = urllib.parse.unquote(parts[0])
            job = self.state["jobs"].get(sid)
            if job is None:
                return 404, {"messages": [{"type": "ERROR", "text": f"Unknown sid: {sid}"}]}

            if len(parts) == 1 and method == "GET":
                job["polls"] += 1
                mode = job["mode"]
                if job["cancelled"]:
                    content = {
                        "isDone": True,
                        "dispatchState": "CANCELLED",
                        "resultCount": 0,
                        "eventCount": 0,
                        "runDuration": 0.05,
                        "messages": [{"type": "INFO", "text": "Job cancelled"}],
                    }
                elif mode == "failed":
                    content = {
                        "isDone": True,
                        "dispatchState": "FAILED",
                        "resultCount": 0,
                        "eventCount": 0,
                        "runDuration": 0.02,
                        "messages": [{"type": "ERROR", "text": "Search failed in mock Splunk"}],
                    }
                elif mode == "stuck_queued":
                    content = {
                        "isDone": False,
                        "dispatchState": "QUEUED",
                        "resultCount": 0,
                        "eventCount": 0,
                        "runDuration": 0.1,
                        "messages": [],
                    }
                elif mode == "queued_then_done" and job["polls"] == 1:
                    content = {
                        "isDone": False,
                        "dispatchState": "QUEUED",
                        "resultCount": 0,
                        "eventCount": 0,
                        "runDuration": 0.01,
                        "messages": [],
                    }
                else:
                    results = self.state["job_results"]
                    content = {
                        "isDone": True,
                        "dispatchState": "DONE",
                        "resultCount": len(results),
                        "eventCount": len(results),
                        "runDuration": 0.05,
                        "messages": [],
                    }
                return 200, {"entry": [{"content": content}]}

            if len(parts) == 2 and parts[1] == "results" and method == "GET":
                return 200, {"results": copy.deepcopy(self.state["job_results"])}

            if len(parts) == 2 and parts[1] == "control" and method == "POST":
                action = (form_data.get("action") or [""])[0]
                if action == "cancel":
                    job["cancelled"] = True
                return 200, {
                    "messages": [{"type": "INFO", "text": f"Control action '{action}' applied"}],
                    "output_mode": (query.get("output_mode") or ["xml"])[0],
                }

        return 404, {"messages": [{"type": "ERROR", "text": f"Not found: {method} {path}"}]}


class BrandHTTPServer:
    """Local multi-domain HTTP server serving synthetic brand sites."""

    def __init__(self, sites: dict[str, BrandSiteProfile] | None = None) -> None:
        self._lock = threading.Lock()
        raw_sites = sites if sites is not None else build_default_brand_sites()
        self.sites: dict[str, BrandSiteProfile] = {k.lower(): v for k, v in raw_sites.items()}
        self.default_domain: str = next(iter(self.sites), "brand-alpha.local")
        self.requests_log: list[dict[str, Any]] = []
        self._fault_queue: list[FaultSpec] = []
        self._persistent_faults: list[FaultSpec] = []
        self._domain_servers: dict[str, tuple[ThreadingHTTPServer, threading.Thread, int]] = {}

        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                server_ref._dispatch(self, "GET")

            def do_HEAD(self) -> None:
                server_ref._dispatch(self, "HEAD")

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port: int = self._httpd.server_address[1]
        self.base_url: str = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def _ensure_domain_listener_locked(self, domain: str) -> int:
        norm_domain = domain.lower()
        existing = self._domain_servers.get(norm_domain)
        if existing is not None:
            return existing[2]

        server_ref = self

        class DomainHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                server_ref._dispatch(self, "GET", forced_domain=norm_domain)

            def do_HEAD(self) -> None:
                server_ref._dispatch(self, "HEAD", forced_domain=norm_domain)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), DomainHandler)
        port: int = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self._domain_servers[norm_domain] = (httpd, thread, port)
        return port

    def close(self) -> None:
        self._httpd.shutdown()
        self._thread.join(timeout=5.0)
        self._httpd.server_close()
        with self._lock:
            domain_servers = list(self._domain_servers.values())
            self._domain_servers.clear()
        for httpd, thread, _ in domain_servers:
            httpd.shutdown()
            thread.join(timeout=5.0)
            httpd.server_close()

    def shutdown(self) -> None:
        self.close()

    def site_url(self, domain: str) -> str:
        """Return origin-root URL ``http://127.0.0.1:<domain_port>`` for ``domain``."""
        with self._lock:
            port = self._ensure_domain_listener_locked(domain)
        return f"http://127.0.0.1:{port}"

    def path_url(self, domain: str) -> str:
        """Return path-prefixed URL ``http://127.0.0.1:<port>/sites/<domain>``."""
        return f"{self.base_url}/sites/{domain.lower()}"

    def add_site(self, profile: BrandSiteProfile) -> None:
        with self._lock:
            self.sites[profile.domain.lower()] = profile

    def set_route(self, domain: str, path: str, route: RouteSpec) -> None:
        norm_path = path if path.startswith("/") else f"/{path}"
        norm_domain = domain.lower()
        with self._lock:
            if norm_domain not in self.sites:
                self.sites[norm_domain] = BrandSiteProfile(domain=norm_domain)
            self.sites[norm_domain].routes[norm_path] = route

    def queue_fault(
        self,
        domain: str | None,
        path_prefix: str,
        status_code: int,
        body: bytes | str = b"",
        headers: dict[str, str] | None = None,
        delay_seconds: float = 0.0,
        count: int = 1,
    ) -> None:
        with self._lock:
            self._fault_queue.append(
                FaultSpec(
                    path_prefix=path_prefix,
                    status_code=status_code,
                    body=body,
                    headers=dict(headers or {}),
                    domain=domain,
                    delay_seconds=delay_seconds,
                    remaining=count,
                )
            )

    def set_fault(
        self,
        domain: str | None,
        path_prefix: str,
        status_code: int,
        body: bytes | str = b"",
        headers: dict[str, str] | None = None,
        delay_seconds: float = 0.0,
    ) -> None:
        with self._lock:
            self._persistent_faults.append(
                FaultSpec(
                    path_prefix=path_prefix,
                    status_code=status_code,
                    body=body,
                    headers=dict(headers or {}),
                    domain=domain,
                    delay_seconds=delay_seconds,
                    remaining=None,
                )
            )

    def clear_faults(self) -> None:
        with self._lock:
            self._fault_queue.clear()
            self._persistent_faults.clear()

    def _resolve_domain_and_path(
        self,
        raw_path: str,
        host_header: str,
        forced_domain: str | None = None,
    ) -> tuple[str, str]:
        parsed_path = urllib.parse.urlsplit(raw_path).path or "/"
        if parsed_path.startswith("/sites/"):
            rest = parsed_path[len("/sites/") :]
            if "/" in rest:
                dom, sub_path = rest.split("/", 1)
                return dom.lower(), "/" + sub_path
            return rest.lower(), "/"
        if forced_domain is not None:
            return forced_domain.lower(), parsed_path
        host_only = host_header.split(":", 1)[0].strip().lower()
        if host_only in self.sites:
            return host_only, parsed_path
        return self.default_domain, parsed_path

    def _pop_fault_locked(self, domain: str, route_path: str) -> FaultSpec | None:
        for idx, spec in enumerate(self._fault_queue):
            if (spec.domain is None or spec.domain.lower() == domain) and route_path.startswith(spec.path_prefix):
                if spec.remaining is not None:
                    spec.remaining -= 1
                    if spec.remaining <= 0:
                        self._fault_queue.pop(idx)
                return spec
        for spec in self._persistent_faults:
            if (spec.domain is None or spec.domain.lower() == domain) and route_path.startswith(spec.path_prefix):
                return spec
        return None

    def _dispatch(
        self,
        handler: BaseHTTPRequestHandler,
        method: str,
        forced_domain: str | None = None,
    ) -> None:
        host_hdr = handler.headers.get("Host", "")
        headers_dict = {k: v for k, v in handler.headers.items()}
        is_head = method == "HEAD"

        with self._lock:
            domain, route_path = self._resolve_domain_and_path(
                handler.path,
                host_hdr,
                forced_domain=forced_domain,
            )
            self.requests_log.append(
                {
                    "method": method,
                    "domain": domain,
                    "path": route_path,
                    "raw_path": handler.path,
                    "host": host_hdr,
                    "headers": headers_dict,
                }
            )
            fault = self._pop_fault_locked(domain, route_path)
            site = self.sites.get(domain)
            route = site.routes.get(route_path) if site is not None else None

        if fault is not None:
            if fault.delay_seconds > 0:
                time.sleep(fault.delay_seconds)
            body_bytes = fault.body.encode("utf-8") if isinstance(fault.body, str) else bytes(fault.body or b"")
            handler.send_response(fault.status_code)
            handler.send_header("Content-Type", fault.headers.get("Content-Type", "text/plain; charset=utf-8"))
            handler.send_header("Content-Length", str(len(body_bytes)))
            for k, v in fault.headers.items():
                if k.lower() not in ("content-type", "content-length"):
                    handler.send_header(k, v)
            handler.end_headers()
            if not is_head and body_bytes:
                handler.wfile.write(body_bytes)
            return

        if route is None:
            not_found = b"Not Found"
            handler.send_response(404)
            handler.send_header("Content-Type", "text/plain; charset=utf-8")
            handler.send_header("Content-Length", str(len(not_found)))
            handler.end_headers()
            if not is_head:
                handler.wfile.write(not_found)
            return

        if route.delay_seconds > 0:
            time.sleep(route.delay_seconds)

        handler.send_response(route.status)
        handler.send_header("Content-Type", route.content_type)
        for k, v in route.headers.items():
            handler.send_header(k, v)

        if route.body_chunks is not None:
            if "Content-Length" not in route.headers:
                handler.send_header("Transfer-Encoding", "chunked")
            handler.end_headers()
            if not is_head:
                use_chunked = "Content-Length" not in route.headers
                try:
                    for chunk in route.body_chunks():
                        if not chunk:
                            continue
                        if use_chunked:
                            handler.wfile.write(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
                        else:
                            handler.wfile.write(chunk)
                        handler.wfile.flush()
                    if use_chunked:
                        handler.wfile.write(b"0\r\n\r\n")
                        handler.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
            return

        if "Content-Length" not in route.headers:
            handler.send_header("Content-Length", str(len(route.body)))
        handler.end_headers()
        if not is_head and route.body:
            handler.wfile.write(route.body)


@pytest.fixture
def e2e_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create an isolated temporary workspace and scrub ambient RF/Splunk env vars."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir(parents=True, exist_ok=True)
    ignored_file = tmp_path / "ignored_hashes.txt"
    ignored_file.write_text("# E2E isolated ignored hashes\n", encoding="utf-8")

    for key in list(os.environ):
        if key.startswith(("RF_", "SPLUNK_")) or key in (
            "RECORDED_FUTURE_API_KEY",
            "RECORDED_FUTURE_SANDBOX_TOKEN",
        ):
            monkeypatch.delenv(key, raising=False)

    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(tmp_path / "soclens_cfg" / "settings.json"))
    monkeypatch.setenv("RF_BASE_URL", "http://127.0.0.1:0")
    monkeypatch.setenv("RF_SANDBOX_BASE_URL", "http://127.0.0.1:0/api/v0")
    monkeypatch.setenv("RF_API_TOKEN", "test-rf-token")
    monkeypatch.setenv("RECORDED_FUTURE_API_KEY", "test-rf-token")
    monkeypatch.setenv("RECORDED_FUTURE_SANDBOX_TOKEN", "test-sandbox-token")
    monkeypatch.setenv("RF_SANDBOX_TOKEN", "test-sandbox-token")
    monkeypatch.setenv("RF_IGNORED_HASHES_FILE", str(ignored_file))
    monkeypatch.setenv("SPLUNK_HOST", "http://127.0.0.1:0")
    monkeypatch.setenv("SPLUNK_TOKEN", "test-splunk-token")
    monkeypatch.setenv("SPLUNK_APP", "SplunkEnterpriseSecuritySuite")
    return tmp_path


@pytest.fixture
def mock_rf_server(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[MockRFServer]:
    """Provide a stateful local Recorded Future mock HTTP server and export env vars."""
    server = MockRFServer()
    monkeypatch.setenv("RF_BASE_URL", server.base_url)
    monkeypatch.setenv("RF_SANDBOX_BASE_URL", server.sandbox_base_url)
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def mock_splunk_server(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[MockSplunkServer]:
    """Provide a stateful local Splunk REST mock HTTP server and export env vars."""
    server = MockSplunkServer()
    monkeypatch.setenv("SPLUNK_HOST", server.base_url)
    monkeypatch.setenv("SPLUNK_TOKEN", "test-splunk-token")
    monkeypatch.setenv("SPLUNK_APP", "SplunkEnterpriseSecuritySuite")
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def brand_http_server(e2e_workspace: Path) -> Iterator[BrandHTTPServer]:
    """Provide a local multi-domain synthetic brand website HTTP server."""
    server = BrandHTTPServer()
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def run_cli(
    e2e_workspace: Path,
) -> Callable[..., subprocess.CompletedProcess[str]]:
    """Return a subprocess runner executing ``python -m soclens.cli`` in ``e2e_workspace``."""

    def _run(
        args: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        timeout: float = 30.0,
    ) -> subprocess.CompletedProcess[str]:
        proc_env = os.environ.copy()
        if env:
            proc_env.update(env)
        return subprocess.run(
            [sys.executable, "-m", "soclens.cli", *args],
            cwd=cwd or e2e_workspace,
            env=proc_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    return _run
