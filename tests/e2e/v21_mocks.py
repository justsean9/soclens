"""Local stateful mock HTTP servers and fixtures for SOCLens v2.1 E2E tests."""

from __future__ import annotations

import base64
import copy
import json
import math
import os
import re
import threading
import time
import urllib.parse
import uuid
from collections.abc import Iterable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Self

import pytest

from soclens.settings import (
    SECRET_MANAGED_SETTING_KEYS,
    clear_session_overrides,
    invalidate_settings_cache,
)
from tests.e2e.conftest import FaultSpec, _QuietThreadingHTTPServer

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

_V21_ENV_PREFIXES: tuple[str, ...] = (
    "S1_",
    "SENTINELONE_",
    "TSS_",
    "VAULT_",
    "OP_",
    "BW_",
    "SOCLENS_SECRET_",
    "SOCLENS_TSS_",
    "SOCLENS_VAULT_",
    "SOCLENS_OP_",
    "SOCLENS_BW_",
    "SPLUNK_ES_",
    "RF_LLM_",
)

_V21_ENV_KEYS: frozenset[str] = frozenset(
    {
        "SOCLENS_VAULT_SECRET_MAP",
        "SOCLENS_UI_VIEW",
        "SOCLENS_AUTO_APPROVE",
        "SOCLENS_TENANT_FIELD",
        "SOCLENS_DEFAULT_TABLE_FIELDS",
        "SOCLENS_DEFAULT_SUPPRESS_FIELDS",
        "SOCLENS_PROFILE",
        "SOCLENS_INSECURE_SSL",
        "SOCLENS_IMAGE_VIEWER",
        "SOCLENS_RF_RETRY_BACKOFF",
        "SECURITYTRAILS_API_KEY",
        "RISKRECON_API_TOKEN",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    }
)

_MC_VALID_FINDINGS_QUERY_PARAMS: frozenset[str] = frozenset(
    {
        "finding_ids",
        "urgency",
        "status",
        "owner",
        "disposition",
        "limit",
        "offset",
        "sort",
        "fields",
        "earliest",
        "latest",
        "rule_title",
        "search_format",
        "search_finding_groups",
    }
)

_ES_STATUS_CODE_TO_LABEL: dict[str, str] = {
    "1": "New",
    "2": "In Progress",
    "3": "Pending",
    "4": "Resolved",
    "5": "Closed",
}

_ES_STATUS_LABEL_TO_CODE: dict[str, str] = {
    "new": "1",
    "in progress": "2",
    "in_progress": "2",
    "pending": "3",
    "resolved": "4",
    "closed": "5",
}

_ES_DISPOSITION_LABELS: dict[str, str] = {
    "disposition:1": "True Positive - Suspicious Activity",
    "true_positive": "True Positive - Suspicious Activity",
    "disposition:2": "Benign Positive - Suspicious But Expected",
    "benign_positive": "Benign Positive - Suspicious But Expected",
    "disposition:3": "False Positive - Incorrect Analytic Logic",
    "false_positive": "False Positive - Incorrect Analytic Logic",
    "disposition:4": "False Positive - Inaccurate Data",
    "disposition:5": "Other",
    "disposition:6": "Undetermined",
    "undetermined": "Undetermined",
}

_THREAT_INTEL_COLLECTIONS: frozenset[str] = frozenset(
    {
        "ip_intel",
        "domain_intel",
        "file_intel",
        "http_intel",
        "email_intel",
        "user_intel",
        "process_intel",
        "certificate_intel",
    }
)

_SHA1_HEX_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_fixture(filename: str, fixture_path: Path | None = None) -> dict[str, Any]:
    target = fixture_path if fixture_path is not None else (FIXTURES_DIR / filename)
    raw = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Expected JSON object in fixture {target}")
    return copy.deepcopy(raw)


def _header_ci(headers: Mapping[str, str], name: str) -> str:
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return ""


def _parse_bool_param(query: Mapping[str, list[str]], key: str, default: bool) -> bool:
    vals = query.get(key)
    if not vals:
        return default
    raw = vals[0].strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


def _split_csv_param(query: Mapping[str, list[str]], key: str) -> list[str]:
    vals = query.get(key)
    if not vals:
        return []
    out: list[str] = []
    for item in vals:
        for part in item.split(","):
            cleaned = part.strip()
            if cleaned:
                out.append(cleaned)
    return out


class _BaseV21MockServer:
    """Shared local ThreadingHTTPServer lifecycle, logging, and fault injection base."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
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

            def do_LIST(self) -> None:
                self._handle("LIST")

            def do_OPTIONS(self) -> None:
                self._handle("OPTIONS")

        self._httpd = _QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port: int = int(self._httpd.server_address[1])
        self.base_url: str = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            kwargs={"poll_interval": 0.005},
            daemon=True,
        )
        self._thread.start()

    def _reset_state_locked(self) -> None:
        self.state = {}

    def close(self) -> None:
        self._httpd.shutdown()
        self._thread.join(timeout=5.0)
        self._httpd.server_close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def reset(self) -> None:
        with self._lock:
            self.requests_log.clear()
            self._fault_queue.clear()
            self._persistent_faults.clear()
            self._reset_state_locked()

    def queue_fault(
        self,
        path_prefix: str,
        status_code: int,
        body: Any = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
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
                    method=method.upper() if method else None,
                    delay_seconds=float(delay_seconds),
                    remaining=max(1, int(count)),
                )
            )

    def set_fault(
        self,
        path_prefix: str,
        status_code: int,
        body: Any = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
        delay_seconds: float = 0.0,
    ) -> None:
        with self._lock:
            self._persistent_faults.append(
                FaultSpec(
                    path_prefix=path_prefix,
                    status_code=status_code,
                    body=body,
                    headers=dict(headers or {}),
                    method=method.upper() if method else None,
                    delay_seconds=float(delay_seconds),
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

    def _default_fault_body(self, path: str, status_code: int) -> Any:
        return {"error": f"HTTP {status_code}", "path": path}

    def _send_raw(
        self,
        handler: BaseHTTPRequestHandler,
        status_code: int,
        body: bytes,
        content_type: str | None,
        headers: Mapping[str, str] | None = None,
        *,
        is_head: bool = False,
    ) -> None:
        handler.send_response(status_code)
        if content_type is not None:
            handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            handler.send_header(k, v)
        handler.end_headers()
        if not is_head and body:
            try:
                handler.wfile.write(body)
                handler.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return

    def _send_json(
        self,
        handler: BaseHTTPRequestHandler,
        status_code: int,
        payload: Any,
        headers: Mapping[str, str] | None = None,
        *,
        is_head: bool = False,
    ) -> None:
        if payload is None:
            self._send_raw(handler, status_code, b"", None, headers, is_head=is_head)
            return
        raw = json.dumps(payload).encode("utf-8")
        self._send_raw(handler, status_code, raw, "application/json", headers, is_head=is_head)

    def _dispatch(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        parsed = urllib.parse.urlsplit(handler.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        try:
            content_len = int(handler.headers.get("Content-Length") or "0")
        except ValueError:
            self._send_json(handler, 400, {"error": "Invalid Content-Length header"})
            return

        body_bytes = handler.rfile.read(content_len) if content_len > 0 else b""
        headers_dict = {k: v for k, v in handler.headers.items()}
        content_type = _header_ci(headers_dict, "Content-Type").lower()

        parsed_json: Any = None
        form_data: dict[str, list[str]] = {}
        if body_bytes:
            body_text = body_bytes.decode("utf-8", errors="replace")
            if "application/x-www-form-urlencoded" in content_type:
                form_data = urllib.parse.parse_qs(body_text, keep_blank_values=True)
            else:
                try:
                    parsed_json = json.loads(body_text)
                except ValueError:
                    if "=" in body_text and not body_text.lstrip().startswith(("{", "[")):
                        form_data = urllib.parse.parse_qs(body_text, keep_blank_values=True)

        log_entry: dict[str, Any] = {
            "method": method,
            "path": path,
            "raw_path": handler.path,
            "query": query,
            "headers": headers_dict,
            "body": parsed_json,
            "json_body": parsed_json,
            "form": form_data,
            "body_bytes": body_bytes,
            "timestamp": time.monotonic(),
            "utc": _now_iso(),
            "utc_timestamp": time.time(),
        }

        with self._lock:
            self.requests_log.append(log_entry)
            fault = self._pop_fault_locked(method, path)

        if fault is not None:
            if fault.delay_seconds > 0:
                time.sleep(fault.delay_seconds)
            if isinstance(fault.body, (bytes, bytearray)):
                self._send_raw(
                    handler,
                    fault.status_code,
                    bytes(fault.body),
                    _header_ci(fault.headers, "Content-Type") or "application/octet-stream",
                    fault.headers,
                    is_head=(method == "HEAD"),
                )
            elif isinstance(fault.body, str):
                self._send_raw(
                    handler,
                    fault.status_code,
                    fault.body.encode("utf-8"),
                    _header_ci(fault.headers, "Content-Type") or "text/plain; charset=utf-8",
                    fault.headers,
                    is_head=(method == "HEAD"),
                )
            else:
                body_payload = (
                    fault.body
                    if fault.body is not None
                    else self._default_fault_body(path, fault.status_code)
                )
                self._send_json(
                    handler,
                    fault.status_code,
                    body_payload,
                    fault.headers,
                    is_head=(method == "HEAD"),
                )
            return

        self._handle_request(
            handler,
            method=method,
            path=path,
            query=query,
            headers=headers_dict,
            json_body=parsed_json,
            form_data=form_data,
        )

    def _handle_request(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> None:
        with self._lock:
            status_code, payload, resp_headers = self._route_locked(
                method=method,
                path=path,
                query=query,
                headers=headers,
                json_body=json_body,
                form_data=form_data,
            )
        self._send_json(handler, status_code, payload, resp_headers, is_head=(method == "HEAD"))

    def _route_locked(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> tuple[int, Any, dict[str, str]]:
        return 404, {"error": f"No route for {method} {path}"}, {}


# ======================================================================
# 1. Delinea / Thycotic Secret Server Mock
# ======================================================================


class MockSecretServer(_BaseV21MockServer):
    """Stateful local Secret Server mock supporting password, platform, and token auth."""

    def __init__(self, fixture_path: Path | None = None) -> None:
        self._fixture_path = fixture_path
        super().__init__()

    def _reset_state_locked(self) -> None:
        raw = _load_fixture("v21_secret_stores.json", self._fixture_path)["secret_server"]
        creds = dict(raw.get("credentials") or {})
        preissued = str(creds.get("access_token") or "e2e-tss-preissued-token")
        self.state = {
            "credentials": creds,
            "secrets": copy.deepcopy(raw.get("secrets") or []),
            "active_access_tokens": {preissued},
            "valid_refresh_tokens": set(),
            "revoked_tokens": set(),
            "token_counter": 0,
            "expires_in": 3600,
            "required_domain": None,
        }

    def expire_access_token(self, token: str | None = None) -> None:
        with self._lock:
            if token is None:
                self.state["active_access_tokens"].clear()
            else:
                self.state["active_access_tokens"].discard(token)

    def set_oauth_expires_in(self, seconds: int) -> None:
        with self._lock:
            self.state["expires_in"] = int(seconds)

    def set_required_domain(self, domain: str | None) -> None:
        with self._lock:
            self.state["required_domain"] = domain

    def _issue_tokens_locked(self, *, with_refresh: bool = True) -> tuple[str, str | None]:
        self.state["token_counter"] += 1
        n = self.state["token_counter"]
        access_tok = f"e2e-tss-at-{n}"
        self.state["active_access_tokens"].add(access_tok)
        refresh_tok: str | None = None
        if with_refresh:
            refresh_tok = f"e2e-tss-rt-{n}"
            self.state["valid_refresh_tokens"].add(refresh_tok)
        return access_tok, refresh_tok

    def _check_bearer_locked(self, headers: Mapping[str, str]) -> str | None:
        auth = _header_ci(headers, "Authorization")
        if not auth.startswith("Bearer "):
            return None
        tok = auth[7:].strip()
        if tok and tok in self.state["active_access_tokens"]:
            return tok
        return None

    def _route_locked(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> tuple[int, Any, dict[str, str]]:
        creds = self.state["credentials"]

        if path == "/oauth2/token" and method == "POST":
            grant_type = (form_data.get("grant_type") or [""])[0]
            if grant_type == "password":
                username = (form_data.get("username") or [""])[0]
                password = (form_data.get("password") or [""])[0]
                domain = (form_data.get("domain") or [""])[0]
                req_domain = self.state.get("required_domain")
                if req_domain and domain.lower() != str(req_domain).lower():
                    return 400, {"error": "invalid_grant", "error_description": "Invalid domain."}, {}
                if domain and creds.get("domain") and domain.lower() != str(creds["domain"]).lower():
                    return 400, {"error": "invalid_grant", "error_description": "Invalid domain."}, {}
                if username == creds.get("username") and password == creds.get("password"):
                    at, rt = self._issue_tokens_locked(with_refresh=True)
                    return (
                        200,
                        {
                            "access_token": at,
                            "refresh_token": rt,
                            "token_type": "bearer",
                            "expires_in": self.state["expires_in"],
                        },
                        {},
                    )
                return (
                    400,
                    {"error": "invalid_grant", "error_description": "Invalid username or password."},
                    {},
                )
            if grant_type == "refresh_token":
                rt_val = (form_data.get("refresh_token") or [""])[0]
                valid_rts: set[str] = self.state["valid_refresh_tokens"]
                if not rt_val or rt_val not in valid_rts:
                    return (
                        400,
                        {
                            "error": "invalid_grant",
                            "error_description": "Refresh token invalid or already used.",
                        },
                        {},
                    )
                valid_rts.remove(rt_val)
                at, new_rt = self._issue_tokens_locked(with_refresh=True)
                return (
                    200,
                    {
                        "access_token": at,
                        "refresh_token": new_rt,
                        "token_type": "bearer",
                        "expires_in": self.state["expires_in"],
                    },
                    {},
                )
            return 400, {"error": "unsupported_grant_type", "error_description": "Unsupported grant."}, {}

        if path == "/identity/api/oauth2/token/xpmplatform" and method == "POST":
            grant_type = (form_data.get("grant_type") or [""])[0]
            client_id = (form_data.get("client_id") or [""])[0]
            client_secret = (form_data.get("client_secret") or [""])[0]
            if (
                grant_type == "client_credentials"
                and client_id == creds.get("client_id")
                and client_secret == creds.get("client_secret")
            ):
                at, _ = self._issue_tokens_locked(with_refresh=False)
                return (
                    200,
                    {
                        "access_token": at,
                        "token_type": "Bearer",
                        "expires_in": self.state["expires_in"],
                    },
                    {},
                )
            return (
                401,
                {"error": "invalid_client", "error_description": "Invalid client credentials."},
                {},
            )

        tok = self._check_bearer_locked(headers)
        if tok is None:
            return 401, {"message": "Unauthorized"}, {}

        if path == "/vaultbroker/api/vaults" and method == "GET":
            return (
                200,
                [
                    {
                        "isDefault": True,
                        "isActive": True,
                        "type": "SecretServerCloud",
                        "connection": {"url": self.base_url},
                    }
                ],
                {},
            )

        if path == "/api/v1/oauth-expiration" and method == "POST":
            self.state["active_access_tokens"].discard(tok)
            self.state["revoked_tokens"].add(tok)
            return 200, {}, {}

        # /api/v1/secrets or /api/v2/secrets
        m_list = re.match(r"^/api/v[12]/secrets$", path)
        if m_list and method == "GET":
            folder_filter = (query.get("filter.folderId") or [""])[0].strip()
            search_text = (query.get("filter.searchText") or [""])[0].strip().lower()
            try:
                take = max(1, int((query.get("take") or ["100"])[0]))
            except ValueError:
                take = 100

            matched: list[dict[str, Any]] = []
            for rec in self.state["secrets"]:
                if folder_filter and str(rec.get("folderId", "")) != folder_filter:
                    continue
                if search_text:
                    haystack_parts = [
                        str(rec.get("name", "")),
                        str(rec.get("folderPath", "")),
                    ]
                    for item in rec.get("items") or []:
                        haystack_parts.append(str(item.get("slug", "")))
                        haystack_parts.append(str(item.get("fieldName", "")))
                    if search_text not in " ".join(haystack_parts).lower():
                        continue
                matched.append(
                    {
                        "id": rec["id"],
                        "name": rec["name"],
                        "folderId": rec.get("folderId"),
                        "folderPath": rec.get("folderPath", ""),
                        "secretTemplateName": rec.get("secretTemplateName", ""),
                    }
                )
            total = len(matched)
            return 200, {"records": matched[:take], "total": total, "take": take}, {}

        m_field = re.match(r"^/api/v[12]/secrets/([^/]+)/fields/([^/]+)$", path)
        if m_field and method == "GET":
            sid = urllib.parse.unquote(m_field.group(1))
            slug = urllib.parse.unquote(m_field.group(2)).lower()
            rec = next((s for s in self.state["secrets"] if str(s["id"]) == sid), None)
            if rec is None:
                return 404, {"message": "Secret not found."}, {}
            for item in rec.get("items") or []:
                if (
                    str(item.get("slug", "")).lower() == slug
                    or str(item.get("fieldName", "")).lower() == slug
                ):
                    return 200, {"value": item.get("itemValue", "")}, {}
            return 404, {"message": "Field not found."}, {}

        m_detail = re.match(r"^/api/v[12]/secrets/([^/]+)$", path)
        if m_detail and method == "GET":
            sid = urllib.parse.unquote(m_detail.group(1))
            rec = next((s for s in self.state["secrets"] if str(s["id"]) == sid), None)
            if rec is None:
                return 404, {"message": "Secret not found."}, {}
            return 200, copy.deepcopy(rec), {}

        return 404, {"message": f"Unknown endpoint: {method} {path}"}, {}


# ======================================================================
# 2. HashiCorp Vault KV v2 Mock
# ======================================================================


class MockHashiCorpVaultServer(_BaseV21MockServer):
    """Stateful local HashiCorp Vault KV v2 mock supporting LIST, ?list=true, AppRole & namespaces."""

    def __init__(self, fixture_path: Path | None = None) -> None:
        self._fixture_path = fixture_path
        super().__init__()

    def _reset_state_locked(self) -> None:
        raw = _load_fixture("v21_secret_stores.json", self._fixture_path)["hashicorp_vault"]
        creds = dict(raw.get("credentials") or {})
        self.state = {
            "credentials": creds,
            "kv_mount": str(raw.get("kv_mount") or "secret").strip("/"),
            "secrets": copy.deepcopy(raw.get("secrets") or {}),
            "valid_tokens": {str(creds.get("token") or "e2e-vault-token-001")},
            "token_counter": 0,
            "required_namespace": None,
            "allow_list_verb": True,
            "sealed": False,
        }

    def set_required_namespace(self, namespace: str | None) -> None:
        with self._lock:
            self.state["required_namespace"] = namespace

    def set_allow_list_verb(self, allowed: bool) -> None:
        with self._lock:
            self.state["allow_list_verb"] = bool(allowed)

    def set_sealed(self, sealed: bool) -> None:
        with self._lock:
            self.state["sealed"] = bool(sealed)

    def _check_namespace_locked(self, headers: Mapping[str, str]) -> bool:
        req_ns = self.state.get("required_namespace")
        if not req_ns:
            return True
        return _header_ci(headers, "X-Vault-Namespace").strip() == str(req_ns).strip()

    def _check_token_locked(self, headers: Mapping[str, str]) -> str | None:
        tok = _header_ci(headers, "X-Vault-Token").strip()
        if tok and tok in self.state["valid_tokens"]:
            return tok
        return None

    def _list_keys_locked(self, prefix: str) -> list[str] | None:
        clean_prefix = prefix.strip("/")
        secrets: dict[str, dict[str, Any]] = self.state["secrets"]
        children: set[str] = set()
        for secret_path in secrets:
            norm = secret_path.strip("/")
            if not clean_prefix:
                parts = norm.split("/", 1)
                children.add(f"{parts[0]}/" if len(parts) > 1 else parts[0])
            elif norm.startswith(clean_prefix + "/"):
                rem = norm[len(clean_prefix) + 1 :]
                if not rem:
                    continue
                parts = rem.split("/", 1)
                children.add(f"{parts[0]}/" if len(parts) > 1 else parts[0])
        if not children:
            return None
        return sorted(children)

    def _route_locked(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> tuple[int, Any, dict[str, str]]:
        if path == "/v1/sys/health" and method == "GET":
            if self.state["sealed"]:
                return 503, {"initialized": True, "sealed": True}, {}
            return 200, {"initialized": True, "sealed": False}, {}

        if not self._check_namespace_locked(headers):
            return 403, {"errors": ["permission denied: namespace mismatch"]}, {}

        m_login = re.match(r"^/v1/auth/([^/]+)/login$", path)
        if m_login and method == "POST":
            body = json_body if isinstance(json_body, dict) else {}
            role_id = str(body.get("role_id") or "")
            secret_id = str(body.get("secret_id") or "")
            creds = self.state["credentials"]
            if role_id == creds.get("role_id") and secret_id == creds.get("secret_id"):
                self.state["token_counter"] += 1
                tok = f"e2e-vault-approle-{self.state['token_counter']}"
                self.state["valid_tokens"].add(tok)
                return (
                    200,
                    {"auth": {"client_token": tok, "lease_duration": 3600, "renewable": True}},
                    {},
                )
            return 400, {"errors": ["invalid role or secret ID"]}, {}

        tok = self._check_token_locked(headers)
        if tok is None:
            return 403, {"errors": ["permission denied"]}, {}

        if path == "/v1/auth/token/lookup-self" and method == "GET":
            return (
                200,
                {
                    "data": {
                        "id": tok,
                        "display_name": "e2e-vault-token",
                        "policies": ["default", "soclens-read"],
                        "ttl": 3600,
                    }
                },
                {},
            )

        kv_mount = self.state["kv_mount"]
        meta_prefix = f"/v1/{kv_mount}/metadata"
        if path == meta_prefix or path.startswith(meta_prefix + "/"):
            is_list_get = method == "GET" and _parse_bool_param(query, "list", False)
            if method == "LIST" and not self.state["allow_list_verb"]:
                return 405, {"errors": ["method not allowed"]}, {}
            if method == "LIST" or is_list_get:
                sub = path[len(meta_prefix) :].strip("/")
                keys = self._list_keys_locked(sub)
                if keys is None:
                    return 404, {"errors": []}, {}
                return 200, {"data": {"keys": keys}}, {}

        subkeys_prefix = f"/v1/{kv_mount}/subkeys/"
        if path.startswith(subkeys_prefix) and method == "GET":
            secret_path = path[len(subkeys_prefix) :].strip("/")
            secret_data = self.state["secrets"].get(secret_path)
            if secret_data is None:
                return 404, {"errors": []}, {}
            return (
                200,
                {
                    "data": {
                        "subkeys": dict.fromkeys(secret_data, None),
                        "metadata": {"version": 1},
                    }
                },
                {},
            )

        data_prefix = f"/v1/{kv_mount}/data/"
        if path.startswith(data_prefix) and method == "GET":
            secret_path = path[len(data_prefix) :].strip("/")
            secret_data = self.state["secrets"].get(secret_path)
            if secret_data is None:
                return 404, {"errors": []}, {}
            return (
                200,
                {
                    "data": {
                        "data": copy.deepcopy(secret_data),
                        "metadata": {"version": 1, "created_time": "2026-11-25T00:00:00Z"},
                    }
                },
                {},
            )

        return 404, {"errors": [f"unsupported path {method} {path}"]}, {}


# ======================================================================
# 3. 1Password Connect Mock
# ======================================================================


class MockOnePasswordConnectServer(_BaseV21MockServer):
    """Stateful local 1Password Connect REST API mock."""

    def __init__(self, fixture_path: Path | None = None) -> None:
        self._fixture_path = fixture_path
        super().__init__()

    def _reset_state_locked(self) -> None:
        raw = _load_fixture("v21_secret_stores.json", self._fixture_path)["onepassword_connect"]
        tok = str((raw.get("credentials") or {}).get("token") or "e2e-op-connect-token-001")
        self.state = {
            "valid_tokens": {tok},
            "vaults": copy.deepcopy(raw.get("vaults") or []),
            "items": copy.deepcopy(raw.get("items") or []),
        }

    def _handle_request(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> None:
        if path == "/heartbeat" and method == "GET":
            self._send_raw(handler, 200, b"1", "text/plain; charset=utf-8")
            return
        super()._handle_request(
            handler,
            method=method,
            path=path,
            query=query,
            headers=headers,
            json_body=json_body,
            form_data=form_data,
        )

    def _route_locked(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> tuple[int, Any, dict[str, str]]:
        auth = _header_ci(headers, "Authorization")
        if not auth.startswith("Bearer ") or auth[7:].strip() not in self.state["valid_tokens"]:
            return 401, {"status": 401, "message": "Invalid bearer token"}, {}

        if path == "/v1/vaults" and method == "GET":
            vaults_out = []
            for v in self.state["vaults"]:
                count = sum(1 for it in self.state["items"] if it.get("vault", {}).get("id") == v["id"])
                vaults_out.append(
                    {
                        "id": v["id"],
                        "name": v["name"],
                        "attributeVersion": 1,
                        "contentVersion": 1,
                        "items": count,
                    }
                )
            return 200, vaults_out, {}

        m_vault = re.match(r"^/v1/vaults/([^/]+)$", path)
        if m_vault and method == "GET":
            vid = urllib.parse.unquote(m_vault.group(1))
            vault = next((v for v in self.state["vaults"] if v["id"] == vid), None)
            if vault is None:
                return 404, {"status": 404, "message": "Vault not found"}, {}
            count = sum(1 for it in self.state["items"] if it.get("vault", {}).get("id") == vid)
            return (
                200,
                {
                    "id": vault["id"],
                    "name": vault["name"],
                    "attributeVersion": 1,
                    "contentVersion": 1,
                    "items": count,
                },
                {},
            )

        m_items = re.match(r"^/v1/vaults/([^/]+)/items$", path)
        if m_items and method == "GET":
            vid = urllib.parse.unquote(m_items.group(1))
            if not any(v["id"] == vid for v in self.state["vaults"]):
                return 404, {"status": 404, "message": "Vault not found"}, {}
            summaries = [
                {
                    "id": it["id"],
                    "title": it["title"],
                    "vault": {"id": vid},
                    "category": it.get("category", "API_CREDENTIAL"),
                    "tags": list(it.get("tags") or []),
                }
                for it in self.state["items"]
                if it.get("vault", {}).get("id") == vid
            ]
            return 200, summaries, {}

        m_item = re.match(r"^/v1/vaults/([^/]+)/items/([^/]+)$", path)
        if m_item and method == "GET":
            vid = urllib.parse.unquote(m_item.group(1))
            iid = urllib.parse.unquote(m_item.group(2))
            item = next(
                (
                    it
                    for it in self.state["items"]
                    if it.get("vault", {}).get("id") == vid and it["id"] == iid
                ),
                None,
            )
            if item is None:
                return 404, {"status": 404, "message": "Item not found"}, {}
            return 200, copy.deepcopy(item), {}

        return 404, {"status": 404, "message": f"Not found: {method} {path}"}, {}


# ======================================================================
# 4. Bitwarden `bw serve` Mock
# ======================================================================


class MockBitwardenServer(_BaseV21MockServer):
    """Stateful local Bitwarden CLI `bw serve` mock."""

    def __init__(self, fixture_path: Path | None = None) -> None:
        self._fixture_path = fixture_path
        super().__init__()

    def _reset_state_locked(self) -> None:
        raw = _load_fixture("v21_secret_stores.json", self._fixture_path)["bitwarden"]
        creds = dict(raw.get("credentials") or {})
        self.state = {
            "lock_status": "unlocked",
            "valid_master_password": str(creds.get("master_password") or "e2e-bw-master-password"),
            "user_email": str(creds.get("user_email") or "analyst@example.test"),
            "items": copy.deepcopy(raw.get("items") or []),
            "sync_count": 0,
        }

    def set_lock_status(self, status: str) -> None:
        with self._lock:
            self.state["lock_status"] = status

    def _route_locked(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> tuple[int, Any, dict[str, str]]:
        if path == "/status" and method == "GET":
            return (
                200,
                {
                    "success": True,
                    "data": {
                        "template": {
                            "status": self.state["lock_status"],
                            "userEmail": self.state["user_email"],
                            "serverUrl": "https://bw.example.test",
                            "lastSync": "2026-11-25T00:00:00.000Z",
                        }
                    },
                },
                {},
            )

        if path == "/unlock" and method == "POST":
            if self.state["lock_status"] == "unauthenticated":
                return 400, {"success": False, "message": "You are not logged in."}, {}
            body = json_body if isinstance(json_body, dict) else {}
            pw = str(body.get("password") or "")
            if pw and pw == self.state["valid_master_password"]:
                self.state["lock_status"] = "unlocked"
                return (
                    200,
                    {"success": True, "data": {"noColor": False, "title": "Your vault is now unlocked!"}},
                    {},
                )
            return 400, {"success": False, "message": "Invalid master password."}, {}

        if self.state["lock_status"] != "unlocked":
            return 400, {"success": False, "message": "Vault is locked."}, {}

        if path == "/sync" and method == "POST":
            self.state["sync_count"] += 1
            return (
                200,
                {"success": True, "data": {"noColor": False, "title": "Syncing complete."}},
                {},
            )

        if path == "/list/object/items" and method == "GET":
            folder_id = (query.get("folderid") or [""])[0].strip()
            collection_id = (query.get("collectionid") or [""])[0].strip()
            org_id = (query.get("organizationid") or [""])[0].strip()
            search = (query.get("search") or [""])[0].strip().lower()

            matched: list[dict[str, Any]] = []
            for item in self.state["items"]:
                if folder_id and str(item.get("folderId") or "") != folder_id:
                    continue
                if collection_id and collection_id not in (item.get("collectionIds") or []):
                    continue
                if org_id and str(item.get("organizationId") or "") != org_id:
                    continue
                if search:
                    parts = [
                        str(item.get("name") or ""),
                        str(item.get("notes") or ""),
                        str((item.get("login") or {}).get("username") or ""),
                    ]
                    for fld in item.get("fields") or []:
                        parts.append(str(fld.get("name") or ""))
                    if search not in " ".join(parts).lower():
                        continue
                matched.append(copy.deepcopy(item))

            return 200, {"success": True, "data": {"object": "list", "data": matched}}, {}

        m_item = re.match(r"^/object/item/([^/]+)$", path)
        if m_item and method == "GET":
            iid = urllib.parse.unquote(m_item.group(1))
            item = next((it for it in self.state["items"] if it["id"] == iid), None)
            if item is None:
                return 404, {"success": False, "message": "Not found."}, {}
            return 200, {"success": True, "data": copy.deepcopy(item)}, {}

        return 404, {"success": False, "message": f"Unknown route: {method} {path}"}, {}


# ======================================================================
# 5. Local LLM (Ollama + OpenAI-Compatible) Mock
# ======================================================================


class MockLocalLLMServer(_BaseV21MockServer):
    """Stateful local LLM mock supporting Ollama and OpenAI-compatible endpoints."""

    def __init__(self, fixture_path: Path | None = None) -> None:
        self._fixture_path = fixture_path
        super().__init__()
        self.ollama_base_url: str = self.base_url
        self.openai_base_url: str = f"{self.base_url}/v1"

    def _reset_state_locked(self) -> None:
        raw = _load_fixture("v21_llm.json", self._fixture_path)
        self.state = {
            "ollama_models": copy.deepcopy(raw.get("ollama_models") or []),
            "openai_models": copy.deepcopy(raw.get("openai_models") or []),
            "canned_responses": copy.deepcopy(raw.get("canned_responses") or {}),
            "queued_responses": [],
            "required_api_key": None,
        }

    def set_required_api_key(self, key: str | None) -> None:
        with self._lock:
            self.state["required_api_key"] = key

    def queue_response(self, content: str, chunks: list[str] | None = None) -> None:
        with self._lock:
            self.state["queued_responses"].append(
                {
                    "content": content,
                    "chunks": list(chunks) if chunks is not None else [content],
                }
            )

    def _select_reply_locked(self, messages: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        queued: list[dict[str, Any]] = self.state["queued_responses"]
        if queued:
            return queued.pop(0)
        joined = " ".join(str(m.get("content") or "") for m in messages)
        canned = self.state["canned_responses"]
        if "[ES + Tenant" in joined or "Splunk ES Finding" in joined or "Closing Note" in joined:
            if "copilot_triage" in canned:
                return copy.deepcopy(canned["copilot_triage"])
        return copy.deepcopy(
            canned.get("default")
            or {
                "content": "Synthetic SOC copilot summary.",
                "chunks": ["Synthetic SOC ", "copilot summary."],
            }
        )

    def _handle_request(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> None:
        with self._lock:
            req_key = self.state.get("required_api_key")
            if path.startswith("/v1/") and req_key:
                auth = _header_ci(headers, "Authorization")
                if not auth.startswith("Bearer ") or auth[7:].strip() != req_key:
                    self._send_json(
                        handler,
                        401,
                        {"error": {"message": "Invalid API key", "type": "authentication_error"}},
                    )
                    return

            if path == "/api/tags" and method == "GET":
                models = [
                    {"name": m["name"], "model": m.get("model", m["name"]), "size": m.get("size", 1024)}
                    for m in self.state["ollama_models"]
                ]
                self._send_json(handler, 200, {"models": models})
                return

            if path == "/v1/models" and method == "GET":
                data = [
                    {"id": m["id"], "object": "model", "owned_by": m.get("owned_by", "local.example.test")}
                    for m in self.state["openai_models"]
                ]
                self._send_json(handler, 200, {"object": "list", "data": data})
                return

            if path == "/api/chat" and method == "POST":
                body = json_body if isinstance(json_body, dict) else {}
                messages = body.get("messages")
                if not isinstance(messages, list) or not messages:
                    self._send_json(handler, 400, {"error": "messages must not be empty"})
                    return
                model = str(body.get("model") or "llama3.2:latest")
                stream = bool(body.get("stream", False))
                reply = self._select_reply_locked(messages)
                if not stream:
                    self._send_json(
                        handler,
                        200,
                        {
                            "model": model,
                            "created_at": _now_iso(),
                            "message": {"role": "assistant", "content": reply["content"]},
                            "done": True,
                        },
                    )
                    return
                chunks = list(reply.get("chunks") or [reply["content"]])
                lines = [
                    json.dumps(
                        {
                            "model": model,
                            "created_at": _now_iso(),
                            "message": {"role": "assistant", "content": chunk},
                            "done": False,
                        }
                    )
                    for chunk in chunks
                ]
                lines.append(
                    json.dumps(
                        {
                            "model": model,
                            "created_at": _now_iso(),
                            "message": {"role": "assistant", "content": ""},
                            "done": True,
                        }
                    )
                )
                raw = ("\n".join(lines) + "\n").encode("utf-8")
                self._send_raw(handler, 200, raw, "application/x-ndjson")
                return

            if path == "/v1/chat/completions" and method == "POST":
                body = json_body if isinstance(json_body, dict) else {}
                messages = body.get("messages")
                if not isinstance(messages, list) or not messages:
                    self._send_json(
                        handler,
                        400,
                        {"error": {"message": "messages must not be empty", "type": "invalid_request_error"}},
                    )
                    return
                model = str(body.get("model") or "qwen2.5-coder:7b")
                stream = bool(body.get("stream", False))
                reply = self._select_reply_locked(messages)
                if not stream:
                    self._send_json(
                        handler,
                        200,
                        {
                            "id": "chatcmpl-e2e-1",
                            "object": "chat.completion",
                            "model": model,
                            "choices": [
                                {
                                    "index": 0,
                                    "message": {"role": "assistant", "content": reply["content"]},
                                    "finish_reason": "stop",
                                }
                            ],
                        },
                    )
                    return
                chunks = list(reply.get("chunks") or [reply["content"]])
                events = [
                    "data: "
                    + json.dumps(
                        {
                            "id": "chatcmpl-e2e-1",
                            "object": "chat.completion.chunk",
                            "model": model,
                            "choices": [
                                {"index": 0, "delta": {"content": chunk}, "finish_reason": None}
                            ],
                        }
                    )
                    for chunk in chunks
                ]
                events.append(
                    "data: "
                    + json.dumps(
                        {
                            "id": "chatcmpl-e2e-1",
                            "object": "chat.completion.chunk",
                            "model": model,
                            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                        }
                    )
                )
                events.append("data: [DONE]")
                raw = ("\n\n".join(events) + "\n\n").encode("utf-8")
                self._send_raw(handler, 200, raw, "text/event-stream")
                return

        self._send_json(handler, 404, {"error": f"Unknown LLM endpoint: {method} {path}"})


# ======================================================================
# 6. Splunk ES 8.6 Mission Control v2 + 7.x Fallback Mock
# ======================================================================


class MockSplunkESServer(_BaseV21MockServer):
    """Stateful local Splunk ES 8.6 MC v2 + 7.x SPL/REST mock server."""

    def __init__(
        self,
        fixture_path: Path | None = None,
        *,
        valid_tokens: Iterable[str] | None = None,
        valid_basic_users: dict[str, str] | None = None,
        ignore_unknown_finding_params: bool = True,
        incident_review_404_fallback: bool = True,
        mc_v2_enabled: bool = True,
    ) -> None:
        self._fixture_path = fixture_path
        self.valid_tokens: set[str] = (
            set(valid_tokens) if valid_tokens is not None else {"test-splunk-token"}
        )
        self.valid_basic_users: dict[str, str] = (
            dict(valid_basic_users)
            if valid_basic_users is not None
            else {"soc_analyst": "test-splunk-password"}
        )
        self._init_ignore_unknown = ignore_unknown_finding_params
        self._init_incident_review_404 = incident_review_404_fallback
        self._init_mc_v2_enabled = mc_v2_enabled
        super().__init__()

    def _reset_state_locked(self) -> None:
        raw = _load_fixture("v21_splunk_es.json", self._fixture_path)
        self.state = {
            **raw,
            "jobs": {},
            "default_job_mode": "done",
            "job_counter": 0,
            "id_counter": 0,
            "ignore_unknown_finding_params": self._init_ignore_unknown,
            "incident_review_404_fallback": self._init_incident_review_404,
            "mc_v2_enabled": self._init_mc_v2_enabled,
        }

    def set_mc_v2_enabled(self, enabled: bool) -> None:
        with self._lock:
            self.state["mc_v2_enabled"] = bool(enabled)

    def set_ignore_unknown_finding_params(self, enabled: bool) -> None:
        with self._lock:
            self.state["ignore_unknown_finding_params"] = bool(enabled)

    def set_incident_review_404_fallback(self, enabled: bool) -> None:
        with self._lock:
            self.state["incident_review_404_fallback"] = bool(enabled)

    def set_job_behavior(
        self,
        mode: str = "done",
        results: list[dict[str, Any]] | None = None,
    ) -> None:
        with self._lock:
            self.state["default_job_mode"] = mode
            if results is not None:
                self.state["default_job_results"] = list(results)

    def _mc_error(self, code: str, message: str) -> dict[str, str]:
        return {"code": code, "request_id": str(uuid.uuid4()), "message": message}

    def _default_fault_body(self, path: str, status_code: int) -> Any:
        if path.startswith("/servicesNS/nobody/missioncontrol/public/v2"):
            code = "MC_0017" if status_code == 429 else f"MC_{status_code:04d}"
            msg = "Rate limit exceeded" if status_code == 429 else f"HTTP {status_code}"
            return self._mc_error(code, msg)
        return {"messages": [{"type": "ERROR", "text": f"HTTP {status_code}"}]}

    def _check_auth_locked(self, headers: Mapping[str, str]) -> str | None:
        auth = _header_ci(headers, "Authorization")
        if auth.startswith("Bearer "):
            tok = auth[7:].strip()
            if tok and tok in self.valid_tokens:
                return "soc_analyst"
            return None
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:].strip(), validate=True).decode("utf-8")
                if ":" not in decoded:
                    return None
                user, pwd = decoded.split(":", 1)
                if not user.strip() or not pwd.strip():
                    return None
                if user in self.valid_basic_users and self.valid_basic_users[user] == pwd:
                    return user
                return None
            except Exception:
                return None
        return None

    def _find_finding_locked(self, record_id: str) -> dict[str, Any] | None:
        target = record_id.strip()
        for fnd in self.state["findings"]:
            if fnd.get("event_id") == target or fnd.get("finding_id") == target:
                return fnd
        return None

    def _find_investigation_locked(self, inv_id: str) -> dict[str, Any] | None:
        target = inv_id.strip()
        for inv in self.state["investigations"]:
            if inv.get("investigation_guid") == target or inv.get("investigation_id") == target:
                return inv
        return None

    def _record_history_locked(
        self,
        object_id: str,
        *,
        user: str,
        message: str,
        short_description: str,
        change: str,
        category: str = "investigation",
        finding_id: str = "",
    ) -> None:
        hist_map: dict[str, list[dict[str, Any]]] = self.state.setdefault("history", {})
        hist_map.setdefault(object_id, []).append(
            {
                "_time": _now_iso(),
                "finding_id": finding_id or object_id,
                "object_id": object_id,
                "user": user,
                "request_id": f"req-{uuid.uuid4().hex[:8]}",
                "message": message,
                "short_description": short_description,
                "change": change,
                "category": category,
            }
        )

    def _apply_status_update(self, target: dict[str, Any], status_val: Any) -> None:
        raw = str(status_val).strip()
        if not raw:
            return
        lower = raw.lower()
        if raw in _ES_STATUS_CODE_TO_LABEL:
            code = raw
            label = _ES_STATUS_CODE_TO_LABEL[raw]
        elif lower in _ES_STATUS_LABEL_TO_CODE:
            code = _ES_STATUS_LABEL_TO_CODE[lower]
            label = _ES_STATUS_CODE_TO_LABEL[code]
        else:
            code = raw
            label = raw
        target["status"] = code
        target["status_label"] = label
        target["status_name"] = label

    def _apply_disposition_update(self, target: dict[str, Any], disp_val: Any) -> None:
        raw = str(disp_val).strip()
        if not raw:
            return
        label = _ES_DISPOSITION_LABELS.get(raw.lower(), raw)
        target["disposition"] = raw
        target["disposition_label"] = label
        target["disposition_name"] = label

    def _evaluate_spl_search_locked(self, spl: str) -> list[dict[str, Any]]:
        clean = spl.strip()
        m_loadjob = re.search(r'\|\s*loadjob\s+"?([^"\s|]+)"?', clean, flags=re.IGNORECASE)
        if m_loadjob:
            sid = m_loadjob.group(1)
            return copy.deepcopy(self.state.get("jobs_by_sid", {}).get(sid, []))

        lower = clean.lower()
        if "cim_modactions" in lower or "modular_action_invocations" in lower:
            rows = copy.deepcopy(self.state.get("modaction_invocations", []))
            m_sid = re.search(r'(?:orig_sid|sid)="([^"]+)"', clean)
            if m_sid:
                rows = [
                    r
                    for r in rows
                    if r.get("sid") == m_sid.group(1) or r.get("orig_sid") == m_sid.group(1)
                ]
            return rows

        if "asset_lookup_by_str" in lower:
            return copy.deepcopy(self.state.get("asset_lookup_rows", []))

        if "identity_lookup_expanded" in lower:
            return copy.deepcopy(self.state.get("identity_lookup_rows", []))

        if "index=risk" in lower:
            rows = copy.deepcopy(self.state.get("risk_events", []))
            m_ro = re.search(r'risk_object="([^"]+)"', clean)
            if m_ro:
                rows = [r for r in rows if r.get("risk_object") == m_ro.group(1)]
            return rows

        if "`notable`" in lower or "notable" in lower:
            rows = copy.deepcopy(self.state.get("findings", []))
            m_urg = re.search(r'urgency="([^"]+)"', clean)
            if m_urg:
                rows = [r for r in rows if str(r.get("urgency", "")).lower() == m_urg.group(1).lower()]
            m_st = re.search(r'status=(\d+)', clean)
            if m_st:
                rows = [r for r in rows if str(r.get("status", "")) == m_st.group(1)]
            m_own = re.search(r'owner="([^"]+)"', clean)
            if m_own:
                rows = [r for r in rows if str(r.get("owner", "")) == m_own.group(1)]
            m_orig_sid = re.search(r'orig_sid="([^"]+)"', clean)
            if m_orig_sid:
                rows = [r for r in rows if str(r.get("orig_sid", "")) == m_orig_sid.group(1)]
            m_raw = re.search(r'_raw="\*?([^*"]+)\*?"', clean)
            if m_raw:
                needle = m_raw.group(1).lower()
                rows = [r for r in rows if needle in str(r.get("_raw", "")).lower()]
            m_ten = re.search(r'(?:tenant_id|org_id|client_code|customer_id)="([^"]+)"', clean)
            if m_ten:
                ten = m_ten.group(1)
                rows = [
                    r
                    for r in rows
                    if any(
                        str(v) == ten
                        for k, v in r.items()
                        if k.lower() in {"tenant_id", "org_id", "client_code", "customer_id"}
                    )
                ]
            m_head = re.search(r"\|\s*head\s+(\d+)", clean, flags=re.IGNORECASE)
            if m_head:
                rows = rows[: int(m_head.group(1))]
            return rows

        return copy.deepcopy(self.state.get("default_job_results", []))

    def _route_locked(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> tuple[int, Any, dict[str, str]]:
        mc_prefix = "/servicesNS/nobody/missioncontrol/public/v2"
        is_mc = path.startswith(mc_prefix)

        auth_user = self._check_auth_locked(headers)
        if auth_user is None:
            if is_mc:
                return 401, None, {}
            return 401, {"messages": [{"type": "ERROR", "text": "Unauthorized"}]}, {}

        if is_mc:
            if not self.state["mc_v2_enabled"]:
                return (
                    404,
                    self._mc_error("MC_0404", "Mission Control v2 API not available (ES 7.x mode)"),
                    {},
                )
            subpath = path[len(mc_prefix) :]
            return self._route_mc_v2_locked(
                method=method,
                subpath=subpath,
                query=query,
                json_body=json_body,
                auth_user=auth_user,
            )

        return self._route_legacy_splunk_locked(
            method=method,
            path=path,
            query=query,
            form_data=form_data,
            json_body=json_body,
            auth_user=auth_user,
        )

    def _route_mc_v2_locked(
        self,
        *,
        method: str,
        subpath: str,
        query: dict[str, list[str]],
        json_body: Any,
        auth_user: str,
    ) -> tuple[int, Any, dict[str, str]]:
        if subpath == "/findings" and method == "GET":
            unknown_params = [k for k in query if k not in _MC_VALID_FINDINGS_QUERY_PARAMS]
            if unknown_params and not self.state["ignore_unknown_finding_params"]:
                return (
                    400,
                    self._mc_error("MC_0100", f"Unsupported query parameter(s): {', '.join(unknown_params)}"),
                    {},
                )
            findings = copy.deepcopy(self.state["findings"])
            if "search_finding_groups" in query:
                include_groups = _parse_bool_param(query, "search_finding_groups", True)
                if not include_groups:
                    findings = [f for f in findings if f.get("notable_type") != "finding_group"]
            finding_ids = set(_split_csv_param(query, "finding_ids"))
            if finding_ids:
                findings = [
                    f
                    for f in findings
                    if f.get("event_id") in finding_ids or f.get("finding_id") in finding_ids
                ]
            if "urgency" in query and query["urgency"][0].strip():
                urg = query["urgency"][0].strip().lower()
                findings = [f for f in findings if str(f.get("urgency", "")).lower() == urg]
            if "status" in query and query["status"][0].strip():
                st = query["status"][0].strip().lower()
                st_code = _ES_STATUS_LABEL_TO_CODE.get(st, st)
                findings = [
                    f
                    for f in findings
                    if str(f.get("status", "")).lower() == st_code
                    or str(f.get("status_label", "")).lower() == st
                ]
            if "owner" in query and query["owner"][0].strip():
                own = query["owner"][0].strip()
                findings = [f for f in findings if str(f.get("owner", "")) == own]
            if "disposition" in query and query["disposition"][0].strip():
                disp = query["disposition"][0].strip().lower()
                findings = [f for f in findings if str(f.get("disposition", "")).lower() == disp]
            if "rule_title" in query and query["rule_title"][0].strip():
                rt = query["rule_title"][0].strip().lower()
                findings = [f for f in findings if rt in str(f.get("rule_title", "")).lower()]

            try:
                offset = max(0, int((query.get("offset") or ["0"])[0]))
            except ValueError:
                offset = 0
            try:
                limit = max(1, int((query.get("limit") or ["100"])[0]))
            except ValueError:
                limit = 100
            total = len(findings)
            sliced = findings[offset : offset + limit]
            fields_req = set(_split_csv_param(query, "fields"))
            if fields_req:
                fields_req.update({"_time", "event_id", "finding_id"})
                sliced = [{k: v for k, v in f.items() if k in fields_req} for f in sliced]
            return 200, {"items": sliced, "offset": offset, "limit": limit, "total": total}, {}

        if subpath == "/findings" and method == "POST":
            body = json_body if isinstance(json_body, dict) else {}
            rule_title = str(body.get("rule_title") or "").strip()
            sec_domain = str(body.get("security_domain") or "").strip()
            if not rule_title or not sec_domain:
                return 400, self._mc_error("MC_0100", "rule_title and security_domain are required"), {}
            self.state["id_counter"] += 1
            n = self.state["id_counter"]
            eid = f"fnd-manual-{n}"
            fid = f"{eid}@@notable@@{uuid.uuid4().hex[:8]}"
            now = _now_iso()
            record: dict[str, Any] = {
                "event_id": eid,
                "finding_id": fid,
                "_time": now,
                "create_time": now,
                "update_time": now,
                "rule_title": rule_title,
                "rule_name": rule_title,
                "rule_description": str(body.get("rule_description") or ""),
                "security_domain": sec_domain,
                "risk_object": str(body.get("risk_object") or ""),
                "risk_object_type": str(body.get("risk_object_type") or "other"),
                "risk_score": str(body.get("risk_score") if body.get("risk_score") is not None else "0"),
                "urgency": str(body.get("urgency") or "medium").lower(),
                "owner": str(body.get("owner") or "unassigned"),
                "owner_realname": str(body.get("owner") or "unassigned"),
                "creator": auth_user,
                "queue_id": str(body.get("queue_id") or "__system_default_queue__"),
                "investigation_type": str(body.get("investigation_type") or "default"),
                "notable_type": "notable",
            }
            self._apply_status_update(record, body.get("status") or "1")
            self._apply_disposition_update(record, body.get("disposition") or "disposition:6")
            add_fields = body.get("additional_fields")
            if isinstance(add_fields, list):
                for af in add_fields:
                    if isinstance(af, dict) and af.get("name"):
                        record[str(af["name"])] = af.get("value")
            self.state["findings"].append(record)
            return (
                201,
                {
                    "_time": now,
                    "finding_id": fid,
                    "event_id": eid,
                    "risk_object": record["risk_object"],
                    "risk_object_type": record["risk_object_type"],
                    "risk_score": record["risk_score"],
                    "creator": auth_user,
                    "status": record["status"],
                    "urgency": record["urgency"],
                    "disposition": record["disposition"],
                    "owner_realname": record["owner_realname"],
                    "queue_id": record["queue_id"],
                    "investigation_type": record["investigation_type"],
                },
                {},
            )

        if subpath == "/findings/bulk_create" and method == "POST":
            if not isinstance(json_body, list):
                return 400, {"status": "error", "errors": [{"error": "Expected list payload"}]}, {}
            created_items: list[dict[str, Any]] = []
            errors: list[dict[str, Any]] = []
            for idx, entry in enumerate(json_body):
                status_c, payload_c, _ = self._route_mc_v2_locked(
                    method="POST",
                    subpath="/findings",
                    query={},
                    json_body=entry,
                    auth_user=auth_user,
                )
                if status_c == 201:
                    created_items.append(payload_c)
                else:
                    errors.append({"index": idx, "error": payload_c.get("message", "Invalid item")})
            if not created_items and errors:
                return 400, {"status": "error", "errors": errors}, {}
            return (
                201,
                {
                    "status": "success" if not errors else "partial_success",
                    "created": len(created_items),
                    "failed": len(errors),
                    "findings": created_items,
                    "errors": errors,
                },
                {},
            )

        m_fnd = re.match(r"^/findings/([^/]+)$", subpath)
        if m_fnd and method == "GET":
            fid = urllib.parse.unquote(m_fnd.group(1))
            fnd = self._find_finding_locked(fid)
            if fnd is None:
                return 404, self._mc_error("MC_0404", f"Finding not found: {fid}"), {}
            out = copy.deepcopy(fnd)
            fields_req = set(_split_csv_param(query, "fields"))
            if fields_req:
                fields_req.update({"_time", "event_id", "finding_id"})
                out = {k: v for k, v in out.items() if k in fields_req}
            return 200, out, {}

        if subpath == "/investigations" and method == "GET":
            invs = copy.deepcopy(self.state["investigations"])
            ids_filter = set(_split_csv_param(query, "ids"))
            if ids_filter:
                invs = [
                    inv
                    for inv in invs
                    if inv.get("investigation_guid") in ids_filter
                    or inv.get("investigation_id") in ids_filter
                ]
            for key in ("status", "urgency", "owner", "disposition", "sensitivity"):
                if key in query and query[key][0].strip():
                    val = query[key][0].strip().lower()
                    invs = [inv for inv in invs if str(inv.get(key, "")).lower() == val]
            if "normalized_risk_object" in query and query["normalized_risk_object"][0].strip():
                ro = query["normalized_risk_object"][0].strip().lower()
                invs = [
                    inv
                    for inv in invs
                    if ro in str(inv.get("normalized_risk_object", "")).lower()
                    or ro in str(inv.get("name", "")).lower()
                ]
            try:
                offset = max(0, int((query.get("offset") or ["0"])[0]))
            except ValueError:
                offset = 0
            try:
                limit = max(1, int((query.get("limit") or ["100"])[0]))
            except ValueError:
                limit = 100
            return 200, invs[offset : offset + limit], {}

        if subpath == "/investigations" and method == "POST":
            body = json_body if isinstance(json_body, dict) else {}
            name = str(body.get("name") or "").strip()
            if not name:
                return 400, self._mc_error("MC_0100", "name is required"), {}
            self.state["id_counter"] += 1
            n = self.state["id_counter"]
            guid = f"inv-guid-{n}"
            now = _now_iso()
            finding_ids = list(body.get("finding_ids") or [])
            inv: dict[str, Any] = {
                "investigation_guid": guid,
                "investigation_id": f"ES-{2000 + n}",
                "name": name,
                "description": str(body.get("description") or ""),
                "investigation_type": str(body.get("investigation_type") or "default"),
                "status": str(body.get("status") or "1"),
                "status_name": _ES_STATUS_CODE_TO_LABEL.get(str(body.get("status") or "1"), str(body.get("status") or "New")),
                "urgency": str(body.get("urgency") or "medium").lower(),
                "owner": str(body.get("owner") or "unassigned"),
                "disposition": str(body.get("disposition") or "disposition:6"),
                "sensitivity": str(body.get("sensitivity") or "Amber"),
                "queue_id": str(body.get("queue_id") or "__system_default_queue__"),
                "findings": {"incident_ids": finding_ids},
                "count_findings": len(finding_ids),
                "create_time": now,
                "update_time": now,
            }
            self.state["investigations"].append(inv)
            self._record_history_locked(
                guid,
                user=auth_user,
                message=f"Investigation '{name}' created.",
                short_description="Investigation created",
                change="created",
            )
            return 201, {"investigation_guid": guid}, {}

        if subpath == "/investigations/bulk_update" and method == "POST":
            body = json_body if isinstance(json_body, dict) else {}
            record_ids = body.get("record_ids")
            aq_sid = body.get("aq_sid")
            if record_ids is not None and not isinstance(record_ids, list):
                return (
                    400,
                    self._mc_error("MC_0100", "record_ids must be a list"),
                    {},
                )
            has_records = isinstance(record_ids, list) and len(record_ids) > 0
            aq_sid_clean = aq_sid.strip() if isinstance(aq_sid, str) else ""
            has_aq_sid = isinstance(aq_sid, str) and bool(aq_sid_clean)
            if has_records == has_aq_sid:
                return (
                    400,
                    self._mc_error("MC_0100", "Provide either record_ids or aq_sid (mutually exclusive)"),
                    {},
                )
            if has_records and isinstance(record_ids, list):
                ids_to_update = [str(r) for r in record_ids]
            else:
                ids_to_update = []
                job = self.state.get("jobs", {}).get(aq_sid_clean)
                if isinstance(job, dict):
                    for row in job.get("results") or []:
                        if isinstance(row, dict):
                            cand = str(row.get("event_id") or row.get("finding_id") or "").strip()
                            if (
                                cand
                                and (
                                    self._find_finding_locked(cand) is not None
                                    or self._find_investigation_locked(cand) is not None
                                )
                                and cand not in ids_to_update
                            ):
                                ids_to_update.append(cand)
                if not ids_to_update:
                    for fnd in self.state["findings"]:
                        if str(fnd.get("orig_sid") or "") == aq_sid_clean:
                            eid = str(fnd.get("event_id") or "").strip()
                            if eid and eid not in ids_to_update:
                                ids_to_update.append(eid)
            results: list[dict[str, Any]] = []
            has_error = False
            for rid in ids_to_update:
                target = self._find_finding_locked(rid) or self._find_investigation_locked(rid)
                if target is None:
                    has_error = True
                    results.append({"error": f"Record not found: {rid}"})
                    continue
                if "status" in body:
                    self._apply_status_update(target, body["status"])
                if "urgency" in body:
                    target["urgency"] = str(body["urgency"]).lower()
                if "owner" in body:
                    target["owner"] = str(body["owner"])
                    target["owner_realname"] = str(body["owner"])
                if "disposition" in body:
                    self._apply_disposition_update(target, body["disposition"])
                if "sensitivity" in body:
                    target["sensitivity"] = str(body["sensitivity"])
                if "queue_id" in body:
                    target["queue_id"] = str(body["queue_id"])
                target["update_time"] = _now_iso()
                note_obj = body.get("investigation_note")
                if isinstance(note_obj, dict) and str(note_obj.get("content") or "").strip():
                    self._route_mc_v2_locked(
                        method="POST",
                        subpath=f"/investigations/{urllib.parse.quote(rid, safe='')}/notes",
                        query={},
                        json_body=note_obj,
                        auth_user=auth_user,
                    )
                self._record_history_locked(
                    rid,
                    user=auth_user,
                    message="Bulk updated record.",
                    short_description="Bulk update",
                    change="bulk_update",
                )
                results.append({"id": rid})
            if has_error:
                return (
                    400,
                    {
                        "message": "Partial failure",
                        "results": results,
                        "request_id": str(uuid.uuid4()),
                    },
                    {},
                )
            return 200, results, {}

        m_inv_findings = re.match(r"^/investigations/([^/]+)/findings$", subpath)
        if m_inv_findings and method == "POST":
            inv_id = urllib.parse.unquote(m_inv_findings.group(1))
            inv = self._find_investigation_locked(inv_id)
            if inv is None:
                return 404, self._mc_error("MC_0404", f"Investigation not found: {inv_id}"), {}
            body = json_body if isinstance(json_body, dict) else {}
            fids = body.get("finding_ids")
            ftimes = body.get("finding_times")
            if not isinstance(fids, list) or not isinstance(ftimes, list):
                return 400, self._mc_error("MC_0100", "finding_ids and finding_times are required"), {}
            existing = inv.setdefault("findings", {}).setdefault("incident_ids", [])
            for fid in fids:
                if fid not in existing:
                    existing.append(fid)
            inv["count_findings"] = len(existing)
            inv["update_time"] = _now_iso()
            self._record_history_locked(
                inv["investigation_guid"],
                user=auth_user,
                message=f"Added {len(fids)} finding(s).",
                short_description="Findings attached",
                change="add_findings",
            )
            return 200, {"investigation_guid": inv["investigation_guid"]}, {}

        m_note_id = re.match(r"^/investigations/([^/]+)/notes/([^/]+)$", subpath)
        if m_note_id:
            rec_id = urllib.parse.unquote(m_note_id.group(1))
            note_id = urllib.parse.unquote(m_note_id.group(2))
            notes_map_all: dict[str, list[dict[str, Any]]] = self.state.setdefault("notes", {})
            fnd_match = self._find_finding_locked(rec_id)
            canonical_rec_id = (
                str(fnd_match.get("event_id") or rec_id)
                if fnd_match is not None and rec_id not in notes_map_all
                else rec_id
            )
            notes_list: list[dict[str, Any]] = notes_map_all.get(canonical_rec_id, [])
            note = next((n for n in notes_list if n["id"] == note_id), None)
            if note is None:
                return 404, self._mc_error("MC_0404", f"Note not found: {note_id}"), {}
            if method == "POST":
                body = json_body if isinstance(json_body, dict) else {}
                if "title" in body:
                    note["title"] = str(body["title"])
                if "content" in body:
                    note["content"] = str(body["content"])
                if "files" in body and isinstance(body["files"], list):
                    note["files"] = list(body["files"])
                note["update_time"] = _now_iso()
                return 200, copy.deepcopy(note), {}
            if method == "DELETE":
                notes_list.remove(note)
                return 200, {}, {}

        m_notes = re.match(r"^/investigations/([^/]+)/notes$", subpath)
        if m_notes:
            rec_id = urllib.parse.unquote(m_notes.group(1))
            notes_map: dict[str, list[dict[str, Any]]] = self.state.setdefault("notes", {})
            fnd_match = self._find_finding_locked(rec_id)
            canonical_rec_id = (
                str(fnd_match.get("event_id") or rec_id)
                if fnd_match is not None
                else rec_id
            )
            if method == "GET":
                notes_list = list(notes_map.get(canonical_rec_id, notes_map.get(rec_id, [])))
                search = (query.get("search") or [""])[0].strip().lower()
                if search:
                    notes_list = [
                        n
                        for n in notes_list
                        if search in str(n.get("content", "")).lower()
                        or search in str(n.get("title", "")).lower()
                    ]
                note_type = (query.get("type") or [""])[0].strip()
                if note_type and note_type.lower() != "all":
                    notes_list = [
                        n for n in notes_list if str(n.get("source_type", "")).lower() == note_type.lower()
                    ]
                try:
                    offset = int((query.get("offset") or ["0"])[0])
                    limit = int((query.get("limit") or ["50"])[0])
                except ValueError:
                    return 400, self._mc_error("MC_0100", "offset and limit must be integers"), {}
                if offset < 0 or limit < 1:
                    return 400, self._mc_error("MC_0100", "offset must be >= 0 and limit must be >= 1"), {}
                return (
                    200,
                    {
                        "items": copy.deepcopy(notes_list[offset : offset + limit]),
                        "offset": offset,
                        "limit": limit,
                        "total": len(notes_list),
                    },
                    {},
                )
            if method == "POST":
                body = json_body if isinstance(json_body, dict) else {}
                content = str(body.get("content") or "").strip()
                if not content:
                    return 400, self._mc_error("MC_0100", "content is required"), {}
                self.state["id_counter"] += 1
                now = _now_iso()
                new_note = {
                    "id": f"note-{self.state['id_counter']}",
                    "title": str(body.get("title") or ""),
                    "content": content,
                    "author": {"username": auth_user},
                    "record_type": "Investigation" if self._find_investigation_locked(rec_id) else "Finding",
                    "record_title": canonical_rec_id,
                    "source_type": "Incident",
                    "incident_id": canonical_rec_id,
                    "files": list(body.get("files") or []),
                    "create_time": now,
                    "update_time": now,
                }
                notes_map.setdefault(canonical_rec_id, []).append(new_note)
                self._record_history_locked(
                    canonical_rec_id,
                    user=auth_user,
                    message=f"Added note '{new_note['id']}'.",
                    short_description="Note added",
                    change="note_added",
                )
                return 201, copy.deepcopy(new_note), {}

        m_hist = re.match(r"^/investigations/([^/]+)/history$", subpath)
        if m_hist and method == "GET":
            rec_id = urllib.parse.unquote(m_hist.group(1))
            fnd_match = self._find_finding_locked(rec_id)
            canonical_rec_id = (
                str(fnd_match.get("event_id") or rec_id)
                if fnd_match is not None
                else rec_id
            )
            known = (
                self._find_investigation_locked(rec_id) is not None
                or fnd_match is not None
                or rec_id in self.state.get("history", {})
                or canonical_rec_id in self.state.get("history", {})
            )
            if not known:
                return 404, self._mc_error("MC_0404", f"Record not found: {rec_id}"), {}
            try:
                offset = int((query.get("offset") or ["0"])[0])
                limit = int((query.get("limit") or ["100"])[0])
            except ValueError:
                return 400, self._mc_error("MC_0100", "offset and limit must be integers"), {}
            if offset < 0 or limit < 1:
                return 400, self._mc_error("MC_0100", "offset must be >= 0 and limit must be >= 1"), {}
            items = list(self.state.get("history", {}).get(canonical_rec_id, []))
            return (
                200,
                {
                    "items": copy.deepcopy(items[offset : offset + limit]),
                    "offset": offset,
                    "limit": limit,
                    "total": len(items),
                },
                {},
            )

        m_inv = re.match(r"^/investigations/([^/]+)$", subpath)
        if m_inv and method == "POST":
            inv_id = urllib.parse.unquote(m_inv.group(1))
            target = self._find_investigation_locked(inv_id) or self._find_finding_locked(inv_id)
            if target is None:
                return 404, self._mc_error("MC_0404", f"Investigation/finding not found: {inv_id}"), {}
            body = json_body if isinstance(json_body, dict) else {}
            for key in ("name", "description", "urgency", "owner", "sensitivity", "investigation_type", "queue_id"):
                if key in body:
                    target[key] = body[key]
            if "status" in body:
                self._apply_status_update(target, body["status"])
            target["update_time"] = _now_iso()
            note_obj = body.get("investigation_note")
            if isinstance(note_obj, dict) and str(note_obj.get("content") or "").strip():
                self._route_mc_v2_locked(
                    method="POST",
                    subpath=f"/investigations/{urllib.parse.quote(inv_id, safe='')}/notes",
                    query={},
                    json_body=note_obj,
                    auth_user=auth_user,
                )
            self._record_history_locked(
                inv_id,
                user=auth_user,
                message="Updated investigation/finding.",
                short_description="Updated",
                change="update",
            )
            return 200, {"investigation_guid": target.get("investigation_guid") or inv_id}, {}

        if subpath == "/queues":
            if method == "GET":
                return (
                    200,
                    {"queues": copy.deepcopy(self.state["queues"]), "last_updated_time": time.time()},
                    {},
                )
            if method == "POST":
                body = json_body if isinstance(json_body, dict) else {}
                title = str(body.get("title") or "").strip()
                if not title:
                    return 400, self._mc_error("MC_0100", "title is required"), {}
                self.state["id_counter"] += 1
                q = {
                    "id": f"queue-{self.state['id_counter']}",
                    "title": title,
                    "description": str(body.get("description") or ""),
                    "allow_override": bool(body.get("allow_override", True)),
                    "wildcard_role_access": bool(body.get("wildcard_role_access", True)),
                }
                self.state["queues"].append(q)
                return 201, copy.deepcopy(q), {}

        m_q = re.match(r"^/queues/([^/]+)$", subpath)
        if m_q:
            qid = urllib.parse.unquote(m_q.group(1))
            q = next((item for item in self.state["queues"] if item["id"] == qid), None)
            if q is None:
                return 404, self._mc_error("MC_0404", f"Queue not found: {qid}"), {}
            if method == "GET":
                return 200, copy.deepcopy(q), {}
            if method == "POST":
                if isinstance(json_body, dict):
                    q.update(json_body)
                return 200, copy.deepcopy(q), {}
            if method == "DELETE":
                self.state["queues"].remove(q)
                return 200, {}, {}

        m_asset = re.match(r"^/assets/([^/]+)$", subpath)
        if m_asset and method == "GET":
            aid = urllib.parse.unquote(m_asset.group(1)).lower()
            for asset in self.state.get("assets", []):
                candidates = (
                    [str(asset.get("id") or "").lower()]
                    + [str(x).lower() for x in (asset.get("ip") or [])]
                    + [str(x).lower() for x in (asset.get("dns") or [])]
                    + [str(x).lower() for x in (asset.get("nt_host") or [])]
                    + [str(x).lower() for x in (asset.get("asset") or [])]
                )
                if aid in candidates:
                    return 200, copy.deepcopy(asset), {}
            return 404, self._mc_error("MC_0404", f"Asset not found: {aid}"), {}

        m_ident = re.match(r"^/identity/([^/]+)$", subpath)
        if m_ident and method == "GET":
            iid = urllib.parse.unquote(m_ident.group(1)).lower()
            for ident in self.state.get("identities", []):
                candidates = (
                    [str(ident.get("id") or "").lower()]
                    + [str(x).lower() for x in (ident.get("identity") or [])]
                    + [str(x).lower() for x in (ident.get("email") or [])]
                )
                if iid in candidates:
                    return 200, copy.deepcopy(ident), {}
            return 404, None, {}

        m_risk = re.match(r"^/risks/risk_scores/([^/]+)$", subpath)
        if m_risk:
            entity = urllib.parse.unquote(m_risk.group(1))
            if method == "GET":
                etype = (query.get("entity_type") or [""])[0].strip().lower()
                matches = [
                    copy.deepcopy(r)
                    for r in self.state.get("risk_scores", [])
                    if str(r.get("entity", "")).lower() == entity.lower()
                    and (not etype or str(r.get("entity_type", "")).lower() == etype)
                ]
                return 200, matches, {}
            if method == "POST":
                body = json_body if isinstance(json_body, dict) else {}
                etype = str(body.get("entity_type") or "").strip()
                mod = body.get("risk_modifier")
                if not etype or mod is None:
                    return 400, self._mc_error("MC_0100", "risk_modifier and entity_type are required"), {}
                if isinstance(mod, bool):
                    return 400, self._mc_error("MC_0100", "risk_modifier must be numeric"), {}
                try:
                    mod_val = float(mod)
                except (TypeError, ValueError):
                    return 400, self._mc_error("MC_0100", "risk_modifier must be numeric"), {}
                if not math.isfinite(mod_val):
                    return 400, self._mc_error("MC_0100", "risk_modifier must be finite"), {}
                existing = next(
                    (
                        r
                        for r in self.state["risk_scores"]
                        if str(r.get("entity", "")).lower() == entity.lower()
                        and str(r.get("entity_type", "")).lower() == etype.lower()
                    ),
                    None,
                )
                if existing is not None:
                    new_score = int(float(existing.get("risk_score") or 0) + mod_val)
                    existing["risk_score"] = str(new_score)
                    existing["ers"] = str(new_score)
                else:
                    self.state["risk_scores"].append(
                        {
                            "entity": entity,
                            "risk_score": str(int(mod_val)),
                            "entity_type": etype,
                            "ers": str(int(mod_val)),
                        }
                    )
                return 201, {"message": "Risk score updated"}, {}

        return 404, self._mc_error("MC_0404", f"Not found: {method} {subpath}"), {}

    def _route_legacy_splunk_locked(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        form_data: dict[str, list[str]],
        json_body: Any,
        auth_user: str,
    ) -> tuple[int, Any, dict[str, str]]:
        if path == "/services/server/info" and method == "GET":
            version = "10.6.2.5" if self.state["mc_v2_enabled"] else "7.3.0"
            return 200, {"entry": [{"name": "server-info", "content": {"version": version, "serverName": "es-mock.example.test"}}]}, {}

        if path == "/services/authentication/currentcontext" and method == "GET":
            return 200, {"entry": [{"name": "currentcontext", "content": {"username": auth_user, "roles": ["ess_analyst", "admin"]}}]}, {}

        if path == "/services/authentication/users" and method == "GET":
            entries = [
                {
                    "name": u["username"],
                    "content": {
                        "realname": u["realname"],
                        "email": u["email"],
                        "roles": u["roles"],
                    },
                }
                for u in self.state["users"]
            ]
            return 200, {"entry": entries}, {}

        if path == "/services/data/indexes" and method == "GET":
            return (
                200,
                {
                    "entry": [
                        {
                            "name": "notable",
                            "content": {
                                "totalEventCount": len(self.state["findings"]),
                                "datatype": "event",
                                "disabled": False,
                            },
                        },
                        {
                            "name": "risk",
                            "content": {
                                "totalEventCount": len(self.state["risk_events"]),
                                "datatype": "event",
                                "disabled": False,
                            },
                        },
                    ]
                },
                {},
            )

        if path == "/services/notable_update" and method == "POST":
            rule_uids = [u.strip() for u in (form_data.get("ruleUIDs") or []) if u.strip()]
            status_val = (form_data.get("status") or [""])[0].strip()
            urgency_val = (form_data.get("urgency") or [""])[0].strip()
            owner_val = (form_data.get("newOwner") or [""])[0].strip()
            disp_val = (form_data.get("disposition") or [""])[0].strip()
            comment_val = (form_data.get("comment") or [""])[0].strip()
            if not rule_uids or not any([status_val, urgency_val, owner_val, disp_val, comment_val]):
                return (
                    400,
                    {"messages": [{"type": "ERROR", "text": "ruleUIDs and at least one update field required"}]},
                    {},
                )
            updated = 0
            for uid in rule_uids:
                fnd = self._find_finding_locked(uid)
                if fnd is None:
                    continue
                updated += 1
                note_key = str(fnd.get("event_id") or uid)
                finding_id_val = str(fnd.get("finding_id") or note_key)
                if status_val:
                    self._apply_status_update(fnd, status_val)
                if urgency_val:
                    fnd["urgency"] = urgency_val.lower()
                if owner_val:
                    fnd["owner"] = owner_val
                    fnd["owner_realname"] = owner_val
                if disp_val:
                    self._apply_disposition_update(fnd, disp_val)
                fnd["update_time"] = _now_iso()
                if comment_val:
                    self.state["id_counter"] += 1
                    self.state.setdefault("notes", {}).setdefault(note_key, []).append(
                        {
                            "id": f"note-{self.state['id_counter']}",
                            "title": "Notable Update",
                            "content": comment_val,
                            "author": {"username": auth_user},
                            "record_type": "Finding",
                            "record_title": str(fnd.get("rule_title") or note_key),
                            "source_type": "Incident",
                            "incident_id": note_key,
                            "create_time": _now_iso(),
                            "update_time": _now_iso(),
                        }
                    )
                self._record_history_locked(
                    note_key,
                    user=auth_user,
                    message=comment_val or "Updated via notable_update",
                    short_description="Notable updated",
                    change="notable_update",
                    category="finding",
                    finding_id=finding_id_val,
                )
            return 200, {"success": True, "message": f"Updated {updated} notable(s)", "ruleUIDs": rule_uids}, {}

        if path == "/services/alerts/modaction_adhoc" and method == "POST":
            action_name = (form_data.get("action_name") or [""])[0].strip()
            sid = (form_data.get("sid") or [""])[0].strip()
            rid = (form_data.get("rid") or [""])[0].strip()
            if not action_name or not sid or not rid:
                return 400, {"messages": [{"type": "ERROR", "text": "action_name, sid, and rid are required"}]}, {}
            self.state["id_counter"] += 1
            inv_id = f"modact-{self.state['id_counter']}"
            self.state["modaction_invocations"].append(
                {
                    "invocation_id": inv_id,
                    "sid": sid,
                    "rid": rid,
                    "orig_sid": sid,
                    "orig_rid": rid,
                    "action_name": action_name,
                    "action_status": "success",
                    "action_mode": "adhoc",
                    "status_description": f"Dispatched {action_name}",
                    "action_time": _now_iso(),
                }
            )
            return 200, {"success": True, "invocation_id": inv_id, "action_name": action_name, "sid": sid, "rid": rid}, {}

        if path == "/services/alerts/modaction_invocations" or re.match(
            r"^/servicesNS/[^/]+/[^/]+/alerts/modaction_invocations$", path
        ):
            if method == "GET":
                sid = (query.get("sid") or [""])[0].strip()
                rid = (query.get("rid") or [""])[0].strip()
                if not sid or not rid:
                    return (
                        400,
                        {
                            "success": False,
                            "messages": [{"type": "ERROR", "message": "Missing required arguments: ['sid', 'rid']"}],
                            "responses": [],
                        },
                        {},
                    )
                matches = [
                    copy.deepcopy(row)
                    for row in self.state["modaction_invocations"]
                    if row.get("sid") == sid and row.get("rid") == rid
                ]
                return (
                    200,
                    {
                        "success": True,
                        "responses": matches,
                        "search_id": sid,
                        "search": f"| `modular_action_invocations({sid},{rid})`",
                    },
                    {},
                )
            if method == "POST":
                body = json_body if isinstance(json_body, dict) else {}
                action_name = str(body.get("action_name") or (form_data.get("action_name") or [""])[0]).strip()
                sid = str(body.get("sid") or (form_data.get("sid") or [""])[0]).strip()
                rid = str(body.get("rid") or (form_data.get("rid") or [""])[0]).strip()
                self.state["id_counter"] += 1
                inv_id = f"modact-{self.state['id_counter']}"
                self.state["modaction_invocations"].append(
                    {
                        "invocation_id": inv_id,
                        "sid": sid,
                        "rid": rid,
                        "orig_sid": sid,
                        "orig_rid": rid,
                        "action_name": action_name,
                        "action_status": "success",
                        "action_mode": "adhoc",
                        "action_time": _now_iso(),
                    }
                )
                return 200, {"success": True, "invocation_id": inv_id}, {}

        if path.startswith("/servicesNS/"):
            parts = path[len("/servicesNS/") :].split("/")
            if len(parts) >= 4:
                app = parts[1]
                section = "/".join(parts[2:])

                if section == "configs/conf-incident_review/incident_review" and method == "GET":
                    if self.state["incident_review_404_fallback"]:
                        return (
                            404,
                            {"messages": [{"type": "ERROR", "text": "Could not find object id=incident_review"}]},
                            {},
                        )
                    return (
                        200,
                        {
                            "entry": [
                                {
                                    "name": "incident_review",
                                    "content": {
                                        "event_attributes": json.dumps(self.state["event_attributes"]),
                                        "table_attributes": json.dumps(self.state["table_attributes"]),
                                    },
                                }
                            ]
                        },
                        {},
                    )

                if section == "configs/conf-log_review/incident_review" and method == "GET":
                    return (
                        200,
                        {
                            "entry": [
                                {
                                    "name": "incident_review",
                                    "content": {
                                        "event_attributes": json.dumps(self.state["event_attributes"]),
                                        "table_attributes": json.dumps(self.state["table_attributes"]),
                                    },
                                }
                            ]
                        },
                        {},
                    )

                if section in ("admin/alert_actions", "alerts/alert_actions") and method == "GET":
                    return 200, {"entry": copy.deepcopy(self.state["alert_actions"])}, {}

                if section == "saved/searches":
                    if method == "GET":
                        return 200, {"entry": copy.deepcopy(self.state["correlations"])}, {}
                    if method == "POST":
                        name = (form_data.get("name") or ["unnamed_search"])[0]
                        search_spl = (form_data.get("search") or [""])[0]
                        entry = {
                            "name": name,
                            "acl": {"app": app},
                            "content": {"search": search_spl, "disabled": False},
                        }
                        self.state["correlations"].append(entry)
                        return 201, {"entry": [copy.deepcopy(entry)]}, {}

                if len(parts) == 5 and parts[2] == "saved" and parts[3] == "searches" and method == "POST":
                    name = urllib.parse.unquote(parts[4])
                    entry = next((c for c in self.state["correlations"] if c["name"] == name), None)
                    if entry is None:
                        return 404, {"messages": [{"type": "ERROR", "text": f"Unknown search: {name}"}]}, {}
                    if "disabled" in form_data:
                        entry["content"]["disabled"] = form_data["disabled"][0].strip() in ("1", "true", "True")
                    return 200, {"entry": [copy.deepcopy(entry)]}, {}

                if (
                    len(parts) == 6
                    and parts[2] == "saved"
                    and parts[3] == "searches"
                    and parts[5] == "dispatch"
                    and method == "POST"
                ):
                    name = urllib.parse.unquote(parts[4])
                    entry = next((c for c in self.state["correlations"] if c["name"] == name), None)
                    if entry is None:
                        return 404, {"messages": [{"type": "ERROR", "text": f"Unknown search: {name}"}]}, {}
                    self.state["job_counter"] += 1
                    sid = f"1700000000.{self.state['job_counter']}"
                    spl = str(entry.get("content", {}).get("search") or "")
                    self.state["jobs"][sid] = {
                        "sid": sid,
                        "app": app,
                        "search": spl,
                        "mode": self.state["default_job_mode"],
                        "polls": 0,
                        "cancelled": False,
                        "results": self._evaluate_spl_search_locked(spl),
                    }
                    return 201, {"sid": sid}, {}

                if section == "search/jobs" and method == "POST":
                    self.state["job_counter"] += 1
                    sid = f"1700000000.{self.state['job_counter']}"
                    search_spl = (form_data.get("search") or [""])[0]
                    self.state["jobs"][sid] = {
                        "sid": sid,
                        "app": app,
                        "search": search_spl,
                        "mode": self.state["default_job_mode"],
                        "polls": 0,
                        "cancelled": False,
                        "results": self._evaluate_spl_search_locked(search_spl),
                    }
                    return 201, {"sid": sid}, {}

                if (
                    parts[0] == "nobody"
                    and app == "DA-ESS-ThreatIntelligence"
                    and len(parts) == 6
                    and parts[2] == "storage"
                    and parts[3] == "collections"
                    and parts[4] == "data"
                ):
                    collection = parts[5]
                    if collection not in _THREAT_INTEL_COLLECTIONS:
                        return 404, {"messages": [{"type": "ERROR", "text": f"Unknown collection: {collection}"}]}, {}
                    ti_store = self.state.setdefault("threat_intel", {})
                    rows = ti_store.setdefault(collection, [])
                    if method == "GET":
                        out = copy.deepcopy(rows)
                        raw_q = (query.get("query") or [""])[0].strip()
                        if raw_q:
                            try:
                                qdict = json.loads(raw_q)
                                if isinstance(qdict, dict):
                                    out = [
                                        r
                                        for r in out
                                        if all(str(r.get(k, "")) == str(v) for k, v in qdict.items())
                                    ]
                            except ValueError:
                                pass
                        if "limit" in query:
                            try:
                                lim = max(1, int(query["limit"][0]))
                                out = out[:lim]
                            except ValueError:
                                pass
                        return 200, out, {}
                    if method == "POST":
                        entry = dict(json_body) if isinstance(json_body, dict) else {}
                        self.state["id_counter"] += 1
                        key = str(entry.get("_key") or f"ti-{collection}-{self.state['id_counter']}")
                        entry["_key"] = key
                        rows.append(entry)
                        return 201, {"_key": key}, {}

        if path.startswith("/services/search/jobs/"):
            rest = path[len("/services/search/jobs/") :]
            parts = rest.split("/")
            sid = urllib.parse.unquote(parts[0])
            job = self.state["jobs"].get(sid)
            if job is None:
                return 404, {"messages": [{"type": "ERROR", "text": f"Unknown sid: {sid}"}]}, {}
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
                        "messages": [{"type": "ERROR", "text": "Search failed in mock Splunk ES"}],
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
                    results = job["results"]
                    content = {
                        "isDone": True,
                        "dispatchState": "DONE",
                        "resultCount": len(results),
                        "eventCount": len(results),
                        "runDuration": 0.05,
                        "messages": [],
                    }
                return 200, {"entry": [{"content": content}]}, {}
            if len(parts) == 2 and parts[1] == "results" and method == "GET":
                rows = job["results"]
                try:
                    offset = int((query.get("offset") or ["0"])[0])
                    count = int((query.get("count") or ["0"])[0])
                except ValueError:
                    return (
                        400,
                        {"messages": [{"type": "ERROR", "text": "offset and count must be integers"}]},
                        {},
                    )
                if offset < 0 or count < 0:
                    return (
                        400,
                        {"messages": [{"type": "ERROR", "text": "offset and count must be >= 0"}]},
                        {},
                    )
                sliced = rows[offset : offset + count] if count > 0 else rows[offset:]
                fields = [{"name": k} for k in (sliced[0].keys() if sliced else [])]
                return 200, {"fields": fields, "results": copy.deepcopy(sliced)}, {}
            if len(parts) == 2 and parts[1] == "control" and method == "POST":
                action = (form_data.get("action") or [""])[0]
                if action == "cancel":
                    job["cancelled"] = True
                return 200, {"messages": [{"type": "INFO", "text": f"Control action '{action}' applied"}]}, {}

        return 404, {"messages": [{"type": "ERROR", "text": f"Not found: {method} {path}"}]}, {}


# ======================================================================
# 7. SentinelOne v2.1 Console Mock
# ======================================================================


class MockSentinelOneServer(_BaseV21MockServer):
    """Stateful local SentinelOne v2.1 API mock with strict guardrails."""

    def __init__(
        self,
        fixture_path: Path | None = None,
        *,
        valid_tokens: Iterable[str] | None = None,
        enforce_limit_max_100: bool = True,
        sites_as_list: bool = False,
    ) -> None:
        self._fixture_path = fixture_path
        self.valid_tokens: set[str] = set(valid_tokens) if valid_tokens is not None else {"test-s1-token"}
        self._init_enforce_limit_max_100 = enforce_limit_max_100
        self._init_sites_as_list = sites_as_list
        super().__init__()

    def _reset_state_locked(self) -> None:
        raw = _load_fixture("v21_sentinelone.json", self._fixture_path)
        self.state = {
            **raw,
            "enforce_limit_max_100": self._init_enforce_limit_max_100,
            "sites_as_list": self._init_sites_as_list,
            "id_counter": 0,
            "dv_queries": {},
            "reset_email_requests": [],
        }

    def set_sites_as_list(self, enabled: bool) -> None:
        with self._lock:
            self.state["sites_as_list"] = bool(enabled)

    def set_enforce_limit_max_100(self, enabled: bool) -> None:
        with self._lock:
            self.state["enforce_limit_max_100"] = bool(enabled)

    def seed_bulk_exclusions(self, site_id: str, count: int) -> list[str]:
        """Seed additional synthetic exclusions on a site for pagination/pacing tests."""
        created_ids: list[str] = []
        with self._lock:
            site = next((s for s in self.state["sites"] if s["id"] == site_id), None)
            site_name = site["name"] if site else site_id
            for idx in range(count):
                self.state["id_counter"] += 1
                eid = f"excl-bulk-{self.state['id_counter']}"
                self.state["exclusions"].append(
                    {
                        "id": eid,
                        "scope": "site",
                        "scopeId": site_id,
                        "scopeName": site_name,
                        "type": "path",
                        "osType": "linux",
                        "value": f"/opt/bulk/tool_{idx:03d}",
                        "mode": "suppress",
                        "pathExclusionType": "file",
                        "description": f"Bulk exclusion {idx + 1}",
                        "actions": ["detect"],
                    }
                )
                created_ids.append(eid)
        return created_ids

    def _s1_err(self, code: int, title: str, detail: str) -> dict[str, Any]:
        return {"errors": [{"code": code, "title": title, "detail": detail}]}

    def _default_fault_body(self, path: str, status_code: int) -> Any:
        if status_code == 429:
            return self._s1_err(429001, "Rate limit exceeded", "Too many requests")
        return self._s1_err(status_code * 1000, f"HTTP {status_code}", f"Mock fault on {path}")

    def _parse_limit_and_cursor(
        self, query: Mapping[str, list[str]], default_limit: int = 100
    ) -> tuple[int, int] | tuple[None, None]:
        limit = default_limit
        if "limit" in query and query["limit"][0].strip() != "":
            try:
                limit = int(query["limit"][0])
            except ValueError:
                return None, None
            if self.state["enforce_limit_max_100"] and (limit < 1 or limit > 100):
                return None, None
        offset = 0
        if "cursor" in query and query["cursor"][0].strip():
            raw_cursor = query["cursor"][0].strip()
            try:
                decoded = base64.b64decode(raw_cursor.encode("ascii")).decode("utf-8")
                if decoded.startswith("offset:"):
                    offset = max(0, int(decoded.split(":", 1)[1]))
            except Exception:
                if raw_cursor.isdigit():
                    offset = int(raw_cursor)
        return limit, offset

    def _paginate_items(
        self, items: Sequence[dict[str, Any]], limit: int, offset: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        sliced = copy.deepcopy(list(items[offset : offset + limit]))
        next_cursor: str | None = None
        if offset + limit < len(items):
            next_cursor = base64.b64encode(f"offset:{offset + limit}".encode()).decode("ascii")
        return sliced, {"nextCursor": next_cursor, "totalItems": len(items)}

    def _has_non_empty_filter(self, flt: Any) -> bool:
        if not isinstance(flt, dict) or not flt:
            return False
        for k, v in flt.items():
            if isinstance(v, list):
                if any(str(x).strip() for x in v):
                    return True
            elif v is not None and str(v).strip() != "":
                return True
        return False

    def _matches_scope(
        self,
        item: Mapping[str, Any],
        *,
        account_ids: set[str],
        site_ids: set[str],
        group_ids: set[str] | None = None,
        ids: set[str] | None = None,
        nested_paths: Sequence[str] = (),
    ) -> bool:
        if ids and str(item.get("id") or "") not in ids:
            return False
        acc = str(item.get("accountId") or "")
        site = str(item.get("siteId") or "")
        grp = str(item.get("groupId") or "")
        for np in nested_paths:
            nested = item.get(np)
            if isinstance(nested, dict):
                acc = acc or str(nested.get("accountId") or "")
                site = site or str(nested.get("siteId") or "")
                grp = grp or str(nested.get("groupId") or "")
        if account_ids and acc not in account_ids:
            return False
        if site_ids and site not in site_ids:
            return False
        if group_ids and grp not in group_ids:
            return False
        return True

    def _resolve_filter_targets(
        self,
        items: Sequence[dict[str, Any]],
        flt: Mapping[str, Any],
        *,
        nested_paths: Sequence[str] = (),
    ) -> list[dict[str, Any]]:
        ids = {str(x) for x in (flt.get("ids") or []) if str(x).strip()}
        site_ids = {str(x) for x in (flt.get("siteIds") or []) if str(x).strip()}
        account_ids = {str(x) for x in (flt.get("accountIds") or []) if str(x).strip()}
        group_ids = {str(x) for x in (flt.get("groupIds") or []) if str(x).strip()}
        return [
            item
            for item in items
            if self._matches_scope(
                item,
                account_ids=account_ids,
                site_ids=site_ids,
                group_ids=group_ids,
                ids=ids,
                nested_paths=nested_paths,
            )
        ]

    def _route_locked(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        json_body: Any,
        form_data: dict[str, list[str]],
    ) -> tuple[int, Any, dict[str, str]]:
        auth = _header_ci(headers, "Authorization")
        if not auth.startswith("ApiToken ") or auth[9:].strip() not in self.valid_tokens:
            return (
                401,
                self._s1_err(401001, "Authentication failed", "Invalid or missing ApiToken"),
                {},
            )

        prefix = "/web/api/v2.1/"
        if not path.startswith(prefix):
            return 404, self._s1_err(404001, "Not found", f"Unknown path {path}"), {}
        subpath = path[len(prefix) :].strip("/")

        limit = 100
        offset = 0
        if method == "GET" and "limit" in query:
            parsed_lim, parsed_off = self._parse_limit_and_cursor(query)
            if parsed_lim is None or parsed_off is None:
                raw_lim = query["limit"][0]
                return (
                    400,
                    self._s1_err(400010, "Bad parameter given", f"limit must be between 1 and 100, got {raw_lim}"),
                    {},
                )
            limit, offset = parsed_lim, parsed_off
        elif method == "GET":
            _, parsed_off = self._parse_limit_and_cursor(query)
            offset = parsed_off or 0

        body = json_body if isinstance(json_body, dict) else {}

        # Guardrail: empty filter & data.ids checks on mutations
        if method in ("POST", "PUT", "DELETE"):
            if "filter" in body and not self._has_non_empty_filter(body.get("filter")):
                return 400, self._s1_err(400010, "Empty filter", "Mutation filter must not be empty"), {}
            filter_required_paths = (
                "threats/analyst-verdict",
                "threats/incident",
                "threats/notes",
                "threats/add-to-exclusions",
                "cloud-detection/alerts/analyst-verdict",
                "cloud-detection/alerts/incident",
                "users/delete-users",
                "users/login/send-reset-password-email",
                "service-users/delete-service-users",
            )
            if (
                subpath in filter_required_paths
                or subpath.startswith("threats/mitigate/")
                or subpath.startswith("agents/actions/")
                or (subpath == "exclusions" and method == "POST")
                or (subpath == "restrictions" and method == "POST")
            ) and not self._has_non_empty_filter(body.get("filter")):
                return 400, self._s1_err(400010, "Empty filter", "Mutation filter must not be empty"), {}

            if (
                (subpath in ("exclusions", "restrictions") and method == "DELETE")
                or subpath in ("users/reset-2fa", "users/delete-2fa")
            ):
                ids_list = (body.get("data") or {}).get("ids") if isinstance(body.get("data"), dict) else None
                if not isinstance(ids_list, list) or not [x for x in ids_list if str(x).strip()]:
                    return 400, self._s1_err(400010, "Missing IDs", "data.ids must be non-empty"), {}

        # --- System & Accounts ---
        if subpath == "system/info" and method == "GET":
            return (
                200,
                {
                    "data": {
                        "release": "24.2",
                        "version": "24.2.1",
                        "build": "24.2.1.10",
                        "patch": "0",
                        "latestAgentVersion": "24.2.1.10",
                    },
                    "errors": [],
                },
                {},
            )

        if subpath == "accounts" and method == "GET":
            accs = list(self.state["accounts"])
            ids_f = set(_split_csv_param(query, "ids") or _split_csv_param(query, "accountIds"))
            if ids_f:
                accs = [a for a in accs if a["id"] in ids_f]
            q_str = (query.get("query") or [""])[0].strip().lower()
            if q_str:
                accs = [a for a in accs if q_str in str(a.get("name", "")).lower()]
            data, pag = self._paginate_items(accs, limit, offset)
            return 200, {"data": data, "pagination": pag, "errors": []}, {}

        # --- Sites & Policies ---
        if subpath == "sites":
            if method == "GET":
                sites = list(self.state["sites"])
                acc_f = set(_split_csv_param(query, "accountIds"))
                site_f = set(_split_csv_param(query, "siteIds"))
                if acc_f:
                    sites = [s for s in sites if s.get("accountId") in acc_f]
                if site_f:
                    sites = [s for s in sites if s.get("id") in site_f]
                if "name" in query and query["name"][0].strip():
                    nm = query["name"][0].strip().lower()
                    sites = [s for s in sites if s.get("name", "").lower() == nm]
                if "state" in query and query["state"][0].strip():
                    st = query["state"][0].strip().lower()
                    sites = [s for s in sites if s.get("state", "").lower() == st]
                q_str = (query.get("query") or [""])[0].strip().lower()
                if q_str:
                    sites = [s for s in sites if q_str in str(s.get("name", "")).lower()]
                sliced, pag = self._paginate_items(sites, limit, offset)
                if self.state["sites_as_list"]:
                    return 200, {"data": sliced, "pagination": pag, "errors": []}, {}
                return (
                    200,
                    {
                        "data": {
                            "sites": sliced,
                            "allSites": {
                                "activeLicenses": sum(int(s.get("activeLicenses", 0) or 0) for s in sites),
                                "totalLicenses": sum(int(s.get("totalLicenses", 0) or 0) for s in sites),
                            },
                        },
                        "pagination": pag,
                        "errors": [],
                    },
                    {},
                )
            if method == "POST":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                name = str(d.get("name") or "").strip()
                if not name:
                    return 400, self._s1_err(400010, "Bad parameter", "Site name is required"), {}
                raw_lic = d.get("totalLicenses")
                if raw_lic is None:
                    total_licenses = 50
                elif isinstance(raw_lic, bool):
                    return 400, self._s1_err(400010, "Bad parameter", "totalLicenses must be an integer"), {}
                else:
                    try:
                        total_licenses = int(raw_lic)
                    except (TypeError, ValueError):
                        return 400, self._s1_err(400010, "Bad parameter", "totalLicenses must be an integer"), {}
                    if total_licenses < 0:
                        return (
                            400,
                            self._s1_err(400010, "Bad parameter", "totalLicenses must be non-negative"),
                            {},
                        )
                self.state["id_counter"] += 1
                sid = str(900000 + self.state["id_counter"])
                acc_id = str(d.get("accountId") or "acc-100")
                acc = next((a for a in self.state["accounts"] if a["id"] == acc_id), None)
                new_site = {
                    "id": sid,
                    "name": name,
                    "accountId": acc_id,
                    "accountName": acc["name"] if acc else "SOCLens Managed Org",
                    "state": "active",
                    "siteType": str(d.get("siteType") or "Paid"),
                    "sku": str(d.get("sku") or "Complete"),
                    "suite": str(d.get("suite") or "Complete"),
                    "totalLicenses": total_licenses,
                    "activeLicenses": 0,
                    "unlimitedLicenses": bool(d.get("unlimitedLicenses", False)),
                    "unlimitedExpiration": bool(d.get("unlimitedExpiration", True)),
                    "expiration": d.get("expiration"),
                    "inherits": bool(d.get("inherits", True)),
                    "description": str(d.get("description") or ""),
                    "usageType": d.get("usageType"),
                    "externalId": d.get("externalId"),
                    "registrationToken": f"reg-tok-{sid}",
                }
                self.state["sites"].append(new_site)
                policy = copy.deepcopy(d.get("policy") or self.state["default_policy"])
                self.state["policies"][sid] = policy
                return 200, {"data": copy.deepcopy(new_site), "errors": []}, {}

        if subpath == "sites/duplicate-site" and method == "POST":
            d = body.get("data") if isinstance(body.get("data"), dict) else {}
            src_id = str(d.get("sourceSiteId") or "").strip()
            name = str(d.get("name") or "").strip()
            src_site = next((s for s in self.state["sites"] if s["id"] == src_id), None)
            if src_site is None:
                return 404, self._s1_err(404001, "Site not found", f"Unknown sourceSiteId {src_id}"), {}
            if not name:
                return 400, self._s1_err(400010, "Bad parameter", "name is required"), {}
            raw_lic = d.get("totalLicenses")
            if raw_lic is None:
                src_lic = src_site.get("totalLicenses")
                total_licenses = int(src_lic) if src_lic is not None else 50
            elif isinstance(raw_lic, bool):
                return 400, self._s1_err(400010, "Bad parameter", "totalLicenses must be an integer"), {}
            else:
                try:
                    total_licenses = int(raw_lic)
                except (TypeError, ValueError):
                    return 400, self._s1_err(400010, "Bad parameter", "totalLicenses must be an integer"), {}
                if total_licenses < 0:
                    return (
                        400,
                        self._s1_err(400010, "Bad parameter", "totalLicenses must be non-negative"),
                        {},
                    )
            self.state["id_counter"] += 1
            sid = str(910000 + self.state["id_counter"])
            new_site = {
                **copy.deepcopy(src_site),
                "id": sid,
                "name": name,
                "activeLicenses": 0,
                "totalLicenses": total_licenses,
                "unlimitedLicenses": bool(d.get("unlimitedLicenses", src_site.get("unlimitedLicenses", False))),
                "registrationToken": f"reg-tok-{sid}",
            }
            self.state["sites"].append(new_site)
            if d.get("policySource") == "copy_source_site" and src_id in self.state["policies"]:
                self.state["policies"][sid] = copy.deepcopy(self.state["policies"][src_id])
            elif isinstance(d.get("policy"), dict):
                self.state["policies"][sid] = copy.deepcopy(d["policy"])
            else:
                self.state["policies"][sid] = copy.deepcopy(self.state["default_policy"])
            if d.get("copyUsers"):
                for u in list(self.state["users"]):
                    if any(str(sr.get("id")) == src_id for sr in u.get("scopeRoles") or []):
                        u["scopeRoles"].append(
                            {"id": sid, "name": name, "roleId": u["scopeRoles"][0]["roleId"], "roleName": u["scopeRoles"][0].get("roleName", "Admin")}
                        )
            return 200, {"data": copy.deepcopy(new_site), "errors": []}, {}

        m_site_sub = re.match(r"^sites/([^/]+)/(policy|revert-policy|expire-now|reactivate|regenerate-key|token)$", subpath)
        if m_site_sub:
            sid, action = m_site_sub.group(1), m_site_sub.group(2)
            site = next((s for s in self.state["sites"] if s["id"] == sid), None)
            if site is None:
                return 404, self._s1_err(404001, "Site not found", f"Unknown site {sid}"), {}
            if action == "policy":
                if method == "GET":
                    pol = self.state["policies"].get(sid, self.state["default_policy"])
                    return 200, {"data": copy.deepcopy(pol), "errors": []}, {}
                if method == "PUT":
                    d = body.get("data") if isinstance(body.get("data"), dict) else {}
                    pol = copy.deepcopy(self.state["policies"].get(sid, self.state["default_policy"]))
                    pol.update(d)
                    pol["inherits"] = False
                    self.state["policies"][sid] = pol
                    return 200, {"data": copy.deepcopy(pol), "errors": []}, {}
            if action == "revert-policy" and method == "PUT":
                pol = copy.deepcopy(self.state["default_policy"])
                pol["inherits"] = True
                self.state["policies"][sid] = pol
                return 200, {"data": {"success": True}, "errors": []}, {}
            if action == "expire-now" and method == "POST":
                site["state"] = "expired"
                return 200, {"data": copy.deepcopy(site), "errors": []}, {}
            if action == "reactivate" and method == "PUT":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                site["state"] = "active"
                if "unlimited" in d:
                    site["unlimitedExpiration"] = bool(d["unlimited"])
                if "expiration" in d:
                    site["expiration"] = d["expiration"]
                return 200, {"data": {"success": True}, "errors": []}, {}
            if action == "regenerate-key" and method == "PUT":
                self.state["id_counter"] += 1
                tok = f"reg-tok-{sid}-{self.state['id_counter']}"
                site["registrationToken"] = tok
                return 200, {"data": {"registrationToken": tok}, "errors": []}, {}
            if action == "token" and method == "GET":
                return 200, {"data": {"token": site.get("registrationToken", "")}, "errors": []}, {}

        m_site = re.match(r"^sites/([^/]+)$", subpath)
        if m_site:
            sid = m_site.group(1)
            site = next((s for s in self.state["sites"] if s["id"] == sid), None)
            if site is None:
                return 404, self._s1_err(404001, "Site not found", f"Unknown site {sid}"), {}
            if method == "GET":
                return 200, {"data": copy.deepcopy(site), "errors": []}, {}
            if method == "PUT":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                site.update(d)
                return 200, {"data": copy.deepcopy(site), "errors": []}, {}
            if method == "DELETE":
                self.state["sites"].remove(site)
                return 200, {"data": {"success": True}, "errors": []}, {}

        # --- Groups ---
        if subpath == "groups" and method == "GET":
            groups = list(self.state["groups"])
            acc_f = set(_split_csv_param(query, "accountIds"))
            site_f = set(_split_csv_param(query, "siteIds"))
            grp_f = set(_split_csv_param(query, "groupIds"))
            groups = [g for g in groups if self._matches_scope(g, account_ids=acc_f, site_ids=site_f, ids=grp_f)]
            q_str = (query.get("query") or [""])[0].strip().lower()
            if q_str:
                groups = [g for g in groups if q_str in str(g.get("name", "")).lower()]
            data, pag = self._paginate_items(groups, limit, offset)
            return 200, {"data": data, "pagination": pag, "errors": []}, {}

        # --- Users, Service Users & RBAC ---
        if subpath == "users":
            if method == "GET":
                users = list(self.state["users"])
                site_f = set(_split_csv_param(query, "siteIds"))
                acc_f = set(_split_csv_param(query, "accountIds"))
                if site_f or acc_f:
                    allowed = site_f | acc_f
                    users = [
                        u
                        for u in users
                        if any(str(sr.get("id")) in allowed for sr in u.get("scopeRoles") or [])
                    ]
                if "email" in query and query["email"][0].strip():
                    em = query["email"][0].strip().lower()
                    users = [u for u in users if em in str(u.get("email", "")).lower()]
                if "fullName" in query and query["fullName"][0].strip():
                    fn = query["fullName"][0].strip().lower()
                    users = [u for u in users if fn in str(u.get("fullName", "")).lower()]
                role_f = set(_split_csv_param(query, "roleIds"))
                if role_f:
                    users = [
                        u
                        for u in users
                        if any(str(sr.get("roleId") or "") in role_f for sr in u.get("scopeRoles") or [])
                    ]
                if "twoFaEnabled" in query and query["twoFaEnabled"][0].strip():
                    want_2fa = _parse_bool_param(query, "twoFaEnabled", False)
                    users = [u for u in users if bool(u.get("twoFaEnabled")) is want_2fa]
                q_str = (query.get("query") or [""])[0].strip().lower()
                if q_str:
                    users = [
                        u
                        for u in users
                        if q_str in str(u.get("email", "")).lower()
                        or q_str in str(u.get("fullName", "")).lower()
                    ]
                data, pag = self._paginate_items(users, limit, offset)
                return 200, {"data": data, "pagination": pag, "errors": []}, {}
            if method == "POST":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                email = str(d.get("email") or "").strip()
                full_name = str(d.get("fullName") or "").strip()
                scope = str(d.get("scope") or "").strip()
                if not email or not full_name or not scope:
                    return 400, self._s1_err(400010, "Bad parameter", "email, fullName, and scope are required"), {}
                self.state["id_counter"] += 1
                uid = f"usr-{self.state['id_counter']}"
                new_user = {
                    "id": uid,
                    "email": email,
                    "fullName": full_name,
                    "scope": scope,
                    "twoFaEnabled": bool(d.get("twoFaEnabled", False)),
                    "twoFaConfigured": False,
                    "canGenerateApiToken": True,
                    "scopeRoles": list(d.get("scopeRoles") or []),
                }
                self.state["users"].append(new_user)
                return 200, {"data": copy.deepcopy(new_user), "errors": []}, {}

        if subpath == "users/delete-users" and method == "POST":
            ids_set = {str(x) for x in body["filter"].get("ids") or []}
            before = len(self.state["users"])
            self.state["users"] = [u for u in self.state["users"] if u["id"] not in ids_set]
            return 200, {"data": {"affected": before - len(self.state["users"])}, "errors": []}, {}

        if subpath == "users/login/send-reset-password-email" and method == "POST":
            ids_set = {str(x) for x in body["filter"].get("ids") or []}
            matched = [u for u in self.state["users"] if u["id"] in ids_set]
            self.state["reset_email_requests"].extend(u["id"] for u in matched)
            return 200, {"data": {"affected": len(matched)}, "errors": []}, {}

        if subpath in ("users/reset-2fa", "users/delete-2fa") and method == "POST":
            d = body["data"]
            ids_set = {str(x) for x in d["ids"]}
            affected = 0
            for u in self.state["users"]:
                if u["id"] in ids_set:
                    affected += 1
                    if subpath == "users/reset-2fa":
                        u["twoFaConfigured"] = False
                        if "enroll" in d:
                            u["twoFaEnabled"] = bool(d["enroll"])
                    else:
                        u["twoFaEnabled"] = False
                        u["twoFaConfigured"] = False
            return 200, {"data": {"affected": affected}, "errors": []}, {}

        if subpath == "users/logout" and method == "POST":
            return 200, {"data": {"redirectTo": "https://s1-console.example.test/logout"}, "errors": []}, {}

        m_user = re.match(r"^users/([^/]+)$", subpath)
        if m_user:
            uid = m_user.group(1)
            user = next((u for u in self.state["users"] if u["id"] == uid), None)
            if user is None:
                return 404, self._s1_err(404001, "User not found", f"Unknown user {uid}"), {}
            if method == "GET":
                return 200, {"data": copy.deepcopy(user), "errors": []}, {}
            if method == "PUT":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                user.update(d)
                return 200, {"data": copy.deepcopy(user), "errors": []}, {}
            if method == "DELETE":
                self.state["users"].remove(user)
                return 200, {"data": {"success": True}, "errors": []}, {}

        if subpath == "service-users":
            if method == "GET":
                svc_users = list(self.state["service_users"])
                data, pag = self._paginate_items(svc_users, limit, offset)
                return 200, {"data": data, "pagination": pag, "errors": []}, {}
            if method == "POST":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                name = str(d.get("name") or "").strip()
                scope = str(d.get("scope") or "").strip()
                exp = str(d.get("expirationDate") or "").strip()
                if not name or not scope or not exp:
                    return 400, self._s1_err(400010, "Bad parameter", "name, scope, expirationDate required"), {}
                self.state["id_counter"] += 1
                suid = f"svc-{self.state['id_counter']}"
                su = {
                    "id": suid,
                    "name": name,
                    "description": str(d.get("description") or ""),
                    "scope": scope,
                    "expirationDate": exp,
                    "scopeRoles": list(d.get("scopeRoles") or []),
                }
                self.state["service_users"].append(su)
                return 200, {"data": copy.deepcopy(su), "errors": []}, {}

        if subpath == "service-users/delete-service-users" and method == "POST":
            ids_set = {str(x) for x in body["filter"].get("ids") or []}
            before = len(self.state["service_users"])
            self.state["service_users"] = [u for u in self.state["service_users"] if u["id"] not in ids_set]
            return 200, {"data": {"affected": before - len(self.state["service_users"])}, "errors": []}, {}

        m_su_tok = re.match(r"^service-users/([^/]+)/generate-api-token$", subpath)
        if m_su_tok and method == "POST":
            suid = m_su_tok.group(1)
            su = next((u for u in self.state["service_users"] if u["id"] == suid), None)
            if su is None:
                return 404, self._s1_err(404001, "Service user not found", f"Unknown service user {suid}"), {}
            d = body.get("data") if isinstance(body.get("data"), dict) else {}
            self.state["id_counter"] += 1
            return (
                200,
                {
                    "data": {
                        "createdAt": _now_iso(),
                        "expiresAt": str(d.get("expirationDate") or su.get("expirationDate") or ""),
                        "token": f"s1-svc-tok-{self.state['id_counter']}",
                    },
                    "errors": [],
                },
                {},
            )

        m_su = re.match(r"^service-users/([^/]+)$", subpath)
        if m_su:
            suid = m_su.group(1)
            su = next((u for u in self.state["service_users"] if u["id"] == suid), None)
            if su is None:
                return 404, self._s1_err(404001, "Service user not found", f"Unknown service user {suid}"), {}
            if method == "GET":
                return 200, {"data": copy.deepcopy(su), "errors": []}, {}
            if method == "PUT":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                su.update(d)
                return 200, {"data": copy.deepcopy(su), "errors": []}, {}
            if method == "DELETE":
                self.state["service_users"].remove(su)
                return 200, {"data": {"success": True}, "errors": []}, {}

        if subpath == "rbac/roles" and method == "GET":
            roles = list(self.state["rbac_roles"])
            if "name" in query and query["name"][0].strip():
                nm = query["name"][0].strip().lower()
                roles = [r for r in roles if r.get("name", "").lower() == nm]
            data, pag = self._paginate_items(roles, limit, offset)
            return 200, {"data": data, "pagination": pag, "errors": []}, {}

        # --- Exclusions & Validate ---
        if subpath == "exclusions":
            if method == "GET":
                excls = list(self.state["exclusions"])
                site_f = set(_split_csv_param(query, "siteIds"))
                acc_f = set(_split_csv_param(query, "accountIds"))
                grp_f = set(_split_csv_param(query, "groupIds"))
                include_parents = _parse_bool_param(query, "includeParents", True)
                if site_f:
                    parent_acc_ids = {
                        str(s.get("accountId") or "")
                        for s in self.state["sites"]
                        if s["id"] in site_f
                    }
                    filtered_excls: list[dict[str, Any]] = []
                    for ex in excls:
                        sc = str(ex.get("scope") or "").lower()
                        sc_id = str(ex.get("scopeId") or "")
                        if sc == "site" and sc_id in site_f:
                            filtered_excls.append(ex)
                        elif include_parents and sc in ("account", "global", "tenant") and (
                            sc_id in parent_acc_ids or sc == "global"
                        ):
                            filtered_excls.append(ex)
                    excls = filtered_excls
                elif acc_f:
                    excls = [ex for ex in excls if str(ex.get("scopeId") or "") in acc_f]
                elif grp_f:
                    excls = [ex for ex in excls if str(ex.get("scopeId") or "") in grp_f]

                if "type" in query and query["type"][0].strip():
                    tp = query["type"][0].strip().lower()
                    excls = [ex for ex in excls if str(ex.get("type", "")).lower() == tp]
                os_f = {x.lower() for x in _split_csv_param(query, "osTypes")}
                if os_f:
                    excls = [ex for ex in excls if str(ex.get("osType", "")).lower() in os_f]
                if "value__contains" in query and query["value__contains"][0].strip():
                    sub = query["value__contains"][0].strip().lower()
                    excls = [ex for ex in excls if sub in str(ex.get("value", "")).lower()]
                data, pag = self._paginate_items(excls, limit, offset)
                return 200, {"data": data, "pagination": pag, "errors": []}, {}

            if method == "POST":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                flt = body["filter"]
                scope = "site"
                scope_id = ""
                if flt.get("siteIds"):
                    scope = "site"
                    scope_id = str(flt["siteIds"][0])
                elif flt.get("groupIds"):
                    scope = "group"
                    scope_id = str(flt["groupIds"][0])
                elif flt.get("accountIds"):
                    scope = "account"
                    scope_id = str(flt["accountIds"][0])
                self.state["id_counter"] += 1
                new_ex = {
                    "id": f"excl-{self.state['id_counter']}",
                    "scope": scope,
                    "scopeId": scope_id,
                    "type": d.get("type", "path"),
                    "osType": d.get("osType", "windows"),
                    "value": d.get("value", ""),
                    "mode": d.get("mode", "suppress"),
                    "description": d.get("description", ""),
                    **({"pathExclusionType": d["pathExclusionType"]} if "pathExclusionType" in d else {}),
                    **({"actions": d["actions"]} if "actions" in d else {}),
                }
                self.state["exclusions"].append(new_ex)
                return 200, {"data": [copy.deepcopy(new_ex)], "errors": []}, {}

            if method == "PUT":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                eid = str(d.get("id") or "")
                ex = next((item for item in self.state["exclusions"] if item["id"] == eid), None)
                if ex is None:
                    return 404, self._s1_err(404001, "Exclusion not found", f"Unknown exclusion {eid}"), {}
                ex.update(d)
                return 200, {"data": [copy.deepcopy(ex)], "errors": []}, {}

            if method == "DELETE":
                ids_set = {str(x) for x in body["data"]["ids"]}
                before = len(self.state["exclusions"])
                self.state["exclusions"] = [ex for ex in self.state["exclusions"] if ex["id"] not in ids_set]
                return 200, {"data": {"affected": before - len(self.state["exclusions"])}, "errors": []}, {}

        if subpath == "exclusions/validate" and method == "POST":
            d = body.get("data") if isinstance(body.get("data"), dict) else {}
            ex_type = str(d.get("exclusionType") or "").lower()
            os_type = str(d.get("osType") or "").lower()
            val = str(d.get("value") or "").strip()
            if val in ("/", "C:\\", "C:\\\\"):
                return 200, {"data": {"status": "Not recommended", "details": []}, "errors": []}, {}
            for existing in self.state["exclusions"]:
                ex_t = "hash" if existing.get("type") == "white_hash" else str(existing.get("type", "")).lower()
                if (
                    ex_t == ex_type
                    and str(existing.get("osType", "")).lower() == os_type
                    and str(existing.get("value", "")).strip().rstrip("\\/") == val.rstrip("\\/")
                ):
                    return 200, {"data": {"status": "Duplication", "details": []}, "errors": []}, {}
            return 200, {"data": {"status": "NONE", "details": []}, "errors": []}, {}

        # --- Threats & Cloud Detection ---
        if subpath == "threats" and method == "GET":
            threats = list(self.state["threats"])
            acc_f = set(_split_csv_param(query, "accountIds"))
            site_f = set(_split_csv_param(query, "siteIds"))
            grp_f = set(_split_csv_param(query, "groupIds"))
            threats = [
                t
                for t in threats
                if self._matches_scope(
                    t,
                    account_ids=acc_f,
                    site_ids=site_f,
                    group_ids=grp_f,
                    nested_paths=("agentRealtimeInfo", "agentDetectionInfo"),
                )
            ]
            st_f = {x.lower() for x in _split_csv_param(query, "incidentStatuses")}
            if st_f:
                threats = [
                    t
                    for t in threats
                    if str((t.get("threatInfo") or {}).get("incidentStatus", "")).lower() in st_f
                ]
            vd_f = {x.lower() for x in _split_csv_param(query, "analystVerdicts")}
            if vd_f:
                threats = [
                    t
                    for t in threats
                    if str((t.get("threatInfo") or {}).get("analystVerdict", "")).lower() in vd_f
                ]
            if "resolved" in query and query["resolved"][0].strip():
                want_resolved = _parse_bool_param(query, "resolved", False)
                threats = [
                    t
                    for t in threats
                    if (
                        str((t.get("threatInfo") or {}).get("incidentStatus", "")).lower() == "resolved"
                        or bool(t.get("resolved"))
                    )
                    is want_resolved
                ]
            if "computerNameContains" in query and query["computerNameContains"][0].strip():
                needle = query["computerNameContains"][0].strip().lower()
                threats = [
                    t
                    for t in threats
                    if needle in str((t.get("agentRealtimeInfo") or {}).get("agentComputerName", "")).lower()
                ]
            if "query" in query and query["query"][0].strip():
                needle = query["query"][0].strip().lower()
                threats = [
                    t
                    for t in threats
                    if needle in json.dumps(t).lower()
                ]
            data, pag = self._paginate_items(threats, limit, offset)
            return 200, {"data": data, "pagination": pag, "errors": []}, {}

        m_tl = re.match(r"^threats/([^/]+)/timeline$", subpath)
        if m_tl and method == "GET":
            tid = m_tl.group(1)
            if not any(t["id"] == tid for t in self.state["threats"]):
                return 404, self._s1_err(404001, "Threat not found", f"Unknown threat {tid}"), {}
            events = list(self.state.get("timelines", {}).get(tid, []))
            data, pag = self._paginate_items(events, limit, offset)
            return 200, {"data": data, "pagination": pag, "errors": []}, {}

        if subpath in ("threats/analyst-verdict", "threats/incident", "threats/notes") and method == "POST":
            targets = self._resolve_filter_targets(
                self.state["threats"],
                body["filter"],
                nested_paths=("agentRealtimeInfo", "agentDetectionInfo"),
            )
            d = body.get("data") if isinstance(body.get("data"), dict) else {}
            for t in targets:
                ti = t.setdefault("threatInfo", {})
                if subpath == "threats/analyst-verdict" and "analystVerdict" in d:
                    ti["analystVerdict"] = d["analystVerdict"]
                elif subpath == "threats/incident" and "incidentStatus" in d:
                    ti["incidentStatus"] = d["incidentStatus"]
                elif subpath == "threats/notes" and "text" in d:
                    self.state.setdefault("timelines", {}).setdefault(t["id"], []).append(
                        {"id": f"tl-note-{len(targets)}", "activityType": 4099, "primaryDescription": d["text"], "createdAt": _now_iso()}
                    )
            return 200, {"data": {"affected": len(targets)}, "errors": []}, {}

        if subpath.startswith("threats/mitigate/") and method == "POST":
            action = subpath[len("threats/mitigate/") :]
            targets = self._resolve_filter_targets(
                self.state["threats"],
                body["filter"],
                nested_paths=("agentRealtimeInfo", "agentDetectionInfo"),
            )
            for t in targets:
                t.setdefault("threatInfo", {})["mitigationStatus"] = f"mitigated:{action}"
            return 200, {"data": {"affected": len(targets)}, "errors": []}, {}

        if subpath == "threats/add-to-exclusions" and method == "POST":
            targets = self._resolve_filter_targets(
                self.state["threats"],
                body["filter"],
                nested_paths=("agentRealtimeInfo", "agentDetectionInfo"),
            )
            d = body.get("data") if isinstance(body.get("data"), dict) else {}
            for t in targets:
                self.state["id_counter"] += 1
                ti = t.get("threatInfo") or {}
                ari = t.get("agentRealtimeInfo") or {}
                self.state["exclusions"].append(
                    {
                        "id": f"excl-thr-{self.state['id_counter']}",
                        "scope": "site",
                        "scopeId": ari.get("siteId", ""),
                        "type": d.get("type", "white_hash"),
                        "osType": ari.get("agentOsType", "windows"),
                        "value": ti.get("sha1") or ti.get("filePath") or "",
                        "mode": d.get("mode", "suppress"),
                    }
                )
            return 200, {"data": {"affected": len(targets)}, "errors": []}, {}

        if subpath == "cloud-detection/alerts" and method == "GET":
            alerts = list(self.state["cloud_alerts"])
            acc_f = set(_split_csv_param(query, "accountIds"))
            site_f = set(_split_csv_param(query, "siteIds"))
            grp_f = set(_split_csv_param(query, "groupIds"))
            ids_f = set(_split_csv_param(query, "ids"))
            alerts = [
                a
                for a in alerts
                if self._matches_scope(
                    a,
                    account_ids=acc_f,
                    site_ids=site_f,
                    group_ids=grp_f,
                    ids=ids_f,
                    nested_paths=("agentDetectionInfo",),
                )
            ]
            inc_f = {
                x.lower()
                for x in (
                    _split_csv_param(query, "incidentStatus")
                    + _split_csv_param(query, "incidentStatuses")
                )
            }
            if inc_f:
                alerts = [
                    a
                    for a in alerts
                    if str((a.get("alertInfo") or {}).get("incidentStatus", "")).lower() in inc_f
                ]
            vd_f = {
                x.lower()
                for x in (
                    _split_csv_param(query, "analystVerdict")
                    + _split_csv_param(query, "analystVerdicts")
                )
            }
            if vd_f:
                alerts = [
                    a
                    for a in alerts
                    if str((a.get("alertInfo") or {}).get("analystVerdict", "")).lower() in vd_f
                ]
            sev_f = {
                x.lower()
                for x in (_split_csv_param(query, "severity") + _split_csv_param(query, "severities"))
            }
            if sev_f:
                alerts = [
                    a
                    for a in alerts
                    if str((a.get("ruleInfo") or {}).get("severity", "")).lower() in sev_f
                ]
            scopes_f = {x.lower() for x in _split_csv_param(query, "scopes")}
            if scopes_f:
                def _alert_scope(alert: Mapping[str, Any]) -> str:
                    explicit = str(alert.get("scope") or "").strip().lower()
                    if explicit:
                        return explicit
                    det = alert.get("agentDetectionInfo")
                    if isinstance(det, Mapping):
                        if det.get("groupId"):
                            return "group"
                        if det.get("siteId"):
                            return "site"
                        if det.get("accountId"):
                            return "account"
                    return ""

                alerts = [a for a in alerts if _alert_scope(a) in scopes_f]
            if "ruleName__contains" in query and query["ruleName__contains"][0].strip():
                rn = query["ruleName__contains"][0].strip().lower()
                alerts = [
                    a
                    for a in alerts
                    if rn in str((a.get("ruleInfo") or {}).get("name", "")).lower()
                ]
            if "origAgentName__contains" in query and query["origAgentName__contains"][0].strip():
                an = query["origAgentName__contains"][0].strip().lower()
                alerts = [
                    a
                    for a in alerts
                    if an in str((a.get("agentDetectionInfo") or {}).get("name", "")).lower()
                ]
            if (
                "sourceProcessFileHashSha1__contains" in query
                and query["sourceProcessFileHashSha1__contains"][0].strip()
            ):
                sh = query["sourceProcessFileHashSha1__contains"][0].strip().lower()
                alerts = [
                    a
                    for a in alerts
                    if sh in str((a.get("sourceProcessInfo") or {}).get("fileHashSha1", "")).lower()
                ]
            os_f = {x.lower() for x in _split_csv_param(query, "osType")}
            if os_f:
                alerts = [
                    a
                    for a in alerts
                    if str((a.get("agentDetectionInfo") or {}).get("osType", "")).lower() in os_f
                ]
            q_str = (query.get("query") or [""])[0].strip().lower()
            if q_str:
                alerts = [
                    a
                    for a in alerts
                    if q_str
                    in " ".join(
                        str(v)
                        for v in (
                            a.get("id", ""),
                            (a.get("alertInfo") or {}).get("alertId", ""),
                            (a.get("alertInfo") or {}).get("incidentStatus", ""),
                            (a.get("alertInfo") or {}).get("analystVerdict", ""),
                            (a.get("ruleInfo") or {}).get("name", ""),
                            (a.get("ruleInfo") or {}).get("severity", ""),
                            (a.get("sourceProcessInfo") or {}).get("name", ""),
                            (a.get("sourceProcessInfo") or {}).get("fileHashSha1", ""),
                            (a.get("agentDetectionInfo") or {}).get("name", ""),
                            (a.get("agentDetectionInfo") or {}).get("siteName", ""),
                            (a.get("agentDetectionInfo") or {}).get("siteId", ""),
                        )
                    ).lower()
                ]
            data, pag = self._paginate_items(alerts, limit, offset)
            return 200, {"data": data, "pagination": pag, "errors": []}, {}

        if subpath in ("cloud-detection/alerts/analyst-verdict", "cloud-detection/alerts/incident") and method == "POST":
            targets = self._resolve_filter_targets(
                self.state["cloud_alerts"],
                body["filter"],
                nested_paths=("agentDetectionInfo",),
            )
            d = body.get("data") if isinstance(body.get("data"), dict) else {}
            for a in targets:
                ai = a.setdefault("alertInfo", {})
                if subpath.endswith("analyst-verdict") and "analystVerdict" in d:
                    ai["analystVerdict"] = d["analystVerdict"]
                elif subpath.endswith("incident") and "incidentStatus" in d:
                    ai["incidentStatus"] = d["incidentStatus"]
            return 200, {"data": {"affected": len(targets)}, "errors": []}, {}

        # --- Agents & Actions ---
        if subpath in ("agents", "agents/count") and method == "GET":
            agents = list(self.state["agents"])
            acc_f = set(_split_csv_param(query, "accountIds"))
            site_f = set(_split_csv_param(query, "siteIds"))
            grp_f = set(_split_csv_param(query, "groupIds"))
            ids_f = set(_split_csv_param(query, "ids"))
            agents = [
                ag
                for ag in agents
                if self._matches_scope(ag, account_ids=acc_f, site_ids=site_f, group_ids=grp_f, ids=ids_f)
            ]
            if "isActive" in query:
                want_active = _parse_bool_param(query, "isActive", True)
                agents = [ag for ag in agents if bool(ag.get("isActive")) is want_active]
            if "infected" in query:
                want_inf = _parse_bool_param(query, "infected", False)
                agents = [ag for ag in agents if bool(ag.get("infected")) is want_inf]
            if "computerName__contains" in query and query["computerName__contains"][0].strip():
                needle = query["computerName__contains"][0].strip().lower()
                agents = [ag for ag in agents if needle in str(ag.get("computerName", "")).lower()]
            if "query" in query and query["query"][0].strip():
                needle = query["query"][0].strip().lower()
                agents = [ag for ag in agents if needle in json.dumps(ag).lower()]
            if subpath == "agents/count":
                return 200, {"data": {"total": len(agents)}, "errors": []}, {}
            data, pag = self._paginate_items(agents, limit, offset)
            return 200, {"data": data, "pagination": pag, "errors": []}, {}

        if subpath.startswith("agents/actions/") and method == "POST":
            action = subpath[len("agents/actions/") :]
            targets = self._resolve_filter_targets(self.state["agents"], body["filter"])
            d = body.get("data") if isinstance(body.get("data"), dict) else {}
            for ag in targets:
                if action == "disconnect":
                    ag["networkStatus"] = "disconnected"
                elif action == "connect":
                    ag["networkStatus"] = "connected"
                elif action == "decommission":
                    ag["isDecommissioned"] = True
                    ag["isActive"] = False
                elif action == "move-to-site":
                    target_sid = str(d.get("targetSiteId") or "")
                    target_site = next((s for s in self.state["sites"] if s["id"] == target_sid), None)
                    ag["siteId"] = target_sid
                    if target_site:
                        ag["siteName"] = target_site["name"]
                elif action == "manage-tags":
                    op = d.get("operation", "add")
                    tags_in = d.get("tags") or []
                    cur = ag.setdefault("tags", {}).setdefault("sentinelone", [])
                    if op == "add":
                        for tg in tags_in:
                            if tg not in cur:
                                cur.append(tg)
                    elif op == "remove":
                        ag["tags"]["sentinelone"] = [t for t in cur if t not in tags_in]
            return 200, {"data": {"affected": len(targets)}, "errors": []}, {}

        # --- Blocklist Restrictions ---
        if subpath == "restrictions":
            if method == "GET":
                items = list(self.state["restrictions"])
                site_f = set(_split_csv_param(query, "siteIds"))
                acc_f = set(_split_csv_param(query, "accountIds"))
                if site_f:
                    items = [r for r in items if str(r.get("siteId") or r.get("scopeId") or "") in site_f]
                elif acc_f:
                    items = [r for r in items if str(r.get("scopeId") or "") in acc_f]
                if "value__contains" in query and query["value__contains"][0].strip():
                    sub = query["value__contains"][0].strip().lower()
                    items = [r for r in items if sub in str(r.get("value", "")).lower()]
                data, pag = self._paginate_items(items, limit, offset)
                return 200, {"data": data, "pagination": pag, "errors": []}, {}
            if method == "POST":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                val = str(d.get("value") or "").strip().lower()
                if not _SHA1_HEX_RE.match(val):
                    return 400, self._s1_err(400010, "Invalid SHA-1", "Blocklist requires a 40-char hex SHA-1"), {}
                flt = body["filter"]
                scope_id = str((flt.get("siteIds") or flt.get("accountIds") or flt.get("groupIds") or [""])[0])
                scope = "site" if flt.get("siteIds") else ("group" if flt.get("groupIds") else "account")
                self.state["id_counter"] += 1
                entry = {
                    "id": f"rst-{self.state['id_counter']}",
                    "scope": scope,
                    "scopeId": scope_id,
                    "siteId": scope_id if scope == "site" else "",
                    "type": "black_hash",
                    "osType": d.get("osType", "windows"),
                    "value": val,
                    "description": d.get("description", ""),
                    "source": d.get("source", "soclens"),
                }
                self.state["restrictions"].append(entry)
                return 200, {"data": [copy.deepcopy(entry)], "errors": []}, {}
            if method == "PUT":
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                rid = str(d.get("id") or "")
                val = str(d.get("value") or "").strip().lower()
                if val and not _SHA1_HEX_RE.match(val):
                    return 400, self._s1_err(400010, "Invalid SHA-1", "Blocklist requires a 40-char hex SHA-1"), {}
                item = next((r for r in self.state["restrictions"] if r["id"] == rid), None)
                if item is None:
                    return 404, self._s1_err(404001, "Restriction not found", f"Unknown restriction {rid}"), {}
                item.update(d)
                return 200, {"data": [copy.deepcopy(item)], "errors": []}, {}
            if method == "DELETE":
                ids_set = {str(x) for x in body["data"]["ids"]}
                before = len(self.state["restrictions"])
                self.state["restrictions"] = [r for r in self.state["restrictions"] if r["id"] not in ids_set]
                return 200, {"data": {"affected": before - len(self.state["restrictions"])}, "errors": []}, {}

        # --- Activities & Deep Visibility ---
        if subpath == "activities" and method == "GET":
            acts = list(self.state["activities"])
            acc_f = set(_split_csv_param(query, "accountIds"))
            site_f = set(_split_csv_param(query, "siteIds"))
            acts = [a for a in acts if self._matches_scope(a, account_ids=acc_f, site_ids=site_f)]
            data, pag = self._paginate_items(acts, limit, offset)
            return 200, {"data": data, "pagination": pag, "errors": []}, {}

        if subpath == "dv/init-query" and method == "POST":
            self.state["id_counter"] += 1
            qid = f"dvq-{self.state['id_counter']}"
            self.state["dv_queries"][qid] = {
                "queryId": qid,
                "responseState": "FINISHED",
                "progressStatus": 100,
                "events": [
                    {
                        "id": f"dve-{self.state['id_counter']}",
                        "agentName": "wkstn-1001-01.example.test",
                        "processName": "procdump64.exe",
                        "siteId": "100101",
                        "createdAt": _now_iso(),
                    }
                ],
            }
            return 200, {"data": {"queryId": qid}, "errors": []}, {}

        if subpath == "dv/query-status" and method == "GET":
            qid = (query.get("queryId") or [""])[0].strip()
            dq = self.state["dv_queries"].get(qid)
            if dq is None:
                return 404, self._s1_err(404001, "DV query not found", f"Unknown queryId {qid}"), {}
            return (
                200,
                {
                    "data": {
                        "queryId": qid,
                        "responseState": dq["responseState"],
                        "progressStatus": dq["progressStatus"],
                    },
                    "errors": [],
                },
                {},
            )

        if subpath == "dv/events" and method == "GET":
            qid = (query.get("queryId") or [""])[0].strip()
            dq = self.state["dv_queries"].get(qid)
            if dq is None:
                return 404, self._s1_err(404001, "DV query not found", f"Unknown queryId {qid}"), {}
            data, pag = self._paginate_items(dq["events"], limit, offset)
            return 200, {"data": data, "pagination": pag, "errors": []}, {}

        return 404, self._s1_err(404001, "Not found", f"Unknown endpoint: {method} {subpath}"), {}


# ======================================================================
# Pytest Fixtures
# ======================================================================


@pytest.fixture
def v21_workspace(e2e_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Extend ``e2e_workspace`` by scrubbing all v2.1 env vars and resetting caches."""
    for key in list(os.environ):
        if key.startswith(_V21_ENV_PREFIXES) or key in _V21_ENV_KEYS:
            monkeypatch.delenv(key, raising=False)
    clear_session_overrides()
    invalidate_settings_cache()
    try:
        yield e2e_workspace
    finally:
        clear_session_overrides()
        invalidate_settings_cache()


@pytest.fixture
def mock_secret_server(
    v21_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[MockSecretServer]:
    server = MockSecretServer()
    monkeypatch.setenv("TSS_BASE_URL", server.base_url)
    monkeypatch.setenv("TSS_AUTH_MODE", "password")
    monkeypatch.setenv("TSS_USERNAME", "e2e-tss-user")
    monkeypatch.setenv("TSS_PASSWORD", "e2e-tss-password")
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def mock_vault_server(
    v21_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[MockHashiCorpVaultServer]:
    server = MockHashiCorpVaultServer()
    monkeypatch.setenv("VAULT_ADDR", server.base_url)
    monkeypatch.setenv("VAULT_AUTH_MODE", "token")
    monkeypatch.setenv("VAULT_TOKEN", "e2e-vault-token-001")
    monkeypatch.setenv("VAULT_KV_MOUNT", "secret")
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def mock_op_connect_server(
    v21_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[MockOnePasswordConnectServer]:
    server = MockOnePasswordConnectServer()
    monkeypatch.setenv("OP_CONNECT_URL", server.base_url)
    monkeypatch.setenv("OP_CONNECT_TOKEN", "e2e-op-connect-token-001")
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def mock_bitwarden_server(
    v21_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[MockBitwardenServer]:
    server = MockBitwardenServer()
    monkeypatch.setenv("BW_SERVE_URL", server.base_url)
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def mock_splunk_es_server(
    v21_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[MockSplunkESServer]:
    server = MockSplunkESServer()
    monkeypatch.setenv("SPLUNK_HOST", server.base_url)
    monkeypatch.setenv("SPLUNK_TOKEN", "test-splunk-token")
    monkeypatch.setenv("SPLUNK_APP", "SplunkEnterpriseSecuritySuite")
    monkeypatch.setenv("SPLUNK_VERIFY_SSL", "false")
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def mock_s1_server(
    v21_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[MockSentinelOneServer]:
    server = MockSentinelOneServer()
    monkeypatch.setenv("S1_CONSOLE_URL", server.base_url)
    monkeypatch.setenv("S1_API_TOKEN", "test-s1-token")
    monkeypatch.setenv("S1_VERIFY_SSL", "false")
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def mock_llm_server(
    v21_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[MockLocalLLMServer]:
    server = MockLocalLLMServer()
    monkeypatch.setenv("RF_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("RF_LLM_BASE_URL", server.base_url)
    monkeypatch.setenv("RF_LLM_MODEL", "llama3.2:latest")
    try:
        yield server
    finally:
        server.close()


# ======================================================================
# Offline Self-Test Harness
# ======================================================================


def _assert_synthetic_payload(data: Any) -> None:
    serialized = json.dumps(data)
    forbidden = ("recordedfuture.com", "sentinelone.net", "splunkcloud.com")
    for marker in forbidden:
        assert marker not in serialized.lower(), f"Forbidden domain marker found: {marker}"


def run_v21_mocks_self_test() -> None:
    """Exercise all 7 local mock servers, guardrails, faults, and synthetic fixtures offline."""
    import requests

    # 1. Fixtures validation
    sec_fix = _load_fixture("v21_secret_stores.json")
    llm_fix = _load_fixture("v21_llm.json")
    es_fix = _load_fixture("v21_splunk_es.json")
    s1_fix = _load_fixture("v21_sentinelone.json")
    for fix in (sec_fix, llm_fix, es_fix, s1_fix):
        _assert_synthetic_payload(fix)
    expected_keys = set(SECRET_MANAGED_SETTING_KEYS)
    for prov in ("secret_server", "hashicorp_vault", "onepassword_connect", "bitwarden"):
        assert set(sec_fix[prov]["recommended_map"].keys()) == expected_keys

    # 2. MockSecretServer
    with MockSecretServer() as tss:
        assert (
            requests.post(
                f"{tss.base_url}/oauth2/token",
                data={"grant_type": "password", "username": "e2e-tss-user", "password": "wrong"},
                timeout=5,
            ).status_code
            == 400
        )
        r_tok = requests.post(
            f"{tss.base_url}/oauth2/token",
            data={"grant_type": "password", "username": "e2e-tss-user", "password": "e2e-tss-password"},
            timeout=5,
        )
        assert r_tok.status_code == 200
        tok_data = r_tok.json()
        at, rt = tok_data["access_token"], tok_data["refresh_token"]

        r_ref = requests.post(
            f"{tss.base_url}/oauth2/token",
            data={"grant_type": "refresh_token", "refresh_token": rt},
            timeout=5,
        )
        assert r_ref.status_code == 200
        at2 = r_ref.json()["access_token"]
        assert (
            requests.post(
                f"{tss.base_url}/oauth2/token",
                data={"grant_type": "refresh_token", "refresh_token": rt},
                timeout=5,
            ).status_code
            == 400
        )

        r_plat = requests.post(
            f"{tss.base_url}/identity/api/oauth2/token/xpmplatform",
            data={
                "grant_type": "client_credentials",
                "client_id": "e2e-tss-client-id",
                "client_secret": "e2e-tss-client-secret",
            },
            timeout=5,
        )
        assert r_plat.status_code == 200
        plat_at = r_plat.json()["access_token"]
        r_vb = requests.get(
            f"{tss.base_url}/vaultbroker/api/vaults",
            headers={"Authorization": f"Bearer {plat_at}"},
            timeout=5,
        )
        assert r_vb.status_code == 200 and r_vb.json()[0]["connection"]["url"] == tss.base_url

        hdrs = {"Authorization": f"Bearer {at2}"}
        r_list = requests.get(
            f"{tss.base_url}/api/v1/secrets?filter.searchText=Splunk&filter.folderId=10",
            headers=hdrs,
            timeout=5,
        )
        assert r_list.status_code == 200 and r_list.json()["records"][0]["id"] == 1002
        assert requests.get(f"{tss.base_url}/api/v1/secrets/1002", headers=hdrs, timeout=5).status_code == 200
        r_fld = requests.get(
            f"{tss.base_url}/api/v1/secrets/1002/fields/splunk-token",
            headers=hdrs,
            timeout=5,
        )
        assert r_fld.status_code == 200 and r_fld.json()["value"] == "e2e-tss-splunk-token"

        tss.queue_fault("/api/v1/secrets/", 503)
        assert requests.get(f"{tss.base_url}/api/v1/secrets/1002", headers=hdrs, timeout=5).status_code == 503
        assert requests.get(f"{tss.base_url}/api/v1/secrets/1002", headers=hdrs, timeout=5).status_code == 200

        assert requests.post(f"{tss.base_url}/api/v1/oauth-expiration", headers=hdrs, timeout=5).status_code == 200
        assert requests.get(f"{tss.base_url}/api/v1/secrets/1002", headers=hdrs, timeout=5).status_code == 401
        assert at != at2

    # 3. MockHashiCorpVaultServer
    with MockHashiCorpVaultServer() as vault:
        assert requests.get(f"{vault.base_url}/v1/auth/token/lookup-self", timeout=5).status_code == 403
        vh = {"X-Vault-Token": "e2e-vault-token-001"}
        assert requests.get(f"{vault.base_url}/v1/auth/token/lookup-self", headers=vh, timeout=5).status_code == 200
        r_ar = requests.post(
            f"{vault.base_url}/v1/auth/approle/login",
            json={"role_id": "e2e-vault-role-001", "secret_id": "e2e-vault-secret-001"},
            timeout=5,
        )
        assert r_ar.status_code == 200 and r_ar.json()["auth"]["client_token"]

        r_root = requests.request("LIST", f"{vault.base_url}/v1/secret/metadata", headers=vh, timeout=5)
        assert r_root.status_code == 200 and r_root.json()["data"]["keys"] == ["soclens/"]
        r_sub = requests.get(f"{vault.base_url}/v1/secret/metadata/soclens?list=true", headers=vh, timeout=5)
        assert r_sub.status_code == 200 and sorted(r_sub.json()["data"]["keys"]) == ["edr", "llm", "rf", "splunk"]

        vault.set_allow_list_verb(False)
        assert requests.request("LIST", f"{vault.base_url}/v1/secret/metadata", headers=vh, timeout=5).status_code == 405
        assert requests.get(f"{vault.base_url}/v1/secret/metadata?list=true", headers=vh, timeout=5).status_code == 200
        vault.set_allow_list_verb(True)

        vault.set_required_namespace("soc-prod")
        assert requests.get(f"{vault.base_url}/v1/auth/token/lookup-self", headers=vh, timeout=5).status_code == 403
        vh_ns = {**vh, "X-Vault-Namespace": "soc-prod"}
        assert requests.get(f"{vault.base_url}/v1/auth/token/lookup-self", headers=vh_ns, timeout=5).status_code == 200
        vault.set_required_namespace(None)

        r_sk = requests.get(f"{vault.base_url}/v1/secret/subkeys/soclens/rf", headers=vh, timeout=5)
        assert r_sk.status_code == 200 and r_sk.json()["data"]["subkeys"]["api_token"] is None
        vault.queue_fault("/v1/secret/subkeys/", 403)
        assert requests.get(f"{vault.base_url}/v1/secret/subkeys/soclens/rf", headers=vh, timeout=5).status_code == 403
        r_data = requests.get(f"{vault.base_url}/v1/secret/data/soclens/rf", headers=vh, timeout=5)
        assert r_data.status_code == 200 and r_data.json()["data"]["data"]["api_token"] == "e2e-vault-rf-api-token"

    # 4. MockOnePasswordConnectServer
    with MockOnePasswordConnectServer() as op:
        assert requests.get(f"{op.base_url}/heartbeat", timeout=5).status_code == 200
        assert requests.get(f"{op.base_url}/v1/vaults", timeout=5).status_code == 401
        oh = {"Authorization": "Bearer e2e-op-connect-token-001"}
        r_vs = requests.get(f"{op.base_url}/v1/vaults", headers=oh, timeout=5)
        assert r_vs.status_code == 200
        vid = r_vs.json()[0]["id"]
        r_its = requests.get(f"{op.base_url}/v1/vaults/{vid}/items", headers=oh, timeout=5)
        assert r_its.status_code == 200 and "fields" not in r_its.json()[0]
        iid = r_its.json()[0]["id"]
        r_it = requests.get(f"{op.base_url}/v1/vaults/{vid}/items/{iid}", headers=oh, timeout=5)
        assert r_it.status_code == 200 and len(r_it.json()["fields"]) == 5
        assert requests.get(f"{op.base_url}/v1/vaults/{vid}/items/missing", headers=oh, timeout=5).status_code == 404

    # 5. MockBitwardenServer
    with MockBitwardenServer() as bw:
        bw.set_lock_status("unauthenticated")
        assert requests.get(f"{bw.base_url}/status", timeout=5).json()["data"]["template"]["status"] == "unauthenticated"
        assert requests.post(f"{bw.base_url}/unlock", json={"password": "x"}, timeout=5).status_code == 400
        bw.set_lock_status("locked")
        assert requests.get(f"{bw.base_url}/list/object/items", timeout=5).status_code == 400
        assert requests.post(f"{bw.base_url}/unlock", json={"password": "wrong"}, timeout=5).status_code == 400
        assert requests.post(f"{bw.base_url}/unlock", json={"password": "e2e-bw-master-password"}, timeout=5).status_code == 200
        assert requests.get(f"{bw.base_url}/status", timeout=5).json()["data"]["template"]["status"] == "unlocked"
        assert requests.post(f"{bw.base_url}/sync", timeout=5).status_code == 200
        r_bw_l = requests.get(f"{bw.base_url}/list/object/items?search=Splunk", timeout=5)
        assert r_bw_l.status_code == 200 and len(r_bw_l.json()["data"]["data"]) == 1
        iid = r_bw_l.json()["data"]["data"][0]["id"]
        assert requests.get(f"{bw.base_url}/object/item/{iid}", timeout=5).status_code == 200
        assert requests.get(f"{bw.base_url}/object/item/missing", timeout=5).status_code == 404

    # 6. MockLocalLLMServer
    with MockLocalLLMServer() as llm:
        assert requests.get(f"{llm.base_url}/api/tags", timeout=5).status_code == 200
        r_ol = requests.post(
            f"{llm.base_url}/api/chat",
            json={"model": "llama3.2:latest", "messages": [{"role": "user", "content": "Hello"}], "stream": False},
            timeout=5,
        )
        assert r_ol.status_code == 200 and r_ol.json()["done"] is True
        r_ols = requests.post(
            f"{llm.base_url}/api/chat",
            json={"model": "llama3.2:latest", "messages": [{"role": "user", "content": "Hello"}], "stream": True},
            timeout=5,
        )
        assert r_ols.status_code == 200 and '"done": true' in r_ols.text

        assert requests.get(f"{llm.openai_base_url}/models", timeout=5).status_code == 200
        r_oa = requests.post(
            f"{llm.openai_base_url}/chat/completions",
            json={"model": "qwen2.5-coder:7b", "messages": [{"role": "user", "content": "[ES + Tenant"}], "stream": False},
            timeout=5,
        )
        assert r_oa.status_code == 200 and "Closing Note" in r_oa.json()["choices"][0]["message"]["content"]
        r_oas = requests.post(
            f"{llm.openai_base_url}/chat/completions",
            json={"model": "qwen2.5-coder:7b", "messages": [{"role": "user", "content": "Hi"}], "stream": True},
            timeout=5,
        )
        assert r_oas.status_code == 200 and "data: [DONE]" in r_oas.text
        llm.set_required_api_key("e2e-llm-api-key-001")
        assert requests.get(f"{llm.openai_base_url}/models", timeout=5).status_code == 401
        assert (
            requests.get(
                f"{llm.openai_base_url}/models",
                headers={"Authorization": "Bearer e2e-llm-api-key-001"},
                timeout=5,
            ).status_code
            == 200
        )
        llm.reset()
        assert llm.requests_log == []

    # 7. MockSplunkESServer
    with MockSplunkESServer() as es:
        mc_base = f"{es.base_url}/servicesNS/nobody/missioncontrol/public/v2"
        assert requests.get(f"{mc_base}/findings", timeout=5).status_code == 401
        assert requests.get(f"{es.base_url}/services/server/info", timeout=5).status_code == 401

        eh = {"Authorization": "Bearer test-splunk-token"}
        basic_tok = base64.b64encode(b"soc_analyst:test-splunk-password").decode("ascii")
        assert requests.get(f"{es.base_url}/services/server/info", headers={"Authorization": f"Basic {basic_tok}"}, timeout=5).status_code == 200

        r_unk = requests.get(f"{mc_base}/findings?tenant_id=1001&limit=20", headers=eh, timeout=5)
        assert r_unk.status_code == 200 and r_unk.json()["total"] == len(es_fix["findings"])
        assert es.requests_log[-1]["query"]["tenant_id"] == ["1001"]
        es.set_ignore_unknown_finding_params(False)
        assert requests.get(f"{mc_base}/findings?tenant_id=1001", headers=eh, timeout=5).status_code == 400
        es.set_ignore_unknown_finding_params(True)

        r_inv = requests.get(f"{mc_base}/investigations", headers=eh, timeout=5)
        assert r_inv.status_code == 200 and isinstance(r_inv.json(), list) and len(r_inv.json()) >= 2

        r_cf = requests.post(
            f"{mc_base}/findings",
            headers=eh,
            json={
                "rule_title": "Manual E2E Test",
                "security_domain": "endpoint",
                "additional_fields": [{"name": "tenant_id", "value": "1001"}],
            },
            timeout=5,
        )
        assert r_cf.status_code == 201
        fid = r_cf.json()["finding_id"]
        assert requests.get(f"{mc_base}/findings/{urllib.parse.quote(fid, safe='')}", headers=eh, timeout=5).status_code == 200

        r_bc = requests.post(
            f"{mc_base}/findings/bulk_create",
            headers=eh,
            json=[{"rule_title": "Bulk 1", "security_domain": "network"}],
            timeout=5,
        )
        assert r_bc.status_code == 201 and r_bc.json()["status"] == "success" and r_bc.json()["created"] == 1

        r_ci = requests.post(f"{mc_base}/investigations", headers=eh, json={"name": "E2E Inv"}, timeout=5)
        assert r_ci.status_code == 201
        guid = r_ci.json()["investigation_guid"]
        assert (
            requests.post(
                f"{mc_base}/investigations/{guid}/findings",
                headers=eh,
                json={"finding_ids": ["fnd-1001-a"], "finding_times": ["2026-11-25T02:15:00Z"]},
                timeout=5,
            ).status_code
            == 200
        )
        assert (
            requests.post(
                f"{mc_base}/investigations/bulk_update",
                headers=eh,
                json={"record_ids": ["fnd-1001-a"], "status": "In Progress"},
                timeout=5,
            ).status_code
            == 200
        )
        r_bf = requests.post(
            f"{mc_base}/investigations/bulk_update",
            headers=eh,
            json={"record_ids": ["fnd-1001-a", "missing-id"], "status": "Closed"},
            timeout=5,
        )
        assert r_bf.status_code == 400 and r_bf.json()["message"] == "Partial failure"
        r_baq = requests.post(
            f"{mc_base}/investigations/bulk_update",
            headers=eh,
            json={"record_ids": [], "aq_sid": "1700000100.11", "status": "Resolved"},
            timeout=5,
        )
        assert r_baq.status_code == 200 and r_baq.json() == [{"id": "fnd-1001-a"}]
        assert requests.get(f"{mc_base}/findings/fnd-1001-a", headers=eh, timeout=5).json()["status"] == "4"
        assert (
            requests.post(
                f"{mc_base}/investigations/bulk_update",
                headers=eh,
                json={"record_ids": ["fnd-1001-a"], "aq_sid": "1700000100.11", "status": "New"},
                timeout=5,
            ).status_code
            == 400
        )
        r_aq_job = requests.post(
            f"{es.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs?output_mode=json",
            headers=eh,
            data={"search": '`notable` | search tenant_id="1002"'},
            timeout=5,
        )
        aq_job_sid = r_aq_job.json()["sid"]
        r_baq_job = requests.post(
            f"{mc_base}/investigations/bulk_update",
            headers=eh,
            json={"record_ids": [], "aq_sid": aq_job_sid, "status": "Pending"},
            timeout=5,
        )
        assert r_baq_job.status_code == 200 and r_baq_job.json() == [{"id": "fnd-1002-org"}]
        assert requests.get(f"{mc_base}/findings/fnd-1002-org", headers=eh, timeout=5).json()["status"] == "3"

        r_cn = requests.post(f"{mc_base}/investigations/{guid}/notes", headers=eh, json={"content": "Note body"}, timeout=5)
        assert r_cn.status_code == 201
        nid = r_cn.json()["id"]
        assert requests.get(f"{mc_base}/investigations/{guid}/notes", headers=eh, timeout=5).json()["total"] == 1
        assert requests.get(f"{mc_base}/investigations/{guid}/notes?offset=abc&limit=xyz", headers=eh, timeout=5).status_code == 400
        assert requests.post(f"{mc_base}/investigations/{guid}/notes/{nid}", headers=eh, json={"content": "Updated"}, timeout=5).status_code == 200
        assert requests.delete(f"{mc_base}/investigations/{guid}/notes/{nid}", headers=eh, timeout=5).status_code == 200
        assert len(requests.get(f"{mc_base}/investigations/{guid}/history", headers=eh, timeout=5).json()["items"]) >= 2
        assert requests.get(f"{mc_base}/investigations/{guid}/history?offset=abc&limit=xyz", headers=eh, timeout=5).status_code == 400

        assert requests.get(f"{mc_base}/queues", headers=eh, timeout=5).status_code == 200
        assert requests.get(f"{mc_base}/assets/wkstn-1001-01.example.test", headers=eh, timeout=5).status_code == 200
        assert requests.get(f"{mc_base}/identity/jdoe@example.test", headers=eh, timeout=5).status_code == 200
        r_rs = requests.get(f"{mc_base}/risks/risk_scores/wkstn-1001-01.example.test", headers=eh, timeout=5)
        assert r_rs.status_code == 200 and isinstance(r_rs.json(), list)
        assert (
            requests.post(
                f"{mc_base}/risks/risk_scores/wkstn-1001-01.example.test",
                headers=eh,
                json={"risk_modifier": "not-a-number", "entity_type": "system"},
                timeout=5,
            ).status_code
            == 400
        )

        es.set_mc_v2_enabled(False)
        assert requests.get(f"{mc_base}/findings", headers=eh, timeout=5).status_code == 404
        es.set_mc_v2_enabled(True)

        assert requests.get(f"{es.base_url}/servicesNS/-/-/configs/conf-incident_review/incident_review?output_mode=json", headers=eh, timeout=5).status_code == 404
        es.set_incident_review_404_fallback(False)
        assert requests.get(f"{es.base_url}/servicesNS/-/-/configs/conf-incident_review/incident_review?output_mode=json", headers=eh, timeout=5).status_code == 200
        es.set_incident_review_404_fallback(True)
        r_lr = requests.get(f"{es.base_url}/servicesNS/-/-/configs/conf-log_review/incident_review?output_mode=json", headers=eh, timeout=5)
        attrs = json.loads(r_lr.json()["entry"][0]["content"]["event_attributes"])
        assert any(a["field"] == "tenant_id" for a in attrs)

        r_lj = requests.post(
            f"{es.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs?output_mode=json",
            headers=eh,
            data={"search": '| loadjob "1700000100.11"'},
            timeout=5,
        )
        sid = r_lj.json()["sid"]
        assert requests.get(f"{es.base_url}/services/search/jobs/{sid}?output_mode=json", headers=eh, timeout=5).json()["entry"][0]["content"]["isDone"] is True
        assert len(requests.get(f"{es.base_url}/services/search/jobs/{sid}/results?output_mode=json", headers=eh, timeout=5).json()["results"]) == 2
        assert requests.get(f"{es.base_url}/services/search/jobs/{sid}/results?output_mode=json&offset=abc", headers=eh, timeout=5).status_code == 400
        assert requests.get(f"{es.base_url}/services/search/jobs/{sid}/results?output_mode=json&count=xyz", headers=eh, timeout=5).status_code == 400

        r_not_spl = requests.post(
            f"{es.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs?output_mode=json",
            headers=eh,
            data={"search": '`notable` | search _raw="*mimikatz_marker_raw*" | head 10'},
            timeout=5,
        )
        not_sid = r_not_spl.json()["sid"]
        not_rows = requests.get(f"{es.base_url}/services/search/jobs/{not_sid}/results?output_mode=json", headers=eh, timeout=5).json()["results"]
        assert len(not_rows) == 1 and not_rows[0]["event_id"] == "fnd-raw-only"

        assert requests.post(
            f"{es.base_url}/services/notable_update?output_mode=json",
            headers=eh,
            data={"ruleUIDs": "fnd-1001-a@@notable@@1001", "status": "4", "comment": "Legacy close"},
            timeout=5,
        ).status_code == 200
        assert requests.get(f"{mc_base}/findings/fnd-1001-a", headers=eh, timeout=5).json()["status"] == "4"
        fnd_notes = requests.get(f"{mc_base}/investigations/fnd-1001-a/notes", headers=eh, timeout=5).json()["items"]
        assert any(n.get("content") == "Legacy close" for n in fnd_notes)

        assert requests.get(f"{es.base_url}/servicesNS/nobody/SA-ThreatIntelligence/alerts/modaction_invocations?output_mode=json", headers=eh, timeout=5).status_code == 400
        assert requests.get(f"{es.base_url}/servicesNS/nobody/SA-ThreatIntelligence/alerts/modaction_invocations?output_mode=json&sid=1700000100.11&rid=0", headers=eh, timeout=5).status_code == 200
        assert (
            requests.post(
                f"{es.base_url}/services/alerts/modaction_adhoc?output_mode=json",
                headers=eh,
                data={"action_name": "ping", "sid": "1700000100.11", "rid": "0", "param.dest": "203.0.113.45"},
                timeout=5,
            ).status_code
            == 200
        )
        assert requests.get(f"{es.base_url}/servicesNS/-/-/alerts/alert_actions?output_mode=json", headers=eh, timeout=5).status_code == 200
        assert requests.get(f"{es.base_url}/services/authentication/users?output_mode=json", headers=eh, timeout=5).status_code == 200
        assert requests.post(f"{es.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/ES_Disabled_Test_Rule?output_mode=json", headers=eh, data={"disabled": "0"}, timeout=5).status_code == 200
        assert requests.post(f"{es.base_url}/servicesNS/nobody/DA-ESS-ThreatIntelligence/storage/collections/data/ip_intel", headers=eh, json={"ip": "203.0.113.77"}, timeout=5).status_code == 201

        es.queue_fault("/servicesNS/nobody/missioncontrol/public/v2/findings", 429, headers={"Retry-After": "1"})
        r_429 = requests.get(f"{mc_base}/findings", headers=eh, timeout=5)
        assert r_429.status_code == 429 and r_429.headers["Retry-After"] == "1"
        assert requests.get(f"{mc_base}/findings", headers=eh, timeout=5).status_code == 200

    # 8. MockSentinelOneServer
    with MockSentinelOneServer() as s1:
        s1_base = f"{s1.base_url}/web/api/v2.1"
        r_unauth = requests.get(f"{s1_base}/system/info", timeout=5)
        assert r_unauth.status_code == 401 and r_unauth.json()["errors"][0]["code"] == 401001
        sh = {"Authorization": "ApiToken test-s1-token"}
        assert requests.get(f"{s1_base}/system/info", headers=sh, timeout=5).status_code == 200
        assert requests.get(f"{s1_base}/agents?limit=101", headers=sh, timeout=5).status_code == 400

        r_p1 = requests.get(f"{s1_base}/agents?limit=2", headers=sh, timeout=5).json()
        r_p2 = requests.get(f"{s1_base}/agents?limit=2&cursor={r_p1['pagination']['nextCursor']}", headers=sh, timeout=5).json()
        r_p3 = requests.get(f"{s1_base}/agents?limit=2&cursor={r_p2['pagination']['nextCursor']}", headers=sh, timeout=5).json()
        assert len(r_p1["data"]) + len(r_p2["data"]) + len(r_p3["data"]) == r_p1["pagination"]["totalItems"]
        assert r_p3["pagination"]["nextCursor"] is None

        assert requests.post(f"{s1_base}/threats/analyst-verdict", headers=sh, json={"filter": {}, "data": {"analystVerdict": "true_positive"}}, timeout=5).status_code == 400
        assert requests.post(f"{s1_base}/agents/actions/disconnect", headers=sh, json={"filter": {"ids": []}}, timeout=5).status_code == 400
        assert requests.post(f"{s1_base}/exclusions", headers=sh, json={"data": {"type": "path"}}, timeout=5).status_code == 400
        assert requests.delete(f"{s1_base}/exclusions", headers=sh, json={"data": {"ids": []}}, timeout=5).status_code == 400
        assert requests.post(f"{s1_base}/users/reset-2fa", headers=sh, json={"data": {"ids": []}}, timeout=5).status_code == 400

        assert isinstance(requests.get(f"{s1_base}/sites", headers=sh, timeout=5).json()["data"]["sites"], list)
        s1.set_sites_as_list(True)
        assert isinstance(requests.get(f"{s1_base}/sites", headers=sh, timeout=5).json()["data"], list)
        s1.set_sites_as_list(False)

        assert (
            requests.post(
                f"{s1_base}/sites",
                headers=sh,
                json={"data": {"name": "MDR-BAD", "accountId": "acc-100", "totalLicenses": "abc"}},
                timeout=5,
            ).status_code
            == 400
        )
        r_cs_zero = requests.post(
            f"{s1_base}/sites",
            headers=sh,
            json={"data": {"name": "MDR-9000-ZERO", "accountId": "acc-100", "totalLicenses": 0}},
            timeout=5,
        )
        assert r_cs_zero.status_code == 200 and r_cs_zero.json()["data"]["totalLicenses"] == 0
        assert requests.delete(f"{s1_base}/sites/{r_cs_zero.json()['data']['id']}", headers=sh, timeout=5).status_code == 200

        r_cs = requests.post(f"{s1_base}/sites", headers=sh, json={"data": {"name": "MDR-9001", "accountId": "acc-100"}}, timeout=5)
        new_sid = r_cs.json()["data"]["id"]
        assert requests.get(f"{s1_base}/sites/{new_sid}/policy", headers=sh, timeout=5).status_code == 200
        assert requests.put(f"{s1_base}/sites/{new_sid}/policy", headers=sh, json={"data": {"mitigationMode": "detect"}}, timeout=5).status_code == 200
        assert (
            requests.post(
                f"{s1_base}/sites/duplicate-site",
                headers=sh,
                json={"data": {"sourceSiteId": "100101", "name": "MDR-BAD-DUP", "totalLicenses": "abc"}},
                timeout=5,
            ).status_code
            == 400
        )
        dup_site = requests.post(
            f"{s1_base}/sites/duplicate-site",
            headers=sh,
            json={"data": {"sourceSiteId": "100101", "name": "MDR-9002", "policySource": "copy_source_site", "totalLicenses": 0}},
            timeout=5,
        )
        assert dup_site.status_code == 200 and dup_site.json()["data"]["totalLicenses"] == 0
        dup_sid = dup_site.json()["data"]["id"]
        assert requests.post(f"{s1_base}/sites/{new_sid}/expire-now", headers=sh, timeout=5).json()["data"]["state"] == "expired"
        assert requests.put(f"{s1_base}/sites/{new_sid}/reactivate", headers=sh, json={"data": {"unlimited": True}}, timeout=5).status_code == 200
        assert requests.put(f"{s1_base}/sites/{new_sid}/regenerate-key", headers=sh, timeout=5).status_code == 200
        assert requests.get(f"{s1_base}/sites/{new_sid}/token", headers=sh, timeout=5).status_code == 200
        assert requests.delete(f"{s1_base}/sites/{new_sid}", headers=sh, timeout=5).status_code == 200
        assert requests.delete(f"{s1_base}/sites/{dup_sid}", headers=sh, timeout=5).status_code == 200

        # Users & Service Users
        assert len(requests.get(f"{s1_base}/users?email=alice.mdr@example.test", headers=sh, timeout=5).json()["data"]) == 1
        assert len(requests.get(f"{s1_base}/users?fullName=Bob", headers=sh, timeout=5).json()["data"]) == 1
        assert len(requests.get(f"{s1_base}/users?roleIds=role-admin", headers=sh, timeout=5).json()["data"]) == 2
        assert len(requests.get(f"{s1_base}/users?twoFaEnabled=false", headers=sh, timeout=5).json()["data"]) == 1

        r_cu = requests.post(
            f"{s1_base}/users",
            headers=sh,
            json={"data": {"email": "temp.user@example.test", "fullName": "Temp User", "scope": "site", "scopeRoles": [{"id": "100101", "roleId": "role-soc"}]}},
            timeout=5,
        )
        assert r_cu.status_code == 200
        temp_uid = r_cu.json()["data"]["id"]
        assert requests.post(f"{s1_base}/users/reset-2fa", headers=sh, json={"data": {"ids": [temp_uid], "enroll": False}}, timeout=5).status_code == 200
        assert requests.post(f"{s1_base}/users/delete-users", headers=sh, json={"filter": {"ids": [temp_uid]}, "data": {}}, timeout=5).status_code == 200
        r_su = requests.post(
            f"{s1_base}/service-users",
            headers=sh,
            json={"data": {"name": "svc-temp", "scope": "site", "expirationDate": "2027-01-01T00:00:00Z"}},
            timeout=5,
        )
        su_id = r_su.json()["data"]["id"]
        assert requests.post(f"{s1_base}/service-users/{su_id}/generate-api-token", headers=sh, json={"data": {"expirationDate": "2027-01-01T00:00:00Z"}}, timeout=5).status_code == 200
        assert requests.delete(f"{s1_base}/service-users/{su_id}", headers=sh, timeout=5).status_code == 200

        ex_no_p = requests.get(f"{s1_base}/exclusions?siteIds=100102&includeParents=false", headers=sh, timeout=5).json()["data"]
        ex_with_p = requests.get(f"{s1_base}/exclusions?siteIds=100102&includeParents=true", headers=sh, timeout=5).json()["data"]
        assert not any(e["id"] == "excl-acct-1" for e in ex_no_p)
        assert any(e["id"] == "excl-acct-1" for e in ex_with_p)

        assert requests.post(f"{s1_base}/exclusions/validate", headers=sh, json={"data": {"exclusionType": "path", "osType": "linux", "value": "/opt/monitoring/agent"}}, timeout=5).json()["data"]["status"] == "Duplication"
        assert requests.post(f"{s1_base}/restrictions", headers=sh, json={"data": {"type": "black_hash", "value": "bad"}, "filter": {"siteIds": ["100101"]}}, timeout=5).status_code == 400
        assert requests.post(f"{s1_base}/restrictions", headers=sh, json={"data": {"type": "black_hash", "osType": "windows", "value": "f" * 40}, "filter": {"siteIds": ["100101"]}}, timeout=5).status_code == 200

        # Threats, Cloud Alerts, Agents, DV
        assert len(requests.get(f"{s1_base}/threats?resolved=true", headers=sh, timeout=5).json()["data"]) == 1
        assert len(requests.get(f"{s1_base}/threats?resolved=false", headers=sh, timeout=5).json()["data"]) == 5
        assert len(requests.get(f"{s1_base}/cloud-detection/alerts?severity=Critical", headers=sh, timeout=5).json()["data"]) == 1
        assert len(requests.get(f"{s1_base}/cloud-detection/alerts?incidentStatus=UNRESOLVED&query=Reverse_Shell", headers=sh, timeout=5).json()["data"]) == 1
        assert len(requests.get(f"{s1_base}/cloud-detection/alerts?analystVerdict=TRUE_POSITIVE", headers=sh, timeout=5).json()["data"]) == 0
        assert len(requests.get(f"{s1_base}/cloud-detection/alerts?scopes=site", headers=sh, timeout=5).json()["data"]) == 2
        assert requests.get(f"{s1_base}/threats/thr-1001-1/timeline", headers=sh, timeout=5).status_code == 200
        assert requests.post(f"{s1_base}/threats/analyst-verdict", headers=sh, json={"filter": {"ids": ["thr-1001-1"]}, "data": {"analystVerdict": "true_positive"}}, timeout=5).status_code == 200
        assert requests.post(f"{s1_base}/threats/mitigate/kill", headers=sh, json={"filter": {"ids": ["thr-1001-1"]}}, timeout=5).status_code == 200
        assert requests.post(f"{s1_base}/cloud-detection/alerts/analyst-verdict", headers=sh, json={"filter": {"ids": ["cld-1001-1"]}, "data": {"analystVerdict": "true_positive"}}, timeout=5).status_code == 200
        assert len(requests.get(f"{s1_base}/cloud-detection/alerts?analystVerdict=TRUE_POSITIVE", headers=sh, timeout=5).json()["data"]) == 1
        assert requests.post(f"{s1_base}/agents/actions/move-to-site", headers=sh, json={"filter": {"ids": ["ag-1001-2"]}, "data": {"targetSiteId": "100102"}}, timeout=5).status_code == 200
        dv_qid = requests.post(f"{s1_base}/dv/init-query", headers=sh, json={"query": "EventType = ProcessCreation", "fromDate": "2026-11-25T00:00:00Z", "toDate": "2026-11-25T03:00:00Z"}, timeout=5).json()["data"]["queryId"]
        assert requests.get(f"{s1_base}/dv/query-status?queryId={dv_qid}", headers=sh, timeout=5).json()["data"]["responseState"] == "FINISHED"
        assert len(requests.get(f"{s1_base}/dv/events?queryId={dv_qid}", headers=sh, timeout=5).json()["data"]) == 1

        s1.queue_fault("/web/api/v2.1/exclusions", 429, headers={"Retry-After": "1"}, method="POST")
        r_s1_429 = requests.post(f"{s1_base}/exclusions", headers=sh, json={"data": {"type": "path", "osType": "linux", "value": "/opt/new"}, "filter": {"siteIds": ["100101"]}}, timeout=5)
        assert r_s1_429.status_code == 429 and r_s1_429.headers["Retry-After"] == "1"
        assert requests.post(f"{s1_base}/exclusions", headers=sh, json={"data": {"type": "path", "osType": "linux", "value": "/opt/new"}, "filter": {"siteIds": ["100101"]}}, timeout=5).status_code == 200
        assert all(isinstance(entry["timestamp"], float) for entry in s1.requests_log)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SOCLens v2.1 local E2E mock servers.")
    parser.add_argument("--self-test", action="store_true", help="Run offline mock server self-tests.")
    args = parser.parse_args()
    if args.self_test:
        run_v21_mocks_self_test()
        print("v21_mocks self-test passed.")
