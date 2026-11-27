"""Pure-ASGI security middleware, localhost auth handshake, and secret scrubbing."""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlparse

from starlette.types import ASGIApp, Receive, Scope, Send

from soclens.agent_audit import redact_sensitive_data
from soclens.settings import (
    DB_SECRET_MANAGED_SETTING_KEYS,
    SECRET_MANAGED_SETTING_KEYS,
    SETTING_SPECS_BY_KEY,
    is_vault_hydrated_setting,
)

SESSION_COOKIE_NAME = "soclens_session"
CSRF_HEADER_NAME = "x-soclens-token"
AUTH_EXCHANGE_PATH = "/api/auth/exchange"
STATE_CHANGING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
ALLOWED_SEC_FETCH_SITES: frozenset[str] = frozenset({"same-origin", "same-site", "none"})
ALLOWED_LOCAL_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})

_EXPLICIT_WEB_SECRET_KEYS: frozenset[str] = frozenset(
    {
        *SECRET_MANAGED_SETTING_KEYS,
        *DB_SECRET_MANAGED_SETTING_KEYS,
        "vault_secret_map",
    }
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|_)(?:secret|token|password|passphrase|api_key|dsn)(?:$|_)",
    re.IGNORECASE,
)
_URL_CREDENTIALS_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/@\s]+:[^/@\s]*@")
_VAULT_REF_RE = re.compile(r"vault://[^\s\"']+", re.IGNORECASE)
_HOST_IPV6_RE = re.compile(r"^\[::1\](?::(\d{1,5}))?$")
_HOST_NAME_RE = re.compile(r"^(127\.0\.0\.1|localhost)(?::(\d{1,5}))?$", re.IGNORECASE)


@dataclass(slots=True)
class WebSession:
    """In-memory authenticated localhost browser session."""

    session_id: str
    csrf_token: str
    created_at: float = field(default_factory=time.time)


class WebAuthManager:
    """Manages per-launch bootstrap token exchange and HttpOnly session cookies."""

    def __init__(self, bootstrap_token: str | None = None) -> None:
        cleaned = (bootstrap_token or "").strip()
        if cleaned:
            self._bootstrap_token = cleaned
        else:
            self._bootstrap_token = secrets.token_urlsafe(32)
        self._lock = threading.RLock()
        self._sessions: dict[str, WebSession] = {}

    @property
    def bootstrap_token(self) -> str:
        """Return the active per-launch bootstrap token."""
        return self._bootstrap_token

    def exchange_token(self, provided_token: str) -> WebSession | None:
        """Validate ``provided_token`` in constant time and mint a new session."""
        candidate = (provided_token or "").strip()
        if not candidate:
            return None
        if not secrets.compare_digest(candidate, self._bootstrap_token):
            return None
        session = WebSession(
            session_id=secrets.token_urlsafe(32),
            csrf_token=secrets.token_urlsafe(32),
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str | None) -> WebSession | None:
        """Look up an active session by cookie value using constant-time scan."""
        if not session_id:
            return None
        with self._lock:
            matched: WebSession | None = None
            for sid, sess in self._sessions.items():
                if secrets.compare_digest(session_id, sid):
                    matched = sess
            return matched

    def get_session_from_cookie_header(self, cookie_header: str | None) -> WebSession | None:
        """Extract and verify ``soclens_session`` from a raw ``Cookie`` header."""
        if not cookie_header:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            return None
        morsel = cookie.get(SESSION_COOKIE_NAME)
        if morsel is None:
            return None
        return self.get_session(morsel.value)

    def clear_sessions(self) -> None:
        """Invalidate all in-memory sessions."""
        with self._lock:
            self._sessions.clear()


def build_session_cookie_header(session_id: str) -> str:
    """Format a strict localhost ``Set-Cookie`` header."""
    return f"{SESSION_COOKIE_NAME}={session_id}; HttpOnly; SameSite=Strict; Path=/"


def parse_validated_local_host(
    raw_host: str | None,
    *,
    bound_port: int | None = None,
) -> tuple[bool, int, str]:
    """Validate an HTTP ``Host`` header against loopback-only targets.

    Returns ``(ok, status_code, reason)``.
    """
    if raw_host is None:
        return False, 400, "Missing Host header."
    host = raw_host.strip()
    if not host:
        return False, 400, "Empty Host header."
    if any(ch in host for ch in ("/", "\\", "@", " ", "\t", "\r", "\n", "?", "#")):
        return False, 403, "Malformed Host header."

    port_str: str | None = None
    ipv6_match = _HOST_IPV6_RE.match(host)
    if ipv6_match is not None:
        port_str = ipv6_match.group(1)
    else:
        name_match = _HOST_NAME_RE.match(host)
        if name_match is None:
            return False, 403, f"Rejected non-local Host header: {host!r}"
        port_str = name_match.group(2)

    if port_str is not None:
        try:
            port_num = int(port_str)
        except ValueError:
            return False, 400, "Invalid port in Host header."
        if port_num < 1 or port_num > 65535:
            return False, 400, "Out-of-range port in Host header."
        if bound_port is not None and port_num != bound_port:
            return False, 403, f"Host port {port_num} does not match bound port {bound_port}."
    elif bound_port is not None and bound_port != 80:
        return False, 403, f"Host header missing port; expected bound port {bound_port}."

    return True, 200, "ok"


def validate_origin_header(
    raw_origin: str | None,
    *,
    bound_port: int | None = None,
) -> tuple[bool, str]:
    """Validate an HTTP ``Origin`` header when present."""
    if raw_origin is None:
        return True, "ok"
    origin = raw_origin.strip()
    if not origin or origin.lower() == "null":
        return False, "Rejected null or empty Origin header."
    parsed = urlparse(origin)
    if parsed.scheme.lower() != "http":
        return False, f"Rejected non-http Origin scheme: {parsed.scheme!r}"
    if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        return False, "Rejected malformed Origin header."
    hostname = (parsed.hostname or "").lower()
    if hostname not in ALLOWED_LOCAL_HOSTS:
        return False, f"Rejected non-local Origin host: {hostname!r}"
    try:
        origin_port = parsed.port
    except ValueError:
        return False, "Invalid port in Origin header."
    if bound_port is not None:
        effective_origin_port = origin_port if origin_port is not None else 80
        if effective_origin_port != bound_port:
            return False, f"Origin port {effective_origin_port} does not match bound port {bound_port}."
    return True, "ok"


def validate_sec_fetch_site(raw_value: str | None) -> tuple[bool, str]:
    """Validate ``Sec-Fetch-Site`` when present."""
    if raw_value is None:
        return True, "ok"
    val = raw_value.strip().lower()
    if val in ALLOWED_SEC_FETCH_SITES:
        return True, "ok"
    return False, f"Rejected Sec-Fetch-Site: {val!r}"


def is_sensitive_setting_key(key: str) -> bool:
    """Return True if ``key`` must be completely masked/omitted in web responses."""
    clean = str(key or "").strip()
    if not clean:
        return False
    if clean in _EXPLICIT_WEB_SECRET_KEYS:
        return True
    spec = SETTING_SPECS_BY_KEY.get(clean)
    if spec is not None and (spec.secret or spec.mask_url_credentials):
        return True
    return bool(_SENSITIVE_KEY_RE.search(clean))


def _contains_sensitive_url_or_vault(value: str | None) -> bool:
    if not value:
        return False
    if _VAULT_REF_RE.search(value):
        return True
    if _URL_CREDENTIALS_RE.search(value):
        return True
    return False


def mask_web_setting_value(key: str, raw_value: str | None) -> str:
    """Return ``'********'`` when a sensitive setting is configured, else ``''``."""
    cleaned = str(raw_value).strip() if raw_value is not None else ""
    if not cleaned:
        return ""
    if is_sensitive_setting_key(key) or _contains_sensitive_url_or_vault(cleaned):
        return "********"
    return cleaned


def sanitize_settings_items_for_web(
    items: Iterable[Mapping[str, Any]],
    *,
    raw_lookup: Mapping[str, tuple[str | None, bool]] | None = None,
) -> list[dict[str, Any]]:
    """Sanitize ``describe_all_settings()`` entries so zero secrets or Vault refs leak."""
    sanitized: list[dict[str, Any]] = []
    for item in items:
        key = str(item.get("key") or "").strip()
        spec = SETTING_SPECS_BY_KEY.get(key)
        is_secret = bool(item.get("secret")) or is_sensitive_setting_key(key)
        has_saved = bool(item.get("has_saved"))

        raw_val: str | None = None
        if raw_lookup is not None and key in raw_lookup:
            raw_val, has_saved = raw_lookup[key]
        else:
            v = item.get("value")
            raw_val = str(v) if v is not None else None

        raw_saved = item.get("saved_value")
        saved_present = has_saved or bool(str(raw_saved or "").strip())

        if is_secret or _contains_sensitive_url_or_vault(raw_val) or _contains_sensitive_url_or_vault(
            str(raw_saved or "")
        ):
            configured = bool(str(raw_val or "").strip()) or saved_present
            display_val = "********" if str(raw_val or "").strip() else ""
            saved_display = "********" if saved_present else ""
        else:
            configured = bool(str(raw_val or "").strip())
            display_val = str(raw_val or "")
            saved_display = str(raw_saved or "")

        safe_default = item.get("default")
        if is_secret or _contains_sensitive_url_or_vault(str(safe_default or "")):
            safe_default = None

        sanitized.append(
            {
                "key": key,
                "category": str(item.get("category") or (spec.category if spec else "")),
                "label": str(item.get("label") or (spec.label if spec else key)),
                "env_vars": list(item.get("env_vars") or (spec.env_vars if spec else ())),
                "secret": is_secret,
                "value": display_val,
                "saved_value": saved_display,
                "has_saved": saved_present,
                "configured": configured,
                "vault_hydrated": is_vault_hydrated_setting(key),
                "env_override": item.get("env_override"),
                "source": str(item.get("source") or "unset"),
                "default": safe_default,
                "description": str(item.get("description") or ""),
            }
        )
    return sanitized


def redact_web_payload(value: Any) -> Any:
    """Recursively redact sensitive tokens/credentials/Vault refs from JSON payloads."""
    redacted = redact_sensitive_data(value)
    if isinstance(redacted, str):
        return _VAULT_REF_RE.sub("********", redacted)
    if isinstance(redacted, dict):
        return {k: redact_web_payload(v) for k, v in redacted.items()}
    if isinstance(redacted, list):
        return [redact_web_payload(v) for v in redacted]
    return redacted


async def _send_json_error(send: Send, status_code: int, message: str) -> None:
    payload = json.dumps({"ok": False, "error": message}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(payload)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload, "more_body": False})


class SecurityMiddleware:
    """Pure ASGI security middleware blocking DNS rebinding, cross-origin access, and CSRF.

    Implemented directly over ASGI rather than Starlette's ``BaseHTTPMiddleware`` so
    ``StreamingResponse`` SSE frames are never buffered or delayed.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        auth_manager: WebAuthManager,
        bound_port: int | None = None,
    ) -> None:
        self.app = app
        self.auth_manager = auth_manager
        self.bound_port = bound_port

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers_raw: list[tuple[bytes, bytes]] = list(scope.get("headers") or [])
        host_values = [v.decode("latin-1") for k, v in headers_raw if k.lower() == b"host"]
        if len(host_values) > 1:
            await _send_json_error(send, 400, "Multiple Host headers are not permitted.")
            return
        raw_host = host_values[0] if host_values else None
        host_ok, host_status, host_msg = parse_validated_local_host(
            raw_host,
            bound_port=self.bound_port,
        )
        if not host_ok:
            await _send_json_error(send, host_status, host_msg)
            return

        header_map: dict[bytes, str] = {}
        for k, v in headers_raw:
            lk = k.lower()
            if lk not in header_map:
                header_map[lk] = v.decode("latin-1")

        origin_ok, origin_msg = validate_origin_header(
            header_map.get(b"origin"),
            bound_port=self.bound_port,
        )
        if not origin_ok:
            await _send_json_error(send, 403, origin_msg)
            return

        sfs_ok, sfs_msg = validate_sec_fetch_site(header_map.get(b"sec-fetch-site"))
        if not sfs_ok:
            await _send_json_error(send, 403, sfs_msg)
            return

        path = str(scope.get("path") or "/")
        method = str(scope.get("method") or "GET").upper()

        if path.startswith("/api/"):
            if path == AUTH_EXCHANGE_PATH and method == "POST":
                await self.app(scope, receive, send)
                return

            session = self.auth_manager.get_session_from_cookie_header(header_map.get(b"cookie"))
            if session is None:
                await _send_json_error(send, 401, "Missing or invalid SOCLens session cookie.")
                return

            if method in STATE_CHANGING_METHODS:
                csrf_hdr = (header_map.get(CSRF_HEADER_NAME.encode("ascii")) or "").strip()
                if not csrf_hdr or not secrets.compare_digest(csrf_hdr, session.csrf_token):
                    await _send_json_error(send, 403, "Missing or invalid X-SOCLens-Token CSRF header.")
                    return

            state = scope.setdefault("state", {})
            if isinstance(state, dict):
                state["web_session"] = session

        await self.app(scope, receive, send)
