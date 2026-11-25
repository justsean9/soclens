"""Microsoft Copilot (M365 Chat, Copilot Studio Direct Line, Security Copilot) transports.

All transports operate synchronously over ``requests.Session`` / ``ConfiguredSession``
with zero extra runtime dependencies so air-gapped ``wheelhouse/`` builds remain small
and reliable. Authentication is token-first (no Entra ID App Registration required):

- ``m365_copilot``: Microsoft Graph ``/beta/copilot/conversations`` (Bearer token or ``az_cli``).
- ``copilot_directline``: Copilot Studio Token Endpoint or Direct Line v3 secret.
- ``security_copilot``: Microsoft Graph ``/beta/security/securityCopilot/workspaces`` (Bearer token or ``az_cli``).
"""

from __future__ import annotations

import base64
import json
import logging
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import requests

from soclens.config import (
    DEFAULT_COPILOT_DIRECTLINE_URL,
    DEFAULT_M365_COPILOT_GRAPH_URL,
    LocalLLMConfig,
)

__all__ = [
    "CopilotDirectLineTransport",
    "CopilotTokenResolver",
    "M365CopilotTransport",
    "SecurityCopilotTransport",
    "extract_activity_text",
    "extract_m365_reply_text",
    "inspect_jwt_expiry",
]

logger = logging.getLogger("soclens.copilot")

_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
_USER_AGENT = "SOCLens/2.3"


def inspect_jwt_expiry(token: str) -> dict[str, Any]:
    """Decode a JWT payload (without signature verification) to inspect expiry and claims.

    Returns ``{"is_jwt": bool, "expired": bool, "expires_at": float | None, "upn": str | None}``.
    Never raises on opaque or non-JWT tokens.
    """
    raw = (token or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    parts = raw.split(".")
    if len(parts) != 3:
        return {"is_jwt": False, "expired": False, "expires_at": None, "upn": None}
    payload_b64 = parts[1]
    pad = "=" * (-len(payload_b64) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload_b64 + pad)
        claims = json.loads(decoded.decode("utf-8", errors="replace"))
    except Exception:
        return {"is_jwt": False, "expired": False, "expires_at": None, "upn": None}
    if not isinstance(claims, dict):
        return {"is_jwt": False, "expired": False, "expires_at": None, "upn": None}
    exp = claims.get("exp")
    expires_at: float | None = None
    expired = False
    if isinstance(exp, (int, float)):
        expires_at = float(exp)
        expired = time.time() >= (expires_at - 15.0)
    upn = claims.get("upn") or claims.get("preferred_username") or claims.get("unique_name")
    return {
        "is_jwt": True,
        "expired": expired,
        "expires_at": expires_at,
        "upn": str(upn) if upn else None,
    }


def _extract_http_error(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        text = (response.text or "").strip()
        return text[:400] if text else f"HTTP {response.status_code}"
    if isinstance(payload, dict):
        err = payload.get("error")
        if isinstance(err, dict):
            code = err.get("code")
            msg = err.get("message") or err.get("detail")
            if code and msg:
                return f"{code}: {msg}"
            if msg:
                return str(msg)
        elif isinstance(err, str) and err.strip():
            return err.strip()
        msg = payload.get("message") or payload.get("detail")
        if msg:
            return str(msg)
    return f"HTTP {response.status_code}"


def _graph_resource_from_url(graph_base_url: str) -> str:
    parsed = urlparse(graph_base_url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return "https://graph.microsoft.com"


def _extract_adaptive_card_text(card: Mapping[str, Any]) -> list[str]:
    """Recursively collect readable text from an Adaptive Card body."""
    lines: list[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, Mapping):
            text = node.get("text")
            if isinstance(text, str) and text.strip():
                lines.append(text.strip())
            title = node.get("title")
            if isinstance(title, str) and title.strip() and node.get("type") != "Action.OpenUrl":
                lines.append(title.strip())
            facts = node.get("facts")
            if isinstance(facts, list):
                for fact in facts:
                    if isinstance(fact, Mapping):
                        ft = str(fact.get("title") or "").strip()
                        fv = str(fact.get("value") or "").strip()
                        if ft and fv:
                            lines.append(f"- **{ft}**: {fv}")
                        elif fv:
                            lines.append(f"- {fv}")
            for key in ("body", "items", "columns"):
                children = node.get(key)
                if isinstance(children, list):
                    for child in children:
                        _walk(child)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(card)
    return lines


def extract_activity_text(activity: Mapping[str, Any]) -> str:
    """Render a Bot Framework / Copilot Studio activity (text + Adaptive Cards + citations)."""
    parts: list[str] = []
    text = activity.get("text")
    if isinstance(text, str) and text.strip():
        parts.append(text.strip())

    attachments = activity.get("attachments")
    if isinstance(attachments, list):
        for att in attachments:
            if not isinstance(att, Mapping):
                continue
            ctype = str(att.get("contentType") or "").lower()
            content = att.get("content")
            if ("adaptive" in ctype or (isinstance(content, Mapping) and str(content.get("type") or "").lower() == "adaptivecard")) and isinstance(content, Mapping):
                card_lines = _extract_adaptive_card_text(content)
                if card_lines:
                    parts.append("\n".join(card_lines))
            elif isinstance(content, Mapping):
                for key in ("title", "subtitle", "text"):
                    val = content.get(key)
                    if isinstance(val, str) and val.strip():
                        parts.append(val.strip())

    entities = activity.get("entities")
    citations: list[str] = []
    if isinstance(entities, list):
        for ent in entities:
            if not isinstance(ent, Mapping):
                continue
            url = ent.get("url") or ent.get("@id")
            name = ent.get("name") or ent.get("title")
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                label = str(name).strip() if name else url
                citations.append(f"- [{label}]({url})")
    if citations:
        parts.append("\nSources:\n" + "\n".join(dict.fromkeys(citations)))

    return "\n\n".join(p for p in parts if p).strip()


def extract_m365_reply_text(payload: Mapping[str, Any]) -> str:
    """Extract assistant response text and citations from an M365 Copilot Chat API response."""
    # Direct message response or conversation object with messages[]
    text_candidates: list[str] = []
    citations: list[str] = []

    def _collect_attributions(obj: Mapping[str, Any]) -> None:
        attrs = obj.get("attributions")
        if isinstance(attrs, list):
            for attr in attrs:
                if not isinstance(attr, Mapping):
                    continue
                url = attr.get("seeMoreWebUrl") or attr.get("url")
                title = (
                    (attr.get("providerDisplayName") or "")
                    if not attr.get("title")
                    else attr.get("title")
                )
                if isinstance(url, str) and url.startswith(("http://", "https://")):
                    label = str(title).strip() or url
                    citations.append(f"- [{label}]({url})")

    messages = payload.get("messages")
    if isinstance(messages, list) and messages:
        # Grab the latest non-user / response message
        for msg in reversed(messages):
            if not isinstance(msg, Mapping):
                continue
            odata_type = str(msg.get("@odata.type") or "").lower()
            author = str(msg.get("author") or msg.get("role") or "").lower()
            if "requestmessage" in odata_type or author == "user":
                continue
            msg_text = msg.get("text") or msg.get("content")
            if isinstance(msg_text, str) and msg_text.strip():
                text_candidates.append(msg_text.strip())
                _collect_attributions(msg)
                break
    else:
        for key in ("text", "content"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                text_candidates.append(val.strip())
                break
        if not text_candidates and isinstance(payload.get("message"), Mapping):
            inner = payload["message"]
            val = inner.get("text") or inner.get("content")
            if isinstance(val, str) and val.strip():
                text_candidates.append(val.strip())
            _collect_attributions(inner)
        _collect_attributions(payload)

    body = "\n\n".join(text_candidates).strip()
    if citations:
        deduped = "\n".join(dict.fromkeys(citations))
        body = f"{body}\n\nSources:\n{deduped}".strip()
    return body


class CopilotTokenResolver:
    """Resolves Microsoft Graph Bearer tokens without Entra ID App Registration.

    Supports:
    - ``token``: direct Bearer token from settings / env / PAM vault.
    - ``az_cli``: automatic token acquisition via ``az account get-access-token``.
    """

    def __init__(
        self,
        *,
        auth_mode: str = "token",
        bearer_token: str | None = None,
        resource: str = "https://graph.microsoft.com",
    ) -> None:
        self.auth_mode = (auth_mode or "token").strip().lower()
        self._static_token = self._clean_token(bearer_token)
        self.resource = resource.rstrip("/")
        self._cached_token: str | None = None
        self._cached_expires_at: float = 0.0
        self._lock = threading.Lock()

    @staticmethod
    def _clean_token(raw: str | None) -> str | None:
        if not raw:
            return None
        cleaned = raw.strip()
        if cleaned.lower().startswith("bearer "):
            cleaned = cleaned[7:].strip()
        return cleaned or None

    def get_token(self, *, error_cls: Callable[[str], Exception] = RuntimeError) -> str:
        """Return a valid Bearer token or raise ``error_cls`` with actionable guidance."""
        if self.auth_mode == "az_cli":
            return self._get_az_cli_token(error_cls=error_cls)

        if not self._static_token:
            raise error_cls(
                "No Microsoft Graph Bearer token configured. Paste a token in Settings "
                "(MS Copilot / Graph Bearer Token), set SOCLENS_MS_COPILOT_TOKEN, or switch "
                "MS Copilot Auth Mode to 'az_cli' (see docs/MICROSOFT_COPILOT_GUIDE.md)."
            )
        info = inspect_jwt_expiry(self._static_token)
        if info["expired"] and info["expires_at"] is not None:
            mins = max(1, int((time.time() - info["expires_at"]) // 60))
            raise error_cls(
                f"Microsoft Graph Bearer token expired ~{mins}m ago. Refresh it from Graph "
                "Explorer or `az account get-access-token --resource https://graph.microsoft.com`, "
                "or switch MS Copilot Auth Mode to 'az_cli' for automatic refresh."
            )
        return self._static_token

    def _get_az_cli_token(self, *, error_cls: Callable[[str], Exception] = RuntimeError) -> str:
        with self._lock:
            now = time.time()
            if self._cached_token and now < (self._cached_expires_at - 60.0):
                return self._cached_token

            cmd = [
                "az",
                "account",
                "get-access-token",
                "--resource",
                self.resource,
                "--output",
                "json",
            ]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
            except FileNotFoundError as exc:
                raise error_cls(
                    "Azure CLI ('az') was not found on PATH. Install Azure CLI and run "
                    "`az login`, or switch MS Copilot Auth Mode to 'token'."
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise error_cls("Timed out invoking `az account get-access-token`.") from exc

            if proc.returncode != 0:
                stderr = (proc.stderr or proc.stdout or "").strip()
                raise error_cls(
                    f"`az account get-access-token` failed (exit {proc.returncode}): "
                    f"{stderr[:300] or 'Run `az login` first.'}"
                )

            try:
                data = json.loads(proc.stdout)
            except ValueError as exc:
                raise error_cls(f"Invalid JSON from `az account get-access-token`: {exc}") from exc

            token = self._clean_token(data.get("accessToken") if isinstance(data, dict) else None)
            if not token:
                raise error_cls("`az account get-access-token` did not return an accessToken.")

            expires_at = now + 3000.0
            if isinstance(data, dict):
                if isinstance(data.get("expires_on"), (int, float)):
                    expires_at = float(data["expires_on"])
                else:
                    jwt_info = inspect_jwt_expiry(token)
                    if jwt_info["expires_at"] is not None:
                        expires_at = float(jwt_info["expires_at"])

            self._cached_token = token
            self._cached_expires_at = expires_at
            return token


class _BaseCopilotTransport:
    """Shared HTTP request, retry, and cancellation helpers for Copilot transports."""

    provider_name: str = "m365_copilot"

    def __init__(
        self,
        config: LocalLLMConfig,
        session: requests.Session,
        *,
        stop_event: threading.Event,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        error_factory: Callable[..., Exception],
        connection_error_factory: Callable[..., Exception],
    ) -> None:
        self.config = config
        self.session = session
        self._stop_event = stop_event
        self.max_retries = max(0, int(max_retries))
        self.backoff_base = max(0.0, float(backoff_base))
        self._make_error = error_factory
        self._make_conn_error = connection_error_factory
        self.conversation_id: str | None = None

    def reset_conversation(self) -> None:
        self.conversation_id = None

    def _check_cancelled(self, endpoint: str) -> None:
        if self._stop_event.is_set():
            raise self._make_error(
                f"{self.provider_name} request cancelled.",
                provider=self.provider_name,
                endpoint=endpoint,
            )

    def _wait_or_cancel(self, seconds: float, endpoint: str) -> None:
        if seconds <= 0:
            self._check_cancelled(endpoint)
            return
        if self._stop_event.wait(seconds):
            raise self._make_error(
                f"{self.provider_name} request cancelled.",
                provider=self.provider_name,
                endpoint=endpoint,
            )

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        json_payload: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        stream: bool = False,
        timeout: float | None = None,
    ) -> requests.Response:
        eff_timeout = self.config.timeout if timeout is None else timeout
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._check_cancelled(url)
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=json_payload,
                    params=params,
                    timeout=eff_timeout,
                    verify=self.config.verify_ssl,
                    stream=stream,
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    self._wait_or_cancel(self.backoff_base * (2**attempt), url)
                    continue
                raise self._make_conn_error(
                    f"Failed to connect to {self.provider_name} at {url}: {exc}",
                    provider=self.provider_name,
                    endpoint=url,
                ) from exc
            except requests.RequestException as exc:
                raise self._make_error(
                    f"{self.provider_name} HTTP error ({url}): {exc}",
                    provider=self.provider_name,
                    endpoint=url,
                ) from exc

            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                response.close()
                self._wait_or_cancel(self.backoff_base * (2**attempt), url)
                continue

            if response.status_code >= 400:
                detail = _extract_http_error(response)
                status = response.status_code
                response.close()
                hint = ""
                if status == 401:
                    hint = " (Token expired or invalid — refresh your Copilot token.)"
                elif status == 403:
                    hint = (
                        " (Access denied — check your M365 Copilot license / Graph consent "
                        "or Security Copilot RBAC role.)"
                    )
                raise self._make_error(
                    f"{self.provider_name} HTTP {status}: {detail}{hint}",
                    status_code=status,
                    provider=self.provider_name,
                    endpoint=url,
                )
            return response

        raise self._make_conn_error(
            f"Failed to connect to {self.provider_name} at {url}: {last_exc}",
            provider=self.provider_name,
            endpoint=url,
        )


class M365CopilotTransport(_BaseCopilotTransport):
    """Enterprise Microsoft 365 Copilot Chat API transport (Microsoft Graph Beta)."""

    provider_name = "m365_copilot"

    def __init__(
        self,
        config: LocalLLMConfig,
        session: requests.Session,
        *,
        stop_event: threading.Event,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        error_factory: Callable[..., Exception],
        connection_error_factory: Callable[..., Exception],
        token_resolver: CopilotTokenResolver | None = None,
    ) -> None:
        super().__init__(
            config,
            session,
            stop_event=stop_event,
            max_retries=max_retries,
            backoff_base=backoff_base,
            error_factory=error_factory,
            connection_error_factory=connection_error_factory,
        )
        base = (config.base_url or config.ms_graph_base_url or DEFAULT_M365_COPILOT_GRAPH_URL).rstrip("/")
        self.graph_base_url = base
        token = config.ms_bearer_token or config.api_key
        self.token_resolver = token_resolver or CopilotTokenResolver(
            auth_mode=config.ms_auth_mode,
            bearer_token=token,
            resource=_graph_resource_from_url(base),
        )

    def _headers(self, *, accept: str = "application/json") -> dict[str, str]:
        token = self.token_resolver.get_token(
            error_cls=lambda msg: self._make_error(
                msg, provider=self.provider_name, endpoint=self.graph_base_url
            )
        )
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": accept,
            "User-Agent": _USER_AGENT,
        }

    def check_connection(self) -> dict[str, Any]:
        """Validate Graph token and probe ``/me`` (gracefully handles minimal token scopes)."""
        try:
            headers = self._headers()
            url = f"{self.graph_base_url}/me"
            resp = self._request("GET", url, headers=headers, timeout=min(20.0, self.config.timeout))
            try:
                data = resp.json()
            except ValueError:
                data = {}
            finally:
                resp.close()
            upn = ""
            if isinstance(data, dict):
                upn = str(data.get("userPrincipalName") or data.get("displayName") or "")
            label = f"M365 Copilot ({upn})" if upn else "M365 Copilot Chat"
            return {
                "ok": True,
                "provider": self.provider_name,
                "base_url": self.graph_base_url,
                "models": [label],
                "error": None,
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider": self.provider_name,
                "base_url": self.graph_base_url,
                "models": [],
                "error": str(exc),
            }

    def start_conversation(self) -> str:
        url = f"{self.graph_base_url}/copilot/conversations"
        resp = self._request("POST", url, headers=self._headers(), json_payload={})
        try:
            data = resp.json()
        except ValueError as exc:
            raise self._make_error(
                f"Invalid JSON starting M365 Copilot conversation: {exc}",
                status_code=resp.status_code,
                provider=self.provider_name,
                endpoint=url,
            ) from exc
        finally:
            resp.close()
        conv_id = str(data.get("id") or "").strip() if isinstance(data, dict) else ""
        if not conv_id:
            raise self._make_error(
                "M365 Copilot API did not return a conversation id.",
                provider=self.provider_name,
                endpoint=url,
            )
        self.conversation_id = conv_id
        return conv_id

    def send_turn(
        self,
        text: str,
        *,
        conversation_id: str | None = None,
        stream_callback: Callable[[str], None] | None = None,
        model_label: str = "M365 Copilot Chat",
    ) -> dict[str, Any]:
        conv_id = (conversation_id or self.conversation_id or "").strip()
        if not conv_id:
            conv_id = self.start_conversation()
        else:
            self.conversation_id = conv_id

        tz_name = time.tzname[0] if time.tzname else "UTC"
        payload: dict[str, Any] = {
            "message": {"text": text},
            "locationHint": {"timeZone": tz_name},
            "contextualResources": {
                "webContext": {"isWebEnabled": bool(self.config.ms_web_grounding)}
            },
        }

        if stream_callback is not None:
            url = f"{self.graph_base_url}/copilot/conversations/{conv_id}/chatOverStream"
            resp = self._request(
                "POST",
                url,
                headers=self._headers(accept="text/event-stream"),
                json_payload=payload,
                stream=True,
            )
            try:
                return self._consume_sse(
                    resp,
                    conv_id=conv_id,
                    url=url,
                    stream_callback=stream_callback,
                    model_label=model_label,
                )
            finally:
                resp.close()

        url = f"{self.graph_base_url}/copilot/conversations/{conv_id}/chat"
        resp = self._request("POST", url, headers=self._headers(), json_payload=payload)
        try:
            data = resp.json()
        except ValueError as exc:
            raise self._make_error(
                f"Invalid JSON from M365 Copilot chat endpoint: {exc}",
                status_code=resp.status_code,
                provider=self.provider_name,
                endpoint=url,
            ) from exc
        finally:
            resp.close()

        content = extract_m365_reply_text(data) if isinstance(data, dict) else ""
        return {
            "content": content,
            "model": model_label,
            "provider": self.provider_name,
            "conversation_id": conv_id,
            "done": True,
            "raw": data,
        }

    def _consume_sse(
        self,
        response: requests.Response,
        *,
        conv_id: str,
        url: str,
        stream_callback: Callable[[str], None],
        model_label: str,
    ) -> dict[str, Any]:
        last_full_text = ""
        chunks: list[str] = []
        raw_events: list[dict[str, Any]] = []
        done = True

        for raw_line in response.iter_lines(decode_unicode=True):
            if self._stop_event.is_set():
                done = False
                break
            if raw_line is None:
                continue
            line = (
                raw_line.decode("utf-8", errors="replace")
                if isinstance(raw_line, bytes)
                else raw_line
            )
            stripped = line.strip()
            if not stripped or stripped.startswith(":") or stripped.startswith("event:"):
                continue
            data_str = stripped[5:].strip() if stripped.startswith("data:") else stripped
            if data_str == "[DONE]":
                break
            try:
                event = json.loads(data_str)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            raw_events.append(event)
            full = extract_m365_reply_text(event)
            if full:
                if full.startswith(last_full_text):
                    delta = full[len(last_full_text) :]
                    last_full_text = full
                else:
                    delta = full
                    last_full_text = last_full_text + delta
                if delta:
                    chunks.append(delta)
                    stream_callback(delta)

        final_content = last_full_text or "".join(chunks)
        return {
            "content": final_content,
            "model": model_label,
            "provider": self.provider_name,
            "conversation_id": conv_id,
            "done": done,
            "raw": raw_events,
        }


class CopilotDirectLineTransport(_BaseCopilotTransport):
    """Copilot Studio Direct Line v3 / Token Endpoint transport (zero Entra App Reg)."""

    provider_name = "copilot_directline"

    def __init__(
        self,
        config: LocalLLMConfig,
        session: requests.Session,
        *,
        stop_event: threading.Event,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        error_factory: Callable[..., Exception],
        connection_error_factory: Callable[..., Exception],
        poll_interval: float = 1.2,
    ) -> None:
        super().__init__(
            config,
            session,
            stop_event=stop_event,
            max_retries=max_retries,
            backoff_base=backoff_base,
            error_factory=error_factory,
            connection_error_factory=connection_error_factory,
        )
        self.directline_base_url = (
            config.ms_directline_url or DEFAULT_COPILOT_DIRECTLINE_URL
        ).rstrip("/")
        # Allow passing Token Endpoint directly via base_url if it looks like a powerplatform token endpoint
        base_override = (config.base_url or "").strip()
        self.token_endpoint = (config.ms_token_endpoint or "").strip()
        if (
            not self.token_endpoint
            and base_override
            and base_override.rstrip("/") != self.directline_base_url
            and ("powerplatform" in base_override.lower() or "directline/token" in base_override.lower())
        ):
            self.token_endpoint = base_override
        self.directline_secret = (config.ms_directline_secret or config.api_key or "").strip()
        self.poll_interval = max(0.1, float(poll_interval))
        self._dl_token: str | None = None
        self._watermark: str | None = None
        self._user_id = "soclens-analyst"

    def reset_conversation(self) -> None:
        super().reset_conversation()
        self._watermark = None

    def _acquire_directline_token(self) -> str:
        if self._dl_token:
            return self._dl_token
        if self.token_endpoint:
            resp = self._request(
                "GET",
                self.token_endpoint,
                headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
            )
            try:
                data = resp.json()
            except ValueError as exc:
                raise self._make_error(
                    f"Invalid JSON from Copilot Studio Token Endpoint: {exc}",
                    provider=self.provider_name,
                    endpoint=self.token_endpoint,
                ) from exc
            finally:
                resp.close()
            tok = str(data.get("token") or "").strip() if isinstance(data, dict) else ""
            if not tok:
                raise self._make_error(
                    "Copilot Studio Token Endpoint did not return a 'token' field.",
                    provider=self.provider_name,
                    endpoint=self.token_endpoint,
                )
            self._dl_token = tok
            return tok

        if self.directline_secret:
            url = f"{self.directline_base_url}/tokens/generate"
            resp = self._request(
                "POST",
                url,
                headers={
                    "Authorization": f"Bearer {self.directline_secret}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": _USER_AGENT,
                },
            )
            try:
                data = resp.json()
            except ValueError as exc:
                raise self._make_error(
                    f"Invalid JSON from Direct Line tokens/generate: {exc}",
                    provider=self.provider_name,
                    endpoint=url,
                ) from exc
            finally:
                resp.close()
            tok = str(data.get("token") or "").strip() if isinstance(data, dict) else ""
            if not tok:
                raise self._make_error(
                    "Direct Line tokens/generate did not return a 'token' field.",
                    provider=self.provider_name,
                    endpoint=url,
                )
            self._dl_token = tok
            return tok

        raise self._make_error(
            "Copilot Studio Direct Line requires either a Token Endpoint URL "
            "(SOCLENS_MS_COPILOT_TOKEN_ENDPOINT) or a Direct Line Secret "
            "(SOCLENS_MS_COPILOT_DIRECTLINE_SECRET).",
            provider=self.provider_name,
            endpoint=self.directline_base_url,
        )

    def check_connection(self) -> dict[str, Any]:
        try:
            self._dl_token = None
            self._acquire_directline_token()
            return {
                "ok": True,
                "provider": self.provider_name,
                "base_url": self.token_endpoint or self.directline_base_url,
                "models": ["Copilot Studio Agent"],
                "error": None,
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider": self.provider_name,
                "base_url": self.token_endpoint or self.directline_base_url,
                "models": [],
                "error": str(exc),
            }

    def start_conversation(self) -> str:
        token = self._acquire_directline_token()
        url = f"{self.directline_base_url}/conversations"
        resp = self._request(
            "POST",
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": _USER_AGENT,
            },
        )
        try:
            data = resp.json()
        except ValueError as exc:
            raise self._make_error(
                f"Invalid JSON starting Direct Line conversation: {exc}",
                provider=self.provider_name,
                endpoint=url,
            ) from exc
        finally:
            resp.close()

        conv_id = str(data.get("conversationId") or "").strip() if isinstance(data, dict) else ""
        if not conv_id:
            raise self._make_error(
                "Direct Line did not return a conversationId.",
                provider=self.provider_name,
                endpoint=url,
            )
        if isinstance(data, dict) and data.get("token"):
            self._dl_token = str(data["token"]).strip()
        self.conversation_id = conv_id
        self._watermark = None

        # Drain any initial greeting so watermark advances past it
        try:
            init_resp = self._request(
                "GET",
                f"{self.directline_base_url}/conversations/{conv_id}/activities",
                headers={"Authorization": f"Bearer {self._dl_token}", "Accept": "application/json"},
                timeout=min(10.0, self.config.timeout),
            )
            try:
                init_data = init_resp.json()
                if isinstance(init_data, dict) and init_data.get("watermark"):
                    self._watermark = str(init_data["watermark"])
            except ValueError:
                pass
            finally:
                init_resp.close()
        except Exception:
            pass
        return conv_id

    def send_turn(
        self,
        text: str,
        *,
        conversation_id: str | None = None,
        stream_callback: Callable[[str], None] | None = None,
        model_label: str = "Copilot Studio Agent",
    ) -> dict[str, Any]:
        conv_id = (conversation_id or self.conversation_id or "").strip()
        if not conv_id:
            conv_id = self.start_conversation()
        else:
            self.conversation_id = conv_id
        token = self._acquire_directline_token()

        send_url = f"{self.directline_base_url}/conversations/{conv_id}/activities"
        send_resp = self._request(
            "POST",
            send_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": _USER_AGENT,
            },
            json_payload={
                "type": "message",
                "from": {"id": self._user_id, "name": "SOCLens Analyst"},
                "text": text,
            },
        )
        send_resp.close()

        deadline = time.monotonic() + max(5.0, float(self.config.timeout))
        replies: list[str] = []
        raw_activities: list[dict[str, Any]] = []

        while time.monotonic() < deadline:
            self._check_cancelled(send_url)
            params = {"watermark": self._watermark} if self._watermark else None
            poll_resp = self._request(
                "GET",
                send_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "User-Agent": _USER_AGENT,
                },
                params=params,
            )
            try:
                poll_data = poll_resp.json()
            except ValueError:
                poll_data = {}
            finally:
                poll_resp.close()

            if isinstance(poll_data, dict):
                if poll_data.get("watermark"):
                    self._watermark = str(poll_data["watermark"])
                activities = poll_data.get("activities")
                if isinstance(activities, list):
                    for act in activities:
                        if not isinstance(act, dict):
                            continue
                        sender = act.get("from")
                        sender_id = str(sender.get("id") or "") if isinstance(sender, dict) else ""
                        if sender_id == self._user_id:
                            continue
                        if str(act.get("type") or "").lower() != "message":
                            continue
                        rendered = extract_activity_text(act)
                        if rendered:
                            replies.append(rendered)
                            raw_activities.append(act)
                            if stream_callback is not None:
                                stream_callback(rendered)

            if replies:
                break
            self._wait_or_cancel(self.poll_interval, send_url)

        if not replies:
            raise self._make_conn_error(
                f"Timed out waiting for Copilot Studio Direct Line reply after {self.config.timeout:.0f}s.",
                provider=self.provider_name,
                endpoint=send_url,
            )

        return {
            "content": "\n\n".join(replies),
            "model": model_label,
            "provider": self.provider_name,
            "conversation_id": conv_id,
            "done": True,
            "raw": raw_activities,
        }


class SecurityCopilotTransport(_BaseCopilotTransport):
    """Microsoft Security Copilot Graph Beta transport (workspaces/sessions/prompts/evaluations)."""

    provider_name = "security_copilot"

    def __init__(
        self,
        config: LocalLLMConfig,
        session: requests.Session,
        *,
        stop_event: threading.Event,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        error_factory: Callable[..., Exception],
        connection_error_factory: Callable[..., Exception],
        token_resolver: CopilotTokenResolver | None = None,
    ) -> None:
        super().__init__(
            config,
            session,
            stop_event=stop_event,
            max_retries=max_retries,
            backoff_base=backoff_base,
            error_factory=error_factory,
            connection_error_factory=connection_error_factory,
        )
        base = (config.base_url or config.ms_graph_base_url or DEFAULT_M365_COPILOT_GRAPH_URL).rstrip("/")
        self.graph_base_url = base
        self.workspace_id = (config.ms_security_workspace or "default").strip() or "default"
        self.poll_interval = max(0.1, float(config.ms_security_poll_interval))
        token = config.ms_bearer_token or config.api_key
        self.token_resolver = token_resolver or CopilotTokenResolver(
            auth_mode=config.ms_auth_mode,
            bearer_token=token,
            resource=_graph_resource_from_url(base),
        )

    def _headers(self) -> dict[str, str]:
        token = self.token_resolver.get_token(
            error_cls=lambda msg: self._make_error(
                msg, provider=self.provider_name, endpoint=self.graph_base_url
            )
        )
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        }

    def _workspace_url(self) -> str:
        return f"{self.graph_base_url}/security/securityCopilot/workspaces/{self.workspace_id}"

    def check_connection(self) -> dict[str, Any]:
        """Probe the configured Security Copilot workspace."""
        url = self._workspace_url()
        try:
            resp = self._request("GET", url, headers=self._headers(), timeout=min(20.0, self.config.timeout))
            try:
                data = resp.json()
            except ValueError:
                data = {}
            finally:
                resp.close()
            ws_name = str(data.get("displayName") or self.workspace_id) if isinstance(data, dict) else self.workspace_id
            return {
                "ok": True,
                "provider": self.provider_name,
                "base_url": url,
                "models": [f"Security Copilot ({ws_name})"],
                "error": None,
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider": self.provider_name,
                "base_url": url,
                "models": [],
                "error": str(exc),
            }

    def create_session(self, display_name: str | None = None) -> str:
        url = f"{self._workspace_url()}/sessions"
        title = display_name or f"SOCLens Investigation {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}"
        resp = self._request(
            "POST",
            url,
            headers=self._headers(),
            json_payload={"displayName": title},
        )
        try:
            data = resp.json()
        except ValueError as exc:
            raise self._make_error(
                f"Invalid JSON creating Security Copilot session: {exc}",
                provider=self.provider_name,
                endpoint=url,
            ) from exc
        finally:
            resp.close()
        session_id = str(data.get("id") or "").strip() if isinstance(data, dict) else ""
        if not session_id:
            raise self._make_error(
                "Security Copilot API did not return a session id.",
                provider=self.provider_name,
                endpoint=url,
            )
        self.conversation_id = session_id
        return session_id

    def send_turn(
        self,
        text: str,
        *,
        conversation_id: str | None = None,
        stream_callback: Callable[[str], None] | None = None,
        model_label: str = "Security Copilot",
    ) -> dict[str, Any]:
        session_id = (conversation_id or self.conversation_id or "").strip()
        if not session_id:
            session_id = self.create_session()
        else:
            self.conversation_id = session_id

        # 1. Create prompt
        prompts_url = f"{self._workspace_url()}/sessions/{session_id}/prompts"
        p_resp = self._request(
            "POST",
            prompts_url,
            headers=self._headers(),
            json_payload={"content": text, "type": "prompt"},
        )
        try:
            p_data = p_resp.json()
        except ValueError as exc:
            raise self._make_error(
                f"Invalid JSON creating Security Copilot prompt: {exc}",
                provider=self.provider_name,
                endpoint=prompts_url,
            ) from exc
        finally:
            p_resp.close()

        prompt_id = str(p_data.get("id") or "").strip() if isinstance(p_data, dict) else ""
        if not prompt_id:
            raise self._make_error(
                "Security Copilot API did not return a prompt id.",
                provider=self.provider_name,
                endpoint=prompts_url,
            )

        # 2. Trigger evaluation
        evals_url = f"{prompts_url}/{prompt_id}/evaluations"
        e_resp = self._request("POST", evals_url, headers=self._headers(), json_payload={})
        try:
            e_data = e_resp.json()
        except ValueError as exc:
            raise self._make_error(
                f"Invalid JSON triggering Security Copilot evaluation: {exc}",
                provider=self.provider_name,
                endpoint=evals_url,
            ) from exc
        finally:
            e_resp.close()

        eval_id = str(e_data.get("id") or "").strip() if isinstance(e_data, dict) else ""
        if not eval_id:
            raise self._make_error(
                "Security Copilot API did not return an evaluation id.",
                provider=self.provider_name,
                endpoint=evals_url,
            )

        # 3. Poll evaluation until completed/failed/cancelled
        poll_url = f"{evals_url}/{eval_id}"
        deadline = time.monotonic() + max(10.0, float(self.config.timeout))
        last_data: dict[str, Any] = e_data if isinstance(e_data, dict) else {}

        while time.monotonic() < deadline:
            self._check_cancelled(poll_url)
            state = str(last_data.get("state") or "").strip().lower()
            if state in ("completed", "succeeded"):
                result_obj = last_data.get("result")
                content = ""
                if isinstance(result_obj, Mapping):
                    content = str(result_obj.get("content") or result_obj.get("text") or "").strip()
                elif isinstance(last_data.get("content"), str):
                    content = last_data["content"].strip()
                if content and stream_callback is not None:
                    stream_callback(content)
                return {
                    "content": content,
                    "model": model_label,
                    "provider": self.provider_name,
                    "conversation_id": session_id,
                    "done": True,
                    "raw": last_data,
                }
            if state in ("failed", "cancelled", "canceled"):
                err_detail = str(last_data.get("error") or last_data.get("state") or state)
                raise self._make_error(
                    f"Security Copilot evaluation {state}: {err_detail}",
                    provider=self.provider_name,
                    endpoint=poll_url,
                )

            self._wait_or_cancel(self.poll_interval, poll_url)
            g_resp = self._request("GET", poll_url, headers=self._headers())
            try:
                polled = g_resp.json()
                if isinstance(polled, dict):
                    last_data = polled
            except ValueError:
                pass
            finally:
                g_resp.close()

        raise self._make_conn_error(
            f"Timed out waiting for Security Copilot evaluation after {self.config.timeout:.0f}s.",
            provider=self.provider_name,
            endpoint=poll_url,
        )
