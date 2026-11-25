"""HashiCorp Vault KV v2 secret store provider implementation."""

from __future__ import annotations

import json
import math
import threading
import time
from collections import deque
from typing import Any, ClassVar
from urllib.parse import quote

import requests

from soclens.config import SecretStoreConfig
from soclens.secret_stores.base import (
    SecretCatalogEntry,
    SecretStoreAuthError,
    SecretStoreError,
    SecretStoreNotFoundError,
    SecretStoreProvider,
    _lookup_field_value,
    format_secret_ref,
    parse_secret_ref,
)

_SUPPORTED_AUTH_MODES: frozenset[str] = frozenset({"token", "approle"})
_MAX_DISCOVERY_DEPTH: int = 4
_MAX_DISCOVERY_ITEMS: int = 200
_REFRESH_LEEWAY_SECONDS: float = 60.0


def _encode_vault_path(path: str) -> str:
    """URL-encode each segment of a Vault mount or secret path."""
    return "/".join(quote(seg, safe="") for seg in path.strip("/").split("/") if seg)


def _safe_vault_error(response: requests.Response) -> str:
    """Extract a short, credential-free error message from a Vault response."""
    try:
        payload: Any = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        errors = payload.get("errors")
        if isinstance(errors, list):
            parts = [str(item).strip() for item in errors if str(item).strip()]
            if parts:
                return "; ".join(parts)[:200]
        for key in ("message", "error", "detail"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()[:200]
    text = (response.text or "").strip()
    if text:
        return text[:200]
    return f"HTTP {response.status_code}"


class HashiCorpVaultProvider(SecretStoreProvider):
    """HashiCorp Vault KV v2 provider supporting token and AppRole auth."""

    provider_name: ClassVar[str] = "hashicorp_vault"

    def __init__(
        self,
        config: SecretStoreConfig,
        *,
        stop_event: threading.Event | None = None,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(config, stop_event=stop_event, session=session)
        self._vault_addr: str = (config.vault_addr or "").strip().rstrip("/")
        if self._vault_addr and not self._vault_addr.lower().startswith(("http://", "https://")):
            raise SecretStoreError(
                "HashiCorp Vault address (vault_addr) must use http:// or https://.",
                provider=self.provider_name,
                reason="invalid_config",
            )

        auth_mode = (config.vault_auth_mode or "token").strip().lower()
        if auth_mode not in _SUPPORTED_AUTH_MODES:
            raise SecretStoreError(
                f"Unsupported HashiCorp Vault auth mode {config.vault_auth_mode!r}.",
                provider=self.provider_name,
                reason="invalid_config",
            )
        self._auth_mode: str = auth_mode

        self._kv_mount: str = (config.vault_kv_mount or "secret").strip().strip("/") or "secret"
        self._auth_mount: str = (config.vault_auth_mount or "approle").strip().strip("/") or "approle"
        self._namespace: str | None = (
            config.vault_namespace.strip()
            if config.vault_namespace and config.vault_namespace.strip()
            else None
        )
        self._prefix: str = (config.vault_prefix or "").strip().strip("/")
        self._auth_lock: threading.RLock = threading.RLock()
        self._token: str | None = (
            config.vault_token.strip()
            if (self._auth_mode == "token" and config.vault_token and config.vault_token.strip())
            else None
        )
        self._token_expires_at: float | None = None

    def _require_vault_addr(self) -> str:
        if not self._vault_addr:
            raise SecretStoreError(
                "HashiCorp Vault address (vault_addr) is not configured.",
                provider=self.provider_name,
                reason="missing_config",
            )
        return self._vault_addr

    def _base_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        return headers

    def _ensure_token(self) -> str:
        with self._auth_lock:
            self._check_cancelled()
            vault_addr = self._require_vault_addr()
            if self._auth_mode == "token":
                if not self._token:
                    raise SecretStoreAuthError(
                        "HashiCorp Vault token (vault_token) is not configured.",
                        provider=self.provider_name,
                        reason="missing_credentials",
                    )
                return self._token

            if self._token and (
                self._token_expires_at is None
                or time.monotonic() < (self._token_expires_at - _REFRESH_LEEWAY_SECONDS)
            ):
                return self._token

            role_id = (self.config.vault_role_id or "").strip()
            secret_id = self.config.vault_secret_id
            if not role_id or not secret_id:
                raise SecretStoreAuthError(
                    "HashiCorp Vault AppRole role_id and secret_id are required.",
                    provider=self.provider_name,
                    reason="missing_credentials",
                )

            login_url = f"{vault_addr}/v1/auth/{_encode_vault_path(self._auth_mount)}/login"
            headers = self._base_headers()
            headers["Content-Type"] = "application/json"
            resp = self._session_request(
                "POST",
                login_url,
                headers=headers,
                json_body={"role_id": role_id, "secret_id": secret_id},
            )
            if resp.status_code >= 400:
                raise SecretStoreAuthError(
                    f"Vault AppRole login failed: {_safe_vault_error(resp)}",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=login_url,
                    reason="auth_failed",
                )
            try:
                payload: Any = resp.json()
            except ValueError as exc:
                raise SecretStoreAuthError(
                    "Vault AppRole login returned invalid JSON.",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=login_url,
                    reason="auth_failed",
                ) from exc
            if not isinstance(payload, dict):
                raise SecretStoreAuthError(
                    "Vault AppRole login returned unexpected response format.",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=login_url,
                    reason="auth_failed",
                )
            auth = payload.get("auth")
            if not isinstance(auth, dict):
                raise SecretStoreAuthError(
                    "Vault AppRole login response missing 'auth' block.",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=login_url,
                    reason="auth_failed",
                )
            raw_token = auth.get("client_token")
            token = raw_token.strip() if isinstance(raw_token, str) else ""
            if not token:
                raise SecretStoreAuthError(
                    "Vault AppRole login response missing 'client_token'.",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=login_url,
                    reason="auth_failed",
                )

            self._token = token
            self._token_expires_at = None
            lease = auth.get("lease_duration")
            if isinstance(lease, (int, float)) and not isinstance(lease, bool):
                lease_sec = float(lease)
                if math.isfinite(lease_sec) and lease_sec > 0:
                    self._token_expires_at = time.monotonic() + lease_sec
            return token

    def _request_with_auth(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> requests.Response:
        token = self._ensure_token()
        headers = self._base_headers()
        headers["X-Vault-Token"] = token
        if json_body is not None:
            headers["Content-Type"] = "application/json"

        resp = self._session_request(
            method,
            url,
            headers=headers,
            params=params,
            json_body=json_body,
        )
        if resp.status_code == 401 and self._auth_mode == "approle":
            with self._auth_lock:
                if self._token and self._token != token:
                    new_token = self._token
                else:
                    if self._token == token:
                        self._token = None
                        self._token_expires_at = None
                    new_token = self._ensure_token()
            retry_headers = dict(headers)
            retry_headers["X-Vault-Token"] = new_token
            resp = self._session_request(
                method,
                url,
                headers=retry_headers,
                params=params,
                json_body=json_body,
            )
        return resp

    def _decode_json(self, resp: requests.Response, endpoint: str) -> Any:
        try:
            return resp.json()
        except ValueError as exc:
            raise SecretStoreError(
                "HashiCorp Vault returned invalid JSON.",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=endpoint,
                reason="invalid_response",
            ) from exc

    def _raise_for_status(self, resp: requests.Response, endpoint: str) -> None:
        if resp.status_code in (401, 403):
            raise SecretStoreAuthError(
                f"Vault authorization failed: {_safe_vault_error(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=endpoint,
                reason="unauthorized",
            )
        if resp.status_code == 404:
            raise SecretStoreNotFoundError(
                f"Vault secret or path not found: {_safe_vault_error(resp)}",
                provider=self.provider_name,
                status_code=404,
                endpoint=endpoint,
                reason="not_found",
            )
        if resp.status_code >= 400:
            raise SecretStoreError(
                f"Vault API error ({resp.status_code}): {_safe_vault_error(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=endpoint,
                reason="api_error",
            )

    def test_connection(self) -> dict[str, Any]:
        self._check_cancelled()
        vault_addr = self._require_vault_addr()
        lookup_url = f"{vault_addr}/v1/auth/token/lookup-self"
        resp = self._request_with_auth("GET", lookup_url)

        if resp.status_code == 200:
            payload = self._decode_json(resp, lookup_url)
            data = payload.get("data") if isinstance(payload, dict) else None
            info = data if isinstance(data, dict) else {}
            return {
                "ok": True,
                "provider": self.provider_name,
                "auth_mode": self._auth_mode,
                "vault_addr": vault_addr,
                "kv_mount": self._kv_mount,
                "namespace": self._namespace,
                "display_name": info.get("display_name"),
                "policies": info.get("policies"),
                "ttl": info.get("ttl"),
            }

        if resp.status_code in (401, 403):
            raise SecretStoreAuthError(
                f"Vault token lookup unauthorized: {_safe_vault_error(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=lookup_url,
                reason="unauthorized",
            )

        if resp.status_code in (404, 501):
            health_url = f"{vault_addr}/v1/sys/health"
            health_resp = self._session_request(
                "GET",
                health_url,
                headers=self._base_headers(),
            )
            try:
                health_payload: Any = health_resp.json()
            except ValueError:
                health_payload = None
            if health_resp.status_code == 503 or (
                isinstance(health_payload, dict) and health_payload.get("sealed") is True
            ):
                raise SecretStoreError(
                    "HashiCorp Vault is sealed.",
                    provider=self.provider_name,
                    status_code=health_resp.status_code,
                    endpoint=health_url,
                    reason="vault_sealed",
                )
            if health_resp.status_code in (200, 429, 472, 473):
                return {
                    "ok": True,
                    "provider": self.provider_name,
                    "auth_mode": self._auth_mode,
                    "vault_addr": vault_addr,
                    "kv_mount": self._kv_mount,
                    "namespace": self._namespace,
                    "health_status": health_resp.status_code,
                }
            raise SecretStoreError(
                f"Vault health check failed ({health_resp.status_code}): "
                f"{_safe_vault_error(health_resp)}",
                provider=self.provider_name,
                status_code=health_resp.status_code,
                endpoint=health_url,
                reason="vault_unhealthy",
            )

        self._raise_for_status(resp, lookup_url)
        return {"ok": True, "provider": self.provider_name}

    def list_secrets(
        self,
        query: str = "",
        *,
        limit: int = 100,
    ) -> list[SecretCatalogEntry]:
        self._check_cancelled()
        if limit <= 0:
            return []
        eff_limit = int(limit)
        vault_addr = self._require_vault_addr()
        self._ensure_token()

        encoded_mount = _encode_vault_path(self._kv_mount)
        queue: deque[tuple[str, int]] = deque([(self._prefix, 0)])
        visited: set[str] = set()
        discovered_paths: list[str] = []

        while queue and len(discovered_paths) < _MAX_DISCOVERY_ITEMS:
            self._check_cancelled()
            cur_path, depth = queue.popleft()
            if cur_path in visited:
                continue
            visited.add(cur_path)

            encoded_sub = _encode_vault_path(cur_path) if cur_path else ""
            meta_url = (
                f"{vault_addr}/v1/{encoded_mount}/metadata/{encoded_sub}"
                if encoded_sub
                else f"{vault_addr}/v1/{encoded_mount}/metadata"
            )
            resp = self._request_with_auth("LIST", meta_url)
            if resp.status_code == 405:
                resp = self._request_with_auth("GET", meta_url, params={"list": "true"})

            if resp.status_code == 404:
                continue
            if resp.status_code in (401, 403):
                raise SecretStoreAuthError(
                    f"Vault metadata list unauthorized: {_safe_vault_error(resp)}",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=meta_url,
                    reason="unauthorized",
                )
            if resp.status_code >= 400:
                raise SecretStoreError(
                    f"Vault metadata list failed ({resp.status_code}): {_safe_vault_error(resp)}",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=meta_url,
                    reason="api_error",
                )

            payload = self._decode_json(resp, meta_url)
            data = payload.get("data") if isinstance(payload, dict) else None
            raw_keys = data.get("keys") if isinstance(data, dict) else None
            if not isinstance(raw_keys, list):
                continue

            for raw_key in raw_keys:
                key_str = str(raw_key or "").strip()
                if not key_str:
                    continue
                if key_str.endswith("/"):
                    child = key_str.rstrip("/")
                    if child and depth < _MAX_DISCOVERY_DEPTH:
                        next_path = f"{cur_path}/{child}" if cur_path else child
                        if next_path not in visited:
                            queue.append((next_path, depth + 1))
                else:
                    secret_path = f"{cur_path}/{key_str}" if cur_path else key_str
                    discovered_paths.append(secret_path)
                    if len(discovered_paths) >= _MAX_DISCOVERY_ITEMS:
                        break

        query_cf = query.strip().casefold()
        entries: list[SecretCatalogEntry] = []
        for secret_path in discovered_paths:
            self._check_cancelled()
            if len(entries) >= eff_limit:
                break
            try:
                field_entries = self.list_secret_fields(secret_path)
            except (SecretStoreNotFoundError, SecretStoreAuthError):
                continue
            for entry in field_entries:
                if query_cf and not (
                    query_cf in entry.path.casefold()
                    or query_cf in entry.field_key.casefold()
                    or query_cf in entry.display_label.casefold()
                ):
                    continue
                entries.append(entry)
                if len(entries) >= eff_limit:
                    break

        return entries[:eff_limit]

    @staticmethod
    def _extract_secret_path(ref_or_id: str) -> str:
        cleaned = ref_or_id.strip()
        if cleaned.lower().startswith("hashicorp_vault:"):
            if cleaned.count(":") >= 2:
                _, item_id, _ = parse_secret_ref(cleaned)
                return item_id.strip("/")
            return cleaned.split(":", 1)[1].strip().strip("/")
        return cleaned.strip("/")

    def list_secret_fields(self, ref_or_id: str) -> list[SecretCatalogEntry]:
        self._check_cancelled()
        vault_addr = self._require_vault_addr()
        secret_path = self._extract_secret_path(ref_or_id)
        if not secret_path:
            raise SecretStoreError(
                f"Invalid HashiCorp Vault path or reference: {ref_or_id!r}.",
                provider=self.provider_name,
                reason="invalid_ref",
            )

        encoded_mount = _encode_vault_path(self._kv_mount)
        encoded_path = _encode_vault_path(secret_path)
        subkeys_url = f"{vault_addr}/v1/{encoded_mount}/subkeys/{encoded_path}"
        resp = self._request_with_auth("GET", subkeys_url)

        field_keys: list[str]
        if resp.status_code == 200:
            payload = self._decode_json(resp, subkeys_url)
            data = payload.get("data") if isinstance(payload, dict) else None
            subkeys = data.get("subkeys") if isinstance(data, dict) else None
            if not isinstance(subkeys, dict):
                raise SecretStoreNotFoundError(
                    f"Vault subkeys missing for path {secret_path!r}.",
                    provider=self.provider_name,
                    status_code=404,
                    endpoint=subkeys_url,
                    reason="not_found",
                )
            field_keys = [str(k).strip() for k in subkeys if str(k).strip()]
        elif resp.status_code in (403, 404):
            fields = self._fetch_item_fields(secret_path)
            field_keys = list(fields.keys()) if fields is not None else []
        else:
            self._raise_for_status(resp, subkeys_url)
            field_keys = []

        item_title = secret_path.rsplit("/", 1)[-1]
        entries: list[SecretCatalogEntry] = []
        seen_refs: set[str] = set()
        for key in field_keys:
            if not key or ":" in key:
                continue
            ref = format_secret_ref(self.provider_name, secret_path, key)
            if ref in seen_refs:
                continue
            seen_refs.add(ref)
            entries.append(
                SecretCatalogEntry(
                    ref=ref,
                    display_label=f"{secret_path} / {key} ({ref})",
                    provider=self.provider_name,
                    item_id=secret_path,
                    field_key=key,
                    item_title=item_title,
                    path=secret_path,
                    is_secret=True,
                )
            )
        return entries

    def _fetch_item_fields(self, item_id: str) -> dict[str, str] | None:
        self._check_cancelled()
        vault_addr = self._require_vault_addr()
        secret_path = item_id.strip().strip("/")
        if not secret_path:
            raise SecretStoreError(
                "HashiCorp Vault secret path must be non-empty.",
                provider=self.provider_name,
                reason="invalid_ref",
            )

        data_url = (
            f"{vault_addr}/v1/{_encode_vault_path(self._kv_mount)}"
            f"/data/{_encode_vault_path(secret_path)}"
        )
        resp = self._request_with_auth("GET", data_url)
        if resp.status_code >= 400:
            self._raise_for_status(resp, data_url)

        payload = self._decode_json(resp, data_url)
        outer = payload.get("data") if isinstance(payload, dict) else None
        inner = outer.get("data") if isinstance(outer, dict) else None
        if not isinstance(inner, dict):
            raise SecretStoreNotFoundError(
                f"Vault secret {secret_path!r} has no active version data.",
                provider=self.provider_name,
                status_code=404,
                endpoint=data_url,
                reason="secret_deleted",
            )

        fields: dict[str, str] = {}
        for raw_key, raw_val in inner.items():
            key = str(raw_key).strip()
            if not key or raw_val is None:
                continue
            fields[key] = (
                json.dumps(raw_val, ensure_ascii=False)
                if isinstance(raw_val, (dict, list))
                else str(raw_val)
            )
        return fields

    def get_secret_value(self, ref: str) -> str:
        self._check_cancelled()
        provider, secret_path, field_key = parse_secret_ref(ref)
        if provider != self.provider_name:
            raise SecretStoreError(
                f"Reference {ref!r} targets provider {provider!r}, "
                f"but active provider is {self.provider_name!r}.",
                provider=self.provider_name,
                reason="provider_mismatch",
            )

        fields = self._fetch_item_fields(secret_path)
        val = _lookup_field_value(fields, field_key) if fields is not None else None
        if val is None:
            raise SecretStoreNotFoundError(
                f"Field {field_key!r} not found in Vault secret {secret_path!r}.",
                provider=self.provider_name,
                status_code=404,
                reason="field_not_found",
            )
        return val


__all__ = ["HashiCorpVaultProvider"]
