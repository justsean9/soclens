"""Thycotic / Delinea Secret Server provider implementation."""

from __future__ import annotations

import json
import math
import threading
import time
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

_SUPPORTED_AUTH_MODES: frozenset[str] = frozenset({"password", "platform", "token"})
_SUPPORTED_API_VERSIONS: frozenset[str] = frozenset({"v1", "v2"})
_REFRESH_LEEWAY_SECONDS: float = 60.0


def _safe_error_snippet(response: requests.Response) -> str:
    """Extract a short, credential-free error snippet from an HTTP response."""
    try:
        payload: Any = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        for key in ("error_description", "message", "error", "detail", "title"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()[:200]
    text = (response.text or "").strip()
    if text:
        return text[:200]
    return f"HTTP {response.status_code}"


def _extract_vault_list(payload: Any) -> list[dict[str, Any]]:
    """Normalize vault discovery responses from Delinea Platform ``vaultbroker/api/vaults``."""
    raw_items: Any = None
    if isinstance(payload, list):
        raw_items = payload
    elif isinstance(payload, dict):
        for key in ("vaults", "items", "records", "data"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                raw_items = candidate
                break
    if not isinstance(raw_items, list):
        return []
    return [item for item in raw_items if isinstance(item, dict)]


def _extract_vault_url(vault: dict[str, Any]) -> str:
    """Extract a Secret Server URL from a Platform vault broker record."""
    conn = vault.get("connection")
    if isinstance(conn, dict):
        for key in ("url", "baseUrl", "base_url", "uri"):
            val = conn.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip().rstrip("/")
    for key in ("url", "baseUrl", "base_url", "uri"):
        val = vault.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip().rstrip("/")
    return ""


def _is_active_vault(vault: dict[str, Any]) -> bool:
    if vault.get("isActive") is False or vault.get("active") is False:
        return False
    status = vault.get("status")
    if isinstance(status, str) and status.strip().lower() in {"inactive", "disabled"}:
        return False
    return True


def _select_platform_vault_url(vaults: list[dict[str, Any]]) -> str:
    """Select the best active Secret Server URL from Platform vault broker records."""
    candidates: list[tuple[int, str]] = []
    for vault in vaults:
        if not _is_active_vault(vault):
            continue
        url = _extract_vault_url(vault)
        if not url:
            continue
        vtype = str(vault.get("type") or vault.get("vaultType") or "").strip().casefold()
        is_default = vault.get("isDefault") is True or vault.get("default") is True
        is_ss = vtype == "secretservercloud" or "secretserver" in vtype
        if is_ss and is_default:
            rank = 0
        elif is_ss:
            rank = 1
        elif is_default:
            rank = 2
        else:
            rank = 3
        candidates.append((rank, url))
    if not candidates:
        return ""
    candidates.sort(key=lambda pair: pair[0])
    return candidates[0][1]


class SecretServerProvider(SecretStoreProvider):
    """Thycotic / Delinea Secret Server secret store provider."""

    provider_name: ClassVar[str] = "secret_server"

    def __init__(
        self,
        config: SecretStoreConfig,
        *,
        stop_event: threading.Event | None = None,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(config, stop_event=stop_event, session=session)
        self._base_url: str = (config.tss_base_url or "").strip().rstrip("/")
        self._platform_url: str = (config.tss_platform_url or "").strip().rstrip("/")

        auth_mode = (config.tss_auth_mode or "password").strip().lower()
        if auth_mode not in _SUPPORTED_AUTH_MODES:
            raise SecretStoreError(
                f"Unsupported Secret Server auth mode {config.tss_auth_mode!r}.",
                provider=self.provider_name,
                reason="invalid_config",
            )
        self._auth_mode: str = auth_mode

        api_version = (config.tss_api_version or "v1").strip().lower()
        if api_version not in _SUPPORTED_API_VERSIONS:
            raise SecretStoreError(
                f"Unsupported Secret Server API version {config.tss_api_version!r}.",
                provider=self.provider_name,
                reason="invalid_config",
            )
        self._api_version: str = api_version

        if self._base_url and not self._base_url.lower().startswith(("http://", "https://")):
            raise SecretStoreError(
                "Secret Server base URL (tss_base_url) must use http:// or https://.",
                provider=self.provider_name,
                reason="invalid_config",
            )
        if self._platform_url and not self._platform_url.lower().startswith(
            ("http://", "https://")
        ):
            raise SecretStoreError(
                "Delinea Platform URL (tss_platform_url) must use http:// or https://.",
                provider=self.provider_name,
                reason="invalid_config",
            )

        self._folder_id: str | None = (
            config.tss_folder_id.strip()
            if config.tss_folder_id and config.tss_folder_id.strip()
            else None
        )
        self._auto_comment: str | None = (
            config.tss_auto_comment.strip()
            if config.tss_auto_comment and config.tss_auto_comment.strip()
            else None
        )
        self._auth_lock: threading.RLock = threading.RLock()
        self._access_token: str | None = (
            config.tss_access_token.strip()
            if (
                self._auth_mode == "token"
                and config.tss_access_token
                and config.tss_access_token.strip()
            )
            else None
        )
        self._refresh_token: str | None = None
        self._token_expires_at: float | None = None
        self._token_acquired_by_provider: bool = False

    def _require_base_url(self) -> str:
        if not self._base_url:
            raise SecretStoreError(
                "Secret Server base URL (tss_base_url) is not configured.",
                provider=self.provider_name,
                reason="missing_config",
            )
        return self._base_url

    def _is_token_valid_locked(self) -> bool:
        if not self._access_token:
            return False
        if self._token_expires_at is None:
            return True
        return time.monotonic() < (self._token_expires_at - _REFRESH_LEEWAY_SECONDS)

    def _store_token_payload_locked(self, payload: dict[str, Any], endpoint: str) -> str:
        raw_token = payload.get("access_token")
        token = raw_token.strip() if isinstance(raw_token, str) else ""
        if not token:
            raise SecretStoreAuthError(
                "Secret Server token response did not include an access_token.",
                provider=self.provider_name,
                endpoint=endpoint,
                reason="auth_failed",
            )
        self._access_token = token
        raw_refresh = payload.get("refresh_token")
        if isinstance(raw_refresh, str) and raw_refresh.strip():
            self._refresh_token = raw_refresh.strip()
        raw_exp = payload.get("expires_in")
        self._token_expires_at = None
        if isinstance(raw_exp, (int, float)) and not isinstance(raw_exp, bool):
            exp_val = float(raw_exp)
            if math.isfinite(exp_val) and exp_val > 0:
                self._token_expires_at = time.monotonic() + exp_val
        elif isinstance(raw_exp, str) and raw_exp.strip():
            try:
                exp_val = float(raw_exp.strip())
            except ValueError:
                exp_val = 0.0
            if math.isfinite(exp_val) and exp_val > 0:
                self._token_expires_at = time.monotonic() + exp_val
        self._token_acquired_by_provider = True
        return token

    def _discover_platform_vault_url_locked(self, token: str) -> str:
        if self._base_url:
            return self._base_url
        if not self._platform_url:
            raise SecretStoreError(
                "Delinea Platform URL (tss_platform_url) is not configured.",
                provider=self.provider_name,
                reason="missing_config",
            )
        vaults_url = f"{self._platform_url}/vaultbroker/api/vaults"
        resp = self._session_request(
            "GET",
            vaults_url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )
        if resp.status_code in (401, 403):
            raise SecretStoreAuthError(
                f"Delinea Platform vault discovery unauthorized: {_safe_error_snippet(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=vaults_url,
                reason="auth_failed",
            )
        if resp.status_code >= 400:
            raise SecretStoreError(
                f"Delinea Platform vault discovery failed: {_safe_error_snippet(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=vaults_url,
                reason="vault_discovery_failed",
            )
        try:
            payload: Any = resp.json()
        except ValueError as exc:
            raise SecretStoreError(
                "Delinea Platform vault discovery returned invalid JSON.",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=vaults_url,
                reason="vault_discovery_failed",
            ) from exc
        vaults = _extract_vault_list(payload)
        discovered = _select_platform_vault_url(vaults)
        if not discovered:
            raise SecretStoreError(
                "No active Secret Server vault URL returned by Delinea Platform.",
                provider=self.provider_name,
                endpoint=vaults_url,
                reason="vault_discovery_failed",
            )
        if not discovered.lower().startswith(("http://", "https://")):
            raise SecretStoreError(
                "Discovered Secret Server vault URL must use http:// or https://.",
                provider=self.provider_name,
                endpoint=vaults_url,
                reason="vault_discovery_failed",
            )
        self._base_url = discovered
        return discovered

    def _refresh_password_token_locked(self, token_url: str, refresh_token: str) -> str | None:
        resp = self._session_request(
            "POST",
            token_url,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )
        if resp.status_code < 200 or resp.status_code >= 300:
            return None
        try:
            payload: Any = resp.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None
        raw_tok = payload.get("access_token")
        if not isinstance(raw_tok, str) or not raw_tok.strip():
            return None
        return self._store_token_payload_locked(payload, token_url)

    def _ensure_access_token(self) -> str:
        with self._auth_lock:
            self._check_cancelled()
            if self._auth_mode == "token":
                self._require_base_url()
                if not self._access_token:
                    raise SecretStoreAuthError(
                        "Secret Server access token (tss_access_token) is not configured.",
                        provider=self.provider_name,
                        reason="missing_credentials",
                    )
                return self._access_token

            if self._auth_mode == "password":
                base_url = self._require_base_url()
                if self._is_token_valid_locked():
                    assert self._access_token is not None
                    return self._access_token

                username = (self.config.tss_username or "").strip()
                password = self.config.tss_password
                if not username or not password:
                    raise SecretStoreAuthError(
                        "Secret Server username and password are required for password auth mode.",
                        provider=self.provider_name,
                        reason="missing_credentials",
                    )

                token_url = f"{base_url}/oauth2/token"
                if self._refresh_token:
                    rt = self._refresh_token
                    self._refresh_token = None
                    refreshed = self._refresh_password_token_locked(token_url, rt)
                    if refreshed is not None:
                        return refreshed
                    self._access_token = None
                    self._token_expires_at = None

                form: dict[str, str] = {
                    "grant_type": "password",
                    "username": username,
                    "password": password,
                }
                if self.config.tss_domain and self.config.tss_domain.strip():
                    form["domain"] = self.config.tss_domain.strip()

                resp = self._session_request(
                    "POST",
                    token_url,
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    data=form,
                )
                if resp.status_code >= 400:
                    raise SecretStoreAuthError(
                        f"Secret Server authentication failed: {_safe_error_snippet(resp)}",
                        provider=self.provider_name,
                        status_code=resp.status_code,
                        endpoint=token_url,
                        reason="auth_failed",
                    )
                try:
                    payload: Any = resp.json()
                except ValueError as exc:
                    raise SecretStoreAuthError(
                        "Secret Server authentication returned invalid JSON.",
                        provider=self.provider_name,
                        status_code=resp.status_code,
                        endpoint=token_url,
                        reason="auth_failed",
                    ) from exc
                if not isinstance(payload, dict):
                    raise SecretStoreAuthError(
                        "Secret Server authentication returned unexpected response format.",
                        provider=self.provider_name,
                        status_code=resp.status_code,
                        endpoint=token_url,
                        reason="auth_failed",
                    )
                return self._store_token_payload_locked(payload, token_url)

            # Platform client_credentials mode
            if not self._platform_url:
                raise SecretStoreError(
                    "Delinea Platform URL (tss_platform_url) is not configured.",
                    provider=self.provider_name,
                    reason="missing_config",
                )
            if self._is_token_valid_locked():
                assert self._access_token is not None
                if not self._base_url:
                    self._discover_platform_vault_url_locked(self._access_token)
                return self._access_token

            client_id = (self.config.tss_client_id or "").strip()
            client_secret = self.config.tss_client_secret
            if not client_id or not client_secret:
                raise SecretStoreAuthError(
                    "Delinea Platform client_id and client_secret are required for platform auth.",
                    provider=self.provider_name,
                    reason="missing_credentials",
                )

            platform_token_url = f"{self._platform_url}/identity/api/oauth2/token/xpmplatform"
            resp = self._session_request(
                "POST",
                platform_token_url,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "xpmheadless",
                },
            )
            if resp.status_code >= 400:
                raise SecretStoreAuthError(
                    f"Delinea Platform authentication failed: {_safe_error_snippet(resp)}",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=platform_token_url,
                    reason="auth_failed",
                )
            try:
                plat_payload: Any = resp.json()
            except ValueError as exc:
                raise SecretStoreAuthError(
                    "Delinea Platform authentication returned invalid JSON.",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=platform_token_url,
                    reason="auth_failed",
                ) from exc
            if not isinstance(plat_payload, dict):
                raise SecretStoreAuthError(
                    "Delinea Platform authentication returned unexpected response format.",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=platform_token_url,
                    reason="auth_failed",
                )
            token = self._store_token_payload_locked(plat_payload, platform_token_url)
            if not self._base_url:
                self._discover_platform_vault_url_locked(token)
            return token

    def _request_with_auth(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> requests.Response:
        token = self._ensure_access_token()
        url = f"{self._require_base_url()}{path}"
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        if json_body is not None:
            headers["Content-Type"] = "application/json"

        resp = self._session_request(
            method,
            url,
            headers=headers,
            params=params,
            json_body=json_body,
        )
        if resp.status_code == 401:
            if self._auth_mode == "token":
                raise SecretStoreAuthError(
                    f"Secret Server bearer token rejected: {_safe_error_snippet(resp)}",
                    provider=self.provider_name,
                    status_code=401,
                    endpoint=url,
                    reason="unauthorized",
                )
            with self._auth_lock:
                if self._access_token and self._access_token != token:
                    new_token = self._access_token
                else:
                    if self._access_token == token:
                        self._access_token = None
                        self._token_expires_at = None
                    new_token = self._ensure_access_token()
            retry_headers = dict(headers)
            retry_headers["Authorization"] = f"Bearer {new_token}"
            url = f"{self._require_base_url()}{path}"
            resp = self._session_request(
                method,
                url,
                headers=retry_headers,
                params=params,
                json_body=json_body,
            )

        if resp.status_code in (401, 403):
            raise SecretStoreAuthError(
                f"Secret Server authorization failed: {_safe_error_snippet(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=url,
                reason="unauthorized",
            )
        if resp.status_code == 404:
            raise SecretStoreNotFoundError(
                f"Secret Server resource not found: {_safe_error_snippet(resp)}",
                provider=self.provider_name,
                status_code=404,
                endpoint=url,
                reason="not_found",
            )
        if resp.status_code >= 400:
            raise SecretStoreError(
                f"Secret Server API error ({resp.status_code}): {_safe_error_snippet(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=url,
                reason="api_error",
            )
        return resp

    def _decode_json(self, resp: requests.Response, endpoint: str) -> Any:
        try:
            return resp.json()
        except ValueError as exc:
            raise SecretStoreError(
                "Secret Server returned invalid JSON.",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=endpoint,
                reason="invalid_response",
            ) from exc

    @staticmethod
    def _extract_secret_records(payload: Any) -> list[dict[str, Any]]:
        raw: Any = None
        if isinstance(payload, list):
            raw = payload
        elif isinstance(payload, dict):
            for key in ("records", "items", "data"):
                cand = payload.get(key)
                if isinstance(cand, list):
                    raw = cand
                    break
        if not isinstance(raw, list):
            return []
        return [rec for rec in raw if isinstance(rec, dict)]

    def _entries_from_secret_dict(
        self,
        secret_obj: dict[str, Any],
        fallback_id: str = "",
    ) -> list[SecretCatalogEntry]:
        secret_id = str(secret_obj.get("id") or fallback_id).strip()
        if not secret_id:
            return []
        secret_name = str(secret_obj.get("name") or secret_id).strip()
        folder_path = str(
            secret_obj.get("folderPath") or secret_obj.get("folderId") or ""
        ).strip()
        raw_items = secret_obj.get("items")
        if not isinstance(raw_items, list):
            return []

        entries: list[SecretCatalogEntry] = []
        seen_refs: set[str] = set()
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            raw_slug = str(item.get("slug") or "").strip()
            raw_field_name = str(item.get("fieldName") or "").strip()
            slug = raw_slug if (raw_slug and ":" not in raw_slug) else ""
            if not slug and raw_field_name and ":" not in raw_field_name:
                slug = raw_field_name
            if not slug:
                continue
            field_label = raw_field_name or slug
            ref = format_secret_ref(self.provider_name, secret_id, slug)
            if ref in seen_refs:
                continue
            seen_refs.add(ref)
            is_secret = item.get("isPassword") is not False
            entries.append(
                SecretCatalogEntry(
                    ref=ref,
                    display_label=f"{secret_name} / {field_label} ({ref})",
                    provider=self.provider_name,
                    item_id=secret_id,
                    field_key=slug,
                    item_title=secret_name,
                    path=folder_path,
                    is_secret=is_secret,
                )
            )
        return entries

    def test_connection(self) -> dict[str, Any]:
        self._check_cancelled()
        resp = self._request_with_auth(
            "GET",
            f"/api/{self._api_version}/secrets",
            params={"take": "1"},
        )
        payload = self._decode_json(resp, f"/api/{self._api_version}/secrets")
        total: int | None = None
        if isinstance(payload, dict):
            raw_total = payload.get("total")
            if isinstance(raw_total, int) and not isinstance(raw_total, bool):
                total = raw_total
            else:
                total = len(self._extract_secret_records(payload))
        elif isinstance(payload, list):
            total = len(payload)
        return {
            "ok": True,
            "provider": self.provider_name,
            "auth_mode": self._auth_mode,
            "base_url": self._base_url,
            "api_version": self._api_version,
            "secret_count": total,
        }

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
        params: dict[str, str] = {
            "take": str(eff_limit),
            "filter.includeRestricted": "true",
        }
        cleaned_query = query.strip()
        if cleaned_query:
            params["filter.searchText"] = cleaned_query
        if self._folder_id:
            params["filter.folderId"] = self._folder_id

        path = f"/api/{self._api_version}/secrets"
        resp = self._request_with_auth("GET", path, params=params)
        payload = self._decode_json(resp, path)
        records = self._extract_secret_records(payload)

        entries: list[SecretCatalogEntry] = []
        for rec in records:
            self._check_cancelled()
            if len(entries) >= eff_limit:
                break
            sid = str(rec.get("id") or "").strip()
            if not sid:
                continue
            inline_items = rec.get("items")
            if isinstance(inline_items, list) and inline_items:
                rec_entries = self._entries_from_secret_dict(rec, fallback_id=sid)
            else:
                try:
                    rec_entries = self.list_secret_fields(sid)
                except (SecretStoreNotFoundError, SecretStoreAuthError):
                    continue
            for entry in rec_entries:
                entries.append(entry)
                if len(entries) >= eff_limit:
                    break

        return entries[:eff_limit]

    def list_secret_fields(self, ref_or_id: str) -> list[SecretCatalogEntry]:
        self._check_cancelled()
        cleaned = ref_or_id.strip()
        if cleaned.lower().startswith("secret_server:"):
            if cleaned.count(":") >= 2:
                _, secret_id, _ = parse_secret_ref(cleaned)
            else:
                secret_id = cleaned.split(":", 1)[1].strip()
        else:
            secret_id = cleaned
        if not secret_id:
            raise SecretStoreError(
                f"Invalid Secret Server reference or ID: {ref_or_id!r}.",
                provider=self.provider_name,
                reason="invalid_ref",
            )

        path = f"/api/{self._api_version}/secrets/{quote(secret_id, safe='')}"
        resp = self._request_with_auth("GET", path)
        payload = self._decode_json(resp, path)
        if not isinstance(payload, dict):
            raise SecretStoreError(
                "Secret Server secret detail response must be a JSON object.",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=path,
                reason="invalid_response",
            )
        return self._entries_from_secret_dict(payload, fallback_id=secret_id)

    def _fetch_item_fields(self, item_id: str) -> dict[str, str] | None:
        self._check_cancelled()
        secret_id = item_id.strip()
        if not secret_id:
            raise SecretStoreError(
                "Secret Server secret ID must be non-empty.",
                provider=self.provider_name,
                reason="invalid_ref",
            )
        path = f"/api/{self._api_version}/secrets/{quote(secret_id, safe='')}"
        params: dict[str, str] | None = (
            {"autoComment": self._auto_comment} if self._auto_comment else None
        )
        resp = self._request_with_auth("GET", path, params=params)
        payload = self._decode_json(resp, path)
        if not isinstance(payload, dict):
            raise SecretStoreError(
                "Secret Server secret detail response must be a JSON object.",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=path,
                reason="invalid_response",
            )
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            return {}

        fields: dict[str, str] = {}
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            raw_val = item.get("itemValue")
            if raw_val is None:
                continue
            val_str = (
                json.dumps(raw_val, ensure_ascii=False)
                if isinstance(raw_val, (dict, list))
                else str(raw_val)
            )
            slug = str(item.get("slug") or "").strip()
            field_name = str(item.get("fieldName") or "").strip()
            if slug:
                fields[slug] = val_str
            if field_name:
                fields.setdefault(field_name, val_str)
        return fields

    def get_secret_value(self, ref: str) -> str:
        self._check_cancelled()
        provider, secret_id, slug = parse_secret_ref(ref)
        if provider != self.provider_name:
            raise SecretStoreError(
                f"Reference {ref!r} targets provider {provider!r}, "
                f"but active provider is {self.provider_name!r}.",
                provider=self.provider_name,
                reason="provider_mismatch",
            )

        field_path = f"/api/v1/secrets/{quote(secret_id, safe='')}/fields/{quote(slug, safe='')}"
        params: dict[str, str] | None = (
            {"autoComment": self._auto_comment} if self._auto_comment else None
        )
        try:
            resp = self._request_with_auth("GET", field_path, params=params)
        except SecretStoreNotFoundError:
            resp = None
        except SecretStoreError as exc:
            if exc.status_code in (400, 405, 501):
                resp = None
            else:
                raise

        if resp is not None:
            parsed = self._extract_field_endpoint_value(resp)
            if parsed is not None:
                return parsed

        fields = self._fetch_item_fields(secret_id)
        if fields is not None:
            val = _lookup_field_value(fields, slug)
            if val is not None:
                return val

        raise SecretStoreNotFoundError(
            f"Field {slug!r} not found in Secret Server secret {secret_id!r}.",
            provider=self.provider_name,
            status_code=404,
            endpoint=field_path,
            reason="field_not_found",
        )

    @staticmethod
    def _extract_field_endpoint_value(resp: requests.Response) -> str | None:
        try:
            payload: Any = resp.json()
        except ValueError:
            raw_text = resp.text
            return raw_text if raw_text != "" else None

        if isinstance(payload, str):
            return payload
        if isinstance(payload, (int, float)) and not isinstance(payload, bool):
            return str(payload)
        if isinstance(payload, dict):
            for key in ("itemValue", "value"):
                val = payload.get(key)
                if val is not None:
                    return (
                        json.dumps(val, ensure_ascii=False)
                        if isinstance(val, (dict, list))
                        else str(val)
                    )
        return None

    def close(self) -> None:
        with self._auth_lock:
            token = self._access_token
            base_url = self._base_url
            should_revoke = (
                self._token_acquired_by_provider
                and bool(token)
                and bool(base_url)
                and not self.stop_event.is_set()
            )
            self._access_token = None
            self._refresh_token = None
            self._token_expires_at = None
            self._token_acquired_by_provider = False

        if should_revoke and token and base_url:
            try:
                self._session_request(
                    "POST",
                    f"{base_url}/api/v1/oauth-expiration",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {token}",
                    },
                )
            except Exception:
                pass
        super().close()


__all__ = ["SecretServerProvider"]
