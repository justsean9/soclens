"""Akeyless Vault secret store provider supporting static, dynamic, and rotated secrets."""

from __future__ import annotations

import json
import threading
from collections import deque
from typing import Any, ClassVar

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

_SUPPORTED_AUTH_MODES: frozenset[str] = frozenset({"access_key", "token"})
_SUPPORTED_ITEM_TYPES: frozenset[str] = frozenset(
    {"STATIC_SECRET", "DYNAMIC_SECRET", "ROTATED_SECRET"}
)
_MAX_DISCOVERY_DEPTH: int = 4
_MAX_DISCOVERY_ITEMS: int = 200


def _normalize_akeyless_path(path: str, *, allow_root: bool = False) -> str:
    """Normalize an Akeyless item or folder path with a single leading slash."""
    cleaned = path.strip().strip("/")
    if not cleaned:
        return "/" if allow_root else ""
    return f"/{cleaned}"


def _normalize_item_type(raw_type: Any) -> str:
    """Normalize Akeyless item_type strings (e.g. 'static-secret' -> 'STATIC_SECRET')."""
    return str(raw_type or "").strip().upper().replace("-", "_")


def _safe_akeyless_error(response: requests.Response) -> str:
    """Extract a short, credential-free error message from an Akeyless HTTP response."""
    try:
        payload: Any = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        for key in ("error", "message", "detail", "title"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()[:200]
    text = (response.text or "").strip()
    if text:
        return text[:200]
    return f"HTTP {response.status_code}"


def _flatten_secret_payload(raw_val: Any) -> dict[str, str]:
    """Convert an Akeyless secret payload (JSON object, JSON string, or scalar) into field map."""
    if raw_val is None:
        return {}
    if isinstance(raw_val, str):
        stripped = raw_val.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                parsed = json.loads(stripped)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                return _dict_to_fields(parsed)
        return {"value": raw_val}
    if isinstance(raw_val, dict):
        return _dict_to_fields(raw_val)
    if isinstance(raw_val, list):
        return {"value": json.dumps(raw_val, ensure_ascii=False)}
    return {"value": str(raw_val)}


def _dict_to_fields(data: dict[str, Any]) -> dict[str, str]:
    """Convert a JSON dict into ``{field_key: str_value}``, skipping empty keys or None values."""
    fields: dict[str, str] = {}
    for raw_key, raw_val in data.items():
        key = str(raw_key).strip()
        if not key or raw_val is None:
            continue
        fields[key] = (
            json.dumps(raw_val, ensure_ascii=False)
            if isinstance(raw_val, (dict, list))
            else str(raw_val)
        )
    return fields


class AkeylessProvider(SecretStoreProvider):
    """Akeyless Vault provider supporting static, dynamic, and rotated secrets."""

    provider_name: ClassVar[str] = "akeyless"

    def __init__(
        self,
        config: SecretStoreConfig,
        *,
        stop_event: threading.Event | None = None,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(config, stop_event=stop_event, session=session)
        api_url = (config.akeyless_api_url or "https://api.akeyless.io").strip().rstrip("/")
        if not api_url.lower().startswith(("http://", "https://")):
            raise SecretStoreError(
                "Akeyless API URL (akeyless_api_url) must use http:// or https://.",
                provider=self.provider_name,
                reason="invalid_config",
            )
        self._api_url: str = api_url

        auth_mode = (config.akeyless_auth_mode or "access_key").strip().lower()
        if auth_mode not in _SUPPORTED_AUTH_MODES:
            raise SecretStoreError(
                f"Unsupported Akeyless auth mode {config.akeyless_auth_mode!r}.",
                provider=self.provider_name,
                reason="invalid_config",
            )
        self._auth_mode: str = auth_mode

        self._prefix: str = _normalize_akeyless_path(config.akeyless_prefix or "", allow_root=True)
        self._auth_lock: threading.RLock = threading.RLock()
        self._token: str | None = (
            config.akeyless_token.strip()
            if (self._auth_mode == "token" and config.akeyless_token and config.akeyless_token.strip())
            else None
        )
        self._item_types: dict[str, str] = {}

    def _ensure_token(self) -> str:
        with self._auth_lock:
            self._check_cancelled()
            if self._auth_mode == "token":
                if not self._token:
                    raise SecretStoreAuthError(
                        "Akeyless token (akeyless_token) is not configured.",
                        provider=self.provider_name,
                        reason="missing_credentials",
                    )
                return self._token

            if self._token:
                return self._token

            access_id = (self.config.akeyless_access_id or "").strip()
            access_key = self.config.akeyless_access_key
            if not access_id or not access_key:
                raise SecretStoreAuthError(
                    "Akeyless access_id and access_key are required for access_key auth mode.",
                    provider=self.provider_name,
                    reason="missing_credentials",
                )

            auth_url = f"{self._api_url}/auth"
            resp = self._session_request(
                "POST",
                auth_url,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json_body={
                    "access-type": "access_key",
                    "access-id": access_id,
                    "access-key": access_key,
                },
            )
            if resp.status_code >= 400:
                raise SecretStoreAuthError(
                    f"Akeyless authentication failed: {_safe_akeyless_error(resp)}",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=auth_url,
                    reason="auth_failed",
                )
            payload = self._decode_json(resp, auth_url)
            if not isinstance(payload, dict):
                raise SecretStoreAuthError(
                    "Akeyless authentication returned unexpected response format.",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=auth_url,
                    reason="auth_failed",
                )
            raw_token = payload.get("token")
            token = raw_token.strip() if isinstance(raw_token, str) else ""
            if not token:
                raise SecretStoreAuthError(
                    "Akeyless authentication response missing 'token'.",
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=auth_url,
                    reason="auth_failed",
                )
            self._token = token
            return token

    def _decode_json(self, resp: requests.Response, endpoint: str) -> Any:
        try:
            return resp.json()
        except ValueError as exc:
            raise SecretStoreError(
                "Akeyless returned invalid JSON.",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=endpoint,
                reason="invalid_response",
            ) from exc

    def _raise_for_status(self, resp: requests.Response, endpoint: str) -> None:
        if resp.status_code in (401, 403):
            raise SecretStoreAuthError(
                f"Akeyless authorization failed: {_safe_akeyless_error(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=endpoint,
                reason="unauthorized",
            )
        if resp.status_code == 404:
            raise SecretStoreNotFoundError(
                f"Akeyless item or path not found: {_safe_akeyless_error(resp)}",
                provider=self.provider_name,
                status_code=404,
                endpoint=endpoint,
                reason="not_found",
            )
        if resp.status_code >= 400:
            raise SecretStoreError(
                f"Akeyless API error ({resp.status_code}): {_safe_akeyless_error(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=endpoint,
                reason="api_error",
            )

    def _post_with_auth(self, path: str, body: dict[str, Any]) -> Any:
        token = self._ensure_token()
        url = f"{self._api_url}/{path.lstrip('/')}"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        req_body = dict(body)
        req_body["token"] = token

        resp = self._session_request("POST", url, headers=headers, json_body=req_body)
        if resp.status_code == 401 and self._auth_mode == "access_key":
            with self._auth_lock:
                if self._token and self._token != token:
                    new_token = self._token
                else:
                    if self._token == token:
                        self._token = None
                    new_token = self._ensure_token()
            retry_body = dict(body)
            retry_body["token"] = new_token
            resp = self._session_request("POST", url, headers=headers, json_body=retry_body)

        if resp.status_code >= 400:
            self._raise_for_status(resp, url)
        return self._decode_json(resp, url)

    def test_connection(self) -> dict[str, Any]:
        self._check_cancelled()
        payload = self._post_with_auth("list-items", {"path": self._prefix})
        items = payload.get("items") if isinstance(payload, dict) else None
        count = len(items) if isinstance(items, list) else 0
        return {
            "ok": True,
            "provider": self.provider_name,
            "auth_mode": self._auth_mode,
            "api_url": self._api_url,
            "prefix": self._prefix,
            "item_count": count,
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

        queue: deque[tuple[str, int]] = deque([(self._prefix, 0)])
        visited_folders: set[str] = set()
        discovered_paths: list[str] = []

        while queue and len(discovered_paths) < _MAX_DISCOVERY_ITEMS:
            self._check_cancelled()
            cur_path, depth = queue.popleft()
            if cur_path in visited_folders:
                continue
            visited_folders.add(cur_path)

            next_page = ""
            while len(discovered_paths) < _MAX_DISCOVERY_ITEMS:
                req: dict[str, Any] = {"path": cur_path}
                if next_page:
                    req["pagination-token"] = next_page
                try:
                    payload = self._post_with_auth("list-items", req)
                except SecretStoreNotFoundError:
                    break

                if not isinstance(payload, dict):
                    break

                raw_folders = payload.get("folders")
                if isinstance(raw_folders, list) and depth < _MAX_DISCOVERY_DEPTH:
                    for raw_folder in raw_folders:
                        folder_path = _normalize_akeyless_path(str(raw_folder or ""))
                        if folder_path and folder_path not in visited_folders:
                            queue.append((folder_path, depth + 1))

                raw_items = payload.get("items")
                if isinstance(raw_items, list):
                    for item in raw_items:
                        if not isinstance(item, dict):
                            continue
                        item_name = _normalize_akeyless_path(str(item.get("item_name") or ""))
                        if not item_name:
                            continue
                        item_type = _normalize_item_type(item.get("item_type"))
                        if item_type == "FOLDER":
                            if depth < _MAX_DISCOVERY_DEPTH and item_name not in visited_folders:
                                queue.append((item_name, depth + 1))
                            continue
                        if item_type and item_type not in _SUPPORTED_ITEM_TYPES:
                            continue
                        if item_type:
                            self._item_types[item_name] = item_type
                        discovered_paths.append(item_name)
                        if len(discovered_paths) >= _MAX_DISCOVERY_ITEMS:
                            break

                raw_next = payload.get("next_page")
                next_page = raw_next.strip() if isinstance(raw_next, str) else ""
                if not next_page:
                    break

        query_cf = query.strip().casefold()
        entries: list[SecretCatalogEntry] = []
        for item_path in discovered_paths:
            self._check_cancelled()
            if len(entries) >= eff_limit:
                break
            try:
                field_entries = self.list_secret_fields(item_path)
            except (SecretStoreNotFoundError, SecretStoreAuthError, SecretStoreError):
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
    def _extract_item_path(ref_or_id: str) -> str:
        cleaned = ref_or_id.strip()
        if cleaned.lower().startswith("akeyless:"):
            if cleaned.count(":") >= 2:
                _, item_id, _ = parse_secret_ref(cleaned)
                return _normalize_akeyless_path(item_id)
            return _normalize_akeyless_path(cleaned.split(":", 1)[1])
        return _normalize_akeyless_path(cleaned)

    def _resolve_item_type(self, item_path: str) -> str:
        cached = self._item_types.get(item_path)
        if cached:
            return cached
        payload = self._post_with_auth("describe-item", {"name": item_path})
        if isinstance(payload, dict):
            item_type = _normalize_item_type(payload.get("item_type"))
            if item_type:
                self._item_types[item_path] = item_type
                return item_type
        return "STATIC_SECRET"

    def list_secret_fields(self, ref_or_id: str) -> list[SecretCatalogEntry]:
        self._check_cancelled()
        item_path = self._extract_item_path(ref_or_id)
        if not item_path:
            raise SecretStoreError(
                f"Invalid Akeyless item path or reference: {ref_or_id!r}.",
                provider=self.provider_name,
                reason="invalid_ref",
            )

        fields = self._fetch_item_fields(item_path)
        field_keys = list(fields.keys()) if fields is not None else []
        item_title = item_path.rsplit("/", 1)[-1]
        entries: list[SecretCatalogEntry] = []
        seen_refs: set[str] = set()
        for key in field_keys:
            if not key or ":" in key:
                continue
            ref = format_secret_ref(self.provider_name, item_path, key)
            if ref in seen_refs:
                continue
            seen_refs.add(ref)
            entries.append(
                SecretCatalogEntry(
                    ref=ref,
                    display_label=f"{item_path} / {key} ({ref})",
                    provider=self.provider_name,
                    item_id=item_path,
                    field_key=key,
                    item_title=item_title,
                    path=item_path,
                    is_secret=True,
                )
            )
        return entries

    def _fetch_item_fields(self, item_id: str) -> dict[str, str] | None:
        self._check_cancelled()
        item_path = _normalize_akeyless_path(item_id)
        if not item_path:
            raise SecretStoreError(
                "Akeyless item path must be non-empty.",
                provider=self.provider_name,
                reason="invalid_ref",
            )

        item_type = self._resolve_item_type(item_path)
        if item_type == "DYNAMIC_SECRET":
            payload = self._post_with_auth("get-dynamic-secret-value", {"name": item_path})
            return _flatten_secret_payload(payload)

        if item_type == "ROTATED_SECRET":
            payload = self._post_with_auth("get-rotated-secret-value", {"names": item_path})
            if isinstance(payload, dict) and "value" in payload and len(payload) == 1:
                return _flatten_secret_payload(payload["value"])
            return _flatten_secret_payload(payload)

        payload = self._post_with_auth("get-secret-value", {"names": [item_path]})
        if isinstance(payload, dict):
            if item_path in payload:
                return _flatten_secret_payload(payload[item_path])
            stripped_key = item_path.lstrip("/")
            if stripped_key in payload:
                return _flatten_secret_payload(payload[stripped_key])
            if len(payload) == 1:
                only_val = next(iter(payload.values()))
                return _flatten_secret_payload(only_val)
            raise SecretStoreNotFoundError(
                f"Akeyless secret {item_path!r} not returned in response.",
                provider=self.provider_name,
                status_code=404,
                reason="not_found",
            )
        return _flatten_secret_payload(payload)

    def get_secret_value(self, ref: str) -> str:
        self._check_cancelled()
        provider, item_id, field_key = parse_secret_ref(ref)
        if provider != self.provider_name:
            raise SecretStoreError(
                f"Reference {ref!r} targets provider {provider!r}, "
                f"but active provider is {self.provider_name!r}.",
                provider=self.provider_name,
                reason="provider_mismatch",
            )

        item_path = _normalize_akeyless_path(item_id)
        fields = self._fetch_item_fields(item_path)
        val = _lookup_field_value(fields, field_key) if fields is not None else None
        if val is None:
            raise SecretStoreNotFoundError(
                f"Field {field_key!r} not found in Akeyless item {item_path!r}.",
                provider=self.provider_name,
                status_code=404,
                reason="field_not_found",
            )
        return val


__all__ = ["AkeylessProvider"]
