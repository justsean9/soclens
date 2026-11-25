"""Bitwarden (bw serve) local REST API secret store provider implementation."""

from __future__ import annotations

import threading
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

_AUTH_ERROR_PHRASES: tuple[str, ...] = (
    "locked",
    "unauthenticated",
    "unauthorized",
    "master password",
    "not logged in",
)


def _extract_bw_entries(item: dict[str, Any]) -> list[tuple[str, bool]]:
    """Return ``[(field_key, is_secret), ...]`` for catalog listing of a Bitwarden item."""
    entries: list[tuple[str, bool]] = []
    seen_cf: set[str] = set()

    def _add(key: str, is_secret: bool) -> None:
        cf = key.casefold()
        if not key or ":" in key or cf in seen_cf:
            return
        seen_cf.add(cf)
        entries.append((key, is_secret))

    login = item.get("login")
    if isinstance(login, dict):
        username = login.get("username")
        if isinstance(username, str) and username != "":
            _add("username", False)
        password = login.get("password")
        if isinstance(password, str) and password != "":
            _add("password", True)

    notes = item.get("notes")
    if isinstance(notes, str) and notes != "":
        _add("notes", True)

    raw_fields = item.get("fields")
    if isinstance(raw_fields, list):
        for fld in raw_fields:
            if not isinstance(fld, dict):
                continue
            fname = str(fld.get("name") or "").strip()
            fval = fld.get("value")
            if not fname or fval is None or str(fval) == "":
                continue
            fld_type = fld.get("type")
            is_secret = fld_type not in (0, 2)
            _add(fname, is_secret)

    return entries


def _extract_bw_field_map(item: dict[str, Any]) -> dict[str, str]:
    """Extract all item fields plus ``login.username`` / ``login.password`` aliases."""
    fields_map: dict[str, str] = {}

    login = item.get("login")
    if isinstance(login, dict):
        username = login.get("username")
        if username is not None:
            user_str = str(username)
            fields_map["username"] = user_str
            fields_map["login.username"] = user_str
        password = login.get("password")
        if password is not None:
            pass_str = str(password)
            fields_map["password"] = pass_str
            fields_map["login.password"] = pass_str

    notes = item.get("notes")
    if notes is not None:
        fields_map["notes"] = str(notes)

    raw_fields = item.get("fields")
    if isinstance(raw_fields, list):
        for fld in raw_fields:
            if not isinstance(fld, dict):
                continue
            fname = str(fld.get("name") or "").strip()
            fval = fld.get("value")
            if not fname or fval is None:
                continue
            fields_map.setdefault(fname, str(fval))

    return fields_map


def _item_matches_query(item: dict[str, Any], query_cf: str) -> bool:
    if not query_cf:
        return True
    parts: list[str] = [
        str(item.get("name") or ""),
        str(item.get("id") or ""),
        str(item.get("notes") or ""),
    ]
    login = item.get("login")
    if isinstance(login, dict):
        parts.append(str(login.get("username") or ""))
        uris = login.get("uris")
        if isinstance(uris, list):
            for uri_obj in uris:
                if isinstance(uri_obj, dict):
                    parts.append(str(uri_obj.get("uri") or ""))
    raw_fields = item.get("fields")
    if isinstance(raw_fields, list):
        for fld in raw_fields:
            if isinstance(fld, dict):
                parts.append(str(fld.get("name") or ""))
    return query_cf in " ".join(parts).casefold()


class BitwardenProvider(SecretStoreProvider):
    """Bitwarden ``bw serve`` local HTTP REST provider."""

    provider_name: ClassVar[str] = "bitwarden"

    def __init__(
        self,
        config: SecretStoreConfig,
        *,
        stop_event: threading.Event | None = None,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(config, stop_event=stop_event, session=session)
        self._base_url: str = (config.bw_serve_url or "").strip().rstrip("/")
        if self._base_url and not self._base_url.lower().startswith(("http://", "https://")):
            raise SecretStoreError(
                "Bitwarden bw serve URL (bw_serve_url) must use http:// or https://.",
                provider=self.provider_name,
                reason="invalid_config",
            )
        self._lock: threading.RLock = threading.RLock()
        self._unlocked: bool = False

    def _require_base_url(self) -> str:
        if not self._base_url:
            raise SecretStoreError(
                "Bitwarden bw serve URL (bw_serve_url) is not configured.",
                provider=self.provider_name,
                reason="missing_config",
            )
        return self._base_url

    def _request_bw(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        headers: dict[str, str] = {"Accept": "application/json"}
        if json_body is not None:
            headers["Content-Type"] = "application/json"

        resp = self._session_request(
            method,
            url,
            headers=headers,
            params=params,
            json_body=json_body,
        )
        if resp.status_code in (401, 403):
            with self._lock:
                self._unlocked = False
            raise SecretStoreAuthError(
                "Bitwarden bw serve request unauthorized.",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=url,
                reason="auth_failed",
            )
        if resp.status_code == 404:
            raise SecretStoreNotFoundError(
                "Bitwarden item or endpoint not found.",
                provider=self.provider_name,
                status_code=404,
                endpoint=url,
                reason="not_found",
            )

        try:
            payload: Any = resp.json()
        except ValueError as exc:
            raise SecretStoreError(
                f"Bitwarden bw serve returned invalid JSON (HTTP {resp.status_code}).",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=url,
                reason="invalid_response",
            ) from exc

        if not isinstance(payload, dict):
            raise SecretStoreError(
                "Bitwarden bw serve returned unexpected response format.",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=url,
                reason="invalid_response",
            )

        if payload.get("success") is False or resp.status_code >= 400:
            raw_msg = payload.get("message")
            msg = (
                raw_msg.strip()
                if isinstance(raw_msg, str) and raw_msg.strip()
                else (resp.text or "").strip()[:200] or f"Bitwarden API error (HTTP {resp.status_code})"
            )
            low = msg.casefold()
            if any(phrase in low for phrase in _AUTH_ERROR_PHRASES):
                with self._lock:
                    self._unlocked = False
                raise SecretStoreAuthError(
                    msg,
                    provider=self.provider_name,
                    status_code=resp.status_code,
                    endpoint=url,
                    reason="auth_failed",
                )
            if "not found" in low:
                raise SecretStoreNotFoundError(
                    msg,
                    provider=self.provider_name,
                    status_code=404,
                    endpoint=url,
                    reason="not_found",
                )
            raise SecretStoreError(
                msg,
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=url,
                reason="api_error",
            )

        return payload.get("data")

    def _check_status_and_unlock(self, *, force: bool = False) -> dict[str, Any]:
        with self._lock:
            self._check_cancelled()
            base_url = self._require_base_url()
            if not force and self._unlocked:
                return {"status": "unlocked", "unlocked_now": False}

            status_url = f"{base_url}/status"
            data = self._request_bw("GET", status_url)
            if not isinstance(data, dict):
                raise SecretStoreError(
                    "Bitwarden /status response missing 'data' object.",
                    provider=self.provider_name,
                    endpoint=status_url,
                    reason="invalid_response",
                )
            raw_tpl = data.get("template")
            template = raw_tpl if isinstance(raw_tpl, dict) else data
            status = str(template.get("status") or "").strip().lower()

            if status == "unlocked":
                self._unlocked = True
                return {
                    "status": "unlocked",
                    "unlocked_now": False,
                    "user_email": template.get("userEmail"),
                    "server_url": template.get("serverUrl"),
                    "last_sync": template.get("lastSync"),
                }

            if status == "unauthenticated":
                self._unlocked = False
                raise SecretStoreAuthError(
                    "Bitwarden CLI ('bw serve') is unauthenticated. Run 'bw login' before starting 'bw serve'.",
                    provider=self.provider_name,
                    status_code=401,
                    endpoint=status_url,
                    reason="unauthenticated",
                )

            if status == "locked":
                master_pw = self.config.bw_master_password
                if not master_pw or not master_pw.strip():
                    self._unlocked = False
                    raise SecretStoreAuthError(
                        "Bitwarden vault ('bw serve') is locked. Unlock it via 'bw unlock' "
                        "or provide bw_master_password.",
                        provider=self.provider_name,
                        status_code=401,
                        endpoint=status_url,
                        reason="vault_locked",
                    )

                unlock_url = f"{base_url}/unlock"
                try:
                    self._request_bw(
                        "POST",
                        unlock_url,
                        json_body={"password": master_pw},
                    )
                except SecretStoreError as exc:
                    self._unlocked = False
                    raise SecretStoreAuthError(
                        "Failed to unlock Bitwarden vault ('bw serve').",
                        provider=self.provider_name,
                        status_code=exc.status_code or 401,
                        endpoint=unlock_url,
                        reason="unlock_failed",
                    ) from exc

                self._unlocked = True
                return {
                    "status": "unlocked",
                    "unlocked_now": True,
                    "user_email": template.get("userEmail"),
                    "server_url": template.get("serverUrl"),
                    "last_sync": template.get("lastSync"),
                }

            raise SecretStoreError(
                f"Unexpected Bitwarden bw serve status: {status!r}.",
                provider=self.provider_name,
                endpoint=status_url,
                reason="unexpected_status",
            )

    def test_connection(self) -> dict[str, Any]:
        self._check_cancelled()
        base_url = self._require_base_url()
        info = self._check_status_and_unlock(force=True)
        return {
            "ok": True,
            "provider": self.provider_name,
            "url": base_url,
            **info,
        }

    def sync(self) -> dict[str, Any]:
        self._check_cancelled()
        base_url = self._require_base_url()
        self._check_status_and_unlock()
        data = self._request_bw("POST", f"{base_url}/sync")
        return {
            "ok": True,
            "provider": self.provider_name,
            "data": data,
        }

    def _entries_from_item(self, item: dict[str, Any]) -> list[SecretCatalogEntry]:
        item_uuid = str(item.get("id") or "").strip()
        if not item_uuid:
            return []
        item_name = str(item.get("name") or item_uuid).strip()
        folder_id = str(item.get("folderId") or "").strip()
        entries: list[SecretCatalogEntry] = []
        for field_key, is_secret in _extract_bw_entries(item):
            ref = format_secret_ref(self.provider_name, item_uuid, field_key)
            entries.append(
                SecretCatalogEntry(
                    ref=ref,
                    display_label=f"{item_name} -> {field_key}",
                    provider=self.provider_name,
                    item_id=item_uuid,
                    field_key=field_key,
                    item_title=item_name,
                    path=folder_id,
                    is_secret=is_secret,
                )
            )
        return entries

    def list_secrets(
        self,
        query: str = "",
        *,
        limit: int = 100,
        sync: bool = False,
    ) -> list[SecretCatalogEntry]:
        self._check_cancelled()
        if limit <= 0:
            return []
        eff_limit = int(limit)
        base_url = self._require_base_url()
        self._check_status_and_unlock()
        if sync:
            self.sync()

        params: dict[str, str] = {}
        cleaned_query = query.strip()
        if cleaned_query:
            params["search"] = cleaned_query
        if self.config.bw_folder_id and self.config.bw_folder_id.strip():
            params["folderid"] = self.config.bw_folder_id.strip()
        if self.config.bw_collection_id and self.config.bw_collection_id.strip():
            params["collectionid"] = self.config.bw_collection_id.strip()
        if self.config.bw_organization_id and self.config.bw_organization_id.strip():
            params["organizationid"] = self.config.bw_organization_id.strip()

        data = self._request_bw("GET", f"{base_url}/list/object/items", params=params or None)
        raw_items: Any
        if isinstance(data, dict):
            raw_items = data.get("data")
        elif isinstance(data, list):
            raw_items = data
        else:
            raw_items = []
        if not isinstance(raw_items, list):
            return []

        query_cf = cleaned_query.casefold()
        entries: list[SecretCatalogEntry] = []
        for item in raw_items:
            self._check_cancelled()
            if len(entries) >= eff_limit:
                break
            if not isinstance(item, dict):
                continue
            item_matches = _item_matches_query(item, query_cf)
            for entry in self._entries_from_item(item):
                if query_cf and not item_matches and query_cf not in entry.field_key.casefold():
                    continue
                entries.append(entry)
                if len(entries) >= eff_limit:
                    break

        return entries[:eff_limit]

    @staticmethod
    def _extract_item_id(ref_or_id: str) -> str:
        cleaned = ref_or_id.strip()
        if cleaned.lower().startswith("bitwarden:"):
            if cleaned.count(":") >= 2:
                _, item_id, _ = parse_secret_ref(cleaned)
                return item_id
            return cleaned.split(":", 1)[1].strip()
        return cleaned

    def list_secret_fields(self, ref_or_id: str) -> list[SecretCatalogEntry]:
        self._check_cancelled()
        base_url = self._require_base_url()
        item_id = self._extract_item_id(ref_or_id)
        if not item_id:
            raise SecretStoreError(
                f"Invalid Bitwarden item ID or reference: {ref_or_id!r}.",
                provider=self.provider_name,
                reason="invalid_ref",
            )
        self._check_status_and_unlock()
        data = self._request_bw("GET", f"{base_url}/object/item/{quote(item_id, safe='')}")
        if not isinstance(data, dict):
            raise SecretStoreError(
                "Bitwarden /object/item response missing item object.",
                provider=self.provider_name,
                reason="invalid_response",
            )
        return self._entries_from_item(data)

    def _fetch_item_fields(self, item_id: str) -> dict[str, str] | None:
        self._check_cancelled()
        base_url = self._require_base_url()
        cleaned_id = item_id.strip()
        if not cleaned_id:
            raise SecretStoreError(
                "Bitwarden item ID must be non-empty.",
                provider=self.provider_name,
                reason="invalid_ref",
            )
        self._check_status_and_unlock()
        data = self._request_bw("GET", f"{base_url}/object/item/{quote(cleaned_id, safe='')}")
        if not isinstance(data, dict):
            raise SecretStoreError(
                "Bitwarden /object/item response missing item object.",
                provider=self.provider_name,
                reason="invalid_response",
            )
        return _extract_bw_field_map(data)

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

        fields_map = self._fetch_item_fields(item_id)
        val = _lookup_field_value(fields_map, field_key) if fields_map is not None else None
        if val is None and field_key.casefold() in {"login.username", "login.password"}:
            alias = field_key.split(".", 1)[1]
            val = _lookup_field_value(fields_map, alias) if fields_map is not None else None
        if val is None:
            raise SecretStoreNotFoundError(
                f"Field {field_key!r} not found in Bitwarden item {item_id!r}.",
                provider=self.provider_name,
                status_code=404,
                reason="field_not_found",
            )
        return val


__all__ = ["BitwardenProvider"]
