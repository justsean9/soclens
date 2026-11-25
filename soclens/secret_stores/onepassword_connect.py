"""1Password Connect Server secret store provider implementation."""

from __future__ import annotations

import json
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


def _safe_op_error(response: requests.Response) -> str:
    """Extract a short, credential-free error snippet from a Connect response."""
    try:
        payload: Any = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        for key in ("message", "detail", "error"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()[:200]
    text = (response.text or "").strip()
    if text:
        return text[:200]
    return f"HTTP {response.status_code}"


def _build_op_field_map(fields_raw: list[Any]) -> dict[str, str]:
    """Build ``{field_key: value}`` with case-insensitive ``label -> id -> purpose`` priority."""
    valid_fields: list[tuple[dict[str, Any], str]] = []
    for raw in fields_raw:
        if not isinstance(raw, dict):
            continue
        raw_val = raw.get("value")
        if raw_val is None:
            continue
        val_str = (
            json.dumps(raw_val, ensure_ascii=False)
            if isinstance(raw_val, (dict, list))
            else str(raw_val)
        )
        valid_fields.append((raw, val_str))

    resolved: dict[str, str] = {}
    casefold_to_key: dict[str, str] = {}

    def _put(key: str, val: str, *, overwrite: bool) -> None:
        cf = key.casefold()
        existing = casefold_to_key.get(cf)
        if existing is not None:
            if not overwrite:
                return
            resolved.pop(existing, None)
        resolved[key] = val
        casefold_to_key[cf] = key

    # Pass 1: purpose (lowest priority, first-seen wins)
    for fld, val_str in valid_fields:
        purpose = str(fld.get("purpose") or "").strip()
        if purpose:
            _put(purpose, val_str, overwrite=False)

    # Pass 2: id (overrides Pass 1 purpose; first-seen wins within id tier)
    seen_id_cf: set[str] = set()
    for fld, val_str in valid_fields:
        fld_id = str(fld.get("id") or "").strip()
        if not fld_id:
            continue
        cf = fld_id.casefold()
        if cf in seen_id_cf:
            continue
        seen_id_cf.add(cf)
        _put(fld_id, val_str, overwrite=True)

    # Pass 3: label (highest priority, overrides id & purpose; first-seen wins within label tier)
    seen_label_cf: set[str] = set()
    for fld, val_str in valid_fields:
        label = str(fld.get("label") or "").strip()
        if not label:
            continue
        cf = label.casefold()
        if cf in seen_label_cf:
            continue
        seen_label_cf.add(cf)
        _put(label, val_str, overwrite=True)

    return resolved


class OnePasswordConnectProvider(SecretStoreProvider):
    """1Password Connect Server REST provider."""

    provider_name: ClassVar[str] = "onepassword_connect"

    def __init__(
        self,
        config: SecretStoreConfig,
        *,
        stop_event: threading.Event | None = None,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(config, stop_event=stop_event, session=session)
        self._base_url: str = (config.op_connect_url or "").strip().rstrip("/")
        if self._base_url and not self._base_url.lower().startswith(("http://", "https://")):
            raise SecretStoreError(
                "1Password Connect URL (op_connect_url) must use http:// or https://.",
                provider=self.provider_name,
                reason="invalid_config",
            )
        self._vault_id: str | None = (
            config.op_vault_id.strip()
            if config.op_vault_id and config.op_vault_id.strip()
            else None
        )

    def _require_base_url(self) -> str:
        if not self._base_url:
            raise SecretStoreError(
                "1Password Connect URL (op_connect_url) is not configured.",
                provider=self.provider_name,
                reason="missing_config",
            )
        return self._base_url

    def _require_token(self) -> str:
        token = (self.config.op_connect_token or "").strip()
        if not token:
            raise SecretStoreAuthError(
                "1Password Connect Bearer token (op_connect_token) is not configured.",
                provider=self.provider_name,
                reason="missing_credentials",
            )
        return token

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._require_token()}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> Any:
        resp = self._session_request(
            method,
            url,
            headers=self._auth_headers(),
            params=params,
        )
        if resp.status_code in (401, 403):
            raise SecretStoreAuthError(
                f"1Password Connect authorization failed: {_safe_op_error(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=url,
                reason="auth_failed",
            )
        if resp.status_code == 404:
            raise SecretStoreNotFoundError(
                f"1Password Connect resource not found: {_safe_op_error(resp)}",
                provider=self.provider_name,
                status_code=404,
                endpoint=url,
                reason="not_found",
            )
        if resp.status_code >= 400:
            raise SecretStoreError(
                f"1Password Connect API error ({resp.status_code}): {_safe_op_error(resp)}",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=url,
                reason="api_error",
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise SecretStoreError(
                "1Password Connect returned invalid JSON.",
                provider=self.provider_name,
                status_code=resp.status_code,
                endpoint=url,
                reason="invalid_response",
            ) from exc

    def _split_vault_and_item(self, ref_or_id: str) -> tuple[str, str]:
        cleaned = ref_or_id.strip()
        if cleaned.lower().startswith("onepassword_connect:"):
            if cleaned.count(":") >= 2:
                _, item_part, _ = parse_secret_ref(cleaned)
            else:
                item_part = cleaned.split(":", 1)[1].strip()
        else:
            item_part = cleaned

        if "/" in item_part:
            vault_uuid, item_uuid = item_part.split("/", 1)
            vault_clean = vault_uuid.strip()
            item_clean = item_uuid.strip()
            if not vault_clean or not item_clean:
                raise SecretStoreError(
                    f"Invalid 1Password Connect item identifier: {ref_or_id!r}.",
                    provider=self.provider_name,
                    reason="invalid_ref",
                )
            return vault_clean, item_clean

        if self._vault_id and item_part:
            return self._vault_id, item_part

        raise SecretStoreError(
            f"1Password Connect item identifier {ref_or_id!r} must include '<vault_uuid>/<item_uuid>'.",
            provider=self.provider_name,
            reason="invalid_ref",
        )

    def _entries_from_item(
        self,
        item: dict[str, Any],
        vault_id: str,
        vault_name: str,
    ) -> list[SecretCatalogEntry]:
        item_uuid = str(item.get("id") or "").strip()
        if not item_uuid:
            return []
        item_title = str(item.get("title") or item_uuid).strip()
        raw_fields = item.get("fields")
        if not isinstance(raw_fields, list):
            return []

        entries: list[SecretCatalogEntry] = []
        seen_refs: set[str] = set()
        for fld in raw_fields:
            if not isinstance(fld, dict):
                continue
            label = str(fld.get("label") or "").strip()
            fld_id = str(fld.get("id") or "").strip()
            purpose = str(fld.get("purpose") or "").strip()

            field_key = ""
            for candidate in (label, fld_id, purpose):
                if candidate and ":" not in candidate:
                    field_key = candidate
                    break
            if not field_key:
                continue

            ref = format_secret_ref(
                self.provider_name,
                f"{vault_id}/{item_uuid}",
                field_key,
            )
            if ref in seen_refs:
                continue
            seen_refs.add(ref)

            fld_type = str(fld.get("type") or "").strip().upper()
            fld_purpose = purpose.upper()
            is_secret = fld_type == "CONCEALED" or fld_purpose == "PASSWORD"
            path_label = vault_name or vault_id
            entries.append(
                SecretCatalogEntry(
                    ref=ref,
                    display_label=f"{item_title} -> {label or field_key} ({path_label})",
                    provider=self.provider_name,
                    item_id=f"{vault_id}/{item_uuid}",
                    field_key=field_key,
                    item_title=item_title,
                    path=path_label,
                    is_secret=is_secret,
                )
            )
        return entries

    def test_connection(self) -> dict[str, Any]:
        self._check_cancelled()
        base_url = self._require_base_url()
        self._require_token()

        hb_url = f"{base_url}/heartbeat"
        hb_resp = self._session_request(
            "GET",
            hb_url,
            headers={"Accept": "application/json, text/plain"},
        )
        if hb_resp.status_code >= 400:
            raise SecretStoreError(
                f"1Password Connect heartbeat failed ({hb_resp.status_code}): "
                f"{_safe_op_error(hb_resp)}",
                provider=self.provider_name,
                status_code=hb_resp.status_code,
                endpoint=hb_url,
                reason="heartbeat_failed",
            )

        vaults_url = f"{base_url}/v1/vaults"
        raw_vaults = self._request_json("GET", vaults_url)
        if not isinstance(raw_vaults, list):
            raise SecretStoreError(
                "1Password Connect /v1/vaults returned unexpected response format.",
                provider=self.provider_name,
                endpoint=vaults_url,
                reason="invalid_response",
            )
        vaults = [v for v in raw_vaults if isinstance(v, dict)]
        vault_ids = [str(v["id"]).strip() for v in vaults if v.get("id")]

        if self._vault_id and self._vault_id not in vault_ids:
            vault_url = f"{base_url}/v1/vaults/{quote(self._vault_id, safe='')}"
            self._request_json("GET", vault_url)

        return {
            "ok": True,
            "provider": self.provider_name,
            "url": base_url,
            "heartbeat": (hb_resp.text or "").strip() or "OK",
            "vault_count": len(vaults),
            "vault_ids": vault_ids,
            "configured_vault_id": self._vault_id,
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
        base_url = self._require_base_url()
        self._require_token()

        vault_targets: list[tuple[str, str]] = []
        if self._vault_id:
            vault_targets.append((self._vault_id, self._vault_id))
        else:
            raw_vaults = self._request_json("GET", f"{base_url}/v1/vaults")
            if isinstance(raw_vaults, list):
                for vault in raw_vaults:
                    if not isinstance(vault, dict):
                        continue
                    vid = str(vault.get("id") or "").strip()
                    if not vid:
                        continue
                    vname = str(vault.get("name") or vid).strip()
                    vault_targets.append((vid, vname))

        query_cf = query.strip().casefold()
        entries: list[SecretCatalogEntry] = []

        for vault_id, vault_name in vault_targets:
            self._check_cancelled()
            if len(entries) >= eff_limit:
                break
            items_url = f"{base_url}/v1/vaults/{quote(vault_id, safe='')}/items"
            raw_items = self._request_json("GET", items_url)
            if not isinstance(raw_items, list):
                continue
            items = [it for it in raw_items if isinstance(it, dict)]

            for item in items:
                self._check_cancelled()
                if len(entries) >= eff_limit:
                    break
                item_uuid = str(item.get("id") or "").strip()
                if not item_uuid:
                    continue
                item_title = str(item.get("title") or item_uuid).strip()
                tags = item.get("tags")
                tags_text = (
                    " ".join(str(t) for t in tags if t is not None).casefold()
                    if isinstance(tags, list)
                    else ""
                )
                category = str(item.get("category") or "").strip().upper()

                if query_cf and len(items) > eff_limit:
                    summary_haystack = " ".join(
                        [item_title, item_uuid, category, vault_name, tags_text]
                    ).casefold()
                    if query_cf not in summary_haystack:
                        continue

                raw_fields = item.get("fields")
                if isinstance(raw_fields, list) and raw_fields:
                    item_entries = self._entries_from_item(item, vault_id, vault_name)
                else:
                    detail_url = (
                        f"{base_url}/v1/vaults/{quote(vault_id, safe='')}"
                        f"/items/{quote(item_uuid, safe='')}"
                    )
                    try:
                        detail = self._request_json("GET", detail_url)
                        item_entries = (
                            self._entries_from_item(detail, vault_id, vault_name)
                            if isinstance(detail, dict)
                            else []
                        )
                    except SecretStoreNotFoundError:
                        inferred_field = (
                            "credential"
                            if category == "API_CREDENTIAL"
                            else ("notesPlain" if category == "SECURE_NOTE" else "password")
                        )
                        ref = format_secret_ref(
                            self.provider_name,
                            f"{vault_id}/{item_uuid}",
                            inferred_field,
                        )
                        item_entries = [
                            SecretCatalogEntry(
                                ref=ref,
                                display_label=f"{item_title} -> {inferred_field} ({vault_name})",
                                provider=self.provider_name,
                                item_id=f"{vault_id}/{item_uuid}",
                                field_key=inferred_field,
                                item_title=item_title,
                                path=vault_name,
                                is_secret=True,
                            )
                        ]

                for entry in item_entries:
                    if query_cf:
                        haystack = " ".join(
                            [
                                entry.item_title,
                                entry.field_key,
                                entry.display_label,
                                entry.ref,
                                entry.path,
                                tags_text,
                            ]
                        ).casefold()
                        if query_cf not in haystack:
                            continue
                    entries.append(entry)
                    if len(entries) >= eff_limit:
                        break

        return entries[:eff_limit]

    def list_secret_fields(self, ref_or_id: str) -> list[SecretCatalogEntry]:
        self._check_cancelled()
        base_url = self._require_base_url()
        vault_uuid, item_uuid = self._split_vault_and_item(ref_or_id)
        item_url = (
            f"{base_url}/v1/vaults/{quote(vault_uuid, safe='')}"
            f"/items/{quote(item_uuid, safe='')}"
        )
        payload = self._request_json("GET", item_url)
        if not isinstance(payload, dict):
            raise SecretStoreError(
                "1Password Connect item response must be a JSON object.",
                provider=self.provider_name,
                endpoint=item_url,
                reason="invalid_response",
            )
        vault_obj = payload.get("vault")
        vault_name = (
            str(vault_obj.get("name") or vault_uuid).strip()
            if isinstance(vault_obj, dict)
            else vault_uuid
        )
        return self._entries_from_item(payload, vault_uuid, vault_name)

    def _fetch_item_fields(self, item_id: str) -> dict[str, str] | None:
        self._check_cancelled()
        base_url = self._require_base_url()
        vault_uuid, item_uuid = self._split_vault_and_item(item_id)
        item_url = (
            f"{base_url}/v1/vaults/{quote(vault_uuid, safe='')}"
            f"/items/{quote(item_uuid, safe='')}"
        )
        payload = self._request_json("GET", item_url)
        if not isinstance(payload, dict):
            raise SecretStoreError(
                "1Password Connect item response must be a JSON object.",
                provider=self.provider_name,
                endpoint=item_url,
                reason="invalid_response",
            )
        raw_fields = payload.get("fields")
        return _build_op_field_map(raw_fields if isinstance(raw_fields, list) else [])

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
        if val is None:
            raise SecretStoreNotFoundError(
                f"Field {field_key!r} not found in 1Password item {item_id!r}.",
                provider=self.provider_name,
                status_code=404,
                reason="field_not_found",
            )
        return val


__all__ = ["OnePasswordConnectProvider"]
