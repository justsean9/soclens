"""Base interfaces, exceptions, catalog entries, and batch resolution for secret store providers."""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

import requests

from soclens.config import (
    ConfiguredSession,
    SecretStoreConfig,
    suppress_insecure_ssl_warnings,
)
from soclens.settings import SUPPORTED_SECRET_PROVIDERS

logger = logging.getLogger("soclens.secret_stores")

SECRET_PROVIDER_LABELS: dict[str, str] = {
    "none": "Disabled (Manual / Env Vars)",
    "secret_server": "Thycotic / Delinea Secret Server",
    "hashicorp_vault": "HashiCorp Vault (KV v2)",
    "onepassword_connect": "1Password Connect Server",
    "bitwarden": "Bitwarden (bw serve)",
    "akeyless": "Akeyless Vault",
}


class SecretStoreError(RuntimeError):
    """Base exception raised by SOCLens secret manager integrations."""

    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        status_code: int | None = None,
        endpoint: str | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message: str = message
        self.provider: str | None = provider
        self.status_code: int | None = status_code
        self.endpoint: str | None = endpoint
        self.reason: str | None = reason


class SecretStoreAuthError(SecretStoreError):
    """Raised on authentication, authorization, or locked-vault errors."""


class SecretStoreNotFoundError(SecretStoreError):
    """Raised when a requested secret, item, path, or field does not exist."""


@dataclass(frozen=True)
class SecretCatalogEntry:
    """Normalized selectable secret field entry returned by provider catalog discovery."""

    ref: str
    display_label: str
    provider: str
    item_id: str
    field_key: str
    item_title: str = ""
    path: str = ""
    is_secret: bool = True


def parse_secret_ref(ref: str) -> tuple[str, str, str]:
    """Parse canonical ``<provider>:<item_or_path>:<field_key>`` into a 3-tuple.

    Splits provider on the first ``:`` and ``field_key`` on the last ``:`` so
    item IDs or paths containing colons remain unambiguous.
    """
    cleaned = ref.strip()
    if not cleaned or ":" not in cleaned:
        raise SecretStoreError(
            f"Invalid secret reference {ref!r}. Expected '<provider>:<item_id>:<field_key>'.",
            reason="invalid_ref",
        )
    provider_raw, rest = cleaned.split(":", 1)
    provider = provider_raw.strip().lower()
    if provider not in SUPPORTED_SECRET_PROVIDERS or provider == "none":
        raise SecretStoreError(
            f"Unsupported secret provider in reference {ref!r}: {provider!r}.",
            provider=provider,
            reason="invalid_ref",
        )
    if ":" not in rest:
        raise SecretStoreError(
            f"Invalid secret reference {ref!r}. Missing ':<field_key>' suffix.",
            provider=provider,
            reason="invalid_ref",
        )
    item_id, field_key = rest.rsplit(":", 1)
    item_clean = item_id.strip()
    field_clean = field_key.strip()
    if not item_clean or not field_clean:
        raise SecretStoreError(
            f"Invalid secret reference {ref!r}. Item ID and field key must be non-empty.",
            provider=provider,
            reason="invalid_ref",
        )
    return provider, item_clean, field_clean


def format_secret_ref(provider: str, item_id: str, field_key: str) -> str:
    """Build a canonical secret reference string."""
    prov = provider.strip().lower()
    item = item_id.strip()
    fld = field_key.strip()
    if not prov or prov == "none" or prov not in SUPPORTED_SECRET_PROVIDERS:
        raise ValueError(f"Unsupported secret provider: {provider!r}.")
    if not item or not fld:
        raise ValueError("item_id and field_key must be non-empty.")
    if ":" in fld:
        raise ValueError("field_key must not contain ':'.")
    return f"{prov}:{item}:{fld}"


def _lookup_field_value(fields_map: Mapping[str, str], field_key: str) -> str | None:
    """Lookup ``field_key`` exactly first, then fall back to case-insensitive match."""
    if field_key in fields_map:
        return fields_map[field_key]
    lowered = field_key.casefold()
    for key, val in fields_map.items():
        if key.casefold() == lowered:
            return val
    return None


class SecretStoreProvider(ABC):
    """Abstract base class for SOCLens external secret manager providers."""

    provider_name: ClassVar[str] = "none"

    def __init__(
        self,
        config: SecretStoreConfig,
        *,
        stop_event: threading.Event | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.config: SecretStoreConfig = config
        self.stop_event: threading.Event = (
            stop_event if stop_event is not None else threading.Event()
        )
        self._owns_session: bool = session is None
        if config.verify_ssl is False:
            suppress_insecure_ssl_warnings()
        self.session: requests.Session = (
            session if session is not None else ConfiguredSession()
        )
        self.session.verify = config.verify_ssl

    def __enter__(self) -> SecretStoreProvider:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying ``ConfiguredSession`` if owned by this provider."""
        if self._owns_session:
            try:
                self.session.close()
            except Exception:
                pass

    def _check_cancelled(self) -> None:
        if self.stop_event.is_set():
            raise SecretStoreError(
                "Secret store operation cancelled.",
                provider=self.provider_name,
                reason="cancelled",
            )

    def _sleep(self, seconds: float) -> None:
        if seconds <= 0:
            return
        if self.stop_event.wait(seconds):
            raise SecretStoreError(
                "Secret store operation cancelled.",
                provider=self.provider_name,
                reason="cancelled",
            )

    def _session_request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        data: dict[str, Any] | str | None = None,
        timeout: float | None = None,
    ) -> requests.Response:
        """Execute an HTTP request honoring ``stop_event``, ``verify_ssl``, and ``timeout``."""
        self._check_cancelled()
        eff_timeout = self.config.timeout if timeout is None else timeout
        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                data=data,
                timeout=eff_timeout,
                verify=self.config.verify_ssl,
            )
        except requests.RequestException as exc:
            raise SecretStoreError(
                f"Network error calling {self.provider_name} ({method.upper()} {url}): {exc}",
                provider=self.provider_name,
                endpoint=url,
                reason="network_error",
            ) from exc
        self._check_cancelled()
        return response

    @abstractmethod
    def test_connection(self) -> dict[str, Any]:
        """Verify provider connectivity and authentication; return diagnostic summary."""

    @abstractmethod
    def list_secrets(
        self,
        query: str = "",
        *,
        limit: int = 100,
    ) -> list[SecretCatalogEntry]:
        """Discover selectable secret entries (metadata/labels only where supported)."""

    @abstractmethod
    def list_secret_fields(self, ref_or_id: str) -> list[SecretCatalogEntry]:
        """List selectable fields for a specific secret/item ID or reference."""

    @abstractmethod
    def get_secret_value(self, ref: str) -> str:
        """Fetch and return the plaintext secret value for canonical ``ref``."""

    def _fetch_item_fields(self, item_id: str) -> dict[str, str] | None:
        """Optional hook returning ``{field_key: secret_value}`` for single-fetch batching.

        Providers that fetch an entire secret/item in one HTTP call should override
        this method so ``resolve_mapped_settings()`` fetches each unique ``item_id``
        only once across multiple mapped settings.
        """
        return None

    def resolve_mapped_settings(
        self,
        mapping: Mapping[str, str],
    ) -> dict[str, str]:
        """Resolve ``{setting_key: canonical_ref}`` with per-ref and per-item caching.

        Guarantees at most one fetch per unique ``item_id`` when ``_fetch_item_fields``
        is implemented, and at most one fetch per unique ``ref`` otherwise.
        """
        self._check_cancelled()
        resolved: dict[str, str] = {}
        ref_cache: dict[str, str] = {}
        item_cache: dict[str, dict[str, str]] = {}

        for setting_key, raw_ref in mapping.items():
            self._check_cancelled()
            ref = str(raw_ref or "").strip()
            if not ref:
                continue

            provider, item_id, field_key = parse_secret_ref(ref)
            if provider != self.provider_name:
                raise SecretStoreError(
                    f"Reference {ref!r} targets provider {provider!r}, "
                    f"but active provider is {self.provider_name!r}.",
                    provider=self.provider_name,
                    reason="provider_mismatch",
                )

            if ref in ref_cache:
                resolved[setting_key] = ref_cache[ref]
                continue

            if item_id not in item_cache:
                fetched_map = self._fetch_item_fields(item_id)
                if fetched_map is not None:
                    item_cache[item_id] = fetched_map

            if item_id in item_cache:
                val = _lookup_field_value(item_cache[item_id], field_key)
                if val is None:
                    raise SecretStoreNotFoundError(
                        f"Field {field_key!r} not found in {self.provider_name} item {item_id!r}.",
                        provider=self.provider_name,
                        status_code=404,
                        reason="field_not_found",
                    )
                ref_cache[ref] = val
                resolved[setting_key] = val
                continue

            val = self.get_secret_value(ref)
            ref_cache[ref] = val
            resolved[setting_key] = val

        return resolved


__all__ = [
    "SECRET_PROVIDER_LABELS",
    "SUPPORTED_SECRET_PROVIDERS",
    "SecretCatalogEntry",
    "SecretStoreAuthError",
    "SecretStoreConfig",
    "SecretStoreError",
    "SecretStoreNotFoundError",
    "SecretStoreProvider",
    "format_secret_ref",
    "parse_secret_ref",
]
