"""Pluggable secret manager / PAM provider factory and public exports."""

from __future__ import annotations

import importlib
import threading

import requests

from soclens.secret_stores.base import (
    SECRET_PROVIDER_LABELS,
    SUPPORTED_SECRET_PROVIDERS,
    SecretCatalogEntry,
    SecretStoreAuthError,
    SecretStoreConfig,
    SecretStoreError,
    SecretStoreNotFoundError,
    SecretStoreProvider,
    format_secret_ref,
    parse_secret_ref,
)

_PROVIDER_REGISTRY: dict[str, tuple[str, str]] = {
    "secret_server": ("soclens.secret_stores.secret_server", "SecretServerProvider"),
    "hashicorp_vault": ("soclens.secret_stores.hashicorp_vault", "HashiCorpVaultProvider"),
    "onepassword_connect": (
        "soclens.secret_stores.onepassword_connect",
        "OnePasswordConnectProvider",
    ),
    "bitwarden": ("soclens.secret_stores.bitwarden", "BitwardenProvider"),
}


def build_secret_store_provider(
    config: SecretStoreConfig,
    *,
    stop_event: threading.Event | None = None,
    session: requests.Session | None = None,
) -> SecretStoreProvider:
    """Instantiate the configured ``SecretStoreProvider`` implementation."""
    provider = config.provider.strip().lower()
    if not provider or provider == "none":
        raise SecretStoreError(
            "Secret store provider is disabled ('none').",
            provider="none",
            reason="disabled",
        )
    spec = _PROVIDER_REGISTRY.get(provider)
    if spec is None:
        supported = ", ".join(p for p in SUPPORTED_SECRET_PROVIDERS if p != "none")
        raise SecretStoreError(
            f"Unsupported secret store provider {config.provider!r}. Expected one of: {supported}.",
            provider=provider,
            reason="unsupported_provider",
        )

    module_name, class_name = spec
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name:
            raise SecretStoreError(
                f"Secret store provider {provider!r} ({module_name}) is not available yet.",
                provider=provider,
                reason="provider_unavailable",
            ) from exc
        raise

    provider_cls = getattr(module, class_name, None)
    if not isinstance(provider_cls, type) or not issubclass(provider_cls, SecretStoreProvider):
        raise SecretStoreError(
            f"Provider module {module_name!r} does not export a valid {class_name}.",
            provider=provider,
            reason="invalid_provider_class",
        )

    return provider_cls(config, stop_event=stop_event, session=session)


__all__ = [
    "SECRET_PROVIDER_LABELS",
    "SUPPORTED_SECRET_PROVIDERS",
    "SecretCatalogEntry",
    "SecretStoreAuthError",
    "SecretStoreConfig",
    "SecretStoreError",
    "SecretStoreNotFoundError",
    "SecretStoreProvider",
    "build_secret_store_provider",
    "format_secret_ref",
    "parse_secret_ref",
]
