"""Cross-platform configuration, console UTF-8 initialization, and error logging."""

from __future__ import annotations

import json
import logging
import math
import os
import sys
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
import urllib3
from requests.utils import should_bypass_proxies

from soclens.settings import (
    SETTING_SPECS_BY_KEY,
    get_effective_setting,
    get_saved_setting,
    get_session_override,
)

_ERROR_LOG_LOCK = threading.Lock()
_SSL_WARNING_LOCK = threading.Lock()
_SSL_WARNINGS_SUPPRESSED = False
_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

UI_VIEW_USER = "user"
UI_VIEW_ADMIN = "admin"
UI_VIEW_MODES: tuple[str, ...] = (UI_VIEW_USER, UI_VIEW_ADMIN)


def suppress_insecure_ssl_warnings() -> None:
    """Suppress urllib3 InsecureRequestWarning once in a thread-safe manner."""
    global _SSL_WARNINGS_SUPPRESSED
    if _SSL_WARNINGS_SUPPRESSED:
        return
    with _SSL_WARNING_LOCK:
        if not _SSL_WARNINGS_SUPPRESSED:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            _SSL_WARNINGS_SUPPRESSED = True


class ConfigurationError(ValueError):
    """Raised when required configuration or credentials are missing or invalid."""


@dataclass(frozen=True)
class SplunkConfig:
    """Resolved Splunk connection and Splunk ES app configuration."""

    host: str
    token: str | None = field(default=None, repr=False)
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    app: str = "SplunkEnterpriseSecuritySuite"
    verify_ssl: bool | str = False

    @property
    def has_auth(self) -> bool:
        """Return True if either token auth or username/password auth is configured."""
        return bool(self.token) or bool(self.username and self.password)


@dataclass(frozen=True)
class SentinelOneConfig:
    """Resolved SentinelOne Management API v2.1 connection and scope configuration."""

    console_url: str
    api_token: str | None = field(default=None, repr=False)
    account_id: str | None = None
    site_id: str | None = None
    verify_ssl: bool | str = True
    timeout: float = 30.0

    @property
    def has_auth(self) -> bool:
        """Return True if both console URL and API token are configured."""
        return bool(self.console_url and self.api_token)


DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_OPENAI_BASE_URL = "http://127.0.0.1:1234/v1"
SUPPORTED_LLM_PROVIDERS: frozenset[str] = frozenset({"ollama", "openai"})


@dataclass(frozen=True)
class LocalLLMConfig:
    """Resolved local LLM configuration for Ollama or OpenAI-compatible endpoints."""

    provider: str = "ollama"
    base_url: str = DEFAULT_OLLAMA_BASE_URL
    model: str | None = None
    api_key: str | None = field(default=None, repr=False)
    timeout: float = 120.0
    verify_ssl: bool | str = True
    temperature: float = 0.2
    max_tokens: int | None = None


def _clean_optional_str(value: str | None) -> str | None:
    """Strip whitespace from optional strings and normalize empty strings to None."""
    if value is None:
        return None
    stripped = value.strip()
    return stripped if stripped else None


def get_workspace_dir(explicit: Path | str | None = None) -> Path:
    """Resolve the active SOC workspace directory cross-platform.

    Resolution order:
    1. ``explicit`` path argument (if non-empty)
    2. Session override / ``SOCLENS_HOME`` env var / saved user setting
    3. Current working directory (``Path.cwd()``)

    Never resolves relative to ``__file__`` or ``site-packages``.
    """
    if explicit is not None:
        explicit_str = str(explicit).strip()
        if explicit_str:
            return Path(explicit_str).expanduser().resolve()

    configured_home = get_effective_setting("soclens_home")
    if configured_home:
        return Path(configured_home).expanduser().resolve()

    return Path.cwd().resolve()


def get_ui_view_mode(explicit: str | None = None) -> str:
    """Resolve the TUI view mode (``user`` or ``admin``), defaulting to ``user``.

    Resolution order:
    1. ``explicit`` view mode argument (validated against ``UI_VIEW_MODES``)
    2. ``SOCLENS_UI_VIEW`` environment variable (if set and valid)
    3. Default ``"user"``
    """
    if explicit is not None and str(explicit).strip():
        normalized = str(explicit).strip().lower()
        if normalized not in UI_VIEW_MODES:
            valid = ", ".join(UI_VIEW_MODES)
            raise ConfigurationError(
                f"Invalid UI view mode '{explicit}'. Valid options: {valid}."
            )
        return normalized

    env_view = _clean_optional_str(os.environ.get("SOCLENS_UI_VIEW"))
    if env_view:
        normalized = env_view.lower()
        if normalized in UI_VIEW_MODES:
            return normalized
        valid = ", ".join(UI_VIEW_MODES)
        raise ConfigurationError(
            f"Invalid SOCLENS_UI_VIEW '{env_view}'. Valid options: {valid}."
        )
    return UI_VIEW_USER


def get_rf_token(required: bool = True, explicit: str | None = None) -> str | None:
    """Resolve the Recorded Future Core API token.

    Checks ``explicit``, session override, ``RF_API_TOKEN`` /
    ``RECORDED_FUTURE_API_KEY``, and saved user settings.
    Raises ``ConfigurationError`` when ``required=True`` and no token is available.
    """
    token = _clean_optional_str(explicit) or get_effective_setting("rf_api_token")
    if not token and required:
        raise ConfigurationError(
            "Recorded Future API token is required. Configure it in the Settings menu "
            "(Settings tab or 'soclens settings') or set RF_API_TOKEN / RECORDED_FUTURE_API_KEY."
        )
    return token


def get_rf_sandbox_token(
    required: bool = False,
    explicit: str | None = None,
    default_core_token: str | None = None,
) -> str | None:
    """Resolve the Recorded Future Sandbox API token.

    Checks ``explicit``, session/env ``RF_SANDBOX_TOKEN`` / saved setting,
    ``default_core_token``, then ``get_rf_token(required=False)``.
    Raises ``ConfigurationError`` when ``required=True`` and no token is available.
    """
    token = (
        _clean_optional_str(explicit)
        or get_effective_setting("rf_sandbox_token")
        or _clean_optional_str(default_core_token)
        or get_rf_token(required=False)
    )
    if not token and required:
        raise ConfigurationError(
            "Recorded Future Sandbox API token is required. Configure it in the Settings menu "
            "or set RF_SANDBOX_TOKEN / RF_API_TOKEN."
        )
    return token


def get_rf_asi_key(required: bool = False, explicit: str | None = None) -> str | None:
    """Resolve the Recorded Future Attack Surface Intelligence (ASI) API key.

    Checks ``explicit``, session override, ``RF_ASI_API_KEY`` /
    ``SECURITYTRAILS_API_KEY``, and saved user settings.
    Raises ``ConfigurationError`` when ``required=True`` and no key is available.
    """
    key = _clean_optional_str(explicit) or get_effective_setting("rf_asi_api_key")
    if not key and required:
        raise ConfigurationError(
            "Recorded Future ASI API key is required. Configure it in the Settings menu "
            "or set RF_ASI_API_KEY / SECURITYTRAILS_API_KEY."
        )
    return key


def get_rf_pfi_token(
    required: bool = False,
    explicit: str | None = None,
    default_core_token: str | None = None,
) -> str | None:
    """Resolve the Recorded Future Payment Fraud Intelligence (PFI) API token.

    Checks ``explicit``, session/env ``RF_PFI_TOKEN`` / saved setting,
    ``default_core_token``, then ``get_rf_token(required=False)``.
    Raises ``ConfigurationError`` when ``required=True`` and no token is available.
    """
    token = (
        _clean_optional_str(explicit)
        or get_effective_setting("rf_pfi_token")
        or _clean_optional_str(default_core_token)
        or get_rf_token(required=False)
    )
    if not token and required:
        raise ConfigurationError(
            "Recorded Future PFI API token is required. Configure it in the Settings menu "
            "or set RF_PFI_TOKEN / RF_API_TOKEN."
        )
    return token


def get_rf_riskrecon_token(required: bool = False, explicit: str | None = None) -> str | None:
    """Resolve the Recorded Future RiskRecon API bearer token.

    Checks ``explicit``, session override, ``RF_RISKRECON_TOKEN`` /
    ``RISKRECON_API_TOKEN``, and saved user settings.
    Raises ``ConfigurationError`` when ``required=True`` and no token is available.
    """
    token = _clean_optional_str(explicit) or get_effective_setting("rf_riskrecon_token")
    if not token and required:
        raise ConfigurationError(
            "Recorded Future RiskRecon token is required. Configure it in the Settings menu "
            "or set RF_RISKRECON_TOKEN / RISKRECON_API_TOKEN."
        )
    return token


_TRUTHY_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on"})
_FALSY_VALUES: frozenset[str] = frozenset({"0", "false", "no", "off"})


def parse_ssl_verify(
    raw_value: bool | str | Path | None,
    *,
    default: bool = True,
) -> bool | str:
    """Normalize an SSL verification setting into bool or CA bundle path string."""
    if raw_value is None:
        return default
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, Path):
        return str(raw_value.expanduser())
    cleaned = raw_value.strip()
    if not cleaned:
        return default
    lowered = cleaned.lower()
    if lowered in _TRUTHY_VALUES:
        return True
    if lowered in _FALSY_VALUES:
        return False
    return os.path.expanduser(cleaned)


def has_rf_ssl_env_override() -> bool:
    """Return True if any Recorded Future / web SSL environment override is set."""
    for env_name in ("RF_VERIFY_SSL", "RF_INSECURE_SSL", "SOCLENS_INSECURE_SSL", "RF_CA_BUNDLE"):
        if _clean_optional_str(os.environ.get(env_name)) is not None:
            return True
    return False


def has_rf_ssl_config_override() -> bool:
    """Return True if any SSL override is configured via env, session, or saved settings."""
    if has_rf_ssl_env_override():
        return True
    for key in ("rf_verify_ssl", "rf_ca_bundle"):
        has_sess, sess_val = get_session_override(key)
        if has_sess and sess_val is not None:
            return True
        if get_saved_setting(key) is not None:
            return True
    return False


def get_rf_verify_ssl(
    explicit: bool | str | Path | None = None,
    *,
    insecure: bool | None = None,
    ca_bundle: str | Path | None = None,
) -> bool | str:
    """Resolve SSL verification mode for Recorded Future API and web requests.

    Precedence:
    1. ``insecure is True`` -> ``False``
    2. Explicit ``ca_bundle`` path
    3. ``explicit`` bool/path string
    4. ``insecure is False`` -> ``True``
    5. TUI session override (``rf_verify_ssl`` / ``rf_ca_bundle``)
    6. ``RF_VERIFY_SSL`` environment variable
    7. ``RF_INSECURE_SSL`` / ``SOCLENS_INSECURE_SSL`` environment variable
    8. ``RF_CA_BUNDLE`` environment variable
    9. Saved ``rf_verify_ssl`` / ``rf_ca_bundle`` in per-user settings
    10. Default ``True`` (``requests`` still honors ``REQUESTS_CA_BUNDLE`` / ``CURL_CA_BUNDLE``)
    """
    if insecure is True:
        return False

    if ca_bundle is not None:
        cleaned_ca = _clean_optional_str(str(ca_bundle))
        if cleaned_ca:
            return os.path.expanduser(cleaned_ca)

    if explicit is not None:
        return parse_ssl_verify(explicit, default=True)

    if insecure is False:
        return True

    has_sess_verify, sess_verify = get_session_override("rf_verify_ssl")
    has_sess_ca, sess_ca = get_session_override("rf_ca_bundle")
    if has_sess_verify and sess_verify is not None:
        parsed_sess = parse_ssl_verify(sess_verify, default=True)
        if parsed_sess is False or not (has_sess_ca and sess_ca):
            return parsed_sess
    if has_sess_ca and sess_ca is not None:
        return os.path.expanduser(sess_ca)

    env_verify = _clean_optional_str(os.environ.get("RF_VERIFY_SSL"))
    if env_verify is not None:
        return parse_ssl_verify(env_verify, default=True)

    env_insecure = _clean_optional_str(os.environ.get("RF_INSECURE_SSL")) or _clean_optional_str(
        os.environ.get("SOCLENS_INSECURE_SSL")
    )
    if env_insecure is not None:
        lowered = env_insecure.lower()
        if lowered in _TRUTHY_VALUES:
            return False
        if lowered in _FALSY_VALUES:
            return True

    env_ca = _clean_optional_str(os.environ.get("RF_CA_BUNDLE"))
    if env_ca is not None:
        return os.path.expanduser(env_ca)

    saved_verify = get_saved_setting("rf_verify_ssl")
    if saved_verify is not None:
        return parse_ssl_verify(saved_verify, default=True)

    saved_ca = get_saved_setting("rf_ca_bundle")
    if saved_ca is not None:
        return os.path.expanduser(saved_ca)

    return True


def format_ssl_verify_status(verify_ssl: bool | str) -> str:
    """Return a concise human-readable description of the active SSL verify state."""
    if verify_ssl is False:
        return "INSECURE (Disabled - Proxy Mode)"
    if isinstance(verify_ssl, str):
        return f"Custom CA ({verify_ssl})"
    env_ca = _clean_optional_str(os.environ.get("REQUESTS_CA_BUNDLE")) or _clean_optional_str(
        os.environ.get("CURL_CA_BUNDLE")
    )
    if env_ca:
        return f"Enabled (Env CA: {env_ca})"
    return "Enabled (Verified)"


def _mask_proxy_url(raw_url: str) -> str:
    """Mask any userinfo credentials inside a proxy URL while keeping host/port visible."""
    cleaned = raw_url.strip()
    has_scheme = "://" in cleaned
    try:
        parsed = urlsplit(cleaned if has_scheme else f"//{cleaned}")
        has_creds = parsed.username is not None or parsed.password is not None
        if not has_creds:
            return cleaned
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port_suffix = f":{parsed.port}" if parsed.port is not None else ""
        scheme_prefix = f"{parsed.scheme}://" if has_scheme and parsed.scheme else ""
        return f"{scheme_prefix}***@{host}{port_suffix}{parsed.path}"
    except ValueError:
        return "***"


def get_proxy_settings() -> dict[str, str]:
    """Return effective proxy settings (``https``, ``http``, ``no_proxy``)."""
    proxies: dict[str, str] = {}
    https_proxy = get_effective_setting("https_proxy")
    http_proxy = get_effective_setting("http_proxy")
    no_proxy = get_effective_setting("no_proxy")
    if https_proxy:
        proxies["https"] = https_proxy
    if http_proxy:
        proxies["http"] = http_proxy
    if no_proxy:
        proxies["no_proxy"] = no_proxy
    return proxies


def get_saved_proxies_for_url(url: str) -> dict[str, str]:
    """Return configured HTTP/HTTPS proxies for ``url`` unless bypassed by ``no_proxy``."""
    effective_no_proxy = get_effective_setting("no_proxy")
    if should_bypass_proxies(url, no_proxy=effective_no_proxy):
        return {}
    result: dict[str, str] = {}
    https_proxy = get_effective_setting("https_proxy")
    http_proxy = get_effective_setting("http_proxy")
    if https_proxy:
        result["https"] = https_proxy
    if http_proxy:
        result["http"] = http_proxy
    return result


class ConfiguredSession(requests.Session):
    """``requests.Session`` subclass honoring per-user saved/session proxy settings."""

    def merge_environment_settings(
        self,
        url: str,
        proxies: dict[str, str] | None,
        stream: bool | None,
        verify: bool | str | None,
        cert: str | tuple[str, str] | None,
    ) -> dict[str, Any]:
        merged = super().merge_environment_settings(url, proxies, stream, verify, cert)
        if not self.trust_env:
            return merged

        explicit_schemes: set[str] = set()
        if proxies:
            explicit_schemes.update(proxies.keys())
        if self.proxies:
            explicit_schemes.update(self.proxies.keys())

        effective_no_proxy = get_effective_setting("no_proxy")
        has_sess_no_proxy, _ = get_session_override("no_proxy")
        has_configured_no_proxy = effective_no_proxy is not None

        merged_proxies = dict(merged.get("proxies") or {})
        if (has_sess_no_proxy or has_configured_no_proxy) and should_bypass_proxies(
            url, no_proxy=effective_no_proxy
        ):
            for key in list(merged_proxies):
                if key not in explicit_schemes:
                    merged_proxies.pop(key, None)
            merged["proxies"] = merged_proxies
            return merged

        for scheme, setting_key in (("https", "https_proxy"), ("http", "http_proxy")):
            if scheme in explicit_schemes:
                continue
            has_sess, sess_val = get_session_override(setting_key)
            if has_sess and sess_val is not None:
                merged_proxies[scheme] = sess_val
            elif scheme not in merged_proxies:
                effective = get_effective_setting(setting_key)
                if effective is not None:
                    merged_proxies[scheme] = effective

        merged["proxies"] = merged_proxies
        return merged


def get_proxy_summary() -> str:
    """Summarize active HTTP/HTTPS proxy settings with credentials masked."""
    parts: list[str] = []
    proxy_cfg = get_proxy_settings()
    https_proxy = proxy_cfg.get("https")
    http_proxy = proxy_cfg.get("http")
    if https_proxy:
        parts.append(f"HTTPS={_mask_proxy_url(https_proxy)}")
    if http_proxy:
        parts.append(f"HTTP={_mask_proxy_url(http_proxy)}")
    return " | ".join(parts) if parts else "None (Direct)"


_RF_SERVICE_BASE_URL_KEYS: dict[str, str] = {
    "core": "rf_base_url",
    "sandbox": "rf_sandbox_base_url",
    "asi": "rf_asi_base_url",
    "pfi": "rf_pfi_base_url",
    "riskrecon": "rf_riskrecon_base_url",
}


def get_rf_base_url(service: str = "core", explicit: str | None = None) -> str:
    """Resolve the Recorded Future base URL for ``service``."""
    clean_service = service.strip().lower()
    key = _RF_SERVICE_BASE_URL_KEYS.get(clean_service)
    if key is None:
        raise ConfigurationError(f"Unknown Recorded Future service: {service!r}")
    resolved = _clean_optional_str(explicit) or get_effective_setting(key, include_default=True)
    if not resolved:
        spec = SETTING_SPECS_BY_KEY[key]
        resolved = spec.default or ""
    return resolved.rstrip("/")


def get_auto_approve() -> bool:
    """Return True when ``SOCLENS_AUTO_APPROVE`` or saved setting allows auto-approve."""
    raw = get_effective_setting("soclens_auto_approve")
    if raw is None:
        return False
    return raw.strip().lower() in _TRUTHY_VALUES


def get_sigma_setting(key: str) -> str | None:
    """Resolve an optional Sigma configuration setting (session > env > saved)."""
    val = get_effective_setting(key)
    if val is not None:
        return val
    return _clean_optional_str(os.environ.get(key))


def get_logo_overrides_file() -> str | None:
    """Resolve optional brand logo overrides file path (session > env > saved)."""
    return get_effective_setting("rf_logo_overrides_file")


def get_ignored_hashes_file() -> str | None:
    """Resolve optional ignored logo hashes file path (session > env > saved)."""
    return get_effective_setting("rf_ignored_hashes_file")


def get_ignored_hashes() -> str | None:
    """Resolve optional comma-separated ignored logo hashes (session > env > saved)."""
    return get_effective_setting("rf_ignored_hashes")


def get_tui_image_protocol() -> str | None:
    """Resolve optional TUI image protocol override (session > env > saved)."""
    return get_effective_setting("rf_tui_image_protocol")


def _parse_verify_ssl(raw_value: bool | str | None) -> bool | str:
    """Normalize SPLUNK_VERIFY_SSL into bool or CA bundle path string."""
    return parse_ssl_verify(raw_value, default=False)


def get_splunk_config(
    host: str | None = None,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    app: str | None = None,
    verify_ssl: bool | str | None = None,
    required: bool = False,
) -> SplunkConfig:
    """Load Splunk configuration from explicit args, environment, or saved user settings.

    Reads ``SPLUNK_HOST``, ``SPLUNK_TOKEN``, ``SPLUNK_USERNAME``, ``SPLUNK_PASSWORD``,
    ``SPLUNK_APP`` (default ``SplunkEnterpriseSecuritySuite``), and ``SPLUNK_VERIFY_SSL``.
    """
    raw_host = (
        _clean_optional_str(host)
        or get_effective_setting("splunk_host")
        or "https://127.0.0.1:8089"
    )
    if not raw_host.lower().startswith(("http://", "https://")):
        raw_host = f"https://{raw_host}"
    normalized_host = raw_host.rstrip("/")

    resolved_token = (
        _clean_optional_str(token)
        if token is not None
        else get_effective_setting("splunk_token")
    )
    resolved_username = (
        _clean_optional_str(username)
        if username is not None
        else get_effective_setting("splunk_username")
    )
    resolved_password = (
        _clean_optional_str(password)
        if password is not None
        else get_effective_setting("splunk_password")
    )
    resolved_app = (
        _clean_optional_str(app)
        if app is not None
        else get_effective_setting("splunk_app")
    ) or "SplunkEnterpriseSecuritySuite"
    raw_verify: bool | str | None = (
        verify_ssl if verify_ssl is not None else get_effective_setting("splunk_verify_ssl")
    )
    resolved_verify = _parse_verify_ssl(raw_verify)

    config = SplunkConfig(
        host=normalized_host,
        token=resolved_token,
        username=resolved_username,
        password=resolved_password,
        app=resolved_app,
        verify_ssl=resolved_verify,
    )
    if required and not config.has_auth:
        raise ConfigurationError(
            "Splunk credentials are required. Configure them in the Settings menu "
            "or set SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD."
        )
    return config


    return config


def get_sentinelone_config(
    console_url: str | None = None,
    api_token: str | None = None,
    account_id: str | None = None,
    site_id: str | None = None,
    verify_ssl: bool | str | Path | None = None,
    timeout: float | None = None,
    required: bool = False,
) -> SentinelOneConfig:
    """Load SentinelOne Management API v2.1 config from args, env, or saved settings.

    Reads ``S1_CONSOLE_URL`` / ``SENTINELONE_URL``, ``S1_API_TOKEN`` /
    ``SENTINELONE_API_TOKEN``, ``S1_ACCOUNT_ID``, ``S1_SITE_ID``,
    ``S1_VERIFY_SSL`` (falling back to ``get_rf_verify_ssl()``), and ``S1_TIMEOUT``.
    """
    raw_url = _clean_optional_str(console_url) or get_effective_setting("s1_console_url") or ""
    if raw_url and not raw_url.lower().startswith(("http://", "https://")):
        raw_url = f"https://{raw_url}"
    normalized_url = raw_url.rstrip("/")

    resolved_token = (
        _clean_optional_str(api_token)
        if api_token is not None
        else get_effective_setting("s1_api_token")
    )
    resolved_account_id = (
        _clean_optional_str(account_id)
        if account_id is not None
        else get_effective_setting("s1_account_id")
    )
    resolved_site_id = (
        _clean_optional_str(site_id)
        if site_id is not None
        else get_effective_setting("s1_site_id")
    )

    if verify_ssl is not None:
        resolved_verify: bool | str = parse_ssl_verify(verify_ssl, default=True)
    else:
        configured_verify = get_effective_setting("s1_verify_ssl")
        if configured_verify is not None:
            resolved_verify = parse_ssl_verify(configured_verify, default=True)
        else:
            resolved_verify = get_rf_verify_ssl()

    resolved_timeout = 30.0
    if timeout is not None:
        resolved_timeout = float(timeout)
    else:
        configured_timeout = get_effective_setting("s1_timeout")
        if configured_timeout is not None:
            try:
                resolved_timeout = float(configured_timeout)
            except ValueError as exc:
                raise ConfigurationError(
                    f"Invalid S1_TIMEOUT value: {configured_timeout!r}"
                ) from exc
    if resolved_timeout <= 0:
        raise ConfigurationError(f"SentinelOne timeout must be positive, got {resolved_timeout!r}")

    config = SentinelOneConfig(
        console_url=normalized_url,
        api_token=resolved_token,
        account_id=resolved_account_id,
        site_id=resolved_site_id,
        verify_ssl=resolved_verify,
        timeout=resolved_timeout,
    )
    if required and not config.has_auth:
        raise ConfigurationError(
            "SentinelOne credentials are required. Configure them in the Settings menu "
            "or set S1_CONSOLE_URL (or SENTINELONE_URL) and "
            "S1_API_TOKEN (or SENTINELONE_API_TOKEN)."
        )
    return config


def _normalize_llm_provider(raw_provider: str | None) -> str:
    cleaned = (_clean_optional_str(raw_provider) or "ollama").lower()
    if cleaned in ("openai-compatible", "openai_compatible"):
        cleaned = "openai"
    if cleaned not in SUPPORTED_LLM_PROVIDERS:
        raise ConfigurationError(
            f"Unsupported local LLM provider '{raw_provider}'. "
            f"Expected one of: {', '.join(sorted(SUPPORTED_LLM_PROVIDERS))}."
        )
    return cleaned


def _parse_positive_float(raw_value: float | str | None, *, default: float, name: str) -> float:
    if raw_value is None:
        return default
    if isinstance(raw_value, bool):
        raise ConfigurationError(f"Invalid {name}: {raw_value!r}")
    if isinstance(raw_value, str):
        cleaned = raw_value.strip()
        if not cleaned:
            return default
        try:
            parsed = float(cleaned)
        except ValueError as exc:
            raise ConfigurationError(f"Invalid {name}: {raw_value!r}") from exc
    else:
        parsed = float(raw_value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise ConfigurationError(f"{name} must be a positive finite number, got {raw_value!r}")
    return parsed


def _parse_temperature(raw_value: float | str | None, *, default: float = 0.2) -> float:
    if raw_value is None:
        return default
    if isinstance(raw_value, bool):
        raise ConfigurationError(f"Invalid temperature: {raw_value!r}")
    if isinstance(raw_value, str):
        cleaned = raw_value.strip()
        if not cleaned:
            return default
        try:
            parsed = float(cleaned)
        except ValueError as exc:
            raise ConfigurationError(f"Invalid temperature: {raw_value!r}") from exc
    else:
        parsed = float(raw_value)
    if not math.isfinite(parsed) or parsed < 0.0 or parsed > 2.0:
        raise ConfigurationError(
            f"temperature must be between 0.0 and 2.0, got {raw_value!r}"
        )
    return parsed


def _parse_optional_positive_int(raw_value: int | str | None, *, name: str) -> int | None:
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        raise ConfigurationError(f"Invalid {name}: {raw_value!r}")
    if isinstance(raw_value, str):
        cleaned = raw_value.strip()
        if not cleaned:
            return None
        try:
            parsed = int(cleaned)
        except ValueError as exc:
            raise ConfigurationError(f"Invalid {name}: {raw_value!r}") from exc
    else:
        parsed = int(raw_value)
    if parsed <= 0:
        raise ConfigurationError(f"{name} must be a positive integer, got {raw_value!r}")
    return parsed


def get_local_llm_config(
    provider: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    timeout: float | str | None = None,
    verify_ssl: bool | str | Path | None = None,
    temperature: float | str | None = None,
    max_tokens: int | str | None = None,
) -> LocalLLMConfig:
    """Load local LLM configuration from explicit arguments or environment variables.

    Reads ``RF_LLM_PROVIDER`` (default ``ollama``), ``RF_LLM_BASE_URL``,
    ``RF_LLM_MODEL``, ``RF_LLM_API_KEY``, ``RF_LLM_TIMEOUT`` (default ``120.0``),
    ``RF_LLM_VERIFY_SSL``, ``RF_LLM_TEMPERATURE`` (default ``0.2``), and
    ``RF_LLM_MAX_TOKENS``.
    """
    resolved_provider = _normalize_llm_provider(
        provider if provider is not None else os.environ.get("RF_LLM_PROVIDER")
    )
    default_url = (
        DEFAULT_OPENAI_BASE_URL if resolved_provider == "openai" else DEFAULT_OLLAMA_BASE_URL
    )
    raw_url = (
        _clean_optional_str(base_url)
        or _clean_optional_str(os.environ.get("RF_LLM_BASE_URL"))
        or default_url
    )
    if not raw_url.lower().startswith(("http://", "https://")):
        raw_url = f"http://{raw_url}"
    normalized_url = raw_url.rstrip("/")

    resolved_model = _clean_optional_str(
        model if model is not None else os.environ.get("RF_LLM_MODEL")
    )
    resolved_api_key = _clean_optional_str(
        api_key if api_key is not None else os.environ.get("RF_LLM_API_KEY")
    )
    raw_timeout: float | str | None = (
        timeout if timeout is not None else os.environ.get("RF_LLM_TIMEOUT")
    )
    resolved_timeout = _parse_positive_float(raw_timeout, default=120.0, name="RF_LLM_TIMEOUT")

    raw_verify: bool | str | Path | None = (
        verify_ssl if verify_ssl is not None else os.environ.get("RF_LLM_VERIFY_SSL")
    )
    resolved_verify = parse_ssl_verify(raw_verify, default=True)

    raw_temp: float | str | None = (
        temperature if temperature is not None else os.environ.get("RF_LLM_TEMPERATURE")
    )
    resolved_temp = _parse_temperature(raw_temp, default=0.2)

    raw_max_tokens: int | str | None = (
        max_tokens if max_tokens is not None else os.environ.get("RF_LLM_MAX_TOKENS")
    )
    resolved_max_tokens = _parse_optional_positive_int(raw_max_tokens, name="RF_LLM_MAX_TOKENS")

    return LocalLLMConfig(
        provider=resolved_provider,
        base_url=normalized_url,
        model=resolved_model,
        api_key=resolved_api_key,
        timeout=resolved_timeout,
        verify_ssl=resolved_verify,
        temperature=resolved_temp,
        max_tokens=resolved_max_tokens,
    )


def ensure_utf8_console() -> None:
    """Safely configure ``sys.stdout`` and ``sys.stderr`` for UTF-8 output.

    Prevents Windows ``cp1252`` ``UnicodeEncodeError`` while remaining safe on
    captured, redirected, ``StringIO``, ``None``, or mocked streams.
    """
    for stream in (sys.stdout, sys.stderr):
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        encoding = getattr(stream, "encoding", None)
        should_reconfigure = os.name == "nt" or not (
            isinstance(encoding, str) and encoding.lower() in ("utf-8", "utf8")
        )
        if not should_reconfigure:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError, TypeError, LookupError):
            pass


def _resolve_level(level: int | str) -> int:
    """Convert a logging level name or integer to a numeric logging level."""
    if isinstance(level, int) and not isinstance(level, bool):
        return level
    if not isinstance(level, str):
        raise ConfigurationError(f"Invalid log level: {level!r}")
    name = level.strip().upper()
    resolved = logging.getLevelName(name)
    if isinstance(resolved, int):
        return resolved
    raise ConfigurationError(f"Invalid log level: {level!r}")


def configure_logging(
    level: int | str = logging.INFO,
    log_file: Path | str | None = None,
    workspace_dir: Path | str | None = None,
    stream: Any = None,
    *,
    enable_console: bool = True,
) -> logging.Logger:
    """Configure the ``soclens`` package logger idempotently across platforms."""
    ensure_utf8_console()
    numeric_level = _resolve_level(level)

    pkg_logger = logging.getLogger("soclens")
    pkg_logger.setLevel(numeric_level)
    formatter = logging.Formatter(_LOG_FORMAT)

    # Remove previously managed handlers to keep repeated calls idempotent.
    for existing in list(pkg_logger.handlers):
        if getattr(existing, "_soclens_managed", False):
            pkg_logger.removeHandler(existing)
            try:
                existing.close()
            except OSError:
                pass

    if enable_console or stream is not None:
        target_stream = stream if stream is not None else sys.stderr
        stream_handler = logging.StreamHandler(target_stream)
        stream_handler.setLevel(numeric_level)
        stream_handler.setFormatter(formatter)
        setattr(stream_handler, "_soclens_managed", True)
        pkg_logger.addHandler(stream_handler)

    if log_file is not None:
        log_path = Path(log_file).expanduser()
        if not log_path.is_absolute():
            log_path = get_workspace_dir(workspace_dir) / log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        setattr(file_handler, "_soclens_managed", True)
        pkg_logger.addHandler(file_handler)

    return pkg_logger


def record_api_error(
    entry: dict[str, Any],
    log_dir: Path | str | None = None,
    workspace_dir: Path | str | None = None,
) -> Path:
    """Append a structured API error record as JSONL to ``logs/rf_api_errors.jsonl``.

    Creates parent directories if missing and uses a module-level lock for
    thread-safe concurrent writes.
    """
    target_dir = (
        Path(log_dir).expanduser().resolve()
        if log_dir is not None
        else get_workspace_dir(workspace_dir) / "logs"
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / "rf_api_errors.jsonl"

    trace_id = entry.get("trace_id") or entry.get("traceId")
    record: dict[str, Any] = {
        "timestamp": entry.get("timestamp")
        or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endpoint": entry.get("endpoint"),
        "method": entry.get("method"),
        "status_code": entry.get("status_code"),
        "trace_id": trace_id,
        "message": entry.get("message"),
        "reason": entry.get("reason"),
        "category": entry.get("category"),
    }
    for key, val in entry.items():
        if key not in record and key != "traceId":
            record[key] = val

    line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
    with _ERROR_LOG_LOCK:
        with target_file.open("a", encoding="utf-8") as fh:
            fh.write(line)

    return target_file


IMAGE_VIEWER_TUI = "tui"
IMAGE_VIEWER_OS = "os"
IMAGE_VIEWER_MODES: tuple[str, str] = (IMAGE_VIEWER_TUI, IMAGE_VIEWER_OS)
TUI_SETTINGS_FILENAME = ".soclens_tui_settings.json"
_TUI_SETTINGS_LOCK = threading.Lock()

_IMAGE_VIEWER_OS_ALIASES: frozenset[str] = frozenset(
    {"os", "os_viewer", "os-viewer", "native", "external", "system"}
)
_IMAGE_VIEWER_TUI_ALIASES: frozenset[str] = frozenset(
    {"tui", "modal", "inline", "builtin", "internal"}
)


def normalize_image_viewer_mode(raw_value: str) -> str:
    """Normalize a TUI image viewer mode string into ``'tui'`` or ``'os'``."""
    cleaned = raw_value.strip().lower()
    if cleaned in _IMAGE_VIEWER_OS_ALIASES:
        return IMAGE_VIEWER_OS
    if cleaned in _IMAGE_VIEWER_TUI_ALIASES:
        return IMAGE_VIEWER_TUI
    raise ConfigurationError(
        f"Invalid image viewer mode '{raw_value}'. Valid options: tui, os."
    )


def load_tui_settings(workspace_dir: Path | str | None = None) -> dict[str, Any]:
    """Load persisted TUI settings from ``<workspace>/.soclens_tui_settings.json``."""
    settings_path = get_workspace_dir(workspace_dir) / TUI_SETTINGS_FILENAME
    with _TUI_SETTINGS_LOCK:
        if not settings_path.is_file():
            return {}
        try:
            raw = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return dict(raw) if isinstance(raw, dict) else {}


def save_tui_settings(
    updates: dict[str, Any],
    workspace_dir: Path | str | None = None,
) -> Path:
    """Merge and persist TUI settings into ``<workspace>/.soclens_tui_settings.json``."""
    target_dir = get_workspace_dir(workspace_dir)
    settings_path = target_dir / TUI_SETTINGS_FILENAME
    with _TUI_SETTINGS_LOCK:
        existing: dict[str, Any] = {}
        if settings_path.is_file():
            try:
                loaded = json.loads(settings_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing = loaded
            except (OSError, ValueError):
                existing = {}
        existing.update(updates)
        target_dir.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(
            json.dumps(existing, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    return settings_path


def has_explicit_image_viewer_setting(
    explicit: str | None = None,
    *,
    workspace_dir: Path | str | None = None,
) -> bool:
    """Return True when the user explicitly configured ``image_viewer`` via arg, env, or disk."""
    if _clean_optional_str(explicit) is not None:
        return True
    if _clean_optional_str(os.environ.get("SOCLENS_IMAGE_VIEWER")) is not None:
        return True
    if _clean_optional_str(os.environ.get("RF_TUI_OPEN_IMAGES_IN_OS_VIEWER")) is not None:
        return True
    persisted = load_tui_settings(workspace_dir).get("image_viewer")
    if isinstance(persisted, str) and persisted.strip():
        try:
            normalize_image_viewer_mode(persisted)
            return True
        except ConfigurationError:
            return False
    return False


def get_image_viewer_mode(
    explicit: str | None = None,
    *,
    workspace_dir: Path | str | None = None,
    default_mode: str = IMAGE_VIEWER_TUI,
) -> str:
    """Resolve the default TUI image viewer mode (``'tui'`` or ``'os'``).

    Precedence:
    1. ``explicit`` argument
    2. ``SOCLENS_IMAGE_VIEWER`` environment variable
    3. ``RF_TUI_OPEN_IMAGES_IN_OS_VIEWER`` boolean environment variable
    4. Persisted workspace setting in ``.soclens_tui_settings.json``
    5. ``default_mode`` (defaults to ``'tui'``)
    """
    cleaned_explicit = _clean_optional_str(explicit)
    if cleaned_explicit is not None:
        return normalize_image_viewer_mode(cleaned_explicit)

    env_mode = _clean_optional_str(os.environ.get("SOCLENS_IMAGE_VIEWER"))
    if env_mode is not None:
        return normalize_image_viewer_mode(env_mode)

    env_os_flag = _clean_optional_str(os.environ.get("RF_TUI_OPEN_IMAGES_IN_OS_VIEWER"))
    if env_os_flag is not None:
        lowered = env_os_flag.lower()
        if lowered in _TRUTHY_VALUES:
            return IMAGE_VIEWER_OS
        if lowered in _FALSY_VALUES:
            return IMAGE_VIEWER_TUI
        raise ConfigurationError(
            f"Invalid RF_TUI_OPEN_IMAGES_IN_OS_VIEWER '{env_os_flag}'. "
            "Expected true/false."
        )

    persisted = load_tui_settings(workspace_dir).get("image_viewer")
    if isinstance(persisted, str) and persisted.strip():
        try:
            return normalize_image_viewer_mode(persisted)
        except ConfigurationError:
            pass

    return normalize_image_viewer_mode(default_mode)


def format_image_viewer_status(mode: str) -> str:
    """Return a concise human-readable description of the default image viewer."""
    return (
        "OS Image Viewer (Default)"
        if mode == IMAGE_VIEWER_OS
        else "TUI Modal Viewer (Default)"
    )
