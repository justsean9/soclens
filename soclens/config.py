"""Cross-platform configuration, console UTF-8 initialization, and error logging."""

from __future__ import annotations

import json
import logging
import math
import os
import re
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
import urllib3
from requests.utils import should_bypass_proxies

from soclens.settings import (
    AKEYLESS_AUTH_MODES,
    MS_COPILOT_AUTH_MODES,
    SECRET_MANAGED_SETTING_KEYS,
    SETTING_SPECS_BY_KEY,
    SUPPORTED_SECRET_PROVIDERS,
    TSS_AUTH_MODES,
    VAULT_AUTH_MODES,
    get_effective_setting,
    get_env_override_for_setting,
    get_saved_setting,
    get_session_override,
    mask_secret,
    parse_s1_site_tenant_map,
    parse_s1_tier_rules,
    parse_vault_secret_map,
    set_session_overrides,
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
DEFAULT_M365_COPILOT_GRAPH_URL = "https://graph.microsoft.com/beta"
DEFAULT_COPILOT_DIRECTLINE_URL = "https://directline.botframework.com/v3/directline"
COPILOT_LLM_PROVIDERS: frozenset[str] = frozenset(
    {"m365_copilot", "copilot_studio", "copilot_directline", "security_copilot"}
)
SUPPORTED_LLM_PROVIDERS: frozenset[str] = frozenset(
    {"ollama", "openai", "m365_copilot", "copilot_studio", "copilot_directline", "security_copilot"}
)


@dataclass(frozen=True)
class CopilotAgentPreset:
    """Named Microsoft Copilot or LLM agent preset for multi-agent workflows."""

    name: str
    provider: str = "m365_copilot"
    model: str | None = None
    base_url: str | None = None
    token_endpoint: str | None = field(default=None, repr=False)
    directline_secret: str | None = field(default=None, repr=False)
    bearer_token: str | None = field(default=None, repr=False)
    workspace: str | None = None
    web_grounding: bool | None = None


@dataclass(frozen=True)
class LocalLLMConfig:
    """Resolved AI analyst configuration for local LLMs and Microsoft Copilot agents."""

    provider: str = "ollama"
    base_url: str = DEFAULT_OLLAMA_BASE_URL
    model: str | None = None
    api_key: str | None = field(default=None, repr=False)
    timeout: float = 120.0
    verify_ssl: bool | str = True
    temperature: float = 0.2
    max_tokens: int | None = None
    # Microsoft Copilot & Security Copilot settings
    ms_auth_mode: str = "token"
    ms_bearer_token: str | None = field(default=None, repr=False)
    ms_graph_base_url: str = DEFAULT_M365_COPILOT_GRAPH_URL
    ms_web_grounding: bool = True
    ms_directline_url: str = DEFAULT_COPILOT_DIRECTLINE_URL
    ms_token_endpoint: str | None = field(default=None, repr=False)
    ms_directline_secret: str | None = field(default=None, repr=False)
    ms_security_workspace: str = "default"
    ms_security_poll_interval: float = 2.0
    agent_presets: tuple[CopilotAgentPreset, ...] = ()
    visible_providers: tuple[str, ...] = ()


@dataclass(frozen=True)
class OSINTConfig:
    """Resolved free passive OSINT enrichment configuration (secrets hidden from repr)."""

    enabled: bool = True
    timeout: float = 8.0
    verify_ssl: bool | str = True
    vt_api_key: str | None = field(default=None, repr=False)
    abuseipdb_api_key: str | None = field(default=None, repr=False)
    abusech_api_key: str | None = field(default=None, repr=False)
    otx_api_key: str | None = field(default=None, repr=False)
    urlscan_api_key: str | None = field(default=None, repr=False)
    greynoise_api_key: str | None = field(default=None, repr=False)

    def configured_key_count(self) -> int:
        """Return count of configured optional free-tier OSINT API keys."""
        return sum(
            1
            for val in (
                self.vt_api_key,
                self.abuseipdb_api_key,
                self.abusech_api_key,
                self.otx_api_key,
                self.urlscan_api_key,
                self.greynoise_api_key,
            )
            if val
        )


@dataclass(frozen=True)
class SecretStoreConfig:
    """Resolved secret manager / PAM configuration (secret fields excluded from repr)."""

    provider: str = "none"
    verify_ssl: bool | str = True
    timeout: float = 15.0
    secret_map: dict[str, str] = field(default_factory=dict)

    # Thycotic / Delinea Secret Server
    tss_base_url: str = ""
    tss_auth_mode: str = "password"
    tss_username: str | None = None
    tss_password: str | None = field(default=None, repr=False)
    tss_domain: str | None = None
    tss_client_id: str | None = None
    tss_client_secret: str | None = field(default=None, repr=False)
    tss_access_token: str | None = field(default=None, repr=False)
    tss_platform_url: str = ""
    tss_folder_id: str | None = None
    tss_api_version: str = "v1"
    tss_auto_comment: str | None = None

    # HashiCorp Vault (KV v2)
    vault_addr: str = ""
    vault_auth_mode: str = "token"
    vault_token: str | None = field(default=None, repr=False)
    vault_role_id: str | None = None
    vault_secret_id: str | None = field(default=None, repr=False)
    vault_auth_mount: str = "approle"
    vault_kv_mount: str = "secret"
    vault_namespace: str | None = None
    vault_prefix: str | None = None

    # 1Password Connect Server
    op_connect_url: str = ""
    op_connect_token: str | None = field(default=None, repr=False)
    op_vault_id: str | None = None

    # Bitwarden (bw serve)
    bw_serve_url: str = "http://127.0.0.1:8087"
    bw_master_password: str | None = field(default=None, repr=False)
    bw_folder_id: str | None = None
    bw_collection_id: str | None = None
    bw_organization_id: str | None = None

    # Akeyless Vault
    akeyless_api_url: str = "https://api.akeyless.io"
    akeyless_auth_mode: str = "access_key"
    akeyless_access_id: str | None = None
    akeyless_access_key: str | None = field(default=None, repr=False)
    akeyless_token: str | None = field(default=None, repr=False)
    akeyless_prefix: str | None = None

    @property
    def enabled(self) -> bool:
        """Return True when an active secret store provider is selected."""
        return self.provider.strip().lower() not in ("", "none")

    @property
    def is_enabled(self) -> bool:
        """Return True when an active secret store provider is selected."""
        return self.enabled

    @property
    def vault_mount(self) -> str:
        """Compatibility alias for ``vault_kv_mount``."""
        return self.vault_kv_mount

    @property
    def vault_path_prefix(self) -> str:
        """Compatibility alias for ``vault_prefix``."""
        return self.vault_prefix or ""

    @property
    def bw_api_url(self) -> str:
        """Compatibility alias for ``bw_serve_url``."""
        return self.bw_serve_url


@dataclass(frozen=True)
class PivotPayload:
    """Typed cross-workbench pivot message passed across TUI panes."""

    source_tab: str = ""
    target_tab: str = ""
    tenant_id: str | None = None
    site_id: str | None = None
    site_name: str | None = None
    tier: str | None = None
    entity: str | None = None
    entity_type: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    hostname: str | None = None
    username: str | None = None
    orig_sid: str | None = None
    earliest: str | None = None
    latest: str | None = None
    spl_query: str | None = None
    auto_run: bool = False
    es_finding: dict[str, Any] | None = None
    s1_threat: dict[str, Any] | None = None
    rf_enrichment: dict[str, Any] | None = None
    summary: str | None = None

    def primary_ioc(self) -> tuple[str, str] | None:
        """Return the highest-priority ``(entity_type, value)`` tuple for RF/Research pivots."""
        if self.entity and self.entity.strip() and self.entity.strip() != "-":
            return (self.entity_type or "auto", self.entity.strip())
        for kind, val in (
            ("hash", self.sha256),
            ("hash", self.sha1),
            ("ip", self.src_ip),
            ("ip", self.dest_ip),
            ("host", self.hostname),
            ("user", self.username),
        ):
            if val and val.strip() and val.strip() != "-":
                return (kind, val.strip())
        return None


def _extract_scalar_tenant(val: Any) -> str | None:
    if isinstance(val, bool) or val is None:
        return None
    if isinstance(val, (list, tuple)):
        for item in val:
            extracted = _extract_scalar_tenant(item)
            if extracted is not None:
                return extracted
        return None
    if isinstance(val, (dict, set)):
        return None
    cleaned = str(val).strip()
    return cleaned if cleaned else None


@dataclass(frozen=True)
class SplunkESTenantConfig:
    """Resolved Splunk ES tenant extraction and custom-field configuration."""

    tenant_field: str = "tenant_id"
    tenant_aliases: tuple[str, ...] = ("org_id", "client_code", "customer_id")
    custom_fields: tuple[str, ...] = ()

    @property
    def all_tenant_keys(self) -> tuple[str, ...]:
        """Ordered candidate field names starting with ``tenant_field``."""
        seen: set[str] = {self.tenant_field.casefold()}
        keys: list[str] = [self.tenant_field]
        for alias in self.tenant_aliases:
            low = alias.casefold()
            if low not in seen:
                seen.add(low)
                keys.append(alias)
        return tuple(keys)

    def extract_tenant(self, record: Mapping[str, Any]) -> str | None:
        """Extract tenant identifier case-insensitively across primary field and aliases."""
        containers: list[Mapping[str, Any]] = [record]
        for nested_key in ("fields", "event"):
            nested = record.get(nested_key)
            if isinstance(nested, Mapping):
                containers.append(nested)

        for candidate_key in self.all_tenant_keys:
            target = candidate_key.casefold()
            for container in containers:
                if candidate_key in container:
                    val = _extract_scalar_tenant(container[candidate_key])
                    if val is not None:
                        return val
                for rec_k, rec_v in container.items():
                    if isinstance(rec_k, str) and rec_k.casefold() == target:
                        val = _extract_scalar_tenant(rec_v)
                        if val is not None:
                            return val
        return None


DEFAULT_S1_TIER_RULES: tuple[tuple[str, str], ...] = (
    ("MDR", r"(?i)^mdr[-_]?([a-z0-9]+)"),
    ("MSSP", r"(?i)^mssp[-_]?([a-z0-9]+)"),
)
_COMPILED_DEFAULT_S1_TIER_RULES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (tier, re.compile(pattern)) for tier, pattern in DEFAULT_S1_TIER_RULES
)


@dataclass(frozen=True)
class S1TierConfig:
    """Resolved SentinelOne site tier classification and site-to-tenant mapping."""

    rules: tuple[tuple[str, re.Pattern[str]], ...] = _COMPILED_DEFAULT_S1_TIER_RULES
    site_tenant_map: dict[str, str] = field(default_factory=dict)
    default_tier: str = "Other"

    def classify_site(
        self,
        site_name: str,
        site_id: str | None = None,
    ) -> tuple[str, str | None, str | None]:
        """Classify ``site_name`` into ``(tier, site_code, tenant_id)``."""
        cleaned_name = site_name.strip()
        tier = self.default_tier
        site_code: str | None = None

        for rule_tier, pattern in self.rules:
            match = pattern.search(cleaned_name)
            if match is not None:
                tier = rule_tier
                if match.lastindex and match.lastindex >= 1:
                    raw_code = match.group(1)
                    if isinstance(raw_code, str) and raw_code.strip():
                        site_code = raw_code.strip()
                break

        lowered_map = {k.casefold(): v for k, v in self.site_tenant_map.items()}
        mapped_tenant: str | None = None
        candidates: list[str] = []
        if cleaned_name:
            candidates.append(cleaned_name)
        if site_id and site_id.strip():
            candidates.append(site_id.strip())
        if site_code:
            candidates.append(site_code)

        for cand in candidates:
            if cand in self.site_tenant_map:
                mapped_tenant = self.site_tenant_map[cand]
                break
            low = cand.casefold()
            if low in lowered_map:
                mapped_tenant = lowered_map[low]
                break

        tenant_id = mapped_tenant if mapped_tenant is not None else site_code
        return tier, site_code, tenant_id


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


def get_osint_config(
    *,
    enabled: bool | None = None,
    timeout: float | None = None,
    verify_ssl: bool | str | Path | None = None,
) -> OSINTConfig:
    """Resolve passive OSINT enrichment settings (explicit > session > env > saved > defaults)."""
    if enabled is not None:
        resolved_enabled = bool(enabled)
    else:
        raw_enabled = get_effective_setting("osint_enabled", include_default=True)
        resolved_enabled = (
            raw_enabled.strip().lower() not in _FALSY_VALUES
            if raw_enabled is not None
            else True
        )

    if timeout is not None:
        resolved_timeout = max(1.0, float(timeout))
    else:
        raw_timeout = get_effective_setting("osint_timeout", include_default=True)
        try:
            parsed_timeout = float(raw_timeout) if raw_timeout is not None else 8.0
            resolved_timeout = (
                parsed_timeout
                if math.isfinite(parsed_timeout) and parsed_timeout > 0
                else 8.0
            )
        except ValueError:
            resolved_timeout = 8.0

    resolved_verify = (
        parse_ssl_verify(verify_ssl, default=True)
        if verify_ssl is not None
        else get_rf_verify_ssl()
    )

    return OSINTConfig(
        enabled=resolved_enabled,
        timeout=resolved_timeout,
        verify_ssl=resolved_verify,
        vt_api_key=_clean_optional_str(get_effective_setting("osint_vt_api_key")),
        abuseipdb_api_key=_clean_optional_str(get_effective_setting("osint_abuseipdb_api_key")),
        abusech_api_key=_clean_optional_str(get_effective_setting("osint_abusech_api_key")),
        otx_api_key=_clean_optional_str(get_effective_setting("osint_otx_api_key")),
        urlscan_api_key=_clean_optional_str(get_effective_setting("osint_urlscan_api_key")),
        greynoise_api_key=_clean_optional_str(get_effective_setting("osint_greynoise_api_key")),
    )


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
    aliases = {
        "openai-compatible": "openai",
        "openai_compatible": "openai",
        "copilot": "m365_copilot",
        "m365": "m365_copilot",
        "m365-copilot": "m365_copilot",
        "enterprise_copilot": "m365_copilot",
        "directline": "copilot_directline",
        "copilot-directline": "copilot_directline",
        "copilot_studio": "copilot_studio",
        "copilot-studio": "copilot_studio",
        "d2e": "copilot_studio",
        "security-copilot": "security_copilot",
        "sec_copilot": "security_copilot",
        "secops": "security_copilot",
    }
    cleaned = aliases.get(cleaned, cleaned)
    if cleaned not in SUPPORTED_LLM_PROVIDERS:
        raise ConfigurationError(
            f"Unsupported LLM provider '{raw_provider}'. "
            f"Expected one of: {', '.join(sorted(SUPPORTED_LLM_PROVIDERS))}."
        )
    return cleaned


def parse_copilot_agent_presets(raw: str | Sequence[Mapping[str, Any]] | None) -> tuple[CopilotAgentPreset, ...]:
    """Parse ``ms_copilot_agents_json`` into validated ``CopilotAgentPreset`` entries."""
    if raw is None:
        return ()
    data: Any
    if isinstance(raw, str):
        cleaned = raw.strip()
        if not cleaned:
            return ()
        try:
            data = json.loads(cleaned)
        except ValueError as exc:
            raise ConfigurationError(
                f"Invalid JSON in ms_copilot_agents_json: {exc}"
            ) from exc
    else:
        data = raw

    items: list[Mapping[str, Any]] = []
    if isinstance(data, dict):
        # Allow {"Agent Name": "https://token-endpoint..." or {config dict}}
        for name, val in data.items():
            clean_name = str(name).strip()
            if not clean_name:
                continue
            if isinstance(val, str):
                items.append(
                    {
                        "name": clean_name,
                        "provider": "copilot_directline",
                        "token_endpoint": val.strip(),
                    }
                )
            elif isinstance(val, Mapping):
                entry = dict(val)
                entry.setdefault("name", clean_name)
                items.append(entry)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, Mapping):
                items.append(item)
    else:
        raise ConfigurationError(
            "ms_copilot_agents_json must be a JSON array of agent objects or a JSON object map."
        )

    presets: list[CopilotAgentPreset] = []
    seen: set[str] = set()
    for item in items:
        name = _clean_optional_str(str(item.get("name") or ""))
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        prov = _normalize_llm_provider(
            _clean_optional_str(str(item.get("provider") or "")) or "m365_copilot"
        )
        raw_wg = item.get("web_grounding")
        web_grounding: bool | None = None
        if isinstance(raw_wg, bool):
            web_grounding = raw_wg
        elif isinstance(raw_wg, str) and raw_wg.strip():
            web_grounding = raw_wg.strip().lower() in ("1", "true", "yes", "on")
        presets.append(
            CopilotAgentPreset(
                name=name,
                provider=prov,
                model=_clean_optional_str(
                    str(item["model"]) if item.get("model") is not None else None
                ),
                base_url=_clean_optional_str(
                    str(item["base_url"]) if item.get("base_url") is not None else None
                ),
                token_endpoint=_clean_optional_str(
                    str(item["token_endpoint"]) if item.get("token_endpoint") is not None else None
                ),
                directline_secret=_clean_optional_str(
                    str(item["directline_secret"])
                    if item.get("directline_secret") is not None
                    else None
                ),
                bearer_token=_clean_optional_str(
                    str(item["bearer_token"]) if item.get("bearer_token") is not None else None
                ),
                workspace=_clean_optional_str(
                    str(item["workspace"]) if item.get("workspace") is not None else None
                ),
                web_grounding=web_grounding,
            )
        )
    return tuple(presets)


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


def parse_visible_llm_providers(raw: str | Sequence[str] | None) -> tuple[str, ...]:
    """Parse ``llm_visible_providers`` into an ordered tuple of normalized provider keys."""
    if raw is None:
        return ()
    tokens: list[str]
    if isinstance(raw, str):
        cleaned = raw.strip()
        if not cleaned or cleaned.lower() == "all":
            return ()
        tokens = [part.strip() for part in cleaned.split(",") if part.strip()]
    else:
        tokens = [str(part).strip() for part in raw if str(part).strip()]
    resolved: list[str] = []
    for tok in tokens:
        try:
            norm = _normalize_llm_provider(tok)
        except ConfigurationError:
            continue
        if norm not in resolved:
            resolved.append(norm)
    return tuple(resolved)


def get_local_llm_config(
    provider: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    timeout: float | str | None = None,
    verify_ssl: bool | str | Path | None = None,
    temperature: float | str | None = None,
    max_tokens: int | str | None = None,
    *,
    ms_auth_mode: str | None = None,
    ms_bearer_token: str | None = None,
    ms_graph_base_url: str | None = None,
    ms_web_grounding: bool | str | None = None,
    ms_directline_url: str | None = None,
    ms_token_endpoint: str | None = None,
    ms_directline_secret: str | None = None,
    ms_security_workspace: str | None = None,
    ms_security_poll_interval: float | str | None = None,
    agent_presets: str | Sequence[Mapping[str, Any]] | tuple[CopilotAgentPreset, ...] | None = None,
) -> LocalLLMConfig:
    """Load AI analyst configuration from explicit arguments, environment variables, or settings.

    Supports ``ollama``, ``openai``, ``m365_copilot``, ``copilot_directline``,
    and ``security_copilot``.
    """
    resolved_visible = parse_visible_llm_providers(get_effective_setting("llm_visible_providers"))
    raw_provider = provider if provider is not None else os.environ.get("RF_LLM_PROVIDER")
    if not _clean_optional_str(raw_provider) and resolved_visible:
        resolved_provider = resolved_visible[0]
    else:
        resolved_provider = _normalize_llm_provider(raw_provider)

    resolved_graph_url = (
        _clean_optional_str(ms_graph_base_url)
        or get_effective_setting("ms_copilot_graph_base_url")
        or DEFAULT_M365_COPILOT_GRAPH_URL
    ).rstrip("/")
    resolved_dl_url = (
        _clean_optional_str(ms_directline_url)
        or get_effective_setting("ms_copilot_directline_url")
        or DEFAULT_COPILOT_DIRECTLINE_URL
    ).rstrip("/")

    if resolved_provider == "openai":
        default_url = DEFAULT_OPENAI_BASE_URL
    elif resolved_provider in ("m365_copilot", "security_copilot"):
        default_url = resolved_graph_url
    elif resolved_provider == "copilot_studio":
        default_url = get_effective_setting("ms_copilot_token_endpoint") or ""
    elif resolved_provider == "copilot_directline":
        default_url = resolved_dl_url
    else:
        default_url = DEFAULT_OLLAMA_BASE_URL

    env_base_url = (
        _clean_optional_str(os.environ.get("RF_LLM_BASE_URL"))
        if resolved_provider in ("ollama", "openai")
        else None
    )
    raw_url = _clean_optional_str(base_url) or env_base_url or default_url
    if raw_url and not raw_url.lower().startswith(("http://", "https://")):
        scheme = "https://" if resolved_provider in COPILOT_LLM_PROVIDERS else "http://"
        raw_url = f"{scheme}{raw_url}"
    normalized_url = raw_url.rstrip("/")

    resolved_model = _clean_optional_str(
        model if model is not None else os.environ.get("RF_LLM_MODEL")
    )
    resolved_api_key = (
        _clean_optional_str(api_key)
        if api_key is not None
        else get_effective_setting("rf_llm_api_key")
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

    raw_auth_mode = (
        _clean_optional_str(ms_auth_mode)
        if ms_auth_mode is not None
        else get_effective_setting("ms_copilot_auth_mode")
    )
    resolved_auth_mode = (raw_auth_mode or "token").strip().lower()
    if resolved_auth_mode not in MS_COPILOT_AUTH_MODES:
        raise ConfigurationError(
            f"Unsupported ms_copilot_auth_mode '{resolved_auth_mode}'. "
            f"Expected one of: {', '.join(MS_COPILOT_AUTH_MODES)}."
        )

    resolved_ms_token = (
        _clean_optional_str(ms_bearer_token)
        if ms_bearer_token is not None
        else get_effective_setting("ms_copilot_bearer_token")
    )
    resolved_token_endpoint = (
        _clean_optional_str(ms_token_endpoint)
        if ms_token_endpoint is not None
        else get_effective_setting("ms_copilot_token_endpoint")
    )
    resolved_dl_secret = (
        _clean_optional_str(ms_directline_secret)
        if ms_directline_secret is not None
        else get_effective_setting("ms_copilot_directline_secret")
    )
    resolved_sec_ws = (
        _clean_optional_str(ms_security_workspace)
        if ms_security_workspace is not None
        else get_effective_setting("ms_security_copilot_workspace")
    ) or "default"

    raw_poll = (
        ms_security_poll_interval
        if ms_security_poll_interval is not None
        else get_effective_setting("ms_security_copilot_poll_interval")
    )
    resolved_poll = _parse_positive_float(
        raw_poll, default=2.0, name="SOCLENS_MS_SECURITY_COPILOT_POLL_INTERVAL"
    )

    if isinstance(ms_web_grounding, bool):
        resolved_web_grounding = ms_web_grounding
    else:
        raw_wg = (
            ms_web_grounding
            if ms_web_grounding is not None
            else get_effective_setting("ms_copilot_web_grounding")
        )
        resolved_web_grounding = (
            True
            if raw_wg is None or not str(raw_wg).strip()
            else str(raw_wg).strip().lower() in ("1", "true", "yes", "on")
        )

    resolved_presets: tuple[CopilotAgentPreset, ...]
    if isinstance(agent_presets, tuple) and all(
        isinstance(p, CopilotAgentPreset) for p in agent_presets
    ):
        resolved_presets = agent_presets
    elif agent_presets is not None:
        resolved_presets = parse_copilot_agent_presets(agent_presets)  # type: ignore[arg-type]
    else:
        try:
            resolved_presets = parse_copilot_agent_presets(
                get_effective_setting("ms_copilot_agents_json")
            )
        except ConfigurationError:
            resolved_presets = ()

    return LocalLLMConfig(
        provider=resolved_provider,
        base_url=normalized_url,
        model=resolved_model,
        api_key=resolved_api_key,
        timeout=resolved_timeout,
        verify_ssl=resolved_verify,
        temperature=resolved_temp,
        max_tokens=resolved_max_tokens,
        ms_auth_mode=resolved_auth_mode,
        ms_bearer_token=resolved_ms_token,
        ms_graph_base_url=resolved_graph_url,
        ms_web_grounding=resolved_web_grounding,
        ms_directline_url=resolved_dl_url,
        ms_token_endpoint=resolved_token_endpoint,
        ms_directline_secret=resolved_dl_secret,
        ms_security_workspace=resolved_sec_ws,
        ms_security_poll_interval=resolved_poll,
        agent_presets=resolved_presets,
        visible_providers=resolved_visible,
    )


def _normalize_optional_url(value: str | None, *, default: str = "") -> str:
    cleaned = _clean_optional_str(value)
    if cleaned is None:
        return default
    return cleaned.rstrip("/")


def get_secret_store_config(
    *,
    provider: str | None = None,
    verify_ssl: bool | str | Path | None = None,
    timeout: float | str | None = None,
    secret_map: str | Mapping[str, str] | None = None,
    tss_base_url: str | None = None,
    tss_auth_mode: str | None = None,
    tss_username: str | None = None,
    tss_password: str | None = None,
    tss_domain: str | None = None,
    tss_client_id: str | None = None,
    tss_client_secret: str | None = None,
    tss_access_token: str | None = None,
    tss_platform_url: str | None = None,
    tss_folder_id: str | None = None,
    tss_api_version: str | None = None,
    tss_auto_comment: str | None = None,
    vault_addr: str | None = None,
    vault_auth_mode: str | None = None,
    vault_token: str | None = None,
    vault_role_id: str | None = None,
    vault_secret_id: str | None = None,
    vault_auth_mount: str | None = None,
    vault_kv_mount: str | None = None,
    vault_namespace: str | None = None,
    vault_prefix: str | None = None,
    op_connect_url: str | None = None,
    op_connect_token: str | None = None,
    op_vault_id: str | None = None,
    bw_serve_url: str | None = None,
    bw_master_password: str | None = None,
    bw_folder_id: str | None = None,
    bw_collection_id: str | None = None,
    bw_organization_id: str | None = None,
    akeyless_api_url: str | None = None,
    akeyless_auth_mode: str | None = None,
    akeyless_access_id: str | None = None,
    akeyless_access_key: str | None = None,
    akeyless_token: str | None = None,
    akeyless_prefix: str | None = None,
) -> SecretStoreConfig:
    """Resolve Secret Manager / PAM configuration from args, session, env, or saved settings."""
    raw_provider = (
        _clean_optional_str(provider)
        if provider is not None
        else get_effective_setting("secret_provider", include_default=True)
    )
    resolved_provider = (raw_provider or "none").strip().lower()
    if resolved_provider not in SUPPORTED_SECRET_PROVIDERS:
        valid = ", ".join(SUPPORTED_SECRET_PROVIDERS)
        raise ConfigurationError(
            f"Unsupported secret store provider {raw_provider!r}. Expected one of: {valid}."
        )

    if verify_ssl is not None:
        resolved_verify: bool | str = parse_ssl_verify(verify_ssl, default=True)
    else:
        configured_verify = get_effective_setting("secret_store_verify_ssl")
        if configured_verify is not None:
            resolved_verify = parse_ssl_verify(configured_verify, default=True)
        else:
            resolved_verify = get_rf_verify_ssl()

    raw_timeout: float | str | None = (
        timeout
        if timeout is not None
        else get_effective_setting("secret_store_timeout", include_default=True)
    )
    resolved_timeout = _parse_positive_float(
        raw_timeout,
        default=15.0,
        name="SOCLENS_SECRET_STORE_TIMEOUT",
    )

    raw_secret_map: str | Mapping[str, str] | None = (
        secret_map if secret_map is not None else get_effective_setting("vault_secret_map")
    )
    try:
        resolved_secret_map = parse_vault_secret_map(raw_secret_map, strict=False)
    except ValueError as exc:
        raise ConfigurationError(f"Invalid vault_secret_map: {exc}") from exc

    raw_tss_auth_mode = (
        _clean_optional_str(tss_auth_mode)
        if tss_auth_mode is not None
        else get_effective_setting("tss_auth_mode", include_default=True)
    )
    resolved_tss_auth_mode = (raw_tss_auth_mode or "password").strip().lower()
    if resolved_tss_auth_mode not in TSS_AUTH_MODES:
        valid = ", ".join(TSS_AUTH_MODES)
        raise ConfigurationError(
            f"Invalid Secret Server auth mode {raw_tss_auth_mode!r}. Expected one of: {valid}."
        )

    raw_tss_api_ver = (
        _clean_optional_str(tss_api_version)
        if tss_api_version is not None
        else _clean_optional_str(os.environ.get("TSS_API_VERSION"))
    )
    resolved_tss_api_ver = (raw_tss_api_ver or "v1").strip().lower()
    if resolved_tss_api_ver not in {"v1", "v2"}:
        raise ConfigurationError(
            f"Invalid Secret Server API version {raw_tss_api_ver!r}. Expected 'v1' or 'v2'."
        )

    resolved_tss_auto_comment = (
        _clean_optional_str(tss_auto_comment)
        if tss_auto_comment is not None
        else _clean_optional_str(os.environ.get("TSS_AUTO_COMMENT"))
    )

    raw_vault_auth_mode = (
        _clean_optional_str(vault_auth_mode)
        if vault_auth_mode is not None
        else get_effective_setting("vault_auth_mode", include_default=True)
    )
    resolved_vault_auth_mode = (raw_vault_auth_mode or "token").strip().lower()
    if resolved_vault_auth_mode not in VAULT_AUTH_MODES:
        valid = ", ".join(VAULT_AUTH_MODES)
        raise ConfigurationError(
            f"Invalid Vault auth mode {raw_vault_auth_mode!r}. Expected one of: {valid}."
        )

    raw_akeyless_auth_mode = (
        _clean_optional_str(akeyless_auth_mode)
        if akeyless_auth_mode is not None
        else get_effective_setting("akeyless_auth_mode", include_default=True)
    )
    resolved_akeyless_auth_mode = (raw_akeyless_auth_mode or "access_key").strip().lower()
    if resolved_akeyless_auth_mode not in AKEYLESS_AUTH_MODES:
        valid = ", ".join(AKEYLESS_AUTH_MODES)
        raise ConfigurationError(
            f"Invalid Akeyless auth mode {raw_akeyless_auth_mode!r}. Expected one of: {valid}."
        )

    def _opt(explicit_val: str | None, key: str, *, include_default: bool = False) -> str | None:
        if explicit_val is not None:
            return _clean_optional_str(explicit_val)
        return get_effective_setting(key, include_default=include_default)

    return SecretStoreConfig(
        provider=resolved_provider,
        verify_ssl=resolved_verify,
        timeout=resolved_timeout,
        secret_map=resolved_secret_map,
        tss_base_url=_normalize_optional_url(_opt(tss_base_url, "tss_base_url")),
        tss_auth_mode=resolved_tss_auth_mode,
        tss_username=_opt(tss_username, "tss_username"),
        tss_password=_opt(tss_password, "tss_password"),
        tss_domain=_opt(tss_domain, "tss_domain"),
        tss_client_id=_opt(tss_client_id, "tss_client_id"),
        tss_client_secret=_opt(tss_client_secret, "tss_client_secret"),
        tss_access_token=_opt(tss_access_token, "tss_access_token"),
        tss_platform_url=_normalize_optional_url(_opt(tss_platform_url, "tss_platform_url")),
        tss_folder_id=_opt(tss_folder_id, "tss_folder_id"),
        tss_api_version=resolved_tss_api_ver,
        tss_auto_comment=resolved_tss_auto_comment,
        vault_addr=_normalize_optional_url(_opt(vault_addr, "vault_addr")),
        vault_auth_mode=resolved_vault_auth_mode,
        vault_token=_opt(vault_token, "vault_token"),
        vault_role_id=_opt(vault_role_id, "vault_role_id"),
        vault_secret_id=_opt(vault_secret_id, "vault_secret_id"),
        vault_auth_mount=(_opt(vault_auth_mount, "vault_auth_mount", include_default=True) or "approle").strip("/"),
        vault_kv_mount=(_opt(vault_kv_mount, "vault_kv_mount", include_default=True) or "secret").strip("/"),
        vault_namespace=_opt(vault_namespace, "vault_namespace"),
        vault_prefix=_opt(vault_prefix, "vault_prefix"),
        op_connect_url=_normalize_optional_url(_opt(op_connect_url, "op_connect_url")),
        op_connect_token=_opt(op_connect_token, "op_connect_token"),
        op_vault_id=_opt(op_vault_id, "op_vault_id"),
        bw_serve_url=_normalize_optional_url(
            _opt(bw_serve_url, "bw_serve_url", include_default=True),
            default="http://127.0.0.1:8087",
        ),
        bw_master_password=_opt(bw_master_password, "bw_master_password"),
        bw_folder_id=_opt(bw_folder_id, "bw_folder_id"),
        bw_collection_id=_opt(bw_collection_id, "bw_collection_id"),
        bw_organization_id=_opt(bw_organization_id, "bw_organization_id"),
        akeyless_api_url=_normalize_optional_url(
            _opt(akeyless_api_url, "akeyless_api_url", include_default=True),
            default="https://api.akeyless.io",
        ),
        akeyless_auth_mode=resolved_akeyless_auth_mode,
        akeyless_access_id=_opt(akeyless_access_id, "akeyless_access_id"),
        akeyless_access_key=_opt(akeyless_access_key, "akeyless_access_key"),
        akeyless_token=_opt(akeyless_token, "akeyless_token"),
        akeyless_prefix=_opt(akeyless_prefix, "akeyless_prefix"),
    )


def hydrate_secrets_from_store(
    *,
    force: bool = False,
    overwrite_existing: bool = False,
    stop_event: threading.Event | None = None,
) -> dict[str, str]:
    """Pull mapped secrets into process-local session overrides without writing to disk.

    Preserves environment variable precedence when ``overwrite_existing=False``.
    Returns ``{setting_key: masked_secret_value}``.
    """
    cfg = get_secret_store_config()
    if not cfg.is_enabled or not cfg.secret_map:
        return {}
    if stop_event is not None and stop_event.is_set():
        return {}

    target_map: dict[str, str] = {}
    for setting_key, ref in cfg.secret_map.items():
        if setting_key not in SECRET_MANAGED_SETTING_KEYS:
            continue
        if not overwrite_existing and get_env_override_for_setting(setting_key) is not None:
            continue
        if not force:
            has_sess, sess_val = get_session_override(setting_key)
            if has_sess and sess_val is not None:
                continue
        target_map[setting_key] = ref

    if not target_map:
        return {}
    if stop_event is not None and stop_event.is_set():
        return {}

    from soclens.secret_stores import build_secret_store_provider

    with build_secret_store_provider(cfg, stop_event=stop_event) as provider:
        resolved = provider.resolve_mapped_settings(target_map)

    to_apply: dict[str, str] = {}
    for setting_key, secret_val in resolved.items():
        if setting_key not in SECRET_MANAGED_SETTING_KEYS:
            continue
        cleaned = _clean_optional_str(secret_val)
        if cleaned is None:
            continue
        if not overwrite_existing and get_env_override_for_setting(setting_key) is not None:
            continue
        to_apply[setting_key] = cleaned

    if to_apply:
        set_session_overrides(to_apply, vault_hydrated=True)

    return {k: mask_secret(v) for k, v in to_apply.items()}


def _parse_field_list(raw: str | Sequence[str] | None) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return ()
        if stripped.startswith("["):
            try:
                loaded: Any = json.loads(stripped)
            except ValueError:
                loaded = None
            if isinstance(loaded, list):
                return tuple(str(item).strip() for item in loaded if str(item).strip())
        return tuple(part.strip() for part in stripped.split(",") if part.strip())
    return tuple(str(item).strip() for item in raw if str(item).strip())


def get_splunk_es_tenant_settings(
    *,
    tenant_field: str | None = None,
    tenant_aliases: str | Sequence[str] | None = None,
    custom_fields: str | Sequence[str] | None = None,
) -> SplunkESTenantConfig:
    """Resolve Splunk ES tenant extraction and pinned custom-field settings."""
    resolved_field = (
        _clean_optional_str(tenant_field)
        or get_effective_setting("splunk_es_tenant_field")
        or get_effective_setting("soclens_tenant_field")
        or "tenant_id"
    )
    resolved_aliases = (
        _parse_field_list(tenant_aliases)
        if tenant_aliases is not None
        else _parse_field_list(
            get_effective_setting("splunk_es_tenant_aliases", include_default=True)
        )
    )
    if not resolved_aliases and tenant_aliases is None:
        resolved_aliases = ("org_id", "client_code", "customer_id")

    resolved_custom = (
        _parse_field_list(custom_fields)
        if custom_fields is not None
        else _parse_field_list(get_effective_setting("splunk_es_custom_fields"))
    )

    return SplunkESTenantConfig(
        tenant_field=resolved_field,
        tenant_aliases=resolved_aliases,
        custom_fields=resolved_custom,
    )


def get_s1_tier_config(
    *,
    tier_rules: str | Sequence[Any] | Mapping[str, Any] | None = None,
    site_tenant_map: str | Mapping[str, Any] | None = None,
) -> S1TierConfig:
    """Resolve SentinelOne site tier rules and site-to-tenant override mapping."""
    raw_rules: str | Sequence[Any] | Mapping[str, Any] | None = (
        tier_rules if tier_rules is not None else get_effective_setting("s1_tier_rules")
    )
    try:
        parsed_rules = parse_s1_tier_rules(raw_rules)
    except ValueError as exc:
        raise ConfigurationError(f"Invalid s1_tier_rules: {exc}") from exc

    compiled_rules = tuple(parsed_rules) if parsed_rules else _COMPILED_DEFAULT_S1_TIER_RULES

    raw_map: str | Mapping[str, Any] | None = (
        site_tenant_map
        if site_tenant_map is not None
        else get_effective_setting("s1_site_tenant_map")
    )
    try:
        parsed_map = parse_s1_site_tenant_map(raw_map)
    except ValueError as exc:
        raise ConfigurationError(f"Invalid s1_site_tenant_map: {exc}") from exc

    return S1TierConfig(rules=compiled_rules, site_tenant_map=parsed_map)


def classify_site_tier(
    site_name: str,
    *,
    site_id: str | None = None,
    tier_rules: str | Sequence[Any] | Mapping[str, Any] | None = None,
    site_tenant_map: str | Mapping[str, Any] | None = None,
) -> tuple[str, str | None]:
    """Classify an S1 ``siteName`` into ``(tier, tenant_id)``."""
    cfg = get_s1_tier_config(tier_rules=tier_rules, site_tenant_map=site_tenant_map)
    tier, _site_code, tenant_id = cfg.classify_site(site_name, site_id=site_id)
    return tier, tenant_id


def extract_tenant_from_site_name(
    site_name: str,
    *,
    site_id: str | None = None,
    tier_rules: str | Sequence[Any] | Mapping[str, Any] | None = None,
    site_tenant_map: str | Mapping[str, Any] | None = None,
) -> str | None:
    """Return the mapped or regex-extracted ``tenant_id`` for an S1 site name."""
    _tier, tenant_id = classify_site_tier(
        site_name,
        site_id=site_id,
        tier_rules=tier_rules,
        site_tenant_map=site_tenant_map,
    )
    return tenant_id


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
