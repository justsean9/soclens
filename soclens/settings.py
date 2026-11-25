"""Cross-platform per-user settings storage, named profiles, and credential registry."""

from __future__ import annotations

import copy
import json
import logging
import math
import os
import re
import stat
import sys
import tempfile
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from soclens.settings_crypto import (
    ENCRYPTED_SETTINGS_CIPHER,
    ENCRYPTED_SETTINGS_SCHEMA_VERSION,
    ENCRYPTION_MODE_OS_KEYSTORE,
    ENCRYPTION_MODE_PASSPHRASE,
    MIN_PASSPHRASE_LENGTH,
    SUPPORTED_ENCRYPTION_MODES,
    SettingsCryptoError,
    SettingsDecryptionError,
    SettingsKeystoreError,
    SettingsLockedError,
    clear_unlocked_keys,
    decrypt_settings_envelope,
    encrypt_settings_payload,
    get_env_passphrase,
    inspect_settings_file_encryption,
    is_encrypted_envelope,
)

logger = logging.getLogger("soclens.settings")

APP_CONFIG_DIR_NAME = "soclens"
SETTINGS_FILENAME = "settings.json"
SETTINGS_SCHEMA_VERSION = ENCRYPTED_SETTINGS_SCHEMA_VERSION
DEFAULT_PROFILE = "default"

_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_TRUTHY_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on"})
_FALSY_VALUES: frozenset[str] = frozenset({"0", "false", "no", "off"})

# Test hook allowing pytest fixtures to redirect default user settings cleanly even
# when os.environ is cleared by patch.dict(os.environ, {}, clear=True).
_DEFAULT_SETTINGS_PATH_OVERRIDE: Path | None = None

_STORE_LOCK = threading.RLock()
_CACHE: dict[Path, tuple[tuple[int, int] | None, dict[str, Any], str | None]] = {}
_LAST_ERRORS: dict[Path, str] = {}

_SESSION_LOCK = threading.RLock()
_SESSION_OVERRIDES: dict[str, str | None] = {}
_VAULT_HYDRATED_KEYS: set[str] = set()


@dataclass(frozen=True)
class SettingSpec:
    """Metadata describing a configurable user setting and its env var aliases."""

    key: str
    category: str
    label: str
    env_vars: tuple[str, ...]
    secret: bool = False
    value_type: str = "str"
    default: str | None = None
    mask_url_credentials: bool = False
    description: str = ""
    choices: tuple[str, ...] = ()


SUPPORTED_SECRET_PROVIDERS: tuple[str, ...] = (
    "none",
    "secret_server",
    "hashicorp_vault",
    "onepassword_connect",
    "bitwarden",
)
TSS_AUTH_MODES: tuple[str, ...] = ("password", "platform", "token")
VAULT_AUTH_MODES: tuple[str, ...] = ("token", "approle")
SECRET_MANAGED_SETTING_KEYS: tuple[str, ...] = (
    "rf_api_token",
    "rf_sandbox_token",
    "rf_asi_api_key",
    "rf_pfi_token",
    "rf_riskrecon_token",
    "splunk_token",
    "splunk_username",
    "splunk_password",
    "s1_api_token",
    "rf_llm_api_key",
)


SETTING_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("recorded_future", "Recorded Future API"),
    ("splunk", "Splunk & Splunk ES"),
    ("sentinelone", "SentinelOne EDR"),
    ("network", "Network, SSL & Proxy"),
    ("workspace", "Workspace & Tool Defaults"),
    ("secret_manager", "Secret Manager (PAM / Vault)"),
    ("osint", "OSINT Enrichment APIs"),
)

SETTING_SPECS: tuple[SettingSpec, ...] = (
    # Recorded Future API
    SettingSpec(
        key="rf_api_token",
        category="recorded_future",
        label="RF Core API Token",
        env_vars=("RF_API_TOKEN", "RECORDED_FUTURE_API_KEY"),
        secret=True,
        description="Primary Recorded Future API token (X-RFToken).",
    ),
    SettingSpec(
        key="rf_sandbox_token",
        category="recorded_future",
        label="RF Sandbox Token",
        env_vars=("RF_SANDBOX_TOKEN",),
        secret=True,
        description="Optional Recorded Future Sandbox token (falls back to Core token).",
    ),
    SettingSpec(
        key="rf_asi_api_key",
        category="recorded_future",
        label="RF ASI / SecurityTrails API Key",
        env_vars=("RF_ASI_API_KEY", "SECURITYTRAILS_API_KEY"),
        secret=True,
        description="Optional Attack Surface Intelligence API key.",
    ),
    SettingSpec(
        key="rf_pfi_token",
        category="recorded_future",
        label="RF Payment Fraud (PFI) Token",
        env_vars=("RF_PFI_TOKEN",),
        secret=True,
        description="Optional Payment Fraud Intelligence token (falls back to Core token).",
    ),
    SettingSpec(
        key="rf_riskrecon_token",
        category="recorded_future",
        label="RF RiskRecon API Token",
        env_vars=("RF_RISKRECON_TOKEN", "RISKRECON_API_TOKEN"),
        secret=True,
        description="Optional RiskRecon third-party posture API bearer token.",
    ),
    SettingSpec(
        key="rf_base_url",
        category="recorded_future",
        label="RF Core Base URL",
        env_vars=("RF_BASE_URL",),
        value_type="url",
        default="https://api.recordedfuture.com",
        description="Base URL for Recorded Future Core REST APIs.",
    ),
    SettingSpec(
        key="rf_sandbox_base_url",
        category="recorded_future",
        label="RF Sandbox Base URL",
        env_vars=("RF_SANDBOX_BASE_URL",),
        value_type="url",
        default="https://sandbox.recordedfuture.com/api/v0",
        description="Base URL for Recorded Future Sandbox v0 API.",
    ),
    SettingSpec(
        key="rf_asi_base_url",
        category="recorded_future",
        label="RF ASI Base URL",
        env_vars=("RF_ASI_BASE_URL",),
        value_type="url",
        default="https://api.securitytrails.com/v2",
        description="Base URL for Attack Surface Intelligence API.",
    ),
    SettingSpec(
        key="rf_pfi_base_url",
        category="recorded_future",
        label="RF PFI Base URL",
        env_vars=("RF_PFI_BASE_URL",),
        value_type="url",
        default="https://pfi.regemini.com/api/v1",
        description="Base URL for Payment Fraud Intelligence API.",
    ),
    SettingSpec(
        key="rf_riskrecon_base_url",
        category="recorded_future",
        label="RF RiskRecon Base URL",
        env_vars=("RF_RISKRECON_BASE_URL",),
        value_type="url",
        default="https://api.riskrecon.com/v1",
        description="Base URL for RiskRecon API.",
    ),
    # Splunk & Splunk ES
    SettingSpec(
        key="splunk_host",
        category="splunk",
        label="Splunk Management Host",
        env_vars=("SPLUNK_HOST",),
        value_type="host_url",
        default="https://127.0.0.1:8089",
        description="Splunk management API URL (default port 8089).",
    ),
    SettingSpec(
        key="splunk_token",
        category="splunk",
        label="Splunk Bearer Token",
        env_vars=("SPLUNK_TOKEN",),
        secret=True,
        description="Preferred Splunk REST authentication token.",
    ),
    SettingSpec(
        key="splunk_username",
        category="splunk",
        label="Splunk Username",
        env_vars=("SPLUNK_USERNAME",),
        description="Splunk username (used when Bearer token is not set).",
    ),
    SettingSpec(
        key="splunk_password",
        category="splunk",
        label="Splunk Password",
        env_vars=("SPLUNK_PASSWORD",),
        secret=True,
        description="Splunk password paired with Splunk Username.",
    ),
    SettingSpec(
        key="splunk_app",
        category="splunk",
        label="Splunk App Namespace",
        env_vars=("SPLUNK_APP",),
        default="SplunkEnterpriseSecuritySuite",
        description="Target Splunk app context for saved searches.",
    ),
    SettingSpec(
        key="splunk_verify_ssl",
        category="splunk",
        label="Splunk SSL Verification",
        env_vars=("SPLUNK_VERIFY_SSL",),
        value_type="ssl_verify",
        default="false",
        description="true, false, or path to a custom CA bundle PEM file.",
    ),
    SettingSpec(
        key="splunk_es_tenant_field",
        category="splunk",
        label="Splunk ES Tenant Field",
        env_vars=("SPLUNK_ES_TENANT_FIELD",),
        default="tenant_id",
        description="Primary field name for tenant extraction on ES notables (inherits soclens_tenant_field).",
    ),
    SettingSpec(
        key="splunk_es_tenant_aliases",
        category="splunk",
        label="Splunk ES Tenant Aliases",
        env_vars=("SPLUNK_ES_TENANT_ALIASES",),
        default="org_id,client_code,customer_id",
        description="Fallback tenant field aliases (CSV or JSON list) checked case-insensitively.",
    ),
    SettingSpec(
        key="splunk_es_custom_fields",
        category="splunk",
        label="Splunk ES Custom Fields",
        env_vars=("SPLUNK_ES_CUSTOM_FIELDS",),
        description="Optional CSV or JSON list of pinned custom ES notable fields.",
    ),
    SettingSpec(
        key="splunk_es_saved_views",
        category="splunk",
        label="Splunk ES Saved Views",
        env_vars=("SPLUNK_ES_SAVED_VIEWS",),
        description="Single-line JSON array or object storing custom Splunk ES queue views.",
    ),
    # SentinelOne EDR
    SettingSpec(
        key="s1_console_url",
        category="sentinelone",
        label="SentinelOne Console URL",
        env_vars=("S1_CONSOLE_URL", "SENTINELONE_URL"),
        value_type="host_url",
        description="SentinelOne management console URL (e.g. https://tenant.sentinelone.net).",
    ),
    SettingSpec(
        key="s1_api_token",
        category="sentinelone",
        label="SentinelOne API Token",
        env_vars=("S1_API_TOKEN", "SENTINELONE_API_TOKEN"),
        secret=True,
        description="SentinelOne Management API v2.1 API token.",
    ),
    SettingSpec(
        key="s1_account_id",
        category="sentinelone",
        label="SentinelOne Account ID",
        env_vars=("S1_ACCOUNT_ID",),
        description="Optional default SentinelOne account ID filter.",
    ),
    SettingSpec(
        key="s1_site_id",
        category="sentinelone",
        label="SentinelOne Site ID",
        env_vars=("S1_SITE_ID",),
        description="Optional default SentinelOne site ID filter.",
    ),
    SettingSpec(
        key="s1_verify_ssl",
        category="sentinelone",
        label="SentinelOne SSL Verification",
        env_vars=("S1_VERIFY_SSL",),
        value_type="ssl_verify",
        description="true, false, CA bundle path, or leave blank to inherit RF SSL setting.",
    ),
    SettingSpec(
        key="s1_timeout",
        category="sentinelone",
        label="SentinelOne Timeout (sec)",
        env_vars=("S1_TIMEOUT",),
        value_type="float",
        default="30.0",
        description="Request timeout in seconds for SentinelOne API calls.",
    ),
    SettingSpec(
        key="s1_tier_rules",
        category="sentinelone",
        label="SentinelOne Site Tier Rules",
        env_vars=("S1_TIER_RULES",),
        description="Optional single-line JSON mapping/list of tier regex rules (default MDR-*, MSSP-*).",
    ),
    SettingSpec(
        key="s1_site_tenant_map",
        category="sentinelone",
        label="SentinelOne Site-Tenant Map",
        env_vars=("S1_SITE_TENANT_MAP",),
        description="Optional single-line JSON mapping of site name/code/ID to tenant_id.",
    ),
    # Network, SSL & Proxy
    SettingSpec(
        key="rf_verify_ssl",
        category="network",
        label="RF & Web SSL Verification",
        env_vars=("RF_VERIFY_SSL", "RF_INSECURE_SSL", "SOCLENS_INSECURE_SSL"),
        value_type="ssl_verify",
        default="true",
        description="true (verify certificates), false (insecure proxy mode), or CA path.",
    ),
    SettingSpec(
        key="rf_ca_bundle",
        category="network",
        label="Custom CA Bundle Path",
        env_vars=("RF_CA_BUNDLE",),
        value_type="path",
        description="Path to PEM CA certificate bundle for corporate SSL inspection.",
    ),
    SettingSpec(
        key="https_proxy",
        category="network",
        label="HTTPS Proxy URL",
        env_vars=("HTTPS_PROXY", "https_proxy"),
        value_type="url",
        mask_url_credentials=True,
        description="HTTPS proxy URL (e.g. http://proxy.corp:8080).",
    ),
    SettingSpec(
        key="http_proxy",
        category="network",
        label="HTTP Proxy URL",
        env_vars=("HTTP_PROXY", "http_proxy"),
        value_type="url",
        mask_url_credentials=True,
        description="HTTP proxy URL (e.g. http://proxy.corp:8080).",
    ),
    SettingSpec(
        key="no_proxy",
        category="network",
        label="No-Proxy Hosts / CIDRs",
        env_vars=("NO_PROXY", "no_proxy"),
        description="Comma-separated hosts/domains bypassing proxy (e.g. localhost,127.0.0.1).",
    ),
    # Workspace & Tool Defaults
    SettingSpec(
        key="soclens_home",
        category="workspace",
        label="SOC Workspace Directory",
        env_vars=("SOCLENS_HOME",),
        value_type="path",
        description="Default workspace directory for caches, state, and logs (blank = CWD).",
    ),
    SettingSpec(
        key="rf_tui_image_protocol",
        category="workspace",
        label="TUI Image Protocol",
        env_vars=("RF_TUI_IMAGE_PROTOCOL",),
        description="auto (blank), kitty, iterm2, sixel, or halfblock.",
    ),
    SettingSpec(
        key="soclens_default_table_fields",
        category="workspace",
        label="Sigma Default Table Fields",
        env_vars=("SOCLENS_DEFAULT_TABLE_FIELDS",),
        description="Default Splunk | table fields injected during Sigma conversion.",
    ),
    SettingSpec(
        key="soclens_default_suppress_fields",
        category="workspace",
        label="Sigma Default Suppress Fields",
        env_vars=("SOCLENS_DEFAULT_SUPPRESS_FIELDS",),
        description="Default alert.suppress.fields for Splunk ES saved searches.",
    ),
    SettingSpec(
        key="soclens_tenant_field",
        category="workspace",
        label="Sigma Tenant Field",
        env_vars=("SOCLENS_TENANT_FIELD",),
        description="Optional tenant field appended to Splunk Sigma output/suppress fields.",
    ),
    SettingSpec(
        key="rf_logo_overrides_file",
        category="workspace",
        label="Logo Overrides JSON File",
        env_vars=("RF_LOGO_OVERRIDES_FILE",),
        value_type="path",
        description="Path to optional brand logo domain/URL override JSON file.",
    ),
    SettingSpec(
        key="rf_ignored_hashes_file",
        category="workspace",
        label="Ignored Hashes File",
        env_vars=("RF_IGNORED_HASHES_FILE",),
        value_type="path",
        description="Path to ignored logo hashes text file.",
    ),
    SettingSpec(
        key="rf_ignored_hashes",
        category="workspace",
        label="Ignored Hashes (CSV)",
        env_vars=("RF_IGNORED_HASHES",),
        description="Comma-separated SHA-256 logo hashes to ignore during sync.",
    ),
    SettingSpec(
        key="soclens_auto_approve",
        category="workspace",
        label="Auto-Approve CLI Writes",
        env_vars=("SOCLENS_AUTO_APPROVE",),
        value_type="bool",
        default="false",
        description="Permit non-interactive CLI mutations without --yes (true/false).",
    ),
    SettingSpec(
        key="rf_llm_api_key",
        category="workspace",
        label="Local LLM API Key",
        env_vars=("RF_LLM_API_KEY",),
        secret=True,
        description="Optional API key for OpenAI-compatible local LLM endpoints.",
    ),
    # Secret Manager (PAM / Vault)
    SettingSpec(
        key="secret_provider",
        category="secret_manager",
        label="Secret Manager Provider",
        env_vars=("SOCLENS_SECRET_PROVIDER",),
        default="none",
        choices=SUPPORTED_SECRET_PROVIDERS,
        description="Active PAM / Secret Manager backend (none, secret_server, hashicorp_vault, onepassword_connect, bitwarden).",
    ),
    SettingSpec(
        key="secret_store_verify_ssl",
        category="secret_manager",
        label="Secret Store SSL Verification",
        env_vars=("SOCLENS_SECRET_STORE_VERIFY_SSL", "SOCLENS_SECRET_VERIFY_SSL"),
        value_type="ssl_verify",
        description="true, false, CA bundle path, or leave blank to inherit RF SSL setting.",
    ),
    SettingSpec(
        key="secret_store_timeout",
        category="secret_manager",
        label="Secret Store Timeout (sec)",
        env_vars=("SOCLENS_SECRET_STORE_TIMEOUT", "SOCLENS_SECRET_TIMEOUT"),
        value_type="float",
        default="15.0",
        description="HTTP timeout in seconds for secret manager API calls.",
    ),
    SettingSpec(
        key="vault_secret_map",
        category="secret_manager",
        label="Vault Secret Map (JSON)",
        env_vars=("SOCLENS_VAULT_SECRET_MAP",),
        description="Single-line JSON mapping of SOCLens setting keys to canonical vault references.",
    ),
    SettingSpec(
        key="tss_base_url",
        category="secret_manager",
        label="Secret Server Base URL",
        env_vars=("TSS_BASE_URL", "SOCLENS_TSS_BASE_URL"),
        value_type="url",
        description="Thycotic / Delinea Secret Server base URL.",
    ),
    SettingSpec(
        key="tss_auth_mode",
        category="secret_manager",
        label="Secret Server Auth Mode",
        env_vars=("TSS_AUTH_MODE", "SOCLENS_TSS_AUTH_MODE"),
        default="password",
        choices=TSS_AUTH_MODES,
        description="Secret Server authentication mode: password, platform, or token.",
    ),
    SettingSpec(
        key="tss_username",
        category="secret_manager",
        label="Secret Server Username",
        env_vars=("TSS_USERNAME", "SOCLENS_TSS_USERNAME"),
        description="Secret Server username for OAuth2 password grant.",
    ),
    SettingSpec(
        key="tss_password",
        category="secret_manager",
        label="Secret Server Password",
        env_vars=("TSS_PASSWORD", "SOCLENS_TSS_PASSWORD"),
        secret=True,
        description="Secret Server bootstrap password.",
    ),
    SettingSpec(
        key="tss_domain",
        category="secret_manager",
        label="Secret Server Domain",
        env_vars=("TSS_DOMAIN", "SOCLENS_TSS_DOMAIN"),
        description="Optional Active Directory domain for Secret Server authentication.",
    ),
    SettingSpec(
        key="tss_client_id",
        category="secret_manager",
        label="Secret Server Platform Client ID",
        env_vars=("TSS_CLIENT_ID", "SOCLENS_TSS_CLIENT_ID"),
        description="Delinea Platform OAuth2 client ID.",
    ),
    SettingSpec(
        key="tss_client_secret",
        category="secret_manager",
        label="Secret Server Platform Client Secret",
        env_vars=("TSS_CLIENT_SECRET", "SOCLENS_TSS_CLIENT_SECRET"),
        secret=True,
        description="Delinea Platform OAuth2 client secret.",
    ),
    SettingSpec(
        key="tss_access_token",
        category="secret_manager",
        label="Secret Server Access Token",
        env_vars=("TSS_ACCESS_TOKEN", "SOCLENS_TSS_ACCESS_TOKEN"),
        secret=True,
        description="Pre-issued Secret Server Bearer token.",
    ),
    SettingSpec(
        key="tss_platform_url",
        category="secret_manager",
        label="Secret Server Platform URL",
        env_vars=("TSS_PLATFORM_URL", "SOCLENS_TSS_PLATFORM_URL"),
        value_type="url",
        description="Delinea Platform identity URL.",
    ),
    SettingSpec(
        key="tss_folder_id",
        category="secret_manager",
        label="Secret Server Folder ID",
        env_vars=("TSS_FOLDER_ID", "SOCLENS_TSS_FOLDER_ID"),
        description="Optional Secret Server folder ID filter.",
    ),
    SettingSpec(
        key="vault_addr",
        category="secret_manager",
        label="HashiCorp Vault Address",
        env_vars=("VAULT_ADDR", "SOCLENS_VAULT_ADDR"),
        value_type="url",
        description="HashiCorp Vault or OpenBao server URL.",
    ),
    SettingSpec(
        key="vault_auth_mode",
        category="secret_manager",
        label="Vault Auth Mode",
        env_vars=("VAULT_AUTH_MODE", "SOCLENS_VAULT_AUTH_MODE"),
        default="token",
        choices=VAULT_AUTH_MODES,
        description="HashiCorp Vault authentication mode: token or approle.",
    ),
    SettingSpec(
        key="vault_token",
        category="secret_manager",
        label="Vault Token",
        env_vars=("VAULT_TOKEN", "SOCLENS_VAULT_TOKEN"),
        secret=True,
        description="HashiCorp Vault authentication token.",
    ),
    SettingSpec(
        key="vault_role_id",
        category="secret_manager",
        label="Vault AppRole Role ID",
        env_vars=("VAULT_ROLE_ID", "SOCLENS_VAULT_ROLE_ID"),
        description="HashiCorp Vault AppRole role_id.",
    ),
    SettingSpec(
        key="vault_secret_id",
        category="secret_manager",
        label="Vault AppRole Secret ID",
        env_vars=("VAULT_SECRET_ID", "SOCLENS_VAULT_SECRET_ID"),
        secret=True,
        description="HashiCorp Vault AppRole secret_id.",
    ),
    SettingSpec(
        key="vault_auth_mount",
        category="secret_manager",
        label="Vault AppRole Auth Mount",
        env_vars=("VAULT_AUTH_MOUNT", "SOCLENS_VAULT_AUTH_MOUNT"),
        default="approle",
        description="HashiCorp Vault AppRole auth mount path (default approle).",
    ),
    SettingSpec(
        key="vault_kv_mount",
        category="secret_manager",
        label="Vault KV v2 Mount",
        env_vars=("VAULT_KV_MOUNT", "VAULT_MOUNT", "SOCLENS_VAULT_KV_MOUNT"),
        default="secret",
        description="HashiCorp Vault KV v2 secrets engine mount path (default secret).",
    ),
    SettingSpec(
        key="vault_namespace",
        category="secret_manager",
        label="Vault Namespace",
        env_vars=("VAULT_NAMESPACE", "SOCLENS_VAULT_NAMESPACE"),
        description="Optional HashiCorp Vault Enterprise namespace header.",
    ),
    SettingSpec(
        key="vault_prefix",
        category="secret_manager",
        label="Vault Path Prefix",
        env_vars=("VAULT_PREFIX", "VAULT_PATH_PREFIX", "SOCLENS_VAULT_PREFIX"),
        description="Optional KV v2 subpath prefix for catalog discovery.",
    ),
    SettingSpec(
        key="op_connect_url",
        category="secret_manager",
        label="1Password Connect URL",
        env_vars=("OP_CONNECT_HOST", "OP_CONNECT_URL", "SOCLENS_OP_CONNECT_URL"),
        value_type="url",
        description="1Password Connect Server base URL.",
    ),
    SettingSpec(
        key="op_connect_token",
        category="secret_manager",
        label="1Password Connect Token",
        env_vars=("OP_CONNECT_TOKEN", "SOCLENS_OP_CONNECT_TOKEN"),
        secret=True,
        description="1Password Connect Server Bearer token.",
    ),
    SettingSpec(
        key="op_vault_id",
        category="secret_manager",
        label="1Password Vault UUID",
        env_vars=("OP_VAULT_ID", "SOCLENS_OP_VAULT_ID"),
        description="Optional 1Password Vault UUID scope.",
    ),
    SettingSpec(
        key="bw_serve_url",
        category="secret_manager",
        label="Bitwarden bw serve URL",
        env_vars=("BW_SERVE_URL", "BW_API_URL", "SOCLENS_BW_SERVE_URL"),
        value_type="url",
        default="http://127.0.0.1:8087",
        description="Local Bitwarden CLI 'bw serve' REST URL.",
    ),
    SettingSpec(
        key="bw_master_password",
        category="secret_manager",
        label="Bitwarden Master Password",
        env_vars=("BW_MASTER_PASSWORD", "SOCLENS_BW_MASTER_PASSWORD"),
        secret=True,
        description="Optional Bitwarden vault unlock password (blank by default; session/env preferred).",
    ),
    SettingSpec(
        key="bw_folder_id",
        category="secret_manager",
        label="Bitwarden Folder ID",
        env_vars=("BW_FOLDER_ID", "SOCLENS_BW_FOLDER_ID"),
        description="Optional Bitwarden folder UUID filter.",
    ),
    SettingSpec(
        key="bw_collection_id",
        category="secret_manager",
        label="Bitwarden Collection ID",
        env_vars=("BW_COLLECTION_ID", "SOCLENS_BW_COLLECTION_ID"),
        description="Optional Bitwarden collection UUID filter.",
    ),
    SettingSpec(
        key="bw_organization_id",
        category="secret_manager",
        label="Bitwarden Organization ID",
        env_vars=("BW_ORGANIZATION_ID", "SOCLENS_BW_ORGANIZATION_ID"),
        description="Optional Bitwarden organization UUID filter.",
    ),
    # OSINT Enrichment APIs (Free Passive Sources & Optional Free-Tier Keys)
    SettingSpec(
        key="osint_enabled",
        category="osint",
        label="Enable Free OSINT Enrichment",
        env_vars=("SOCLENS_OSINT_ENABLED",),
        value_type="bool",
        default="true",
        description="Include passive free OSINT feeds alongside Recorded Future in Threat Research.",
    ),
    SettingSpec(
        key="osint_timeout",
        category="osint",
        label="OSINT Per-Source Timeout (sec)",
        env_vars=("SOCLENS_OSINT_TIMEOUT",),
        value_type="float",
        default="8.0",
        description="HTTP timeout in seconds per passive OSINT provider (default 8.0).",
    ),
    SettingSpec(
        key="osint_vt_api_key",
        category="osint",
        label="VirusTotal v3 Free API Key",
        env_vars=("VT_API_KEY", "VIRUSTOTAL_API_KEY", "SOCLENS_VT_API_KEY"),
        secret=True,
        description="Optional free VirusTotal v3 API key (4 req/min, 500/day; virustotal.com).",
    ),
    SettingSpec(
        key="osint_abuseipdb_api_key",
        category="osint",
        label="AbuseIPDB v2 Free API Key",
        env_vars=("ABUSEIPDB_API_KEY", "SOCLENS_ABUSEIPDB_API_KEY"),
        secret=True,
        description="Optional free AbuseIPDB v2 API key (1,000 checks/day; abuseipdb.com).",
    ),
    SettingSpec(
        key="osint_abusech_api_key",
        category="osint",
        label="abuse.ch Free Auth-Key",
        env_vars=("ABUSECH_AUTH_KEY", "ABUSECH_API_KEY", "SOCLENS_ABUSECH_API_KEY"),
        secret=True,
        description="Optional free abuse.ch Auth-Key unlocking ThreatFox, URLhaus & MalwareBazaar (auth.abuse.ch).",
    ),
    SettingSpec(
        key="osint_otx_api_key",
        category="osint",
        label="AlienVault OTX Free API Key",
        env_vars=("OTX_API_KEY", "ALIENVAULT_OTX_API_KEY", "SOCLENS_OTX_API_KEY"),
        secret=True,
        description="Optional free LevelBlue/AlienVault OTX API key for higher rate limits (otx.alienvault.com).",
    ),
    SettingSpec(
        key="osint_urlscan_api_key",
        category="osint",
        label="URLScan.io Free API Key",
        env_vars=("URLSCAN_API_KEY", "SOCLENS_URLSCAN_API_KEY"),
        secret=True,
        description="Optional free URLScan.io API key for higher search quotas (urlscan.io).",
    ),
    SettingSpec(
        key="osint_greynoise_api_key",
        category="osint",
        label="GreyNoise Community Free Key",
        env_vars=("GREYNOISE_API_KEY", "SOCLENS_GREYNOISE_API_KEY"),
        secret=True,
        description="Optional free GreyNoise Community API key (viz.greynoise.io).",
    ),
)

SETTING_SPECS_BY_KEY: dict[str, SettingSpec] = {spec.key: spec for spec in SETTING_SPECS}

_ALIAS_TO_KEY: dict[str, str] = {}
for _spec in SETTING_SPECS:
    _ALIAS_TO_KEY[_spec.key.lower()] = _spec.key
    for _env_name in _spec.env_vars:
        _ALIAS_TO_KEY[_env_name.lower()] = _spec.key


def _clean_str(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = str(value).strip()
    return stripped if stripped else None


def resolve_setting_key(name: str) -> str | None:
    """Resolve a canonical setting key or environment variable alias to a canonical key."""
    cleaned = _clean_str(name)
    if not cleaned:
        return None
    return _ALIAS_TO_KEY.get(cleaned.lower())


def validate_profile_name(name: str) -> str:
    """Validate and normalize a settings profile name."""
    cleaned = str(name).strip()
    if not cleaned or cleaned in {".", ".."} or not _PROFILE_NAME_RE.match(cleaned):
        raise ValueError(
            "Profile name must be 1-64 characters using letters, numbers, '.', '_', or '-'."
        )
    return cleaned


def get_settings_path(explicit: Path | str | None = None) -> Path:
    """Resolve the per-user settings JSON file path cross-platform.

    Resolution order:
    1. ``explicit`` path argument (if non-empty)
    2. ``SOCLENS_SETTINGS_FILE`` environment variable (if non-empty)
    3. Internal test override ``_DEFAULT_SETTINGS_PATH_OVERRIDE`` (if set)
    4. Platform per-user configuration directory:
       - Windows: ``%APPDATA%\\soclens\\settings.json``
       - macOS: ``~/Library/Application Support/soclens/settings.json``
       - Linux/POSIX: ``$XDG_CONFIG_HOME/soclens/settings.json``
         (fallback ``~/.config/soclens/settings.json``)
    """
    if explicit is not None:
        raw_explicit = str(explicit).strip()
        if raw_explicit:
            candidate = Path(raw_explicit).expanduser()
            return candidate if candidate.is_absolute() else candidate.resolve()

    env_file = _clean_str(os.environ.get("SOCLENS_SETTINGS_FILE"))
    if env_file:
        candidate = Path(env_file).expanduser()
        return candidate if candidate.is_absolute() else candidate.resolve()

    if _DEFAULT_SETTINGS_PATH_OVERRIDE is not None:
        return _DEFAULT_SETTINGS_PATH_OVERRIDE

    if os.name == "nt" or sys.platform == "win32":
        appdata = _clean_str(os.environ.get("APPDATA"))
        base_dir = (
            Path(appdata).expanduser()
            if appdata
            else Path.home() / "AppData" / "Roaming"
        )
        return base_dir / APP_CONFIG_DIR_NAME / SETTINGS_FILENAME

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_CONFIG_DIR_NAME / SETTINGS_FILENAME

    xdg_home = _clean_str(os.environ.get("XDG_CONFIG_HOME"))
    base_dir = Path(xdg_home).expanduser() if xdg_home else Path.home() / ".config"
    return base_dir / APP_CONFIG_DIR_NAME / SETTINGS_FILENAME


def _cache_key(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def invalidate_settings_cache() -> None:
    """Clear the cached per-user settings store across all paths."""
    with _STORE_LOCK:
        _CACHE.clear()
        _LAST_ERRORS.clear()


def get_last_load_error(settings_path: Path | str | None = None) -> str | None:
    """Return the most recent load error for ``settings_path``, if any."""
    resolved = _cache_key(get_settings_path(settings_path))
    with _STORE_LOCK:
        if resolved in _LAST_ERRORS:
            return _LAST_ERRORS[resolved]
        entry = _CACHE.get(resolved)
        return entry[2] if entry is not None else None


def _default_store() -> dict[str, Any]:
    return {
        "schema_version": SETTINGS_SCHEMA_VERSION,
        "active_profile": DEFAULT_PROFILE,
        "profiles": {DEFAULT_PROFILE: {}},
    }


def _normalize_store(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Settings file root must be a JSON object.")

    store: dict[str, Any] = copy.deepcopy(raw)
    store.setdefault("schema_version", SETTINGS_SCHEMA_VERSION)

    raw_profiles = store.get("profiles")
    profiles: dict[str, dict[str, str]] = {}
    if isinstance(raw_profiles, dict):
        for prof_name, prof_data in raw_profiles.items():
            if not isinstance(prof_name, str) or not isinstance(prof_data, dict):
                continue
            try:
                clean_prof = validate_profile_name(prof_name)
            except ValueError:
                continue
            cleaned_entries: dict[str, str] = {}
            for k, v in prof_data.items():
                if not isinstance(k, str) or v is None:
                    continue
                val_str = str(v).strip()
                if val_str:
                    cleaned_entries[k.strip()] = val_str
            profiles[clean_prof] = cleaned_entries

    if DEFAULT_PROFILE not in profiles:
        profiles[DEFAULT_PROFILE] = {}
    store["profiles"] = profiles

    raw_active = store.get("active_profile")
    active = DEFAULT_PROFILE
    if isinstance(raw_active, str):
        try:
            candidate = validate_profile_name(raw_active)
            if candidate in profiles:
                active = candidate
        except ValueError:
            active = DEFAULT_PROFILE
    store["active_profile"] = active
    return store


def _stat_signature(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _read_raw_settings_json(target: Path) -> Any:
    raw_text = target.read_text(encoding="utf-8")
    return json.loads(raw_text) if raw_text.strip() else {}


def _load_store_for_mutation(
    target: Path,
    *,
    passphrase: str | None = None,
) -> dict[str, Any]:
    """Load the store for mutation, refusing to overwrite locked or undecryptable files."""
    if not target.is_file():
        return _default_store()

    try:
        parsed = _read_raw_settings_json(target)
    except Exception as exc:
        logger.warning("Failed to parse non-encrypted settings file '%s' before save: %s", target, exc)
        return _default_store()

    if is_encrypted_envelope(parsed):
        decrypted = decrypt_settings_envelope(
            parsed,
            settings_path=target,
            passphrase=passphrase,
        )
        return _normalize_store(decrypted)

    return _normalize_store(parsed)


def load_settings_store(settings_path: Path | str | None = None) -> dict[str, Any]:
    """Load the per-user settings store (with mtime caching, decryption, and resilience)."""
    target = get_settings_path(settings_path)
    key = _cache_key(target)

    with _STORE_LOCK:
        sig = _stat_signature(target)
        cached = _CACHE.get(key)
        if cached is not None and cached[0] == sig and cached[2] is None:
            return copy.deepcopy(cached[1])

        if sig is None:
            default_data = _default_store()
            _LAST_ERRORS.pop(key, None)
            _CACHE[key] = (None, copy.deepcopy(default_data), None)
            return default_data

        load_error: str | None = None
        cache_result = True
        try:
            parsed = _read_raw_settings_json(target)
            if is_encrypted_envelope(parsed):
                decrypted = decrypt_settings_envelope(parsed, settings_path=target)
                normalized = _normalize_store(decrypted)
            else:
                normalized = _normalize_store(parsed)
        except SettingsLockedError as exc:
            load_error = str(exc)
            cache_result = False
            normalized = _default_store()
        except SettingsCryptoError as exc:
            load_error = f"Failed to decrypt settings file '{target}': {exc}"
            logger.warning("%s", load_error)
            cache_result = False
            normalized = _default_store()
        except Exception as exc:
            load_error = f"Failed to parse settings file '{target}': {exc}"
            logger.warning("%s", load_error)
            normalized = _default_store()

        if load_error is not None:
            _LAST_ERRORS[key] = load_error
        else:
            _LAST_ERRORS.pop(key, None)
        if cache_result:
            _CACHE[key] = (sig, copy.deepcopy(normalized), load_error)
        else:
            _CACHE.pop(key, None)
        return normalized


def _write_store_atomic(
    target: Path,
    store: dict[str, Any],
    *,
    mode: str | None = None,
    passphrase: str | None = None,
    reuse_existing_dek: bool = True,
    rotate_kek: bool = False,
) -> None:
    """Encrypt and write ``store`` atomically with owner-only file permissions where supported."""
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass

    store_to_encrypt = copy.deepcopy(store)
    store_to_encrypt["schema_version"] = SETTINGS_SCHEMA_VERSION
    envelope = encrypt_settings_payload(
        store_to_encrypt,
        settings_path=target,
        mode=mode,
        passphrase=passphrase,
        reuse_existing_dek=reuse_existing_dek,
        rotate_kek=rotate_kek,
    )

    serialized = json.dumps(envelope, indent=2, ensure_ascii=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".settings.", suffix=".tmp", dir=str(parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        if os.name != "nt":
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
        os.replace(tmp_path, target)
        if os.name != "nt":
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
    except BaseException:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise

    key = _cache_key(target)
    sig = _stat_signature(target)
    with _STORE_LOCK:
        _LAST_ERRORS.pop(key, None)
        _CACHE[key] = (sig, copy.deepcopy(store_to_encrypt), None)


def inspect_settings_encryption(settings_path: Path | str | None = None) -> dict[str, Any]:
    """Inspect encryption mode, backend, and lock state for ``settings_path`` without unlocking."""
    target = get_settings_path(settings_path)
    return inspect_settings_file_encryption(target)


def is_settings_locked(settings_path: Path | str | None = None) -> bool:
    """Return True if ``settings_path`` is passphrase-encrypted and currently locked."""
    info = inspect_settings_encryption(settings_path)
    return bool(info.get("locked", False))


def unlock_settings(
    passphrase: str | None = None,
    *,
    settings_path: Path | str | None = None,
) -> dict[str, Any]:
    """Unlock a passphrase-protected settings file into process-local memory."""
    target = get_settings_path(settings_path)
    key = _cache_key(target)
    with _STORE_LOCK:
        if not target.is_file():
            default_data = _default_store()
            _LAST_ERRORS.pop(key, None)
            _CACHE[key] = (None, copy.deepcopy(default_data), None)
            return default_data

        parsed = _read_raw_settings_json(target)
        if is_encrypted_envelope(parsed):
            eff_passphrase = passphrase if passphrase is not None else get_env_passphrase()
            decrypted = decrypt_settings_envelope(
                parsed,
                settings_path=target,
                passphrase=eff_passphrase,
                allow_env_passphrase=False,
            )
            normalized = _normalize_store(decrypted)
        else:
            normalized = _normalize_store(parsed)

        sig = _stat_signature(target)
        _LAST_ERRORS.pop(key, None)
        _CACHE[key] = (sig, copy.deepcopy(normalized), None)
        return normalized


def lock_settings(settings_path: Path | str | None = None) -> bool:
    """Clear in-memory decrypted settings and encryption keys for ``settings_path`` (or all paths)."""
    with _STORE_LOCK:
        if settings_path is None:
            clear_unlocked_keys(None, mark_locked=True)
            _CACHE.clear()
            _LAST_ERRORS.clear()
            return is_settings_locked()

        target = get_settings_path(settings_path)
        key = _cache_key(target)
        clear_unlocked_keys(target, mark_locked=True)
        _CACHE.pop(key, None)
        _LAST_ERRORS.pop(key, None)
        return is_settings_locked(target)


def encrypt_settings_store(
    *,
    mode: str = ENCRYPTION_MODE_OS_KEYSTORE,
    passphrase: str | None = None,
    current_passphrase: str | None = None,
    settings_path: Path | str | None = None,
) -> dict[str, Any]:
    """Encrypt legacy plaintext settings or switch between ``os_keystore`` and ``passphrase`` mode."""
    target_mode = mode.strip().lower()
    if target_mode not in SUPPORTED_ENCRYPTION_MODES:
        raise ValueError(
            f"Unsupported encryption mode {mode!r}. Expected one of: {', '.join(SUPPORTED_ENCRYPTION_MODES)}."
        )
    if target_mode == ENCRYPTION_MODE_PASSPHRASE:
        eff_pass = passphrase if passphrase is not None else get_env_passphrase()
        if not eff_pass or len(eff_pass) < MIN_PASSPHRASE_LENGTH:
            raise ValueError(
                f"Master passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters long."
            )
    else:
        eff_pass = None

    target = get_settings_path(settings_path)
    with _STORE_LOCK:
        store = _load_store_for_mutation(target, passphrase=current_passphrase)
        _write_store_atomic(
            target,
            store,
            mode=target_mode,
            passphrase=eff_pass,
            reuse_existing_dek=False,
        )
    return get_settings_storage_info(target)


def rotate_settings_key(
    *,
    passphrase: str | None = None,
    new_passphrase: str | None = None,
    rotate_kek: bool = False,
    settings_path: Path | str | None = None,
) -> dict[str, Any]:
    """Rotate the per-file AES-256-GCM DEK (and optionally passphrase or OS master KEK)."""
    target = get_settings_path(settings_path)
    with _STORE_LOCK:
        enc_info = inspect_settings_file_encryption(target)
        store = _load_store_for_mutation(target, passphrase=passphrase)

        if new_passphrase is not None:
            target_mode = ENCRYPTION_MODE_PASSPHRASE
            eff_new_pass: str | None = new_passphrase
        elif enc_info.get("encryption_mode") == ENCRYPTION_MODE_PASSPHRASE:
            target_mode = ENCRYPTION_MODE_PASSPHRASE
            eff_new_pass = passphrase if passphrase is not None else get_env_passphrase()
            if not eff_new_pass:
                raise ValueError(
                    "Current or new master passphrase is required to rotate key in passphrase mode."
                )
        else:
            target_mode = ENCRYPTION_MODE_OS_KEYSTORE
            eff_new_pass = None

        _write_store_atomic(
            target,
            store,
            mode=target_mode,
            passphrase=eff_new_pass,
            reuse_existing_dek=False,
            rotate_kek=rotate_kek,
        )
    return get_settings_storage_info(target)


def get_active_profile_name(settings_path: Path | str | None = None) -> str:
    """Return the active profile name, honoring ``SOCLENS_PROFILE`` if set."""
    env_profile = _clean_str(os.environ.get("SOCLENS_PROFILE"))
    if env_profile:
        try:
            return validate_profile_name(env_profile)
        except ValueError:
            logger.warning("Ignoring invalid SOCLENS_PROFILE value: %r", env_profile)
    store = load_settings_store(settings_path)
    return str(store.get("active_profile") or DEFAULT_PROFILE)


def list_profiles(settings_path: Path | str | None = None) -> list[str]:
    """Return sorted profile names from the settings store (always includes ``default``)."""
    store = load_settings_store(settings_path)
    profiles = store.get("profiles", {})
    names = sorted(str(k) for k in profiles.keys())
    if DEFAULT_PROFILE in names:
        names.remove(DEFAULT_PROFILE)
        names.insert(0, DEFAULT_PROFILE)
    return names


def get_profile_settings(
    profile: str | None = None,
    settings_path: Path | str | None = None,
) -> dict[str, str]:
    """Return a copy of the saved settings dictionary for ``profile``."""
    store = load_settings_store(settings_path)
    prof_name = (
        validate_profile_name(profile)
        if profile is not None
        else get_active_profile_name(settings_path)
    )
    prof_map = store.get("profiles", {}).get(prof_name, {})
    return dict(prof_map) if isinstance(prof_map, dict) else {}


def save_profile_settings(
    values: Mapping[str, str | None],
    *,
    profile: str | None = None,
    replace: bool = False,
    settings_path: Path | str | None = None,
) -> Path:
    """Merge or replace settings for ``profile`` and persist atomically."""
    target = get_settings_path(settings_path)
    with _STORE_LOCK:
        store = _load_store_for_mutation(target)
        env_profile = _clean_str(os.environ.get("SOCLENS_PROFILE"))
        if profile is not None:
            prof_name = validate_profile_name(profile)
        elif env_profile:
            try:
                prof_name = validate_profile_name(env_profile)
            except ValueError:
                prof_name = str(store.get("active_profile") or DEFAULT_PROFILE)
        else:
            prof_name = str(store.get("active_profile") or DEFAULT_PROFILE)
        profiles: dict[str, dict[str, str]] = store.setdefault("profiles", {})
        if DEFAULT_PROFILE not in profiles:
            profiles[DEFAULT_PROFILE] = {}

        existing = {} if replace else dict(profiles.get(prof_name, {}))
        for raw_key, raw_val in values.items():
            canon = resolve_setting_key(raw_key) or raw_key.strip()
            if not canon:
                continue
            cleaned = _clean_str(raw_val)
            if cleaned is None:
                existing.pop(canon, None)
            else:
                with _SESSION_LOCK:
                    skip_vault = (
                        canon in SECRET_MANAGED_SETTING_KEYS
                        and canon in _VAULT_HYDRATED_KEYS
                        and cleaned == _SESSION_OVERRIDES.get(canon)
                    )
                if not skip_vault:
                    existing[canon] = cleaned

        profiles[prof_name] = existing
        _write_store_atomic(target, store)
    return target


def set_active_profile(
    profile: str,
    *,
    create: bool = True,
    settings_path: Path | str | None = None,
) -> Path:
    """Switch the persisted ``active_profile`` to ``profile``."""
    prof_name = validate_profile_name(profile)
    target = get_settings_path(settings_path)
    with _STORE_LOCK:
        store = _load_store_for_mutation(target)
        profiles: dict[str, dict[str, str]] = store.setdefault("profiles", {})
        if prof_name not in profiles:
            if not create:
                raise KeyError(f"Profile '{prof_name}' does not exist.")
            profiles[prof_name] = {}
        store["active_profile"] = prof_name
        _write_store_atomic(target, store)
    return target


def delete_profile(
    profile: str,
    *,
    settings_path: Path | str | None = None,
) -> Path:
    """Delete a non-default profile from the settings store."""
    prof_name = validate_profile_name(profile)
    if prof_name == DEFAULT_PROFILE:
        raise ValueError("Cannot delete the built-in 'default' profile.")
    target = get_settings_path(settings_path)
    with _STORE_LOCK:
        store = _load_store_for_mutation(target)
        profiles: dict[str, dict[str, str]] = store.setdefault("profiles", {})
        if prof_name not in profiles:
            raise KeyError(f"Profile '{prof_name}' does not exist.")
        profiles.pop(prof_name, None)
        if store.get("active_profile") == prof_name:
            store["active_profile"] = DEFAULT_PROFILE
        _write_store_atomic(target, store)
    return target


def clear_profile_settings(
    profile: str | None = None,
    *,
    settings_path: Path | str | None = None,
) -> Path:
    """Remove all saved values in ``profile`` (keeping the profile entry itself)."""
    return save_profile_settings({}, profile=profile, replace=True, settings_path=settings_path)


def get_settings_storage_info(settings_path: Path | str | None = None) -> dict[str, Any]:
    """Return path, existence, permission posture, encryption metadata, and profile info."""
    target = get_settings_path(settings_path)
    active = get_active_profile_name(target)
    profiles = list_profiles(target)
    enc = inspect_settings_file_encryption(target)
    load_error = get_last_load_error(target)
    exists = target.is_file()
    is_locked = bool(enc.get("locked", False)) or (
        enc.get("encryption_mode") == ENCRYPTION_MODE_PASSPHRASE
        and load_error is not None
        and "decrypt" in load_error.lower()
    )

    if exists:
        if os.name == "nt":
            perms = "user profile private (Windows ACL)"
        else:
            try:
                mode = stat.S_IMODE(target.stat().st_mode)
                perms = (
                    f"{mode:04o} (owner-only)"
                    if (mode & 0o077) == 0
                    else f"{mode:04o} (warning: group/world accessible)"
                )
            except OSError:
                perms = "unknown"
    else:
        perms = "not created yet (0600 owner-only on first save)" if os.name != "nt" else "not created yet"

    return {
        "path": str(target),
        "exists": exists,
        "permissions": perms,
        "active_profile": active,
        "profiles": profiles,
        "profile_count": len(profiles),
        "env_override_profile": _clean_str(os.environ.get("SOCLENS_PROFILE")),
        "load_error": load_error,
        "encrypted": bool(enc.get("encrypted", False)),
        "schema_version": enc.get("schema_version"),
        "cipher": enc.get("cipher") or (ENCRYPTED_SETTINGS_CIPHER if enc.get("encrypted") else None),
        "encryption_mode": str(enc.get("encryption_mode") or ENCRYPTION_MODE_OS_KEYSTORE),
        "key_backend": str(enc.get("key_backend") or "none"),
        "key_backend_label": str(enc.get("key_backend_label") or ""),
        "locked": is_locked,
        "legacy_plaintext": bool(enc.get("legacy_plaintext", False)),
        "encryption_summary": str(enc.get("encryption_summary") or ""),
    }


def _validate_url(value: str, *, require_scheme: bool) -> str | None:
    if require_scheme and not value.lower().startswith(("http://", "https://")):
        return "Must start with http:// or https://."
    candidate = value if "://" in value else f"https://{value}"
    if "://" in value and not candidate.lower().startswith(("http://", "https://")):
        return "Scheme must be http:// or https://."
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port
    except ValueError as exc:
        return f"Invalid URL ({exc})."
    if not parsed.hostname:
        return "URL must include a valid hostname."
    return None


def parse_vault_secret_map(
    raw: str | Mapping[str, Any] | None,
    *,
    strict: bool = True,
) -> dict[str, str]:
    """Parse ``vault_secret_map`` JSON/mapping into ``{setting_key: canonical_ref}``."""
    if raw is None:
        return {}
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return {}
        try:
            loaded: Any = json.loads(stripped)
        except ValueError as exc:
            raise ValueError(f"vault_secret_map must be valid JSON: {exc}") from exc
    elif isinstance(raw, Mapping):
        loaded = raw
    else:
        raise ValueError("vault_secret_map must be a JSON object or mapping.")

    if not isinstance(loaded, Mapping):
        raise ValueError("vault_secret_map must be a JSON object.")

    parsed: dict[str, str] = {}
    for raw_k, raw_v in loaded.items():
        if not isinstance(raw_k, str) or not raw_k.strip():
            raise ValueError("vault_secret_map keys must be non-empty strings.")
        canon = resolve_setting_key(raw_k) or raw_k.strip()
        if canon not in SECRET_MANAGED_SETTING_KEYS:
            raise ValueError(f"Unsupported secret-managed setting key: {raw_k!r}.")
        if raw_v is None:
            if strict:
                raise ValueError(f"Vault reference for {canon!r} must be a non-empty string.")
            continue
        if not isinstance(raw_v, str):
            raise ValueError(f"Vault reference for {canon!r} must be a string.")
        if "\n" in raw_v or "\r" in raw_v:
            raise ValueError(f"Vault reference for {canon!r} cannot contain newlines.")
        cleaned = raw_v.strip()
        if not cleaned:
            if strict:
                raise ValueError(f"Vault reference for {canon!r} cannot be empty.")
            continue
        parsed[canon] = cleaned
    return parsed


def serialize_vault_secret_map(mapping: Mapping[str, str | None]) -> str:
    """Serialize ``{setting_key: canonical_ref}`` into compact single-line JSON."""
    cleaned: dict[str, str] = {}
    for raw_k, raw_v in mapping.items():
        if not isinstance(raw_k, str) or not raw_k.strip():
            raise ValueError("vault_secret_map keys must be non-empty strings.")
        canon = resolve_setting_key(raw_k) or raw_k.strip()
        if canon not in SECRET_MANAGED_SETTING_KEYS:
            raise ValueError(f"Unsupported secret-managed setting key: {raw_k!r}.")
        if raw_v is None:
            continue
        if not isinstance(raw_v, str):
            raise ValueError(f"Vault reference for {canon!r} must be a string.")
        if "\n" in raw_v or "\r" in raw_v:
            raise ValueError(f"Vault reference for {canon!r} cannot contain newlines.")
        val = raw_v.strip()
        if val:
            cleaned[canon] = val
    if not cleaned:
        return ""
    return json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_s1_tier_rules(
    raw: str | Sequence[Any] | Mapping[str, Any] | None,
) -> list[tuple[str, re.Pattern[str]]]:
    """Parse ``s1_tier_rules`` into ordered ``[(tier_name, compiled_regex), ...]``."""
    if raw is None:
        return []
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return []
        try:
            loaded: Any = json.loads(stripped)
        except ValueError as exc:
            raise ValueError(f"s1_tier_rules must be valid JSON: {exc}") from exc
    else:
        loaded = raw

    pairs: list[tuple[str, str]] = []
    if isinstance(loaded, Mapping):
        for tier_k, pat_v in loaded.items():
            if not isinstance(tier_k, str):
                raise ValueError("s1_tier_rules tier names must be non-empty strings.")
            if "\n" in tier_k or "\r" in tier_k:
                raise ValueError(f"s1_tier_rules tier name {tier_k!r} cannot contain newlines.")
            if not tier_k.strip():
                raise ValueError("s1_tier_rules tier names must be non-empty strings.")
            if not isinstance(pat_v, str):
                raise ValueError(f"s1_tier_rules pattern for {tier_k!r} must be a non-empty string.")
            if "\n" in pat_v or "\r" in pat_v:
                raise ValueError(
                    f"s1_tier_rules pattern for {tier_k.strip()!r} cannot contain newlines."
                )
            if not pat_v.strip():
                raise ValueError(f"s1_tier_rules pattern for {tier_k!r} must be a non-empty string.")
            pairs.append((tier_k.strip(), pat_v.strip()))
    elif isinstance(loaded, Sequence) and not isinstance(loaded, (str, bytes, bytearray)):
        for item in loaded:
            if isinstance(item, Mapping):
                tier_val = item.get("tier")
                pat_val = item.get("pattern") if item.get("pattern") is not None else item.get("regex")
            elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)) and len(item) == 2:
                tier_val, pat_val = item[0], item[1]
            else:
                raise ValueError(
                    "s1_tier_rules list entries must be {'tier': ..., 'pattern': ...} or [tier, pattern]."
                )
            if not isinstance(tier_val, str):
                raise ValueError("s1_tier_rules entry 'tier' must be a non-empty string.")
            if "\n" in tier_val or "\r" in tier_val:
                raise ValueError(f"s1_tier_rules entry 'tier' {tier_val!r} cannot contain newlines.")
            if not tier_val.strip():
                raise ValueError("s1_tier_rules entry 'tier' must be a non-empty string.")
            if not isinstance(pat_val, str):
                raise ValueError(
                    f"s1_tier_rules entry pattern for {tier_val!r} must be a non-empty string."
                )
            if "\n" in pat_val or "\r" in pat_val:
                raise ValueError(
                    f"s1_tier_rules pattern for {tier_val.strip()!r} cannot contain newlines."
                )
            if not pat_val.strip():
                raise ValueError(
                    f"s1_tier_rules entry pattern for {tier_val!r} must be a non-empty string."
                )
            pairs.append((tier_val.strip(), pat_val.strip()))
    else:
        raise ValueError("s1_tier_rules must be a JSON object or array.")

    compiled: list[tuple[str, re.Pattern[str]]] = []
    for tier_name, pattern_str in pairs:
        if "\n" in tier_name or "\r" in tier_name:
            raise ValueError(f"s1_tier_rules tier name {tier_name!r} cannot contain newlines.")
        if "\n" in pattern_str or "\r" in pattern_str:
            raise ValueError(f"s1_tier_rules pattern for {tier_name!r} cannot contain newlines.")
        try:
            regex = re.compile(pattern_str)
        except re.error as exc:
            raise ValueError(
                f"s1_tier_rules invalid regex for {tier_name!r}: {exc}"
            ) from exc
        compiled.append((tier_name, regex))
    return compiled


def parse_s1_site_tenant_map(
    raw: str | Mapping[str, Any] | None,
) -> dict[str, str]:
    """Parse ``s1_site_tenant_map`` JSON/mapping into ``{site_or_code: tenant_id}``."""
    if raw is None:
        return {}
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return {}
        try:
            loaded: Any = json.loads(stripped)
        except ValueError as exc:
            raise ValueError(f"s1_site_tenant_map must be valid JSON: {exc}") from exc
    elif isinstance(raw, Mapping):
        loaded = raw
    else:
        raise ValueError("s1_site_tenant_map must be a JSON object or mapping.")

    if not isinstance(loaded, Mapping):
        raise ValueError("s1_site_tenant_map must be a JSON object.")

    result: dict[str, str] = {}
    for raw_k, raw_v in loaded.items():
        if isinstance(raw_k, (dict, list, bool)) or raw_k is None:
            raise ValueError("s1_site_tenant_map keys must be non-empty strings.")
        key_str = str(raw_k).strip()
        if not key_str:
            raise ValueError("s1_site_tenant_map keys must be non-empty strings.")
        if not isinstance(raw_v, str) or not raw_v.strip():
            raise ValueError(f"s1_site_tenant_map value for {key_str!r} must be a non-empty string.")
        if "\n" in raw_v or "\r" in raw_v:
            raise ValueError(f"s1_site_tenant_map value for {key_str!r} cannot contain newlines.")
        result[key_str] = raw_v.strip()
    return result


def validate_settings_values(values: Mapping[str, str | None]) -> list[tuple[str, str]]:
    """Validate candidate setting values, returning ``[(key, error_message), ...]``."""
    errors: list[tuple[str, str]] = []
    for raw_key, raw_val in values.items():
        if raw_val is None:
            continue
        raw_str = str(raw_val)
        canon = resolve_setting_key(raw_key) or raw_key.strip()
        spec = SETTING_SPECS_BY_KEY.get(canon)
        label = spec.label if spec is not None else canon

        if "\n" in raw_str or "\r" in raw_str:
            errors.append((canon, f"{label}: newline characters are not permitted."))
            continue

        cleaned = raw_str.strip()
        if not cleaned:
            continue

        if spec is None:
            continue

        if spec.choices and cleaned.lower() not in {c.lower() for c in spec.choices}:
            valid_choices = ", ".join(spec.choices)
            errors.append((canon, f"{label}: must be one of {valid_choices}."))
            continue

        if spec.value_type == "url":
            err = _validate_url(cleaned, require_scheme=True)
            if err:
                errors.append((canon, f"{label}: {err}"))
        elif spec.value_type == "host_url":
            err = _validate_url(cleaned, require_scheme=False)
            if err:
                errors.append((canon, f"{label}: {err}"))
        elif spec.value_type == "float":
            try:
                num = float(cleaned)
            except ValueError:
                errors.append((canon, f"{label}: must be a positive number."))
                continue
            if not math.isfinite(num) or num <= 0:
                errors.append((canon, f"{label}: must be greater than 0."))
        elif spec.value_type == "bool":
            if cleaned.lower() not in (_TRUTHY_VALUES | _FALSY_VALUES):
                errors.append((canon, f"{label}: must be true or false."))
        elif canon == "rf_tui_image_protocol":
            if cleaned.lower() not in {"auto", "kitty", "iterm2", "sixel", "halfblock"}:
                errors.append(
                    (canon, f"{label}: must be auto, kitty, iterm2, sixel, or halfblock.")
                )
        elif canon == "vault_secret_map":
            try:
                parse_vault_secret_map(cleaned, strict=True)
            except ValueError as exc:
                errors.append((canon, f"{label}: {exc}"))
        elif canon == "s1_tier_rules":
            try:
                parse_s1_tier_rules(cleaned)
            except ValueError as exc:
                errors.append((canon, f"{label}: {exc}"))
        elif canon == "s1_site_tenant_map":
            try:
                parse_s1_site_tenant_map(cleaned)
            except ValueError as exc:
                errors.append((canon, f"{label}: {exc}"))
        elif canon == "splunk_es_saved_views":
            try:
                loaded_views: Any = json.loads(cleaned)
            except ValueError as exc:
                errors.append((canon, f"{label}: must be valid JSON ({exc})."))
                continue
            if isinstance(loaded_views, list):
                if not all(isinstance(item, dict) for item in loaded_views):
                    errors.append((canon, f"{label}: JSON list entries must be objects."))
            elif not isinstance(loaded_views, dict):
                errors.append((canon, f"{label}: must be a JSON object or list of objects."))
        elif canon == "splunk_es_tenant_field":
            if any(ch.isspace() for ch in cleaned):
                errors.append((canon, f"{label}: must be a single field name without whitespace."))
        elif canon in {"splunk_es_tenant_aliases", "splunk_es_custom_fields"}:
            if cleaned.startswith("["):
                try:
                    loaded_list: Any = json.loads(cleaned)
                except ValueError as exc:
                    errors.append((canon, f"{label}: invalid JSON list ({exc})."))
                    continue
                if not isinstance(loaded_list, list) or not all(
                    isinstance(item, str) and item.strip() for item in loaded_list
                ):
                    errors.append((canon, f"{label}: JSON list must contain non-empty strings."))

    return errors


def mask_secret(value: str | None) -> str:
    """Mask secret tokens and passwords for safe terminal/UI display."""
    cleaned = _clean_str(value)
    if not cleaned:
        return ""
    if len(cleaned) <= 4:
        return "*" * len(cleaned)
    if len(cleaned) <= 10:
        return f"{cleaned[:2]}{'*' * (len(cleaned) - 4)}{cleaned[-2:]}"
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def _mask_proxy_userinfo(raw_url: str) -> str:
    cleaned = raw_url.strip()
    has_scheme = "://" in cleaned
    try:
        parsed = urlsplit(cleaned if has_scheme else f"//{cleaned}")
        if parsed.username is None and parsed.password is None:
            return cleaned
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port_suffix = f":{parsed.port}" if parsed.port is not None else ""
        scheme_prefix = f"{parsed.scheme}://" if has_scheme and parsed.scheme else ""
        return f"{scheme_prefix}***@{host}{port_suffix}{parsed.path}"
    except ValueError:
        return "***"


def format_setting_display(
    key: str,
    value: str | None,
    *,
    reveal: bool = False,
) -> str:
    """Format a setting value for display, masking secrets unless ``reveal=True``."""
    cleaned = _clean_str(value)
    if cleaned is None:
        return ""
    if reveal:
        return cleaned
    spec = SETTING_SPECS_BY_KEY.get(key)
    if spec is not None and spec.secret:
        return mask_secret(cleaned)
    if spec is not None and spec.mask_url_credentials:
        return _mask_proxy_userinfo(cleaned)
    return cleaned


def set_session_overrides(
    overrides: Mapping[str, str | None],
    *,
    vault_hydrated: bool = False,
) -> None:
    """Update process-local TUI session overrides without mutating ``os.environ``."""
    with _SESSION_LOCK:
        for key, val in overrides.items():
            canon = resolve_setting_key(key) or key.strip()
            cleaned = _clean_str(val)
            if cleaned is None:
                _SESSION_OVERRIDES.pop(canon, None)
                _VAULT_HYDRATED_KEYS.discard(canon)
            else:
                _SESSION_OVERRIDES[canon] = cleaned
                if vault_hydrated:
                    _VAULT_HYDRATED_KEYS.add(canon)
                else:
                    _VAULT_HYDRATED_KEYS.discard(canon)


def clear_session_overrides(keys: tuple[str, ...] | list[str] | None = None) -> None:
    """Clear all or selected process-local session overrides."""
    with _SESSION_LOCK:
        if keys is None:
            _SESSION_OVERRIDES.clear()
            _VAULT_HYDRATED_KEYS.clear()
        else:
            for key in keys:
                canon = resolve_setting_key(key) or key.strip()
                _SESSION_OVERRIDES.pop(canon, None)
                _VAULT_HYDRATED_KEYS.discard(canon)


def is_vault_hydrated_setting(key: str) -> bool:
    """Return True if ``key`` currently holds a vault-hydrated session override."""
    canon = resolve_setting_key(key) or key.strip()
    with _SESSION_LOCK:
        return canon in _VAULT_HYDRATED_KEYS and _SESSION_OVERRIDES.get(canon) is not None


def get_session_override(key: str) -> tuple[bool, str | None]:
    """Return ``(is_present, value)`` for a process-local session override."""
    canon = resolve_setting_key(key) or key.strip()
    with _SESSION_LOCK:
        if canon in _SESSION_OVERRIDES:
            return True, _SESSION_OVERRIDES[canon]
    return False, None


def get_saved_setting(
    key: str,
    *,
    profile: str | None = None,
    settings_path: Path | str | None = None,
) -> str | None:
    """Return a single saved setting from ``profile`` (or the active profile)."""
    canon = resolve_setting_key(key) or key.strip()
    prof = get_profile_settings(profile=profile, settings_path=settings_path)
    return _clean_str(prof.get(canon))


def get_env_override_for_setting(key: str) -> tuple[str, str] | None:
    """Return ``(env_var_name, normalized_value)`` if an env var is set for ``key``."""
    canon = resolve_setting_key(key) or key.strip()
    spec = SETTING_SPECS_BY_KEY.get(canon)
    if spec is None:
        return None

    if canon == "rf_verify_ssl":
        raw_verify = _clean_str(os.environ.get("RF_VERIFY_SSL"))
        if raw_verify is not None:
            return ("RF_VERIFY_SSL", raw_verify)
        for insecure_var in ("RF_INSECURE_SSL", "SOCLENS_INSECURE_SSL"):
            raw_insec = _clean_str(os.environ.get(insecure_var))
            if raw_insec is not None:
                low = raw_insec.lower()
                if low in _TRUTHY_VALUES:
                    return (insecure_var, "false")
                if low in _FALSY_VALUES:
                    return (insecure_var, "true")
                return (insecure_var, raw_insec)
        return None

    for env_name in spec.env_vars:
        raw_val = _clean_str(os.environ.get(env_name))
        if raw_val is not None:
            return (env_name, raw_val)
    return None


def get_setting_with_source(
    key: str,
    *,
    profile: str | None = None,
    settings_path: Path | str | None = None,
) -> tuple[str | None, str]:
    """Resolve ``(value, source)`` for ``key``.

    ``source`` is one of ``"session"``, ``"env:<VAR>"``, ``"settings"``,
    ``"default"``, or ``"unset"``.
    """
    canon = resolve_setting_key(key) or key.strip()
    spec = SETTING_SPECS_BY_KEY.get(canon)

    if profile is None:
        has_sess, sess_val = get_session_override(canon)
        if has_sess:
            return (sess_val, "session") if sess_val is not None else (None, "unset")

    env_hit = get_env_override_for_setting(canon)
    if env_hit is not None:
        return env_hit[1], f"env:{env_hit[0]}"

    saved = get_saved_setting(canon, profile=profile, settings_path=settings_path)
    if saved is not None:
        return saved, "settings"

    if spec is not None and spec.default is not None:
        return spec.default, "default"

    return None, "unset"


def get_effective_setting(
    key: str,
    *,
    include_default: bool = False,
    settings_path: Path | str | None = None,
) -> str | None:
    """Resolve a setting value checking session override, environment, and saved settings."""
    val, source = get_setting_with_source(key, settings_path=settings_path)
    if source == "default" and not include_default:
        return None
    return val


def collect_env_importable_settings() -> dict[str, str]:
    """Collect all recognized settings currently populated in ``os.environ``."""
    imported: dict[str, str] = {}
    for spec in SETTING_SPECS:
        hit = get_env_override_for_setting(spec.key)
        if hit is not None:
            imported[spec.key] = hit[1]
    return imported


def describe_all_settings(
    *,
    reveal: bool = False,
    profile: str | None = None,
    settings_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Build a structured summary of every registered setting, its value, and source."""
    saved_map = get_profile_settings(profile=profile, settings_path=settings_path)
    items: list[dict[str, Any]] = []
    for spec in SETTING_SPECS:
        val, source = get_setting_with_source(
            spec.key,
            profile=profile,
            settings_path=settings_path,
        )
        saved_val = _clean_str(saved_map.get(spec.key))
        env_hit = get_env_override_for_setting(spec.key)
        items.append(
            {
                "key": spec.key,
                "category": spec.category,
                "label": spec.label,
                "env_vars": list(spec.env_vars),
                "secret": spec.secret,
                "value": format_setting_display(spec.key, val, reveal=reveal),
                "saved_value": format_setting_display(spec.key, saved_val, reveal=reveal),
                "has_saved": saved_val is not None,
                "env_override": env_hit[0] if env_hit is not None else None,
                "source": source,
                "default": spec.default,
                "description": spec.description,
            }
        )
    return items


__all__ = [
    "APP_CONFIG_DIR_NAME",
    "DEFAULT_PROFILE",
    "ENCRYPTED_SETTINGS_CIPHER",
    "ENCRYPTED_SETTINGS_SCHEMA_VERSION",
    "ENCRYPTION_MODE_OS_KEYSTORE",
    "ENCRYPTION_MODE_PASSPHRASE",
    "MIN_PASSPHRASE_LENGTH",
    "SECRET_MANAGED_SETTING_KEYS",
    "SETTING_CATEGORIES",
    "SETTING_SPECS",
    "SETTING_SPECS_BY_KEY",
    "SETTINGS_FILENAME",
    "SETTINGS_SCHEMA_VERSION",
    "SUPPORTED_ENCRYPTION_MODES",
    "SUPPORTED_SECRET_PROVIDERS",
    "SettingSpec",
    "SettingsCryptoError",
    "SettingsDecryptionError",
    "SettingsKeystoreError",
    "SettingsLockedError",
    "TSS_AUTH_MODES",
    "VAULT_AUTH_MODES",
    "clear_profile_settings",
    "clear_session_overrides",
    "clear_unlocked_keys",
    "collect_env_importable_settings",
    "delete_profile",
    "describe_all_settings",
    "encrypt_settings_store",
    "format_setting_display",
    "get_active_profile_name",
    "get_effective_setting",
    "get_env_override_for_setting",
    "get_last_load_error",
    "get_profile_settings",
    "get_saved_setting",
    "get_setting_with_source",
    "get_settings_path",
    "get_settings_storage_info",
    "inspect_settings_encryption",
    "invalidate_settings_cache",
    "is_settings_locked",
    "is_vault_hydrated_setting",
    "list_profiles",
    "load_settings_store",
    "lock_settings",
    "mask_secret",
    "parse_s1_site_tenant_map",
    "parse_s1_tier_rules",
    "parse_vault_secret_map",
    "resolve_setting_key",
    "rotate_settings_key",
    "save_profile_settings",
    "serialize_vault_secret_map",
    "set_active_profile",
    "set_session_overrides",
    "unlock_settings",
    "validate_profile_name",
    "validate_settings_values",
]
