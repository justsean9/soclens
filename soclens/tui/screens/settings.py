"""Per-user Settings & Credentials editor pane for the SOCLens TUI."""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from textual import events, on, work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    ContentSwitcher,
    Input,
    OptionList,
    Select,
    Static,
)
from textual.widgets.option_list import Option

from soclens.client import RecordedFutureClient
from soclens.config import (
    SecretStoreConfig,
    format_ssl_verify_status,
    get_proxy_summary,
    get_rf_asi_key,
    get_rf_base_url,
    get_rf_pfi_token,
    get_rf_riskrecon_token,
    get_rf_sandbox_token,
    get_rf_token,
    get_rf_verify_ssl,
    get_secret_store_config,
    get_sentinelone_config,
    get_splunk_config,
    hydrate_secrets_from_store,
)
from soclens.secret_stores import build_secret_store_provider
from soclens.secret_stores.base import SECRET_PROVIDER_LABELS, SecretCatalogEntry
from soclens.sentinelone import SentinelOneClient
from soclens.settings import (
    DEFAULT_PROFILE,
    SECRET_MANAGED_SETTING_KEYS,
    SETTING_SPECS,
    SETTING_SPECS_BY_KEY,
    SUPPORTED_SECRET_PROVIDERS,
    TSS_AUTH_MODES,
    VAULT_AUTH_MODES,
    clear_profile_settings,
    clear_session_overrides,
    collect_env_importable_settings,
    delete_profile,
    get_active_profile_name,
    get_env_override_for_setting,
    get_profile_settings,
    get_session_override,
    get_setting_with_source,
    get_settings_storage_info,
    is_vault_hydrated_setting,
    list_profiles,
    mask_secret,
    parse_vault_secret_map,
    save_profile_settings,
    serialize_vault_secret_map,
    set_active_profile,
    set_session_overrides,
    validate_profile_name,
    validate_settings_values,
)
from soclens.splunk import SplunkValidator
from soclens.tui.screens.base import BaseSocPane

logger = logging.getLogger("soclens.tui.settings")

_SPLIT_HORIZONTAL_MIN_WIDTH = 96

_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("cat-rf", "Recorded Future API"),
    ("cat-splunk", "Splunk & Splunk ES"),
    ("cat-s1", "SentinelOne EDR"),
    ("cat-network", "Network, SSL & Proxy"),
    ("cat-workspace", "Workspace & Defaults"),
    ("cat-profiles", "Profiles & Storage"),
    ("cat-secrets", "Secret Manager (PAM / Vault)"),
)

_SECRET_MANAGED_VAULT_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("rf_api_token", "set-rf-api-token", "set-rf-api-token-vault"),
    ("rf_sandbox_token", "set-rf-sandbox-token", "set-rf-sandbox-token-vault"),
    ("rf_asi_api_key", "set-rf-asi-api-key", "set-rf-asi-api-key-vault"),
    ("rf_pfi_token", "set-rf-pfi-token", "set-rf-pfi-token-vault"),
    ("rf_riskrecon_token", "set-rf-riskrecon-token", "set-rf-riskrecon-token-vault"),
    ("splunk_token", "set-splunk-token", "set-splunk-token-vault"),
    ("splunk_username", "set-splunk-username", "set-splunk-username-vault"),
    ("splunk_password", "set-splunk-password", "set-splunk-password-vault"),
    ("s1_api_token", "set-s1-api-token", "set-s1-api-token-vault"),
    ("rf_llm_api_key", "set-rf-llm-api-key", "set-rf-llm-api-key-vault"),
)

_SECRET_MANAGED_INPUT_KEYS: frozenset[str] = frozenset(
    key for key, _inp_id, _sel_id in _SECRET_MANAGED_VAULT_FIELDS
)

_VAULT_SELECT_BY_KEY: dict[str, str] = {
    key: sel_id for key, _inp_id, sel_id in _SECRET_MANAGED_VAULT_FIELDS
}

_VAULT_BANNER_IDS: tuple[str, ...] = (
    "cat-rf-vault-banner",
    "cat-splunk-vault-banner",
    "cat-s1-vault-banner",
    "cat-workspace-vault-banner",
)

_VAULT_MODE_BANNER_TEXT = (
    "Secret Manager active: select a vault reference below "
    "(pulled secrets stay in memory only)."
)

_RF_URL_KEYS: frozenset[str] = frozenset(
    {
        "rf_base_url",
        "rf_sandbox_base_url",
        "rf_asi_base_url",
        "rf_pfi_base_url",
        "rf_riskrecon_base_url",
    }
)

# Map canonical setting key -> (category_pane_id, widget_id)
_KEY_TO_WIDGET: dict[str, tuple[str, str]] = {
    "rf_api_token": ("cat-rf", "set-rf-api-token"),
    "rf_sandbox_token": ("cat-rf", "set-rf-sandbox-token"),
    "rf_asi_api_key": ("cat-rf", "set-rf-asi-api-key"),
    "rf_pfi_token": ("cat-rf", "set-rf-pfi-token"),
    "rf_riskrecon_token": ("cat-rf", "set-rf-riskrecon-token"),
    "rf_base_url": ("cat-rf", "set-rf-base-url"),
    "rf_sandbox_base_url": ("cat-rf", "set-rf-sandbox-base-url"),
    "rf_asi_base_url": ("cat-rf", "set-rf-asi-base-url"),
    "rf_pfi_base_url": ("cat-rf", "set-rf-pfi-base-url"),
    "rf_riskrecon_base_url": ("cat-rf", "set-rf-riskrecon-base-url"),
    "splunk_host": ("cat-splunk", "set-splunk-host"),
    "splunk_token": ("cat-splunk", "set-splunk-token"),
    "splunk_username": ("cat-splunk", "set-splunk-username"),
    "splunk_password": ("cat-splunk", "set-splunk-password"),
    "splunk_app": ("cat-splunk", "set-splunk-app"),
    "splunk_verify_ssl": ("cat-splunk", "set-splunk-verify-ssl"),
    "s1_console_url": ("cat-s1", "set-s1-console-url"),
    "s1_api_token": ("cat-s1", "set-s1-api-token"),
    "s1_account_id": ("cat-s1", "set-s1-account-id"),
    "s1_site_id": ("cat-s1", "set-s1-site-id"),
    "s1_verify_ssl": ("cat-s1", "set-s1-verify-ssl"),
    "s1_timeout": ("cat-s1", "set-s1-timeout"),
    "rf_verify_ssl": ("cat-network", "set-rf-verify-ssl"),
    "rf_ca_bundle": ("cat-network", "set-rf-ca-bundle"),
    "https_proxy": ("cat-network", "set-https-proxy"),
    "http_proxy": ("cat-network", "set-http-proxy"),
    "no_proxy": ("cat-network", "set-no-proxy"),
    "soclens_home": ("cat-workspace", "set-soclens-home"),
    "rf_tui_image_protocol": ("cat-workspace", "set-rf-tui-image-protocol"),
    "soclens_default_table_fields": ("cat-workspace", "set-sigma-table-fields"),
    "soclens_default_suppress_fields": ("cat-workspace", "set-sigma-suppress-fields"),
    "soclens_tenant_field": ("cat-workspace", "set-sigma-tenant-field"),
    "rf_logo_overrides_file": ("cat-workspace", "set-logo-overrides-file"),
    "rf_ignored_hashes_file": ("cat-workspace", "set-ignored-hashes-file"),
    "rf_ignored_hashes": ("cat-workspace", "set-ignored-hashes"),
    "soclens_auto_approve": ("cat-workspace", "set-auto-approve"),
    "rf_llm_api_key": ("cat-workspace", "set-rf-llm-api-key"),
    "secret_provider": ("cat-secrets", "set-secret-provider"),
    "secret_store_verify_ssl": ("cat-secrets", "set-secret-store-verify-ssl"),
    "secret_store_timeout": ("cat-secrets", "set-pam-timeout"),
    "vault_secret_map": ("cat-secrets", "set-secret-provider"),
    "tss_base_url": ("cat-secrets", "set-tss-base-url"),
    "tss_auth_mode": ("cat-secrets", "set-tss-auth-mode"),
    "tss_username": ("cat-secrets", "set-tss-username"),
    "tss_password": ("cat-secrets", "set-tss-password"),
    "tss_domain": ("cat-secrets", "set-tss-domain"),
    "tss_client_id": ("cat-secrets", "set-tss-client-id"),
    "tss_client_secret": ("cat-secrets", "set-tss-client-secret"),
    "tss_access_token": ("cat-secrets", "set-tss-access-token"),
    "tss_platform_url": ("cat-secrets", "set-tss-platform-url"),
    "tss_folder_id": ("cat-secrets", "set-tss-folder-id"),
    "vault_addr": ("cat-secrets", "set-vault-addr"),
    "vault_auth_mode": ("cat-secrets", "set-vault-auth-mode"),
    "vault_token": ("cat-secrets", "set-vault-token"),
    "vault_role_id": ("cat-secrets", "set-vault-role-id"),
    "vault_secret_id": ("cat-secrets", "set-vault-secret-id"),
    "vault_auth_mount": ("cat-secrets", "set-vault-auth-mount"),
    "vault_kv_mount": ("cat-secrets", "set-vault-kv-mount"),
    "vault_namespace": ("cat-secrets", "set-vault-namespace"),
    "vault_prefix": ("cat-secrets", "set-vault-prefix"),
    "op_connect_url": ("cat-secrets", "set-op-connect-url"),
    "op_connect_token": ("cat-secrets", "set-op-connect-token"),
    "op_vault_id": ("cat-secrets", "set-op-vault-id"),
    "bw_serve_url": ("cat-secrets", "set-bw-serve-url"),
    "bw_master_password": ("cat-secrets", "set-bw-master-password"),
    "bw_folder_id": ("cat-secrets", "set-bw-folder-id"),
    "bw_collection_id": ("cat-secrets", "set-bw-collection-id"),
    "bw_organization_id": ("cat-secrets", "set-bw-organization-id"),
}

_SECRET_INPUT_IDS: tuple[str, ...] = (
    "set-rf-api-token",
    "set-rf-sandbox-token",
    "set-rf-asi-api-key",
    "set-rf-pfi-token",
    "set-rf-riskrecon-token",
    "set-splunk-token",
    "set-splunk-password",
    "set-s1-api-token",
    "set-rf-llm-api-key",
    "set-tss-password",
    "set-tss-client-secret",
    "set-tss-access-token",
    "set-vault-token",
    "set-vault-secret-id",
    "set-op-connect-token",
    "set-bw-master-password",
)

_INPUT_SPECS_SIMPLE: tuple[tuple[str, str, str], ...] = (
    ("rf_api_token", "set-rf-api-token", "Enter RF Core API token..."),
    ("rf_sandbox_token", "set-rf-sandbox-token", "Optional (falls back to Core token)"),
    ("rf_asi_api_key", "set-rf-asi-api-key", "Optional SecurityTrails / ASI key"),
    ("rf_pfi_token", "set-rf-pfi-token", "Optional (falls back to Core token)"),
    ("rf_riskrecon_token", "set-rf-riskrecon-token", "Optional RiskRecon bearer token"),
    ("rf_base_url", "set-rf-base-url", "Default: https://api.recordedfuture.com"),
    ("rf_sandbox_base_url", "set-rf-sandbox-base-url", "Default: https://sandbox.recordedfuture.com/api/v0"),
    ("rf_asi_base_url", "set-rf-asi-base-url", "Default: https://api.securitytrails.com/v2"),
    ("rf_pfi_base_url", "set-rf-pfi-base-url", "Default: https://pfi.regemini.com/api/v1"),
    ("rf_riskrecon_base_url", "set-rf-riskrecon-base-url", "Default: https://api.riskrecon.com/v1"),
    ("splunk_host", "set-splunk-host", "Default: https://127.0.0.1:8089"),
    ("splunk_token", "set-splunk-token", "Splunk bearer token (preferred)"),
    ("splunk_username", "set-splunk-username", "Splunk username (if no token)"),
    ("splunk_password", "set-splunk-password", "Splunk password"),
    ("splunk_app", "set-splunk-app", "Default: SplunkEnterpriseSecuritySuite"),
    ("s1_console_url", "set-s1-console-url", "e.g. https://tenant.sentinelone.net"),
    ("s1_api_token", "set-s1-api-token", "SentinelOne API v2.1 token"),
    ("s1_account_id", "set-s1-account-id", "Optional SentinelOne Account ID"),
    ("s1_site_id", "set-s1-site-id", "Optional SentinelOne Site ID"),
    ("s1_timeout", "set-s1-timeout", "Default: 30.0"),
    ("https_proxy", "set-https-proxy", "e.g. http://proxy.corp:8080"),
    ("http_proxy", "set-http-proxy", "e.g. http://proxy.corp:8080"),
    ("no_proxy", "set-no-proxy", "e.g. localhost,127.0.0.1,.corp.local"),
    ("soclens_home", "set-soclens-home", "Blank = current working directory"),
    ("soclens_default_table_fields", "set-sigma-table-fields", "Optional Splunk | table fields"),
    ("soclens_default_suppress_fields", "set-sigma-suppress-fields", "Optional alert.suppress.fields"),
    ("soclens_tenant_field", "set-sigma-tenant-field", "Optional tenant field name"),
    ("rf_logo_overrides_file", "set-logo-overrides-file", "Optional JSON overrides path"),
    ("rf_ignored_hashes_file", "set-ignored-hashes-file", "Optional ignored_hashes.txt path"),
    ("rf_ignored_hashes", "set-ignored-hashes", "Comma-separated SHA-256 hashes"),
    ("rf_llm_api_key", "set-rf-llm-api-key", "Optional API key for OpenAI-compatible local LLM"),
    ("secret_store_timeout", "set-pam-timeout", "Default: 15.0"),
    ("tss_base_url", "set-tss-base-url", "e.g. https://secrets.corp.local/SecretServer"),
    ("tss_platform_url", "set-tss-platform-url", "Optional Delinea Platform identity URL"),
    ("tss_username", "set-tss-username", "Secret Server username (OAuth2 password grant)"),
    ("tss_password", "set-tss-password", "Secret Server bootstrap password"),
    ("tss_domain", "set-tss-domain", "Optional Active Directory domain"),
    ("tss_client_id", "set-tss-client-id", "Delinea Platform OAuth2 client ID"),
    ("tss_client_secret", "set-tss-client-secret", "Delinea Platform OAuth2 client secret"),
    ("tss_access_token", "set-tss-access-token", "Pre-issued Secret Server bearer token"),
    ("tss_folder_id", "set-tss-folder-id", "Optional Secret Server folder ID filter"),
    ("vault_addr", "set-vault-addr", "e.g. https://vault.corp.local:8200"),
    ("vault_token", "set-vault-token", "HashiCorp Vault X-Vault-Token"),
    ("vault_role_id", "set-vault-role-id", "HashiCorp Vault AppRole role_id"),
    ("vault_secret_id", "set-vault-secret-id", "HashiCorp Vault AppRole secret_id"),
    ("vault_auth_mount", "set-vault-auth-mount", "Default: approle"),
    ("vault_kv_mount", "set-vault-kv-mount", "Default: secret"),
    ("vault_namespace", "set-vault-namespace", "Optional Vault Enterprise namespace"),
    ("vault_prefix", "set-vault-prefix", "Optional KV path prefix (e.g. soclens)"),
    ("op_connect_url", "set-op-connect-url", "e.g. https://connect.corp.local"),
    ("op_connect_token", "set-op-connect-token", "1Password Connect Bearer token"),
    ("op_vault_id", "set-op-vault-id", "Optional 1Password Vault UUID"),
    ("bw_serve_url", "set-bw-serve-url", "Default: http://127.0.0.1:8087"),
    (
        "bw_master_password",
        "set-bw-master-password",
        "Optional (blank by default; session/env preferred)",
    ),
    ("bw_folder_id", "set-bw-folder-id", "Optional Bitwarden folder UUID"),
    ("bw_collection_id", "set-bw-collection-id", "Optional Bitwarden collection UUID"),
    ("bw_organization_id", "set-bw-organization-id", "Optional Bitwarden organization UUID"),
)

_SSL_VERIFY_TRUE = frozenset({"1", "true", "yes", "on"})
_SSL_VERIFY_FALSE = frozenset({"0", "false", "no", "off"})


def _label_id(key: str) -> str:
    return f"lbl-{key.replace('_', '-')}"


def _input_widget_for_key(key: str) -> tuple[str, str]:
    return _KEY_TO_WIDGET.get(key, ("cat-rf", "set-rf-api-token"))


class SettingsPane(BaseSocPane):
    """Interactive per-user settings, credentials, SSL/proxy, and profile manager."""

    DEFAULT_CSS: ClassVar[str] = """
    SettingsPane .secret-provider-group {
        width: 1fr;
        height: auto;
    }
    SettingsPane .vault-mode-banner {
        height: auto;
        width: 1fr;
        margin: 0 0 1 0;
    }
    SettingsPane #settings-secrets-summary {
        height: auto;
        width: 1fr;
        margin-top: 1;
    }
    SettingsPane.settings-compact #settings-status {
        max-height: 2;
        overflow-y: auto;
    }
    SettingsPane.settings-compact #settings-storage-info {
        max-height: 2;
        border: none;
        overflow-y: auto;
    }
    """

    STATUS_ID = "settings-status"
    LOG_ID = ""
    LOG_SOURCE = "settings"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._populating_form = False
        self._internal_reloading = False
        self._catalog_entries: list[SecretCatalogEntry] = []
        self._catalog_provider: str = ""

    def _make_vault_select(self, select_id: str) -> Select[str]:
        return Select(
            [("Not Mapped (Unset / Env)", "")],
            allow_blank=False,
            value="",
            id=select_id,
            classes="setting-field",
            compact=True,
        )

    def compose(self) -> ComposeResult:
        yield Static("Settings & Credentials (Per-User Configuration)", classes="pane-title")
        yield Static(
            "Configure Recorded Future, Splunk, SentinelOne, SSL, and workspace defaults.",
            id="settings-status",
            classes="status-bar",
            markup=False,
        )
        yield Static("", id="settings-storage-info", classes="info-box", markup=False)

        with Horizontal(classes="action-row toolbar-row"):
            yield Button(
                "Save Settings",
                id="settings-save-btn",
                variant="primary",
                compact=True,
            )
            yield Button("Reload", id="settings-reload-btn", compact=True)
            yield Button("Import from Env", id="settings-import-env-btn", compact=True)
            yield Button("Test Connections", id="settings-test-all-btn", compact=True)
            yield Checkbox(
                "Show Secrets",
                value=False,
                id="settings-show-secrets",
                compact=True,
            )
            yield Button(
                "Clear Profile",
                id="settings-clear-btn",
                variant="error",
                compact=True,
            )

        with Container(id="settings-workspace", classes="split-workspace"):
            with Vertical(id="settings-nav-pane"):
                yield Static("Categories", classes="section-label")
                yield OptionList(
                    *(Option(title, id=cat_id) for cat_id, title in _CATEGORIES),
                    id="settings-category-list",
                    markup=False,
                    compact=True,
                )

            with Container(id="settings-form-pane"):
                with ContentSwitcher(initial="cat-rf", id="settings-category-switcher"):
                    with VerticalScroll(id="cat-rf", classes="settings-cat-scroll"):
                        yield Static(
                            "Recorded Future API Credentials",
                            classes="section-label",
                            markup=False,
                        )
                        yield Static(
                            _VAULT_MODE_BANNER_TEXT,
                            id="cat-rf-vault-banner",
                            classes="info-box vault-mode-banner",
                            markup=False,
                        )
                        yield self._make_label("rf_api_token")
                        yield Input(
                            value="",
                            password=True,
                            placeholder="Enter RF Core API token...",
                            id="set-rf-api-token",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_vault_select("set-rf-api-token-vault")
                        yield self._make_label("rf_sandbox_token")
                        yield Input(
                            value="",
                            password=True,
                            placeholder="Optional (falls back to Core token)",
                            id="set-rf-sandbox-token",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_vault_select("set-rf-sandbox-token-vault")
                        yield self._make_label("rf_asi_api_key")
                        yield Input(
                            value="",
                            password=True,
                            placeholder="Optional SecurityTrails / ASI key",
                            id="set-rf-asi-api-key",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_vault_select("set-rf-asi-api-key-vault")
                        yield self._make_label("rf_pfi_token")
                        yield Input(
                            value="",
                            password=True,
                            placeholder="Optional (falls back to Core token)",
                            id="set-rf-pfi-token",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_vault_select("set-rf-pfi-token-vault")
                        yield self._make_label("rf_riskrecon_token")
                        yield Input(
                            value="",
                            password=True,
                            placeholder="Optional RiskRecon bearer token",
                            id="set-rf-riskrecon-token",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_vault_select("set-rf-riskrecon-token-vault")
                        with Horizontal(classes="action-row toolbar-row"):
                            yield Button(
                                "Test RF Connection",
                                id="settings-test-rf-btn",
                                compact=True,
                            )
                        with Collapsible(
                            title="Advanced: Custom Recorded Future API Base URLs",
                            collapsed=True,
                            id="settings-rf-urls-collapsible",
                        ):
                            yield self._make_label("rf_base_url")
                            yield Input(
                                value="",
                                placeholder="Default: https://api.recordedfuture.com",
                                id="set-rf-base-url",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("rf_sandbox_base_url")
                            yield Input(
                                value="",
                                placeholder="Default: https://sandbox.recordedfuture.com/api/v0",
                                id="set-rf-sandbox-base-url",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("rf_asi_base_url")
                            yield Input(
                                value="",
                                placeholder="Default: https://api.securitytrails.com/v2",
                                id="set-rf-asi-base-url",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("rf_pfi_base_url")
                            yield Input(
                                value="",
                                placeholder="Default: https://pfi.regemini.com/api/v1",
                                id="set-rf-pfi-base-url",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("rf_riskrecon_base_url")
                            yield Input(
                                value="",
                                placeholder="Default: https://api.riskrecon.com/v1",
                                id="set-rf-riskrecon-base-url",
                                classes="setting-field",
                                compact=True,
                            )

                    with VerticalScroll(id="cat-splunk", classes="settings-cat-scroll"):
                        yield Static(
                            "Splunk & Splunk ES Connection",
                            classes="section-label",
                            markup=False,
                        )
                        yield Static(
                            _VAULT_MODE_BANNER_TEXT,
                            id="cat-splunk-vault-banner",
                            classes="info-box vault-mode-banner",
                            markup=False,
                        )
                        yield self._make_label("splunk_host")
                        yield Input(
                            value="",
                            placeholder="Default: https://127.0.0.1:8089",
                            id="set-splunk-host",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("splunk_token")
                        yield Input(
                            value="",
                            password=True,
                            placeholder="Splunk bearer token (preferred)",
                            id="set-splunk-token",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_vault_select("set-splunk-token-vault")
                        yield self._make_label("splunk_username")
                        yield Input(
                            value="",
                            placeholder="Splunk username (if no token)",
                            id="set-splunk-username",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_vault_select("set-splunk-username-vault")
                        yield self._make_label("splunk_password")
                        yield Input(
                            value="",
                            password=True,
                            placeholder="Splunk password",
                            id="set-splunk-password",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_vault_select("set-splunk-password-vault")
                        yield self._make_label("splunk_app")
                        yield Input(
                            value="",
                            placeholder="Default: SplunkEnterpriseSecuritySuite",
                            id="set-splunk-app",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("splunk_verify_ssl")
                        yield Select(
                            [
                                ("False (Default for Self-Signed)", "false"),
                                ("True (Verify SSL)", "true"),
                                ("Custom CA Bundle Path", "custom"),
                            ],
                            allow_blank=False,
                            value="false",
                            id="set-splunk-verify-ssl",
                            classes="setting-field",
                            compact=True,
                        )
                        yield Input(
                            value="",
                            placeholder="Path to Splunk custom CA PEM bundle...",
                            id="set-splunk-ca-bundle",
                            classes="setting-field",
                            disabled=True,
                            compact=True,
                        )
                        with Horizontal(classes="action-row toolbar-row"):
                            yield Button(
                                "Test Splunk Connection",
                                id="settings-test-splunk-btn",
                                compact=True,
                            )

                    with VerticalScroll(id="cat-s1", classes="settings-cat-scroll"):
                        yield Static(
                            "SentinelOne Management API v2.1",
                            classes="section-label",
                            markup=False,
                        )
                        yield Static(
                            _VAULT_MODE_BANNER_TEXT,
                            id="cat-s1-vault-banner",
                            classes="info-box vault-mode-banner",
                            markup=False,
                        )
                        yield self._make_label("s1_console_url")
                        yield Input(
                            value="",
                            placeholder="e.g. https://tenant.sentinelone.net",
                            id="set-s1-console-url",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("s1_api_token")
                        yield Input(
                            value="",
                            password=True,
                            placeholder="SentinelOne API v2.1 token",
                            id="set-s1-api-token",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_vault_select("set-s1-api-token-vault")
                        yield self._make_label("s1_account_id")
                        yield Input(
                            value="",
                            placeholder="Optional SentinelOne Account ID",
                            id="set-s1-account-id",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("s1_site_id")
                        yield Input(
                            value="",
                            placeholder="Optional SentinelOne Site ID",
                            id="set-s1-site-id",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("s1_verify_ssl")
                        yield Select(
                            [
                                ("Inherit RF SSL Setting (Default)", ""),
                                ("True (Verify SSL)", "true"),
                                ("False (Insecure)", "false"),
                                ("Custom CA Bundle Path", "custom"),
                            ],
                            allow_blank=False,
                            value="",
                            id="set-s1-verify-ssl",
                            classes="setting-field",
                            compact=True,
                        )
                        yield Input(
                            value="",
                            placeholder="Path to SentinelOne custom CA PEM bundle...",
                            id="set-s1-ca-bundle",
                            classes="setting-field",
                            disabled=True,
                            compact=True,
                        )
                        yield self._make_label("s1_timeout")
                        yield Input(
                            value="",
                            placeholder="Default: 30.0",
                            id="set-s1-timeout",
                            classes="setting-field",
                            compact=True,
                        )
                        with Horizontal(classes="action-row toolbar-row"):
                            yield Button(
                                "Test SentinelOne Connection",
                                id="settings-test-s1-btn",
                                compact=True,
                            )

                    with VerticalScroll(id="cat-network", classes="settings-cat-scroll"):
                        yield Static("Network, SSL Verification & Proxy", classes="section-label")
                        yield self._make_label("rf_verify_ssl")
                        yield Select(
                            [
                                ("Verified (Default)", "true"),
                                ("Insecure Proxy Mode (Disable SSL Verify)", "false"),
                                ("Custom CA Bundle Path", "custom"),
                            ],
                            allow_blank=False,
                            value="true",
                            id="set-rf-verify-ssl",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("rf_ca_bundle")
                        yield Input(
                            value="",
                            placeholder="Path to custom PEM CA certificate bundle...",
                            id="set-rf-ca-bundle",
                            classes="setting-field",
                            disabled=True,
                            compact=True,
                        )
                        yield self._make_label("https_proxy")
                        yield Input(
                            value="",
                            placeholder="e.g. http://proxy.corp:8080",
                            id="set-https-proxy",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("http_proxy")
                        yield Input(
                            value="",
                            placeholder="e.g. http://proxy.corp:8080",
                            id="set-http-proxy",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("no_proxy")
                        yield Input(
                            value="",
                            placeholder="e.g. localhost,127.0.0.1,.corp.local",
                            id="set-no-proxy",
                            classes="setting-field",
                            compact=True,
                        )

                    with VerticalScroll(id="cat-workspace", classes="settings-cat-scroll"):
                        yield Static(
                            "Workspace, Sigma, Brand Logos & CLI Defaults",
                            classes="section-label",
                            markup=False,
                        )
                        yield Static(
                            _VAULT_MODE_BANNER_TEXT,
                            id="cat-workspace-vault-banner",
                            classes="info-box vault-mode-banner",
                            markup=False,
                        )
                        yield self._make_label("soclens_home")
                        yield Input(
                            value="",
                            placeholder="Blank = current working directory",
                            id="set-soclens-home",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("rf_tui_image_protocol")
                        yield Select(
                            [
                                ("Auto-Detect (Recommended)", ""),
                                ("Kitty / Ghostty HD", "kitty"),
                                ("iTerm2 / WezTerm HD", "iterm2"),
                                ("Sixel HD (Windows Terminal / Konsole)", "sixel"),
                                ("Half-Block Unicode", "halfblock"),
                            ],
                            allow_blank=False,
                            value="",
                            id="set-rf-tui-image-protocol",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("soclens_default_table_fields")
                        yield Input(
                            value="",
                            placeholder="Optional Splunk | table fields",
                            id="set-sigma-table-fields",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("soclens_default_suppress_fields")
                        yield Input(
                            value="",
                            placeholder="Optional alert.suppress.fields",
                            id="set-sigma-suppress-fields",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("soclens_tenant_field")
                        yield Input(
                            value="",
                            placeholder="Optional tenant field name",
                            id="set-sigma-tenant-field",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("rf_logo_overrides_file")
                        yield Input(
                            value="",
                            placeholder="Optional JSON overrides path",
                            id="set-logo-overrides-file",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("rf_ignored_hashes_file")
                        yield Input(
                            value="",
                            placeholder="Optional ignored_hashes.txt path",
                            id="set-ignored-hashes-file",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("rf_ignored_hashes")
                        yield Input(
                            value="",
                            placeholder="Comma-separated SHA-256 hashes",
                            id="set-ignored-hashes",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_label("soclens_auto_approve")
                        yield Checkbox(
                            "Auto-Approve CLI Writes (SOCLENS_AUTO_APPROVE)",
                            value=False,
                            id="set-auto-approve",
                            compact=True,
                        )
                        yield self._make_label("rf_llm_api_key")
                        yield Input(
                            value="",
                            password=True,
                            placeholder="Optional API key for OpenAI-compatible local LLM",
                            id="set-rf-llm-api-key",
                            classes="setting-field",
                            compact=True,
                        )
                        yield self._make_vault_select("set-rf-llm-api-key-vault")

                    with VerticalScroll(id="cat-profiles", classes="settings-cat-scroll"):
                        yield Static("Named Profiles & Per-User Storage", classes="section-label")
                        yield Static("Active Profile", classes="setting-label", markup=False)
                        with Horizontal(classes="action-row toolbar-row"):
                            yield Select(
                                [(DEFAULT_PROFILE, DEFAULT_PROFILE)],
                                allow_blank=False,
                                value=DEFAULT_PROFILE,
                                id="set-profile-select",
                                compact=True,
                            )
                            yield Button(
                                "Switch Profile",
                                id="settings-switch-profile-btn",
                                compact=True,
                            )
                            yield Button(
                                "Delete Profile",
                                id="settings-delete-profile-btn",
                                variant="error",
                                compact=True,
                            )
                        yield Static("Create New Profile", classes="setting-label", markup=False)
                        with Horizontal(classes="action-row toolbar-row"):
                            yield Input(
                                value="",
                                placeholder="New profile name (e.g. prod, lab)...",
                                id="set-new-profile-input",
                                compact=True,
                            )
                            yield Button(
                                "Create & Activate",
                                id="settings-create-profile-btn",
                                variant="primary",
                                compact=True,
                            )
                        yield Static(
                            "",
                            id="settings-storage-details",
                            classes="info-box",
                            markup=False,
                        )

                    with VerticalScroll(id="cat-secrets", classes="settings-cat-scroll"):
                        yield Static(
                            "Secret Manager / PAM Integration",
                            classes="section-label",
                            markup=False,
                        )
                        yield self._make_label("secret_provider")
                        yield Select(
                            [(SECRET_PROVIDER_LABELS[p], p) for p in SUPPORTED_SECRET_PROVIDERS],
                            allow_blank=False,
                            value="none",
                            id="set-secret-provider",
                            classes="setting-field",
                            compact=True,
                        )
                        with Horizontal(classes="action-row toolbar-row"):
                            yield Button(
                                "Test Secret Manager",
                                id="settings-test-secrets-btn",
                                compact=True,
                            )
                            yield Button(
                                "Refresh Vault Catalog",
                                id="settings-refresh-vault-btn",
                                variant="primary",
                                compact=True,
                            )
                            yield Button(
                                "Pull Secrets into Session",
                                id="settings-pull-secrets-btn",
                                compact=True,
                            )
                        yield Static(
                            "",
                            id="settings-secrets-summary",
                            classes="info-box",
                            markup=False,
                        )
                        yield self._make_label("secret_store_verify_ssl")
                        yield Select(
                            [
                                ("Inherit RF SSL Setting (Default)", ""),
                                ("True (Verify SSL)", "true"),
                                ("False (Insecure)", "false"),
                                ("Custom CA Bundle Path", "custom"),
                            ],
                            allow_blank=False,
                            value="",
                            id="set-secret-store-verify-ssl",
                            classes="setting-field",
                            compact=True,
                        )
                        yield Input(
                            value="",
                            placeholder="Path to Secret Manager custom CA PEM bundle...",
                            id="set-pam-ca-bundle",
                            classes="setting-field",
                            disabled=True,
                            compact=True,
                        )
                        yield self._make_label("secret_store_timeout")
                        yield Input(
                            value="",
                            placeholder="Default: 15.0",
                            id="set-pam-timeout",
                            classes="setting-field",
                            compact=True,
                        )

                        with Vertical(id="tss-fields-group", classes="secret-provider-group"):
                            yield Static(
                                "Thycotic / Delinea Secret Server",
                                classes="section-label",
                                markup=False,
                            )
                            yield self._make_label("tss_base_url")
                            yield Input(
                                value="",
                                placeholder="e.g. https://secrets.corp.local/SecretServer",
                                id="set-tss-base-url",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("tss_auth_mode")
                            yield Select(
                                [
                                    ("Password Grant (OAuth2)", "password"),
                                    ("Delinea Platform (Client Credentials)", "platform"),
                                    ("Pre-Issued Bearer Token", "token"),
                                ],
                                allow_blank=False,
                                value="password",
                                id="set-tss-auth-mode",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("tss_platform_url")
                            yield Input(
                                value="",
                                placeholder="Optional Delinea Platform identity URL",
                                id="set-tss-platform-url",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("tss_username")
                            yield Input(
                                value="",
                                placeholder="Secret Server username (OAuth2 password grant)",
                                id="set-tss-username",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("tss_password")
                            yield Input(
                                value="",
                                password=True,
                                placeholder="Secret Server bootstrap password",
                                id="set-tss-password",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("tss_domain")
                            yield Input(
                                value="",
                                placeholder="Optional Active Directory domain",
                                id="set-tss-domain",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("tss_client_id")
                            yield Input(
                                value="",
                                placeholder="Delinea Platform OAuth2 client ID",
                                id="set-tss-client-id",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("tss_client_secret")
                            yield Input(
                                value="",
                                password=True,
                                placeholder="Delinea Platform OAuth2 client secret",
                                id="set-tss-client-secret",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("tss_access_token")
                            yield Input(
                                value="",
                                password=True,
                                placeholder="Pre-issued Secret Server bearer token",
                                id="set-tss-access-token",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("tss_folder_id")
                            yield Input(
                                value="",
                                placeholder="Optional Secret Server folder ID filter",
                                id="set-tss-folder-id",
                                classes="setting-field",
                                compact=True,
                            )

                        with Vertical(id="vault-fields-group", classes="secret-provider-group"):
                            yield Static(
                                "HashiCorp Vault (KV v2)",
                                classes="section-label",
                                markup=False,
                            )
                            yield self._make_label("vault_addr")
                            yield Input(
                                value="",
                                placeholder="e.g. https://vault.corp.local:8200",
                                id="set-vault-addr",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("vault_auth_mode")
                            yield Select(
                                [
                                    ("Token Auth (X-Vault-Token)", "token"),
                                    ("AppRole Auth (Role ID + Secret ID)", "approle"),
                                ],
                                allow_blank=False,
                                value="token",
                                id="set-vault-auth-mode",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("vault_token")
                            yield Input(
                                value="",
                                password=True,
                                placeholder="HashiCorp Vault X-Vault-Token",
                                id="set-vault-token",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("vault_role_id")
                            yield Input(
                                value="",
                                placeholder="HashiCorp Vault AppRole role_id",
                                id="set-vault-role-id",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("vault_secret_id")
                            yield Input(
                                value="",
                                password=True,
                                placeholder="HashiCorp Vault AppRole secret_id",
                                id="set-vault-secret-id",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("vault_auth_mount")
                            yield Input(
                                value="",
                                placeholder="Default: approle",
                                id="set-vault-auth-mount",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("vault_kv_mount")
                            yield Input(
                                value="",
                                placeholder="Default: secret",
                                id="set-vault-kv-mount",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("vault_namespace")
                            yield Input(
                                value="",
                                placeholder="Optional Vault Enterprise namespace",
                                id="set-vault-namespace",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("vault_prefix")
                            yield Input(
                                value="",
                                placeholder="Optional KV path prefix (e.g. soclens)",
                                id="set-vault-prefix",
                                classes="setting-field",
                                compact=True,
                            )

                        with Vertical(id="op-fields-group", classes="secret-provider-group"):
                            yield Static(
                                "1Password Connect Server",
                                classes="section-label",
                                markup=False,
                            )
                            yield self._make_label("op_connect_url")
                            yield Input(
                                value="",
                                placeholder="e.g. https://connect.corp.local",
                                id="set-op-connect-url",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("op_connect_token")
                            yield Input(
                                value="",
                                password=True,
                                placeholder="1Password Connect Bearer token",
                                id="set-op-connect-token",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("op_vault_id")
                            yield Input(
                                value="",
                                placeholder="Optional 1Password Vault UUID",
                                id="set-op-vault-id",
                                classes="setting-field",
                                compact=True,
                            )

                        with Vertical(id="bw-fields-group", classes="secret-provider-group"):
                            yield Static(
                                "Bitwarden (bw serve)",
                                classes="section-label",
                                markup=False,
                            )
                            yield self._make_label("bw_serve_url")
                            yield Input(
                                value="",
                                placeholder="Default: http://127.0.0.1:8087",
                                id="set-bw-serve-url",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("bw_master_password")
                            yield Input(
                                value="",
                                password=True,
                                placeholder="Optional (blank by default; session/env preferred)",
                                id="set-bw-master-password",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("bw_folder_id")
                            yield Input(
                                value="",
                                placeholder="Optional Bitwarden folder UUID",
                                id="set-bw-folder-id",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("bw_collection_id")
                            yield Input(
                                value="",
                                placeholder="Optional Bitwarden collection UUID",
                                id="set-bw-collection-id",
                                classes="setting-field",
                                compact=True,
                            )
                            yield self._make_label("bw_organization_id")
                            yield Input(
                                value="",
                                placeholder="Optional Bitwarden organization UUID",
                                id="set-bw-organization-id",
                                classes="setting-field",
                                compact=True,
                            )

    def _make_label(self, key: str) -> Static:
        spec = SETTING_SPECS_BY_KEY[key]
        return Static(
            spec.label,
            id=_label_id(key),
            classes="setting-label",
            markup=False,
        )

    def on_mount(self) -> None:
        self._update_responsive_layout()
        self._load_form_from_store()
        try:
            nav = self.query_one("#settings-category-list", OptionList)
            nav.highlighted = 0
        except Exception:
            pass

    def on_resize(self) -> None:
        self._update_responsive_layout()

    def on_tab_activated(self) -> None:
        self._update_responsive_layout()
        self._sync_secret_manager_field_modes()
        self._refresh_storage_banners()
        self._refresh_secrets_summary()
        self._refresh_field_badges()

    def on_settings_updated(self) -> None:
        if self._internal_reloading:
            return
        self._load_form_from_store()

    def _update_responsive_layout(self) -> None:
        try:
            is_horizontal = self.size.width >= _SPLIT_HORIZONTAL_MIN_WIDTH
            is_compact = (not is_horizontal) or self.size.height <= 26
            self.set_class(is_compact, "settings-compact")

            ws = self.query_one("#settings-workspace", Container)
            if is_horizontal:
                ws.add_class("split-horizontal")
            else:
                ws.remove_class("split-horizontal")

            nav = self.query_one("#settings-nav-pane", Vertical)
            cat_list = self.query_one("#settings-category-list", OptionList)
            form_pane = self.query_one("#settings-form-pane", Container)

            if is_compact:
                ws.styles.height = "1fr"
                ws.styles.min_height = 6
                form_pane.styles.height = "1fr"
                form_pane.styles.min_height = 6
                if is_horizontal:
                    nav.styles.height = "1fr"
                    nav.styles.max_height = "1fr"
                    cat_list.styles.border = None
                else:
                    nav.styles.height = 4
                    nav.styles.max_height = 4
                    cat_list.styles.border = ("none", "transparent")
            else:
                ws.styles.height = None
                ws.styles.min_height = None
                nav.styles.height = None
                nav.styles.max_height = None
                cat_list.styles.border = None
                form_pane.styles.height = None
                form_pane.styles.min_height = None

            label_margin = (0, 0, 0, 0) if is_compact else None
            for lbl in self.query(".setting-label"):
                lbl.styles.margin = label_margin
        except Exception:
            pass

    def _sync_ca_inputs_enabled(self) -> None:
        try:
            rf_sel = str(self.query_one("#set-rf-verify-ssl", Select).value)
            rf_ca = self.query_one("#set-rf-ca-bundle", Input)
            rf_ca.disabled = rf_sel != "custom"
        except Exception:
            pass
        try:
            sp_sel = str(self.query_one("#set-splunk-verify-ssl", Select).value)
            sp_ca = self.query_one("#set-splunk-ca-bundle", Input)
            sp_ca.disabled = sp_sel != "custom"
        except Exception:
            pass
        try:
            s1_sel = str(self.query_one("#set-s1-verify-ssl", Select).value)
            s1_ca = self.query_one("#set-s1-ca-bundle", Input)
            s1_ca.disabled = s1_sel != "custom"
        except Exception:
            pass
        try:
            ss_sel = str(self.query_one("#set-secret-store-verify-ssl", Select).value)
            ss_ca = self.query_one("#set-pam-ca-bundle", Input)
            ss_ca.disabled = ss_sel != "custom"
        except Exception:
            pass

    def _sync_secret_manager_field_modes(self) -> None:
        try:
            provider = str(
                self.query_one("#set-secret-provider", Select).value or "none"
            ).strip().lower()
        except Exception:
            provider = "none"
        enabled = provider != "none"

        for grp_id, target_prov in (
            ("#tss-fields-group", "secret_server"),
            ("#vault-fields-group", "hashicorp_vault"),
            ("#op-fields-group", "onepassword_connect"),
            ("#bw-fields-group", "bitwarden"),
        ):
            try:
                self.query_one(grp_id).display = provider == target_prov
            except Exception:
                pass

        for banner_id in _VAULT_BANNER_IDS:
            try:
                self.query_one(f"#{banner_id}", Static).display = enabled
            except Exception:
                pass

        for _key, inp_id, vault_sel_id in _SECRET_MANAGED_VAULT_FIELDS:
            try:
                self.query_one(f"#{inp_id}", Input).display = not enabled
            except Exception:
                pass
            try:
                self.query_one(f"#{vault_sel_id}", Select).display = enabled
            except Exception:
                pass

    def _populate_vault_dropdowns(
        self,
        entries: Sequence[SecretCatalogEntry],
        saved_map: Mapping[str, str],
        *,
        preserve_current: bool = False,
    ) -> None:
        try:
            raw_map = saved_map.get("vault_secret_map")
            saved_refs = parse_vault_secret_map(raw_map, strict=False)
        except ValueError:
            saved_refs = {}

        try:
            provider = str(
                self.query_one("#set-secret-provider", Select).value or "none"
            ).strip().lower()
        except Exception:
            provider = "none"

        unique_entries: list[SecretCatalogEntry] = []
        seen_refs: set[str] = set()
        for entry in entries:
            if provider != "none" and entry.provider != provider:
                continue
            if not entry.ref or entry.ref in seen_refs:
                continue
            seen_refs.add(entry.ref)
            unique_entries.append(entry)

        base_options: list[tuple[str, str]] = [("Not Mapped (Unset / Env)", "")]
        for entry in unique_entries:
            base_options.append((entry.display_label, entry.ref))
        known_refs = {ref for _lbl, ref in base_options}

        def _matches_provider(ref_val: str) -> bool:
            if not ref_val:
                return False
            if provider == "none":
                return True
            if ref_val.startswith(f"{provider}:"):
                return True
            prefix = ref_val.split(":", 1)[0].strip().lower() if ":" in ref_val else ""
            return prefix not in SUPPORTED_SECRET_PROVIDERS

        for key, _inp_id, vault_sel_id in _SECRET_MANAGED_VAULT_FIELDS:
            sel = self.query_one(f"#{vault_sel_id}", Select)
            target_ref = ""
            if preserve_current:
                cur_val = str(sel.value or "").strip()
                if _matches_provider(cur_val):
                    target_ref = cur_val
            if not target_ref:
                saved_cand = saved_refs.get(key, "").strip()
                if _matches_provider(saved_cand):
                    target_ref = saved_cand

            opts = list(base_options)
            if target_ref and target_ref not in known_refs:
                opts.append((f"{target_ref} (Saved - Refresh to Verify)", target_ref))

            with sel.prevent(Select.Changed):
                sel.set_options(opts)
                sel.value = target_ref

    def _refresh_secrets_summary(self, saved_map: Mapping[str, str] | None = None) -> None:
        try:
            summary_widget = self.query_one("#settings-secrets-summary", Static)
        except Exception:
            return
        active_map = (
            dict(saved_map)
            if saved_map is not None
            else get_profile_settings(profile=get_active_profile_name())
        )
        try:
            provider = str(
                self.query_one("#set-secret-provider", Select).value
                or active_map.get("secret_provider")
                or "none"
            ).strip().lower()
        except Exception:
            provider = str(active_map.get("secret_provider") or "none").strip().lower()

        provider_label = SECRET_PROVIDER_LABELS.get(provider, provider)
        mapped_refs: dict[str, str] = {}
        if provider != "none":
            for key, _inp_id, vault_sel_id in _SECRET_MANAGED_VAULT_FIELDS:
                try:
                    ref_val = str(self.query_one(f"#{vault_sel_id}", Select).value or "").strip()
                except Exception:
                    ref_val = ""
                if ref_val:
                    mapped_refs[key] = ref_val
        if not mapped_refs:
            saved_provider = str(active_map.get("secret_provider") or "none").strip().lower()
            if provider == saved_provider:
                try:
                    mapped_refs = parse_vault_secret_map(
                        active_map.get("vault_secret_map"), strict=False
                    )
                except ValueError:
                    mapped_refs = {}

        hydrated_keys = [
            key for key in SECRET_MANAGED_SETTING_KEYS if is_vault_hydrated_setting(key)
        ]
        mapped_desc = ", ".join(sorted(mapped_refs.keys())) if mapped_refs else "None"
        hydrated_desc = ", ".join(hydrated_keys) if hydrated_keys else "None"
        catalog_count = len(self._catalog_entries)
        summary_widget.update(
            f"Provider: {provider_label} | Catalog Entries: {catalog_count}\n"
            f"Mapped Keys ({len(mapped_refs)}): {mapped_desc}\n"
            f"Session-Hydrated Keys ({len(hydrated_keys)}): {hydrated_desc} "
            "(memory-only; never saved to settings.json)"
        )

    def _form_value_for_display(self, key: str, saved_map: dict[str, str]) -> str | None:
        if is_vault_hydrated_setting(key):
            return saved_map.get(key)
        has_sess, sess_val = get_session_override(key)
        if has_sess:
            return sess_val
        return saved_map.get(key)

    def _load_form_from_store(self) -> None:
        self._populating_form = True
        try:
            active_profile = get_active_profile_name()
            saved_map = get_profile_settings(profile=active_profile)

            for key, widget_id, placeholder in _INPUT_SPECS_SIMPLE:
                inp = self.query_one(f"#{widget_id}", Input)
                val = self._form_value_for_display(key, saved_map)
                inp.value = val or ""
                env_hit = get_env_override_for_setting(key)
                if env_hit is not None and val is None:
                    inp.placeholder = f"Active from ENV ({env_hit[0]}) - click Import from Env or enter value"
                else:
                    inp.placeholder = placeholder

            # Secret Manager provider & auth modes
            raw_prov = (
                self._form_value_for_display("secret_provider", saved_map) or "none"
            ).strip().lower()
            prov_sel = self.query_one("#set-secret-provider", Select)
            with prov_sel.prevent(Select.Changed):
                prov_sel.value = (
                    raw_prov if raw_prov in SUPPORTED_SECRET_PROVIDERS else "none"
                )

            raw_tss_mode = (
                self._form_value_for_display("tss_auth_mode", saved_map) or "password"
            ).strip().lower()
            tss_mode_sel = self.query_one("#set-tss-auth-mode", Select)
            with tss_mode_sel.prevent(Select.Changed):
                tss_mode_sel.value = (
                    raw_tss_mode if raw_tss_mode in TSS_AUTH_MODES else "password"
                )

            raw_vault_mode = (
                self._form_value_for_display("vault_auth_mode", saved_map) or "token"
            ).strip().lower()
            vault_mode_sel = self.query_one("#set-vault-auth-mode", Select)
            with vault_mode_sel.prevent(Select.Changed):
                vault_mode_sel.value = (
                    raw_vault_mode if raw_vault_mode in VAULT_AUTH_MODES else "token"
                )

            ss_verify_val = self._form_value_for_display("secret_store_verify_ssl", saved_map)
            ss_sel = self.query_one("#set-secret-store-verify-ssl", Select)
            ss_ca = self.query_one("#set-pam-ca-bundle", Input)
            with ss_sel.prevent(Select.Changed):
                if ss_verify_val is None:
                    ss_sel.value = ""
                    ss_ca.value = ""
                else:
                    low = ss_verify_val.strip().lower()
                    if low in _SSL_VERIFY_TRUE:
                        ss_sel.value = "true"
                        ss_ca.value = ""
                    elif low in _SSL_VERIFY_FALSE:
                        ss_sel.value = "false"
                        ss_ca.value = ""
                    else:
                        ss_sel.value = "custom"
                        ss_ca.value = ss_verify_val

            # Network RF SSL verification & CA bundle
            rf_verify_val = self._form_value_for_display("rf_verify_ssl", saved_map)
            rf_ca_val = self._form_value_for_display("rf_ca_bundle", saved_map)
            rf_verify_sel = self.query_one("#set-rf-verify-ssl", Select)
            rf_ca_input = self.query_one("#set-rf-ca-bundle", Input)
            with rf_verify_sel.prevent(Select.Changed):
                if rf_ca_val:
                    rf_verify_sel.value = "custom"
                    rf_ca_input.value = rf_ca_val
                elif rf_verify_val is not None:
                    low = rf_verify_val.strip().lower()
                    if low in _SSL_VERIFY_FALSE:
                        rf_verify_sel.value = "false"
                        rf_ca_input.value = ""
                    elif low in _SSL_VERIFY_TRUE:
                        rf_verify_sel.value = "true"
                        rf_ca_input.value = ""
                    else:
                        rf_verify_sel.value = "custom"
                        rf_ca_input.value = rf_verify_val
                else:
                    rf_verify_sel.value = "true"
                    rf_ca_input.value = ""

            # Splunk SSL
            sp_verify_val = self._form_value_for_display("splunk_verify_ssl", saved_map)
            sp_sel = self.query_one("#set-splunk-verify-ssl", Select)
            sp_ca = self.query_one("#set-splunk-ca-bundle", Input)
            with sp_sel.prevent(Select.Changed):
                if sp_verify_val is None:
                    sp_sel.value = "false"
                    sp_ca.value = ""
                else:
                    low = sp_verify_val.strip().lower()
                    if low in _SSL_VERIFY_TRUE:
                        sp_sel.value = "true"
                        sp_ca.value = ""
                    elif low in _SSL_VERIFY_FALSE:
                        sp_sel.value = "false"
                        sp_ca.value = ""
                    else:
                        sp_sel.value = "custom"
                        sp_ca.value = sp_verify_val

            # SentinelOne SSL
            s1_verify_val = self._form_value_for_display("s1_verify_ssl", saved_map)
            s1_sel = self.query_one("#set-s1-verify-ssl", Select)
            s1_ca = self.query_one("#set-s1-ca-bundle", Input)
            with s1_sel.prevent(Select.Changed):
                if s1_verify_val is None:
                    s1_sel.value = ""
                    s1_ca.value = ""
                else:
                    low = s1_verify_val.strip().lower()
                    if low in _SSL_VERIFY_TRUE:
                        s1_sel.value = "true"
                        s1_ca.value = ""
                    elif low in _SSL_VERIFY_FALSE:
                        s1_sel.value = "false"
                        s1_ca.value = ""
                    else:
                        s1_sel.value = "custom"
                        s1_ca.value = s1_verify_val

            # Image protocol
            img_proto = self._form_value_for_display("rf_tui_image_protocol", saved_map)
            proto_sel = self.query_one("#set-rf-tui-image-protocol", Select)
            proto_norm = (img_proto or "").strip().lower()
            with proto_sel.prevent(Select.Changed):
                proto_sel.value = (
                    proto_norm if proto_norm in {"kitty", "iterm2", "sixel", "halfblock"} else ""
                )

            # Auto-approve
            auto_val = self._form_value_for_display("soclens_auto_approve", saved_map)
            self.query_one("#set-auto-approve", Checkbox).value = (
                (auto_val or "").strip().lower() in _SSL_VERIFY_TRUE
            )

            # Profiles dropdown & vault controls
            self._refresh_profile_selector(active_profile)
            self._populate_vault_dropdowns(
                self._catalog_entries,
                saved_map,
                preserve_current=False,
            )
            self._sync_secret_manager_field_modes()
            self._sync_ca_inputs_enabled()
            self._refresh_field_badges()
            self._refresh_secrets_summary(saved_map)
            self._refresh_storage_banners()
        finally:
            self._populating_form = False

    def _refresh_profile_selector(self, active_profile: str | None = None) -> None:
        active = active_profile or get_active_profile_name()
        profiles = list_profiles()
        if active not in profiles:
            profiles.append(active)
        sel = self.query_one("#set-profile-select", Select)
        with sel.prevent(Select.Changed):
            sel.set_options([(name, name) for name in profiles])
            sel.value = active

    def _refresh_field_badges(self) -> None:
        active_profile = get_active_profile_name()
        saved_map = get_profile_settings(profile=active_profile)
        for spec in SETTING_SPECS:
            try:
                lbl = self.query_one(f"#{_label_id(spec.key)}", Static)
            except Exception:
                continue
            has_sess, sess_val = get_session_override(spec.key)
            env_hit = get_env_override_for_setting(spec.key)
            saved_val = saved_map.get(spec.key)
            if has_sess and sess_val is not None:
                badge = "Session Override + Saved" if saved_val is not None else "Session Override"
            elif env_hit is not None and saved_val is not None:
                badge = f"ENV: {env_hit[0]} overrides Saved"
            elif env_hit is not None:
                badge = f"ENV: {env_hit[0]}"
            elif saved_val is not None:
                badge = "Saved"
            elif spec.default is not None:
                badge = f"Default: {spec.default}"
            else:
                badge = "Not Set"
            lbl.update(f"{spec.label} [{badge}]")

    def _refresh_storage_banners(self) -> None:
        info = get_settings_storage_info()
        rf_val, rf_src = get_setting_with_source("rf_api_token")
        sp_cfg = get_splunk_config(required=False)
        s1_cfg = get_sentinelone_config(required=False)
        rf_ssl = format_ssl_verify_status(get_rf_verify_ssl())
        env_hits = collect_env_importable_settings()
        env_note = (
            f"Shell Env Overrides Active: {len(env_hits)} (click Import from Env to save)"
            if env_hits
            else "Shell Env Overrides: None"
        )
        summary = (
            f"Active Profile: {info['active_profile']} ({info['profile_count']} total) | "
            f"File: {info['path']} [{info['permissions']}]\n"
            f"RF Token: {'Set (' + rf_src + ')' if rf_val else 'Missing'} | "
            f"Splunk: {'Configured' if sp_cfg.has_auth else 'Missing'} | "
            f"SentinelOne: {'Configured' if s1_cfg.has_auth else 'Missing'} | "
            f"SSL: {rf_ssl}\n"
            f"{env_note} | Proxy: {get_proxy_summary()}"
        )
        if info.get("load_error"):
            summary += f"\nWarning: {info['load_error']}"
        try:
            self.query_one("#settings-storage-info", Static).update(summary)
        except Exception:
            pass

        details = (
            f"Settings File : {info['path']}\n"
            f"File Exists   : {'Yes' if info['exists'] else 'No (will be created on first save)'}\n"
            f"Permissions   : {info['permissions']}\n"
            f"Active Profile: {info['active_profile']}\n"
            f"All Profiles  : {', '.join(info['profiles'])}\n"
            f"Env Profile   : {info['env_override_profile'] or 'None (SOCLENS_PROFILE unset)'}\n"
            f"Precedence    : CLI flags > Active TUI Session Override > Environment Variables > Saved Profile > Defaults"
        )
        try:
            self.query_one("#settings-storage-details", Static).update(details)
        except Exception:
            pass

    @on(OptionList.OptionHighlighted, "#settings-category-list")
    @on(OptionList.OptionSelected, "#settings-category-list")
    def handle_category_changed(
        self,
        event: OptionList.OptionHighlighted | OptionList.OptionSelected,
    ) -> None:
        cat_id = str(event.option.id or "cat-rf")
        try:
            self.query_one("#settings-category-switcher", ContentSwitcher).current = cat_id
        except Exception:
            pass

    @on(Select.Changed, "#set-rf-verify-ssl")
    @on(Select.Changed, "#set-splunk-verify-ssl")
    @on(Select.Changed, "#set-s1-verify-ssl")
    @on(Select.Changed, "#set-secret-store-verify-ssl")
    def handle_ssl_select_changed(self, event: Select.Changed) -> None:
        self._sync_ca_inputs_enabled()

    @on(Select.Changed, "#set-secret-provider")
    def handle_secret_provider_changed(self, event: Select.Changed) -> None:
        if self._populating_form:
            return
        new_provider = str(event.value or "none").strip().lower()
        if self._catalog_provider and new_provider != self._catalog_provider:
            self._catalog_entries = []
            self._catalog_provider = ""
        saved_map = get_profile_settings(profile=get_active_profile_name())
        self._populate_vault_dropdowns(
            self._catalog_entries,
            saved_map,
            preserve_current=False,
        )
        self._sync_secret_manager_field_modes()
        self._refresh_secrets_summary(saved_map)
        self._refresh_storage_banners()

    @on(Checkbox.Changed, "#settings-show-secrets")
    def handle_toggle_show_secrets(self, event: Checkbox.Changed) -> None:
        hide = not bool(event.value)
        for widget_id in _SECRET_INPUT_IDS:
            try:
                self.query_one(f"#{widget_id}", Input).password = hide
            except Exception:
                pass

    def _switch_to_widget(self, cat_id: str, widget_id: str, *, key: str = "") -> None:
        try:
            cat_ids = [cid for cid, _ in _CATEGORIES]
            if cat_id in cat_ids:
                self.query_one("#settings-category-list", OptionList).highlighted = cat_ids.index(cat_id)
            self.query_one("#settings-category-switcher", ContentSwitcher).current = cat_id
            if key in _RF_URL_KEYS:
                self.query_one("#settings-rf-urls-collapsible", Collapsible).collapsed = False
            widget = self.query_one(f"#{widget_id}")
            if not widget.display and key in _VAULT_SELECT_BY_KEY:
                vault_sel = self.query_one(f"#{_VAULT_SELECT_BY_KEY[key]}", Select)
                if vault_sel.display:
                    widget = vault_sel
            self.call_after_refresh(widget.focus)
        except Exception:
            pass

    def _collect_form_values(
        self,
        existing_saved: dict[str, str],
    ) -> tuple[dict[str, str | None], tuple[str, str, str] | None]:
        """Collect all setting values from form controls.

        Returns ``(values_map, first_ui_error)`` where ``first_ui_error`` is
        ``(key, widget_id, message)`` if a compound control (like custom CA) is invalid.
        """
        values: dict[str, str | None] = {}

        secret_provider = str(
            self.query_one("#set-secret-provider", Select).value or "none"
        ).strip().lower()
        env_prov = get_env_override_for_setting("secret_provider")
        if secret_provider == "none":
            values["secret_provider"] = "none" if env_prov is not None else None
        else:
            values["secret_provider"] = secret_provider

        tss_mode = str(
            self.query_one("#set-tss-auth-mode", Select).value or "password"
        ).strip().lower()
        env_tss_mode = get_env_override_for_setting("tss_auth_mode")
        values["tss_auth_mode"] = (
            tss_mode
            if (tss_mode != "password" or "tss_auth_mode" in existing_saved or env_tss_mode is not None)
            else None
        )

        vault_mode = str(
            self.query_one("#set-vault-auth-mode", Select).value or "token"
        ).strip().lower()
        env_vault_mode = get_env_override_for_setting("vault_auth_mode")
        values["vault_auth_mode"] = (
            vault_mode
            if (vault_mode != "token" or "vault_auth_mode" in existing_saved or env_vault_mode is not None)
            else None
        )

        ss_sel = str(self.query_one("#set-secret-store-verify-ssl", Select).value or "")
        ss_ca_raw = self.query_one("#set-pam-ca-bundle", Input).value
        if "\n" in ss_ca_raw or "\r" in ss_ca_raw:
            return values, (
                "secret_store_verify_ssl",
                "set-pam-ca-bundle",
                "Secret Store SSL Verification: newline characters are not permitted.",
            )
        ss_ca = ss_ca_raw.strip()
        if ss_sel == "custom":
            if not ss_ca:
                return values, (
                    "secret_store_verify_ssl",
                    "set-pam-ca-bundle",
                    "Secret Manager custom CA bundle path is required when Custom CA is selected.",
                )
            values["secret_store_verify_ssl"] = ss_ca
        elif ss_sel in {"true", "false"}:
            values["secret_store_verify_ssl"] = ss_sel
        else:
            values["secret_store_verify_ssl"] = None

        for key, widget_id, _ in _INPUT_SPECS_SIMPLE:
            if secret_provider != "none" and key in _SECRET_MANAGED_INPUT_KEYS:
                continue
            raw = self.query_one(f"#{widget_id}", Input).value
            if "\n" in raw or "\r" in raw:
                spec = SETTING_SPECS_BY_KEY[key]
                return values, (
                    key,
                    widget_id,
                    f"{spec.label}: newline characters are not permitted.",
                )
            values[key] = raw.strip() or None

        if secret_provider == "none":
            if "vault_secret_map" in existing_saved:
                values["vault_secret_map"] = existing_saved["vault_secret_map"]
        else:
            mapped: dict[str, str] = {}
            for key, _inp_id, vault_sel_id in _SECRET_MANAGED_VAULT_FIELDS:
                ref_val = str(self.query_one(f"#{vault_sel_id}", Select).value or "").strip()
                if ref_val:
                    mapped[key] = ref_val
            serialized_map = serialize_vault_secret_map(mapped)
            values["vault_secret_map"] = serialized_map or None
            for key, _inp_id, _vault_sel_id in _SECRET_MANAGED_VAULT_FIELDS:
                if key in mapped or is_vault_hydrated_setting(key):
                    values[key] = None

        # RF SSL + CA Bundle
        rf_sel = str(self.query_one("#set-rf-verify-ssl", Select).value)
        rf_ca_raw = self.query_one("#set-rf-ca-bundle", Input).value
        if "\n" in rf_ca_raw or "\r" in rf_ca_raw:
            return values, (
                "rf_ca_bundle",
                "set-rf-ca-bundle",
                "Custom CA Bundle Path: newline characters are not permitted.",
            )
        rf_ca = rf_ca_raw.strip()
        if rf_sel == "custom":
            if not rf_ca:
                return values, (
                    "rf_ca_bundle",
                    "set-rf-ca-bundle",
                    "Custom CA Bundle Path is required when 'Custom CA Bundle Path' is selected.",
                )
            values["rf_verify_ssl"] = None
            values["rf_ca_bundle"] = rf_ca
        elif rf_sel == "false":
            values["rf_verify_ssl"] = "false"
            values["rf_ca_bundle"] = None
        else:
            env_ssl = get_env_override_for_setting("rf_verify_ssl")
            env_ca = get_env_override_for_setting("rf_ca_bundle")
            values["rf_verify_ssl"] = "true" if (env_ssl is not None or env_ca is not None) else None
            values["rf_ca_bundle"] = None

        # Splunk SSL
        sp_sel = str(self.query_one("#set-splunk-verify-ssl", Select).value)
        sp_ca = self.query_one("#set-splunk-ca-bundle", Input).value.strip()
        if sp_sel == "custom":
            if not sp_ca:
                return values, (
                    "splunk_verify_ssl",
                    "set-splunk-ca-bundle",
                    "Splunk custom CA bundle path is required when Custom CA is selected.",
                )
            values["splunk_verify_ssl"] = sp_ca
        elif sp_sel == "true":
            values["splunk_verify_ssl"] = "true"
        else:
            env_sp = get_env_override_for_setting("splunk_verify_ssl")
            values["splunk_verify_ssl"] = (
                "false"
                if (env_sp is not None or "splunk_verify_ssl" in existing_saved)
                else None
            )

        # SentinelOne SSL
        s1_sel = str(self.query_one("#set-s1-verify-ssl", Select).value)
        s1_ca = self.query_one("#set-s1-ca-bundle", Input).value.strip()
        if s1_sel == "custom":
            if not s1_ca:
                return values, (
                    "s1_verify_ssl",
                    "set-s1-ca-bundle",
                    "SentinelOne custom CA bundle path is required when Custom CA is selected.",
                )
            values["s1_verify_ssl"] = s1_ca
        elif s1_sel in {"true", "false"}:
            values["s1_verify_ssl"] = s1_sel
        else:
            values["s1_verify_ssl"] = None

        # Image protocol
        proto_val = str(self.query_one("#set-rf-tui-image-protocol", Select).value).strip().lower()
        values["rf_tui_image_protocol"] = proto_val or None

        # Auto-approve
        auto_checked = bool(self.query_one("#set-auto-approve", Checkbox).value)
        if auto_checked:
            values["soclens_auto_approve"] = "true"
        else:
            env_auto = get_env_override_for_setting("soclens_auto_approve")
            values["soclens_auto_approve"] = "false" if env_auto is not None else None

        return values, None

    def _apply_session_conflicts(self, values: dict[str, str | None]) -> list[str]:
        """Apply process-local session overrides when saved values conflict with shell env vars."""
        conflict_vars: list[str] = []
        session_updates: dict[str, str | None] = {}
        clear_keys: list[str] = []

        provider_active = (values.get("secret_provider") or "none").strip().lower() != "none"
        mapped_keys: set[str] = set()
        if provider_active:
            try:
                mapped_keys = set(
                    parse_vault_secret_map(values.get("vault_secret_map"), strict=False).keys()
                )
            except ValueError:
                mapped_keys = set()

        for key, new_val in values.items():
            if (
                provider_active
                and new_val is None
                and key in mapped_keys
                and is_vault_hydrated_setting(key)
            ):
                continue
            env_hit = get_env_override_for_setting(key)
            if new_val is not None and env_hit is not None:
                if key == "rf_ca_bundle":
                    session_updates["rf_ca_bundle"] = new_val
                    conflict_vars.append(env_hit[0])
                elif new_val != env_hit[1]:
                    session_updates[key] = new_val
                    conflict_vars.append(env_hit[0])
                else:
                    clear_keys.append(key)
            elif key == "rf_ca_bundle" and new_val is not None:
                if (
                    get_env_override_for_setting("rf_verify_ssl") is not None
                    or get_env_override_for_setting("rf_ca_bundle") is not None
                ):
                    session_updates["rf_ca_bundle"] = new_val
            else:
                clear_keys.append(key)

        if clear_keys:
            clear_session_overrides(clear_keys)
        if session_updates:
            set_session_overrides(session_updates)
        return sorted(set(conflict_vars))

    def _reload_app_after_session_update(self) -> None:
        self._internal_reloading = True
        try:
            reload_fn = getattr(self.app, "reload_settings", None)
            if callable(reload_fn):
                reload_fn()
        finally:
            self._internal_reloading = False

    def _save_form_and_reload(self, *, status_prefix: str = "") -> bool:
        active_profile = get_active_profile_name()
        existing_saved = get_profile_settings(profile=active_profile)
        values, ui_err = self._collect_form_values(existing_saved)
        if ui_err is not None:
            key, widget_id, message = ui_err
            cat_id, _ = _input_widget_for_key(key)
            self._switch_to_widget(cat_id, widget_id, key=key)
            self.set_status(f"Validation error: {message}")
            self.notify_user(message, title="Invalid Setting", severity="error")
            return False

        errors = validate_settings_values(values)
        if errors:
            bad_key, err_msg = errors[0]
            cat_id, widget_id = _input_widget_for_key(bad_key)
            self._switch_to_widget(cat_id, widget_id, key=bad_key)
            self.set_status(f"Validation error: {err_msg}")
            self.notify_user(err_msg, title="Invalid Setting", severity="error")
            return False

        target_path = save_profile_settings(values, profile=active_profile, replace=False)
        conflicts = self._apply_session_conflicts(values)

        if (values.get("secret_provider") or "none").strip().lower() != "none":
            for key, inp_id, _vault_sel_id in _SECRET_MANAGED_VAULT_FIELDS:
                if key in values and values[key] is None:
                    try:
                        inp = self.query_one(f"#{inp_id}", Input)
                        with inp.prevent(Input.Changed):
                            inp.value = ""
                    except Exception:
                        pass

        self._reload_app_after_session_update()
        self._refresh_field_badges()
        self._refresh_secrets_summary(get_profile_settings(profile=active_profile))
        self._refresh_storage_banners()

        base_msg = (
            f"{status_prefix}Saved profile '{active_profile}' to {target_path}."
            if status_prefix
            else f"Saved profile '{active_profile}' to {target_path}."
        )
        if conflicts:
            msg = (
                f"{base_msg} Live TUI session overrides applied over shell env "
                f"({', '.join(conflicts)}); unset those env vars for future CLI runs."
            )
            self.set_status(msg)
            self.append_log(msg, level="WARNING")
            self.notify_user(msg, title="Settings Saved (Env Conflict)", severity="warning")
        else:
            self.set_status(base_msg)
            self.append_log(base_msg)
            self.notify_user(base_msg, title="Settings Saved")

        if (values.get("secret_provider") or "none") != "none" and values.get("vault_secret_map"):
            self._hydrate_after_save_worker()
        return True

    @on(Button.Pressed, "#settings-save-btn")
    def handle_save_settings(self) -> None:
        self._save_form_and_reload()

    @on(Button.Pressed, "#settings-reload-btn")
    def handle_reload_settings(self) -> None:
        clear_session_overrides()
        self._internal_reloading = True
        try:
            reload_fn = getattr(self.app, "reload_settings", None)
            if callable(reload_fn):
                reload_fn()
        finally:
            self._internal_reloading = False
        self._load_form_from_store()
        msg = f"Reloaded settings from disk (profile '{get_active_profile_name()}')."
        self.set_status(msg)
        self.append_log(msg)

    @on(Button.Pressed, "#settings-import-env-btn")
    def handle_import_from_env(self) -> None:
        imported = collect_env_importable_settings()
        if not imported:
            msg = "No recognized environment variables are currently set to import."
            self.set_status(msg)
            self.notify_user(msg, title="Import from Env", severity="information")
            return

        self._populating_form = True
        try:
            for key, widget_id, _ in _INPUT_SPECS_SIMPLE:
                if key in imported:
                    self.query_one(f"#{widget_id}", Input).value = imported[key]

            if "secret_provider" in imported:
                prov = imported["secret_provider"].strip().lower()
                prov_sel = self.query_one("#set-secret-provider", Select)
                with prov_sel.prevent(Select.Changed):
                    prov_sel.value = prov if prov in SUPPORTED_SECRET_PROVIDERS else "none"

            if "tss_auth_mode" in imported:
                tss_mode = imported["tss_auth_mode"].strip().lower()
                tss_sel = self.query_one("#set-tss-auth-mode", Select)
                with tss_sel.prevent(Select.Changed):
                    tss_sel.value = tss_mode if tss_mode in TSS_AUTH_MODES else "password"

            if "vault_auth_mode" in imported:
                vault_mode = imported["vault_auth_mode"].strip().lower()
                vault_sel = self.query_one("#set-vault-auth-mode", Select)
                with vault_sel.prevent(Select.Changed):
                    vault_sel.value = vault_mode if vault_mode in VAULT_AUTH_MODES else "token"

            if "secret_store_verify_ssl" in imported:
                low = imported["secret_store_verify_ssl"].strip().lower()
                ss_sel = self.query_one("#set-secret-store-verify-ssl", Select)
                ss_ca = self.query_one("#set-pam-ca-bundle", Input)
                with ss_sel.prevent(Select.Changed):
                    if low in _SSL_VERIFY_TRUE:
                        ss_sel.value = "true"
                        ss_ca.value = ""
                    elif low in _SSL_VERIFY_FALSE:
                        ss_sel.value = "false"
                        ss_ca.value = ""
                    else:
                        ss_sel.value = "custom"
                        ss_ca.value = imported["secret_store_verify_ssl"]

            if "rf_ca_bundle" in imported:
                rf_sel = self.query_one("#set-rf-verify-ssl", Select)
                with rf_sel.prevent(Select.Changed):
                    rf_sel.value = "custom"
                self.query_one("#set-rf-ca-bundle", Input).value = imported["rf_ca_bundle"]
            elif "rf_verify_ssl" in imported:
                low = imported["rf_verify_ssl"].strip().lower()
                rf_sel = self.query_one("#set-rf-verify-ssl", Select)
                with rf_sel.prevent(Select.Changed):
                    if low in _SSL_VERIFY_FALSE:
                        rf_sel.value = "false"
                        self.query_one("#set-rf-ca-bundle", Input).value = ""
                    elif low in _SSL_VERIFY_TRUE:
                        rf_sel.value = "true"
                        self.query_one("#set-rf-ca-bundle", Input).value = ""
                    else:
                        rf_sel.value = "custom"
                        self.query_one("#set-rf-ca-bundle", Input).value = imported["rf_verify_ssl"]

            if "splunk_verify_ssl" in imported:
                low = imported["splunk_verify_ssl"].strip().lower()
                sp_sel = self.query_one("#set-splunk-verify-ssl", Select)
                with sp_sel.prevent(Select.Changed):
                    if low in _SSL_VERIFY_TRUE:
                        sp_sel.value = "true"
                        self.query_one("#set-splunk-ca-bundle", Input).value = ""
                    elif low in _SSL_VERIFY_FALSE:
                        sp_sel.value = "false"
                        self.query_one("#set-splunk-ca-bundle", Input).value = ""
                    else:
                        sp_sel.value = "custom"
                        self.query_one("#set-splunk-ca-bundle", Input).value = imported["splunk_verify_ssl"]

            if "s1_verify_ssl" in imported:
                low = imported["s1_verify_ssl"].strip().lower()
                s1_sel = self.query_one("#set-s1-verify-ssl", Select)
                with s1_sel.prevent(Select.Changed):
                    if low in _SSL_VERIFY_TRUE:
                        s1_sel.value = "true"
                        self.query_one("#set-s1-ca-bundle", Input).value = ""
                    elif low in _SSL_VERIFY_FALSE:
                        s1_sel.value = "false"
                        self.query_one("#set-s1-ca-bundle", Input).value = ""
                    else:
                        s1_sel.value = "custom"
                        self.query_one("#set-s1-ca-bundle", Input).value = imported["s1_verify_ssl"]

            if "rf_tui_image_protocol" in imported:
                proto = imported["rf_tui_image_protocol"].strip().lower()
                proto_sel = self.query_one("#set-rf-tui-image-protocol", Select)
                with proto_sel.prevent(Select.Changed):
                    proto_sel.value = (
                        proto if proto in {"kitty", "iterm2", "sixel", "halfblock"} else ""
                    )

            if "soclens_auto_approve" in imported:
                self.query_one("#set-auto-approve", Checkbox).value = (
                    imported["soclens_auto_approve"].strip().lower() in _SSL_VERIFY_TRUE
                )

            if "vault_secret_map" in imported:
                self._populate_vault_dropdowns(
                    self._catalog_entries,
                    {"vault_secret_map": imported["vault_secret_map"]},
                    preserve_current=False,
                )

            self._sync_secret_manager_field_modes()
            self._sync_ca_inputs_enabled()
        finally:
            self._populating_form = False

        self._save_form_and_reload(
            status_prefix=f"Imported {len(imported)} setting(s) from environment. "
        )

    @on(Button.Pressed, "#settings-clear-btn")
    def handle_clear_profile(self) -> None:
        active_profile = get_active_profile_name()
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Preview only: would clear saved settings in profile '{active_profile}'."
            self.set_status(msg)
            self.notify_user(msg, title="Dry-Run Preview")
            return

        def _do_clear() -> None:
            clear_profile_settings(profile=active_profile)
            clear_session_overrides()
            self._catalog_entries = []
            self._catalog_provider = ""
            self._internal_reloading = True
            try:
                reload_fn = getattr(self.app, "reload_settings", None)
                if callable(reload_fn):
                    reload_fn()
            finally:
                self._internal_reloading = False
            self._load_form_from_store()
            msg = f"Cleared all saved settings in profile '{active_profile}'."
            self.set_status(msg)
            self.append_log(msg, level="WARNING")
            self.notify_user(msg, title="Profile Cleared", severity="warning")

        self.confirm_destructive_action(
            title="Clear Saved Settings Profile",
            message=f"Remove all saved credentials and settings from profile '{active_profile}'?",
            details="Environment variables (if any) will remain active in your shell.",
            confirm_label="Clear Profile",
            on_approved=_do_clear,
        )

    @on(Button.Pressed, "#settings-switch-profile-btn")
    def handle_switch_profile(self) -> None:
        target = str(self.query_one("#set-profile-select", Select).value or DEFAULT_PROFILE)
        try:
            set_active_profile(target, create=False)
        except Exception as exc:
            self.report_error("Switch Profile", exc)
            return
        clear_session_overrides()
        self._catalog_entries = []
        self._catalog_provider = ""
        self._internal_reloading = True
        try:
            reload_fn = getattr(self.app, "reload_settings", None)
            if callable(reload_fn):
                reload_fn()
        finally:
            self._internal_reloading = False
        self._load_form_from_store()
        msg = f"Switched active settings profile to '{target}'."
        self.set_status(msg)
        self.append_log(msg)
        self.notify_user(msg, title="Profile Switched")

    @on(Button.Pressed, "#settings-create-profile-btn")
    def handle_create_profile(self) -> None:
        raw_name = self.query_one("#set-new-profile-input", Input).value
        try:
            prof_name = validate_profile_name(raw_name)
        except ValueError as exc:
            self.set_status(f"Invalid profile name: {exc}")
            self.query_one("#set-new-profile-input", Input).focus()
            return
        set_active_profile(prof_name, create=True)
        self.query_one("#set-new-profile-input", Input).value = ""
        clear_session_overrides()
        self._catalog_entries = []
        self._catalog_provider = ""
        self._internal_reloading = True
        try:
            reload_fn = getattr(self.app, "reload_settings", None)
            if callable(reload_fn):
                reload_fn()
        finally:
            self._internal_reloading = False
        self._load_form_from_store()
        msg = f"Created and activated settings profile '{prof_name}'."
        self.set_status(msg)
        self.append_log(msg)
        self.notify_user(msg, title="Profile Created")

    @on(Button.Pressed, "#settings-delete-profile-btn")
    def handle_delete_profile(self) -> None:
        target = str(self.query_one("#set-profile-select", Select).value or DEFAULT_PROFILE)
        if target == DEFAULT_PROFILE:
            msg = "Cannot delete the built-in 'default' profile. Use 'Clear Profile' instead."
            self.set_status(msg)
            self.notify_user(msg, title="Cannot Delete Default", severity="warning")
            return
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Preview only: would delete profile '{target}'."
            self.set_status(msg)
            self.notify_user(msg, title="Dry-Run Preview")
            return

        def _do_delete() -> None:
            try:
                delete_profile(target)
            except Exception as exc:
                self.report_error("Delete Profile", exc)
                return
            clear_session_overrides()
            self._catalog_entries = []
            self._catalog_provider = ""
            self._internal_reloading = True
            try:
                reload_fn = getattr(self.app, "reload_settings", None)
                if callable(reload_fn):
                    reload_fn()
            finally:
                self._internal_reloading = False
            self._load_form_from_store()
            msg = f"Deleted settings profile '{target}' (active: '{get_active_profile_name()}')."
            self.set_status(msg)
            self.append_log(msg, level="WARNING")
            self.notify_user(msg, title="Profile Deleted", severity="warning")

        self.confirm_destructive_action(
            title="Delete Settings Profile",
            message=f"Permanently delete profile '{target}' and all its saved credentials?",
            details="Active profile will fall back to 'default' if needed.",
            confirm_label="Delete Profile",
            on_approved=_do_delete,
        )

    def _snapshot_draft_values(self) -> tuple[dict[str, str | None], str | None]:
        """Collect current draft form values cleanly on the UI thread for connection tests."""
        existing_saved = get_profile_settings(profile=get_active_profile_name())
        values, ui_err = self._collect_form_values(existing_saved)
        if ui_err is not None:
            return values, ui_err[2]
        errors = validate_settings_values(values)
        if errors:
            return values, errors[0][1]
        return values, None

    def _resolve_draft_rf_ssl(self, draft: dict[str, str | None]) -> bool | str:
        ca_bundle = draft.get("rf_ca_bundle")
        if ca_bundle:
            return os.path.expanduser(ca_bundle)
        raw_v = draft.get("rf_verify_ssl")
        if raw_v is not None:
            low = raw_v.strip().lower()
            if low in _SSL_VERIFY_FALSE:
                return False
            if low in _SSL_VERIFY_TRUE:
                return True
            return os.path.expanduser(raw_v)
        return get_rf_verify_ssl()

    def _build_secret_store_config_from_draft(
        self,
        draft: dict[str, str | None],
    ) -> SecretStoreConfig:
        verify_ssl: bool | str | None = (
            draft.get("secret_store_verify_ssl")
            if draft.get("secret_store_verify_ssl") is not None
            else self._resolve_draft_rf_ssl(draft)
        )
        return get_secret_store_config(
            provider=draft.get("secret_provider") or "none",
            verify_ssl=verify_ssl,
            timeout=draft.get("secret_store_timeout"),
            secret_map=draft.get("vault_secret_map"),
            tss_base_url=draft.get("tss_base_url"),
            tss_auth_mode=draft.get("tss_auth_mode"),
            tss_username=draft.get("tss_username"),
            tss_password=draft.get("tss_password"),
            tss_domain=draft.get("tss_domain"),
            tss_client_id=draft.get("tss_client_id"),
            tss_client_secret=draft.get("tss_client_secret"),
            tss_access_token=draft.get("tss_access_token"),
            tss_platform_url=draft.get("tss_platform_url"),
            tss_folder_id=draft.get("tss_folder_id"),
            vault_addr=draft.get("vault_addr"),
            vault_auth_mode=draft.get("vault_auth_mode"),
            vault_token=draft.get("vault_token"),
            vault_role_id=draft.get("vault_role_id"),
            vault_secret_id=draft.get("vault_secret_id"),
            vault_auth_mount=draft.get("vault_auth_mount"),
            vault_kv_mount=draft.get("vault_kv_mount"),
            vault_namespace=draft.get("vault_namespace"),
            vault_prefix=draft.get("vault_prefix"),
            op_connect_url=draft.get("op_connect_url"),
            op_connect_token=draft.get("op_connect_token"),
            op_vault_id=draft.get("op_vault_id"),
            bw_serve_url=draft.get("bw_serve_url"),
            bw_master_password=draft.get("bw_master_password"),
            bw_folder_id=draft.get("bw_folder_id"),
            bw_collection_id=draft.get("bw_collection_id"),
            bw_organization_id=draft.get("bw_organization_id"),
        )

    @on(Button.Pressed, "#settings-test-secrets-btn")
    def handle_test_secrets(self) -> None:
        draft, err = self._snapshot_draft_values()
        if err:
            self.set_status(f"Validation error: {err}")
            self.notify_user(err, title="Invalid Setting", severity="error")
            return
        self.set_status("Testing Secret Manager connection...")
        self._test_secrets_worker(draft)

    @on(Button.Pressed, "#settings-refresh-vault-btn")
    def handle_refresh_vault_catalog(self) -> None:
        draft, err = self._snapshot_draft_values()
        if err:
            self.set_status(f"Validation error: {err}")
            self.notify_user(err, title="Invalid Setting", severity="error")
            return
        self.set_status("Refreshing Secret Manager catalog...")
        self._refresh_vault_catalog_worker(draft)

    @on(Button.Pressed, "#settings-pull-secrets-btn")
    def handle_pull_secrets(self) -> None:
        draft, err = self._snapshot_draft_values()
        if err:
            self.set_status(f"Validation error: {err}")
            self.notify_user(err, title="Invalid Setting", severity="error")
            return
        self.set_status("Pulling mapped secrets into session memory...")
        self._pull_secrets_worker(draft)

    @work(thread=True, exit_on_error=False)
    def _test_secrets_worker(self, draft: dict[str, str | None]) -> None:
        stop_event = getattr(self.app, "_stop_event", None)
        if stop_event is not None and stop_event.is_set():
            return
        try:
            cfg = self._build_secret_store_config_from_draft(draft)
            if not cfg.is_enabled:
                msg = "Secret Manager is disabled ('none')."
                self.set_status(msg)
                self.notify_user(msg, title="Secret Manager", severity="information")
                return
            with self.log_scope("settings"):
                with build_secret_store_provider(cfg, stop_event=stop_event) as prov:
                    info = prov.test_connection()
            ok = bool(info.get("ok", True))
            detail = str(info.get("detail") or info.get("status") or info.get("version") or "OK")
            provider_label = SECRET_PROVIDER_LABELS.get(cfg.provider, cfg.provider)
            msg = f"Secret Manager OK ({provider_label}): {detail}"
            if not ok:
                msg = f"Secret Manager check failed ({provider_label}): {detail}"
            self.set_status(msg)
            self.append_log(msg, level="INFO" if ok else "WARNING")

            def _update_summary() -> None:
                try:
                    self.query_one("#settings-secrets-summary", Static).update(
                        f"Connection Test: {msg}"
                    )
                except Exception:
                    pass

            self.run_on_ui(_update_summary)
            self.notify_user(
                msg,
                title="Secret Manager OK" if ok else "Secret Manager Warning",
                severity="information" if ok else "warning",
            )
        except Exception as exc:
            self.report_error("Secret Manager Test", exc)

    @work(thread=True, exit_on_error=False)
    def _refresh_vault_catalog_worker(self, draft: dict[str, str | None]) -> None:
        stop_event = getattr(self.app, "_stop_event", None)
        if stop_event is not None and stop_event.is_set():
            return
        try:
            cfg = self._build_secret_store_config_from_draft(draft)
            if not cfg.is_enabled:
                msg = "Secret Manager is disabled ('none'). Select a provider first."
                self.set_status(msg)
                self.notify_user(msg, title="Refresh Vault Catalog", severity="warning")
                return
            with self.log_scope("settings"):
                with build_secret_store_provider(cfg, stop_event=stop_event) as prov:
                    entries = list(prov.list_secrets(limit=200))

            def _apply_catalog() -> None:
                self._catalog_entries = entries
                self._catalog_provider = cfg.provider
                saved_map = get_profile_settings(profile=get_active_profile_name())
                self._populate_vault_dropdowns(
                    self._catalog_entries,
                    saved_map,
                    preserve_current=True,
                )
                self._refresh_secrets_summary(saved_map)

            self.run_on_ui(_apply_catalog)
            msg = f"Loaded {len(entries)} secret catalog entry(ies) from {cfg.provider}."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Vault Catalog Refreshed")
        except Exception as exc:
            self.report_error("Refresh Vault Catalog", exc)

    @work(thread=True, exit_on_error=False)
    def _pull_secrets_worker(self, draft: dict[str, str | None]) -> None:
        stop_event = getattr(self.app, "_stop_event", None)
        if stop_event is not None and stop_event.is_set():
            return
        try:
            cfg = self._build_secret_store_config_from_draft(draft)
            if not cfg.is_enabled:
                msg = "Secret Manager is disabled ('none')."
                self.set_status(msg)
                self.notify_user(msg, title="Pull Secrets", severity="warning")
                return
            target_map = {
                k: v for k, v in cfg.secret_map.items() if k in SECRET_MANAGED_SETTING_KEYS
            }
            if not target_map:
                msg = "No vault secret mappings configured."
                self.set_status(msg)
                self.notify_user(msg, title="Pull Secrets", severity="warning")
                return
            with self.log_scope("settings"):
                with build_secret_store_provider(cfg, stop_event=stop_event) as prov:
                    resolved = prov.resolve_mapped_settings(target_map)

            to_apply: dict[str, str] = {}
            for key, val in resolved.items():
                if key not in SECRET_MANAGED_SETTING_KEYS:
                    continue
                cleaned = val.strip() if isinstance(val, str) else ""
                if cleaned:
                    to_apply[key] = cleaned

            if to_apply:
                set_session_overrides(to_apply, vault_hydrated=True)
            masked = {k: mask_secret(v) for k, v in to_apply.items()}

            def _apply_ui() -> None:
                self._reload_app_after_session_update()
                self._refresh_field_badges()
                self._refresh_secrets_summary()
                self._refresh_storage_banners()

            self.run_on_ui(_apply_ui)
            preview = ", ".join(f"{k}={m}" for k, m in sorted(masked.items()))
            msg = (
                f"Pulled {len(masked)} secret(s) into session memory ({preview})."
                if masked
                else "No non-empty secrets resolved from mapped references."
            )
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Secrets Hydrated (Memory Only)")
        except Exception as exc:
            self.report_error("Pull Secrets", exc)

    @work(thread=True, exit_on_error=False)
    def _hydrate_after_save_worker(self) -> None:
        stop_event = getattr(self.app, "_stop_event", None)
        if stop_event is not None and stop_event.is_set():
            return
        try:
            with self.log_scope("settings"):
                masked = hydrate_secrets_from_store(
                    force=True,
                    overwrite_existing=True,
                    stop_event=stop_event,
                )

            def _apply_ui() -> None:
                self._reload_app_after_session_update()
                self._refresh_field_badges()
                self._refresh_secrets_summary()
                self._refresh_storage_banners()

            self.run_on_ui(_apply_ui)
            if masked:
                msg = f"Hydrated {len(masked)} secret(s) into session memory from vault."
                self.set_status(msg)
                self.append_log(msg)
        except Exception as exc:
            warn_msg = f"Saved vault map, but session hydration failed: {exc}"
            self.set_status(warn_msg)
            self.append_log(warn_msg, level="WARNING")

    @on(Button.Pressed, "#settings-test-rf-btn")
    def handle_test_rf(self) -> None:
        draft, err = self._snapshot_draft_values()
        if err:
            self.set_status(f"Validation error: {err}")
            self.notify_user(err, title="Invalid Setting", severity="error")
            return
        self.set_status("Testing Recorded Future API connection...")
        self._test_rf_worker(draft)

    @on(Button.Pressed, "#settings-test-splunk-btn")
    def handle_test_splunk(self) -> None:
        draft, err = self._snapshot_draft_values()
        if err:
            self.set_status(f"Validation error: {err}")
            self.notify_user(err, title="Invalid Setting", severity="error")
            return
        self.set_status("Testing Splunk REST API connection...")
        self._test_splunk_worker(draft)

    @on(Button.Pressed, "#settings-test-s1-btn")
    def handle_test_s1(self) -> None:
        draft, err = self._snapshot_draft_values()
        if err:
            self.set_status(f"Validation error: {err}")
            self.notify_user(err, title="Invalid Setting", severity="error")
            return
        self.set_status("Testing SentinelOne Management API connection...")
        self._test_s1_worker(draft)

    @on(Button.Pressed, "#settings-test-all-btn")
    def handle_test_all(self) -> None:
        draft, err = self._snapshot_draft_values()
        if err:
            self.set_status(f"Validation error: {err}")
            self.notify_user(err, title="Invalid Setting", severity="error")
            return
        self.set_status("Testing configured connections (RF, Splunk, SentinelOne)...")
        self._test_all_worker(draft)

    def _run_rf_check(self, draft: dict[str, str | None]) -> str:
        token = draft.get("rf_api_token") or get_rf_token(required=True)
        base_url = draft.get("rf_base_url") or get_rf_base_url("core")
        sandbox_url = draft.get("rf_sandbox_base_url") or get_rf_base_url("sandbox")
        asi_url = draft.get("rf_asi_base_url") or get_rf_base_url("asi")
        pfi_url = draft.get("rf_pfi_base_url") or get_rf_base_url("pfi")
        rr_url = draft.get("rf_riskrecon_base_url") or get_rf_base_url("riskrecon")
        verify_ssl = self._resolve_draft_rf_ssl(draft)

        # If a non-RF injected test client is attached on app (no draft token override),
        # prefer verifying via its check_connection() if present.
        app_client = getattr(self.app, "client", None)
        if (
            app_client is not None
            and not isinstance(app_client, RecordedFutureClient)
            and callable(getattr(app_client, "check_connection", None))
        ):
            info = app_client.check_connection()
            return f"RF connected ({info})"

        client = RecordedFutureClient(
            api_token=token,
            sandbox_token=draft.get("rf_sandbox_token") or get_rf_sandbox_token(required=False),
            asi_api_key=draft.get("rf_asi_api_key") or get_rf_asi_key(required=False),
            pfi_token=draft.get("rf_pfi_token") or get_rf_pfi_token(required=False),
            riskrecon_token=draft.get("rf_riskrecon_token") or get_rf_riskrecon_token(required=False),
            base_url=base_url,
            sandbox_base_url=sandbox_url,
            asi_base_url=asi_url,
            pfi_base_url=pfi_url,
            riskrecon_base_url=rr_url,
            verify_ssl=verify_ssl,
            timeout=5.0,
            stop_event=getattr(self.app, "_stop_event", None),
        )
        try:
            info = client.check_connection()
            return f"RF OK ({info.get('base_url')}, {info.get('sample_lists', 0)} sample list(s))"
        finally:
            try:
                client.session.close()
            except Exception:
                pass

    def _run_splunk_check(self, draft: dict[str, str | None]) -> str:
        cfg = get_splunk_config(
            host=draft.get("splunk_host") or None,
            token=draft.get("splunk_token") if draft.get("splunk_token") else None,
            username=draft.get("splunk_username") if draft.get("splunk_username") else None,
            password=draft.get("splunk_password") if draft.get("splunk_password") else None,
            app=draft.get("splunk_app") or None,
            verify_ssl=draft.get("splunk_verify_ssl"),
            required=True,
        )
        with SplunkValidator(
            host=cfg.host,
            token=cfg.token,
            username=cfg.username,
            password=cfg.password,
            app=cfg.app,
            verify_ssl=cfg.verify_ssl,
            request_timeout=3.0,
            max_retries=0,
            backoff_base=0.05,
        ) as validator:
            ok = validator.check_connection()
        if not ok:
            raise RuntimeError(f"Splunk API returned unauthorized/unreachable for {cfg.host}")
        return f"Splunk OK ({cfg.host}, app={cfg.app})"

    def _run_s1_check(self, draft: dict[str, str | None]) -> str:
        raw_timeout = draft.get("s1_timeout")
        parsed_timeout: float | None = float(raw_timeout) if raw_timeout else None
        cfg = get_sentinelone_config(
            console_url=draft.get("s1_console_url") or None,
            api_token=draft.get("s1_api_token") if draft.get("s1_api_token") else None,
            account_id=draft.get("s1_account_id") if draft.get("s1_account_id") else None,
            site_id=draft.get("s1_site_id") if draft.get("s1_site_id") else None,
            verify_ssl=draft.get("s1_verify_ssl")
            if draft.get("s1_verify_ssl") is not None
            else self._resolve_draft_rf_ssl(draft),
            timeout=parsed_timeout if parsed_timeout is not None else 5.0,
            required=True,
        )
        app_s1 = getattr(self.app, "s1_client", None)
        if app_s1 is not None and not isinstance(app_s1, SentinelOneClient):
            info = app_s1.check_connection()
            return f"SentinelOne OK ({info.get('version') or info})"

        with SentinelOneClient(
            config=cfg,
            max_retries=0,
            stop_event=getattr(self.app, "_stop_event", None),
        ) as s1:
            info = s1.check_connection()
        version = str(info.get("latestAgentVersion") or info.get("version") or "connected")
        return f"SentinelOne OK ({cfg.console_url}, {version})"

    @work(thread=True, exit_on_error=False)
    def _test_rf_worker(self, draft: dict[str, str | None]) -> None:
        try:
            with self.log_scope("settings"):
                msg = self._run_rf_check(draft)
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="RF Connection OK")
        except Exception as exc:
            self.report_error("RF Connection Test", exc)

    @work(thread=True, exit_on_error=False)
    def _test_splunk_worker(self, draft: dict[str, str | None]) -> None:
        try:
            with self.log_scope("settings"):
                msg = self._run_splunk_check(draft)
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Splunk Connection OK")
        except Exception as exc:
            self.report_error("Splunk Connection Test", exc)

    @work(thread=True, exit_on_error=False)
    def _test_s1_worker(self, draft: dict[str, str | None]) -> None:
        try:
            with self.log_scope("settings"):
                msg = self._run_s1_check(draft)
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Connection OK")
        except Exception as exc:
            self.report_error("SentinelOne Connection Test", exc)

    @work(thread=True, exit_on_error=False)
    def _test_all_worker(self, draft: dict[str, str | None]) -> None:
        results: list[str] = []
        any_error = False

        for label, is_configured, runner in (
            (
                "RF",
                bool(draft.get("rf_api_token") or get_rf_token(required=False)),
                self._run_rf_check,
            ),
            (
                "Splunk",
                bool(
                    draft.get("splunk_token")
                    or (draft.get("splunk_username") and draft.get("splunk_password"))
                    or get_splunk_config(required=False).has_auth
                ),
                self._run_splunk_check,
            ),
            (
                "SentinelOne",
                bool(
                    (draft.get("s1_console_url") and draft.get("s1_api_token"))
                    or get_sentinelone_config(required=False).has_auth
                ),
                self._run_s1_check,
            ),
        ):
            if not is_configured:
                results.append(f"{label}: Not configured")
                continue
            try:
                with self.log_scope("settings"):
                    results.append(runner(draft))
            except Exception as exc:
                any_error = True
                results.append(f"{label}: FAILED ({exc})")

        summary = " | ".join(results)
        self.set_status(summary)
        self.append_log(summary, level="WARNING" if any_error else "INFO")
        self.notify_user(
            summary,
            title="Connection Checks",
            severity="warning" if any_error else "information",
        )

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        event.stop()
        items = [
            ("save", "Save Settings"),
            ("reload", "Reload from Disk"),
            ("import_env", "Import from Environment"),
            ("test_all", "Test Configured Connections"),
            ("open_dashboard", "Open Dashboard Tab"),
            ("open_logs", "Open Logs Tab"),
        ]

        def _on_select(action_id: str) -> None:
            if action_id == "save":
                self.handle_save_settings()
            elif action_id == "reload":
                self.handle_reload_settings()
            elif action_id == "import_env":
                self.handle_import_from_env()
            elif action_id == "test_all":
                self.handle_test_all()
            elif action_id == "open_dashboard":
                open_fn = getattr(self.app, "action_switch_tab", None)
                if callable(open_fn):
                    open_fn("tab-dashboard")
            elif action_id == "open_logs":
                open_logs = getattr(self.app, "open_logs_tab", None)
                if callable(open_logs):
                    open_logs()

        self.open_context_menu(
            items,
            title="Settings",
            origin=(event.screen_x, event.screen_y),
            on_select=_on_select,
        )
