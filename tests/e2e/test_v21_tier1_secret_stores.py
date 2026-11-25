"""Tier 1 E2E happy-path tests for SOCLens v2.1 Secret Stores & PAM (V21-F1..V21-F5)."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

import tests.e2e.v21_mocks as _v21
from soclens.config import (
    SecretStoreConfig,
    get_local_llm_config,
    get_secret_store_config,
    hydrate_secrets_from_store,
)
from soclens.secret_stores.bitwarden import BitwardenProvider
from soclens.secret_stores.hashicorp_vault import HashiCorpVaultProvider
from soclens.secret_stores.onepassword_connect import OnePasswordConnectProvider
from soclens.secret_stores.secret_server import SecretServerProvider
from soclens.settings import (
    SECRET_MANAGED_SETTING_KEYS,
    get_effective_setting,
    get_profile_settings,
    parse_vault_secret_map,
    save_profile_settings,
    serialize_vault_secret_map,
    set_session_overrides,
)

if TYPE_CHECKING:
    from tests.e2e.v21_mocks import (
        MockBitwardenServer,
        MockHashiCorpVaultServer,
        MockOnePasswordConnectServer,
        MockSecretServer,
    )

v21_workspace = _v21.v21_workspace
mock_secret_server = _v21.mock_secret_server
mock_vault_server = _v21.mock_vault_server
mock_op_connect_server = _v21.mock_op_connect_server
mock_bitwarden_server = _v21.mock_bitwarden_server

pytestmark = [pytest.mark.e2e, pytest.mark.tier1]

_FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "v21_secret_stores.json"


def _load_secret_fixtures() -> dict[str, Any]:
    return json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))


def _settings_file_path(workspace: Path) -> Path:
    raw = os.environ.get("SOCLENS_SETTINGS_FILE")
    if raw:
        return Path(raw)
    return workspace / "settings.json"


def _active_profile_dict(disk_data: dict[str, Any]) -> dict[str, Any]:
    profiles = disk_data.get("profiles")
    if isinstance(profiles, dict):
        active = disk_data.get("active_profile", "default")
        prof = profiles.get(active)
        if isinstance(prof, dict):
            return prof
    return disk_data


def _find_button_by_id_or_label(
    app: Any,
    candidate_ids: tuple[str, ...],
    label_substrings: tuple[str, ...],
) -> Any:
    from textual.widgets import Button

    for widget_id in candidate_ids:
        matches = app.query(f"#{widget_id}")
        if matches:
            return matches.first()
    for btn in app.query(Button):
        label = str(btn.label).lower()
        if any(sub in label for sub in label_substrings):
            return btn
    raise AssertionError(
        f"Button not found by IDs {candidate_ids} or label substrings {label_substrings}"
    )


# ==============================================================================
# V21-F1: Secret Server Provider
# ==============================================================================


@pytest.mark.feature("V21-F1")
def test_v21_f1_secret_server_password_auth_with_domain_and_test_connection(
    mock_secret_server: MockSecretServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TSS_DOMAIN", "CORP.EXAMPLE.TEST")
    mock_secret_server.set_required_domain("CORP.EXAMPLE.TEST")

    cfg = get_secret_store_config(provider="secret_server")
    with SecretServerProvider(cfg) as provider:
        result = provider.test_connection()

    assert result["ok"] is True
    assert result["auth_mode"] == "password"
    assert result["secret_count"] == 3

    token_reqs = [r for r in mock_secret_server.requests_log if r["path"] == "/oauth2/token"]
    assert len(token_reqs) == 1
    assert token_reqs[0]["form"].get("domain") == ["CORP.EXAMPLE.TEST"]


@pytest.mark.feature("V21-F1")
def test_v21_f1_secret_server_platform_auth_vault_discovery_and_list(
    mock_secret_server: MockSecretServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TSS_AUTH_MODE", "platform")
    monkeypatch.setenv("TSS_BASE_URL", "")
    monkeypatch.setenv("TSS_PLATFORM_URL", mock_secret_server.base_url)
    monkeypatch.setenv("TSS_CLIENT_ID", "e2e-tss-client-id")
    monkeypatch.setenv("TSS_CLIENT_SECRET", "e2e-tss-client-secret")

    cfg = get_secret_store_config(provider="secret_server")
    with SecretServerProvider(cfg) as provider:
        entries = provider.list_secrets(query="Splunk")

    assert entries
    assert all(e.item_id == "1002" for e in entries)
    assert {e.field_key for e in entries} == {"splunk-token", "username", "password"}

    paths = [r["path"] for r in mock_secret_server.requests_log]
    assert "/identity/api/oauth2/token/xpmplatform" in paths
    assert "/vaultbroker/api/vaults" in paths
    assert "/api/v1/secrets" in paths


@pytest.mark.feature("V21-F1")
def test_v21_f1_secret_server_token_auth_and_list_fields(
    mock_secret_server: MockSecretServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TSS_AUTH_MODE", "token")
    monkeypatch.setenv("TSS_ACCESS_TOKEN", "e2e-tss-preissued-token")

    cfg = get_secret_store_config(provider="secret_server")
    with SecretServerProvider(cfg) as provider:
        fields = provider.list_secret_fields("1002")

    by_slug = {f.field_key: f for f in fields}
    assert set(by_slug) == {"splunk-token", "username", "password"}
    assert by_slug["splunk-token"].is_secret is True
    assert by_slug["username"].is_secret is False
    assert by_slug["password"].is_secret is True

    oauth_reqs = [r for r in mock_secret_server.requests_log if "/oauth2/token" in r["path"]]
    assert oauth_reqs == []


@pytest.mark.feature("V21-F1")
def test_v21_f1_secret_server_proactive_refresh_and_401_retry_recovery(
    mock_secret_server: MockSecretServer,
) -> None:
    mock_secret_server.set_oauth_expires_in(30)

    cfg = get_secret_store_config(provider="secret_server")
    with SecretServerProvider(cfg) as provider:
        val1 = provider.get_secret_value("secret_server:1001:rf-api-token")
        assert val1 == "e2e-tss-rf-api-token"

        val2 = provider.get_secret_value("secret_server:1002:splunk-token")
        assert val2 == "e2e-tss-splunk-token"

        mock_secret_server.expire_access_token()
        val3 = provider.get_secret_value("secret_server:1003:s1-api-token")
        assert val3 == "e2e-tss-s1-api-token"

    grant_types = [
        r["form"].get("grant_type", [""])[0]
        for r in mock_secret_server.requests_log
        if r["path"] == "/oauth2/token"
    ]
    assert "password" in grant_types
    assert "refresh_token" in grant_types


@pytest.mark.feature("V21-F1")
def test_v21_f1_secret_server_batch_resolve_deduplicates_item_fetches(
    mock_secret_server: MockSecretServer,
) -> None:
    recommended = _load_secret_fixtures()["secret_server"]["recommended_map"]
    assert set(recommended) == set(SECRET_MANAGED_SETTING_KEYS)

    cfg = get_secret_store_config(provider="secret_server")
    with SecretServerProvider(cfg) as provider:
        resolved = provider.resolve_mapped_settings(recommended)

    assert len(resolved) == 10
    assert resolved["rf_api_token"] == "e2e-tss-rf-api-token"
    assert resolved["splunk_username"] == "e2e-tss-splunk-user"
    assert resolved["s1_api_token"] == "e2e-tss-s1-api-token"
    assert resolved["rf_llm_api_key"] == "e2e-tss-llm-api-key"

    item_gets = [
        r["path"]
        for r in mock_secret_server.requests_log
        if r["method"] == "GET" and r["path"].startswith("/api/v1/secrets/")
    ]
    assert sorted(item_gets) == [
        "/api/v1/secrets/1001",
        "/api/v1/secrets/1002",
        "/api/v1/secrets/1003",
    ]
    field_gets = [r for r in mock_secret_server.requests_log if "/fields/" in r["path"]]
    assert field_gets == []


@pytest.mark.feature("V21-F1")
def test_v21_f1_secret_server_v2_api_and_folder_filter(
    mock_secret_server: MockSecretServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TSS_API_VERSION", "v2")
    monkeypatch.setenv("TSS_FOLDER_ID", "20")

    cfg = get_secret_store_config(provider="secret_server")
    with SecretServerProvider(cfg) as provider:
        entries = provider.list_secrets()

    assert entries
    assert {e.item_id for e in entries} == {"1003"}
    assert {e.field_key for e in entries} == {"s1-api-token", "rf-llm-api-key"}

    v2_list_reqs = [
        r for r in mock_secret_server.requests_log if r["method"] == "GET" and r["path"] == "/api/v2/secrets"
    ]
    assert len(v2_list_reqs) == 1
    assert v2_list_reqs[0]["query"].get("filter.folderId") == ["20"]


# ==============================================================================
# V21-F2: HashiCorp Vault KV v2 Provider
# ==============================================================================


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_token_auth_and_namespace_header(
    mock_vault_server: MockHashiCorpVaultServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_vault_server.set_required_namespace("soc-prod")
    monkeypatch.setenv("VAULT_NAMESPACE", "soc-prod")

    cfg = get_secret_store_config(provider="hashicorp_vault")
    with HashiCorpVaultProvider(cfg) as provider:
        result = provider.test_connection()

    assert result["ok"] is True
    assert result["namespace"] == "soc-prod"

    lookup_reqs = [r for r in mock_vault_server.requests_log if r["path"] == "/v1/auth/token/lookup-self"]
    assert len(lookup_reqs) == 1
    hdrs = {k.lower(): v for k, v in lookup_reqs[0]["headers"].items()}
    assert hdrs.get("x-vault-token") == "e2e-vault-token-001"
    assert hdrs.get("x-vault-namespace") == "soc-prod"


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_approle_login_and_catalog_list_verb(
    mock_vault_server: MockHashiCorpVaultServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.setenv("VAULT_AUTH_MODE", "approle")
    monkeypatch.setenv("VAULT_ROLE_ID", "e2e-vault-role-001")
    monkeypatch.setenv("VAULT_SECRET_ID", "e2e-vault-secret-001")

    cfg = get_secret_store_config(provider="hashicorp_vault")
    with HashiCorpVaultProvider(cfg) as provider:
        entries = provider.list_secrets()

    assert len(entries) == 10
    methods_paths = [(r["method"], r["path"]) for r in mock_vault_server.requests_log]
    assert ("POST", "/v1/auth/approle/login") in methods_paths
    assert ("LIST", "/v1/secret/metadata") in methods_paths
    assert any(p.startswith("/v1/secret/subkeys/") for _, p in methods_paths)
    assert not any("/v1/secret/data/" in p for _, p in methods_paths)


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_list_405_fallback_to_get_list_true(
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    mock_vault_server.set_allow_list_verb(False)

    cfg = get_secret_store_config(provider="hashicorp_vault")
    with HashiCorpVaultProvider(cfg) as provider:
        entries = provider.list_secrets(query="splunk")

    assert len(entries) == 3
    assert all(e.item_id == "soclens/splunk" for e in entries)
    assert {e.field_key for e in entries} == {"token", "username", "password"}

    get_list_reqs = [
        r
        for r in mock_vault_server.requests_log
        if r["method"] == "GET" and r["path"].startswith("/v1/secret/metadata")
    ]
    assert any(r["query"].get("list") == ["true"] for r in get_list_reqs)


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_subkeys_403_fallback_to_kv_data_keys(
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    mock_vault_server.queue_fault("/v1/secret/subkeys/soclens/rf", 403)

    cfg = get_secret_store_config(provider="hashicorp_vault")
    with HashiCorpVaultProvider(cfg) as provider:
        entries = provider.list_secret_fields("soclens/rf")

    assert len(entries) == 5
    assert {e.field_key for e in entries} == {
        "api_token",
        "sandbox_token",
        "asi_api_key",
        "pfi_token",
        "riskrecon_token",
    }
    data_gets = [r for r in mock_vault_server.requests_log if r["path"] == "/v1/secret/data/soclens/rf"]
    assert len(data_gets) == 1


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_kv_v2_read_and_batch_resolve_deduplication(
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    recommended = _load_secret_fixtures()["hashicorp_vault"]["recommended_map"]

    cfg = get_secret_store_config(provider="hashicorp_vault")
    with HashiCorpVaultProvider(cfg) as provider:
        resolved = provider.resolve_mapped_settings(recommended)

    assert len(resolved) == 10
    assert resolved["rf_api_token"] == "e2e-vault-rf-api-token"
    assert resolved["splunk_token"] == "e2e-vault-splunk-token"
    assert resolved["s1_api_token"] == "e2e-vault-s1-api-token"
    assert resolved["rf_llm_api_key"] == "e2e-vault-llm-api-key"

    data_gets = [
        r["path"]
        for r in mock_vault_server.requests_log
        if r["method"] == "GET" and r["path"].startswith("/v1/secret/data/")
    ]
    assert sorted(data_gets) == [
        "/v1/secret/data/soclens/edr",
        "/v1/secret/data/soclens/llm",
        "/v1/secret/data/soclens/rf",
        "/v1/secret/data/soclens/splunk",
    ]


# ==============================================================================
# V21-F3: 1Password Connect & Bitwarden bw serve Providers
# ==============================================================================


@pytest.mark.feature("V21-F3")
def test_v21_f3_onepassword_test_connection_heartbeat_and_vaults(
    mock_op_connect_server: MockOnePasswordConnectServer,
) -> None:
    cfg = get_secret_store_config(provider="onepassword_connect")
    with OnePasswordConnectProvider(cfg) as provider:
        result = provider.test_connection()

    assert result["ok"] is True
    assert result["vault_count"] == 1
    assert result["vault_ids"] == ["11111111-1111-4111-8111-111111111111"]

    paths = [r["path"] for r in mock_op_connect_server.requests_log]
    assert "/heartbeat" in paths
    assert "/v1/vaults" in paths


@pytest.mark.feature("V21-F3")
def test_v21_f3_onepassword_list_secrets_and_batch_resolve(
    mock_op_connect_server: MockOnePasswordConnectServer,
) -> None:
    recommended = _load_secret_fixtures()["onepassword_connect"]["recommended_map"]

    cfg = get_secret_store_config(provider="onepassword_connect")
    with OnePasswordConnectProvider(cfg) as provider:
        entries = provider.list_secrets()
        mock_op_connect_server.requests_log.clear()
        resolved = provider.resolve_mapped_settings(recommended)

    assert len(entries) == 10
    assert len(resolved) == 10
    assert resolved["rf_api_token"] == "e2e-op-rf-api-token"
    assert resolved["splunk_password"] == "e2e-op-splunk-pass"
    assert resolved["s1_api_token"] == "e2e-op-s1-api-token"
    assert resolved["rf_llm_api_key"] == "e2e-op-llm-api-key"

    item_gets = [
        r["path"]
        for r in mock_op_connect_server.requests_log
        if r["method"] == "GET" and "/items/" in r["path"]
    ]
    assert len(item_gets) == 3


@pytest.mark.feature("V21-F3")
def test_v21_f3_onepassword_vault_scope_and_field_lookup(
    mock_op_connect_server: MockOnePasswordConnectServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault_id = "11111111-1111-4111-8111-111111111111"
    item_id = "22222222-2222-4222-8222-222222222202"
    monkeypatch.setenv("OP_VAULT_ID", vault_id)

    cfg = get_secret_store_config(provider="onepassword_connect")
    with OnePasswordConnectProvider(cfg) as provider:
        fields = provider.list_secret_fields(item_id)
        assert len(fields) == 3
        assert {f.field_key for f in fields} == {"splunk_token", "username", "password"}

        assert (
            provider.get_secret_value(f"onepassword_connect:{vault_id}/{item_id}:username")
            == "e2e-op-splunk-user"
        )
        assert (
            provider.get_secret_value(f"onepassword_connect:{vault_id}/{item_id}:password")
            == "e2e-op-splunk-pass"
        )
        assert (
            provider.get_secret_value(f"onepassword_connect:{vault_id}/{item_id}:splunk_token")
            == "e2e-op-splunk-token"
        )


@pytest.mark.feature("V21-F3")
def test_v21_f3_bitwarden_unlocked_status_sync_and_list_filters(
    mock_bitwarden_server: MockBitwardenServer,
) -> None:
    cfg = get_secret_store_config(provider="bitwarden")
    with BitwardenProvider(cfg) as provider:
        conn = provider.test_connection()
        assert conn["ok"] is True
        assert conn["status"] == "unlocked"
        assert conn["user_email"] == "analyst@example.test"

        provider.sync()
        assert mock_bitwarden_server.state["sync_count"] == 1

        entries = provider.list_secrets(query="Splunk")
        assert entries
        assert all(e.item_id == "33333333-3333-4333-8333-333333333302" for e in entries)
        assert {e.field_key for e in entries} == {"username", "password", "splunk_token"}


@pytest.mark.feature("V21-F3")
def test_v21_f3_bitwarden_locked_auto_unlock_with_master_password(
    mock_bitwarden_server: MockBitwardenServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_bitwarden_server.set_lock_status("locked")
    monkeypatch.setenv("BW_MASTER_PASSWORD", "e2e-bw-master-password")

    cfg = get_secret_store_config(provider="bitwarden")
    with BitwardenProvider(cfg) as provider:
        conn = provider.test_connection()
        entries = provider.list_secrets()

    assert conn["ok"] is True
    assert conn["unlocked_now"] is True
    assert len(entries) == 11
    assert set(_load_secret_fixtures()["bitwarden"]["recommended_map"].values()).issubset(
        {e.ref for e in entries}
    )
    unlock_reqs = [r for r in mock_bitwarden_server.requests_log if r["path"] == "/unlock"]
    assert len(unlock_reqs) == 1


@pytest.mark.feature("V21-F3")
def test_v21_f3_bitwarden_batch_resolve_login_and_custom_fields(
    mock_bitwarden_server: MockBitwardenServer,
) -> None:
    recommended = _load_secret_fixtures()["bitwarden"]["recommended_map"]

    cfg = get_secret_store_config(provider="bitwarden")
    with BitwardenProvider(cfg) as provider:
        resolved = provider.resolve_mapped_settings(recommended)

    assert len(resolved) == 10
    assert resolved["rf_api_token"] == "e2e-bw-rf-api-token"
    assert resolved["splunk_username"] == "e2e-bw-splunk-user"
    assert resolved["splunk_password"] == "e2e-bw-splunk-pass"
    assert resolved["splunk_token"] == "e2e-bw-splunk-token"
    assert resolved["s1_api_token"] == "e2e-bw-s1-api-token"
    assert resolved["rf_llm_api_key"] == "e2e-bw-llm-api-key"

    item_gets = [
        r["path"]
        for r in mock_bitwarden_server.requests_log
        if r["method"] == "GET" and r["path"].startswith("/object/item/")
    ]
    assert len(item_gets) == 3


# ==============================================================================
# V21-F4: Settings & Memory Hydration
# ==============================================================================


@pytest.mark.feature("V21-F4")
def test_v21_f4_settings_persist_vault_map_only_zero_plaintext_secrets_on_disk(
    v21_workspace: Path,
    mock_vault_server: MockHashiCorpVaultServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for env_key in (
        "RF_API_TOKEN",
        "RF_SANDBOX_TOKEN",
        "RECORDED_FUTURE_API_KEY",
        "RECORDED_FUTURE_API_TOKEN",
        "RECORDED_FUTURE_SANDBOX_TOKEN",
        "SPLUNK_TOKEN",
        "S1_API_TOKEN",
    ):
        monkeypatch.delenv(env_key, raising=False)

    recommended = _load_secret_fixtures()["hashicorp_vault"]["recommended_map"]
    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_secret_map": serialize_vault_secret_map(recommended),
        }
    )

    hydrated = hydrate_secrets_from_store()
    assert set(hydrated) == set(SECRET_MANAGED_SETTING_KEYS)
    effective_values: dict[str, str] = {}
    for key in SECRET_MANAGED_SETTING_KEYS:
        val = get_effective_setting(key)
        assert val is not None and val.startswith("e2e-vault-")
        effective_values[key] = val

    # Re-saving settings including a hydrated secret key must NOT leak pulled tokens to disk
    save_profile_settings(
        {
            "splunk_app": "CustomES",
            "splunk_password": effective_values["splunk_password"],
        }
    )

    settings_path = _settings_file_path(v21_workspace)
    if os.name == "posix":
        assert stat.S_IMODE(settings_path.stat().st_mode) == 0o600
    raw_disk = settings_path.read_text(encoding="utf-8")
    assert json.loads(raw_disk)["encrypted"] is True
    profile_data = get_profile_settings()
    assert "vault_secret_map" in profile_data
    assert profile_data.get("splunk_app") == "CustomES"
    assert "splunk_password" not in profile_data
    for pulled_val in effective_values.values():
        assert pulled_val not in raw_disk


@pytest.mark.feature("V21-F4")
def test_v21_f4_env_var_precedence_preserved_on_startup_hydration_and_overridden_on_pull(
    v21_workspace: Path,
    mock_secret_server: MockSecretServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recommended = _load_secret_fixtures()["secret_server"]["recommended_map"]
    save_profile_settings(
        {
            "secret_provider": "secret_server",
            "vault_secret_map": serialize_vault_secret_map(recommended),
        }
    )
    monkeypatch.setenv("RF_API_TOKEN", "env-rf-precedence")

    startup_hydrated = hydrate_secrets_from_store(overwrite_existing=False)
    assert "rf_api_token" not in startup_hydrated
    assert get_effective_setting("rf_api_token") == "env-rf-precedence"

    pulled = hydrate_secrets_from_store(force=True, overwrite_existing=True)
    assert "rf_api_token" in pulled
    assert "e2e-tss-rf-api-token" not in pulled["rf_api_token"]
    assert get_effective_setting("rf_api_token") == "e2e-tss-rf-api-token"
    assert os.environ["RF_API_TOKEN"] == "env-rf-precedence"


@pytest.mark.feature("V21-F4")
def test_v21_f4_rf_llm_api_key_in_secret_managed_keys_and_get_local_llm_config(
    v21_workspace: Path,
    mock_op_connect_server: MockOnePasswordConnectServer,
) -> None:
    assert "rf_llm_api_key" in SECRET_MANAGED_SETTING_KEYS
    recommended = _load_secret_fixtures()["onepassword_connect"]["recommended_map"]
    save_profile_settings(
        {
            "secret_provider": "onepassword_connect",
            "vault_secret_map": serialize_vault_secret_map(
                {"rf_llm_api_key": recommended["rf_llm_api_key"]}
            ),
        }
    )

    hydrate_secrets_from_store()
    llm_cfg = get_local_llm_config(provider="openai")
    assert llm_cfg.api_key == "e2e-op-llm-api-key"
    assert "e2e-op-llm-api-key" not in repr(llm_cfg)


@pytest.mark.feature("V21-F4")
def test_v21_f4_bootstrap_secrets_and_bw_master_password_blank_default(
    v21_workspace: Path,
    mock_bitwarden_server: MockBitwardenServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert get_secret_store_config().bw_master_password is None

    cfg_repr = repr(
        SecretStoreConfig(
            provider="bitwarden",
            tss_password="sentinel-tss-password-xyz",
            tss_client_secret="sentinel-tss-client-secret-xyz",
            tss_access_token="sentinel-tss-access-token-xyz",
            vault_token="sentinel-vault-token-xyz",
            vault_secret_id="sentinel-vault-secret-id-xyz",
            op_connect_token="sentinel-op-connect-token-xyz",
            bw_master_password="sentinel-bw-master-pw-xyz",
        )
    )
    for sentinel in (
        "sentinel-tss-password-xyz",
        "sentinel-tss-client-secret-xyz",
        "sentinel-tss-access-token-xyz",
        "sentinel-vault-token-xyz",
        "sentinel-vault-secret-id-xyz",
        "sentinel-op-connect-token-xyz",
        "sentinel-bw-master-pw-xyz",
    ):
        assert sentinel not in cfg_repr

    save_profile_settings({"vault_token": "saved-vault-tok"})
    settings_path = _settings_file_path(v21_workspace)
    if os.name == "posix":
        assert stat.S_IMODE(settings_path.stat().st_mode) == 0o600
    assert get_secret_store_config().vault_token == "saved-vault-tok"

    monkeypatch.setenv("VAULT_TOKEN", "env-vault-tok")
    assert get_secret_store_config().vault_token == "env-vault-tok"

    set_session_overrides({"vault_token": "session-vault-tok"})
    assert get_secret_store_config().vault_token == "session-vault-tok"
    assert os.environ["VAULT_TOKEN"] == "env-vault-tok"


@pytest.mark.feature("V21-F4")
def test_v21_f4_secret_store_config_inherits_rf_verify_ssl_and_validates_map(
    v21_workspace: Path,
) -> None:
    recommended = _load_secret_fixtures()["secret_server"]["recommended_map"]
    save_profile_settings({"rf_verify_ssl": "false"})

    cfg = get_secret_store_config()
    assert cfg.verify_ssl is False

    serialized = serialize_vault_secret_map(recommended)
    assert "\n" not in serialized
    parsed = parse_vault_secret_map(serialized, strict=True)
    assert parsed == recommended


@pytest.mark.feature("V21-F4")
def test_v21_f4_cli_no_secret_store_flag_skips_vault_hydration(
    v21_workspace: Path,
    mock_vault_server: MockHashiCorpVaultServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Awaits Wave 2 (M4): soclens --no-secret-store global flag + CLI startup hydration."""
    recommended = _load_secret_fixtures()["hashicorp_vault"]["recommended_map"]
    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_secret_map": serialize_vault_secret_map(recommended),
        }
    )

    proc = run_cli(["--no-secret-store", "settings", "show", "--json"])
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
    assert mock_vault_server.requests_log == []


# ==============================================================================
# V21-F5: soclens secrets CLI & SettingsPane cat-secrets + Dynamic Swap + Startup
# ==============================================================================


@pytest.mark.feature("V21-F5")
def test_v21_f5_cli_secrets_test_list_and_fields(
    v21_workspace: Path,
    mock_secret_server: MockSecretServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Awaits Wave 2 (M4): soclens secrets {test,list,fields} CLI commands."""
    save_profile_settings(
        {
            "secret_provider": "secret_server",
            "tss_base_url": mock_secret_server.base_url,
            "tss_username": "e2e-tss-user",
            "tss_password": "e2e-tss-password",
        }
    )

    test_proc = run_cli(["--json", "secrets", "test"])
    assert test_proc.returncode == 0, f"stdout={test_proc.stdout}\nstderr={test_proc.stderr}"
    test_payload = json.loads(test_proc.stdout)
    assert test_payload.get("ok") is True

    list_proc = run_cli(["--json", "secrets", "list", "--search", "Splunk"])
    assert list_proc.returncode == 0, f"stdout={list_proc.stdout}\nstderr={list_proc.stderr}"
    list_payload = json.loads(list_proc.stdout)
    list_items = (
        list_payload
        if isinstance(list_payload, list)
        else (
            list_payload.get("secrets")
            or list_payload.get("entries")
            or list_payload.get("items")
            or []
        )
    )
    refs = [item.get("ref") for item in list_items]
    assert "secret_server:1002:splunk-token" in refs

    masked_proc = run_cli(["--json", "secrets", "fields", "1002"])
    assert masked_proc.returncode == 0, f"stdout={masked_proc.stdout}\nstderr={masked_proc.stderr}"
    assert json.loads(masked_proc.stdout)
    assert "splunk-token" in masked_proc.stdout
    assert "e2e-tss-splunk-token" not in masked_proc.stdout

    reveal_proc = run_cli(["--json", "secrets", "fields", "1002", "--reveal"])
    assert reveal_proc.returncode == 0, f"stdout={reveal_proc.stdout}\nstderr={reveal_proc.stderr}"
    assert json.loads(reveal_proc.stdout)
    assert "e2e-tss-splunk-token" in reveal_proc.stdout


@pytest.mark.feature("V21-F5")
def test_v21_f5_cli_secrets_map_pull_and_unmap(
    v21_workspace: Path,
    mock_secret_server: MockSecretServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Awaits Wave 2 (M4): soclens secrets {map,pull,unmap} CLI commands."""
    save_profile_settings(
        {
            "secret_provider": "secret_server",
            "tss_base_url": mock_secret_server.base_url,
            "tss_username": "e2e-tss-user",
            "tss_password": "e2e-tss-password",
        }
    )

    m1 = run_cli(["secrets", "map", "rf_api_token", "secret_server:1001:rf-api-token", "--json"])
    assert m1.returncode == 0, f"stdout={m1.stdout}\nstderr={m1.stderr}"
    m2 = run_cli(["secrets", "map", "s1_api_token", "secret_server:1003:s1-api-token", "--json"])
    assert m2.returncode == 0, f"stdout={m2.stdout}\nstderr={m2.stderr}"

    pull_proc = run_cli(["secrets", "pull", "--json"])
    assert pull_proc.returncode == 0, f"stdout={pull_proc.stdout}\nstderr={pull_proc.stderr}"
    assert json.loads(pull_proc.stdout)
    assert "e2e-tss-rf-api-token" not in pull_proc.stdout
    assert "e2e-tss-s1-api-token" not in pull_proc.stdout

    settings_text = _settings_file_path(v21_workspace).read_text(encoding="utf-8")
    assert json.loads(settings_text)["encrypted"] is True
    profile_data = get_profile_settings()
    saved_map = parse_vault_secret_map(profile_data.get("vault_secret_map", ""))
    assert saved_map["rf_api_token"] == "secret_server:1001:rf-api-token"
    assert saved_map["s1_api_token"] == "secret_server:1003:s1-api-token"
    assert "e2e-tss-rf-api-token" not in settings_text
    assert "e2e-tss-s1-api-token" not in settings_text

    unmap_proc = run_cli(["secrets", "unmap", "s1_api_token", "--json"])
    assert unmap_proc.returncode == 0, f"stdout={unmap_proc.stdout}\nstderr={unmap_proc.stderr}"
    assert json.loads(_settings_file_path(v21_workspace).read_text(encoding="utf-8"))["encrypted"] is True
    profile_after = get_profile_settings()
    after_map = parse_vault_secret_map(profile_after.get("vault_secret_map", ""))
    assert "s1_api_token" not in after_map
    assert after_map["rf_api_token"] == "secret_server:1001:rf-api-token"


@pytest.mark.feature("V21-F5")
def test_v21_f5_tui_cat_secrets_provider_groups_and_masked_bootstrap_inputs(
    v21_workspace: Path,
    mock_secret_server: MockSecretServer,
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    """Awaits Wave 2 (M4): SettingsPane cat-secrets tab and masked bootstrap inputs."""
    from textual.widgets import Checkbox, ContentSwitcher, Select

    from soclens.tui import create_app

    app = create_app(dry_run=True, initial_tab="tab-settings", workspace_dir=v21_workspace, view_mode="admin")

    async def _run() -> None:
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            switcher = app.query_one("#settings-category-switcher", ContentSwitcher)
            switcher.current = "cat-secrets"
            await pilot.pause()

            provider_sel = app.query_one("#set-secret-provider", Select)
            for prov, expected_group in (
                ("secret_server", "#tss-fields-group"),
                ("hashicorp_vault", "#vault-fields-group"),
                ("onepassword_connect", "#op-fields-group"),
                ("bitwarden", "#bw-fields-group"),
            ):
                provider_sel.value = prov
                await pilot.pause()
                for gid in (
                    "#tss-fields-group",
                    "#vault-fields-group",
                    "#op-fields-group",
                    "#bw-fields-group",
                ):
                    assert app.query_one(gid).display is (gid == expected_group)

            secret_inputs = [
                inp
                for inp in app.query("#cat-secrets Input")
                if any(
                    tok in (inp.id or "")
                    for tok in ("password", "secret", "token")
                )
            ]
            assert secret_inputs
            assert all(inp.password is True for inp in secret_inputs)

            show_cb = app.query_one("#settings-show-secrets", Checkbox)
            show_cb.value = True
            await pilot.pause()
            assert all(inp.password is False for inp in secret_inputs)

    asyncio.run(_run())


@pytest.mark.feature("V21-F5")
def test_v21_f5_tui_dynamic_input_to_vault_select_swap_and_save(
    v21_workspace: Path,
    mock_vault_server: MockHashiCorpVaultServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Awaits Wave 2 (M4): Dynamic Input <-> Select vault dropdown swap in SettingsPane."""
    from textual.widgets import ContentSwitcher, Input, Select

    from soclens.tui import create_app

    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    app = create_app(dry_run=True, initial_tab="tab-settings", workspace_dir=v21_workspace, view_mode="admin")

    async def _run() -> None:
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            app.query_one("#settings-category-switcher", ContentSwitcher).current = "cat-secrets"
            await pilot.pause()

            app.query_one("#set-secret-provider", Select).value = "hashicorp_vault"
            await pilot.pause()
            app.query_one("#set-vault-addr", Input).value = mock_vault_server.base_url
            app.query_one("#set-vault-token", Input).value = "e2e-vault-token-001"
            await pilot.pause()

            refresh_btn = _find_button_by_id_or_label(
                app,
                ("settings-refresh-catalog-btn", "settings-secrets-refresh-btn", "secrets-refresh-catalog-btn"),
                ("refresh", "catalog"),
            )
            await pilot.click(f"#{refresh_btn.id}")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#set-rf-api-token", Input).display is False
            rf_vault_sel = app.query_one("#set-rf-api-token-vault", Select)
            assert rf_vault_sel.display is True
            assert app.query_one("#set-splunk-token-vault", Select).display is True
            assert app.query_one("#set-s1-api-token-vault", Select).display is True

            rf_vault_sel.value = "hashicorp_vault:soclens/rf:api_token"
            app.query_one("#set-splunk-token-vault", Select).value = "hashicorp_vault:soclens/splunk:token"
            app.query_one("#set-s1-api-token-vault", Select).value = "hashicorp_vault:soclens/edr:s1_api_token"
            await pilot.pause()

            await pilot.click("#settings-save-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            raw_disk = _settings_file_path(v21_workspace).read_text(encoding="utf-8")
            assert json.loads(raw_disk)["encrypted"] is True
            profile_data = get_profile_settings()
            saved_map = parse_vault_secret_map(profile_data.get("vault_secret_map", ""))
            assert saved_map["rf_api_token"] == "hashicorp_vault:soclens/rf:api_token"
            assert "e2e-vault-rf-api-token" not in raw_disk
            assert get_effective_setting("rf_api_token") == "e2e-vault-rf-api-token"

    asyncio.run(_run())


@pytest.mark.feature("V21-F5")
def test_v21_f5_tui_vault_dropdown_offline_saved_ref_fallback_and_toggle_back(
    v21_workspace: Path,
) -> None:
    """Awaits Wave 2 (M4): Saved ref fallback on offline vault & toggle back to none."""
    from textual.widgets import ContentSwitcher, Input, Select

    from soclens.tui import create_app

    saved_ref = "hashicorp_vault:soclens/rf:api_token"
    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": "http://127.0.0.1:9",
            "vault_token": "e2e-vault-token-001",
            "vault_secret_map": serialize_vault_secret_map({"rf_api_token": saved_ref}),
        }
    )

    app = create_app(dry_run=True, initial_tab="tab-settings", workspace_dir=v21_workspace, view_mode="admin")

    async def _run() -> None:
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            rf_vault_sel = app.query_one("#set-rf-api-token-vault", Select)
            assert rf_vault_sel.display is True
            assert rf_vault_sel.value == saved_ref
            assert app.query_one("#set-rf-api-token", Input).display is False

            app.query_one("#settings-category-switcher", ContentSwitcher).current = "cat-secrets"
            await pilot.pause()
            app.query_one("#set-secret-provider", Select).value = "none"
            await pilot.pause()

            assert app.query_one("#set-rf-api-token", Input).display is True
            assert rf_vault_sel.display is False

    asyncio.run(_run())


@pytest.mark.feature("V21-F5")
def test_v21_f5_tui_startup_nonblocking_hydration_populates_panes(
    v21_workspace: Path,
    mock_op_connect_server: MockOnePasswordConnectServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Awaits Wave 2 (M4): Non-blocking TUI startup hydration worker in SocLensApp."""
    from soclens.tui import create_app

    for env_key in (
        "RF_API_TOKEN",
        "RF_SANDBOX_TOKEN",
        "RECORDED_FUTURE_API_KEY",
        "RECORDED_FUTURE_API_TOKEN",
        "RECORDED_FUTURE_SANDBOX_TOKEN",
        "SPLUNK_TOKEN",
        "S1_API_TOKEN",
    ):
        monkeypatch.delenv(env_key, raising=False)

    recommended = _load_secret_fixtures()["onepassword_connect"]["recommended_map"]
    save_profile_settings(
        {
            "secret_provider": "onepassword_connect",
            "op_connect_url": mock_op_connect_server.base_url,
            "op_connect_token": "e2e-op-connect-token-001",
            "vault_secret_map": serialize_vault_secret_map(recommended),
        }
    )

    app = create_app(dry_run=True, workspace_dir=v21_workspace, view_mode="user")

    async def _run() -> None:
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert get_effective_setting("rf_api_token") == "e2e-op-rf-api-token"
            assert app.client.api_token == "e2e-op-rf-api-token"

    asyncio.run(_run())
