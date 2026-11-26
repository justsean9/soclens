"""Tier 2 boundary, error-handling, and corner-case E2E tests for Secret Stores (V21-F1..V21-F5)."""

from __future__ import annotations

import asyncio
import json
import socket
import stat
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from soclens.config import (
    SecretStoreConfig,
    get_local_llm_config,
    get_secret_store_config,
    hydrate_secrets_from_store,
)
from soclens.secret_stores import build_secret_store_provider
from soclens.secret_stores.base import (
    SecretCatalogEntry,
    SecretStoreAuthError,
    SecretStoreError,
    SecretStoreNotFoundError,
    parse_secret_ref,
)
from soclens.settings import (
    SECRET_MANAGED_SETTING_KEYS,
    SETTING_SPECS_BY_KEY,
    clear_session_overrides,
    get_effective_setting,
    get_profile_settings,
    get_setting_with_source,
    mask_secret,
    parse_vault_secret_map,
    save_profile_settings,
    validate_settings_values,
)
from tests.e2e import conftest as _e2e_conftest
from tests.e2e import v21_mocks as _v21_mocks

if TYPE_CHECKING:
    from tests.e2e.v21_mocks import (
        MockBitwardenServer,
        MockHashiCorpVaultServer,
        MockOnePasswordConnectServer,
        MockSecretServer,
        MockSentinelOneServer,
    )

pytestmark = [pytest.mark.e2e, pytest.mark.tier2]

v21_workspace = _v21_mocks.v21_workspace
mock_secret_server = _v21_mocks.mock_secret_server
mock_vault_server = _v21_mocks.mock_vault_server
mock_op_connect_server = _v21_mocks.mock_op_connect_server
mock_bitwarden_server = _v21_mocks.mock_bitwarden_server
mock_s1_server = _v21_mocks.mock_s1_server
run_cli = _e2e_conftest.run_cli


async def _wait_until(
    pilot: Any,
    predicate: Callable[[], bool],
    *,
    max_steps: int = 60,
    delay: float = 0.05,
) -> None:
    for _ in range(max_steps):
        if predicate():
            return
        await pilot.pause(delay)
    assert predicate(), "Timed out waiting for async TUI state"


def _unused_local_url() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    return f"http://127.0.0.1:{port}"


def _read_json_output(proc: Any) -> Any:
    for stream in (proc.stdout, proc.stderr):
        raw = (stream or "").strip()
        if not raw:
            continue
        try:
            return json.loads(raw)
        except ValueError:
            continue
    return None


# ======================================================================
# V21-F1: Secret Server Provider (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F1")
def test_v21_f1_tss_401_triggers_single_use_refresh_token_retry(
    mock_secret_server: MockSecretServer,
) -> None:
    cfg = SecretStoreConfig(
        provider="secret_server",
        tss_base_url=mock_secret_server.base_url,
        tss_auth_mode="password",
        tss_username="e2e-tss-user",
        tss_password="e2e-tss-password",
    )
    with build_secret_store_provider(cfg) as provider:
        val1 = provider.get_secret_value("secret_server:1001:rf-api-token")
        assert val1 == "e2e-tss-rf-api-token"

        mock_secret_server.expire_access_token()
        val2 = provider.get_secret_value("secret_server:1001:rf-api-token")
        assert val2 == "e2e-tss-rf-api-token"

        mock_secret_server.expire_access_token()
        val3 = provider.get_secret_value("secret_server:1001:rf-api-token")
        assert val3 == "e2e-tss-rf-api-token"

    token_posts = [r for r in mock_secret_server.requests_log if r["path"] == "/oauth2/token"]
    password_grants = [r for r in token_posts if r["form"].get("grant_type") == ["password"]]
    refresh_grants = [r for r in token_posts if r["form"].get("grant_type") == ["refresh_token"]]
    assert len(password_grants) == 1
    assert len(refresh_grants) == 2
    used_rts = [r["form"]["refresh_token"][0] for r in refresh_grants]
    assert len(set(used_rts)) == 2


@pytest.mark.feature("V21-F1")
def test_v21_f1_tss_refresh_rejected_falls_back_to_password_grant(
    mock_secret_server: MockSecretServer,
) -> None:
    cfg = SecretStoreConfig(
        provider="secret_server",
        tss_base_url=mock_secret_server.base_url,
        tss_auth_mode="password",
        tss_username="e2e-tss-user",
        tss_password="e2e-tss-password",
    )
    with build_secret_store_provider(cfg) as provider:
        assert provider.get_secret_value("secret_server:1001:rf-api-token") == "e2e-tss-rf-api-token"

        mock_secret_server.expire_access_token()
        mock_secret_server.queue_fault(
            "/oauth2/token",
            400,
            {"error": "invalid_grant", "error_description": "Refresh rejected"},
            method="POST",
            count=1,
        )
        val = provider.get_secret_value("secret_server:1001:rf-api-token")
        assert val == "e2e-tss-rf-api-token"

    token_posts = [r for r in mock_secret_server.requests_log if r["path"] == "/oauth2/token"]
    grants = [r["form"].get("grant_type", [""])[0] for r in token_posts]
    assert grants == ["password", "refresh_token", "password"]


@pytest.mark.feature("V21-F1")
def test_v21_f1_tss_token_mode_401_raises_auth_error_without_retry(
    mock_secret_server: MockSecretServer,
) -> None:
    cfg = SecretStoreConfig(
        provider="secret_server",
        tss_base_url=mock_secret_server.base_url,
        tss_auth_mode="token",
        tss_access_token="invalid-preissued-token-999",
    )
    with build_secret_store_provider(cfg) as provider:
        with pytest.raises(SecretStoreAuthError) as exc_info:
            provider.get_secret_value("secret_server:1001:rf-api-token")
    assert exc_info.value.status_code == 401
    assert exc_info.value.reason == "unauthorized"
    assert len(mock_secret_server.requests_log) == 1
    assert not [r for r in mock_secret_server.requests_log if r["path"] == "/oauth2/token"]


@pytest.mark.feature("V21-F1")
def test_v21_f1_tss_403_and_404_error_classification(
    mock_secret_server: MockSecretServer,
) -> None:
    cfg = SecretStoreConfig(
        provider="secret_server",
        tss_base_url=mock_secret_server.base_url,
        tss_auth_mode="password",
        tss_username="e2e-tss-user",
        tss_password="e2e-tss-password",
    )
    with build_secret_store_provider(cfg) as provider:
        mock_secret_server.queue_fault(
            "/api/v1/secrets/1001",
            403,
            {"message": "Access denied to secret 1001"},
            method="GET",
            count=1,
        )
        with pytest.raises(SecretStoreAuthError) as auth_exc:
            provider.list_secret_fields("1001")
        assert auth_exc.value.status_code == 403

        with pytest.raises(SecretStoreNotFoundError) as nf_secret:
            provider.list_secret_fields("999999")
        assert nf_secret.value.status_code == 404

        with pytest.raises(SecretStoreNotFoundError) as nf_field:
            provider.get_secret_value("secret_server:1001:nonexistent-slug")
        assert nf_field.value.status_code == 404


@pytest.mark.feature("V21-F1")
def test_v21_f1_tss_bad_password_and_missing_creds_fail_cleanly(
    mock_secret_server: MockSecretServer,
) -> None:
    canary_bad_pw = "canary-wrong-tss-pw-xyz"
    bad_pw_cfg = SecretStoreConfig(
        provider="secret_server",
        tss_base_url=mock_secret_server.base_url,
        tss_auth_mode="password",
        tss_username="e2e-tss-user",
        tss_password=canary_bad_pw,
    )
    with build_secret_store_provider(bad_pw_cfg) as provider:
        with pytest.raises(SecretStoreAuthError) as exc_info:
            provider.test_connection()
    assert canary_bad_pw not in str(exc_info.value)

    missing_user_cfg = SecretStoreConfig(
        provider="secret_server",
        tss_base_url=mock_secret_server.base_url,
        tss_auth_mode="password",
        tss_username="",
        tss_password="e2e-tss-password",
    )
    req_before = len(mock_secret_server.requests_log)
    with build_secret_store_provider(missing_user_cfg) as provider:
        with pytest.raises(SecretStoreAuthError) as missing_exc:
            provider.test_connection()
    assert missing_exc.value.reason == "missing_credentials"
    assert len(mock_secret_server.requests_log) == req_before

    mock_secret_server.set_required_domain("CORP.EXAMPLE.TEST")
    no_domain_cfg = SecretStoreConfig(
        provider="secret_server",
        tss_base_url=mock_secret_server.base_url,
        tss_auth_mode="password",
        tss_username="e2e-tss-user",
        tss_password="e2e-tss-password",
        tss_domain=None,
    )
    with build_secret_store_provider(no_domain_cfg) as provider:
        with pytest.raises(SecretStoreAuthError):
            provider.test_connection()

    ok_domain_cfg = SecretStoreConfig(
        provider="secret_server",
        tss_base_url=mock_secret_server.base_url,
        tss_auth_mode="password",
        tss_username="e2e-tss-user",
        tss_password="e2e-tss-password",
        tss_domain="CORP.EXAMPLE.TEST",
    )
    with build_secret_store_provider(ok_domain_cfg) as provider:
        assert provider.test_connection()["ok"] is True


@pytest.mark.feature("V21-F1")
def test_v21_f1_tss_close_revokes_token_and_cancellation_aborts(
    mock_secret_server: MockSecretServer,
) -> None:
    cfg = SecretStoreConfig(
        provider="secret_server",
        tss_base_url=mock_secret_server.base_url,
        tss_auth_mode="password",
        tss_username="e2e-tss-user",
        tss_password="e2e-tss-password",
    )
    provider = build_secret_store_provider(cfg)
    assert provider.get_secret_value("secret_server:1001:rf-api-token") == "e2e-tss-rf-api-token"
    provider.close()

    revoke_calls = [
        r for r in mock_secret_server.requests_log if r["path"] == "/api/v1/oauth-expiration"
    ]
    assert len(revoke_calls) == 1
    assert getattr(provider, "_access_token", None) is None

    stop = threading.Event()
    stop.set()
    req_before = len(mock_secret_server.requests_log)
    with build_secret_store_provider(cfg, stop_event=stop) as cancelled_provider:
        with pytest.raises(SecretStoreError) as exc_info:
            cancelled_provider.get_secret_value("secret_server:1001:rf-api-token")
    assert exc_info.value.reason == "cancelled"
    assert len(mock_secret_server.requests_log) == req_before


# ======================================================================
# V21-F2: HashiCorp Vault KV v2 Provider (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_subkeys_403_falls_back_to_data_read(
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    mock_vault_server.queue_fault("/v1/secret/subkeys/", 403, {"errors": ["subkeys denied"]})
    cfg = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_auth_mode="token",
        vault_token="e2e-vault-token-001",
        vault_kv_mount="secret",
    )
    with build_secret_store_provider(cfg) as provider:
        entries = provider.list_secret_fields("soclens/rf")
    assert entries
    assert all(isinstance(e, SecretCatalogEntry) for e in entries)
    assert {e.field_key for e in entries} >= {"api_token", "sandbox_token", "asi_api_key"}
    paths = [r["path"] for r in mock_vault_server.requests_log]
    assert "/v1/secret/subkeys/soclens/rf" in paths
    assert "/v1/secret/data/soclens/rf" in paths


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_subkeys_404_fallback_and_missing_secret_404(
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    mock_vault_server.queue_fault("/v1/secret/subkeys/soclens/rf", 404, {"errors": []})
    cfg = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_auth_mode="token",
        vault_token="e2e-vault-token-001",
        vault_kv_mount="secret",
    )
    with build_secret_store_provider(cfg) as provider:
        entries = provider.list_secret_fields("soclens/rf")
        assert {e.field_key for e in entries} >= {"api_token"}

        with pytest.raises(SecretStoreNotFoundError) as exc_info:
            provider.list_secret_fields("soclens/does-not-exist")
        assert exc_info.value.status_code == 404


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_list_verb_405_falls_back_to_get_list_true(
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    mock_vault_server.set_allow_list_verb(False)
    cfg = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_auth_mode="token",
        vault_token="e2e-vault-token-001",
        vault_kv_mount="secret",
    )
    with build_secret_store_provider(cfg) as provider:
        entries = provider.list_secrets()
    assert any(e.ref == "hashicorp_vault:soclens/rf:api_token" for e in entries)
    list_calls = [r for r in mock_vault_server.requests_log if r["method"] == "LIST"]
    get_list_calls = [
        r
        for r in mock_vault_server.requests_log
        if r["method"] == "GET" and r["query"].get("list") == ["true"]
    ]
    assert list_calls
    assert get_list_calls

    empty_cfg = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_auth_mode="token",
        vault_token="e2e-vault-token-001",
        vault_kv_mount="secret",
        vault_prefix="soclens/nonexistent-prefix",
    )
    with build_secret_store_provider(empty_cfg) as empty_provider:
        assert empty_provider.list_secrets() == []


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_sealed_503_and_bad_token_403(
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    mock_vault_server.set_sealed(True)
    mock_vault_server.queue_fault("/v1/auth/token/lookup-self", 501, {"errors": ["unsupported"]})
    cfg = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_auth_mode="token",
        vault_token="e2e-vault-token-001",
    )
    with build_secret_store_provider(cfg) as provider:
        with pytest.raises(SecretStoreError) as sealed_exc:
            provider.test_connection()
    assert sealed_exc.value.status_code == 503
    assert sealed_exc.value.reason == "vault_sealed"

    mock_vault_server.set_sealed(False)
    bad_cfg = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_auth_mode="token",
        vault_token="invalid-vault-token-999",
    )
    with build_secret_store_provider(bad_cfg) as provider:
        with pytest.raises(SecretStoreAuthError) as auth_exc:
            provider.test_connection()
    assert auth_exc.value.status_code == 403


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_namespace_mismatch_rejected_with_403(
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    mock_vault_server.set_required_namespace("soc-prod")
    wrong_ns_cfg = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_auth_mode="token",
        vault_token="e2e-vault-token-001",
        vault_namespace="soc-dev",
    )
    with build_secret_store_provider(wrong_ns_cfg) as provider:
        with pytest.raises(SecretStoreAuthError) as exc_info:
            provider.get_secret_value("hashicorp_vault:soclens/rf:api_token")
    assert exc_info.value.status_code == 403

    ok_ns_cfg = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_auth_mode="token",
        vault_token="e2e-vault-token-001",
        vault_namespace="soc-prod",
    )
    with build_secret_store_provider(ok_ns_cfg) as provider:
        val = provider.get_secret_value("hashicorp_vault:soclens/rf:api_token")
    assert val == "e2e-vault-rf-api-token"
    assert any(
        r["headers"].get("X-Vault-Namespace") == "soc-prod"
        for r in mock_vault_server.requests_log
    )


@pytest.mark.feature("V21-F2")
def test_v21_f2_vault_approle_bad_credentials_raises_auth_error(
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    bad_approle = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_auth_mode="approle",
        vault_role_id="e2e-vault-role-001",
        vault_secret_id="wrong-secret-id-999",
    )
    with build_secret_store_provider(bad_approle) as provider:
        with pytest.raises(SecretStoreAuthError) as exc_info:
            provider.get_secret_value("hashicorp_vault:soclens/rf:api_token")
    assert exc_info.value.status_code == 400
    assert not [r for r in mock_vault_server.requests_log if "/data/" in r["path"]]

    missing_sid = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_auth_mode="approle",
        vault_role_id="e2e-vault-role-001",
        vault_secret_id=None,
    )
    req_before = len(mock_vault_server.requests_log)
    with build_secret_store_provider(missing_sid) as provider:
        with pytest.raises(SecretStoreAuthError) as missing_exc:
            provider.test_connection()
    assert missing_exc.value.reason == "missing_credentials"
    assert len(mock_vault_server.requests_log) == req_before


# ======================================================================
# V21-F3: 1Password Connect & Bitwarden Providers (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F3")
def test_v21_f3_op_connect_401_and_missing_token_raises_auth_error(
    mock_op_connect_server: MockOnePasswordConnectServer,
) -> None:
    bad_cfg = SecretStoreConfig(
        provider="onepassword_connect",
        op_connect_url=mock_op_connect_server.base_url,
        op_connect_token="wrong-op-token-999",
    )
    with build_secret_store_provider(bad_cfg) as provider:
        with pytest.raises(SecretStoreAuthError) as exc_info:
            provider.list_secrets()
    assert exc_info.value.status_code == 401

    empty_cfg = SecretStoreConfig(
        provider="onepassword_connect",
        op_connect_url=mock_op_connect_server.base_url,
        op_connect_token="",
    )
    req_before = len(mock_op_connect_server.requests_log)
    with build_secret_store_provider(empty_cfg) as provider:
        with pytest.raises(SecretStoreAuthError) as missing_exc:
            provider.list_secrets()
    assert missing_exc.value.reason == "missing_credentials"
    assert len(mock_op_connect_server.requests_log) == req_before


@pytest.mark.feature("V21-F3")
def test_v21_f3_op_connect_404_missing_item_or_field(
    mock_op_connect_server: MockOnePasswordConnectServer,
) -> None:
    vault_id = "11111111-1111-4111-8111-111111111111"
    item_id = "22222222-2222-4222-8222-222222222201"
    cfg = SecretStoreConfig(
        provider="onepassword_connect",
        op_connect_url=mock_op_connect_server.base_url,
        op_connect_token="e2e-op-connect-token-001",
        op_vault_id=vault_id,
    )
    with build_secret_store_provider(cfg) as provider:
        with pytest.raises(SecretStoreNotFoundError) as nf_item:
            provider.list_secret_fields(f"{vault_id}/99999999-9999-4999-8999-999999999999")
        assert nf_item.value.status_code == 404

        with pytest.raises(SecretStoreNotFoundError) as nf_field:
            provider.get_secret_value(
                f"onepassword_connect:{vault_id}/{item_id}:missing_field_key"
            )
        assert nf_field.value.status_code == 404


@pytest.mark.feature("V21-F3")
def test_v21_f3_op_connect_heartbeat_503_fails_test_connection(
    mock_op_connect_server: MockOnePasswordConnectServer,
) -> None:
    mock_op_connect_server.queue_fault("/heartbeat", 503, "Service Unavailable")
    cfg = SecretStoreConfig(
        provider="onepassword_connect",
        op_connect_url=mock_op_connect_server.base_url,
        op_connect_token="e2e-op-connect-token-001",
    )
    with build_secret_store_provider(cfg) as provider:
        with pytest.raises(SecretStoreError) as exc_info:
            provider.test_connection()
    assert exc_info.value.status_code == 503
    assert exc_info.value.reason == "heartbeat_failed"


@pytest.mark.feature("V21-F3")
def test_v21_f3_bitwarden_locked_blank_password_raises_vault_locked(
    mock_bitwarden_server: MockBitwardenServer,
) -> None:
    mock_bitwarden_server.set_lock_status("locked")
    cfg = SecretStoreConfig(
        provider="bitwarden",
        bw_serve_url=mock_bitwarden_server.base_url,
        bw_master_password="",
    )
    with build_secret_store_provider(cfg) as provider:
        with pytest.raises(SecretStoreAuthError) as exc_info:
            provider.test_connection()
    assert exc_info.value.reason == "vault_locked"
    assert not [r for r in mock_bitwarden_server.requests_log if r["path"] == "/unlock"]


@pytest.mark.feature("V21-F3")
def test_v21_f3_bitwarden_locked_wrong_master_password_raises_unlock_failed(
    mock_bitwarden_server: MockBitwardenServer,
) -> None:
    mock_bitwarden_server.set_lock_status("locked")
    canary_pw = "wrong-bw-master-pw-999"
    cfg = SecretStoreConfig(
        provider="bitwarden",
        bw_serve_url=mock_bitwarden_server.base_url,
        bw_master_password=canary_pw,
    )
    with build_secret_store_provider(cfg) as provider:
        with pytest.raises(SecretStoreAuthError) as exc_info:
            provider.list_secrets()
    assert exc_info.value.reason == "unlock_failed"
    assert canary_pw not in str(exc_info.value)
    assert any(r["path"] == "/unlock" for r in mock_bitwarden_server.requests_log)


@pytest.mark.feature("V21-F3")
def test_v21_f3_bitwarden_unauthenticated_and_404_missing_item_field(
    mock_bitwarden_server: MockBitwardenServer,
) -> None:
    mock_bitwarden_server.set_lock_status("unauthenticated")
    cfg = SecretStoreConfig(
        provider="bitwarden",
        bw_serve_url=mock_bitwarden_server.base_url,
        bw_master_password="e2e-bw-master-password",
    )
    with build_secret_store_provider(cfg) as provider:
        with pytest.raises(SecretStoreAuthError) as exc_info:
            provider.test_connection()
        assert exc_info.value.reason == "unauthenticated"

    mock_bitwarden_server.set_lock_status("unlocked")
    with build_secret_store_provider(cfg) as provider:
        with pytest.raises(SecretStoreNotFoundError) as nf_item:
            provider.list_secret_fields("99999999-9999-4999-8999-999999999999")
        assert nf_item.value.status_code == 404

        with pytest.raises(SecretStoreNotFoundError) as nf_field:
            provider.get_secret_value(
                "bitwarden:33333333-3333-4333-8333-333333333301:missing_field"
            )
        assert nf_field.value.status_code == 404


# ======================================================================
# V21-F4: Settings, Memory Hydration & Env Precedence (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F4")
def test_v21_f4_env_var_precedence_over_vault_hydration(
    mock_vault_server: MockHashiCorpVaultServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)
    monkeypatch.setenv("RF_API_TOKEN", "env-wins-rf-token-001")
    monkeypatch.setenv("S1_API_TOKEN", "env-wins-s1-token-001")
    vault_map = json.dumps(
        {
            "rf_api_token": "hashicorp_vault:soclens/rf:api_token",
            "s1_api_token": "hashicorp_vault:soclens/edr:s1_api_token",
            "splunk_token": "hashicorp_vault:soclens/splunk:token",
        }
    )
    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": mock_vault_server.base_url,
            "vault_auth_mode": "token",
            "vault_token": "e2e-vault-token-001",
            "vault_kv_mount": "secret",
            "vault_secret_map": vault_map,
        }
    )

    hydrated = hydrate_secrets_from_store(force=True, overwrite_existing=False)
    assert "rf_api_token" not in hydrated
    assert "s1_api_token" not in hydrated
    assert hydrated["splunk_token"] == mask_secret("e2e-vault-splunk-token")
    assert get_effective_setting("splunk_token") == "e2e-vault-splunk-token"
    assert get_effective_setting("rf_api_token") == "env-wins-rf-token-001"
    assert get_setting_with_source("rf_api_token") == (
        "env-wins-rf-token-001",
        "env:RF_API_TOKEN",
    )
    assert get_effective_setting("s1_api_token") == "env-wins-s1-token-001"

    hydrated_all = hydrate_secrets_from_store(force=True, overwrite_existing=True)
    assert hydrated_all["rf_api_token"] == mask_secret("e2e-vault-rf-api-token")
    assert get_setting_with_source("rf_api_token") == ("e2e-vault-rf-api-token", "session")
    clear_session_overrides()
    assert get_effective_setting("rf_api_token") == "env-wins-rf-token-001"


@pytest.mark.feature("V21-F4")
def test_v21_f4_zero_disk_token_persistence_on_save_and_hydration(
    v21_workspace: Path,
    mock_vault_server: MockHashiCorpVaultServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for env_key in (
        "RF_API_TOKEN",
        "RECORDED_FUTURE_API_KEY",
        "RF_SANDBOX_TOKEN",
        "RECORDED_FUTURE_SANDBOX_TOKEN",
        "SPLUNK_TOKEN",
    ):
        monkeypatch.delenv(env_key, raising=False)

    mock_vault_server.state["secrets"]["soclens/llm"]["gemini_api_key"] = (
        "e2e-vault-gemini-api-key"
    )
    mock_vault_server.state["secrets"]["soclens/copilot"] = {
        "bearer_token": "e2e-vault-copilot-bearer-token",
        "token_endpoint": "https://login.example.test/oauth2/token",
        "directline_secret": "e2e-vault-copilot-directline-secret",
    }

    vault_map = {
        "rf_api_token": "hashicorp_vault:soclens/rf:api_token",
        "rf_sandbox_token": "hashicorp_vault:soclens/rf:sandbox_token",
        "rf_asi_api_key": "hashicorp_vault:soclens/rf:asi_api_key",
        "rf_pfi_token": "hashicorp_vault:soclens/rf:pfi_token",
        "rf_riskrecon_token": "hashicorp_vault:soclens/rf:riskrecon_token",
        "splunk_token": "hashicorp_vault:soclens/splunk:token",
        "splunk_username": "hashicorp_vault:soclens/splunk:username",
        "splunk_password": "hashicorp_vault:soclens/splunk:password",
        "s1_api_token": "hashicorp_vault:soclens/edr:s1_api_token",
        "rf_llm_api_key": "hashicorp_vault:soclens/llm:api_key",
        "gemini_api_key": "hashicorp_vault:soclens/llm:gemini_api_key",
        "ms_copilot_bearer_token": "hashicorp_vault:soclens/copilot:bearer_token",
        "ms_copilot_token_endpoint": "hashicorp_vault:soclens/copilot:token_endpoint",
        "ms_copilot_directline_secret": "hashicorp_vault:soclens/copilot:directline_secret",
    }
    assert set(vault_map) == set(SECRET_MANAGED_SETTING_KEYS)

    settings_path = save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": mock_vault_server.base_url,
            "vault_auth_mode": "token",
            "vault_token": "e2e-vault-token-001",
            "vault_kv_mount": "secret",
            "vault_secret_map": json.dumps(vault_map),
        }
    )
    hydrated = hydrate_secrets_from_store(force=True)
    assert set(hydrated) == set(SECRET_MANAGED_SETTING_KEYS)
    plaintext_vals = [get_effective_setting(k) for k in SECRET_MANAGED_SETTING_KEYS]
    assert all(plaintext_vals)

    save_profile_settings(
        {
            "rf_base_url": "https://rf.example.test",
            "vault_secret_map": json.dumps(vault_map),
        }
    )
    raw_disk = settings_path.read_text(encoding="utf-8")
    assert json.loads(raw_disk)["encrypted"] is True
    for secret_val in plaintext_vals:
        assert secret_val and secret_val not in raw_disk
    assert "vault_secret_map" in get_profile_settings()


@pytest.mark.feature("V21-F4")
def test_v21_f4_invalid_vault_map_and_cross_provider_ref_rejected(
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    with pytest.raises(ValueError):
        parse_vault_secret_map("{invalid-json", strict=True)
    with pytest.raises(ValueError):
        parse_vault_secret_map({"rf_base_url": "hashicorp_vault:soclens/rf:api_token"}, strict=True)
    with pytest.raises(ValueError):
        parse_vault_secret_map({"rf_api_token": None}, strict=True)

    dropped = parse_vault_secret_map(
        {
            "rf_api_token": "hashicorp_vault:soclens/rf:api_token",
            "s1_api_token": None,
        },
        strict=False,
    )
    assert dropped == {"rf_api_token": "hashicorp_vault:soclens/rf:api_token"}

    errors_bad = validate_settings_values({"vault_secret_map": "{bad-json"})
    assert errors_bad and errors_bad[0][0] == "vault_secret_map"
    errors_unknown_key = validate_settings_values(
        {"vault_secret_map": json.dumps({"rf_base_url": "hashicorp_vault:soclens/rf:api_token"})}
    )
    assert errors_unknown_key and errors_unknown_key[0][0] == "vault_secret_map"

    for bad_ref in ("badref", "secret_server:1001:", "unknown_provider:item:field"):
        with pytest.raises(SecretStoreError) as ref_exc:
            parse_secret_ref(bad_ref)
        assert ref_exc.value.reason == "invalid_ref"

    cfg = SecretStoreConfig(
        provider="hashicorp_vault",
        vault_addr=mock_vault_server.base_url,
        vault_token="e2e-vault-token-001",
    )
    with build_secret_store_provider(cfg) as provider:
        with pytest.raises(SecretStoreError) as mismatch_exc:
            provider.resolve_mapped_settings({"rf_api_token": "bitwarden:item-1:password"})
    assert mismatch_exc.value.reason == "provider_mismatch"


@pytest.mark.feature("V21-F4")
def test_v21_f4_rf_llm_api_key_hydrates_into_local_llm_config(
    v21_workspace: Path,
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    assert "rf_llm_api_key" in SECRET_MANAGED_SETTING_KEYS
    settings_path = save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": mock_vault_server.base_url,
            "vault_auth_mode": "token",
            "vault_token": "e2e-vault-token-001",
            "vault_kv_mount": "secret",
            "vault_secret_map": json.dumps(
                {"rf_llm_api_key": "hashicorp_vault:soclens/llm:api_key"}
            ),
            "rf_llm_provider": "openai",
            "rf_llm_base_url": "http://127.0.0.1:11434/v1",
            "rf_llm_model": "qwen2.5-coder:7b",
        }
    )

    hydrated = hydrate_secrets_from_store(force=True)
    assert hydrated["rf_llm_api_key"] == mask_secret("e2e-vault-llm-api-key")
    llm_cfg = get_local_llm_config()
    assert llm_cfg.api_key == "e2e-vault-llm-api-key"
    assert "e2e-vault-llm-api-key" not in settings_path.read_text(encoding="utf-8")


@pytest.mark.feature("V21-F4")
def test_v21_f4_bw_master_password_blank_default_and_unreachable_vault_error(
    v21_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)
    assert SETTING_SPECS_BY_KEY["bw_master_password"].default in ("", None)
    assert get_secret_store_config().bw_master_password is None

    dead_url = _unused_local_url()
    settings_path = save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": dead_url,
            "vault_auth_mode": "token",
            "vault_token": "e2e-vault-token-001",
            "vault_secret_map": json.dumps(
                {"rf_api_token": "hashicorp_vault:soclens/rf:api_token"}
            ),
        }
    )
    before_disk = settings_path.read_text(encoding="utf-8")
    with pytest.raises(SecretStoreError) as exc_info:
        hydrate_secrets_from_store(force=True)
    assert exc_info.value.reason == "network_error"
    assert settings_path.read_text(encoding="utf-8") == before_disk
    assert get_effective_setting("rf_api_token") is None


@pytest.mark.feature("V21-F4")
def test_v21_f4_cli_no_secret_store_skips_startup_hydration(
    mock_vault_server: MockHashiCorpVaultServer,
    mock_s1_server: MockSentinelOneServer,
    monkeypatch: pytest.MonkeyPatch,
    run_cli: Any,
) -> None:
    monkeypatch.delenv("S1_API_TOKEN", raising=False)
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)
    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": mock_vault_server.base_url,
            "vault_auth_mode": "token",
            "vault_token": "e2e-vault-token-001",
            "vault_kv_mount": "secret",
            "vault_secret_map": json.dumps(
                {"s1_api_token": "hashicorp_vault:soclens/edr:api_token"}
            ),
            "s1_console_url": mock_s1_server.base_url,
        }
    )
    mock_vault_server.requests_log.clear()
    mock_s1_server.requests_log.clear()

    proc = run_cli(["--no-secret-store", "s1", "status", "--json"])
    assert proc.returncode == 1, proc.stderr
    assert "unrecognized arguments" not in proc.stderr
    err_payload = _read_json_output(proc)
    err_text = (
        str(err_payload.get("error") or "")
        if isinstance(err_payload, dict)
        else (proc.stderr + proc.stdout)
    ).lower()
    assert "s1" in err_text or "sentinelone" in err_text or "token" in err_text
    assert len(mock_vault_server.requests_log) == 0
    assert len(mock_s1_server.requests_log) == 0


# ======================================================================
# V21-F5: soclens secrets CLI & SettingsPane Dynamic UI (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F5")
def test_v21_f5_settings_pane_offline_saved_ref_avoids_invalid_select_value(
    v21_workspace: Path,
) -> None:
    from textual.widgets import OptionList, Select

    from soclens.tui.app import create_app
    from soclens.tui.screens.settings import SettingsPane

    dead_url = _unused_local_url()
    saved_ref = "hashicorp_vault:soclens/offline_only:api_token"
    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": dead_url,
            "vault_auth_mode": "token",
            "vault_token": "e2e-vault-token-001",
            "vault_secret_map": json.dumps({"rf_api_token": saved_ref}),
        }
    )

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-settings")
            await _wait_until(pilot, lambda: len(list(app.query(SettingsPane))) == 1)
            await app.workers.wait_for_complete()
            cat_list = app.query_one("#settings-category-list", OptionList)
            cat_list.highlighted = 0
            cat_list.action_select()
            await _wait_until(
                pilot,
                lambda: len(list(app.query("#set-rf-api-token-vault"))) == 1
                and app.query_one("#set-rf-api-token-vault", Select).display is True,
            )
            sel = app.query_one("#set-rf-api-token-vault", Select)
            assert sel.display is True
            assert str(sel.value) == saved_ref
            labels = [str(opt[0]) for opt in getattr(sel, "_options", [])]
            assert any("Saved" in lbl or saved_ref in lbl for lbl in labels)

    asyncio.run(_run())


@pytest.mark.feature("V21-F5")
def test_v21_f5_app_startup_unreachable_vault_non_blocking(
    v21_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.tui.app import create_app

    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)
    dead_url = _unused_local_url()
    settings_path = save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": dead_url,
            "vault_auth_mode": "token",
            "vault_token": "e2e-vault-token-001",
            "vault_secret_map": json.dumps(
                {"rf_api_token": "hashicorp_vault:soclens/rf:api_token"}
            ),
        }
    )
    before_disk = settings_path.read_text(encoding="utf-8")
    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            assert app.is_running
            await pilot.press("9")
            await pilot.pause()
            await pilot.press("f9")
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            assert app.is_running

    asyncio.run(_run())
    after_disk = settings_path.read_text(encoding="utf-8")
    assert "e2e-vault-rf-api-token" not in after_disk
    assert after_disk == before_disk
    assert get_effective_setting("rf_api_token") is None


@pytest.mark.feature("V21-F5")
def test_v21_f5_settings_pane_programmatic_updates_use_prevent_no_spurious_save(
    v21_workspace: Path,
    mock_vault_server: MockHashiCorpVaultServer,
) -> None:
    from textual.widgets import Button, OptionList, Select

    from soclens.tui.app import create_app
    from soclens.tui.screens.settings import SettingsPane

    settings_path = save_profile_settings(
        {
            "secret_provider": "none",
            "vault_addr": mock_vault_server.base_url,
            "vault_auth_mode": "token",
            "vault_token": "e2e-vault-token-001",
            "vault_kv_mount": "secret",
        }
    )
    before_disk = settings_path.read_text(encoding="utf-8")
    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-settings")
            await _wait_until(pilot, lambda: len(list(app.query(SettingsPane))) == 1)
            cat_list = app.query_one("#settings-category-list", OptionList)
            idx = next(
                i
                for i in range(cat_list.option_count)
                if getattr(cat_list.get_option_at_index(i), "id", None) == "cat-secrets"
            )
            cat_list.highlighted = idx
            cat_list.action_select()
            await _wait_until(
                pilot,
                lambda: len(list(app.query("#set-secret-provider"))) == 1,
            )

            prov_sel = app.query_one("#set-secret-provider", Select)
            prov_sel.value = "hashicorp_vault"
            await pilot.pause()

            refresh_btn = app.query_one("#settings-refresh-vault-btn", Button)
            refresh_btn.press()
            await _wait_until(
                pilot,
                lambda: "hashicorp_vault:soclens/rf:api_token"
                in [
                    str(opt[1])
                    for opt in getattr(
                        app.query_one("#set-rf-api-token-vault", Select), "_options", []
                    )
                ],
            )
            await app.workers.wait_for_complete()

            vault_sel = app.query_one("#set-rf-api-token-vault", Select)
            assert vault_sel.display is True

    asyncio.run(_run())
    raw_disk = settings_path.read_text(encoding="utf-8")
    assert raw_disk == before_disk
    assert "e2e-vault-rf-api-token" not in raw_disk
    assert stat.S_IMODE(settings_path.stat().st_mode) == 0o600


@pytest.mark.feature("V21-F5")
def test_v21_f5_cli_secrets_map_unmap_invalid_key_or_ref_exits_1(
    mock_vault_server: MockHashiCorpVaultServer,
    run_cli: Any,
) -> None:
    settings_path = save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": mock_vault_server.base_url,
            "vault_token": "e2e-vault-token-001",
        }
    )
    before_disk = settings_path.read_text(encoding="utf-8")

    bad_key = run_cli(
        ["secrets", "map", "rf_base_url", "hashicorp_vault:soclens/rf:api_token", "--json"]
    )
    assert bad_key.returncode != 0
    assert _read_json_output(bad_key) is not None

    bad_ref = run_cli(["secrets", "map", "rf_api_token", "invalid-ref-no-colons", "--json"])
    assert bad_ref.returncode != 0
    assert _read_json_output(bad_ref) is not None

    bad_unmap = run_cli(["secrets", "unmap", "nonexistent_setting_key", "--json"])
    assert bad_unmap.returncode != 0
    assert _read_json_output(bad_unmap) is not None

    assert settings_path.read_text(encoding="utf-8") == before_disk


@pytest.mark.feature("V21-F5")
def test_v21_f5_cli_secrets_fields_masking_vs_reveal_and_pull_dry_run(
    mock_secret_server: MockSecretServer,
    run_cli: Any,
) -> None:
    settings_path = save_profile_settings(
        {
            "secret_provider": "secret_server",
            "tss_base_url": mock_secret_server.base_url,
            "tss_auth_mode": "password",
            "tss_username": "e2e-tss-user",
            "tss_password": "e2e-tss-password",
            "vault_secret_map": json.dumps({"rf_api_token": "secret_server:1001:rf-api-token"}),
        }
    )

    masked_proc = run_cli(["secrets", "fields", "1001", "--json"])
    assert masked_proc.returncode == 0, masked_proc.stderr
    assert "e2e-tss-rf-api-token" not in masked_proc.stdout
    masked_data = json.loads(masked_proc.stdout)
    masked_fields = (
        masked_data
        if isinstance(masked_data, list)
        else (masked_data.get("fields") or masked_data.get("items") or [])
    )
    assert masked_fields
    assert any(
        "***" in json.dumps(entry) or str(entry.get("value") or "") != "e2e-tss-rf-api-token"
        for entry in masked_fields
        if isinstance(entry, dict)
    )

    reveal_proc = run_cli(["secrets", "fields", "1001", "--reveal", "--json"])
    assert reveal_proc.returncode == 0, reveal_proc.stderr
    assert "e2e-tss-rf-api-token" in reveal_proc.stdout
    reveal_data = json.loads(reveal_proc.stdout)
    assert "e2e-tss-rf-api-token" in json.dumps(reveal_data)

    pull_dry = run_cli(["secrets", "pull", "--dry-run", "--json"])
    assert pull_dry.returncode == 0, pull_dry.stderr
    assert "e2e-tss-rf-api-token" not in settings_path.read_text(encoding="utf-8")


@pytest.mark.feature("V21-F5")
def test_v21_f5_cli_secrets_test_and_list_disabled_or_auth_failure_exits_1(
    mock_vault_server: MockHashiCorpVaultServer,
    monkeypatch: pytest.MonkeyPatch,
    run_cli: Any,
) -> None:
    save_profile_settings({"secret_provider": "none"})
    disabled_proc = run_cli(["secrets", "test", "--json"])
    assert disabled_proc.returncode != 0
    assert _read_json_output(disabled_proc) is not None

    monkeypatch.setenv("VAULT_TOKEN", "wrong-vault-token-999")
    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": mock_vault_server.base_url,
            "vault_auth_mode": "token",
        }
    )
    bad_auth_proc = run_cli(["secrets", "list", "--json"])
    assert bad_auth_proc.returncode != 0
    assert _read_json_output(bad_auth_proc) is not None
