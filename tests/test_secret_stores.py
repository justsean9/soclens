"""Offline Wave 0 unit tests for soclens.secret_stores.{base,__init__} and soclens.tui.pivot."""

from __future__ import annotations

import sys
import threading
import types
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from soclens.config import ConfiguredSession
from soclens.config import SecretStoreConfig as ConfigSecretStoreConfig
from soclens.secret_stores import (
    SecretCatalogEntry,
    SecretStoreAuthError,
    SecretStoreConfig,
    SecretStoreError,
    SecretStoreNotFoundError,
    SecretStoreProvider,
    build_secret_store_provider,
    format_secret_ref,
    parse_secret_ref,
)
from soclens.secret_stores.base import SecretStoreConfig as BaseSecretStoreConfig
from soclens.tui.pivot import (
    PivotPayload,
    build_spl_from_pivot,
    emit_pivot,
    extract_tenant_from_site_name,
    format_copilot_context,
)


class _BatchingTestProvider(SecretStoreProvider):
    provider_name = "secret_server"

    def __init__(
        self,
        config: SecretStoreConfig,
        *,
        stop_event: threading.Event | None = None,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(config, stop_event=stop_event, session=session)
        self.fetch_calls: list[str] = []
        self.get_value_calls: list[str] = []

    def test_connection(self) -> dict[str, Any]:
        return {"ok": True, "provider": self.provider_name}

    def list_secrets(self, query: str = "", *, limit: int = 100) -> list[SecretCatalogEntry]:
        return []

    def list_secret_fields(self, ref_or_id: str) -> list[SecretCatalogEntry]:
        return []

    def _fetch_item_fields(self, item_id: str) -> dict[str, str] | None:
        self.fetch_calls.append(item_id)
        if item_id == "42":
            return {"username": "svc_splunk", "password": "pw-synthetic-42"}
        return None

    def get_secret_value(self, ref: str) -> str:
        self.get_value_calls.append(ref)
        return f"val:{ref}"


class _DirectOnlyTestProvider(SecretStoreProvider):
    provider_name = "hashicorp_vault"

    def __init__(
        self,
        config: SecretStoreConfig,
        *,
        stop_event: threading.Event | None = None,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(config, stop_event=stop_event, session=session)
        self.get_value_calls: list[str] = []

    def test_connection(self) -> dict[str, Any]:
        return {"ok": True}

    def list_secrets(self, query: str = "", *, limit: int = 100) -> list[SecretCatalogEntry]:
        return []

    def list_secret_fields(self, ref_or_id: str) -> list[SecretCatalogEntry]:
        return []

    def get_secret_value(self, ref: str) -> str:
        self.get_value_calls.append(ref)
        return f"vault:{ref}"


def test_secret_store_config_reexport_and_repr_masking() -> None:
    assert SecretStoreConfig is ConfigSecretStoreConfig
    assert BaseSecretStoreConfig is ConfigSecretStoreConfig
    assert issubclass(SecretStoreAuthError, SecretStoreError)
    assert issubclass(SecretStoreNotFoundError, SecretStoreError)

    cfg = SecretStoreConfig(
        provider="secret_server",
        tss_password="synthetic-tss-password",
        tss_client_secret="synthetic-client-secret",
        tss_access_token="synthetic-access-token",
        vault_token="synthetic-vault-token",
        vault_secret_id="synthetic-vault-secret-id",
        op_connect_token="synthetic-op-token",
        bw_master_password="synthetic-bw-password",
    )
    assert cfg.enabled is True
    assert cfg.is_enabled is True
    rendered = repr(cfg)
    for secret_str in (
        "synthetic-tss-password",
        "synthetic-client-secret",
        "synthetic-access-token",
        "synthetic-vault-token",
        "synthetic-vault-secret-id",
        "synthetic-op-token",
        "synthetic-bw-password",
    ):
        assert secret_str not in rendered

    disabled = SecretStoreConfig(provider="none")
    assert disabled.enabled is False
    assert disabled.is_enabled is False


def test_parse_and_format_secret_ref() -> None:
    assert parse_secret_ref("secret_server:1042:api-key") == ("secret_server", "1042", "api-key")
    assert parse_secret_ref("hashicorp_vault:soc/prod:region:api_token") == (
        "hashicorp_vault",
        "soc/prod:region",
        "api_token",
    )
    assert parse_secret_ref("onepassword_connect:vault1/item2:credential") == (
        "onepassword_connect",
        "vault1/item2",
        "credential",
    )
    assert parse_secret_ref("bitwarden:item-uuid:password") == (
        "bitwarden",
        "item-uuid",
        "password",
    )
    assert format_secret_ref("Secret_Server", "1042", "api-key") == "secret_server:1042:api-key"

    for bad_ref in ("", "no_colons", "none:1:field", "bogus:1:field", "secret_server:1", "secret_server::field", "secret_server:1:"):
        with pytest.raises(SecretStoreError):
            parse_secret_ref(bad_ref)

    with pytest.raises(ValueError):
        format_secret_ref("none", "1", "a")
    with pytest.raises(ValueError):
        format_secret_ref("bitwarden", "", "password")
    with pytest.raises(ValueError, match="field_key must not contain ':'"):
        format_secret_ref("hashicorp_vault", "secret/data/app", "a:b")

    # Roundtrip with colons inside item_id remains unambiguous
    ref_with_colons = format_secret_ref("hashicorp_vault", "ns:team/secret/data/app:prod", "api_key")
    assert ref_with_colons == "hashicorp_vault:ns:team/secret/data/app:prod:api_key"
    assert parse_secret_ref(ref_with_colons) == (
        "hashicorp_vault",
        "ns:team/secret/data/app:prod",
        "api_key",
    )


def test_build_secret_store_provider_factory(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SecretStoreError) as disabled_exc:
        build_secret_store_provider(SecretStoreConfig(provider="none"))
    assert disabled_exc.value.reason == "disabled"

    with pytest.raises(SecretStoreError) as unsupported_exc:
        build_secret_store_provider(SecretStoreConfig(provider="invalid_pam"))
    assert unsupported_exc.value.reason == "unsupported_provider"

    # When Wave 1 provider module is not yet present -> provider_unavailable
    with patch("soclens.secret_stores.importlib.import_module", side_effect=ModuleNotFoundError(name="soclens.secret_stores.secret_server")):
        with pytest.raises(SecretStoreError) as unavail_exc:
            build_secret_store_provider(SecretStoreConfig(provider="secret_server"))
        assert unavail_exc.value.reason == "provider_unavailable"

    # Dynamic registry resolves valid SecretStoreProvider subclasses
    fake_mod = types.ModuleType("soclens.secret_stores.secret_server")
    fake_mod.SecretServerProvider = _BatchingTestProvider  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "soclens.secret_stores.secret_server", fake_mod)

    provider = build_secret_store_provider(SecretStoreConfig(provider="secret_server"))
    assert isinstance(provider, _BatchingTestProvider)
    assert isinstance(provider.session, ConfiguredSession)
    provider.close()


def test_resolve_mapped_settings_deduplication_and_stop_event() -> None:
    cfg = SecretStoreConfig(provider="secret_server", verify_ssl=False)
    with _BatchingTestProvider(cfg) as prov:
        resolved = prov.resolve_mapped_settings(
            {
                "splunk_username": "secret_server:42:Username",
                "splunk_password": "secret_server:42:password",
                "rf_api_token": "secret_server:99:token",
                "rf_sandbox_token": "secret_server:99:token",
            }
        )
        assert resolved == {
            "splunk_username": "svc_splunk",
            "splunk_password": "pw-synthetic-42",
            "rf_api_token": "val:secret_server:99:token",
            "rf_sandbox_token": "val:secret_server:99:token",
        }
        # Item 42 was fetched exactly once across 2 different fields
        assert prov.fetch_calls == ["42", "99"]
        # Exact ref 99:token was fetched once across 2 mapped keys
        assert prov.get_value_calls == ["secret_server:99:token"]

        with pytest.raises(SecretStoreNotFoundError):
            prov.resolve_mapped_settings({"rf_api_token": "secret_server:42:missing_field"})

        with pytest.raises(SecretStoreError) as mismatch:
            prov.resolve_mapped_settings({"rf_api_token": "bitwarden:item-1:password"})
        assert mismatch.value.reason == "provider_mismatch"

    # Direct provider ref-cache deduplication
    hv_prov = _DirectOnlyTestProvider(SecretStoreConfig(provider="hashicorp_vault"))
    hv_res = hv_prov.resolve_mapped_settings(
        {
            "rf_api_token": "hashicorp_vault:soc/rf:key",
            "rf_pfi_token": "hashicorp_vault:soc/rf:key",
        }
    )
    assert hv_res["rf_api_token"] == "vault:hashicorp_vault:soc/rf:key"
    assert hv_prov.get_value_calls == ["hashicorp_vault:soc/rf:key"]
    hv_prov.close()

    # Cooperative cancellation via stop_event
    stop_ev = threading.Event()
    stop_ev.set()
    cancelled_prov = _BatchingTestProvider(cfg, stop_event=stop_ev)
    with pytest.raises(SecretStoreError) as cancel_exc:
        cancelled_prov.resolve_mapped_settings({"rf_api_token": "secret_server:42:password"})
    assert cancel_exc.value.reason == "cancelled"

    with pytest.raises(SecretStoreError) as sleep_cancel:
        cancelled_prov._sleep(1.0)
    assert sleep_cancel.value.reason == "cancelled"

    with pytest.raises(SecretStoreError) as req_cancel:
        cancelled_prov._session_request("GET", "https://vault.invalid/test")
    assert req_cancel.value.reason == "cancelled"
    cancelled_prov.close()


def test_pivot_payload_spl_builder_copilot_and_emit() -> None:
    # orig_sid is the ONLY case where auto_run=True
    sid_payload = PivotPayload(source_tab="tab-splunk-es", target_tab="tab-splunk-search", orig_sid="1700000000.123")
    spl, auto_run = build_spl_from_pivot(sid_payload)
    assert spl == '| loadjob "1700000000.123"'
    assert auto_run is True

    # Arbitrary spl_query or IOC search ALWAYS loads with auto_run=False
    custom_spl_payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-splunk-search",
        spl_query="index=main | stats count by host",
        auto_run=True,
    )
    spl2, auto_run2 = build_spl_from_pivot(custom_spl_payload)
    assert spl2 == "index=main | stats count by host"
    assert auto_run2 is False

    ioc_payload = PivotPayload(
        source_tab="tab-sentinelone",
        target_tab="tab-splunk-search",
        tenant_id="1234",
        hostname="wkstn-01.corp.local",
        sha1="a" * 40,
    )
    spl3, auto_run3 = build_spl_from_pivot(ioc_payload)
    assert 'tenant_id="1234"' in spl3
    assert 'host="wkstn-01.corp.local"' in spl3
    assert f'file_hash="{"a" * 40}"' in spl3
    assert auto_run3 is False

    assert ioc_payload.primary_ioc() == ("hash", "a" * 40)
    assert extract_tenant_from_site_name("MDR-1234") == "1234"

    copilot_payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-llm",
        tenant_id="1234",
        site_name="MDR-1234",
        tier="MDR",
        hostname="wkstn-01.corp.local",
        src_ip="192.0.2.10",
        summary="Suspicious script execution",
        es_finding={"rule_name": "Encoded PowerShell"},
        s1_threat={"mitigationStatus": "mitigated"},
        rf_enrichment={"risk_score": 85},
    )
    title, body = format_copilot_context(copilot_payload)
    assert "Tenant 1234" in title
    assert "Encoded PowerShell" in body
    assert "mitigated" in body
    assert "85" in body

    # emit_pivot routes to dispatch_pivot when present, or falls back cleanly
    mock_app = MagicMock()
    mock_app.dispatch_pivot.return_value = True
    assert emit_pivot(mock_app, copilot_payload) is True
    mock_app.dispatch_pivot.assert_called_once_with(copilot_payload)

    fallback_app = types.SimpleNamespace(
        open_splunk_search=MagicMock(),
        open_llm_with_context=MagicMock(),
    )
    assert emit_pivot(fallback_app, sid_payload) is True
    fallback_app.open_splunk_search.assert_called_once_with('| loadjob "1700000000.123"', auto_run=True)
    assert emit_pivot(fallback_app, copilot_payload) is True
    fallback_app.open_llm_with_context.assert_called_once()
