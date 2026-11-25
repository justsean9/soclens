"""Offline unit and integration tests for soclens.secret_stores and soclens.tui.pivot."""

from __future__ import annotations

import contextlib
import json
import logging
import sys
import threading
import types
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
import requests

from soclens.config import (
    ConfiguredSession,
    get_local_llm_config,
    get_sentinelone_config,
    get_splunk_config,
    hydrate_secrets_from_store,
)
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
from soclens.secret_stores.bitwarden import BitwardenProvider
from soclens.secret_stores.hashicorp_vault import HashiCorpVaultProvider
from soclens.secret_stores.onepassword_connect import OnePasswordConnectProvider
from soclens.secret_stores.secret_server import SecretServerProvider
from soclens.settings import (
    get_effective_setting,
    get_settings_path,
    save_profile_settings,
    serialize_vault_secret_map,
)
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


# ---------------------------------------------------------------------------
# Wave 1A Offline HTTP Server Harness & Concrete Provider Tests
# ---------------------------------------------------------------------------


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


HandlerFunc = Callable[
    [str, str, dict[str, list[str]], dict[str, str], bytes],
    tuple[int, dict[str, str] | None, bytes | str | dict[str, Any] | list[Any]],
]


@contextlib.contextmanager
def _local_http_server(
    handler_fn: HandlerFunc,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[str]:
    """Start an ephemeral 127.0.0.1 HTTP server with proxy env vars cleared."""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")

    class _DispatchHandler(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            parsed = urlparse(self.path)
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length) if length > 0 else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            query = parse_qs(parsed.query)
            status, resp_headers, resp_payload = handler_fn(
                self.command,
                parsed.path,
                query,
                headers,
                body,
            )
            self.send_response(status)
            out_bytes: bytes
            default_ctype = "application/json"
            if isinstance(resp_payload, bytes):
                out_bytes = resp_payload
            elif isinstance(resp_payload, str):
                out_bytes = resp_payload.encode("utf-8")
                default_ctype = "text/plain; charset=utf-8"
            else:
                out_bytes = json.dumps(resp_payload).encode("utf-8")

            sent_ctype = False
            if resp_headers:
                for hk, hv in resp_headers.items():
                    if hk.lower() == "content-type":
                        sent_ctype = True
                    self.send_header(hk, hv)
            if not sent_ctype:
                self.send_header("Content-Type", default_ctype)
            self.send_header("Content-Length", str(len(out_bytes)))
            self.end_headers()
            self.wfile.write(out_bytes)

        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_LIST(self) -> None:
            self._handle()

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = _QuietThreadingHTTPServer(("127.0.0.1", 0), _DispatchHandler)
    port = server.server_address[1]
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        daemon=True,
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_registry_builds_all_four_concrete_providers() -> None:
    expected: dict[str, type[SecretStoreProvider]] = {
        "secret_server": SecretServerProvider,
        "hashicorp_vault": HashiCorpVaultProvider,
        "onepassword_connect": OnePasswordConnectProvider,
        "bitwarden": BitwardenProvider,
    }
    for name, cls in expected.items():
        with build_secret_store_provider(SecretStoreConfig(provider=name)) as prov:
            assert isinstance(prov, cls)
            assert prov.provider_name == name


def test_provider_session_ownership_and_close() -> None:
    owned = SecretServerProvider(SecretStoreConfig(provider="secret_server"))
    mock_owned = MagicMock(wraps=owned.session)
    owned.session = mock_owned
    owned.close()
    mock_owned.close.assert_called_once()

    external_session = MagicMock(spec=requests.Session)
    external_provider = OnePasswordConnectProvider(
        SecretStoreConfig(provider="onepassword_connect"),
        session=external_session,
    )
    external_provider.close()
    external_session.close.assert_not_called()


# ---------------------------------------------------------------------------
# 1. SecretServerProvider tests
# ---------------------------------------------------------------------------


def test_secret_server_password_auth_refresh_fallback_and_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, str]] = []
    state = {"token_seq": 0, "revoked": []}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        calls.append((method, path, headers.get("authorization", "")))
        if method == "POST" and path == "/oauth2/token":
            form = parse_qs(body.decode("utf-8"))
            grant = form.get("grant_type", [""])[0]
            if grant == "password":
                assert form.get("username") == ["svc_soc"]
                assert form.get("password") == ["syn-tss-pw"]
                assert form.get("domain") == ["CORP"]
                state["token_seq"] += 1
                if state["token_seq"] == 1:
                    return 200, None, {
                        "access_token": "tok-1",
                        "refresh_token": "rt-1",
                        "expires_in": 30,
                    }
                return 200, None, {
                    "access_token": "tok-3",
                    "refresh_token": "rt-3",
                    "expires_in": 3600,
                }
            if grant == "refresh_token":
                rt = form.get("refresh_token", [""])[0]
                if rt == "rt-1":
                    return 200, None, {
                        "access_token": "tok-2",
                        "refresh_token": "rt-2",
                        "expires_in": 30,
                    }
                return 400, None, {"error": "invalid_grant"}
        if method == "GET" and path == "/api/v1/secrets":
            if headers.get("authorization") in {"Bearer tok-1", "Bearer tok-2", "Bearer tok-3"}:
                return 200, None, {"total": 1, "records": []}
            return 401, None, {"message": "expired"}
        if method == "POST" and path == "/api/v1/oauth-expiration":
            state["revoked"].append(headers.get("authorization", ""))
            return 200, None, {"revoked": True}
        return 404, None, {"message": "not found"}

    with _local_http_server(handler, monkeypatch) as base_url:
        cfg = SecretStoreConfig(
            provider="secret_server",
            tss_base_url=f"{base_url}/",
            tss_auth_mode="password",
            tss_username="svc_soc",
            tss_password="syn-tss-pw",
            tss_domain="CORP",
        )
        with SecretServerProvider(cfg) as prov:
            # 1st call: password grant -> tok-1 (expires_in=30 triggers refresh on next call)
            res1 = prov.test_connection()
            assert res1["ok"] is True
            assert res1["secret_count"] == 1
            # 2nd call: proactive refresh via single-use rt-1 -> tok-2
            res2 = prov.test_connection()
            assert res2["ok"] is True
            # 3rd call: rt-2 fails refresh -> falls back to password grant -> tok-3
            res3 = prov.test_connection()
            assert res3["ok"] is True

        # Exiting context manager triggers oauth-expiration
        assert state["revoked"] == ["Bearer tok-3"]


def test_secret_server_platform_auth_and_vault_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        if method == "POST" and path == "/identity/api/oauth2/token/xpmplatform":
            form = parse_qs(body.decode("utf-8"))
            assert form.get("grant_type") == ["client_credentials"]
            assert form.get("scope") == ["xpmheadless"]
            assert form.get("client_id") == ["cli-id"]
            assert form.get("client_secret") == ["cli-secret"]
            return 200, None, {"access_token": "plat-tok-1", "expires_in": 3600}
        if method == "GET" and path == "/vaultbroker/api/vaults":
            assert headers.get("authorization") == "Bearer plat-tok-1"
            return 200, None, {
                "vaults": [
                    {
                        "name": "Disabled Vault",
                        "type": "SecretServerCloud",
                        "isDefault": True,
                        "isActive": False,
                        "connection": {"url": "https://disabled.example.invalid"},
                    },
                    {
                        "name": "Primary SS Cloud",
                        "type": "SecretServerCloud",
                        "isDefault": True,
                        "isActive": True,
                        "connection": {"url": f"{server_url_holder[0]}/vault1/"},
                    },
                ]
            }
        if method == "GET" and path == "/vault1/api/v1/secrets":
            assert headers.get("authorization") == "Bearer plat-tok-1"
            return 200, None, {"total": 4, "records": []}
        return 404, None, {"message": "not found"}

    server_url_holder = [""]
    with _local_http_server(handler, monkeypatch) as base_url:
        server_url_holder[0] = base_url
        cfg = SecretStoreConfig(
            provider="secret_server",
            tss_auth_mode="platform",
            tss_platform_url=base_url,
            tss_client_id="cli-id",
            tss_client_secret="cli-secret",
        )
        with SecretServerProvider(cfg) as prov:
            info = prov.test_connection()
            assert info["ok"] is True
            assert info["base_url"] == f"{base_url}/vault1"
            assert info["secret_count"] == 4


def test_secret_server_token_mode_401_retry_v2_and_batching(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[tuple[str, str]] = []
    auth_attempts = {"login": 0}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        calls.append((method, path))
        if method == "POST" and path == "/oauth2/token":
            auth_attempts["login"] += 1
            tok = f"pw-tok-{auth_attempts['login']}"
            return 200, None, {"access_token": tok, "expires_in": 3600}
        if method == "POST" and path == "/api/v1/oauth-expiration":
            return 200, None, {}

        auth = headers.get("authorization", "")
        if auth == "Bearer bad-static-token":
            return 401, None, {"message": "invalid static token"}
        if auth == "Bearer pw-tok-1" and path == "/api/v2/secrets/101":
            # Force 401 once to test retry-once recovery
            return 401, None, {"message": "token revoked"}

        if method == "GET" and path == "/api/v2/secrets":
            assert query.get("filter.folderId") == ["7"]
            return 200, None, {
                "records": [
                    {"id": 101, "name": "Splunk Service", "folderPath": "/SOC"},
                    {"id": 102, "name": "Restricted Secret"},
                    {
                        "id": 103,
                        "name": "Inline Secret",
                        "items": [{"slug": "api-key", "fieldName": "API Key", "isPassword": True}],
                    },
                ]
            }
        if method == "GET" and path == "/api/v2/secrets/102":
            return 403, None, {"message": "access denied"}
        if method == "GET" and path == "/api/v2/secrets/101":
            return 200, None, {
                "id": 101,
                "name": "Splunk Service",
                "folderPath": "/SOC",
                "items": [
                    {
                        "slug": "username",
                        "fieldName": "Username",
                        "itemValue": "svc_splunk",
                        "isPassword": False,
                    },
                    {
                        "slug": "password",
                        "fieldName": "Password",
                        "itemValue": "syn-splunk-secret",
                        "isPassword": True,
                    },
                ],
            }
        if method == "GET" and path == "/api/v1/secrets/101/fields/password":
            # Simulate instance lacking /fields/{slug} -> falls back to /api/v2/secrets/101
            return 404, None, {"message": "field endpoint disabled"}
        if method == "GET" and path == "/api/v1/secrets/103/fields/api-key":
            return 200, None, "syn-inline-api-key"
        return 404, None, {"message": "not found"}

    with _local_http_server(handler, monkeypatch) as base_url:
        # Static token mode: 401 raises without retry, close() does NOT revoke static token
        token_cfg = SecretStoreConfig(
            provider="secret_server",
            tss_base_url=base_url,
            tss_auth_mode="token",
            tss_access_token="bad-static-token",
        )
        with caplog.at_level(logging.DEBUG):
            with SecretServerProvider(token_cfg) as tok_prov:
                with pytest.raises(SecretStoreAuthError) as exc_info:
                    tok_prov.test_connection()
                assert "bad-static-token" not in str(exc_info.value)
        assert ("POST", "/api/v1/oauth-expiration") not in calls
        assert "bad-static-token" not in caplog.text

        # v2 + 401 retry + restricted skip + field fallback + batching
        calls.clear()
        auth_attempts["login"] = 0
        v2_cfg = SecretStoreConfig(
            provider="secret_server",
            tss_base_url=base_url,
            tss_auth_mode="password",
            tss_username="svc",
            tss_password="syn-tss-password",
            tss_folder_id="7",
            tss_api_version="v2",
        )
        with SecretServerProvider(v2_cfg) as prov:
            catalog = prov.list_secrets()
            refs = [entry.ref for entry in catalog]
            assert refs == [
                "secret_server:101:username",
                "secret_server:101:password",
                "secret_server:103:api-key",
            ]
            assert auth_attempts["login"] == 2

            # Primary field endpoint (103) and fallback to secret detail (101)
            assert prov.get_secret_value("secret_server:103:api-key") == "syn-inline-api-key"
            assert prov.get_secret_value("secret_server:101:password") == "syn-splunk-secret"
            with pytest.raises(SecretStoreNotFoundError):
                prov.get_secret_value("secret_server:101:nonexistent")

            # Batching: 2 fields on secret 101 fetch /api/v2/secrets/101 exactly once
            calls.clear()
            resolved = prov.resolve_mapped_settings(
                {
                    "splunk_username": "secret_server:101:username",
                    "splunk_password": "secret_server:101:password",
                }
            )
            assert resolved == {
                "splunk_username": "svc_splunk",
                "splunk_password": "syn-splunk-secret",
            }
            detail_gets = [c for c in calls if c == ("GET", "/api/v2/secrets/101")]
            assert len(detail_gets) == 1


# ---------------------------------------------------------------------------
# 2. HashiCorpVaultProvider tests
# ---------------------------------------------------------------------------


def test_hashicorp_vault_token_namespace_and_test_connection_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mode = {"lookup": "ok"}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        assert headers.get("x-vault-namespace") == "soc-ns"
        if path == "/v1/auth/token/lookup-self":
            if mode["lookup"] == "ok":
                assert headers.get("x-vault-token") == "hv-tok-1"
                return 200, None, {"data": {"display_name": "soc-bot", "policies": ["default"], "ttl": 300}}
            if mode["lookup"] == "forbidden":
                return 403, None, {"errors": ["permission denied"]}
            if mode["lookup"] == "missing":
                return 404, None, {"errors": ["unsupported path"]}
        if path == "/v1/sys/health":
            if mode["lookup"] == "missing":
                return 200, None, {"initialized": True, "sealed": False}
            return 503, None, {"initialized": True, "sealed": True}
        return 404, None, {"errors": ["not found"]}

    with _local_http_server(handler, monkeypatch) as base_url:
        cfg = SecretStoreConfig(
            provider="hashicorp_vault",
            vault_addr=base_url,
            vault_auth_mode="token",
            vault_token="hv-tok-1",
            vault_namespace="soc-ns",
        )
        with HashiCorpVaultProvider(cfg) as prov:
            res = prov.test_connection()
            assert res["ok"] is True
            assert res["display_name"] == "soc-bot"
            assert res["namespace"] == "soc-ns"

            # 403 must raise SecretStoreAuthError and NEVER fall back to sys/health
            mode["lookup"] = "forbidden"
            with pytest.raises(SecretStoreAuthError):
                prov.test_connection()

            # 404 falls back to sys/health
            mode["lookup"] = "missing"
            health_res = prov.test_connection()
            assert health_res["ok"] is True
            assert health_res["health_status"] == 200

            # Sealed Vault raises SecretStoreError
            mode["lookup"] = "sealed"
            with pytest.raises(SecretStoreError):
                prov.test_connection()


def test_hashicorp_vault_approle_401_retry_recursive_list_subkeys_and_batching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []
    login_count = {"n": 0}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        calls.append((method, path))
        if method == "POST" and path == "/v1/auth/custom-approle/login":
            payload = json.loads(body.decode("utf-8"))
            assert payload == {"role_id": "role-1", "secret_id": "sec-1"}
            login_count["n"] += 1
            return 200, None, {
                "auth": {
                    "client_token": f"app-tok-{login_count['n']}",
                    "lease_duration": 3600,
                }
            }

        tok = headers.get("x-vault-token", "")
        if tok == "app-tok-1" and path == "/v1/kv/data/soclens/rf":
            # Force 401 once to verify single AppRole re-login retry
            return 401, None, {"errors": ["invalid token"]}

        # Recursive LIST (return 405 on LIST for root prefix to exercise ?list=true fallback)
        if path == "/v1/kv/metadata/soclens":
            if method == "LIST":
                return 405, None, {"errors": ["method not allowed"]}
            assert query.get("list") == ["true"]
            return 200, None, {"data": {"keys": ["rf", "d1/", "deleted"]}}
        if path == "/v1/kv/metadata/soclens/d1":
            return 200, None, {"data": {"keys": ["d2/"]}}
        if path == "/v1/kv/metadata/soclens/d1/d2":
            return 200, None, {"data": {"keys": ["d3/"]}}
        if path == "/v1/kv/metadata/soclens/d1/d2/d3":
            return 200, None, {"data": {"keys": ["d4/"]}}
        if path == "/v1/kv/metadata/soclens/d1/d2/d3/d4":
            return 200, None, {"data": {"keys": ["deep_secret", "too_deep/"]}}
        if path == "/v1/kv/metadata/soclens/d1/d2/d3/d4/too_deep":
            return 200, None, {"data": {"keys": ["unreachable"]}}

        # subkeys vs 403 fallback to data
        if path == "/v1/kv/subkeys/soclens/rf":
            return 200, None, {"data": {"subkeys": {"api_token": {}, "sandbox_token": {}}}}
        if path == "/v1/kv/subkeys/soclens/d1/d2/d3/d4/deep_secret":
            return 403, None, {"errors": ["subkeys denied"]}
        if path == "/v1/kv/subkeys/soclens/deleted":
            return 404, None, {"errors": ["deleted"]}

        if path == "/v1/kv/data/soclens/rf":
            return 200, None, {"data": {"data": {"api_token": "syn-rf-1", "sandbox_token": "syn-sb-1"}}}
        if path == "/v1/kv/data/soclens/d1/d2/d3/d4/deep_secret":
            return 200, None, {"data": {"data": {"token": "syn-deep"}}}
        if path == "/v1/kv/data/soclens/deleted":
            return 200, None, {"data": {"data": None}}

        return 404, None, {"errors": ["not found"]}

    with _local_http_server(handler, monkeypatch) as base_url:
        cfg = SecretStoreConfig(
            provider="hashicorp_vault",
            vault_addr=base_url,
            vault_auth_mode="approle",
            vault_auth_mount="custom-approle",
            vault_kv_mount="/kv/",
            vault_prefix="/soclens/",
            vault_role_id="role-1",
            vault_secret_id="sec-1",
        )
        with HashiCorpVaultProvider(cfg) as prov:
            entries = prov.list_secrets()
            refs = [e.ref for e in entries]
            assert "hashicorp_vault:soclens/rf:api_token" in refs
            assert "hashicorp_vault:soclens/rf:sandbox_token" in refs
            assert "hashicorp_vault:soclens/d1/d2/d3/d4/deep_secret:token" in refs
            # Depth 5 (too_deep) must NOT be traversed
            assert not any("too_deep" in r for r in refs)
            # Soft-deleted secret must be skipped cleanly
            assert not any("deleted" in r for r in refs)

            # Single-fetch batching + 401 AppRole retry
            calls.clear()
            resolved = prov.resolve_mapped_settings(
                {
                    "rf_api_token": "hashicorp_vault:soclens/rf:api_token",
                    "rf_sandbox_token": "hashicorp_vault:soclens/rf:sandbox_token",
                }
            )
            assert resolved == {
                "rf_api_token": "syn-rf-1",
                "rf_sandbox_token": "syn-sb-1",
            }
            assert login_count["n"] == 2
            data_gets = [c for c in calls if c == ("GET", "/v1/kv/data/soclens/rf")]
            # 1 initial 401 attempt + 1 retry after AppRole re-login = 2 (NOT 4)
            assert len(data_gets) == 2

            # Soft-deleted item read raises SecretStoreNotFoundError
            with pytest.raises(SecretStoreNotFoundError):
                prov.get_secret_value("hashicorp_vault:soclens/deleted:key")

            # Cancellation check
            stop_ev = threading.Event()
            stop_ev.set()
            with HashiCorpVaultProvider(cfg, stop_event=stop_ev) as cancelled:
                with pytest.raises(SecretStoreError) as cancel_exc:
                    cancelled.list_secrets()
                assert cancel_exc.value.reason == "cancelled"


# ---------------------------------------------------------------------------
# 3. OnePasswordConnectProvider tests
# ---------------------------------------------------------------------------


def test_onepassword_connect_heartbeat_vaults_and_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mode = {"hb": "ok", "auth": "ok"}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        if path == "/heartbeat":
            if mode["hb"] == "fail":
                return 503, None, "UNHEALTHY"
            # Plain text response (NOT JSON)
            return 200, {"Content-Type": "text/plain"}, "OK"
        if headers.get("authorization") != "Bearer op-tok-valid":
            return 401, None, {"message": "invalid token"}
        if path == "/v1/vaults":
            return 200, None, [{"id": "v-soc", "name": "SOC Vault"}]
        if path == "/v1/vaults/v-missing":
            return 404, None, {"message": "vault not found"}
        return 404, None, {"message": "not found"}

    with _local_http_server(handler, monkeypatch) as base_url:
        with OnePasswordConnectProvider(
            SecretStoreConfig(provider="onepassword_connect", op_connect_url="")
        ) as no_url:
            with pytest.raises(SecretStoreError) as url_err:
                no_url.test_connection()
            assert url_err.value.reason == "missing_config"

        with OnePasswordConnectProvider(
            SecretStoreConfig(provider="onepassword_connect", op_connect_url=base_url)
        ) as no_tok:
            with pytest.raises(SecretStoreAuthError) as tok_err:
                no_tok.test_connection()
            assert tok_err.value.reason == "missing_credentials"

        with OnePasswordConnectProvider(
            SecretStoreConfig(
                provider="onepassword_connect",
                op_connect_url=base_url,
                op_connect_token="op-tok-valid",
            )
        ) as prov:
            info = prov.test_connection()
            assert info["ok"] is True
            assert info["heartbeat"] == "OK"
            assert info["vault_ids"] == ["v-soc"]

            mode["hb"] = "fail"
            with pytest.raises(SecretStoreError):
                prov.test_connection()
            mode["hb"] = "ok"

        with OnePasswordConnectProvider(
            SecretStoreConfig(
                provider="onepassword_connect",
                op_connect_url=base_url,
                op_connect_token="op-tok-bad",
            )
        ) as bad_auth:
            with pytest.raises(SecretStoreAuthError) as auth_err:
                bad_auth.test_connection()
            assert "op-tok-bad" not in str(auth_err.value)

        with OnePasswordConnectProvider(
            SecretStoreConfig(
                provider="onepassword_connect",
                op_connect_url=base_url,
                op_connect_token="op-tok-valid",
                op_vault_id="v-missing",
            )
        ) as bad_vault:
            with pytest.raises(SecretStoreNotFoundError):
                bad_vault.test_connection()


def test_onepassword_connect_list_priority_and_batching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        calls.append((method, path))
        if path == "/v1/vaults":
            return 200, None, [{"id": "v1", "name": "SOC Vault"}]
        if path == "/v1/vaults/v1/items":
            return 200, None, [
                {"id": "item-1", "title": "SOC Credentials", "tags": ["prod", "splunk"]},
                {"id": "item-2", "title": "Minimal Item", "category": "API_CREDENTIAL"},
            ]
        if path == "/v1/vaults/v1/items/item-1":
            return 200, None, {
                "id": "item-1",
                "title": "SOC Credentials",
                "vault": {"id": "v1", "name": "SOC Vault"},
                "fields": [
                    # Mixed-case collision: label="Password" must beat Field B's id="password"
                    {"id": "f_pw", "label": "Password", "purpose": "PASSWORD", "type": "CONCEALED", "value": "label-wins"},
                    {"id": "password", "label": "Secondary", "type": "STRING", "value": "id-loses"},
                    {"id": "api_key", "label": "API:Key", "type": "CONCEALED", "value": "syn-op-apikey"},
                    {"id": "usr", "purpose": "USERNAME", "type": "STRING", "value": "svc_op"},
                    {"purpose": "NOTES", "type": "STRING", "value": "op-notes"},
                ],
            }
        if path == "/v1/vaults/v1/items/item-2":
            # Minimal mock without detail endpoint -> list_secrets gracefully infers API_CREDENTIAL
            return 404, None, {"message": "detail not stubbed"}
        return 404, None, {"message": "not found"}

    with _local_http_server(handler, monkeypatch) as base_url:
        cfg = SecretStoreConfig(
            provider="onepassword_connect",
            op_connect_url=base_url,
            op_connect_token="op-tok-1",
        )
        with OnePasswordConnectProvider(cfg) as prov:
            entries = prov.list_secrets()
            refs = [e.ref for e in entries]
            assert "onepassword_connect:v1/item-1:Password" in refs
            # Label "API:Key" contains ':', so catalog falls back to safe id "api_key"
            assert "onepassword_connect:v1/item-1:api_key" in refs
            # id ("usr") takes precedence over purpose ("USERNAME") when label is absent
            assert "onepassword_connect:v1/item-1:usr" in refs
            # When both label and id are absent, purpose ("NOTES") is used
            assert "onepassword_connect:v1/item-1:NOTES" in refs
            assert "onepassword_connect:v1/item-2:credential" in refs

            # Substring query filter
            filtered = prov.list_secrets(query="splunk")
            assert all(e.item_id == "v1/item-1" for e in filtered)

            # list_secret_fields requires vault/item unless op_vault_id is set
            with pytest.raises(SecretStoreError) as bad_id:
                prov.list_secret_fields("item-1")
            assert bad_id.value.reason == "invalid_ref"
            assert len(prov.list_secret_fields("v1/item-1")) == 5

            # Batching + label -> id -> purpose case-insensitive priority
            calls.clear()
            resolved = prov.resolve_mapped_settings(
                {
                    "splunk_password": "onepassword_connect:v1/item-1:password",
                    "rf_api_token": "onepassword_connect:v1/item-1:api_key",
                    "splunk_username": "onepassword_connect:v1/item-1:username",
                    "rf_sandbox_token": "onepassword_connect:v1/item-1:notes",
                }
            )
            assert resolved == {
                "splunk_password": "label-wins",
                "rf_api_token": "syn-op-apikey",
                "splunk_username": "svc_op",
                "rf_sandbox_token": "op-notes",
            }
            item_gets = [c for c in calls if c == ("GET", "/v1/vaults/v1/items/item-1")]
            assert len(item_gets) == 1

            with pytest.raises(SecretStoreNotFoundError):
                prov.get_secret_value("onepassword_connect:v1/item-1:missing")

            # Cooperative cancellation via stop_event
            stop_ev = threading.Event()
            stop_ev.set()
            with OnePasswordConnectProvider(cfg, stop_event=stop_ev) as cancelled:
                with pytest.raises(SecretStoreError) as cancel_exc:
                    cancelled.list_secrets()
                assert cancel_exc.value.reason == "cancelled"

        # Scoped op_vault_id allows bare item UUID in list_secret_fields
        scoped_cfg = SecretStoreConfig(
            provider="onepassword_connect",
            op_connect_url=base_url,
            op_connect_token="op-tok-1",
            op_vault_id="v1",
        )
        with OnePasswordConnectProvider(scoped_cfg) as scoped:
            assert len(scoped.list_secret_fields("item-1")) == 5


# ---------------------------------------------------------------------------
# 4. BitwardenProvider tests
# ---------------------------------------------------------------------------


def test_bitwarden_status_unlock_sync_list_and_batching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, dict[str, list[str]]]] = []
    state = {"status": "locked", "format": "template"}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        calls.append((method, path, query))
        if method == "GET" and path == "/status":
            if state["format"] == "flat":
                return 200, None, {"success": True, "data": {"status": state["status"]}}
            return 200, None, {
                "success": True,
                "data": {
                    "object": "template",
                    "template": {"status": state["status"], "userEmail": "soc@example.invalid"},
                },
            }
        if method == "POST" and path == "/unlock":
            payload = json.loads(body.decode("utf-8"))
            if payload.get("password") == "master-secret-pw":
                state["status"] = "unlocked"
                return 200, None, {"success": True, "data": {"title": "Unlocked"}}
            return 400, None, {"success": False, "message": "Invalid master password."}
        if method == "POST" and path == "/sync":
            return 200, None, {"success": True, "data": {"title": "Synced"}}
        if method == "GET" and path == "/list/object/items":
            return 200, None, {
                "success": True,
                "data": {
                    "object": "list",
                    "data": [
                        {
                            "id": "bw-item-1",
                            "name": "Splunk Prod",
                            "folderId": "fld-1",
                            "notes": "prod-notes",
                            "login": {"username": "svc_bw", "password": "syn-bw-password"},
                            "fields": [{"name": "API Token", "value": "syn-bw-custom", "type": 1}],
                        }
                    ],
                },
            }
        if method == "GET" and path == "/object/item/bw-item-1":
            return 200, None, {
                "success": True,
                "data": {
                    "id": "bw-item-1",
                    "name": "Splunk Prod",
                    "notes": "prod-notes",
                    "login": {"username": "svc_bw", "password": "syn-bw-password"},
                    "fields": [{"name": "API Token", "value": "syn-bw-custom", "type": 1}],
                },
            }
        if method == "GET" and path == "/object/item/missing":
            return 404, None, {"success": False, "message": "Not found."}
        return 404, None, {"success": False, "message": "Not found."}

    with _local_http_server(handler, monkeypatch) as base_url:
        # Locked without master password -> SecretStoreAuthError(reason="vault_locked")
        locked_cfg = SecretStoreConfig(provider="bitwarden", bw_serve_url=base_url)
        with BitwardenProvider(locked_cfg) as prov:
            with pytest.raises(SecretStoreAuthError) as locked_err:
                prov.test_connection()
            assert locked_err.value.reason == "vault_locked"

        # Unauthenticated -> SecretStoreAuthError(reason="unauthenticated")
        state["status"] = "unauthenticated"
        with BitwardenProvider(locked_cfg) as prov:
            with pytest.raises(SecretStoreAuthError) as unauth_err:
                prov.test_connection()
            assert unauth_err.value.reason == "unauthenticated"

        # Locked with wrong master password -> unlock_failed without leaking password
        state["status"] = "locked"
        wrong_pw_cfg = SecretStoreConfig(
            provider="bitwarden",
            bw_serve_url=base_url,
            bw_master_password="wrong-secret-password",
        )
        with BitwardenProvider(wrong_pw_cfg) as prov:
            with pytest.raises(SecretStoreAuthError) as unlock_err:
                prov.test_connection()
            assert unlock_err.value.reason == "unlock_failed"
            assert "wrong-secret-password" not in str(unlock_err.value)

        # Locked with valid master password -> auto-unlocks, supports sync/list/aliases/batching
        good_cfg = SecretStoreConfig(
            provider="bitwarden",
            bw_serve_url=base_url,
            bw_master_password="master-secret-pw",
            bw_folder_id="fld-1",
            bw_collection_id="col-1",
            bw_organization_id="org-1",
        )
        with BitwardenProvider(good_cfg) as prov:
            conn = prov.test_connection()
            assert conn["ok"] is True
            assert conn["unlocked_now"] is True

            # Flat data.status format also works
            state["format"] = "flat"
            conn2 = prov.test_connection()
            assert conn2["ok"] is True
            assert conn2["unlocked_now"] is False

            sync_res = prov.sync()
            assert sync_res["ok"] is True

            entries = prov.list_secrets(query="splunk")
            assert [e.ref for e in entries] == [
                "bitwarden:bw-item-1:username",
                "bitwarden:bw-item-1:password",
                "bitwarden:bw-item-1:notes",
                "bitwarden:bw-item-1:API Token",
            ]
            list_calls = [c for c in calls if c[1] == "/list/object/items"]
            assert list_calls[-1][2]["folderid"] == ["fld-1"]
            assert list_calls[-1][2]["collectionid"] == ["col-1"]
            assert list_calls[-1][2]["organizationid"] == ["org-1"]
            assert list_calls[-1][2]["search"] == ["splunk"]

            # Both direct and login.* alias work in get_secret_value and resolve_mapped_settings
            assert prov.get_secret_value("bitwarden:bw-item-1:login.password") == "syn-bw-password"
            assert prov.get_secret_value("bitwarden:bw-item-1:api token") == "syn-bw-custom"

            calls.clear()
            resolved = prov.resolve_mapped_settings(
                {
                    "splunk_username": "bitwarden:bw-item-1:login.username",
                    "splunk_password": "bitwarden:bw-item-1:password",
                    "rf_api_token": "bitwarden:bw-item-1:API Token",
                }
            )
            assert resolved == {
                "splunk_username": "svc_bw",
                "splunk_password": "syn-bw-password",
                "rf_api_token": "syn-bw-custom",
            }
            item_gets = [c for c in calls if c[1] == "/object/item/bw-item-1"]
            assert len(item_gets) == 1

            with pytest.raises(SecretStoreNotFoundError):
                prov.get_secret_value("bitwarden:missing:password")
            with pytest.raises(SecretStoreNotFoundError):
                prov.get_secret_value("bitwarden:bw-item-1:absent")


# ---------------------------------------------------------------------------
# 5. End-to-End hydrate_secrets_from_store() Integration Across All 4 Providers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "provider_name",
    ["secret_server", "hashicorp_vault", "onepassword_connect", "bitwarden"],
)
def test_hydrate_secrets_from_store_end_to_end_all_providers(
    provider_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify end-to-end hydration in memory with zero plaintext secrets persisted to settings.json."""
    secrets = {
        "rf_api_token": f"syn-{provider_name}-rf",
        "splunk_username": f"svc_{provider_name}",
        "splunk_password": f"syn-{provider_name}-splunk-pw",
        "s1_api_token": f"syn-{provider_name}-s1",
        "rf_llm_api_key": f"syn-{provider_name}-llm",
    }

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        # Secret Server
        if method == "POST" and path == "/oauth2/token":
            return 200, None, {"access_token": "tss-tok", "expires_in": 3600}
        if method == "POST" and path == "/api/v1/oauth-expiration":
            return 200, None, {}
        if method == "GET" and path == "/api/v1/secrets/10":
            return 200, None, {
                "id": 10,
                "name": "SOC Bundle",
                "items": [
                    {"slug": "rf_key", "fieldName": "rf_key", "itemValue": secrets["rf_api_token"]},
                    {"slug": "splunk_user", "fieldName": "splunk_user", "itemValue": secrets["splunk_username"]},
                    {"slug": "splunk_pw", "fieldName": "splunk_pw", "itemValue": secrets["splunk_password"]},
                    {"slug": "s1_tok", "fieldName": "s1_tok", "itemValue": secrets["s1_api_token"]},
                    {"slug": "llm_key", "fieldName": "llm_key", "itemValue": secrets["rf_llm_api_key"]},
                ],
            }
        if method == "GET" and path.startswith("/api/v1/secrets/10/fields/"):
            return 404, None, {"message": "use secret detail"}

        # HashiCorp Vault
        if method == "GET" and path == "/v1/secret/data/soclens/bundle":
            return 200, None, {
                "data": {
                    "data": {
                        "rf_key": secrets["rf_api_token"],
                        "splunk_user": secrets["splunk_username"],
                        "splunk_pw": secrets["splunk_password"],
                        "s1_tok": secrets["s1_api_token"],
                        "llm_key": secrets["rf_llm_api_key"],
                    }
                }
            }

        # 1Password Connect
        if method == "GET" and path == "/v1/vaults/v-soc/items/item-soc":
            return 200, None, {
                "id": "item-soc",
                "title": "SOC Bundle",
                "fields": [
                    {"id": "rf_key", "label": "rf_key", "value": secrets["rf_api_token"]},
                    {"id": "splunk_user", "label": "splunk_user", "value": secrets["splunk_username"]},
                    {"id": "splunk_pw", "label": "splunk_pw", "value": secrets["splunk_password"]},
                    {"id": "s1_tok", "label": "s1_tok", "value": secrets["s1_api_token"]},
                    {"id": "llm_key", "label": "llm_key", "value": secrets["rf_llm_api_key"]},
                ],
            }

        # Bitwarden bw serve
        if method == "GET" and path == "/status":
            return 200, None, {"success": True, "data": {"template": {"status": "unlocked"}}}
        if method == "GET" and path == "/object/item/bw-bundle":
            return 200, None, {
                "success": True,
                "data": {
                    "id": "bw-bundle",
                    "name": "SOC Bundle",
                    "login": {
                        "username": secrets["splunk_username"],
                        "password": secrets["splunk_password"],
                    },
                    "fields": [
                        {"name": "rf_key", "value": secrets["rf_api_token"], "type": 1},
                        {"name": "s1_tok", "value": secrets["s1_api_token"], "type": 1},
                        {"name": "llm_key", "value": secrets["rf_llm_api_key"], "type": 1},
                    ],
                },
            }

        return 404, None, {"message": "not found"}

    with _local_http_server(handler, monkeypatch) as base_url:
        ref_map_by_provider: dict[str, dict[str, str]] = {
            "secret_server": {
                "rf_api_token": "secret_server:10:rf_key",
                "splunk_username": "secret_server:10:splunk_user",
                "splunk_password": "secret_server:10:splunk_pw",
                "s1_api_token": "secret_server:10:s1_tok",
                "rf_llm_api_key": "secret_server:10:llm_key",
            },
            "hashicorp_vault": {
                "rf_api_token": "hashicorp_vault:soclens/bundle:rf_key",
                "splunk_username": "hashicorp_vault:soclens/bundle:splunk_user",
                "splunk_password": "hashicorp_vault:soclens/bundle:splunk_pw",
                "s1_api_token": "hashicorp_vault:soclens/bundle:s1_tok",
                "rf_llm_api_key": "hashicorp_vault:soclens/bundle:llm_key",
            },
            "onepassword_connect": {
                "rf_api_token": "onepassword_connect:v-soc/item-soc:rf_key",
                "splunk_username": "onepassword_connect:v-soc/item-soc:splunk_user",
                "splunk_password": "onepassword_connect:v-soc/item-soc:splunk_pw",
                "s1_api_token": "onepassword_connect:v-soc/item-soc:s1_tok",
                "rf_llm_api_key": "onepassword_connect:v-soc/item-soc:llm_key",
            },
            "bitwarden": {
                "rf_api_token": "bitwarden:bw-bundle:rf_key",
                "splunk_username": "bitwarden:bw-bundle:login.username",
                "splunk_password": "bitwarden:bw-bundle:password",
                "s1_api_token": "bitwarden:bw-bundle:s1_tok",
                "rf_llm_api_key": "bitwarden:bw-bundle:llm_key",
            },
        }
        profile_settings: dict[str, str] = {
            "secret_provider": provider_name,
            "vault_secret_map": serialize_vault_secret_map(ref_map_by_provider[provider_name]),
            "s1_console_url": "https://s1.example.invalid",
            "splunk_host": "https://splunk.example.invalid:8089",
            "tss_base_url": base_url,
            "tss_auth_mode": "password",
            "tss_username": "bootstrap-user",
            "tss_password": "bootstrap-tss-password",
            "vault_addr": base_url,
            "vault_auth_mode": "token",
            "vault_token": "bootstrap-vault-token",
            "op_connect_url": base_url,
            "op_connect_token": "bootstrap-op-token",
            "bw_serve_url": base_url,
        }
        save_profile_settings(profile_settings)

        # Env var retains precedence when overwrite_existing=False
        monkeypatch.setenv("RF_API_TOKEN", "env-rf-override")
        hydrated = hydrate_secrets_from_store()
        assert "rf_api_token" not in hydrated
        assert get_effective_setting("rf_api_token") == "env-rf-override"
        assert get_effective_setting("rf_llm_api_key") == secrets["rf_llm_api_key"]
        assert get_local_llm_config().api_key == secrets["rf_llm_api_key"]
        assert get_splunk_config().username == secrets["splunk_username"]
        assert get_splunk_config().password == secrets["splunk_password"]
        assert get_sentinelone_config().api_token == secrets["s1_api_token"]

        # Returned values are masked
        for key, masked in hydrated.items():
            assert masked != secrets[key]

        # Re-saving hydrated values in profile settings must NOT persist pulled secrets to disk
        save_profile_settings(
            {
                "splunk_app": "custom_es_app",
                "splunk_password": secrets["splunk_password"],
                "rf_llm_api_key": secrets["rf_llm_api_key"],
            }
        )
        disk_text = get_settings_path().read_text(encoding="utf-8")
        for pulled_secret in secrets.values():
            assert pulled_secret not in disk_text
        assert "vault_secret_map" in disk_text

        # force=True + overwrite_existing=True overrides env var in memory
        forced = hydrate_secrets_from_store(force=True, overwrite_existing=True)
        assert "rf_api_token" in forced
        assert get_effective_setting("rf_api_token") == secrets["rf_api_token"]


# ---------------------------------------------------------------------------
# 6. M1 Iteration-2 Regression Tests
# ---------------------------------------------------------------------------


def test_secret_server_concurrent_401_short_ttl_no_token_churn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = threading.Lock()
    barrier = threading.Barrier(8, timeout=5.0)
    state: dict[str, Any] = {"refresh_count": 0, "valid_token": "tok-1"}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        if method == "POST" and path == "/oauth2/token":
            form = parse_qs(body.decode("utf-8"))
            grant = form.get("grant_type", [""])[0]
            if grant == "password":
                with lock:
                    state["valid_token"] = "tok-1"
                return 200, None, {
                    "access_token": "tok-1",
                    "refresh_token": "rt-1",
                    "expires_in": 3600,
                }
            if grant == "refresh_token":
                with lock:
                    state["refresh_count"] += 1
                    seq = state["refresh_count"] + 1
                    new_tok = f"tok-{seq}"
                    state["valid_token"] = new_tok
                    return 200, None, {
                        "access_token": new_tok,
                        "refresh_token": f"rt-{seq}",
                        "expires_in": 30,
                    }
        if method == "GET" and path == "/api/v1/secrets":
            if headers.get("authorization") == f"Bearer {state['valid_token']}":
                return 200, None, {"total": 1, "records": []}
            return 401, None, {"message": "expired"}
        if method == "GET" and path == "/api/v1/secrets/42/fields/api_key":
            auth = headers.get("authorization", "")
            if auth == "Bearer tok-1":
                barrier.wait()
                return 401, None, {"message": "token revoked"}
            with lock:
                expected = f"Bearer {state['valid_token']}"
            if auth == expected:
                return 200, None, "syn-short-ttl-secret"
            return 401, None, {"message": "superseded"}
        if method == "POST" and path == "/api/v1/oauth-expiration":
            return 200, None, {}
        return 404, None, {"message": "not found"}

    with _local_http_server(handler, monkeypatch) as base_url:
        cfg = SecretStoreConfig(
            provider="secret_server",
            tss_base_url=base_url,
            tss_auth_mode="password",
            tss_username="svc",
            tss_password="syn-tss-password",
        )
        with SecretServerProvider(cfg) as prov:
            assert prov.test_connection()["ok"] is True
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [
                    pool.submit(prov.get_secret_value, "secret_server:42:api_key")
                    for _ in range(8)
                ]
                results = [fut.result(timeout=5.0) for fut in futures]
            assert results == ["syn-short-ttl-secret"] * 8
            assert state["refresh_count"] == 1


def test_hashicorp_vault_approle_concurrent_401_short_lease_no_login_churn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = threading.Lock()
    barrier = threading.Barrier(8, timeout=5.0)
    state: dict[str, Any] = {"login_count": 0, "valid_token": ""}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        if method == "POST" and path == "/v1/auth/approle/login":
            with lock:
                state["login_count"] += 1
                n = state["login_count"]
                tok = f"app-tok-{n}"
                state["valid_token"] = tok
                lease = 3600 if n == 1 else 30
                return 200, None, {"auth": {"client_token": tok, "lease_duration": lease}}
        if method == "GET" and path == "/v1/auth/token/lookup-self":
            return 200, None, {"data": {"display_name": "app"}}
        if method == "GET" and path == "/v1/secret/data/soc/rf":
            tok = headers.get("x-vault-token", "")
            if tok == "app-tok-1":
                barrier.wait()
                return 401, None, {"errors": ["expired"]}
            with lock:
                expected = state["valid_token"]
            if tok == expected:
                return 200, None, {"data": {"data": {"api_key": "syn-vault-short-lease"}}}
            return 401, None, {"errors": ["superseded"]}
        return 404, None, {"errors": ["not found"]}

    with _local_http_server(handler, monkeypatch) as base_url:
        cfg = SecretStoreConfig(
            provider="hashicorp_vault",
            vault_addr=base_url,
            vault_auth_mode="approle",
            vault_role_id="role-1",
            vault_secret_id="sec-1",
        )
        with HashiCorpVaultProvider(cfg) as prov:
            assert prov.test_connection()["ok"] is True
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [
                    pool.submit(prov.get_secret_value, "hashicorp_vault:soc/rf:api_key")
                    for _ in range(8)
                ]
                results = [fut.result(timeout=5.0) for fut in futures]
            assert results == ["syn-vault-short-lease"] * 8
            assert state["login_count"] == 2


def test_hashicorp_vault_list_secrets_skips_partial_403_and_preserves_metadata_403(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mode = {"meta": "ok"}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        if path == "/v1/secret/metadata":
            if mode["meta"] == "forbidden":
                return 403, None, {"errors": ["permission denied"]}
            return 200, None, {"data": {"keys": ["allowed", "restricted"]}}
        if path == "/v1/secret/subkeys/allowed":
            return 200, None, {"data": {"subkeys": {"token": {}}}}
        if path in ("/v1/secret/subkeys/restricted", "/v1/secret/data/restricted"):
            return 403, None, {"errors": ["permission denied"]}
        return 404, None, {"errors": ["not found"]}

    with _local_http_server(handler, monkeypatch) as base_url:
        cfg = SecretStoreConfig(
            provider="hashicorp_vault",
            vault_addr=base_url,
            vault_auth_mode="token",
            vault_token="hv-tok",
        )
        with HashiCorpVaultProvider(cfg) as prov:
            entries = prov.list_secrets()
            assert [e.ref for e in entries] == ["hashicorp_vault:allowed:token"]

            mode["meta"] = "forbidden"
            with pytest.raises(SecretStoreAuthError):
                prov.list_secrets()


def test_hashicorp_vault_sys_health_503_raises_vault_sealed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    health_state: dict[str, Any] = {"status": 503, "body": {"initialized": True, "sealed": True}}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        if path == "/v1/auth/token/lookup-self":
            return 501, None, {"errors": ["unsupported"]}
        if path == "/v1/sys/health":
            return health_state["status"], None, health_state["body"]
        return 404, None, {"errors": ["not found"]}

    with _local_http_server(handler, monkeypatch) as base_url:
        cfg = SecretStoreConfig(
            provider="hashicorp_vault",
            vault_addr=base_url,
            vault_auth_mode="token",
            vault_token="hv-tok",
        )
        with HashiCorpVaultProvider(cfg) as prov:
            with pytest.raises(SecretStoreError) as sealed_exc:
                prov.test_connection()
            assert sealed_exc.value.reason == "vault_sealed"
            assert sealed_exc.value.status_code == 503

            health_state["status"] = 500
            health_state["body"] = {"initialized": True, "sealed": False}
            with pytest.raises(SecretStoreError) as unhealthy_exc:
                prov.test_connection()
            assert unhealthy_exc.value.reason == "vault_unhealthy"


def test_bitwarden_mid_session_relock_resets_unlocked_and_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"status": "unlocked", "unlock_calls": 0}

    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        if method == "GET" and path == "/status":
            return 200, None, {"success": True, "data": {"template": {"status": state["status"]}}}
        if method == "POST" and path == "/unlock":
            state["unlock_calls"] += 1
            payload = json.loads(body.decode("utf-8"))
            if payload.get("password") == "master-secret-pw":
                state["status"] = "unlocked"
                return 200, None, {"success": True, "data": {"title": "Unlocked"}}
            return 400, None, {"success": False, "message": "Invalid master password."}
        if method == "GET" and path == "/object/item/item-1":
            if state["status"] != "unlocked":
                return 400, None, {"success": False, "message": "Vault is locked."}
            return 200, None, {
                "success": True,
                "data": {
                    "id": "item-1",
                    "name": "SOC Key",
                    "login": {"password": "syn-bw-relock-pw"},
                },
            }
        return 404, None, {"success": False, "message": "Not found."}

    with _local_http_server(handler, monkeypatch) as base_url:
        cfg_with_pw = SecretStoreConfig(
            provider="bitwarden",
            bw_serve_url=base_url,
            bw_master_password="master-secret-pw",
        )
        with BitwardenProvider(cfg_with_pw) as prov:
            assert prov.test_connection()["ok"] is True
            assert prov._unlocked is True

            # External re-lock mid-session
            state["status"] = "locked"
            with pytest.raises(SecretStoreAuthError):
                prov.get_secret_value("bitwarden:item-1:password")
            assert prov._unlocked is False

            # Next operation re-checks /status, auto-unlocks, and succeeds
            assert prov.get_secret_value("bitwarden:item-1:password") == "syn-bw-relock-pw"
            assert state["unlock_calls"] == 1
            assert prov._unlocked is True

        # Without master password, re-lock clears _unlocked and subsequent call reports vault_locked
        cfg_no_pw = SecretStoreConfig(provider="bitwarden", bw_serve_url=base_url)
        with BitwardenProvider(cfg_no_pw) as prov_no_pw:
            assert prov_no_pw.test_connection()["ok"] is True
            state["status"] = "locked"
            with pytest.raises(SecretStoreAuthError):
                prov_no_pw.get_secret_value("bitwarden:item-1:password")
            assert prov_no_pw._unlocked is False
            with pytest.raises(SecretStoreAuthError) as locked_err:
                prov_no_pw.get_secret_value("bitwarden:item-1:password")
            assert locked_err.value.reason == "vault_locked"


def test_secret_server_is_password_null_defaults_to_is_secret_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str] | None, Any]:
        if method == "GET" and path == "/api/v1/secrets/55":
            return 200, None, {
                "id": 55,
                "name": "Null Flag Secret",
                "items": [
                    {"slug": "null-pw", "fieldName": "Null PW", "isPassword": None},
                    {"slug": "omitted-pw", "fieldName": "Omitted PW"},
                    {"slug": "explicit-false", "fieldName": "Username", "isPassword": False},
                    {"slug": "explicit-true", "fieldName": "Password", "isPassword": True},
                ],
            }
        return 404, None, {"message": "not found"}

    with _local_http_server(handler, monkeypatch) as base_url:
        cfg = SecretStoreConfig(
            provider="secret_server",
            tss_base_url=base_url,
            tss_auth_mode="token",
            tss_access_token="tok-static",
        )
        with SecretServerProvider(cfg) as prov:
            entries = prov.list_secret_fields("55")
            by_slug = {e.field_key: e.is_secret for e in entries}
            assert by_slug == {
                "null-pw": True,
                "omitted-pw": True,
                "explicit-false": False,
                "explicit-true": True,
            }
