"""Offline unit and regression tests for SOCLens v2.1 CLI extensions."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import soclens.cli as cli
from soclens.secret_stores.base import (
    SecretCatalogEntry,
    SecretStoreAuthError,
    SecretStoreError,
)
from soclens.settings import (
    get_effective_setting,
    get_settings_path,
    parse_vault_secret_map,
    save_profile_settings,
    serialize_vault_secret_map,
)
from soclens.splunk_es import SplunkESClient, SplunkESError


def _run_cli(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(sys, "argv", ["soclens", *argv])
    try:
        cli.main()
        return 0
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1


def _mock_s1_client() -> MagicMock:
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = None
    client.console_url = "https://tenant.example.test"
    return client


def _mock_es_client() -> MagicMock:
    es = MagicMock(spec=SplunkESClient)
    es.__enter__.return_value = es
    es.__exit__.return_value = None
    es.app = "SplunkEnterpriseSecuritySuite"
    es.client = MagicMock()
    return es


# ---------------------------------------------------------------------------
# 1. Global --no-secret-store, --admin Propagation, create_app Compat & Hydration
# ---------------------------------------------------------------------------


def test_global_flags_parse_before_and_after_subcommands() -> None:
    parser = cli.build_parser()

    for argv in (
        ["--no-secret-store", "tui"],
        ["tui", "--no-secret-store"],
        ["s1", "status", "--no-secret-store"],
        ["--no-secret-store", "rf", "apis"],
    ):
        ns = parser.parse_args(argv)
        assert ns.no_secret_store is True

    for argv in (
        ["--admin", "s1", "sites", "create", "--name", "MDR-1001"],
        ["s1", "--admin", "sites", "create", "--name", "MDR-1001"],
        ["s1", "exclusions", "clone", "--from-site", "1", "--to-site", "2", "--admin"],
    ):
        ns = parser.parse_args(argv)
        assert ns.admin is True


def test_tui_no_secret_store_forwarding_and_create_app_signature_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Default launch MUST NOT pass no_secret_store (legacy mock compatibility)
    with (
        patch.object(cli, "run_unified_tui") as mock_tui,
        patch.object(cli, "RecordedFutureClient") as mock_rf,
    ):
        assert _run_cli([], monkeypatch) == 0
        mock_tui.assert_called_once_with(mock_rf.return_value, dry_run=False)

    # With --no-secret-store, no_secret_store=True IS forwarded
    with (
        patch.object(cli, "run_unified_tui") as mock_tui,
        patch.object(cli, "RecordedFutureClient") as mock_rf,
    ):
        assert _run_cli(["--no-secret-store", "tui"], monkeypatch) == 0
        mock_tui.assert_called_once_with(
            mock_rf.return_value,
            dry_run=False,
            no_secret_store=True,
        )

    # Interactive watchlist also respects --no-secret-store
    with (
        patch.object(cli, "run_unified_tui") as mock_tui,
        patch.object(cli, "RecordedFutureClient") as mock_rf,
    ):
        assert _run_cli(["--no-secret-store", "watchlist", "interactive"], monkeypatch) == 0
        mock_tui.assert_called_once_with(
            mock_rf.return_value,
            dry_run=False,
            initial_tab="tab-watchlists",
            no_secret_store=True,
        )

    # Guarded create_app WITHOUT no_secret_store param does NOT raise TypeError
    calls_without: list[dict[str, Any]] = []

    def _legacy_create_app(
        *,
        client: Any = None,
        dry_run: bool = False,
        initial_tab: str | None = None,
        workspace_dir: Any = None,
    ) -> MagicMock:
        calls_without.append({"client": client, "dry_run": dry_run})
        return MagicMock()

    with patch("soclens.tui.create_app", _legacy_create_app):
        cli.run_unified_tui(None, dry_run=True, no_secret_store=True)
    assert calls_without == [{"client": None, "dry_run": True}]

    # Guarded create_app WITH no_secret_store param forwards no_secret_store=True
    calls_with: list[dict[str, Any]] = []

    def _v21_create_app(
        *,
        client: Any = None,
        dry_run: bool = False,
        initial_tab: str | None = None,
        workspace_dir: Any = None,
        no_secret_store: bool = False,
    ) -> MagicMock:
        calls_with.append({"no_secret_store": no_secret_store})
        return MagicMock()

    with patch("soclens.tui.create_app", _v21_create_app):
        cli.run_unified_tui(None, dry_run=False, no_secret_store=True)
        cli.run_unified_tui(None, dry_run=False, no_secret_store=False)
    assert calls_with == [{"no_secret_store": True}, {"no_secret_store": False}]


def test_startup_hydration_rules_and_graceful_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": "https://vault.example.test:8200",
            "vault_token": "tok-bootstrap",
            "vault_secret_map": serialize_vault_secret_map(
                {"s1_api_token": "hashicorp_vault:soclens/s1:token"}
            ),
        }
    )

    # 1. Service command triggers hydration once
    mock_s1 = _mock_s1_client()
    mock_s1.check_connection.return_value = {"build": "24.2"}
    with (
        patch.object(cli, "hydrate_secrets_from_store") as mock_hyd,
        patch.object(cli, "_build_s1_client", return_value=mock_s1),
    ):
        assert _run_cli(["s1", "status", "--json"], monkeypatch) == 0
        mock_hyd.assert_called_once_with(overwrite_existing=False)

    # 2. --no-secret-store skips hydration completely
    with (
        patch.object(cli, "hydrate_secrets_from_store") as mock_hyd,
        patch.object(cli, "_build_s1_client", return_value=mock_s1),
    ):
        assert _run_cli(["--no-secret-store", "s1", "status", "--json"], monkeypatch) == 0
        mock_hyd.assert_not_called()

    # 3. settings, secrets, and tui skip synchronous CLI hydration
    with patch.object(cli, "hydrate_secrets_from_store") as mock_hyd:
        assert _run_cli(["settings", "show", "--json"], monkeypatch) == 0
        mock_hyd.assert_not_called()

    with (
        patch.object(cli, "hydrate_secrets_from_store") as mock_hyd,
        patch.object(cli, "run_unified_tui"),
        patch.object(cli, "RecordedFutureClient"),
    ):
        assert _run_cli(["tui"], monkeypatch) == 0
        mock_hyd.assert_not_called()

    # 4. Graceful error handling when vault is unreachable during startup hydration
    caplog.set_level("WARNING", logger="soclens.cli")
    monkeypatch.setenv("S1_API_TOKEN", "env-fallback-token")
    with (
        patch.object(
            cli,
            "hydrate_secrets_from_store",
            side_effect=SecretStoreError("vault unreachable", provider="hashicorp_vault"),
        ),
        patch.object(cli, "_build_s1_client", return_value=mock_s1),
    ):
        assert _run_cli(["s1", "status", "--json"], monkeypatch) == 0
    assert "Secret store startup hydration skipped" in caplog.text


def test_emit_cli_error_formats_secret_store_and_splunk_es_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli._emit_cli_error(
        SecretStoreError(
            "bad vault token",
            provider="hashicorp_vault",
            status_code=403,
            endpoint="/v1/secret/data/app",
            reason="forbidden",
        ),
        use_json=True,
    )
    sec_err = json.loads(capsys.readouterr().err)
    assert sec_err["provider"] == "hashicorp_vault"
    assert sec_err["status_code"] == 403
    assert sec_err["reason"] == "forbidden"

    cli._emit_cli_error(
        SplunkESError("MC v2 error", status_code=500, endpoint="/findings", messages=["boom"]),
        use_json=True,
    )
    es_err = json.loads(capsys.readouterr().err)
    assert es_err["status_code"] == 500
    assert es_err["messages"] == ["boom"]


# ---------------------------------------------------------------------------
# 2. soclens secrets Subcommands (test, list, fields, map, unmap, pull)
# ---------------------------------------------------------------------------


def test_cli_secrets_missing_subcommand_and_disabled_provider(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _run_cli(["secrets", "--json"], monkeypatch) == 1
    assert "Usage: soclens secrets" in capsys.readouterr().err

    assert _run_cli(["--json", "secrets", "test"], monkeypatch) == 1
    err = json.loads(capsys.readouterr().err)
    assert "disabled" in err["error"].lower()


def test_cli_secrets_test_list_and_fields_masking(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": "https://vault.example.test:8200",
            "vault_token": "tok-bootstrap",
        }
    )
    provider = MagicMock()
    provider.__enter__.return_value = provider
    provider.__exit__.return_value = None
    provider.test_connection.return_value = {"ok": True, "provider": "hashicorp_vault"}
    provider.list_secrets.return_value = [
        SecretCatalogEntry(
            ref="hashicorp_vault:soclens/splunk:token",
            display_label="soclens/splunk :: token",
            provider="hashicorp_vault",
            item_id="soclens/splunk",
            field_key="token",
            item_title="soclens/splunk",
            path="soclens/splunk",
            is_secret=True,
        )
    ]
    provider.list_secret_fields.return_value = [
        SecretCatalogEntry(
            ref="hashicorp_vault:soclens/splunk:token",
            display_label="token",
            provider="hashicorp_vault",
            item_id="soclens/splunk",
            field_key="token",
            is_secret=True,
        )
    ]
    provider.resolve_mapped_settings.return_value = {
        "hashicorp_vault:soclens/splunk:token": "super-secret-splunk-val"
    }

    with patch.object(cli, "build_secret_store_provider", return_value=provider):
        assert _run_cli(["--json", "secrets", "test"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)["ok"] is True

        assert _run_cli(["--json", "secrets", "list", "--search", "splunk"], monkeypatch) == 0
        list_out = json.loads(capsys.readouterr().out)
        assert list_out["count"] == 1
        assert list_out["entries"][0]["ref"] == "hashicorp_vault:soclens/splunk:token"

        # Default fields: MUST NOT call resolve_mapped_settings or expose plaintext
        assert _run_cli(["--json", "secrets", "fields", "soclens/splunk"], monkeypatch) == 0
        fields_raw = capsys.readouterr().out
        assert "super-secret-splunk-val" not in fields_raw
        fields_out = json.loads(fields_raw)
        assert fields_out["revealed"] is False
        assert fields_out["fields"][0]["value"] == "***"
        provider.resolve_mapped_settings.assert_not_called()

        # --reveal fetches and displays plaintext
        assert _run_cli(["secrets", "fields", "soclens/splunk", "--reveal", "--json"], monkeypatch) == 0
        reveal_out = json.loads(capsys.readouterr().out)
        assert reveal_out["revealed"] is True
        assert reveal_out["fields"][0]["value"] == "super-secret-splunk-val"

        # Provider auth error exits 1
        provider.test_connection.side_effect = SecretStoreAuthError(
            "invalid token", provider="hashicorp_vault", status_code=403
        )
        assert _run_cli(["--json", "secrets", "test"], monkeypatch) == 1
        capsys.readouterr()


def test_cli_secrets_map_unmap_and_pull_no_plaintext_persisted(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    save_profile_settings(
        {
            "secret_provider": "secret_server",
            "tss_base_url": "https://tss.example.test",
            "tss_username": "svc-user",
            "tss_password": "svc-password",
        }
    )

    # Dry-run map does not persist
    assert (
        _run_cli(
            [
                "secrets",
                "map",
                "RF_API_TOKEN",
                "secret_server:1001:rf-api-token",
                "--dry-run",
                "--json",
            ],
            monkeypatch,
        )
        == 0
    )
    dry_map = json.loads(capsys.readouterr().out)
    assert dry_map["dry_run"] is True
    assert dry_map["key"] == "rf_api_token"

    # Real map accepts env alias and persists ONLY vault_secret_map
    assert (
        _run_cli(
            ["secrets", "map", "RF_API_TOKEN", "secret_server:1001:rf-api-token", "--json"],
            monkeypatch,
        )
        == 0
    )
    capsys.readouterr()
    assert (
        _run_cli(
            ["secrets", "map", "rf_llm_api_key", "secret_server:1004:llm-key", "--json"],
            monkeypatch,
        )
        == 0
    )
    capsys.readouterr()

    # Reject non-secret-managed setting key & malformed vault ref
    assert (
        _run_cli(
            ["secrets", "map", "rf_base_url", "secret_server:1001:url", "--json"],
            monkeypatch,
        )
        == 1
    )
    capsys.readouterr()
    assert _run_cli(["secrets", "map", "s1_api_token", "bad-ref", "--json"], monkeypatch) == 1
    capsys.readouterr()

    # Pull dry-run makes zero provider calls
    with patch.object(cli, "build_secret_store_provider") as mock_build_prov:
        assert _run_cli(["secrets", "pull", "--dry-run", "--json"], monkeypatch) == 0
        dry_pull = json.loads(capsys.readouterr().out)
        assert dry_pull["dry_run"] is True
        assert dry_pull["persisted_to_disk"] is False
        assert "rf_api_token" in dry_pull["keys"]
        mock_build_prov.assert_not_called()

    # Real pull hydrates via provider and masks stdout; settings.json never stores raw token
    fake_prov = MagicMock()
    fake_prov.__enter__.return_value = fake_prov
    fake_prov.__exit__.return_value = None
    fake_prov.resolve_mapped_settings.return_value = {
        "rf_api_token": "raw-secret-rf-token-9999",
        "rf_llm_api_key": "raw-secret-llm-key-8888",
    }
    with patch("soclens.secret_stores.build_secret_store_provider", return_value=fake_prov):
        assert _run_cli(["secrets", "pull", "--json"], monkeypatch) == 0
    pull_raw = capsys.readouterr().out
    assert "raw-secret-rf-token-9999" not in pull_raw
    assert "raw-secret-llm-key-8888" not in pull_raw
    pull_json = json.loads(pull_raw)
    assert pull_json["persisted_to_disk"] is False
    assert pull_json["count"] == 2

    settings_text = get_settings_path().read_text(encoding="utf-8")
    assert "raw-secret-rf-token-9999" not in settings_text
    assert "raw-secret-llm-key-8888" not in settings_text

    # Unmap dry-run preserves mapping, real unmap removes it
    assert _run_cli(["secrets", "unmap", "rf_llm_api_key", "--dry-run", "--json"], monkeypatch) == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is True

    assert _run_cli(["secrets", "unmap", "rf_llm_api_key", "--json"], monkeypatch) == 0
    unmap_out = json.loads(capsys.readouterr().out)
    assert unmap_out["was_mapped"] is True

    stored = json.loads(get_settings_path().read_text(encoding="utf-8"))
    saved_map = parse_vault_secret_map(stored["profiles"]["default"]["vault_secret_map"])
    assert "rf_llm_api_key" not in saved_map
    assert saved_map["rf_api_token"] == "secret_server:1001:rf-api-token"


# ---------------------------------------------------------------------------
# 3. soclens s1 v2.1 Subcommands, Admin Gating, Site Delete Confirm & Cloning
# ---------------------------------------------------------------------------


def test_cli_s1_admin_gating_blocks_mutations_before_api_call(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SOCLENS_AUTO_APPROVE", "true")
    admin_commands: list[list[str]] = [
        ["s1", "sites", "create", "--name", "MDR-9001", "--yes", "--json"],
        ["s1", "sites", "edit", "1001", "--name", "MDR-9002", "--yes", "--json"],
        ["s1", "sites", "duplicate", "1001", "--name", "MDR-DUP", "--yes", "--json"],
        ["s1", "sites", "expire", "1001", "--yes", "--json"],
        ["s1", "sites", "reactivate", "1001", "--yes", "--json"],
        ["s1", "sites", "rotate-token", "1001", "--yes", "--json"],
        ["s1", "sites", "regenerate-key", "1001", "--yes", "--json"],
        ["s1", "sites", "policy", "update", "1001", "--policy-json", '{"a": 1}', "--yes", "--json"],
        ["s1", "sites", "policy", "revert", "1001", "--yes", "--json"],
        ["s1", "sites", "delete", "1001", "--confirm-name", "MDR-1", "--yes", "--json"],
        ["s1", "users", "create", "--email", "a@b.test", "--name", "A B", "--yes", "--json"],
        ["s1", "users", "edit", "u-1", "--name", "A C", "--yes", "--json"],
        ["s1", "users", "clone", "u-1", "--target-user", "u-2", "--yes", "--json"],
        ["s1", "users", "reset-password", "u-1", "--yes", "--json"],
        ["s1", "users", "reset-2fa", "u-1", "--yes", "--json"],
        ["s1", "users", "logout", "--yes", "--json"],
        ["s1", "users", "delete", "u-1", "--yes", "--json"],
        ["s1", "service-users", "create", "--name", "su1", "--expiration-date", "2027-01-01", "--yes", "--json"],
        ["s1", "service-users", "edit", "su-1", "--description", "upd", "--yes", "--json"],
        ["s1", "service-users", "delete", "su-1", "--yes", "--json"],
        ["s1", "service-users", "token", "su-1", "--expiration-date", "2027-01-01", "--yes", "--json"],
        ["s1", "exclusions", "create", "--type", "path", "--value", "C:\\x.exe", "--site-id", "1", "--yes", "--json"],
        ["s1", "exclusions", "update", "ex-1", "--type", "path", "--os-type", "windows", "--description", "d", "--yes", "--json"],
        ["s1", "exclusions", "delete", "ex-1", "--yes", "--json"],
        ["s1", "exclusions", "clone", "--from-site", "1", "--to-site", "2", "--yes", "--json"],
        ["s1", "exclusions", "--create", "--type", "path", "--value", "C:\\x.exe", "--yes", "--json"],
        ["s1", "exclusions", "--delete", "ex-1", "--yes", "--json"],
        ["s1", "agents", "decommission", "ag-1", "--yes", "--json"],
        ["s1", "agents", "move-to-site", "ag-1", "--to-site", "2", "--yes", "--json"],
        ["s1", "agents", "--move-to-site", "2", "--ids", "ag-1", "--yes", "--json"],
        ["s1", "agents", "--decommission", "--ids", "ag-1", "--yes", "--json"],
        ["s1", "blocklist", "--add", "a" * 40, "--yes", "--json"],
        ["s1", "blocklist", "--remove", "b-1", "--yes", "--json"],
    ]
    with patch.object(cli, "_build_s1_client") as mock_build:
        for cmd in admin_commands:
            assert _run_cli(cmd, monkeypatch) == 1, f"Expected non-admin failure for {cmd}"
            err = json.loads(capsys.readouterr().err)
            assert err["admin_required"] is True
            assert "admin" in err["error"].lower()
        mock_build.assert_not_called()


def test_cli_s1_sites_lifecycle_and_exact_confirm_name_delete(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SOCLENS_AUTO_APPROVE", raising=False)
    client = _mock_s1_client()
    client.list_sites.return_value = [{"id": "1001", "name": "MDR-1001", "state": "active"}]
    client.enrich_sites_with_tiers.return_value = [
        {"id": "1001", "name": "MDR-1001", "tier": "MDR"}
    ]
    client.create_site.return_value = {"id": "1002", "name": "MDR-1002"}
    client.update_site.return_value = {"id": "1002", "name": "MDR-1002-RENAMED"}
    client.duplicate_site.return_value = {"id": "1003", "name": "MDR-1003"}
    client.expire_site.return_value = {"data": {"success": True}}
    client.reactivate_site.return_value = {"data": {"success": True}}
    client.rotate_site_token.return_value = {"data": {"token": "rot"}}
    client.regenerate_site_key.return_value = {"data": {"registrationToken": "reg"}}
    client.get_site_policy.return_value = {"mitigationMode": "protect"}
    client.update_site_policy.return_value = {"mitigationMode": "detect"}
    client.revert_site_policy.return_value = {"data": {"success": True}}
    client.get_site.return_value = {"id": "1002", "name": "MDR-1002"}
    client.delete_site.side_effect = lambda sid, confirm_site_name=None, expected_site_name=None: (
        {"deleted": True}
        if confirm_site_name == expected_site_name
        else (_ for _ in ()).throw(ValueError("Site deletion confirmation name mismatch"))
    )

    with patch.object(cli, "_build_s1_client", return_value=client):
        assert _run_cli(["s1", "sites", "list", "--tier", "MDR", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)[0]["tier"] == "MDR"

        assert (
            _run_cli(
                [
                    "s1",
                    "--admin",
                    "sites",
                    "create",
                    "--name",
                    "MDR-1002",
                    "--account-id",
                    "acc-1",
                    "--licenses",
                    "25",
                    "--copy-policy-from",
                    "1001",
                    "--clone-exclusions-from",
                    "1001",
                    "--yes",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["id"] == "1002"
        assert client.create_site.call_args.kwargs["copy_policy_from_site_id"] == "1001"
        assert client.create_site.call_args.kwargs["clone_exclusions_from_site_id"] == "1001"

        assert (
            _run_cli(
                ["--admin", "s1", "sites", "edit", "1002", "--licenses", "50", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()

        assert (
            _run_cli(
                ["s1", "--admin", "sites", "duplicate", "1001", "--name", "MDR-1003", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()

        for act in ("expire", "reactivate", "rotate-token", "regenerate-key"):
            assert _run_cli(["s1", "--admin", "sites", act, "1002", "--yes", "--json"], monkeypatch) == 0
            capsys.readouterr()

        assert _run_cli(["s1", "sites", "policy", "get", "1002", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)["mitigationMode"] == "protect"

        assert (
            _run_cli(
                [
                    "s1",
                    "--admin",
                    "sites",
                    "policy",
                    "update",
                    "1002",
                    "--policy-json",
                    '{"mitigationMode": "detect"}',
                    "--yes",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()

        assert (
            _run_cli(["s1", "--admin", "sites", "policy", "revert", "1002", "--yes", "--json"], monkeypatch)
            == 0
        )
        capsys.readouterr()

        # Delete without --confirm-name fails before calling delete_site
        assert _run_cli(["s1", "--admin", "sites", "delete", "1002", "--yes", "--json"], monkeypatch) == 1
        err_missing = json.loads(capsys.readouterr().err)
        assert "confirm" in err_missing["error"].lower()
        client.delete_site.assert_not_called()

        # Delete with mismatched --confirm-name fails
        assert (
            _run_cli(
                [
                    "s1",
                    "--admin",
                    "sites",
                    "delete",
                    "1002",
                    "--confirm-name",
                    "WRONG-NAME",
                    "--yes",
                    "--json",
                ],
                monkeypatch,
            )
            == 1
        )
        capsys.readouterr()

        # Delete with exact matching --confirm-name succeeds
        assert (
            _run_cli(
                [
                    "s1",
                    "--admin",
                    "sites",
                    "delete",
                    "1002",
                    "--confirm-name",
                    "MDR-1002",
                    "--yes",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["deleted"] is True


def test_cli_s1_users_service_users_roles_and_cloud_alerts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SOCLENS_AUTO_APPROVE", raising=False)
    client = _mock_s1_client()
    client.list_users.return_value = [{"id": "u-1", "email": "a@example.test", "scope": "site"}]
    client.get_user.return_value = {"id": "u-1", "scope": "site"}
    client.create_user.return_value = {"id": "u-2", "email": "b@example.test"}
    client.update_user.return_value = {"id": "u-1", "fullName": "Updated"}
    client.clone_user_permissions.return_value = {
        "source_user_id": "u-1",
        "scope": "site",
        "scopeRoles": [{"id": "1002", "roleId": "r-1"}],
    }
    client.send_reset_password_email.return_value = {"data": {"affected": 1}}
    client.reset_2fa.return_value = {"data": {"affected": 1}}
    client.delete_2fa.return_value = {"data": {"affected": 1}}
    client.logout_user.return_value = {"data": {"success": True}}
    client.delete_user.return_value = {"data": {"success": True}}
    client.delete_users.return_value = {"data": {"affected": 2}}

    client.list_service_users.return_value = [{"id": "su-1", "name": "siem-bot", "scope": "site"}]
    client.create_service_user.return_value = {"id": "su-2", "name": "soc-bot"}
    client.update_service_user.return_value = {"id": "su-1", "description": "updated"}
    client.delete_service_user.return_value = {"data": {"success": True}}
    client.generate_service_user_token.return_value = {"data": {"token": "tok-new"}}
    client.list_rbac_roles.return_value = [{"id": "r-1", "name": "Admin"}]

    client.list_cloud_alerts.return_value = [{"id": "ca-1", "ruleName": "STAR Rule"}]
    client.update_cloud_alert_verdict.return_value = {"data": {"affected": 1}}
    client.update_cloud_alert_incident_status.return_value = {"data": {"affected": 1}}

    with patch.object(cli, "_build_s1_client", return_value=client):
        assert _run_cli(["s1", "users", "list", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)[0]["id"] == "u-1"

        assert (
            _run_cli(
                [
                    "s1",
                    "--admin",
                    "users",
                    "create",
                    "--email",
                    "b@example.test",
                    "--name",
                    "User B",
                    "--site-id",
                    "1002",
                    "--role-id",
                    "r-1",
                    "--yes",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()

        assert (
            _run_cli(["s1", "--admin", "users", "edit", "u-1", "--name", "Updated", "--yes", "--json"], monkeypatch)
            == 0
        )
        capsys.readouterr()

        assert (
            _run_cli(
                [
                    "s1",
                    "--admin",
                    "users",
                    "clone",
                    "u-1",
                    "--target-user",
                    "u-2",
                    "--to-site",
                    "1002",
                    "--yes",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()

        assert _run_cli(["s1", "--admin", "users", "reset-password", "u-1", "--yes", "--json"], monkeypatch) == 0
        capsys.readouterr()
        assert _run_cli(["s1", "--admin", "users", "reset-2fa", "u-1", "--enroll", "--yes", "--json"], monkeypatch) == 0
        capsys.readouterr()
        assert _run_cli(["s1", "--admin", "users", "reset-2fa", "u-1", "--delete-2fa", "--yes", "--json"], monkeypatch) == 0
        capsys.readouterr()
        assert _run_cli(["s1", "--admin", "users", "logout", "--yes", "--json"], monkeypatch) == 0
        capsys.readouterr()
        assert _run_cli(["s1", "--admin", "users", "delete", "u-1", "u-2", "--yes", "--json"], monkeypatch) == 0
        capsys.readouterr()
        client.delete_users.assert_called_once_with(["u-1", "u-2"])

        # Service users & roles
        assert _run_cli(["s1", "service-users", "list", "--json"], monkeypatch) == 0
        capsys.readouterr()
        assert (
            _run_cli(
                [
                    "s1",
                    "--admin",
                    "service-users",
                    "create",
                    "--name",
                    "soc-bot",
                    "--expiration-date",
                    "2027-01-01",
                    "--site-id",
                    "1001",
                    "--yes",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()
        assert (
            _run_cli(
                ["s1", "--admin", "service-users", "edit", "su-1", "--description", "updated", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()
        assert (
            _run_cli(
                ["s1", "--admin", "service-users", "token", "su-1", "--expiration-date", "2027-01-01", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()
        assert _run_cli(["s1", "--admin", "service-users", "delete", "su-1", "--yes", "--json"], monkeypatch) == 0
        capsys.readouterr()
        assert _run_cli(["s1", "roles", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)[0]["name"] == "Admin"

        # Cloud alerts (Ops triage without --admin)
        assert _run_cli(["s1", "cloud-alerts", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)[0]["id"] == "ca-1"
        assert (
            _run_cli(
                ["s1", "cloud-alerts", "verdict", "ca-1", "--verdict", "true_positive", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()
        assert (
            _run_cli(
                ["s1", "cloud-alerts", "incident-status", "ca-1", "--status", "resolved", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()


def test_cli_s1_exclusions_cloning_agents_and_blocklist(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SOCLENS_AUTO_APPROVE", raising=False)
    client = _mock_s1_client()
    client.list_exclusions.return_value = [{"id": "ex-1", "type": "path", "value": "C:\\a.exe"}]
    client.validate_exclusion.return_value = {"status": "NotFound"}
    client.create_exclusion.return_value = {"data": [{"id": "ex-2"}]}
    client.update_exclusion.return_value = {"data": [{"id": "ex-1"}]}
    client.delete_exclusions.return_value = {"data": {"affected": 1}}
    client.clone_exclusions.side_effect = [
        {
            "source_site_id": "1001",
            "target_site_id": "1002",
            "dry_run": True,
            "requests_per_second": 15.0,
            "will_create": [{"payload": {"value": "C:\\a.exe"}}],
            "skipped_duplicate": [],
            "inherited_from_account": [],
            "counts": {
                "will_create": 1,
                "skipped_duplicate": 0,
                "inherited_from_account": 0,
                "created": 0,
                "failed": 0,
            },
        },
        {
            "source_site_id": "1001",
            "target_site_id": "1002",
            "dry_run": False,
            "requests_per_second": 10.0,
            "counts": {"will_create": 1, "created": 1, "failed": 0},
        },
    ]
    client.fetch_agent_logs.return_value = {"data": {"affected": 1}}
    client.move_agents_to_site.return_value = {"data": {"affected": 1}}
    client.decommission_agents.return_value = {"data": {"affected": 1}}
    client.add_to_blocklist.return_value = {"data": [{"id": "b-1"}]}
    client.update_blocklist.return_value = {"data": [{"id": "b-1"}]}
    client.remove_from_blocklist.return_value = {"data": {"affected": 1}}

    with patch.object(cli, "_build_s1_client", return_value=client):
        # Legacy list preserved
        assert _run_cli(["s1", "exclusions", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)[0]["id"] == "ex-1"

        assert (
            _run_cli(
                ["s1", "exclusions", "validate", "--type", "white_hash", "--value", "a" * 40, "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()

        # Clone without --yes fails
        assert (
            _run_cli(
                ["s1", "--admin", "exclusions", "clone", "--from-site", "1001", "--to-site", "1002", "--json"],
                monkeypatch,
            )
            == 1
        )
        assert json.loads(capsys.readouterr().err)["approval_required"] is True

        # Clone --dry-run calls clone_exclusions(..., dry_run=True) and returns counts
        assert (
            _run_cli(
                [
                    "s1",
                    "--admin",
                    "exclusions",
                    "clone",
                    "--from-site",
                    "1001",
                    "--to-site",
                    "1002",
                    "--dry-run",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        dry_res = json.loads(capsys.readouterr().out)
        assert dry_res["dry_run"] is True
        assert dry_res["counts"]["will_create"] == 1

        # Clone --yes --rate-limit 10 executes
        assert (
            _run_cli(
                [
                    "--admin",
                    "s1",
                    "exclusions",
                    "clone",
                    "--from-site",
                    "1001",
                    "--to-site",
                    "1002",
                    "--rate-limit",
                    "10",
                    "--yes",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["counts"]["created"] == 1
        assert client.clone_exclusions.call_args.kwargs["requests_per_second"] == 10.0

        # Invalid --rate-limit 0 fails cleanly
        assert (
            _run_cli(
                [
                    "s1",
                    "--admin",
                    "exclusions",
                    "clone",
                    "--from-site",
                    "1001",
                    "--to-site",
                    "1002",
                    "--rate-limit",
                    "0",
                    "--dry-run",
                    "--json",
                ],
                monkeypatch,
            )
            == 1
        )
        capsys.readouterr()

        # Agents Ops fetch-logs vs Admin move-to-site / decommission (subcommand & flag modes)
        assert _run_cli(["s1", "agents", "fetch-logs", "ag-1", "--yes", "--json"], monkeypatch) == 0
        capsys.readouterr()
        assert (
            _run_cli(
                ["--admin", "s1", "agents", "--move-to-site", "1002", "--ids", "ag-1", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()
        client.move_agents_to_site.assert_called_with(["ag-1"], "1002")

        assert _run_cli(["s1", "--admin", "agents", "decommission", "ag-1", "--yes", "--json"], monkeypatch) == 0
        capsys.readouterr()

        # Blocklist add/update/remove
        assert (
            _run_cli(
                ["s1", "--admin", "blocklist", "add", "b" * 40, "--site-id", "1001", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()
        assert (
            _run_cli(
                ["s1", "--admin", "blocklist", "update", "b-1", "--sha1", "c" * 40, "--site-id", "1001", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()
        assert _run_cli(["s1", "--admin", "blocklist", "remove", "b-1", "--yes", "--json"], monkeypatch) == 0
        capsys.readouterr()


# ---------------------------------------------------------------------------
# 4. soclens splunk es v2.1 Subcommands & Legacy Preservation
# ---------------------------------------------------------------------------


def test_cli_splunk_es_v21_notables_triage_and_enrich(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    es = _mock_es_client()
    es.list_notables.return_value = [{"event_id": "legacy-1", "urgency": "high"}]
    es.query_findings_hybrid.return_value = {
        "items": [{"event_id": "mc-1@@t1", "tenant_id": "1001", "urgency": "critical"}],
        "offset": 0,
        "limit": 100,
        "total": 1,
        "source_backend": "mc_v2",
    }
    es.update_notable.return_value = {"success": True}
    es.triage_findings_hybrid.return_value = {"backend": "mc_v2", "updated_ids": ["mc-1@@t1"]}

    with patch.object(cli, "_build_splunk_es_client_from_args", return_value=es):
        # Legacy notables path preserved
        assert _run_cli(["splunk", "es", "notables", "--urgency", "high", "--format", "json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)["notables"][0]["event_id"] == "legacy-1"
        es.list_notables.assert_called_once()
        es.query_findings_hybrid.assert_not_called()

        # v2.1 tenant / MC v2 notables path
        assert (
            _run_cli(
                [
                    "splunk",
                    "es",
                    "notables",
                    "--tenant",
                    "1001",
                    "--use-v2",
                    "--item-type",
                    "findings",
                    "--min-risk-score",
                    "50",
                    "--format",
                    "json",
                ],
                monkeypatch,
            )
            == 0
        )
        v2_out = json.loads(capsys.readouterr().out)
        assert v2_out["source_backend"] == "mc_v2"
        assert v2_out["notables"][0]["tenant_id"] == "1001"
        assert es.query_findings_hybrid.call_args.kwargs["tenant_id"] == "1001"
        assert es.query_findings_hybrid.call_args.kwargs["min_risk_score"] == 50.0

        # Legacy update-notable path preserved
        assert _run_cli(["splunk", "es", "update-notable", "ev-1", "--status", "resolved"], monkeypatch) == 0
        capsys.readouterr()
        es.update_notable.assert_called_once()
        es.triage_findings_hybrid.assert_not_called()

        # v2.1 update-notable path
        assert (
            _run_cli(
                [
                    "splunk",
                    "es",
                    "update-notable",
                    "mc-1@@t1",
                    "--use-v2",
                    "--sensitivity",
                    "amber",
                    "--queue-id",
                    "q-1",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["result"]["backend"] == "mc_v2"
        es.triage_findings_hybrid.assert_called_once()

    # enrich --tenant uses query_findings_hybrid
    rf = MagicMock()
    with (
        patch.object(cli, "_build_splunk_es_client_from_args", return_value=es),
        patch.object(cli, "_build_rf_client", return_value=rf),
        patch.object(cli, "SplunkRFEnricher") as mock_enricher_cls,
    ):
        mock_enricher_cls.return_value.enrich_events.return_value = [
            {"event_id": "mc-1@@t1", "tenant_id": "1001", "rf_observables": []}
        ]
        assert _run_cli(["splunk", "es", "enrich", "--tenant", "1001", "--format", "json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)["count"] == 1


def test_cli_splunk_es_investigations_notes_history_ar_and_custom_fields(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SOCLENS_AUTO_APPROVE", raising=False)
    es = _mock_es_client()
    es.list_investigations.return_value = [
        {"event_id": "inv-1", "tenant_id": "1001", "name": "Tenant 1001 Case"},
        {"event_id": "inv-2", "tenant_id": "2002", "name": "Tenant 2002 Case"},
    ]
    es.create_investigation.return_value = {"investigation_guid": "inv-3", "name": "New Inv"}
    es.update_investigation.return_value = {"investigation_guid": "inv-1", "status": "Resolved"}
    es.add_findings_to_investigation.return_value = {"investigation_guid": "inv-1"}
    es.list_notes.return_value = {
        "items": [{"id": "n-1", "title": "Triage", "content": "Checked host"}],
        "offset": 0,
        "limit": 50,
        "total": 1,
        "has_skipped_comments": False,
    }
    es.create_note.return_value = {"id": "n-2", "content": "Added note"}
    es.update_note.return_value = {"id": "n-2", "content": "Edited note"}
    es.delete_note.return_value = {"deleted": True, "note_id": "n-2"}
    es.get_history.return_value = {
        "items": [{"time": "2026-11-25T00:00:00Z", "action": "updated", "field": "status"}],
        "offset": 0,
        "limit": 100,
        "total": 1,
    }
    es.list_modaction_invocations.return_value = [{"action_name": "ping", "status": "success"}]
    es.list_adaptive_response_actions.return_value = [{"name": "ping", "label": "Ping", "supports_adhoc": True}]
    es.dispatch_adaptive_response.return_value = {"success": True}
    es.discover_custom_fields.return_value = [{"field": "tenant_id", "label": "Tenant ID"}]

    with patch.object(cli, "_build_splunk_es_client_from_args", return_value=es):
        # investigations default list + --tenant client filter
        assert _run_cli(["splunk", "es", "investigations", "--tenant", "1001", "--format", "json"], monkeypatch) == 0
        inv_out = json.loads(capsys.readouterr().out)
        assert inv_out["count"] == 1
        assert inv_out["investigations"][0]["event_id"] == "inv-1"

        # investigations create requires --yes or --dry-run
        assert _run_cli(["splunk", "es", "investigations", "create", "--name", "New Inv", "--json"], monkeypatch) == 1
        assert json.loads(capsys.readouterr().err)["approval_required"] is True

        assert (
            _run_cli(
                ["splunk", "es", "investigations", "create", "--name", "New Inv", "--dry-run", "--json"],
                monkeypatch,
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["dry_run"] is True
        es.create_investigation.assert_not_called()

        assert (
            _run_cli(
                ["splunk", "es", "investigations", "create", "--name", "New Inv", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["investigation_guid"] == "inv-3"

        assert (
            _run_cli(
                ["splunk", "es", "investigations", "update", "inv-1", "--status", "Resolved", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()

        assert (
            _run_cli(
                ["splunk", "es", "investigations", "add-findings", "inv-1", "f-1", "f-2", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()

        # notes list (default via --record-id and subcommand), create, update, delete
        assert _run_cli(["splunk", "es", "notes", "--record-id", "f-1@@t1", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)["items"][0]["id"] == "n-1"

        assert (
            _run_cli(
                ["splunk", "es", "notes", "create", "f-1@@t1", "--content", "Added note", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()
        assert (
            _run_cli(
                ["splunk", "es", "notes", "update", "f-1@@t1", "n-2", "--content", "Edited note", "--yes", "--json"],
                monkeypatch,
            )
            == 0
        )
        capsys.readouterr()
        assert _run_cli(["splunk", "es", "notes", "delete", "f-1@@t1", "n-2", "--yes", "--json"], monkeypatch) == 0
        capsys.readouterr()

        # history
        assert _run_cli(["splunk", "es", "history", "f-1@@t1", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)["total"] == 1

        # ar-invocations & ar-dispatch
        assert _run_cli(["splunk", "es", "ar-invocations", "--sid", "sid-1", "--rid", "0", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)["count"] == 1

        assert _run_cli(["splunk", "es", "ar-dispatch", "--list", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)["actions"][0]["name"] == "ping"

        assert (
            _run_cli(
                [
                    "splunk",
                    "es",
                    "ar-dispatch",
                    "--action",
                    "ping",
                    "--sid",
                    "sid-1",
                    "--rid",
                    "0",
                    "--param",
                    "target=198.51.100.1",
                    "--dry-run",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["dry_run"] is True
        es.dispatch_adaptive_response.assert_not_called()

        assert (
            _run_cli(
                [
                    "splunk",
                    "es",
                    "ar-dispatch",
                    "--action",
                    "ping",
                    "--sid",
                    "sid-1",
                    "--rid",
                    "0",
                    "--params-json",
                    '{"target": "198.51.100.1"}',
                    "--param",
                    "count=2",
                    "--yes",
                    "--json",
                ],
                monkeypatch,
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["success"] is True
        es.dispatch_adaptive_response.assert_called_once_with(
            "ping",
            sid="sid-1",
            rid="0",
            params={"target": "198.51.100.1", "count": "2"},
            index=None,
        )

        # custom-fields online
        assert _run_cli(["splunk", "es", "custom-fields", "--refresh", "--json"], monkeypatch) == 0
        cf_out = json.loads(capsys.readouterr().out)
        assert cf_out["tenant_field"] == "tenant_id"
        assert cf_out["discovered_fields"][0]["field"] == "tenant_id"

    # custom-fields --offline never builds Splunk client
    with patch.object(cli, "_build_splunk_es_client_from_args") as mock_build_es:
        assert _run_cli(["splunk", "es", "custom-fields", "--offline", "--json"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)["offline"] is True
        mock_build_es.assert_not_called()


def test_cli_s1_users_edit_preserves_scope_roles_against_real_client(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("S1_CONSOLE_URL", "https://s1.example.test")
    monkeypatch.setenv("S1_API_TOKEN", "tok-s1-test")
    sent: list[tuple[str, str, Any]] = []

    def _fake_request(
        _self: Any,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> MagicMock:
        sent.append((method, url, kwargs.get("json")))
        resp = MagicMock(status_code=200, headers={})
        if method == "GET":
            resp.json.return_value = {
                "data": {
                    "id": "u-1",
                    "email": "a@b.test",
                    "fullName": "Old Name",
                    "scope": "site",
                    "scopeRoles": [
                        {
                            "id": "1001",
                            "roleId": "r-1",
                            "roleName": "IR Team",
                            "name": "MDR-1001",
                            "accountName": "Acct",
                        }
                    ],
                }
            }
        else:
            resp.json.return_value = {"data": {"id": "u-1", "fullName": "New Name"}}
        return resp

    with patch("requests.Session.request", new=_fake_request):
        assert (
            _run_cli(
                ["soclens", "s1", "--admin", "users", "edit", "u-1", "--name", "New Name", "--yes", "--json"][1:],
                monkeypatch,
            )
            == 0
        )
    out = json.loads(capsys.readouterr().out)
    assert out["id"] == "u-1"
    assert len(sent) == 2
    assert sent[0][0] == "GET" and sent[0][1].endswith("/web/api/v2.1/users/u-1")
    assert sent[1][0] == "PUT" and sent[1][1].endswith("/web/api/v2.1/users/u-1")
    put_data = sent[1][2]["data"]
    assert put_data["scope"] == "site"
    assert put_data["fullName"] == "New Name"
    assert put_data["scopeRoles"] == [{"roleId": "r-1", "id": "1001"}]


def test_cli_splunk_es_nested_list_preserves_parent_flags_before_subcommand(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SOCLENS_AUTO_APPROVE", raising=False)
    es = _mock_es_client()
    es.list_investigations.return_value = [
        {"event_id": "inv-1", "tenant_id": "1001", "name": "Tenant 1001 Case"},
        {"event_id": "inv-2", "tenant_id": "2002", "name": "Tenant 2002 Case"},
    ]
    es.create_investigation.return_value = {"investigation_guid": "inv-3", "name": "New Inv"}
    es.list_notes.return_value = {
        "items": [{"id": "n-1", "title": "Triage", "content": "abc hit"}],
        "offset": 0,
        "limit": 50,
        "total": 1,
        "has_skipped_comments": False,
    }

    with patch.object(cli, "_build_splunk_es_client_from_args", return_value=es):
        # Flags placed BEFORE `list` must NOT be clobbered by nested subparser defaults
        assert (
            _run_cli(
                [
                    "splunk",
                    "es",
                    "investigations",
                    "--tenant",
                    "1001",
                    "--status",
                    "New",
                    "--limit",
                    "25",
                    "--offset",
                    "5",
                    "--format",
                    "json",
                    "list",
                ],
                monkeypatch,
            )
            == 0
        )
        inv_out = json.loads(capsys.readouterr().out)
        assert inv_out["count"] == 1
        assert inv_out["investigations"][0]["event_id"] == "inv-1"
        assert es.list_investigations.call_args.kwargs["status"] == "New"
        assert es.list_investigations.call_args.kwargs["limit"] == 25
        assert es.list_investigations.call_args.kwargs["offset"] == 5

        assert (
            _run_cli(
                [
                    "splunk",
                    "es",
                    "notes",
                    "--search",
                    "abc",
                    "--limit",
                    "10",
                    "--offset",
                    "2",
                    "--format",
                    "json",
                    "list",
                    "rec-1@@t1",
                ],
                monkeypatch,
            )
            == 0
        )
        notes_out = json.loads(capsys.readouterr().out)
        assert notes_out["record_id"] == "rec-1@@t1"
        assert notes_out["items"][0]["id"] == "n-1"
        es.list_notes.assert_called_once_with(
            "rec-1@@t1",
            finding_time=None,
            search="abc",
            note_type=None,
            limit=10,
            offset=2,
            sort=None,
        )

        # Parent --format json before `create` is also preserved
        assert (
            _run_cli(
                [
                    "splunk",
                    "es",
                    "investigations",
                    "--format",
                    "json",
                    "create",
                    "--name",
                    "New Inv",
                    "--yes",
                ],
                monkeypatch,
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["investigation_guid"] == "inv-3"

    # Parent Splunk conn flags before nested `list` are not clobbered by _add_splunk_conn_args
    with patch.object(cli, "get_splunk_config") as mock_get_splunk_cfg:
        mock_get_splunk_cfg.return_value = MagicMock(
            host="https://splunk.example.test:8089",
            token="tok-override",
            username=None,
            password=None,
            app="SplunkEnterpriseSecuritySuite",
            verify_ssl=False,
        )
        with patch.object(cli, "SplunkClient") as mock_splunk_cls:
            ns = cli.build_parser().parse_args(
                [
                    "splunk",
                    "es",
                    "investigations",
                    "--host",
                    "https://splunk.example.test:8089",
                    "--token",
                    "tok-override",
                    "list",
                ]
            )
            cli._build_splunk_es_client_from_args(ns)
            assert mock_get_splunk_cfg.call_args.kwargs["host"] == "https://splunk.example.test:8089"
            assert mock_get_splunk_cfg.call_args.kwargs["token"] == "tok-override"
            mock_splunk_cls.assert_called_once()


def test_cli_s1_sites_delete_pre_call_confirm_name_guard_with_plain_mock(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SOCLENS_AUTO_APPROVE", raising=False)
    client = _mock_s1_client()
    client.get_site.return_value = {"id": "1002", "name": "MDR-1002"}

    with patch.object(cli, "_build_s1_client", return_value=client):
        for bad_name in ("wrong", "mdr-1002", " MDR-1002", "MDR-1002 "):
            assert (
                _run_cli(
                    [
                        "s1",
                        "--admin",
                        "sites",
                        "delete",
                        "1002",
                        "--confirm-name",
                        bad_name,
                        "--yes",
                        "--json",
                    ],
                    monkeypatch,
                )
                == 1
            )
            err = json.loads(capsys.readouterr().err)
            assert "mismatch" in err["error"].lower()
            client.delete_site.assert_not_called()


def test_cli_secrets_pull_with_provider_cli_override(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Saved config defaults to secret_provider='none', overridden via CLI --provider hashicorp_vault
    save_profile_settings(
        {
            "secret_provider": "none",
            "vault_addr": "https://vault.example.test:8200",
            "vault_token": "tok-bootstrap",
            "vault_secret_map": serialize_vault_secret_map(
                {"s1_api_token": "hashicorp_vault:soclens/s1:token"}
            ),
        }
    )
    fake_prov = MagicMock()
    fake_prov.__enter__.return_value = fake_prov
    fake_prov.__exit__.return_value = None
    fake_prov.resolve_mapped_settings.return_value = {
        "s1_api_token": "raw-s1-vault-secret-7777",
    }

    with patch.object(cli, "build_secret_store_provider", return_value=fake_prov) as mock_build:
        assert (
            _run_cli(
                ["secrets", "pull", "--provider", "hashicorp_vault", "--json"],
                monkeypatch,
            )
            == 0
        )
    mock_build.assert_called_once()
    passed_cfg = mock_build.call_args.args[0]
    assert passed_cfg.provider == "hashicorp_vault"

    raw_out = capsys.readouterr().out
    assert "raw-s1-vault-secret-7777" not in raw_out
    out = json.loads(raw_out)
    assert out["provider"] == "hashicorp_vault"
    assert out["count"] == 1
    assert out["persisted_to_disk"] is False
    assert "s1_api_token" in out["pulled"]
    assert out["pulled"]["s1_api_token"] != "raw-s1-vault-secret-7777"
    assert get_effective_setting("s1_api_token") == "raw-s1-vault-secret-7777"

    settings_text = get_settings_path().read_text(encoding="utf-8")
    assert "raw-s1-vault-secret-7777" not in settings_text


def test_cli_hygiene_ast_no_posix_or_shell_true() -> None:
    import ast

    cli_src = Path(cli.__file__).read_text(encoding="utf-8")
    tree = ast.parse(cli_src)
    posix_mods = {"fcntl", "termios", "tty", "pty", "pwd", "grp", "resource", "curses", "syslog", "posix"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in posix_mods
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in posix_mods
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    raise AssertionError("os.system is forbidden")
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    raise AssertionError("shell=True is forbidden")
