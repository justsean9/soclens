"""Offline Textual Pilot tests for SettingsPane cat-secrets/vault dropdowns and LocalLLMPane Copilot."""

from __future__ import annotations

import asyncio
import json
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from textual.widgets import (
    Button,
    Checkbox,
    ContentSwitcher,
    Input,
    OptionList,
    RichLog,
    Select,
    Static,
)

from soclens.config import (
    ConfiguredSession,
    PivotPayload,
    get_local_llm_config,
)
from soclens.llm import LocalLLMClient
from soclens.settings import (
    SECRET_MANAGED_SETTING_KEYS,
    clear_session_overrides,
    get_effective_setting,
    get_profile_settings,
    invalidate_settings_cache,
    is_vault_hydrated_setting,
    parse_vault_secret_map,
    save_profile_settings,
    serialize_vault_secret_map,
    set_session_overrides,
)
from soclens.tui import create_app
from soclens.tui.screens.llm import LocalLLMPane
from soclens.tui.screens.settings import (
    _CATEGORIES,
    _SECRET_INPUT_IDS,
    _SECRET_MANAGED_VAULT_FIELDS,
    _VAULT_BANNER_IDS,
    SettingsPane,
)


class _LocalVaultStub:
    """Minimal offline ThreadingHTTPServer mimicking HashiCorp Vault KV v2."""

    def __init__(self) -> None:
        self.secrets: dict[str, dict[str, str]] = {
            "soclens/rf": {"api_token": "vault-rf-tok-secret-9001"},
            "soclens/s1": {"api_token": "vault-s1-tok-secret-9002"},
            "soclens/llm": {"api_key": "vault-llm-key-secret-9003"},
        }
        self.expected_token = "stub-vault-token-123"
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _send_json(self, code: int, body: dict[str, Any]) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _check_auth(self) -> bool:
                tok = self.headers.get("X-Vault-Token", "")
                if tok != parent.expected_token:
                    self._send_json(403, {"errors": ["permission denied"]})
                    return False
                return True

            def do_LIST(self) -> None:  # noqa: N802
                if not self._check_auth():
                    return
                path = self.path.split("?", 1)[0]
                if path == "/v1/secret/metadata":
                    self._send_json(200, {"data": {"keys": ["soclens/"]}})
                elif path == "/v1/secret/metadata/soclens":
                    self._send_json(200, {"data": {"keys": ["rf", "s1", "llm"]}})
                else:
                    self._send_json(404, {"errors": ["not found"]})

            def do_GET(self) -> None:  # noqa: N802
                if not self._check_auth():
                    return
                path = self.path.split("?", 1)[0]
                if path == "/v1/auth/token/lookup-self":
                    self._send_json(
                        200,
                        {"data": {"display_name": "soclens-stub", "policies": ["default"], "ttl": 3600}},
                    )
                    return
                if path.startswith("/v1/secret/data/"):
                    sub = path[len("/v1/secret/data/") :]
                    if sub in parent.secrets:
                        self._send_json(200, {"data": {"data": parent.secrets[sub]}})
                        return
                self._send_json(404, {"errors": ["not found"]})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _LocalVaultStub:
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)


@pytest.fixture
def isolated_settings_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    settings_path = tmp_path / "settings.json"
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(settings_path))
    for env_key in (
        "RF_API_TOKEN",
        "RECORDED_FUTURE_API_KEY",
        "RF_SANDBOX_TOKEN",
        "RF_ASI_API_KEY",
        "RF_PFI_TOKEN",
        "RF_RISKRECON_TOKEN",
        "SPLUNK_TOKEN",
        "SPLUNK_USERNAME",
        "SPLUNK_PASSWORD",
        "S1_API_TOKEN",
        "RF_LLM_API_KEY",
        "SOCLENS_SECRET_PROVIDER",
        "SOCLENS_VAULT_SECRET_MAP",
        "VAULT_ADDR",
        "VAULT_TOKEN",
        "BW_MASTER_PASSWORD",
    ):
        monkeypatch.delenv(env_key, raising=False)
    invalidate_settings_cache()
    clear_session_overrides()
    yield settings_path
    clear_session_overrides()
    invalidate_settings_cache()


def test_tui_settings_cat_secrets_index_and_provider_groups_toggle(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    expected_prefix = (
        ("cat-rf", "Recorded Future API"),
        ("cat-splunk", "Splunk & Splunk ES"),
        ("cat-s1", "SentinelOne EDR"),
        ("cat-network", "Network, SSL & Proxy"),
        ("cat-workspace", "Workspace & Defaults"),
        ("cat-profiles", "Profiles & Storage"),
    )
    assert _CATEGORIES[:6] == expected_prefix
    assert _CATEGORIES[6] == ("cat-secrets", "Secret Manager (PAM / Vault)")

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(SettingsPane)
            cat_list = pane.query_one("#settings-category-list", OptionList)
            cat_list.highlighted = 6
            await pilot.pause()
            assert pane.query_one("#settings-category-switcher", ContentSwitcher).current == "cat-secrets"

            prov_sel = pane.query_one("#set-secret-provider", Select)
            groups = ("#tss-fields-group", "#vault-fields-group", "#op-fields-group", "#bw-fields-group")
            assert all(pane.query_one(gid).display is False for gid in groups)

            for provider, active_gid in (
                ("secret_server", "#tss-fields-group"),
                ("hashicorp_vault", "#vault-fields-group"),
                ("onepassword_connect", "#op-fields-group"),
                ("bitwarden", "#bw-fields-group"),
                ("none", None),
            ):
                prov_sel.value = provider
                await pilot.pause()
                for gid in groups:
                    assert pane.query_one(gid).display is (gid == active_gid)

            assert not isolated_settings_env.exists()

    asyncio.run(_run())


def test_tui_settings_cat_secrets_masked_inputs_bw_optional_and_show_secrets(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(SettingsPane)
            assert len(_SECRET_INPUT_IDS) == 18
            for widget_id in _SECRET_INPUT_IDS:
                assert pane.query_one(f"#{widget_id}", Input).password is True

            bw_pw = pane.query_one("#set-bw-master-password", Input)
            assert bw_pw.password is True
            assert bw_pw.value == ""

            show_cb = pane.query_one("#settings-show-secrets", Checkbox)
            show_cb.value = True
            await pilot.pause()
            for widget_id in _SECRET_INPUT_IDS:
                assert pane.query_one(f"#{widget_id}", Input).password is False

            show_cb.value = False
            await pilot.pause()
            for widget_id in _SECRET_INPUT_IDS:
                assert pane.query_one(f"#{widget_id}", Input).password is True

            # Save Bitwarden with blank bw_master_password -> omitted from settings.json
            pane.query_one("#settings-category-switcher", ContentSwitcher).current = "cat-secrets"
            pane.query_one("#set-secret-provider", Select).value = "bitwarden"
            pane.query_one("#set-bw-serve-url", Input).value = "http://127.0.0.1:8087"
            await pilot.pause()
            await pilot.click("#settings-save-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            saved = get_profile_settings()
            assert saved["secret_provider"] == "bitwarden"
            assert "bw_master_password" not in saved
            assert stat.S_IMODE(isolated_settings_env.stat().st_mode) == 0o600

    asyncio.run(_run())


def test_tui_settings_dynamic_input_to_vault_dropdown_swap_including_llm_key(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    assert len(_SECRET_MANAGED_VAULT_FIELDS) == 10
    assert tuple(k for k, _, _ in _SECRET_MANAGED_VAULT_FIELDS) == SECRET_MANAGED_SETTING_KEYS

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(SettingsPane)

            for _key, inp_id, sel_id in _SECRET_MANAGED_VAULT_FIELDS:
                assert pane.query_one(f"#{inp_id}", Input).display is True
                assert pane.query_one(f"#{sel_id}", Select).display is False
            for banner_id in _VAULT_BANNER_IDS:
                assert pane.query_one(f"#{banner_id}", Static).display is False

            pane.query_one("#set-secret-provider", Select).value = "hashicorp_vault"
            await pilot.pause()

            for _key, inp_id, sel_id in _SECRET_MANAGED_VAULT_FIELDS:
                assert pane.query_one(f"#{inp_id}", Input).display is False
                assert pane.query_one(f"#{sel_id}", Select).display is True
            for banner_id in _VAULT_BANNER_IDS:
                assert pane.query_one(f"#{banner_id}", Static).display is True

            # Non-secret inputs stay visible
            for non_secret_id in ("#set-rf-base-url", "#set-splunk-host", "#set-s1-console-url"):
                assert pane.query_one(non_secret_id, Input).display is True

    asyncio.run(_run())


def test_tui_settings_test_refresh_and_pull_workers_with_mock_provider(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
    )

    with _LocalVaultStub() as vault:
        async def _run() -> None:
            async with app.run_test(size=(130, 40)) as pilot:
                await pilot.pause()
                pane = app.query_one(SettingsPane)
                pane.query_one("#settings-category-switcher", ContentSwitcher).current = "cat-secrets"
                pane.query_one("#set-secret-provider", Select).value = "hashicorp_vault"
                pane.query_one("#set-vault-addr", Input).value = vault.base_url
                pane.query_one("#set-vault-token", Input).value = vault.expected_token
                await pilot.pause()

                # 1. Test Secret Manager with unsaved draft values
                pane.query_one("#settings-test-secrets-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert "Secret Manager OK" in str(pane.query_one("#settings-status", Static).render())
                assert not isolated_settings_env.exists()

                # 2. Refresh Vault Catalog without touching disk
                pane.query_one("#settings-refresh-vault-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert not isolated_settings_env.exists()

                rf_sel = pane.query_one("#set-rf-api-token-vault", Select)
                option_vals = [str(opt[1]) for opt in getattr(rf_sel, "_options", [])]
                assert "hashicorp_vault:soclens/rf:api_token" in option_vals
                assert "hashicorp_vault:soclens/s1:api_token" in option_vals
                assert "hashicorp_vault:soclens/llm:api_key" in option_vals

                # 3. Map tokens & Pull Secrets into Session memory only
                rf_sel.value = "hashicorp_vault:soclens/rf:api_token"
                pane.query_one("#set-s1-api-token-vault", Select).value = "hashicorp_vault:soclens/s1:api_token"
                pane.query_one("#set-rf-llm-api-key-vault", Select).value = "hashicorp_vault:soclens/llm:api_key"
                await pilot.pause()

                pane.query_one("#settings-pull-secrets-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert not isolated_settings_env.exists()
                assert get_effective_setting("rf_api_token") == "vault-rf-tok-secret-9001"
                assert get_effective_setting("s1_api_token") == "vault-s1-tok-secret-9002"
                assert get_local_llm_config(provider="openai").api_key == "vault-llm-key-secret-9003"

                # Hidden Inputs must not receive pulled secrets, and summary must mask secrets
                assert pane.query_one("#set-rf-api-token", Input).value == ""
                assert pane.query_one("#set-rf-llm-api-key", Input).value == ""
                summary_text = str(pane.query_one("#settings-secrets-summary", Static).render())
                assert "vault-rf-tok-secret-9001" not in summary_text
                assert "vault-llm-key-secret-9003" not in summary_text

        asyncio.run(_run())


def test_tui_settings_save_persists_only_vault_map_and_hydrates_memory(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    save_profile_settings({"rf_api_token": "legacy-plaintext-rf-token"})
    save_profile_settings({"rf_base_url": "https://rf.lab.test"}, profile="lab")
    app = create_app(
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
    )

    with _LocalVaultStub() as vault:
        async def _run() -> None:
            async with app.run_test(size=(130, 40)) as pilot:
                await pilot.pause()
                pane = app.query_one(SettingsPane)
                pane.query_one("#settings-category-switcher", ContentSwitcher).current = "cat-secrets"
                pane.query_one("#set-secret-provider", Select).value = "hashicorp_vault"
                pane.query_one("#set-vault-addr", Input).value = vault.base_url
                pane.query_one("#set-vault-token", Input).value = vault.expected_token
                await pilot.pause()

                pane.query_one("#settings-refresh-vault-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                pane.query_one("#set-rf-api-token-vault", Select).value = "hashicorp_vault:soclens/rf:api_token"
                pane.query_one("#set-s1-api-token-vault", Select).value = "hashicorp_vault:soclens/s1:api_token"
                pane.query_one("#set-rf-llm-api-key-vault", Select).value = "hashicorp_vault:soclens/llm:api_key"
                await pilot.pause()

                await pilot.click("#settings-save-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                raw_disk = isolated_settings_env.read_text(encoding="utf-8")
                assert "legacy-plaintext-rf-token" not in raw_disk
                assert "vault-rf-tok-secret-9001" not in raw_disk
                assert "vault-s1-tok-secret-9002" not in raw_disk
                assert "vault-llm-key-secret-9003" not in raw_disk
                assert stat.S_IMODE(isolated_settings_env.stat().st_mode) == 0o600

                saved = get_profile_settings()
                assert "rf_api_token" not in saved
                saved_map = parse_vault_secret_map(saved["vault_secret_map"])
                assert saved_map["rf_api_token"] == "hashicorp_vault:soclens/rf:api_token"
                assert saved_map["rf_llm_api_key"] == "hashicorp_vault:soclens/llm:api_key"

                assert app.client.api_token == "vault-rf-tok-secret-9001"
                assert get_local_llm_config(provider="openai").api_key == "vault-llm-key-secret-9003"

                # Switching profiles clears cached catalog entries
                assert len(pane._catalog_entries) > 0
                pane.query_one("#set-profile-select", Select).value = "lab"
                pane.query_one("#settings-switch-profile-btn", Button).press()
                await pilot.pause()
                assert pane._catalog_entries == []

        asyncio.run(_run())


def test_tui_settings_offline_saved_ref_fallback_and_80x24_layout(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    saved_ref = "hashicorp_vault:soclens/offline_rf:api_token"
    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": "http://127.0.0.1:9",
            "vault_token": "stub-vault-token",
            "vault_secret_map": serialize_vault_secret_map({"rf_api_token": saved_ref}),
        }
    )

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            pane = app.query_one(SettingsPane)
            rf_vault_sel = pane.query_one("#set-rf-api-token-vault", Select)
            assert rf_vault_sel.display is True
            assert rf_vault_sel.value == saved_ref
            labels = [str(opt[0]) for opt in getattr(rf_vault_sel, "_options", [])]
            assert any("Saved" in lbl for lbl in labels)
            assert rf_vault_sel.region.width > 0 and rf_vault_sel.region.height > 0

            pane.query_one("#settings-category-switcher", ContentSwitcher).current = "cat-secrets"
            await pilot.pause()
            prov_sel = pane.query_one("#set-secret-provider", Select)
            assert prov_sel.region.width > 0 and prov_sel.region.height > 0

            for provider, gid in (
                ("secret_server", "#tss-fields-group"),
                ("hashicorp_vault", "#vault-fields-group"),
                ("onepassword_connect", "#op-fields-group"),
                ("bitwarden", "#bw-fields-group"),
                ("akeyless", "#akeyless-fields-group"),
            ):
                prov_sel.value = provider
                await pilot.pause()
                grp = pane.query_one(gid)
                assert grp.display is True
                assert grp.region.width > 0 and grp.region.height > 0

    asyncio.run(_run())


def test_tui_llm_copilot_accept_pivot_attaches_ready_to_send_without_auto_send(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    mock_llm = MagicMock(spec=LocalLLMClient)
    mock_llm.__enter__.return_value = mock_llm
    mock_llm.__exit__.return_value = None

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with patch("soclens.tui.screens.llm.LocalLLMClient", return_value=mock_llm):
            async with app.run_test(size=(120, 36)) as pilot:
                await pilot.pause()
                llm_pane = app.query_one(LocalLLMPane)
                payload = PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-llm",
                    tenant_id="1001",
                    hostname="wkstn-1001-01.example.test",
                    es_finding={"event_id": "fnd-1", "rule_title": "Encoded PS"},
                    s1_threat={"id": "thr-1", "threatName": "Mimikatz"},
                    rf_enrichment={"rf_max_risk_score": 92},
                )
                llm_pane.accept_pivot(payload)
                await pilot.pause()

                badge = llm_pane.query_one("#llm-context-badge", Static)
                assert badge.display is True
                assert "Tenant 1001" in str(badge.render())
                assert llm_pane.query_one("#llm-template-select", Select).value == "summarize_attack_chain"

                transcript = "\n".join(
                    line.text for line in llm_pane.query_one("#llm-transcript", RichLog).lines
                )
                assert "[CONTEXT ATTACHED]" in transcript
                assert mock_llm.analyze_with_template.call_count == 0
                assert mock_llm.chat.call_count == 0

    asyncio.run(_run())


def test_tui_llm_copilot_quick_action_buttons_and_80x24_layout(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    mock_llm = MagicMock(spec=LocalLLMClient)
    mock_llm.__enter__.return_value = mock_llm
    mock_llm.__exit__.return_value = None
    mock_llm.analyze_with_template.side_effect = [
        {
            "content": "Attack Chain: Encoded PS -> LSASS access (Tenant 1001).",
            "model": "llama3.2",
            "provider": "ollama",
            "done": True,
            "raw": {},
        },
        {
            "content": "Closing Note: Contained wkstn-1001-01; escalated to Tier-2.",
            "model": "llama3.2",
            "provider": "ollama",
            "done": True,
            "raw": {},
        },
    ]

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        with (
            patch("soclens.tui.screens.llm.LocalLLMClient", return_value=mock_llm),
            patch.object(LocalLLMPane, "copy_to_clipboard", return_value=True) as mock_copy,
        ):
            async with app.run_test(size=(80, 24)) as pilot:
                await pilot.pause()
                llm_pane = app.query_one(LocalLLMPane)
                assert llm_pane.has_class("llm-compact")

                llm_pane.query_one("#llm-model-input", Input).value = "llama3.2"
                llm_pane.accept_pivot(
                    PivotPayload(
                        source_tab="tab-splunk-es",
                        target_tab="tab-llm",
                        tenant_id="1001",
                        hostname="wkstn-1001-01.example.test",
                        es_finding={"event_id": "fnd-1"},
                        s1_threat={"id": "thr-1"},
                        rf_enrichment={"rf_max_risk_score": 92},
                    )
                )
                await pilot.pause()

                for widget_id in (
                    "#llm-attack-chain-btn",
                    "#llm-closing-note-btn",
                    "#llm-copy-reply-btn",
                    "#llm-clear-context-btn",
                    "#llm-context-badge",
                    "#llm-transcript",
                    "#llm-prompt",
                ):
                    w = llm_pane.query_one(widget_id)
                    assert w.region.width > 0 and w.region.height > 0
                    assert w.region.right <= 80
                    assert w.region.bottom <= 24

                llm_pane.query_one("#llm-attack-chain-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                llm_pane.query_one("#llm-closing-note-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert mock_llm.analyze_with_template.call_count == 2
                first_call = mock_llm.analyze_with_template.call_args_list[0].args
                second_call = mock_llm.analyze_with_template.call_args_list[1].args
                assert first_call[0] == "summarize_attack_chain"
                assert "fnd-1" in first_call[1]
                assert "thr-1" in first_call[1]
                assert second_call[0] == "draft_closing_note"

                llm_pane.query_one("#llm-copy-reply-btn", Button).press()
                await pilot.pause()
                assert mock_copy.call_count == 1
                assert "Closing Note:" in mock_copy.call_args.args[0]

                llm_pane.query_one("#llm-clear-context-btn", Button).press()
                await pilot.pause()
                assert llm_pane.query_one("#llm-context-badge", Static).display is False
                transcript = "\n".join(
                    line.text for line in llm_pane.query_one("#llm-transcript", RichLog).lines
                )
                assert "Closing Note:" in transcript

    asyncio.run(_run())


def test_tui_llm_settings_hydration_and_rf_llm_api_key_flow(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    set_session_overrides({"rf_llm_api_key": "vault-llm-key-002"}, vault_hydrated=True)
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            llm_pane = app.query_one(LocalLLMPane)
            with llm_pane._build_client() as client:
                assert isinstance(client.session, ConfiguredSession)
                assert client.config.api_key == "vault-llm-key-002"

    asyncio.run(_run())


def test_tui_settings_vault_save_clears_hidden_plaintext_prevents_resurrection(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    save_profile_settings(
        {
            "rf_api_token": "legacy-plaintext-zombie",
            "rf_llm_api_key": "legacy-plaintext-llm",
        }
    )
    app = create_app(
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
    )

    with _LocalVaultStub() as vault:
        async def _run() -> None:
            async with app.run_test(size=(130, 40)) as pilot:
                await pilot.pause()
                pane = app.query_one(SettingsPane)
                assert pane.query_one("#set-rf-api-token", Input).value == "legacy-plaintext-zombie"

                pane.query_one("#settings-category-switcher", ContentSwitcher).current = "cat-secrets"
                pane.query_one("#set-secret-provider", Select).value = "hashicorp_vault"
                pane.query_one("#set-vault-addr", Input).value = vault.base_url
                pane.query_one("#set-vault-token", Input).value = vault.expected_token
                await pilot.pause()

                pane.query_one("#settings-refresh-vault-btn", Button).press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                pane.query_one("#set-rf-api-token-vault", Select).value = "hashicorp_vault:soclens/rf:api_token"
                pane.query_one("#set-rf-llm-api-key-vault", Select).value = "hashicorp_vault:soclens/llm:api_key"
                await pilot.pause()

                await pilot.click("#settings-save-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert "rf_api_token" not in get_profile_settings()
                assert "rf_llm_api_key" not in get_profile_settings()
                assert pane.query_one("#set-rf-api-token", Input).value == ""
                assert pane.query_one("#set-rf-llm-api-key", Input).value == ""

                # Switching back to 'none' and saving must NOT resurrect legacy plaintext
                pane.query_one("#set-secret-provider", Select).value = "none"
                await pilot.pause()
                await pilot.click("#settings-save-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                saved_after_disable = get_profile_settings()
                assert "rf_api_token" not in saved_after_disable
                assert "rf_llm_api_key" not in saved_after_disable
                raw_disk = isolated_settings_env.read_text(encoding="utf-8")
                assert "legacy-plaintext-zombie" not in raw_disk
                assert "legacy-plaintext-llm" not in raw_disk

        asyncio.run(_run())


def test_tui_settings_disable_secret_provider_clears_vault_hydrated_session_overrides(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    with _LocalVaultStub() as vault:
        save_profile_settings(
            {
                "secret_provider": "hashicorp_vault",
                "vault_addr": vault.base_url,
                "vault_token": vault.expected_token,
                "vault_secret_map": serialize_vault_secret_map(
                    {
                        "rf_api_token": "hashicorp_vault:soclens/rf:api_token",
                        "rf_llm_api_key": "hashicorp_vault:soclens/llm:api_key",
                    }
                ),
            }
        )
        app = create_app(
            dry_run=True,
            initial_tab="tab-settings",
            workspace_dir=tmp_path,
        )

        async def _run() -> None:
            async with app.run_test(size=(130, 40)) as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert is_vault_hydrated_setting("rf_api_token") is True
                assert get_effective_setting("rf_api_token") == "vault-rf-tok-secret-9001"
                assert app.client.api_token == "vault-rf-tok-secret-9001"
                assert is_vault_hydrated_setting("rf_llm_api_key") is True

                pane = app.query_one(SettingsPane)
                pane.query_one("#settings-category-switcher", ContentSwitcher).current = "cat-secrets"
                prov_sel = pane.query_one("#set-secret-provider", Select)
                prov_sel.value = "secret_server"
                await pilot.pause()
                summary_switched = str(pane.query_one("#settings-secrets-summary", Static).render())
                assert "Mapped Keys (0): None" in summary_switched

                prov_sel.value = "none"
                await pilot.pause()
                await pilot.click("#settings-save-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert is_vault_hydrated_setting("rf_api_token") is False
                assert get_effective_setting("rf_api_token") is None
                assert app.client.api_token is None
                assert is_vault_hydrated_setting("rf_llm_api_key") is False
                assert get_effective_setting("rf_llm_api_key") is None

        asyncio.run(_run())


def test_tui_settings_80x24_cat_secrets_form_pane_and_buttons_clickable(
    tmp_path: Path,
    isolated_settings_env: Path,
) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
    )

    with _LocalVaultStub() as vault:
        async def _run() -> None:
            async with app.run_test(size=(80, 24)) as pilot:
                await pilot.pause()
                pane = app.query_one(SettingsPane)
                assert pane.has_class("settings-compact")

                cat_list = pane.query_one("#settings-category-list", OptionList)
                cat_list.highlighted = 6
                await pilot.pause()

                form_pane = pane.query_one("#settings-form-pane")
                assert form_pane.region.y < 24
                assert form_pane.region.height >= 6

                for widget_id in (
                    "#set-secret-provider",
                    "#settings-test-secrets-btn",
                    "#settings-refresh-vault-btn",
                    "#settings-pull-secrets-btn",
                ):
                    widget = pane.query_one(widget_id)
                    assert widget.region.y >= 0
                    assert widget.region.bottom <= 24

                pane.query_one("#set-secret-provider", Select).value = "hashicorp_vault"
                pane.query_one("#set-vault-addr", Input).value = vault.base_url
                pane.query_one("#set-vault-token", Input).value = vault.expected_token
                await pilot.pause()

                await pilot.click("#settings-refresh-vault-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert "Loaded 3 secret catalog" in str(
                    pane.query_one("#settings-status", Static).render()
                )

        asyncio.run(_run())
