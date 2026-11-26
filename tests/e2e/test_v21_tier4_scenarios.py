"""Tier 4 real-world SOC analyst & admin end-to-end scenario tests for SOCLens v2.1."""

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

from tests.e2e import v21_mocks
from tests.e2e.v21_mocks import (
    MockBitwardenServer,
    MockHashiCorpVaultServer,
    MockLocalLLMServer,
    MockOnePasswordConnectServer,
    MockSecretServer,
    MockSentinelOneServer,
    MockSplunkESServer,
)

if TYPE_CHECKING:
    from tests.e2e.conftest import MockRFServer

v21_workspace = v21_mocks.v21_workspace
mock_secret_server = v21_mocks.mock_secret_server
mock_vault_server = v21_mocks.mock_vault_server
mock_op_connect_server = v21_mocks.mock_op_connect_server
mock_bitwarden_server = v21_mocks.mock_bitwarden_server
mock_splunk_es_server = v21_mocks.mock_splunk_es_server
mock_s1_server = v21_mocks.mock_s1_server
mock_llm_server = v21_mocks.mock_llm_server

pytestmark = [pytest.mark.e2e, pytest.mark.tier4]

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _settings_path() -> Path:
    return Path(os.environ["SOCLENS_SETTINGS_FILE"])


def _load_fixture_json(filename: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / filename).read_text(encoding="utf-8"))


def _assert_settings_0600_and_secret_free(forbidden_tokens: list[str]) -> None:
    path = _settings_path()
    assert path.is_file(), f"Expected settings.json at {path}"
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"Expected 0600 permissions on {path}, got {oct(mode)}"
    raw = path.read_text(encoding="utf-8")
    for token in forbidden_tokens:
        assert token not in raw, f"Pulled service secret {token!r} leaked into settings.json"


def _is_actually_visible(widget: Any) -> bool:
    from textual.widget import Widget

    for anc in widget.ancestors_with_self:
        if isinstance(anc, Widget) and not anc.display:
            return False
    return True


def _select_table_row_containing(
    table: Any,
    rows: list[dict[str, Any]],
    needle: str,
) -> int:
    for idx, row in enumerate(rows):
        if needle in json.dumps(row, default=str):
            table.move_cursor(row=idx)
            return idx
    raise AssertionError(f"Could not find row matching {needle!r} in {len(rows)} rows")


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
# Scenario 1: Vault-Hydrated Analyst Morning Shift
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("V21-F2")
@pytest.mark.feature("V21-F4")
@pytest.mark.feature("V21-F6")
@pytest.mark.feature("V21-F7")
@pytest.mark.feature("V21-F8")
@pytest.mark.feature("V21-F13")
@pytest.mark.feature("V21-F14")
def test_t4_v21_01_vault_hydrated_analyst_morning_shift(
    mock_vault_server: MockHashiCorpVaultServer,
    mock_splunk_es_server: MockSplunkESServer,
    mock_s1_server: MockSentinelOneServer,
    mock_llm_server: MockLocalLLMServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, Input, Static, TabbedContent, TextArea

    from soclens.settings import save_profile_settings, serialize_vault_secret_map
    from soclens.tui.app import create_app
    from soclens.tui.screens.base import DoubleClickDataTable
    from soclens.tui.screens.es_modals import ESNoteModal
    from soclens.tui.screens.sentinelone import SentinelOnePane
    from soclens.tui.screens.splunk_es import SplunkESPane

    fixtures = _load_fixture_json("v21_secret_stores.json")
    rec_map = fixtures["hashicorp_vault"]["recommended_map"]

    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": mock_vault_server.base_url,
            "vault_auth_mode": "token",
            "vault_token": "e2e-vault-token-001",
            "vault_kv_mount": "secret",
            "vault_secret_map": serialize_vault_secret_map(rec_map),
            "splunk_host": mock_splunk_es_server.base_url,
            "splunk_verify_ssl": "false",
            "s1_console_url": mock_s1_server.base_url,
            "s1_verify_ssl": "false",
            "rf_llm_provider": "openai",
            "rf_llm_base_url": mock_llm_server.openai_base_url,
            "rf_llm_model": "qwen2.5-coder:7b",
        }
    )

    for env_key in (
        "RF_API_TOKEN",
        "RECORDED_FUTURE_API_KEY",
        "SPLUNK_TOKEN",
        "S1_API_TOKEN",
        "SENTINELONE_API_TOKEN",
        "RF_LLM_API_KEY",
    ):
        monkeypatch.delenv(env_key, raising=False)
    monkeypatch.setenv("RF_LLM_PROVIDER", "openai")
    monkeypatch.setenv("RF_LLM_BASE_URL", mock_llm_server.openai_base_url)
    monkeypatch.setenv("RF_LLM_MODEL", "qwen2.5-coder:7b")

    mock_rf_server.valid_rf_tokens.add("e2e-vault-rf-api-token")
    mock_splunk_es_server.valid_tokens.add("e2e-vault-splunk-token")
    mock_s1_server.valid_tokens.add("e2e-vault-s1-api-token")
    mock_llm_server.set_required_api_key("e2e-vault-llm-api-key")

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-splunk-es",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert callable(getattr(app, "dispatch_pivot", None)), (
                "SocLensApp.dispatch_pivot must be implemented in M4"
            )
            assert any(
                "/v1/secret/data/" in r["path"] for r in mock_vault_server.requests_log
            ), "Startup secret hydration worker did not pull mapped secrets from Vault"

            es_pane = app.query_one(SplunkESPane)
            es_pane.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            es_pane.query_one("#es-search-input", Input).value = "tenant_id:1001"
            await pilot.pause()
            table = es_pane.query_one("#es-table", DoubleClickDataTable)
            _select_table_row_containing(table, es_pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()

            es_pane.query_one("#es-private-ips-cb", Checkbox).value = True
            await pilot.pause()
            await pilot.click("#es-enrich-selected-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["headers"].get("X-RFToken") == "e2e-vault-rf-api-token"
                for r in mock_rf_server.requests_log
            )

            _select_table_row_containing(table, es_pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()
            await pilot.click("#es-insp-pivot-s1-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-sentinelone"
            s1_pane = app.query_one(SentinelOnePane)
            assert any(
                "wkstn-1001-01" in json.dumps(r, default=str)
                for r in s1_pane._records
            )

            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1_table = s1_pane.query_one("#s1-table", DoubleClickDataTable)
            _select_table_row_containing(s1_table, s1_pane._table_rows, "thr-1001-2")
            await pilot.pause()

            await pilot.click("#s1-pivot-llm-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert tabs.active == "tab-llm"
            assert app.query_one("#llm-context-badge", Static).display is True

            await pilot.click("#llm-send-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["path"] == "/v1/chat/completions"
                and r["headers"].get("Authorization") == "Bearer e2e-vault-llm-api-key"
                for r in mock_llm_server.requests_log
            )

            tabs.active = "tab-splunk-es"
            await pilot.pause()
            _select_table_row_containing(table, es_pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()

            await pilot.click("#es-insp-add-note-btn")
            await pilot.pause()
            assert isinstance(app.screen, ESNoteModal)
            app.screen.query_one("#es-note-title-input", Input).value = "Morning Shift Closure"
            app.screen.query_one("#es-note-text", TextArea).load_text(
                "Correlated LSASS dump + S1 threat; closing note drafted via LLM."
            )
            app.screen.query_one("#es-note-dual-rf-cb", Checkbox).value = True
            await pilot.click("#es-note-submit-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            note_posts = [
                r
                for r in mock_splunk_es_server.requests_log
                if r["method"] == "POST" and "/notes" in r["path"]
            ]
            assert len(note_posts) >= 2

    asyncio.run(_run())
    _assert_settings_0600_and_secret_free(
        [
            "e2e-vault-rf-api-token",
            "e2e-vault-splunk-token",
            "e2e-vault-s1-api-token",
            "e2e-vault-llm-api-key",
        ]
    )


# ==============================================================================
# Scenario 2: Secret Server PAM Onboarding via TUI Settings & CLI
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("V21-F1")
@pytest.mark.feature("V21-F4")
@pytest.mark.feature("V21-F5")
def test_t4_v21_02_secret_server_pam_onboarding_via_tui_and_cli(
    mock_secret_server: MockSecretServer,
    mock_s1_server: MockSentinelOneServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import ContentSwitcher, Input, OptionList, Select

    from soclens.settings import save_profile_settings
    from soclens.tui.app import create_app

    save_profile_settings(
        {
            "s1_console_url": mock_s1_server.base_url,
            "s1_verify_ssl": "false",
        }
    )
    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("S1_API_TOKEN", raising=False)

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-settings",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            cat_list = app.query_one("#settings-category-list", OptionList)
            cat_list.highlighted = cat_list.get_option_index("cat-secrets")
            cat_list.action_select()
            await pilot.pause()

            assert app.query_one("#settings-category-switcher", ContentSwitcher).current == "cat-secrets"
            app.query_one("#set-secret-provider", Select).value = "secret_server"
            await pilot.pause()

            app.query_one("#set-tss-base-url", Input).value = mock_secret_server.base_url
            app.query_one("#set-tss-auth-mode", Select).value = "password"
            app.query_one("#set-tss-username", Input).value = "e2e-tss-user"
            pw_inp = app.query_one("#set-tss-password", Input)
            assert pw_inp.password is True
            pw_inp.value = "e2e-tss-password"

            test_btn = _find_button_by_id_or_label(
                app,
                (
                    "settings-test-secrets-btn",
                    "settings-secrets-test-btn",
                    "secrets-test-btn",
                ),
                ("test secret manager", "test secret"),
            )
            await pilot.click(f"#{test_btn.id}")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(r["path"] == "/oauth2/token" for r in mock_secret_server.requests_log)

            refresh_btn = _find_button_by_id_or_label(
                app,
                (
                    "settings-refresh-vault-btn",
                    "settings-refresh-catalog-btn",
                    "settings-secrets-refresh-btn",
                    "secrets-refresh-catalog-btn",
                ),
                ("refresh vault catalog", "refresh catalog"),
            )
            await pilot.click(f"#{refresh_btn.id}")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            cat_list.highlighted = cat_list.get_option_index("cat-rf")
            cat_list.action_select()
            await pilot.pause()
            assert app.query_one("#set-rf-api-token", Input).display is False
            rf_sel = app.query_one("#set-rf-api-token-vault", Select)
            assert rf_sel.display is True
            rf_sel.value = "secret_server:1001:rf-api-token"

            cat_list.highlighted = cat_list.get_option_index("cat-splunk")
            cat_list.action_select()
            await pilot.pause()
            assert app.query_one("#set-splunk-token", Input).display is False
            sp_sel = app.query_one("#set-splunk-token-vault", Select)
            assert sp_sel.display is True
            sp_sel.value = "secret_server:1002:splunk-token"

            cat_list.highlighted = cat_list.get_option_index("cat-s1")
            cat_list.action_select()
            await pilot.pause()
            assert app.query_one("#set-s1-api-token", Input).display is False
            s1_sel = app.query_one("#set-s1-api-token-vault", Select)
            assert s1_sel.display is True
            s1_sel.value = "secret_server:1003:s1-api-token"

            await pilot.click("#settings-save-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

    asyncio.run(_run())
    _assert_settings_0600_and_secret_free(
        ["e2e-tss-rf-api-token", "e2e-tss-splunk-token", "e2e-tss-s1-api-token"]
    )

    mock_s1_server.valid_tokens.add("e2e-tss-s1-api-token")
    pull_proc = run_cli(["secrets", "pull", "--json"])
    assert pull_proc.returncode == 0, pull_proc.stderr + pull_proc.stdout
    s1_proc = run_cli(["s1", "status", "--json"])
    assert s1_proc.returncode == 0, s1_proc.stderr + s1_proc.stdout
    assert any(
        r["headers"].get("Authorization") == "ApiToken e2e-tss-s1-api-token"
        for r in mock_s1_server.requests_log
    )


# ==============================================================================
# Scenario 3: ES 7.x Legacy Fallback & Custom Tenant Rollup Workflow
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("V21-F6")
@pytest.mark.feature("V21-F7")
@pytest.mark.feature("V21-F8")
def test_t4_v21_03_es_7x_legacy_fallback_tenant_rollup_and_bulk_triage(
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, Input, RichLog, Select

    from soclens.settings import invalidate_settings_cache, save_profile_settings
    from soclens.tui.app import create_app
    from soclens.tui.screens.base import DoubleClickDataTable, extract_richlog_text
    from soclens.tui.screens.es_modals import ESAdaptiveResponseModal, ESBulkTriageModal
    from soclens.tui.screens.splunk_es import SplunkESPane

    mock_splunk_es_server.set_mc_v2_enabled(False)
    mock_splunk_es_server.set_incident_review_404_fallback(True)
    save_profile_settings(
        {
            "splunk_host": mock_splunk_es_server.base_url,
            "splunk_verify_ssl": "false",
            "splunk_es_custom_fields": "snow_ticket,case_id",
        }
    )
    invalidate_settings_cache()

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-splunk-es",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            pane = app.query_one(SplunkESPane)
            pane.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert pane._source_backend == "spl_fallback"
            assert any(
                "conf-log_review/incident_review" in r["path"]
                for r in mock_splunk_es_server.requests_log
            )
            assert any(
                r["method"] == "POST"
                and r["path"].endswith("/search/jobs")
                and "`notable`" in " ".join(r["form"].get("search", []))
                for r in mock_splunk_es_server.requests_log
            )

            await pilot.click("#es-group-tenant-btn")
            await pilot.pause()
            group_rows = [r for r in pane._displayed_rows if r.get("_is_group_row")]
            by_tenant = {str(r["_group_tenant"]): str(r["title"]) for r in group_rows}
            assert "1001" in by_tenant and "4 finding(s)" in by_tenant["1001"]
            assert "1002" in by_tenant and "1 finding(s)" in by_tenant["1002"]
            assert "2001" in by_tenant and "2 finding(s)" in by_tenant["2001"]

            await pilot.click("#es-group-tenant-btn")
            await pilot.pause()

            table = pane.query_one("#es-table", DoubleClickDataTable)
            table.focus()
            for target_eid in ("fnd-1001-a", "fnd-1001-b"):
                _select_table_row_containing(table, pane._displayed_rows, target_eid)
                await pilot.pause()
                await pilot.press("space")
                await pilot.pause()
            assert {"fnd-1001-a", "fnd-1001-b"}.issubset(pane._selected_ids)

            await pilot.click("#es-bulk-triage-btn")
            await pilot.pause()
            assert isinstance(app.screen, ESBulkTriageModal)
            app.screen.query_one("#es-bulk-status-select", Select).value = "Resolved"
            app.screen.query_one("#es-bulk-owner-input", Input).value = "soc_analyst"
            app.screen.query_one("#es-bulk-note-input", Input).value = "7.x fallback bulk triage"
            await pilot.click("#es-bulk-apply-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            # Drain chained post-mutation handle_refresh -> _load_notables_worker (splunk_es.py:2097)
            await app.workers.wait_for_complete()
            await pilot.pause()

            notable_updates = [
                r
                for r in mock_splunk_es_server.requests_log
                if r["method"] == "POST" and r["path"] == "/services/notable_update"
            ]
            assert notable_updates
            rule_ids = notable_updates[-1]["form"].get("ruleUIDs", [])
            assert "fnd-1001-a" in rule_ids and "fnd-1001-b" in rule_ids

            _select_table_row_containing(table, pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()
            await pilot.click("#es-insp-tab-metadata")
            await pilot.pause()
            meta_txt = extract_richlog_text(pane.query_one("#es-detail", RichLog))
            assert "snow_ticket" in meta_txt and "INC0010011" in meta_txt

            await pilot.click("#es-insp-ar-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert isinstance(app.screen, ESAdaptiveResponseModal)
            app.screen.query_one("#es-ar-action-select", Select).value = "ping"
            app.screen.query_one("#es-ar-params-input", Input).value = "dest=203.0.113.45"
            await pilot.click("#es-ar-dispatch-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["method"] == "POST"
                and r["path"] == "/services/alerts/modaction_adhoc"
                and r["form"].get("action_name") == ["ping"]
                for r in mock_splunk_es_server.requests_log
            )

    asyncio.run(_run())


# ==============================================================================
# Scenario 4: S1 MDR Tenant Onboarding, Policy Copy & Exclusion Cloning
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("V21-F9")
@pytest.mark.feature("V21-F11")
@pytest.mark.feature("V21-F12")
def test_t4_v21_04_s1_mdr_tenant_onboarding_policy_copy_and_exclusion_cloning(
    mock_s1_server: MockSentinelOneServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Input, Select, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.s1_modals import CloneExclusionsModal, S1SiteModal, S1UserModal

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-sentinelone",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            await pilot.press("f2")
            await pilot.pause()
            assert app.is_admin_view is True

            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-site-create-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1SiteModal)
            app.screen.query_one("#s1-site-name-input", Input).value = "MDR-1003"
            app.screen.query_one("#s1-site-account-input", Input).value = "acc-100"
            app.screen.query_one("#s1-site-copy-policy-select", Select).value = "100101"
            await pilot.click("#s1-site-save-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert any(
                r["method"] == "POST"
                and r["path"] == "/web/api/v2.1/sites"
                and (r["json_body"] or {}).get("data", {}).get("name") == "MDR-1003"
                for r in mock_s1_server.requests_log
            )

            await pilot.click("#s1-wb-exclusions-btn")
            await pilot.pause()
            await pilot.click("#s1-clone-excl-btn")
            await pilot.pause()
            assert isinstance(app.screen, CloneExclusionsModal)
            app.screen.query_one("#s1-clone-src-select", Select).value = "100101"
            app.screen.query_one("#s1-clone-dst-select", Select).value = "100102"
            await pilot.click("#s1-clone-preview-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            summary_txt = str(app.screen.query_one("#s1-clone-summary", Static).render())
            assert "Will Create: 2" in summary_txt
            assert "Skipped Duplicate: 1" in summary_txt
            assert "Inherited from Account: 1" in summary_txt

            mock_s1_server.requests_log.clear()
            await pilot.click("#s1-clone-apply-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            excl_posts = [
                r
                for r in mock_s1_server.requests_log
                if r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
            ]
            assert len(excl_posts) == 2
            for req in excl_posts:
                desc = str((req["json_body"] or {}).get("data", {}).get("description") or "")
                assert "[Cloned from MDR-1001]" in desc
                assert len(desc) <= 500

            await pilot.click("#s1-wb-users-btn")
            await pilot.pause()
            await pilot.click("#s1-users-load-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-user-create-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1UserModal)
            app.screen.query_one("#s1-user-name-input", Input).value = "Dan MDR"
            app.screen.query_one("#s1-user-email-input", Input).value = "dan.mdr@example.test"
            app.screen.query_one("#s1-user-template-select", Select).value = "usr-mdr-lead"
            app.screen.query_one("#s1-user-tier-select", Select).value = "tier:MDR"
            await pilot.click("#s1-user-save-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            user_posts = [
                r
                for r in mock_s1_server.requests_log
                if r["method"] == "POST" and r["path"] == "/web/api/v2.1/users"
            ]
            assert user_posts
            assert user_posts[-1]["json_body"]["data"]["email"] == "dan.mdr@example.test"

    asyncio.run(_run())

    cli_site = run_cli(
        [
            "--admin",
            "s1",
            "sites",
            "create",
            "--yes",
            "--name",
            "MDR-1004",
            "--account-id",
            "acc-100",
            "--copy-policy-from",
            "100101",
            "--json",
        ]
    )
    assert cli_site.returncode == 0, cli_site.stderr + cli_site.stdout
    cli_clone = run_cli(
        [
            "--admin",
            "s1",
            "exclusions",
            "clone",
            "--yes",
            "--from-site",
            "100101",
            "--to-site",
            "100102",
            "--json",
        ]
    )
    assert cli_clone.returncode == 0, cli_clone.stderr + cli_clone.stdout


# ==============================================================================
# Scenario 5: Multi-Tenant S1 Alert Grouping & Decommission Guardrail
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("V21-F9")
@pytest.mark.feature("V21-F10")
@pytest.mark.feature("V21-F11")
@pytest.mark.feature("V21-F12")
def test_t4_v21_05_s1_multi_tenant_tier_hash_isolation_and_delete_site_gate(
    mock_s1_server: MockSentinelOneServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Input, Select, Static

    from soclens.tui.app import create_app
    from soclens.tui.modals import ConfirmActionModal, S1ThreatTriageModal
    from soclens.tui.screens.base import DoubleClickDataTable
    from soclens.tui.screens.s1_modals import ConfirmDeleteSiteModal
    from soclens.tui.screens.sentinelone import SentinelOnePane

    shared_sha1 = "a" * 40

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-sentinelone",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            assert app.is_admin_view is False

            await pilot.click("#s1-wb-agents-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            mock_s1_server.requests_log.clear()

            await pilot.click("#s1-decommission-btn")
            await pilot.pause()
            assert "Admin View" in str(pane.query_one("#s1-status", Static).render())

            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.click("#s1-site-delete-btn")
            await pilot.pause()
            assert "Admin View" in str(pane.query_one("#s1-status", Static).render())
            assert not any(
                r["method"] in {"POST", "PUT", "DELETE"}
                for r in mock_s1_server.requests_log
            )

            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            pane.query_one("#s1-alert-source-select", Select).value = "unified"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-tier-all-btn")
            await pilot.pause()

            pane.query_one("#s1-grouping-select", Select).value = "tier_hash"
            await pilot.pause()
            labels = [str(r.get("_group_label") or "") for r in pane._table_rows]
            assert f"MDR | {shared_sha1}" in labels
            assert f"MSSP | {shared_sha1}" in labels

            table = pane.query_one("#s1-table", DoubleClickDataTable)
            mdr_idx = next(
                idx
                for idx, row in enumerate(pane._table_rows)
                if row.get("_group_label") == f"MDR | {shared_sha1}"
            )
            table.move_cursor(row=mdr_idx)
            await pilot.pause()

            await pilot.click("#s1-triage-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1ThreatTriageModal)
            app.screen.query_one("#s1-triage-verdict-select", Select).value = "true_positive"
            app.screen.query_one("#s1-triage-status-select", Select).value = "in_progress"
            await pilot.click("#s1-triage-apply-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-kill-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            kill_reqs = [
                r
                for r in mock_s1_server.requests_log
                if r["method"] == "POST" and r["path"] == "/web/api/v2.1/threats/mitigate/kill"
            ]
            assert kill_reqs
            assert set(kill_reqs[-1]["json_body"]["filter"]["ids"]) == {"thr-1001-1", "thr-1002-1"}
            mssp_thr = next(t for t in mock_s1_server.state["threats"] if t["id"] == "thr-2001-1")
            assert mssp_thr["threatInfo"]["incidentStatus"] == "unresolved"

            await pilot.press("f2")
            await pilot.pause()
            assert app.is_admin_view is True

            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            _select_table_row_containing(table, pane._table_rows, "MDR-9999-Expired")
            await pilot.pause()

            await pilot.click("#s1-site-delete-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmDeleteSiteModal)
            app.screen.query_one("#s1-del-site-confirm-input", Input).value = "wrong-site"
            await pilot.click("#s1-del-site-approve-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmDeleteSiteModal)
            assert not any(
                r["method"] == "DELETE" and r["path"] == "/web/api/v2.1/sites/100999"
                for r in mock_s1_server.requests_log
            )

            app.screen.query_one("#s1-del-site-confirm-input", Input).value = "MDR-9999-Expired"
            await pilot.click("#s1-del-site-approve-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert any(
                r["method"] == "DELETE" and r["path"] == "/web/api/v2.1/sites/100999"
                for r in mock_s1_server.requests_log
            )
            assert all(s["id"] != "100999" for s in mock_s1_server.state["sites"])

    asyncio.run(_run())


# ==============================================================================
# Scenario 6: Cross-Workbench Incident Pivot & Safe F8 orig_sid Drilldown
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("V21-F8")
@pytest.mark.feature("V21-F13")
@pytest.mark.feature("V21-F14")
def test_t4_v21_06_cross_workbench_incident_pivot_and_safe_orig_sid_drilldown(
    mock_splunk_es_server: MockSplunkESServer,
    mock_s1_server: MockSentinelOneServer,
    mock_llm_server: MockLocalLLMServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, TabbedContent, TextArea

    from soclens.tui.app import create_app
    from soclens.tui.screens.base import DoubleClickDataTable
    from soclens.tui.screens.sentinelone import SentinelOnePane
    from soclens.tui.screens.splunk_es import SplunkESPane

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-splunk-es",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            assert callable(getattr(app, "dispatch_pivot", None)), (
                "SocLensApp.dispatch_pivot must be implemented in M4"
            )
            es_pane = app.query_one(SplunkESPane)
            es_pane.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            es_table = es_pane.query_one("#es-table", DoubleClickDataTable)
            tabs = app.query_one("#main-tabs", TabbedContent)

            _select_table_row_containing(es_table, es_pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()
            mock_splunk_es_server.requests_log.clear()
            await pilot.click("#es-insp-pivot-search-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert tabs.active == "tab-splunk-search"
            assert '| loadjob "1700000100.11"' in app.query_one("#splunk-search-spl", TextArea).text
            assert any(
                r["method"] == "POST" and r["path"].endswith("/search/jobs")
                for r in mock_splunk_es_server.requests_log
            )

            tabs.active = "tab-splunk-es"
            await pilot.pause()
            _select_table_row_containing(es_table, es_pane._displayed_rows, "fnd-grp-1001")
            await pilot.pause()
            mock_splunk_es_server.requests_log.clear()
            await pilot.click("#es-insp-pivot-search-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert tabs.active == "tab-splunk-search"
            assert app.query_one("#splunk-search-spl", TextArea).text.startswith("search ")
            assert not any(
                r["method"] == "POST" and r["path"].endswith("/search/jobs")
                for r in mock_splunk_es_server.requests_log
            )

            tabs.active = "tab-splunk-es"
            await pilot.pause()
            _select_table_row_containing(es_table, es_pane._displayed_rows, "fnd-1002-org")
            await pilot.pause()
            await pilot.click("#es-insp-pivot-s1-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert tabs.active == "tab-sentinelone"
            s1_pane = app.query_one(SentinelOnePane)
            assert any(
                "laptop-1002-07" in json.dumps(r, default=str)
                for r in s1_pane._records
            )

            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1_table = s1_pane.query_one("#s1-table", DoubleClickDataTable)
            _select_table_row_containing(s1_table, s1_pane._table_rows, "thr-1002-1")
            await pilot.pause()

            await pilot.click("#s1-pivot-llm-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert tabs.active == "tab-llm"
            await pilot.click("#llm-send-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(r["path"] == "/api/chat" for r in mock_llm_server.requests_log)

    asyncio.run(_run())


# ==============================================================================
# Scenario 7: 1Password / Bitwarden Multi-Store Failover & --no-secret-store CLI
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("V21-F3")
@pytest.mark.feature("V21-F4")
@pytest.mark.feature("V21-F5")
@pytest.mark.feature("V21-F12")
def test_t4_v21_07_multi_store_failover_and_no_secret_store_emergency_cli(
    mock_op_connect_server: MockOnePasswordConnectServer,
    mock_bitwarden_server: MockBitwardenServer,
    mock_s1_server: MockSentinelOneServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.settings import save_profile_settings, serialize_vault_secret_map

    fixtures = _load_fixture_json("v21_secret_stores.json")
    op_map = fixtures["onepassword_connect"]["recommended_map"]
    bw_map = fixtures["bitwarden"]["recommended_map"]

    save_profile_settings(
        {
            "secret_provider": "onepassword_connect",
            "op_connect_url": mock_op_connect_server.base_url,
            "op_connect_token": "e2e-op-connect-token-001",
            "vault_secret_map": serialize_vault_secret_map(
                {"s1_api_token": op_map["s1_api_token"]}
            ),
            "s1_console_url": mock_s1_server.base_url,
            "s1_verify_ssl": "false",
        }
    )
    save_profile_settings(
        {
            "secret_provider": "bitwarden",
            "bw_serve_url": mock_bitwarden_server.base_url,
            "vault_secret_map": serialize_vault_secret_map(
                {"s1_api_token": bw_map["s1_api_token"]}
            ),
            "s1_console_url": mock_s1_server.base_url,
            "s1_verify_ssl": "false",
        },
        profile="bw-backup",
    )

    monkeypatch.delenv("S1_API_TOKEN", raising=False)
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)
    mock_s1_server.valid_tokens.add("e2e-op-s1-api-token")
    mock_s1_server.valid_tokens.add("e2e-bw-s1-api-token")

    op_pull = run_cli(["secrets", "pull", "--json"])
    assert op_pull.returncode == 0, op_pull.stderr + op_pull.stdout
    op_status = run_cli(["s1", "status", "--json"])
    assert op_status.returncode == 0, op_status.stderr + op_status.stdout

    mock_op_connect_server.set_fault("/v1/vaults", 503)
    op_test_fail = run_cli(["secrets", "test", "--json"])
    assert op_test_fail.returncode != 0

    mock_op_connect_server.requests_log.clear()
    emergency = run_cli(
        ["--no-secret-store", "s1", "agents", "--json"],
        env={"S1_API_TOKEN": "test-s1-token"},
    )
    assert emergency.returncode == 0, emergency.stderr + emergency.stdout
    assert mock_op_connect_server.requests_log == []

    bw_pull = run_cli(
        ["secrets", "pull", "--json"],
        env={"SOCLENS_PROFILE": "bw-backup"},
    )
    assert bw_pull.returncode == 0, bw_pull.stderr + bw_pull.stdout
    bw_status = run_cli(
        ["s1", "status", "--json"],
        env={"SOCLENS_PROFILE": "bw-backup"},
    )
    assert bw_status.returncode == 0, bw_status.stderr + bw_status.stdout

    _assert_settings_0600_and_secret_free(["e2e-op-s1-api-token", "e2e-bw-s1-api-token"])


# ==============================================================================
# Scenario 8: Responsive 80x24 Cross-Workbench, RF Preservation & Shutdown
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("V21-F5")
@pytest.mark.feature("V21-F8")
@pytest.mark.feature("V21-F15")
def test_t4_v21_08_responsive_80x24_cross_workbench_rf_preservation_and_shutdown(
    mock_splunk_es_server: MockSplunkESServer,
    mock_s1_server: MockSentinelOneServer,
    mock_llm_server: MockLocalLLMServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Button, Checkbox, DataTable, Input, RichLog, TabbedContent

    from soclens.settings import save_profile_settings
    from soclens.tui.app import create_app
    from soclens.tui.screens.splunk_es import SplunkESPane

    save_profile_settings(
        {
            "splunk_host": mock_splunk_es_server.base_url,
            "s1_console_url": mock_s1_server.base_url,
            "rf_base_url": mock_rf_server.base_url,
        }
    )

    async def _run() -> None:
        app = create_app(
            dry_run=True,
            initial_tab="tab-settings",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            tabs = app.query_one("#main-tabs", TabbedContent)

            for tab_id in (
                "tab-settings",
                "tab-splunk-es",
                "tab-sentinelone",
                "tab-splunk-search",
                "tab-llm",
                "tab-rf-intel",
                "tab-research",
            ):
                tabs.active = tab_id
                await pilot.pause()
                pane = await app.ensure_tab_mounted(tab_id)
                await pilot.pause()
                assert pane is not None
                assert pane.region.x >= 0
                assert pane.region.x + pane.region.width <= 80

            tabs.active = "tab-splunk-es"
            await pilot.pause()
            es_pane = await app.ensure_tab_mounted("tab-splunk-es")
            assert isinstance(es_pane, SplunkESPane)
            await pilot.pause()

            for wid in (
                "#es-rf-controls-row",
                "#es-auto-enrich-cb",
                "#es-private-ips-cb",
                "#es-enrich-selected-btn",
                "#es-post-rf-comment-btn",
            ):
                assert es_pane.query_one(wid) is not None

            from soclens.tui.screens.base import DoubleClickDataTable

            es_pane.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = es_pane.query_one("#es-table", DoubleClickDataTable)
            _select_table_row_containing(table, es_pane._displayed_rows, "fnd-1001-b")
            await pilot.pause()

            await pilot.click("#es-enrich-selected-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["path"].startswith("/soar/v3/enrichment")
                for r in mock_rf_server.requests_log
            )

            for widget in es_pane.query("*"):
                if isinstance(
                    widget, (Button, Checkbox, Input, DataTable, RichLog)
                ) and _is_actually_visible(widget):
                    reg = widget.region
                    assert reg.x >= 0 and reg.y >= 0
                    assert reg.x + reg.width <= 80, f"{widget.id} overflowed width: {reg}"
                    assert reg.y + reg.height <= 24, f"{widget.id} overflowed height: {reg}"

            app.exit()
            await pilot.pause()
            assert app._stop_event.is_set()

    asyncio.run(_run())
    _assert_settings_0600_and_secret_free([])


# ==============================================================================
# Scenario 9: S1 Agents Ops vs Admin Lifecycle & Blocklist Admin (TUI + CLI)
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("V21-F9")
@pytest.mark.feature("V21-F11")
@pytest.mark.feature("V21-F12")
def test_t4_v21_09_s1_agent_move_decommission_and_blocklist_admin_lifecycle(
    mock_s1_server: MockSentinelOneServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Input, Select

    from soclens.tui.app import create_app
    from soclens.tui.modals import ConfirmActionModal, S1AddBlocklistModal
    from soclens.tui.screens.base import DoubleClickDataTable
    from soclens.tui.screens.s1_modals import S1MoveAgentModal
    from soclens.tui.screens.sentinelone import SentinelOnePane

    new_sha1 = "e" * 40

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-sentinelone",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            await pilot.press("f2")
            await pilot.pause()
            assert app.is_admin_view is True

            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-wb-agents-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = pane.query_one("#s1-table", DoubleClickDataTable)
            _select_table_row_containing(table, pane._table_rows, "ag-1001-1")
            await pilot.pause()

            await pilot.click("#s1-isolate-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-fetch-logs-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            _select_table_row_containing(table, pane._table_rows, "ag-1001-2")
            await pilot.pause()
            await pilot.click("#s1-move-agent-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1MoveAgentModal)
            app.screen.query_one("#s1-move-target-site-select", Select).value = "100102"
            await pilot.click("#s1-move-apply-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-tier-all-btn")
            await pilot.pause()

            _select_table_row_containing(table, pane._table_rows, "ag-3001-1")
            await pilot.pause()
            await pilot.click("#s1-decommission-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-goto-blocklist-btn")
            await pilot.pause()
            pane._selected_site_ids = {"100102"}
            await pilot.click("#s1-add-block-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1AddBlocklistModal)
            app.screen.query_one("#s1-block-hash-input", Input).value = new_sha1
            app.screen.query_one("#s1-block-desc-input", Input).value = "E2E blocked payload"
            await pilot.click("#s1-block-add-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            for req in mock_s1_server.requests_log:
                if req["method"] == "POST" and "/agents/actions/" in req["path"]:
                    assert req["json_body"]["filter"]["ids"]
            assert any(
                r["method"] == "POST"
                and r["path"] == "/web/api/v2.1/agents/actions/decommission"
                and r["json_body"]["filter"]["ids"] == ["ag-3001-1"]
                for r in mock_s1_server.requests_log
            )
            assert any(
                r["method"] == "POST"
                and r["path"] == "/web/api/v2.1/restrictions"
                and r["json_body"]["data"]["value"] == new_sha1
                and r["json_body"]["filter"]
                for r in mock_s1_server.requests_log
            )

    asyncio.run(_run())

    no_yes = run_cli(
        [
            "--admin",
            "s1",
            "agents",
            "--move-to-site",
            "100102",
            "--ids",
            "ag-1001-2",
            "--json",
        ]
    )
    assert no_yes.returncode != 0

    mock_s1_server.requests_log.clear()
    dry_cli = run_cli(
        [
            "--admin",
            "s1",
            "agents",
            "--dry-run",
            "--move-to-site",
            "100102",
            "--ids",
            "ag-1001-2",
            "--json",
        ]
    )
    assert dry_cli.returncode == 0, dry_cli.stderr + dry_cli.stdout
    assert not any(
        r["method"] == "POST" and "move-to-site" in r["path"]
        for r in mock_s1_server.requests_log
    )

    exec_cli = run_cli(
        [
            "--admin",
            "s1",
            "agents",
            "--yes",
            "--move-to-site",
            "100102",
            "--ids",
            "ag-1001-2",
            "--json",
        ]
    )
    assert exec_cli.returncode == 0, exec_cli.stderr + exec_cli.stdout
    assert any(
        r["method"] == "POST"
        and r["path"] == "/web/api/v2.1/agents/actions/move-to-site"
        and r["json_body"]["filter"]["ids"] == ["ag-1001-2"]
        and r["json_body"]["data"]["targetSiteId"] == "100102"
        for r in mock_s1_server.requests_log
    )
