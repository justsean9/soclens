"""Tier 3 pairwise cross-feature E2E combination tests for SOCLens v2.1."""

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

pytestmark = [pytest.mark.e2e, pytest.mark.tier3]

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
# T3-01 .. T3-05: Secret Stores, Memory Hydration, Env Precedence & S1 Guardrails
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F2")
@pytest.mark.feature("V21-F4")
@pytest.mark.feature("V21-F7")
@pytest.mark.feature("V21-F10")
@pytest.mark.feature("V21-F14")
def test_t3_v21_01_vault_hydrated_tokens_power_es_s1_llm_zero_disk_and_env_precedence(
    mock_vault_server: MockHashiCorpVaultServer,
    mock_splunk_es_server: MockSplunkESServer,
    mock_s1_server: MockSentinelOneServer,
    mock_llm_server: MockLocalLLMServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.config import (
        get_local_llm_config,
        get_sentinelone_config,
        get_splunk_config,
        hydrate_secrets_from_store,
    )
    from soclens.llm import LocalLLMClient
    from soclens.sentinelone import SentinelOneClient
    from soclens.settings import (
        clear_session_overrides,
        mask_secret,
        save_profile_settings,
        serialize_vault_secret_map,
    )
    from soclens.splunk_es import SplunkESClient

    fixtures = _load_fixture_json("v21_secret_stores.json")
    rec_map = fixtures["hashicorp_vault"]["recommended_map"]

    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": mock_vault_server.base_url,
            "vault_auth_mode": "token",
            "vault_kv_mount": "secret",
            "vault_secret_map": serialize_vault_secret_map(rec_map),
            "splunk_host": mock_splunk_es_server.base_url,
            "splunk_verify_ssl": "false",
            "s1_console_url": mock_s1_server.base_url,
            "s1_verify_ssl": "false",
        }
    )

    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("S1_API_TOKEN", raising=False)
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)
    monkeypatch.delenv("RF_LLM_API_KEY", raising=False)
    monkeypatch.setenv("RF_LLM_PROVIDER", "openai")
    monkeypatch.setenv("RF_LLM_BASE_URL", mock_llm_server.openai_base_url)
    monkeypatch.setenv("RF_LLM_MODEL", "qwen2.5-coder:7b")

    hydrated = hydrate_secrets_from_store(force=True)
    assert hydrated["splunk_token"] == mask_secret("e2e-vault-splunk-token")
    assert hydrated["s1_api_token"] == mask_secret("e2e-vault-s1-api-token")
    assert hydrated["rf_llm_api_key"] == mask_secret("e2e-vault-llm-api-key")

    assert get_splunk_config().token == "e2e-vault-splunk-token"
    assert get_sentinelone_config().api_token == "e2e-vault-s1-api-token"
    assert get_local_llm_config().api_key == "e2e-vault-llm-api-key"

    mock_splunk_es_server.valid_tokens.add("e2e-vault-splunk-token")
    mock_s1_server.valid_tokens.add("e2e-vault-s1-api-token")
    mock_llm_server.set_required_api_key("e2e-vault-llm-api-key")

    with SplunkESClient(
        host=mock_splunk_es_server.base_url,
        token=get_splunk_config().token,
        verify_ssl=False,
    ) as es:
        res = es.query_findings_hybrid(limit=10)
        assert res["source_backend"] == "mc_v2"
        assert len(res["items"]) >= 5

    s1_cfg = get_sentinelone_config()
    with SentinelOneClient(config=s1_cfg) as s1:
        threats = s1.list_threats(limit=10)
        assert len(threats) >= 1

    llm_cfg = get_local_llm_config()
    with LocalLLMClient(config=llm_cfg) as llm:
        reply = llm.chat(
            [{"role": "user", "content": "Summarize [ES + Tenant 1001] findings"}],
        )
        assert reply["content"].strip()

    assert any(
        r["headers"].get("Authorization") == "Bearer e2e-vault-splunk-token"
        for r in mock_splunk_es_server.requests_log
    )
    assert any(
        r["headers"].get("Authorization") == "ApiToken e2e-vault-s1-api-token"
        for r in mock_s1_server.requests_log
    )
    assert any(
        r["headers"].get("Authorization") == "Bearer e2e-vault-llm-api-key"
        for r in mock_llm_server.requests_log
        if r["path"].startswith("/v1/")
    )

    _assert_settings_0600_and_secret_free(
        [
            "e2e-vault-splunk-token",
            "e2e-vault-s1-api-token",
            "e2e-vault-llm-api-key",
            "e2e-vault-rf-api-token",
        ]
    )

    clear_session_overrides()
    monkeypatch.setenv("RF_LLM_API_KEY", "env-override-key")
    hydrated_with_env = hydrate_secrets_from_store(force=True, overwrite_existing=False)
    assert "rf_llm_api_key" not in hydrated_with_env
    assert hydrated_with_env["splunk_token"] == mask_secret("e2e-vault-splunk-token")
    assert get_local_llm_config().api_key == "env-override-key"


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F1")
@pytest.mark.feature("V21-F3")
@pytest.mark.feature("V21-F4")
@pytest.mark.feature("V21-F8")
def test_t3_v21_02_secret_server_and_1p_mixed_hydration_with_rf_enrichment(
    mock_secret_server: MockSecretServer,
    mock_op_connect_server: MockOnePasswordConnectServer,
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.config import (
        get_local_llm_config,
        get_rf_token,
        get_sentinelone_config,
        get_splunk_config,
        hydrate_secrets_from_store,
    )
    from soclens.settings import (
        clear_session_overrides,
        mask_secret,
        save_profile_settings,
        serialize_vault_secret_map,
    )
    from soclens.splunk_es import SplunkESClient
    from soclens.splunk_rf_enrichment import SplunkRFEnricher, write_enrichment_to_notable

    fixtures = _load_fixture_json("v21_secret_stores.json")
    tss_map = fixtures["secret_server"]["recommended_map"]
    op_map = fixtures["onepassword_connect"]["recommended_map"]

    save_profile_settings(
        {
            "secret_provider": "secret_server",
            "tss_base_url": mock_secret_server.base_url,
            "tss_auth_mode": "password",
            "tss_username": "e2e-tss-user",
            "tss_password": "e2e-tss-password",
            "vault_secret_map": serialize_vault_secret_map(
                {
                    "rf_api_token": tss_map["rf_api_token"],
                    "splunk_token": tss_map["splunk_token"],
                }
            ),
            "splunk_host": mock_splunk_es_server.base_url,
            "splunk_verify_ssl": "false",
        }
    )

    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("S1_API_TOKEN", raising=False)
    monkeypatch.delenv("RF_LLM_API_KEY", raising=False)

    mock_rf_server.valid_rf_tokens.add("e2e-tss-rf-api-token")
    mock_splunk_es_server.valid_tokens.add("e2e-tss-splunk-token")

    hydrated_tss = hydrate_secrets_from_store(force=True)
    assert hydrated_tss["rf_api_token"] == mask_secret("e2e-tss-rf-api-token")
    assert hydrated_tss["splunk_token"] == mask_secret("e2e-tss-splunk-token")
    assert get_rf_token() == "e2e-tss-rf-api-token"

    rf_client = RecordedFutureClient(
        api_token=get_rf_token(),
        base_url=mock_rf_server.base_url,
    )
    enricher = SplunkRFEnricher(rf_client)
    with SplunkESClient(
        host=mock_splunk_es_server.base_url,
        token=get_splunk_config().token,
        verify_ssl=False,
    ) as es:
        finding = es.get_finding("fnd-1001-b@@notable@@1002")
        enriched = enricher.enrich_events([finding])[0]
        assert enriched["rf_observables"], "Expected RF observables on enriched finding"
        write_enrichment_to_notable(
            es,
            str(enriched["event_id"]),
            enriched,
            use_mc_v2=True,
            finding_time=str(enriched.get("_time") or "") or None,
        )

    assert any(
        r["headers"].get("X-RFToken") == "e2e-tss-rf-api-token"
        for r in mock_rf_server.requests_log
    )
    assert any(
        r["method"] == "POST" and "/notes" in r["path"]
        for r in mock_splunk_es_server.requests_log
    )

    save_profile_settings(
        {
            "secret_provider": "onepassword_connect",
            "op_connect_url": mock_op_connect_server.base_url,
            "op_connect_token": "e2e-op-connect-token-001",
            "vault_secret_map": serialize_vault_secret_map(
                {
                    "s1_api_token": op_map["s1_api_token"],
                    "rf_llm_api_key": op_map["rf_llm_api_key"],
                }
            ),
        },
    )
    hydrated_op = hydrate_secrets_from_store(force=True, overwrite_existing=True)
    assert hydrated_op["s1_api_token"] == mask_secret("e2e-op-s1-api-token")
    assert hydrated_op["rf_llm_api_key"] == mask_secret("e2e-op-llm-api-key")
    assert get_sentinelone_config(required=False).api_token == "e2e-op-s1-api-token"
    assert get_local_llm_config().api_key == "e2e-op-llm-api-key"
    assert get_rf_token(required=False) == "e2e-tss-rf-api-token"

    clear_session_overrides()
    hydrated_op_clean = hydrate_secrets_from_store(force=True)
    assert hydrated_op_clean["s1_api_token"] == mask_secret("e2e-op-s1-api-token")
    assert get_rf_token(required=False) is None

    _assert_settings_0600_and_secret_free(
        [
            "e2e-tss-rf-api-token",
            "e2e-tss-splunk-token",
            "e2e-op-s1-api-token",
            "e2e-op-llm-api-key",
        ]
    )


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F3")
@pytest.mark.feature("V21-F4")
@pytest.mark.feature("V21-F5")
def test_t3_v21_03_bitwarden_unlock_sync_cli_pull_and_no_secret_store_flag(
    mock_bitwarden_server: MockBitwardenServer,
    mock_s1_server: MockSentinelOneServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.config import get_secret_store_config
    from soclens.secret_stores.bitwarden import BitwardenProvider
    from soclens.settings import (
        save_profile_settings,
        serialize_vault_secret_map,
    )

    fixtures = _load_fixture_json("v21_secret_stores.json")
    bw_map = fixtures["bitwarden"]["recommended_map"]

    mock_bitwarden_server.set_lock_status("locked")
    save_profile_settings(
        {
            "secret_provider": "bitwarden",
            "bw_serve_url": mock_bitwarden_server.base_url,
            "bw_master_password": "e2e-bw-master-password",
            "vault_secret_map": serialize_vault_secret_map(bw_map),
            "s1_console_url": mock_s1_server.base_url,
            "s1_verify_ssl": "false",
        }
    )

    monkeypatch.delenv("S1_API_TOKEN", raising=False)
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)

    pull_proc = run_cli(["secrets", "pull", "--json"])
    assert pull_proc.returncode == 0, pull_proc.stderr + pull_proc.stdout
    pull_data = json.loads(pull_proc.stdout)
    assert "e2e-bw-s1-api-token" not in pull_proc.stdout
    assert "e2e-bw-splunk-token" not in pull_proc.stdout
    assert any(r["path"] == "/unlock" for r in mock_bitwarden_server.requests_log)
    assert any(
        r["path"].startswith("/object/item/")
        for r in mock_bitwarden_server.requests_log
    )
    assert pull_data

    bw_provider = BitwardenProvider(get_secret_store_config())
    try:
        sync_res = bw_provider.sync()
    finally:
        bw_provider.close()
    assert sync_res["ok"] is True
    assert any(r["path"] == "/sync" for r in mock_bitwarden_server.requests_log)

    _assert_settings_0600_and_secret_free(
        ["e2e-bw-s1-api-token", "e2e-bw-splunk-token", "e2e-bw-rf-api-token"]
    )

    mock_bitwarden_server.reset()
    no_store_proc = run_cli(["--no-secret-store", "s1", "status", "--json"])
    assert no_store_proc.returncode != 0
    assert not mock_bitwarden_server.requests_log


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F9")
@pytest.mark.feature("V21-F11")
@pytest.mark.feature("V21-F12")
def test_t3_v21_04_s1_admin_f2_site_create_policy_copy_and_exclusion_clone_pacing(
    mock_s1_server: MockSentinelOneServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Input, RichLog, Select, Static

    from soclens.sentinelone import SentinelOneClient
    from soclens.tui.app import create_app
    from soclens.tui.screens.s1_modals import CloneExclusionsModal, S1SiteModal

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-sentinelone",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            assert app.is_admin_view is False

            await pilot.press("f2")
            await pilot.pause()
            assert app.is_admin_view is True
            assert "Admin View: ON" in str(app.query_one("#s1-admin-badge", Static).render())

            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-site-create-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1SiteModal)
            app.screen.query_one("#s1-site-name-input", Input).value = "MDR-1003"
            app.screen.query_one("#s1-site-account-input", Input).value = "acc-100"
            app.screen.query_one("#s1-site-copy-policy-select", Select).value = "100101"
            app.screen.query_one("#s1-site-clone-excl-select", Select).value = "100101"
            await pilot.click("#s1-site-save-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert any(
                r["method"] == "GET" and r["path"] == "/web/api/v2.1/sites/100101/policy"
                for r in mock_s1_server.requests_log
            )
            assert any(
                r["method"] == "POST"
                and r["path"] == "/web/api/v2.1/sites"
                and (r["json_body"] or {}).get("data", {}).get("name") == "MDR-1003"
                for r in mock_s1_server.requests_log
            )
            excl_posts = [
                r
                for r in mock_s1_server.requests_log
                if r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
            ]
            assert excl_posts
            for req in excl_posts:
                desc = str((req["json_body"] or {}).get("data", {}).get("description") or "")
                assert "[Cloned from " in desc
                assert len(desc) <= 500

            await pilot.click("#s1-wb-exclusions-btn")
            await pilot.pause()
            await pilot.click("#s1-clone-excl-btn")
            await pilot.pause()
            assert isinstance(app.screen, CloneExclusionsModal)
            app.screen.query_one("#s1-clone-src-select", Select).value = "100101"
            app.screen.query_one("#s1-clone-dst-select", Select).value = "100102"
            await pilot.click("#s1-clone-preview-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            summary_txt = str(app.screen.query_one("#s1-clone-summary", Static).render())
            assert "Will Create: 2" in summary_txt
            assert "Skipped Duplicate: 1" in summary_txt
            assert "Inherited from Account: 1" in summary_txt

            log_widget = app.screen.query_one("#s1-clone-preview-log", RichLog)
            log_text = "\n".join(str(getattr(line, "text", line)) for line in log_widget.lines)
            assert "[Will Create]" in log_text
            assert "[Skipped Duplicate]" in log_text
            assert "[Inherited from Account]" in log_text
            assert "[Cloned from MDR-1001]" in log_text
            await pilot.click("#s1-clone-cancel-btn")
            await pilot.pause()

    asyncio.run(_run())

    mock_s1_server.reset()
    seeded_ids = mock_s1_server.seed_bulk_exclusions("100101", 16)
    assert len(seeded_ids) == 16
    with SentinelOneClient(
        console_url=mock_s1_server.base_url,
        api_token="test-s1-token",
        verify_ssl=False,
    ) as client:
        result = client.clone_exclusions(
            "100101",
            "100102",
            source_site_name="MDR-1001",
            dry_run=False,
            requests_per_second=15.0,
        )
    assert result["counts"]["created"] >= 16
    write_reqs = [
        r
        for r in mock_s1_server.requests_log
        if r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
    ]
    assert len(write_reqs) >= 16
    elapsed = write_reqs[-1]["timestamp"] - write_reqs[0]["timestamp"]
    min_expected = (len(write_reqs) - 1) / 15.0 * 0.90
    assert elapsed >= min_expected, f"Burst cloning exceeded 15 req/s: {len(write_reqs)} in {elapsed:.3f}s"
    for req in write_reqs:
        desc = str((req["json_body"] or {}).get("data", {}).get("description") or "")
        assert "[Cloned from MDR-1001]" in desc
        assert len(desc) <= 500


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F11")
@pytest.mark.feature("V21-F12")
def test_t3_v21_05_s1_cli_admin_gating_dry_run_vs_execute_exclusion_clone(
    mock_s1_server: MockSentinelOneServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    no_admin = run_cli(
        ["s1", "exclusions", "clone", "--from-site", "100101", "--to-site", "100102", "--json"]
    )
    assert no_admin.returncode != 0
    assert not any(
        r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
        for r in mock_s1_server.requests_log
    )

    no_yes = run_cli(
        [
            "--admin",
            "s1",
            "exclusions",
            "clone",
            "--from-site",
            "100101",
            "--to-site",
            "100102",
            "--json",
        ]
    )
    assert no_yes.returncode != 0
    assert "approval" in (no_yes.stdout + no_yes.stderr).lower() or "yes" in (
        no_yes.stdout + no_yes.stderr
    ).lower()
    assert not any(
        r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
        for r in mock_s1_server.requests_log
    )

    dry_proc = run_cli(
        [
            "--admin",
            "s1",
            "exclusions",
            "clone",
            "--dry-run",
            "--from-site",
            "100101",
            "--to-site",
            "100102",
            "--json",
        ]
    )
    assert dry_proc.returncode == 0, dry_proc.stderr + dry_proc.stdout
    dry_data = json.loads(dry_proc.stdout)
    counts = dry_data.get("counts", dry_data)
    assert counts["will_create"] == 2
    assert counts["skipped_duplicate"] == 1
    assert counts["inherited_from_account"] == 1
    assert not any(
        r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
        for r in mock_s1_server.requests_log
    )

    exec_proc = run_cli(
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
    assert exec_proc.returncode == 0, exec_proc.stderr + exec_proc.stdout
    exec_posts = [
        r
        for r in mock_s1_server.requests_log
        if r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
    ]
    assert len(exec_posts) == 2
    for req in exec_posts:
        desc = str((req["json_body"] or {}).get("data", {}).get("description") or "")
        assert "[Cloned from " in desc
        assert len(desc) <= 500


# ==============================================================================
# T3-06 .. T3-10: Splunk ES Hybrid, Pivot Bus & SettingsPane Dynamic Swap
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F7")
@pytest.mark.feature("V21-F8")
def test_t3_v21_06_es_notes_rf_dual_post_and_saved_views_persistence(
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, Input, RichLog, Select, TextArea

    from soclens.tui.app import create_app
    from soclens.tui.screens.base import DoubleClickDataTable, extract_richlog_text
    from soclens.tui.screens.es_modals import ESNoteModal, ESSavedViewModal
    from soclens.tui.screens.splunk_es import SplunkESPane

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
            await app.workers.wait_for_complete()
            await pilot.pause()

            pane.query_one("#es-search-input", Input).value = "tenant_id:1001"
            await pilot.pause()
            assert pane._current_rows
            assert all(str(r.get("tenant_id")) == "1001" for r in pane._current_rows)

            await pilot.click("#es-save-view-btn")
            await pilot.pause()
            assert isinstance(app.screen, ESSavedViewModal)
            app.screen.query_one("#es-saved-view-name-input", Input).value = "Tenant 1001 Queue"
            await pilot.click("#es-saved-view-save-btn")
            await pilot.pause()

            from soclens.settings import get_profile_settings

            saved_raw = _settings_path().read_text(encoding="utf-8")
            assert json.loads(saved_raw)["encrypted"] is True
            assert "Tenant 1001 Queue" in (get_profile_settings().get("splunk_es_saved_views") or "")

            table = pane.query_one("#es-table", DoubleClickDataTable)
            _select_table_row_containing(table, pane._displayed_rows, "fnd-1001-b")
            await pilot.pause()

            await pilot.click("#es-enrich-selected-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["path"].startswith("/soar/v3/enrichment")
                for r in mock_rf_server.requests_log
            )

            _select_table_row_containing(table, pane._displayed_rows, "fnd-1001-b")
            await pilot.pause()

            await pilot.click("#es-insp-add-note-btn")
            await pilot.pause()
            assert isinstance(app.screen, ESNoteModal)
            app.screen.query_one("#es-note-title-input", Input).value = "E2E Triage Note"
            app.screen.query_one("#es-note-text", TextArea).load_text("**Confirmed** C2 indicator")
            dual_cb = app.screen.query_one("#es-note-dual-rf-cb", Checkbox)
            assert not dual_cb.disabled
            dual_cb.value = True
            await pilot.click("#es-note-submit-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            note_posts = [
                r
                for r in mock_splunk_es_server.requests_log
                if r["method"] == "POST" and "/notes" in r["path"]
            ]
            assert len(note_posts) >= 2
            bodies = [json.dumps(r["json_body"] or {}) for r in note_posts]
            assert any("Confirmed" in b for b in bodies)
            assert any("Recorded Future" in b for b in bodies)

            await pilot.click("#es-insp-tab-notes")
            await app.workers.wait_for_complete()
            await pilot.pause()
            notes_txt = extract_richlog_text(pane.query_one("#es-detail", RichLog))
            assert "E2E Triage Note" in notes_txt or "Confirmed" in notes_txt
            assert "--- Audit History ---" in notes_txt

            sel_opts = [str(opt[1]) for opt in pane.query_one("#es-preset-select", Select)._options]
            assert any("tenant_1001_queue" in opt for opt in sel_opts)

    asyncio.run(_run())


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F6")
@pytest.mark.feature("V21-F7")
def test_t3_v21_07_es_mc_v2_vs_7x_spl_fallback_on_404_and_spl_only_filters(
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from soclens.splunk_es import SplunkESClient

    with SplunkESClient(
        host=mock_splunk_es_server.base_url,
        token="test-splunk-token",
        verify_ssl=False,
    ) as es:
        res_tenant = es.query_findings_hybrid(tenant_id="1001")
        assert res_tenant["source_backend"] == "mc_v2"
        assert res_tenant["items"]
        assert all(str(item.get("tenant_id")) == "1001" for item in res_tenant["items"])
        mc_gets = [
            r
            for r in mock_splunk_es_server.requests_log
            if r["method"] == "GET" and r["path"].endswith("/public/v2/findings")
        ]
        assert mc_gets
        assert all("tenant_id" not in req["query"] for req in mc_gets)

        mock_splunk_es_server.requests_log.clear()
        res_spl_only = es.query_findings_hybrid(
            raw_query="mimikatz_marker_raw",
            orig_sid="1700000100.77",
        )
        assert res_spl_only["source_backend"] == "spl_fallback"
        assert [it["event_id"] for it in res_spl_only["items"]] == ["fnd-raw-only"]
        assert any(
            r["method"] == "POST"
            and r["path"].endswith("/search/jobs")
            and "`notable`" in " ".join(r["form"].get("search", []))
            for r in mock_splunk_es_server.requests_log
        )

        mock_splunk_es_server.set_mc_v2_enabled(False)
        mock_splunk_es_server.requests_log.clear()
        res_404 = es.query_findings_hybrid(tenant_id="1002")
        assert res_404["source_backend"] == "spl_fallback"
        assert [it["event_id"] for it in res_404["items"]] == ["fnd-1002-org"]

        triage_404 = es.triage_findings_hybrid(
            ["fnd-1002-org"],
            status="Resolved",
            owner="soc_analyst",
            note="7.x notable_update fallback",
        )
        assert triage_404["backend"] == "notable_update"
        assert any(
            r["method"] == "POST" and r["path"] == "/services/notable_update"
            for r in mock_splunk_es_server.requests_log
        )


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F8")
@pytest.mark.feature("V21-F13")
def test_t3_v21_08_pivot_bus_f9_to_f8_orig_sid_autorun_vs_custom_spl_safe(
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, TabbedContent, TextArea

    from soclens.tui.app import create_app
    from soclens.tui.screens.base import DoubleClickDataTable
    from soclens.tui.screens.splunk_es import SplunkESPane

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-splunk-es",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            es_pane = app.query_one(SplunkESPane)
            es_pane.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.click("#es-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = es_pane.query_one("#es-table", DoubleClickDataTable)
            _select_table_row_containing(table, es_pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()

            mock_splunk_es_server.requests_log.clear()
            await pilot.click("#es-insp-pivot-search-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-splunk-search"
            spl_text = app.query_one("#splunk-search-spl", TextArea).text
            assert '| loadjob "1700000100.11"' in spl_text
            assert any(
                r["method"] == "POST"
                and r["path"].endswith("/search/jobs")
                and "1700000100.11" in " ".join(r["form"].get("search", []))
                for r in mock_splunk_es_server.requests_log
            )

            tabs.active = "tab-splunk-es"
            await pilot.pause()
            _select_table_row_containing(table, es_pane._displayed_rows, "fnd-grp-1001")
            await pilot.pause()
            mock_splunk_es_server.requests_log.clear()
            await pilot.click("#es-insp-pivot-search-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert tabs.active == "tab-splunk-search"
            safe_spl = app.query_one("#splunk-search-spl", TextArea).text
            assert safe_spl.startswith("search ")
            assert "loadjob" not in safe_spl
            assert not any(
                r["method"] == "POST" and r["path"].endswith("/search/jobs")
                for r in mock_splunk_es_server.requests_log
            )

    asyncio.run(_run())


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F6")
@pytest.mark.feature("V21-F9")
@pytest.mark.feature("V21-F13")
@pytest.mark.feature("V21-F14")
def test_t3_v21_09_pivot_bus_bidirectional_f9_s1_and_f7_copilot_bundle(
    mock_splunk_es_server: MockSplunkESServer,
    mock_s1_server: MockSentinelOneServer,
    mock_llm_server: MockLocalLLMServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, Input, Static, TabbedContent

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
            await app.workers.wait_for_complete()
            await pilot.pause()

            es_table = es_pane.query_one("#es-table", DoubleClickDataTable)
            _select_table_row_containing(es_table, es_pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()

            await pilot.click("#es-insp-pivot-s1-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-sentinelone"
            s1_pane = app.query_one(SentinelOnePane)
            assert s1_pane._records
            assert any(
                "wkstn-1001-01" in json.dumps(r, default=str)
                for r in s1_pane._records
            )

            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1_table = s1_pane.query_one("#s1-table", DoubleClickDataTable)
            _select_table_row_containing(s1_table, s1_pane._table_rows, "thr-1001-2")
            await pilot.pause()

            await pilot.click("#s1-pivot-es-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert tabs.active == "tab-splunk-es"
            assert "tenant_id:1001" in app.query_one("#es-search-input", Input).value

            await pilot.click("#es-insp-pivot-llm-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert tabs.active == "tab-llm"
            badge = app.query_one("#llm-context-badge", Static)
            assert badge.display is True
            assert not any(r["path"] == "/api/chat" for r in mock_llm_server.requests_log)

            await pilot.click("#llm-send-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            chat_reqs = [r for r in mock_llm_server.requests_log if r["path"] == "/api/chat"]
            assert chat_reqs
            prompt_blob = json.dumps(chat_reqs[-1]["json_body"] or {})
            assert "1001" in prompt_blob
            assert "wkstn-1001-01" in prompt_blob

    asyncio.run(_run())


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F2")
@pytest.mark.feature("V21-F4")
@pytest.mark.feature("V21-F5")
def test_t3_v21_10_settings_pane_cat_secrets_dynamic_swap_and_offline_fallback(
    mock_vault_server: MockHashiCorpVaultServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import ContentSwitcher, Input, OptionList, Select

    from soclens.settings import (
        save_profile_settings,
        serialize_vault_secret_map,
    )
    from soclens.tui.app import create_app

    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": mock_vault_server.base_url,
            "vault_token": "e2e-vault-token-001",
            "vault_kv_mount": "secret",
            "vault_secret_map": serialize_vault_secret_map(
                {"rf_api_token": "hashicorp_vault:soclens/rf:api_token"}
            ),
        }
    )

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-settings",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            cat_list = app.query_one("#settings-category-list", OptionList)
            cat_idx = cat_list.get_option_index("cat-secrets")
            cat_list.highlighted = cat_idx
            cat_list.action_select()
            await pilot.pause()

            assert app.query_one("#settings-category-switcher", ContentSwitcher).current == "cat-secrets"
            assert app.query_one("#set-vault-token", Input).password is True
            assert app.query_one("#set-tss-password", Input).password is True
            bw_inp = app.query_one("#set-bw-master-password", Input)
            assert bw_inp.password is True
            assert bw_inp.value == ""

            provider_sel = app.query_one("#set-secret-provider", Select)
            assert provider_sel.value == "hashicorp_vault"
            assert app.query_one("#vault-fields-group").display is True
            assert app.query_one("#tss-fields-group").display is False

            assert app.query_one("#set-rf-api-token", Input).display is False
            rf_vault_sel = app.query_one("#set-rf-api-token-vault", Select)
            assert rf_vault_sel.display is True
            assert rf_vault_sel.value == "hashicorp_vault:soclens/rf:api_token"
            rf_labels = [str(opt[0]) for opt in getattr(rf_vault_sel, "_options", [])]
            assert any(
                "saved" in lbl.lower() or "hashicorp_vault:soclens/rf:api_token" in lbl
                for lbl in rf_labels
            )
            assert app.query_one("#set-splunk-token", Input).display is False
            assert app.query_one("#set-splunk-token-vault", Select).display is True
            assert app.query_one("#set-s1-api-token", Input).display is False
            assert app.query_one("#set-s1-api-token-vault", Select).display is True

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
            await app.workers.wait_for_complete()
            await pilot.pause()

            app.query_one("#set-splunk-token-vault", Select).value = "hashicorp_vault:soclens/splunk:token"
            app.query_one("#set-s1-api-token-vault", Select).value = "hashicorp_vault:soclens/edr:s1_api_token"
            await pilot.click("#settings-save-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            from soclens.settings import get_profile_settings

            saved_text = _settings_path().read_text(encoding="utf-8")
            assert json.loads(saved_text)["encrypted"] is True
            saved_vault_map = get_profile_settings().get("vault_secret_map") or ""
            assert "hashicorp_vault:soclens/splunk:token" in saved_vault_map
            assert "hashicorp_vault:soclens/edr:s1_api_token" in saved_vault_map
            _assert_settings_0600_and_secret_free(
                ["e2e-vault-rf-api-token", "e2e-vault-splunk-token", "e2e-vault-s1-api-token"]
            )

    asyncio.run(_run())


# ==============================================================================
# T3-11 .. T3-15: S1 Tier Isolation, Delete Gate, ES Custom Fields, AR, 80x24
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F9")
@pytest.mark.feature("V21-F10")
def test_t3_v21_11_s1_tier_rules_tier_hash_bulk_action_no_cross_tier_leak(
    mock_s1_server: MockSentinelOneServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Select

    from soclens.tui.app import create_app
    from soclens.tui.modals import ConfirmActionModal
    from soclens.tui.screens.base import DoubleClickDataTable
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

            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            pane.query_one("#s1-grouping-select", Select).value = "tier_hash"
            await pilot.pause()

            group_labels = [str(r.get("_group_label") or "") for r in pane._table_rows]
            assert f"MDR | {shared_sha1}" in group_labels
            assert f"MSSP | {shared_sha1}" in group_labels

            table = pane.query_one("#s1-table", DoubleClickDataTable)
            mdr_idx = next(
                idx
                for idx, row in enumerate(pane._table_rows)
                if row.get("_group_label") == f"MDR | {shared_sha1}"
            )
            table.move_cursor(row=mdr_idx)
            await pilot.pause()

            await pilot.click("#s1-kill-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            kill_reqs = [
                r
                for r in mock_s1_server.requests_log
                if r["method"] == "POST" and r["path"] == "/web/api/v2.1/threats/mitigate/kill"
            ]
            assert kill_reqs
            killed_ids = set(kill_reqs[-1]["json_body"]["filter"]["ids"])
            assert killed_ids == {"thr-1001-1", "thr-1002-1"}
            assert "thr-2001-1" not in killed_ids

            await pilot.click("#s1-wb-agents-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-tier-mdr-btn")
            await pilot.pause()
            assert {r["id"] for r in pane._filtered_records} == {"ag-1001-1", "ag-1001-2", "ag-1002-1"}

            ep_table = pane.query_one("#s1-table", DoubleClickDataTable)
            _select_table_row_containing(ep_table, pane._table_rows, "ag-1001-1")
            await pilot.pause()
            await pilot.click("#s1-isolate-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            iso_reqs = [
                r
                for r in mock_s1_server.requests_log
                if r["method"] == "POST" and r["path"] == "/web/api/v2.1/agents/actions/disconnect"
            ]
            assert iso_reqs
            assert iso_reqs[-1]["json_body"]["filter"]["ids"] == ["ag-1001-1"]

    asyncio.run(_run())


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F9")
@pytest.mark.feature("V21-F11")
@pytest.mark.feature("V21-F13")
def test_t3_v21_12_s1_site_tenant_map_override_and_exact_name_delete_gate(
    mock_s1_server: MockSentinelOneServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Input, Static

    from soclens.config import extract_tenant_from_site_name
    from soclens.settings import invalidate_settings_cache, save_profile_settings
    from soclens.tui.app import create_app
    from soclens.tui.screens.base import DoubleClickDataTable
    from soclens.tui.screens.s1_modals import ConfirmDeleteSiteModal
    from soclens.tui.screens.sentinelone import SentinelOnePane

    save_profile_settings(
        {
            "s1_site_tenant_map": json.dumps(
                {
                    "Corp-Sandbox-3001": "CORP-OVERRIDE-3001",
                    "100102": "CUSTOM-MDR-1002",
                }
            ),
            "s1_console_url": mock_s1_server.base_url,
            "s1_verify_ssl": "false",
        }
    )
    invalidate_settings_cache()

    assert extract_tenant_from_site_name("Corp-Sandbox-3001") == "CORP-OVERRIDE-3001"
    assert extract_tenant_from_site_name("MDR-1002", site_id="100102") == "CUSTOM-MDR-1002"

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-sentinelone",
            workspace_dir=v21_workspace,
            view_mode="admin",
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            pivot_payload = pane._build_pivot_payload(
                "tab-splunk-es",
                rec={
                    "siteId": "300101",
                    "siteName": "Corp-Sandbox-3001",
                    "computerName": "sandbox-3001-01.example.test",
                },
            )
            assert pivot_payload.tenant_id == "CORP-OVERRIDE-3001"

            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = pane.query_one("#s1-table", DoubleClickDataTable)
            _select_table_row_containing(table, pane._table_rows, "MDR-9999-Expired")
            await pilot.pause()

            await pilot.click("#s1-site-delete-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmDeleteSiteModal)

            app.screen.query_one("#s1-del-site-confirm-input", Input).value = "MDR-1001"
            await pilot.click("#s1-del-site-approve-btn")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmDeleteSiteModal)
            err_txt = str(app.screen.query_one("#s1-del-site-error", Static).render())
            assert "mismatch" in err_txt.lower()
            assert not any(
                r["method"] == "DELETE" and r["path"].startswith("/web/api/v2.1/sites/")
                for r in mock_s1_server.requests_log
            )

            app.screen.query_one("#s1-del-site-confirm-input", Input).value = "MDR-9999-Expired"
            await pilot.click("#s1-del-site-approve-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert any(
                r["method"] == "DELETE" and r["path"] == "/web/api/v2.1/sites/100999"
                for r in mock_s1_server.requests_log
            )

    asyncio.run(_run())


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F6")
@pytest.mark.feature("V21-F7")
@pytest.mark.feature("V21-F8")
def test_t3_v21_13_es_event_attributes_log_review_fallback_pinned_fields_and_rollup(
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, RichLog

    from soclens.settings import invalidate_settings_cache, save_profile_settings
    from soclens.tui.app import create_app
    from soclens.tui.screens.base import DoubleClickDataTable, extract_richlog_text
    from soclens.tui.screens.splunk_es import SplunkESPane

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
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert any(
                "conf-incident_review/incident_review" in r["path"]
                for r in mock_splunk_es_server.requests_log
            )
            assert any(
                "conf-log_review/incident_review" in r["path"]
                for r in mock_splunk_es_server.requests_log
            )

            table = pane.query_one("#es-table", DoubleClickDataTable)
            col_keys = {str(col.key.value) for col in table.ordered_columns}
            assert {"tenant_id", "snow_ticket", "case_id"}.issubset(col_keys)

            _select_table_row_containing(table, pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()
            await pilot.click("#es-insp-tab-metadata")
            await pilot.pause()
            meta_text = extract_richlog_text(pane.query_one("#es-detail", RichLog))
            assert "--- Custom / Org Fields ---" in meta_text
            assert "business_unit" in meta_text
            assert "Finance" in meta_text

            await pilot.click("#es-group-tenant-btn")
            await pilot.pause()
            group_rows = [r for r in pane._displayed_rows if r.get("_is_group_row")]
            by_tenant = {str(r["_group_tenant"]): str(r["title"]) for r in group_rows}
            assert "1001" in by_tenant and "4 finding(s)" in by_tenant["1001"]
            assert "1002" in by_tenant and "1 finding(s)" in by_tenant["1002"]
            assert "2001" in by_tenant and "2 finding(s)" in by_tenant["2001"]
            assert "-" in by_tenant and "1 finding(s)" in by_tenant["-"]

    asyncio.run(_run())


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F7")
@pytest.mark.feature("V21-F8")
def test_t3_v21_14_es_adaptive_response_dispatch_and_history_audit(
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, Input, RichLog, Select, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.base import DoubleClickDataTable, extract_richlog_text
    from soclens.tui.screens.es_modals import ESAdaptiveResponseModal
    from soclens.tui.screens.splunk_es import SplunkESPane

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
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = pane.query_one("#es-table", DoubleClickDataTable)
            _select_table_row_containing(table, pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()

            await pilot.click("#es-insp-ar-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert isinstance(app.screen, ESAdaptiveResponseModal)

            action_sel = app.screen.query_one("#es-ar-action-select", Select)
            opt_vals = {str(v) for _lbl, v in action_sel._options}
            assert {"risk", "ping", "ea_servicenow_sync", "s1_isolate"}.issubset(opt_vals)
            assert "notable" not in opt_vals

            hist_text = extract_richlog_text(app.screen.query_one("#es-ar-history-log", RichLog))
            assert "risk" in hist_text or "notable" in hist_text

            action_sel.value = "risk"
            app.screen.query_one("#es-ar-params-input", Input).value = (
                "risk_object=wkstn-1001-01.example.test; risk_score=25"
            )
            await pilot.click("#es-ar-dispatch-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            adhoc_posts = [
                r
                for r in mock_splunk_es_server.requests_log
                if r["method"] == "POST" and r["path"] == "/services/alerts/modaction_adhoc"
            ]
            assert adhoc_posts
            assert adhoc_posts[-1]["form"]["action_name"] == ["risk"]
            assert adhoc_posts[-1]["form"]["sid"] == ["1700000100.11"]

        dry_app = create_app(
            dry_run=True,
            initial_tab="tab-splunk-es",
            workspace_dir=v21_workspace,
        )
        mock_splunk_es_server.requests_log.clear()
        async with dry_app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            pane = dry_app.query_one(SplunkESPane)
            pane.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.click("#es-refresh-btn")
            await dry_app.workers.wait_for_complete()
            await pilot.pause()

            table = pane.query_one("#es-table", DoubleClickDataTable)
            _select_table_row_containing(table, pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()

            await pilot.click("#es-insp-ar-btn")
            await dry_app.workers.wait_for_complete()
            await pilot.pause()
            assert isinstance(dry_app.screen, ESAdaptiveResponseModal)
            assert "[DRY-RUN]" in str(dry_app.screen.query_one("#es-ar-dry-banner", Static).render())
            await pilot.click("#es-ar-dispatch-btn")
            await dry_app.workers.wait_for_complete()
            await pilot.pause()
            assert not any(
                r["method"] == "POST" and r["path"] == "/services/alerts/modaction_adhoc"
                for r in mock_splunk_es_server.requests_log
            )

    asyncio.run(_run())


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F8")
@pytest.mark.feature("V21-F15")
def test_t3_v21_15_es_80x24_responsive_layout_and_v20_rf_controls_preserved(
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.containers import Horizontal
    from textual.widgets import Button, Checkbox, Collapsible, DataTable, Input, RichLog

    from soclens.settings import save_profile_settings
    from soclens.tui.app import create_app
    from soclens.tui.screens.splunk_es import SplunkESPane

    save_profile_settings({"splunk_host": mock_splunk_es_server.base_url})

    async def _run() -> None:
        app = create_app(
            dry_run=True,
            initial_tab="tab-splunk-es",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await pilot.resize_terminal(80, 24)
            await pilot.pause()

            pane = app.query_one(SplunkESPane)
            assert pane.has_class("es-compact")
            assert pane.region.x >= 0
            assert pane.region.x + pane.region.width <= 80

            for wid, cls in (
                ("#es-rf-controls-row", Horizontal),
                ("#es-auto-enrich-cb", Checkbox),
                ("#es-private-ips-cb", Checkbox),
                ("#es-enrich-selected-btn", Button),
                ("#es-enrich-all-btn", Button),
                ("#es-post-rf-comment-btn", Button),
                ("#es-rf-map-collapsible", Collapsible),
                ("#es-rf-field-map-input", Input),
            ):
                assert pane.query_one(wid, cls) is not None

            from soclens.tui.screens.base import DoubleClickDataTable

            pane.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.click("#es-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = pane.query_one("#es-table", DoubleClickDataTable)
            _select_table_row_containing(table, pane._displayed_rows, "fnd-1001-b")
            await pilot.pause()

            await pilot.click("#es-enrich-selected-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["path"].startswith("/soar/v3/enrichment")
                for r in mock_rf_server.requests_log
            )

            for widget in pane.query("*"):
                if isinstance(
                    widget, (Button, Checkbox, Input, DataTable, RichLog)
                ) and _is_actually_visible(widget):
                    reg = widget.region
                    assert reg.x >= 0
                    assert reg.y >= 0
                    assert reg.x + reg.width <= 80, f"{widget.id} overflowed width: {reg}"
                    assert reg.y + reg.height <= 24, f"{widget.id} overflowed height: {reg}"

    asyncio.run(_run())
    _assert_settings_0600_and_secret_free([])


# ==============================================================================
# T3-16 .. T3-20: S1 80x24 + Cloud/STAR, 429/Guardrails, ES Bulk, CLI, Pivots
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F9")
@pytest.mark.feature("V21-F10")
@pytest.mark.feature("V21-F11")
@pytest.mark.feature("V21-F15")
def test_t3_v21_16_s1_80x24_layout_user_vs_admin_view_and_cloud_star_alerts(
    mock_s1_server: MockSentinelOneServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Select, Static

    from soclens.tui.app import create_app
    from soclens.tui.modals import S1ThreatTriageModal
    from soclens.tui.screens.base import DoubleClickDataTable
    from soclens.tui.screens.sentinelone import SentinelOnePane

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-sentinelone",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            assert app.is_admin_view is False
            assert pane.region.x >= 0
            assert pane.region.x + pane.region.width <= 80

            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            mock_s1_server.requests_log.clear()
            for wb_btn, gated_btn in (
                ("#s1-wb-agents-btn", "#s1-move-agent-btn"),
                ("#s1-wb-agents-btn", "#s1-decommission-btn"),
                ("#s1-wb-sites-btn", "#s1-site-create-btn"),
                ("#s1-wb-users-btn", "#s1-user-create-btn"),
                ("#s1-wb-exclusions-btn", "#s1-clone-excl-btn"),
            ):
                await pilot.click(wb_btn)
                await pilot.pause()
                await pilot.click(gated_btn)
                await pilot.pause()
                assert "Admin View" in str(pane.query_one("#s1-status", Static).render())

            await pilot.click("#s1-wb-agents-btn")
            await pilot.pause()
            await pilot.click("#s1-goto-blocklist-btn")
            await pilot.pause()
            await pilot.click("#s1-add-block-btn")
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
            await app.workers.wait_for_complete()
            await pilot.pause()

            record_ids = {str(r.get("id")) for r in pane._filtered_records}
            assert any(rid.startswith("thr-") for rid in record_ids)
            assert any(rid.startswith("cld-") for rid in record_ids)

            table = pane.query_one("#s1-table", DoubleClickDataTable)
            _select_table_row_containing(table, pane._table_rows, "cld-1001-1")
            await pilot.pause()

            await pilot.click("#s1-kill-btn")
            await pilot.pause()
            status_txt = str(pane.query_one("#s1-status", Static).render())
            assert "Cloud/STAR alerts" in status_txt
            assert not any(
                "threats/mitigate/" in r["path"] for r in mock_s1_server.requests_log
            )

            await pilot.click("#s1-triage-btn")
            await pilot.pause()
            assert isinstance(app.screen, S1ThreatTriageModal)
            app.screen.query_one("#s1-triage-verdict-select", Select).value = "true_positive"
            app.screen.query_one("#s1-triage-status-select", Select).value = "in_progress"
            await pilot.click("#s1-triage-apply-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert any(
                r["method"] == "POST"
                and r["path"] == "/web/api/v2.1/cloud-detection/alerts/analyst-verdict"
                and r["json_body"]["filter"]["ids"] == ["cld-1001-1"]
                for r in mock_s1_server.requests_log
            )
            assert any(
                r["method"] == "POST"
                and r["path"] == "/web/api/v2.1/cloud-detection/alerts/incident"
                and r["json_body"]["filter"]["ids"] == ["cld-1001-1"]
                for r in mock_s1_server.requests_log
            )

    asyncio.run(_run())


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F9")
@pytest.mark.feature("V21-F12")
def test_t3_v21_17_s1_429_backoff_cursor_pagination_and_empty_filter_guard(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from soclens.sentinelone import SentinelOneClient

    mock_s1_server.set_enforce_limit_max_100(True)
    mock_s1_server.queue_fault(
        "/web/api/v2.1/sites",
        429,
        headers={"Retry-After": "0.02"},
        method="GET",
        count=1,
    )
    mock_s1_server.queue_fault(
        "/web/api/v2.1/exclusions",
        429,
        headers={"Retry-After": "0.02"},
        method="GET",
        count=1,
    )

    mock_s1_server.seed_bulk_exclusions("100101", 105)
    with SentinelOneClient(
        console_url=mock_s1_server.base_url,
        api_token="test-s1-token",
        verify_ssl=False,
        max_retries=3,
        backoff_base=0.01,
    ) as client:
        sites = client.list_sites(limit=100)
        assert len(sites) >= 5
        exclusions = client.list_exclusions(site_ids=["100101"], limit=150)
        assert len(exclusions) >= 105

        excl_gets = [
            r
            for r in mock_s1_server.requests_log
            if r["method"] == "GET" and r["path"].endswith("/exclusions")
        ]
        assert len(excl_gets) >= 2
        assert any("cursor" in r["query"] for r in excl_gets)

        for req in mock_s1_server.requests_log:
            if req["method"] == "GET" and "limit" in req["query"]:
                assert int(req["query"]["limit"][0]) <= 100

        mock_s1_server.requests_log.clear()
        with pytest.raises(ValueError):
            client.delete_exclusions([])
        with pytest.raises(ValueError):
            client.update_threat_verdict([], "true_positive")
        with pytest.raises(ValueError):
            client.disconnect_agent([])
        assert mock_s1_server.requests_log == []


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F7")
@pytest.mark.feature("V21-F8")
def test_t3_v21_18_es_bulk_triage_queue_pills_autorefresh_pause_and_inspector_step(
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
    v21_workspace: Path,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, Input, Select, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.es_modals import ESBulkTriageModal
    from soclens.tui.screens.splunk_es import SplunkESPane

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
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#es-type-groups-btn")
            await pilot.pause()
            assert [r["event_id"] for r in pane._displayed_rows] == ["fnd-grp-1001"]

            await pilot.click("#es-type-findings-btn")
            await pilot.pause()
            assert pane._displayed_rows
            assert all(r.get("item_type") != "finding_group" for r in pane._displayed_rows)

            await pilot.click("#es-type-all-btn")
            await pilot.pause()
            assert len(pane._displayed_rows) >= 2

            await pilot.click("#es-type-investigations-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            inv_ids = {str(r.get("investigation_guid") or r.get("event_id")) for r in pane._displayed_rows}
            assert {"inv-guid-1001", "inv-guid-2001"}.issubset(inv_ids)

            await pilot.click("#es-type-all-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.click("#es-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert len(pane._displayed_rows) >= 2

            first_hdr = str(pane.query_one("#es-detail-header", Static).render())
            await pilot.click("#es-next-finding-btn")
            await pilot.pause()
            second_hdr = str(pane.query_one("#es-detail-header", Static).render())
            assert second_hdr != first_hdr
            await pilot.click("#es-prev-finding-btn")
            await pilot.pause()
            assert str(pane.query_one("#es-detail-header", Static).render()) == first_hdr

            await pilot.click("#es-select-page-btn")
            await pilot.pause()
            assert pane.query_one("#es-bulk-bar").display is True

            await pilot.click("#es-auto-refresh-btn")
            await pilot.pause()
            assert pane._is_auto_refresh_paused() is True
            mock_splunk_es_server.requests_log.clear()
            pane._on_auto_refresh_tick()
            await pilot.pause()
            assert mock_splunk_es_server.requests_log == []

            await pilot.click("#es-bulk-triage-btn")
            await pilot.pause()
            assert isinstance(app.screen, ESBulkTriageModal)
            app.screen.query_one("#es-bulk-status-select", Select).value = "Resolved"
            app.screen.query_one("#es-bulk-owner-input", Input).value = "soc_analyst"
            app.screen.query_one("#es-bulk-note-input", Input).value = "Bulk closed in E2E"
            await pilot.click("#es-bulk-apply-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            bulk_reqs = [
                r
                for r in mock_splunk_es_server.requests_log
                if r["method"] == "POST"
                and r["path"].endswith("/public/v2/investigations/bulk_update")
            ]
            assert bulk_reqs
            assert bulk_reqs[-1]["json_body"]["status"] == "Resolved"
            assert bulk_reqs[-1]["json_body"]["owner"] == "soc_analyst"

    asyncio.run(_run())


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F2")
@pytest.mark.feature("V21-F5")
@pytest.mark.feature("V21-F6")
@pytest.mark.feature("V21-F8")
def test_t3_v21_19_cli_secrets_crud_map_unmap_masked_fields_and_es_tenant_cli(
    mock_vault_server: MockHashiCorpVaultServer,
    mock_splunk_es_server: MockSplunkESServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.settings import save_profile_settings

    save_profile_settings(
        {
            "secret_provider": "hashicorp_vault",
            "vault_addr": mock_vault_server.base_url,
            "vault_auth_mode": "token",
            "vault_kv_mount": "secret",
            "splunk_host": mock_splunk_es_server.base_url,
            "splunk_verify_ssl": "false",
        }
    )

    test_proc = run_cli(["secrets", "test", "--json"])
    assert test_proc.returncode == 0, test_proc.stderr + test_proc.stdout

    list_proc = run_cli(["secrets", "list", "--search", "splunk", "--json"])
    assert list_proc.returncode == 0, list_proc.stderr + list_proc.stdout
    assert "soclens/splunk" in list_proc.stdout

    fields_masked = run_cli(["secrets", "fields", "soclens/splunk", "--json"])
    assert fields_masked.returncode == 0, fields_masked.stderr + fields_masked.stdout
    assert "e2e-vault-splunk-token" not in fields_masked.stdout

    fields_reveal = run_cli(["secrets", "fields", "soclens/splunk", "--reveal", "--json"])
    assert fields_reveal.returncode == 0, fields_reveal.stderr + fields_reveal.stdout
    assert "e2e-vault-splunk-token" in fields_reveal.stdout

    map_proc = run_cli(
        ["secrets", "map", "splunk_token", "hashicorp_vault:soclens/splunk:token", "--json"]
    )
    assert map_proc.returncode == 0, map_proc.stderr + map_proc.stdout

    invalid_map = run_cli(
        ["secrets", "map", "not_a_real_key", "hashicorp_vault:soclens/splunk:token", "--json"]
    )
    assert invalid_map.returncode != 0

    mock_splunk_es_server.valid_tokens.add("e2e-vault-splunk-token")
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    es_proc = run_cli(["splunk", "es", "notables", "--tenant", "1001", "--format", "json"])
    assert es_proc.returncode == 0, es_proc.stderr + es_proc.stdout
    payload = json.loads(es_proc.stdout)
    rows = (
        payload
        if isinstance(payload, list)
        else (payload.get("notables") or payload.get("items") or [])
    )
    assert rows
    assert all(str(row.get("tenant_id")) == "1001" for row in rows)

    unmap_proc = run_cli(["secrets", "unmap", "splunk_token", "--json"])
    assert unmap_proc.returncode == 0, unmap_proc.stderr + unmap_proc.stdout


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("V21-F4")
@pytest.mark.feature("V21-F13")
@pytest.mark.feature("V21-F14")
def test_t3_v21_20_pivot_f9_to_rf_intel_and_research_and_llm_api_key_auth(
    mock_op_connect_server: MockOnePasswordConnectServer,
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
    mock_llm_server: MockLocalLLMServer,
    v21_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, Select, TabbedContent

    from soclens.config import (
        get_local_llm_config,
        get_rf_token,
        hydrate_secrets_from_store,
    )
    from soclens.settings import (
        mask_secret,
        save_profile_settings,
        serialize_vault_secret_map,
    )
    from soclens.tui.app import create_app
    from soclens.tui.pivot import PivotPayload
    from soclens.tui.screens.base import DoubleClickDataTable
    from soclens.tui.screens.splunk_es import SplunkESPane

    fixtures = _load_fixture_json("v21_secret_stores.json")
    op_map = fixtures["onepassword_connect"]["recommended_map"]

    save_profile_settings(
        {
            "secret_provider": "onepassword_connect",
            "op_connect_url": mock_op_connect_server.base_url,
            "op_connect_token": "e2e-op-connect-token-001",
            "vault_secret_map": serialize_vault_secret_map(
                {
                    "rf_api_token": op_map["rf_api_token"],
                    "rf_llm_api_key": op_map["rf_llm_api_key"],
                }
            ),
            "rf_llm_provider": "openai",
            "rf_llm_base_url": mock_llm_server.openai_base_url,
            "rf_llm_model": "qwen2.5-coder:7b",
        }
    )

    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)
    monkeypatch.delenv("RF_LLM_API_KEY", raising=False)
    monkeypatch.setenv("RF_LLM_PROVIDER", "openai")
    monkeypatch.setenv("RF_LLM_BASE_URL", mock_llm_server.openai_base_url)
    monkeypatch.setenv("RF_LLM_MODEL", "qwen2.5-coder:7b")

    mock_rf_server.valid_rf_tokens.add("e2e-op-rf-api-token")
    mock_llm_server.set_required_api_key("e2e-op-llm-api-key")

    hydrated = hydrate_secrets_from_store(force=True)
    assert hydrated["rf_api_token"] == mask_secret("e2e-op-rf-api-token")
    assert hydrated["rf_llm_api_key"] == mask_secret("e2e-op-llm-api-key")
    assert get_rf_token() == "e2e-op-rf-api-token"
    assert get_local_llm_config().api_key == "e2e-op-llm-api-key"

    async def _run() -> None:
        app = create_app(
            dry_run=False,
            initial_tab="tab-splunk-es",
            workspace_dir=v21_workspace,
        )
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            dispatcher = getattr(app, "dispatch_pivot", None)
            assert callable(dispatcher), "SocLensApp.dispatch_pivot must be implemented in M4"

            es_pane = app.query_one(SplunkESPane)
            es_pane.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.click("#es-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            es_table = es_pane.query_one("#es-table", DoubleClickDataTable)
            _select_table_row_containing(es_table, es_pane._displayed_rows, "fnd-1001-a")
            await pilot.pause()
            row = es_pane.get_selected_row()
            assert row is not None

            mock_rf_server.requests_log.clear()
            assert dispatcher(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-rf-intel",
                    tenant_id="1001",
                    entity="198.51.100.10",
                    entity_type="ip",
                    src_ip="198.51.100.10",
                    auto_run=True,
                    es_finding=dict(row),
                )
            )
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-rf-intel"
            assert any(
                r["headers"].get("X-RFToken") == "e2e-op-rf-api-token"
                and (
                    "198.51.100.10" in r["path"]
                    or "198.51.100.10" in json.dumps(r.get("json_body") or {})
                )
                for r in mock_rf_server.requests_log
            )

            mock_rf_server.requests_log.clear()
            assert dispatcher(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-research",
                    tenant_id="1001",
                    entity="198.51.100.10",
                    entity_type="ip",
                    src_ip="198.51.100.10",
                    auto_run=True,
                    es_finding=dict(row),
                )
            )
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-research"
            assert any(
                r["headers"].get("X-RFToken") == "e2e-op-rf-api-token"
                for r in mock_rf_server.requests_log
            )

            assert dispatcher(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-llm",
                    tenant_id="1001",
                    entity="198.51.100.10",
                    src_ip="198.51.100.10",
                    auto_run=False,
                    es_finding=dict(row),
                )
            )
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-llm"
            assert app.query_one("#llm-provider-select", Select).value == "openai"

            await pilot.click("#llm-send-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["path"] == "/v1/chat/completions"
                and r["headers"].get("Authorization") == "Bearer e2e-op-llm-api-key"
                for r in mock_llm_server.requests_log
            )

    asyncio.run(_run())
