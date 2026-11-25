"""Tier 2 boundary, error-handling, AST, and layout E2E tests for Pivots, Copilot & TUI (V21-F13..V21-F15)."""

from __future__ import annotations

import ast
import asyncio
import ipaddress
import json
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from soclens.config import (
    LocalLLMConfig,
    PivotPayload,
    SecretStoreConfig,
    SentinelOneConfig,
    SplunkConfig,
    classify_site_tier,
    get_local_llm_config,
    get_s1_tier_config,
    hydrate_secrets_from_store,
)
from soclens.llm import (
    SOC_PROMPT_TEMPLATES,
    LocalLLMClient,
    LocalLLMConfigError,
    LocalLLMError,
)
from soclens.settings import save_profile_settings
from soclens.tui.pivot import build_spl_from_pivot, format_copilot_context
from tests.e2e import v21_mocks as _v21_mocks

if TYPE_CHECKING:
    from tests.e2e.conftest import MockRFServer
    from tests.e2e.v21_mocks import (
        MockHashiCorpVaultServer,
        MockLocalLLMServer,
        MockSentinelOneServer,
        MockSplunkESServer,
    )

pytestmark = [pytest.mark.e2e, pytest.mark.tier2]

REPO_ROOT = Path(__file__).resolve().parents[2]
POSIX_ONLY_MODULES = frozenset(
    {"fcntl", "termios", "tty", "pty", "pwd", "grp", "resource", "curses", "syslog", "posix"}
)

v21_workspace = _v21_mocks.v21_workspace
mock_vault_server = _v21_mocks.mock_vault_server
mock_splunk_es_server = _v21_mocks.mock_splunk_es_server
mock_s1_server = _v21_mocks.mock_s1_server
mock_llm_server = _v21_mocks.mock_llm_server


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


# ======================================================================
# V21-F13: Cross-Workbench Pivot Bus (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F13")
def test_v21_f13_f8_arbitrary_spl_and_ioc_pivots_never_auto_run(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import TextArea

    from soclens.tui.app import create_app

    arbitrary_payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-splunk-search",
        tenant_id="1001",
        src_ip="198.51.100.10",
        spl_query="index=main | head 5",
        auto_run=True,  # must be ignored for non-orig_sid SPL
    )
    spl_arb, run_arb = build_spl_from_pivot(arbitrary_payload)
    assert spl_arb == "index=main | head 5"
    assert run_arb is False

    ioc_payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-splunk-search",
        tenant_id="1001",
        src_ip="198.51.100.10",
        sha1="a" * 40,
        auto_run=True,
    )
    spl_ioc, run_ioc = build_spl_from_pivot(ioc_payload)
    assert "tenant_id=" in spl_ioc and "198.51.100.10" in spl_ioc
    assert run_ioc is False

    app = create_app(client=MagicMock(), dry_run=False, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            assert callable(getattr(app, "dispatch_pivot", None))
            req_before = len(mock_splunk_es_server.requests_log)
            app.dispatch_pivot(arbitrary_payload)
            await _wait_until(
                pilot,
                lambda: len(list(app.query("#splunk-search-spl"))) == 1
                and app.query_one("#splunk-search-spl", TextArea).text == "index=main | head 5",
            )
            await pilot.pause(0.1)
            assert not [
                r
                for r in mock_splunk_es_server.requests_log[req_before:]
                if r["method"] == "POST" and "/search/jobs" in r["path"]
            ]

    asyncio.run(_run())


@pytest.mark.feature("V21-F13")
def test_v21_f13_f8_orig_sid_only_triggers_auto_run_true(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import TextArea

    from soclens.tui.app import create_app

    sid_payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-splunk-search",
        orig_sid="1700000100.11",
        spl_query="index=ignored_when_orig_sid_present",
        auto_run=False,
    )
    spl, auto_run = build_spl_from_pivot(sid_payload)
    assert spl == '| loadjob "1700000100.11"'
    assert auto_run is True

    app = create_app(client=MagicMock(), dry_run=False, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            assert callable(getattr(app, "dispatch_pivot", None))
            app.dispatch_pivot(sid_payload)
            await _wait_until(
                pilot,
                lambda: len(list(app.query("#splunk-search-spl"))) == 1
                and '| loadjob "1700000100.11"'
                in app.query_one("#splunk-search-spl", TextArea).text,
            )
            await _wait_until(
                pilot,
                lambda: any(
                    r["method"] == "POST" and "/search/jobs" in r["path"]
                    for r in mock_splunk_es_server.requests_log
                ),
            )

    asyncio.run(_run())


@pytest.mark.feature("V21-F13")
def test_v21_f13_s1_site_tenant_map_override_precedence_over_regex(
    v21_workspace: Path,
) -> None:
    site_map = {
        "MDR-1001": "TENANT-OVR-99",
        "100102": "TENANT-ID-OVR",
    }
    tier_cfg = get_s1_tier_config(site_tenant_map=site_map)
    assert tier_cfg.classify_site("MDR-1001", site_id="100101") == (
        "MDR",
        "1001",
        "TENANT-OVR-99",
    )
    assert classify_site_tier("MDR-1001", site_id="100101", site_tenant_map=site_map) == (
        "MDR",
        "TENANT-OVR-99",
    )
    assert classify_site_tier("MDR-1002", site_id="100102", site_tenant_map=site_map) == (
        "MDR",
        "TENANT-ID-OVR",
    )
    assert classify_site_tier("Corp-Sandbox-3001", site_id="300101", site_tenant_map=site_map) == (
        "Other",
        None,
    )


@pytest.mark.feature("V21-F13")
def test_v21_f13_spl_quote_escaping_and_empty_payload_boundary() -> None:
    sid_payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-splunk-search",
        orig_sid='sid-"quoted"\\test',
    )
    sid_spl, sid_auto = build_spl_from_pivot(sid_payload)
    assert sid_spl == '| loadjob "sid-\\"quoted\\"\\\\test"'
    assert sid_auto is True

    host_payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-splunk-search",
        hostname='ws-"01"\\corp',
    )
    host_spl, host_auto = build_spl_from_pivot(host_payload)
    assert host_spl == 'search host="ws-\\"01\\"\\\\corp"'
    assert host_auto is False

    empty_payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-splunk-search",
    )
    assert build_spl_from_pivot(empty_payload) == ("search *", False)


@pytest.mark.feature("V21-F13")
def test_v21_f13_missing_tenant_dash_does_not_leak_into_pivot_or_s1_filter(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import Input

    from soclens.tui.app import create_app
    from soclens.tui.screens.sentinelone import SentinelOnePane
    from soclens.tui.screens.splunk_es import SplunkESPane

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-splunk-es")
            await _wait_until(pilot, lambda: len(list(app.query(SplunkESPane))) == 1)
            es_pane = app.query_one(SplunkESPane)
            payload = es_pane._build_pivot_payload(
                "tab-sentinelone",
                {
                    "event_id": "fnd-unassigned",
                    "tenant_id": "-",
                    "rule_title": "Unattributed Event",
                },
            )
            assert payload.tenant_id is None

            app.activate_tab("tab-sentinelone")
            await _wait_until(pilot, lambda: len(list(app.query(SentinelOnePane))) == 1)
            s1_pane = app.query_one(SentinelOnePane)
            s1_pane.accept_pivot(payload)
            await pilot.pause()
            assert s1_pane.query_one("#s1-filter-input", Input).value != "-"

    asyncio.run(_run())


@pytest.mark.feature("V21-F13")
def test_v21_f13_lazy_unmounted_target_tab_accepts_pivot_cleanly(
    v21_workspace: Path,
    mock_rf_server: MockRFServer,
    mock_splunk_es_server: MockSplunkESServer,
    mock_s1_server: MockSentinelOneServer,
    mock_llm_server: MockLocalLLMServer,
) -> None:
    from textual.widgets import Input, RichLog, Static, TabbedContent, TextArea

    from soclens.client import RecordedFutureClient
    from soclens.tui.app import create_app
    from soclens.tui.screens.llm import LocalLLMPane
    from soclens.tui.screens.rf_intel import RFIntelPane
    from soclens.tui.screens.sentinelone import SentinelOnePane
    from soclens.tui.screens.splunk_search import SplunkSearchPane

    rf_token = next(iter(sorted(mock_rf_server.valid_rf_tokens)))
    rf_client = RecordedFutureClient(api_token=rf_token, base_url=mock_rf_server.base_url)
    app = create_app(client=rf_client, dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            assert callable(getattr(app, "dispatch_pivot", None))
            tabs = app.query_one("#main-tabs", TabbedContent)

            splunk_payload = PivotPayload(
                source_tab="tab-splunk-es",
                target_tab="tab-splunk-search",
                tenant_id="1001",
                src_ip="198.51.100.10",
            )
            assert app.dispatch_pivot(splunk_payload) is True
            await _wait_until(
                pilot,
                lambda: len(list(app.query(SplunkSearchPane))) == 1
                and tabs.active == "tab-splunk-search"
                and "198.51.100.10" in app.query_one("#splunk-search-spl", TextArea).text,
            )
            spl_text = app.query_one("#splunk-search-spl", TextArea).text
            assert "1001" in spl_text and "198.51.100.10" in spl_text

            s1_payload = PivotPayload(
                source_tab="tab-splunk-es",
                target_tab="tab-sentinelone",
                sha1="a" * 40,
                tenant_id="1001",
            )
            assert app.dispatch_pivot(s1_payload) is True
            await _wait_until(
                pilot,
                lambda: len(list(app.query(SentinelOnePane))) == 1
                and tabs.active == "tab-sentinelone"
                and (
                    "a" * 40 in app.query_one("#s1-filter-input", Input).value
                    or "1001" in app.query_one("#s1-filter-input", Input).value
                ),
            )
            s1_filter = app.query_one("#s1-filter-input", Input).value
            assert "a" * 40 in s1_filter or "1001" in s1_filter

            rf_payload = PivotPayload(
                source_tab="tab-splunk-es",
                target_tab="tab-rf-intel",
                entity="198.51.100.10",
                entity_type="ip",
            )
            assert app.dispatch_pivot(rf_payload) is True
            await _wait_until(
                pilot,
                lambda: len(list(app.query(RFIntelPane))) == 1
                and tabs.active == "tab-rf-intel"
                and (
                    "198.51.100.10" in app.query_one("#rf-ioc-input", Input).value
                    or "198.51.100.10" in app.query_one("#rf-query-input", Input).value
                    or "198.51.100.10" in str(app.query_one("#rf-status", Static).render())
                )
                and any(
                    "/v2/ip/198.51.100.10" in str(req.get("path", ""))
                    for req in mock_rf_server.requests_log
                ),
            )
            assert any(
                "/v2/ip/198.51.100.10" in str(req.get("path", ""))
                for req in mock_rf_server.requests_log
            )

            llm_payload = PivotPayload(
                source_tab="tab-splunk-es",
                target_tab="tab-llm",
                tenant_id="1001",
                es_finding={"event_id": "fnd-1001-a"},
            )
            assert app.dispatch_pivot(llm_payload) is True
            await _wait_until(
                pilot,
                lambda: len(list(app.query(LocalLLMPane))) == 1
                and tabs.active == "tab-llm"
                and app.query_one("#llm-context-badge", Static).display is True,
            )
            transcript = "\n".join(
                line.text for line in app.query_one("#llm-transcript", RichLog).lines
            )
            assert "[CONTEXT ATTACHED]" in transcript
            assert app.is_running

    try:
        asyncio.run(_run())
    finally:
        rf_client.session.close()


# ======================================================================
# V21-F14: Local LLM (F7) Triage Copilot (5 tests)
# ======================================================================


@pytest.mark.feature("V21-F14")
def test_v21_f14_missing_s1_and_rf_data_bundles_gracefully_for_f7() -> None:
    payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-llm",
        tenant_id="1001",
        es_finding={"event_id": "fnd-1001-a", "urgency": "critical"},
        s1_threat=None,
        rf_enrichment=None,
    )
    title, body = format_copilot_context(payload)
    assert "Tenant 1001" in title
    assert "## Splunk ES Finding" in body
    assert "SentinelOne Threat" not in body
    assert "Recorded Future Enrichment" not in body
    assert "```json\nnull\n```" not in body


@pytest.mark.feature("V21-F14")
def test_v21_f14_open_llm_with_context_attaches_without_auto_sending(
    v21_workspace: Path,
    mock_llm_server: MockLocalLLMServer,
) -> None:
    from textual.widgets import RichLog, Static

    from soclens.tui.app import create_app

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            assert callable(getattr(app, "dispatch_pivot", None))
            req_before = len(mock_llm_server.requests_log)
            payload = PivotPayload(
                source_tab="tab-splunk-es",
                target_tab="tab-llm",
                tenant_id="1001",
                es_finding={"event_id": "fnd-1001-a"},
            )
            assert app.dispatch_pivot(payload) is True
            await _wait_until(
                pilot,
                lambda: len(list(app.query("#llm-context-badge"))) == 1
                and app.query_one("#llm-context-badge", Static).display is True,
            )
            transcript = "\n".join(
                line.text for line in app.query_one("#llm-transcript", RichLog).lines
            )
            assert "[CONTEXT ATTACHED]" in transcript
            await pilot.pause(0.1)
            assert not [
                r
                for r in mock_llm_server.requests_log[req_before:]
                if r["method"] == "POST" and r["path"] in {"/api/chat", "/v1/chat/completions"}
            ]

    asyncio.run(_run())


@pytest.mark.feature("V21-F14")
def test_v21_f14_openai_rf_llm_api_key_401_and_v1_url_normalization(
    v21_workspace: Path,
    mock_vault_server: MockHashiCorpVaultServer,
    mock_llm_server: MockLocalLLMServer,
) -> None:
    from soclens.config import ConfiguredSession

    mock_llm_server.set_required_api_key("e2e-vault-llm-api-key")
    canary_bad_key = "wrong-llm-api-key-999"

    with LocalLLMClient(
        provider="openai",
        base_url=mock_llm_server.base_url,
        model="qwen2.5-coder:7b",
        api_key=canary_bad_key,
        max_retries=0,
    ) as bad_client:
        assert isinstance(bad_client.session, ConfiguredSession)
        with pytest.raises(LocalLLMError) as exc_info:
            bad_client.chat([{"role": "user", "content": "Summarize alert"}])
        assert exc_info.value.status_code == 401
        assert canary_bad_key not in str(exc_info.value)

    save_profile_settings(
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
            "rf_llm_base_url": mock_llm_server.base_url,
            "rf_llm_model": "qwen2.5-coder:7b",
        }
    )
    hydrate_secrets_from_store(force=True)
    cfg = get_local_llm_config()
    assert cfg.api_key == "e2e-vault-llm-api-key"

    for url in (mock_llm_server.base_url, mock_llm_server.openai_base_url):
        with LocalLLMClient(
            provider="openai",
            base_url=url,
            model="qwen2.5-coder:7b",
            api_key=cfg.api_key,
        ) as ok_client:
            reply = ok_client.chat([{"role": "user", "content": "Hello copilot"}])
            assert reply


@pytest.mark.feature("V21-F14")
def test_v21_f14_llm_400_500_503_and_unknown_template_error_handling(
    mock_llm_server: MockLocalLLMServer,
) -> None:
    mock_llm_server.queue_fault("/api/chat", 503, {"error": "Model loading"}, method="POST")
    with LocalLLMClient(
        provider="ollama",
        base_url=mock_llm_server.base_url,
        model="llama3.2:latest",
        max_retries=0,
        backoff_base=0.01,
    ) as ollama_client:
        with pytest.raises(LocalLLMError) as exc_503:
            ollama_client.chat([{"role": "user", "content": "test"}])
        assert exc_503.value.status_code == 503

        with pytest.raises(LocalLLMConfigError):
            ollama_client.analyze_with_template("nonexistent_template_xyz", "context")

    mock_llm_server.queue_fault(
        "/v1/chat/completions",
        500,
        {"error": {"message": "Inference crash"}},
        method="POST",
    )
    with LocalLLMClient(
        provider="openai",
        base_url=mock_llm_server.openai_base_url,
        model="qwen2.5-coder:7b",
        max_retries=0,
        backoff_base=0.01,
    ) as openai_client:
        with pytest.raises(LocalLLMError) as exc_500:
            openai_client.chat([{"role": "user", "content": "test"}])
        assert exc_500.value.status_code == 500


@pytest.mark.feature("V21-F14")
def test_v21_f14_copilot_attack_chain_and_closing_note_templates_preserve_bundle(
    mock_llm_server: MockLocalLLMServer,
) -> None:
    attack_tpl = next(
        (k for k in SOC_PROMPT_TEMPLATES if "attack" in k or "chain" in k),
        None,
    )
    closing_tpl = next(
        (k for k in SOC_PROMPT_TEMPLATES if "closing" in k or "close" in k),
        None,
    )
    assert attack_tpl is not None, "Expected attack-chain Copilot template in SOC_PROMPT_TEMPLATES"
    assert closing_tpl is not None, "Expected closing-note Copilot template in SOC_PROMPT_TEMPLATES"

    payload = PivotPayload(
        source_tab="tab-splunk-es",
        target_tab="tab-llm",
        tenant_id="1001",
        es_finding={"event_id": "fnd-1001-a", "rule_title": "Suspicious LSASS Access"},
        s1_threat={"id": "thr-1001-1", "threatName": "Mimikatz.Win64"},
        rf_enrichment={"rf_max_risk_score": 92, "rf_criticality_label": "Very Malicious"},
    )
    _title, bundled = format_copilot_context(payload)

    with LocalLLMClient(
        provider="ollama",
        base_url=mock_llm_server.base_url,
        model="llama3.2:latest",
    ) as llm:
        r1 = llm.analyze_with_template(attack_tpl, bundled)
        r2 = llm.analyze_with_template(closing_tpl, bundled)

    assert r1 and r2
    chat_posts = [r for r in mock_llm_server.requests_log if r["path"] == "/api/chat"]
    assert len(chat_posts) == 2
    for post in chat_posts:
        joined = " ".join(str(m.get("content") or "") for m in post["json_body"]["messages"])
        assert "1001" in joined
        assert "fnd-1001-a" in joined
        assert "thr-1001-1" in joined
        assert "92" in joined


# ======================================================================
# V21-F15: TUI AST, Safety, 80x24 Layout, 0600 & Sanitization (7 tests)
# ======================================================================


@pytest.mark.feature("V21-F15")
def test_v21_f15_ast_zero_emojis_posix_imports_or_shell_true_across_tui() -> None:
    tui_root = REPO_ROOT / "soclens" / "tui"
    py_files = sorted(tui_root.rglob("*.py"))
    assert py_files
    expected_new = {
        tui_root / "pivot.py",
        tui_root / "screens" / "s1_modals.py",
        tui_root / "screens" / "es_modals.py",
    }
    assert expected_new.issubset(set(py_files))

    for py_file in py_files:
        src = py_file.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(py_file))
        emojis = [ch for ch in src if ord(ch) > 0x1F000]
        assert not emojis, f"Emoji character(s) found in {py_file}: {emojis!r}"

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    assert mod not in POSIX_ONLY_MODULES, f"POSIX-only import {mod} in {py_file}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                mod = node.module.split(".")[0]
                assert mod not in POSIX_ONLY_MODULES, f"POSIX-only import {mod} in {py_file}"
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "os" and node.func.attr in {"system", "fork", "killpg"}:
                        raise AssertionError(f"Unsafe os.{node.func.attr} call in {py_file}")
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        raise AssertionError(f"shell=True call in {py_file}")


@pytest.mark.feature("V21-F15")
def test_v21_f15_ast_dynamic_widgets_markup_false_and_worker_safety() -> None:
    tui_root = REPO_ROOT / "soclens" / "tui"
    v21_screens = (
        tui_root / "screens" / "splunk_es.py",
        tui_root / "screens" / "es_modals.py",
        tui_root / "screens" / "sentinelone.py",
        tui_root / "screens" / "s1_modals.py",
        tui_root / "screens" / "settings.py",
        tui_root / "screens" / "llm.py",
    )
    for py_file in v21_screens:
        src = py_file.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"Static", "RichLog"}:
                    id_kw = next(
                        (
                            kw.value.value
                            for kw in node.keywords
                            if kw.arg == "id" and isinstance(kw.value, ast.Constant)
                        ),
                        None,
                    )
                    if id_kw:
                        has_markup_false = any(
                            kw.arg == "markup"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is False
                            for kw in node.keywords
                        )
                        assert has_markup_false, (
                            f"{node.func.id}(id={id_kw!r}) missing markup=False in {py_file.name}:{node.lineno}"
                        )

    for py_file in sorted(tui_root.rglob("*.py")):
        src = py_file.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if (
                        isinstance(dec, ast.Call)
                        and isinstance(dec.func, ast.Name)
                        and dec.func.id == "work"
                    ):
                        kws = {kw.arg: kw.value for kw in dec.keywords if kw.arg}
                        assert (
                            isinstance(kws.get("thread"), ast.Constant)
                            and kws["thread"].value is True
                        ), f"@work missing thread=True on {node.name} in {py_file.name}"
                        assert (
                            isinstance(kws.get("exit_on_error"), ast.Constant)
                            and kws["exit_on_error"].value is False
                        ), f"@work missing exit_on_error=False on {node.name} in {py_file.name}"


def _node_inside_prevent(with_stack: list[ast.With | ast.AsyncWith]) -> bool:
    for with_node in with_stack:
        for item in with_node.items:
            ctx = item.context_expr
            if (
                isinstance(ctx, ast.Call)
                and isinstance(ctx.func, ast.Attribute)
                and ctx.func.attr == "prevent"
            ):
                return True
    return False


def _is_query_one_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "query_one"
    )


def _classify_widget_expr(expr: ast.AST) -> str | None:
    """Return 'vault_select', 'select', 'non_select', or None for a widget construction/query."""
    if _is_query_one_call(expr):
        assert isinstance(expr, ast.Call)
        args = expr.args
        arg0_src = ast.unparse(args[0]).lower() if args else ""
        arg1_name = ""
        if len(args) >= 2 and isinstance(args[1], ast.Name):
            arg1_name = args[1].id
        elif len(args) >= 2 and isinstance(args[1], ast.Attribute):
            arg1_name = args[1].attr

        if arg1_name in {"Input", "Checkbox", "Static", "Button", "Label"}:
            return "non_select"
        is_vault_id = "-vault" in arg0_src or "set-secret-provider" in arg0_src
        if arg1_name == "Select":
            return "vault_select" if is_vault_id else "select"
        if is_vault_id:
            return "vault_select"
        return None

    if isinstance(expr, ast.Call):
        cls_name = ""
        if isinstance(expr.func, ast.Name):
            cls_name = expr.func.id
        elif isinstance(expr.func, ast.Attribute):
            cls_name = expr.func.attr
        if cls_name == "Select":
            return "select"
        if cls_name in {"Input", "Checkbox", "Static", "Button", "Label"}:
            return "non_select"
    return None


def _function_touches_vault_dropdowns(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    fn_low = fn.name.lower()
    if any(tok in fn_low for tok in ("vault", "secret_provider", "provider_controls")):
        return True
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val_low = node.value.lower()
            if "-vault" in val_low or "set-secret-provider" in val_low:
                return True
        elif isinstance(node, ast.Attribute) and node.attr == "_populate_vault_dropdowns":
            return True
        elif isinstance(node, ast.Name) and node.id == "_populate_vault_dropdowns":
            return True
    return False


def _find_settings_prevent_violations(src: str) -> list[str]:
    tree = ast.parse(src)
    violations: list[str] = []

    class _FnVisitor(ast.NodeVisitor):
        def __init__(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            fn_low = fn.name.lower()
            self.is_vault_fn = any(
                tok in fn_low for tok in ("vault", "secret_provider", "provider_controls")
            )
            self.with_stack: list[ast.With | ast.AsyncWith] = []
            self.vault_select_vars: set[str] = set()
            self.any_select_vars: set[str] = set()
            self.non_select_vars: set[str] = set()

            for arg in list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs):
                ann = ast.unparse(arg.annotation) if arg.annotation is not None else ""
                if "Select" in ann:
                    self.any_select_vars.add(arg.arg)
                    if self.is_vault_fn or "vault" in arg.arg.lower():
                        self.vault_select_vars.add(arg.arg)
                elif self.is_vault_fn and arg.arg in {
                    "sel",
                    "select",
                    "vault_sel",
                    "prov_sel",
                    "provider_sel",
                    "dropdown",
                }:
                    self.vault_select_vars.add(arg.arg)

        def visit_With(self, node: ast.With) -> None:
            self.with_stack.append(node)
            self.generic_visit(node)
            self.with_stack.pop()

        def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
            self.with_stack.append(node)
            self.generic_visit(node)
            self.with_stack.pop()

        def visit_Assign(self, node: ast.Assign) -> None:
            rhs_kind = _classify_widget_expr(node.value)
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    if rhs_kind == "vault_select":
                        self.vault_select_vars.add(tgt.id)
                        self.any_select_vars.add(tgt.id)
                        self.non_select_vars.discard(tgt.id)
                    elif rhs_kind == "select":
                        self.any_select_vars.add(tgt.id)
                        if self.is_vault_fn:
                            self.vault_select_vars.add(tgt.id)
                        self.non_select_vars.discard(tgt.id)
                    elif rhs_kind == "non_select":
                        self.non_select_vars.add(tgt.id)
                        self.vault_select_vars.discard(tgt.id)
                        self.any_select_vars.discard(tgt.id)
                elif isinstance(tgt, ast.Attribute) and tgt.attr == "value":
                    if self._is_guarded_select_target(tgt.value) and not _node_inside_prevent(
                        self.with_stack
                    ):
                        violations.append(
                            f"L{node.lineno}: {ast.unparse(tgt)} = ... outside with ...prevent(...)"
                        )
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if isinstance(node.target, ast.Name):
                ann = ast.unparse(node.annotation)
                if "Select" in ann:
                    self.any_select_vars.add(node.target.id)
                    if self.is_vault_fn or "vault" in node.target.id.lower():
                        self.vault_select_vars.add(node.target.id)
                elif any(tok in ann for tok in ("Input", "Checkbox", "Static", "Button")):
                    self.non_select_vars.add(node.target.id)
                if node.value is not None:
                    rhs_kind = _classify_widget_expr(node.value)
                    if rhs_kind == "vault_select":
                        self.vault_select_vars.add(node.target.id)
                    elif rhs_kind == "non_select":
                        self.non_select_vars.add(node.target.id)
                        self.vault_select_vars.discard(node.target.id)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "set_options"
                and (self.is_vault_fn or self._is_guarded_select_target(node.func.value))
                and not _node_inside_prevent(self.with_stack)
            ):
                violations.append(f"L{node.lineno}: set_options() outside with ...prevent(...)")
            self.generic_visit(node)

        def _is_guarded_select_target(self, expr: ast.AST) -> bool:
            expr_kind = _classify_widget_expr(expr)
            if expr_kind == "vault_select":
                return True
            if expr_kind == "select":
                return self.is_vault_fn
            if expr_kind == "non_select":
                return False
            if isinstance(expr, ast.Name):
                if expr.id in self.non_select_vars:
                    return False
                if expr.id in self.vault_select_vars:
                    return True
                if self.is_vault_fn and expr.id in self.any_select_vars:
                    return True
                if self.is_vault_fn and expr.id in {
                    "sel",
                    "select",
                    "vault_sel",
                    "prov_sel",
                    "provider_sel",
                    "dropdown",
                }:
                    return True
            return False

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _function_touches_vault_dropdowns(node):
                _FnVisitor(node).visit(node)

    return violations


@pytest.mark.feature("V21-F15")
def test_v21_f15_ast_settings_dropdown_updates_wrapped_in_prevent() -> None:
    settings_py = REPO_ROOT / "soclens" / "tui" / "screens" / "settings.py"
    src = settings_py.read_text(encoding="utf-8")
    assert "cat-secrets" in src and "set-secret-provider" in src and "vault_secret_map" in src, (
        "SettingsPane must implement cat-secrets vault dropdown integration"
    )
    violations = _find_settings_prevent_violations(src)
    assert not violations, "; ".join(violations)


@pytest.mark.feature("V21-F15")
def test_v21_f15_80x24_clip_free_layout_es_and_s1_workbenches(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import Button, DataTable, RichLog, TabPane

    from soclens.tui.app import create_app
    from soclens.tui.screens.sentinelone import SentinelOnePane
    from soclens.tui.screens.splunk_es import SplunkESPane

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        workspace_dir=v21_workspace,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            app.activate_tab("tab-splunk-es")
            await _wait_until(pilot, lambda: len(list(app.query(SplunkESPane))) == 1)
            es_tab = app.query_one("#tab-splunk-es", TabPane)
            es_pane = app.query_one(SplunkESPane)
            await pilot.pause()
            assert es_tab.region.width == 80
            assert es_tab.region.height >= 19
            assert es_pane.region.width >= 76
            assert es_pane.region.height >= 19
            es_table = es_pane.query_one("#es-table", DataTable)
            es_detail = es_pane.query_one("#es-detail", RichLog)
            assert es_table.region.width > 0 and es_table.region.height > 0
            assert es_detail.region.width > 0 and es_detail.region.height > 0

            app.activate_tab("tab-sentinelone")
            await _wait_until(pilot, lambda: len(list(app.query(SentinelOnePane))) == 1)
            s1_tab = app.query_one("#tab-sentinelone", TabPane)
            s1_pane = app.query_one(SentinelOnePane)
            for wb_btn in (
                "#s1-wb-alerts-btn",
                "#s1-wb-sites-btn",
                "#s1-wb-users-btn",
                "#s1-wb-exclusions-btn",
                "#s1-wb-agents-btn",
            ):
                s1_pane.query_one(wb_btn, Button).press()
                await pilot.pause()
                assert s1_tab.region.width == 80
                assert s1_tab.region.height >= 19
                assert s1_pane.region.width >= 76
                assert s1_pane.region.height >= 19
                s1_table = s1_pane.query_one("#s1-table", DataTable)
                s1_detail = s1_pane.query_one("#s1-detail-log", RichLog)
                assert s1_table.region.width > 0 and s1_table.region.height > 0
                assert s1_detail.region.width > 0 and s1_detail.region.height > 0

    asyncio.run(_run())


@pytest.mark.feature("V21-F15")
def test_v21_f15_80x24_clip_free_layout_settings_cat_secrets_and_modals(
    v21_workspace: Path,
) -> None:
    from textual.widgets import Button, Input, OptionList, Select, TabPane

    from soclens.tui.app import create_app
    from soclens.tui.screens.es_modals import ESAdaptiveResponseModal
    from soclens.tui.screens.s1_modals import ConfirmDeleteSiteModal
    from soclens.tui.screens.settings import SettingsPane

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            app.activate_tab("tab-settings")
            await _wait_until(pilot, lambda: len(list(app.query(SettingsPane))) == 1)
            tab_pane = app.query_one("#tab-settings", TabPane)
            pane = app.query_one(SettingsPane)
            await pilot.pause()
            assert tab_pane.region.width == 80
            assert tab_pane.region.height >= 19
            assert pane.region.width >= 76
            assert pane.region.height >= 19

            cat_list = pane.query_one("#settings-category-list", OptionList)
            secrets_idx = next(
                i
                for i in range(cat_list.option_count)
                if getattr(cat_list.get_option_at_index(i), "id", None) == "cat-secrets"
            )
            cat_list.highlighted = secrets_idx
            cat_list.action_select()
            await pilot.pause()

            prov_sel = pane.query_one("#set-secret-provider", Select)
            assert prov_sel.region.width > 0 and prov_sel.region.height > 0
            provider_groups = (
                ("secret_server", "#tss-fields-group"),
                ("hashicorp_vault", "#vault-fields-group"),
                ("onepassword_connect", "#op-fields-group"),
                ("bitwarden", "#bw-fields-group"),
            )
            for provider, group_id in provider_groups:
                prov_sel.value = provider
                await _wait_until(
                    pilot,
                    lambda gid=group_id: pane.query_one(gid).display is True
                    and pane.query_one(gid).region.width > 0
                    and pane.query_one(gid).region.height > 0,
                )
                group = pane.query_one(group_id)
                assert group.display is True
                assert group.region.width > 0 and group.region.height > 0

            cat_list.highlighted = 0
            cat_list.action_select()
            await _wait_until(
                pilot,
                lambda: pane.query_one("#set-rf-api-token-vault", Select).display is True
                and pane.query_one("#set-rf-api-token-vault", Select).region.width > 0,
            )
            rf_vault_sel = pane.query_one("#set-rf-api-token-vault", Select)
            assert rf_vault_sel.region.width > 0 and rf_vault_sel.region.height > 0

            del_modal = ConfirmDeleteSiteModal(
                site_id="100101",
                site_name="MDR-1001",
                tier="MDR",
                active_agents=2,
                dry_run=True,
            )
            await app.push_screen(del_modal)
            await pilot.pause()
            await _wait_until(
                pilot,
                lambda: app.screen is del_modal
                and del_modal.is_mounted
                and len(list(del_modal.query("#s1-del-site-dialog"))) == 1
                and del_modal.query_one("#s1-del-site-dialog").region.width > 0,
            )
            del_dialog = del_modal.query_one("#s1-del-site-dialog")
            assert 0 < del_dialog.region.width <= 80
            assert 0 < del_dialog.region.height <= 24
            assert del_modal.query_one("#s1-del-site-confirm-input", Input).region.width > 0
            assert del_modal.query_one("#s1-del-site-approve-btn", Button).region.height > 0
            del_modal.query_one("#s1-del-site-cancel-btn", Button).press()
            await _wait_until(pilot, lambda: app.screen is not del_modal)

            ar_modal = ESAdaptiveResponseModal(
                event_id="fnd-1001-a",
                orig_sid="1700000100.11",
                orig_rid="0",
                available_actions=[{"name": "ping", "label": "Ping Host"}],
                dry_run=True,
            )
            await app.push_screen(ar_modal)
            await pilot.pause()
            await _wait_until(
                pilot,
                lambda: app.screen is ar_modal
                and ar_modal.is_mounted
                and len(list(ar_modal.query("#es-ar-dialog"))) == 1
                and ar_modal.query_one("#es-ar-dialog").region.width > 0,
            )
            ar_dialog = ar_modal.query_one("#es-ar-dialog")
            assert 0 < ar_dialog.region.width <= 80
            assert 0 < ar_dialog.region.height <= 24
            assert ar_modal.query_one("#es-ar-action-select", Select).region.width > 0
            assert ar_modal.query_one("#es-ar-dispatch-btn", Button).region.height > 0
            ar_modal.query_one("#es-ar-close-btn", Button).press()
            await _wait_until(pilot, lambda: app.screen is not ar_modal)

    asyncio.run(_run())


@pytest.mark.feature("V21-F15")
def test_v21_f15_settings_json_0600_perms_and_dataclass_repr_false(
    v21_workspace: Path,
) -> None:
    settings_path = save_profile_settings({"rf_base_url": "https://rf.example.test"})
    assert stat.S_IMODE(settings_path.stat().st_mode) == 0o600

    canaries = {
        "tss_pw": "CANARY-TSS-PW-123",
        "tss_cs": "CANARY-TSS-CS-123",
        "tss_at": "CANARY-TSS-AT-123",
        "vault_tok": "CANARY-VAULT-TOK-123",
        "vault_sid": "CANARY-VAULT-SID-123",
        "op_tok": "CANARY-OP-TOK-123",
        "bw_pw": "CANARY-BW-PW-123",
        "splunk_tok": "CANARY-SPLUNK-TOK-123",
        "splunk_pw": "CANARY-SPLUNK-PW-123",
        "s1_tok": "CANARY-S1-TOK-123",
        "llm_key": "CANARY-LLM-KEY-123",
    }
    ss_cfg = SecretStoreConfig(
        provider="secret_server",
        tss_password=canaries["tss_pw"],
        tss_client_secret=canaries["tss_cs"],
        tss_access_token=canaries["tss_at"],
        vault_token=canaries["vault_tok"],
        vault_secret_id=canaries["vault_sid"],
        op_connect_token=canaries["op_tok"],
        bw_master_password=canaries["bw_pw"],
    )
    sp_cfg = SplunkConfig(
        host="https://splunk.example.test:8089",
        token=canaries["splunk_tok"],
        password=canaries["splunk_pw"],
    )
    s1_cfg = SentinelOneConfig(
        console_url="https://s1.example.test",
        api_token=canaries["s1_tok"],
    )
    llm_cfg = LocalLLMConfig(
        provider="openai",
        base_url="http://127.0.0.1:11434/v1",
        api_key=canaries["llm_key"],
    )
    combined_repr = " ".join(repr(c) for c in (ss_cfg, sp_cfg, s1_cfg, llm_cfg))
    for val in canaries.values():
        assert val not in combined_repr


@pytest.mark.feature("V21-F15")
def test_v21_f15_repo_and_fixtures_zero_nonsynthetic_markers() -> None:
    fixtures = sorted((REPO_ROOT / "tests" / "e2e" / "fixtures").glob("v21_*.json"))
    assert len(fixtures) == 4

    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    secret_prefix_re = re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|hvs\.[A-Za-z0-9]{16,})\b")
    allowed_test_nets = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("127.0.0.0/8"),
    )

    for fix in fixtures:
        text = fix.read_text(encoding="utf-8")
        assert not secret_prefix_re.search(text), f"Real-looking token prefix in {fix.name}"
        for raw_ip in ip_re.findall(text):
            addr = ipaddress.ip_address(raw_ip)
            assert any(addr in net for net in allowed_test_nets), (
                f"Non-RFC5737/loopback IP {raw_ip} in {fix.name}"
            )

    for py_file in sorted((REPO_ROOT / "soclens").rglob("*.py")):
        src = py_file.read_text(encoding="utf-8")
        assert not secret_prefix_re.search(src), f"Real-looking token prefix in {py_file}"
