"""Tier 1 E2E happy-path tests for SOCLens v2.1 Pivots, LLM Copilot & TUI Invariants (V21-F13..V21-F15)."""

from __future__ import annotations

import ast
import asyncio
import json
import os
import stat
import subprocess
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

import tests.e2e.v21_mocks as _v21
from soclens.config import (
    LocalLLMConfig,
    SecretStoreConfig,
    SentinelOneConfig,
    SplunkConfig,
    classify_site_tier,
)
from soclens.llm import LocalLLMClient
from soclens.settings import set_session_overrides
from soclens.tui.pivot import PivotPayload, build_spl_from_pivot, format_copilot_context

if TYPE_CHECKING:
    from tests.e2e.v21_mocks import (
        MockLocalLLMServer,
        MockRFServer,
        MockSentinelOneServer,
        MockSplunkESServer,
    )

v21_workspace = _v21.v21_workspace
mock_splunk_es_server = _v21.mock_splunk_es_server
mock_s1_server = _v21.mock_s1_server
mock_llm_server = _v21.mock_llm_server

pytestmark = [pytest.mark.e2e, pytest.mark.tier1]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POSIX_ONLY_MODULES = frozenset(
    {
        "fcntl",
        "grp",
        "pty",
        "pwd",
        "resource",
        "syslog",
        "termios",
        "tty",
    }
)


def _richlog_text(app: Any, selector: str) -> str:
    from textual.widgets import RichLog

    log = app.query_one(selector, RichLog)
    return "\n".join(line.text for line in log.lines)


# ==============================================================================
# V21-F13: Cross-Workbench Pivot Bus
# ==============================================================================


@pytest.mark.feature("V21-F13")
def test_v21_f13_s1_site_tenant_extraction_regex_and_override_map(
    v21_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert classify_site_tier("MDR-1001") == ("MDR", "1001")
    assert classify_site_tier("mssp_2001") == ("MSSP", "2001")
    assert classify_site_tier("Corp-Sandbox-3001") == ("Other", None)

    monkeypatch.setenv(
        "S1_SITE_TENANT_MAP",
        '{"Corp-Sandbox-3001":"3001","100102":"override-1002"}',
    )
    assert classify_site_tier("Corp-Sandbox-3001") == ("Other", "3001")
    assert classify_site_tier("MDR-1002", site_id="100102") == ("MDR", "override-1002")


@pytest.mark.feature("V21-F13")
def test_v21_f13_build_spl_from_pivot_orig_sid_auto_run_vs_ioc_manual(
    v21_workspace: Path,
) -> None:
    spl_sid, auto_sid = build_spl_from_pivot(PivotPayload(orig_sid="1700000100.11"))
    assert spl_sid == '| loadjob "1700000100.11"'
    assert auto_sid is True

    spl_ioc, auto_ioc = build_spl_from_pivot(
        PivotPayload(
            tenant_id="1001",
            src_ip="198.51.100.10",
            hostname="wkstn-1001-01.example.test",
        )
    )
    assert auto_ioc is False
    assert (
        spl_ioc
        == 'search tenant_id="1001" OR src="198.51.100.10" OR host="wkstn-1001-01.example.test"'
    )

    explicit_spl, auto_exp = build_spl_from_pivot(
        PivotPayload(spl_query="index=notable tenant_id=1001 | head 10")
    )
    assert explicit_spl == "index=notable tenant_id=1001 | head 10"
    assert auto_exp is False


@pytest.mark.feature("V21-F13")
def test_v21_f13_es_to_f8_splunk_search_orig_sid_auto_run_via_tui(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Checkbox, DataTable, TabbedContent, TextArea

    from soclens.tui import create_app

    app = create_app(
        dry_run=True,
        initial_tab="tab-splunk-es",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.pause()
            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#es-insp-pivot-search-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#main-tabs", TabbedContent).active == "tab-splunk-search"
            assert (
                app.query_one("#splunk-search-spl", TextArea).text.strip()
                == '| loadjob "1700000100.11"'
            )
            assert app.query_one("#splunk-search-table", DataTable).row_count == 2

    asyncio.run(_run())


@pytest.mark.feature("V21-F13")
def test_v21_f13_bidirectional_es_and_s1_pivot_via_tui(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    """Awaits Wave 2 (M4): SocLensApp.dispatch_pivot bidirectional F9 <-> 9 wiring."""
    from textual.widgets import Checkbox, DataTable, Input, TabbedContent

    from soclens.tui import create_app

    app = create_app(
        dry_run=True,
        initial_tab="tab-splunk-es",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.pause()
            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#es-insp-pivot-s1-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#main-tabs", TabbedContent).active == "tab-sentinelone"
            s1_filter = app.query_one("#s1-filter-input", Input).value
            assert "wkstn-1001-01.example.test" in s1_filter or "1001" in s1_filter
            assert app.query_one("#s1-table", DataTable).row_count >= 1

            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-pivot-es-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#main-tabs", TabbedContent).active == "tab-splunk-es"
            es_tenant = app.query_one("#es-filter-tenant", Input).value
            es_search = app.query_one("#es-search-input", Input).value
            assert es_tenant == "1001" or "tenant_id:1001" in es_search

    asyncio.run(_run())


@pytest.mark.feature("V21-F13")
def test_v21_f13_pivot_from_es_and_s1_to_rf_intel_and_research(
    v21_workspace: Path,
    mock_rf_server: MockRFServer,
    mock_splunk_es_server: MockSplunkESServer,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    """Awaits Wave 2 (M4): SocLensApp.dispatch_pivot wiring to tab-rf-intel and tab-research."""
    from textual.widgets import Input, TabbedContent

    from soclens.tui import create_app
    from soclens.tui.pivot import PivotPayload

    app = create_app(
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            mock_rf_server.requests_log.clear()
            await pilot.click("#s1-pivot-rf-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-rf-intel"
            assert mock_rf_server.requests_log

            app.dispatch_pivot(  # type: ignore[attr-defined]
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-research",
                    entity="203.0.113.45",
                    entity_type="ip",
                    tenant_id="1001",
                )
            )
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-research"
            assert "203.0.113.45" in app.query_one("#res-target-input", Input).value

    asyncio.run(_run())


@pytest.mark.feature("V21-F13")
def test_v21_f13_s1_to_f8_splunk_search_prefills_without_auto_run(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    """Awaits Wave 2 (M4): Pivot from S1 -> F8 Splunk Search pre-fills without auto-running."""
    from textual.widgets import TabbedContent, TextArea

    from soclens.tui import create_app
    from soclens.tui.pivot import PivotPayload

    app = create_app(
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            mock_splunk_es_server.requests_log.clear()

            app.dispatch_pivot(  # type: ignore[attr-defined]
                PivotPayload(
                    source_tab="tab-sentinelone",
                    target_tab="tab-splunk-search",
                    tenant_id="1001",
                    hostname="srv-1001-db.example.test",
                    sha1="a" * 40,
                    auto_run=False,
                )
            )
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#main-tabs", TabbedContent).active == "tab-splunk-search"
            spl_text = app.query_one("#splunk-search-spl", TextArea).text
            assert 'tenant_id="1001"' in spl_text
            assert "srv-1001-db.example.test" in spl_text
            assert not any(
                r["method"] == "POST" and "/search/jobs" in r["path"]
                for r in mock_splunk_es_server.requests_log
            )

    asyncio.run(_run())


# ==============================================================================
# V21-F14: Local LLM (F7) Triage Copilot
# ==============================================================================


@pytest.mark.feature("V21-F14")
def test_v21_f14_ollama_models_and_chat_nonstream_and_stream(
    mock_llm_server: MockLocalLLMServer,
) -> None:
    with LocalLLMClient(
        provider="ollama",
        base_url=mock_llm_server.ollama_base_url,
        model="llama3.2:latest",
    ) as client:
        models = client.list_models()
        assert models == ["llama3.2:latest", "qwen2.5-coder:7b"]

        non_stream = client.chat([{"role": "user", "content": "Summarize incident"}])
        assert non_stream["done"] is True
        assert "Attack chain summary:" in non_stream["content"]

        chunks: list[str] = []
        streamed = client.chat(
            [{"role": "user", "content": "Summarize incident"}],
            stream_callback=chunks.append,
        )
        assert streamed["done"] is True
        assert len(chunks) == 3
        assert "Attack chain summary:" in "".join(chunks)


@pytest.mark.feature("V21-F14")
def test_v21_f14_openai_compatible_with_rf_llm_api_key_auth(
    v21_workspace: Path,
    mock_llm_server: MockLocalLLMServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_llm_server.set_required_api_key("e2e-llm-api-key-001")
    monkeypatch.setenv("RF_LLM_PROVIDER", "openai")
    monkeypatch.setenv("RF_LLM_BASE_URL", mock_llm_server.openai_base_url)
    monkeypatch.setenv("RF_LLM_MODEL", "qwen2.5-coder:7b")
    set_session_overrides({"rf_llm_api_key": "e2e-llm-api-key-001"})

    with LocalLLMClient() as client:
        models = client.list_models()
        assert models == ["qwen2.5-coder:7b", "llama3.2:latest"]

        chunks: list[str] = []
        res = client.chat(
            [{"role": "user", "content": "[ES + Tenant 1001]"}],
            stream_callback=chunks.append,
        )
        assert "Closing Note:" in res["content"]

    assert any(
        r["headers"].get("Authorization") == "Bearer e2e-llm-api-key-001"
        or r["headers"].get("authorization") == "Bearer e2e-llm-api-key-001"
        for r in mock_llm_server.requests_log
    )


@pytest.mark.feature("V21-F14")
def test_v21_f14_format_copilot_context_bundles_es_tenant_s1_rf(
    v21_workspace: Path,
) -> None:
    title, body = format_copilot_context(
        PivotPayload(
            source_tab="tab-splunk-es",
            target_tab="tab-llm",
            tenant_id="1001",
            hostname="wkstn-1001-01.example.test",
            src_ip="198.51.100.10",
            es_finding={"event_id": "fnd-1001-a", "rule_name": "ES_Suspicious_LSASS_Dump"},
            s1_threat={"id": "thr-1001-2", "threatName": "procdump64.exe"},
            rf_enrichment={"198.51.100.10": {"risk": {"score": 75}}},
        )
    )
    assert "Tenant 1001" in title
    for section in (
        "## Tenant & Scope",
        "## Indicators & Entities",
        "## Splunk ES Finding",
        "## SentinelOne Threat / Context",
        "## Recorded Future Enrichment",
    ):
        assert section in body


@pytest.mark.feature("V21-F14")
def test_v21_f14_tui_es_pivot_to_llm_attaches_context_ready_to_send(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
    mock_llm_server: MockLocalLLMServer,
) -> None:
    from textual.widgets import Checkbox, Static, TabbedContent

    from soclens.tui import create_app

    app = create_app(
        dry_run=True,
        initial_tab="tab-splunk-es",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.pause()
            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#es-insp-pivot-llm-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#main-tabs", TabbedContent).active == "tab-llm"
            badge = app.query_one("#llm-context-badge", Static)
            assert badge.display is True
            assert "Tenant 1001" in str(badge.content)
            assert not any(r["path"] == "/api/chat" for r in mock_llm_server.requests_log)

            await pilot.click("#llm-send-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            chat_posts = [r for r in mock_llm_server.requests_log if r["path"] == "/api/chat"]
            assert len(chat_posts) == 1
            assert "1001" in json.dumps(chat_posts[0]["json_body"])
            transcript = _richlog_text(app, "#llm-transcript")
            assert "Attack" in transcript

    asyncio.run(_run())


@pytest.mark.feature("V21-F14")
def test_v21_f14_tui_llm_provider_switch_refresh_models_and_clear(
    v21_workspace: Path,
    mock_llm_server: MockLocalLLMServer,
) -> None:
    from textual.widgets import Input, Select, Static

    from soclens.tui import create_app

    app = create_app(
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            await pilot.click("#llm-refresh-models-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            model_sel = app.query_one("#llm-model-select", Select)
            assert model_sel.value is not Select.BLANK

            app.query_one("#llm-provider-select", Select).value = "openai"
            app.query_one("#llm-base-url-input", Input).value = mock_llm_server.openai_base_url
            await pilot.pause()
            await pilot.click("#llm-check-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            app.query_one("#llm-prompt", Input).value = "Draft triage summary"
            await pilot.click("#llm-send-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#llm-clear-btn")
            await pilot.pause()
            assert app.query_one("#llm-context-badge", Static).display is False

    asyncio.run(_run())


@pytest.mark.feature("V21-F14")
def test_v21_f14_llm_copilot_attack_chain_and_closing_note_drafting(
    v21_workspace: Path,
    mock_llm_server: MockLocalLLMServer,
) -> None:
    """Awaits Wave 2 (M4): LocalLLMClient ConfiguredSession adoption & copilot templates."""
    from soclens.config import ConfiguredSession
    from soclens.llm import SOC_PROMPT_TEMPLATES

    with LocalLLMClient(
        provider="ollama",
        base_url=mock_llm_server.ollama_base_url,
        model="llama3.2:latest",
    ) as client:
        assert isinstance(client.session, ConfiguredSession)
        copilot_keys = [
            k
            for k in SOC_PROMPT_TEMPLATES
            if any(tok in k.lower() for tok in ("copilot", "attack_chain", "closing_note"))
        ]
        assert copilot_keys, (
            "Expected at least one v2.1 copilot prompt template in SOC_PROMPT_TEMPLATES"
        )
        prompt_tpl = SOC_PROMPT_TEMPLATES[copilot_keys[0]]
        assert isinstance(prompt_tpl, dict)
        system_prompt = str(prompt_tpl.get("system_prompt") or "").strip()
        assert system_prompt
        user_prefix = str(prompt_tpl.get("user_prefix") or "")
        res = client.chat(
            [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": f"{user_prefix}[ES + Tenant 1001] Closing Note draft",
                },
            ]
        )
        assert "Attack Chain Summary" in res["content"]
        assert "Closing Note" in res["content"]


# ==============================================================================
# V21-F15: TUI AST, Safety, 80x24 Layout, 0600 Profile & Sanitization Invariants
# ==============================================================================


@pytest.mark.feature("V21-F15")
def test_v21_f15_ast_zero_emojis_zero_posix_imports_zero_shell_true() -> None:
    tui_dir = _REPO_ROOT / "soclens" / "tui"
    py_files = sorted(tui_dir.rglob("*.py"))
    assert py_files

    saw_worker = False
    for py_file in py_files:
        src = py_file.read_text(encoding="utf-8")
        emojis = [ch for ch in src if ord(ch) > 0x1F000]
        assert not emojis, f"{py_file} contains emoji chars: {emojis}"

        tree = ast.parse(src, filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in _POSIX_ONLY_MODULES
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in _POSIX_ONLY_MODULES
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "os"
                        and node.func.attr in {"system", "fork", "killpg"}
                    ):
                        raise AssertionError(f"{py_file} calls os.{node.func.attr}()")
                    if node.func.attr == "run_worker":
                        saw_worker = True
                elif isinstance(node.func, ast.Name) and node.func.id == "work":
                    saw_worker = True
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        raise AssertionError(f"{py_file} passes shell=True")
            elif isinstance(node, ast.Name) and node.id == "work":
                saw_worker = True

    assert saw_worker


@pytest.mark.feature("V21-F15")
def test_v21_f15_tui_dynamic_widgets_markup_false_and_prevent_guards(
    v21_workspace: Path,
) -> None:
    from textual.widgets import RichLog, TabbedContent

    from soclens.tui import create_app

    tui_dir = _REPO_ROOT / "soclens" / "tui"
    saw_prevent = False
    for py_file in sorted(tui_dir.rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.With):
                for item in node.items:
                    if (
                        isinstance(item.context_expr, ast.Call)
                        and isinstance(item.context_expr.func, ast.Attribute)
                        and item.context_expr.func.attr == "prevent"
                    ):
                        saw_prevent = True
    assert saw_prevent

    app = create_app(dry_run=True, workspace_dir=v21_workspace, view_mode="admin")

    async def _run() -> None:
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            tabs = app.query_one("#main-tabs", TabbedContent)
            for tab_id, log_id in (
                ("tab-llm", "#llm-transcript"),
                ("tab-splunk-es", "#es-detail"),
                ("tab-sentinelone", "#s1-detail-log"),
                ("tab-splunk-search", "#splunk-search-detail"),
                ("tab-research", "#res-detail-log"),
            ):
                tabs.active = tab_id
                await pilot.pause()
                assert app.query_one(log_id, RichLog).markup is False

    asyncio.run(_run())


@pytest.mark.feature("V21-F15")
def test_v21_f15_tui_80x24_clip_free_rendering_all_tabs(
    v21_workspace: Path,
) -> None:
    from textual.widgets import TabbedContent

    from soclens.tui import ALL_TABS, create_app

    app = create_app(dry_run=True, workspace_dir=v21_workspace, view_mode="admin")

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert app.screen.has_class("-compact-narrow")
            tabs = app.query_one("#main-tabs", TabbedContent)
            for tab_id in ALL_TABS:
                tabs.active = tab_id
                await pilot.pause()
                pane = app.query_one(f"#{tab_id}")
                assert pane.region.width <= 80
                assert pane.region.right <= 80
                assert pane.region.bottom <= 24

    asyncio.run(_run())


@pytest.mark.feature("V21-F15")
def test_v21_f15_settings_profile_0600_permissions_and_secret_repr_safety(
    v21_workspace: Path,
) -> None:
    from soclens.settings import save_profile_settings

    save_profile_settings({"splunk_app": "ES"})
    raw_path = os.environ.get("SOCLENS_SETTINGS_FILE")
    settings_path = Path(raw_path) if raw_path else (v21_workspace / "settings.json")
    assert settings_path.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(settings_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(settings_path.parent.stat().st_mode) in (0o700, 0o755, 0o775)

    sec_cfg = SecretStoreConfig(
        provider="secret_server",
        tss_password="secret-tss-pw",
        tss_client_secret="secret-tss-cs",
        tss_access_token="secret-tss-at",
        vault_token="secret-vault-tok",
        vault_secret_id="secret-vault-sid",
        op_connect_token="secret-op-tok",
        bw_master_password="secret-bw-mp",
    )
    llm_cfg = LocalLLMConfig(api_key="secret-llm-key")
    spl_cfg = SplunkConfig(host="https://splunk.example.test:8089", token="secret-spl-tok", password="secret-spl-pw")
    s1_cfg = SentinelOneConfig(console_url="https://s1.example.test", api_token="secret-s1-tok")

    for obj, secrets in (
        (
            sec_cfg,
            (
                "secret-tss-pw",
                "secret-tss-cs",
                "secret-tss-at",
                "secret-vault-tok",
                "secret-vault-sid",
                "secret-op-tok",
                "secret-bw-mp",
            ),
        ),
        (llm_cfg, ("secret-llm-key",)),
        (spl_cfg, ("secret-spl-tok", "secret-spl-pw")),
        (s1_cfg, ("secret-s1-tok",)),
    ):
        rendered = repr(obj)
        for s in secrets:
            assert s not in rendered


@pytest.mark.feature("V21-F15")
def test_v21_f15_public_repo_sanitization_and_zero_new_runtime_deps() -> None:
    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = " ".join(pyproject["project"]["dependencies"]).lower()
    for forbidden_sdk in (
        "python-tss-sdk",
        "hvac",
        "onepasswordconnectsdk",
        "bitwarden",
    ):
        assert forbidden_sdk not in deps

    scan_paths = [_REPO_ROOT / "tests" / "e2e" / "v21_mocks.py"] + sorted(
        (_REPO_ROOT / "tests" / "e2e" / "fixtures").glob("v21_*.json")
    )
    for path in scan_paths:
        text = path.read_text(encoding="utf-8")
        if path.name == "v21_mocks.py":
            text = text.split("def _assert_synthetic_payload", 1)[0]
        lowered = text.lower()
        for domain in ("recordedfuture.com", "sentinelone.net", "splunkcloud.com"):
            assert domain not in lowered, f"{path} contains forbidden domain {domain}"
        for prefix in ("sk-", "ghp_", "AKIA", "BEGIN RSA PRIVATE KEY"):
            assert prefix not in text, f"{path} contains forbidden secret prefix {prefix}"


@pytest.mark.feature("V21-F15")
def test_v21_f15_v200_rf_enrichment_controls_and_ssl_flags_preserved(
    v21_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    from textual.widgets import TabbedContent

    from soclens.tui import create_app

    app = create_app(
        dry_run=True,
        initial_tab="tab-splunk-es",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-splunk-es"
            for widget_id in (
                "#es-auto-enrich-cb",
                "#es-private-ips-cb",
                "#es-enrich-selected-btn",
                "#es-enrich-all-btn",
                "#es-post-rf-comment-btn",
                "#es-rf-field-map-input",
            ):
                assert app.query_one(widget_id) is not None

            app.set_insecure_ssl(True)
            await pilot.pause()
            assert "INSECURE SSL" in app.sub_title or "SSL" in app.sub_title

    asyncio.run(_run())

    help_proc = run_cli(["--help"])
    assert help_proc.returncode == 0
    assert "--insecure" in help_proc.stdout
    assert "--ca-bundle" in help_proc.stdout
