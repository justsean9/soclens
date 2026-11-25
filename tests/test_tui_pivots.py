"""Offline Pilot and unit tests for Cross-Workbench Pivot Bus, Hydration, F2 Broadcast & Pane Hooks."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from textual.containers import HorizontalScroll
from textual.widget import Widget
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TextArea,
)

from soclens.config import PivotPayload, extract_tenant_from_site_name
from soclens.tui.app import create_app
from soclens.tui.filters import S1_PRESETS_BY_VIEW
from soclens.tui.pivot import build_spl_from_pivot, emit_pivot, format_copilot_context
from soclens.tui.screens.base import extract_richlog_text
from soclens.tui.screens.research import ResearchPane
from soclens.tui.screens.rf_intel import RFIntelPane
from soclens.tui.screens.sentinelone import SentinelOnePane
from soclens.tui.screens.splunk_es import SplunkESPane
from soclens.tui.screens.splunk_search import SplunkSearchPane


def _make_rf_client() -> MagicMock:
    client = MagicMock()
    client.asi_api_key = None
    client.riskrecon_token = None
    client._stop_event = None
    client.get_watchlists.return_value = []
    client.v2_lookup.return_value = {
        "data": {
            "entity": {"id": "ip:198.51.100.42", "name": "198.51.100.42", "type": "IpAddress"},
            "risk": {
                "score": 82,
                "riskString": "5/62",
                "criticalityLabel": "Malicious",
                "riskSummary": "Synthetic C2 indicator.",
                "evidenceDetails": [],
            },
            "timestamps": {"firstSeen": "2026-01-01T00:00:00Z", "lastSeen": "2026-01-02T00:00:00Z"},
            "threatLists": [],
            "counts": [],
        }
    }
    client.entity_match.return_value = [
        {"id": "ent-host-1", "name": "FIN-WKSTN-01", "type": "System"}
    ]
    client.entity_lookup.return_value = {"id": "ent-host-1", "name": "FIN-WKSTN-01", "type": "System"}
    client.v2_search.return_value = {"data": {"results": []}}
    client.links_search.return_value = {"data": []}
    client.search_analyst_notes.return_value = {"data": []}
    client.search_detection_rules.return_value = []
    client.search_alerts_v3.return_value = {"data": []}
    client.search_playbook_alerts.return_value = {"data": []}
    client.sandbox_search.return_value = {"samples": []}
    client.soar_enrich.return_value = {"data": {"results": []}}
    return client


def _make_splunk_client() -> MagicMock:
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = None
    client.run_search.return_value = {
        "sid": "sid_pivot_1",
        "query": '| loadjob "sid_999"',
        "status": "success",
        "result_count": 1,
        "event_count": 1,
        "scan_count": 1,
        "duration": 0.1,
        "fields": ["_time", "host", "src", "_raw"],
        "results": [
            {
                "_time": "2026-01-02T00:00:00Z",
                "host": "FIN-WKSTN-01",
                "src": "198.51.100.42",
                "_raw": "synthetic event",
            }
        ],
        "error_message": None,
        "messages": [],
    }
    return client


def _make_s1_client() -> MagicMock:
    s1 = MagicMock()
    s1.console_url = "https://tenant.sentinelone.net"
    s1.check_connection.return_value = {"build": "24.2.1"}
    s1.list_sites.return_value = [
        {"id": "site-100", "name": "MDR-1234", "state": "active", "activeLicenses": 10},
    ]
    s1.list_threats.return_value = [
        {
            "id": "thr-1",
            "threatInfo": {
                "threatName": "Trojan.Test",
                "sha1": "a" * 40,
                "analystVerdict": "undefined",
                "incidentStatus": "unresolved",
                "createdAt": "2026-01-02T00:00:00Z",
            },
            "agentRealtimeInfo": {
                "agentComputerName": "FIN-WKSTN-01",
                "siteId": "site-100",
                "siteName": "MDR-1234",
            },
        }
    ]
    s1.list_agents.return_value = []
    s1.list_users.return_value = []
    s1.list_rbac_roles.return_value = []
    s1.list_activities.return_value = []
    return s1


# ---------------------------------------------------------------------------
# 1. Startup Secret Hydration
# ---------------------------------------------------------------------------


def test_startup_secret_hydration_nonblocking_and_reloads_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = threading.Event()
    calls: list[dict[str, Any]] = []

    def _fake_hydrate(
        *,
        force: bool = False,
        overwrite_existing: bool = False,
        stop_event: threading.Event | None = None,
    ) -> dict[str, str]:
        calls.append(
            {
                "force": force,
                "overwrite_existing": overwrite_existing,
                "has_stop_event": stop_event is not None,
            }
        )
        gate.wait(timeout=2.0)
        return {"rf_api_token": "tok***", "splunk_token": "spl***"}

    monkeypatch.setattr("soclens.tui.app.hydrate_secrets_from_store", _fake_hydrate)
    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=False,
    )
    assert app.no_secret_store is False

    reload_calls: list[bool] = []
    orig_reload = app.reload_settings

    def _wrapped_reload() -> None:
        reload_calls.append(True)
        orig_reload()

    monkeypatch.setattr(app, "reload_settings", _wrapped_reload)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            # TUI mounts without waiting for slow vault hydration.
            assert app._ui_mounted is True
            gate.set()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert len(calls) == 1
            assert calls[0]["has_stop_event"] is True
            assert len(reload_calls) == 1
            secret_logs = [
                e for e in app.log_store.snapshot() if e.source == "secrets"
            ]
            assert any("Hydrated 2 secret(s)" in e.message for e in secret_logs)
            assert any("rf_api_token" in e.message for e in secret_logs)

    asyncio.run(_run())


def test_startup_secret_hydration_skipped_when_no_secret_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    def _fail_if_called(**kwargs: Any) -> dict[str, str]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr("soclens.tui.app.hydrate_secrets_from_store", _fail_if_called)
    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=True,
    )
    assert app.no_secret_store is True

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert called is False

    asyncio.run(_run())


def test_startup_secret_hydration_handles_unreachable_vault_safely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(**kwargs: Any) -> dict[str, str]:
        raise ConnectionError("Synthetic vault unreachable")

    monkeypatch.setattr("soclens.tui.app.hydrate_secrets_from_store", _boom)
    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=False,
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app._ui_mounted is True
            warnings = [
                e
                for e in app.log_store.snapshot()
                if e.source == "secrets" and e.level == "WARNING"
            ]
            assert any("Synthetic vault unreachable" in e.message for e in warnings)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. SocLensApp.dispatch_pivot + Lazy Mounting + Fallbacks
# ---------------------------------------------------------------------------


def test_dispatch_pivot_lazy_mounts_tabs_and_enriches_site_tenant(
    tmp_path: Path,
) -> None:
    rf_client = _make_rf_client()
    s1_client = _make_s1_client()
    fake_splunk = _make_splunk_client()

    app = create_app(
        client=rf_client,
        s1_client=s1_client,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        with patch.object(SplunkSearchPane, "_build_splunk_client", return_value=fake_splunk):
            async with app.run_test(size=(130, 36)) as pilot:
                await pilot.pause()
                tabs = app.query_one("#main-tabs", TabbedContent)
                assert app._get_mounted_pane("tab-splunk-search") is None
                assert app._get_mounted_pane("tab-rf-intel") is None
                assert app._get_mounted_pane("tab-sentinelone") is None
                assert app._get_mounted_pane("tab-splunk-es") is None
                assert app._get_mounted_pane("tab-llm") is None

                # Invalid & hidden-admin tabs fail cleanly
                assert app.dispatch_pivot(PivotPayload(target_tab="tab-unknown")) is False
                assert app.dispatch_pivot(PivotPayload(target_tab="tab-sigma")) is False

                # 1) Lazy-mount tab-splunk-search
                assert app.dispatch_pivot(
                    PivotPayload(
                        source_tab="tab-splunk-es",
                        target_tab="tab-splunk-search",
                        site_name="MDR-1234",
                        src_ip="198.51.100.42",
                        earliest="-4h",
                        latest="now",
                    )
                )
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert tabs.active == "tab-splunk-search"
                search_pane = app.query_one(SplunkSearchPane)
                assert "1234" in search_pane.query_one("#splunk-search-spl", TextArea).text
                assert "198.51.100.42" in search_pane.query_one("#splunk-search-spl", TextArea).text
                fake_splunk.run_search.assert_not_called()

                # 2) Lazy-mount tab-rf-intel
                assert app.dispatch_pivot(
                    PivotPayload(
                        source_tab="tab-splunk-es",
                        target_tab="tab-rf-intel",
                        entity="198.51.100.42",
                        entity_type="ip",
                    )
                )
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert tabs.active == "tab-rf-intel"
                assert app.query_one("#rf-ioc-input", Input).value == "198.51.100.42"
                rf_client.v2_lookup.assert_called()

                # 3) Lazy-mount tab-sentinelone (with tenant enrichment from site_name)
                assert app.dispatch_pivot(
                    PivotPayload(
                        source_tab="tab-splunk-es",
                        target_tab="tab-sentinelone",
                        site_name="MDR-1234",
                        site_id="site-100",
                        hostname="FIN-WKSTN-01",
                        auto_run=True,
                    )
                )
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert tabs.active == "tab-sentinelone"
                assert app.query_one("#s1-filter-input", Input).value == "FIN-WKSTN-01"

                # 4) Lazy-mount tab-splunk-es
                with patch.object(SplunkESPane, "handle_refresh") as mock_es_refresh:
                    assert app.dispatch_pivot(
                        PivotPayload(
                            source_tab="tab-sentinelone",
                            target_tab="tab-splunk-es",
                            site_name="MDR-1234",
                            hostname="FIN-WKSTN-01",
                            auto_run=True,
                        )
                    )
                    await pilot.pause()
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    assert tabs.active == "tab-splunk-es"
                    assert app.query_one("#es-filter-tenant", Input).value == "1234"
                    mock_es_refresh.assert_called()

                # 5) Lazy-mount tab-llm (works via accept_pivot or analyze_context fallback)
                assert app.dispatch_pivot(
                    PivotPayload(
                        source_tab="tab-splunk-es",
                        target_tab="tab-llm",
                        tenant_id="1234",
                        hostname="FIN-WKSTN-01",
                        src_ip="198.51.100.42",
                        es_finding={"rule_name": "Beacon", "tenant_id": "1234"},
                        s1_threat={"id": "thr-1"},
                        rf_enrichment={"rf_max_risk_score": 82},
                        summary="Synthetic triage bundle",
                    )
                )
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert tabs.active == "tab-llm"
                assert app.query_one("#llm-context-badge", Static).display is True
                transcript = extract_richlog_text(app.query_one("#llm-transcript", RichLog))
                assert "[CONTEXT ATTACHED]" in transcript

                # 6) Target tab-research
                assert app.dispatch_pivot(
                    PivotPayload(
                        source_tab="tab-splunk-es",
                        target_tab="tab-research",
                        entity="198.51.100.42",
                        entity_type="ip",
                    )
                )
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert tabs.active == "tab-research"
                assert app.query_one("#res-target-input", Input).value == "198.51.100.42"

    asyncio.run(_run())


def test_dispatch_pivot_fallback_when_accept_pivot_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        initial_tab="tab-llm",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 36)) as pilot:
            await pilot.pause()
            llm_pane = app._get_mounted_pane("tab-llm")
            assert llm_pane is not None
            monkeypatch.setattr(llm_pane, "accept_pivot", None, raising=False)
            captured: list[tuple[str, str, str, bool]] = []

            def _fake_analyze(
                title: str, content: str, *, template: str = "freeform", auto_send: bool = False
            ) -> None:
                captured.append((title, content, template, auto_send))

            monkeypatch.setattr(llm_pane, "analyze_context", _fake_analyze)

            payload = PivotPayload(
                source_tab="tab-splunk-es",
                target_tab="tab-llm",
                tenant_id="1234",
                hostname="FIN-WKSTN-01",
                summary="Fallback check",
            )
            assert emit_pivot(app, payload) is True
            await pilot.pause()
            assert len(captured) == 1
            assert captured[0][2] == "triage_alert"
            assert captured[0][3] is False
            assert "1234" in captured[0][1]

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 3. F9 <-> 9 Tenant / Site Mapping
# ---------------------------------------------------------------------------


def test_tenant_site_mapping_regex_and_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("S1_TIER_RULES", "")
    monkeypatch.setenv("S1_SITE_TENANT_MAP", "")
    assert extract_tenant_from_site_name("MDR-1234") == "1234"
    assert extract_tenant_from_site_name("MSSP-ACME") == "ACME"
    assert extract_tenant_from_site_name("Internal-Corp") is None

    monkeypatch.setenv("S1_SITE_TENANT_MAP", '{"Custom Site": "tenant_99"}')
    assert extract_tenant_from_site_name("Custom Site") == "tenant_99"


# ---------------------------------------------------------------------------
# 4. F8 Splunk Search Safety Invariant & Window Sync
# ---------------------------------------------------------------------------


def test_splunk_search_pivot_safety_invariant_and_orig_sid(tmp_path: Path) -> None:
    fake_splunk = _make_splunk_client()
    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        initial_tab="tab-splunk-search",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        with patch.object(SplunkSearchPane, "_build_splunk_client", return_value=fake_splunk):
            async with app.run_test(size=(130, 36)) as pilot:
                await pilot.pause()
                pane = app.query_one(SplunkSearchPane)

                # Even if caller passes auto_run=True, arbitrary SPL/IOC MUST NOT auto-run
                assert app.dispatch_pivot(
                    PivotPayload(
                        source_tab="tab-splunk-es",
                        target_tab="tab-splunk-search",
                        tenant_id="1234",
                        src_ip="198.51.100.42",
                        spl_query="index=main src=198.51.100.42 | head 20",
                        earliest="-4h",
                        latest="now",
                        auto_run=True,
                    )
                )
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert (
                    pane.query_one("#splunk-search-spl", TextArea).text
                    == "index=main src=198.51.100.42 | head 20"
                )
                assert pane.query_one("#splunk-search-earliest", Input).value == "-4h"
                assert pane.query_one("#splunk-search-latest", Input).value == "now"
                assert str(pane.query_one("#splunk-search-preset", Select).value) == "-4h"
                fake_splunk.run_search.assert_not_called()

                # orig_sid drilldown MUST load | loadjob and auto-run
                assert app.dispatch_pivot(
                    PivotPayload(
                        source_tab="tab-splunk-es",
                        target_tab="tab-splunk-search",
                        orig_sid="sid_999",
                        earliest="-15m",
                        latest="-5m",
                        auto_run=False,
                    )
                )
                await app.workers.wait_for_complete()
                await pilot.pause()

                assert (
                    pane.query_one("#splunk-search-spl", TextArea).text
                    == '| loadjob "sid_999"'
                )
                assert str(pane.query_one("#splunk-search-preset", Select).value) == "custom"
                fake_splunk.run_search.assert_called_once()
                assert fake_splunk.run_search.call_args.args[0] == '| loadjob "sid_999"'

    asyncio.run(_run())


def test_build_spl_from_pivot_safety_unit() -> None:
    spl, auto_run = build_spl_from_pivot(
        PivotPayload(spl_query="index=sec | stats count", auto_run=True)
    )
    assert spl == "index=sec | stats count"
    assert auto_run is False

    spl_sid, auto_sid = build_spl_from_pivot(PivotPayload(orig_sid='sid"1'))
    assert spl_sid == '| loadjob "sid\\"1"'
    assert auto_sid is True

    title, body = format_copilot_context(
        PivotPayload(tenant_id="1234", hostname="FIN-WKSTN-01", summary="Alert")
    )
    assert "1234" in title
    assert "## Summary" in body


# ---------------------------------------------------------------------------
# 5. RFIntelPane (4) & ResearchPane (7) Pivot Routing
# ---------------------------------------------------------------------------


def test_rf_intel_pivot_routes_ioc_vs_entity_match(tmp_path: Path) -> None:
    rf_client = _make_rf_client()
    app = create_app(
        client=rf_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(RFIntelPane)

            # Empty payload -> status only, no API calls
            pane.accept_pivot(PivotPayload(source_tab="tab-splunk-es", target_tab="tab-rf-intel"))
            rf_client.v2_lookup.assert_not_called()
            rf_client.entity_match.assert_not_called()

            # Hash alias -> v2_lookup("hash", ...)
            sha = "a" * 64
            pane.accept_pivot(
                PivotPayload(
                    target_tab="tab-rf-intel",
                    entity=sha,
                    entity_type="sha256",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert str(pane.query_one("#rf-v2-type", Select).value) == "hash"
            assert pane.query_one("#rf-ioc-input", Input).value == sha
            assert rf_client.v2_lookup.call_args.args[:2] == ("hash", sha)

            # CVE in auto mode -> v2_lookup("vulnerability", ...)
            pane.accept_pivot(
                PivotPayload(
                    target_tab="tab-rf-intel",
                    entity="CVE-2021-44228",
                    entity_type="auto",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert str(pane.query_one("#rf-v2-type", Select).value) == "vulnerability"
            assert rf_client.v2_lookup.call_args.args[:2] == ("vulnerability", "CVE-2021-44228")

            # Hostname without dot -> entity_match (NOT v2_lookup)
            v2_count_before = rf_client.v2_lookup.call_count
            pane.accept_pivot(
                PivotPayload(
                    target_tab="tab-rf-intel",
                    hostname="FIN-WKSTN-01",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert rf_client.v2_lookup.call_count == v2_count_before
            assert pane.query_one("#rf-query-input", Input).value == "FIN-WKSTN-01"
            rf_client.entity_match.assert_called_once()
            assert rf_client.entity_match.call_args.args[0] == "FIN-WKSTN-01"

            # User entity -> entity_match
            pane.accept_pivot(
                PivotPayload(
                    target_tab="tab-rf-intel",
                    username="alice.analyst",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane.query_one("#rf-query-input", Input).value == "alice.analyst"
            assert rf_client.entity_match.call_args.args[0] == "alice.analyst"

    asyncio.run(_run())


def test_research_pivot_runs_scoped_investigation(tmp_path: Path) -> None:
    rf_client = _make_rf_client()
    app = create_app(
        client=rf_client,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(ResearchPane)

            # Empty payload -> no API calls
            pane.accept_pivot(PivotPayload(target_tab="tab-research"))
            rf_client.v2_lookup.assert_not_called()

            # Alias ipaddress -> ip
            pane.accept_pivot(
                PivotPayload(
                    target_tab="tab-research",
                    entity="198.51.100.42",
                    entity_type="ipaddress",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert str(pane.query_one("#res-target-type", Select).value) == "ip"
            assert pane.query_one("#res-target-input", Input).value == "198.51.100.42"
            assert pane._current_dossier is not None
            assert pane._current_dossier.target.canonical_name == "198.51.100.42"

            # Hostname falls back to auto
            pane.accept_pivot(
                PivotPayload(
                    target_tab="tab-research",
                    hostname="FIN-WKSTN-01",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert str(pane.query_one("#res-target-type", Select).value) == "auto"
            assert pane.query_one("#res-target-input", Input).value == "FIN-WKSTN-01"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 6. F2 Admin View Broadcast & SentinelOne users_rbac Preset
# ---------------------------------------------------------------------------


def test_f2_admin_broadcast_updates_s1_badge_and_pane_hooks(tmp_path: Path) -> None:
    s1_client = _make_s1_client()
    app = create_app(
        client=_make_rf_client(),
        s1_client=s1_client,
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        view_mode="user",
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 36)) as pilot:
            await pilot.pause()
            s1_pane = app.query_one(SentinelOnePane)
            badge = s1_pane.query_one("#s1-admin-badge", Static)
            assert "User View" in str(badge.render())

            # Attach both 0-arg and 1-arg on_view_mode_changed hooks on mounted panes
            zero_arg_calls: list[str] = []
            one_arg_calls: list[str] = []

            def _zero_arg_hook() -> None:
                zero_arg_calls.append("called")

            def _one_arg_hook(mode: str) -> None:
                one_arg_calls.append(mode)

            s1_pane.on_view_mode_changed = _one_arg_hook  # type: ignore[attr-defined]
            # Mount a second pane to verify 0-arg hook compatibility too
            app.activate_tab("tab-research")
            await pilot.pause()
            res_pane = app.query_one(ResearchPane)
            res_pane.on_view_mode_changed = _zero_arg_hook  # type: ignore[attr-defined]

            await pilot.press("f2")
            await pilot.pause()
            assert app.is_admin_view is True
            assert "Admin View: ON" in str(badge.render())
            assert one_arg_calls == ["admin"]
            assert zero_arg_calls == ["called"]

            await pilot.press("f2")
            await pilot.pause()
            assert app.is_admin_view is False
            assert "User View" in str(badge.render())
            assert one_arg_calls == ["admin", "user"]
            assert zero_arg_calls == ["called", "called"]

    asyncio.run(_run())


def test_s1_presets_include_users_rbac_and_populate_select(tmp_path: Path) -> None:
    assert "users_rbac" in S1_PRESETS_BY_VIEW
    rbac_presets = S1_PRESETS_BY_VIEW["users_rbac"]
    assert len(rbac_presets) >= 1
    assert rbac_presets[0]["timeframe"] == "any"
    assert rbac_presets[0]["status"] == "any"

    s1_client = _make_s1_client()
    app = create_app(
        client=_make_rf_client(),
        s1_client=s1_client,
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 36)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-wb-users-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            s1_pane = app.query_one(SentinelOnePane)
            assert s1_pane._current_view == "users_rbac"
            assert str(s1_pane.query_one("#s1-preset-select", Select).value) == "all"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 7. 80x24 Layout Bounds for M4b Panes
# ---------------------------------------------------------------------------


def test_m4b_panes_fit_80x24_bounds(tmp_path: Path) -> None:
    def _is_actually_visible(widget: Widget) -> bool:
        for anc in widget.ancestors_with_self:
            if isinstance(anc, Widget) and not anc.display:
                return False
        return True

    def _in_hscroll(widget: Widget) -> bool:
        return any(isinstance(anc, HorizontalScroll) for anc in widget.ancestors)

    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            for tab_id, pane_cls in (
                ("tab-splunk-search", SplunkSearchPane),
                ("tab-research", ResearchPane),
                ("tab-rf-intel", RFIntelPane),
            ):
                app.activate_tab(tab_id)
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                pane = app.query_one(pane_cls)
                checked = 0
                for widget in pane.query("*"):
                    if (
                        isinstance(
                            widget,
                            (Button, Select, Input, Checkbox, DataTable, RichLog, TextArea),
                        )
                        and _is_actually_visible(widget)
                        and not _in_hscroll(widget)
                    ):
                        checked += 1
                        reg = widget.region
                        assert reg.x >= 0, f"{tab_id}:{widget.id} x={reg.x} < 0"
                        assert reg.y >= 0, f"{tab_id}:{widget.id} y={reg.y} < 0"
                        assert reg.x + reg.width <= 80, (
                            f"{tab_id}:{widget.id} right={reg.x + reg.width} > 80 ({reg})"
                        )
                        assert reg.y + reg.height <= 24, (
                            f"{tab_id}:{widget.id} bottom={reg.y + reg.height} > 24 ({reg})"
                        )
                        assert reg.width > 0, f"{tab_id}:{widget.id} width <= 0"
                        assert reg.height > 0, f"{tab_id}:{widget.id} height <= 0"
                assert checked >= 5

    asyncio.run(_run())


def test_rf_intel_pivot_aliases_and_dotted_host_and_dispatch_error_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rf_client = _make_rf_client()
    app = create_app(
        client=rf_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(RFIntelPane)

            # Dotted host -> v2_lookup("domain", ...)
            pane.accept_pivot(
                PivotPayload(
                    target_tab="tab-rf-intel",
                    hostname="web01.evil.example",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert str(pane.query_one("#rf-v2-type", Select).value) == "domain"
            assert rf_client.v2_lookup.call_args.args[:2] == ("domain", "web01.evil.example")

            # ip_address alias -> v2_lookup("ip", ...)
            pane.accept_pivot(
                PivotPayload(
                    target_tab="tab-rf-intel",
                    entity="198.51.100.42",
                    entity_type="ip_address",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert str(pane.query_one("#rf-v2-type", Select).value) == "ip"
            assert rf_client.v2_lookup.call_args.args[:2] == ("ip", "198.51.100.42")

            # Delivery exception in dispatch_pivot logs ERROR rather than dropping silently
            def _raise_pivot(payload: PivotPayload) -> None:
                raise RuntimeError("Synthetic pivot delivery failure")

            monkeypatch.setattr(pane, "accept_pivot", _raise_pivot)
            assert app.dispatch_pivot(
                PivotPayload(source_tab="tab-splunk-es", target_tab="tab-rf-intel")
            )
            await pilot.pause()
            err_logs = [
                e for e in app.log_store.snapshot() if e.level == "ERROR" and e.source == "tui"
            ]
            assert any("Synthetic pivot delivery failure" in e.message for e in err_logs)

    asyncio.run(_run())


def test_m4b_panes_resize_roundtrip_bounds(tmp_path: Path) -> None:
    def _is_actually_visible(widget: Widget) -> bool:
        for anc in widget.ancestors_with_self:
            if isinstance(anc, Widget) and not anc.display:
                return False
        return True

    def _in_hscroll(widget: Widget) -> bool:
        return any(isinstance(anc, HorizontalScroll) for anc in widget.ancestors)

    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        sizes = [(80, 24), (140, 40), (180, 52), (120, 36), (80, 24)]
        async with app.run_test(size=sizes[0]) as pilot:
            for idx, (w, h) in enumerate(sizes):
                if idx > 0:
                    await pilot.resize_terminal(w, h)
                    await pilot.pause()
                for tab_id, pane_cls in (
                    ("tab-splunk-search", SplunkSearchPane),
                    ("tab-research", ResearchPane),
                    ("tab-rf-intel", RFIntelPane),
                ):
                    app.activate_tab(tab_id)
                    await pilot.pause()
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    pane = app.query_one(pane_cls)
                    if pane_cls is RFIntelPane:
                        if w in (80, 140, 180):
                            assert pane.has_class("rf-detail-compact")
                        elif w == 120:
                            assert not pane.has_class("rf-detail-compact")
                    checked = 0
                    for widget in pane.query("*"):
                        if (
                            isinstance(
                                widget,
                                (Button, Select, Input, Checkbox, DataTable, RichLog, TextArea, Static),
                            )
                            and _is_actually_visible(widget)
                            and not _in_hscroll(widget)
                        ):
                            checked += 1
                            reg = widget.region
                            assert reg.x >= 0, f"{tab_id}@{w}x{h}:{widget.id} x={reg.x} < 0"
                            assert reg.y >= 0, f"{tab_id}@{w}x{h}:{widget.id} y={reg.y} < 0"
                            assert reg.x + reg.width <= w, (
                                f"{tab_id}@{w}x{h}:{widget.id} right={reg.x + reg.width} > {w} ({reg})"
                            )
                            assert reg.y + reg.height <= h, (
                                f"{tab_id}@{w}x{h}:{widget.id} bottom={reg.y + reg.height} > {h} ({reg})"
                            )
                            assert reg.width > 0, f"{tab_id}@{w}x{h}:{widget.id} width <= 0"
                            assert reg.height > 0, f"{tab_id}@{w}x{h}:{widget.id} height <= 0"
                    assert checked >= 5

    asyncio.run(_run())


def test_dispatch_pivot_whitespace_site_name_resolves_tenant_without_forcing_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("S1_SITE_TENANT_MAP", '{"site-only-1": "ten-only-1"}')
    s1_client = _make_s1_client()
    app = create_app(
        client=_make_rf_client(),
        s1_client=s1_client,
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 36)) as pilot:
            await pilot.pause()
            s1_pane = app.query_one(SentinelOnePane)
            captured: list[PivotPayload] = []
            monkeypatch.setattr(s1_pane, "accept_pivot", lambda p: captured.append(p))

            assert app.dispatch_pivot(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-sentinelone",
                    site_name="   ",
                    site_id="site-only-1",
                )
            )
            await pilot.pause()
            assert len(captured) == 1
            assert captured[0].tenant_id == "ten-only-1"
            assert captured[0].tier is None

            assert app.dispatch_pivot(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-sentinelone",
                    site_name="   ",
                    site_id="  ",
                )
            )
            await pilot.pause()
            assert len(captured) == 2
            assert captured[1].tenant_id is None
            assert captured[1].tier is None

    asyncio.run(_run())


def test_rf_intel_accept_pivot_preserves_comma_in_url(tmp_path: Path) -> None:
    rf_client = _make_rf_client()
    app = create_app(
        client=rf_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(RFIntelPane)

            comma_url = "https://evil.example/a,b"
            pane.accept_pivot(
                PivotPayload(
                    target_tab="tab-rf-intel",
                    entity=comma_url,
                    entity_type="url",
                )
            )
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert str(pane.query_one("#rf-v2-type", Select).value) == "url"
            assert pane.query_one("#rf-ioc-input", Input).value == comma_url
            assert rf_client.v2_lookup.call_args.args[:2] == ("url", comma_url)

            # Multi-IOC comma splitting remains active for non-URL types (e.g., ip)
            sel = pane.query_one("#rf-v2-type", Select)
            inp = pane.query_one("#rf-ioc-input", Input)
            with sel.prevent(Select.Changed):
                sel.value = "ip"
            with inp.prevent(Input.Changed):
                inp.value = "198.51.100.42, 198.51.100.43"
            pane.handle_v2_lookup()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert rf_client.v2_lookup.call_args.args[:2] == ("ip", "198.51.100.42")

    asyncio.run(_run())

