"""Tests for 24h alert caching/preloading, S1 defaults, hover popups, and human-readable UIs."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

from textual.widgets import RichLog

from soclens.alert_cache import (
    CACHE_SOURCE_ES,
    CACHE_SOURCE_RF,
    CACHE_SOURCE_S1,
    AlertCacheStore,
    format_cache_age,
)
from soclens.sentinelone import SentinelOneClient
from soclens.tui.app import create_app
from soclens.tui.s1_formatters import (
    format_s1_value,
    pretty_s1_label,
    render_s1_policy_detail,
    render_s1_record_detail,
)
from soclens.tui.screens.base import DoubleClickDataTable, extract_richlog_text
from soclens.tui.screens.rf_intel import RFIntelPane
from soclens.tui.screens.sentinelone import SentinelOnePane
from soclens.tui.screens.splunk_es import SplunkESPane
from soclens.tui.screens.splunk_search import SplunkSearchPane


def _recent_iso(hours_ago: int = 1) -> str:
    return (datetime.now(UTC) - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_alert_cache_store_persists_and_reloads(tmp_path: Path) -> None:
    cache_dir = tmp_path / "alert_cache"
    store = AlertCacheStore(cache_dir=cache_dir)
    assert store.get(CACHE_SOURCE_S1) is None
    assert store.is_stale(CACHE_SOURCE_S1, 300) is True

    items = [{"id": "th-1", "title": "Beacon"}]
    entry = store.put(CACHE_SOURCE_S1, items, meta={"sites": [{"id": "s1", "name": "MDR-100"}]})
    assert entry.source == CACHE_SOURCE_S1
    assert len(entry.items) == 1
    assert store.is_stale(CACHE_SOURCE_S1, 300) is False

    # Reload from disk in a fresh store instance
    store2 = AlertCacheStore(cache_dir=cache_dir)
    loaded = store2.get(CACHE_SOURCE_S1)
    assert loaded is not None
    assert loaded.items == items
    assert loaded.meta["sites"][0]["name"] == "MDR-100"

    # Expiry check
    assert store2.get(CACHE_SOURCE_S1, max_age_seconds=600) is not None
    assert store2.get(CACHE_SOURCE_S1, max_age_seconds=0.0) is None

    # Clear removes disk file
    store2.clear(CACHE_SOURCE_S1)
    assert store2.get(CACHE_SOURCE_S1) is None
    assert not (cache_dir / f"{CACHE_SOURCE_S1}.json").exists()


def test_format_cache_age_labels() -> None:
    now = time.time()
    assert format_cache_age(now - 10, now=now) == "just now"
    assert format_cache_age(now - 180, now=now) == "3m ago"
    assert format_cache_age(now - 3660, now=now) == "1h 1m ago"
    assert format_cache_age(now - 90000, now=now) == "1d ago"


def test_sentinelone_client_list_threats_sends_created_at_bounds() -> None:
    client = SentinelOneClient(console_url="https://s1.example.test", api_token="tok")
    captured: list[dict[str, object]] = []

    def _fake_paginate(path: str, *, params=None, **kwargs):
        captured.append({"path": path, "params": dict(params or {})})
        return []

    client._paginate = _fake_paginate  # type: ignore[method-assign]
    client.list_threats(
        created_after="2026-11-24T00:00:00Z",
        created_before="2026-11-25T00:00:00Z",
    )
    assert len(captured) == 1
    assert captured[0]["path"] == "threats"
    assert captured[0]["params"]["createdAt__gte"] == "2026-11-24T00:00:00Z"  # type: ignore[index]
    assert captured[0]["params"]["createdAt__lte"] == "2026-11-25T00:00:00Z"  # type: ignore[index]


def test_background_preloader_hydrates_rf_es_and_s1_panes(tmp_path: Path) -> None:
    recent = _recent_iso(2)

    rf_client = MagicMock()
    rf_client.search_alerts_v3.return_value = {
        "data": [
            {
                "id": "rf-a1",
                "title": "Preloaded RF Alert",
                "rule": {"name": "Domain Spoofing"},
                "review": {"status": "New"},
                "log": {"triggered": recent},
            }
        ],
        "counts": {"total": 1},
    }
    rf_client.get_alert_v3.return_value = {
        "data": {
            "id": "rf-a1",
            "title": "Preloaded RF Alert",
            "rule": {"name": "Domain Spoofing"},
            "review": {"status": "New", "assignee": "analyst@soc.test"},
            "log": {"triggered": recent},
            "ai_insights": {"text": "Preloaded AI summary for instant click-in."},
            "hits": [
                {
                    "id": "hit-1",
                    "fragment": "Suspicious lookalike domain observed.",
                    "document": {"title": "DNS Telemetry"},
                }
            ],
        }
    }

    s1_client = MagicMock()
    s1_client.console_url = "https://tenant.sentinelone.net"
    s1_client.list_threats.return_value = [
        {
            "id": "s1-th-1",
            "threatInfo": {
                "threatName": "Preloaded.Trojan",
                "analystVerdict": "undefined",
                "incidentStatus": "unresolved",
                "mitigationStatus": "active",
                "createdAt": recent,
            },
            "agentRealtimeInfo": {
                "agentComputerName": "MDR-HOST-1",
                "siteId": "site-mdr",
                "siteName": "MDR-4200",
            },
        }
    ]
    s1_client.list_sites.return_value = [
        {"id": "site-mdr", "name": "MDR-4200", "state": "active"}
    ]

    es_client = MagicMock()
    es_client.query_findings_hybrid.return_value = {
        "items": [
            {
                "event_id": "es-1",
                "rule_title": "Preloaded ES Notable",
                "urgency": "high",
                "status_label": "New",
                "owner": "unassigned",
                "_time": recent,
            }
        ],
        "source_backend": "mc_v2",
    }

    app = create_app(
        client=rf_client,
        s1_client=s1_client,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        preload_alerts=True,
        alert_cache_refresh_seconds=0,
    )
    app.splunk_es_client = es_client  # type: ignore[attr-defined]

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()

            # All three 24h caches must be populated in background
            assert app.alert_cache.get(CACHE_SOURCE_RF) is not None
            assert app.alert_cache.get(CACHE_SOURCE_ES) is not None
            assert app.alert_cache.get(CACHE_SOURCE_S1) is not None
            assert s1_client.list_threats.call_args.kwargs.get("created_after") is not None

            # Switch to SentinelOne -> instantly hydrated from cache with MDR + Alerts + 24h
            app.activate_tab("tab-sentinelone")
            await pilot.pause()
            await pilot.pause()
            s1_pane = app.query_one(SentinelOnePane)
            assert s1_pane._current_view == "threats"
            assert s1_pane._tier_filter == "MDR"
            assert s1_pane._timeframe_filter == "last_24h"
            assert s1_pane.query_one("#s1-table", DoubleClickDataTable).row_count == 1
            assert s1_client.list_threats.call_count == 1  # No redundant API call

            # Switch to RF Intel -> instantly hydrated from cache WITH full alert details
            app.activate_tab("tab-rf-intel")
            await pilot.pause()
            await pilot.pause()
            rf_pane = app.query_one(RFIntelPane)
            assert rf_pane._active_mode == "alerts_v3"
            assert rf_pane.query_one("#rf-results-table", DoubleClickDataTable).row_count == 1
            assert ("alerts_v3", "rf-a1") in rf_pane._detail_cache
            rf_detail_text = extract_richlog_text(rf_pane.query_one("#rf-log", RichLog))
            assert "Preloaded AI summary for instant click-in." in rf_detail_text
            assert rf_client.search_alerts_v3.call_count == 1
            assert rf_client.get_alert_v3.call_count == 1

            # Switch to Splunk ES -> instantly hydrated from cache
            app.activate_tab("tab-splunk-es")
            await pilot.pause()
            await pilot.pause()
            es_pane = app.query_one(SplunkESPane)
            assert es_pane.query_one("#es-table", DoubleClickDataTable).row_count == 1
            assert es_client.query_findings_hybrid.call_count == 1

    asyncio.run(_run())


def test_s1_human_readable_overview_and_raw_json_toggle(tmp_path: Path) -> None:
    recent = _recent_iso(1)
    s1 = MagicMock()
    s1.console_url = "https://tenant.sentinelone.net"
    s1.list_threats.return_value = [
        {
            "id": "th-hr-1",
            "mitigationStatus": [
                {
                    "action": "unquarantine",
                    "actionsCounters": {
                        "failed": 0,
                        "notFound": 0,
                        "pendingReboot": 0,
                        "success": 1,
                        "total": 1,
                    },
                    "lastUpdate": recent,
                    "status": "success",
                },
                {
                    "action": "kill",
                    "actionsCounters": {
                        "failed": 0,
                        "notFound": 0,
                        "pendingReboot": 0,
                        "success": 951,
                        "total": 951,
                    },
                    "lastUpdate": recent,
                    "status": "success",
                },
            ],
            "threatInfo": {
                "threatName": "Mimikatz.CredentialDump",
                "classification": "Hacktool",
                "confidenceLevel": "malicious",
                "analystVerdict": "true_positive",
                "incidentStatus": "unresolved",
                "mitigationStatus": "mitigated",
                "filePath": r"C:\Users\admin\mimi.exe",
                "sha1": "a" * 40,
                "createdAt": recent,
            },
            "agentRealtimeInfo": {
                "agentComputerName": "DC-01",
                "agentOsName": "Windows Server 2022",
                "siteId": "s-1",
                "siteName": "MDR-7777",
            },
        }
    ]

    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            await pilot.click("#s1-refresh-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            detail_text = extract_richlog_text(pane.query_one("#s1-detail-log", RichLog))
            assert "Mimikatz.CredentialDump" in detail_text
            assert "DC-01" in detail_text
            assert "MDR-7777" in detail_text
            assert "Mitigation Actions (2)" in detail_text
            assert "Unquarantine" in detail_text
            assert "951/951 succeeded" in detail_text
            # Overview mode must NOT dump raw JSON or Python dict/list reprs
            assert '"threatInfo":' not in detail_text
            assert '"agentRealtimeInfo":' not in detail_text
            assert "Actionscounters" not in detail_text
            assert "{'action'" not in detail_text.lower()

            # Hover tooltip builder returns full line for row 0
            table = pane.query_one("#s1-table", DoubleClickDataTable)
            tip = table._build_hover_tooltip(0)
            assert tip is not None
            assert "Mimikatz" in tip
            assert "MDR" in tip

            # Clicking Raw JSON explicitly shows JSON; clicking Overview switches back
            await pilot.click("#s1-view-json-btn")
            await pilot.pause()
            json_text = extract_richlog_text(pane.query_one("#s1-detail-log", RichLog))
            assert '"threatInfo"' in json_text

            await pilot.click("#s1-view-overview-btn")
            await pilot.pause()
            ov_text = extract_richlog_text(pane.query_one("#s1-detail-log", RichLog))
            assert '"threatInfo":' not in ov_text

    asyncio.run(_run())


def test_s1_formatters_and_policy_render_human_readable() -> None:
    assert pretty_s1_label("agentComputerName") == "Hostname"
    assert pretty_s1_label("twoFaEnabled") == "2FA Enabled"
    assert format_s1_value(True) == "Yes"
    assert format_s1_value({"mitigationMode": "protect", "ioc": True}) == "Mitigation Mode: protect; Ioc: Yes"

    policy_group = render_s1_policy_detail(
        {"mitigationMode": "protect", "engines": {"reputation": "on", "preExecution": "on"}},
        site_name="MDR-100",
        site_id="s-1",
    )
    assert policy_group.renderables

    rec_group = render_s1_record_detail(
        "endpoints",
        {"id": "ag-1", "computerName": "WKSTN-1", "infected": False, "networkStatus": "connected"},
        tier="MDR",
        site_name="MDR-100",
    )
    assert rec_group.renderables


def test_splunk_search_detail_is_human_readable(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-splunk-search",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SplunkSearchPane)
            pane._table_mode = "events"
            pane._current_rows = [
                {
                    "_time": "2026-11-25T12:00:00Z",
                    "host": "web-01",
                    "nested_meta": {"user": "alice", "action": "login"},
                }
            ]
            pane._render_event_detail(0)
            await pilot.pause()
            text = extract_richlog_text(pane.query_one("#splunk-search-detail", RichLog))
            assert "web-01" in text
            assert "User: alice" in text
            assert '"action":' not in text

    asyncio.run(_run())


def test_any_field_right_click_pivot_and_keyword_spl(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from soclens.tui.modals import ContextMenuModal
    from soclens.tui.pivot import (
        build_keyword_spl,
        extract_pivot_from_click,
        make_pivot_text,
    )

    assert build_keyword_spl("services.exe") == 'index=* "services.exe"'
    assert build_keyword_spl("da39a3ee5e6b4b0d3255bfef95601890afd80709") == (
        'index=* "da39a3ee5e6b4b0d3255bfef95601890afd80709"'
    )

    tagged = make_pivot_text("services.exe", field="Process")
    span_style = tagged.spans[0].style
    fake_event = SimpleNamespace(style=span_style)
    assert extract_pivot_from_click(fake_event) == ("Process", "services.exe")

    app = create_app(
        client=MagicMock(),
        s1_client=MagicMock(),
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)
            pane.open_field_pivot_menu("Process", "services.exe", origin=(10, 10))
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            # Selecting the first item ("splunk_keyword") pivots to Splunk Search with index=* "services.exe"
            app.screen.dismiss("splunk_keyword")
            await pilot.pause()
            await pilot.pause()
            search_pane = app.query_one(SplunkSearchPane)
            from textual.widgets import TextArea

            spl_val = search_pane.query_one("#splunk-search-spl", TextArea).text
            assert spl_val == 'index=* "services.exe"'

    asyncio.run(_run())


def test_global_highlight_selection_pivots_to_research_and_splunk(tmp_path: Path) -> None:
    from textual.widgets import Input, TextArea

    from soclens.tui.modals import ContextMenuModal
    from soclens.tui.screens.research import ResearchPane

    app = create_app(
        client=MagicMock(),
        s1_client=MagicMock(),
        dry_run=True,
        initial_tab="tab-logs",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()

            # Simulate highlighted text anywhere on screen (works across all 13 dashboards)
            app.get_selected_text = lambda: "svchost.exe"  # type: ignore[method-assign]

            # F5 -> Splunk Search with index=* "svchost.exe"
            await pilot.press("f5")
            await pilot.pause()
            await pilot.pause()
            search_pane = app.query_one(SplunkSearchPane)
            assert search_pane.query_one("#splunk-search-spl", TextArea).text == 'index=* "svchost.exe"'

            # F4 -> Research tab with svchost.exe populated
            await pilot.press("f4")
            await pilot.pause()
            await pilot.pause()
            res_pane = app.query_one(ResearchPane)
            assert res_pane.query_one("#res-target-input", Input).value == "svchost.exe"

            # F6 -> Floating transparent Pivot menu for highlighted text
            await pilot.press("f6")
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            app.screen.dismiss(None)
            await pilot.pause()

    asyncio.run(_run())


def test_selectable_richlog_highlights_and_extracts_selected_text(tmp_path: Path) -> None:
    from textual.geometry import Offset
    from textual.selection import Selection

    from soclens.tui.screens.base import SelectableRichLog

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            log = app.query_one("#rf-log", SelectableRichLog)
            log.clear()
            log.write("Process: services.exe")
            log.write("SHA-1: da39a3ee5e6b4b0d3255bfef95601890afd80709")
            await pilot.pause()

            sel = Selection(Offset(9, 0), Offset(21, 0))
            extracted = log.get_selection(sel)
            assert extracted is not None
            assert extracted[0] == "services.exe"

            # Apply selection to screen and verify SocLensApp.get_selected_text() returns it
            app.screen.selections = {log: sel}
            await pilot.pause()
            assert app.get_selected_text() == "services.exe"
            # Rendering line 0 with active selection must succeed without error
            strip = log.render_line(0)
            assert strip.cell_length > 0

    asyncio.run(_run())


def test_playbook_alerts_precache_details_and_images_without_enter(tmp_path: Path) -> None:
    from soclens.tui.image_render import DecodedImage, encode_png

    recent = _recent_iso(1)
    rgb_rows = [bytes([40, 90, 180] * 8) for _ in range(8)]
    png_bytes = encode_png(
        DecodedImage(width=8, height=8, color_type=2, bit_depth=8, raw_size=0, rgb_rows=rgb_rows)
    )

    rf_client = MagicMock()
    rf_client.search_alerts_v3.return_value = {"data": [], "counts": {"total": 0}}
    rf_client.search_playbook_alerts.return_value = {
        "data": [
            {
                "playbook_alert_id": "pb-img-1",
                "category": "domain_abuse",
                "status": "New",
                "priority": "High",
                "title": "spoof-bank.example",
                "updated": recent,
            }
        ],
        "counts": {"total": 1},
    }
    rf_client.get_playbook_alert.return_value = {
        "data": {
            "playbook_alert_id": "pb-img-1",
            "category": "domain_abuse",
            "panel_status": {"status": "New", "priority": "High", "entity_name": "spoof-bank.example"},
            "panel_evidence_summary": {
                "screenshots": [{"image_id": "img-abc", "description": "Landing page"}]
            },
        }
    }
    rf_client.get_playbook_alert_image.return_value = png_bytes

    app = create_app(
        client=rf_client,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        preload_alerts=True,
        alert_cache_refresh_seconds=0,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()

            # Preloader fetched Playbook Alert detail AND screenshot bytes into local cache
            assert rf_client.get_playbook_alert.call_count == 1
            assert rf_client.get_playbook_alert_image.call_count == 1
            assert app.alert_cache.get_image_bytes("domain_abuse__pb-img-1__img-abc") == png_bytes

            # Switching to RF Intel hydrates playbook details & decoded images immediately
            app.activate_tab("tab-rf-intel")
            await pilot.pause()
            await pilot.pause()
            rf_pane = app.query_one(RFIntelPane)
            assert ("playbook", "pb-img-1") in rf_pane._detail_cache
            img_entry = rf_pane._image_cache.get(("domain_abuse", "pb-img-1", "img-abc"))
            assert img_entry is not None
            assert img_entry.get("bytes") == png_bytes
            assert img_entry.get("decoded") is not None

    asyncio.run(_run())


def test_ascii_art_toggle_defaults_off_and_auto_hides_after_10s(
    tmp_path: Path, monkeypatch
) -> None:
    from textual.widgets import Checkbox

    from soclens.tui.research_art import (
        ASCII_ART_AUTO_HIDE_SECONDS,
        ResearchMoodBanner,
        determine_research_mood,
    )
    from soclens.tui.screens.settings import SettingsPane

    assert ASCII_ART_AUTO_HIDE_SECONDS == 10.0
    monkeypatch.delenv("SOCLENS_ASCII_ART", raising=False)

    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            banner = app.query_one("#res-mood-strip", ResearchMoodBanner)
            # Off by default -> banner stays hidden even on mood updates
            assert banner.display is False
            banner.set_mood(determine_research_mood(None, searching=True, query="example.com"))
            await pilot.pause()
            assert banner.display is False

            # Settings checkbox exists and defaults to False
            app.activate_tab("tab-settings")
            await pilot.pause()
            await pilot.pause()
            settings_pane = app.query_one(SettingsPane)
            cb = settings_pane.query_one("#set-ascii-art-enabled", Checkbox)
            assert cb.value is False

            # Unlock via env/setting -> banner appears with a 10s auto-hide timer and re-hides
            monkeypatch.setenv("SOCLENS_ASCII_ART", "true")
            banner.AUTO_HIDE_SECONDS = 0.05
            banner.set_mood(determine_research_mood(None, searching=True, query="evil.test"))
            await pilot.pause()
            assert banner.display is True
            assert banner._hide_timer is not None
            await asyncio.sleep(0.12)
            await pilot.pause()
            assert banner.display is False

    asyncio.run(_run())
