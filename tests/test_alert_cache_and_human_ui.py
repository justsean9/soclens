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

    from textual.widgets import OptionList

    from soclens.tui.modals import ContextMenuModal
    from soclens.tui.pivot import (
        build_keyword_spl,
        extract_pivot_from_click,
        is_clickable_known_field,
        make_pivot_text,
    )

    assert build_keyword_spl("services.exe") == 'index=* "services.exe"'
    assert build_keyword_spl("da39a3ee5e6b4b0d3255bfef95601890afd80709") == (
        'index=* "da39a3ee5e6b4b0d3255bfef95601890afd80709"'
    )

    # Known structured fields get pivot metadata; free-text/status fields do NOT
    tagged = make_pivot_text("services.exe", field="Process")
    span_style = tagged.spans[0].style
    fake_event = SimpleNamespace(style=span_style)
    assert extract_pivot_from_click(fake_event) == ("Process", "services.exe")

    assert is_clickable_known_field("Description", "Some long narrative text") is False
    assert is_clickable_known_field("Status", "Resolved") is False
    assert is_clickable_known_field("Explanation", "Domain looked suspicious") is False
    free_text = make_pivot_text("Some long narrative text", field="Description")
    assert free_text.spans == []

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
            opts = app.screen.query_one("#ctx-menu-options", OptionList)
            opt_ids = [str(opts.get_option_at_index(i).id) for i in range(opts.option_count)]
            assert opt_ids == ["research", "rf_intel", "splunk_keyword"]

            # Selecting "splunk_keyword" pivots to Splunk Search with index=* "services.exe"
            app.screen.dismiss("splunk_keyword")
            await pilot.pause()
            await pilot.pause()
            search_pane = app.query_one(SplunkSearchPane)
            from textual.widgets import TextArea

            spl_val = search_pane.query_one("#splunk-search-spl", TextArea).text
            assert spl_val == 'index=* "services.exe"'

    asyncio.run(_run())


def test_global_highlight_selection_pivots_to_research_and_splunk(tmp_path: Path) -> None:
    from textual.widgets import Input, OptionList, TextArea

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

            # F6 -> Floating transparent RF/Splunk-only menu for highlighted text
            await pilot.press("f6")
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            opts = app.screen.query_one("#ctx-menu-options", OptionList)
            opt_ids = [str(opts.get_option_at_index(i).id) for i in range(opts.option_count)]
            assert opt_ids == ["research", "rf_intel", "splunk_keyword"]
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
    from textual.widgets import Checkbox, Static

    from soclens.research import ResearchDossier, ResolvedTarget
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
            art = banner.query_one("#res-mood-art", Static)
            caption = banner.query_one("#res-mood-caption", Static)

            # Idle at startup -> banner hidden, ASCII art off
            assert banner.display is False
            assert art.display is False

            # Searching with default settings -> shows banner WITHOUT ASCII art (0 width), stays visible while searching
            banner.set_mood(determine_research_mood(None, searching=True, query="example.com"))
            await pilot.pause()
            assert banner.display is True
            assert art.display is False
            assert art.region.width == 0
            assert banner._hide_timer is None
            assert "SCANNING..." in str(caption.render())

            # Transition from search -> initial thoughts (dossier verdict), auto-hides after 10s
            banner.AUTO_HIDE_SECONDS = 0.05
            dossier = ResearchDossier(
                target=ResolvedTarget(
                    raw_query="example.com",
                    canonical_name="example.com",
                    detected_kind="domain",
                    entity_id=None,
                ),
                generated_at="2026-11-25T00:00:00Z",
                risk_score=10,
            )
            banner.set_mood(determine_research_mood(dossier))
            await pilot.pause()
            assert banner.display is True
            assert art.display is False
            assert banner._hide_timer is not None
            assert "LOW RISK" in str(caption.render())
            assert "PONY" not in str(caption.render())
            await asyncio.sleep(0.12)
            await pilot.pause()
            assert banner.display is False

            # Settings checkbox exists and defaults to False
            app.activate_tab("tab-settings")
            await pilot.pause()
            await pilot.pause()
            settings_pane = app.query_one(SettingsPane)
            cb = settings_pane.query_one("#set-ascii-art-enabled", Checkbox)
            assert cb.value is False

            # Unlock via env/setting -> ASCII art renders during search -> initial thoughts and still drops after 10s
            monkeypatch.setenv("SOCLENS_ASCII_ART", "true")
            banner.set_mood(determine_research_mood(None, searching=True, query="evil.test"))
            await pilot.pause()
            assert banner.display is True
            assert art.display is True
            assert banner._hide_timer is None

            banner.set_mood(determine_research_mood(dossier))
            await pilot.pause()
            assert banner.display is True
            assert art.display is True
            assert "HAPPY PONY" in str(caption.render())
            assert banner._hide_timer is not None
            await asyncio.sleep(0.12)
            await pilot.pause()
            assert banner.display is False

    asyncio.run(_run())


def _strip_bgcolors_for_text(strip: object, needle: str) -> list[str]:
    """Return hex bgcolor names for every segment overlapping ``needle`` in ``strip``."""
    from textual.strip import Strip

    assert isinstance(strip, Strip)
    text = strip.text
    start = text.find(needle)
    assert start != -1, f"{needle!r} not found in strip line {text!r}"
    end = start + len(needle)
    pos = 0
    bgs: list[str] = []
    for seg in strip._segments:
        seg_end = pos + len(seg.text)
        if seg_end > start and pos < end and seg.style and seg.style.bgcolor:
            bgs.append(str(seg.style.bgcolor.name))
        pos = seg_end
    return bgs


def test_bottom_panel_highlight_and_right_click_s1_and_rf_playbooks(tmp_path: Path) -> None:
    from textual.widgets import Input, OptionList, TextArea

    from soclens.tui.modals import ContextMenuModal
    from soclens.tui.rf_formatters import render_playbook_alert_detail
    from soclens.tui.s1_formatters import render_s1_record_detail
    from soclens.tui.screens.base import SelectableRichLog

    async def _find_line_and_col(
        log: SelectableRichLog, needle: str
    ) -> tuple[int, int]:
        for idx, strip in enumerate(log.lines):
            col = strip.text.find(needle)
            if col != -1:
                return idx, col
        raise AssertionError(f"Could not find {needle!r} in SelectableRichLog")

    # 1. SentinelOne bottom detail panel: visible drag highlight + button-like known field clicks
    s1_app = create_app(
        client=MagicMock(),
        s1_client=MagicMock(),
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=tmp_path,
    )

    async def _run_s1() -> None:
        async with s1_app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            s1_log = s1_app.query_one("#s1-detail-log", SelectableRichLog)
            s1_log.clear()
            rec = {
                "id": "th-901",
                "threatInfo": {
                    "threatName": "evil_dropper.exe",
                    "classification": "Suspicious binary execution from user temp directory",
                    "originatorProcess": "services.exe",
                    "commandLine": "services.exe -enc SQBFAFgA",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                },
                "agentRealtimeInfo": {"agentComputerName": "WKSTN-042"},
            }
            s1_log.write(render_s1_record_detail("threats", rec))
            await pilot.pause()

            # A. Free-text field (Classification) without highlight -> left or right click opens NO menu
            cls_line, cls_col = await _find_line_and_col(s1_log, "Suspicious binary")
            s1_log.scroll_to(y=max(0, cls_line - 1), animate=False)
            await pilot.pause()
            sy = s1_log.content_region.y + (cls_line - int(round(s1_log.scroll_y)))
            sx = s1_log.content_region.x + cls_col + 2
            await pilot.click(offset=(sx, sy), button=1)
            await pilot.pause()
            assert not isinstance(s1_app.screen, ContextMenuModal)
            await pilot.click(offset=(sx, sy), button=3)
            await pilot.pause()
            assert not isinstance(s1_app.screen, ContextMenuModal)

            # B. Real mouse-drag highlight inside free-text Classification -> bright #f2cc60 highlight + search!
            drag_start_x = s1_log.content_region.x + cls_col
            drag_end_x = drag_start_x + len("Suspicious binary") - 1
            await pilot.mouse_down(offset=(drag_start_x, sy))
            await pilot.hover(offset=(drag_end_x, sy))
            await pilot.mouse_up(offset=(drag_end_x, sy))
            await pilot.pause()
            assert s1_app.get_selected_text() == "Suspicious binary"
            vis_y = cls_line - s1_log.scroll_offset.y
            sel_strip = s1_log.render_line(vis_y)
            assert "#f2cc60" in _strip_bgcolors_for_text(sel_strip, "Suspicious binary")
            assert "#f2cc60" not in _strip_bgcolors_for_text(sel_strip, "execution")
            assert "#f2cc60" not in _strip_bgcolors_for_text(sel_strip, "from")

            await pilot.click(offset=(drag_start_x + 3, sy), button=3)
            await pilot.pause()
            assert isinstance(s1_app.screen, ContextMenuModal)
            opts = s1_app.screen.query_one("#ctx-menu-options", OptionList)
            assert [str(opts.get_option_at_index(i).id) for i in range(opts.option_count)] == [
                "research",
                "rf_intel",
                "splunk_keyword",
            ]
            s1_app.screen.dismiss(None)
            await pilot.pause()
            s1_app.screen.clear_selection()
            await pilot.pause()

            # C. Hovering over known field (Process -> services.exe) highlights it like a button (#1f6feb)
            proc_line, proc_col = await _find_line_and_col(s1_log, "services.exe")
            s1_log.scroll_to(y=max(0, proc_line - 1), animate=False)
            await pilot.pause()
            psy = s1_log.content_region.y + (proc_line - int(round(s1_log.scroll_y)))
            psx = s1_log.content_region.x + proc_col + 2
            await pilot.hover(offset=(psx, psy))
            await pilot.pause()
            assert s1_log._hovered_pivot == ("Process", "services.exe")
            proc_vis_y = proc_line - s1_log.scroll_offset.y
            assert "#1f6feb" in _strip_bgcolors_for_text(
                s1_log.render_line(proc_vis_y), "services.exe"
            )

            # D. Drag-highlighting a substring of services.exe does NOT auto-popup on release, highlights #f2cc60
            p_start_x = s1_log.content_region.x + proc_col
            p_end_x = p_start_x + len("services") - 1
            await pilot.mouse_down(offset=(p_start_x, psy))
            await pilot.hover(offset=(p_end_x, psy))
            await pilot.mouse_up(offset=(p_end_x, psy))
            await pilot.pause()
            assert not isinstance(s1_app.screen, ContextMenuModal)
            assert s1_app.get_selected_text() == "services"
            proc_strip = s1_log.render_line(proc_vis_y)
            assert "#f2cc60" in _strip_bgcolors_for_text(proc_strip, "services")
            assert "#f2cc60" not in _strip_bgcolors_for_text(proc_strip, "Process")
            assert "#f2cc60" not in _strip_bgcolors_for_text(proc_strip, ".exe")
            s1_app.screen.clear_selection()
            await pilot.pause()

            # E. Single left-click (button=1) on known field services.exe auto-pops up RF/Splunk search!
            await pilot.click(offset=(psx, psy), button=1)
            await pilot.pause()
            assert isinstance(s1_app.screen, ContextMenuModal)
            assert s1_log._active_pivot == ("Process", "services.exe")
            opts = s1_app.screen.query_one("#ctx-menu-options", OptionList)
            assert [str(opts.get_option_at_index(i).id) for i in range(opts.option_count)] == [
                "research",
                "rf_intel",
                "splunk_keyword",
            ]
            assert "services.exe" in str(opts.get_option_at_index(0).prompt)
            s1_app.screen.dismiss("splunk_keyword")
            await pilot.pause()
            await pilot.pause()
            assert s1_log._active_pivot is None
            assert (
                s1_app.query_one("#splunk-search-spl", TextArea).text
                == 'index=* "services.exe"'
            )

    asyncio.run(_run_s1())

    # 2. RF Playbook Alert bottom detail panel: visible drag highlight + button-like known field click
    rf_app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )

    async def _run_rf() -> None:
        async with rf_app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            rf_log = rf_app.query_one("#rf-log", SelectableRichLog)
            rf_log.clear()
            norm = {
                "id": "pb-hl-1",
                "category": "domain_abuse",
                "status": "New",
                "priority": "High",
                "title": "spoof-bank.example",
                "rule_name": "Brand Lookalike",
                "assignee": "analyst",
                "created": "2026-11-24T10:00:00Z",
                "updated": "2026-11-24T12:00:00Z",
                "targets": ["mybank.example", "portal.mybank.example"],
                "logo_hashes": ["hash:" + ("f" * 64)],
                "raw": {
                    "panel_evidence_summary": {
                        "explanation": "Typosquatted portal observed hosting credential form",
                    },
                    "panel_evidence_dns": {
                        "ip_list": [{"ip": "203.0.113.77", "risk_score": 85, "criticality": "High"}],
                    },
                },
            }
            rf_log.write(render_playbook_alert_detail(norm))
            await pilot.pause()

            # A. Free-text Explanation without highlight -> left or right click opens NO menu
            exp_line, exp_col = await _find_line_and_col(rf_log, "credential form")
            rf_log.scroll_to(y=max(0, exp_line - 1), animate=False)
            await pilot.pause()
            esy = rf_log.content_region.y + (exp_line - int(round(rf_log.scroll_y)))
            esx = rf_log.content_region.x + exp_col
            await pilot.click(offset=(esx + 2, esy), button=1)
            await pilot.pause()
            assert not isinstance(rf_app.screen, ContextMenuModal)
            await pilot.click(offset=(esx + 2, esy), button=3)
            await pilot.pause()
            assert not isinstance(rf_app.screen, ContextMenuModal)

            # B. Drag highlight "observed" in free-text Explanation -> ONLY "observed" is highlighted (#f2cc60)
            obs_line, obs_col = await _find_line_and_col(rf_log, "observed")
            rf_log.scroll_to(y=max(0, obs_line - 1), animate=False)
            await pilot.pause()
            osy = rf_log.content_region.y + (obs_line - int(round(rf_log.scroll_y)))
            osx = rf_log.content_region.x + obs_col
            await pilot.mouse_down(offset=(osx, osy))
            await pilot.hover(offset=(osx + 3, osy))
            await pilot.hover(offset=(osx + len("observed") - 1, osy))
            await pilot.mouse_up(offset=(osx + len("observed") - 1, osy))
            await pilot.pause()
            assert rf_app.get_selected_text() == "observed"
            obs_vis_y = obs_line - rf_log.scroll_offset.y
            obs_strip = rf_log.render_line(obs_vis_y)
            assert "#f2cc60" in _strip_bgcolors_for_text(obs_strip, "observed")
            assert "#f2cc60" not in _strip_bgcolors_for_text(obs_strip, "Typosquatted")
            assert "#f2cc60" not in _strip_bgcolors_for_text(obs_strip, "portal")
            assert "#f2cc60" not in _strip_bgcolors_for_text(obs_strip, "hosting")

            # Also verify start-of-line (vis_start == 0) and end-of-line (vis_end == line_len) slices
            line_text = rf_log.lines[obs_line].text
            rf_app.screen.clear_selection()
            await pilot.pause()
            await pilot.mouse_down(offset=(rf_log.content_region.x, osy))
            await pilot.hover(offset=(rf_log.content_region.x + 5, osy))
            await pilot.mouse_up(offset=(rf_log.content_region.x + 5, osy))
            await pilot.pause()
            start_strip = rf_log.render_line(obs_vis_y)
            assert "#f2cc60" in _strip_bgcolors_for_text(start_strip, start_strip.text[:6])
            assert "#f2cc60" not in _strip_bgcolors_for_text(start_strip, "observed")

            rf_app.screen.clear_selection()
            await pilot.pause()
            end_x1 = rf_log.content_region.x + line_text.index("hosting")
            end_x2 = rf_log.content_region.x + obs_strip.cell_length - 1
            await pilot.mouse_down(offset=(end_x1, osy))
            await pilot.hover(offset=(end_x2, osy))
            await pilot.mouse_up(offset=(end_x2, osy))
            await pilot.pause()
            end_strip = rf_log.render_line(obs_vis_y)
            assert "#f2cc60" in _strip_bgcolors_for_text(end_strip, "hosting")
            assert "#f2cc60" not in _strip_bgcolors_for_text(end_strip, "observed")

            # Re-select "observed" and open right-click search menu
            rf_app.screen.clear_selection()
            await pilot.pause()
            await pilot.mouse_down(offset=(osx, osy))
            await pilot.hover(offset=(osx + len("observed") - 1, osy))
            await pilot.mouse_up(offset=(osx + len("observed") - 1, osy))
            await pilot.pause()
            await pilot.click(offset=(osx + 2, osy), button=3)
            await pilot.pause()
            assert isinstance(rf_app.screen, ContextMenuModal)
            opts = rf_app.screen.query_one("#ctx-menu-options", OptionList)
            assert [str(opts.get_option_at_index(i).id) for i in range(opts.option_count)] == [
                "research",
                "rf_intel",
                "splunk_keyword",
            ]
            rf_app.screen.dismiss(None)
            await pilot.pause()
            rf_app.screen.clear_selection()
            await pilot.pause()

            # C. Known field DNS IP (203.0.113.77) -> left-click auto-pops up RF/Splunk search!
            ip_line, ip_col = await _find_line_and_col(rf_log, "203.0.113.77")
            rf_log.scroll_to(y=max(0, ip_line - 1), animate=False)
            await pilot.pause()
            isy = rf_log.content_region.y + (ip_line - int(round(rf_log.scroll_y)))
            isx = rf_log.content_region.x + ip_col + 2
            await pilot.click(offset=(isx, isy), button=1)
            await pilot.pause()
            assert isinstance(rf_app.screen, ContextMenuModal)
            rf_app.screen.dismiss("research")
            await pilot.pause()
            await pilot.pause()
            assert rf_app.query_one("#res-target-input", Input).value == "203.0.113.77"

    asyncio.run(_run_rf())


def test_datatable_highlight_and_known_cell_right_click(tmp_path: Path) -> None:
    from textual.widgets import OptionList

    from soclens.tui.modals import ContextMenuModal
    from soclens.tui.screens.base import DoubleClickDataTable

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
            table = app.query_one("#s1-table", DoubleClickDataTable)
            table.clear(columns=True)
            table.add_columns("Host", "Status", "SHA-1")
            sha1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
            table.add_row("FIN-WKSTN-07", "Resolved", sha1)
            await pilot.pause()

            row_y = table.content_region.y + 1
            line_txt = table.render_line(1).text
            host_col = line_txt.index("FIN-WKSTN-07")
            status_col = line_txt.index("Resolved")

            # 1. Right-click Status cell without highlight -> non-searchable field, NO menu
            await pilot.click(offset=(table.content_region.x + status_col + 2, row_y), button=3)
            await pilot.pause()
            assert not isinstance(app.screen, ContextMenuModal)

            # 2. Right-click Host cell without highlight -> known field, RF/Splunk-only menu
            await pilot.click(offset=(table.content_region.x + host_col + 2, row_y), button=3)
            await pilot.pause()
            assert isinstance(app.screen, ContextMenuModal)
            opts = app.screen.query_one("#ctx-menu-options", OptionList)
            assert [str(opts.get_option_at_index(i).id) for i in range(opts.option_count)] == [
                "research",
                "rf_intel",
                "splunk_keyword",
            ]
            assert "FIN-WKSTN-07" in str(opts.get_option_at_index(0).prompt)
            app.screen.dismiss(None)
            await pilot.pause()

            # 3. Mouse-drag highlight substring inside table cell -> extracts exact text + #f2cc60 style
            sha_col = line_txt.index(sha1)
            sx1 = table.content_region.x + sha_col
            sx2 = sx1 + 11
            await pilot.mouse_down(offset=(sx1, row_y))
            await pilot.hover(offset=(sx2, row_y))
            await pilot.mouse_up(offset=(sx2, row_y))
            await pilot.pause()
            assert app.get_selected_text() == sha1[:12]
            sel_strip = table.render_line(1)
            pos = 0
            bgs: list[str] = []
            for seg in sel_strip._segments:
                seg_end = pos + len(seg.text)
                if seg_end > sha_col and pos < sha_col + 12 and seg.style and seg.style.bgcolor:
                    bgs.append(str(seg.style.bgcolor.name))
                pos = seg_end
            assert "#f2cc60" in bgs
            assert "#f2cc60" not in _strip_bgcolors_for_text(sel_strip, "FIN-WKSTN-07")
            assert "#f2cc60" not in _strip_bgcolors_for_text(sel_strip, "Resolved")
            assert "#f2cc60" not in _strip_bgcolors_for_text(sel_strip, sha1[12:])

    asyncio.run(_run())


def test_legacy_right_click_menus_removed_across_panes(tmp_path: Path) -> None:
    from soclens.tui.modals import ContextMenuModal

    app = create_app(
        client=MagicMock(),
        s1_client=MagicMock(),
        dry_run=True,
        initial_tab="tab-dashboard",
        view_mode="admin",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            for tab_id, target_sel in (
                ("tab-dashboard", "#dash-env-summary"),
                ("tab-logs", "#app-log"),
                ("tab-llm", "#llm-transcript"),
                ("tab-settings", "#settings-status"),
                ("tab-sigma", "#sigma-log"),
                ("tab-splunk-bundle", "#splunk-results-table"),
                ("tab-splunk-es", "#es-detail"),
                ("tab-splunk-search", "#splunk-search-detail"),
                ("tab-watchlists", "#wl-status"),
                ("tab-brand-logos", "#brand-status"),
            ):
                app.activate_tab(tab_id)
                await pilot.pause()
                await pilot.pause()
                await pilot.click(target_sel, offset=(2, 0), button=3)
                await pilot.pause()
                assert not isinstance(app.screen, ContextMenuModal), (
                    f"Unexpected right-click menu opened on {tab_id} ({target_sel})"
                )

    asyncio.run(_run())


def test_alert_cache_store_nonblocking_load_prepared_images_and_404_negative_cache(
    tmp_path: Path,
) -> None:
    from soclens.alert_cache import CACHE_SOURCE_RF_PLAYBOOK

    cache_dir = tmp_path / "alert_cache"
    seed = AlertCacheStore(cache_dir=cache_dir)
    seed.put(CACHE_SOURCE_RF, [{"id": "old-1"}], fetched_at=100.0)
    seed.put(CACHE_SOURCE_RF_PLAYBOOK, [{"id": "pb-1"}], fetched_at=100.0)
    seed.mark_image_unavailable("domain_abuse__pb-1__missing-img")

    # load_on_init=False keeps constructor instant; newer in-memory entries are preserved
    store = AlertCacheStore(cache_dir=cache_dir, load_on_init=False)
    assert store.get(CACHE_SOURCE_RF) is None
    assert store.is_image_unavailable("domain_abuse__pb-1__missing-img") is False

    store.put(CACHE_SOURCE_RF, [{"id": "newer-in-mem"}], fetched_at=500.0)
    loaded = store.load_from_disk_sources()
    assert CACHE_SOURCE_RF_PLAYBOOK in loaded
    assert CACHE_SOURCE_RF not in loaded
    assert store.get(CACHE_SOURCE_RF).items == [{"id": "newer-in-mem"}]  # type: ignore[union-attr]
    assert store.is_image_unavailable("domain_abuse__pb-1__missing-img") is True

    # Prepared image storage & retrieval
    store.put_prepared_image("k1", {"bytes": b"abc", "crop_checked": True})
    got = store.get_prepared_image("k1")
    assert got is not None and got["crop_checked"] is True

    # Writing actual image bytes clears the 404 negative cache entry
    store.put_image_bytes("domain_abuse__pb-1__missing-img", b"\x89PNG\r\n\x1a\n123456")
    assert store.is_image_unavailable("domain_abuse__pb-1__missing-img") is False


def test_rf_tab_hydrates_without_ui_image_decoding_or_api_calls(
    tmp_path: Path, monkeypatch
) -> None:
    import soclens.tui.image_render as image_render_mod
    import soclens.tui.screens.rf_intel as rf_intel_mod
    from soclens.tui.image_render import DecodedImage, encode_png

    recent = _recent_iso(1)
    rgb_rows = [bytes([20, 80, 160] * 16) for _ in range(16)]
    png_bytes = encode_png(
        DecodedImage(width=16, height=16, color_type=2, bit_depth=8, raw_size=0, rgb_rows=rgb_rows)
    )

    rf_client = MagicMock()
    rf_client.search_alerts_v3.return_value = {
        "data": [
            {
                "id": "rf-u1",
                "title": "Background RF Alert",
                "rule": {"name": "Lookalike"},
                "review": {"status": "New"},
                "log": {"triggered": recent},
            }
        ],
        "counts": {"total": 1},
    }
    rf_client.get_alert_v3.return_value = {
        "data": {
            "id": "rf-u1",
            "title": "Background RF Alert",
            "rule": {"name": "Lookalike"},
            "review": {"status": "New", "assignee": "soc_analyst"},
            "log": {"triggered": recent},
        }
    }
    rf_client.search_playbook_alerts.return_value = {
        "data": [
            {
                "playbook_alert_id": "pb-u1",
                "category": "domain_abuse",
                "status": "New",
                "priority": "High",
                "title": "fake-login.example",
                "updated": recent,
            }
        ],
        "counts": {"total": 1},
    }
    rf_client.get_playbook_alert.return_value = {
        "data": {
            "playbook_alert_id": "pb-u1",
            "category": "domain_abuse",
            "panel_status": {"status": "New", "priority": "High", "entity_name": "fake-login.example"},
            "panel_evidence_summary": {
                "screenshots": [{"image_id": "img-u1", "description": "Login spoof"}]
            },
        }
    }
    rf_client.get_playbook_alert_image.return_value = png_bytes

    es_client = MagicMock()
    es_client.query_findings_hybrid.return_value = {"items": [], "source_backend": "mc_v2"}

    app = create_app(
        client=rf_client,
        dry_run=True,
        initial_tab="tab-splunk-es",
        workspace_dir=tmp_path,
        preload_alerts=True,
        alert_cache_refresh_seconds=0,
    )
    app.splunk_es_client = es_client  # type: ignore[attr-defined]

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()

            def _forbid_ui_work(*_args, **_kwargs):
                raise AssertionError("UI thread must not decode/crop/blur/encode cached images!")

            monkeypatch.setattr(rf_intel_mod, "blur_decoded_image", _forbid_ui_work)
            monkeypatch.setattr(rf_intel_mod, "encode_png", _forbid_ui_work)
            monkeypatch.setattr(image_render_mod, "decode_image", _forbid_ui_work)
            monkeypatch.setattr(image_render_mod, "auto_crop_margins", _forbid_ui_work)
            monkeypatch.setattr(image_render_mod, "blur_decoded_image", _forbid_ui_work)
            monkeypatch.setattr(image_render_mod, "encode_png", _forbid_ui_work)

            # Visiting RF Alerts hydrates Alerts v3 + Playbook Alerts with zero UI image decode
            app.activate_tab("tab-rf-intel")
            await pilot.pause()
            await pilot.pause()
            rf_pane = app.query_one(RFIntelPane)
            assert rf_pane._active_mode == "alerts_v3"
            assert rf_pane.query_one("#rf-results-table", DoubleClickDataTable).row_count == 1

            # Switch to Playbook Alerts view: renders inline pre-blurred screenshot with ZERO UI decode/blur!
            from textual.widgets import Select

            rf_pane.query_one("#rf-view-select", Select).value = "playbook"
            await pilot.pause()
            await pilot.pause()
            assert rf_pane._active_mode == "playbook"
            assert rf_pane.query_one("#rf-results-table", DoubleClickDataTable).row_count == 1
            assert rf_client.search_alerts_v3.call_count == 1
            assert rf_client.search_playbook_alerts.call_count == 1
            assert rf_client.get_playbook_alert_image.call_count == 1

    asyncio.run(_run())


def test_cold_disk_cache_warms_in_background_and_skips_404_images(tmp_path: Path) -> None:
    from soclens.alert_cache import CACHE_SOURCE_RF_PLAYBOOK
    from soclens.client import RecordedFutureError
    from soclens.tui.image_render import DecodedImage, encode_png
    from soclens.tui.rf_formatters import normalize_alert_v3

    recent = _recent_iso(1)
    rgb_rows = [bytes([60, 120, 200] * 16) for _ in range(16)]
    png_bytes = encode_png(
        DecodedImage(width=16, height=16, color_type=2, bit_depth=8, raw_size=0, rgb_rows=rgb_rows)
    )

    cache_dir = tmp_path / ".soclens_cache" / "alerts"
    seed = AlertCacheStore(cache_dir=cache_dir)
    seed.put(
        CACHE_SOURCE_RF,
        [
            normalize_alert_v3(
                {
                    "id": "disk-a1",
                    "title": "Disk Alert",
                    "rule": {"name": "Disk Rule"},
                    "review": {"status": "New"},
                    "ai_insights": {"priority": "High"},
                    "log": {"triggered": recent},
                }
            )
        ],
        meta={"total": 1, "details": {}},
    )
    seed.put(
        CACHE_SOURCE_RF_PLAYBOOK,
        [
            {
                "id": "disk-pb-1",
                "category": "domain_abuse",
                "status": "New",
                "priority": "High",
                "title": "disk-pb.example",
                "updated": recent,
                "screenshot_ids": ["img-disk-1"],
            }
        ],
        meta={
            "total": 1,
            "details": {
                "disk-pb-1": {
                    "playbook_alert_id": "disk-pb-1",
                    "category": "domain_abuse",
                    "panel_status": {"status": "New", "priority": "High"},
                    "panel_evidence_summary": {"screenshots": [{"image_id": "img-disk-1"}]},
                }
            },
            "image_keys": {"disk-pb-1": [["domain_abuse", "disk-pb-1", "domain_abuse__disk-pb-1__img-disk-1"]]},
        },
    )
    seed.put_image_bytes("domain_abuse__disk-pb-1__img-disk-1", png_bytes)
    seed.mark_image_unavailable("domain_abuse__disk-pb-2__img-404")

    rf_client = MagicMock()
    rf_client.search_alerts_v3.return_value = {"data": [], "counts": {"total": 0}}
    rf_client.search_playbook_alerts.return_value = {
        "data": [
            {
                "playbook_alert_id": "disk-pb-2",
                "category": "domain_abuse",
                "status": "New",
                "priority": "High",
                "title": "missing-img.example",
                "updated": recent,
            }
        ],
        "counts": {"total": 1},
    }
    rf_client.get_playbook_alert.return_value = {
        "data": {
            "playbook_alert_id": "disk-pb-2",
            "category": "domain_abuse",
            "panel_status": {"status": "New", "priority": "High"},
            "panel_evidence_summary": {"screenshots": [{"image_id": "img-404"}]},
        }
    }
    rf_client.get_playbook_alert_image.side_effect = RecordedFutureError(
        404, "Not found", endpoint="/playbook-alert/domain_abuse/disk-pb-2/image/img-404"
    )

    app = create_app(
        client=rf_client,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        preload_alerts=False,
    )
    # Constructor did not synchronously load disk cache
    assert app.alert_cache.get(CACHE_SOURCE_RF) is None

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()

            # Background disk warmer loaded JSON + prepared image bytes
            assert app.alert_cache.get(CACHE_SOURCE_RF) is not None
            assert app.alert_cache.get_prepared_image("domain_abuse__disk-pb-1__img-disk-1") is not None

            # Running playbook preload skips the already-marked 404 image completely
            app._preload_rf_playbook_24h()
            assert rf_client.get_playbook_alert_image.call_count == 0

            # Switching to RF Intel hydrates instantly
            app.activate_tab("tab-rf-intel")
            await pilot.pause()
            await pilot.pause()
            rf_pane = app.query_one(RFIntelPane)
            assert rf_pane.query_one("#rf-results-table", DoubleClickDataTable).row_count == 1

    asyncio.run(_run())


def test_per_source_workers_independent_when_one_source_blocks(tmp_path: Path) -> None:
    import threading

    recent = _recent_iso(1)
    pb_gate = threading.Event()
    pb_started = threading.Event()

    rf_client = MagicMock()
    rf_client.search_alerts_v3.return_value = {
        "data": [
            {
                "id": "rf-fast-1",
                "title": "Fast RF Alert",
                "rule": {"name": "Rule"},
                "review": {"status": "New"},
                "log": {"triggered": recent},
            }
        ],
        "counts": {"total": 1},
    }
    rf_client.get_alert_v3.return_value = {"data": {"id": "rf-fast-1", "title": "Fast RF Alert"}}

    def _slow_playbook(**_kwargs):
        pb_started.set()
        pb_gate.wait(timeout=5.0)
        return {"data": [], "counts": {"total": 0}}

    rf_client.search_playbook_alerts.side_effect = _slow_playbook

    es_client = MagicMock()
    es_client.query_findings_hybrid.return_value = {
        "items": [{"event_id": "es-fast-1", "rule_title": "Fast ES", "urgency": "high", "_time": recent}],
        "source_backend": "mc_v2",
    }
    s1_client = MagicMock()
    s1_client.console_url = "https://tenant.sentinelone.net"
    s1_client.list_threats.return_value = []
    s1_client.list_sites.return_value = []

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
            # Wait for slow playbook worker to start, while fast workers finish independently
            assert pb_started.wait(timeout=3.0)
            for _ in range(30):
                if (
                    app.alert_cache.get(CACHE_SOURCE_RF) is not None
                    and app.alert_cache.get(CACHE_SOURCE_ES) is not None
                    and app.alert_cache.get(CACHE_SOURCE_S1) is not None
                ):
                    break
                await pilot.pause(0.05)

            assert app.alert_cache.get(CACHE_SOURCE_RF) is not None
            assert app.alert_cache.get(CACHE_SOURCE_ES) is not None
            assert app.alert_cache.get(CACHE_SOURCE_S1) is not None

            # Switch to RF Alerts while Playbook worker is STILL blocked -> instant Alerts v3 hydration!
            app.activate_tab("tab-rf-intel")
            await pilot.pause()
            await pilot.pause()
            rf_pane = app.query_one(RFIntelPane)
            assert rf_pane.query_one("#rf-results-table", DoubleClickDataTable).row_count == 1
            # Visiting tab did NOT re-trigger search_alerts_v3
            assert rf_client.search_alerts_v3.call_count == 1

            pb_gate.set()
            await app.workers.wait_for_complete()

    asyncio.run(_run())


def test_api_access_registry_and_research_skips_denied_apis(tmp_path: Path) -> None:
    import json

    from soclens.api_access import (
        ApiAccessRegistry,
        credential_fingerprint,
        is_permanent_access_denial,
    )
    from soclens.client import RecordedFutureAPIError, RecordedFutureAuthError
    from soclens.research import probe_api_capabilities, research_target

    assert is_permanent_access_denial(401, message="Bad authorization token") is True
    assert is_permanent_access_denial(403, permission_type="missing_api_privileges") is True
    assert is_permanent_access_denial(403, permission_type="proxy_blocked") is False
    assert is_permanent_access_denial(429, message="Rate limit") is False
    assert is_permanent_access_denial(400, message="Bad arg") is False

    # Seed from rf_api_errors.jsonl
    err_log = tmp_path / "logs" / "rf_api_errors.jsonl"
    err_log.parent.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    err_log.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": now_iso,
                        "endpoint": "/risk/history",
                        "method": "POST",
                        "status_code": 403,
                        "message": "Access requires Risk Api privilege",
                        "category": "core_flat",
                    }
                ),
                json.dumps(
                    {
                        "timestamp": now_iso,
                        "endpoint": "/search",
                        "method": "GET",
                        "status_code": 401,
                        "message": "Bad authorization token.",
                        "category": "sandbox_v0",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    reg = ApiAccessRegistry(state_path=tmp_path / ".soclens_cache" / "api_access.json")
    fp1 = credential_fingerprint("token-one")
    sb_fp1 = credential_fingerprint("bad-sandbox")
    seeded = reg.seed_from_error_log(err_log, rf_core_fp=fp1, rf_sandbox_fp=sb_fp1)
    assert seeded == 2
    assert reg.is_denied("risk_history", credential_fp=fp1) is True
    assert reg.is_denied("sandbox_v0", credential_fp=sb_fp1) is True

    # Different token invalidates cached denials automatically
    fp2 = credential_fingerprint("token-two")
    assert reg.is_denied("risk_history", credential_fp=fp2) is False

    # research_target records 403 denials on first call and skips them on second call with 0 HTTP calls
    reg2 = ApiAccessRegistry(state_path=tmp_path / ".soclens_cache" / "api_access_2.json")
    client = MagicMock()
    client._stop_event = None
    client.api_token = "tok-a"
    client.sandbox_token = "tok-sb"
    client.asi_api_key = None
    client.riskrecon_token = None
    client.entity_match.return_value = [{"id": "idn:evil.example", "name": "evil.example", "type": "InternetDomainName"}]
    client.entity_lookup.return_value = {"name": "evil.example"}
    client.v2_lookup.return_value = {"data": {"entity": {"id": "idn:evil.example", "name": "evil.example"}, "risk": {"score": 50}}}
    client.v2_company_by_domain.side_effect = RecordedFutureAuthError(
        403, "Missing Data permissions", permission_type="missing_data_permissions"
    )
    client.search_collective_insights.side_effect = RecordedFutureAuthError(
        403, "Not enough privileges", permission_type="missing_api_privileges"
    )
    client.search_risk_history.side_effect = RecordedFutureAuthError(
        403, "Access requires Risk Api privilege", permission_type="missing_api_privileges"
    )
    client.identity_search.side_effect = RecordedFutureAuthError(
        403, "User does not have access", permission_type="missing_api_privileges"
    )
    client.sandbox_search.side_effect = RecordedFutureAuthError(
        401, "Bad authorization token", permission_type="unauthorized"
    )
    client.soar_enrich.return_value = {"data": []}
    client.links_search.return_value = {"data": []}
    client.search_analyst_notes.return_value = {"data": []}
    client.search_detection_rules.return_value = []
    client.malware_intel_query_iocs.side_effect = RecordedFutureAPIError(500, "Transient")
    client.search_alerts_v3.return_value = {"data": []}
    client.search_playbook_alerts.return_value = {"data": []}

    d1 = research_target(
        client,
        "evil.example",
        include_osint=False,
        access_registry=reg2,
    )
    assert d1.sections["collective_insights"].status == "not_entitled"
    assert d1.sections["risk_history"].status == "not_entitled"
    assert d1.sections["identity"].status == "not_entitled"
    assert d1.sections["sandbox"].status == "not_entitled"
    assert "Missing Data permissions" in str(d1.sections["v2_intel"].data["company_by_domain_note"])

    # Second research run must NOT call those denied APIs again, while transient 500 IS retried
    d2 = research_target(
        client,
        "evil2.example",
        include_osint=False,
        access_registry=reg2,
    )
    assert d2.sections["collective_insights"].status == "not_entitled"
    assert "Skipped (no API access cached" in d2.sections["collective_insights"].message
    assert client.search_collective_insights.call_count == 1
    assert client.search_risk_history.call_count == 1
    assert client.identity_search.call_count == 1
    assert client.sandbox_search.call_count == 1
    assert client.v2_company_by_domain.call_count == 1
    assert client.malware_intel_query_iocs.call_count == 2

    # probe_api_capabilities also updates access_registry
    probe_api_capabilities(client, access_registry=reg2)
    assert reg2.is_denied("v2_company", credential_fp=credential_fingerprint("tok-a")) is True


def test_debug_log_file_sink_redaction_and_logs_filters(tmp_path: Path) -> None:
    from textual.widgets import Button, Select

    from soclens.tui.logging_bridge import AppLogStore, LogEntry

    log_file = tmp_path / "logs" / "soclens_debug.log"
    store = AppLogStore()
    store.set_file_sink(log_file, max_bytes=10_000)
    store.append(
        LogEntry(
            timestamp="12:00:00",
            level="DEBUG",
            source="cache",
            logger_name="AlertPreloader",
            message="Loaded cache with X-RFToken: secret-tok-123 and Bearer abcdefgh12345",
        )
    )
    content = log_file.read_text(encoding="utf-8")
    assert "secret-tok-123" not in content
    assert "abcdefgh12345" not in content
    assert "<REDACTED>" in content
    assert "[DEBUG] [cache|AlertPreloader]" in content

    app = create_app(client=MagicMock(), dry_run=True, initial_tab="tab-logs", workspace_dir=tmp_path)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.record_log("Cache debug msg", level="DEBUG", source="cache", logger_name="AlertPreloader")
            app.record_log("Cache info msg", level="INFO", source="cache", logger_name="AlertPreloader")
            app.record_log("Other info msg", level="INFO", source="tui", logger_name="SocLensApp")
            await pilot.pause()

            await pilot.click("#logs-cache-btn")
            await pilot.pause()
            assert app.query_one("#logs-source-select", Select).value == "cache"
            txt = extract_richlog_text(app.query_one("#app-log", RichLog))
            assert "Cache debug msg" in txt
            assert "Cache info msg" in txt
            assert "Other info msg" not in txt

            await pilot.click("#logs-debug-btn")
            await pilot.pause()
            assert app.query_one("#logs-level-select", Select).value == "DEBUG_ONLY"
            dbg_txt = extract_richlog_text(app.query_one("#app-log", RichLog))
            assert "Cache debug msg" in dbg_txt
            assert "Cache info msg" not in dbg_txt

            # Verify narrow 80x24 layout keeps new Cache & Debug buttons unclipped
            await pilot.resize_terminal(80, 24)
            await pilot.pause()
            for btn_id in ("#logs-cache-btn", "#logs-debug-btn", "#logs-tz-btn"):
                btn = app.query_one(btn_id, Button)
                assert btn.region.height >= 1

    asyncio.run(_run())


def test_preload_invalidates_stale_rf_alert_details_on_status_change(tmp_path: Path) -> None:
    from soclens.tui.rf_formatters import normalize_alert_v3

    recent = _recent_iso(2)
    cache_dir = tmp_path / ".soclens_cache" / "alerts"
    seed = AlertCacheStore(cache_dir=cache_dir)

    old_det_1 = {
        "id": "rf-stale-1",
        "title": "Stale Alert 1",
        "rule": {"name": "Rule 1"},
        "review": {"status_in_portal": "New", "priority": "High", "assignee": None},
        "log": {"triggered": recent, "status_date": None},
    }
    old_det_2 = {
        "id": "rf-stale-2",
        "title": "Stale Alert 2",
        "rule": {"name": "Rule 2"},
        "review": {"status_in_portal": "New", "priority": "High", "assignee": None},
        "log": {"triggered": recent, "status_date": None},
    }
    seed.put(
        CACHE_SOURCE_RF,
        [normalize_alert_v3(old_det_1), normalize_alert_v3(old_det_2)],
        timeframe="last_24h",
        meta={"total": 2, "details": {"rf-stale-1": old_det_1, "rf-stale-2": old_det_2}},
    )

    search_row_1 = {
        "id": "rf-stale-1",
        "title": "Stale Alert 1",
        "rule": {"name": "Rule 1"},
        # Search omits status change inside review, only updating status_date
        "log": {"triggered": recent, "status_date": "2026-11-25T16:42:15Z"},
    }
    search_row_2 = {
        "id": "rf-stale-2",
        "title": "Stale Alert 2",
        "rule": {"name": "Rule 2"},
        "review": {"status_in_portal": "Resolved", "priority": "High"},
        "log": {"triggered": recent, "status_date": "2026-11-25T17:00:00Z"},
    }
    fresh_details = {
        "rf-stale-1": {
            "id": "rf-stale-1",
            "title": "Stale Alert 1",
            "rule": {"name": "Rule 1"},
            "review": {"status_in_portal": "Resolved", "priority": "High", "assignee": "soc1@cocc.com"},
            "log": {"triggered": recent, "status_date": "2026-11-25T16:42:15Z"},
        },
        "rf-stale-2": {
            "id": "rf-stale-2",
            "title": "Stale Alert 2",
            "rule": {"name": "Rule 2"},
            "review": {"status_in_portal": "Resolved", "priority": "High", "assignee": "soc2@cocc.com"},
            "log": {"triggered": recent, "status_date": "2026-11-25T17:00:00Z"},
        },
    }

    rf_client = MagicMock()
    rf_client.search_alerts_v3.return_value = {
        "data": [search_row_1, search_row_2],
        "counts": {"total": 2},
    }
    rf_client.get_alert_v3.side_effect = lambda aid: {"data": fresh_details[aid]}

    app = create_app(
        client=rf_client,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        preload_alerts=False,
    )
    app.alert_cache.load_from_disk_sources()
    app._preload_rf_alerts_24h()

    assert rf_client.get_alert_v3.call_count == 2
    entry = app.alert_cache.get(CACHE_SOURCE_RF)
    assert entry is not None
    by_id = {it["id"]: it for it in entry.items}
    assert by_id["rf-stale-1"]["status"] == "Resolved"
    assert by_id["rf-stale-2"]["status"] == "Resolved"
    assert by_id["rf-stale-1"]["assignee"] == "soc1@cocc.com"

    # Second preload with matching status/status_date reuses fresh details with 0 get_alert_v3 calls
    search_row_1["review"] = {"status_in_portal": "Resolved", "priority": "High", "assignee": "soc1@cocc.com"}
    search_row_2["review"] = {"status_in_portal": "Resolved", "priority": "High", "assignee": "soc2@cocc.com"}
    app._preload_rf_alerts_24h()
    assert rf_client.get_alert_v3.call_count == 2


def test_preload_invalidates_stale_playbook_details_on_status_or_updated_change(tmp_path: Path) -> None:
    from soclens.alert_cache import CACHE_SOURCE_RF_PLAYBOOK
    from soclens.tui.rf_formatters import normalize_playbook_alert

    t1 = _recent_iso(4)
    t2 = _recent_iso(1)
    cache_dir = tmp_path / ".soclens_cache" / "alerts"
    seed = AlertCacheStore(cache_dir=cache_dir)

    old_pb = {
        "playbook_alert_id": "pb-stale-1",
        "category": "domain_abuse",
        "panel_status": {
            "status": "New",
            "priority": "High",
            "updated": t1,
            "entity_name": "spoof.example",
        },
        "panel_evidence_summary": {},
    }
    seed.put(
        CACHE_SOURCE_RF_PLAYBOOK,
        [normalize_playbook_alert(old_pb)],
        timeframe="last_24h",
        meta={"total": 1, "details": {"pb-stale-1": old_pb}, "image_keys": {}},
    )

    fresh_pb = {
        "playbook_alert_id": "pb-stale-1",
        "category": "domain_abuse",
        "panel_status": {
            "status": "Resolved",
            "priority": "High",
            "assignee_name": "soc@cocc.com",
            "updated": t2,
            "entity_name": "spoof.example",
        },
        "panel_evidence_summary": {},
    }

    rf_client = MagicMock()
    rf_client.search_playbook_alerts.return_value = {
        "data": [
            {
                "playbook_alert_id": "pb-stale-1",
                "category": "domain_abuse",
                "status": "Resolved",
                "priority": "High",
                "title": "spoof.example",
                "updated": t2,
            }
        ],
        "counts": {"total": 1},
    }
    rf_client.get_playbook_alert.return_value = {"data": fresh_pb}

    app = create_app(
        client=rf_client,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        preload_alerts=False,
    )
    app.alert_cache.load_from_disk_sources()
    app._preload_rf_playbook_24h()

    assert rf_client.get_playbook_alert.call_count == 1
    entry = app.alert_cache.get(CACHE_SOURCE_RF_PLAYBOOK)
    assert entry is not None
    assert entry.items[0]["status"] == "Resolved"
    assert entry.items[0]["assignee"] == "soc@cocc.com"

    # Second preload with identical status & updated reuses cached detail with 0 detail fetches
    app._preload_rf_playbook_24h()
    assert rf_client.get_playbook_alert.call_count == 1


def test_manual_detail_fetch_updates_alert_cache(tmp_path: Path) -> None:
    cache_dir = tmp_path / ".soclens_cache" / "alerts"
    store = AlertCacheStore(cache_dir=cache_dir)
    store.put(
        CACHE_SOURCE_RF,
        [{"id": "rf-1", "title": "Alert 1", "status": "New"}],
        timeframe="last_24h",
        meta={"total": 1, "details": {"rf-1": {"id": "rf-1", "review": {"status_in_portal": "New"}}}},
    )

    fresh_detail = {
        "id": "rf-1",
        "review": {"status_in_portal": "Resolved", "assignee": "analyst@cocc.com"},
        "log": {"status_date": "2026-11-25T18:00:00Z"},
    }
    ok = store.update_cached_item(
        CACHE_SOURCE_RF,
        "rf-1",
        item_updates={"status": "Resolved", "assignee": "analyst@cocc.com"},
        detail=fresh_detail,
    )
    assert ok is True

    reloaded = AlertCacheStore(cache_dir=cache_dir)
    entry = reloaded.get(CACHE_SOURCE_RF)
    assert entry is not None
    assert entry.items[0]["status"] == "Resolved"
    assert entry.items[0]["assignee"] == "analyst@cocc.com"
    assert entry.meta["details"]["rf-1"]["review"]["status_in_portal"] == "Resolved"


def test_playbook_button_preserves_cached_screenshots_and_auto_downloads_missing(
    tmp_path: Path,
) -> None:
    from textual.widgets import Button

    from soclens.alert_cache import CACHE_SOURCE_RF_PLAYBOOK
    from soclens.tui.image_render import DecodedImage, encode_png
    from soclens.tui.rf_formatters import normalize_playbook_alert

    recent = _recent_iso(1)
    rgb_rows = [bytes([25, 110, 210] * 16) for _ in range(16)]
    png_bytes = encode_png(
        DecodedImage(width=16, height=16, color_type=2, bit_depth=8, raw_size=0, rgb_rows=rgb_rows)
    )

    cache_dir = tmp_path / ".soclens_cache" / "alerts"
    seed = AlertCacheStore(cache_dir=cache_dir)
    cached_detail = {
        "playbook_alert_id": "pb-cached-1",
        "category": "domain_abuse",
        "panel_status": {
            "status": "New",
            "priority": "High",
            "updated": recent,
            "entity_name": "cached-brand.example",
        },
        "panel_evidence_summary": {
            "screenshots": [{"image_id": "img-cached-1", "description": "Cached screenshot"}]
        },
    }
    ondemand_detail = {
        "playbook_alert_id": "pb-ondemand-3",
        "category": "domain_abuse",
        "panel_status": {
            "status": "New",
            "priority": "Moderate",
            "updated": recent,
            "entity_name": "ondemand.example",
        },
        "panel_evidence_summary": {
            "screenshots": [{"image_id": "img-ondemand-3", "description": "Missing from disk"}]
        },
    }
    seed.put(
        CACHE_SOURCE_RF_PLAYBOOK,
        [normalize_playbook_alert(cached_detail), normalize_playbook_alert(ondemand_detail)],
        timeframe="last_24h",
        meta={
            "total": 2,
            "details": {"pb-cached-1": cached_detail, "pb-ondemand-3": ondemand_detail},
            "image_keys": {"pb-cached-1": [["domain_abuse", "pb-cached-1", "domain_abuse__pb-cached-1__img-cached-1"]]},
        },
    )
    seed.put_image_bytes("domain_abuse__pb-cached-1__img-cached-1", png_bytes)

    rf_client = MagicMock()
    rf_client.search_playbook_alerts.return_value = {
        "data": [
            {
                "playbook_alert_id": "pb-cached-1",
                "category": "domain_abuse",
                "status": "New",
                "priority": "High",
                "title": "cached-brand.example",
                "updated": recent,
            },
            {
                "playbook_alert_id": "pb-new-2",
                "category": "domain_abuse",
                "status": "New",
                "priority": "High",
                "title": "new-brand.example",
                "updated": recent,
            },
            {
                "playbook_alert_id": "pb-ondemand-3",
                "category": "domain_abuse",
                "status": "New",
                "priority": "Moderate",
                "title": "ondemand.example",
                "updated": recent,
            },
        ],
        "counts": {"total": 3},
    }
    rf_client.get_playbook_alert.return_value = {
        "data": {
            "playbook_alert_id": "pb-new-2",
            "category": "domain_abuse",
            "panel_status": {
                "status": "InProgress",
                "priority": "High",
                "assignee_name": "soc@cocc.com",
                "updated": recent,
                "entity_name": "new-brand.example",
            },
            "panel_evidence_summary": {
                "screenshots": [{"image_id": "img-new-2", "description": "New screenshot"}]
            },
        }
    }
    rf_client.get_playbook_alert_image.return_value = png_bytes

    app = create_app(
        client=rf_client,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        preload_alerts=False,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()

            app.activate_tab("tab-rf-intel")
            await pilot.pause()
            await pilot.pause()
            rf_pane = app.query_one(RFIntelPane)

            # Clicking Playbook Alerts keeps pb-cached-1's screenshots/prepared image and auto-downloads pb-new-2
            await pilot.click("#rf-pb-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert rf_pane._active_mode == "playbook"
            rf_client.get_playbook_alert.assert_called_once_with("domain_abuse", "pb-new-2")
            by_id = {it["id"]: it for it in rf_pane._datasets["playbook"]}
            assert by_id["pb-cached-1"]["screenshot_ids"] == ["img-cached-1"]
            assert by_id["pb-new-2"]["screenshot_ids"] == ["img-new-2"]
            assert rf_pane._image_cache[("domain_abuse", "pb-cached-1", "img-cached-1")].get("decoded") is not None
            assert rf_pane._image_cache[("domain_abuse", "pb-new-2", "img-new-2")].get("decoded") is not None
            assert app.query_one("#rf-images-btn", Button).disabled is False

            # Selecting pb-ondemand-3 (whose image wasn't on disk yet) auto-downloads img-ondemand-3
            table = rf_pane.query_one("#rf-results-table", DoubleClickDataTable)
            ondemand_idx = next(
                idx for idx, it in enumerate(rf_pane._visible_items) if it.get("id") == "pb-ondemand-3"
            )
            table.move_cursor(row=ondemand_idx, column=0)
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert rf_pane._image_cache[("domain_abuse", "pb-ondemand-3", "img-ondemand-3")].get("decoded") is not None
            assert app.alert_cache.get_image_bytes("domain_abuse__pb-ondemand-3__img-ondemand-3") == png_bytes
            img_calls = [call.args for call in rf_client.get_playbook_alert_image.call_args_list]
            assert ("domain_abuse", "pb-new-2", "img-new-2") in img_calls
            assert ("domain_abuse", "pb-ondemand-3", "img-ondemand-3") in img_calls
            assert ("domain_abuse", "pb-cached-1", "img-cached-1") not in img_calls

    asyncio.run(_run())
