"""Unit, CLI, and TUI Pilot tests for configurable display timezones."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfoNotFoundError

import pytest
from textual.widgets import Button, DataTable, Input, RichLog, Select

from soclens.cli import build_parser, main
from soclens.config import ConfigurationError
from soclens.research import ResearchDossier, ResearchSectionResult, ResolvedTarget
from soclens.timezone import (
    format_datetime_in_tz,
    format_iso_date_or_timestamp,
    format_iso_timestamp,
    format_timezone_label,
    get_active_timezone,
    reset_active_timezone,
    resolve_timezone,
    set_active_timezone,
)
from soclens.tui import create_app
from soclens.tui.logging_bridge import LogEntry
from soclens.tui.modals import TimezoneModal
from soclens.tui.research_formatters import build_research_findings
from soclens.tui.rf_formatters import format_date_or_ts, format_timestamp
from soclens.tui.screens.research import ResearchPane


@pytest.fixture(autouse=True)
def _reset_timezone_after_test() -> object:
    reset_active_timezone()
    yield
    reset_active_timezone()


def test_timezone_resolution_offsets_env_and_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert get_active_timezone() == "UTC"

    canon_ny, _ = resolve_timezone("america/new_york")
    assert canon_ny == "America/New_York"

    canon_off, _ = resolve_timezone("+0200")
    assert canon_off == "UTC+02:00"

    canon_neg, _ = resolve_timezone("UTC-5")
    assert canon_neg == "UTC-05:00"

    canon_local, _ = resolve_timezone("local")
    assert canon_local == "local"

    with pytest.raises(ConfigurationError):
        resolve_timezone("Mars/Olympus_Mons")
    with pytest.raises(ConfigurationError):
        resolve_timezone("UTC+25:00")

    monkeypatch.setenv("SOCLENS_TIMEZONE", "Asia/Tokyo")
    assert get_active_timezone() == "Asia/Tokyo"

    with patch("soclens.timezone.ZoneInfo", side_effect=ZoneInfoNotFoundError("no tzdata")):
        fb_name, _ = resolve_timezone("America/New_York")
        assert fb_name == "America/New_York"
        assert format_iso_timestamp("2026-11-24T15:30:00Z", tz_name=fb_name) == "2026-11-24 10:30 EST"


def test_timezone_formatting_utc_and_converted() -> None:
    ts = "2026-11-24T20:30:00Z"
    assert format_iso_timestamp(ts, tz_name="UTC") == "2026-11-24 20:30Z"
    assert format_iso_timestamp(ts, tz_name="America/New_York") == "2026-11-24 15:30 EST"
    assert format_iso_timestamp(ts, tz_name="Asia/Tokyo") == "2026-11-25 05:30 JST"
    assert format_iso_timestamp("2026-11-24T10:00:00Z", tz_name="UTC+05:30") == (
        "2026-11-24 15:30 UTC+05:30"
    )
    assert format_iso_timestamp("2026-11-24") == "2026-11-24"
    assert format_iso_date_or_timestamp("2026-11-24T00:00:00Z", tz_name="America/New_York") == (
        "2026-11-24"
    )

    set_active_timezone("UTC+02:00")
    assert format_timestamp("2026-11-24T10:00:00Z") == "2026-11-24 12:00 UTC+02:00"
    assert format_date_or_ts("2026-11-24T10:00:00Z") == "2026-11-24 12:00 UTC+02:00"
    assert format_timezone_label() == "UTC+02:00"
    dt = datetime(2026, 11, 24, 10, 15, 30, tzinfo=UTC)
    assert format_datetime_in_tz(dt, fmt="%H:%M:%S") == "12:15:30"


def test_cli_timezone_flag_sets_active_timezone_and_rejects_invalid() -> None:
    parser = build_parser()
    parsed = parser.parse_args(["--tz", "America/New_York", "--tui"])
    assert parsed.timezone == "America/New_York"

    with patch("soclens.cli.RecordedFutureClient"):
        with patch("soclens.cli.run_unified_tui"):
            with patch("sys.argv", ["soclens", "--timezone", "America/New_York", "--tui"]):
                main()
    assert get_active_timezone() == "America/New_York"

    with patch("sys.argv", ["soclens", "--timezone", "Invalid/Zone", "--tui"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2


def test_tui_f3_and_logs_tz_button_update_alerts_research_and_logs(
    tmp_path: Path,
) -> None:
    mock_client = MagicMock()
    mock_client.api_token = "tok-tz"
    mock_client.search_alerts_v3.return_value = {
        "data": [
            {
                "id": "al-tz-1",
                "title": "Timezone Test Hit",
                "type": "ENTITY_MATCH",
                "review": {"priority": "High", "status_in_portal": "New", "assignee": "alice"},
                "rule": {"id": "r1", "name": "Rule 1"},
                "log": {"triggered": "2026-11-24T15:00:00Z"},
                "hits": [],
            }
        ],
        "counts": {"returned": 1, "total": 1},
    }

    app = create_app(
        client=mock_client,
        dry_run=True,
        initial_tab="tab-rf-intel",
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()

            # Seed fixed-UTC log entry and Research dossier for deterministic assertions
            app.log_store.append(
                LogEntry(
                    timestamp="15:00:00",
                    level="INFO",
                    source="tui",
                    logger_name="tz-test",
                    message="Deterministic UTC log event",
                    created_utc=datetime(2026, 11, 24, 15, 0, 0, tzinfo=UTC),
                )
            )
            dossier = ResearchDossier(
                target=ResolvedTarget(
                    raw_query="evil.example",
                    detected_kind="domain",
                    canonical_name="evil.example",
                    entity_id="idn:evil.example",
                    v2_type="domain",
                    v2_lookup_id="evil.example",
                ),
                generated_at="2026-11-24T15:00:00Z",
                sections={
                    "v2_intel": ResearchSectionResult(
                        key="v2_intel",
                        title="Connect v2 Intel",
                        status="ok",
                        count=1,
                        data={
                            "lookup": {
                                "data": {
                                    "entity": {"id": "idn:evil.example", "name": "evil.example"},
                                    "timestamps": {
                                        "firstSeen": "2026-11-24T15:00:00Z",
                                        "lastSeen": "2026-11-24T15:00:00Z",
                                    },
                                }
                            }
                        },
                    ),
                    "alerts": ResearchSectionResult(
                        key="alerts",
                        title="Alerts",
                        status="ok",
                        count=1,
                        data={
                            "data": [
                                {
                                    "id": "al-res-1",
                                    "title": "Dossier Hit",
                                    "review": {"priority": "High", "status_in_portal": "New"},
                                    "log": {"triggered": "2026-11-24T15:00:00Z"},
                                }
                            ]
                        },
                    ),
                },
            )
            res_pane = await app.ensure_tab_mounted("tab-research")
            assert isinstance(res_pane, ResearchPane)
            res_pane._current_dossier = dossier
            res_pane._all_findings = build_research_findings(dossier)
            res_pane._render_master_table()
            res_pane._render_detail_panel()

            await pilot.click("#rf-alerts-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            rf_table = app.query_one("#rf-results-table", DataTable)
            assert "2026-11-24 15:00Z" in [str(c) for c in rf_table.get_row_at(0)]

            # Press F3 -> open TimezoneModal -> apply custom UTC+02:00
            await pilot.press("f3")
            await pilot.pause()
            assert isinstance(app.screen, TimezoneModal)
            app.screen.query_one("#tz-custom-input", Input).value = "UTC+02:00"
            await pilot.pause()
            await pilot.click("#tz-apply-btn")
            await pilot.pause()

            assert get_active_timezone() == "UTC+02:00"
            assert "2026-11-24 17:00 UTC+02:00" in [str(c) for c in rf_table.get_row_at(0)]

            # Switch to Research tab so #res-detail-log renders at visible pane width
            await pilot.press("7")
            await pilot.pause()
            res_detail = "\n".join(line.text for line in app.query_one("#res-detail-log", RichLog).lines)
            assert "2026-11-24 17:00 UTC+02:00" in res_detail
            res_table = app.query_one("#res-table", DataTable)
            assert any("2026-11-24 17:00 UTC+02:00" in str(c) for c in res_table.get_row_at(1))

            # Switch to Logs tab, verify badge & updated timestamp
            await pilot.press("8")
            await pilot.pause()
            logs_tz_btn = app.query_one("#logs-tz-btn", Button)
            assert "UTC+02:00" in str(logs_tz_btn.label)
            logs_lines = "\n".join(line.text for line in app.query_one("#app-log", RichLog).lines)
            assert "17:00:00" in logs_lines

            # Open modal from Logs TZ button, select America/New_York preset, and Apply
            await pilot.click("#logs-tz-btn")
            await pilot.pause()
            assert isinstance(app.screen, TimezoneModal)
            app.screen.query_one("#tz-preset-select", Select).value = "America/New_York"
            await pilot.pause()
            await pilot.click("#tz-apply-btn")
            await pilot.pause()
            assert get_active_timezone() == "America/New_York"
            logs_lines_est = "\n".join(line.text for line in app.query_one("#app-log", RichLog).lines)
            assert "10:00:00" in logs_lines_est
            assert "2026-11-24 10:00 EST" in [str(c) for c in rf_table.get_row_at(0)]

            # Revert to UTC via Use UTC button
            await pilot.click("#logs-tz-btn")
            await pilot.pause()
            assert isinstance(app.screen, TimezoneModal)
            await pilot.click("#tz-utc-btn")
            await pilot.pause()
            assert get_active_timezone() == "UTC"
            assert "2026-11-24 15:00Z" in [str(c) for c in rf_table.get_row_at(0)]

    asyncio.run(_run())
