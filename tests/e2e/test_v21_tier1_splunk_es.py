"""Tier 1 E2E happy-path tests for SOCLens v2.1 Splunk ES 8.6 MC & Custom Fields (V21-F6..V21-F8)."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

import tests.e2e.v21_mocks as _v21
from soclens.config import get_splunk_config
from soclens.splunk_es import (
    SplunkESClient,
    extract_custom_fields,
    extract_finding_tenant,
)

if TYPE_CHECKING:
    from tests.e2e.v21_mocks import MockRFServer, MockSplunkESServer

v21_workspace = _v21.v21_workspace
mock_splunk_es_server = _v21.mock_splunk_es_server

pytestmark = [pytest.mark.e2e, pytest.mark.tier1]


def _richlog_text(app: Any, selector: str = "#es-detail") -> str:
    from textual.widgets import RichLog

    log = app.query_one(selector, RichLog)
    return "\n".join(line.text for line in log.lines)


def _settings_file_path(workspace: Path) -> Path:
    raw = os.environ.get("SOCLENS_SETTINGS_FILE")
    if raw:
        return Path(raw)
    return workspace / "settings.json"


def _make_es_client() -> SplunkESClient:
    cfg = get_splunk_config(required=True)
    return SplunkESClient(
        host=cfg.host,
        token=cfg.token,
        username=cfg.username,
        password=cfg.password,
        app=cfg.app,
        verify_ssl=cfg.verify_ssl,
    )


# ==============================================================================
# V21-F6: ES Tenant Extraction & Dynamic Custom Fields
# ==============================================================================


@pytest.mark.feature("V21-F6")
def test_v21_f6_tenant_extraction_case_insensitive_aliases_and_custom_field_config(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _make_es_client() as es:
        res = es.query_findings_hybrid(limit=50)

    by_id = {item["event_id"]: item for item in res["items"]}
    assert by_id["fnd-1001-a"]["tenant_id"] == "1001"
    assert by_id["fnd-1002-org"]["tenant_id"] == "1002"
    assert by_id["fnd-2001-cc"]["tenant_id"] == "2001"
    assert by_id["fnd-2001-cust"]["tenant_id"] == "2001"
    assert by_id["fnd-raw-only"]["tenant_id"] == "1001"
    assert by_id["fnd-unassigned"]["tenant_id"] == ""

    monkeypatch.setenv("SPLUNK_ES_TENANT_FIELD", "snow_ticket")
    monkeypatch.setenv("SPLUNK_ES_CUSTOM_FIELDS", "snow_ticket,case_id")

    from soclens.config import get_splunk_es_tenant_settings

    tenant_cfg = get_splunk_es_tenant_settings()
    assert extract_finding_tenant(by_id["fnd-1001-a"], tenant_cfg) == "INC0010011"

    custom = extract_custom_fields(
        {
            **by_id["fnd-1001-a"],
            "_raw": "raw line",
            "date_hour": "02",
            "splunk_server": "idx1",
        },
        pinned_fields=tenant_cfg.custom_fields,
    )
    assert custom.get("snow_ticket") == "INC0010011"
    assert custom.get("case_id") == "CASE-1001-A"
    assert custom.get("business_unit") == "Finance"
    assert "_raw" not in custom
    assert "date_hour" not in custom
    assert "splunk_server" not in custom


@pytest.mark.feature("V21-F6")
def test_v21_f6_discover_custom_fields_incident_review_and_log_review_fallback(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    with _make_es_client() as es:
        fields = es.discover_custom_fields()
        names = {f["field"] for f in fields}
        assert {"tenant_id", "snow_ticket", "case_id", "business_unit"}.issubset(names)

        incident_reqs = [
            r
            for r in mock_splunk_es_server.requests_log
            if "conf-incident_review/incident_review" in r["path"]
        ]
        log_reqs = [
            r
            for r in mock_splunk_es_server.requests_log
            if "conf-log_review/incident_review" in r["path"]
        ]
        assert len(incident_reqs) >= 1
        assert len(log_reqs) >= 1

        mock_splunk_es_server.requests_log.clear()
        mock_splunk_es_server.set_incident_review_404_fallback(False)
        fields_direct = es.discover_custom_fields(force_refresh=True)
        names_direct = {f["field"] for f in fields_direct}
        assert {"tenant_id", "snow_ticket", "case_id", "business_unit"}.issubset(names_direct)

    direct_log_reqs = [
        r
        for r in mock_splunk_es_server.requests_log
        if "conf-log_review/incident_review" in r["path"]
    ]
    assert direct_log_reqs == []


@pytest.mark.feature("V21-F6")
def test_v21_f6_create_finding_with_custom_additional_fields_and_roundtrip(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    with _make_es_client() as es:
        created = es.create_finding(
            rule_title="Tenant 1001 Custom Alert",
            security_domain="endpoint",
            risk_object="wkstn-1001-01.example.test",
            additional_fields={
                "tenant_id": "1001",
                "snow_ticket": "INC99901",
                "business_unit": "Finance",
            },
        )
        finding_id = created.get("finding_id") or created.get("event_id")
        assert finding_id

        post_reqs = [
            r
            for r in mock_splunk_es_server.requests_log
            if r["method"] == "POST" and r["path"].endswith("/public/v2/findings")
        ]
        assert len(post_reqs) == 1
        add_fields = post_reqs[0]["json_body"].get("additional_fields")
        assert isinstance(add_fields, list)
        assert {"name": "tenant_id", "value": "1001"} in add_fields

        fetched = es.get_finding(finding_id)
        assert fetched["tenant_id"] == "1001"
        assert fetched["custom_fields"]["snow_ticket"] == "INC99901"


@pytest.mark.feature("V21-F6")
def test_v21_f6_tui_tenant_column_header_badge_and_custom_fields_inspector(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from textual.widgets import Checkbox, DataTable, Static

    from soclens.tui import create_app

    monkeypatch.setenv("SPLUNK_ES_CUSTOM_FIELDS", "snow_ticket,case_id")
    app = create_app(
        dry_run=False,
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

            table = app.query_one("#es-table", DataTable)
            assert table.row_count == 8
            rendered_rows = " ".join(
                " ".join(str(cell) for cell in table.get_row_at(idx))
                for idx in range(table.row_count)
            )
            for token in ("1001", "1002", "2001", "INC0010011", "CASE-1001-A"):
                assert token in rendered_rows

            header_text = str(app.query_one("#es-detail-header", Static).content)
            assert "[Tenant: 1001]" in header_text

            await pilot.click("#es-insp-tab-metadata")
            await pilot.pause()
            detail = _richlog_text(app, "#es-detail")
            assert "Custom / Org Fields" in detail
            assert "INC0010011" in detail
            assert "CASE-1001-A" in detail
            assert "Finance" in detail

    asyncio.run(_run())


@pytest.mark.feature("V21-F6")
def test_v21_f6_tui_tenant_structured_filter_and_group_by_tenant_rollup(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Checkbox, DataTable, Input

    from soclens.tui import create_app

    app = create_app(
        dry_run=False,
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

            table = app.query_one("#es-table", DataTable)
            assert table.row_count == 8

            search_inp = app.query_one("#es-search-input", Input)
            search_inp.value = "tenant_id:1001"
            await search_inp.action_submit()
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 4

            search_inp.value = ""
            await search_inp.action_submit()
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 8

            await pilot.click("#es-group-tenant-btn")
            await pilot.pause()
            rows_text = "\n".join(
                " | ".join(str(cell) for cell in table.get_row_at(idx))
                for idx in range(table.row_count)
            )
            assert "Tenant 1001:" in rows_text
            assert "Tenant 2001:" in rows_text
            assert "Tenant 1002:" in rows_text
            assert table.row_count == 12

    asyncio.run(_run())


# ==============================================================================
# V21-F7: ES 8.6 MC v2 Primary & 7.x SPL / notable_update Fallback
# ==============================================================================


@pytest.mark.feature("V21-F7")
def test_v21_f7_mc_v2_primary_findings_and_no_unknown_query_params(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    mock_splunk_es_server.set_ignore_unknown_finding_params(False)
    with _make_es_client() as es:
        res = es.query_findings_hybrid(urgency="high", tenant_id="1001", limit=50)

    assert res["source_backend"] == "mc_v2"
    assert {item["event_id"] for item in res["items"]} == {
        "fnd-1001-b",
        "fnd-grp-1001",
        "fnd-raw-only",
    }

    v2_gets = [
        r
        for r in mock_splunk_es_server.requests_log
        if r["method"] == "GET" and r["path"].endswith("/public/v2/findings")
    ]
    assert len(v2_gets) == 1
    assert "tenant_id" not in v2_gets[0]["query"]


@pytest.mark.feature("V21-F7")
def test_v21_f7_mc_v2_investigations_array_envelope_notes_history_and_context(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    with _make_es_client() as es:
        invs = es.list_investigations()
        inv_guids = {inv.get("investigation_guid") or inv.get("id") for inv in invs}
        assert {"inv-guid-1001", "inv-guid-2001"}.issubset(inv_guids)

        created_inv = es.create_investigation("E2E Inv", finding_ids=["fnd-1001-a"])
        guid = created_inv["investigation_guid"]
        es.add_findings_to_investigation(guid, ["fnd-1001-b"])

        created_note = es.create_note(guid, "Note body", title="T")
        nid = created_note["id"]
        es.update_note(guid, nid, content="Updated")
        notes = es.list_notes(guid)
        assert any(n.get("content") == "Updated" for n in notes.get("items", []))

        history = es.get_history(guid)
        assert isinstance(history, dict)
        es.delete_note(guid, nid)

        queues = es.list_queues()
        assert queues.get("queues")
        asset = es.get_asset("wkstn-1001-01.example.test")
        assert asset
        identity = es.get_identity("jdoe@example.test")
        assert identity
        risk = es.get_risk_scores("wkstn-1001-01.example.test")
        assert risk


@pytest.mark.feature("V21-F7")
def test_v21_f7_mc_v2_404_auto_fallback_to_spl_notable_and_notable_update(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    mock_splunk_es_server.set_mc_v2_enabled(False)
    with _make_es_client() as es:
        res = es.query_findings_hybrid(tenant_id="1001", urgency="critical")
        assert res["source_backend"] == "spl_fallback"
        assert [item["event_id"] for item in res["items"]] == ["fnd-1001-a"]

        paths = [r["path"] for r in mock_splunk_es_server.requests_log]
        assert any(p.endswith("/public/v2/findings") for p in paths)
        assert any(p.endswith("/search/jobs") for p in paths)

        triage_res = es.triage_findings_hybrid(
            ["fnd-1001-a@@notable@@1001"],
            status="resolved",
            disposition="disposition:1",
            note="7x close",
        )
        assert triage_res["backend"] == "notable_update"
        upd_reqs = [
            r
            for r in mock_splunk_es_server.requests_log
            if r["method"] == "POST" and "/services/notable_update" in r["path"]
        ]
        assert len(upd_reqs) == 1

        mock_splunk_es_server.set_mc_v2_enabled(True)
        updated = es.get_finding("fnd-1001-a")
        assert str(updated["status"]) == "4"


@pytest.mark.feature("V21-F7")
def test_v21_f7_spl_only_filters_raw_and_orig_sid_bypass_mc_v2(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    with _make_es_client() as es:
        raw_res = es.query_findings_hybrid(raw_query="mimikatz_marker_raw")
        assert raw_res["source_backend"] == "spl_fallback"
        assert [i["event_id"] for i in raw_res["items"]] == ["fnd-raw-only"]
        assert not any(
            "/public/v2/findings" in r["path"] for r in mock_splunk_es_server.requests_log
        )

        mock_splunk_es_server.requests_log.clear()
        sid_res = es.query_findings_hybrid(orig_sid="1700000100.11")
        assert sid_res["source_backend"] == "spl_fallback"
        assert [i["event_id"] for i in sid_res["items"]] == ["fnd-1001-a"]
        assert not any(
            "/public/v2/findings" in r["path"] for r in mock_splunk_es_server.requests_log
        )


@pytest.mark.feature("V21-F7")
def test_v21_f7_mc_v2_bulk_update_and_aq_sid_server_state_update(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    with _make_es_client() as es:
        es.bulk_update_findings(
            record_ids=["fnd-1001-a", "fnd-1001-b"],
            status="In Progress",
            owner="soc_analyst",
            disposition="true_positive",
            investigation_note={"title": "Bulk", "content": "Escalated"},
        )
        assert str(es.get_finding("fnd-1001-a")["status"]) == "2"
        assert str(es.get_finding("fnd-1001-b")["status"]) == "2"

        es.bulk_update_findings(aq_sid="1700000100.11", status="Resolved")
        assert str(es.get_finding("fnd-1001-a")["status"]) == "4"


# ==============================================================================
# V21-F8: ES Workbench Queue, Saved Views, Bulk Bar, 6-Tab Inspector, AR, RF & CLI
# ==============================================================================


@pytest.mark.feature("V21-F8")
def test_v21_f8_tui_queue_presets_type_pills_and_sparkline_strip(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Checkbox, DataTable, Select, Static

    from soclens.tui import create_app

    app = create_app(
        dry_run=False,
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

            table = app.query_one("#es-table", DataTable)
            assert table.row_count == 8

            preset_sel = app.query_one("#es-preset-select", Select)
            preset_sel.value = "unassigned_7d"
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert 1 <= table.row_count < 8

            preset_sel.value = "all"
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 8

            await pilot.click("#es-type-groups-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 1

            await pilot.click("#es-type-findings-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 7

            await pilot.click("#es-type-investigations-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 2

            await pilot.click("#es-type-all-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 8

            await pilot.click("#es-sparkline-toggle-btn")
            await pilot.pause()
            strip = app.query_one("#es-sparkline-strip", Static)
            assert strip.display is True
            assert "Timeline [" in str(strip.content)

    asyncio.run(_run())


@pytest.mark.feature("V21-F8")
def test_v21_f8_tui_saved_views_pagination_multiselect_bulk_bar_and_autorefresh_pause(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Checkbox, DataTable, Input, Select, Static

    from soclens.tui import create_app
    from soclens.tui.screens.splunk_es import SplunkESPane

    app = create_app(
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            pane = app.query_one(SplunkESPane)
            app.query_one("#es-auto-enrich-cb", Checkbox).value = False
            await pilot.pause()
            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#es-auto-refresh-btn")
            await pilot.pause()
            assert not pane._is_auto_refresh_paused()

            await pilot.click("#es-select-page-btn")
            await pilot.pause()
            assert app.query_one("#es-bulk-bar").display is True
            assert pane._is_auto_refresh_paused() is True

            await pilot.click("#es-bulk-triage-btn")
            await pilot.pause()
            app.screen.query_one("#es-bulk-status-select", Select).value = "In Progress"
            app.screen.query_one("#es-bulk-note-input", Input).value = "Batch triage"
            await pilot.click("#es-bulk-apply-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["method"] == "POST" and "/investigations/bulk_update" in r["path"]
                for r in mock_splunk_es_server.requests_log
            )

            await pilot.click("#es-save-view-btn")
            await pilot.pause()
            app.screen.query_one("#es-saved-view-name-input", Input).value = "My Tenant View"
            await pilot.click("#es-saved-view-save-btn")
            await pilot.pause()
            from soclens.settings import get_profile_settings

            raw_settings = _settings_file_path(v21_workspace).read_text(encoding="utf-8")
            assert json.loads(raw_settings)["encrypted"] is True
            assert "My Tenant View" in (get_profile_settings().get("splunk_es_saved_views") or "")

            await pilot.click("#es-del-view-btn")
            await pilot.pause()

            pane._page_size = 4
            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            table = app.query_one("#es-table", DataTable)
            assert table.row_count == 4
            assert "Page 1/2" in str(app.query_one("#es-page-label", Static).content)

            await pilot.click("#es-next-page-btn")
            await pilot.pause()
            assert "Page 2/2" in str(app.query_one("#es-page-label", Static).content)
            await pilot.click("#es-prev-page-btn")
            await pilot.pause()
            assert "Page 1/2" in str(app.query_one("#es-page-label", Static).content)

    asyncio.run(_run())


@pytest.mark.feature("V21-F8")
def test_v21_f8_tui_six_tab_inspector_stepping_and_investigations_modal(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Checkbox, Input, Static

    from soclens.tui import create_app

    app = create_app(
        dry_run=False,
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

            first_hdr = str(app.query_one("#es-detail-header", Static).content)
            await pilot.click("#es-next-finding-btn")
            await pilot.pause()
            second_hdr = str(app.query_one("#es-detail-header", Static).content)
            assert second_hdr != first_hdr

            await pilot.click("#es-prev-finding-btn")
            await pilot.pause()
            assert str(app.query_one("#es-detail-header", Static).content) == first_hdr

            await pilot.click("#es-insp-tab-overview")
            await pilot.pause()
            assert "LSASS" in _richlog_text(app, "#es-detail")

            await pilot.click("#es-insp-tab-metadata")
            await pilot.pause()
            assert "Custom / Org Fields" in _richlog_text(app, "#es-detail")

            await pilot.click("#es-insp-tab-srcdest")
            await pilot.pause()
            assert "198.51.100.10" in _richlog_text(app, "#es-detail")

            await pilot.click("#es-insp-tab-rf")
            await pilot.pause()
            assert _richlog_text(app, "#es-detail")

            await pilot.click("#es-insp-tab-notes")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert "Triage Started" in _richlog_text(app, "#es-detail")

            await pilot.click("#es-insp-tab-raw")
            await pilot.pause()
            assert "event_id" in _richlog_text(app, "#es-detail")

            await pilot.click("#es-new-inv-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            app.screen.query_one("#es-inv-name-input", Input).value = "E2E UI Case"
            await pilot.click("#es-inv-submit-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["method"] == "POST" and r["path"].endswith("/public/v2/investigations")
                for r in mock_splunk_es_server.requests_log
            )

    asyncio.run(_run())


@pytest.mark.feature("V21-F8")
def test_v21_f8_tui_adaptive_response_invocations_and_adhoc_dispatch(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Checkbox, Input, RichLog, Select

    from soclens.tui import create_app

    app = create_app(
        dry_run=False,
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

            await pilot.click("#es-insp-ar-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            paths = [r["path"] for r in mock_splunk_es_server.requests_log]
            assert any("modaction_invocations" in p for p in paths)
            assert any("alert_actions" in p for p in paths)

            ar_log = "\n".join(
                line.text for line in app.screen.query_one("#es-ar-history-log", RichLog).lines
            )
            assert "risk" in ar_log or "notable" in ar_log

            app.screen.query_one("#es-ar-action-select", Select).value = "ping"
            app.screen.query_one("#es-ar-params-input", Input).value = "dest=203.0.113.45"
            await pilot.click("#es-ar-dispatch-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            adhoc_posts = [
                r
                for r in mock_splunk_es_server.requests_log
                if r["method"] == "POST" and "modaction_adhoc" in r["path"]
            ]
            assert adhoc_posts
            assert adhoc_posts[-1]["form"].get("action_name") == ["ping"]

    asyncio.run(_run())


@pytest.mark.feature("V21-F8")
def test_v21_f8_tui_v200_rf_enrichment_controls_and_dual_post_rf_comment(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
) -> None:
    from textual.widgets import Checkbox, Input, TextArea

    from soclens.tui import create_app

    app = create_app(
        dry_run=False,
        initial_tab="tab-splunk-es",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            app.query_one("#es-auto-enrich-cb", Checkbox).value = True
            app.query_one("#es-private-ips-cb", Checkbox).value = True
            app.query_one("#es-rf-field-map-input", Input).value = "ip=src,dest"
            await pilot.pause()

            await pilot.click("#es-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#es-enrich-selected-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert mock_rf_server.requests_log
            rf_reqs_dump = json.dumps(mock_rf_server.requests_log, default=str)
            assert "203.0.113.45" in rf_reqs_dump or "198.51.100.10" in rf_reqs_dump

            await pilot.click("#es-insp-tab-rf")
            await pilot.pause()
            rf_detail = _richlog_text(app, "#es-detail")
            assert "75" in rf_detail or "Risk" in rf_detail

            mock_splunk_es_server.requests_log.clear()
            await pilot.click("#es-insp-add-note-btn")
            await pilot.pause()
            dual_cb = app.screen.query_one("#es-note-dual-rf-cb", Checkbox)
            assert dual_cb.disabled is False
            dual_cb.value = True
            app.screen.query_one("#es-note-text", TextArea).text = "Confirmed C2"
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


@pytest.mark.feature("V21-F8")
def test_v21_f8_cli_splunk_es_existing_v200_subcommands(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    commands: list[list[str]] = [
        ["splunk", "es", "notables", "--format", "json"],
        [
            "splunk",
            "es",
            "update-notable",
            "fnd-1001-a@@notable@@1001",
            "--status",
            "in_progress",
            "--comment",
            "CLI update",
        ],
        ["splunk", "es", "correlations", "--format", "json"],
        ["splunk", "es", "toggle-correlation", "ES_Disabled_Test_Rule", "--enable", "--yes"],
        ["splunk", "es", "threat-intel", "ip_intel", "--format", "json"],
        ["splunk", "es", "assets", "--format", "json"],
        ["splunk", "es", "identities", "--format", "json"],
        [
            "splunk",
            "es",
            "risk",
            "--risk-object",
            "wkstn-1001-01.example.test",
            "--format",
            "json",
        ],
    ]
    for cmd in commands:
        proc = run_cli(cmd)
        assert proc.returncode == 0, f"cmd={cmd}\nstdout={proc.stdout}\nstderr={proc.stderr}"


@pytest.mark.feature("V21-F8")
def test_v21_f8_cli_splunk_es_v21_tenant_and_mc_v2_subcommands(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Awaits Wave 2 (M4): soclens splunk es v2.1 tenant/MC v2 CLI flags and subcommands."""
    proc = run_cli(["splunk", "es", "notables", "--tenant", "1001", "--format", "json"])
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
    payload = json.loads(proc.stdout)
    rows = (
        payload
        if isinstance(payload, list)
        else (payload.get("notables") or payload.get("items") or [])
    )
    assert rows
    assert all(
        str(r.get("tenant_id") or r.get("TENANT_ID") or "") == "1001" for r in rows
    )

    inv_proc = run_cli(["splunk", "es", "investigations", "--format", "json"])
    assert inv_proc.returncode == 0, f"stdout={inv_proc.stdout}\nstderr={inv_proc.stderr}"
    inv_payload = json.loads(inv_proc.stdout)
    inv_rows = (
        inv_payload
        if isinstance(inv_payload, list)
        else (inv_payload.get("investigations") or inv_payload.get("items") or [])
    )
    assert inv_rows
    assert any(
        "/public/v2/investigations" in r["path"] for r in mock_splunk_es_server.requests_log
    )
