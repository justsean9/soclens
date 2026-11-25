"""Tier 2 boundary, error-handling, and corner-case E2E tests for Splunk ES (V21-F6..V21-F8)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from soclens.client import RecordedFutureClient
from soclens.config import SplunkESTenantConfig
from soclens.settings import save_profile_settings
from soclens.splunk import SplunkClient
from soclens.splunk_es import (
    SplunkESClient,
    SplunkESError,
    extract_custom_fields,
    extract_finding_tenant,
)
from soclens.splunk_rf_enrichment import SplunkRFEnricher
from tests.e2e import conftest as _e2e_conftest
from tests.e2e import v21_mocks as _v21_mocks

if TYPE_CHECKING:
    from tests.e2e.conftest import MockRFServer
    from tests.e2e.v21_mocks import MockSplunkESServer

pytestmark = [pytest.mark.e2e, pytest.mark.tier2]

v21_workspace = _v21_mocks.v21_workspace
mock_splunk_es_server = _v21_mocks.mock_splunk_es_server
mock_rf_server = _e2e_conftest.mock_rf_server
run_cli = _e2e_conftest.run_cli


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


def _build_es_client(
    es_server: MockSplunkESServer,
    *,
    max_retries: int = 1,
    backoff_base: float = 0.02,
    poll_interval: float = 0.05,
) -> SplunkESClient:
    return SplunkESClient(
        host=es_server.base_url,
        token="test-splunk-token",
        app="SplunkEnterpriseSecuritySuite",
        verify_ssl=False,
        max_retries=max_retries,
        backoff_base=backoff_base,
        poll_interval=poll_interval,
    )


# ======================================================================
# V21-F6: ES Tenant Extraction & Dynamic Custom Fields (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F6")
def test_v21_f6_conf_incident_review_404_falls_back_to_conf_log_review(
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    mock_splunk_es_server.set_incident_review_404_fallback(True)
    with _build_es_client(mock_splunk_es_server) as es:
        fields = es.discover_custom_fields()
        assert any(f["field"] == "tenant_id" for f in fields)
        assert any(f["field"] == "snow_ticket" for f in fields)
        cached = es.discover_custom_fields()
        assert cached == fields

    paths = [r["path"] for r in mock_splunk_es_server.requests_log]
    assert "/servicesNS/-/-/configs/conf-incident_review/incident_review" in paths
    assert "/servicesNS/-/-/configs/conf-log_review/incident_review" in paths
    assert len([p for p in paths if "conf-log_review" in p]) == 1

    mock_splunk_es_server.set_fault("/servicesNS/-/-/configs/conf-log_review/", 403, {"messages": []})
    with _build_es_client(mock_splunk_es_server) as es_denied:
        assert es_denied.discover_custom_fields(force_refresh=True) == []


@pytest.mark.feature("V21-F6")
def test_v21_f6_malformed_event_attributes_and_internal_fields_excluded(
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    mock_splunk_es_server.set_incident_review_404_fallback(False)
    mock_splunk_es_server.queue_fault(
        "/servicesNS/-/-/configs/conf-incident_review/incident_review",
        200,
        {"entry": [{"name": "incident_review", "content": {"event_attributes": "{bad-json"}}]},
        method="GET",
        count=1,
    )
    with _build_es_client(mock_splunk_es_server) as es:
        assert es.discover_custom_fields() == []

    sample_record = {
        "event_id": "fnd-custom-1",
        "_raw": "raw log payload",
        "_time": "2026-11-25T00:00:00Z",
        "punct": "---",
        "splunk_server": "idx-01",
        "tag::eventtype": "notable",
        "org_custom_flag": "tier1-esc",
        "custom_fields": {
            "snow_ticket": "INC9001",
            "_indextime": "1700000000",
        },
    }
    extracted = extract_custom_fields(
        sample_record,
        pinned_fields=["org_custom_flag"],
        discovered_fields=[{"field": "snow_ticket", "label": "SNOW Ticket"}],
    )
    assert extracted["org_custom_flag"] == "tier1-esc"
    assert extracted["snow_ticket"] == "INC9001"
    for internal_key in ("_raw", "_time", "punct", "splunk_server", "tag::eventtype", "_indextime"):
        assert internal_key not in extracted


@pytest.mark.feature("V21-F6")
def test_v21_f6_missing_tenant_renders_dash_badge_and_clears_on_pivot(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import DataTable, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.splunk_es import SplunkESPane

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-splunk-es")
            await _wait_until(
                pilot,
                lambda: app.query_one("#tab-splunk-es", object) is not None
                and len(list(app.query(SplunkESPane))) == 1,
            )
            pane = app.query_one(SplunkESPane)
            pane.handle_refresh()
            await _wait_until(pilot, lambda: len(pane._displayed_rows) >= 8 and not pane._loading)

            unassigned_idx = next(
                i
                for i, row in enumerate(pane._displayed_rows)
                if row.get("event_id") == "fnd-unassigned"
            )
            table = pane.query_one("#es-table", DataTable)
            table.move_cursor(row=unassigned_idx, column=0)
            pane._render_detail(unassigned_idx)
            await pilot.pause()

            row_cells = [str(c) for c in table.get_row_at(unassigned_idx)]
            assert "-" in row_cells
            header_text = str(pane.query_one("#es-detail-header", Static).render())
            assert "[Tenant: -]" not in header_text

            payload = pane._build_pivot_payload("tab-sentinelone", pane._displayed_rows[unassigned_idx])
            assert payload.tenant_id is None

    asyncio.run(_run())


@pytest.mark.feature("V21-F6")
def test_v21_f6_case_insensitive_tenant_aliases_and_setting_override(
    v21_workspace: Path,
) -> None:
    assert extract_finding_tenant({"TENANT_ID": "1001"}) == "1001"
    assert extract_finding_tenant({"custom_fields": {"Org_Id": "1002"}}) == "1002"
    assert extract_finding_tenant({"fields": {"client_code": "2001"}}) == "2001"
    assert extract_finding_tenant({"raw": {"customer_id": "2002"}}) == "2002"
    assert extract_finding_tenant({"rule_title": "No tenant anywhere"}) is None

    override_cfg = SplunkESTenantConfig(
        tenant_field="client_code",
        tenant_aliases=("tenant_id", "org_id", "customer_id"),
    )
    mixed_rec = {"tenant_id": "9999", "Client_Code": "2001"}
    assert extract_finding_tenant(mixed_rec, override_cfg) == "2001"


@pytest.mark.feature("V21-F6")
def test_v21_f6_group_by_tenant_sorts_missing_tenant_last_in_tui(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Button

    from soclens.tui.app import create_app
    from soclens.tui.screens.splunk_es import SplunkESPane

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-splunk-es")
            await _wait_until(pilot, lambda: len(list(app.query(SplunkESPane))) == 1)
            pane = app.query_one(SplunkESPane)
            pane.handle_refresh()
            await _wait_until(pilot, lambda: len(pane._displayed_rows) >= 8 and not pane._loading)

            pane.query_one("#es-group-tenant-btn", Button).press()
            await pilot.pause()

            group_rows = [r for r in pane._displayed_rows if r.get("_is_group_row")]
            assert len(group_rows) >= 3
            tenant_order = [str(r.get("_group_tenant")) for r in group_rows]
            assert tenant_order[-1] == "-"

    asyncio.run(_run())


@pytest.mark.feature("V21-F6")
def test_v21_f6_pinned_custom_fields_appear_in_metadata_inspector_tab(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Button, DataTable, RichLog

    from soclens.tui.app import create_app
    from soclens.tui.screens.splunk_es import SplunkESPane

    save_profile_settings({"splunk_es_custom_fields": "business_unit,ticket_ref"})
    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-splunk-es")
            await _wait_until(pilot, lambda: len(list(app.query(SplunkESPane))) == 1)
            pane = app.query_one(SplunkESPane)
            pane.handle_refresh()
            await _wait_until(pilot, lambda: len(pane._displayed_rows) >= 8 and not pane._loading)

            target_idx = next(
                i
                for i, r in enumerate(pane._displayed_rows)
                if r.get("event_id") == "fnd-1001-a"
            )
            pane._displayed_rows[target_idx].setdefault("custom_fields", {})["ticket_ref"] = "CHG-4242"
            table = pane.query_one("#es-table", DataTable)
            table.move_cursor(row=target_idx, column=0)
            pane.query_one("#es-insp-tab-metadata", Button).press()
            pane._render_detail(target_idx)
            await pilot.pause()

            detail_text = "\n".join(line.text for line in pane.query_one("#es-detail", RichLog).lines)
            assert "--- Custom / Org Fields ---" in detail_text
            assert "business_unit" in detail_text
            assert "ticket_ref" in detail_text

    asyncio.run(_run())


# ======================================================================
# V21-F7: ES 8.6 MC v2 Primary & 7.x SPL Fallback (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F7")
def test_v21_f7_mc_v2_unknown_param_hygiene_never_sends_tenant_id_to_findings(
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    mock_splunk_es_server.set_ignore_unknown_finding_params(False)
    with _build_es_client(mock_splunk_es_server) as es:
        res = es.query_findings_hybrid(
            tenant_id="1001",
            custom_filters={"business_unit": "Finance"},
        )
    assert res["source_backend"] == "mc_v2"
    assert res["items"]
    assert all(item["tenant_id"] == "1001" for item in res["items"])
    findings_reqs = [
        r
        for r in mock_splunk_es_server.requests_log
        if r["path"].endswith("/public/v2/findings")
    ]
    assert findings_reqs
    for req in findings_reqs:
        assert "tenant_id" not in req["query"]
        assert "business_unit" not in req["query"]


@pytest.mark.feature("V21-F7")
def test_v21_f7_raw_and_orig_sid_filters_trigger_direct_spl_fallback(
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    with _build_es_client(mock_splunk_es_server) as es:
        raw_res = es.query_findings_hybrid(raw_query="mimikatz_marker_raw")
        assert raw_res["source_backend"] == "spl_fallback"
        assert [it["event_id"] for it in raw_res["items"]] == ["fnd-raw-only"]

        sid_res = es.query_findings_hybrid(orig_sid="1700000100.11")
        assert sid_res["source_backend"] == "spl_fallback"
        assert any(it["event_id"] == "fnd-1001-a" for it in sid_res["items"])

    assert not [
        r
        for r in mock_splunk_es_server.requests_log
        if "/public/v2/findings" in r["path"]
    ]
    job_posts = [
        r for r in mock_splunk_es_server.requests_log if r["path"].endswith("/search/jobs")
    ]
    assert len(job_posts) == 2
    assert all("`notable`" in (p["form"].get("search") or [""])[0] for p in job_posts)


@pytest.mark.feature("V21-F7")
def test_v21_f7_mc_v2_404_falls_back_to_spl_notable_and_notable_update(
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    mock_splunk_es_server.set_mc_v2_enabled(False)
    with _build_es_client(mock_splunk_es_server) as es:
        q_res = es.query_findings_hybrid(tenant_id="1001")
        assert q_res["source_backend"] == "spl_fallback"
        assert q_res["items"]

        t_res = es.triage_findings_hybrid(
            ["fnd-1001-a"],
            status="resolved",
            disposition="benign_positive",
            note="7.x fallback triage note",
        )
        assert t_res["backend"] == "notable_update"

    assert any(
        r["path"] == "/services/notable_update" and r["method"] == "POST"
        for r in mock_splunk_es_server.requests_log
    )
    updated_fnd = next(
        f for f in mock_splunk_es_server.state["findings"] if f["event_id"] == "fnd-1001-a"
    )
    assert updated_fnd["status_label"] == "Resolved"


@pytest.mark.feature("V21-F7")
def test_v21_f7_mc_v2_non_404_errors_and_spl_job_failures(
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    mock_splunk_es_server.set_fault(
        "/servicesNS/nobody/missioncontrol/public/v2/findings",
        500,
        {"message": "MC v2 internal error"},
        method="GET",
    )
    with _build_es_client(mock_splunk_es_server, max_retries=0) as es:
        with pytest.raises(SplunkESError) as exc_500:
            es.query_findings_hybrid()
        assert exc_500.value.status_code == 500

    assert not [
        r for r in mock_splunk_es_server.requests_log if r["path"].endswith("/search/jobs")
    ]

    mock_splunk_es_server.clear_faults()
    mock_splunk_es_server.set_fault(
        "/servicesNS/nobody/missioncontrol/public/v2/investigations/bulk_update",
        400,
        {"message": "Bad bulk update payload"},
        method="POST",
    )
    with _build_es_client(mock_splunk_es_server, max_retries=0) as es:
        with pytest.raises(SplunkESError) as exc_400:
            es.triage_findings_hybrid(["fnd-1001-a"], status="Closed")
        assert exc_400.value.status_code == 400

    assert not [
        r for r in mock_splunk_es_server.requests_log if r["path"] == "/services/notable_update"
    ]

    mock_splunk_es_server.clear_faults()
    mock_splunk_es_server.set_job_behavior("failed")
    with _build_es_client(mock_splunk_es_server, max_retries=0) as es:
        with pytest.raises(RuntimeError, match="failed"):
            es.query_findings_hybrid(use_spl=True)


@pytest.mark.feature("V21-F7")
def test_v21_f7_bulk_update_partial_failure_400_and_tui_error_handling(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.splunk_es import SplunkESPane

    with _build_es_client(mock_splunk_es_server) as es:
        with pytest.raises(SplunkESError) as exc_info:
            es.bulk_update_findings(
                record_ids=["fnd-1001-a", "missing-id-999"],
                status="Closed",
            )
    assert exc_info.value.status_code == 400
    assert "partial" in str(exc_info.value).lower()

    app = create_app(client=MagicMock(), dry_run=False, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-splunk-es")
            await _wait_until(pilot, lambda: len(list(app.query(SplunkESPane))) == 1)
            pane = app.query_one(SplunkESPane)
            pane._bulk_triage_worker(
                {"event_ids": ["fnd-1001-a", "missing-id-999"], "status": "Closed"}
            )
            await _wait_until(
                pilot,
                lambda: "failed" in str(pane.query_one("#es-status", Static).render()).lower()
                or "partial" in str(pane.query_one("#es-status", Static).render()).lower()
                or "error" in str(pane.query_one("#es-status", Static).render()).lower(),
            )
            assert app.is_running

    asyncio.run(_run())


@pytest.mark.feature("V21-F7")
def test_v21_f7_bulk_update_validation_and_investigations_array_envelope(
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    with _build_es_client(mock_splunk_es_server) as es:
        req_before = len(mock_splunk_es_server.requests_log)
        with pytest.raises(ValueError):
            es.bulk_update_findings(record_ids=["fnd-1001-a"], aq_sid="sid-1", status="Closed")
        with pytest.raises(ValueError):
            es.bulk_update_findings(status="Closed")
        with pytest.raises(ValueError):
            es.bulk_update_findings(record_ids=["fnd-1001-a"])
        assert len(mock_splunk_es_server.requests_log) == req_before

        invs = es.list_investigations()
        assert len(invs) == 2

        mock_splunk_es_server.queue_fault(
            "/servicesNS/nobody/missioncontrol/public/v2/investigations",
            200,
            [],
            method="GET",
            count=1,
        )
        assert es.list_investigations() == []


# ======================================================================
# V21-F8: ES Queue, Inspector, AR, RF Controls & CLI (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F8")
def test_v21_f8_auto_refresh_pauses_while_rows_selected_and_resumes_on_deselect(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Button, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.splunk_es import SplunkESPane

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-splunk-es")
            await _wait_until(pilot, lambda: len(list(app.query(SplunkESPane))) == 1)
            pane = app.query_one(SplunkESPane)
            pane.handle_refresh()
            await _wait_until(pilot, lambda: len(pane._displayed_rows) >= 8 and not pane._loading)

            pane.query_one("#es-auto-refresh-btn", Button).press()
            await pilot.pause()
            assert pane._auto_refresh_enabled is True
            assert pane._is_auto_refresh_paused() is False

            pane.query_one("#es-select-page-btn", Button).press()
            await pilot.pause()
            assert pane._is_auto_refresh_paused() is True
            summary_txt = str(pane.query_one("#es-summary-bar", Static).render())
            assert "Auto: PAUSED" in summary_txt

            req_before = len(mock_splunk_es_server.requests_log)
            pane._on_auto_refresh_tick()
            await pilot.pause()
            assert len(mock_splunk_es_server.requests_log) == req_before

            pane.query_one("#es-deselect-btn", Button).press()
            await pilot.pause()
            assert pane._is_auto_refresh_paused() is False

    asyncio.run(_run())


@pytest.mark.feature("V21-F8")
def test_v21_f8_modaction_invocations_missing_sid_rid_400_and_client_guard(
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    with SplunkClient(
        host=mock_splunk_es_server.base_url,
        token="test-splunk-token",
        verify_ssl=False,
    ) as raw_splunk:
        raw_resp = raw_splunk._request(
            "GET",
            "/servicesNS/nobody/SA-ThreatIntelligence/alerts/modaction_invocations?output_mode=json",
        )
        assert raw_resp.status_code == 400

    with _build_es_client(mock_splunk_es_server) as es:
        req_before = len(mock_splunk_es_server.requests_log)
        assert es.list_modaction_invocations("", "0") == []
        assert len(mock_splunk_es_server.requests_log) == req_before

        with pytest.raises(ValueError):
            es.dispatch_adaptive_response("ping", sid="", rid="0")
        assert len(mock_splunk_es_server.requests_log) == req_before


@pytest.mark.feature("V21-F8")
def test_v21_f8_modaction_invocations_404_empty_vs_500_error_and_ar_modal_validation(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Button, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.es_modals import ESAdaptiveResponseModal

    with _build_es_client(mock_splunk_es_server, max_retries=0) as es:
        mock_splunk_es_server.queue_fault(
            "/servicesNS/nobody/SA-ThreatIntelligence/alerts/modaction_invocations",
            404,
            {"messages": []},
            method="GET",
            count=1,
        )
        assert es.list_modaction_invocations("1700000100.11", "0") == []

        mock_splunk_es_server.queue_fault(
            "/servicesNS/nobody/SA-ThreatIntelligence/alerts/modaction_invocations",
            500,
            {"messages": [{"text": "Internal Error"}]},
            method="GET",
            count=1,
        )
        with pytest.raises(SplunkESError) as exc_info:
            es.list_modaction_invocations("1700000100.11", "0")
        assert exc_info.value.status_code == 500

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(100, 32)) as pilot:
            modal = ESAdaptiveResponseModal(
                event_id="fnd-no-sid",
                orig_sid="",
                orig_rid="",
                available_actions=[{"name": "ping", "label": "Ping Host"}],
            )
            app.push_screen(modal)
            await pilot.pause()
            modal.query_one("#es-ar-dispatch-btn", Button).press()
            await pilot.pause()
            err_txt = str(modal.query_one("#es-ar-error", Static).render())
            assert "orig_sid" in err_txt and "orig_rid" in err_txt
            assert app.screen is modal

    asyncio.run(_run())


@pytest.mark.feature("V21-F8")
def test_v21_f8_dry_run_blocks_all_es_tui_mutations(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
) -> None:
    from textual.widgets import Button, DataTable, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.splunk_es import SplunkESPane

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-splunk-es")
            await _wait_until(pilot, lambda: len(list(app.query(SplunkESPane))) == 1)
            pane = app.query_one(SplunkESPane)
            pane.handle_refresh()
            await _wait_until(pilot, lambda: len(pane._displayed_rows) >= 8 and not pane._loading)

            pane.query_one("#es-table", DataTable).move_cursor(row=0, column=0)
            req_before = len(mock_splunk_es_server.requests_log)

            pane.query_one("#es-assign-me-btn", Button).press()
            await pilot.pause()
            assert "DRY-RUN" in str(pane.query_one("#es-status", Static).render())

            pane.query_one("#es-suppress-btn", Button).press()
            await pilot.pause()
            assert "DRY-RUN" in str(pane.query_one("#es-status", Static).render())

            pane.query_one("#es-create-finding-btn", Button).press()
            await pilot.pause()
            assert "DRY-RUN" in str(pane.query_one("#es-status", Static).render())

            mutating_reqs = [
                r
                for r in mock_splunk_es_server.requests_log[req_before:]
                if r["method"] == "POST"
                and any(
                    seg in r["path"]
                    for seg in ("bulk_update", "/public/v2/findings", "/notes", "notable_update")
                )
            ]
            assert mutating_reqs == []

    asyncio.run(_run())


@pytest.mark.feature("V21-F8")
def test_v21_f8_v200_rf_enrichment_controls_preserved_and_private_ip_boundary(
    v21_workspace: Path,
    mock_splunk_es_server: MockSplunkESServer,
    mock_rf_server: MockRFServer,
) -> None:
    from textual.widgets import Button, Checkbox, Input

    from soclens.tui.app import create_app
    from soclens.tui.screens.splunk_es import SplunkESPane

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-splunk-es")
            await _wait_until(pilot, lambda: len(list(app.query(SplunkESPane))) == 1)
            pane = app.query_one(SplunkESPane)
            assert pane.query_one("#es-rf-controls-row") is not None
            assert pane.query_one("#es-auto-enrich-cb", Checkbox) is not None
            priv_cb = pane.query_one("#es-private-ips-cb", Checkbox)
            assert priv_cb.value is False
            assert pane.query_one("#es-enrich-selected-btn", Button) is not None
            assert pane.query_one("#es-enrich-all-btn", Button) is not None
            assert pane.query_one("#es-post-rf-comment-btn", Button) is not None
            assert pane.query_one("#es-rf-field-map-input", Input) is not None

    asyncio.run(_run())

    rf = RecordedFutureClient(
        api_token="e2e-rf-token",
        base_url=mock_rf_server.base_url,
    )
    enricher = SplunkRFEnricher(rf, include_private_ips=False)
    enriched = enricher.enrich_events([{"event_id": "fnd-priv", "src": "10.0.0.5"}])
    assert enriched[0]["rf_observables"] == []
    assert not [r for r in mock_rf_server.requests_log if "/soar/" in r["path"]]


@pytest.mark.feature("V21-F8")
def test_v21_f8_cli_splunk_es_tenant_filter_and_dry_run_guardrail(
    mock_splunk_es_server: MockSplunkESServer,
    run_cli: Any,
) -> None:
    list_proc = run_cli(["splunk", "es", "notables", "--tenant", "1001", "--format", "json"])
    assert list_proc.returncode == 0, list_proc.stderr
    payload = json.loads(list_proc.stdout)
    assert isinstance(payload, dict)
    assert "notables" in payload and "count" in payload
    rows = payload["notables"]
    assert isinstance(rows, list) and rows
    assert payload["count"] == len(rows)
    assert all(str(r.get("tenant_id") or "") == "1001" for r in rows)

    empty_proc = run_cli(
        ["splunk", "es", "notables", "--tenant", "UNKNOWN-TENANT-999", "--format", "json"]
    )
    assert empty_proc.returncode == 0, empty_proc.stderr
    empty_payload = json.loads(empty_proc.stdout)
    assert isinstance(empty_payload, dict)
    assert empty_payload["count"] == 0
    assert empty_payload["notables"] == []

    req_before = len(mock_splunk_es_server.requests_log)
    dry_proc = run_cli(
        [
            "splunk",
            "es",
            "update-notable",
            "fnd-1001-a",
            "--status",
            "resolved",
            "--dry-run",
            "--json",
        ]
    )
    assert dry_proc.returncode == 0, dry_proc.stderr
    assert not [
        r
        for r in mock_splunk_es_server.requests_log[req_before:]
        if r["method"] == "POST" and ("bulk_update" in r["path"] or "notable_update" in r["path"])
    ]
