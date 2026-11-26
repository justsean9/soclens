"""Tier 2 boundary, error-handling, and corner-case E2E tests for SentinelOne (V21-F9..V21-F12)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from soclens.config import classify_site_tier
from soclens.sentinelone import (
    MAX_EXCLUSION_CLONE_RPS,
    SentinelOneAuthError,
    SentinelOneClient,
    SentinelOneRateLimitError,
    _format_cloned_description,
)
from soclens.settings import validate_settings_values
from tests.e2e import conftest as _e2e_conftest
from tests.e2e import v21_mocks as _v21_mocks

if TYPE_CHECKING:
    from tests.e2e.v21_mocks import MockSentinelOneServer

pytestmark = [pytest.mark.e2e, pytest.mark.tier2]

v21_workspace = _v21_mocks.v21_workspace
mock_s1_server = _v21_mocks.mock_s1_server
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
    assert predicate(), "Timed out waiting for async SentinelOne TUI state"


def _build_s1_client(
    s1_server: MockSentinelOneServer,
    *,
    api_token: str = "test-s1-token",
    max_retries: int = 1,
    backoff_base: float = 0.02,
) -> SentinelOneClient:
    return SentinelOneClient(
        console_url=s1_server.base_url,
        api_token=api_token,
        verify_ssl=False,
        max_retries=max_retries,
        backoff_base=backoff_base,
    )


# ======================================================================
# V21-F9: Hierarchy, Tier Rules, Pagination & Guardrails (5 tests)
# ======================================================================


@pytest.mark.feature("V21-F9")
def test_v21_f9_cursor_pagination_enforces_limit_le_100(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    mock_s1_server.set_enforce_limit_max_100(True)
    mock_s1_server.seed_bulk_exclusions("100101", 25)

    with _build_s1_client(mock_s1_server) as s1:
        exclusions = s1.list_exclusions(site_ids=["100101"], limit=250)
        threats = s1.list_threats(limit=500)

    assert len(exclusions) >= 25
    assert len(threats) >= 1
    get_limits = [
        int(r["query"]["limit"][0])
        for r in mock_s1_server.requests_log
        if r["method"] == "GET" and "limit" in r["query"]
    ]
    assert get_limits
    assert all(1 <= lim <= 100 for lim in get_limits)


@pytest.mark.feature("V21-F9")
def test_v21_f9_429_retry_after_backoff_recovers_and_exhaustion_raises(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    mock_s1_server.queue_fault(
        "/web/api/v2.1/threats",
        429,
        {"errors": [{"code": 429001, "title": "Rate limit exceeded"}]},
        headers={"Retry-After": "0"},
        method="GET",
        count=1,
    )
    with _build_s1_client(mock_s1_server, max_retries=1, backoff_base=0.01) as s1:
        threats = s1.list_threats()
    assert threats
    threat_gets = [
        r for r in mock_s1_server.requests_log if r["path"] == "/web/api/v2.1/threats"
    ]
    assert len(threat_gets) == 2

    mock_s1_server.set_fault(
        "/web/api/v2.1/threats",
        429,
        {"errors": [{"code": 429001, "title": "Persistent rate limit"}]},
        headers={"Retry-After": "0"},
        method="GET",
    )
    with _build_s1_client(mock_s1_server, max_retries=1, backoff_base=0.01) as s1:
        with pytest.raises(SentinelOneRateLimitError) as exc_info:
            s1.list_threats()
    assert exc_info.value.status_code == 429
    assert exc_info.value.retry_after == 0.0


@pytest.mark.feature("V21-F9")
def test_v21_f9_empty_filter_mutation_rejected_before_http(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    with _build_s1_client(mock_s1_server) as s1:
        req_before = len(mock_s1_server.requests_log)
        with pytest.raises(ValueError):
            s1._request(
                "POST",
                "threats/incident",
                json_body={"filter": {}, "data": {"incidentStatus": "resolved"}},
            )
        with pytest.raises(ValueError):
            s1.disconnect_agent([])
        with pytest.raises(ValueError):
            s1.mitigate_threat([], "quarantine")
        with pytest.raises(ValueError):
            s1.create_exclusion(
                exclusion_type="path",
                os_type="windows",
                value="C:\\Temp\\safe.exe",
            )
        with pytest.raises(ValueError):
            s1.add_to_blocklist("a" * 40)
        with pytest.raises(ValueError):
            s1.delete_exclusions([])
        with pytest.raises(ValueError):
            s1.reset_2fa([])
        assert len(mock_s1_server.requests_log) == req_before


@pytest.mark.feature("V21-F9")
def test_v21_f9_list_sites_handles_dict_and_list_envelopes(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    with _build_s1_client(mock_s1_server) as s1:
        mock_s1_server.set_sites_as_list(False)
        sites_dict = s1.enrich_sites_with_tiers(s1.list_sites())

        mock_s1_server.set_sites_as_list(True)
        sites_list = s1.enrich_sites_with_tiers(s1.list_sites())

    assert len(sites_dict) == len(sites_list) >= 5
    for sites in (sites_dict, sites_list):
        mdr_site = next(s for s in sites if s["id"] == "100101")
        assert mdr_site["tier"] == "MDR"
        assert mdr_site["tenantId"] == "1001"


@pytest.mark.feature("V21-F9")
def test_v21_f9_tier_rules_case_insensitive_and_malformed_regex_boundary(
    v21_workspace: Path,
) -> None:
    assert classify_site_tier("mdr-1001") == ("MDR", "1001")
    assert classify_site_tier("MSSP_2001") == ("MSSP", "2001")
    assert classify_site_tier("Corp-Sandbox-3001") == ("Other", None)

    bad_rules = json.dumps([{"tier": "MDR", "pattern": "[unclosed-regex"}])
    errors = validate_settings_values({"s1_tier_rules": bad_rules})
    assert errors and errors[0][0] == "s1_tier_rules"

    empty_tier_rules = json.dumps([{"tier": "", "pattern": "^MDR-(\\d+)"}])
    errors_empty = validate_settings_values({"s1_tier_rules": empty_tier_rules})
    assert errors_empty and errors_empty[0][0] == "s1_tier_rules"


# ======================================================================
# V21-F10: Alerts, Threats & Cloud/STAR Alerts (5 tests)
# ======================================================================


@pytest.mark.feature("V21-F10")
def test_v21_f10_mitigate_unquarantine_and_rollback_aliases(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    with _build_s1_client(mock_s1_server) as s1:
        s1.mitigate_threat(["thr-1001-1"], "unquarantine")
        s1.mitigate_threat(["thr-1001-1"], "un-quarantine")
        s1.mitigate_threat(["thr-1001-1"], "rollback")
        s1.mitigate_threat(["thr-1001-1"], "rollback-remediation")

    post_paths = [
        r["path"] for r in mock_s1_server.requests_log if r["method"] == "POST"
    ]
    assert post_paths == [
        "/web/api/v2.1/threats/mitigate/un-quarantine",
        "/web/api/v2.1/threats/mitigate/un-quarantine",
        "/web/api/v2.1/threats/mitigate/rollback-remediation",
        "/web/api/v2.1/threats/mitigate/rollback-remediation",
    ]


@pytest.mark.feature("V21-F10")
def test_v21_f10_tier_plus_file_hash_cross_tier_bulk_isolation(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import Button, DataTable, Select

    from soclens.tui.app import create_app
    from soclens.tui.screens.sentinelone import SentinelOnePane

    app = create_app(client=MagicMock(), dry_run=False, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-sentinelone")
            await _wait_until(pilot, lambda: len(list(app.query(SentinelOnePane))) == 1)
            pane = app.query_one(SentinelOnePane)
            pane.query_one("#s1-wb-alerts-btn", Button).press()
            pane.query_one("#s1-refresh-btn", Button).press()
            await app.workers.wait_for_complete()
            await _wait_until(pilot, lambda: len(pane._records) >= 6)

            grp_sel = pane.query_one("#s1-grouping-select", Select)
            grp_sel.value = "tier_hash"
            await pilot.pause()

            sha1_a = "a" * 40
            mdr_hdr_idx = next(
                i
                for i, r in enumerate(pane._table_rows)
                if r.get("_is_group_header")
                and f"MDR | {sha1_a}" in str(r.get("_group_label") or "")
            )
            mssp_hdr_idx = next(
                i
                for i, r in enumerate(pane._table_rows)
                if r.get("_is_group_header")
                and f"MSSP | {sha1_a}" in str(r.get("_group_label") or "")
            )
            assert mdr_hdr_idx != mssp_hdr_idx

            pane.query_one("#s1-table", DataTable).move_cursor(row=mdr_hdr_idx, column=0)
            pane._select_record(pane._table_rows[mdr_hdr_idx])
            await pilot.pause()

            pane.query_one("#s1-quarantine-btn", Button).press()
            await _wait_until(
                pilot,
                lambda: hasattr(app.screen, "handle_approve"),
            )
            step1_modal = app.screen
            step1_modal.query_one("#confirm-approve-btn", Button).press()
            await _wait_until(
                pilot,
                lambda: hasattr(app.screen, "handle_approve") and app.screen is not step1_modal,
            )
            app.screen.query_one("#confirm-approve-btn", Button).press()
            await _wait_until(
                pilot,
                lambda: any(
                    r["path"] == "/web/api/v2.1/threats/mitigate/quarantine"
                    for r in mock_s1_server.requests_log
                ),
            )

    asyncio.run(_run())
    quarantine_reqs = [
        r
        for r in mock_s1_server.requests_log
        if r["path"] == "/web/api/v2.1/threats/mitigate/quarantine"
    ]
    assert len(quarantine_reqs) == 1
    sent_ids = quarantine_reqs[0]["json_body"]["filter"]["ids"]
    assert set(sent_ids) == {"thr-1001-1", "thr-1002-1"}
    assert "thr-2001-1" not in sent_ids


@pytest.mark.feature("V21-F10")
def test_v21_f10_mixed_endpoint_and_cloud_alert_partitioning(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from soclens.tui.app import create_app
    from soclens.tui.screens.sentinelone import SentinelOnePane

    with _build_s1_client(mock_s1_server) as s1:
        cloud_only = s1.list_cloud_alerts(analyst_verdicts=["true_positive"])
        assert cloud_only == []
        unified = s1.list_unified_alerts()
        grouped = s1.group_alerts(unified, mode="tier_hash")
        assert any(k.startswith("MDR | ") for k in grouped)

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-sentinelone")
            await _wait_until(pilot, lambda: len(list(app.query(SentinelOnePane))) == 1)
            pane = app.query_one(SentinelOnePane)
            pane._selected_record = {
                "_is_group_header": True,
                "_group_label": "MDR | mixed",
                "_group_records": [
                    {"id": "thr-1001-1", "recordType": "threat"},
                    {"id": "cld-1001-1", "recordType": "cloud_alert", "alertInfo": {"id": "cld-1001-1"}},
                ],
            }
            part = pane._selected_threat_partition_for_action()
            assert part is not None
            ep_ids, cl_ids, _label, _primary = part
            assert ep_ids == ["thr-1001-1"]
            assert cl_ids == ["cld-1001-1"]

    asyncio.run(_run())


@pytest.mark.feature("V21-F10")
def test_v21_f10_invalid_mitigation_and_401_403_errors(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    with _build_s1_client(mock_s1_server) as s1:
        req_before = len(mock_s1_server.requests_log)
        with pytest.raises(ValueError):
            s1.mitigate_threat(["thr-1001-1"], "invalid_op")
        assert len(mock_s1_server.requests_log) == req_before

    with _build_s1_client(mock_s1_server, api_token="wrong-s1-token-999") as bad_s1:
        with pytest.raises(SentinelOneAuthError) as exc_401:
            bad_s1.list_threats()
        assert exc_401.value.status_code == 401

    mock_s1_server.queue_fault(
        "/web/api/v2.1/threats",
        403,
        {"errors": [{"code": 403001, "title": "Forbidden"}]},
        method="GET",
        count=1,
    )
    with _build_s1_client(mock_s1_server) as s1:
        with pytest.raises(SentinelOneAuthError) as exc_403:
            s1.list_threats()
        assert exc_403.value.status_code == 403


@pytest.mark.feature("V21-F10")
def test_v21_f10_tui_dry_run_blocks_threat_triage_and_mitigation(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import Button, DataTable, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.sentinelone import SentinelOnePane

    app = create_app(client=MagicMock(), dry_run=True, workspace_dir=v21_workspace)

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-sentinelone")
            await _wait_until(pilot, lambda: len(list(app.query(SentinelOnePane))) == 1)
            pane = app.query_one(SentinelOnePane)
            pane.query_one("#s1-wb-alerts-btn", Button).press()
            pane.query_one("#s1-refresh-btn", Button).press()
            await app.workers.wait_for_complete()
            await _wait_until(pilot, lambda: len(pane._records) >= 1)

            pane.query_one("#s1-table", DataTable).move_cursor(row=0, column=0)
            pane._select_record(pane._table_rows[0])
            req_before = len(mock_s1_server.requests_log)

            pane.query_one("#s1-quarantine-btn", Button).press()
            await pilot.pause()
            assert "DRY-RUN" in str(pane.query_one("#s1-status", Static).render())

            pane.query_one("#s1-kill-btn", Button).press()
            await pilot.pause()
            assert "DRY-RUN" in str(pane.query_one("#s1-status", Static).render())

            assert not [
                r for r in mock_s1_server.requests_log[req_before:] if r["method"] == "POST"
            ]

    asyncio.run(_run())


# ======================================================================
# V21-F11: Sites Admin & Users/RBAC Admin (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F11")
def test_v21_f11_user_view_blocks_all_s1_admin_mutations(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import Button, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.sentinelone import SentinelOnePane

    app = create_app(
        client=MagicMock(),
        dry_run=False,
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-sentinelone")
            await _wait_until(pilot, lambda: len(list(app.query(SentinelOnePane))) == 1)
            pane = app.query_one(SentinelOnePane)
            req_before = len(mock_s1_server.requests_log)

            pane.query_one("#s1-wb-sites-btn", Button).press()
            await pilot.pause()
            for btn_id in (
                "#s1-site-create-btn",
                "#s1-site-edit-btn",
                "#s1-site-duplicate-btn",
                "#s1-site-expire-btn",
                "#s1-site-reactivate-btn",
                "#s1-site-rotate-token-btn",
                "#s1-site-delete-btn",
            ):
                pane.query_one(btn_id, Button).press()
                await pilot.pause()
                assert "Admin View (F2)" in str(pane.query_one("#s1-status", Static).render())
                assert len(app.screen_stack) == 1

            pane.query_one("#s1-wb-users-btn", Button).press()
            await pilot.pause()
            for btn_id in (
                "#s1-user-create-btn",
                "#s1-user-edit-btn",
                "#s1-user-reset-pw-btn",
                "#s1-user-reset-2fa-btn",
                "#s1-user-logout-btn",
                "#s1-user-delete-btn",
            ):
                pane.query_one(btn_id, Button).press()
                await pilot.pause()
                assert "Admin View (F2)" in str(pane.query_one("#s1-status", Static).render())
                assert len(app.screen_stack) == 1

            muts = [
                r
                for r in mock_s1_server.requests_log[req_before:]
                if r["method"] in {"POST", "PUT", "DELETE"}
            ]
            assert muts == []

    asyncio.run(_run())


@pytest.mark.feature("V21-F11")
def test_v21_f11_delete_site_exact_name_gate_rejects_mismatch(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import Button, DataTable, Input, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.s1_modals import ConfirmDeleteSiteModal
    from soclens.tui.screens.sentinelone import SentinelOnePane

    with _build_s1_client(mock_s1_server) as s1:
        req_before = len(mock_s1_server.requests_log)
        with pytest.raises(ValueError):
            s1.delete_site("100101", confirm_site_name="mdr-1001", expected_site_name="MDR-1001")
        assert len(mock_s1_server.requests_log) == req_before

    app = create_app(
        client=MagicMock(),
        dry_run=False,
        workspace_dir=v21_workspace,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-sentinelone")
            await _wait_until(pilot, lambda: len(list(app.query(SentinelOnePane))) == 1)
            pane = app.query_one(SentinelOnePane)
            pane.query_one("#s1-wb-sites-btn", Button).press()
            pane.query_one("#s1-sites-btn", Button).press()
            await app.workers.wait_for_complete()
            await _wait_until(
                pilot,
                lambda: any(r.get("id") == "100101" for r in pane._filtered_records),
            )

            idx = next(i for i, r in enumerate(pane._table_rows) if r.get("id") == "100101")
            pane.query_one("#s1-table", DataTable).move_cursor(row=idx, column=0)
            pane._select_record(pane._table_rows[idx])
            pane.query_one("#s1-site-delete-btn", Button).press()
            await _wait_until(pilot, lambda: isinstance(app.screen, ConfirmDeleteSiteModal))

            modal = app.screen
            inp = modal.query_one("#s1-del-site-confirm-input", Input)
            approve = modal.query_one("#s1-del-site-approve-btn", Button)
            for bad_name in ("mdr-1001", "MDR-100", ""):
                inp.value = bad_name
                approve.press()
                await pilot.pause()
                assert isinstance(app.screen, ConfirmDeleteSiteModal)
                assert "mismatch" in str(modal.query_one("#s1-del-site-error", Static).render()).lower()

            assert not [
                r
                for r in mock_s1_server.requests_log
                if r["method"] == "DELETE" and "/sites/" in r["path"]
            ]

            inp.value = "MDR-1001"
            approve.press()
            await _wait_until(
                pilot,
                lambda: any(
                    r["method"] == "DELETE" and r["path"] == "/web/api/v2.1/sites/100101"
                    for r in mock_s1_server.requests_log
                ),
            )

    asyncio.run(_run())


@pytest.mark.feature("V21-F11")
def test_v21_f11_confirm_modal_cancel_aborts_site_and_user_mutations(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import Button, DataTable

    from soclens.tui.app import create_app
    from soclens.tui.modals import ConfirmActionModal
    from soclens.tui.screens.sentinelone import SentinelOnePane

    app = create_app(
        client=MagicMock(),
        dry_run=False,
        workspace_dir=v21_workspace,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-sentinelone")
            await _wait_until(pilot, lambda: len(list(app.query(SentinelOnePane))) == 1)
            pane = app.query_one(SentinelOnePane)
            pane.query_one("#s1-wb-sites-btn", Button).press()
            pane.query_one("#s1-sites-btn", Button).press()
            await app.workers.wait_for_complete()
            await _wait_until(pilot, lambda: len(pane._filtered_records) >= 1)

            pane.query_one("#s1-table", DataTable).move_cursor(row=0, column=0)
            pane._select_record(pane._table_rows[0])
            req_before = len(mock_s1_server.requests_log)

            pane.query_one("#s1-site-expire-btn", Button).press()
            await _wait_until(pilot, lambda: isinstance(app.screen, ConfirmActionModal))
            app.screen.query_one("#confirm-cancel-btn", Button).press()
            await _wait_until(pilot, lambda: not isinstance(app.screen, ConfirmActionModal))

            pane.query_one("#s1-wb-users-btn", Button).press()
            pane.query_one("#s1-users-load-btn", Button).press()
            await app.workers.wait_for_complete()
            await _wait_until(
                pilot,
                lambda: pane._current_view == "users_rbac"
                and len(pane._filtered_records) >= 1,
            )
            pane.query_one("#s1-table", DataTable).move_cursor(row=0, column=0)
            pane._select_record(pane._table_rows[0])
            pane.query_one("#s1-user-delete-btn", Button).press()
            await _wait_until(pilot, lambda: isinstance(app.screen, ConfirmActionModal))
            await pilot.press("escape")
            await _wait_until(pilot, lambda: not isinstance(app.screen, ConfirmActionModal))

            assert not [
                r
                for r in mock_s1_server.requests_log[req_before:]
                if r["method"] in {"POST", "PUT", "DELETE"}
            ]

    asyncio.run(_run())


@pytest.mark.feature("V21-F11")
def test_v21_f11_site_policy_copy_strips_readonly_keys(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    dirty_policy = {
        "mitigationMode": "protect",
        "antiTamperingOn": True,
        "createdAt": "2025-01-01T00:00:00Z",
        "updatedAt": "2026-01-01T00:00:00Z",
        "userId": "usr-admin",
        "userFullName": "Admin User",
        "inheritedFrom": "acc-100",
        "fwForNetworkQuarantineEnabled": False,
    }
    with _build_s1_client(mock_s1_server) as s1:
        s1.update_site_policy("100102", dirty_policy)

    put_req = next(
        r
        for r in mock_s1_server.requests_log
        if r["method"] == "PUT" and r["path"] == "/web/api/v2.1/sites/100102/policy"
    )
    sent_data = put_req["json_body"]["data"]
    assert sent_data["mitigationMode"] == "protect"
    for forbidden in (
        "createdAt",
        "updatedAt",
        "userId",
        "userFullName",
        "inheritedFrom",
        "fwForNetworkQuarantineEnabled",
    ):
        assert forbidden not in sent_data


@pytest.mark.feature("V21-F11")
def test_v21_f11_rbac_role_row_readonly_and_clone_user_permissions_validation(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import Button, DataTable, Select, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.sentinelone import SentinelOnePane

    with _build_s1_client(mock_s1_server) as s1:
        cloned = s1.clone_user_permissions("usr-mdr-lead", target_site_ids=["100102"])
        assert cloned["scope"] == "site"
        assert cloned["scopeRoles"]
        for role_entry in cloned["scopeRoles"]:
            assert "name" not in role_entry
            assert "accountName" not in role_entry
            assert role_entry["id"] == "100102"

    app = create_app(
        client=MagicMock(),
        dry_run=False,
        workspace_dir=v21_workspace,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-sentinelone")
            await _wait_until(pilot, lambda: len(list(app.query(SentinelOnePane))) == 1)
            pane = app.query_one(SentinelOnePane)
            pane.query_one("#s1-wb-users-btn", Button).press()
            await _wait_until(
                pilot,
                lambda: pane._current_view == "users_rbac",
            )
            pane.query_one("#s1-users-mode-select", Select).value = "roles"
            pane.query_one("#s1-users-load-btn", Button).press()
            await app.workers.wait_for_complete()
            await _wait_until(
                pilot,
                lambda: pane._users_submode == "roles"
                and len(pane._filtered_records) >= 1,
            )
            pane.query_one("#s1-table", DataTable).move_cursor(row=0, column=0)
            pane._select_record(pane._table_rows[0])
            pane.query_one("#s1-user-edit-btn", Button).press()
            await pilot.pause()
            status_txt = str(pane.query_one("#s1-status", Static).render()).lower()
            assert "read-only" in status_txt or "role" in status_txt
            assert len(app.screen_stack) == 1

            pane.query_one("#s1-user-delete-btn", Button).press()
            await pilot.pause()
            assert len(app.screen_stack) == 1

    asyncio.run(_run())


@pytest.mark.feature("V21-F11")
def test_v21_f11_site_and_user_client_validation_rejects_invalid_inputs(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    with _build_s1_client(mock_s1_server) as s1:
        req_before = len(mock_s1_server.requests_log)
        with pytest.raises(ValueError):
            s1.create_site(name="MDR-9999", account_id="acc-100", sku="Gold")
        with pytest.raises(ValueError):
            s1.create_site(name="MDR-9999", account_id="acc-100", site_type="Free")
        with pytest.raises(ValueError):
            s1.create_user(email="", full_name="Analyst", scope="site")
        with pytest.raises(ValueError):
            s1.create_user(email="a@example.test", full_name="", scope="site")
        with pytest.raises(ValueError):
            s1.create_service_user(name="svc-test", scope="site", expiration_date="")
        assert len(mock_s1_server.requests_log) == req_before

        # totalLicenses=0 is valid and preserved
        created = s1.create_site(
            name="MDR-ZERO-LIC",
            account_id="acc-100",
            total_licenses=0,
            unlimited_licenses=False,
        )
        assert created["totalLicenses"] == 0


# ======================================================================
# V21-F12: Exclusions, Cloning <=15 req/s, Agents & CLI (6 tests)
# ======================================================================


@pytest.mark.feature("V21-F12")
def test_v21_f12_exclusion_cloning_enforces_le_15_rps_pacing(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    mock_s1_server.seed_bulk_exclusions("100101", 20)
    with _build_s1_client(mock_s1_server) as s1:
        result = s1.clone_exclusions(
            "100101",
            "100102",
            source_site_name="MDR-1001",
            dry_run=False,
            requests_per_second=50.0,
        )
    assert result["requests_per_second"] == MAX_EXCLUSION_CLONE_RPS == 15.0
    assert result["counts"]["created"] >= 20

    post_timestamps = [
        r["timestamp"]
        for r in mock_s1_server.requests_log
        if r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
    ]
    assert len(post_timestamps) >= 20
    elapsed = post_timestamps[-1] - post_timestamps[0]
    assert elapsed >= (len(post_timestamps) - 1) / 15.0 - 0.15


@pytest.mark.feature("V21-F12")
def test_v21_f12_cloned_description_provenance_500_char_truncation() -> None:
    for length in (0, 470, 495, 520):
        raw = "X" * length
        desc = _format_cloned_description(raw, "MDR-1001")
        assert desc.endswith("[Cloned from MDR-1001]")
        assert len(desc) <= 500
        if length >= 495:
            assert "... [Cloned from MDR-1001]" in desc


@pytest.mark.feature("V21-F12")
def test_v21_f12_exclusion_cloning_dedup_inheritance_and_dry_run(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    with _build_s1_client(mock_s1_server) as s1:
        plan = s1.clone_exclusions(
            "100101",
            "100102",
            source_site_name="MDR-1001",
            dry_run=True,
        )

    assert plan["dry_run"] is True
    assert len(plan["will_create"]) >= 2
    assert len(plan["skipped_duplicate"]) >= 1
    assert len(plan["inherited_from_account"]) >= 1
    assert not [
        r
        for r in mock_s1_server.requests_log
        if r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
    ]
    excl_gets = [
        r
        for r in mock_s1_server.requests_log
        if r["method"] == "GET" and r["path"] == "/web/api/v2.1/exclusions"
    ]
    assert any(r["query"].get("includeParents") == ["false"] for r in excl_gets)
    assert any(r["query"].get("includeParents") == ["true"] for r in excl_gets)


@pytest.mark.feature("V21-F12")
def test_v21_f12_user_view_blocks_exclusions_blocklist_and_agent_admin_ops(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import Button, Static

    from soclens.tui.app import create_app
    from soclens.tui.screens.sentinelone import SentinelOnePane

    app = create_app(
        client=MagicMock(),
        dry_run=False,
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            app.activate_tab("tab-sentinelone")
            await _wait_until(pilot, lambda: len(list(app.query(SentinelOnePane))) == 1)
            pane = app.query_one(SentinelOnePane)
            req_before = len(mock_s1_server.requests_log)

            pane.query_one("#s1-wb-exclusions-btn", Button).press()
            await pilot.pause()
            for btn_id in (
                "#s1-create-excl-btn",
                "#s1-edit-excl-btn",
                "#s1-delete-excl-btn",
                "#s1-clone-excl-btn",
            ):
                pane.query_one(btn_id, Button).press()
                await pilot.pause()
                assert "Admin View (F2)" in str(pane.query_one("#s1-status", Static).render())

            pane.query_one("#s1-wb-agents-btn", Button).press()
            await pilot.pause()
            for btn_id in ("#s1-move-agent-btn", "#s1-decommission-btn"):
                pane.query_one(btn_id, Button).press()
                await pilot.pause()
                assert "Admin View (F2)" in str(pane.query_one("#s1-status", Static).render())

            pane.query_one("#s1-goto-blocklist-btn", Button).press()
            await pilot.pause()
            for btn_id in ("#s1-add-block-btn", "#s1-delete-block-btn"):
                pane.query_one(btn_id, Button).press()
                await pilot.pause()
                assert "Admin View (F2)" in str(pane.query_one("#s1-status", Static).render())

            assert not [
                r
                for r in mock_s1_server.requests_log[req_before:]
                if r["method"] in {"POST", "PUT", "DELETE"}
            ]

    asyncio.run(_run())


@pytest.mark.feature("V21-F12")
def test_v21_f12_blocklist_invalid_sha1_and_empty_ids_rejected(
    mock_s1_server: MockSentinelOneServer,
) -> None:
    with _build_s1_client(mock_s1_server) as s1:
        req_before = len(mock_s1_server.requests_log)
        with pytest.raises(ValueError):
            s1.add_to_blocklist("not-a-sha1", site_ids=["100101"])
        with pytest.raises(ValueError):
            s1.remove_from_blocklist([])
        assert len(mock_s1_server.requests_log) == req_before


def _read_cli_json(proc: Any) -> Any:
    for stream in (proc.stdout, proc.stderr):
        raw = (stream or "").strip()
        if not raw:
            continue
        try:
            return json.loads(raw)
        except ValueError:
            continue
    return None


@pytest.mark.feature("V21-F12")
def test_v21_f12_cli_s1_admin_yes_dry_run_and_delete_site_name_gates(
    mock_s1_server: MockSentinelOneServer,
    run_cli: Any,
) -> None:
    req_before = len(mock_s1_server.requests_log)

    no_admin = run_cli(
        [
            "s1",
            "sites",
            "create",
            "--name",
            "MDR-CLI-TEST",
            "--account-id",
            "acc-100",
            "--yes",
            "--json",
        ]
    )
    assert no_admin.returncode != 0
    no_admin_err = _read_cli_json(no_admin)
    if isinstance(no_admin_err, dict):
        assert no_admin_err.get("error")
        assert "admin" in str(no_admin_err["error"]).lower()
    else:
        assert "admin" in (no_admin.stderr + no_admin.stdout).lower()

    no_yes = run_cli(
        [
            "s1",
            "exclusions",
            "clone",
            "--from-site",
            "100101",
            "--to-site",
            "100102",
            "--admin",
            "--json",
        ]
    )
    assert no_yes.returncode != 0
    no_yes_err = _read_cli_json(no_yes)
    assert isinstance(no_yes_err, dict) and no_yes_err.get("error")
    assert no_yes_err.get("approval_required") is True or "yes" in str(no_yes_err["error"]).lower()

    del_proc = run_cli(["s1", "sites", "delete", "100101", "--admin", "--yes", "--json"])
    assert del_proc.returncode != 0
    del_err = _read_cli_json(del_proc)
    if isinstance(del_err, dict):
        assert del_err.get("error")
        err_low = str(del_err["error"]).lower()
        assert "confirm" in err_low or "name" in err_low
    else:
        combined_del = (del_proc.stderr + del_proc.stdout).lower()
        assert "confirm" in combined_del or "name" in combined_del

    dry_clone = run_cli(
        [
            "s1",
            "exclusions",
            "clone",
            "--from-site",
            "100101",
            "--to-site",
            "100102",
            "--admin",
            "--dry-run",
            "--json",
        ]
    )
    assert dry_clone.returncode == 0, dry_clone.stderr
    dry_payload = json.loads(dry_clone.stdout)
    assert isinstance(dry_payload, dict)
    assert dry_payload.get("dry_run") is True
    assert any(
        k in dry_payload
        for k in ("plan", "will_create", "summary", "action", "from_site", "to_site")
    )
    assert not [
        r
        for r in mock_s1_server.requests_log[req_before:]
        if r["method"] in {"POST", "PUT", "DELETE"}
    ]
