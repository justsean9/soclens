"""Tier 1 E2E happy-path tests for SOCLens v2.1 SentinelOne Multi-Site & Admin (V21-F9..V21-F12)."""

from __future__ import annotations

import asyncio
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

import tests.e2e.v21_mocks as _v21
from soclens.config import get_s1_tier_config, get_sentinelone_config
from soclens.sentinelone import SentinelOneClient

if TYPE_CHECKING:
    from tests.e2e.v21_mocks import MockRFServer, MockSentinelOneServer

v21_workspace = _v21.v21_workspace
mock_s1_server = _v21.mock_s1_server

pytestmark = [pytest.mark.e2e, pytest.mark.tier1]


def _table_rows_text(app: Any, selector: str = "#s1-table") -> list[str]:
    from textual.widgets import DataTable

    table = app.query_one(selector, DataTable)
    return [
        " | ".join(str(cell) for cell in table.get_row_at(idx))
        for idx in range(table.row_count)
    ]


# ==============================================================================
# V21-F9: S1 Hierarchy, Tier Classifier, Tier Pills, 4 Grouping Modes & Guardrails
# ==============================================================================


@pytest.mark.feature("V21-F9")
def test_v21_f9_hierarchy_accounts_sites_groups_and_sites_envelope_variants(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        info = s1.check_connection()
        assert info

        accounts = s1.list_accounts()
        assert {a["id"] for a in accounts} == {"acc-100", "acc-200"}

        sites = s1.list_sites()
        assert len(sites) == 5

        groups = s1.list_groups(site_ids=["100101"])
        assert any(g["id"] == "grp-100101-ws" for g in groups)

        mock_s1_server.set_sites_as_list(True)
        sites_list_env = s1.list_sites()
        assert len(sites_list_env) == 5


@pytest.mark.feature("V21-F9")
def test_v21_f9_tier_classifier_case_insensitive_custom_rules_and_site_tenant_map(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        enriched = s1.enrich_sites_with_tiers(s1.list_sites())
        by_id = {site["id"]: site for site in enriched}
        assert (by_id["100101"]["tier"], by_id["100101"]["tenantId"]) == ("MDR", "1001")
        assert (by_id["200101"]["tier"], by_id["200101"]["tenantId"]) == ("MSSP", "2001")
        assert (by_id["300101"]["tier"], by_id["300101"]["tenantId"]) == ("Other", None)

        assert s1.classify_site("mdr_42") == ("MDR", "42", "42")

        monkeypatch.setenv("S1_TIER_RULES", '{"Enterprise": "(?i)^corp[-_]([a-z0-9-]+)"}')
        monkeypatch.setenv(
            "S1_SITE_TENANT_MAP", '{"Corp-Sandbox-3001": "3001"}'
        )
        tier_cfg = get_s1_tier_config()
        assert tier_cfg.classify_site("Corp-Sandbox-3001") == (
            "Enterprise",
            "Sandbox-3001",
            "3001",
        )
        assert s1.classify_site("Corp-Sandbox-3001") == (
            "Enterprise",
            "Sandbox-3001",
            "3001",
        )


@pytest.mark.feature("V21-F9")
def test_v21_f9_guardrails_cursor_pagination_limit_100_and_429_retry_backoff(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    base_agent = dict(mock_s1_server.state["agents"][0])
    for idx in range(102):
        clone = dict(base_agent)
        clone["id"] = f"ag-extra-{idx:03d}"
        clone["computerName"] = f"extra-{idx:03d}.example.test"
        mock_s1_server.state["agents"].append(clone)

    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        agents = s1.list_agents(limit=200)
        assert len(agents) == 107

        agent_gets = [
            r
            for r in mock_s1_server.requests_log
            if r["method"] == "GET" and r["path"] == "/web/api/v2.1/agents"
        ]
        assert len(agent_gets) == 2
        assert all(int(r["query"]["limit"][0]) <= 100 for r in agent_gets)
        assert "cursor" in agent_gets[1]["query"]

        mock_s1_server.requests_log.clear()
        mock_s1_server.queue_fault(
            "/web/api/v2.1/sites",
            429,
            headers={"Retry-After": "0.05"},
            method="GET",
        )
        sites = s1.list_sites()
        assert len(sites) == 5

        site_gets = [
            r
            for r in mock_s1_server.requests_log
            if r["method"] == "GET" and r["path"] == "/web/api/v2.1/sites"
        ]
        assert len(site_gets) == 2


@pytest.mark.feature("V21-F9")
def test_v21_f9_guardrail_non_empty_filter_and_data_ids_on_mutations(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        s1.update_threat_verdict(["thr-1001-1"], "true_positive")
        s1.disconnect_agent(["ag-1001-1"])
        s1.delete_exclusions(["excl-src-dup"])

    verdict_post = [
        r for r in mock_s1_server.requests_log if r["path"].endswith("/threats/analyst-verdict")
    ][-1]
    assert verdict_post["json_body"]["filter"]["ids"] == ["thr-1001-1"]

    disconnect_post = [
        r for r in mock_s1_server.requests_log if r["path"].endswith("/agents/actions/disconnect")
    ][-1]
    assert disconnect_post["json_body"]["filter"]["ids"] == ["ag-1001-1"]

    del_excl = [
        r
        for r in mock_s1_server.requests_log
        if r["method"] == "DELETE" and r["path"].endswith("/exclusions")
    ][-1]
    assert del_excl["json_body"]["data"]["ids"] == ["excl-src-dup"]


@pytest.mark.feature("V21-F9")
def test_v21_f9_tui_tier_filter_pills_site_multiselect_and_four_grouping_modes(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import Collapsible, DataTable, Input, Select

    from soclens.tui import create_app

    app = create_app(
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = app.query_one("#s1-table", DataTable)
            assert table.row_count == 6

            await pilot.click("#s1-tier-mdr-btn")
            await pilot.pause()
            assert table.row_count == 3

            await pilot.click("#s1-tier-mssp-btn")
            await pilot.pause()
            assert table.row_count == 2

            await pilot.click("#s1-tier-other-btn")
            await pilot.pause()
            assert table.row_count == 1

            await pilot.click("#s1-tier-all-btn")
            await pilot.pause()
            assert table.row_count == 6

            grouping_sel = app.query_one("#s1-grouping-select", Select)
            grouping_sel.value = "tier"
            await pilot.pause()
            assert table.row_count >= 3

            grouping_sel.value = "site"
            await pilot.pause()
            assert table.row_count >= 4

            grouping_sel.value = "tier_hash"
            await pilot.pause()
            rows_joined = "\n".join(_table_rows_text(app))
            assert "MDR" in rows_joined
            assert "MSSP" in rows_joined

            app.query_one("#s1-scope-collapsible", Collapsible).collapsed = False
            await pilot.pause()
            await pilot.click("#s1-site-load-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            app.query_one("#s1-site-search-input", Input).value = "MDR"
            await pilot.pause()

    asyncio.run(_run())


# ==============================================================================
# V21-F10: S1 Alerts & Threats + Cloud/STAR Alerts
# ==============================================================================


@pytest.mark.feature("V21-F10")
def test_v21_f10_threats_list_timeline_verdict_status_mitigate_and_note(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        unresolved = s1.list_threats(resolved=False)
        assert len(unresolved) == 5

        timeline = s1.get_threat_timeline("thr-1001-1")
        assert len(timeline) == 2

        s1.update_threat_verdict(["thr-1001-1"], "true_positive")
        s1.update_threat_incident_status(["thr-1001-1"], "in_progress")
        s1.add_threat_note("thr-1001-1", "Verified beacon")
        s1.mitigate_threat(["thr-1001-1"], "kill")

        updated_timeline = s1.get_threat_timeline("thr-1001-1")
        assert len(updated_timeline) == 3

    thr_info = mock_s1_server.state["threats"][0]["threatInfo"]
    assert thr_info["analystVerdict"] == "true_positive"
    assert thr_info["incidentStatus"] == "in_progress"
    assert thr_info["mitigationStatus"] == "mitigated:kill"


@pytest.mark.feature("V21-F10")
def test_v21_f10_cloud_star_alerts_filter_verdict_status_and_unified_stream(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        crit = s1.list_cloud_alerts(severities="critical")
        assert [c["id"] for c in crit] == ["cld-2001-1"]

        s1.update_cloud_alert_verdict(["cld-1001-1"], "true_positive")
        s1.update_cloud_alert_incident_status(["cld-1001-1"], "resolved")

        unified = s1.list_unified_alerts()
        assert len(unified) == 8
        assert all(a.get("tier") in {"MDR", "MSSP", "Other"} for a in unified)
        by_id = {a["id"]: a for a in unified}
        assert by_id["thr-1001-1"]["tenantId"] == "1001"
        assert by_id["cld-2001-1"]["tenantId"] == "2001"


@pytest.mark.feature("V21-F10")
def test_v21_f10_threat_add_to_exclusions_creates_site_exclusion(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        res = s1.add_threat_to_exclusions(
            ["thr-1001-2"],
            target_scope="site",
            mode="suppress",
            description="Approved IR tool",
        )
        affected = res.get("affected")
        if affected is None and isinstance(res.get("data"), dict):
            affected = res["data"].get("affected")
        assert affected == 1

    assert any(
        e.get("scopeId") == "100101" and e.get("value") == "b" * 40
        for e in mock_s1_server.state["exclusions"]
    )


@pytest.mark.feature("V21-F10")
def test_v21_f10_tui_alerts_workbench_unified_triage_and_mitigate(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import DataTable, Input, Select

    from soclens.tui import create_app

    app = create_app(
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            app.query_one("#s1-alert-source-select", Select).value = "unified"
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#s1-table", DataTable).row_count == 8

            await pilot.click("#s1-triage-btn")
            await pilot.pause()
            app.screen.query_one("#s1-triage-verdict-select", Select).value = "true_positive"
            app.screen.query_one("#s1-triage-status-select", Select).value = "resolved"
            app.screen.query_one("#s1-triage-note-input", Input).value = "Triaged in TUI"
            await pilot.click("#s1-triage-apply-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert any(
                "analyst-verdict" in r["path"] for r in mock_s1_server.requests_log
            )

            await pilot.click("#s1-quarantine-btn")
            await pilot.pause()
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert any(
                "/threats/mitigate/quarantine" in r["path"]
                for r in mock_s1_server.requests_log
            )

    asyncio.run(_run())


@pytest.mark.feature("V21-F10")
def test_v21_f10_tui_alerts_enrich_in_rf_pivot(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
    mock_rf_server: MockRFServer,
) -> None:
    """Awaits Wave 2 (M4): SocLensApp.dispatch_pivot wiring from S1 -> tab-rf-intel."""
    from textual.widgets import DataTable, TabbedContent

    from soclens.tui import create_app

    app = create_app(
        dry_run=True,
        initial_tab="tab-sentinelone",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-wb-alerts-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#s1-table", DataTable).row_count == 6
            mock_rf_server.requests_log.clear()

            await pilot.click("#s1-pivot-rf-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#main-tabs", TabbedContent).active == "tab-rf-intel"
            assert mock_rf_server.requests_log
            rf_paths = " ".join(r["path"] for r in mock_rf_server.requests_log)
            assert ("a" * 40) in rf_paths or "srv-1001-db.example.test" in rf_paths

    asyncio.run(_run())


# ==============================================================================
# V21-F11: S1 Sites Admin & Users/RBAC Admin + Admin View F2 Gating
# ==============================================================================


@pytest.mark.feature("V21-F11")
def test_v21_f11_sites_admin_create_with_policy_copy_duplicate_and_lifecycle(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        created = s1.create_site(
            name="MDR-5001",
            account_id="acc-100",
            total_licenses=50,
            copy_policy_from_site_id="100101",
        )
        sid = str(created["id"])
        pol = s1.get_site_policy(sid)
        assert pol["mitigationModeSuspicious"] == "protect"
        assert pol["inherits"] is False

        dup = s1.duplicate_site(
            "100101",
            "MDR-5002",
            policy_source="copy_source_site",
            copy_users=True,
        )
        assert dup["name"] == "MDR-5002"

        s1.update_site(sid, description="Updated")
        s1.expire_site(sid)
        s1.reactivate_site(sid, unlimited=True)
        rot = s1.rotate_site_token(sid)
        assert rot
        tok = s1.get_site_token(sid)
        assert tok
        s1.revert_site_policy(sid)
        del_res = s1.delete_site(
            sid,
            confirm_site_name="MDR-5001",
            expected_site_name="MDR-5001",
        )
        assert del_res


@pytest.mark.feature("V21-F11")
def test_v21_f11_users_service_users_rbac_and_clone_permissions(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        assert len(s1.list_users()) == 3
        assert len(s1.list_service_users()) == 2
        assert len(s1.list_rbac_roles()) == 4

        cloned = s1.clone_user_permissions("usr-mdr-lead", target_site_ids=["100102"])
        created_usr = s1.create_user(
            email="cloned.mdr@example.test",
            full_name="Cloned MDR",
            scope=cloned["scope"],
            scope_roles=cloned["scopeRoles"],
        )
        uid = str(created_usr["id"])
        s1.send_reset_password_email([uid])
        s1.reset_2fa([uid], enroll=False)
        s1.logout_user()
        s1.delete_user(uid)

        svc = s1.create_service_user(
            name="svc-cloned-1002",
            scope="site",
            expiration_date="2027-11-25T00:00:00Z",
            scope_roles=cloned["scopeRoles"],
        )
        svc_id = str(svc["id"])
        tok_res = s1.generate_service_user_token(
            svc_id, expiration_date="2027-11-25T00:00:00Z"
        )
        assert tok_res
        s1.delete_service_user(svc_id)


@pytest.mark.feature("V21-F11")
def test_v21_f11_tui_sites_admin_user_view_read_only_vs_f2_admin_create_and_delete(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import DataTable, Input, Static

    from soclens.tui import create_app

    app = create_app(
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = app.query_one("#s1-table", DataTable)
            assert table.row_count == 5

            mock_s1_server.requests_log.clear()
            await pilot.click("#s1-site-create-btn")
            await pilot.pause()
            await pilot.click("#s1-site-delete-btn")
            await pilot.pause()
            assert not any(
                r["method"] in {"POST", "DELETE"} and "/sites" in r["path"]
                for r in mock_s1_server.requests_log
            )

            await pilot.press("f2")
            await pilot.pause()
            assert "Admin View: ON [F2]" in str(
                app.query_one("#s1-admin-badge", Static).content
            )

            await pilot.click("#s1-site-create-btn")
            await pilot.pause()
            app.screen.query_one("#s1-site-name-input", Input).value = "MDR-7001"
            app.screen.query_one("#s1-site-account-input", Input).value = "acc-100"
            app.screen.query_one("#s1-site-licenses-input", Input).value = "25"
            await pilot.click("#s1-site-save-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 6

            for idx in range(table.row_count):
                if "MDR-7001" in " ".join(str(c) for c in table.get_row_at(idx)):
                    table.move_cursor(row=idx)
                    break
            await pilot.pause()

            await pilot.click("#s1-site-delete-btn")
            await pilot.pause()
            app.screen.query_one("#s1-del-site-confirm-input", Input).value = "MDR-7001"
            await pilot.click("#s1-del-site-approve-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 5

    asyncio.run(_run())


@pytest.mark.feature("V21-F11")
def test_v21_f11_tui_sites_policy_modal_copy_and_lifecycle_actions(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import DataTable, Select

    from soclens.tui import create_app

    app = create_app(
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=v21_workspace,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = app.query_one("#s1-table", DataTable)
            for idx in range(table.row_count):
                if "MDR-1002" in " ".join(str(c) for c in table.get_row_at(idx)):
                    table.move_cursor(row=idx)
                    break
            await pilot.pause()

            await pilot.click("#s1-site-policy-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            app.screen.query_one("#s1-policy-src-select", Select).value = "100101"
            await pilot.click("#s1-policy-copy-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["method"] == "PUT" and r["path"].endswith("/sites/100102/policy")
                for r in mock_s1_server.requests_log
            )
            from soclens.tui.screens.s1_modals import S1SitePolicyModal

            if isinstance(app.screen, S1SitePolicyModal):
                await pilot.click("#s1-policy-cancel-btn")
                await pilot.pause()

            for btn_id, expected_suffix in (
                ("#s1-site-expire-btn", "/expire-now"),
                ("#s1-site-reactivate-btn", "/reactivate"),
                ("#s1-site-rotate-token-btn", "/regenerate-key"),
            ):
                await pilot.click(btn_id)
                await pilot.pause()
                await pilot.click("#confirm-approve-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert any(
                    r["path"].endswith(expected_suffix)
                    for r in mock_s1_server.requests_log
                )

    asyncio.run(_run())


@pytest.mark.feature("V21-F11")
def test_v21_f11_tui_users_rbac_workbench_create_and_modes(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import DataTable, Input, Select

    from soclens.tui import create_app

    app = create_app(
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=v21_workspace,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-wb-users-btn")
            await pilot.pause()
            await pilot.click("#s1-users-load-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            table = app.query_one("#s1-table", DataTable)
            assert table.row_count == 3

            await pilot.click("#s1-user-create-btn")
            await pilot.pause()
            app.screen.query_one("#s1-user-email-input", Input).value = "new.mdr@example.test"
            app.screen.query_one("#s1-user-name-input", Input).value = "New MDR"
            app.screen.query_one("#s1-user-template-select", Select).value = "usr-mdr-lead"
            app.screen.query_one("#s1-user-site-select", Select).value = "100102"
            await pilot.click("#s1-user-save-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["method"] == "POST" and r["path"] == "/web/api/v2.1/users"
                for r in mock_s1_server.requests_log
            )

            mode_sel = app.query_one("#s1-users-mode-select", Select)
            mode_sel.value = "service"
            await pilot.pause()
            await pilot.click("#s1-users-load-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 2

            mode_sel.value = "roles"
            await pilot.pause()
            await pilot.click("#s1-users-load-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert table.row_count == 4

    asyncio.run(_run())


@pytest.mark.feature("V21-F11")
def test_v21_f11_cli_s1_admin_sites_and_users_lifecycle(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Awaits Wave 2 (M4): soclens s1 --admin sites/users lifecycle CLI commands."""
    create_site_proc = run_cli(
        [
            "s1",
            "--admin",
            "sites",
            "create",
            "--name",
            "MDR-8001",
            "--account-id",
            "acc-100",
            "--licenses",
            "25",
            "--yes",
            "--json",
        ]
    )
    assert create_site_proc.returncode == 0, (
        f"stdout={create_site_proc.stdout}\nstderr={create_site_proc.stderr}"
    )
    created_site = json.loads(create_site_proc.stdout)
    nested_site = (
        created_site.get("site")
        if isinstance(created_site.get("site"), dict)
        else (created_site.get("data") if isinstance(created_site.get("data"), dict) else {})
    )
    sid = str(created_site.get("id") or nested_site.get("id") or "")
    assert sid

    create_user_proc = run_cli(
        [
            "s1",
            "--admin",
            "users",
            "create",
            "--email",
            "cli.mdr@example.test",
            "--name",
            "CLI MDR",
            "--site-id",
            sid,
            "--yes",
            "--json",
        ]
    )
    assert create_user_proc.returncode == 0, (
        f"stdout={create_user_proc.stdout}\nstderr={create_user_proc.stderr}"
    )
    assert json.loads(create_user_proc.stdout)
    assert any(
        r["method"] == "POST" and r["path"] == "/web/api/v2.1/users"
        for r in mock_s1_server.requests_log
    )

    del_site_proc = run_cli(
        [
            "s1",
            "--admin",
            "sites",
            "delete",
            sid,
            "--confirm-name",
            "MDR-8001",
            "--yes",
            "--json",
        ]
    )
    assert del_site_proc.returncode == 0, (
        f"stdout={del_site_proc.stdout}\nstderr={del_site_proc.stderr}"
    )
    assert json.loads(del_site_proc.stdout)
    assert any(
        r["method"] == "DELETE" and f"/web/api/v2.1/sites/{sid}" in r["path"]
        for r in mock_s1_server.requests_log
    )


# ==============================================================================
# V21-F12: S1 Exclusions & Site-to-Site Cloning, Agents Ops/Admin & Blocklist, CLI
# ==============================================================================


@pytest.mark.feature("V21-F12")
def test_v21_f12_exclusions_clone_dry_run_diff_live_pacing_15_rps_and_500_char_note(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        plan = s1.plan_clone_exclusions("100101", "100102", source_site_name="MDR-1001")
        assert plan["counts"]["will_create"] == 2
        assert plan["counts"]["skipped_duplicate"] == 1
        assert plan["counts"]["inherited_from_account"] == 1

        excl_gets = [
            r
            for r in mock_s1_server.requests_log
            if r["method"] == "GET" and r["path"] == "/web/api/v2.1/exclusions"
        ]
        assert any(r["query"].get("includeParents") == ["false"] for r in excl_gets)
        assert any(r["query"].get("includeParents") == ["true"] for r in excl_gets)

        for item in plan["will_create"]:
            desc = item["payload"]["description"]
            assert len(desc) <= 500
            if "CERT-EXAMPLE-9988" in str(item["payload"].get("value")):
                assert desc.endswith("[Cloned from MDR-1001]")

        mock_s1_server.seed_bulk_exclusions("100101", 6)
        mock_s1_server.requests_log.clear()
        res = s1.clone_exclusions(
            "100101",
            "100102",
            source_site_name="MDR-1001",
            dry_run=False,
            requests_per_second=15.0,
        )
        assert res["counts"]["created"] == 8

    post_times = [
        r["timestamp"]
        for r in mock_s1_server.requests_log
        if r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
    ]
    assert len(post_times) == 8
    assert (post_times[-1] - post_times[0]) >= (7 / 15.0 - 0.05)


@pytest.mark.feature("V21-F12")
def test_v21_f12_tui_clone_exclusions_modal_preview_and_execute(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    from textual.widgets import RichLog, Select

    from soclens.tui import create_app

    app = create_app(
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=v21_workspace,
        view_mode="admin",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-wb-exclusions-btn")
            await pilot.pause()
            await pilot.click("#s1-clone-excl-btn")
            await pilot.pause()

            app.screen.query_one("#s1-clone-src-select", Select).value = "100101"
            app.screen.query_one("#s1-clone-dst-select", Select).value = "100102"
            await pilot.click("#s1-clone-preview-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            preview_text = "\n".join(
                line.text
                for line in app.screen.query_one("#s1-clone-preview-log", RichLog).lines
            )
            assert preview_text.count("[Will Create]") == 2
            assert "[Skipped Duplicate]" in preview_text
            assert "[Inherited from Account]" in preview_text

            mock_s1_server.requests_log.clear()
            await pilot.click("#s1-clone-apply-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            posts = [
                r
                for r in mock_s1_server.requests_log
                if r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
            ]
            assert len(posts) == 2

    asyncio.run(_run())


@pytest.mark.feature("V21-F12")
def test_v21_f12_agents_ops_vs_admin_move_decommission_and_blocklist_crud(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
) -> None:
    cfg = get_sentinelone_config(required=True)
    with SentinelOneClient(config=cfg) as s1:
        s1.disconnect_agent(["ag-1001-1"])
        s1.connect_agent(["ag-1001-1"])
        s1.fetch_logs(["ag-1001-1"])
        s1.move_agents_to_site(["ag-1001-2"], "100102")
        s1.decommission(["ag-3001-1"])

        by_id = {a["id"]: a for a in mock_s1_server.state["agents"]}
        assert by_id["ag-1001-2"]["siteId"] == "100102"
        assert by_id["ag-3001-1"]["isDecommissioned"] is True

        added = s1.add_to_blocklist(
            "f" * 40,
            os_type="windows",
            description="Test IOC",
            site_ids=["100101"],
        )
        entries = s1.list_blocklist(site_ids=["100101"])
        assert any(e.get("value") == "f" * 40 for e in entries)
        bid = str(added.get("id") or entries[-1]["id"])
        s1.remove_from_blocklist([bid])


@pytest.mark.feature("V21-F12")
def test_v21_f12_tui_agents_and_blocklist_ops_vs_admin_gating(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from textual.widgets import DataTable, Input, Select

    from soclens.tui import create_app
    from soclens.tui.screens.sentinelone import SentinelOnePane

    app = create_app(
        dry_run=False,
        initial_tab="tab-sentinelone",
        workspace_dir=v21_workspace,
        view_mode="user",
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#s1-wb-sites-btn")
            await pilot.pause()
            await pilot.click("#s1-sites-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            await pilot.click("#s1-wb-agents-btn")
            await pilot.pause()
            await pilot.click("#s1-refresh-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#s1-table", DataTable).row_count == 5

            await pilot.click("#s1-isolate-btn")
            await pilot.pause()
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["path"].endswith("/agents/actions/disconnect")
                for r in mock_s1_server.requests_log
            )

            mock_s1_server.requests_log.clear()
            await pilot.click("#s1-move-agent-btn")
            await pilot.pause()
            await pilot.click("#s1-decommission-btn")
            await pilot.pause()
            assert not any(
                "/agents/actions/move-to-site" in r["path"]
                or "/agents/actions/decommission" in r["path"]
                for r in mock_s1_server.requests_log
            )

            await pilot.press("f2")
            await pilot.pause()
            await pilot.click("#s1-move-agent-btn")
            await pilot.pause()
            app.screen.query_one("#s1-move-target-site-select", Select).value = "100102"
            await pilot.click("#s1-move-apply-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["path"].endswith("/agents/actions/move-to-site")
                for r in mock_s1_server.requests_log
            )

            monkeypatch.setenv("S1_SITE_ID", "100101")
            app.query_one(SentinelOnePane).on_settings_updated()
            await pilot.click("#s1-goto-blocklist-btn")
            await pilot.pause()
            await pilot.click("#s1-add-block-btn")
            await pilot.pause()
            app.screen.query_one("#s1-block-hash-input", Input).value = "f" * 40
            await pilot.click("#s1-block-add-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert any(
                r["method"] == "POST" and r["path"].endswith("/restrictions")
                for r in mock_s1_server.requests_log
            )

    asyncio.run(_run())


@pytest.mark.feature("V21-F12")
def test_v21_f12_cli_s1_existing_v200_ops_commands(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    commands: list[list[str]] = [
        ["s1", "status", "--json"],
        ["s1", "agents", "--json"],
        ["s1", "threats", "--json"],
        ["s1", "isolate", "ag-1001-1", "--yes", "--json"],
        ["s1", "triage", "thr-1001-1", "--verdict", "true_positive", "--yes", "--json"],
        ["s1", "exclusions", "--json"],
        ["s1", "blocklist", "--json"],
        ["s1", "sites", "--json"],
        ["s1", "activities", "--json"],
    ]
    for cmd in commands:
        proc = run_cli(cmd)
        assert proc.returncode == 0, f"cmd={cmd}\nstdout={proc.stdout}\nstderr={proc.stderr}"


@pytest.mark.feature("V21-F12")
def test_v21_f12_cli_s1_v21_exclusions_clone_dry_run_and_execute(
    v21_workspace: Path,
    mock_s1_server: MockSentinelOneServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Awaits Wave 2 (M4): soclens s1 --admin exclusions clone CLI command."""
    dry_proc = run_cli(
        [
            "s1",
            "--admin",
            "exclusions",
            "clone",
            "--from-site",
            "100101",
            "--to-site",
            "100102",
            "--dry-run",
            "--json",
        ]
    )
    assert dry_proc.returncode == 0, f"stdout={dry_proc.stdout}\nstderr={dry_proc.stderr}"
    assert json.loads(dry_proc.stdout)
    assert not any(
        r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
        for r in mock_s1_server.requests_log
    )

    exec_proc = run_cli(
        [
            "s1",
            "--admin",
            "exclusions",
            "clone",
            "--from-site",
            "100101",
            "--to-site",
            "100102",
            "--yes",
            "--json",
        ]
    )
    assert exec_proc.returncode == 0, f"stdout={exec_proc.stdout}\nstderr={exec_proc.stderr}"
    assert json.loads(exec_proc.stdout)
    posts = [
        r
        for r in mock_s1_server.requests_log
        if r["method"] == "POST" and r["path"] == "/web/api/v2.1/exclusions"
    ]
    assert len(posts) == 2
