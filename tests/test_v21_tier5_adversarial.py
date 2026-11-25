"""Tier 5 white-box adversarial tests covering GAP-01 through GAP-10."""

from __future__ import annotations

import ast
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from textual.widgets import Button, Checkbox, Collapsible, Input, Select, Static, TabbedContent

from soclens.client import RecordedFutureClient
from soclens.config import PivotPayload
from soclens.sentinelone import SentinelOneClient, _sanitize_scope_roles
from soclens.settings import (
    get_profile_settings,
    save_profile_settings,
    set_session_overrides,
)
from soclens.tui.app import ALL_TABS, create_app
from soclens.tui.modals import (
    ConfirmActionModal,
    ContextMenuModal,
    CopyTextModal,
    SaveFilterPresetModal,
    TimezoneModal,
)
from soclens.tui.pivot import build_spl_from_pivot
from soclens.tui.screens.research import ResearchPane
from soclens.tui.screens.rf_intel import RFIntelPane
from soclens.tui.screens.s1_modals import S1UserModal
from soclens.tui.screens.sentinelone import SentinelOnePane
from soclens.tui.screens.settings import SettingsPane
from soclens.tui.screens.splunk_es import SplunkESPane

REPO_ROOT = Path(__file__).resolve().parents[1]


async def _wait_until(
    pilot: Any,
    predicate: Any,
    *,
    max_ticks: int = 80,
    delay: float = 0.02,
) -> None:
    for _ in range(max_ticks):
        if predicate():
            return
        await pilot.pause(delay)
    assert predicate()


# ======================================================================
# GAP-01: SentinelOneClient._scope_params() & list_sites() Isolation
# ======================================================================


def test_gap01_s1_scope_params_explicit_isolation() -> None:
    sess = MagicMock()

    def _empty_resp(*args: Any, **kwargs: Any) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.json.return_value = {"data": [], "pagination": {"nextCursor": None}}
        resp.text = "{}"
        return resp

    sess.request.side_effect = _empty_resp
    client = SentinelOneClient(
        console_url="https://s1.example.test",
        api_token="tok-test",
        account_id="acc-default",
        site_id="site-default",
        session=sess,
    )

    client.list_threats(account_ids=["acc-other"])
    params_threats = sess.request.call_args_list[-1].kwargs["params"]
    assert params_threats["accountIds"] == "acc-other"
    assert "siteIds" not in params_threats
    assert "groupIds" not in params_threats

    client.list_exclusions(site_ids=["site-other"])
    params_excl = sess.request.call_args_list[-1].kwargs["params"]
    assert params_excl["siteIds"] == "site-other"
    assert "accountIds" not in params_excl

    client.list_agents(group_ids=["grp-9"])
    params_agents = sess.request.call_args_list[-1].kwargs["params"]
    assert params_agents["groupIds"] == "grp-9"
    assert "accountIds" not in params_agents
    assert "siteIds" not in params_agents

    client.list_sites(account_ids=["acc-other"])
    params_sites_explicit = sess.request.call_args_list[-1].kwargs["params"]
    assert params_sites_explicit["accountIds"] == "acc-other"

    client.list_sites(account_ids=[])
    params_sites_empty = sess.request.call_args_list[-1].kwargs["params"]
    assert "accountIds" not in params_sites_empty

    client.list_threats()
    params_default = sess.request.call_args_list[-1].kwargs["params"]
    assert params_default["accountIds"] == "acc-default"
    assert params_default["siteIds"] == "site-default"

    client.list_sites()
    params_sites_default = sess.request.call_args_list[-1].kwargs["params"]
    assert params_sites_default["accountIds"] == "acc-default"


# ======================================================================
# GAP-02: Multi-Site S1UserModal(mode="edit") & _sanitize_scope_roles()
# ======================================================================


def test_gap02_sanitize_scope_roles_preserves_heterogeneous_without_cartesian() -> None:
    orig_roles = [
        {"id": "site-1", "roleId": "role-admin", "name": "MDR-1001"},
        {"id": "site-2", "roleId": "role-viewer", "name": "MDR-1002"},
    ]

    preserved = _sanitize_scope_roles(
        orig_roles,
        scope="site",
        target_site_ids=["site-1", "site-2"],
    )
    assert preserved == [
        {"roleId": "role-admin", "id": "site-1"},
        {"roleId": "role-viewer", "id": "site-2"},
    ]

    subset = _sanitize_scope_roles(
        orig_roles,
        scope="site",
        target_site_ids=["site-2"],
    )
    assert subset == [{"roleId": "role-viewer", "id": "site-2"}]

    cloned_new = _sanitize_scope_roles(
        [{"id": "site-old", "roleId": "role-ir"}],
        scope="site",
        target_site_ids=["site-new-1", "site-new-2"],
    )
    assert cloned_new == [
        {"roleId": "role-ir", "id": "site-new-1"},
        {"roleId": "role-ir", "id": "site-new-2"},
    ]


def test_gap02_s1_user_modal_edit_preserves_heterogeneous_roles_and_allows_override(
    tmp_path: Path,
) -> None:
    s1 = MagicMock()
    s1.tier_config = MagicMock(default_tier="Other")
    app = create_app(
        client=MagicMock(),
        s1_client=s1,
        dry_run=False,
        initial_tab="tab-sentinelone",
        view_mode="admin",
        workspace_dir=tmp_path,
    )

    user_multi = {
        "id": "u-multi",
        "fullName": "Alice Original",
        "email": "alice@example.test",
        "scope": "site",
        "scopeRoles": [
            {"id": "site-1", "roleId": "role-admin", "roleName": "Admin"},
            {"id": "site-2", "roleId": "role-viewer", "roleName": "Viewer"},
        ],
        "twoFaEnabled": True,
    }
    roles = [
        {"id": "role-admin", "name": "Admin"},
        {"id": "role-viewer", "name": "Viewer"},
        {"id": "role-analyst", "name": "Analyst"},
    ]
    sites = [
        {"id": "site-1", "name": "MDR-1001"},
        {"id": "site-2", "name": "MDR-1002"},
    ]

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(SentinelOnePane)

            # 1. Edit only fullName -> preserve heterogeneous roles exactly
            captured: list[dict[str, Any] | None] = []
            app.push_screen(
                S1UserModal(
                    mode="edit",
                    kind="console",
                    user=user_multi,
                    roles=roles,
                    sites=sites,
                ),
                captured.append,
            )
            await pilot.pause()
            assert isinstance(app.screen, S1UserModal)
            assert app.screen.query_one("#s1-user-role-select", Select).value == ""
            assert app.screen.query_one("#s1-user-site-select", Select).value == ""
            app.screen.query_one("#s1-user-name-input", Input).value = "Alice Updated"
            await pilot.click("#s1-user-save-btn")
            await pilot.pause()

            assert len(captured) == 1
            assert captured[0] is not None
            assert captured[0]["role_id"] == ""
            assert captured[0]["target_site_ids"] == []

            worker = pane._user_mutation_worker(captured[0])
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert worker.error is None
            s1.update_user.assert_called_once_with(
                "u-multi",
                scope="site",
                scope_roles=[
                    {"roleId": "role-admin", "id": "site-1"},
                    {"roleId": "role-viewer", "id": "site-2"},
                ],
                full_name="Alice Updated",
                email="alice@example.test",
                two_fa_enabled=True,
            )

            # 2. Explicit role override applies selected role across existing sites
            s1.update_user.reset_mock()
            override_captured: list[dict[str, Any] | None] = []
            app.push_screen(
                S1UserModal(
                    mode="edit",
                    kind="console",
                    user=user_multi,
                    roles=roles,
                    sites=sites,
                ),
                override_captured.append,
            )
            await pilot.pause()
            assert isinstance(app.screen, S1UserModal)
            app.screen.query_one("#s1-user-role-select", Select).value = "role-analyst"
            await pilot.click("#s1-user-save-btn")
            await pilot.pause()

            assert len(override_captured) == 1
            assert override_captured[0] is not None
            assert override_captured[0]["role_id"] == "role-analyst"
            assert override_captured[0]["target_site_ids"] == ["site-1", "site-2"]

            worker2 = pane._user_mutation_worker(override_captured[0])
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert worker2.error is None
            s1.update_user.assert_called_once_with(
                "u-multi",
                scope="site",
                scope_roles=[
                    {"id": "site-1", "roleId": "role-analyst"},
                    {"id": "site-2", "roleId": "role-analyst"},
                ],
                full_name="Alice Original",
                email="alice@example.test",
                two_fa_enabled=True,
            )

    asyncio.run(_run())


# ======================================================================
# GAP-03: RF Pivot Real HTTP Transport & E2E Test Hardening Check
# ======================================================================


def test_gap03_rf_pivot_exercises_real_http_transport_and_e2e_test_uses_mock_rf_server(
    tmp_path: Path,
) -> None:
    e2e_src = (REPO_ROOT / "tests" / "e2e" / "test_v21_tier2_pivots_copilot_tui.py").read_text(
        encoding="utf-8"
    )
    fn_start = e2e_src.index("def test_v21_f13_lazy_unmounted_target_tab_accepts_pivot_cleanly")
    fn_end = e2e_src.index("def test_v21_f14_", fn_start)
    fn_block = e2e_src[fn_start:fn_end]
    assert "mock_rf_server" in fn_block
    assert "RecordedFutureClient(" in fn_block
    assert "client=MagicMock()" not in fn_block

    seen_paths: list[str] = []

    class _StubRFHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:  # noqa: N802
            seen_paths.append(self.path)
            body = json.dumps(
                {
                    "entity": {"id": "ip:198.51.100.10", "name": "198.51.100.10", "type": "IpAddress"},
                    "risk": {"score": 72, "level": 3, "riskString": "3/10", "evidenceDetails": []},
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _StubRFHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    rf_client = RecordedFutureClient(
        api_token="stub-rf-token",
        base_url=f"http://127.0.0.1:{httpd.server_address[1]}",
    )
    app = create_app(
        client=rf_client,
        dry_run=True,
        no_secret_store=True,
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            ok = app.dispatch_pivot(
                PivotPayload(
                    source_tab="tab-splunk-es",
                    target_tab="tab-rf-intel",
                    entity="198.51.100.10",
                    entity_type="ip",
                )
            )
            assert ok is True
            await _wait_until(
                pilot,
                lambda: any("/v2/ip/198.51.100.10" in p for p in seen_paths),
            )

    try:
        asyncio.run(_run())
    finally:
        rf_client.session.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2.0)

    assert any("/v2/ip/198.51.100.10" in p for p in seen_paths)


# ======================================================================
# GAP-04: ModalScreen on_mount() Shutdown Guards
# ======================================================================


def test_gap04_all_modal_screens_have_on_mount_shutdown_guards() -> None:
    modal_files = [
        REPO_ROOT / "soclens" / "tui" / "modals.py",
        REPO_ROOT / "soclens" / "tui" / "screens" / "s1_modals.py",
        REPO_ROOT / "soclens" / "tui" / "screens" / "es_modals.py",
    ]
    checked = 0
    for path in modal_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            is_modal = any(
                (isinstance(b, ast.Name) and b.id == "ModalScreen")
                or (
                    isinstance(b, ast.Subscript)
                    and isinstance(b.value, ast.Name)
                    and b.value.id == "ModalScreen"
                )
                for b in node.bases
            )
            if not is_modal:
                continue
            on_mount = next(
                (
                    fn
                    for fn in node.body
                    if isinstance(fn, ast.FunctionDef) and fn.name == "on_mount"
                ),
                None,
            )
            assert on_mount is not None, f"{path.name}:{node.name} missing on_mount"
            first_stmt = ast.unparse(on_mount.body[0])
            assert "is_running" in first_stmt and "_exit" in first_stmt, (
                f"{path.name}:{node.name}.on_mount missing shutdown guard: {first_stmt}"
            )
            checked += 1
    assert checked >= 25


def test_gap04_pushing_modals_during_exit_does_not_raise_nomatches(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        no_secret_store=True,
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app._exit = True
            modals = [
                ConfirmActionModal(title="Test", message="Confirm?"),
                ContextMenuModal([("a", "Action A")], title="Menu"),
                TimezoneModal(current_tz="UTC"),
                SaveFilterPresetModal(),
                CopyTextModal(title="Copy", text="hello"),
            ]
            for modal in modals:
                app.push_screen(modal)
                await pilot.pause()
            assert app.screen is not None

    asyncio.run(_run())


# ======================================================================
# GAP-05: SettingsPane Dirty-Edit Guard Against Background Hydration
# ======================================================================


def test_gap05_settings_dirty_edit_guard_survives_background_hydration(
    tmp_path: Path,
) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-settings",
        no_secret_store=True,
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(SettingsPane)
            # Clean right after mount
            assert pane._dirty is False

            # Toggling Show Secrets should NOT mark form dirty
            pane.query_one("#settings-show-secrets", Checkbox).value = True
            await pilot.pause()
            assert pane._dirty is False

            # User edits Splunk host, Secret Provider, and Auto-Approve
            splunk_host = pane.query_one("#set-splunk-host", Input)
            splunk_host.value = "https://user-typing-mid-edit.invalid:8089"
            pane.query_one("#set-secret-provider", Select).value = "hashicorp_vault"
            pane.query_one("#set-auto-approve", Checkbox).value = True
            await pilot.pause()
            assert pane._dirty is True

            # Simulate background vault hydration finishing and calling reload_settings()
            set_session_overrides({"rf_api_token": "hydrated-vault-tok"}, vault_hydrated=True)
            app.reload_settings()
            await pilot.pause()

            # Unsaved edits MUST survive while badges refresh!
            assert splunk_host.value == "https://user-typing-mid-edit.invalid:8089"
            assert pane.query_one("#set-secret-provider", Select).value == "hashicorp_vault"
            assert pane.query_one("#set-auto-approve", Checkbox).value is True
            rf_badge = str(pane.query_one("#lbl-rf-api-token", Static).render())
            assert "Session Override" in rf_badge

            # Saving clears _dirty and persists edits cleanly
            await pilot.click("#settings-save-btn")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane._dirty is False
            saved = get_profile_settings()
            assert saved["splunk_host"] == "https://user-typing-mid-edit.invalid:8089"
            assert saved["secret_provider"] == "hashicorp_vault"
            assert saved["soclens_auto_approve"] == "true"

            # Editing again then Reloading resets _dirty and restores saved values
            splunk_host.value = "https://unsaved-discard.invalid:8089"
            await pilot.pause()
            assert pane._dirty is True
            await pilot.click("#settings-reload-btn")
            await pilot.pause()
            assert pane._dirty is False
            assert splunk_host.value == "https://user-typing-mid-edit.invalid:8089"

    asyncio.run(_run())


def test_gap05_settings_reload_refreshes_when_form_is_clean(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-settings",
        no_secret_store=True,
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(SettingsPane)
            assert pane._dirty is False
            save_profile_settings({"splunk_host": "https://disk-updated.invalid:8089"})
            app.reload_settings()
            await pilot.pause()
            assert pane.query_one("#set-splunk-host", Input).value == "https://disk-updated.invalid:8089"
            assert pane._dirty is False

    asyncio.run(_run())


# ======================================================================
# GAP-06: SocLensApp.activate_tab() Logs on_ready Exceptions as ERROR
# ======================================================================


def test_gap06_activate_tab_logs_on_ready_exceptions(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        no_secret_store=True,
        workspace_dir=tmp_path,
    )

    def _boom_lazy(_pane: Any) -> None:
        raise RuntimeError("boom_in_lazy_on_ready")

    def _boom_mounted(_pane: Any) -> None:
        raise RuntimeError("boom_in_mounted_on_ready")

    async def _run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            # 1. Lazy unmounted tab
            assert app.activate_tab("tab-sentinelone", on_ready=_boom_lazy) is True
            await _wait_until(
                pilot,
                lambda: any(
                    e.level == "ERROR" and "boom_in_lazy_on_ready" in e.message
                    for e in app.log_store.snapshot()
                ),
            )
            # 2. Already mounted tab
            assert app.activate_tab("tab-sentinelone", on_ready=_boom_mounted) is True
            await pilot.pause()
            assert any(
                e.level == "ERROR" and "boom_in_mounted_on_ready" in e.message
                for e in app.log_store.snapshot()
            )
            assert app.is_running

    asyncio.run(_run())


# ======================================================================
# GAP-07 & GAP-08: Full 13-Tab 80x24 Admin Layout & Clickability
# ======================================================================


def test_gap07_gap08_80x24_all_13_admin_tabs_zero_unscrollable_x_overflow(
    tmp_path: Path,
) -> None:
    app = create_app(
        client=MagicMock(),
        s1_client=MagicMock(),
        dry_run=True,
        view_mode="admin",
        no_secret_store=True,
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            tabs = app.query_one("#main-tabs", TabbedContent)
            overflows: list[tuple[str, str, int, int]] = []

            for tab_id in ALL_TABS:
                app.activate_tab(tab_id, auto_enable_admin=True)
                await _wait_until(
                    pilot,
                    lambda tid=tab_id: tabs.active == tid
                    and app._get_mounted_pane(tid) is not None,
                )
                await pilot.pause()
                pane = app._get_mounted_pane(tab_id)
                assert pane is not None
                for widget in pane.walk_children():
                    if not widget.display:
                        continue
                    reg = widget.region
                    if reg.width <= 0 or reg.height <= 0:
                        continue
                    if reg.right > 80 or reg.x < 0:
                        can_scroll_x = any(
                            getattr(anc, "allow_horizontal_scroll", False)
                            for anc in widget.ancestors
                        )
                        if not can_scroll_x:
                            overflows.append(
                                (
                                    tab_id,
                                    widget.id or type(widget).__name__,
                                    reg.x,
                                    reg.right,
                                )
                            )

                if tab_id == "tab-splunk-es":
                    col = pane.query_one("#es-structured-filter-collapsible", Collapsible)
                    title_w = col.query_one("CollapsibleTitle")
                    assert title_w.region.right <= 80

            assert overflows == [], f"Unscrollable 80x24 X-overflows: {overflows}"

            # Verify Settings #settings-show-secrets & #settings-clear-btn visible & clickable
            app.activate_tab("tab-settings")
            await pilot.pause()
            settings_pane = app.query_one(SettingsPane)
            show_cb = settings_pane.query_one("#settings-show-secrets", Checkbox)
            clear_btn = settings_pane.query_one("#settings-clear-btn", Button)
            assert 0 <= show_cb.region.x and show_cb.region.right <= 80
            assert 0 <= clear_btn.region.x and clear_btn.region.right <= 80
            await pilot.click("#settings-clear-btn")
            await pilot.pause()
            assert "DRY-RUN" in str(settings_pane.query_one("#settings-status", Static).render())

    asyncio.run(_run())


# ======================================================================
# GAP-09: Splunk ES _build_pivot_payload() Strips "-" Sentinel
# ======================================================================


def test_gap09_splunk_es_pivot_strips_dash_sentinels(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-splunk-es",
        no_secret_store=True,
        workspace_dir=tmp_path,
    )

    async def _run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            es_pane = app.query_one(SplunkESPane)
            row = {
                "event_id": "fnd-dash-test",
                "tenant_id": "1001",
                "entity": "-",
                "risk_object": "-",
                "risk_object_type": "-",
                "src": "-",
                "dest": "-",
                "user": "-",
                "orig_sid": "-",
                "raw": {"sha1": "-", "sha256": "-", "orig_sid": "-"},
                "title": "Dash Sentinel Finding",
            }
            payload = es_pane._build_pivot_payload("tab-rf-intel", row, use_orig_sid=True)
            assert payload.tenant_id == "1001"
            assert payload.entity is None
            assert payload.entity_type is None
            assert payload.src_ip is None
            assert payload.dest_ip is None
            assert payload.username is None
            assert payload.sha1 is None
            assert payload.sha256 is None
            assert payload.hostname is None
            assert payload.orig_sid is None
            assert payload.primary_ioc() is None

            spl, auto_run = build_spl_from_pivot(payload)
            assert auto_run is False
            assert '"-"' not in spl

            # Even a direct PivotPayload containing "-" must be rejected by RF/Research
            bad_payload = PivotPayload(
                source_tab="tab-splunk-es",
                target_tab="tab-rf-intel",
                entity="-",
                src_ip="-",
            )
            assert bad_payload.primary_ioc() is None

            app.activate_tab("tab-rf-intel")
            await _wait_until(pilot, lambda: len(list(app.query(RFIntelPane))) == 1)
            rf_pane = app.query_one(RFIntelPane)
            rf_pane.accept_pivot(bad_payload)
            await pilot.pause()
            assert "no IOC" in str(rf_pane.query_one("#rf-status", Static).render())

            app.activate_tab("tab-research")
            await _wait_until(pilot, lambda: len(list(app.query(ResearchPane))) == 1)
            res_pane = app.query_one(ResearchPane)
            res_pane.accept_pivot(bad_payload)
            await pilot.pause()
            assert "no IOC" in str(res_pane.query_one("#res-status", Static).render())

    asyncio.run(_run())


# ======================================================================
# GAP-10: SplunkESPane._load_notables_worker() Concurrent _loading Guard
# ======================================================================


def test_gap10_splunk_es_loading_flag_sequence_guard(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-splunk-es",
        no_secret_store=True,
        workspace_dir=tmp_path,
    )

    seq1_entered = threading.Event()
    seq1_release = threading.Event()
    seq2_entered = threading.Event()
    seq2_release = threading.Event()
    call_count = 0
    call_lock = threading.Lock()

    class _FakeESClient:
        def __enter__(self) -> _FakeESClient:
            return self

        def __exit__(self, *args: Any) -> None:
            return

        def discover_custom_fields(self) -> list[dict[str, Any]]:
            return []

        def list_users(self, count: int = 100) -> list[dict[str, Any]]:
            return []

        def get_current_user(self) -> str:
            return "analyst"

        def query_findings_hybrid(self, **kwargs: Any) -> dict[str, Any]:
            nonlocal call_count
            with call_lock:
                call_count += 1
                idx = call_count
            if idx == 1:
                seq1_entered.set()
                seq1_release.wait(timeout=5.0)
            else:
                seq2_entered.set()
                seq2_release.wait(timeout=5.0)
            return {"items": [], "source_backend": "mc_v2"}

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            pane = app.query_one(SplunkESPane)
            pane._build_es_client = lambda: _FakeESClient()  # type: ignore[method-assign]

            pane._request_seq = 1
            w1 = pane._load_notables_worker(
                seq=1,
                expected_view="notables",
                earliest="-24h",
                urgency=None,
                status=None,
                search_text=None,
            )
            assert await asyncio.to_thread(seq1_entered.wait, 3.0)
            assert pane._loading is True

            pane._request_seq = 2
            w2 = pane._load_notables_worker(
                seq=2,
                expected_view="notables",
                earliest="-24h",
                urgency=None,
                status=None,
                search_text=None,
            )
            assert await asyncio.to_thread(seq2_entered.wait, 3.0)

            # Finish seq=1 while seq=2 is still running: _loading MUST remain True!
            seq1_release.set()
            for _ in range(80):
                if w1.is_finished:
                    break
                await pilot.pause(0.01)
            assert w1.is_finished
            assert not w2.is_finished
            assert pane._loading is True
            assert pane._is_auto_refresh_paused() is True

            # Finish seq=2: _loading MUST now clear to False
            seq2_release.set()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert w2.is_finished
            assert pane._loading is False

    asyncio.run(_run())
