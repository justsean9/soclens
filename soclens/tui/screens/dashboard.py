"""Dashboard, environment status, RF API coverage catalog, and traceId error viewer."""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any

from textual import events, on, work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Select, Static, TabbedContent

from soclens.config import (
    IMAGE_VIEWER_OS,
    format_image_viewer_status,
    format_ssl_verify_status,
    get_image_viewer_mode,
    get_local_llm_config,
    get_proxy_summary,
    get_rf_sandbox_token,
    get_rf_token,
    get_rf_verify_ssl,
    get_sentinelone_config,
    get_splunk_config,
)
from soclens.settings import get_setting_with_source, get_settings_storage_info
from soclens.splunk import SplunkValidator
from soclens.tui.filters import TIMEFRAME_OPTIONS, timestamp_matches_timeframe
from soclens.tui.image_render import format_graphics_protocol_status
from soclens.tui.screens.base import BaseSocPane, DoubleClickDataTable

_SPLIT_HORIZONTAL_MIN_WIDTH = 110
_DASH_ERROR_TIMEFRAMES: tuple[tuple[str, str], ...] = TIMEFRAME_OPTIONS[:7]

_API_SURFACES: tuple[tuple[str, str, str, str], ...] = (
    ("Lists & Watchlists", "/list/*", "X-RFToken", "Watchlists tab / watchlist CLI"),
    ("Entity Match & Lookup", "/entity-match/*", "X-RFToken", "RF Intel & Research / rf entity-match"),
    ("Connect API v2 & Extensions", "/v2/{type}/*", "X-RFToken", "RF Intel & Research / rf lookup,extension"),
    ("SOAR API v3", "/soar/v3/*", "X-RFToken", "RF Intel & Research / rf enrich,triage"),
    ("Detection Rules", "/detection-rule/*", "X-RFToken", "Sigma & Research tabs / research rules"),
    ("Playbook Alerts", "/playbook-alert/*", "X-RFToken", "RF Intel & Research / rf playbook-alerts"),
    ("Alerts v3 & v2", "/alert/{v3,v2/rule,v2/update}", "X-RFToken", "RF Intel & Research / rf alerts"),
    ("Cases", "/case/*", "X-RFToken", "RF Intel tab / rf cases"),
    ("Sandbox v0", "sandbox.recordedfuture.com/api/v0", "Authorization: Bearer", "RF Intel & Research / research sandbox"),
    ("Links Graph", "/links/*", "X-RFToken", "Research tab / research links"),
    ("Analyst Notes", "/analyst-note/*", "X-RFToken", "Research tab / research notes"),
    ("Threat Maps & Actors", "/threat/*", "X-RFToken", "Research tab / research actors"),
    ("Malware Intelligence", "/malware-intelligence/v1/*", "X-RFToken", "Research tab / research malware"),
    ("Risk History & Active Rules", "/risk/*", "X-RFToken", "Research tab / research risk"),
    ("Identity Intelligence", "/identity/*", "X-RFToken", "Research tab / research identity"),
    ("Collective Insights", "/collective-insights/*", "X-RFToken", "Research tab / research collective-insights"),
    ("Fusion v3", "/fusion/v3/*", "X-RFToken", "Research tab / research fusion"),
    ("Autonomous Threat Ops (ATO)", "/autonomous-threat-operations/v1/*", "X-RFToken", "Research tab / research ato"),
    ("STIX / TAXII 2.1", "/taxii2/*", "Basic :token", "Research tab / research taxii2"),
    ("Attack Surface Intel (ASI)", "api.securitytrails.com/v2/*", "apikey", "Research tab / research asi"),
    ("Payment Fraud Intel (PFI)", "pfi.regemini.com/api/v1/*", "X-RFToken", "Research tab / research pfi"),
    ("RiskRecon", "api.riskrecon.com/v1/*", "Authorization: Bearer", "Research tab / research riskrecon"),
)

_ERROR_COLUMN_SPECS: tuple[tuple[str, float, int], ...] = (
    ("timestamp", 0.18, 16),
    ("status", 0.08, 6),
    ("endpoint", 0.22, 16),
    ("trace_id", 0.20, 14),
    ("message", 0.32, 20),
)
_API_COLUMN_SPECS: tuple[tuple[str, float, int], ...] = (
    ("family", 0.20, 16),
    ("endpoint", 0.28, 20),
    ("auth", 0.18, 14),
    ("surface", 0.34, 22),
)


class DashboardPane(BaseSocPane):
    """Diagnostics, credential status, API surface overview, and traceId JSONL log viewer."""

    STATUS_ID = "dash-status"
    LOG_ID = ""
    LOG_SOURCE = "dashboard"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tables_ready = False
        self._all_error_rows: list[tuple[str, str, str, str, str]] = []
        self._error_timeframe: str = "any"
        self._error_query: str = ""

    def compose(self) -> ComposeResult:
        yield Static("Dashboard & Diagnostics", classes="pane-title")
        yield Static(
            "Initializing diagnostics...",
            id="dash-status",
            classes="status-bar",
            markup=False,
        )
        with Horizontal(id="dash-toolbar", classes="action-row toolbar-row"):
            yield Button(
                "Refresh Diagnostics",
                id="dash-refresh-btn",
                variant="primary",
                compact=True,
            )
            yield Button("Check Splunk Connection", id="dash-splunk-btn", compact=True)
            yield Button("Insecure SSL: OFF", id="dash-ssl-btn", compact=True)
            yield Button("Image Viewer: TUI", id="dash-image-viewer-btn", compact=True)
            yield Button("Settings", id="dash-settings-btn", compact=True)
        yield Static("", id="dash-env-summary", classes="info-box", markup=False)
        with Container(id="dash-workspace", classes="split-workspace"):
            with Vertical(id="dash-errors-pane", classes="table-pane"):
                yield Static(
                    "Recent API Errors (logs/rf_api_errors.jsonl)",
                    classes="section-label",
                )
                with Horizontal(id="dash-error-filter-bar", classes="action-row filter-bar"):
                    yield Select(
                        list(_DASH_ERROR_TIMEFRAMES),
                        allow_blank=False,
                        value="any",
                        id="dash-error-timeframe",
                        compact=True,
                    )
                    yield Input(
                        placeholder="Filter traceId, status, or message...",
                        id="dash-error-filter",
                        compact=True,
                    )
                yield DoubleClickDataTable(id="dash-errors-table")
            with Vertical(id="dash-apis-pane", classes="table-pane"):
                yield Static(
                    "Documented Recorded Future API Surfaces (docs/RF_API_REVIEW.md)",
                    classes="section-label",
                )
                yield DoubleClickDataTable(id="dash-apis-table")

    def on_mount(self) -> None:
        err_table = self.query_one("#dash-errors-table", DataTable)
        err_table.cursor_type = "row"
        err_table.zebra_stripes = True
        err_table.add_column("Timestamp", key="timestamp")
        err_table.add_column("Status", key="status")
        err_table.add_column("Endpoint", key="endpoint")
        err_table.add_column("Trace ID", key="trace_id")
        err_table.add_column("Message", key="message")

        api_table = self.query_one("#dash-apis-table", DataTable)
        api_table.cursor_type = "row"
        api_table.zebra_stripes = True
        api_table.add_column("API Family", key="family")
        api_table.add_column("Endpoint Base", key="endpoint")
        api_table.add_column("Auth Header", key="auth")
        api_table.add_column("Toolkit Surface", key="surface")
        for row in _API_SURFACES:
            api_table.add_row(*row)

        self._tables_ready = True
        self._sync_ssl_button()
        self._sync_image_viewer_button()
        self._update_split_layout()
        self._load_local_diagnostics()
        self.call_after_refresh(self._fit_tables)

    def _effective_image_viewer_mode(self) -> str:
        app_mode = getattr(self.app, "image_viewer_mode", None)
        if isinstance(app_mode, str) and app_mode:
            return app_mode
        return get_image_viewer_mode(workspace_dir=self.workspace_dir)

    def _sync_image_viewer_button(self) -> None:
        try:
            btn = self.query_one("#dash-image-viewer-btn", Button)
        except Exception:
            return
        if self._effective_image_viewer_mode() == IMAGE_VIEWER_OS:
            btn.label = "Image Viewer: OS"
            btn.variant = "success"
        else:
            btn.label = "Image Viewer: TUI"
            btn.variant = "default"

    def sync_image_viewer_state(self) -> None:
        """Refresh Dashboard image viewer button and summary text."""
        self._sync_image_viewer_button()
        if self._tables_ready:
            self._load_local_diagnostics()

    def _effective_verify_ssl(self) -> bool | str:
        app_fn = getattr(self.app, "get_effective_verify_ssl", None)
        if callable(app_fn):
            res = app_fn()
            if isinstance(res, (bool, str)):
                return res
        client_verify = getattr(self.client, "verify_ssl", None)
        if isinstance(client_verify, (bool, str)):
            return client_verify
        return get_rf_verify_ssl()

    def _sync_ssl_button(self) -> None:
        try:
            btn = self.query_one("#dash-ssl-btn", Button)
        except Exception:
            return
        if self._effective_verify_ssl() is False:
            btn.label = "Insecure SSL: ON"
            btn.variant = "warning"
        else:
            btn.label = "Insecure SSL: OFF"
            btn.variant = "default"

    def _update_split_layout(self) -> None:
        try:
            workspace = self.query_one("#dash-workspace", Container)
            width = int(getattr(self.app.size, "width", 120) or 120)
            workspace.set_class(width >= _SPLIT_HORIZONTAL_MIN_WIDTH, "split-horizontal")
        except Exception:
            pass

    def on_resize(self) -> None:
        if self._tables_ready:
            self._update_split_layout()
            self.call_after_refresh(self._fit_tables)

    def on_tab_activated(self) -> None:
        if self._tables_ready:
            self._update_split_layout()
            self.call_after_refresh(self._fit_tables)

    def on_settings_updated(self) -> None:
        self._sync_ssl_button()
        self._load_local_diagnostics()

    def _fit_tables(self) -> None:
        if self.is_app_shutting_down() or not self._tables_ready:
            return
        try:
            self.fit_table_columns(
                self.query_one("#dash-errors-table", DataTable),
                _ERROR_COLUMN_SPECS,
            )
            self.fit_table_columns(
                self.query_one("#dash-apis-table", DataTable),
                _API_COLUMN_SPECS,
            )
        except Exception:
            pass

    def _collect_local_snapshot(self) -> tuple[str, list[tuple[str, str, str, str, str]]]:
        ws = self.workspace_dir
        storage_info = get_settings_storage_info()
        _, rf_src = get_setting_with_source("rf_api_token")
        rf_core = (
            f"Set ({rf_src})"
            if get_rf_token(required=False)
            else "Missing ([0] Settings)"
        )
        rf_sandbox = "Set" if get_rf_sandbox_token(required=False) else "Missing"
        splunk_cfg = get_splunk_config(required=False)
        splunk_auth = (
            "Configured"
            if splunk_cfg.has_auth
            else "Missing ([0] Settings)"
        )
        s1_cfg = get_sentinelone_config(required=False)
        s1_status = (
            f"Configured ({s1_cfg.console_url})"
            if s1_cfg.has_auth
            else "Missing ([0] Settings)"
        )
        try:
            llm_cfg = get_local_llm_config()
            llm_summary = (
                f"{llm_cfg.provider} ({llm_cfg.base_url}) | "
                f"Model: {llm_cfg.model or 'Not set'}"
            )
        except Exception as exc:
            llm_summary = f"Invalid config ({exc})"
        mode = "DRY-RUN" if self.effective_dry_run else "ACTIVE"
        try:
            view_label = "Admin" if bool(getattr(self.app, "is_admin_view", False)) else "User"
        except Exception:
            view_label = "User"
        wh_dir = ws / "wheelhouse"
        wh_count = len(list(wh_dir.glob("*.whl"))) if wh_dir.is_dir() else 0
        wh_status = f"Ready ({wh_count} wheels)" if wh_count > 0 else "Not bundled"
        try:
            app_ref = self.app
            is_headless = bool(getattr(app_ref, "is_headless", False))
        except Exception:
            app_ref = None
            is_headless = False

        summary = (
            f"Platform: {platform.system()} ({platform.machine()}) | Py {platform.python_version()} | "
            f"Mode: {mode} ({view_label}) | Profile: {storage_info['active_profile']}\n"
            f"Workspace: {ws} | Settings: {storage_info['path']}\n"
            f"RF Core: {rf_core} | Sandbox: {rf_sandbox} | Wheelhouse: {wh_status}\n"
            f"RF/Web SSL Verify: {format_ssl_verify_status(self._effective_verify_ssl())} | "
            f"Proxy: {get_proxy_summary()}\n"
            f"Splunk: {splunk_cfg.host} (App: {splunk_cfg.app}) | Auth: {splunk_auth}\n"
            f"SentinelOne EDR: {s1_status} | Local LLM: {llm_summary}\n"
            f"Image Viewer: {format_image_viewer_status(self._effective_image_viewer_mode())} | "
            f"Graphics: {format_graphics_protocol_status(is_headless=is_headless, app=app_ref)}"
        )

        error_rows: list[tuple[str, str, str, str, str]] = []
        jsonl_path = ws / "logs" / "rf_api_errors.jsonl"
        if jsonl_path.is_file():
            try:
                lines = [
                    ln for ln in jsonl_path.read_text(encoding="utf-8").splitlines() if ln.strip()
                ]
                for raw in lines[-25:][::-1]:
                    entry: dict[str, Any] = json.loads(raw)
                    error_rows.append(
                        (
                            str(entry.get("timestamp") or ""),
                            str(entry.get("status_code") or ""),
                            str(entry.get("endpoint") or ""),
                            str(entry.get("trace_id") or entry.get("traceId") or ""),
                            str(entry.get("message") or "")[:90],
                        )
                    )
            except (OSError, ValueError) as exc:
                error_rows.append(("parse-error", "", str(jsonl_path), "", str(exc)))

        return summary, error_rows

    def _render_errors_table(self) -> None:
        if not self._tables_ready:
            return
        err_table = self.query_one("#dash-errors-table", DataTable)
        err_table.clear()
        filtered: list[tuple[str, str, str, str, str]] = []
        for row in self._all_error_rows:
            ts, status, endpoint, trace_id, message = row
            if self._error_timeframe != "any":
                if not timestamp_matches_timeframe(ts, self._error_timeframe):
                    continue
            if self._error_query:
                haystack = f"{ts} {status} {endpoint} {trace_id} {message}".lower()
                if self._error_query not in haystack:
                    continue
            filtered.append(row)

        if filtered:
            for row in filtered:
                err_table.add_row(*row)
        elif self._all_error_rows:
            err_table.add_row("-", "-", "-", "-", "No API errors match the current filter.")
        else:
            err_table.add_row("-", "-", "-", "-", "No recorded API errors in workspace.")
        self.call_after_refresh(self._fit_tables)

    @on(Select.Changed, "#dash-error-timeframe")
    def handle_error_timeframe_changed(self, event: Select.Changed) -> None:
        if isinstance(event.value, str) and event.value:
            self._error_timeframe = event.value
            self._render_errors_table()

    @on(Input.Changed, "#dash-error-filter")
    def handle_error_filter_changed(self, event: Input.Changed) -> None:
        self._error_query = event.value.strip().lower()
        self._render_errors_table()

    def _apply_snapshot(
        self, summary: str, error_rows: list[tuple[str, str, str, str, str]]
    ) -> None:
        self.query_one("#dash-env-summary", Static).update(summary)
        self._sync_ssl_button()
        self._sync_image_viewer_button()
        self._all_error_rows = list(error_rows)
        self._render_errors_table()

    def _load_local_diagnostics(self) -> None:
        summary, rows = self._collect_local_snapshot()
        self._apply_snapshot(summary, rows)
        self.set_status(f"Diagnostics loaded for workspace: {Path(self.workspace_dir)}")

    @on(Button.Pressed, "#dash-refresh-btn")
    def handle_refresh(self) -> None:
        self._refresh_diagnostics_worker()

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        event.stop()
        self._open_dashboard_menu(row_summary=None, origin=(event.screen_x, event.screen_y))

    @on(DoubleClickDataTable.RowRightClicked, "#dash-errors-table")
    @on(DoubleClickDataTable.RowRightClicked, "#dash-apis-table")
    def handle_table_right_click(self, event: DoubleClickDataTable.RowRightClicked) -> None:
        event.stop()
        row_summary: str | None = None
        if event.row_key is not None:
            try:
                row = event.data_table.get_row(event.row_key)
                if row:
                    row_summary = " | ".join(str(cell) for cell in row)
            except Exception:
                row_summary = None
        self._open_dashboard_menu(
            row_summary=row_summary, origin=(event.screen_x, event.screen_y)
        )

    def _open_dashboard_menu(
        self, *, row_summary: str | None, origin: tuple[int, int]
    ) -> None:
        items: list[tuple[str, str]] = []
        if row_summary:
            items.append(("log_row", "Log Selected Row Details"))
        items.extend(
            [
                ("refresh_diag", "Refresh Diagnostics"),
                ("check_splunk", "Check Splunk Connection"),
                ("toggle_ssl", "Toggle Insecure SSL (Proxy Mode)"),
                ("toggle_image_viewer", "Toggle Default Image Viewer (OS / TUI)"),
                ("open_watchlists", "Open Watchlists Tab"),
                ("open_research", "Open Research Tab"),
                ("open_logs", "Open Logs Tab"),
                ("open_settings", "Open Settings"),
            ]
        )

        def _on_select(action_id: str) -> None:
            if action_id == "log_row" and row_summary:
                self.append_log(row_summary)
            elif action_id == "refresh_diag":
                self.handle_refresh()
            elif action_id == "check_splunk":
                self.handle_check_splunk()
            elif action_id == "toggle_ssl":
                self.handle_toggle_insecure_ssl()
            elif action_id == "toggle_image_viewer":
                self.handle_toggle_image_viewer()
            elif action_id == "open_watchlists":
                self.app.query_one("#main-tabs", TabbedContent).active = "tab-watchlists"
            elif action_id == "open_research":
                self.app.query_one("#main-tabs", TabbedContent).active = "tab-research"
            elif action_id == "open_logs":
                open_fn = getattr(self.app, "open_logs_tab", None)
                if callable(open_fn):
                    open_fn()
            elif action_id == "open_settings":
                self.handle_open_settings()

        self.open_context_menu(
            items,
            title="Dashboard",
            origin=origin,
            on_select=_on_select,
        )

    @work(thread=True, exit_on_error=False)
    def _refresh_diagnostics_worker(self) -> None:
        try:
            summary, rows = self._collect_local_snapshot()
            self.run_on_ui(self._apply_snapshot, summary, rows)
            msg = f"Diagnostics refreshed ({len(rows)} recent API error record(s))."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Dashboard Refresh", exc)

    @on(Button.Pressed, "#dash-image-viewer-btn")
    def handle_toggle_image_viewer(self) -> None:
        toggle_fn = getattr(self.app, "toggle_image_viewer_mode", None)
        if callable(toggle_fn):
            resolved = toggle_fn()
        else:
            resolved = IMAGE_VIEWER_OS
        label = format_image_viewer_status(str(resolved))
        msg = f"Default image viewer updated to {label}."
        self.set_status(msg)
        self.append_log(msg)

    @on(Button.Pressed, "#dash-splunk-btn")
    def handle_check_splunk(self) -> None:
        self._check_splunk_worker()

    @on(Button.Pressed, "#dash-settings-btn")
    def handle_open_settings(self) -> None:
        open_fn = getattr(self.app, "open_settings_tab", None)
        if callable(open_fn):
            open_fn()
        else:
            self.app.query_one("#main-tabs", TabbedContent).active = "tab-settings"

    @on(Button.Pressed, "#dash-ssl-btn")
    def handle_toggle_insecure_ssl(self) -> None:
        currently_insecure = self._effective_verify_ssl() is False
        new_insecure = not currently_insecure
        set_fn = getattr(self.app, "set_insecure_ssl", None)
        if callable(set_fn):
            resolved = set_fn(new_insecure)
        else:
            resolved = False if new_insecure else True
        self._load_local_diagnostics()
        state_str = (
            "ENABLED (Insecure Proxy Mode)"
            if resolved is False
            else "DISABLED (SSL Verified)"
        )
        msg = f"Insecure SSL verification {state_str}."
        self.set_status(msg)
        self.append_log(msg, level="WARNING" if resolved is False else "INFO")
        self.notify_user(
            msg,
            title="SSL Verification",
            severity="warning" if resolved is False else "information",
        )

    @work(thread=True, exit_on_error=False)
    def _check_splunk_worker(self) -> None:
        try:
            cfg = get_splunk_config(required=True)
            with self.log_scope("splunk"):
                with SplunkValidator(
                    host=cfg.host,
                    token=cfg.token,
                    username=cfg.username,
                    password=cfg.password,
                    app=cfg.app,
                    verify_ssl=cfg.verify_ssl,
                    request_timeout=2.0,
                    max_retries=0,
                    backoff_base=0.05,
                ) as validator:
                    ok = validator.check_connection()
            if ok:
                msg = f"Splunk API connected cleanly: {cfg.host} (app={cfg.app})"
                self.set_status(msg)
                self.append_log(msg)
                self.notify_user(msg, title="Splunk Connected")
            else:
                msg = f"Splunk API connection failed or unauthorized (401/unreachable): {cfg.host}"
                self.set_status(msg)
                self.append_log(msg)
                self.notify_user(msg, title="Splunk Connection Failed", severity="warning")
        except Exception as exc:
            self.report_error("Splunk Connection Check", exc)
