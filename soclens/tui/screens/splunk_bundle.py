"""Splunk savedsearches.conf validator and air-gapped ZIP bundle builder pane."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from textual import events, on, work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Checkbox, DataTable, Input, Select, Static

from soclens.bundler import create_bundle
from soclens.config import get_splunk_config
from soclens.splunk import SplunkValidator, parse_savedsearches_files
from soclens.tui.filters import SPLUNK_TIME_PRESETS
from soclens.tui.screens.base import (
    BaseSocPane,
    DoubleClickDataTable,
    extract_table_row_text,
)

_SPLUNK_COLUMN_SPECS: tuple[tuple[str, float, int], ...] = (
    ("stanza", 0.24, 16),
    ("file", 0.18, 14),
    ("status", 0.12, 10),
    ("triggers", 0.10, 8),
    ("error", 0.36, 20),
)


class SplunkBundlePane(BaseSocPane):
    """Splunk Enterprise Security saved-search validation & air-gapped deployment bundler."""

    STATUS_ID = "splunk-status"
    LOG_ID = ""
    LOG_SOURCE = "splunk"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tables_ready = False
        self._last_searches: list[dict[str, Any]] = []
        self._last_synced_splunk_app = "SplunkEnterpriseSecuritySuite"
        self._syncing_time: bool = False

    def compose(self) -> ComposeResult:
        yield Static("Splunk ES Validation & Air-Gapped Bundle", classes="pane-title")
        yield Static(
            "Validate savedsearches.conf or package an offline ZIP bundle.",
            id="splunk-status",
            classes="status-bar",
            markup=False,
        )

        with Horizontal(classes="action-row filter-bar"):
            yield Input(
                value="savedsearches.conf",
                placeholder="Saved searches conf path/glob",
                id="splunk-input",
                compact=True,
            )
            yield Input(
                value="",
                placeholder="Splunk host override (optional)",
                id="splunk-host",
                compact=True,
            )
            yield Input(
                value="SplunkEnterpriseSecuritySuite",
                placeholder="Splunk ES app",
                id="splunk-app",
                compact=True,
            )

        with Horizontal(id="splunk-bundle-toolbar", classes="action-row toolbar-row"):
            yield Select(
                list(SPLUNK_TIME_PRESETS),
                allow_blank=False,
                value="-7d",
                id="splunk-bundle-time-preset",
                compact=True,
            )
            yield Input(value="-7d", placeholder="Earliest", id="splunk-earliest", compact=True)
            yield Input(value="now", placeholder="Latest", id="splunk-latest", compact=True)
            yield Checkbox("Dry Run", value=False, id="splunk-dry-checkbox", compact=True)
            yield Button("Check Connection", id="splunk-check-btn", compact=True)
            yield Button(
                "Validate Searches",
                id="splunk-validate-btn",
                variant="primary",
                compact=True,
            )

        yield DoubleClickDataTable(id="splunk-results-table")

        yield Static("Air-Gapped Deployment Bundler", classes="section-label")
        with Horizontal(classes="action-row toolbar-row"):
            yield Input(
                value="",
                placeholder="Bundle output ZIP path (optional)",
                id="bundle-output-input",
                compact=True,
            )
            yield Select(
                [
                    ("Current Platform", "current"),
                    ("All Platforms (Offline Wheelhouse)", "all"),
                    ("Pure Python (Cross-OS)", "pure"),
                    ("Windows x64 (win_amd64)", "win_amd64"),
                    ("Linux x64 (manylinux2014_x86_64)", "manylinux2014_x86_64"),
                    ("macOS ARM64 (macosx_arm64)", "macosx_arm64"),
                ],
                allow_blank=False,
                value="current",
                id="bundle-platform-select",
                compact=True,
            )
            yield Checkbox("Wheelhouse", value=False, id="bundle-wheelhouse-cb", compact=True)
            yield Button("Build Bundle", id="bundle-build-btn", compact=True)

    def on_mount(self) -> None:
        table = self.query_one("#splunk-results-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("Stanza", key="stanza")
        table.add_column("File", key="file")
        table.add_column("Status", key="status")
        table.add_column("Triggers", key="triggers")
        table.add_column("Error", key="error")
        if self.effective_dry_run:
            self.query_one("#splunk-dry-checkbox", Checkbox).value = True
        wh_dir = Path(self.workspace_dir) / "wheelhouse"
        if wh_dir.is_dir() and any(wh_dir.glob("*.whl")):
            self.query_one("#bundle-wheelhouse-cb", Checkbox).value = True
        default_app = get_splunk_config(required=False).app
        self._last_synced_splunk_app = default_app
        self.query_one("#splunk-app", Input).value = default_app
        self._tables_ready = True
        self.call_after_refresh(self._fit_tables)

    def on_settings_updated(self) -> None:
        try:
            app_input = self.query_one("#splunk-app", Input)
            new_app = get_splunk_config(required=False).app
            if not app_input.value.strip() or app_input.value.strip() == self._last_synced_splunk_app:
                app_input.value = new_app
            self._last_synced_splunk_app = new_app
        except Exception:
            pass

    def on_resize(self) -> None:
        if self._tables_ready:
            self.call_after_refresh(self._fit_tables)

    def on_tab_activated(self) -> None:
        if self._tables_ready:
            self.call_after_refresh(self._fit_tables)

    def _fit_tables(self) -> None:
        if self.is_app_shutting_down() or not self._tables_ready:
            return
        try:
            self.fit_table_columns(
                self.query_one("#splunk-results-table", DataTable),
                _SPLUNK_COLUMN_SPECS,
            )
        except Exception:
            pass

    @on(Select.Changed, "#splunk-bundle-time-preset")
    def handle_time_preset_changed(self, event: Select.Changed) -> None:
        if self._syncing_time or event.value is Select.BLANK:
            return
        val = str(event.value or "-7d")
        if val != "custom":
            self._syncing_time = True
            try:
                self.query_one("#splunk-earliest", Input).value = val
                self.query_one("#splunk-latest", Input).value = "now"
            finally:
                self._syncing_time = False

    @on(Input.Changed, "#splunk-earliest")
    @on(Input.Changed, "#splunk-latest")
    def handle_time_input_changed(self) -> None:
        if self._syncing_time:
            return
        earliest = self.query_one("#splunk-earliest", Input).value.strip()
        latest = self.query_one("#splunk-latest", Input).value.strip()
        preset_vals = {val for _, val in SPLUNK_TIME_PRESETS if val != "custom"}
        target = earliest if (earliest in preset_vals and latest == "now") else "custom"
        try:
            sel = self.query_one("#splunk-bundle-time-preset", Select)
            if str(sel.value) != target:
                self._syncing_time = True
                try:
                    sel.value = target
                finally:
                    self._syncing_time = False
        except Exception:
            pass

    @on(Button.Pressed, "#splunk-check-btn")
    def handle_check_connection(self) -> None:
        host_ov = self.query_one("#splunk-host", Input).value.strip() or None
        app_ov = self.query_one("#splunk-app", Input).value.strip() or None
        self._check_connection_worker(host_ov, app_ov)

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        event.stop()
        self._open_splunk_menu(origin=(event.screen_x, event.screen_y))

    @on(DoubleClickDataTable.RowRightClicked, "#splunk-results-table")
    def handle_results_right_click(self, event: DoubleClickDataTable.RowRightClicked) -> None:
        event.stop()
        self._open_splunk_menu(
            origin=(event.screen_x, event.screen_y),
            row_index=event.row_index,
        )

    def _selected_stanza_or_row_text(self, row_index: int | None = None) -> tuple[str, str]:
        """Return ``(copy_text, modal_title)`` for the selected Splunk stanza or table row."""
        table = self.query_one("#splunk-results-table", DataTable)
        idx = table.cursor_row if row_index is None else row_index
        if idx is not None and 0 <= idx < len(self._last_searches):
            entry = self._last_searches[idx]
            stanza_name = str(entry.get("stanza") or "Saved Search")
            search_str = str(entry.get("search") or "").strip()
            if search_str:
                text = f"[{stanza_name}]\nsearch = {search_str}"
                return text, f"Splunk Stanza - {stanza_name}"
        row_text = extract_table_row_text(table, row_index=row_index)
        return row_text, "Splunk Validation Row"

    def _open_splunk_menu(
        self,
        *,
        origin: tuple[int, int],
        row_index: int | None = None,
    ) -> None:
        items = [
            ("copy_stanza_row", "Copy Selected Stanza / Row"),
            ("open_copy_view", "Open Copyable View"),
            ("validate", "Validate Searches"),
            ("check_splunk", "Check Splunk Connection"),
            ("build_bundle", "Build Air-Gapped Bundle"),
            ("open_logs", "Open Logs Tab"),
        ]

        def _on_select(action_id: str) -> None:
            if action_id == "copy_stanza_row":
                text, _title = self._selected_stanza_or_row_text(row_index=row_index)
                self.copy_to_clipboard(text, label="Splunk Stanza / Row")
            elif action_id == "open_copy_view":
                text, title = self._selected_stanza_or_row_text(row_index=row_index)
                self.open_copy_modal(text, title=title)
            elif action_id == "validate":
                self.handle_validate()
            elif action_id == "check_splunk":
                self.handle_check_connection()
            elif action_id == "build_bundle":
                self.handle_build_bundle()
            elif action_id == "open_logs":
                open_fn = getattr(self.app, "open_logs_tab", None)
                if callable(open_fn):
                    open_fn(source="splunk")

        self.open_context_menu(
            items,
            title="Splunk & Bundle",
            origin=origin,
            on_select=_on_select,
        )

    @work(thread=True, exit_on_error=False)
    def _check_connection_worker(self, host_ov: str | None, app_ov: str | None) -> None:
        try:
            cfg = get_splunk_config(host=host_ov, app=app_ov, required=True)
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
            msg = (
                f"Splunk reachable: {cfg.host}"
                if ok
                else f"Splunk check failed or unauthorized: {cfg.host}"
            )
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Splunk Connection", exc)

    @on(Button.Pressed, "#splunk-validate-btn")
    def handle_validate(self) -> None:
        raw_input = self.query_one("#splunk-input", Input).value.strip() or "savedsearches.conf"
        host_ov = self.query_one("#splunk-host", Input).value.strip() or None
        app_ov = self.query_one("#splunk-app", Input).value.strip() or None
        earliest = self.query_one("#splunk-earliest", Input).value.strip() or "-7d"
        latest = self.query_one("#splunk-latest", Input).value.strip() or "now"
        dry_run = bool(
            self.effective_dry_run or self.query_one("#splunk-dry-checkbox", Checkbox).value
        )
        self._validate_worker(raw_input, host_ov, app_ov, earliest, latest, dry_run)

    @work(thread=True, exit_on_error=False)
    def _validate_worker(
        self,
        raw_input: str,
        host_ov: str | None,
        app_ov: str | None,
        earliest: str,
        latest: str,
        dry_run: bool,
    ) -> None:
        try:
            with self.log_scope("splunk"):
                input_path = Path(raw_input).expanduser()
                resolved_pattern = str(
                    input_path if input_path.is_absolute() else self.workspace_dir / raw_input
                )
                searches = parse_savedsearches_files(resolved_pattern)
                self._last_searches = list(searches)
                if not searches:
                    self.set_status(f"No saved searches found matching: {raw_input}")
                    return

                if dry_run:

                    def _populate_dry() -> None:
                        table = self.query_one("#splunk-results-table", DataTable)
                        table.clear()
                        for item in searches:
                            table.add_row(str(item["stanza"]), str(item["file"]), "DRY-RUN", "-", "")
                        self.call_after_refresh(self._fit_tables)

                    self.run_on_ui(_populate_dry)
                    msg = f"[DRY-RUN] Parsed {len(searches)} search stanza(s) cleanly."
                    self.set_status(msg)
                    self.append_log(msg)
                    return

                cfg = get_splunk_config(host=host_ov, app=app_ov, required=True)
                with SplunkValidator(
                    host=cfg.host,
                    token=cfg.token,
                    username=cfg.username,
                    password=cfg.password,
                    app=cfg.app,
                    verify_ssl=cfg.verify_ssl,
                    request_timeout=3.0,
                    max_retries=0,
                    backoff_base=0.05,
                ) as validator:
                    if not validator.check_connection():
                        self.set_status(f"Splunk connection failed at {cfg.host}")
                        return
                    results = [
                        validator.run_single_search(s, earliest=earliest, latest=latest, timeout=60)
                        for s in searches
                    ]

            def _populate() -> None:
                table = self.query_one("#splunk-results-table", DataTable)
                table.clear()
                for res in results:
                    table.add_row(
                        str(res.get("stanza") or ""),
                        str(res.get("file") or ""),
                        str(res.get("status") or ""),
                        str(res.get("trigger_count", 0)),
                        str(res.get("error_message") or ""),
                    )
                self.call_after_refresh(self._fit_tables)

            self.run_on_ui(_populate)
            ok_cnt = sum(1 for r in results if r.get("status") == "success")
            msg = f"Validation complete: {ok_cnt}/{len(results)} succeeded."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Splunk Validation", exc)

    @on(Button.Pressed, "#bundle-build-btn")
    def handle_build_bundle(self) -> None:
        out_raw = self.query_one("#bundle-output-input", Input).value.strip() or None
        plat_val = str(self.query_one("#bundle-platform-select", Select).value)
        target_plat = None if plat_val == "current" else plat_val
        wheelhouse = bool(self.query_one("#bundle-wheelhouse-cb", Checkbox).value)

        if self.effective_dry_run:
            msg = (
                f"[DRY-RUN] Would build bundle from {self.workspace_dir} "
                f"(platform={plat_val}, wheelhouse={wheelhouse})."
            )
            self.set_status(msg)
            self.append_log(msg)
            return

        self._bundle_worker(out_raw, target_plat, wheelhouse)

    @work(thread=True, exit_on_error=False)
    def _bundle_worker(
        self,
        out_raw: str | None,
        target_plat: str | None,
        wheelhouse: bool,
    ) -> None:
        try:
            out_path: Path | None = None
            if out_raw:
                candidate = Path(out_raw).expanduser()
                out_path = candidate if candidate.is_absolute() else self.workspace_dir / candidate
            with self.log_scope("splunk"):
                bundle_zip = create_bundle(
                    self.workspace_dir,
                    output_path=out_path,
                    wheelhouse=wheelhouse,
                    target_platform=target_plat,
                )
            msg = f"Air-gapped bundle created: {bundle_zip}"
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Bundle Created")
        except Exception as exc:
            self.report_error("Bundle Build", exc)
