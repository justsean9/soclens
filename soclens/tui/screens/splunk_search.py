"""Interactive Splunk Search workbench pane with dynamic results table, pagination, and export."""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual import events, on, work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, RichLog, Select, Static, TextArea

from soclens.config import get_splunk_config
from soclens.splunk import SplunkClient, export_results_csv, export_results_json
from soclens.splunk_rf_enrichment import SplunkRFEnricher
from soclens.tui.filters import SPLUNK_TIME_PRESETS
from soclens.tui.pivot import PivotPayload, build_spl_from_pivot, make_pivot_text
from soclens.tui.s1_formatters import format_s1_value as _format_human_value
from soclens.tui.s1_formatters import pretty_s1_label as _pretty_field_label
from soclens.tui.screens.base import BaseSocPane, DoubleClickDataTable, SelectableRichLog

_TIME_PRESETS: list[tuple[str, str]] = list(SPLUNK_TIME_PRESETS)

_MAX_TABLE_COLUMNS = 12
_MAX_CELL_LEN = 80

_RF_ENRICHMENT_KEYS: frozenset[str] = frozenset(
    {
        "rf_max_risk_score",
        "rf_criticality_label",
        "rf_top_ioc",
        "rf_top_field",
        "rf_rules_triggered",
        "rf_evidence_summary",
        "rf_observables",
    }
)


def _clean_cell(value: Any, max_len: int = _MAX_CELL_LEN) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        text = ", ".join(str(v) for v in value)
    elif isinstance(value, dict):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value)
    text = " ".join(text.splitlines()).strip()
    if len(text) > max_len:
        return f"{text[: max_len - 1]}…"
    return text


def _order_display_fields(fields: list[str], rows: list[dict[str, Any]]) -> list[str]:
    """Select ordered display columns for the dynamic results table."""
    candidates = list(fields)
    if not candidates:
        seen: set[str] = set()
        for row in rows:
            for key in row:
                key_str = str(key)
                if key_str not in seen:
                    seen.add(key_str)
                    candidates.append(key_str)
    if not candidates:
        return []
    priority = [
        "_time",
        "rf_max_risk_score",
        "rf_criticality_label",
        "rf_top_field",
        "host",
        "source",
        "sourcetype",
        "index",
    ]
    ordered: list[str] = [f for f in priority if f in candidates]
    for f in candidates:
        if f not in ordered and f != "_raw" and f != "rf_observables":
            ordered.append(f)
    if "_raw" in candidates and "_raw" not in ordered:
        ordered.append("_raw")
    return ordered[:_MAX_TABLE_COLUMNS]


class SplunkSearchPane(BaseSocPane):
    """Interactive Splunk Search REST workbench with pagination, saved searches, and export."""

    STATUS_ID = "splunk-search-status"
    LOG_ID = ""
    LOG_SOURCE = "splunk"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._table_mode: str = "results"
        self._current_sid: str | None = None
        self._active_sid: str | None = None
        self._active_sid_lock = threading.Lock()
        self._total_results: int = 0
        self._current_offset: int = 0
        self._page_size: int = 100
        self._current_fields: list[str] = []
        self._raw_rows: list[dict[str, Any]] = []
        self._current_rows: list[dict[str, Any]] = []
        self._last_duration: float = 0.0
        self._rendering_table: bool = False
        self._syncing_preset: bool = False
        self._request_seq: int = 0
        self._enricher: SplunkRFEnricher | None = None

    def compose(self) -> ComposeResult:
        yield Static("Splunk Search Workbench", classes="pane-title")
        yield Static(
            "Enter an SPL query and click Run Search, or load Saved Searches / Indexes.",
            id="splunk-search-status",
            classes="status-bar",
            markup=False,
        )

        yield TextArea(
            "",
            id="splunk-search-spl",
            soft_wrap=True,
            show_line_numbers=False,
        )

        with Horizontal(id="splunk-search-time-bar", classes="action-row filter-bar"):
            yield Select(
                _TIME_PRESETS,
                allow_blank=False,
                value="-24h",
                id="splunk-search-preset",
                compact=True,
            )
            yield Input(
                value="-24h",
                placeholder="Earliest",
                id="splunk-search-earliest",
                compact=True,
            )
            yield Input(
                value="now",
                placeholder="Latest",
                id="splunk-search-latest",
                compact=True,
            )
            yield Input(
                value="",
                placeholder="App (optional)",
                id="splunk-search-app",
                compact=True,
            )
            yield Input(
                value="100",
                placeholder="Limit",
                id="splunk-search-limit",
                compact=True,
            )

        with Horizontal(id="splunk-search-toolbar", classes="action-row toolbar-row"):
            yield Button(
                "Run Search",
                id="splunk-search-run-btn",
                variant="primary",
                compact=True,
            )
            yield Button("Cancel", id="splunk-search-cancel-btn", compact=True)
            yield Button("Load Saved Searches", id="splunk-search-saved-btn", compact=True)
            yield Button("List Indexes", id="splunk-search-indexes-btn", compact=True)
            yield Button("Enrich Results with RF", id="splunk-search-rf-enrich-btn", compact=True)
            yield Button("Export JSON", id="splunk-search-export-json-btn", compact=True)
            yield Button("Export CSV", id="splunk-search-export-csv-btn", compact=True)

        with Container(id="splunk-search-workspace", classes="split-workspace"):
            with Vertical(id="splunk-search-master-pane", classes="table-pane"):
                with Horizontal(classes="detail-toolbar"):
                    yield Static(
                        "Results (0)",
                        id="splunk-search-page-info",
                        markup=False,
                    )
                    yield Button("Prev", id="splunk-search-prev-btn", compact=True, disabled=True)
                    yield Button("Next", id="splunk-search-next-btn", compact=True, disabled=True)
                with Horizontal(id="splunk-search-results-filter", classes="action-row filter-bar"):
                    yield Input(
                        placeholder="Filter loaded rows...",
                        id="splunk-search-filter-input",
                        compact=True,
                    )
                    yield Static(
                        "Results: 0 | Window: -24h -> now",
                        id="splunk-search-summary",
                        markup=False,
                    )
                yield DoubleClickDataTable(id="splunk-search-table")

            with Vertical(id="splunk-search-detail-pane"):
                yield Static(
                    "Event Detail",
                    id="splunk-search-detail-header",
                    classes="section-label",
                    markup=False,
                )
                yield SelectableRichLog(
                    id="splunk-search-detail",
                    classes="detail-log",
                    highlight=False,
                    markup=False,
                    wrap=True,
                )

    def on_mount(self) -> None:
        table = self.query_one("#splunk-search-table", DoubleClickDataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        self._update_split_layout()

    def on_resize(self) -> None:
        self._update_split_layout()

    def on_tab_activated(self) -> None:
        self._update_split_layout()

    def _update_split_layout(self) -> None:
        if self.is_app_shutting_down():
            return
        try:
            compact = self.size.width < 110 or self.size.height <= 26
            self.set_class(compact, "search-compact")
            self.set_class(
                compact or self.size.width < 130,
                "search-toolbar-compact",
            )
            ws = self.query_one("#splunk-search-workspace", Container)
            if self.size.width >= 110:
                ws.add_class("split-horizontal")
            else:
                ws.remove_class("split-horizontal")
        except Exception:
            pass

    def load_query(self, spl: str, *, auto_run: bool = False) -> None:
        """Load an SPL query into the editor for cross-tab pivoting."""
        clean_spl = str(spl or "").strip()
        try:
            editor = self.query_one("#splunk-search-spl", TextArea)
            editor.load_text(clean_spl)
        except Exception:
            return
        self.set_status(f"Loaded SPL query ({len(clean_spl)} chars). Ready to run.")
        if auto_run and clean_spl:
            self.handle_run_search()

    def accept_pivot(self, payload: PivotPayload) -> None:
        """Accept a ``PivotPayload``, sync time window, and auto-run ONLY for ``orig_sid``."""
        spl, should_auto_run = build_spl_from_pivot(payload)

        earliest_val = (payload.earliest or "").strip()
        latest_val = (payload.latest or "").strip()
        if earliest_val or latest_val:
            target_earliest = earliest_val or "-24h"
            target_latest = latest_val or "now"
            self._syncing_preset = True
            try:
                earliest_inp = self.query_one("#splunk-search-earliest", Input)
                latest_inp = self.query_one("#splunk-search-latest", Input)
                preset_sel = self.query_one("#splunk-search-preset", Select)
                with earliest_inp.prevent(Input.Changed):
                    earliest_inp.value = target_earliest
                with latest_inp.prevent(Input.Changed):
                    latest_inp.value = target_latest
                preset_values = {v for _, v in _TIME_PRESETS if v != "custom"}
                target_preset = (
                    target_earliest
                    if (target_earliest in preset_values and target_latest == "now")
                    else "custom"
                )
                with preset_sel.prevent(Select.Changed):
                    preset_sel.value = target_preset
            finally:
                self._syncing_preset = False

        self.load_query(spl, auto_run=False)
        self._update_summary_bar()
        src = payload.source_tab or "workbench"
        if should_auto_run:
            self.set_status(f"Pivot from {src}: running orig_sid drilldown.")
            self.handle_run_search()
        else:
            self.set_status(
                f"Pivot from {src}: loaded SPL ({len(spl)} chars; auto-run disabled for safety)."
            )

    def _build_splunk_client(self, app_override: str | None = None) -> SplunkClient:
        cfg = get_splunk_config(app=app_override, required=True)
        return SplunkClient(
            host=cfg.host,
            token=cfg.token,
            username=cfg.username,
            password=cfg.password,
            app=cfg.app,
            verify_ssl=cfg.verify_ssl,
            stop_event=getattr(self.app, "_stop_event", None),
        )

    def _parse_limit(self) -> tuple[bool, int]:
        raw = self.query_one("#splunk-search-limit", Input).value.strip() or "100"
        try:
            limit = int(raw)
            if limit < 1:
                raise ValueError("Limit must be >= 1")
            return True, limit
        except ValueError as exc:
            self.set_status(f"Invalid limit '{raw}': {exc}")
            return False, 100

    @on(Select.Changed, "#splunk-search-preset")
    def handle_preset_changed(self, event: Select.Changed) -> None:
        if self._syncing_preset:
            return
        value = str(event.value)
        if value != "custom":
            self._syncing_preset = True
            try:
                earliest_inp = self.query_one("#splunk-search-earliest", Input)
                latest_inp = self.query_one("#splunk-search-latest", Input)
                with earliest_inp.prevent(Input.Changed):
                    earliest_inp.value = value
                with latest_inp.prevent(Input.Changed):
                    latest_inp.value = "now"
            finally:
                self._syncing_preset = False
        self._update_summary_bar()

    @on(Input.Changed, "#splunk-search-earliest")
    @on(Input.Changed, "#splunk-search-latest")
    def handle_time_input_changed(self) -> None:
        if self._syncing_preset:
            return
        earliest = self.query_one("#splunk-search-earliest", Input).value.strip()
        latest = self.query_one("#splunk-search-latest", Input).value.strip()
        preset_values = {v for _, v in _TIME_PRESETS if v != "custom"}
        target = earliest if (earliest in preset_values and latest == "now") else "custom"
        select = self.query_one("#splunk-search-preset", Select)
        if str(select.value) != target:
            self._syncing_preset = True
            try:
                with select.prevent(Select.Changed):
                    select.value = target
            finally:
                self._syncing_preset = False
        self._update_summary_bar()

    @on(Input.Changed, "#splunk-search-filter-input")
    def handle_results_filter_changed(self) -> None:
        if not self._rendering_table and self._raw_rows:
            self._render_filtered_results()

    def _update_summary_bar(self) -> None:
        try:
            summary = self.query_one("#splunk-search-summary", Static)
            earliest = self.query_one("#splunk-search-earliest", Input).value.strip() or "-24h"
            latest = self.query_one("#splunk-search-latest", Input).value.strip() or "now"
            filt = self.query_one("#splunk-search-filter-input", Input).value.strip()
        except Exception:
            return
        mode_lbl = {
            "results": "Results",
            "saved_searches": "Saved Searches",
            "indexes": "Indexes",
        }.get(self._table_mode, "Rows")
        parts = [f"{mode_lbl}: {len(self._current_rows)} (loaded {len(self._raw_rows)})"]
        parts.append(f"Window: {earliest} -> {latest}")
        if filt:
            parts.append(f"Filter='{filt}'")
        summary.update(" | ".join(parts))

    def _render_filtered_results(self) -> None:
        query = ""
        try:
            query = self.query_one("#splunk-search-filter-input", Input).value.strip().lower()
        except Exception:
            pass
        if query:
            rows = [
                row
                for row in self._raw_rows
                if query in json.dumps(row, default=str).lower()
            ]
        else:
            rows = list(self._raw_rows)

        self._current_rows = rows
        fields = self._current_fields
        mode = self._table_mode
        table = self.query_one("#splunk-search-table", DoubleClickDataTable)
        self._rendering_table = True
        try:
            table.clear(columns=True)
            display_cols = (
                list(fields) if mode != "results" else _order_display_fields(fields, rows)
            )
            if not display_cols and self._raw_rows:
                display_cols = (
                    list(fields)
                    if mode != "results"
                    else _order_display_fields(fields, self._raw_rows)
                )
            if not display_cols:
                table.add_column("Message", key="message")
            else:
                for col in display_cols:
                    table.add_column(col, key=col)
                for idx, row in enumerate(rows):
                    table.add_row(
                        *[_clean_cell(row.get(col)) for col in display_cols],
                        key=str(idx),
                    )
        finally:
            self._rendering_table = False

        self._update_pagination_controls()
        self._update_summary_bar()
        if rows:
            self._render_event_detail(0)
        else:
            msg = "No loaded rows match the current filter." if self._raw_rows else "No rows to display."
            self._clear_event_detail(msg)

    def _populate_results_table(
        self,
        rows: list[dict[str, Any]],
        fields: list[str],
        *,
        mode: str = "results",
    ) -> None:
        self._table_mode = mode
        self._raw_rows = list(rows)
        self._current_fields = list(fields)
        self._render_filtered_results()

    def _update_pagination_controls(self) -> None:
        info = self.query_one("#splunk-search-page-info", Static)
        prev_btn = self.query_one("#splunk-search-prev-btn", Button)
        next_btn = self.query_one("#splunk-search-next-btn", Button)

        if self._table_mode == "results":
            shown = len(self._current_rows)
            if self._total_results > 0 and shown > 0:
                start = self._current_offset + 1
                end = self._current_offset + shown
                info.update(f"Results {start}-{end} of {self._total_results}")
            else:
                info.update(f"Results ({self._total_results})")
            has_sid = bool(self._current_sid)
            prev_btn.disabled = not (has_sid and self._current_offset > 0)
            next_btn.disabled = not (
                has_sid and (self._current_offset + self._page_size) < self._total_results
            )
        elif self._table_mode == "saved_searches":
            info.update(f"Saved Searches ({len(self._current_rows)}) — double-click to load SPL")
            prev_btn.disabled = True
            next_btn.disabled = True
        elif self._table_mode == "indexes":
            info.update(f"Indexes ({len(self._current_rows)}) — double-click to load SPL")
            prev_btn.disabled = True
            next_btn.disabled = True

    def _clear_event_detail(self, message: str = "") -> None:
        detail = self.query_one("#splunk-search-detail", RichLog)
        detail.clear()
        if message:
            detail.write(message)

    def _render_event_detail(self, row_index: int) -> None:
        if row_index < 0 or row_index >= len(self._current_rows):
            return
        row = self._current_rows[row_index]
        detail = self.query_one("#splunk-search-detail", RichLog)
        detail.clear()
        header = self.query_one("#splunk-search-detail-header", Static)
        if self._table_mode == "saved_searches":
            panel_title = f"Saved Search Detail — {row.get('name', '')}"
            header.update(panel_title)
        elif self._table_mode == "indexes":
            panel_title = f"Index Detail — {row.get('name', '')}"
            header.update(panel_title)
        else:
            panel_title = f"Event Detail — Row #{self._current_offset + row_index + 1}"
            header.update(panel_title)

        tbl = Table.grid(padding=(0, 2), expand=True)
        tbl.add_column(style="bold cyan", no_wrap=True, min_width=16)
        tbl.add_column(ratio=1, overflow="fold")
        for key, value in row.items():
            if key in _RF_ENRICHMENT_KEYS:
                continue
            rendered = _format_human_value(value)
            if rendered and rendered != "-":
                label = "Time" if key == "_time" else ("Raw Event" if key == "_raw" else _pretty_field_label(str(key)))
                tbl.add_row(label, make_pivot_text(rendered, field=label))
        detail.write(
            Panel(
                tbl,
                title=Text(panel_title, style="bold cyan"),
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

        if "rf_observables" in row or "rf_max_risk_score" in row:
            detail.write("")
            detail.write("--- Recorded Future Enrichment ---")
            max_score = row.get("rf_max_risk_score")
            score_txt = f"{max_score}/99" if max_score is not None else "N/A"
            detail.write(f"Max Risk Score: {score_txt}")
            detail.write(f"Criticality: {row.get('rf_criticality_label') or 'No Data'}")
            if row.get("rf_top_field"):
                detail.write(f"Top Mapped IOC: {row.get('rf_top_field')}")
            detail.write(f"Rules Triggered: {row.get('rf_rules_triggered', 0)}")
            if row.get("rf_evidence_summary"):
                detail.write(f"Evidence Summary: {row.get('rf_evidence_summary')}")

            observables = row.get("rf_observables")
            if isinstance(observables, list) and observables:
                for obs in observables:
                    if not isinstance(obs, dict):
                        continue
                    src_field = str(obs.get("source_field") or obs.get("ioc_type") or "")
                    ioc_type = str(obs.get("ioc_type") or "")
                    val = str(obs.get("value") or "")
                    obs_score = obs.get("risk_score")
                    obs_score_txt = f"{obs_score}/99" if obs_score is not None else "N/A"
                    obs_crit = str(obs.get("criticality_label") or "No Data")
                    detail.write(
                        f"  * {src_field} -> {val} [{ioc_type}] | Risk: {obs_score_txt} ({obs_crit})"
                    )
                    ev_list = obs.get("evidence")
                    if isinstance(ev_list, list) and ev_list:
                        for ev in ev_list[:5]:
                            if isinstance(ev, dict):
                                rule_name = str(ev.get("rule") or "").strip()
                                ev_str = str(ev.get("evidence") or "").strip()
                                if rule_name and ev_str:
                                    detail.write(f"      - {rule_name}: {ev_str}")
                                elif rule_name:
                                    detail.write(f"      - {rule_name}")
                    intel_url = str(obs.get("intel_card_url") or "").strip()
                    if intel_url:
                        detail.write(f"      Intel Card: {intel_url}")
            else:
                detail.write("  (No public/mappable IOCs extracted from this event.)")

    def _selected_row_index(self) -> int | None:
        table = self.query_one("#splunk-search-table", DoubleClickDataTable)
        if table.row_count == 0 or not self._current_rows:
            return None
        row_idx = table.cursor_row
        if 0 <= row_idx < len(self._current_rows):
            return row_idx
        return 0

    @on(DataTable.RowHighlighted, "#splunk-search-table")
    def handle_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self._rendering_table:
            return
        if 0 <= event.cursor_row < len(self._current_rows):
            self._render_event_detail(event.cursor_row)

    @on(DataTable.RowSelected, "#splunk-search-table")
    def handle_row_selected(self, event: DataTable.RowSelected) -> None:
        if self._rendering_table:
            return
        idx = event.cursor_row
        if idx < 0 or idx >= len(self._current_rows):
            return
        row = self._current_rows[idx]
        if self._table_mode == "saved_searches":
            spl = str(row.get("search") or "").strip()
            if spl:
                self.load_query(spl, auto_run=False)
                self.set_status(f"Loaded saved search '{row.get('name', '')}' into SPL editor.")
        elif self._table_mode == "indexes":
            idx_name = str(row.get("name") or "").strip()
            if idx_name:
                self.load_query(f"index={idx_name} | head 100", auto_run=False)
                self.set_status(f"Loaded index '{idx_name}' query into SPL editor.")
        else:
            self._render_event_detail(idx)

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        if self.handle_field_pivot_right_click(event, source_tab="tab-splunk-search"):
            return
        event.stop()
        self._open_search_menu(
            row_index=self._selected_row_index(),
            origin=(event.screen_x, event.screen_y),
        )

    @on(DoubleClickDataTable.RowRightClicked, "#splunk-search-table")
    def handle_table_right_click(self, event: DoubleClickDataTable.RowRightClicked) -> None:
        event.stop()
        row_index = event.row_index if event.row_index is not None else self._selected_row_index()
        self._open_search_menu(
            row_index=row_index,
            origin=(event.screen_x, event.screen_y),
        )

    def _open_search_menu(
        self,
        *,
        row_index: int | None,
        origin: tuple[int, int],
    ) -> None:
        items: list[tuple[str, str]] = [
            ("inspect_event", "Inspect Event"),
            ("enrich_rf", "Enrich Results with RF"),
            ("export_json", "Export JSON"),
            ("export_csv", "Export CSV"),
            ("open_logs", "Open Logs Tab"),
        ]

        def _on_select(action_id: str) -> None:
            if action_id == "inspect_event":
                if row_index is not None and 0 <= row_index < len(self._current_rows):
                    self._render_event_detail(row_index)
                    self.query_one("#splunk-search-detail", RichLog).focus()
                else:
                    self.set_status("No event selected to inspect.")
            elif action_id == "enrich_rf":
                self.handle_enrich_results_rf()
            elif action_id == "export_json":
                self.handle_export_json()
            elif action_id == "export_csv":
                self.handle_export_csv()
            elif action_id == "open_logs":
                open_fn = getattr(self.app, "open_logs_tab", None)
                if callable(open_fn):
                    open_fn(source="splunk")

        self.open_context_menu(
            items,
            title="Splunk Search",
            origin=origin,
            on_select=_on_select,
        )

    @on(Button.Pressed, "#splunk-search-run-btn")
    def handle_run_search(self) -> None:
        spl = self.query_one("#splunk-search-spl", TextArea).text.strip()
        if not spl:
            self.set_status("Enter an SPL query before running a search.")
            return
        ok, limit = self._parse_limit()
        if not ok:
            return
        earliest = self.query_one("#splunk-search-earliest", Input).value.strip() or "-24h"
        latest = self.query_one("#splunk-search-latest", Input).value.strip() or "now"
        app_ov = self.query_one("#splunk-search-app", Input).value.strip() or None
        self._page_size = limit
        self._current_offset = 0
        self._request_seq += 1
        self._run_search_worker(spl, earliest, latest, app_ov, limit, seq=self._request_seq)

    @work(thread=True, exit_on_error=False)
    def _run_search_worker(
        self,
        spl: str,
        earliest: str,
        latest: str,
        app_ov: str | None,
        limit: int,
        *,
        seq: int = 0,
    ) -> None:
        try:
            self.set_status(f"Dispatching Splunk search ({earliest} to {latest})...")

            def _on_progress(prog: dict[str, Any]) -> None:
                if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                    return
                sid = str(prog.get("sid") or "")
                with self._active_sid_lock:
                    if sid:
                        self._active_sid = sid
                state = str(prog.get("dispatch_state") or "RUNNING")
                res_cnt = int(prog.get("result_count", 0))
                dur = float(prog.get("duration", 0.0))
                self.set_status(
                    f"State: {state} | Results: {res_cnt} | Duration: {dur:.2f}s | SID: {sid}"
                )

            with self.log_scope("splunk"):
                with self._build_splunk_client(app_override=app_ov) as splunk:
                    res = splunk.run_search(
                        spl,
                        earliest=earliest,
                        latest=latest,
                        app=app_ov,
                        count=limit,
                        offset=0,
                        progress_cb=_on_progress,
                    )

            with self._active_sid_lock:
                self._active_sid = None

            if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                return

            sid = str(res.get("sid") or "")
            if res.get("status") != "success":
                err = str(res.get("error_message") or "Search failed.")
                self._current_sid = sid or None
                self._total_results = int(res.get("result_count", 0))
                self._last_duration = float(res.get("duration", 0.0))
                self._current_offset = 0
                self.set_status(f"State: FAILED | SID: {sid or '-'} | {err}")
                self.append_log(f"Splunk search failed: {err}", level="ERROR")
                return

            rows = list(res.get("results") or [])
            fields = list(res.get("fields") or [])
            total_results = int(res.get("result_count", 0))
            last_duration = float(res.get("duration", 0.0))

            def _apply() -> None:
                if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                    return
                self._current_sid = sid or None
                self._total_results = total_results
                self._last_duration = last_duration
                self._current_offset = 0
                self._populate_results_table(rows, fields, mode="results")

            self.run_on_ui(_apply)
            banner = (
                f"State: DONE | Results: {total_results} | "
                f"Duration: {last_duration:.2f}s | SID: {sid}"
            )
            self.set_status(banner)
            self.append_log(banner)
        except Exception as exc:
            with self._active_sid_lock:
                self._active_sid = None
            if not self.is_app_shutting_down() and (not seq or seq == self._request_seq):
                self.report_error("Splunk Search", exc)

    @on(Button.Pressed, "#splunk-search-cancel-btn")
    def handle_cancel_search(self) -> None:
        with self._active_sid_lock:
            sid = self._active_sid or self._current_sid
        if not sid:
            self.set_status("No active Splunk search job to cancel.")
            return
        app_ov = self.query_one("#splunk-search-app", Input).value.strip() or None
        self._cancel_job_worker(sid, app_ov)

    @work(thread=True, exit_on_error=False)
    def _cancel_job_worker(self, sid: str, app_ov: str | None) -> None:
        try:
            with self.log_scope("splunk"):
                with self._build_splunk_client(app_override=app_ov) as splunk:
                    cancelled = splunk.cancel_job(sid)
            msg = (
                f"Cancelled Splunk job SID: {sid}"
                if cancelled
                else f"Failed to cancel Splunk job SID: {sid}"
            )
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Cancel Splunk Job", exc)

    @on(Button.Pressed, "#splunk-search-prev-btn")
    def handle_prev_page(self) -> None:
        if not self._current_sid or self._current_offset <= 0:
            return
        new_offset = max(0, self._current_offset - self._page_size)
        app_ov = self.query_one("#splunk-search-app", Input).value.strip() or None
        self._request_seq += 1
        self._paginate_worker(
            self._current_sid,
            self._page_size,
            new_offset,
            app_ov,
            seq=self._request_seq,
        )

    @on(Button.Pressed, "#splunk-search-next-btn")
    def handle_next_page(self) -> None:
        if not self._current_sid:
            return
        new_offset = self._current_offset + self._page_size
        if new_offset >= self._total_results:
            return
        app_ov = self.query_one("#splunk-search-app", Input).value.strip() or None
        self._request_seq += 1
        self._paginate_worker(
            self._current_sid,
            self._page_size,
            new_offset,
            app_ov,
            seq=self._request_seq,
        )

    @work(thread=True, exit_on_error=False)
    def _paginate_worker(
        self,
        sid: str,
        count: int,
        offset: int,
        app_ov: str | None,
        *,
        seq: int = 0,
    ) -> None:
        try:
            self.set_status(f"Loading results page (offset={offset}) for SID: {sid}...")
            with self.log_scope("splunk"):
                with self._build_splunk_client(app_override=app_ov) as splunk:
                    page = splunk.get_job_results(sid, count=count, offset=offset)
            if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                return
            rows = list(page.get("results") or [])
            fields = list(page.get("fields") or self._current_fields)

            def _apply() -> None:
                if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                    return
                self._current_offset = offset
                self._populate_results_table(rows, fields, mode="results")

            self.run_on_ui(_apply)
            self.set_status(
                f"State: DONE | Results: {self._total_results} | "
                f"Duration: {self._last_duration:.2f}s | SID: {sid}"
            )
        except Exception as exc:
            if not self.is_app_shutting_down() and (not seq or seq == self._request_seq):
                self.report_error("Splunk Pagination", exc)

    @on(Button.Pressed, "#splunk-search-saved-btn")
    def handle_load_saved_searches(self) -> None:
        app_ov = self.query_one("#splunk-search-app", Input).value.strip() or None
        self._request_seq += 1
        self._load_saved_searches_worker(app_ov, seq=self._request_seq)

    @work(thread=True, exit_on_error=False)
    def _load_saved_searches_worker(self, app_ov: str | None, *, seq: int = 0) -> None:
        try:
            self.set_status("Loading Splunk saved searches...")
            with self.log_scope("splunk"):
                with self._build_splunk_client(app_override=app_ov) as splunk:
                    items = splunk.list_saved_searches(app=app_ov, count=100)
            if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                return
            cols = ["name", "app", "cron_schedule", "earliest_time", "latest_time", "disabled"]

            def _apply() -> None:
                if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                    return
                self._populate_results_table(items, cols, mode="saved_searches")

            self.run_on_ui(_apply)
            msg = f"Loaded {len(items)} Splunk saved search(es)."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            if not self.is_app_shutting_down() and (not seq or seq == self._request_seq):
                self.report_error("Load Saved Searches", exc)

    @on(Button.Pressed, "#splunk-search-indexes-btn")
    def handle_list_indexes(self) -> None:
        app_ov = self.query_one("#splunk-search-app", Input).value.strip() or None
        self._request_seq += 1
        self._list_indexes_worker(app_ov, seq=self._request_seq)

    @work(thread=True, exit_on_error=False)
    def _list_indexes_worker(self, app_ov: str | None, *, seq: int = 0) -> None:
        try:
            self.set_status("Listing Splunk indexes...")
            with self.log_scope("splunk"):
                with self._build_splunk_client(app_override=app_ov) as splunk:
                    items = splunk.list_indexes()
            if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                return
            cols = ["name", "total_event_count", "current_db_size_mb", "datatype", "disabled"]

            def _apply() -> None:
                if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                    return
                self._populate_results_table(items, cols, mode="indexes")

            self.run_on_ui(_apply)
            msg = f"Loaded {len(items)} Splunk index(es)."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            if not self.is_app_shutting_down() and (not seq or seq == self._request_seq):
                self.report_error("List Indexes", exc)

    @on(Button.Pressed, "#splunk-search-export-json-btn")
    def handle_export_json(self) -> None:
        self._export_current_results("json")

    @on(Button.Pressed, "#splunk-search-export-csv-btn")
    def handle_export_csv(self) -> None:
        self._export_current_results("csv")

    def _export_current_results(self, fmt: str) -> None:
        if not self._current_rows:
            self.set_status("No results available to export.")
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = Path(self.workspace_dir) / f"splunk_results_{stamp}.{fmt}"
        try:
            written = (
                export_results_json(self._current_rows, out_path)
                if fmt == "json"
                else export_results_csv(self._current_rows, out_path, fields=self._current_fields)
            )
            msg = f"Exported {len(self._current_rows)} row(s) to {written}"
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Export Complete")
        except Exception as exc:
            self.report_error(f"Export {fmt.upper()}", exc)

    def _get_rf_enricher(self) -> SplunkRFEnricher:
        if self._enricher is None or self._enricher.rf_client is not self.client:
            self._enricher = SplunkRFEnricher(self.client)
        return self._enricher

    @on(Button.Pressed, "#splunk-search-rf-enrich-btn")
    def handle_enrich_results_rf(self) -> None:
        if self._table_mode != "results":
            self.set_status("Run an SPL search first before enriching results with Recorded Future.")
            return
        if not self._current_rows:
            self.set_status("No search results available to enrich with Recorded Future.")
            return
        rows_copy = [dict(r) for r in self._current_rows]
        fields_copy = list(self._current_fields)
        self._request_seq += 1
        self._enrich_results_worker(rows_copy, fields_copy, seq=self._request_seq)

    @work(thread=True, exit_on_error=False)
    def _enrich_results_worker(
        self,
        rows: list[dict[str, Any]],
        fields: list[str],
        *,
        seq: int = 0,
    ) -> None:
        try:
            self.set_status(
                f"Enriching {len(rows)} Splunk search result(s) with Recorded Future SOAR v3..."
            )
            enricher = self._get_rf_enricher()
            with self.log_scope("rf"):
                enriched = enricher.enrich_events(rows)

            if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                return

            enriched_fields = list(fields)
            for extra in ("rf_max_risk_score", "rf_criticality_label", "rf_top_field"):
                if extra not in enriched_fields:
                    enriched_fields.append(extra)

            def _apply() -> None:
                if self.is_app_shutting_down() or (seq and seq != self._request_seq):
                    return
                self._populate_results_table(enriched, enriched_fields, mode="results")

            self.run_on_ui(_apply)
            mapped_cnt = sum(1 for r in enriched if r.get("rf_observables"))
            top_scores = [
                int(r["rf_max_risk_score"])
                for r in enriched
                if r.get("rf_max_risk_score") is not None
            ]
            max_str = f" | Highest RF Risk: {max(top_scores)}/99" if top_scores else ""
            msg = (
                f"Recorded Future enrichment complete: {mapped_cnt}/{len(enriched)} "
                f"result(s) had mapped IOCs{max_str}."
            )
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            if not self.is_app_shutting_down() and (not seq or seq == self._request_seq):
                self.report_error("RF Search Enrichment", exc)
