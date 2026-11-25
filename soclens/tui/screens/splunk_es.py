"""Interactive Splunk Enterprise Security (ES) workbench pane."""

from __future__ import annotations

import json
from typing import Any

from textual import events, on, work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, Checkbox, Collapsible, DataTable, Input, RichLog, Select, Static

from soclens.client import RecordedFutureClient
from soclens.config import get_rf_token, get_splunk_config
from soclens.splunk_es import (
    NOTABLE_STATUS_LABELS,
    NOTABLE_STATUS_MAP,
    NOTABLE_URGENCIES,
    SPLUNK_ES_APP,
    THREAT_INTEL_COLLECTIONS,
    SplunkESClient,
)
from soclens.splunk_rf_enrichment import (
    SplunkRFEnricher,
    format_notable_rf_comment,
    load_splunk_rf_field_map,
    write_enrichment_to_notable,
)
from soclens.tui.filters import (
    ES_TIMEFRAME_OPTIONS,
    SPLUNK_ES_PRESETS,
    timeframe_label,
    timestamp_matches_timeframe,
)
from soclens.tui.modals import SplunkNotableTriageModal
from soclens.tui.screens.base import BaseSocPane, DoubleClickDataTable

_ES_PRESETS_BY_ID: dict[str, dict[str, Any]] = {p["id"]: p for p in SPLUNK_ES_PRESETS}
_ES_TIMEFRAME_EARLIEST_MAP: dict[str, str] = {
    "-24h": "-24h",
    "-48h": "-48h",
    "-7d": "-7d",
    "-14d": "-14d",
    "-30d": "-30d",
    "-90d": "-90d",
    "older_7d": "-30d",
    "older_14d": "-90d",
    "older_30d": "-90d",
    "any": "-30d",
}

_VIEW_OPTIONS: list[tuple[str, str]] = [
    ("Notable Events", "notables"),
    ("Correlation Searches", "correlations"),
    ("Threat Intel", "threat_intel"),
    ("Assets & Identities", "assets_identities"),
    ("Risk Events (RBA)", "risk"),
]

_ENTITY_KIND_OPTIONS: list[tuple[str, str]] = [
    ("Assets", "assets"),
    ("Identities", "identities"),
]

_MAX_CELL_LEN = 72
_MAX_DYNAMIC_COLS = 10

_NOTABLE_COLUMNS: list[tuple[str, str]] = [
    ("_time", "Time"),
    ("urgency", "Urgency"),
    ("status_label", "Status"),
    ("rule_name", "Rule"),
    ("owner", "Owner"),
    ("src", "Src"),
    ("dest", "Dest"),
    ("user", "User"),
    ("risk_score", "Risk"),
    ("rf_max_risk_score", "RF Risk"),
    ("rf_criticality_label", "RF Label"),
    ("rf_top_field", "RF Mapped IOC"),
]

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
        return f"{text[: max_len - 1]}..."
    return text


def _infer_columns(rows: list[dict[str, Any]], preferred: list[str] | None = None) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    if preferred:
        for col in preferred:
            if any(col in row for row in rows):
                ordered.append(col)
                seen.add(col)
    for row in rows:
        for key in row:
            key_str = str(key)
            if key_str == "raw" or key_str in seen:
                continue
            seen.add(key_str)
            ordered.append(key_str)
    return ordered[:_MAX_DYNAMIC_COLS]


class SplunkESPane(BaseSocPane):
    """Splunk Enterprise Security workbench for Notables, Correlations, Threat Intel, Assets/IDs, and RBA."""

    STATUS_ID = "es-status"
    LOG_ID = ""
    LOG_SOURCE = "splunk"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._current_view: str = "notables"
        self._raw_rows: list[dict[str, Any]] = []
        self._raw_columns: list[tuple[str, str]] = []
        self._raw_header_label: str = "Notable Events"
        self._current_rows: list[dict[str, Any]] = []
        self._rendering_table: bool = False
        self._enricher: SplunkRFEnricher | None = None
        self._active_preset_id: str = "all"
        self._local_timeframe: str = "any"
        self._preset_statuses: tuple[str, ...] = ()
        self._preset_urgencies: tuple[str, ...] = ()
        self._preset_owner_mode: str = "any"
        self._syncing_es_filters: bool = False
        self._es_ready: bool = False

    def compose(self) -> ComposeResult:
        urgency_options: list[tuple[str, str]] = [("All Urgencies", "")] + [
            (u.title(), u) for u in NOTABLE_URGENCIES
        ]
        status_options: list[tuple[str, str]] = [("All Statuses", "")] + [
            (NOTABLE_STATUS_LABELS[code], key) for key, code in NOTABLE_STATUS_MAP.items()
        ]
        collection_options: list[tuple[str, str]] = [
            (col, col) for col in THREAT_INTEL_COLLECTIONS
        ]
        preset_options: list[tuple[str, str]] = [
            (str(p["label"]), str(p["id"])) for p in SPLUNK_ES_PRESETS
        ] + [("Custom Filter", "__custom__")]

        yield Static("Splunk Enterprise Security (ES) Workbench", classes="pane-title")
        yield Static(
            "Select an ES view and click Refresh to load Notable Events, Correlations, Threat Intel, Assets/IDs, or RBA.",
            id="es-status",
            classes="status-bar",
            markup=False,
        )

        with Horizontal(classes="action-row toolbar-row"):
            yield Select(
                _VIEW_OPTIONS,
                allow_blank=False,
                value="notables",
                id="es-view-select",
                compact=True,
            )
            yield Select(
                preset_options,
                allow_blank=False,
                value="all",
                id="es-preset-select",
                compact=True,
            )
            yield Select(
                ES_TIMEFRAME_OPTIONS,
                allow_blank=False,
                value="-24h",
                id="es-timeframe-select",
                compact=True,
            )
            yield Input(
                value="-24h",
                placeholder="Earliest (e.g. -24h)",
                id="es-earliest-input",
                compact=True,
            )
            yield Select(
                collection_options,
                allow_blank=False,
                value=THREAT_INTEL_COLLECTIONS[0],
                id="es-collection-select",
                compact=True,
            )
            yield Select(
                _ENTITY_KIND_OPTIONS,
                allow_blank=False,
                value="assets",
                id="es-entity-kind-select",
                compact=True,
            )

        with Horizontal(classes="action-row filter-bar"):
            yield Select(
                urgency_options,
                allow_blank=False,
                value="",
                id="es-urgency-select",
                compact=True,
            )
            yield Select(
                status_options,
                allow_blank=False,
                value="",
                id="es-status-select",
                compact=True,
            )
            yield Input(
                value="",
                placeholder="Search / Filter / Risk Object...",
                id="es-search-input",
                compact=True,
            )
            yield Button("Refresh", id="es-refresh-btn", variant="primary", compact=True)
            yield Button("Triage Notable", id="es-triage-btn", compact=True)
            yield Button("Toggle Enable/Disable", id="es-toggle-corr-btn", compact=True)
            yield Button("Load Collection", id="es-load-ti-btn", compact=True)
            yield Button("Lookup", id="es-lookup-btn", compact=True)
            yield Button("Reset", id="es-clear-filter-btn", compact=True)

        with Horizontal(id="es-rf-controls-row", classes="action-row toolbar-row"):
            yield Checkbox("Auto-Enrich RF", value=True, id="es-auto-enrich-cb", compact=True)
            yield Checkbox(
                "Include Private IPs", value=False, id="es-private-ips-cb", compact=True
            )
            yield Button("Enrich Selected", id="es-enrich-selected-btn", compact=True)
            yield Button("Enrich All", id="es-enrich-all-btn", compact=True)
            yield Button("Post RF Comment", id="es-post-rf-comment-btn", compact=True)

        with Collapsible(
            title="RF Field Mapping Override",
            collapsed=True,
            id="es-rf-map-collapsible",
        ):
            yield Input(
                value="",
                placeholder="ip=src_ip,dest_ip;domain=dns_query",
                id="es-rf-field-map-input",
                compact=True,
            )

        yield Static(
            "Notable Events: 0 | Pick a preset or timeframe to filter",
            id="es-summary-bar",
            classes="rf-summary-bar",
            markup=False,
        )

        with Container(id="es-workspace", classes="split-workspace"):
            with Vertical(id="es-master-pane", classes="table-pane"):
                yield Static(
                    "Notable Events (0)",
                    id="es-table-header",
                    classes="section-label",
                    markup=False,
                )
                yield DoubleClickDataTable(id="es-table")

            with Vertical(id="es-detail-pane"):
                yield Static(
                    "Detail",
                    id="es-detail-header",
                    classes="section-label",
                    markup=False,
                )
                yield RichLog(
                    id="es-detail",
                    classes="detail-log",
                    highlight=False,
                    markup=False,
                    wrap=True,
                )

    def on_mount(self) -> None:
        table = self.query_one("#es-table", DoubleClickDataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        self._sync_controls_for_view(self._current_view)
        self._update_split_layout()
        self.call_after_refresh(self._mark_es_ready)

    def _mark_es_ready(self) -> None:
        self._es_ready = True

    def on_resize(self) -> None:
        self._update_split_layout()

    def on_tab_activated(self) -> None:
        self._update_split_layout()

    def _update_split_layout(self) -> None:
        if self.is_app_shutting_down():
            return
        try:
            ws = self.query_one("#es-workspace", Container)
            if self.size.width >= 110:
                ws.add_class("split-horizontal")
            else:
                ws.remove_class("split-horizontal")
        except Exception:
            pass

    def _build_es_client(self) -> SplunkESClient:
        cfg = get_splunk_config(app=SPLUNK_ES_APP, required=True)
        return SplunkESClient(
            host=cfg.host,
            token=cfg.token,
            username=cfg.username,
            password=cfg.password,
            app=cfg.app,
            verify_ssl=cfg.verify_ssl,
        )

    def _sync_controls_for_view(self, view: str) -> None:
        self._current_view = view
        is_notables = view == "notables"
        is_corr = view == "correlations"
        is_ti = view == "threat_intel"
        is_ai = view == "assets_identities"
        is_risk = view == "risk"

        self.query_one("#es-preset-select", Select).display = is_notables
        self.query_one("#es-timeframe-select", Select).display = is_notables or is_risk
        self.query_one("#es-urgency-select", Select).display = is_notables
        self.query_one("#es-status-select", Select).display = is_notables
        self.query_one("#es-earliest-input", Input).display = is_notables or is_risk
        self.query_one("#es-collection-select", Select).display = is_ti
        self.query_one("#es-entity-kind-select", Select).display = is_ai

        self.query_one("#es-triage-btn", Button).display = is_notables
        self.query_one("#es-toggle-corr-btn", Button).display = is_corr
        self.query_one("#es-load-ti-btn", Button).display = is_ti
        self.query_one("#es-lookup-btn", Button).display = is_ai or is_risk
        self.query_one("#es-rf-controls-row", Horizontal).display = is_notables
        self.query_one("#es-rf-map-collapsible", Collapsible).display = is_notables

        search_input = self.query_one("#es-search-input", Input)
        if is_notables:
            search_input.placeholder = "Search notables (rule, src, dest, user, text)..."
        elif is_corr:
            search_input.placeholder = "Filter correlation searches..."
        elif is_ti:
            search_input.placeholder = "Optional KV Store filter substring..."
        elif is_ai:
            search_input.placeholder = "Lookup asset or identity (IP, host, user, email)..."
        else:
            search_input.placeholder = "Filter by risk_object (host, IP, user)..."

        view_titles = {
            "notables": "Notable Events",
            "correlations": "Correlation Searches",
            "threat_intel": "Threat Intel",
            "assets_identities": "Assets & Identities",
            "risk": "Risk Events (RBA)",
        }
        self.query_one("#es-table-header", Static).update(
            f"{view_titles.get(view, 'Splunk ES')} ({len(self._current_rows)})"
        )
        self._update_summary_bar()

    @on(Select.Changed, "#es-view-select")
    def handle_view_changed(self, event: Select.Changed) -> None:
        view = str(event.value or "notables")
        self._raw_rows = []
        self._current_rows = []
        self._sync_controls_for_view(view)
        self._populate_table([], [], header_label=self._view_header_title(view))
        self.set_status(f"Switched to {self._view_header_title(view)} view. Click Refresh to load.")

    def _view_header_title(self, view: str | None = None) -> str:
        target = view or self._current_view
        return {
            "notables": "Notable Events",
            "correlations": "Correlation Searches",
            "threat_intel": "Threat Intel",
            "assets_identities": "Assets & Identities",
            "risk": "Risk Events (RBA)",
        }.get(target, "Splunk ES")

    def _update_summary_bar(self) -> None:
        try:
            bar = self.query_one("#es-summary-bar", Static)
        except Exception:
            return
        total = len(self._raw_rows)
        shown = len(self._current_rows)
        title = self._view_header_title()
        count_txt = f"{shown}/{total}" if shown != total else f"{total}"
        parts = [f"{title}: {count_txt}"]
        if self._current_view == "notables":
            preset_obj = _ES_PRESETS_BY_ID.get(self._active_preset_id)
            if preset_obj is not None and self._active_preset_id != "all":
                parts.append(f"View: {preset_obj['label']}")
            elif self._local_timeframe != "any":
                parts.append(f"Time: {timeframe_label(self._local_timeframe)}")
            if self._preset_statuses:
                parts.append(f"Status: {','.join(self._preset_statuses)}")
            if self._preset_urgencies:
                parts.append(f"Urgency: {','.join(self._preset_urgencies)}")
            if self._preset_owner_mode == "unassigned":
                parts.append("Owner: Unassigned")
        elif self._current_view == "risk" and self._local_timeframe != "any":
            parts.append(f"Time: {timeframe_label(self._local_timeframe)}")
        bar.update("  |  ".join(parts))

    def _row_matches_local_filters(self, row: dict[str, Any]) -> bool:
        if self._current_view == "notables":
            urgency_sel = str(self.query_one("#es-urgency-select", Select).value or "").strip().lower()
            if self._preset_urgencies:
                row_urg = str(row.get("urgency") or "").strip().lower()
                if row_urg not in {u.lower() for u in self._preset_urgencies}:
                    return False
            elif urgency_sel:
                if str(row.get("urgency") or "").strip().lower() != urgency_sel:
                    return False

            status_sel = str(self.query_one("#es-status-select", Select).value or "").strip().lower()
            row_status_lbl = str(row.get("status_label") or row.get("status") or "").strip().lower()
            if self._preset_statuses:
                allowed = {s.lower() for s in self._preset_statuses}
                if row_status_lbl not in allowed:
                    return False
            elif status_sel:
                expected_code = NOTABLE_STATUS_MAP.get(status_sel)
                expected_label = (
                    NOTABLE_STATUS_LABELS.get(expected_code, status_sel).lower()
                    if expected_code is not None
                    else status_sel
                )
                if row_status_lbl != expected_label and str(row.get("status") or "").lower() != status_sel:
                    return False

            if self._preset_owner_mode == "unassigned":
                owner = str(row.get("owner") or "").strip().lower()
                if owner not in {"", "-", "unassigned"}:
                    return False

        if self._current_view in ("notables", "risk") and self._local_timeframe != "any":
            ts_val = row.get("_time") or row.get("created") or row.get("updated")
            if not timestamp_matches_timeframe(ts_val, self._local_timeframe):
                return False

        search_q = self.query_one("#es-search-input", Input).value.strip().lower()
        if search_q:
            blob = " ".join(str(v) for k, v in row.items() if k != "raw" and v is not None).lower()
            if search_q not in blob:
                raw_obj = row.get("raw")
                raw_blob = json.dumps(raw_obj, default=str).lower() if raw_obj else ""
                if search_q not in raw_blob:
                    return False
        return True

    def _render_filtered_table(self, *, select_row: int = 0) -> None:
        filtered = [row for row in self._raw_rows if self._row_matches_local_filters(row)]
        self._current_rows = filtered
        columns = self._raw_columns
        table = self.query_one("#es-table", DoubleClickDataTable)
        self._rendering_table = True
        try:
            table.clear(columns=True)
            if not columns:
                table.add_column("Message", key="message")
            else:
                for key, label in columns:
                    table.add_column(label, key=key)
                for idx, row in enumerate(filtered):
                    table.add_row(
                        *[_clean_cell(row.get(key)) for key, _ in columns],
                        key=str(idx),
                    )
        finally:
            self._rendering_table = False

        header_count = (
            f"{len(filtered)} of {len(self._raw_rows)}"
            if len(filtered) != len(self._raw_rows)
            else f"{len(filtered)}"
        )
        self.query_one("#es-table-header", Static).update(
            f"{self._raw_header_label} ({header_count})"
        )
        self._update_summary_bar()
        if filtered:
            target_idx = max(0, min(select_row, len(filtered) - 1))
            if target_idx > 0:
                try:
                    table.move_cursor(row=target_idx)
                except Exception:
                    pass
            self._render_detail(target_idx)
        else:
            self._clear_detail("No matching records.")

    def _populate_table(
        self,
        rows: list[dict[str, Any]],
        columns: list[tuple[str, str]],
        *,
        header_label: str,
        select_row: int = 0,
    ) -> None:
        self._raw_rows = list(rows)
        self._raw_columns = list(columns)
        self._raw_header_label = header_label
        self._render_filtered_table(select_row=select_row)

    @on(Select.Changed, "#es-preset-select")
    def handle_preset_changed(self, event: Select.Changed) -> None:
        if self._syncing_es_filters or not self._es_ready:
            return
        preset_id = str(event.value or "all")
        if preset_id == "__custom__":
            return
        preset = _ES_PRESETS_BY_ID.get(preset_id)
        if preset is None:
            return
        self._syncing_es_filters = True
        try:
            self._active_preset_id = preset_id
            self._preset_statuses = tuple(preset.get("statuses") or ())
            self._preset_urgencies = tuple(preset.get("urgencies") or ())
            self._preset_owner_mode = str(preset.get("owner_mode") or "any")
            tf_val = str(preset.get("timeframe") or "any")
            self._local_timeframe = "any" if preset_id == "all" else tf_val

            tf_sel = self.query_one("#es-timeframe-select", Select)
            with tf_sel.prevent(Select.Changed):
                tf_sel.value = tf_val
            earliest_inp = self.query_one("#es-earliest-input", Input)
            with earliest_inp.prevent(Input.Changed):
                earliest_inp.value = str(preset.get("earliest") or "-24h")

            urg_sel = self.query_one("#es-urgency-select", Select)
            with urg_sel.prevent(Select.Changed):
                urg_sel.value = (
                    self._preset_urgencies[0]
                    if len(self._preset_urgencies) == 1
                    else ""
                )

            st_sel = self.query_one("#es-status-select", Select)
            with st_sel.prevent(Select.Changed):
                if len(self._preset_statuses) == 1:
                    target_lbl = self._preset_statuses[0].lower()
                    matched_key = ""
                    for key, code in NOTABLE_STATUS_MAP.items():
                        if NOTABLE_STATUS_LABELS.get(code, "").lower() == target_lbl:
                            matched_key = key
                            break
                    st_sel.value = matched_key
                else:
                    st_sel.value = ""
        finally:
            self._syncing_es_filters = False

        if self._raw_rows:
            self._render_filtered_table()
        else:
            self._update_summary_bar()
        self.set_status(f"Selected ES view '{preset['label']}'.")

    @on(Select.Changed, "#es-timeframe-select")
    def handle_timeframe_changed(self, event: Select.Changed) -> None:
        if self._syncing_es_filters or not self._es_ready:
            return
        tf_val = str(event.value or "-24h")
        self._syncing_es_filters = True
        try:
            self._local_timeframe = tf_val
            if tf_val != "custom":
                mapped_earliest = _ES_TIMEFRAME_EARLIEST_MAP.get(tf_val, "-24h")
                inp = self.query_one("#es-earliest-input", Input)
                with inp.prevent(Input.Changed):
                    inp.value = mapped_earliest
            self._mark_es_custom_preset()
        finally:
            self._syncing_es_filters = False
        if self._raw_rows:
            self._render_filtered_table()
        else:
            self._update_summary_bar()

    @on(Input.Changed, "#es-earliest-input")
    def handle_earliest_changed(self, event: Input.Changed) -> None:
        if self._syncing_es_filters or not self._es_ready:
            return
        val = event.value.strip()
        preset_sel = self.query_one("#es-timeframe-select", Select)
        target = val if val in {"-24h", "-48h", "-7d", "-14d", "-30d", "-90d"} else "custom"
        self._syncing_es_filters = True
        try:
            with preset_sel.prevent(Select.Changed):
                preset_sel.value = target
            self._local_timeframe = target if target != "custom" else "any"
            self._mark_es_custom_preset()
        finally:
            self._syncing_es_filters = False

    def _mark_es_custom_preset(self) -> None:
        self._active_preset_id = "__custom__"
        preset_sel = self.query_one("#es-preset-select", Select)
        with preset_sel.prevent(Select.Changed):
            preset_sel.value = "__custom__"

    @on(Select.Changed, "#es-urgency-select")
    @on(Select.Changed, "#es-status-select")
    def handle_es_dropdown_filter_changed(self) -> None:
        if self._syncing_es_filters or not self._es_ready:
            return
        self._preset_statuses = ()
        self._preset_urgencies = ()
        self._preset_owner_mode = "any"
        self._mark_es_custom_preset()
        if self._raw_rows:
            self._render_filtered_table()
        else:
            self._update_summary_bar()

    @on(Input.Changed, "#es-search-input")
    def handle_es_search_changed(self) -> None:
        if self._raw_rows:
            self._render_filtered_table()

    @on(Button.Pressed, "#es-clear-filter-btn")
    def handle_es_reset_filters(self) -> None:
        self._syncing_es_filters = True
        try:
            self._active_preset_id = "all"
            self._local_timeframe = "any"
            self._preset_statuses = ()
            self._preset_urgencies = ()
            self._preset_owner_mode = "any"
            for sel_id, val in (
                ("#es-preset-select", "all"),
                ("#es-timeframe-select", "-24h"),
                ("#es-urgency-select", ""),
                ("#es-status-select", ""),
            ):
                sel = self.query_one(sel_id, Select)
                with sel.prevent(Select.Changed):
                    sel.value = val
            with self.query_one("#es-earliest-input", Input).prevent(Input.Changed):
                self.query_one("#es-earliest-input", Input).value = "-24h"
            with self.query_one("#es-search-input", Input).prevent(Input.Changed):
                self.query_one("#es-search-input", Input).value = ""
        finally:
            self._syncing_es_filters = False
        if self._raw_rows:
            self._render_filtered_table()
        else:
            self._update_summary_bar()
        self.set_status("Reset Splunk ES filters.")

    def _clear_detail(self, message: str = "") -> None:
        detail = self.query_one("#es-detail", RichLog)
        detail.clear()
        self.query_one("#es-detail-header", Static).update("Detail")
        if message:
            detail.write(message)

    def _render_detail(self, row_index: int) -> None:
        if row_index < 0 or row_index >= len(self._current_rows):
            return
        row = self._current_rows[row_index]
        detail = self.query_one("#es-detail", RichLog)
        detail.clear()

        title_hint = (
            row.get("rule_name")
            or row.get("name")
            or row.get("risk_object")
            or row.get("ip")
            or row.get("domain")
            or row.get("identity")
            or row.get("nt_host")
            or f"Row #{row_index + 1}"
        )
        self.query_one("#es-detail-header", Static).update(
            f"{self._view_header_title()} Detail - {title_hint}"
        )

        for key, value in row.items():
            if key == "raw" or key in _RF_ENRICHMENT_KEYS:
                continue
            if isinstance(value, (dict, list)):
                rendered = json.dumps(value, indent=2, ensure_ascii=False)
            else:
                rendered = str(value)
            detail.write(f"{key}: {rendered}")

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
                detail.write("  (No public/mappable IOCs extracted from this notable.)")

        raw_payload = row.get("raw")
        if isinstance(raw_payload, dict) and raw_payload:
            detail.write("")
            detail.write("--- Raw Fields ---")
            detail.write(json.dumps(raw_payload, indent=2, ensure_ascii=False, sort_keys=True))

    def _selected_row_index(self) -> int | None:
        table = self.query_one("#es-table", DoubleClickDataTable)
        if table.row_count == 0 or not self._current_rows:
            return None
        row_idx = table.cursor_row
        if 0 <= row_idx < len(self._current_rows):
            return row_idx
        return 0

    def get_selected_row(self) -> dict[str, Any] | None:
        """Return the currently selected row dictionary, or ``None`` if none is selected."""
        idx = self._selected_row_index()
        if idx is None or idx < 0 or idx >= len(self._current_rows):
            return None
        return self._current_rows[idx]

    @on(DataTable.RowHighlighted, "#es-table")
    def handle_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self._rendering_table:
            return
        if 0 <= event.cursor_row < len(self._current_rows):
            self._render_detail(event.cursor_row)

    @on(DataTable.RowSelected, "#es-table")
    def handle_row_selected(self, event: DataTable.RowSelected) -> None:
        if self._rendering_table:
            return
        if 0 <= event.cursor_row < len(self._current_rows):
            self._render_detail(event.cursor_row)

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        event.stop()
        self._open_es_menu(
            row_index=self._selected_row_index(),
            origin=(event.screen_x, event.screen_y),
        )

    @on(DoubleClickDataTable.RowRightClicked, "#es-table")
    def handle_table_right_click(self, event: DoubleClickDataTable.RowRightClicked) -> None:
        event.stop()
        row_index = event.row_index if event.row_index is not None else self._selected_row_index()
        self._open_es_menu(
            row_index=row_index,
            origin=(event.screen_x, event.screen_y),
        )

    def _open_es_menu(
        self,
        *,
        row_index: int | None,
        origin: tuple[int, int],
    ) -> None:
        items: list[tuple[str, str]] = [
            ("inspect", "Inspect Detail"),
            ("refresh", "Refresh View"),
        ]
        if self._current_view == "notables":
            items.append(("triage", "Triage Notable"))
            items.append(("enrich_selected", "Enrich Selected Notable with RF"))
            items.append(("enrich_all", "Enrich All Loaded Notables"))
            items.append(("post_rf_comment", "Post RF Comment to Notable"))
        elif self._current_view == "correlations":
            items.append(("toggle_corr", "Toggle Enable/Disable"))
            items.append(("pivot_spl", "Open SPL in Splunk Search"))
        items.append(("open_logs", "Open Logs Tab"))

        def _on_select(action_id: str) -> None:
            if action_id == "inspect":
                if row_index is not None and 0 <= row_index < len(self._current_rows):
                    self._render_detail(row_index)
                    self.query_one("#es-detail", RichLog).focus()
                else:
                    self.set_status("No row selected to inspect.")
            elif action_id == "refresh":
                self.handle_refresh()
            elif action_id == "triage":
                self.handle_triage_notable()
            elif action_id == "enrich_selected":
                self.handle_enrich_selected()
            elif action_id == "enrich_all":
                self.handle_enrich_all()
            elif action_id == "post_rf_comment":
                self.handle_post_rf_comment()
            elif action_id == "toggle_corr":
                self.handle_toggle_correlation()
            elif action_id == "pivot_spl":
                row = (
                    self._current_rows[row_index]
                    if row_index is not None and 0 <= row_index < len(self._current_rows)
                    else self.get_selected_row()
                )
                spl = str((row or {}).get("search") or "").strip()
                open_fn = getattr(self.app, "open_splunk_search", None)
                if spl and callable(open_fn):
                    open_fn(spl, auto_run=False)
                else:
                    self.set_status("Selected correlation search has no SPL query to load.")
            elif action_id == "open_logs":
                open_logs = getattr(self.app, "open_logs_tab", None)
                if callable(open_logs):
                    open_logs(source="splunk")

        self.open_context_menu(
            items,
            title="Splunk ES",
            origin=origin,
            on_select=_on_select,
        )

    # ------------------------------------------------------------------
    # Refresh / Load Triggers
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#es-refresh-btn")
    @on(Button.Pressed, "#es-load-ti-btn")
    @on(Button.Pressed, "#es-lookup-btn")
    @on(Input.Submitted, "#es-search-input")
    def handle_refresh(self) -> None:
        view = str(self.query_one("#es-view-select", Select).value or "notables")
        self._current_view = view
        search_text = self.query_one("#es-search-input", Input).value.strip()

        if view == "notables":
            urgency = str(self.query_one("#es-urgency-select", Select).value or "").strip() or None
            status = str(self.query_one("#es-status-select", Select).value or "").strip() or None
            earliest = self.query_one("#es-earliest-input", Input).value.strip() or "-24h"
            auto_enrich = bool(self.query_one("#es-auto-enrich-cb", Checkbox).value)
            include_private = bool(self.query_one("#es-private-ips-cb", Checkbox).value)
            field_map_raw = self.query_one("#es-rf-field-map-input", Input).value.strip() or None
            self._load_notables_worker(
                earliest=earliest,
                urgency=urgency,
                status=status,
                search_text=search_text or None,
                auto_enrich=auto_enrich,
                include_private_ips=include_private,
                field_map_override=field_map_raw,
            )
        elif view == "correlations":
            self._load_correlations_worker(search_filter=search_text or None)
        elif view == "threat_intel":
            collection = str(
                self.query_one("#es-collection-select", Select).value
                or THREAT_INTEL_COLLECTIONS[0]
            )
            self._load_threat_intel_worker(collection=collection, filter_text=search_text)
        elif view == "assets_identities":
            kind = str(self.query_one("#es-entity-kind-select", Select).value or "assets")
            self._load_assets_identities_worker(kind=kind, query=search_text)
        elif view == "risk":
            earliest = self.query_one("#es-earliest-input", Input).value.strip() or "-24h"
            self._load_risk_worker(risk_object=search_text or None, earliest=earliest)

    def _get_rf_enricher(self) -> SplunkRFEnricher:
        if self._enricher is None or self._enricher.rf_client is not self.client:
            self._enricher = SplunkRFEnricher(self.client)
        return self._enricher

    def _can_auto_enrich_rf(self) -> bool:
        rf_client = self.client
        if isinstance(rf_client, RecordedFutureClient):
            return bool(rf_client.api_token or get_rf_token(required=False))
        return bool(getattr(rf_client, "api_token", getattr(rf_client, "token", True)))

    def _read_rf_enrichment_options(self) -> tuple[dict[str, list[str]] | None, bool] | None:
        raw_override = self.query_one("#es-rf-field-map-input", Input).value.strip()
        field_map: dict[str, list[str]] | None = None
        if raw_override:
            try:
                field_map = load_splunk_rf_field_map(raw_override)
            except ValueError as exc:
                self.set_status(f"Invalid RF field mapping override: {exc}")
                return None
        include_private = bool(self.query_one("#es-private-ips-cb", Checkbox).value)
        return field_map, include_private

    @work(thread=True, exit_on_error=False)
    def _load_notables_worker(
        self,
        *,
        earliest: str,
        urgency: str | None,
        status: str | None,
        search_text: str | None,
        auto_enrich: bool = False,
        include_private_ips: bool = False,
        field_map_override: str | None = None,
    ) -> None:
        try:
            self.set_status(f"Loading Splunk ES notable events ({earliest} to now)...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    notables = es.list_notables(
                        earliest=earliest,
                        urgency=urgency,
                        status=status,
                        search_text=search_text,
                        limit=100,
                    )
            self.run_on_ui(
                self._populate_table,
                notables,
                _NOTABLE_COLUMNS,
                header_label="Notable Events",
            )
            msg = f"Loaded {len(notables)} Splunk ES notable event(s)."
            self.set_status(msg)
            self.append_log(msg)

            if auto_enrich and notables and self._can_auto_enrich_rf():
                try:
                    self.set_status(
                        f"Auto-enriching {len(notables)} Splunk ES notable event(s) with Recorded Future..."
                    )
                    effective_map = (
                        load_splunk_rf_field_map(field_map_override)
                        if field_map_override
                        else None
                    )
                    enricher = self._get_rf_enricher()
                    with self.log_scope("rf"):
                        enriched = enricher.enrich_events(
                            notables,
                            field_map=effective_map,
                            include_private_ips=include_private_ips,
                        )
                    mapped_cnt = sum(1 for row in enriched if row.get("rf_observables"))
                    self.run_on_ui(
                        self._populate_table,
                        enriched,
                        _NOTABLE_COLUMNS,
                        header_label="Notable Events",
                    )
                    done_msg = (
                        f"Loaded {len(enriched)} Splunk ES notable event(s); "
                        f"RF enriched {mapped_cnt}/{len(enriched)} with mapped IOCs."
                    )
                    self.set_status(done_msg)
                    self.append_log(done_msg)
                except Exception as exc:
                    warn_msg = (
                        f"Loaded {len(notables)} notable(s); RF auto-enrichment skipped: "
                        f"{self.format_exception(exc)}"
                    )
                    self.set_status(warn_msg)
                    self.append_log(warn_msg, level="WARNING")
        except Exception as exc:
            self.report_error("Load ES Notables", exc)

    @work(thread=True, exit_on_error=False)
    def _load_correlations_worker(self, *, search_filter: str | None) -> None:
        try:
            self.set_status("Loading Splunk ES correlation searches...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    items = es.list_correlation_searches(search_filter=search_filter, count=200)
            cols = [
                ("name", "Name"),
                ("enabled", "Enabled"),
                ("severity", "Severity"),
                ("security_domain", "Domain"),
                ("cron_schedule", "Cron"),
                ("action_notable", "Notable"),
                ("action_risk", "Risk"),
            ]
            self.run_on_ui(
                self._populate_table,
                items,
                cols,
                header_label="Correlation Searches",
            )
            msg = f"Loaded {len(items)} Splunk ES correlation search(es)."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Load ES Correlations", exc)

    @work(thread=True, exit_on_error=False)
    def _load_threat_intel_worker(self, *, collection: str, filter_text: str) -> None:
        try:
            self.set_status(f"Loading Threat Intel collection '{collection}'...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    entries = es.query_threat_intel(collection, limit=100)
            if filter_text:
                needle = filter_text.lower()
                entries = [
                    row
                    for row in entries
                    if needle in json.dumps(row, ensure_ascii=False).lower()
                ]
            preferred = [
                "ip",
                "domain",
                "file_hash",
                "url",
                "src_user",
                "description",
                "threat_key",
                "weight",
                "_key",
            ]
            col_keys = _infer_columns(entries, preferred=preferred)
            cols = [(k, k) for k in col_keys]
            self.run_on_ui(
                self._populate_table,
                entries,
                cols,
                header_label=f"Threat Intel ({collection})",
            )
            msg = f"Loaded {len(entries)} entry/entries from '{collection}'."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Load ES Threat Intel", exc)

    @work(thread=True, exit_on_error=False)
    def _load_assets_identities_worker(self, *, kind: str, query: str) -> None:
        try:
            label = "Assets" if kind == "assets" else "Identities"
            self.set_status(f"Looking up Splunk ES {label}...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    rows = (
                        es.lookup_asset(query=query, limit=50)
                        if kind == "assets"
                        else es.lookup_identity(query=query, limit=50)
                    )
            preferred = (
                ["ip", "nt_host", "dns", "mac", "owner", "priority", "category", "bunit"]
                if kind == "assets"
                else ["identity", "email", "first", "last", "priority", "bunit", "category"]
            )
            col_keys = _infer_columns(rows, preferred=preferred)
            cols = [(k, k) for k in col_keys]
            self.run_on_ui(self._populate_table, rows, cols, header_label=f"ES {label}")
            msg = f"Loaded {len(rows)} Splunk ES {label.lower()} record(s)."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("ES Asset/Identity Lookup", exc)

    @work(thread=True, exit_on_error=False)
    def _load_risk_worker(self, *, risk_object: str | None, earliest: str) -> None:
        try:
            self.set_status(f"Loading Splunk ES Risk (RBA) events ({earliest} to now)...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    rows = es.list_risk_events(
                        risk_object=risk_object,
                        earliest=earliest,
                        limit=100,
                    )
            preferred = [
                "_time",
                "risk_object",
                "risk_object_type",
                "risk_score",
                "search_name",
                "risk_message",
            ]
            col_keys = _infer_columns(rows, preferred=preferred)
            cols = [(k, k) for k in col_keys]
            self.run_on_ui(self._populate_table, rows, cols, header_label="Risk Events (RBA)")
            msg = f"Loaded {len(rows)} Splunk ES risk event(s)."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Load ES Risk Events", exc)

    # ------------------------------------------------------------------
    # Contextual Actions (Guarded by Dry-Run & Confirmation)
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#es-triage-btn")
    def handle_triage_notable(self) -> None:
        if self._current_view != "notables":
            self.set_status("Switch to Notable Events view to triage a notable.")
            return
        row = self.get_selected_row()
        if not row:
            self.set_status("Select a notable event before triaging.")
            return
        event_id = str(row.get("event_id") or "").strip()
        if not event_id:
            self.set_status("Selected notable has no event_id to update.")
            return
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Notable triage for '{event_id}' is blocked in read-only dry-run mode."
            self.set_status(msg)
            self.append_log(msg)
            return

        modal = SplunkNotableTriageModal(
            event_id=event_id,
            rule_name=str(row.get("rule_name") or event_id),
            current_status=str(row.get("status_label") or ""),
            current_urgency=str(row.get("urgency") or ""),
            current_owner=str(row.get("owner") or ""),
            current_disposition=str(row.get("disposition") or ""),
            dry_run=self.effective_dry_run,
        )

        def _on_result(result: dict[str, Any] | None) -> None:
            if not result:
                return
            if self.effective_dry_run:
                self.set_status(
                    f"[DRY-RUN] Would update notable '{event_id}' (blocked in dry-run mode)."
                )
                return
            self._apply_notable_triage_worker(event_id, result)

        self.app.push_screen(modal, _on_result)

    @work(thread=True, exit_on_error=False)
    def _apply_notable_triage_worker(self, event_id: str, updates: dict[str, Any]) -> None:
        try:
            self.set_status(f"Updating Splunk ES notable '{event_id}'...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    es.update_notable(
                        [event_id],
                        status=updates.get("status"),
                        urgency=updates.get("urgency"),
                        owner=updates.get("owner"),
                        disposition=updates.get("disposition"),
                        comment=updates.get("comment"),
                    )
            msg = f"Updated Splunk ES notable '{event_id}'."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Notable Updated")
            self.run_on_ui(self.handle_refresh)
        except Exception as exc:
            self.report_error("Update ES Notable", exc)

    @on(Button.Pressed, "#es-toggle-corr-btn")
    def handle_toggle_correlation(self) -> None:
        if self._current_view != "correlations":
            self.set_status("Switch to Correlation Searches view to toggle a search.")
            return
        row = self.get_selected_row()
        if not row:
            self.set_status("Select a correlation search to enable or disable.")
            return
        name = str(row.get("name") or "").strip()
        if not name:
            self.set_status("Selected correlation search has no name.")
            return
        currently_enabled = bool(row.get("enabled", not bool(row.get("disabled", False))))
        target_enabled = not currently_enabled
        action_verb = "Enable" if target_enabled else "Disable"

        if self.effective_dry_run:
            msg = (
                f"[DRY-RUN] Would {action_verb.lower()} correlation search '{name}' "
                f"(blocked in read-only dry-run mode)."
            )
            self.set_status(msg)
            self.append_log(msg)
            return

        self.confirm_destructive_action(
            title=f"{action_verb} Correlation Search",
            message=f"Are you sure you want to {action_verb.lower()} correlation search '{name}'?",
            details=f"Current state: {'Enabled' if currently_enabled else 'Disabled'} -> Target: {'Enabled' if target_enabled else 'Disabled'}",
            confirm_label=f"Confirm {action_verb}",
            on_approved=lambda: self._toggle_correlation_worker(name, target_enabled),
            on_cancelled=lambda: self.set_status(f"Cancelled toggling correlation search '{name}'."),
        )

    @work(thread=True, exit_on_error=False)
    def _toggle_correlation_worker(self, name: str, enabled: bool) -> None:
        try:
            action_verb = "Enabling" if enabled else "Disabling"
            self.set_status(f"{action_verb} correlation search '{name}'...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    es.set_correlation_search_enabled(name, enabled)
            state_label = "enabled" if enabled else "disabled"
            msg = f"Correlation search '{name}' is now {state_label}."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Correlation Search Updated")
            self.run_on_ui(self.handle_refresh)
        except Exception as exc:
            self.report_error("Toggle ES Correlation Search", exc)

    # ------------------------------------------------------------------
    # Recorded Future IOC Enrichment & Comment Write-Back
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#es-enrich-selected-btn")
    def handle_enrich_selected(self) -> None:
        if self._current_view != "notables":
            self.set_status("Switch to Notable Events view to enrich notables with Recorded Future.")
            return
        idx = self._selected_row_index()
        if idx is None or idx < 0 or idx >= len(self._current_rows):
            self.set_status("Select a notable event before enriching with Recorded Future.")
            return
        opts = self._read_rf_enrichment_options()
        if opts is None:
            return
        field_map, include_private = opts
        target_row = dict(self._current_rows[idx])
        self._enrich_notables_worker(
            rows=[target_row],
            row_index=idx,
            field_map=field_map,
            include_private_ips=include_private,
        )

    @on(Button.Pressed, "#es-enrich-all-btn")
    def handle_enrich_all(self) -> None:
        if self._current_view != "notables":
            self.set_status("Switch to Notable Events view to enrich notables with Recorded Future.")
            return
        if not self._current_rows:
            self.set_status("Load notable events before enriching with Recorded Future.")
            return
        opts = self._read_rf_enrichment_options()
        if opts is None:
            return
        field_map, include_private = opts
        rows_copy = [dict(r) for r in self._current_rows]
        self._enrich_notables_worker(
            rows=rows_copy,
            row_index=None,
            field_map=field_map,
            include_private_ips=include_private,
        )

    @work(thread=True, exit_on_error=False)
    def _enrich_notables_worker(
        self,
        *,
        rows: list[dict[str, Any]],
        row_index: int | None,
        field_map: dict[str, list[str]] | None,
        include_private_ips: bool,
    ) -> None:
        try:
            scope_lbl = "selected notable" if row_index is not None else f"{len(rows)} notable(s)"
            self.set_status(f"Enriching {scope_lbl} with Recorded Future SOAR v3...")
            enricher = self._get_rf_enricher()
            with self.log_scope("rf"):
                enriched = enricher.enrich_events(
                    rows,
                    field_map=field_map,
                    include_private_ips=include_private_ips,
                )

            def _apply() -> None:
                if self._current_view != "notables":
                    return
                if row_index is not None:
                    if 0 <= row_index < len(self._current_rows) and enriched:
                        target_eid = str(self._current_rows[row_index].get("event_id") or "")
                        updated_raw = list(self._raw_rows) if self._raw_rows else list(self._current_rows)
                        replaced = False
                        if target_eid:
                            for r_idx, raw_r in enumerate(updated_raw):
                                if str(raw_r.get("event_id") or "") == target_eid:
                                    updated_raw[r_idx] = enriched[0]
                                    replaced = True
                                    break
                        if not replaced and 0 <= row_index < len(updated_raw):
                            updated_raw[row_index] = enriched[0]
                        self._populate_table(
                            updated_raw,
                            _NOTABLE_COLUMNS,
                            header_label="Notable Events",
                            select_row=row_index,
                        )
                else:
                    sel = self._selected_row_index() or 0
                    self._populate_table(
                        enriched,
                        _NOTABLE_COLUMNS,
                        header_label="Notable Events",
                        select_row=sel,
                    )

            self.run_on_ui(_apply)
            mapped_cnt = sum(1 for r in enriched if r.get("rf_observables"))
            msg = (
                f"Recorded Future enrichment complete for {scope_lbl}: "
                f"{mapped_cnt}/{len(enriched)} with mapped IOCs."
            )
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("RF Notable Enrichment", exc)

    @on(Button.Pressed, "#es-post-rf-comment-btn")
    def handle_post_rf_comment(self) -> None:
        if self._current_view != "notables":
            self.set_status("Switch to Notable Events view to post a Recorded Future comment.")
            return
        row = self.get_selected_row()
        if not row:
            self.set_status("Select a notable event before posting a Recorded Future comment.")
            return
        event_id = str(row.get("event_id") or "").strip()
        if not event_id:
            self.set_status("Selected notable has no event_id to update.")
            return
        if "rf_observables" not in row:
            self.set_status(
                "Enrich the selected notable with Recorded Future before posting a comment."
            )
            return

        comment_preview = format_notable_rf_comment(row)
        if self.effective_dry_run:
            msg = (
                f"[DRY-RUN] Would post RF enrichment comment to notable '{event_id}' "
                f"(blocked in read-only dry-run mode)."
            )
            self.set_status(msg)
            self.append_log(f"{msg}\n{comment_preview}")
            return

        self.confirm_destructive_action(
            title="Post Recorded Future Comment to Notable",
            message=f"Post Recorded Future enrichment summary comment to notable '{event_id}'?",
            details=comment_preview,
            confirm_label="Post RF Comment",
            on_approved=lambda: self._post_rf_comment_worker(event_id, dict(row)),
            on_cancelled=lambda: self.set_status(
                f"Cancelled posting RF comment to notable '{event_id}'."
            ),
        )

    @work(thread=True, exit_on_error=False)
    def _post_rf_comment_worker(self, event_id: str, enriched_row: dict[str, Any]) -> None:
        try:
            self.set_status(f"Posting Recorded Future comment to notable '{event_id}'...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    write_enrichment_to_notable(es, event_id, enriched_row, dry_run=False)
            msg = f"Posted Recorded Future enrichment comment to notable '{event_id}'."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="RF Comment Posted")
        except Exception as exc:
            self.report_error("Post RF Comment", exc)
