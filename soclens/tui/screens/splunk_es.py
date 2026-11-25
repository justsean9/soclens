"""Interactive Splunk Enterprise Security (ES) 8.6 Mission Control & 7.x fallback workbench."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from textual import events, on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widgets import Button, Checkbox, Collapsible, DataTable, Input, RichLog, Select, Static

from soclens.client import RecordedFutureClient
from soclens.config import (
    PivotPayload,
    get_rf_token,
    get_splunk_config,
    get_splunk_es_tenant_settings,
)
from soclens.splunk_es import (
    NOTABLE_STATUS_LABELS,
    NOTABLE_STATUS_MAP,
    NOTABLE_URGENCIES,
    SPLUNK_ES_APP,
    THREAT_INTEL_COLLECTIONS,
    SplunkESClient,
    SplunkESError,
    delete_splunk_es_saved_view,
    extract_custom_fields,
    extract_finding_tenant,
    load_splunk_es_saved_views,
    save_splunk_es_saved_view,
)
from soclens.splunk_rf_enrichment import (
    SplunkRFEnricher,
    format_notable_rf_comment,
    load_splunk_rf_field_map,
    write_enrichment_to_notable,
)
from soclens.timezone import parse_iso_datetime
from soclens.tui.filters import (
    ES_TIMEFRAME_OPTIONS,
    SPLUNK_ES_PRESETS,
    timeframe_label,
    timestamp_matches_timeframe,
)
from soclens.tui.modals import SplunkNotableTriageModal
from soclens.tui.pivot import emit_pivot
from soclens.tui.screens.base import BaseSocPane, DoubleClickDataTable
from soclens.tui.screens.es_modals import (
    ESAdaptiveResponseModal,
    ESBulkTriageModal,
    ESCreateFindingModal,
    ESInvestigationModal,
    ESNoteModal,
    ESSavedViewModal,
)

# Local extensions to filters.py constants (filters.py stays read-only in Wave 1C)
_LOCAL_ES_TIMEFRAME_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Last 15m (-15m)", "-15m"),
    ("Last 1h (-60m)", "-1h"),
    ("Last 4h (-4h)", "-4h"),
    *ES_TIMEFRAME_OPTIONS,
    ("Today", "today"),
    ("Week to date", "wtd"),
)

_LOCAL_SPLUNK_ES_PRESETS: tuple[dict[str, Any], ...] = (
    *SPLUNK_ES_PRESETS,
    {
        "id": "owned_by_me",
        "label": "Owned by me",
        "earliest": "-7d",
        "timeframe": "-7d",
        "statuses": (),
        "urgencies": (),
        "owner_mode": "me",
    },
    {
        "id": "reran_findings",
        "label": "Re-ran findings",
        "earliest": "-7d",
        "timeframe": "-7d",
        "statuses": (),
        "urgencies": (),
        "owner_mode": "any",
        "reran_only": True,
    },
    {
        "id": "risk_score",
        "label": "Risk score >= 50",
        "earliest": "-7d",
        "timeframe": "-7d",
        "statuses": (),
        "urgencies": (),
        "owner_mode": "any",
        "min_risk_score": 50.0,
    },
    {
        "id": "suppressed",
        "label": "Suppressed",
        "earliest": "-30d",
        "timeframe": "-30d",
        "statuses": (),
        "urgencies": (),
        "owner_mode": "any",
        "suppressed_only": True,
    },
)

_ES_TIMEFRAME_EARLIEST_MAP: dict[str, str] = {
    "-15m": "-15m",
    "-1h": "-1h",
    "-4h": "-4h",
    "-24h": "-24h",
    "-48h": "-48h",
    "-7d": "-7d",
    "-14d": "-14d",
    "-30d": "-30d",
    "-90d": "-90d",
    "today": "@d",
    "wtd": "@w0",
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

_ITEM_TYPE_PILLS: tuple[tuple[str, str, str], ...] = (
    ("es-type-all-btn", "All types", "all"),
    ("es-type-investigations-btn", "Investigations", "investigations"),
    ("es-type-groups-btn", "Finding groups", "finding_groups"),
    ("es-type-findings-btn", "Findings", "findings"),
)

_INSPECTOR_TABS: tuple[tuple[str, str, str], ...] = (
    ("es-insp-tab-overview", "Overview", "overview"),
    ("es-insp-tab-metadata", "Metadata & Custom", "metadata"),
    ("es-insp-tab-srcdest", "Src / Dest", "srcdest"),
    ("es-insp-tab-rf", "RF Enrichment", "rf"),
    ("es-insp-tab-notes", "Notes & History", "notes"),
    ("es-insp-tab-raw", "Raw JSON", "raw"),
)

_MAX_CELL_LEN = 72
_MAX_DYNAMIC_COLS = 10

_NOTABLE_BASE_COLUMNS: list[tuple[str, str]] = [
    ("selected", "[x]"),
    ("_time", "Time"),
    ("tenant_id", "Tenant"),
    ("urgency", "Urgency"),
    ("status_label", "Status"),
    ("disposition", "Disposition"),
    ("title", "Title"),
    ("entity", "Entity"),
    ("risk_score", "Score"),
    ("owner", "Owner"),
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

_STRUCTURED_TOKEN_RE = re.compile(r"([A-Za-z0-9_.-]+):(?:\"([^\"]+)\"|([^\s]+))")
_SLUG_RE = re.compile(r"[^a-z0-9]+")


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
            if key_str in {"raw", "custom_fields"} or key_str in seen:
                continue
            seen.add(key_str)
            ordered.append(key_str)
    return ordered[:_MAX_DYNAMIC_COLS]


def _es_timeframe_label(tf_val: str) -> str:
    for lbl, val in _LOCAL_ES_TIMEFRAME_OPTIONS:
        if val == tf_val:
            return lbl
    return timeframe_label(tf_val)


def _parse_utc_dt(ts_val: Any) -> datetime | None:
    parsed = parse_iso_datetime(ts_val)
    if parsed is None:
        return None
    dt, _has_time = parsed
    return dt.astimezone(UTC)


def _es_timestamp_matches(ts_val: Any, tf_val: str) -> bool:
    if tf_val == "any":
        return True
    if tf_val in {"today", "wtd"}:
        dt = _parse_utc_dt(ts_val)
        if dt is None:
            return False
        now = datetime.now(UTC)
        if tf_val == "today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            start = (now - timedelta(days=now.weekday())).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        return dt >= start
    return timestamp_matches_timeframe(ts_val, tf_val)


def _parse_structured_search(query: str) -> tuple[dict[str, str], list[str]]:
    """Parse ``key:value`` structured tokens and remaining free-text tokens."""
    facets: dict[str, str] = {}
    used_spans: list[tuple[int, int]] = []
    for match in _STRUCTURED_TOKEN_RE.finditer(query):
        key = match.group(1).strip().casefold()
        val = (match.group(2) if match.group(2) is not None else match.group(3) or "").strip()
        if key and val:
            facets[key] = val
            used_spans.append(match.span())

    if not used_spans:
        terms = [t for t in query.strip().split() if t]
        return {}, terms

    parts: list[str] = []
    cursor = 0
    for start, end in used_spans:
        if start > cursor:
            parts.append(query[cursor:start])
        cursor = end
    if cursor < len(query):
        parts.append(query[cursor:])
    leftover = " ".join(parts).strip()
    terms = [t for t in leftover.split() if t] if leftover else []
    return facets, terms


def _build_ascii_sparkline(rows: list[dict[str, Any]], buckets: int = 12) -> str:
    """Render a compact ASCII timeline sparkline over finding timestamps."""
    glyphs = " .:-=+*#%@"
    parsed: list[datetime] = []
    for row in rows:
        dt = _parse_utc_dt(row.get("_time") or row.get("created") or row.get("updated"))
        if dt is not None:
            parsed.append(dt)
    if not parsed:
        return "." * buckets
    t_min = min(parsed)
    t_max = max(parsed)
    span = (t_max - t_min).total_seconds()
    counts = [0] * buckets
    if span <= 0:
        counts[-1] = len(parsed)
    else:
        for dt in parsed:
            pos = int(((dt - t_min).total_seconds() / span) * (buckets - 1))
            pos = max(0, min(buckets - 1, pos))
            counts[pos] += 1
    peak = max(counts) or 1
    return "".join(glyphs[min(len(glyphs) - 1, int((c / peak) * (len(glyphs) - 1)))] for c in counts)


class SplunkESPane(BaseSocPane):
    """Splunk ES 8.6 Mission Control & 7.x fallback workbench pane."""

    STATUS_ID = "es-status"
    LOG_ID = ""
    LOG_SOURCE = "splunk"

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("space", "toggle_select_row", "Select Row", show=False),
        Binding("slash", "toggle_structured_filters", "Filters", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    SplunkESPane #es-mc-toolbar,
    SplunkESPane #es-mc-actions-row,
    SplunkESPane #es-bulk-bar,
    SplunkESPane #es-pagination-row {
        height: auto;
        min-height: 1;
        width: 1fr;
    }
    SplunkESPane #es-inspector-tabs {
        layout: grid;
        grid-size: 3;
        grid-rows: 1;
        grid-gutter: 0 1;
        height: auto;
        width: 1fr;
    }
    SplunkESPane #es-inspector-actions {
        layout: grid;
        grid-size: 4;
        grid-rows: 1;
        grid-gutter: 0 1;
        height: auto;
        width: 1fr;
    }
    SplunkESPane #es-mc-toolbar Button,
    SplunkESPane #es-mc-actions-row Button,
    SplunkESPane #es-bulk-bar Button,
    SplunkESPane #es-pagination-row Button {
        min-width: 6;
        margin-right: 1;
    }
    SplunkESPane #es-inspector-tabs Button,
    SplunkESPane #es-inspector-actions Button {
        width: 1fr;
        min-width: 5;
    }
    SplunkESPane .es-pill-active {
        background: $accent;
        color: $text;
        text-style: bold;
    }
    SplunkESPane #es-sparkline-strip {
        height: 1;
        width: 1fr;
        padding: 0 1;
        background: #141c2c;
        color: #9ed0ff;
    }
    SplunkESPane #es-structured-filter-collapsible {
        height: auto;
        margin-bottom: 0;
    }
    SplunkESPane #es-structured-filter-grid {
        layout: grid;
        grid-size: 5;
        grid-gutter: 1 0;
        height: auto;
        width: 1fr;
    }
    SplunkESPane #es-structured-filter-grid Input {
        width: 1fr;
        margin-right: 0;
    }
    SplunkESPane.es-compact #es-structured-filter-grid {
        grid-size: 3;
    }
    SplunkESPane.es-compact #es-status {
        height: 1 !important;
    }
    SplunkESPane.es-compact #es-toolbar-row1 {
        padding: 0 !important;
        height: 1 !important;
    }
    SplunkESPane.es-compact #es-toolbar-row1 Select {
        width: 1fr !important;
        min-width: 10 !important;
        margin-right: 1 !important;
    }
    SplunkESPane.es-compact #es-earliest-input {
        width: 10 !important;
        margin-right: 0 !important;
    }
    SplunkESPane.es-compact #es-filter-bar {
        padding: 0 !important;
        height: 1 !important;
    }
    SplunkESPane.es-compact #es-urgency-select,
    SplunkESPane.es-compact #es-status-select {
        width: 13 !important;
        margin-right: 1 !important;
    }
    SplunkESPane.es-compact #es-search-input {
        width: 1fr !important;
        min-width: 10 !important;
        margin-right: 1 !important;
    }
    SplunkESPane.es-compact #es-filter-bar Button {
        min-width: 4 !important;
        margin-right: 1 !important;
    }
    SplunkESPane.es-compact #es-clear-filter-btn {
        margin-right: 0 !important;
    }
    SplunkESPane.es-compact #es-mc-toolbar {
        layout: grid;
        grid-size: 7;
        grid-rows: 1;
        grid-gutter: 0 1;
        padding: 0 !important;
        height: 1 !important;
    }
    SplunkESPane.es-compact #es-mc-actions-row {
        layout: grid;
        grid-size: 6;
        grid-rows: 1;
        grid-gutter: 0 1;
        padding: 0 !important;
        height: 1 !important;
    }
    SplunkESPane.es-compact #es-rf-controls-row {
        layout: grid;
        grid-size: 5;
        grid-rows: 1;
        grid-gutter: 0 1;
        padding: 0 !important;
        height: 1 !important;
    }
    SplunkESPane.es-compact #es-bulk-bar {
        layout: grid;
        grid-size: 6;
        grid-rows: 1;
        grid-gutter: 0 1;
        padding: 0 !important;
        height: 1 !important;
    }
    SplunkESPane.es-compact #es-mc-toolbar Button,
    SplunkESPane.es-compact #es-mc-actions-row Button,
    SplunkESPane.es-compact #es-rf-controls-row Button,
    SplunkESPane.es-compact #es-rf-controls-row Checkbox,
    SplunkESPane.es-compact #es-bulk-bar Button,
    SplunkESPane.es-compact #es-inspector-tabs Button,
    SplunkESPane.es-compact #es-inspector-actions Button {
        width: 1fr !important;
        min-width: 2 !important;
        margin-right: 0 !important;
        padding: 0 1 !important;
    }
    SplunkESPane.es-compact #es-rf-controls-row Checkbox {
        padding: 0 !important;
    }
    SplunkESPane.es-compact #es-workspace {
        min-height: 6 !important;
    }
    SplunkESPane.es-compact #es-workspace.split-horizontal {
        min-height: 6 !important;
    }
    SplunkESPane.es-compact #es-workspace.split-horizontal > #es-master-pane {
        width: 42% !important;
        min-height: 4 !important;
        margin-right: 1 !important;
    }
    SplunkESPane.es-compact #es-workspace.split-horizontal > #es-detail-pane {
        width: 58% !important;
        min-height: 4 !important;
    }
    SplunkESPane.es-compact #es-table {
        min-height: 3 !important;
        border: none !important;
    }
    SplunkESPane.es-compact #es-detail {
        min-height: 2 !important;
        border: none !important;
    }
    SplunkESPane.es-compact #es-prev-finding-btn,
    SplunkESPane.es-compact #es-next-finding-btn {
        min-width: 5 !important;
        margin-left: 1 !important;
    }
    SplunkESPane #es-bulk-bar {
        background: #1e2738;
        padding: 0 1;
    }
    SplunkESPane #es-page-label {
        width: auto;
        padding: 0 1;
        color: $text-muted;
    }
    SplunkESPane #es-workspace {
        height: 1fr;
        min-height: 10;
    }
    SplunkESPane #es-table {
        height: 1fr;
        min-height: 4;
    }
    SplunkESPane #es-detail {
        height: 1fr;
        min-height: 4;
    }
    SplunkESPane #es-detail-toolbar {
        height: 1;
        width: 1fr;
    }
    SplunkESPane #es-detail-header {
        width: 1fr;
        height: 1;
    }
    SplunkESPane #es-prev-finding-btn,
    SplunkESPane #es-next-finding-btn {
        min-width: 7;
        margin-left: 1;
    }
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._current_view: str = "notables"
        self._raw_rows: list[dict[str, Any]] = []
        self._raw_columns: list[tuple[str, str]] = []
        self._raw_header_label: str = "Notable Events"
        self._current_rows: list[dict[str, Any]] = []
        self._displayed_rows: list[dict[str, Any]] = []
        self._rendering_table: bool = False
        self._enricher: SplunkRFEnricher | None = None
        self._active_preset_id: str = "all"
        self._local_timeframe: str = "any"
        self._preset_statuses: tuple[str, ...] = ()
        self._preset_urgencies: tuple[str, ...] = ()
        self._preset_owner_mode: str = "any"
        self._preset_reran_only: bool = False
        self._preset_min_risk: float | None = None
        self._preset_suppressed_only: bool = False
        self._syncing_es_filters: bool = False
        self._es_ready: bool = False

        # Mission Control & WS1 state
        self._request_seq: int = 0
        self._loading: bool = False
        self._source_backend: str = "spl_fallback"
        self._item_type: str = "all"
        self._inspector_tab: str = "overview"
        self._selected_ids: set[str] = set()
        self._group_by_tenant: bool = False
        self._collapsed_tenants: set[str] = set()
        self._sort_col: str = ""
        self._sort_desc: bool = False
        self._page_offset: int = 0
        self._page_size: int = 50
        self._total_display_items: int = 0
        self._auto_refresh_enabled: bool = False
        self._refresh_timer: Timer | None = None
        self._sparkline_visible: bool = False
        self._discovered_fields: list[dict[str, str]] = []
        self._discovered_labels: dict[str, str] = {}
        self._splunk_users: list[str] = []
        self._current_splunk_user: str = ""
        self._notes_history_cache: dict[str, dict[str, Any]] = {}
        self._custom_views: dict[str, dict[str, Any]] = {}
        self._structured_preset_filters: dict[str, str] = {}
        self._last_s1_context: dict[str, Any] | None = None

    def _get_all_presets_by_id(self) -> dict[str, dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {p["id"]: p for p in _LOCAL_SPLUNK_ES_PRESETS}
        merged.update(self._custom_views)
        return merged

    def _build_preset_options(self) -> list[tuple[str, str]]:
        opts: list[tuple[str, str]] = [
            (str(p["label"]), str(p["id"])) for p in _LOCAL_SPLUNK_ES_PRESETS
        ]
        for view_id, view in self._custom_views.items():
            opts.append((f"[Saved] {view.get('label', view_id)}", view_id))
        opts.append(("Custom Filter", "__custom__"))
        return opts

    def compose(self) -> ComposeResult:
        try:
            for item in load_splunk_es_saved_views():
                vid = str(item.get("id") or "").strip()
                if vid:
                    self._custom_views[vid] = item
        except Exception:
            pass

        urgency_options: list[tuple[str, str]] = [("All Urgencies", "")] + [
            (u.title(), u) for u in NOTABLE_URGENCIES
        ]
        status_options: list[tuple[str, str]] = [("All Statuses", "")] + [
            (NOTABLE_STATUS_LABELS[code], key) for key, code in NOTABLE_STATUS_MAP.items()
        ]
        collection_options: list[tuple[str, str]] = [
            (col, col) for col in THREAT_INTEL_COLLECTIONS
        ]
        preset_options = self._build_preset_options()

        yield Static("Splunk Enterprise Security (ES) Workbench", classes="pane-title")
        yield Static(
            "Select an ES view and click Refresh to load Findings, Correlations, Threat Intel, Assets/IDs, or RBA.",
            id="es-status",
            classes="status-bar",
            markup=False,
        )

        with Horizontal(id="es-toolbar-row1", classes="action-row toolbar-row"):
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
                _LOCAL_ES_TIMEFRAME_OPTIONS,
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

        with Horizontal(id="es-filter-bar", classes="action-row filter-bar"):
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
                placeholder="Search (tenant_id:ACME, owner:jdoe, _raw:hit, or text)...",
                id="es-search-input",
                compact=True,
            )
            yield Button("Refresh", id="es-refresh-btn", variant="primary", compact=True)
            yield Button("Triage Notable", id="es-triage-btn", compact=True)
            yield Button("Toggle Enable/Disable", id="es-toggle-corr-btn", compact=True)
            yield Button("Load Collection", id="es-load-ti-btn", compact=True)
            yield Button("Lookup", id="es-lookup-btn", compact=True)
            yield Button("Reset", id="es-clear-filter-btn", compact=True)

        with Horizontal(id="es-mc-toolbar", classes="action-row toolbar-row"):
            for pill_id, pill_lbl, pill_val in _ITEM_TYPE_PILLS:
                classes = "es-pill-active" if pill_val == "all" else ""
                yield Button(pill_lbl, id=pill_id, classes=classes, compact=True)
            yield Button("Group by Tenant", id="es-group-tenant-btn", compact=True)
            yield Button("Auto: OFF", id="es-auto-refresh-btn", compact=True)
            yield Button("Timeline", id="es-sparkline-toggle-btn", compact=True)

        with Horizontal(id="es-mc-actions-row", classes="action-row toolbar-row"):
            yield Button("Select Page", id="es-select-page-btn", compact=True)
            yield Button("Select All", id="es-select-all-btn", compact=True)
            yield Button("Save View", id="es-save-view-btn", compact=True)
            yield Button("Del View", id="es-del-view-btn", compact=True)
            yield Button("+ Finding", id="es-create-finding-btn", compact=True)
            yield Button("+ Investigation", id="es-new-inv-btn", compact=True)

        with Collapsible(
            title="Structured Filters (tenant_id, disposition, owner, domain, entity, hash, _raw)",
            collapsed=True,
            id="es-structured-filter-collapsible",
        ):
            with Horizontal(id="es-structured-filter-grid", classes="action-row"):
                yield Input(value="", placeholder="Tenant ID", id="es-filter-tenant", compact=True)
                yield Input(value="", placeholder="Disposition", id="es-filter-disposition", compact=True)
                yield Input(value="", placeholder="Owner", id="es-filter-owner", compact=True)
                yield Input(value="", placeholder="Domain", id="es-filter-domain", compact=True)
                yield Input(value="", placeholder="Entity/Host/IP", id="es-filter-entity", compact=True)
                yield Input(value="", placeholder="File Hash", id="es-filter-hash", compact=True)
                yield Input(value="", placeholder="Min Score", id="es-filter-min-score", compact=True)
                yield Input(value="", placeholder="ID", id="es-filter-id", compact=True)
                yield Input(value="", placeholder="_raw", id="es-filter-raw", compact=True)

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
        yield Static("", id="es-sparkline-strip", markup=False)

        with Horizontal(id="es-bulk-bar", classes="action-row"):
            yield Button("Deselect", id="es-deselect-btn", compact=True)
            yield Button("Bulk Triage", id="es-bulk-triage-btn", variant="primary", compact=True)
            yield Button("Assign to me", id="es-assign-me-btn", compact=True)
            yield Button("Move to Investigation", id="es-move-inv-btn", compact=True)
            yield Button("Suppress", id="es-suppress-btn", compact=True)
            yield Button("Enrich Selected", id="es-bulk-enrich-btn", compact=True)

        with Container(id="es-workspace", classes="split-workspace"):
            with Vertical(id="es-master-pane", classes="table-pane"):
                yield Static(
                    "Notable Events (0)",
                    id="es-table-header",
                    classes="section-label",
                    markup=False,
                )
                yield DoubleClickDataTable(id="es-table")
                with Horizontal(id="es-pagination-row", classes="action-row"):
                    yield Button("< Page", id="es-prev-page-btn", compact=True)
                    yield Static("Page 1/1", id="es-page-label", markup=False)
                    yield Button("Page >", id="es-next-page-btn", compact=True)

            with Vertical(id="es-detail-pane"):
                with Horizontal(id="es-detail-toolbar", classes="detail-toolbar"):
                    yield Static(
                        "Detail",
                        id="es-detail-header",
                        classes="section-label",
                        markup=False,
                    )
                    yield Button("< Prev", id="es-prev-finding-btn", compact=True)
                    yield Button("Next >", id="es-next-finding-btn", compact=True)
                with Container(id="es-inspector-tabs"):
                    for tab_id, tab_lbl, tab_key in _INSPECTOR_TABS:
                        cls = "es-pill-active" if tab_key == "overview" else ""
                        yield Button(tab_lbl, id=tab_id, classes=cls, compact=True)
                with Container(id="es-inspector-actions"):
                    yield Button("Assign Me", id="es-insp-assign-me-btn", compact=True)
                    yield Button("Add Note", id="es-insp-add-note-btn", compact=True)
                    yield Button("Adaptive Resp", id="es-insp-ar-btn", compact=True)
                    yield Button("Investigations", id="es-insp-inv-btn", compact=True)
                    yield Button("Pivot F8", id="es-insp-pivot-search-btn", compact=True)
                    yield Button("Pivot S1", id="es-insp-pivot-s1-btn", compact=True)
                    yield Button("Copilot F7", id="es-insp-pivot-llm-btn", compact=True)
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
        self.query_one("#es-sparkline-strip", Static).display = False
        self.query_one("#es-bulk-bar", Horizontal).display = False
        self._sync_controls_for_view(self._current_view)
        self._update_split_layout()
        self._refresh_timer = self.set_interval(30.0, self._on_auto_refresh_tick)
        self.call_after_refresh(self._mark_es_ready)

    def on_unmount(self) -> None:
        if self._refresh_timer is not None:
            try:
                self._refresh_timer.stop()
            except Exception:
                pass
            self._refresh_timer = None

    def _mark_es_ready(self) -> None:
        self._es_ready = True

    def on_resize(self) -> None:
        self._update_split_layout()

    def on_tab_activated(self) -> None:
        self._update_split_layout()

    def _sync_compact_labels(self, compact: bool) -> None:
        button_labels: tuple[tuple[str, str, str], ...] = (
            ("#es-triage-btn", "Triage", "Triage Notable"),
            ("#es-type-all-btn", "All", "All types"),
            ("#es-type-investigations-btn", "Invs", "Investigations"),
            ("#es-type-groups-btn", "Groups", "Finding groups"),
            ("#es-type-findings-btn", "Findings", "Findings"),
            ("#es-group-tenant-btn", "Tenants", "Group by Tenant"),
            ("#es-sparkline-toggle-btn", "Trend", "Timeline"),
            ("#es-select-page-btn", "Sel Page", "Select Page"),
            ("#es-select-all-btn", "Sel All", "Select All"),
            ("#es-save-view-btn", "Save Vw", "Save View"),
            ("#es-del-view-btn", "Del Vw", "Del View"),
            ("#es-create-finding-btn", "+Finding", "+ Finding"),
            ("#es-new-inv-btn", "+Inv", "+ Investigation"),
            ("#es-enrich-selected-btn", "Enrich Sel", "Enrich Selected"),
            ("#es-enrich-all-btn", "Enrich All", "Enrich All"),
            ("#es-post-rf-comment-btn", "Post RF", "Post RF Comment"),
            ("#es-deselect-btn", "Deselect", "Deselect"),
            ("#es-bulk-triage-btn", "Triage", "Bulk Triage"),
            ("#es-assign-me-btn", "AssignMe", "Assign to me"),
            ("#es-move-inv-btn", "Move>Inv", "Move to Investigation"),
            ("#es-suppress-btn", "Suppress", "Suppress"),
            ("#es-bulk-enrich-btn", "EnrichSel", "Enrich Selected"),
            ("#es-insp-tab-overview", "Overview", "Overview"),
            ("#es-insp-tab-metadata", "Metadata", "Metadata & Custom"),
            ("#es-insp-tab-srcdest", "Src/Dest", "Src / Dest"),
            ("#es-insp-tab-rf", "RF", "RF Enrichment"),
            ("#es-insp-tab-notes", "Notes", "Notes & History"),
            ("#es-insp-tab-raw", "Raw", "Raw JSON"),
            ("#es-insp-assign-me-btn", "Assign", "Assign Me"),
            ("#es-insp-add-note-btn", "Note", "Add Note"),
            ("#es-insp-ar-btn", "AR", "Adaptive Resp"),
            ("#es-insp-inv-btn", "Invs", "Investigations"),
            ("#es-insp-pivot-search-btn", "F8 SPL", "Pivot F8"),
            ("#es-insp-pivot-s1-btn", "S1 (9)", "Pivot S1"),
            ("#es-insp-pivot-llm-btn", "F7 LLM", "Copilot F7"),
        )
        for sel, short_lbl, full_lbl in button_labels:
            try:
                self.query_one(sel, Button).label = short_lbl if compact else full_lbl
            except Exception:
                pass
        try:
            auto_btn = self.query_one("#es-auto-refresh-btn", Button)
            if compact:
                auto_btn.label = "Auto:30s" if self._auto_refresh_enabled else "Auto:OFF"
            else:
                auto_btn.label = "Auto: 30s" if self._auto_refresh_enabled else "Auto: OFF"
        except Exception:
            pass
        for sel, short_lbl, full_lbl in (
            ("#es-auto-enrich-cb", "Auto RF", "Auto-Enrich RF"),
            ("#es-private-ips-cb", "Priv IP", "Include Private IPs"),
        ):
            try:
                self.query_one(sel, Checkbox).label = short_lbl if compact else full_lbl
            except Exception:
                pass

    def _apply_compact_inline_styles(self, compact: bool) -> None:
        bar_ids = (
            "#es-status",
            "#es-summary-bar",
            "#es-sparkline-strip",
            "#es-table-header",
            "#es-detail-header",
        )
        if compact:
            for row_id in (
                "#es-toolbar-row1",
                "#es-filter-bar",
                "#es-mc-toolbar",
                "#es-mc-actions-row",
                "#es-rf-controls-row",
                "#es-bulk-bar",
            ):
                rw = self.query_one(row_id)
                rw.styles.height = 1
                rw.styles.padding = (0, 0)
            for bar_id in bar_ids:
                bar = self.query_one(bar_id)
                bar.styles.height = 1
                bar.styles.max_height = 1
                bar.styles.overflow_y = "hidden"
            for sel_id in (
                "#es-view-select",
                "#es-preset-select",
                "#es-timeframe-select",
                "#es-collection-select",
                "#es-entity-kind-select",
            ):
                w = self.query_one(sel_id)
                w.styles.width = "1fr"
                w.styles.min_width = 8
                w.styles.margin = (0, 1, 0, 0)
            earliest = self.query_one("#es-earliest-input")
            earliest.styles.width = 9
            earliest.styles.margin = (0, 0, 0, 0)
            for sel_id in ("#es-urgency-select", "#es-status-select"):
                w = self.query_one(sel_id)
                w.styles.width = 12
                w.styles.margin = (0, 1, 0, 0)
            search_inp = self.query_one("#es-search-input")
            search_inp.styles.width = "1fr"
            search_inp.styles.min_width = 8
            search_inp.styles.margin = (0, 1, 0, 0)
            master = self.query_one("#es-master-pane")
            master.styles.width = "42%"
            master.styles.min_height = 4
            detail_pane = self.query_one("#es-detail-pane")
            detail_pane.styles.width = "58%"
            detail_pane.styles.min_height = 4
            table = self.query_one("#es-table")
            table.styles.min_height = 3
            table.styles.border = ("none", "transparent")
            detail = self.query_one("#es-detail")
            detail.styles.min_height = 2
            detail.styles.border = ("none", "transparent")
        else:
            for row_id in (
                "#es-toolbar-row1",
                "#es-filter-bar",
                "#es-mc-toolbar",
                "#es-mc-actions-row",
                "#es-rf-controls-row",
                "#es-bulk-bar",
            ):
                rw = self.query_one(row_id)
                rw.styles.height = None
                rw.styles.padding = None
            for bar_id in bar_ids:
                bar = self.query_one(bar_id)
                bar.styles.height = None
                bar.styles.max_height = None
                bar.styles.overflow_y = None
            for sel_id in (
                "#es-view-select",
                "#es-preset-select",
                "#es-timeframe-select",
                "#es-collection-select",
                "#es-entity-kind-select",
                "#es-earliest-input",
                "#es-urgency-select",
                "#es-status-select",
                "#es-search-input",
                "#es-master-pane",
                "#es-detail-pane",
                "#es-table",
                "#es-detail",
            ):
                w = self.query_one(sel_id)
                w.styles.width = None
                w.styles.min_width = None
                w.styles.margin = None
                w.styles.min_height = None
                w.styles.border = None

    def _update_split_layout(self) -> None:
        if self.is_app_shutting_down():
            return
        try:
            compact_small = self.size.width < 100 or self.size.height <= 26
            self.set_class(compact_small, "es-compact")
            self._sync_compact_labels(compact_small)
            self._apply_compact_inline_styles(compact_small)
            ws = self.query_one("#es-workspace", Container)
            if self.size.width >= 110 or (compact_small and self.size.width >= 76):
                ws.add_class("split-horizontal")
            else:
                ws.remove_class("split-horizontal")
            if compact_small:
                self.query_one("#es-structured-filter-collapsible", Collapsible).collapsed = True
                self.query_one("#es-rf-map-collapsible", Collapsible).collapsed = True
                if not self._sparkline_visible:
                    self.query_one("#es-sparkline-strip", Static).display = False
        except Exception:
            pass

    def _build_es_client(self) -> SplunkESClient:
        cfg = get_splunk_config(app=SPLUNK_ES_APP, required=True)
        stop_event = None
        try:
            stop_event = getattr(self.app, "_stop_event", None)
        except Exception:
            stop_event = None
        return SplunkESClient(
            host=cfg.host,
            token=cfg.token,
            username=cfg.username,
            password=cfg.password,
            app=cfg.app,
            verify_ssl=cfg.verify_ssl,
            stop_event=stop_event,
        )

    def _get_notable_columns(self) -> list[tuple[str, str]]:
        cols = list(_NOTABLE_BASE_COLUMNS)
        existing_keys = {k for k, _ in cols}
        try:
            tenant_cfg = get_splunk_es_tenant_settings()
            for field in tenant_cfg.custom_fields:
                clean = field.strip()
                if clean and clean not in existing_keys:
                    existing_keys.add(clean)
                    label = self._discovered_labels.get(clean, clean)
                    cols.append((clean, label))
        except Exception:
            pass
        return cols

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
        self.query_one("#es-mc-toolbar", Horizontal).display = is_notables
        self.query_one("#es-mc-actions-row", Horizontal).display = is_notables
        self.query_one("#es-structured-filter-collapsible", Collapsible).display = is_notables
        self.query_one("#es-rf-controls-row", Horizontal).display = is_notables
        self.query_one("#es-rf-map-collapsible", Collapsible).display = is_notables
        self.query_one("#es-inspector-tabs", Container).display = is_notables
        self.query_one("#es-inspector-actions", Container).display = is_notables
        self.query_one("#es-bulk-bar", Horizontal).display = is_notables and bool(self._selected_ids)
        self.query_one("#es-sparkline-strip", Static).display = (
            is_notables and self._sparkline_visible
        )

        search_input = self.query_one("#es-search-input", Input)
        if is_notables:
            search_input.placeholder = "Search (tenant_id:ACME, owner:jdoe, _raw:hit, or text)..."
        elif is_corr:
            search_input.placeholder = "Filter correlation searches..."
        elif is_ti:
            search_input.placeholder = "Optional KV Store filter substring..."
        elif is_ai:
            search_input.placeholder = "Lookup asset or identity (IP, host, user, email)..."
        else:
            search_input.placeholder = "Filter by risk_object (host, IP, user)..."

        self.query_one("#es-table-header", Static).update(
            f"{self._view_header_title(view)} ({len(self._current_rows)})"
        )
        self._update_summary_bar()

    @on(Select.Changed, "#es-view-select")
    def handle_view_changed(self, event: Select.Changed) -> None:
        view = str(event.value or "notables")
        self._request_seq += 1
        self._raw_rows = []
        self._current_rows = []
        self._displayed_rows = []
        self._selected_ids.clear()
        self._page_offset = 0
        self._total_display_items = 0
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

    def _is_auto_refresh_paused(self) -> bool:
        if self._selected_ids or self._loading or self.is_app_shutting_down():
            return True
        try:
            if isinstance(self.app.screen, ModalScreen):
                return True
        except Exception:
            return True
        return False

    def _on_auto_refresh_tick(self) -> None:
        if not self._auto_refresh_enabled or self._current_view != "notables":
            return
        if self._is_auto_refresh_paused():
            self._update_summary_bar()
            return
        self.handle_refresh()

    @on(Button.Pressed, "#es-auto-refresh-btn")
    def handle_toggle_auto_refresh(self) -> None:
        self._auto_refresh_enabled = not self._auto_refresh_enabled
        btn = self.query_one("#es-auto-refresh-btn", Button)
        if self.has_class("es-compact"):
            btn.label = "Auto:30s" if self._auto_refresh_enabled else "Auto:OFF"
        else:
            btn.label = "Auto: 30s" if self._auto_refresh_enabled else "Auto: OFF"
        if self._auto_refresh_enabled:
            btn.add_class("es-pill-active")
        else:
            btn.remove_class("es-pill-active")
        self._update_summary_bar()

    @on(Button.Pressed, "#es-sparkline-toggle-btn")
    def handle_toggle_sparkline(self) -> None:
        self._sparkline_visible = not self._sparkline_visible
        strip = self.query_one("#es-sparkline-strip", Static)
        strip.display = self._sparkline_visible and self._current_view == "notables"
        btn = self.query_one("#es-sparkline-toggle-btn", Button)
        if self._sparkline_visible:
            btn.add_class("es-pill-active")
        else:
            btn.remove_class("es-pill-active")
        self._update_sparkline_strip()

    def _update_sparkline_strip(self) -> None:
        try:
            strip = self.query_one("#es-sparkline-strip", Static)
        except Exception:
            return
        if not self._sparkline_visible or self._current_view != "notables":
            return
        rows = self._current_rows
        spark = _build_ascii_sparkline(rows)
        crit_cnt = sum(1 for r in rows if str(r.get("urgency") or "").lower() == "critical")
        high_cnt = sum(1 for r in rows if str(r.get("urgency") or "").lower() == "high")
        new_cnt = sum(1 for r in rows if str(r.get("status_label") or "").lower() == "new")
        tenants = {
            str(r.get("tenant_id") or "").strip()
            for r in rows
            if str(r.get("tenant_id") or "").strip() not in {"", "-"}
        }
        strip.update(
            f"Timeline [{spark}] | Crit:{crit_cnt} High:{high_cnt} | New:{new_cnt} | Tenants:{len(tenants)}"
        )

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
            presets = self._get_all_presets_by_id()
            preset_obj = presets.get(self._active_preset_id)
            if preset_obj is not None and self._active_preset_id != "all":
                parts.append(f"View: {preset_obj['label']}")
            elif self._local_timeframe != "any":
                parts.append(f"Time: {_es_timeframe_label(self._local_timeframe)}")
            if self._item_type != "all":
                parts.append(f"Type: {self._item_type}")
            if self._group_by_tenant:
                parts.append("Grouped: Tenant")
            if self._selected_ids:
                parts.append(f"Selected: {len(self._selected_ids)}")
            if self._auto_refresh_enabled:
                parts.append("Auto: PAUSED" if self._is_auto_refresh_paused() else "Auto: 30s")
            if self._source_backend == "mc_v2":
                parts.append("MC v2")
        elif self._current_view == "risk" and self._local_timeframe != "any":
            parts.append(f"Time: {_es_timeframe_label(self._local_timeframe)}")
        bar.update("  |  ".join(parts))

    def _read_structured_inputs(self) -> dict[str, str]:
        mapping = {
            "tenant_id": "#es-filter-tenant",
            "disposition": "#es-filter-disposition",
            "owner": "#es-filter-owner",
            "security_domain": "#es-filter-domain",
            "entity": "#es-filter-entity",
            "file_hash": "#es-filter-hash",
            "min_score": "#es-filter-min-score",
            "event_id": "#es-filter-id",
            "_raw": "#es-filter-raw",
        }
        out: dict[str, str] = {}
        for k, v in self._structured_preset_filters.items():
            if v:
                out[k] = v
        for key, wid in mapping.items():
            try:
                val = self.query_one(wid, Input).value.strip()
            except Exception:
                val = ""
            if val:
                out[key] = val
        return out

    def _row_matches_local_filters(self, row: dict[str, Any]) -> bool:
        if self._current_view == "notables":
            if self._item_type == "investigations" and not (
                row.get("is_investigation") or row.get("item_type") == "investigation"
            ):
                return False
            if self._item_type == "finding_groups" and row.get("item_type") != "finding_group":
                return False
            if self._item_type == "findings" and (
                row.get("is_investigation") or row.get("item_type") in {"investigation", "finding_group"}
            ):
                return False

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
            elif self._preset_owner_mode == "me" and self._current_splunk_user:
                if str(row.get("owner") or "").strip().lower() != self._current_splunk_user.lower():
                    return False

            if self._preset_reran_only:
                raw_reran = row.get("raw")
                raw_obj: Mapping[str, Any] = raw_reran if isinstance(raw_reran, Mapping) else {}
                if not (
                    str(row.get("orig_sid") or raw_obj.get("orig_sid") or "").strip()
                    or "re-ran" in str(row.get("title") or row.get("rule_name") or "").lower()
                ):
                    return False
            if self._preset_min_risk is not None:
                try:
                    score_v = float(row.get("risk_score") or -1)
                except (TypeError, ValueError):
                    score_v = -1.0
                if score_v < self._preset_min_risk:
                    return False
            if self._preset_suppressed_only and not bool(row.get("suppressed")):
                return False

            struct = self._read_structured_inputs()
            search_raw = self.query_one("#es-search-input", Input).value.strip()
            inline_facets, free_terms = _parse_structured_search(search_raw)
            for fk, fv in inline_facets.items():
                norm_fk = {
                    "tenant": "tenant_id",
                    "tenant_id": "tenant_id",
                    "disp": "disposition",
                    "disposition": "disposition",
                    "owner": "owner",
                    "domain": "security_domain",
                    "security_domain": "security_domain",
                    "entity": "entity",
                    "hash": "file_hash",
                    "file_hash": "file_hash",
                    "score": "min_score",
                    "finding_score": "min_score",
                    "id": "event_id",
                    "event_id": "event_id",
                    "_raw": "_raw",
                    "raw": "_raw",
                    "src": "src",
                    "dest": "dest",
                    "user": "user",
                    "title": "title",
                    "severity": "severity",
                }.get(fk, fk)
                struct[norm_fk] = fv

            if struct:
                raw_val = row.get("raw")
                raw_dict: Mapping[str, Any] = raw_val if isinstance(raw_val, Mapping) else {}
                cf_val = row.get("custom_fields")
                cf_dict: Mapping[str, Any] = cf_val if isinstance(cf_val, Mapping) else {}
                for sk, sv in struct.items():
                    sv_low = sv.casefold()
                    if sk == "tenant_id":
                        tval = str(row.get("tenant_id") or "").casefold()
                        if sv_low not in tval:
                            return False
                    elif sk == "min_score":
                        try:
                            min_s = float(sv)
                            cur_s = float(row.get("risk_score") or -1)
                        except (TypeError, ValueError):
                            return False
                        if cur_s < min_s:
                            return False
                    elif sk == "entity":
                        ent_blob = " ".join(
                            str(row.get(k) or "")
                            for k in ("entity", "risk_object", "src", "dest", "user")
                        ).casefold()
                        if sv_low not in ent_blob:
                            return False
                    elif sk == "file_hash":
                        fh_blob = " ".join(
                            str(m.get(k) or "")
                            for m in (row, raw_dict, cf_dict)
                            for k in ("file_hash", "sha256", "sha1", "md5")
                        ).casefold()
                        if sv_low not in fh_blob:
                            return False
                    elif sk == "_raw":
                        raw_txt = str(raw_dict.get("_raw") or row.get("_raw") or "").casefold()
                        if sv_low not in raw_txt:
                            return False
                    elif sk == "title":
                        title_txt = f"{row.get('title', '')} {row.get('rule_name', '')}".casefold()
                        if sv_low not in title_txt:
                            return False
                    else:
                        matched = False
                        for container in (row, cf_dict, raw_dict):
                            for ck, cv in container.items():
                                if isinstance(ck, str) and ck.casefold() == sk.casefold() and cv is not None:
                                    if sv_low in str(cv).casefold():
                                        matched = True
                                        break
                            if matched:
                                break
                        if not matched:
                            return False
        else:
            free_terms = [
                t for t in self.query_one("#es-search-input", Input).value.strip().split() if t
            ]

        if self._current_view in ("notables", "risk") and self._local_timeframe != "any":
            ts_val = row.get("_time") or row.get("created") or row.get("updated")
            if not _es_timestamp_matches(ts_val, self._local_timeframe):
                return False

        for term in free_terms:
            q = term.casefold()
            blob = " ".join(str(v) for k, v in row.items() if k != "raw" and v is not None).casefold()
            if q not in blob:
                raw_blob_obj = row.get("raw")
                raw_blob = json.dumps(raw_blob_obj, default=str).casefold() if raw_blob_obj else ""
                if q not in raw_blob:
                    return False
        return True

    def _prepare_notable_display_row(
        self,
        row: dict[str, Any],
        pinned_fields: tuple[str, ...],
        tenant_cfg: Any,
    ) -> dict[str, Any]:
        out = dict(row)
        eid = str(out.get("event_id") or out.get("finding_id") or "").strip()
        out["selected"] = "[x]" if eid and eid in self._selected_ids else "[ ]"
        if not out.get("title"):
            out["title"] = out.get("rule_title") or out.get("rule_name") or ""
        if not out.get("tenant_id"):
            out["tenant_id"] = extract_finding_tenant(out, tenant_cfg) or "-"
        if not out.get("entity"):
            out["entity"] = (
                out.get("risk_object")
                or out.get("src")
                or out.get("dest")
                or out.get("user")
                or ""
            )
        cf_val = out.get("custom_fields")
        cf_dict: Mapping[str, Any] = cf_val if isinstance(cf_val, Mapping) else {}
        raw_val = out.get("raw")
        raw_dict: Mapping[str, Any] = raw_val if isinstance(raw_val, Mapping) else {}
        for pfield in pinned_fields:
            if pfield not in out or out[pfield] in (None, ""):
                target_low = pfield.casefold()
                val: Any = None
                for container in (out, cf_dict, raw_dict):
                    for ck, cv in container.items():
                        if (
                            isinstance(ck, str)
                            and ck.casefold() == target_low
                            and cv not in (None, "")
                        ):
                            val = cv
                            break
                    if val is not None:
                        break
                if val is not None:
                    out[pfield] = val
        return out

    def _render_filtered_table(self, *, select_row: int = 0) -> None:
        filtered = [row for row in self._raw_rows if self._row_matches_local_filters(row)]
        if self._current_view == "notables":
            tenant_cfg = get_splunk_es_tenant_settings()
            pinned = tenant_cfg.custom_fields
            filtered = [self._prepare_notable_display_row(r, pinned, tenant_cfg) for r in filtered]
            columns = self._get_notable_columns()
            self._raw_columns = columns
        else:
            columns = self._raw_columns

        if self._sort_col and columns:
            def _sort_key(item: dict[str, Any]) -> tuple[int, str]:
                val = item.get(self._sort_col)
                if self._sort_col == "risk_score" or self._sort_col == "rf_max_risk_score":
                    try:
                        return (0, f"{float(val or -1):012.2f}")
                    except (TypeError, ValueError):
                        return (1, str(val or ""))
                return (0, str(val or "").casefold())

            filtered = sorted(filtered, key=_sort_key, reverse=self._sort_desc)

        self._current_rows = filtered

        if self._current_view == "notables" and self._group_by_tenant:
            grouped_rows: list[dict[str, Any]] = []
            by_tenant: dict[str, list[dict[str, Any]]] = {}
            for r in filtered:
                tkey = str(r.get("tenant_id") or "-").strip() or "-"
                by_tenant.setdefault(tkey, []).append(r)
            for tkey in sorted(by_tenant.keys(), key=lambda x: (x == "-", x.casefold())):
                members = by_tenant[tkey]
                collapsed = tkey in self._collapsed_tenants
                crit_cnt = sum(1 for m in members if str(m.get("urgency") or "").lower() == "critical")
                high_cnt = sum(1 for m in members if str(m.get("urgency") or "").lower() == "high")
                new_cnt = sum(1 for m in members if str(m.get("status_label") or "").lower() == "new")
                prefix = "[+]" if collapsed else "[-]"
                grouped_rows.append(
                    {
                        "_is_group_row": True,
                        "_group_tenant": tkey,
                        "selected": prefix,
                        "tenant_id": tkey,
                        "title": f"Tenant {tkey}: {len(members)} finding(s) | Crit:{crit_cnt} High:{high_cnt} New:{new_cnt}",
                    }
                )
                if not collapsed:
                    grouped_rows.extend(members)
            page_source = grouped_rows
        else:
            page_source = filtered

        total_items = len(page_source)
        self._total_display_items = total_items
        total_pages = max(1, (total_items + self._page_size - 1) // self._page_size)
        if self._page_offset >= total_items:
            self._page_offset = 0
        cur_page = (self._page_offset // self._page_size) + 1
        page_rows = page_source[self._page_offset : self._page_offset + self._page_size]
        self._displayed_rows = page_rows

        try:
            self.query_one("#es-page-label", Static).update(f"Page {cur_page}/{total_pages}")
            self.query_one("#es-pagination-row", Horizontal).display = (
                self._current_view == "notables" and total_items > self._page_size
            )
            self.query_one("#es-bulk-bar", Horizontal).display = (
                self._current_view == "notables" and bool(self._selected_ids)
            )
        except Exception:
            pass

        table = self.query_one("#es-table", DoubleClickDataTable)
        self._rendering_table = True
        try:
            table.clear(columns=True)
            if not columns:
                table.add_column("Message", key="message")
            else:
                for key, label in columns:
                    table.add_column(label, key=key)
                for idx, row in enumerate(page_rows):
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
        self._update_sparkline_strip()

        if page_rows:
            target_idx = max(0, min(select_row, len(page_rows) - 1))
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
        self._page_offset = 0
        self._render_filtered_table(select_row=select_row)

    @on(DataTable.HeaderSelected, "#es-table")
    def handle_header_selected(self, event: DataTable.HeaderSelected) -> None:
        col_key = str(event.column_key.value or "")
        if not col_key or col_key == "selected":
            return
        if self._sort_col == col_key:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_col = col_key
            self._sort_desc = False
        self._render_filtered_table()

    @on(Button.Pressed, "#es-prev-page-btn")
    def handle_prev_page(self) -> None:
        if self._page_offset > 0:
            self._page_offset = max(0, self._page_offset - self._page_size)
            self._render_filtered_table()

    @on(Button.Pressed, "#es-next-page-btn")
    def handle_next_page(self) -> None:
        if self._page_offset + self._page_size < self._total_display_items:
            self._page_offset += self._page_size
            self._render_filtered_table()

    @on(Select.Changed, "#es-preset-select")
    def handle_preset_changed(self, event: Select.Changed) -> None:
        if self._syncing_es_filters or not self._es_ready:
            return
        preset_id = str(event.value or "all")
        if preset_id == "__custom__":
            return
        preset = self._get_all_presets_by_id().get(preset_id)
        if preset is None:
            return
        self._syncing_es_filters = True
        try:
            self._active_preset_id = preset_id
            self._preset_statuses = tuple(preset.get("statuses") or ())
            self._preset_urgencies = tuple(preset.get("urgencies") or ())
            self._preset_owner_mode = str(preset.get("owner_mode") or "any")
            self._preset_reran_only = bool(preset.get("reran_only", False))
            raw_min_risk = preset.get("min_risk_score")
            self._preset_min_risk = float(raw_min_risk) if raw_min_risk is not None else None
            self._preset_suppressed_only = bool(preset.get("suppressed_only", False))
            self._structured_preset_filters = dict(preset.get("structured_filters") or {})

            tf_val = str(preset.get("timeframe") or "any")
            self._local_timeframe = "any" if preset_id == "all" else tf_val

            tf_sel = self.query_one("#es-timeframe-select", Select)
            with tf_sel.prevent(Select.Changed):
                valid_tfs = {v for _, v in _LOCAL_ES_TIMEFRAME_OPTIONS}
                tf_sel.value = tf_val if tf_val in valid_tfs else "custom"
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

            if "search_text" in preset:
                s_inp = self.query_one("#es-search-input", Input)
                with s_inp.prevent(Input.Changed):
                    s_inp.value = str(preset.get("search_text") or "")
            if "item_type" in preset:
                self._set_item_type_ui(str(preset.get("item_type") or "all"))
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
        known = {"-15m", "-1h", "-4h", "-24h", "-48h", "-7d", "-14d", "-30d", "-90d"}
        target = val if val in known else "custom"
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
        self._preset_reran_only = False
        self._preset_min_risk = None
        self._preset_suppressed_only = False
        self._mark_es_custom_preset()
        if self._raw_rows:
            self._render_filtered_table()
        else:
            self._update_summary_bar()

    @on(Input.Changed, "#es-search-input")
    @on(Input.Changed, "#es-filter-tenant")
    @on(Input.Changed, "#es-filter-disposition")
    @on(Input.Changed, "#es-filter-owner")
    @on(Input.Changed, "#es-filter-domain")
    @on(Input.Changed, "#es-filter-entity")
    @on(Input.Changed, "#es-filter-hash")
    @on(Input.Changed, "#es-filter-min-score")
    @on(Input.Changed, "#es-filter-id")
    @on(Input.Changed, "#es-filter-raw")
    def handle_es_search_changed(self) -> None:
        if self._syncing_es_filters or not self._es_ready:
            return
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
            self._preset_reran_only = False
            self._preset_min_risk = None
            self._preset_suppressed_only = False
            self._structured_preset_filters = {}
            self._set_item_type_ui("all")
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
            for inp_id in (
                "#es-search-input",
                "#es-filter-tenant",
                "#es-filter-disposition",
                "#es-filter-owner",
                "#es-filter-domain",
                "#es-filter-entity",
                "#es-filter-hash",
                "#es-filter-min-score",
                "#es-filter-id",
                "#es-filter-raw",
            ):
                inp = self.query_one(inp_id, Input)
                with inp.prevent(Input.Changed):
                    inp.value = ""
        finally:
            self._syncing_es_filters = False
        if self._raw_rows:
            self._render_filtered_table()
        else:
            self._update_summary_bar()
        self.set_status("Reset Splunk ES filters.")

    # ------------------------------------------------------------------
    # Item Type Pills, Grouping & Saved Views
    # ------------------------------------------------------------------

    def _set_item_type_ui(self, item_type: str) -> None:
        self._item_type = item_type
        for pill_id, _, pill_val in _ITEM_TYPE_PILLS:
            try:
                btn = self.query_one(f"#{pill_id}", Button)
                if pill_val == item_type:
                    btn.add_class("es-pill-active")
                else:
                    btn.remove_class("es-pill-active")
            except Exception:
                pass

    @on(Button.Pressed, "#es-type-all-btn")
    @on(Button.Pressed, "#es-type-investigations-btn")
    @on(Button.Pressed, "#es-type-groups-btn")
    @on(Button.Pressed, "#es-type-findings-btn")
    def handle_item_type_pill(self, event: Button.Pressed) -> None:
        btn_id = str(event.button.id or "")
        mapping = {pid: pval for pid, _, pval in _ITEM_TYPE_PILLS}
        target_type = mapping.get(btn_id, "all")
        self._set_item_type_ui(target_type)
        if self._raw_rows and target_type != "investigations":
            self._render_filtered_table()
        else:
            self.handle_refresh()

    @on(Button.Pressed, "#es-group-tenant-btn")
    def handle_toggle_group_by_tenant(self) -> None:
        self._group_by_tenant = not self._group_by_tenant
        btn = self.query_one("#es-group-tenant-btn", Button)
        if self._group_by_tenant:
            btn.add_class("es-pill-active")
        else:
            btn.remove_class("es-pill-active")
        self._render_filtered_table()

    def action_toggle_structured_filters(self) -> None:
        try:
            col = self.query_one("#es-structured-filter-collapsible", Collapsible)
            col.collapsed = not col.collapsed
        except Exception:
            pass

    @on(Button.Pressed, "#es-save-view-btn")
    def handle_save_custom_view(self) -> None:
        def _on_saved(res: dict[str, Any] | None) -> None:
            if not res:
                return
            label = str(res.get("label") or "").strip()
            if not label:
                return
            slug = _SLUG_RE.sub("_", label.lower()).strip("_") or "custom_view"
            view_id = f"custom_{slug}"
            urgency_val = str(self.query_one("#es-urgency-select", Select).value or "").strip()
            status_val = str(self.query_one("#es-status-select", Select).value or "").strip()
            statuses: list[str] = []
            if status_val:
                code = NOTABLE_STATUS_MAP.get(status_val)
                if code is not None:
                    statuses.append(NOTABLE_STATUS_LABELS[code])
            view_def: dict[str, Any] = {
                "id": view_id,
                "label": label,
                "earliest": self.query_one("#es-earliest-input", Input).value.strip() or "-24h",
                "timeframe": str(self.query_one("#es-timeframe-select", Select).value or "-24h"),
                "statuses": statuses,
                "urgencies": [urgency_val] if urgency_val else [],
                "owner_mode": "any",
                "item_type": self._item_type,
                "search_text": self.query_one("#es-search-input", Input).value.strip(),
                "structured_filters": self._read_structured_inputs(),
            }
            saved_list = save_splunk_es_saved_view(view_def)
            self._custom_views = {
                str(v["id"]): v for v in saved_list if str(v.get("id") or "").strip()
            }
            preset_sel = self.query_one("#es-preset-select", Select)
            with preset_sel.prevent(Select.Changed):
                preset_sel.set_options(self._build_preset_options())
                preset_sel.value = view_id
            self._active_preset_id = view_id
            self._update_summary_bar()
            self.set_status(f"Saved custom ES queue view '{label}'.")

        self.app.push_screen(ESSavedViewModal(), _on_saved)

    @on(Button.Pressed, "#es-del-view-btn")
    def handle_delete_custom_view(self) -> None:
        if self._active_preset_id not in self._custom_views:
            self.set_status("Select a saved custom view before deleting.")
            return
        target_id = self._active_preset_id
        remaining = delete_splunk_es_saved_view(target_id)
        self._custom_views = {
            str(v["id"]): v for v in remaining if str(v.get("id") or "").strip()
        }
        preset_sel = self.query_one("#es-preset-select", Select)
        with preset_sel.prevent(Select.Changed):
            preset_sel.set_options(self._build_preset_options())
            preset_sel.value = "all"
        self._active_preset_id = "all"
        self._update_summary_bar()
        self.set_status(f"Deleted custom ES view '{target_id}'.")

    # ------------------------------------------------------------------
    # Multi-Select Queue & Bulk Bar Actions
    # ------------------------------------------------------------------

    def action_toggle_select_row(self) -> None:
        if self._current_view != "notables":
            return
        try:
            table = self.query_one("#es-table", DoubleClickDataTable)
            if not table.has_focus:
                return
        except Exception:
            return
        idx = self._selected_row_index()
        if idx is None or idx < 0 or idx >= len(self._displayed_rows):
            return
        row = self._displayed_rows[idx]
        if row.get("_is_group_row"):
            tkey = str(row.get("_group_tenant") or "")
            if tkey in self._collapsed_tenants:
                self._collapsed_tenants.discard(tkey)
            else:
                self._collapsed_tenants.add(tkey)
            self._render_filtered_table(select_row=idx)
            return
        eid = str(row.get("event_id") or "").strip()
        if not eid:
            return
        if eid in self._selected_ids:
            self._selected_ids.discard(eid)
        else:
            self._selected_ids.add(eid)
        self._render_filtered_table(select_row=idx)

    @on(Button.Pressed, "#es-select-page-btn")
    def handle_select_page(self) -> None:
        for row in self._displayed_rows:
            if row.get("_is_group_row"):
                continue
            eid = str(row.get("event_id") or "").strip()
            if eid:
                self._selected_ids.add(eid)
        self._render_filtered_table(select_row=self._selected_row_index() or 0)

    @on(Button.Pressed, "#es-select-all-btn")
    def handle_select_all(self) -> None:
        for row in self._current_rows:
            eid = str(row.get("event_id") or "").strip()
            if eid:
                self._selected_ids.add(eid)
        self._render_filtered_table(select_row=self._selected_row_index() or 0)

    @on(Button.Pressed, "#es-deselect-btn")
    def handle_deselect_all(self) -> None:
        self._selected_ids.clear()
        self._render_filtered_table(select_row=self._selected_row_index() or 0)

    def _target_event_ids(self) -> list[str]:
        if self._selected_ids:
            return [
                str(r.get("event_id"))
                for r in self._current_rows
                if str(r.get("event_id") or "").strip() in self._selected_ids
            ] or sorted(self._selected_ids)
        row = self.get_selected_row()
        eid = str((row or {}).get("event_id") or "").strip()
        return [eid] if eid else []

    @on(Button.Pressed, "#es-bulk-triage-btn")
    def handle_bulk_triage(self) -> None:
        target_ids = self._target_event_ids()
        if not target_ids:
            self.set_status("Select one or more findings before bulk triaging.")
            return
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Bulk triage for {len(target_ids)} finding(s) is blocked in dry-run mode."
            self.set_status(msg)
            self.append_log(msg)
            return

        modal = ESBulkTriageModal(
            event_ids=target_ids,
            available_owners=self._splunk_users,
            current_user=self._current_splunk_user,
            dry_run=self.effective_dry_run,
        )

        def _on_result(result: dict[str, Any] | None) -> None:
            if not result:
                return
            self._bulk_triage_worker(result)

        self.app.push_screen(modal, _on_result)

    @work(thread=True, exit_on_error=False)
    def _bulk_triage_worker(self, payload: dict[str, Any]) -> None:
        try:
            ids = list(payload.get("event_ids") or [])
            if not ids:
                return
            self.set_status(f"Applying Mission Control triage to {len(ids)} finding(s)...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    if isinstance(es, SplunkESClient) or callable(
                        getattr(es, "triage_findings_hybrid", None)
                    ):
                        es.triage_findings_hybrid(
                            ids,
                            status=payload.get("status"),
                            urgency=payload.get("urgency"),
                            owner=payload.get("owner"),
                            disposition=payload.get("disposition"),
                            note=payload.get("note"),
                        )
                    else:
                        es.update_notable(
                            ids,
                            status=payload.get("status"),
                            urgency=payload.get("urgency"),
                            owner=payload.get("owner"),
                            disposition=payload.get("disposition"),
                            comment=payload.get("note"),
                        )
                    if payload.get("dual_post_rf") and payload.get("note"):
                        for eid in ids:
                            row = next(
                                (r for r in self._current_rows if str(r.get("event_id")) == eid),
                                None,
                            )
                            if row and "rf_observables" in row:
                                write_enrichment_to_notable(
                                    es,
                                    eid,
                                    row,
                                    dry_run=False,
                                    use_mc_v2=True,
                                    finding_time=str(row.get("_time") or "") or None,
                                )
            msg = f"Updated {len(ids)} Splunk ES finding(s)."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Bulk Triage Applied")
            self.run_on_ui(self.handle_refresh)
        except Exception as exc:
            self.report_error("Bulk Triage ES Findings", exc)

    @on(Button.Pressed, "#es-assign-me-btn")
    @on(Button.Pressed, "#es-insp-assign-me-btn")
    def handle_assign_to_me(self) -> None:
        target_ids = self._target_event_ids()
        if not target_ids:
            self.set_status("Select one or more findings to assign.")
            return
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Assign-to-me for {len(target_ids)} finding(s) is blocked in dry-run mode."
            self.set_status(msg)
            self.append_log(msg)
            return
        owner = self._current_splunk_user or "admin"
        self._bulk_triage_worker(
            {
                "event_ids": target_ids,
                "owner": owner,
                "note": f"Assigned to {owner} from SOCLens",
            }
        )

    @on(Button.Pressed, "#es-suppress-btn")
    def handle_suppress_selected(self) -> None:
        target_ids = self._target_event_ids()
        if not target_ids:
            self.set_status("Select one or more findings to suppress.")
            return
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Suppressing {len(target_ids)} finding(s) is blocked in dry-run mode."
            self.set_status(msg)
            self.append_log(msg)
            return
        self.confirm_destructive_action(
            title="Suppress Findings",
            message=f"Suppress and close {len(target_ids)} selected finding(s)?",
            details="Sets Status=Closed and Disposition=Benign Positive - Suspicious But Expected.",
            confirm_label="Confirm Suppress",
            on_approved=lambda: self._bulk_triage_worker(
                {
                    "event_ids": target_ids,
                    "status": "Closed",
                    "disposition": "disposition:2",
                    "note": "Suppressed from SOCLens queue",
                }
            ),
            on_cancelled=lambda: self.set_status("Cancelled suppressing findings."),
        )

    @on(Button.Pressed, "#es-bulk-enrich-btn")
    def handle_bulk_enrich_selected(self) -> None:
        if not self._selected_ids:
            self.handle_enrich_selected()
            return
        opts = self._read_rf_enrichment_options()
        if opts is None:
            return
        field_map, include_private = opts
        rows = [
            dict(r)
            for r in self._current_rows
            if str(r.get("event_id") or "").strip() in self._selected_ids
        ]
        if not rows:
            self.set_status("No selected findings matched current rows.")
            return
        self._enrich_notables_worker(
            seq=self._request_seq,
            rows=rows,
            row_index=None,
            field_map=field_map,
            include_private_ips=include_private,
        )

    # ------------------------------------------------------------------
    # Inspector Sub-Tabs, Stepping, Notes, AR, Investigations, Create Finding
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#es-insp-tab-overview")
    @on(Button.Pressed, "#es-insp-tab-metadata")
    @on(Button.Pressed, "#es-insp-tab-srcdest")
    @on(Button.Pressed, "#es-insp-tab-rf")
    @on(Button.Pressed, "#es-insp-tab-notes")
    @on(Button.Pressed, "#es-insp-tab-raw")
    def handle_inspector_tab_pressed(self, event: Button.Pressed) -> None:
        btn_id = str(event.button.id or "")
        mapping = {tid: tkey for tid, _, tkey in _INSPECTOR_TABS}
        target_tab = mapping.get(btn_id, "overview")
        self._inspector_tab = target_tab
        for tid, _, tkey in _INSPECTOR_TABS:
            try:
                btn = self.query_one(f"#{tid}", Button)
                if tkey == target_tab:
                    btn.add_class("es-pill-active")
                else:
                    btn.remove_class("es-pill-active")
            except Exception:
                pass
        idx = self._selected_row_index()
        if idx is not None:
            self._render_detail(idx)
            if target_tab == "notes":
                row = self._displayed_rows[idx]
                eid = str(row.get("event_id") or "").strip()
                if eid and eid not in self._notes_history_cache:
                    self._load_notes_history_worker(
                        eid,
                        finding_time=str(row.get("_time") or "") or None,
                        orig_sid=str(row.get("orig_sid") or ""),
                        orig_rid=str(row.get("orig_rid") or ""),
                    )

    @on(Button.Pressed, "#es-prev-finding-btn")
    def handle_prev_finding(self) -> None:
        idx = self._selected_row_index()
        if idx is None or not self._displayed_rows:
            return
        target = max(0, idx - 1)
        table = self.query_one("#es-table", DoubleClickDataTable)
        try:
            table.move_cursor(row=target)
        except Exception:
            pass
        self._render_detail(target)

    @on(Button.Pressed, "#es-next-finding-btn")
    def handle_next_finding(self) -> None:
        idx = self._selected_row_index()
        if idx is None or not self._displayed_rows:
            return
        target = min(len(self._displayed_rows) - 1, idx + 1)
        table = self.query_one("#es-table", DoubleClickDataTable)
        try:
            table.move_cursor(row=target)
        except Exception:
            pass
        self._render_detail(target)

    @work(thread=True, exit_on_error=False)
    def _load_notes_history_worker(
        self,
        event_id: str,
        *,
        finding_time: str | None = None,
        orig_sid: str = "",
        orig_rid: str = "",
    ) -> None:
        try:
            notes_items: list[dict[str, Any]] = []
            history_items: list[dict[str, Any]] = []
            ar_items: list[dict[str, Any]] = []
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    if isinstance(es, SplunkESClient) or callable(getattr(es, "list_notes", None)):
                        try:
                            nres = es.list_notes(event_id, finding_time=finding_time, limit=25)
                            if isinstance(nres, dict):
                                notes_items = list(nres.get("items") or [])
                        except SplunkESError:
                            pass
                    if isinstance(es, SplunkESClient) or callable(getattr(es, "get_history", None)):
                        try:
                            hres = es.get_history(event_id, finding_time=finding_time, limit=25)
                            if isinstance(hres, dict):
                                history_items = list(hres.get("items") or [])
                        except SplunkESError:
                            pass
                    if orig_sid and orig_rid and (
                        isinstance(es, SplunkESClient)
                        or callable(getattr(es, "list_modaction_invocations", None))
                    ):
                        try:
                            ares = es.list_modaction_invocations(orig_sid, orig_rid)
                            if isinstance(ares, list):
                                ar_items = ares
                        except SplunkESError:
                            pass
            self._notes_history_cache[event_id] = {
                "notes": notes_items,
                "history": history_items,
                "ar": ar_items,
            }

            def _refresh_if_still_selected() -> None:
                if self._inspector_tab == "notes":
                    idx = self._selected_row_index()
                    if idx is not None and 0 <= idx < len(self._displayed_rows):
                        if str(self._displayed_rows[idx].get("event_id") or "") == event_id:
                            self._render_detail(idx)

            self.run_on_ui(_refresh_if_still_selected)
        except Exception as exc:
            self.report_error("Load Finding Notes & History", exc)

    @on(Button.Pressed, "#es-insp-add-note-btn")
    def handle_add_note_modal(self) -> None:
        row = self.get_selected_row()
        if not row:
            self.set_status("Select a finding before adding a note.")
            return
        eid = str(row.get("event_id") or "").strip()
        if not eid:
            self.set_status("Selected record has no event_id.")
            return
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Adding note to '{eid}' is blocked in dry-run mode."
            self.set_status(msg)
            self.append_log(msg)
            return

        modal = ESNoteModal(
            event_id=eid,
            has_rf_data="rf_observables" in row,
            dry_run=self.effective_dry_run,
        )

        def _on_note(res: dict[str, Any] | None) -> None:
            if not res:
                return
            self._post_note_worker(eid, dict(row), res)

        self.app.push_screen(modal, _on_note)

    @work(thread=True, exit_on_error=False)
    def _post_note_worker(
        self,
        event_id: str,
        row: dict[str, Any],
        note_payload: dict[str, Any],
    ) -> None:
        try:
            content = str(note_payload.get("content") or "").strip()
            title = note_payload.get("title")
            dual_rf = bool(note_payload.get("dual_post_rf"))
            finding_time = str(row.get("_time") or "").strip() or None
            self.set_status(f"Posting note to '{event_id}'...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    posted_mc = False
                    if isinstance(es, SplunkESClient) or callable(getattr(es, "create_note", None)):
                        try:
                            es.create_note(
                                event_id,
                                content,
                                title=title,
                                finding_time=finding_time,
                            )
                            posted_mc = True
                        except SplunkESError as exc:
                            if exc.status_code != 404:
                                raise
                    if not posted_mc:
                        es.update_notable([event_id], comment=content)
                    if dual_rf:
                        if "rf_observables" in row:
                            write_enrichment_to_notable(
                                es,
                                event_id,
                                row,
                                dry_run=False,
                                use_mc_v2=isinstance(es, SplunkESClient),
                                finding_time=finding_time,
                            )
                        else:
                            es.update_notable([event_id], comment=content)
            self._notes_history_cache.pop(event_id, None)
            msg = f"Posted note to '{event_id}'."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Note Posted")
        except Exception as exc:
            self.report_error("Post Finding Note", exc)

    @on(Button.Pressed, "#es-insp-ar-btn")
    def handle_open_ar_modal(self) -> None:
        row = self.get_selected_row()
        if not row:
            self.set_status("Select a finding to inspect Adaptive Response.")
            return
        eid = str(row.get("event_id") or "").strip()
        orig_sid = str(row.get("orig_sid") or "").strip()
        orig_rid = str(row.get("orig_rid") or "").strip()
        self._open_ar_worker(eid, orig_sid, orig_rid)

    @work(thread=True, exit_on_error=False)
    def _open_ar_worker(self, event_id: str, orig_sid: str, orig_rid: str) -> None:
        try:
            invocations: list[dict[str, Any]] = []
            actions: list[dict[str, Any]] = []
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    if orig_sid and orig_rid and callable(
                        getattr(es, "list_modaction_invocations", None)
                    ):
                        try:
                            res_inv = es.list_modaction_invocations(orig_sid, orig_rid)
                            if isinstance(res_inv, list):
                                invocations = res_inv
                        except SplunkESError:
                            pass
                    if callable(getattr(es, "list_adaptive_response_actions", None)):
                        try:
                            res_act = es.list_adaptive_response_actions(adhoc_only=True, count=100)
                            if isinstance(res_act, list):
                                actions = res_act
                        except SplunkESError:
                            pass

            def _show() -> None:
                modal = ESAdaptiveResponseModal(
                    event_id=event_id,
                    orig_sid=orig_sid,
                    orig_rid=orig_rid,
                    invocations=invocations,
                    available_actions=actions,
                    dry_run=self.effective_dry_run,
                )

                def _on_dispatch(res: dict[str, Any] | None) -> None:
                    if not res:
                        return
                    if self.effective_dry_run:
                        self.set_status(
                            f"[DRY-RUN] Ad-hoc AR dispatch '{res.get('action_name')}' blocked."
                        )
                        return
                    self._dispatch_ar_worker(res)

                self.app.push_screen(modal, _on_dispatch)

            self.run_on_ui(_show)
        except Exception as exc:
            self.report_error("Load Adaptive Response", exc)

    @work(thread=True, exit_on_error=False)
    def _dispatch_ar_worker(self, payload: dict[str, Any]) -> None:
        try:
            action_name = str(payload.get("action_name") or "")
            sid = str(payload.get("sid") or "")
            rid = str(payload.get("rid") or "")
            params = payload.get("params") or {}
            self.set_status(f"Dispatching Adaptive Response '{action_name}'...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    es.dispatch_adaptive_response(action_name, sid=sid, rid=rid, params=params)
            msg = f"Dispatched Adaptive Response '{action_name}' for sid={sid} rid={rid}."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Adaptive Response Dispatched")
        except Exception as exc:
            self.report_error("Dispatch Adaptive Response", exc)

    @on(Button.Pressed, "#es-new-inv-btn")
    @on(Button.Pressed, "#es-move-inv-btn")
    @on(Button.Pressed, "#es-insp-inv-btn")
    def handle_open_investigation_modal(self, event: Button.Pressed) -> None:
        btn_id = str(event.button.id or "")
        default_mode = "attach" if btn_id == "es-move-inv-btn" else "create"
        target_ids = self._target_event_ids()
        finding_times = [
            str(r.get("_time") or "")
            for r in self._current_rows
            if str(r.get("event_id") or "").strip() in set(target_ids)
        ]
        self._open_investigation_worker(target_ids, finding_times, default_mode=default_mode)

    @work(thread=True, exit_on_error=False)
    def _open_investigation_worker(
        self,
        finding_ids: list[str],
        finding_times: list[str],
        *,
        default_mode: str,
    ) -> None:
        existing_invs: list[dict[str, Any]] = []
        try:
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    if callable(getattr(es, "list_investigations", None)):
                        try:
                            res = es.list_investigations(limit=50)
                            if isinstance(res, list):
                                existing_invs = res
                        except SplunkESError:
                            pass
        except Exception:
            existing_invs = []

        def _show() -> None:
            modal = ESInvestigationModal(
                finding_ids=finding_ids,
                finding_times=finding_times,
                existing_investigations=existing_invs,
                default_mode=default_mode,
                dry_run=self.effective_dry_run,
            )

            def _on_inv(res: dict[str, Any] | None) -> None:
                if not res:
                    return
                if self.effective_dry_run:
                    self.set_status("[DRY-RUN] Investigation mutation blocked in dry-run mode.")
                    return
                self._apply_investigation_worker(res)

            self.app.push_screen(modal, _on_inv)

        self.run_on_ui(_show)

    @work(thread=True, exit_on_error=False)
    def _apply_investigation_worker(self, payload: dict[str, Any]) -> None:
        try:
            mode = str(payload.get("mode") or "create")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    if mode == "attach":
                        inv_id = str(payload.get("investigation_id") or "")
                        es.add_findings_to_investigation(
                            inv_id,
                            list(payload.get("finding_ids") or []),
                            list(payload.get("finding_times") or []),
                        )
                        msg = f"Attached findings to investigation '{inv_id}'."
                    else:
                        name = str(payload.get("name") or "")
                        res = es.create_investigation(
                            name,
                            description=payload.get("description"),
                            urgency=payload.get("urgency"),
                            status=payload.get("status"),
                            owner=payload.get("owner"),
                            finding_ids=payload.get("finding_ids"),
                            finding_times=payload.get("finding_times"),
                        )
                        guid = str(res.get("investigation_guid") or "")
                        msg = f"Created investigation '{name}' ({guid})."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Investigation Updated")
            self.run_on_ui(self.handle_refresh)
        except Exception as exc:
            self.report_error("ES Investigation", exc)

    @on(Button.Pressed, "#es-create-finding-btn")
    def handle_create_finding_modal(self) -> None:
        tenant_cfg = get_splunk_es_tenant_settings()
        modal = ESCreateFindingModal(
            tenant_field=tenant_cfg.tenant_field,
            pinned_custom_fields=tenant_cfg.custom_fields,
            discovered_fields=self._discovered_fields,
            dry_run=self.effective_dry_run,
        )

        def _on_create(res: dict[str, Any] | None) -> None:
            if not res:
                return
            if self.effective_dry_run:
                self.set_status(
                    f"[DRY-RUN] Create finding '{res.get('rule_title')}' blocked in dry-run mode."
                )
                return
            self._create_finding_worker(res)

        self.app.push_screen(modal, _on_create)

    @work(thread=True, exit_on_error=False)
    def _create_finding_worker(self, payload: dict[str, Any]) -> None:
        try:
            title = str(payload.get("rule_title") or "")
            self.set_status(f"Creating manual finding '{title}'...")
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    res = es.create_finding(
                        rule_title=title,
                        security_domain=str(payload.get("security_domain") or "threat"),
                        rule_description=payload.get("rule_description"),
                        urgency=payload.get("urgency"),
                        risk_object=payload.get("risk_object"),
                        additional_fields=payload.get("additional_fields"),
                    )
            fid = str(res.get("finding_id") or "")
            msg = f"Created manual finding '{title}' ({fid})."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="Finding Created")
            self.run_on_ui(self.handle_refresh)
        except Exception as exc:
            self.report_error("Create Manual Finding", exc)

    # ------------------------------------------------------------------
    # Cross-Workbench Pivot Bus (WS4)
    # ------------------------------------------------------------------

    def _build_pivot_payload(
        self,
        target_tab: str,
        row: dict[str, Any],
        *,
        use_orig_sid: bool = False,
        auto_run: bool = False,
        summary: str | None = None,
    ) -> PivotPayload:
        raw_val = row.get("raw")
        raw_obj: Mapping[str, Any] = raw_val if isinstance(raw_val, Mapping) else {}
        cf_val = row.get("custom_fields")
        cf_obj: Mapping[str, Any] = cf_val if isinstance(cf_val, Mapping) else {}
        tenant_val = str(row.get("tenant_id") or "").strip()
        if tenant_val == "-":
            tenant_val = ""
        hostname = str(
            row.get("dest_host")
            or row.get("src_host")
            or raw_obj.get("dest_host")
            or raw_obj.get("src_host")
            or raw_obj.get("dvc")
            or raw_obj.get("host")
            or ""
        ).strip()
        sha1 = str(raw_obj.get("sha1") or cf_obj.get("sha1") or "").strip() or None
        sha256 = (
            str(
                raw_obj.get("sha256")
                or raw_obj.get("file_hash")
                or cf_obj.get("sha256")
                or cf_obj.get("file_hash")
                or ""
            ).strip()
            or None
        )
        orig_sid = str(row.get("orig_sid") or raw_obj.get("orig_sid") or "").strip() or None
        earliest = self.query_one("#es-earliest-input", Input).value.strip() or "-24h"
        rf_blob: dict[str, Any] | None = None
        if "rf_observables" in row or "rf_max_risk_score" in row:
            rf_blob = {
                "rf_max_risk_score": row.get("rf_max_risk_score"),
                "rf_criticality_label": row.get("rf_criticality_label"),
                "rf_top_field": row.get("rf_top_field"),
                "rf_observables": row.get("rf_observables"),
            }
        return PivotPayload(
            source_tab="tab-splunk-es",
            target_tab=target_tab,
            tenant_id=tenant_val or None,
            entity=str(row.get("entity") or row.get("risk_object") or "").strip() or None,
            entity_type=str(row.get("risk_object_type") or "").strip() or None,
            src_ip=str(row.get("src") or "").strip() or None,
            dest_ip=str(row.get("dest") or "").strip() or None,
            sha1=sha1,
            sha256=sha256,
            hostname=hostname or None,
            username=str(row.get("user") or "").strip() or None,
            orig_sid=orig_sid if use_orig_sid else None,
            earliest=earliest,
            latest="now",
            auto_run=auto_run,
            es_finding=dict(row),
            s1_threat=dict(self._last_s1_context) if self._last_s1_context else None,
            rf_enrichment=rf_blob,
            summary=summary or str(row.get("title") or row.get("rule_name") or ""),
        )

    def _emit_pivot_for_target(
        self,
        target_tab: str,
        *,
        use_orig_sid: bool = False,
        auto_run: bool = False,
    ) -> None:
        row = self.get_selected_row()
        if not row:
            self.set_status("Select a finding before pivoting.")
            return
        payload = self._build_pivot_payload(
            target_tab,
            row,
            use_orig_sid=use_orig_sid,
            auto_run=auto_run,
        )
        if not emit_pivot(self.app, payload):
            self.set_status(f"Pivot prepared for {target_tab} (host dispatcher not active).")
        else:
            self.set_status(f"Pivoted to {target_tab}.")

    @on(Button.Pressed, "#es-insp-pivot-search-btn")
    def handle_pivot_to_search(self) -> None:
        row = self.get_selected_row()
        if not row:
            self.set_status("Select a finding before pivoting to Splunk Search.")
            return
        raw_val = row.get("raw")
        raw_obj_s: Mapping[str, Any] = raw_val if isinstance(raw_val, Mapping) else {}
        has_sid = bool(str(row.get("orig_sid") or raw_obj_s.get("orig_sid") or "").strip())
        self._emit_pivot_for_target(
            "tab-splunk-search",
            use_orig_sid=has_sid,
            auto_run=has_sid,
        )

    @on(Button.Pressed, "#es-insp-pivot-s1-btn")
    def handle_pivot_to_sentinelone(self) -> None:
        self._emit_pivot_for_target("tab-sentinelone", auto_run=True)

    @on(Button.Pressed, "#es-insp-pivot-llm-btn")
    def handle_pivot_to_llm_copilot(self) -> None:
        self._emit_pivot_for_target("tab-llm", auto_run=False)

    def accept_pivot(self, payload: PivotPayload) -> None:
        """Apply an incoming cross-workbench pivot filter and optionally auto-load ES findings."""
        self._request_seq += 1
        self._syncing_es_filters = True
        try:
            view_sel = self.query_one("#es-view-select", Select)
            if self._current_view != "notables":
                with view_sel.prevent(Select.Changed):
                    view_sel.value = "notables"
                self._sync_controls_for_view("notables")

            if payload.earliest and payload.earliest.strip():
                with self.query_one("#es-earliest-input", Input).prevent(Input.Changed):
                    self.query_one("#es-earliest-input", Input).value = payload.earliest.strip()

            if payload.tenant_id and payload.tenant_id.strip():
                with self.query_one("#es-filter-tenant", Input).prevent(Input.Changed):
                    self.query_one("#es-filter-tenant", Input).value = payload.tenant_id.strip()

            primary_indicator = (
                payload.hostname
                or payload.sha256
                or payload.sha1
                or payload.src_ip
                or payload.dest_ip
                or payload.username
                or payload.entity
                or ""
            ).strip()
            parts: list[str] = []
            if payload.tenant_id and payload.tenant_id.strip():
                parts.append(f"tenant_id:{payload.tenant_id.strip()}")
            if primary_indicator:
                parts.append(primary_indicator)
            with self.query_one("#es-search-input", Input).prevent(Input.Changed):
                self.query_one("#es-search-input", Input).value = " ".join(parts)

            if payload.s1_threat:
                self._last_s1_context = dict(payload.s1_threat)
        finally:
            self._syncing_es_filters = False

        if self._raw_rows:
            self._render_filtered_table()
        if payload.auto_run or not self._raw_rows:
            self.handle_refresh()
        self.set_status(
            f"Pivoted from {payload.source_tab or 'external'} "
            f"(tenant={payload.tenant_id or '-'})."
        )

    # ------------------------------------------------------------------
    # Detail Inspector Rendering
    # ------------------------------------------------------------------

    def _clear_detail(self, message: str = "") -> None:
        detail = self.query_one("#es-detail", RichLog)
        detail.clear()
        self.query_one("#es-detail-header", Static).update("Detail")
        if message:
            detail.write(message)

    def _render_detail(self, row_index: int) -> None:
        if row_index < 0 or row_index >= len(self._displayed_rows):
            return
        row = self._displayed_rows[row_index]
        detail = self.query_one("#es-detail", RichLog)
        detail.clear()

        if row.get("_is_group_row"):
            tkey = str(row.get("_group_tenant") or "-")
            self.query_one("#es-detail-header", Static).update(f"Tenant Group - {tkey}")
            detail.write(str(row.get("title") or ""))
            detail.write("Press Space or Enter on this group header row to expand/collapse.")
            return

        title_hint = (
            row.get("rule_title")
            or row.get("rule_name")
            or row.get("name")
            or row.get("risk_object")
            or row.get("ip")
            or row.get("domain")
            or row.get("identity")
            or row.get("nt_host")
            or f"Row #{row_index + 1}"
        )
        tenant_badge = str(row.get("tenant_id") or "").strip()
        badge_str = f" [Tenant: {tenant_badge}]" if tenant_badge and tenant_badge != "-" else ""
        self.query_one("#es-detail-header", Static).update(
            f"{self._view_header_title()} Detail - {title_hint}{badge_str}"
        )

        if self._current_view != "notables":
            for key, value in row.items():
                if key == "raw" or key in _RF_ENRICHMENT_KEYS:
                    continue
                rendered = (
                    json.dumps(value, indent=2, ensure_ascii=False)
                    if isinstance(value, (dict, list))
                    else str(value)
                )
                detail.write(f"{key}: {rendered}")
            raw_payload = row.get("raw")
            if isinstance(raw_payload, dict) and raw_payload:
                detail.write("")
                detail.write("--- Raw Fields ---")
                detail.write(json.dumps(raw_payload, indent=2, ensure_ascii=False, sort_keys=True))
            return

        tab = self._inspector_tab
        if tab == "overview":
            self._render_inspector_overview(detail, row, tenant_badge)
        elif tab == "metadata":
            self._render_inspector_metadata(detail, row)
        elif tab == "srcdest":
            self._render_inspector_srcdest(detail, row)
        elif tab == "rf":
            self._render_inspector_rf(detail, row)
        elif tab == "notes":
            self._render_inspector_notes(detail, row)
        else:
            raw_payload = row.get("raw") or row
            detail.write(json.dumps(raw_payload, indent=2, ensure_ascii=False, sort_keys=True))

    def _render_inspector_overview(
        self, detail: RichLog, row: dict[str, Any], tenant_badge: str
    ) -> None:
        if tenant_badge and tenant_badge != "-":
            detail.write(f"Tenant: {tenant_badge}")
        for key, value in row.items():
            if key in {"raw", "custom_fields", "selected"} or key in _RF_ENRICHMENT_KEYS:
                continue
            rendered = (
                json.dumps(value, indent=2, ensure_ascii=False)
                if isinstance(value, (dict, list))
                else str(value)
            )
            detail.write(f"{key}: {rendered}")

        tenant_cfg = get_splunk_es_tenant_settings()
        if tenant_cfg.custom_fields:
            cf_map = extract_custom_fields(
                row,
                pinned_fields=tenant_cfg.custom_fields,
                discovered_fields=self._discovered_fields,
            )
            pinned_items = [(k, cf_map[k]) for k in tenant_cfg.custom_fields if k in cf_map]
            if pinned_items:
                detail.write("")
                detail.write("--- Pinned Custom Fields ---")
                for k, v in pinned_items:
                    lbl = self._discovered_labels.get(k, k)
                    detail.write(f"{lbl} ({k}): {v}")

        if "rf_observables" in row or "rf_max_risk_score" in row:
            self._render_inspector_rf(detail, row, include_header_gap=True)

    def _render_inspector_metadata(self, detail: RichLog, row: dict[str, Any]) -> None:
        detail.write("--- Finding Metadata ---")
        for k in (
            "event_id",
            "rule_title",
            "rule_name",
            "rule_description",
            "urgency",
            "severity",
            "status_label",
            "disposition",
            "owner",
            "security_domain",
            "risk_score",
            "orig_sid",
            "orig_rid",
            "queue_id",
            "source_backend",
            "_time",
        ):
            if row.get(k) not in (None, ""):
                detail.write(f"{k}: {row.get(k)}")

        tenant_cfg = get_splunk_es_tenant_settings()
        custom_map = extract_custom_fields(
            row,
            pinned_fields=tenant_cfg.custom_fields,
            discovered_fields=self._discovered_fields,
        )
        detail.write("")
        detail.write("--- Custom / Org Fields ---")
        if not custom_map:
            detail.write("(No non-internal custom/org fields present on this record.)")
        else:
            for k in sorted(custom_map.keys()):
                lbl = self._discovered_labels.get(k, k)
                prefix = f"{lbl} ({k})" if lbl != k else k
                val = custom_map[k]
                rendered = json.dumps(val, ensure_ascii=False) if isinstance(val, (dict, list)) else str(val)
                detail.write(f"{prefix}: {rendered}")

    def _render_inspector_srcdest(self, detail: RichLog, row: dict[str, Any]) -> None:
        raw_val = row.get("raw")
        raw_obj: Mapping[str, Any] = raw_val if isinstance(raw_val, Mapping) else {}
        detail.write("--- Source / Destination & Entities ---")
        for k in (
            "src",
            "src_ip",
            "src_host",
            "src_user",
            "dest",
            "dest_ip",
            "dest_host",
            "user",
            "domain",
            "dvc",
            "risk_object",
            "risk_object_type",
            "risk_score",
        ):
            val = row.get(k) if row.get(k) not in (None, "") else raw_obj.get(k)
            if val not in (None, ""):
                detail.write(f"{k}: {val}")
        if "rf_observables" in row:
            detail.write("")
            detail.write("--- RF Observable Matches ---")
            for obs in row.get("rf_observables") or []:
                if isinstance(obs, dict):
                    detail.write(
                        f"  {obs.get('source_field')}={obs.get('value')} -> "
                        f"{obs.get('risk_score')}/99 ({obs.get('criticality_label')})"
                    )

    def _render_inspector_rf(
        self, detail: RichLog, row: dict[str, Any], *, include_header_gap: bool = False
    ) -> None:
        if include_header_gap:
            detail.write("")
        detail.write("--- Recorded Future Enrichment ---")
        if "rf_observables" not in row and "rf_max_risk_score" not in row:
            detail.write("Not enriched yet. Click Enrich Selected to query Recorded Future.")
            return
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

    def _render_inspector_notes(self, detail: RichLog, row: dict[str, Any]) -> None:
        eid = str(row.get("event_id") or "").strip()
        cached = self._notes_history_cache.get(eid)
        detail.write("--- Notes ---")
        if cached is None:
            detail.write("Loading notes, audit history, and Adaptive Response invocations...")
            return
        notes = cached.get("notes") or []
        if not notes:
            detail.write("(No notes recorded.)")
        else:
            for n in notes:
                author = str(n.get("author") or n.get("user") or "-")
                ts = str(n.get("create_time") or n.get("update_time") or "-")
                title = str(n.get("title") or "").strip()
                content = str(n.get("content") or "")
                hdr = f"[{ts}] {author}" + (f" — {title}" if title else "")
                detail.write(hdr)
                detail.write(f"  {content}")

        detail.write("")
        detail.write("--- Audit History ---")
        hist = cached.get("history") or []
        if not hist:
            detail.write("(No audit history entries.)")
        else:
            for h in hist[:20]:
                ts = str(h.get("_time") or "-")
                user = str(h.get("user") or "-")
                msg = str(h.get("message") or "")
                detail.write(f"[{ts}] {user}: {msg}")

        detail.write("")
        detail.write("--- Adaptive Response Invocations ---")
        ars = cached.get("ar") or []
        if not ars:
            detail.write("(No Adaptive Response invocations recorded.)")
        else:
            for inv in ars[:15]:
                ts = str(inv.get("_time") or "-")
                name = str(inv.get("action_label") or inv.get("action_name") or "-")
                status = str(inv.get("action_status") or "-")
                detail.write(f"[{ts}] {name} | status={status}")

    def _selected_row_index(self) -> int | None:
        table = self.query_one("#es-table", DoubleClickDataTable)
        if table.row_count == 0 or not self._displayed_rows:
            return None
        row_idx = table.cursor_row
        if 0 <= row_idx < len(self._displayed_rows):
            return row_idx
        return 0

    def get_selected_row(self) -> dict[str, Any] | None:
        """Return the currently selected row dictionary, or ``None`` if none is selected."""
        idx = self._selected_row_index()
        if idx is None or idx < 0 or idx >= len(self._displayed_rows):
            return None
        row = self._displayed_rows[idx]
        if row.get("_is_group_row"):
            return None
        return row

    @on(DataTable.RowHighlighted, "#es-table")
    def handle_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self._rendering_table:
            return
        if 0 <= event.cursor_row < len(self._displayed_rows):
            self._render_detail(event.cursor_row)

    @on(DataTable.RowSelected, "#es-table")
    def handle_row_selected(self, event: DataTable.RowSelected) -> None:
        if self._rendering_table:
            return
        if 0 <= event.cursor_row < len(self._displayed_rows):
            row = self._displayed_rows[event.cursor_row]
            if row.get("_is_group_row"):
                tkey = str(row.get("_group_tenant") or "")
                if tkey in self._collapsed_tenants:
                    self._collapsed_tenants.discard(tkey)
                else:
                    self._collapsed_tenants.add(tkey)
                self._render_filtered_table(select_row=event.cursor_row)
                return
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
            items.extend(
                [
                    ("triage", "Triage Notable"),
                    ("bulk_triage", "Bulk Triage Selected"),
                    ("add_note", "Add Markdown Note"),
                    ("ar_modal", "Adaptive Response"),
                    ("investigations", "Create / Attach Investigation"),
                    ("enrich_selected", "Enrich Selected Notable with RF"),
                    ("enrich_all", "Enrich All Loaded Notables"),
                    ("post_rf_comment", "Post RF Comment to Notable"),
                    ("pivot_f8", "Pivot to Splunk Search (F8)"),
                    ("pivot_s1", "Pivot to SentinelOne (9)"),
                    ("pivot_rf", "Pivot IOC to RF Intel (4)"),
                    ("pivot_research", "Pivot IOC to Research (7)"),
                    ("pivot_llm", "Send Bundle to Local LLM (F7)"),
                ]
            )
        elif self._current_view == "correlations":
            items.append(("toggle_corr", "Toggle Enable/Disable"))
            items.append(("pivot_spl", "Open SPL in Splunk Search"))
        items.append(("open_logs", "Open Logs Tab"))

        def _on_select(action_id: str) -> None:
            if action_id == "inspect":
                if row_index is not None and 0 <= row_index < len(self._displayed_rows):
                    self._render_detail(row_index)
                    self.query_one("#es-detail", RichLog).focus()
                else:
                    self.set_status("No row selected to inspect.")
            elif action_id == "refresh":
                self.handle_refresh()
            elif action_id == "triage":
                self.handle_triage_notable()
            elif action_id == "bulk_triage":
                self.handle_bulk_triage()
            elif action_id == "add_note":
                self.handle_add_note_modal()
            elif action_id == "ar_modal":
                self.handle_open_ar_modal()
            elif action_id == "investigations":
                target_ids = self._target_event_ids()
                self._open_investigation_worker(target_ids, [], default_mode="create")
            elif action_id == "enrich_selected":
                self.handle_enrich_selected()
            elif action_id == "enrich_all":
                self.handle_enrich_all()
            elif action_id == "post_rf_comment":
                self.handle_post_rf_comment()
            elif action_id == "pivot_f8":
                self.handle_pivot_to_search()
            elif action_id == "pivot_s1":
                self.handle_pivot_to_sentinelone()
            elif action_id == "pivot_rf":
                self._emit_pivot_for_target("tab-rf-intel", auto_run=True)
            elif action_id == "pivot_research":
                self._emit_pivot_for_target("tab-research", auto_run=True)
            elif action_id == "pivot_llm":
                self.handle_pivot_to_llm_copilot()
            elif action_id == "toggle_corr":
                self.handle_toggle_correlation()
            elif action_id == "pivot_spl":
                row = (
                    self._displayed_rows[row_index]
                    if row_index is not None and 0 <= row_index < len(self._displayed_rows)
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
    # Refresh / Load Triggers (Protected by _request_seq)
    # ------------------------------------------------------------------

    def _run_if_current(
        self,
        seq: int,
        expected_view: str,
        fn: Any,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        def _guarded() -> None:
            if seq != self._request_seq or self._current_view != expected_view:
                return
            fn(*args, **kwargs)

        self.run_on_ui(_guarded)

    @on(Button.Pressed, "#es-refresh-btn")
    @on(Button.Pressed, "#es-load-ti-btn")
    @on(Button.Pressed, "#es-lookup-btn")
    @on(Input.Submitted, "#es-search-input")
    def handle_refresh(self) -> None:
        view = str(self.query_one("#es-view-select", Select).value or "notables")
        self._current_view = view
        self._request_seq += 1
        seq = self._request_seq
        search_text = self.query_one("#es-search-input", Input).value.strip()

        if view == "notables":
            urgency = str(self.query_one("#es-urgency-select", Select).value or "").strip() or None
            status = str(self.query_one("#es-status-select", Select).value or "").strip() or None
            earliest = self.query_one("#es-earliest-input", Input).value.strip() or "-24h"
            auto_enrich = bool(self.query_one("#es-auto-enrich-cb", Checkbox).value)
            include_private = bool(self.query_one("#es-private-ips-cb", Checkbox).value)
            field_map_raw = self.query_one("#es-rf-field-map-input", Input).value.strip() or None
            merged_filters = dict(self._read_structured_inputs())
            inline_facets, free_terms = _parse_structured_search(search_text)
            facet_aliases = {
                "tenant": "tenant_id",
                "tenant_id": "tenant_id",
                "disp": "disposition",
                "disposition": "disposition",
                "owner": "owner",
                "domain": "security_domain",
                "security_domain": "security_domain",
                "entity": "entity",
                "hash": "file_hash",
                "file_hash": "file_hash",
                "score": "min_score",
                "finding_score": "min_score",
                "id": "event_id",
                "event_id": "event_id",
                "_raw": "_raw",
                "raw": "_raw",
                "src": "src",
                "dest": "dest",
                "user": "user",
                "title": "title",
                "severity": "severity",
                "orig_sid": "orig_sid",
            }
            for fk, fv in inline_facets.items():
                norm_fk = facet_aliases.get(fk, fk)
                merged_filters[norm_fk] = fv

            raw_q = merged_filters.pop("_raw", None) or None
            orig_sid = merged_filters.pop("orig_sid", None) or None
            tenant_id = merged_filters.pop("tenant_id", None) or None
            owner = merged_filters.pop("owner", None) or None
            disposition = merged_filters.pop("disposition", None) or None
            security_domain = merged_filters.pop("security_domain", None) or None
            entity = merged_filters.pop("entity", None) or None
            file_hash = merged_filters.pop("file_hash", None) or None
            src = merged_filters.pop("src", None) or None
            dest = merged_filters.pop("dest", None) or None
            user = merged_filters.pop("user", None) or None
            severity = merged_filters.pop("severity", None) or None
            rule_name = merged_filters.pop("title", None) or None
            min_score_raw = merged_filters.pop("min_score", None)
            min_risk_score: float | None = self._preset_min_risk
            if min_score_raw is not None and str(min_score_raw).strip():
                try:
                    min_risk_score = float(min_score_raw)
                except (TypeError, ValueError):
                    pass
            free_search = " ".join(free_terms).strip() or None
            custom_filters = dict(merged_filters) if merged_filters else None

            self._load_notables_worker(
                seq=seq,
                expected_view=view,
                earliest=earliest,
                urgency=urgency,
                status=status,
                owner=owner,
                disposition=disposition,
                rule_name=rule_name,
                search_text=free_search,
                raw_search_text=search_text or None,
                tenant_id=tenant_id,
                security_domain=security_domain,
                severity=severity,
                entity=entity,
                src=src,
                dest=dest,
                user=user,
                file_hash=file_hash,
                min_risk_score=min_risk_score,
                raw_query=raw_q,
                orig_sid=orig_sid,
                custom_filters=custom_filters,
                item_type=self._item_type,
                auto_enrich=auto_enrich,
                include_private_ips=include_private,
                field_map_override=field_map_raw,
            )
        elif view == "correlations":
            self._load_correlations_worker(
                seq=seq,
                expected_view=view,
                search_filter=search_text or None,
            )
        elif view == "threat_intel":
            collection = str(
                self.query_one("#es-collection-select", Select).value
                or THREAT_INTEL_COLLECTIONS[0]
            )
            self._load_threat_intel_worker(
                seq=seq,
                expected_view=view,
                collection=collection,
                filter_text=search_text,
            )
        elif view == "assets_identities":
            kind = str(self.query_one("#es-entity-kind-select", Select).value or "assets")
            self._load_assets_identities_worker(
                seq=seq,
                expected_view=view,
                kind=kind,
                query=search_text,
            )
        elif view == "risk":
            earliest = self.query_one("#es-earliest-input", Input).value.strip() or "-24h"
            self._load_risk_worker(
                seq=seq,
                expected_view=view,
                risk_object=search_text or None,
                earliest=earliest,
            )

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
        seq: int,
        expected_view: str,
        earliest: str,
        urgency: str | None,
        status: str | None,
        search_text: str | None,
        raw_search_text: str | None = None,
        owner: str | None = None,
        disposition: str | None = None,
        rule_name: str | None = None,
        tenant_id: str | None = None,
        security_domain: str | None = None,
        severity: str | None = None,
        entity: str | None = None,
        src: str | None = None,
        dest: str | None = None,
        user: str | None = None,
        file_hash: str | None = None,
        min_risk_score: float | None = None,
        raw_query: str | None = None,
        orig_sid: str | None = None,
        custom_filters: dict[str, str] | None = None,
        item_type: str = "all",
        auto_enrich: bool = False,
        include_private_ips: bool = False,
        field_map_override: str | None = None,
    ) -> None:
        self._loading = True
        try:
            self.set_status(f"Loading Splunk ES findings/notables ({earliest} to now)...")
            backend = "spl_fallback"
            notables: list[dict[str, Any]] = []
            with self.log_scope("splunk"):
                with self._build_es_client() as es:
                    if isinstance(es, SplunkESClient):
                        try:
                            discovered = es.discover_custom_fields()
                            if discovered:
                                self._discovered_fields = discovered
                                self._discovered_labels = {
                                    d["field"]: d["label"] for d in discovered if d.get("field")
                                }
                        except Exception:
                            pass
                        try:
                            if not self._splunk_users:
                                users = es.list_users(count=100)
                                self._splunk_users = [
                                    str(u["username"]) for u in users if u.get("username")
                                ]
                        except Exception:
                            pass
                        try:
                            if not self._current_splunk_user:
                                self._current_splunk_user = es.get_current_user()
                        except Exception:
                            pass

                    hybrid_fn = getattr(es, "query_findings_hybrid", None)
                    hybrid_res = None
                    if callable(hybrid_fn):
                        candidate = hybrid_fn(
                            earliest=earliest,
                            urgency=urgency,
                            status=status,
                            owner=owner,
                            disposition=disposition,
                            rule_name=rule_name,
                            search_text=search_text,
                            tenant_id=tenant_id,
                            security_domain=security_domain,
                            severity=severity,
                            entity=entity,
                            src=src,
                            dest=dest,
                            user=user,
                            file_hash=file_hash,
                            min_risk_score=min_risk_score,
                            raw_query=raw_query,
                            orig_sid=orig_sid,
                            custom_filters=custom_filters,
                            item_type=item_type,
                            limit=100,
                        )
                        if isinstance(candidate, dict) and isinstance(candidate.get("items"), list):
                            hybrid_res = candidate

                    if hybrid_res is not None:
                        notables = list(hybrid_res["items"])
                        backend = str(hybrid_res.get("source_backend") or "mc_v2")
                    else:
                        notables = es.list_notables(
                            earliest=earliest,
                            urgency=urgency,
                            status=status,
                            search_text=raw_search_text or search_text,
                            limit=100,
                        )
                        backend = "spl_fallback"

            if seq != self._request_seq or self._current_view != expected_view:
                return

            self._source_backend = backend
            cols = self._get_notable_columns()
            self._run_if_current(
                seq,
                expected_view,
                self._populate_table,
                notables,
                cols,
                header_label="Notable Events",
            )
            msg = f"Loaded {len(notables)} Splunk ES finding/notable(s) [{backend}]."
            self.set_status(msg)
            self.append_log(msg)

            if auto_enrich and notables and self._can_auto_enrich_rf():
                if seq != self._request_seq or self._current_view != expected_view:
                    return
                try:
                    self.set_status(
                        f"Auto-enriching {len(notables)} Splunk ES finding(s) with Recorded Future..."
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
                    if seq != self._request_seq or self._current_view != expected_view:
                        return
                    mapped_cnt = sum(1 for row in enriched if row.get("rf_observables"))
                    self._run_if_current(
                        seq,
                        expected_view,
                        self._populate_table,
                        enriched,
                        cols,
                        header_label="Notable Events",
                    )
                    done_msg = (
                        f"Loaded {len(enriched)} Splunk ES finding(s); "
                        f"RF enriched {mapped_cnt}/{len(enriched)} with mapped IOCs."
                    )
                    self.set_status(done_msg)
                    self.append_log(done_msg)
                except Exception as exc:
                    warn_msg = (
                        f"Loaded {len(notables)} finding(s); RF auto-enrichment skipped: "
                        f"{self.format_exception(exc)}"
                    )
                    self.set_status(warn_msg)
                    self.append_log(warn_msg, level="WARNING")
        except Exception as exc:
            if seq == self._request_seq and self._current_view == expected_view:
                self.report_error("Load ES Notables", exc)
        finally:
            self._loading = False

    @work(thread=True, exit_on_error=False)
    def _load_correlations_worker(
        self, *, seq: int, expected_view: str, search_filter: str | None
    ) -> None:
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
            self._run_if_current(
                seq,
                expected_view,
                self._populate_table,
                items,
                cols,
                header_label="Correlation Searches",
            )
            if seq == self._request_seq and self._current_view == expected_view:
                msg = f"Loaded {len(items)} Splunk ES correlation search(es)."
                self.set_status(msg)
                self.append_log(msg)
        except Exception as exc:
            if seq == self._request_seq and self._current_view == expected_view:
                self.report_error("Load ES Correlations", exc)

    @work(thread=True, exit_on_error=False)
    def _load_threat_intel_worker(
        self, *, seq: int, expected_view: str, collection: str, filter_text: str
    ) -> None:
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
            self._run_if_current(
                seq,
                expected_view,
                self._populate_table,
                entries,
                cols,
                header_label=f"Threat Intel ({collection})",
            )
            if seq == self._request_seq and self._current_view == expected_view:
                msg = f"Loaded {len(entries)} entry/entries from '{collection}'."
                self.set_status(msg)
                self.append_log(msg)
        except Exception as exc:
            if seq == self._request_seq and self._current_view == expected_view:
                self.report_error("Load ES Threat Intel", exc)

    @work(thread=True, exit_on_error=False)
    def _load_assets_identities_worker(
        self, *, seq: int, expected_view: str, kind: str, query: str
    ) -> None:
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
            self._run_if_current(
                seq,
                expected_view,
                self._populate_table,
                rows,
                cols,
                header_label=f"ES {label}",
            )
            if seq == self._request_seq and self._current_view == expected_view:
                msg = f"Loaded {len(rows)} Splunk ES {label.lower()} record(s)."
                self.set_status(msg)
                self.append_log(msg)
        except Exception as exc:
            if seq == self._request_seq and self._current_view == expected_view:
                self.report_error("ES Asset/Identity Lookup", exc)

    @work(thread=True, exit_on_error=False)
    def _load_risk_worker(
        self, *, seq: int, expected_view: str, risk_object: str | None, earliest: str
    ) -> None:
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
            self._run_if_current(
                seq,
                expected_view,
                self._populate_table,
                rows,
                cols,
                header_label="Risk Events (RBA)",
            )
            if seq == self._request_seq and self._current_view == expected_view:
                msg = f"Loaded {len(rows)} Splunk ES risk event(s)."
                self.set_status(msg)
                self.append_log(msg)
        except Exception as exc:
            if seq == self._request_seq and self._current_view == expected_view:
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
            rule_name=str(row.get("rule_title") or row.get("rule_name") or event_id),
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
                    if isinstance(es, SplunkESClient):
                        es.triage_findings_hybrid(
                            [event_id],
                            status=updates.get("status"),
                            urgency=updates.get("urgency"),
                            owner=updates.get("owner"),
                            disposition=updates.get("disposition"),
                            note=updates.get("comment"),
                        )
                    else:
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
        if idx is None or idx < 0 or idx >= len(self._displayed_rows):
            self.set_status("Select a notable event before enriching with Recorded Future.")
            return
        row = self._displayed_rows[idx]
        if row.get("_is_group_row"):
            self.set_status("Select a finding row rather than a group header.")
            return
        opts = self._read_rf_enrichment_options()
        if opts is None:
            return
        field_map, include_private = opts
        target_row = dict(row)
        self._enrich_notables_worker(
            seq=self._request_seq,
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
            seq=self._request_seq,
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
        seq: int | None = None,
    ) -> None:
        expected_seq = self._request_seq if seq is None else seq
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
                if expected_seq != self._request_seq or self._current_view != "notables":
                    return
                cols = self._get_notable_columns()
                if row_index is not None:
                    if 0 <= row_index < len(self._displayed_rows) and enriched:
                        target_eid = str(self._displayed_rows[row_index].get("event_id") or "")
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
                            cols,
                            header_label="Notable Events",
                            select_row=row_index,
                        )
                elif len(enriched) < len(self._raw_rows):
                    by_id = {
                        str(r.get("event_id") or ""): r
                        for r in enriched
                        if str(r.get("event_id") or "").strip()
                    }
                    merged_raw = [
                        by_id.get(str(r.get("event_id") or "").strip(), r) for r in self._raw_rows
                    ]
                    sel = self._selected_row_index() or 0
                    self._populate_table(
                        merged_raw,
                        cols,
                        header_label="Notable Events",
                        select_row=sel,
                    )
                else:
                    sel = self._selected_row_index() or 0
                    self._populate_table(
                        enriched,
                        cols,
                        header_label="Notable Events",
                        select_row=sel,
                    )

            self.run_on_ui(_apply)
            if expected_seq != self._request_seq or self._current_view != "notables":
                return
            mapped_cnt = sum(1 for r in enriched if r.get("rf_observables"))
            msg = (
                f"Recorded Future enrichment complete for {scope_lbl}: "
                f"{mapped_cnt}/{len(enriched)} with mapped IOCs."
            )
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            if expected_seq == self._request_seq and self._current_view == "notables":
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
                    write_enrichment_to_notable(
                        es,
                        event_id,
                        enriched_row,
                        dry_run=False,
                        use_mc_v2=isinstance(es, SplunkESClient),
                        finding_time=str(enriched_row.get("_time") or "") or None,
                    )
            msg = f"Posted Recorded Future enrichment comment to notable '{event_id}'."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="RF Comment Posted")
        except Exception as exc:
            self.report_error("Post RF Comment", exc)
