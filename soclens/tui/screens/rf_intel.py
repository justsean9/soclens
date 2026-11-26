"""Recorded Future Intel, Entity Match, SOAR Enrichment, Alerts, Cases & Sandbox pane."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, ClassVar

from rich.console import Group
from rich.panel import Panel
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, HorizontalScroll, Vertical
from textual.coordinate import Coordinate
from textual.widgets import (
    Button,
    Collapsible,
    DataTable,
    Input,
    RichLog,
    Select,
    Static,
    TabbedContent,
)

from soclens.alert_cache import CACHE_SOURCE_RF, CACHE_SOURCE_RF_PLAYBOOK
from soclens.client import RecordedFutureError
from soclens.event_tracker import EventSourceKind, UniqueEvent, normalize_unique_event
from soclens.tui.ai_widgets import EventAIPanelWidget
from soclens.tui.filters import (
    ASSIGNEE_FILTER_BASE_OPTIONS,
    PRIORITY_FILTER_OPTIONS,
    SORT_FILTER_OPTIONS,
    TIME_FIELD_OPTIONS,
    TIMEFRAME_OPTIONS,
    FilterPreset,
    assignee_matches_filter,
    build_alerts_v3_triggered_param,
    build_case_date_range,
    build_playbook_date_range,
    delete_custom_rf_preset,
    extract_item_timestamp,
    get_all_rf_presets,
    map_priority_for_cases,
    map_priority_for_playbook,
    priority_matches_filter,
    sanitize_preset_id,
    save_custom_rf_preset,
    sort_rf_items,
    timeframe_label,
    timestamp_matches_timeframe,
)
from soclens.tui.image_render import (
    blur_decoded_image,
    blur_image_bytes,
    build_kitty_upload_sequence,
    can_emit_kitty_truecolor,
    clear_kitty_images,
    compute_terminal_cell_grid,
    detect_terminal_graphics_protocol,
    encode_png,
    get_terminal_cell_aspect,
    is_tmux_session,
    next_kitty_image_id,
    open_image_in_native_viewer,
    prepare_image_cache_entry,
    stage_screenshot_file,
    write_terminal_graphics,
)
from soclens.tui.modals import (
    CreateCaseModal,
    SaveFilterPresetModal,
    ScreenshotViewerModal,
    TriageItemModal,
)
from soclens.tui.pivot import PivotPayload
from soclens.tui.rf_formatters import (
    PLAYBOOK_API_STATUS_MAP,
    STATUS_FILTER_CHOICES,
    build_summary_bar_text,
    extract_alerts_v3,
    extract_cases,
    extract_playbook_alerts,
    extract_sandbox_samples,
    extract_soar_results,
    format_timestamp,
    is_alert_v3_detail_stale,
    is_playbook_detail_stale,
    normalize_alert_v3,
    normalize_case,
    normalize_entity_match,
    normalize_playbook_alert,
    normalize_sandbox_sample,
    normalize_soar_item,
    normalize_status_key,
    normalize_v2_record,
    priority_text,
    render_alert_v3_detail,
    render_case_detail,
    render_entity_match_detail,
    render_error_panel,
    render_playbook_alert_detail,
    render_raw_json,
    render_sandbox_detail,
    render_soar_detail,
    render_v2_intel_card,
    render_welcome_view,
    score_text,
    status_matches_filter,
    status_text,
    truncate_text,
)
from soclens.tui.screens.base import (
    BaseSocPane,
    DoubleClickDataTable,
    SelectableRichLog,
    extract_richlog_text,
    extract_table_row_text,
)

_V2_LOOKUP_FIELDS: dict[str, list[str]] = {
    "ip": ["entity", "risk", "timestamps", "intelCard", "threatLists", "counts", "location"],
    "domain": ["entity", "risk", "timestamps", "intelCard", "threatLists", "counts"],
    "hash": [
        "entity",
        "risk",
        "timestamps",
        "intelCard",
        "threatLists",
        "counts",
        "hashAlgorithm",
    ],
    "url": ["entity", "risk", "timestamps", "intelCard", "counts"],
    "vulnerability": [
        "entity",
        "risk",
        "timestamps",
        "intelCard",
        "cvss",
        "nvdDescription",
        "lifecycleStage",
        "counts",
    ],
}

_V2_TO_WATCHLIST_TYPE: dict[str, str] = {
    "domain": "InternetDomainName",
    "internetdomainname": "InternetDomainName",
    "ip": "IpAddress",
    "ipaddress": "IpAddress",
    "hash": "Hash",
    "url": "URL",
    "vulnerability": "CyberVulnerability",
    "cybervulnerability": "CyberVulnerability",
    "company": "Company",
}

_WATCHLIST_TO_V2_TYPE: dict[str, str] = {
    "internetdomainname": "domain",
    "domain": "domain",
    "ipaddress": "ip",
    "ip": "ip",
    "hash": "hash",
    "url": "url",
    "cybervulnerability": "vulnerability",
    "vulnerability": "vulnerability",
}

_PIVOT_V2_TYPE_ALIASES: dict[str, str] = {
    **_WATCHLIST_TO_V2_TYPE,
    "ip_address": "ip",
    "file_hash": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "md5": "hash",
    "cve": "vulnerability",
}

_VIEW_LABELS: dict[str, str] = {
    "welcome": "Quick Start",
    "alerts_v3": "Alerts v3",
    "playbook": "Playbook Alerts",
    "cases": "Cases",
    "intel_v2": "IOC Intel (v2)",
    "soar": "SOAR v3 Results",
    "entity_match": "Entity Match",
    "sandbox": "Sandbox v0",
}

_CUSTOM_PRESET_SENTINEL = "__custom__"
_BASE_ASSIGNEE_VALUES: frozenset[str] = frozenset({"any", "unassigned", "assigned"})

_WELCOME_ROWS: tuple[dict[str, str], ...] = (
    {
        "action_id": "alerts_v3",
        "workflow": "Alerts v3",
        "trigger": "Load Alerts v3",
        "summary": "Classic alert queue, hits, AI insights, bulk status triage, create Case",
    },
    {
        "action_id": "playbook",
        "workflow": "Playbook Alerts",
        "trigger": "Load Playbook Alerts",
        "summary": "Brand logo hash matches, DNS/WHOIS panels, PNG screenshots, triage",
    },
    {
        "action_id": "cases",
        "workflow": "Cases",
        "trigger": "Load Cases",
        "summary": "Investigation cases, audit logs, priority & status updates",
    },
    {
        "action_id": "intel_v2",
        "workflow": "Connect v2 / SOAR",
        "trigger": "v2 Lookup / SOAR Enrich",
        "summary": "Intelligence Cards with risk gauge, triggered rules, geolocation, triage",
    },
    {
        "action_id": "entity_match",
        "workflow": "Entity Match & Sandbox",
        "trigger": "Entity Match / Search Sandbox",
        "summary": "Resolve RF entity IDs, pivot to Watchlists, inspect Sandbox signatures",
    },
)

_STATUS_BUTTON_TO_VALUE: dict[str, str] = {
    f"rf-st-{normalize_status_key(val)}": val for _lbl, val in STATUS_FILTER_CHOICES
}
_logger = logging.getLogger(__name__)

_TABLE_SPECS: dict[str, tuple[tuple[str, str, float, int], ...]] = {
    "welcome": (
        ("workflow", "Workflow", 0.24, 14),
        ("trigger", "Trigger", 0.28, 16),
        ("summary", "Capabilities", 0.48, 22),
    ),
    "alerts_v3": (
        ("priority", "Priority", 0.10, 8),
        ("status", "Status", 0.12, 9),
        ("rule", "Rule", 0.21, 12),
        ("title", "Title", 0.27, 16),
        ("assignee", "Assignee", 0.12, 10),
        ("hits", "Hits", 0.06, 5),
        ("triggered", "Triggered", 0.12, 12),
    ),
    "playbook": (
        ("priority", "Priority", 0.12, 8),
        ("status", "Status", 0.13, 9),
        ("category", "Category", 0.18, 12),
        ("title", "Title", 0.31, 16),
        ("assignee", "Assignee", 0.12, 10),
        ("updated", "Updated", 0.14, 12),
    ),
    "cases": (
        ("priority", "Priority", 0.12, 8),
        ("status", "Status", 0.14, 10),
        ("title", "Title", 0.42, 18),
        ("assignee", "Assignee", 0.16, 10),
        ("updated", "Updated", 0.16, 12),
    ),
    "intel_v2": (
        ("score", "Score", 0.10, 6),
        ("type", "Type", 0.14, 9),
        ("entity", "Entity", 0.32, 16),
        ("criticality", "Criticality", 0.16, 10),
        ("rules", "Rules / Sightings", 0.28, 14),
    ),
    "soar": (
        ("score", "Score", 0.10, 6),
        ("verdict", "Verdict", 0.14, 10),
        ("type", "Type", 0.14, 9),
        ("ioc", "IOC", 0.30, 16),
        ("top_rule", "Context / Top Rule", 0.32, 16),
    ),
    "entity_match": (
        ("id", "Entity ID", 0.30, 16),
        ("type", "Type", 0.24, 12),
        ("name", "Name", 0.46, 20),
    ),
    "sandbox": (
        ("score", "Score", 0.10, 6),
        ("status", "Status", 0.14, 10),
        ("target", "Target", 0.34, 16),
        ("sha256", "SHA-256", 0.24, 14),
        ("submitted", "Submitted", 0.18, 12),
    ),
}


def _infer_ioc_type_and_value(raw_val: str, known_type: str = "") -> tuple[str, str]:
    """Infer Connect v2 entity type and clean IOC value from a raw entity label."""
    val = raw_val.strip()
    lower = val.lower()
    for prefix, mapped in (
        ("ip:", "ip"),
        ("idn:", "domain"),
        ("hash:", "hash"),
        ("url:", "url"),
    ):
        if lower.startswith(prefix):
            return mapped, val[len(prefix) :].strip()

    if known_type:
        mapped_type = _WATCHLIST_TO_V2_TYPE.get(known_type.strip().lower())
        if mapped_type:
            return mapped_type, val

    if lower.startswith(("http://", "https://")):
        return "url", val
    if lower.startswith("cve-"):
        return "vulnerability", val
    try:
        ipaddress.ip_address(val)
        return "ip", val
    except ValueError:
        pass
    if len(val) in (32, 40, 64) and re.fullmatch(r"[0-9a-fA-F]+", val):
        return "hash", val
    return "domain", val


class RFIntelPane(BaseSocPane):
    """Interactive Recorded Future threat intelligence & SOC operations workbench."""

    STATUS_ID = "rf-status"
    LOG_ID = "rf-log"
    LOG_SOURCE = "rf_intel"

    DEFAULT_CSS: ClassVar[str] = """
    RFIntelPane #rf-status-bar {
        height: 1;
        width: 1fr;
        overflow-y: hidden;
        background: #131926;
        padding: 0 1;
        align-vertical: middle;
    }
    RFIntelPane #rf-status-bar Button {
        min-width: 5;
        margin-right: 1;
    }
    RFIntelPane #rf-auto-enrich-btn {
        min-width: 15;
    }
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("slash", "toggle_filter", "Filter & Tools"),
        Binding("escape", "collapse_filter", "Close Filter", show=False),
        Binding("j", "toggle_json_view", "Raw JSON"),
        Binding("v", "view_screenshots", "Images"),
        Binding("o", "open_screenshot_os", "Open Image", show=False),
        Binding("b", "toggle_image_blur", "Blur/Reveal", show=False),
        Binding("t", "triage_selected", "Triage"),
        Binding("m", "open_context_menu", "Menu"),
        Binding("r", "reload_active_view", "Reload"),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._datasets: dict[str, list[dict[str, Any]]] = {
            "alerts_v3": [],
            "playbook": [],
            "cases": [],
            "intel_v2": [],
            "soar": [],
            "entity_match": [],
            "sandbox": [],
        }
        self._dataset_totals: dict[str, int | None] = {}
        self._detail_cache: dict[tuple[str, str], dict[str, Any]] = {}
        self._image_cache: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._active_mode: str = "welcome"
        self._detail_mode: str = "overview"
        self._visible_items: list[dict[str, Any]] = []
        self._selected_index: int | None = None
        self._tables_ready: bool = False
        self._rendering_table: bool = False
        self._syncing_view_select: bool = False
        self._request_seq: int = 0
        self._enrich_seq: int = 0
        self._selected_statuses: list[str] = []
        self._active_preset_id: str = "all"
        self._priority_filter: str = "any"
        self._timeframe_filter: str = "any"
        self._assignee_filter: str = "any"
        self._sort_by: str = "newest"
        self._time_field: str = "auto"
        self._applying_preset: bool = False
        self._syncing_assignee_options: bool = False
        self._syncing_preset_options: bool = False
        self._presets_by_id: dict[str, FilterPreset] = {}
        self._auto_enrich_enabled: bool = True
        self._auto_enriched_keys: set[tuple[str, str]] = set()
        self._last_detail_width: int = 0
        self._last_error_payload: tuple[str, str] | None = None
        self._inline_kitty_ids: list[int] = []
        self._preparing_image_keys: set[tuple[str, str, str]] = set()

    def _safe_load_presets(self) -> list[FilterPreset]:
        try:
            ws = self.workspace_dir
        except Exception:
            ws = None
        presets = get_all_rf_presets(workspace_dir=ws)
        self._presets_by_id = {p.id: p for p in presets}
        return presets

    def _build_preset_select_options(self) -> list[tuple[str, str]]:
        presets = self._safe_load_presets()
        options: list[tuple[str, str]] = [(p.label, p.id) for p in presets]
        options.append(("Custom Filter", _CUSTOM_PRESET_SENTINEL))
        return options

    def compose(self) -> ComposeResult:
        yield Static("Recorded Future Intel, SOAR & Alerts", classes="pane-title")
        yield Static(
            "Ready. Load Alerts, Playbook Alerts, Cases, or pick a View Preset.",
            id="rf-status",
            classes="status-bar",
            markup=False,
        )

        with Horizontal(id="rf-top-toolbar", classes="action-row toolbar-row"):
            yield Button("Load Alerts v3", id="rf-alerts-btn", variant="primary", compact=True)
            yield Button("Load Playbook Alerts", id="rf-pb-btn", compact=True)
            yield Button("Load Cases", id="rf-cases-btn", compact=True)
            yield Input(value="20", placeholder="Limit", id="rf-limit-input", compact=True)
            yield Button("Auto-Enrich: ON", id="rf-auto-enrich-btn", variant="primary", compact=True)
            yield Select(
                self._build_preset_select_options(),
                allow_blank=False,
                value="all",
                id="rf-preset-select",
                compact=True,
            )

        with Horizontal(id="rf-filter-bar", classes="action-row filter-bar"):
            yield Select(
                list(PRIORITY_FILTER_OPTIONS),
                allow_blank=False,
                value="any",
                id="rf-priority-filter",
                compact=True,
            )
            yield Select(
                list(TIMEFRAME_OPTIONS),
                allow_blank=False,
                value="any",
                id="rf-timeframe-filter",
                compact=True,
            )
            yield Select(
                list(ASSIGNEE_FILTER_BASE_OPTIONS),
                allow_blank=False,
                value="any",
                id="rf-assignee-filter",
                compact=True,
            )
            yield Select(
                list(SORT_FILTER_OPTIONS),
                allow_blank=False,
                value="newest",
                id="rf-sort-select",
                compact=True,
            )
            yield Button("Save View", id="rf-save-preset-btn", compact=True)
            yield Button("Reset", id="rf-reset-filters-btn", compact=True)

        with HorizontalScroll(id="rf-status-bar"):
            yield Button("All", id="rf-st-all", variant="primary", compact=True)
            for short_lbl, st_val in STATUS_FILTER_CHOICES:
                yield Button(
                    short_lbl,
                    id=f"rf-st-{normalize_status_key(st_val)}",
                    compact=True,
                )

        with Container(id="rf-lookup-bar"):
            with Horizontal(id="rf-ioc-row", classes="action-row toolbar-row"):
                yield Select(
                    [
                        ("ip", "ip"),
                        ("domain", "domain"),
                        ("hash", "hash"),
                        ("url", "url"),
                        ("vulnerability", "vulnerability"),
                    ],
                    allow_blank=False,
                    value="ip",
                    id="rf-v2-type",
                    compact=True,
                )
                yield Input(
                    placeholder="IOC value(s) (comma-separated for SOAR enrich)",
                    id="rf-ioc-input",
                    compact=True,
                )
                yield Button("v2 Lookup", id="rf-lookup-btn", compact=True)
                yield Button("SOAR Enrich", id="rf-enrich-btn", compact=True)

            with Horizontal(id="rf-entity-row", classes="action-row toolbar-row"):
                yield Input(
                    placeholder="Entity match / search / sandbox query",
                    id="rf-query-input",
                    compact=True,
                )
                yield Button("Entity Match", id="rf-match-btn", compact=True)
                yield Button("Search Sandbox", id="rf-sandbox-btn", compact=True)

        with Collapsible(
            title="More Filters, Custom Dates & Tools (press /)",
            collapsed=True,
            collapsed_symbol=">",
            expanded_symbol="v",
            id="rf-filter-collapsible",
        ):
            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    placeholder="Filter loaded rows (ID, title, rule, entity, status)...",
                    id="rf-table-filter",
                    compact=True,
                )
                yield Input(
                    placeholder="Rule contains...",
                    id="rf-rule-filter",
                    compact=True,
                )
                yield Input(
                    placeholder="Entity/target contains...",
                    id="rf-entity-filter",
                    compact=True,
                )
                yield Select(
                    [
                        ("All Categories", "all"),
                        ("Brand (Domain Abuse + Malicious)", "brand_bundle"),
                        ("domain_abuse", "domain_abuse"),
                        ("malicious_sites", "malicious_sites"),
                        ("cyber_vulnerability", "cyber_vulnerability"),
                        ("code_repo_leakage", "code_repo_leakage"),
                        ("third_party_risk", "third_party_risk"),
                        ("identity_novel_exposures", "identity_novel_exposures"),
                        ("dark_web", "dark_web"),
                        ("socmed_impersonation", "socmed_impersonation"),
                    ],
                    allow_blank=False,
                    value="all",
                    id="rf-pb-category",
                    compact=True,
                )
                yield Button("Clear", id="rf-clear-filter-btn", compact=True)
            with Horizontal(classes="action-row filter-bar"):
                yield Select(
                    list(TIME_FIELD_OPTIONS),
                    allow_blank=False,
                    value="auto",
                    id="rf-time-field-select",
                    compact=True,
                )
                yield Input(
                    placeholder="From (YYYY-MM-DD / -7d)",
                    id="rf-date-from",
                    compact=True,
                )
                yield Input(
                    placeholder="To (YYYY-MM-DD)",
                    id="rf-date-to",
                    compact=True,
                )
                yield Button("Fetch Filtered", id="rf-apply-server-btn", variant="primary", compact=True)
                yield Button("Delete Preset", id="rf-delete-preset-btn", variant="error", compact=True, disabled=True)
            with Horizontal(classes="action-row toolbar-row"):
                yield Select(
                    [
                        ("phishing", "phishing"),
                        ("malware", "malware"),
                        ("c2", "c2"),
                    ],
                    allow_blank=False,
                    value="phishing",
                    id="rf-triage-context",
                    compact=True,
                )
                yield Button("SOAR Triage", id="rf-triage-btn", compact=True)
                yield Button("Company by Domain", id="rf-company-btn", compact=True)
                yield Button("OS Viewer Default: OFF", id="rf-os-viewer-default-btn", compact=True)
                yield Select(
                    [
                        ("Quick Start", "welcome"),
                        ("Alerts v3", "alerts_v3"),
                        ("Playbook Alerts", "playbook"),
                        ("Cases", "cases"),
                        ("IOC Intel (v2)", "intel_v2"),
                        ("SOAR v3 Results", "soar"),
                        ("Entity Match", "entity_match"),
                        ("Sandbox v0", "sandbox"),
                    ],
                    allow_blank=False,
                    value="welcome",
                    id="rf-view-select",
                    compact=True,
                )

        yield Static("", id="rf-summary-bar", classes="rf-summary-bar", markup=False)

        with Container(id="rf-workspace", classes="split-workspace"):
            with Vertical(id="rf-results-pane", classes="table-pane"):
                yield Static(
                    "Quick Start (select a workflow or load data above)",
                    id="rf-results-header",
                    classes="section-label",
                    markup=False,
                )
                yield DoubleClickDataTable(id="rf-results-table")

            with Vertical(id="rf-detail-pane", classes="table-pane"):
                with Horizontal(id="rf-detail-toolbar", classes="detail-toolbar"):
                    yield Static(
                        "Inspector (Overview)",
                        id="rf-detail-header",
                        classes="section-label",
                        markup=False,
                    )
                    yield Button(
                        "Overview",
                        id="rf-view-overview-btn",
                        variant="primary",
                        compact=True,
                    )
                    yield Button("Raw JSON", id="rf-view-json-btn", compact=True)
                    yield Button("Deep Detail", id="rf-fetch-detail-btn", compact=True)
                    yield Button("Images", id="rf-images-btn", compact=True)
                    yield Button("Blur: ON", id="rf-blur-images-btn", variant="warning", compact=True)
                    yield Button("Triage...", id="rf-triage-status-btn", compact=True)
                    yield Button("Copy Detail", id="rf-copy-detail-btn", compact=True)
                yield SelectableRichLog(
                    id="rf-log",
                    classes="detail-log",
                    highlight=False,
                    markup=False,
                    wrap=True,
                )
                yield EventAIPanelWidget(id="rf-ai-panel")

    def on_mount(self) -> None:
        table = self.query_one("#rf-results-table", DoubleClickDataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        self._tables_ready = True
        self._hydrated_from_cache: bool = False
        self._cache_fetched_at: float = 0.0
        self._pb_cache_fetched_at: float = 0.0
        self._refresh_preset_options(select_id=self._active_preset_id)
        hydrated = self.hydrate_from_alert_cache(force=False)
        if not hydrated and self._active_mode == "welcome":
            self._render_view()
        self._update_responsive_layout()

    def _hydrate_playbook_cache(self, cache: Any, *, force: bool = False) -> bool:
        pb_entry = cache.get(CACHE_SOURCE_RF_PLAYBOOK)
        if pb_entry is None:
            return False
        if (
            not force
            and getattr(self, "_pb_cache_fetched_at", 0.0) > 0.0
            and pb_entry.fetched_at <= getattr(self, "_pb_cache_fetched_at", 0.0)
        ):
            return False
        self._datasets["playbook"] = list(pb_entry.items)
        raw_total = pb_entry.meta.get("total")
        self._dataset_totals["playbook"] = (
            raw_total if isinstance(raw_total, int) else len(pb_entry.items)
        )
        pb_details = pb_entry.meta.get("details")
        pb_detail_ids = (
            {str(aid) for aid in pb_details if aid and isinstance(pb_details[aid], dict)}
            if isinstance(pb_details, dict)
            else set()
        )
        for item in pb_entry.items:
            aid = str(item.get("id") or "").strip()
            if aid and aid not in pb_detail_ids:
                key = ("playbook", aid)
                self._detail_cache.pop(key, None)
                self._auto_enriched_keys.discard(key)
        if isinstance(pb_details, dict):
            for aid, detail in pb_details.items():
                if aid and isinstance(detail, dict):
                    key = ("playbook", str(aid))
                    self._detail_cache[key] = detail
                    self._auto_enriched_keys.add(key)
        # Only pull already-prepared (memory) images here — never decode/crop/read disk on the UI thread.
        pb_img_keys = pb_entry.meta.get("image_keys")
        get_prepared = getattr(cache, "get_prepared_image", None)
        prep_hits = 0
        if isinstance(pb_img_keys, dict) and callable(get_prepared):
            for aid, entries in pb_img_keys.items():
                if not isinstance(entries, list):
                    continue
                for rec in entries:
                    if not isinstance(rec, (list, tuple)) or len(rec) != 3:
                        continue
                    eff_cat, sid, img_key = str(rec[0]), str(rec[1]), str(rec[2])
                    cache_tuple = (eff_cat, str(aid), sid)
                    existing_img = self._image_cache.get(cache_tuple)
                    if existing_img and existing_img.get("decoded") is not None and not existing_img.get("error"):
                        continue
                    prepared = get_prepared(img_key)
                    if isinstance(prepared, dict) and prepared.get("decoded") is not None:
                        self._image_cache[cache_tuple] = prepared
                        prep_hits += 1
        self._pb_cache_fetched_at = pb_entry.fetched_at
        self.record_app_log(
            f"Hydrated Playbook cache ({len(pb_entry.items)} item(s), {prep_hits} prepared image(s)).",
            level="DEBUG",
            source="cache",
        )
        if self._active_mode == "playbook":
            sel = self._get_selected_item()
            preserve = str(sel.get("id") or "") if sel is not None else None
            self._refresh_assignee_options()
            self._render_view(preserve_id=preserve, schedule_auto_enrich=False)
        return True

    def hydrate_from_alert_cache(self, *, force: bool = False) -> bool:
        """Populate RF Alerts v3 and Playbook Alerts (with prepared images) from the local 24h cache."""
        if not self._tables_ready:
            return False
        cache = getattr(self.app, "alert_cache", None)
        if cache is None:
            return False
        pb_hydrated = self._hydrate_playbook_cache(cache, force=force)
        entry = cache.get(CACHE_SOURCE_RF)
        if entry is None:
            loading_fn = getattr(self.app, "is_cache_source_loading", None)
            if (
                self._active_mode == "welcome"
                and callable(loading_fn)
                and loading_fn(CACHE_SOURCE_RF)
            ):
                self.set_status(
                    "Background preload in progress for RF Alerts (24h)... Data will populate automatically."
                )
            return pb_hydrated

        manual_alerts_loaded = bool(self._datasets.get("alerts_v3")) and not getattr(
            self, "_hydrated_from_cache", False
        )
        if not force and manual_alerts_loaded and self._active_mode == "alerts_v3":
            return pb_hydrated

        already_same_cache = (
            getattr(self, "_hydrated_from_cache", False)
            and getattr(self, "_cache_fetched_at", 0.0) > 0.0
            and entry.fetched_at <= getattr(self, "_cache_fetched_at", 0.0)
        )
        if not force and already_same_cache:
            if self._active_mode == "welcome":
                self._active_mode = "alerts_v3"
                self._refresh_assignee_options()
                self._render_view(schedule_auto_enrich=False)
                return True
            return pb_hydrated

        self._datasets["alerts_v3"] = list(entry.items)
        raw_total = entry.meta.get("total")
        self._dataset_totals["alerts_v3"] = (
            raw_total if isinstance(raw_total, int) else len(entry.items)
        )
        cached_details = entry.meta.get("details")
        cached_detail_ids = (
            {str(aid) for aid in cached_details if aid and isinstance(cached_details[aid], dict)}
            if isinstance(cached_details, dict)
            else set()
        )
        for item in entry.items:
            aid = str(item.get("id") or "").strip()
            if aid and aid not in cached_detail_ids:
                key = ("alerts_v3", aid)
                self._detail_cache.pop(key, None)
                self._auto_enriched_keys.discard(key)
        if isinstance(cached_details, dict):
            for aid, detail in cached_details.items():
                if aid and isinstance(detail, dict):
                    key = ("alerts_v3", str(aid))
                    self._detail_cache[key] = detail
                    self._auto_enriched_keys.add(key)
        self._hydrated_from_cache = True
        self._cache_fetched_at = entry.fetched_at

        detail_count = len(cached_details) if isinstance(cached_details, dict) else 0
        self.record_app_log(
            f"Hydrated RF Alerts cache ({len(entry.items)} item(s), {detail_count} detail(s)).",
            level="DEBUG",
            source="cache",
        )

        if self._active_mode == "welcome" or force:
            self._active_mode = "alerts_v3"
        if self._active_mode == "alerts_v3":
            sel = self._get_selected_item()
            preserve = str(sel.get("id") or "") if sel is not None else None
            self._refresh_assignee_options()
            self._render_view(preserve_id=preserve, schedule_auto_enrich=False)
            detail_note = f", {detail_count} detail(s) preloaded" if detail_count else ""
            self.set_status(
                f"Loaded {len(entry.items)} cached RF alert(s) "
                f"(Last 24h{detail_note}, updated {entry.age_label()})."
            )
        return True

    def on_unmount(self) -> None:
        clear_kitty_images(self.app, self._inline_kitty_ids)

    def on_resize(self) -> None:
        if self._tables_ready:
            self._update_responsive_layout()

    def on_tab_activated(self) -> None:
        if self._tables_ready:
            self.hydrate_from_alert_cache(force=False)
            self._update_responsive_layout()

    def _update_responsive_layout(self) -> None:
        compact = self.size.width < 110 or self.size.height <= 26
        split_horizontal = self.size.width >= 130
        self.set_class(compact, "rf-compact")
        self.set_class(
            compact or (split_horizontal and self.size.width < 225),
            "rf-detail-compact",
        )
        workspace = self.query_one("#rf-workspace", Container)
        if split_horizontal:
            workspace.add_class("split-horizontal")
        else:
            workspace.remove_class("split-horizontal")
        try:
            lookup_bar = self.query_one("#rf-lookup-bar", Container)
            if self.size.width >= 135:
                lookup_bar.add_class("lookup-inline")
            else:
                lookup_bar.remove_class("lookup-inline")
        except Exception:
            pass
        with contextlib.suppress(Exception):
            ai_panel = self.query_one("#rf-ai-panel", EventAIPanelWidget)
            ai_panel.display = self.size.height > 26
            ai_panel.set_class(
                not split_horizontal and self.size.height < 40,
                "ai-panel-compact",
            )
        self.call_after_refresh(self._refresh_after_layout)

    def _refresh_after_layout(self) -> None:
        self._fit_results_table()
        if self.is_app_shutting_down() or not self._tables_ready:
            return
        try:
            log_widget = self.query_one("#rf-log", RichLog)
            width = log_widget.scrollable_content_region.width
            if width > 0 and width != self._last_detail_width:
                self._render_detail_panel()
        except Exception:
            pass

    def _fit_results_table(self) -> None:
        if self.is_app_shutting_down() or not self._tables_ready:
            return
        specs = _TABLE_SPECS.get(self._active_mode, _TABLE_SPECS["welcome"])
        col_specs = tuple((key, weight, min_w) for key, _, weight, min_w in specs)
        try:
            self.fit_table_columns(
                self.query_one("#rf-results-table", DoubleClickDataTable),
                col_specs,
            )
        except Exception:
            pass

    def _parse_limit(self, default: int = 10) -> int | None:
        raw = self.query_one("#rf-limit-input", Input).value.strip()
        if not raw:
            return default
        try:
            val = int(raw)
            if val < 1:
                raise ValueError("limit must be >= 1")
            return val
        except ValueError:
            self.set_status(f"Invalid numeric limit: '{raw}'")
            return None

    def lookup_from_watchlist(self, entity_type: str, entity_value: str) -> None:
        """Populate RF Intel inputs from a Watchlist entity and run a lookup."""
        value = entity_value.strip()
        if not value:
            self.set_status("Selected entity has no value to look up.")
            return
        mapped = _WATCHLIST_TO_V2_TYPE.get(entity_type.strip().lower())
        if mapped:
            sel = self.query_one("#rf-v2-type", Select)
            inp = self.query_one("#rf-ioc-input", Input)
            with sel.prevent(Select.Changed):
                sel.value = mapped
            with inp.prevent(Input.Changed):
                inp.value = value
            self.handle_v2_lookup()
        else:
            q_inp = self.query_one("#rf-query-input", Input)
            with q_inp.prevent(Input.Changed):
                q_inp.value = value
            self.handle_entity_match()

    @staticmethod
    def _classify_pivot_v2_ioc(norm_kind: str, clean_val: str) -> tuple[str, str] | None:
        """Return ``(v2_type, ioc_value)`` for IOC pivots, or ``None`` for entity match."""
        lower = clean_val.lower()
        for prefix, mapped in (
            ("ip:", "ip"),
            ("idn:", "domain"),
            ("hash:", "hash"),
            ("url:", "url"),
        ):
            if lower.startswith(prefix):
                stripped = clean_val[len(prefix) :].strip()
                return (mapped, stripped) if stripped else None

        if norm_kind in _PIVOT_V2_TYPE_ALIASES:
            return _PIVOT_V2_TYPE_ALIASES[norm_kind], clean_val

        is_dotted_domain = (
            "." in clean_val
            and " " not in clean_val
            and not clean_val.startswith(".")
            and not clean_val.endswith(".")
        )
        if norm_kind in ("host", "system"):
            return ("domain", clean_val) if is_dotted_domain else None

        if norm_kind in ("", "auto"):
            if lower.startswith(("http://", "https://")):
                return "url", clean_val
            if lower.startswith("cve-"):
                return "vulnerability", clean_val
            try:
                ipaddress.ip_address(clean_val)
                return "ip", clean_val
            except ValueError:
                pass
            if len(clean_val) in (32, 40, 64) and re.fullmatch(r"[0-9a-fA-F]+", clean_val):
                return "hash", clean_val
            if is_dotted_domain:
                return "domain", clean_val
            return None

        return None

    def accept_pivot(self, payload: PivotPayload) -> None:
        """Accept a ``PivotPayload`` and auto-run Connect v2 lookup or Entity Match."""
        primary = payload.primary_ioc()
        if primary is None:
            self.set_status("Pivot payload contained no IOC or entity to look up.")
            return
        raw_kind, raw_val = primary
        clean_val = raw_val.strip()
        if not clean_val or clean_val == "-":
            self.set_status("Pivot payload contained an empty IOC or entity.")
            return

        norm_kind = raw_kind.strip().lower()
        classified = self._classify_pivot_v2_ioc(norm_kind, clean_val)
        if classified is not None:
            v2_type, ioc_val = classified
            sel = self.query_one("#rf-v2-type", Select)
            inp = self.query_one("#rf-ioc-input", Input)
            with sel.prevent(Select.Changed):
                sel.value = v2_type
            with inp.prevent(Input.Changed):
                inp.value = ioc_val
            self.handle_v2_lookup()
        else:
            q_inp = self.query_one("#rf-query-input", Input)
            with q_inp.prevent(Input.Changed):
                q_inp.value = clean_val
            self.handle_entity_match()

    def report_error(self, context: str, exc: Exception) -> None:
        """Update status, notify user, and render a clear error card in the inspector."""
        if self.is_app_shutting_down():
            return
        if isinstance(exc, RecordedFutureError) and getattr(exc, "reason", None) == "cancelled":
            return
        detail = self.format_exception(exc)
        msg = f"[ERROR] {context}: {detail}"
        self.set_status(msg)
        self.record_app_log(msg, level="ERROR")
        self.notify_user(detail, title=context, severity="error")

        def _render_err() -> None:
            clear_kitty_images(self.app, self._inline_kitty_ids)
            self._last_error_payload = (context, detail)
            log_widget = self.query_one("#rf-log", RichLog)
            avail = log_widget.scrollable_content_region.width
            width = max(44, avail) if avail > 0 else None
            self._last_detail_width = avail
            log_widget.clear()
            log_widget.write(
                render_error_panel(context, detail),
                width=width,
                expand=True,
                scroll_end=False,
            )
            log_widget.scroll_home(animate=False)
            self.query_one("#rf-detail-header", Static).update(
                Text(f"Error: {context}", style="bold red")
            )

        self.run_on_ui(_render_err)

    # ------------------------------------------------------------------
    # Filtering, View Switching & Rendering
    # ------------------------------------------------------------------

    def _active_filter_summary(self) -> str:
        text_q = self.query_one("#rf-table-filter", Input).value.strip()
        rule_q = self.query_one("#rf-rule-filter", Input).value.strip()
        ent_q = self.query_one("#rf-entity-filter", Input).value.strip()
        pb_cat = str(self.query_one("#rf-pb-category", Select).value)
        parts: list[str] = []
        if self._active_preset_id not in ("all", _CUSTOM_PRESET_SENTINEL):
            preset = self._presets_by_id.get(self._active_preset_id)
            if preset is not None:
                return preset.label
        if self._selected_statuses:
            parts.append(",".join(self._selected_statuses))
        if self._priority_filter != "any":
            parts.append(f"prio:{self._priority_filter}")
        if self._timeframe_filter != "any":
            parts.append(timeframe_label(self._timeframe_filter))
        if self._assignee_filter != "any":
            parts.append(f"assignee:{self._assignee_filter}")
        if pb_cat != "all":
            parts.append(f"cat:{pb_cat}")
        if rule_q:
            parts.append(f"rule:{rule_q}")
        if ent_q:
            parts.append(f"entity:{ent_q}")
        if text_q:
            parts.append(f'"{text_q}"')
        if self._sort_by != "newest":
            parts.append(f"sort:{self._sort_by}")
        return " | ".join(parts)

    def _update_filter_title(self) -> None:
        text_q = self.query_one("#rf-table-filter", Input).value.strip()
        rule_q = self.query_one("#rf-rule-filter", Input).value.strip()
        ent_q = self.query_one("#rf-entity-filter", Input).value.strip()
        pb_cat = str(self.query_one("#rf-pb-category", Select).value)
        parts: list[str] = [_VIEW_LABELS.get(self._active_mode, self._active_mode)]
        if self._timeframe_filter != "any":
            parts.append(timeframe_label(self._timeframe_filter))
        if self._priority_filter != "any":
            parts.append(f"prio: {self._priority_filter}")
        if pb_cat != "all":
            parts.append(f"cat: {pb_cat}")
        if self._selected_statuses:
            parts.append(f"status: {','.join(self._selected_statuses)}")
        if rule_q:
            parts.append(f'rule: "{rule_q}"')
        if ent_q:
            parts.append(f'entity: "{ent_q}"')
        if text_q:
            parts.append(f'filter: "{text_q}"')
        self.query_one("#rf-filter-collapsible", Collapsible).title = (
            f"More Filters, Custom Dates & Tools [{' | '.join(parts)}] (press /)"
        )

    def _refresh_preset_options(self, *, select_id: str | None = None) -> None:
        if not self._tables_ready:
            return
        options = self._build_preset_select_options()
        valid_ids = {val for _lbl, val in options}
        target = select_id if select_id is not None else self._active_preset_id
        if target not in valid_ids:
            target = "all"
        self._active_preset_id = target
        sel = self.query_one("#rf-preset-select", Select)
        self._syncing_preset_options = True
        try:
            with sel.prevent(Select.Changed):
                sel.set_options(options)
                sel.value = target
        finally:
            self._syncing_preset_options = False
        self._sync_delete_preset_button()

    def _sync_delete_preset_button(self) -> None:
        if not self._tables_ready:
            return
        preset = self._presets_by_id.get(self._active_preset_id)
        is_custom_saved = preset is not None and not preset.builtin
        try:
            self.query_one("#rf-delete-preset-btn", Button).disabled = not is_custom_saved
        except Exception:
            pass

    def _refresh_assignee_options(self) -> None:
        if not self._tables_ready:
            return
        names: set[str] = set()
        for key in ("alerts_v3", "playbook", "cases"):
            for item in self._datasets.get(key, []):
                person = str(item.get("assignee") or "").strip()
                if person and person not in {"-", "Unassigned", "unassigned", "None"}:
                    names.add(person)
        options: list[tuple[str, str]] = list(ASSIGNEE_FILTER_BASE_OPTIONS)
        for name in sorted(names, key=str.lower):
            options.append((name, name))
        cur = self._assignee_filter or "any"
        if cur.lower() not in _BASE_ASSIGNEE_VALUES and cur not in names:
            options.append((f"{cur} (saved)", cur))
        sel = self.query_one("#rf-assignee-filter", Select)
        self._syncing_assignee_options = True
        try:
            with sel.prevent(Select.Changed):
                sel.set_options(options)
                sel.value = cur
        finally:
            self._syncing_assignee_options = False

    def _is_default_filter_state(self) -> bool:
        return (
            not self._selected_statuses
            and self._priority_filter == "any"
            and self._timeframe_filter == "any"
            and self._assignee_filter == "any"
            and self._sort_by == "newest"
            and self._time_field == "auto"
            and str(self.query_one("#rf-pb-category", Select).value) == "all"
            and not self.query_one("#rf-table-filter", Input).value.strip()
            and not self.query_one("#rf-rule-filter", Input).value.strip()
            and not self.query_one("#rf-entity-filter", Input).value.strip()
            and not self.query_one("#rf-date-from", Input).value.strip()
            and not self.query_one("#rf-date-to", Input).value.strip()
        )

    def _mark_custom_if_modified(self) -> None:
        if self._applying_preset or not self._tables_ready:
            return
        target = "all" if self._is_default_filter_state() else _CUSTOM_PRESET_SENTINEL
        if self._active_preset_id == target:
            self._sync_delete_preset_button()
            return
        self._active_preset_id = target
        sel = self.query_one("#rf-preset-select", Select)
        self._syncing_preset_options = True
        try:
            with sel.prevent(Select.Changed):
                sel.value = target
        finally:
            self._syncing_preset_options = False
        self._sync_delete_preset_button()

    def _apply_preset(self, preset: FilterPreset) -> None:
        self._applying_preset = True
        try:
            self._active_preset_id = preset.id
            self._selected_statuses = list(preset.statuses)
            self._priority_filter = preset.priority
            self._timeframe_filter = preset.timeframe
            self._assignee_filter = preset.assignee
            self._sort_by = preset.sort_by
            self._time_field = preset.time_field

            self._refresh_assignee_options()
            self._sync_status_bar_controls()

            for sel_id, val in (
                ("#rf-priority-filter", preset.priority),
                ("#rf-timeframe-filter", preset.timeframe),
                ("#rf-assignee-filter", preset.assignee),
                ("#rf-sort-select", preset.sort_by),
                ("#rf-time-field-select", preset.time_field),
                ("#rf-pb-category", preset.pb_category),
            ):
                sel = self.query_one(sel_id, Select)
                with sel.prevent(Select.Changed):
                    sel.value = val

            for inp_id, txt in (
                ("#rf-table-filter", preset.text_query),
                ("#rf-rule-filter", preset.rule_query),
                ("#rf-entity-filter", preset.entity_query),
                ("#rf-date-from", preset.date_from),
                ("#rf-date-to", preset.date_to),
            ):
                inp = self.query_one(inp_id, Input)
                with inp.prevent(Input.Changed):
                    inp.value = txt

            preset_sel = self.query_one("#rf-preset-select", Select)
            self._syncing_preset_options = True
            try:
                with preset_sel.prevent(Select.Changed):
                    preset_sel.value = preset.id
            finally:
                self._syncing_preset_options = False
            self._sync_delete_preset_button()
        finally:
            self._applying_preset = False

        self._update_filter_title()
        if self._active_mode != "welcome":
            self._render_view()
            self.set_status(
                f"Applied preset '{preset.label}' ({len(self._visible_items)} matching row(s); press [r] to fetch from API)."
            )
        else:
            self.set_status(
                f"Selected preset '{preset.label}'. Load Alerts v3, Playbook Alerts, or Cases to apply."
            )

    def _build_current_preset(self, label: str) -> FilterPreset:
        return FilterPreset(
            id=sanitize_preset_id(label),
            label=label.strip(),
            statuses=tuple(self._selected_statuses),
            priority=self._priority_filter,
            timeframe=self._timeframe_filter,
            assignee=self._assignee_filter,
            sort_by=self._sort_by,
            time_field=self._time_field,
            pb_category=str(self.query_one("#rf-pb-category", Select).value or "all"),
            rule_query=self.query_one("#rf-rule-filter", Input).value.strip(),
            entity_query=self.query_one("#rf-entity-filter", Input).value.strip(),
            text_query=self.query_one("#rf-table-filter", Input).value.strip(),
            date_from=self.query_one("#rf-date-from", Input).value.strip(),
            date_to=self.query_one("#rf-date-to", Input).value.strip(),
            builtin=False,
        )

    def _sync_status_bar_controls(self) -> None:
        if not self._tables_ready:
            return
        active_norm = {normalize_status_key(st) for st in self._selected_statuses}
        try:
            self.query_one("#rf-st-all", Button).variant = (
                "primary" if not active_norm else "default"
            )
            for btn_id, st_val in _STATUS_BUTTON_TO_VALUE.items():
                is_active = normalize_status_key(st_val) in active_norm
                self.query_one(f"#{btn_id}", Button).variant = (
                    "primary" if is_active else "default"
                )
            enrich_btn = self.query_one("#rf-auto-enrich-btn", Button)
            enrich_btn.label = (
                "Auto-Enrich: ON" if self._auto_enrich_enabled else "Auto-Enrich: OFF"
            )
            enrich_btn.variant = "primary" if self._auto_enrich_enabled else "default"
        except Exception:
            pass

    def _sync_view_selector(self) -> None:
        sel = self.query_one("#rf-view-select", Select)
        if str(sel.value) == self._active_mode:
            return
        self._syncing_view_select = True
        try:
            with sel.prevent(Select.Changed):
                sel.value = self._active_mode
        finally:
            self._syncing_view_select = False

    def _filter_items(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        text_q = self.query_one("#rf-table-filter", Input).value.strip().lower()
        rule_q = self.query_one("#rf-rule-filter", Input).value.strip().lower()
        ent_q = self.query_one("#rf-entity-filter", Input).value.strip().lower()
        pb_cat = str(self.query_one("#rf-pb-category", Select).value).lower()
        date_from = self.query_one("#rf-date-from", Input).value.strip()
        date_to = self.query_one("#rf-date-to", Input).value.strip()

        filtered: list[dict[str, Any]] = []
        for item in items:
            if (
                self._active_mode in ("alerts_v3", "playbook", "cases", "sandbox")
                and self._selected_statuses
            ):
                if not status_matches_filter(item.get("status"), self._selected_statuses):
                    continue

            if (
                self._active_mode in ("alerts_v3", "playbook", "cases")
                and self._priority_filter != "any"
            ):
                if not priority_matches_filter(item.get("priority"), self._priority_filter):
                    continue

            if (
                self._active_mode in ("alerts_v3", "playbook", "cases")
                and self._assignee_filter != "any"
            ):
                if not assignee_matches_filter(item.get("assignee"), self._assignee_filter):
                    continue

            if (
                self._active_mode in ("alerts_v3", "playbook", "cases", "sandbox")
                and self._timeframe_filter != "any"
            ):
                ts_val = extract_item_timestamp(item, self._active_mode, self._time_field)
                if not timestamp_matches_timeframe(
                    ts_val,
                    self._timeframe_filter,
                    date_from=date_from,
                    date_to=date_to,
                ):
                    continue

            if self._active_mode == "playbook" and pb_cat != "all":
                cat_val = str(item.get("category") or "").lower()
                if pb_cat == "brand_bundle":
                    if cat_val not in {"domain_abuse", "malicious_sites"}:
                        continue
                elif cat_val != pb_cat:
                    continue

            if rule_q:
                rule_blob = " ".join(
                    str(item.get(k) or "") for k in ("rule_name", "rule_id", "category", "top_rule")
                ).lower()
                if rule_q not in rule_blob:
                    continue

            if ent_q:
                targets_val = item.get("targets") or []
                attackers_val = item.get("attackers") or []
                ent_parts = [
                    str(item.get(k) or "")
                    for k in ("primary_entity", "entity_name", "name", "target", "id")
                ]
                ent_parts.extend(str(t) for t in targets_val)
                ent_parts.extend(str(a) for a in attackers_val)
                if ent_q not in " ".join(ent_parts).lower():
                    continue

            if text_q:
                haystack = " ".join(
                    str(item.get(k) or "")
                    for k in (
                        "id",
                        "title",
                        "name",
                        "rule_name",
                        "category",
                        "status",
                        "priority",
                        "assignee",
                        "primary_entity",
                        "entity_name",
                        "rf_type",
                        "type",
                        "criticality_label",
                        "top_rule",
                        "target",
                        "sha256",
                        "verdict",
                        "context",
                        "note",
                        "description",
                    )
                ).lower()
                if text_q not in haystack:
                    continue

            filtered.append(item)
        return sort_rf_items(filtered, self._active_mode, self._sort_by)

    def _build_table_row(self, mode: str, item: dict[str, Any]) -> tuple[Any, ...]:
        if mode == "welcome":
            return (
                Text(item["workflow"], style="bold cyan"),
                Text(item["trigger"], style="white"),
                Text(item["summary"], style="dim"),
            )
        if mode == "alerts_v3":
            return (
                priority_text(item.get("priority")),
                status_text(item.get("status")),
                Text(truncate_text(item.get("rule_name") or "-", 28)),
                Text(truncate_text(item.get("title") or "-", 44)),
                Text(truncate_text(item.get("assignee") or "-", 16)),
                Text(str(item.get("hits_count", 0)), justify="right"),
                Text(format_timestamp(item.get("triggered"))),
            )
        if mode == "playbook":
            return (
                priority_text(item.get("priority")),
                status_text(item.get("status")),
                Text(str(item.get("category") or "-"), style="cyan"),
                Text(truncate_text(item.get("title") or "-", 42)),
                Text(truncate_text(item.get("assignee") or "-", 16)),
                Text(format_timestamp(item.get("updated"))),
            )
        if mode == "cases":
            return (
                priority_text(item.get("priority")),
                status_text(item.get("status")),
                Text(truncate_text(item.get("title") or "-", 48)),
                Text(truncate_text(item.get("assignee") or "-", 18)),
                Text(format_timestamp(item.get("updated"))),
            )
        if mode == "intel_v2":
            rules_cnt = item.get("rules_count", 0)
            ev = item.get("evidence_details") or []
            top = str(ev[0].get("rule") or "") if ev else ""
            rule_summary = f"{rules_cnt} rule(s)" + (f": {truncate_text(top, 24)}" if top else "")
            return (
                score_text(item.get("risk_score"), max_score=99),
                Text(str(item.get("rf_type") or item.get("entity_type") or "-"), style="cyan"),
                Text(truncate_text(item.get("name") or item.get("id") or "-", 36)),
                Text(str(item.get("criticality_label") or "-")),
                Text(rule_summary),
            )
        if mode == "soar":
            verdict = str(item.get("verdict") or "-")
            v_style = (
                "bold red"
                if verdict.upper() == "MALICIOUS"
                else ("green" if verdict.upper() == "BENIGN" else "dim")
            )
            ctx_or_rule = item.get("top_rule") or item.get("context") or "-"
            return (
                score_text(item.get("score"), max_score=99),
                Text(verdict, style=v_style),
                Text(str(item.get("type") or "-"), style="cyan"),
                Text(truncate_text(item.get("name") or item.get("id") or "-", 36)),
                Text(truncate_text(ctx_or_rule, 32)),
            )
        if mode == "entity_match":
            return (
                Text(str(item.get("id") or "-"), style="cyan"),
                Text(str(item.get("type") or "-")),
                Text(truncate_text(item.get("name") or "-", 48)),
            )
        if mode == "sandbox":
            sha = str(item.get("sha256") or "")
            short_sha = sha[:16] + "..." if len(sha) > 16 else (sha or "-")
            return (
                score_text(item.get("score"), max_score=10),
                status_text(item.get("status")),
                Text(truncate_text(item.get("target") or "-", 36)),
                Text(short_sha, style="dim"),
                Text(format_timestamp(item.get("submitted"))),
            )
        return (Text(str(item)),)

    def _render_view(
        self, *, preserve_id: str | None = None, schedule_auto_enrich: bool = True
    ) -> None:
        self._last_error_payload = None
        self._sync_view_selector()
        self._update_filter_title()

        mode = self._active_mode
        table = self.query_one("#rf-results-table", DoubleClickDataTable)
        specs = _TABLE_SPECS.get(mode, _TABLE_SPECS["welcome"])

        if mode == "welcome":
            raw_items = [dict(row) for row in _WELCOME_ROWS]
            filtered_items = raw_items
        else:
            raw_items = self._datasets.get(mode, [])
            filtered_items = self._filter_items(raw_items)

        self._visible_items = filtered_items

        self._rendering_table = True
        try:
            table.clear(columns=True)
            for key, label, _, _ in specs:
                table.add_column(label, key=key)
            for idx, item in enumerate(filtered_items):
                table.add_row(*self._build_table_row(mode, item), key=f"row-{idx}")

            target_idx: int | None = None
            if filtered_items:
                if preserve_id:
                    for idx, item in enumerate(filtered_items):
                        if str(item.get("id") or "") == preserve_id:
                            target_idx = idx
                            break
                if target_idx is None:
                    target_idx = 0
                table.cursor_coordinate = Coordinate(target_idx, 0)
            self._selected_index = target_idx
        finally:
            self._rendering_table = False

        # Update headers & KPI summary bar
        label = _VIEW_LABELS.get(mode, mode)
        header = self.query_one("#rf-results-header", Static)
        if mode == "welcome":
            header.update("Quick Start Workflows (double-click or Enter to jump)")
        elif len(filtered_items) != len(raw_items):
            header.update(f"{label} ({len(filtered_items)} of {len(raw_items)})")
        else:
            header.update(f"{label} ({len(filtered_items)})")

        summary_bar = self.query_one("#rf-summary-bar", Static)
        summary_bar.update(
            build_summary_bar_text(
                mode,
                len(raw_items),
                len(filtered_items),
                self._dataset_totals.get(mode),
                raw_items,
                active_filter_summary=self._active_filter_summary(),
            )
        )

        self._update_toolbar_state()
        self._render_detail_panel()
        self.call_after_refresh(self._fit_results_table)
        if schedule_auto_enrich:
            self.call_after_refresh(self._schedule_visible_enrichment)

    def _update_toolbar_state(self) -> None:
        overview_btn = self.query_one("#rf-view-overview-btn", Button)
        json_btn = self.query_one("#rf-view-json-btn", Button)
        detail_btn = self.query_one("#rf-fetch-detail-btn", Button)
        images_btn = self.query_one("#rf-images-btn", Button)
        triage_btn = self.query_one("#rf-triage-status-btn", Button)

        if self._detail_mode == "json":
            overview_btn.variant = "default"
            json_btn.variant = "primary"
        else:
            overview_btn.variant = "primary"
            json_btn.variant = "default"

        has_sel = (
            self._selected_index is not None
            and 0 <= self._selected_index < len(self._visible_items)
        )
        detail_btn.disabled = self._active_mode == "welcome" or not has_sel
        triage_btn.disabled = (
            self._active_mode not in ("alerts_v3", "playbook", "cases") or not has_sel
        )

        os_default = self._is_os_viewer_default()
        try:
            os_default_btn = self.query_one("#rf-os-viewer-default-btn", Button)
            os_default_btn.label = (
                "OS Viewer Default: ON" if os_default else "OS Viewer Default: OFF"
            )
            os_default_btn.variant = "success" if os_default else "default"
        except Exception:
            pass

        blur_enabled = self._is_image_blur_enabled()
        try:
            blur_btn = self.query_one("#rf-blur-images-btn", Button)
            blur_btn.label = "Blur: ON" if blur_enabled else "Blur: OFF"
            blur_btn.variant = "warning" if blur_enabled else "default"
        except Exception:
            pass

        item = self._get_selected_item() if has_sel else None
        sc_ids: list[Any] = []
        if item and self._active_mode == "playbook":
            sc_ids = list(item.get("screenshot_ids") or [])
            if not sc_ids:
                item_id = str(item.get("id") or "")
                cached_pb = self._detail_cache.get(("playbook", item_id))
                if isinstance(cached_pb, dict):
                    sc_ids = list(normalize_playbook_alert(cached_pb).get("screenshot_ids") or [])
        if sc_ids:
            images_btn.disabled = False
            images_btn.label = (
                f"Images ({len(sc_ids)}) (OS)" if os_default else f"Images ({len(sc_ids)})"
            )
        else:
            images_btn.disabled = True
            images_btn.label = "Images (OS)" if os_default else "Images"

    def _is_os_viewer_default(self) -> bool:
        return bool(getattr(self.app, "open_images_in_os_viewer", False))

    def _is_image_blur_enabled(self) -> bool:
        return bool(getattr(self.app, "blur_images", True))

    def on_image_viewer_mode_changed(self) -> None:
        """Refresh toolbar labels and detail hints when default image viewer changes."""
        if not self._tables_ready:
            return
        self._update_toolbar_state()
        if self._active_mode == "playbook":
            self._render_detail_panel()

    def on_image_blur_changed(self) -> None:
        """Refresh toolbar blur toggle and re-render inline Playbook screenshots."""
        if not self._tables_ready:
            return
        self._update_toolbar_state()
        if self._active_mode == "playbook":
            self._render_detail_panel()

    def _get_selected_item(self) -> dict[str, Any] | None:
        if self._selected_index is None:
            return None
        if 0 <= self._selected_index < len(self._visible_items):
            return self._visible_items[self._selected_index]
        return None

    def _active_unique_event(self, item: dict[str, Any] | None = None) -> UniqueEvent | None:
        mode = self._active_mode
        if mode not in ("alerts_v3", "playbook"):
            return None
        target = item if item is not None else self._get_selected_item()
        if not isinstance(target, dict):
            return None
        source_kind: EventSourceKind = "rf_alert" if mode == "alerts_v3" else "rf_playbook"
        item_id = str(target.get("id") or "").strip()
        cached_full = self._detail_cache.get((mode, item_id)) if item_id else None
        payload: dict[str, Any] = (
            {**cached_full, **target} if isinstance(cached_full, dict) else dict(target)
        )
        try:
            return normalize_unique_event(source_kind, payload)
        except (TypeError, ValueError):
            return None

    def refresh_event_ai_panel_if_matching(self, event: UniqueEvent) -> None:
        """Refresh the RF AI panel when the currently selected event matches ``event``."""
        cur = self._active_unique_event()
        if cur is not None and cur.event_key == event.event_key:
            self.sync_event_ai_panel("#rf-ai-panel", cur)

    @on(EventAIPanelWidget.AskRequested, "#rf-ai-panel")
    def handle_ai_ask_requested(self, message: EventAIPanelWidget.AskRequested) -> None:
        _ = message
        self.request_ask_event_ai("#rf-ai-panel", self._active_unique_event())

    @on(EventAIPanelWidget.FullInvestigateRequested, "#rf-ai-panel")
    def handle_ai_full_requested(
        self, message: EventAIPanelWidget.FullInvestigateRequested
    ) -> None:
        _ = message
        self.request_full_event_ai("#rf-ai-panel", self._active_unique_event())

    def _write_detail_renderable(self, renderable: Any) -> None:
        log_widget = self.query_one("#rf-log", RichLog)
        avail = log_widget.scrollable_content_region.width
        width = max(44, avail) if avail > 0 else None
        self._last_detail_width = avail
        log_widget.clear()
        log_widget.write(renderable, width=width, expand=True, scroll_end=False)
        log_widget.scroll_home(animate=False)

    def _schedule_cached_image_prep(
        self, category: str, alert_id: str, screenshot_ids: list[str]
    ) -> None:
        to_prep: list[str] = []
        for sid in screenshot_ids:
            key = (category, alert_id, sid)
            if key not in self._preparing_image_keys:
                self._preparing_image_keys.add(key)
                to_prep.append(sid)
        if to_prep:
            self._prepare_cached_images_worker(category, alert_id, to_prep)

    @work(thread=True, exit_on_error=False)
    def _prepare_cached_images_worker(
        self, category: str, alert_id: str, screenshot_ids: list[str]
    ) -> None:
        cache = getattr(self.app, "alert_cache", None)
        is_unavail_fn = getattr(cache, "is_image_unavailable", None)
        mark_unavail_fn = getattr(cache, "mark_image_unavailable", None)
        get_img_fn = getattr(self.client, "get_playbook_alert_image", None)
        results: dict[str, dict[str, Any] | None] = {}
        downloaded_count = 0
        prepared_count = 0
        try:
            for sid in screenshot_ids:
                if self.is_app_shutting_down():
                    return
                img_key = f"{category}__{alert_id}__{sid}"
                if callable(is_unavail_fn) and is_unavail_fn(img_key):
                    results[sid] = {"error": "Screenshot unavailable (HTTP 404 from Recorded Future)"}
                    continue
                prepared = (
                    cache.get_prepared_image(img_key)
                    if cache is not None and hasattr(cache, "get_prepared_image")
                    else None
                )
                if prepared is None:
                    raw_bytes = cache.get_image_bytes(img_key) if cache is not None else None
                    if raw_bytes is None and self._auto_enrich_enabled and callable(get_img_fn):
                        try:
                            fetched = get_img_fn(category, alert_id, sid)
                            if isinstance(fetched, (bytes, bytearray)) and len(fetched) > 8:
                                raw_bytes = bytes(fetched)
                                downloaded_count += 1
                                if cache is not None:
                                    cache.put_image_bytes(img_key, raw_bytes)
                            else:
                                prepared = {
                                    "error": "Empty or unsupported screenshot response"
                                }
                        except RecordedFutureError as img_exc:
                            if img_exc.status_code == 404:
                                if callable(mark_unavail_fn):
                                    mark_unavail_fn(img_key)
                                prepared = {
                                    "error": "Screenshot unavailable (HTTP 404 from Recorded Future)"
                                }
                            else:
                                prepared = {"error": self.format_exception(img_exc)}
                        except Exception as img_exc:
                            prepared = {"error": self.format_exception(img_exc)}
                    if prepared is None and raw_bytes:
                        try:
                            prepared = prepare_image_cache_entry(raw_bytes)
                            prepared_count += 1
                            if cache is not None and hasattr(cache, "put_prepared_image"):
                                cache.put_prepared_image(img_key, prepared)
                        except Exception as exc:
                            prepared = {"error": self.format_exception(exc)}
                results[sid] = prepared
        finally:
            if downloaded_count or prepared_count:
                self.record_app_log(
                    f"Playbook screenshot worker ({alert_id}): downloaded={downloaded_count}, prepared={prepared_count}.",
                    level="DEBUG",
                    source="cache",
                )

            def _apply() -> None:
                for sid in screenshot_ids:
                    self._preparing_image_keys.discard((category, alert_id, sid))
                if self.is_app_shutting_down():
                    return
                updated = False
                for sid, prepared in results.items():
                    img_tuple = (category, alert_id, sid)
                    if prepared is not None:
                        self._image_cache[img_tuple] = prepared
                        updated = True
                    elif self._image_cache.get(img_tuple, {}).get("loading"):
                        self._image_cache.pop(img_tuple, None)
                        updated = True
                if updated and self._active_mode == "playbook":
                    sel = self._get_selected_item()
                    if sel is not None and str(sel.get("id") or "") == alert_id:
                        self._render_detail_panel()

            self.run_on_ui(_apply)

    def _prepare_inline_screenshots(
        self, category: str, alert_id: str, sc_ids: list[Any], avail_width: int
    ) -> dict[str, dict[str, Any]]:
        sc_map: dict[str, dict[str, Any]] = {}
        blurred = self._is_image_blur_enabled()
        use_kitty = (
            detect_terminal_graphics_protocol(
                is_headless=self.app.is_headless,
                app=self.app,
            )
            == "kitty"
            and can_emit_kitty_truecolor(self.app)
        )
        tmux = is_tmux_session() if use_kitty else False
        cell_aspect = get_terminal_cell_aspect() if use_kitty else 0.5
        max_cols = max(4, min(255, avail_width - 6))

        cache = getattr(self.app, "alert_cache", None)
        get_prepared = getattr(cache, "get_prepared_image", None)
        is_unavail_fn = getattr(cache, "is_image_unavailable", None)
        loading_fn = getattr(self.app, "is_cache_source_loading", None)
        pb_loading = callable(loading_fn) and bool(loading_fn(CACHE_SOURCE_RF_PLAYBOOK))
        pb_has_key_set: set[str] = set()
        if cache is not None:
            pb_entry = cache.get(CACHE_SOURCE_RF_PLAYBOOK)
            if pb_entry is not None and isinstance(pb_entry.meta.get("image_keys"), dict):
                for rec in pb_entry.meta["image_keys"].get(alert_id) or []:
                    if isinstance(rec, (list, tuple)) and len(rec) == 3:
                        pb_has_key_set.add(str(rec[1]))

        missing_for_bg: list[str] = []
        for sc_id in sc_ids[:4]:
            sid = str(sc_id)
            img_key = f"{category}__{alert_id}__{sid}"
            img_tuple = (category, alert_id, sid)
            entry = self._image_cache.get(img_tuple)
            if entry is None and callable(get_prepared):
                prepared = get_prepared(img_key)
                if isinstance(prepared, dict):
                    self._image_cache[img_tuple] = prepared
                    entry = prepared
            if entry is None:
                if callable(is_unavail_fn) and is_unavail_fn(img_key):
                    sc_map[sid] = {"error": "Screenshot unavailable (HTTP 404 from Recorded Future)"}
                elif sid in pb_has_key_set:
                    sc_map[sid] = {"loading": True}
                    missing_for_bg.append(sid)
                elif pb_loading:
                    sc_map[sid] = {"loading": True}
                elif self._auto_enrich_enabled:
                    sc_map[sid] = {"loading": True}
                    missing_for_bg.append(sid)
                continue

            view_entry = dict(entry)
            view_entry["blurred"] = blurred
            view_entry["pre_blurred"] = False
            decoded = entry.get("decoded")
            if decoded is not None:
                if blurred and entry.get("blurred_decoded") is not None:
                    view_entry["decoded"] = entry["blurred_decoded"]
                    view_entry["pre_blurred"] = True
                elif not blurred and entry.get("cropped_decoded") is not None:
                    view_entry["decoded"] = entry["cropped_decoded"]

            if decoded is not None and use_kitty:
                base_img = entry.get("cropped_decoded") or decoded
                if blurred:
                    png_bytes = entry.get("blurred_png")
                    if png_bytes is None:
                        disp_img = entry.get("blurred_decoded") or blur_decoded_image(base_img)
                        entry["blurred_decoded"] = disp_img
                        png_bytes = encode_png(disp_img)
                        entry["blurred_png"] = png_bytes
                else:
                    png_bytes = entry.get("cropped_png")
                    if png_bytes is None:
                        raw_b = entry.get("bytes")
                        crop_box = entry.get("crop_box")
                        if (
                            crop_box is None
                            and isinstance(raw_b, (bytes, bytearray))
                            and bytes(raw_b).startswith(b"\x89PNG\r\n\x1a\n")
                        ):
                            png_bytes = bytes(raw_b)
                        else:
                            png_bytes = encode_png(base_img)
                        entry["cropped_png"] = png_bytes
                cols, rows = compute_terminal_cell_grid(
                    base_img.width,
                    base_img.height,
                    max_cols=max_cols,
                    max_rows=18,
                    cell_aspect=cell_aspect,
                )
                kid = next_kitty_image_id()
                try:
                    seq = build_kitty_upload_sequence(
                        png_bytes,
                        image_id=kid,
                        cols=cols,
                        rows=rows,
                        tmux_passthrough=tmux,
                    )
                except ValueError:
                    seq = ""
                if seq and write_terminal_graphics(self.app, seq):
                    self._inline_kitty_ids.append(kid)
                    view_entry["kitty_placeholder"] = (kid, cols, rows)
            sc_map[sid] = view_entry

        if missing_for_bg:
            self._schedule_cached_image_prep(category, alert_id, missing_for_bg)
        return sc_map

    def _render_detail_panel(self) -> None:
        clear_kitty_images(self.app, self._inline_kitty_ids)
        detail_header = self.query_one("#rf-detail-header", Static)
        if self._last_error_payload is not None:
            self.sync_event_ai_panel("#rf-ai-panel", None)
            ctx, det = self._last_error_payload
            detail_header.update(Text(f"Error: {ctx}", style="bold red"))
            self._write_detail_renderable(render_error_panel(ctx, det))
            return

        if self._active_mode == "welcome":
            self.sync_event_ai_panel("#rf-ai-panel", None)
            detail_header.update("Inspector (Quick Start)")
            self._write_detail_renderable(render_welcome_view())
            return

        item = self._get_selected_item()
        if item is None:
            self.sync_event_ai_panel("#rf-ai-panel", None)
            raw_items = self._datasets.get(self._active_mode, [])
            msg = (
                "No records returned for this query."
                if not raw_items
                else "No rows match the active filter. Press [/] -> Clear to reset."
            )
            detail_header.update("Inspector (Empty)")
            self._write_detail_renderable(Panel(Text(msg, style="dim"), border_style="dim"))
            return

        self.sync_event_ai_panel("#rf-ai-panel", self._active_unique_event(item))

        item_id = str(item.get("id") or "")
        cached_full = self._detail_cache.get((self._active_mode, item_id))
        title_text = truncate_text(
            item.get("title") or item.get("name") or item.get("target") or item_id or "Item",
            44,
        )
        mode_tag = "Raw JSON" if self._detail_mode == "json" else "Overview"
        if cached_full is not None and self._detail_mode == "overview":
            mode_tag = "Deep Detail"
        detail_header.update(f"Inspector ({mode_tag}): {title_text}")

        if self._detail_mode == "json":
            raw_payload = cached_full if cached_full is not None else item.get("raw", item)
            self._write_detail_renderable(
                render_raw_json(raw_payload, title=f"Raw JSON - {title_text}")
            )
            return

        rendered: Group | Panel
        if self._active_mode == "alerts_v3":
            rendered = render_alert_v3_detail(item, full_detail=cached_full)
        elif self._active_mode == "playbook":
            cat = str(item.get("category") or "domain_abuse")
            avail_w = self.query_one("#rf-log", RichLog).scrollable_content_region.width
            effective_w = max(48, avail_w or 84)
            sc_ids = list(item.get("screenshot_ids") or [])
            if not sc_ids and isinstance(cached_full, dict):
                sc_ids = list(normalize_playbook_alert(cached_full).get("screenshot_ids") or [])
            sc_map = self._prepare_inline_screenshots(
                cat,
                item_id,
                sc_ids,
                effective_w,
            )
            rendered = render_playbook_alert_detail(
                item,
                full_detail=cached_full,
                screenshots_cache=sc_map,
                render_width=effective_w,
                os_viewer_default=self._is_os_viewer_default(),
                blur_images=self._is_image_blur_enabled(),
            )
        elif self._active_mode == "cases":
            rendered = render_case_detail(item, full_detail=cached_full)
        elif self._active_mode == "intel_v2":
            rendered = render_v2_intel_card(item)
        elif self._active_mode == "soar":
            rendered = render_soar_detail(item)
        elif self._active_mode == "entity_match":
            rendered = render_entity_match_detail(item, full_detail=cached_full)
        elif self._active_mode == "sandbox":
            rendered = render_sandbox_detail(item, full_detail=cached_full)
        else:
            rendered = render_raw_json(item)

        self._write_detail_renderable(rendered)

    # ------------------------------------------------------------------
    # Actions & Event Handlers
    # ------------------------------------------------------------------

    def action_toggle_filter(self) -> None:
        """Toggle the Search & Filter drawer and focus the filter input when expanded."""
        collapsible = self.query_one("#rf-filter-collapsible", Collapsible)
        collapsible.collapsed = not collapsible.collapsed
        if not collapsible.collapsed:
            self.call_after_refresh(lambda: self.query_one("#rf-table-filter", Input).focus())

    def action_collapse_filter(self) -> None:
        """Collapse the Search & Filter drawer if open."""
        collapsible = self.query_one("#rf-filter-collapsible", Collapsible)
        if not collapsible.collapsed:
            collapsible.collapsed = True
            self.call_after_refresh(
                lambda: self.query_one("#rf-results-table", DoubleClickDataTable).focus()
            )

    def action_toggle_json_view(self) -> None:
        """Toggle the inspector panel between structured Overview and Raw JSON."""
        self._last_error_payload = None
        self._detail_mode = "json" if self._detail_mode == "overview" else "overview"
        self._update_toolbar_state()
        self._render_detail_panel()

    def action_triage_selected(self) -> None:
        """Open the Triage modal for the currently selected alert or case."""
        self.handle_open_triage()

    def action_view_screenshots(self) -> None:
        """Open screenshots in the configured default viewer (TUI modal or OS viewer)."""
        self.handle_view_screenshots()

    def action_open_screenshot_os(self) -> None:
        """Open the selected Playbook Alert screenshot directly in the native OS viewer."""
        if self._active_mode != "playbook":
            self.set_status("Select a Playbook Alert to open screenshots.")
            return
        item = self._get_selected_item()
        if item is None:
            self.set_status("Select a Playbook Alert row first.")
            return
        self._open_playbook_screenshot(item)

    def action_toggle_image_blur(self) -> None:
        """Toggle privacy blur on screenshots."""
        self.handle_toggle_image_blur()

    def action_reload_active_view(self) -> None:
        """Reload the currently active view dataset."""
        if self._active_mode == "alerts_v3":
            self.handle_alerts()
        elif self._active_mode == "playbook":
            self.handle_playbook_alerts()
        elif self._active_mode == "cases":
            self.handle_cases()
        elif self._active_mode == "intel_v2":
            self.handle_v2_lookup()
        elif self._active_mode == "soar":
            self.handle_soar_enrich()
        elif self._active_mode == "entity_match":
            self.handle_entity_match()
        elif self._active_mode == "sandbox":
            self.handle_sandbox()

    def action_open_context_menu(self) -> None:
        """Open the contextual menu via keyboard shortcut."""
        table = self.query_one("#rf-results-table", DoubleClickDataTable)
        item = self._get_selected_item()
        origin = (table.region.x + 4, table.region.y + 2)
        if item is not None and self._active_mode != "welcome":
            self._open_item_context_menu(item, origin=origin)
        else:
            self._open_pane_context_menu(origin=origin)

    @on(Button.Pressed, "#rf-view-overview-btn")
    def handle_view_overview(self) -> None:
        self._last_error_payload = None
        self._detail_mode = "overview"
        self._update_toolbar_state()
        self._render_detail_panel()

    @on(Button.Pressed, "#rf-view-json-btn")
    def handle_view_json(self) -> None:
        self._last_error_payload = None
        self._detail_mode = "json"
        self._update_toolbar_state()
        self._render_detail_panel()

    @on(Button.Pressed, "#rf-fetch-detail-btn")
    def handle_fetch_detail_btn(self) -> None:
        item = self._get_selected_item()
        if item is not None and self._active_mode != "welcome":
            self._trigger_deep_detail(item)

    def _open_screenshot_modal(
        self,
        item: dict[str, Any],
        *,
        initial_image_id: str | None = None,
    ) -> None:
        sc_ids = [str(s) for s in (item.get("screenshot_ids") or []) if s]
        if not sc_ids:
            self.set_status("No screenshots attached to this Playbook Alert.")
            return
        aid = str(item.get("id") or "")
        cat = str(item.get("category") or "domain_abuse")
        meta_by_id = {
            str(m.get("image_id") or ""): m
            for m in (item.get("screenshots_meta") or [])
            if isinstance(m, dict)
        }
        shots: list[dict[str, Any]] = []
        for img_id in sc_ids:
            cached = self._image_cache.get((cat, aid, img_id), {})
            shots.append(
                {
                    "image_id": img_id,
                    "meta": meta_by_id.get(img_id, {}),
                    "decoded": cached.get("decoded"),
                    "raw_bytes": cached.get("bytes"),
                    "loading": bool(cached.get("loading")),
                    "error": cached.get("error"),
                }
            )
        initial_index = sc_ids.index(initial_image_id) if initial_image_id in sc_ids else 0
        modal = ScreenshotViewerModal(
            title=str(item.get("title") or aid),
            screenshots=shots,
            initial_index=initial_index,
            dry_run=self.effective_dry_run,
        )

        def _on_close(result: str | None) -> None:
            if isinstance(result, str) and result.startswith("save:"):
                chosen_id = result[5:]
                self._save_playbook_screenshot_by_id(item, chosen_id)

        self.app.push_screen(modal, _on_close)

    @on(Button.Pressed, "#rf-os-viewer-default-btn")
    def handle_toggle_os_viewer_default(self) -> None:
        toggle_fn = getattr(self.app, "toggle_image_viewer_mode", None)
        if callable(toggle_fn):
            mode = str(toggle_fn())
        else:
            mode = "tui"
        self.set_status(
            "Default image viewer set to OS Image Viewer."
            if mode == "os"
            else "Default image viewer set to TUI Modal Viewer."
        )

    @on(Button.Pressed, "#rf-blur-images-btn")
    def handle_toggle_image_blur(self) -> None:
        toggle_fn = getattr(self.app, "toggle_blur_images", None)
        if callable(toggle_fn):
            blurred = bool(toggle_fn())
        else:
            blurred = True
        self.set_status(
            "Screenshot blur ON (safe mode; press [b] or Unblur to reveal)."
            if blurred
            else "Screenshot blur OFF (displaying unblurred screenshots)."
        )

    @on(Button.Pressed, "#rf-images-btn")
    def handle_view_screenshots(self) -> None:
        if self._active_mode != "playbook":
            self.set_status("Select a Playbook Alert to view screenshots.")
            return
        item = self._get_selected_item()
        if item is None:
            self.set_status("Select a Playbook Alert row first.")
            return
        sc_ids = [str(s) for s in (item.get("screenshot_ids") or []) if s]
        if not sc_ids:
            self.set_status("No screenshots attached to this Playbook Alert.")
            return
        if self._is_os_viewer_default():
            self._open_playbook_screenshot(item)
            return
        self._open_screenshot_modal(item)

    @on(Button.Pressed, "#rf-triage-status-btn")
    def handle_open_triage(self) -> None:
        if self._active_mode not in ("alerts_v3", "playbook", "cases"):
            self.set_status("Select an Alert v3, Playbook Alert, or Case to triage.")
            return
        item = self._get_selected_item()
        if item is None:
            self.set_status("Select a row first before triaging.")
            return
        self._open_triage_modal(self._active_mode, item)

    @on(Input.Changed, "#rf-table-filter")
    @on(Input.Changed, "#rf-rule-filter")
    @on(Input.Changed, "#rf-entity-filter")
    @on(Input.Changed, "#rf-date-from")
    @on(Input.Changed, "#rf-date-to")
    def handle_table_filter_changed(self) -> None:
        self._mark_custom_if_modified()
        self._update_filter_title()
        if self._active_mode != "welcome":
            self._render_view()

    @on(Select.Changed, "#rf-preset-select")
    def handle_preset_selected(self, event: Select.Changed) -> None:
        if self._syncing_preset_options or self._applying_preset:
            return
        preset_id = str(event.value or "all")
        if preset_id == _CUSTOM_PRESET_SENTINEL:
            return
        preset = self._presets_by_id.get(preset_id)
        if preset is not None:
            self._apply_preset(preset)

    @on(Select.Changed, "#rf-priority-filter")
    def handle_priority_filter_changed(self, event: Select.Changed) -> None:
        if self._applying_preset:
            return
        self._priority_filter = str(event.value or "any")
        self._mark_custom_if_modified()
        self._update_filter_title()
        if self._active_mode != "welcome":
            self._render_view()

    @on(Select.Changed, "#rf-timeframe-filter")
    def handle_timeframe_filter_changed(self, event: Select.Changed) -> None:
        if self._applying_preset:
            return
        self._timeframe_filter = str(event.value or "any")
        self._mark_custom_if_modified()
        self._update_filter_title()
        if self._timeframe_filter == "custom":
            collapsible = self.query_one("#rf-filter-collapsible", Collapsible)
            if collapsible.collapsed:
                collapsible.collapsed = False
            self.call_after_refresh(lambda: self.query_one("#rf-date-from", Input).focus())
        if self._active_mode != "welcome":
            self._render_view()

    @on(Select.Changed, "#rf-assignee-filter")
    def handle_assignee_filter_changed(self, event: Select.Changed) -> None:
        if self._syncing_assignee_options or self._applying_preset:
            return
        self._assignee_filter = str(event.value or "any")
        self._mark_custom_if_modified()
        self._update_filter_title()
        if self._active_mode != "welcome":
            self._render_view()

    @on(Select.Changed, "#rf-sort-select")
    def handle_sort_select_changed(self, event: Select.Changed) -> None:
        if self._applying_preset:
            return
        self._sort_by = str(event.value or "newest")
        self._mark_custom_if_modified()
        self._update_filter_title()
        if self._active_mode != "welcome":
            self._render_view()

    @on(Select.Changed, "#rf-time-field-select")
    def handle_time_field_changed(self, event: Select.Changed) -> None:
        if self._applying_preset:
            return
        self._time_field = str(event.value or "auto")
        self._mark_custom_if_modified()
        self._update_filter_title()
        if self._active_mode != "welcome":
            self._render_view()

    @on(Button.Pressed, "#rf-save-preset-btn")
    def handle_save_preset_btn(self) -> None:
        summary = self._active_filter_summary() or "All items (no filters)"
        cur_preset = self._presets_by_id.get(self._active_preset_id)
        default_name = (
            cur_preset.label
            if (cur_preset is not None and not cur_preset.builtin)
            else ""
        )
        modal = SaveFilterPresetModal(summary=summary, default_name=default_name)

        def _on_saved(name: str | None) -> None:
            if not name:
                return
            preset = self._build_current_preset(name)
            try:
                save_custom_rf_preset(preset, workspace_dir=self.workspace_dir)
                self._refresh_preset_options(select_id=preset.id)
                self._active_preset_id = preset.id
                self._sync_delete_preset_button()
                if self._active_mode != "welcome":
                    self._render_view()
                msg = f"Saved filter view preset '{preset.label}'."
                self.set_status(msg)
                self.notify_user(msg, title="Preset Saved")
            except Exception as exc:
                self.report_error("Save Filter Preset", exc)

        self.app.push_screen(modal, _on_saved)

    @on(Button.Pressed, "#rf-delete-preset-btn")
    def handle_delete_preset_btn(self) -> None:
        preset = self._presets_by_id.get(self._active_preset_id)
        if preset is None or preset.builtin:
            self.set_status("Select a custom saved preset to delete.")
            return
        try:
            delete_custom_rf_preset(preset.id, workspace_dir=self.workspace_dir)
            self._refresh_preset_options(select_id="all")
            self.handle_clear_filters()
            msg = f"Deleted custom preset '{preset.label}'."
            self.set_status(msg)
            self.notify_user(msg, title="Preset Deleted")
        except Exception as exc:
            self.report_error("Delete Filter Preset", exc)

    @on(Button.Pressed, "#rf-apply-server-btn")
    def handle_apply_server_filters(self) -> None:
        if self._active_mode in ("alerts_v3", "playbook", "cases"):
            self.action_reload_active_view()
        else:
            self.handle_alerts()

    @on(Button.Pressed, "#rf-st-all")
    def handle_status_all_pressed(self) -> None:
        if not self._selected_statuses:
            return
        self._selected_statuses = []
        self._sync_status_bar_controls()
        self._mark_custom_if_modified()
        self._update_filter_title()
        if self._active_mode != "welcome":
            self._render_view()

    @on(Button.Pressed, "#rf-status-bar > Button")
    def handle_status_chip_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        st_val = _STATUS_BUTTON_TO_VALUE.get(btn_id)
        if st_val is None:
            return
        norm_target = normalize_status_key(st_val)
        existing = [
            s for s in self._selected_statuses if normalize_status_key(s) != norm_target
        ]
        if len(existing) == len(self._selected_statuses):
            existing.append(st_val)
        self._selected_statuses = existing
        self._sync_status_bar_controls()
        self._mark_custom_if_modified()
        self._update_filter_title()
        if self._active_mode != "welcome":
            self._render_view()

    @on(Button.Pressed, "#rf-auto-enrich-btn")
    def handle_auto_enrich_toggle(self) -> None:
        self._auto_enrich_enabled = not self._auto_enrich_enabled
        self._sync_status_bar_controls()
        if self._auto_enrich_enabled:
            self.set_status("On-screen alert auto-enrichment enabled.")
            self._schedule_visible_enrichment()
        else:
            self.set_status("On-screen alert auto-enrichment paused.")

    @on(Select.Changed, "#rf-pb-category")
    def handle_pb_category_changed(self) -> None:
        if self._applying_preset:
            return
        self._mark_custom_if_modified()
        self._update_filter_title()
        if self._active_mode == "playbook":
            self._render_view()

    @on(Select.Changed, "#rf-view-select")
    def handle_view_select_changed(self, event: Select.Changed) -> None:
        if self._syncing_view_select:
            return
        if str(event.value) != str(event.select.value):
            return
        new_mode = str(event.value or "welcome")
        if new_mode == self._active_mode:
            return
        self._active_mode = new_mode
        self._render_view()

    @on(Button.Pressed, "#rf-reset-filters-btn")
    @on(Button.Pressed, "#rf-clear-filter-btn")
    def handle_clear_filters(self) -> None:
        default_preset = self._presets_by_id.get("all") or FilterPreset(
            id="all", label="View: All Alerts", builtin=True
        )
        self._apply_preset(default_preset)

    @on(DataTable.RowHighlighted, "#rf-results-table")
    def handle_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self._rendering_table:
            return
        if 0 <= event.cursor_row < len(self._visible_items):
            self._last_error_payload = None
            self._selected_index = event.cursor_row
            self._update_toolbar_state()
            self._render_detail_panel()
            self._schedule_visible_enrichment()

    @on(DataTable.RowSelected, "#rf-results-table")
    def handle_row_selected(self, event: DataTable.RowSelected) -> None:
        if self._rendering_table:
            return
        if not (0 <= event.cursor_row < len(self._visible_items)):
            return
        self._selected_index = event.cursor_row
        item = self._visible_items[event.cursor_row]
        if self._active_mode == "welcome":
            self._activate_welcome_action(str(item.get("action_id") or ""))
            return
        self._trigger_deep_detail(item)

    def _activate_welcome_action(self, action_id: str) -> None:
        if action_id == "alerts_v3":
            self.handle_alerts()
        elif action_id == "playbook":
            self.handle_playbook_alerts()
        elif action_id == "cases":
            self.handle_cases()
        elif action_id == "intel_v2":
            self.query_one("#rf-ioc-input", Input).focus()
        elif action_id == "entity_match":
            self.query_one("#rf-query-input", Input).focus()

    def _trigger_deep_detail(self, item: dict[str, Any]) -> None:
        mode = self._active_mode
        item_id = str(item.get("id") or "")
        if not item_id and mode != "intel_v2":
            return
        if mode == "alerts_v3":
            self._fetch_alert_v3_detail_worker(item_id)
        elif mode == "playbook":
            cat = str(item.get("category") or "domain_abuse")
            self._fetch_playbook_detail_worker(cat, item_id)
        elif mode == "cases":
            self._fetch_case_detail_worker(item_id)
        elif mode == "entity_match":
            self._fetch_entity_lookup_worker(item_id)
        elif mode == "soar":
            ent_type, clean_val = _infer_ioc_type_and_value(
                str(item.get("name") or item_id), str(item.get("type") or "")
            )
            self._v2_lookup_worker(ent_type, clean_val)
        elif mode == "intel_v2":
            ent_type = str(item.get("entity_type") or "ip")
            query_val = str(item.get("query_value") or item_id)
            if ent_type in _V2_LOOKUP_FIELDS:
                self._v2_lookup_worker(ent_type, query_val, include_related=True)
        elif mode == "sandbox":
            self._fetch_sandbox_overview_worker(item_id)

    # ------------------------------------------------------------------
    # Context Menus & Cross-Tab Pivots
    # ------------------------------------------------------------------

    def _get_copyable_detail(self) -> tuple[str, str, str | None]:
        """Return ``(text, title, language)`` for copying or viewing the active detail panel."""
        item = self._get_selected_item()
        if item is not None and self._detail_mode == "json":
            item_id = str(item.get("id") or "")
            cached_full = self._detail_cache.get((self._active_mode, item_id))
            raw_payload = cached_full if cached_full is not None else item.get("raw", item)
            title = str(item.get("title") or item.get("name") or item_id or "RF Intel JSON")
            return json.dumps(raw_payload, indent=2, default=str), f"RF Intel JSON - {title}", "json"
        try:
            text = extract_richlog_text(self.query_one("#rf-log", RichLog))
        except Exception:
            text = ""
        title = "RF Intel Detail"
        if item is not None:
            item_label = str(item.get("title") or item.get("name") or item.get("id") or "")
            if item_label:
                title = f"RF Intel - {item_label}"
        return text, title, None

    @on(Button.Pressed, "#rf-copy-detail-btn")
    def handle_copy_detail(self) -> None:
        text, _title, _lang = self._get_copyable_detail()
        self.copy_to_clipboard(text, label="RF Intel Detail")

    def _copy_selected_row(self, row_index: int | None = None) -> None:
        table = self.query_one("#rf-results-table", DataTable)
        text = extract_table_row_text(table, row_index=row_index)
        self.copy_to_clipboard(text, label="RF Intel Row")

    def _open_detail_copy_modal(self) -> None:
        text, title, lang = self._get_copyable_detail()
        self.open_copy_modal(text, title=title, language=lang)

    def _open_pane_context_menu(self, *, origin: tuple[int, int]) -> None:
        os_default = self._is_os_viewer_default()
        items = [
            ("load_alerts", "Load Alerts v3"),
            ("load_pb", "Load Playbook Alerts"),
            ("load_cases", "Load Cases"),
            ("entity_match", "Run Entity Match"),
            ("v2_lookup", "Run Connect v2 Lookup"),
            ("soar_enrich", "Run SOAR Enrich"),
            ("toggle_filter", "Toggle Filter & Advanced Tools"),
            (
                "toggle_json",
                "Switch to Overview Card" if self._detail_mode == "json" else "Switch to Raw JSON",
            ),
            (
                "toggle_os_viewer_default",
                (
                    "Default Image Viewer: OS Viewer [ON] -> Switch to TUI"
                    if os_default
                    else "Default Image Viewer: TUI Modal -> Set OS Viewer Default"
                ),
            ),
            ("copy_row", "Copy Selected Row"),
            ("copy_detail", "Copy Detail Panel"),
            ("open_copy_view", "Open Copyable View"),
        ]
        self.open_context_menu(
            items,
            title="RF Intel Actions",
            origin=origin,
            on_select=self._handle_pane_menu_action,
        )

    def _handle_pane_menu_action(self, action_id: str) -> None:
        actions = {
            "load_alerts": self.handle_alerts,
            "load_pb": self.handle_playbook_alerts,
            "load_cases": self.handle_cases,
            "entity_match": self.handle_entity_match,
            "v2_lookup": self.handle_v2_lookup,
            "soar_enrich": self.handle_soar_enrich,
            "toggle_filter": self.action_toggle_filter,
            "toggle_json": self.action_toggle_json_view,
            "toggle_os_viewer_default": self.handle_toggle_os_viewer_default,
            "copy_row": self._copy_selected_row,
            "copy_detail": self.handle_copy_detail,
            "open_copy_view": self._open_detail_copy_modal,
        }
        fn = actions.get(action_id)
        if fn is not None:
            fn()

    def open_event_row_context_menu(
        self, row_index: int, *, origin: tuple[int, int]
    ) -> bool:
        """Select ``row_index`` and open the RF alert/playbook context menu."""
        if self._active_mode not in ("alerts_v3", "playbook"):
            return False
        if not (0 <= row_index < len(self._visible_items)):
            return False
        item = self._visible_items[row_index]
        if self._active_unique_event(item) is None:
            return False
        self._selected_index = row_index
        with contextlib.suppress(Exception):
            table = self.query_one("#rf-results-table", DoubleClickDataTable)
            table.cursor_coordinate = Coordinate(row_index, 0)
        self._update_toolbar_state()
        self._render_detail_panel()
        self._open_item_context_menu(item, origin=origin)
        return True

    def _open_item_context_menu(
        self,
        item: dict[str, Any],
        *,
        origin: tuple[int, int],
        focused_screenshot_id: str | None = None,
        from_detail: bool = False,
    ) -> None:
        mode = self._active_mode
        item_id = str(item.get("id") or "")
        items: list[tuple[str, str]] = []

        pivot_entity = ""
        pivot_type = ""
        target_sc_id = ""

        if mode in ("alerts_v3", "playbook"):
            items.extend(
                [
                    ("ai_ask_event", "Ask AI / Copilot (Event Only)..."),
                    ("ai_full_investigate", "Full AI Investigation (Cross-Search)"),
                ]
            )

        if mode == "alerts_v3":
            items.extend(
                [
                    ("deep_detail", "Fetch Full Alert & Hits"),
                    ("triage", "Triage Alert (Status / Assignee / Note)..."),
                    ("create_case", "Create Investigation Case from Alert..."),
                ]
            )
            if item.get("primary_entity"):
                pivot_entity = str(item["primary_entity"])
        elif mode == "playbook":
            sc_ids = [str(s) for s in (item.get("screenshot_ids") or []) if s]
            shot_items: list[tuple[str, str]] = []
            if sc_ids:
                target_sc_id = (
                    focused_screenshot_id if focused_screenshot_id in sc_ids else sc_ids[0]
                )
                shot_tag = (
                    f" {sc_ids.index(target_sc_id) + 1}/{len(sc_ids)}"
                    if (focused_screenshot_id in sc_ids and len(sc_ids) > 1)
                    else ""
                )
                os_default = self._is_os_viewer_default()
                blur_enabled = self._is_image_blur_enabled()
                shot_items.append(
                    ("open_screenshot", f"Open Screenshot{shot_tag} in OS Image Viewer")
                )
                if blur_enabled:
                    shot_items.append(
                        (
                            "open_screenshot_unblurred",
                            f"Open Unblurred Screenshot{shot_tag} in OS Image Viewer",
                        )
                    )
                if len(sc_ids) > 1:
                    shot_items.append(
                        (
                            "open_all_screenshots",
                            f"Open All Screenshots ({len(sc_ids)}) in OS Image Viewer",
                        )
                    )
                shot_items.append(
                    (
                        "view_screenshots",
                        f"View Screenshot{shot_tag} in TUI Modal"
                        if shot_tag
                        else "View Screenshots in TUI Modal",
                    )
                )
                shot_items.append(
                    ("save_screenshot", f"Save Screenshot{shot_tag} PNG to Workspace")
                )
                shot_items.append(
                    (
                        "toggle_image_blur",
                        "Unblur Screenshots ([b])"
                        if blur_enabled
                        else "Blur Screenshots ([b])",
                    )
                )
                shot_items.append(
                    (
                        "toggle_os_viewer_default",
                        (
                            "Default Image Viewer: OS Viewer [ON] -> Switch to TUI"
                            if os_default
                            else "Default Image Viewer: TUI Modal -> Set OS Viewer Default"
                        ),
                    )
                )

            pb_core_items = [
                ("deep_detail", "Fetch Playbook Evidence (DNS / WHOIS / Logos)"),
                ("triage", "Triage Playbook Alert..."),
                ("create_case", "Create Case from Playbook Alert..."),
            ]
            if from_detail and shot_items:
                items.extend(shot_items)
                items.extend(pb_core_items)
            else:
                items.extend(pb_core_items)
                items.extend(shot_items)

            targets = item.get("targets") or []
            if targets:
                pivot_entity = str(targets[0])
            elif item.get("entity_name"):
                pivot_entity = str(item["entity_name"])
            if item.get("logo_hashes") and bool(getattr(self.app, "is_admin_view", True)):
                items.append(("send_hash_watchlist", "Send Matched Logo Hash to Watchlists"))
        elif mode == "cases":
            items.extend(
                [
                    ("deep_detail", "Fetch Full Case Log & Details"),
                    ("triage", "Update Case (Status / Priority / Assignee)..."),
                ]
            )
        elif mode == "intel_v2":
            items.extend(
                [
                    ("deep_detail", "Fetch Related Entities (v2)"),
                    ("soar_enrich_row", "Enrich via SOAR v3"),
                ]
            )
            pivot_entity = str(item.get("query_value") or item.get("name") or item_id)
            pivot_type = str(item.get("entity_type") or "")
        elif mode == "soar":
            items.append(("deep_detail", "Deep Lookup via Connect v2"))
            pivot_entity = str(item.get("name") or item_id)
            pivot_type = str(item.get("type") or "")
        elif mode == "entity_match":
            items.append(("deep_detail", "Fetch Entity Metadata & Aliases"))
            pivot_entity = str(item.get("name") or item_id)
            pivot_type = str(item.get("type") or "")
        elif mode == "sandbox":
            items.append(("deep_detail", "Fetch Sandbox Overview & Signatures"))
            if item.get("sha256"):
                pivot_entity = str(item["sha256"])
                pivot_type = "hash"

        if pivot_entity:
            if mode not in ("intel_v2", "soar"):
                items.append(("pivot_v2", f"Lookup '{truncate_text(pivot_entity, 24)}' in Connect v2"))
            items.append(
                ("deep_research", f"Deep Research '{truncate_text(pivot_entity, 24)}' in Research Tab")
            )
            if bool(getattr(self.app, "is_admin_view", True)):
                items.append(
                    ("send_watchlist", f"Send '{truncate_text(pivot_entity, 24)}' to Watchlists Tab")
                )

        items.append(
            (
                "toggle_json",
                "Switch to Overview Card" if self._detail_mode == "json" else "Switch to Raw JSON",
            )
        )
        items.append(("copy_row", "Copy Selected Row"))
        items.append(("copy_detail", "Copy Detail Panel"))
        items.append(("open_copy_view", "Open Copyable View"))
        items.append(("reload_view", "Reload Active View"))

        def _on_select(action_id: str) -> None:
            if action_id == "ai_ask_event":
                self.request_ask_event_ai("#rf-ai-panel", self._active_unique_event(item))
            elif action_id == "ai_full_investigate":
                self.request_full_event_ai("#rf-ai-panel", self._active_unique_event(item))
            elif action_id == "deep_detail":
                self._trigger_deep_detail(item)
            elif action_id == "triage":
                self._open_triage_modal(mode, item)
            elif action_id == "create_case":
                self._open_create_case_modal(mode, item)
            elif action_id == "view_screenshots":
                self._open_screenshot_modal(item, initial_image_id=target_sc_id or None)
            elif action_id == "open_screenshot":
                self._open_playbook_screenshot(item, image_id=target_sc_id or None)
            elif action_id == "open_screenshot_unblurred":
                self._open_playbook_screenshot(
                    item, image_id=target_sc_id or None, force_unblurred=True
                )
            elif action_id == "open_all_screenshots":
                self._open_playbook_screenshot(item, open_all=True)
            elif action_id == "save_screenshot":
                if target_sc_id:
                    self._save_playbook_screenshot_by_id(item, target_sc_id)
                else:
                    self._save_playbook_screenshot(item)
            elif action_id == "toggle_image_blur":
                self.handle_toggle_image_blur()
            elif action_id == "toggle_os_viewer_default":
                self.handle_toggle_os_viewer_default()
            elif action_id == "send_hash_watchlist":
                hashes = item.get("logo_hashes") or []
                if hashes:
                    h_val = str(hashes[0])
                    if h_val.lower().startswith("hash:"):
                        h_val = h_val[5:]
                    self._send_entity_to_watchlists("Hash", h_val)
            elif action_id == "soar_enrich_row":
                v2_type, clean_val = _infer_ioc_type_and_value(pivot_entity, pivot_type)
                self._soar_enrich_worker({v2_type: [clean_val]})
            elif action_id == "pivot_v2":
                v2_type, clean_val = _infer_ioc_type_and_value(pivot_entity, pivot_type)
                self.query_one("#rf-v2-type", Select).value = v2_type
                self.query_one("#rf-ioc-input", Input).value = clean_val
                self._v2_lookup_worker(v2_type, clean_val)
            elif action_id == "deep_research":
                self._research_in_research_tab(pivot_entity, pivot_type)
            elif action_id == "send_watchlist":
                v2_type, clean_val = _infer_ioc_type_and_value(pivot_entity, pivot_type)
                wl_type = _V2_TO_WATCHLIST_TYPE.get(v2_type, pivot_type or "InternetDomainName")
                self._send_entity_to_watchlists(wl_type, clean_val)
            elif action_id == "toggle_json":
                self.action_toggle_json_view()
            elif action_id == "copy_row":
                self._copy_selected_row()
            elif action_id == "copy_detail":
                self.handle_copy_detail()
            elif action_id == "open_copy_view":
                self._open_detail_copy_modal()
            elif action_id == "reload_view":
                self.action_reload_active_view()

        menu_title = truncate_text(
            item.get("title") or item.get("name") or item.get("target") or item_id,
            40,
        )
        self.open_context_menu(
            items,
            title=menu_title or _VIEW_LABELS.get(mode, "Actions"),
            origin=origin,
            on_select=_on_select,
        )

    def _send_entity_to_watchlists(self, ent_type: str, ent_val: str) -> None:
        from soclens.tui.screens.watchlists import WatchlistsPane

        def _fill(wl_pane: BaseSocPane) -> None:
            wl_pane.query_one("#wl-ent-type", Input).value = ent_type
            wl_pane.query_one("#wl-ent-value", Input).value = ent_val
            wl_pane.query_one("#wl-ent-value", Input).focus()
            wl_pane.set_status(f"Populated entity from RF Intel: {ent_type} = {ent_val}")

        activate_fn = getattr(self.app, "activate_tab", None)
        if callable(activate_fn):
            activate_fn("tab-watchlists", auto_enable_admin=True, on_ready=_fill)
            return

        tabs = self.app.query_one("#main-tabs", TabbedContent)
        tabs.active = "tab-watchlists"
        wl_pane = self.app.query_one(WatchlistsPane)
        self.call_after_refresh(_fill, wl_pane)

    def _research_in_research_tab(self, entity_val: str, entity_type: str = "") -> None:
        from soclens.tui.screens.research import ResearchPane

        v2_type, clean_val = _infer_ioc_type_and_value(entity_val, entity_type)

        def _fill(pane: BaseSocPane) -> None:
            if isinstance(pane, ResearchPane):
                pane.investigate_external(clean_val, v2_type or "auto")

        activate_fn = getattr(self.app, "activate_tab", None)
        if callable(activate_fn):
            activate_fn("tab-research", on_ready=_fill)
            return

        tabs = self.app.query_one("#main-tabs", TabbedContent)
        tabs.active = "tab-research"
        res_pane = self.app.query_one(ResearchPane)
        self.call_after_refresh(res_pane.investigate_external, clean_val, v2_type or "auto")

    # ------------------------------------------------------------------
    # Triage, Create Case & Screenshot Actions
    # ------------------------------------------------------------------

    def _open_triage_modal(self, mode: str, item: dict[str, Any]) -> None:
        item_kind = {"alerts_v3": "alert_v3", "playbook": "playbook", "cases": "case"}.get(mode)
        if item_kind is None:
            return
        item_id = str(item.get("id") or "")
        if not item_id:
            self.set_status("Selected item has no ID to update.")
            return

        modal = TriageItemModal(
            item_kind=item_kind,
            item_id=item_id,
            item_title=str(item.get("title") or item_id),
            current_status=str(item.get("status") or ""),
            current_priority=str(item.get("priority") or ""),
            current_assignee=str(item.get("assignee") or ""),
            dry_run=self.effective_dry_run,
        )

        def _on_result(result: dict[str, str] | None) -> None:
            if not result:
                return
            status_val = result.get("status", "").strip()
            priority_val = result.get("priority", "").strip()
            assignee_val = result.get("assignee", "").strip()
            note_val = result.get("note", "").strip()
            orig_assignee = str(item.get("assignee") or "").strip()
            assignee_changed = bool(assignee_val and assignee_val != orig_assignee)

            if not (status_val or priority_val or assignee_changed or note_val):
                self.set_status("No triage changes selected.")
                return

            if self.effective_dry_run:
                summary = (
                    f"[DRY-RUN] Would update {item_kind} {item_id}: "
                    f"status={status_val or '(unchanged)'}, "
                    f"priority={priority_val or '(unchanged)'}, "
                    f"assignee={assignee_val if assignee_changed else '(unchanged)'}"
                )
                self.set_status(summary)
                self.notify_user(summary, title="Dry-Run Triage Preview")
                return

            self._apply_triage_worker(
                mode=mode,
                item_id=item_id,
                status_val=status_val or None,
                priority_val=priority_val or None,
                assignee_val=assignee_val if assignee_changed else None,
                note_val=note_val or None,
            )

        self.app.push_screen(modal, _on_result)

    @work(thread=True, exit_on_error=False)
    def _apply_triage_worker(
        self,
        *,
        mode: str,
        item_id: str,
        status_val: str | None,
        priority_val: str | None,
        assignee_val: str | None,
        note_val: str | None,
    ) -> None:
        try:
            self.set_status(f"Updating {item_id} in Recorded Future...")
            if mode == "alerts_v3":
                update_obj: dict[str, Any] = {"id": item_id}
                if status_val is not None:
                    update_obj["statusInPortal"] = status_val
                if assignee_val is not None:
                    update_obj["assignee"] = assignee_val
                if note_val is not None:
                    update_obj["note"] = note_val
                self.client.update_alerts_v2([update_obj])
            elif mode == "playbook":
                self.client.update_playbook_alert(
                    item_id,
                    status=status_val,
                    priority=priority_val,
                    assignee=assignee_val,
                    log_entry=note_val,
                )
            elif mode == "cases":
                self.client.update_case(
                    item_id,
                    status=status_val,
                    priority=priority_val,
                    assignee=assignee_val,
                )

            if mode in ("alerts_v3", "playbook"):
                cache = getattr(self.app, "alert_cache", None)
                if cache is not None and hasattr(cache, "update_cached_item"):
                    cache_src = CACHE_SOURCE_RF if mode == "alerts_v3" else CACHE_SOURCE_RF_PLAYBOOK
                    triage_updates: dict[str, Any] = {}
                    if status_val is not None:
                        triage_updates["status"] = status_val
                    if priority_val is not None:
                        triage_updates["priority"] = priority_val
                    if assignee_val is not None:
                        triage_updates["assignee"] = assignee_val
                    if note_val is not None:
                        triage_updates["note"] = note_val
                    updated_detail: dict[str, Any] | None = None
                    cache_entry = cache.get(cache_src)
                    if cache_entry is not None and isinstance(cache_entry.meta.get("details"), dict):
                        raw_det = cache_entry.meta["details"].get(item_id)
                        if isinstance(raw_det, dict):
                            updated_detail = dict(raw_det)
                            if status_val is not None:
                                updated_detail["status"] = status_val
                                updated_detail["statusInPortal"] = status_val
                                if isinstance(updated_detail.get("review"), dict):
                                    updated_detail["review"] = {
                                        **updated_detail["review"],
                                        "status_in_portal": status_val,
                                    }
                                if isinstance(updated_detail.get("panel_status"), dict):
                                    updated_detail["panel_status"] = {
                                        **updated_detail["panel_status"],
                                        "status": status_val,
                                    }
                            if priority_val is not None:
                                updated_detail["priority"] = priority_val
                                if isinstance(updated_detail.get("panel_status"), dict):
                                    updated_detail["panel_status"] = {
                                        **updated_detail["panel_status"],
                                        "priority": priority_val,
                                    }
                            if assignee_val is not None:
                                updated_detail["assignee"] = assignee_val
                                if isinstance(updated_detail.get("review"), dict):
                                    updated_detail["review"] = {
                                        **updated_detail["review"],
                                        "assignee": assignee_val,
                                    }
                            if note_val is not None and isinstance(updated_detail.get("review"), dict):
                                updated_detail["review"] = {
                                    **updated_detail["review"],
                                    "note": note_val,
                                }
                    cache.update_cached_item(
                        cache_src,
                        item_id,
                        item_updates=triage_updates or None,
                        detail=updated_detail,
                    )

            def _apply_local() -> None:
                for entry in self._datasets.get(mode, []):
                    if str(entry.get("id") or "") == item_id:
                        if status_val is not None:
                            entry["status"] = status_val
                        if priority_val is not None:
                            entry["priority"] = priority_val
                        if assignee_val is not None:
                            entry["assignee"] = assignee_val
                        if note_val is not None:
                            entry["note"] = note_val
                cached = self._detail_cache.get((mode, item_id))
                if isinstance(cached, dict):
                    if status_val is not None:
                        cached["status"] = status_val
                        cached["statusInPortal"] = status_val
                        if isinstance(cached.get("review"), dict):
                            cached["review"]["status_in_portal"] = status_val
                        if isinstance(cached.get("panel_status"), dict):
                            cached["panel_status"]["status"] = status_val
                    if priority_val is not None:
                        cached["priority"] = priority_val
                        if isinstance(cached.get("panel_status"), dict):
                            cached["panel_status"]["priority"] = priority_val
                    if assignee_val is not None:
                        cached["assignee"] = assignee_val
                        if isinstance(cached.get("review"), dict):
                            cached["review"]["assignee"] = assignee_val
                    if note_val is not None and isinstance(cached.get("review"), dict):
                        cached["review"]["note"] = note_val
                if self._active_mode == mode:
                    self._render_view(preserve_id=item_id)

            self.run_on_ui(_apply_local)
            msg = f"Updated {item_id} successfully."
            self.set_status(msg)
            self.notify_user(msg, title="Triage Updated")
        except Exception as exc:
            self.report_error("Triage Update", exc)

    def _open_create_case_modal(self, mode: str, item: dict[str, Any]) -> None:
        item_id = str(item.get("id") or "")
        default_title = str(item.get("title") or f"Investigation: {item_id}").strip()
        summary_lines = [
            f"Source: {_VIEW_LABELS.get(mode, mode)} ({item_id})",
            f"Rule: {item.get('rule_name') or '-'}",
            f"Status: {item.get('status') or '-'} | Priority: {item.get('priority') or '-'}",
        ]
        if item.get("targets"):
            summary_lines.append("Targets: " + ", ".join(item["targets"]))
        if item.get("logo_hashes"):
            summary_lines.append("Logo Hashes: " + ", ".join(item["logo_hashes"]))
        modal = CreateCaseModal(
            default_title=default_title,
            default_description=" | ".join(summary_lines),
            default_priority=str(item.get("priority") or "High"),
            dry_run=self.effective_dry_run,
        )

        def _on_result(result: dict[str, str] | None) -> None:
            if not result:
                return
            if self.effective_dry_run:
                msg = (
                    f"[DRY-RUN] Would create Case '{result['title']}' "
                    f"(priority={result['priority']}, status={result['status']})."
                )
                self.set_status(msg)
                self.notify_user(msg, title="Dry-Run Case Preview")
                return
            self._create_case_worker(
                title=result["title"],
                priority=result["priority"],
                status=result["status"],
                description=result["description"],
            )

        self.app.push_screen(modal, _on_result)

    @work(thread=True, exit_on_error=False)
    def _create_case_worker(
        self,
        *,
        title: str,
        priority: str,
        status: str,
        description: str,
    ) -> None:
        try:
            self.set_status(f"Creating Case '{title}'...")
            created = self.client.create_case(
                title=title,
                description=description or None,
                status=status,
                priority=priority,
            )
            case_obj = (
                created.get("data")
                if isinstance(created.get("data"), dict)
                else created
            )
            norm = normalize_case(
                case_obj
                if isinstance(case_obj, dict) and case_obj.get("id")
                else {
                    "id": str(created.get("id") or "new-case"),
                    "title": title,
                    "status": status,
                    "priority": priority,
                    "description": description,
                }
            )

            def _insert_case() -> None:
                self._datasets["cases"].insert(0, norm)
                if self._active_mode == "cases":
                    self._render_view(preserve_id=norm["id"])

            self.run_on_ui(_insert_case)
            msg = f"Created Case {norm['id']}: '{title}'"
            self.set_status(msg)
            self.notify_user(msg, title="Case Created")
        except Exception as exc:
            self.report_error("Create Case", exc)

    def _open_playbook_screenshot(
        self,
        item: dict[str, Any],
        *,
        image_id: str | None = None,
        open_all: bool = False,
        force_unblurred: bool = False,
    ) -> None:
        sc_ids = [str(s) for s in (item.get("screenshot_ids") or []) if s]
        if not sc_ids:
            self.set_status("No screenshot IDs available. Fetch Deep Detail first.")
            return
        aid = str(item.get("id") or "")
        cat = str(item.get("category") or "domain_abuse")
        if not aid:
            self.set_status("No screenshot IDs available. Fetch Deep Detail first.")
            return
        blurred = self._is_image_blur_enabled() and not force_unblurred

        if open_all:
            target_ids = sc_ids[:4]
            cached_map: dict[str, bytes | None] = {}
            for sid in target_ids:
                c_entry = self._image_cache.get((cat, aid, sid), {})
                raw_b = c_entry.get("bytes")
                cached_map[sid] = bytes(raw_b) if isinstance(raw_b, (bytes, bytearray)) else None
            if self.effective_dry_run and all(val is None for val in cached_map.values()):
                msg = (
                    f"[DRY-RUN] Would open {len(target_ids)} Playbook Alert screenshot(s) "
                    f"for {cat}/{aid} in OS viewer."
                )
                self.set_status(msg)
                self.notify_user(msg, title="Dry-Run Screenshot Preview")
                return
            self._open_multiple_screenshots_worker(
                cat, aid, target_ids, cached_map, blurred=blurred
            )
            return

        img_id = image_id if (image_id and image_id in sc_ids) else sc_ids[0]
        if not img_id:
            self.set_status("No screenshot IDs available. Fetch Deep Detail first.")
            return
        cached = self._image_cache.get((cat, aid, img_id), {})
        cached_bytes = (
            bytes(cached["bytes"]) if isinstance(cached.get("bytes"), (bytes, bytearray)) else None
        )
        if self.effective_dry_run and cached_bytes is None:
            msg = f"[DRY-RUN] Would open Playbook Alert screenshot {cat}/{aid}/{img_id} in OS viewer."
            self.set_status(msg)
            self.notify_user(msg, title="Dry-Run Screenshot Preview")
            return

        sibling_bytes: dict[str, bytes] = {}
        for sib_id in sc_ids[:4]:
            if sib_id == img_id:
                continue
            sib_entry = self._image_cache.get((cat, aid, sib_id), {})
            sib_raw = sib_entry.get("bytes")
            if isinstance(sib_raw, (bytes, bytearray)) and len(sib_raw) > 0:
                sibling_bytes[sib_id] = bytes(sib_raw)

        self._open_screenshot_worker(
            cat,
            aid,
            img_id,
            cached_bytes=cached_bytes,
            sibling_bytes=sibling_bytes or None,
            blurred=blurred,
        )

    @work(thread=True, exit_on_error=False)
    def _open_screenshot_worker(
        self,
        category: str,
        alert_id: str,
        image_id: str,
        *,
        cached_bytes: bytes | None = None,
        sibling_bytes: dict[str, bytes] | None = None,
        blurred: bool = True,
    ) -> None:
        try:
            if cached_bytes is not None:
                raw_bytes = cached_bytes
            else:
                self.set_status(f"Downloading screenshot {image_id} for {alert_id}...")
                raw_bytes = self.client.get_playbook_alert_image(category, alert_id, image_id)
                if isinstance(raw_bytes, (bytes, bytearray)) and len(raw_bytes) > 8:
                    payload_bytes = bytes(raw_bytes)
                    cache_entry: dict[str, Any] = {"bytes": payload_bytes}
                    try:
                        payload_bytes = bytes(raw_bytes)
                        prepared = prepare_image_cache_entry(payload_bytes)
                        cache_entry.update(prepared)
                        cache = getattr(self.app, "alert_cache", None)
                        if cache is not None and hasattr(cache, "put_prepared_image"):
                            cache.put_prepared_image(f"{category}__{alert_id}__{image_id}", prepared)
                    except Exception:
                        pass

                    def _store_cache() -> None:
                        self._image_cache[(category, alert_id, image_id)] = cache_entry

                    self.run_on_ui(_store_cache)

            if sibling_bytes:
                for sib_id, sib_raw in sibling_bytes.items():
                    if sib_id == image_id or not sib_raw:
                        continue
                    try:
                        sib_payload = blur_image_bytes(sib_raw) if blurred else sib_raw
                        sib_target_id = f"{sib_id}_blurred" if blurred else sib_id
                        stage_screenshot_file(sib_payload, image_id=sib_target_id)
                    except Exception:
                        pass

            open_bytes = blur_image_bytes(raw_bytes) if blurred else raw_bytes
            open_id = f"{image_id}_blurred" if blurred else image_id
            out_path = open_image_in_native_viewer(open_bytes, image_id=open_id)
            msg = f"Opened {out_path.name} in OS image viewer"
            self.set_status(msg)
            self.notify_user(msg, title="Screenshot Opened")
        except Exception as exc:
            self.report_error("Open Playbook Screenshot", exc)

    @work(thread=True, exit_on_error=False)
    def _open_multiple_screenshots_worker(
        self,
        category: str,
        alert_id: str,
        image_ids: list[str],
        cached_bytes_map: dict[str, bytes | None],
        *,
        blurred: bool = True,
    ) -> None:
        try:
            opened_names: list[str] = []
            for idx, image_id in enumerate(image_ids, start=1):
                if self.is_app_shutting_down():
                    return
                raw_bytes = cached_bytes_map.get(image_id)
                if raw_bytes is None:
                    if self.effective_dry_run:
                        continue
                    self.set_status(
                        f"Downloading screenshot {idx}/{len(image_ids)} ({image_id})..."
                    )
                    raw_bytes = self.client.get_playbook_alert_image(
                        category, alert_id, image_id
                    )
                open_bytes = blur_image_bytes(raw_bytes) if blurred else raw_bytes
                open_id = f"{image_id}_blurred" if blurred else image_id
                out_path = open_image_in_native_viewer(open_bytes, image_id=open_id)
                opened_names.append(out_path.name)
            if not opened_names:
                self.set_status("No cached screenshots available to open in dry-run mode.")
                return
            msg = (
                f"Opened {len(opened_names)} screenshot(s) in OS image viewer: "
                + ", ".join(opened_names)
            )
            self.set_status(msg)
            self.notify_user(msg, title="Screenshots Opened")
        except Exception as exc:
            self.report_error("Open Playbook Screenshots", exc)

    def _save_playbook_screenshot(self, item: dict[str, Any]) -> None:
        sc_ids = item.get("screenshot_ids") or []
        if not sc_ids:
            self.set_status("No screenshot IDs available. Fetch Deep Detail first.")
            return
        self._save_playbook_screenshot_by_id(item, str(sc_ids[0]))

    def _save_playbook_screenshot_by_id(self, item: dict[str, Any], image_id: str) -> None:
        aid = str(item.get("id") or "")
        cat = str(item.get("category") or "domain_abuse")
        if not aid or not image_id:
            self.set_status("No screenshot IDs available. Fetch Deep Detail first.")
            return
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Would download Playbook Alert screenshot {cat}/{aid}/{image_id}."
            self.set_status(msg)
            self.notify_user(msg, title="Dry-Run Screenshot Preview")
            return
        cached = self._image_cache.get((cat, aid, image_id), {})
        cached_bytes = cached.get("bytes") if isinstance(cached.get("bytes"), bytes) else None
        self._save_screenshot_worker(cat, aid, image_id, cached_bytes=cached_bytes)

    @work(thread=True, exit_on_error=False)
    def _save_screenshot_worker(
        self,
        category: str,
        alert_id: str,
        image_id: str,
        *,
        cached_bytes: bytes | None = None,
    ) -> None:
        try:
            if cached_bytes is not None:
                raw_bytes = cached_bytes
            else:
                self.set_status(f"Downloading screenshot {image_id} for {alert_id}...")
                raw_bytes = self.client.get_playbook_alert_image(category, alert_id, image_id)
            safe_alert = re.sub(r"[^A-Za-z0-9._-]+", "_", alert_id)
            safe_img = re.sub(r"[^A-Za-z0-9._-]+", "_", image_id)
            dest_dir = self.workspace_dir / "screenshots"
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / f"{safe_alert}_{safe_img}.png"
            dest_path.write_bytes(raw_bytes)
            msg = f"Saved Playbook Alert screenshot ({len(raw_bytes)} bytes) to {dest_path}"
            self.set_status(msg)
            self.notify_user(msg, title="Screenshot Saved")
        except Exception as exc:
            self.report_error("Playbook Screenshot", exc)

    # ------------------------------------------------------------------
    # Query & Fetch Workers
    # ------------------------------------------------------------------

    @on(Input.Submitted, "#rf-query-input")
    def handle_query_submitted(self) -> None:
        self.handle_entity_match()

    @on(Input.Submitted, "#rf-ioc-input")
    def handle_ioc_submitted(self) -> None:
        self.handle_v2_lookup()

    @on(Button.Pressed, "#rf-match-btn")
    def handle_entity_match(self) -> None:
        query = self.query_one("#rf-query-input", Input).value.strip()
        limit = self._parse_limit(10)
        if limit is None:
            return
        if not query:
            self.set_status("Enter an entity name to match.")
            return
        self._request_seq += 1
        self._entity_match_worker(query, limit, self._request_seq)

    @work(thread=True, exit_on_error=False)
    def _entity_match_worker(self, query: str, limit: int, seq: int) -> None:
        try:
            self.set_status(f"Matching entities for '{query}'...")
            matches = self.client.entity_match(query, limit=limit)
            normalized = [normalize_entity_match(m) for m in matches if isinstance(m, dict)]

            def _apply() -> None:
                if seq != self._request_seq:
                    return
                self._datasets["entity_match"] = normalized
                self._dataset_totals["entity_match"] = len(normalized)
                self._active_mode = "entity_match"
                self._render_view()

            self.run_on_ui(_apply)
            self.set_status(f"Entity Match returned {len(normalized)} hit(s) for '{query}'.")
        except Exception as exc:
            self.report_error("RF Entity Match", exc)

    @work(thread=True, exit_on_error=False)
    def _fetch_entity_lookup_worker(self, entity_id: str) -> None:
        try:
            self.set_status(f"Fetching entity metadata for {entity_id}...")
            data = self.client.entity_lookup(entity_id)

            def _apply() -> None:
                self._last_error_payload = None
                self._detail_cache[("entity_match", entity_id)] = data
                if self._active_mode == "entity_match":
                    self._render_detail_panel()

            self.run_on_ui(_apply)
            self.set_status(f"Loaded Entity Lookup details for {entity_id}.")
        except Exception as exc:
            self.report_error("Entity Lookup", exc)

    @on(Button.Pressed, "#rf-lookup-btn")
    def handle_v2_lookup(self) -> None:
        ent_type = str(self.query_one("#rf-v2-type", Select).value)
        raw_ioc = self.query_one("#rf-ioc-input", Input).value.strip()
        if not raw_ioc:
            self.set_status("Enter an IOC value for Connect v2 lookup.")
            return
        first_ioc = raw_ioc if ent_type == "url" else raw_ioc.split(",")[0].strip()
        if not first_ioc:
            self.set_status("Enter an IOC value for Connect v2 lookup.")
            return
        self._request_seq += 1
        self._v2_lookup_worker(ent_type, first_ioc, seq=self._request_seq)

    @work(thread=True, exit_on_error=False)
    def _v2_lookup_worker(
        self,
        ent_type: str,
        ioc_val: str,
        *,
        include_related: bool = False,
        seq: int | None = None,
    ) -> None:
        try:
            self.set_status(f"Looking up {ent_type}:{ioc_val} via Connect v2...")
            fields = list(_V2_LOOKUP_FIELDS.get(ent_type, ["entity", "risk", "timestamps"]))
            if include_related and "relatedEntities" not in fields:
                fields.append("relatedEntities")
            data = self.client.v2_lookup(ent_type, ioc_val, fields=fields)
            norm = normalize_v2_record(ent_type, ioc_val, data)

            def _apply() -> None:
                if seq is not None and seq != self._request_seq:
                    return
                existing = self._datasets["intel_v2"]
                updated_list = [
                    item
                    for item in existing
                    if not (
                        item.get("entity_type") == ent_type
                        and str(item.get("query_value") or "").lower() == ioc_val.lower()
                    )
                ]
                updated_list.insert(0, norm)
                self._datasets["intel_v2"] = updated_list
                self._dataset_totals["intel_v2"] = len(updated_list)
                self._active_mode = "intel_v2"
                self._render_view(preserve_id=norm["id"])

            self.run_on_ui(_apply)
            score = norm.get("risk_score")
            score_label = f" (Risk {score}/99)" if score is not None else ""
            self.set_status(f"Connect v2 lookup succeeded for {ent_type}:{ioc_val}{score_label}.")
        except Exception as exc:
            self.report_error("Connect v2 Lookup", exc)

    @on(Button.Pressed, "#rf-company-btn")
    def handle_company_by_domain(self) -> None:
        raw_ioc = self.query_one("#rf-ioc-input", Input).value.strip()
        if not raw_ioc:
            self.set_status("Enter a domain in the IOC field for Company by Domain lookup.")
            return
        domain = raw_ioc.split(",")[0].strip()
        self._request_seq += 1
        self._company_lookup_worker(domain, self._request_seq)

    @work(thread=True, exit_on_error=False)
    def _company_lookup_worker(self, domain: str, seq: int) -> None:
        try:
            self.set_status(f"Resolving company for domain '{domain}'...")
            data = self.client.v2_company_by_domain(domain)
            norm = normalize_v2_record("company", domain, data)

            def _apply() -> None:
                if seq != self._request_seq:
                    return
                existing = self._datasets["intel_v2"]
                updated_list = [
                    item
                    for item in existing
                    if not (
                        item.get("entity_type") == "company"
                        and str(item.get("query_value") or "").lower() == domain.lower()
                    )
                ]
                updated_list.insert(0, norm)
                self._datasets["intel_v2"] = updated_list
                self._dataset_totals["intel_v2"] = len(updated_list)
                self._active_mode = "intel_v2"
                self._render_view(preserve_id=norm["id"])

            self.run_on_ui(_apply)
            self.set_status(f"Resolved company '{norm['name']}' for {domain}.")
        except Exception as exc:
            self.report_error("Company by Domain", exc)

    @on(Button.Pressed, "#rf-enrich-btn")
    def handle_soar_enrich(self) -> None:
        ent_type = str(self.query_one("#rf-v2-type", Select).value)
        raw_ioc = self.query_one("#rf-ioc-input", Input).value.strip()
        values = [v.strip() for v in raw_ioc.split(",") if v.strip()]
        if not values:
            self.set_status("Enter one or more comma-separated IOC values for SOAR enrich.")
            return
        self._request_seq += 1
        self._soar_enrich_worker({ent_type: values}, seq=self._request_seq)

    @work(thread=True, exit_on_error=False)
    def _soar_enrich_worker(
        self, iocs: dict[str, list[str]], *, seq: int | None = None
    ) -> None:
        try:
            self.set_status("Running SOAR v3 batch enrichment...")
            data = self.client.soar_enrich(iocs)
            raw_results = extract_soar_results(data)
            normalized = [normalize_soar_item(r, mode="enrich") for r in raw_results]

            def _apply() -> None:
                if seq is not None and seq != self._request_seq:
                    return
                self._datasets["soar"] = normalized
                self._dataset_totals["soar"] = len(normalized)
                self._active_mode = "soar"
                self._render_view()

            self.run_on_ui(_apply)
            self.set_status(f"SOAR v3 enrichment returned {len(normalized)} result(s).")
        except Exception as exc:
            self.report_error("SOAR v3 Enrich", exc)

    @on(Button.Pressed, "#rf-triage-btn")
    def handle_soar_triage(self) -> None:
        ent_type = str(self.query_one("#rf-v2-type", Select).value)
        ctx = str(self.query_one("#rf-triage-context", Select).value)
        raw_ioc = self.query_one("#rf-ioc-input", Input).value.strip()
        values = [v.strip() for v in raw_ioc.split(",") if v.strip()]
        if not values:
            self.set_status("Enter one or more comma-separated IOC values for SOAR triage.")
            return
        self._request_seq += 1
        self._soar_triage_worker(ctx, {ent_type: values}, self._request_seq)

    @work(thread=True, exit_on_error=False)
    def _soar_triage_worker(
        self, context_name: str, iocs: dict[str, list[str]], seq: int
    ) -> None:
        try:
            self.set_status(f"Running SOAR v3 triage (context={context_name})...")
            data = self.client.soar_triage(context_name, iocs)
            raw_results = extract_soar_results(data)
            normalized = [
                normalize_soar_item(r, mode="triage", context=context_name) for r in raw_results
            ]

            def _apply() -> None:
                if seq != self._request_seq:
                    return
                self._datasets["soar"] = normalized
                self._dataset_totals["soar"] = len(normalized)
                self._active_mode = "soar"
                self._render_view()

            self.run_on_ui(_apply)
            self.set_status(
                f"SOAR triage ({context_name}) returned {len(normalized)} verdict(s)."
            )
        except Exception as exc:
            self.report_error("SOAR v3 Triage", exc)

    def _get_on_screen_items(self, *, max_items: int = 20) -> list[dict[str, Any]]:
        items = self._visible_items
        if not items:
            return []
        try:
            table = self.query_one("#rf-results-table", DoubleClickDataTable)
            vis_h = int(table.scrollable_content_region.height or table.size.height or 0)
            scroll_y = int(round(table.scroll_y))
            cursor_row = int(table.cursor_coordinate.row)
        except Exception:
            vis_h = 0
            scroll_y = 0
            cursor_row = 0

        if vis_h <= 0:
            start = 0
            end = min(len(items), max_items)
        else:
            start = max(0, scroll_y)
            end = min(len(items), start + max(vis_h + 2, 10), start + max_items)
            if 0 <= cursor_row < len(items) and not (start <= cursor_row < end):
                start = max(0, cursor_row - 2)
                end = min(len(items), start + max(vis_h + 2, 10), start + max_items)
        return list(items[start:end])

    @staticmethod
    def _needs_auto_enrich(mode: str, item: dict[str, Any]) -> bool:
        raw_obj = item.get("raw")
        raw = raw_obj if isinstance(raw_obj, dict) else {}
        if mode == "playbook":
            return not isinstance(raw.get("panel_status"), dict)
        if mode == "alerts_v3":
            return not item.get("assignee")
        if mode == "cases":
            return not item.get("assignee") or not item.get("description")
        return False

    def _claim_visible_enrichment_targets(
        self, expected_mode: str | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        if (
            not self._tables_ready
            or self.is_app_shutting_down()
            or not self._auto_enrich_enabled
        ):
            return [], 0
        mode = expected_mode or self._active_mode
        if mode != self._active_mode or mode not in ("alerts_v3", "playbook", "cases"):
            return [], 0
        loading_fn = getattr(self.app, "is_cache_source_loading", None)
        if callable(loading_fn):
            if mode == "alerts_v3" and getattr(self, "_hydrated_from_cache", False) and loading_fn(CACHE_SOURCE_RF):
                return [], 0
            if mode == "playbook" and getattr(self, "_pb_cache_fetched_at", 0.0) > 0.0 and loading_fn(CACHE_SOURCE_RF_PLAYBOOK):
                return [], 0
        on_screen = self._get_on_screen_items(max_items=20)
        targets: list[dict[str, Any]] = []
        for item in on_screen:
            aid = str(item.get("id") or "").strip()
            if not aid:
                continue
            key = (mode, aid)
            if key in self._auto_enriched_keys or key in self._detail_cache:
                continue
            if self._needs_auto_enrich(mode, item):
                targets.append(dict(item))
        if not targets:
            return [], 0
        for item in targets:
            self._auto_enriched_keys.add((mode, str(item.get("id") or "").strip()))
        self._enrich_seq += 1
        return targets, self._enrich_seq

    def _schedule_visible_enrichment(self) -> None:
        targets, seq = self._claim_visible_enrichment_targets()
        if not targets:
            return
        self._auto_enrich_visible_worker(self._active_mode, targets, seq)

    @work(thread=True, exit_on_error=False)
    def _auto_enrich_visible_worker(
        self, mode: str, targets: list[dict[str, Any]], seq: int
    ) -> None:
        self._run_auto_enrich_sync(mode, targets, seq)

    def _run_auto_enrich_sync(
        self, mode: str, targets: list[dict[str, Any]], seq: int
    ) -> None:
        if self.is_app_shutting_down() or seq != self._enrich_seq or not targets:
            return
        updates: dict[str, dict[str, Any]] = {}
        full_details: dict[str, dict[str, Any]] = {}

        try:
            if mode == "cases":
                ids = [str(it.get("id") or "").strip() for it in targets if it.get("id")]
                if ids:
                    try:
                        resp = self.client.lookup_cases(ids)
                        raw_list = resp.get("data") if isinstance(resp.get("data"), list) else []
                        for raw_case in raw_list:
                            if not isinstance(raw_case, dict):
                                continue
                            norm = normalize_case(raw_case)
                            cid = str(norm.get("id") or "").strip()
                            if cid:
                                updates[cid] = norm
                                full_details[cid] = raw_case
                    except Exception as exc:
                        _logger.debug("Auto-enrich cases batch failed: %s", exc)
            elif mode == "playbook":
                def _fetch_pb(
                    item: dict[str, Any],
                ) -> tuple[str, dict[str, Any], dict[str, Any]] | None:
                    if self.is_app_shutting_down() or seq != self._enrich_seq:
                        return None
                    aid = str(item.get("id") or "").strip()
                    cat = str(item.get("category") or "").strip()
                    try:
                        if cat and cat != "-":
                            try:
                                resp = self.client.get_playbook_alert(cat, aid)
                            except ValueError:
                                resp = self.client.get_playbook_alert_preview(aid)
                            except RecordedFutureError as exc:
                                if exc.status_code == 404:
                                    resp = self.client.get_playbook_alert_preview(aid)
                                else:
                                    raise
                        else:
                            resp = self.client.get_playbook_alert_preview(aid)
                        raw_data = resp.get("data") if isinstance(resp, dict) else None
                        detail: dict[str, Any] = (
                            raw_data
                            if isinstance(raw_data, dict)
                            else (resp if isinstance(resp, dict) else {})
                        )
                        if not detail:
                            return None
                        if not detail.get("category") and cat and cat != "-":
                            detail = {**detail, "category": cat}
                        norm = normalize_playbook_alert(detail)
                        eff_cat = str(
                            norm.get("category")
                            if norm.get("category") and norm.get("category") != "-"
                            else (cat if cat and cat != "-" else "domain_abuse")
                        )
                        sc_ids = [str(s) for s in (norm.get("screenshot_ids") or []) if s][:4]
                        cache = getattr(self.app, "alert_cache", None)
                        is_unavail_fn = getattr(cache, "is_image_unavailable", None)
                        mark_unavail_fn = getattr(cache, "mark_image_unavailable", None)
                        if cache is not None and hasattr(cache, "update_cached_item") and isinstance(detail, dict):
                            cache.update_cached_item(
                                CACHE_SOURCE_RF_PLAYBOOK,
                                aid,
                                item_updates=norm,
                                detail=detail,
                            )
                        for sid in sc_ids:
                            if self.is_app_shutting_down() or seq != self._enrich_seq:
                                break
                            img_tuple = (eff_cat, aid, sid)
                            if img_tuple in self._image_cache and not self._image_cache[img_tuple].get("error"):
                                continue
                            img_key = f"{eff_cat}__{aid}__{sid}"
                            if callable(is_unavail_fn) and is_unavail_fn(img_key):
                                self._image_cache[img_tuple] = {
                                    "error": "Screenshot unavailable (HTTP 404 from Recorded Future)"
                                }
                                continue
                            try:
                                raw_bytes = (
                                    cache.get_image_bytes(img_key) if cache is not None else None
                                )
                                if raw_bytes is None:
                                    fetched = self.client.get_playbook_alert_image(
                                        eff_cat, aid, sid
                                    )
                                    if isinstance(fetched, (bytes, bytearray)) and len(fetched) > 8:
                                        raw_bytes = bytes(fetched)
                                        if cache is not None:
                                            cache.put_image_bytes(img_key, raw_bytes)
                                    else:
                                        self._image_cache[img_tuple] = {
                                            "error": "Empty or unsupported screenshot response"
                                        }
                                if raw_bytes:
                                    prepared = prepare_image_cache_entry(bytes(raw_bytes))
                                    self._image_cache[img_tuple] = prepared
                                    if cache is not None and hasattr(cache, "put_prepared_image"):
                                        cache.put_prepared_image(img_key, prepared)
                            except RecordedFutureError as img_exc:
                                if img_exc.status_code == 404:
                                    if callable(mark_unavail_fn):
                                        mark_unavail_fn(img_key)
                                    self._image_cache[img_tuple] = {
                                        "error": "Screenshot unavailable (HTTP 404 from Recorded Future)"
                                    }
                                else:
                                    self._image_cache[img_tuple] = {
                                        "error": self.format_exception(img_exc)
                                    }
                            except Exception as img_exc:
                                self._image_cache[img_tuple] = {
                                    "error": self.format_exception(img_exc)
                                }
                        return aid, norm, detail
                    except Exception as exc:
                        _logger.debug("Auto-enrich playbook %s failed: %s", aid, exc)
                        return None

                with ThreadPoolExecutor(max_workers=4) as pool:
                    pb_futures = [pool.submit(_fetch_pb, it) for it in targets]
                    for fut in as_completed(pb_futures):
                        if self.is_app_shutting_down() or seq != self._enrich_seq:
                            break
                        res = fut.result()
                        if res is not None:
                            updates[res[0]] = res[1]
                            full_details[res[0]] = res[2]
            elif mode == "alerts_v3":
                def _fetch_v3(
                    item: dict[str, Any],
                ) -> tuple[str, dict[str, Any], dict[str, Any]] | None:
                    if self.is_app_shutting_down() or seq != self._enrich_seq:
                        return None
                    aid = str(item.get("id") or "").strip()
                    try:
                        resp = self.client.get_alert_v3(aid)
                        raw_data = resp.get("data") if isinstance(resp, dict) else None
                        detail: dict[str, Any] = (
                            raw_data
                            if isinstance(raw_data, dict)
                            else (resp if isinstance(resp, dict) else {})
                        )
                        if not detail:
                            return None
                        norm = normalize_alert_v3(detail)
                        return aid, norm, detail
                    except Exception as exc:
                        _logger.debug("Auto-enrich alert_v3 %s failed: %s", aid, exc)
                        return None

                with ThreadPoolExecutor(max_workers=4) as pool:
                    v3_futures = [pool.submit(_fetch_v3, it) for it in targets]
                    for v3_fut in as_completed(v3_futures):
                        if self.is_app_shutting_down() or seq != self._enrich_seq:
                            break
                        v3_res = v3_fut.result()
                        if v3_res is not None:
                            updates[v3_res[0]] = v3_res[1]
                            full_details[v3_res[0]] = v3_res[2]
        except Exception as exc:
            _logger.debug("Auto-enrich worker %s error: %s", mode, exc)
            return

        if not updates or self.is_app_shutting_down() or seq != self._enrich_seq:
            return

        def _apply() -> None:
            if seq != self._enrich_seq or self.is_app_shutting_down():
                return
            for aid, raw_det in full_details.items():
                self._detail_cache[(mode, aid)] = raw_det
            for entry in self._datasets.get(mode, []):
                aid = str(entry.get("id") or "").strip()
                norm = updates.get(aid)
                if norm is None:
                    continue
                if mode == "playbook":
                    for field in (
                        "assignee",
                        "status",
                        "priority",
                        "entity_name",
                        "targets",
                        "attackers",
                        "actions_taken",
                        "logo_hashes",
                        "logotypes",
                        "screenshot_ids",
                        "screenshots_meta",
                        "updated",
                        "risk_score",
                    ):
                        val = norm.get(field)
                        if val not in ("", None, "-", []) or not entry.get(field):
                            entry[field] = val
                    if (
                        norm.get("rule_name") not in ("", None, "-")
                        and entry.get("rule_name") in ("", None, "-")
                    ):
                        entry["rule_name"] = norm["rule_name"]
                    if (
                        norm.get("title") not in ("", None, "-", aid)
                        and entry.get("title") in ("", None, "-", aid)
                    ):
                        entry["title"] = norm["title"]
                    norm_raw = norm.get("raw")
                    if isinstance(norm_raw, dict) and isinstance(norm_raw.get("panel_status"), dict):
                        cur_raw = entry.get("raw")
                        if not isinstance(cur_raw, dict):
                            cur_raw = {}
                            entry["raw"] = cur_raw
                        cur_raw["panel_status"] = norm_raw["panel_status"]
                elif mode == "alerts_v3":
                    for field in (
                        "assignee",
                        "status",
                        "priority",
                        "note",
                        "hits",
                        "hits_count",
                        "ai_insights",
                        "primary_entity",
                        "rule_name",
                        "org_name",
                        "portal_url",
                        "status_date",
                    ):
                        val = norm.get(field)
                        if val not in ("", None, "-", [], 0) or not entry.get(field):
                            entry[field] = val
                    if isinstance(norm.get("raw"), dict):
                        entry["raw"] = norm["raw"]
                else:
                    merged = dict(norm)
                    if not merged.get("title") and entry.get("title"):
                        merged["title"] = entry["title"]
                    entry.update(merged)

            selected = self._get_selected_item()
            preserve = str(selected.get("id") or "") if selected is not None else None
            self._refresh_assignee_options()
            if self._active_mode == mode:
                self._render_view(preserve_id=preserve, schedule_auto_enrich=False)
                label = _VIEW_LABELS.get(mode, mode)
                self.set_status(
                    f"Auto-enriched {len(updates)} on-screen {label} row(s) (assignee & status)."
                )

        self.run_on_ui(_apply)

    def _current_server_filter_snapshot(self) -> dict[str, Any]:
        return {
            "timeframe": self._timeframe_filter,
            "date_from": self.query_one("#rf-date-from", Input).value.strip(),
            "date_to": self.query_one("#rf-date-to", Input).value.strip(),
            "priority": self._priority_filter,
            "assignee": self._assignee_filter,
            "sort_by": self._sort_by,
            "time_field": self._time_field,
        }

    @on(Button.Pressed, "#rf-alerts-btn")
    def handle_alerts(self) -> None:
        limit = self._parse_limit(20)
        if limit is None:
            return
        statuses = list(self._selected_statuses)
        filters = self._current_server_filter_snapshot()
        self._auto_enriched_keys = {k for k in self._auto_enriched_keys if k[0] != "alerts_v3"}
        self._enrich_seq += 1
        self._request_seq += 1
        self._alerts_worker(limit, self._request_seq, statuses=statuses, filters=filters)

    @work(thread=True, exit_on_error=False)
    def _alerts_worker(
        self,
        limit: int,
        seq: int,
        statuses: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> None:
        try:
            active_statuses = list(statuses or [])
            f = filters or {}
            extra_kwargs: dict[str, Any] = {}
            triggered_param = build_alerts_v3_triggered_param(
                str(f.get("timeframe") or "any"),
                date_from=str(f.get("date_from") or ""),
                date_to=str(f.get("date_to") or ""),
            )
            if triggered_param:
                extra_kwargs["triggered"] = triggered_param
            assignee_val = str(f.get("assignee") or "any")
            if assignee_val.lower() not in _BASE_ASSIGNEE_VALUES:
                extra_kwargs["assignee"] = assignee_val
            if str(f.get("sort_by") or "") == "oldest":
                extra_kwargs["direction"] = "asc"

            if active_statuses:
                self.set_status(
                    f"Loading Alerts v3 matching statuses ({', '.join(active_statuses)})..."
                )
            else:
                self.set_status(f"Loading up to {limit} classic Alert(s) via Alerts v3...")

            def _call_alerts_v3(status_val: str | None = None) -> dict[str, Any]:
                call_kw: dict[str, Any] = {"limit": limit, **extra_kwargs}
                if status_val is not None:
                    call_kw["status_in_portal"] = status_val
                try:
                    return self.client.search_alerts_v3(**call_kw)
                except RecordedFutureError as exc:
                    if exc.status_code not in (400, 422) or not extra_kwargs:
                        raise
                    fallback_kw: dict[str, Any] = {"limit": limit}
                    if status_val is not None:
                        fallback_kw["status_in_portal"] = status_val
                    return self.client.search_alerts_v3(**fallback_kw)

            raw_items: list[dict[str, Any]] = []
            total: int | None = None
            if not active_statuses:
                data: dict[str, Any] = _call_alerts_v3()
                raw_items, total = extract_alerts_v3(data)
            elif len(active_statuses) == 1:
                try:
                    data = _call_alerts_v3(active_statuses[0])
                    raw_items, total = extract_alerts_v3(data)
                except RecordedFutureError as exc:
                    if exc.status_code not in (400, 422):
                        raise
                    data = _call_alerts_v3()
                    raw_items, total = extract_alerts_v3(data)
            else:
                by_id: dict[str, dict[str, Any]] = {}
                any_succeeded = False
                for st in active_statuses:
                    try:
                        chunk = _call_alerts_v3(st)
                        any_succeeded = True
                        chunk_items, _ = extract_alerts_v3(chunk)
                        for rec in chunk_items:
                            rid = str(rec.get("id") or "")
                            if rid and rid not in by_id:
                                by_id[rid] = rec
                    except RecordedFutureError as exc:
                        if exc.status_code not in (400, 422):
                            raise
                if not any_succeeded:
                    data = _call_alerts_v3()
                    raw_items, total = extract_alerts_v3(data)
                else:
                    merged_items = list(by_id.values())
                    merged_items.sort(
                        key=lambda it: str(
                            (it.get("log") or {}).get("triggered")
                            if isinstance(it.get("log"), dict)
                            else it.get("triggered") or ""
                        ),
                        reverse=True,
                    )
                    raw_items = merged_items[:limit]
                    total = len(by_id)

            normalized = [normalize_alert_v3(item) for item in raw_items]

            def _merge_v3_det(entry: dict[str, Any], det: dict[str, Any]) -> None:
                norm_det = normalize_alert_v3(det)
                for field in (
                    "note",
                    "hits",
                    "hits_count",
                    "ai_insights",
                    "primary_entity",
                    "rule_name",
                    "org_name",
                    "portal_url",
                ):
                    val = norm_det.get(field)
                    if val not in ("", None, "-", [], 0) or not entry.get(field):
                        entry[field] = val
                for field in ("status", "priority", "assignee", "status_date"):
                    if entry.get(field) in ("", None, "-") and norm_det.get(field) not in (
                        "",
                        None,
                        "-",
                    ):
                        entry[field] = norm_det[field]
                if isinstance(norm_det.get("raw"), dict):
                    entry["raw"] = norm_det["raw"]

            cache = getattr(self.app, "alert_cache", None)
            reusable_details: dict[str, dict[str, Any]] = {}
            stale_ids: set[str] = set()
            if cache is not None:
                existing_entry = cache.get(CACHE_SOURCE_RF)
                raw_existing_details = (
                    existing_entry.meta.get("details")
                    if existing_entry is not None and isinstance(existing_entry.meta.get("details"), dict)
                    else {}
                )
                for item in normalized:
                    aid = str(item.get("id") or "").strip()
                    det = raw_existing_details.get(aid) if aid else None
                    if isinstance(det, dict) and not is_alert_v3_detail_stale(item, det):
                        reusable_details[aid] = det
                        _merge_v3_det(item, det)
                    elif aid:
                        stale_ids.add(aid)
                if (
                    str(f.get("timeframe") or "any") == "last_24h"
                    and not active_statuses
                    and assignee_val.lower() == "any"
                ):
                    cache.put(
                        CACHE_SOURCE_RF,
                        normalized,
                        timeframe="last_24h",
                        meta={"total": total, "details": reusable_details},
                    )

            def _apply() -> tuple[list[dict[str, Any]], int] | None:
                if seq != self._request_seq:
                    return None
                for item in normalized:
                    aid = str(item.get("id") or "").strip()
                    if not aid:
                        continue
                    key = ("alerts_v3", aid)
                    if aid in reusable_details:
                        self._detail_cache[key] = reusable_details[aid]
                        self._auto_enriched_keys.add(key)
                    elif aid in stale_ids or aid not in self._detail_cache:
                        ui_det = self._detail_cache.get(key)
                        if isinstance(ui_det, dict) and not is_alert_v3_detail_stale(item, ui_det):
                            _merge_v3_det(item, ui_det)
                            self._auto_enriched_keys.add(key)
                        else:
                            self._detail_cache.pop(key, None)
                            self._auto_enriched_keys.discard(key)
                self._datasets["alerts_v3"] = normalized
                self._dataset_totals["alerts_v3"] = total
                self._active_mode = "alerts_v3"
                self._hydrated_from_cache = False
                self._refresh_assignee_options()
                self._render_view(schedule_auto_enrich=False)
                return self._claim_visible_enrichment_targets("alerts_v3")

            enrich_info = self.run_on_ui(_apply)
            if seq != self._request_seq or self.is_app_shutting_down():
                return
            self.set_status(f"Loaded {len(normalized)} classic alert(s) via Alerts v3.")
            if enrich_info:
                targets, enrich_seq = enrich_info
                if targets:
                    self._run_auto_enrich_sync("alerts_v3", targets, enrich_seq)
        except Exception as exc:
            self.report_error("Alerts v3 Search", exc)

    @work(thread=True, exit_on_error=False)
    def _fetch_alert_v3_detail_worker(self, alert_id: str) -> None:
        try:
            self.set_status(f"Fetching full detail for Alert {alert_id}...")
            resp = self.client.get_alert_v3(alert_id)
            detail = resp.get("data") if isinstance(resp.get("data"), dict) else resp
            if not isinstance(detail, dict):
                detail = resp
            norm = normalize_alert_v3(detail)
            cache = getattr(self.app, "alert_cache", None)
            if cache is not None and hasattr(cache, "update_cached_item") and isinstance(detail, dict):
                item_updates = {
                    k: norm[k]
                    for k in (
                        "assignee",
                        "status",
                        "priority",
                        "note",
                        "hits",
                        "hits_count",
                        "ai_insights",
                        "primary_entity",
                        "rule_name",
                        "org_name",
                        "portal_url",
                        "status_date",
                    )
                    if norm.get(k) not in ("", None, "-", [], 0)
                }
                if isinstance(norm.get("raw"), dict):
                    item_updates["raw"] = norm["raw"]
                cache.update_cached_item(
                    CACHE_SOURCE_RF,
                    alert_id,
                    item_updates=item_updates,
                    detail=detail,
                )

            def _apply() -> None:
                self._last_error_payload = None
                self._detail_cache[("alerts_v3", alert_id)] = detail
                for entry in self._datasets.get("alerts_v3", []):
                    if str(entry.get("id") or "") == alert_id:
                        for field in (
                            "assignee",
                            "status",
                            "priority",
                            "note",
                            "hits",
                            "hits_count",
                            "ai_insights",
                            "primary_entity",
                            "rule_name",
                            "org_name",
                            "portal_url",
                            "status_date",
                        ):
                            val = norm.get(field)
                            if val not in ("", None, "-", [], 0) or not entry.get(field):
                                entry[field] = val
                        if isinstance(norm.get("raw"), dict):
                            entry["raw"] = norm["raw"]
                if self._active_mode == "alerts_v3":
                    self._render_view(preserve_id=alert_id)

            self.run_on_ui(_apply)
            self.set_status(f"Loaded full Alert v3 detail for {alert_id}.")
        except Exception as exc:
            self.report_error("Alert v3 Detail", exc)

    @on(Button.Pressed, "#rf-pb-btn")
    def handle_playbook_alerts(self) -> None:
        limit = self._parse_limit(20)
        if limit is None:
            return
        pb_cat = str(self.query_one("#rf-pb-category", Select).value)
        if pb_cat == "all":
            categories: list[str] | None = None
        elif pb_cat == "brand_bundle":
            categories = ["domain_abuse", "malicious_sites"]
        else:
            categories = [pb_cat]
        statuses = list(self._selected_statuses)
        filters = self._current_server_filter_snapshot()
        self._auto_enriched_keys = {k for k in self._auto_enriched_keys if k[0] != "playbook"}
        self._enrich_seq += 1
        self._request_seq += 1
        self._playbook_worker(
            categories, limit, self._request_seq, statuses=statuses, filters=filters
        )

    @work(thread=True, exit_on_error=False)
    def _playbook_worker(
        self,
        categories: list[str] | None,
        limit: int,
        seq: int,
        statuses: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> None:
        try:
            active_statuses = list(statuses or [])
            f = filters or {}
            api_statuses = [
                PLAYBOOK_API_STATUS_MAP[normalize_status_key(s)]
                for s in active_statuses
                if normalize_status_key(s) in PLAYBOOK_API_STATUS_MAP
            ]
            # Preserve insertion order without duplicates
            api_statuses = list(dict.fromkeys(api_statuses))

            extra_kwargs: dict[str, Any] = {}
            pb_range = build_playbook_date_range(
                str(f.get("timeframe") or "any"),
                date_from=str(f.get("date_from") or ""),
                date_to=str(f.get("date_to") or ""),
            )
            if pb_range:
                if str(f.get("time_field") or "auto") == "created":
                    extra_kwargs["created_range"] = pb_range
                else:
                    extra_kwargs["updated_range"] = pb_range
            pb_priorities = map_priority_for_playbook(str(f.get("priority") or "any"))
            if pb_priorities:
                extra_kwargs["priorities"] = pb_priorities
            assignee_val = str(f.get("assignee") or "any")
            if assignee_val.lower() not in _BASE_ASSIGNEE_VALUES:
                extra_kwargs["assignees"] = [assignee_val]
            if str(f.get("sort_by") or "") == "oldest":
                extra_kwargs["direction"] = "asc"

            if api_statuses:
                self.set_status(
                    f"Loading Playbook Alerts (statuses: {', '.join(api_statuses)})..."
                )
            else:
                self.set_status("Loading Playbook Alerts from Recorded Future...")

            if api_statuses and len(api_statuses) == len(active_statuses):
                try:
                    data = self.client.search_playbook_alerts(
                        categories=categories,
                        statuses=api_statuses,
                        limit=limit,
                        **extra_kwargs,
                    )
                except RecordedFutureError as exc:
                    if exc.status_code not in (400, 422):
                        raise
                    data = self.client.search_playbook_alerts(
                        categories=categories, limit=limit
                    )
            else:
                try:
                    data = self.client.search_playbook_alerts(
                        categories=categories, limit=limit, **extra_kwargs
                    )
                except RecordedFutureError as exc:
                    if exc.status_code not in (400, 422) or not extra_kwargs:
                        raise
                    data = self.client.search_playbook_alerts(
                        categories=categories, limit=limit
                    )
            raw_items, total = extract_playbook_alerts(data)
            normalized = [normalize_playbook_alert(item) for item in raw_items]

            def _merge_pb_det(entry: dict[str, Any], det: dict[str, Any]) -> None:
                norm_det = dict(normalize_playbook_alert(det))
                if norm_det.get("category") == "-" and entry.get("category"):
                    norm_det["category"] = entry["category"]
                if not det.get("title") and entry.get("title"):
                    norm_det["title"] = entry["title"]
                for state_k in ("status", "priority", "updated", "assignee"):
                    if entry.get(state_k) not in ("", None, "-"):
                        norm_det[state_k] = entry[state_k]
                entry.update(norm_det)

            cache = getattr(self.app, "alert_cache", None)
            reusable_pb_details: dict[str, dict[str, Any]] = {}
            stale_pb_ids: set[str] = set()
            if cache is not None:
                pb_entry = cache.get(CACHE_SOURCE_RF_PLAYBOOK)
                raw_pb_details = (
                    pb_entry.meta.get("details")
                    if pb_entry is not None and isinstance(pb_entry.meta.get("details"), dict)
                    else {}
                )
                for item in normalized:
                    aid = str(item.get("id") or "").strip()
                    det = raw_pb_details.get(aid) if aid else None
                    if isinstance(det, dict) and not is_playbook_detail_stale(item, det):
                        reusable_pb_details[aid] = det
                        _merge_pb_det(item, det)
                    elif aid:
                        stale_pb_ids.add(aid)

            def _apply() -> tuple[list[dict[str, Any]], int] | None:
                if seq != self._request_seq:
                    return None
                get_prepared = getattr(cache, "get_prepared_image", None)
                for item in normalized:
                    aid = str(item.get("id") or "").strip()
                    if not aid:
                        continue
                    key = ("playbook", aid)
                    if aid in reusable_pb_details:
                        self._detail_cache[key] = reusable_pb_details[aid]
                        self._auto_enriched_keys.add(key)
                    elif aid in stale_pb_ids or key in self._detail_cache:
                        ui_det = self._detail_cache.get(key)
                        if isinstance(ui_det, dict) and not is_playbook_detail_stale(item, ui_det):
                            _merge_pb_det(item, ui_det)
                            self._auto_enriched_keys.add(key)
                        else:
                            self._detail_cache.pop(key, None)
                            self._auto_enriched_keys.discard(key)
                    if callable(get_prepared):
                        eff_cat = str(item.get("category") or "domain_abuse")
                        for sid in item.get("screenshot_ids") or []:
                            sid_s = str(sid)
                            img_tuple = (eff_cat, aid, sid_s)
                            if img_tuple not in self._image_cache:
                                prep = get_prepared(f"{eff_cat}__{aid}__{sid_s}")
                                if isinstance(prep, dict) and prep.get("decoded") is not None:
                                    self._image_cache[img_tuple] = prep
                self._datasets["playbook"] = normalized
                self._dataset_totals["playbook"] = total
                self._active_mode = "playbook"
                self._refresh_assignee_options()
                self._render_view(schedule_auto_enrich=False)
                return self._claim_visible_enrichment_targets("playbook")

            enrich_info = self.run_on_ui(_apply)
            if seq != self._request_seq or self.is_app_shutting_down():
                return
            self.set_status(f"Loaded {len(normalized)} Playbook Alert(s).")
            if enrich_info:
                targets, enrich_seq = enrich_info
                if targets:
                    self._run_auto_enrich_sync("playbook", targets, enrich_seq)
        except Exception as exc:
            self.report_error("Playbook Alerts Search", exc)

    @work(thread=True, exit_on_error=False)
    def _fetch_playbook_detail_worker(self, category: str, alert_id: str) -> None:
        try:
            self.set_status(f"Fetching Playbook Alert detail ({category}) for {alert_id}...")
            try:
                resp = self.client.get_playbook_alert(category, alert_id)
            except ValueError:
                resp = self.client.get_playbook_alert_preview(alert_id)
            except RecordedFutureError as exc:
                if exc.status_code == 404:
                    resp = self.client.get_playbook_alert_preview(alert_id)
                else:
                    raise

            detail = resp.get("data") if isinstance(resp.get("data"), dict) else resp
            if not isinstance(detail, dict):
                detail = resp
            if (
                isinstance(detail, dict)
                and not detail.get("category")
                and category
                and category != "-"
            ):
                detail = {**detail, "category": category}
            norm = normalize_playbook_alert(detail)
            cache = getattr(self.app, "alert_cache", None)
            if cache is not None and hasattr(cache, "update_cached_item") and isinstance(detail, dict):
                pb_updates = {
                    k: v
                    for k, v in norm.items()
                    if v not in ("", None, "-", [], 0) or k == "raw"
                }
                cache.update_cached_item(
                    CACHE_SOURCE_RF_PLAYBOOK,
                    alert_id,
                    item_updates=pb_updates,
                    detail=detail,
                )
            effective_cat = str(
                norm.get("category")
                if norm.get("category") and norm.get("category") != "-"
                else (category if category and category != "-" else "domain_abuse")
            )
            sc_ids = [str(s) for s in (norm.get("screenshot_ids") or []) if s][:4]
            to_fetch = [
                sid
                for sid in sc_ids
                if (effective_cat, alert_id, sid) not in self._image_cache
                or self._image_cache[(effective_cat, alert_id, sid)].get("error")
            ]

            def _apply() -> None:
                self._last_error_payload = None
                self._detail_cache[("playbook", alert_id)] = detail
                for sid in to_fetch:
                    self._image_cache[(effective_cat, alert_id, sid)] = {"loading": True}
                for entry in self._datasets.get("playbook", []):
                    if str(entry.get("id") or "") == alert_id:
                        updated_norm = dict(norm)
                        if updated_norm.get("category") == "-" and entry.get("category"):
                            updated_norm["category"] = entry["category"]
                        if (
                            isinstance(detail, dict)
                            and not detail.get("title")
                            and entry.get("title")
                        ):
                            updated_norm["title"] = entry["title"]
                        entry.update(updated_norm)
                if self._active_mode == "playbook":
                    self._render_view(preserve_id=alert_id)

            self.run_on_ui(_apply)

            if not to_fetch:
                self.set_status(f"Loaded Playbook Alert panels for {alert_id}.")
                return

            loaded_count = 0
            for idx, sid in enumerate(to_fetch, start=1):
                if self.is_app_shutting_down():
                    return
                self.set_status(
                    f"Downloading Playbook Alert screenshot {idx}/{len(to_fetch)} for {alert_id}..."
                )
                try:
                    raw_bytes = self.client.get_playbook_alert_image(
                        effective_cat, alert_id, sid
                    )
                    if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) <= 8:
                        self._image_cache[(effective_cat, alert_id, sid)] = {
                            "error": "Preview image bytes not available"
                        }
                    else:
                        payload_bytes = bytes(raw_bytes)
                        prepared = prepare_image_cache_entry(payload_bytes)
                        self._image_cache[(effective_cat, alert_id, sid)] = prepared
                        cache = getattr(self.app, "alert_cache", None)
                        if cache is not None:
                            img_key = f"{effective_cat}__{alert_id}__{sid}"
                            cache.put_image_bytes(img_key, payload_bytes)
                            if hasattr(cache, "put_prepared_image"):
                                cache.put_prepared_image(img_key, prepared)
                        loaded_count += 1
                except Exception as img_exc:
                    self._image_cache[(effective_cat, alert_id, sid)] = {
                        "error": self.format_exception(img_exc)
                    }

            def _refresh_images() -> None:
                if self._active_mode != "playbook":
                    return
                sel = self._get_selected_item()
                if sel is not None and str(sel.get("id") or "") == alert_id:
                    self._render_detail_panel()

            self.run_on_ui(_refresh_images)
            self.set_status(
                f"Loaded Playbook Alert panels & {loaded_count}/{len(to_fetch)} screenshot(s) for {alert_id}."
            )
        except Exception as exc:
            self.report_error("Playbook Alert Detail", exc)

    @on(Button.Pressed, "#rf-cases-btn")
    def handle_cases(self) -> None:
        limit = self._parse_limit(20)
        if limit is None:
            return
        statuses = list(self._selected_statuses)
        filters = self._current_server_filter_snapshot()
        self._auto_enriched_keys = {k for k in self._auto_enriched_keys if k[0] != "cases"}
        self._enrich_seq += 1
        self._request_seq += 1
        self._cases_worker(limit, self._request_seq, statuses=statuses, filters=filters)

    @work(thread=True, exit_on_error=False)
    def _cases_worker(
        self,
        limit: int,
        seq: int,
        statuses: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> None:
        try:
            active_statuses = list(statuses or [])
            f = filters or {}
            extra_kwargs: dict[str, Any] = {}
            case_range = build_case_date_range(
                str(f.get("timeframe") or "any"),
                date_from=str(f.get("date_from") or ""),
                date_to=str(f.get("date_to") or ""),
            )
            if case_range:
                if str(f.get("time_field") or "auto") == "created":
                    extra_kwargs["created"] = case_range
                else:
                    extra_kwargs["modified"] = case_range
            case_priorities = map_priority_for_cases(str(f.get("priority") or "any"))
            if case_priorities:
                extra_kwargs["priorities"] = case_priorities
            assignee_val = str(f.get("assignee") or "any")
            if assignee_val.lower() not in _BASE_ASSIGNEE_VALUES:
                extra_kwargs["assignees"] = [assignee_val]
            if str(f.get("sort_by") or "") == "oldest":
                extra_kwargs["direction"] = "asc"

            if active_statuses:
                self.set_status(
                    f"Loading Cases (statuses: {', '.join(active_statuses)})..."
                )
                try:
                    data = self.client.search_cases(
                        statuses=active_statuses, limit=limit, **extra_kwargs
                    )
                except RecordedFutureError as exc:
                    if exc.status_code not in (400, 422):
                        raise
                    data = self.client.search_cases(limit=limit)
            else:
                self.set_status(f"Loading up to {limit} Case(s)...")
                try:
                    data = self.client.search_cases(limit=limit, **extra_kwargs)
                except RecordedFutureError as exc:
                    if exc.status_code not in (400, 422) or not extra_kwargs:
                        raise
                    data = self.client.search_cases(limit=limit)
            raw_items, total = extract_cases(data)
            normalized = [normalize_case(item) for item in raw_items]

            def _apply() -> tuple[list[dict[str, Any]], int] | None:
                if seq != self._request_seq:
                    return None
                self._datasets["cases"] = normalized
                self._dataset_totals["cases"] = total
                self._active_mode = "cases"
                self._refresh_assignee_options()
                self._render_view(schedule_auto_enrich=False)
                return self._claim_visible_enrichment_targets("cases")

            enrich_info = self.run_on_ui(_apply)
            if seq != self._request_seq or self.is_app_shutting_down():
                return
            self.set_status(f"Loaded {len(normalized)} Case(s).")
            if enrich_info:
                targets, enrich_seq = enrich_info
                if targets:
                    self._run_auto_enrich_sync("cases", targets, enrich_seq)
        except Exception as exc:
            self.report_error("Cases Search", exc)

    @work(thread=True, exit_on_error=False)
    def _fetch_case_detail_worker(self, case_id: str) -> None:
        try:
            self.set_status(f"Fetching Case detail for {case_id}...")
            resp = self.client.lookup_cases([case_id])
            data_list = resp.get("data") if isinstance(resp.get("data"), list) else []
            detail = (
                data_list[0]
                if data_list and isinstance(data_list[0], dict)
                else (resp if isinstance(resp, dict) else {})
            )
            norm = normalize_case(detail)

            def _apply() -> None:
                self._detail_cache[("cases", case_id)] = detail
                for entry in self._datasets.get("cases", []):
                    if str(entry.get("id") or "") == case_id:
                        entry.update(norm)
                if self._active_mode == "cases":
                    self._render_view(preserve_id=case_id)

            self.run_on_ui(_apply)
            self.set_status(f"Loaded full detail for Case {case_id}.")
        except Exception as exc:
            self.report_error("Case Detail", exc)

    @on(Button.Pressed, "#rf-sandbox-btn")
    def handle_sandbox(self) -> None:
        query = self.query_one("#rf-query-input", Input).value.strip()
        limit = self._parse_limit(20)
        if limit is None:
            return
        if not query:
            self.set_status("Enter a Sandbox search query first.")
            return
        self._request_seq += 1
        self._sandbox_worker(query, limit, self._request_seq)

    @work(thread=True, exit_on_error=False)
    def _sandbox_worker(self, query: str, limit: int, seq: int) -> None:
        try:
            self.set_status(f"Searching Sandbox for '{query}'...")
            data = self.client.sandbox_search(query, limit=limit)
            raw_samples = extract_sandbox_samples(data)
            normalized = [normalize_sandbox_sample(s) for s in raw_samples]

            def _apply() -> None:
                if seq != self._request_seq:
                    return
                self._datasets["sandbox"] = normalized
                self._dataset_totals["sandbox"] = len(normalized)
                self._active_mode = "sandbox"
                self._render_view()

            self.run_on_ui(_apply)
            self.set_status(f"Sandbox search returned {len(normalized)} sample(s).")
        except Exception as exc:
            self.report_error("Sandbox Search", exc)

    @work(thread=True, exit_on_error=False)
    def _fetch_sandbox_overview_worker(self, sample_id: str) -> None:
        try:
            self.set_status(f"Fetching Sandbox overview for {sample_id}...")
            try:
                detail = self.client.sandbox_get_overview(sample_id)
            except RecordedFutureError:
                detail = self.client.sandbox_get_sample(sample_id)

            def _apply() -> None:
                self._last_error_payload = None
                self._detail_cache[("sandbox", sample_id)] = detail
                if self._active_mode == "sandbox":
                    self._render_detail_panel()

            self.run_on_ui(_apply)
            self.set_status(f"Loaded Sandbox overview for {sample_id}.")
        except Exception as exc:
            self.report_error("Sandbox Overview", exc)
