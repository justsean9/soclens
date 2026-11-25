"""Brand logo extraction, hashing, state viewer, and continuous sync pane."""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar

from rich.text import Text
from textual import events, on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.widgets import (
    Button,
    Collapsible,
    DataTable,
    Input,
    Select,
    SelectionList,
    Static,
)
from textual.widgets.selection_list import Selection

from soclens.client import RecordedFutureClient
from soclens.logos.brand_sync import (
    BRAND_SYNC_ISSUE_CATEGORIES,
    BRAND_SYNC_ISSUE_LABELS,
    DEFAULT_STATE_FILENAME,
    BrandSyncIssuesReport,
    analyze_brand_sync_issues,
    calculate_brand_sync_delta,
    execute_domain_brand_sync,
    filter_brand_issues,
    get_domains_from_watchlist,
    load_brand_sync_state,
    resolve_state_path,
    run_continuous_brand_sync,
    sort_brand_domains,
    sort_brand_rows,
)
from soclens.logos.extractor import load_domains_file
from soclens.tui.screens.base import (
    BaseSocPane,
    DoubleClickDataTable,
    extract_table_row_text,
)

BRAND_HASH_FETCH_TYPES: tuple[str, ...] = ("hash", "brand", "domain")
_HASH_PRIORITY_KEYWORDS: tuple[str, ...] = ("brand", "image", "logo", "icon")
_BRAND_HASH_KEYWORDS: tuple[str, ...] = ("image", "logo", "hash", "icon")

_BRAND_COLUMN_SPECS: tuple[tuple[str, float, int], ...] = (
    ("domain", 0.26, 14),
    ("status", 0.18, 11),
    ("hashes", 0.10, 6),
    ("detail", 0.46, 20),
)
_BRAND_COLUMN_LABELS: dict[str, str] = {
    "domain": "Domain / Key",
    "status": "Status",
    "hashes": "Hashes",
    "detail": "Detail / Reason / SHA-256",
}
_BRAND_SORT_CYCLE: tuple[str, ...] = (
    "none",
    "domain",
    "status",
    "hashes",
    "failures",
    "detail",
    "severity",
)
_BRAND_SORT_DISPLAY: dict[str, str] = {
    "none": "Default",
    "domain": "Domain",
    "status": "Status",
    "hashes": "Hashes",
    "failures": "Failures",
    "detail": "Detail",
    "severity": "Severity",
}
_DOMAIN_SORT_CYCLE: tuple[tuple[str, bool, str], ...] = (
    ("domain", False, "A-Z ^"),
    ("domain", True, "Z-A v"),
    ("hashes", False, "0-Hash"),
    ("failures", True, "Errors"),
    ("selected", True, "Checked"),
)
_DASHBOARD_VIEW_OPTIONS: list[tuple[str, str]] = [
    ("View: Local Sync State", "state"),
    ("View: Sync / Validate Delta", "delta"),
    ("View: Brand List Hashes", "hashes"),
    ("Issue: Missing Hashes (0)", "issue:missing_hashes"),
    ("Issue: Zero Hashes (No Error)", "issue:silent_zero_hashes"),
    ("Issue: Domain / HTTP / Bot Errors", "issue:domain_errors"),
    ("Issue: Image Fetch / Validation Errors", "issue:image_errors"),
    ("Issue: Repeated Failures (Grace)", "issue:failing_grace"),
    ("Issue: Shared / Duplicate Hashes", "issue:duplicate_hashes"),
    ("Issue: All Issues", "issue:all"),
]


def filter_brand_hash_lists(raw_lists: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return candidate Brand Hash Watchlists ordered with ``hash`` brand lists first."""
    seen: set[str] = set()
    ranked: list[tuple[int, str, str, dict[str, Any]]] = []

    for item in raw_lists:
        if not isinstance(item, Mapping):
            continue
        lid = str(item.get("id") or "").strip()
        if not lid or lid in seen:
            continue
        seen.add(lid)

        ltype = str(item.get("type") or "").strip().lower()
        lname = str(item.get("name") or "").strip()
        lname_lower = lname.lower()

        if ltype == "hash" and any(kw in lname_lower for kw in _HASH_PRIORITY_KEYWORDS):
            tier = 0
        elif ltype == "hash":
            tier = 1
        elif ltype == "brand" and any(kw in lname_lower for kw in _BRAND_HASH_KEYWORDS):
            tier = 2
        else:
            continue

        ranked.append((tier, lname_lower, lid.lower(), dict(item)))

    ranked.sort(key=lambda row: (row[0], row[1], row[2]))
    return [row[3] for row in ranked]


def filter_domain_watchlists(raw_lists: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return ``domain`` Watchlists sorted alphabetically by name and ID."""
    seen: set[str] = set()
    ranked: list[tuple[str, str, dict[str, Any]]] = []

    for item in raw_lists:
        if not isinstance(item, Mapping):
            continue
        lid = str(item.get("id") or "").strip()
        if not lid or lid in seen:
            continue
        seen.add(lid)

        ltype = str(item.get("type") or "").strip().lower()
        if ltype != "domain":
            continue

        lname = str(item.get("name") or "").strip()
        ranked.append((lname.lower(), lid.lower(), dict(item)))

    ranked.sort(key=lambda row: (row[0], row[1]))
    return [row[2] for row in ranked]


def format_watchlist_option_label(item: Mapping[str, Any]) -> str:
    """Build a concise ASCII Select option label for a Recorded Future watchlist."""
    lid = str(item.get("id") or "").strip()
    lname = str(item.get("name") or "").strip()
    ltype = str(item.get("type") or "").strip().lower()
    base = f"{lname} ({lid})" if lname else lid
    return f"{base} [{ltype}]" if ltype else base


class _RightClickSelectionList(SelectionList[str]):
    """SelectionList that emits ``DomainRightClicked`` without toggling on right-click."""

    class DomainRightClicked(Message):
        """Posted when a user right-clicks inside the domain checklist."""

        def __init__(
            self,
            selection_list: _RightClickSelectionList,
            domain: str,
            screen_x: int,
            screen_y: int,
        ) -> None:
            self.selection_list: _RightClickSelectionList = selection_list
            self.domain: str = domain
            self.screen_x: int = screen_x
            self.screen_y: int = screen_y
            super().__init__()

        @property
        def control(self) -> _RightClickSelectionList:
            return self.selection_list

    async def _on_click(self, event: events.Click) -> None:
        if event.button == 3:
            event.prevent_default()
            event.stop()
            self.focus()
            clicked_option: int | None = event.style.meta.get("option")
            domain = ""
            if clicked_option is not None and 0 <= clicked_option < self.option_count:
                self.highlighted = clicked_option
                opt = self.get_option_at_index(clicked_option)
                domain = str(getattr(opt, "value", "") or "").strip().lower()
            self.post_message(
                _RightClickSelectionList.DomainRightClicked(
                    self,
                    domain,
                    event.screen_x,
                    event.screen_y,
                )
            )
            return
        await super()._on_click(event)


class BrandLogosPane(BaseSocPane):
    """Domain-to-Brand-Logo extraction, hashing, delta sync, and continuous automation."""

    STATUS_ID = "brand-status"
    LOG_ID = ""
    LOG_SOURCE = "brand_sync"

    DEFAULT_CSS: ClassVar[str] = """
    BrandLogosPane #brand-domains-toolbar > #brand-domains-header,
    BrandLogosPane #brand-results-toolbar > #brand-table-header {
        width: 1fr;
        height: 1;
    }
    BrandLogosPane #brand-domain-sort-btn {
        min-width: 8;
        margin-left: 1;
    }
    BrandLogosPane #brand-dashboard-select {
        width: 24;
    }
    BrandLogosPane #brand-issues-btn,
    BrandLogosPane #brand-select-issues-btn {
        min-width: 10;
    }
    BrandLogosPane #brand-results-pane > #brand-table {
        height: 1fr;
        min-height: 5;
    }
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("f6", "cycle_table_sort", "Sort"),
        Binding("r", "reload_brand_lists", "Reload Lists"),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._watch_stop_event = threading.Event()
        self._tables_ready = False
        self._brand_lists: list[dict[str, Any]] = []
        self._brand_list_by_id: dict[str, dict[str, Any]] = {}
        self._domain_lists: list[dict[str, Any]] = []
        self._domain_list_by_id: dict[str, dict[str, Any]] = {}
        self._watchlist_domains: list[str] = []
        self._visible_domains: list[str] = []
        self._selected_domains: set[str] = set()
        self._loaded_domain_source_id: str = ""
        self._auto_load_started: bool = False
        self._pending_activation: bool = False
        self._hashes_request_seq: int = 0
        self._domains_request_seq: int = 0
        self._domain_sort_idx: int = 0
        self._table_sort_by: str = "none"
        self._table_sort_desc: bool = False
        self._active_view: str = "state"
        self._last_non_issue_view: str = "state"
        self._syncing_dashboard_select: bool = False
        self._state_rows: list[dict[str, Any]] = []
        self._delta_rows: list[dict[str, Any]] = []
        self._hash_rows: list[dict[str, Any]] = []
        self._visible_result_rows: list[dict[str, Any]] = []
        self._state_header_text: str = "Local Sync State (brand_sync_state.json)"
        self._delta_header_text: str = "Discovered Logos & Sync Delta"
        self._hashes_header_text: str = "Brand List Hashes"
        self._last_state: dict[str, Any] = {}
        self._last_existing_entries: list[dict[str, Any]] | None = None
        self._last_delta_context: dict[str, Any] | None = None
        self._issues_report: BrandSyncIssuesReport = analyze_brand_sync_issues()

    def compose(self) -> ComposeResult:
        yield Static("Brand Logo Extraction, Hashing & Continuous Sync", classes="pane-title")
        yield Static(
            "Ready. Auto-loading brand hash and domain watchlists...",
            id="brand-status",
            classes="status-bar",
            markup=False,
        )

        with Horizontal(classes="action-row toolbar-row"):
            yield Select[str](
                [],
                prompt="Select Brand Hash List...",
                allow_blank=True,
                id="brand-list-select",
                compact=True,
            )
            yield Input(
                placeholder="List ID (e.g. report:abc123)",
                id="brand-list-id",
                compact=True,
            )
            yield Button("Reload Lists", id="brand-reload-lists-btn", compact=True)

        with Horizontal(classes="action-row toolbar-row"):
            yield Select[str](
                [],
                prompt="Select Domain Watchlist...",
                allow_blank=True,
                id="brand-source-list-select",
                compact=True,
            )
            yield Input(
                placeholder="Domain List ID (e.g. report:xyz789)",
                id="brand-source-list",
                compact=True,
            )
            yield Button("Load Domains", id="brand-load-domains-btn", compact=True)

        with Horizontal(classes="action-row toolbar-row"):
            yield Button(
                "Validate (Dry-Run)",
                id="brand-validate-btn",
                variant="primary",
                compact=True,
            )
            yield Button("Sync Logos", id="brand-sync-btn", compact=True)
            yield Button("View Hashes", id="brand-view-hashes-btn", compact=True)
            yield Button("Sync State", id="brand-state-btn", compact=True)
            yield Button("View Logs", id="brand-view-logs-btn", compact=True)

        with Collapsible(
            title="Advanced Sources, Manual Override & Continuous Watch",
            collapsed=True,
            collapsed_symbol=">",
            expanded_symbol="v",
            id="brand-advanced-collapsible",
        ):
            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    placeholder="Manual domains override (comma-separated, optional)",
                    id="brand-domains",
                    compact=True,
                )
                yield Input(
                    placeholder="Domains file / CSV path (optional)",
                    id="brand-domains-file",
                    compact=True,
                )
            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    placeholder="Ignored hashes file (default: ignored_hashes.txt)",
                    id="brand-ignore-file",
                    compact=True,
                )
                yield Input(
                    value="3600",
                    placeholder="Interval seconds (limit/delay)",
                    id="brand-interval",
                    compact=True,
                )
                yield Input(
                    value="1",
                    placeholder="Max watch runs (limit)",
                    id="brand-max-runs",
                    compact=True,
                )
            with Horizontal(classes="action-row toolbar-row"):
                yield Button("Start Watch", id="brand-watch-start-btn", compact=True)
                yield Button(
                    "Stop Watch",
                    id="brand-watch-stop-btn",
                    variant="warning",
                    compact=True,
                )

        with Container(id="brand-workspace", classes="split-workspace"):
            with Vertical(id="brand-domains-pane", classes="table-pane"):
                with Horizontal(id="brand-domains-toolbar", classes="detail-toolbar"):
                    yield Static(
                        "Watchlist Domains (none loaded)",
                        id="brand-domains-header",
                        classes="section-label",
                        markup=False,
                    )
                    yield Button("A-Z ^", id="brand-domain-sort-btn", compact=True)
                with Horizontal(classes="action-row filter-bar"):
                    yield Button("Select All", id="brand-domains-all-btn", compact=True)
                    yield Button("Deselect All", id="brand-domains-none-btn", compact=True)
                    yield Input(
                        placeholder="Filter domains...",
                        id="brand-domain-filter",
                        compact=True,
                    )
                yield _RightClickSelectionList(id="brand-domain-selection", compact=True)
            with Vertical(id="brand-results-pane", classes="table-pane"):
                yield Static(
                    "Brand Health: Load state, domains, or run Validate to inspect issues.",
                    id="brand-issues-summary",
                    classes="rf-summary-bar",
                    markup=False,
                )
                with Horizontal(id="brand-results-toolbar", classes="detail-toolbar"):
                    yield Static(
                        "Discovered Logos & Sync State",
                        id="brand-table-header",
                        classes="section-label",
                        markup=False,
                    )
                    yield Button("Sort: Default", id="brand-sort-cycle-btn", compact=True)
                    yield Button("Asc ^", id="brand-sort-dir-btn", compact=True)
                with Horizontal(id="brand-dashboard-bar", classes="action-row filter-bar"):
                    yield Select[str](
                        list(_DASHBOARD_VIEW_OPTIONS),
                        allow_blank=False,
                        value="state",
                        id="brand-dashboard-select",
                        compact=True,
                    )
                    yield Input(
                        placeholder="Filter results/issues...",
                        id="brand-results-filter",
                        compact=True,
                    )
                    yield Button("Issues (0)", id="brand-issues-btn", compact=True)
                    yield Button("Use Issues", id="brand-select-issues-btn", compact=True)
                yield DoubleClickDataTable(id="brand-table")

    def on_mount(self) -> None:
        table = self.query_one("#brand-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column(_BRAND_COLUMN_LABELS["domain"], key="domain")
        table.add_column(_BRAND_COLUMN_LABELS["status"], key="status")
        table.add_column(_BRAND_COLUMN_LABELS["hashes"], key="hashes")
        table.add_column(_BRAND_COLUMN_LABELS["detail"], key="detail")
        self._tables_ready = True
        self._load_state_snapshot()
        self._update_responsive_layout()
        if self._pending_activation or getattr(self.app, "initial_tab", "") == "tab-brand-logos":
            self._pending_activation = False
            self._maybe_auto_load()

    def on_resize(self) -> None:
        if self._tables_ready:
            self._update_responsive_layout()

    def on_tab_activated(self) -> None:
        if not self._tables_ready:
            self._pending_activation = True
            return
        self._update_responsive_layout()
        self._maybe_auto_load()

    def _update_responsive_layout(self) -> None:
        try:
            workspace = self.query_one("#brand-workspace", Container)
            if self.size.width >= 130:
                workspace.add_class("split-horizontal")
            else:
                workspace.remove_class("split-horizontal")
        except Exception:
            pass
        self.call_after_refresh(self._fit_tables)

    def _fit_tables(self) -> None:
        if self.is_app_shutting_down() or not self._tables_ready:
            return
        try:
            self.fit_table_columns(
                self.query_one("#brand-table", DataTable),
                _BRAND_COLUMN_SPECS,
            )
        except Exception:
            pass

    def on_unmount(self) -> None:
        self._watch_stop_event.set()

    def on_settings_updated(self) -> None:
        if not self._brand_lists:
            self._auto_load_started = False
            self.set_status("Settings updated. Open Brand Logos or click 'Reload Lists'.")

    def _maybe_auto_load(self) -> None:
        if self._auto_load_started:
            return
        self._auto_load_started = True
        if isinstance(self.client, RecordedFutureClient) and not self.client.api_token:
            self.set_status(
                "RF_API_TOKEN not configured. Open Settings (0 / F10) or set RF_API_TOKEN and click 'Reload Lists'."
            )
            return
        self._load_brand_lists_worker()

    def action_reload_brand_lists(self) -> None:
        """Reload brand hash lists and domain source lists from Recorded Future."""
        self.handle_reload_brand_lists()

    @on(Button.Pressed, "#brand-reload-lists-btn")
    def handle_reload_brand_lists(self) -> None:
        if isinstance(self.client, RecordedFutureClient) and not self.client.api_token:
            self.set_status(
                "RF_API_TOKEN not configured. Open Settings (0 / F10) or set RF_API_TOKEN and click 'Reload Lists'."
            )
            return
        self._load_brand_lists_worker()

    @work(thread=True, exit_on_error=False, exclusive=True, group="brand-lists")
    def _load_brand_lists_worker(self) -> None:
        try:
            if self.is_app_shutting_down():
                return
            self.set_status("Loading brand hash lists from Recorded Future...")
            raw_lists = self.client.get_watchlists(list_types=BRAND_HASH_FETCH_TYPES)
            if self.is_app_shutting_down():
                return
            lists_data = list(raw_lists) if isinstance(raw_lists, list) else []
            brand_lists = filter_brand_hash_lists(lists_data)
            domain_lists = filter_domain_watchlists(lists_data)

            state = load_brand_sync_state(
                resolve_state_path(DEFAULT_STATE_FILENAME, self.workspace_dir)
            )
            raw_state_id = state.get("list_id") if isinstance(state, dict) else ""
            preferred_list_id = str(raw_state_id).strip() if raw_state_id else ""

            self.run_on_ui(
                self._apply_watchlists_to_ui,
                brand_lists,
                domain_lists,
                preferred_list_id=preferred_list_id,
            )
        except Exception as exc:
            self.report_error("Load Brand Hash Lists", exc)

    def _apply_watchlists_to_ui(
        self,
        brand_lists: list[dict[str, Any]],
        domain_lists: list[dict[str, Any]],
        *,
        preferred_list_id: str = "",
    ) -> None:
        self._brand_lists = list(brand_lists)
        self._brand_list_by_id = {
            str(item["id"]): item for item in brand_lists if item.get("id")
        }
        self._domain_lists = list(domain_lists)
        self._domain_list_by_id = {
            str(item["id"]): item for item in domain_lists if item.get("id")
        }

        brand_select = self.query_one("#brand-list-select", Select)
        brand_input = self.query_one("#brand-list-id", Input)
        brand_options = [
            (format_watchlist_option_label(item), str(item["id"]))
            for item in brand_lists
        ]

        active_id = ""
        with brand_select.prevent(Select.Changed), brand_input.prevent(Input.Changed):
            brand_select.prompt = (
                "Select Brand Hash List..." if brand_options else "No brand hash lists found"
            )
            brand_select.set_options(brand_options)
            existing_id = brand_input.value.strip()
            if existing_id:
                active_id = existing_id
                if existing_id in self._brand_list_by_id:
                    brand_select.value = existing_id
                else:
                    brand_select.value = Select.NULL
            elif brand_lists:
                chosen_id = (
                    preferred_list_id
                    if preferred_list_id in self._brand_list_by_id
                    else str(brand_lists[0]["id"])
                )
                brand_select.value = chosen_id
                brand_input.value = chosen_id
                active_id = chosen_id
            else:
                brand_select.value = Select.NULL

        src_select = self.query_one("#brand-source-list-select", Select)
        src_input = self.query_one("#brand-source-list", Input)
        domain_options = [
            (format_watchlist_option_label(item), str(item["id"]))
            for item in domain_lists
        ]

        active_src_id = ""
        with src_select.prevent(Select.Changed), src_input.prevent(Input.Changed):
            src_select.prompt = (
                "Select Domain Watchlist..."
                if domain_options
                else "No domain watchlists found"
            )
            src_select.set_options(domain_options)
            existing_src = src_input.value.strip()
            if existing_src:
                active_src_id = existing_src
                if existing_src in self._domain_list_by_id:
                    src_select.value = existing_src
                else:
                    src_select.value = Select.NULL
            elif domain_lists:
                chosen_src = str(domain_lists[0]["id"])
                src_select.value = chosen_src
                src_input.value = chosen_src
                active_src_id = chosen_src
            else:
                src_select.value = Select.NULL

        if brand_lists:
            if active_id and active_id in self._brand_list_by_id:
                active_name = str(self._brand_list_by_id[active_id].get("name") or active_id)
                msg = (
                    f"Loaded {len(brand_lists)} brand hash list(s). "
                    f"Active: {active_name} ({active_id})"
                )
            elif active_id:
                msg = f"Loaded {len(brand_lists)} brand hash list(s). Active ID: {active_id}"
            else:
                msg = f"Loaded {len(brand_lists)} brand hash list(s)."
        else:
            msg = "No brand hash lists found. Enter a List ID manually or click Reload Lists."

        self.set_status(msg)
        self.append_log(msg)

        if active_src_id and (
            active_src_id != self._loaded_domain_source_id or not self._watchlist_domains
        ):
            self._start_load_watchlist_domains(active_src_id)

    @on(Select.Changed, "#brand-list-select")
    def handle_brand_list_selected(self, event: Select.Changed) -> None:
        brand_input = self.query_one("#brand-list-id", Input)
        with brand_input.prevent(Input.Changed):
            if isinstance(event.value, str) and event.value.strip():
                list_id = event.value.strip()
                brand_input.value = list_id
                meta = self._brand_list_by_id.get(list_id, {})
                name = str(meta.get("name") or "").strip()
                ltype = str(meta.get("type") or "").strip().lower()
                label = f"{name} ({list_id})" if name else list_id
                if ltype:
                    label = f"{label} [{ltype}]"
                self.set_status(f"Selected brand hash list: {label}")
            else:
                brand_input.value = ""
                self.set_status("Cleared Brand Hash List selection.")

    @on(Input.Changed, "#brand-list-id")
    def handle_brand_list_input_changed(self, event: Input.Changed) -> None:
        list_id = event.value.strip()
        brand_select = self.query_one("#brand-list-select", Select)
        with brand_select.prevent(Select.Changed):
            if list_id and list_id in self._brand_list_by_id:
                brand_select.value = list_id
            else:
                brand_select.value = Select.NULL

    @on(Select.Changed, "#brand-source-list-select")
    def handle_source_list_selected(self, event: Select.Changed) -> None:
        src_input = self.query_one("#brand-source-list", Input)
        with src_input.prevent(Input.Changed):
            if isinstance(event.value, str) and event.value.strip():
                list_id = event.value.strip()
                src_input.value = list_id
                meta = self._domain_list_by_id.get(list_id, {})
                name = str(meta.get("name") or "").strip()
                label = f"{name} ({list_id})" if name else list_id
                self.set_status(f"Selected source domain list: {label}")
            else:
                src_input.value = ""
                list_id = ""

        if list_id:
            self._start_load_watchlist_domains(list_id)
        else:
            self._clear_watchlist_domains()
            self.set_status("Cleared source domain watchlist.")

    @on(Input.Changed, "#brand-source-list")
    def handle_source_list_input_changed(self, event: Input.Changed) -> None:
        list_id = event.value.strip()
        src_select = self.query_one("#brand-source-list-select", Select)
        with src_select.prevent(Select.Changed):
            if list_id and list_id in self._domain_list_by_id:
                src_select.value = list_id
            else:
                src_select.value = Select.NULL

    @on(Input.Submitted, "#brand-source-list")
    def handle_source_list_submitted(self) -> None:
        self.handle_load_watchlist_domains()

    @on(Button.Pressed, "#brand-load-domains-btn")
    def handle_load_watchlist_domains(self) -> None:
        list_id = self._resolve_source_list_id()
        if not list_id:
            self.set_status("Select or enter a Domain Watchlist ID first.")
            return
        self._start_load_watchlist_domains(list_id)

    def _start_load_watchlist_domains(self, list_id: str) -> None:
        clean_id = list_id.strip()
        if not clean_id:
            return
        self._domains_request_seq += 1
        seq = self._domains_request_seq
        self.query_one("#brand-domains-header", Static).update(
            f"Loading domains from {clean_id}..."
        )
        self._load_watchlist_domains_worker(clean_id, seq)

    @work(thread=True, exit_on_error=False, exclusive=True, group="brand-domains")
    def _load_watchlist_domains_worker(self, list_id: str, request_seq: int) -> None:
        try:
            if self.is_app_shutting_down():
                return
            self.set_status(f"Loading domains from watchlist {list_id}...")
            with self.log_scope("brand_sync"):
                raw_domains = get_domains_from_watchlist(self.client, list_id)
            if self.is_app_shutting_down():
                return
            domains = sorted(
                {str(d).strip().lower() for d in raw_domains if str(d).strip()}
            )
            self.run_on_ui(self._apply_watchlist_domains_to_ui, list_id, domains, request_seq)
        except Exception as exc:
            def _mark_failed() -> None:
                if request_seq == self._domains_request_seq:
                    self.query_one("#brand-domains-header", Static).update(
                        "Watchlist Domains (load failed)"
                    )

            self.run_on_ui(_mark_failed)
            self.report_error("Load Watchlist Domains", exc)

    def _apply_watchlist_domains_to_ui(
        self, list_id: str, domains: list[str], request_seq: int
    ) -> None:
        if request_seq != self._domains_request_seq:
            return
        self._loaded_domain_source_id = list_id
        self._watchlist_domains = list(domains)
        self._selected_domains = set(domains)
        filter_input = self.query_one("#brand-domain-filter", Input)
        with filter_input.prevent(Input.Changed):
            filter_input.value = ""
        self._recompute_issues_report()
        self._render_domain_selection()
        if self._active_view.startswith("issue:"):
            self._render_results_table()

        list_name = str(self._domain_list_by_id.get(list_id, {}).get("name") or "").strip()
        label = f"{list_name} ({list_id})" if list_name and list_name != list_id else list_id
        if domains:
            msg = f"Loaded {len(domains)} domain(s) from {label} (all selected)."
        else:
            msg = f"No live domains found in {label}."
        self.set_status(msg)
        self.append_log(msg)

    def _clear_watchlist_domains(self) -> None:
        self._domains_request_seq += 1
        self._loaded_domain_source_id = ""
        self._watchlist_domains = []
        self._visible_domains = []
        self._selected_domains = set()
        sl = self.query_one("#brand-domain-selection", SelectionList)
        with sl.prevent(SelectionList.SelectedChanged):
            sl.clear_options()
        self.query_one("#brand-domains-header", Static).update(
            "Watchlist Domains (none selected)"
        )
        self._recompute_issues_report()
        if self._active_view.startswith("issue:"):
            self._render_results_table()

    def _render_domain_selection(self) -> None:
        query = self.query_one("#brand-domain-filter", Input).value.strip().lower()
        sort_field, sort_desc, sort_label = _DOMAIN_SORT_CYCLE[self._domain_sort_idx]
        state_domains = (
            self._last_state.get("domains")
            if isinstance(self._last_state.get("domains"), Mapping)
            else None
        )
        ordered = sort_brand_domains(
            self._watchlist_domains,
            sort_by=sort_field,
            descending=sort_desc,
            state_domains=state_domains,
            hash_counts=self._issues_report.domain_hash_counts,
            failure_counts=self._issues_report.domain_failure_counts,
            selected_domains=self._selected_domains,
        )
        visible = [dom for dom in ordered if not query or query in dom.lower()]
        self._visible_domains = visible
        sl = self.query_one("#brand-domain-selection", SelectionList)
        with sl.prevent(SelectionList.SelectedChanged):
            sl.clear_options()
            if visible:
                sl.add_options(
                    [Selection(dom, dom, dom in self._selected_domains) for dom in visible]
                )
        try:
            self.query_one("#brand-domain-sort-btn", Button).label = sort_label
        except Exception:
            pass
        self._update_domains_header()

    def _update_domains_header(self) -> None:
        header = self.query_one("#brand-domains-header", Static)
        total = len(self._watchlist_domains)
        if total == 0:
            if self._loaded_domain_source_id:
                header.update(f"Watchlist Domains ({self._loaded_domain_source_id}: 0 domains)")
            else:
                header.update("Watchlist Domains (none loaded)")
            return
        selected_count = len(self._selected_domains)
        query = self.query_one("#brand-domain-filter", Input).value.strip()
        if query:
            header.update(
                f"Watchlist Domains ({selected_count}/{total} selected, showing {len(self._visible_domains)})"
            )
        else:
            header.update(f"Watchlist Domains ({selected_count}/{total} selected)")

    @on(SelectionList.SelectedChanged, "#brand-domain-selection")
    def handle_domain_selection_changed(
        self, event: SelectionList.SelectedChanged[str]
    ) -> None:
        visible_set = set(self._visible_domains)
        checked_visible = {str(val) for val in event.selection_list.selected}
        self._selected_domains = (self._selected_domains - visible_set) | checked_visible
        self._update_domains_header()

    @on(Input.Changed, "#brand-domain-filter")
    def handle_domain_filter_changed(self) -> None:
        self._render_domain_selection()

    @on(Button.Pressed, "#brand-domains-all-btn")
    def handle_select_all_domains(self) -> None:
        if not self._watchlist_domains:
            self.set_status("No watchlist domains loaded.")
            return
        query = self.query_one("#brand-domain-filter", Input).value.strip()
        targets = self._visible_domains if query else self._watchlist_domains
        self._selected_domains.update(targets)
        sl = self.query_one("#brand-domain-selection", SelectionList)
        with sl.prevent(SelectionList.SelectedChanged):
            sl.select_all()
        self._update_domains_header()
        self.set_status(
            f"Selected {len(self._selected_domains)} of {len(self._watchlist_domains)} watchlist domain(s)."
        )

    @on(Button.Pressed, "#brand-domains-none-btn")
    def handle_deselect_all_domains(self) -> None:
        if not self._watchlist_domains:
            self.set_status("No watchlist domains loaded.")
            return
        query = self.query_one("#brand-domain-filter", Input).value.strip()
        targets = self._visible_domains if query else self._watchlist_domains
        self._selected_domains.difference_update(targets)
        sl = self.query_one("#brand-domain-selection", SelectionList)
        with sl.prevent(SelectionList.SelectedChanged):
            sl.deselect_all()
        self._update_domains_header()
        self.set_status(
            f"Selected {len(self._selected_domains)} of {len(self._watchlist_domains)} watchlist domain(s)."
        )

    def select_brand_list(
        self, list_id: str, *, list_name: str = "", list_type: str = ""
    ) -> None:
        """Select or inject a target Brand Hash List ID from another tab."""
        clean_id = list_id.strip()
        if not clean_id:
            return
        if clean_id not in self._brand_list_by_id:
            entry = {
                "id": clean_id,
                "name": list_name.strip() or clean_id,
                "type": list_type.strip().lower(),
            }
            self._brand_lists = [entry] + list(self._brand_lists)
            self._brand_list_by_id[clean_id] = entry
            brand_select = self.query_one("#brand-list-select", Select)
            options = [
                (format_watchlist_option_label(item), str(item["id"]))
                for item in self._brand_lists
            ]
            with brand_select.prevent(Select.Changed):
                brand_select.prompt = "Select Brand Hash List..."
                brand_select.set_options(options)

        brand_select = self.query_one("#brand-list-select", Select)
        brand_input = self.query_one("#brand-list-id", Input)
        with brand_select.prevent(Select.Changed), brand_input.prevent(Input.Changed):
            brand_select.value = clean_id
            brand_input.value = clean_id

        meta = self._brand_list_by_id.get(clean_id, {})
        resolved_name = str(meta.get("name") or list_name or "").strip()
        label = f"{resolved_name} ({clean_id})" if resolved_name and resolved_name != clean_id else clean_id
        self.set_status(f"Selected brand hash list: {label}")

    def select_source_domain_list(self, list_id: str, *, list_name: str = "") -> None:
        """Select or inject a source Domain Watchlist ID from another tab."""
        clean_id = list_id.strip()
        if not clean_id:
            return
        if clean_id not in self._domain_list_by_id:
            entry = {
                "id": clean_id,
                "name": list_name.strip() or clean_id,
                "type": "domain",
            }
            self._domain_lists = [entry] + list(self._domain_lists)
            self._domain_list_by_id[clean_id] = entry
            src_select = self.query_one("#brand-source-list-select", Select)
            options = [
                (format_watchlist_option_label(item), str(item["id"]))
                for item in self._domain_lists
            ]
            with src_select.prevent(Select.Changed):
                src_select.prompt = "Source Domain List (optional)..."
                src_select.set_options(options)

        src_select = self.query_one("#brand-source-list-select", Select)
        src_input = self.query_one("#brand-source-list", Input)
        with src_select.prevent(Select.Changed), src_input.prevent(Input.Changed):
            src_select.value = clean_id
            src_input.value = clean_id

        meta = self._domain_list_by_id.get(clean_id, {})
        resolved_name = str(meta.get("name") or list_name or "").strip()
        label = f"{resolved_name} ({clean_id})" if resolved_name and resolved_name != clean_id else clean_id
        self.set_status(f"Selected source domain list: {label}")
        self._start_load_watchlist_domains(clean_id)

    def _resolve_target_list_id(self) -> str:
        raw_input = self.query_one("#brand-list-id", Input).value.strip()
        if raw_input:
            return raw_input
        raw_select = self.query_one("#brand-list-select", Select).value
        if isinstance(raw_select, str) and raw_select.strip():
            return raw_select.strip()
        return ""

    def _resolve_source_list_id(self) -> str:
        raw_input = self.query_one("#brand-source-list", Input).value.strip()
        if raw_input:
            return raw_input
        raw_select = self.query_one("#brand-source-list-select", Select).value
        if isinstance(raw_select, str) and raw_select.strip():
            return raw_select.strip()
        return ""

    def _resolve_domains(self) -> list[str]:
        raw_domains = self.query_one("#brand-domains", Input).value.strip()
        domains_file = self.query_one("#brand-domains-file", Input).value.strip()
        source_list = self._resolve_source_list_id()
        loaded_id = self._loaded_domain_source_id
        loaded_domains = list(self._watchlist_domains)
        selected_set = set(self._selected_domains)

        if domains_file:
            path = Path(domains_file).expanduser()
            if not path.is_absolute():
                path = self.workspace_dir / path
            if not path.is_file():
                raise FileNotFoundError(f"Domains file not found: {path}")
            return load_domains_file(path)
        if raw_domains:
            return [d.strip() for d in raw_domains.split(",") if d.strip()]
        if source_list and source_list == loaded_id:
            return [dom for dom in loaded_domains if dom in selected_set]
        if not source_list and loaded_domains:
            return [dom for dom in loaded_domains if dom in selected_set]
        if source_list:
            return get_domains_from_watchlist(self.client, source_list)
        return []

    def _resolve_ignore_file(self) -> str | None:
        raw = self.query_one("#brand-ignore-file", Input).value.strip()
        if not raw:
            default_path = self.workspace_dir / "ignored_hashes.txt"
            return str(default_path) if default_path.is_file() else None
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = self.workspace_dir / candidate
        return str(candidate)

    @on(Button.Pressed, "#brand-domain-sort-btn")
    def handle_cycle_domain_sort(self) -> None:
        self._domain_sort_idx = (self._domain_sort_idx + 1) % len(_DOMAIN_SORT_CYCLE)
        sort_field, sort_desc, sort_label = _DOMAIN_SORT_CYCLE[self._domain_sort_idx]
        self._render_domain_selection()
        direction = "desc" if sort_desc else "asc"
        self.set_status(f"Watchlist domains sorted by {sort_field} ({direction}: {sort_label}).")

    def _recompute_issues_report(self) -> None:
        delta_ctx = self._last_delta_context or {}
        report = analyze_brand_sync_issues(
            state=self._last_state or None,
            watchlist_domains=self._watchlist_domains or None,
            existing_entries=self._last_existing_entries,
            target_hashes=delta_ctx.get("target_hashes"),
            domain_errors=delta_ctx.get("domain_errors"),
            image_errors=delta_ctx.get("image_errors"),
            scoped_domains=delta_ctx.get("scoped_domains"),
        )
        self._issues_report = report
        if not self._tables_ready:
            return
        try:
            summary_widget = self.query_one("#brand-issues-summary", Static)
            if report.total_domains == 0 and not report.issues:
                summary_widget.update(
                    "Brand Health: Load state, domain watchlist, or run Validate to inspect issues."
                )
            else:
                summary_widget.update(
                    f"Domains: {report.total_domains} | OK: {report.healthy_domains} | "
                    f"Missing Hashes: {report.missing_hashes_count} "
                    f"({report.silent_zero_hashes_count} silent, {report.domain_errors_count} err) | "
                    f"Img Err: {report.image_errors_count} | Shared: {report.duplicate_hashes_count}"
                )
            issues_btn = self.query_one("#brand-issues-btn", Button)
            issues_btn.label = f"Issues ({len(report.issues)})"
            issues_btn.variant = (
                "warning"
                if (
                    report.missing_hashes_count > 0
                    or report.domain_errors_count > 0
                    or report.image_errors_count > 0
                )
                else "default"
            )
        except Exception:
            pass

    @staticmethod
    def _update_table_sort_headers(
        table: DataTable[Any],
        sort_by: str,
        descending: bool,
    ) -> None:
        cols_by_key = {
            (col.key.value if col.key.value is not None else str(col.key)): col
            for col in table.columns.values()
        }
        for key, base in _BRAND_COLUMN_LABELS.items():
            col = cols_by_key.get(key)
            if col is None:
                continue
            if sort_by == key:
                indicator = " v" if descending else " ^"
                label_text = Text(f"{base}{indicator}")
            else:
                label_text = Text(base)
            col.label = label_text
            col.content_width = max(col.content_width, len(label_text.plain))
        table._require_update_dimensions = True
        table._clear_caches()
        table.refresh(layout=True)

    def _sync_table_sort_controls(self) -> None:
        if not self._tables_ready:
            return
        label = _BRAND_SORT_DISPLAY.get(self._table_sort_by, self._table_sort_by)
        self.query_one("#brand-sort-cycle-btn", Button).label = f"Sort: {label}"
        self.query_one("#brand-sort-dir-btn", Button).label = (
            "Desc v" if self._table_sort_desc else "Asc ^"
        )

    def _set_table_sort(
        self,
        sort_by: str,
        *,
        descending: bool | None = None,
        toggle_if_same: bool = False,
    ) -> None:
        if sort_by not in _BRAND_SORT_DISPLAY:
            return
        if sort_by == "none":
            next_sort = "none"
            next_desc = False
        elif toggle_if_same and sort_by == self._table_sort_by:
            next_sort = sort_by
            next_desc = not self._table_sort_desc
        else:
            next_sort = sort_by
            next_desc = False if descending is None else bool(descending)

        if (next_sort, next_desc) == (self._table_sort_by, self._table_sort_desc):
            return

        self._table_sort_by = next_sort
        self._table_sort_desc = next_desc
        self._sync_table_sort_controls()
        self._render_results_table()
        if self._table_sort_by == "none":
            self.set_status("Brand table sort reset to default order.")
        else:
            direction = "descending" if self._table_sort_desc else "ascending"
            label = _BRAND_SORT_DISPLAY.get(self._table_sort_by, self._table_sort_by)
            self.set_status(f"Sorted brand results by {label} ({direction}).")

    def action_cycle_table_sort(self) -> None:
        """Cycle Brand Logos results table sort order."""
        try:
            idx = _BRAND_SORT_CYCLE.index(self._table_sort_by)
        except ValueError:
            idx = 0
        next_sort = _BRAND_SORT_CYCLE[(idx + 1) % len(_BRAND_SORT_CYCLE)]
        self._set_table_sort(next_sort, descending=False)

    @on(Button.Pressed, "#brand-sort-cycle-btn")
    def handle_sort_cycle_pressed(self) -> None:
        self.action_cycle_table_sort()

    @on(Button.Pressed, "#brand-sort-dir-btn")
    def handle_sort_dir_pressed(self) -> None:
        if self._table_sort_by == "none":
            self._set_table_sort("domain", descending=False)
        else:
            self._set_table_sort(self._table_sort_by, descending=not self._table_sort_desc)

    @on(DataTable.HeaderSelected, "#brand-table")
    def handle_brand_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        col_key = (
            event.column_key.value if event.column_key.value is not None else str(event.column_key)
        )
        if col_key in _BRAND_SORT_DISPLAY:
            self._set_table_sort(col_key, toggle_if_same=True)

    def _set_active_view(self, view_id: str, *, announce: bool = True) -> None:
        if not view_id.startswith("issue:") and view_id in ("state", "delta", "hashes"):
            self._last_non_issue_view = view_id
        self._active_view = view_id
        if self._tables_ready:
            sel = self.query_one("#brand-dashboard-select", Select)
            if str(sel.value) != view_id:
                self._syncing_dashboard_select = True
                try:
                    with sel.prevent(Select.Changed):
                        sel.value = view_id
                finally:
                    self._syncing_dashboard_select = False
            self._render_results_table()
        if announce:
            if view_id.startswith("issue:"):
                cat = view_id.split(":", 1)[1]
                cat_label = BRAND_SYNC_ISSUE_LABELS.get(cat, cat)
                count = self._issues_report.category_counts.get(cat, 0)
                self.set_status(f"Issue Dashboard: {cat_label} ({count} issue(s)).")
            elif view_id == "state":
                self.set_status("Viewing local brand_sync_state.json snapshot.")
            elif view_id == "delta":
                self.set_status("Viewing discovered logos & sync delta.")
            elif view_id == "hashes":
                self.set_status("Viewing brand watchlist hashes.")

    @on(Select.Changed, "#brand-dashboard-select")
    def handle_dashboard_select_changed(self, event: Select.Changed) -> None:
        if self._syncing_dashboard_select or not self._tables_ready:
            return
        if isinstance(event.value, str) and event.value.strip():
            new_view = event.value.strip()
            if new_view == self._active_view:
                return
            self._set_active_view(new_view, announce=True)

    @on(Input.Changed, "#brand-results-filter")
    def handle_results_filter_changed(self) -> None:
        if self._tables_ready:
            self._render_results_table()

    @on(Button.Pressed, "#brand-issues-btn")
    def handle_toggle_issues_dashboard(self) -> None:
        if self._active_view.startswith("issue:"):
            self._set_active_view(self._last_non_issue_view or "state", announce=True)
            return
        target = (
            "issue:missing_hashes"
            if self._issues_report.missing_hashes_count > 0
            else "issue:all"
        )
        self._set_active_view(target, announce=True)

    @on(Button.Pressed, "#brand-select-issues-btn")
    def handle_select_issue_domains(self) -> None:
        rows_source: list[dict[str, Any]]
        if self._active_view.startswith("issue:"):
            rows_source = list(self._visible_result_rows)
        else:
            missing_issues = filter_brand_issues(
                self._issues_report.issues, category="missing_hashes"
            )
            source_issues = (
                missing_issues if missing_issues else list(self._issues_report.issues)
            )
            rows_source = [
                {
                    "domain": issue.domain,
                    "issue_domains": issue.domains
                    or ((issue.domain,) if "." in issue.domain else ()),
                }
                for issue in source_issues
            ]

        target_domains: set[str] = set()
        for row in rows_source:
            doms = row.get("issue_domains")
            if isinstance(doms, (list, tuple, set)):
                for d in doms:
                    clean = str(d).strip().lower()
                    if clean and "." in clean:
                        target_domains.add(clean)
            else:
                dom = str(row.get("domain") or "").strip().lower()
                if dom and "." in dom:
                    target_domains.add(dom)

        if not target_domains:
            self.set_status("No issue domains available to select.")
            return

        if self._watchlist_domains:
            watchlist_set = {d.strip().lower() for d in self._watchlist_domains}
            matched = {d for d in self._watchlist_domains if d.strip().lower() in target_domains}
            extra = sorted(target_domains - watchlist_set)
            if matched:
                self._selected_domains = set(matched)
                self._render_domain_selection()
                if extra:
                    self.set_status(
                        f"Selected {len(matched)} issue domain(s) from watchlist "
                        f"({len(extra)} not in current watchlist)."
                    )
                else:
                    self.set_status(
                        f"Selected {len(matched)} issue domain(s) in watchlist checklist."
                    )
                return

        self.query_one("#brand-domains", Input).value = ",".join(sorted(target_domains))
        self.set_status(
            f"Populated {len(target_domains)} issue domain(s) into manual override."
        )

    def _render_results_table(self) -> None:
        if not self._tables_ready:
            return
        view_id = self._active_view
        empty_placeholder: tuple[str, str, str, str] | None = None

        if view_id.startswith("issue:"):
            raw_cat = view_id.split(":", 1)[1]
            cat = raw_cat if raw_cat in BRAND_SYNC_ISSUE_CATEGORIES else "all"
            cat_issues = filter_brand_issues(self._issues_report.issues, category=cat)
            base_rows = [
                {
                    "domain": issue.domain,
                    "status": issue.status,
                    "hashes_display": str(issue.hash_count),
                    "hash_count": issue.hash_count,
                    "consecutive_failures": issue.consecutive_failures,
                    "detail": issue.reason,
                    "severity_rank": issue.severity_rank,
                    "issue_domains": issue.domains
                    or ((issue.domain,) if "." in issue.domain else ()),
                }
                for issue in cat_issues
            ]
            cat_label = BRAND_SYNC_ISSUE_LABELS.get(cat, cat)
            base_header = f"Issue Dashboard: {cat_label} ({len(cat_issues)})"
            if not base_rows:
                empty_placeholder = (
                    "-",
                    "OK",
                    "0",
                    f"No issues matched '{cat_label}'.",
                )
        elif view_id == "delta":
            base_rows = list(self._delta_rows)
            base_header = self._delta_header_text
            if not base_rows:
                empty_placeholder = (
                    "delta",
                    "empty",
                    "0",
                    "Run Validate (Dry-Run) or Sync Logos to compute delta.",
                )
        elif view_id == "hashes":
            base_rows = list(self._hash_rows)
            base_header = self._hashes_header_text
            if not base_rows:
                empty_placeholder = (
                    "hashes",
                    "empty",
                    "0",
                    "Click 'View Hashes' to inspect entities in the target brand list.",
                )
        else:
            base_rows = list(self._state_rows)
            base_header = self._state_header_text

        query_tokens = (
            self.query_one("#brand-results-filter", Input).value.strip().casefold().split()
        )
        if query_tokens:
            filtered_rows = [
                row
                for row in base_rows
                if all(
                    tok
                    in (
                        f"{row.get('domain', '')} {row.get('status', '')} "
                        f"{row.get('hashes_display', '')} {row.get('detail', '')}"
                    ).casefold()
                    for tok in query_tokens
                )
            ]
        else:
            filtered_rows = base_rows

        ordered_rows = (
            sort_brand_rows(
                filtered_rows,
                sort_by=self._table_sort_by,
                descending=self._table_sort_desc,
            )
            if self._table_sort_by != "none"
            else filtered_rows
        )
        self._visible_result_rows = ordered_rows

        table = self.query_one("#brand-table", DataTable)
        self._update_table_sort_headers(table, self._table_sort_by, self._table_sort_desc)
        table.clear()
        if ordered_rows:
            for row in ordered_rows:
                table.add_row(
                    str(row.get("domain", "")),
                    str(row.get("status", "")),
                    str(row.get("hashes_display", "")),
                    str(row.get("detail", "")),
                )
        elif empty_placeholder is not None and not query_tokens:
            table.add_row(*empty_placeholder)
        elif query_tokens:
            table.add_row("-", "NO MATCH", "0", "No rows match results filter.")

        header = self.query_one("#brand-table-header", Static)
        if query_tokens:
            header.update(f"{base_header} [showing {len(ordered_rows)}/{len(base_rows)}]")
        else:
            header.update(base_header)
        self.call_after_refresh(self._fit_tables)

    def _load_state_snapshot(self) -> None:
        state_path = resolve_state_path(DEFAULT_STATE_FILENAME, self.workspace_dir)
        state = load_brand_sync_state(state_path)
        domains_map = state.get("domains", {}) if isinstance(state, dict) else {}

        rows: list[dict[str, Any]] = []
        if not domains_map:
            rows.append(
                {
                    "domain": "state",
                    "status": "empty",
                    "hashes_display": "0",
                    "hash_count": 0,
                    "consecutive_failures": 0,
                    "detail": str(state_path),
                    "severity_rank": 99,
                }
            )
        else:
            for dom, info in sorted(domains_map.items()):
                info_map = info if isinstance(info, Mapping) else {}
                failures = int(info_map.get("consecutive_failures") or 0)
                hashes = info_map.get("hashes") or []
                hash_cnt = len(hashes)
                last_err = str(info_map.get("last_error") or "").strip()
                if failures > 0:
                    status = f"failures={failures}"
                elif hash_cnt == 0:
                    status = "NO HASHES"
                else:
                    status = "OK"
                detail = last_err if last_err else f"{hash_cnt} hash(es)"
                rows.append(
                    {
                        "domain": str(dom),
                        "status": status,
                        "hashes_display": str(hash_cnt),
                        "hash_count": hash_cnt,
                        "consecutive_failures": failures,
                        "detail": detail,
                        "severity_rank": 0 if hash_cnt == 0 else (1 if failures > 0 else 3),
                    }
                )

        def _populate() -> None:
            self._last_state = dict(state) if isinstance(state, dict) else {}
            self._state_rows = rows
            self._state_header_text = "Local Sync State (brand_sync_state.json)"
            self._recompute_issues_report()
            if self._watchlist_domains:
                self._render_domain_selection()
            self._set_active_view("state", announce=False)

        self.run_on_ui(_populate)

    @on(Button.Pressed, "#brand-state-btn")
    def handle_load_state(self) -> None:
        self._load_state_snapshot()
        self.set_status("Loaded local brand_sync_state.json snapshot.")

    @on(Button.Pressed, "#brand-view-logs-btn")
    def handle_view_logs(self) -> None:
        open_fn = getattr(self.app, "open_logs_tab", None)
        if callable(open_fn):
            open_fn(source="brand_sync")

    @on(Button.Pressed, "#brand-view-hashes-btn")
    def handle_view_list_hashes(self) -> None:
        list_id = self._resolve_target_list_id()
        if not list_id:
            self.set_status("Select or enter a Target Brand Hash List ID first.")
            return
        self._hashes_request_seq += 1
        seq = self._hashes_request_seq
        self.query_one("#brand-table-header", Static).update(
            f"Loading hashes for {list_id}..."
        )
        self._load_list_hashes_worker(list_id, seq)

    @work(thread=True, exit_on_error=False, exclusive=True, group="brand-hashes")
    def _load_list_hashes_worker(self, list_id: str, request_seq: int) -> None:
        try:
            if self.is_app_shutting_down():
                return
            self.set_status(f"Fetching hashes from {list_id}...")
            raw_entries = self.client.get_watchlist_entities(list_id)
            if self.is_app_shutting_down():
                return
            entries = list(raw_entries) if isinstance(raw_entries, list) else []
            list_name = str(self._brand_list_by_id.get(list_id, {}).get("name") or "").strip()

            hash_rows: list[dict[str, Any]] = []
            if entries:
                for entry in entries:
                    ent = entry.get("entity", {}) or {}
                    ctx = entry.get("context", {}) or {}
                    hash_val = str(ent.get("name") or ent.get("id") or "")
                    status = str(entry.get("status") or ent.get("type") or "ready")
                    ctx_domains = ctx.get("domains")
                    if isinstance(ctx_domains, list) and ctx_domains:
                        domain_key = ", ".join(
                            str(d).strip() for d in ctx_domains if str(d).strip()
                        )
                    else:
                        domain_key = str(
                            ctx.get("domain")
                            or ctx.get("annotation")
                            or ent.get("type")
                            or "Hash"
                        )
                    hash_rows.append(
                        {
                            "domain": domain_key,
                            "status": status,
                            "hashes_display": "1",
                            "hash_count": 1,
                            "consecutive_failures": 0,
                            "detail": hash_val,
                            "severity_rank": 3,
                        }
                    )
            else:
                hash_rows.append(
                    {
                        "domain": list_id,
                        "status": "empty",
                        "hashes_display": "0",
                        "hash_count": 0,
                        "consecutive_failures": 0,
                        "detail": "No hashes or entities in list",
                        "severity_rank": 2,
                    }
                )

            def _populate() -> None:
                if request_seq != self._hashes_request_seq:
                    return
                label = f"{list_name} ({list_id})" if list_name else list_id
                self._last_existing_entries = entries
                self._hash_rows = hash_rows
                self._hashes_header_text = f"Hashes in {label} ({len(entries)})"
                self._recompute_issues_report()
                self._set_active_view("hashes", announce=False)

            self.run_on_ui(_populate)
            msg = f"Loaded {len(entries)} hash/entity record(s) from {list_id}."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Load Brand List Hashes", exc)

    @on(Button.Pressed, "#brand-validate-btn")
    def handle_validate_logos(self) -> None:
        list_id = self._resolve_target_list_id()
        if not list_id:
            self.set_status("Target Brand Hash List ID is required.")
            return
        self._run_logo_sync_worker(list_id, force_dry_run=True)

    @on(Button.Pressed, "#brand-sync-btn")
    def handle_sync_logos(self) -> None:
        list_id = self._resolve_target_list_id()
        if not list_id:
            self.set_status("Target Brand Hash List ID is required.")
            return
        self._run_logo_sync_worker(list_id, force_dry_run=self.effective_dry_run)

    @work(thread=True, exit_on_error=False)
    def _run_logo_sync_worker(
        self,
        list_id: str,
        force_dry_run: bool,
        *,
        target_domains: list[str] | None = None,
    ) -> None:
        try:
            if target_domains is not None:
                domains = [str(d).strip().lower() for d in target_domains if str(d).strip()]
            else:
                domains = self._resolve_domains()
            if not domains:
                self.set_status(
                    "No domains selected. Check watchlist domains, click Select All, or enter manual domains."
                )
                return
            ignore_file = self._resolve_ignore_file()
            is_dry = bool(force_dry_run or self.effective_dry_run)
            mode_verb = "Validating" if is_dry else "Syncing"
            single_scope = target_domains is not None and len(domains) == 1
            if single_scope:
                self.set_status(
                    f"{mode_verb} single domain '{domains[0]}' (dry_run={is_dry})..."
                )
                self.append_log(
                    f"Starting single-domain brand logo "
                    f"{'validation (dry-run)' if is_dry else 'sync'} "
                    f"for '{domains[0]}' -> {list_id}..."
                )
            else:
                self.set_status(
                    f"Calculating brand logo delta for {len(domains)} domain(s) (dry_run={is_dry})..."
                )
                self.append_log(
                    f"Starting brand logo {'validation (dry-run)' if is_dry else 'sync'} "
                    f"for {len(domains)} domain(s) -> {list_id}..."
                )

            def _on_progress(done: int, total: int, domain: str, _res: Any) -> None:
                if not self.is_app_shutting_down():
                    self.set_status(
                        f"{mode_verb} logos: {done}/{total} ({domain}) - click 'View Logs' or press 8"
                    )

            with self.log_scope("brand_sync"):
                try:
                    target_hashes, existing_map, to_add, to_remove, dom_err, img_err = (
                        calculate_brand_sync_delta(
                            self.client,
                            list_id,
                            domains,
                            output_locations_file=None,
                            ignore_hashes_file=ignore_file,
                            workspace_dir=self.workspace_dir,
                            progress_callback=_on_progress,
                        )
                    )
                except TypeError as exc:
                    if "progress_callback" not in str(exc):
                        raise
                    target_hashes, existing_map, to_add, to_remove, dom_err, img_err = (
                        calculate_brand_sync_delta(
                            self.client,
                            list_id,
                            domains,
                            output_locations_file=None,
                            ignore_hashes_file=ignore_file,
                            workspace_dir=self.workspace_dir,
                        )
                    )

            domains_with_hashes: set[str] = set()
            delta_rows: list[dict[str, Any]] = []
            for h_val, meta in target_hashes.items():
                meta_map = meta if isinstance(meta, Mapping) else {}
                owners = meta_map.get("domains") or (
                    [meta_map.get("domain")] if meta_map.get("domain") else []
                )
                for own in owners:
                    clean_own = str(own).strip().lower()
                    if clean_own:
                        domains_with_hashes.add(clean_own)
                action = "ADD" if h_val in to_add else "KEEP"
                delta_rows.append(
                    {
                        "domain": str(meta_map.get("domain", "")),
                        "status": action,
                        "hashes_display": "1",
                        "hash_count": 1,
                        "consecutive_failures": 0,
                        "detail": h_val[:24] + "...",
                        "severity_rank": 3,
                    }
                )
            for rem in to_remove:
                delta_rows.append(
                    {
                        "domain": "remove",
                        "status": "REMOVE",
                        "hashes_display": "-",
                        "hash_count": None,
                        "consecutive_failures": 0,
                        "detail": str(rem.get("name") or rem.get("id") or ""),
                        "severity_rank": 2,
                    }
                )
            norm_dom_err = {str(k).strip().lower(): str(v) for k, v in dom_err.items()}
            norm_img_err = {
                str(k).strip().lower(): list(v) for k, v in (img_err or {}).items()
            }
            for dom, err in dom_err.items():
                delta_rows.append(
                    {
                        "domain": dom,
                        "status": "ERROR",
                        "hashes_display": "0",
                        "hash_count": 0,
                        "consecutive_failures": 1,
                        "detail": str(err),
                        "severity_rank": 0,
                    }
                )
            for dom in domains:
                dom_clean = dom.strip().lower()
                if not dom_clean or dom_clean in norm_dom_err or dom_clean in domains_with_hashes:
                    continue
                if dom_clean in norm_img_err:
                    delta_rows.append(
                        {
                            "domain": dom_clean,
                            "status": "IMAGE ERR",
                            "hashes_display": "0",
                            "hash_count": 0,
                            "consecutive_failures": 1,
                            "detail": "; ".join(norm_img_err[dom_clean]),
                            "severity_rank": 0,
                        }
                    )
                else:
                    delta_rows.append(
                        {
                            "domain": dom_clean,
                            "status": "NO HASHES",
                            "hashes_display": "0",
                            "hash_count": 0,
                            "consecutive_failures": 0,
                            "detail": "0 brand image hashes extracted",
                            "severity_rank": 0,
                        }
                    )

            def _populate() -> None:
                self._last_delta_context = {
                    "target_hashes": target_hashes,
                    "domain_errors": dom_err,
                    "image_errors": img_err,
                    "scoped_domains": list(domains),
                }
                self._delta_rows = delta_rows
                self._delta_header_text = f"Discovered Logos & Sync Delta ({list_id})"
                self._recompute_issues_report()
                if self._watchlist_domains:
                    self._render_domain_selection()
                self._set_active_view("delta", announce=False)

            self.run_on_ui(_populate)

            if is_dry:
                msg = (
                    f"[DRY-RUN] Found {len(target_hashes)} hash(es), existing={len(existing_map)}, "
                    f"to_add={len(to_add)}, to_remove={len(to_remove)}."
                )
                self.set_status(msg)
                self.append_log(msg)
                return

            if to_remove:
                preview_lines = [
                    str(rem.get("name") or rem.get("id") or "")
                    for rem in to_remove[:10]
                ]
                if len(to_remove) > 10:
                    preview_lines.append(f"... and {len(to_remove) - 10} more")
                approved = self.confirm_action_from_worker(
                    title="Confirm Brand Hash Deletion",
                    message=(
                        f"Syncing {list_id} will delete {len(to_remove)} hash(es) "
                        f"and add {len(to_add)} hash(es). Approve deletion?"
                    ),
                    details="\n".join(preview_lines),
                    confirm_label="Approve Delete & Sync",
                )
                if not approved:
                    msg = f"Sync cancelled by operator ({len(to_remove)} hash(es) kept)."
                    self.set_status(msg)
                    self.append_log(msg)
                    return

            with self.log_scope("brand_sync"):
                try:
                    ok = execute_domain_brand_sync(
                        self.client,
                        list_id,
                        domains,
                        dry_run=False,
                        output_locations_file=None,
                        ignore_hashes_file=ignore_file,
                        workspace_dir=self.workspace_dir,
                        progress_callback=_on_progress,
                    )
                except TypeError as exc:
                    if "progress_callback" not in str(exc):
                        raise
                    ok = execute_domain_brand_sync(
                        self.client,
                        list_id,
                        domains,
                        dry_run=False,
                        output_locations_file=None,
                        ignore_hashes_file=ignore_file,
                        workspace_dir=self.workspace_dir,
                    )
            self._load_state_snapshot()
            msg = f"Brand logo sync completed (ok={ok}, add={len(to_add)}, remove={len(to_remove)})."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Brand Logo Sync", exc)

    @staticmethod
    def _is_valid_single_domain(candidate: str) -> bool:
        clean = candidate.strip().lower()
        return bool(
            clean
            and clean not in {"remove", "state", "delta", "hashes", "-"}
            and "." in clean
            and "," not in clean
            and " " not in clean
        )

    def _resolve_table_row_domain(
        self, event: DoubleClickDataTable.RowRightClicked
    ) -> str:
        if self._active_view == "hashes" or event.row_key is None:
            return ""
        if (
            event.row_index is not None
            and 0 <= event.row_index < len(self._visible_result_rows)
        ):
            row_dict = self._visible_result_rows[event.row_index]
            cand = str(row_dict.get("domain") or "").strip().lower()
            if self._is_valid_single_domain(cand):
                return cand
            issue_doms = row_dict.get("issue_domains")
            if isinstance(issue_doms, (list, tuple)) and len(issue_doms) == 1:
                only = str(issue_doms[0]).strip().lower()
                if self._is_valid_single_domain(only):
                    return only
            return ""
        table = self.query_one("#brand-table", DoubleClickDataTable)
        try:
            row = table.get_row(event.row_key)
        except Exception:
            return ""
        if not row:
            return ""
        cand = str(row[0]).strip().lower()
        return cand if self._is_valid_single_domain(cand) else ""

    def _sync_single_domain_action(self, domain: str, *, force_dry_run: bool) -> None:
        list_id = self._resolve_target_list_id()
        if not list_id:
            self.set_status("Target Brand Hash List ID is required.")
            return
        self._run_logo_sync_worker(
            list_id, force_dry_run=force_dry_run, target_domains=[domain]
        )

    def _select_single_domain_action(self, domain: str) -> None:
        clean = domain.strip().lower()
        if not self._is_valid_single_domain(clean):
            return
        if self._watchlist_domains:
            matched = [d for d in self._watchlist_domains if d.strip().lower() == clean]
            if not matched:
                self._watchlist_domains.append(clean)
                matched = [clean]
            self._selected_domains = set(matched)
            self._render_domain_selection()
        else:
            self.query_one("#brand-domains", Input).value = clean
        self.set_status(f"Selected only '{clean}' for Brand Sync.")

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        event.stop()
        self._open_brand_menu(origin=(event.screen_x, event.screen_y))

    @on(DoubleClickDataTable.RowRightClicked, "#brand-table")
    def handle_brand_right_click(self, event: DoubleClickDataTable.RowRightClicked) -> None:
        event.stop()
        clicked_domain = self._resolve_table_row_domain(event)
        self._open_brand_menu(
            origin=(event.screen_x, event.screen_y),
            domain=clicked_domain,
            row_index=event.row_index,
        )

    @on(_RightClickSelectionList.DomainRightClicked, "#brand-domain-selection")
    def handle_domain_selection_right_click(
        self, event: _RightClickSelectionList.DomainRightClicked
    ) -> None:
        event.stop()
        clicked_domain = (
            event.domain if self._is_valid_single_domain(event.domain) else ""
        )
        self._open_brand_menu(
            origin=(event.screen_x, event.screen_y),
            domain=clicked_domain,
        )

    def _extract_brand_hash_or_domain(self, row_index: int | None = None) -> tuple[str, str]:
        """Return ``(primary_value, full_row_text)`` from ``#brand-table``."""
        table = self.query_one("#brand-table", DataTable)
        full_row = extract_table_row_text(table, row_index=row_index)
        if table.row_count <= 0:
            return "", full_row
        idx = table.cursor_row if row_index is None else row_index
        if idx is None or idx < 0 or idx >= table.row_count:
            return "", full_row
        try:
            cells = table.get_row(table.ordered_rows[idx].key)
            domain_val = str(cells[0]).strip() if len(cells) > 0 else ""
            detail_val = str(cells[-1]).strip() if len(cells) >= 3 else ""
            # Prefer a 64-hex SHA-256 hash when present in the detail column, otherwise domain/key
            if len(detail_val) == 64 and all(c in "0123456789abcdefABCDEF" for c in detail_val):
                return detail_val, full_row
            return domain_val or detail_val, full_row
        except Exception:
            return "", full_row

    def _open_brand_menu(
        self,
        *,
        origin: tuple[int, int],
        domain: str = "",
        row_index: int | None = None,
    ) -> None:
        clean_domain = domain.strip().lower()
        items: list[tuple[str, str]] = []
        if clean_domain:
            items.extend(
                [
                    ("sync_single_domain", f"Sync '{clean_domain}' Only"),
                    ("validate_single_domain", f"Validate '{clean_domain}' Only (Dry-Run)"),
                    ("select_single_domain", f"Select Only '{clean_domain}' in Checklist"),
                ]
            )
        items.extend(
            [
                ("copy_hash_domain", "Copy Hash / Domain"),
                ("copy_row", "Copy Selected Row"),
                ("open_copy_view", "Open Copyable View"),
            ]
        )
        items.extend(
            [
                ("issue_missing_hashes", "Issue Dashboard: Missing Hashes (0)"),
                ("issue_silent_zero_hashes", "Issue Dashboard: Zero Hashes (No Error)"),
                ("issue_domain_errors", "Issue Dashboard: Domain / HTTP / Bot Errors"),
                ("issue_image_errors", "Issue Dashboard: Image Fetch Errors"),
                ("issue_failing_grace", "Issue Dashboard: Repeated Failures (Grace)"),
                ("issue_duplicate_hashes", "Issue Dashboard: Shared / Duplicate Hashes"),
                ("issue_all", "Issue Dashboard: All Issues"),
                ("select_issue_domains", "Select Affected Issue Domains"),
                ("cycle_sort", "Cycle Results Table Sort"),
                ("toggle_sort_dir", "Toggle Results Sort Direction"),
                ("reset_sort", "Reset Results Sort"),
                ("cycle_domain_sort", "Cycle Watchlist Domain Sort"),
                ("reload_lists", "Reload Brand Hash Lists"),
                ("load_domains", "Reload Watchlist Domains"),
                ("select_all_domains", "Select All Watchlist Domains"),
                ("deselect_all_domains", "Deselect All Watchlist Domains"),
                ("view_hashes", "View Selected List Hashes"),
                ("validate", "Validate Logos (Dry-Run)"),
                ("sync", "Sync Brand Logos"),
                ("load_state", "Load Local Sync State"),
                ("view_logs", "Open Brand Sync Logs"),
                ("toggle_adv", "Toggle Advanced & Watch Options"),
            ]
        )

        def _on_select(action_id: str) -> None:
            if action_id == "copy_hash_domain":
                val, _row = self._extract_brand_hash_or_domain(row_index=row_index)
                self.copy_to_clipboard(val, label="Hash / Domain")
            elif action_id == "copy_row":
                _val, row_text = self._extract_brand_hash_or_domain(row_index=row_index)
                self.copy_to_clipboard(row_text, label="Brand Logo Row")
            elif action_id == "open_copy_view":
                _val, row_text = self._extract_brand_hash_or_domain(row_index=row_index)
                self.open_copy_modal(row_text, title="Brand Logo Entry")
            elif action_id == "sync_single_domain" and clean_domain:
                self._sync_single_domain_action(
                    clean_domain, force_dry_run=self.effective_dry_run
                )
            elif action_id == "validate_single_domain" and clean_domain:
                self._sync_single_domain_action(clean_domain, force_dry_run=True)
            elif action_id == "select_single_domain" and clean_domain:
                self._select_single_domain_action(clean_domain)
            elif action_id.startswith("issue_"):
                cat = action_id.removeprefix("issue_")
                self._set_active_view(f"issue:{cat}", announce=True)
            elif action_id == "select_issue_domains":
                self.handle_select_issue_domains()
            elif action_id == "cycle_sort":
                self.action_cycle_table_sort()
            elif action_id == "toggle_sort_dir":
                self.handle_sort_dir_pressed()
            elif action_id == "reset_sort":
                self._set_table_sort("none")
            elif action_id == "cycle_domain_sort":
                self.handle_cycle_domain_sort()
            elif action_id == "reload_lists":
                self.handle_reload_brand_lists()
            elif action_id == "load_domains":
                self.handle_load_watchlist_domains()
            elif action_id == "select_all_domains":
                self.handle_select_all_domains()
            elif action_id == "deselect_all_domains":
                self.handle_deselect_all_domains()
            elif action_id == "view_hashes":
                self.handle_view_list_hashes()
            elif action_id == "validate":
                self.handle_validate_logos()
            elif action_id == "sync":
                self.handle_sync_logos()
            elif action_id == "load_state":
                self.handle_load_state()
            elif action_id == "view_logs":
                self.handle_view_logs()
            elif action_id == "toggle_adv":
                col = self.query_one("#brand-advanced-collapsible", Collapsible)
                col.collapsed = not col.collapsed

        menu_title = f"Brand Sync: {clean_domain}" if clean_domain else "Brand Logos"
        self.open_context_menu(
            items,
            title=menu_title,
            origin=origin,
            on_select=_on_select,
        )

    @on(Button.Pressed, "#brand-watch-start-btn")
    def handle_start_watch(self) -> None:
        list_id = self._resolve_target_list_id()
        if not list_id:
            self.set_status("Target Brand Hash List ID is required for continuous watch.")
            return
        raw_interval = self.query_one("#brand-interval", Input).value.strip() or "3600"
        raw_max_runs = self.query_one("#brand-max-runs", Input).value.strip()
        try:
            interval = float(raw_interval)
            if interval < 0:
                raise ValueError("Interval must be >= 0")
            max_runs = int(raw_max_runs) if raw_max_runs else None
            if max_runs is not None and max_runs < 1:
                raise ValueError("Max runs must be >= 1")
        except ValueError as exc:
            self.set_status(f"Invalid watch settings: {exc}")
            return

        if self.effective_dry_run:
            self._watch_stop_event.clear()
            self._continuous_watch_worker(list_id, interval, max_runs)
            return

        def _start_watch() -> None:
            self._watch_stop_event.clear()
            self._continuous_watch_worker(list_id, interval, max_runs)

        self.confirm_destructive_action(
            title="Approve Live Continuous Brand Watch",
            message=(
                f"Live continuous watch on {list_id} may automatically delete stale logo hashes. "
                "Approve starting watch?"
            ),
            details=(
                f"List ID: {list_id}\nInterval: {interval}s\n"
                f"Max runs: {max_runs if max_runs is not None else 'unlimited'}"
            ),
            confirm_label="Approve Live Watch",
            on_approved=_start_watch,
            on_cancelled=lambda: self.set_status("Live continuous watch cancelled."),
        )

    @on(Button.Pressed, "#brand-watch-stop-btn")
    def handle_stop_watch(self) -> None:
        self._watch_stop_event.set()
        self.set_status("Stopping continuous watch loop...")

    @work(thread=True, exit_on_error=False, exclusive=True, group="brand-watch")
    def _continuous_watch_worker(
        self, list_id: str, interval: float, max_runs: int | None
    ) -> None:
        try:
            domains = self._resolve_domains()
            if not domains:
                self.set_status(
                    "No domains selected. Check watchlist domains, click Select All, or enter manual domains."
                )
                return
            ignore_file = self._resolve_ignore_file()
            self.set_status(
                f"Continuous watch active (interval={interval}s, dry_run={self.effective_dry_run})..."
            )
            with self.log_scope("brand_sync"):
                summary = run_continuous_brand_sync(
                    self.client,
                    list_id,
                    domains=domains,
                    dry_run=self.effective_dry_run,
                    output_locations_file=None,
                    ignore_hashes_file=ignore_file,
                    interval_seconds=interval,
                    max_runs=max_runs,
                    stop_event=self._watch_stop_event,
                    workspace_dir=self.workspace_dir,
                )
            self._load_state_snapshot()
            msg = (
                f"Watch stopped: attempted={summary['runs_attempted']}, "
                f"succeeded={summary['runs_succeeded']}, failed={summary['runs_failed']}"
            )
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Continuous Brand Watch", exc)
