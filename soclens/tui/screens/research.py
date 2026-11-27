"""Unified search-first Recorded Future + Passive OSINT Threat Research Workbench pane."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, ClassVar

from rich.text import Text
from textual import events, on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    DataTable,
    Input,
    RichLog,
    Select,
    Static,
)

from soclens.client import RecordedFutureError
from soclens.config import get_osint_config
from soclens.osint import OSINT_MODULES, OSINTClient
from soclens.research import (
    ResearchDossier,
    export_dossier_json,
    export_dossier_markdown,
    render_dossier_markdown,
    research_target,
)
from soclens.tui.filters import SPLUNK_TIME_PRESETS
from soclens.tui.modals import OSINTSourcesModal
from soclens.tui.pivot import PivotPayload
from soclens.tui.research_art import ResearchMoodBanner, determine_research_mood
from soclens.tui.research_formatters import (
    build_research_findings,
    build_search_summary_bar,
    render_finding_detail,
    render_research_json,
    render_research_welcome,
)
from soclens.tui.rf_formatters import (
    render_error_panel,
    truncate_text,
)
from soclens.tui.screens.base import (
    BaseSocPane,
    DoubleClickDataTable,
    SelectableRichLog,
    extract_richlog_text,
    extract_table_row_text,
)

_TARGET_TYPE_OPTIONS: list[tuple[str, str]] = [
    ("Auto Detect", "auto"),
    ("IP", "ip"),
    ("Domain", "domain"),
    ("Hash", "hash"),
    ("URL", "url"),
    ("Vulnerability (CVE)", "vulnerability"),
    ("Malware", "malware"),
    ("Threat Actor", "actor"),
    ("Company", "company"),
    ("Email", "email"),
    ("MITRE ATT&CK", "mitre"),
    ("ASN", "asn"),
    ("RF Entity ID", "entity_id"),
    ("Free Text", "text"),
]

_SOURCE_MODE_OPTIONS: list[tuple[str, str]] = [
    ("RF + OSINT", "all"),
    ("OSINT Only", "osint"),
    ("RF Only", "rf"),
]

_SOURCE_GROUP_FILTER_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Source: All", "all"),
    ("Recorded Future", "rf"),
    ("Free OSINT", "osint"),
)

_RES_TIMEFRAME_PRESETS: tuple[tuple[str, str], ...] = tuple(
    item
    for item in SPLUNK_TIME_PRESETS
    if item[1] in {"-24h", "-48h", "-7d", "-14d", "-30d", "-90d", "custom"}
)

_RES_CATEGORY_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Category: All", "all"),
    ("Summary", "Summary"),
    ("WHOIS", "WHOIS"),
    ("DNS", "DNS"),
    ("Network", "Network"),
    ("Certificates", "Certificates"),
    ("Reputation", "Reputation"),
    ("Web Intel", "Web Intel"),
    ("Vulnerability", "Vulnerability"),
    ("File Intel", "File Intel"),
    ("Sources", "Sources"),
    ("Report", "Report"),
    ("Actor", "Actor"),
    ("Threat Map", "Threat Map"),
    ("Related", "Related"),
    ("Rule", "Rule"),
    ("Alert", "Alert"),
    ("Sample", "Sample"),
    ("History", "History"),
    ("Exposure", "Exposure"),
    ("Attack Surface", "Attack Surface"),
    ("Third Party", "Third Party"),
    ("Context", "Context"),
)

_FINDING_SPECS: tuple[tuple[str, str, float, int], ...] = (
    ("category", "Category", 0.16, 10),
    ("source", "Source", 0.13, 8),
    ("finding", "Finding", 0.39, 18),
    ("detail", "Detail", 0.32, 14),
)

_EXAMPLE_FINDINGS: tuple[dict[str, Any], ...] = (
    {
        "kind": "example",
        "category": "Actor",
        "source_group": "rf",
        "source_label": "RF",
        "title": "APT29",
        "detail": "Threat actor profile, aliases, threat map & Insikt reports",
        "example_query": "APT29",
        "search_blob": "apt29 threat actor",
    },
    {
        "kind": "example",
        "category": "CVE",
        "source_group": "unified",
        "source_label": "RF+OSINT",
        "title": "CVE-2021-44228",
        "detail": "RF risk/rules + MITRE CVE 5.x, FIRST EPSS & CISA KEV",
        "example_query": "CVE-2021-44228",
        "search_blob": "cve-2021-44228 vulnerability log4j kev epss",
    },
    {
        "kind": "example",
        "category": "Malware",
        "source_group": "rf",
        "source_label": "RF",
        "title": "Cobalt Strike",
        "detail": "Malware profile, threat map, reports & detection rules",
        "example_query": "Cobalt Strike",
        "search_blob": "cobalt strike malware",
    },
    {
        "kind": "example",
        "category": "IP",
        "source_group": "unified",
        "source_label": "RF+OSINT",
        "title": "8.8.8.8",
        "detail": "RF risk + WHOIS/RDAP, PTR DNS, GeoIP, BGP, Shodan, DShield & VT",
        "example_query": "8.8.8.8",
        "search_blob": "8.8.8.8 ip osint whois dns shodan virustotal",
    },
)

_ALWAYS_RESERVED_KEYS: frozenset[str] = frozenset(
    {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "q", "m", "slash", "space"}
)
_DOSSIER_RESERVED_KEYS: frozenset[str] = frozenset(
    {"j", "p", "s", "left_square_bracket", "right_square_bracket"}
)


class ResearchPane(BaseSocPane):
    """Unified search-first Recorded Future + Passive OSINT Threat Research Workbench."""

    STATUS_ID = "res-status"
    LOG_ID = ""
    LOG_SOURCE = "research"

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("slash", "toggle_filter", "Filter & Options"),
        Binding("escape", "collapse_filter", "Close Options", show=False),
        Binding("j", "toggle_json_view", "Raw JSON"),
        Binding("p", "pivot_selected", "Search Selected"),
        Binding("s", "open_sources_modal", "OSINT Sources"),
        Binding("[", "history_back", "Back"),
        Binding("]", "history_forward", "Forward"),
        Binding("m", "open_context_menu", "Menu"),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tables_ready: bool = False
        self._rendering_table: bool = False
        self._detail_mode: str = "overview"
        self._current_dossier: ResearchDossier | None = None
        self._dossier_cache: dict[tuple[str, str, str, tuple[str, ...]], ResearchDossier] = {}
        self._history: list[tuple[str, str, str, tuple[str, ...]]] = []
        self._history_index: int = -1
        self._all_findings: list[dict[str, Any]] = list(_EXAMPLE_FINDINGS)
        self._visible_rows: list[dict[str, Any]] = []
        self._selected_index: int | None = None
        self._last_detail_width: int = 0
        self._request_seq: int = 0
        self._last_submitted_query: str = ""
        self._syncing_timeframe: bool = False
        self._category_filter: str = "all"
        self._source_group_filter: str = "all"
        self._source_mode: str = "all"
        self._enabled_osint_sources: set[str] = set(OSINT_MODULES)
        self._custom_osint_selection: bool = False

    def compose(self) -> ComposeResult:
        yield Static("Threat Research (Recorded Future + Passive OSINT)", classes="pane-title")
        yield Static(
            "Start typing to search any domain (badsite.com), IP, URL, hash, CVE, ASN, malware, actor, or topic.",
            id="res-status",
            classes="status-bar",
            markup=False,
        )

        with Horizontal(id="res-toolbar", classes="action-row toolbar-row"):
            yield Input(
                placeholder="Search domain (badsite.com), IP, URL, hash, CVE, ASN, APT29, Cobalt Strike...",
                id="res-target-input",
                select_on_focus=False,
                compact=True,
            )
            yield Select(
                _SOURCE_MODE_OPTIONS,
                allow_blank=False,
                value="all",
                id="res-source-mode",
                compact=True,
            )
            yield Button("Search", id="res-investigate-btn", variant="primary", compact=True)
            yield Button("Sources", id="res-sources-btn", compact=True)
            yield Button("< Back", id="res-back-btn", compact=True)
            yield Button("Fwd >", id="res-fwd-btn", compact=True)
            yield Button("Export", id="res-export-md-btn", compact=True)

        with Collapsible(
            title="Filter Results & Search Options (press /)",
            collapsed=True,
            collapsed_symbol=">",
            expanded_symbol="v",
            id="res-options-collapsible",
        ):
            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    placeholder="Filter findings...",
                    id="res-filter-input",
                    select_on_focus=False,
                    compact=True,
                )
                yield Select(
                    list(_SOURCE_GROUP_FILTER_OPTIONS),
                    allow_blank=False,
                    value="all",
                    id="res-source-group-filter",
                    compact=True,
                )
                yield Select(
                    list(_RES_CATEGORY_OPTIONS),
                    allow_blank=False,
                    value="all",
                    id="res-category-filter",
                    compact=True,
                )
                yield Button("Reset", id="res-clear-filter-btn", compact=True)
            with Horizontal(classes="action-row filter-bar"):
                yield Select(
                    _TARGET_TYPE_OPTIONS,
                    allow_blank=False,
                    value="auto",
                    id="res-target-type",
                    compact=True,
                )
                yield Select(
                    list(_RES_TIMEFRAME_PRESETS),
                    allow_blank=False,
                    value="-30d",
                    id="res-timeframe-preset",
                    compact=True,
                )
                yield Input(value="-30d", placeholder="Timeframe", id="res-links-timeframe", compact=True)
                yield Input(value="20", placeholder="Limit", id="res-limit-input", compact=True)
                yield Checkbox("Deep Lookup", value=False, id="res-deep-check", compact=True)
                yield Button("Export JSON", id="res-export-json-btn", compact=True)

        yield ResearchMoodBanner(id="res-mood-strip")
        yield Static("", id="res-summary-bar", classes="rf-summary-bar", markup=False)

        with Container(id="res-workspace", classes="split-workspace"):
            with Vertical(id="res-master-pane", classes="table-pane"):
                yield Static("Example Searches", id="res-master-header", classes="section-label", markup=False)
                yield DoubleClickDataTable(id="res-table")

            with Vertical(id="res-detail-pane", classes="table-pane"):
                with Horizontal(classes="detail-toolbar"):
                    yield Static(
                        "Intelligence Brief",
                        id="res-detail-header",
                        classes="section-label",
                        markup=False,
                    )
                    yield Button("Search Selected", id="res-pivot-btn", compact=True)
                    yield Button("Raw JSON", id="res-detail-mode-btn", compact=True)
                    yield Button("Copy Detail", id="res-copy-detail-btn", compact=True)
                yield SelectableRichLog(
                    id="res-detail-log",
                    classes="detail-log",
                    highlight=False,
                    markup=False,
                    wrap=True,
                )

    def _get_osint_client(self) -> OSINTClient | None:
        injected = getattr(self.app, "osint_client", None)
        if isinstance(injected, OSINTClient) or injected is not None:
            return injected  # type: ignore[no-any-return]
        return None

    def _build_osint_inspector_client(self) -> OSINTClient:
        injected = self._get_osint_client()
        if isinstance(injected, OSINTClient):
            return injected
        return OSINTClient(get_osint_config(), workspace_dir=self.workspace_dir)

    def on_mount(self) -> None:
        table = self.query_one("#res-table", DoubleClickDataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        self._tables_ready = True
        self._render_master_table()
        self._render_detail_panel()
        self._update_responsive_layout()

    def on_resize(self) -> None:
        if self._tables_ready:
            self._update_responsive_layout()

    def on_tab_activated(self) -> None:
        if self._tables_ready:
            self._update_responsive_layout()

    def on_settings_updated(self) -> None:
        """Refresh OSINT key readiness, ASCII art toggle, and clear cached dossiers after Settings updates."""
        self._dossier_cache.clear()
        try:
            self.query_one("#res-mood-strip", ResearchMoodBanner).sync_ascii_art_setting()
        except Exception:
            pass
        if self._tables_ready and self._current_dossier is None:
            self._render_detail_panel()

    def _update_responsive_layout(self) -> None:
        workspace = self.query_one("#res-workspace", Container)
        if self.size.width >= 120:
            workspace.add_class("split-horizontal")
        else:
            workspace.remove_class("split-horizontal")
        self.call_after_refresh(self._refresh_after_layout)

    def _refresh_after_layout(self) -> None:
        self._fit_table()
        if self.is_app_shutting_down() or not self._tables_ready:
            return
        try:
            log_widget = self.query_one("#res-detail-log", RichLog)
            width = log_widget.scrollable_content_region.width
            if width > 0 and width != self._last_detail_width:
                self._render_detail_panel()
        except Exception:
            pass

    def _fit_table(self) -> None:
        if self.is_app_shutting_down() or not self._tables_ready:
            return
        col_specs = tuple((key, weight, min_w) for key, _, weight, min_w in _FINDING_SPECS)
        try:
            self.fit_table_columns(self.query_one("#res-table", DoubleClickDataTable), col_specs)
        except Exception:
            pass

    def _parse_limit(self, default: int = 20) -> int:
        raw = self.query_one("#res-limit-input", Input).value.strip()
        if not raw:
            return default
        try:
            return max(1, int(raw))
        except ValueError:
            return default

    def _active_sources_sig(self) -> tuple[str, ...]:
        if not self._custom_osint_selection:
            return ("__default__",)
        return tuple(sorted(self._enabled_osint_sources))

    def _push_history(
        self,
        query: str,
        explicit_type: str,
        source_mode: str,
        sources_sig: tuple[str, ...],
    ) -> None:
        entry = (query, explicit_type, source_mode, sources_sig)
        if 0 <= self._history_index < len(self._history) and self._history[self._history_index] == entry:
            return
        if self._history_index + 1 < len(self._history):
            self._history = self._history[: self._history_index + 1]
        self._history.append(entry)
        self._history_index = len(self._history) - 1

    def investigate_external(self, target: str, target_type: str = "auto") -> None:
        """Populate Research search bar from another tab and run the unified search."""
        clean = target.strip()
        if not clean:
            return
        valid_types = {val for _, val in _TARGET_TYPE_OPTIONS}
        resolved_type = target_type if target_type in valid_types else "auto"
        sel = self.query_one("#res-target-type", Select)
        inp = self.query_one("#res-target-input", Input)
        with sel.prevent(Select.Changed):
            sel.value = resolved_type
        with inp.prevent(Input.Changed):
            inp.value = clean
        self._start_investigation(clean, resolved_type, record_history=True)

    def accept_pivot(self, payload: PivotPayload) -> None:
        """Accept a ``PivotPayload`` and auto-run a scoped unified Threat Research search."""
        primary = payload.primary_ioc()
        if primary is None:
            self.set_status("Pivot payload contained no IOC or entity to research.")
            return
        raw_kind, raw_val = primary
        clean = raw_val.strip()
        if not clean or clean == "-":
            self.set_status("Pivot payload contained an empty IOC or entity to research.")
            return

        norm_kind = raw_kind.strip().lower()
        aliases = {
            "ipaddress": "ip",
            "ip_address": "ip",
            "internetdomainname": "domain",
            "cybervulnerability": "vulnerability",
            "cve": "vulnerability",
            "file_hash": "hash",
            "sha1": "hash",
            "sha256": "hash",
            "md5": "hash",
        }
        mapped_kind = aliases.get(norm_kind, norm_kind)
        valid_types = {val for _, val in _TARGET_TYPE_OPTIONS}
        resolved_type = mapped_kind if mapped_kind in valid_types else "auto"

        sel = self.query_one("#res-target-type", Select)
        inp = self.query_one("#res-target-input", Input)
        with sel.prevent(Select.Changed):
            sel.value = resolved_type
        with inp.prevent(Input.Changed):
            inp.value = clean
        self._start_investigation(clean, resolved_type, record_history=True)

    # ------------------------------------------------------------------
    # Instant Type-to-Search & Actions
    # ------------------------------------------------------------------

    def _is_text_or_select_focused(self) -> bool:
        focused = self.app.focused
        if focused is None:
            return False
        if isinstance(focused, (Input, Select)):
            return True
        return any(isinstance(anc, (Input, Select)) for anc in focused.ancestors)

    def _focus_findings_table(self) -> None:
        table = self.query_one("#res-table", DoubleClickDataTable)
        if table.row_count > 0 and not (0 <= table.cursor_row < table.row_count):
            table.move_cursor(row=0, column=0, animate=False)
        self.screen.set_focus(table)

    def _start_type_to_search(self, char: str) -> None:
        search_input = self.query_one("#res-target-input", Input)
        current = search_input.value
        if (
            self._current_dossier is not None
            and self._last_submitted_query
            and current.strip() == self._last_submitted_query
        ):
            search_input.value = char
        else:
            search_input.value = current + char
        search_input.cursor_position = len(search_input.value)
        self.screen.set_focus(search_input)

    def handle_type_to_search_key(self, event: events.Key) -> bool:
        """Start or continue typing in #res-target-input when focus is outside text inputs."""
        if isinstance(self.app.screen, ModalScreen) or self._is_text_or_select_focused():
            return False

        if event.key == "backspace":
            search_input = self.query_one("#res-target-input", Input)
            if search_input.value:
                search_input.value = search_input.value[:-1]
                search_input.cursor_position = len(search_input.value)
                self.screen.set_focus(search_input)
                event.stop()
                event.prevent_default()
                return True
            return False

        if (
            event.character
            and event.is_printable
            and not event.control
            and event.character not in ("\r", "\n", "\t", "/", " ")
        ):
            if event.key in _ALWAYS_RESERVED_KEYS:
                return False
            if self._current_dossier is not None and event.key in _DOSSIER_RESERVED_KEYS:
                return False
            self._start_type_to_search(event.character)
            event.stop()
            event.prevent_default()
            return True
        return False

    def on_key(self, event: events.Key) -> None:
        """Handle instant type-to-search and down-arrow jump to the findings table."""
        focused = self.app.focused
        if event.key == "down" and focused is not None and focused.id in (
            "res-target-input",
            "res-filter-input",
        ):
            self._focus_findings_table()
            event.stop()
            event.prevent_default()
            return
        self.handle_type_to_search_key(event)

    def action_toggle_filter(self) -> None:
        collapsible = self.query_one("#res-options-collapsible", Collapsible)
        collapsible.collapsed = not collapsible.collapsed
        if not collapsible.collapsed:
            self.call_after_refresh(lambda: self.query_one("#res-filter-input", Input).focus())

    def action_collapse_filter(self) -> None:
        collapsible = self.query_one("#res-options-collapsible", Collapsible)
        focused = self.app.focused
        if not collapsible.collapsed:
            collapsible.collapsed = True
            if focused is not None and (
                focused is collapsible or collapsible in focused.ancestors
            ):
                self._focus_findings_table()
        elif focused is not None and focused.id == "res-target-input":
            self._focus_findings_table()
        else:
            filter_input = self.query_one("#res-filter-input", Input)
            if filter_input.value:
                filter_input.value = ""

    def action_toggle_json_view(self) -> None:
        self._detail_mode = "json" if self._detail_mode == "overview" else "overview"
        self.query_one("#res-detail-mode-btn", Button).variant = (
            "primary" if self._detail_mode == "json" else "default"
        )
        self._render_detail_panel()

    def action_open_sources_modal(self) -> None:
        """Open the interactive passive free OSINT Sources modal."""
        if self.is_app_shutting_down():
            return
        inspector = self._build_osint_inspector_client()
        avail = inspector.source_availability()

        def _on_close(result: dict[str, Any] | None) -> None:
            if not isinstance(result, dict):
                return
            action = result.get("action")
            if action == "open_settings":
                self._open_osint_settings()
                return
            if action == "apply":
                chosen = set(result.get("sources") or [])
                self._enabled_osint_sources = chosen
                self._custom_osint_selection = chosen != set(OSINT_MODULES)
                self.set_status(
                    f"Active OSINT sources updated: {len(chosen)}/{len(OSINT_MODULES)} enabled."
                )
                if self._current_dossier is not None and self._last_submitted_query:
                    t_type = str(self.query_one("#res-target-type", Select).value or "auto")
                    self._start_investigation(
                        self._last_submitted_query, t_type, record_history=False
                    )

        self.app.push_screen(
            OSINTSourcesModal(avail, self._enabled_osint_sources),
            callback=_on_close,
        )

    def _open_osint_settings(self) -> None:
        open_fn = getattr(self.app, "open_settings_tab", None)
        if callable(open_fn):
            open_fn(category="cat-osint")
        else:
            self.switch_to_pane("tab-settings")

    def action_history_back(self) -> None:
        self._navigate_history(-1)

    def action_history_forward(self) -> None:
        self._navigate_history(1)

    def _navigate_history(self, delta: int) -> None:
        new_idx = self._history_index + delta
        if new_idx < 0 or new_idx >= len(self._history):
            self.set_status("No further search history in that direction.")
            return
        self._history_index = new_idx
        query, t_type, mode, src_sig = self._history[new_idx]
        self._last_submitted_query = query.strip()
        self._source_mode = mode
        self.query_one("#res-target-input", Input).value = query
        self.query_one("#res-target-type", Select).value = t_type
        mode_sel = self.query_one("#res-source-mode", Select)
        with mode_sel.prevent(Select.Changed):
            mode_sel.value = mode
        cached = self._dossier_cache.get((query, t_type, mode, src_sig))
        if cached is not None:
            self._apply_dossier(cached)
            self.set_status(f"Showing results for '{cached.target.canonical_name}'.")
        else:
            self._start_investigation(query, t_type, record_history=False)

    def _selected_finding(self) -> dict[str, Any] | None:
        if self._selected_index is not None and 0 <= self._selected_index < len(self._visible_rows):
            return self._visible_rows[self._selected_index]
        return None

    def _extract_pivot_from_finding(self, item: dict[str, Any] | None) -> tuple[str, str] | None:
        if not item:
            return None
        if item.get("example_query"):
            return str(item["example_query"]), "auto"
        target = item.get("pivot_target")
        if target:
            return str(target), str(item.get("pivot_kind") or "auto")
        return None

    def action_pivot_selected(self) -> None:
        item = self._selected_finding()
        piv = self._extract_pivot_from_finding(item)
        if piv is None:
            self.set_status("Select a Related Entity, Actor, or Sample finding to search.")
            return
        eid, pkind = piv
        valid_types = {val for _, val in _TARGET_TYPE_OPTIONS}
        t_type = pkind if pkind in valid_types else "auto"
        self.query_one("#res-target-input", Input).value = eid
        self.query_one("#res-target-type", Select).value = t_type
        self._start_investigation(eid, t_type, record_history=True)

    def action_open_context_menu(self) -> None:
        self._open_research_context_menu(origin=(4, 4))

    # ------------------------------------------------------------------
    # Button / Input / Table Event Handlers
    # ------------------------------------------------------------------

    @on(Input.Submitted, "#res-target-input")
    @on(Button.Pressed, "#res-investigate-btn")
    def handle_investigate(self) -> None:
        query = self.query_one("#res-target-input", Input).value.strip()
        if not query:
            self.set_status("Enter an IP, domain (badsite.com), hash, URL, CVE, ASN, malware, actor, or topic.")
            return
        t_type = str(self.query_one("#res-target-type", Select).value or "auto")
        self._start_investigation(query, t_type, record_history=True)
        focused = self.app.focused
        if focused is not None and focused.id in ("res-target-input", "res-investigate-btn"):
            self._focus_findings_table()

    @on(Select.Changed, "#res-source-mode")
    def handle_source_mode_changed(self, event: Select.Changed) -> None:
        if event.value is Select.BLANK:
            return
        new_mode = str(event.value or "all")
        if new_mode == self._source_mode:
            return
        self._source_mode = new_mode
        mode_lbl = {"all": "RF + OSINT", "osint": "OSINT Only", "rf": "RF Only"}.get(new_mode, new_mode)
        self.set_status(f"Search mode set to {mode_lbl}.")
        if self._current_dossier is not None and self._last_submitted_query:
            t_type = str(self.query_one("#res-target-type", Select).value or "auto")
            self._start_investigation(self._last_submitted_query, t_type, record_history=True)

    @on(Button.Pressed, "#res-sources-btn")
    def handle_sources_btn(self) -> None:
        self.action_open_sources_modal()

    @on(Button.Pressed, "#res-back-btn")
    def handle_back(self) -> None:
        self._navigate_history(-1)

    @on(Button.Pressed, "#res-fwd-btn")
    def handle_forward(self) -> None:
        self._navigate_history(1)

    @on(Button.Pressed, "#res-detail-mode-btn")
    def handle_toggle_json_btn(self) -> None:
        self.action_toggle_json_view()

    @on(Button.Pressed, "#res-pivot-btn")
    def handle_pivot_btn(self) -> None:
        self.action_pivot_selected()

    @on(Button.Pressed, "#res-export-md-btn")
    def handle_export_md(self) -> None:
        self._export_current("markdown")

    @on(Button.Pressed, "#res-export-json-btn")
    def handle_export_json(self) -> None:
        self._export_current("json")

    def _export_current(self, fmt: str) -> None:
        if self._current_dossier is None:
            self.set_status("Run a search before exporting.")
            return
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        slug = (
            "".join(
                ch if ch.isalnum() or ch in ("-", "_", ".") else "_"
                for ch in self._current_dossier.target.canonical_name
            )[:48]
            or "research"
        )
        ext = "json" if fmt == "json" else "md"
        out_path = self.workspace_dir / "reports" / f"rf_research_{slug}_{stamp}.{ext}"
        try:
            written = (
                export_dossier_json(self._current_dossier, out_path)
                if fmt == "json"
                else export_dossier_markdown(self._current_dossier, out_path)
            )
            msg = f"Exported {fmt.upper()} report to {written}"
            self.set_status(msg)
            self.notify_user(msg, title="Export Complete")
        except Exception as exc:
            self.report_error("Export Report", exc)

    @on(Input.Changed, "#res-filter-input")
    def handle_filter_changed(self) -> None:
        self._render_master_table()

    @on(Select.Changed, "#res-source-group-filter")
    def handle_source_group_filter_changed(self, event: Select.Changed) -> None:
        if event.value is Select.BLANK:
            return
        self._source_group_filter = str(event.value or "all")
        self._render_master_table()

    @on(Select.Changed, "#res-category-filter")
    def handle_category_filter_changed(self, event: Select.Changed) -> None:
        if event.value is Select.BLANK:
            return
        self._category_filter = str(event.value or "all")
        self._render_master_table()

    @on(Select.Changed, "#res-timeframe-preset")
    def handle_timeframe_preset_changed(self, event: Select.Changed) -> None:
        if self._syncing_timeframe or event.value is Select.BLANK:
            return
        val = str(event.value or "-30d")
        if val != "custom":
            self._syncing_timeframe = True
            try:
                self.query_one("#res-links-timeframe", Input).value = val
            finally:
                self._syncing_timeframe = False

    @on(Input.Changed, "#res-links-timeframe")
    def handle_links_timeframe_changed(self) -> None:
        if self._syncing_timeframe:
            return
        raw = self.query_one("#res-links-timeframe", Input).value.strip()
        preset_vals = {val for _, val in _RES_TIMEFRAME_PRESETS if val != "custom"}
        target = raw if raw in preset_vals else "custom"
        try:
            sel = self.query_one("#res-timeframe-preset", Select)
            if str(sel.value) != target:
                self._syncing_timeframe = True
                try:
                    sel.value = target
                finally:
                    self._syncing_timeframe = False
        except Exception:
            pass

    @on(Button.Pressed, "#res-clear-filter-btn")
    def handle_clear_filters(self) -> None:
        self._category_filter = "all"
        self._source_group_filter = "all"
        try:
            self.query_one("#res-filter-input", Input).value = ""
            sel = self.query_one("#res-category-filter", Select)
            with sel.prevent(Select.Changed):
                sel.value = "all"
            src_sel = self.query_one("#res-source-group-filter", Select)
            with src_sel.prevent(Select.Changed):
                src_sel.value = "all"
        except Exception:
            pass
        self._render_master_table()
        self.set_status("Cleared Research result filters.")

    @on(DataTable.RowHighlighted, "#res-table")
    def handle_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self._rendering_table:
            return
        if 0 <= event.cursor_row < len(self._visible_rows):
            self._selected_index = event.cursor_row
            self._render_detail_panel()

    @on(DoubleClickDataTable.RowSelected, "#res-table")
    def handle_row_selected(self, event: DoubleClickDataTable.RowSelected) -> None:
        if self._rendering_table:
            return
        if 0 <= event.cursor_row < len(self._visible_rows):
            self._selected_index = event.cursor_row
            item = self._visible_rows[event.cursor_row]
            kind = str(item.get("kind") or "")
            if kind == "note" and item.get("note_id"):
                self._lookup_note_worker(str(item["note_id"]))
                return
            if kind in ("example", "pivot", "actor", "malware_sample", "sandbox"):
                if self._extract_pivot_from_finding(item) is not None:
                    self.action_pivot_selected()
                    return
            self._render_detail_panel()

    def _get_copyable_detail(self) -> tuple[str, str, str | None]:
        """Return ``(text, title, language)`` for copying or viewing the active research detail."""
        item = self._selected_finding()
        if self._detail_mode == "json":
            payload: Any = None
            if item is not None and item.get("kind") != "example":
                payload = item.get("payload")
                if isinstance(payload, ResearchDossier):
                    payload = payload.to_dict()
                elif hasattr(payload, "__dict__"):
                    payload = payload.__dict__
            elif self._current_dossier is not None:
                payload = self._current_dossier.to_dict()
            if payload is not None:
                title = str((item or {}).get("title") or "Research JSON")
                return json.dumps(payload, indent=2, default=str), f"Research JSON - {title}", "json"
        try:
            text = extract_richlog_text(self.query_one("#res-detail-log", RichLog))
        except Exception:
            text = ""
        title = str((item or {}).get("title") or "Research Detail")
        return text, title, None

    @on(Button.Pressed, "#res-copy-detail-btn")
    def handle_copy_detail(self) -> None:
        text, _title, _lang = self._get_copyable_detail()
        self.copy_to_clipboard(text, label="Research Detail")

    def _copy_selected_row(self, row_index: int | None = None) -> None:
        table = self.query_one("#res-table", DataTable)
        text = extract_table_row_text(table, row_index=row_index)
        self.copy_to_clipboard(text, label="Research Row")

    def _open_detail_copy_modal(self) -> None:
        text, title, lang = self._get_copyable_detail()
        self.open_copy_modal(text, title=title, language=lang)

    def _open_research_context_menu(self, *, origin: tuple[int, int]) -> None:
        item = self._selected_finding()
        piv = self._extract_pivot_from_finding(item)
        items: list[tuple[str, str]] = []
        if piv is not None:
            items.append(("pivot", f"Search '{truncate_text(piv[0], 26)}'"))
            if bool(getattr(self.app, "is_admin_view", True)):
                items.append(("send_watchlist", "Send Entity to Watchlists Tab"))
            items.append(("send_rf_intel", "Lookup Entity in RF Intel Tab"))
            items.append(("send_splunk", "Hunt Entity in Splunk Search"))
        if self._current_dossier is not None:
            items.append(("send_llm", "Analyze Unified Brief with Local LLM"))
        items.extend(
            [
                ("configure_osint", "Configure Free OSINT Sources..."),
                ("open_osint_settings", "Configure Free OSINT API Keys (Settings)"),
                (
                    "toggle_json",
                    "Switch to Intelligence View" if self._detail_mode == "json" else "Switch to Raw JSON",
                ),
                ("copy_row", "Copy Selected Row"),
                ("copy_detail", "Copy Detail Panel"),
                ("open_copy_view", "Open Copyable View"),
                ("export_md", "Export Markdown Report"),
                ("export_json", "Export JSON Report"),
                ("open_logs", "Open Research Logs"),
            ]
        )

        def _on_select(action_id: str) -> None:
            if action_id == "pivot":
                self.action_pivot_selected()
            elif action_id == "send_watchlist" and piv is not None:
                self._send_to_watchlists(piv[0], piv[1])
            elif action_id == "send_rf_intel" and piv is not None:
                self._send_to_rf_intel(piv[0], piv[1])
            elif action_id == "send_splunk" and piv is not None:
                self._send_to_splunk(piv[0], piv[1])
            elif action_id == "send_llm":
                self._send_to_llm()
            elif action_id == "configure_osint":
                self.action_open_sources_modal()
            elif action_id == "open_osint_settings":
                self._open_osint_settings()
            elif action_id == "toggle_json":
                self.action_toggle_json_view()
            elif action_id == "copy_row":
                self._copy_selected_row()
            elif action_id == "copy_detail":
                self.handle_copy_detail()
            elif action_id == "open_copy_view":
                self._open_detail_copy_modal()
            elif action_id == "export_md":
                self.handle_export_md()
            elif action_id == "export_json":
                self.handle_export_json()
            elif action_id == "open_logs":
                open_fn = getattr(self.app, "open_logs_tab", None)
                if callable(open_fn):
                    open_fn(source="research")

        self.open_context_menu(
            items,
            title="Research Actions",
            origin=origin,
            on_select=_on_select,
        )

    def _send_to_watchlists(self, entity_value: str, kind: str) -> None:
        clean_val = entity_value.strip()
        for prefix in ("ip:", "idn:", "hash:"):
            if clean_val.lower().startswith(prefix):
                clean_val = clean_val[len(prefix) :].strip()
                break

        type_map = {
            "ip": "IpAddress",
            "domain": "InternetDomainName",
            "hash": "Hash",
            "url": "URL",
            "vulnerability": "CyberVulnerability",
            "company": "Company",
        }
        wl_type = type_map.get(kind, "InternetDomainName")

        def _fill(wl_pane: BaseSocPane) -> None:
            wl_pane.query_one("#wl-ent-type", Input).value = wl_type
            wl_pane.query_one("#wl-ent-value", Input).value = clean_val
            wl_pane.query_one("#wl-ent-value", Input).focus()
            wl_pane.set_status(f"Populated entity from Research: {wl_type} = {clean_val}")

        self.switch_to_pane("tab-watchlists", auto_enable_admin=True, on_ready=_fill)

    def _send_to_rf_intel(self, entity_value: str, kind: str) -> None:
        from soclens.tui.screens.rf_intel import RFIntelPane

        def _fill(pane: BaseSocPane) -> None:
            if isinstance(pane, RFIntelPane):
                pane.lookup_from_watchlist(kind, entity_value)

        self.switch_to_pane("tab-rf-intel", on_ready=_fill)

    def _send_to_splunk(self, entity_value: str, kind: str) -> None:
        clean_val = entity_value.strip()
        for prefix in ("ip:", "idn:", "hash:", "url:", "email:", "asn:", "mitre:"):
            if clean_val.lower().startswith(prefix):
                clean_val = clean_val[len(prefix) :].strip()
                break
        dispatch = getattr(self.app, "dispatch_pivot", None)
        if callable(dispatch):
            dispatch(
                PivotPayload(
                    source_tab="tab-research",
                    target_tab="tab-splunk-search",
                    entity=clean_val,
                    entity_type=kind,
                )
            )

    def _send_to_llm(self) -> None:
        if self._current_dossier is None:
            self.set_status("Run a search before sending to Local LLM.")
            return
        open_llm = getattr(self.app, "open_llm_with_context", None)
        if callable(open_llm):
            md = render_dossier_markdown(self._current_dossier)
            open_llm(
                f"Unified RF + OSINT Brief: {self._current_dossier.target.canonical_name}",
                md[:8000],
                template="triage_alert",
                auto_send=False,
            )

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def _start_investigation(self, query: str, explicit_type: str, *, record_history: bool) -> None:
        self._last_submitted_query = query.strip()
        source_mode = self._source_mode
        sources_sig = self._active_sources_sig()
        if record_history:
            self._push_history(query, explicit_type, source_mode, sources_sig)
        links_tf = self.query_one("#res-links-timeframe", Input).value.strip() or "-30d"
        limit = self._parse_limit(20)
        deep = bool(self.query_one("#res-deep-check", Checkbox).value)
        self._request_seq += 1
        seq = self._request_seq
        mode_desc = {
            "all": "RF + OSINT",
            "osint": "Free Passive OSINT",
            "rf": "Recorded Future",
        }.get(source_mode, source_mode)
        banner_source_desc = {
            "all": "Recorded Future + Passive OSINT",
            "osint": "Free Passive OSINT",
            "rf": "Recorded Future",
        }.get(source_mode, mode_desc)
        self.set_status(f"Searching ({mode_desc}) for '{query}'...")
        self.query_one("#res-mood-strip", ResearchMoodBanner).set_mood(
            determine_research_mood(
                None,
                searching=True,
                query=query,
                source_desc=banner_source_desc,
            )
        )
        self._investigate_worker(
            seq,
            query,
            explicit_type,
            deep=deep,
            links_timeframe=links_tf,
            limit=limit,
            source_mode=source_mode,
            sources_sig=sources_sig,
            osint_sources=sorted(self._enabled_osint_sources) if self._custom_osint_selection else None,
            osint_client=self._get_osint_client(),
        )

    @work(thread=True, exit_on_error=False)
    def _investigate_worker(
        self,
        seq: int,
        query: str,
        explicit_type: str,
        *,
        deep: bool,
        links_timeframe: str,
        limit: int,
        source_mode: str,
        sources_sig: tuple[str, ...],
        osint_sources: list[str] | None,
        osint_client: OSINTClient | None,
    ) -> None:
        try:
            include_rf = source_mode in ("all", "rf")
            include_osint = source_mode in ("all", "osint")
            self.append_log(
                f"Research search started: {query} (type={explicit_type}, mode={source_mode}, deep={deep})"
            )
            with self.log_scope("research"):
                dossier = research_target(
                    self.client if include_rf else None,
                    query,
                    explicit_type=explicit_type,
                    deep=deep,
                    links_timeframe=links_timeframe,
                    limit=limit,
                    include_rf=include_rf,
                    include_osint=include_osint,
                    osint_sources=osint_sources,
                    osint_client=osint_client,
                    workspace_dir=self.workspace_dir,
                    access_registry=getattr(self.app, "api_access", None),
                )
            if seq != self._request_seq or self.is_app_shutting_down():
                return
            self._dossier_cache[(query, explicit_type, source_mode, sources_sig)] = dossier
            self.run_on_ui(self._apply_dossier, dossier)
            self.append_log(f"Research search completed: {dossier.target.canonical_name}")
        except Exception as exc:
            if seq == self._request_seq:
                self.report_error("Threat Research", exc)

    def _apply_dossier(self, dossier: ResearchDossier) -> None:
        self._current_dossier = dossier
        self._all_findings = build_research_findings(dossier)
        self._selected_index = 0
        self.query_one("#res-mood-strip", ResearchMoodBanner).set_mood(
            determine_research_mood(dossier)
        )
        self._render_master_table()
        self._render_detail_panel()
        findings_cnt = max(0, len(self._all_findings) - 1)
        notes: list[str] = []
        if dossier.risk_score is not None:
            notes.append(f"RF Risk {dossier.risk_score}/99")
        if dossier.osint_sections:
            ok_cnt = sum(1 for s in dossier.osint_sections.values() if s.status == "ok")
            notes.append(f"OSINT {ok_cnt}/{len(dossier.osint_sections)} hit(s)")
        extra = f" | {' | '.join(notes)}" if notes else ""
        self.set_status(
            f"Results for '{dossier.target.canonical_name}'{extra} ({findings_cnt} finding(s))."
        )

    @work(thread=True, exit_on_error=False)
    def _lookup_note_worker(self, note_id: str) -> None:
        try:
            with self.log_scope("research"):
                full_note = self.client.lookup_analyst_note(note_id, serialization="full")
            if self.is_app_shutting_down():
                return

            def _apply_note() -> None:
                for row in self._all_findings:
                    if row.get("kind") == "note" and str(row.get("note_id")) == note_id:
                        payload = row.get("payload")
                        if isinstance(payload, dict):
                            payload.update(full_note)
                self._render_detail_panel()
                self.set_status("Loaded full threat report.")

            self.run_on_ui(_apply_note)
        except Exception as exc:
            self.report_error("Threat Report Lookup", exc)

    # ------------------------------------------------------------------
    # Table & Detail Rendering
    # ------------------------------------------------------------------

    def _render_master_table(self) -> None:
        if not self._tables_ready:
            return
        table = self.query_one("#res-table", DoubleClickDataTable)
        filt = self.query_one("#res-filter-input", Input).value.strip().lower()

        self._rendering_table = True
        try:
            table.clear(columns=True)
            for key, label, _, _ in _FINDING_SPECS:
                table.add_column(label, key=key)

            rows_source = self._all_findings
            cat_filter = self._category_filter.strip().lower()
            src_filter = self._source_group_filter.strip().lower()
            visible = [
                row
                for row in rows_source
                if (
                    cat_filter == "all"
                    or str(row.get("category") or "").strip().lower() == cat_filter
                )
                and (
                    src_filter == "all"
                    or str(row.get("source_group") or "rf").strip().lower() in (src_filter, "unified")
                )
                and (not filt or filt in str(row.get("search_blob") or row).lower())
            ]
            self._visible_rows = visible

            if self._current_dossier is None:
                self.query_one("#res-master-header", Static).update("Example Searches")
            else:
                self.query_one("#res-master-header", Static).update(
                    f"Findings ({len(visible)})"
                )

            for idx, item in enumerate(visible):
                cat = str(item.get("category") or "-")
                cat_style = {
                    "Summary": "bold cyan",
                    "WHOIS": "bold green",
                    "DNS": "bold green",
                    "Network": "green",
                    "Certificates": "cyan",
                    "Reputation": "bold yellow",
                    "Web Intel": "cyan",
                    "Vulnerability": "bold red",
                    "File Intel": "bold green",
                    "Sources": "dim",
                    "Report": "blue",
                    "Actor": "bold magenta",
                    "Threat Map": "magenta",
                    "Related": "green",
                    "Rule": "yellow",
                    "Alert": "bold red",
                    "Sample": "bold yellow",
                }.get(cat, "white")
                src_lbl = str(item.get("source_label") or ("OSINT" if item.get("source_group") == "osint" else "RF"))
                src_style = (
                    "bold cyan"
                    if src_lbl in ("Unified", "RF+OSINT")
                    else ("green" if item.get("source_group") == "osint" else "blue")
                )
                table.add_row(
                    Text(cat, style=cat_style),
                    Text(src_lbl, style=src_style),
                    truncate_text(str(item.get("title") or "-"), 42),
                    truncate_text(str(item.get("detail") or "-"), 48),
                    key=str(idx),
                )

            if visible:
                target_idx = (
                    self._selected_index
                    if self._selected_index is not None and 0 <= self._selected_index < len(visible)
                    else 0
                )
                self._selected_index = target_idx
                table.move_cursor(row=target_idx, column=0, animate=False)
            else:
                self._selected_index = None

            self.query_one("#res-summary-bar", Static).update(
                build_search_summary_bar(
                    self._current_dossier,
                    len(rows_source),
                    len(visible),
                )
            )
            self.call_after_refresh(self._fit_table)
        finally:
            self._rendering_table = False

    def _render_detail_panel(self) -> None:
        if not self._tables_ready:
            return
        log_widget = self.query_one("#res-detail-log", RichLog)
        header = self.query_one("#res-detail-header", Static)
        avail = log_widget.scrollable_content_region.width
        width = max(44, avail) if avail > 0 else None
        self._last_detail_width = avail
        log_widget.clear()

        item = self._selected_finding()
        if item is None or item.get("kind") == "example":
            if self._current_dossier is not None:
                header.update("Intelligence Brief")
                renderable = (
                    render_research_json(self._current_dossier.to_dict())
                    if self._detail_mode == "json"
                    else render_finding_detail({"kind": "brief", "payload": self._current_dossier}, self._current_dossier)
                )
            else:
                header.update("Threat Research (RF + Free OSINT)")
                renderable = render_research_welcome(osint_client=self._build_osint_inspector_client())
            log_widget.write(renderable, width=width, expand=True, scroll_end=False)
            log_widget.scroll_home(animate=False)
            return

        if self._detail_mode == "json":
            header.update("Raw JSON")
            payload = item.get("payload")
            if isinstance(payload, ResearchDossier):
                payload = payload.to_dict()
            elif hasattr(payload, "__dict__"):
                payload = payload.__dict__
            log_widget.write(render_research_json(payload), width=width, expand=True, scroll_end=False)
            log_widget.scroll_home(animate=False)
            return

        header.update(truncate_text(str(item.get("title") or "Intelligence Brief"), 54))
        renderable = render_finding_detail(item, self._current_dossier)
        log_widget.write(renderable, width=width, expand=True, scroll_end=False)
        log_widget.scroll_home(animate=False)

    def report_error(self, context: str, exc: Exception) -> None:
        """Surface errors cleanly in status, toast, and detail pane."""
        if self.is_app_shutting_down():
            return
        if isinstance(exc, RecordedFutureError) and getattr(exc, "reason", None) == "cancelled":
            def _reset_cancelled_banner() -> None:
                try:
                    self.query_one("#res-mood-strip", ResearchMoodBanner).set_mood(
                        determine_research_mood(None)
                    )
                except Exception:
                    pass

            self.run_on_ui(_reset_cancelled_banner)
            return
        detail = self.format_exception(exc)
        self.set_status(f"Search failed: {detail}")
        self.append_log(f"[-] {context}: {detail}", level="ERROR")
        self.notify_user(detail, title=context, severity="error")

        def _render_err() -> None:
            log_widget = self.query_one("#res-detail-log", RichLog)
            avail = log_widget.scrollable_content_region.width
            width = max(44, avail) if avail > 0 else None
            self._last_detail_width = avail
            log_widget.clear()
            log_widget.write(render_error_panel(context, detail), width=width, expand=True, scroll_end=False)
            log_widget.scroll_home(animate=False)
            self.query_one("#res-detail-header", Static).update(
                Text(f"Error: {context}", style="bold red")
            )
            self.query_one("#res-mood-strip", ResearchMoodBanner).set_mood(
                determine_research_mood(None, error=detail)
            )

        self.run_on_ui(_render_err)

    def on_timezone_changed(self, tz_name: str) -> None:
        """Rebuild dossier findings & detail timestamps when the active timezone changes."""
        _ = tz_name
        if self._current_dossier is None:
            return
        prev_idx = self._selected_index
        self._all_findings = build_research_findings(self._current_dossier)
        self._render_master_table()
        if prev_idx is not None and 0 <= prev_idx < len(self._visible_rows):
            self._selected_index = prev_idx
        self._last_detail_width = 0
        self._render_detail_panel()
