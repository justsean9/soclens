"""Watchlist and entity management pane covering all 21 Recorded Future list types."""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from rich.text import Text
from textual import events, on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.coordinate import Coordinate
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Collapsible,
    DataTable,
    Input,
    Select,
    Static,
    TabbedContent,
)

from soclens.client import LIST_TYPES, RecordedFutureClient
from soclens.tui.screens.base import BaseSocPane, DoubleClickDataTable
from soclens.tui.screens.brand_logos import BrandLogosPane
from soclens.tui.screens.rf_intel import RFIntelPane
from soclens.watchlist import (
    export_watchlist,
    filter_watchlist_entities,
    sort_watchlist_entities,
    sort_watchlists,
)

_LIST_COLUMN_SPECS: tuple[tuple[str, float, int], ...] = (
    ("name", 0.78, 24),
    ("type", 0.22, 10),
)
_ENTITY_COLUMN_SPECS: tuple[tuple[str, float, int], ...] = (
    ("name", 0.38, 18),
    ("type", 0.18, 10),
    ("status", 0.12, 8),
    ("annotation", 0.32, 14),
)
_LIST_COLUMN_LABELS: dict[str, str] = {
    "name": "Name",
    "type": "Type",
}
_ENTITY_COLUMN_LABELS: dict[str, str] = {
    "name": "Name",
    "type": "Type",
    "status": "Status",
    "annotation": "Annotation",
}
_ENTITY_SORT_CYCLE: tuple[str, ...] = (
    "none",
    "name",
    "id",
    "type",
    "status",
    "annotation",
)
_ENTITY_SORT_DISPLAY: dict[str, str] = {
    "none": "Default",
    "name": "Name",
    "id": "Entity ID",
    "type": "Type",
    "status": "Status",
    "annotation": "Annotation",
}
_ENTITY_SORT_OPTIONS: list[tuple[str, str]] = [
    (f"Sort: {_ENTITY_SORT_DISPLAY[key]}", key) for key in _ENTITY_SORT_CYCLE
]
_RESERVED_TYPE_FILTER_KEYS: frozenset[str] = frozenset(
    {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "q", "r", "m", "slash", "space"}
)


class _WatchlistSelectTable(DoubleClickDataTable):
    """DataTable that opens a watchlist on single left-click while keeping header sorts."""

    async def _on_click(self, event: events.Click) -> None:
        if event.button != 1:
            return

        event.prevent_default()
        self._set_hover_cursor(True)
        meta = event.style.meta
        if "row" not in meta or "column" not in meta:
            return
        if self.cursor_type != "row" and meta.get("out_of_bounds", False):
            return

        row_index = int(meta["row"])
        column_index = int(meta["column"])
        is_header_click = self.show_header and row_index == -1
        is_row_label_click = self.show_row_labels and column_index == -1
        if is_header_click or is_row_label_click:
            await super()._on_click(event)
            return

        if event.chain >= 2:
            event.stop()
            return

        if (
            self.show_cursor
            and self.cursor_type != "none"
            and self.is_valid_row_index(row_index)
        ):
            self.cursor_coordinate = Coordinate(row_index, max(0, column_index))
            self._last_click_row = None
            self._last_click_time = 0.0
            self._post_selected_message()
            self._scroll_cursor_into_view(animate=True)
            event.stop()


class WatchlistsPane(BaseSocPane):
    """Interactive Recorded Future Lists & Watchlists manager."""

    STATUS_ID = "wl-status"
    LOG_ID = ""
    LOG_SOURCE = "watchlists"

    DEFAULT_CSS: ClassVar[str] = """
    WatchlistsPane .wl-hidden {
        display: none;
    }
    WatchlistsPane #wl-workspace {
        layout: vertical;
        width: 1fr;
        height: 1fr;
        min-height: 8;
    }
    WatchlistsPane #wl-lists-pane,
    WatchlistsPane #wl-entities-pane {
        width: 1fr;
        height: 1fr;
        margin-right: 0;
    }
    WatchlistsPane #wl-entities-footer-bar {
        height: auto;
        width: 1fr;
        margin-top: 0;
    }
    WatchlistsPane #wl-back-btn,
    WatchlistsPane #wl-back-bottom-btn,
    WatchlistsPane #wl-copy-id-btn,
    WatchlistsPane #wl-entities-copy-id-btn,
    WatchlistsPane #wl-entities-copy-id-bottom-btn,
    WatchlistsPane #wl-entities-reload-btn {
        min-width: 10;
    }
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("slash", "toggle_filter", "Search/Filter"),
        Binding("f4", "copy_list_id", "Copy List ID"),
        Binding("f6", "cycle_entity_sort", "Sort"),
        Binding("r", "reload_watchlists", "Reload Lists"),
        Binding("m", "open_context_menu", "Menu"),
        Binding("escape", "collapse_filter", "Back / Close Filter", show=False),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._all_watchlists: list[dict[str, Any]] = []
        self._visible_watchlists: list[dict[str, Any]] = []
        self._row_key_to_watchlist: dict[str, dict[str, Any]] = {}
        self._loaded_type_filter: str = "all"
        self._auto_load_started: bool = False
        self._has_loaded_lists_once: bool = False
        self._current_entities: list[dict[str, Any]] = []
        self._visible_entities: list[dict[str, Any]] = []
        self._row_key_to_entity: dict[str, dict[str, Any]] = {}
        self._current_list_id: str = ""
        self._current_list_name: str = ""
        self._lists_request_seq: int = 0
        self._entities_request_seq: int = 0
        self._tables_ready: bool = False
        self._pending_activation: bool = False
        self._view_stage: Literal["lists", "entities"] = "lists"
        self._entity_sort_by: str = "none"
        self._entity_sort_desc: bool = False
        self._list_sort_by: str = "none"
        self._list_sort_desc: bool = False
        self._selected_entity: dict[str, str] | None = None

    def compose(self) -> ComposeResult:
        yield Static("Recorded Future Lists & Watchlists", classes="pane-title")
        yield Static(
            "Ready. Click or press Enter on any watchlist to expand entities; "
            "click headers to sort or Copy List ID (F4) for its ID.",
            id="wl-status",
            classes="status-bar",
            markup=False,
        )

        options: list[tuple[str, str]] = [("All 21 List Types", "all")] + [
            (lt, lt) for lt in LIST_TYPES
        ]
        with Collapsible(
            title="Search & Filter [All 21 types] (press / or start typing)",
            collapsed=True,
            collapsed_symbol=">",
            expanded_symbol="v",
            id="wl-filter-collapsible",
        ):
            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    placeholder="Filter watchlists by name, type, or ID...",
                    id="wl-search-input",
                    select_on_focus=False,
                    compact=True,
                )
                yield Select(
                    options,
                    allow_blank=False,
                    value="all",
                    id="wl-type-filter",
                    compact=True,
                )
                yield Button("Clear", id="wl-clear-filter-btn", compact=True)
            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    placeholder="Filter loaded entities by name, ID, type, status, or annotation...",
                    id="wl-entity-search-input",
                    select_on_focus=False,
                    compact=True,
                )
                yield Select(
                    _ENTITY_SORT_OPTIONS,
                    allow_blank=False,
                    value="none",
                    id="wl-entity-sort-select",
                    compact=True,
                )
            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    placeholder="Optional direct Target List ID override (e.g. report:abc123)",
                    id="wl-target-list-id",
                    compact=True,
                )

        with Horizontal(classes="action-row toolbar-row"):
            yield Button("Load Watchlists", id="wl-load-btn", variant="primary", compact=True)
            yield Button("Open Watchlist", id="wl-entities-btn", compact=True)
            yield Button("Copy List ID", id="wl-copy-id-btn", compact=True)

        with Horizontal(classes="action-row toolbar-row"):
            yield Input(
                value="InternetDomainName",
                placeholder="Entity type (e.g. InternetDomainName, Hash)",
                id="wl-ent-type",
                compact=True,
            )
            yield Input(placeholder="Entity value or ID", id="wl-ent-value", compact=True)
            yield Button("Add Entity", id="wl-add-btn", compact=True)
            yield Button("Remove Entity", id="wl-remove-btn", variant="warning", compact=True)

        with Horizontal(classes="action-row toolbar-row"):
            yield Input(placeholder="New list name", id="wl-create-name", compact=True)
            yield Button("Create List", id="wl-create-btn", compact=True)
            yield Input(placeholder="Export path (CSV or JSON)", id="wl-export-path", compact=True)
            yield Button("Export List", id="wl-export-btn", compact=True)

        with Container(id="wl-workspace", classes="split-workspace"):
            with Vertical(id="wl-lists-pane", classes="table-pane"):
                yield Static(
                    "Watchlists (click or press Enter to expand entities)",
                    id="wl-lists-header",
                    classes="section-label",
                    markup=False,
                )
                yield _WatchlistSelectTable(id="wl-lists-table")
            with Vertical(id="wl-entities-pane", classes="table-pane wl-hidden"):
                with Horizontal(id="wl-entities-toolbar", classes="detail-toolbar"):
                    yield Button(
                        "<- Back to Watchlists",
                        id="wl-back-btn",
                        variant="primary",
                        compact=True,
                    )
                    yield Static(
                        "Watchlist Entities",
                        id="wl-entities-header",
                        classes="section-label",
                        markup=False,
                    )
                    yield Button("Copy List ID", id="wl-entities-copy-id-btn", compact=True)
                    yield Button("Reload", id="wl-entities-reload-btn", compact=True)
                    yield Button("Sort: Default", id="wl-sort-cycle-btn", compact=True)
                    yield Button("Asc ^", id="wl-sort-dir-btn", compact=True)
                yield DoubleClickDataTable(id="wl-entities-table")
                with Horizontal(id="wl-entities-footer-bar", classes="action-row toolbar-row"):
                    yield Button(
                        "<- Back to Watchlists",
                        id="wl-back-bottom-btn",
                        variant="primary",
                        compact=True,
                    )
                    yield Button(
                        "Copy List ID",
                        id="wl-entities-copy-id-bottom-btn",
                        compact=True,
                    )

    def on_mount(self) -> None:
        lists_table = self.query_one("#wl-lists-table", DataTable)
        lists_table.cursor_type = "row"
        lists_table.zebra_stripes = True
        lists_table.add_column("Name", key="name")
        lists_table.add_column("Type", key="type")

        ent_table = self.query_one("#wl-entities-table", DataTable)
        ent_table.cursor_type = "row"
        ent_table.zebra_stripes = True
        ent_table.add_column("Name", key="name")
        ent_table.add_column("Type", key="type")
        ent_table.add_column("Status", key="status")
        ent_table.add_column("Annotation", key="annotation")

        self._tables_ready = True
        self._set_view_stage("lists", focus_table=False)
        if self._pending_activation or getattr(self.app, "initial_tab", "") == "tab-watchlists":
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
        workspace = self.query_one("#wl-workspace", Container)
        workspace.remove_class("split-horizontal")
        self.call_after_refresh(self._fit_tables)

    def _set_view_stage(
        self, stage: Literal["lists", "entities"], *, focus_table: bool = True
    ) -> None:
        self._view_stage = stage
        lists_pane = self.query_one("#wl-lists-pane", Vertical)
        entities_pane = self.query_one("#wl-entities-pane", Vertical)
        if stage == "entities":
            lists_pane.add_class("wl-hidden")
            entities_pane.remove_class("wl-hidden")
        else:
            entities_pane.add_class("wl-hidden")
            lists_pane.remove_class("wl-hidden")
        self._update_responsive_layout()
        if focus_table:
            target_id = "#wl-entities-table" if stage == "entities" else "#wl-lists-table"
            self.call_after_refresh(lambda: self._focus_table_if_visible(target_id))

    def _focus_table_if_visible(self, table_id: str) -> None:
        if self.is_app_shutting_down() or not self._tables_ready:
            return
        try:
            self.query_one(table_id, DataTable).focus()
        except Exception:
            pass

    def _fit_tables(self) -> None:
        if self.is_app_shutting_down() or not self._tables_ready:
            return
        try:
            if self._view_stage == "entities":
                self.fit_table_columns(
                    self.query_one("#wl-entities-table", DataTable),
                    _ENTITY_COLUMN_SPECS,
                )
            else:
                self.fit_table_columns(
                    self.query_one("#wl-lists-table", DataTable),
                    _LIST_COLUMN_SPECS,
                )
        except Exception:
            pass

    def on_settings_updated(self) -> None:
        if not self._all_watchlists:
            self._auto_load_started = False
            self.set_status("Settings updated. Open Watchlists or click 'Load Watchlists'.")

    def _maybe_auto_load(self) -> None:
        if self._auto_load_started:
            return
        self._auto_load_started = True
        if isinstance(self.client, RecordedFutureClient) and not self.client.api_token:
            self.set_status(
                "RF_API_TOKEN not configured. Open Settings (0 / F10) or set RF_API_TOKEN and click 'Load Watchlists'."
            )
            return
        type_filter = str(self.query_one("#wl-type-filter", Select).value)
        self._start_load_watchlists(None if type_filter == "all" else type_filter)

    def _update_filter_title(self) -> None:
        type_val = str(self.query_one("#wl-type-filter", Select).value)
        wl_q = self.query_one("#wl-search-input", Input).value.strip()
        ent_q = self.query_one("#wl-entity-search-input", Input).value.strip()

        parts: list[str] = ["All 21 types" if type_val == "all" else f"type: {type_val}"]
        if wl_q:
            parts.append(f'list: "{wl_q}"')
        if ent_q:
            parts.append(f'entity: "{ent_q}"')
        if self._entity_sort_by != "none":
            arrow = "v" if self._entity_sort_desc else "^"
            sort_label = _ENTITY_SORT_DISPLAY.get(self._entity_sort_by, self._entity_sort_by)
            parts.append(f"sort: {sort_label} {arrow}")

        collapsible = self.query_one("#wl-filter-collapsible", Collapsible)
        collapsible.title = f"Search & Filter [{' | '.join(parts)}] (press / or start typing)"

    @staticmethod
    def _update_table_sort_headers(
        table: DataTable[Any],
        base_labels: dict[str, str],
        sort_by: str,
        descending: bool,
    ) -> None:
        cols_by_key = {
            (col.key.value if col.key.value is not None else str(col.key)): col
            for col in table.columns.values()
        }
        for key, base in base_labels.items():
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

    def _sync_entity_sort_controls(self) -> None:
        sort_label = _ENTITY_SORT_DISPLAY.get(self._entity_sort_by, self._entity_sort_by)
        self.query_one("#wl-sort-cycle-btn", Button).label = f"Sort: {sort_label}"
        self.query_one("#wl-sort-dir-btn", Button).label = (
            "Desc v" if self._entity_sort_desc else "Asc ^"
        )
        sort_select = self.query_one("#wl-entity-sort-select", Select)
        if str(sort_select.value) != self._entity_sort_by:
            with sort_select.prevent(Select.Changed):
                sort_select.value = self._entity_sort_by

    def _set_entity_sort(
        self,
        sort_by: str,
        *,
        descending: bool | None = None,
        toggle_if_same: bool = False,
    ) -> None:
        if sort_by not in _ENTITY_SORT_DISPLAY:
            return
        if sort_by == "none":
            next_sort = "none"
            next_desc = False
        elif toggle_if_same and sort_by == self._entity_sort_by:
            next_sort = sort_by
            next_desc = not self._entity_sort_desc
        else:
            next_sort = sort_by
            next_desc = False if descending is None else bool(descending)

        if (next_sort, next_desc) == (self._entity_sort_by, self._entity_sort_desc):
            return

        self._entity_sort_by = next_sort
        self._entity_sort_desc = next_desc
        self._sync_entity_sort_controls()
        self._update_filter_title()
        self._render_entities_table()
        if self._entity_sort_by == "none":
            self.set_status("Entity sort reset to default API order.")
        else:
            direction = "descending" if self._entity_sort_desc else "ascending"
            label = _ENTITY_SORT_DISPLAY.get(self._entity_sort_by, self._entity_sort_by)
            self.set_status(f"Sorted entities by {label} ({direction}).")

    def _toggle_entity_sort_direction(self) -> None:
        if self._entity_sort_by == "none":
            self._set_entity_sort("name", descending=False)
        else:
            self._set_entity_sort(self._entity_sort_by, descending=not self._entity_sort_desc)

    def _copy_text(self, value: str, label: str) -> None:
        clean = value.strip()
        if not clean:
            self.set_status(f"No {label} selected to copy.")
            return
        copy_label = label if clean in label else f"{label}: {clean}"
        self.copy_to_clipboard(clean, label=copy_label)

    def _watchlist_for_row(
        self,
        *,
        row_key: Any = None,
        row_index: int | None = None,
    ) -> dict[str, Any] | None:
        if row_key is not None:
            key_val = getattr(row_key, "value", row_key)
            if isinstance(key_val, str) and key_val in self._row_key_to_watchlist:
                return self._row_key_to_watchlist[key_val]
        if row_index is not None and 0 <= row_index < len(self._visible_watchlists):
            return self._visible_watchlists[row_index]
        return None

    def _entity_for_row(
        self,
        *,
        row_key: Any = None,
        row_index: int | None = None,
    ) -> dict[str, Any] | None:
        if row_key is not None:
            key_val = getattr(row_key, "value", row_key)
            if isinstance(key_val, str) and key_val in self._row_key_to_entity:
                return self._row_key_to_entity[key_val]
        if row_index is not None and 0 <= row_index < len(self._visible_entities):
            return self._visible_entities[row_index]
        return None

    def _active_or_highlighted_list(self) -> tuple[str, str]:
        if self._view_stage == "entities" and self._current_list_id:
            return self._current_list_id, self._current_list_name
        lists_table = self.query_one("#wl-lists-table", DataTable)
        if lists_table.row_count > 0 and 0 <= lists_table.cursor_row < lists_table.row_count:
            item = self._watchlist_for_row(row_index=lists_table.cursor_row)
            if item is not None:
                return str(item.get("id") or "").strip(), str(item.get("name") or "").strip()
        target_id = self.query_one("#wl-target-list-id", Input).value.strip()
        matched_name = next(
            (str(w.get("name") or "") for w in self._all_watchlists if str(w.get("id") or "") == target_id),
            "",
        )
        return target_id, matched_name

    def _render_watchlists_table(self) -> None:
        type_val = str(self.query_one("#wl-type-filter", Select).value)
        query = self.query_one("#wl-search-input", Input).value.strip().lower()

        filtered: list[dict[str, Any]] = []
        for item in self._all_watchlists:
            item_id = str(item.get("id") or "")
            item_type = str(item.get("type") or "")
            item_name = str(item.get("name") or "")
            if type_val != "all" and item_type != type_val:
                continue
            if query and query not in f"{item_id} {item_type} {item_name}".lower():
                continue
            filtered.append(item)

        if self._list_sort_by != "none":
            filtered = sort_watchlists(
                filtered,
                sort_by=self._list_sort_by,
                descending=self._list_sort_desc,
            )

        self._visible_watchlists = list(filtered)
        self._row_key_to_watchlist = {}
        table = self.query_one("#wl-lists-table", DataTable)
        self._update_table_sort_headers(
            table, _LIST_COLUMN_LABELS, self._list_sort_by, self._list_sort_desc
        )
        table.clear()
        for idx, item in enumerate(filtered):
            item_id = str(item.get("id") or "")
            item_type = str(item.get("type") or "")
            item_name = str(item.get("name") or "") or item_id
            key = (
                item_id
                if item_id and item_id not in self._row_key_to_watchlist
                else f"wl:{idx}:{item_id}"
            )
            self._row_key_to_watchlist[key] = item
            table.add_row(item_name, item_type, key=key)

        target_input = self.query_one("#wl-target-list-id", Input)
        if filtered and not target_input.value.strip():
            target_input.value = str(filtered[0].get("id") or "")

        header = self.query_one("#wl-lists-header", Static)
        if type_val != "all" or query:
            header.update(
                f"Watchlists ({len(filtered)} of {len(self._all_watchlists)}) "
                "- click or press Enter to expand entities"
            )
        else:
            header.update(
                f"Watchlists ({len(filtered)}) - click or press Enter to expand entities"
            )
        self.call_after_refresh(self._fit_tables)

    def _render_entities_table(self) -> None:
        raw_query = self.query_one("#wl-entity-search-input", Input).value.strip()
        filtered = filter_watchlist_entities(self._current_entities, raw_query)
        ordered = (
            sort_watchlist_entities(
                filtered,
                sort_by=self._entity_sort_by,
                descending=self._entity_sort_desc,
            )
            if self._entity_sort_by != "none"
            else filtered
        )

        self._visible_entities = list(ordered)
        self._row_key_to_entity = {}
        table = self.query_one("#wl-entities-table", DataTable)
        self._update_table_sort_headers(
            table, _ENTITY_COLUMN_LABELS, self._entity_sort_by, self._entity_sort_desc
        )
        table.clear()
        for idx, entry in enumerate(ordered):
            ent = entry.get("entity", {}) or {}
            ctx = entry.get("context", {}) or {}
            ent_id = str(ent.get("id") or "")
            ent_type = str(ent.get("type") or "")
            ent_status = str(entry.get("status") or "")
            ent_name = str(ent.get("name") or "") or ent_id
            ent_note = str(ctx.get("annotation") or "")
            key = f"ent:{idx}:{ent_id}"
            self._row_key_to_entity[key] = entry
            table.add_row(ent_name, ent_type, ent_status, ent_note, key=key)

        header = self.query_one("#wl-entities-header", Static)
        if not self._current_list_id:
            header.update("Watchlist Entities")
        else:
            label = self._current_list_name or self._current_list_id
            if raw_query:
                header.update(
                    f"{label} ({len(ordered)} of {len(self._current_entities)} entities)"
                )
            else:
                header.update(f"{label} ({len(ordered)} entities)")
        self.call_after_refresh(self._fit_tables)

    def _is_text_or_select_focused(self) -> bool:
        focused = self.app.focused
        if focused is None:
            return False
        if isinstance(focused, (Input, Select)):
            return True
        return any(isinstance(anc, (Input, Select)) for anc in focused.ancestors)

    def _start_type_to_filter(self, char: str, *, target: str) -> None:
        collapsible = self.query_one("#wl-filter-collapsible", Collapsible)
        collapsible.collapsed = False
        input_id = "#wl-entity-search-input" if target == "entities" else "#wl-search-input"
        search_input = self.query_one(input_id, Input)
        search_input.value = search_input.value + char
        search_input.cursor_position = len(search_input.value)
        self.screen.set_focus(search_input)

    def handle_type_to_filter_key(self, event: events.Key) -> bool:
        """Start or continue filtering when a printable key is pressed outside Inputs."""
        if isinstance(self.app.screen, ModalScreen) or self._is_text_or_select_focused():
            return False

        in_entities_stage = self._view_stage == "entities"
        has_watchlists = bool(self._all_watchlists)

        if event.key == "backspace":
            if in_entities_stage:
                ent_input = self.query_one("#wl-entity-search-input", Input)
                if ent_input.value:
                    self.query_one("#wl-filter-collapsible", Collapsible).collapsed = False
                    ent_input.value = ent_input.value[:-1]
                    ent_input.cursor_position = len(ent_input.value)
                    self.screen.set_focus(ent_input)
                    event.stop()
                    event.prevent_default()
                    return True
                self.action_back_to_watchlists()
                event.stop()
                event.prevent_default()
                return True
            wl_input = self.query_one("#wl-search-input", Input)
            if wl_input.value:
                self.query_one("#wl-filter-collapsible", Collapsible).collapsed = False
                wl_input.value = wl_input.value[:-1]
                wl_input.cursor_position = len(wl_input.value)
                self.screen.set_focus(wl_input)
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
            if in_entities_stage:
                self._start_type_to_filter(event.character, target="entities")
                event.stop()
                event.prevent_default()
                return True
            if event.key in _RESERVED_TYPE_FILTER_KEYS:
                return False
            if has_watchlists:
                self._start_type_to_filter(event.character, target="watchlists")
                event.stop()
                event.prevent_default()
                return True
        return False

    def _focus_table_after_filter(self, table_id: str) -> None:
        table = self.query_one(table_id, DataTable)
        if table.row_count > 0 and not (0 <= table.cursor_row < table.row_count):
            table.move_cursor(row=0, column=0)
        self.screen.set_focus(table)

    def on_key(self, event: events.Key) -> None:
        """Handle instant type-to-filter and quick navigation between search box and table."""
        focused = self.app.focused
        if event.key == "down" and focused is not None:
            if focused.id == "wl-entity-search-input":
                self._focus_table_after_filter("#wl-entities-table")
                event.stop()
                event.prevent_default()
                return
            if focused.id == "wl-search-input":
                self._focus_table_after_filter("#wl-lists-table")
                event.stop()
                event.prevent_default()
                return
        self.handle_type_to_filter_key(event)

    def action_cycle_entity_sort(self) -> None:
        """Cycle entity sorting through default, name, id, type, status, and annotation."""
        try:
            idx = _ENTITY_SORT_CYCLE.index(self._entity_sort_by)
        except ValueError:
            idx = 0
        next_sort = _ENTITY_SORT_CYCLE[(idx + 1) % len(_ENTITY_SORT_CYCLE)]
        self._set_entity_sort(next_sort, descending=False)

    def action_toggle_filter(self) -> None:
        """Toggle the Search & Filter panel and focus the active stage's search box."""
        in_entities = self._view_stage == "entities"
        collapsible = self.query_one("#wl-filter-collapsible", Collapsible)
        collapsible.collapsed = not collapsible.collapsed
        if not collapsible.collapsed:
            target = "#wl-entity-search-input" if in_entities else "#wl-search-input"
            self.call_after_refresh(lambda: self.query_one(target, Input).focus())

    def action_collapse_filter(self) -> None:
        """Collapse filter, clear active filter, or go back from Entity List to Watchlists."""
        collapsible = self.query_one("#wl-filter-collapsible", Collapsible)
        if not collapsible.collapsed:
            collapsible.collapsed = True
            target_id = "#wl-entities-table" if self._view_stage == "entities" else "#wl-lists-table"
            self.call_after_refresh(lambda: self._focus_table_if_visible(target_id))
            return

        if self._view_stage == "entities":
            ent_input = self.query_one("#wl-entity-search-input", Input)
            if ent_input.value.strip():
                ent_input.value = ""
                self.set_status("Cleared entity filter.")
            else:
                self.action_back_to_watchlists()
            return

        wl_input = self.query_one("#wl-search-input", Input)
        if wl_input.value.strip():
            wl_input.value = ""
            self.set_status("Cleared watchlist filter.")

    def action_back_to_watchlists(self) -> None:
        """Return from the expanded entity list back to the Watchlists finder."""
        if self._view_stage == "lists":
            self._focus_table_if_visible("#wl-lists-table")
            return
        self._set_view_stage("lists")
        total = len(self._visible_watchlists)
        self.set_status(
            f"Returned to watchlists ({total} shown). Click or press Enter to inspect another."
        )

    def action_copy_list_id(self) -> None:
        """Copy the active or highlighted watchlist's ID to the clipboard."""
        list_id, list_name = self._active_or_highlighted_list()
        if not list_id:
            self.set_status("Select or open a watchlist before copying its List ID.")
            return
        label = f"List ID ({list_name})" if list_name else "List ID"
        self._copy_text(list_id, label)

    def action_reload_watchlists(self) -> None:
        """Reload watchlists using the currently active list-type filter."""
        self.handle_load_watchlists()

    def action_open_context_menu(self) -> None:
        """Open a context menu via keyboard shortcut for the active stage."""
        if self._view_stage == "entities":
            ent_table = self.query_one("#wl-entities-table", DoubleClickDataTable)
            if ent_table.row_count > 0 and 0 <= ent_table.cursor_row < ent_table.row_count:
                entry = self._entity_for_row(row_index=ent_table.cursor_row)
                if entry is not None:
                    self._open_entity_menu(
                        entry, origin=(ent_table.region.x + 4, ent_table.region.y + 2)
                    )
                    return
            self._open_empty_entities_menu(origin=(ent_table.region.x + 4, ent_table.region.y + 2))
            return

        lists_table = self.query_one("#wl-lists-table", DoubleClickDataTable)
        if lists_table.row_count > 0 and 0 <= lists_table.cursor_row < lists_table.row_count:
            item = self._watchlist_for_row(row_index=lists_table.cursor_row)
            if item is not None:
                self._open_watchlist_menu(
                    item, origin=(lists_table.region.x + 4, lists_table.region.y + 2)
                )
                return
        self._open_empty_watchlists_menu(origin=(lists_table.region.x + 4, lists_table.region.y + 2))

    def _handle_pane_menu_action(self, action_id: str) -> None:
        if action_id == "reload_lists":
            self.handle_load_watchlists()
        elif action_id == "load_selected":
            self.handle_load_entities()
        elif action_id == "toggle_filter":
            self.action_toggle_filter()
        elif action_id == "focus_create":
            self.query_one("#wl-create-name", Input).focus()

    def _open_empty_watchlists_menu(self, *, origin: tuple[int, int]) -> None:
        items = [
            ("reload_lists", "Load / Reload Watchlists"),
            ("toggle_filter", "Toggle Search & Filter"),
            ("focus_create", "Create New Watchlist..."),
        ]
        self.open_context_menu(
            items,
            title="Watchlists",
            origin=origin,
            on_select=self._handle_pane_menu_action,
        )

    def _open_watchlist_menu(
        self, item: dict[str, Any], *, origin: tuple[int, int]
    ) -> None:
        list_id = str(item.get("id") or "").strip()
        list_type = str(item.get("type") or "").strip().lower()
        list_name = str(item.get("name") or "").strip()
        if not list_id:
            self._open_empty_watchlists_menu(origin=origin)
            return
        self.query_one("#wl-target-list-id", Input).value = list_id
        items: list[tuple[str, str]] = [
            ("load_entities", "Expand Entities List"),
            ("copy_list_id", f"Copy List ID ({list_id})"),
            ("inspect_info", "Inspect List Info & Status"),
            ("focus_add", "Add Entity to This List..."),
            ("focus_export", "Export This Watchlist..."),
        ]
        if list_type in ("hash", "brand"):
            items.append(("send_brand_logos", "Use in Brand Logos Tab"))
        elif list_type == "domain":
            items.append(("send_brand_source", "Use as Domain Source in Brand Logos Tab"))
        items.extend(
            [
                ("copy_row", "Copy Row"),
                ("open_copy_view", "Open Copyable View"),
                ("toggle_filter", "Toggle Search & Filter"),
                ("reload_lists", "Reload Watchlists"),
            ]
        )

        row_text = f"ID: {list_id} | Type: {list_type} | Name: {list_name}"

        def _on_select(action_id: str) -> None:
            if action_id == "load_entities":
                self._start_load_entities(list_id, list_name=list_name)
            elif action_id == "copy_list_id":
                self._copy_text(list_id, f"List ID ({list_name or list_id})")
            elif action_id == "inspect_info":
                self._inspect_list_info_worker(list_id, list_name)
            elif action_id == "copy_row":
                self.copy_to_clipboard(row_text, label="Watchlist Row")
            elif action_id == "open_copy_view":
                self.open_copy_modal(row_text, title=f"Watchlist - {list_name or list_id}")
            elif action_id == "focus_add":
                self.query_one("#wl-target-list-id", Input).value = list_id
                self.query_one("#wl-ent-value", Input).focus()
            elif action_id == "focus_export":
                self.query_one("#wl-target-list-id", Input).value = list_id
                export_in = self.query_one("#wl-export-path", Input)
                if not export_in.value.strip():
                    safe_slug = list_id.replace(":", "_")
                    export_in.value = f"{safe_slug}.csv"
                export_in.focus()
            elif action_id == "send_brand_logos":
                self._send_to_brand_logos(list_id, list_name, list_type, as_source=False)
            elif action_id == "send_brand_source":
                self._send_to_brand_logos(list_id, list_name, list_type, as_source=True)
            elif action_id == "toggle_filter":
                self.action_toggle_filter()
            elif action_id == "reload_lists":
                self.handle_load_watchlists()

        self.open_context_menu(
            items,
            title=list_name or list_id,
            origin=origin,
            on_select=_on_select,
        )

    def _send_to_brand_logos(
        self, list_id: str, list_name: str, list_type: str, *, as_source: bool
    ) -> None:
        def _apply(brand_pane: BaseSocPane) -> None:
            if not isinstance(brand_pane, BrandLogosPane):
                return
            if as_source:
                brand_pane.select_source_domain_list(list_id, list_name=list_name)
            else:
                brand_pane.select_brand_list(
                    list_id,
                    list_name=list_name,
                    list_type=list_type,
                )

        activate_fn = getattr(self.app, "activate_tab", None)
        if callable(activate_fn):
            activate_fn("tab-brand-logos", auto_enable_admin=True, on_ready=_apply)
            return

        tabs = self.app.query_one("#main-tabs", TabbedContent)
        tabs.active = "tab-brand-logos"
        brand_pane = self.app.query_one(BrandLogosPane)
        self.call_after_refresh(_apply, brand_pane)

    @staticmethod
    def _entity_sort_menu_items() -> list[tuple[str, str]]:
        return [
            ("sort_name", "Sort by Name (A-Z)"),
            ("sort_type", "Sort by Entity Type"),
            ("sort_annotation", "Sort by Annotation"),
            ("toggle_sort_dir", "Toggle Sort Direction (Asc/Desc)"),
            ("reset_sort", "Reset Sort Order"),
        ]

    def _handle_entity_sort_menu_action(self, action_id: str) -> bool:
        if action_id == "sort_name":
            self._set_entity_sort("name", descending=False)
            return True
        if action_id == "sort_type":
            self._set_entity_sort("type", descending=False)
            return True
        if action_id == "sort_annotation":
            self._set_entity_sort("annotation", descending=False)
            return True
        if action_id == "toggle_sort_dir":
            self._toggle_entity_sort_direction()
            return True
        if action_id == "reset_sort":
            self._set_entity_sort("none")
            return True
        return False

    def _open_empty_entities_menu(self, *, origin: tuple[int, int]) -> None:
        items = [
            ("back_to_lists", "<- Back to Watchlists"),
            ("copy_list_id", "Copy Watchlist ID"),
            ("reload_entities", "Load / Reload Entities"),
            ("focus_add", "Add Entity to Watchlist..."),
            ("filter_entities", "Filter Entities..."),
            *self._entity_sort_menu_items(),
        ]

        def _on_select(action_id: str) -> None:
            if self._handle_entity_sort_menu_action(action_id):
                return
            if action_id == "back_to_lists":
                self.action_back_to_watchlists()
            elif action_id == "copy_list_id":
                self.action_copy_list_id()
            elif action_id == "reload_entities":
                self.handle_load_entities()
            elif action_id == "focus_add":
                self.query_one("#wl-ent-value", Input).focus()
            elif action_id == "filter_entities":
                collapsible = self.query_one("#wl-filter-collapsible", Collapsible)
                collapsible.collapsed = False
                self.call_after_refresh(
                    lambda: self.query_one("#wl-entity-search-input", Input).focus()
                )

        self.open_context_menu(
            items,
            title=self._current_list_name or "Entities",
            origin=origin,
            on_select=_on_select,
        )

    def _open_entity_menu(
        self, entry: dict[str, Any], *, origin: tuple[int, int]
    ) -> None:
        ent = entry.get("entity", {}) or {}
        ent_id = str(ent.get("id") or "").strip()
        ent_type = str(ent.get("type") or "").strip()
        ent_name = str(ent.get("name") or "").strip()
        if not ent_id and not ent_name:
            self._open_empty_entities_menu(origin=origin)
            return

        display_val = ent_name or ent_id
        copy_target = ent_id or display_val
        ent_status = str(entry.get("status") or "").strip()
        ctx = entry.get("context") or {}
        ent_ann = str(ctx.get("annotation") or "").strip() if isinstance(ctx, dict) else ""
        row_text = (
            f"ID: {ent_id} | Type: {ent_type} | Status: {ent_status} | "
            f"Name: {ent_name} | Annotation: {ent_ann}"
        )
        items = [
            ("back_to_lists", "<- Back to Watchlists"),
            ("select_entity", "Populate Entity Form"),
            ("copy_entity_id", f"Copy Entity ID ({copy_target})"),
            ("copy_list_id", "Copy Watchlist ID"),
            ("copy_row", "Copy Row"),
            ("open_copy_view", "Open Copyable View"),
            ("lookup_intel", "Lookup in RF Intel Tab"),
            ("deep_research", "Deep Research in Research Tab"),
            ("reload_entities", "Reload Entities"),
            ("filter_entities", "Filter Entities..."),
            *self._entity_sort_menu_items(),
            ("remove_entity", "Remove Entity... [Approval Required]"),
        ]

        def _on_select(action_id: str) -> None:
            if self._handle_entity_sort_menu_action(action_id):
                return
            if action_id == "back_to_lists":
                self.action_back_to_watchlists()
            elif action_id == "select_entity":
                if ent_type:
                    self.query_one("#wl-ent-type", Input).value = ent_type
                self.query_one("#wl-ent-value", Input).value = display_val
                self._remember_selected_entity(ent_id, ent_type, ent_name)
            elif action_id == "copy_row":
                self.copy_to_clipboard(row_text, label="Entity Row")
            elif action_id == "open_copy_view":
                self.open_copy_modal(row_text, title=f"Entity - {display_val}")
            elif action_id == "lookup_intel":
                self._lookup_entity_in_rf_intel(ent_type, display_val)
            elif action_id == "deep_research":
                self._research_entity_in_research_tab(ent_type, display_val)
            elif action_id == "copy_entity_id":
                self._copy_text(copy_target, "Entity ID")
            elif action_id == "copy_list_id":
                self.action_copy_list_id()
            elif action_id == "reload_entities":
                self.handle_load_entities()
            elif action_id == "filter_entities":
                collapsible = self.query_one("#wl-filter-collapsible", Collapsible)
                collapsible.collapsed = False
                self.call_after_refresh(
                    lambda: self.query_one("#wl-entity-search-input", Input).focus()
                )
            elif action_id == "remove_entity":
                target_list_id = (
                    self._current_list_id
                    or self.query_one("#wl-target-list-id", Input).value.strip()
                )
                if ent_id:
                    self._request_remove_entity(
                        target_list_id,
                        ent_id,
                        ent_type or None,
                        is_id=True,
                        display_name=display_val,
                    )
                else:
                    self._request_remove_entity(
                        target_list_id,
                        display_val,
                        None,
                        is_id=False,
                        display_name=display_val,
                    )

        self.open_context_menu(
            items,
            title=display_val,
            origin=origin,
            on_select=_on_select,
        )

    def _lookup_entity_in_rf_intel(self, ent_type: str, ent_val: str) -> None:
        def _apply(rf_pane: BaseSocPane) -> None:
            if isinstance(rf_pane, RFIntelPane):
                rf_pane.lookup_from_watchlist(ent_type, ent_val)

        activate_fn = getattr(self.app, "activate_tab", None)
        if callable(activate_fn):
            activate_fn("tab-rf-intel", on_ready=_apply)
            return

        tabs = self.app.query_one("#main-tabs", TabbedContent)
        tabs.active = "tab-rf-intel"
        rf_pane = self.app.query_one(RFIntelPane)
        self.call_after_refresh(rf_pane.lookup_from_watchlist, ent_type, ent_val)

    def _research_entity_in_research_tab(self, ent_type: str, ent_val: str) -> None:
        from soclens.tui.screens.research import ResearchPane

        type_map = {
            "ipaddress": "ip",
            "internetdomainname": "domain",
            "hash": "hash",
            "url": "url",
            "cybervulnerability": "vulnerability",
            "malware": "malware",
            "company": "company",
        }
        mapped = type_map.get(ent_type.strip().lower(), "auto")

        def _apply(res_pane: BaseSocPane) -> None:
            if isinstance(res_pane, ResearchPane):
                res_pane.investigate_external(ent_val, mapped)

        activate_fn = getattr(self.app, "activate_tab", None)
        if callable(activate_fn):
            activate_fn("tab-research", on_ready=_apply)
            return

        tabs = self.app.query_one("#main-tabs", TabbedContent)
        tabs.active = "tab-research"
        res_pane = self.app.query_one(ResearchPane)
        self.call_after_refresh(res_pane.investigate_external, ent_val, mapped)

    @work(thread=True, exit_on_error=False)
    def _inspect_list_info_worker(self, list_id: str, list_name: str) -> None:
        try:
            if self.is_app_shutting_down():
                return
            self.set_status(f"Loading info & status for {list_id}...")
            info = self.client.get_list_info(list_id)
            status = self.client.get_list_status(list_id)
            size = status.get("size", "?") if isinstance(status, dict) else "?"
            ltype = info.get("type", "") if isinstance(info, dict) else ""
            lname = (info.get("name") if isinstance(info, dict) else None) or list_name or list_id
            summary = f"Watchlist '{lname}' ({list_id}) | type={ltype} | size={size}"
            self.set_status(summary)
            from soclens.tui.s1_formatters import format_s1_value, pretty_s1_label

            lines = [f"=== {summary} ==="]
            if isinstance(info, dict):
                for k, v in info.items():
                    if v not in (None, "", [], {}):
                        lines.append(f"  {pretty_s1_label(str(k))}: {format_s1_value(v)}")
            if isinstance(status, dict):
                for k, v in status.items():
                    if v not in (None, "", [], {}):
                        lines.append(f"  Status {pretty_s1_label(str(k))}: {format_s1_value(v)}")
            self.append_log("\n".join(lines))
        except Exception as exc:
            self.report_error("Inspect Watchlist Info", exc)

    @on(Input.Changed, "#wl-search-input")
    def handle_watchlist_search_changed(self) -> None:
        self._update_filter_title()
        self._render_watchlists_table()

    @on(Input.Submitted, "#wl-search-input")
    def handle_watchlist_search_submitted(self) -> None:
        self._focus_table_after_filter("#wl-lists-table")

    @on(Input.Changed, "#wl-entity-search-input")
    def handle_entity_search_changed(self) -> None:
        self._update_filter_title()
        self._render_entities_table()

    @on(Input.Submitted, "#wl-entity-search-input")
    def handle_entity_search_submitted(self) -> None:
        self._focus_table_after_filter("#wl-entities-table")

    @on(Select.Changed, "#wl-entity-sort-select")
    def handle_entity_sort_select_changed(self, event: Select.Changed) -> None:
        if not self._tables_ready:
            return
        new_sort = str(event.value)
        if new_sort == self._entity_sort_by:
            return
        self._set_entity_sort(new_sort)

    @on(Button.Pressed, "#wl-sort-cycle-btn")
    def handle_sort_cycle_pressed(self) -> None:
        self.action_cycle_entity_sort()

    @on(Button.Pressed, "#wl-sort-dir-btn")
    def handle_sort_dir_pressed(self) -> None:
        self._toggle_entity_sort_direction()

    @on(DataTable.HeaderSelected, "#wl-entities-table")
    def handle_entities_header_selected(self, event: DataTable.HeaderSelected) -> None:
        col_key = event.column_key.value if event.column_key.value is not None else str(event.column_key)
        self._set_entity_sort(col_key, toggle_if_same=True)

    @on(DataTable.HeaderSelected, "#wl-lists-table")
    def handle_lists_header_selected(self, event: DataTable.HeaderSelected) -> None:
        col_key = event.column_key.value if event.column_key.value is not None else str(event.column_key)
        if col_key not in _LIST_COLUMN_LABELS:
            return
        if self._list_sort_by == col_key:
            self._list_sort_desc = not self._list_sort_desc
        else:
            self._list_sort_by = col_key
            self._list_sort_desc = False
        self._render_watchlists_table()
        direction = "descending" if self._list_sort_desc else "ascending"
        self.set_status(f"Sorted watchlists by {_LIST_COLUMN_LABELS[col_key]} ({direction}).")

    @on(Select.Changed, "#wl-type-filter")
    def handle_type_filter_changed(self, event: Select.Changed) -> None:
        self._update_filter_title()
        if not self._has_loaded_lists_once:
            return
        new_type = str(event.value)
        if self._loaded_type_filter == "all" or new_type == self._loaded_type_filter:
            self._render_watchlists_table()
        else:
            self._start_load_watchlists(None if new_type == "all" else new_type)

    @on(Button.Pressed, "#wl-clear-filter-btn")
    def handle_clear_filters(self) -> None:
        wl_search = self.query_one("#wl-search-input", Input)
        ent_search = self.query_one("#wl-entity-search-input", Input)
        type_select = self.query_one("#wl-type-filter", Select)
        with wl_search.prevent(Input.Changed):
            wl_search.value = ""
        with ent_search.prevent(Input.Changed):
            ent_search.value = ""
        with type_select.prevent(Select.Changed):
            type_select.value = "all"
        self._update_filter_title()
        if self._has_loaded_lists_once and self._loaded_type_filter != "all":
            self._start_load_watchlists(None)
        else:
            self._render_watchlists_table()
        self._render_entities_table()

    @on(Button.Pressed, "#wl-back-btn")
    @on(Button.Pressed, "#wl-back-bottom-btn")
    def handle_back_pressed(self) -> None:
        self.action_back_to_watchlists()

    @on(Button.Pressed, "#wl-copy-id-btn")
    @on(Button.Pressed, "#wl-entities-copy-id-btn")
    @on(Button.Pressed, "#wl-entities-copy-id-bottom-btn")
    def handle_copy_list_id_pressed(self) -> None:
        self.action_copy_list_id()

    @on(Button.Pressed, "#wl-entities-reload-btn")
    def handle_entities_reload_pressed(self) -> None:
        self.handle_load_entities()

    @on(DataTable.RowHighlighted, "#wl-lists-table")
    def handle_list_highlighted(self, event: DataTable.RowHighlighted) -> None:
        item = self._watchlist_for_row(row_key=event.row_key, row_index=event.cursor_row)
        if item is not None:
            list_id = str(item.get("id") or "").strip()
            if list_id:
                self.query_one("#wl-target-list-id", Input).value = list_id

    @on(DataTable.RowSelected, "#wl-lists-table")
    def handle_list_selected(self, event: DataTable.RowSelected) -> None:
        item = self._watchlist_for_row(row_key=event.row_key, row_index=event.cursor_row)
        if item is None:
            return
        list_id = str(item.get("id") or "").strip()
        list_name = str(item.get("name") or "").strip()
        if not list_id:
            return
        self.query_one("#wl-target-list-id", Input).value = list_id
        self._start_load_entities(list_id, list_name=list_name)

    @on(DataTable.RowSelected, "#wl-entities-table")
    def handle_entity_selected(self, event: DataTable.RowSelected) -> None:
        entry = self._entity_for_row(row_key=event.row_key, row_index=event.cursor_row)
        if entry is None:
            return
        ent = entry.get("entity", {}) or {}
        ent_id = str(ent.get("id") or "").strip()
        ent_type = str(ent.get("type") or "").strip()
        ent_name = str(ent.get("name") or "").strip()
        if ent_type:
            self.query_one("#wl-ent-type", Input).value = ent_type
        if ent_name or ent_id:
            self.query_one("#wl-ent-value", Input).value = ent_name or ent_id
        self._remember_selected_entity(ent_id, ent_type, ent_name)

    @on(Input.Submitted, "#wl-target-list-id")
    def handle_target_list_submitted(self) -> None:
        list_id = self.query_one("#wl-target-list-id", Input).value.strip()
        if not list_id:
            self.set_status("Enter a Target List ID first.")
            return
        matched = next(
            (str(w.get("name") or "") for w in self._all_watchlists if str(w.get("id") or "") == list_id),
            "",
        )
        self._start_load_entities(list_id, list_name=matched)

    @on(Button.Pressed, "#wl-load-btn")
    def handle_load_watchlists(self) -> None:
        if self._view_stage == "entities":
            self._set_view_stage("lists")
        type_filter = str(self.query_one("#wl-type-filter", Select).value)
        self._start_load_watchlists(None if type_filter == "all" else type_filter)

    def _start_load_watchlists(self, list_type: str | None) -> None:
        self._lists_request_seq += 1
        self._load_watchlists_worker(list_type, self._lists_request_seq)

    def _refresh_watchlists_inline(
        self,
        list_type: str | None,
        *,
        request_seq: int | None = None,
        update_status: bool = True,
    ) -> None:
        if request_seq is None:
            def _prepare() -> int | None:
                if self.is_app_shutting_down():
                    return None
                self._lists_request_seq += 1
                return self._lists_request_seq

            prepared = self.run_on_ui(_prepare)
            if prepared is None:
                return
            seq = int(prepared)
        else:
            seq = request_seq

        if seq != self._lists_request_seq or self.is_app_shutting_down():
            return
        if update_status:
            self.set_status("Loading watchlists from Recorded Future...")
        with self.log_scope("watchlists"):
            raw_lists = self.client.get_watchlists(list_types=list_type)
        if seq != self._lists_request_seq or self.is_app_shutting_down():
            return
        lists_data = list(raw_lists) if isinstance(raw_lists, list) else []

        def _populate() -> None:
            if seq != self._lists_request_seq or self.is_app_shutting_down():
                return
            self._all_watchlists = lists_data
            self._loaded_type_filter = list_type or "all"
            self._has_loaded_lists_once = True
            self._update_filter_title()
            self._render_watchlists_table()

        self.run_on_ui(_populate)
        if seq != self._lists_request_seq or self.is_app_shutting_down():
            return
        if update_status:
            msg = f"Loaded {len(lists_data)} watchlist(s)."
            self.set_status(msg)
            self.append_log(msg)

    @work(thread=True, exit_on_error=False)
    def _load_watchlists_worker(
        self, list_type: str | None, request_seq: int | None = None
    ) -> None:
        try:
            seq = self._lists_request_seq if request_seq is None else request_seq
            self._refresh_watchlists_inline(list_type, request_seq=seq, update_status=True)
        except Exception as exc:
            self.report_error("Load Watchlists", exc)

    def _start_load_entities(self, list_id: str, *, list_name: str = "") -> None:
        self._entities_request_seq += 1
        seq = self._entities_request_seq
        self._current_list_id = list_id
        self._current_list_name = list_name
        self._selected_entity = None
        self.query_one("#wl-target-list-id", Input).value = list_id
        label = list_name or list_id
        self.query_one("#wl-entities-header", Static).update(f"Loading entities for {label}...")
        self._set_view_stage("entities")
        self._load_entities_worker(list_id, seq)

    @on(Button.Pressed, "#wl-entities-btn")
    def handle_load_entities(self) -> None:
        if self._view_stage == "lists":
            lists_table = self.query_one("#wl-lists-table", DataTable)
            if lists_table.row_count > 0 and 0 <= lists_table.cursor_row < lists_table.row_count:
                item = self._watchlist_for_row(row_index=lists_table.cursor_row)
                if item is not None:
                    lid = str(item.get("id") or "").strip()
                    lname = str(item.get("name") or "").strip()
                    if lid:
                        self._start_load_entities(lid, list_name=lname)
                        return
        list_id = self.query_one("#wl-target-list-id", Input).value.strip()
        if not list_id:
            self.set_status("Select or enter a Watchlist first.")
            return
        matched = next(
            (str(w.get("name") or "") for w in self._all_watchlists if str(w.get("id") or "") == list_id),
            "",
        )
        self._start_load_entities(list_id, list_name=matched)

    def _refresh_entities_inline(
        self,
        list_id: str,
        *,
        request_seq: int | None = None,
        update_status: bool = True,
    ) -> None:
        if request_seq is None:
            def _prepare() -> int | None:
                if self.is_app_shutting_down() or list_id != self._current_list_id:
                    return None
                self._entities_request_seq += 1
                self._selected_entity = None
                return self._entities_request_seq

            prepared = self.run_on_ui(_prepare)
            if prepared is None:
                return
            seq = int(prepared)
        else:
            seq = request_seq

        if seq != self._entities_request_seq or self.is_app_shutting_down():
            return
        if update_status:
            self.set_status(f"Fetching entities for {list_id}...")
        with self.log_scope("watchlists"):
            raw_entries = self.client.get_watchlist_entities(list_id)
        if seq != self._entities_request_seq or self.is_app_shutting_down():
            return
        entries = list(raw_entries) if isinstance(raw_entries, list) else []

        def _populate() -> None:
            if (
                seq != self._entities_request_seq
                or self.is_app_shutting_down()
                or list_id != self._current_list_id
            ):
                return
            self._current_entities = entries
            self._render_entities_table()

        self.run_on_ui(_populate)
        if seq != self._entities_request_seq or self.is_app_shutting_down():
            return
        if update_status:
            msg = f"Loaded {len(entries)} entity/entities from {list_id}."
            self.set_status(msg)
            self.append_log(msg)

    @work(thread=True, exit_on_error=False)
    def _load_entities_worker(self, list_id: str, request_seq: int) -> None:
        try:
            self._refresh_entities_inline(list_id, request_seq=request_seq, update_status=True)
        except Exception as exc:
            self.report_error("Load Watchlist Entities", exc)

    @on(Button.Pressed, "#wl-create-btn")
    def handle_create_list(self) -> None:
        name = self.query_one("#wl-create-name", Input).value.strip()
        type_filter = str(self.query_one("#wl-type-filter", Select).value)
        list_type = "entity" if type_filter == "all" else type_filter
        if not name:
            self.set_status("Enter a list name before creating.")
            return
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Would create list '{name}' (type={list_type})."
            self.set_status(msg)
            self.append_log(msg)
            return
        self._create_list_worker(name, list_type)

    @work(thread=True, exit_on_error=False)
    def _create_list_worker(self, name: str, list_type: str) -> None:
        try:
            if self.is_app_shutting_down():
                return
            with self.log_scope("watchlists"):
                created = self.client.create_list(name, list_type)
            if self.is_app_shutting_down():
                return
            lid = str(created.get("id") or "")
            if lid:
                self.run_on_ui(
                    lambda: setattr(self.query_one("#wl-target-list-id", Input), "value", lid)
                )
            msg = f"Created list '{name}' (ID: {lid}, type={list_type})."
            self.set_status(msg)
            self.append_log(msg)
            if not self.is_app_shutting_down():
                self._refresh_watchlists_inline(None, update_status=False)
        except Exception as exc:
            self.report_error("Create List", exc)

    @on(Button.Pressed, "#wl-add-btn")
    def handle_add_entity(self) -> None:
        list_id = self.query_one("#wl-target-list-id", Input).value.strip()
        ent_type = self.query_one("#wl-ent-type", Input).value.strip() or "InternetDomainName"
        ent_val = self.query_one("#wl-ent-value", Input).value.strip()
        if not list_id or not ent_val:
            self.set_status("Target List ID and Entity value are required.")
            return
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Would add '{ent_val}' ({ent_type}) to {list_id}."
            self.set_status(msg)
            self.append_log(msg)
            return
        self._add_entity_worker(list_id, ent_type, ent_val)

    @work(thread=True, exit_on_error=False)
    def _add_entity_worker(self, list_id: str, ent_type: str, ent_val: str) -> None:
        try:
            if self.is_app_shutting_down():
                return
            with self.log_scope("watchlists"):
                res: dict[str, Any] = self.client.add_entity(list_id, ent_type, ent_val)
            if self.is_app_shutting_down():
                return
            msg = f"Add entity result for '{ent_val}': {res.get('result', 'added')}"
            self.set_status(msg)
            self.append_log(msg)
            if list_id == self._current_list_id and not self.is_app_shutting_down():
                self._refresh_entities_inline(list_id, update_status=False)
        except Exception as exc:
            self.report_error("Add Entity", exc)

    def _remember_selected_entity(self, ent_id: str, ent_type: str, ent_name: str) -> None:
        clean_id = ent_id.strip()
        if clean_id and self._current_list_id:
            self._selected_entity = {
                "list_id": self._current_list_id,
                "id": clean_id,
                "type": ent_type.strip(),
                "name": ent_name.strip(),
            }
        else:
            self._selected_entity = None

    def _resolve_loaded_entity_for_removal(
        self,
        list_id: str,
        ent_val: str,
        ent_type: str | None,
    ) -> tuple[str, str | None, bool, str]:
        """Resolve loaded row ID/name for removal: ``(target_val, ent_type, is_id, display_name)``."""
        clean_val = ent_val.strip()
        if not clean_val:
            return clean_val, ent_type, False, clean_val

        sel = self._selected_entity
        if sel is not None and sel.get("list_id") == list_id and sel.get("id"):
            sel_id = sel["id"]
            sel_type = sel.get("type", "")
            sel_name = sel.get("name", "")
            matched_by_id = clean_val == sel_id
            matched_by_name = bool(sel_name) and clean_val.casefold() == sel_name.casefold()
            type_ok = (
                not ent_type
                or not sel_type
                or ent_type.strip().casefold() == sel_type.casefold()
            )
            if matched_by_id or (matched_by_name and type_ok):
                return sel_id, (sel_type or ent_type), True, (sel_name or sel_id)

        if list_id == self._current_list_id and self._current_entities:
            val_cf = clean_val.casefold()
            ent_type_cf = ent_type.strip().casefold() if ent_type else ""
            ci_id_matches: dict[str, tuple[str, str, str]] = {}
            typed_name_matches: dict[str, tuple[str, str, str]] = {}
            all_name_matches: dict[str, tuple[str, str, str]] = {}

            for entry in self._current_entities:
                ent = entry.get("entity", {}) or {}
                eid = str(ent.get("id") or "").strip()
                if not eid:
                    continue
                etype = str(ent.get("type") or "").strip()
                ename = str(ent.get("name") or "").strip()

                if eid == clean_val:
                    return eid, (etype or ent_type), True, (ename or eid)
                if eid.casefold() == val_cf:
                    ci_id_matches[eid] = (eid, etype, ename)
                if ename and ename.casefold() == val_cf:
                    if ent_type_cf and etype.casefold() == ent_type_cf:
                        typed_name_matches[eid] = (eid, etype, ename)
                    all_name_matches[eid] = (eid, etype, ename)

            if len(ci_id_matches) == 1:
                eid, etype, ename = next(iter(ci_id_matches.values()))
                return eid, (etype or ent_type), True, (ename or eid)
            if len(ci_id_matches) > 1:
                ids = ", ".join(ci_id_matches.keys())
                raise ValueError(
                    f"Multiple loaded entities match ID '{clean_val}' ({ids}); "
                    "select the specific row and press [m] or enter its exact case-sensitive Entity ID."
                )

            if len(typed_name_matches) == 1:
                eid, etype, ename = next(iter(typed_name_matches.values()))
                return eid, (etype or ent_type), True, (ename or eid)
            if len(typed_name_matches) > 1:
                ids = ", ".join(typed_name_matches.keys())
                raise ValueError(
                    f"Multiple loaded entities match '{clean_val}' ({ids}); "
                    "select the specific row and press [m] or enter its exact Entity ID."
                )
            if not typed_name_matches and len(all_name_matches) == 1:
                eid, etype, ename = next(iter(all_name_matches.values()))
                return eid, (etype or ent_type), True, (ename or eid)
            if len(all_name_matches) > 1:
                ids = ", ".join(all_name_matches.keys())
                raise ValueError(
                    f"Multiple loaded entities match '{clean_val}' ({ids}); "
                    "select the specific row and press [m] or enter its exact Entity ID."
                )

        return clean_val, ent_type, False, clean_val

    @on(Button.Pressed, "#wl-remove-btn")
    def handle_remove_entity(self) -> None:
        list_id = self.query_one("#wl-target-list-id", Input).value.strip()
        ent_type = self.query_one("#wl-ent-type", Input).value.strip() or None
        ent_val = self.query_one("#wl-ent-value", Input).value.strip()
        if not list_id or not ent_val:
            self._request_remove_entity(list_id, ent_val, ent_type)
            return
        try:
            target_val, resolved_type, resolved_is_id, display_name = (
                self._resolve_loaded_entity_for_removal(list_id, ent_val, ent_type)
            )
        except ValueError as exc:
            self.set_status(str(exc))
            self.append_log(str(exc))
            return
        self._request_remove_entity(
            list_id,
            target_val,
            resolved_type,
            is_id=resolved_is_id,
            display_name=display_name,
        )

    def _request_remove_entity(
        self,
        list_id: str,
        ent_val: str,
        ent_type: str | None,
        *,
        is_id: bool = False,
        display_name: str = "",
    ) -> None:
        if not list_id or not ent_val:
            self.set_status("Target List ID and Entity value/ID are required.")
            return
        label = display_name or ent_val
        if self.effective_dry_run:
            msg = f"[DRY-RUN] Would remove '{label}' from {list_id}."
            self.set_status(msg)
            self.append_log(msg)
            return

        matched_name = next(
            (str(w.get("name") or "") for w in self._all_watchlists if str(w.get("id") or "") == list_id),
            self._current_list_name if list_id == self._current_list_id else "",
        )
        list_label = f"{matched_name} ({list_id})" if matched_name else list_id

        if is_id and display_name and display_name != ent_val:
            confirm_msg = (
                f"Permanently remove '{display_name}' [{ent_val}] "
                f"({ent_type or 'auto'}) from {list_label}?"
            )
            details = (
                f"Watchlist ID: {list_id}\n"
                f"Entity Name: {display_name}\n"
                f"Entity ID: {ent_val}\n"
                f"Type: {ent_type or 'auto-detect'}"
            )
        else:
            confirm_msg = f"Permanently remove '{label}' ({ent_type or 'auto'}) from {list_label}?"
            details = (
                f"Watchlist ID: {list_id}\n"
                f"Entity: {label}\n"
                f"Type: {ent_type or 'auto-detect'}"
            )

        def _cancel() -> None:
            self.set_status("Deletion cancelled. Entity was not removed.")
            self.append_log(f"Cancelled removal of '{label}' from {list_id}.")

        self.confirm_destructive_action(
            title="Confirm Entity Deletion",
            message=confirm_msg,
            details=details,
            confirm_label="Approve Removal",
            on_approved=lambda: self._remove_entity_worker(
                list_id,
                ent_val,
                ent_type,
                is_id=is_id,
                display_name=display_name,
            ),
            on_cancelled=_cancel,
        )

    @work(thread=True, exit_on_error=False)
    def _remove_entity_worker(
        self,
        list_id: str,
        ent_val: str,
        ent_type: str | None,
        *,
        is_id: bool = False,
        display_name: str = "",
    ) -> None:
        label = display_name or ent_val
        try:
            if self.is_app_shutting_down():
                return
            with self.log_scope("watchlists"):
                if is_id:
                    res = self.client.remove_entity(list_id, ent_val, is_id=True)
                else:
                    res = self.client.remove_entity(list_id, ent_val, entity_type=ent_type)
            if self.is_app_shutting_down():
                return
            msg = f"Remove entity result for '{label}': {res.get('result', 'removed')}"
            self.set_status(msg)
            self.append_log(msg)
            if list_id == self._current_list_id and not self.is_app_shutting_down():
                self._refresh_entities_inline(list_id, update_status=False)
        except Exception as exc:
            self.report_error("Remove Entity", exc)

    @on(Button.Pressed, "#wl-export-btn")
    def handle_export_list(self) -> None:
        list_id = self.query_one("#wl-target-list-id", Input).value.strip()
        out_path = self.query_one("#wl-export-path", Input).value.strip()
        if not list_id or not out_path:
            self.set_status("Target List ID and Export path are required.")
            return
        fmt = "json" if out_path.lower().endswith(".json") else "csv"
        self._export_list_worker(list_id, out_path, fmt)

    @work(thread=True, exit_on_error=False)
    def _export_list_worker(self, list_id: str, out_path: str, fmt: str) -> None:
        try:
            if self.is_app_shutting_down():
                return
            dest = (
                self.workspace_dir / out_path
                if not out_path.startswith(("/", "\\"))
                else out_path
            )
            with self.log_scope("watchlists"):
                ok = export_watchlist(self.client, list_id, dest, file_format=fmt)
            if self.is_app_shutting_down():
                return
            msg = (
                f"Exported {list_id} to {dest} ({fmt})."
                if ok
                else f"Failed exporting {list_id}."
            )
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Export Watchlist", exc)
