"""Dedicated application, Brand Sync, and Research logs viewer pane."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, ClassVar

from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Button, Input, RichLog, Select, Static

from soclens.timezone import (
    format_datetime_in_tz,
    format_timezone_label,
    now_in_active_timezone,
)
from soclens.tui.filters import LOG_TIMEFRAME_OPTIONS, timestamp_matches_timeframe
from soclens.tui.logging_bridge import (
    LOG_LEVEL_OPTIONS,
    LOG_LEVEL_RANK,
    LOG_SOURCE_OPTIONS,
    AppLogStore,
    LogEntry,
    source_matches_filter,
)
from soclens.tui.screens.base import BaseSocPane

_LEVEL_STYLE: dict[str, tuple[str, str]] = {
    "DEBUG": ("[DEBUG]", "dim"),
    "INFO": ("[INFO] ", "cyan"),
    "WARNING": ("[WARN] ", "bold yellow"),
    "ERROR": ("[ERROR]", "bold red"),
}


def _entry_display_timestamp(entry: LogEntry) -> str:
    if entry.created_utc is not None:
        return format_datetime_in_tz(entry.created_utc, fmt="%H:%M:%S")
    return entry.timestamp


def format_log_entry(entry: LogEntry) -> Text:
    """Format a ``LogEntry`` into a colorized ``rich.text.Text`` line without markup parsing."""
    badge, badge_style = _LEVEL_STYLE.get(entry.level, ("[INFO] ", "cyan"))
    line = Text(no_wrap=False)
    line.append(_entry_display_timestamp(entry), style="dim")
    line.append(" ")
    line.append(badge, style=badge_style)
    line.append(" ")
    if entry.logger_name and entry.logger_name != entry.source:
        tag = f"[{entry.source}|{entry.logger_name}]"
    else:
        tag = f"[{entry.source}]"
    line.append(tag, style="magenta")
    line.append(" ")
    line.append(entry.message)
    return line


def format_plain_log_entry(entry: LogEntry) -> str:
    """Format a ``LogEntry`` as plain text for file export."""
    if entry.logger_name and entry.logger_name != entry.source:
        tag = f"[{entry.source}|{entry.logger_name}]"
    else:
        tag = f"[{entry.source}]"
    return f"{_entry_display_timestamp(entry)} [{entry.level}] {tag} {entry.message}"


class LogsPane(BaseSocPane):
    """Dedicated Logs page capturing application logging, Brand Sync, Research, and stdio."""

    STATUS_ID = "logs-status"
    LOG_ID = ""
    LOG_SOURCE = "tui"

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("slash", "toggle_filter", "Filter Logs"),
        Binding("escape", "collapse_filter", "Clear Filter", show=False),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._source_filter: str = "all"
        self._level_filter: str = "ALL"
        self._timeframe_filter: str = "any"
        self._text_filter: str = ""
        self._auto_scroll: bool = True
        self._shown_count: int = 0
        self._ready: bool = False

    def compose(self) -> ComposeResult:
        yield Static("Activity, Brand Sync, Research & Application Logs", classes="pane-title")
        yield Static(
            "Logs: 0/0 shown | Warnings: 0 | Errors: 0 | Auto-scroll: ON",
            id="logs-status",
            classes="status-bar",
            markup=False,
        )

        with Horizontal(classes="action-row filter-bar"):
            yield Select(
                list(LOG_SOURCE_OPTIONS),
                allow_blank=False,
                value="all",
                id="logs-source-select",
                compact=True,
            )
            yield Select(
                list(LOG_LEVEL_OPTIONS),
                allow_blank=False,
                value="ALL",
                id="logs-level-select",
                compact=True,
            )
            yield Select(
                list(LOG_TIMEFRAME_OPTIONS),
                allow_blank=False,
                value="any",
                id="logs-timeframe-select",
                compact=True,
            )
            yield Input(
                placeholder="Filter logs (domain, hash, trace_id)...",
                id="logs-filter-input",
                compact=True,
            )

        with Horizontal(classes="action-row toolbar-row"):
            yield Button(
                "Scroll: ON",
                id="logs-autoscroll-btn",
                variant="primary",
                compact=True,
            )
            yield Button("Clear", id="logs-clear-btn", compact=True)
            yield Button("Copy", id="logs-copy-btn", compact=True)
            yield Button("Export", id="logs-export-btn", compact=True)
            yield Button("Errors", id="logs-errors-btn", compact=True)
            yield Button("Brand", id="logs-brand-btn", compact=True)
            yield Button(f"TZ: {format_timezone_label()}", id="logs-tz-btn", compact=True)

        yield RichLog(
            id="app-log",
            classes="primary-log",
            highlight=False,
            markup=False,
            wrap=True,
            auto_scroll=True,
        )

    def on_mount(self) -> None:
        self._ready = True
        try:
            self.query_one("#logs-tz-btn", Button).label = f"TZ: {format_timezone_label()}"
        except Exception:
            pass
        self.rebuild_view()

    def on_tab_activated(self) -> None:
        if self._ready:
            self._update_status_bar()

    def _get_store(self) -> AppLogStore | None:
        store = getattr(self.app, "log_store", None)
        return store if isinstance(store, AppLogStore) else None

    def _entry_matches(self, entry: LogEntry) -> bool:
        if not source_matches_filter(entry.source, self._source_filter):
            return False
        min_rank = LOG_LEVEL_RANK.get(self._level_filter, 0)
        entry_rank = LOG_LEVEL_RANK.get(entry.level, 20)
        if entry_rank < min_rank:
            return False
        if self._timeframe_filter != "any":
            if not timestamp_matches_timeframe(entry.created_utc, self._timeframe_filter):
                return False
        if self._text_filter:
            haystack = (
                f"{_entry_display_timestamp(entry)} {entry.level} {entry.source} "
                f"{entry.logger_name} {entry.message}"
            ).lower()
            if self._text_filter not in haystack:
                return False
        return True

    def _sync_quick_buttons(self) -> None:
        try:
            err_btn = self.query_one("#logs-errors-btn", Button)
            err_btn.variant = "warning" if self._level_filter == "ERROR" else "default"
            brand_btn = self.query_one("#logs-brand-btn", Button)
            brand_btn.variant = "primary" if self._source_filter == "brand_sync" else "default"
        except Exception:
            pass

    def _update_status_bar(self) -> None:
        store = self._get_store()
        total, warn_cnt, err_cnt = store.counts() if store is not None else (0, 0, 0)
        scroll_state = "ON" if self._auto_scroll else "OFF"
        self.set_status(
            f"Logs: {self._shown_count}/{total} shown | "
            f"Warnings: {warn_cnt} | Errors: {err_cnt} | Auto-scroll: {scroll_state}"
        )

    def rebuild_view(self) -> None:
        """Clear and re-render visible log entries from the shared log store."""
        if not self._ready or self.is_app_shutting_down():
            return
        clear_pending = getattr(self.app, "clear_pending_log_flush", None)
        if callable(clear_pending):
            clear_pending()
        try:
            log_widget = self.query_one("#app-log", RichLog)
        except Exception:
            return

        log_widget.clear()
        store = self._get_store()
        entries = store.snapshot() if store is not None else []
        shown = 0
        for entry in entries:
            if self._entry_matches(entry):
                log_widget.write(format_log_entry(entry), scroll_end=False)
                shown += 1
        self._shown_count = shown
        if self._auto_scroll and shown > 0:
            log_widget.scroll_end(animate=False)
        self._sync_quick_buttons()
        self._update_status_bar()

    def append_entries(self, entries: Sequence[LogEntry]) -> None:
        """Incrementally append newly emitted entries matching current filters."""
        if not entries or not self._ready or self.is_app_shutting_down():
            return
        try:
            log_widget = self.query_one("#app-log", RichLog)
        except Exception:
            return

        for entry in entries:
            if self._entry_matches(entry):
                log_widget.write(format_log_entry(entry), scroll_end=self._auto_scroll)
                self._shown_count += 1
        self._update_status_bar()

    def set_source_filter(self, source: str) -> None:
        """Programmatically select a source filter and refresh the view."""
        valid = {val for _label, val in LOG_SOURCE_OPTIONS}
        target = source if source in valid else "all"
        self._source_filter = target
        try:
            sel = self.query_one("#logs-source-select", Select)
            with sel.prevent(Select.Changed):
                sel.value = target
        except Exception:
            pass
        self.rebuild_view()

    def action_toggle_filter(self) -> None:
        """Focus the log text filter input."""
        try:
            self.query_one("#logs-filter-input", Input).focus()
        except Exception:
            pass

    def action_collapse_filter(self) -> None:
        """Clear the text filter if active."""
        try:
            inp = self.query_one("#logs-filter-input", Input)
            if inp.value:
                inp.value = ""
        except Exception:
            pass

    @on(Select.Changed, "#logs-source-select")
    def handle_source_changed(self, event: Select.Changed) -> None:
        if isinstance(event.value, str) and event.value:
            self._source_filter = event.value
            self.rebuild_view()

    @on(Select.Changed, "#logs-level-select")
    def handle_level_changed(self, event: Select.Changed) -> None:
        if isinstance(event.value, str) and event.value:
            self._level_filter = event.value
            self.rebuild_view()

    @on(Select.Changed, "#logs-timeframe-select")
    def handle_timeframe_changed(self, event: Select.Changed) -> None:
        if isinstance(event.value, str) and event.value:
            self._timeframe_filter = event.value
            self.rebuild_view()

    @on(Input.Changed, "#logs-filter-input")
    def handle_filter_changed(self, event: Input.Changed) -> None:
        self._text_filter = event.value.strip().lower()
        self.rebuild_view()

    @on(Button.Pressed, "#logs-autoscroll-btn")
    def handle_toggle_autoscroll(self) -> None:
        self._auto_scroll = not self._auto_scroll
        btn = self.query_one("#logs-autoscroll-btn", Button)
        btn.label = f"Scroll: {'ON' if self._auto_scroll else 'OFF'}"
        btn.variant = "primary" if self._auto_scroll else "default"
        log_widget = self.query_one("#app-log", RichLog)
        log_widget.auto_scroll = self._auto_scroll
        if self._auto_scroll:
            log_widget.scroll_end(animate=False)
        self._update_status_bar()

    @on(Button.Pressed, "#logs-clear-btn")
    def handle_clear_logs(self) -> None:
        store = self._get_store()
        if store is not None:
            store.clear()
        self.query_one("#app-log", RichLog).clear()
        self._shown_count = 0
        self._update_status_bar()

    @on(Button.Pressed, "#logs-errors-btn")
    def handle_toggle_errors_only(self) -> None:
        target = "ALL" if self._level_filter == "ERROR" else "ERROR"
        self._level_filter = target
        sel = self.query_one("#logs-level-select", Select)
        with sel.prevent(Select.Changed):
            sel.value = target
        self.rebuild_view()

    @on(Button.Pressed, "#logs-brand-btn")
    def handle_toggle_brand_sync(self) -> None:
        target = "all" if self._source_filter == "brand_sync" else "brand_sync"
        self.set_source_filter(target)

    def on_timezone_changed(self, tz_name: str) -> None:
        """Refresh TZ button badge and re-render visible log timestamps cleanly."""
        try:
            self.query_one("#logs-tz-btn", Button).label = f"TZ: {format_timezone_label(tz_name)}"
        except Exception:
            pass
        self.rebuild_view()

    @on(Button.Pressed, "#logs-tz-btn")
    def handle_choose_timezone(self) -> None:
        choose_fn = getattr(self.app, "action_choose_timezone", None)
        if callable(choose_fn):
            choose_fn()

    def _visible_logs_plain_text(self) -> str:
        store = self._get_store()
        entries = store.snapshot() if store is not None else []
        matching = [entry for entry in entries if self._entry_matches(entry)]
        return "\n".join(format_plain_log_entry(entry) for entry in matching)

    @on(Button.Pressed, "#logs-copy-btn")
    def handle_copy_visible_logs(self) -> None:
        text = self._visible_logs_plain_text()
        self.copy_to_clipboard(text, label="Visible Logs")

    @on(Button.Pressed, "#logs-export-btn")
    def handle_export_logs(self) -> None:
        store = self._get_store()
        entries = store.snapshot() if store is not None else []
        matching = [entry for entry in entries if self._entry_matches(entry)]

        logs_dir = Path(self.workspace_dir) / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        stamp = now_in_active_timezone().strftime("%Y%m%d_%H%M%S")
        dest = logs_dir / f"tui_session_{stamp}.log"
        lines = [format_plain_log_entry(entry) for entry in matching]
        dest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

        msg = f"Exported {len(matching)} log entry/entries to {dest}"
        self.set_status(msg)
        self.notify_user(msg, title="Logs Exported")

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        event.stop()
        items = [
            ("copy_logs", "Copy Visible Logs"),
            ("open_copy_view", "Open Copyable View"),
            ("filter_all", "Filter: All Sources"),
            ("filter_brand", "Filter: Brand Sync"),
            ("filter_research", "Filter: Research"),
            ("filter_errors", "Filter: Errors Only"),
            ("toggle_scroll", "Toggle Auto-Scroll"),
            ("export_log", "Export Visible Log"),
            ("clear_log", "Clear All Logs"),
        ]

        def _on_select(action_id: str) -> None:
            if action_id == "copy_logs":
                self.handle_copy_visible_logs()
            elif action_id == "open_copy_view":
                self.open_copy_modal(self._visible_logs_plain_text(), title="Visible Logs")
            elif action_id == "filter_all":
                self.set_source_filter("all")
            elif action_id == "filter_brand":
                self.set_source_filter("brand_sync")
            elif action_id == "filter_research":
                self.set_source_filter("research")
            elif action_id == "filter_errors":
                self.handle_toggle_errors_only()
            elif action_id == "toggle_scroll":
                self.handle_toggle_autoscroll()
            elif action_id == "export_log":
                self.handle_export_logs()
            elif action_id == "clear_log":
                self.handle_clear_logs()

        self.open_context_menu(
            items,
            title="Application Logs",
            origin=(event.screen_x, event.screen_y),
            on_select=_on_select,
        )
