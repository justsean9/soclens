"""Shared base pane, double/right-click DataTable, and thread-safe UI helpers."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from rich.text import Text
from textual import events
from textual.containers import VerticalScroll
from textual.coordinate import Coordinate
from textual.message import Message
from textual.widgets import DataTable, RichLog, Static
from textual.widgets._data_table import RowKey

from soclens.client import (
    RecordedFutureAuthError,
    RecordedFutureClient,
    RecordedFutureError,
    RecordedFutureRateLimitError,
)
from soclens.config import ConfigurationError, get_workspace_dir
from soclens.tui.clipboard import copy_text_to_clipboard
from soclens.tui.modals import ConfirmActionModal, ContextMenuModal, CopyTextModal
from soclens.tui.pivot import (
    PivotPayload,
    build_keyword_spl,
    emit_pivot,
    extract_pivot_from_click,
)


def extract_table_row_text(table: DataTable[Any], row_index: int | None = None) -> str:
    """Format a DataTable row as plain copyable ``Column: Value`` text."""
    if table.row_count <= 0:
        return ""
    idx = table.cursor_row if row_index is None else row_index
    if idx is None or idx < 0 or idx >= table.row_count:
        return ""
    try:
        row_key = table.ordered_rows[idx].key
        cells = table.get_row(row_key)
    except Exception:
        return ""
    columns = list(table.ordered_columns)
    parts: list[str] = []
    for col_idx, cell in enumerate(cells):
        val = cell.plain if isinstance(cell, Text) else str(cell)
        val = val.strip()
        if col_idx < len(columns):
            raw_label = columns[col_idx].label
            label = (raw_label.plain if isinstance(raw_label, Text) else str(raw_label)).strip()
            parts.append(f"{label}: {val}" if label else val)
        else:
            parts.append(val)
    return " | ".join(parts)


def extract_richlog_text(log_widget: RichLog) -> str:
    """Extract plain text lines currently rendered in a ``RichLog`` widget."""
    lines = getattr(log_widget, "lines", None)
    if not lines:
        return ""
    extracted = [str(getattr(line, "text", line)).rstrip() for line in lines]
    return "\n".join(extracted).strip()


class DoubleClickDataTable(DataTable[Any]):
    """DataTable emitting ``RowSelected`` on double-click/Enter and ``RowRightClicked`` on button 3."""

    DOUBLE_CLICK_WINDOW: float = 0.55

    class RowRightClicked(Message):
        """Posted when a user right-clicks inside a ``DoubleClickDataTable``."""

        def __init__(
            self,
            data_table: DoubleClickDataTable,
            row_index: int | None,
            row_key: RowKey | None,
            screen_x: int,
            screen_y: int,
        ) -> None:
            self.data_table: DoubleClickDataTable = data_table
            self.row_index: int | None = row_index
            self.row_key: RowKey | None = row_key
            self.screen_x: int = screen_x
            self.screen_y: int = screen_y
            super().__init__()

        @property
        def control(self) -> DoubleClickDataTable:
            return self.data_table

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._last_click_row: int | None = None
        self._last_click_time: float = 0.0
        self._hovered_row_index: int | None = None
        self._row_tooltip_provider: Callable[[int], str | None] | None = None

    def set_row_tooltip_provider(self, provider: Callable[[int], str | None] | None) -> None:
        """Register an optional callback returning custom full-line hover text for a row index."""
        self._row_tooltip_provider = provider

    def _build_hover_tooltip(self, row_index: int) -> str | None:
        if not self.is_valid_row_index(row_index):
            return None
        if self._row_tooltip_provider is not None:
            try:
                custom = self._row_tooltip_provider(row_index)
                if custom:
                    return custom
            except Exception:
                pass
        row_text = extract_table_row_text(self, row_index=row_index)
        return row_text or None

    def on_mouse_move(self, event: events.MouseMove) -> None:
        """Show a full-line hover popup tooltip for the row currently under the pointer."""
        meta = event.style.meta
        if "row" in meta:
            try:
                row_index = int(meta["row"])
            except (TypeError, ValueError):
                row_index = -1
            if self.is_valid_row_index(row_index):
                if row_index != self._hovered_row_index:
                    self._hovered_row_index = row_index
                    self.tooltip = self._build_hover_tooltip(row_index)
                return
        if self._hovered_row_index is not None or self.tooltip is not None:
            self._hovered_row_index = None
            self.tooltip = None

    def on_leave(self, _event: events.Leave) -> None:
        """Clear row hover popup tooltip when pointer leaves the table."""
        self._hovered_row_index = None
        self.tooltip = None

    async def _on_click(self, event: events.Click) -> None:
        event.prevent_default()
        self._set_hover_cursor(True)

        if event.button == 3:
            event.stop()
            self.focus()
            meta = event.style.meta
            if "row" in meta and "column" in meta:
                row_index = int(meta["row"])
                column_index = int(meta["column"])
                if self.is_valid_row_index(row_index):
                    self.cursor_coordinate = Coordinate(row_index, max(0, column_index))
                    row_key = self.ordered_rows[row_index].key
                    self.post_message(
                        DoubleClickDataTable.RowRightClicked(
                            self,
                            row_index,
                            row_key,
                            event.screen_x,
                            event.screen_y,
                        )
                    )
                    return
            self.post_message(
                DoubleClickDataTable.RowRightClicked(
                    self,
                    None,
                    None,
                    event.screen_x,
                    event.screen_y,
                )
            )
            return

        if event.button != 1:
            return

        meta = event.style.meta
        if "row" not in meta or "column" not in meta:
            return
        if self.cursor_type != "row" and meta.get("out_of_bounds", False):
            return

        row_index = int(meta["row"])
        column_index = int(meta["column"])
        is_header_click = self.show_header and row_index == -1
        is_row_label_click = self.show_row_labels and column_index == -1
        if is_header_click:
            if 0 <= column_index < len(self.ordered_columns):
                column = self.ordered_columns[column_index]
                self.post_message(
                    DataTable.HeaderSelected(
                        self, column.key, column_index, label=column.label
                    )
                )
            event.stop()
        elif is_row_label_click:
            if 0 <= row_index < len(self.ordered_rows):
                row = self.ordered_rows[row_index]
                label = row.label if row.label is not None else Text("")
                self.post_message(
                    DataTable.RowLabelSelected(
                        self, row.key, row_index, label=label
                    )
                )
        elif (
            self.show_cursor
            and self.cursor_type != "none"
            and self.is_valid_row_index(row_index)
        ):
            self.cursor_coordinate = Coordinate(row_index, max(0, column_index))
            now = time.monotonic()
            is_double = (event.chain >= 2 and event.chain % 2 == 0) or (
                event.chain == 1
                and self._last_click_row == row_index
                and (now - self._last_click_time) <= self.DOUBLE_CLICK_WINDOW
            )
            if is_double:
                self._last_click_row = None
                self._last_click_time = 0.0
                self._post_selected_message()
            else:
                self._last_click_row = row_index
                self._last_click_time = now
            self._scroll_cursor_into_view(animate=True)
            event.stop()


class BaseSocPane(VerticalScroll):
    """Base scrollable pane offering thread-safe status, log, modal, and layout helpers."""

    STATUS_ID: str = ""
    LOG_ID: str = ""
    LOG_SOURCE: str = "tui"

    def log_scope(self, source: str | None = None) -> AbstractContextManager[None]:
        """Tag stdout/stderr/warnings emitted by worker code with this pane's source."""
        scope_fn = getattr(self.app, "log_scope", None)
        if callable(scope_fn):
            ctx = scope_fn(source or self.LOG_SOURCE or "tui")
            if isinstance(ctx, AbstractContextManager):
                return ctx
        return contextlib.nullcontext()

    def record_app_log(
        self,
        message: str,
        *,
        level: str = "INFO",
        source: str | None = None,
    ) -> None:
        """Forward a structured message to the centralized application Logs page."""
        try:
            record_fn = getattr(self.app, "record_log", None)
            if callable(record_fn):
                record_fn(
                    message,
                    level=level,
                    source=source or self.LOG_SOURCE or "tui",
                    logger_name=type(self).__name__,
                )
        except Exception:
            pass

    def on_tab_activated(self) -> None:
        """Hook invoked when this pane's TabPane becomes active."""

    def on_settings_updated(self) -> None:
        """Hook invoked after per-user settings are saved or reloaded."""

    @property
    def client(self) -> Any:
        """Return the shared client owned by the App."""
        app_client = getattr(self.app, "client", None)
        if app_client is not None:
            return app_client
        return RecordedFutureClient()

    @property
    def effective_dry_run(self) -> bool:
        """Return True when the TUI is running in read-only dry-run mode."""
        return bool(getattr(self.app, "dry_run", False))

    @property
    def workspace_dir(self) -> Path:
        """Resolve the active workspace directory cross-platform."""
        return get_workspace_dir(getattr(self.app, "workspace_dir", None))

    def is_app_shutting_down(self) -> bool:
        """Return True if this pane is unattached or the host app is exiting."""
        if not self.is_attached:
            return True
        try:
            app = self.app
        except Exception:
            return True
        return bool(getattr(app, "is_shutting_down", False))

    def run_on_ui(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute a UI mutation safely from either the UI thread or a worker thread."""
        if self.is_app_shutting_down():
            return None
        try:
            app = self.app
            app_tid = getattr(app, "_thread_id", None)
            if app_tid is not None and threading.get_ident() != app_tid:
                return app.call_from_thread(fn, *args, **kwargs)
            return fn(*args, **kwargs)
        except Exception:
            return None

    def set_status(self, message: str) -> None:
        """Update the pane status banner safely from any thread."""
        if not self.STATUS_ID:
            return

        def _apply() -> None:
            try:
                widget = self.query_one(f"#{self.STATUS_ID}", Static)
                widget.update(message)
            except Exception:
                pass

        self.run_on_ui(_apply)

    def append_log(self, message: str, *, level: str = "INFO") -> None:
        """Append a line to the centralized Logs tab and optional local viewer."""
        self.record_app_log(message, level=level)
        if not self.LOG_ID:
            return

        def _apply() -> None:
            try:
                log_widget = self.query_one(f"#{self.LOG_ID}", RichLog)
                log_widget.write(message)
            except Exception:
                pass

        self.run_on_ui(_apply)

    def notify_user(
        self, message: str, *, title: str = "RF SOC", severity: str = "information"
    ) -> None:
        """Display a non-blocking Textual notification safely from any thread."""

        def _apply() -> None:
            try:
                self.app.notify(message, title=title, severity=severity)  # type: ignore[arg-type]
            except Exception:
                pass

        self.run_on_ui(_apply)

    def copy_to_clipboard(self, text: str, *, label: str = "Text") -> bool:
        """Copy text to the OS clipboard / OSC 52, updating status and notifying the user."""
        if not text:
            msg = f"Nothing to copy for {label}."
            self.set_status(msg)
            self.notify_user(msg, title="Clipboard", severity="warning")
            return False

        app_obj: Any = None
        try:
            app_obj = self.app
        except Exception:
            app_obj = None

        result = copy_text_to_clipboard(text, app=app_obj)
        if result.success:
            msg = f"Copied {label} ({result.char_count:,} chars) via {result.method}."
            self.set_status(msg)
            self.notify_user(msg, title="Copied to Clipboard")
            return True

        err = result.error or "No clipboard backend available."
        msg = f"Failed to copy {label}: {err}"
        self.set_status(msg)
        self.notify_user(msg, title="Clipboard Unavailable", severity="warning")
        return False

    def open_copy_modal(
        self,
        text: str,
        *,
        title: str = "Copyable Text",
        language: str | None = None,
    ) -> None:
        """Open a selectable read-only ``CopyTextModal`` for inspecting and copying text."""
        if self.is_app_shutting_down():
            return
        if not text:
            msg = f"No text available for {title}."
            self.set_status(msg)
            self.notify_user(msg, title="Copyable View", severity="warning")
            return
        self.run_on_ui(
            self.app.push_screen,
            CopyTextModal(
                text,
                title=title,
                language=language,
                workspace_dir=self.workspace_dir,
            ),
        )

    def open_context_menu(
        self,
        items: Sequence[tuple[str, str]],
        *,
        title: str = "",
        origin: tuple[int, int] = (2, 2),
        on_select: Callable[[str], None],
    ) -> None:
        """Open a floating right-click context menu and invoke ``on_select`` when chosen."""
        if self.is_app_shutting_down() or not items:
            return

        def _handle_result(action_id: str | None) -> None:
            if action_id is not None:
                on_select(action_id)

        self.run_on_ui(
            self.app.push_screen,
            ContextMenuModal(items, title=title, origin=origin),
            _handle_result,
        )

    def open_field_pivot_menu(
        self,
        field_label: str,
        value: str,
        *,
        origin: tuple[int, int] = (2, 2),
        source_tab: str = "",
    ) -> None:
        """Open a universal right-click search & pivot menu for any clicked field value."""
        clean_val = str(value or "").strip()
        if not clean_val or clean_val == "-":
            return
        short_val = clean_val if len(clean_val) <= 34 else f"{clean_val[:31]}..."
        spl_preview = build_keyword_spl(short_val)
        items: list[tuple[str, str]] = [
            ("splunk_keyword", f"Splunk Search: {spl_preview}"),
            ("research", f"Deep Research (RF + OSINT): {short_val}"),
            ("rf_intel", "RF Intel Lookup (v2 / Entity Match)"),
            ("splunk_es", "Search Splunk ES Notables"),
            ("sentinelone", "Search SentinelOne"),
            ("llm", "Analyze in Local LLM (F7)"),
            ("copy_value", f"Copy Value ({field_label})"),
        ]

        def _on_select(action_id: str) -> None:
            if action_id == "copy_value":
                self.copy_to_clipboard(clean_val, label=field_label)
                return
            if action_id == "splunk_keyword":
                spl = build_keyword_spl(clean_val)
                open_fn = getattr(self.app, "open_splunk_search", None)
                if callable(open_fn):
                    open_fn(spl, auto_run=False)
                else:
                    emit_pivot(
                        self.app,
                        PivotPayload(
                            source_tab=source_tab or self.LOG_SOURCE,
                            target_tab="tab-splunk-search",
                            entity=clean_val,
                            spl_query=spl,
                        ),
                    )
                return
            target_map = {
                "research": "tab-research",
                "rf_intel": "tab-rf-intel",
                "splunk_es": "tab-splunk-es",
                "sentinelone": "tab-sentinelone",
                "llm": "tab-llm",
            }
            target_tab = target_map.get(action_id)
            if not target_tab:
                return
            emit_pivot(
                self.app,
                PivotPayload(
                    source_tab=source_tab or self.LOG_SOURCE,
                    target_tab=target_tab,
                    entity=clean_val,
                    entity_type="auto",
                    summary=f"{field_label}: {clean_val}",
                ),
            )

        self.open_context_menu(
            items,
            title=f"Pivot {field_label}: {short_val}",
            origin=origin,
            on_select=_on_select,
        )

    def handle_field_pivot_right_click(
        self,
        event: events.Click,
        *,
        source_tab: str = "",
    ) -> bool:
        """If ``event`` is a right-click with highlighted text or on a pivotable field, open the menu."""
        if event.button != 3:
            return False
        get_sel = getattr(self.app, "get_selected_text", None)
        if callable(get_sel):
            selected = str(get_sel() or "").strip()
            if selected:
                event.stop()
                self.open_field_pivot_menu(
                    "Selection",
                    selected,
                    origin=(event.screen_x, event.screen_y),
                    source_tab=source_tab,
                )
                return True
        hit = extract_pivot_from_click(event)
        if hit is None:
            return False
        field_label, value = hit
        event.stop()
        self.open_field_pivot_menu(
            field_label,
            value,
            origin=(event.screen_x, event.screen_y),
            source_tab=source_tab,
        )
        return True

    def on_click(self, event: events.Click) -> None:
        """Default pane right-click handler enabling any-field search & pivot."""
        self.handle_field_pivot_right_click(event)

    def confirm_destructive_action(
        self,
        *,
        title: str,
        message: str,
        details: str = "",
        confirm_label: str = "Approve Delete",
        on_approved: Callable[[], Any],
        on_cancelled: Callable[[], Any] | None = None,
    ) -> None:
        """Display an explicit approval prompt before executing a deletion."""
        if self.is_app_shutting_down():
            return

        def _handle_result(approved: bool | None) -> None:
            if approved:
                on_approved()
            elif on_cancelled is not None:
                on_cancelled()

        self.run_on_ui(
            self.app.push_screen,
            ConfirmActionModal(
                title,
                message,
                details=details,
                confirm_label=confirm_label,
            ),
            _handle_result,
        )

    def confirm_action_from_worker(
        self,
        *,
        title: str,
        message: str,
        details: str = "",
        confirm_label: str = "Approve Delete",
    ) -> bool:
        """Prompt for approval from a worker thread and wait safely for decision."""
        if self.is_app_shutting_down():
            return False
        done = threading.Event()
        decision: list[bool] = [False]

        def _on_result(approved: bool | None) -> None:
            decision[0] = bool(approved)
            done.set()

        def _push() -> None:
            try:
                self.app.push_screen(
                    ConfirmActionModal(
                        title,
                        message,
                        details=details,
                        confirm_label=confirm_label,
                    ),
                    _on_result,
                )
            except Exception:
                done.set()

        self.run_on_ui(_push)
        while not done.wait(0.1):
            if self.is_app_shutting_down():
                return False
        return decision[0]

    def fit_table_columns(
        self,
        table: DataTable[Any],
        specs: Sequence[tuple[str, float, int]],
    ) -> None:
        """Stretch DataTable columns proportionally to fill the available horizontal width."""
        if not specs or not table.columns:
            return
        avail = table.content_region.width - 2
        if avail <= 0:
            return
        padding_total = len(specs) * (2 * table.cell_padding)
        usable = max(0, avail - padding_total)
        widths = [max(min_w, int(usable * weight)) for _, weight, min_w in specs]
        rem = usable - sum(widths)
        if rem > 0:
            widths[-1] += rem

        cols_by_key = {
            (col.key.value if col.key.value is not None else str(col.key)): col
            for col in table.columns.values()
        }
        ordered_cols = list(table.columns.values())
        for idx, ((key, _, _), width) in enumerate(zip(specs, widths, strict=False)):
            col = cols_by_key.get(key)
            if col is None and idx < len(ordered_cols):
                col = ordered_cols[idx]
            if col is not None:
                col.auto_width = False
                col.width = width

        table._require_update_dimensions = True
        table.refresh(layout=True)

    @staticmethod
    def format_exception(exc: Exception) -> str:
        """Format Recorded Future / configuration / IO errors with actionable diagnostics."""
        if isinstance(exc, RecordedFutureAuthError):
            trace = f" | trace_id={exc.trace_id}" if exc.trace_id else ""
            return f"HTTP {exc.status_code} ({exc.permission_type}): {exc.message}{trace}"
        if isinstance(exc, RecordedFutureRateLimitError):
            trace = f" | trace_id={exc.trace_id}" if exc.trace_id else ""
            retry = f" | retry_after={exc.retry_after}s" if exc.retry_after is not None else ""
            return f"HTTP 429 Rate Limit: {exc.message}{retry}{trace}"
        if isinstance(exc, RecordedFutureError):
            trace = f" | trace_id={exc.trace_id}" if exc.trace_id else ""
            status = f"HTTP {exc.status_code}" if exc.status_code is not None else "API Error"
            return f"{status}: {exc.message}{trace}"
        if isinstance(exc, ConfigurationError):
            return f"Configuration error: {exc}"
        return f"{type(exc).__name__}: {exc}"

    def report_error(self, context: str, exc: Exception) -> None:
        """Log and notify an error safely without crashing the TUI."""
        if self.is_app_shutting_down():
            return
        if isinstance(exc, RecordedFutureError) and getattr(exc, "reason", None) == "cancelled":
            return
        detail = self.format_exception(exc)
        msg = f"[ERROR] {context}: {detail}"
        self.set_status(msg)
        self.append_log(msg, level="ERROR")
        self.notify_user(detail, title=context, severity="error")

    def on_timezone_changed(self, tz_name: str) -> None:
        """Hook invoked when the active TUI display timezone changes."""
        _ = tz_name
