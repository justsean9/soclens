"""Shared base pane, double/right-click DataTable, and thread-safe UI helpers."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from rich.cells import cell_len, get_character_cell_size
from rich.segment import Segment
from rich.style import Style
from rich.text import Text
from textual import events
from textual.containers import VerticalScroll
from textual.coordinate import Coordinate
from textual.message import Message
from textual.selection import Selection
from textual.strip import Strip
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
    is_clickable_known_field,
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


_DEFAULT_SELECTION_STYLE = Style(bgcolor="#f2cc60", color="#0b0f17", bold=True)


def _apply_post_style(strip: Strip, post_style: Style) -> Strip:
    """Apply ``post_style`` on top of existing segment styles while preserving metadata."""
    return Strip(
        Segment.apply_style(strip._segments, post_style=post_style),
        strip.cell_length,
    )


def _apply_selection_highlight(
    widget: Any,
    strip: Strip,
    line_index: int,
    line_text: str,
    scroll_x: int,
) -> Strip:
    """Apply high-contrast selection highlight styling to a rendered ``Strip`` line."""
    selection = getattr(widget, "text_selection", None)
    if selection is None:
        return strip
    span = selection.get_span(line_index)
    if span is None:
        return strip
    start_char, end_char = span
    start_cell = cell_len(line_text[:start_char]) if start_char > 0 else 0
    end_cell = (
        strip.cell_length + scroll_x
        if end_char == -1
        else cell_len(line_text[:end_char])
    )
    line_len = strip.cell_length
    vis_start = max(0, start_cell - scroll_x)
    vis_end = max(0, min(line_len, end_cell - scroll_x))
    if vis_start >= vis_end:
        return strip
    try:
        sel_style = widget.screen.get_component_rich_style("screen--selection")
    except Exception:
        sel_style = _DEFAULT_SELECTION_STYLE
    if (
        not sel_style
        or sel_style.bgcolor is None
        or sel_style.color == sel_style.bgcolor
    ):
        sel_style = _DEFAULT_SELECTION_STYLE
    else:
        sel_style = sel_style + Style(bold=True)
    if vis_start == 0 and vis_end >= line_len:
        return _apply_post_style(strip, sel_style)
    if vis_start == 0:
        middle, after = strip.divide([vis_end, line_len])
        return Strip.join([_apply_post_style(middle, sel_style), after])
    if vis_end >= line_len:
        before, middle = strip.divide([vis_start, line_len])
        return Strip.join([before, _apply_post_style(middle, sel_style)])
    before, middle, after = strip.divide([vis_start, vis_end, line_len])
    return Strip.join([before, _apply_post_style(middle, sel_style), after])


class SelectableRichLog(RichLog):
    """``RichLog`` subclass with bright drag selection and button-like clickable known fields."""

    ALLOW_SELECT = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._hovered_pivot: tuple[str, str] | None = None
        self._active_pivot: tuple[str, str] | None = None
        self._left_down_screen_pos: tuple[int, int] | None = None

    def on_mouse_move(self, event: events.MouseMove) -> None:
        """Highlight hovered clickable known fields like buttons."""
        hit = extract_pivot_from_click(event)
        if hit != self._hovered_pivot:
            self._hovered_pivot = hit
            self.refresh()

    def on_leave(self, _event: events.Leave) -> None:
        """Clear hovered field highlight when the pointer leaves the log."""
        if self._hovered_pivot is not None:
            self._hovered_pivot = None
            self.refresh()

    def on_mouse_down(self, event: events.MouseDown) -> None:
        """Track left-press coordinates so drag-highlighting does not trigger button-click popup."""
        if event.button == 1:
            self._left_down_screen_pos = (event.screen_x, event.screen_y)

    def on_click(self, event: events.Click) -> None:
        """Left-clicking a known clickable field auto-opens the RF / Splunk search popup."""
        if event.button != 1:
            return
        down_pos = self._left_down_screen_pos
        self._left_down_screen_pos = None
        if down_pos is not None and down_pos != (event.screen_x, event.screen_y):
            return
        get_sel = getattr(self.app, "get_selected_text", None)
        if callable(get_sel) and str(get_sel() or "").strip():
            return
        hit = extract_pivot_from_click(event)
        if hit is None:
            return
        field_label, value = hit
        self._active_pivot = (field_label, value)
        self.refresh()

        def _clear_active() -> None:
            self._active_pivot = None
            self.refresh()

        open_menu = getattr(self.app, "open_selection_pivot_menu", None)
        if callable(open_menu):
            event.stop()
            open_menu(
                value,
                origin=(event.screen_x, event.screen_y),
                field_label=field_label,
                on_close=_clear_active,
            )

    def _apply_pivot_button_style(self, strip: Strip) -> Strip:
        if self._active_pivot is None and self._hovered_pivot is None:
            return strip
        active = self._active_pivot
        hovered = self._hovered_pivot
        active_style = Style(bgcolor="#f2cc60", color="#0b0f17", bold=True, underline=True)
        hover_style = Style(bgcolor="#1f6feb", color="#ffffff", bold=True, underline=True)
        changed = False
        new_segments: list[Segment] = []
        for seg in strip._segments:
            style = seg.style
            meta = style.meta if style is not None and style._meta is not None else None
            if isinstance(meta, dict):
                pv = str(meta.get("pivot_value") or "").strip()
                pf = str(meta.get("pivot_field") or "Value").strip() or "Value"
                if pv:
                    pair = (pf, pv)
                    if active is not None and pair == active:
                        new_segments.append(
                            Segment(
                                seg.text,
                                (style + active_style) if style else active_style,
                                seg.control,
                            )
                        )
                        changed = True
                        continue
                    if hovered is not None and pair == hovered:
                        new_segments.append(
                            Segment(
                                seg.text,
                                (style + hover_style) if style else hover_style,
                                seg.control,
                            )
                        )
                        changed = True
                        continue
            new_segments.append(seg)
        return Strip(new_segments, strip.cell_length) if changed else strip

    def get_selection(self, selection: Selection) -> tuple[str, str] | None:
        """Extract the exact highlighted text across rendered ``RichLog`` lines."""
        if not self.lines:
            return None
        full_text = "\n".join(line.text for line in self.lines)
        extracted = selection.extract(full_text)
        if not extracted:
            return None
        cleaned = "\n".join(part.rstrip() for part in extracted.splitlines()).strip()
        if not cleaned:
            return None
        return cleaned, "\n"

    def selection_updated(self, selection: Selection | None) -> None:
        """Refresh visible lines immediately as the user drags a text highlight."""
        self._line_cache.clear()
        self.refresh()

    def render_line(self, y: int) -> Strip:
        """Render a viewport line with selection offset metadata, button hover/active, and highlight."""
        strip = super().render_line(y)
        scroll_x, scroll_y = self.scroll_offset
        line_index = scroll_y + y
        if not (0 <= line_index < len(self.lines)):
            return strip
        line_text = self.lines[line_index].text
        char_x = 0
        if scroll_x > 0:
            cells = 0
            for ch in line_text:
                if cells >= scroll_x:
                    break
                cells += get_character_cell_size(ch)
                char_x += 1
        strip = self._apply_pivot_button_style(strip)
        strip = _apply_selection_highlight(self, strip, line_index, line_text, scroll_x)
        return strip.apply_offsets(char_x, line_index)


class DoubleClickDataTable(DataTable[Any]):
    """Selectable DataTable emitting ``RowSelected`` on double-click/Enter."""

    ALLOW_SELECT = True
    DOUBLE_CLICK_WINDOW: float = 0.55

    class RowRightClicked(Message):
        """Legacy message type kept for backwards-compatible imports."""

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

    def _fixed_rows_height(self) -> int:
        fixed_h = 0
        for i in range(self.fixed_rows):
            row_key = self._row_locations.get_key(i)
            if row_key is not None:
                fixed_h += self.get_row_height(row_key)
        if self.show_header:
            fixed_h += self.get_row_height(self._header_row_key)
        return fixed_h

    def selection_updated(self, selection: Selection | None) -> None:
        """Refresh table lines immediately as the user drags a text highlight."""
        self._line_cache.clear()
        self.refresh()

    def render_line(self, y: int) -> Strip:
        """Render a table line with selection offset metadata and highlight styling."""
        strip = super().render_line(y)
        scroll_x, scroll_y = self.scroll_offset
        fixed_h = self._fixed_rows_height()
        line_index = y if y < fixed_h else y + scroll_y
        char_x = 0
        if scroll_x > 0:
            left_strip = self._render_line(line_index, 0, scroll_x, self.rich_style)
            char_x = len(left_strip.text)
        if self.text_selection is not None:
            if scroll_x > 0:
                full_w = max(self.virtual_size.width, self.size.width)
                full_text = self._render_line(line_index, 0, full_w, self.rich_style).text
            else:
                full_text = strip.text
            strip = _apply_selection_highlight(self, strip, line_index, full_text, scroll_x)
        return strip.apply_offsets(char_x, line_index)

    def get_selection(self, selection: Selection) -> tuple[str, str] | None:
        """Extract highlighted cell text from rendered ``DataTable`` rows."""
        total_lines = self._fixed_rows_height() + sum(
            self.get_row_height(row.key) for row in self.ordered_rows
        )
        if total_lines <= 0:
            return None
        start_y = max(0, selection.start.y) if selection.start is not None else 0
        end_y = (
            min(total_lines - 1, selection.end.y)
            if selection.end is not None
            else total_lines - 1
        )
        if end_y < start_y:
            return None
        full_w = max(self.virtual_size.width, self.size.width)
        lines: list[str] = [""] * start_y
        for idx in range(start_y, end_y + 1):
            rendered = self._render_line(idx, 0, full_w, self.rich_style)
            lines.append(rendered.text)
        extracted = selection.extract("\n".join(lines))
        if not extracted:
            return None
        cleaned = "\n".join(part.rstrip() for part in extracted.splitlines()).strip()
        if not cleaned:
            return None
        return cleaned, "\n"

    def extract_cell_at_event(self, event: events.MouseEvent) -> tuple[str, str] | None:
        """Return ``(column_label, cell_value)`` when pointer is on a searchable known cell."""
        style = getattr(event, "style", None)
        meta = getattr(style, "meta", None) if style is not None else None
        if not isinstance(meta, dict):
            return None
        if "row" not in meta or "column" not in meta:
            return None
        try:
            row_index = int(meta["row"])
            col_index = int(meta["column"])
        except (TypeError, ValueError):
            return None
        if row_index < 0 or not self.is_valid_row_index(row_index):
            return None
        columns = list(self.ordered_columns)
        if not (0 <= col_index < len(columns)):
            return None
        try:
            row_key = self.ordered_rows[row_index].key
            cells = self.get_row(row_key)
        except Exception:
            return None
        if col_index >= len(cells):
            return None
        cell = cells[col_index]
        val = (cell.plain if isinstance(cell, Text) else str(cell)).strip()
        raw_label = columns[col_index].label
        col_label = (raw_label.plain if isinstance(raw_label, Text) else str(raw_label)).strip() or "Field"
        if not is_clickable_known_field(col_label, val):
            return None
        return col_label, val

    def extract_row_index_at_event(self, event: events.MouseEvent) -> int | None:
        """Return the valid 0-based data row index under ``event``, or ``None`` if header/outside."""
        style = getattr(event, "style", None)
        meta = getattr(style, "meta", None) if style is not None else None
        if not isinstance(meta, dict) or "row" not in meta:
            return None
        if meta.get("out_of_bounds", False):
            return None
        try:
            row_index = int(meta["row"])
        except (TypeError, ValueError):
            return None
        if row_index < 0 or not self.is_valid_row_index(row_index):
            return None
        return row_index

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
        """Open a right-click RF / Splunk search menu for a clicked field or highlighted text."""
        clean_val = " ".join(str(value or "").strip().splitlines()).strip()
        if not clean_val or clean_val == "-":
            return
        app_menu = getattr(self.app, "open_selection_pivot_menu", None)
        if callable(app_menu):
            app_menu(clean_val, origin=origin, field_label=field_label)
            return

        short_val = clean_val if len(clean_val) <= 34 else f"{clean_val[:31]}..."
        spl_preview = build_keyword_spl(short_val)
        items: list[tuple[str, str]] = [
            ("research", f"Search in RF (Research): {short_val}"),
            ("rf_intel", f"Search in RF Intel: {short_val}"),
            ("splunk_keyword", f"Search in Splunk: {spl_preview}"),
        ]

        def _on_select(action_id: str) -> None:
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
            target_tab = "tab-research" if action_id == "research" else "tab-rf-intel"
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

        title = (
            f"Search {field_label}: {short_val}"
            if field_label and field_label != "Selection"
            else f"Search: {short_val}"
        )
        self.open_context_menu(
            items,
            title=title,
            origin=origin,
            on_select=_on_select,
        )

    def handle_field_pivot_right_click(
        self,
        event: events.Click,
        *,
        source_tab: str = "",
    ) -> bool:
        """If ``event`` is a right-click with highlighted text or on a known field, open search."""
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
        if not is_clickable_known_field(field_label, value):
            return False
        event.stop()
        self.open_field_pivot_menu(
            field_label,
            value,
            origin=(event.screen_x, event.screen_y),
            source_tab=source_tab,
        )
        return True

    def confirm_destructive_action(
        self,
        *,
        title: str,
        message: str,
        details: str = "",
        confirm_label: str = "Approve Delete",
        warning_text: str | None = None,
        double_confirm: bool = False,
        second_title: str | None = None,
        second_message: str | None = None,
        second_confirm_label: str | None = None,
        second_warning_text: str | None = None,
        on_approved: Callable[[], Any],
        on_cancelled: Callable[[], Any] | None = None,
    ) -> None:
        """Display an explicit approval prompt (or two sequential prompts) before acting."""
        if self.is_app_shutting_down():
            return

        def _handle_final_result(approved: bool | None) -> None:
            if approved:
                on_approved()
            elif on_cancelled is not None:
                on_cancelled()

        if not double_confirm:
            self.run_on_ui(
                self.app.push_screen,
                ConfirmActionModal(
                    title,
                    message,
                    details=details,
                    confirm_label=confirm_label,
                    warning_text=warning_text,
                ),
                _handle_final_result,
            )
            return

        step1_title = title if title.startswith("[Step 1/2]") else f"[Step 1/2] {title}"
        step1_warning = (
            warning_text
            if warning_text is not None
            else "Step 1 of 2: Double approval is required for this high-impact action."
        )
        step2_title = second_title or f"[Step 2/2] Final Confirmation: {title}"
        step2_message = second_message or f"Confirm again: {message}"
        step2_label = second_confirm_label or f"Confirm {confirm_label}"
        step2_warning = (
            second_warning_text
            if second_warning_text is not None
            else "FINAL APPROVAL (Step 2 of 2): This high-impact action will execute immediately."
        )

        def _handle_step1(approved: bool | None) -> None:
            if not approved:
                if on_cancelled is not None:
                    on_cancelled()
                return
            if self.is_app_shutting_down():
                return
            self.run_on_ui(
                self.app.push_screen,
                ConfirmActionModal(
                    step2_title,
                    step2_message,
                    details=details,
                    confirm_label=step2_label,
                    warning_text=step2_warning,
                ),
                _handle_final_result,
            )

        self.run_on_ui(
            self.app.push_screen,
            ConfirmActionModal(
                step1_title,
                message,
                details=details,
                confirm_label=confirm_label,
                warning_text=step1_warning,
            ),
            _handle_step1,
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

    def switch_to_pane(
        self,
        tab_id: str,
        *,
        auto_enable_admin: bool = False,
        on_ready: Callable[[BaseSocPane], None] | None = None,
    ) -> bool:
        """Activate ``tab_id`` via ``SocLensApp.activate_tab`` or ``WorkspaceHost``."""
        activate_fn = getattr(self.app, "activate_tab", None)
        if callable(activate_fn):
            return bool(
                activate_fn(
                    tab_id,
                    auto_enable_admin=auto_enable_admin,
                    on_ready=on_ready,
                )
            )
        from soclens.tui.tiling import WorkspaceHost

        with contextlib.suppress(Exception):
            host = self.app.query_one(WorkspaceHost)
            return bool(
                host.switch_to_pane(
                    tab_id,
                    auto_enable_admin=auto_enable_admin,
                    on_ready=on_ready,
                )
            )
        return False

    def sync_event_ai_panel(self, panel_selector: str, event: Any) -> None:
        """Bind ``event`` and its persisted AI entries to the pane-scoped ``EventAIPanelWidget``."""
        from soclens.tui.ai_widgets import EventAIPanelWidget

        try:
            panel = self.query_one(panel_selector, EventAIPanelWidget)
        except Exception:
            return
        if event is None:
            panel.set_event(None, ())
            return
        store = getattr(self.app, "event_ai_store", None)
        panels = store.get_panels(event.event_key) if store is not None else ()
        panel.set_event(event, panels)

    def request_ask_event_ai(self, panel_selector: str, event: Any) -> None:
        """Prompt for an event-only question and launch an ``ask_only`` investigation."""
        if self.is_app_shutting_down() or event is None:
            return
        is_killed_fn = getattr(self.app, "is_ai_killed", None)
        if callable(is_killed_fn) and is_killed_fn():
            self.notify_user(
                "AI Kill Switch is active — all AI actions are halted. Click AI HALTED or press the kill hotkey to resume.",
                title="AI Halted",
                severity="warning",
            )
            return
        from soclens.tui.ai_widgets import AskEventAIModal, EventAIPanelWidget

        modal = AskEventAIModal(
            event_title=str(getattr(event, "title", "") or getattr(event, "native_id", "")),
            event_key=str(getattr(event, "event_key", "")),
        )

        def _on_question(question: str | None) -> None:
            if not question or not question.strip() or self.is_app_shutting_down():
                return
            if callable(is_killed_fn) and is_killed_fn():
                self.notify_user(
                    "AI Kill Switch is active — all AI actions are halted.",
                    title="AI Halted",
                    severity="warning",
                )
                return
            with contextlib.suppress(Exception):
                self.query_one(panel_selector, EventAIPanelWidget).show_investigating(
                    event, "ask_only", question=question.strip()
                )
            trigger_fn = getattr(self.app, "trigger_event_ai_investigation", None)
            if callable(trigger_fn):
                trigger_fn(event, "ask_only", question=question.strip())

        self.run_on_ui(self.app.push_screen, modal, _on_question)

    def request_full_event_ai(self, panel_selector: str, event: Any) -> None:
        """Launch a ``full_investigation`` run for ``event`` and show loading state."""
        if self.is_app_shutting_down() or event is None:
            return
        is_killed_fn = getattr(self.app, "is_ai_killed", None)
        if callable(is_killed_fn) and is_killed_fn():
            self.notify_user(
                "AI Kill Switch is active — all AI actions are halted. Click AI HALTED or press the kill hotkey to resume.",
                title="AI Halted",
                severity="warning",
            )
            return
        from soclens.tui.ai_widgets import EventAIPanelWidget

        with contextlib.suppress(Exception):
            self.query_one(panel_selector, EventAIPanelWidget).show_investigating(
                event, "full_investigation"
            )
        trigger_fn = getattr(self.app, "trigger_event_ai_investigation", None)
        if callable(trigger_fn):
            trigger_fn(event, "full_investigation")

    def request_teach_event_ai(
        self,
        panel_selector: str,
        event: Any,
        *,
        prefill_title: str = "",
        prefill_content: str = "",
    ) -> None:
        """Open ``TeachLearnModal`` prefilled from an event and its latest AI panel entry."""
        _ = panel_selector
        if self.is_app_shutting_down():
            return
        from soclens.agent_audit import AuditLogStore
        from soclens.agent_learning import SOCLearningManager
        from soclens.agent_policy import AIPolicyStore
        from soclens.tui.ai_widgets import (
            AuditLogViewWidget,
            KnowledgeManagerWidget,
            TeachLearnModal,
        )

        lm = getattr(self.app, "learning_manager", None)
        if not isinstance(lm, SOCLearningManager):
            stor = getattr(self.app, "storage", None)
            cache_dir = self.workspace_dir / ".soclens_cache"
            pol = getattr(self.app, "ai_policy_store", None)
            aud = getattr(self.app, "ai_audit_store", None)
            lm = SOCLearningManager(
                storage=stor,
                workspace_dir=self.workspace_dir,
                policy_store=pol if isinstance(pol, AIPolicyStore) else AIPolicyStore(path=cache_dir / "ai_policy.json", storage=stor),
                audit_store=aud if isinstance(aud, AuditLogStore) else AuditLogStore(path=cache_dir / "ai_audit.jsonl", storage=stor),
            )

        ev_title = prefill_title.strip() or str(
            getattr(event, "title", "") or getattr(event, "event_key", "") or "SOC Event Lesson"
        ).strip()
        modal = TeachLearnModal(
            learning_manager=lm,
            prefill_title=ev_title[:80],
            prefill_content=prefill_content,
            modal_title="Teach / Learn from This Event",
        )

        def _after(saved: dict[str, Any] | None) -> None:
            if saved is None or self.is_app_shutting_down():
                return
            with contextlib.suppress(Exception):
                self.app.query_one(KnowledgeManagerWidget).refresh_entries()
            with contextlib.suppress(Exception):
                self.app.query_one(AuditLogViewWidget).refresh_entries()
            self.notify_user(
                f"Saved active learning: {saved.get('title', '')}",
                title="SOC Knowledge",
            )

        self.run_on_ui(self.app.push_screen, modal, _after)
