"""Reusable right-click context menu and destructive-action approval modals."""

from __future__ import annotations

import contextlib
import re
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, OptionList, RichLog, Select, Static, TextArea
from textual.widgets.option_list import Option

from soclens.config import get_workspace_dir
from soclens.splunk_es import (
    NOTABLE_DISPOSITIONS,
    NOTABLE_STATUS_LABELS,
    NOTABLE_STATUS_MAP,
    NOTABLE_URGENCIES,
)
from soclens.tui.clipboard import copy_text_to_clipboard
from soclens.tui.image_render import (
    DecodedImage,
    auto_crop_margins,
    blur_decoded_image,
    blur_image_bytes,
    build_iterm2_overlay_sequence,
    build_kitty_upload_sequence,
    build_sixel_overlay_sequence,
    can_emit_kitty_truecolor,
    clear_kitty_images,
    compute_terminal_cell_grid,
    crop_decoded_image,
    decode_image,
    detect_terminal_graphics_protocol,
    encode_png,
    encode_sixel,
    get_terminal_cell_aspect,
    get_terminal_cell_pixel_size,
    is_tmux_session,
    next_kitty_image_id,
    open_image_in_native_viewer,
    render_image_halfblock,
    render_kitty_placeholder_grid,
    write_terminal_graphics,
)


class ContextMenuModal(ModalScreen[str | None]):
    """Floating right-click context menu anchored near the cursor coordinates."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Close", show=False),
        Binding("q", "cancel", "Close", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    ContextMenuModal {
        background: $background 25%;
        align: left top;
    }
    #ctx-menu-box {
        width: auto;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 0;
    }
    #ctx-menu-title {
        height: 1;
        background: $boost;
        padding: 0 1;
        text-style: bold;
        color: $text;
    }
    #ctx-menu-options {
        width: 1fr;
        height: auto;
        border: none;
        background: $surface;
    }
    """

    def __init__(
        self,
        items: Sequence[tuple[str, str]],
        *,
        title: str = "",
        origin: tuple[int, int] = (2, 2),
    ) -> None:
        super().__init__()
        self._items: list[tuple[str, str]] = list(items)
        self._title = title.strip()
        self._origin = origin

    def compose(self) -> ComposeResult:
        with Vertical(id="ctx-menu-box"):
            if self._title:
                clipped = self._title if len(self._title) <= 44 else self._title[:41] + "..."
                yield Static(clipped, id="ctx-menu-title", markup=False)
            yield OptionList(
                *(Option(label, id=action_id) for action_id, label in self._items),
                id="ctx-menu-options",
                markup=False,
                compact=True,
            )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        box = self.query_one("#ctx-menu-box", Vertical)
        max_label = max((len(label) for _, label in self._items), default=20)
        max_title = len(self._title[:44]) if self._title else 0
        app_w = max(24, self.app.size.width)
        app_h = max(8, self.app.size.height)
        width = min(max(26, max_label + 6, max_title + 4), max(20, app_w - 2))
        height = min(len(self._items) + (3 if self._title else 2), max(5, app_h - 2))
        x = max(0, min(self._origin[0], max(0, app_w - width)))
        y = max(0, min(self._origin[1], max(0, app_h - height)))
        box.styles.width = width
        box.styles.offset = (x, y)
        self.query_one("#ctx-menu-options", OptionList).focus()

    @on(OptionList.OptionSelected, "#ctx-menu-options")
    def handle_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.dismiss(event.option.id)

    def on_click(self, event: events.Click) -> None:
        box = self.query_one("#ctx-menu-box", Vertical)
        if not box.region.contains(event.screen_x, event.screen_y):
            event.stop()
            self.dismiss(None)

    def action_cancel(self) -> None:
        """Close the context menu without running an action."""
        self.dismiss(None)


class ConfirmActionModal(ModalScreen[bool]):
    """Explicit operator approval dialog required before deleting Recorded Future data."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    ConfirmActionModal {
        align: center middle;
        background: $background 60%;
    }
    #confirm-dialog {
        width: 72;
        max-width: 90%;
        height: auto;
        max-height: 80%;
        border: round $error;
        background: $surface;
        padding: 1 2;
    }
    #confirm-title {
        text-style: bold;
        color: $error;
        margin-bottom: 1;
    }
    #confirm-message {
        margin-bottom: 1;
    }
    #confirm-details {
        max-height: 10;
        border: solid $panel-lighten-1;
        padding: 0 1;
        margin-bottom: 1;
    }
    #confirm-warning {
        color: $warning;
        margin-bottom: 1;
    }
    #confirm-buttons {
        height: auto;
        align-horizontal: right;
    }
    #confirm-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        title: str,
        message: str,
        *,
        details: str = "",
        confirm_label: str = "Approve Delete",
        cancel_label: str = "Cancel",
    ) -> None:
        super().__init__()
        self._title = title
        self._message = message
        self._details = details.strip()
        self._confirm_label = confirm_label
        self._cancel_label = cancel_label

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Static(self._title, id="confirm-title", markup=False)
            yield Static(self._message, id="confirm-message", markup=False)
            if self._details:
                yield Static(self._details, id="confirm-details", markup=False)
            yield Static(
                "Approval required: this destructive action modifies Recorded Future data.",
                id="confirm-warning",
                markup=False,
            )
            with Horizontal(id="confirm-buttons"):
                yield Button(
                    self._cancel_label,
                    id="confirm-cancel-btn",
                    variant="default",
                    compact=True,
                )
                yield Button(
                    self._confirm_label,
                    id="confirm-approve-btn",
                    variant="error",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#confirm-cancel-btn", Button).focus()

    @on(Button.Pressed, "#confirm-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#confirm-approve-btn")
    def handle_approve(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        """Dismiss the confirmation prompt safely as cancelled."""
        self.dismiss(False)


_TRIAGE_STATUS_OPTIONS: dict[str, tuple[str, ...]] = {
    "alert_v3": ("New", "Pending", "InProgress", "Resolved", "Dismissed"),
    "playbook": ("New", "InProgress", "Resolved", "Dismissed"),
    "case": ("Open", "InProgress", "Pending", "Closed"),
}

_TRIAGE_PRIORITY_OPTIONS: dict[str, tuple[str, ...]] = {
    "playbook": ("High", "Moderate", "Informational"),
    "case": ("Critical", "High", "Medium", "Low"),
}


class TriageItemModal(ModalScreen[dict[str, str] | None]):
    """Modal dialog for updating status, priority, assignee, and note on alerts/cases."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    TriageItemModal {
        align: center middle;
        background: $background 60%;
    }
    #triage-dialog {
        width: 76;
        max-width: 92%;
        height: auto;
        max-height: 85%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #triage-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #triage-summary {
        margin-bottom: 1;
        color: $text-muted;
    }
    .triage-field-label {
        height: 1;
        margin-top: 0;
        text-style: bold;
    }
    #triage-dialog Select, #triage-dialog Input {
        width: 1fr;
        margin-bottom: 1;
    }
    #triage-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #triage-buttons {
        height: auto;
        align-horizontal: right;
    }
    #triage-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        item_kind: str,
        item_id: str,
        item_title: str,
        current_status: str = "",
        current_priority: str = "",
        current_assignee: str = "",
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._item_kind = item_kind
        self._item_id = item_id
        self._item_title = item_title
        self._current_status = current_status.strip()
        self._current_priority = current_priority.strip()
        self._current_assignee = current_assignee.strip()
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        kind_label = {
            "alert_v3": "Alert v3",
            "playbook": "Playbook Alert",
            "case": "Case",
        }.get(self._item_kind, "Item")

        status_choices = list(_TRIAGE_STATUS_OPTIONS.get(self._item_kind, ("New", "Resolved")))
        if (
            self._current_status
            and self._current_status != "-"
            and self._current_status not in status_choices
        ):
            status_choices.insert(0, self._current_status)
        status_options: list[tuple[str, str]] = [("(Unchanged)", "")] + [
            (val, val) for val in status_choices
        ]

        priority_choices = list(_TRIAGE_PRIORITY_OPTIONS.get(self._item_kind, ()))
        if (
            priority_choices
            and self._current_priority
            and self._current_priority != "-"
            and self._current_priority not in priority_choices
        ):
            priority_choices.insert(0, self._current_priority)
        priority_options: list[tuple[str, str]] = [("(Unchanged)", "")] + [
            (val, val) for val in priority_choices
        ]

        with Vertical(id="triage-dialog"):
            yield Static(
                f"Triage {kind_label}: {self._item_id}",
                id="triage-title",
                markup=False,
            )
            yield Static(
                f"{self._item_title}\n"
                f"Current -> Status: {self._current_status or '-'} | "
                f"Priority: {self._current_priority or '-'} | "
                f"Assignee: {self._current_assignee or 'Unassigned'}",
                id="triage-summary",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: Recorded Future will not be modified.",
                    id="triage-dry-banner",
                    markup=False,
                )

            yield Static("Status", classes="triage-field-label", markup=False)
            yield Select(
                status_options,
                allow_blank=False,
                value="",
                id="triage-status-select",
                compact=True,
            )

            if priority_choices:
                yield Static("Priority", classes="triage-field-label", markup=False)
                yield Select(
                    priority_options,
                    allow_blank=False,
                    value="",
                    id="triage-priority-select",
                    compact=True,
                )

            yield Static("Assignee", classes="triage-field-label", markup=False)
            yield Input(
                value=self._current_assignee,
                placeholder="Assignee username/email (leave blank for unchanged)",
                id="triage-assignee-input",
                compact=True,
            )

            if self._item_kind in ("alert_v3", "playbook"):
                yield Static("Note / Audit Log Entry", classes="triage-field-label", markup=False)
                yield Input(
                    value="",
                    placeholder="Optional triage note or action log entry",
                    id="triage-note-input",
                    compact=True,
                )

            with Horizontal(id="triage-buttons"):
                yield Button("Cancel", id="triage-cancel-btn", variant="default", compact=True)
                yield Button(
                    "Apply Update",
                    id="triage-apply-btn",
                    variant="primary",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#triage-status-select", Select).focus()

    @on(Button.Pressed, "#triage-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#triage-apply-btn")
    def handle_apply(self) -> None:
        status_val = str(self.query_one("#triage-status-select", Select).value or "")
        priority_val = ""
        if self._item_kind in _TRIAGE_PRIORITY_OPTIONS:
            priority_val = str(self.query_one("#triage-priority-select", Select).value or "")
        assignee_val = self.query_one("#triage-assignee-input", Input).value.strip()
        note_val = ""
        if self._item_kind in ("alert_v3", "playbook"):
            note_val = self.query_one("#triage-note-input", Input).value.strip()
        self.dismiss(
            {
                "status": status_val,
                "priority": priority_val,
                "assignee": assignee_val,
                "note": note_val,
            }
        )

    def action_cancel(self) -> None:
        """Dismiss the triage dialog safely."""
        self.dismiss(None)


class CreateCaseModal(ModalScreen[dict[str, str] | None]):
    """Modal dialog for creating a new Recorded Future Case from an alert or workflow."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    CreateCaseModal {
        align: center middle;
        background: $background 60%;
    }
    #case-dialog {
        width: 78;
        max-width: 92%;
        height: auto;
        max-height: 85%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #case-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    .case-field-label {
        height: 1;
        text-style: bold;
    }
    #case-dialog Select, #case-dialog Input {
        width: 1fr;
        margin-bottom: 1;
    }
    #case-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #case-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #case-buttons {
        height: auto;
        align-horizontal: right;
    }
    #case-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        default_title: str = "",
        default_description: str = "",
        default_priority: str = "High",
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._default_title = default_title.strip()
        self._default_description = default_description.strip()
        self._default_priority = (
            default_priority
            if default_priority in ("Low", "Medium", "High", "Critical")
            else "High"
        )
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        with Vertical(id="case-dialog"):
            yield Static("Create Investigation Case", id="case-title", markup=False)
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: no Case will be created in Recorded Future.",
                    id="case-dry-banner",
                    markup=False,
                )
            yield Static("Case Title", classes="case-field-label", markup=False)
            yield Input(
                value=self._default_title,
                placeholder="Required investigation case title",
                id="case-title-input",
                compact=True,
            )
            yield Static("Priority", classes="case-field-label", markup=False)
            yield Select(
                [("Low", "Low"), ("Medium", "Medium"), ("High", "High"), ("Critical", "Critical")],
                allow_blank=False,
                value=self._default_priority,
                id="case-priority-select",
                compact=True,
            )
            yield Static("Status", classes="case-field-label", markup=False)
            yield Select(
                [("Open", "Open"), ("New", "New"), ("InProgress", "InProgress")],
                allow_blank=False,
                value="Open",
                id="case-status-select",
                compact=True,
            )
            yield Static("Description", classes="case-field-label", markup=False)
            yield Input(
                value=self._default_description,
                placeholder="Investigation summary / context",
                id="case-desc-input",
                compact=True,
            )
            yield Static("", id="case-error", markup=False)
            with Horizontal(id="case-buttons"):
                yield Button("Cancel", id="case-cancel-btn", variant="default", compact=True)
                yield Button("Create Case", id="case-create-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#case-title-input", Input).focus()

    @on(Button.Pressed, "#case-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#case-create-btn")
    def handle_create(self) -> None:
        title = self.query_one("#case-title-input", Input).value.strip()
        if not title:
            self.query_one("#case-error", Static).update("Case title is required.")
            self.query_one("#case-title-input", Input).focus()
            return
        priority = str(self.query_one("#case-priority-select", Select).value or "High")
        status = str(self.query_one("#case-status-select", Select).value or "Open")
        desc = self.query_one("#case-desc-input", Input).value.strip()
        self.dismiss(
            {
                "title": title,
                "priority": priority,
                "status": status,
                "description": desc,
            }
        )

    def action_cancel(self) -> None:
        """Dismiss the create-case dialog safely."""
        self.dismiss(None)


class ScreenshotViewerModal(ModalScreen[str | None]):
    """Fullscreen-scaled modal viewer for Playbook Alert PNG screenshots."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Close", show=False),
        Binding("q", "cancel", "Close", show=False),
        Binding("left", "prev_image", "Prev", show=False),
        Binding("p", "prev_image", "Prev", show=False),
        Binding("right", "next_image", "Next", show=False),
        Binding("n", "next_image", "Next", show=False),
        Binding("b", "toggle_blur", "Blur/Reveal", show=False),
        Binding("c", "toggle_crop", "Crop/Full", show=False),
        Binding("plus", "zoom_in", "Zoom +", show=False),
        Binding("equals_sign", "zoom_in", "Zoom +", show=False),
        Binding("minus", "zoom_out", "Zoom -", show=False),
        Binding("0", "reset_zoom", "Reset Zoom", show=False),
        Binding("w", "pan_up", "Pan Up", show=False),
        Binding("up", "pan_up", "Pan Up", show=False),
        Binding("s", "pan_down", "Pan Down", show=False),
        Binding("down", "pan_down", "Pan Down", show=False),
        Binding("a", "pan_left", "Pan Left", show=False),
        Binding("d", "pan_right", "Pan Right", show=False),
        Binding("o", "open_viewer", "Open Viewer", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    ScreenshotViewerModal {
        align: center middle;
        background: $background 70%;
    }
    #shot-viewer-dialog {
        width: 94%;
        height: 92%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #shot-viewer-header {
        height: 1;
        text-style: bold;
        color: $accent;
    }
    #shot-viewer-meta {
        height: auto;
        color: $text-muted;
        margin-bottom: 1;
    }
    #shot-viewer-canvas {
        width: 1fr;
        height: 1fr;
        min-height: 6;
        border: solid $primary-darken-2;
        margin-bottom: 1;
    }
    #shot-viewer-buttons {
        height: auto;
        align-horizontal: right;
    }
    #shot-viewer-buttons Button {
        min-width: 5;
        width: auto;
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        title: str,
        screenshots: Sequence[dict[str, Any]],
        initial_index: int = 0,
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._title = title.strip() or "Playbook Alert"
        self._shots: list[dict[str, Any]] = list(screenshots)
        self._index = max(0, min(initial_index, max(0, len(self._shots) - 1)))
        self._dry_run = dry_run
        self._auto_crop: bool = True
        self._blurred: bool = True
        self._zoom_levels: tuple[float, ...] = (1.0, 1.5, 2.0, 3.0)
        self._zoom_idx: int = 0
        self._pan_x: float = 0.5
        self._pan_y: float = 0.5
        self._protocol: str = "halfblock"
        self._active_kitty_ids: list[int] = []
        self._overlay_token: int = 0
        self._last_render_sig: tuple[Any, ...] | None = None
        self._crop_cache: dict[str, tuple[DecodedImage, tuple[int, int, int, int] | None]] = {}
        self._blur_cache: dict[tuple[str, tuple[int, int, int, int] | None], DecodedImage] = {}
        self._encoded_png_cache: dict[tuple[str, tuple[int, int, int, int] | None, bool], bytes] = {}
        self._sixel_cache: dict[
            tuple[str, tuple[int, int, int, int] | None, bool, int, int], str
        ] = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="shot-viewer-dialog"):
            yield Static("", id="shot-viewer-header", markup=False)
            yield Static("", id="shot-viewer-meta", markup=False)
            yield RichLog(
                id="shot-viewer-canvas",
                highlight=False,
                markup=False,
                wrap=False,
            )
            with Horizontal(id="shot-viewer-buttons"):
                yield Button("Prev", id="shot-prev-btn", compact=True)
                yield Button("Next", id="shot-next-btn", compact=True)
                yield Button("Blur: ON", id="shot-blur-btn", variant="warning", compact=True)
                yield Button("Crop: Auto", id="shot-crop-btn", compact=True)
                yield Button("Zoom -", id="shot-zoom-out-btn", compact=True)
                yield Button("Zoom +", id="shot-zoom-in-btn", compact=True)
                yield Button("Open Viewer", id="shot-open-btn", compact=True)
                yield Button("OS Default: OFF", id="shot-os-default-btn", compact=True)
                save_label = "Save PNG (Dry-Run)" if self._dry_run else "Save PNG"
                yield Button(save_label, id="shot-save-btn", variant="primary", compact=True)
                yield Button("Close", id="shot-close-btn", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self._blurred = bool(getattr(self.app, "blur_images", True))
        self._protocol = detect_terminal_graphics_protocol(
            is_headless=self.app.is_headless,
            app=self.app,
        )
        self.sync_os_viewer_default_button()
        self.call_after_refresh(self._render_current)
        self.query_one("#shot-close-btn", Button).focus()

    def sync_os_viewer_default_button(self) -> None:
        """Synchronize the OS default viewer toggle button and primary Open action styling."""
        is_os = bool(getattr(self.app, "open_images_in_os_viewer", False))
        try:
            default_btn = self.query_one("#shot-os-default-btn", Button)
            default_btn.label = "OS Default: ON" if is_os else "OS Default: OFF"
            default_btn.variant = "success" if is_os else "default"
        except Exception:
            pass
        try:
            open_btn = self.query_one("#shot-open-btn", Button)
            open_btn.variant = (
                "primary" if (is_os or self._protocol == "halfblock") else "default"
            )
        except Exception:
            pass

    def sync_blur_state(self) -> None:
        """Synchronize blur toggle state from the parent application."""
        target = bool(getattr(self.app, "blur_images", True))
        if target != self._blurred:
            self._blurred = target
            self._last_render_sig = None
            if self.is_mounted:
                self._render_current(force=True)

    def on_resize(self) -> None:
        self.call_after_refresh(self._render_current)

    def on_unmount(self) -> None:
        self._overlay_token += 1
        clear_kitty_images(self.app, self._active_kitty_ids)
        if self._protocol in {"sixel", "iterm2"}:
            with contextlib.suppress(Exception):
                for scr in self.app.screen_stack:
                    scr.refresh(repaint=True)

    def _get_cropped_view(
        self, img_id: str, decoded: DecodedImage
    ) -> tuple[DecodedImage, tuple[int, int, int, int] | None]:
        cached = self._crop_cache.get(img_id)
        if cached is None:
            cached = auto_crop_margins(decoded)
            self._crop_cache[img_id] = cached
        return cached

    def _get_blurred_view(
        self,
        img_id: str,
        img: DecodedImage,
        effective_box: tuple[int, int, int, int] | None,
    ) -> DecodedImage:
        cache_key = (img_id, effective_box)
        cached = self._blur_cache.get(cache_key)
        if cached is None:
            cached = blur_decoded_image(img)
            self._blur_cache[cache_key] = cached
        return cached

    def _apply_zoom_and_pan(
        self,
        img: DecodedImage,
        base_box: tuple[int, int, int, int] | None,
    ) -> tuple[DecodedImage, tuple[int, int, int, int] | None]:
        zoom = self._zoom_levels[self._zoom_idx]
        if zoom <= 1.0:
            return img, base_box
        vw = max(16, int(round(img.width / zoom)))
        vh = max(16, int(round(img.height / zoom)))
        max_x0 = max(0, img.width - vw)
        max_y0 = max(0, img.height - vh)
        vx0 = max(0, min(max_x0, int(round(self._pan_x * max_x0))))
        vy0 = max(0, min(max_y0, int(round(self._pan_y * max_y0))))
        vx1 = min(img.width, vx0 + vw)
        vy1 = min(img.height, vy0 + vh)
        origin_x = base_box[0] if base_box is not None else 0
        origin_y = base_box[1] if base_box is not None else 0
        abs_box = (origin_x + vx0, origin_y + vy0, origin_x + vx1, origin_y + vy1)
        return crop_decoded_image(img, (vx0, vy0, vx1, vy1)), abs_box

    def _get_png_for_view(
        self,
        img_id: str,
        render_img: DecodedImage,
        effective_box: tuple[int, int, int, int] | None,
        raw_bytes: bytes | bytearray | None,
        *,
        blurred: bool,
    ) -> bytes:
        if (
            not blurred
            and effective_box is None
            and isinstance(raw_bytes, (bytes, bytearray))
            and bytes(raw_bytes).startswith(b"\x89PNG\r\n\x1a\n")
        ):
            return bytes(raw_bytes)
        cache_key = (img_id, effective_box, blurred)
        cached_png = self._encoded_png_cache.get(cache_key)
        if cached_png is None:
            cached_png = encode_png(render_img)
            self._encoded_png_cache[cache_key] = cached_png
        return cached_png

    def _get_sixel_for_view(
        self,
        img_id: str,
        render_img: DecodedImage,
        effective_box: tuple[int, int, int, int] | None,
        *,
        blurred: bool,
        max_w: int,
        max_h: int,
    ) -> str:
        cache_key = (img_id, effective_box, blurred, max_w, max_h)
        cached_sixel = self._sixel_cache.get(cache_key)
        if cached_sixel is None:
            cached_sixel = encode_sixel(render_img, max_width=max_w, max_height=max_h)
            self._sixel_cache[cache_key] = cached_sixel
        return cached_sixel

    def _update_control_buttons(self, *, has_image: bool, can_save: bool, total: int) -> None:
        self.query_one("#shot-prev-btn", Button).disabled = total <= 1
        self.query_one("#shot-next-btn", Button).disabled = total <= 1

        blur_btn = self.query_one("#shot-blur-btn", Button)
        blur_btn.label = "Blur: ON" if self._blurred else "Blur: OFF"
        blur_btn.variant = "warning" if self._blurred else "default"
        blur_btn.disabled = not has_image

        crop_btn = self.query_one("#shot-crop-btn", Button)
        crop_btn.label = "Crop: Auto" if self._auto_crop else "Crop: Full"
        crop_btn.disabled = not has_image

        zoom_out_btn = self.query_one("#shot-zoom-out-btn", Button)
        zoom_in_btn = self.query_one("#shot-zoom-in-btn", Button)
        zoom_out_btn.disabled = not has_image or self._zoom_idx <= 0
        zoom_in_btn.disabled = not has_image or self._zoom_idx >= len(self._zoom_levels) - 1

        self.query_one("#shot-open-btn", Button).disabled = not can_save
        self.query_one("#shot-save-btn", Button).disabled = not can_save
        self.sync_os_viewer_default_button()

    @staticmethod
    def _protocol_label(proto: str) -> str:
        return {
            "kitty": "Kitty HD",
            "iterm2": "iTerm2 HD",
            "sixel": "Sixel HD",
        }.get(proto, "Halfblock")

    def _write_halfblock_fallback(
        self,
        canvas: RichLog,
        meta_bar: Static,
        render_img: DecodedImage,
        avail_w: int,
        avail_h: int,
        base_meta: list[str],
    ) -> None:
        canvas.clear()
        canvas.write(
            render_image_halfblock(
                render_img,
                max_width=max(24, avail_w - 2),
                max_height=max(6, avail_h),
                sharpen=not self._blurred,
            ),
            width=avail_w,
            scroll_end=False,
        )
        canvas.scroll_home(animate=False)
        parts = list(base_meta)
        parts.append("Mode: Halfblock")
        parts.append("[b] Blur/Reveal | [o] Open Viewer | [c] Crop/Full | [+/-] Zoom")
        meta_bar.update(" | ".join(parts))

    def _emit_overlay(
        self,
        token: int,
        proto: str,
        payload_data: bytes | str,
        cols: int,
        rows: int,
        tmux: bool,
        render_img: DecodedImage,
        avail_w: int,
        avail_h: int,
        base_meta: list[str],
    ) -> None:
        if not self.is_mounted or token != self._overlay_token:
            return
        canvas = self.query_one("#shot-viewer-canvas", RichLog)
        meta_bar = self.query_one("#shot-viewer-meta", Static)
        region = canvas.scrollable_content_region
        row = max(1, region.y + 1)
        col = max(1, region.x + 1)
        try:
            if proto == "iterm2":
                assert isinstance(payload_data, bytes)
                seq = build_iterm2_overlay_sequence(
                    payload_data,
                    row=row,
                    col=col,
                    cols=cols,
                    rows=rows,
                    tmux_passthrough=tmux,
                )
            else:
                assert isinstance(payload_data, str)
                seq = build_sixel_overlay_sequence(
                    payload_data,
                    row=row,
                    col=col,
                    tmux_passthrough=tmux,
                )
        except ValueError:
            seq = ""
        if not seq or not write_terminal_graphics(self.app, seq):
            self._write_halfblock_fallback(
                canvas, meta_bar, render_img, avail_w, avail_h, base_meta
            )

    def _render_current(self, *, force: bool = False) -> None:
        header = self.query_one("#shot-viewer-header", Static)
        meta_bar = self.query_one("#shot-viewer-meta", Static)
        canvas = self.query_one("#shot-viewer-canvas", RichLog)

        total = len(self._shots)
        if total == 0:
            self._overlay_token += 1
            clear_kitty_images(self.app, self._active_kitty_ids)
            self._last_render_sig = None
            header.update(f"Screenshots - {self._title}")
            meta_bar.update("No screenshots attached.")
            self._update_control_buttons(has_image=False, can_save=False, total=0)
            canvas.clear()
            canvas.write(Text("No screenshots available.", style="dim"))
            return

        entry = self._shots[self._index]
        img_id = str(entry.get("image_id") or "")
        raw_meta = entry.get("meta")
        meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}

        decoded = entry.get("decoded")
        raw_bytes = entry.get("raw_bytes")
        err = entry.get("error")
        if decoded is None and isinstance(raw_bytes, (bytes, bytearray)) and not err:
            try:
                decoded = decode_image(bytes(raw_bytes))
                entry["decoded"] = decoded
            except ValueError as exc:
                err = str(exc)

        can_save = bool(img_id) and not bool(err) and (
            decoded is not None or isinstance(raw_bytes, (bytes, bytearray))
        )
        has_image = decoded is not None and not bool(err) and not bool(entry.get("loading"))

        avail_w = canvas.scrollable_content_region.width or max(40, self.app.size.width - 14)
        avail_h = canvas.scrollable_content_region.height or max(10, self.app.size.height - 12)
        render_sig: tuple[Any, ...] = (
            self._index,
            self._auto_crop,
            self._blurred,
            self._zoom_idx,
            round(self._pan_x, 3),
            round(self._pan_y, 3),
            self._protocol,
            avail_w,
            avail_h,
            img_id,
            has_image,
            bool(entry.get("loading")),
            bool(err),
        )
        if not force and render_sig == self._last_render_sig:
            return

        self._overlay_token += 1
        clear_kitty_images(self.app, self._active_kitty_ids)
        header.update(f"Screenshot {self._index + 1} of {total} - {self._title}")
        self._update_control_buttons(has_image=has_image, can_save=can_save, total=total)

        meta_parts = [f"ID: {img_id}"]
        if decoded is not None:
            meta_parts.append(f"{decoded.width}x{decoded.height}")
            meta_parts.append(f"{decoded.raw_size / 1024:.1f} KB")
        elif isinstance(raw_bytes, (bytes, bytearray)):
            meta_parts.append(f"{len(raw_bytes) / 1024:.1f} KB")
        if meta.get("created"):
            from soclens.timezone import format_iso_timestamp

            meta_parts.append(f"Created: {format_iso_timestamp(meta['created'])}")
        if meta.get("tag"):
            meta_parts.append(f"Tag: {meta['tag']}")

        canvas.clear()

        if entry.get("loading"):
            meta_bar.update(" | ".join(meta_parts))
            canvas.write(Text("Downloading screenshot...", style="yellow"), scroll_end=False)
            self._last_render_sig = render_sig
            return
        if err:
            meta_bar.update(" | ".join(meta_parts))
            canvas.write(Text(f"Unable to render screenshot: {err}", style="red"), scroll_end=False)
            self._last_render_sig = render_sig
            return
        if decoded is None:
            meta_bar.update(" | ".join(meta_parts))
            canvas.write(
                Text("Screenshot has not been downloaded yet.", style="dim"),
                scroll_end=False,
            )
            self._last_render_sig = render_sig
            return

        display_img = decoded
        crop_box: tuple[int, int, int, int] | None = None
        if self._auto_crop:
            display_img, crop_box = self._get_cropped_view(img_id, decoded)

        zoom = self._zoom_levels[self._zoom_idx]
        display_img, effective_box = self._apply_zoom_and_pan(display_img, crop_box)
        render_img = (
            self._get_blurred_view(img_id, display_img, effective_box)
            if self._blurred
            else display_img
        )

        if crop_box is not None:
            cw = crop_box[2] - crop_box[0]
            ch = crop_box[3] - crop_box[1]
            meta_parts.append(f"Cropped: {cw}x{ch}")
        elif not self._auto_crop:
            meta_parts.append("Full Page")
        if zoom > 1.0:
            meta_parts.append(f"Zoom: {zoom:g}x")
        if self._blurred:
            meta_parts.append("BLURRED")

        base_meta = list(meta_parts)
        used_proto = "halfblock"

        if self._protocol == "kitty" and can_emit_kitty_truecolor(self.app):
            cols, rows = compute_terminal_cell_grid(
                display_img.width,
                display_img.height,
                max_cols=max(4, min(255, avail_w - 2)),
                max_rows=max(4, min(255, avail_h)),
                cell_aspect=get_terminal_cell_aspect(),
            )
            try:
                png_bytes = self._get_png_for_view(
                    img_id, render_img, effective_box, raw_bytes, blurred=self._blurred
                )
                kid = next_kitty_image_id()
                tmux = is_tmux_session()
                seq = build_kitty_upload_sequence(
                    png_bytes,
                    image_id=kid,
                    cols=cols,
                    rows=rows,
                    tmux_passthrough=tmux,
                )
                if write_terminal_graphics(self.app, seq):
                    self._active_kitty_ids.append(kid)
                    canvas.write(
                        render_kitty_placeholder_grid(image_id=kid, cols=cols, rows=rows),
                        width=avail_w,
                        scroll_end=False,
                    )
                    used_proto = "kitty"
            except ValueError:
                used_proto = "halfblock"
        elif self._protocol in {"iterm2", "sixel"}:
            cols, rows = compute_terminal_cell_grid(
                display_img.width,
                display_img.height,
                max_cols=max(4, min(255, avail_w - 2)),
                max_rows=max(4, min(255, avail_h)),
                cell_aspect=get_terminal_cell_aspect(),
            )
            tmux = is_tmux_session()
            overlay_payload: bytes | str | None = None
            if self._protocol == "iterm2":
                overlay_payload = self._get_png_for_view(
                    img_id, render_img, effective_box, raw_bytes, blurred=self._blurred
                )
            else:
                cell_w, cell_h = get_terminal_cell_pixel_size()
                px_w = max(32, min(720, cols * cell_w))
                px_h = max(32, min(480, rows * cell_h))
                overlay_payload = self._get_sixel_for_view(
                    img_id,
                    render_img,
                    effective_box,
                    blurred=self._blurred,
                    max_w=px_w,
                    max_h=px_h,
                )
            if overlay_payload is not None:
                canvas.write(
                    Text("\n" * max(0, rows - 1), no_wrap=True),
                    width=avail_w,
                    scroll_end=False,
                )
                tok = self._overlay_token
                self.call_after_refresh(
                    self._emit_overlay,
                    tok,
                    self._protocol,
                    overlay_payload,
                    cols,
                    rows,
                    tmux,
                    render_img,
                    avail_w,
                    avail_h,
                    base_meta,
                )
                used_proto = self._protocol

        if used_proto == "halfblock":
            self._write_halfblock_fallback(
                canvas, meta_bar, render_img, avail_w, avail_h, base_meta
            )
        else:
            canvas.scroll_home(animate=False)
            meta_parts.append(f"Mode: {self._protocol_label(used_proto)}")
            meta_parts.append("[b] Blur/Reveal | [o] Open Viewer | [c] Crop/Full | [+/-] Zoom")
            meta_bar.update(" | ".join(meta_parts))

        self._last_render_sig = render_sig

    def _reset_viewport(self) -> None:
        self._zoom_idx = 0
        self._pan_x = 0.5
        self._pan_y = 0.5

    def action_prev_image(self) -> None:
        if len(self._shots) > 1:
            self._index = (self._index - 1) % len(self._shots)
            self._reset_viewport()
            self._render_current()

    def action_next_image(self) -> None:
        if len(self._shots) > 1:
            self._index = (self._index + 1) % len(self._shots)
            self._reset_viewport()
            self._render_current()

    def action_toggle_blur(self) -> None:
        self._blurred = not self._blurred
        set_blur_fn = getattr(self.app, "set_blur_images", None)
        if callable(set_blur_fn):
            set_blur_fn(self._blurred)
        self._last_render_sig = None
        self._render_current(force=True)

    def action_toggle_crop(self) -> None:
        self._auto_crop = not self._auto_crop
        self._reset_viewport()
        self._render_current()

    def action_zoom_in(self) -> None:
        if self._zoom_idx < len(self._zoom_levels) - 1:
            self._zoom_idx += 1
            self._render_current()

    def action_zoom_out(self) -> None:
        if self._zoom_idx > 0:
            self._zoom_idx -= 1
            if self._zoom_idx == 0:
                self._pan_x = 0.5
                self._pan_y = 0.5
            self._render_current()

    def action_reset_zoom(self) -> None:
        self._reset_viewport()
        self._render_current()

    def _pan(self, dx: float, dy: float) -> None:
        if self._zoom_levels[self._zoom_idx] <= 1.0:
            return
        self._pan_x = max(0.0, min(1.0, self._pan_x + dx))
        self._pan_y = max(0.0, min(1.0, self._pan_y + dy))
        self._render_current()

    def action_pan_up(self) -> None:
        self._pan(0.0, -0.15)

    def action_pan_down(self) -> None:
        self._pan(0.0, 0.15)

    def action_pan_left(self) -> None:
        self._pan(-0.15, 0.0)

    def action_pan_right(self) -> None:
        self._pan(0.15, 0.0)

    def action_open_viewer(self, *, force_unblurred: bool = False) -> None:
        if not self._shots:
            return
        entry = self._shots[self._index]
        img_id = str(entry.get("image_id") or "")
        raw_bytes = entry.get("raw_bytes")
        decoded = entry.get("decoded")
        payload: bytes | None = None
        if isinstance(raw_bytes, (bytes, bytearray)) and len(raw_bytes) > 0:
            payload = bytes(raw_bytes)
        elif isinstance(decoded, DecodedImage):
            payload = encode_png(decoded)
        if not payload:
            self.app.notify("No screenshot image bytes available to open.", severity="warning")
            return
        use_blur = self._blurred and not force_unblurred
        target_id = img_id or "screenshot"
        if use_blur:
            try:
                payload = blur_image_bytes(
                    payload,
                    decoded=decoded if isinstance(decoded, DecodedImage) else None,
                )
                target_id = f"{target_id}_blurred"
            except Exception as exc:
                self.app.notify(f"Unable to blur screenshot: {exc}", severity="warning")
                return
        try:
            out_path = open_image_in_native_viewer(payload, image_id=target_id)
            msg = (
                f"Opened blurred {out_path.name} in OS image viewer (press [b] to reveal unblurred)"
                if use_blur
                else f"Opened {out_path.name} in OS image viewer"
            )
            self.app.notify(msg, title="Screenshot Opened")
        except Exception as exc:
            self.app.notify(str(exc), title="Open Viewer", severity="warning")

    @on(Button.Pressed, "#shot-prev-btn")
    def handle_prev(self) -> None:
        self.action_prev_image()

    @on(Button.Pressed, "#shot-next-btn")
    def handle_next(self) -> None:
        self.action_next_image()

    @on(Button.Pressed, "#shot-blur-btn")
    def handle_toggle_blur(self) -> None:
        self.action_toggle_blur()

    @on(Button.Pressed, "#shot-crop-btn")
    def handle_toggle_crop(self) -> None:
        self.action_toggle_crop()

    @on(Button.Pressed, "#shot-zoom-out-btn")
    def handle_zoom_out(self) -> None:
        self.action_zoom_out()

    @on(Button.Pressed, "#shot-zoom-in-btn")
    def handle_zoom_in(self) -> None:
        self.action_zoom_in()

    @on(Button.Pressed, "#shot-open-btn")
    def handle_open_viewer(self) -> None:
        self.action_open_viewer()

    @on(Button.Pressed, "#shot-os-default-btn")
    def handle_toggle_os_default(self) -> None:
        toggle_fn = getattr(self.app, "toggle_image_viewer_mode", None)
        if callable(toggle_fn):
            toggle_fn()
        self.sync_os_viewer_default_button()

    @on(Button.Pressed, "#shot-save-btn")
    def handle_save(self) -> None:
        if not self._shots:
            return
        img_id = str(self._shots[self._index].get("image_id") or "")
        if img_id:
            self.dismiss(f"save:{img_id}")

    @on(Button.Pressed, "#shot-close-btn")
    def handle_close(self) -> None:
        self.dismiss(None)

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        event.stop()
        is_os = bool(getattr(self.app, "open_images_in_os_viewer", False))
        items: list[tuple[str, str]] = [
            (
                "open_viewer",
                "Open Blurred in OS Image Viewer" if self._blurred else "Open in OS Image Viewer",
            ),
        ]
        if self._blurred:
            items.append(("open_viewer_unblurred", "Open Unblurred in OS Image Viewer"))
        items.extend(
            [
                ("toggle_blur", "Unblur Image ([b])" if self._blurred else "Blur Image ([b])"),
                ("save_png", "Save Original PNG to Workspace"),
                (
                    "toggle_crop",
                    "Crop: Switch to Full Page" if self._auto_crop else "Crop: Switch to Auto",
                ),
            ]
        )
        if self._zoom_idx > 0:
            items.append(("reset_zoom", "Reset Zoom (1x)"))
        items.append(
            (
                "toggle_os_default",
                (
                    "Default Image Viewer: OS Viewer [ON] -> Switch to TUI"
                    if is_os
                    else "Default Image Viewer: TUI Modal -> Set OS Viewer Default"
                ),
            )
        )
        items.append(("close", "Close Viewer"))

        def _on_select(action_id: str | None) -> None:
            if action_id == "open_viewer":
                self.action_open_viewer()
            elif action_id == "open_viewer_unblurred":
                self.action_open_viewer(force_unblurred=True)
            elif action_id == "toggle_blur":
                self.action_toggle_blur()
            elif action_id == "save_png":
                self.handle_save()
            elif action_id == "toggle_crop":
                self.action_toggle_crop()
            elif action_id == "reset_zoom":
                self.action_reset_zoom()
            elif action_id == "toggle_os_default":
                self.handle_toggle_os_default()
            elif action_id == "close":
                self.action_cancel()

        self.app.push_screen(
            ContextMenuModal(
                items,
                title=self._title[:40] or "Screenshot Viewer",
                origin=(event.screen_x, event.screen_y),
            ),
            _on_select,
        )

    def action_cancel(self) -> None:
        """Close the screenshot viewer modal."""
        self.dismiss(None)


_S1_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class S1ThreatTriageModal(ModalScreen[dict[str, str] | None]):
    """Modal dialog for triaging a SentinelOne threat (verdict, status, optional note)."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    S1ThreatTriageModal {
        align: center middle;
        background: $background 60%;
    }
    #s1-triage-dialog {
        width: 76;
        max-width: 92%;
        height: auto;
        max-height: 85%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #s1-triage-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #s1-triage-summary {
        margin-bottom: 1;
        color: $text-muted;
    }
    .s1-modal-label {
        height: 1;
        text-style: bold;
    }
    #s1-triage-dialog Select, #s1-triage-dialog Input {
        width: 1fr;
        margin-bottom: 1;
    }
    #s1-triage-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #s1-triage-buttons {
        height: auto;
        align-horizontal: right;
    }
    #s1-triage-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        threat_id: str,
        threat_name: str = "",
        current_verdict: str = "",
        current_status: str = "",
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._threat_id = threat_id
        self._threat_name = threat_name.strip() or threat_id
        self._current_verdict = current_verdict.strip().lower()
        self._current_status = current_status.strip().lower()
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        verdict_options: list[tuple[str, str]] = [
            ("(Unchanged)", ""),
            ("Undefined", "undefined"),
            ("True Positive", "true_positive"),
            ("False Positive", "false_positive"),
            ("Suspicious", "suspicious"),
        ]
        status_options: list[tuple[str, str]] = [
            ("(Unchanged)", ""),
            ("Unresolved", "unresolved"),
            ("In Progress", "in_progress"),
            ("Resolved", "resolved"),
        ]
        init_verdict = (
            self._current_verdict
            if self._current_verdict in {"undefined", "true_positive", "false_positive", "suspicious"}
            else ""
        )
        init_status = (
            self._current_status
            if self._current_status in {"unresolved", "in_progress", "resolved"}
            else ""
        )

        with Vertical(id="s1-triage-dialog"):
            yield Static(
                f"SentinelOne Threat Triage: {self._threat_id}",
                id="s1-triage-title",
                markup=False,
            )
            yield Static(
                f"{self._threat_name}\n"
                f"Current -> Verdict: {self._current_verdict or '-'} | "
                f"Incident Status: {self._current_status or '-'}",
                id="s1-triage-summary",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: SentinelOne will not be modified.",
                    id="s1-triage-dry-banner",
                    markup=False,
                )
            yield Static("Analyst Verdict", classes="s1-modal-label", markup=False)
            yield Select(
                verdict_options,
                allow_blank=False,
                value=init_verdict,
                id="s1-triage-verdict-select",
                compact=True,
            )
            yield Static("Incident Status", classes="s1-modal-label", markup=False)
            yield Select(
                status_options,
                allow_blank=False,
                value=init_status,
                id="s1-triage-status-select",
                compact=True,
            )
            yield Static("Analyst Note (Optional)", classes="s1-modal-label", markup=False)
            yield Input(
                value="",
                placeholder="Optional note to attach to this threat",
                id="s1-triage-note-input",
                compact=True,
            )
            with Horizontal(id="s1-triage-buttons"):
                yield Button("Cancel", id="s1-triage-cancel-btn", variant="default", compact=True)
                yield Button(
                    "Apply Triage",
                    id="s1-triage-apply-btn",
                    variant="primary",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#s1-triage-verdict-select", Select).focus()

    @on(Button.Pressed, "#s1-triage-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#s1-triage-apply-btn")
    def handle_apply(self) -> None:
        verdict = str(self.query_one("#s1-triage-verdict-select", Select).value or "")
        status = str(self.query_one("#s1-triage-status-select", Select).value or "")
        note = self.query_one("#s1-triage-note-input", Input).value.strip()
        self.dismiss(
            {
                "analyst_verdict": verdict,
                "incident_status": status,
                "note": note,
            }
        )

    def action_cancel(self) -> None:
        """Dismiss the SentinelOne threat triage dialog safely."""
        self.dismiss(None)


class S1CreateExclusionModal(ModalScreen[dict[str, str] | None]):
    """Modal dialog for creating a SentinelOne exclusion."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    S1CreateExclusionModal {
        align: center middle;
        background: $background 60%;
    }
    #s1-excl-dialog {
        width: 78;
        max-width: 92%;
        height: auto;
        max-height: 88%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #s1-excl-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    .s1-excl-label {
        height: 1;
        text-style: bold;
    }
    #s1-excl-dialog Select, #s1-excl-dialog Input {
        width: 1fr;
        margin-bottom: 1;
    }
    #s1-excl-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #s1-excl-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #s1-excl-buttons {
        height: auto;
        align-horizontal: right;
    }
    #s1-excl-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(self, *, dry_run: bool = False) -> None:
        super().__init__()
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        with Vertical(id="s1-excl-dialog"):
            yield Static("Create SentinelOne Exclusion", id="s1-excl-title", markup=False)
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: no exclusion will be created in SentinelOne.",
                    id="s1-excl-dry-banner",
                    markup=False,
                )
            yield Static("Exclusion Type", classes="s1-excl-label", markup=False)
            yield Select(
                [
                    ("Path", "path"),
                    ("White Hash (SHA-1)", "white_hash"),
                    ("Certificate", "certificate"),
                    ("Browser", "browser"),
                    ("File Type", "file_type"),
                ],
                allow_blank=False,
                value="path",
                id="s1-excl-type-select",
                compact=True,
            )
            yield Static("OS Type", classes="s1-excl-label", markup=False)
            yield Select(
                [("Windows", "windows"), ("macOS", "macos"), ("Linux", "linux")],
                allow_blank=False,
                value="windows",
                id="s1-excl-os-select",
                compact=True,
            )
            yield Static("Value", classes="s1-excl-label", markup=False)
            yield Input(
                value="",
                placeholder="Path, SHA-1 hash, signer, browser, or file extension",
                id="s1-excl-value-input",
                compact=True,
            )
            yield Static("Mode", classes="s1-excl-label", markup=False)
            yield Select(
                [
                    ("Suppress Alerts", "suppress"),
                    ("Suppress Dynamic Only", "suppress_dynamic_only"),
                    ("Interoperability (Disable In-Process)", "disable_in_process_monitor"),
                    ("Interoperability Extended", "disable_in_process_monitor_deep"),
                    ("Performance Focus", "disable_all_monitors"),
                    ("Performance Focus Extended", "disable_all_monitors_deep"),
                ],
                allow_blank=False,
                value="suppress",
                id="s1-excl-mode-select",
                compact=True,
            )
            yield Static("Description", classes="s1-excl-label", markup=False)
            yield Input(
                value="",
                placeholder="Reason / ticket reference for this exclusion",
                id="s1-excl-desc-input",
                compact=True,
            )
            yield Static("", id="s1-excl-error", markup=False)
            with Horizontal(id="s1-excl-buttons"):
                yield Button("Cancel", id="s1-excl-cancel-btn", variant="default", compact=True)
                yield Button(
                    "Create Exclusion",
                    id="s1-excl-create-btn",
                    variant="primary",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#s1-excl-value-input", Input).focus()

    @on(Button.Pressed, "#s1-excl-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#s1-excl-create-btn")
    def handle_create(self) -> None:
        value = self.query_one("#s1-excl-value-input", Input).value.strip()
        if not value:
            self.query_one("#s1-excl-error", Static).update("Exclusion value is required.")
            self.query_one("#s1-excl-value-input", Input).focus()
            return
        excl_type = str(self.query_one("#s1-excl-type-select", Select).value or "path")
        os_type = str(self.query_one("#s1-excl-os-select", Select).value or "windows")
        mode = str(self.query_one("#s1-excl-mode-select", Select).value or "suppress")
        desc = self.query_one("#s1-excl-desc-input", Input).value.strip()
        self.dismiss(
            {
                "type": excl_type,
                "os_type": os_type,
                "value": value,
                "mode": mode,
                "description": desc,
            }
        )

    def action_cancel(self) -> None:
        """Dismiss the create-exclusion dialog safely."""
        self.dismiss(None)


class S1AddBlocklistModal(ModalScreen[dict[str, str] | None]):
    """Modal dialog for adding a SHA-1 hash IOC to the SentinelOne blocklist."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    S1AddBlocklistModal {
        align: center middle;
        background: $background 60%;
    }
    #s1-block-dialog {
        width: 76;
        max-width: 92%;
        height: auto;
        max-height: 85%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #s1-block-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    .s1-block-label {
        height: 1;
        text-style: bold;
    }
    #s1-block-dialog Select, #s1-block-dialog Input {
        width: 1fr;
        margin-bottom: 1;
    }
    #s1-block-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #s1-block-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #s1-block-buttons {
        height: auto;
        align-horizontal: right;
    }
    #s1-block-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(self, *, dry_run: bool = False) -> None:
        super().__init__()
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        with Vertical(id="s1-block-dialog"):
            yield Static("Add SHA-1 Hash to SentinelOne Blocklist", id="s1-block-title", markup=False)
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: no hash will be added to SentinelOne blocklist.",
                    id="s1-block-dry-banner",
                    markup=False,
                )
            yield Static("SHA-1 Hash (40 hex chars)", classes="s1-block-label", markup=False)
            yield Input(
                value="",
                placeholder="e.g. da39a3ee5e6b4b0d3255bfef95601890afd80709",
                id="s1-block-hash-input",
                compact=True,
            )
            yield Static("OS Type", classes="s1-block-label", markup=False)
            yield Select(
                [("Windows", "windows"), ("macOS", "macos"), ("Linux", "linux")],
                allow_blank=False,
                value="windows",
                id="s1-block-os-select",
                compact=True,
            )
            yield Static("Description", classes="s1-block-label", markup=False)
            yield Input(
                value="",
                placeholder="Reason / IOC source / ticket reference",
                id="s1-block-desc-input",
                compact=True,
            )
            yield Static("", id="s1-block-error", markup=False)
            with Horizontal(id="s1-block-buttons"):
                yield Button("Cancel", id="s1-block-cancel-btn", variant="default", compact=True)
                yield Button(
                    "Add to Blocklist",
                    id="s1-block-add-btn",
                    variant="primary",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#s1-block-hash-input", Input).focus()

    @on(Button.Pressed, "#s1-block-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#s1-block-add-btn")
    def handle_add(self) -> None:
        sha1 = self.query_one("#s1-block-hash-input", Input).value.strip().lower()
        if not _S1_SHA1_RE.match(sha1):
            self.query_one("#s1-block-error", Static).update(
                "A valid 40-character hexadecimal SHA-1 hash is required."
            )
            self.query_one("#s1-block-hash-input", Input).focus()
            return
        os_type = str(self.query_one("#s1-block-os-select", Select).value or "windows")
        desc = self.query_one("#s1-block-desc-input", Input).value.strip()
        self.dismiss(
            {
                "value": sha1,
                "os_type": os_type,
                "description": desc,
            }
        )

    def action_cancel(self) -> None:
        """Dismiss the add-blocklist dialog safely."""
        self.dismiss(None)


class TimezoneModal(ModalScreen[str | None]):
    """Modal dialog for switching the active display timezone across the TUI."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    TimezoneModal {
        align: center middle;
        background: $background 60%;
    }
    #tz-dialog {
        width: 72;
        max-width: 92%;
        height: auto;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #tz-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #tz-preview {
        height: auto;
        color: $text-muted;
        margin-bottom: 1;
    }
    .tz-field-label {
        height: 1;
        margin-top: 1;
        text-style: bold;
    }
    #tz-error {
        height: auto;
        color: $error;
        margin-top: 1;
    }
    #tz-buttons {
        height: auto;
        margin-top: 1;
        align-horizontal: right;
    }
    #tz-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(self, *, current_tz: str = "UTC") -> None:
        super().__init__()
        self._current_tz = current_tz
        self._last_preset: str = "UTC"
        self._syncing_select = False

    def compose(self) -> ComposeResult:
        from soclens.timezone import COMMON_TIMEZONES, resolve_timezone

        canonical, _ = resolve_timezone(self._current_tz)
        preset_values = {val for _lbl, val in COMMON_TIMEZONES}
        initial_preset = canonical if canonical in preset_values else "UTC"
        self._last_preset = initial_preset
        custom_default = "" if canonical in preset_values else canonical

        with Vertical(id="tz-dialog"):
            yield Static("Display Timezone Settings", id="tz-title", markup=False)
            yield Static("", id="tz-preview", markup=False)
            yield Static("Preset Timezone:", classes="tz-field-label", markup=False)
            yield Select(
                list(COMMON_TIMEZONES),
                allow_blank=False,
                value=initial_preset,
                id="tz-preset-select",
            )
            yield Static(
                "Custom IANA Name or UTC Offset (optional, e.g. Europe/Paris or UTC+02:00):",
                classes="tz-field-label",
                markup=False,
            )
            yield Input(
                value=custom_default,
                placeholder="Leave blank to use preset above (e.g. America/Denver, UTC-05:00)",
                id="tz-custom-input",
            )
            yield Static("", id="tz-error", markup=False)
            with Horizontal(id="tz-buttons"):
                yield Button("Use UTC", id="tz-utc-btn", compact=True)
                yield Button("Use Local", id="tz-local-btn", compact=True)
                yield Button("Cancel", id="tz-cancel-btn", compact=True)
                yield Button("Apply", id="tz-apply-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self._update_preview(self._current_tz)

    def _effective_candidate(self) -> str:
        custom = self.query_one("#tz-custom-input", Input).value.strip()
        if custom:
            return custom
        return str(self.query_one("#tz-preset-select", Select).value or "UTC")

    def _update_preview(self, candidate: str) -> None:
        from datetime import UTC, datetime

        from soclens.config import ConfigurationError
        from soclens.timezone import (
            format_iso_timestamp,
            format_timezone_label,
            resolve_timezone,
        )

        err_box = self.query_one("#tz-error", Static)
        preview = self.query_one("#tz-preview", Static)
        try:
            canonical, _tz_obj = resolve_timezone(candidate)
            badge = format_timezone_label(canonical)
            sample = format_iso_timestamp(
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                tz_name=canonical,
                include_seconds=True,
            )
            preview.update(f"Active Preview: {canonical} ({badge}) -> {sample}")
            err_box.update("")
        except ConfigurationError as exc:
            preview.update(f"Active Preview: invalid specification ({candidate})")
            err_box.update(str(exc))

    @on(Select.Changed, "#tz-preset-select")
    def handle_preset_changed(self, event: Select.Changed) -> None:
        if self._syncing_select:
            return
        val = str(event.value or "UTC")
        if val == self._last_preset:
            return
        self._last_preset = val
        custom_in = self.query_one("#tz-custom-input", Input)
        if custom_in.value.strip():
            custom_in.value = ""
        self._update_preview(val)

    @on(Input.Changed, "#tz-custom-input")
    def handle_custom_changed(self) -> None:
        self._update_preview(self._effective_candidate())

    @on(Input.Submitted, "#tz-custom-input")
    def handle_custom_submitted(self) -> None:
        self.handle_apply()

    @on(Button.Pressed, "#tz-utc-btn")
    def handle_use_utc(self) -> None:
        self.dismiss("UTC")

    @on(Button.Pressed, "#tz-local-btn")
    def handle_use_local(self) -> None:
        self.dismiss("local")

    @on(Button.Pressed, "#tz-apply-btn")
    def handle_apply(self) -> None:
        from soclens.config import ConfigurationError
        from soclens.timezone import resolve_timezone

        candidate = self._effective_candidate()
        try:
            canonical, _ = resolve_timezone(candidate)
        except ConfigurationError as exc:
            self.query_one("#tz-error", Static).update(str(exc))
            return
        self.dismiss(canonical)

    @on(Button.Pressed, "#tz-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        """Dismiss the timezone modal without changing the active timezone."""
        self.dismiss(None)


class SplunkNotableTriageModal(ModalScreen[dict[str, Any] | None]):
    """Modal dialog for updating status, urgency, owner, disposition, and comment on a Splunk ES notable."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    SplunkNotableTriageModal {
        align: center middle;
        background: $background 60%;
    }
    #es-triage-dialog {
        width: 78;
        max-width: 92%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #es-triage-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #es-triage-summary {
        margin-bottom: 1;
        color: $text-muted;
    }
    .es-triage-label {
        height: 1;
        text-style: bold;
    }
    #es-triage-dialog Select, #es-triage-dialog Input {
        width: 1fr;
        margin-bottom: 1;
    }
    #es-triage-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #es-triage-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #es-triage-buttons {
        height: auto;
        align-horizontal: right;
    }
    #es-triage-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        event_id: str,
        rule_name: str = "",
        current_status: str = "",
        current_urgency: str = "",
        current_owner: str = "",
        current_disposition: str = "",
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._event_id = event_id.strip()
        self._rule_name = rule_name.strip() or self._event_id
        self._current_status = current_status.strip()
        self._current_urgency = current_urgency.strip()
        self._current_owner = current_owner.strip()
        self._current_disposition = current_disposition.strip()
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        status_options: list[tuple[str, str]] = [("(Unchanged)", "")] + [
            (f"{NOTABLE_STATUS_LABELS[code]} ({key})", key)
            for key, code in NOTABLE_STATUS_MAP.items()
        ]
        urgency_options: list[tuple[str, str]] = [("(Unchanged)", "")] + [
            (u.title(), u) for u in NOTABLE_URGENCIES
        ]
        disposition_options: list[tuple[str, str]] = [("(Unchanged)", "")] + list(
            NOTABLE_DISPOSITIONS
        )
        initial_owner = "" if self._current_owner.lower() == "unassigned" else self._current_owner

        with Vertical(id="es-triage-dialog"):
            yield Static(
                f"Triage Splunk ES Notable: {self._event_id}",
                id="es-triage-title",
                markup=False,
            )
            yield Static(
                f"{self._rule_name}\n"
                f"Current -> Status: {self._current_status or '-'} | "
                f"Urgency: {self._current_urgency or '-'} | "
                f"Owner: {self._current_owner or 'unassigned'} | "
                f"Disposition: {self._current_disposition or '-'}",
                id="es-triage-summary",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: Splunk ES notable will not be modified.",
                    id="es-triage-dry-banner",
                    markup=False,
                )

            yield Static("Status", classes="es-triage-label", markup=False)
            yield Select(
                status_options,
                allow_blank=False,
                value="",
                id="es-triage-status-select",
                compact=True,
            )

            yield Static("Urgency", classes="es-triage-label", markup=False)
            yield Select(
                urgency_options,
                allow_blank=False,
                value="",
                id="es-triage-urgency-select",
                compact=True,
            )

            yield Static("Owner", classes="es-triage-label", markup=False)
            yield Input(
                value=initial_owner,
                placeholder="Splunk username (leave blank for unchanged)",
                id="es-triage-owner-input",
                compact=True,
            )

            yield Static("Disposition", classes="es-triage-label", markup=False)
            yield Select(
                disposition_options,
                allow_blank=False,
                value="",
                id="es-triage-disposition-select",
                compact=True,
            )

            yield Static("Comment", classes="es-triage-label", markup=False)
            yield Input(
                value="",
                placeholder="Optional triage audit comment",
                id="es-triage-comment-input",
                compact=True,
            )

            yield Static("", id="es-triage-error", markup=False)

            with Horizontal(id="es-triage-buttons"):
                yield Button("Cancel", id="es-triage-cancel-btn", variant="default", compact=True)
                yield Button(
                    "Apply Update",
                    id="es-triage-apply-btn",
                    variant="primary",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#es-triage-status-select", Select).focus()

    @on(Button.Pressed, "#es-triage-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#es-triage-apply-btn")
    def handle_apply(self) -> None:
        status_val = str(self.query_one("#es-triage-status-select", Select).value or "").strip()
        urgency_val = str(self.query_one("#es-triage-urgency-select", Select).value or "").strip()
        owner_val = self.query_one("#es-triage-owner-input", Input).value.strip()
        disposition_val = str(
            self.query_one("#es-triage-disposition-select", Select).value or ""
        ).strip()
        comment_val = self.query_one("#es-triage-comment-input", Input).value.strip()

        orig_owner = "" if self._current_owner.lower() == "unassigned" else self._current_owner
        owner_changed = bool(owner_val and owner_val != orig_owner)

        if not (status_val or urgency_val or owner_changed or disposition_val or comment_val):
            self.query_one("#es-triage-error", Static).update(
                "Select at least one field to update before applying."
            )
            return

        self.dismiss(
            {
                "status": status_val or None,
                "urgency": urgency_val or None,
                "owner": owner_val if owner_changed else None,
                "disposition": disposition_val or None,
                "comment": comment_val or None,
            }
        )

    def action_cancel(self) -> None:
        """Dismiss the Splunk ES notable triage dialog safely."""
        self.dismiss(None)


_COPY_FILENAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")


class CopyTextModal(ModalScreen[None]):
    """Read-only, mouse/keyboard-selectable text modal with Copy, Wrap, and Save controls."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Close", show=False),
        Binding("q", "cancel", "Close", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    CopyTextModal {
        align: center middle;
        background: $background 65%;
    }
    #copy-modal-dialog {
        width: 92%;
        height: 88%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #copy-modal-title {
        height: 1;
        text-style: bold;
        color: $accent;
    }
    #copy-modal-meta {
        height: 1;
        color: $text-muted;
        margin-bottom: 1;
    }
    #copy-modal-textarea {
        width: 1fr;
        height: 1fr;
        min-height: 6;
        border: solid $primary-darken-2;
        margin-bottom: 1;
    }
    #copy-modal-buttons {
        height: auto;
        align-horizontal: right;
    }
    #copy-modal-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        text: str,
        *,
        title: str = "Copyable Text",
        language: str | None = None,
        workspace_dir: Path | str | None = None,
    ) -> None:
        super().__init__()
        self._text = text
        self._title = title.strip() or "Copyable Text"
        self._language = language
        self._workspace_dir = workspace_dir

    def _meta_summary(self) -> str:
        line_count = len(self._text.splitlines()) if self._text else 0
        char_count = len(self._text)
        return (
            f"{char_count:,} chars | {line_count:,} line(s) | "
            "Drag or Shift+Arrows to select, Ctrl+C / Copy All to copy"
        )

    def compose(self) -> ComposeResult:
        with Vertical(id="copy-modal-dialog"):
            yield Static(self._title, id="copy-modal-title", markup=False)
            yield Static(self._meta_summary(), id="copy-modal-meta", markup=False)
            yield TextArea(
                self._text,
                id="copy-modal-textarea",
                read_only=True,
                soft_wrap=True,
                show_line_numbers=True,
            )
            with Horizontal(id="copy-modal-buttons"):
                yield Button(
                    "Copy All",
                    id="copy-modal-copy-btn",
                    variant="primary",
                    compact=True,
                )
                yield Button("Toggle Wrap", id="copy-modal-wrap-btn", compact=True)
                yield Button("Save to File", id="copy-modal-save-btn", compact=True)
                yield Button("Close", id="copy-modal-close-btn", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        ta = self.query_one("#copy-modal-textarea", TextArea)
        if self._language:
            try:
                if self._language in ta.available_languages:
                    ta.language = self._language
            except Exception:
                pass
        ta.focus()

    @on(Button.Pressed, "#copy-modal-copy-btn")
    def handle_copy_all(self) -> None:
        result = copy_text_to_clipboard(self._text, app=self.app)
        if result.success:
            msg = f"Copied {result.char_count:,} char(s) via {result.method}."
            self.app.notify(msg, title="Copied to Clipboard")
        else:
            err = result.error or "Clipboard unavailable."
            self.app.notify(err, title="Clipboard Copy Failed", severity="warning")

    @on(Button.Pressed, "#copy-modal-wrap-btn")
    def handle_toggle_wrap(self) -> None:
        ta = self.query_one("#copy-modal-textarea", TextArea)
        ta.soft_wrap = not ta.soft_wrap
        state = "ON" if ta.soft_wrap else "OFF"
        self.query_one("#copy-modal-wrap-btn", Button).label = f"Wrap: {state}"

    @on(Button.Pressed, "#copy-modal-save-btn")
    def handle_save_file(self) -> None:
        try:
            ws = get_workspace_dir(
                self._workspace_dir
                if self._workspace_dir is not None
                else getattr(self.app, "workspace_dir", None)
            )
            exports_dir = ws / "exports"
            exports_dir.mkdir(parents=True, exist_ok=True)
            slug = _COPY_FILENAME_RE.sub("_", self._title.lower()).strip("._")[:48] or "export"
            ext_map = {
                "yaml": ".yaml",
                "json": ".json",
                "markdown": ".md",
                "spl": ".spl",
                "conf": ".conf",
            }
            ext = ext_map.get((self._language or "").lower(), ".txt")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = exports_dir / f"{slug}_{stamp}{ext}"
            dest.write_text(self._text, encoding="utf-8")
            self.app.notify(f"Saved to {dest}", title="Saved Text")
        except Exception as exc:
            self.app.notify(f"Save failed: {exc}", title="Save Failed", severity="error")

    @on(Button.Pressed, "#copy-modal-close-btn")
    def handle_close(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        """Close the copyable text modal."""
        self.dismiss(None)


class SaveFilterPresetModal(ModalScreen[str | None]):
    """Modal dialog for naming and saving a reusable filter preset view."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    SaveFilterPresetModal {
        align: center middle;
        background: $background 65%;
    }
    #preset-dialog {
        width: 72;
        max-width: 92%;
        height: auto;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #preset-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #preset-summary {
        height: auto;
        color: $text-muted;
        border: solid $primary-darken-2;
        padding: 0 1;
        margin-bottom: 1;
    }
    .preset-field-label {
        height: 1;
        text-style: bold;
    }
    #preset-name-input {
        width: 1fr;
        margin-bottom: 1;
    }
    #preset-error {
        height: auto;
        color: $error;
        margin-bottom: 1;
    }
    #preset-buttons {
        height: auto;
        align-horizontal: right;
    }
    #preset-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(self, *, summary: str = "", default_name: str = "") -> None:
        super().__init__()
        self._summary = summary.strip() or "Current active filter settings"
        self._default_name = default_name.strip()

    def compose(self) -> ComposeResult:
        with Vertical(id="preset-dialog"):
            yield Static("Save Filter View Preset", id="preset-title", markup=False)
            yield Static(self._summary, id="preset-summary", markup=False)
            yield Static("View Name", classes="preset-field-label", markup=False)
            yield Input(
                value=self._default_name,
                placeholder="e.g. High Crit Unassigned (7d) or Stale Cleanup",
                id="preset-name-input",
                compact=True,
            )
            yield Static("", id="preset-error", markup=False)
            with Horizontal(id="preset-buttons"):
                yield Button("Cancel", id="preset-cancel-btn", variant="default", compact=True)
                yield Button(
                    "Save Preset",
                    id="preset-save-btn",
                    variant="primary",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#preset-name-input", Input).focus()

    @on(Input.Submitted, "#preset-name-input")
    def handle_submit(self) -> None:
        self.handle_save()

    @on(Button.Pressed, "#preset-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#preset-save-btn")
    def handle_save(self) -> None:
        name = self.query_one("#preset-name-input", Input).value.strip()
        if not name:
            self.query_one("#preset-error", Static).update("Please enter a name for this preset.")
            self.query_one("#preset-name-input", Input).focus()
            return
        self.dismiss(name)

    def action_cancel(self) -> None:
        """Dismiss the save-preset dialog without saving."""
        self.dismiss(None)


class OSINTSourcesModal(ModalScreen[dict[str, Any] | None]):
    """Interactive selector for toggling passive free OSINT sources & opening Settings."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Close", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    OSINTSourcesModal {
        align: center middle;
        background: $background 65%;
    }
    #osint-modal-dialog {
        width: 96;
        max-width: 94%;
        height: auto;
        max-height: 88%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #osint-modal-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #osint-modal-intro {
        color: $text-muted;
        height: auto;
        margin-bottom: 1;
    }
    #osint-modal-list {
        height: 1fr;
        min-height: 10;
        max-height: 22;
        border: solid $panel-lighten-1;
        padding: 0 1;
        margin-bottom: 1;
    }
    #osint-modal-list Checkbox {
        width: 1fr;
        margin: 0;
    }
    #osint-modal-buttons {
        height: auto;
        align-horizontal: right;
    }
    #osint-modal-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        sources_info: Sequence[dict[str, Any]],
        enabled_keys: set[str],
    ) -> None:
        super().__init__()
        self._sources_info = list(sources_info)
        self._enabled_keys = set(enabled_keys)

    def compose(self) -> ComposeResult:
        ready_cnt = sum(1 for s in self._sources_info if s.get("configured"))
        with Vertical(id="osint-modal-dialog"):
            yield Static(
                f"Free Passive OSINT Sources ({ready_cnt}/{len(self._sources_info)} Ready)",
                id="osint-modal-title",
                markup=False,
            )
            yield Static(
                "All sources are 100% passive (zero direct connections to the target). "
                "Toggle which free feeds run alongside Recorded Future, or open Settings to add optional free API keys.",
                id="osint-modal-intro",
                markup=False,
            )
            with VerticalScroll(id="osint-modal-list"):
                for info in self._sources_info:
                    key = str(info["key"])
                    tier_tag = {
                        "free_no_key": "FREE / No Key",
                        "free_optional_key": "FREE / Key Opt",
                        "free_api_key": "FREE Key",
                    }.get(str(info.get("tier") or ""), "FREE")
                    state_tag = {
                        "key_configured": "Ready (Key Set)",
                        "ready": "Ready",
                        "needs_free_key": "Add Free Key in Settings",
                    }.get(str(info.get("state") or ""), "Ready")
                    label = f"{info['title']}  [{tier_tag} | {state_tag}]"
                    yield Checkbox(
                        label,
                        value=key in self._enabled_keys,
                        id=f"osint-src-{key.replace('_', '-')}",
                        compact=True,
                    )
            with Horizontal(id="osint-modal-buttons"):
                yield Button("Enable All", id="osint-modal-all-btn", compact=True)
                yield Button("No-Key Only", id="osint-modal-nokey-btn", compact=True)
                yield Button("Free API Keys (Settings)", id="osint-modal-settings-btn", compact=True)
                yield Button("Cancel", id="osint-modal-cancel-btn", compact=True)
                yield Button("Apply", id="osint-modal-apply-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        with contextlib.suppress(Exception):
            self.query_one("#osint-modal-apply-btn", Button).focus()

    @on(Button.Pressed, "#osint-modal-all-btn")
    def handle_enable_all(self) -> None:
        for info in self._sources_info:
            cid = f"#osint-src-{str(info['key']).replace('_', '-')}"
            self.query_one(cid, Checkbox).value = True

    @on(Button.Pressed, "#osint-modal-nokey-btn")
    def handle_nokey_only(self) -> None:
        for info in self._sources_info:
            cid = f"#osint-src-{str(info['key']).replace('_', '-')}"
            is_nokey = str(info.get("tier") or "") in ("free_no_key", "free_optional_key")
            self.query_one(cid, Checkbox).value = is_nokey

    @on(Button.Pressed, "#osint-modal-settings-btn")
    def handle_open_settings(self) -> None:
        self.dismiss({"action": "open_settings"})

    @on(Button.Pressed, "#osint-modal-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#osint-modal-apply-btn")
    def handle_apply(self) -> None:
        selected: list[str] = []
        for info in self._sources_info:
            key = str(info["key"])
            cid = f"#osint-src-{key.replace('_', '-')}"
            if self.query_one(cid, Checkbox).value:
                selected.append(key)
        self.dismiss({"action": "apply", "sources": selected})

    def action_cancel(self) -> None:
        """Close the OSINT sources dialog without applying changes."""
        self.dismiss(None)


__all__ = [
    "ConfirmActionModal",
    "ContextMenuModal",
    "CopyTextModal",
    "CreateCaseModal",
    "OSINTSourcesModal",
    "S1AddBlocklistModal",
    "S1CreateExclusionModal",
    "S1ThreatTriageModal",
    "SaveFilterPresetModal",
    "ScreenshotViewerModal",
    "SplunkNotableTriageModal",
    "TimezoneModal",
    "TriageItemModal",
]
