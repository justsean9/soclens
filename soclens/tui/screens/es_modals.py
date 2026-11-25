"""Modal dialogs for Splunk Enterprise Security (ES) 8.6 Mission Control workbench."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, RichLog, Select, Static, TextArea

from soclens.splunk_es import (
    MC_DISPOSITIONS,
    MC_FINDING_STATUSES,
    NOTABLE_URGENCIES,
)

_SECURITY_DOMAINS: tuple[tuple[str, str], ...] = (
    ("Threat", "threat"),
    ("Endpoint", "endpoint"),
    ("Network", "network"),
    ("Access", "access"),
    ("Identity", "identity"),
    ("Audit", "audit"),
)

_SHARED_MODAL_CSS = """
    align: center middle;
    background: $background 60%;
"""


def _parse_kv_or_json(raw: str) -> dict[str, str]:
    text = raw.strip()
    if not text:
        return {}
    if text.startswith("{"):
        loaded = json.loads(text)
        if not isinstance(loaded, dict):
            raise ValueError("JSON input must be an object.")
        return {str(k).strip(): str(v) for k, v in loaded.items() if str(k).strip()}
    parsed: dict[str, str] = {}
    for seg in text.split(";"):
        clean = seg.strip()
        if not clean:
            continue
        if "=" not in clean:
            raise ValueError(f"Invalid key=value segment '{clean}'. Expected 'field=value; ...'.")
        key, val = clean.split("=", 1)
        clean_k = key.strip()
        if not clean_k:
            raise ValueError("Field name cannot be empty.")
        parsed[clean_k] = val.strip()
    return parsed


class ESBulkTriageModal(ModalScreen[dict[str, Any] | None]):
    """Bulk or single-finding Mission Control triage modal with owner picker and dual-post RF note."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = f"""
    ESBulkTriageModal {{ {_SHARED_MODAL_CSS} }}
    #es-bulk-dialog {{
        width: 76;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }}
    #es-bulk-title {{
        text-style: bold;
        color: $accent;
        height: auto;
    }}
    #es-bulk-summary {{
        color: $text-muted;
        height: auto;
        margin-bottom: 1;
    }}
    #es-bulk-dry-banner {{
        color: $warning;
        height: auto;
        margin-bottom: 1;
    }}
    #es-bulk-scroll {{
        width: 1fr;
        height: auto;
        max-height: 48vh;
    }}
    .es-modal-label {{
        height: 1;
        text-style: bold;
    }}
    #es-bulk-scroll Select, #es-bulk-scroll Input {{
        width: 1fr;
        margin-bottom: 1;
    }}
    #es-bulk-error {{
        color: $error;
        height: auto;
    }}
    #es-bulk-buttons {{
        height: auto;
        align-horizontal: right;
        margin-top: 1;
    }}
    #es-bulk-buttons Button {{
        margin-left: 1;
    }}
    """

    def __init__(
        self,
        *,
        event_ids: Sequence[str],
        available_owners: Sequence[str] = (),
        current_user: str = "",
        default_status: str = "",
        default_urgency: str = "",
        default_disposition: str = "",
        default_note: str = "",
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._event_ids = [str(eid).strip() for eid in event_ids if str(eid).strip()]
        self._available_owners = [str(u).strip() for u in available_owners if str(u).strip()]
        self._current_user = current_user.strip()
        self._default_status = default_status.strip()
        self._default_urgency = default_urgency.strip().lower()
        self._default_disposition = default_disposition.strip()
        self._default_note = default_note
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        status_opts: list[tuple[str, str]] = [("(Unchanged)", "")] + [
            (s, s) for s in MC_FINDING_STATUSES
        ]
        urgency_opts: list[tuple[str, str]] = [("(Unchanged)", "")] + [
            (u.title(), u) for u in NOTABLE_URGENCIES
        ]
        disp_opts: list[tuple[str, str]] = [("(Unchanged)", "")] + list(MC_DISPOSITIONS)

        owner_opts: list[tuple[str, str]] = [("(Unchanged)", "")]
        if self._current_user:
            owner_opts.append((f"Assign to me ({self._current_user})", self._current_user))
        owner_opts.append(("unassigned", "unassigned"))
        seen_owners = {"", self._current_user, "unassigned"}
        for user_name in self._available_owners:
            if user_name not in seen_owners:
                seen_owners.add(user_name)
                owner_opts.append((user_name, user_name))

        valid_status = self._default_status if self._default_status in MC_FINDING_STATUSES else ""
        valid_urg = self._default_urgency if self._default_urgency in NOTABLE_URGENCIES else ""
        valid_disp_vals = {val for _, val in MC_DISPOSITIONS}
        valid_disp = self._default_disposition if self._default_disposition in valid_disp_vals else ""

        with Vertical(id="es-bulk-dialog"):
            yield Static(
                f"Mission Control Triage ({len(self._event_ids)} selected)",
                id="es-bulk-title",
                markup=False,
            )
            preview = ", ".join(self._event_ids[:3])
            if len(self._event_ids) > 3:
                preview += f" (+{len(self._event_ids) - 3} more)"
            yield Static(f"Records: {preview or '-'}", id="es-bulk-summary", markup=False)
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: Mission Control records will not be modified.",
                    id="es-bulk-dry-banner",
                    markup=False,
                )

            with VerticalScroll(id="es-bulk-scroll"):
                yield Static("Status", classes="es-modal-label", markup=False)
                yield Select(
                    status_opts,
                    allow_blank=False,
                    value=valid_status,
                    id="es-bulk-status-select",
                    compact=True,
                )
                yield Static("Urgency", classes="es-modal-label", markup=False)
                yield Select(
                    urgency_opts,
                    allow_blank=False,
                    value=valid_urg,
                    id="es-bulk-urgency-select",
                    compact=True,
                )
                yield Static("Disposition", classes="es-modal-label", markup=False)
                yield Select(
                    disp_opts,
                    allow_blank=False,
                    value=valid_disp,
                    id="es-bulk-disposition-select",
                    compact=True,
                )
                yield Static("Owner (Picker or Manual)", classes="es-modal-label", markup=False)
                yield Select(
                    owner_opts,
                    allow_blank=False,
                    value="",
                    id="es-bulk-owner-select",
                    compact=True,
                )
                yield Input(
                    value="",
                    placeholder="Optional owner username override",
                    id="es-bulk-owner-input",
                    compact=True,
                )
                yield Static("Markdown Triage Note", classes="es-modal-label", markup=False)
                yield Input(
                    value=self._default_note,
                    placeholder="Optional Markdown audit note",
                    id="es-bulk-note-input",
                    compact=True,
                )
                yield Checkbox(
                    "Dual-post note as RF Comment",
                    value=False,
                    id="es-bulk-dual-rf-cb",
                    compact=True,
                )

            yield Static("", id="es-bulk-error", markup=False)
            with Horizontal(id="es-bulk-buttons"):
                yield Button("Cancel", id="es-bulk-cancel-btn", variant="default", compact=True)
                yield Button("Apply Triage", id="es-bulk-apply-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#es-bulk-status-select", Select).focus()

    @on(Button.Pressed, "#es-bulk-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted)
    def handle_input_submitted(self) -> None:
        self.handle_apply()

    @on(Button.Pressed, "#es-bulk-apply-btn")
    def handle_apply(self) -> None:
        status_val = str(self.query_one("#es-bulk-status-select", Select).value or "").strip()
        urgency_val = str(self.query_one("#es-bulk-urgency-select", Select).value or "").strip()
        disp_val = str(self.query_one("#es-bulk-disposition-select", Select).value or "").strip()
        owner_sel = str(self.query_one("#es-bulk-owner-select", Select).value or "").strip()
        owner_inp = self.query_one("#es-bulk-owner-input", Input).value.strip()
        owner_val = owner_inp or owner_sel
        note_val = self.query_one("#es-bulk-note-input", Input).value.strip()
        dual_rf = bool(self.query_one("#es-bulk-dual-rf-cb", Checkbox).value)

        if not (status_val or urgency_val or disp_val or owner_val or note_val):
            self.query_one("#es-bulk-error", Static).update(
                "Select at least one field or enter a note before applying."
            )
            return

        self.dismiss(
            {
                "event_ids": list(self._event_ids),
                "status": status_val or None,
                "urgency": urgency_val or None,
                "disposition": disp_val or None,
                "owner": owner_val or None,
                "note": note_val or None,
                "dual_post_rf": dual_rf,
            }
        )

    def action_cancel(self) -> None:
        self.dismiss(None)


class ESInvestigationModal(ModalScreen[dict[str, Any] | None]):
    """Modal for creating a new ES 8.6 Investigation or attaching findings to an existing one."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = f"""
    ESInvestigationModal {{ {_SHARED_MODAL_CSS} }}
    #es-inv-dialog {{
        width: 76;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }}
    #es-inv-title {{
        text-style: bold;
        color: $accent;
        height: auto;
    }}
    #es-inv-summary {{
        color: $text-muted;
        height: auto;
        margin-bottom: 1;
    }}
    #es-inv-dry-banner {{
        color: $warning;
        height: auto;
        margin-bottom: 1;
    }}
    #es-inv-scroll {{
        width: 1fr;
        height: auto;
        max-height: 48vh;
    }}
    .es-modal-label {{
        height: 1;
        text-style: bold;
    }}
    #es-inv-scroll Select, #es-inv-scroll Input {{
        width: 1fr;
        margin-bottom: 1;
    }}
    #es-inv-error {{
        color: $error;
        height: auto;
    }}
    #es-inv-buttons {{
        height: auto;
        align-horizontal: right;
        margin-top: 1;
    }}
    #es-inv-buttons Button {{
        margin-left: 1;
    }}
    """

    def __init__(
        self,
        *,
        finding_ids: Sequence[str] = (),
        finding_times: Sequence[str] = (),
        existing_investigations: Sequence[dict[str, Any]] = (),
        default_mode: str = "create",
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._finding_ids = [str(fid).strip() for fid in finding_ids if str(fid).strip()]
        self._finding_times = [str(ft).strip() for ft in finding_times]
        self._existing = [dict(inv) for inv in existing_investigations]
        self._default_mode = "attach" if default_mode == "attach" and self._existing else "create"
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        mode_opts: list[tuple[str, str]] = [("Create New Investigation", "create")]
        if self._existing:
            mode_opts.append(("Attach to Existing Investigation", "attach"))
        inv_opts: list[tuple[str, str]] = []
        for inv in self._existing:
            guid = str(inv.get("investigation_guid") or inv.get("event_id") or "").strip()
            name = str(inv.get("name") or inv.get("rule_title") or guid).strip()
            if guid:
                inv_opts.append((f"{name} ({guid[:12]})", guid))
        if not inv_opts:
            inv_opts.append(("(No existing investigations loaded)", ""))

        urgency_opts: list[tuple[str, str]] = [("Default", "")] + [
            (u.title(), u) for u in NOTABLE_URGENCIES
        ]
        status_opts: list[tuple[str, str]] = [("New", "New"), ("In Progress", "In Progress")]

        with Vertical(id="es-inv-dialog"):
            yield Static("Splunk ES Investigation", id="es-inv-title", markup=False)
            yield Static(
                f"Attached findings: {len(self._finding_ids)}",
                id="es-inv-summary",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: Investigation will not be created/modified.",
                    id="es-inv-dry-banner",
                    markup=False,
                )
            with VerticalScroll(id="es-inv-scroll"):
                yield Static("Action Mode", classes="es-modal-label", markup=False)
                yield Select(
                    mode_opts,
                    allow_blank=False,
                    value=self._default_mode,
                    id="es-inv-mode-select",
                    compact=True,
                )
                yield Static("Existing Investigation", id="es-inv-existing-lbl", classes="es-modal-label", markup=False)
                yield Select(
                    inv_opts,
                    allow_blank=False,
                    value=inv_opts[0][1],
                    id="es-inv-existing-select",
                    compact=True,
                )
                yield Static("Investigation Name", id="es-inv-name-lbl", classes="es-modal-label", markup=False)
                yield Input(
                    value="",
                    placeholder="e.g. Incident: C2 Beacon Investigation",
                    id="es-inv-name-input",
                    compact=True,
                )
                yield Static("Description", id="es-inv-desc-lbl", classes="es-modal-label", markup=False)
                yield Input(
                    value="",
                    placeholder="Optional investigation summary",
                    id="es-inv-desc-input",
                    compact=True,
                )
                yield Static("Urgency", id="es-inv-urg-lbl", classes="es-modal-label", markup=False)
                yield Select(
                    urgency_opts,
                    allow_blank=False,
                    value="",
                    id="es-inv-urgency-select",
                    compact=True,
                )
                yield Static("Status", id="es-inv-status-lbl", classes="es-modal-label", markup=False)
                yield Select(
                    status_opts,
                    allow_blank=False,
                    value="New",
                    id="es-inv-status-select",
                    compact=True,
                )
                yield Static("Owner", id="es-inv-owner-lbl", classes="es-modal-label", markup=False)
                yield Input(
                    value="",
                    placeholder="Optional owner username",
                    id="es-inv-owner-input",
                    compact=True,
                )

            yield Static("", id="es-inv-error", markup=False)
            with Horizontal(id="es-inv-buttons"):
                yield Button("Cancel", id="es-inv-cancel-btn", variant="default", compact=True)
                yield Button("Submit", id="es-inv-submit-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self._sync_mode_visibility()
        self.query_one("#es-inv-mode-select", Select).focus()

    def _sync_mode_visibility(self) -> None:
        mode = str(self.query_one("#es-inv-mode-select", Select).value or "create")
        is_attach = mode == "attach"
        self.query_one("#es-inv-existing-lbl", Static).display = is_attach
        self.query_one("#es-inv-existing-select", Select).display = is_attach
        for wid in (
            "#es-inv-name-lbl",
            "#es-inv-name-input",
            "#es-inv-desc-lbl",
            "#es-inv-desc-input",
            "#es-inv-urg-lbl",
            "#es-inv-urgency-select",
            "#es-inv-status-lbl",
            "#es-inv-status-select",
            "#es-inv-owner-lbl",
            "#es-inv-owner-input",
        ):
            self.query_one(wid).display = not is_attach

    @on(Select.Changed, "#es-inv-mode-select")
    def handle_mode_changed(self) -> None:
        self._sync_mode_visibility()

    @on(Button.Pressed, "#es-inv-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted)
    def handle_input_submitted(self) -> None:
        self.handle_submit()

    @on(Button.Pressed, "#es-inv-submit-btn")
    def handle_submit(self) -> None:
        mode = str(self.query_one("#es-inv-mode-select", Select).value or "create")
        if mode == "attach":
            inv_id = str(self.query_one("#es-inv-existing-select", Select).value or "").strip()
            if not inv_id:
                self.query_one("#es-inv-error", Static).update(
                    "Select an existing investigation to attach findings."
                )
                return
            if not self._finding_ids:
                self.query_one("#es-inv-error", Static).update(
                    "Select at least one finding to attach."
                )
                return
            self.dismiss(
                {
                    "mode": "attach",
                    "investigation_id": inv_id,
                    "finding_ids": list(self._finding_ids),
                    "finding_times": list(self._finding_times),
                }
            )
            return

        name = self.query_one("#es-inv-name-input", Input).value.strip()
        if not name:
            self.query_one("#es-inv-error", Static).update("Investigation name is required.")
            return
        self.dismiss(
            {
                "mode": "create",
                "name": name,
                "description": self.query_one("#es-inv-desc-input", Input).value.strip() or None,
                "urgency": str(self.query_one("#es-inv-urgency-select", Select).value or "").strip()
                or None,
                "status": str(self.query_one("#es-inv-status-select", Select).value or "").strip()
                or None,
                "owner": self.query_one("#es-inv-owner-input", Input).value.strip() or None,
                "finding_ids": list(self._finding_ids),
                "finding_times": list(self._finding_times),
            }
        )

    def action_cancel(self) -> None:
        self.dismiss(None)


class ESAdaptiveResponseModal(ModalScreen[dict[str, Any] | None]):
    """Inspect executed Adaptive Response invocations and dispatch ad-hoc AR actions."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = f"""
    ESAdaptiveResponseModal {{ {_SHARED_MODAL_CSS} }}
    #es-ar-dialog {{
        width: 76;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }}
    #es-ar-title {{
        text-style: bold;
        color: $accent;
        height: auto;
    }}
    #es-ar-summary {{
        color: $text-muted;
        height: auto;
        margin-bottom: 1;
    }}
    #es-ar-dry-banner {{
        color: $warning;
        height: auto;
        margin-bottom: 1;
    }}
    #es-ar-scroll {{
        width: 1fr;
        height: auto;
        max-height: 48vh;
    }}
    #es-ar-history-log {{
        height: 6;
        max-height: 7;
        border: solid $primary;
        margin-bottom: 1;
    }}
    .es-modal-label {{
        height: 1;
        text-style: bold;
    }}
    #es-ar-scroll Select, #es-ar-scroll Input {{
        width: 1fr;
        margin-bottom: 1;
    }}
    #es-ar-error {{
        color: $error;
        height: auto;
    }}
    #es-ar-buttons {{
        height: auto;
        align-horizontal: right;
        margin-top: 1;
    }}
    #es-ar-buttons Button {{
        margin-left: 1;
    }}
    """

    def __init__(
        self,
        *,
        event_id: str,
        orig_sid: str = "",
        orig_rid: str = "",
        invocations: Sequence[dict[str, Any]] = (),
        available_actions: Sequence[dict[str, Any]] = (),
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._event_id = event_id.strip()
        self._orig_sid = orig_sid.strip()
        self._orig_rid = orig_rid.strip()
        self._invocations = [dict(inv) for inv in invocations]
        self._actions = [dict(act) for act in available_actions]
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        action_opts: list[tuple[str, str]] = []
        for act in self._actions:
            name = str(act.get("name") or "").strip()
            label = str(act.get("label") or name).strip()
            if name:
                action_opts.append((f"{label} ({name})", name))
        if not action_opts:
            action_opts.append(("(No ad-hoc AR actions available)", ""))

        with Vertical(id="es-ar-dialog"):
            yield Static(
                f"Adaptive Response: {self._event_id}",
                id="es-ar-title",
                markup=False,
            )
            yield Static(
                f"orig_sid={self._orig_sid or '-'} | orig_rid={self._orig_rid or '-'}",
                id="es-ar-summary",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: Ad-hoc Adaptive Response dispatch is blocked.",
                    id="es-ar-dry-banner",
                    markup=False,
                )
            with VerticalScroll(id="es-ar-scroll"):
                yield Static("Recent AR Invocations", classes="es-modal-label", markup=False)
                yield RichLog(
                    id="es-ar-history-log",
                    highlight=False,
                    markup=False,
                    wrap=True,
                )
                yield Static("Ad-Hoc Action", classes="es-modal-label", markup=False)
                yield Select(
                    action_opts,
                    allow_blank=False,
                    value=action_opts[0][1],
                    id="es-ar-action-select",
                    compact=True,
                )
                yield Static("Parameters (JSON or k=v; ...)", classes="es-modal-label", markup=False)
                yield Input(
                    value="",
                    placeholder="e.g. risk_score=25; risk_message=Confirmed C2",
                    id="es-ar-params-input",
                    compact=True,
                )
            yield Static("", id="es-ar-error", markup=False)
            with Horizontal(id="es-ar-buttons"):
                yield Button("Close", id="es-ar-close-btn", variant="default", compact=True)
                yield Button("Dispatch Action", id="es-ar-dispatch-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        log = self.query_one("#es-ar-history-log", RichLog)
        if not self._invocations:
            log.write("No Adaptive Response invocations recorded for this finding.")
        else:
            for inv in self._invocations:
                ts = str(inv.get("_time") or "-")
                name = str(inv.get("action_label") or inv.get("action_name") or "-")
                status = str(inv.get("action_status") or "-")
                mode = str(inv.get("action_mode") or "-")
                user = str(inv.get("user") or "-")
                log.write(f"[{ts}] {name} | status={status} | mode={mode} | user={user}")
        self.query_one("#es-ar-action-select", Select).focus()

    @on(Button.Pressed, "#es-ar-close-btn")
    def handle_close(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted)
    def handle_input_submitted(self) -> None:
        self.handle_dispatch()

    @on(Button.Pressed, "#es-ar-dispatch-btn")
    def handle_dispatch(self) -> None:
        action_name = str(self.query_one("#es-ar-action-select", Select).value or "").strip()
        if not action_name:
            self.query_one("#es-ar-error", Static).update("No Adaptive Response action selected.")
            return
        if not self._orig_sid or not self._orig_rid:
            self.query_one("#es-ar-error", Static).update(
                "Finding requires orig_sid and orig_rid for ad-hoc AR dispatch."
            )
            return
        raw_params = self.query_one("#es-ar-params-input", Input).value
        try:
            params = _parse_kv_or_json(raw_params)
        except ValueError as exc:
            self.query_one("#es-ar-error", Static).update(f"Invalid parameters: {exc}")
            return
        self.dismiss(
            {
                "action_name": action_name,
                "sid": self._orig_sid,
                "rid": self._orig_rid,
                "params": params,
            }
        )

    def action_cancel(self) -> None:
        self.dismiss(None)


class ESCreateFindingModal(ModalScreen[dict[str, Any] | None]):
    """Modal for creating a manual finding via ES 8.6 MC v2 ``POST /public/v2/findings``."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = f"""
    ESCreateFindingModal {{ {_SHARED_MODAL_CSS} }}
    #es-create-dialog {{
        width: 76;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }}
    #es-create-title {{
        text-style: bold;
        color: $accent;
        height: auto;
    }}
    #es-create-fields-hint {{
        color: $text-muted;
        height: auto;
        margin-bottom: 1;
    }}
    #es-create-dry-banner {{
        color: $warning;
        height: auto;
        margin-bottom: 1;
    }}
    #es-create-scroll {{
        width: 1fr;
        height: auto;
        max-height: 48vh;
    }}
    .es-modal-label {{
        height: 1;
        text-style: bold;
    }}
    #es-create-scroll Select, #es-create-scroll Input {{
        width: 1fr;
        margin-bottom: 1;
    }}
    #es-create-error {{
        color: $error;
        height: auto;
    }}
    #es-create-buttons {{
        height: auto;
        align-horizontal: right;
        margin-top: 1;
    }}
    #es-create-buttons Button {{
        margin-left: 1;
    }}
    """

    def __init__(
        self,
        *,
        tenant_field: str = "tenant_id",
        pinned_custom_fields: Sequence[str] = (),
        discovered_fields: Sequence[dict[str, str]] = (),
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._tenant_field = tenant_field.strip() or "tenant_id"
        self._pinned_fields = [str(f).strip() for f in pinned_custom_fields if str(f).strip()]
        self._discovered_fields = [dict(f) for f in discovered_fields]
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        urgency_opts: list[tuple[str, str]] = [(u.title(), u) for u in NOTABLE_URGENCIES]
        suggested = list(self._pinned_fields)
        for item in self._discovered_fields[:8]:
            fname = str(item.get("field") or "").strip()
            if fname and fname not in suggested:
                suggested.append(fname)
        hint = (
            "Registered/pinned fields: " + ", ".join(suggested[:10])
            if suggested
            else "Custom fields: key=value; key2=value2 (or JSON object)"
        )

        with Vertical(id="es-create-dialog"):
            yield Static("Create Manual Finding (MC v2)", id="es-create-title", markup=False)
            yield Static(hint, id="es-create-fields-hint", markup=False)
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: Finding will not be created.",
                    id="es-create-dry-banner",
                    markup=False,
                )
            with VerticalScroll(id="es-create-scroll"):
                yield Static("Rule Title *", classes="es-modal-label", markup=False)
                yield Input(
                    value="",
                    placeholder="e.g. Manual C2 Escalation",
                    id="es-create-title-input",
                    compact=True,
                )
                yield Static("Security Domain", classes="es-modal-label", markup=False)
                yield Select(
                    list(_SECURITY_DOMAINS),
                    allow_blank=False,
                    value="threat",
                    id="es-create-domain-select",
                    compact=True,
                )
                yield Static("Urgency", classes="es-modal-label", markup=False)
                yield Select(
                    urgency_opts,
                    allow_blank=False,
                    value="medium",
                    id="es-create-urgency-select",
                    compact=True,
                )
                yield Static("Risk Object / Entity", classes="es-modal-label", markup=False)
                yield Input(
                    value="",
                    placeholder="e.g. 198.51.100.10 or ws-01",
                    id="es-create-entity-input",
                    compact=True,
                )
                yield Static(f"Tenant ({self._tenant_field})", classes="es-modal-label", markup=False)
                yield Input(
                    value="",
                    placeholder="Optional tenant identifier",
                    id="es-create-tenant-input",
                    compact=True,
                )
                yield Static("Description", classes="es-modal-label", markup=False)
                yield Input(
                    value="",
                    placeholder="Optional finding description",
                    id="es-create-desc-input",
                    compact=True,
                )
                yield Static("Additional / Custom Fields", classes="es-modal-label", markup=False)
                yield Input(
                    value="",
                    placeholder="e.g. snow_ticket=INC1234; src=198.51.100.10",
                    id="es-create-custom-fields-input",
                    compact=True,
                )

            yield Static("", id="es-create-error", markup=False)
            with Horizontal(id="es-create-buttons"):
                yield Button("Cancel", id="es-create-cancel-btn", variant="default", compact=True)
                yield Button("Create Finding", id="es-create-submit-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#es-create-title-input", Input).focus()

    @on(Button.Pressed, "#es-create-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted)
    def handle_input_submitted(self) -> None:
        self.handle_submit()

    @on(Button.Pressed, "#es-create-submit-btn")
    def handle_submit(self) -> None:
        title = self.query_one("#es-create-title-input", Input).value.strip()
        if not title:
            self.query_one("#es-create-error", Static).update("Rule Title is required.")
            return
        raw_extra = self.query_one("#es-create-custom-fields-input", Input).value
        try:
            additional = _parse_kv_or_json(raw_extra)
        except ValueError as exc:
            self.query_one("#es-create-error", Static).update(f"Invalid custom fields: {exc}")
            return

        tenant_val = self.query_one("#es-create-tenant-input", Input).value.strip()
        if tenant_val:
            additional.setdefault(self._tenant_field, tenant_val)

        self.dismiss(
            {
                "rule_title": title,
                "security_domain": str(
                    self.query_one("#es-create-domain-select", Select).value or "threat"
                ),
                "urgency": str(self.query_one("#es-create-urgency-select", Select).value or "medium"),
                "risk_object": self.query_one("#es-create-entity-input", Input).value.strip() or None,
                "rule_description": self.query_one("#es-create-desc-input", Input).value.strip()
                or None,
                "additional_fields": additional or None,
            }
        )

    def action_cancel(self) -> None:
        self.dismiss(None)


class ESSavedViewModal(ModalScreen[dict[str, Any] | None]):
    """Modal for naming and saving a custom Splunk ES queue view to settings."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = f"""
    ESSavedViewModal {{ {_SHARED_MODAL_CSS} }}
    #es-saved-view-dialog {{
        width: 64;
        max-width: 92%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }}
    #es-saved-view-title {{
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }}
    #es-saved-view-name-input {{
        width: 1fr;
        margin-bottom: 1;
    }}
    #es-saved-view-error {{
        color: $error;
        height: auto;
    }}
    #es-saved-view-buttons {{
        height: auto;
        align-horizontal: right;
        margin-top: 1;
    }}
    #es-saved-view-buttons Button {{
        margin-left: 1;
    }}
    """

    def __init__(self, *, default_name: str = "") -> None:
        super().__init__()
        self._default_name = default_name.strip()

    def compose(self) -> ComposeResult:
        with Vertical(id="es-saved-view-dialog"):
            yield Static("Save Custom Splunk ES View", id="es-saved-view-title", markup=False)
            yield Static("View Name", markup=False)
            yield Input(
                value=self._default_name,
                placeholder="e.g. ACME High/Crit Open",
                id="es-saved-view-name-input",
                compact=True,
            )
            yield Static("", id="es-saved-view-error", markup=False)
            with Horizontal(id="es-saved-view-buttons"):
                yield Button("Cancel", id="es-saved-view-cancel-btn", variant="default", compact=True)
                yield Button("Save View", id="es-saved-view-save-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#es-saved-view-name-input", Input).focus()

    @on(Button.Pressed, "#es-saved-view-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted)
    def handle_input_submitted(self) -> None:
        self.handle_save()

    @on(Button.Pressed, "#es-saved-view-save-btn")
    def handle_save(self) -> None:
        name = self.query_one("#es-saved-view-name-input", Input).value.strip()
        if not name:
            self.query_one("#es-saved-view-error", Static).update("View name is required.")
            return
        self.dismiss({"label": name})

    def action_cancel(self) -> None:
        self.dismiss(None)


class ESNoteModal(ModalScreen[dict[str, Any] | None]):
    """Markdown note modal with optional dual-post as Recorded Future Comment."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = f"""
    ESNoteModal {{ {_SHARED_MODAL_CSS} }}
    #es-note-dialog {{
        width: 74;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }}
    #es-note-title {{
        text-style: bold;
        color: $accent;
        height: auto;
    }}
    #es-note-dry-banner {{
        color: $warning;
        height: auto;
        margin-bottom: 1;
    }}
    #es-note-scroll {{
        width: 1fr;
        height: auto;
        max-height: 48vh;
    }}
    #es-note-title-input {{
        width: 1fr;
        margin-bottom: 1;
    }}
    #es-note-text {{
        width: 1fr;
        height: 6;
        margin-bottom: 1;
    }}
    #es-note-error {{
        color: $error;
        height: auto;
    }}
    #es-note-buttons {{
        height: auto;
        align-horizontal: right;
        margin-top: 1;
    }}
    #es-note-buttons Button {{
        margin-left: 1;
    }}
    """

    def __init__(self, *, event_id: str, has_rf_data: bool = False, dry_run: bool = False) -> None:
        super().__init__()
        self._event_id = event_id.strip()
        self._has_rf_data = has_rf_data
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        with Vertical(id="es-note-dialog"):
            yield Static(f"Add Markdown Note: {self._event_id}", id="es-note-title", markup=False)
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: Note will not be posted.",
                    id="es-note-dry-banner",
                    markup=False,
                )
            with VerticalScroll(id="es-note-scroll"):
                yield Static("Title (optional)", markup=False)
                yield Input(
                    value="",
                    placeholder="e.g. Initial Triage",
                    id="es-note-title-input",
                    compact=True,
                )
                yield Static("Markdown Content", markup=False)
                yield TextArea("", id="es-note-text")
                dual_label = (
                    "Also dual-post as RF Comment"
                    if self._has_rf_data
                    else "Also dual-post as RF Comment (no RF data on row)"
                )
                yield Checkbox(
                    dual_label,
                    value=False,
                    id="es-note-dual-rf-cb",
                    disabled=not self._has_rf_data,
                    compact=True,
                )
            yield Static("", id="es-note-error", markup=False)
            with Horizontal(id="es-note-buttons"):
                yield Button("Cancel", id="es-note-cancel-btn", variant="default", compact=True)
                yield Button("Post Note", id="es-note-submit-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#es-note-text", TextArea).focus()

    @on(Button.Pressed, "#es-note-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#es-note-submit-btn")
    def handle_submit(self) -> None:
        content = self.query_one("#es-note-text", TextArea).text.strip()
        if not content:
            self.query_one("#es-note-error", Static).update("Note content is required.")
            return
        self.dismiss(
            {
                "title": self.query_one("#es-note-title-input", Input).value.strip() or None,
                "content": content,
                "dual_post_rf": bool(self.query_one("#es-note-dual-rf-cb", Checkbox).value),
            }
        )

    def action_cancel(self) -> None:
        self.dismiss(None)
