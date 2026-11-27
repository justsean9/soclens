"""Reusable Textual widgets and modals for agentic SOC event AI panels, policy, and audit."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Sequence
from typing import Any, ClassVar

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
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
    Switch,
)

from soclens.agent_audit import AuditEntry, AuditLogStore, redact_sensitive_data
from soclens.agent_policy import (
    DEFAULT_KILL_SWITCH_LABEL,
    MAX_IDENTICAL_TOOL_CALLS,
    MAX_SAME_TOOL_FAILURES,
    MAX_TOOL_STEPS,
    MIN_IDENTICAL_TOOL_CALLS,
    MIN_SAME_TOOL_FAILURES,
    MIN_TOOL_STEPS,
    AIPolicyStore,
    InvestigationMode,
)
from soclens.agent_tools import ReadOnlyToolRegistry
from soclens.event_tracker import EventAIPanelEntry, UniqueEvent

_KILL_HOTKEY_OPTIONS: tuple[tuple[str, str], ...] = (
    ("F12 (Default)", "f12"),
    ("F11", "f11"),
    ("Ctrl+\\", "ctrl+backslash"),
    ("Disabled (Button Only)", "none"),
)

_KILL_CONFIG_SWITCH_SPECS: tuple[tuple[str, str, str], ...] = (
    (
        "ai-ctrl-kill-visible",
        "kill_switch_visible",
        "Show Kill Switch Button in Every Dashboard",
    ),
    (
        "ai-ctrl-kill-confirm-engage",
        "kill_switch_confirm_engage",
        "Require Confirmation Before Halting AI",
    ),
    (
        "ai-ctrl-kill-confirm-resume",
        "kill_switch_confirm_resume",
        "Require Confirmation Before Resuming AI",
    ),
    (
        "ai-ctrl-kill-persist",
        "kill_switch_persist_across_restarts",
        "Keep AI Halted Across App Restarts",
    ),
)

_CONTROL_SWITCH_SPECS: tuple[tuple[str, str, str], ...] = (
    (
        "ai-ctrl-background-triage",
        "background_triage_enabled",
        "Background Triage (Auto-investigate new events)",
    ),
    (
        "ai-ctrl-cross-search",
        "cross_search_enabled",
        "Cross-Source Search (Read-only pivoting)",
    ),
    (
        "ai-ctrl-splunk-search",
        "splunk_search_enabled",
        "Splunk SPL Search (Read-only SPL queries)",
    ),
    (
        "ai-ctrl-splunk-es",
        "splunk_es_enabled",
        "Splunk ES (Notables, investigations & RBA)",
    ),
    (
        "ai-ctrl-sentinelone",
        "sentinelone_enabled",
        "SentinelOne (Threats, agents & activities)",
    ),
    (
        "ai-ctrl-recorded-future",
        "recorded_future_enabled",
        "Recorded Future (Alerts, Playbook & IOCs)",
    ),
    (
        "ai-ctrl-watchlists-osint",
        "watchlists_osint_enabled",
        "Watchlists & OSINT (Lookup & entity research)",
    ),
    (
        "ai-ctrl-local-db",
        "local_db_enabled",
        "Local DB History & Knowledge (Zero-API local search)",
    ),
)

_SWITCH_ID_TO_FIELD: dict[str, str] = {
    **{sw_id: field_name for sw_id, field_name, _label in _CONTROL_SWITCH_SPECS},
    **{sw_id: field_name for sw_id, field_name, _label in _KILL_CONFIG_SWITCH_SPECS},
}


class AskEventAIModal(ModalScreen[str | None]):
    """Modal dialog prompting the analyst for an event-only AI/Copilot question."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    AskEventAIModal {
        align: center middle;
        background: $background 60%;
    }
    #ask-ai-dialog {
        width: 76;
        max-width: 92%;
        height: auto;
        max-height: 85%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #ask-ai-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #ask-ai-event-summary {
        color: $text-muted;
        margin-bottom: 1;
    }
    #ask-ai-input {
        width: 1fr;
        margin-bottom: 1;
    }
    #ask-ai-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #ask-ai-buttons {
        height: auto;
        align-horizontal: right;
    }
    #ask-ai-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        event_title: str = "",
        event_key: str = "",
        default_question: str = "",
    ) -> None:
        super().__init__()
        self._event_title = event_title.strip()
        self._event_key = event_key.strip()
        self._default_question = default_question

    def compose(self) -> ComposeResult:
        summary_parts: list[str] = []
        if self._event_title:
            summary_parts.append(self._event_title)
        if self._event_key:
            summary_parts.append(f"[{self._event_key}]")
        summary_text = " ".join(summary_parts) or "Selected SOC Event (event context only)"
        with Vertical(id="ask-ai-dialog"):
            yield Static(
                "Ask AI / Copilot (Event Context Only — 0 External Tools)",
                id="ask-ai-title",
                markup=False,
            )
            yield Static(summary_text, id="ask-ai-event-summary", markup=False)
            yield Input(
                value=self._default_question,
                placeholder="Enter question about this event...",
                id="ask-ai-input",
                compact=True,
            )
            yield Static("", id="ask-ai-error", markup=False)
            with Horizontal(id="ask-ai-buttons"):
                yield Button("Cancel", id="ask-ai-cancel", variant="default", compact=True)
                yield Button("Ask AI", id="ask-ai-submit", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#ask-ai-input", Input).focus()

    def _submit_question(self) -> None:
        inp = self.query_one("#ask-ai-input", Input)
        question = inp.value.strip()
        if not question:
            self.query_one("#ask-ai-error", Static).update("Please enter a question.")
            inp.focus()
            return
        self.dismiss(question)

    @on(Button.Pressed, "#ask-ai-submit")
    def handle_submit(self) -> None:
        self._submit_question()

    @on(Input.Submitted, "#ask-ai-input")
    def handle_input_submitted(self) -> None:
        self._submit_question()

    @on(Button.Pressed, "#ask-ai-cancel")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        """Dismiss the Ask AI modal without triggering an investigation."""
        self.dismiss(None)


class EventAIPanelWidget(Vertical):
    """Per-event AI investigation panel displaying persisted and live AI responses."""

    DEFAULT_CSS: ClassVar[str] = """
    EventAIPanelWidget {
        width: 1fr;
        height: 10;
        min-height: 7;
        max-height: 12;
        margin-top: 0;
        background: #101726;
        border-top: solid #2e3c5c;
    }
    EventAIPanelWidget.ai-panel-compact {
        height: 5;
        min-height: 4;
        max-height: 6;
    }
    EventAIPanelWidget .ai-panel-header {
        height: 1;
        width: 1fr;
        background: #182032;
        padding: 0 1;
        align-vertical: middle;
    }
    EventAIPanelWidget .ai-panel-title {
        width: 1fr;
        height: 1;
        color: #9ec5ff;
        text-style: bold;
    }
    EventAIPanelWidget .ai-panel-header Button {
        min-width: 6;
        margin-left: 1;
    }
    EventAIPanelWidget .ai-panel-log {
        width: 1fr;
        height: 1fr;
        min-height: 3;
        background: #0d111a;
        border: round #2e3c5c;
    }
    EventAIPanelWidget.ai-panel-compact .ai-panel-log {
        min-height: 2;
        border: none;
    }
    """

    class AskRequested(Message):
        """Posted when the analyst clicks Ask AI on the per-event AI panel."""

        def __init__(self, panel: EventAIPanelWidget, event: UniqueEvent | None) -> None:
            self.panel: EventAIPanelWidget = panel
            self.event: UniqueEvent | None = event
            super().__init__()

        @property
        def control(self) -> EventAIPanelWidget:
            return self.panel

    class FullInvestigateRequested(Message):
        """Posted when the analyst clicks Full Investigate on the per-event AI panel."""

        def __init__(self, panel: EventAIPanelWidget, event: UniqueEvent | None) -> None:
            self.panel: EventAIPanelWidget = panel
            self.event: UniqueEvent | None = event
            super().__init__()

        @property
        def control(self) -> EventAIPanelWidget:
            return self.panel

    def __init__(self, *args: Any, classes: str | None = None, **kwargs: Any) -> None:
        merged_classes = f"event-ai-panel {classes}".strip() if classes else "event-ai-panel"
        super().__init__(*args, classes=merged_classes, **kwargs)
        self._current_event: UniqueEvent | None = None
        self._entries: list[EventAIPanelEntry] = []

    @property
    def current_event(self) -> UniqueEvent | None:
        """Return the currently bound ``UniqueEvent`` if any."""
        return self._current_event

    @property
    def current_event_key(self) -> str | None:
        """Return the ``event_key`` currently displayed in this panel."""
        return self._current_event.event_key if self._current_event is not None else None

    def compose(self) -> ComposeResult:
        with Horizontal(classes="ai-panel-header"):
            yield Static(
                "AI Investigation (No event selected)",
                classes="ai-panel-title",
                markup=False,
            )
            yield Button("Ask AI", id="btn-ai-ask-event", compact=True)
            yield Button(
                "Full Investigate",
                id="btn-ai-full-investigate",
                variant="primary",
                compact=True,
            )
        yield RichLog(
            classes="ai-panel-log",
            highlight=False,
            markup=False,
            wrap=True,
        )

    def _set_header_title(self, text: str) -> None:
        with contextlib.suppress(Exception):
            self.query_one(".ai-panel-title", Static).update(text)

    def set_event(
        self,
        event: UniqueEvent | None,
        panels: Sequence[EventAIPanelEntry] = (),
    ) -> None:
        """Bind ``event`` and render its persisted ``EventAIPanelEntry`` records."""
        self._current_event = event
        self._entries = list(panels)
        try:
            log = self.query_one(RichLog)
        except Exception:
            return

        log.clear()
        if event is None:
            self._set_header_title("AI Investigation (No event selected)")
            log.write("Select an event row to view or run AI investigations.")
            return

        if not self._entries:
            self._set_header_title(f"AI Investigation (0): {event.event_key}")
            log.write(
                f"No AI investigations recorded yet for {event.event_key}. "
                "Use Ask AI or Full Investigate."
            )
            return

        self._set_header_title(f"AI Investigation ({len(self._entries)}): {event.event_key}")
        for idx, entry in enumerate(self._entries):
            if idx > 0:
                log.write("-" * 48)
            auto_tag = " [AUTO]" if entry.auto_triggered else ""
            header_line = (
                f"[{entry.timestamp}] mode={entry.mode} "
                f"provider={entry.provider or '-'} model={entry.model or '-'} "
                f"status={entry.status}{auto_tag}"
            )
            log.write(Text(header_line, style="bold cyan"))
            if entry.question:
                log.write(f"Question: {entry.question}")
            if entry.answer_markdown:
                log.write(entry.answer_markdown)
            if entry.tool_calls:
                tools_desc = ", ".join(
                    str(tc.get("tool_name") or tc.get("name") or "")
                    for tc in entry.tool_calls
                    if isinstance(tc, dict)
                )
                if tools_desc:
                    log.write(f"Tools called ({len(entry.tool_calls)}): {tools_desc}")
            if entry.blocked_actions:
                blocked_desc = "; ".join(
                    f"{blk.get('tool_name', '')} ({blk.get('reason', '')})"
                    for blk in entry.blocked_actions
                    if isinstance(blk, dict)
                )
                if blocked_desc:
                    log.write(Text(f"Blocked actions: {blocked_desc}", style="yellow"))
            if entry.error:
                log.write(Text(f"Error: {entry.error}", style="bold red"))

    def show_investigating(
        self,
        event: UniqueEvent,
        mode: InvestigationMode,
        *,
        question: str = "",
    ) -> None:
        """Show an in-progress indicator for ``event`` while an investigation runs."""
        self._current_event = event
        self._set_header_title(f"AI Investigation (Running {mode}): {event.event_key}")
        try:
            log = self.query_one(RichLog)
        except Exception:
            return
        log.clear()
        log.write(Text(f"Running {mode} for {event.event_key}...", style="bold yellow"))
        if question:
            log.write(f"Question: {question}")

    @on(Button.Pressed, "#btn-ai-ask-event")
    def handle_ask_button(self, event: Button.Pressed) -> None:
        event.stop()
        self.post_message(self.AskRequested(self, self._current_event))

    @on(Button.Pressed, "#btn-ai-full-investigate")
    def handle_full_button(self, event: Button.Pressed) -> None:
        event.stop()
        self.post_message(self.FullInvestigateRequested(self, self._current_event))


class AIControlPanelWidget(VerticalScroll):
    """AI Control Panel governing background triage, cross-search, source, and tool policies."""

    DEFAULT_CSS: ClassVar[str] = """
    AIControlPanelWidget {
        width: 1fr;
        height: 1fr;
        padding: 0 1;
        background: #0f131c;
    }
    AIControlPanelWidget .ai-ctrl-title {
        height: 1;
        width: 1fr;
        text-style: bold;
        color: #9ec5ff;
        background: #182032;
        padding: 0 1;
        margin-bottom: 1;
    }
    AIControlPanelWidget .ai-ctrl-row {
        height: auto;
        width: 1fr;
        align-vertical: middle;
        padding: 0 1;
        margin-bottom: 0;
    }
    AIControlPanelWidget .ai-ctrl-label {
        width: 1fr;
        padding-left: 1;
        color: #e6edf7;
    }
    AIControlPanelWidget .ai-ctrl-kill-bar {
        height: auto;
        width: 1fr;
        align-vertical: middle;
        background: #1b1620;
        padding: 0 1;
        margin-bottom: 1;
    }
    AIControlPanelWidget .ai-ctrl-kill-bar.ai-halted {
        background: #3b1219;
    }
    AIControlPanelWidget #ai-ctrl-kill-status {
        width: 1fr;
        text-style: bold;
        color: #f0f6ff;
    }
    AIControlPanelWidget .ai-ctrl-limits-box {
        height: auto;
        width: 1fr;
        background: #131926;
        padding: 0 1;
        margin-bottom: 1;
    }
    AIControlPanelWidget .ai-ctrl-limit-label {
        width: 30;
        color: #c5d4f0;
    }
    AIControlPanelWidget .ai-ctrl-limit-input {
        width: 10;
        margin-right: 1;
    }
    AIControlPanelWidget .ai-ctrl-preset-btn {
        min-width: 5;
        margin-right: 1;
    }
    AIControlPanelWidget #ai-ctrl-kill-label {
        width: 24;
        margin-right: 1;
    }
    AIControlPanelWidget #ai-ctrl-kill-hotkey {
        width: 28;
    }
    AIControlPanelWidget #ai-ctrl-kill-config-collapsible,
    AIControlPanelWidget #ai-ctrl-tools-collapsible {
        margin-top: 1;
    }
    """

    def __init__(
        self,
        *,
        policy_store: AIPolicyStore,
        audit_store: AuditLogStore,
        registry: ReadOnlyToolRegistry | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._policy_store = policy_store
        self._audit_store = audit_store
        self._registry = registry
        self._syncing: bool = False

    def compose(self) -> ComposeResult:
        policy = self._policy_store.load()
        yield Static(
            "AI Control Panel — Read-Only Agent Governance",
            classes="ai-ctrl-title",
            markup=False,
        )
        with Horizontal(id="ai-ctrl-kill-bar", classes="ai-ctrl-kill-bar"):
            yield Static(
                "AI Status: HALTED BY KILL SWITCH"
                if policy.ai_kill_switch_active
                else "AI Status: ACTIVE",
                id="ai-ctrl-kill-status",
                markup=False,
            )
            yield Button(
                "RESUME AI ACTIONS" if policy.ai_kill_switch_active else "HALT ALL AI NOW",
                id="ai-ctrl-kill-btn",
                variant="warning" if policy.ai_kill_switch_active else "error",
                compact=True,
            )
        yield Static(
            "Policy toggles and limits persist immediately and record policy_change audit entries.",
            id="ai-ctrl-status",
            classes="status-bar",
            markup=False,
        )
        with Vertical(classes="ai-ctrl-limits-box"):
            with Horizontal(classes="ai-ctrl-row"):
                yield Static(
                    f"Max Tool Steps ({MIN_TOOL_STEPS}-{MAX_TOOL_STEPS}):",
                    classes="ai-ctrl-limit-label",
                    markup=False,
                )
                yield Input(
                    value=str(policy.max_tool_steps),
                    placeholder=str(policy.max_tool_steps),
                    id="ai-ctrl-max-tool-steps",
                    classes="ai-ctrl-limit-input",
                    compact=True,
                )
                yield Button("25", id="ai-ctrl-preset-steps-25", classes="ai-ctrl-preset-btn", compact=True)
                yield Button("50", id="ai-ctrl-preset-steps-50", classes="ai-ctrl-preset-btn", compact=True)
                yield Button("100", id="ai-ctrl-preset-steps-100", classes="ai-ctrl-preset-btn", compact=True)
                yield Button("250", id="ai-ctrl-preset-steps-250", classes="ai-ctrl-preset-btn", compact=True)
            with Horizontal(classes="ai-ctrl-row"):
                yield Static(
                    f"Max Identical Calls ({MIN_IDENTICAL_TOOL_CALLS}-{MAX_IDENTICAL_TOOL_CALLS}):",
                    classes="ai-ctrl-limit-label",
                    markup=False,
                )
                yield Input(
                    value=str(policy.max_identical_tool_calls),
                    placeholder=str(policy.max_identical_tool_calls),
                    id="ai-ctrl-max-identical-calls",
                    classes="ai-ctrl-limit-input",
                    compact=True,
                )
                yield Static(
                    f"Max Failures ({MIN_SAME_TOOL_FAILURES}-{MAX_SAME_TOOL_FAILURES}):",
                    classes="ai-ctrl-limit-label",
                    markup=False,
                )
                yield Input(
                    value=str(policy.max_same_tool_failures),
                    placeholder=str(policy.max_same_tool_failures),
                    id="ai-ctrl-max-tool-failures",
                    classes="ai-ctrl-limit-input",
                    compact=True,
                )
                yield Button("Save Limits", id="ai-ctrl-save-limits", variant="primary", compact=True)

        for sw_id, field_name, label in _CONTROL_SWITCH_SPECS:
            with Horizontal(classes="ai-ctrl-row"):
                yield Switch(
                    value=bool(getattr(policy, field_name, False)),
                    id=sw_id,
                )
                yield Static(label, classes="ai-ctrl-label", markup=False)

        with Collapsible(
            title="Global Kill Button Configuration",
            collapsed=True,
            id="ai-ctrl-kill-config-collapsible",
        ):
            for sw_id, field_name, label in _KILL_CONFIG_SWITCH_SPECS:
                with Horizontal(classes="ai-ctrl-row"):
                    yield Switch(
                        value=bool(getattr(policy, field_name, False)),
                        id=sw_id,
                    )
                    yield Static(label, classes="ai-ctrl-label", markup=False)
            with Horizontal(classes="ai-ctrl-row"):
                yield Static("Global Kill Hotkey:", classes="ai-ctrl-limit-label", markup=False)
                yield Select(
                    list(_KILL_HOTKEY_OPTIONS),
                    allow_blank=False,
                    value=policy.kill_switch_hotkey,
                    id="ai-ctrl-kill-hotkey",
                    compact=True,
                )
            with Horizontal(classes="ai-ctrl-row"):
                yield Static("Kill Button Label:", classes="ai-ctrl-limit-label", markup=False)
                yield Input(
                    value=policy.kill_switch_label,
                    placeholder=DEFAULT_KILL_SWITCH_LABEL,
                    id="ai-ctrl-kill-label",
                    compact=True,
                )
                yield Button("Save Label", id="ai-ctrl-save-kill-label", variant="primary", compact=True)

        with Collapsible(
            title="Per-Tool Overrides (Read-Only Tools)",
            collapsed=True,
            id="ai-ctrl-tools-collapsible",
        ):
            if self._registry is not None:
                disabled_set = set(policy.disabled_tools)
                for spec in self._registry.list_tools():
                    yield Checkbox(
                        f"{spec.name} [{spec.source_category}]",
                        value=spec.name not in disabled_set,
                        id=f"ai-ctrl-tool-{spec.name}",
                        compact=True,
                    )
            else:
                yield Static("No tool registry attached.", markup=False)

    def on_mount(self) -> None:
        self.sync_from_store()

    def sync_from_store(self) -> None:
        """Synchronize UI switches, limits, kill-switch config, and tool checkboxes."""
        self._syncing = True
        try:
            policy = self._policy_store.load()
            with contextlib.suppress(Exception):
                kill_bar = self.query_one("#ai-ctrl-kill-bar", Horizontal)
                kill_bar.set_class(policy.ai_kill_switch_active, "ai-halted")
            with contextlib.suppress(Exception):
                self.query_one("#ai-ctrl-kill-status", Static).update(
                    "AI Status: HALTED BY KILL SWITCH"
                    if policy.ai_kill_switch_active
                    else "AI Status: ACTIVE"
                )
            with contextlib.suppress(Exception):
                kbtn = self.query_one("#ai-ctrl-kill-btn", Button)
                kbtn.label = (
                    "RESUME AI ACTIONS" if policy.ai_kill_switch_active else "HALT ALL AI NOW"
                )
                kbtn.variant = "warning" if policy.ai_kill_switch_active else "error"

            for inp_id, val_str in (
                ("#ai-ctrl-max-tool-steps", str(policy.max_tool_steps)),
                ("#ai-ctrl-max-identical-calls", str(policy.max_identical_tool_calls)),
                ("#ai-ctrl-max-tool-failures", str(policy.max_same_tool_failures)),
                ("#ai-ctrl-kill-label", policy.kill_switch_label),
            ):
                with contextlib.suppress(Exception):
                    inp = self.query_one(inp_id, Input)
                    with inp.prevent(Input.Changed):
                        inp.value = val_str

            with contextlib.suppress(Exception):
                hsel = self.query_one("#ai-ctrl-kill-hotkey", Select)
                if hsel.value != policy.kill_switch_hotkey:
                    with hsel.prevent(Select.Changed):
                        hsel.value = policy.kill_switch_hotkey

            for sw_id, field_name, _label in (*_CONTROL_SWITCH_SPECS, *_KILL_CONFIG_SWITCH_SPECS):
                with contextlib.suppress(Exception):
                    sw = self.query_one(f"#{sw_id}", Switch)
                    with sw.prevent(Switch.Changed):
                        sw.value = bool(getattr(policy, field_name, False))
            if self._registry is not None:
                disabled_set = set(policy.disabled_tools)
                for spec in self._registry.list_tools():
                    with contextlib.suppress(Exception):
                        cb = self.query_one(f"#ai-ctrl-tool-{spec.name}", Checkbox)
                        with cb.prevent(Checkbox.Changed):
                            cb.value = spec.name not in disabled_set
        finally:
            self._syncing = False

    def _update_status(self, message: str) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#ai-ctrl-status", Static).update(message)

    def _sync_app_kill_ui(self) -> None:
        sync_fn = getattr(self.app, "sync_ai_kill_switch_ui", None)
        if callable(sync_fn):
            with contextlib.suppress(Exception):
                sync_fn()

    def _audit_policy_change(self, field_name: str, reason: str, payload: dict[str, Any]) -> None:
        self._audit_store.append(
            AuditEntry(
                entry_id="",
                timestamp="",
                run_id="control-panel",
                event_key="",
                provider="tui",
                mode="policy",
                event_type="policy_change",
                tool_name=field_name,
                allowed=None,
                reason=reason,
                payload=payload,
            )
        )

    @on(Button.Pressed, "#ai-ctrl-kill-btn")
    def handle_kill_switch_button(self) -> None:
        policy = self._policy_store.load()
        if policy.ai_kill_switch_active:
            resume_fn = getattr(self.app, "resume_ai_actions", None)
            if callable(resume_fn):
                resume_fn(source="control_panel", reason="Resumed from AI Control Panel")
            else:
                self._policy_store.update(ai_kill_switch_active=False)
                self._audit_policy_change(
                    "ai_kill_switch",
                    "AI Kill Switch disengaged in control panel",
                    {"ai_kill_switch_active": False},
                )
                self.sync_from_store()
            self._update_status("AI Kill Switch disengaged — AI actions resumed.")
        else:
            halt_fn = getattr(self.app, "halt_all_ai_actions", None)
            if callable(halt_fn):
                halt_fn(source="control_panel", reason="Halted from AI Control Panel")
            else:
                self._policy_store.update(ai_kill_switch_active=True)
                self._audit_policy_change(
                    "ai_kill_switch",
                    "AI Kill Switch engaged in control panel",
                    {"ai_kill_switch_active": True},
                )
                self.sync_from_store()
            self._update_status("AI KILL SWITCH ENGAGED — all AI actions halted.")

    def _apply_limit_preset(self, steps: int) -> None:
        updated = self._policy_store.update(max_tool_steps=steps)
        self._audit_policy_change(
            "max_tool_steps",
            f"Control panel preset set max_tool_steps={updated.max_tool_steps}",
            {"field": "max_tool_steps", "value": updated.max_tool_steps},
        )
        self.sync_from_store()
        self._update_status(f"Updated max_tool_steps = {updated.max_tool_steps}")

    @on(Button.Pressed, "#ai-ctrl-preset-steps-25")
    def handle_preset_25(self) -> None:
        self._apply_limit_preset(25)

    @on(Button.Pressed, "#ai-ctrl-preset-steps-50")
    def handle_preset_50(self) -> None:
        self._apply_limit_preset(50)

    @on(Button.Pressed, "#ai-ctrl-preset-steps-100")
    def handle_preset_100(self) -> None:
        self._apply_limit_preset(100)

    @on(Button.Pressed, "#ai-ctrl-preset-steps-250")
    def handle_preset_250(self) -> None:
        self._apply_limit_preset(250)

    @on(Button.Pressed, "#ai-ctrl-save-limits")
    @on(Input.Submitted, "#ai-ctrl-max-tool-steps")
    @on(Input.Submitted, "#ai-ctrl-max-identical-calls")
    @on(Input.Submitted, "#ai-ctrl-max-tool-failures")
    def handle_save_limits(self) -> None:
        raw_steps = self.query_one("#ai-ctrl-max-tool-steps", Input).value.strip()
        raw_ident = self.query_one("#ai-ctrl-max-identical-calls", Input).value.strip()
        raw_fail = self.query_one("#ai-ctrl-max-tool-failures", Input).value.strip()
        updates: dict[str, int] = {}
        try:
            if raw_steps:
                updates["max_tool_steps"] = int(raw_steps)
            if raw_ident:
                updates["max_identical_tool_calls"] = int(raw_ident)
            if raw_fail:
                updates["max_same_tool_failures"] = int(raw_fail)
        except ValueError:
            self._update_status("Invalid integer in tool limits; enter whole numbers.")
            return
        if not updates:
            return
        updated = self._policy_store.update(**updates)
        self._audit_policy_change(
            "tool_limits",
            (
                f"Control panel updated limits: max_tool_steps={updated.max_tool_steps}, "
                f"max_identical_tool_calls={updated.max_identical_tool_calls}, "
                f"max_same_tool_failures={updated.max_same_tool_failures}"
            ),
            {
                "max_tool_steps": updated.max_tool_steps,
                "max_identical_tool_calls": updated.max_identical_tool_calls,
                "max_same_tool_failures": updated.max_same_tool_failures,
            },
        )
        self.sync_from_store()
        self._update_status(
            f"Saved tool limits: steps={updated.max_tool_steps}, "
            f"identical={updated.max_identical_tool_calls}, failures={updated.max_same_tool_failures}"
        )

    @on(Select.Changed, "#ai-ctrl-kill-hotkey")
    def handle_kill_hotkey_changed(self, event: Select.Changed) -> None:
        if self._syncing or not self.is_mounted or not isinstance(event.value, str):
            return
        new_hotkey = event.value.strip().lower()
        if not new_hotkey:
            return
        if self._policy_store.load().kill_switch_hotkey == new_hotkey:
            return
        updated = self._policy_store.update(kill_switch_hotkey=new_hotkey)
        self._audit_policy_change(
            "kill_switch_hotkey",
            f"Control panel set kill_switch_hotkey={updated.kill_switch_hotkey}",
            {"field": "kill_switch_hotkey", "value": updated.kill_switch_hotkey},
        )
        self._sync_app_kill_ui()
        self._update_status(f"Updated global kill hotkey: {updated.kill_switch_hotkey}")

    @on(Button.Pressed, "#ai-ctrl-save-kill-label")
    @on(Input.Submitted, "#ai-ctrl-kill-label")
    def handle_save_kill_label(self) -> None:
        raw_label = self.query_one("#ai-ctrl-kill-label", Input).value
        updated = self._policy_store.update(kill_switch_label=raw_label)
        self._audit_policy_change(
            "kill_switch_label",
            f"Control panel set kill_switch_label={updated.kill_switch_label!r}",
            {"field": "kill_switch_label", "value": updated.kill_switch_label},
        )
        self.sync_from_store()
        self._sync_app_kill_ui()
        self._update_status(f"Updated kill button label: {updated.kill_switch_label}")

    @on(Switch.Changed)
    def handle_switch_changed(self, event: Switch.Changed) -> None:
        if self._syncing:
            return
        sw_id = str(event.switch.id or "")
        field_name = _SWITCH_ID_TO_FIELD.get(sw_id)
        if not field_name:
            return
        new_val = bool(event.value)
        self._policy_store.update(**{field_name: new_val})
        self._audit_policy_change(
            field_name,
            f"Control panel set {field_name}={new_val}",
            {"field": field_name, "value": new_val},
        )
        if sw_id.startswith("ai-ctrl-kill-"):
            self._sync_app_kill_ui()
        self._update_status(f"Updated policy: {field_name} = {new_val}")

    @on(Checkbox.Changed)
    def handle_tool_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if self._syncing:
            return
        cb_id = str(event.checkbox.id or "")
        prefix = "ai-ctrl-tool-"
        if not cb_id.startswith(prefix):
            return
        tool_name = cb_id[len(prefix) :]
        if not tool_name:
            return
        policy = self._policy_store.load()
        disabled = list(policy.disabled_tools)
        enabled = bool(event.value)
        if enabled:
            disabled = [name for name in disabled if name != tool_name]
        elif tool_name not in disabled:
            disabled.append(tool_name)
        self._policy_store.update(disabled_tools=disabled)
        self._audit_store.append(
            AuditEntry(
                entry_id="",
                timestamp="",
                run_id="control-panel",
                event_key="",
                provider="tui",
                mode="policy",
                event_type="policy_change",
                tool_name=tool_name,
                allowed=None,
                reason=f"Control panel set tool {tool_name} enabled={enabled}",
                payload={"tool_name": tool_name, "enabled": enabled},
            )
        )
        self._update_status(f"Updated tool policy: {tool_name} enabled = {enabled}")


class AuditLogViewWidget(Vertical):
    """Persistent redacted AI Agent Audit Log viewer with blocked-only filtering."""

    DEFAULT_CSS: ClassVar[str] = """
    AuditLogViewWidget {
        width: 1fr;
        height: 1fr;
        background: #0f131c;
    }
    AuditLogViewWidget .ai-audit-toolbar {
        height: auto;
        width: 1fr;
        background: #161c2a;
        padding: 0 1;
        align-vertical: middle;
    }
    AuditLogViewWidget .ai-audit-title {
        width: 1fr;
        color: #9ec5ff;
        text-style: bold;
    }
    AuditLogViewWidget .ai-audit-filter-label {
        width: auto;
        padding: 0 1;
        color: #e6edf7;
    }
    AuditLogViewWidget #ai-audit-table {
        height: 1fr;
        min-height: 6;
    }
    AuditLogViewWidget #ai-audit-detail {
        height: 1fr;
        min-height: 5;
    }
    """

    def __init__(self, *, audit_store: AuditLogStore, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._audit_store = audit_store
        self._entries: list[AuditEntry] = []

    def compose(self) -> ComposeResult:
        with Horizontal(classes="ai-audit-toolbar"):
            yield Static("AI Agent Audit Log (Redacted)", classes="ai-audit-title", markup=False)
            yield Switch(value=False, id="ai-audit-filter-blocked")
            yield Static("Blocked Only", classes="ai-audit-filter-label", markup=False)
            yield Button("Refresh", id="ai-audit-refresh", variant="primary", compact=True)
        yield DataTable(id="ai-audit-table")
        yield RichLog(
            id="ai-audit-detail",
            highlight=False,
            markup=False,
            wrap=True,
        )

    def on_mount(self) -> None:
        table = self.query_one("#ai-audit-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("Timestamp", key="timestamp")
        table.add_column("Type", key="event_type")
        table.add_column("Provider", key="provider")
        table.add_column("Mode", key="mode")
        table.add_column("Tool", key="tool_name")
        table.add_column("Allowed", key="allowed")
        table.add_column("Event Key", key="event_key")
        table.add_column("Reason", key="reason")
        self.refresh_entries()

    def refresh_entries(self) -> None:
        """Reload entries from ``AuditLogStore`` applying the blocked-only switch."""
        try:
            blocked_only = bool(self.query_one("#ai-audit-filter-blocked", Switch).value)
            table = self.query_one("#ai-audit-table", DataTable)
        except Exception:
            return

        entries = list(reversed(self._audit_store.query(blocked_only=blocked_only, limit=500)))
        self._entries = entries
        table.clear(columns=False)

        for idx, entry in enumerate(entries):
            redacted_provider = str(redact_sensitive_data(entry.provider or "-"))
            redacted_reason = str(redact_sensitive_data(entry.reason or "-"))
            allowed_label = "-" if entry.allowed is None else ("ALLOW" if entry.allowed else "BLOCKED")
            table.add_row(
                entry.timestamp or "-",
                entry.event_type,
                redacted_provider,
                entry.mode or "-",
                entry.tool_name or "-",
                allowed_label,
                entry.event_key or "-",
                redacted_reason,
                key=f"{idx}:{entry.entry_id}",
            )

        if entries:
            with contextlib.suppress(Exception):
                table.move_cursor(row=0)
            self._render_entry_detail(0)
        else:
            with contextlib.suppress(Exception):
                detail = self.query_one("#ai-audit-detail", RichLog)
                detail.clear()
                detail.write("No audit log entries match the current filter.")

    def _render_entry_detail(self, row_index: int) -> None:
        if not (0 <= row_index < len(self._entries)):
            return
        try:
            detail = self.query_one("#ai-audit-detail", RichLog)
        except Exception:
            return
        entry = self._entries[row_index]
        redacted = redact_sensitive_data(entry.to_dict())
        if not isinstance(redacted, dict):
            redacted = {"entry": redacted}
        detail.clear()
        detail.write(
            Text(
                f"[{redacted.get('timestamp', '-')}] {redacted.get('event_type', '-')} "
                f"| tool={redacted.get('tool_name') or '-'} "
                f"| allowed={redacted.get('allowed')} "
                f"| provider={redacted.get('provider') or '-'} "
                f"| mode={redacted.get('mode') or '-'}",
                style="bold cyan",
            )
        )
        detail.write(f"Event Key: {redacted.get('event_key') or '-'}")
        detail.write(f"Run ID: {redacted.get('run_id') or '-'}")
        detail.write(f"Reason: {redacted.get('reason') or '-'}")
        detail.write(json.dumps(redacted.get("payload", {}), indent=2, default=str))

    @on(Button.Pressed, "#ai-audit-refresh")
    def handle_refresh(self) -> None:
        self.refresh_entries()

    @on(Switch.Changed, "#ai-audit-filter-blocked")
    def handle_filter_changed(self) -> None:
        self.refresh_entries()

    @on(DataTable.RowHighlighted, "#ai-audit-table")
    def handle_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._render_entry_detail(event.cursor_row)

    @on(DataTable.RowSelected, "#ai-audit-table")
    def handle_row_selected(self, event: DataTable.RowSelected) -> None:
        self._render_entry_detail(event.cursor_row)


__all__ = [
    "AIControlPanelWidget",
    "AskEventAIModal",
    "AuditLogViewWidget",
    "EventAIPanelWidget",
]
