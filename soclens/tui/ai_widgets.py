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
    TextArea,
)

from soclens.agent_audit import AuditEntry, AuditLogStore, redact_sensitive_data
from soclens.agent_learning import (
    VALID_LEARNING_CATEGORIES,
    SOCLearningEntry,
    SOCLearningManager,
)
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

_LEARNING_MODE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Manual (Default — Stage Pending)", "manual"),
    ("Auto (Opt-In — Auto-Promote)", "auto"),
)

_LEARNING_CATEGORY_OPTIONS: tuple[tuple[str, str], ...] = tuple(
    (cat.replace("_", " ").title(), cat) for cat in VALID_LEARNING_CATEGORIES
)

_KNOWLEDGE_FILTER_OPTIONS: tuple[tuple[str, str], ...] = (
    ("All Entries", "all"),
    ("Pending Queue", "pending"),
    ("Active", "active"),
    ("Base Seed", "base_seed"),
    ("Rolled Back", "rolled_back"),
    ("Blocked", "blocked"),
)

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


class TeachLearnModal(ModalScreen[dict[str, Any] | None]):
    """Editable preview modal for ``/learn``, Teach from This, and Knowledge editing."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    TeachLearnModal {
        align: center middle;
        background: $background 60%;
    }
    #teach-learn-dialog {
        width: 82;
        max-width: 94%;
        height: auto;
        max-height: 88%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #teach-learn-heading {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    .teach-learn-label {
        color: $text-muted;
        margin-top: 0;
    }
    #teach-learn-title,
    #teach-learn-category,
    #teach-learn-tags {
        width: 1fr;
        margin-bottom: 1;
    }
    #teach-learn-content {
        width: 1fr;
        height: 7;
        min-height: 4;
        margin-bottom: 1;
    }
    #teach-learn-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #teach-learn-buttons {
        height: auto;
        align-horizontal: right;
    }
    #teach-learn-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        learning_manager: SOCLearningManager,
        entry_id: str | None = None,
        prefill_title: str = "",
        prefill_content: str = "",
        prefill_category: str = "environment_fact",
        prefill_tags: str = "",
        actor: str = "analyst",
        modal_title: str = "Teach / Learn SOC Knowledge",
    ) -> None:
        super().__init__()
        self._learning_manager = learning_manager
        self._entry_id = entry_id
        self._prefill_title = prefill_title.strip()
        self._prefill_content = prefill_content.strip()
        self._prefill_category = (
            prefill_category
            if prefill_category in VALID_LEARNING_CATEGORIES
            else "environment_fact"
        )
        self._prefill_tags = prefill_tags.strip()
        self._actor = actor or "analyst"
        self._modal_title = modal_title

    def compose(self) -> ComposeResult:
        with Vertical(id="teach-learn-dialog"):
            yield Static(self._modal_title, id="teach-learn-heading", markup=False)
            yield Static("Title:", classes="teach-learn-label", markup=False)
            yield Input(
                value=self._prefill_title,
                placeholder="Short title (e.g. Escalation Contact or Benign Admin Tool)",
                id="teach-learn-title",
                compact=True,
            )
            yield Static("Category:", classes="teach-learn-label", markup=False)
            yield Select(
                list(_LEARNING_CATEGORY_OPTIONS),
                allow_blank=False,
                value=self._prefill_category,
                id="teach-learn-category",
                compact=True,
            )
            yield Static("Tags (comma-separated):", classes="teach-learn-label", markup=False)
            yield Input(
                value=self._prefill_tags,
                placeholder="e.g. escalation, splunk, prod",
                id="teach-learn-tags",
                compact=True,
            )
            yield Static("Knowledge / Playbook Lesson:", classes="teach-learn-label", markup=False)
            yield TextArea(
                text=self._prefill_content,
                id="teach-learn-content",
            )
            yield Static("", id="teach-learn-error", markup=False)
            with Horizontal(id="teach-learn-buttons"):
                yield Button("Cancel", id="teach-learn-cancel", variant="default", compact=True)
                yield Button(
                    "Save Learning",
                    id="teach-learn-save",
                    variant="primary",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        if not self._prefill_title:
            self.query_one("#teach-learn-title", Input).focus()
        else:
            self.query_one("#teach-learn-content", TextArea).focus()

    def _submit_learning(self) -> None:
        title = self.query_one("#teach-learn-title", Input).value.strip()
        cat_val = self.query_one("#teach-learn-category", Select).value
        category = str(cat_val) if isinstance(cat_val, str) and cat_val else "environment_fact"
        raw_tags = self.query_one("#teach-learn-tags", Input).value
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
        content = self.query_one("#teach-learn-content", TextArea).text.strip()
        err_widget = self.query_one("#teach-learn-error", Static)
        if not content:
            err_widget.update("Please enter the learning content before saving.")
            self.query_one("#teach-learn-content", TextArea).focus()
            return
        try:
            if self._entry_id:
                saved = self._learning_manager.edit_entry(
                    self._entry_id,
                    title=title or content.splitlines()[0][:80],
                    content=content,
                    category=category,
                    tags=tags,
                    actor=self._actor,
                )
            else:
                saved = self._learning_manager.submit_manual_learn(
                    title=title or content.splitlines()[0][:80],
                    content=content,
                    category=category,
                    tags=tags,
                    actor=self._actor,
                )
        except (ValueError, KeyError) as exc:
            err_widget.update(str(exc))
            return
        self.dismiss(saved.to_dict())

    @on(Button.Pressed, "#teach-learn-save")
    def handle_save(self) -> None:
        self._submit_learning()

    @on(Button.Pressed, "#teach-learn-cancel")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        """Dismiss the Teach/Learn modal without saving."""
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

    class TeachRequested(Message):
        """Posted when the analyst clicks Teach / Learn on the per-event AI panel."""

        def __init__(
            self,
            panel: EventAIPanelWidget,
            event: UniqueEvent | None,
            *,
            prefill_title: str = "",
            prefill_content: str = "",
        ) -> None:
            self.panel: EventAIPanelWidget = panel
            self.event: UniqueEvent | None = event
            self.prefill_title: str = prefill_title
            self.prefill_content: str = prefill_content
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
            teach_btn = Button("Teach / Learn", id="btn-ai-teach-event", compact=True)
            teach_btn.tooltip = "Teach / Learn from This"
            yield teach_btn
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

    @on(Button.Pressed, "#btn-ai-teach-event")
    def handle_teach_button(self, event: Button.Pressed) -> None:
        event.stop()
        ev = self._current_event
        ev_title = str(getattr(ev, "title", "") or getattr(ev, "event_key", "") or "SOC Event Lesson").strip()
        prefill_parts: list[str] = []
        if self._entries:
            latest = self._entries[-1]
            if latest.answer_markdown:
                prefill_parts.append(latest.answer_markdown.strip()[:800])
            elif latest.question:
                prefill_parts.append(latest.question.strip())
        elif ev is not None and getattr(ev, "summary", None):
            prefill_parts.append(str(getattr(ev, "summary", "")).strip())
        self.post_message(
            self.TeachRequested(
                self,
                ev,
                prefill_title=ev_title[:80],
                prefill_content="\n\n".join(prefill_parts),
            )
        )


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
    AIControlPanelWidget #ai-ctrl-learning-mode {
        width: 38;
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
            with Horizontal(classes="ai-ctrl-row"):
                yield Static(
                    "Self-Learning Mode:",
                    classes="ai-ctrl-limit-label",
                    markup=False,
                )
                yield Select(
                    list(_LEARNING_MODE_OPTIONS),
                    allow_blank=False,
                    value=getattr(policy, "learning_mode", "manual"),
                    id="ai-ctrl-learning-mode",
                    compact=True,
                )

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

            with contextlib.suppress(Exception):
                lsel = self.query_one("#ai-ctrl-learning-mode", Select)
                target_lm = getattr(policy, "learning_mode", "manual")
                if lsel.value != target_lm:
                    with lsel.prevent(Select.Changed):
                        lsel.value = target_lm

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

    @on(Select.Changed, "#ai-ctrl-learning-mode")
    def handle_learning_mode_changed(self, event: Select.Changed) -> None:
        if self._syncing or not self.is_mounted or not isinstance(event.value, str):
            return
        new_mode = event.value.strip().lower()
        if new_mode not in {"manual", "auto"}:
            return
        if getattr(self._policy_store.load(), "learning_mode", "manual") == new_mode:
            return
        updated = self._policy_store.update(learning_mode=new_mode)
        self._audit_policy_change(
            "learning_mode",
            f"Control panel set learning_mode={updated.learning_mode}",
            {"field": "learning_mode", "value": updated.learning_mode},
        )
        self._update_status(f"Updated self-learning mode: {updated.learning_mode}")

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


class KnowledgeManagerWidget(Vertical):
    """Manage Pending Learnings Queue, Base Info seeding, pinning, edits, and rollback."""

    DEFAULT_CSS: ClassVar[str] = """
    KnowledgeManagerWidget {
        width: 1fr;
        height: 1fr;
        background: #0f131c;
    }
    KnowledgeManagerWidget .ai-know-toolbar {
        height: auto;
        width: 1fr;
        background: #161c2a;
        padding: 0 1;
        align-vertical: middle;
    }
    KnowledgeManagerWidget #ai-know-status-filter {
        width: 24;
        margin-right: 1;
    }
    KnowledgeManagerWidget #ai-know-search {
        width: 1fr;
        margin-right: 1;
    }
    KnowledgeManagerWidget .ai-know-toolbar Button {
        margin-left: 1;
    }
    KnowledgeManagerWidget .ai-know-actions {
        height: auto;
        width: 1fr;
        background: #131926;
        padding: 0 1;
        align-vertical: middle;
    }
    KnowledgeManagerWidget .ai-know-actions Button {
        margin-right: 1;
    }
    KnowledgeManagerWidget #ai-know-table {
        height: 1fr;
        min-height: 6;
    }
    KnowledgeManagerWidget #ai-know-detail {
        height: 9;
        min-height: 4;
        background: #0d111a;
        border-top: solid #2e3c5c;
    }
    """

    def __init__(
        self,
        *,
        learning_manager: SOCLearningManager,
        audit_store: AuditLogStore | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._learning_manager = learning_manager
        self._audit_store = audit_store
        self._entries: list[SOCLearningEntry] = []

    def rebind_learning_manager(
        self,
        learning_manager: SOCLearningManager,
        audit_store: AuditLogStore | None = None,
    ) -> None:
        """Update the backing ``SOCLearningManager`` and refresh displayed rows."""
        self._learning_manager = learning_manager
        if audit_store is not None:
            self._audit_store = audit_store
        self.refresh_entries()

    def compose(self) -> ComposeResult:
        with Horizontal(classes="ai-know-toolbar"):
            yield Select(
                list(_KNOWLEDGE_FILTER_OPTIONS),
                allow_blank=False,
                value="all",
                id="ai-know-status-filter",
                compact=True,
            )
            yield Input(
                placeholder="Filter by keyword, tag, or source...",
                id="ai-know-search",
                compact=True,
            )
            yield Button("Refresh", id="ai-know-refresh-btn", compact=True)
            yield Button("+ Teach", id="ai-know-add-btn", variant="primary", compact=True)
            yield Button("Seed / Reload Base Info", id="ai-know-reload-base-btn", compact=True)
        yield Static(
            "Knowledge & Pending Queue ready.",
            id="ai-know-status",
            classes="status-bar",
            markup=False,
        )
        yield DataTable(id="ai-know-table")
        with Horizontal(classes="ai-know-actions"):
            yield Button("Approve", id="ai-know-approve-btn", variant="success", compact=True)
            yield Button("Edit", id="ai-know-edit-btn", compact=True)
            yield Button("Reject", id="ai-know-reject-btn", variant="warning", compact=True)
            yield Button("Pin / Unpin", id="ai-know-pin-btn", compact=True)
            yield Button("Rollback", id="ai-know-rollback-btn", compact=True)
            yield Button("Delete", id="ai-know-delete-btn", variant="error", compact=True)
        yield RichLog(
            id="ai-know-detail",
            highlight=False,
            markup=False,
            wrap=True,
        )

    def on_mount(self) -> None:
        table = self.query_one("#ai-know-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("ID", key="id")
        table.add_column("Status", key="status")
        table.add_column("Source", key="source")
        table.add_column("Category", key="category")
        table.add_column("Title", key="title")
        table.add_column("Conf", key="conf")
        table.add_column("Seen", key="seen")
        table.add_column("Pin", key="pinned")
        self.refresh_entries()

    def _selected_entry(self) -> SOCLearningEntry | None:
        try:
            table = self.query_one("#ai-know-table", DataTable)
        except Exception:
            return None
        row_idx = int(table.cursor_row)
        if 0 <= row_idx < len(self._entries):
            return self._entries[row_idx]
        return None

    def _set_status(self, message: str) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#ai-know-status", Static).update(message)

    def _notify_audit_sibling(self) -> None:
        with contextlib.suppress(Exception):
            self.app.query_one(AuditLogViewWidget).refresh_entries()

    def refresh_entries(self) -> None:
        """Reload entries from ``SOCLearningManager`` matching filter/search controls."""
        try:
            flt_raw = self.query_one("#ai-know-status-filter", Select).value
            flt = str(flt_raw) if isinstance(flt_raw, str) else "all"
            search_q = self.query_one("#ai-know-search", Input).value.strip().lower()
            table = self.query_one("#ai-know-table", DataTable)
        except Exception:
            return

        if flt == "base_seed":
            entries = self._learning_manager.list_entries(source="base_seed", limit=300)
        elif flt in {"pending", "active", "rolled_back", "blocked"}:
            entries = self._learning_manager.list_entries(status=flt, limit=300)
        else:
            entries = self._learning_manager.list_entries(limit=300)

        if search_q:
            entries = [
                e
                for e in entries
                if search_q in f"{e.id} {e.title} {e.content} {e.category} {e.source} {' '.join(e.tags)}".lower()
            ]

        self._entries = entries
        table.clear(columns=False)
        for idx, entry in enumerate(entries):
            table.add_row(
                entry.id[:12],
                entry.status,
                entry.source,
                entry.category,
                entry.title[:50],
                f"{entry.confidence:.2f}",
                str(entry.seen_count),
                "PIN" if entry.pinned else "-",
                key=f"{idx}:{entry.id}",
            )

        all_pending = len(self._learning_manager.list_entries(status="pending", limit=300))
        mode = self._learning_manager.get_learning_mode()
        self._set_status(
            f"Showing {len(entries)} knowledge entries | Pending Queue: {all_pending} | Mode: {mode}"
        )

        if entries:
            with contextlib.suppress(Exception):
                table.move_cursor(row=0)
            self._render_detail(0)
        else:
            with contextlib.suppress(Exception):
                detail = self.query_one("#ai-know-detail", RichLog)
                detail.clear()
                detail.write("No SOC knowledge entries match the active filter.")

    def _render_detail(self, row_index: int) -> None:
        if not (0 <= row_index < len(self._entries)):
            return
        try:
            detail = self.query_one("#ai-know-detail", RichLog)
        except Exception:
            return
        entry = self._entries[row_index]
        detail.clear()
        detail.write(
            Text(
                f"[{entry.status.upper()}] {entry.title} "
                f"(id={entry.id}, source={entry.source}, category={entry.category}, "
                f"conf={entry.confidence:.2f}, seen={entry.seen_count}, uses={entry.use_count}, "
                f"pinned={entry.pinned})",
                style="bold cyan",
            )
        )
        if entry.tags:
            detail.write(f"Tags: {', '.join(entry.tags)}")
        detail.write(str(redact_sensitive_data(entry.content, preserve_env_var_refs=True)))
        revisions = self._learning_manager.get_revisions(entry.id)
        if revisions:
            rev_summary = ", ".join(
                f"r{r['revision_no']}:{r['action']}({r['new_status']})"
                for r in revisions[:5]
            )
            detail.write(f"Revisions: {rev_summary}")

    @on(Select.Changed, "#ai-know-status-filter")
    def handle_filter_changed(self) -> None:
        self.refresh_entries()

    @on(Input.Changed, "#ai-know-search")
    @on(Input.Submitted, "#ai-know-search")
    def handle_search_changed(self) -> None:
        self.refresh_entries()

    @on(Button.Pressed, "#ai-know-refresh-btn")
    def handle_refresh_btn(self) -> None:
        self.refresh_entries()

    @on(Button.Pressed, "#ai-know-reload-base-btn")
    def handle_reload_base(self) -> None:
        ws_dir = getattr(self.app, "workspace_dir", None)
        loaded = self._learning_manager.load_base_knowledge(ws_dir)
        self.refresh_entries()
        self._notify_audit_sibling()
        self._set_status(f"Base Info reloaded ({len(loaded)} base_seed entries synced).")

    @on(Button.Pressed, "#ai-know-add-btn")
    def handle_add_btn(self) -> None:
        modal = TeachLearnModal(learning_manager=self._learning_manager)

        def _after(saved: dict[str, Any] | None) -> None:
            if saved is not None:
                self.refresh_entries()
                self._notify_audit_sibling()
                self._set_status(f"Saved active learning: {saved.get('title', '')}")

        self.app.push_screen(modal, _after)

    @on(Button.Pressed, "#ai-know-approve-btn")
    def handle_approve_btn(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            self._set_status("Select a knowledge entry first.")
            return
        try:
            updated = self._learning_manager.approve_entry(entry.id)
        except KeyError as exc:
            self.refresh_entries()
            self._set_status(f"Entry unavailable ({exc}); list refreshed.")
            return
        self.refresh_entries()
        self._notify_audit_sibling()
        self._set_status(f"Approved entry '{updated.title}' -> active.")

    @on(Button.Pressed, "#ai-know-edit-btn")
    def handle_edit_btn(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            self._set_status("Select a knowledge entry first.")
            return
        modal = TeachLearnModal(
            learning_manager=self._learning_manager,
            entry_id=entry.id,
            prefill_title=entry.title,
            prefill_content=entry.content,
            prefill_category=entry.category,
            prefill_tags=", ".join(entry.tags),
            modal_title=f"Edit SOC Knowledge ({entry.id[:8]})",
        )

        def _after(saved: dict[str, Any] | None) -> None:
            if saved is not None:
                self.refresh_entries()
                self._notify_audit_sibling()
                self._set_status(f"Updated learning '{saved.get('title', '')}'.")

        self.app.push_screen(modal, _after)

    @on(Button.Pressed, "#ai-know-reject-btn")
    def handle_reject_btn(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            self._set_status("Select a pending entry to reject.")
            return
        try:
            deleted = self._learning_manager.delete_entry(entry.id)
        except KeyError as exc:
            self.refresh_entries()
            self._set_status(f"Entry unavailable ({exc}); list refreshed.")
            return
        self.refresh_entries()
        self._notify_audit_sibling()
        if not deleted:
            self._set_status(f"Entry '{entry.title}' was already removed; list refreshed.")
        else:
            self._set_status(f"Rejected and removed entry '{entry.title}'.")

    @on(Button.Pressed, "#ai-know-pin-btn")
    def handle_pin_btn(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            self._set_status("Select a knowledge entry to pin/unpin.")
            return
        try:
            updated = self._learning_manager.pin_entry(entry.id, not entry.pinned)
        except KeyError as exc:
            self.refresh_entries()
            self._set_status(f"Entry unavailable ({exc}); list refreshed.")
            return
        self.refresh_entries()
        self._notify_audit_sibling()
        self._set_status(
            f"{'Pinned' if updated.pinned else 'Unpinned'} entry '{updated.title}'."
        )

    @on(Button.Pressed, "#ai-know-rollback-btn")
    def handle_rollback_btn(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            self._set_status("Select a knowledge entry to roll back.")
            return
        try:
            updated = self._learning_manager.rollback_entry(entry.id)
        except KeyError as exc:
            self.refresh_entries()
            self._set_status(f"Entry unavailable ({exc}); list refreshed.")
            return
        self.refresh_entries()
        self._notify_audit_sibling()
        self._set_status(f"Rolled back entry '{updated.title}' (status={updated.status}).")

    @on(Button.Pressed, "#ai-know-delete-btn")
    def handle_delete_btn(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            self._set_status("Select a knowledge entry to delete.")
            return
        try:
            deleted = self._learning_manager.delete_entry(entry.id)
        except KeyError as exc:
            self.refresh_entries()
            self._set_status(f"Entry unavailable ({exc}); list refreshed.")
            return
        self.refresh_entries()
        self._notify_audit_sibling()
        if not deleted:
            self._set_status(f"Entry '{entry.title}' was already removed; list refreshed.")
        else:
            self._set_status(f"Deleted entry '{entry.title}'.")

    @on(DataTable.RowHighlighted, "#ai-know-table")
    def handle_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._render_detail(event.cursor_row)

    @on(DataTable.RowSelected, "#ai-know-table")
    def handle_row_selected(self, event: DataTable.RowSelected) -> None:
        self._render_detail(event.cursor_row)


__all__ = [
    "AIControlPanelWidget",
    "AskEventAIModal",
    "AuditLogViewWidget",
    "EventAIPanelWidget",
    "KnowledgeManagerWidget",
    "TeachLearnModal",
]
