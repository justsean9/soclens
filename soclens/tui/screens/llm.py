"""AI Analyst pane supporting Local LLMs (Ollama/OpenAI) and Microsoft Copilot multi-agent chats."""

from __future__ import annotations

import contextlib
import os
import threading
from dataclasses import dataclass, field
from typing import Any, ClassVar

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Input, RichLog, Select, Static, TabbedContent, TabPane

from soclens.agent_audit import AuditLogStore
from soclens.agent_learning import SOCLearningManager
from soclens.agent_orchestrator import SocAgentOrchestrator
from soclens.agent_policy import AIPolicyStore, evaluate_tool_permission
from soclens.agent_tools import ReadOnlyToolRegistry, build_default_readonly_registry
from soclens.config import (
    COPILOT_LLM_PROVIDERS,
    DEFAULT_COPILOT_DIRECTLINE_URL,
    DEFAULT_GEMINI_BASE_URL,
    DEFAULT_M365_COPILOT_GRAPH_URL,
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OPENAI_BASE_URL,
    PivotPayload,
    get_local_llm_config,
    has_rf_ssl_config_override,
)
from soclens.llm import SOC_PROMPT_TEMPLATES, LocalLLMClient, LocalLLMError
from soclens.tui.ai_widgets import (
    AIControlPanelWidget,
    AuditLogViewWidget,
    KnowledgeManagerWidget,
    TeachLearnModal,
)
from soclens.tui.pivot import format_copilot_context
from soclens.tui.screens.base import BaseSocPane, SelectableRichLog, extract_richlog_text

_MANUAL_MODEL_VALUE = "__manual__"

_PROVIDER_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Ollama", "ollama"),
    ("OpenAI-Compatible", "openai"),
    ("Google Gemini API", "gemini"),
    ("M365 Copilot Chat", "m365_copilot"),
    ("Copilot Studio (Direct-to-Engine)", "copilot_studio"),
    ("Copilot Studio (Direct Line)", "copilot_directline"),
    ("Security Copilot", "security_copilot"),
)

_PROVIDER_SHORT_LABELS: dict[str, str] = {
    "ollama": "Ollama",
    "openai": "OpenAI",
    "gemini": "Gemini",
    "m365_copilot": "M365 Copilot",
    "copilot_studio": "Copilot Studio D2E",
    "copilot_directline": "Copilot Direct Line",
    "security_copilot": "Security Copilot",
}

_DEFAULT_GEMINI_MODELS: tuple[str, ...] = (
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
)

_VALID_PROVIDERS: frozenset[str] = frozenset(_PROVIDER_SHORT_LABELS.keys())

_TEMPLATE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Freeform", "freeform"),
    ("Attack-Chain Summary", "summarize_attack_chain"),
    ("Draft Closing Note", "draft_closing_note"),
    ("Explain Sigma/SPL", "explain_sigma"),
    ("Triage RF Alert", "triage_alert"),
    ("IOC Summary", "summarize_ioc"),
    ("SPL Helper", "spl_helper"),
)


@dataclass
class _ChatSession:
    """Independent state for a single chat window inside the AI Analyst pane."""

    session_id: str
    index: int
    provider: str = "ollama"
    base_url: str = DEFAULT_OLLAMA_BASE_URL
    model: str | None = None
    template: str = "freeform"
    history: list[dict[str, str]] = field(default_factory=list)
    transcript: list[str | Text] = field(default_factory=list)
    attached_title: str | None = None
    attached_context: str | None = None
    attached_payload: PivotPayload | None = None
    last_reply: str = ""
    remote_conversation_id: str | None = None
    remote_conversation_token: str | None = None
    remote_watermark: str | None = None
    tools_enabled: bool = True
    stop_event: threading.Event | None = None
    busy: bool = False

    def display_label(self) -> str:
        short = _PROVIDER_SHORT_LABELS.get(self.provider, self.provider)
        target = (self.model or "").strip()
        suffix = f" ({target})" if target and target.lower() != short.lower() else ""
        busy_mark = " ●" if self.busy else ""
        return f"Chat {self.index}: {short}{suffix}{busy_mark}"


def _default_url_for_provider(provider: str) -> str:
    cfg = get_local_llm_config(provider=provider)
    if provider == "openai":
        return DEFAULT_OPENAI_BASE_URL
    if provider == "gemini":
        return cfg.base_url or DEFAULT_GEMINI_BASE_URL
    if provider in ("m365_copilot", "security_copilot"):
        return cfg.ms_graph_base_url or DEFAULT_M365_COPILOT_GRAPH_URL
    if provider == "copilot_studio":
        return cfg.ms_token_endpoint or ""
    if provider == "copilot_directline":
        return cfg.ms_token_endpoint or cfg.ms_directline_url or DEFAULT_COPILOT_DIRECTLINE_URL
    return DEFAULT_OLLAMA_BASE_URL


def _default_agent_label_for_provider(provider: str) -> str:
    if provider == "m365_copilot":
        return "M365 Copilot Chat"
    if provider in ("copilot_studio", "copilot_directline"):
        return "Copilot Studio Agent"
    if provider == "security_copilot":
        return "Security Copilot"
    return ""


class LocalLLMPane(BaseSocPane):
    """Interactive AI Analyst pane with Local LLMs, Microsoft Copilot agents, and multi-chat tabs."""

    DEFAULT_CSS: ClassVar[str] = """
    LocalLLMPane #llm-subtabs {
        width: 1fr;
        height: 1fr;
    }
    LocalLLMPane #llm-tab-chat,
    LocalLLMPane #llm-tab-control-panel,
    LocalLLMPane #llm-tab-audit-log,
    LocalLLMPane #llm-tab-knowledge {
        width: 1fr;
        height: 1fr;
        padding: 0;
    }
    LocalLLMPane #llm-transcript {
        min-height: 5 !important;
    }
    LocalLLMPane #llm-session-bar {
        height: 1;
        width: 1fr;
    }
    LocalLLMPane #llm-copilot-bar {
        height: 1;
        width: 1fr;
    }
    LocalLLMPane.llm-compact #llm-session-select {
        width: 24;
    }
    LocalLLMPane.llm-compact #llm-provider-select {
        width: 16;
    }
    LocalLLMPane.llm-compact #llm-model-select {
        width: 18;
    }
    LocalLLMPane.llm-compact #llm-template-select {
        width: 18;
    }
    LocalLLMPane.llm-short #llm-status {
        height: 1 !important;
        min-height: 1 !important;
    }
    LocalLLMPane.llm-short #llm-transcript {
        min-height: 3 !important;
    }
    """

    STATUS_ID = "llm-status"
    LOG_ID = ""
    LOG_SOURCE = "llm"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        cfg = get_local_llm_config()
        self._session_counter = 1
        initial = _ChatSession(
            session_id="chat-1",
            index=1,
            provider=cfg.provider,
            base_url=cfg.base_url,
            model=cfg.model,
            template="freeform",
        )
        self._sessions: dict[str, _ChatSession] = {initial.session_id: initial}
        self._active_session_id: str = initial.session_id
        self._available_models: list[str] = []

    @property
    def _active_session(self) -> _ChatSession:
        return self._sessions[self._active_session_id]

    @property
    def _history(self) -> list[dict[str, str]]:
        return self._active_session.history

    @property
    def _attached_title(self) -> str | None:
        return self._active_session.attached_title

    @_attached_title.setter
    def _attached_title(self, value: str | None) -> None:
        self._active_session.attached_title = value

    @property
    def _attached_context(self) -> str | None:
        return self._active_session.attached_context

    @_attached_context.setter
    def _attached_context(self, value: str | None) -> None:
        self._active_session.attached_context = value

    @property
    def _attached_payload(self) -> PivotPayload | None:
        return self._active_session.attached_payload

    @_attached_payload.setter
    def _attached_payload(self, value: PivotPayload | None) -> None:
        self._active_session.attached_payload = value

    @property
    def _last_reply(self) -> str:
        return self._active_session.last_reply

    @_last_reply.setter
    def _last_reply(self, value: str) -> None:
        self._active_session.last_reply = value

    @property
    def _active_stop_event(self) -> threading.Event | None:
        return self._active_session.stop_event

    @_active_stop_event.setter
    def _active_stop_event(self, value: threading.Event | None) -> None:
        self._active_session.stop_event = value

    def _model_options_for_provider(
        self, provider: str, current_model: str | None = None
    ) -> tuple[list[tuple[str, str]], str]:
        cfg = get_local_llm_config(provider=provider)
        candidates: list[str] = []
        if provider in COPILOT_LLM_PROVIDERS:
            for preset in cfg.agent_presets:
                if preset.provider == provider and preset.name not in candidates:
                    candidates.append(preset.name)
            default_label = _default_agent_label_for_provider(provider)
            if default_label and default_label not in candidates:
                candidates.insert(0, default_label)
        elif provider == "gemini":
            for m in self._available_models:
                if m not in candidates:
                    candidates.append(m)
            for m in _DEFAULT_GEMINI_MODELS:
                if m not in candidates:
                    candidates.append(m)
        else:
            for m in self._available_models:
                if m not in candidates:
                    candidates.append(m)
        if current_model and current_model not in candidates:
            candidates.insert(0, current_model)

        options: list[tuple[str, str]] = [(c, c) for c in candidates]
        options.append(("(Manual / Custom)", _MANUAL_MODEL_VALUE))
        if current_model and current_model in candidates:
            selected = current_model
        elif provider in (*COPILOT_LLM_PROVIDERS, "gemini") and candidates:
            selected = candidates[0]
        else:
            selected = _MANUAL_MODEL_VALUE
        return options, selected

    @staticmethod
    def _visible_provider_options(
        visible_providers: tuple[str, ...] | None = None,
        *,
        ensure_provider: str | None = None,
    ) -> list[tuple[str, str]]:
        allowed = (
            visible_providers
            if visible_providers is not None
            else get_local_llm_config().visible_providers
        )
        if not allowed:
            return list(_PROVIDER_OPTIONS)
        opts = [(label, key) for label, key in _PROVIDER_OPTIONS if key in allowed]
        if ensure_provider and not any(key == ensure_provider for _, key in opts):
            for label, key in _PROVIDER_OPTIONS:
                if key == ensure_provider:
                    opts.append((label, key))
                    break
        return opts or list(_PROVIDER_OPTIONS)

    def compose(self) -> ComposeResult:
        cfg = get_local_llm_config()
        self._active_session.provider = cfg.provider
        self._active_session.base_url = cfg.base_url
        self._active_session.model = cfg.model

        provider_options = self._visible_provider_options(
            cfg.visible_providers, ensure_provider=cfg.provider
        )
        model_options, initial_model_select = self._model_options_for_provider(
            cfg.provider, cfg.model
        )
        session_options = [(s.display_label(), s.session_id) for s in self._sessions.values()]

        yield Static(
            "AI Analyst (Local LLM, Gemini API & Microsoft Copilot Multi-Agent)",
            classes="pane-title",
            markup=False,
        )
        yield Static(
            f"Ready ({cfg.provider} @ {cfg.base_url}). Open multiple chats or ask a question.",
            id="llm-status",
            classes="status-bar",
            markup=False,
        )

        policy_store, audit_store, registry = self._resolve_ai_stores()

        with TabbedContent(initial="llm-tab-chat", id="llm-subtabs"):
            with TabPane("AI Chat", id="llm-tab-chat"):
                with Horizontal(id="llm-session-bar", classes="action-row toolbar-row"):
                    yield Select(
                        session_options,
                        allow_blank=False,
                        value=self._active_session_id,
                        id="llm-session-select",
                        compact=True,
                    )
                    yield Button("+ New Chat", id="llm-new-chat-btn", variant="primary", compact=True)
                    yield Button("Close Chat", id="llm-close-chat-btn", compact=True)
                    yield Button("Tools: ON", id="llm-tools-toggle-btn", variant="success", compact=True)

                with Horizontal(classes="action-row toolbar-row"):
                    yield Select(
                        provider_options,
                        allow_blank=False,
                        value=cfg.provider,
                        id="llm-provider-select",
                        compact=True,
                    )
                    yield Input(
                        value=cfg.base_url,
                        placeholder="Base URL or Copilot Token Endpoint",
                        id="llm-base-url-input",
                        compact=True,
                    )
                    yield Button("Check Connection", id="llm-check-btn", compact=True)
                    yield Button("Refresh Models", id="llm-refresh-models-btn", compact=True)

                with Horizontal(classes="action-row filter-bar"):
                    yield Select(
                        model_options,
                        allow_blank=False,
                        value=initial_model_select,
                        id="llm-model-select",
                        compact=True,
                    )
                    yield Input(
                        value=cfg.model or "",
                        placeholder="Model or Copilot Agent name (e.g. llama3.2, SOC Triage Agent)",
                        id="llm-model-input",
                        compact=True,
                    )
                    yield Select(
                        list(_TEMPLATE_OPTIONS),
                        allow_blank=False,
                        value="freeform",
                        id="llm-template-select",
                        compact=True,
                    )

                with Horizontal(id="llm-copilot-bar", classes="action-row toolbar-row"):
                    yield Button("Attack Chain", id="llm-attack-chain-btn", compact=True)
                    yield Button("Closing Note", id="llm-closing-note-btn", compact=True)
                    yield Button("Copy Reply", id="llm-copy-reply-btn", compact=True)
                    yield Button("Detach Ctx", id="llm-clear-context-btn", compact=True)
                    teach_chat_btn = Button("Teach / Learn", id="llm-teach-btn", compact=True)
                    teach_chat_btn.tooltip = "Teach / Learn from This"
                    yield teach_chat_btn

                yield Static("", id="llm-context-badge", classes="rf-summary-bar", markup=False)
                yield SelectableRichLog(
                    id="llm-transcript",
                    classes="primary-log",
                    highlight=False,
                    markup=False,
                    wrap=True,
                )

                with Horizontal(classes="action-row toolbar-row"):
                    yield Input(
                        placeholder="Ask the AI analyst or add instructions for attached context...",
                        id="llm-prompt",
                        compact=True,
                    )
                    yield Button("Send", id="llm-send-btn", variant="primary", compact=True)
                    yield Button("Stop", id="llm-stop-btn", variant="warning", compact=True)
                    yield Button("Clear", id="llm-clear-btn", compact=True)

            with TabPane("AI Control Panel", id="llm-tab-control-panel"):
                yield AIControlPanelWidget(
                    policy_store=policy_store,
                    audit_store=audit_store,
                    registry=registry,
                    id="llm-ai-control-panel",
                )

            with TabPane("Audit Log", id="llm-tab-audit-log"):
                yield AuditLogViewWidget(
                    audit_store=audit_store,
                    id="llm-ai-audit-log",
                )

            with TabPane("Knowledge & Learning", id="llm-tab-knowledge"):
                yield KnowledgeManagerWidget(
                    learning_manager=self._resolve_learning_manager(),
                    audit_store=audit_store,
                    id="llm-knowledge-manager",
                )

    def _resolve_ai_stores(self) -> tuple[AIPolicyStore, AuditLogStore, Any]:
        policy_store = getattr(self.app, "ai_policy_store", None)
        audit_store = getattr(self.app, "ai_audit_store", None)
        registry = getattr(self.app, "ai_tool_registry", None)
        storage = getattr(self.app, "storage", None)
        cache_dir = self.workspace_dir / ".soclens_cache"
        if not isinstance(policy_store, AIPolicyStore):
            policy_store = AIPolicyStore(path=cache_dir / "ai_policy.json", storage=storage)
        if not isinstance(audit_store, AuditLogStore):
            audit_store = AuditLogStore(path=cache_dir / "ai_audit.jsonl", storage=storage)
        return policy_store, audit_store, registry

    def _resolve_learning_manager(self) -> SOCLearningManager:
        existing = getattr(self.app, "learning_manager", None)
        if isinstance(existing, SOCLearningManager):
            return existing
        policy_store, audit_store, _registry = self._resolve_ai_stores()
        storage = getattr(self.app, "storage", None)
        return SOCLearningManager(
            storage=storage,
            workspace_dir=self.workspace_dir,
            policy_store=policy_store,
            audit_store=audit_store,
        )

    def _resolve_orchestrator(self) -> SocAgentOrchestrator:
        existing = getattr(self.app, "ai_orchestrator", None)
        if isinstance(existing, SocAgentOrchestrator):
            return existing
        policy_store, audit_store, registry = self._resolve_ai_stores()
        storage = getattr(self.app, "storage", None)
        eff_registry = (
            registry
            if isinstance(registry, ReadOnlyToolRegistry)
            else build_default_readonly_registry(storage=storage)
        )
        return SocAgentOrchestrator(
            registry=eff_registry,
            policy_store=policy_store,
            audit_store=audit_store,
            storage=storage,
            learning_manager=self._resolve_learning_manager,
        )

    def _sync_tools_toggle_button(self, enabled: bool) -> None:
        try:
            btn = self.query_one("#llm-tools-toggle-btn", Button)
            btn.label = "Tools: ON" if enabled else "Tools: OFF"
            btn.variant = "success" if enabled else "default"
        except Exception:
            pass

    @on(Button.Pressed, "#llm-tools-toggle-btn")
    def handle_toggle_tools(self) -> None:
        sess = self._active_session
        sess.tools_enabled = not sess.tools_enabled
        self._sync_tools_toggle_button(sess.tools_enabled)
        if sess.tools_enabled:
            policy_store, _audit_store, registry = self._resolve_ai_stores()
            policy = policy_store.load()
            permitted_cnt = 0
            if isinstance(registry, ReadOnlyToolRegistry):
                specs = registry.list_tools()
                names = {s.name for s in specs}
                permitted_cnt = sum(
                    1
                    for s in specs
                    if evaluate_tool_permission(
                        s.name,
                        s.source_category,
                        s.readonly,
                        "full_investigation",
                        policy,
                        registered_tools=names,
                    ).allowed
                )
            self.set_status(
                f"Freeform read-only SOC tools enabled for Chat {sess.index} "
                f"({permitted_cnt} tool(s) permitted by AI Control Panel)."
            )
        else:
            self.set_status(
                f"Freeform tools disabled for Chat {sess.index} (chat-only mode)."
            )

    def on_mount(self) -> None:
        self._sync_compact_class()
        badge = self.query_one("#llm-context-badge", Static)
        badge.display = False

    def on_tab_activated(self) -> None:
        self._sync_compact_class()
        self._sync_subtab_views()

    def _sync_subtab_views(self, active_tab_id: str | None = None) -> None:
        target = active_tab_id
        if target is None:
            with contextlib.suppress(Exception):
                target = str(self.query_one("#llm-subtabs", TabbedContent).active or "")
        if target == "llm-tab-control-panel":
            with contextlib.suppress(Exception):
                self.query_one(AIControlPanelWidget).sync_from_store()
        elif target == "llm-tab-audit-log":
            with contextlib.suppress(Exception):
                self.query_one(AuditLogViewWidget).refresh_entries()
        elif target == "llm-tab-knowledge":
            with contextlib.suppress(Exception):
                self.query_one(KnowledgeManagerWidget).refresh_entries()

    @on(TabbedContent.TabActivated, "#llm-subtabs")
    def handle_subtab_activated(self, event: TabbedContent.TabActivated) -> None:
        if event.pane is not None:
            self._sync_subtab_views(str(event.pane.id or ""))

    def on_resize(self) -> None:
        self._sync_compact_class()

    def sync_responsive_layout(
        self,
        width: int | None = None,
        height: int | None = None,
    ) -> None:
        self._sync_compact_class(width=width, height=height)

    def _sync_compact_class(
        self,
        width: int | None = None,
        height: int | None = None,
    ) -> None:
        try:
            w = int(self.size.width if width is None else width)
            h = int(self.size.height if height is None else height)
            self.set_class(w < 96, "llm-compact")
            self.set_class(h <= 26, "llm-short")
        except Exception:
            pass

    def _refresh_session_select(self) -> None:
        try:
            sel = self.query_one("#llm-session-select", Select)
            options = [(s.display_label(), s.session_id) for s in self._sessions.values()]
            with sel.prevent(Select.Changed):
                sel.set_options(options)
                sel.value = self._active_session_id
        except Exception:
            pass

    def _save_active_session_controls(self) -> None:
        sess = self._active_session
        try:
            sess.provider = self._current_provider()
            sess.base_url = self._current_base_url()
            sess.model = self._resolve_model()
            sess.template = self._current_template()
        except Exception:
            pass

    def _load_session_into_ui(self, sess: _ChatSession) -> None:
        prov_sel = self.query_one("#llm-provider-select", Select)
        url_inp = self.query_one("#llm-base-url-input", Input)
        model_sel = self.query_one("#llm-model-select", Select)
        model_inp = self.query_one("#llm-model-input", Input)
        tpl_sel = self.query_one("#llm-template-select", Select)
        badge = self.query_one("#llm-context-badge", Static)
        log = self.query_one("#llm-transcript", RichLog)

        with prov_sel.prevent(Select.Changed):
            prov_sel.set_options(
                self._visible_provider_options(ensure_provider=sess.provider)
            )
            prov_sel.value = sess.provider
        with url_inp.prevent(Input.Changed):
            url_inp.value = sess.base_url

        options, selected_model = self._model_options_for_provider(sess.provider, sess.model)
        with model_sel.prevent(Select.Changed):
            model_sel.set_options(options)
            model_sel.value = selected_model
        with model_inp.prevent(Input.Changed):
            model_inp.value = sess.model or ""

        with tpl_sel.prevent(Select.Changed):
            tpl_sel.value = sess.template if sess.template in SOC_PROMPT_TEMPLATES else "freeform"

        self._sync_tools_toggle_button(sess.tools_enabled)

        if sess.attached_context:
            tpl_label = SOC_PROMPT_TEMPLATES.get(sess.template, SOC_PROMPT_TEMPLATES["freeform"])[
                "label"
            ]
            badge.update(
                f"Attached Context: {sess.attached_title or 'Context'} "
                f"({len(sess.attached_context)} chars) | Template: {tpl_label}"
            )
            badge.display = True
        else:
            badge.update("")
            badge.display = False

        log.clear()
        for entry in sess.transcript:
            log.write(entry)

    def create_new_chat(
        self,
        *,
        provider: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
    ) -> str:
        """Create and activate a new independent chat window."""
        self._save_active_session_controls()
        self._session_counter += 1
        cfg = get_local_llm_config(provider=provider) if provider else get_local_llm_config()
        eff_provider = provider if provider in _VALID_PROVIDERS else cfg.provider
        eff_base_url = base_url if base_url is not None else _default_url_for_provider(eff_provider)
        eff_model = model if model is not None else (
            _default_agent_label_for_provider(eff_provider)
            if eff_provider in COPILOT_LLM_PROVIDERS
            else cfg.model
        )
        sid = f"chat-{self._session_counter}"
        sess = _ChatSession(
            session_id=sid,
            index=self._session_counter,
            provider=eff_provider,
            base_url=eff_base_url,
            model=eff_model,
            template="freeform",
        )
        self._sessions[sid] = sess
        self._active_session_id = sid
        self._load_session_into_ui(sess)
        self._refresh_session_select()
        self.set_status(
            f"Opened {sess.display_label()} ({len(self._sessions)} chat window(s) open)."
        )
        try:
            self.query_one("#llm-prompt", Input).focus()
        except Exception:
            pass
        return sid

    @on(Button.Pressed, "#llm-new-chat-btn")
    def handle_new_chat(self) -> None:
        self.create_new_chat()

    @on(Button.Pressed, "#llm-close-chat-btn")
    def handle_close_chat(self) -> None:
        if len(self._sessions) <= 1:
            self.set_status("At least one chat window must remain open (use Clear to reset it).")
            return
        closing = self._active_session
        if closing.stop_event is not None and not closing.stop_event.is_set():
            closing.stop_event.set()
        del self._sessions[closing.session_id]
        next_sid = next(iter(self._sessions))
        self._active_session_id = next_sid
        self._load_session_into_ui(self._active_session)
        self._refresh_session_select()
        self.set_status(
            f"Closed Chat {closing.index}. Switched to {self._active_session.display_label()}."
        )

    @on(Select.Changed, "#llm-session-select")
    def handle_session_changed(self, event: Select.Changed) -> None:
        if not isinstance(event.value, str) or event.value not in self._sessions:
            return
        if event.value == self._active_session_id:
            return
        self._save_active_session_controls()
        self._active_session_id = event.value
        self._load_session_into_ui(self._active_session)
        self._refresh_session_select()
        self.set_status(f"Switched to {self._active_session.display_label()}.")

    def on_settings_updated(self) -> None:
        cfg = get_local_llm_config()
        try:
            prov_sel = self.query_one("#llm-provider-select", Select)
            allowed = cfg.visible_providers
            if allowed and self._active_session.provider not in allowed:
                new_prov = allowed[0]
                self._active_session.provider = new_prov
                self._active_session.base_url = _default_url_for_provider(new_prov)
                self._active_session.remote_conversation_id = None
                self._active_session.remote_conversation_token = None
                self._active_session.remote_watermark = None
                self._load_session_into_ui(self._active_session)
                self._refresh_session_select()
            else:
                opts = self._visible_provider_options(
                    allowed, ensure_provider=self._active_session.provider
                )
                with prov_sel.prevent(Select.Changed):
                    prov_sel.set_options(opts)
                    prov_sel.value = self._active_session.provider
            model_input = self.query_one("#llm-model-input", Input)
            if not model_input.value.strip() and cfg.model:
                with model_input.prevent(Input.Changed):
                    model_input.value = cfg.model
        except Exception:
            pass
        if self._active_stop_event is None or self._active_stop_event.is_set():
            self.set_status(f"Settings reloaded ({cfg.provider} @ {cfg.base_url}).")
        with contextlib.suppress(Exception):
            self.query_one(AIControlPanelWidget).sync_from_store()
        with contextlib.suppress(Exception):
            self.query_one(AuditLogViewWidget).refresh_entries()
        with contextlib.suppress(Exception):
            _pol, audit_store, _reg = self._resolve_ai_stores()
            self.query_one(KnowledgeManagerWidget).rebind_learning_manager(
                self._resolve_learning_manager(),
                audit_store=audit_store,
            )

    def _current_provider(self) -> str:
        val = self.query_one("#llm-provider-select", Select).value
        if isinstance(val, str) and val in _VALID_PROVIDERS:
            return val
        return "ollama"

    def _current_base_url(self) -> str:
        raw = self.query_one("#llm-base-url-input", Input).value.strip()
        if raw:
            return raw
        return _default_url_for_provider(self._current_provider())

    def _current_template(self) -> str:
        val = self.query_one("#llm-template-select", Select).value
        if isinstance(val, str) and val in SOC_PROMPT_TEMPLATES:
            return val
        return "freeform"

    def _resolve_model(self) -> str | None:
        manual = self.query_one("#llm-model-input", Input).value.strip()
        if manual:
            return manual
        selected = self.query_one("#llm-model-select", Select).value
        if isinstance(selected, str) and selected and selected != _MANUAL_MODEL_VALUE:
            return selected
        return None

    def _build_client(
        self,
        *,
        provider: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        conversation_id: str | None = None,
        conversation_token: str | None = None,
        watermark: str | None = None,
        stop_event: threading.Event | None = None,
    ) -> LocalLLMClient:
        eff_provider = provider if provider is not None else self._current_provider()
        eff_base_url = base_url if base_url is not None else self._current_base_url()
        eff_model = model if model is not None else self._resolve_model()
        app_make_stop = getattr(self.app, "_make_ai_stop_event", None)
        if callable(app_make_stop):
            eff_stop = app_make_stop(stop_event)
        else:
            app_stop = getattr(self.app, "_stop_event", None)
            eff_stop = stop_event
            if eff_stop is None and isinstance(app_stop, threading.Event):
                eff_stop = app_stop

        verify_ssl: bool | str | None = None
        if not (os.environ.get("RF_LLM_VERIFY_SSL") or "").strip():
            app_ssl_override = getattr(self.app, "_verify_ssl_override", None)
            if app_ssl_override is not None or has_rf_ssl_config_override():
                get_ssl_fn = getattr(self.app, "get_effective_verify_ssl", None)
                if callable(get_ssl_fn):
                    eff_ssl = get_ssl_fn()
                    if isinstance(eff_ssl, (bool, str)):
                        verify_ssl = eff_ssl

        kwargs: dict[str, Any] = {
            "provider": eff_provider,
            "base_url": eff_base_url,
            "model": eff_model,
            "verify_ssl": verify_ssl,
            "stop_event": eff_stop,
        }
        if conversation_id:
            kwargs["conversation_id"] = conversation_id
        if conversation_token:
            kwargs["conversation_token"] = conversation_token
        if watermark:
            kwargs["watermark"] = watermark
        return LocalLLMClient(**kwargs)

    def _write_transcript(
        self, text: str | Text, *, session_id: str | None = None
    ) -> None:
        target_sid = session_id or self._active_session_id

        def _apply() -> None:
            sess = self._sessions.get(target_sid)
            if sess is not None:
                sess.transcript.append(text)
            if target_sid != self._active_session_id:
                return
            try:
                log = self.query_one("#llm-transcript", RichLog)
                log.write(text)
            except Exception:
                pass

        self.run_on_ui(_apply)

    def _apply_models_list(self, models: list[str]) -> None:
        self._available_models = list(models)
        select = self.query_one("#llm-model-select", Select)
        manual_input = self.query_one("#llm-model-input", Input)
        options: list[tuple[str, str]] = [(m, m) for m in models]
        options.append(("(Manual / Custom)", _MANUAL_MODEL_VALUE))
        current_manual = manual_input.value.strip()
        with select.prevent(Select.Changed):
            select.set_options(options)
            if current_manual and current_manual in models:
                select.value = current_manual
            elif models and not current_manual:
                select.value = models[0]
            else:
                select.value = _MANUAL_MODEL_VALUE
        if models and not current_manual:
            with manual_input.prevent(Input.Changed):
                manual_input.value = models[0]
        self._active_session.model = self._resolve_model()
        self._refresh_session_select()

    @on(Select.Changed, "#llm-provider-select")
    def handle_provider_changed(self, event: Select.Changed) -> None:
        if not isinstance(event.value, str) or event.value not in _VALID_PROVIDERS:
            return
        new_provider = event.value
        url_input = self.query_one("#llm-base-url-input", Input)
        default_urls = {
            "",
            DEFAULT_OLLAMA_BASE_URL,
            DEFAULT_OPENAI_BASE_URL,
            DEFAULT_GEMINI_BASE_URL,
            DEFAULT_M365_COPILOT_GRAPH_URL,
            DEFAULT_COPILOT_DIRECTLINE_URL,
        }
        current = url_input.value.strip().rstrip("/")
        if current in default_urls or self._active_session.provider != new_provider:
            with url_input.prevent(Input.Changed):
                url_input.value = _default_url_for_provider(new_provider)

        self._active_session.provider = new_provider
        self._active_session.base_url = url_input.value.strip()
        self._active_session.remote_conversation_id = None
        self._active_session.remote_conversation_token = None
        self._active_session.remote_watermark = None

        options, selected = self._model_options_for_provider(new_provider)
        model_sel = self.query_one("#llm-model-select", Select)
        model_inp = self.query_one("#llm-model-input", Input)
        with model_sel.prevent(Select.Changed):
            model_sel.set_options(options)
            model_sel.value = selected
        if new_provider in (*COPILOT_LLM_PROVIDERS, "gemini"):
            with model_inp.prevent(Input.Changed):
                model_inp.value = "" if selected == _MANUAL_MODEL_VALUE else selected
        self._active_session.model = self._resolve_model()
        self._refresh_session_select()

    @on(Select.Changed, "#llm-model-select")
    def handle_model_select_changed(self, event: Select.Changed) -> None:
        if isinstance(event.value, str) and event.value != _MANUAL_MODEL_VALUE:
            manual_input = self.query_one("#llm-model-input", Input)
            with manual_input.prevent(Input.Changed):
                manual_input.value = event.value
            self._active_session.model = event.value
            self._active_session.remote_conversation_id = None
            self._active_session.remote_conversation_token = None
            self._active_session.remote_watermark = None
            self._refresh_session_select()

    def accept_pivot(self, payload: PivotPayload) -> None:
        """Pre-attach bundled [ES + Tenant + S1 + RF] context ready to send (auto_send=False)."""
        self._attached_payload = payload
        title, content = format_copilot_context(payload)
        if payload.es_finding or payload.s1_threat:
            default_tpl = "summarize_attack_chain"
        elif payload.rf_enrichment:
            default_tpl = "summarize_ioc"
        else:
            default_tpl = "triage_alert"
        self.analyze_context(title, content, template=default_tpl, auto_send=False)

    def analyze_context(
        self,
        title: str,
        content: str,
        template: str = "freeform",
        auto_send: bool = False,
    ) -> None:
        """Attach SOC context (e.g. Sigma rule or alert) to the active chat window."""
        clean_title = title.strip() or "Attached Context"
        self._attached_title = clean_title
        self._attached_context = content

        tpl_key = template if template in SOC_PROMPT_TEMPLATES else "freeform"
        self._active_session.template = tpl_key
        tpl_sel = self.query_one("#llm-template-select", Select)
        with tpl_sel.prevent(Select.Changed):
            tpl_sel.value = tpl_key

        badge = self.query_one("#llm-context-badge", Static)
        badge.update(
            f"Attached Context: {clean_title} ({len(content)} chars) | Template: {SOC_PROMPT_TEMPLATES[tpl_key]['label']}"
        )
        badge.display = True

        header = Text()
        header.append("[CONTEXT ATTACHED] ", style="bold cyan")
        header.append(f"{clean_title} ({len(content)} chars, template={tpl_key})")
        self._write_transcript(header)
        self.set_status(
            f"Loaded context '{clean_title}' ({len(content)} chars) into {self._active_session.display_label()}. Click Send, Attack Chain, or Closing Note."
        )
        self.record_app_log(f"Loaded LLM context: {clean_title} (template={tpl_key})")

        if auto_send:
            self.handle_send()

    def _clear_attached_context(self) -> None:
        self._attached_title = None
        self._attached_context = None
        self._attached_payload = None
        try:
            badge = self.query_one("#llm-context-badge", Static)
            badge.update("")
            badge.display = False
        except Exception:
            pass

    def _run_copilot_template(self, template_key: str) -> None:
        tpl_key = template_key if template_key in SOC_PROMPT_TEMPLATES else "freeform"
        self._active_session.template = tpl_key
        tpl_sel = self.query_one("#llm-template-select", Select)
        with tpl_sel.prevent(Select.Changed):
            tpl_sel.value = tpl_key

        prompt_input = self.query_one("#llm-prompt", Input)
        if not self._attached_context and not prompt_input.value.strip():
            if self._history:
                recent = "\n".join(
                    f"{msg.get('role', 'user').upper()}: {msg.get('content', '')}"
                    for msg in self._history[-6:]
                    if msg.get("content")
                ).strip()
                if recent:
                    with prompt_input.prevent(Input.Changed):
                        prompt_input.value = recent
            if not prompt_input.value.strip():
                self.set_status(
                    "Attach ES/S1/RF context or enter details in the prompt box first."
                )
                prompt_input.focus()
                return
        self.handle_send()

    @on(Button.Pressed, "#llm-attack-chain-btn")
    def handle_attack_chain(self) -> None:
        self._run_copilot_template("summarize_attack_chain")

    @on(Button.Pressed, "#llm-closing-note-btn")
    def handle_closing_note(self) -> None:
        self._run_copilot_template("draft_closing_note")

    @on(Button.Pressed, "#llm-copy-reply-btn")
    def handle_copy_reply(self) -> None:
        text = self._last_reply.strip()
        if not text:
            try:
                text = extract_richlog_text(self.query_one("#llm-transcript", RichLog))
            except Exception:
                text = ""
        self.copy_to_clipboard(text, label="AI Response")

    @on(Button.Pressed, "#llm-clear-context-btn")
    def handle_clear_context(self) -> None:
        self._clear_attached_context()
        self.set_status("Detached context (transcript preserved).")

    @on(Button.Pressed, "#llm-check-btn")
    def handle_check_connection(self) -> None:
        provider = self._current_provider()
        base_url = self._current_base_url()
        model = self._resolve_model()
        self._check_connection_worker(provider=provider, base_url=base_url, model=model)

    @work(thread=True, exit_on_error=False)
    def _check_connection_worker(
        self,
        *,
        provider: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
    ) -> None:
        try:
            self.set_status(f"Checking {provider or 'AI'} connection...")
            with self.log_scope("llm"):
                with self._build_client(
                    provider=provider, base_url=base_url, model=model
                ) as client:
                    result = client.check_connection()
            if result.get("ok"):
                models = list(result.get("models") or [])
                self.run_on_ui(self._apply_models_list, models)
                msg = (
                    f"Connected to {result['provider']} ({result['base_url']}): "
                    f"{len(models)} model/agent(s) available."
                )
                self.set_status(msg)
                self.record_app_log(msg)
                self.notify_user(msg, title="AI Analyst Connected")
            else:
                err = str(result.get("error") or "Connection failed")
                msg = f"AI endpoint unreachable ({result['provider']} @ {result['base_url']}): {err}"
                self.set_status(msg)
                self.record_app_log(msg, level="WARNING")
                self.notify_user(err, title="AI Connection Failed", severity="warning")
        except Exception as exc:
            self.report_error("AI Connection Check", exc)

    @on(Button.Pressed, "#llm-refresh-models-btn")
    def handle_refresh_models(self) -> None:
        provider = self._current_provider()
        base_url = self._current_base_url()
        model = self._resolve_model()
        self._refresh_models_worker(provider=provider, base_url=base_url, model=model)

    @work(thread=True, exit_on_error=False)
    def _refresh_models_worker(
        self,
        *,
        provider: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
    ) -> None:
        eff_provider = provider or "ollama"
        try:
            self.set_status(f"Refreshing models/agents from {eff_provider}...")
            with self.log_scope("llm"):
                with self._build_client(
                    provider=eff_provider, base_url=base_url, model=model
                ) as client:
                    models = client.list_models()
            self.run_on_ui(self._apply_models_list, models)
            msg = f"Loaded {len(models)} model(s) from {eff_provider}."
            self.set_status(msg)
            self.record_app_log(msg)
        except Exception as exc:
            self.report_error("Refresh Models / Agents", exc)

    def _open_teach_modal(
        self,
        *,
        prefill_title: str = "",
        prefill_content: str = "",
        session_id: str | None = None,
    ) -> None:
        lm = self._resolve_learning_manager()
        modal = TeachLearnModal(
            learning_manager=lm,
            prefill_title=prefill_title,
            prefill_content=prefill_content,
            modal_title="Teach / Learn SOC Knowledge",
        )

        def _after(saved: dict[str, Any] | None) -> None:
            if saved is None or self.is_app_shutting_down():
                return
            saved_title = str(saved.get("title") or "")
            self.set_status(f"Saved active SOC learning: {saved_title}")
            if session_id:
                note = Text()
                note.append("[Learned] ", style="bold green")
                note.append(f"Saved active knowledge entry: {saved_title}")
                self._write_transcript(note, session_id=session_id)
            with contextlib.suppress(Exception):
                self.query_one(KnowledgeManagerWidget).refresh_entries()
            with contextlib.suppress(Exception):
                self.query_one(AuditLogViewWidget).refresh_entries()

        self.app.push_screen(modal, _after)

    @on(Button.Pressed, "#llm-teach-btn")
    def handle_teach_button(self) -> None:
        sess = self._active_session
        content = (sess.last_reply or "").strip()
        if not content:
            for msg in reversed(sess.history):
                if msg.get("role") == "assistant" and msg.get("content", "").strip():
                    content = msg["content"].strip()
                    break
        if not content and sess.attached_context:
            content = sess.attached_context.strip()[:800]
        title = (sess.attached_title or "AI Chat Lesson").strip()[:80]
        self._open_teach_modal(
            prefill_title=title,
            prefill_content=content[:1200],
            session_id=sess.session_id,
        )

    @on(Input.Submitted, "#llm-prompt")
    def handle_prompt_submitted(self) -> None:
        self.handle_send()

    @on(Button.Pressed, "#llm-send-btn")
    def handle_send(self) -> None:
        prompt_input = self.query_one("#llm-prompt", Input)
        user_prompt = prompt_input.value.strip()
        sess = self._active_session
        session_id = sess.session_id

        # Intercept /learn <lesson> BEFORE kill-switch/model checks & worker launch
        lower_prompt = user_prompt.lower()
        if lower_prompt == "/learn" or (
            lower_prompt.startswith("/learn")
            and len(user_prompt) > 6
            and user_prompt[6].isspace()
        ):
            lesson = user_prompt[6:].strip()
            if not lesson:
                self.set_status("Usage: /learn <lesson text>")
                return
            with prompt_input.prevent(Input.Changed):
                prompt_input.value = ""
            first_line = lesson.splitlines()[0].strip()
            self._open_teach_modal(
                prefill_title=first_line[:80],
                prefill_content=lesson,
                session_id=session_id,
            )
            return

        is_killed_fn = getattr(self.app, "is_ai_killed", None)
        policy_store, _audit_store, _registry = self._resolve_ai_stores()
        if (callable(is_killed_fn) and is_killed_fn()) or policy_store.load().ai_kill_switch_active:
            msg = "AI Kill Switch is active — all AI actions are halted. Resume AI to send prompts."
            self.set_status(msg)
            self._write_transcript(Text(f"[Blocked: {msg}]", style="bold red"), session_id=session_id)
            self.notify_user(msg, title="AI Halted", severity="warning")
            return
        attached_ctx = sess.attached_context
        attached_title = sess.attached_title
        template_key = self._current_template()
        provider = self._current_provider()
        base_url = self._current_base_url()
        model = self._resolve_model()
        if not model and provider in COPILOT_LLM_PROVIDERS:
            model = _default_agent_label_for_provider(provider)
        history_snapshot = list(sess.history)
        remote_conv_id = sess.remote_conversation_id
        remote_conv_token = sess.remote_conversation_token
        remote_watermark = sess.remote_watermark
        tools_enabled = sess.tools_enabled

        if not user_prompt and not attached_ctx:
            self.set_status("Enter a prompt or attach context before sending.")
            return
        if not model:
            self.set_status("Specify a model name or click Refresh Models first.")
            self.notify_user(
                "No model selected. Enter a model name or click Refresh Models.",
                title="AI Analyst",
                severity="warning",
            )
            return

        sess.provider = provider
        sess.base_url = base_url
        sess.model = model
        sess.template = template_key

        if sess.stop_event is not None:
            sess.stop_event.set()
        stop_event = threading.Event()
        sess.stop_event = stop_event
        sess.busy = True
        self._refresh_session_select()

        with prompt_input.prevent(Input.Changed):
            prompt_input.value = ""

        user_header = Text()
        user_header.append("You: ", style="bold green")
        if attached_ctx and user_prompt:
            user_header.append(f"[{attached_title or 'Context'}] {user_prompt}")
        elif attached_ctx:
            user_header.append(
                f"[{SOC_PROMPT_TEMPLATES[template_key]['label']}] Analyze {attached_title or 'attached context'}"
            )
        else:
            user_header.append(user_prompt)
        self._write_transcript(user_header, session_id=session_id)

        self._send_chat_worker(
            session_id=session_id,
            user_prompt=user_prompt,
            attached_ctx=attached_ctx,
            attached_title=attached_title,
            template_key=template_key,
            provider=provider,
            base_url=base_url,
            model=model,
            history_snapshot=history_snapshot,
            remote_conversation_id=remote_conv_id,
            remote_conversation_token=remote_conv_token,
            remote_watermark=remote_watermark,
            tools_enabled=tools_enabled,
            stop_event=stop_event,
        )

    @work(thread=True, exit_on_error=False)
    def _send_chat_worker(
        self,
        *,
        session_id: str,
        user_prompt: str,
        attached_ctx: str | None,
        attached_title: str | None = None,
        template_key: str,
        provider: str | None = None,
        base_url: str | None = None,
        model: str,
        history_snapshot: list[dict[str, str]] | None = None,
        remote_conversation_id: str | None = None,
        remote_conversation_token: str | None = None,
        remote_watermark: str | None = None,
        tools_enabled: bool = True,
        stop_event: threading.Event,
    ) -> None:
        eff_provider = provider or "ollama"
        try:
            if session_id == self._active_session_id:
                self.set_status(f"Querying {eff_provider} ({model})...")
            updated_freeform_pair: list[dict[str, str]] | None = None
            tool_call_count = 0

            def _on_tool_event(ev: dict[str, Any]) -> None:
                kind = str(ev.get("kind") or "")
                tname = str(ev.get("tool_name") or "")
                if kind == "tool_start":
                    if session_id == self._active_session_id:
                        self.set_status(
                            f"Running read-only tool: {tname} (step {ev.get('step', '?')})..."
                        )
                elif kind == "tool_result":
                    line = Text()
                    line.append(f"[Tool {ev.get('step', '?')}] ", style="bold cyan")
                    line.append(tname)
                    if ev.get("ok"):
                        line.append(" -> OK", style="green")
                    else:
                        line.append(f" -> ERROR: {ev.get('error', '')}", style="red")
                    self._write_transcript(line, session_id=session_id)
                elif kind == "tool_blocked":
                    line = Text()
                    line.append("[Tool Blocked] ", style="bold yellow")
                    line.append(
                        f"{tname} ({ev.get('rule', 'blocked')}): {ev.get('reason', '')}",
                        style="yellow",
                    )
                    self._write_transcript(line, session_id=session_id)

            with self.log_scope("llm"):
                with self._build_client(
                    provider=eff_provider,
                    base_url=base_url,
                    model=model,
                    conversation_id=remote_conversation_id,
                    conversation_token=remote_conversation_token,
                    watermark=remote_watermark,
                    stop_event=stop_event,
                ) as client:
                    if template_key != "freeform":
                        target_content = attached_ctx if attached_ctx is not None else user_prompt
                        extra_instr = user_prompt if attached_ctx is not None else ""
                        result = client.analyze_with_template(
                            template_key,
                            target_content,
                            extra_instruction=extra_instr,
                            model=model,
                        )
                    else:
                        orchestrator = self._resolve_orchestrator()
                        chat_res = orchestrator.chat(
                            user_prompt=user_prompt,
                            history=history_snapshot,
                            attached_context=attached_ctx,
                            attached_title=attached_title,
                            session_id=session_id,
                            client=client,
                            provider=eff_provider,
                            model=model,
                            enable_tools=tools_enabled,
                            stop_event=stop_event,
                            tool_event_callback=_on_tool_event,
                        )
                        if chat_res.status == "cancelled":
                            raise LocalLLMError("AI request cancelled by user.", provider=eff_provider)
                        if chat_res.status == "error":
                            raise LocalLLMError(
                                chat_res.error or "Freeform chat failed.",
                                provider=eff_provider,
                            )
                        tool_call_count = len(chat_res.tool_calls)
                        result = {
                            "content": chat_res.content,
                            "model": chat_res.model or model,
                            "provider": chat_res.provider or eff_provider,
                            "conversation_id": chat_res.conversation_id,
                            "conversation_token": chat_res.conversation_token,
                            "watermark": chat_res.watermark,
                            "done": chat_res.done,
                        }
                        history_user_text = user_prompt or f"Analyze {attached_title or 'attached context'}"
                        updated_freeform_pair = [
                            {"role": "user", "content": history_user_text},
                            {"role": "assistant", "content": str(chat_res.content or "")},
                        ]

            reply = str(result.get("content") or "").strip()
            resp_model = str(result.get("model") or model)
            new_conv_id = result.get("conversation_id")
            new_conv_token = result.get("conversation_token")
            new_watermark = result.get("watermark")

            def _record_reply() -> None:
                target = self._sessions.get(session_id)
                if target is None:
                    return
                target.last_reply = reply
                target.busy = False
                if isinstance(new_conv_id, str) and new_conv_id.strip():
                    target.remote_conversation_id = new_conv_id.strip()
                if isinstance(new_conv_token, str) and new_conv_token.strip():
                    target.remote_conversation_token = new_conv_token.strip()
                if isinstance(new_watermark, str) and new_watermark.strip():
                    target.remote_watermark = new_watermark.strip()
                if updated_freeform_pair is not None:
                    target.history.extend(updated_freeform_pair)
                self._refresh_session_select()
                with contextlib.suppress(Exception):
                    self.query_one(AuditLogViewWidget).refresh_entries()

            self.run_on_ui(_record_reply)
            header = Text()
            header.append(f"Assistant ({resp_model}):", style="bold magenta")
            self._write_transcript(header, session_id=session_id)
            self._write_transcript(reply or "(Empty response)", session_id=session_id)
            self._write_transcript("", session_id=session_id)

            tool_suffix = f" [{tool_call_count} tool call(s)]" if tool_call_count else ""
            status_msg = f"Response received from {result.get('provider')} ({resp_model}){tool_suffix}."
            if session_id == self._active_session_id:
                self.set_status(status_msg)
            else:
                sess_obj = self._sessions.get(session_id)
                label = sess_obj.display_label() if sess_obj else session_id
                self.notify_user(f"Reply ready in {label}", title="AI Analyst")
            self.record_app_log(status_msg)
        except LocalLLMError as exc:
            def _clear_busy() -> None:
                target = self._sessions.get(session_id)
                if target is not None:
                    target.busy = False
                self._refresh_session_select()

            self.run_on_ui(_clear_busy)
            if "cancelled" in str(exc).lower():
                if session_id == self._active_session_id:
                    self.set_status("AI request stopped.")
                self._write_transcript(Text("[Stopped by user]", style="yellow"), session_id=session_id)
                return
            self.report_error("AI Chat", exc)
        except Exception as exc:
            def _clear_busy_exc() -> None:
                target = self._sessions.get(session_id)
                if target is not None:
                    target.busy = False
                self._refresh_session_select()

            self.run_on_ui(_clear_busy_exc)
            self.report_error("AI Chat", exc)

    def halt_all_sessions(self) -> int:
        """Immediately halt all active chat sessions across every open tab."""
        stopped = 0
        for sid, sess in self._sessions.items():
            was_busy = sess.busy or (
                sess.stop_event is not None and not sess.stop_event.is_set()
            )
            if sess.stop_event is not None and not sess.stop_event.is_set():
                sess.stop_event.set()
            if was_busy:
                stopped += 1
                self._write_transcript(
                    Text("[HALTED BY AI KILL SWITCH]", style="bold red"),
                    session_id=sid,
                )
            sess.busy = False
        self._refresh_session_select()
        if stopped:
            self.set_status(f"Halted {stopped} active AI chat session(s) via Kill Switch.")
        else:
            self.set_status("AI Kill Switch active — all chat sessions halted.")
        return stopped

    @on(Button.Pressed, "#llm-stop-btn")
    def handle_stop(self) -> None:
        if self._active_stop_event is not None and not self._active_stop_event.is_set():
            self._active_stop_event.set()
            self.set_status("Stopping active AI request...")
        else:
            self.set_status("No active AI request to stop.")

    @on(Button.Pressed, "#llm-clear-btn")
    def handle_clear(self) -> None:
        sess = self._active_session
        sess.history.clear()
        sess.transcript.clear()
        sess.last_reply = ""
        sess.remote_conversation_id = None
        sess.remote_conversation_token = None
        sess.remote_watermark = None
        self._clear_attached_context()
        try:
            self.query_one("#llm-transcript", RichLog).clear()
        except Exception:
            pass
        self.set_status(f"Cleared transcript and conversation state for {sess.display_label()}.")
