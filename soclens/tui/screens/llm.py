"""Local LLM (Ollama & OpenAI-compatible) interactive analyst pane."""

from __future__ import annotations

import threading
from typing import Any

from rich.text import Text
from textual import events, on, work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Input, RichLog, Select, Static

from soclens.config import (
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OPENAI_BASE_URL,
    get_local_llm_config,
)
from soclens.llm import SOC_PROMPT_TEMPLATES, LocalLLMClient, LocalLLMError
from soclens.tui.screens.base import BaseSocPane

_MANUAL_MODEL_VALUE = "__manual__"

_PROVIDER_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Ollama", "ollama"),
    ("OpenAI-Compatible", "openai"),
)

_TEMPLATE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Freeform", "freeform"),
    ("Explain Sigma/SPL", "explain_sigma"),
    ("Triage RF Alert", "triage_alert"),
    ("IOC Summary", "summarize_ioc"),
    ("SPL Helper", "spl_helper"),
)


class LocalLLMPane(BaseSocPane):
    """Interactive Local LLM chat and SOC template analysis pane."""

    STATUS_ID = "llm-status"
    LOG_ID = ""
    LOG_SOURCE = "llm"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._history: list[dict[str, str]] = []
        self._attached_title: str | None = None
        self._attached_context: str | None = None
        self._active_stop_event: threading.Event | None = None
        self._available_models: list[str] = []

    def compose(self) -> ComposeResult:
        cfg = get_local_llm_config()
        model_options: list[tuple[str, str]] = []
        if cfg.model:
            model_options.append((cfg.model, cfg.model))
        model_options.append(("(Manual / Custom)", _MANUAL_MODEL_VALUE))
        initial_model_select = cfg.model if cfg.model else _MANUAL_MODEL_VALUE

        yield Static("Local LLM Analyst (Ollama & OpenAI-Compatible)", classes="pane-title")
        yield Static(
            f"Ready ({cfg.provider} @ {cfg.base_url}). Refresh models or ask a question.",
            id="llm-status",
            classes="status-bar",
            markup=False,
        )

        with Horizontal(classes="action-row toolbar-row"):
            yield Select(
                list(_PROVIDER_OPTIONS),
                allow_blank=False,
                value=cfg.provider,
                id="llm-provider-select",
                compact=True,
            )
            yield Input(
                value=cfg.base_url,
                placeholder="Base URL (e.g. http://127.0.0.1:11434)",
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
                placeholder="Manual model name (e.g. llama3.2, qwen2.5)",
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

        yield Static("", id="llm-context-badge", classes="rf-summary-bar", markup=False)
        yield RichLog(
            id="llm-transcript",
            classes="primary-log",
            highlight=False,
            markup=False,
            wrap=True,
        )

        with Horizontal(classes="action-row toolbar-row"):
            yield Input(
                placeholder="Ask the local LLM or add instructions for attached context...",
                id="llm-prompt",
                compact=True,
            )
            yield Button("Send", id="llm-send-btn", variant="primary", compact=True)
            yield Button("Stop", id="llm-stop-btn", variant="warning", compact=True)
            yield Button("Clear", id="llm-clear-btn", compact=True)

    def on_mount(self) -> None:
        badge = self.query_one("#llm-context-badge", Static)
        badge.display = False

    def _current_provider(self) -> str:
        val = self.query_one("#llm-provider-select", Select).value
        if isinstance(val, str) and val in ("ollama", "openai"):
            return val
        return "ollama"

    def _current_base_url(self) -> str:
        raw = self.query_one("#llm-base-url-input", Input).value.strip()
        if raw:
            return raw
        return (
            DEFAULT_OPENAI_BASE_URL
            if self._current_provider() == "openai"
            else DEFAULT_OLLAMA_BASE_URL
        )

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

    def _build_client(self, *, stop_event: threading.Event | None = None) -> LocalLLMClient:
        provider = self._current_provider()
        base_url = self._current_base_url()
        model = self._resolve_model()
        app_stop = getattr(self.app, "_stop_event", None)
        eff_stop = stop_event
        if eff_stop is None and isinstance(app_stop, threading.Event):
            eff_stop = app_stop
        return LocalLLMClient(
            provider=provider,
            base_url=base_url,
            model=model,
            stop_event=eff_stop,
        )

    def _write_transcript(self, text: str | Text) -> None:
        def _apply() -> None:
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
        select.set_options(options)
        current_manual = manual_input.value.strip()
        if current_manual and current_manual in models:
            select.value = current_manual
        elif models and not current_manual:
            select.value = models[0]
            manual_input.value = models[0]
        else:
            select.value = _MANUAL_MODEL_VALUE

    @on(Select.Changed, "#llm-provider-select")
    def handle_provider_changed(self, event: Select.Changed) -> None:
        if not isinstance(event.value, str):
            return
        url_input = self.query_one("#llm-base-url-input", Input)
        current = url_input.value.strip().rstrip("/")
        if event.value == "openai" and (not current or current == DEFAULT_OLLAMA_BASE_URL):
            url_input.value = DEFAULT_OPENAI_BASE_URL
        elif event.value == "ollama" and (not current or current == DEFAULT_OPENAI_BASE_URL):
            url_input.value = DEFAULT_OLLAMA_BASE_URL

    @on(Select.Changed, "#llm-model-select")
    def handle_model_select_changed(self, event: Select.Changed) -> None:
        if isinstance(event.value, str) and event.value != _MANUAL_MODEL_VALUE:
            self.query_one("#llm-model-input", Input).value = event.value

    def analyze_context(
        self,
        title: str,
        content: str,
        template: str = "freeform",
        auto_send: bool = False,
    ) -> None:
        """Attach SOC context (e.g. Sigma rule or alert) to the LLM pane."""
        clean_title = title.strip() or "Attached Context"
        self._attached_title = clean_title
        self._attached_context = content

        tpl_key = template if template in SOC_PROMPT_TEMPLATES else "freeform"
        self.query_one("#llm-template-select", Select).value = tpl_key

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
            f"Loaded context '{clean_title}' ({len(content)} chars). Click Send to analyze."
        )
        self.record_app_log(f"Loaded LLM context: {clean_title} (template={tpl_key})")

        if auto_send:
            self.handle_send()

    def _clear_attached_context(self) -> None:
        self._attached_title = None
        self._attached_context = None
        try:
            badge = self.query_one("#llm-context-badge", Static)
            badge.update("")
            badge.display = False
        except Exception:
            pass

    @on(Button.Pressed, "#llm-check-btn")
    def handle_check_connection(self) -> None:
        self._check_connection_worker()

    @work(thread=True, exit_on_error=False)
    def _check_connection_worker(self) -> None:
        try:
            self.set_status("Checking local LLM connection...")
            with self.log_scope("llm"):
                with self._build_client() as client:
                    result = client.check_connection()
            if result.get("ok"):
                models = list(result.get("models") or [])
                self.run_on_ui(self._apply_models_list, models)
                msg = (
                    f"Connected to {result['provider']} ({result['base_url']}): "
                    f"{len(models)} model(s) available."
                )
                self.set_status(msg)
                self.record_app_log(msg)
                self.notify_user(msg, title="Local LLM Connected")
            else:
                err = str(result.get("error") or "Connection failed")
                msg = f"Local LLM unreachable ({result['provider']} @ {result['base_url']}): {err}"
                self.set_status(msg)
                self.record_app_log(msg, level="WARNING")
                self.notify_user(err, title="Local LLM Connection Failed", severity="warning")
        except Exception as exc:
            self.report_error("Local LLM Connection Check", exc)

    @on(Button.Pressed, "#llm-refresh-models-btn")
    def handle_refresh_models(self) -> None:
        self._refresh_models_worker()

    @work(thread=True, exit_on_error=False)
    def _refresh_models_worker(self) -> None:
        try:
            self.set_status("Refreshing local LLM models...")
            with self.log_scope("llm"):
                with self._build_client() as client:
                    models = client.list_models()
            self.run_on_ui(self._apply_models_list, models)
            msg = f"Loaded {len(models)} model(s) from {self._current_provider()}."
            self.set_status(msg)
            self.record_app_log(msg)
        except Exception as exc:
            self.report_error("Refresh Local LLM Models", exc)

    @on(Input.Submitted, "#llm-prompt")
    def handle_prompt_submitted(self) -> None:
        self.handle_send()

    @on(Button.Pressed, "#llm-send-btn")
    def handle_send(self) -> None:
        prompt_input = self.query_one("#llm-prompt", Input)
        user_prompt = prompt_input.value.strip()
        attached_ctx = self._attached_context
        attached_title = self._attached_title
        template_key = self._current_template()
        model = self._resolve_model()

        if not user_prompt and not attached_ctx:
            self.set_status("Enter a prompt or attach context before sending.")
            return
        if not model:
            self.set_status("Specify a model name or click Refresh Models first.")
            self.notify_user(
                "No model selected. Enter a model name or click Refresh Models.",
                title="Local LLM",
                severity="warning",
            )
            return

        if self._active_stop_event is not None:
            self._active_stop_event.set()
        stop_event = threading.Event()
        self._active_stop_event = stop_event

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
        self._write_transcript(user_header)

        self._send_chat_worker(
            user_prompt=user_prompt,
            attached_ctx=attached_ctx,
            template_key=template_key,
            model=model,
            stop_event=stop_event,
        )

    @work(thread=True, exit_on_error=False)
    def _send_chat_worker(
        self,
        *,
        user_prompt: str,
        attached_ctx: str | None,
        template_key: str,
        model: str,
        stop_event: threading.Event,
    ) -> None:
        try:
            self.set_status(f"Querying {self._current_provider()} ({model})...")
            with self.log_scope("llm"):
                with self._build_client(stop_event=stop_event) as client:
                    if attached_ctx is not None:
                        result = client.analyze_with_template(
                            template_key,
                            attached_ctx,
                            extra_instruction=user_prompt,
                            model=model,
                        )
                    elif template_key != "freeform":
                        result = client.analyze_with_template(
                            template_key,
                            user_prompt,
                            model=model,
                        )
                    else:
                        messages = [*self._history, {"role": "user", "content": user_prompt}]
                        system_prompt = SOC_PROMPT_TEMPLATES["freeform"]["system_prompt"]
                        result = client.chat(
                            messages,
                            model=model,
                            system_prompt=system_prompt,
                        )
                        self._history.append({"role": "user", "content": user_prompt})
                        self._history.append(
                            {"role": "assistant", "content": str(result.get("content") or "")}
                        )

            reply = str(result.get("content") or "").strip()
            resp_model = str(result.get("model") or model)
            header = Text()
            header.append(f"Assistant ({resp_model}):", style="bold magenta")
            self._write_transcript(header)
            self._write_transcript(reply or "(Empty response)")
            self._write_transcript("")

            status_msg = f"Response received from {result.get('provider')} ({resp_model})."
            self.set_status(status_msg)
            self.record_app_log(status_msg)
        except LocalLLMError as exc:
            if "cancelled" in str(exc).lower():
                self.set_status("Local LLM request stopped.")
                self._write_transcript(Text("[Stopped by user]", style="yellow"))
                return
            self.report_error("Local LLM Chat", exc)
        except Exception as exc:
            self.report_error("Local LLM Chat", exc)

    @on(Button.Pressed, "#llm-stop-btn")
    def handle_stop(self) -> None:
        if self._active_stop_event is not None and not self._active_stop_event.is_set():
            self._active_stop_event.set()
            self.set_status("Stopping active local LLM request...")
        else:
            self.set_status("No active local LLM request to stop.")

    @on(Button.Pressed, "#llm-clear-btn")
    def handle_clear(self) -> None:
        self._history.clear()
        self._clear_attached_context()
        try:
            self.query_one("#llm-transcript", RichLog).clear()
        except Exception:
            pass
        self.set_status("Cleared LLM transcript and attached context.")

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        event.stop()
        items: list[tuple[str, str]] = [
            ("check_conn", "Check LLM Connection"),
            ("refresh_models", "Refresh Models"),
            ("stop_req", "Stop Active Request"),
            ("clear_chat", "Clear Transcript & Context"),
            ("open_logs", "Open Logs Tab"),
        ]

        def _on_select(action_id: str) -> None:
            if action_id == "check_conn":
                self.handle_check_connection()
            elif action_id == "refresh_models":
                self.handle_refresh_models()
            elif action_id == "stop_req":
                self.handle_stop()
            elif action_id == "clear_chat":
                self.handle_clear()
            elif action_id == "open_logs":
                open_fn = getattr(self.app, "open_logs_tab", None)
                if callable(open_fn):
                    open_fn(source="llm")

        self.open_context_menu(
            items,
            title="Local LLM",
            origin=(event.screen_x, event.screen_y),
            on_select=_on_select,
        )
