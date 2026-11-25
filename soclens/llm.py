"""Local LLM client supporting Ollama and OpenAI-compatible inference servers."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter

from soclens.config import (
    COPILOT_LLM_PROVIDERS,
    ConfigurationError,
    ConfiguredSession,
    CopilotAgentPreset,
    LocalLLMConfig,
    PivotPayload,
    get_local_llm_config,
    suppress_insecure_ssl_warnings,
)
from soclens.copilot import (
    CopilotDirectLineTransport,
    CopilotStudioD2ETransport,
    M365CopilotTransport,
    SecurityCopilotTransport,
    is_copilot_d2e_url,
)

__all__ = [
    "SOC_PROMPT_TEMPLATES",
    "LocalLLMClient",
    "LocalLLMConfigError",
    "LocalLLMConnectionError",
    "LocalLLMError",
    "build_copilot_prompt",
    "format_llm_copilot_context",
]

logger = logging.getLogger("soclens.llm")

_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({500, 502, 503, 504})


class LocalLLMError(RuntimeError):
    """Base exception for local LLM client failures."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        provider: str | None = None,
        endpoint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.provider = provider
        self.endpoint = endpoint


class LocalLLMConnectionError(LocalLLMError):
    """Raised when the local LLM endpoint is unreachable or times out."""


class LocalLLMConfigError(LocalLLMError, ConfigurationError):
    """Raised when local LLM configuration (provider, model, template) is invalid."""


SOC_PROMPT_TEMPLATES: dict[str, dict[str, str]] = {
    "freeform": {
        "label": "Freeform",
        "description": "General SOC analyst assistant for Recorded Future, Splunk, and IR.",
        "system_prompt": (
            "You are a senior Security Operations Center (SOC) analyst assistant working with "
            "Recorded Future threat intelligence, Sigma detection rules, and Splunk Enterprise "
            "Security (SPL). Provide concise, accurate, actionable technical guidance."
        ),
        "user_prefix": "",
    },
    "explain_sigma": {
        "label": "Explain Sigma/SPL",
        "description": "Break down Sigma YAML or Splunk SPL detection logic, ATT&CK, and tuning.",
        "system_prompt": (
            "You are a detection engineering specialist. Explain Sigma detection rules and "
            "Splunk SPL queries clearly for SOC analysts. Cover: (1) what adversary behavior is "
            "detected, (2) key detection logic and required log sources/fields, (3) MITRE ATT&CK "
            "mapping, (4) common false positives, and (5) practical tuning or triage steps."
        ),
        "user_prefix": "Analyze and explain the following Sigma rule or SPL detection:\n\n",
    },
    "triage_alert": {
        "label": "Triage RF Alert",
        "description": "Structure triage steps, severity assessment, and containment for an RF alert.",
        "system_prompt": (
            "You are a Tier-2/3 SOC incident responder triaging Recorded Future alerts and "
            "playbook alerts. Provide: (1) executive severity assessment, (2) key indicators and "
            "evidence, (3) immediate Splunk/EDR enrichment pivots, (4) containment recommendations, "
            "and (5) escalation criteria."
        ),
        "user_prefix": "Triage the following Recorded Future alert data:\n\n",
    },
    "summarize_ioc": {
        "label": "IOC Summary",
        "description": "Summarize Recorded Future IOC enrichment or dossier into analyst takeaways.",
        "system_prompt": (
            "You are a threat intelligence analyst summarizing Recorded Future IOC enrichment "
            "and research dossiers. Highlight risk score, threat actor/malware attribution, "
            "notable risk rules, related infrastructure, and concrete defensive actions "
            "(watchlist updates, blocks, or Splunk hunts)."
        ),
        "user_prefix": "Summarize the following IOC / threat intelligence context:\n\n",
    },
    "spl_helper": {
        "label": "SPL Helper",
        "description": "Write, explain, or optimize Splunk Enterprise Security SPL queries.",
        "system_prompt": (
            "You are a Splunk Enterprise Security (v10.2) and SPL expert. Help analysts write, "
            "debug, and optimize SPL searches using CIM data models (`tstats`, `datamodel`) "
            "and ES correlation search best practices. Keep queries readable and performant."
        ),
        "user_prefix": "Assist with the following Splunk SPL request:\n\n",
    },
    "summarize_attack_chain": {
        "label": "Attack-Chain Summary",
        "description": "Summarize correlated Splunk ES, Tenant, SentinelOne, and RF context into an attack chain.",
        "system_prompt": (
            "You are a senior Tier-2/3 SOC incident responder analyzing correlated multi-tool "
            "telemetry ([Splunk ES Notable + Tenant Context + SentinelOne Threat/Mitigation + "
            "Recorded Future IOC Enrichment]). Produce a structured attack-chain summary covering: "
            "(1) Tenant & Scope, (2) Execution & Attack Chain Timeline, (3) Endpoint / SentinelOne "
            "Telemetry & Mitigation State, (4) Recorded Future Threat Intel & Risk Attribution, and "
            "(5) Immediate Containment & Next Hunt Steps. Cite only facts present in the context; "
            "explicitly note if S1 or RF telemetry is absent."
        ),
        "user_prefix": "Summarize the attack chain from the following bundled SOC context:\n\n",
    },
    "draft_closing_note": {
        "label": "Draft Closing Note",
        "description": "Draft a concise, audit-ready SOC closing note from bundled ES/S1/RF triage context.",
        "system_prompt": (
            "You are a senior SOC analyst drafting a concise, audit-ready closing note for a "
            "Splunk ES notable/investigation or incident ticket. Output: (1) Recommended Disposition "
            "& Severity, (2) Concise Incident Summary (Tenant, Host/User, Key IOCs), (3) Actions "
            "Taken / Mitigation Status (SentinelOne/ES), (4) Recorded Future Risk Context, and "
            "(5) Follow-up / Monitoring Notes. Keep the note factual, crisp, and ready to paste."
        ),
        "user_prefix": "Draft a concise closing note for the following bundled SOC context:\n\n",
    },
}


def format_llm_copilot_context(context: str | PivotPayload | Mapping[str, Any]) -> str:
    """Format bundled ``[ES + Tenant + S1 + RF]`` SOC context into prompt text."""
    if isinstance(context, str):
        rendered = context.strip()
        if not rendered:
            raise LocalLLMConfigError("Copilot context cannot be empty.")
        return rendered

    if isinstance(context, PivotPayload):
        title_parts = ["SOC Triage Pivot"]
        if context.tenant_id:
            title_parts.append(f"Tenant {context.tenant_id}")
        if context.hostname:
            title_parts.append(context.hostname)
        elif context.entity:
            title_parts.append(context.entity)
        title = " | ".join(title_parts)

        sections: list[str] = [f"# {title}"]
        if context.summary and context.summary.strip():
            sections.append(f"## Summary\n{context.summary.strip()}")

        scope_lines: list[str] = []
        for label, val in (
            ("Source Tab", context.source_tab),
            ("Tenant ID", context.tenant_id),
            ("Tier", context.tier),
            ("Site Name", context.site_name),
            ("Site ID", context.site_id),
            ("Earliest", context.earliest),
            ("Latest", context.latest),
        ):
            if val:
                scope_lines.append(f"- **{label}**: {val}")
        if scope_lines:
            sections.append("## Tenant & Scope\n" + "\n".join(scope_lines))

        ioc_lines: list[str] = []
        for label, val in (
            ("Entity", context.entity),
            ("Entity Type", context.entity_type),
            ("Hostname", context.hostname),
            ("Username", context.username),
            ("Source IP", context.src_ip),
            ("Destination IP", context.dest_ip),
            ("SHA-1", context.sha1),
            ("SHA-256", context.sha256),
            ("Original SID", context.orig_sid),
        ):
            if val:
                ioc_lines.append(f"- **{label}**: `{val}`")
        if ioc_lines:
            sections.append("## Indicators & Entities\n" + "\n".join(ioc_lines))

        if context.spl_query and context.spl_query.strip():
            sections.append(f"## Splunk Query\n```spl\n{context.spl_query.strip()}\n```")

        for heading, blob in (
            ("Splunk ES Finding", context.es_finding),
            ("SentinelOne Threat / Context", context.s1_threat),
            ("Recorded Future Enrichment", context.rf_enrichment),
        ):
            if blob:
                rendered_blob = json.dumps(blob, indent=2, ensure_ascii=False, default=str)
                sections.append(f"## {heading}\n```json\n{rendered_blob}\n```")

        has_substance = any(
            (
                context.summary and context.summary.strip(),
                context.tenant_id,
                context.tier,
                context.site_name,
                context.site_id,
                context.entity,
                context.hostname,
                context.username,
                context.src_ip,
                context.dest_ip,
                context.sha1,
                context.sha256,
                context.orig_sid,
                context.spl_query and context.spl_query.strip(),
                context.es_finding,
                context.s1_threat,
                context.rf_enrichment,
            )
        )
        if not has_substance:
            raise LocalLLMConfigError("Copilot context cannot be empty.")
        return "\n\n".join(sections)

    if isinstance(context, Mapping):
        if not context:
            raise LocalLLMConfigError("Copilot context cannot be empty.")
        return json.dumps(dict(context), indent=2, ensure_ascii=False, default=str)

    raise LocalLLMConfigError("Unsupported copilot context type.")


def build_copilot_prompt(
    template_key: str,
    context: str | PivotPayload | Mapping[str, Any],
    *,
    extra_instruction: str = "",
) -> tuple[str, str]:
    """Validate ``template_key`` and build ``(system_prompt, user_content)``."""
    key = template_key.strip().lower()
    template = SOC_PROMPT_TEMPLATES.get(key)
    if template is None:
        available = ", ".join(SOC_PROMPT_TEMPLATES.keys())
        raise LocalLLMConfigError(
            f"Unknown SOC prompt template '{template_key}'. Available: {available}"
        )

    rendered_context = format_llm_copilot_context(context)
    prefix = template.get("user_prefix", "")
    parts = [f"{prefix}{rendered_context}"]
    extra = extra_instruction.strip()
    if extra:
        parts.append(f"\n\nAdditional analyst instructions:\n{extra}")
    user_content = "".join(parts).strip()
    return template["system_prompt"], user_content


def _extract_error_detail(response: requests.Response) -> str:
    """Extract a readable error message from an Ollama or OpenAI-compatible error payload."""
    try:
        payload = response.json()
    except ValueError:
        text = (response.text or "").strip()
        return text[:400] if text else f"HTTP {response.status_code}"

    if isinstance(payload, dict):
        err = payload.get("error")
        if isinstance(err, dict):
            msg = err.get("message") or err.get("detail") or err.get("type")
            if msg:
                return str(msg)
        elif isinstance(err, str) and err.strip():
            return err.strip()
        detail = payload.get("detail") or payload.get("message")
        if detail:
            return str(detail)
    return f"HTTP {response.status_code}"


class LocalLLMClient:
    """HTTP client for local LLMs (Ollama/OpenAI-compatible) and Microsoft Copilot agents."""

    def __init__(
        self,
        config: LocalLLMConfig | None = None,
        *,
        provider: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        timeout: float | str | None = None,
        verify_ssl: bool | str | Path | None = None,
        temperature: float | str | None = None,
        max_tokens: int | str | None = None,
        ms_auth_mode: str | None = None,
        ms_bearer_token: str | None = None,
        ms_graph_base_url: str | None = None,
        ms_web_grounding: bool | str | None = None,
        ms_directline_url: str | None = None,
        ms_token_endpoint: str | None = None,
        ms_directline_secret: str | None = None,
        ms_security_workspace: str | None = None,
        ms_security_poll_interval: float | str | None = None,
        agent_name: str | None = None,
        conversation_id: str | None = None,
        conversation_token: str | None = None,
        watermark: str | None = None,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        stop_event: threading.Event | None = None,
        session: requests.Session | None = None,
    ) -> None:
        try:
            if config is not None:
                has_overrides = any(
                    v is not None
                    for v in (
                        provider,
                        base_url,
                        model,
                        api_key,
                        timeout,
                        verify_ssl,
                        temperature,
                        max_tokens,
                        ms_auth_mode,
                        ms_bearer_token,
                        ms_graph_base_url,
                        ms_web_grounding,
                        ms_directline_url,
                        ms_token_endpoint,
                        ms_directline_secret,
                        ms_security_workspace,
                        ms_security_poll_interval,
                    )
                )
                if has_overrides:
                    self.config = get_local_llm_config(
                        provider=provider if provider is not None else config.provider,
                        base_url=base_url if base_url is not None else config.base_url,
                        model=model if model is not None else config.model,
                        api_key=api_key if api_key is not None else config.api_key,
                        timeout=timeout if timeout is not None else config.timeout,
                        verify_ssl=verify_ssl if verify_ssl is not None else config.verify_ssl,
                        temperature=temperature if temperature is not None else config.temperature,
                        max_tokens=max_tokens if max_tokens is not None else config.max_tokens,
                        ms_auth_mode=ms_auth_mode if ms_auth_mode is not None else config.ms_auth_mode,
                        ms_bearer_token=(
                            ms_bearer_token if ms_bearer_token is not None else config.ms_bearer_token
                        ),
                        ms_graph_base_url=(
                            ms_graph_base_url
                            if ms_graph_base_url is not None
                            else config.ms_graph_base_url
                        ),
                        ms_web_grounding=(
                            ms_web_grounding
                            if ms_web_grounding is not None
                            else config.ms_web_grounding
                        ),
                        ms_directline_url=(
                            ms_directline_url
                            if ms_directline_url is not None
                            else config.ms_directline_url
                        ),
                        ms_token_endpoint=(
                            ms_token_endpoint
                            if ms_token_endpoint is not None
                            else config.ms_token_endpoint
                        ),
                        ms_directline_secret=(
                            ms_directline_secret
                            if ms_directline_secret is not None
                            else config.ms_directline_secret
                        ),
                        ms_security_workspace=(
                            ms_security_workspace
                            if ms_security_workspace is not None
                            else config.ms_security_workspace
                        ),
                        ms_security_poll_interval=(
                            ms_security_poll_interval
                            if ms_security_poll_interval is not None
                            else config.ms_security_poll_interval
                        ),
                        agent_presets=config.agent_presets,
                    )
                else:
                    self.config = config
            else:
                self.config = get_local_llm_config(
                    provider=provider,
                    base_url=base_url,
                    model=model,
                    api_key=api_key,
                    timeout=timeout,
                    verify_ssl=verify_ssl,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    ms_auth_mode=ms_auth_mode,
                    ms_bearer_token=ms_bearer_token,
                    ms_graph_base_url=ms_graph_base_url,
                    ms_web_grounding=ms_web_grounding,
                    ms_directline_url=ms_directline_url,
                    ms_token_endpoint=ms_token_endpoint,
                    ms_directline_secret=ms_directline_secret,
                    ms_security_workspace=ms_security_workspace,
                    ms_security_poll_interval=ms_security_poll_interval,
                )
        except ConfigurationError as exc:
            raise LocalLLMConfigError(str(exc)) from exc

        # Apply named agent preset if agent_name or model matches a configured preset
        target_agent = (agent_name or "").strip() or (self.config.model or "").strip()
        matched_preset = self._find_agent_preset(target_agent) if target_agent else None
        if matched_preset is not None and (
            agent_name is not None or self.config.provider in COPILOT_LLM_PROVIDERS
        ):
            self.config = self._apply_agent_preset(self.config, matched_preset)

        self.max_retries = max(0, int(max_retries))
        self.backoff_base = max(0.0, float(backoff_base))
        self._stop_event = stop_event if stop_event is not None else threading.Event()
        self._owns_session = session is None
        self._initial_conversation_id = (conversation_id or "").strip() or None
        self._initial_conversation_token = (conversation_token or "").strip() or None
        self._initial_watermark = (watermark or "").strip() or None
        self._copilot_transport: (
            M365CopilotTransport
            | CopilotStudioD2ETransport
            | CopilotDirectLineTransport
            | SecurityCopilotTransport
            | None
        ) = None

        if session is not None:
            self.session = session
        else:
            self.session = ConfiguredSession()
            adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

        self.session.verify = self.config.verify_ssl
        if self.config.verify_ssl is False:
            suppress_insecure_ssl_warnings()

    def _find_agent_preset(self, name: str) -> CopilotAgentPreset | None:
        needle = name.strip().lower()
        if not needle:
            return None
        for preset in self.config.agent_presets:
            if preset.name.strip().lower() == needle:
                return preset
        return None

    @staticmethod
    def _apply_agent_preset(cfg: LocalLLMConfig, preset: CopilotAgentPreset) -> LocalLLMConfig:
        return get_local_llm_config(
            provider=preset.provider,
            base_url=preset.base_url or cfg.base_url,
            model=preset.model or preset.name,
            api_key=cfg.api_key,
            timeout=cfg.timeout,
            verify_ssl=cfg.verify_ssl,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            ms_auth_mode=cfg.ms_auth_mode,
            ms_bearer_token=preset.bearer_token or cfg.ms_bearer_token,
            ms_graph_base_url=cfg.ms_graph_base_url,
            ms_web_grounding=(
                preset.web_grounding if preset.web_grounding is not None else cfg.ms_web_grounding
            ),
            ms_directline_url=cfg.ms_directline_url,
            ms_token_endpoint=preset.token_endpoint or cfg.ms_token_endpoint,
            ms_directline_secret=preset.directline_secret or cfg.ms_directline_secret,
            ms_security_workspace=preset.workspace or cfg.ms_security_workspace,
            ms_security_poll_interval=cfg.ms_security_poll_interval,
            agent_presets=cfg.agent_presets,
        )

    @property
    def is_copilot_provider(self) -> bool:
        return self.config.provider in COPILOT_LLM_PROVIDERS

    @property
    def conversation_id(self) -> str | None:
        if self._copilot_transport is not None:
            return self._copilot_transport.conversation_id
        return self._initial_conversation_id

    def reset_conversation(self) -> None:
        """Reset server-side Copilot / Security Copilot conversation state."""
        self._initial_conversation_id = None
        if self._copilot_transport is not None:
            self._copilot_transport.reset_conversation()

    def _get_copilot_transport(
        self,
    ) -> (
        M365CopilotTransport
        | CopilotStudioD2ETransport
        | CopilotDirectLineTransport
        | SecurityCopilotTransport
    ):
        if self._copilot_transport is not None:
            return self._copilot_transport
        common_kwargs: dict[str, Any] = {
            "stop_event": self._stop_event,
            "max_retries": self.max_retries,
            "backoff_base": self.backoff_base,
            "error_factory": LocalLLMError,
            "connection_error_factory": LocalLLMConnectionError,
        }
        is_d2e = self.config.provider == "copilot_studio" or (
            self.config.provider == "copilot_directline"
            and (
                is_copilot_d2e_url(self.config.base_url)
                or is_copilot_d2e_url(self.config.ms_token_endpoint)
            )
        )
        if self.config.provider == "m365_copilot":
            transport: (
                M365CopilotTransport
                | CopilotStudioD2ETransport
                | CopilotDirectLineTransport
                | SecurityCopilotTransport
            ) = M365CopilotTransport(self.config, self.session, **common_kwargs)
        elif is_d2e:
            transport = CopilotStudioD2ETransport(self.config, self.session, **common_kwargs)
        elif self.config.provider == "copilot_directline":
            transport = CopilotDirectLineTransport(
                self.config,
                self.session,
                conversation_token=self._initial_conversation_token,
                watermark=self._initial_watermark,
                **common_kwargs,
            )
        elif self.config.provider == "security_copilot":
            transport = SecurityCopilotTransport(self.config, self.session, **common_kwargs)
        else:
            raise LocalLLMConfigError(
                f"Provider '{self.config.provider}' is not a Microsoft Copilot provider."
            )
        if self._initial_conversation_id:
            transport.conversation_id = self._initial_conversation_id
        self._copilot_transport = transport
        return transport

    def __enter__(self) -> LocalLLMClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP session if owned by this client."""
        if self._owns_session:
            self.session.close()

    @property
    def provider(self) -> str:
        return self.config.provider

    @property
    def base_url(self) -> str:
        return self.config.base_url

    @property
    def model(self) -> str | None:
        return self.config.model

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.config.provider == "openai" and self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def _endpoint_url(self, kind: str) -> str:
        base = self.config.base_url.rstrip("/")
        if self.config.provider == "ollama":
            if kind == "models":
                return f"{base}/api/tags"
            if kind == "chat":
                return f"{base}/api/chat"
            raise LocalLLMConfigError(f"Unknown endpoint kind: {kind}")

        # OpenAI-compatible endpoints: avoid duplicating /v1 if base_url already includes it
        for suffix in ("/chat/completions", "/models"):
            if base.lower().endswith(suffix):
                base = base[: -len(suffix)].rstrip("/")
                break
        has_v1 = base.lower().endswith("/v1") or "/v1/" in base.lower()
        prefix = "" if has_v1 else "/v1"
        if kind == "models":
            return f"{base}{prefix}/models"
        if kind == "chat":
            return f"{base}{prefix}/chat/completions"
        raise LocalLLMConfigError(f"Unknown endpoint kind: {kind}")

    def _check_cancelled(self, endpoint: str) -> None:
        if self._stop_event.is_set():
            raise LocalLLMError(
                "Local LLM request cancelled.",
                provider=self.config.provider,
                endpoint=endpoint,
            )

    def _sleep_backoff(self, attempt: int, endpoint: str) -> None:
        delay = self.backoff_base * (2**attempt)
        if delay <= 0:
            self._check_cancelled(endpoint)
            return
        if self._stop_event.wait(delay):
            raise LocalLLMError(
                "Local LLM request cancelled.",
                provider=self.config.provider,
                endpoint=endpoint,
            )

    def _request(
        self,
        method: str,
        url: str,
        *,
        json_payload: dict[str, Any] | None = None,
        stream: bool = False,
        timeout: float | None = None,
    ) -> requests.Response:
        eff_timeout = self.config.timeout if timeout is None else timeout
        headers = self._build_headers()

        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._check_cancelled(url)
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=json_payload,
                    timeout=eff_timeout,
                    verify=self.config.verify_ssl,
                    stream=stream,
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    logger.warning(
                        "Transient local LLM connection error (%s) on %s (attempt %d/%d); retrying",
                        exc,
                        url,
                        attempt + 1,
                        self.max_retries + 1,
                    )
                    self._sleep_backoff(attempt, url)
                    continue
                raise LocalLLMConnectionError(
                    f"Failed to connect to {self.config.provider} at {url}: {exc}",
                    provider=self.config.provider,
                    endpoint=url,
                ) from exc
            except requests.RequestException as exc:
                raise LocalLLMError(
                    f"Local LLM HTTP request error ({url}): {exc}",
                    provider=self.config.provider,
                    endpoint=url,
                ) from exc

            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                detail = _extract_error_detail(response)
                response.close()
                logger.warning(
                    "Transient local LLM HTTP %d on %s (%s); retrying (%d/%d)",
                    response.status_code,
                    url,
                    detail,
                    attempt + 1,
                    self.max_retries + 1,
                )
                self._sleep_backoff(attempt, url)
                continue

            if response.status_code >= 400:
                detail = _extract_error_detail(response)
                status = response.status_code
                response.close()
                raise LocalLLMError(
                    f"Local LLM HTTP {status} ({self.config.provider}): {detail}",
                    status_code=status,
                    provider=self.config.provider,
                    endpoint=url,
                )

            return response

        raise LocalLLMConnectionError(
            f"Failed to connect to {self.config.provider} at {url}: {last_exc}",
            provider=self.config.provider,
            endpoint=url,
        )

    def _default_copilot_model_label(self) -> str:
        if self.config.model:
            return self.config.model
        if self.config.provider == "m365_copilot":
            return "M365 Copilot Chat"
        if self.config.provider in ("copilot_studio", "copilot_directline"):
            return "Copilot Studio Agent"
        if self.config.provider == "security_copilot":
            return f"Security Copilot ({self.config.ms_security_workspace})"
        return self.config.provider

    def list_models(self) -> list[str]:
        """Return available model names/IDs or configured Copilot agent presets."""
        if self.is_copilot_provider:
            names: list[str] = [
                preset.name
                for preset in self.config.agent_presets
                if preset.provider == self.config.provider
            ]
            default_label = self._default_copilot_model_label()
            if default_label not in names:
                names.insert(0, default_label)
            return names

        url = self._endpoint_url("models")
        response = self._request("GET", url)
        try:
            payload = response.json()
        except ValueError as exc:
            raise LocalLLMError(
                f"Invalid JSON returned by {url}: {exc}",
                status_code=response.status_code,
                provider=self.config.provider,
                endpoint=url,
            ) from exc
        finally:
            response.close()

        models: list[str] = []
        seen: set[str] = set()
        if isinstance(payload, dict):
            raw_items = (
                payload.get("models")
                if self.config.provider == "ollama"
                else payload.get("data")
            )
            if isinstance(raw_items, list):
                for item in raw_items:
                    if isinstance(item, dict):
                        candidate = (
                            item.get("name") or item.get("model")
                            if self.config.provider == "ollama"
                            else item.get("id") or item.get("name")
                        )
                    elif isinstance(item, str):
                        candidate = item
                    else:
                        candidate = None
                    if isinstance(candidate, str):
                        cleaned = candidate.strip()
                        if cleaned and cleaned not in seen:
                            seen.add(cleaned)
                            models.append(cleaned)
        return models

    def check_connection(self) -> dict[str, Any]:
        """Probe the configured LLM or Microsoft Copilot endpoint and return a health summary."""
        if self.is_copilot_provider:
            transport = self._get_copilot_transport()
            result = transport.check_connection()
            if result.get("ok"):
                presets = self.list_models()
                existing = list(result.get("models") or [])
                merged = list(dict.fromkeys([*presets, *existing]))
                result["models"] = merged
            return result

        try:
            models = self.list_models()
            return {
                "ok": True,
                "provider": self.config.provider,
                "base_url": self.config.base_url,
                "models": models,
                "error": None,
            }
        except LocalLLMError as exc:
            return {
                "ok": False,
                "provider": self.config.provider,
                "base_url": self.config.base_url,
                "models": [],
                "error": str(exc),
            }

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream_callback: Callable[[str], None] | None = None,
        conversation_id: str | None = None,
    ) -> dict[str, Any]:
        """Send a chat completion request (streaming or non-streaming)."""
        if not messages:
            raise LocalLLMConfigError("At least one chat message is required.")

        if self.is_copilot_provider:
            selected_label = (
                (model if model is not None else self.config.model or "").strip()
                or self._default_copilot_model_label()
            )
            # Extract latest user prompt
            latest_user = ""
            for msg in reversed(messages):
                if str(msg.get("role") or "user").strip().lower() == "user":
                    latest_user = str(msg.get("content") or "").strip()
                    if latest_user:
                        break
            if not latest_user:
                latest_user = str(messages[-1].get("content") or "").strip()

            clean_system = (system_prompt or "").strip()
            freeform_sys = SOC_PROMPT_TEMPLATES["freeform"]["system_prompt"].strip()
            if clean_system and clean_system != freeform_sys:
                turn_text = f"[Analyst Instructions]\n{clean_system}\n\n{latest_user}"
            else:
                turn_text = latest_user

            transport = self._get_copilot_transport()
            return transport.send_turn(
                turn_text,
                conversation_id=conversation_id,
                stream_callback=stream_callback,
                model_label=selected_label,
            )

        selected_model = (model if model is not None else self.config.model or "").strip()
        if not selected_model:
            raise LocalLLMConfigError(
                "No local LLM model specified. Set RF_LLM_MODEL or pass model explicitly."
            )

        full_messages: list[dict[str, str]] = []
        clean_system = (system_prompt or "").strip()
        if clean_system:
            if not (
                messages
                and messages[0].get("role") == "system"
                and messages[0].get("content", "").strip() == clean_system
            ):
                full_messages.append({"role": "system", "content": clean_system})
        for msg in messages:
            role = str(msg.get("role") or "user").strip()
            content = str(msg.get("content") or "")
            full_messages.append({"role": role, "content": content})

        eff_temp = self.config.temperature if temperature is None else float(temperature)
        eff_max_tokens = self.config.max_tokens if max_tokens is None else int(max_tokens)
        streaming = stream_callback is not None

        url = self._endpoint_url("chat")
        if self.config.provider == "ollama":
            options: dict[str, Any] = {"temperature": eff_temp}
            if eff_max_tokens is not None:
                options["num_predict"] = eff_max_tokens
            payload: dict[str, Any] = {
                "model": selected_model,
                "messages": full_messages,
                "stream": streaming,
                "options": options,
            }
        else:
            payload = {
                "model": selected_model,
                "messages": full_messages,
                "stream": streaming,
                "temperature": eff_temp,
            }
            if eff_max_tokens is not None:
                payload["max_tokens"] = eff_max_tokens

        response = self._request("POST", url, json_payload=payload, stream=streaming)
        try:
            if streaming:
                return self._consume_stream(
                    response,
                    selected_model=selected_model,
                    url=url,
                    stream_callback=stream_callback,
                )
            return self._consume_non_stream(response, selected_model=selected_model, url=url)
        finally:
            response.close()

    def _consume_non_stream(
        self,
        response: requests.Response,
        *,
        selected_model: str,
        url: str,
    ) -> dict[str, Any]:
        try:
            data = response.json()
        except ValueError as exc:
            raise LocalLLMError(
                f"Invalid JSON response from {url}: {exc}",
                status_code=response.status_code,
                provider=self.config.provider,
                endpoint=url,
            ) from exc

        if not isinstance(data, dict):
            raise LocalLLMError(
                f"Unexpected non-object response from {url}.",
                status_code=response.status_code,
                provider=self.config.provider,
                endpoint=url,
            )

        if self.config.provider == "ollama":
            msg = data.get("message")
            content = str(msg.get("content") or "") if isinstance(msg, dict) else ""
            resp_model = str(data.get("model") or selected_model)
            done = bool(data.get("done", True))
        else:
            choices = data.get("choices")
            content = ""
            if isinstance(choices, list) and choices:
                first = choices[0]
                if isinstance(first, dict):
                    msg = first.get("message")
                    if isinstance(msg, dict):
                        content = str(msg.get("content") or "")
            resp_model = str(data.get("model") or selected_model)
            done = True

        return {
            "content": content,
            "model": resp_model,
            "provider": self.config.provider,
            "done": done,
            "raw": data,
        }

    def _consume_stream(
        self,
        response: requests.Response,
        *,
        selected_model: str,
        url: str,
        stream_callback: Callable[[str], None] | None,
    ) -> dict[str, Any]:
        chunks: list[str] = []
        raw_events: list[dict[str, Any]] = []
        resp_model = selected_model
        done = False

        for raw_line in response.iter_lines(decode_unicode=True):
            if self._stop_event.is_set():
                done = False
                break
            if raw_line is None:
                continue
            line = raw_line.decode("utf-8", errors="replace") if isinstance(raw_line, bytes) else raw_line
            stripped = line.strip()
            if not stripped:
                continue

            if self.config.provider == "ollama":
                try:
                    event = json.loads(stripped)
                except ValueError as exc:
                    raise LocalLLMError(
                        f"Malformed Ollama NDJSON chunk from {url}: {exc}",
                        provider=self.config.provider,
                        endpoint=url,
                    ) from exc
                if not isinstance(event, dict):
                    continue
                raw_events.append(event)
                if event.get("model"):
                    resp_model = str(event["model"])
                msg = event.get("message")
                if isinstance(msg, dict):
                    delta = str(msg.get("content") or "")
                    if delta:
                        chunks.append(delta)
                        if stream_callback is not None:
                            stream_callback(delta)
                if event.get("done"):
                    done = True
                    break
            else:
                if stripped.startswith(":"):
                    continue
                if stripped.startswith("data:"):
                    data_str = stripped[5:].strip()
                else:
                    data_str = stripped
                if data_str == "[DONE]":
                    done = True
                    break
                try:
                    event = json.loads(data_str)
                except ValueError as exc:
                    raise LocalLLMError(
                        f"Malformed OpenAI SSE chunk from {url}: {exc}",
                        provider=self.config.provider,
                        endpoint=url,
                    ) from exc
                if not isinstance(event, dict):
                    continue
                raw_events.append(event)
                if event.get("model"):
                    resp_model = str(event["model"])
                choices = event.get("choices")
                if isinstance(choices, list) and choices:
                    first = choices[0]
                    if isinstance(first, dict):
                        delta_obj = first.get("delta")
                        if isinstance(delta_obj, dict):
                            delta = str(delta_obj.get("content") or "")
                            if delta:
                                chunks.append(delta)
                                if stream_callback is not None:
                                    stream_callback(delta)
                        if first.get("finish_reason") is not None:
                            done = True

        return {
            "content": "".join(chunks),
            "model": resp_model,
            "provider": self.config.provider,
            "done": done,
            "raw": raw_events,
        }

    def analyze_with_template(
        self,
        template_key: str,
        content: str,
        *,
        extra_instruction: str = "",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream_callback: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Run a structured SOC prompt template over the provided content."""
        key = template_key.strip().lower()
        template = SOC_PROMPT_TEMPLATES.get(key)
        if template is None:
            available = ", ".join(SOC_PROMPT_TEMPLATES.keys())
            raise LocalLLMConfigError(
                f"Unknown SOC prompt template '{template_key}'. Available: {available}"
            )

        if content.strip():
            system_prompt, user_content = build_copilot_prompt(
                key,
                content,
                extra_instruction=extra_instruction,
            )
        else:
            extra = extra_instruction.strip()
            if not extra:
                raise LocalLLMConfigError("Prompt content cannot be empty.")
            system_prompt = template["system_prompt"]
            user_content = f"Additional analyst instructions:\n{extra}"

        return self.chat(
            [{"role": "user", "content": user_content}],
            model=model,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            stream_callback=stream_callback,
        )

    def summarize_attack_chain(
        self,
        context: str | PivotPayload | Mapping[str, Any],
        *,
        extra_instruction: str = "",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream_callback: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Summarize a bundled [ES + Tenant + S1 + RF] triage context into an attack chain."""
        rendered = format_llm_copilot_context(context)
        return self.analyze_with_template(
            "summarize_attack_chain",
            rendered,
            extra_instruction=extra_instruction,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            stream_callback=stream_callback,
        )

    def draft_closing_note(
        self,
        context: str | PivotPayload | Mapping[str, Any],
        *,
        extra_instruction: str = "",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream_callback: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Draft a concise closing note from a bundled [ES + Tenant + S1 + RF] triage context."""
        rendered = format_llm_copilot_context(context)
        return self.analyze_with_template(
            "draft_closing_note",
            rendered,
            extra_instruction=extra_instruction,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            stream_callback=stream_callback,
        )
