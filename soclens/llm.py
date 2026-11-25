"""Local LLM client supporting Ollama and OpenAI-compatible inference servers."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter

from soclens.config import (
    ConfigurationError,
    LocalLLMConfig,
    get_local_llm_config,
    suppress_insecure_ssl_warnings,
)

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
}


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
    """HTTP client for local Ollama and OpenAI-compatible LLM servers."""

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
                )
        except ConfigurationError as exc:
            raise LocalLLMConfigError(str(exc)) from exc

        self.max_retries = max(0, int(max_retries))
        self.backoff_base = max(0.0, float(backoff_base))
        self._stop_event = stop_event if stop_event is not None else threading.Event()
        self._owns_session = session is None

        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

        self.session.verify = self.config.verify_ssl
        if self.config.verify_ssl is False:
            suppress_insecure_ssl_warnings()

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

    def list_models(self) -> list[str]:
        """Return available model names/IDs from the configured local LLM server."""
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
        """Probe the local LLM server and return a structured health summary."""
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
    ) -> dict[str, Any]:
        """Send a chat completion request (streaming or non-streaming)."""
        selected_model = (model if model is not None else self.config.model or "").strip()
        if not selected_model:
            raise LocalLLMConfigError(
                "No local LLM model specified. Set RF_LLM_MODEL or pass model explicitly."
            )
        if not messages:
            raise LocalLLMConfigError("At least one chat message is required.")

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

        prefix = template.get("user_prefix", "")
        parts = [f"{prefix}{content.strip()}"] if content.strip() else []
        extra = extra_instruction.strip()
        if extra:
            parts.append(f"\n\nAdditional analyst instructions:\n{extra}")
        user_content = "".join(parts).strip()
        if not user_content:
            raise LocalLLMConfigError("Prompt content cannot be empty.")

        return self.chat(
            [{"role": "user", "content": user_content}],
            model=model,
            system_prompt=template["system_prompt"],
            temperature=temperature,
            max_tokens=max_tokens,
            stream_callback=stream_callback,
        )
