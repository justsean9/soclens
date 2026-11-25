"""SentinelOne Management API v2.1 client for SOC endpoint & threat operations."""

from __future__ import annotations

import logging
import math
import random
import re
import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter

from soclens.config import (
    ConfigurationError,
    ConfiguredSession,
    SentinelOneConfig,
    get_sentinelone_config,
    suppress_insecure_ssl_warnings,
)

logger = logging.getLogger("soclens.sentinelone")

API_PREFIX = "/web/api/v2.1"
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")

ANALYST_VERDICTS: frozenset[str] = frozenset(
    {"undefined", "true_positive", "false_positive", "suspicious"}
)
INCIDENT_STATUSES: frozenset[str] = frozenset({"unresolved", "in_progress", "resolved"})
MITIGATION_ACTIONS: frozenset[str] = frozenset(
    {"kill", "quarantine", "remediate", "rollback", "un-quarantine"}
)
EXCLUSION_TYPES: frozenset[str] = frozenset(
    {"path", "white_hash", "certificate", "browser", "file_type"}
)
EXCLUSION_MODES: frozenset[str] = frozenset(
    {
        "suppress",
        "suppress_dynamic_only",
        "disable_in_process_monitor",
        "disable_in_process_monitor_deep",
        "disable_all_monitors",
        "disable_all_monitors_deep",
    }
)
OS_TYPES: frozenset[str] = frozenset({"windows", "macos", "linux", "windows_legacy"})


class SentinelOneError(RuntimeError):
    """Base error raised for SentinelOne Management API v2.1 failures."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        endpoint: str | None = None,
        errors: list[dict[str, Any]] | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.endpoint = endpoint
        self.errors: list[dict[str, Any]] = list(errors) if errors else []
        self.reason = reason


class SentinelOneAuthError(SentinelOneError):
    """Raised on HTTP 401/403 authentication or authorization failures."""


class SentinelOneRateLimitError(SentinelOneError):
    """Raised on HTTP 429 rate-limit exhaustion."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = 429,
        endpoint: str | None = None,
        errors: list[dict[str, Any]] | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            endpoint=endpoint,
            errors=errors,
            reason="rate_limited",
        )
        self.retry_after = retry_after


def _parse_retry_after(header_value: str | None) -> float | None:
    """Parse numeric or HTTP-date Retry-After header, clamped to [0, 60] seconds."""
    if not header_value:
        return None
    raw = header_value.strip()
    if not raw:
        return None
    try:
        seconds = float(raw)
    except ValueError:
        try:
            dt = parsedate_to_datetime(raw)
        except (TypeError, ValueError, IndexError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        seconds = (dt - datetime.now(UTC)).total_seconds()
    if not math.isfinite(seconds):
        return None
    return min(max(seconds, 0.0), 60.0)


def _normalize_id_list(ids: Sequence[str] | str, *, field_name: str = "ids") -> list[str]:
    """Normalize a single ID or sequence of IDs into a deduplicated non-empty list."""
    raw_items: list[str]
    if isinstance(ids, str):
        raw_items = [part.strip() for part in ids.split(",")]
    else:
        raw_items = [str(item).strip() for item in ids]
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        if item and item not in seen:
            seen.add(item)
            cleaned.append(item)
    if not cleaned:
        raise ValueError(f"At least one non-empty ID is required for {field_name}.")
    return cleaned


def _csv_param(values: Sequence[str] | str | None) -> str | None:
    """Join an optional string or sequence into a comma-separated query parameter."""
    if values is None:
        return None
    if isinstance(values, str):
        cleaned = values.strip()
        return cleaned if cleaned else None
    parts = [str(v).strip() for v in values if str(v).strip()]
    return ",".join(parts) if parts else None


def _extract_error_details(response: requests.Response) -> tuple[str, list[dict[str, Any]]]:
    """Extract SentinelOne v2.1 structured error entries from an HTTP response."""
    try:
        payload = response.json()
    except ValueError:
        text = (response.text or "").strip()
        return text or f"HTTP {response.status_code}", []

    if isinstance(payload, dict):
        raw_errors = payload.get("errors")
        if isinstance(raw_errors, list) and raw_errors:
            parsed: list[dict[str, Any]] = [e for e in raw_errors if isinstance(e, dict)]
            messages: list[str] = []
            for err in parsed:
                title = str(err.get("title") or "").strip()
                detail = str(err.get("detail") or "").strip()
                code = err.get("code")
                parts = [p for p in (title, detail) if p]
                msg = ": ".join(parts) if parts else str(err)
                if code is not None:
                    msg = f"[{code}] {msg}"
                messages.append(msg)
            if messages:
                return "; ".join(messages), parsed
        fallback_msg = payload.get("message") or payload.get("error")
        if fallback_msg:
            return str(fallback_msg), []
    return (response.text or "").strip() or f"HTTP {response.status_code}", []


class SentinelOneClient:
    """Thread-safe client for SentinelOne Management API v2.1."""

    def __init__(
        self,
        *,
        console_url: str | None = None,
        api_token: str | None = None,
        account_id: str | None = None,
        site_id: str | None = None,
        verify_ssl: bool | str | Path | None = None,
        timeout: float | None = None,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        stop_event: threading.Event | None = None,
        session: requests.Session | None = None,
        config: SentinelOneConfig | None = None,
    ) -> None:
        if config is None:
            config = get_sentinelone_config(
                console_url=console_url,
                api_token=api_token,
                account_id=account_id,
                site_id=site_id,
                verify_ssl=verify_ssl,
                timeout=timeout,
                required=False,
            )
        self.config = config
        self.console_url: str = config.console_url
        self._api_token: str | None = config.api_token
        self.account_id: str | None = config.account_id
        self.site_id: str | None = config.site_id
        self.verify_ssl: bool | str = config.verify_ssl
        self.timeout: float = config.timeout
        self.max_retries: int = max(0, int(max_retries))
        self.backoff_base: float = max(0.01, float(backoff_base))
        self.stop_event: threading.Event = stop_event if stop_event is not None else threading.Event()
        self._owns_session: bool = session is None

        if self.verify_ssl is False:
            suppress_insecure_ssl_warnings()

        self.session: requests.Session = session if session is not None else ConfiguredSession()
        if self._owns_session:
            adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)
        self.session.verify = self.verify_ssl
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        if self._api_token:
            self.session.headers["Authorization"] = f"ApiToken {self._api_token}"

    @property
    def has_auth(self) -> bool:
        """Return True if console URL and API token are both configured."""
        return bool(self.console_url and self._api_token)

    def __enter__(self) -> SentinelOneClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying pooled ``requests.Session`` if owned by this client."""
        if self._owns_session:
            try:
                self.session.close()
            except Exception:
                pass

    def _ensure_configured(self) -> None:
        if not self.console_url or not self._api_token:
            raise ConfigurationError(
                "SentinelOne credentials are required. "
                "Set S1_CONSOLE_URL (or SENTINELONE_URL) and "
                "S1_API_TOKEN (or SENTINELONE_API_TOKEN)."
            )

    def _sleep(self, seconds: float) -> None:
        """Sleep up to ``seconds``, aborting early if ``stop_event`` is signalled."""
        if seconds <= 0:
            return
        if self.stop_event.wait(seconds):
            raise SentinelOneError("SentinelOne request cancelled.", reason="cancelled")

    def _build_url(self, path: str) -> str:
        clean_path = path.lstrip("/")
        if clean_path.startswith("web/api/"):
            return f"{self.console_url}/{clean_path}"
        return f"{self.console_url}{API_PREFIX}/{clean_path}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute an authenticated SentinelOne v2.1 API request with backoff retries."""
        self._ensure_configured()
        if self.stop_event.is_set():
            raise SentinelOneError("SentinelOne request cancelled.", reason="cancelled")

        url = self._build_url(path)
        clean_params = (
            {k: v for k, v in params.items() if v is not None} if params is not None else None
        )
        attempts = self.max_retries + 1

        for attempt in range(attempts):
            if self.stop_event.is_set():
                raise SentinelOneError("SentinelOne request cancelled.", reason="cancelled")
            try:
                response = self.session.request(
                    method=method.upper(),
                    url=url,
                    params=clean_params,
                    json=json_body,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            except requests.RequestException as exc:
                if attempt < attempts - 1:
                    delay = self.backoff_base * (2**attempt) + random.uniform(0.0, 0.25)
                    logger.warning(
                        "SentinelOne %s %s failed (%s); retrying in %.2fs (%d/%d)",
                        method,
                        path,
                        exc,
                        delay,
                        attempt + 1,
                        self.max_retries,
                    )
                    self._sleep(delay)
                    continue
                raise SentinelOneError(
                    f"Network error calling SentinelOne {method} {path}: {exc}",
                    endpoint=path,
                ) from exc

            status = response.status_code
            if status in (401, 403):
                detail, err_list = _extract_error_details(response)
                raise SentinelOneAuthError(
                    f"SentinelOne authentication/authorization failed (HTTP {status}): {detail}",
                    status_code=status,
                    endpoint=path,
                    errors=err_list,
                    reason="unauthorized" if status == 401 else "forbidden",
                )

            if status in _RETRYABLE_STATUS_CODES:
                detail, err_list = _extract_error_details(response)
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                if attempt < attempts - 1:
                    delay = (
                        retry_after
                        if retry_after is not None
                        else self.backoff_base * (2**attempt) + random.uniform(0.0, 0.25)
                    )
                    logger.warning(
                        "SentinelOne %s %s returned HTTP %d; retrying in %.2fs (%d/%d)",
                        method,
                        path,
                        status,
                        delay,
                        attempt + 1,
                        self.max_retries,
                    )
                    self._sleep(delay)
                    continue
                if status == 429:
                    raise SentinelOneRateLimitError(
                        f"SentinelOne rate limit exceeded (HTTP 429): {detail}",
                        status_code=429,
                        endpoint=path,
                        errors=err_list,
                        retry_after=retry_after,
                    )
                raise SentinelOneError(
                    f"SentinelOne server error (HTTP {status}): {detail}",
                    status_code=status,
                    endpoint=path,
                    errors=err_list,
                )

            if status >= 400:
                detail, err_list = _extract_error_details(response)
                raise SentinelOneError(
                    f"SentinelOne API error (HTTP {status}) on {path}: {detail}",
                    status_code=status,
                    endpoint=path,
                    errors=err_list,
                )

            if not response.content:
                return {"data": {}}
            try:
                parsed = response.json()
            except ValueError as exc:
                raise SentinelOneError(
                    f"Invalid JSON response from SentinelOne {path}: {exc}",
                    status_code=status,
                    endpoint=path,
                ) from exc
            if isinstance(parsed, dict):
                return parsed
            return {"data": parsed}

        raise SentinelOneError(f"SentinelOne request failed after retries: {path}", endpoint=path)

    def _paginate(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        limit: int = 100,
        max_pages: int = 20,
        nested_data_key: str | None = None,
    ) -> list[dict[str, Any]]:
        """Iterate SentinelOne cursor-paginated endpoints until exhausted or ``limit`` reached."""
        collected: list[dict[str, Any]] = []
        cursor: str | None = None
        target_limit = max(1, int(limit))
        pages = max(1, int(max_pages))
        base_params = dict(params or {})

        for _ in range(pages):
            remaining = target_limit - len(collected)
            if remaining <= 0:
                break
            page_params = dict(base_params)
            page_params["limit"] = min(100, remaining)
            if cursor:
                page_params["cursor"] = cursor

            payload = self._request("GET", path, params=page_params)
            raw_data = payload.get("data")
            items: list[Any]
            if isinstance(raw_data, list):
                items = raw_data
            elif isinstance(raw_data, dict) and nested_data_key:
                nested = raw_data.get(nested_data_key)
                items = nested if isinstance(nested, list) else []
            else:
                items = []

            for item in items:
                if isinstance(item, dict):
                    collected.append(item)
                    if len(collected) >= target_limit:
                        break

            pagination = payload.get("pagination")
            next_cursor = (
                pagination.get("nextCursor") if isinstance(pagination, dict) else None
            )
            if not next_cursor or not items or len(collected) >= target_limit:
                break
            cursor = str(next_cursor)

        return collected

    def _scope_params(
        self,
        *,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
    ) -> dict[str, Any]:
        """Build default account/site/group query parameters from explicit args or config."""
        params: dict[str, Any] = {}
        acc = _csv_param(account_ids) or self.account_id
        site = _csv_param(site_ids) or self.site_id
        grp = _csv_param(group_ids)
        if acc:
            params["accountIds"] = acc
        if site:
            params["siteIds"] = site
        if grp:
            params["groupIds"] = grp
        return params

    def _scope_filter_dict(
        self,
        *,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
    ) -> dict[str, Any]:
        """Build a JSON ``filter`` object for SentinelOne scoped POST/DELETE calls."""
        flt: dict[str, Any] = {}
        if account_ids is not None:
            flt["accountIds"] = _normalize_id_list(account_ids, field_name="account_ids")
        elif self.account_id:
            flt["accountIds"] = [self.account_id]
        if site_ids is not None:
            flt["siteIds"] = _normalize_id_list(site_ids, field_name="site_ids")
        elif self.site_id:
            flt["siteIds"] = [self.site_id]
        if group_ids is not None:
            flt["groupIds"] = _normalize_id_list(group_ids, field_name="group_ids")
        return flt

    # ------------------------------------------------------------------
    # Scope & Health
    # ------------------------------------------------------------------

    def check_connection(self) -> dict[str, Any]:
        """Verify SentinelOne API connectivity and token validity via ``/system/info``."""
        payload = self._request("GET", "system/info")
        data = payload.get("data")
        return data if isinstance(data, dict) else payload

    def list_accounts(
        self,
        *,
        query: str | None = None,
        limit: int = 100,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """List SentinelOne accounts visible to the configured API token."""
        params: dict[str, Any] = {}
        if query and query.strip():
            params["query"] = query.strip()
        return self._paginate("accounts", params=params, limit=limit, max_pages=max_pages)

    def list_sites(
        self,
        *,
        account_ids: Sequence[str] | str | None = None,
        query: str | None = None,
        limit: int = 100,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """List SentinelOne sites (handles both list and ``data.sites`` response shapes)."""
        params: dict[str, Any] = {}
        acc = _csv_param(account_ids) or self.account_id
        if acc:
            params["accountIds"] = acc
        if query and query.strip():
            params["query"] = query.strip()
        return self._paginate(
            "sites",
            params=params,
            limit=limit,
            max_pages=max_pages,
            nested_data_key="sites",
        )

    def list_groups(
        self,
        *,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        query: str | None = None,
        limit: int = 100,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """List SentinelOne endpoint groups."""
        params = self._scope_params(account_ids=account_ids, site_ids=site_ids)
        if query and query.strip():
            params["query"] = query.strip()
        return self._paginate("groups", params=params, limit=limit, max_pages=max_pages)

    # ------------------------------------------------------------------
    # Agents / Endpoints
    # ------------------------------------------------------------------

    def list_agents(
        self,
        *,
        query: str | None = None,
        computer_name: str | None = None,
        is_active: bool | None = None,
        infected: bool | None = None,
        network_status: str | None = None,
        os_types: Sequence[str] | str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
        limit: int = 100,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """List SentinelOne agents/endpoints with optional filters."""
        params = self._scope_params(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        if query and query.strip():
            params["query"] = query.strip()
        if computer_name and computer_name.strip():
            params["computerName__contains"] = computer_name.strip()
        if is_active is not None:
            params["isActive"] = str(bool(is_active)).lower()
        if infected is not None:
            params["infected"] = str(bool(infected)).lower()
        if network_status and network_status.strip():
            params["networkStatuses"] = network_status.strip()
        os_csv = _csv_param(os_types)
        if os_csv:
            params["osTypes"] = os_csv
        return self._paginate("agents", params=params, limit=limit, max_pages=max_pages)

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        """Fetch a single SentinelOne agent by ID."""
        clean_id = agent_id.strip()
        if not clean_id:
            raise ValueError("agent_id must be non-empty.")
        payload = self._request("GET", "agents", params={"ids": clean_id, "limit": 1})
        data = payload.get("data")
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return data[0]
        raise SentinelOneError(
            f"SentinelOne agent not found: {clean_id}",
            status_code=404,
            endpoint="agents",
        )

    def disconnect_agent(self, agent_ids: Sequence[str] | str) -> dict[str, Any]:
        """Network-isolate one or more SentinelOne endpoints."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        return self._request("POST", "agents/actions/disconnect", json_body={"filter": {"ids": ids}})

    def connect_agent(self, agent_ids: Sequence[str] | str) -> dict[str, Any]:
        """Reconnect one or more isolated SentinelOne endpoints to the network."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        return self._request("POST", "agents/actions/connect", json_body={"filter": {"ids": ids}})

    def initiate_scan(self, agent_ids: Sequence[str] | str) -> dict[str, Any]:
        """Initiate a full disk scan on one or more SentinelOne endpoints."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        return self._request(
            "POST", "agents/actions/initiate-scan", json_body={"filter": {"ids": ids}}
        )

    def abort_scan(self, agent_ids: Sequence[str] | str) -> dict[str, Any]:
        """Abort an in-progress scan on one or more SentinelOne endpoints."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        return self._request("POST", "agents/actions/abort-scan", json_body={"filter": {"ids": ids}})

    def reboot_agent(self, agent_ids: Sequence[str] | str) -> dict[str, Any]:
        """Restart one or more SentinelOne endpoints."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        return self._request(
            "POST", "agents/actions/restart-machine", json_body={"filter": {"ids": ids}}
        )

    def move_agents_to_site(
        self,
        agent_ids: Sequence[str] | str,
        target_site_id: str,
    ) -> dict[str, Any]:
        """Move one or more SentinelOne endpoints to a different site."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        clean_site = target_site_id.strip()
        if not clean_site:
            raise ValueError("target_site_id must be non-empty.")
        return self._request(
            "POST",
            "agents/actions/move-to-site",
            json_body={"filter": {"ids": ids}, "data": {"targetSiteId": clean_site}},
        )

    def uninstall_agent(self, agent_ids: Sequence[str] | str) -> dict[str, Any]:
        """Uninstall the SentinelOne agent from one or more endpoints."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        return self._request("POST", "agents/actions/uninstall", json_body={"filter": {"ids": ids}})

    def add_agent_tags(
        self,
        agent_ids: Sequence[str] | str,
        tags: Sequence[dict[str, Any] | str],
    ) -> dict[str, Any]:
        """Add tags to one or more SentinelOne endpoints."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        normalized_tags = _normalize_agent_tags(tags)
        return self._request(
            "POST",
            "agents/actions/manage-tags",
            json_body={
                "filter": {"ids": ids},
                "data": {"operation": "add", "tags": normalized_tags},
            },
        )

    def remove_agent_tags(
        self,
        agent_ids: Sequence[str] | str,
        tags: Sequence[dict[str, Any] | str],
    ) -> dict[str, Any]:
        """Remove tags from one or more SentinelOne endpoints."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        normalized_tags = _normalize_agent_tags(tags)
        return self._request(
            "POST",
            "agents/actions/manage-tags",
            json_body={
                "filter": {"ids": ids},
                "data": {"operation": "remove", "tags": normalized_tags},
            },
        )

    # ------------------------------------------------------------------
    # Threats
    # ------------------------------------------------------------------

    def list_threats(
        self,
        *,
        query: str | None = None,
        incident_statuses: Sequence[str] | str | None = None,
        analyst_verdicts: Sequence[str] | str | None = None,
        resolved: bool | None = None,
        computer_name: str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        limit: int = 100,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """List SentinelOne threats with optional incident/verdict/query filters."""
        params = self._scope_params(account_ids=account_ids, site_ids=site_ids)
        if query and query.strip():
            params["query"] = query.strip()
        if computer_name and computer_name.strip():
            params["computerNameContains"] = computer_name.strip()
        inc_csv = _csv_param(incident_statuses)
        if inc_csv:
            params["incidentStatuses"] = inc_csv
        verdict_csv = _csv_param(analyst_verdicts)
        if verdict_csv:
            params["analystVerdicts"] = verdict_csv
        if resolved is not None:
            params["resolved"] = str(bool(resolved)).lower()
        return self._paginate("threats", params=params, limit=limit, max_pages=max_pages)

    def get_threat_timeline(
        self,
        threat_id: str,
        *,
        limit: int = 100,
        max_pages: int = 5,
    ) -> list[dict[str, Any]]:
        """Retrieve timeline events for a specific SentinelOne threat."""
        clean_id = threat_id.strip()
        if not clean_id:
            raise ValueError("threat_id must be non-empty.")
        return self._paginate(
            f"threats/{clean_id}/timeline",
            limit=limit,
            max_pages=max_pages,
        )

    def update_threat_verdict(
        self,
        threat_ids: Sequence[str] | str,
        analyst_verdict: str,
    ) -> dict[str, Any]:
        """Set analyst verdict (``undefined|true_positive|false_positive|suspicious``)."""
        ids = _normalize_id_list(threat_ids, field_name="threat_ids")
        verdict = analyst_verdict.strip().lower()
        if verdict not in ANALYST_VERDICTS:
            raise ValueError(
                f"Invalid analyst_verdict {analyst_verdict!r}. "
                f"Expected one of: {', '.join(sorted(ANALYST_VERDICTS))}."
            )
        return self._request(
            "POST",
            "threats/analyst-verdict",
            json_body={"filter": {"ids": ids}, "data": {"analystVerdict": verdict}},
        )

    def update_threat_incident_status(
        self,
        threat_ids: Sequence[str] | str,
        incident_status: str,
    ) -> dict[str, Any]:
        """Set incident status (``unresolved|in_progress|resolved``) for threats."""
        ids = _normalize_id_list(threat_ids, field_name="threat_ids")
        status = incident_status.strip().lower()
        if status not in INCIDENT_STATUSES:
            raise ValueError(
                f"Invalid incident_status {incident_status!r}. "
                f"Expected one of: {', '.join(sorted(INCIDENT_STATUSES))}."
            )
        return self._request(
            "POST",
            "threats/incident",
            json_body={"filter": {"ids": ids}, "data": {"incidentStatus": status}},
        )

    def mitigate_threat(
        self,
        threat_ids: Sequence[str] | str,
        action: str,
    ) -> dict[str, Any]:
        """Execute a threat mitigation action (``kill|quarantine|remediate|rollback|un-quarantine``)."""
        ids = _normalize_id_list(threat_ids, field_name="threat_ids")
        clean_action = action.strip().lower()
        if clean_action not in MITIGATION_ACTIONS:
            raise ValueError(
                f"Invalid mitigation action {action!r}. "
                f"Expected one of: {', '.join(sorted(MITIGATION_ACTIONS))}."
            )
        return self._request(
            "POST",
            f"threats/mitigate/{clean_action}",
            json_body={"filter": {"ids": ids}},
        )

    def add_threat_to_exclusions(
        self,
        threat_ids: Sequence[str] | str,
        *,
        target_scope: str = "site",
        mode: str = "suppress",
        path_exclusion_type: str | None = None,
        description: str = "",
    ) -> dict[str, Any]:
        """Add one or more threats to SentinelOne exclusions."""
        ids = _normalize_id_list(threat_ids, field_name="threat_ids")
        data: dict[str, Any] = {
            "targetScope": target_scope.strip() or "site",
            "mode": mode.strip() or "suppress",
        }
        if path_exclusion_type:
            data["pathExclusionType"] = path_exclusion_type.strip()
        if description.strip():
            data["description"] = description.strip()
        return self._request(
            "POST",
            "threats/add-to-exclusions",
            json_body={"filter": {"ids": ids}, "data": data},
        )

    def add_threat_note(self, threat_id: str, text: str) -> dict[str, Any]:
        """Attach an analyst note to a SentinelOne threat."""
        clean_id = threat_id.strip()
        clean_text = text.strip()
        if not clean_id:
            raise ValueError("threat_id must be non-empty.")
        if not clean_text:
            raise ValueError("Note text must be non-empty.")
        return self._request(
            "POST",
            "threats/notes",
            json_body={"filter": {"ids": [clean_id]}, "data": {"text": clean_text}},
        )

    # ------------------------------------------------------------------
    # Exclusions
    # ------------------------------------------------------------------

    def list_exclusions(
        self,
        *,
        exclusion_type: str | None = None,
        os_types: Sequence[str] | str | None = None,
        query: str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        limit: int = 100,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """List SentinelOne exclusions."""
        params = self._scope_params(account_ids=account_ids, site_ids=site_ids)
        if exclusion_type and exclusion_type.strip():
            params["type"] = exclusion_type.strip()
        os_csv = _csv_param(os_types)
        if os_csv:
            params["osTypes"] = os_csv
        if query and query.strip():
            params["value__contains"] = query.strip()
        return self._paginate("exclusions", params=params, limit=limit, max_pages=max_pages)

    def create_exclusion(
        self,
        *,
        exclusion_type: str,
        os_type: str,
        value: str,
        description: str = "",
        mode: str = "suppress",
        path_exclusion_type: str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
    ) -> dict[str, Any]:
        """Create a SentinelOne exclusion."""
        clean_type = exclusion_type.strip().lower()
        if clean_type not in EXCLUSION_TYPES:
            raise ValueError(
                f"Invalid exclusion_type {exclusion_type!r}. "
                f"Expected one of: {', '.join(sorted(EXCLUSION_TYPES))}."
            )
        clean_os = os_type.strip().lower()
        if clean_os not in OS_TYPES:
            raise ValueError(
                f"Invalid os_type {os_type!r}. Expected one of: {', '.join(sorted(OS_TYPES))}."
            )
        clean_value = value.strip()
        if not clean_value:
            raise ValueError("Exclusion value must be non-empty.")

        data: dict[str, Any] = {
            "type": clean_type,
            "osType": clean_os,
            "value": clean_value,
            "description": description.strip(),
            "mode": mode.strip() or "suppress",
        }
        if path_exclusion_type:
            data["pathExclusionType"] = path_exclusion_type.strip()

        body: dict[str, Any] = {"data": data}
        flt = self._scope_filter_dict(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        if flt:
            body["filter"] = flt
        return self._request("POST", "exclusions", json_body=body)

    def delete_exclusions(
        self,
        ids: Sequence[str] | str,
        *,
        exclusion_type: str | None = None,
    ) -> dict[str, Any]:
        """Delete one or more SentinelOne exclusions by ID."""
        clean_ids = _normalize_id_list(ids, field_name="ids")
        data: dict[str, Any] = {"ids": clean_ids}
        if exclusion_type and exclusion_type.strip():
            data["type"] = exclusion_type.strip().lower()
        return self._request("DELETE", "exclusions", json_body={"data": data})

    # ------------------------------------------------------------------
    # Blocklist / Hash IOCs
    # ------------------------------------------------------------------

    def list_blocklist(
        self,
        *,
        query: str | None = None,
        os_types: Sequence[str] | str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        limit: int = 100,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """List SentinelOne SHA-1 blocklist (``black_hash``) entries."""
        params = self._scope_params(account_ids=account_ids, site_ids=site_ids)
        params["type"] = "black_hash"
        os_csv = _csv_param(os_types)
        if os_csv:
            params["osTypes"] = os_csv
        if query and query.strip():
            params["value__contains"] = query.strip()
        return self._paginate("restrictions", params=params, limit=limit, max_pages=max_pages)

    def add_to_blocklist(
        self,
        sha1_hash: str,
        *,
        os_type: str = "windows",
        description: str = "",
        source: str = "soclens",
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
    ) -> dict[str, Any]:
        """Add a SHA-1 hash IOC to the SentinelOne blocklist."""
        clean_hash = sha1_hash.strip().lower()
        if not _SHA1_RE.match(clean_hash):
            raise ValueError(
                f"Invalid SHA-1 hash {sha1_hash!r}. SentinelOne blocklist requires a 40-char hex SHA-1."
            )
        clean_os = os_type.strip().lower()
        if clean_os not in OS_TYPES:
            raise ValueError(
                f"Invalid os_type {os_type!r}. Expected one of: {', '.join(sorted(OS_TYPES))}."
            )

        body: dict[str, Any] = {
            "data": {
                "type": "black_hash",
                "value": clean_hash,
                "osType": clean_os,
                "description": description.strip(),
                "source": source.strip() or "soclens",
            }
        }
        flt = self._scope_filter_dict(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        if flt:
            body["filter"] = flt
        return self._request("POST", "restrictions", json_body=body)

    def remove_from_blocklist(self, ids: Sequence[str] | str) -> dict[str, Any]:
        """Remove one or more SHA-1 entries from the SentinelOne blocklist by ID."""
        clean_ids = _normalize_id_list(ids, field_name="ids")
        return self._request(
            "DELETE",
            "restrictions",
            json_body={"data": {"ids": clean_ids, "type": "black_hash"}},
        )

    # ------------------------------------------------------------------
    # Activities & Deep Visibility
    # ------------------------------------------------------------------

    def list_activities(
        self,
        *,
        activity_types: Sequence[str] | str | None = None,
        agent_ids: Sequence[str] | str | None = None,
        threat_ids: Sequence[str] | str | None = None,
        query: str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        limit: int = 100,
        max_pages: int = 5,
    ) -> list[dict[str, Any]]:
        """List SentinelOne audit/activity log entries."""
        params = self._scope_params(account_ids=account_ids, site_ids=site_ids)
        act_csv = _csv_param(activity_types)
        if act_csv:
            params["activityTypes"] = act_csv
        ag_csv = _csv_param(agent_ids)
        if ag_csv:
            params["agentIds"] = ag_csv
        th_csv = _csv_param(threat_ids)
        if th_csv:
            params["threatIds"] = th_csv
        if query and query.strip():
            params["primaryDescription__contains"] = query.strip()
        return self._paginate("activities", params=params, limit=limit, max_pages=max_pages)

    def create_dv_query(
        self,
        query: str,
        from_date: str,
        to_date: str,
        *,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
        query_type: str = "events",
    ) -> dict[str, Any]:
        """Initiate a SentinelOne Deep Visibility query."""
        clean_query = query.strip()
        if not clean_query:
            raise ValueError("Deep Visibility query must be non-empty.")
        clean_from = from_date.strip()
        clean_to = to_date.strip()
        if not clean_from or not clean_to:
            raise ValueError("from_date and to_date are required for Deep Visibility queries.")

        body: dict[str, Any] = {
            "query": clean_query,
            "fromDate": clean_from,
            "toDate": clean_to,
            "queryType": [query_type.strip() or "events"],
        }
        flt = self._scope_filter_dict(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        body.update(flt)
        return self._request("POST", "dv/init-query", json_body=body)

    def get_dv_query_status(self, query_id: str) -> dict[str, Any]:
        """Check the execution status of a SentinelOne Deep Visibility query."""
        clean_id = query_id.strip()
        if not clean_id:
            raise ValueError("query_id must be non-empty.")
        return self._request("GET", "dv/query-status", params={"queryId": clean_id})

    def get_dv_events(
        self,
        query_id: str,
        *,
        limit: int = 100,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """Retrieve events returned by a completed Deep Visibility query."""
        clean_id = query_id.strip()
        if not clean_id:
            raise ValueError("query_id must be non-empty.")
        return self._paginate(
            "dv/events",
            params={"queryId": clean_id},
            limit=limit,
            max_pages=max_pages,
        )


def _normalize_agent_tags(tags: Sequence[dict[str, Any] | str]) -> list[dict[str, Any]]:
    """Normalize agent tags from dicts or ``key=value`` strings into SentinelOne tag objects."""
    normalized: list[dict[str, Any]] = []
    for tag in tags:
        if isinstance(tag, dict):
            if tag:
                normalized.append(dict(tag))
        else:
            raw = str(tag).strip()
            if not raw:
                continue
            if "=" in raw:
                key, value = raw.split("=", 1)
                normalized.append({"key": key.strip(), "value": value.strip()})
            else:
                normalized.append({"key": raw, "value": ""})
    if not normalized:
        raise ValueError("At least one tag is required.")
    return normalized
