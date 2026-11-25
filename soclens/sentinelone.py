"""SentinelOne Management API v2.1 client for SOC endpoint & threat operations."""

from __future__ import annotations

import logging
import math
import random
import re
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter

from soclens.config import (
    ConfigurationError,
    ConfiguredSession,
    S1TierConfig,
    SentinelOneConfig,
    get_s1_tier_config,
    get_sentinelone_config,
    suppress_insecure_ssl_warnings,
)
from soclens.timezone import parse_iso_datetime

logger = logging.getLogger("soclens.sentinelone")

API_PREFIX = "/web/api/v2.1"
MAX_PAGE_SIZE: int = 100
SORT_ORDERS: frozenset[str] = frozenset({"asc", "desc"})
_TIMESTAMP_SORT_FIELDS: frozenset[str] = frozenset(
    {
        "createdAt",
        "updatedAt",
        "alertInfoCreatedAt",
        "alertInfoReportedAt",
        "lastActiveDate",
        "registeredAt",
        "dateJoined",
    }
)
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")

ANALYST_VERDICTS: frozenset[str] = frozenset(
    {"undefined", "true_positive", "false_positive", "suspicious"}
)
INCIDENT_STATUSES: frozenset[str] = frozenset({"unresolved", "in_progress", "resolved"})
MITIGATION_ACTIONS: frozenset[str] = frozenset(
    {
        "kill",
        "quarantine",
        "remediate",
        "rollback",
        "rollback-remediation",
        "un-quarantine",
        "unquarantine",
        "remove_macros",
        "restore_macros",
    }
)
_MITIGATION_ACTION_ENDPOINT_MAP: dict[str, str] = {
    "rollback": "rollback-remediation",
    "unquarantine": "un-quarantine",
}
EXCLUSION_TYPES: frozenset[str] = frozenset(
    {"path", "white_hash", "certificate", "browser", "file_type"}
)
EXCLUSION_MODES: frozenset[str] = frozenset(
    {
        "suppress",
        "suppress_dynamic_only",
        "suppress_dfi_only",
        "disable_in_process_monitor",
        "disable_in_process_monitor_deep",
        "disable_all_monitors",
        "disable_all_monitors_deep",
        "suppress_app_control",
        "suppress_drift_detection",
    }
)
EXCLUSION_ACTIONS: frozenset[str] = frozenset({"upload", "detect"})
PATH_EXCLUSION_TYPES: frozenset[str] = frozenset({"file", "folder", "subfolders"})
OS_TYPES: frozenset[str] = frozenset({"windows", "macos", "linux", "windows_legacy"})
SITE_TYPES: frozenset[str] = frozenset({"Paid", "Trial"})
SITE_SKUS: frozenset[str] = frozenset({"Core", "Control", "Complete"})
SITE_USAGE_TYPES: frozenset[str] = frozenset({"customer", "mssp", "ir"})
SITE_POLICY_SOURCES: frozenset[str] = frozenset(
    {"inherit_global", "copy_source_site", "custom"}
)
USER_SCOPES: frozenset[str] = frozenset({"tenant", "account", "site"})
CLOUD_ALERT_SEVERITIES: frozenset[str] = frozenset(
    {"Info", "Low", "Medium", "High", "Critical"}
)
CLOUD_ALERT_SCOPES: frozenset[str] = frozenset({"site", "account", "group", "global"})
ALERT_GROUPING_MODES: frozenset[str] = frozenset({"flat", "tier", "site", "tier_hash"})
MAX_EXCLUSION_CLONE_RPS: float = 15.0
EXCLUSION_DESCRIPTION_MAX_LEN: int = 500
_READONLY_SITE_POLICY_KEYS: frozenset[str] = frozenset(
    {
        "createdAt",
        "updatedAt",
        "userId",
        "userFullName",
        "inheritedFrom",
        "fwForNetworkQuarantineEnabled",
    }
)
_MUTATION_FILTER_SCOPE_KEYS: tuple[str, ...] = ("ids", "siteIds", "groupIds", "accountIds")
_FILTER_SCOPED_MUTATION_PATHS: frozenset[str] = frozenset(
    {
        "threats/incident",
        "threats/analyst-verdict",
        "threats/notes",
        "threats/add-to-exclusions",
        "cloud-detection/alerts/incident",
        "cloud-detection/alerts/analyst-verdict",
        "users/delete-users",
        "users/login/send-reset-password-email",
        "service-users/delete-service-users",
    }
)
_FILTER_SCOPED_MUTATION_PREFIXES: tuple[str, ...] = (
    "threats/mitigate/",
    "agents/actions/",
)


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
    if isinstance(ids, (bytes, bytearray)):
        raise ValueError(f"Bytes values are not valid for {field_name}.")
    raw_items: list[str]
    if isinstance(ids, str):
        raw_items = [part.strip() for part in ids.split(",")]
    else:
        raw_items = []
        for item in ids:
            if item is None:
                continue
            if isinstance(item, (bytes, bytearray)):
                raise ValueError(f"Bytes values are not valid for {field_name}.")
            raw_items.append(str(item).strip())
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


class _RatePacer:
    """Thread-safe request-rate pacer honoring ``stop_event`` cancellation."""

    def __init__(
        self,
        requests_per_second: float,
        *,
        stop_event: threading.Event,
    ) -> None:
        rps = float(requests_per_second)
        if not math.isfinite(rps) or rps <= 0:
            raise ValueError("requests_per_second must be a finite positive number.")
        self.requests_per_second = rps
        self.interval: float = 1.0 / self.requests_per_second
        self._stop_event = stop_event
        self._lock = threading.Lock()
        self._next_allowed: float = 0.0

    def acquire(self) -> None:
        """Reserve the next write slot and sleep via ``stop_event.wait`` if needed."""
        if self._stop_event.is_set():
            raise SentinelOneError("SentinelOne request cancelled.", reason="cancelled")
        with self._lock:
            now = time.monotonic()
            if self._next_allowed <= 0.0:
                self._next_allowed = now + self.interval
                return
            wait_seconds = self._next_allowed - now
            scheduled = max(now, self._next_allowed)
            self._next_allowed = scheduled + self.interval
        if wait_seconds > 0.0 and self._stop_event.wait(wait_seconds):
            raise SentinelOneError("SentinelOne request cancelled.", reason="cancelled")


def _has_nonempty_id_items(raw: Any) -> bool:
    """Return True if ``raw`` is a collection containing at least one non-empty ID."""
    return isinstance(raw, (list, tuple, set, frozenset)) and any(
        v is not None and str(v).strip() != "" for v in raw
    )


def _assert_safe_mutation_body(
    method: str,
    path: str,
    json_body: Mapping[str, Any] | None,
) -> None:
    """Forbid empty or unscoped mutation filters before sending any write request."""
    upper_method = method.upper()
    if upper_method not in {"POST", "PUT", "DELETE"}:
        return

    raw_path = path.split("?", 1)[0].split("#", 1)[0].strip()
    clean_path = (
        re.sub(r"/+", "/", raw_path)
        .strip("/")
        .lower()
        .removeprefix("web/api/v2.1/")
        .strip("/")
    )
    data = json_body.get("data") if isinstance(json_body, Mapping) else None
    if upper_method == "DELETE" and clean_path in {"exclusions", "restrictions"}:
        has_data_ids = isinstance(data, Mapping) and _has_nonempty_id_items(data.get("ids"))
        if not has_data_ids:
            raise ValueError(
                f"Refusing SentinelOne DELETE /{clean_path} without non-empty data.ids."
            )
    if upper_method == "POST" and clean_path in {"users/reset-2fa", "users/delete-2fa"}:
        has_data_ids = isinstance(data, Mapping) and _has_nonempty_id_items(data.get("ids"))
        if not has_data_ids:
            raise ValueError(
                f"Refusing SentinelOne POST /{clean_path} without non-empty data.ids."
            )

    requires_filter = (
        clean_path in _FILTER_SCOPED_MUTATION_PATHS
        or clean_path.startswith(_FILTER_SCOPED_MUTATION_PREFIXES)
        or (upper_method == "POST" and clean_path == "exclusions")
        or (upper_method in {"POST", "PUT"} and clean_path == "restrictions")
    )
    has_filter_key = isinstance(json_body, Mapping) and "filter" in json_body
    if not (requires_filter or has_filter_key):
        return

    flt = json_body.get("filter") if isinstance(json_body, Mapping) else None
    has_scope_ids = isinstance(flt, Mapping) and any(
        _has_nonempty_id_items(flt.get(key)) for key in _MUTATION_FILTER_SCOPE_KEYS
    )
    if not has_scope_ids:
        raise ValueError(
            "Refusing SentinelOne mutation with empty or unscoped filter; "
            "non-empty ids, siteIds, groupIds, or accountIds are required."
        )


def _format_cloned_description(
    description: str,
    source_label: str,
    *,
    max_len: int = EXCLUSION_DESCRIPTION_MAX_LEN,
) -> str:
    """Append ``[Cloned from <SRC>]`` provenance note, preserving ``<= max_len`` chars."""
    clean_source = source_label.strip() or "source"
    tag = f"[Cloned from {clean_source}]"
    base = description.strip()
    if not base:
        return tag[:max_len]
    if base.endswith(tag):
        if len(base) <= max_len:
            return base
        prefix = base[: -len(tag)].rstrip()
    else:
        prefix = base
    candidate = f"{prefix} {tag}".strip()
    if len(candidate) <= max_len:
        return candidate
    if len(tag) >= max_len:
        return tag[:max_len]
    available = max_len - len(tag) - 1  # space before tag
    if available <= 3:
        return tag[:max_len]
    return f"{prefix[: available - 3].rstrip()}... {tag}"


def _normalize_exclusion_dedup_key(item: Mapping[str, Any]) -> tuple[str, str, str, str]:
    """Compute a normalized deduplication key ``(type, osType, value, mode)``."""
    ex_type = str(item.get("type") or "").strip().lower()
    os_type = str(item.get("osType") or "").strip().lower()
    raw_value = str(item.get("value") or "").strip()
    if ex_type in {"white_hash", "certificate"}:
        norm_value = raw_value.lower()
    elif ex_type == "path":
        normalized_path = (
            raw_value.replace("/", "\\") if os_type in {"windows", "windows_legacy"} else raw_value
        )
        stripped = normalized_path.rstrip("\\/")
        norm_value = (stripped or normalized_path).casefold()
    else:
        norm_value = raw_value.casefold()
    mode = str(item.get("mode") or "").strip().lower()
    return (ex_type, os_type, norm_value, mode)


def _strip_readonly_policy_keys(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Return a mutable copy of a site policy without read-only response audit fields."""
    return {
        str(k): v
        for k, v in policy.items()
        if str(k) not in _READONLY_SITE_POLICY_KEYS
    }


def _sanitize_scope_roles(
    scope_roles: Sequence[Mapping[str, Any]] | None,
    *,
    scope: str,
    target_site_ids: Sequence[str] | str | None = None,
) -> list[dict[str, Any]]:
    """Strip read-only ``name``/``accountName`` fields from ``scopeRoles`` entries."""
    clean_scope = scope.strip().lower()
    target_ids: list[str] = []
    if target_site_ids is not None:
        target_ids = _normalize_id_list(target_site_ids, field_name="target_site_ids")

    sanitized: list[dict[str, Any]] = []
    if not scope_roles:
        return sanitized

    role_templates: list[dict[str, Any]] = []
    for entry in scope_roles:
        if not isinstance(entry, Mapping):
            continue
        item: dict[str, Any] = {}
        role_id = entry.get("roleId") or entry.get("roleID")
        if role_id is not None and str(role_id).strip():
            item["roleId"] = str(role_id).strip()
        elif entry.get("roleName"):
            item["roleName"] = str(entry["roleName"]).strip()
        elif isinstance(entry.get("roles"), Sequence) and not isinstance(
            entry.get("roles"), (str, bytes)
        ):
            item["roles"] = [str(r).strip() for r in entry["roles"] if str(r).strip()]
        if not item:
            continue
        if clean_scope != "tenant" and entry.get("id") is not None and str(entry.get("id")).strip():
            item["id"] = str(entry["id"]).strip()
        role_templates.append(item)

    if target_ids and clean_scope in {"site", "account"}:
        existing_by_id: dict[str, list[dict[str, Any]]] = {}
        for template in role_templates:
            tid = str(template.get("id") or "").strip()
            if tid:
                existing_by_id.setdefault(tid, []).append(template)

        seen_pairs: set[tuple[str, str]] = set()
        for target_id in target_ids:
            matched_templates = existing_by_id.get(target_id)
            templates_for_target = matched_templates if matched_templates else role_templates
            for template in templates_for_target:
                role_marker = str(
                    template.get("roleId") or template.get("roleName") or template.get("roles") or ""
                )
                pair = (target_id, role_marker)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                scoped_item = dict(template)
                scoped_item["id"] = target_id
                sanitized.append(scoped_item)
        return sanitized

    return role_templates


def _extract_record_timestamp(rec: Mapping[str, Any]) -> Any:
    """Extract the most relevant creation/activity timestamp from any SentinelOne record."""
    raw_tinfo = rec.get("threatInfo")
    tinfo: Mapping[str, Any] = raw_tinfo if isinstance(raw_tinfo, Mapping) else {}
    raw_ainfo = rec.get("alertInfo")
    ainfo: Mapping[str, Any] = raw_ainfo if isinstance(raw_ainfo, Mapping) else {}
    for candidate in (
        rec.get("createdAt"),
        tinfo.get("createdAt"),
        ainfo.get("createdAt"),
        ainfo.get("reportedAt"),
        rec.get("updatedAt"),
        tinfo.get("updatedAt"),
        rec.get("lastActiveDate"),
        rec.get("registeredAt"),
        rec.get("dateJoined"),
    ):
        if candidate is not None and str(candidate).strip():
            return candidate
    return None


def sort_s1_records_newest_first(
    records: Sequence[Mapping[str, Any]],
    *,
    descending: bool = True,
) -> list[dict[str, Any]]:
    """Return copies of SentinelOne records sorted by timestamp (newest-first by default).

    Records without parseable timestamps are placed after timestamped records while
    preserving their relative order.
    """
    copied = [dict(rec) for rec in records]
    if len(copied) <= 1:
        return copied

    def _sort_key(rec: dict[str, Any]) -> tuple[int, float]:
        parsed = parse_iso_datetime(_extract_record_timestamp(rec))
        if parsed is None:
            return (1, 0.0)
        ts = parsed[0].timestamp()
        return (0, -ts if descending else ts)

    copied.sort(key=_sort_key)
    return copied


def _apply_sort_params(
    params: dict[str, Any],
    *,
    sort_by: str | None,
    sort_order: str | None,
) -> tuple[str | None, str]:
    """Validate and apply SentinelOne ``sortBy`` and ``sortOrder`` query parameters."""
    clean_order = (sort_order if sort_order is not None else "desc").strip().lower()
    if clean_order not in SORT_ORDERS:
        raise ValueError(
            f"Invalid sort_order {sort_order!r}. Expected one of: {', '.join(sorted(SORT_ORDERS))}."
        )
    clean_by = sort_by.strip() if isinstance(sort_by, str) and sort_by.strip() else None
    if clean_by is not None:
        params["sortBy"] = clean_by
    params["sortOrder"] = clean_order
    return clean_by, clean_order


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
        tier_config: S1TierConfig | None = None,
        max_requests_per_second: float = MAX_EXCLUSION_CLONE_RPS,
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
        self._tier_config: S1TierConfig | None = tier_config
        max_rps = float(max_requests_per_second)
        if not math.isfinite(max_rps) or max_rps <= 0:
            raise ValueError("max_requests_per_second must be a finite positive number.")
        self.max_requests_per_second: float = min(max_rps, MAX_EXCLUSION_CLONE_RPS)
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

    @property
    def tier_config(self) -> S1TierConfig:
        """Return explicit or live-resolved ``S1TierConfig``."""
        if self._tier_config is not None:
            return self._tier_config
        return get_s1_tier_config()

    def classify_site(
        self,
        site_name: str,
        site_id: str | None = None,
    ) -> tuple[str, str | None, str | None]:
        """Classify a site into ``(tier, site_code, tenant_id)``."""
        return self.tier_config.classify_site(site_name, site_id=site_id)

    def enrich_sites_with_tiers(
        self,
        sites: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Attach ``tier``, ``siteCode``, and ``tenantId`` metadata to site dicts."""
        cfg = self.tier_config
        enriched: list[dict[str, Any]] = []
        for site in sites:
            item = dict(site)
            site_name = str(item.get("name") or item.get("siteName") or "")
            raw_id = item.get("id")
            site_id = str(raw_id).strip() if raw_id is not None else None
            tier, site_code, tenant_id = cfg.classify_site(site_name, site_id=site_id)
            item["tier"] = tier
            item["siteCode"] = site_code
            item["tenantId"] = tenant_id
            enriched.append(item)
        return enriched

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
        _assert_safe_mutation_body(method, path, json_body)

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
        limit: int | None = None,
        max_pages: int | None = None,
        nested_data_key: str | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Iterate SentinelOne cursor-paginated endpoints until exhausted or ``limit`` reached."""
        collected: list[dict[str, Any]] = []
        cursor: str | None = None
        target_limit: int | None = max(1, int(limit)) if limit is not None else None
        page_cap: int | None = max(1, int(max_pages)) if max_pages is not None else None
        base_params = dict(params or {})
        seen_cursors: set[str] = set()
        consecutive_empty_pages = 0
        page_count = 0

        while page_cap is None or page_count < page_cap:
            if target_limit is not None:
                remaining = target_limit - len(collected)
                if remaining <= 0:
                    break
                page_limit = min(MAX_PAGE_SIZE, remaining)
            else:
                page_limit = MAX_PAGE_SIZE

            page_params = dict(base_params)
            page_params["limit"] = page_limit
            if cursor:
                page_params["cursor"] = cursor

            payload = self._request("GET", path, params=page_params)
            page_count += 1

            raw_data = payload.get("data")
            items: list[Any]
            if isinstance(raw_data, list):
                items = raw_data
            elif isinstance(raw_data, dict) and nested_data_key:
                nested = raw_data.get(nested_data_key)
                items = nested if isinstance(nested, list) else []
            else:
                items = []

            page_added = 0
            for item in items:
                if isinstance(item, dict):
                    collected.append(item)
                    page_added += 1
                    if target_limit is not None and len(collected) >= target_limit:
                        break

            pagination = payload.get("pagination")
            total_items: int | None = None
            if isinstance(pagination, dict):
                raw_total = pagination.get("totalItems")
                if raw_total is not None and not isinstance(raw_total, bool):
                    try:
                        total_items = int(raw_total)
                    except (TypeError, ValueError):
                        total_items = None

            if on_page is not None:
                on_page(len(collected), total_items)

            if target_limit is not None and len(collected) >= target_limit:
                break

            raw_next = pagination.get("nextCursor") if isinstance(pagination, dict) else None
            next_cursor = str(raw_next).strip() if raw_next is not None else ""
            if not next_cursor or next_cursor.lower() == "null":
                break
            if next_cursor in seen_cursors:
                logger.warning(
                    "SentinelOne %s pagination repeated cursor %r; stopping to avoid loop.",
                    path,
                    next_cursor,
                )
                break
            seen_cursors.add(next_cursor)

            if page_added == 0:
                consecutive_empty_pages += 1
                if consecutive_empty_pages >= 5:
                    logger.warning(
                        "SentinelOne %s returned %d consecutive empty pages with nextCursor; stopping.",
                        path,
                        consecutive_empty_pages,
                    )
                    break
            else:
                consecutive_empty_pages = 0

            cursor = next_cursor

        sort_by = str(base_params.get("sortBy") or "").strip()
        if sort_by in _TIMESTAMP_SORT_FIELDS:
            descending = str(base_params.get("sortOrder") or "desc").strip().lower() != "asc"
            collected = sort_s1_records_newest_first(collected, descending=descending)

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
        if account_ids is None and site_ids is None and group_ids is None:
            if self.account_id:
                params["accountIds"] = self.account_id
            if self.site_id:
                params["siteIds"] = self.site_id
            return params
        acc = _csv_param(account_ids)
        site = _csv_param(site_ids)
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
        if account_ids is None and site_ids is None and group_ids is None:
            if self.account_id:
                flt["accountIds"] = [self.account_id]
            if self.site_id:
                flt["siteIds"] = [self.site_id]
            return flt
        if account_ids is not None:
            flt["accountIds"] = _normalize_id_list(account_ids, field_name="account_ids")
        if site_ids is not None:
            flt["siteIds"] = _normalize_id_list(site_ids, field_name="site_ids")
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
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """List SentinelOne accounts visible to the configured API token."""
        params: dict[str, Any] = {}
        if query and query.strip():
            params["query"] = query.strip()
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "accounts",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

    def list_sites(
        self,
        *,
        account_ids: Sequence[str] | str | None = None,
        query: str | None = None,
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """List SentinelOne sites (handles both list and ``data.sites`` response shapes)."""
        params: dict[str, Any] = {}
        acc = _csv_param(account_ids) if account_ids is not None else self.account_id
        if acc:
            params["accountIds"] = acc
        if query and query.strip():
            params["query"] = query.strip()
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "sites",
            params=params,
            limit=limit,
            max_pages=max_pages,
            nested_data_key="sites",
            on_page=on_page,
        )

    def get_site(self, site_id: str) -> dict[str, Any]:
        """Fetch a single SentinelOne site by ID."""
        clean_id = site_id.strip()
        if not clean_id:
            raise ValueError("site_id must be non-empty.")
        payload = self._request("GET", f"sites/{clean_id}")
        data = payload.get("data")
        return data if isinstance(data, dict) else payload

    def create_site(
        self,
        *,
        name: str,
        account_id: str | None = None,
        site_type: str = "Paid",
        total_licenses: int | None = None,
        unlimited_licenses: bool | None = None,
        unlimited_expiration: bool = True,
        expiration: str | None = None,
        inherit_account_expiration: bool | None = None,
        sku: str | None = None,
        suite: str | None = None,
        description: str = "",
        inherits: bool = True,
        usage_type: str | None = None,
        external_id: str | None = None,
        policy: Mapping[str, Any] | None = None,
        copy_policy_from_site_id: str | None = None,
        clone_exclusions_from_site_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a SentinelOne site with optional policy copy and exclusion cloning."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Site name must be non-empty.")
        clean_type = site_type.strip()
        if clean_type not in SITE_TYPES:
            raise ValueError(
                f"Invalid site_type {site_type!r}. Expected one of: {', '.join(sorted(SITE_TYPES))}."
            )
        resolved_sku = (sku or suite or "").strip() or None
        if resolved_sku is not None and resolved_sku not in SITE_SKUS:
            raise ValueError(
                f"Invalid sku/suite {resolved_sku!r}. Expected one of: {', '.join(sorted(SITE_SKUS))}."
            )
        if usage_type is not None and usage_type.strip() not in SITE_USAGE_TYPES:
            raise ValueError(
                f"Invalid usage_type {usage_type!r}. "
                f"Expected one of: {', '.join(sorted(SITE_USAGE_TYPES))}."
            )

        data: dict[str, Any] = {
            "name": clean_name,
            "siteType": clean_type,
            "inherits": bool(inherits),
            "unlimitedExpiration": bool(unlimited_expiration),
        }
        resolved_acc = (account_id or self.account_id or "").strip()
        if resolved_acc:
            data["accountId"] = resolved_acc
        if description.strip():
            data["description"] = description.strip()
        if total_licenses is not None:
            data["totalLicenses"] = int(total_licenses)
        if unlimited_licenses is not None:
            data["unlimitedLicenses"] = bool(unlimited_licenses)
        if expiration and expiration.strip():
            data["expiration"] = expiration.strip()
        if inherit_account_expiration is not None:
            data["inheritAccountExpiration"] = bool(inherit_account_expiration)
        if resolved_sku is not None:
            data["sku"] = resolved_sku
            data["suite"] = resolved_sku
        if usage_type and usage_type.strip():
            data["usageType"] = usage_type.strip()
        if external_id and external_id.strip():
            data["externalId"] = external_id.strip()

        if policy is not None:
            data["policy"] = _strip_readonly_policy_keys(policy)
        elif copy_policy_from_site_id and copy_policy_from_site_id.strip():
            src_policy = self.get_site_policy(copy_policy_from_site_id.strip())
            if src_policy:
                data["policy"] = _strip_readonly_policy_keys(src_policy)
                data["inherits"] = False

        payload = self._request("POST", "sites", json_body={"data": data})
        raw_site = payload.get("data")
        created_site = dict(raw_site) if isinstance(raw_site, dict) else dict(payload)
        created_site_id = str(created_site.get("id") or "").strip()

        if (
            clone_exclusions_from_site_id
            and clone_exclusions_from_site_id.strip()
            and created_site_id
        ):
            clone_result = self.clone_exclusions(
                clone_exclusions_from_site_id.strip(),
                created_site_id,
                dry_run=False,
            )
            created_site["_clonedExclusions"] = clone_result
        return created_site

    def duplicate_site(
        self,
        source_site_id: str | int,
        name: str,
        *,
        policy_source: str = "copy_source_site",
        copy_users: bool = False,
        total_licenses: int | None = None,
        unlimited_licenses: bool | None = None,
        policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Duplicate an existing SentinelOne site (``sourceSiteId`` coerced to ``int``)."""
        if isinstance(source_site_id, bool):
            raise ValueError("source_site_id must be a numeric site ID.")
        clean_src = str(source_site_id).strip()
        if not clean_src or not clean_src.isdigit():
            raise ValueError(f"source_site_id must be numeric for duplicate_site: {source_site_id!r}")
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("New site name must be non-empty.")
        clean_policy_source = policy_source.strip()
        if clean_policy_source not in SITE_POLICY_SOURCES:
            raise ValueError(
                f"Invalid policy_source {policy_source!r}. "
                f"Expected one of: {', '.join(sorted(SITE_POLICY_SOURCES))}."
            )

        data: dict[str, Any] = {
            "sourceSiteId": int(clean_src),
            "name": clean_name,
            "policySource": clean_policy_source,
            "copyUsers": bool(copy_users),
        }
        if total_licenses is not None:
            data["totalLicenses"] = int(total_licenses)
        if unlimited_licenses is not None:
            data["unlimitedLicenses"] = bool(unlimited_licenses)
        if policy is not None:
            data["policy"] = _strip_readonly_policy_keys(policy)

        payload = self._request("POST", "sites/duplicate-site", json_body={"data": data})
        raw_site = payload.get("data")
        return dict(raw_site) if isinstance(raw_site, dict) else payload

    def update_site(self, site_id: str, **fields: Any) -> dict[str, Any]:
        """Update properties on an existing SentinelOne site."""
        clean_id = site_id.strip()
        if not clean_id:
            raise ValueError("site_id must be non-empty.")
        field_alias_map = {
            "site_type": "siteType",
            "total_licenses": "totalLicenses",
            "unlimited_licenses": "unlimitedLicenses",
            "unlimited_expiration": "unlimitedExpiration",
            "inherit_account_expiration": "inheritAccountExpiration",
            "external_id": "externalId",
            "usage_type": "usageType",
        }
        data: dict[str, Any] = {}
        for key, value in fields.items():
            if value is None:
                continue
            api_key = field_alias_map.get(key, key)
            if api_key == "policy" and isinstance(value, Mapping):
                data["policy"] = _strip_readonly_policy_keys(value)
            else:
                data[api_key] = value
        if not data:
            raise ValueError("At least one field must be provided to update_site.")
        payload = self._request("PUT", f"sites/{clean_id}", json_body={"data": data})
        raw_site = payload.get("data")
        return dict(raw_site) if isinstance(raw_site, dict) else payload

    def expire_site(self, site_id: str) -> dict[str, Any]:
        """Expire a SentinelOne site immediately."""
        clean_id = site_id.strip()
        if not clean_id:
            raise ValueError("site_id must be non-empty.")
        return self._request("POST", f"sites/{clean_id}/expire-now", json_body={})

    def reactivate_site(
        self,
        site_id: str,
        *,
        unlimited: bool = True,
        expiration: str | None = None,
    ) -> dict[str, Any]:
        """Reactivate an expired SentinelOne site."""
        clean_id = site_id.strip()
        if not clean_id:
            raise ValueError("site_id must be non-empty.")
        data: dict[str, Any] = {"unlimited": bool(unlimited)}
        if expiration and expiration.strip():
            data["expiration"] = expiration.strip()
        return self._request("PUT", f"sites/{clean_id}/reactivate", json_body={"data": data})

    def regenerate_site_key(self, site_id: str) -> dict[str, Any]:
        """Regenerate a SentinelOne site's registration token."""
        clean_id = site_id.strip()
        if not clean_id:
            raise ValueError("site_id must be non-empty.")
        return self._request("PUT", f"sites/{clean_id}/regenerate-key", json_body={})

    def rotate_site_token(self, site_id: str) -> dict[str, Any]:
        """Alias for ``regenerate_site_key``."""
        return self.regenerate_site_key(site_id)

    def get_site_token(self, site_id: str) -> dict[str, Any]:
        """Fetch a SentinelOne site's agent registration token."""
        clean_id = site_id.strip()
        if not clean_id:
            raise ValueError("site_id must be non-empty.")
        return self._request("GET", f"sites/{clean_id}/token")

    def get_site_policy(self, site_id: str) -> dict[str, Any]:
        """Fetch the effective policy configuration for a SentinelOne site."""
        clean_id = site_id.strip()
        if not clean_id:
            raise ValueError("site_id must be non-empty.")
        payload = self._request("GET", f"sites/{clean_id}/policy")
        data = payload.get("data")
        return dict(data) if isinstance(data, dict) else payload

    def update_site_policy(
        self,
        site_id: str,
        policy: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Update a SentinelOne site policy, stripping read-only audit metadata."""
        clean_id = site_id.strip()
        if not clean_id:
            raise ValueError("site_id must be non-empty.")
        cleaned_policy = _strip_readonly_policy_keys(policy)
        if not cleaned_policy:
            raise ValueError("Site policy payload must be non-empty.")
        payload = self._request(
            "PUT",
            f"sites/{clean_id}/policy",
            json_body={"data": cleaned_policy},
        )
        data = payload.get("data")
        return dict(data) if isinstance(data, dict) else payload

    def revert_site_policy(self, site_id: str) -> dict[str, Any]:
        """Revert a SentinelOne site policy to inherit from its parent account."""
        clean_id = site_id.strip()
        if not clean_id:
            raise ValueError("site_id must be non-empty.")
        return self._request("PUT", f"sites/{clean_id}/revert-policy", json_body={})

    def delete_site(
        self,
        site_id: str,
        *,
        confirm_site_name: str | None = None,
        expected_site_name: str | None = None,
    ) -> dict[str, Any]:
        """Delete a SentinelOne site by ID (with optional exact-name confirmation check)."""
        clean_id = site_id.strip()
        if not clean_id:
            raise ValueError("site_id must be non-empty.")
        if expected_site_name is not None and confirm_site_name != expected_site_name:
            raise ValueError(
                f"Site deletion confirmation name mismatch for {expected_site_name!r}."
            )
        return self._request("DELETE", f"sites/{clean_id}")

    def list_groups(
        self,
        *,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        query: str | None = None,
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """List SentinelOne endpoint groups."""
        params = self._scope_params(account_ids=account_ids, site_ids=site_ids)
        if query and query.strip():
            params["query"] = query.strip()
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "groups",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

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
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
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
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "agents",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

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

    def fetch_agent_logs(
        self,
        agent_ids: Sequence[str] | str,
        *,
        agent_logs: bool = True,
        customer_facing_logs: bool = True,
        platform_logs: bool = False,
    ) -> dict[str, Any]:
        """Request diagnostic logs from one or more SentinelOne endpoints."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        return self._request(
            "POST",
            "agents/actions/fetch-logs",
            json_body={
                "filter": {"ids": ids},
                "data": {
                    "agentLogs": bool(agent_logs),
                    "customerFacingLogs": bool(customer_facing_logs),
                    "platformLogs": bool(platform_logs),
                },
            },
        )

    def fetch_logs(
        self,
        agent_ids: Sequence[str] | str,
        *,
        agent_logs: bool = True,
        customer_facing_logs: bool = True,
        platform_logs: bool = False,
    ) -> dict[str, Any]:
        """Alias for ``fetch_agent_logs``."""
        return self.fetch_agent_logs(
            agent_ids,
            agent_logs=agent_logs,
            customer_facing_logs=customer_facing_logs,
            platform_logs=platform_logs,
        )

    def decommission_agents(self, agent_ids: Sequence[str] | str) -> dict[str, Any]:
        """Decommission one or more offline/retired SentinelOne endpoints."""
        ids = _normalize_id_list(agent_ids, field_name="agent_ids")
        return self._request(
            "POST",
            "agents/actions/decommission",
            json_body={"filter": {"ids": ids}},
        )

    def decommission(self, agent_ids: Sequence[str] | str) -> dict[str, Any]:
        """Alias for ``decommission_agents``."""
        return self.decommission_agents(agent_ids)

    def count_agents(
        self,
        *,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
        is_active: bool | None = None,
        infected: bool | None = None,
    ) -> int:
        """Count matching SentinelOne agents without fetching full agent records."""
        params = self._scope_params(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        if is_active is not None:
            params["isActive"] = str(bool(is_active)).lower()
        if infected is not None:
            params["infected"] = str(bool(infected)).lower()
        payload = self._request("GET", "agents/count", params=params)
        data = payload.get("data")
        if isinstance(data, dict):
            return int(data.get("total", 0) or 0)
        return 0

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
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
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
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "threats",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

    def get_threat_timeline(
        self,
        threat_id: str,
        *,
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve timeline events for a specific SentinelOne threat."""
        clean_id = threat_id.strip()
        if not clean_id:
            raise ValueError("threat_id must be non-empty.")
        params: dict[str, Any] = {}
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            f"threats/{clean_id}/timeline",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
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
        endpoint_action = _MITIGATION_ACTION_ENDPOINT_MAP.get(clean_action, clean_action)
        return self._request(
            "POST",
            f"threats/mitigate/{endpoint_action}",
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
    # Cloud / STAR Alerts, Normalization & Grouping
    # ------------------------------------------------------------------

    def list_cloud_alerts(
        self,
        *,
        query: str | None = None,
        incident_statuses: Sequence[str] | str | None = None,
        analyst_verdicts: Sequence[str] | str | None = None,
        severities: Sequence[str] | str | None = None,
        scopes: Sequence[str] | str | None = None,
        os_types: Sequence[str] | str | None = None,
        rule_name: str | None = None,
        computer_name: str | None = None,
        sha1: str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
        ids: Sequence[str] | str | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        sort_by: str | None = "alertInfoCreatedAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """List SentinelOne Cloud/STAR detection alerts (``/cloud-detection/alerts``)."""
        params = self._scope_params(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        ids_csv = _csv_param(ids)
        if ids_csv:
            params["ids"] = ids_csv
        if query and query.strip():
            params["query"] = query.strip()
        if rule_name and rule_name.strip():
            params["ruleName__contains"] = rule_name.strip()
        if computer_name and computer_name.strip():
            params["origAgentName__contains"] = computer_name.strip()
        if sha1 and sha1.strip():
            params["sourceProcessFileHashSha1__contains"] = sha1.strip()
        if created_after and created_after.strip():
            params["createdAt__gte"] = created_after.strip()
        if created_before and created_before.strip():
            params["createdAt__lte"] = created_before.strip()

        if incident_statuses is not None:
            raw_statuses = _normalize_id_list(incident_statuses, field_name="incident_statuses")
            normalized_statuses: list[str] = []
            for st in raw_statuses:
                low = st.lower()
                if low not in INCIDENT_STATUSES:
                    raise ValueError(
                        f"Invalid incident_status {st!r}. "
                        f"Expected one of: {', '.join(sorted(INCIDENT_STATUSES))}."
                    )
                normalized_statuses.append(low.upper())
            params["incidentStatus"] = ",".join(normalized_statuses)

        if analyst_verdicts is not None:
            raw_verdicts = _normalize_id_list(analyst_verdicts, field_name="analyst_verdicts")
            normalized_verdicts: list[str] = []
            for v in raw_verdicts:
                low = v.lower()
                if low not in ANALYST_VERDICTS:
                    raise ValueError(
                        f"Invalid analyst_verdict {v!r}. "
                        f"Expected one of: {', '.join(sorted(ANALYST_VERDICTS))}."
                    )
                normalized_verdicts.append(low.upper())
            params["analystVerdict"] = ",".join(normalized_verdicts)

        if severities is not None:
            raw_sevs = _normalize_id_list(severities, field_name="severities")
            normalized_sevs: list[str] = []
            for sev in raw_sevs:
                titled = sev.strip().capitalize()
                if titled not in CLOUD_ALERT_SEVERITIES:
                    raise ValueError(
                        f"Invalid severity {sev!r}. "
                        f"Expected one of: {', '.join(sorted(CLOUD_ALERT_SEVERITIES))}."
                    )
                normalized_sevs.append(titled)
            params["severity"] = ",".join(normalized_sevs)

        if scopes is not None:
            raw_scopes = _normalize_id_list(scopes, field_name="scopes")
            normalized_scopes: list[str] = []
            for sc in raw_scopes:
                low = sc.lower()
                if low not in CLOUD_ALERT_SCOPES:
                    raise ValueError(
                        f"Invalid scope {sc!r}. "
                        f"Expected one of: {', '.join(sorted(CLOUD_ALERT_SCOPES))}."
                    )
                normalized_scopes.append(low)
            params["scopes"] = ",".join(normalized_scopes)

        os_csv = _csv_param(os_types)
        if os_csv:
            params["osType"] = os_csv

        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "cloud-detection/alerts",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

    def update_cloud_alert_verdict(
        self,
        alert_ids: Sequence[str] | str,
        analyst_verdict: str,
    ) -> dict[str, Any]:
        """Set analyst verdict on one or more Cloud/STAR alerts."""
        ids = _normalize_id_list(alert_ids, field_name="alert_ids")
        verdict = analyst_verdict.strip().lower()
        if verdict not in ANALYST_VERDICTS:
            raise ValueError(
                f"Invalid analyst_verdict {analyst_verdict!r}. "
                f"Expected one of: {', '.join(sorted(ANALYST_VERDICTS))}."
            )
        return self._request(
            "POST",
            "cloud-detection/alerts/analyst-verdict",
            json_body={"filter": {"ids": ids}, "data": {"analystVerdict": verdict.upper()}},
        )

    def update_cloud_alert_incident_status(
        self,
        alert_ids: Sequence[str] | str,
        incident_status: str,
    ) -> dict[str, Any]:
        """Set incident status on one or more Cloud/STAR alerts."""
        ids = _normalize_id_list(alert_ids, field_name="alert_ids")
        status = incident_status.strip().lower()
        if status not in INCIDENT_STATUSES:
            raise ValueError(
                f"Invalid incident_status {incident_status!r}. "
                f"Expected one of: {', '.join(sorted(INCIDENT_STATUSES))}."
            )
        return self._request(
            "POST",
            "cloud-detection/alerts/incident",
            json_body={"filter": {"ids": ids}, "data": {"incidentStatus": status.upper()}},
        )

    def normalize_alert(
        self,
        record: Mapping[str, Any],
        *,
        source_kind: str | None = None,
        site_lookup: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Normalize an endpoint threat or Cloud/STAR alert with tier & tenant metadata."""
        raw_alert_info = record.get("alertInfo")
        alert_info: Mapping[str, Any] = raw_alert_info if isinstance(raw_alert_info, Mapping) else {}
        raw_rule_info = record.get("ruleInfo")
        rule_info: Mapping[str, Any] = raw_rule_info if isinstance(raw_rule_info, Mapping) else {}
        raw_threat_info = record.get("threatInfo")
        threat_info: Mapping[str, Any] = (
            raw_threat_info if isinstance(raw_threat_info, Mapping) else {}
        )
        raw_agent_rt = record.get("agentRealtimeInfo")
        agent_rt: Mapping[str, Any] = raw_agent_rt if isinstance(raw_agent_rt, Mapping) else {}
        raw_agent_det = record.get("agentDetectionInfo")
        agent_det: Mapping[str, Any] = raw_agent_det if isinstance(raw_agent_det, Mapping) else {}
        raw_proc = record.get("sourceProcessInfo")
        proc_info: Mapping[str, Any] = raw_proc if isinstance(raw_proc, Mapping) else {}

        kind = source_kind or ("cloud_alert" if (alert_info or rule_info) else "threat")
        rec_id = str(
            record.get("id")
            or alert_info.get("alertId")
            or threat_info.get("threatId")
            or ""
        ).strip()

        site_id = str(
            agent_rt.get("siteId")
            or agent_det.get("siteId")
            or record.get("siteId")
            or ""
        ).strip()
        site_name = str(
            agent_rt.get("siteName")
            or agent_det.get("siteName")
            or record.get("siteName")
            or ""
        ).strip()
        account_id = str(
            agent_rt.get("accountId")
            or agent_det.get("accountId")
            or record.get("accountId")
            or ""
        ).strip()

        if site_lookup and site_id and site_id in site_lookup:
            site_entry = site_lookup[site_id]
            if not site_name:
                site_name = str(site_entry.get("name") or "").strip()
            if not account_id:
                account_id = str(site_entry.get("accountId") or "").strip()

        tier, site_code, tenant_id = self.classify_site(site_name, site_id=site_id or None)

        title = str(
            rule_info.get("name")
            or threat_info.get("threatName")
            or record.get("threatName")
            or record.get("title")
            or rec_id
        ).strip()
        severity = str(
            rule_info.get("severity")
            or threat_info.get("confidenceLevel")
            or record.get("severity")
            or "-"
        ).strip()
        confidence = str(
            threat_info.get("confidenceLevel")
            or rule_info.get("severity")
            or record.get("confidenceLevel")
            or ""
        ).strip()
        incident_status = str(
            alert_info.get("incidentStatus")
            or threat_info.get("incidentStatus")
            or record.get("incidentStatus")
            or "unresolved"
        ).strip().lower()
        analyst_verdict = str(
            alert_info.get("analystVerdict")
            or threat_info.get("analystVerdict")
            or record.get("analystVerdict")
            or "undefined"
        ).strip().lower()
        mitigation_status = str(
            threat_info.get("mitigationStatus")
            or record.get("mitigationStatus")
            or ("cloud_alert" if kind == "cloud_alert" else "-")
        ).strip()
        computer_name = str(
            agent_rt.get("agentComputerName")
            or agent_det.get("agentComputerName")
            or record.get("agentComputerName")
            or record.get("computerName")
            or "-"
        ).strip()
        sha1 = str(
            threat_info.get("sha1")
            or proc_info.get("fileHashSha1")
            or record.get("sha1")
            or ""
        ).strip().lower()
        sha256 = str(
            threat_info.get("sha256")
            or proc_info.get("fileHashSha256")
            or record.get("sha256")
            or ""
        ).strip().lower()
        file_path = str(
            threat_info.get("filePath")
            or proc_info.get("filePath")
            or record.get("filePath")
            or ""
        ).strip()
        command_line = str(
            proc_info.get("commandline")
            or threat_info.get("originatorProcess")
            or record.get("commandLine")
            or ""
        ).strip()
        username = str(
            proc_info.get("user")
            or agent_rt.get("agentLastLoggedInUserName")
            or record.get("username")
            or ""
        ).strip()
        created_at = str(
            alert_info.get("createdAt")
            or threat_info.get("createdAt")
            or record.get("createdAt")
            or ""
        ).strip()

        return {
            "id": rec_id,
            "recordType": kind,
            "title": title,
            "severity": severity,
            "confidenceLevel": confidence,
            "incidentStatus": incident_status,
            "analystVerdict": analyst_verdict,
            "mitigationStatus": mitigation_status,
            "siteId": site_id,
            "siteName": site_name,
            "accountId": account_id,
            "tier": tier,
            "siteCode": site_code,
            "tenantId": tenant_id,
            "computerName": computer_name,
            "sha1": sha1,
            "sha256": sha256,
            "filePath": file_path,
            "commandLine": command_line,
            "username": username,
            "createdAt": created_at,
            "raw": dict(record),
        }

    def list_unified_alerts(
        self,
        *,
        include_threats: bool = True,
        include_cloud_alerts: bool = True,
        query: str | None = None,
        incident_statuses: Sequence[str] | str | None = None,
        analyst_verdicts: Sequence[str] | str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        sites: Sequence[Mapping[str, Any]] | None = None,
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch and normalize endpoint threats and/or Cloud/STAR alerts together."""
        clean_order = sort_order.strip().lower()
        if clean_order not in SORT_ORDERS:
            raise ValueError(
                f"Invalid sort_order {sort_order!r}. Expected one of: {', '.join(sorted(SORT_ORDERS))}."
            )

        site_lookup: dict[str, Mapping[str, Any]] = {}
        if sites:
            for site in sites:
                sid = str(site.get("id") or "").strip()
                if sid:
                    site_lookup[sid] = site

        loaded_counts = {"threats": 0, "cloud": 0}
        total_counts: dict[str, int | None] = {"threats": None, "cloud": None}

        def _emit_unified_progress(source: str, count: int, total: int | None) -> None:
            loaded_counts[source] = count
            total_counts[source] = total
            if on_page is None:
                return
            combined_loaded = loaded_counts["threats"] + loaded_counts["cloud"]
            known_totals = [t for t in total_counts.values() if t is not None]
            combined_total = sum(known_totals) if known_totals else None
            on_page(combined_loaded, combined_total)

        unified: list[dict[str, Any]] = []
        if include_threats:
            threats = self.list_threats(
                query=query,
                incident_statuses=incident_statuses,
                analyst_verdicts=analyst_verdicts,
                account_ids=account_ids,
                site_ids=site_ids,
                sort_order=clean_order,
                limit=limit,
                max_pages=max_pages,
                on_page=(
                    (lambda cnt, tot: _emit_unified_progress("threats", cnt, tot))
                    if on_page is not None
                    else None
                ),
            )
            for item in threats:
                unified.append(
                    self.normalize_alert(item, source_kind="threat", site_lookup=site_lookup)
                )
        if include_cloud_alerts:
            cloud = self.list_cloud_alerts(
                query=query,
                incident_statuses=incident_statuses,
                analyst_verdicts=analyst_verdicts,
                account_ids=account_ids,
                site_ids=site_ids,
                sort_order=clean_order,
                limit=limit,
                max_pages=max_pages,
                on_page=(
                    (lambda cnt, tot: _emit_unified_progress("cloud", cnt, tot))
                    if on_page is not None
                    else None
                ),
            )
            for item in cloud:
                unified.append(
                    self.normalize_alert(item, source_kind="cloud_alert", site_lookup=site_lookup)
                )
        return sort_s1_records_newest_first(unified, descending=(clean_order == "desc"))

    def group_alerts(
        self,
        alerts: Sequence[Mapping[str, Any]],
        *,
        mode: str = "flat",
    ) -> dict[str, list[dict[str, Any]]]:
        """Group alerts under ``flat``, ``tier``, ``site``, or ``tier_hash``."""
        clean_mode = mode.strip().lower()
        if clean_mode not in ALERT_GROUPING_MODES:
            raise ValueError(
                f"Invalid grouping mode {mode!r}. "
                f"Expected one of: {', '.join(sorted(ALERT_GROUPING_MODES))}."
            )
        normalized = [
            dict(a)
            if ("tier" in a and "recordType" in a and "sha1" in a)
            else self.normalize_alert(a)
            for a in alerts
        ]
        if not normalized:
            return {}
        if clean_mode == "flat":
            return {"All Alerts": normalized}

        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in normalized:
            tier = str(item.get("tier") or self.tier_config.default_tier)
            site_label = str(item.get("siteName") or item.get("siteId") or "Unknown Site")
            sha1 = str(item.get("sha1") or "").strip().lower()
            if clean_mode == "tier":
                key = tier
            elif clean_mode == "site":
                key = site_label
            else:  # tier_hash — strictly partitioned per tier
                key = f"{tier} | {sha1 or 'no-sha1'}"
            grouped.setdefault(key, []).append(item)
        return grouped

    # ------------------------------------------------------------------
    # Exclusions & Site-to-Site Cloning
    # ------------------------------------------------------------------

    def list_exclusions(
        self,
        *,
        exclusion_type: str | None = None,
        os_types: Sequence[str] | str | None = None,
        query: str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
        include_parents: bool | None = None,
        include_children: bool | None = None,
        modes: Sequence[str] | str | None = None,
        scopes: Sequence[str] | str | None = None,
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """List SentinelOne exclusions with optional hierarchy/mode/scope filters."""
        params = self._scope_params(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        if exclusion_type and exclusion_type.strip():
            params["type"] = exclusion_type.strip()
        os_csv = _csv_param(os_types)
        if os_csv:
            params["osTypes"] = os_csv
        if query and query.strip():
            params["value__contains"] = query.strip()
        if include_parents is not None:
            params["includeParents"] = str(bool(include_parents)).lower()
        if include_children is not None:
            params["includeChildren"] = str(bool(include_children)).lower()
        modes_csv = _csv_param(modes)
        if modes_csv:
            params["modes"] = modes_csv
        scopes_csv = _csv_param(scopes)
        if scopes_csv:
            params["scopes"] = scopes_csv
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "exclusions",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

    def create_exclusion(
        self,
        *,
        exclusion_type: str,
        os_type: str,
        value: str,
        description: str = "",
        mode: str = "suppress",
        path_exclusion_type: str | None = None,
        actions: Sequence[str] | str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
    ) -> dict[str, Any]:
        """Create a scoped SentinelOne exclusion."""
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
        clean_mode = (mode or "suppress").strip().lower()
        if clean_mode not in EXCLUSION_MODES:
            raise ValueError(
                f"Invalid exclusion mode {mode!r}. "
                f"Expected one of: {', '.join(sorted(EXCLUSION_MODES))}."
            )

        data: dict[str, Any] = {
            "type": clean_type,
            "osType": clean_os,
            "value": clean_value,
            "description": description.strip()[:EXCLUSION_DESCRIPTION_MAX_LEN],
            "mode": clean_mode,
        }
        if path_exclusion_type and path_exclusion_type.strip():
            clean_path_type = path_exclusion_type.strip().lower()
            if clean_path_type not in PATH_EXCLUSION_TYPES:
                raise ValueError(
                    f"Invalid path_exclusion_type {path_exclusion_type!r}. "
                    f"Expected one of: {', '.join(sorted(PATH_EXCLUSION_TYPES))}."
                )
            data["pathExclusionType"] = clean_path_type
        if actions is not None:
            action_list = [
                a.lower() for a in _normalize_id_list(actions, field_name="actions")
            ]
            invalid = [a for a in action_list if a not in EXCLUSION_ACTIONS]
            if invalid:
                raise ValueError(
                    f"Invalid exclusion actions {invalid!r}. "
                    f"Expected subset of: {', '.join(sorted(EXCLUSION_ACTIONS))}."
                )
            data["actions"] = action_list

        flt = self._scope_filter_dict(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        if not flt:
            raise ValueError(
                "At least one scope (account_ids, site_ids, or group_ids) is required "
                "to create a SentinelOne exclusion."
            )
        body: dict[str, Any] = {"data": data, "filter": flt}
        return self._request("POST", "exclusions", json_body=body)

    def update_exclusion(
        self,
        exclusion_id: str,
        *,
        exclusion_type: str,
        os_type: str,
        value: str | None = None,
        description: str | None = None,
        mode: str | None = None,
        path_exclusion_type: str | None = None,
        actions: Sequence[str] | str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
    ) -> dict[str, Any]:
        """Update an existing SentinelOne exclusion."""
        clean_id = exclusion_id.strip()
        if not clean_id:
            raise ValueError("exclusion_id must be non-empty.")
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
        data: dict[str, Any] = {
            "id": clean_id,
            "type": clean_type,
            "osType": clean_os,
        }
        if value is not None:
            clean_val = value.strip()
            if not clean_val:
                raise ValueError("Exclusion value must be non-empty.")
            data["value"] = clean_val
        if description is not None:
            data["description"] = description.strip()[:EXCLUSION_DESCRIPTION_MAX_LEN]
        if mode is not None:
            clean_mode = mode.strip().lower()
            if clean_mode not in EXCLUSION_MODES:
                raise ValueError(
                    f"Invalid exclusion mode {mode!r}. "
                    f"Expected one of: {', '.join(sorted(EXCLUSION_MODES))}."
                )
            data["mode"] = clean_mode
        if path_exclusion_type is not None and path_exclusion_type.strip():
            clean_path_type = path_exclusion_type.strip().lower()
            if clean_path_type not in PATH_EXCLUSION_TYPES:
                raise ValueError(
                    f"Invalid path_exclusion_type {path_exclusion_type!r}."
                )
            data["pathExclusionType"] = clean_path_type
        if actions is not None:
            action_list = [
                a.lower() for a in _normalize_id_list(actions, field_name="actions")
            ]
            invalid = [a for a in action_list if a not in EXCLUSION_ACTIONS]
            if invalid:
                raise ValueError(f"Invalid exclusion actions {invalid!r}.")
            data["actions"] = action_list

        del account_ids, site_ids, group_ids  # PutExclusionSchema defines ["data"] only
        body: dict[str, Any] = {"data": data}
        return self._request("PUT", "exclusions", json_body=body)

    def validate_exclusion(
        self,
        *,
        exclusion_type: str,
        os_type: str,
        value: str,
    ) -> dict[str, Any]:
        """Validate an exclusion payload before creation (``white_hash`` -> ``hash``)."""
        clean_type = exclusion_type.strip().lower()
        if clean_type not in EXCLUSION_TYPES and clean_type != "hash":
            raise ValueError(
                f"Invalid exclusion_type {exclusion_type!r}. "
                f"Expected one of: {', '.join(sorted(EXCLUSION_TYPES))}."
            )
        clean_os = os_type.strip().lower()
        if clean_os not in OS_TYPES:
            raise ValueError(
                f"Invalid os_type {os_type!r}. Expected one of: {', '.join(sorted(OS_TYPES))}."
            )
        clean_val = value.strip()
        if not clean_val:
            raise ValueError("Exclusion value must be non-empty.")
        api_type = "hash" if clean_type == "white_hash" else clean_type
        payload = self._request(
            "POST",
            "exclusions/validate",
            json_body={
                "data": {
                    "exclusionType": api_type,
                    "osType": clean_os,
                    "value": clean_val,
                }
            },
        )
        data = payload.get("data")
        return dict(data) if isinstance(data, dict) else payload

    def plan_clone_exclusions(
        self,
        source_site_id: str,
        target_site_id: str,
        *,
        source_site_name: str | None = None,
        include_source_parents: bool = False,
        limit: int | None = None,
        max_pages: int | None = None,
    ) -> dict[str, Any]:
        """Compute a dry-run diff plan for cloning exclusions from source to target site."""
        src_id = source_site_id.strip()
        dst_id = target_site_id.strip()
        if not src_id or not dst_id:
            raise ValueError("Both source_site_id and target_site_id must be non-empty.")
        if src_id == dst_id:
            raise ValueError("source_site_id and target_site_id must be different.")

        src_label = (source_site_name or "").strip() or src_id
        source_exclusions = self.list_exclusions(
            site_ids=[src_id],
            include_parents=include_source_parents,
            limit=limit,
            max_pages=max_pages,
        )
        target_exclusions = self.list_exclusions(
            site_ids=[dst_id],
            include_parents=True,
            limit=limit,
            max_pages=max_pages,
        )

        target_by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for item in target_exclusions:
            key = _normalize_exclusion_dedup_key(item)
            existing = target_by_key.get(key)
            item_scope = str(item.get("scope") or "").strip().lower()
            if existing is None or item_scope in {"account", "global", "tenant"}:
                target_by_key[key] = item

        will_create: list[dict[str, Any]] = []
        skipped_duplicate: list[dict[str, Any]] = []
        inherited_from_account: list[dict[str, Any]] = []
        seen_source_keys: set[tuple[str, str, str, str]] = set()

        for src_item in source_exclusions:
            key = _normalize_exclusion_dedup_key(src_item)
            if key in seen_source_keys:
                skipped_duplicate.append(
                    {
                        "source": dict(src_item),
                        "reason": "duplicate_in_source",
                        "category": "Skipped Duplicate",
                    }
                )
                continue
            seen_source_keys.add(key)

            matched = target_by_key.get(key)
            if matched is not None:
                matched_scope = str(matched.get("scope") or "").strip().lower()
                if matched_scope in {"account", "global", "tenant"}:
                    inherited_from_account.append(
                        {
                            "source": dict(src_item),
                            "target": dict(matched),
                            "scope": matched_scope,
                            "category": "Inherited from Account",
                        }
                    )
                else:
                    skipped_duplicate.append(
                        {
                            "source": dict(src_item),
                            "target": dict(matched),
                            "scope": matched_scope or "site",
                            "category": "Skipped Duplicate",
                        }
                    )
                continue

            planned_payload: dict[str, Any] = {
                "exclusion_type": str(src_item.get("type") or "").strip().lower(),
                "os_type": str(src_item.get("osType") or "").strip().lower(),
                "value": str(src_item.get("value") or "").strip(),
                "mode": str(src_item.get("mode") or "suppress").strip().lower() or "suppress",
                "description": _format_cloned_description(
                    str(src_item.get("description") or ""),
                    src_label,
                ),
            }
            if src_item.get("pathExclusionType"):
                planned_payload["path_exclusion_type"] = str(src_item["pathExclusionType"]).strip()
            if isinstance(src_item.get("actions"), Sequence) and not isinstance(
                src_item.get("actions"), (str, bytes)
            ):
                planned_payload["actions"] = [str(a) for a in src_item["actions"]]
            will_create.append(
                {
                    "source": dict(src_item),
                    "payload": planned_payload,
                    "category": "Will Create",
                }
            )

        return {
            "source_site_id": src_id,
            "source_site_name": src_label,
            "target_site_id": dst_id,
            "dry_run": True,
            "will_create": will_create,
            "skipped_duplicate": skipped_duplicate,
            "inherited_from_account": inherited_from_account,
            "created": [],
            "failed": [],
            "counts": {
                "source_total": len(source_exclusions),
                "target_total": len(target_exclusions),
                "will_create": len(will_create),
                "skipped_duplicate": len(skipped_duplicate),
                "inherited_from_account": len(inherited_from_account),
                "created": 0,
                "failed": 0,
            },
        }

    def clone_exclusions(
        self,
        source_site_id: str,
        target_site_id: str,
        *,
        source_site_name: str | None = None,
        dry_run: bool = True,
        requests_per_second: float = MAX_EXCLUSION_CLONE_RPS,
        include_source_parents: bool = False,
        continue_on_error: bool = True,
        limit: int | None = None,
        max_pages: int | None = None,
    ) -> dict[str, Any]:
        """Clone site exclusions from ``source_site_id`` to ``target_site_id`` at ``<= 15`` req/s."""
        rps = float(requests_per_second)
        if not math.isfinite(rps) or rps <= 0:
            raise ValueError("requests_per_second must be a finite positive number.")
        effective_rps = min(rps, MAX_EXCLUSION_CLONE_RPS)

        plan = self.plan_clone_exclusions(
            source_site_id,
            target_site_id,
            source_site_name=source_site_name,
            include_source_parents=include_source_parents,
            limit=limit,
            max_pages=max_pages,
        )
        plan["dry_run"] = bool(dry_run)
        plan["requests_per_second"] = effective_rps
        if dry_run:
            return plan

        pacer = _RatePacer(effective_rps, stop_event=self.stop_event)
        created: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        dst_id = plan["target_site_id"]

        for entry in plan["will_create"]:
            if self.stop_event.is_set():
                raise SentinelOneError("SentinelOne exclusion cloning cancelled.", reason="cancelled")
            pacer.acquire()
            payload = dict(entry["payload"])
            try:
                resp = self.create_exclusion(
                    exclusion_type=payload["exclusion_type"],
                    os_type=payload["os_type"],
                    value=payload["value"],
                    description=payload["description"],
                    mode=payload["mode"],
                    path_exclusion_type=payload.get("path_exclusion_type"),
                    actions=payload.get("actions"),
                    site_ids=[dst_id],
                )
                created.append({"payload": payload, "response": resp})
            except SentinelOneError as exc:
                if exc.reason == "cancelled" or not continue_on_error:
                    raise
                failed.append({"payload": payload, "error": exc.message})
            except Exception as exc:
                if not continue_on_error:
                    raise
                failed.append({"payload": payload, "error": str(exc)})

        plan["created"] = created
        plan["failed"] = failed
        plan["counts"]["created"] = len(created)
        plan["counts"]["failed"] = len(failed)
        return plan

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
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """List SentinelOne SHA-1 blocklist (``black_hash``) entries."""
        params = self._scope_params(account_ids=account_ids, site_ids=site_ids)
        params["type"] = "black_hash"
        os_csv = _csv_param(os_types)
        if os_csv:
            params["osTypes"] = os_csv
        if query and query.strip():
            params["value__contains"] = query.strip()
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "restrictions",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

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
        """Add a SHA-1 hash IOC to the scoped SentinelOne blocklist."""
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

        flt = self._scope_filter_dict(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        if not flt:
            raise ValueError(
                "At least one scope (account_ids, site_ids, or group_ids) is required "
                "for SentinelOne blocklist restrictions."
            )
        body: dict[str, Any] = {
            "data": {
                "type": "black_hash",
                "value": clean_hash,
                "osType": clean_os,
                "description": description.strip(),
                "source": source.strip() or "soclens",
            },
            "filter": flt,
        }
        return self._request("POST", "restrictions", json_body=body)

    def update_blocklist(
        self,
        entry_id: str,
        *,
        sha1_hash: str,
        os_type: str = "windows",
        description: str = "",
        source: str = "soclens",
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
    ) -> dict[str, Any]:
        """Update an existing SentinelOne SHA-1 blocklist entry."""
        clean_id = entry_id.strip()
        if not clean_id:
            raise ValueError("entry_id must be non-empty.")
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
        flt = self._scope_filter_dict(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        if not flt:
            raise ValueError(
                "At least one scope (account_ids, site_ids, or group_ids) is required "
                "to update a SentinelOne blocklist entry."
            )
        body: dict[str, Any] = {
            "data": {
                "id": clean_id,
                "type": "black_hash",
                "value": clean_hash,
                "osType": clean_os,
                "description": description.strip(),
                "source": source.strip() or "soclens",
            },
            "filter": flt,
        }
        return self._request("PUT", "restrictions", json_body=body)

    def remove_from_blocklist(self, ids: Sequence[str] | str) -> dict[str, Any]:
        """Remove one or more SHA-1 entries from the SentinelOne blocklist by ID."""
        clean_ids = _normalize_id_list(ids, field_name="ids")
        return self._request(
            "DELETE",
            "restrictions",
            json_body={"data": {"ids": clean_ids, "type": "black_hash"}},
        )

    # ------------------------------------------------------------------
    # Users, Service Users & RBAC Admin
    # ------------------------------------------------------------------

    def list_users(
        self,
        *,
        query: str | None = None,
        email: str | None = None,
        full_name: str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        role_ids: Sequence[str] | str | None = None,
        two_fa_enabled: bool | None = None,
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """List SentinelOne console users."""
        params = self._scope_params(account_ids=account_ids, site_ids=site_ids)
        if query and query.strip():
            params["query"] = query.strip()
        if email and email.strip():
            params["email"] = email.strip()
        if full_name and full_name.strip():
            params["fullName"] = full_name.strip()
        roles_csv = _csv_param(role_ids)
        if roles_csv:
            params["roleIds"] = roles_csv
        if two_fa_enabled is not None:
            params["twoFaEnabled"] = str(bool(two_fa_enabled)).lower()
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "users",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

    def get_user(self, user_id: str) -> dict[str, Any]:
        """Fetch a single SentinelOne console user by ID."""
        clean_id = user_id.strip()
        if not clean_id:
            raise ValueError("user_id must be non-empty.")
        payload = self._request("GET", f"users/{clean_id}")
        data = payload.get("data")
        return dict(data) if isinstance(data, dict) else payload

    def create_user(
        self,
        *,
        email: str,
        full_name: str,
        scope: str,
        scope_roles: Sequence[Mapping[str, Any]] | None = None,
        password: str | None = None,
        two_fa_enabled: bool | None = None,
        allow_remote_shell: bool | None = None,
        force_credential_auth: bool | None = None,
    ) -> dict[str, Any]:
        """Create a SentinelOne console user."""
        clean_email = email.strip()
        clean_name = full_name.strip()
        clean_scope = scope.strip().lower()
        if not clean_email:
            raise ValueError("User email must be non-empty.")
        if not clean_name:
            raise ValueError("User full_name must be non-empty.")
        if clean_scope not in USER_SCOPES:
            raise ValueError(
                f"Invalid user scope {scope!r}. Expected one of: {', '.join(sorted(USER_SCOPES))}."
            )
        data: dict[str, Any] = {
            "email": clean_email,
            "fullName": clean_name,
            "scope": clean_scope,
            "scopeRoles": _sanitize_scope_roles(scope_roles, scope=clean_scope),
        }
        if password:
            data["password"] = password
        if two_fa_enabled is not None:
            data["twoFaEnabled"] = bool(two_fa_enabled)
        if allow_remote_shell is not None:
            data["allowRemoteShell"] = bool(allow_remote_shell)
        if force_credential_auth is not None:
            data["forceCredentialAuth"] = bool(force_credential_auth)
        payload = self._request("POST", "users", json_body={"data": data})
        raw = payload.get("data")
        return dict(raw) if isinstance(raw, dict) else payload

    def update_user(
        self,
        user_id: str,
        *,
        scope: str,
        scope_roles: Sequence[Mapping[str, Any]] | None = None,
        full_name: str | None = None,
        email: str | None = None,
        two_fa_enabled: bool | None = None,
        can_generate_api_token: bool | None = None,
    ) -> dict[str, Any]:
        """Update an existing SentinelOne console user."""
        clean_id = user_id.strip()
        if not clean_id:
            raise ValueError("user_id must be non-empty.")
        clean_scope = scope.strip().lower()
        if clean_scope not in USER_SCOPES:
            raise ValueError(
                f"Invalid user scope {scope!r}. Expected one of: {', '.join(sorted(USER_SCOPES))}."
            )
        data: dict[str, Any] = {
            "scope": clean_scope,
            "scopeRoles": _sanitize_scope_roles(scope_roles, scope=clean_scope),
        }
        if full_name and full_name.strip():
            data["fullName"] = full_name.strip()
        if email and email.strip():
            data["email"] = email.strip()
        if two_fa_enabled is not None:
            data["twoFaEnabled"] = bool(two_fa_enabled)
        if can_generate_api_token is not None:
            data["canGenerateApiToken"] = bool(can_generate_api_token)
        payload = self._request("PUT", f"users/{clean_id}", json_body={"data": data})
        raw = payload.get("data")
        return dict(raw) if isinstance(raw, dict) else payload

    def delete_user(self, user_id: str) -> dict[str, Any]:
        """Delete a single SentinelOne console user by ID."""
        clean_id = user_id.strip()
        if not clean_id:
            raise ValueError("user_id must be non-empty.")
        return self._request("DELETE", f"users/{clean_id}")

    def delete_users(self, user_ids: Sequence[str] | str) -> dict[str, Any]:
        """Bulk delete SentinelOne console users."""
        ids = _normalize_id_list(user_ids, field_name="user_ids")
        return self._request(
            "POST",
            "users/delete-users",
            json_body={"filter": {"ids": ids}, "data": {}},
        )

    def send_reset_password_email(self, user_ids: Sequence[str] | str) -> dict[str, Any]:
        """Send password reset emails to one or more SentinelOne console users."""
        ids = _normalize_id_list(user_ids, field_name="user_ids")
        return self._request(
            "POST",
            "users/login/send-reset-password-email",
            json_body={"filter": {"ids": ids}, "data": {}},
        )

    def reset_2fa(
        self,
        user_ids: Sequence[str] | str,
        *,
        enroll: bool = False,
    ) -> dict[str, Any]:
        """Reset 2FA configuration for one or more SentinelOne console users."""
        ids = _normalize_id_list(user_ids, field_name="user_ids")
        return self._request(
            "POST",
            "users/reset-2fa",
            json_body={"data": {"ids": ids, "enroll": bool(enroll)}},
        )

    def delete_2fa(self, user_ids: Sequence[str] | str) -> dict[str, Any]:
        """Delete 2FA configuration for one or more SentinelOne console users."""
        ids = _normalize_id_list(user_ids, field_name="user_ids")
        return self._request(
            "POST",
            "users/delete-2fa",
            json_body={"data": {"ids": ids}},
        )

    def logout_user(self) -> dict[str, Any]:
        """Log out the currently authenticated SentinelOne API session."""
        return self._request("POST", "users/logout", json_body={})

    def list_service_users(
        self,
        *,
        query: str | None = None,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        role_ids: Sequence[str] | str | None = None,
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """List SentinelOne service users."""
        params = self._scope_params(account_ids=account_ids, site_ids=site_ids)
        if query and query.strip():
            params["query"] = query.strip()
        roles_csv = _csv_param(role_ids)
        if roles_csv:
            params["roleIds"] = roles_csv
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "service-users",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

    def get_service_user(self, service_user_id: str) -> dict[str, Any]:
        """Fetch a single SentinelOne service user by ID."""
        clean_id = service_user_id.strip()
        if not clean_id:
            raise ValueError("service_user_id must be non-empty.")
        payload = self._request("GET", f"service-users/{clean_id}")
        data = payload.get("data")
        return dict(data) if isinstance(data, dict) else payload

    def create_service_user(
        self,
        *,
        name: str,
        scope: str,
        expiration_date: str,
        description: str | None = None,
        scope_roles: Sequence[Mapping[str, Any]] | None = None,
        force_legacy: bool | None = None,
    ) -> dict[str, Any]:
        """Create a SentinelOne service user."""
        clean_name = name.strip()
        clean_scope = scope.strip().lower()
        clean_exp = expiration_date.strip()
        if not clean_name:
            raise ValueError("Service user name must be non-empty.")
        if clean_scope not in USER_SCOPES:
            raise ValueError(
                f"Invalid scope {scope!r}. Expected one of: {', '.join(sorted(USER_SCOPES))}."
            )
        if not clean_exp:
            raise ValueError("expiration_date must be non-empty.")
        data: dict[str, Any] = {
            "name": clean_name,
            "scope": clean_scope,
            "expirationDate": clean_exp,
            "scopeRoles": _sanitize_scope_roles(scope_roles, scope=clean_scope),
        }
        if description is not None and description.strip():
            data["description"] = description.strip()
        if force_legacy is not None:
            data["forceLegacy"] = bool(force_legacy)
        payload = self._request("POST", "service-users", json_body={"data": data})
        raw = payload.get("data")
        return dict(raw) if isinstance(raw, dict) else payload

    def update_service_user(
        self,
        service_user_id: str,
        *,
        description: str | None = None,
        scope: str | None = None,
        scope_roles: Sequence[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Update an existing SentinelOne service user."""
        clean_id = service_user_id.strip()
        if not clean_id:
            raise ValueError("service_user_id must be non-empty.")
        data: dict[str, Any] = {}
        resolved_scope = "site"
        if scope is not None:
            resolved_scope = scope.strip().lower()
            if resolved_scope not in USER_SCOPES:
                raise ValueError(
                    f"Invalid scope {scope!r}. Expected one of: {', '.join(sorted(USER_SCOPES))}."
                )
            data["scope"] = resolved_scope
        if scope_roles is not None:
            data["scopeRoles"] = _sanitize_scope_roles(scope_roles, scope=resolved_scope)
        if description is not None:
            data["description"] = description.strip()
        if not data:
            raise ValueError("At least one field must be provided to update_service_user.")
        payload = self._request("PUT", f"service-users/{clean_id}", json_body={"data": data})
        raw = payload.get("data")
        return dict(raw) if isinstance(raw, dict) else payload

    def delete_service_user(self, service_user_id: str) -> dict[str, Any]:
        """Delete a single SentinelOne service user by ID."""
        clean_id = service_user_id.strip()
        if not clean_id:
            raise ValueError("service_user_id must be non-empty.")
        return self._request("DELETE", f"service-users/{clean_id}")

    def delete_service_users(self, service_user_ids: Sequence[str] | str) -> dict[str, Any]:
        """Bulk delete SentinelOne service users."""
        ids = _normalize_id_list(service_user_ids, field_name="service_user_ids")
        return self._request(
            "POST",
            "service-users/delete-service-users",
            json_body={"filter": {"ids": ids}, "data": {}},
        )

    def generate_service_user_token(
        self,
        service_user_id: str,
        *,
        expiration_date: str,
    ) -> dict[str, Any]:
        """Generate a new API token for a SentinelOne service user."""
        clean_id = service_user_id.strip()
        clean_exp = expiration_date.strip()
        if not clean_id:
            raise ValueError("service_user_id must be non-empty.")
        if not clean_exp:
            raise ValueError("expiration_date must be non-empty.")
        return self._request(
            "POST",
            f"service-users/{clean_id}/generate-api-token",
            json_body={"data": {"expirationDate": clean_exp}},
        )

    def list_rbac_roles(
        self,
        *,
        account_ids: Sequence[str] | str | None = None,
        site_ids: Sequence[str] | str | None = None,
        group_ids: Sequence[str] | str | None = None,
        include_parents: bool | None = None,
        include_children: bool | None = None,
        predefined_role: bool | None = None,
        name: str | None = None,
        query: str | None = None,
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """List SentinelOne RBAC roles."""
        params = self._scope_params(
            account_ids=account_ids,
            site_ids=site_ids,
            group_ids=group_ids,
        )
        if include_parents is not None:
            params["includeParents"] = str(bool(include_parents)).lower()
        if include_children is not None:
            params["includeChildren"] = str(bool(include_children)).lower()
        if predefined_role is not None:
            params["predefinedRole"] = str(bool(predefined_role)).lower()
        if name and name.strip():
            params["name"] = name.strip()
        if query and query.strip():
            params["query"] = query.strip()
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "rbac/roles",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

    def clone_user_permissions(
        self,
        source_user_id: str,
        *,
        target_site_ids: Sequence[str] | str | None = None,
        service_user: bool = False,
    ) -> dict[str, Any]:
        """Fetch a source user's RBAC scope & sanitized ``scopeRoles`` for cloning."""
        source = (
            self.get_service_user(source_user_id)
            if service_user
            else self.get_user(source_user_id)
        )
        scope = str(source.get("scope") or "site").strip().lower()
        if scope not in USER_SCOPES:
            scope = "site"
        if target_site_ids is not None:
            scope = "site"
        raw_roles = source.get("scopeRoles")
        roles_seq = raw_roles if isinstance(raw_roles, Sequence) else []
        sanitized_roles = _sanitize_scope_roles(
            roles_seq,
            scope=scope,
            target_site_ids=target_site_ids,
        )
        return {
            "source_user_id": source_user_id.strip(),
            "scope": scope,
            "scopeRoles": sanitized_roles,
        }

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
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
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
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "activities",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
        )

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
        sort_by: str | None = "createdAt",
        sort_order: str = "desc",
        limit: int | None = None,
        max_pages: int | None = None,
        on_page: Callable[[int, int | None], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve events returned by a completed Deep Visibility query."""
        clean_id = query_id.strip()
        if not clean_id:
            raise ValueError("query_id must be non-empty.")
        params: dict[str, Any] = {"queryId": clean_id}
        _apply_sort_params(params, sort_by=sort_by, sort_order=sort_order)
        return self._paginate(
            "dv/events",
            params=params,
            limit=limit,
            max_pages=max_pages,
            on_page=on_page,
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
