"""Splunk Search Head REST API client, validator, and savedsearches.conf parser."""

from __future__ import annotations

import configparser
import csv
import glob
import json
import logging
import math
import random
import re
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Self
from urllib.parse import quote

import requests
import urllib3
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth

from soclens.config import ConfiguredSession, get_splunk_config

logger = logging.getLogger("soclens.splunk")

_SSL_WARNING_LOCK = threading.Lock()
_SSL_WARNINGS_SUPPRESSED = False

_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
_SPL_PREFIX_RE = re.compile(r"^(?:search(?:\s|$)|\|)", re.IGNORECASE)


def _suppress_insecure_ssl_warnings() -> None:
    """Suppress urllib3 InsecureRequestWarning once in a thread-safe manner."""
    global _SSL_WARNINGS_SUPPRESSED
    if _SSL_WARNINGS_SUPPRESSED:
        return
    with _SSL_WARNING_LOCK:
        if not _SSL_WARNINGS_SUPPRESSED:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            _SSL_WARNINGS_SUPPRESSED = True


def _normalize_spl_query(raw_query: str) -> str:
    """Normalize an SPL search string without corrupting leading pipes or search keywords."""
    stripped = raw_query.strip()
    if not stripped:
        return ""
    if _SPL_PREFIX_RE.match(stripped):
        return stripped
    return f"search {stripped}"


def _parse_retry_after(header_value: str | None) -> float | None:
    """Parse numeric or HTTP-date Retry-After header, clamped to [0, 30] seconds."""
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
    return min(max(seconds, 0.0), 30.0)


def _ends_with_single_backslash(line: str) -> bool:
    """Return True if a line ends with an odd number of trailing backslashes."""
    stripped = line.rstrip("\r\n")
    trailing = len(stripped) - len(stripped.rstrip("\\"))
    return trailing % 2 == 1


def _unfold_splunk_continuations(text: str) -> str:
    """Unfold Splunk savedsearches.conf trailing-backslash line continuations for ConfigParser."""
    lines = text.splitlines()
    unfolded: list[str] = []
    buffer: str | None = None

    for line in lines:
        if buffer is not None:
            cont = line.lstrip()
            if _ends_with_single_backslash(cont):
                part = cont[:-1].rstrip()
                buffer = f"{buffer} {part}".strip() if part else buffer
            else:
                joined = f"{buffer} {cont}".strip() if cont else buffer
                unfolded.append(joined)
                buffer = None
            continue

        stripped_left = line.lstrip()
        if not stripped_left.startswith(("#", ";")) and _ends_with_single_backslash(line):
            buffer = line[:-1].rstrip()
        else:
            unfolded.append(line)

    if buffer is not None:
        unfolded.append(buffer)

    return "\n".join(unfolded)


def _safe_int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if math.isfinite(parsed) else default


def _extract_first_entry_content(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    entries = payload.get("entry")
    if not isinstance(entries, list) or not entries:
        return {}
    first = entries[0]
    if not isinstance(first, dict):
        return {}
    content = first.get("content")
    return content if isinstance(content, dict) else {}


def _extract_splunk_message_list(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return []
    texts: list[str] = []
    for msg in messages:
        if isinstance(msg, dict):
            text = msg.get("text")
            if text:
                texts.append(str(text))
        elif isinstance(msg, str) and msg.strip():
            texts.append(msg.strip())
    return texts


def _extract_splunk_messages(payload: Any) -> str:
    return "; ".join(_extract_splunk_message_list(payload))


def _normalize_result_fields(raw_fields: Any, results: list[dict[str, Any]]) -> list[str]:
    """Extract ordered field names from Splunk results payload or result rows."""
    names: list[str] = []
    seen: set[str] = set()
    if isinstance(raw_fields, list):
        for item in raw_fields:
            name: str | None = None
            if isinstance(item, dict):
                raw_name = item.get("name")
                if raw_name is not None and str(raw_name).strip():
                    name = str(raw_name)
            elif isinstance(item, str) and item.strip():
                name = item
            if name and name not in seen:
                seen.add(name)
                names.append(name)
    if not names:
        for row in results:
            if not isinstance(row, dict):
                continue
            for key in row:
                key_str = str(key)
                if key_str not in seen:
                    seen.add(key_str)
                    names.append(key_str)
    return names


def _safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off", ""}:
            return False
    return default


def _format_csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def export_results_json(
    results: list[dict[str, Any]],
    output_path: Path | str,
) -> Path:
    """Export Splunk search result rows to a UTF-8 JSON file."""
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def export_results_csv(
    results: list[dict[str, Any]],
    output_path: Path | str,
    fields: list[str] | None = None,
) -> Path:
    """Export Splunk search result rows to a UTF-8 CSV file."""
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(fields) if fields else _normalize_result_fields(None, results)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        if fieldnames:
            writer.writeheader()
            for row in results:
                if isinstance(row, dict):
                    writer.writerow({k: _format_csv_cell(row.get(k)) for k in fieldnames})
    return path


class SplunkClient:
    """Splunk Search Head REST API client supporting interactive search, jobs, and metadata."""

    def __init__(
        self,
        host: str | None = None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        app: str | None = None,
        verify_ssl: bool | str | None = None,
        session: requests.Session | None = None,
        request_timeout: float = 15.0,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        poll_interval: float = 2.0,
    ) -> None:
        config = get_splunk_config(
            host=host,
            token=token,
            username=username,
            password=password,
            app=app,
            verify_ssl=verify_ssl,
            required=True,
        )
        self.config = config
        self.host = config.host
        self.token = config.token
        self.username = config.username
        self.password = config.password
        self.app = config.app
        self.verify_ssl: bool | str = config.verify_ssl
        self.request_timeout = request_timeout
        self.max_retries = max(0, max_retries)
        self.backoff_base = max(0.0, backoff_base)
        self.poll_interval = max(0.05, poll_interval)

        if self.verify_ssl is False:
            _suppress_insecure_ssl_warnings()

        self.headers: dict[str, str] = {}
        self.auth: HTTPBasicAuth | None = None

        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"
        elif self.username and self.password:
            self.auth = HTTPBasicAuth(self.username, self.password)

        self._owns_session = session is None
        if session is not None:
            self.session = session
        else:
            self.session = ConfiguredSession()
            adapter = HTTPAdapter(pool_connections=32, pool_maxsize=32)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

    def close(self) -> None:
        """Close the underlying HTTP session if owned by this client."""
        if self._owns_session:
            self.session.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _build_url(self, path: str) -> str:
        """Join a relative REST path onto ``self.host``."""
        if path.startswith(("http://", "https://")):
            return path
        clean_path = path if path.startswith("/") else f"/{path}"
        return f"{self.host}{clean_path}"

    def _encode_app(self, app: str | None = None) -> str:
        target_app = (app or self.app).strip() if (app or self.app) else self.app
        if target_app == "-":
            return "-"
        return quote(str(target_app), safe="")

    def _compute_backoff(self, attempt: int, retry_after: float | None = None) -> float:
        if retry_after is not None:
            return min(max(retry_after, 0.0), 30.0)
        base = min(self.backoff_base * (2**attempt), 10.0)
        return base * random.uniform(0.75, 1.25)

    def _request(
        self,
        method: str,
        url: str,
        *,
        timeout: float | None = None,
        deadline: float | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        full_url = self._build_url(url)
        base_timeout = timeout if timeout is not None else self.request_timeout
        last_exc: requests.exceptions.RequestException | None = None

        for attempt in range(self.max_retries + 1):
            req_timeout = base_timeout
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Search execution deadline exceeded.")
                req_timeout = min(base_timeout, max(0.1, remaining))

            try:
                response = self.session.request(
                    method,
                    full_url,
                    headers=self.headers,
                    auth=self.auth,
                    verify=self.verify_ssl,
                    timeout=req_timeout,
                    **kwargs,
                )
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                if attempt >= self.max_retries:
                    raise
                delay = self._compute_backoff(attempt)
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("Search execution deadline exceeded.") from exc
                    delay = min(delay, remaining)
                logger.warning(
                    "Splunk %s %s failed (%s); retrying in %.2fs (attempt %d/%d).",
                    method,
                    full_url,
                    exc,
                    delay,
                    attempt + 1,
                    self.max_retries,
                )
                time.sleep(delay)
                continue

            if response.status_code not in _RETRYABLE_STATUS_CODES:
                return response

            if attempt >= self.max_retries:
                return response

            retry_after = (
                _parse_retry_after(response.headers.get("Retry-After"))
                if response.status_code == 429
                else None
            )
            delay = self._compute_backoff(attempt, retry_after=retry_after)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return response
                delay = min(delay, remaining)
            logger.warning(
                "Splunk %s %s returned HTTP %d; retrying in %.2fs (attempt %d/%d).",
                method,
                full_url,
                response.status_code,
                delay,
                attempt + 1,
                self.max_retries,
            )
            time.sleep(delay)

        if last_exc is not None:  # pragma: no cover - defensive fallback
            raise last_exc
        raise RuntimeError("Unexpected retry loop exit")  # pragma: no cover

    def check_connection(self) -> bool:
        """Verifies connectivity to Splunk."""
        info_url = f"{self.host}/services/server/info?output_mode=json"
        try:
            response = self._request("GET", info_url, timeout=self.request_timeout)
            if response.status_code == 200:
                data = response.json()
                content = _extract_first_entry_content(data)
                version = content.get("version", "Unknown")
                logger.info("Connected to Splunk API. Server version: %s", version)
                return True
        except (requests.exceptions.RequestException, ValueError, TypeError) as e:
            logger.debug("Connection check via server/info failed: %s", e)

        context_url = f"{self.host}/services/authentication/currentcontext?output_mode=json"
        try:
            response = self._request("GET", context_url, timeout=self.request_timeout)
            if response.status_code == 200:
                data = response.json()
                content = _extract_first_entry_content(data)
                username = content.get("username", "Unknown")
                logger.info("Connected to Splunk API. Authenticated user: %s", username)
                return True
        except (requests.exceptions.RequestException, ValueError, TypeError) as e:
            logger.error("Failed to connect to Splunk API at %s: %s", self.host, e)
            return False

        return False

    def _cancel_search_job(self, cancel_url: str) -> bool:
        """Attempt best-effort cancellation of a Splunk search job."""
        try:
            cancel_resp = self.session.request(
                "POST",
                cancel_url,
                headers=self.headers,
                auth=self.auth,
                data={"action": "cancel"},
                verify=self.verify_ssl,
                timeout=min(5.0, self.request_timeout),
            )
            if cancel_resp.status_code >= 400:
                logger.warning(
                    "Failed to cancel Splunk job at %s (HTTP %d).",
                    cancel_url,
                    cancel_resp.status_code,
                )
                return False
            return True
        except requests.exceptions.RequestException as exc:
            logger.warning("Failed to cancel Splunk job at %s: %s", cancel_url, exc)
            return False

    def cancel_job(self, sid: str) -> bool:
        """Cancel a running Splunk search job by its search ID (SID)."""
        clean_sid = str(sid).strip()
        if not clean_sid:
            return False
        safe_sid = quote(clean_sid, safe="")
        cancel_url = f"{self.host}/services/search/jobs/{safe_sid}/control?output_mode=json"
        return self._cancel_search_job(cancel_url)

    def get_job_results(
        self,
        sid: str,
        *,
        count: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Fetch paginated results for a completed Splunk search job."""
        clean_sid = str(sid).strip()
        if not clean_sid:
            raise ValueError("Search ID (sid) is required.")
        safe_sid = quote(clean_sid, safe="")
        safe_count = max(0, int(count))
        safe_offset = max(0, int(offset))
        results_url = (
            f"{self.host}/services/search/jobs/{safe_sid}/results"
            f"?output_mode=json&count={safe_count}&offset={safe_offset}"
        )
        response = self._request("GET", results_url, timeout=self.request_timeout)
        if response.status_code != 200:
            try:
                err_msg = _extract_splunk_messages(response.json()) or response.text
            except ValueError:
                err_msg = response.text
            raise RuntimeError(
                f"Failed to fetch results for job {clean_sid} (HTTP {response.status_code}): {err_msg}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Invalid JSON returned when fetching results for job {clean_sid}: {exc}"
            ) from exc

        raw_results = payload.get("results", []) if isinstance(payload, dict) else []
        results: list[dict[str, Any]] = (
            [row for row in raw_results if isinstance(row, dict)]
            if isinstance(raw_results, list)
            else []
        )
        raw_fields = payload.get("fields") if isinstance(payload, dict) else None
        fields = _normalize_result_fields(raw_fields, results)
        return {
            "sid": clean_sid,
            "fields": fields,
            "results": results,
            "count": safe_count,
            "offset": safe_offset,
        }

    def _poll_job_until_done(
        self,
        sid: str,
        *,
        deadline: float,
        timeout: int,
        progress_cb: Callable[[dict[str, Any]], None] | None = None,
    ) -> tuple[dict[str, Any] | None, str | None, list[str]]:
        """Poll a Splunk search job until completion or deadline expiration."""
        safe_sid = quote(str(sid), safe="")
        status_url = f"{self.host}/services/search/jobs/{safe_sid}?output_mode=json"
        cancel_url = f"{self.host}/services/search/jobs/{safe_sid}/control?output_mode=json"
        collected_messages: list[str] = []

        while True:
            if time.monotonic() >= deadline:
                self._cancel_search_job(cancel_url)
                return None, f"Search job timed out after {timeout} seconds.", collected_messages

            try:
                status_resp = self._request(
                    "GET",
                    status_url,
                    timeout=min(10.0, self.request_timeout),
                    deadline=deadline,
                )
            except TimeoutError:
                self._cancel_search_job(cancel_url)
                return None, f"Search job timed out after {timeout} seconds.", collected_messages

            if status_resp.status_code != 200:
                return (
                    None,
                    f"Failed to get job status (HTTP {status_resp.status_code})",
                    collected_messages,
                )

            try:
                status_payload = status_resp.json()
            except ValueError as exc:
                return (
                    None,
                    f"Invalid JSON returned during status poll: {exc}",
                    collected_messages,
                )

            job_content = _extract_first_entry_content(status_payload)
            payload_msgs = _extract_splunk_message_list(status_payload)
            content_msgs = _extract_splunk_message_list(job_content)
            for msg in (*payload_msgs, *content_msgs):
                if msg not in collected_messages:
                    collected_messages.append(msg)

            is_done = bool(job_content.get("isDone", False))
            dispatch_state = str(job_content.get("dispatchState", "QUEUED")).upper()

            if progress_cb is not None:
                try:
                    progress_cb(
                        {
                            "sid": sid,
                            "dispatch_state": dispatch_state,
                            "done_progress": _safe_float(job_content.get("doneProgress"), 0.0),
                            "result_count": _safe_int(job_content.get("resultCount"), 0),
                            "event_count": _safe_int(job_content.get("eventCount"), 0),
                            "scan_count": _safe_int(job_content.get("scanCount"), 0),
                            "duration": _safe_float(job_content.get("runDuration"), 0.0),
                            "is_done": is_done,
                        }
                    )
                except Exception as exc:
                    logger.debug("Splunk progress_cb raised an exception: %s", exc)

            if is_done:
                if dispatch_state in ("FAILED", "CANCELLED", "ABORTED"):
                    err_msg = (
                        "Job execution failed in Splunk."
                        if dispatch_state == "FAILED"
                        else f"Job ended with dispatchState={dispatch_state}."
                    )
                    if collected_messages:
                        err_msg += f" Messages: {'; '.join(collected_messages)}"
                    return None, err_msg, collected_messages
                return job_content, None, collected_messages

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._cancel_search_job(cancel_url)
                return None, f"Search job timed out after {timeout} seconds.", collected_messages
            time.sleep(min(self.poll_interval, remaining))

    def run_search(
        self,
        spl: str,
        *,
        earliest: str = "-24h",
        latest: str = "now",
        app: str | None = None,
        count: int = 100,
        offset: int = 0,
        timeout: int = 180,
        progress_cb: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Dispatch an ad-hoc SPL search job, poll to completion, and return results."""
        result_data: dict[str, Any] = {
            "sid": None,
            "query": spl,
            "status": "failed",
            "result_count": 0,
            "event_count": 0,
            "scan_count": 0,
            "duration": 0.0,
            "fields": [],
            "results": [],
            "error_message": None,
            "messages": [],
        }

        query = _normalize_spl_query(spl)
        if not query:
            result_data["error_message"] = "Empty search query."
            return result_data

        safe_app = self._encode_app(app)
        create_url = f"{self.host}/servicesNS/nobody/{safe_app}/search/jobs?output_mode=json"
        payload = {
            "search": query,
            "earliest_time": earliest,
            "latest_time": latest,
            "exec_mode": "normal",
        }

        deadline = time.monotonic() + max(0.0, float(timeout))

        try:
            try:
                response = self._request(
                    "POST",
                    create_url,
                    data=payload,
                    timeout=self.request_timeout,
                    deadline=deadline,
                )
            except TimeoutError:
                result_data["error_message"] = f"Search job timed out after {timeout} seconds."
                return result_data

            if response.status_code not in (200, 201):
                try:
                    err_payload = response.json()
                    result_data["messages"] = _extract_splunk_message_list(err_payload)
                    err_msg = _extract_splunk_messages(err_payload) or response.text
                except ValueError:
                    err_msg = response.text
                result_data["error_message"] = (
                    f"Failed to create job (HTTP {response.status_code}): {err_msg}"
                )
                return result_data

            try:
                create_data = response.json()
            except ValueError as exc:
                result_data["error_message"] = f"Invalid JSON returned during job creation: {exc}"
                return result_data

            sid = create_data.get("sid") if isinstance(create_data, dict) else None
            if not sid:
                result_data["error_message"] = "No search ID (sid) returned by Splunk."
                return result_data
            result_data["sid"] = str(sid)

            job_content, poll_err, messages = self._poll_job_until_done(
                str(sid),
                deadline=deadline,
                timeout=timeout,
                progress_cb=progress_cb,
            )
            result_data["messages"] = messages
            if poll_err is not None or job_content is None:
                result_data["error_message"] = poll_err or "Search job failed."
                return result_data

            result_count = _safe_int(job_content.get("resultCount"), 0)
            event_count = _safe_int(job_content.get("eventCount"), 0)
            scan_count = _safe_int(job_content.get("scanCount"), 0)
            duration = _safe_float(job_content.get("runDuration"), 0.0)

            result_data["result_count"] = result_count
            result_data["event_count"] = event_count
            result_data["scan_count"] = scan_count
            result_data["duration"] = duration
            result_data["status"] = "success"

            if result_count > 0 and count > 0:
                page = self.get_job_results(str(sid), count=count, offset=offset)
                result_data["fields"] = page["fields"]
                result_data["results"] = page["results"]

        except Exception as exc:
            result_data["error_message"] = f"Unexpected exception: {exc}"

        return result_data

    def list_indexes(self) -> list[dict[str, Any]]:
        """List Splunk indexes accessible to the authenticated user."""
        url = f"{self.host}/services/data/indexes?output_mode=json&count=0"
        response = self._request("GET", url, timeout=self.request_timeout)
        if response.status_code != 200:
            try:
                err_msg = _extract_splunk_messages(response.json()) or response.text
            except ValueError:
                err_msg = response.text
            raise RuntimeError(
                f"Failed to list Splunk indexes (HTTP {response.status_code}): {err_msg}"
            )
        payload = response.json()
        entries = payload.get("entry", []) if isinstance(payload, dict) else []
        indexes: list[dict[str, Any]] = []
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                content = entry.get("content")
                if not isinstance(content, dict):
                    content = {}
                indexes.append(
                    {
                        "name": str(entry.get("name") or ""),
                        "total_event_count": _safe_int(content.get("totalEventCount"), 0),
                        "current_db_size_mb": _safe_float(content.get("currentDBSizeMB"), 0.0),
                        "datatype": str(content.get("datatype") or "event"),
                        "disabled": _safe_bool(content.get("disabled"), False),
                        "min_time": str(content.get("minTime") or ""),
                        "max_time": str(content.get("maxTime") or ""),
                    }
                )
        return indexes

    def list_saved_searches(
        self,
        app: str | None = None,
        search_filter: str | None = None,
        count: int = 100,
    ) -> list[dict[str, Any]]:
        """List Splunk saved searches in ``app`` (or ``self.app``)."""
        safe_app = self._encode_app(app)
        safe_count = max(0, int(count))
        url = (
            f"{self.host}/servicesNS/nobody/{safe_app}/saved/searches"
            f"?output_mode=json&count={safe_count}"
        )
        response = self._request("GET", url, timeout=self.request_timeout)
        if response.status_code != 200:
            try:
                err_msg = _extract_splunk_messages(response.json()) or response.text
            except ValueError:
                err_msg = response.text
            raise RuntimeError(
                f"Failed to list saved searches (HTTP {response.status_code}): {err_msg}"
            )
        payload = response.json()
        entries = payload.get("entry", []) if isinstance(payload, dict) else []
        needle = search_filter.strip().lower() if search_filter else ""
        saved: list[dict[str, Any]] = []
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                content = entry.get("content")
                if not isinstance(content, dict):
                    content = {}
                acl = entry.get("acl")
                entry_app = (
                    str(acl.get("app"))
                    if isinstance(acl, dict) and acl.get("app")
                    else str(app or self.app)
                )
                item: dict[str, Any] = {
                    "name": str(entry.get("name") or ""),
                    "app": entry_app,
                    "search": str(content.get("search") or ""),
                    "description": str(content.get("description") or ""),
                    "cron_schedule": str(content.get("cron_schedule") or ""),
                    "earliest_time": str(content.get("dispatch.earliest_time") or ""),
                    "latest_time": str(content.get("dispatch.latest_time") or ""),
                    "disabled": _safe_bool(content.get("disabled"), False),
                    "is_scheduled": _safe_bool(content.get("is_scheduled"), False),
                }
                if needle:
                    haystack = " ".join(
                        [
                            str(item["name"]),
                            str(item["search"]),
                            str(item["description"]),
                            str(item["app"]),
                        ]
                    ).lower()
                    if needle not in haystack:
                        continue
                saved.append(item)
        return saved

    def dispatch_saved_search(
        self,
        name: str,
        *,
        app: str | None = None,
        earliest: str | None = None,
        latest: str | None = None,
        count: int = 100,
        timeout: int = 180,
    ) -> dict[str, Any]:
        """Dispatch a saved search by name, poll until completion, and return results."""
        clean_name = str(name).strip()
        result_data: dict[str, Any] = {
            "sid": None,
            "name": clean_name,
            "query": "",
            "status": "failed",
            "result_count": 0,
            "event_count": 0,
            "scan_count": 0,
            "duration": 0.0,
            "fields": [],
            "results": [],
            "error_message": None,
            "messages": [],
        }
        if not clean_name:
            result_data["error_message"] = "Saved search name is required."
            return result_data

        safe_app = self._encode_app(app)
        safe_name = quote(clean_name, safe="")
        dispatch_url = (
            f"{self.host}/servicesNS/nobody/{safe_app}/saved/searches/{safe_name}/dispatch"
            f"?output_mode=json"
        )
        payload: dict[str, str] = {}
        if earliest:
            payload["dispatch.earliest_time"] = earliest
        if latest:
            payload["dispatch.latest_time"] = latest

        deadline = time.monotonic() + max(0.0, float(timeout))
        try:
            try:
                response = self._request(
                    "POST",
                    dispatch_url,
                    data=payload,
                    timeout=self.request_timeout,
                    deadline=deadline,
                )
            except TimeoutError:
                result_data["error_message"] = f"Search job timed out after {timeout} seconds."
                return result_data

            if response.status_code not in (200, 201):
                try:
                    err_payload = response.json()
                    result_data["messages"] = _extract_splunk_message_list(err_payload)
                    err_msg = _extract_splunk_messages(err_payload) or response.text
                except ValueError:
                    err_msg = response.text
                result_data["error_message"] = (
                    f"Failed to dispatch saved search '{clean_name}' "
                    f"(HTTP {response.status_code}): {err_msg}"
                )
                return result_data

            try:
                dispatch_data = response.json()
            except ValueError as exc:
                result_data["error_message"] = (
                    f"Invalid JSON returned during saved search dispatch: {exc}"
                )
                return result_data

            sid = dispatch_data.get("sid") if isinstance(dispatch_data, dict) else None
            if not sid:
                result_data["error_message"] = "No search ID (sid) returned by Splunk."
                return result_data
            result_data["sid"] = str(sid)

            job_content, poll_err, messages = self._poll_job_until_done(
                str(sid),
                deadline=deadline,
                timeout=timeout,
            )
            result_data["messages"] = messages
            if poll_err is not None or job_content is None:
                result_data["error_message"] = poll_err or "Saved search job failed."
                return result_data

            result_count = _safe_int(job_content.get("resultCount"), 0)
            event_count = _safe_int(job_content.get("eventCount"), 0)
            scan_count = _safe_int(job_content.get("scanCount"), 0)
            duration = _safe_float(job_content.get("runDuration"), 0.0)
            resolved_query = str(job_content.get("eventSearch") or job_content.get("search") or "")

            result_data["query"] = resolved_query
            result_data["result_count"] = result_count
            result_data["event_count"] = event_count
            result_data["scan_count"] = scan_count
            result_data["duration"] = duration
            result_data["status"] = "success"

            if result_count > 0 and count > 0:
                page = self.get_job_results(str(sid), count=count, offset=0)
                result_data["fields"] = page["fields"]
                result_data["results"] = page["results"]
        except Exception as exc:
            result_data["error_message"] = f"Unexpected exception: {exc}"

        return result_data


class SplunkValidator(SplunkClient):
    """Validates Splunk savedsearches.conf stanzas against a Splunk Search Head REST API."""

    def run_single_search(
        self,
        search_info: dict[str, Any],
        earliest: str,
        latest: str,
        timeout: int = 180,
    ) -> dict[str, Any]:
        stanza = str(search_info.get("stanza", ""))
        raw_query = str(search_info.get("search", ""))
        source_file = str(search_info.get("file", ""))

        result_data: dict[str, Any] = {
            "stanza": stanza,
            "query": raw_query,
            "file": source_file,
            "status": "failed",
            "trigger_count": 0,
            "scan_count": 0,
            "duration": 0.0,
            "error_message": None,
            "sample_results": [],
        }

        query = _normalize_spl_query(raw_query)
        if not query:
            result_data["error_message"] = "Empty search query."
            return result_data

        safe_app = quote(str(self.app), safe="")
        create_url = f"{self.host}/servicesNS/nobody/{safe_app}/search/jobs?output_mode=json"
        payload = {
            "search": query,
            "earliest_time": earliest,
            "latest_time": latest,
            "exec_mode": "normal",
        }

        deadline = time.monotonic() + max(0.0, float(timeout))

        try:
            try:
                response = self._request(
                    "POST",
                    create_url,
                    data=payload,
                    timeout=self.request_timeout,
                    deadline=deadline,
                )
            except TimeoutError:
                result_data["error_message"] = f"Search job timed out after {timeout} seconds."
                return result_data

            if response.status_code != 201:
                try:
                    err_payload = response.json()
                    err_msg = _extract_splunk_messages(err_payload) or response.text
                except ValueError:
                    err_msg = response.text
                result_data["error_message"] = (
                    f"Failed to create job (HTTP {response.status_code}): {err_msg}"
                )
                return result_data

            try:
                create_data = response.json()
            except ValueError as exc:
                result_data["error_message"] = f"Invalid JSON returned during job creation: {exc}"
                return result_data

            sid = create_data.get("sid") if isinstance(create_data, dict) else None
            if not sid:
                result_data["error_message"] = "No search ID (sid) returned by Splunk."
                return result_data

            safe_sid = quote(str(sid), safe="")
            status_url = f"{self.host}/services/search/jobs/{safe_sid}?output_mode=json"
            cancel_url = f"{self.host}/services/search/jobs/{safe_sid}/control?output_mode=json"
            results_url = f"{self.host}/services/search/jobs/{safe_sid}/results?output_mode=json&count=5"

            while True:
                if time.monotonic() >= deadline:
                    result_data["error_message"] = f"Search job timed out after {timeout} seconds."
                    self._cancel_search_job(cancel_url)
                    return result_data

                try:
                    status_resp = self._request(
                        "GET",
                        status_url,
                        timeout=min(10.0, self.request_timeout),
                        deadline=deadline,
                    )
                except TimeoutError:
                    result_data["error_message"] = f"Search job timed out after {timeout} seconds."
                    self._cancel_search_job(cancel_url)
                    return result_data

                if status_resp.status_code != 200:
                    result_data["error_message"] = (
                        f"Failed to get job status (HTTP {status_resp.status_code})"
                    )
                    return result_data

                try:
                    status_payload = status_resp.json()
                except ValueError as exc:
                    result_data["error_message"] = f"Invalid JSON returned during status poll: {exc}"
                    return result_data

                job_content = _extract_first_entry_content(status_payload)
                is_done = bool(job_content.get("isDone", False))
                dispatch_state = str(job_content.get("dispatchState", "QUEUED")).upper()

                if is_done:
                    if dispatch_state in ("FAILED", "CANCELLED", "ABORTED"):
                        err_msg = (
                            "Job execution failed in Splunk."
                            if dispatch_state == "FAILED"
                            else f"Job ended with dispatchState={dispatch_state}."
                        )
                        msg_text = _extract_splunk_messages(job_content)
                        if msg_text:
                            err_msg += f" Messages: {msg_text}"
                        result_data["error_message"] = err_msg
                        return result_data

                    result_data["trigger_count"] = _safe_int(job_content.get("resultCount"), 0)
                    result_data["scan_count"] = _safe_int(job_content.get("eventCount"), 0)
                    result_data["duration"] = _safe_float(job_content.get("runDuration"), 0.0)
                    result_data["status"] = "success"
                    break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result_data["error_message"] = f"Search job timed out after {timeout} seconds."
                    self._cancel_search_job(cancel_url)
                    return result_data
                time.sleep(min(self.poll_interval, remaining))

            if result_data["trigger_count"] > 0:
                results_resp = self._request(
                    "GET",
                    results_url,
                    timeout=self.request_timeout,
                )
                if results_resp.status_code == 200:
                    try:
                        res_payload = results_resp.json()
                        sample_results = (
                            res_payload.get("results", [])
                            if isinstance(res_payload, dict)
                            else []
                        )
                        if isinstance(sample_results, list):
                            result_data["sample_results"] = sample_results
                    except ValueError as exc:
                        logger.warning(
                            "Failed to decode sample results JSON for %s: %s",
                            stanza,
                            exc,
                        )
                else:
                    logger.warning(
                        "Failed to fetch sample results for %s (HTTP %d)",
                        stanza,
                        results_resp.status_code,
                    )

        except Exception as e:
            result_data["error_message"] = f"Unexpected exception: {e}"

        return result_data


def _resolve_conf_files(input_pattern: str | Path) -> list[Path]:
    pattern_str = str(input_pattern).strip()
    if not pattern_str:
        return []

    if not glob.has_magic(pattern_str):
        candidate = Path(pattern_str).expanduser()
        if candidate.is_file():
            return [candidate]
        if candidate.is_dir():
            return sorted(p for p in candidate.glob("*.conf") if p.is_file())

    matched = glob.glob(pattern_str, recursive="**" in pattern_str)
    return sorted({Path(p) for p in matched if Path(p).is_file()})


def parse_savedsearches_files(input_pattern: str | Path) -> list[dict[str, Any]]:
    """Parses configuration files matching a pattern/path and extracts saved searches."""
    logger.info("Searching for configuration files matching: %s", input_pattern)
    files = _resolve_conf_files(input_pattern)
    if not files:
        logger.info("No files found matching pattern: %s", input_pattern)
        return []

    searches: list[dict[str, Any]] = []
    for filepath in files:
        logger.info("Parsing savedsearches configuration: %s", filepath)
        config = configparser.ConfigParser(
            interpolation=None,
            strict=False,
            allow_no_value=True,
        )
        try:
            raw_text = filepath.read_text(encoding="utf-8-sig")
            unfolded_text = _unfold_splunk_continuations(raw_text)
            config.read_string(unfolded_text, source=str(filepath))
        except (configparser.Error, OSError, UnicodeDecodeError) as e:
            logger.error("Failed to parse file %s: %s", filepath, e)
            continue

        for section in config.sections():
            section_data = config[section]
            if "search" not in section_data:
                continue

            raw_search = section_data.get("search")
            if not isinstance(raw_search, str) or not raw_search.strip():
                logger.warning(
                    "Skipping stanza '%s' in %s with empty or null search key.",
                    section,
                    filepath.name,
                )
                continue

            raw_description = section_data.get("description")
            description = (
                raw_description.strip()
                if isinstance(raw_description, str) and raw_description.strip()
                else "No description provided."
            )

            searches.append(
                {
                    "stanza": section,
                    "search": raw_search.strip(),
                    "description": description,
                    "file": filepath.name,
                }
            )

    logger.info("Successfully loaded %d search stanzas from %d file(s).", len(searches), len(files))
    return searches
