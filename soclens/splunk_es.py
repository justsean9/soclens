"""Splunk Enterprise Security (ES) REST API and SPL client for Splunk 10.2+."""

from __future__ import annotations

import json
import logging
from typing import Any, Self
from urllib.parse import quote

import requests

from soclens.splunk import (
    SplunkClient,
    _extract_splunk_message_list,
    _extract_splunk_messages,
    _safe_bool,
)

logger = logging.getLogger("soclens.splunk_es")

SPLUNK_ES_APP = "SplunkEnterpriseSecuritySuite"
SPLUNK_TI_APP = "DA-ESS-ThreatIntelligence"

NOTABLE_STATUS_MAP: dict[str, int] = {
    "new": 1,
    "in_progress": 2,
    "pending": 3,
    "resolved": 4,
    "closed": 5,
}

NOTABLE_STATUS_LABELS: dict[int, str] = {
    1: "New",
    2: "In Progress",
    3: "Pending",
    4: "Resolved",
    5: "Closed",
}

NOTABLE_URGENCIES: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
)

NOTABLE_DISPOSITIONS: tuple[tuple[str, str], ...] = (
    ("True Positive", "true_positive"),
    ("Benign Positive", "benign_positive"),
    ("False Positive", "false_positive"),
    ("Undetermined", "undetermined"),
)

THREAT_INTEL_COLLECTIONS: tuple[str, ...] = (
    "ip_intel",
    "domain_intel",
    "file_intel",
    "http_intel",
    "email_intel",
    "user_intel",
    "process_intel",
    "certificate_intel",
)


class SplunkESError(RuntimeError):
    """Raised when a Splunk Enterprise Security REST or SPL operation fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        endpoint: str | None = None,
        messages: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.endpoint = endpoint
        self.messages: list[str] = list(messages or [])


def _escape_spl_string(value: str) -> str:
    """Escape a string value for safe interpolation inside double-quoted SPL literals."""
    cleaned = " ".join(str(value).splitlines()).strip()
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def _stringify_field(value: Any) -> str:
    """Normalize scalar or multivalue Splunk result fields to a clean string."""
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item).strip() for item in value if item is not None and str(item).strip())
    return str(value).strip()


def normalize_notable_status(status: int | str) -> int:
    """Normalize a notable status integer or label into its Splunk ES integer status ID."""
    if isinstance(status, bool):
        raise ValueError(f"Invalid notable status: {status!r}")
    if isinstance(status, int):
        if status in NOTABLE_STATUS_LABELS:
            return status
        raise ValueError(
            f"Unsupported notable status code {status}. "
            f"Valid codes: {sorted(NOTABLE_STATUS_LABELS)}."
        )
    raw = str(status).strip()
    if not raw:
        raise ValueError("Notable status cannot be empty.")
    if raw.isdigit():
        code = int(raw)
        if code in NOTABLE_STATUS_LABELS:
            return code
        raise ValueError(
            f"Unsupported notable status code {code}. "
            f"Valid codes: {sorted(NOTABLE_STATUS_LABELS)}."
        )
    key = raw.lower().replace("-", "_").replace(" ", "_")
    if key in NOTABLE_STATUS_MAP:
        return NOTABLE_STATUS_MAP[key]
    raise ValueError(
        f"Unsupported notable status '{status}'. "
        f"Valid values: {', '.join(NOTABLE_STATUS_MAP)}."
    )


def notable_status_label(status: int | str | None, fallback: str = "") -> str:
    """Resolve a human-readable Splunk ES notable status label."""
    if status is None or str(status).strip() == "":
        return fallback
    try:
        code = normalize_notable_status(status)
        return NOTABLE_STATUS_LABELS[code]
    except ValueError:
        return fallback or str(status).strip()


def _normalize_notable_row(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a raw `` `notable` `` SPL result row into a consistent dictionary."""
    raw_status = row.get("status")
    status_val: int | str = ""
    if raw_status is not None and str(raw_status).strip() != "":
        try:
            status_val = normalize_notable_status(raw_status)
        except ValueError:
            status_val = _stringify_field(raw_status)

    explicit_label = _stringify_field(row.get("status_label"))
    label = explicit_label or notable_status_label(status_val, fallback="Unknown")

    return {
        "event_id": _stringify_field(row.get("event_id") or row.get("rule_id")),
        "rule_name": _stringify_field(row.get("rule_name") or row.get("search_name")),
        "urgency": _stringify_field(row.get("urgency")).lower(),
        "status": status_val,
        "status_label": label,
        "owner": _stringify_field(row.get("owner")) or "unassigned",
        "disposition": _stringify_field(row.get("disposition_label") or row.get("disposition")),
        "security_domain": _stringify_field(row.get("security_domain")),
        "src": _stringify_field(row.get("src") or row.get("src_ip")),
        "dest": _stringify_field(row.get("dest") or row.get("dest_ip")),
        "user": _stringify_field(row.get("user") or row.get("src_user")),
        "risk_score": _stringify_field(row.get("risk_score")),
        "_time": _stringify_field(row.get("_time")),
        "raw": dict(row),
    }


def _validate_threat_collection(collection: str) -> str:
    """Validate and return a Splunk ES Threat Intelligence KV Store collection name."""
    clean = str(collection).strip()
    if clean not in THREAT_INTEL_COLLECTIONS:
        raise ValueError(
            f"Unsupported threat intelligence collection '{collection}'. "
            f"Valid collections: {', '.join(THREAT_INTEL_COLLECTIONS)}."
        )
    return clean


def _raise_for_es_response(response: requests.Response, endpoint: str, action: str) -> None:
    """Raise ``SplunkESError`` with parsed Splunk REST messages on HTTP error."""
    messages: list[str] = []
    err_msg = ""
    try:
        payload = response.json()
        messages = _extract_splunk_message_list(payload)
        err_msg = _extract_splunk_messages(payload) or response.text
    except ValueError:
        err_msg = response.text
    raise SplunkESError(
        f"Failed to {action} (HTTP {response.status_code}): {err_msg}",
        status_code=response.status_code,
        endpoint=endpoint,
        messages=messages,
    )


class SplunkESClient:
    """Splunk Enterprise Security (ES) REST and SPL client wrapping ``SplunkClient``."""

    def __init__(
        self,
        *,
        splunk_client: SplunkClient | None = None,
        host: str | None = None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        app: str | None = SPLUNK_ES_APP,
        verify_ssl: bool | str | None = None,
        session: requests.Session | None = None,
        request_timeout: float = 15.0,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        poll_interval: float = 2.0,
    ) -> None:
        if splunk_client is not None:
            self.client = splunk_client
            self._owns_client = False
            self.app = (app or splunk_client.app or SPLUNK_ES_APP).strip()
        else:
            target_app = (app or SPLUNK_ES_APP).strip() or SPLUNK_ES_APP
            self.client = SplunkClient(
                host=host,
                token=token,
                username=username,
                password=password,
                app=target_app,
                verify_ssl=verify_ssl,
                session=session,
                request_timeout=request_timeout,
                max_retries=max_retries,
                backoff_base=backoff_base,
                poll_interval=poll_interval,
            )
            self._owns_client = True
            self.app = self.client.app
        self.host = self.client.host

    def close(self) -> None:
        """Close the underlying ``SplunkClient`` if owned by this ES client."""
        if self._owns_client:
            self.client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Notable Events
    # ------------------------------------------------------------------

    def list_notables(
        self,
        *,
        earliest: str = "-24h",
        latest: str = "now",
        urgency: str | None = None,
        status: str | None = None,
        owner: str | None = None,
        rule_name: str | None = None,
        search_text: str | None = None,
        limit: int = 100,
        timeout: int = 120,
    ) -> list[dict[str, Any]]:
        """Query Splunk ES Notable Events using the `` `notable` `` SPL macro."""
        safe_limit = max(1, int(limit))
        clauses: list[str] = ["`notable`"]

        if urgency and urgency.strip():
            clean_urgency = urgency.strip().lower()
            if clean_urgency not in NOTABLE_URGENCIES:
                raise ValueError(
                    f"Unsupported urgency '{urgency}'. "
                    f"Valid urgencies: {', '.join(NOTABLE_URGENCIES)}."
                )
            clauses.append(f'| search urgency="{_escape_spl_string(clean_urgency)}"')

        if status is not None and str(status).strip():
            status_code = normalize_notable_status(status)
            status_lbl = NOTABLE_STATUS_LABELS[status_code]
            clauses.append(
                f'| search (status={status_code} OR status_label="{_escape_spl_string(status_lbl)}")'
            )

        if owner and owner.strip():
            clauses.append(f'| search owner="{_escape_spl_string(owner)}"')

        if rule_name and rule_name.strip():
            clauses.append(f'| search rule_name="*{_escape_spl_string(rule_name)}*"')

        if search_text and search_text.strip():
            clauses.append(f'| search "*{_escape_spl_string(search_text)}*"')

        clauses.append(f"| head {safe_limit}")
        spl = " ".join(clauses)

        res = self.client.run_search(
            spl,
            earliest=earliest,
            latest=latest,
            app=self.app,
            count=safe_limit,
            timeout=timeout,
        )
        if res.get("status") != "success":
            raise SplunkESError(
                str(res.get("error_message") or "Failed to query Splunk ES notable events."),
                messages=list(res.get("messages") or []),
            )
        rows = res.get("results") or []
        return [_normalize_notable_row(row) for row in rows if isinstance(row, dict)]

    def update_notable(
        self,
        event_ids: list[str],
        *,
        status: int | str | None = None,
        urgency: str | None = None,
        owner: str | None = None,
        disposition: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Update one or more Splunk ES notable events via ``/services/notable_update``."""
        clean_ids = [str(eid).strip() for eid in event_ids if str(eid).strip()]
        if not clean_ids:
            raise ValueError("At least one notable event_id is required.")

        payload: dict[str, Any] = {"ruleUIDs": clean_ids}
        has_mutation = False

        if status is not None and str(status).strip() != "":
            payload["status"] = str(normalize_notable_status(status))
            has_mutation = True

        if urgency is not None and urgency.strip():
            clean_urgency = urgency.strip().lower()
            if clean_urgency not in NOTABLE_URGENCIES:
                raise ValueError(
                    f"Unsupported urgency '{urgency}'. "
                    f"Valid urgencies: {', '.join(NOTABLE_URGENCIES)}."
                )
            payload["urgency"] = clean_urgency
            has_mutation = True

        if owner is not None and owner.strip():
            payload["newOwner"] = owner.strip()
            has_mutation = True

        if disposition is not None and disposition.strip():
            payload["disposition"] = disposition.strip()
            has_mutation = True

        if comment is not None and comment.strip():
            payload["comment"] = comment.strip()
            has_mutation = True

        if not has_mutation:
            raise ValueError(
                "At least one update field (status, urgency, owner, disposition, or comment) "
                "must be provided."
            )

        endpoint = "/services/notable_update?output_mode=json"
        response = self.client._request("POST", endpoint, data=payload)
        if response.status_code not in (200, 201):
            _raise_for_es_response(response, endpoint, "update notable event(s)")

        try:
            body = response.json()
        except ValueError:
            body = {"success": True, "ruleUIDs": clean_ids}
        if not isinstance(body, dict):
            return {"success": True, "ruleUIDs": clean_ids, "response": body}
        return body

    # ------------------------------------------------------------------
    # Correlation Searches
    # ------------------------------------------------------------------

    def list_correlation_searches(
        self,
        search_filter: str | None = None,
        count: int = 200,
    ) -> list[dict[str, Any]]:
        """List Splunk ES correlation searches from saved searches."""
        safe_count = max(0, int(count))
        endpoint = (
            f"/servicesNS/nobody/{SPLUNK_ES_APP}/saved/searches"
            f"?output_mode=json&count={safe_count}"
        )
        response = self.client._request("GET", endpoint)
        if response.status_code != 200:
            _raise_for_es_response(response, endpoint, "list correlation searches")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned when listing correlation searches: {exc}",
                endpoint=endpoint,
            ) from exc

        entries = payload.get("entry", []) if isinstance(payload, dict) else []
        needle = search_filter.strip().lower() if search_filter else ""
        results: list[dict[str, Any]] = []

        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                content = entry.get("content")
                if not isinstance(content, dict):
                    content = {}
                acl = entry.get("acl")
                if not isinstance(acl, dict):
                    acl = {}

                action_notable = _safe_bool(content.get("action.notable"), False)
                action_risk = _safe_bool(content.get("action.risk"), False)
                corr_enabled = _safe_bool(content.get("action.correlationsearch.enabled"), False)
                if not (action_notable or action_risk or corr_enabled):
                    continue

                name = str(entry.get("name") or "")
                label = str(content.get("action.correlationsearch.label") or name)
                description = str(content.get("description") or "")
                search_spl = str(content.get("search") or "")

                if needle and not (
                    needle in name.lower()
                    or needle in label.lower()
                    or needle in description.lower()
                    or needle in search_spl.lower()
                ):
                    continue

                disabled = _safe_bool(content.get("disabled"), False)
                results.append(
                    {
                        "name": name,
                        "label": label,
                        "app": str(acl.get("app") or SPLUNK_ES_APP),
                        "description": description,
                        "search": search_spl,
                        "cron_schedule": str(content.get("cron_schedule") or ""),
                        "disabled": disabled,
                        "enabled": not disabled,
                        "action_notable": action_notable,
                        "action_risk": action_risk,
                        "security_domain": str(
                            content.get("action.notable.param.security_domain") or ""
                        ),
                        "severity": str(content.get("action.notable.param.severity") or ""),
                        "raw": content,
                    }
                )
        return results

    def set_correlation_search_enabled(self, name: str, enabled: bool) -> dict[str, Any]:
        """Enable or disable a Splunk ES correlation search by name."""
        clean_name = str(name).strip()
        if not clean_name:
            raise ValueError("Correlation search name is required.")
        quoted_name = quote(clean_name, safe="")
        endpoint = (
            f"/servicesNS/nobody/{SPLUNK_ES_APP}/saved/searches/{quoted_name}?output_mode=json"
        )
        disabled_val = "0" if enabled else "1"
        response = self.client._request("POST", endpoint, data={"disabled": disabled_val})
        if response.status_code not in (200, 201):
            _raise_for_es_response(
                response,
                endpoint,
                f"{'enable' if enabled else 'disable'} correlation search '{clean_name}'",
            )
        try:
            body = response.json()
        except ValueError:
            body = {}
        return {
            "name": clean_name,
            "enabled": bool(enabled),
            "disabled": not bool(enabled),
            "response": body,
        }

    # ------------------------------------------------------------------
    # Threat Intelligence KV Store
    # ------------------------------------------------------------------

    def list_threat_collections(self) -> tuple[str, ...]:
        """Return supported Splunk ES Threat Intelligence KV Store collection names."""
        return THREAT_INTEL_COLLECTIONS

    def query_threat_intel(
        self,
        collection: str,
        *,
        query: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query entries from a Splunk ES Threat Intelligence KV Store collection."""
        clean_col = _validate_threat_collection(collection)
        endpoint = (
            f"/servicesNS/nobody/{SPLUNK_TI_APP}/storage/collections/data/{clean_col}"
        )
        params: dict[str, Any] = {}
        safe_limit = max(0, int(limit))
        if safe_limit > 0:
            params["limit"] = safe_limit
        if query is not None:
            params["query"] = json.dumps(query, ensure_ascii=False)

        response = self.client._request("GET", endpoint, params=params or None)
        if response.status_code != 200:
            _raise_for_es_response(
                response,
                endpoint,
                f"query threat intelligence collection '{clean_col}'",
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkESError(
                f"Invalid JSON returned from threat intel collection '{clean_col}': {exc}",
                endpoint=endpoint,
            ) from exc

        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        return []

    def add_threat_intel_entry(
        self,
        collection: str,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        """Insert a single indicator entry into a Splunk ES Threat Intel KV Store collection."""
        clean_col = _validate_threat_collection(collection)
        if not isinstance(entry, dict) or not entry:
            raise ValueError("Threat intelligence entry must be a non-empty dictionary.")

        endpoint = (
            f"/servicesNS/nobody/{SPLUNK_TI_APP}/storage/collections/data/{clean_col}"
        )
        response = self.client._request("POST", endpoint, json=entry)
        if response.status_code not in (200, 201):
            _raise_for_es_response(
                response,
                endpoint,
                f"add threat intelligence entry to '{clean_col}'",
            )
        try:
            body = response.json()
        except ValueError:
            body = {}
        if isinstance(body, dict):
            return body
        return {"response": body}

    # ------------------------------------------------------------------
    # Assets, Identities & Risk-Based Alerting (RBA)
    # ------------------------------------------------------------------

    def lookup_asset(self, query: str = "", limit: int = 50) -> list[dict[str, Any]]:
        """Search the Splunk ES ``asset_lookup_by_str`` lookup table."""
        safe_limit = max(1, int(limit))
        spl = "| inputlookup asset_lookup_by_str"
        if query and query.strip():
            spl += f' | search "*{_escape_spl_string(query)}*"'
        spl += f" | head {safe_limit}"

        res = self.client.run_search(
            spl,
            earliest="-24h",
            latest="now",
            app=self.app,
            count=safe_limit,
        )
        if res.get("status") != "success":
            raise SplunkESError(
                str(res.get("error_message") or "Failed to lookup Splunk ES assets."),
                messages=list(res.get("messages") or []),
            )
        return [row for row in (res.get("results") or []) if isinstance(row, dict)]

    def lookup_identity(self, query: str = "", limit: int = 50) -> list[dict[str, Any]]:
        """Search the Splunk ES ``identity_lookup_expanded`` lookup table."""
        safe_limit = max(1, int(limit))
        spl = "| inputlookup identity_lookup_expanded"
        if query and query.strip():
            spl += f' | search "*{_escape_spl_string(query)}*"'
        spl += f" | head {safe_limit}"

        res = self.client.run_search(
            spl,
            earliest="-24h",
            latest="now",
            app=self.app,
            count=safe_limit,
        )
        if res.get("status") != "success":
            raise SplunkESError(
                str(res.get("error_message") or "Failed to lookup Splunk ES identities."),
                messages=list(res.get("messages") or []),
            )
        return [row for row in (res.get("results") or []) if isinstance(row, dict)]

    def list_risk_events(
        self,
        *,
        risk_object: str | None = None,
        earliest: str = "-24h",
        latest: str = "now",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query Splunk ES Risk-Based Alerting (RBA) events from ``index=risk``."""
        safe_limit = max(1, int(limit))
        spl = "search index=risk"
        if risk_object and risk_object.strip():
            spl += f' risk_object="{_escape_spl_string(risk_object)}"'
        spl += f" | head {safe_limit}"

        res = self.client.run_search(
            spl,
            earliest=earliest,
            latest=latest,
            app=self.app,
            count=safe_limit,
        )
        if res.get("status") != "success":
            raise SplunkESError(
                str(res.get("error_message") or "Failed to query Splunk ES risk events."),
                messages=list(res.get("messages") or []),
            )
        return [row for row in (res.get("results") or []) if isinstance(row, dict)]
