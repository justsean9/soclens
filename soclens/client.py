"""Unified Recorded Future Core & Sandbox API client."""

from __future__ import annotations

import json
import logging
import math
import os
import random
import re
import threading
import time
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

from soclens.config import (
    ConfigurationError,
    ConfiguredSession,
    get_rf_asi_key,
    get_rf_base_url,
    get_rf_pfi_token,
    get_rf_riskrecon_token,
    get_rf_sandbox_token,
    get_rf_token,
    get_rf_verify_ssl,
    has_rf_ssl_config_override,
    parse_ssl_verify,
    record_api_error,
    suppress_insecure_ssl_warnings,
)

logger = logging.getLogger("soclens.client")

WATCHLIST_DEFAULT_LIMIT = 1000
WATCHLIST_WARNING_THRESHOLD = 900
MAX_ENTITY_TAGS = 9
MAX_SOAR_IOCS = 1000


class ListType(StrEnum):
    """All 21 Recorded Future Watch List / Entity List types."""

    ENTITY = "entity"
    SOURCE = "source"
    TEXT = "text"
    CUSTOM = "custom"
    IP = "ip"
    DOMAIN = "domain"
    TECH_STACK = "tech_stack"
    INDUSTRY = "industry"
    BRAND = "brand"
    PARTNER = "partner"
    INDUSTRY_PEER = "industry_peer"
    LOCATION = "location"
    SUPPLIER = "supplier"
    VULNERABILITY = "vulnerability"
    COMPANY = "company"
    HASH = "hash"
    OPERATION = "operation"
    ATTACKER = "attacker"
    TARGET = "target"
    METHOD = "method"
    EXECUTIVE = "executive"


LIST_TYPES: tuple[str, ...] = tuple(t.value for t in ListType)

RF_ID_PREFIXES: tuple[str, ...] = (
    "asn:",
    "ext:aws:",
    "bin:",
    "bitcoin:",
    "email:",
    "hash:",
    "idn:",
    "ip:",
    "mitre:",
    "num:",
    "cc:",
    "tel:",
    "v:",
    "url:",
    "uuid:",
    "wmid:",
    "report:",
    "doc:",
    "uhash:",
    "enum:",
    "vuln:",
    "company:",
    "malware:",
    "threatactor:",
)

AUTO_RESOLVED_ENTITY_TYPES: dict[str, str] = {
    "ipaddress": "IpAddress",
    "internetdomainname": "InternetDomainName",
    "hash": "Hash",
    "cybervulnerability": "CyberVulnerability",
}

PLAYBOOK_CATEGORY_PATH_MAP: dict[str, str] = {
    "domain_abuse": "domain_abuse",
    "malicious_sites": "malicious_sites",
    "cyber_vulnerability": "vulnerability",
    "vulnerability": "vulnerability",
    "code_repo_leakage": "code_repo_leakage",
    "third_party_risk": "third_party_risk",
    "identity_novel_exposures": "identity_novel_exposures",
    "geopolitics_facility": "geopolitics_facility",
    "malware_report": "malware_report",
    "bank_checks": "bank_checks",
    "dark_web": "dark_web_brand",
    "dark_web_brand": "dark_web_brand",
    "socmed_impersonation": "social_media_impersonation",
    "social_media_impersonation": "social_media_impersonation",
}

_V2_TYPE_ALIASES: dict[str, str] = {
    "ip": "ip",
    "ipaddress": "ip",
    "domain": "domain",
    "internetdomainname": "domain",
    "hash": "hash",
    "url": "url",
    "vulnerability": "vulnerability",
    "cybervulnerability": "vulnerability",
    "malware": "malware",
    "company": "company",
}

_V2_RISKLIST_TYPES: frozenset[str] = frozenset({"ip", "domain", "hash", "url", "vulnerability"})
_V2_RISKRULES_TYPES: frozenset[str] = frozenset(
    {"ip", "domain", "hash", "url", "vulnerability", "company"}
)
_V2_FIELDS_TYPES: frozenset[str] = frozenset(
    {"ip", "domain", "hash", "url", "vulnerability", "company", "malware"}
)

ENTITY_ID_PREFIXES: dict[str, str] = {
    "ASNumber": "asn:",
    "AWSAccessKey": "ext:aws:",
    "BankIdentificationNumber": "bin:",
    "BitcoinAddress": "bitcoin:",
    "EmailAddress": "email:",
    "Hash": "hash:",
    "InternetDomainName": "idn:",
    "IpAddress": "ip:",
    "MitreAttackIdentifier": "mitre:",
    "NumericIdentifier": "num:",
    "PaymentCardNumber": "cc:",
    "PhoneNumber": "tel:",
    "ProductVersion": "v:",
    "URL": "url:",
    "UUID": "uuid:",
    "WebMoneyID": "wmid:",
}

ANALYST_NOTE_TOPICS: dict[str, str] = {
    "Actor Profile": "TXSFt2",
    "Analyst On Demand Report": "VllhvH",
    "Card Fraud Trends & Updates": "rcSgUb",
    "Carding & Fraud Tutorials": "rcSgUd",
    "Country Risk Update": "pyo2g2",
    "Cyber Threat Analysis": "TXSFt1",
    "Executive Insights": "t38oMj",
    "Flash Report": "TXSFt0",
    "Fraud Source Intelligence": "rcSgUa",
    "Fraud TTP Analysis": "rcSgUc",
    "Geopolitical Flash Event": "h4G-3F",
    "Geopolitical Intelligence Summary": "aUyI9M",
    "Geopolitical Profile": "h4G-3L",
    "Geopolitical Threat Forecast": "h4G-3H",
    "Geopolitical Validated Event": "h4G-3N",
    "Hunting Package": "ZjnoP2",
    "Indicator": "TXSFt4",
    "Informational": "UrMRnT",
    "Insikt Research Lead": "hPX1cE",
    "Magecart E-Skimmer Reports": "rcSgUZ",
    "Malware/Tool Profile": "UX0YIU",
    "Nuclei Template Rule": "2QsLey",
    "Payment Card Breach Alerts": "rcSgUY",
    "Ransomware Actor Profile": "xG68dQ",
    "Ransomware Tool Profile": "xG68dS",
    "Regular Vendor Vulnerability Disclosures": "hYWSFk",
    "Sigma Rule": "g1KBGI",
    "SNORT Rule": "ZjnoP0",
    "Source Profile": "UZmDut",
    "Suricata Rule": "t2frPZ",
    "The Record by Recorded Future": "irEim2",
    "Threat Lead": "TXSFt3",
    "TTP Instance": "aDKkpk",
    "Validated Intelligence Event": "TXSFt5",
    "Vulnerability Intelligence": "wJv-Gk",
    "Weekly Threat Landscape": "VllhvG",
    "YARA Rule": "VTrvnW",
}

_ANALYST_NOTE_TOPICS_LOWER: dict[str, str] = {
    name.lower(): code for name, code in ANALYST_NOTE_TOPICS.items()
}

V2_EXTENSION_CATALOG: dict[str, tuple[str, ...]] = {
    "ip": (
        "CarbonBlack",
        "Censys",
        "GreyNoiseIntelligence",
        "Kaspersky_Threat_Intelligence_Portal",
        "SentinelOne",
        "ThreatConnect",
        "active_ip_geo",
        "active_ip_history",
    ),
    "domain": (
        "CarbonBlack",
        "Kaspersky_Threat_Intelligence_Portal",
        "ThreatConnect",
        "active_bitdefender",
        "active_security_trails",
        "alienvault",
        "cisco_umbrella",
        "domaintools_iris",
    ),
    "hash": (
        "CarbonBlack",
        "ThreatConnect",
        "facebookte",
        "servicenow",
        "Censys",
        "Kaspersky_Threat_Intelligence_Portal",
        "SentinelOne",
        "active_polyswarm",
    ),
    "url": (
        "Kaspersky_Threat_Intelligence_Portal",
        "ThreatConnect",
        "active_bitdefender",
        "facebookte",
        "inquest",
        "mandiant",
        "phishme",
        "report_website",
    ),
    "vulnerability": (
        "EVEClient",
        "reversinglabs",
        "alienvault",
        "shodan",
        "bitsight",
        "xforce",
        "epss",
        "facebookte",
    ),
    "malware": (
        "bitsight",
        "facebookte",
        "hunter_malware",
        "mandiant",
        "reversinglabs",
        "xforce",
    ),
}

MALWARE_INTEL_FIELDS: tuple[str, ...] = (
    "sha256",
    "ip_address",
    "domain",
    "url",
    "command_line",
    "ttp",
    "dst_port",
    "signature",
)

PFI_PIPELINES: dict[str, str] = {
    "cards_full": "/pipeline/cardsFullData",
    "cards_partial": "/pipeline/cardsPartialData",
    "cards_partial_sold": "/pipeline/cardsPartialDataSold",
    "checks": "/pipeline/checks",
    "bank_accounts": "/pipeline/bankAccounts",
    "cpp_merchants": "/pipeline/merchantsCpp",
    "magecart_domain": "/pipeline/merchantsMagecartDomain",
    "magecart_merchant": "/pipeline/merchantsMagecartMerchant",
    "magescanner_scans": "/pipeline/merchantsMagescannerScans",
    "tester_merchant": "/pipeline/merchantsTester",
}

_MALWARE_INTEL_MIN_START_DATE = "2023-11-01"


class RecordedFutureError(Exception):
    """Base exception for Recorded Future API and network failures."""

    def __init__(
        self,
        status_code: int | None,
        message: str,
        trace_id: str | None = None,
        reason: str | None = None,
        payload: Any = None,
        endpoint: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.message = message
        self.trace_id = trace_id
        self.reason = reason
        self.payload = payload
        self.endpoint = endpoint
        prefix = f"[HTTP {status_code}] " if status_code is not None else ""
        suffix = f" (trace_id={trace_id})" if trace_id else ""
        super().__init__(f"{prefix}{message}{suffix}")


class RecordedFutureAuthError(RecordedFutureError):
    """Raised on HTTP 401 or 403 permission/entitlement errors."""

    def __init__(
        self,
        status_code: int | None,
        message: str,
        trace_id: str | None = None,
        permission_type: str = "unauthorized",
        *,
        reason: str | None = None,
        payload: Any = None,
        endpoint: str | None = None,
    ) -> None:
        self.permission_type = permission_type
        super().__init__(
            status_code=status_code,
            message=message,
            trace_id=trace_id,
            reason=reason,
            payload=payload,
            endpoint=endpoint,
        )


class RecordedFutureRateLimitError(RecordedFutureError):
    """Raised when HTTP 429 retries are exhausted."""

    def __init__(
        self,
        status_code: int | None = 429,
        message: str = "Rate limit exceeded",
        trace_id: str | None = None,
        retry_after: float | None = None,
        *,
        reason: str | None = None,
        payload: Any = None,
        endpoint: str | None = None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(
            status_code=status_code,
            message=message,
            trace_id=trace_id,
            reason=reason,
            payload=payload,
            endpoint=endpoint,
        )


class RecordedFutureAPIError(RecordedFutureError):
    """Raised on non-auth, non-rate-limit HTTP 4xx/5xx or network errors."""

    def __init__(
        self,
        status_code: int | None,
        message: str,
        trace_id: str | None = None,
        reason: str | None = None,
        payload: Any = None,
        *,
        endpoint: str | None = None,
    ) -> None:
        super().__init__(
            status_code=status_code,
            message=message,
            trace_id=trace_id,
            reason=reason,
            payload=payload,
            endpoint=endpoint,
        )


_PROXY_BLOCK_MARKERS: tuple[str, ...] = (
    "<html",
    "<!doctype html",
    "proxysg",
    "blue coat",
    "bluecoat",
    "edge swg",
    "policy_denied",
    "symantec web security",
)

# Trailing alphabetic extension (e.g. ".com", ".exe", ".bat", ".sh") on the final
# URL path segment triggers ProxySG/Edge SWG executable-extension blocks (HTTP 403).
_TRAILING_PATH_EXT_RE = re.compile(r"\.[A-Za-z][A-Za-z0-9-]{0,62}$")


def _append_proxysg_safe_slash(endpoint: str, *, always: bool = False) -> str:
    """Append a trailing ``/`` so ProxySG does not treat ``.com``/``.exe`` as a file download.

    Broadcom/Symantec ProxySG (Edge SWG) evaluates ``url.extension`` on the final
    URL path segment, so paths like ``/v2/domain/example.com`` are blocked with HTTP
    403 as DOS ``.com`` executable downloads. Appending ``/`` makes
    ``url.extension`` empty while remaining valid for Recorded Future REST paths.
    """
    if endpoint.endswith("/"):
        return endpoint
    if always:
        return f"{endpoint}/"
    last_segment = endpoint.rsplit("/", 1)[-1]
    if _TRAILING_PATH_EXT_RE.search(last_segment):
        return f"{endpoint}/"
    return endpoint


def classify_403_permission(
    message: str | None,
    reason: str | None = None,
    payload: Any = None,
) -> str:
    """Classify HTTP 403 errors into RF entitlement, data-group ACL, or proxy-block categories."""
    parts: list[str] = []
    if isinstance(message, str):
        parts.append(message)
    if isinstance(reason, str):
        parts.append(reason)
    if isinstance(payload, (dict, list)):
        try:
            parts.append(json.dumps(payload, default=str))
        except (TypeError, ValueError):
            pass
    combined = " ".join(parts).lower()
    if "missing api privileges" in combined:
        return "missing_api_privileges"
    if "missing data permissions" in combined:
        return "missing_data_permissions"
    if payload is None and any(marker in combined for marker in _PROXY_BLOCK_MARKERS):
        return "proxy_blocked"
    return "unauthorized"


def parse_retry_after(headers: Any) -> float | None:
    """Parse ``Retry-After`` HTTP header (numeric seconds or HTTP-date)."""
    if not isinstance(headers, Mapping):
        return None

    raw_val: Any = None
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == "retry-after":
            raw_val = value
            break

    if raw_val is None or not isinstance(raw_val, (str, int, float)):
        return None

    text = str(raw_val).strip()
    if not text:
        return None

    try:
        seconds = float(text)
        if not math.isfinite(seconds):
            return None
        return max(0.0, seconds)
    except ValueError:
        pass

    try:
        dt = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    delta = (dt - datetime.now(UTC)).total_seconds()
    return max(0.0, delta)


def _require_non_empty(value: str, field_name: str) -> str:
    """Validate that a required string argument is non-empty after stripping."""
    clean = value.strip() if isinstance(value, str) else ""
    if not clean:
        raise ValueError(f"{field_name} cannot be empty.")
    return clean


def _is_rf_entity_id(entity_type: str, value: str) -> bool:
    """Determine if ``value`` should be sent as ``{"id": ...}`` vs ``{"type", "name"}``."""
    clean = value.strip()
    if not clean:
        return False
    lower = clean.lower()
    if lower.startswith(("http://", "https://")):
        return False
    if lower.startswith(RF_ID_PREFIXES):
        return True
    if entity_type.strip().lower() in AUTO_RESOLVED_ENTITY_TYPES:
        return False
    if len(clean) in (32, 40, 64) and re.fullmatch(r"[0-9a-fA-F]+", clean):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9]{4,10}", clean)) and any(c.isdigit() for c in clean)


class RecordedFutureClient:
    """Unified client for Recorded Future Core and Sandbox APIs.

    Implements persistent ``requests.Session`` pooling, ``Retry-After`` and
    jittered exponential backoff on ``429``/``5xx``/network failures, typed
    exceptions, 403 permission classification, and ``traceId`` JSONL logging.
    """

    CORE_BASE_URL = "https://api.recordedfuture.com"
    SANDBOX_BASE_URL = "https://sandbox.recordedfuture.com/api/v0"
    ASI_BASE_URL = "https://api.securitytrails.com/v2"
    PFI_BASE_URL = "https://pfi.regemini.com/api/v1"
    RISKRECON_BASE_URL = "https://api.riskrecon.com"
    RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

    def __init__(
        self,
        api_token: str | None = None,
        sandbox_token: str | None = None,
        base_url: str | None = None,
        session: requests.Session | None = None,
        error_log_dir: Path | str | None = None,
        sandbox_base_url: str | None = None,
        timeout: float = 30.0,
        *,
        stop_event: threading.Event | None = None,
        asi_api_key: str | None = None,
        asi_base_url: str | None = None,
        pfi_token: str | None = None,
        pfi_base_url: str | None = None,
        riskrecon_token: str | None = None,
        riskrecon_base_url: str | None = None,
        verify_ssl: bool | str | Path | None = None,
        insecure: bool | None = None,
        retry_backoff: float | None = None,
    ) -> None:
        if api_token is not None:
            self.api_token: str | None = api_token.strip() or None
        else:
            self.api_token = get_rf_token(required=False)

        if sandbox_token is not None:
            self.sandbox_token: str | None = sandbox_token.strip() or None
        else:
            self.sandbox_token = get_rf_sandbox_token(
                required=False, default_core_token=self.api_token
            )

        if asi_api_key is not None:
            self.asi_api_key: str | None = asi_api_key.strip() or None
        else:
            self.asi_api_key = get_rf_asi_key(required=False)

        if pfi_token is not None:
            self.pfi_token: str | None = pfi_token.strip() or None
        else:
            self.pfi_token = get_rf_pfi_token(
                required=False, default_core_token=self.api_token
            )

        if riskrecon_token is not None:
            self.riskrecon_token: str | None = riskrecon_token.strip() or None
        else:
            self.riskrecon_token = get_rf_riskrecon_token(required=False)

        if not self.api_token:
            logger.debug("No Recorded Future Core API token configured at initialization.")

        self.core_base_url = get_rf_base_url("core", explicit=base_url)
        self.sandbox_base_url = get_rf_base_url("sandbox", explicit=sandbox_base_url)
        self.asi_base_url = get_rf_base_url("asi", explicit=asi_base_url)
        self.pfi_base_url = get_rf_base_url("pfi", explicit=pfi_base_url)
        self.riskrecon_base_url = get_rf_base_url("riskrecon", explicit=riskrecon_base_url)
        self.session: requests.Session = (
            session if session is not None else ConfiguredSession()
        )
        if (
            verify_ssl is None
            and insecure is None
            and not has_rf_ssl_config_override()
            and session is not None
        ):
            session_verify = getattr(session, "verify", None)
            if isinstance(session_verify, (bool, str)) and session_verify is not True:
                self.verify_ssl: bool | str = session_verify
            else:
                self.verify_ssl = get_rf_verify_ssl()
        else:
            self.verify_ssl = get_rf_verify_ssl(explicit=verify_ssl, insecure=insecure)

        if session is None or verify_ssl is not None or insecure is not None or self.verify_ssl is not True:
            self.session.verify = self.verify_ssl

        if self.verify_ssl is False:
            suppress_insecure_ssl_warnings()
            logger.warning(
                "SSL certificate verification is DISABLED for Recorded Future API requests (insecure/proxy mode)."
            )

        self.error_log_dir: Path | None = (
            Path(error_log_dir) if error_log_dir is not None else None
        )
        self.timeout = timeout
        if retry_backoff is not None:
            self.retry_backoff = max(0.0, float(retry_backoff))
        else:
            raw_backoff = os.environ.get("SOCLENS_RF_RETRY_BACKOFF", "").strip()
            if raw_backoff:
                try:
                    self.retry_backoff = max(0.0, float(raw_backoff))
                except ValueError:
                    self.retry_backoff = 2.0
            else:
                self.retry_backoff = 2.0
        self._stop_event: threading.Event | None = stop_event
        self.last_trace_id: str | None = None

    @property
    def base_url(self) -> str:
        """Return the configured Core API base URL."""
        return self.core_base_url

    def set_verify_ssl(self, verify_ssl: bool | str | Path) -> bool | str:
        """Update SSL verification behavior at runtime for this client and its session."""
        resolved = parse_ssl_verify(verify_ssl, default=True)
        self.verify_ssl = resolved
        self.session.verify = resolved
        if resolved is False:
            suppress_insecure_ssl_warnings()
            logger.warning(
                "SSL certificate verification is DISABLED for Recorded Future API requests (insecure/proxy mode)."
            )
        else:
            logger.info("Updated Recorded Future SSL verification to %r.", resolved)
        return resolved

    def reload_from_config(self) -> None:
        """Re-resolve tokens, base URLs, and SSL verification from active settings/env."""
        self.api_token = get_rf_token(required=False)
        self.sandbox_token = get_rf_sandbox_token(
            required=False, default_core_token=self.api_token
        )
        self.asi_api_key = get_rf_asi_key(required=False)
        self.pfi_token = get_rf_pfi_token(
            required=False, default_core_token=self.api_token
        )
        self.riskrecon_token = get_rf_riskrecon_token(required=False)
        self.core_base_url = get_rf_base_url("core")
        self.sandbox_base_url = get_rf_base_url("sandbox")
        self.asi_base_url = get_rf_base_url("asi")
        self.pfi_base_url = get_rf_base_url("pfi")
        self.riskrecon_base_url = get_rf_base_url("riskrecon")
        self.set_verify_ssl(get_rf_verify_ssl())

    def check_connection(self) -> dict[str, Any]:
        """Verify Recorded Future Core API connectivity and token validity."""
        lists = self.get_watchlists(limit=1, include_all_types=False)
        return {
            "connected": True,
            "base_url": self.core_base_url,
            "sample_lists": len(lists),
        }

    def _get_headers(
        self, is_sandbox: bool = False, *, auth_mode: str | None = None
    ) -> dict[str, str]:
        """Return authentication and content-type headers for the target RF platform."""
        mode = auth_mode or ("sandbox" if is_sandbox else "core")
        if mode == "sandbox":
            token = self.sandbox_token or self.api_token
            if not token:
                raise ConfigurationError(
                    "Recorded Future Sandbox API token is required but not set."
                )
            return {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
        if mode == "taxii2":
            if not self.api_token:
                raise ConfigurationError("Recorded Future API token is required for TAXII 2.1.")
            return {
                "Accept": "application/taxii+json;version=2.1",
            }
        if mode == "asi":
            if not self.asi_api_key:
                raise ConfigurationError(
                    "Recorded Future ASI API key is required. "
                    "Set RF_ASI_API_KEY or SECURITYTRAILS_API_KEY."
                )
            return {
                "apikey": self.asi_api_key,
                "Content-Type": "application/json",
            }
        if mode == "pfi":
            token = self.pfi_token or self.api_token
            if not token:
                raise ConfigurationError(
                    "Recorded Future PFI token is required. Set RF_PFI_TOKEN or RF_API_TOKEN."
                )
            return {
                "X-RFToken": token,
                "Content-Type": "application/json",
            }
        if mode == "riskrecon":
            if not self.riskrecon_token:
                raise ConfigurationError(
                    "Recorded Future RiskRecon token is required. "
                    "Set RF_RISKRECON_TOKEN or RISKRECON_API_TOKEN."
                )
            return {
                "Authorization": f"Bearer {self.riskrecon_token}",
                "Content-Type": "application/json",
            }

        if not self.api_token:
            raise ConfigurationError("Recorded Future API token is required but not set.")

        return {
            "X-RFToken": self.api_token,
            "Content-Type": "application/json",
        }

    def _compute_backoff(self, backoff: float, attempt: int) -> float:
        """Compute bounded exponential backoff with multiplicative jitter."""
        base = min(max(backoff, 0.0) * (2**attempt), 60.0)
        return base * random.uniform(0.75, 1.25)

    def _wait_backoff(self, delay: float) -> bool:
        """Sleep for retry backoff; returns True if cancelled via stop_event."""
        if self._stop_event is None:
            time.sleep(delay)
            return False
        return self._stop_event.wait(delay)

    def _request(
        self,
        method: str,
        endpoint: str,
        json_data: dict[str, Any] | list[Any] | None = None,
        params: dict[str, Any] | None = None,
        retries: int = 5,
        backoff: float | None = None,
        is_sandbox: bool = False,
        *,
        headers_extra: dict[str, str] | None = None,
        base_url_override: str | None = None,
        timeout: float | None = None,
        raise_on_error: bool = True,
        auth: tuple[str, str] | None = None,
        auth_mode: str | None = None,
    ) -> requests.Response:
        """Execute an HTTP request with retry/backoff and structured error handling."""
        mode = auth_mode or ("sandbox" if is_sandbox else "core")
        if base_url_override:
            base = base_url_override.rstrip("/")
        elif mode == "sandbox":
            base = self.sandbox_base_url
        elif mode == "asi":
            base = self.asi_base_url
        elif mode == "pfi":
            base = self.pfi_base_url
        elif mode == "riskrecon":
            base = self.riskrecon_base_url
        else:
            base = self.core_base_url

        url = f"{base}{endpoint}"
        headers = self._get_headers(is_sandbox=is_sandbox, auth_mode=auth_mode)
        if headers_extra:
            headers.update(headers_extra)

        req_auth: tuple[str, str] | None = auth
        if req_auth is None and mode == "taxii2":
            if not self.api_token:
                raise ConfigurationError("Recorded Future API token is required for TAXII 2.1.")
            req_auth = ("", self.api_token)

        max_attempts = max(1, retries)
        effective_backoff = self.retry_backoff if backoff is None else backoff
        req_timeout = self.timeout if timeout is None else timeout

        for attempt in range(max_attempts):
            if self._stop_event is not None and self._stop_event.is_set():
                raise RecordedFutureAPIError(
                    None,
                    f"Request cancelled for {endpoint}",
                    reason="cancelled",
                    endpoint=endpoint,
                )
            try:
                req_kwargs: dict[str, Any] = {
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "json": json_data,
                    "params": params,
                    "timeout": req_timeout,
                    "verify": self.verify_ssl,
                }
                if req_auth is not None:
                    req_kwargs["auth"] = req_auth
                response = self.session.request(**req_kwargs)
            except requests.exceptions.SSLError as exc:
                logger.error("SSL error on %s %s: %s", method, url, exc)
                self._persist_error_record(
                    {
                        "endpoint": endpoint,
                        "method": method,
                        "status_code": None,
                        "trace_id": None,
                        "message": str(exc),
                        "reason": "ssl_error",
                        "category": "ssl_error",
                    }
                )
                raise RecordedFutureAPIError(
                    None,
                    (
                        f"SSL certificate verification failed on {endpoint}: {exc}. "
                        "If behind an internal/corporate proxy, pass --insecure / -k, "
                        "set RF_VERIFY_SSL=false (or RF_INSECURE_SSL=true), "
                        "or configure a CA bundle via --ca-bundle / RF_CA_BUNDLE."
                    ),
                    reason="ssl_error",
                    endpoint=endpoint,
                ) from exc
            except requests.exceptions.RequestException as exc:
                logger.error("Network error on %s %s: %s", method, url, exc)
                if attempt < max_attempts - 1:
                    delay = self._compute_backoff(effective_backoff, attempt)
                    if self._wait_backoff(delay):
                        raise RecordedFutureAPIError(
                            None,
                            f"Request cancelled for {endpoint}",
                            reason="cancelled",
                            endpoint=endpoint,
                        ) from exc
                    continue

                self._persist_error_record(
                    {
                        "endpoint": endpoint,
                        "method": method,
                        "status_code": None,
                        "trace_id": None,
                        "message": str(exc),
                        "reason": "network_error",
                        "category": "network_error",
                    }
                )
                raise RecordedFutureAPIError(
                    None,
                    f"Network error on {endpoint}: {exc}",
                    reason="network_error",
                    endpoint=endpoint,
                ) from exc

            status_code = response.status_code

            if status_code in self.RETRYABLE_STATUS_CODES:
                retry_after = (
                    parse_retry_after(getattr(response, "headers", None))
                    if status_code == 429
                    else None
                )
                if attempt < max_attempts - 1:
                    if status_code == 429:
                        self._log_api_error(endpoint, response, method=method)
                    if retry_after is not None:
                        delay = min(retry_after, 60.0)
                    else:
                        delay = self._compute_backoff(effective_backoff, attempt)
                    logger.warning(
                        "Retryable HTTP %s on %s %s (attempt %d/%d). Sleeping %.2fs...",
                        status_code,
                        method,
                        url,
                        attempt + 1,
                        max_attempts,
                        delay,
                    )
                    if self._wait_backoff(delay):
                        raise RecordedFutureAPIError(
                            None,
                            f"Request cancelled for {endpoint}",
                            reason="cancelled",
                            endpoint=endpoint,
                        )
                    continue

                meta = self._log_api_error(endpoint, response, method=method)
                if not raise_on_error:
                    return response
                if status_code == 429:
                    raise RecordedFutureRateLimitError(
                        status_code=429,
                        message=meta["message"],
                        trace_id=meta["trace_id"],
                        retry_after=retry_after,
                        reason=meta["reason"],
                        payload=meta["payload"],
                        endpoint=endpoint,
                    )
                raise RecordedFutureAPIError(
                    status_code=status_code,
                    message=meta["message"],
                    trace_id=meta["trace_id"],
                    reason=meta["reason"],
                    payload=meta["payload"],
                    endpoint=endpoint,
                )

            if status_code >= 400:
                meta = self._log_api_error(endpoint, response, method=method)
                if not raise_on_error:
                    return response
                if status_code in (401, 403):
                    perm = (
                        "unauthorized"
                        if status_code == 401
                        else classify_403_permission(
                            meta["message"], meta["reason"], meta["payload"]
                        )
                    )
                    raise RecordedFutureAuthError(
                        status_code=status_code,
                        message=meta["message"],
                        trace_id=meta["trace_id"],
                        permission_type=perm,
                        reason=meta["reason"],
                        payload=meta["payload"],
                        endpoint=endpoint,
                    )
                raise RecordedFutureAPIError(
                    status_code=status_code,
                    message=meta["message"],
                    trace_id=meta["trace_id"],
                    reason=meta["reason"],
                    payload=meta["payload"],
                    endpoint=endpoint,
                )

            return response

        raise RecordedFutureAPIError(None, f"Request to {endpoint} failed", endpoint=endpoint)

    def _persist_error_record(self, entry: dict[str, Any]) -> None:
        """Persist error telemetry to JSONL without masking original API errors."""
        try:
            record_api_error(entry, log_dir=self.error_log_dir)
        except OSError as exc:
            logger.debug("Could not write rf_api_errors.jsonl: %s", exc)

    def _log_api_error(
        self,
        endpoint: str,
        response: requests.Response,
        method: str = "UNKNOWN",
    ) -> dict[str, Any]:
        """Parse and log API errors across all RF payload schemas and persist traceId."""
        headers = getattr(response, "headers", None)
        header_trace_id: str | None = None
        if isinstance(headers, Mapping):
            for key, value in headers.items():
                if isinstance(key, str) and key.lower() in ("trace-id", "x-trace-id"):
                    if isinstance(value, str) and value.strip():
                        header_trace_id = value.strip()
                        break

        status_code = getattr(response, "status_code", None)
        msg = "Unknown error"
        reason = "N/A"
        trace_id: str | None = header_trace_id
        payload: Any = None
        category = "api_error"

        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                payload = error_data
                trace_raw = error_data.get("traceId") or error_data.get("trace_id")
                if isinstance(trace_raw, str) and trace_raw.strip():
                    trace_id = trace_raw.strip()

                err_field = error_data.get("error")
                status_field = error_data.get("status")
                detail_field = error_data.get("detail")

                if isinstance(err_field, dict):
                    # Connect v2: {"error": {"status": ..., "message": ..., "reason": ...}, "traceId": "..."}
                    category = "connect_v2"
                    msg = str(err_field.get("message") or error_data.get("message") or msg)
                    reason = str(err_field.get("reason") or "N/A")
                elif isinstance(err_field, str):
                    # Sandbox v0: {"error": "BAD_REQUEST", "message": "..."}
                    category = "sandbox_v0"
                    reason = err_field
                    msg = str(error_data.get("message") or err_field)
                elif isinstance(status_field, dict):
                    # Playbook Alerts / Cases: {"status": {"status_code": "Error", "status_message": "..."}}
                    category = "playbook_or_case"
                    reason = str(status_field.get("status_code") or "Error")
                    msg = str(
                        status_field.get("status_message")
                        or error_data.get("message")
                        or reason
                    )
                elif isinstance(detail_field, list) and detail_field:
                    # ASI validation error: {"detail": [{"loc": ..., "msg": ..., "type": ...}]}
                    category = "validation_detail"
                    first = detail_field[0]
                    if isinstance(first, dict):
                        msg = str(first.get("msg") or first)
                        reason = str(first.get("type") or "validation_error")
                    else:
                        msg = str(first)
                elif isinstance(detail_field, str) and detail_field.strip():
                    category = "validation_detail"
                    msg = detail_field.strip()
                    reason = str(
                        error_data.get("reason")
                        or error_data.get("status_code")
                        or "N/A"
                    )
                else:
                    # Lists, Detection Rules, Entity Match, Identity, Links, Playbook PUT
                    category = "core_flat"
                    msg = str(
                        error_data.get("message")
                        or error_data.get("status_message")
                        or msg
                    )
                    reason = str(
                        error_data.get("reason")
                        or error_data.get("status_code")
                        or "N/A"
                    )
            elif isinstance(error_data, (list, str, int, float, bool)):
                payload = error_data
                msg = str(error_data)
            else:
                text_body = getattr(response, "text", None)
                if isinstance(text_body, str) and text_body.strip():
                    msg = text_body.strip()[:500]
        except (ValueError, TypeError):
            text_body = getattr(response, "text", None)
            if isinstance(text_body, str) and text_body.strip():
                msg = text_body.strip()[:500]

        self.last_trace_id = trace_id
        logger.error(
            "API Error on %s (HTTP %s): Message: '%s', Reason: '%s', Trace ID: %s",
            endpoint,
            status_code,
            msg,
            reason,
            trace_id or "N/A",
        )

        self._persist_error_record(
            {
                "endpoint": endpoint,
                "method": method,
                "status_code": status_code,
                "trace_id": trace_id,
                "message": msg,
                "reason": reason,
                "category": category,
            }
        )

        return {
            "status_code": status_code,
            "message": msg,
            "reason": reason,
            "trace_id": trace_id,
            "payload": payload,
            "category": category,
        }

    def _json_or_raise(self, response: requests.Response, endpoint: str) -> Any:
        """Decode JSON from a successful response or raise RecordedFutureAPIError."""
        try:
            return response.json()
        except (ValueError, TypeError) as exc:
            raise RecordedFutureAPIError(
                status_code=getattr(response, "status_code", None),
                message=f"Invalid JSON payload returned from {endpoint}: {exc}",
                reason="invalid_json",
                endpoint=endpoint,
            ) from exc

    def _build_entity_ref(
        self,
        entity_type: str | None,
        entity_value: str,
        *,
        is_id: bool | None = None,
        resolve: bool = False,
    ) -> dict[str, str]:
        """Build a Watch List entity reference (``{"id": ...}`` or ``{"type", "name"}``)."""
        clean = entity_value.strip()
        if not clean:
            raise ValueError("Entity value cannot be empty.")

        if entity_type is None:
            return {"id": clean}

        raw_type = entity_type.strip()
        if not raw_type:
            return {"id": clean}

        norm_type = AUTO_RESOLVED_ENTITY_TYPES.get(raw_type.lower(), raw_type)
        if is_id is not None:
            treat_as_id = is_id
        elif resolve:
            lower = clean.lower()
            treat_as_id = (
                not lower.startswith(("http://", "https://"))
                and lower.startswith(RF_ID_PREFIXES)
            )
        else:
            treat_as_id = _is_rf_entity_id(norm_type, clean)
        if treat_as_id:
            return {"id": clean}

        if resolve and norm_type.lower() not in AUTO_RESOLVED_ENTITY_TYPES:
            matches = self.entity_match(clean, types=[norm_type], limit=1)
            if not matches:
                raise RecordedFutureAPIError(
                    404,
                    f"Could not resolve {norm_type} '{clean}' via Entity Match",
                    reason="entity_not_found",
                    endpoint="/entity-match/match",
                )
            return {"id": str(matches[0]["id"])}

        return {"type": norm_type, "name": clean}

    def _warn_if_near_capacity(self, size: int, list_id: str) -> None:
        """Emit a warning when a Watch List approaches or reaches the 1,000-entity cap."""
        if size >= WATCHLIST_DEFAULT_LIMIT:
            logger.warning(
                "Watchlist '%s' has %d entities (>= %d default limit); "
                "additional adds may be rejected by Recorded Future.",
                list_id,
                size,
                WATCHLIST_DEFAULT_LIMIT,
            )
        elif size >= WATCHLIST_WARNING_THRESHOLD:
            logger.warning(
                "Watchlist '%s' has %d entities (approaching %d-entity default limit).",
                list_id,
                size,
                WATCHLIST_DEFAULT_LIMIT,
            )

    # ------------------------------------------------------------------
    # F4: Complete Lists & Watchlists API
    # ------------------------------------------------------------------
    def get_watchlists(
        self,
        list_types: Iterable[str | ListType] | str | ListType | None = None,
        name: str | None = None,
        limit: int = 100,
        *,
        include_all_types: bool = True,
    ) -> list[dict[str, Any]]:
        """Search Watch Lists, querying all 21 types by default to bypass the 100-item cap."""
        clamped_limit = max(1, min(limit, 100))
        queries: list[dict[str, Any]] = []

        if list_types is not None:
            if isinstance(list_types, (str, ListType)):
                normalized_types = [str(list_types)]
            else:
                normalized_types = [str(t) for t in list_types]
            for list_type in normalized_types:
                q: dict[str, Any] = {"type": list_type, "limit": clamped_limit}
                if name:
                    q["name"] = name
                queries.append(q)
        elif name is not None or not include_all_types:
            q = {"limit": clamped_limit}
            if name:
                q["name"] = name
            queries.append(q)
        else:
            queries.append({"limit": clamped_limit})
            for list_type in LIST_TYPES:
                queries.append({"type": list_type, "limit": clamped_limit})

        lists_by_id: dict[str, dict[str, Any]] = {}
        unkeyed: list[dict[str, Any]] = []

        for query in queries:
            if self._stop_event is not None and self._stop_event.is_set():
                break
            response = self._request("POST", "/list/search", json_data=query)
            data = self._json_or_raise(response, "/list/search")
            if isinstance(data, list):
                for lst in data:
                    if not isinstance(lst, dict):
                        continue
                    list_id = lst.get("id")
                    if isinstance(list_id, str) and list_id:
                        lists_by_id[list_id] = lst
                    else:
                        unkeyed.append(lst)

        combined = list(lists_by_id.values()) + unkeyed
        combined.sort(key=lambda item: str(item.get("name", "")).lower())
        return combined

    def create_list(self, name: str, list_type: str | ListType) -> dict[str, Any]:
        """Create a new Recorded Future Watch List / Entity List."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("List name cannot be empty.")

        resolved_type = ListType(str(list_type).strip()).value
        payload: dict[str, Any] = {"name": clean_name, "type": resolved_type}
        response = self._request("POST", "/list/create", json_data=payload)
        data = self._json_or_raise(response, "/list/create")
        return data if isinstance(data, dict) else {"name": clean_name, "type": resolved_type}

    def get_list_info(self, list_id: str) -> dict[str, Any]:
        """Retrieve metadata and ownership details for a Watch List."""
        clean_id = _require_non_empty(list_id, "list_id")
        endpoint = f"/list/{quote(clean_id, safe=':')}/info"
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def get_list_status(self, list_id: str) -> dict[str, Any]:
        """Retrieve Watch List entity count and processing status."""
        clean_id = _require_non_empty(list_id, "list_id")
        endpoint = f"/list/{quote(clean_id, safe=':')}/status"
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        if isinstance(data, dict):
            size = data.get("size")
            if isinstance(size, int):
                self._warn_if_near_capacity(size, clean_id)
            return data
        return {}

    def get_watchlist_entities(self, list_id: str) -> list[dict[str, Any]]:
        """Retrieve all entities and contexts in a Watch List."""
        clean_id = _require_non_empty(list_id, "list_id")
        endpoint = f"/list/{quote(clean_id, safe=':')}/entities"
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        if isinstance(data, list):
            self._warn_if_near_capacity(len(data), clean_id)
            return data
        return []

    def add_entity(
        self,
        list_id: str,
        entity_type: str,
        entity_value: str | None = None,
        context: dict[str, Any] | None = None,
        *,
        name: str | None = None,
        is_id: bool | None = None,
        resolve: bool = False,
        check_limit: bool = False,
        current_size: int | None = None,
    ) -> dict[str, Any]:
        """Add a single entity (or update its context) in a Watch List."""
        clean_list_id = _require_non_empty(list_id, "list_id")
        target_value = entity_value if entity_value is not None else name
        if target_value is None or not target_value.strip():
            raise ValueError("Entity value cannot be empty.")

        if current_size is not None:
            self._warn_if_near_capacity(current_size, clean_list_id)
        elif check_limit:
            self.get_list_status(clean_list_id)

        entity_ref = self._build_entity_ref(
            entity_type,
            target_value,
            is_id=is_id,
            resolve=resolve,
        )
        payload: dict[str, Any] = {"entity": entity_ref}
        if context is not None:
            payload["context"] = context

        endpoint = f"/list/{quote(clean_list_id, safe=':')}/entity/add"
        response = self._request("POST", endpoint, json_data=payload)
        try:
            data = response.json()
        except (ValueError, TypeError):
            data = None
        return data if isinstance(data, dict) else {"result": "added"}

    def _resolve_list_entity_id(
        self,
        list_id: str,
        entity_type: str,
        entity_value: str,
        *,
        use_entity_match: bool = True,
    ) -> str | None:
        """Resolve a Watch List entity value/name to its Recorded Future entity ID."""
        clean_val = entity_value.strip()
        if not clean_val:
            return None

        clean_type = entity_type.strip()
        norm_type = AUTO_RESOLVED_ENTITY_TYPES.get(clean_type.lower(), clean_type)
        val_cf = clean_val.casefold()
        type_cf = norm_type.casefold()

        known_prefix = next(
            (prefix for key, prefix in ENTITY_ID_PREFIXES.items() if key.lower() == type_cf),
            "",
        )
        prefixed_candidate_cf = (
            f"{known_prefix}{clean_val}".casefold() if known_prefix else None
        )

        entries = self.get_watchlist_entities(list_id)

        ci_id_matches: list[str] = []
        typed_name_matches: list[str] = []
        any_name_matches: list[str] = []
        list_ids: set[str] = set()

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ent = entry.get("entity")
            if not isinstance(ent, dict):
                continue
            eid = str(ent.get("id") or "").strip()
            if not eid:
                continue
            list_ids.add(eid)
            if eid == clean_val:
                return eid

            eid_cf = eid.casefold()
            if eid_cf == val_cf or (
                prefixed_candidate_cf is not None and eid_cf == prefixed_candidate_cf
            ):
                if eid not in ci_id_matches:
                    ci_id_matches.append(eid)

            ename = str(ent.get("name") or "").strip()
            if ename and ename.casefold() == val_cf:
                etype = str(ent.get("type") or "").strip()
                if etype and etype.casefold() == type_cf:
                    if eid not in typed_name_matches:
                        typed_name_matches.append(eid)
                if eid not in any_name_matches:
                    any_name_matches.append(eid)

        if len(ci_id_matches) == 1:
            return ci_id_matches[0]
        if len(ci_id_matches) > 1:
            raise ValueError(
                f"Multiple entities matching ID '{clean_val}' found in watchlist '{list_id}': "
                f"{', '.join(ci_id_matches)}. Pass the exact case-sensitive Entity ID."
            )

        if len(typed_name_matches) == 1:
            return typed_name_matches[0]
        if len(typed_name_matches) > 1:
            raise ValueError(
                f"Multiple entities named '{clean_val}' ({norm_type}) found in watchlist '{list_id}': "
                f"{', '.join(typed_name_matches)}. Pass the exact Entity ID."
            )
        if len(any_name_matches) == 1:
            return any_name_matches[0]
        if len(any_name_matches) > 1:
            raise ValueError(
                f"Multiple entities named '{clean_val}' found in watchlist '{list_id}': "
                f"{', '.join(any_name_matches)}. Pass the exact Entity ID."
            )

        if use_entity_match:
            matches = self.entity_match(clean_val, types=[norm_type], limit=5)
            matched_ids = list(
                dict.fromkeys(
                    str(m.get("id") or "").strip()
                    for m in matches
                    if isinstance(m, dict) and str(m.get("id") or "").strip()
                )
            )
            in_list = [cid for cid in matched_ids if cid in list_ids]
            if len(in_list) == 1:
                return in_list[0]
            if matched_ids:
                return matched_ids[0]

        return None

    def remove_entity(
        self,
        list_id: str,
        entity_id_or_value: str | None = None,
        entity_type: str | None = None,
        *,
        entity_id: str | None = None,
        is_id: bool | None = None,
        resolve: bool = True,
    ) -> dict[str, Any]:
        """Remove a single entity from a Watch List by RF ID or by type + name."""
        clean_list_id = _require_non_empty(list_id, "list_id")
        target_value = entity_id_or_value if entity_id_or_value is not None else entity_id
        if target_value is None or not target_value.strip():
            raise ValueError("Entity ID or value cannot be empty.")

        clean = target_value.strip()
        endpoint = f"/list/{quote(clean_list_id, safe=':')}/entity/remove"

        if entity_type is None or not entity_type.strip() or is_id is True:
            entity_ref: dict[str, str] = {"id": clean}
        else:
            raw_type = entity_type.strip()
            norm_type = AUTO_RESOLVED_ENTITY_TYPES.get(raw_type.lower(), raw_type)
            lower = clean.lower()
            if not lower.startswith(("http://", "https://")) and lower.startswith(RF_ID_PREFIXES):
                entity_ref = {"id": clean}
            elif norm_type.lower() in AUTO_RESOLVED_ENTITY_TYPES:
                entity_ref = {"type": norm_type, "name": clean}
            elif resolve:
                resolved_id = self._resolve_list_entity_id(
                    clean_list_id,
                    norm_type,
                    clean,
                    use_entity_match=True,
                )
                if resolved_id:
                    entity_ref = {"id": resolved_id}
                else:
                    known_prefix = next(
                        (
                            prefix
                            for key, prefix in ENTITY_ID_PREFIXES.items()
                            if key.lower() == norm_type.lower()
                        ),
                        "",
                    )
                    if known_prefix:
                        entity_ref = {"id": f"{known_prefix}{clean}"}
                    elif is_id is None and _is_rf_entity_id(norm_type, clean):
                        entity_ref = {"id": clean}
                    else:
                        raise RecordedFutureAPIError(
                            404,
                            f"Could not resolve {norm_type} '{clean}' in watchlist "
                            f"'{clean_list_id}' or via Entity Match",
                            reason="entity_not_found",
                            endpoint=endpoint,
                        )
            else:
                entity_ref = self._build_entity_ref(
                    entity_type,
                    clean,
                    is_id=is_id,
                    resolve=False,
                )

        payload: dict[str, Any] = {"entity": entity_ref}
        response = self._request("POST", endpoint, json_data=payload)
        try:
            data = response.json()
        except (ValueError, TypeError):
            data = None
        return data if isinstance(data, dict) else {"result": "removed"}

    def get_text_entries(self, list_id: str) -> list[str]:
        """Retrieve entries from a ``text`` type list."""
        clean_id = _require_non_empty(list_id, "list_id")
        endpoint = f"/list/{quote(clean_id, safe=':')}/textEntries"
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        if isinstance(data, list):
            return [str(item) for item in data]
        return []

    def get_entities_with_tags(self, list_id: str) -> list[dict[str, Any]]:
        """Retrieve entities along with their applied tags (``company`` lists)."""
        clean_id = _require_non_empty(list_id, "list_id")
        endpoint = f"/list/{quote(clean_id, safe=':')}/entitiesWithTags"
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        if isinstance(data, list):
            self._warn_if_near_capacity(len(data), clean_id)
            return data
        return []

    def replace_entity_tags(
        self,
        list_id: str,
        entity: dict[str, str] | str,
        tags: list[str],
        *,
        entity_type: str | None = None,
    ) -> dict[str, Any]:
        """Replace all predefined tags on a ``company`` Watch List entity (max 9 tags)."""
        clean_list_id = _require_non_empty(list_id, "list_id")
        if len(tags) > MAX_ENTITY_TAGS:
            raise ValueError(
                f"Recorded Future supports at most {MAX_ENTITY_TAGS} tags per entity "
                f"(got {len(tags)})."
            )

        if isinstance(entity, dict):
            entity_ref = dict(entity)
        else:
            entity_ref = self._build_entity_ref(entity_type, entity, resolve=False)

        payload: dict[str, Any] = {"entity": entity_ref, "tags": list(tags)}
        endpoint = f"/list/{quote(clean_list_id, safe=':')}/entity/tags"
        response = self._request("POST", endpoint, json_data=payload)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------
    # F5: Detection Rules API
    # ------------------------------------------------------------------
    def search_detection_rules(
        self,
        days: int | None = None,
        rule_types: list[str] | None = None,
        entities: list[str] | None = None,
        title: str | None = None,
        limit: int = 50,
        *,
        doc_id: str | None = None,
        tagged_entities: bool = False,
        paginate: bool = True,
    ) -> list[dict[str, Any]]:
        """Search Detection Rules (Sigma, YARA, Snort) using ``result`` and ``next_offset``."""
        filter_obj: dict[str, Any] = {
            "types": list(rule_types) if rule_types is not None else ["sigma"],
        }
        if days is not None:
            time_limit = (datetime.now(UTC) - timedelta(days=days)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            filter_obj["updated"] = {"after": time_limit}
        if entities:
            filter_obj["entities"] = list(entities)
        if title:
            filter_obj["title"] = title
        if doc_id:
            filter_obj["doc_id"] = doc_id

        payload: dict[str, Any] = {
            "filter": filter_obj,
            "limit": max(1, limit),
        }
        if tagged_entities:
            payload["tagged_entities"] = True

        rules: list[dict[str, Any]] = []
        seen_offsets: set[str] = set()

        while True:
            response = self._request("POST", "/detection-rule/search", json_data=payload)
            res_json = self._json_or_raise(response, "/detection-rule/search")
            if not isinstance(res_json, dict):
                break
            batch = res_json.get("result", [])
            if isinstance(batch, list):
                rules.extend(batch)

            next_offset = res_json.get("next_offset")
            if (
                not paginate
                or not isinstance(next_offset, str)
                or not next_offset
                or next_offset in seen_offsets
            ):
                break
            seen_offsets.add(next_offset)
            payload["offset"] = next_offset

        return rules

    def get_detection_rule_entities(self) -> list[dict[str, Any]]:
        """List entities associated with Detection Rules for filtering."""
        endpoint = "/detection-rule-relation/entity/list"
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, list) else []

    def get_detection_rule_entity_types(self) -> list[dict[str, Any]]:
        """List entity types associated with Detection Rules."""
        endpoint = "/detection-rule-relation/entity/types"
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, list) else []

    # ------------------------------------------------------------------
    # F6: Expanded SOC APIs
    # ------------------------------------------------------------------
    def entity_match(
        self,
        name: str,
        types: list[str] | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Resolve a human-readable name to Recorded Future entity IDs."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Entity match query name cannot be empty.")

        payload: dict[str, Any] = {
            "name": clean_name,
            "limit": max(1, min(limit, 100)),
        }
        if types:
            payload["type"] = list(types)

        response = self._request("POST", "/entity-match/match", json_data=payload)
        data = self._json_or_raise(response, "/entity-match/match")
        return data if isinstance(data, list) else []

    def entity_lookup(self, entity_id: str) -> dict[str, Any]:
        """Fetch metadata and aliases for a known Recorded Future entity ID."""
        clean_id = _require_non_empty(entity_id, "entity_id")
        if clean_id.lower().startswith("idn:"):
            clean_id = clean_id.rstrip("/")
        encoded_id = quote(clean_id, safe=":")
        endpoint = _append_proxysg_safe_slash(f"/entity-match/entity/{encoded_id}")
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def _validate_soar_iocs(self, iocs: dict[str, list[str]]) -> dict[str, list[str]]:
        if not iocs:
            raise ValueError("IOC dictionary cannot be empty.")
        cleaned: dict[str, list[str]] = {}
        total = 0
        for key, values in iocs.items():
            if not values:
                continue
            cleaned[key] = list(values)
            total += len(values)
        if total == 0:
            raise ValueError("At least one IOC must be provided.")
        if total > MAX_SOAR_IOCS:
            raise ValueError(
                f"SOAR API supports at most {MAX_SOAR_IOCS} IOCs per request (got {total})."
            )
        return cleaned

    def soar_enrich(
        self,
        iocs: dict[str, list[str]],
        metadata: bool = False,
    ) -> dict[str, Any]:
        """Batch-enrich up to 1,000 IOCs via SOAR v3."""
        body = self._validate_soar_iocs(iocs)
        params = {"metadata": "true" if metadata else "false"}
        response = self._request(
            "POST", "/soar/v3/enrichment", json_data=body, params=params
        )
        data = self._json_or_raise(response, "/soar/v3/enrichment")
        return data if isinstance(data, dict) else {}

    def soar_get_contexts(self) -> dict[str, Any]:
        """Retrieve available SOAR v3 triage contexts and default thresholds."""
        response = self._request("GET", "/soar/v3/triage/contexts")
        data = self._json_or_raise(response, "/soar/v3/triage/contexts")
        return data if isinstance(data, dict) else {}

    def soar_triage(
        self,
        context_name: str,
        iocs: dict[str, list[str]],
        *,
        metadata: bool = False,
        threshold: int | None = None,
        threshold_type: str | None = None,
        fmt: str | None = None,
    ) -> dict[str, Any]:
        """Batch-triage IOCs against a SOAR v3 context (e.g. phishing, malware, c2)."""
        clean_ctx = context_name.strip()
        if not clean_ctx:
            raise ValueError("SOAR triage context_name cannot be empty.")
        body = self._validate_soar_iocs(iocs)
        params: dict[str, Any] = {"metadata": "true" if metadata else "false"}
        if threshold is not None:
            params["threshold"] = threshold
        if threshold_type is not None:
            params["threshold_type"] = threshold_type
        if fmt is not None:
            params["format"] = fmt

        encoded_ctx = quote(clean_ctx, safe="")
        endpoint = f"/soar/v3/triage/contexts/{encoded_ctx}"
        response = self._request("POST", endpoint, json_data=body, params=params)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def _normalize_v2_type(self, entity_type: str) -> str:
        norm = _V2_TYPE_ALIASES.get(entity_type.strip().lower())
        if not norm:
            raise ValueError(f"Unsupported Connect v2 entity type: {entity_type!r}")
        return norm

    def _encode_v2_entity_id(self, norm_type: str, entity_id: str) -> str:
        clean_id = _require_non_empty(entity_id, "entity_id")
        if norm_type == "domain":
            clean_id = clean_id.rstrip("/")
            if not clean_id:
                raise ValueError("entity_id cannot be empty.")
        if norm_type == "url":
            raw_url = clean_id[4:] if clean_id.lower().startswith("url:") else clean_id
            encoded_url = raw_url if "/" not in raw_url else quote(raw_url, safe="")
            return f"url:{encoded_url}"
        return quote(clean_id, safe=":")

    def v2_lookup(
        self,
        entity_type: str,
        entity_id: str,
        fields: str | list[str] | None = None,
        *,
        metadata: bool = False,
        tagged_text: bool = False,
    ) -> dict[str, Any]:
        """Look up a single entity via Connect API v2 (percent-encoding URL paths)."""
        norm_type = self._normalize_v2_type(entity_type)
        encoded_id = self._encode_v2_entity_id(norm_type, entity_id)

        params: dict[str, Any] = {}
        if fields:
            params["fields"] = ",".join(fields) if isinstance(fields, list) else fields
        if metadata:
            params["metadata"] = "true"
        if tagged_text:
            params["taggedText"] = "true"

        endpoint = f"/v2/{norm_type}/{encoded_id}"
        if norm_type == "domain":
            endpoint = _append_proxysg_safe_slash(endpoint, always=True)
        elif norm_type == "url":
            endpoint = _append_proxysg_safe_slash(endpoint)
        response = self._request("GET", endpoint, params=params or None)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def v2_fields(self, entity_type: str) -> dict[str, Any]:
        """Retrieve valid ``fields`` parameter names for a Connect v2 entity type."""
        norm_type = self._normalize_v2_type(entity_type)
        if norm_type not in _V2_FIELDS_TYPES:
            raise ValueError(f"Fields endpoint is not supported for type: {norm_type!r}")
        endpoint = f"/v2/{norm_type}/fields"
        return self._get_json_dict(endpoint)

    def v2_lookup_extension(
        self,
        entity_type: str,
        entity_id: str,
        extension: str,
        *,
        metadata: bool = False,
    ) -> dict[str, Any]:
        """Look up third-party Intelligence Card extension data for a Connect v2 entity."""
        norm_type = self._normalize_v2_type(entity_type)
        if norm_type not in V2_EXTENSION_CATALOG:
            raise ValueError(
                f"Extensions are not supported for Connect v2 type: {norm_type!r}"
            )
        clean_ext = _require_non_empty(extension, "extension")
        encoded_id = self._encode_v2_entity_id(norm_type, entity_id)
        params: dict[str, Any] | None = {"metadata": "true"} if metadata else None
        endpoint = f"/v2/{norm_type}/{encoded_id}/extension/{quote(clean_ext, safe='')}"
        return self._get_json_dict(endpoint, params=params)

    def v2_company_by_domain(
        self,
        domain: str,
        fields: str | list[str] | None = None,
        *,
        metadata: bool = False,
    ) -> dict[str, Any]:
        """Resolve a domain name to its owning company via Connect v2."""
        clean_domain = domain.strip().rstrip("/")
        if not clean_domain:
            raise ValueError("Domain cannot be empty.")
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = ",".join(fields) if isinstance(fields, list) else fields
        if metadata:
            params["metadata"] = "true"

        endpoint = _append_proxysg_safe_slash(
            f"/v2/company/by_domain/{quote(clean_domain, safe='')}",
            always=True,
        )
        response = self._request("GET", endpoint, params=params or None)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def v2_risklist(
        self,
        entity_type: str,
        fmt: str = "csv/splunk",
        list_name: str | None = None,
        gzip: bool = False,
    ) -> bytes | str | dict[str, Any]:
        """Download a Connect v2 Risk List feed in CSV, STIX XML, or STIX 2.1 JSON."""
        norm_type = self._normalize_v2_type(entity_type)
        if norm_type not in _V2_RISKLIST_TYPES:
            raise ValueError(f"Risk lists are not supported for type: {norm_type!r}")

        params: dict[str, Any] = {
            "format": fmt,
            "gzip": "true" if gzip else "false",
        }
        if list_name:
            params["list"] = list_name

        endpoint = f"/v2/{norm_type}/risklist"
        response = self._request("GET", endpoint, params=params)
        if gzip:
            return response.content
        if "json" in fmt.lower():
            data = self._json_or_raise(response, endpoint)
            return data if isinstance(data, dict) else {"data": data}
        return response.text

    def v2_stat_risklist(
        self,
        entity_type: str,
        fmt: str = "csv/splunk",
        list_name: str | None = None,
        gzip: bool = False,
    ) -> dict[str, str]:
        """Perform a HEAD request on a Risk List to check ETag / Last-Modified headers."""
        norm_type = self._normalize_v2_type(entity_type)
        if norm_type not in _V2_RISKLIST_TYPES:
            raise ValueError(f"Risk lists are not supported for type: {norm_type!r}")

        params: dict[str, Any] = {
            "format": fmt,
            "gzip": "true" if gzip else "false",
        }
        if list_name:
            params["list"] = list_name

        endpoint = f"/v2/{norm_type}/risklist"
        response = self._request("HEAD", endpoint, params=params)
        headers = getattr(response, "headers", {})
        if isinstance(headers, Mapping):
            return {str(k): str(v) for k, v in headers.items()}
        return {}

    def v2_riskrules(self, entity_type: str) -> dict[str, Any]:
        """Retrieve available Connect v2 risk rules for an entity type."""
        norm_type = self._normalize_v2_type(entity_type)
        if norm_type not in _V2_RISKRULES_TYPES:
            raise ValueError(f"Risk rules are not supported for type: {norm_type!r}")
        endpoint = f"/v2/{norm_type}/riskrules"
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def v2_search(self, entity_type: str, **params: Any) -> dict[str, Any]:
        """Search entities via Connect API v2."""
        norm_type = self._normalize_v2_type(entity_type)
        query_params = dict(params)
        fields = query_params.get("fields")
        if isinstance(fields, list):
            if fields:
                query_params["fields"] = ",".join(str(f) for f in fields)
            else:
                query_params.pop("fields", None)
        endpoint = f"/v2/{norm_type}/search"
        response = self._request("GET", endpoint, params=query_params or None)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def _check_playbook_status(self, data: Any, endpoint: str) -> None:
        """Raise RecordedFutureAPIError if a Playbook Alert / Case status object signals Error."""
        if not isinstance(data, dict):
            return
        status_obj = data.get("status")
        if isinstance(status_obj, dict) and status_obj.get("status_code") == "Error":
            raise RecordedFutureAPIError(
                status_code=200,
                message=str(status_obj.get("status_message") or "Playbook Alert error"),
                reason="Error",
                payload=data,
                endpoint=endpoint,
            )
        if data.get("status_code") == "Error":
            raise RecordedFutureAPIError(
                status_code=200,
                message=str(data.get("status_message") or "Playbook Alert error"),
                reason="Error",
                payload=data,
                endpoint=endpoint,
            )

    def search_playbook_alerts(
        self,
        categories: list[str] | None = None,
        statuses: list[str] | None = None,
        priorities: list[str] | None = None,
        entities: list[str] | None = None,
        assignees: list[str] | None = None,
        created_range: dict[str, str] | None = None,
        updated_range: dict[str, str] | None = None,
        order_by: str | None = None,
        direction: str | None = None,
        limit: int = 100,
        offset: str | None = None,
        *,
        paginate: bool = False,
    ) -> dict[str, Any]:
        """Search Playbook Alerts (domain_abuse, malicious_sites, dark_web, etc.)."""
        body: dict[str, Any] = {"limit": max(1, limit)}
        if categories is not None:
            body["category"] = list(categories)
        if statuses is not None:
            body["statuses"] = list(statuses)
        if priorities is not None:
            body["priority"] = list(priorities)
        if entities is not None:
            body["entity"] = list(entities)
        if assignees is not None:
            body["assignee"] = list(assignees)
        if created_range is not None:
            body["created_range"] = dict(created_range)
        if updated_range is not None:
            body["updated_range"] = dict(updated_range)
        if order_by is not None:
            body["order_by"] = order_by
        if direction is not None:
            body["direction"] = direction
        if offset is not None:
            body["offset"] = offset

        endpoint = "/playbook-alert/search"
        all_data: list[Any] = []
        seen_offsets: set[str] = set()
        last_payload: dict[str, Any] = {}

        while True:
            response = self._request("POST", endpoint, json_data=body)
            data = self._json_or_raise(response, endpoint)
            self._check_playbook_status(data, endpoint)
            if not isinstance(data, dict):
                return {"data": []}
            last_payload = data
            batch = data.get("data", [])
            if isinstance(batch, list):
                all_data.extend(batch)

            next_offset = data.get("next_offset")
            if (
                not paginate
                or not isinstance(next_offset, str)
                or not next_offset
                or next_offset in seen_offsets
            ):
                break
            seen_offsets.add(next_offset)
            body["offset"] = next_offset

        if paginate:
            result = dict(last_payload)
            result["data"] = all_data
            return result
        return last_payload

    def get_playbook_alert_preview(self, alert_id: str) -> dict[str, Any]:
        """Fetch common preview properties for a Playbook Alert."""
        clean_id = _require_non_empty(alert_id, "alert_id")
        endpoint = f"/playbook-alert/common/{quote(clean_id, safe='')}"
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        self._check_playbook_status(data, endpoint)
        return data if isinstance(data, dict) else {}

    def get_playbook_alert(
        self,
        category: str,
        alert_id: str,
        panels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Fetch category-specific Playbook Alert panels (e.g. domain_abuse, malicious_sites)."""
        mapped_cat = PLAYBOOK_CATEGORY_PATH_MAP.get(category.strip().lower())
        if not mapped_cat:
            raise ValueError(f"Unsupported Playbook Alert category: {category!r}")
        clean_id = _require_non_empty(alert_id, "alert_id")

        endpoint = f"/playbook-alert/{mapped_cat}/{quote(clean_id, safe='')}"
        body: dict[str, Any] = {"panels": list(panels)} if panels is not None else {}
        response = self._request("POST", endpoint, json_data=body)
        data = self._json_or_raise(response, endpoint)
        self._check_playbook_status(data, endpoint)
        return data if isinstance(data, dict) else {}

    def update_playbook_alert(
        self,
        alert_id: str,
        *,
        priority: str | None = None,
        status: str | None = None,
        assignee: str | None = None,
        log_entry: str | None = None,
        reopen: str | None = None,
        added_actions_taken: list[str] | None = None,
        removed_actions_taken: list[str] | None = None,
    ) -> dict[str, Any]:
        """Update status, priority, assignee, or audit log on a Playbook Alert."""
        clean_id = _require_non_empty(alert_id, "alert_id")
        body: dict[str, Any] = {}
        if priority is not None:
            body["priority"] = priority
        if status is not None:
            body["status"] = status
        if assignee is not None:
            body["assignee"] = assignee
        if log_entry is not None:
            body["log_entry"] = log_entry
        if reopen is not None:
            body["reopen"] = reopen
        if added_actions_taken is not None:
            body["added_actions_taken"] = list(added_actions_taken)
        if removed_actions_taken is not None:
            body["removed_actions_taken"] = list(removed_actions_taken)

        endpoint = f"/playbook-alert/common/{quote(clean_id, safe='')}"
        response = self._request("PUT", endpoint, json_data=body)
        data = self._json_or_raise(response, endpoint)
        self._check_playbook_status(data, endpoint)
        return data if isinstance(data, dict) else {}

    def get_playbook_alert_image(
        self,
        category: str,
        alert_id: str,
        image_id: str,
    ) -> bytes:
        """Download binary PNG screenshot bytes attached to a Playbook Alert."""
        mapped_cat = PLAYBOOK_CATEGORY_PATH_MAP.get(category.strip().lower())
        if not mapped_cat:
            raise ValueError(f"Unsupported Playbook Alert category: {category!r}")
        clean_alert_id = _require_non_empty(alert_id, "alert_id")
        clean_image_id = _require_non_empty(image_id, "image_id")
        if mapped_cat == "dark_web_brand":
            return self.get_alert_v3_image(clean_image_id)

        endpoint = (
            f"/playbook-alert/{mapped_cat}/{quote(clean_alert_id, safe='')}"
            f"/image/{quote(clean_image_id, safe='')}"
        )
        response = self._request(
            "GET",
            endpoint,
            headers_extra={"Accept": "image/png, */*"},
        )
        return response.content

    def search_alerts_v3(
        self,
        triggered: str | None = None,
        assignee: str | None = None,
        status_in_portal: str | None = None,
        alert_rule: str | None = None,
        freetext: str | None = None,
        fields: str | list[str] | None = None,
        limit: int = 100,
        offset: int = 0,
        orderby: str | None = None,
        direction: str | None = None,
        tagged_text: bool = False,
    ) -> dict[str, Any]:
        """Search classic Alerts via ``GET /alert/v3``."""
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000.")
        if offset < 0:
            raise ValueError("offset cannot be negative.")
        if limit + offset > 1000:
            raise ValueError("limit + offset cannot exceed 1000 for Alerts v3.")

        params: dict[str, Any] = {"limit": limit}
        if offset > 0:
            params["from"] = offset
        if triggered is not None:
            params["triggered"] = triggered
        if assignee is not None:
            params["assignee"] = assignee
        if status_in_portal is not None:
            params["statusInPortal"] = status_in_portal
        if alert_rule is not None:
            params["alertRule"] = alert_rule
        if freetext is not None:
            params["freetext"] = freetext
        if fields:
            params["fields"] = ",".join(fields) if isinstance(fields, list) else fields
        if orderby is not None:
            params["orderby"] = orderby
        if direction is not None:
            params["direction"] = direction
        if tagged_text:
            params["taggedText"] = "true"

        response = self._request("GET", "/alert/v3", params=params)
        data = self._json_or_raise(response, "/alert/v3")
        return data if isinstance(data, dict) else {}

    def get_alert_v3(
        self,
        alert_id: str,
        fields: str | list[str] | None = None,
        tagged_text: bool = False,
    ) -> dict[str, Any]:
        """Fetch full detail for an Alert v3 by ID."""
        clean_id = _require_non_empty(alert_id, "alert_id")
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = ",".join(fields) if isinstance(fields, list) else fields
        if tagged_text:
            params["taggedText"] = "true"
        endpoint = f"/alert/v3/{quote(clean_id, safe='')}"
        response = self._request("GET", endpoint, params=params or None)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def get_alert_v3_hits(
        self,
        ids: str | list[str],
        tagged_text: bool = False,
    ) -> dict[str, Any]:
        """Fetch triggering alert hits via ``GET /alert/v3/hits``."""
        params: dict[str, Any] = {
            "ids": ",".join(ids) if isinstance(ids, list) else ids,
        }
        if tagged_text:
            params["taggedText"] = "true"
        response = self._request("GET", "/alert/v3/hits", params=params)
        data = self._json_or_raise(response, "/alert/v3/hits")
        return data if isinstance(data, dict) else {}

    def update_alerts_v2(self, updates: list[dict[str, Any]]) -> dict[str, Any]:
        """Bulk-update alert statuses, assignees, or notes via ``POST /alert/v2/update``."""
        response = self._request("POST", "/alert/v2/update", json_data=updates)
        data = self._json_or_raise(response, "/alert/v2/update")
        return data if isinstance(data, dict) else {}

    def search_cases(
        self,
        statuses: list[str] | None = None,
        priorities: list[str] | None = None,
        assignees: list[str] | None = None,
        owners: list[str] | None = None,
        creators: list[str] | None = None,
        created: dict[str, str] | None = None,
        modified: dict[str, str] | None = None,
        order_by: str | None = None,
        direction: str | None = None,
        limit: int = 100,
        offset: str | None = None,
        *,
        paginate: bool = False,
    ) -> dict[str, Any]:
        """Search investigation Cases via ``POST /case/search``."""
        body: dict[str, Any] = {"limit": max(1, min(limit, 100))}
        if statuses is not None:
            body["statuses"] = list(statuses)
        if priorities is not None:
            body["priorities"] = list(priorities)
        if assignees is not None:
            body["assignees"] = list(assignees)
        if owners is not None:
            body["owners"] = list(owners)
        if creators is not None:
            body["creators"] = list(creators)
        if created is not None:
            body["created"] = dict(created)
        if modified is not None:
            body["modified"] = dict(modified)
        if order_by is not None:
            body["order_by"] = order_by
        if direction is not None:
            body["direction"] = direction
        if offset is not None:
            body["offset"] = offset

        endpoint = "/case/search"
        all_data: list[Any] = []
        seen_offsets: set[str] = set()
        last_payload: dict[str, Any] = {}

        while True:
            response = self._request("POST", endpoint, json_data=body)
            data = self._json_or_raise(response, endpoint)
            self._check_playbook_status(data, endpoint)
            if not isinstance(data, dict):
                return {"data": []}
            last_payload = data
            batch = data.get("data", [])
            if isinstance(batch, list):
                all_data.extend(batch)

            next_offset = data.get("next_offset")
            if (
                not paginate
                or not isinstance(next_offset, str)
                or not next_offset
                or next_offset in seen_offsets
            ):
                break
            seen_offsets.add(next_offset)
            body["offset"] = next_offset

        if paginate:
            result = dict(last_payload)
            result["data"] = all_data
            return result
        return last_payload

    def lookup_cases(
        self,
        ids: list[str],
        panels: list[str] | None = None,
        log_limit: int | None = None,
    ) -> dict[str, Any]:
        """Bulk-lookup case details via ``POST /case/lookup``."""
        if not ids:
            raise ValueError("Case IDs list cannot be empty.")
        body: dict[str, Any] = {
            "ids": list(ids),
            "panels": list(panels) if panels is not None else ["summary", "details", "log"],
        }
        if log_limit is not None:
            body["logLimit"] = log_limit
        response = self._request("POST", "/case/lookup", json_data=body)
        data = self._json_or_raise(response, "/case/lookup")
        self._check_playbook_status(data, "/case/lookup")
        return data if isinstance(data, dict) else {}

    def create_case(
        self,
        title: str | None = None,
        description: str | None = None,
        *,
        status: str | None = None,
        priority: str | None = None,
        assignee: str | None = None,
        organization: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new investigation Case via ``POST /case/create``."""
        body: dict[str, Any] = {}
        if title is not None:
            body["title"] = title
        if description is not None:
            body["description"] = description
        if status is not None:
            body["status"] = status
        if priority is not None:
            body["priority"] = priority
        if assignee is not None:
            body["assignee"] = assignee
        if organization is not None:
            body["organization"] = organization
        if context is not None:
            body["context"] = dict(context)
        response = self._request("POST", "/case/create", json_data=body)
        data = self._json_or_raise(response, "/case/create")
        self._check_playbook_status(data, "/case/create")
        return data if isinstance(data, dict) else {}

    def update_case(
        self,
        case_id: str,
        *,
        status: str | None = None,
        priority: str | None = None,
        title: str | None = None,
        description: str | None = None,
        assignee: str | None = None,
    ) -> dict[str, Any]:
        """Update an investigation Case via ``PUT /case/update``."""
        body: dict[str, Any] = {"id": case_id}
        if status is not None:
            body["status"] = status
        if priority is not None:
            body["priority"] = priority
        if title is not None:
            body["title"] = title
        if description is not None:
            body["description"] = description
        if assignee is not None:
            body["assignee"] = assignee
        response = self._request("PUT", "/case/update", json_data=body)
        data = self._json_or_raise(response, "/case/update")
        self._check_playbook_status(data, "/case/update")
        return data if isinstance(data, dict) else {}

    def sandbox_search(
        self,
        query: str,
        limit: int = 50,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """Search Recorded Future Sandbox analyses using ``Bearer`` auth."""
        clean_query = query.strip()
        if not clean_query:
            raise ValueError("Sandbox search query cannot be empty.")

        params: dict[str, Any] = {
            "query": clean_query,
            "limit": max(1, min(limit, 200)),
        }
        if offset is not None:
            params["offset"] = offset

        response = self._request("GET", "/search", params=params, is_sandbox=True)
        data = self._json_or_raise(response, "/search")
        return data if isinstance(data, dict) else {}

    def sandbox_get_sample(self, sample_id: str) -> dict[str, Any]:
        """Retrieve status and task details for a Sandbox sample."""
        clean_id = _require_non_empty(sample_id, "sample_id")
        endpoint = f"/samples/{quote(clean_id, safe='')}"
        response = self._request("GET", endpoint, is_sandbox=True)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def sandbox_get_overview(self, sample_id: str) -> dict[str, Any]:
        """Retrieve the full overview.json report for a Sandbox sample."""
        clean_id = _require_non_empty(sample_id, "sample_id")
        endpoint = f"/samples/{quote(clean_id, safe='')}/overview.json"
        response = self._request("GET", endpoint, is_sandbox=True)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------
    # Shared Research Helpers
    # ------------------------------------------------------------------
    def _get_json_dict(
        self,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        is_sandbox: bool = False,
        auth_mode: str | None = None,
    ) -> dict[str, Any]:
        response = self._request(
            "GET",
            endpoint,
            params=params,
            is_sandbox=is_sandbox,
            auth_mode=auth_mode,
        )
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def _post_json_dict(
        self,
        endpoint: str,
        body: dict[str, Any] | None = None,
        *,
        params: dict[str, Any] | None = None,
        auth_mode: str | None = None,
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            endpoint,
            json_data=body,
            params=params,
            auth_mode=auth_mode,
        )
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _resolve_malware_intel_dates(
        start_date: str | None, end_date: str | None
    ) -> tuple[str, str | None]:
        resolved_start = (
            start_date.strip()
            if isinstance(start_date, str) and start_date.strip()
            else (datetime.now(UTC) - timedelta(days=90)).strftime("%Y-%m-%d")
        )
        if resolved_start < _MALWARE_INTEL_MIN_START_DATE:
            resolved_start = _MALWARE_INTEL_MIN_START_DATE
        resolved_end = (
            end_date.strip() if isinstance(end_date, str) and end_date.strip() else None
        )
        return resolved_start, resolved_end

    @staticmethod
    def _normalize_fusion_path(path: str) -> str:
        clean = _require_non_empty(path, "path")
        if not clean.startswith("/"):
            clean = f"/{clean}"
        return quote(clean, safe="")

    # ------------------------------------------------------------------
    # F7: Links Graph API
    # ------------------------------------------------------------------
    def links_search(
        self,
        entities: list[str],
        *,
        sections: list[str] | None = None,
        entity_types: list[str] | None = None,
        sources: list[str] | None = None,
        timeframe: str | None = None,
        events: list[str] | None = None,
        connected_entities: list[str] | None = None,
        search_scope: str = "medium",
        per_entity_type: int | None = None,
    ) -> dict[str, Any]:
        """Search validated technical and Insikt relationships via ``POST /links/search``."""
        clean_entities = [str(e).strip() for e in entities if str(e).strip()]
        if not clean_entities:
            raise ValueError("Links search requires at least one entity ID.")

        body: dict[str, Any] = {"entities": clean_entities}
        filters: dict[str, Any] = {}
        if sections:
            filters["sections"] = list(sections)
        if entity_types:
            filters["entity_types"] = list(entity_types)
        if sources:
            filters["sources"] = list(sources)

        technical: dict[str, Any] = {}
        if timeframe:
            technical["timeframe"] = timeframe
        if events:
            technical["events"] = list(events)
        if connected_entities:
            technical["connected_entities"] = list(connected_entities)
        if technical:
            filters["technical"] = technical
        if filters:
            body["filters"] = filters

        limits: dict[str, Any] = {}
        if search_scope:
            limits["search_scope"] = search_scope
        if per_entity_type is not None:
            limits["per_entity_type"] = max(1, per_entity_type)
        if limits:
            body["limits"] = limits

        return self._post_json_dict("/links/search", body)

    def links_metadata_entities(self) -> dict[str, Any]:
        """List valid target entity types for Links Graph searches."""
        return self._get_json_dict("/links/metadata/entities")

    def links_metadata_events(self) -> dict[str, Any]:
        """List valid technical analysis event types for Links Graph searches."""
        return self._get_json_dict("/links/metadata/events")

    def links_metadata_sections(self) -> dict[str, Any]:
        """List valid link section categories for Links Graph searches."""
        return self._get_json_dict("/links/metadata/sections")

    # ------------------------------------------------------------------
    # F8: Analyst Notes API
    # ------------------------------------------------------------------
    def search_analyst_notes(
        self,
        *,
        entity: str | None = None,
        topic: str | None = None,
        title: str | None = None,
        label: str | None = None,
        source: str | None = None,
        published: str | None = None,
        serialization: str = "full",
        tagged_text: bool = False,
        escape_html: bool = False,
        enterprise_only: bool = False,
        limit: int = 20,
        offset: str | None = None,
        paginate: bool = False,
    ) -> dict[str, Any]:
        """Search Insikt Group and enterprise Analyst Notes via ``POST /analyst-note/search``."""
        body: dict[str, Any] = {
            "serialization": serialization,
            "limit": max(1, min(limit, 1000)),
        }
        if entity:
            body["entity"] = entity
        if topic:
            clean_topic = topic.strip()
            body["topic"] = _ANALYST_NOTE_TOPICS_LOWER.get(clean_topic.lower(), clean_topic)
        if title:
            body["title"] = title
        if label:
            body["label"] = label
        if source:
            body["source"] = source
        if published:
            body["published"] = published
        if tagged_text:
            body["tagged_text"] = True
        if escape_html:
            body["escape_html"] = True
        if enterprise_only:
            body["enterprise_only"] = True
        if offset:
            body["from"] = offset

        endpoint = "/analyst-note/search"
        all_items: list[Any] = []
        seen_offsets: set[str] = set()
        last_payload: dict[str, Any] = {}

        while True:
            data = self._post_json_dict(endpoint, body)
            last_payload = data
            batch = data.get("data", [])
            if isinstance(batch, list):
                all_items.extend(batch)
            next_offset = data.get("next_offset")
            if (
                not paginate
                or not isinstance(next_offset, str)
                or not next_offset
                or next_offset in seen_offsets
            ):
                break
            seen_offsets.add(next_offset)
            body["from"] = next_offset

        if paginate:
            result = dict(last_payload)
            result["data"] = all_items
            return result
        return last_payload

    def lookup_analyst_note(
        self,
        note_id: str,
        *,
        serialization: str = "full",
        tagged_text: bool = False,
        escape_html: bool = False,
    ) -> dict[str, Any]:
        """Retrieve a specific Analyst Note via ``POST /analyst-note/lookup/{note_id}``."""
        clean_id = _require_non_empty(note_id, "note_id")
        endpoint = f"/analyst-note/lookup/{quote(clean_id, safe=':')}"
        body: dict[str, Any] = {"serialization": serialization}
        if tagged_text:
            body["tagged_text"] = True
        if escape_html:
            body["escape_html"] = True
        return self._post_json_dict(endpoint, body)

    def get_analyst_note_attachment(self, note_id: str) -> bytes:
        """Download binary attachment associated with an Analyst Note."""
        clean_id = _require_non_empty(note_id, "note_id")
        endpoint = f"/analyst-note/attachment/{quote(clean_id, safe=':')}"
        response = self._request("GET", endpoint)
        return response.content

    def export_analyst_note(self, note_id: str, fmt: str = "html") -> bytes:
        """Export an Analyst Note rendered as ``html`` or ``pdf``."""
        clean_id = _require_non_empty(note_id, "note_id")
        norm_fmt = fmt.strip().lower()
        if norm_fmt not in ("html", "pdf"):
            raise ValueError(f"Unsupported Analyst Note export format: {fmt!r}")
        endpoint = f"/analyst-note/export/{norm_fmt}/{quote(clean_id, safe=':')}"
        response = self._request("GET", endpoint)
        return response.content

    # ------------------------------------------------------------------
    # F9: Threat Maps & Threat Actors API
    # ------------------------------------------------------------------
    def get_threat_maps(self) -> dict[str, Any]:
        """List all Threat Maps accessible to the current API token."""
        return self._get_json_dict("/threat/maps")

    def _threat_map_request(
        self,
        map_kind: str,
        *,
        org_id: str | None,
        entity_key: str,
        entities: list[str] | None,
        categories: list[str] | None,
        watchlists: list[str] | None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if entities:
            body[entity_key] = list(entities)
        if categories:
            body["categories"] = list(categories)
        if watchlists:
            body["watchlists"] = list(watchlists)
        if org_id and org_id.strip():
            endpoint = f"/threat/map/{quote(org_id.strip(), safe=':')}/{map_kind}"
        else:
            endpoint = f"/threat/map/{map_kind}"
        return self._post_json_dict(endpoint, body)

    def get_threat_actor_map(
        self,
        *,
        org_id: str | None = None,
        actors: list[str] | None = None,
        categories: list[str] | None = None,
        watchlists: list[str] | None = None,
    ) -> dict[str, Any]:
        """Retrieve organizational Threat Actor Threat Map scores (intent & opportunity)."""
        return self._threat_map_request(
            "actors",
            org_id=org_id,
            entity_key="actors",
            entities=actors,
            categories=categories,
            watchlists=watchlists,
        )

    def search_threat_actors(
        self,
        *,
        name: str | None = None,
        limit: int = 25,
        offset: str | None = None,
        paginate: bool = False,
    ) -> dict[str, Any]:
        """Search Recorded Future's threat actor database via ``POST /threat/actor/search``."""
        body: dict[str, Any] = {"limit": max(1, limit)}
        if name is not None and name.strip():
            body["name"] = name.strip()
        if offset is not None:
            body["offset"] = offset

        endpoint = "/threat/actor/search"
        all_items: list[Any] = []
        seen_offsets: set[str] = set()
        last_payload: dict[str, Any] = {}

        while True:
            data = self._post_json_dict(endpoint, body)
            last_payload = data
            batch = data.get("data", [])
            if isinstance(batch, list):
                all_items.extend(batch)
            next_offset = data.get("next_offset")
            if (
                not paginate
                or not isinstance(next_offset, str)
                or not next_offset
                or next_offset in seen_offsets
            ):
                break
            seen_offsets.add(next_offset)
            body["offset"] = next_offset

        if paginate:
            result = dict(last_payload)
            result["data"] = all_items
            return result
        return last_payload

    def get_threat_actor_categories(self) -> dict[str, Any]:
        """Retrieve the Recorded Future Threat Actor category taxonomy."""
        return self._get_json_dict("/threat/actor/categories")

    def get_malware_threat_map(
        self,
        *,
        org_id: str | None = None,
        malware: list[str] | None = None,
        categories: list[str] | None = None,
        watchlists: list[str] | None = None,
    ) -> dict[str, Any]:
        """Retrieve organizational Malware Threat Map scores (prevalence & opportunity)."""
        return self._threat_map_request(
            "malware",
            org_id=org_id,
            entity_key="malware",
            entities=malware,
            categories=categories,
            watchlists=watchlists,
        )

    def get_malware_categories(self) -> dict[str, Any]:
        """Retrieve the Recorded Future Malware category taxonomy."""
        return self._get_json_dict("/threat/malware/categories")

    # ------------------------------------------------------------------
    # F10: Malware Intelligence API
    # ------------------------------------------------------------------
    def _malware_intel_query_payload(
        self,
        *,
        field: str,
        start_date: str | None,
        end_date: str | None,
        my_enterprise: bool,
        page: int,
        sandbox_score: bool,
        links: bool,
        sanitize: bool,
    ) -> dict[str, Any]:
        clean_field = field.strip()
        if clean_field not in MALWARE_INTEL_FIELDS:
            raise ValueError(
                f"Unsupported Malware Intelligence field {field!r}; "
                f"expected one of {MALWARE_INTEL_FIELDS}."
            )
        resolved_start, resolved_end = self._resolve_malware_intel_dates(start_date, end_date)
        body: dict[str, Any] = {
            "field": clean_field,
            "start_date": resolved_start,
            "my_enterprise": my_enterprise,
            "page": max(0, page),
            "sandbox_score": sandbox_score,
            "links": links,
            "sanitize": sanitize,
        }
        if resolved_end is not None:
            body["end_date"] = resolved_end
        return body

    def malware_intel_query(
        self,
        query: str,
        field: str = "sha256",
        *,
        start_date: str | None = None,
        end_date: str | None = None,
        my_enterprise: bool = False,
        page: int = 0,
        sandbox_score: bool = True,
        links: bool = True,
        sanitize: bool = False,
    ) -> dict[str, Any]:
        """Query Malware Intelligence using structured query syntax."""
        clean_query = _require_non_empty(query, "query")
        body = self._malware_intel_query_payload(
            field=field,
            start_date=start_date,
            end_date=end_date,
            my_enterprise=my_enterprise,
            page=page,
            sandbox_score=sandbox_score,
            links=links,
            sanitize=sanitize,
        )
        body["query"] = clean_query
        return self._post_json_dict("/malware-intelligence/v1/query", body)

    def malware_intel_query_nl(
        self,
        query: str,
        field: str = "sha256",
        *,
        start_date: str | None = None,
        end_date: str | None = None,
        my_enterprise: bool = False,
        page: int = 0,
        sandbox_score: bool = True,
        links: bool = True,
        sanitize: bool = False,
    ) -> dict[str, Any]:
        """Query Malware Intelligence using natural language."""
        clean_query = _require_non_empty(query, "query")
        body = self._malware_intel_query_payload(
            field=field,
            start_date=start_date,
            end_date=end_date,
            my_enterprise=my_enterprise,
            page=page,
            sandbox_score=sandbox_score,
            links=links,
            sanitize=sanitize,
        )
        body["query"] = clean_query
        return self._post_json_dict("/malware-intelligence/v1/query_nl", body)

    def malware_intel_query_iocs(
        self,
        *,
        sha256_list: list[str] | None = None,
        ip_list: list[str] | None = None,
        domain_list: list[str] | None = None,
        url_list: list[str] | None = None,
        field: str = "sha256",
        operator: str = "or",
        start_date: str | None = None,
        end_date: str | None = None,
        my_enterprise: bool = False,
        page: int = 0,
        sandbox_score: bool = True,
        links: bool = True,
        sanitize: bool = False,
    ) -> dict[str, Any]:
        """Query Malware Intelligence by IOC lists."""
        body = self._malware_intel_query_payload(
            field=field,
            start_date=start_date,
            end_date=end_date,
            my_enterprise=my_enterprise,
            page=page,
            sandbox_score=sandbox_score,
            links=links,
            sanitize=sanitize,
        )
        norm_op = operator.strip().lower()
        if norm_op not in ("and", "or"):
            raise ValueError(f"Unsupported operator {operator!r}; expected 'and' or 'or'.")
        body["operator"] = norm_op

        has_any = False
        for key, vals in (
            ("sha256_list", sha256_list),
            ("ip_list", ip_list),
            ("domain_list", domain_list),
            ("url_list", url_list),
        ):
            if vals:
                cleaned = [str(v).strip() for v in vals if str(v).strip()]
                if cleaned:
                    body[key] = cleaned
                    has_any = True
        if not has_any:
            raise ValueError(
                "At least one IOC list (sha256_list, ip_list, domain_list, or url_list) is required."
            )
        return self._post_json_dict("/malware-intelligence/v1/query_iocs", body)

    def malware_intel_sandbox_reports(
        self,
        sha256: str,
        query: str,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
        my_enterprise: bool = False,
        limit: int = 10,
        sanitize: bool = False,
    ) -> dict[str, Any]:
        """Fetch top sandbox reports for a SHA-256 matching a Malware Intelligence query."""
        clean_sha = _require_non_empty(sha256, "sha256")
        clean_query = _require_non_empty(query, "query")
        resolved_start, resolved_end = self._resolve_malware_intel_dates(start_date, end_date)
        body: dict[str, Any] = {
            "sha256": clean_sha,
            "query": clean_query,
            "start_date": resolved_start,
            "my_enterprise": my_enterprise,
            "limit": max(1, limit),
            "sanitize": sanitize,
        }
        if resolved_end is not None:
            body["end_date"] = resolved_end
        return self._post_json_dict("/malware-intelligence/v1/reports", body)

    # ------------------------------------------------------------------
    # F11: Risk History & Company Risk Rules API
    # ------------------------------------------------------------------
    def search_risk_history(
        self,
        entities: list[str],
        *,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve historical risk score, criticality, and risk rule change events."""
        clean_entities = [str(e).strip() for e in entities if str(e).strip()]
        if not clean_entities:
            raise ValueError("Risk history requires at least one entity ID.")
        body: dict[str, Any] = {"entities": clean_entities}
        if start_date:
            body["from"] = start_date
        if end_date:
            body["to"] = end_date
        return self._post_json_dict("/risk/history", body)

    def get_active_company_risk_rule(
        self,
        company: str,
        rule_alias: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Fetch enriched evidence for an active company risk rule."""
        clean_company = _require_non_empty(company, "company")
        clean_rule = _require_non_empty(rule_alias, "rule_alias")
        body: dict[str, Any] = {
            "company": clean_company,
            "rule_alias": clean_rule,
            "limit": max(1, limit),
            "offset": max(0, offset),
        }
        return self._post_json_dict("/risk/active/rule", body)

    # ------------------------------------------------------------------
    # F12: Identity Intelligence API
    # ------------------------------------------------------------------
    def identity_detections(
        self,
        *,
        organization_id: list[str] | None = None,
        include_enterprise_level: bool | None = None,
        domains: list[str] | None = None,
        novel_only: bool | None = None,
        malware_only: bool | None = None,
        detection_type: str | None = None,
        created_gte: str | None = None,
        created_lt: str | None = None,
        limit: int = 50,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve identity exposure detections via ``POST /identity/detections``."""
        body: dict[str, Any] = {"limit": max(1, limit)}
        if organization_id:
            body["organization_id"] = list(organization_id)
        if include_enterprise_level is not None:
            body["include_enterprise_level"] = include_enterprise_level
        filt: dict[str, Any] = {}
        if novel_only is not None:
            filt["novel_only"] = novel_only
        if malware_only is not None:
            filt["malware_only"] = malware_only
        if domains:
            filt["domains"] = list(domains)
        if detection_type:
            filt["detection_type"] = detection_type
        created: dict[str, str] = {}
        if created_gte:
            created["gte"] = created_gte
        if created_lt:
            created["lt"] = created_lt
        if created:
            filt["created"] = created
        if filt:
            body["filter"] = filt
        if offset:
            body["offset"] = offset
        return self._post_json_dict("/identity/detections", body)

    def identity_search(
        self,
        *,
        domains: list[str] | None = None,
        domain_types: list[str] | None = None,
        organization_id: str | None = None,
        filter_obj: dict[str, Any] | None = None,
        limit: int = 50,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """Search compromised identities for domain(s) via ``POST /identity/credentials/search``."""
        body: dict[str, Any] = {"limit": max(1, limit)}
        if organization_id:
            body["organization_id"] = organization_id
        if domains:
            body["domains"] = list(domains)
        if domain_types:
            body["domain_types"] = list(domain_types)
        if filter_obj:
            body["filter"] = dict(filter_obj)
        if offset:
            body["offset"] = offset
        return self._post_json_dict("/identity/credentials/search", body)

    def identity_lookup(
        self,
        *,
        subjects: list[str] | None = None,
        subjects_sha1: list[str] | None = None,
        subjects_login: list[dict[str, str]] | None = None,
        organization_id: str | None = None,
        filter_obj: dict[str, Any] | None = None,
        limit: int = 50,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """Look up full credential exposure history for specific subjects."""
        body: dict[str, Any] = {"limit": max(1, limit)}
        if organization_id:
            body["organization_id"] = organization_id
        if subjects:
            body["subjects"] = list(subjects)
        if subjects_sha1:
            body["subjects_sha1"] = list(subjects_sha1)
        if subjects_login:
            body["subjects_login"] = [dict(item) for item in subjects_login]
        if filter_obj:
            body["filter"] = dict(filter_obj)
        if offset:
            body["offset"] = offset
        return self._post_json_dict("/identity/credentials/lookup", body)

    def identity_password_lookup(self, passwords: list[dict[str, str]]) -> dict[str, Any]:
        """Check whether cryptographic password hashes or prefixes have been exposed."""
        if not passwords:
            raise ValueError("At least one password hash entry is required.")
        return self._post_json_dict(
            "/identity/password/lookup",
            {"passwords": [dict(p) for p in passwords]},
        )

    def identity_hostname_lookup(
        self,
        hostname: str,
        *,
        organization_id: str | None = None,
        filter_obj: dict[str, Any] | None = None,
        limit: int = 50,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """Look up compromised credentials associated with a specific hostname."""
        clean_host = _require_non_empty(hostname, "hostname")
        body: dict[str, Any] = {"hostname": clean_host, "limit": max(1, limit)}
        if organization_id:
            body["organization_id"] = organization_id
        if filter_obj:
            body["filter"] = dict(filter_obj)
        if offset:
            body["offset"] = offset
        return self._post_json_dict("/identity/hostname/lookup", body)

    def identity_ip_lookup(
        self,
        *,
        ip: str | None = None,
        ip_range: dict[str, str] | None = None,
        organization_id: str | None = None,
        filter_obj: dict[str, Any] | None = None,
        limit: int = 50,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """Look up compromised credentials associated with an IP address or range."""
        if not (ip and ip.strip()) and not ip_range:
            raise ValueError("Provide either 'ip' or 'ip_range' for identity IP lookup.")
        body: dict[str, Any] = {"limit": max(1, limit)}
        if ip and ip.strip():
            body["ip"] = ip.strip()
        if ip_range:
            body["range"] = dict(ip_range)
        if organization_id:
            body["organization_id"] = organization_id
        if filter_obj:
            body["filter"] = dict(filter_obj)
        if offset:
            body["offset"] = offset
        return self._post_json_dict("/identity/ip/lookup", body)

    def identity_incident_report(
        self,
        source: str,
        *,
        include_details: bool = True,
        organization_id: str | None = None,
        limit: int = 50,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve an exposure incident report for a specific malware log source."""
        clean_source = _require_non_empty(source, "source")
        body: dict[str, Any] = {
            "source": clean_source,
            "include_details": include_details,
            "limit": max(1, limit),
        }
        if organization_id:
            body["organization_id"] = organization_id
        if offset:
            body["offset"] = offset
        return self._post_json_dict("/identity/incident/report", body)

    def identity_dump_metadata(
        self,
        names: list[str] | None = None,
        *,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Search metadata for breach databases and stealer dumps."""
        body: dict[str, Any] = {"limit": max(1, limit)}
        if names:
            body["names"] = list(names)
        return self._post_json_dict("/identity/metadata/dump/search", body)

    # ------------------------------------------------------------------
    # F13: Collective Insights API
    # ------------------------------------------------------------------
    def search_collective_insights(
        self,
        *,
        filters: dict[str, Any] | None = None,
        limit: int = 50,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """Search enriched Collective Insights events."""
        body: dict[str, Any] = {"limit": max(1, limit)}
        if filters:
            body["filters"] = dict(filters)
        if offset:
            body["offset"] = offset
        return self._post_json_dict("/collective-insights/search", body)

    def list_collective_insights_exclusions(
        self,
        organization: str,
        *,
        limit: int = 50,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """List Collective Insights exclusion items for an organization."""
        clean_org = _require_non_empty(organization, "organization")
        params: dict[str, Any] = {"limit": max(1, limit)}
        if offset:
            params["offset"] = offset
        endpoint = f"/collective-insights/exclusions/{quote(clean_org, safe='')}/all"
        return self._get_json_dict(endpoint, params=params)

    # ------------------------------------------------------------------
    # F14: Fusion v3 API
    # ------------------------------------------------------------------
    def fusion_list_directory(self, path: str = "/public") -> dict[str, Any]:
        """List files and subdirectories in a Fusion v3 directory."""
        encoded = self._normalize_fusion_path(path)
        return self._get_json_dict(f"/fusion/v3/files/directory/{encoded}")

    def fusion_stat_file(self, path: str) -> dict[str, str]:
        """Check Fusion v3 file metadata (ETag, Last-Modified) via HEAD."""
        encoded = self._normalize_fusion_path(path)
        response = self._request("HEAD", f"/fusion/v3/files/{encoded}")
        headers = getattr(response, "headers", {})
        if isinstance(headers, Mapping):
            return {str(k): str(v) for k, v in headers.items()}
        return {}

    def fusion_get_file(self, path: str) -> bytes:
        """Download a file from the Fusion v3 file system."""
        encoded = self._normalize_fusion_path(path)
        response = self._request("GET", f"/fusion/v3/files/{encoded}")
        return response.content

    # ------------------------------------------------------------------
    # F15: Expanded Sandbox v0 Research API
    # ------------------------------------------------------------------
    def sandbox_list_samples(
        self,
        *,
        subset: str = "org",
        limit: int = 50,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """List Sandbox submissions by ownership scope (``owned``, ``public``, ``org``)."""
        params: dict[str, Any] = {"subset": subset, "limit": max(1, limit)}
        if offset:
            params["offset"] = offset
        return self._get_json_dict("/samples", params=params, is_sandbox=True)

    def sandbox_get_summary(self, sample_id: str) -> dict[str, Any]:
        """Retrieve mid-level summary with per-task metadata for a Sandbox sample."""
        clean_id = _require_non_empty(sample_id, "sample_id")
        return self._get_json_dict(
            f"/samples/{quote(clean_id, safe='')}/summary", is_sandbox=True
        )

    def sandbox_get_static_report(self, sample_id: str) -> dict[str, Any]:
        """Retrieve the static analysis report for a Sandbox sample."""
        clean_id = _require_non_empty(sample_id, "sample_id")
        return self._get_json_dict(
            f"/samples/{quote(clean_id, safe='')}/reports/static", is_sandbox=True
        )

    def sandbox_get_dynamic_report(
        self, sample_id: str, task_id: str = "behavioral1"
    ) -> dict[str, Any]:
        """Retrieve the behavioral dynamic triage report for a Sandbox task."""
        clean_id = _require_non_empty(sample_id, "sample_id")
        clean_task = _require_non_empty(task_id, "task_id")
        return self._get_json_dict(
            f"/samples/{quote(clean_id, safe='')}/{quote(clean_task, safe='')}/report_triage.json",
            is_sandbox=True,
        )

    def sandbox_get_url_scan_report(self, sample_id: str) -> dict[str, Any]:
        """Retrieve URL scan report for a Sandbox URL submission."""
        clean_id = _require_non_empty(sample_id, "sample_id")
        return self._get_json_dict(
            f"/samples/{quote(clean_id, safe='')}/urlscan1/report_urlscan.json",
            is_sandbox=True,
        )

    def sandbox_get_url_scan_screenshot(self, sample_id: str) -> bytes:
        """Retrieve PNG screenshot bytes captured during a Sandbox URL scan."""
        clean_id = _require_non_empty(sample_id, "sample_id")
        response = self._request(
            "GET",
            f"/samples/{quote(clean_id, safe='')}/urlscan1/screenshot.png",
            is_sandbox=True,
            headers_extra={"Accept": "image/png, */*"},
        )
        return response.content

    def sandbox_list_yara_rules(self) -> dict[str, Any]:
        """List accessible custom YARA rules in Recorded Future Sandbox."""
        return self._get_json_dict("/yara", is_sandbox=True)

    def sandbox_get_yara_rule(self, rule_name: str) -> dict[str, Any]:
        """Retrieve a Sandbox custom YARA rule's source and compilation warnings."""
        clean_name = _require_non_empty(rule_name, "rule_name")
        return self._get_json_dict(f"/yara/{quote(clean_name, safe='')}", is_sandbox=True)

    # ------------------------------------------------------------------
    # F16: Expanded Alerts, Playbook Alerts & Cases Read Endpoints
    # ------------------------------------------------------------------
    def search_alert_rules(
        self,
        *,
        freetext: str | None = None,
        limit: int = 50,
        tagged_text: bool = False,
    ) -> dict[str, Any]:
        """Search classic alert rule definitions via ``GET /alert/v2/rule``."""
        params: dict[str, Any] = {"limit": max(1, limit)}
        if freetext:
            params["freetext"] = freetext
        if tagged_text:
            params["taggedText"] = "true"
        return self._get_json_dict("/alert/v2/rule", params=params)

    def get_alert_v3_image(self, image_id: str) -> bytes:
        """Download raw image bytes tied to an Alert v3 hit."""
        clean_id = _require_non_empty(image_id, "image_id")
        response = self._request(
            "GET",
            "/alert/v3/image",
            params={"id": clean_id},
            headers_extra={"Accept": "image/png, */*"},
        )
        return response.content

    def get_playbook_alert_metadata(self) -> dict[str, Any]:
        """Fetch Playbook Alert status, category, priority, and action enumerations."""
        return self._get_json_dict("/playbook-alert/metadata/common")

    def get_case_eligible_assignees(
        self,
        case_id: str,
        *,
        text: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """List users eligible to be assigned to a specific Case."""
        clean_id = _require_non_empty(case_id, "case_id")
        body: dict[str, Any] = {"id": clean_id, "limit": max(1, limit)}
        if text:
            body["text"] = text
        response = self._request("POST", "/case/assignees", json_data=body)
        data = self._json_or_raise(response, "/case/assignees")
        self._check_playbook_status(data, "/case/assignees")
        return data if isinstance(data, (list, dict)) else {}

    # ------------------------------------------------------------------
    # F17: Autonomous Threat Operations (ATO) API
    # ------------------------------------------------------------------
    def ato_list_sources(self) -> list[dict[str, Any]]:
        """List custom intelligence sources in Autonomous Threat Operations."""
        endpoint = "/autonomous-threat-operations/v1/sources"
        response = self._request("GET", endpoint)
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, list) else []

    def ato_query_profiles(
        self,
        kind: str = "detection",
        *,
        ids: list[str] | None = None,
        enterprise: str | None = None,
        integration: str | None = None,
    ) -> dict[str, Any]:
        """Query ATO hunting, detection, or prevention profiles."""
        norm_kind = kind.strip().lower()
        if norm_kind not in ("hunting", "detection", "prevention"):
            raise ValueError(f"Unsupported ATO profile kind: {kind!r}")
        body: dict[str, Any] = {}
        if ids:
            body["ids"] = list(ids)
        if enterprise:
            body["enterprise"] = enterprise
        if integration:
            body["integration"] = integration
        return self._post_json_dict(
            f"/autonomous-threat-operations/v1/{norm_kind}/profiles/query", body
        )

    def _ato_profile_action(
        self,
        kind: str,
        profile_id: str,
        suffix: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        norm_kind = kind.strip().lower()
        if norm_kind not in ("detection", "prevention"):
            raise ValueError(
                f"ATO profile {suffix} requires 'detection' or 'prevention' (got {kind!r})."
            )
        clean_id = _require_non_empty(profile_id, "profile_id")
        endpoint = (
            f"/autonomous-threat-operations/v1/{norm_kind}/profiles/"
            f"{quote(clean_id, safe='')}/{suffix}"
        )
        return self._post_json_dict(endpoint, body)

    def ato_get_profile_indicators(
        self,
        kind: str,
        profile_id: str,
        *,
        indicator_types: list[str] | None = None,
        algorithms: list[str] | None = None,
        include_risk: bool = True,
        limit: int = 100,
        offset: str | None = None,
    ) -> dict[str, Any]:
        """Fetch indicators from an ATO detection or prevention profile."""
        body: dict[str, Any] = {"limit": max(1, limit)}
        filt: dict[str, Any] = {}
        if indicator_types:
            filt["types"] = list(indicator_types)
        if algorithms:
            filt["algorithms"] = list(algorithms)
        if filt:
            body["filter"] = filt
        if include_risk:
            body["include"] = {"risk": {"score": True, "rules": True}}
        if offset:
            body["offset"] = offset
        return self._ato_profile_action(kind, profile_id, "indicators", body)

    def ato_get_profile_rules(
        self,
        kind: str,
        profile_id: str,
        *,
        rule_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """Fetch deployable detection rules from an ATO detection or prevention profile."""
        types_val = list(rule_types) if rule_types else ["sigma", "snort", "yara"]
        return self._ato_profile_action(
            kind, profile_id, "rules", {"filter": {"types": types_val}}
        )

    # ------------------------------------------------------------------
    # F18: STIX / TAXII 2.1 Research API
    # ------------------------------------------------------------------
    def taxii2_discover(self) -> dict[str, Any]:
        """Discover STIX/TAXII 2.1 server info and API roots."""
        return self._get_json_dict("/taxii2/", auth_mode="taxii2")

    def taxii2_get_collections(self, api_root: str = "default") -> dict[str, Any]:
        """List STIX/TAXII 2.1 collections under an API root."""
        clean_root = _require_non_empty(api_root, "api_root")
        return self._get_json_dict(
            f"/taxii2/{quote(clean_root, safe='')}/collections/",
            auth_mode="taxii2",
        )

    def taxii2_get_objects(
        self,
        collection_id: str,
        *,
        api_root: str = "default",
        limit: int = 100,
        next_token: str | None = None,
        added_after: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve STIX 2.1 objects from a TAXII 2.1 collection."""
        clean_root = _require_non_empty(api_root, "api_root")
        clean_col = _require_non_empty(collection_id, "collection_id")
        params: dict[str, Any] = {"limit": max(1, min(limit, 1000))}
        if next_token:
            params["next"] = next_token
        if added_after:
            params["added_after"] = added_after
        return self._get_json_dict(
            f"/taxii2/{quote(clean_root, safe='')}/collections/{quote(clean_col, safe='')}/objects/",
            params=params,
            auth_mode="taxii2",
        )

    # ------------------------------------------------------------------
    # F19: External Recorded Future Platforms (ASI, PFI, RiskRecon)
    # ------------------------------------------------------------------
    def asi_list_projects(self, *, sort_direction: str | None = None) -> dict[str, Any]:
        """List Attack Surface Intelligence (ASI) projects."""
        params = {"sort_direction": sort_direction} if sort_direction else None
        return self._get_json_dict("/projects", params=params, auth_mode="asi")

    def asi_find_assets(
        self,
        project_id: str,
        **filters: Any,
    ) -> dict[str, Any]:
        """Find ASI assets using lightweight GET query parameter filters."""
        clean_proj = _require_non_empty(project_id, "project_id")
        params = {k: v for k, v in filters.items() if v is not None}
        return self._get_json_dict(
            f"/projects/{quote(clean_proj, safe='')}/assets",
            params=params or None,
            auth_mode="asi",
        )

    def asi_search_assets(
        self,
        project_id: str,
        *,
        filter_obj: dict[str, Any] | None = None,
        limit: int = 50,
        next_cursor: str | None = None,
        enrichments: list[str] | None = None,
        sort: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Search ASI assets via ``POST /projects/{project_id}/assets/_search``."""
        clean_proj = _require_non_empty(project_id, "project_id")
        pagination: dict[str, Any] = {"limit": max(1, limit)}
        if next_cursor:
            pagination["next_cursor"] = next_cursor
        body: dict[str, Any] = {"pagination": pagination}
        if filter_obj is not None:
            body["filter"] = filter_obj
        if enrichments:
            body["enrichments"] = list(enrichments)
        if sort:
            body["sort"] = list(sort)
        return self._post_json_dict(
            f"/projects/{quote(clean_proj, safe='')}/assets/_search",
            body,
            auth_mode="asi",
        )

    def asi_read_asset(
        self,
        project_id: str,
        asset_id: str,
        *,
        additional_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Retrieve detailed ASI information for a specific asset."""
        clean_proj = _require_non_empty(project_id, "project_id")
        clean_asset = _require_non_empty(asset_id, "asset_id")
        params = {"additional_fields": list(additional_fields)} if additional_fields else None
        return self._get_json_dict(
            f"/projects/{quote(clean_proj, safe='')}/assets/{quote(clean_asset, safe='')}",
            params=params,
            auth_mode="asi",
        )

    def asi_list_asset_exposures(self, project_id: str, asset_id: str) -> dict[str, Any]:
        """List exposures discovered on a specific ASI asset."""
        clean_proj = _require_non_empty(project_id, "project_id")
        clean_asset = _require_non_empty(asset_id, "asset_id")
        return self._get_json_dict(
            f"/projects/{quote(clean_proj, safe='')}/assets/{quote(clean_asset, safe='')}/exposures",
            auth_mode="asi",
        )

    def asi_list_exposures(self, project_id: str, **filters: Any) -> dict[str, Any]:
        """List project-level ASI exposure signatures."""
        clean_proj = _require_non_empty(project_id, "project_id")
        params = {k: v for k, v in filters.items() if v is not None}
        return self._get_json_dict(
            f"/projects/{quote(clean_proj, safe='')}/exposures",
            params=params or None,
            auth_mode="asi",
        )

    def asi_get_exposure_assets(
        self,
        project_id: str,
        signature_id: str,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve ASI assets affected by a given exposure signature ID."""
        clean_proj = _require_non_empty(project_id, "project_id")
        clean_sig = _require_non_empty(signature_id, "signature_id")
        params: dict[str, Any] = {"limit": max(1, limit)}
        if cursor:
            params["cursor"] = cursor
        return self._get_json_dict(
            f"/projects/{quote(clean_proj, safe='')}/exposures/{quote(clean_sig, safe='')}",
            params=params,
            auth_mode="asi",
        )

    def asi_list_signatures(self, project_id: str, **filters: Any) -> dict[str, Any]:
        """List ASI detection signatures matching filters."""
        clean_proj = _require_non_empty(project_id, "project_id")
        params = {k: v for k, v in filters.items() if v is not None}
        return self._get_json_dict(
            f"/projects/{quote(clean_proj, safe='')}/signatures",
            params=params or None,
            auth_mode="asi",
        )

    def asi_get_signature(
        self,
        project_id: str,
        signature_id: str,
        *,
        additional_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Retrieve full details for an ASI exposure signature."""
        clean_proj = _require_non_empty(project_id, "project_id")
        clean_sig = _require_non_empty(signature_id, "signature_id")
        params = {"additional_fields": list(additional_fields)} if additional_fields else None
        return self._get_json_dict(
            f"/projects/{quote(clean_proj, safe='')}/signatures/{quote(clean_sig, safe='')}",
            params=params,
            auth_mode="asi",
        )

    def pfi_list_tasks(self) -> dict[str, Any]:
        """List queued Payment Fraud Intelligence (PFI) tasks."""
        return self._get_json_dict("/task/list", auth_mode="pfi")

    def pfi_get_task_status(self, task_id: str) -> dict[str, Any]:
        """Poll status of a PFI bulk data task."""
        clean_id = _require_non_empty(task_id, "task_id")
        return self._get_json_dict(f"/task/{quote(clean_id, safe='')}", auth_mode="pfi")

    def pfi_query_pipeline(
        self,
        pipeline_name: str,
        *,
        query: str | None = None,
        from_date: str = "now-7d/d",
        to_date: str = "now/d",
        columns: list[str] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Submit or dry-run a PFI bulk data pipeline query."""
        raw_name = _require_non_empty(pipeline_name, "pipeline_name")
        endpoint = PFI_PIPELINES.get(raw_name.lower(), raw_name)
        if not endpoint.startswith("/"):
            endpoint = f"/pipeline/{endpoint}"
        input_obj: dict[str, Any] = {
            "queryRange": {"from": from_date, "to": to_date},
        }
        if query:
            input_obj["query"] = query
        body: dict[str, Any] = {
            "dryRun": dry_run,
            "input": input_obj,
            "output": {"columns": list(columns) if columns else []},
        }
        response = self._request("PUT", endpoint, json_data=body, auth_mode="pfi")
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, dict) else {}

    def pfi_pickup_data(
        self,
        task_id: str,
        *,
        fmt: str = "json",
        columns: list[str] | None = None,
    ) -> list[dict[str, Any]] | str:
        """Download completed PFI bulk task output via ``POST /file/{id}``."""
        clean_id = _require_non_empty(task_id, "task_id")
        norm_fmt = fmt.strip().lower()
        if norm_fmt not in ("json", "csv"):
            raise ValueError(f"Unsupported PFI output format: {fmt!r}")
        endpoint = f"/file/{quote(clean_id, safe='')}"
        body = {"format": norm_fmt, "columns": list(columns) if columns else []}
        response = self._request("POST", endpoint, json_data=body, auth_mode="pfi")
        raw_text = response.text or ""
        if norm_fmt == "csv":
            return raw_text
        records: list[dict[str, Any]] = []
        for line in raw_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                records.append(parsed)
        return records

    def riskrecon_list_toes(self) -> list[dict[str, Any]]:
        """List Targets of Evaluation (TOEs) in RiskRecon."""
        endpoint = "/v1/toes"
        response = self._request("GET", endpoint, auth_mode="riskrecon")
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, list) else []

    def riskrecon_lookup_by_domain(self, domain: str) -> list[dict[str, Any]]:
        """Look up RiskRecon TOE records by domain or hostname."""
        clean_domain = _require_non_empty(domain, "domain")
        endpoint = "/v1/toes/by_domains"
        response = self._request(
            "GET", endpoint, params={"domain": clean_domain}, auth_mode="riskrecon"
        )
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, list) else []

    def riskrecon_lookup_by_cve(self, cve_id: str) -> list[dict[str, Any]]:
        """Look up RiskRecon TOEs affected by a given CVE."""
        clean_cve = _require_non_empty(cve_id, "cve_id")
        endpoint = "/v1/toes/by_cve"
        response = self._request(
            "GET", endpoint, params={"cve_id": clean_cve}, auth_mode="riskrecon"
        )
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, list) else []

    def riskrecon_get_ratings(
        self,
        toe_id: str,
        *,
        current_rating_only: bool = True,
        page: int = 1,
        per_page: int = 50,
    ) -> dict[str, Any]:
        """Retrieve current or historical security ratings for a RiskRecon TOE."""
        clean_id = _require_non_empty(toe_id, "toe_id")
        params: dict[str, Any] = {
            "current_rating_only": "true" if current_rating_only else "false",
            "page": max(1, page),
            "per_page": max(1, per_page),
        }
        return self._get_json_dict(
            f"/v1/toes/{quote(clean_id, safe='')}/ratings",
            params=params,
            auth_mode="riskrecon",
        )

    def riskrecon_get_findings(
        self,
        toe_id: str,
        *,
        severity: str | None = None,
        page: int = 1,
        per_page: int = 50,
    ) -> dict[str, Any]:
        """Retrieve paginated findings for the latest RiskRecon TOE analysis."""
        clean_id = _require_non_empty(toe_id, "toe_id")
        params: dict[str, Any] = {
            "page": max(1, page),
            "per_page": max(1, per_page),
        }
        if severity:
            params["severity"] = severity
        return self._get_json_dict(
            f"/v1/findings_paginated/{quote(clean_id, safe='')}",
            params=params,
            auth_mode="riskrecon",
        )

    def riskrecon_get_hosts(self, toe_id: str) -> list[dict[str, Any]]:
        """Retrieve discovered hosts for the latest RiskRecon TOE analysis."""
        clean_id = _require_non_empty(toe_id, "toe_id")
        endpoint = f"/v1/hosts/{quote(clean_id, safe='')}"
        response = self._request("GET", endpoint, auth_mode="riskrecon")
        data = self._json_or_raise(response, endpoint)
        return data if isinstance(data, list) else []

    def riskrecon_get_breach_events(
        self,
        *,
        toe_id: str | None = None,
        page: int = 1,
        per_page: int = 50,
    ) -> dict[str, Any]:
        """Retrieve portfolio data-loss / breach events from RiskRecon."""
        params: dict[str, Any] = {
            "page": max(1, page),
            "per_page": max(1, per_page),
        }
        if toe_id:
            params["toe_id"] = toe_id
        return self._get_json_dict(
            "/v1/portfolio_data_loss_events",
            params=params,
            auth_mode="riskrecon",
        )
