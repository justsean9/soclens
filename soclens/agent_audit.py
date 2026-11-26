"""Secret-redacted, thread-safe persistent JSONL audit log for agentic SOC runs."""

from __future__ import annotations

import bisect
import json
import logging
import re
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from soclens.config import get_workspace_dir

logger = logging.getLogger(__name__)

AuditEventType = Literal[
    "prompt",
    "llm_response",
    "tool_call",
    "permission_check",
    "tool_result",
    "decision",
    "blocked_action",
    "policy_change",
    "error",
]

VALID_AUDIT_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "prompt",
        "llm_response",
        "tool_call",
        "permission_check",
        "tool_result",
        "decision",
        "blocked_action",
        "policy_change",
        "error",
    }
)

_MAX_REDACT_DEPTH: int = 64

_NON_SECRET_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "max_tokens",
        "token_count",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "tokens_used",
        "ms_auth_mode",
        "auth_mode",
        "auth_method",
        "token_type",
    }
)

_SENSITIVE_KEY_EXACT: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "proxy_authorization",
        "x-api-key",
        "x_api_key",
        "x-rftoken",
        "x_rftoken",
        "api_key",
        "apikey",
        "api-key",
        "api_token",
        "apitoken",
        "access_token",
        "refresh_token",
        "id_token",
        "auth",
        "auth_key",
        "auth-key",
        "auth_token",
        "bearer_token",
        "bearer",
        "token",
        "secret",
        "secret_key",
        "client_secret",
        "directline_secret",
        "password",
        "passwd",
        "passphrase",
        "private_key",
        "credential",
        "credentials",
        "rf_llm_api_key",
        "rf_api_token",
        "s1_api_token",
        "splunk_token",
        "splunk_password",
        "ms_bearer_token",
        "ms_copilot_bearer_token",
        "ms_directline_secret",
        "ms_copilot_directline_secret",
        "sig",
        "session_token",
    }
)

_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[_-])("
    r"api[-_]?key|apikey|api[-_]?token|access[-_]?token|refresh[-_]?token|"
    r"id[-_]?token|auth[-_]?token|bearer[-_]?token|session[-_]?token|"
    r"client[-_]?secret|directline[-_]?secret|private[-_]?key|"
    r"password|passwd|passphrase|secret|credential|credentials|rftoken|"
    r"authorization"
    r")(?:$|[_-])",
    re.IGNORECASE,
)

_URL_QUERY_EXTRA_KEYS: frozenset[str] = frozenset({"auth", "jwt", "signature"})

_AUTH_HEADER_KEYS: frozenset[str] = frozenset(
    {"authorization", "proxy-authorization", "proxy_authorization"}
)

_AUTH_SINGLE_TOKEN_SCHEMES = (
    r"Bearer|ApiToken|Basic|Splunk|Token|JWT|OAuth|Negotiate|NTLM|SSWS|Bot|DPoP|ApiKey"
)
_AUTH_SINGLE_TOKEN_SCHEME_SET: frozenset[str] = frozenset(
    {
        "bearer",
        "apitoken",
        "basic",
        "splunk",
        "token",
        "apikey",
        "jwt",
        "oauth",
        "negotiate",
        "ntlm",
        "ssws",
        "bot",
        "dpop",
    }
)
_AUTH_MULTIPARAM_SCHEMES = (
    r"Digest|AWS4-HMAC-SHA256|AWS4-ECDSA-P256-SHA256|HMAC|HOBA|Mutual|"
    r"SCRAM-SHA-256|SCRAM-SHA-1|Signature|Hawk|VAPID"
)
_NON_AUTH_LOG_KEYS: frozenset[str] = frozenset(
    {
        "host",
        "hostname",
        "ip",
        "src",
        "dst",
        "src_ip",
        "dst_ip",
        "port",
        "method",
        "path",
        "url",
        "status",
        "status_code",
        "env",
        "region",
        "cluster",
        "zone",
        "tenant",
        "provider",
        "mode",
        "msg",
        "message",
        "event",
        "event_key",
        "run_id",
        "user_agent",
        "ua",
        "time",
        "timestamp",
        "ts_iso",
        "level",
        "severity",
        "source",
        "index",
        "sourcetype",
        "page",
        "limit",
        "offset",
        "service",
        "component",
        "logger",
        "trace_id",
        "span_id",
        "request_id",
        "req_id",
        "corr_id",
        "correlation_id",
    }
)

_NON_AUTH_SPACE_LOG_KEYS: frozenset[str] = frozenset(
    {
        "id",
        "ts",
        "headers",
        "uri",
        "app",
        "expires_in",
        "date",
        "namespace",
        "pod",
        "node",
        "datacenter",
        "dc",
        "az",
        "account",
        "account_id",
        "project",
        "project_id",
        "org",
        "org_id",
        "session_id",
        "client_id",
    }
)

_MULTIPARAM_SPACE_OPTIONAL_AUTH_KEYS: frozenset[str] = frozenset(
    {"id", "ts", "headers", "uri", "app", "expires_in"}
)

_UNAMBIGUOUS_HTTP_AUTH_PARAM_KEYS: frozenset[str] = frozenset(
    {
        "realm",
        "nonce",
        "qop",
        "nc",
        "cnonce",
        "response",
        "opaque",
        "algorithm",
        "keyid",
        "signature",
        "mac",
        "signedheaders",
    }
)

_HTTP_AUTH_PARAM_KEYS: frozenset[str] = frozenset(
    {
        "realm",
        "nonce",
        "qop",
        "nc",
        "cnonce",
        "response",
        "opaque",
        "algorithm",
        "keyid",
        "signature",
        "mac",
        "key",
        "token",
        "auth",
        "credential",
        "signedheaders",
        "api_key",
        "apikey",
        "secret",
    }
)

# 1. URL userinfo: https://user:pass@host
_URL_USERINFO_RE = re.compile(
    r"(https?|wss?|ftp)://([^/\s:@\"']++):([^/\s@\"']++)@",
    re.IGNORECASE,
)

# 2. Header / key-value assignments (key-first O(N) scan; value matched only for sensitive keys).
_HEADER_KEY_SEP_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(-*+)([A-Za-z0-9_][A-Za-z0-9_-]*+)[ \t]*+([:=])[ \t]*+"
)
_REDACTED_PLACEHOLDERS: frozenset[str] = frozenset(
    {"<REDACTED>", "<REDACTED_JWT>", "<REDACTED_MAX_DEPTH>"}
)
_REDACTED_PLACEHOLDER_PAT = r"<REDACTED(?:_JWT|_MAX_DEPTH)?>"
_REDACTED_PLACEHOLDER_RE = re.compile(_REDACTED_PLACEHOLDER_PAT)


def _is_redacted_placeholder(val: str) -> bool:
    return val in _REDACTED_PLACEHOLDERS


_QUOTED_START_RE = re.compile(r"(\\*+)([\"'])")
_AUTH_MULTI_SCHEME_RE = re.compile(r"(?i)(" + _AUTH_MULTIPARAM_SCHEMES + r")([ \t]++)")
_AUTH_SINGLE_SCHEME_RE = re.compile(r"(?i)(" + _AUTH_SINGLE_TOKEN_SCHEMES + r")([ \t]++)")
_AUTH_UNKNOWN_SCHEME_RE = re.compile(
    r"(?!sk-|gh[pousr]_|github_pat_|AKIA|xox[baprs]-|eyJ|<REDACTED)"
    r"([A-Za-z][A-Za-z0-9-]*+[ \t]++)"
)
_BS_RUN_RE = re.compile(r"\\++")
_CLOSING_TAG_RE = re.compile(r"</[A-Za-z][A-Za-z0-9:-]{0,31}>")
_KV_STOP_SCAN_RE = re.compile(r"[&\s,;\"'<>}\])\\]")
_KV_NEXT_KEY_RE = re.compile(
    rf"(?:[A-Za-z0-9_][A-Za-z0-9_-]*+|{_REDACTED_PLACEHOLDER_PAT})="
)
_KV_SEMI_STOP_RE = re.compile(
    rf"[ \t\r\n}}\]]|$|(?:[A-Za-z0-9_][A-Za-z0-9_-]*+|{_REDACTED_PLACEHOLDER_PAT})="
)
_COMMA_SEP_RE = re.compile(r"[ \t]*+,[ \t]*+")
_AUTH_KV_QUOTED_RE = re.compile(r"([A-Za-z0-9_-]++[ \t]*+=[ \t]*+)(\\*+)([\"'])")
_AUTH_KV_PREFIX_RE = re.compile(r"([A-Za-z0-9_-]++)[ \t]*+([=:])")
_AUTH_MORE_PARAMS_KV_RE = re.compile(r"[ \t]*+,[ \t]*+([A-Za-z0-9_-]++)[ \t]*+=")
_AUTH_REDACTED_KV_RE = re.compile(rf"[A-Za-z0-9_-]++={_REDACTED_PLACEHOLDER_PAT}")
_QUOTE_SPECIAL_RE = re.compile(r"[\n\"'\\]")
_QUOTE_NO_NL_RE = re.compile(r"[\"'\\]")

# 3. Standalone Bearer / ApiToken schemes.
_BEARER_SCHEME_START_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:(token_type)[ \t]*+[:=][ \t]*+)?(Bearer|ApiToken)[ \t]++"
)
_BEARER_UNQUOTED_VAL_RE = re.compile(
    rf"(?:{_REDACTED_PLACEHOLDER_PAT}|[A-Za-z0-9._~+/=-])++"
)
_KV_SEP_AHEAD_RE = re.compile(r"[ \t]*+[=:]")
_SPACE_EQ_RE = re.compile(r"[ \t]*+=[ \t]*+")
_IDENT_FULL_RE = re.compile(r"[A-Za-z0-9_-]++")

# 4. JWTs (header.payload.signature or header.payload).
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{6,}+\.[A-Za-z0-9_-]{6,}+(?:\.[A-Za-z0-9_=-]{4,}+)?\b"
)

# 5. URL query parameters carrying credentials/signatures (key-first O(N) scan).
_URL_QUERY_KEY_RE = re.compile(
    r"([?&;])([A-Za-z0-9_][A-Za-z0-9_-]*+)=",
    re.IGNORECASE,
)
_URL_QUERY_SCAN_RE = re.compile(r"[?&#;\s\"'<>}\]),]")

# 6. Quoted JSON/Python-repr/escaped-JSON secret fields (start anchor; closing quote scanned).
_QUOTED_FIELD_START_RE = re.compile(
    r"(?i)(?<!\\)(\\*+)([\"'])([A-Za-z0-9_-]++)\1\2\s*+:\s*+(\\*+)([\"'])"
)

# 7. Unquoted key="quoted value" / key='quoted value' / key: "quoted value" assignments.
_QUOTED_ASSIGNMENT_START_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(-*+)([A-Za-z0-9_][A-Za-z0-9_-]*+)\s*+([:=])\s*+(\\*+)([\"'])"
)

# 8. Well-known vendor secret prefixes.
_VENDOR_PREFIX_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{10,}+|gh[pousr]_[A-Za-z0-9]{10,}+|"
    r"github_pat_[A-Za-z0-9_]{10,}+|"
    r"AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,}+)\b"
)


@lru_cache(maxsize=1024)
def _is_sensitive_key(key: str) -> bool:
    low = key.strip().lower()
    if not low or low in _NON_SECRET_METADATA_KEYS:
        return False
    if low in _SENSITIVE_KEY_EXACT:
        return True
    if low.endswith(("_token", "-token")):
        return True
    return bool(_SENSITIVE_KEY_RE.search(low))


def _is_sensitive_url_param(key: str) -> bool:
    low = key.strip().lower()
    if not low or low in _NON_SECRET_METADATA_KEYS:
        return False
    return _is_sensitive_key(low) or low in _URL_QUERY_EXTRA_KEYS


def _closing_quote_step(backslash_count: int) -> int:
    if (backslash_count & (backslash_count + 1)) == 0:
        return 2 * (backslash_count + 1)
    if backslash_count % 2 == 0:
        return 2
    return 0


def _is_valid_json_after_comma(text: str, comma_pos: int) -> bool:
    n = len(text)
    k = comma_pos + 1
    while k < n and text[k] in (" ", "\t", "\r", "\n"):
        k += 1
    if k >= n:
        return True
    ch = text[k]
    if ch in ('"', "'", "\\", "{", "[", "}", "]"):
        return True
    end = -1
    if ch == "-" or ("0" <= ch <= "9"):
        j = k + 1
        while j < n and ("0" <= text[j] <= "9" or text[j] in (".", "-", "+", "e", "E")):
            j += 1
        if j > k + 1 or ch != "-":
            end = j
    elif text.startswith("true", k):
        end = k + 4
    elif text.startswith("false", k):
        end = k + 5
    elif text.startswith("null", k):
        end = k + 4
    if end == -1:
        return False
    while end < n and text[end] in (" ", "\t", "\r", "\n"):
        end += 1
    return end >= n or text[end] in (",", "]", "}")


def _bs2_gt2_matches(text: str, quote_pos: int, *, json_field: bool) -> bool:
    n = len(text)
    after_pos = quote_pos + 1
    if json_field:
        k = after_pos
        while k < n and text[k] in (" ", "\t"):
            k += 1
        if k >= n:
            return True
        if text[k] in "}]\r\n":
            return True
        if text[k] == ",":
            return _is_valid_json_after_comma(text, k)
        return False
    return after_pos >= n or text[after_pos] in " \t\r\n,};])"


def _is_json_val_opener(text: str, quote_start: int) -> bool:
    j = quote_start - 1
    while j >= 0 and text[j] in (" ", "\t", "\r", "\n"):
        j -= 1
    if j < 0:
        return False
    ch = text[j]
    if ch == "[":
        return True
    if ch == ":":
        j -= 1
        while j >= 0 and text[j] in (" ", "\t", "\r", "\n"):
            j -= 1
        return j >= 0 and text[j] in ('"', "'")
    if ch == ",":
        j -= 1
        while j >= 0 and text[j] in (" ", "\t", "\r", "\n"):
            j -= 1
        if j < 0:
            return False
        prev = text[j]
        if prev in ('"', "'", "]", "}"):
            return True
        tok_start: int | None = None
        if "0" <= prev <= "9":
            k = j - 1
            while k >= 0 and (
                "0" <= text[k] <= "9" or text[k] in (".", "-", "+", "e", "E")
            ):
                k -= 1
            if k < 0 or not (text[k].isalnum() or text[k] == "_"):
                tok_start = k
        elif prev == "e":
            if j >= 3 and text[j - 3 : j + 1] == "true" and (
                j == 3 or not (text[j - 4].isalnum() or text[j - 4] == "_")
            ):
                tok_start = j - 4
            elif j >= 4 and text[j - 4 : j + 1] == "false" and (
                j == 4 or not (text[j - 5].isalnum() or text[j - 5] == "_")
            ):
                tok_start = j - 5
        elif prev == "l" and j >= 3 and text[j - 3 : j + 1] == "null" and (
            j == 3 or not (text[j - 4].isalnum() or text[j - 4] == "_")
        ):
            tok_start = j - 4
        if tok_start is None:
            return False
        while tok_start >= 0 and text[tok_start] in (" ", "\t", "\r", "\n"):
            tok_start -= 1
        return tok_start >= 0 and text[tok_start] in (":", "[", ",")
    return False


def _is_valid_multiline_close(
    text: str,
    cand_idx: int,
    close_after: int,
    line_start: int,
    *,
    json_field: bool,
) -> bool:
    n = len(text)
    j = cand_idx - 1
    while j >= line_start and text[j] in (" ", "\t"):
        j -= 1
    if j >= line_start and text[j] in ("=", ":"):
        return False

    if json_field:
        k = close_after
        while k < n and text[k] in (" ", "\t"):
            k += 1
        return k >= n or text[k] in ",}]\r\n"

    return close_after >= n or text[close_after] in " \t\r\n,;})]"


def _build_pem_end_index(text: str) -> tuple[dict[str, list[int]], list[int]]:
    end_index: dict[str, list[int]] = {}
    pos = 0
    while (end_idx := text.find("-----END ", pos)) != -1:
        label_start = end_idx + 9
        header_end = text.find("-----", label_start)
        if header_end == -1:
            break
        label = text[label_start:header_end]
        if "\n" in label or "\r" in label:
            pos = end_idx + 9
            continue
        end_index.setdefault(label, []).append(end_idx)
        pos = header_end + 5

    begin_positions: list[int] = []
    if end_index:
        pos = 0
        while (begin_idx := text.find("-----BEGIN ", pos)) != -1:
            begin_positions.append(begin_idx)
            pos = begin_idx + 11
    return end_index, begin_positions


def _extract_pem_header(
    text: str, start: int, first_nl: int, n: int
) -> tuple[bool, str | None, int]:
    line1 = text[start:first_nl]
    begin_rel = line1.find("-----BEGIN ")
    if begin_rel != -1:
        begin_abs = start + begin_rel
    elif not line1.strip(" \t\r"):
        j = first_nl + 1
        while j < n and text[j] in (" ", "\t", "\r", "\n"):
            j += 1
        if text.startswith("-----BEGIN ", j):
            begin_abs = j
        else:
            return False, None, start
    else:
        return False, None, start

    label_start = begin_abs + 11
    header_end = text.find("-----", label_start)
    if (
        header_end == -1
        or "\n" in text[label_start:header_end]
        or "\r" in text[label_start:header_end]
    ):
        return True, None, label_start
    return True, text[label_start:header_end], header_end + 5


def _find_closing_quote_ex(
    text: str,
    start: int,
    backslash_count: int,
    quote_char: str,
    *,
    json_field: bool,
    pem_index: tuple[dict[str, list[int]], list[int]] | None = None,
    max_end: int | None = None,
) -> tuple[int | None, int]:
    """Return ``(close_idx, unclosed_end)`` for a quoted value starting at ``start``."""
    n = len(text)
    scan_end = n if max_end is None else min(n, max_end)
    if start >= scan_end:
        return None, scan_end
    step = _closing_quote_step(backslash_count)
    fast_i = start
    first_nl: int | None = None
    if backslash_count == 0:
        while fast_i < scan_end:
            q_pos = text.find(quote_char, fast_i, scan_end)
            bs_limit = q_pos if q_pos != -1 else scan_end
            bs_pos = text.find("\\", fast_i, bs_limit)
            seg_end = bs_pos if bs_pos != -1 else bs_limit
            nl_pos = text.find("\n", fast_i, seg_end)
            if nl_pos != -1:
                first_nl = nl_pos
                break
            if bs_pos != -1:
                if bs_pos + 1 >= scan_end:
                    return None, scan_end
                if text[bs_pos + 1] == "\n":
                    first_nl = bs_pos + 1
                    break
                fast_i = bs_pos + 2
                continue
            if q_pos != -1:
                return q_pos, q_pos
            return None, scan_end
        else:
            return None, scan_end
    else:
        while fast_i < scan_end:
            bs_pos = text.find("\\", fast_i, scan_end)
            seg_end = bs_pos if bs_pos != -1 else scan_end
            nl_pos = text.find("\n", fast_i, seg_end)
            if nl_pos != -1:
                first_nl = nl_pos
                break
            if bs_pos == -1:
                return None, scan_end
            bs = 1
            while bs_pos + bs < n and text[bs_pos + bs] == "\\":
                bs += 1
            if bs_pos + bs < n and text[bs_pos + bs] == quote_char:
                is_match = False
                if step and bs >= backslash_count and (bs - backslash_count) % step == 0:
                    if backslash_count == 2 and bs > 2 and (bs - 2) % 4 == 0:
                        is_match = _bs2_gt2_matches(text, bs_pos + bs, json_field=json_field)
                    else:
                        is_match = True
                elif not step and bs == backslash_count:
                    is_match = True
                if is_match:
                    cand_idx = bs_pos + bs - backslash_count
                    if cand_idx >= scan_end:
                        return None, scan_end
                    return cand_idx, cand_idx
                fast_i = bs_pos + bs + 1
                continue
            fast_i = bs_pos + bs
        else:
            return None, scan_end

    line1_end = scan_end if first_nl is None else first_nl

    is_pem = False
    end_marker = -1
    if first_nl is not None:
        is_pem, pem_label, search_from = _extract_pem_header(text, start, first_nl, n)
        if not is_pem and _is_redacted_placeholder(text[start:first_nl].rstrip("\r")):
            return None, first_nl
        if is_pem and pem_label is not None:
            if pem_index is not None:
                end_map, begin_positions = pem_index
                positions = end_map.get(pem_label)
                if positions:
                    pos_i = bisect.bisect_left(positions, search_from)
                    if pos_i < len(positions):
                        cand_end = positions[pos_i]
                        b_i = bisect.bisect_left(begin_positions, search_from)
                        if b_i < len(begin_positions) and begin_positions[b_i] < cand_end:
                            end_marker = -1
                        else:
                            end_marker = cand_end
            else:
                cand_end = text.find(f"-----END {pem_label}-----", search_from)
                if cand_end != -1:
                    next_begin = text.find("-----BEGIN ", search_from, cand_end)
                    end_marker = -1 if next_begin != -1 else cand_end

    i = start
    line_start = start
    limit = line1_end
    in_multiline = False

    while True:
        while i < limit:
            if backslash_count == 0:
                q_pos = text.find(quote_char, i, limit)
                bs_limit = q_pos if q_pos != -1 else limit
                bs_pos = text.find("\\", i, bs_limit)
                if q_pos == -1 and bs_pos == -1:
                    i = limit
                    break
                if bs_pos != -1:
                    if bs_pos + 1 >= scan_end:
                        i = scan_end
                        break
                    if not in_multiline and bs_pos + 1 == line1_end:
                        i = bs_pos + 2
                        break
                    i = bs_pos + 2
                    continue
                cand_idx = q_pos
                if in_multiline:
                    nl_before = text.rfind("\n", line_start, cand_idx)
                    if nl_before != -1:
                        line_start = nl_before + 1
                close_after = cand_idx + 1
                if in_multiline:
                    if is_pem:
                        if end_marker != -1:
                            if cand_idx >= end_marker:
                                return cand_idx, cand_idx
                            i = cand_idx + 1
                            continue
                        if not _is_valid_multiline_close(
                            text, cand_idx, close_after, line_start, json_field=json_field
                        ):
                            unclosed = (
                                max(start, line_start - 1) if line_start > start else first_nl
                            )
                            return None, unclosed if unclosed is not None else scan_end
                        return cand_idx, cand_idx
                    if _is_valid_multiline_close(
                        text, cand_idx, close_after, line_start, json_field=json_field
                    ):
                        return cand_idx, cand_idx
                    return None, first_nl if first_nl is not None else scan_end
                return cand_idx, cand_idx

            bs_pos = text.find("\\", i, limit)
            if bs_pos == -1:
                i = limit
                break
            if in_multiline:
                nl_before = text.rfind("\n", line_start, bs_pos)
                if nl_before != -1:
                    line_start = nl_before + 1
            i = bs_pos
            bs = 0
            while i + bs < n and text[i + bs] == "\\":
                bs += 1
            if i + bs < n and text[i + bs] == quote_char:
                is_match = False
                if step and bs >= backslash_count and (bs - backslash_count) % step == 0:
                    if backslash_count == 2 and bs > 2 and (bs - 2) % 4 == 0:
                        is_match = _bs2_gt2_matches(text, i + bs, json_field=json_field)
                    else:
                        is_match = True
                elif not step and bs == backslash_count:
                    is_match = True

                if is_match:
                    cand_idx = i + bs - backslash_count
                    if cand_idx >= scan_end:
                        return None, first_nl if (first_nl is not None and not is_pem) else scan_end
                    close_after = i + bs + 1
                    if in_multiline:
                        if is_pem:
                            if end_marker != -1:
                                if cand_idx >= end_marker:
                                    return cand_idx, cand_idx
                                i += bs + 1
                                continue
                            if not _is_valid_multiline_close(
                                text, cand_idx, close_after, line_start, json_field=json_field
                            ):
                                unclosed = (
                                    max(start, line_start - 1)
                                    if line_start > start
                                    else first_nl
                                )
                                return None, unclosed if unclosed is not None else scan_end
                            return cand_idx, cand_idx
                        if _is_valid_multiline_close(
                            text, cand_idx, close_after, line_start, json_field=json_field
                        ):
                            return cand_idx, cand_idx
                        return None, first_nl if first_nl is not None else scan_end
                    return cand_idx, cand_idx
                i += bs + 1
                continue
            i += bs
            continue

        if in_multiline or first_nl is None:
            break
        in_multiline = True
        if i <= first_nl:
            i = first_nl + 1
        line_start = first_nl + 1
        limit = scan_end

    if first_nl is None or is_pem:
        return None, scan_end
    return None, first_nl


def _find_closing_quote(
    text: str, start: int, backslash_count: int, quote_char: str
) -> int | None:
    """Return the index where the matching closing quote delimiter begins, or ``None``."""
    close_idx, _ = _find_closing_quote_ex(
        text, start, backslash_count, quote_char, json_field=False
    )
    return close_idx


def _redact_quoted_fields(text: str) -> str:
    parts: list[str] = []
    pos = 0
    pem_index: tuple[dict[str, list[int]], list[int]] | None = None
    while (match := _QUOTED_FIELD_START_RE.search(text, pos)) is not None:
        key = match.group(3)
        if not _is_sensitive_key(key):
            parts.append(text[pos : match.end()])
            pos = match.end()
            continue

        if pem_index is None:
            pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])

        q2_backslashes = match.group(4)
        q2_char = match.group(5)
        close_idx, unclosed_end = _find_closing_quote_ex(
            text,
            match.end(),
            len(q2_backslashes),
            q2_char,
            json_field=True,
            pem_index=pem_index,
        )
        q1 = f"{match.group(1)}{match.group(2)}"
        q2 = f"{q2_backslashes}{q2_char}"

        if close_idx is None:
            end_idx = max(match.end(), unclosed_end)
            if (
                end_idx > match.end()
                and end_idx < len(text)
                and text[end_idx] == "\n"
                and text[end_idx - 1] == "\r"
            ):
                end_idx -= 1
            val = text[match.end() : end_idx]
            if not val or _is_redacted_placeholder(val):
                parts.append(text[pos:end_idx])
                pos = end_idx
                continue
            parts.append(text[pos : match.start()])
            parts.append(f"{q1}{key}{q1}: {q2}<REDACTED>")
            pos = end_idx
            continue

        close_end = close_idx + len(q2_backslashes) + 1
        val = text[match.end() : close_idx]
        if not val or _is_redacted_placeholder(val):
            parts.append(text[pos:close_end])
            pos = close_end
            continue

        parts.append(text[pos : match.start()])
        parts.append(f"{q1}{key}{q1}: {q2}<REDACTED>{q2}")
        pos = close_end

    if pos == 0:
        return text
    parts.append(text[pos:])
    return "".join(parts)


def _redact_quoted_assignments(text: str) -> str:
    parts: list[str] = []
    pos = 0
    pem_index: tuple[dict[str, list[int]], list[int]] | None = None
    while (match := _QUOTED_ASSIGNMENT_START_RE.search(text, pos)) is not None:
        cli_prefix = match.group(1)
        key = match.group(2)
        if not _is_sensitive_key(key):
            parts.append(text[pos : match.end()])
            pos = match.end()
            continue

        if pem_index is None:
            pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])

        sep = match.group(3)
        sep_out = ": " if sep == ":" else "="
        q_backslashes = match.group(4)
        q_char = match.group(5)
        q = f"{q_backslashes}{q_char}"
        close_idx, unclosed_end = _find_closing_quote_ex(
            text,
            match.end(),
            len(q_backslashes),
            q_char,
            json_field=False,
            pem_index=pem_index,
        )

        if close_idx is None:
            end_idx = max(match.end(), unclosed_end)
            if (
                end_idx > match.end()
                and end_idx < len(text)
                and text[end_idx] == "\n"
                and text[end_idx - 1] == "\r"
            ):
                end_idx -= 1
            val = text[match.end() : end_idx]
            if not val or _is_redacted_placeholder(val):
                parts.append(text[pos:end_idx])
                pos = end_idx
                continue
            parts.append(text[pos : match.start()])
            parts.append(f"{cli_prefix}{key}{sep_out}{q}<REDACTED>")
            pos = end_idx
            continue

        close_end = close_idx + len(q_backslashes) + 1
        val = text[match.end() : close_idx]
        if not val or _is_redacted_placeholder(val):
            parts.append(text[pos:close_end])
            pos = close_end
            continue

        parts.append(text[pos : match.start()])
        parts.append(f"{cli_prefix}{key}{sep_out}{q}<REDACTED>{q}")
        pos = close_end

    if pos == 0:
        return text
    parts.append(text[pos:])
    return "".join(parts)


def _redact_pem_blocks(text: str) -> str:
    if "-----BEGIN " not in text:
        return text
    parts: list[str] = []
    pos = 0
    n = len(text)
    while (begin_idx := text.find("-----BEGIN ", pos)) != -1:
        header_end = text.find("-----", begin_idx + 11)
        if header_end == -1 or "\n" in text[begin_idx + 11 : header_end]:
            parts.append(text[pos : begin_idx + 11])
            pos = begin_idx + 11
            continue
        label = text[begin_idx + 11 : header_end]
        if "PRIVATE KEY" not in label.upper():
            parts.append(text[pos : header_end + 5])
            pos = header_end + 5
            continue
        end_marker = f"-----END {label}-----"
        end_idx = text.find(end_marker, header_end + 5)
        close_pos = end_idx + len(end_marker) if end_idx != -1 else n
        parts.append(text[pos:begin_idx])
        parts.append("<REDACTED>")
        pos = close_pos
    if pos == 0:
        return text
    parts.append(text[pos:])
    return "".join(parts)


def _scan_url_query_value_end(text: str, start: int) -> int | None:
    """Monotonic O(N) scan for an unquoted URL query value ending."""
    n = len(text)
    cur = start
    angle_depth = 0
    while cur < n:
        m = _URL_QUERY_SCAN_RE.search(text, cur)
        if m is None:
            end = n
            break
        pos_ch = m.start()
        ch = text[pos_ch]
        if ch == "\\":
            bs_m = _BS_RUN_RE.match(text, pos_ch)
            bs_end = bs_m.end() if bs_m is not None else pos_ch + 1
            if bs_end < n and text[bs_end] in ('"', "'"):
                end = pos_ch
                break
            cur = bs_end
            continue
        if ch == "<":
            ph_m = _REDACTED_PLACEHOLDER_RE.match(text, pos_ch)
            if ph_m is not None:
                cur = ph_m.end()
                continue
            if _CLOSING_TAG_RE.match(text, pos_ch) is not None:
                end = pos_ch
                break
            angle_depth += 1
            cur = pos_ch + 1
            continue
        if ch == ">":
            if angle_depth > 0:
                angle_depth -= 1
                cur = pos_ch + 1
                continue
            end = pos_ch
            break
        end = pos_ch
        break
    else:
        end = n
    return end if end > start else None


def _scan_kv_value_end(text: str, start: int, *, multi_param: bool = False) -> int | None:
    """Monotonic O(N) scan for an unquoted header/KV value ending."""
    n = len(text)
    cur = start
    angle_depth = 0
    while cur < n:
        m = _KV_STOP_SCAN_RE.search(text, cur)
        if m is None:
            end = n
            break
        pos_ch = m.start()
        ch = text[pos_ch]
        if ch == "&":
            if _KV_NEXT_KEY_RE.match(text, pos_ch + 1) is not None:
                end = pos_ch
                break
            cur = pos_ch + 1
            continue
        if ch == ";":
            if not multi_param or _KV_SEMI_STOP_RE.match(text, pos_ch + 1) is not None:
                end = pos_ch
                break
            cur = pos_ch + 1
            continue
        if ch == "\\":
            bs_m = _BS_RUN_RE.match(text, pos_ch)
            bs_end = bs_m.end() if bs_m is not None else pos_ch + 1
            if bs_end < n and text[bs_end] in ('"', "'"):
                end = pos_ch
                break
            cur = bs_end
            continue
        if ch == "<":
            ph_m = _REDACTED_PLACEHOLDER_RE.match(text, pos_ch)
            if ph_m is not None:
                cur = ph_m.end()
                continue
            if _CLOSING_TAG_RE.match(text, pos_ch) is not None:
                end = pos_ch
                break
            angle_depth += 1
            cur = pos_ch + 1
            continue
        if ch == ">":
            if angle_depth > 0:
                angle_depth -= 1
                cur = pos_ch + 1
                continue
            if pos_ch + 1 >= n or text[pos_ch + 1] in " \t\r\n,;\"'})]&<":
                end = pos_ch
                break
            cur = pos_ch + 1
            continue
        if ch in ("]", ")"):
            if (
                pos_ch - start <= 20
                and _is_redacted_placeholder(text[start:pos_ch])
                and (pos_ch + 1 >= n or text[pos_ch + 1] in " \t\r\n,;\"'})]&<")
            ):
                end = pos_ch
                break
            cur = pos_ch + 1
            continue
        end = pos_ch
        break
    else:
        end = n
    return end if end > start else None


def _redact_url_query_secrets(text: str) -> str:
    parts: list[str] = []
    pos = 0
    n = len(text)
    pem_index: tuple[dict[str, list[int]], list[int]] | None = None
    quote_tracker: _LineQuoteTracker | None = None
    while (match := _URL_QUERY_KEY_RE.search(text, pos)) is not None:
        param = match.group(2)
        if not _is_sensitive_url_param(param):
            parts.append(text[pos : match.end()])
            pos = match.end()
            continue
        val_start = match.end()
        if (q_m := _QUOTED_START_RE.match(text, val_start)) is not None:
            if quote_tracker is None:
                quote_tracker = _LineQuoteTracker(text)
            q_snap = quote_tracker.snapshot()
            quote_tracker.advance_to(match.start())
            encl = quote_tracker.innermost_open_ex()
            q_bs = q_m.group(1)
            q_ch = q_m.group(2)
            quote_tracker.advance_to(q_m.start())
            if quote_tracker.is_closing_quote(len(q_bs), q_ch, q_m.start()):
                parts.append(text[pos:val_start])
                pos = val_start
                continue
            if pem_index is None:
                pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])
            q = f"{q_bs}{q_ch}"
            close_idx, unclosed_end = _find_closing_quote_ex(
                text, q_m.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
            )
            if close_idx is None:
                end_idx = max(q_m.end(), unclosed_end)
                encl_end, pem_index = _resolve_encl_end(
                    text, val_start, end_idx, encl, pem_index
                )
                if encl_end < end_idx:
                    end_idx = encl_end
                    quote_tracker.restore(q_snap)
                    quote_tracker.advance_to(end_idx)
                if (
                    end_idx > q_m.end()
                    and end_idx < n
                    and text[end_idx] == "\n"
                    and text[end_idx - 1] == "\r"
                ):
                    end_idx -= 1
                val = text[q_m.end() : end_idx]
                if not val or _is_redacted_placeholder(val):
                    parts.append(text[pos:end_idx])
                    pos = end_idx
                    continue
                parts.append(text[pos : match.start()])
                parts.append(f"{match.group(1)}{param}={q}<REDACTED>")
                pos = end_idx
                continue
            close_end = close_idx + len(q_bs) + 1
            encl_end, pem_index = _resolve_encl_end(
                text, val_start, close_end, encl, pem_index
            )
            if encl_end < close_end:
                end_idx = encl_end
                if (
                    end_idx > q_m.end()
                    and end_idx < n
                    and text[end_idx] == "\n"
                    and text[end_idx - 1] == "\r"
                ):
                    end_idx -= 1
                quote_tracker.restore(q_snap)
                quote_tracker.advance_to(end_idx)
                val = text[q_m.end() : end_idx]
                if not val or _is_redacted_placeholder(val):
                    parts.append(text[pos:end_idx])
                    pos = end_idx
                    continue
                parts.append(text[pos : match.start()])
                parts.append(f"{match.group(1)}{param}={q}<REDACTED>")
                pos = end_idx
                continue
            val = text[q_m.end() : close_idx]
            if not val or _is_redacted_placeholder(val):
                parts.append(text[pos:close_end])
                pos = close_end
                continue
            parts.append(text[pos : match.start()])
            parts.append(f"{match.group(1)}{param}={q}<REDACTED>{q}")
            pos = close_end
            continue

        val_end = _scan_url_query_value_end(text, val_start)
        if val_end is None:
            parts.append(text[pos:val_start])
            pos = val_start
            continue
        val = text[val_start:val_end]
        if _is_redacted_placeholder(val):
            parts.append(text[pos:val_end])
            pos = val_end
            continue
        parts.append(text[pos : match.start()])
        parts.append(f"{match.group(1)}{param}=<REDACTED>")
        pos = val_end
    if pos == 0:
        return text
    parts.append(text[pos:])
    return "".join(parts)


def _quote_matches(s_bs: int, bs: int) -> bool:
    if bs < s_bs:
        return False
    step = _closing_quote_step(s_bs)
    if step == 0:
        return bs == s_bs
    return (bs - s_bs) % step == 0


class _LineQuoteTracker:
    """Monotonic O(N) per-line quote-parity tracker for distinguishing closing quotes."""

    __slots__ = ("_text", "_n", "_cursor", "_stack")

    def __init__(self, text: str) -> None:
        self._text = text
        self._n = len(text)
        self._cursor = 0
        self._stack: list[tuple[str, int, bool]] = []

    def snapshot(self) -> tuple[int, list[tuple[str, int, bool]]]:
        return (self._cursor, self._stack.copy())

    def restore(self, snap: tuple[int, list[tuple[str, int, bool]]]) -> None:
        self._cursor, saved_stack = snap
        self._stack = saved_stack.copy()

    def _toggle(self, ch: str, bs: int, quote_pos: int) -> None:
        stack = self._stack
        for idx in range(len(stack) - 1, -1, -1):
            s_ch, s_bs, s_json = stack[idx]
            if s_ch == ch and _quote_matches(s_bs, bs):
                if s_bs == 2 and bs > 2 and (bs - 2) % 4 == 0:
                    if not _bs2_gt2_matches(self._text, quote_pos, json_field=s_json):
                        return
                del stack[idx:]
                return
        if (
            bs == 0
            and ch == "'"
            and quote_pos > 0
            and quote_pos + 1 < self._n
            and self._text[quote_pos - 1].isalnum()
            and self._text[quote_pos + 1].isalnum()
        ):
            return
        is_json = bs == 2 and _is_json_val_opener(self._text, quote_pos - bs)
        stack.append((ch, bs, is_json))

    def advance_to(self, target: int) -> None:
        text = self._text
        n = min(target, self._n)
        i = self._cursor
        stack = self._stack
        search_with_nl = _QUOTE_SPECIAL_RE.search
        search_no_nl = _QUOTE_NO_NL_RE.search
        while i < n:
            m = search_with_nl(text, i, n) if stack else search_no_nl(text, i, n)
            if m is None:
                i = n
                break
            pos = m.start()
            ch = text[pos]
            if ch == "\n":
                stack.clear()
                i = pos + 1
                continue
            if ch == "\\":
                bs = 1
                while pos + bs < self._n and text[pos + bs] == "\\":
                    bs += 1
                if pos + bs >= n:
                    i = self._n if pos + bs >= self._n else pos
                    break
                nxt = text[pos + bs]
                if nxt in ("'", '"'):
                    self._toggle(nxt, bs, pos + bs)
                    i = pos + bs + 1
                    continue
                i = pos + bs
                continue
            self._toggle(ch, 0, pos)
            i = pos + 1
        self._cursor = i

    def is_closing_quote(self, bs: int, ch: str, _quote_start: int | None = None) -> bool:
        quote_pos = (_quote_start + bs) if _quote_start is not None else -1
        for s_ch, s_bs, s_json in reversed(self._stack):
            if s_ch == ch and _quote_matches(s_bs, bs):
                if s_bs == 2 and bs > 2 and (bs - 2) % 4 == 0 and quote_pos >= 0:
                    return _bs2_gt2_matches(self._text, quote_pos, json_field=s_json)
                return True
        return False

    def innermost_open(self) -> tuple[str, int] | None:
        if not self._stack:
            return None
        ch, bs, _ = self._stack[-1]
        return (ch, bs)

    def innermost_open_ex(self) -> tuple[str, int, bool] | None:
        if not self._stack:
            return None
        return self._stack[-1]


@lru_cache(maxsize=1024)
def _is_non_auth_separator_key(key_low: str) -> bool:
    return (
        key_low in _NON_AUTH_LOG_KEYS
        or key_low in _NON_SECRET_METADATA_KEYS
        or _is_sensitive_key(key_low)
    )


@lru_cache(maxsize=1024)
def _is_non_auth_space_separator_key(key_low: str) -> bool:
    return _is_non_auth_separator_key(key_low) or key_low in _NON_AUTH_SPACE_LOG_KEYS


@lru_cache(maxsize=1024)
def _is_auth_param_key(key_low: str) -> bool:
    if (
        key_low in _NON_AUTH_LOG_KEYS
        or key_low in _NON_SECRET_METADATA_KEYS
        or _is_sensitive_key(key_low)
    ):
        return False
    if key_low in _HTTP_AUTH_PARAM_KEYS:
        return True
    if key_low.startswith(("auth_", "auth-")):
        return True
    return key_low.endswith(
        (
            "_sig",
            "-sig",
            "_mac",
            "-mac",
            "_key",
            "-key",
            "_auth",
            "-auth",
            "_nonce",
            "-nonce",
            "_signature",
            "-signature",
        )
    )


def _has_comma_auth_param(
    text: str,
    first_kv_key: str,
    after_kv: int,
    *,
    quote_tracker: _LineQuoteTracker,
    pem_index: tuple[dict[str, list[int]], list[int]],
    allow_oauth_params: bool = False,
) -> bool:
    n = len(text)
    has_auth_param = _is_auth_param_key(first_kv_key) or (
        allow_oauth_params and first_kv_key.startswith("oauth_")
    )
    cur = after_kv
    snap = quote_tracker.snapshot()
    try:
        for step_idx in range(32):
            while cur < n and text[cur] in (" ", "\t"):
                cur += 1
            if cur >= n or text[cur] in "\r\n}];":
                return False
            q_chk = _QUOTED_START_RE.match(text, cur)
            if q_chk is not None:
                q_bs = q_chk.group(1)
                q_ch = q_chk.group(2)
                quote_tracker.advance_to(q_chk.start())
                if quote_tracker.is_closing_quote(len(q_bs), q_ch, q_chk.start()):
                    return False
                close_idx, _ = _find_closing_quote_ex(
                    text, q_chk.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
                )
                if close_idx is None:
                    return False
                val_end = close_idx + len(q_bs) + 1
            else:
                sv_end = _scan_kv_value_end(text, cur, multi_param=True)
                if sv_end is None:
                    return False
                val_end = sv_end
            if step_idx > 0 and has_auth_param:
                return True
            more_m = _AUTH_MORE_PARAMS_KV_RE.match(text, val_end)
            if more_m is None:
                if (comma_m := _COMMA_SEP_RE.match(text, val_end)) is not None:
                    cur = comma_m.end()
                    continue
                return step_idx > 0 and has_auth_param
            next_k = more_m.group(1).lower()
            is_oauth_k = allow_oauth_params and next_k.startswith("oauth_")
            if _is_sensitive_key(next_k) and not is_oauth_k and not has_auth_param:
                return False
            if is_oauth_k or _is_auth_param_key(next_k):
                has_auth_param = True
            cur = more_m.end()
        return has_auth_param
    finally:
        quote_tracker.restore(snap)


def _has_space_auth_params(
    text: str,
    first_kv_key: str,
    after_kv: int,
    *,
    quote_tracker: _LineQuoteTracker,
    pem_index: tuple[dict[str, list[int]], list[int]],
) -> bool:
    if _is_non_auth_space_separator_key(first_kv_key):
        return False
    n = len(text)
    snap = quote_tracker.snapshot()
    try:
        while after_kv < n and text[after_kv] in (" ", "\t"):
            after_kv += 1
        if after_kv >= n or text[after_kv] in "\r\n}];":
            return False
        q_chk = _QUOTED_START_RE.match(text, after_kv)
        if q_chk is not None:
            q_bs = q_chk.group(1)
            q_ch = q_chk.group(2)
            quote_tracker.advance_to(q_chk.start())
            if quote_tracker.is_closing_quote(len(q_bs), q_ch, q_chk.start()):
                return False
            close_idx, _ = _find_closing_quote_ex(
                text, q_chk.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
            )
            if close_idx is None:
                return False
            val_end = close_idx + len(q_bs) + 1
        else:
            sv_end = _scan_kv_value_end(text, after_kv, multi_param=False)
            if sv_end is None:
                return False
            val_end = sv_end

        cur = val_end
        ws_start = cur
        while cur < n and text[cur] in (" ", "\t"):
            cur += 1
        if cur == ws_start or cur >= n or text[cur] in "\r\n}];,":
            return False
        kv2 = _AUTH_KV_PREFIX_RE.match(text, cur)
        if kv2 is None or kv2.group(2) == ":":
            return False
        next_k = kv2.group(1).lower()
        if _is_non_auth_space_separator_key(next_k) or _is_sensitive_key(next_k):
            return False
        return True
    finally:
        quote_tracker.restore(snap)


def _has_multiparam_space_auth_ahead(
    text: str,
    after_kv: int,
    *,
    quote_tracker: _LineQuoteTracker | None,
    pem_index: tuple[dict[str, list[int]], list[int]] | None,
) -> int | None:
    n = len(text)
    cur = after_kv
    snap = quote_tracker.snapshot() if quote_tracker is not None else None
    try:
        for _ in range(32):
            while cur < n and text[cur] in (" ", "\t"):
                cur += 1
            if cur >= n or text[cur] in "\r\n}];":
                return None
            q_chk = _QUOTED_START_RE.match(text, cur)
            if q_chk is not None:
                q_bs = q_chk.group(1)
                q_ch = q_chk.group(2)
                if quote_tracker is not None:
                    quote_tracker.advance_to(q_chk.start())
                    if quote_tracker.is_closing_quote(len(q_bs), q_ch, q_chk.start()):
                        return None
                if pem_index is None:
                    pem_index = (
                        _build_pem_end_index(text) if "-----END " in text else ({}, [])
                    )
                close_idx, _ = _find_closing_quote_ex(
                    text, q_chk.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
                )
                if close_idx is None:
                    return None
                val_end = close_idx + len(q_bs) + 1
            else:
                mv_end = _scan_kv_value_end(text, cur, multi_param=True)
                if mv_end is None:
                    return None
                val_end = mv_end

            cur = val_end
            ws_start = cur
            while cur < n and text[cur] in (" ", "\t"):
                cur += 1
            if cur >= n or text[cur] in "\r\n}];":
                return None
            has_comma = False
            if text[cur] == ",":
                has_comma = True
                cur += 1
                while cur < n and text[cur] in (" ", "\t"):
                    cur += 1
                if cur >= n or text[cur] in "\r\n}];":
                    return None
            elif cur == ws_start:
                return None

            next_kv = _AUTH_KV_PREFIX_RE.match(text, cur)
            if next_kv is None or next_kv.group(2) == ":":
                return None
            next_k = next_kv.group(1).lower()
            if next_k in _UNAMBIGUOUS_HTTP_AUTH_PARAM_KEYS:
                return next_kv.start()
            if next_k in _NON_SECRET_METADATA_KEYS or _is_sensitive_key(next_k):
                return None
            if not has_comma:
                if next_k in _NON_AUTH_LOG_KEYS:
                    return None
                if (
                    next_k in _NON_AUTH_SPACE_LOG_KEYS
                    and next_k not in _MULTIPARAM_SPACE_OPTIONAL_AUTH_KEYS
                ):
                    return None
            cur = next_kv.end()
        return None
    finally:
        if quote_tracker is not None and snap is not None:
            quote_tracker.restore(snap)


def _scan_auth_more_params_end(
    text: str,
    first_end: int,
    *,
    allow_unquoted_space_token: bool,
    pem_index: tuple[dict[str, list[int]], list[int]] | None,
    quote_tracker: _LineQuoteTracker | None = None,
    multi_param: bool = False,
) -> int | None:
    n = len(text)
    last_end = first_end
    cur = first_end
    found_more = False
    confirmed_until = -1

    while cur < n:
        iter_snap = quote_tracker.snapshot() if quote_tracker is not None else None
        ws_start = cur
        while cur < n and text[cur] in (" ", "\t"):
            cur += 1
        if cur >= n or text[cur] in "\r\n}];":
            break

        has_comma = False
        if text[cur] == ",":
            has_comma = True
            cur += 1
            while cur < n and text[cur] in (" ", "\t"):
                cur += 1
            if cur >= n or text[cur] in "\r\n}];":
                break
        elif cur == ws_start:
            break

        kv_m = _AUTH_KV_PREFIX_RE.match(text, cur)
        if kv_m is not None:
            kv_key = kv_m.group(1).lower()
            kv_sep = kv_m.group(2)
            if kv_sep == ":":
                break
            if not has_comma and _is_non_auth_space_separator_key(kv_key):
                if not (multi_param and kv_key in _MULTIPARAM_SPACE_OPTIONAL_AUTH_KEYS):
                    break
                if cur >= confirmed_until:
                    conf_pos = _has_multiparam_space_auth_ahead(
                        text,
                        kv_m.end(),
                        quote_tracker=quote_tracker,
                        pem_index=pem_index,
                    )
                    if conf_pos is None:
                        break
                    confirmed_until = conf_pos
            if not multi_param and has_comma and kv_key in _NON_AUTH_LOG_KEYS:
                break
            after_kv = kv_m.end()
            while after_kv < n and text[after_kv] in (" ", "\t"):
                after_kv += 1
            if after_kv >= n or text[after_kv] in "\r\n}];":
                last_end = after_kv
                found_more = True
                cur = after_kv
                continue
            q_m = _QUOTED_START_RE.match(text, after_kv)
            if q_m is not None:
                q_bs = q_m.group(1)
                q_ch = q_m.group(2)
                is_close = False
                if quote_tracker is not None:
                    quote_tracker.advance_to(q_m.start())
                    is_close = quote_tracker.is_closing_quote(len(q_bs), q_ch, q_m.start())
                if not is_close:
                    if pem_index is None:
                        pem_index = (
                            _build_pem_end_index(text) if "-----END " in text else ({}, [])
                        )
                    close_idx, unclosed_end = _find_closing_quote_ex(
                        text, q_m.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
                    )
                    param_end = (
                        close_idx + len(q_bs) + 1
                        if close_idx is not None
                        else max(q_m.end(), unclosed_end)
                    )
                else:
                    if quote_tracker is not None and iter_snap is not None:
                        quote_tracker.restore(iter_snap)
                    break
            else:
                sv_end = _scan_kv_value_end(text, after_kv, multi_param=multi_param)
                param_end = sv_end if sv_end is not None else after_kv
            last_end = param_end
            found_more = True
            cur = param_end
            continue

        if not has_comma and not allow_unquoted_space_token:
            break

        q_m = _QUOTED_START_RE.match(text, cur)
        if q_m is not None:
            q_bs = q_m.group(1)
            q_ch = q_m.group(2)
            if quote_tracker is not None:
                quote_tracker.advance_to(q_m.start())
                if quote_tracker.is_closing_quote(len(q_bs), q_ch, q_m.start()):
                    if iter_snap is not None:
                        quote_tracker.restore(iter_snap)
                    break
            if pem_index is None:
                pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])
            close_idx, unclosed_end = _find_closing_quote_ex(
                text, q_m.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
            )
            param_end = (
                close_idx + len(q_bs) + 1
                if close_idx is not None
                else max(q_m.end(), unclosed_end)
            )
            last_end = param_end
            found_more = True
            cur = param_end
            continue

        sv_end = _scan_kv_value_end(text, cur, multi_param=multi_param)
        if sv_end is None:
            break
        last_end = sv_end
        found_more = True
        cur = sv_end

    return last_end if found_more else None


def _resolve_encl_end(
    text: str,
    start: int,
    end_pos: int,
    encl: tuple[str, int, bool] | None,
    pem_index: tuple[dict[str, list[int]], list[int]] | None,
) -> tuple[int, tuple[dict[str, list[int]], list[int]] | None]:
    if encl is not None and end_pos > start:
        encl_ch, encl_bs, encl_is_json = encl
        if pem_index is None:
            pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])
        encl_close_idx, _ = _find_closing_quote_ex(
            text,
            start,
            encl_bs,
            encl_ch,
            json_field=encl_is_json,
            pem_index=pem_index,
            max_end=end_pos,
        )
        if encl_close_idx is not None and encl_close_idx < end_pos:
            return encl_close_idx, pem_index
    return end_pos, pem_index


def _redact_header_kvs(text: str) -> str:
    parts: list[str] = []
    pos = 0
    n = len(text)
    pem_index: tuple[dict[str, list[int]], list[int]] | None = None
    quote_tracker = _LineQuoteTracker(text)
    while (match := _HEADER_KEY_SEP_RE.search(text, pos)) is not None:
        cli_prefix = match.group(1)
        key = match.group(2)
        if not _is_sensitive_key(key):
            parts.append(text[pos : match.end()])
            pos = match.end()
            continue

        val_start = match.end()
        if val_start >= n or text[val_start] in "\r\n":
            parts.append(text[pos:val_start])
            pos = val_start
            continue

        q_m = _QUOTED_START_RE.match(text, val_start)
        if q_m is not None:
            q_bs = q_m.group(1)
            q_ch = q_m.group(2)
            quote_tracker.advance_to(q_m.start())
            if quote_tracker.is_closing_quote(len(q_bs), q_ch, q_m.start()):
                parts.append(text[pos:val_start])
                pos = val_start
                continue
            if pem_index is None:
                pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])
            close_idx, unclosed_end = _find_closing_quote_ex(
                text, q_m.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
            )
            skip_end = (
                close_idx + len(q_bs) + 1 if close_idx is not None else max(q_m.end(), unclosed_end)
            )
            parts.append(text[pos:skip_end])
            pos = skip_end
            continue

        sep = match.group(3)
        sep_out = ": " if sep == ":" else "="
        key_low = key.strip().lower()

        multi_m = _AUTH_MULTI_SCHEME_RE.match(text, val_start)
        if multi_m is not None:
            scheme_text = multi_m.group(0)
            after_scheme = multi_m.end()
            if after_scheme >= n or text[after_scheme] in "\r\n":
                parts.append(text[pos:after_scheme])
                pos = after_scheme
                continue
            quote_tracker.advance_to(match.start())
            encl = quote_tracker.innermost_open_ex()
            multi_snap = quote_tracker.snapshot()
            skip_multi = False
            q_m = _QUOTED_START_RE.match(text, after_scheme)
            if q_m is not None:
                quote_tracker.advance_to(q_m.start())
                if quote_tracker.is_closing_quote(len(q_m.group(1)), q_m.group(2), q_m.start()):
                    if key_low in _AUTH_HEADER_KEYS:
                        parts.append(text[pos:after_scheme])
                        pos = after_scheme
                        continue
                    quote_tracker.restore(multi_snap)
                    skip_multi = True
            if not skip_multi and key_low not in _AUTH_HEADER_KEYS:
                if (kv_p := _AUTH_KV_PREFIX_RE.match(text, after_scheme)) is not None:
                    kv_key = kv_p.group(1).lower()
                    if kv_p.group(2) == ":":
                        quote_tracker.restore(multi_snap)
                        skip_multi = True
                    elif (
                        kv_key not in _HTTP_AUTH_PARAM_KEYS
                        and _is_non_auth_space_separator_key(kv_key)
                    ):
                        if pem_index is None:
                            pem_index = (
                                _build_pem_end_index(text) if "-----END " in text else ({}, [])
                            )
                        if not _has_comma_auth_param(
                            text,
                            kv_key,
                            kv_p.end(),
                            quote_tracker=quote_tracker,
                            pem_index=pem_index,
                        ):
                            quote_tracker.restore(multi_snap)
                            skip_multi = True
            if not skip_multi:
                if q_m is not None:
                    if pem_index is None:
                        pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])
                    q_bs = q_m.group(1)
                    q_ch = q_m.group(2)
                    q = f"{q_bs}{q_ch}"
                    close_idx, unclosed_end = _find_closing_quote_ex(
                        text, q_m.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
                    )
                    if close_idx is not None:
                        close_end = close_idx + len(q_bs) + 1
                        more_end = _scan_auth_more_params_end(
                            text,
                            close_end,
                            allow_unquoted_space_token=True,
                            pem_index=pem_index,
                            quote_tracker=quote_tracker,
                            multi_param=True,
                        )
                        if more_end is None:
                            encl_end, pem_index = _resolve_encl_end(
                                text, after_scheme, close_end, encl, pem_index
                            )
                            if encl_end < close_end:
                                end_pos = encl_end
                                if (
                                    end_pos > q_m.end()
                                    and end_pos < n
                                    and text[end_pos] == "\n"
                                    and text[end_pos - 1] == "\r"
                                ):
                                    end_pos -= 1
                                quote_tracker.restore(multi_snap)
                                quote_tracker.advance_to(end_pos)
                                val = text[q_m.end() : end_pos]
                                if not val or _is_redacted_placeholder(val):
                                    parts.append(text[pos:end_pos])
                                    pos = end_pos
                                    continue
                                parts.append(text[pos : match.start()])
                                parts.append(
                                    f"{cli_prefix}{key}{sep_out}{scheme_text}{q}<REDACTED>"
                                )
                                pos = end_pos
                                continue
                            val = text[q_m.end() : close_idx]
                            if not val or _is_redacted_placeholder(val):
                                parts.append(text[pos:close_end])
                                pos = close_end
                                continue
                            parts.append(text[pos : match.start()])
                            parts.append(
                                f"{cli_prefix}{key}{sep_out}{scheme_text}{q}<REDACTED>{q}"
                            )
                            pos = close_end
                            continue
                        end_pos = more_end
                    else:
                        end_pos = max(q_m.end(), unclosed_end)
                else:
                    first_end: int
                    if (
                        kv_p := _AUTH_KV_PREFIX_RE.match(text, after_scheme)
                    ) is not None and kv_p.group(2) == "=":
                        after_kv = kv_p.end()
                        while after_kv < n and text[after_kv] in (" ", "\t"):
                            after_kv += 1
                        if after_kv >= n or text[after_kv] in "\r\n}];":
                            first_end = after_kv
                        elif (q_kv := _QUOTED_START_RE.match(text, after_kv)) is not None:
                            quote_tracker.advance_to(q_kv.start())
                            if quote_tracker.is_closing_quote(
                                len(q_kv.group(1)), q_kv.group(2), q_kv.start()
                            ):
                                quote_tracker.restore(multi_snap)
                                first_end = after_scheme
                            else:
                                if pem_index is None:
                                    pem_index = (
                                        _build_pem_end_index(text)
                                        if "-----END " in text
                                        else ({}, [])
                                    )
                                c_idx, u_end = _find_closing_quote_ex(
                                    text,
                                    q_kv.end(),
                                    len(q_kv.group(1)),
                                    q_kv.group(2),
                                    json_field=False,
                                    pem_index=pem_index,
                                )
                                first_end = (
                                    c_idx + len(q_kv.group(1)) + 1
                                    if c_idx is not None
                                    else max(q_kv.end(), u_end)
                                )
                        else:
                            mv_end = _scan_kv_value_end(text, after_kv, multi_param=True)
                            first_end = mv_end if mv_end is not None else after_kv
                    else:
                        mv_end = _scan_kv_value_end(text, after_scheme, multi_param=True)
                        first_end = mv_end if mv_end is not None else after_scheme

                    if first_end <= after_scheme:
                        end_pos = after_scheme
                    else:
                        more_end = _scan_auth_more_params_end(
                            text,
                            first_end,
                            allow_unquoted_space_token=True,
                            pem_index=pem_index,
                            quote_tracker=quote_tracker,
                            multi_param=True,
                        )
                        end_pos = more_end if more_end is not None else first_end

                encl_end, pem_index = _resolve_encl_end(
                    text, after_scheme, end_pos, encl, pem_index
                )
                if encl_end < end_pos:
                    end_pos = encl_end
                    quote_tracker.restore(multi_snap)
                    quote_tracker.advance_to(end_pos)
                if (
                    end_pos > after_scheme
                    and end_pos < n
                    and text[end_pos] == "\n"
                    and text[end_pos - 1] == "\r"
                ):
                    end_pos -= 1
                if end_pos <= after_scheme:
                    quote_tracker.restore(multi_snap)
                    quote_tracker.advance_to(after_scheme)
                    parts.append(text[pos:after_scheme])
                    pos = after_scheme
                    continue
                if _REDACTED_PLACEHOLDER_RE.fullmatch(text[after_scheme:end_pos]) is not None:
                    parts.append(text[pos:end_pos])
                    pos = end_pos
                    continue
                parts.append(text[pos : match.start()])
                parts.append(f"{cli_prefix}{key}{sep_out}{scheme_text}<REDACTED>")
                pos = end_pos
                continue

        is_oauth_comma_multiparam = False
        single_m = _AUTH_SINGLE_SCHEME_RE.match(text, val_start)
        if single_m is not None:
            after_s = single_m.end()
            if (kv_p := _AUTH_KV_PREFIX_RE.match(text, after_s)) is not None:
                kv_key = kv_p.group(1).lower()
                kv_sep = kv_p.group(2)
                if kv_sep == ":" or kv_key in _NON_AUTH_LOG_KEYS or (
                    (sep == "=" or key_low not in _AUTH_HEADER_KEYS)
                    and _is_non_auth_space_separator_key(kv_key)
                ):
                    if kv_sep != ":" and single_m.group(1).strip().lower() == "oauth":
                        quote_tracker.advance_to(match.start())
                        if pem_index is None:
                            pem_index = (
                                _build_pem_end_index(text) if "-----END " in text else ({}, [])
                            )
                        if _has_comma_auth_param(
                            text,
                            kv_key,
                            kv_p.end(),
                            quote_tracker=quote_tracker,
                            pem_index=pem_index,
                            allow_oauth_params=True,
                        ):
                            is_oauth_comma_multiparam = True
                        else:
                            single_m = None
                    else:
                        single_m = None

        is_unknown_comma_multiparam = False
        unknown_m = (
            _AUTH_UNKNOWN_SCHEME_RE.match(text, val_start)
            if (single_m is None and sep == ":" and key_low in _AUTH_HEADER_KEYS)
            else None
        )
        if unknown_m is not None:
            after_unk = unknown_m.end()
            if after_unk >= n or text[after_unk] in "\r\n,}]":
                unknown_m = None
            else:
                quote_tracker.advance_to(match.start())
                unk_snap = quote_tracker.snapshot()
                if (q_chk := _QUOTED_START_RE.match(text, after_unk)) is not None:
                    quote_tracker.advance_to(q_chk.start())
                    is_unk_close = quote_tracker.is_closing_quote(
                        len(q_chk.group(1)), q_chk.group(2), q_chk.start()
                    )
                    quote_tracker.restore(unk_snap)
                    if is_unk_close:
                        unknown_m = None
                elif (kv_p := _AUTH_KV_PREFIX_RE.match(text, after_unk)) is not None:
                    kv_key = kv_p.group(1).lower()
                    if kv_p.group(2) == ":" or _is_sensitive_key(kv_key):
                        unknown_m = None
                    elif kv_key not in _HTTP_AUTH_PARAM_KEYS:
                        if pem_index is None:
                            pem_index = (
                                _build_pem_end_index(text) if "-----END " in text else ({}, [])
                            )
                        if _has_comma_auth_param(
                            text,
                            kv_key,
                            kv_p.end(),
                            quote_tracker=quote_tracker,
                            pem_index=pem_index,
                        ):
                            is_unknown_comma_multiparam = True
                        elif not _has_space_auth_params(
                            text,
                            kv_key,
                            kv_p.end(),
                            quote_tracker=quote_tracker,
                            pem_index=pem_index,
                        ):
                            unknown_m = None
                    else:
                        if pem_index is None:
                            pem_index = (
                                _build_pem_end_index(text) if "-----END " in text else ({}, [])
                            )
                        if _has_comma_auth_param(
                            text,
                            kv_key,
                            kv_p.end(),
                            quote_tracker=quote_tracker,
                            pem_index=pem_index,
                        ):
                            is_unknown_comma_multiparam = True

        is_unknown_scheme = single_m is None and unknown_m is not None
        scheme_m = single_m if single_m is not None else unknown_m
        if scheme_m is not None and (
            key_low in _AUTH_HEADER_KEYS
            or scheme_m.group(1).strip().lower() in _AUTH_SINGLE_TOKEN_SCHEME_SET
        ):
            scheme_low = scheme_m.group(1).strip().lower()
            scheme_text = scheme_m.group(0)
            after_scheme = scheme_m.end()
            if after_scheme >= n or text[after_scheme] in "\r\n":
                parts.append(text[pos:after_scheme])
                pos = after_scheme
                continue
            quote_tracker.advance_to(match.start())
            scheme_encl = quote_tracker.innermost_open_ex()
            scheme_snap = quote_tracker.snapshot()
            is_multi_scheme = (
                is_unknown_comma_multiparam
                or is_oauth_comma_multiparam
                or scheme_low == "oauth"
            )
            if (q_m := _QUOTED_START_RE.match(text, after_scheme)) is not None:
                q_bs = q_m.group(1)
                q_ch = q_m.group(2)
                quote_tracker.advance_to(q_m.start())
                if quote_tracker.is_closing_quote(len(q_bs), q_ch, q_m.start()):
                    parts.append(text[pos:after_scheme])
                    pos = after_scheme
                    continue
                if pem_index is None:
                    pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])
                q = f"{q_bs}{q_ch}"
                close_idx, unclosed_end = _find_closing_quote_ex(
                    text, q_m.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
                )
                if close_idx is None:
                    end_idx = max(q_m.end(), unclosed_end)
                    encl_end, pem_index = _resolve_encl_end(
                        text, after_scheme, end_idx, scheme_encl, pem_index
                    )
                    if encl_end < end_idx:
                        end_idx = encl_end
                        quote_tracker.restore(scheme_snap)
                        quote_tracker.advance_to(end_idx)
                    if (
                        end_idx > q_m.end()
                        and end_idx < n
                        and text[end_idx] == "\n"
                        and text[end_idx - 1] == "\r"
                    ):
                        end_idx -= 1
                    val = text[q_m.end() : end_idx]
                    if not val or _is_redacted_placeholder(val):
                        parts.append(text[pos:end_idx])
                        pos = end_idx
                        continue
                    parts.append(text[pos : match.start()])
                    parts.append(f"{cli_prefix}{key}{sep_out}{scheme_text}{q}<REDACTED>")
                    pos = end_idx
                    continue
                close_end = close_idx + len(q_bs) + 1
                if (key_low in _AUTH_HEADER_KEYS and sep == ":") or (
                    scheme_low == "oauth"
                    and _AUTH_MORE_PARAMS_KV_RE.match(text, close_end) is not None
                ):
                    more_end = _scan_auth_more_params_end(
                        text,
                        close_end,
                        allow_unquoted_space_token=is_unknown_scheme,
                        pem_index=pem_index,
                        quote_tracker=quote_tracker,
                        multi_param=is_multi_scheme,
                    )
                    if more_end is not None:
                        end_pos = more_end
                        encl_end, pem_index = _resolve_encl_end(
                            text, after_scheme, end_pos, scheme_encl, pem_index
                        )
                        if encl_end < end_pos:
                            end_pos = encl_end
                            quote_tracker.restore(scheme_snap)
                            quote_tracker.advance_to(end_pos)
                        if (
                            end_pos > after_scheme
                            and end_pos < n
                            and text[end_pos] == "\n"
                            and text[end_pos - 1] == "\r"
                        ):
                            end_pos -= 1
                        if end_pos <= after_scheme:
                            quote_tracker.restore(scheme_snap)
                            quote_tracker.advance_to(after_scheme)
                            parts.append(text[pos:after_scheme])
                            pos = after_scheme
                            continue
                        parts.append(text[pos : match.start()])
                        parts.append(f"{cli_prefix}{key}{sep_out}{scheme_text}<REDACTED>")
                        pos = end_pos
                        continue
                encl_end, pem_index = _resolve_encl_end(
                    text, after_scheme, close_end, scheme_encl, pem_index
                )
                if encl_end < close_end:
                    end_idx = encl_end
                    if (
                        end_idx > q_m.end()
                        and end_idx < n
                        and text[end_idx] == "\n"
                        and text[end_idx - 1] == "\r"
                    ):
                        end_idx -= 1
                    quote_tracker.restore(scheme_snap)
                    quote_tracker.advance_to(end_idx)
                    val = text[q_m.end() : end_idx]
                    if not val or _is_redacted_placeholder(val):
                        parts.append(text[pos:end_idx])
                        pos = end_idx
                        continue
                    parts.append(text[pos : match.start()])
                    parts.append(f"{cli_prefix}{key}{sep_out}{scheme_text}{q}<REDACTED>")
                    pos = end_idx
                    continue
                val = text[q_m.end() : close_idx]
                if not val or _is_redacted_placeholder(val):
                    parts.append(text[pos:close_end])
                    pos = close_end
                    continue
                parts.append(text[pos : match.start()])
                parts.append(f"{cli_prefix}{key}{sep_out}{scheme_text}{q}<REDACTED>{q}")
                pos = close_end
                continue

            if (kv_m := _AUTH_KV_QUOTED_RE.match(text, after_scheme)) is not None:
                kv_prefix = kv_m.group(1)
                q_bs = kv_m.group(2)
                q_ch = kv_m.group(3)
                quote_tracker.advance_to(kv_m.start(2))
                if quote_tracker.is_closing_quote(len(q_bs), q_ch, kv_m.start(2)):
                    parts.append(text[pos : kv_m.start(2)])
                    pos = kv_m.start(2)
                    continue
                if pem_index is None:
                    pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])
                q = f"{q_bs}{q_ch}"
                close_idx, unclosed_end = _find_closing_quote_ex(
                    text, kv_m.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
                )
                if close_idx is None:
                    end_idx = max(kv_m.end(), unclosed_end)
                    encl_end, pem_index = _resolve_encl_end(
                        text, after_scheme, end_idx, scheme_encl, pem_index
                    )
                    if encl_end < end_idx:
                        end_idx = encl_end
                        quote_tracker.restore(scheme_snap)
                        quote_tracker.advance_to(end_idx)
                    if (
                        end_idx > kv_m.end()
                        and end_idx < n
                        and text[end_idx] == "\n"
                        and text[end_idx - 1] == "\r"
                    ):
                        end_idx -= 1
                    val = text[kv_m.end() : end_idx]
                    if not val or _is_redacted_placeholder(val):
                        parts.append(text[pos:end_idx])
                        pos = end_idx
                        continue
                    parts.append(text[pos : match.start()])
                    parts.append(
                        f"{cli_prefix}{key}{sep_out}{scheme_text}{kv_prefix}{q}<REDACTED>"
                    )
                    pos = end_idx
                    continue
                close_end = close_idx + len(q_bs) + 1
                if (key_low in _AUTH_HEADER_KEYS and sep == ":") or (
                    scheme_low == "oauth"
                    and _AUTH_MORE_PARAMS_KV_RE.match(text, close_end) is not None
                ):
                    more_end = _scan_auth_more_params_end(
                        text,
                        close_end,
                        allow_unquoted_space_token=is_unknown_scheme,
                        pem_index=pem_index,
                        quote_tracker=quote_tracker,
                        multi_param=is_multi_scheme,
                    )
                    if more_end is not None:
                        end_pos = more_end
                        encl_end, pem_index = _resolve_encl_end(
                            text, after_scheme, end_pos, scheme_encl, pem_index
                        )
                        if encl_end < end_pos:
                            end_pos = encl_end
                            quote_tracker.restore(scheme_snap)
                            quote_tracker.advance_to(end_pos)
                        if (
                            end_pos > after_scheme
                            and end_pos < n
                            and text[end_pos] == "\n"
                            and text[end_pos - 1] == "\r"
                        ):
                            end_pos -= 1
                        if end_pos <= after_scheme:
                            quote_tracker.restore(scheme_snap)
                            quote_tracker.advance_to(after_scheme)
                            parts.append(text[pos:after_scheme])
                            pos = after_scheme
                            continue
                        parts.append(text[pos : match.start()])
                        parts.append(f"{cli_prefix}{key}{sep_out}{scheme_text}<REDACTED>")
                        pos = end_pos
                        continue
                encl_end, pem_index = _resolve_encl_end(
                    text, after_scheme, close_end, scheme_encl, pem_index
                )
                if encl_end < close_end:
                    end_idx = encl_end
                    if (
                        end_idx > kv_m.end()
                        and end_idx < n
                        and text[end_idx] == "\n"
                        and text[end_idx - 1] == "\r"
                    ):
                        end_idx -= 1
                    quote_tracker.restore(scheme_snap)
                    quote_tracker.advance_to(end_idx)
                    val = text[kv_m.end() : end_idx]
                    if not val or _is_redacted_placeholder(val):
                        parts.append(text[pos:end_idx])
                        pos = end_idx
                        continue
                    parts.append(text[pos : match.start()])
                    parts.append(
                        f"{cli_prefix}{key}{sep_out}{scheme_text}{kv_prefix}{q}<REDACTED>"
                    )
                    pos = end_idx
                    continue
                val = text[kv_m.end() : close_idx]
                if not val or _is_redacted_placeholder(val):
                    parts.append(text[pos:close_end])
                    pos = close_end
                    continue
                parts.append(text[pos : match.start()])
                parts.append(
                    f"{cli_prefix}{key}{sep_out}{scheme_text}{kv_prefix}{q}<REDACTED>{q}"
                )
                pos = close_end
                continue

            sv_end = _scan_kv_value_end(text, after_scheme, multi_param=False)
            if sv_end is None:
                parts.append(text[pos:after_scheme])
                pos = after_scheme
                continue
            if (key_low in _AUTH_HEADER_KEYS and sep == ":") or (
                scheme_low == "oauth"
                and _AUTH_MORE_PARAMS_KV_RE.match(text, sv_end) is not None
            ):
                if pem_index is None:
                    pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])
                more_end = _scan_auth_more_params_end(
                    text,
                    sv_end,
                    allow_unquoted_space_token=is_unknown_scheme,
                    pem_index=pem_index,
                    quote_tracker=quote_tracker,
                    multi_param=is_multi_scheme,
                )
                if more_end is not None:
                    end_pos = more_end
                    encl_end, pem_index = _resolve_encl_end(
                        text, after_scheme, end_pos, scheme_encl, pem_index
                    )
                    if encl_end < end_pos:
                        end_pos = encl_end
                        quote_tracker.restore(scheme_snap)
                        quote_tracker.advance_to(end_pos)
                    if (
                        end_pos > after_scheme
                        and end_pos < n
                        and text[end_pos] == "\n"
                        and text[end_pos - 1] == "\r"
                    ):
                        end_pos -= 1
                    if end_pos <= after_scheme:
                        quote_tracker.restore(scheme_snap)
                        quote_tracker.advance_to(after_scheme)
                        parts.append(text[pos:after_scheme])
                        pos = after_scheme
                        continue
                    if _is_redacted_placeholder(text[after_scheme:end_pos]):
                        parts.append(text[pos:end_pos])
                        pos = end_pos
                        continue
                    parts.append(text[pos : match.start()])
                    parts.append(f"{cli_prefix}{key}{sep_out}{scheme_text}<REDACTED>")
                    pos = end_pos
                    continue
            sv_val = text[after_scheme:sv_end]
            if _is_redacted_placeholder(sv_val) or _AUTH_REDACTED_KV_RE.fullmatch(sv_val) is not None:
                parts.append(text[pos:sv_end])
                pos = sv_end
                continue
            parts.append(text[pos : match.start()])
            parts.append(f"{cli_prefix}{key}{sep_out}{scheme_text}<REDACTED>")
            pos = sv_end
            continue

        sv_end = _scan_kv_value_end(text, val_start, multi_param=False)
        if sv_end is None:
            parts.append(text[pos:val_start])
            pos = val_start
            continue
        if _is_redacted_placeholder(text[val_start:sv_end]):
            parts.append(text[pos:sv_end])
            pos = sv_end
            continue
        parts.append(text[pos : match.start()])
        parts.append(f"{cli_prefix}{key}{sep_out}<REDACTED>")
        pos = sv_end

    if pos == 0:
        return text
    parts.append(text[pos:])
    return "".join(parts)


def _redact_bearer_schemes(text: str) -> str:
    parts: list[str] = []
    pos = 0
    n = len(text)
    pem_index: tuple[dict[str, list[int]], list[int]] | None = None
    quote_tracker = _LineQuoteTracker(text)
    while (match := _BEARER_SCHEME_START_RE.search(text, pos)) is not None:
        if match.group(1) is not None:
            parts.append(text[pos : match.end()])
            pos = match.end()
            continue
        val_start = match.end()
        if val_start >= n or text[val_start] in "\r\n":
            parts.append(text[pos:val_start])
            pos = val_start
            continue
        q_m = _QUOTED_START_RE.match(text, val_start)
        if q_m is not None:
            q_bs = q_m.group(1)
            q_ch = q_m.group(2)
            quote_tracker.advance_to(q_m.start())
            if quote_tracker.is_closing_quote(len(q_bs), q_ch, q_m.start()):
                parts.append(text[pos:val_start])
                pos = val_start
                continue
            q = f"{q_bs}{q_ch}"
            if pem_index is None:
                pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])
            close_idx, unclosed_end = _find_closing_quote_ex(
                text, q_m.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
            )
            if close_idx is None:
                end_idx = max(q_m.end(), unclosed_end)
                if (
                    end_idx > q_m.end()
                    and end_idx < n
                    and text[end_idx] == "\n"
                    and text[end_idx - 1] == "\r"
                ):
                    end_idx -= 1
                val = text[q_m.end() : end_idx]
                if not val or _is_redacted_placeholder(val):
                    parts.append(text[pos:end_idx])
                    pos = end_idx
                    continue
                parts.append(text[pos : match.start()])
                parts.append(f"{match.group(2)} {q}<REDACTED>")
                pos = end_idx
                continue
            close_end = close_idx + len(q_bs) + 1
            val = text[q_m.end() : close_idx]
            if not val or _is_redacted_placeholder(val):
                parts.append(text[pos:close_end])
                pos = close_end
                continue
            parts.append(text[pos : match.start()])
            parts.append(f"{match.group(2)} {q}<REDACTED>{q}")
            pos = close_end
            continue

        if (kv_m := _AUTH_KV_QUOTED_RE.match(text, val_start)) is not None:
            kv_snap = quote_tracker.snapshot()
            quote_tracker.advance_to(match.start())
            encl = quote_tracker.innermost_open_ex()
            kv_prefix = kv_m.group(1)
            q_bs = kv_m.group(2)
            q_ch = kv_m.group(3)
            quote_tracker.advance_to(kv_m.start(2))
            if quote_tracker.is_closing_quote(len(q_bs), q_ch, kv_m.start(2)):
                quote_tracker.restore(kv_snap)
            else:
                if pem_index is None:
                    pem_index = _build_pem_end_index(text) if "-----END " in text else ({}, [])
                q = f"{q_bs}{q_ch}"
                kv_key = kv_prefix.split("=", 1)[0].strip().lower()
                is_non_secret_kv = kv_key in _NON_SECRET_METADATA_KEYS or (
                    not _is_sensitive_key(kv_key)
                    and (kv_key in _NON_AUTH_LOG_KEYS or kv_key in _NON_AUTH_SPACE_LOG_KEYS)
                )
                close_idx, unclosed_end = _find_closing_quote_ex(
                    text, kv_m.end(), len(q_bs), q_ch, json_field=False, pem_index=pem_index
                )
                if close_idx is None:
                    end_idx = max(kv_m.end(), unclosed_end)
                    encl_end, pem_index = _resolve_encl_end(
                        text, val_start, end_idx, encl, pem_index
                    )
                    if encl_end < end_idx:
                        end_idx = encl_end
                        quote_tracker.restore(kv_snap)
                        quote_tracker.advance_to(end_idx)
                    if (
                        end_idx > kv_m.end()
                        and end_idx < n
                        and text[end_idx] == "\n"
                        and text[end_idx - 1] == "\r"
                    ):
                        end_idx -= 1
                    val = text[kv_m.end() : end_idx]
                    if is_non_secret_kv or not val or _is_redacted_placeholder(val):
                        parts.append(text[pos:end_idx])
                        pos = end_idx
                        continue
                    parts.append(text[pos : match.start()])
                    parts.append(f"{match.group(2)} {kv_prefix}{q}<REDACTED>")
                    pos = end_idx
                    continue
                close_end = close_idx + len(q_bs) + 1
                encl_end, pem_index = _resolve_encl_end(
                    text, val_start, close_end, encl, pem_index
                )
                if encl_end < close_end:
                    end_idx = encl_end
                    if (
                        end_idx > kv_m.end()
                        and end_idx < n
                        and text[end_idx] == "\n"
                        and text[end_idx - 1] == "\r"
                    ):
                        end_idx -= 1
                    quote_tracker.restore(kv_snap)
                    quote_tracker.advance_to(end_idx)
                    val = text[kv_m.end() : end_idx]
                    if is_non_secret_kv or not val or _is_redacted_placeholder(val):
                        parts.append(text[pos:end_idx])
                        pos = end_idx
                        continue
                    parts.append(text[pos : match.start()])
                    parts.append(f"{match.group(2)} {kv_prefix}{q}<REDACTED>")
                    pos = end_idx
                    continue
                val = text[kv_m.end() : close_idx]
                if is_non_secret_kv or not val or _is_redacted_placeholder(val):
                    parts.append(text[pos:close_end])
                    pos = close_end
                    continue
                parts.append(text[pos : match.start()])
                parts.append(f"{match.group(2)} {kv_prefix}{q}<REDACTED>{q}")
                pos = close_end
                continue

        val_m = _BEARER_UNQUOTED_VAL_RE.match(text, val_start)
        if val_m is None:
            parts.append(text[pos:val_start])
            pos = val_start
            continue
        val = val_m.group(0)
        if _is_redacted_placeholder(val):
            parts.append(text[pos : val_m.end()])
            pos = val_m.end()
            continue
        if (
            val.lower() in _NON_SECRET_METADATA_KEYS
            and _KV_SEP_AHEAD_RE.match(text, val_m.end()) is not None
        ):
            parts.append(text[pos : val_m.end()])
            pos = val_m.end()
            continue
        if (
            _IDENT_FULL_RE.fullmatch(val) is not None
            and (sp_eq := _SPACE_EQ_RE.match(text, val_m.end())) is not None
        ):
            val_low = val.lower()
            if val_low in _NON_AUTH_LOG_KEYS or val_low in _NON_AUTH_SPACE_LOG_KEYS:
                parts.append(text[pos : val_m.end()])
                pos = val_m.end()
                continue
            rhs_m = _BEARER_UNQUOTED_VAL_RE.match(text, sp_eq.end())
            if rhs_m is not None:
                rhs = rhs_m.group(0)
                if _is_redacted_placeholder(rhs):
                    parts.append(text[pos : rhs_m.end()])
                    pos = rhs_m.end()
                    continue
                rhs_has_ph = (
                    "<REDACTED" in rhs and _REDACTED_PLACEHOLDER_RE.search(rhs) is not None
                )
                if rhs_has_ph or len(rhs) >= 6 or len(val) >= 6:
                    parts.append(text[pos : match.start()])
                    parts.append(f"{match.group(2)} <REDACTED>")
                    pos = rhs_m.end()
                    continue
                parts.append(text[pos : rhs_m.end()])
                pos = rhs_m.end()
                continue
        if (kv_p := _AUTH_KV_PREFIX_RE.match(val)) is not None and kv_p.group(2) == "=":
            k_low = kv_p.group(1).lower()
            if k_low in _NON_SECRET_METADATA_KEYS or (
                not _is_sensitive_key(k_low)
                and (k_low in _NON_AUTH_LOG_KEYS or k_low in _NON_AUTH_SPACE_LOG_KEYS)
            ):
                parts.append(text[pos : val_m.end()])
                pos = val_m.end()
                continue
            if _AUTH_REDACTED_KV_RE.fullmatch(val) is not None:
                parts.append(text[pos : val_m.end()])
                pos = val_m.end()
                continue
        has_placeholder = "<REDACTED" in val and _REDACTED_PLACEHOLDER_RE.search(val) is not None
        if has_placeholder or len(val) >= 6:
            parts.append(text[pos : match.start()])
            parts.append(f"{match.group(2)} <REDACTED>")
            pos = val_m.end()
            continue
        parts.append(text[pos : val_m.end()])
        pos = val_m.end()
    if pos == 0:
        return text
    parts.append(text[pos:])
    return "".join(parts)


def _redact_string(text: str) -> str:
    if not text:
        return text
    out = _URL_USERINFO_RE.sub(r"\1://\2:<REDACTED>@", text)
    out = _redact_quoted_fields(out)
    out = _redact_quoted_assignments(out)
    out = _redact_pem_blocks(out)
    out = _redact_url_query_secrets(out)
    out = _redact_header_kvs(out)
    out = _redact_bearer_schemes(out)
    out = _JWT_RE.sub("<REDACTED_JWT>", out)
    out = _VENDOR_PREFIX_RE.sub("<REDACTED>", out)
    return out


def _redact_recursive(value: Any, *, _depth: int = 0) -> Any:
    if _depth >= _MAX_REDACT_DEPTH:
        return "<REDACTED_MAX_DEPTH>"

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return _redact_string(value)

    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for raw_k, raw_v in value.items():
            key_str = str(raw_k)
            if _is_sensitive_key(key_str):
                if raw_v is None or isinstance(raw_v, bool):
                    redacted[key_str] = raw_v
                elif isinstance(raw_v, str) and not raw_v:
                    redacted[key_str] = raw_v
                elif isinstance(raw_v, Mapping):
                    redacted[key_str] = _redact_recursive(raw_v, _depth=_depth + 1)
                else:
                    redacted[key_str] = "<REDACTED>"
            else:
                redacted[key_str] = _redact_recursive(raw_v, _depth=_depth + 1)
        return redacted

    if isinstance(value, list):
        return [_redact_recursive(item, _depth=_depth + 1) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_recursive(item, _depth=_depth + 1) for item in value)

    if isinstance(value, set):
        return [_redact_recursive(item, _depth=_depth + 1) for item in sorted(value, key=str)]

    return _redact_string(str(value))


def redact_sensitive_data(value: Any) -> Any:
    """Recursively redact Bearer tokens, API keys, secrets, JWTs, and passwords."""
    return _redact_recursive(value, _depth=0)


@dataclass(frozen=True)
class AuditEntry:
    """Structured immutable record in the persistent SOC agent audit log."""

    entry_id: str
    timestamp: str
    run_id: str
    event_key: str
    provider: str
    mode: str
    event_type: AuditEventType
    tool_name: str = ""
    allowed: bool | None = None
    reason: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert entry into a JSON-serializable dictionary."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "event_key": self.event_key,
            "provider": self.provider,
            "mode": self.mode,
            "event_type": self.event_type,
            "tool_name": self.tool_name,
            "allowed": self.allowed,
            "reason": self.reason,
            "payload": dict(self.payload),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> AuditEntry | None:
        """Reconstruct an ``AuditEntry`` from parsed JSON, returning ``None`` if invalid."""
        event_type_raw = raw.get("event_type")
        if not isinstance(event_type_raw, str) or event_type_raw not in VALID_AUDIT_EVENT_TYPES:
            return None
        event_type: AuditEventType = event_type_raw  # type: ignore[assignment]

        entry_id = raw.get("entry_id")
        timestamp = raw.get("timestamp")
        if not isinstance(entry_id, str) or not isinstance(timestamp, str):
            return None

        allowed_raw = raw.get("allowed")
        allowed: bool | None = allowed_raw if isinstance(allowed_raw, bool) else None

        payload_raw = raw.get("payload")
        payload: dict[str, Any] = (
            dict(payload_raw) if isinstance(payload_raw, Mapping) else {}
        )

        return cls(
            entry_id=entry_id,
            timestamp=timestamp,
            run_id=str(raw.get("run_id") or ""),
            event_key=str(raw.get("event_key") or ""),
            provider=str(raw.get("provider") or ""),
            mode=str(raw.get("mode") or ""),
            event_type=event_type,
            tool_name=str(raw.get("tool_name") or ""),
            allowed=allowed,
            reason=str(raw.get("reason") or ""),
            payload=payload,
        )


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditLogStore:
    """Thread-safe, secret-redacting JSONL audit log store surviving restarts."""

    def __init__(self, path: Path | str | None = None) -> None:
        if path is not None:
            self._path = Path(path).expanduser()
        else:
            self._path = get_workspace_dir() / ".soclens_cache" / "ai_audit.jsonl"
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self._path

    def rebind_path(self, path: Path | str) -> None:
        """Thread-safely rebind this audit store to a new JSONL file path."""
        new_path = Path(path).expanduser()
        with self._lock:
            self._path = new_path

    def append(self, entry: AuditEntry) -> AuditEntry:
        """Redact sensitive values in ``entry`` and append it atomically to JSONL."""
        entry_id = entry.entry_id.strip() if isinstance(entry.entry_id, str) else ""
        if not entry_id:
            entry_id = uuid.uuid4().hex[:16]

        timestamp = entry.timestamp.strip() if isinstance(entry.timestamp, str) else ""
        if not timestamp:
            timestamp = _utc_now_iso()

        raw_payload = dict(entry.payload) if isinstance(entry.payload, Mapping) else {}
        redacted_payload_obj = redact_sensitive_data(raw_payload)
        redacted_payload: dict[str, Any] = (
            dict(redacted_payload_obj) if isinstance(redacted_payload_obj, Mapping) else {}
        )

        redacted_reason = str(redact_sensitive_data(entry.reason or ""))
        redacted_event_key = str(redact_sensitive_data(entry.event_key or ""))
        redacted_provider = str(redact_sensitive_data(entry.provider or ""))
        redacted_tool_name = str(redact_sensitive_data(entry.tool_name or ""))

        sanitized = AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            run_id=str(entry.run_id or ""),
            event_key=redacted_event_key,
            provider=redacted_provider,
            mode=str(entry.mode or ""),
            event_type=entry.event_type,
            tool_name=redacted_tool_name,
            allowed=entry.allowed,
            reason=redacted_reason,
            payload=redacted_payload,
        )

        line = json.dumps(sanitized.to_dict(), ensure_ascii=False, default=str) + "\n"
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
        return sanitized

    def query(
        self,
        *,
        event_key: str | None = None,
        run_id: str | None = None,
        event_type: str | None = None,
        blocked_only: bool = False,
        limit: int = 500,
    ) -> list[AuditEntry]:
        """Query persisted audit log entries with optional filters."""
        if limit <= 0:
            return []

        with self._lock:
            if not self._path.is_file():
                return []
            try:
                lines = self._path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as exc:
                logger.warning("Failed to read AI audit log %s: %s", self._path, exc)
                return []

        matched: list[AuditEntry] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except ValueError:
                logger.warning("Skipping corrupt JSONL line %d in %s.", idx, self._path)
                continue
            if not isinstance(raw, Mapping):
                continue
            entry = AuditEntry.from_dict(raw)
            if entry is None:
                continue
            if event_key is not None and entry.event_key != event_key:
                continue
            if run_id is not None and entry.run_id != run_id:
                continue
            if event_type is not None and entry.event_type != event_type:
                continue
            if blocked_only and not (
                entry.event_type == "blocked_action" or entry.allowed is False
            ):
                continue
            matched.append(entry)

        return matched[-limit:]


__all__ = [
    "AuditEntry",
    "AuditEventType",
    "AuditLogStore",
    "VALID_AUDIT_EVENT_TYPES",
    "redact_sensitive_data",
]
