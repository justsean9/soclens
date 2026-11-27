"""Strictly read-only tool registry, SPL command lexer, and SOC integration wrappers."""

from __future__ import annotations

import dataclasses
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal, cast

from soclens.agent_audit import AuditEntry, AuditLogStore, redact_sensitive_data
from soclens.agent_policy import (
    SOURCE_CATEGORY_LOCAL,
    SOURCE_CATEGORY_OSINT,
    SOURCE_CATEGORY_RF,
    SOURCE_CATEGORY_S1,
    SOURCE_CATEGORY_SPLUNK,
    SOURCE_CATEGORY_SPLUNK_ES,
    AIPolicyConfig,
    InvestigationMode,
    evaluate_tool_permission,
    register_readonly_tool_names,
)
from soclens.client import RecordedFutureClient
from soclens.config import ConfigurationError, get_splunk_config
from soclens.osint import OSINTClient
from soclens.research import classify_research_target, research_target
from soclens.sentinelone import SentinelOneClient
from soclens.splunk import SplunkClient
from soclens.splunk_es import SPLUNK_ES_APP, THREAT_INTEL_COLLECTIONS, SplunkESClient
from soclens.watchlist import filter_watchlist_entities

type ClientOrFactory[TClient] = TClient | Callable[[], TClient | None] | None

FORBIDDEN_MUTATING_METHOD_NAMES: frozenset[str] = frozenset(
    {
        # RecordedFutureClient (9)
        "create_list",
        "add_entity",
        "remove_entity",
        "replace_entity_tags",
        "update_playbook_alert",
        "update_alerts_v2",
        "create_case",
        "update_case",
        "pfi_query_pipeline",
        # SentinelOneClient — sites, policy & tokens/secrets (11)
        "create_site",
        "duplicate_site",
        "update_site",
        "expire_site",
        "reactivate_site",
        "regenerate_site_key",
        "rotate_site_token",
        "get_site_token",
        "update_site_policy",
        "revert_site_policy",
        "delete_site",
        # SentinelOneClient — endpoint actions (13)
        "disconnect_agent",
        "connect_agent",
        "initiate_scan",
        "abort_scan",
        "reboot_agent",
        "move_agents_to_site",
        "uninstall_agent",
        "add_agent_tags",
        "remove_agent_tags",
        "fetch_agent_logs",
        "fetch_logs",
        "decommission_agents",
        "decommission",
        # SentinelOneClient — threat & cloud alert mutations/mitigations (7)
        "update_threat_verdict",
        "update_threat_incident_status",
        "mitigate_threat",
        "add_threat_to_exclusions",
        "add_threat_note",
        "update_cloud_alert_verdict",
        "update_cloud_alert_incident_status",
        # SentinelOneClient — exclusions & blocklist writes (7)
        "create_exclusion",
        "update_exclusion",
        "clone_exclusions",
        "delete_exclusions",
        "add_to_blocklist",
        "update_blocklist",
        "remove_from_blocklist",
        # SentinelOneClient — users, service users, RBAC & token minting (13)
        "create_user",
        "update_user",
        "delete_user",
        "delete_users",
        "send_reset_password_email",
        "reset_2fa",
        "delete_2fa",
        "logout_user",
        "create_service_user",
        "update_service_user",
        "delete_service_user",
        "delete_service_users",
        "generate_service_user_token",
        # SplunkClient (3)
        "dispatch_saved_search",
        "cancel_job",
        "_cancel_search_job",
        # SplunkESClient & module-level ES writers (17)
        "update_notable",
        "set_correlation_search_enabled",
        "add_threat_intel_entry",
        "create_finding",
        "bulk_create_findings",
        "create_investigation",
        "update_investigation",
        "add_findings_to_investigation",
        "bulk_update_findings",
        "create_note",
        "update_note",
        "delete_note",
        "update_risk_score",
        "triage_findings_hybrid",
        "dispatch_adaptive_response",
        "save_splunk_es_saved_view",
        "delete_splunk_es_saved_view",
        # SplunkRFEnricher / splunk_rf_enrichment.py (1)
        "write_enrichment_to_notable",
    }
)

FORBIDDEN_SPL_COMMANDS: frozenset[str] = frozenset(
    {
        "outputlookup",
        "outputcsv",
        "outputtext",
        "outputtelemetry",
        "collect",
        "tscollect",
        "mcollect",
        "meventcollect",
        "stash",
        "summaryindex",
        "dump",
        "dbxoutput",
        "dbxquery",
        "sendtoparquet",
        "export",
        "sendemail",
        "sendalert",
        "sendmodalert",
        "sendresults",
        "alert",
        "webhook",
        "trigger",
        "run",
        "runshellscript",
        "script",
        "map",
        "savedsearch",
        "delete",
        "rest",
        "crawl",
        "curl",
        "http",
        "put",
        "post",
        "patch",
        "update",
        "modify",
    }
)

READONLY_TOOL_NAMES: frozenset[str] = frozenset(
    {
        # Splunk SPL (3)
        "splunk_search",
        "splunk_list_indexes",
        "splunk_list_saved_searches",
        # Splunk ES (7)
        "splunk_es_list_notables",
        "splunk_es_get_finding",
        "splunk_es_list_investigations",
        "splunk_es_list_risk_events",
        "splunk_es_lookup_asset",
        "splunk_es_lookup_identity",
        "splunk_es_query_threat_intel",
        # SentinelOne (7)
        "s1_list_threats",
        "s1_get_threat_timeline",
        "s1_list_cloud_alerts",
        "s1_list_agents",
        "s1_get_agent",
        "s1_list_activities",
        "s1_dv_query",
        # Recorded Future (8)
        "rf_search_alerts",
        "rf_get_alert",
        "rf_search_playbook_alerts",
        "rf_get_playbook_alert",
        "rf_lookup_ioc_or_cve",
        "rf_search_analyst_notes",
        "rf_soar_enrich",
        "rf_links_search",
        # Watchlists & OSINT (4)
        "rf_get_watchlists",
        "rf_get_watchlist_entities",
        "osint_enrich_target",
        "unified_research_target",
        # Local DB-First Tools (3)
        "local_search_alerts_history",
        "local_lookup_ioc_sightings",
        "local_search_soc_knowledge",
    }
)

register_readonly_tool_names(READONLY_TOOL_NAMES)

_SPL_CMD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)")
_SPL_CONT_PREDICATE_RE = re.compile(
    r"^(?:'[^']*'|[A-Za-z_][A-Za-z0-9_.*:-]*)\s*(?:!=|==|<=|>=|=|<|>)\s*(?:<STR>|'[^']*'|[^\s()]+)"
)
_SPL_CONT_BOOL_RE = re.compile(r"^(AND|OR|NOT)(?=$|[\s(\[])", re.IGNORECASE)
_SPL_CONT_OP_NUM_RE = re.compile(r"^(?:!=|==|<=|>=|[+\-*/%=<>]|\d+(?:\.\d+)?)")
_MAX_AUDIT_RESULT_CHARS = 16000


def _validate_spl_continuation(seg: str) -> tuple[bool, str]:
    """Validate non-empty tokens following a closing subsearch bracket ``]``."""
    pos = 0
    length = len(seg)
    while pos < length:
        while pos < length and seg[pos].isspace():
            pos += 1
        if pos >= length:
            break

        if seg.startswith("<STR>", pos):
            pos += 5
            continue

        if seg[pos] in "(),":
            pos += 1
            continue

        pred_match = _SPL_CONT_PREDICATE_RE.match(seg[pos:])
        if pred_match:
            pos += pred_match.end()
            continue

        bool_match = _SPL_CONT_BOOL_RE.match(seg[pos:])
        if bool_match:
            pos += bool_match.end()
            continue

        op_num_match = _SPL_CONT_OP_NUM_RE.match(seg[pos:])
        if op_num_match:
            pos += op_num_match.end()
            continue

        cmd_match = _SPL_CMD_RE.match(seg[pos:])
        if cmd_match:
            cmd = cmd_match.group(1).lower()
            if cmd in FORBIDDEN_SPL_COMMANDS:
                return (
                    False,
                    f"Forbidden SPL command '{cmd}' is not allowed in read-only mode.",
                )
            return (
                False,
                f"Unexpected SPL token '{cmd_match.group(1)}' after subsearch ']' without pipe '|'.",
            )

        return (
            False,
            "Unexpected syntax after subsearch ']' without pipe '|'.",
        )

    return True, "ok"


def validate_readonly_spl(spl: str) -> tuple[bool, str]:
    """Validate that an SPL query is syntactically balanced and strictly read-only.

    Uses a deterministic single-pass lexer that handles double-quoted string literals
    with backslash escapes, triple-backtick comments (`` ```...``` ``), subsearches
    (``[...]``), and pipes (``|``), while blocking backtick macros, semicolons, null
    bytes, unclosed delimiters, and all mutating/side-effect/network/script SPL
    commands. Single quotes (``'...'``) are checked for balance as field identifiers
    but do NOT suppress pipes, semicolons, or backtick macros, and do not allow
    embedded ``"`` or `` ``` `` to desynchronize quote/comment state.
    """
    if not isinstance(spl, str) or not spl.strip():
        return False, "SPL query must be a non-empty string."
    if "\x00" in spl:
        return False, "SPL query contains illegal null bytes."

    segments: list[tuple[str, str, str | None]] = []
    # Each entry: (segment_kind, segment_text, closing_delimiter)
    current_kind = "initial"
    current_buf: list[str] = []

    in_double_quote = False
    single_quote_open = False
    in_comment = False
    escaped = False
    bracket_depth = 0

    n = len(spl)
    i = 0
    while i < n:
        ch = spl[i]

        if in_comment:
            if spl.startswith("```", i):
                in_comment = False
                current_buf.append(" ")
                i += 3
                continue
            i += 1
            continue

        if in_double_quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_double_quote = False
                current_buf.append(" <STR> ")
            i += 1
            continue

        # Outside double quotes and comments (single quotes do NOT suppress delimiters)
        if not single_quote_open and spl.startswith("```", i):
            in_comment = True
            current_buf.append(" ")
            i += 3
            continue

        if ch == "`":
            return False, "Backtick macros are not permitted in read-only SPL searches."

        if ch == ";":
            return False, "Semicolons outside quotes are not permitted in read-only SPL searches."

        if not single_quote_open and ch == "\\" and i + 1 < n and spl[i + 1] in ("\\", '"'):
            current_buf.append(spl[i : i + 2])
            i += 2
            continue

        if ch == '"':
            if single_quote_open:
                current_buf.append(ch)
            else:
                in_double_quote = True
                escaped = False
            i += 1
            continue

        if ch == "'":
            single_quote_open = not single_quote_open
            current_buf.append(ch)
            i += 1
            continue

        if ch == "[":
            bracket_depth += 1
            segments.append((current_kind, "".join(current_buf), "["))
            current_kind = "subsearch"
            current_buf = []
            i += 1
            continue

        if ch == "]":
            if bracket_depth <= 0:
                return False, "Unbalanced closing ']' in SPL query."
            bracket_depth -= 1
            segments.append((current_kind, "".join(current_buf), "]"))
            current_kind = "continuation"
            current_buf = []
            i += 1
            continue

        if ch == "|":
            segments.append((current_kind, "".join(current_buf), "|"))
            current_kind = "pipe"
            current_buf = []
            i += 1
            continue

        current_buf.append(ch)
        i += 1

    if in_comment:
        return False, "Unclosed SPL triple-backtick comment."
    if in_double_quote or single_quote_open:
        return False, "Unclosed string literal in SPL query."
    if bracket_depth != 0:
        return False, "Unbalanced '[' subsearch bracket in SPL query."

    segments.append((current_kind, "".join(current_buf), None))

    for kind, raw_seg, next_delim in segments:
        seg = raw_seg.strip()
        if kind == "pipe":
            if not seg:
                return False, "Empty SPL pipe command is not allowed."
            match = _SPL_CMD_RE.match(seg)
            if not match:
                return False, "Invalid or quoted SPL command after pipe."
            cmd = match.group(1).lower()
            if cmd in FORBIDDEN_SPL_COMMANDS:
                return False, f"Forbidden SPL command '{cmd}' is not allowed in read-only mode."
        elif kind == "subsearch":
            if not seg:
                if next_delim == "|":
                    continue
                return False, "Empty SPL subsearch is not allowed."
            match = _SPL_CMD_RE.match(seg)
            if match:
                cmd = match.group(1).lower()
                if cmd in FORBIDDEN_SPL_COMMANDS:
                    return (
                        False,
                        f"Forbidden SPL command '{cmd}' is not allowed in read-only mode.",
                    )
        elif kind == "continuation":
            if not seg:
                continue
            cont_ok, cont_reason = _validate_spl_continuation(seg)
            if not cont_ok:
                return False, cont_reason
        elif kind == "initial":
            if not seg:
                continue
            match = _SPL_CMD_RE.match(seg)
            if match:
                cmd = match.group(1).lower()
                if cmd in FORBIDDEN_SPL_COMMANDS:
                    return (
                        False,
                        f"Forbidden SPL command '{cmd}' is not allowed in read-only mode.",
                    )

    return True, "ok"


def _to_json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _to_json_safe(dataclasses.asdict(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(k): _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_json_safe(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [_to_json_safe(item) for item in sorted(value, key=str)]
    return str(value)


def _truncate_for_audit(value: Any) -> Any:
    safe = redact_sensitive_data(_to_json_safe(value))
    try:
        encoded = json.dumps(safe, ensure_ascii=False, default=str)
        if len(encoded) <= _MAX_AUDIT_RESULT_CHARS:
            return safe
        return {
            "truncated": True,
            "original_chars": len(encoded),
            "preview": encoded[:_MAX_AUDIT_RESULT_CHARS],
        }
    except Exception:
        text = str(safe)
        return text[:_MAX_AUDIT_RESULT_CHARS]


@dataclasses.dataclass(frozen=True)
class ReadOnlyToolSpec:
    """Explicitly allowlisted read-only tool specification."""

    name: str
    source_category: str
    description: str
    parameters_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any]
    readonly: Literal[True] = True
    underlying_methods: tuple[str, ...] = ()


_FORBIDDEN_MUTATING_LOWER: frozenset[str] = frozenset(
    name.strip().lower() for name in FORBIDDEN_MUTATING_METHOD_NAMES
)


class ReadOnlyToolRegistry:
    """Fail-closed registry executing only verified read-only SOC tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ReadOnlyToolSpec] = {}

    def register(self, spec: ReadOnlyToolSpec) -> None:
        """Register a strictly read-only tool specification."""
        if spec.readonly is not True:
            raise ValueError(f"Tool '{spec.name}' must set readonly=True.")
        clean_name = spec.name.strip() if isinstance(spec.name, str) else ""
        if not clean_name:
            raise ValueError("Tool name must be a non-empty string.")
        if clean_name.lower() in _FORBIDDEN_MUTATING_LOWER:
            raise ValueError(f"Forbidden mutating tool name cannot be registered: {clean_name}")
        if not isinstance(spec.source_category, str) or not spec.source_category.strip():
            raise ValueError(f"Tool '{clean_name}' must specify a valid source_category.")
        handler_name = str(getattr(spec.handler, "__name__", "") or "").strip()
        if handler_name.lower() in _FORBIDDEN_MUTATING_LOWER:
            raise ValueError(
                f"Forbidden mutating handler cannot be registered: {handler_name}"
            )
        for method_name in spec.underlying_methods:
            clean_method = str(method_name).strip()
            if clean_method.lower() in _FORBIDDEN_MUTATING_LOWER:
                raise ValueError(
                    f"Tool '{clean_name}' references forbidden mutating method '{clean_method}'."
                )

        self._tools[clean_name] = spec

    def list_tools(self) -> list[ReadOnlyToolSpec]:
        """Return all registered read-only tools in registration order."""
        return list(self._tools.values())

    def get_tool(self, name: str) -> ReadOnlyToolSpec | None:
        """Look up a registered tool by name."""
        return self._tools.get(name)

    def openai_schemas(self, allowed_names: set[str] | None = None) -> list[dict[str, Any]]:
        """Return OpenAI-compatible function-calling schemas for registered tools."""
        schemas: list[dict[str, Any]] = []
        for spec in self._tools.values():
            if allowed_names is not None and spec.name not in allowed_names:
                continue
            schemas.append(
                {
                    "type": "function",
                    "function": {
                        "name": spec.name,
                        "description": spec.description,
                        "parameters": spec.parameters_schema,
                    },
                }
            )
        return schemas

    def _emit_audit(
        self,
        audit: AuditLogStore | None,
        *,
        run_id: str,
        event_key: str,
        provider: str,
        mode: str,
        event_type: Literal[
            "tool_call",
            "permission_check",
            "tool_result",
            "blocked_action",
            "error",
        ],
        tool_name: str,
        allowed: bool | None = None,
        reason: str = "",
        payload: dict[str, Any] | None = None,
    ) -> None:
        if audit is None:
            return
        audit.append(
            AuditEntry(
                entry_id="",
                timestamp="",
                run_id=run_id,
                event_key=event_key,
                provider=provider,
                mode=mode,
                event_type=event_type,
                tool_name=tool_name,
                allowed=allowed,
                reason=reason,
                payload=payload or {},
            )
        )

    def execute(
        self,
        name: str,
        arguments: Mapping[str, Any] | None,
        *,
        mode: InvestigationMode,
        policy: AIPolicyConfig,
        audit: AuditLogStore | None = None,
        run_id: str = "",
        event_key: str = "",
        provider: str = "",
    ) -> dict[str, Any]:
        """Validate policy & SPL guardrails, audit lifecycle events, and execute tool."""
        if arguments is None:
            args: dict[str, Any] = {}
        elif isinstance(arguments, Mapping):
            args = dict(arguments)
        else:
            err_msg = (
                f"Invalid tool arguments: expected mapping, got {type(arguments).__name__}."
            )
            truncated_args = _truncate_for_audit(arguments)
            self._emit_audit(
                audit,
                run_id=run_id,
                event_key=event_key,
                provider=provider,
                mode=mode,
                event_type="tool_call",
                tool_name=name,
                payload={"arguments": truncated_args},
            )
            self._emit_audit(
                audit,
                run_id=run_id,
                event_key=event_key,
                provider=provider,
                mode=mode,
                event_type="permission_check",
                tool_name=name,
                allowed=False,
                reason=err_msg,
                payload={"rule": "invalid_arguments"},
            )
            self._emit_audit(
                audit,
                run_id=run_id,
                event_key=event_key,
                provider=provider,
                mode=mode,
                event_type="error",
                tool_name=name,
                allowed=False,
                reason=err_msg,
                payload={
                    "error_type": "TypeError",
                    "rule": "invalid_arguments",
                    "arguments": truncated_args,
                },
            )
            return {
                "ok": False,
                "blocked": False,
                "tool": name,
                "error": err_msg,
            }

        spec = self.get_tool(name)

        truncated_args = _truncate_for_audit(args)

        self._emit_audit(
            audit,
            run_id=run_id,
            event_key=event_key,
            provider=provider,
            mode=mode,
            event_type="tool_call",
            tool_name=name,
            payload={"arguments": truncated_args},
        )

        source_category = spec.source_category if spec is not None else ""
        is_readonly = bool(spec is not None and spec.readonly is True)
        decision = evaluate_tool_permission(
            tool_name=name,
            source_category=source_category,
            is_readonly=is_readonly,
            mode=mode,
            policy=policy,
            arguments=args,
            registered_tools=set(self._tools.keys()),
        )

        self._emit_audit(
            audit,
            run_id=run_id,
            event_key=event_key,
            provider=provider,
            mode=mode,
            event_type="permission_check",
            tool_name=name,
            allowed=decision.allowed,
            reason=decision.reason,
            payload={"rule": decision.rule},
        )

        if not decision.allowed or spec is None:
            self._emit_audit(
                audit,
                run_id=run_id,
                event_key=event_key,
                provider=provider,
                mode=mode,
                event_type="blocked_action",
                tool_name=name,
                allowed=False,
                reason=decision.reason,
                payload={"rule": decision.rule, "arguments": truncated_args},
            )
            return {
                "ok": False,
                "blocked": True,
                "tool": name,
                "rule": decision.rule,
                "reason": decision.reason,
                "error": decision.reason,
            }

        # Defense-in-depth SPL validation before invoking splunk_search handler.
        if name == "splunk_search":
            raw_spl = args.get("spl")
            valid_spl, spl_reason = validate_readonly_spl(
                raw_spl if isinstance(raw_spl, str) else ""
            )
            if not valid_spl:
                self._emit_audit(
                    audit,
                    run_id=run_id,
                    event_key=event_key,
                    provider=provider,
                    mode=mode,
                    event_type="blocked_action",
                    tool_name=name,
                    allowed=False,
                    reason=spl_reason,
                    payload={"rule": "spl_readonly_violation", "arguments": truncated_args},
                )
                return {
                    "ok": False,
                    "blocked": True,
                    "tool": name,
                    "rule": "spl_readonly_violation",
                    "reason": spl_reason,
                    "error": spl_reason,
                }

        # Enforce recorded_future_enabled policy inside unified_research_target.
        handler_args = args
        rf_clamped = False
        if name == "unified_research_target" and not policy.recorded_future_enabled:
            raw_rf = args.get("include_rf")
            rf_clamped = raw_rf if isinstance(raw_rf, bool) else True
            handler_args = dict(args)
            handler_args["include_rf"] = False
            if rf_clamped:
                self._emit_audit(
                    audit,
                    run_id=run_id,
                    event_key=event_key,
                    provider=provider,
                    mode=mode,
                    event_type="blocked_action",
                    tool_name=name,
                    allowed=False,
                    reason=(
                        "Source category 'recorded_future' is disabled in the AI Control Panel; "
                        "enforced include_rf=False on unified_research_target."
                    ),
                    payload={
                        "rule": f"source_disabled:{SOURCE_CATEGORY_RF}",
                        "clamped_argument": "include_rf",
                        "enforced_value": False,
                    },
                )

        try:
            raw_result = spec.handler(handler_args)
        except Exception as exc:
            self._emit_audit(
                audit,
                run_id=run_id,
                event_key=event_key,
                provider=provider,
                mode=mode,
                event_type="error",
                tool_name=name,
                allowed=True,
                reason=str(exc),
                payload={"error_type": type(exc).__name__},
            )
            return {
                "ok": False,
                "blocked": False,
                "tool": name,
                "error": str(exc),
                "error_type": type(exc).__name__,
            }

        normalized = _to_json_safe(raw_result)
        if isinstance(normalized, dict) and normalized.get("ok") is False:
            is_blocked = bool(normalized.get("blocked"))
            err_msg = str(normalized.get("error") or normalized.get("reason") or "Tool error.")
            self._emit_audit(
                audit,
                run_id=run_id,
                event_key=event_key,
                provider=provider,
                mode=mode,
                event_type="blocked_action" if is_blocked else "error",
                tool_name=name,
                allowed=not is_blocked,
                reason=err_msg,
                payload={"result": _truncate_for_audit(normalized)},
            )
            return {**normalized, "tool": name}

        result_payload: dict[str, Any] = {"result": _truncate_for_audit(normalized)}
        response: dict[str, Any] = {"ok": True, "tool": name, "result": normalized}
        if rf_clamped:
            clamp_info = {
                "include_rf": False,
                "rule": f"source_disabled:{SOURCE_CATEGORY_RF}",
            }
            result_payload["policy_clamped"] = clamp_info
            response["policy_clamped"] = clamp_info
        self._emit_audit(
            audit,
            run_id=run_id,
            event_key=event_key,
            provider=provider,
            mode=mode,
            event_type="tool_result",
            tool_name=name,
            allowed=True,
            reason="ok",
            payload=result_payload,
        )
        return response


def _resolve_client[TClient](
    provided: ClientOrFactory[TClient],
    default_factory: Callable[[], TClient | None],
) -> TClient | None:
    if provided is not None:
        if hasattr(provided, "_mock_return_value"):
            return cast(TClient, provided)
        if callable(provided):
            try:
                return provided()
            except ConfigurationError:
                return None
        return provided
    try:
        return default_factory()
    except ConfigurationError:
        return None


def _default_splunk_factory() -> SplunkClient | None:
    cfg = get_splunk_config(required=False)
    if not cfg.has_auth:
        return None
    return SplunkClient()


def _default_splunk_es_factory() -> SplunkESClient | None:
    cfg = get_splunk_config(app=SPLUNK_ES_APP, required=False)
    if not cfg.has_auth:
        return None
    return SplunkESClient()


def _default_rf_factory() -> RecordedFutureClient | None:
    return RecordedFutureClient()


def _default_s1_factory() -> SentinelOneClient | None:
    return SentinelOneClient()


def _default_osint_factory() -> OSINTClient | None:
    return OSINTClient()


def _require_str_arg(args: Mapping[str, Any], key: str) -> str:
    val = args.get(key)
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"Missing or empty required string argument: '{key}'.")
    return val.strip()


def _opt_str(args: Mapping[str, Any], key: str) -> str | None:
    val = args.get(key)
    if val is None:
        return None
    text = str(val).strip()
    return text or None


def _opt_int(
    args: Mapping[str, Any],
    key: str,
    default: int,
    *,
    min_val: int = 1,
    max_val: int = 200,
) -> int:
    val = args.get(key)
    if val is None or isinstance(val, bool):
        return default
    try:
        parsed = int(val)
    except (TypeError, ValueError):
        return default
    return max(min_val, min(parsed, max_val))


def _opt_bool(args: Mapping[str, Any], key: str, default: bool) -> bool:
    val = args.get(key)
    if isinstance(val, bool):
        return val
    return default


def _opt_str_list_or_str(args: Mapping[str, Any], key: str) -> list[str] | str | None:
    val = args.get(key)
    if val is None or isinstance(val, (bytes, bytearray)):
        return None
    if isinstance(val, str):
        clean = val.strip()
        return clean or None
    if isinstance(val, Sequence):
        cleaned = [str(item).strip() for item in val if str(item).strip()]
        return cleaned or None
    return None


def _opt_str_list(args: Mapping[str, Any], key: str) -> list[str] | None:
    val = args.get(key)
    if val is None or isinstance(val, (bytes, bytearray)):
        return None
    if isinstance(val, str):
        cleaned = [part.strip() for part in val.split(",") if part.strip()]
        return cleaned or None
    if isinstance(val, Sequence):
        cleaned = [str(item).strip() for item in val if str(item).strip()]
        return cleaned or None
    return None


def _is_rf_configured(rf: Any) -> bool:
    if rf is None:
        return False
    if isinstance(rf, RecordedFutureClient) and not getattr(rf, "api_token", None):
        return False
    return True


def _is_s1_configured(s1: Any) -> bool:
    if s1 is None:
        return False
    if isinstance(s1, SentinelOneClient) and not getattr(s1, "has_auth", False):
        return False
    return True


def _infer_rf_v2_entity_type(value: str) -> str:
    clean = value.strip()
    try:
        resolved = classify_research_target(clean)
        v2_type = resolved.v2_type
        if v2_type:
            return v2_type
    except Exception:
        pass
    low = clean.lower()
    if low.startswith("cve-"):
        return "vulnerability"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", clean):
        return "ip"
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", low):
        return "hash"
    if low.startswith(("http://", "https://")):
        return "url"
    return "domain"


def build_default_readonly_registry(
    *,
    rf_client: ClientOrFactory[RecordedFutureClient] = None,
    s1_client: ClientOrFactory[SentinelOneClient] = None,
    splunk_client: ClientOrFactory[SplunkClient] = None,
    splunk_es_client: ClientOrFactory[SplunkESClient] = None,
    osint_client: ClientOrFactory[OSINTClient] = None,
    research_fn: Callable[..., Any] | None = None,
    storage: Any | Callable[[], Any | None] | None = None,
    learning_manager: Any | Callable[[], Any | None] | None = None,
) -> ReadOnlyToolRegistry:
    """Build the default ReadOnlyToolRegistry with all 32 allowlisted SOC tools."""
    registry = ReadOnlyToolRegistry()
    active_research_fn = research_fn if research_fn is not None else research_target

    def get_storage() -> Any | None:
        if storage is None:
            return None
        if hasattr(storage, "_mock_return_value"):
            return storage
        if callable(storage):
            try:
                return storage()
            except Exception:
                return None
        return storage

    _fallback_learning_mgr: Any = None

    def get_learning_manager() -> Any | None:
        nonlocal _fallback_learning_mgr
        if learning_manager is not None:
            if hasattr(learning_manager, "_mock_return_value"):
                return learning_manager
            if callable(learning_manager):
                try:
                    return learning_manager()
                except Exception:
                    return None
            return learning_manager
        stor = get_storage()
        if stor is not None and callable(getattr(stor, "search_learnings", None)):
            if _fallback_learning_mgr is None:
                from soclens.agent_learning import SOCLearningManager

                _fallback_learning_mgr = SOCLearningManager(storage=stor)
            return _fallback_learning_mgr
        return None

    def get_splunk() -> SplunkClient | None:
        return _resolve_client(splunk_client, _default_splunk_factory)

    def get_splunk_es() -> SplunkESClient | None:
        return _resolve_client(splunk_es_client, _default_splunk_es_factory)

    def get_s1() -> SentinelOneClient | None:
        client = _resolve_client(s1_client, _default_s1_factory)
        return client if _is_s1_configured(client) else None

    def get_rf() -> RecordedFutureClient | None:
        client = _resolve_client(rf_client, _default_rf_factory)
        return client if _is_rf_configured(client) else None

    def get_osint() -> OSINTClient | None:
        return _resolve_client(osint_client, _default_osint_factory)

    # ------------------------------------------------------------------
    # A. Splunk SPL (3 tools)
    # ------------------------------------------------------------------
    def _splunk_search_handler(args: dict[str, Any]) -> Any:
        spl = _require_str_arg(args, "spl")
        valid_spl, reason = validate_readonly_spl(spl)
        if not valid_spl:
            return {"ok": False, "blocked": True, "rule": "spl_readonly_violation", "error": reason}
        client = get_splunk()
        if client is None:
            return {"ok": False, "error": "Splunk is not configured."}
        return client.run_search(
            spl,
            earliest=_opt_str(args, "earliest") or "-24h",
            latest=_opt_str(args, "latest") or "now",
            app=_opt_str(args, "app"),
            count=_opt_int(args, "count", 50, min_val=1, max_val=200),
            offset=_opt_int(args, "offset", 0, min_val=0, max_val=10000),
            timeout=_opt_int(args, "timeout", 120, min_val=1, max_val=300),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_search",
            source_category=SOURCE_CATEGORY_SPLUNK,
            description=(
                "Execute a read-only Splunk SPL search (mutating commands and backtick macros "
                "are blocked; use splunk_es_list_notables for ES notables)."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "spl": {"type": "string", "description": "Read-only SPL search query."},
                    "earliest": {"type": "string", "description": "Earliest time (default -24h)."},
                    "latest": {"type": "string", "description": "Latest time (default now)."},
                    "app": {"type": "string", "description": "Optional Splunk app context."},
                    "count": {"type": "integer", "description": "Max results (default 50, max 200)."},
                    "offset": {"type": "integer", "description": "Result offset (default 0)."},
                    "timeout": {"type": "integer", "description": "Search timeout in seconds."},
                },
                "required": ["spl"],
            },
            handler=_splunk_search_handler,
            underlying_methods=("run_search",),
        )
    )

    def _splunk_list_indexes_handler(_args: dict[str, Any]) -> Any:
        client = get_splunk()
        if client is None:
            return {"ok": False, "error": "Splunk is not configured."}
        return client.list_indexes()

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_list_indexes",
            source_category=SOURCE_CATEGORY_SPLUNK,
            description="List available Splunk indexes and event/time metadata.",
            parameters_schema={"type": "object", "properties": {}},
            handler=_splunk_list_indexes_handler,
            underlying_methods=("list_indexes",),
        )
    )

    def _splunk_list_saved_searches_handler(args: dict[str, Any]) -> Any:
        client = get_splunk()
        if client is None:
            return {"ok": False, "error": "Splunk is not configured."}
        return client.list_saved_searches(
            app=_opt_str(args, "app"),
            search_filter=_opt_str(args, "search_filter"),
            count=_opt_int(args, "count", 100, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_list_saved_searches",
            source_category=SOURCE_CATEGORY_SPLUNK,
            description="List Splunk saved searches (metadata only; does not dispatch).",
            parameters_schema={
                "type": "object",
                "properties": {
                    "app": {"type": "string"},
                    "search_filter": {"type": "string"},
                    "count": {"type": "integer"},
                },
            },
            handler=_splunk_list_saved_searches_handler,
            underlying_methods=("list_saved_searches",),
        )
    )

    # ------------------------------------------------------------------
    # B. Splunk ES (7 tools)
    # ------------------------------------------------------------------
    def _es_list_notables_handler(args: dict[str, Any]) -> Any:
        client = get_splunk_es()
        if client is None:
            return {"ok": False, "error": "Splunk ES is not configured."}
        return client.list_notables(
            earliest=_opt_str(args, "earliest") or "-24h",
            latest=_opt_str(args, "latest") or "now",
            urgency=_opt_str(args, "urgency"),
            status=_opt_str(args, "status"),
            owner=_opt_str(args, "owner"),
            rule_name=_opt_str(args, "rule_name"),
            search_text=_opt_str(args, "search_text"),
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_es_list_notables",
            source_category=SOURCE_CATEGORY_SPLUNK_ES,
            description="List Splunk Enterprise Security notable events matching filters.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "earliest": {"type": "string"},
                    "latest": {"type": "string"},
                    "urgency": {"type": "string"},
                    "status": {"type": "string"},
                    "owner": {"type": "string"},
                    "rule_name": {"type": "string"},
                    "search_text": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
            handler=_es_list_notables_handler,
            underlying_methods=("list_notables",),
        )
    )

    def _es_get_finding_handler(args: dict[str, Any]) -> Any:
        client = get_splunk_es()
        if client is None:
            return {"ok": False, "error": "Splunk ES is not configured."}
        finding_id = _require_str_arg(args, "finding_id")
        return client.get_finding(
            finding_id,
            earliest=_opt_str(args, "earliest"),
            latest=_opt_str(args, "latest"),
            normalize=_opt_bool(args, "normalize", True),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_es_get_finding",
            source_category=SOURCE_CATEGORY_SPLUNK_ES,
            description="Fetch a single Splunk ES Mission Control finding by finding_id.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "earliest": {"type": "string"},
                    "latest": {"type": "string"},
                    "normalize": {"type": "boolean"},
                },
                "required": ["finding_id"],
            },
            handler=_es_get_finding_handler,
            underlying_methods=("get_finding",),
        )
    )

    def _es_list_investigations_handler(args: dict[str, Any]) -> Any:
        client = get_splunk_es()
        if client is None:
            return {"ok": False, "error": "Splunk ES is not configured."}
        return client.list_investigations(
            ids=_opt_str_list_or_str(args, "ids"),
            status=_opt_str(args, "status"),
            owner=_opt_str(args, "owner"),
            urgency=_opt_str(args, "urgency"),
            disposition=_opt_str(args, "disposition"),
            normalized_risk_object=_opt_str(args, "normalized_risk_object"),
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
            offset=_opt_int(args, "offset", 0, min_val=0, max_val=10000),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_es_list_investigations",
            source_category=SOURCE_CATEGORY_SPLUNK_ES,
            description="List Splunk ES investigations with optional status/owner/risk filters.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "ids": {"type": "array", "items": {"type": "string"}},
                    "status": {"type": "string"},
                    "owner": {"type": "string"},
                    "urgency": {"type": "string"},
                    "disposition": {"type": "string"},
                    "normalized_risk_object": {"type": "string"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"},
                },
            },
            handler=_es_list_investigations_handler,
            underlying_methods=("list_investigations",),
        )
    )

    def _es_list_risk_events_handler(args: dict[str, Any]) -> Any:
        client = get_splunk_es()
        if client is None:
            return {"ok": False, "error": "Splunk ES is not configured."}
        return client.list_risk_events(
            risk_object=_opt_str(args, "risk_object"),
            earliest=_opt_str(args, "earliest") or "-24h",
            latest=_opt_str(args, "latest") or "now",
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_es_list_risk_events",
            source_category=SOURCE_CATEGORY_SPLUNK_ES,
            description="List Splunk ES risk index events for a risk object or timeframe.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "risk_object": {"type": "string"},
                    "earliest": {"type": "string"},
                    "latest": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
            handler=_es_list_risk_events_handler,
            underlying_methods=("list_risk_events",),
        )
    )

    def _es_lookup_asset_handler(args: dict[str, Any]) -> Any:
        client = get_splunk_es()
        if client is None:
            return {"ok": False, "error": "Splunk ES is not configured."}
        return client.lookup_asset(
            query=_opt_str(args, "query") or "",
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_es_lookup_asset",
            source_category=SOURCE_CATEGORY_SPLUNK_ES,
            description="Look up asset records in the Splunk ES asset identity framework.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
            handler=_es_lookup_asset_handler,
            underlying_methods=("lookup_asset",),
        )
    )

    def _es_lookup_identity_handler(args: dict[str, Any]) -> Any:
        client = get_splunk_es()
        if client is None:
            return {"ok": False, "error": "Splunk ES is not configured."}
        return client.lookup_identity(
            query=_opt_str(args, "query") or "",
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_es_lookup_identity",
            source_category=SOURCE_CATEGORY_SPLUNK_ES,
            description="Look up user/identity records in Splunk ES.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
            handler=_es_lookup_identity_handler,
            underlying_methods=("lookup_identity",),
        )
    )

    def _es_query_threat_intel_handler(args: dict[str, Any]) -> Any:
        client = get_splunk_es()
        if client is None:
            return {"ok": False, "error": "Splunk ES is not configured."}
        collection = _require_str_arg(args, "collection")
        raw_query = args.get("query")
        query_dict = dict(raw_query) if isinstance(raw_query, Mapping) else None
        return client.query_threat_intel(
            collection,
            query=query_dict,
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_es_query_threat_intel",
            source_category=SOURCE_CATEGORY_SPLUNK_ES,
            description="Query a Splunk ES threat intelligence KVStore collection.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "collection": {"type": "string", "enum": list(THREAT_INTEL_COLLECTIONS)},
                    "query": {"type": "object"},
                    "limit": {"type": "integer"},
                },
                "required": ["collection"],
            },
            handler=_es_query_threat_intel_handler,
            underlying_methods=("query_threat_intel",),
        )
    )

    # ------------------------------------------------------------------
    # C. SentinelOne (7 tools)
    # ------------------------------------------------------------------
    def _s1_list_threats_handler(args: dict[str, Any]) -> Any:
        client = get_s1()
        if client is None:
            return {"ok": False, "error": "SentinelOne is not configured."}
        return client.list_threats(
            query=_opt_str(args, "query"),
            incident_statuses=_opt_str_list_or_str(args, "incident_statuses"),
            analyst_verdicts=_opt_str_list_or_str(args, "analyst_verdicts"),
            resolved=args.get("resolved") if isinstance(args.get("resolved"), bool) else None,
            computer_name=_opt_str(args, "computer_name"),
            account_ids=_opt_str_list_or_str(args, "account_ids"),
            site_ids=_opt_str_list_or_str(args, "site_ids"),
            created_after=_opt_str(args, "created_after"),
            created_before=_opt_str(args, "created_before"),
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="s1_list_threats",
            source_category=SOURCE_CATEGORY_S1,
            description="List SentinelOne endpoint threats matching query or status filters.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "incident_statuses": {"type": "array", "items": {"type": "string"}},
                    "analyst_verdicts": {"type": "array", "items": {"type": "string"}},
                    "resolved": {"type": "boolean"},
                    "computer_name": {"type": "string"},
                    "account_ids": {"type": "array", "items": {"type": "string"}},
                    "site_ids": {"type": "array", "items": {"type": "string"}},
                    "created_after": {"type": "string"},
                    "created_before": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
            handler=_s1_list_threats_handler,
            underlying_methods=("list_threats",),
        )
    )

    def _s1_get_threat_timeline_handler(args: dict[str, Any]) -> Any:
        client = get_s1()
        if client is None:
            return {"ok": False, "error": "SentinelOne is not configured."}
        threat_id = _require_str_arg(args, "threat_id")
        return client.get_threat_timeline(
            threat_id,
            limit=_opt_int(args, "limit", 100, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="s1_get_threat_timeline",
            source_category=SOURCE_CATEGORY_S1,
            description="Get timeline events for a SentinelOne threat by threat_id.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "threat_id": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["threat_id"],
            },
            handler=_s1_get_threat_timeline_handler,
            underlying_methods=("get_threat_timeline",),
        )
    )

    def _s1_list_cloud_alerts_handler(args: dict[str, Any]) -> Any:
        client = get_s1()
        if client is None:
            return {"ok": False, "error": "SentinelOne is not configured."}
        return client.list_cloud_alerts(
            query=_opt_str(args, "query"),
            incident_statuses=_opt_str_list_or_str(args, "incident_statuses"),
            analyst_verdicts=_opt_str_list_or_str(args, "analyst_verdicts"),
            severities=_opt_str_list_or_str(args, "severities"),
            rule_name=_opt_str(args, "rule_name"),
            computer_name=_opt_str(args, "computer_name"),
            sha1=_opt_str(args, "sha1"),
            account_ids=_opt_str_list_or_str(args, "account_ids"),
            site_ids=_opt_str_list_or_str(args, "site_ids"),
            created_after=_opt_str(args, "created_after"),
            created_before=_opt_str(args, "created_before"),
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="s1_list_cloud_alerts",
            source_category=SOURCE_CATEGORY_S1,
            description="List SentinelOne Cloud/STAR alerts matching query or IOC filters.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "incident_statuses": {"type": "array", "items": {"type": "string"}},
                    "analyst_verdicts": {"type": "array", "items": {"type": "string"}},
                    "severities": {"type": "array", "items": {"type": "string"}},
                    "rule_name": {"type": "string"},
                    "computer_name": {"type": "string"},
                    "sha1": {"type": "string"},
                    "account_ids": {"type": "array", "items": {"type": "string"}},
                    "site_ids": {"type": "array", "items": {"type": "string"}},
                    "created_after": {"type": "string"},
                    "created_before": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
            handler=_s1_list_cloud_alerts_handler,
            underlying_methods=("list_cloud_alerts",),
        )
    )

    def _s1_list_agents_handler(args: dict[str, Any]) -> Any:
        client = get_s1()
        if client is None:
            return {"ok": False, "error": "SentinelOne is not configured."}
        return client.list_agents(
            query=_opt_str(args, "query"),
            computer_name=_opt_str(args, "computer_name"),
            is_active=args.get("is_active") if isinstance(args.get("is_active"), bool) else None,
            infected=args.get("infected") if isinstance(args.get("infected"), bool) else None,
            network_status=_opt_str(args, "network_status"),
            os_types=_opt_str_list_or_str(args, "os_types"),
            account_ids=_opt_str_list_or_str(args, "account_ids"),
            site_ids=_opt_str_list_or_str(args, "site_ids"),
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="s1_list_agents",
            source_category=SOURCE_CATEGORY_S1,
            description="List SentinelOne endpoint agents matching hostname, OS, or health filters.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "computer_name": {"type": "string"},
                    "is_active": {"type": "boolean"},
                    "infected": {"type": "boolean"},
                    "network_status": {"type": "string"},
                    "os_types": {"type": "array", "items": {"type": "string"}},
                    "account_ids": {"type": "array", "items": {"type": "string"}},
                    "site_ids": {"type": "array", "items": {"type": "string"}},
                    "limit": {"type": "integer"},
                },
            },
            handler=_s1_list_agents_handler,
            underlying_methods=("list_agents",),
        )
    )

    def _s1_get_agent_handler(args: dict[str, Any]) -> Any:
        client = get_s1()
        if client is None:
            return {"ok": False, "error": "SentinelOne is not configured."}
        agent_id = _require_str_arg(args, "agent_id")
        return client.get_agent(agent_id)

    registry.register(
        ReadOnlyToolSpec(
            name="s1_get_agent",
            source_category=SOURCE_CATEGORY_S1,
            description="Fetch detailed SentinelOne metadata for a specific agent_id.",
            parameters_schema={
                "type": "object",
                "properties": {"agent_id": {"type": "string"}},
                "required": ["agent_id"],
            },
            handler=_s1_get_agent_handler,
            underlying_methods=("get_agent",),
        )
    )

    def _s1_list_activities_handler(args: dict[str, Any]) -> Any:
        client = get_s1()
        if client is None:
            return {"ok": False, "error": "SentinelOne is not configured."}
        return client.list_activities(
            activity_types=_opt_str_list_or_str(args, "activity_types"),
            agent_ids=_opt_str_list_or_str(args, "agent_ids"),
            threat_ids=_opt_str_list_or_str(args, "threat_ids"),
            query=_opt_str(args, "query"),
            account_ids=_opt_str_list_or_str(args, "account_ids"),
            site_ids=_opt_str_list_or_str(args, "site_ids"),
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="s1_list_activities",
            source_category=SOURCE_CATEGORY_S1,
            description="List SentinelOne activity audit records for agents or threats.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "activity_types": {"type": "array", "items": {"type": "string"}},
                    "agent_ids": {"type": "array", "items": {"type": "string"}},
                    "threat_ids": {"type": "array", "items": {"type": "string"}},
                    "query": {"type": "string"},
                    "account_ids": {"type": "array", "items": {"type": "string"}},
                    "site_ids": {"type": "array", "items": {"type": "string"}},
                    "limit": {"type": "integer"},
                },
            },
            handler=_s1_list_activities_handler,
            underlying_methods=("list_activities",),
        )
    )

    def _s1_dv_query_handler(args: dict[str, Any]) -> Any:
        client = get_s1()
        if client is None:
            return {"ok": False, "error": "SentinelOne is not configured."}
        query = _require_str_arg(args, "query")
        from_date = _require_str_arg(args, "from_date")
        to_date = _require_str_arg(args, "to_date")
        limit = _opt_int(args, "limit", 100, min_val=1, max_val=200)
        raw_timeout = args.get("poll_timeout_seconds", 15.0)
        poll_timeout = (
            float(raw_timeout)
            if isinstance(raw_timeout, (int, float)) and not isinstance(raw_timeout, bool)
            else 15.0
        )
        poll_timeout = max(0.05, min(poll_timeout, 120.0))
        raw_interval = args.get("poll_interval_seconds", 0.5)
        poll_interval = (
            float(raw_interval)
            if isinstance(raw_interval, (int, float)) and not isinstance(raw_interval, bool)
            else 0.5
        )
        poll_interval = max(0.0, min(poll_interval, 5.0))

        init_resp = client.create_dv_query(
            query,
            from_date,
            to_date,
            account_ids=_opt_str_list_or_str(args, "account_ids"),
            site_ids=_opt_str_list_or_str(args, "site_ids"),
            group_ids=_opt_str_list_or_str(args, "group_ids"),
            query_type=_opt_str(args, "query_type") or "events",
        )
        data_obj = init_resp.get("data") if isinstance(init_resp, Mapping) else None
        query_id = ""
        if isinstance(data_obj, Mapping):
            query_id = str(data_obj.get("queryId") or "").strip()
        if not query_id and isinstance(init_resp, Mapping):
            query_id = str(init_resp.get("queryId") or "").strip()
        if not query_id:
            return {"ok": False, "error": "SentinelOne DV query did not return a queryId."}

        deadline = time.monotonic() + poll_timeout
        max_polls = 200
        polls = 0
        while polls < max_polls:
            polls += 1
            status_resp = client.get_dv_query_status(query_id)
            status_data = status_resp.get("data") if isinstance(status_resp, Mapping) else {}
            if not isinstance(status_data, Mapping):
                status_data = {}
            state = str(status_data.get("responseState") or "").strip().upper()
            progress = status_data.get("progressStatus")

            if state == "EMPTY_RESULTS":
                return {"query_id": query_id, "status": state, "events": []}
            if state in {"FINISHED", "DONE", "COMPLETED"} or progress == 100:
                events = client.get_dv_events(query_id, limit=limit)
                return {"query_id": query_id, "status": state or "FINISHED", "events": events}
            if state in {"FAILED", "ERROR", "CANCELLED", "TIMED_OUT"}:
                return {
                    "ok": False,
                    "error": f"SentinelOne DV query {query_id} ended with state {state}.",
                }
            if time.monotonic() >= deadline:
                break
            if poll_interval > 0:
                time.sleep(poll_interval)

        return {"ok": False, "error": f"SentinelOne DV query {query_id} timed out polling."}

    registry.register(
        ReadOnlyToolSpec(
            name="s1_dv_query",
            source_category=SOURCE_CATEGORY_S1,
            description=(
                "Run a read-only SentinelOne Deep Visibility telemetry query and return events."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "from_date": {"type": "string"},
                    "to_date": {"type": "string"},
                    "account_ids": {"type": "array", "items": {"type": "string"}},
                    "site_ids": {"type": "array", "items": {"type": "string"}},
                    "group_ids": {"type": "array", "items": {"type": "string"}},
                    "query_type": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query", "from_date", "to_date"],
            },
            handler=_s1_dv_query_handler,
            underlying_methods=("create_dv_query", "get_dv_query_status", "get_dv_events"),
        )
    )

    # ------------------------------------------------------------------
    # D. Recorded Future (8 tools)
    # ------------------------------------------------------------------
    def _rf_search_alerts_handler(args: dict[str, Any]) -> Any:
        client = get_rf()
        if client is None:
            return {"ok": False, "error": "Recorded Future is not configured."}
        return client.search_alerts_v3(
            triggered=_opt_str(args, "triggered"),
            assignee=_opt_str(args, "assignee"),
            status_in_portal=_opt_str(args, "status_in_portal"),
            alert_rule=_opt_str(args, "alert_rule"),
            freetext=_opt_str(args, "freetext"),
            fields=_opt_str_list_or_str(args, "fields"),
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
            offset=_opt_int(args, "offset", 0, min_val=0, max_val=800),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="rf_search_alerts",
            source_category=SOURCE_CATEGORY_RF,
            description="Search Recorded Future classic alerts v3 matching rule/status/text.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "triggered": {"type": "string"},
                    "assignee": {"type": "string"},
                    "status_in_portal": {"type": "string"},
                    "alert_rule": {"type": "string"},
                    "freetext": {"type": "string"},
                    "fields": {"type": "array", "items": {"type": "string"}},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"},
                },
            },
            handler=_rf_search_alerts_handler,
            underlying_methods=("search_alerts_v3",),
        )
    )

    def _rf_get_alert_handler(args: dict[str, Any]) -> Any:
        client = get_rf()
        if client is None:
            return {"ok": False, "error": "Recorded Future is not configured."}
        alert_id = _require_str_arg(args, "alert_id")
        return client.get_alert_v3(
            alert_id,
            fields=_opt_str_list_or_str(args, "fields"),
            tagged_text=_opt_bool(args, "tagged_text", False),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="rf_get_alert",
            source_category=SOURCE_CATEGORY_RF,
            description="Fetch full Recorded Future classic alert v3 details by alert_id.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string"},
                    "fields": {"type": "array", "items": {"type": "string"}},
                    "tagged_text": {"type": "boolean"},
                },
                "required": ["alert_id"],
            },
            handler=_rf_get_alert_handler,
            underlying_methods=("get_alert_v3",),
        )
    )

    def _rf_search_playbook_alerts_handler(args: dict[str, Any]) -> Any:
        client = get_rf()
        if client is None:
            return {"ok": False, "error": "Recorded Future is not configured."}
        return client.search_playbook_alerts(
            categories=_opt_str_list(args, "categories"),
            statuses=_opt_str_list(args, "statuses"),
            priorities=_opt_str_list(args, "priorities"),
            entities=_opt_str_list(args, "entities"),
            limit=_opt_int(args, "limit", 50, min_val=1, max_val=200),
            offset=_opt_str(args, "offset"),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="rf_search_playbook_alerts",
            source_category=SOURCE_CATEGORY_RF,
            description="Search Recorded Future Playbook Alerts by category, status, or entity.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "categories": {"type": "array", "items": {"type": "string"}},
                    "statuses": {"type": "array", "items": {"type": "string"}},
                    "priorities": {"type": "array", "items": {"type": "string"}},
                    "entities": {"type": "array", "items": {"type": "string"}},
                    "limit": {"type": "integer"},
                    "offset": {"type": "string"},
                },
            },
            handler=_rf_search_playbook_alerts_handler,
            underlying_methods=("search_playbook_alerts",),
        )
    )

    def _rf_get_playbook_alert_handler(args: dict[str, Any]) -> Any:
        client = get_rf()
        if client is None:
            return {"ok": False, "error": "Recorded Future is not configured."}
        alert_id = _require_str_arg(args, "alert_id")
        category = _opt_str(args, "category")
        if category is not None:
            return client.get_playbook_alert(
                category,
                alert_id,
                panels=_opt_str_list(args, "panels"),
            )
        return client.get_playbook_alert_preview(alert_id)

    registry.register(
        ReadOnlyToolSpec(
            name="rf_get_playbook_alert",
            source_category=SOURCE_CATEGORY_RF,
            description="Fetch Recorded Future Playbook Alert panels (or preview if category omitted).",
            parameters_schema={
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string"},
                    "category": {"type": "string"},
                    "panels": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["alert_id"],
            },
            handler=_rf_get_playbook_alert_handler,
            underlying_methods=("get_playbook_alert", "get_playbook_alert_preview"),
        )
    )

    def _rf_lookup_ioc_or_cve_handler(args: dict[str, Any]) -> Any:
        client = get_rf()
        if client is None:
            return {"ok": False, "error": "Recorded Future is not configured."}
        value = _require_str_arg(args, "value")
        entity_type = _opt_str(args, "entity_type") or _infer_rf_v2_entity_type(value)
        return client.v2_lookup(
            entity_type,
            value,
            fields=_opt_str_list_or_str(args, "fields"),
            metadata=_opt_bool(args, "metadata", False),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="rf_lookup_ioc_or_cve",
            source_category=SOURCE_CATEGORY_RF,
            description="Look up an IP, domain, hash, URL, CVE, malware, or company in Recorded Future Connect v2.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "entity_type": {"type": "string"},
                    "fields": {"type": "array", "items": {"type": "string"}},
                    "metadata": {"type": "boolean"},
                },
                "required": ["value"],
            },
            handler=_rf_lookup_ioc_or_cve_handler,
            underlying_methods=("v2_lookup",),
        )
    )

    def _rf_search_analyst_notes_handler(args: dict[str, Any]) -> Any:
        client = get_rf()
        if client is None:
            return {"ok": False, "error": "Recorded Future is not configured."}
        return client.search_analyst_notes(
            entity=_opt_str(args, "entity"),
            topic=_opt_str(args, "topic"),
            title=_opt_str(args, "title"),
            label=_opt_str(args, "label"),
            source=_opt_str(args, "source"),
            published=_opt_str(args, "published"),
            limit=_opt_int(args, "limit", 20, min_val=1, max_val=100),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="rf_search_analyst_notes",
            source_category=SOURCE_CATEGORY_RF,
            description="Search Recorded Future Insikt Group / Analyst Notes.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "entity": {"type": "string"},
                    "topic": {"type": "string"},
                    "title": {"type": "string"},
                    "label": {"type": "string"},
                    "source": {"type": "string"},
                    "published": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
            handler=_rf_search_analyst_notes_handler,
            underlying_methods=("search_analyst_notes",),
        )
    )

    def _rf_soar_enrich_handler(args: dict[str, Any]) -> Any:
        client = get_rf()
        if client is None:
            return {"ok": False, "error": "Recorded Future is not configured."}
        raw_iocs = args.get("iocs")
        if not isinstance(raw_iocs, Mapping) or not raw_iocs:
            raise ValueError("Missing or empty required 'iocs' mapping argument.")
        normalized_iocs: dict[str, list[str]] = {}
        for k, v in raw_iocs.items():
            if isinstance(v, Sequence) and not isinstance(v, str):
                vals = [str(item).strip() for item in v if str(item).strip()]
                if vals:
                    normalized_iocs[str(k)] = vals
        if not normalized_iocs:
            raise ValueError("'iocs' mapping must contain at least one non-empty IOC list.")
        return client.soar_enrich(
            normalized_iocs,
            metadata=_opt_bool(args, "metadata", False),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="rf_soar_enrich",
            source_category=SOURCE_CATEGORY_RF,
            description="Batch-enrich IPs, domains, hashes, URLs, or CVEs via Recorded Future SOAR v3.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "iocs": {"type": "object"},
                    "metadata": {"type": "boolean"},
                },
                "required": ["iocs"],
            },
            handler=_rf_soar_enrich_handler,
            underlying_methods=("soar_enrich",),
        )
    )

    def _rf_links_search_handler(args: dict[str, Any]) -> Any:
        client = get_rf()
        if client is None:
            return {"ok": False, "error": "Recorded Future is not configured."}
        entities = _opt_str_list(args, "entities")
        if not entities:
            raise ValueError("Missing or empty required 'entities' list argument.")
        raw_per_type = args.get("per_entity_type")
        per_entity_type = (
            int(raw_per_type)
            if isinstance(raw_per_type, int) and not isinstance(raw_per_type, bool)
            else None
        )
        return client.links_search(
            entities,
            sections=_opt_str_list(args, "sections"),
            entity_types=_opt_str_list(args, "entity_types"),
            timeframe=_opt_str(args, "timeframe"),
            search_scope=_opt_str(args, "search_scope") or "medium",
            per_entity_type=per_entity_type,
        )

    registry.register(
        ReadOnlyToolSpec(
            name="rf_links_search",
            source_category=SOURCE_CATEGORY_RF,
            description="Query Recorded Future entity relationship links across threat intel.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "entities": {"type": "array", "items": {"type": "string"}},
                    "sections": {"type": "array", "items": {"type": "string"}},
                    "entity_types": {"type": "array", "items": {"type": "string"}},
                    "timeframe": {"type": "string"},
                    "search_scope": {"type": "string"},
                    "per_entity_type": {"type": "integer"},
                },
                "required": ["entities"],
            },
            handler=_rf_links_search_handler,
            underlying_methods=("links_search",),
        )
    )

    # ------------------------------------------------------------------
    # E. Watchlists & OSINT (4 tools)
    # ------------------------------------------------------------------
    def _rf_get_watchlists_handler(args: dict[str, Any]) -> Any:
        client = get_rf()
        if client is None:
            return {"ok": False, "error": "Recorded Future is not configured."}
        return client.get_watchlists(
            list_types=_opt_str_list_or_str(args, "list_types"),
            name=_opt_str(args, "name"),
            limit=_opt_int(args, "limit", 100, min_val=1, max_val=200),
            include_all_types=_opt_bool(args, "include_all_types", True),
        )

    registry.register(
        ReadOnlyToolSpec(
            name="rf_get_watchlists",
            source_category=SOURCE_CATEGORY_OSINT,
            description="List Recorded Future watchlists (read-only metadata).",
            parameters_schema={
                "type": "object",
                "properties": {
                    "list_types": {"type": "array", "items": {"type": "string"}},
                    "name": {"type": "string"},
                    "limit": {"type": "integer"},
                    "include_all_types": {"type": "boolean"},
                },
            },
            handler=_rf_get_watchlists_handler,
            underlying_methods=("get_watchlists",),
        )
    )

    def _rf_get_watchlist_entities_handler(args: dict[str, Any]) -> Any:
        client = get_rf()
        if client is None:
            return {"ok": False, "error": "Recorded Future is not configured."}
        list_id = _require_str_arg(args, "list_id")
        entries = client.get_watchlist_entities(list_id)
        query = _opt_str(args, "query")
        if query and isinstance(entries, list):
            return filter_watchlist_entities(entries, query)
        return entries

    registry.register(
        ReadOnlyToolSpec(
            name="rf_get_watchlist_entities",
            source_category=SOURCE_CATEGORY_OSINT,
            description="Fetch entities belonging to a Recorded Future watchlist.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "list_id": {"type": "string"},
                    "query": {"type": "string"},
                },
                "required": ["list_id"],
            },
            handler=_rf_get_watchlist_entities_handler,
            underlying_methods=("get_watchlist_entities",),
        )
    )

    def _osint_enrich_target_handler(args: dict[str, Any]) -> Any:
        client = get_osint()
        if client is None:
            return {"ok": False, "error": "OSINT client is not configured."}
        target = _require_str_arg(args, "target")
        kind = _opt_str(args, "kind")
        if kind is None:
            try:
                kind = classify_research_target(target).detected_kind
            except Exception:
                kind = "auto"
        outcomes = client.enrich_target(
            target,
            kind,
            extracted_domain=_opt_str(args, "extracted_domain"),
            sources=_opt_str_list(args, "sources"),
        )
        return {k: _to_json_safe(v) for k, v in outcomes.items()}

    registry.register(
        ReadOnlyToolSpec(
            name="osint_enrich_target",
            source_category=SOURCE_CATEGORY_OSINT,
            description="Enrich an IP, domain, hash, URL, or CVE using passive OSINT sources.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "kind": {"type": "string"},
                    "extracted_domain": {"type": "string"},
                    "sources": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["target"],
            },
            handler=_osint_enrich_target_handler,
            underlying_methods=("enrich_target",),
        )
    )

    def _unified_research_target_handler(args: dict[str, Any]) -> Any:
        query = _require_str_arg(args, "query")
        want_rf = _opt_bool(args, "include_rf", True)
        want_osint = _opt_bool(args, "include_osint", True)
        rf = get_rf() if want_rf else None
        osint = get_osint() if want_osint else None
        effective_rf = rf if want_rf else None
        if effective_rf is None and not (want_osint and osint is not None):
            return {
                "ok": False,
                "error": "Neither Recorded Future nor OSINT client is configured.",
            }
        dossier = active_research_fn(
            effective_rf,
            query,
            explicit_type=_opt_str(args, "explicit_type"),
            modules=_opt_str_list(args, "modules"),
            deep=_opt_bool(args, "deep", False),
            include_rf=bool(effective_rf is not None and want_rf),
            include_osint=bool(osint is not None and want_osint),
            osint_sources=_opt_str_list(args, "osint_sources"),
            osint_client=osint,
            limit=_opt_int(args, "limit", 20, min_val=1, max_val=100),
        )
        if hasattr(dossier, "to_dict") and callable(dossier.to_dict):
            return dossier.to_dict()
        return _to_json_safe(dossier)

    registry.register(
        ReadOnlyToolSpec(
            name="unified_research_target",
            source_category=SOURCE_CATEGORY_OSINT,
            description="Run unified Recorded Future + passive OSINT threat research on an observable.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "explicit_type": {"type": "string"},
                    "modules": {"type": "array", "items": {"type": "string"}},
                    "deep": {"type": "boolean"},
                    "include_rf": {"type": "boolean"},
                    "include_osint": {"type": "boolean"},
                    "osint_sources": {"type": "array", "items": {"type": "string"}},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
            handler=_unified_research_target_handler,
            underlying_methods=("research_target",),
        )
    )

    # ------------------------------------------------------------------
    # F. Local DB-First Tools (3 tools, zero external API calls)
    # ------------------------------------------------------------------
    def _local_search_alerts_history_handler(args: dict[str, Any]) -> Any:
        query = _opt_str(args, "query") or ""
        source = _opt_str(args, "source")
        limit = _opt_int(args, "limit", 25, min_val=1, max_val=200)
        stor = get_storage()
        if not query or stor is None:
            return {"ok": True, "query": query, "count": 0, "items": []}
        try:
            rows = stor.search_alerts_history(query, source=source, limit=limit)
        except TypeError:
            rows = stor.search_alerts_history(query, limit=limit)
        safe_rows = redact_sensitive_data(list(rows) if isinstance(rows, Sequence) else [])
        items = _to_json_safe(safe_rows) if isinstance(safe_rows, list) else []
        return {"ok": True, "query": query, "count": len(items), "items": items}

    registry.register(
        ReadOnlyToolSpec(
            name="local_search_alerts_history",
            source_category=SOURCE_CATEGORY_LOCAL,
            description=(
                "Search SOCLens's local historical alerts database (SQLite FTS5 / SQL DB) "
                "before issuing external SOC API queries."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "source": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
            handler=_local_search_alerts_history_handler,
            underlying_methods=("search_alerts_history",),
        )
    )

    def _local_lookup_ioc_sightings_handler(args: dict[str, Any]) -> Any:
        indicator = _opt_str(args, "indicator") or ""
        limit = _opt_int(args, "limit", 50, min_val=1, max_val=200)
        stor = get_storage()
        if not indicator or stor is None:
            return {"ok": True, "indicator": indicator, "count": 0, "sightings": []}
        try:
            rows = stor.lookup_ioc_sightings(indicator, limit=limit)
        except TypeError:
            rows = stor.lookup_ioc_sightings(indicator)
        safe_rows = redact_sensitive_data(list(rows) if isinstance(rows, Sequence) else [])
        sightings = _to_json_safe(safe_rows) if isinstance(safe_rows, list) else []
        return {"ok": True, "indicator": indicator, "count": len(sightings), "sightings": sightings}

    registry.register(
        ReadOnlyToolSpec(
            name="local_lookup_ioc_sightings",
            source_category=SOURCE_CATEGORY_LOCAL,
            description=(
                "Look up historical local sightings of an IP, CIDR, domain, hash, or CVE "
                "in SOCLens's local database before calling external threat intel APIs."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "indicator": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["indicator"],
            },
            handler=_local_lookup_ioc_sightings_handler,
            underlying_methods=("lookup_ioc_sightings",),
        )
    )

    def _local_search_soc_knowledge_handler(args: dict[str, Any]) -> Any:
        query = _opt_str(args, "query") or ""
        category = _opt_str(args, "category")
        limit = _opt_int(args, "limit", 20, min_val=1, max_val=200)
        if not query:
            return {"ok": True, "query": query, "count": 0, "entries": []}
        lm = get_learning_manager()
        stor = get_storage()
        raw_entries: Any = []
        if lm is not None and callable(getattr(lm, "match_relevant_entries", None)):
            matched = lm.match_relevant_entries(query, max_chars=4000)
            items_list = list(matched) if isinstance(matched, Sequence) else []
            if category:
                items_list = [
                    it
                    for it in items_list
                    if (
                        it.get("category")
                        if isinstance(it, Mapping)
                        else getattr(it, "category", None)
                    )
                    == category
                ]
            raw_entries = items_list[:limit]
        elif stor is not None:
            try:
                raw_entries = stor.search_learnings(
                    query,
                    status="active",
                    category=category,
                    limit=limit,
                )
            except TypeError:
                raw_entries = stor.search_learnings(query, limit=limit)
        safe_raw = _to_json_safe(list(raw_entries) if isinstance(raw_entries, Sequence) else [])
        redacted_entries = redact_sensitive_data(safe_raw, preserve_env_var_refs=True)
        entries = redacted_entries if isinstance(redacted_entries, list) else []
        return {"ok": True, "query": query, "count": len(entries), "entries": entries}

    registry.register(
        ReadOnlyToolSpec(
            name="local_search_soc_knowledge",
            source_category=SOURCE_CATEGORY_LOCAL,
            description=(
                "Search SOCLens's local base knowledge, playbooks, and learned SOC facts "
                "before issuing external queries."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "category": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
            handler=_local_search_soc_knowledge_handler,
            underlying_methods=("search_learnings",),
        )
    )

    return registry


__all__ = [
    "ClientOrFactory",
    "FORBIDDEN_MUTATING_METHOD_NAMES",
    "FORBIDDEN_SPL_COMMANDS",
    "READONLY_TOOL_NAMES",
    "ReadOnlyToolRegistry",
    "ReadOnlyToolSpec",
    "build_default_readonly_registry",
    "validate_readonly_spl",
]
