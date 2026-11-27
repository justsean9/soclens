"""Hermes-inspired SOC self-learning, base-knowledge seeding, and passive discovery."""

from __future__ import annotations

import hashlib
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from soclens.agent_audit import AuditEntry, AuditLogStore, redact_sensitive_data
from soclens.agent_guards import (
    LearningGuardResult,
    PromptAndSecretGuard,
    scan_candidate,
)
from soclens.agent_policy import AIPolicyStore, LearningMode, _normalize_learning_mode
from soclens.config import get_workspace_dir

if TYPE_CHECKING:
    from soclens.storage import StorageManager

VALID_LEARNING_CATEGORIES: tuple[str, ...] = (
    "environment_fact",
    "playbook",
    "escalation_rule",
    "benign_tool",
    "watchlist",
    "takeaway",
)
VALID_LEARNING_SOURCES: tuple[str, ...] = (
    "base_seed",
    "passive_discovery",
    "manual_learn",
    "ai_takeaway",
)
VALID_LEARNING_STATUSES: tuple[str, ...] = (
    "pending",
    "active",
    "rolled_back",
    "blocked",
)

_QUERY_TOKEN_RE = re.compile(r"[a-z0-9_.-]{2,}")
_MD_HEADING_RE = re.compile(r"^\s{0,3}#+\s+(.+?)\s*$")


@dataclass
class SOCLearningEntry:
    """Single persisted SOC knowledge, playbook, or passively learned fact."""

    id: str
    fingerprint: str
    category: str
    title: str
    content: str
    source: str
    status: str
    confidence: float = 1.0
    seen_count: int = 1
    use_count: int = 0
    pinned: bool = False
    tags: list[str] = field(default_factory=list)
    created_by: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize entry into a JSON-safe dictionary."""
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "category": self.category,
            "title": self.title,
            "content": self.content,
            "source": self.source,
            "status": self.status,
            "confidence": float(self.confidence),
            "seen_count": int(self.seen_count),
            "use_count": int(self.use_count),
            "pinned": bool(self.pinned),
            "tags": list(self.tags),
            "created_by": self.created_by,
            "created_at": float(self.created_at),
            "updated_at": float(self.updated_at),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> SOCLearningEntry:
        """Construct ``SOCLearningEntry`` from a storage mapping."""
        raw_tags = raw.get("tags")
        tags = [str(t) for t in raw_tags] if isinstance(raw_tags, Sequence) and not isinstance(raw_tags, (str, bytes)) else []
        return cls(
            id=str(raw.get("id") or ""),
            fingerprint=str(raw.get("fingerprint") or ""),
            category=str(raw.get("category") or "environment_fact"),
            title=str(raw.get("title") or ""),
            content=str(raw.get("content") or ""),
            source=str(raw.get("source") or "manual_learn"),
            status=str(raw.get("status") or "active"),
            confidence=float(raw.get("confidence", 1.0)),
            seen_count=int(raw.get("seen_count", 1)),
            use_count=int(raw.get("use_count", 0)),
            pinned=bool(raw.get("pinned", False)),
            tags=tags,
            created_by=str(raw.get("created_by") or ""),
            created_at=float(raw.get("created_at", 0.0)),
            updated_at=float(raw.get("updated_at", 0.0)),
        )


def _compute_fingerprint(category: str, key: str) -> str:
    return hashlib.sha256(f"{category}:{key.strip().lower()}".encode()).hexdigest()[:32]


def _normalize_category(category: str | None) -> str:
    clean = str(category or "environment_fact").strip().lower()
    if clean in VALID_LEARNING_CATEGORIES:
        return clean
    return "environment_fact"


def _clamp_confidence(value: Any, default: float = 0.75) -> float:
    if isinstance(value, bool):
        return default
    try:
        num = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, num))


def _flatten_strings(obj: Any, *, limit: int = 4000) -> str:
    parts: list[str] = []

    def _walk(val: Any) -> None:
        if sum(len(p) for p in parts) >= limit:
            return
        if isinstance(val, str):
            clean = val.strip()
            if clean:
                parts.append(clean)
        elif isinstance(val, Mapping):
            for v in val.values():
                _walk(v)
        elif isinstance(val, Sequence) and not isinstance(val, (bytes, bytearray)):
            for item in val:
                _walk(item)

    _walk(obj)
    return "\n".join(parts)[:limit]


class PassiveEnvironmentDiscoverer:
    """Zero-API-call structured fact extractor over read-only SOC tool outputs."""

    def extract(
        self,
        *,
        tool_name: str,
        tool_args: Mapping[str, Any] | None,
        tool_output: Any,
    ) -> list[dict[str, Any]]:
        """Extract structured environment learning candidates from ``tool_output``."""
        _ = tool_args
        if tool_output is None:
            return []
        if isinstance(tool_output, Mapping):
            if tool_output.get("ok") is False or tool_output.get("blocked") is True:
                return []
            if not tool_output:
                return []
        elif isinstance(tool_output, Sequence) and not isinstance(tool_output, (str, bytes)):
            if not tool_output:
                return []
        else:
            return []

        clean_tool = str(tool_name or "").strip().lower()
        outer_conf = (
            tool_output.get("confidence") if isinstance(tool_output, Mapping) else None
        )

        if clean_tool == "splunk_list_indexes":
            return self._extract_splunk_indexes(tool_output, outer_conf)
        if clean_tool == "splunk_search":
            return self._extract_splunk_search(tool_output, outer_conf)
        if clean_tool == "splunk_list_saved_searches":
            return self._extract_splunk_saved_searches(tool_output, outer_conf)
        if clean_tool in {"splunk_es_list_notables", "splunk_es_get_finding"}:
            return self._extract_es_notables(tool_output, outer_conf)
        if clean_tool in {"splunk_es_lookup_asset", "splunk_es_lookup_identity"}:
            return self._extract_es_assets_identities(clean_tool, tool_output, outer_conf)
        if clean_tool in {"s1_list_agents", "s1_get_agent", "s1_get_agent_details"}:
            return self._extract_s1_agents(tool_output, outer_conf)
        if clean_tool in {"s1_list_threats", "s1_get_threat_details"}:
            return self._extract_s1_threats(tool_output, outer_conf)
        if clean_tool == "rf_get_watchlists":
            return self._extract_rf_watchlists(tool_output, outer_conf)
        if clean_tool in {"rf_search_alerts", "rf_search_playbook_alerts"}:
            return self._extract_rf_alerts(clean_tool, tool_output, outer_conf)
        return []

    @staticmethod
    def _unwrap_items(tool_output: Any, *keys: str) -> list[Mapping[str, Any]]:
        single_object_keys = (
            "name",
            "rule_name",
            "orig_rule_title",
            "siteName",
            "siteId",
            "osType",
            "osName",
            "processName",
            "threatInfo",
            "computerName",
        )
        if isinstance(tool_output, Sequence) and not isinstance(tool_output, (str, bytes)):
            return [item for item in tool_output if isinstance(item, Mapping)]
        if isinstance(tool_output, Mapping):
            for key in keys:
                val = tool_output.get(key)
                if isinstance(val, Sequence) and not isinstance(val, (str, bytes)):
                    return [item for item in val if isinstance(item, Mapping)]
                if isinstance(val, Mapping):
                    nested = val.get("results") or val.get("items") or val.get("data")
                    if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes)):
                        return [item for item in nested if isinstance(item, Mapping)]
                    if any(k in val for k in single_object_keys):
                        return [val]
            if any(k in tool_output for k in single_object_keys):
                return [tool_output]
        return []

    def _extract_splunk_indexes(self, tool_output: Any, outer_conf: Any) -> list[dict[str, Any]]:
        items = self._unwrap_items(tool_output, "indexes", "results", "data")
        candidates: list[dict[str, Any]] = []
        for idx in items[:25]:
            name = str(idx.get("name") or idx.get("title") or "").strip()
            if not name:
                continue
            raw_count = idx.get("totalEventCount", idx.get("total_event_count"))
            count_str = ""
            state = "active"
            if raw_count is not None:
                try:
                    cnt = int(raw_count)
                    state = "active" if cnt > 0 else "empty"
                    count_str = f" (events={cnt})"
                except (TypeError, ValueError):
                    pass
            if idx.get("disabled") is True:
                state = "disabled"
            extra_notes: list[str] = []
            for extra_k in ("description", "note", "datatype"):
                extra_v = idx.get(extra_k)
                if isinstance(extra_v, str) and extra_v.strip():
                    extra_notes.append(f"{extra_k}: {extra_v.strip()}")
            note_suffix = f" — {'; '.join(extra_notes)}" if extra_notes else ""
            conf = _clamp_confidence(idx.get("confidence", outer_conf), 0.75 if state == "active" else 0.65)
            candidates.append(
                {
                    "fingerprint": _compute_fingerprint("environment_fact", f"splunk_index:{name}"),
                    "category": "environment_fact",
                    "title": f"Splunk Index: {name} ({state})",
                    "content": f"Splunk index '{name}' is {state}{count_str}{note_suffix}.",
                    "tags": ["splunk", "index", name],
                    "confidence": conf,
                    "entity_tokens": [name.lower()],
                    "raw_blob": _flatten_strings(idx),
                }
            )
        return candidates

    def _extract_splunk_search(self, tool_output: Any, outer_conf: Any) -> list[dict[str, Any]]:
        if not isinstance(tool_output, Mapping):
            return []
        rows = tool_output.get("results")
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
            return []
        seen_pairs: set[tuple[str, str]] = set()
        candidates: list[dict[str, Any]] = []
        for row in rows[:30]:
            if not isinstance(row, Mapping):
                continue
            index_name = str(row.get("index") or "").strip()
            sourcetype = str(row.get("sourcetype") or "").strip()
            if not index_name and not sourcetype:
                continue
            pair = (index_name, sourcetype)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            fields_list = [str(k) for k in list(row.keys())[:10]]
            label = f"index={index_name or '*'} sourcetype={sourcetype or '*'}"
            candidates.append(
                {
                    "fingerprint": _compute_fingerprint(
                        "environment_fact", f"splunk_sourcetype:{index_name}:{sourcetype}"
                    ),
                    "category": "environment_fact",
                    "title": f"Splunk Telemetry Schema: {label}",
                    "content": (
                        f"Observed Splunk telemetry {label} with fields: {', '.join(fields_list)}."
                    ),
                    "tags": ["splunk", "sourcetype", *(t for t in (index_name, sourcetype) if t)],
                    "confidence": _clamp_confidence(outer_conf, 0.75),
                    "entity_tokens": [t.lower() for t in (index_name, sourcetype) if t],
                    "raw_blob": _flatten_strings(row),
                }
            )
        return candidates

    def _extract_splunk_saved_searches(
        self, tool_output: Any, outer_conf: Any
    ) -> list[dict[str, Any]]:
        items = self._unwrap_items(tool_output, "saved_searches", "results", "data")
        candidates: list[dict[str, Any]] = []
        for item in items[:20]:
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            app = str(item.get("app") or "").strip()
            candidates.append(
                {
                    "fingerprint": _compute_fingerprint("environment_fact", f"splunk_saved:{name}"),
                    "category": "environment_fact",
                    "title": f"Splunk Saved Search: {name}",
                    "content": f"Splunk saved search '{name}' configured (app={app or 'default'}).",
                    "tags": ["splunk", "saved_search", *(t for t in (app,) if t)],
                    "confidence": _clamp_confidence(item.get("confidence", outer_conf), 0.75),
                    "entity_tokens": [name.lower()],
                    "raw_blob": _flatten_strings(item),
                }
            )
        return candidates

    def _extract_es_notables(self, tool_output: Any, outer_conf: Any) -> list[dict[str, Any]]:
        items = self._unwrap_items(tool_output, "notables", "findings", "results", "data")
        seen_rules: set[str] = set()
        candidates: list[dict[str, Any]] = []
        for item in items[:20]:
            rule = str(
                item.get("rule_name") or item.get("orig_rule_title") or item.get("title") or ""
            ).strip()
            if not rule or rule.lower() in seen_rules:
                continue
            seen_rules.add(rule.lower())
            domain = str(item.get("security_domain") or "threat").strip()
            urgency = str(item.get("urgency") or item.get("severity") or "medium").strip()
            candidates.append(
                {
                    "fingerprint": _compute_fingerprint("environment_fact", f"es_rule:{rule}"),
                    "category": "environment_fact",
                    "title": f"Splunk ES Correlation Rule: {rule}",
                    "content": (
                        f"Splunk ES correlation rule '{rule}' active "
                        f"(security_domain={domain}, urgency={urgency})."
                    ),
                    "tags": ["splunk_es", "correlation_rule", domain],
                    "confidence": _clamp_confidence(item.get("confidence", outer_conf), 0.75),
                    "entity_tokens": [rule.lower()],
                    "raw_blob": _flatten_strings(item),
                }
            )
        return candidates

    def _extract_es_assets_identities(
        self, clean_tool: str, tool_output: Any, outer_conf: Any
    ) -> list[dict[str, Any]]:
        items = self._unwrap_items(tool_output, "assets", "identities", "results", "data")
        candidates: list[dict[str, Any]] = []
        kind = "asset" if "asset" in clean_tool else "identity"
        for item in items[:15]:
            ident = str(
                item.get("nt_host")
                or item.get("dns")
                or item.get("ip")
                or item.get("identity")
                or item.get("email")
                or ""
            ).strip()
            if not ident:
                continue
            bunit = str(item.get("bunit") or item.get("owner") or "").strip()
            prio = str(item.get("priority") or "").strip()
            candidates.append(
                {
                    "fingerprint": _compute_fingerprint(
                        "environment_fact", f"es_{kind}:{ident}"
                    ),
                    "category": "environment_fact",
                    "title": f"Splunk ES {kind.title()}: {ident}",
                    "content": (
                        f"Splunk ES {kind} '{ident}' observed "
                        f"(priority={prio or 'normal'}, owner/bunit={bunit or 'unspecified'})."
                    ),
                    "tags": ["splunk_es", kind],
                    "confidence": _clamp_confidence(item.get("confidence", outer_conf), 0.75),
                    "entity_tokens": [ident.lower()],
                    "raw_blob": _flatten_strings(item),
                }
            )
        return candidates

    def _extract_s1_agents(self, tool_output: Any, outer_conf: Any) -> list[dict[str, Any]]:
        items = self._unwrap_items(tool_output, "agents", "data", "results")
        seen_site_os: set[tuple[str, str]] = set()
        candidates: list[dict[str, Any]] = []
        for agent in items[:30]:
            site = str(agent.get("siteName") or agent.get("siteId") or "").strip()
            os_type = str(agent.get("osType") or agent.get("osName") or "").strip()
            if not site and not os_type:
                continue
            key = (site or "Default", os_type or "unknown")
            if key in seen_site_os:
                continue
            seen_site_os.add(key)
            candidates.append(
                {
                    "fingerprint": _compute_fingerprint(
                        "environment_fact", f"s1_site_os:{key[0]}:{key[1]}"
                    ),
                    "category": "environment_fact",
                    "title": f"SentinelOne Site & OS: {key[0]} ({key[1]})",
                    "content": (
                        f"SentinelOne site '{key[0]}' hosts endpoints running '{key[1]}'."
                    ),
                    "tags": ["sentinelone", "site", key[0], key[1]],
                    "confidence": _clamp_confidence(agent.get("confidence", outer_conf), 0.75),
                    "entity_tokens": [key[0].lower(), key[1].lower()],
                    "raw_blob": _flatten_strings(agent),
                }
            )
        return candidates

    def _extract_s1_threats(self, tool_output: Any, outer_conf: Any) -> list[dict[str, Any]]:
        items = self._unwrap_items(tool_output, "threats", "data", "results")
        candidates: list[dict[str, Any]] = []
        for item in items[:20]:
            threat_info = item.get("threatInfo")
            ti = threat_info if isinstance(threat_info, Mapping) else {}
            agent_info = item.get("agentDetectionInfo")
            ai = agent_info if isinstance(agent_info, Mapping) else {}

            proc = str(
                item.get("processName")
                or ti.get("processName")
                or item.get("threatName")
                or ti.get("threatName")
                or ""
            ).strip()
            if not proc:
                continue
            classification = str(
                item.get("classification") or ti.get("classification") or ""
            ).strip()
            signer = str(
                item.get("signerIdentity")
                or ti.get("signerIdentity")
                or item.get("publisherName")
                or ti.get("publisherName")
                or ""
            ).strip()
            site = str(item.get("siteName") or ai.get("siteName") or "").strip()
            raw_conf = item.get("confidence", outer_conf)
            if raw_conf is None:
                lvl = str(ti.get("confidenceLevel") or "").strip().lower()
                if lvl in {"malicious", "high"}:
                    raw_conf = 0.85
                elif lvl in {"suspicious", "medium"}:
                    raw_conf = 0.65
            conf = _clamp_confidence(raw_conf, 0.70)
            is_benign_signed = bool(signer) and "benign" in classification.lower()
            category = "benign_tool" if is_benign_signed else "environment_fact"
            details = [p for p in (classification, f"signer={signer}" if signer else "", f"site={site}" if site else "") if p]
            detail_str = f" ({', '.join(details)})" if details else ""
            candidates.append(
                {
                    "fingerprint": _compute_fingerprint(category, f"s1_process:{proc}"),
                    "category": category,
                    "title": f"SentinelOne Observed Process: {proc}",
                    "content": f"SentinelOne telemetry observed '{proc}'{detail_str}.",
                    "tags": ["sentinelone", "process", proc],
                    "confidence": conf,
                    "entity_tokens": [proc.lower()],
                    "raw_blob": _flatten_strings(item),
                }
            )
        return candidates

    def _extract_rf_watchlists(self, tool_output: Any, outer_conf: Any) -> list[dict[str, Any]]:
        items = self._unwrap_items(tool_output, "watchlists", "data", "results")
        candidates: list[dict[str, Any]] = []
        for wl in items[:25]:
            name = str(wl.get("name") or wl.get("title") or "").strip()
            if not name:
                continue
            wl_id = str(wl.get("id") or "").strip()
            wl_type = str(wl.get("type") or "watchlist").strip()
            conf = _clamp_confidence(wl.get("confidence", outer_conf), 0.75)
            candidates.append(
                {
                    "fingerprint": _compute_fingerprint("watchlist", f"rf_watchlist:{name}"),
                    "category": "watchlist",
                    "title": f"Recorded Future Watchlist: {name}",
                    "content": (
                        f"Recorded Future watchlist '{name}' "
                        f"(id={wl_id or 'unknown'}, type={wl_type}) is configured."
                    ),
                    "tags": ["recorded_future", "watchlist", name],
                    "confidence": conf,
                    "entity_tokens": [name.lower()],
                    "raw_blob": _flatten_strings(wl),
                }
            )
        return candidates

    def _extract_rf_alerts(
        self, clean_tool: str, tool_output: Any, outer_conf: Any
    ) -> list[dict[str, Any]]:
        items = self._unwrap_items(tool_output, "data", "results", "alerts")
        seen_rules: set[str] = set()
        candidates: list[dict[str, Any]] = []
        for item in items[:20]:
            rule_obj = item.get("rule")
            rule_name = (
                str(rule_obj.get("name") or "").strip()
                if isinstance(rule_obj, Mapping)
                else str(item.get("rule_name") or item.get("category") or item.get("title") or "").strip()
            )
            if not rule_name or rule_name.lower() in seen_rules:
                continue
            seen_rules.add(rule_name.lower())
            candidates.append(
                {
                    "fingerprint": _compute_fingerprint("environment_fact", f"rf_rule:{rule_name}"),
                    "category": "environment_fact",
                    "title": f"Recorded Future Alert Rule: {rule_name}",
                    "content": (
                        f"Recorded Future alert rule '{rule_name}' observed via {clean_tool}."
                    ),
                    "tags": ["recorded_future", "alert_rule"],
                    "confidence": _clamp_confidence(item.get("confidence", outer_conf), 0.75),
                    "entity_tokens": [rule_name.lower()],
                    "raw_blob": _flatten_strings(item),
                }
            )
        return candidates


class SOCLearningManager:
    """Manages SOCLens base knowledge, frozen prompt snapshots, discovery, and lifecycle."""

    def __init__(
        self,
        storage: StorageManager | Callable[[], Any | None] | None = None,
        *,
        workspace_dir: Path | str | None = None,
        policy_store: AIPolicyStore | None = None,
        audit_store: AuditLogStore | None = None,
    ) -> None:
        self._storage_ref = storage
        self._workspace_dir = (
            Path(workspace_dir).expanduser() if workspace_dir is not None else get_workspace_dir()
        )
        self._policy_store = policy_store
        self._audit_store = audit_store
        self._fallback_storage: StorageManager | None = None
        self._fallback_policy_store: AIPolicyStore | None = None
        self._fallback_audit_store: AuditLogStore | None = None
        self._guard = PromptAndSecretGuard()
        self._discoverer = PassiveEnvironmentDiscoverer()
        self._lock = threading.RLock()
        self._frozen_entries: list[SOCLearningEntry] | None = None

    @property
    def workspace_dir(self) -> Path:
        return self._workspace_dir

    def rebind_workspace(self, workspace_dir: Path | str) -> None:
        """Update the workspace root for Base Info loading and reset the frozen snapshot."""
        with self._lock:
            self._workspace_dir = Path(workspace_dir).expanduser()
            self._frozen_entries = None

    def _resolve_storage(self) -> Any:
        raw = self._storage_ref
        if raw is not None:
            if hasattr(raw, "_mock_return_value"):
                return raw
            if callable(raw):
                try:
                    resolved = raw()
                    if resolved is not None:
                        return resolved
                except Exception:
                    pass
            else:
                return raw
        if self._fallback_storage is None:
            from soclens.storage import DatabaseConfig, StorageManager

            db_path = self._workspace_dir / ".soclens_cache" / "soclens.db"
            stor = StorageManager(DatabaseConfig(sqlite_path=db_path))
            stor.ensure_schema()
            self._fallback_storage = stor
        return self._fallback_storage

    def _resolve_policy_store(self) -> AIPolicyStore:
        if self._policy_store is not None:
            return self._policy_store
        if self._fallback_policy_store is None:
            stor = self._resolve_storage()
            self._fallback_policy_store = AIPolicyStore(storage=stor)
        return self._fallback_policy_store

    def _resolve_audit_store(self) -> AuditLogStore:
        if self._audit_store is not None:
            return self._audit_store
        if self._fallback_audit_store is None:
            stor = self._resolve_storage()
            self._fallback_audit_store = AuditLogStore(storage=stor)
        return self._fallback_audit_store

    def _audit(
        self,
        *,
        event_type: Literal["decision", "policy_change", "blocked_action"],
        reason: str,
        allowed: bool | None = True,
        tool_name: str = "learning_manager",
        event_key: str = "",
        actor: str = "",
        payload: dict[str, Any] | None = None,
    ) -> None:
        audit_store = self._resolve_audit_store()
        safe_payload = dict(payload or {})
        if actor:
            safe_payload["actor"] = actor
        audit_store.append(
            AuditEntry(
                entry_id="",
                timestamp="",
                run_id="learning",
                event_key=event_key,
                provider="soclens",
                mode="learning",
                event_type=event_type,
                tool_name=tool_name,
                allowed=allowed,
                reason=str(redact_sensitive_data(reason)),
                payload=safe_payload,
                analyst_id=actor,
            )
        )

    def get_learning_mode(self) -> LearningMode:
        """Return the active learning mode (``'manual'`` default or ``'auto'``)."""
        try:
            policy = self._resolve_policy_store().load()
            return _normalize_learning_mode(getattr(policy, "learning_mode", "manual"))
        except Exception:
            return "manual"

    def set_learning_mode(self, mode: str, *, actor: str = "analyst") -> LearningMode:
        """Persist ``learning_mode`` (``'manual'`` or ``'auto'``) and record an audit event."""
        raw_clean = str(mode or "").strip().lower()
        if raw_clean not in {"manual", "auto"}:
            raise ValueError(f"Invalid learning_mode {mode!r}; expected 'manual' or 'auto'.")
        normalized: LearningMode = "auto" if raw_clean == "auto" else "manual"
        self._resolve_policy_store().update(learning_mode=normalized)
        self._audit(
            event_type="policy_change",
            tool_name="learning_mode",
            allowed=None,
            reason=f"Learning mode set to {normalized!r}",
            actor=actor,
            payload={"field": "learning_mode", "value": normalized},
        )
        return normalized

    def scan_candidate(self, text: str) -> LearningGuardResult:
        """Run invisible-Unicode, prompt-injection, and credential redaction guards."""
        return self._guard.scan_candidate(text)

    def reset_frozen_snapshot(self) -> None:
        """Clear the session-cached frozen snapshot so the next call rebuilds it."""
        with self._lock:
            self._frozen_entries = None

    def load_base_knowledge(
        self, workspace_dir: Path | str | None = None
    ) -> list[SOCLearningEntry]:
        """Load ``BASE_ENVIRONMENT.md`` and ``playbooks/*.md`` into ``source='base_seed'``."""
        root = Path(workspace_dir).expanduser() if workspace_dir is not None else self._workspace_dir
        knowledge_dir = root / ".soclens_cache" / "knowledge"
        with self._lock:
            self._workspace_dir = root
            self._frozen_entries = None
            if not knowledge_dir.is_dir():
                return []

            files_to_read: list[tuple[Path, str, str]] = []
            base_file = knowledge_dir / "BASE_ENVIRONMENT.md"
            if base_file.is_file():
                files_to_read.append((base_file, "BASE_ENVIRONMENT.md", "environment_fact"))
            playbooks_dir = knowledge_dir / "playbooks"
            if playbooks_dir.is_dir():
                for pb_path in sorted(playbooks_dir.glob("*.md")):
                    if pb_path.is_file():
                        files_to_read.append(
                            (pb_path, f"playbooks/{pb_path.name}", "playbook")
                        )

            if not files_to_read:
                return []

            stor = self._resolve_storage()
            loaded_entries: list[SOCLearningEntry] = []

            for file_path, rel_name, category in files_to_read:
                try:
                    raw_text = file_path.read_text(encoding="utf-8-sig").lstrip("\ufeff").strip()
                except OSError:
                    continue
                if not raw_text:
                    continue

                lines = raw_text.splitlines()
                first_heading = ""
                for line in lines:
                    m = _MD_HEADING_RE.match(line)
                    if m:
                        first_heading = m.group(1).strip()
                        break
                title = first_heading or file_path.stem.replace("_", " ").replace("-", " ").title()

                guard = self.scan_candidate(f"{title}\n{raw_text}")
                if not guard.allowed:
                    self._audit(
                        event_type="blocked_action",
                        allowed=False,
                        tool_name="load_base_knowledge",
                        event_key=f"base_seed:{rel_name}",
                        reason=(
                            f"Quarantined poisoned base knowledge file {rel_name}: "
                            + "; ".join(guard.blocked_reasons)
                        ),
                        actor="base_knowledge_loader",
                        payload={
                            "action": "quarantine_base_seed",
                            "file": rel_name,
                            "reasons": guard.blocked_reasons,
                        },
                    )
                    continue

                clean_title = str(self._guard.redact_text(title)).strip()
                clean_content = str(self._guard.redact_text(raw_text)).strip()
                fp = _compute_fingerprint("base_seed", rel_name)
                existing = stor.get_learning_by_fingerprint(fp)
                if existing is not None:
                    # Never mutate pinned or non-base_seed entries.
                    if existing.get("pinned") or existing.get("source") != "base_seed":
                        loaded_entries.append(SOCLearningEntry.from_dict(existing))
                        continue
                    if (
                        existing.get("title") == clean_title
                        and existing.get("content") == clean_content
                        and existing.get("status") == "active"
                    ):
                        loaded_entries.append(SOCLearningEntry.from_dict(existing))
                        continue
                    saved = stor.upsert_learning(
                        entry_id=str(existing["id"]),
                        fingerprint=fp,
                        category=category,
                        title=clean_title,
                        content=clean_content,
                        source="base_seed",
                        status="active",
                        confidence=1.0,
                        seen_count=int(existing.get("seen_count", 1)),
                        use_count=int(existing.get("use_count", 0)),
                        pinned=False,
                        tags=["base_seed", rel_name],
                        created_by="base_seed",
                        created_at=float(existing.get("created_at") or time.time()),
                    )
                    stor.record_learning_revision(
                        learning_id=str(saved["id"]),
                        action="base_sync",
                        actor="base_seed",
                        previous_content=str(existing.get("content") or ""),
                        new_content=clean_content,
                        previous_status=str(existing.get("status") or ""),
                        new_status="active",
                        snapshot=saved,
                    )
                else:
                    saved = stor.upsert_learning(
                        fingerprint=fp,
                        category=category,
                        title=clean_title,
                        content=clean_content,
                        source="base_seed",
                        status="active",
                        confidence=1.0,
                        seen_count=1,
                        use_count=0,
                        pinned=False,
                        tags=["base_seed", rel_name],
                        created_by="base_seed",
                        dedupe_by_fingerprint=True,
                    )
                    stor.record_learning_revision(
                        learning_id=str(saved["id"]),
                        action="base_seed",
                        actor="base_seed",
                        previous_content="",
                        new_content=clean_content,
                        previous_status="",
                        new_status="active",
                        snapshot=saved,
                    )
                loaded_entries.append(SOCLearningEntry.from_dict(saved))

            if loaded_entries:
                self._audit(
                    event_type="decision",
                    allowed=True,
                    tool_name="load_base_knowledge",
                    reason=f"Loaded {len(loaded_entries)} base knowledge entries from {knowledge_dir}",
                    actor="base_knowledge_loader",
                    payload={
                        "action": "load_base_knowledge",
                        "count": len(loaded_entries),
                        "titles": [e.title for e in loaded_entries[:10]],
                    },
                )
            return loaded_entries

    def build_frozen_snapshot(self, max_chars: int = 2500) -> str:
        """Build a session-frozen, prefix-stable, character-bounded active knowledge snapshot."""
        if max_chars <= 0:
            return ""
        with self._lock:
            if self._frozen_entries is None:
                stor = self._resolve_storage()
                rows = stor.list_learnings(status="active", limit=200)
                entries = [SOCLearningEntry.from_dict(r) for r in rows]
                # Stable deterministic ordering: base_seed first, then pinned, confidence, id
                entries.sort(
                    key=lambda e: (
                        0 if e.source == "base_seed" else 1,
                        0 if e.pinned else 1,
                        -float(e.confidence),
                        e.id,
                    )
                )
                self._frozen_entries = entries
            frozen = list(self._frozen_entries)

        if not frozen:
            return ""

        parts: list[str] = []
        total_len = 0
        for entry in frozen:
            block = f"[{entry.category}:{entry.source}] {entry.title}\n{entry.content}".strip()
            sep_len = 2 if parts else 0
            if total_len + sep_len + len(block) <= max_chars:
                parts.append(block)
                total_len += sep_len + len(block)
            else:
                remaining = max_chars - total_len - sep_len
                if remaining > 12:
                    clipped = block[: max(1, remaining - 3)].rstrip() + "..."
                    parts.append(clipped[:remaining])
                elif not parts:
                    parts.append(block[:max_chars])
                break

        result = "\n\n".join(parts)
        if len(result) > max_chars:
            result = result[:max_chars]
        return result

    def match_relevant_entries(
        self,
        query: str,
        max_chars: int = 2000,
        *,
        limit: int = 10,
    ) -> list[SOCLearningEntry]:
        """Search active SOC learnings and return entries strictly within ``max_chars``."""
        clean_q = str(query or "").strip()
        if max_chars <= 0 or not clean_q:
            return []

        stor = self._resolve_storage()
        seen_ids: set[str] = set()
        candidates: list[SOCLearningEntry] = []

        try:
            fts_rows = stor.search_learnings(clean_q, status="active", limit=max(limit * 3, 25))
        except Exception:
            fts_rows = []
        for row in fts_rows:
            entry = SOCLearningEntry.from_dict(row)
            if entry.id and entry.id not in seen_ids:
                seen_ids.add(entry.id)
                candidates.append(entry)

        # Keyword-overlap fallback so partial multi-term queries (e.g. "PsExec lateral movement 7045")
        # still retrieve matching playbooks even when SQLite FTS5 AND misses one token.
        q_tokens = [tok for tok in _QUERY_TOKEN_RE.findall(clean_q.lower()) if len(tok) >= 2]
        if q_tokens:
            try:
                all_active = stor.list_learnings(status="active", limit=200)
            except Exception:
                all_active = []
            scored: list[tuple[int, float, SOCLearningEntry]] = []
            for row in all_active:
                entry = SOCLearningEntry.from_dict(row)
                if not entry.id or entry.id in seen_ids:
                    continue
                haystack = f"{entry.title} {entry.content} {' '.join(entry.tags)}".lower()
                hits = sum(1 for tok in set(q_tokens) if tok in haystack)
                if hits > 0:
                    scored.append((hits, float(entry.confidence), entry))
            scored.sort(key=lambda item: (-item[0], -item[1], item[2].id))
            for _hits, _conf, entry in scored:
                seen_ids.add(entry.id)
                candidates.append(entry)

        matched: list[SOCLearningEntry] = []
        used_chars = 0
        for entry in candidates:
            entry_cost = len(entry.title) + len(entry.content)
            if used_chars + entry_cost > max_chars:
                continue
            matched.append(entry)
            used_chars += entry_cost
            if len(matched) >= limit:
                break

        for entry in matched:
            try:
                if callable(getattr(stor, "increment_learning_use", None)):
                    stor.increment_learning_use(entry.id, delta=1)
            except Exception:
                pass
        return matched

    def _matches_protected_entry(
        self, stor: Any, entity_tokens: Sequence[str]
    ) -> bool:
        if not entity_tokens:
            return False
        try:
            active_rows = stor.list_learnings(limit=200)
        except Exception:
            return False
        for row in active_rows:
            if not (row.get("pinned") or row.get("source") == "base_seed"):
                continue
            haystack = f"{row.get('title', '')} {row.get('content', '')}".lower()
            if any(tok in haystack for tok in entity_tokens if len(tok) >= 4):
                # Only treat as protected conflict if it's a pinned/base_seed rule for the same tool/entity
                if row.get("pinned") and row.get("category") in {"benign_tool", "escalation_rule", "watchlist"}:
                    return True
        return False

    def record_passive_discovery(
        self,
        *,
        tool_name: str,
        tool_args: Mapping[str, Any] | None = None,
        tool_output: Any = None,
        learning_mode: str | None = None,
        actor: str = "passive_discovery",
    ) -> list[SOCLearningEntry]:
        """Extract environment facts from read-only tool outputs with zero extra API calls."""
        candidates = self._discoverer.extract(
            tool_name=tool_name,
            tool_args=tool_args,
            tool_output=tool_output,
        )
        if not candidates:
            return []

        eff_mode = _normalize_learning_mode(
            learning_mode if learning_mode is not None else self.get_learning_mode()
        )
        stor = self._resolve_storage()
        results: list[SOCLearningEntry] = []

        with self._lock:
            for cand in candidates:
                raw_blob = str(cand.get("raw_blob") or "")
                candidate_text = f"{cand['title']}\n{cand['content']}\n{raw_blob}"
                guard = self.scan_candidate(candidate_text)
                if not guard.allowed:
                    self._audit(
                        event_type="blocked_action",
                        allowed=False,
                        tool_name=tool_name,
                        event_key=str(cand["fingerprint"]),
                        reason=(
                            f"Blocked poisoned passive discovery from {tool_name}: "
                            + "; ".join(guard.blocked_reasons)
                        ),
                        actor=actor,
                        payload={
                            "action": "blocked_passive_discovery",
                            "tool_name": tool_name,
                            "reasons": guard.blocked_reasons,
                            "redacted_preview": guard.redacted_content[:300],
                        },
                    )
                    continue

                clean_title = str(self._guard.redact_text(str(cand["title"]))).strip()
                clean_content = str(self._guard.redact_text(str(cand["content"]))).strip()
                fp = str(cand["fingerprint"])
                conf = float(cand["confidence"])
                category = _normalize_category(cand["category"])
                tags = [str(t) for t in cand.get("tags") or []]
                entity_tokens = [str(t).lower() for t in cand.get("entity_tokens") or []]

                existing = stor.get_learning_by_fingerprint(fp)
                if existing is not None:
                    # Immutable protection for base_seed and user-pinned entries.
                    if existing.get("pinned") or existing.get("source") == "base_seed":
                        results.append(SOCLearningEntry.from_dict(existing))
                        continue

                    prev_status = str(existing.get("status") or "pending")
                    new_seen = int(existing.get("seen_count", 1)) + 1
                    new_conf = max(float(existing.get("confidence", 0.0)), conf)
                    new_status = prev_status
                    if prev_status == "pending" and eff_mode == "auto":
                        if new_conf >= 0.80 or new_seen >= 2:
                            new_status = "active"

                    saved = stor.upsert_learning(
                        entry_id=str(existing["id"]),
                        fingerprint=fp,
                        category=category,
                        title=clean_title,
                        content=clean_content,
                        source=str(existing.get("source") or "passive_discovery"),
                        status=new_status,
                        confidence=new_conf,
                        seen_count=new_seen,
                        use_count=int(existing.get("use_count", 0)),
                        pinned=False,
                        tags=tags,
                        created_by=str(existing.get("created_by") or actor),
                        created_at=float(existing.get("created_at") or time.time()),
                    )
                    action_name = (
                        "auto_promote"
                        if prev_status != "active" and new_status == "active"
                        else "passive_refresh"
                    )
                    stor.record_learning_revision(
                        learning_id=str(saved["id"]),
                        action=action_name,
                        actor=actor,
                        previous_content=str(existing.get("content") or ""),
                        new_content=clean_content,
                        previous_status=prev_status,
                        new_status=new_status,
                        snapshot=saved,
                    )
                    self._audit(
                        event_type="decision",
                        allowed=True,
                        tool_name="learning_manager",
                        event_key=str(saved["id"]),
                        reason=f"Passive discovery {action_name}: {clean_title} (status={new_status}, seen={new_seen})",
                        actor=actor,
                        payload={
                            "action": action_name,
                            "learning_id": saved["id"],
                            "source_tool": tool_name,
                            "status": new_status,
                            "seen_count": new_seen,
                            "confidence": new_conf,
                        },
                    )
                    results.append(SOCLearningEntry.from_dict(saved))
                    continue

                if self._matches_protected_entry(stor, entity_tokens):
                    self._audit(
                        event_type="decision",
                        allowed=True,
                        tool_name="learning_manager",
                        event_key=fp,
                        reason=f"Skipped passive discovery '{clean_title}' due to pinned/base protection.",
                        actor=actor,
                        payload={"action": "protected_skip", "tool_name": tool_name},
                    )
                    continue

                initial_status = (
                    "active" if (eff_mode == "auto" and conf >= 0.80) else "pending"
                )
                saved = stor.upsert_learning(
                    fingerprint=fp,
                    category=category,
                    title=clean_title,
                    content=clean_content,
                    source="passive_discovery",
                    status=initial_status,
                    confidence=conf,
                    seen_count=1,
                    use_count=0,
                    pinned=False,
                    tags=tags,
                    created_by=actor,
                    dedupe_by_fingerprint=True,
                )
                action_name = "auto_promote" if initial_status == "active" else "stage_pending"
                stor.record_learning_revision(
                    learning_id=str(saved["id"]),
                    action=action_name,
                    actor=actor,
                    previous_content="",
                    new_content=clean_content,
                    previous_status="",
                    new_status=initial_status,
                    snapshot=saved,
                )
                self._audit(
                    event_type="decision",
                    allowed=True,
                    tool_name="learning_manager",
                    event_key=str(saved["id"]),
                    reason=f"Passive discovery {action_name}: {clean_title} (status={initial_status})",
                    actor=actor,
                    payload={
                        "action": action_name,
                        "learning_id": saved["id"],
                        "source_tool": tool_name,
                        "status": initial_status,
                        "confidence": conf,
                    },
                )
                results.append(SOCLearningEntry.from_dict(saved))

        return results

    def record_post_investigation_takeaway(
        self,
        *,
        event_key: str,
        mode: str,
        answer_markdown: str,
        tool_calls: Sequence[Mapping[str, Any]],
        learning_mode: str | None = None,
        actor: str = "ai_takeaway",
    ) -> SOCLearningEntry | None:
        """Deterministically extract a post-investigation takeaway with zero extra LLM calls."""
        if mode != "full_investigation":
            return None
        if not event_key or event_key.startswith("freeform_chat::"):
            return None
        clean_answer = str(answer_markdown or "").strip()
        if not clean_answer:
            return None
        ok_tools = [
            str(tc.get("tool_name") or "").strip()
            for tc in tool_calls
            if isinstance(tc, Mapping) and tc.get("ok") is True and tc.get("tool_name")
        ]
        if not ok_tools:
            return None

        first_line = ""
        for line in clean_answer.splitlines():
            stripped = line.strip().lstrip("#").strip()
            if stripped:
                first_line = stripped
                break
        if not first_line:
            return None

        title = f"Investigation Takeaway ({event_key})"
        tools_summary = ", ".join(dict.fromkeys(ok_tools))
        content = f"{first_line[:350]} [Corroborated via: {tools_summary}]"
        guard = self.scan_candidate(f"{title}\n{content}")
        if not guard.allowed:
            self._audit(
                event_type="blocked_action",
                allowed=False,
                tool_name="record_post_investigation_takeaway",
                event_key=event_key,
                reason="Blocked unsafe post-investigation takeaway: " + "; ".join(guard.blocked_reasons),
                actor=actor,
                payload={"action": "blocked_takeaway", "reasons": guard.blocked_reasons},
            )
            return None

        eff_mode = _normalize_learning_mode(
            learning_mode if learning_mode is not None else self.get_learning_mode()
        )
        clean_title = str(self._guard.redact_text(title)).strip()
        clean_content = str(self._guard.redact_text(content)).strip()
        fp = _compute_fingerprint("takeaway", f"{event_key}:{first_line[:120]}")
        stor = self._resolve_storage()

        with self._lock:
            existing = stor.get_learning_by_fingerprint(fp)
            if existing is not None:
                if existing.get("pinned") or existing.get("source") == "base_seed":
                    return SOCLearningEntry.from_dict(existing)
                prev_status = str(existing.get("status") or "pending")
                new_seen = int(existing.get("seen_count", 1)) + 1
                new_conf = max(float(existing.get("confidence", 0.80)), 0.82)
                new_status = "active" if (eff_mode == "auto" and prev_status == "pending") else prev_status
                saved = stor.upsert_learning(
                    entry_id=str(existing["id"]),
                    fingerprint=fp,
                    category="takeaway",
                    title=clean_title,
                    content=clean_content,
                    source="ai_takeaway",
                    status=new_status,
                    confidence=new_conf,
                    seen_count=new_seen,
                    use_count=int(existing.get("use_count", 0)),
                    pinned=False,
                    tags=["takeaway", *list(dict.fromkeys(ok_tools))[:4]],
                    created_by=actor,
                    created_at=float(existing.get("created_at") or time.time()),
                )
            else:
                initial_status = "active" if eff_mode == "auto" else "pending"
                saved = stor.upsert_learning(
                    fingerprint=fp,
                    category="takeaway",
                    title=clean_title,
                    content=clean_content,
                    source="ai_takeaway",
                    status=initial_status,
                    confidence=0.82,
                    seen_count=1,
                    use_count=0,
                    pinned=False,
                    tags=["takeaway", *list(dict.fromkeys(ok_tools))[:4]],
                    created_by=actor,
                    dedupe_by_fingerprint=True,
                )
            stor.record_learning_revision(
                learning_id=str(saved["id"]),
                action="takeaway",
                actor=actor,
                previous_content=str(existing.get("content") or "") if existing else "",
                new_content=clean_content,
                previous_status=str(existing.get("status") or "") if existing else "",
                new_status=str(saved["status"]),
                snapshot=saved,
            )
            self._audit(
                event_type="decision",
                allowed=True,
                tool_name="learning_manager",
                event_key=str(saved["id"]),
                reason=f"Post-investigation takeaway saved: {clean_title} (status={saved['status']})",
                actor=actor,
                payload={"action": "post_investigation_takeaway", "learning_id": saved["id"], "status": saved["status"]},
            )
        return SOCLearningEntry.from_dict(saved)

    def submit_manual_learn(
        self,
        *,
        title: str,
        content: str,
        category: str = "environment_fact",
        tags: Sequence[str] = (),
        actor: str = "analyst",
    ) -> SOCLearningEntry:
        """Validate, guard-scan, redact, and persist an analyst-taught ``status='active'`` entry."""
        raw_content = str(content or "").strip()
        raw_title = str(title or "").strip()
        if not raw_content:
            raise ValueError("Learning content must not be empty.")
        if not raw_title:
            first_line = raw_content.splitlines()[0].strip()
            raw_title = first_line[:80] if first_line else "Analyst Lesson"

        guard = self.scan_candidate(f"{raw_title}\n{raw_content}")
        if not guard.allowed:
            self._audit(
                event_type="blocked_action",
                allowed=False,
                tool_name="submit_manual_learn",
                reason="Blocked unsafe manual learning input: " + "; ".join(guard.blocked_reasons),
                actor=actor,
                payload={
                    "action": "blocked_manual_learn",
                    "title": str(self._guard.redact_text(raw_title))[:120],
                    "reasons": guard.blocked_reasons,
                },
            )
            raise ValueError("; ".join(guard.blocked_reasons))

        clean_title = str(self._guard.redact_text(raw_title)).strip()
        clean_content = str(self._guard.redact_text(raw_content)).strip()
        eff_cat = _normalize_category(category)
        clean_tags = [str(self._guard.redact_text(str(t))).strip() for t in tags if str(t).strip()]
        fp = _compute_fingerprint(eff_cat, f"{clean_title}:{clean_content}")
        stor = self._resolve_storage()

        with self._lock:
            existing = stor.get_learning_by_fingerprint(fp)
            if existing is not None and not existing.get("pinned") and existing.get("source") != "base_seed":
                saved = stor.upsert_learning(
                    entry_id=str(existing["id"]),
                    fingerprint=fp,
                    category=eff_cat,
                    title=clean_title,
                    content=clean_content,
                    source="manual_learn",
                    status="active",
                    confidence=1.0,
                    seen_count=int(existing.get("seen_count", 1)) + 1,
                    use_count=int(existing.get("use_count", 0)),
                    pinned=bool(existing.get("pinned", False)),
                    tags=clean_tags,
                    created_by=actor or "analyst",
                    created_at=float(existing.get("created_at") or time.time()),
                )
            else:
                saved = stor.upsert_learning(
                    entry_id=uuid.uuid4().hex[:16] if existing is not None else None,
                    fingerprint=fp,
                    category=eff_cat,
                    title=clean_title,
                    content=clean_content,
                    source="manual_learn",
                    status="active",
                    confidence=1.0,
                    seen_count=1,
                    use_count=0,
                    pinned=False,
                    tags=clean_tags,
                    created_by=actor or "analyst",
                )
            stor.record_learning_revision(
                learning_id=str(saved["id"]),
                action="manual_learn",
                actor=actor or "analyst",
                previous_content=str(existing.get("content") or "") if existing else "",
                new_content=clean_content,
                previous_status=str(existing.get("status") or "") if existing else "",
                new_status="active",
                snapshot=saved,
            )
            self._audit(
                event_type="decision",
                allowed=True,
                tool_name="learning_manager",
                event_key=str(saved["id"]),
                reason=f"Manual learning saved active: {clean_title}",
                actor=actor or "analyst",
                payload={
                    "action": "manual_learn",
                    "learning_id": saved["id"],
                    "title": clean_title,
                    "category": eff_cat,
                },
            )
        return SOCLearningEntry.from_dict(saved)

    def list_entries(
        self,
        *,
        status: str | None = None,
        category: str | None = None,
        source: str | None = None,
        limit: int = 200,
    ) -> list[SOCLearningEntry]:
        """List persisted learning entries with optional status/category/source filters."""
        stor = self._resolve_storage()
        rows = stor.list_learnings(status=status, category=category, source=source, limit=limit)
        return [SOCLearningEntry.from_dict(r) for r in rows]

    def get_entry(self, entry_id: str) -> SOCLearningEntry | None:
        """Fetch a single learning entry by ID, or ``None`` if not found."""
        stor = self._resolve_storage()
        row = stor.get_learning(entry_id)
        return SOCLearningEntry.from_dict(row) if row is not None else None

    def get_revisions(self, entry_id: str) -> list[dict[str, Any]]:
        """Return ordered revision history for ``entry_id`` (newest first)."""
        stor = self._resolve_storage()
        return list(stor.get_learning_revisions(entry_id))

    def approve_entry(self, entry_id: str, *, actor: str = "analyst") -> SOCLearningEntry:
        """Promote a pending/rolled-back learning entry to ``status='active'``."""
        stor = self._resolve_storage()
        with self._lock:
            existing = stor.get_learning(entry_id)
            if existing is None:
                raise KeyError(f"Learning entry not found: {entry_id!r}")
            prev_status = str(existing.get("status") or "")
            saved = stor.upsert_learning(
                entry_id=str(existing["id"]),
                fingerprint=str(existing["fingerprint"]),
                category=str(existing["category"]),
                title=str(existing["title"]),
                content=str(existing["content"]),
                source=str(existing["source"]),
                status="active",
                confidence=float(existing.get("confidence", 1.0)),
                seen_count=int(existing.get("seen_count", 1)),
                use_count=int(existing.get("use_count", 0)),
                pinned=bool(existing.get("pinned", False)),
                tags=list(existing.get("tags") or []),
                created_by=str(existing.get("created_by") or actor),
                created_at=float(existing.get("created_at") or time.time()),
            )
            stor.record_learning_revision(
                learning_id=str(saved["id"]),
                action="approve",
                actor=actor,
                previous_content=str(existing.get("content") or ""),
                new_content=str(saved["content"]),
                previous_status=prev_status,
                new_status="active",
                snapshot=saved,
            )
            self._audit(
                event_type="decision",
                allowed=True,
                tool_name="learning_manager",
                event_key=str(saved["id"]),
                reason=f"Approved learning entry {saved['id']}: {saved['title']}",
                actor=actor,
                payload={
                    "action": "approve",
                    "learning_id": saved["id"],
                    "previous_status": prev_status,
                    "new_status": "active",
                },
            )
        return SOCLearningEntry.from_dict(saved)

    def edit_entry(
        self,
        entry_id: str,
        *,
        title: str | None = None,
        content: str | None = None,
        category: str | None = None,
        tags: Sequence[str] | None = None,
        actor: str = "analyst",
    ) -> SOCLearningEntry:
        """Edit an entry after guard scanning & redaction, recording a revision snapshot."""
        stor = self._resolve_storage()
        with self._lock:
            existing = stor.get_learning(entry_id)
            if existing is None:
                raise KeyError(f"Learning entry not found: {entry_id!r}")
            new_title = str(existing["title"]) if title is None else str(title).strip()
            new_content = str(existing["content"]) if content is None else str(content).strip()
            if not new_title or not new_content:
                raise ValueError("Edited learning title and content must not be empty.")
            guard = self.scan_candidate(f"{new_title}\n{new_content}")
            if not guard.allowed:
                self._audit(
                    event_type="blocked_action",
                    allowed=False,
                    tool_name="edit_entry",
                    event_key=str(existing["id"]),
                    reason="Blocked unsafe learning edit: " + "; ".join(guard.blocked_reasons),
                    actor=actor,
                    payload={"action": "blocked_edit", "learning_id": existing["id"], "reasons": guard.blocked_reasons},
                )
                raise ValueError("; ".join(guard.blocked_reasons))

            clean_title = str(self._guard.redact_text(new_title)).strip()
            clean_content = str(self._guard.redact_text(new_content)).strip()
            eff_cat = _normalize_category(category) if category is not None else str(existing["category"])
            eff_tags = (
                [str(self._guard.redact_text(str(t))).strip() for t in tags if str(t).strip()]
                if tags is not None
                else list(existing.get("tags") or [])
            )
            saved = stor.upsert_learning(
                entry_id=str(existing["id"]),
                fingerprint=str(existing["fingerprint"]),
                category=eff_cat,
                title=clean_title,
                content=clean_content,
                source=str(existing["source"]),
                status=str(existing["status"]),
                confidence=float(existing.get("confidence", 1.0)),
                seen_count=int(existing.get("seen_count", 1)),
                use_count=int(existing.get("use_count", 0)),
                pinned=bool(existing.get("pinned", False)),
                tags=eff_tags,
                created_by=str(existing.get("created_by") or actor),
                created_at=float(existing.get("created_at") or time.time()),
            )
            stor.record_learning_revision(
                learning_id=str(saved["id"]),
                action="edit",
                actor=actor,
                previous_content=str(existing.get("content") or ""),
                new_content=clean_content,
                previous_status=str(existing.get("status") or ""),
                new_status=str(saved["status"]),
                snapshot=saved,
            )
            self._audit(
                event_type="decision",
                allowed=True,
                tool_name="learning_manager",
                event_key=str(saved["id"]),
                reason=f"Edited learning entry {saved['id']}: {clean_title}",
                actor=actor,
                payload={"action": "edit", "learning_id": saved["id"], "title": clean_title},
            )
        return SOCLearningEntry.from_dict(saved)

    def pin_entry(
        self,
        entry_id: str,
        pinned: bool = True,
        *,
        actor: str = "analyst",
    ) -> SOCLearningEntry:
        """Pin or unpin a learning entry to protect it from automatic updates."""
        stor = self._resolve_storage()
        with self._lock:
            existing = stor.get_learning(entry_id)
            if existing is None:
                raise KeyError(f"Learning entry not found: {entry_id!r}")
            new_pinned = bool(pinned)
            saved = stor.upsert_learning(
                entry_id=str(existing["id"]),
                fingerprint=str(existing["fingerprint"]),
                category=str(existing["category"]),
                title=str(existing["title"]),
                content=str(existing["content"]),
                source=str(existing["source"]),
                status=str(existing["status"]),
                confidence=float(existing.get("confidence", 1.0)),
                seen_count=int(existing.get("seen_count", 1)),
                use_count=int(existing.get("use_count", 0)),
                pinned=new_pinned,
                tags=list(existing.get("tags") or []),
                created_by=str(existing.get("created_by") or actor),
                created_at=float(existing.get("created_at") or time.time()),
            )
            stor.record_learning_revision(
                learning_id=str(saved["id"]),
                action="pin" if new_pinned else "unpin",
                actor=actor,
                previous_content=str(existing.get("content") or ""),
                new_content=str(saved["content"]),
                previous_status=str(existing.get("status") or ""),
                new_status=str(saved["status"]),
                snapshot=saved,
            )
            self._audit(
                event_type="decision",
                allowed=True,
                tool_name="learning_manager",
                event_key=str(saved["id"]),
                reason=f"{'Pinned' if new_pinned else 'Unpinned'} learning entry {saved['id']}",
                actor=actor,
                payload={"action": "pin" if new_pinned else "unpin", "learning_id": saved["id"], "pinned": new_pinned},
            )
        return SOCLearningEntry.from_dict(saved)

    def rollback_entry(self, entry_id: str, *, actor: str = "analyst") -> SOCLearningEntry:
        """Roll back an entry (restoring prior revision content when present & setting ``rolled_back``)."""
        stor = self._resolve_storage()
        with self._lock:
            existing = stor.get_learning(entry_id)
            if existing is None:
                raise KeyError(f"Learning entry not found: {entry_id!r}")
            revisions = stor.get_learning_revisions(str(existing["id"]))

            cur_content = str(existing.get("content") or "")
            restored_content = cur_content
            restored_title = str(existing.get("title") or "")
            restored_category = str(existing.get("category") or "environment_fact")
            restored_tags = list(existing.get("tags") or [])

            for rev in revisions:
                prev_c = str(rev.get("previous_content") or "").strip()
                if prev_c and prev_c != cur_content:
                    restored_content = prev_c
                    break
                snap = rev.get("snapshot")
                if isinstance(snap, Mapping):
                    snap_c = str(snap.get("content") or "").strip()
                    if snap_c and snap_c != cur_content:
                        restored_content = snap_c
                        if snap.get("title"):
                            restored_title = str(snap["title"])
                        if snap.get("category"):
                            restored_category = str(snap["category"])
                        if isinstance(snap.get("tags"), list):
                            restored_tags = [str(t) for t in snap["tags"]]
                        break

            prev_status = str(existing.get("status") or "")
            saved = stor.upsert_learning(
                entry_id=str(existing["id"]),
                fingerprint=str(existing["fingerprint"]),
                category=restored_category,
                title=restored_title,
                content=restored_content,
                source=str(existing["source"]),
                status="rolled_back",
                confidence=float(existing.get("confidence", 1.0)),
                seen_count=int(existing.get("seen_count", 1)),
                use_count=int(existing.get("use_count", 0)),
                pinned=bool(existing.get("pinned", False)),
                tags=restored_tags,
                created_by=str(existing.get("created_by") or actor),
                created_at=float(existing.get("created_at") or time.time()),
            )
            stor.record_learning_revision(
                learning_id=str(saved["id"]),
                action="rollback",
                actor=actor,
                previous_content=cur_content,
                new_content=restored_content,
                previous_status=prev_status,
                new_status="rolled_back",
                snapshot=saved,
            )
            self._audit(
                event_type="decision",
                allowed=True,
                tool_name="learning_manager",
                event_key=str(saved["id"]),
                reason=f"Rolled back learning entry {saved['id']}: {restored_title}",
                actor=actor,
                payload={
                    "action": "rollback",
                    "learning_id": saved["id"],
                    "previous_status": prev_status,
                    "new_status": "rolled_back",
                },
            )
        return SOCLearningEntry.from_dict(saved)

    def delete_entry(self, entry_id: str, *, actor: str = "analyst") -> bool:
        """Delete a learning entry by ID and record an audit log entry."""
        stor = self._resolve_storage()
        with self._lock:
            existing = stor.get_learning(entry_id)
            if existing is None:
                return False
            deleted = bool(stor.delete_learning(str(existing["id"])))
            if deleted:
                self._audit(
                    event_type="decision",
                    allowed=True,
                    tool_name="learning_manager",
                    event_key=str(existing["id"]),
                    reason=f"Deleted learning entry {existing['id']}: {existing.get('title', '')}",
                    actor=actor,
                    payload={
                        "action": "delete",
                        "learning_id": existing["id"],
                        "title": existing.get("title", ""),
                    },
                )
            return deleted


__all__ = [
    "LearningGuardResult",
    "PassiveEnvironmentDiscoverer",
    "PromptAndSecretGuard",
    "SOCLearningEntry",
    "SOCLearningManager",
    "VALID_LEARNING_CATEGORIES",
    "VALID_LEARNING_SOURCES",
    "VALID_LEARNING_STATUSES",
    "scan_candidate",
]
