"""AI Control Panel policy schema, atomic persistence, and fail-closed permission gating."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from soclens.config import get_workspace_dir

if TYPE_CHECKING:
    from soclens.storage import StorageManager

logger = logging.getLogger(__name__)

InvestigationMode = Literal["ask_only", "full_investigation"]
VALID_INVESTIGATION_MODES: frozenset[str] = frozenset({"ask_only", "full_investigation"})

LearningMode = Literal["manual", "auto"]
DEFAULT_LEARNING_MODE: LearningMode = "manual"
VALID_LEARNING_MODES: tuple[str, ...] = ("manual", "auto")

SOURCE_CATEGORY_SPLUNK: str = "splunk_search"
SOURCE_CATEGORY_SPLUNK_ES: str = "splunk_es"
SOURCE_CATEGORY_S1: str = "sentinelone"
SOURCE_CATEGORY_RF: str = "recorded_future"
SOURCE_CATEGORY_OSINT: str = "watchlists_osint"
SOURCE_CATEGORY_LOCAL: str = "local_db"

SOURCE_CATEGORY_TOGGLE_MAP: dict[str, str] = {
    SOURCE_CATEGORY_SPLUNK: "splunk_search_enabled",
    SOURCE_CATEGORY_SPLUNK_ES: "splunk_es_enabled",
    SOURCE_CATEGORY_S1: "sentinelone_enabled",
    SOURCE_CATEGORY_RF: "recorded_future_enabled",
    SOURCE_CATEGORY_OSINT: "watchlists_osint_enabled",
    SOURCE_CATEGORY_LOCAL: "local_db_enabled",
}

DEFAULT_MAX_TOOL_STEPS: int = 50
MIN_TOOL_STEPS: int = 1
MAX_TOOL_STEPS: int = 500

DEFAULT_MAX_IDENTICAL_TOOL_CALLS: int = 2
MIN_IDENTICAL_TOOL_CALLS: int = 1
MAX_IDENTICAL_TOOL_CALLS: int = 50

DEFAULT_MAX_SAME_TOOL_FAILURES: int = 10
MIN_SAME_TOOL_FAILURES: int = 1
MAX_SAME_TOOL_FAILURES: int = 100

DEFAULT_KILL_SWITCH_LABEL: str = "KILL AI"
MAX_KILL_SWITCH_LABEL_LEN: int = 20
DEFAULT_KILL_SWITCH_HOTKEY: str = "f12"
VALID_KILL_SWITCH_HOTKEYS: tuple[str, ...] = ("f12", "f11", "ctrl+backslash", "none")

_KILL_SWITCH_HOTKEY_BADGES: dict[str, str] = {
    "f12": "[F12]",
    "f11": "[F11]",
    "ctrl+backslash": "[Ctrl+\\]",
    "none": "",
}

_REGISTRY_LOCK = threading.Lock()
_REGISTERED_READONLY_TOOLS: set[str] = set()


def register_readonly_tool_names(names: Iterable[str]) -> None:
    """Register known read-only tool names for fail-closed policy evaluation."""
    cleaned = {str(name).strip() for name in names if isinstance(name, str) and name.strip()}
    with _REGISTRY_LOCK:
        _REGISTERED_READONLY_TOOLS.update(cleaned)


def get_registered_readonly_tool_names() -> frozenset[str]:
    """Return a snapshot of currently registered read-only tool names."""
    with _REGISTRY_LOCK:
        if _REGISTERED_READONLY_TOOLS:
            return frozenset(_REGISTERED_READONLY_TOOLS)
    try:
        from soclens.agent_tools import READONLY_TOOL_NAMES

        register_readonly_tool_names(READONLY_TOOL_NAMES)
        with _REGISTRY_LOCK:
            return frozenset(_REGISTERED_READONLY_TOOLS)
    except Exception:
        return frozenset()


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"1", "true", "yes", "on"}:
            return True
        if low in {"0", "false", "no", "off"}:
            return False
    return default


def _coerce_bounded_int(value: Any, default: int, min_val: int, max_val: int) -> int:
    if isinstance(value, bool):
        return default
    parsed: int | None = None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        stripped = value.strip()
        if stripped and (stripped.isdigit() or (stripped.startswith("-") and stripped[1:].isdigit())):
            parsed = int(stripped)
    if parsed is None:
        return default
    return max(min_val, min(parsed, max_val))


def _normalize_disabled_tools(value: Any) -> list[str]:
    items: list[str]
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = [str(item) for item in value if isinstance(item, str)]
    else:
        return []

    seen: set[str] = set()
    normalized: list[str] = []
    for raw in items:
        clean = raw.strip()
        if clean and clean not in seen:
            seen.add(clean)
            normalized.append(clean)
    return normalized


def _normalize_kill_switch_label(value: Any) -> str:
    if not isinstance(value, str):
        return DEFAULT_KILL_SWITCH_LABEL
    collapsed = " ".join(value.split()).strip()
    if not collapsed:
        return DEFAULT_KILL_SWITCH_LABEL
    return collapsed[:MAX_KILL_SWITCH_LABEL_LEN].strip() or DEFAULT_KILL_SWITCH_LABEL


def _normalize_kill_switch_hotkey(value: Any) -> str:
    if not isinstance(value, str):
        return DEFAULT_KILL_SWITCH_HOTKEY
    cleaned = value.strip().lower()
    if cleaned in VALID_KILL_SWITCH_HOTKEYS:
        return cleaned
    return DEFAULT_KILL_SWITCH_HOTKEY


def _normalize_learning_mode(value: Any) -> LearningMode:
    if isinstance(value, str) and value.strip().lower() == "auto":
        return "auto"
    return "manual"


def format_kill_switch_hotkey_badge(hotkey: str) -> str:
    """Return a compact display badge (e.g. ``[F12]``) for ``hotkey``, or ``''``."""
    return _KILL_SWITCH_HOTKEY_BADGES.get(_normalize_kill_switch_hotkey(hotkey), "")


def _env_max_tool_steps_default() -> int:
    raw = (os.environ.get("SOCLENS_AI_MAX_TOOL_STEPS") or "").strip()
    if not raw:
        return DEFAULT_MAX_TOOL_STEPS
    return _coerce_bounded_int(raw, DEFAULT_MAX_TOOL_STEPS, MIN_TOOL_STEPS, MAX_TOOL_STEPS)


@dataclass
class AIPolicyConfig:
    """Granular AI Control Panel policy governing read-only agent capabilities."""

    background_triage_enabled: bool = False
    cross_search_enabled: bool = True
    splunk_search_enabled: bool = True
    splunk_es_enabled: bool = True
    sentinelone_enabled: bool = True
    recorded_future_enabled: bool = True
    watchlists_osint_enabled: bool = True
    local_db_enabled: bool = True
    disabled_tools: list[str] = field(default_factory=list)
    max_tool_steps: int = DEFAULT_MAX_TOOL_STEPS
    max_identical_tool_calls: int = DEFAULT_MAX_IDENTICAL_TOOL_CALLS
    max_same_tool_failures: int = DEFAULT_MAX_SAME_TOOL_FAILURES
    ai_kill_switch_active: bool = False
    kill_switch_visible: bool = True
    kill_switch_confirm_engage: bool = False
    kill_switch_confirm_resume: bool = False
    kill_switch_persist_across_restarts: bool = True
    kill_switch_label: str = DEFAULT_KILL_SWITCH_LABEL
    kill_switch_hotkey: str = DEFAULT_KILL_SWITCH_HOTKEY
    learning_mode: LearningMode = DEFAULT_LEARNING_MODE

    def __post_init__(self) -> None:
        self.background_triage_enabled = _coerce_bool(self.background_triage_enabled, False)
        self.cross_search_enabled = _coerce_bool(self.cross_search_enabled, True)
        self.splunk_search_enabled = _coerce_bool(self.splunk_search_enabled, True)
        self.splunk_es_enabled = _coerce_bool(self.splunk_es_enabled, True)
        self.sentinelone_enabled = _coerce_bool(self.sentinelone_enabled, True)
        self.recorded_future_enabled = _coerce_bool(self.recorded_future_enabled, True)
        self.watchlists_osint_enabled = _coerce_bool(self.watchlists_osint_enabled, True)
        self.local_db_enabled = _coerce_bool(self.local_db_enabled, True)
        self.disabled_tools = _normalize_disabled_tools(self.disabled_tools)
        self.max_tool_steps = _coerce_bounded_int(
            self.max_tool_steps,
            DEFAULT_MAX_TOOL_STEPS,
            MIN_TOOL_STEPS,
            MAX_TOOL_STEPS,
        )
        self.max_identical_tool_calls = _coerce_bounded_int(
            self.max_identical_tool_calls,
            DEFAULT_MAX_IDENTICAL_TOOL_CALLS,
            MIN_IDENTICAL_TOOL_CALLS,
            MAX_IDENTICAL_TOOL_CALLS,
        )
        self.max_same_tool_failures = _coerce_bounded_int(
            self.max_same_tool_failures,
            DEFAULT_MAX_SAME_TOOL_FAILURES,
            MIN_SAME_TOOL_FAILURES,
            MAX_SAME_TOOL_FAILURES,
        )
        self.ai_kill_switch_active = _coerce_bool(self.ai_kill_switch_active, False)
        self.kill_switch_visible = _coerce_bool(self.kill_switch_visible, True)
        self.kill_switch_confirm_engage = _coerce_bool(self.kill_switch_confirm_engage, False)
        self.kill_switch_confirm_resume = _coerce_bool(self.kill_switch_confirm_resume, False)
        self.kill_switch_persist_across_restarts = _coerce_bool(
            self.kill_switch_persist_across_restarts, True
        )
        self.kill_switch_label = _normalize_kill_switch_label(self.kill_switch_label)
        self.kill_switch_hotkey = _normalize_kill_switch_hotkey(self.kill_switch_hotkey)
        self.learning_mode = _normalize_learning_mode(self.learning_mode)

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy configuration into a JSON-friendly dictionary."""
        return {
            "background_triage_enabled": self.background_triage_enabled,
            "cross_search_enabled": self.cross_search_enabled,
            "splunk_search_enabled": self.splunk_search_enabled,
            "splunk_es_enabled": self.splunk_es_enabled,
            "sentinelone_enabled": self.sentinelone_enabled,
            "recorded_future_enabled": self.recorded_future_enabled,
            "watchlists_osint_enabled": self.watchlists_osint_enabled,
            "local_db_enabled": self.local_db_enabled,
            "disabled_tools": list(self.disabled_tools),
            "max_tool_steps": self.max_tool_steps,
            "max_identical_tool_calls": self.max_identical_tool_calls,
            "max_same_tool_failures": self.max_same_tool_failures,
            "ai_kill_switch_active": self.ai_kill_switch_active,
            "kill_switch_visible": self.kill_switch_visible,
            "kill_switch_confirm_engage": self.kill_switch_confirm_engage,
            "kill_switch_confirm_resume": self.kill_switch_confirm_resume,
            "kill_switch_persist_across_restarts": self.kill_switch_persist_across_restarts,
            "kill_switch_label": self.kill_switch_label,
            "kill_switch_hotkey": self.kill_switch_hotkey,
            "learning_mode": self.learning_mode,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> AIPolicyConfig:
        """Build an ``AIPolicyConfig`` from a persisted mapping, falling back on bad values."""
        return cls(
            background_triage_enabled=_coerce_bool(raw.get("background_triage_enabled"), False),
            cross_search_enabled=_coerce_bool(raw.get("cross_search_enabled"), True),
            splunk_search_enabled=_coerce_bool(raw.get("splunk_search_enabled"), True),
            splunk_es_enabled=_coerce_bool(raw.get("splunk_es_enabled"), True),
            sentinelone_enabled=_coerce_bool(raw.get("sentinelone_enabled"), True),
            recorded_future_enabled=_coerce_bool(raw.get("recorded_future_enabled"), True),
            watchlists_osint_enabled=_coerce_bool(raw.get("watchlists_osint_enabled"), True),
            local_db_enabled=_coerce_bool(raw.get("local_db_enabled"), True),
            disabled_tools=_normalize_disabled_tools(raw.get("disabled_tools")),
            max_tool_steps=_coerce_bounded_int(
                raw.get("max_tool_steps"),
                DEFAULT_MAX_TOOL_STEPS,
                MIN_TOOL_STEPS,
                MAX_TOOL_STEPS,
            ),
            max_identical_tool_calls=_coerce_bounded_int(
                raw.get("max_identical_tool_calls"),
                DEFAULT_MAX_IDENTICAL_TOOL_CALLS,
                MIN_IDENTICAL_TOOL_CALLS,
                MAX_IDENTICAL_TOOL_CALLS,
            ),
            max_same_tool_failures=_coerce_bounded_int(
                raw.get("max_same_tool_failures"),
                DEFAULT_MAX_SAME_TOOL_FAILURES,
                MIN_SAME_TOOL_FAILURES,
                MAX_SAME_TOOL_FAILURES,
            ),
            ai_kill_switch_active=_coerce_bool(raw.get("ai_kill_switch_active"), False),
            kill_switch_visible=_coerce_bool(raw.get("kill_switch_visible"), True),
            kill_switch_confirm_engage=_coerce_bool(raw.get("kill_switch_confirm_engage"), False),
            kill_switch_confirm_resume=_coerce_bool(raw.get("kill_switch_confirm_resume"), False),
            kill_switch_persist_across_restarts=_coerce_bool(
                raw.get("kill_switch_persist_across_restarts"), True
            ),
            kill_switch_label=_normalize_kill_switch_label(raw.get("kill_switch_label")),
            kill_switch_hotkey=_normalize_kill_switch_hotkey(raw.get("kill_switch_hotkey")),
            learning_mode=_normalize_learning_mode(raw.get("learning_mode")),
        )


def _atomic_write_text(path: Path, text: str, *, prefix: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=prefix,
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


class AIPolicyStore:
    """Thread-safe, atomically persisted AI Control Panel policy store."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        storage: StorageManager | None = None,
    ) -> None:
        self._has_explicit_path = path is not None
        if path is not None:
            self._path = Path(path).expanduser()
        else:
            self._path = get_workspace_dir() / ".soclens_cache" / "ai_policy.json"
        self._storage: StorageManager | None = storage
        self._lock = threading.RLock()
        self._io_lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def storage(self) -> StorageManager | None:
        return self._storage

    def rebind_storage(self, storage: StorageManager | None) -> None:
        """Thread-safely rebind the backing ``StorageManager``."""
        with self._lock:
            with self._io_lock:
                self._storage = storage

    def rebind_path(self, path: Path | str) -> None:
        """Thread-safely rebind this policy store to a new JSON file path."""
        new_path = Path(path).expanduser()
        with self._lock:
            with self._io_lock:
                self._path = new_path
                self._has_explicit_path = True

    def load(self) -> AIPolicyConfig:
        """Load the persisted AI policy, returning safe defaults if missing or corrupt."""
        stor = self._storage
        if stor is not None:
            payload = stor.load_ai_policy()
            if isinstance(payload, Mapping):
                if "max_tool_steps" not in payload or payload.get("max_tool_steps") is None:
                    merged = dict(payload)
                    merged["max_tool_steps"] = _env_max_tool_steps_default()
                    return AIPolicyConfig.from_dict(merged)
                return AIPolicyConfig.from_dict(payload)
            if not self._has_explicit_path:
                return AIPolicyConfig(max_tool_steps=_env_max_tool_steps_default())

        with self._io_lock:
            if not self._path.is_file():
                return AIPolicyConfig(max_tool_steps=_env_max_tool_steps_default())
            try:
                raw_text = self._path.read_text(encoding="utf-8")
                payload = json.loads(raw_text)
            except (OSError, ValueError) as exc:
                logger.warning("Failed to load AI policy from %s (%s); using defaults.", self._path, exc)
                return AIPolicyConfig(max_tool_steps=_env_max_tool_steps_default())

        if not isinstance(payload, Mapping):
            logger.warning(
                "AI policy file %s contained non-mapping payload (%s); using defaults.",
                self._path,
                type(payload).__name__,
            )
            return AIPolicyConfig(max_tool_steps=_env_max_tool_steps_default())
        if "max_tool_steps" not in payload or payload.get("max_tool_steps") is None:
            merged = dict(payload)
            merged["max_tool_steps"] = _env_max_tool_steps_default()
            return AIPolicyConfig.from_dict(merged)
        return AIPolicyConfig.from_dict(payload)

    def save(self, policy: AIPolicyConfig) -> None:
        """Persist ``policy`` atomically to storage and/or disk."""
        normalized = AIPolicyConfig.from_dict(policy.to_dict())
        stor = self._storage
        if stor is not None:
            stor.save_ai_policy(normalized.to_dict())
            if not self._has_explicit_path:
                return
        serialized = json.dumps(normalized.to_dict(), indent=2, ensure_ascii=False) + "\n"
        with self._io_lock:
            _atomic_write_text(self._path, serialized, prefix=".ai_policy.")

    def update(self, **kwargs: Any) -> AIPolicyConfig:
        """Atomically update one or more policy fields and persist to disk."""
        valid_fields = {f.name for f in fields(AIPolicyConfig)}
        for key in kwargs:
            if key not in valid_fields:
                raise ValueError(f"Unknown AI policy field: {key!r}")

        with self._lock:
            merged = self.load().to_dict()
            merged.update(kwargs)
            updated = AIPolicyConfig.from_dict(merged)
            self.save(updated)
            return updated


@dataclass(frozen=True)
class PermissionDecision:
    """Outcome of a fail-closed AI tool permission evaluation."""

    allowed: bool
    reason: str
    rule: str


def _resolve_registered_tools(registered_tools: Collection[str] | None) -> frozenset[str]:
    if registered_tools is not None:
        return frozenset(
            str(name).strip()
            for name in registered_tools
            if isinstance(name, str) and name.strip()
        )
    return get_registered_readonly_tool_names()


def evaluate_tool_permission(
    tool_name: str,
    source_category: str,
    is_readonly: bool,
    mode: InvestigationMode | str,
    policy: AIPolicyConfig,
    arguments: dict[str, Any] | None = None,
    *,
    registered_tools: Collection[str] | None = None,
) -> PermissionDecision:
    """Evaluate tool invocation permission in strict fail-closed order.

    Evaluation order:
      1. Read-only & registration check -> ``readonly_enforced``
      2. Investigation mode check -> ``ask_only_no_tools`` / ``invalid_mode``
      3. Global cross-search toggle -> ``cross_search_disabled``
      4. Source category toggle -> ``source_disabled:{source_category}``
      5. Per-tool disable list -> ``tool_disabled``
      6. SPL read-only validation when ``tool_name == "splunk_search"`` and
         ``arguments`` includes ``"spl"`` -> ``spl_readonly_violation``
      7. Allow -> ``allowed``
    """
    clean_tool = tool_name.strip() if isinstance(tool_name, str) else ""
    known_tools = _resolve_registered_tools(registered_tools)

    # 1. Fail-closed read-only & allowlist enforcement (runs before any other check).
    if is_readonly is not True or not clean_tool or clean_tool not in known_tools:
        return PermissionDecision(
            allowed=False,
            reason=(
                f"Tool '{clean_tool or tool_name}' is not a registered read-only tool."
            ),
            rule="readonly_enforced",
        )

    # 1b. Global AI Kill Switch enforcement (blocks all AI tool execution immediately).
    if policy.ai_kill_switch_active:
        return PermissionDecision(
            allowed=False,
            reason="AI Kill Switch is active; all AI tool execution is halted.",
            rule="ai_kill_switch",
        )

    # 2. Mode enforcement.
    if mode == "ask_only":
        return PermissionDecision(
            allowed=False,
            reason="External investigation tools are disabled in ask_only mode.",
            rule="ask_only_no_tools",
        )
    if mode != "full_investigation":
        return PermissionDecision(
            allowed=False,
            reason=f"Unsupported investigation mode: {mode!r}.",
            rule="invalid_mode",
        )

    # 3. Global cross-search toggle.
    if not policy.cross_search_enabled:
        return PermissionDecision(
            allowed=False,
            reason="Cross-source searching is disabled in the AI Control Panel.",
            rule="cross_search_disabled",
        )

    # 4. Per-source category toggle (unknown source categories fail closed).
    clean_cat = source_category.strip() if isinstance(source_category, str) else ""
    toggle_attr = SOURCE_CATEGORY_TOGGLE_MAP.get(clean_cat)
    if toggle_attr is None:
        return PermissionDecision(
            allowed=False,
            reason=f"Unknown or unsupported source category: {source_category!r}.",
            rule=f"source_disabled:{clean_cat or 'unknown'}",
        )
    if not bool(getattr(policy, toggle_attr, False)):
        return PermissionDecision(
            allowed=False,
            reason=f"Source category '{clean_cat}' is disabled in the AI Control Panel.",
            rule=f"source_disabled:{clean_cat}",
        )

    # 5. Per-tool opt-out list (always wins over broader source/cross-search enables).
    disabled_set = {
        item.strip() for item in policy.disabled_tools if isinstance(item, str) and item.strip()
    }
    if clean_tool in disabled_set:
        return PermissionDecision(
            allowed=False,
            reason=f"Tool '{clean_tool}' is disabled in the AI Control Panel.",
            rule="tool_disabled",
        )

    # 5b. Cross-source Recorded Future enforcement for unified_research_target.
    if (
        clean_tool == "unified_research_target"
        and not policy.recorded_future_enabled
        and isinstance(arguments, Mapping)
    ):
        raw_rf = arguments.get("include_rf")
        raw_osint = arguments.get("include_osint")
        want_rf = raw_rf if isinstance(raw_rf, bool) else True
        want_osint = raw_osint if isinstance(raw_osint, bool) else True
        if want_rf and not want_osint:
            return PermissionDecision(
                allowed=False,
                reason=(
                    "Source category 'recorded_future' is disabled in the AI Control Panel "
                    "and include_osint=False leaves no permitted source."
                ),
                rule=f"source_disabled:{SOURCE_CATEGORY_RF}",
            )

    # 6. Defense-in-depth SPL validation if SPL query arguments were supplied.
    if clean_tool == "splunk_search" and isinstance(arguments, Mapping) and "spl" in arguments:
        try:
            from soclens.agent_tools import validate_readonly_spl
        except Exception as exc:
            return PermissionDecision(
                allowed=False,
                reason=f"SPL read-only validator unavailable: {exc}",
                rule="spl_readonly_violation",
            )
        raw_spl = arguments.get("spl")
        valid_spl, spl_reason = validate_readonly_spl(raw_spl if isinstance(raw_spl, str) else "")
        if not valid_spl:
            return PermissionDecision(
                allowed=False,
                reason=spl_reason,
                rule="spl_readonly_violation",
            )

    # 7. Permitted.
    return PermissionDecision(
        allowed=True,
        reason=f"Tool '{clean_tool}' permitted for full_investigation.",
        rule="allowed",
    )


__all__ = [
    "AIPolicyConfig",
    "AIPolicyStore",
    "DEFAULT_KILL_SWITCH_HOTKEY",
    "DEFAULT_KILL_SWITCH_LABEL",
    "DEFAULT_LEARNING_MODE",
    "DEFAULT_MAX_IDENTICAL_TOOL_CALLS",
    "DEFAULT_MAX_SAME_TOOL_FAILURES",
    "DEFAULT_MAX_TOOL_STEPS",
    "InvestigationMode",
    "LearningMode",
    "MAX_IDENTICAL_TOOL_CALLS",
    "MAX_KILL_SWITCH_LABEL_LEN",
    "MAX_SAME_TOOL_FAILURES",
    "MAX_TOOL_STEPS",
    "MIN_IDENTICAL_TOOL_CALLS",
    "MIN_SAME_TOOL_FAILURES",
    "MIN_TOOL_STEPS",
    "PermissionDecision",
    "SOURCE_CATEGORY_LOCAL",
    "SOURCE_CATEGORY_OSINT",
    "SOURCE_CATEGORY_RF",
    "SOURCE_CATEGORY_S1",
    "SOURCE_CATEGORY_SPLUNK",
    "SOURCE_CATEGORY_SPLUNK_ES",
    "SOURCE_CATEGORY_TOGGLE_MAP",
    "VALID_INVESTIGATION_MODES",
    "VALID_KILL_SWITCH_HOTKEYS",
    "VALID_LEARNING_MODES",
    "evaluate_tool_permission",
    "format_kill_switch_hotkey_badge",
    "get_registered_readonly_tool_names",
    "register_readonly_tool_names",
]
