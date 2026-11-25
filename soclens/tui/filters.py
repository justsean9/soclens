"""Shared timeframe, priority, assignee, sorting, and filter preset utilities for the TUI."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from soclens.config import load_tui_settings, save_tui_settings
from soclens.timezone import parse_iso_datetime
from soclens.tui.rf_formatters import normalize_status_key

TIMEFRAME_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Time: Any", "any"),
    ("Last 24h", "last_24h"),
    ("Last 48h", "last_48h"),
    ("Last 7d", "last_7d"),
    ("Last 14d", "last_14d"),
    ("Last 30d", "last_30d"),
    ("Last 90d", "last_90d"),
    ("Older > 7d", "older_7d"),
    ("Older > 14d", "older_14d"),
    ("Older > 30d", "older_30d"),
    ("Older > 60d", "older_60d"),
    ("Older > 90d", "older_90d"),
    ("Custom Range...", "custom"),
)

PRIORITY_FILTER_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Priority: Any", "any"),
    ("High & Critical", "high_crit"),
    ("Critical", "critical"),
    ("High", "high"),
    ("Moderate / Med", "moderate"),
    ("Low / Info", "low_info"),
)

ASSIGNEE_FILTER_BASE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Assignee: Any", "any"),
    ("Unassigned", "unassigned"),
    ("Assigned (Any)", "assigned"),
)

SORT_FILTER_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Sort: Newest", "newest"),
    ("Sort: Oldest", "oldest"),
    ("Sort: Priority", "priority_desc"),
    ("Sort: Status", "status"),
)

TIME_FIELD_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Time Field: Auto", "auto"),
    ("Field: Created / Triggered", "created"),
    ("Field: Updated / Modified", "updated"),
)

LOG_TIMEFRAME_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Time: Any", "any"),
    ("Last 5m", "last_5m"),
    ("Last 15m", "last_15m"),
    ("Last 1h", "last_1h"),
    ("Last 24h", "last_24h"),
)

SPLUNK_TIME_PRESETS: tuple[tuple[str, str], ...] = (
    ("Last 15m (-15m)", "-15m"),
    ("Last 1h (-1h)", "-1h"),
    ("Last 4h (-4h)", "-4h"),
    ("Last 24h (-24h)", "-24h"),
    ("Last 48h (-48h)", "-48h"),
    ("Last 7d (-7d)", "-7d"),
    ("Last 14d (-14d)", "-14d"),
    ("Last 30d (-30d)", "-30d"),
    ("Last 90d (-90d)", "-90d"),
    ("Custom", "custom"),
)

ES_TIMEFRAME_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Last 24h (-24h)", "-24h"),
    ("Last 48h (-48h)", "-48h"),
    ("Last 7d (-7d)", "-7d"),
    ("Last 14d (-14d)", "-14d"),
    ("Last 30d (-30d)", "-30d"),
    ("Last 90d (-90d)", "-90d"),
    ("Older > 7d", "older_7d"),
    ("Older > 14d", "older_14d"),
    ("Older > 30d", "older_30d"),
    ("Time: Any", "any"),
    ("Custom", "custom"),
)

_RELATIVE_WINDOW_DELTAS: dict[str, timedelta] = {
    "last_5m": timedelta(minutes=5),
    "last_15m": timedelta(minutes=15),
    "-15m": timedelta(minutes=15),
    "last_1h": timedelta(hours=1),
    "-1h": timedelta(hours=1),
    "last_4h": timedelta(hours=4),
    "-4h": timedelta(hours=4),
    "last_24h": timedelta(hours=24),
    "-24h": timedelta(hours=24),
    "last_48h": timedelta(hours=48),
    "-48h": timedelta(hours=48),
    "last_7d": timedelta(days=7),
    "-7d": timedelta(days=7),
    "last_14d": timedelta(days=14),
    "-14d": timedelta(days=14),
    "last_30d": timedelta(days=30),
    "-30d": timedelta(days=30),
    "last_60d": timedelta(days=60),
    "-60d": timedelta(days=60),
    "last_90d": timedelta(days=90),
    "-90d": timedelta(days=90),
}

_OLDER_WINDOW_DELTAS: dict[str, timedelta] = {
    "older_7d": timedelta(days=7),
    "older_14d": timedelta(days=14),
    "older_30d": timedelta(days=30),
    "older_60d": timedelta(days=60),
    "older_90d": timedelta(days=90),
}

_PRIORITY_RANK: dict[str, int] = {
    "critical": 5,
    "urgent": 5,
    "high": 4,
    "moderate": 3,
    "medium": 3,
    "warn": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}

_STATUS_SORT_RANK: dict[str, int] = {
    "new": 0,
    "open": 1,
    "unassigned": 2,
    "inprogress": 3,
    "pending": 4,
    "assigned": 5,
    "actionable": 6,
    "resolved": 7,
    "dismissed": 8,
    "closed": 9,
}

_RELATIVE_TEXT_RE = re.compile(r"^-(\d+)\s*([mhdw])$", re.IGNORECASE)
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_CUSTOM_PRESETS_SETTINGS_KEY = "rf_filter_presets"


@dataclass(frozen=True)
class FilterPreset:
    """Reusable multi-faceted filter view definition for RF Intel & Alerts."""

    id: str
    label: str
    statuses: tuple[str, ...] = ()
    priority: str = "any"
    timeframe: str = "any"
    assignee: str = "any"
    sort_by: str = "newest"
    time_field: str = "auto"
    pb_category: str = "all"
    rule_query: str = ""
    entity_query: str = ""
    text_query: str = ""
    date_from: str = ""
    date_to: str = ""
    builtin: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize preset into a JSON-safe dictionary."""
        data = asdict(self)
        data["statuses"] = list(self.statuses)
        return data

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], *, builtin: bool = False) -> FilterPreset:
        """Deserialize a preset dictionary safely with resilient defaults."""
        pid = str(raw.get("id") or "").strip() or "custom"
        label = str(raw.get("label") or pid).strip() or pid
        statuses_raw = raw.get("statuses")
        statuses: tuple[str, ...] = (
            tuple(str(s).strip() for s in statuses_raw if str(s).strip())
            if isinstance(statuses_raw, (list, tuple))
            else ()
        )
        return cls(
            id=pid,
            label=label,
            statuses=statuses,
            priority=str(raw.get("priority") or "any").strip() or "any",
            timeframe=str(raw.get("timeframe") or "any").strip() or "any",
            assignee=str(raw.get("assignee") or "any").strip() or "any",
            sort_by=str(raw.get("sort_by") or "newest").strip() or "newest",
            time_field=str(raw.get("time_field") or "auto").strip() or "auto",
            pb_category=str(raw.get("pb_category") or "all").strip() or "all",
            rule_query=str(raw.get("rule_query") or ""),
            entity_query=str(raw.get("entity_query") or ""),
            text_query=str(raw.get("text_query") or ""),
            date_from=str(raw.get("date_from") or ""),
            date_to=str(raw.get("date_to") or ""),
            builtin=bool(raw.get("builtin", builtin)),
        )


BUILTIN_RF_PRESETS: tuple[FilterPreset, ...] = (
    FilterPreset(
        id="all",
        label="View: All Alerts",
        builtin=True,
    ),
    FilterPreset(
        id="active_7d",
        label="Active: New + InProg (7d)",
        statuses=("New", "InProgress"),
        timeframe="last_7d",
        sort_by="newest",
        builtin=True,
    ),
    FilterPreset(
        id="fresh_24h",
        label="Fresh: New + InProg (24h)",
        statuses=("New", "InProgress"),
        timeframe="last_24h",
        sort_by="newest",
        builtin=True,
    ),
    FilterPreset(
        id="new_24h",
        label="Brand New (Last 24h)",
        statuses=("New", "Open"),
        timeframe="last_24h",
        sort_by="newest",
        builtin=True,
    ),
    FilterPreset(
        id="high_crit_active_7d",
        label="Urgent: High/Crit Active (7d)",
        statuses=("New", "InProgress", "Pending", "Open"),
        priority="high_crit",
        timeframe="last_7d",
        sort_by="priority_desc",
        builtin=True,
    ),
    FilterPreset(
        id="unassigned_new_7d",
        label="Unassigned New (Last 7d)",
        statuses=("New", "Open"),
        assignee="unassigned",
        timeframe="last_7d",
        sort_by="newest",
        builtin=True,
    ),
    FilterPreset(
        id="pending_followup_14d",
        label="Pending Follow-Up (14d)",
        statuses=("Pending", "InProgress"),
        timeframe="last_14d",
        sort_by="oldest",
        builtin=True,
    ),
    FilterPreset(
        id="cleanup_old_new_7d",
        label="Cleanup: Old New (>7d)",
        statuses=("New", "Open"),
        timeframe="older_7d",
        sort_by="oldest",
        builtin=True,
    ),
    FilterPreset(
        id="cleanup_old_new_30d",
        label="Cleanup: Stale New (>30d)",
        statuses=("New", "Open"),
        timeframe="older_30d",
        sort_by="oldest",
        builtin=True,
    ),
    FilterPreset(
        id="cleanup_stale_inprog_14d",
        label="Cleanup: Stale Active (>14d)",
        statuses=("InProgress", "Pending"),
        timeframe="older_14d",
        sort_by="oldest",
        builtin=True,
    ),
    FilterPreset(
        id="cleanup_old_low_14d",
        label="Cleanup: Old Low/Info (>14d)",
        statuses=("New", "Open"),
        priority="low_info",
        timeframe="older_14d",
        sort_by="oldest",
        builtin=True,
    ),
    FilterPreset(
        id="cleanup_unassigned_old_14d",
        label="Cleanup: Unassigned Old (>14d)",
        statuses=("New", "Open", "Pending"),
        assignee="unassigned",
        timeframe="older_14d",
        sort_by="oldest",
        builtin=True,
    ),
    FilterPreset(
        id="resolved_7d",
        label="Recently Resolved (7d)",
        statuses=("Resolved", "Dismissed", "Closed"),
        timeframe="last_7d",
        sort_by="newest",
        builtin=True,
    ),
)

BUILTIN_RF_PRESETS_BY_ID: dict[str, FilterPreset] = {p.id: p for p in BUILTIN_RF_PRESETS}


SPLUNK_ES_PRESETS: tuple[dict[str, Any], ...] = (
    {
        "id": "all",
        "label": "View: All Notables",
        "earliest": "-24h",
        "timeframe": "-24h",
        "statuses": (),
        "urgencies": (),
        "owner_mode": "any",
    },
    {
        "id": "active_24h",
        "label": "Active: New + InProg (24h)",
        "earliest": "-24h",
        "timeframe": "-24h",
        "statuses": ("New", "In Progress"),
        "urgencies": (),
        "owner_mode": "any",
    },
    {
        "id": "active_7d",
        "label": "Active: New + InProg (7d)",
        "earliest": "-7d",
        "timeframe": "-7d",
        "statuses": ("New", "In Progress"),
        "urgencies": (),
        "owner_mode": "any",
    },
    {
        "id": "urgent_24h",
        "label": "Urgent: High/Crit (24h)",
        "earliest": "-24h",
        "timeframe": "-24h",
        "statuses": ("New", "In Progress", "Pending"),
        "urgencies": ("high", "critical"),
        "owner_mode": "any",
    },
    {
        "id": "urgent_7d",
        "label": "Urgent: High/Crit (7d)",
        "earliest": "-7d",
        "timeframe": "-7d",
        "statuses": ("New", "In Progress", "Pending"),
        "urgencies": ("high", "critical"),
        "owner_mode": "any",
    },
    {
        "id": "unassigned_7d",
        "label": "Unassigned New (7d)",
        "earliest": "-7d",
        "timeframe": "-7d",
        "statuses": ("New",),
        "urgencies": (),
        "owner_mode": "unassigned",
    },
    {
        "id": "cleanup_old_new_7d",
        "label": "Cleanup: Old New (>7d)",
        "earliest": "-30d",
        "timeframe": "older_7d",
        "statuses": ("New",),
        "urgencies": (),
        "owner_mode": "any",
    },
    {
        "id": "cleanup_old_new_14d",
        "label": "Cleanup: Stale New (>14d)",
        "earliest": "-90d",
        "timeframe": "older_14d",
        "statuses": ("New",),
        "urgencies": (),
        "owner_mode": "any",
    },
    {
        "id": "cleanup_stale_inprog_14d",
        "label": "Cleanup: Stale InProg (>14d)",
        "earliest": "-90d",
        "timeframe": "older_14d",
        "statuses": ("In Progress", "Pending"),
        "urgencies": (),
        "owner_mode": "any",
    },
    {
        "id": "closed_7d",
        "label": "Resolved / Closed (7d)",
        "earliest": "-7d",
        "timeframe": "-7d",
        "statuses": ("Resolved", "Closed"),
        "urgencies": (),
        "owner_mode": "any",
    },
)


S1_PRESETS_BY_VIEW: dict[str, tuple[dict[str, Any], ...]] = {
    "threats": (
        {"id": "all", "label": "View: Alerts (Last 24h)", "timeframe": "last_24h", "status": "any"},
        {"id": "all_time", "label": "View: All Time Alerts", "timeframe": "any", "status": "any"},
        {
            "id": "active_24h",
            "label": "Active Unresolved (24h)",
            "timeframe": "last_24h",
            "status": "unresolved",
        },
        {
            "id": "active_7d",
            "label": "Active Unresolved (7d)",
            "timeframe": "last_7d",
            "status": "unresolved",
        },
        {
            "id": "tp_7d",
            "label": "True Positives (7d)",
            "timeframe": "last_7d",
            "status": "true_positive",
        },
        {
            "id": "undefined_7d",
            "label": "Needs Verdict (7d)",
            "timeframe": "last_7d",
            "status": "undefined",
        },
        {
            "id": "cleanup_old_7d",
            "label": "Cleanup: Old Unresolved (>7d)",
            "timeframe": "older_7d",
            "status": "unresolved",
        },
        {
            "id": "cleanup_old_30d",
            "label": "Cleanup: Stale Unresolved (>30d)",
            "timeframe": "older_30d",
            "status": "unresolved",
        },
        {
            "id": "resolved_7d",
            "label": "Resolved (Last 7d)",
            "timeframe": "last_7d",
            "status": "resolved",
        },
    ),
    "endpoints": (
        {"id": "all", "label": "View: All Endpoints", "timeframe": "any", "status": "any"},
        {"id": "infected", "label": "Infected Endpoints", "timeframe": "any", "status": "infected"},
        {
            "id": "isolated",
            "label": "Isolated / Disconnected",
            "timeframe": "any",
            "status": "disconnected",
        },
        {
            "id": "connected",
            "label": "Connected Healthy",
            "timeframe": "any",
            "status": "connected",
        },
    ),
    "sites_activities": (
        {"id": "all", "label": "View: All Records", "timeframe": "any", "status": "any"},
        {"id": "recent_24h", "label": "Recent (24h)", "timeframe": "last_24h", "status": "any"},
        {"id": "recent_7d", "label": "Recent (7d)", "timeframe": "last_7d", "status": "any"},
        {
            "id": "cleanup_old_7d",
            "label": "Cleanup: Older (>7d)",
            "timeframe": "older_7d",
            "status": "any",
        },
    ),
    "exclusions": (
        {"id": "all", "label": "View: All Exclusions", "timeframe": "any", "status": "any"},
    ),
    "blocklist": (
        {"id": "all", "label": "View: All Blocklist", "timeframe": "any", "status": "any"},
    ),
    "users_rbac": (
        {"id": "all", "label": "View: All Users & RBAC", "timeframe": "any", "status": "any"},
    ),
}


def sanitize_preset_id(label: str) -> str:
    """Derive a clean slug identifier for a custom filter preset."""
    slug = _SLUG_RE.sub("_", label.strip().lower()).strip("_")
    return f"custom_{slug[:36] or 'view'}"


def load_custom_rf_presets(workspace_dir: Path | str | None = None) -> list[FilterPreset]:
    """Load user-saved custom RF filter presets from TUI settings."""
    settings = load_tui_settings(workspace_dir=workspace_dir)
    raw_list = settings.get(_CUSTOM_PRESETS_SETTINGS_KEY)
    if not isinstance(raw_list, list):
        return []
    presets: list[FilterPreset] = []
    seen: set[str] = set()
    for item in raw_list:
        if not isinstance(item, Mapping):
            continue
        preset = FilterPreset.from_dict(item, builtin=False)
        if preset.id in BUILTIN_RF_PRESETS_BY_ID or preset.id in seen:
            continue
        seen.add(preset.id)
        presets.append(preset)
    return presets


def save_custom_rf_preset(
    preset: FilterPreset,
    workspace_dir: Path | str | None = None,
) -> list[FilterPreset]:
    """Persist or update a custom RF filter preset and return the updated custom list."""
    existing = load_custom_rf_presets(workspace_dir=workspace_dir)
    pid = preset.id if preset.id not in BUILTIN_RF_PRESETS_BY_ID else sanitize_preset_id(preset.label)
    cleaned = FilterPreset(
        id=pid,
        label=preset.label.strip() or pid,
        statuses=tuple(preset.statuses),
        priority=preset.priority,
        timeframe=preset.timeframe,
        assignee=preset.assignee,
        sort_by=preset.sort_by,
        time_field=preset.time_field,
        pb_category=preset.pb_category,
        rule_query=preset.rule_query,
        entity_query=preset.entity_query,
        text_query=preset.text_query,
        date_from=preset.date_from,
        date_to=preset.date_to,
        builtin=False,
    )
    updated = [p for p in existing if p.id != cleaned.id]
    updated.append(cleaned)
    save_tui_settings(
        {_CUSTOM_PRESETS_SETTINGS_KEY: [p.to_dict() for p in updated]},
        workspace_dir=workspace_dir,
    )
    return updated


def delete_custom_rf_preset(
    preset_id: str,
    workspace_dir: Path | str | None = None,
) -> list[FilterPreset]:
    """Remove a saved custom RF filter preset by ID and return remaining custom presets."""
    existing = load_custom_rf_presets(workspace_dir=workspace_dir)
    updated = [p for p in existing if p.id != preset_id]
    save_tui_settings(
        {_CUSTOM_PRESETS_SETTINGS_KEY: [p.to_dict() for p in updated]},
        workspace_dir=workspace_dir,
    )
    return updated


def get_all_rf_presets(workspace_dir: Path | str | None = None) -> list[FilterPreset]:
    """Return built-in RF filter presets followed by user-saved custom presets."""
    return list(BUILTIN_RF_PRESETS) + load_custom_rf_presets(workspace_dir=workspace_dir)


def timeframe_label(timeframe: str) -> str:
    """Return human-readable label for a timeframe key."""
    for lbl, val in TIMEFRAME_OPTIONS:
        if val == timeframe:
            return lbl
    for lbl, val in ES_TIMEFRAME_OPTIONS:
        if val == timeframe:
            return lbl
    for lbl, val in LOG_TIMEFRAME_OPTIONS:
        if val == timeframe:
            return lbl
    return timeframe


def _parse_bound_datetime(raw: str, *, is_end: bool, now_ref: datetime) -> datetime | None:
    clean = raw.strip()
    if not clean:
        return None
    rel_match = _RELATIVE_TEXT_RE.fullmatch(clean)
    if rel_match:
        amount = int(rel_match.group(1))
        unit = rel_match.group(2).lower()
        unit_map = {
            "m": timedelta(minutes=amount),
            "h": timedelta(hours=amount),
            "d": timedelta(days=amount),
            "w": timedelta(weeks=amount),
        }
        return now_ref - unit_map[unit]
    parsed = parse_iso_datetime(clean)
    if parsed is None:
        return None
    dt, has_time = parsed
    dt_utc = dt.astimezone(UTC)
    if is_end and not has_time:
        return dt_utc + timedelta(days=1) - timedelta(microseconds=1)
    return dt_utc


def compute_timeframe_bounds(
    timeframe: str,
    *,
    date_from: str = "",
    date_to: str = "",
    now_utc: datetime | None = None,
) -> tuple[datetime | None, datetime | None]:
    """Resolve ``(start_utc, end_utc)`` inclusive bounds for a timeframe key."""
    key = (timeframe or "any").strip().lower()
    if key == "any":
        return None, None

    now_ref = (now_utc or datetime.now(UTC)).astimezone(UTC)
    if key in _RELATIVE_WINDOW_DELTAS:
        return now_ref - _RELATIVE_WINDOW_DELTAS[key], None
    if key in _OLDER_WINDOW_DELTAS:
        return None, now_ref - _OLDER_WINDOW_DELTAS[key]
    if key == "custom":
        start = _parse_bound_datetime(date_from, is_end=False, now_ref=now_ref)
        end = _parse_bound_datetime(date_to, is_end=True, now_ref=now_ref)
        return start, end
    return None, None


def timestamp_matches_timeframe(
    ts: Any,
    timeframe: str,
    *,
    date_from: str = "",
    date_to: str = "",
    now_utc: datetime | None = None,
) -> bool:
    """Return True when timestamp ``ts`` falls inside the selected timeframe window."""
    key = (timeframe or "any").strip().lower()
    if key == "any":
        return True
    start, end = compute_timeframe_bounds(
        key, date_from=date_from, date_to=date_to, now_utc=now_utc
    )
    if start is None and end is None:
        return True

    parsed = parse_iso_datetime(ts)
    if parsed is None:
        return False
    dt, _has_time = parsed
    dt_utc = dt.astimezone(UTC)
    if start is not None and dt_utc < start:
        return False
    if end is not None and dt_utc > end:
        return False
    return True


def extract_item_timestamp(
    item: Mapping[str, Any],
    mode: str,
    time_field: str = "auto",
) -> str:
    """Select the primary timestamp string for an RF record in ``mode``."""
    field = (time_field or "auto").strip().lower()
    if mode == "alerts_v3":
        if field == "updated":
            return str(item.get("status_date") or item.get("triggered") or "")
        return str(item.get("triggered") or item.get("status_date") or "")
    if mode in ("playbook", "cases"):
        if field == "created":
            return str(item.get("created") or item.get("updated") or "")
        return str(item.get("updated") or item.get("created") or "")
    if mode == "sandbox":
        if field == "updated":
            return str(item.get("completed") or item.get("submitted") or "")
        return str(item.get("submitted") or item.get("completed") or "")
    if mode == "intel_v2":
        ts_obj = item.get("timestamps")
        if isinstance(ts_obj, Mapping):
            if field == "created":
                return str(ts_obj.get("firstSeen") or ts_obj.get("lastSeen") or "")
            return str(ts_obj.get("lastSeen") or ts_obj.get("firstSeen") or "")
    return str(
        item.get("updated")
        or item.get("triggered")
        or item.get("created")
        or item.get("submitted")
        or ""
    )


def priority_matches_filter(priority_val: Any, filter_key: str) -> bool:
    """Match an alert/case priority string against a filter key."""
    key = (filter_key or "any").strip().lower()
    if key == "any":
        return True
    norm = str(priority_val or "").strip().lower()
    if key == "high_crit":
        return norm in {"critical", "high", "urgent"}
    if key == "critical":
        return norm in {"critical", "urgent"}
    if key == "high":
        return norm == "high"
    if key == "moderate":
        return norm in {"moderate", "medium", "warn"}
    if key == "low_info":
        return norm in {"low", "informational", "info"}
    return norm == key


def assignee_matches_filter(assignee_val: Any, filter_key: str) -> bool:
    """Match an assignee display string against ``any``, ``unassigned``, ``assigned``, or name."""
    key = (filter_key or "any").strip()
    low_key = key.lower()
    if not low_key or low_key == "any":
        return True
    clean = str(assignee_val or "").strip()
    is_unassigned = not clean or clean in {"-", "unassigned", "Unassigned", "none", "None"}
    if low_key == "unassigned":
        return is_unassigned
    if low_key == "assigned":
        return not is_unassigned
    return clean.lower() == low_key


def _parse_sort_epoch(ts: Any) -> float:
    parsed = parse_iso_datetime(ts)
    if parsed is None:
        return 0.0
    return parsed[0].astimezone(UTC).timestamp()


def sort_rf_items(
    items: Sequence[dict[str, Any]],
    mode: str,
    sort_by: str,
) -> list[dict[str, Any]]:
    """Return a sorted copy of RF items according to ``sort_by``."""
    rows = list(items)
    key = (sort_by or "newest").strip().lower()
    if key == "oldest":
        rows.sort(key=lambda it: _parse_sort_epoch(extract_item_timestamp(it, mode)))
        return rows
    if key == "priority_desc":
        rows.sort(
            key=lambda it: (
                _PRIORITY_RANK.get(str(it.get("priority") or "").strip().lower(), 0),
                _parse_sort_epoch(extract_item_timestamp(it, mode)),
            ),
            reverse=True,
        )
        return rows
    if key == "status":
        rows.sort(
            key=lambda it: (
                _STATUS_SORT_RANK.get(normalize_status_key(it.get("status")), 50),
                normalize_status_key(it.get("status")),
                -_parse_sort_epoch(extract_item_timestamp(it, mode)),
            )
        )
        return rows
    # Default: newest first when timestamps exist (preserving original order on ties)
    if any(extract_item_timestamp(it, mode) for it in rows):
        rows.sort(
            key=lambda it: _parse_sort_epoch(extract_item_timestamp(it, mode)),
            reverse=True,
        )
    return rows


def _fmt_iso_utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_alerts_v3_triggered_param(
    timeframe: str,
    *,
    date_from: str = "",
    date_to: str = "",
    now_utc: datetime | None = None,
) -> str | None:
    """Build Recorded Future ``GET /alert/v3`` ``triggered`` range query parameter."""
    key = (timeframe or "any").strip().lower()
    if key == "any":
        return None
    start, end = compute_timeframe_bounds(
        key, date_from=date_from, date_to=date_to, now_utc=now_utc
    )
    if start is None and end is None:
        return None
    if start is not None and end is not None:
        return f"[{_fmt_iso_utc(start)},{_fmt_iso_utc(end)}]"
    if start is not None:
        return f"[{_fmt_iso_utc(start)},]"
    assert end is not None
    return f"[,{_fmt_iso_utc(end)}]"


def build_playbook_date_range(
    timeframe: str,
    *,
    date_from: str = "",
    date_to: str = "",
    now_utc: datetime | None = None,
) -> dict[str, str] | None:
    """Build ``POST /playbook-alert/search`` ``created_range`` / ``updated_range`` dict."""
    key = (timeframe or "any").strip().lower()
    if key == "any":
        return None
    start, end = compute_timeframe_bounds(
        key, date_from=date_from, date_to=date_to, now_utc=now_utc
    )
    payload: dict[str, str] = {}
    if start is not None:
        payload["from"] = _fmt_iso_utc(start)
    if end is not None:
        payload["until"] = _fmt_iso_utc(end)
    return payload or None


def build_case_date_range(
    timeframe: str,
    *,
    date_from: str = "",
    date_to: str = "",
    now_utc: datetime | None = None,
) -> dict[str, str] | None:
    """Build ``POST /case/search`` ``created`` / ``modified`` date filter dict."""
    key = (timeframe or "any").strip().lower()
    if key == "any":
        return None
    start, end = compute_timeframe_bounds(
        key, date_from=date_from, date_to=date_to, now_utc=now_utc
    )
    payload: dict[str, str] = {}
    if start is not None:
        payload["after"] = _fmt_iso_utc(start)
    if end is not None:
        payload["before"] = _fmt_iso_utc(end)
    return payload or None


def map_priority_for_playbook(priority_key: str) -> list[str] | None:
    """Map UI priority filter key to Playbook Alert API priority strings."""
    key = (priority_key or "any").strip().lower()
    mapping: dict[str, list[str]] = {
        "high_crit": ["High"],
        "critical": ["High"],
        "high": ["High"],
        "moderate": ["Moderate"],
        "low_info": ["Informational"],
    }
    return mapping.get(key)


def map_priority_for_cases(priority_key: str) -> list[str] | None:
    """Map UI priority filter key to Case API priority strings."""
    key = (priority_key or "any").strip().lower()
    mapping: dict[str, list[str]] = {
        "high_crit": ["Critical", "High"],
        "critical": ["Critical"],
        "high": ["High"],
        "moderate": ["Medium"],
        "low_info": ["Low"],
    }
    return mapping.get(key)
