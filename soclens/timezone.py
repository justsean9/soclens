"""Cross-platform timezone resolution, state, and timestamp formatting utilities."""

from __future__ import annotations

import re
import threading
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from soclens.config import ConfigurationError, _clean_optional_str

DEFAULT_TIMEZONE = "UTC"
TIMEZONE_ENV_VAR = "SOCLENS_TIMEZONE"

COMMON_TIMEZONES: tuple[tuple[str, str], ...] = (
    ("UTC (Coordinated Universal Time)", "UTC"),
    ("System Local Timezone", "local"),
    ("US Eastern (America/New_York)", "America/New_York"),
    ("US Central (America/Chicago)", "America/Chicago"),
    ("US Mountain (America/Denver)", "America/Denver"),
    ("US Pacific (America/Los_Angeles)", "America/Los_Angeles"),
    ("US Alaska (America/Anchorage)", "America/Anchorage"),
    ("US Hawaii (Pacific/Honolulu)", "Pacific/Honolulu"),
    ("Canada Toronto (America/Toronto)", "America/Toronto"),
    ("UK London (Europe/London)", "Europe/London"),
    ("EU Central (Europe/Berlin)", "Europe/Berlin"),
    ("India (Asia/Kolkata)", "Asia/Kolkata"),
    ("Singapore (Asia/Singapore)", "Asia/Singapore"),
    ("Japan (Asia/Tokyo)", "Asia/Tokyo"),
    ("Australia Sydney (Australia/Sydney)", "Australia/Sydney"),
)

# Fallback standard offsets when tzdata is unavailable on minimal Windows environments.
_FALLBACK_FIXED_OFFSETS: dict[str, tuple[str, int]] = {
    "America/New_York": ("EST", -300),
    "America/Toronto": ("EST", -300),
    "America/Chicago": ("CST", -360),
    "America/Denver": ("MST", -420),
    "America/Phoenix": ("MST", -420),
    "America/Los_Angeles": ("PST", -480),
    "America/Anchorage": ("AKST", -540),
    "Pacific/Honolulu": ("HST", -600),
    "Europe/London": ("GMT", 0),
    "Europe/Berlin": ("CET", 60),
    "Europe/Paris": ("CET", 60),
    "Asia/Kolkata": ("IST", 330),
    "Asia/Singapore": ("SGT", 480),
    "Asia/Tokyo": ("JST", 540),
    "Australia/Sydney": ("AEST", 600),
}

_CANONICAL_IANA_CI: dict[str, str] = {
    val.lower(): val for _label, val in COMMON_TIMEZONES if val.lower() not in {"utc", "local"}
}
for _iana in _FALLBACK_FIXED_OFFSETS:
    _CANONICAL_IANA_CI.setdefault(_iana.lower(), _iana)

_OFFSET_RE = re.compile(
    r"^(?:(?:UTC|GMT)\s*)?([+-])\s*(\d{1,2})(?::?(\d{2}))?$",
    re.IGNORECASE,
)

_TZ_LOCK = threading.RLock()
_ACTIVE_TIMEZONE: str | None = None


def _format_fixed_offset_name(offset_minutes: int) -> str:
    if offset_minutes == 0:
        return "UTC"
    sign = "+" if offset_minutes > 0 else "-"
    total = abs(offset_minutes)
    hh, mm = divmod(total, 60)
    return f"UTC{sign}{hh:02d}:{mm:02d}"


def resolve_timezone(tz_name: str | None) -> tuple[str, tzinfo]:
    """Validate and resolve a timezone string into ``(canonical_name, tzinfo)``.

    Supports ``"UTC"``, ``"local"`` / ``"system"``, fixed offsets (e.g.
    ``"UTC-05:00"``, ``"+02:00"``, ``"UTC+5"``), and IANA timezone names
    (e.g. ``"America/New_York"``).
    """
    raw = _clean_optional_str(tz_name)
    if not raw:
        return DEFAULT_TIMEZONE, UTC

    low = raw.lower()
    if low in {"utc", "z", "gmt", "etc/utc", "etc/gmt"}:
        return DEFAULT_TIMEZONE, UTC

    if low in {"local", "system", "localtime"}:
        local_tz = datetime.now().astimezone().tzinfo or UTC
        return "local", local_tz

    match = _OFFSET_RE.fullmatch(raw)
    if match:
        sign_str, hh_str, mm_str = match.groups()
        hours = int(hh_str)
        mins = int(mm_str or "0")
        total_minutes = hours * 60 + mins
        if hours > 23 or mins >= 60 or total_minutes >= 24 * 60:
            raise ConfigurationError(f"Invalid UTC offset timezone: {tz_name!r}")
        if sign_str == "-":
            total_minutes = -total_minutes
        if total_minutes == 0:
            return DEFAULT_TIMEZONE, UTC
        label = _format_fixed_offset_name(total_minutes)
        return label, timezone(timedelta(minutes=total_minutes), name=label)

    canonical = _CANONICAL_IANA_CI.get(low, raw)
    try:
        zi = ZoneInfo(canonical)
        return zi.key, zi
    except (ZoneInfoNotFoundError, ValueError, OSError):
        fallback = _FALLBACK_FIXED_OFFSETS.get(canonical)
        if fallback is not None:
            abbr, mins = fallback
            return canonical, timezone(timedelta(minutes=mins), name=abbr)
        raise ConfigurationError(
            f"Unknown timezone '{tz_name}'. Use 'UTC', 'local', an IANA name like "
            "'America/New_York', or an offset like 'UTC-05:00'."
        ) from None


def get_configured_timezone(explicit: str | None = None) -> str:
    """Resolve configured timezone from ``explicit``, ``SOCLENS_TIMEZONE``, or ``UTC``."""
    import os

    cand = _clean_optional_str(explicit) or _clean_optional_str(os.environ.get(TIMEZONE_ENV_VAR))
    if not cand:
        return DEFAULT_TIMEZONE
    canonical, _tz = resolve_timezone(cand)
    return canonical


def get_active_timezone() -> str:
    """Return the active TUI/CLI timezone name (default: ``UTC``)."""
    with _TZ_LOCK:
        if _ACTIVE_TIMEZONE is not None:
            return _ACTIVE_TIMEZONE
    return get_configured_timezone()


def set_active_timezone(tz_name: str) -> str:
    """Validate and set the process-wide active timezone, returning canonical name."""
    canonical, _tz = resolve_timezone(tz_name)
    with _TZ_LOCK:
        global _ACTIVE_TIMEZONE
        _ACTIVE_TIMEZONE = canonical
    return canonical


def reset_active_timezone() -> None:
    """Clear explicit runtime timezone override so environment/default applies."""
    with _TZ_LOCK:
        global _ACTIVE_TIMEZONE
        _ACTIVE_TIMEZONE = None


def format_timezone_label(tz_name: str | None = None) -> str:
    """Build a compact badge such as ``UTC``, ``EST``, ``Local (EST)``, or ``UTC-05:00``."""
    canonical, tz_obj = resolve_timezone(tz_name or get_active_timezone())
    if canonical == DEFAULT_TIMEZONE:
        return DEFAULT_TIMEZONE
    if canonical == "local":
        abbr = datetime.now(tz_obj).tzname() or "Local"
        return f"Local ({abbr})"
    sample = datetime.now(tz_obj)
    tz_abbr = sample.tzname() or ""
    if tz_abbr and not tz_abbr.startswith(("+", "-")):
        return tz_abbr
    if canonical.startswith(("UTC+", "UTC-")):
        return canonical
    offset = sample.utcoffset()
    if offset is None:
        return canonical
    return _format_fixed_offset_name(int(offset.total_seconds() // 60))


def parse_iso_datetime(ts: Any) -> tuple[datetime, bool] | None:
    """Parse an ISO-8601 string or date-only string into ``(utc_or_aware_dt, has_time)``."""
    if isinstance(ts, datetime):
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)
        return dt, True
    if not isinstance(ts, str):
        return None
    clean = ts.strip()
    if not clean:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", clean):
        try:
            dt_date = datetime.fromisoformat(clean).replace(tzinfo=UTC)
            return dt_date, False
        except ValueError:
            return None
    norm = clean[:-1] + "+00:00" if clean.endswith(("Z", "z")) else clean
    try:
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt, True
    except ValueError:
        return None


def _tz_abbr_for_dt(local_dt: datetime, canonical: str) -> str:
    name = local_dt.tzname()
    if name and name not in {"UTC", "GMT"} and not name.startswith(("+", "-")):
        return name
    if canonical == DEFAULT_TIMEZONE:
        return "Z"
    if canonical.startswith(("UTC+", "UTC-")):
        return canonical
    offset = local_dt.utcoffset()
    if offset is None:
        return canonical
    mins = int(offset.total_seconds() // 60)
    if mins == 0:
        return "UTC"
    return _format_fixed_offset_name(mins)


def format_iso_timestamp(
    ts: Any,
    *,
    tz_name: str | None = None,
    include_seconds: bool = False,
) -> str:
    """Format an ISO-8601 timestamp compactly in the active or specified timezone."""
    if not isinstance(ts, str) or not ts.strip():
        return "-"
    clean = ts.strip()
    parsed = parse_iso_datetime(clean)
    if parsed is None:
        if "T" in clean:
            date_part, time_part = clean.split("T", 1)
            hhmm = time_part[:5]
            suffix = "Z" if clean.endswith("Z") else ""
            return f"{date_part} {hhmm}{suffix}"
        return clean[:19]

    dt, has_time = parsed
    if not has_time:
        return dt.strftime("%Y-%m-%d")

    canonical, tz_obj = resolve_timezone(tz_name or get_active_timezone())
    converted = dt.astimezone(tz_obj)
    time_fmt = "%Y-%m-%d %H:%M:%S" if include_seconds else "%Y-%m-%d %H:%M"
    if canonical == DEFAULT_TIMEZONE:
        return f"{converted.strftime(time_fmt)}Z"
    abbr = _tz_abbr_for_dt(converted, canonical)
    return f"{converted.strftime(time_fmt)} {abbr}"


def format_iso_date_or_timestamp(ts: Any, *, tz_name: str | None = None) -> str:
    """Format midnight ISO dates as ``YYYY-MM-DD`` and full timestamps in active timezone."""
    if not isinstance(ts, str) or not ts.strip():
        return "-"
    clean = ts.strip()
    if clean.endswith(("T00:00:00Z", "T00:00:00.000Z")) and len(clean) >= 10:
        return clean[:10]
    return format_iso_timestamp(clean, tz_name=tz_name)


def format_datetime_in_tz(
    dt: datetime,
    *,
    tz_name: str | None = None,
    fmt: str = "%H:%M:%S",
) -> str:
    """Format an explicit ``datetime`` instance in the active or specified timezone."""
    aware = dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    canonical, tz_obj = resolve_timezone(tz_name or get_active_timezone())
    converted = aware.astimezone(tz_obj)
    return converted.strftime(fmt)


def now_in_active_timezone() -> datetime:
    """Return current wall-clock ``datetime`` in the active timezone."""
    _canonical, tz_obj = resolve_timezone(get_active_timezone())
    return datetime.now(tz_obj)
