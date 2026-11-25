"""Cross-platform per-user settings storage, named profiles, and credential registry."""

from __future__ import annotations

import copy
import json
import logging
import math
import os
import re
import stat
import sys
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger("soclens.settings")

APP_CONFIG_DIR_NAME = "soclens"
SETTINGS_FILENAME = "settings.json"
SETTINGS_SCHEMA_VERSION = 1
DEFAULT_PROFILE = "default"

_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_TRUTHY_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on"})
_FALSY_VALUES: frozenset[str] = frozenset({"0", "false", "no", "off"})

# Test hook allowing pytest fixtures to redirect default user settings cleanly even
# when os.environ is cleared by patch.dict(os.environ, {}, clear=True).
_DEFAULT_SETTINGS_PATH_OVERRIDE: Path | None = None

_STORE_LOCK = threading.RLock()
_CACHE: dict[Path, tuple[tuple[int, int] | None, dict[str, Any], str | None]] = {}
_LAST_ERRORS: dict[Path, str] = {}

_SESSION_LOCK = threading.RLock()
_SESSION_OVERRIDES: dict[str, str | None] = {}


@dataclass(frozen=True)
class SettingSpec:
    """Metadata describing a configurable user setting and its env var aliases."""

    key: str
    category: str
    label: str
    env_vars: tuple[str, ...]
    secret: bool = False
    value_type: str = "str"
    default: str | None = None
    mask_url_credentials: bool = False
    description: str = ""


SETTING_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("recorded_future", "Recorded Future API"),
    ("splunk", "Splunk & Splunk ES"),
    ("sentinelone", "SentinelOne EDR"),
    ("network", "Network, SSL & Proxy"),
    ("workspace", "Workspace & Tool Defaults"),
)

SETTING_SPECS: tuple[SettingSpec, ...] = (
    # Recorded Future API
    SettingSpec(
        key="rf_api_token",
        category="recorded_future",
        label="RF Core API Token",
        env_vars=("RF_API_TOKEN", "RECORDED_FUTURE_API_KEY"),
        secret=True,
        description="Primary Recorded Future API token (X-RFToken).",
    ),
    SettingSpec(
        key="rf_sandbox_token",
        category="recorded_future",
        label="RF Sandbox Token",
        env_vars=("RF_SANDBOX_TOKEN",),
        secret=True,
        description="Optional Recorded Future Sandbox token (falls back to Core token).",
    ),
    SettingSpec(
        key="rf_asi_api_key",
        category="recorded_future",
        label="RF ASI / SecurityTrails API Key",
        env_vars=("RF_ASI_API_KEY", "SECURITYTRAILS_API_KEY"),
        secret=True,
        description="Optional Attack Surface Intelligence API key.",
    ),
    SettingSpec(
        key="rf_pfi_token",
        category="recorded_future",
        label="RF Payment Fraud (PFI) Token",
        env_vars=("RF_PFI_TOKEN",),
        secret=True,
        description="Optional Payment Fraud Intelligence token (falls back to Core token).",
    ),
    SettingSpec(
        key="rf_riskrecon_token",
        category="recorded_future",
        label="RF RiskRecon API Token",
        env_vars=("RF_RISKRECON_TOKEN", "RISKRECON_API_TOKEN"),
        secret=True,
        description="Optional RiskRecon third-party posture API bearer token.",
    ),
    SettingSpec(
        key="rf_base_url",
        category="recorded_future",
        label="RF Core Base URL",
        env_vars=("RF_BASE_URL",),
        value_type="url",
        default="https://api.recordedfuture.com",
        description="Base URL for Recorded Future Core REST APIs.",
    ),
    SettingSpec(
        key="rf_sandbox_base_url",
        category="recorded_future",
        label="RF Sandbox Base URL",
        env_vars=("RF_SANDBOX_BASE_URL",),
        value_type="url",
        default="https://sandbox.recordedfuture.com/api/v0",
        description="Base URL for Recorded Future Sandbox v0 API.",
    ),
    SettingSpec(
        key="rf_asi_base_url",
        category="recorded_future",
        label="RF ASI Base URL",
        env_vars=("RF_ASI_BASE_URL",),
        value_type="url",
        default="https://api.securitytrails.com/v2",
        description="Base URL for Attack Surface Intelligence API.",
    ),
    SettingSpec(
        key="rf_pfi_base_url",
        category="recorded_future",
        label="RF PFI Base URL",
        env_vars=("RF_PFI_BASE_URL",),
        value_type="url",
        default="https://pfi.regemini.com/api/v1",
        description="Base URL for Payment Fraud Intelligence API.",
    ),
    SettingSpec(
        key="rf_riskrecon_base_url",
        category="recorded_future",
        label="RF RiskRecon Base URL",
        env_vars=("RF_RISKRECON_BASE_URL",),
        value_type="url",
        default="https://api.riskrecon.com/v1",
        description="Base URL for RiskRecon API.",
    ),
    # Splunk & Splunk ES
    SettingSpec(
        key="splunk_host",
        category="splunk",
        label="Splunk Management Host",
        env_vars=("SPLUNK_HOST",),
        value_type="host_url",
        default="https://127.0.0.1:8089",
        description="Splunk management API URL (default port 8089).",
    ),
    SettingSpec(
        key="splunk_token",
        category="splunk",
        label="Splunk Bearer Token",
        env_vars=("SPLUNK_TOKEN",),
        secret=True,
        description="Preferred Splunk REST authentication token.",
    ),
    SettingSpec(
        key="splunk_username",
        category="splunk",
        label="Splunk Username",
        env_vars=("SPLUNK_USERNAME",),
        description="Splunk username (used when Bearer token is not set).",
    ),
    SettingSpec(
        key="splunk_password",
        category="splunk",
        label="Splunk Password",
        env_vars=("SPLUNK_PASSWORD",),
        secret=True,
        description="Splunk password paired with Splunk Username.",
    ),
    SettingSpec(
        key="splunk_app",
        category="splunk",
        label="Splunk App Namespace",
        env_vars=("SPLUNK_APP",),
        default="SplunkEnterpriseSecuritySuite",
        description="Target Splunk app context for saved searches.",
    ),
    SettingSpec(
        key="splunk_verify_ssl",
        category="splunk",
        label="Splunk SSL Verification",
        env_vars=("SPLUNK_VERIFY_SSL",),
        value_type="ssl_verify",
        default="false",
        description="true, false, or path to a custom CA bundle PEM file.",
    ),
    # SentinelOne EDR
    SettingSpec(
        key="s1_console_url",
        category="sentinelone",
        label="SentinelOne Console URL",
        env_vars=("S1_CONSOLE_URL", "SENTINELONE_URL"),
        value_type="host_url",
        description="SentinelOne management console URL (e.g. https://tenant.sentinelone.net).",
    ),
    SettingSpec(
        key="s1_api_token",
        category="sentinelone",
        label="SentinelOne API Token",
        env_vars=("S1_API_TOKEN", "SENTINELONE_API_TOKEN"),
        secret=True,
        description="SentinelOne Management API v2.1 API token.",
    ),
    SettingSpec(
        key="s1_account_id",
        category="sentinelone",
        label="SentinelOne Account ID",
        env_vars=("S1_ACCOUNT_ID",),
        description="Optional default SentinelOne account ID filter.",
    ),
    SettingSpec(
        key="s1_site_id",
        category="sentinelone",
        label="SentinelOne Site ID",
        env_vars=("S1_SITE_ID",),
        description="Optional default SentinelOne site ID filter.",
    ),
    SettingSpec(
        key="s1_verify_ssl",
        category="sentinelone",
        label="SentinelOne SSL Verification",
        env_vars=("S1_VERIFY_SSL",),
        value_type="ssl_verify",
        description="true, false, CA bundle path, or leave blank to inherit RF SSL setting.",
    ),
    SettingSpec(
        key="s1_timeout",
        category="sentinelone",
        label="SentinelOne Timeout (sec)",
        env_vars=("S1_TIMEOUT",),
        value_type="float",
        default="30.0",
        description="Request timeout in seconds for SentinelOne API calls.",
    ),
    # Network, SSL & Proxy
    SettingSpec(
        key="rf_verify_ssl",
        category="network",
        label="RF & Web SSL Verification",
        env_vars=("RF_VERIFY_SSL", "RF_INSECURE_SSL", "SOCLENS_INSECURE_SSL"),
        value_type="ssl_verify",
        default="true",
        description="true (verify certificates), false (insecure proxy mode), or CA path.",
    ),
    SettingSpec(
        key="rf_ca_bundle",
        category="network",
        label="Custom CA Bundle Path",
        env_vars=("RF_CA_BUNDLE",),
        value_type="path",
        description="Path to PEM CA certificate bundle for corporate SSL inspection.",
    ),
    SettingSpec(
        key="https_proxy",
        category="network",
        label="HTTPS Proxy URL",
        env_vars=("HTTPS_PROXY", "https_proxy"),
        value_type="url",
        mask_url_credentials=True,
        description="HTTPS proxy URL (e.g. http://proxy.corp:8080).",
    ),
    SettingSpec(
        key="http_proxy",
        category="network",
        label="HTTP Proxy URL",
        env_vars=("HTTP_PROXY", "http_proxy"),
        value_type="url",
        mask_url_credentials=True,
        description="HTTP proxy URL (e.g. http://proxy.corp:8080).",
    ),
    SettingSpec(
        key="no_proxy",
        category="network",
        label="No-Proxy Hosts / CIDRs",
        env_vars=("NO_PROXY", "no_proxy"),
        description="Comma-separated hosts/domains bypassing proxy (e.g. localhost,127.0.0.1).",
    ),
    # Workspace & Tool Defaults
    SettingSpec(
        key="soclens_home",
        category="workspace",
        label="SOC Workspace Directory",
        env_vars=("SOCLENS_HOME",),
        value_type="path",
        description="Default workspace directory for caches, state, and logs (blank = CWD).",
    ),
    SettingSpec(
        key="rf_tui_image_protocol",
        category="workspace",
        label="TUI Image Protocol",
        env_vars=("RF_TUI_IMAGE_PROTOCOL",),
        description="auto (blank), kitty, iterm2, sixel, or halfblock.",
    ),
    SettingSpec(
        key="soclens_default_table_fields",
        category="workspace",
        label="Sigma Default Table Fields",
        env_vars=("SOCLENS_DEFAULT_TABLE_FIELDS",),
        description="Default Splunk | table fields injected during Sigma conversion.",
    ),
    SettingSpec(
        key="soclens_default_suppress_fields",
        category="workspace",
        label="Sigma Default Suppress Fields",
        env_vars=("SOCLENS_DEFAULT_SUPPRESS_FIELDS",),
        description="Default alert.suppress.fields for Splunk ES saved searches.",
    ),
    SettingSpec(
        key="soclens_tenant_field",
        category="workspace",
        label="Sigma Tenant Field",
        env_vars=("SOCLENS_TENANT_FIELD",),
        description="Optional tenant field appended to Splunk Sigma output/suppress fields.",
    ),
    SettingSpec(
        key="rf_logo_overrides_file",
        category="workspace",
        label="Logo Overrides JSON File",
        env_vars=("RF_LOGO_OVERRIDES_FILE",),
        value_type="path",
        description="Path to optional brand logo domain/URL override JSON file.",
    ),
    SettingSpec(
        key="rf_ignored_hashes_file",
        category="workspace",
        label="Ignored Hashes File",
        env_vars=("RF_IGNORED_HASHES_FILE",),
        value_type="path",
        description="Path to ignored logo hashes text file.",
    ),
    SettingSpec(
        key="rf_ignored_hashes",
        category="workspace",
        label="Ignored Hashes (CSV)",
        env_vars=("RF_IGNORED_HASHES",),
        description="Comma-separated SHA-256 logo hashes to ignore during sync.",
    ),
    SettingSpec(
        key="soclens_auto_approve",
        category="workspace",
        label="Auto-Approve CLI Writes",
        env_vars=("SOCLENS_AUTO_APPROVE",),
        value_type="bool",
        default="false",
        description="Permit non-interactive CLI mutations without --yes (true/false).",
    ),
)

SETTING_SPECS_BY_KEY: dict[str, SettingSpec] = {spec.key: spec for spec in SETTING_SPECS}

_ALIAS_TO_KEY: dict[str, str] = {}
for _spec in SETTING_SPECS:
    _ALIAS_TO_KEY[_spec.key.lower()] = _spec.key
    for _env_name in _spec.env_vars:
        _ALIAS_TO_KEY[_env_name.lower()] = _spec.key


def _clean_str(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = str(value).strip()
    return stripped if stripped else None


def resolve_setting_key(name: str) -> str | None:
    """Resolve a canonical setting key or environment variable alias to a canonical key."""
    cleaned = _clean_str(name)
    if not cleaned:
        return None
    return _ALIAS_TO_KEY.get(cleaned.lower())


def validate_profile_name(name: str) -> str:
    """Validate and normalize a settings profile name."""
    cleaned = str(name).strip()
    if not cleaned or cleaned in {".", ".."} or not _PROFILE_NAME_RE.match(cleaned):
        raise ValueError(
            "Profile name must be 1-64 characters using letters, numbers, '.', '_', or '-'."
        )
    return cleaned


def get_settings_path(explicit: Path | str | None = None) -> Path:
    """Resolve the per-user settings JSON file path cross-platform.

    Resolution order:
    1. ``explicit`` path argument (if non-empty)
    2. ``SOCLENS_SETTINGS_FILE`` environment variable (if non-empty)
    3. Internal test override ``_DEFAULT_SETTINGS_PATH_OVERRIDE`` (if set)
    4. Platform per-user configuration directory:
       - Windows: ``%APPDATA%\\soclens\\settings.json``
       - macOS: ``~/Library/Application Support/soclens/settings.json``
       - Linux/POSIX: ``$XDG_CONFIG_HOME/soclens/settings.json``
         (fallback ``~/.config/soclens/settings.json``)
    """
    if explicit is not None:
        raw_explicit = str(explicit).strip()
        if raw_explicit:
            candidate = Path(raw_explicit).expanduser()
            return candidate if candidate.is_absolute() else candidate.resolve()

    env_file = _clean_str(os.environ.get("SOCLENS_SETTINGS_FILE"))
    if env_file:
        candidate = Path(env_file).expanduser()
        return candidate if candidate.is_absolute() else candidate.resolve()

    if _DEFAULT_SETTINGS_PATH_OVERRIDE is not None:
        return _DEFAULT_SETTINGS_PATH_OVERRIDE

    if os.name == "nt" or sys.platform == "win32":
        appdata = _clean_str(os.environ.get("APPDATA"))
        base_dir = (
            Path(appdata).expanduser()
            if appdata
            else Path.home() / "AppData" / "Roaming"
        )
        return base_dir / APP_CONFIG_DIR_NAME / SETTINGS_FILENAME

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_CONFIG_DIR_NAME / SETTINGS_FILENAME

    xdg_home = _clean_str(os.environ.get("XDG_CONFIG_HOME"))
    base_dir = Path(xdg_home).expanduser() if xdg_home else Path.home() / ".config"
    return base_dir / APP_CONFIG_DIR_NAME / SETTINGS_FILENAME


def _cache_key(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def invalidate_settings_cache() -> None:
    """Clear the cached per-user settings store across all paths."""
    with _STORE_LOCK:
        _CACHE.clear()
        _LAST_ERRORS.clear()


def get_last_load_error(settings_path: Path | str | None = None) -> str | None:
    """Return the most recent load error for ``settings_path``, if any."""
    resolved = _cache_key(get_settings_path(settings_path))
    with _STORE_LOCK:
        if resolved in _LAST_ERRORS:
            return _LAST_ERRORS[resolved]
        entry = _CACHE.get(resolved)
        return entry[2] if entry is not None else None


def _default_store() -> dict[str, Any]:
    return {
        "schema_version": SETTINGS_SCHEMA_VERSION,
        "active_profile": DEFAULT_PROFILE,
        "profiles": {DEFAULT_PROFILE: {}},
    }


def _normalize_store(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Settings file root must be a JSON object.")

    store: dict[str, Any] = copy.deepcopy(raw)
    store.setdefault("schema_version", SETTINGS_SCHEMA_VERSION)

    raw_profiles = store.get("profiles")
    profiles: dict[str, dict[str, str]] = {}
    if isinstance(raw_profiles, dict):
        for prof_name, prof_data in raw_profiles.items():
            if not isinstance(prof_name, str) or not isinstance(prof_data, dict):
                continue
            try:
                clean_prof = validate_profile_name(prof_name)
            except ValueError:
                continue
            cleaned_entries: dict[str, str] = {}
            for k, v in prof_data.items():
                if not isinstance(k, str) or v is None:
                    continue
                val_str = str(v).strip()
                if val_str:
                    cleaned_entries[k.strip()] = val_str
            profiles[clean_prof] = cleaned_entries

    if DEFAULT_PROFILE not in profiles:
        profiles[DEFAULT_PROFILE] = {}
    store["profiles"] = profiles

    raw_active = store.get("active_profile")
    active = DEFAULT_PROFILE
    if isinstance(raw_active, str):
        try:
            candidate = validate_profile_name(raw_active)
            if candidate in profiles:
                active = candidate
        except ValueError:
            active = DEFAULT_PROFILE
    store["active_profile"] = active
    return store


def _stat_signature(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def load_settings_store(settings_path: Path | str | None = None) -> dict[str, Any]:
    """Load the per-user settings store (with mtime caching and corrupt-file resilience)."""
    target = get_settings_path(settings_path)
    key = _cache_key(target)

    with _STORE_LOCK:
        sig = _stat_signature(target)
        cached = _CACHE.get(key)
        if cached is not None and cached[0] == sig:
            return copy.deepcopy(cached[1])

        if sig is None:
            default_data = _default_store()
            _LAST_ERRORS.pop(key, None)
            _CACHE[key] = (None, copy.deepcopy(default_data), None)
            return default_data

        load_error: str | None = None
        try:
            raw_text = target.read_text(encoding="utf-8")
            parsed = json.loads(raw_text) if raw_text.strip() else {}
            normalized = _normalize_store(parsed)
        except Exception as exc:
            load_error = f"Failed to parse settings file '{target}': {exc}"
            logger.warning("%s", load_error)
            normalized = _default_store()

        if load_error is not None:
            _LAST_ERRORS[key] = load_error
        else:
            _LAST_ERRORS.pop(key, None)
        _CACHE[key] = (sig, copy.deepcopy(normalized), load_error)
        return normalized


def _write_store_atomic(target: Path, store: dict[str, Any]) -> None:
    """Write ``store`` atomically with owner-only file permissions where supported."""
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass

    serialized = json.dumps(store, indent=2, ensure_ascii=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".settings.", suffix=".tmp", dir=str(parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        if os.name != "nt":
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
        os.replace(tmp_path, target)
        if os.name != "nt":
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
    except BaseException:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise

    key = _cache_key(target)
    sig = _stat_signature(target)
    with _STORE_LOCK:
        _LAST_ERRORS.pop(key, None)
        _CACHE[key] = (sig, copy.deepcopy(store), None)


def get_active_profile_name(settings_path: Path | str | None = None) -> str:
    """Return the active profile name, honoring ``SOCLENS_PROFILE`` if set."""
    env_profile = _clean_str(os.environ.get("SOCLENS_PROFILE"))
    if env_profile:
        try:
            return validate_profile_name(env_profile)
        except ValueError:
            logger.warning("Ignoring invalid SOCLENS_PROFILE value: %r", env_profile)
    store = load_settings_store(settings_path)
    return str(store.get("active_profile") or DEFAULT_PROFILE)


def list_profiles(settings_path: Path | str | None = None) -> list[str]:
    """Return sorted profile names from the settings store (always includes ``default``)."""
    store = load_settings_store(settings_path)
    profiles = store.get("profiles", {})
    names = sorted(str(k) for k in profiles.keys())
    if DEFAULT_PROFILE in names:
        names.remove(DEFAULT_PROFILE)
        names.insert(0, DEFAULT_PROFILE)
    return names


def get_profile_settings(
    profile: str | None = None,
    settings_path: Path | str | None = None,
) -> dict[str, str]:
    """Return a copy of the saved settings dictionary for ``profile``."""
    store = load_settings_store(settings_path)
    prof_name = (
        validate_profile_name(profile)
        if profile is not None
        else get_active_profile_name(settings_path)
    )
    prof_map = store.get("profiles", {}).get(prof_name, {})
    return dict(prof_map) if isinstance(prof_map, dict) else {}


def save_profile_settings(
    values: Mapping[str, str | None],
    *,
    profile: str | None = None,
    replace: bool = False,
    settings_path: Path | str | None = None,
) -> Path:
    """Merge or replace settings for ``profile`` and persist atomically."""
    target = get_settings_path(settings_path)
    with _STORE_LOCK:
        store = load_settings_store(target)
        prof_name = (
            validate_profile_name(profile)
            if profile is not None
            else get_active_profile_name(target)
        )
        profiles: dict[str, dict[str, str]] = store.setdefault("profiles", {})
        if DEFAULT_PROFILE not in profiles:
            profiles[DEFAULT_PROFILE] = {}

        existing = {} if replace else dict(profiles.get(prof_name, {}))
        for raw_key, raw_val in values.items():
            canon = resolve_setting_key(raw_key) or raw_key.strip()
            if not canon:
                continue
            cleaned = _clean_str(raw_val)
            if cleaned is None:
                existing.pop(canon, None)
            else:
                existing[canon] = cleaned

        profiles[prof_name] = existing
        _write_store_atomic(target, store)
    return target


def set_active_profile(
    profile: str,
    *,
    create: bool = True,
    settings_path: Path | str | None = None,
) -> Path:
    """Switch the persisted ``active_profile`` to ``profile``."""
    prof_name = validate_profile_name(profile)
    target = get_settings_path(settings_path)
    with _STORE_LOCK:
        store = load_settings_store(target)
        profiles: dict[str, dict[str, str]] = store.setdefault("profiles", {})
        if prof_name not in profiles:
            if not create:
                raise KeyError(f"Profile '{prof_name}' does not exist.")
            profiles[prof_name] = {}
        store["active_profile"] = prof_name
        _write_store_atomic(target, store)
    return target


def delete_profile(
    profile: str,
    *,
    settings_path: Path | str | None = None,
) -> Path:
    """Delete a non-default profile from the settings store."""
    prof_name = validate_profile_name(profile)
    if prof_name == DEFAULT_PROFILE:
        raise ValueError("Cannot delete the built-in 'default' profile.")
    target = get_settings_path(settings_path)
    with _STORE_LOCK:
        store = load_settings_store(target)
        profiles: dict[str, dict[str, str]] = store.setdefault("profiles", {})
        if prof_name not in profiles:
            raise KeyError(f"Profile '{prof_name}' does not exist.")
        profiles.pop(prof_name, None)
        if store.get("active_profile") == prof_name:
            store["active_profile"] = DEFAULT_PROFILE
        _write_store_atomic(target, store)
    return target


def clear_profile_settings(
    profile: str | None = None,
    *,
    settings_path: Path | str | None = None,
) -> Path:
    """Remove all saved values in ``profile`` (keeping the profile entry itself)."""
    return save_profile_settings({}, profile=profile, replace=True, settings_path=settings_path)


def get_settings_storage_info(settings_path: Path | str | None = None) -> dict[str, Any]:
    """Return path, existence, permission posture, and profile metadata."""
    target = get_settings_path(settings_path)
    active = get_active_profile_name(target)
    profiles = list_profiles(target)
    exists = target.is_file()

    if exists:
        if os.name == "nt":
            perms = "user profile private (Windows ACL)"
        else:
            try:
                mode = stat.S_IMODE(target.stat().st_mode)
                perms = (
                    f"{mode:04o} (owner-only)"
                    if (mode & 0o077) == 0
                    else f"{mode:04o} (warning: group/world accessible)"
                )
            except OSError:
                perms = "unknown"
    else:
        perms = "not created yet (0600 owner-only on first save)" if os.name != "nt" else "not created yet"

    return {
        "path": str(target),
        "exists": exists,
        "permissions": perms,
        "active_profile": active,
        "profiles": profiles,
        "profile_count": len(profiles),
        "env_override_profile": _clean_str(os.environ.get("SOCLENS_PROFILE")),
        "load_error": get_last_load_error(target),
    }


def _validate_url(value: str, *, require_scheme: bool) -> str | None:
    if require_scheme and not value.lower().startswith(("http://", "https://")):
        return "Must start with http:// or https://."
    candidate = value if "://" in value else f"https://{value}"
    if "://" in value and not candidate.lower().startswith(("http://", "https://")):
        return "Scheme must be http:// or https://."
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port
    except ValueError as exc:
        return f"Invalid URL ({exc})."
    if not parsed.hostname:
        return "URL must include a valid hostname."
    return None


def validate_settings_values(values: Mapping[str, str | None]) -> list[tuple[str, str]]:
    """Validate candidate setting values, returning ``[(key, error_message), ...]``."""
    errors: list[tuple[str, str]] = []
    for raw_key, raw_val in values.items():
        if raw_val is None:
            continue
        raw_str = str(raw_val)
        canon = resolve_setting_key(raw_key) or raw_key.strip()
        spec = SETTING_SPECS_BY_KEY.get(canon)
        label = spec.label if spec is not None else canon

        if "\n" in raw_str or "\r" in raw_str:
            errors.append((canon, f"{label}: newline characters are not permitted."))
            continue

        cleaned = raw_str.strip()
        if not cleaned:
            continue

        if spec is None:
            continue

        if spec.value_type == "url":
            err = _validate_url(cleaned, require_scheme=True)
            if err:
                errors.append((canon, f"{label}: {err}"))
        elif spec.value_type == "host_url":
            err = _validate_url(cleaned, require_scheme=False)
            if err:
                errors.append((canon, f"{label}: {err}"))
        elif spec.value_type == "float":
            try:
                num = float(cleaned)
            except ValueError:
                errors.append((canon, f"{label}: must be a positive number."))
                continue
            if not math.isfinite(num) or num <= 0:
                errors.append((canon, f"{label}: must be greater than 0."))
        elif spec.value_type == "bool":
            if cleaned.lower() not in (_TRUTHY_VALUES | _FALSY_VALUES):
                errors.append((canon, f"{label}: must be true or false."))
        elif canon == "rf_tui_image_protocol":
            if cleaned.lower() not in {"auto", "kitty", "iterm2", "sixel", "halfblock"}:
                errors.append(
                    (canon, f"{label}: must be auto, kitty, iterm2, sixel, or halfblock.")
                )

    return errors


def mask_secret(value: str | None) -> str:
    """Mask secret tokens and passwords for safe terminal/UI display."""
    cleaned = _clean_str(value)
    if not cleaned:
        return ""
    if len(cleaned) <= 4:
        return "*" * len(cleaned)
    if len(cleaned) <= 10:
        return f"{cleaned[:2]}{'*' * (len(cleaned) - 4)}{cleaned[-2:]}"
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def _mask_proxy_userinfo(raw_url: str) -> str:
    cleaned = raw_url.strip()
    has_scheme = "://" in cleaned
    try:
        parsed = urlsplit(cleaned if has_scheme else f"//{cleaned}")
        if parsed.username is None and parsed.password is None:
            return cleaned
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port_suffix = f":{parsed.port}" if parsed.port is not None else ""
        scheme_prefix = f"{parsed.scheme}://" if has_scheme and parsed.scheme else ""
        return f"{scheme_prefix}***@{host}{port_suffix}{parsed.path}"
    except ValueError:
        return "***"


def format_setting_display(
    key: str,
    value: str | None,
    *,
    reveal: bool = False,
) -> str:
    """Format a setting value for display, masking secrets unless ``reveal=True``."""
    cleaned = _clean_str(value)
    if cleaned is None:
        return ""
    if reveal:
        return cleaned
    spec = SETTING_SPECS_BY_KEY.get(key)
    if spec is not None and spec.secret:
        return mask_secret(cleaned)
    if spec is not None and spec.mask_url_credentials:
        return _mask_proxy_userinfo(cleaned)
    return cleaned


def set_session_overrides(overrides: Mapping[str, str | None]) -> None:
    """Update process-local TUI session overrides without mutating ``os.environ``."""
    with _SESSION_LOCK:
        for key, val in overrides.items():
            canon = resolve_setting_key(key) or key.strip()
            cleaned = _clean_str(val)
            if cleaned is None:
                _SESSION_OVERRIDES.pop(canon, None)
            else:
                _SESSION_OVERRIDES[canon] = cleaned


def clear_session_overrides(keys: tuple[str, ...] | list[str] | None = None) -> None:
    """Clear all or selected process-local session overrides."""
    with _SESSION_LOCK:
        if keys is None:
            _SESSION_OVERRIDES.clear()
        else:
            for key in keys:
                canon = resolve_setting_key(key) or key.strip()
                _SESSION_OVERRIDES.pop(canon, None)


def get_session_override(key: str) -> tuple[bool, str | None]:
    """Return ``(is_present, value)`` for a process-local session override."""
    canon = resolve_setting_key(key) or key.strip()
    with _SESSION_LOCK:
        if canon in _SESSION_OVERRIDES:
            return True, _SESSION_OVERRIDES[canon]
    return False, None


def get_saved_setting(
    key: str,
    *,
    profile: str | None = None,
    settings_path: Path | str | None = None,
) -> str | None:
    """Return a single saved setting from ``profile`` (or the active profile)."""
    canon = resolve_setting_key(key) or key.strip()
    prof = get_profile_settings(profile=profile, settings_path=settings_path)
    return _clean_str(prof.get(canon))


def get_env_override_for_setting(key: str) -> tuple[str, str] | None:
    """Return ``(env_var_name, normalized_value)`` if an env var is set for ``key``."""
    canon = resolve_setting_key(key) or key.strip()
    spec = SETTING_SPECS_BY_KEY.get(canon)
    if spec is None:
        return None

    if canon == "rf_verify_ssl":
        raw_verify = _clean_str(os.environ.get("RF_VERIFY_SSL"))
        if raw_verify is not None:
            return ("RF_VERIFY_SSL", raw_verify)
        for insecure_var in ("RF_INSECURE_SSL", "SOCLENS_INSECURE_SSL"):
            raw_insec = _clean_str(os.environ.get(insecure_var))
            if raw_insec is not None:
                low = raw_insec.lower()
                if low in _TRUTHY_VALUES:
                    return (insecure_var, "false")
                if low in _FALSY_VALUES:
                    return (insecure_var, "true")
                return (insecure_var, raw_insec)
        return None

    for env_name in spec.env_vars:
        raw_val = _clean_str(os.environ.get(env_name))
        if raw_val is not None:
            return (env_name, raw_val)
    return None


def get_setting_with_source(
    key: str,
    *,
    profile: str | None = None,
    settings_path: Path | str | None = None,
) -> tuple[str | None, str]:
    """Resolve ``(value, source)`` for ``key``.

    ``source`` is one of ``"session"``, ``"env:<VAR>"``, ``"settings"``,
    ``"default"``, or ``"unset"``.
    """
    canon = resolve_setting_key(key) or key.strip()
    spec = SETTING_SPECS_BY_KEY.get(canon)

    if profile is None:
        has_sess, sess_val = get_session_override(canon)
        if has_sess:
            return (sess_val, "session") if sess_val is not None else (None, "unset")

    env_hit = get_env_override_for_setting(canon)
    if env_hit is not None:
        return env_hit[1], f"env:{env_hit[0]}"

    saved = get_saved_setting(canon, profile=profile, settings_path=settings_path)
    if saved is not None:
        return saved, "settings"

    if spec is not None and spec.default is not None:
        return spec.default, "default"

    return None, "unset"


def get_effective_setting(
    key: str,
    *,
    include_default: bool = False,
    settings_path: Path | str | None = None,
) -> str | None:
    """Resolve a setting value checking session override, environment, and saved settings."""
    val, source = get_setting_with_source(key, settings_path=settings_path)
    if source == "default" and not include_default:
        return None
    return val


def collect_env_importable_settings() -> dict[str, str]:
    """Collect all recognized settings currently populated in ``os.environ``."""
    imported: dict[str, str] = {}
    for spec in SETTING_SPECS:
        hit = get_env_override_for_setting(spec.key)
        if hit is not None:
            imported[spec.key] = hit[1]
    return imported


def describe_all_settings(
    *,
    reveal: bool = False,
    profile: str | None = None,
    settings_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Build a structured summary of every registered setting, its value, and source."""
    saved_map = get_profile_settings(profile=profile, settings_path=settings_path)
    items: list[dict[str, Any]] = []
    for spec in SETTING_SPECS:
        val, source = get_setting_with_source(
            spec.key,
            profile=profile,
            settings_path=settings_path,
        )
        saved_val = _clean_str(saved_map.get(spec.key))
        env_hit = get_env_override_for_setting(spec.key)
        items.append(
            {
                "key": spec.key,
                "category": spec.category,
                "label": spec.label,
                "env_vars": list(spec.env_vars),
                "secret": spec.secret,
                "value": format_setting_display(spec.key, val, reveal=reveal),
                "saved_value": format_setting_display(spec.key, saved_val, reveal=reveal),
                "has_saved": saved_val is not None,
                "env_override": env_hit[0] if env_hit is not None else None,
                "source": source,
                "default": spec.default,
                "description": spec.description,
            }
        )
    return items


__all__ = [
    "APP_CONFIG_DIR_NAME",
    "DEFAULT_PROFILE",
    "SETTING_CATEGORIES",
    "SETTING_SPECS",
    "SETTING_SPECS_BY_KEY",
    "SETTINGS_FILENAME",
    "SETTINGS_SCHEMA_VERSION",
    "SettingSpec",
    "clear_profile_settings",
    "clear_session_overrides",
    "collect_env_importable_settings",
    "delete_profile",
    "describe_all_settings",
    "format_setting_display",
    "get_active_profile_name",
    "get_effective_setting",
    "get_env_override_for_setting",
    "get_last_load_error",
    "get_profile_settings",
    "get_saved_setting",
    "get_setting_with_source",
    "get_settings_path",
    "get_settings_storage_info",
    "invalidate_settings_cache",
    "list_profiles",
    "load_settings_store",
    "mask_secret",
    "resolve_setting_key",
    "save_profile_settings",
    "set_active_profile",
    "set_session_overrides",
    "validate_profile_name",
    "validate_settings_values",
]
