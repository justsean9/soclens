"""Sigma rule caching, search, pySigma pipeline conversion, and Splunk export."""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.splunk import (
    splunk_cim_data_model,
    splunk_windows_pipeline,
    splunk_windows_sysmon_acceleration_keywords,
)
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
)

from soclens.client import RecordedFutureError
from soclens.config import (
    ConfigurationError,
    get_rf_token,
    get_sigma_setting,
    get_workspace_dir,
)

logger = logging.getLogger("soclens.sigma")

CACHE_FILE_NAME = "sigma_rules_cache.json"
SIGMA_PIPELINES: tuple[str, ...] = (
    "splunk_windows",
    "splunk_windows_sysmon",
    "splunk_cim",
    "none",
)
SIGMA_OUTPUT_FORMATS: tuple[str, ...] = ("default", "data_model")

_CONTROL_CHARS_RE = re.compile(r"[ \t]*[\r\n\x00-\x1f\x7f]+[ \t]*")
_SPL_SEARCH_PREFIX_RE = re.compile(r"^search(?:\s|$)", re.IGNORECASE)
_SPL_EXISTING_INDEX_RE = re.compile(r"(?:^|\s|\()index\s*(?:=|IN\b)", re.IGNORECASE)
_SPL_TABLE_RE = re.compile(r"\|\s*table\b", re.IGNORECASE)
_SPL_TRAILING_TABLE_RE = re.compile(r"\s*\|\s*table\s+([^|]+?)\s*$", re.IGNORECASE)
_SPL_QUOTED_SIMPLE_INDEX_RE = re.compile(r'\bindex="([A-Za-z0-9_*.-]+)"')
_SPL_DEFERRED_MULTI_INDEX_RE = re.compile(
    r"^(?P<prefix>\|\s*rex\b.*?\|\s*search\s+)(?P<idx>\(index\s+IN\s*\([^)]+\)\))\s*",
    re.IGNORECASE | re.DOTALL,
)
_SIMPLE_INDEX_TOKEN_RE = re.compile(r"^[A-Za-z0-9_*.-]+$")
_KV_SPLIT_RE = re.compile(r"(?:;|,(?=\s*[A-Za-z0-9_.*:/-]+\s*=))")
_FIELD_SPLIT_RE = re.compile(r"[\s,]+")
_SPLIT_FILENAME_SANITIZE_RE = re.compile(r"[^a-z0-9._-]+")

_DEFAULT_STANZA_PREFIX = "Recorded Future Sigma (Automated) - "


class SigmaConfigurationError(ConfigurationError, RuntimeError):
    """Raised when Sigma operations require Recorded Future API credentials or config."""


class NoPipelineSplunkBackend(SplunkBackend):
    """Splunk backend allowing optional or dynamic processing pipelines."""

    requires_pipeline = False


def _clean_env_str(name: str) -> str | None:
    """Read an optional Sigma setting from session/env/saved user configuration."""
    return get_sigma_setting(name)


def _sanitize_ini_value(value: Any, default: str = "") -> str:
    """Flatten newlines and ASCII control characters into single spaces for Splunk INI files."""
    if value is None:
        return default
    text = str(value)
    cleaned = _CONTROL_CHARS_RE.sub(" ", text).strip()
    return cleaned if cleaned else default


def _resolve_client_token(client: Any) -> str | None:
    """Extract an API token from a client instance or fall back to environment config."""
    if client is not None:
        token = getattr(client, "api_token", None)
        if isinstance(token, str):
            stripped = token.strip()
            return stripped if stripped else None
        return token if token else None
    return get_rf_token(required=False)


def _dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    """Deduplicate non-empty strings while preserving original insertion order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        cleaned = item.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def parse_field_list(raw: str | Iterable[str] | None) -> list[str]:
    """Parse comma- and/or whitespace-separated Splunk field names into an ordered unique list."""
    if raw is None:
        return []

    tokens: list[str] = []
    if isinstance(raw, str):
        sanitized = _sanitize_ini_value(raw)
        if sanitized:
            tokens.extend(part for part in _FIELD_SPLIT_RE.split(sanitized) if part)
    else:
        for item in raw:
            if item is None:
                continue
            sanitized = _sanitize_ini_value(str(item))
            if sanitized:
                tokens.extend(part for part in _FIELD_SPLIT_RE.split(sanitized) if part)

    return _dedupe_preserve_order(tokens)


def parse_key_value_mapping(
    raw: str | list[str] | tuple[str, ...] | Mapping[str, Any] | None,
    *,
    lowercase_keys: bool = True,
) -> dict[str, str | list[str]]:
    """Parse key=value strings, repeatable flag lists, JSON text, or dicts into a clean mapping."""
    if raw is None:
        return {}

    result: dict[str, str | list[str]] = {}

    def _normalize_key(key: Any) -> str:
        text = str(key).strip()
        return text.lower() if lowercase_keys else text

    def _normalize_val(val: Any) -> str | list[str] | None:
        if val is None:
            return None
        if isinstance(val, (list, tuple)):
            cleaned_list = [_sanitize_ini_value(item) for item in val if _sanitize_ini_value(item)]
            return cleaned_list if cleaned_list else None
        cleaned = _sanitize_ini_value(val)
        return cleaned if cleaned else None

    if isinstance(raw, Mapping):
        for k, v in raw.items():
            nk = _normalize_key(k)
            nv = _normalize_val(v)
            if nk and nv is not None:
                result[nk] = nv
        return result

    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return {}
        if text.startswith("{"):
            try:
                loaded = json.loads(text)
            except ValueError as exc:
                raise ValueError(f"Invalid JSON mapping '{raw}': {exc}") from exc
            if not isinstance(loaded, Mapping):
                raise ValueError(f"Expected JSON object mapping, got {type(loaded).__name__}.")
            return parse_key_value_mapping(loaded, lowercase_keys=lowercase_keys)
        segments = _KV_SPLIT_RE.split(text)
    elif isinstance(raw, (list, tuple)):
        segments = []
        for entry in raw:
            if not entry:
                continue
            entry_str = str(entry).strip()
            if entry_str.startswith("{"):
                result.update(parse_key_value_mapping(entry_str, lowercase_keys=lowercase_keys))
            else:
                segments.extend(_KV_SPLIT_RE.split(entry_str))
    else:
        raise ValueError(f"Unsupported mapping type: {type(raw).__name__}")

    for segment in segments:
        part = segment.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"Invalid mapping entry '{part}'; expected key=value format.")
        key_raw, val_raw = part.split("=", 1)
        nk = _normalize_key(key_raw)
        nv = _normalize_val(val_raw)
        if not nk or nv is None:
            raise ValueError(f"Invalid mapping entry '{part}'; key and value must be non-empty.")
        result[nk] = nv

    return result


def _parse_bool_flag(raw: Any, default: bool = True) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return default
    text = str(raw).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return default


@dataclass
class SigmaConversionConfig:
    """Configuration profile controlling Sigma-to-Splunk index, field, and pipeline conversion."""

    index_map: dict[str, str | list[str]] = field(default_factory=dict)
    default_index: str | None = None
    index_override: str | None = None
    sourcetype_map: dict[str, str | list[str]] = field(default_factory=dict)
    field_map: dict[str, str | list[str]] = field(default_factory=dict)
    table_fields: str | None = None
    custom_table_fields: list[str] = field(default_factory=list)
    table_fields_map: dict[str, str | list[str]] = field(default_factory=dict)
    include_rule_fields: bool = True
    suppress_fields: str | None = None
    custom_suppress_fields: list[str] = field(default_factory=list)
    suppress_fields_map: dict[str, str | list[str]] = field(default_factory=dict)
    pipeline: str = "splunk_windows"
    pipeline_path: str | None = None
    output_format: str = "default"
    cron_schedule: str = "0 * * * *"
    earliest_time: str = "-70m"
    latest_time: str = "-10m"
    suppress_period: str = "86400s"
    stanza_prefix: str = _DEFAULT_STANZA_PREFIX
    security_domain: str = "threat"
    split_by_index: bool = True
    write_mode: str = "overwrite"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SigmaConversionConfig:
        """Build a ``SigmaConversionConfig`` from a JSON/YAML mapping."""
        if not isinstance(data, Mapping):
            raise ValueError("Sigma configuration must be a mapping/object.")

        pipeline_val = _sanitize_ini_value(data.get("pipeline"), default="splunk_windows")
        output_fmt = _sanitize_ini_value(
            data.get("output_format"),
            default="data_model" if pipeline_val.lower() == "splunk_cim" else "default",
        ).lower()
        if output_fmt not in SIGMA_OUTPUT_FORMATS:
            raise ValueError(
                f"Unsupported Sigma output_format '{output_fmt}'. "
                f"Expected one of: {', '.join(SIGMA_OUTPUT_FORMATS)}."
            )

        raw_default_index = data.get("default_index")
        raw_index_override = data.get("index_override", data.get("index"))
        raw_table_fields = data.get("table_fields", data.get("default_table_fields"))
        raw_suppress_fields = data.get("suppress_fields", data.get("default_suppress_fields"))
        raw_pipeline_path = data.get("pipeline_path")

        if "stanza_prefix" in data and data.get("stanza_prefix") is not None:
            raw_prefix = data.get("stanza_prefix")
            resolved_prefix = _sanitize_ini_value(raw_prefix, default="")
            if (
                isinstance(raw_prefix, str)
                and raw_prefix.endswith(" ")
                and resolved_prefix
                and not resolved_prefix.endswith(" ")
            ):
                resolved_prefix = f"{resolved_prefix} "
        else:
            resolved_prefix = _DEFAULT_STANZA_PREFIX

        return cls(
            index_map=parse_key_value_mapping(data.get("index_map"), lowercase_keys=True),
            default_index=(
                _sanitize_ini_value(raw_default_index)
                if raw_default_index is not None and _sanitize_ini_value(raw_default_index)
                else None
            ),
            index_override=(
                _sanitize_ini_value(raw_index_override)
                if raw_index_override is not None and _sanitize_ini_value(raw_index_override)
                else None
            ),
            sourcetype_map=parse_key_value_mapping(
                data.get("sourcetype_map"), lowercase_keys=True
            ),
            field_map=parse_key_value_mapping(data.get("field_map"), lowercase_keys=False),
            table_fields=(
                _sanitize_ini_value(raw_table_fields) if raw_table_fields is not None else None
            ),
            custom_table_fields=parse_field_list(
                data.get("custom_table_fields", data.get("extra_table_fields"))
            ),
            table_fields_map=parse_key_value_mapping(
                data.get("table_fields_map"), lowercase_keys=True
            ),
            include_rule_fields=_parse_bool_flag(data.get("include_rule_fields"), default=True),
            suppress_fields=(
                _sanitize_ini_value(raw_suppress_fields)
                if raw_suppress_fields is not None
                else None
            ),
            custom_suppress_fields=parse_field_list(data.get("custom_suppress_fields")),
            suppress_fields_map=parse_key_value_mapping(
                data.get("suppress_fields_map"), lowercase_keys=True
            ),
            pipeline=pipeline_val,
            pipeline_path=(
                str(raw_pipeline_path).strip()
                if raw_pipeline_path is not None and str(raw_pipeline_path).strip()
                else None
            ),
            output_format=output_fmt,
            cron_schedule=_sanitize_ini_value(data.get("cron_schedule"), default="0 * * * *"),
            earliest_time=_sanitize_ini_value(data.get("earliest_time"), default="-70m"),
            latest_time=_sanitize_ini_value(data.get("latest_time"), default="-10m"),
            suppress_period=_sanitize_ini_value(data.get("suppress_period"), default="86400s"),
            stanza_prefix=resolved_prefix,
            security_domain=_sanitize_ini_value(data.get("security_domain"), default="threat"),
            split_by_index=_parse_bool_flag(data.get("split_by_index"), default=True),
            write_mode=_sanitize_ini_value(data.get("write_mode"), default="overwrite").lower(),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> SigmaConversionConfig:
        """Load a ``SigmaConversionConfig`` from a JSON or YAML file."""
        file_path = Path(path).expanduser()
        if not file_path.is_file():
            raise FileNotFoundError(f"Sigma config file not found: {file_path}")
        raw_text = file_path.read_text(encoding="utf-8")
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            loaded = json.loads(raw_text)
        else:
            loaded = yaml.safe_load(raw_text)
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, Mapping):
            raise ValueError(
                f"Invalid Sigma config in '{file_path}': expected a mapping/object."
            )
        return cls.from_dict(loaded)

    @classmethod
    def from_env(cls) -> SigmaConversionConfig:
        """Build a ``SigmaConversionConfig`` from ``SOCLENS_*`` environment variables."""
        cfg = cls()
        return _apply_env_to_sigma_config(cfg)

    def to_dict(self) -> dict[str, Any]:
        """Serialize configuration values to a JSON-friendly dictionary."""
        return {
            "index_map": dict(self.index_map),
            "default_index": self.default_index,
            "index_override": self.index_override,
            "sourcetype_map": dict(self.sourcetype_map),
            "field_map": dict(self.field_map),
            "table_fields": self.table_fields,
            "custom_table_fields": list(self.custom_table_fields),
            "table_fields_map": dict(self.table_fields_map),
            "include_rule_fields": self.include_rule_fields,
            "suppress_fields": self.suppress_fields,
            "custom_suppress_fields": list(self.custom_suppress_fields),
            "suppress_fields_map": dict(self.suppress_fields_map),
            "pipeline": self.pipeline,
            "pipeline_path": self.pipeline_path,
            "output_format": self.output_format,
            "cron_schedule": self.cron_schedule,
            "earliest_time": self.earliest_time,
            "latest_time": self.latest_time,
            "suppress_period": self.suppress_period,
            "stanza_prefix": self.stanza_prefix,
            "security_domain": self.security_domain,
            "split_by_index": self.split_by_index,
            "write_mode": self.write_mode,
        }


def _apply_env_to_sigma_config(cfg: SigmaConversionConfig) -> SigmaConversionConfig:
    """Overlay ``SOCLENS_*`` environment variables onto a ``SigmaConversionConfig``."""
    env_index = _clean_env_str("SOCLENS_INDEX")
    if env_index is not None:
        cfg.index_override = env_index

    env_index_map = _clean_env_str("SOCLENS_INDEX_MAP")
    if env_index_map is not None:
        merged_idx = dict(cfg.index_map)
        merged_idx.update(parse_key_value_mapping(env_index_map, lowercase_keys=True))
        cfg.index_map = merged_idx

    env_default_idx = _clean_env_str("SOCLENS_DEFAULT_INDEX")
    if env_default_idx is not None:
        cfg.default_index = env_default_idx

    env_st_map = _clean_env_str("SOCLENS_SOURCETYPE_MAP")
    if env_st_map is not None:
        merged_st = dict(cfg.sourcetype_map)
        merged_st.update(parse_key_value_mapping(env_st_map, lowercase_keys=True))
        cfg.sourcetype_map = merged_st

    env_field_map = _clean_env_str("SOCLENS_FIELD_MAP")
    if env_field_map is not None:
        merged_fm = dict(cfg.field_map)
        merged_fm.update(parse_key_value_mapping(env_field_map, lowercase_keys=False))
        cfg.field_map = merged_fm

    env_table_fields = _clean_env_str("SOCLENS_DEFAULT_TABLE_FIELDS")
    if env_table_fields is not None:
        cfg.table_fields = env_table_fields

    env_custom_table = _clean_env_str("SOCLENS_CUSTOM_TABLE_FIELDS")
    if env_custom_table is not None:
        cfg.custom_table_fields = _dedupe_preserve_order(
            cfg.custom_table_fields + parse_field_list(env_custom_table)
        )

    env_table_map = _clean_env_str("SOCLENS_TABLE_FIELDS_MAP")
    if env_table_map is not None:
        merged_tm = dict(cfg.table_fields_map)
        merged_tm.update(parse_key_value_mapping(env_table_map, lowercase_keys=True))
        cfg.table_fields_map = merged_tm

    env_suppress = _clean_env_str("SOCLENS_DEFAULT_SUPPRESS_FIELDS")
    if env_suppress is not None:
        cfg.suppress_fields = env_suppress

    env_custom_suppress = _clean_env_str("SOCLENS_CUSTOM_SUPPRESS_FIELDS")
    if env_custom_suppress is not None:
        cfg.custom_suppress_fields = _dedupe_preserve_order(
            cfg.custom_suppress_fields + parse_field_list(env_custom_suppress)
        )

    env_suppress_map = _clean_env_str("SOCLENS_SUPPRESS_FIELDS_MAP")
    if env_suppress_map is not None:
        merged_sm = dict(cfg.suppress_fields_map)
        merged_sm.update(parse_key_value_mapping(env_suppress_map, lowercase_keys=True))
        cfg.suppress_fields_map = merged_sm

    env_pipeline = _clean_env_str("SOCLENS_SIGMA_PIPELINE")
    if env_pipeline is not None:
        cfg.pipeline = env_pipeline

    env_pipeline_path = _clean_env_str("SOCLENS_SIGMA_PIPELINE_PATH")
    if env_pipeline_path is not None:
        cfg.pipeline_path = env_pipeline_path

    env_output_fmt = _clean_env_str("SOCLENS_SIGMA_OUTPUT_FORMAT")
    if env_output_fmt is not None:
        cfg.output_format = env_output_fmt.lower()
    elif cfg.pipeline.lower().strip() == "splunk_cim" and cfg.output_format == "default":
        cfg.output_format = "data_model"

    return cfg


def load_sigma_config(config_path: str | Path | None = None) -> SigmaConversionConfig:
    """Load Sigma conversion config from file (or ``SOCLENS_SIGMA_CONFIG``) plus env overrides."""
    resolved_path: str | Path | None = config_path
    if resolved_path is None:
        resolved_path = _clean_env_str("SOCLENS_SIGMA_CONFIG")

    if resolved_path is not None:
        cfg = SigmaConversionConfig.from_file(resolved_path)
    else:
        cfg = SigmaConversionConfig()

    return _apply_env_to_sigma_config(cfg)


def _lookup_logsource_mapping(logsource: Any, mapping: Mapping[str, Any] | None) -> Any | None:
    """Resolve the most specific value matching ``logsource`` in ``mapping``."""
    if not mapping:
        return None

    normalized_map = {
        str(k).strip().lower(): v for k, v in mapping.items() if str(k).strip()
    }
    if not normalized_map:
        return None

    product = ""
    service = ""
    category = ""
    if isinstance(logsource, Mapping):
        product = str(logsource.get("product") or "").strip().lower()
        service = str(logsource.get("service") or "").strip().lower()
        category = str(logsource.get("category") or "").strip().lower()

    candidates: list[str] = []
    if product and service and category:
        candidates.append(f"{product}:{service}:{category}")
    if product and service:
        candidates.append(f"{product}:{service}")
    if product and category:
        candidates.append(f"{product}:{category}")
    if service and category:
        candidates.append(f"{service}:{category}")
    if service:
        candidates.append(service)
    if category:
        candidates.append(category)
    if product:
        candidates.append(product)

    # Common cross-platform aliases when canonical product was not explicitly mapped
    if product == "macos":
        candidates.append("mac")
    elif product == "mac":
        candidates.append("macos")
    elif product == "linux":
        candidates.append("unix")
    elif product == "unix":
        candidates.append("linux")
    elif product == "windows":
        candidates.append("wineventlog")

    candidates.extend(("default", "*"))

    for key in candidates:
        if key in normalized_map:
            return normalized_map[key]
    return None


def normalize_index_values(index_spec: str | Iterable[str] | None) -> list[str]:
    """Normalize an index specification (single string, comma-separated, or list) into tokens."""
    if index_spec is None:
        return []

    if isinstance(index_spec, str):
        sanitized = _sanitize_ini_value(index_spec)
        if not sanitized:
            return []
        # Preserve already-qualified SPL expressions as a single clause.
        if _SPL_EXISTING_INDEX_RE.search(sanitized) or " OR " in sanitized.upper():
            return [sanitized]
        return _dedupe_preserve_order(part.strip() for part in sanitized.split(",") if part.strip())

    tokens: list[str] = []
    for item in index_spec:
        if item is None:
            continue
        sanitized = _sanitize_ini_value(str(item))
        if not sanitized:
            continue
        if _SPL_EXISTING_INDEX_RE.search(sanitized) or " OR " in sanitized.upper():
            tokens.append(sanitized)
        else:
            tokens.extend(part.strip() for part in sanitized.split(",") if part.strip())
    return _dedupe_preserve_order(tokens)


def format_spl_index_clause(index_spec: str | Iterable[str] | None) -> str:
    """Format one or more Splunk index values into a valid SPL ``index=...`` clause."""
    tokens = normalize_index_values(index_spec)
    if not tokens:
        return "index=*"

    if len(tokens) == 1 and _SPL_EXISTING_INDEX_RE.search(tokens[0]):
        return tokens[0]

    def _fmt_single(token: str) -> str:
        if _SIMPLE_INDEX_TOKEN_RE.match(token):
            return f"index={token}"
        escaped = token.replace('"', '\\"')
        return f'index="{escaped}"'

    if len(tokens) == 1:
        return _fmt_single(tokens[0])

    joined = " OR ".join(_fmt_single(tok) for tok in tokens)
    return f"({joined})"


def _resolve_index_map(
    index_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None,
) -> dict[str, str | list[str]]:
    if index_map is not None:
        return parse_key_value_mapping(index_map, lowercase_keys=True)
    env_map = _clean_env_str("SOCLENS_INDEX_MAP")
    if env_map is not None:
        return parse_key_value_mapping(env_map, lowercase_keys=True)
    return {}


def map_logsource_to_index(
    logsource: Any,
    *,
    index_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    default_index: str | None = None,
    index_override: str | None = None,
) -> str:
    """Map a Sigma ``logsource`` dict to a Splunk index name or comma-separated index list."""
    resolved_override = (
        _sanitize_ini_value(index_override)
        if index_override is not None
        else _clean_env_str("SOCLENS_INDEX")
    )
    if resolved_override:
        override_tokens = normalize_index_values(resolved_override)
        if override_tokens:
            return ",".join(override_tokens)

    resolved_map = _resolve_index_map(index_map)
    if resolved_map:
        mapped_val = _lookup_logsource_mapping(logsource, resolved_map)
        if mapped_val is not None:
            mapped_tokens = normalize_index_values(mapped_val)
            if mapped_tokens:
                return ",".join(mapped_tokens)

    resolved_default = (
        _sanitize_ini_value(default_index)
        if default_index is not None and _sanitize_ini_value(default_index)
        else (_clean_env_str("SOCLENS_DEFAULT_INDEX") or "*")
    )

    if not isinstance(logsource, Mapping):
        return resolved_default

    product = logsource.get("product")
    service = logsource.get("service")
    category = logsource.get("category")

    if (service and "sysmon" in str(service).lower()) or (
        category and "sysmon" in str(category).lower()
    ):
        return "*sysmon"

    if not product:
        if service:
            service_lower = str(service).lower().strip()
            if "cloudtrail" in service_lower:
                return "*aws"
            if "azure" in service_lower:
                return "*azure"
            if "gcp" in service_lower:
                return "*gcp"
        if category:
            category_lower = str(category).lower().strip()
            if "proxy" in category_lower:
                return "*proxy"
            if "firewall" in category_lower:
                return "*firewall"
            if "web" in category_lower:
                return "*web"
        return resolved_default

    product_lower = str(product).lower().strip()
    if "windows" in product_lower:
        return "*wineventlog"
    if "macos" in product_lower or "mac" in product_lower:
        return "*mac"
    if "linux" in product_lower or "unix" in product_lower:
        return "*unix"
    if "aws" in product_lower:
        return "*aws"
    if "azure" in product_lower:
        return "*azure"
    if "gcp" in product_lower:
        return "*gcp"
    return f"*{product_lower}"


def get_split_output_path(output_path: str | Path, index_name: str) -> str:
    """Compute a filesystem-safe per-index ``savedsearches_<index>.conf`` output path."""
    path = Path(output_path)
    raw = str(index_name).lower().strip()
    raw = re.sub(r"\bindex\s*=\s*", "", raw, flags=re.IGNORECASE)
    raw = raw.replace("*", "").replace('"', "").replace("'", "").strip()
    clean_index = _SPLIT_FILENAME_SANITIZE_RE.sub("_", raw).strip("_")
    if not clean_index:
        clean_index = "other"

    split_path = path.with_name(f"{path.stem}_{clean_index}{path.suffix}")
    return str(split_path)


def _apply_field_map(
    fields: list[str],
    field_map: Mapping[str, Any] | None,
) -> list[str]:
    """Rename fields using ``field_map`` while preserving order and unmapped fields."""
    if not field_map:
        return fields

    lower_map = {str(k).strip().lower(): v for k, v in field_map.items() if str(k).strip()}
    mapped: list[str] = []
    for fld in fields:
        target = field_map.get(fld)
        if target is None:
            target = lower_map.get(fld.lower())
        if target is None and fld.lower() == "eventcode" and "eventcode" not in lower_map:
            target = lower_map.get("eventid")

        if target is None:
            mapped.append(fld)
        elif isinstance(target, (list, tuple)):
            for item in target:
                cleaned = _sanitize_ini_value(item)
                if cleaned:
                    mapped.append(cleaned)
        else:
            cleaned = _sanitize_ini_value(target)
            if cleaned:
                mapped.append(cleaned)

    return _dedupe_preserve_order(mapped)


def _builtin_table_fields_for_logsource(logsource: Any) -> list[str]:
    if not isinstance(logsource, Mapping):
        return ["_time", "host", "User", "CommandLine", "Image", "ParentCommandLine", "ParentImage"]

    product = str(logsource.get("product") or "").lower().strip()
    service = str(logsource.get("service") or "").lower().strip()
    category = str(logsource.get("category") or "").lower().strip()

    if "aws" in product or "cloudtrail" in service:
        return [
            "_time",
            "src_ip",
            "user",
            "eventName",
            "eventSource",
            "userIdentity.arn",
            "sourceIPAddress",
            "userAgent",
            "awsRegion",
        ]
    if "azure" in product or "azureactivity" in service:
        return [
            "_time",
            "src_ip",
            "user",
            "operationName.localizedValue",
            "OperationNameValue",
            "CategoryValue",
            "ActivityStatusValue",
            "ResourceProviderValue",
        ]
    if "gcp" in product or "gcp.audit" in service:
        return [
            "_time",
            "src_ip",
            "user",
            "protoPayload.methodName",
            "protoPayload.serviceName",
            "protoPayload.authenticationInfo.principalEmail",
            "protoPayload.requestMetadata.callerIp",
        ]
    if "dns" in category:
        return ["_time", "host", "User", "Image", "QueryName", "QueryStatus", "QueryResults", "src_ip", "dest_ip"]
    if "registry" in category:
        return ["_time", "host", "User", "Image", "TargetObject", "Details", "EventType"]
    if "file" in category:
        return ["_time", "host", "User", "Image", "TargetFilename", "action", "size"]
    if "create_remote_thread" in category:
        return ["_time", "host", "User", "SourceImage", "TargetImage", "TargetProcessId", "StartAddress"]
    if "powershell" in service:
        return ["_time", "host", "User", "EventCode", "ScriptBlockText"]
    if any(k in category for k in ("proxy", "webserver", "firewall", "network")):
        return [
            "_time",
            "host",
            "src",
            "dest",
            "src_ip",
            "dest_ip",
            "url",
            "uri_path",
            "cs_method",
            "cs_cookie",
            "http_user_agent",
            "status",
            "action",
        ]
    if "sysmon" in service or "sysmon" in category:
        return [
            "_time",
            "host",
            "User",
            "EventCode",
            "Image",
            "CommandLine",
            "TargetFilename",
            "TargetObject",
            "Details",
        ]
    return ["_time", "host", "User", "CommandLine", "Image", "ParentCommandLine", "ParentImage"]


def _builtin_cim_table_fields_for_logsource(logsource: Any) -> list[str]:
    if not isinstance(logsource, Mapping):
        return [
            "firstTime",
            "lastTime",
            "count",
            "dest",
            "user",
            "process",
            "process_path",
            "parent_process",
            "parent_process_path",
        ]

    service = str(logsource.get("service") or "").lower().strip()
    category = str(logsource.get("category") or "").lower().strip()

    if "registry" in category:
        return [
            "firstTime",
            "lastTime",
            "count",
            "dest",
            "user",
            "registry_path",
            "registry_value_name",
            "registry_value_data",
        ]
    if "file" in category:
        return ["firstTime", "lastTime", "count", "dest", "user", "file_name", "file_path"]
    if "proxy" in category or "web" in category:
        return [
            "firstTime",
            "lastTime",
            "count",
            "src",
            "dest",
            "url",
            "http_user_agent",
            "http_method",
            "status",
        ]
    if "dns" in category or service == "dns":
        return ["firstTime", "lastTime", "count", "src", "dest", "query", "record_type", "answer"]
    return [
        "firstTime",
        "lastTime",
        "count",
        "dest",
        "user",
        "process",
        "process_path",
        "parent_process",
        "parent_process_path",
    ]


def _builtin_suppress_fields_for_logsource(logsource: Any) -> list[str]:
    if not isinstance(logsource, Mapping):
        return ["host", "User"]

    product = str(logsource.get("product") or "").lower().strip()
    service = str(logsource.get("service") or "").lower().strip()
    category = str(logsource.get("category") or "").lower().strip()

    if "aws" in product or "cloudtrail" in service:
        return ["userIdentity.arn", "eventName"]
    if "azure" in product or "azureactivity" in service:
        return ["caller", "OperationNameValue"]
    if "gcp" in product or "gcp.audit" in service:
        return ["protoPayload.authenticationInfo.principalEmail", "protoPayload.methodName"]
    if "dns" in category:
        return ["host", "QueryName"]
    if "registry" in category:
        return ["host", "TargetObject"]
    if "file" in category:
        return ["host", "TargetFilename"]
    if "create_remote_thread" in category:
        return ["host", "SourceImage", "TargetImage"]
    if "powershell" in service:
        return ["host", "ScriptBlockText"]
    if any(k in category for k in ("proxy", "webserver", "firewall", "network")):
        return ["src_ip", "dest_ip", "url"]
    if "sysmon" in service or "sysmon" in category:
        return ["host", "CommandLine"]
    return ["host", "User"]


def get_table_fields_for_logsource(
    logsource: Any,
    default_fields: str | None = None,
    *,
    custom_fields: str | list[str] | tuple[str, ...] | None = None,
    table_fields_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    rule_fields: list[str] | tuple[str, ...] | None = None,
    field_map: Mapping[str, Any] | None = None,
    cim: bool = False,
) -> str:
    """Resolve space-separated Splunk ``| table`` fields for ``logsource`` with custom overrides."""
    extra_custom = parse_field_list(custom_fields)
    env_custom = parse_field_list(_clean_env_str("SOCLENS_CUSTOM_TABLE_FIELDS"))
    tenant_field = _clean_env_str("SOCLENS_TENANT_FIELD")
    clean_tenant = _sanitize_ini_value(tenant_field) if tenant_field else ""

    if default_fields is not None:
        base = parse_field_list(default_fields)
        if not base and not extra_custom:
            return ""
        combined = _dedupe_preserve_order(base + extra_custom)
        return " ".join(combined)

    resolved_map = (
        parse_key_value_mapping(table_fields_map, lowercase_keys=True)
        if table_fields_map is not None
        else parse_key_value_mapping(_clean_env_str("SOCLENS_TABLE_FIELDS_MAP"), lowercase_keys=True)
    )
    mapped_table = _lookup_logsource_mapping(logsource, resolved_map) if resolved_map else None

    mapped_rule_fields = _apply_field_map(parse_field_list(rule_fields), field_map)
    all_custom = _dedupe_preserve_order(extra_custom + env_custom)
    if clean_tenant and clean_tenant not in all_custom:
        all_custom.append(clean_tenant)

    if mapped_table is not None:
        base = parse_field_list(mapped_table)
        combined = _dedupe_preserve_order(base + mapped_rule_fields + all_custom)
        return " ".join(combined)

    env_default = _clean_env_str("SOCLENS_DEFAULT_TABLE_FIELDS")
    if env_default is not None:
        base = parse_field_list(env_default)
        # Preserve existing SOCLENS_DEFAULT_TABLE_FIELDS precedence over SOCLENS_TENANT_FIELD
        # when explicit/env custom fields are not specified.
        append_fields = _dedupe_preserve_order(mapped_rule_fields + extra_custom + env_custom)
        combined = _dedupe_preserve_order(base + append_fields)
        return " ".join(combined)

    builtin = (
        _builtin_cim_table_fields_for_logsource(logsource)
        if cim
        else _builtin_table_fields_for_logsource(logsource)
    )
    base = _apply_field_map(builtin, field_map)
    combined = _dedupe_preserve_order(base + mapped_rule_fields + all_custom)
    return " ".join(combined)


def get_suppress_fields_for_logsource(
    logsource: Any,
    default_fields: str | None = None,
    *,
    custom_fields: str | list[str] | tuple[str, ...] | None = None,
    suppress_fields_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    field_map: Mapping[str, Any] | None = None,
) -> str:
    """Resolve comma-separated ``alert.suppress.fields`` for ``logsource`` with custom overrides."""
    extra_custom = parse_field_list(custom_fields)
    env_custom = parse_field_list(_clean_env_str("SOCLENS_CUSTOM_SUPPRESS_FIELDS"))
    tenant_field = _clean_env_str("SOCLENS_TENANT_FIELD")
    clean_tenant = _sanitize_ini_value(tenant_field) if tenant_field else ""

    if default_fields is not None:
        base = parse_field_list(default_fields)
        if not base and not extra_custom:
            return ""
        combined = _dedupe_preserve_order(extra_custom + base)
        return ",".join(combined)

    resolved_map = (
        parse_key_value_mapping(suppress_fields_map, lowercase_keys=True)
        if suppress_fields_map is not None
        else parse_key_value_mapping(
            _clean_env_str("SOCLENS_SUPPRESS_FIELDS_MAP"), lowercase_keys=True
        )
    )
    mapped_suppress = _lookup_logsource_mapping(logsource, resolved_map) if resolved_map else None

    prepend_custom = _dedupe_preserve_order(
        ([clean_tenant] if clean_tenant else []) + extra_custom + env_custom
    )

    if mapped_suppress is not None:
        base = parse_field_list(mapped_suppress)
        combined = _dedupe_preserve_order(prepend_custom + base)
        return ",".join(combined)

    env_default = _clean_env_str("SOCLENS_DEFAULT_SUPPRESS_FIELDS")
    if env_default is not None:
        base = parse_field_list(env_default)
        explicit_extra = _dedupe_preserve_order(extra_custom + env_custom)
        combined = _dedupe_preserve_order(explicit_extra + base)
        return ",".join(combined)

    base = _apply_field_map(_builtin_suppress_fields_for_logsource(logsource), field_map)
    combined = _dedupe_preserve_order(prepend_custom + base)
    return ",".join(combined)


def _build_logsource_condition(key: str) -> LogsourceCondition | None:
    """Convert a mapping key (e.g. ``windows:security`` or ``default``) into a LogsourceCondition."""
    cleaned = key.strip().lower()
    if not cleaned or cleaned in ("default", "*"):
        return None

    parts = [p.strip() for p in cleaned.split(":") if p.strip()]
    if len(parts) == 3:
        return LogsourceCondition(product=parts[0], service=parts[1], category=parts[2])
    if len(parts) == 2:
        p0, p1 = parts
        known_categories = {
            "process_creation",
            "file_event",
            "file_change",
            "file_delete",
            "file_rename",
            "registry_event",
            "registry_set",
            "registry_add",
            "registry_delete",
            "network_connection",
            "dns_query",
            "dns",
            "proxy",
            "firewall",
            "webserver",
            "create_remote_thread",
            "image_load",
            "pipe_created",
            "driver_load",
            "ps_script",
            "ps_module",
        }
        if p1 in known_categories:
            return LogsourceCondition(product=p0, category=p1)
        return LogsourceCondition(product=p0, service=p1)

    single = parts[0]
    known_products = {"windows", "linux", "unix", "macos", "mac", "aws", "azure", "gcp", "okta", "m365"}
    known_categories_single = {
        "process_creation",
        "file_event",
        "registry_event",
        "network_connection",
        "dns_query",
        "dns",
        "proxy",
        "firewall",
        "webserver",
        "create_remote_thread",
    }
    if single in known_products:
        alias = {"mac": "macos", "unix": "linux"}.get(single, single)
        return LogsourceCondition(product=alias)
    if single in known_categories_single:
        return LogsourceCondition(category=single)
    return LogsourceCondition(service=single)


def build_splunk_pipeline(
    pipeline: str = "splunk_windows",
    *,
    pipeline_path: str | Path | None = None,
    index_spec: str | list[str] | tuple[str, ...] | None = None,
    sourcetype_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    field_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
) -> ProcessingPipeline | None:
    """Build a pySigma ``ProcessingPipeline`` combining built-in Splunk, custom YAML, index, sourcetype, and field rules."""
    pipe_name = (pipeline or "none").strip()
    pipe_lower = pipe_name.lower()

    pipelines: list[ProcessingPipeline] = []

    pre_field_map = parse_key_value_mapping(field_map, lowercase_keys=False)
    is_cim = pipe_lower == "splunk_cim"

    # Apply custom Sigma->Splunk field mappings before splunk_windows_pipeline so
    # overrides such as EventID->event_id win over EventID->EventCode.
    if pre_field_map and not is_cim:
        pre_map: dict[str | None, str | list[str]] = {
            k: v for k, v in pre_field_map.items() if k != "EventCode" or "EventID" in pre_field_map
        }
        if pre_map:
            pipelines.append(
                ProcessingPipeline(
                    name="soclens_pre_field_mappings",
                    priority=10,
                    items=[
                        ProcessingItem(
                            identifier="soclens_custom_field_mapping_pre",
                            transformation=FieldMappingTransformation(pre_map),
                        )
                    ],
                )
            )

    if pipe_lower in ("", "none", "no_pipeline"):
        pass
    elif pipe_lower == "splunk_windows":
        pipelines.append(splunk_windows_pipeline())
    elif pipe_lower == "splunk_windows_sysmon":
        pipelines.append(splunk_windows_pipeline())
        pipelines.append(splunk_windows_sysmon_acceleration_keywords())
    elif pipe_lower == "splunk_cim":
        pipelines.append(splunk_cim_data_model())
    elif pipe_lower.endswith((".yml", ".yaml")) or Path(pipe_name).expanduser().is_file():
        yaml_path = Path(pipe_name).expanduser()
        if not yaml_path.is_file():
            raise FileNotFoundError(f"Sigma pipeline file not found: {yaml_path}")
        pipelines.append(ProcessingPipeline.from_yaml(yaml_path.read_text(encoding="utf-8")))
    else:
        raise ValueError(
            f"Unknown Sigma pipeline '{pipeline}'. "
            f"Expected one of: {', '.join(SIGMA_PIPELINES)} or a YAML file path."
        )

    if pipeline_path is not None:
        ext_path = Path(pipeline_path).expanduser()
        if not ext_path.is_file():
            raise FileNotFoundError(f"Sigma pipeline file not found: {ext_path}")
        pipelines.append(ProcessingPipeline.from_yaml(ext_path.read_text(encoding="utf-8")))

    # Post-pipeline mappings (e.g. CIM field overrides or explicit EventCode remap)
    if pre_field_map:
        if is_cim:
            post_map: dict[str | None, str | list[str]] = {
                k: v for k, v in pre_field_map.items()
            }
        elif "EventCode" in pre_field_map and "EventID" not in pre_field_map:
            post_map = {"EventCode": pre_field_map["EventCode"]}
        else:
            post_map = {}

        if post_map:
            pipelines.append(
                ProcessingPipeline(
                    name="soclens_post_field_mappings",
                    priority=40,
                    items=[
                        ProcessingItem(
                            identifier="soclens_custom_field_mapping_post",
                            transformation=FieldMappingTransformation(post_map),
                        )
                    ],
                )
            )

    resolved_st_map = parse_key_value_mapping(sourcetype_map, lowercase_keys=True)
    if resolved_st_map and not is_cim:
        st_items: list[ProcessingItem] = []
        for idx_num, (ls_key, st_val) in enumerate(resolved_st_map.items()):
            cond = _build_logsource_condition(ls_key)
            st_items.append(
                ProcessingItem(
                    identifier=f"soclens_sourcetype_{idx_num}",
                    transformation=AddConditionTransformation({"sourcetype": st_val}),
                    rule_conditions=[cond] if cond is not None else [],
                )
            )
        pipelines.append(
            ProcessingPipeline(
                name="soclens_sourcetype_mappings",
                priority=45,
                items=st_items,
            )
        )

    if index_spec is not None and not is_cim:
        idx_tokens = normalize_index_values(index_spec)
        if idx_tokens and not (
            len(idx_tokens) == 1 and _SPL_EXISTING_INDEX_RE.search(idx_tokens[0])
        ):
            idx_val: str | list[str] = idx_tokens[0] if len(idx_tokens) == 1 else idx_tokens
            pipelines.append(
                ProcessingPipeline(
                    name="soclens_index_condition",
                    priority=50,
                    items=[
                        ProcessingItem(
                            identifier="soclens_custom_index",
                            transformation=AddConditionTransformation({"index": idx_val}),
                        )
                    ],
                )
            )

    if not pipelines:
        return None

    combined = pipelines[0]
    for extra in pipelines[1:]:
        combined = combined + extra
    return combined


def _normalize_pysigma_spl(query: str, *, strip_rule_table: bool = False) -> str:
    """Normalize pySigma Splunk SPL output into clean single-line Splunk syntax."""
    cleaned = _sanitize_ini_value(query)
    if not cleaned:
        return ""

    # Hoist deferred multi-index (index IN (...)) from `| rex ... | search (index IN (...))`
    # so Splunk filters by index before running regex/eval stages.
    deferred_match = _SPL_DEFERRED_MULTI_INDEX_RE.match(cleaned)
    if deferred_match:
        prefix = deferred_match.group("prefix")
        idx_clause = deferred_match.group("idx")
        remainder = cleaned[deferred_match.end() :].strip()
        cleaned = f"{idx_clause} {prefix}{remainder}".strip()

    # Unquote simple unspaced index tokens emitted by pySigma (e.g. index="*wineventlog")
    cleaned = _SPL_QUOTED_SIMPLE_INDEX_RE.sub(r"index=\1", cleaned)

    # Collapse redundant wildcard immediately before `| regex` when index= is present
    if cleaned.startswith("* |"):
        cleaned = f"index=* {cleaned[2:].lstrip()}"
    else:
        cleaned = re.sub(r"^(\S+)\s+\*\s+(\|\s*regex\b)", r"\1 \2", cleaned, flags=re.IGNORECASE)

    if strip_rule_table:
        cleaned = _SPL_TRAILING_TABLE_RE.sub("", cleaned).strip()

    return cleaned


def convert_to_savedsearch_stanza(
    rule_id: str,
    rule_title: str,
    rule_content: str,
    splunk_query: str,
    suffix: str = "",
    cron_schedule: str = "0 * * * *",
    earliest_time: str = "-70m",
    latest_time: str = "-10m",
    suppress_period: str = "86400s",
    suppress_fields: str | None = None,
    parsed: dict[str, Any] | None = None,
    index_val: str | None = None,
    table_fields: str | None = None,
    *,
    custom_table_fields: str | list[str] | tuple[str, ...] | None = None,
    table_fields_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    custom_suppress_fields: str | list[str] | tuple[str, ...] | None = None,
    suppress_fields_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    index_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    default_index: str | None = None,
    index_override: str | None = None,
    field_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    rule_fields: list[str] | tuple[str, ...] | None = None,
    stanza_prefix: str = _DEFAULT_STANZA_PREFIX,
    security_domain: str = "threat",
    cim: bool = False,
) -> str:
    """Format a Splunk ES ``savedsearches.conf`` stanza with custom index, table, and suppression fields."""
    if parsed is None:
        try:
            parsed = yaml.safe_load(rule_content)
        except Exception as e:
            logger.warning("Failed to parse rule YAML for metadata extraction: %s", e)
            parsed = {}

    if not isinstance(parsed, dict):
        parsed = {}

    raw_title = parsed.get("title")
    title = _sanitize_ini_value(
        raw_title if raw_title is not None else rule_title,
        default="Unnamed Rule",
    )

    raw_description = parsed.get("description")
    if raw_description is None:
        raw_description = raw_title if raw_title is not None else rule_title
    description = _sanitize_ini_value(raw_description, default="No description provided.")

    raw_level = parsed.get("level")
    level = str(raw_level if raw_level is not None else "medium").lower().strip()

    severity_map = {
        "informational": "informational",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    splunk_severity = _sanitize_ini_value(severity_map.get(level, "medium"), default="medium")

    mitre_techniques: list[str] = []
    tags = parsed.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("attack.t"):
                parts = tag.split(".")
                if len(parts) >= 2:
                    tech_str = ".".join(parts[1:]).upper()
                    mitre_techniques.append(tech_str)

    annotations_json = ""
    if mitre_techniques:
        annotations_json = _sanitize_ini_value(json.dumps({"mitre_attack": mitre_techniques}))

    safe_prefix = _sanitize_ini_value(stanza_prefix, default="")
    if stanza_prefix.endswith(" ") and safe_prefix and not safe_prefix.endswith(" "):
        safe_prefix = f"{safe_prefix} "
    stanza_name = _sanitize_ini_value(f"{safe_prefix}{title}{suffix}")

    logsource = parsed.get("logsource", {})
    if not isinstance(logsource, dict):
        logsource = {}

    if index_val is not None:
        splunk_index = _sanitize_ini_value(index_val, default="*")
    else:
        splunk_index = _sanitize_ini_value(
            map_logsource_to_index(
                logsource,
                index_map=index_map,
                default_index=default_index,
                index_override=index_override,
            ),
            default="*",
        )

    resolved_field_map = parse_key_value_mapping(field_map, lowercase_keys=False)
    cleaned_query = _sanitize_ini_value(splunk_query)
    resolved_table_fields = _sanitize_ini_value(
        get_table_fields_for_logsource(
            logsource,
            default_fields=table_fields,
            custom_fields=custom_table_fields,
            table_fields_map=table_fields_map,
            rule_fields=rule_fields,
            field_map=resolved_field_map,
            cim=cim,
        )
    )

    idx_clause = format_spl_index_clause(splunk_index)
    pre_pipe_query = cleaned_query.split("|", 1)[0]

    if cleaned_query.startswith("|"):
        base_query = cleaned_query
    elif _SPL_SEARCH_PREFIX_RE.match(cleaned_query):
        if _SPL_EXISTING_INDEX_RE.search(pre_pipe_query):
            base_query = cleaned_query
        else:
            remainder = _SPL_SEARCH_PREFIX_RE.sub("", cleaned_query, count=1).strip()
            base_query = (
                f"search {idx_clause} {remainder}".strip()
                if remainder
                else f"search {idx_clause}"
            )
    elif _SPL_EXISTING_INDEX_RE.search(pre_pipe_query):
        base_query = cleaned_query
    elif cleaned_query:
        if cleaned_query == "*" or cleaned_query.startswith("* |"):
            remainder = cleaned_query[1:].lstrip()
            base_query = f"{idx_clause} {remainder}".strip()
        else:
            base_query = f"{idx_clause} {cleaned_query}"
    else:
        base_query = idx_clause

    if not _SPL_TABLE_RE.search(base_query):
        if resolved_table_fields:
            final_query = f"{base_query} | table {resolved_table_fields}"
        else:
            final_query = base_query
    else:
        trailing_match = _SPL_TRAILING_TABLE_RE.search(base_query)
        if trailing_match and table_fields is not None:
            prefix_query = base_query[: trailing_match.start()].rstrip()
            final_query = (
                f"{prefix_query} | table {resolved_table_fields}"
                if resolved_table_fields
                else prefix_query
            )
        elif trailing_match:
            extra_fields = _dedupe_preserve_order(
                _apply_field_map(parse_field_list(rule_fields), resolved_field_map)
                + parse_field_list(custom_table_fields)
                + parse_field_list(_clean_env_str("SOCLENS_CUSTOM_TABLE_FIELDS"))
                + (
                    [_sanitize_ini_value(_clean_env_str("SOCLENS_TENANT_FIELD"))]
                    if _clean_env_str("SOCLENS_TENANT_FIELD")
                    else []
                )
            )
            if extra_fields:
                existing_fields = parse_field_list(trailing_match.group(1))
                merged_fields = _dedupe_preserve_order(existing_fields + extra_fields)
                prefix_query = base_query[: trailing_match.start()].rstrip()
                final_query = f"{prefix_query} | table {' '.join(merged_fields)}"
            else:
                final_query = base_query
        else:
            final_query = base_query

    final_suppress_fields = _sanitize_ini_value(
        get_suppress_fields_for_logsource(
            logsource,
            default_fields=suppress_fields,
            custom_fields=custom_suppress_fields,
            suppress_fields_map=suppress_fields_map,
            field_map=resolved_field_map,
        )
    )

    safe_cron = _sanitize_ini_value(cron_schedule, default="0 * * * *")
    safe_earliest = _sanitize_ini_value(earliest_time, default="-70m")
    safe_latest = _sanitize_ini_value(latest_time, default="-10m")
    safe_suppress_period = _sanitize_ini_value(suppress_period, default="86400s")
    safe_domain = _sanitize_ini_value(security_domain, default="threat")

    stanza = [
        f"[{stanza_name}]",
        f"search = {final_query}",
        f"description = {description}",
        "disabled = 0",
        "action.correlationsearch.enabled = 1",
        f"action.correlationsearch.label = {stanza_name}",
    ]
    if annotations_json:
        stanza.append(f"action.correlationsearch.annotations = {annotations_json}")
    stanza.extend(
        [
            "action.notable = 1",
            f"action.notable.param.security_domain = {safe_domain}",
            f"action.notable.param.severity = {splunk_severity}",
            f"action.notable.param.rule_title = {stanza_name}",
            f"action.notable.param.rule_description = {description}",
            "enableSched = 1",
            f"cron_schedule = {safe_cron}",
            f"dispatch.earliest_time = {safe_earliest}",
            f"dispatch.latest_time = {safe_latest}",
            "alert.suppress = 1",
            f"alert.suppress.period = {safe_suppress_period}",
        ]
    )

    if final_suppress_fields:
        stanza.append(f"alert.suppress.fields = {final_suppress_fields}")

    stanza.append("")  # Empty line separator
    return "\n".join(stanza)


def extract_sigma_metadata(parsed: Any) -> dict[str, Any]:
    """Extract standard logsource, indexing, and MITRE metadata from parsed Sigma YAML."""
    if not isinstance(parsed, dict):
        parsed = {}

    logsource = parsed.get("logsource", {})
    if not isinstance(logsource, dict):
        logsource = {}

    product = logsource.get("product")
    category = logsource.get("category")
    service = logsource.get("service")
    index = map_logsource_to_index(logsource)

    mitre_techniques: list[str] = []
    tags = parsed.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("attack.t"):
                parts = tag.split(".")
                if len(parts) >= 2:
                    tech_str = ".".join(parts[1:]).upper()
                    mitre_techniques.append(tech_str)

    return {
        "logsource": logsource,
        "product": product,
        "category": category,
        "service": service,
        "index": index,
        "mitre_techniques": mitre_techniques,
    }


def _resolve_rule_conversion_config(
    config: SigmaConversionConfig | None = None,
    *,
    index_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    default_index: str | None = None,
    index_override: str | None = None,
    sourcetype_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    field_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    table_fields: str | None = None,
    custom_table_fields: str | list[str] | tuple[str, ...] | None = None,
    table_fields_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    include_rule_fields: bool | None = None,
    suppress_fields: str | None = None,
    custom_suppress_fields: str | list[str] | tuple[str, ...] | None = None,
    suppress_fields_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    pipeline: str | None = None,
    pipeline_path: str | Path | None = None,
    output_format: str | None = None,
    cron_schedule: str | None = None,
    earliest_time: str | None = None,
    latest_time: str | None = None,
    suppress_period: str | None = None,
    stanza_prefix: str | None = None,
    security_domain: str | None = None,
    split_by_index: bool | None = None,
    write_mode: str | None = None,
) -> SigmaConversionConfig:
    """Merge an optional base ``SigmaConversionConfig`` with explicit call overrides."""
    base = (
        SigmaConversionConfig.from_dict(config.to_dict())
        if config is not None
        else SigmaConversionConfig.from_env()
    )

    if index_map is not None:
        base.index_map = parse_key_value_mapping(index_map, lowercase_keys=True)
    if default_index is not None:
        cleaned_def = _sanitize_ini_value(default_index)
        base.default_index = cleaned_def if cleaned_def else None
    if index_override is not None:
        cleaned_ov = _sanitize_ini_value(index_override)
        base.index_override = cleaned_ov if cleaned_ov else None
    if sourcetype_map is not None:
        base.sourcetype_map = parse_key_value_mapping(sourcetype_map, lowercase_keys=True)
    if field_map is not None:
        base.field_map = parse_key_value_mapping(field_map, lowercase_keys=False)
    if table_fields is not None:
        base.table_fields = _sanitize_ini_value(table_fields)
    if custom_table_fields is not None:
        base.custom_table_fields = parse_field_list(custom_table_fields)
    if table_fields_map is not None:
        base.table_fields_map = parse_key_value_mapping(table_fields_map, lowercase_keys=True)
    if include_rule_fields is not None:
        base.include_rule_fields = include_rule_fields
    if suppress_fields is not None:
        base.suppress_fields = _sanitize_ini_value(suppress_fields)
    if custom_suppress_fields is not None:
        base.custom_suppress_fields = parse_field_list(custom_suppress_fields)
    if suppress_fields_map is not None:
        base.suppress_fields_map = parse_key_value_mapping(
            suppress_fields_map, lowercase_keys=True
        )
    if pipeline is not None:
        base.pipeline = pipeline.strip()
        if output_format is None:
            base.output_format = "data_model" if base.pipeline.lower() == "splunk_cim" else "default"
    if pipeline_path is not None:
        base.pipeline_path = str(pipeline_path).strip() or None
    if output_format is not None:
        fmt_lower = output_format.strip().lower()
        if fmt_lower not in SIGMA_OUTPUT_FORMATS:
            raise ValueError(
                f"Unsupported Sigma output_format '{output_format}'. "
                f"Expected one of: {', '.join(SIGMA_OUTPUT_FORMATS)}."
            )
        base.output_format = fmt_lower
    if cron_schedule is not None:
        base.cron_schedule = cron_schedule
    if earliest_time is not None:
        base.earliest_time = earliest_time
    if latest_time is not None:
        base.latest_time = latest_time
    if suppress_period is not None:
        base.suppress_period = suppress_period
    if stanza_prefix is not None:
        base.stanza_prefix = stanza_prefix
    if security_domain is not None:
        base.security_domain = security_domain
    if split_by_index is not None:
        base.split_by_index = split_by_index
    if write_mode is not None:
        base.write_mode = write_mode

    return base


def _coerce_rule_dict(rule: str | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(rule, str):
        return {"rule_id": "local", "file_name": "rule.yml", "content": rule}
    if isinstance(rule, Mapping):
        return dict(rule)
    raise ValueError(f"Expected Sigma rule YAML string or mapping, got {type(rule).__name__}.")


def _convert_single_rule(
    rule: dict[str, Any],
    cfg: SigmaConversionConfig,
    backend_cache: dict[tuple[str, str | None, str], NoPipelineSplunkBackend] | None = None,
) -> dict[str, Any]:
    """Convert one Sigma rule dict using ``cfg`` and return normalized SPL + Splunk ES stanzas."""
    content = rule.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Rule has no YAML content.")

    try:
        parsed = yaml.safe_load(content)
    except Exception:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}

    logsource = parsed.get("logsource", {})
    if not isinstance(logsource, dict):
        logsource = {}

    mapped_idx = map_logsource_to_index(
        logsource,
        index_map=cfg.index_map or None,
        default_index=cfg.default_index,
        index_override=cfg.index_override,
    )

    resolved_format = cfg.output_format
    if cfg.pipeline.lower().strip() == "splunk_cim" and resolved_format == "default":
        resolved_format = "data_model"

    cache_key = (cfg.pipeline, cfg.pipeline_path, mapped_idx)
    if backend_cache is not None and cache_key in backend_cache:
        backend = backend_cache[cache_key]
    else:
        proc_pipeline = build_splunk_pipeline(
            pipeline=cfg.pipeline,
            pipeline_path=cfg.pipeline_path,
            index_spec=mapped_idx,
            sourcetype_map=cfg.sourcetype_map or None,
            field_map=cfg.field_map or None,
        )
        backend = NoPipelineSplunkBackend(processing_pipeline=proc_pipeline)
        if backend_cache is not None:
            backend_cache[cache_key] = backend

    rule_collection = SigmaCollection.from_yaml(content)
    if resolved_format == "default":
        raw_queries = backend.convert(rule_collection)
    else:
        raw_queries = backend.convert(rule_collection, output_format=resolved_format)

    if not raw_queries:
        raise ValueError("No Splunk queries generated for rule.")

    rule_fields_raw = parsed.get("fields")
    rule_fields: list[str] | None = None
    if cfg.include_rule_fields and isinstance(rule_fields_raw, list):
        rule_fields = [str(f) for f in rule_fields_raw if f is not None and str(f).strip()]

    is_cim_format = resolved_format == "data_model"
    effective_table_fields = get_table_fields_for_logsource(
        logsource,
        default_fields=cfg.table_fields,
        custom_fields=cfg.custom_table_fields or None,
        table_fields_map=cfg.table_fields_map or None,
        rule_fields=rule_fields,
        field_map=cfg.field_map or None,
        cim=is_cim_format,
    )
    effective_suppress_fields = get_suppress_fields_for_logsource(
        logsource,
        default_fields=cfg.suppress_fields,
        custom_fields=cfg.custom_suppress_fields or None,
        suppress_fields_map=cfg.suppress_fields_map or None,
        field_map=cfg.field_map or None,
    )

    rule_id = str(rule.get("rule_id") or parsed.get("id") or "N/A")
    rule_title = str(parsed.get("title") or rule.get("title") or "N/A")
    file_name = str(rule.get("file_name") or "Unnamed Rule")
    raw_level = parsed.get("level") or rule.get("level")
    lvl = str(raw_level if raw_level is not None and str(raw_level).strip() else "medium").lower().strip()
    if lvl == "n/a":
        lvl = "medium"

    meta = extract_sigma_metadata(parsed)
    mitre_techniques = list(rule.get("mitre_techniques") or meta["mitre_techniques"] or [])

    normalized_queries: list[str] = []
    stanzas: list[str] = []
    strip_rule_table = resolved_format != "data_model"

    for idx_num, raw_query in enumerate(raw_queries):
        norm_query = _normalize_pysigma_spl(str(raw_query), strip_rule_table=strip_rule_table)
        normalized_queries.append(norm_query)
        suffix = f" - Query {idx_num + 1}" if len(raw_queries) > 1 else ""
        stanza = convert_to_savedsearch_stanza(
            rule_id,
            rule_title,
            content,
            norm_query,
            suffix,
            cron_schedule=cfg.cron_schedule,
            earliest_time=cfg.earliest_time,
            latest_time=cfg.latest_time,
            suppress_period=cfg.suppress_period,
            suppress_fields=cfg.suppress_fields,
            parsed=parsed,
            index_val=mapped_idx,
            table_fields=cfg.table_fields,
            custom_table_fields=cfg.custom_table_fields or None,
            table_fields_map=cfg.table_fields_map or None,
            custom_suppress_fields=cfg.custom_suppress_fields or None,
            suppress_fields_map=cfg.suppress_fields_map or None,
            field_map=cfg.field_map or None,
            rule_fields=rule_fields,
            stanza_prefix=cfg.stanza_prefix,
            security_domain=cfg.security_domain,
            cim=is_cim_format,
        )
        stanzas.append(stanza)

    return {
        "rule_id": rule_id,
        "title": rule_title,
        "file_name": file_name,
        "logsource": logsource,
        "service": logsource.get("service"),
        "level": lvl,
        "index": mapped_idx,
        "table_fields": effective_table_fields,
        "suppress_fields": effective_suppress_fields,
        "pipeline": cfg.pipeline,
        "output_format": resolved_format,
        "mitre_techniques": mitre_techniques,
        "queries": normalized_queries,
        "stanzas": stanzas,
    }


def convert_sigma_rule(
    rule: str | Mapping[str, Any],
    config: SigmaConversionConfig | None = None,
    *,
    index_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    default_index: str | None = None,
    index_override: str | None = None,
    sourcetype_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    field_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    table_fields: str | None = None,
    custom_table_fields: str | list[str] | tuple[str, ...] | None = None,
    table_fields_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    include_rule_fields: bool | None = None,
    suppress_fields: str | None = None,
    custom_suppress_fields: str | list[str] | tuple[str, ...] | None = None,
    suppress_fields_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    pipeline: str | None = None,
    pipeline_path: str | Path | None = None,
    output_format: str | None = None,
    cron_schedule: str | None = None,
    earliest_time: str | None = None,
    latest_time: str | None = None,
    suppress_period: str | None = None,
    stanza_prefix: str | None = None,
    security_domain: str | None = None,
) -> dict[str, Any]:
    """Convert a single Sigma YAML rule (string or dict) into Splunk SPL queries and ES stanzas."""
    cfg = _resolve_rule_conversion_config(
        config,
        index_map=index_map,
        default_index=default_index,
        index_override=index_override,
        sourcetype_map=sourcetype_map,
        field_map=field_map,
        table_fields=table_fields,
        custom_table_fields=custom_table_fields,
        table_fields_map=table_fields_map,
        include_rule_fields=include_rule_fields,
        suppress_fields=suppress_fields,
        custom_suppress_fields=custom_suppress_fields,
        suppress_fields_map=suppress_fields_map,
        pipeline=pipeline,
        pipeline_path=pipeline_path,
        output_format=output_format,
        cron_schedule=cron_schedule,
        earliest_time=earliest_time,
        latest_time=latest_time,
        suppress_period=suppress_period,
        stanza_prefix=stanza_prefix,
        security_domain=security_domain,
    )
    return _convert_single_rule(_coerce_rule_dict(rule), cfg)


def convert_sigma_rules(
    rules: list[str | Mapping[str, Any]],
    *,
    config: SigmaConversionConfig | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    """Convert a batch of Sigma rules in-memory with custom indexes, fields, and pipelines."""
    cfg = _resolve_rule_conversion_config(config, **overrides)
    backend_cache: dict[tuple[str, str | None, str], NoPipelineSplunkBackend] = {}

    results: list[dict[str, Any]] = []
    stanzas_by_index: dict[str, list[str]] = {}
    converted_count = 0
    failed_count = 0
    converted_by_index: dict[str, int] = {}
    converted_by_level: dict[str, int] = {}
    converted_by_service: dict[str, int] = {}
    converted_by_mitre: dict[str, int] = {}
    errors: list[dict[str, str]] = []

    for raw_rule in rules:
        rule_dict = _coerce_rule_dict(raw_rule)
        filename = str(rule_dict.get("file_name") or "Unnamed Rule")
        try:
            converted = _convert_single_rule(rule_dict, cfg, backend_cache=backend_cache)
        except Exception as exc:
            failed_count += 1
            errors.append({"file_name": filename, "error": str(exc)})
            continue

        results.append(converted)
        mapped_idx = converted["index"]
        stanzas_by_index.setdefault(mapped_idx, []).extend(converted["stanzas"])

        query_count = len(converted["queries"])
        converted_count += query_count
        converted_by_index[mapped_idx] = converted_by_index.get(mapped_idx, 0) + query_count
        lvl = converted["level"]
        converted_by_level[lvl] = converted_by_level.get(lvl, 0) + query_count
        srv = converted.get("service")
        srv_name = str(srv).lower().strip() if srv else "unspecified/na"
        converted_by_service[srv_name] = converted_by_service.get(srv_name, 0) + query_count
        for tech in converted.get("mitre_techniques") or []:
            converted_by_mitre[tech] = converted_by_mitre.get(tech, 0) + query_count

    return {
        "results": results,
        "stanzas_by_index": stanzas_by_index,
        "converted_count": converted_count,
        "failed_count": failed_count,
        "converted_by_index": converted_by_index,
        "converted_by_level": converted_by_level,
        "converted_by_service": converted_by_service,
        "converted_by_mitre": converted_by_mitre,
        "errors": errors,
    }


def flatten_rules(api_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten Recorded Future detection-rule API search results into per-file rule entries."""
    flat_rules: list[dict[str, Any]] = []
    for rule_set in api_results:
        if not isinstance(rule_set, dict):
            continue
        rule_id = rule_set.get("id", "N/A")
        set_title = rule_set.get("title") or "N/A"
        rules_list = rule_set.get("rules") or []

        for r in rules_list:
            if not isinstance(r, dict):
                continue
            filename = r.get("file_name") or "Unnamed Rule"
            content = r.get("content")
            if not content:
                continue

            try:
                parsed = yaml.safe_load(content)
            except Exception:
                parsed = {}

            if not isinstance(parsed, dict):
                parsed = {}

            meta = extract_sigma_metadata(parsed)
            title = parsed.get("title")
            description = parsed.get("description")
            author = parsed.get("author")
            level = parsed.get("level")
            references = parsed.get("references")

            flat_rules.append(
                {
                    "rule_id": rule_id,
                    "rule_set_title": set_title,
                    "file_name": filename,
                    "content": content,
                    "title": title if title is not None else set_title,
                    "description": (
                        description if description is not None else "No description provided."
                    ),
                    "author": author if author is not None else "N/A",
                    "level": level if level is not None else "N/A",
                    "references": references if references is not None else [],
                    "product": meta["product"],
                    "category": meta["category"],
                    "service": meta["service"],
                    "index": meta["index"],
                    "mitre_techniques": meta["mitre_techniques"],
                }
            )
    return flat_rules


def enrich_rules_in_place(rules: list[dict[str, Any]]) -> bool:
    """Populate missing metadata fields on cached Sigma rule dicts in-place."""
    modified = False
    for r in rules:
        if "product" not in r or "index" not in r or "mitre_techniques" not in r:
            content = r.get("content") or ""
            try:
                parsed = yaml.safe_load(content)
            except Exception:
                parsed = {}
            meta = extract_sigma_metadata(parsed)
            r["product"] = meta["product"]
            r["category"] = meta["category"]
            r["service"] = meta["service"]
            r["index"] = meta["index"]
            r["mitre_techniques"] = meta["mitre_techniques"]
            modified = True
    return modified


def print_sourcing_validation(rules: list[dict[str, Any]]) -> None:
    """Print logsource, level, service, and MITRE ATT&CK distribution summary for loaded rules."""
    counts: dict[str, int] = {}
    level_counts: dict[str, int] = {}
    mitre_counts: dict[str, int] = {}
    service_counts: dict[str, int] = {}
    fallback_rules: list[dict[str, Any]] = []

    for r in rules:
        idx = r.get("index") or "*"
        counts[idx] = counts.get(idx, 0) + 1
        if idx == "*":
            fallback_rules.append(r)

        lvl = str(r.get("level") or "N/A").lower().strip()
        level_counts[lvl] = level_counts.get(lvl, 0) + 1

        techs = r.get("mitre_techniques") or []
        for tech in techs:
            mitre_counts[tech] = mitre_counts.get(tech, 0) + 1

        srv = r.get("service")
        srv_name = str(srv).lower().strip() if srv else "unspecified/NA"
        service_counts[srv_name] = service_counts.get(srv_name, 0) + 1

    print("\nRules Sourcing Validation Summary:")
    for idx, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {idx} got {count} rules.")

    print("\nRules Criticality Validation Summary:")
    for lvl, count in sorted(level_counts.items(), key=lambda x: -x[1]):
        print(f"  {lvl} got {count} rules.")

    print("\nRules Service Validation Summary:")
    for srv_name, count in sorted(service_counts.items(), key=lambda x: -x[1]):
        print(f"  {srv_name} got {count} rules.")

    if mitre_counts:
        print("\nTop 10 MITRE ATT&CK Techniques:")
        for tech, count in sorted(mitre_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {tech} got {count} rules.")

    if fallback_rules:
        print("\nRules with missing or unrecognized products (mapped to '*'):")
        for r in fallback_rules:
            product_val = r.get("product")
            category_val = r.get("category")
            logsource_str = (
                f"product: {product_val}, category: {category_val}"
                if product_val or category_val
                else "none"
            )
            print(f"  - {r.get('rule_id')} | {r.get('title')} (Logsource: {logsource_str})")
    print()


def _load_cached_rules(cache_path: str) -> list[dict[str, Any]]:
    with open(cache_path, encoding="utf-8") as f:
        loaded = json.load(f)
    if not isinstance(loaded, list):
        raise RuntimeError(f"Invalid Sigma rule cache format in '{cache_path}': expected a list.")
    rules: list[dict[str, Any]] = loaded
    if enrich_rules_in_place(rules):
        Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as wf:
            json.dump(rules, wf, indent=2)
    print_sourcing_validation(rules)
    return rules


def load_rules(
    client: Any,
    refresh: bool = False,
    days: int | None = None,
    cache_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Load Insikt Group Sigma rules from local cache or Recorded Future Detection Rule API."""
    resolved_dir = get_workspace_dir(cache_dir)
    cache_path = os.fspath(resolved_dir / CACHE_FILE_NAME)
    token = _resolve_client_token(client)

    if days is not None:
        if not token:
            raise SigmaConfigurationError(
                "Recorded Future API token is not set; cannot fetch recent detection rules."
            )
        raw_rules = client.search_detection_rules(days=days)
        if raw_rules is None:
            raise RuntimeError("API fetch failed while retrieving detection rules.")
        return flatten_rules(raw_rules)

    cache_exists = os.path.exists(cache_path)

    if not refresh and cache_exists:
        try:
            return _load_cached_rules(cache_path)
        except (json.JSONDecodeError, ValueError, RuntimeError, OSError) as exc:
            logger.warning(
                "Corrupted or unreadable Sigma cache at %s (%s); refreshing from API.",
                cache_path,
                exc,
            )
            cache_exists = False

    if refresh or not cache_exists:
        if not token:
            if not cache_exists:
                raise SigmaConfigurationError(
                    "Recorded Future API token is not set and no cache file exists."
                )
            logger.warning("API token not set. Using existing cache file at %s.", cache_path)
            print("Warning: API token not set. Using existing cache file.")
            return _load_cached_rules(cache_path)

        try:
            raw_rules = client.search_detection_rules()
        except (RecordedFutureError, ConfigurationError) as exc:
            if cache_exists:
                logger.warning("API fetch failed (%s). Falling back to cached rules.", exc)
                print(f"Warning: API fetch failed ({exc}). Falling back to cached rules.")
                return _load_cached_rules(cache_path)
            raise

        if raw_rules is None:
            if cache_exists:
                logger.warning("API fetch returned None. Falling back to cached rules.")
                print("Warning: API fetch failed. Falling back to cached rules.")
                return _load_cached_rules(cache_path)
            raise RuntimeError("API fetch failed and no cached rules available.")

        flat_rules = flatten_rules(raw_rules)
        if cache_exists and not flat_rules:
            try:
                existing_rules = _load_cached_rules(cache_path)
                if existing_rules:
                    logger.warning(
                        "API refresh returned 0 rules; preserving existing %d cached rules.",
                        len(existing_rules),
                    )
                    print(
                        "Warning: API refresh returned 0 rules. "
                        "Preserving existing cached rules."
                    )
                    return existing_rules
            except (OSError, ValueError, RuntimeError) as exc:
                logger.warning("Failed to read existing cache during empty refresh guard: %s", exc)

        Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(flat_rules, f, indent=2)
        print_sourcing_validation(flat_rules)
        return flat_rules

    return _load_cached_rules(cache_path)


def convert_sigma_rule_to_spl(
    rule: dict[str, Any],
    *,
    config: SigmaConversionConfig | None = None,
) -> str:
    """Convert a single Sigma rule dict into an executable Splunk SPL query."""
    if config is not None:
        converted = convert_sigma_rule(rule, config=config)
        stanzas = converted.get("stanzas") or []
        if stanzas:
            for line in str(stanzas[0]).splitlines():
                if line.startswith("search = "):
                    return line[len("search = ") :].strip()
        queries = converted.get("queries") or []
        if queries:
            return str(queries[0]).strip()
        raise ValueError("No Splunk SPL query was generated for this Sigma rule.")

    content = str(rule.get("content") or "").strip()
    if not content:
        raise ValueError("Selected Sigma rule has no YAML content.")

    try:
        parsed = yaml.safe_load(content)
    except Exception:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}

    logsource = parsed.get("logsource", {})
    if not isinstance(logsource, dict):
        logsource = {}
    raw_idx = rule.get("index")
    mapped_idx = (
        _sanitize_ini_value(raw_idx, default="*")
        if raw_idx
        else _sanitize_ini_value(map_logsource_to_index(logsource), default="*")
    )

    backend = NoPipelineSplunkBackend()
    rule_collection = SigmaCollection.from_yaml(content)
    queries = backend.convert(rule_collection)
    if not queries:
        raise ValueError("No Splunk SPL query was generated for this Sigma rule.")

    cleaned_query = _sanitize_ini_value(queries[0])
    if cleaned_query.startswith("|"):
        return cleaned_query
    if _SPL_EXISTING_INDEX_RE.search(cleaned_query):
        return cleaned_query
    if _SPL_SEARCH_PREFIX_RE.match(cleaned_query):
        remainder = _SPL_SEARCH_PREFIX_RE.sub("", cleaned_query, count=1).strip()
        return f"search index={mapped_idx} {remainder}".strip() if remainder else f"search index={mapped_idx}"
    return f"index={mapped_idx} {cleaned_query}".strip() if cleaned_query else f"index={mapped_idx}"


def export_rules_to_splunk(
    rules: list[dict[str, Any]],
    output_path: str | Path,
    write_mode: str = "overwrite",
    cron_schedule: str = "0 * * * *",
    earliest_time: str = "-70m",
    latest_time: str = "-10m",
    suppress_period: str = "86400s",
    suppress_fields: str | None = None,
    table_fields: str | None = None,
    *,
    index_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    default_index: str | None = None,
    index_override: str | None = None,
    custom_table_fields: str | list[str] | tuple[str, ...] | None = None,
    table_fields_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    custom_suppress_fields: str | list[str] | tuple[str, ...] | None = None,
    suppress_fields_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    field_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    sourcetype_map: Mapping[str, Any] | str | list[str] | tuple[str, ...] | None = None,
    pipeline: str | None = None,
    pipeline_path: str | Path | None = None,
    output_format: str | None = None,
    split_by_index: bool | None = None,
    include_rule_fields: bool | None = None,
    stanza_prefix: str | None = None,
    security_domain: str | None = None,
    config: SigmaConversionConfig | None = None,
) -> dict[str, Any]:
    """Convert Sigma rules using pySigma pipelines and export Splunk ES ``savedsearches.conf`` stanzas."""
    cfg = _resolve_rule_conversion_config(
        config,
        index_map=index_map,
        default_index=default_index,
        index_override=index_override,
        sourcetype_map=sourcetype_map,
        field_map=field_map,
        table_fields=table_fields,
        custom_table_fields=custom_table_fields,
        table_fields_map=table_fields_map,
        include_rule_fields=include_rule_fields,
        suppress_fields=suppress_fields,
        custom_suppress_fields=custom_suppress_fields,
        suppress_fields_map=suppress_fields_map,
        pipeline=pipeline,
        pipeline_path=pipeline_path,
        output_format=output_format,
        cron_schedule=cron_schedule if config is None or cron_schedule != "0 * * * *" else None,
        earliest_time=earliest_time if config is None or earliest_time != "-70m" else None,
        latest_time=latest_time if config is None or latest_time != "-10m" else None,
        suppress_period=suppress_period if config is None or suppress_period != "86400s" else None,
        stanza_prefix=stanza_prefix,
        security_domain=security_domain,
        split_by_index=split_by_index,
        write_mode=write_mode if config is None or write_mode != "overwrite" else None,
    )

    print(
        f"\nProcessing and converting {len(rules)} rules to Splunk Saved Searches "
        f"(pipeline={cfg.pipeline}, format={cfg.output_format})..."
    )

    stanzas_by_file: dict[str, list[str]] = {}
    converted_count = 0
    failed_count = 0
    converted_by_index: dict[str, int] = {}
    converted_by_level: dict[str, int] = {}
    converted_by_service: dict[str, int] = {}
    converted_by_mitre: dict[str, int] = {}
    errors: list[dict[str, str]] = []
    backend_cache: dict[tuple[str, str | None, str], NoPipelineSplunkBackend] = {}

    for rule in rules:
        filename = str(rule.get("file_name") or "Unnamed Rule")
        content = rule.get("content")

        if not content:
            print(f"  [WARNING] Rule '{filename}' has no content.")
            continue

        try:
            converted = _convert_single_rule(rule, cfg, backend_cache=backend_cache)
            mapped_idx = converted["index"]
            target_file = (
                get_split_output_path(output_path, mapped_idx)
                if cfg.split_by_index
                else str(output_path)
            )
            stanzas_by_file.setdefault(target_file, []).extend(converted["stanzas"])

            query_count = len(converted["queries"])
            converted_count += query_count
            converted_by_index[mapped_idx] = converted_by_index.get(mapped_idx, 0) + query_count
            lvl = converted["level"]
            converted_by_level[lvl] = converted_by_level.get(lvl, 0) + query_count
            srv = converted.get("service")
            srv_name = str(srv).lower().strip() if srv else "unspecified/na"
            converted_by_service[srv_name] = converted_by_service.get(srv_name, 0) + query_count
            for tech in converted.get("mitre_techniques") or []:
                converted_by_mitre[tech] = converted_by_mitre.get(tech, 0) + query_count

            print(f"  [SUCCESS] Converted '{filename}'")

        except Exception as e:
            print(f"  [ERROR] Failed to convert '{filename}': {e}")
            failed_count += 1
            errors.append({"file_name": filename, "error": str(e)})

    print("\nSplunk Conversion Summary:")
    print(f"  Successfully converted {converted_count} Splunk queries from {len(rules)} rule files.")
    print(f"  Failed conversions: {failed_count}")

    if converted_by_index:
        print("\nSourcing breakdown of successfully converted queries:")
        for index_name, count in sorted(converted_by_index.items(), key=lambda x: -x[1]):
            print(f"  {index_name}: {count} queries")

    if converted_by_level:
        print("\nCriticality breakdown of successfully converted queries:")
        for lvl, count in sorted(converted_by_level.items(), key=lambda x: -x[1]):
            print(f"  {lvl}: {count} queries")

    if converted_by_service:
        print("\nService breakdown of successfully converted queries:")
        for srv, count in sorted(converted_by_service.items(), key=lambda x: -x[1]):
            print(f"  {srv}: {count} queries")

    if converted_by_mitre:
        print("\nTop 10 MITRE ATT&CK Techniques of successfully converted queries:")
        for tech, count in sorted(converted_by_mitre.items(), key=lambda x: -x[1])[:10]:
            print(f"  {tech}: {count} queries")

    files_written: list[str] = []
    if not stanzas_by_file:
        print("No stanzas generated. Output files will not be written.")
        return {
            "converted_count": converted_count,
            "failed_count": failed_count,
            "files_written": files_written,
            "converted_by_index": converted_by_index,
            "converted_by_level": converted_by_level,
            "converted_by_service": converted_by_service,
            "converted_by_mitre": converted_by_mitre,
            "errors": errors,
        }

    mode_char = "a" if cfg.write_mode == "append" else "w"

    for target_file, file_stanzas in stanzas_by_file.items():
        output_abs_path = os.path.abspath(target_file)
        print(
            f"\nWriting {len(file_stanzas)} stanzas to {output_abs_path} "
            f"(mode: {cfg.write_mode})..."
        )
        try:
            Path(output_abs_path).parent.mkdir(parents=True, exist_ok=True)
            file_exists = os.path.exists(output_abs_path)
            with open(output_abs_path, mode_char, encoding="utf-8") as f:
                if mode_char == "a" and file_exists:
                    f.write("\n")
                f.write("\n".join(file_stanzas))
            files_written.append(output_abs_path)
        except Exception as e:
            print(f"Error writing to output file {output_abs_path}: {e}")

    print("Done!")
    return {
        "converted_count": converted_count,
        "failed_count": failed_count,
        "files_written": files_written,
        "converted_by_index": converted_by_index,
        "converted_by_level": converted_by_level,
        "converted_by_service": converted_by_service,
        "converted_by_mitre": converted_by_mitre,
        "errors": errors,
    }


def search_rules(rules: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    """Search Sigma rules by keyword match across title, rule set, filename, description, and YAML."""
    if not query.strip():
        return []

    terms = query.lower().split()
    results: list[tuple[int, dict[str, Any]]] = []

    for r in rules:
        score = 0
        title = str(r.get("title") or "").lower()
        set_title = str(r.get("rule_set_title") or "").lower()
        filename = str(r.get("file_name") or "").lower()
        desc = str(r.get("description") or "").lower()
        content = str(r.get("content") or "").lower()

        for term in terms:
            term_matched = False
            if term in title:
                score += 15
                term_matched = True
            if term in set_title:
                score += 10
                term_matched = True
            if term in filename:
                score += 8
                term_matched = True
            if term in desc:
                score += 5
                term_matched = True
            if term in content:
                score += 2
                term_matched = True

            if not term_matched:
                score = 0
                break

        if score > 0:
            results.append((score, r))

    results.sort(key=lambda x: (-x[0], str(x[1].get("title") or "")))
    return [item[1] for item in results]


def print_rule(rule: dict[str, Any]) -> None:
    """Pretty-print a Sigma rule summary and full YAML content to stdout."""
    print("\n" + "=" * 80)
    print(f"RULE: {rule.get('title')}")
    print("=" * 80)
    print(f"File Name:    {rule.get('file_name')}")
    print(f"RF Rule ID:   {rule.get('rule_id')}")
    print(f"Log Source:   {rule.get('product', 'N/A')}")
    print(f"Splunk Index: {rule.get('index', 'N/A')}")
    print(f"Level:        {rule.get('level')}")
    print(f"Author:       {rule.get('author')}")
    print(f"Description:  {rule.get('description')}")

    refs = rule.get("references")
    if refs:
        print("References:")
        if isinstance(refs, list):
            for ref in refs:
                print(f"  - {ref}")
        else:
            print(f"  - {refs}")

    print("-" * 80)
    content = rule.get("content")
    if content:
        print(str(content).strip())
    print("=" * 80 + "\n")


def interactive_loop(
    rules: list[dict[str, Any]],
    client: Any,
    cache_dir: str | Path | None = None,
) -> None:
    """Interactive terminal loop for searching and viewing Sigma rules."""
    print(f"\nLoaded {len(rules)} rules. Ready for search!")
    print("Type 'exit' or 'quit' to end, or '--refresh' to update rules from API.")

    while True:
        try:
            query = input("\nEnter search query (or 'exit' to return to menu): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nReturning to Sigma Rules menu...")
            break

        if not query:
            continue

        if query.lower() in ("exit", "quit"):
            print("Returning to Sigma Rules menu...")
            break

        if query.lower() == "--refresh":
            try:
                rules = load_rules(client, refresh=True, cache_dir=cache_dir)
                print(f"Cache refreshed. Loaded {len(rules)} rules.")
            except (RecordedFutureError, ConfigurationError, RuntimeError) as exc:
                logger.warning("Failed to refresh Sigma rules: %s", exc)
                print(f"Warning: Failed to refresh rules: {exc}")
            continue

        matches = search_rules(rules, query)

        if not matches:
            print(f"No rules found matching '{query}'.")
            continue

        if len(matches) == 1:
            print("\nFound 1 match:")
            print_rule(matches[0])
            continue

        print(f"\nFound {len(matches)} matching rules:")
        display_limit = min(len(matches), 15)
        for idx in range(display_limit):
            r = matches[idx]
            print(f"  {idx + 1:2d}. {r.get('title')} ({r.get('file_name')})")

        if len(matches) > 15:
            print(f"  ... and {len(matches) - 15} more matches.")

        while True:
            try:
                choice = input(
                    f"\nSelect a number to view (1-{display_limit}), "
                    "or press Enter to search again (or 'exit' to return to menu): "
                ).strip()
            except (KeyboardInterrupt, EOFError):
                choice = ""

            if not choice:
                break

            if choice.lower() in ("exit", "quit"):
                print("Returning to Sigma Rules menu...")
                return

            try:
                num = int(choice)
                if 1 <= num <= display_limit:
                    print_rule(matches[num - 1])
                    break
                print(f"Please enter a number between 1 and {display_limit}.")
            except ValueError:
                print("Invalid input. Please enter a valid number or press Enter.")
