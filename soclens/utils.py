"""Backward-compatible bundler utilities re-exported from ``soclens.bundler``."""

from __future__ import annotations

import logging

from soclens.bundler import (
    DEFAULT_BUNDLE_FILENAME,
    create_bundle,
    discover_runtime_dependencies,
)

logger = logging.getLogger("soclens.utils")

__all__ = [
    "DEFAULT_BUNDLE_FILENAME",
    "create_bundle",
    "discover_runtime_dependencies",
    "logger",
]
