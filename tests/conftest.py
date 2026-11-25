"""Shared pytest isolation fixtures for unit and TUI tests."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

import soclens.settings as _settings


@pytest.fixture(autouse=True)
def _isolate_user_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Ensure unit and TUI tests never read or write a user's real settings file."""
    isolated_path = tmp_path / "soclens_cfg" / "settings.json"
    monkeypatch.setattr(_settings, "_DEFAULT_SETTINGS_PATH_OVERRIDE", isolated_path)
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(isolated_path))
    _settings.clear_session_overrides()
    _settings.invalidate_settings_cache()
    try:
        yield
    finally:
        _settings.clear_session_overrides()
        _settings.invalidate_settings_cache()
