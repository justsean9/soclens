"""Shared pytest isolation fixtures for unit and TUI tests."""

from __future__ import annotations

import asyncio
import contextlib
import unicodedata
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest
import textual._wait
import textual.app
import textual.constants
import textual.css.stylesheet
import textual.pilot
import textual.screen
from textual import events
from textual.app import REPLACED_KEYS, _character_to_key, _get_unicode_name_from_key
from textual.widgets import Button

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
    # Keep legacy RF-only unit/TUI/E2E tests deterministic and offline by default;
    # OSINT tests explicitly enable SOCLENS_OSINT_ENABLED or pass an OSINTClient.
    monkeypatch.setenv("SOCLENS_OSINT_ENABLED", "false")
    _settings.clear_session_overrides()
    _settings.invalidate_settings_cache()
    try:
        yield
    finally:
        _settings.clear_session_overrides()
        _settings.invalidate_settings_cache()


def _any_active_queue(app: Any) -> bool:
    if not getattr(app, "is_running", True):
        return False
    if not app._message_queue.empty() or app._pending_message is not None:
        return True
    try:
        screen = app.screen
    except Exception:
        return False
    if not screen._message_queue.empty() or screen._pending_message is not None:
        return True
    return any(
        not child._message_queue.empty() or child._pending_message is not None
        for child in screen.walk_children()
    )


async def _drain_queues_only(app: Any, max_ticks: int = 200) -> None:
    for _ in range(max_ticks):
        if not getattr(app, "is_running", True):
            break
        await asyncio.sleep(0)
        if getattr(app, "_tab_mount_events", None):
            continue
        if not _any_active_queue(app):
            await asyncio.sleep(0)
            if not _any_active_queue(app) and not getattr(app, "_tab_mount_events", None):
                break


async def _drain_app_fast(app: Any) -> None:
    for _ in range(10):
        await _drain_queues_only(app)
        if not getattr(app, "is_running", True):
            break
        if getattr(app, "_resize_timer", None) is not None:
            with contextlib.suppress(Exception):
                app._check_resize()
            await _drain_queues_only(app)
        try:
            screen = app.screen
        except Exception:
            break
        needs_timer = bool(
            screen._layout_required
            or screen._scroll_required
            or screen._repaint_required
            or screen._dirty_widgets
            or screen._recompose_required
            or screen._callbacks
        )
        if not needs_timer:
            break
        had_async = bool(screen._callbacks or screen._recompose_required)
        screen._on_timer_update()
        await _drain_queues_only(app)
        try:
            screen_after = app.screen
        except Exception:
            break
        if (
            not had_async
            and screen_after is screen
            and not screen_after._layout_required
            and not screen_after._scroll_required
            and not screen_after._recompose_required
            and not screen_after._callbacks
        ):
            break


_GLOBAL_CSS_PARSE_CACHE: dict[Any, list[Any]] = {}


@pytest.fixture(autouse=True)
def _fast_textual_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disable Textual animations and replace 20ms idle polling with deterministic drains."""
    orig_parse_rules = textual.css.stylesheet.Stylesheet._parse_rules
    orig_compositor_refresh = textual.screen.Screen._compositor_refresh

    def _cached_parse_rules(
        self: Any,
        css: str,
        read_from: Any,
        is_default_rules: bool = False,
        tie_breaker: int = 0,
        scope: str = "",
    ) -> list[Any]:
        var_key = tuple(
            sorted(
                (k, tuple((t.name, t.value) for t in v))
                for k, v in self._variable_tokens.items()
            )
        )
        gkey = (css, read_from, is_default_rules, tie_breaker, scope, var_key)
        cached = _GLOBAL_CSS_PARSE_CACHE.get(gkey)
        if cached is not None:
            return list(cached)
        rules = orig_parse_rules(
            self,
            css,
            read_from,
            is_default_rules=is_default_rules,
            tie_breaker=tie_breaker,
            scope=scope,
        )
        _GLOBAL_CSS_PARSE_CACHE[gkey] = list(rules)
        return rules

    def _fast_headless_compositor_refresh(self: Any) -> Any:
        app = self.app
        if app.is_headless and not app.is_inline and self is app.screen:
            self._dirty_widgets.clear()
            self._compositor._dirty_regions.clear()
            app._update_mouse_over(self)
            app.post_display_hook()
            return None
        return orig_compositor_refresh(self)

    async def _fast_pause(self: Any, delay: float | None = None) -> None:
        if delay is not None:
            await _drain_app_fast(self.app)
            await asyncio.sleep(delay)
        await _drain_app_fast(self.app)

    async def _fast_press_keys(self: Any, keys: Iterable[str]) -> None:
        driver = self._driver
        if driver is None:
            return
        for key in keys:
            if not self.is_running or self._driver is None:
                break
            if key.startswith("wait:"):
                _, wait_ms = key.split(":")
                await asyncio.sleep(float(wait_ms) / 1000)
                await self._animator.wait_until_complete()
            else:
                if len(key) == 1 and not key.isalnum():
                    key = _character_to_key(key)
                original_key = REPLACED_KEYS.get(key, key)
                char: str | None
                try:
                    char = unicodedata.lookup(_get_unicode_name_from_key(original_key))
                except KeyError:
                    char = key if len(key) == 1 else None
                key_event = events.Key(key, char)
                key_event.set_sender(self)
                driver.send_message(key_event)
                await _drain_queues_only(self)

    async def _fast_press(self: Any, *keys: str) -> None:
        if keys:
            await self._app._press_keys(keys)
            await _drain_app_fast(self._app)

    async def _fast_wait_for_idle(
        min_sleep: float = 0.0,
        max_sleep: float = 0.05,
    ) -> None:
        del min_sleep, max_sleep
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    monkeypatch.setattr(textual.constants, "TEXTUAL_ANIMATIONS", "none")
    monkeypatch.setattr(Button, "_start_active_affect", lambda _self: None)
    monkeypatch.setattr(
        textual.css.stylesheet.Stylesheet,
        "_parse_rules",
        _cached_parse_rules,
    )
    monkeypatch.setattr(
        textual.screen.Screen,
        "_compositor_refresh",
        _fast_headless_compositor_refresh,
    )
    monkeypatch.setattr(textual.pilot.Pilot, "pause", _fast_pause)
    monkeypatch.setattr(textual.pilot.Pilot, "press", _fast_press)
    monkeypatch.setattr(textual.app.App, "_press_keys", _fast_press_keys)
    monkeypatch.setattr(textual._wait, "wait_for_idle", _fast_wait_for_idle)
    monkeypatch.setattr(textual.pilot, "wait_for_idle", _fast_wait_for_idle)
    monkeypatch.setattr(textual.app, "wait_for_idle", _fast_wait_for_idle)
