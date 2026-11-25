"""Main Windows-compatible Textual Application for the SOCLens."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
import threading
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from rich.color import ColorSystem
from rich.console import RenderableType
from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import ModalScreen, Screen
from textual.theme import Theme
from textual.widgets import Button, Footer, Header, Select, Static, TabbedContent, TabPane

from soclens.alert_cache import (
    CACHE_SOURCE_ES,
    CACHE_SOURCE_RF,
    CACHE_SOURCE_S1,
    AlertCacheStore,
    get_alert_cache_refresh_seconds,
)
from soclens.client import RecordedFutureClient
from soclens.config import (
    IMAGE_VIEWER_OS,
    UI_VIEW_ADMIN,
    UI_VIEW_USER,
    PivotPayload,
    classify_site_tier,
    ensure_utf8_console,
    format_image_viewer_status,
    get_image_viewer_mode,
    get_rf_token,
    get_rf_verify_ssl,
    get_sentinelone_config,
    get_splunk_config,
    get_ui_view_mode,
    get_workspace_dir,
    has_explicit_image_viewer_setting,
    hydrate_secrets_from_store,
    normalize_image_viewer_mode,
    save_tui_settings,
    suppress_insecure_ssl_warnings,
)
from soclens.sentinelone import SentinelOneClient
from soclens.settings import (
    clear_session_overrides,
    clear_unlocked_keys,
    invalidate_settings_cache,
    is_settings_locked,
)
from soclens.tui.image_render import (
    get_recommended_image_viewer_mode,
    get_terminal_probe_result,
    is_truecolor_kitty_env,
)
from soclens.tui.logging_bridge import (
    AppLogStore,
    LogEntry,
    TuiLoggingBridge,
    classify_log_source,
    infer_print_level,
)
from soclens.tui.pivot import build_spl_from_pivot, format_copilot_context
from soclens.tui.screens import (
    BrandLogosPane,
    DashboardPane,
    LocalLLMPane,
    LogsPane,
    ResearchPane,
    RFIntelPane,
    SentinelOnePane,
    SettingsPane,
    SigmaPane,
    SplunkBundlePane,
    SplunkESPane,
    SplunkSearchPane,
    WatchlistsPane,
)
from soclens.tui.screens.base import BaseSocPane

USER_VIEW_TABS: tuple[str, ...] = (
    "tab-rf-intel",
    "tab-research",
    "tab-logs",
    "tab-sentinelone",
    "tab-llm",
    "tab-splunk-search",
    "tab-splunk-es",
    "tab-settings",
)
ADMIN_ONLY_TABS: tuple[str, ...] = (
    "tab-dashboard",
    "tab-watchlists",
    "tab-brand-logos",
    "tab-sigma",
    "tab-splunk-bundle",
)
ALL_TABS: tuple[str, ...] = (
    "tab-dashboard",
    "tab-watchlists",
    "tab-brand-logos",
    "tab-rf-intel",
    "tab-sigma",
    "tab-splunk-bundle",
    "tab-research",
    "tab-logs",
    "tab-sentinelone",
    "tab-llm",
    "tab-splunk-search",
    "tab-splunk-es",
    "tab-settings",
)
DEFAULT_USER_TAB = "tab-research"
DEFAULT_ADMIN_TAB = "tab-dashboard"
_VIEW_MODE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("User View", UI_VIEW_USER),
    ("Admin View", UI_VIEW_ADMIN),
)

_SOCLENS_THEME = Theme(
    name="soclens-dark",
    primary="#2f81f7",
    secondary="#38568a",
    accent="#58a6ff",
    foreground="#e6edf7",
    background="#0f131c",
    surface="#171d2b",
    panel="#1e273b",
    success="#2ea043",
    warning="#d29922",
    error="#f85149",
    dark=True,
)


class _SocTabbedContent(TabbedContent):
    """TabbedContent that ignores stale focus events from hidden panes."""

    def _on_tab_pane_focused(self, event: TabPane.Focused) -> None:
        if not event.tab_pane.display:
            event.prevent_default()
            event.stop()
            return
        super()._on_tab_pane_focused(event)


class _SocFooter(Footer):
    """Footer that skips redundant recomposition when visible bindings are unchanged."""

    _last_bindings_sig: tuple[tuple[str, str, str, bool, object], ...] | None = None

    def bindings_changed(self, screen: Screen[Any]) -> None:
        self._bindings_ready = True
        if not screen.app.app_focus:
            return
        if self.is_attached and screen is self.screen:
            sig = tuple(
                (
                    binding.key,
                    binding.action,
                    binding.description,
                    enabled,
                    binding.group,
                )
                for (_, binding, enabled, _tooltip) in screen.active_bindings.values()
                if binding.show
            )
            if self._last_bindings_sig == sig and len(self.children) > 0:
                return
            self._last_bindings_sig = sig
            self.call_after_refresh(self.recompose)


class SocLensApp(App[None]):
    """Cross-platform Textual TUI covering all SOCLens investigation workflows."""

    TITLE = "SOCLens"
    SUB_TITLE = "SOC Investigation Workbench"

    _TAB_SPECS: ClassVar[tuple[tuple[str, str, type[BaseSocPane]], ...]] = (
        ("tab-dashboard", "Dashboard & Diagnostics", DashboardPane),
        ("tab-watchlists", "Watchlists", WatchlistsPane),
        ("tab-brand-logos", "Brand Logos", BrandLogosPane),
        ("tab-rf-intel", "RF Intel & Alerts", RFIntelPane),
        ("tab-sigma", "Sigma Rules", SigmaPane),
        ("tab-splunk-bundle", "Splunk & Bundle", SplunkBundlePane),
        ("tab-research", "Research", ResearchPane),
        ("tab-logs", "Logs", LogsPane),
        ("tab-sentinelone", "SentinelOne", SentinelOnePane),
        ("tab-llm", "Local LLM", LocalLLMPane),
        ("tab-splunk-search", "Splunk Search", SplunkSearchPane),
        ("tab-splunk-es", "Splunk ES", SplunkESPane),
        ("tab-settings", "Settings", SettingsPane),
    )
    _TAB_PANE_CLASSES: ClassVar[dict[str, type[BaseSocPane]]] = {
        tab_id: pane_cls for tab_id, _title, pane_cls in _TAB_SPECS
    }

    CSS: ClassVar[str] = """
    Screen {
        layout: vertical;
        width: 100%;
        height: 100%;
        background: #0f131c;
        color: #e6edf7;
    }
    ModalScreen {
        background: rgba(15, 19, 28, 0.55);
    }
    ContextMenuModal {
        background: rgba(0, 0, 0, 0);
    }
    Header {
        background: #141a29;
        color: #f0f6ff;
    }
    Footer {
        background: #141a29;
        color: #b7c6e4;
    }
    #view-mode-bar {
        height: 1;
        width: 1fr;
        padding: 0 1;
        align-vertical: middle;
        background: #141b2a;
        border-bottom: none;
    }
    #view-mode-label {
        width: 1fr;
        height: 1;
        color: #c5d4f0;
        text-style: bold;
    }
    #view-mode-select {
        width: 18;
        height: 1;
        margin-left: 1;
    }
    #view-mode-toggle-btn {
        min-width: 17;
        height: 1;
        margin-left: 1;
    }
    TabbedContent {
        width: 1fr;
        height: 1fr;
        background: #0f131c;
    }
    TabbedContent > ContentSwitcher {
        width: 1fr;
        height: 1fr;
        background: #0f131c;
    }
    TabbedContent Tabs {
        background: #131926;
        border-bottom: none;
    }
    TabbedContent Tab {
        color: #93a7cb;
        background: #131926;
        padding: 0 2;
    }
    TabbedContent Tab:hover {
        color: #e6edf7;
        background: #1b2437;
    }
    TabbedContent Tab.-active {
        color: #ffffff;
        background: #1f2b44;
        text-style: bold;
    }
    TabbedContent Underline > .underline--bar {
        color: #388bfd;
        background: #1f2b44;
    }
    TabPane {
        width: 1fr;
        height: 1fr;
        padding: 0 1;
        background: #0f131c;
    }
    BaseSocPane {
        width: 1fr;
        height: 1fr;
        padding: 0;
        background: #0f131c;
    }
    .pane-title {
        height: 1;
        width: 1fr;
        text-style: bold;
        padding: 0 1;
        color: #f0f6ff;
        background: #1b2438;
        border-left: thick #388bfd;
    }
    .status-bar {
        height: auto;
        min-height: 1;
        width: 1fr;
        padding: 0 1;
        margin: 0;
        color: #dbe6fa;
        background: #131926;
        border-left: thick #58a6ff;
    }
    .info-box {
        height: auto;
        width: 1fr;
        padding: 0 1;
        margin: 0;
        color: #d6e2f8;
        background: #141b2a;
        border: round #2e3c5c;
    }
    .section-label {
        height: 1;
        width: 1fr;
        text-style: bold;
        color: #9ec5ff;
        padding: 0 1;
        background: #1a2234;
        margin-top: 0;
    }
    .action-row {
        height: auto;
        width: 1fr;
        margin: 0;
        padding: 0;
        align-vertical: middle;
    }
    .toolbar-row {
        background: #161c2a;
        padding: 0 1;
    }
    .filter-bar {
        background: #131926;
        padding: 0 1;
    }
    .action-row Input {
        width: 1fr;
        margin-right: 1;
    }
    .action-row Select {
        width: 24;
        margin-right: 1;
    }
    .action-row Button {
        min-width: 6;
        margin-right: 1;
    }
    .action-row Checkbox {
        width: auto;
        margin-right: 1;
    }
    Button.-textual-compact {
        background: #24304a;
        color: #eef4ff;
        text-style: bold;
        height: 1;
        border-left: outer #5f77ab !important;
        border-right: outer #5f77ab !important;
    }
    Button.-textual-compact:hover {
        background: #314266;
        color: #ffffff;
        border-left: outer #8cb4ff !important;
        border-right: outer #8cb4ff !important;
    }
    Button.-textual-compact:focus {
        background: #374a72;
        color: #ffffff;
        text-style: bold underline;
        border-left: outer #a5c8ff !important;
        border-right: outer #a5c8ff !important;
    }
    Button.-textual-compact.-primary {
        background: #1f6feb;
        color: #ffffff;
        border-left: outer #79c0ff !important;
        border-right: outer #79c0ff !important;
    }
    Button.-textual-compact.-primary:hover {
        background: #388bfd;
        color: #ffffff;
        border-left: outer #a5d6ff !important;
        border-right: outer #a5d6ff !important;
    }
    Button.-textual-compact.-success {
        background: #1f7a4c;
        color: #ffffff;
        border-left: outer #56d364 !important;
        border-right: outer #56d364 !important;
    }
    Button.-textual-compact.-success:hover {
        background: #2ea043;
        color: #ffffff;
    }
    Button.-textual-compact.-warning {
        background: #9e6a03;
        color: #ffffff;
        border-left: outer #f2cc60 !important;
        border-right: outer #f2cc60 !important;
    }
    Button.-textual-compact.-warning:hover {
        background: #bb8009;
        color: #ffffff;
    }
    Button.-textual-compact.-error {
        background: #b62324;
        color: #ffffff;
        border-left: outer #ff7b72 !important;
        border-right: outer #ff7b72 !important;
    }
    Button.-textual-compact.-error:hover {
        background: #da3633;
        color: #ffffff;
    }
    Button.-textual-compact:disabled {
        background: #151b28;
        color: #58647c;
        border-left: outer #283249 !important;
        border-right: outer #283249 !important;
    }
    Select.-textual-compact > SelectCurrent {
        background: #1d263a;
        color: #eef4ff;
        padding: 0 1;
        border-left: outer #556c9e !important;
        border-right: outer #556c9e !important;
    }
    Select.-textual-compact:hover > SelectCurrent {
        background: #25314b;
        border-left: outer #79c0ff !important;
        border-right: outer #79c0ff !important;
    }
    Select.-textual-compact:focus > SelectCurrent {
        background: #273450;
        color: #ffffff;
        border-left: outer #79c0ff !important;
        border-right: outer #79c0ff !important;
    }
    Select.-textual-compact > SelectOverlay {
        border: round #58a6ff;
        background: #161d2c;
        color: #eef4ff;
    }
    Input.-textual-compact {
        background: #0a0e16;
        color: #f2f6ff;
        padding: 0 1;
        height: 1;
        border-left: outer #44567c !important;
        border-right: outer #44567c !important;
    }
    Input.-textual-compact:focus {
        background: #0e1420;
        color: #ffffff;
        border-left: outer #58a6ff !important;
        border-right: outer #58a6ff !important;
    }
    .-compact-narrow Button.-textual-compact,
    .-compact-narrow Select.-textual-compact > SelectCurrent,
    .-compact-narrow Input.-textual-compact {
        border-left: none !important;
        border-right: none !important;
    }
    .-compact-narrow .toolbar-row,
    .-compact-narrow .filter-bar {
        padding: 0;
    }
    .-compact-narrow #dash-toolbar,
    .-compact-narrow #sigma-toolbar,
    .-compact-narrow #splunk-bundle-toolbar {
        layout: grid;
        grid-size: 3;
        grid-gutter: 0 1;
        height: auto;
        padding: 0;
    }
    .-compact-narrow #dash-toolbar Button,
    .-compact-narrow #sigma-toolbar Button,
    .-compact-narrow #sigma-toolbar Input,
    .-compact-narrow #sigma-toolbar Select,
    .-compact-narrow #splunk-bundle-toolbar Button,
    .-compact-narrow #splunk-bundle-toolbar Input,
    .-compact-narrow #splunk-bundle-toolbar Select,
    .-compact-narrow #splunk-bundle-toolbar Checkbox {
        width: 1fr;
        min-width: 6;
        height: 1;
        margin-right: 0;
    }
    .-compact-narrow #sigma-toolbar Select > SelectCurrent,
    .-compact-narrow #splunk-bundle-toolbar Select > SelectCurrent {
        height: 1;
    }
    Checkbox.-textual-compact {
        background: #182133;
        color: #e6edf7;
        padding: 0 1;
    }
    #wl-ent-type {
        width: 18;
    }
    #wl-entity-sort-select {
        width: 22;
    }
    #rf-limit-input {
        width: 6;
    }
    #rf-auto-enrich-btn {
        min-width: 21;
    }
    #rf-v2-type {
        width: 16;
    }
    #rf-preset-select {
        width: 1fr;
        min-width: 22;
    }
    #rf-priority-filter {
        width: 19;
    }
    #rf-timeframe-filter {
        width: 18;
    }
    #rf-assignee-filter {
        width: 20;
    }
    #rf-sort-select {
        width: 18;
    }
    #rf-time-field-select {
        width: 24;
    }
    #rf-date-from, #rf-date-to {
        width: 18;
    }
    #rf-rule-filter, #rf-entity-filter {
        width: 22;
    }
    #rf-pb-category {
        width: 30;
    }
    #rf-triage-context {
        width: 16;
    }
    #rf-view-select {
        width: 20;
    }
    #rf-lookup-bar {
        layout: vertical;
        width: 1fr;
        height: auto;
    }
    #rf-lookup-bar.lookup-inline {
        layout: horizontal;
    }
    #rf-lookup-bar.lookup-inline > #rf-ioc-row {
        width: 56%;
        margin-right: 1;
    }
    #rf-lookup-bar.lookup-inline > #rf-entity-row {
        width: 44%;
    }
    #sigma-days-input {
        width: 24;
    }
    #sigma-pipeline-select {
        width: 28;
    }
    #sigma-level-filter {
        width: 17;
    }
    #sigma-time-preset {
        width: 18;
    }
    #brand-interval, #brand-max-runs {
        width: 18;
    }
    #brand-list-select, #brand-source-list-select {
        width: 1fr;
    }
    #brand-list-id, #brand-source-list {
        width: 24;
    }
    #splunk-earliest, #splunk-latest {
        width: 12;
    }
    #splunk-search-spl {
        width: 1fr;
        height: 5;
        min-height: 4;
        margin: 0;
        background: #0a0e16;
        border: round #2e3c5c;
    }
    #splunk-search-spl:focus {
        border: round #58a6ff;
    }
    #splunk-search-preset {
        width: 23;
    }
    #splunk-search-earliest, #splunk-search-latest {
        width: 12;
    }
    #splunk-search-app {
        width: 24;
    }
    #splunk-search-limit {
        width: 10;
    }
    #splunk-search-filter-input {
        width: 1fr;
        min-width: 16;
    }
    #splunk-search-summary {
        width: auto;
        padding: 0 1;
        color: #dbe6fa;
    }
    .search-compact #splunk-search-status {
        height: 1;
        min-height: 1;
    }
    .search-compact #splunk-search-spl {
        height: 3;
        min-height: 3;
    }
    .search-compact #splunk-search-time-bar {
        layout: grid;
        grid-size: 5;
        grid-gutter: 0 1;
        height: 1;
        padding: 0;
    }
    .search-compact #splunk-search-time-bar Select,
    .search-compact #splunk-search-time-bar Input {
        width: 1fr;
        min-width: 6;
        height: 1;
        margin-right: 0;
    }
    .search-compact #splunk-search-time-bar Select > SelectCurrent {
        height: 1;
    }
    .search-compact #splunk-search-toolbar,
    .search-toolbar-compact #splunk-search-toolbar {
        layout: grid;
        grid-size: 4;
        grid-gutter: 0 1;
        height: auto;
        padding: 0;
    }
    .search-compact #splunk-search-toolbar Button,
    .search-toolbar-compact #splunk-search-toolbar Button {
        width: 1fr;
        min-width: 6;
        margin-right: 0;
    }
    .search-compact #splunk-search-workspace {
        min-height: 6;
    }
    .search-compact #splunk-search-master-pane {
        min-height: 4;
    }
    .search-compact #splunk-search-table {
        min-height: 3;
    }
    .search-compact #splunk-search-detail {
        min-height: 3;
    }
    .rf-compact #rf-status {
        height: 1;
        min-height: 1;
    }
    .rf-compact #rf-top-toolbar,
    .rf-compact #rf-filter-bar {
        layout: grid;
        grid-size: 3;
        grid-gutter: 0 1;
        height: auto;
        padding: 0;
    }
    .rf-compact #rf-top-toolbar Button,
    .rf-compact #rf-top-toolbar Input,
    .rf-compact #rf-top-toolbar Select,
    .rf-compact #rf-filter-bar Select,
    .rf-compact #rf-filter-bar Button {
        width: 1fr;
        min-width: 5;
        height: 1;
        margin-right: 0;
    }
    .rf-compact #rf-top-toolbar Select > SelectCurrent,
    .rf-compact #rf-filter-bar Select > SelectCurrent {
        height: 1;
    }
    .rf-compact #rf-detail-toolbar,
    .rf-detail-compact #rf-detail-toolbar {
        layout: grid;
        grid-size: 4;
        grid-gutter: 0 1;
        height: auto;
        padding: 0;
    }
    .rf-compact #rf-detail-toolbar #rf-detail-header,
    .rf-detail-compact #rf-detail-toolbar #rf-detail-header {
        width: 1fr;
        height: 1;
    }
    .rf-compact #rf-detail-toolbar Button,
    .rf-detail-compact #rf-detail-toolbar Button {
        width: 1fr;
        min-width: 5;
        height: 1;
        margin-left: 0;
    }
    .rf-compact #rf-workspace {
        min-height: 6;
    }
    .rf-compact #rf-results-pane,
    .rf-compact #rf-detail-pane {
        min-height: 3;
    }
    .rf-compact #rf-results-table,
    .rf-compact #rf-log {
        min-height: 2;
    }
    #splunk-bundle-time-preset {
        width: 23;
    }
    #es-view-select {
        width: 22;
    }
    #es-preset-select {
        width: 28;
    }
    #es-timeframe-select {
        width: 23;
    }
    #es-urgency-select, #es-status-select, #es-entity-kind-select {
        width: 21;
    }
    #es-collection-select {
        width: 22;
    }
    #es-earliest-input {
        width: 12;
    }
    #res-target-type {
        width: 20;
    }
    #res-source-mode {
        width: 18;
    }
    #res-source-group-filter {
        width: 19;
    }
    #res-timeframe-preset {
        width: 22;
    }
    #res-category-filter {
        width: 22;
    }
    #res-limit-input {
        width: 10;
    }
    #res-links-timeframe {
        width: 12;
    }
    #res-mood-strip {
        height: 4;
        width: 1fr;
        padding: 0 1;
        background: #101726;
    }
    #res-mood-art {
        width: 24;
        height: 4;
        content-align: left middle;
    }
    #res-mood-caption {
        width: 1fr;
        height: 4;
        padding-left: 1;
        content-align: left middle;
    }
    .-compact-narrow #res-toolbar {
        layout: grid;
        grid-size: 3;
        grid-gutter: 0 1;
        height: auto;
        padding: 0;
    }
    .-compact-narrow #res-toolbar Input,
    .-compact-narrow #res-toolbar Select,
    .-compact-narrow #res-toolbar Button {
        width: 1fr;
        min-width: 6;
        height: 1;
        margin-right: 0;
    }
    .-compact-narrow #res-toolbar Select > SelectCurrent {
        height: 1;
    }
    #logs-source-select {
        width: 19;
    }
    #logs-level-select {
        width: 17;
    }
    #logs-timeframe-select {
        width: 17;
    }
    #s1-view-select {
        width: 22;
    }
    #s1-preset-select {
        width: 28;
    }
    #s1-timeframe-select {
        width: 18;
    }
    #s1-status-select {
        width: 20;
    }
    #dash-error-timeframe {
        width: 16;
    }
    #llm-provider-select {
        width: 22;
    }
    #llm-model-select {
        width: 26;
    }
    #llm-template-select {
        width: 24;
    }
    Collapsible {
        width: 1fr;
        height: auto;
        border: none;
        border-left: thick #486399;
        padding: 0;
        margin: 0;
        background: #161d2c;
    }
    Collapsible > CollapsibleTitle {
        color: #a9c6ff;
        text-style: bold;
        padding: 0 1;
        background: #182133;
    }
    Collapsible > CollapsibleTitle:hover {
        color: #ffffff;
        background: #212d45;
    }
    Collapsible > Contents {
        padding: 0 1 0 1;
        width: 1fr;
        height: auto;
        background: #131926;
    }
    DataTable {
        width: 1fr;
        height: 1fr;
        min-height: 5;
        margin: 0;
        background: #0d111a;
        border: round #2e3c5c;
    }
    DataTable:focus {
        border: round #58a6ff;
    }
    DataTable > .datatable--header {
        background: #1c263b;
        color: #a8c7ff;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: #1f447a;
        color: #ffffff;
        text-style: bold;
    }
    DataTable > .datatable--hover {
        background: #1d3557;
        color: #f0f6ff;
    }
    Tooltip {
        background: #162033;
        color: #eef4ff;
        border: round #58a6ff;
        max-width: 110;
        padding: 0 1;
    }
    RichLog {
        width: 1fr;
        height: 1fr;
        min-height: 4;
        background: #0d111a;
        border: round #2e3c5c;
    }
    RichLog:focus {
        border: round #58a6ff;
    }
    RichLog.compact-log {
        height: 5;
        min-height: 3;
        max-height: 8;
    }
    RichLog.primary-log {
        height: 1fr;
        min-height: 10;
    }
    RichLog.detail-log {
        height: 1fr;
        min-height: 4;
    }
    .rf-summary-bar {
        height: 1;
        width: 1fr;
        padding: 0 1;
        background: #151c2b;
        color: #dbe6fa;
    }
    .detail-toolbar {
        height: 1;
        width: 1fr;
        align-vertical: middle;
        background: #182032;
        padding: 0 1;
    }
    .detail-toolbar > #rf-detail-header,
    .detail-toolbar > #wl-entities-header,
    .detail-toolbar > #res-detail-header,
    .detail-toolbar > #s1-detail-header,
    .detail-toolbar > #splunk-search-page-info,
    .detail-toolbar > #sigma-detail-header {
        width: 1fr;
        height: 1;
    }
    .detail-toolbar Button {
        min-width: 6;
        margin-left: 1;
    }
    .table-pane {
        width: 1fr;
        height: 1fr;
        min-height: 6;
    }
    .split-workspace {
        layout: vertical;
        width: 1fr;
        height: 1fr;
        min-height: 12;
    }
    .split-workspace.split-horizontal {
        layout: horizontal;
        min-height: 8;
    }
    .split-workspace.split-horizontal > #wl-lists-pane {
        width: 45%;
        height: 1fr;
        margin-right: 1;
    }
    .split-workspace.split-horizontal > #wl-entities-pane {
        width: 55%;
        height: 1fr;
    }
    .split-workspace.split-horizontal > #rf-results-pane {
        width: 48%;
        height: 1fr;
        margin-right: 1;
    }
    .split-workspace.split-horizontal > #rf-detail-pane {
        width: 52%;
        height: 1fr;
    }
    .split-workspace.split-horizontal > #brand-domains-pane {
        width: 42%;
        height: 1fr;
        margin-right: 1;
    }
    .split-workspace.split-horizontal > #brand-results-pane {
        width: 58%;
        height: 1fr;
    }
    .split-workspace.split-horizontal > #res-master-pane {
        width: 40%;
        height: 1fr;
        margin-right: 1;
    }
    .split-workspace.split-horizontal > #res-detail-pane {
        width: 60%;
        height: 1fr;
    }
    .split-workspace.split-horizontal > #s1-results-pane {
        width: 52%;
        height: 1fr;
        margin-right: 1;
    }
    .split-workspace.split-horizontal > #s1-detail-pane {
        width: 48%;
        height: 1fr;
    }
    .split-workspace.split-horizontal > #splunk-search-master-pane {
        width: 58%;
        height: 1fr;
        margin-right: 1;
    }
    .split-workspace.split-horizontal > #splunk-search-detail-pane {
        width: 42%;
        height: 1fr;
    }
    .split-workspace.split-horizontal > #es-master-pane {
        width: 58%;
        height: 1fr;
        margin-right: 1;
    }
    .split-workspace.split-horizontal > #es-detail-pane {
        width: 42%;
        height: 1fr;
    }
    .split-workspace.split-horizontal > #dash-errors-pane {
        width: 52%;
        height: 1fr;
        margin-right: 1;
    }
    .split-workspace.split-horizontal > #dash-apis-pane {
        width: 48%;
        height: 1fr;
    }
    .split-workspace > #settings-nav-pane {
        width: 1fr;
        height: auto;
        max-height: 10;
    }
    .split-workspace.split-horizontal > #settings-nav-pane {
        width: 26%;
        height: 1fr;
        max-height: 1fr;
        margin-right: 1;
    }
    .split-workspace.split-horizontal > #settings-form-pane {
        width: 74%;
        height: 1fr;
    }
    #settings-form-pane {
        width: 1fr;
        height: 1fr;
    }
    #settings-category-switcher {
        width: 1fr;
        height: 1fr;
    }
    #settings-category-list {
        width: 1fr;
        height: 1fr;
        background: #0d111a;
        border: round #2e3c5c;
    }
    .settings-cat-scroll {
        width: 1fr;
        height: 1fr;
        padding: 0 1 1 0;
    }
    .setting-label {
        height: 1;
        width: 1fr;
        text-style: bold;
        margin-top: 1;
        color: #c5d4f0;
    }
    .setting-field {
        width: 1fr;
        margin-bottom: 0;
    }
    #brand-domain-selection {
        width: 1fr;
        height: 1fr;
        min-height: 4;
        background: #0d111a;
        border: round #2e3c5c;
    }
    #dash-errors-table, #dash-apis-table {
        height: 1fr;
        min-height: 6;
    }
    #brand-table, #sigma-table, #splunk-results-table {
        height: 2fr;
        min-height: 7;
    }
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("1", "switch_tab('tab-dashboard')", "Dashboard"),
        Binding("2", "switch_tab('tab-watchlists')", "Watchlists"),
        Binding("3", "switch_tab('tab-brand-logos')", "Brand Logos"),
        Binding("4", "switch_tab('tab-rf-intel')", "RF Intel"),
        Binding("5", "switch_tab('tab-sigma')", "Sigma"),
        Binding("6", "switch_tab('tab-splunk-bundle')", "Splunk & Bundle"),
        Binding("7", "switch_tab('tab-research')", "Research"),
        Binding("8", "switch_tab('tab-logs')", "Logs"),
        Binding("9", "switch_tab('tab-sentinelone')", "SentinelOne"),
        Binding("0", "switch_tab('tab-settings')", "Settings"),
        Binding("f2", "toggle_admin_view", "Toggle Admin"),
        Binding("f7", "switch_tab('tab-llm')", "Local LLM"),
        Binding("f8", "switch_tab('tab-splunk-search')", "Splunk Search"),
        Binding("f9", "switch_tab('tab-splunk-es')", "Splunk ES"),
        Binding("f10", "open_settings", "Settings", show=False),
        Binding("slash", "toggle_watchlist_filter", "Search/Filter", show=False),
        Binding("escape", "collapse_watchlist_filter", "Close Filter", show=False),
        Binding("q", "quit", "Quit"),
        Binding("ctrl+q", "quit", "Quit"),
        Binding("f3", "choose_timezone", "Timezone"),
    ]

    def __init__(
        self,
        *,
        client: RecordedFutureClient | None = None,
        s1_client: SentinelOneClient | None = None,
        osint_client: Any = None,
        dry_run: bool = False,
        initial_tab: str | None = None,
        workspace_dir: Path | str | None = None,
        image_viewer: str | None = None,
        view_mode: str | None = None,
        no_secret_store: bool = False,
        preload_alerts: bool | None = None,
        alert_cache_refresh_seconds: int | None = None,
    ) -> None:
        ensure_utf8_console()
        super().__init__()
        if (
            not self.no_color
            and not self.is_headless
            and getattr(self.console, "_color_system", None) != ColorSystem.TRUECOLOR
            and (is_truecolor_kitty_env(os.environ) or get_terminal_probe_result() == "kitty")
        ):
            self.console._color_system = ColorSystem.TRUECOLOR
        self.register_theme(_SOCLENS_THEME)
        self.theme = _SOCLENS_THEME.name
        self._stop_event = threading.Event()
        self._shutting_down = False
        self._custom_client_injected = client is not None
        self._custom_s1_client_injected = s1_client is not None
        self._custom_osint_client_injected = osint_client is not None
        self._custom_workspace_injected = workspace_dir is not None
        self._ui_mounted = False
        self.client = (
            client if client is not None else RecordedFutureClient(stop_event=self._stop_event)
        )
        self.s1_client = s1_client
        self.osint_client = osint_client
        self.dry_run = dry_run
        self.no_secret_store: bool = bool(no_secret_store)
        if view_mode is not None:
            resolved_view = get_ui_view_mode(explicit=view_mode)
        elif initial_tab and initial_tab in ADMIN_ONLY_TABS:
            resolved_view = UI_VIEW_ADMIN
        else:
            resolved_view = get_ui_view_mode()
        self.view_mode: str = resolved_view

        if resolved_view == UI_VIEW_USER:
            if initial_tab and initial_tab in USER_VIEW_TABS:
                self.initial_tab = initial_tab
            else:
                self.initial_tab = DEFAULT_USER_TAB
        else:
            self.initial_tab = initial_tab or DEFAULT_ADMIN_TAB

        self._last_user_tab: str = (
            self.initial_tab if self.initial_tab in USER_VIEW_TABS else DEFAULT_USER_TAB
        )
        self._syncing_view_select: bool = False
        self.workspace_dir = get_workspace_dir(workspace_dir)
        self._has_explicit_image_viewer: bool = has_explicit_image_viewer_setting(
            image_viewer, workspace_dir=self.workspace_dir
        )
        self._image_viewer_mode: str = get_image_viewer_mode(
            image_viewer, workspace_dir=self.workspace_dir
        )
        self._blur_images: bool = True
        self.log_store = AppLogStore()
        self._pending_log_lock = threading.Lock()
        self._pending_log_entries: list[LogEntry] = []
        self._log_flush_scheduled = False
        self._thread_log_scopes = threading.local()
        self._scope_lock = threading.Lock()
        self._active_scopes: dict[str, int] = {}
        self._print_buf_lock = threading.Lock()
        self._print_buffers: dict[tuple[int, bool], str] = {}
        self._logging_bridge = TuiLoggingBridge(
            self.log_store,
            active_source_fn=self.active_log_source,
        )
        self.log_store.set_on_entry(self._on_store_entry)
        self._verify_ssl_override: bool | str | None = None
        self._mounted_tabs: set[str] = {self.initial_tab}
        self._tab_mount_events: dict[str, asyncio.Event] = {}
        self._pending_tab_callbacks: dict[str, list[Callable[[BaseSocPane], None]]] = {}
        self._preload_alerts_opt: bool | None = preload_alerts
        self._alert_cache_refresh_override: int | None = alert_cache_refresh_seconds
        self._preload_lock = threading.Lock()
        self._preload_running: bool = False
        self._alert_refresh_timer: Any = None
        self.alert_cache = AlertCacheStore(
            cache_dir=self.workspace_dir / ".soclens_cache" / "alerts"
        )
        self._update_subtitle()

    @property
    def is_admin_view(self) -> bool:
        """Return True when the TUI is currently in full Admin view."""
        return self.view_mode == UI_VIEW_ADMIN

    @property
    def visible_tab_ids(self) -> tuple[str, ...]:
        """Return the ordered tuple of tab IDs currently visible for the active view mode."""
        return ALL_TABS if self.is_admin_view else USER_VIEW_TABS

    def is_tab_visible(self, tab_id: str) -> bool:
        """Return True if ``tab_id`` is accessible in the active view mode."""
        return tab_id in self.visible_tab_ids

    def get_effective_verify_ssl(self) -> bool | str:
        """Return the active SSL verification mode for RF API and web requests."""
        client_verify = getattr(self.client, "verify_ssl", None)
        if isinstance(client_verify, (bool, str)):
            return client_verify
        if self._verify_ssl_override is not None:
            return self._verify_ssl_override
        return get_rf_verify_ssl()

    def _update_subtitle(self) -> None:
        view_text = "Admin View" if self.is_admin_view else "User View"
        parts: list[str] = [view_text]
        if self.dry_run:
            parts.append("DRY-RUN MODE (Read-Only)")
        if self.get_effective_verify_ssl() is False:
            parts.append("INSECURE SSL (Proxy Mode)")
        self.sub_title = " | ".join(parts)

    def _refresh_subtitle(self) -> None:
        self._update_subtitle()

    def set_insecure_ssl(self, insecure: bool) -> bool | str:
        """Toggle insecure SSL (proxy mode) for the active TUI session."""
        target: bool | str = False if insecure else True
        set_fn = getattr(self.client, "set_verify_ssl", None)
        if isinstance(self.client, RecordedFutureClient) and callable(set_fn):
            resolved = set_fn(target)
        else:
            if callable(set_fn):
                try:
                    set_fn(target)
                except Exception:
                    pass
            try:
                self.client.verify_ssl = target
                sess = getattr(self.client, "session", None)
                if sess is not None:
                    sess.verify = target
            except Exception:
                pass
            if target is False:
                suppress_insecure_ssl_warnings()
            resolved = target
        self._verify_ssl_override = resolved
        self._update_subtitle()
        return resolved

    @property
    def image_viewer_mode(self) -> str:
        """Return the configured default screenshot viewer mode (``'tui'`` or ``'os'``)."""
        return self._image_viewer_mode

    @property
    def open_images_in_os_viewer(self) -> bool:
        """Return True when screenshots open in the native OS viewer by default."""
        return self._image_viewer_mode == IMAGE_VIEWER_OS

    def set_image_viewer_mode(self, mode: str, *, persist: bool = True) -> str:
        """Validate, apply, and optionally persist the default TUI image viewer mode."""
        resolved = normalize_image_viewer_mode(mode)
        self._image_viewer_mode = resolved
        if persist:
            try:
                save_tui_settings({"image_viewer": resolved}, workspace_dir=self.workspace_dir)
            except OSError as exc:
                self.record_log(
                    f"Unable to save TUI image viewer setting: {exc}",
                    level="WARNING",
                    source="tui",
                    logger_name="SocLensApp",
                )
        try:
            self.query_one(DashboardPane).sync_image_viewer_state()
        except Exception:
            pass
        try:
            self.query_one(RFIntelPane).on_image_viewer_mode_changed()
        except Exception:
            pass
        try:
            from soclens.tui.modals import ScreenshotViewerModal

            if isinstance(self.screen, ScreenshotViewerModal):
                self.screen.sync_os_viewer_default_button()
        except Exception:
            pass
        self.record_log(
            f"Default image viewer set to {format_image_viewer_status(resolved)}.",
            source="tui",
            logger_name="SocLensApp",
        )
        return resolved

    def toggle_image_viewer_mode(self, *, persist: bool = True) -> str:
        """Toggle default screenshot opening between TUI modal and native OS viewer."""
        new_mode = "tui" if self.open_images_in_os_viewer else "os"
        resolved = self.set_image_viewer_mode(new_mode, persist=persist)
        label = format_image_viewer_status(resolved)
        self.notify(f"Default image viewer: {label}", title="Image Viewer Setting")
        return resolved

    @property
    def blur_images(self) -> bool:
        """Return True when screenshots are privacy-blurred by default."""
        return self._blur_images

    def set_blur_images(self, enabled: bool) -> bool:
        """Update global screenshot privacy blur state and sync active panes/modals."""
        self._blur_images = bool(enabled)
        try:
            self.query_one(RFIntelPane).on_image_blur_changed()
        except Exception:
            pass
        try:
            from soclens.tui.modals import ScreenshotViewerModal

            if isinstance(self.screen, ScreenshotViewerModal):
                self.screen.sync_blur_state()
        except Exception:
            pass
        self.record_log(
            f"Image privacy blur {'enabled' if self._blur_images else 'disabled'}.",
            source="tui",
            logger_name="SocLensApp",
        )
        return self._blur_images

    def toggle_blur_images(self) -> bool:
        """Toggle screenshot privacy blur on/off and notify the user."""
        new_state = self.set_blur_images(not self._blur_images)
        self.notify(
            "Image blur: ON (Protected)" if new_state else "Image blur: OFF (Full Clarity)",
            title="Image Privacy Blur",
        )
        return new_state

    @property
    def is_shutting_down(self) -> bool:
        """Return True once the application has begun exiting or unmounting."""
        return self._shutting_down

    def active_log_source(self) -> str | None:
        """Return the active thread-local or uniquely active worker log source."""
        stack = getattr(self._thread_log_scopes, "stack", None)
        if isinstance(stack, list) and stack:
            return str(stack[-1])
        with self._scope_lock:
            active_keys = [key for key, count in self._active_scopes.items() if count > 0]
        if len(active_keys) == 1:
            return active_keys[0]
        return None

    @contextlib.contextmanager
    def log_scope(self, source: str) -> Iterator[None]:
        """Context manager attributing stdout/stderr/warnings to ``source``."""
        clean_source = source.strip() or "tui"
        stack = getattr(self._thread_log_scopes, "stack", None)
        if not isinstance(stack, list):
            stack = []
            self._thread_log_scopes.stack = stack
        stack.append(clean_source)
        with self._scope_lock:
            self._active_scopes[clean_source] = self._active_scopes.get(clean_source, 0) + 1
        try:
            yield
        finally:
            if stack:
                stack.pop()
            with self._scope_lock:
                remaining = self._active_scopes.get(clean_source, 0) - 1
                if remaining > 0:
                    self._active_scopes[clean_source] = remaining
                else:
                    self._active_scopes.pop(clean_source, None)

    def record_log(
        self,
        message: str,
        *,
        level: str = "INFO",
        source: str = "tui",
        logger_name: str = "tui",
    ) -> None:
        """Record a structured entry into the centralized TUI log store."""
        text = str(message).rstrip()
        if not text:
            return
        self.log_store.append(
            LogEntry(
                timestamp=datetime.now().strftime("%H:%M:%S"),
                level=level,
                source=source or "tui",
                logger_name=logger_name or source or "tui",
                message=text,
            )
        )

    def _on_store_entry(self, entry: LogEntry) -> None:
        if self._shutting_down:
            return
        should_schedule = False
        with self._pending_log_lock:
            self._pending_log_entries.append(entry)
            if not self._log_flush_scheduled:
                self._log_flush_scheduled = True
                should_schedule = True

        app_tid = getattr(self, "_thread_id", None)
        if app_tid is not None and threading.get_ident() == app_tid:
            self._flush_pending_logs()
            return

        if should_schedule:
            loop = getattr(self, "_loop", None)
            if loop is not None and not loop.is_closed():
                try:
                    loop.call_soon_threadsafe(self._flush_pending_logs)
                except Exception:
                    with self._pending_log_lock:
                        self._log_flush_scheduled = False
            else:
                with self._pending_log_lock:
                    self._log_flush_scheduled = False

    def clear_pending_log_flush(self) -> None:
        """Drop queued incremental log flush entries after a full log view rebuild."""
        with self._pending_log_lock:
            self._pending_log_entries.clear()
            self._log_flush_scheduled = False

    def _flush_pending_logs(self) -> None:
        with self._pending_log_lock:
            batch = self._pending_log_entries
            self._pending_log_entries = []
            self._log_flush_scheduled = False
        if not batch or self._shutting_down:
            return
        logs_pane = self._get_mounted_pane("tab-logs")
        if isinstance(logs_pane, LogsPane):
            with contextlib.suppress(Exception):
                logs_pane.append_entries(batch)

    def _get_mounted_pane(self, tab_id: str) -> BaseSocPane | None:
        if not self._ui_mounted or not tab_id or tab_id in self._tab_mount_events:
            return None
        try:
            tab_pane = self.query_one(f"#{tab_id}", TabPane)
        except Exception:
            return None
        for child in tab_pane.children:
            if isinstance(child, BaseSocPane):
                return child
        return None

    async def ensure_tab_mounted(self, tab_id: str) -> BaseSocPane | None:
        """Lazily mount the pane widget for ``tab_id`` if it has not been mounted yet."""
        existing = self._get_mounted_pane(tab_id)
        if existing is not None:
            self._mounted_tabs.add(tab_id)
            return existing

        pane_cls = self._TAB_PANE_CLASSES.get(tab_id)
        if pane_cls is None or self._shutting_down or not self._ui_mounted:
            return None

        inflight = self._tab_mount_events.get(tab_id)
        if inflight is not None:
            await inflight.wait()
            return self._get_mounted_pane(tab_id)

        try:
            tab_pane = self.query_one(f"#{tab_id}", TabPane)
        except Exception:
            return None

        done_event = asyncio.Event()
        self._tab_mount_events[tab_id] = done_event
        try:
            pane = pane_cls()
            await tab_pane.mount(pane)
            for _ in range(10):
                if self._shutting_down or not pane.is_attached:
                    break
                pending_events = [
                    ev
                    for child in pane.walk_children(with_self=True)
                    if isinstance((ev := getattr(child, "_mounted_event", None)), asyncio.Event)
                    and not ev.is_set()
                    and not getattr(child, "_closing", False)
                    and not getattr(child, "_pruning", False)
                ]
                if not pending_events:
                    break
                tasks = [asyncio.create_task(ev.wait()) for ev in pending_events]
                _done, pending = await asyncio.wait(tasks, timeout=2.0)
                for task in pending:
                    task.cancel()
                if pending:
                    break
            self._mounted_tabs.add(tab_id)
            return pane
        finally:
            done_event.set()
            self._tab_mount_events.pop(tab_id, None)

    def set_timezone(self, tz_name: str) -> str:
        """Validate, apply, and broadcast a display timezone change across mounted panes."""
        from soclens.timezone import format_timezone_label, set_active_timezone

        canonical = set_active_timezone(tz_name)
        badge = format_timezone_label(canonical)
        for pane in self.query(BaseSocPane):
            try:
                pane.on_timezone_changed(canonical)
            except Exception:
                pass
        try:
            rf_pane = self.query_one(RFIntelPane)
            if rf_pane._active_mode != "welcome":
                sel = rf_pane._get_selected_item()
                preserve = str(sel.get("id") or "") if sel is not None else None
                rf_pane._render_view(preserve_id=preserve)
        except Exception:
            pass
        self.record_log(
            f"Display timezone changed to {canonical} ({badge}).",
            source="tui",
            logger_name="SocLensApp",
        )
        self.notify(f"Timezone set to {canonical} ({badge})", title="Timezone Updated")
        return canonical

    def action_choose_timezone(self) -> None:
        """Open the modal dialog to change the active display timezone."""
        from soclens.timezone import get_active_timezone
        from soclens.tui.modals import TimezoneModal

        def _on_close(selected: str | None) -> None:
            if selected:
                self.set_timezone(selected)

        self.push_screen(TimezoneModal(current_tz=get_active_timezone()), callback=_on_close)

    def open_logs_tab(self, *, source: str | None = None) -> None:
        """Switch to the dedicated Logs tab and optionally filter by ``source``."""

        def _apply(pane: BaseSocPane) -> None:
            if isinstance(pane, LogsPane) and source is not None:
                pane.set_source_filter(source)

        with contextlib.suppress(Exception):
            self.activate_tab(
                "tab-logs",
                on_ready=_apply if source is not None else None,
            )

    def open_llm_with_context(
        self,
        title: str,
        content: str,
        *,
        template: str = "freeform",
        auto_send: bool = False,
    ) -> None:
        """Switch to the Local LLM tab and pre-load ``content`` with the given template."""

        def _apply(pane: BaseSocPane) -> None:
            if isinstance(pane, LocalLLMPane):
                pane.analyze_context(
                    title,
                    content,
                    template=template,
                    auto_send=auto_send,
                )

        with contextlib.suppress(Exception):
            self.activate_tab("tab-llm", on_ready=_apply)

    def open_splunk_search(self, spl: str, *, auto_run: bool = False) -> None:
        """Switch to the Splunk Search tab and load an SPL query."""

        def _apply(pane: BaseSocPane) -> None:
            if isinstance(pane, SplunkSearchPane):
                pane.load_query(spl, auto_run=auto_run)

        with contextlib.suppress(Exception):
            self.activate_tab("tab-splunk-search", on_ready=_apply)

    def dispatch_pivot(self, payload: PivotPayload) -> bool:
        """Route a ``PivotPayload`` across workbenches, lazy-mounting the target tab if needed."""
        if not self._ui_mounted or self._shutting_down:
            return False
        if not isinstance(payload, PivotPayload):
            return False
        target_tab = str(payload.target_tab or "").strip()
        if target_tab not in ALL_TABS:
            return False

        effective_payload = payload
        clean_site_name = (payload.site_name or "").strip()
        clean_site_id = (payload.site_id or "").strip()
        if (clean_site_name or clean_site_id) and (not payload.tenant_id or not payload.tier):
            try:
                tier, tenant = classify_site_tier(
                    clean_site_name,
                    site_id=clean_site_id or None,
                )
                effective_payload = replace(
                    payload,
                    tenant_id=payload.tenant_id or tenant,
                    tier=payload.tier or (tier if clean_site_name else None),
                )
            except Exception:
                effective_payload = payload

        def _deliver(pane: BaseSocPane) -> None:
            try:
                accept_fn = getattr(pane, "accept_pivot", None)
                if callable(accept_fn):
                    accept_fn(effective_payload)
                elif target_tab == "tab-llm":
                    analyze_fn = getattr(pane, "analyze_context", None)
                    if callable(analyze_fn):
                        title, content = format_copilot_context(effective_payload)
                        analyze_fn(
                            title,
                            content,
                            template="triage_alert",
                            auto_send=False,
                        )
                elif target_tab == "tab-splunk-search":
                    load_fn = getattr(pane, "load_query", None)
                    if callable(load_fn):
                        spl, auto_run = build_spl_from_pivot(effective_payload)
                        load_fn(spl, auto_run=auto_run)
            except Exception as exc:
                self.record_log(
                    f"Pivot delivery to {target_tab} failed: {exc}",
                    level="ERROR",
                    source="tui",
                    logger_name="SocLensApp",
                )

        ok = self.activate_tab(target_tab, auto_enable_admin=False, on_ready=_deliver)
        if ok:
            self.record_log(
                f"Dispatched pivot {effective_payload.source_tab or '-'} -> {target_tab}",
                source="tui",
                logger_name="SocLensApp",
            )
        return ok

    def open_settings_tab(self, *, category: str | None = None) -> None:
        """Switch to the Settings & Credentials tab, optionally focusing a category."""

        def _focus_cat(pane: BaseSocPane) -> None:
            if category and isinstance(pane, SettingsPane):
                select_fn = getattr(pane, "select_category", None)
                if callable(select_fn):
                    select_fn(category)

        with contextlib.suppress(Exception):
            self.activate_tab(
                "tab-settings",
                on_ready=_focus_cat if category else None,
            )

    def action_open_settings(self) -> None:
        """Open the Settings tab unless a modal dialog is currently active."""
        if isinstance(self.screen, ModalScreen):
            return
        self.open_settings_tab()

    def reload_settings(self) -> None:
        """Invalidate settings cache, reload live clients, and notify all mounted panes."""
        invalidate_settings_cache()
        if isinstance(self.client, RecordedFutureClient):
            self.client.reload_from_config()
            self._verify_ssl_override = None
        if not self._custom_s1_client_injected:
            self.s1_client = None
        if not self._custom_workspace_injected:
            self.workspace_dir = get_workspace_dir()
        for attr in ("splunk_client", "splunk_es_client", "llm_client"):
            if hasattr(self, attr) and not getattr(self, f"_custom_{attr}_injected", False):
                setattr(self, attr, None)
        self._update_subtitle()
        for pane in self.query(BaseSocPane):
            try:
                pane.on_settings_updated()
            except Exception:
                pass

    def _focus_main_tabs(self) -> None:
        """Keep focus on the main tab bar rather than the top view-mode chrome."""
        with contextlib.suppress(Exception):
            self.query_one("#main-tabs", TabbedContent).query_one("ContentTabs").focus()

    def _sync_responsive_chrome(self) -> None:
        with contextlib.suppress(Exception):
            self.screen.set_class(self.size.width < 96, "-compact-narrow")

    def on_mount(self) -> None:
        """Install logging bridge and apply initial UI view mode once mounted."""
        self._ui_mounted = True
        self._logging_bridge.install(self)
        if not self._has_explicit_image_viewer and not self.is_headless:
            rec = get_recommended_image_viewer_mode(is_headless=False, app=self)
            if rec != self._image_viewer_mode:
                self._image_viewer_mode = rec
                with contextlib.suppress(Exception):
                    self.query_one(DashboardPane).sync_image_viewer_state()
                with contextlib.suppress(Exception):
                    self.query_one(RFIntelPane).on_image_viewer_mode_changed()
        with self.batch_update():
            self._apply_view_mode_to_ui()
            self._sync_responsive_chrome()
            self._focus_main_tabs()
        if is_settings_locked():
            self._prompt_settings_unlock()
        elif not self.no_secret_store:
            self._hydrate_secrets_worker()
        self._start_alert_preloader()

    def _should_preload_alerts(self) -> bool:
        """Return True when startup/periodic 24h alert preloading should run."""
        if self._preload_alerts_opt is not None:
            return bool(self._preload_alerts_opt)
        return not self.is_headless

    def _effective_alert_refresh_seconds(self) -> int:
        if self._alert_cache_refresh_override is not None:
            return max(0, int(self._alert_cache_refresh_override))
        return get_alert_cache_refresh_seconds()

    def _start_alert_preloader(self) -> None:
        if self._shutting_down or not self._should_preload_alerts():
            return
        self._preload_alerts_worker()
        interval = self._effective_alert_refresh_seconds()
        if interval > 0 and self._alert_refresh_timer is None:
            with contextlib.suppress(Exception):
                self._alert_refresh_timer = self.set_interval(
                    float(interval), self._on_alert_refresh_tick
                )

    def _on_alert_refresh_tick(self) -> None:
        if self._shutting_down or self._stop_event.is_set():
            return
        self._preload_alerts_worker()

    @work(thread=True, exit_on_error=False)
    def _preload_alerts_worker(self) -> None:
        """Preload and refresh last-24h RF Alerts, Splunk ES Notables, and S1 Alerts."""
        if self._stop_event.is_set() or self._shutting_down:
            return
        with self._preload_lock:
            if self._preload_running:
                return
            self._preload_running = True
        try:
            from concurrent.futures import ThreadPoolExecutor

            tasks: list[tuple[str, Callable[[], None]]] = [
                (CACHE_SOURCE_RF, self._preload_rf_alerts_24h),
                (CACHE_SOURCE_ES, self._preload_es_notables_24h),
                (CACHE_SOURCE_S1, self._preload_s1_threats_24h),
            ]
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix="soclens-preload") as pool:
                futures = [pool.submit(fn) for _, fn in tasks]
                for fut in futures:
                    with contextlib.suppress(Exception):
                        fut.result()
        finally:
            with self._preload_lock:
                self._preload_running = False

    def _preload_rf_alerts_24h(self) -> None:
        if self._stop_event.is_set() or self._shutting_down:
            return
        if not self._custom_client_injected and not get_rf_token(required=False):
            return
        try:
            from concurrent.futures import ThreadPoolExecutor

            from soclens.tui.filters import build_alerts_v3_triggered_param
            from soclens.tui.rf_formatters import extract_alerts_v3, normalize_alert_v3

            triggered = build_alerts_v3_triggered_param("last_24h")
            call_kw: dict[str, Any] = {"limit": 100}
            if triggered:
                call_kw["triggered"] = triggered
            data = self.client.search_alerts_v3(**call_kw)
            raw_items, total = extract_alerts_v3(data)
            normalized = [normalize_alert_v3(item) for item in raw_items]
            if self._stop_event.is_set() or self._shutting_down:
                return

            # Reuse any already-cached alert details while publishing the fresh list immediately
            existing_entry = self.alert_cache.get(CACHE_SOURCE_RF)
            existing_details: dict[str, dict[str, Any]] = {}
            if existing_entry is not None and isinstance(existing_entry.meta.get("details"), dict):
                existing_details = {
                    str(k): v
                    for k, v in existing_entry.meta["details"].items()
                    if isinstance(v, dict)
                }

            self.alert_cache.put(
                CACHE_SOURCE_RF,
                normalized,
                timeframe="last_24h",
                meta={"total": total, "details": existing_details},
            )
            self._notify_cache_updated(CACHE_SOURCE_RF, len(normalized))

            # Preload full Alert v3 details for all 24h alerts so clicking any row is instant
            get_detail_fn = getattr(self.client, "get_alert_v3", None)
            if not callable(get_detail_fn) or not normalized:
                return

            alert_ids = [
                str(item.get("id") or "").strip()
                for item in normalized
                if str(item.get("id") or "").strip()
            ]
            if not alert_ids:
                return

            details_by_id: dict[str, dict[str, Any]] = {
                aid: existing_details[aid] for aid in alert_ids if aid in existing_details
            }
            to_fetch = [aid for aid in alert_ids if aid not in details_by_id]

            def _fetch_one(aid: str) -> tuple[str, dict[str, Any] | None]:
                if self._stop_event.is_set() or self._shutting_down:
                    return aid, None
                try:
                    resp = get_detail_fn(aid)
                    if not isinstance(resp, dict):
                        return aid, None
                    detail = resp.get("data") if isinstance(resp.get("data"), dict) else resp
                    return (aid, detail) if isinstance(detail, dict) else (aid, None)
                except Exception:
                    return aid, None

            if to_fetch:
                with ThreadPoolExecutor(
                    max_workers=4, thread_name_prefix="soclens-rf-detail"
                ) as pool:
                    for aid, detail in pool.map(_fetch_one, to_fetch):
                        if self._stop_event.is_set() or self._shutting_down:
                            return
                        if detail is not None:
                            details_by_id[aid] = detail

            if not details_by_id or self._stop_event.is_set() or self._shutting_down:
                return

            detail_fields = (
                "assignee",
                "status",
                "priority",
                "note",
                "hits",
                "hits_count",
                "ai_insights",
                "primary_entity",
                "rule_name",
                "org_name",
                "portal_url",
                "status_date",
            )
            for item in normalized:
                aid = str(item.get("id") or "").strip()
                detail = details_by_id.get(aid)
                if detail is None:
                    continue
                norm = normalize_alert_v3(detail)
                for field in detail_fields:
                    val = norm.get(field)
                    if val not in ("", None, "-", [], 0) or not item.get(field):
                        item[field] = val
                if isinstance(norm.get("raw"), dict):
                    item["raw"] = norm["raw"]

            self.alert_cache.put(
                CACHE_SOURCE_RF,
                normalized,
                timeframe="last_24h",
                meta={"total": total, "details": details_by_id},
            )
            self._notify_cache_updated(CACHE_SOURCE_RF, len(normalized))
        except Exception as exc:
            self._log_preload_debug("RF alerts (24h)", exc)

    def _preload_es_notables_24h(self) -> None:
        if self._stop_event.is_set() or self._shutting_down:
            return
        custom_es = getattr(self, "splunk_es_client", None)
        if custom_es is None and not get_splunk_config(required=False).has_auth:
            return
        try:
            from soclens.splunk_es import SplunkESClient

            es_client = custom_es
            owns_client = False
            if es_client is None:
                cfg = get_splunk_config(required=True)
                es_client = SplunkESClient(
                    host=cfg.host,
                    token=cfg.token,
                    username=cfg.username,
                    password=cfg.password,
                    verify_ssl=cfg.verify_ssl,
                    stop_event=self._stop_event,
                )
                owns_client = True
            try:
                hybrid_fn = getattr(es_client, "query_findings_hybrid", None)
                notables: list[dict[str, Any]] = []
                backend = "spl_fallback"
                if callable(hybrid_fn):
                    res = hybrid_fn(earliest="-24h", item_type="all", limit=100)
                    if isinstance(res, dict) and isinstance(res.get("items"), list):
                        notables = list(res["items"])
                        backend = str(res.get("source_backend") or "mc_v2")
                if not notables and not callable(hybrid_fn):
                    notables = es_client.list_notables(earliest="-24h", limit=100)
                    backend = "spl_fallback"
            finally:
                if owns_client:
                    with contextlib.suppress(Exception):
                        es_client.close()

            if self._stop_event.is_set() or self._shutting_down:
                return
            self.alert_cache.put(
                CACHE_SOURCE_ES,
                notables,
                timeframe="last_24h",
                meta={"source_backend": backend},
            )
            self._notify_cache_updated(CACHE_SOURCE_ES, len(notables))
        except Exception as exc:
            self._log_preload_debug("Splunk ES notables (24h)", exc)

    def _preload_s1_threats_24h(self) -> None:
        if self._stop_event.is_set() or self._shutting_down:
            return
        if self.s1_client is None and not get_sentinelone_config(required=False).has_auth:
            return
        try:
            from soclens.tui.filters import compute_timeframe_bounds

            start_dt, end_dt = compute_timeframe_bounds("last_24h")
            created_after = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if start_dt else None
            created_before = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if end_dt else None

            s1 = self.s1_client
            owns_client = False
            if s1 is None:
                cfg = get_sentinelone_config(
                    verify_ssl=self.get_effective_verify_ssl(),
                    required=True,
                )
                s1 = SentinelOneClient(config=cfg, stop_event=self._stop_event)
                owns_client = True
            try:
                records = s1.list_threats(
                    created_after=created_after,
                    created_before=created_before,
                )
                sites: list[dict[str, Any]] = []
                with contextlib.suppress(Exception):
                    sites = s1.list_sites()
            finally:
                if owns_client:
                    with contextlib.suppress(Exception):
                        s1.close()

            if self._stop_event.is_set() or self._shutting_down:
                return
            self.alert_cache.put(
                CACHE_SOURCE_S1,
                records,
                timeframe="last_24h",
                meta={"sites": sites},
            )
            self._notify_cache_updated(CACHE_SOURCE_S1, len(records))
        except Exception as exc:
            self._log_preload_debug("SentinelOne alerts (24h)", exc)

    def _log_preload_debug(self, label: str, exc: Exception) -> None:
        if self._stop_event.is_set() or self._shutting_down:
            return
        with contextlib.suppress(Exception):
            self.record_log(
                f"Background preload skipped/failed for {label}: {exc}",
                level="DEBUG",
                source="cache",
                logger_name="AlertPreloader",
            )

    def _notify_cache_updated(self, source: str, count: int) -> None:
        if self._stop_event.is_set() or self._shutting_down:
            return
        with contextlib.suppress(Exception):
            self.record_log(
                f"Preloaded {count} cached record(s) for {source}.",
                level="INFO",
                source="cache",
                logger_name="AlertPreloader",
            )

        def _apply() -> None:
            if self._shutting_down:
                return
            tab_map = {
                CACHE_SOURCE_RF: "tab-rf-intel",
                CACHE_SOURCE_ES: "tab-splunk-es",
                CACHE_SOURCE_S1: "tab-sentinelone",
            }
            tab_id = tab_map.get(source)
            if not tab_id:
                return
            pane = self._get_mounted_pane(tab_id)
            hydrate_fn = getattr(pane, "hydrate_from_alert_cache", None)
            if callable(hydrate_fn):
                with contextlib.suppress(Exception):
                    hydrate_fn(force=False)

        with contextlib.suppress(Exception):
            self.call_from_thread(_apply)

    def _prompt_settings_unlock(self) -> None:
        """Open the master passphrase unlock dialog when settings.json is locked."""
        if self._shutting_down or not self.is_running:
            return
        from soclens.tui.modals import SettingsUnlockModal

        def _on_unlock_result(unlocked: bool | None) -> None:
            if self._shutting_down or not self.is_running:
                return
            if unlocked:
                self.reload_settings()
                self.record_log(
                    "Unlocked encrypted settings.json for active TUI session.",
                    source="settings",
                    logger_name="SocLensApp",
                )
                if not self.no_secret_store:
                    self._hydrate_secrets_worker()
            else:
                self.record_log(
                    "Continuing with locked settings.json (environment overrides only). "
                    "Open [0] Settings -> Profiles & Storage to unlock.",
                    level="WARNING",
                    source="settings",
                    logger_name="SocLensApp",
                )

        self.push_screen(SettingsUnlockModal(), callback=_on_unlock_result)

    @work(thread=True, exit_on_error=False)
    def _hydrate_secrets_worker(self) -> None:
        """Hydrate mapped vault secrets into memory in a background thread."""
        if self.no_secret_store or self._stop_event.is_set() or self.is_shutting_down:
            return
        try:
            hydrated = hydrate_secrets_from_store(
                force=False,
                overwrite_existing=False,
                stop_event=self._stop_event,
            )
        except Exception as exc:
            if self._stop_event.is_set() or self.is_shutting_down:
                return
            with contextlib.suppress(Exception):
                self.call_from_thread(
                    self._log_hydration_warning,
                    f"Startup secret hydration failed: {exc}",
                )
            return
        if not hydrated or self._stop_event.is_set() or self.is_shutting_down:
            return
        with contextlib.suppress(Exception):
            self.call_from_thread(self._apply_hydrated_secrets, hydrated)

    def _log_hydration_warning(self, message: str) -> None:
        """Log a non-fatal startup hydration warning on the UI thread."""
        if self._stop_event.is_set() or self.is_shutting_down:
            return
        self.record_log(
            message,
            level="WARNING",
            source="secrets",
            logger_name="SocLensApp",
        )

    def _apply_hydrated_secrets(self, hydrated: dict[str, str]) -> None:
        """Reload settings/clients after non-blocking vault secret hydration."""
        if self._stop_event.is_set() or self.is_shutting_down:
            return
        self.reload_settings()
        keys_summary = ", ".join(sorted(hydrated))
        self.record_log(
            f"Hydrated {len(hydrated)} secret(s) from vault into session memory: {keys_summary}.",
            source="secrets",
            logger_name="SocLensApp",
        )
        if self._should_preload_alerts():
            self._preload_alerts_worker()

    def on_resize(self) -> None:
        """Update narrow-viewport chrome classes when terminal dimensions change."""
        self._sync_responsive_chrome()

    def _print(self, text: str, stderr: bool = False) -> None:
        """Synchronously capture stdout/stderr prints under the caller's active log scope."""
        super()._print(text, stderr=stderr)
        if self._shutting_down or not text:
            return
        active_source = self.active_log_source()
        key = (threading.get_ident(), stderr)
        complete_lines: list[str]
        with self._print_buf_lock:
            buf = self._print_buffers.get(key, "") + text
            if "\n" in buf:
                parts = buf.split("\n")
                remainder = parts[-1]
                if remainder:
                    self._print_buffers[key] = remainder
                else:
                    self._print_buffers.pop(key, None)
                complete_lines = parts[:-1]
            else:
                self._print_buffers[key] = buf
                complete_lines = []

        if not complete_lines:
            return
        logger_name = "stderr" if stderr else "stdout"
        for raw_line in complete_lines:
            clean = raw_line.rstrip("\r")
            if not clean.strip():
                continue
            level = infer_print_level(clean, stderr=stderr)
            source = classify_log_source(
                logger_name,
                clean,
                default_source="system",
                active_source=active_source,
                brand_sync_active=(active_source == "brand_sync"),
            )
            self.record_log(
                clean,
                level=level,
                source=source,
                logger_name=logger_name,
            )

    def exit(
        self,
        result: None = None,
        return_code: int = 0,
        message: RenderableType | None = None,
    ) -> None:
        """Signal background workers to stop before exiting the application."""
        self._shutting_down = True
        self._stop_event.set()
        super().exit(result=result, return_code=return_code, message=message)

    def on_unmount(self) -> None:
        """Restore console logging handlers and ensure background API retries abort cleanly."""
        self._ui_mounted = False
        self._shutting_down = True
        self._stop_event.set()
        if self._alert_refresh_timer is not None:
            with contextlib.suppress(Exception):
                self._alert_refresh_timer.stop()
            self._alert_refresh_timer = None
        clear_session_overrides()
        clear_unlocked_keys(mark_locked=False)
        self._logging_bridge.uninstall()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="view-mode-bar"):
            yield Static("", id="view-mode-label", markup=False)
            yield Select(
                list(_VIEW_MODE_OPTIONS),
                allow_blank=False,
                value=self.view_mode,
                id="view-mode-select",
                compact=True,
            )
            yield Button("Admin: OFF [F2]", id="view-mode-toggle-btn", compact=True)
        with _SocTabbedContent(initial=self.initial_tab, id="main-tabs"):
            for tab_id, title, pane_cls in self._TAB_SPECS:
                with TabPane(title, id=tab_id):
                    if tab_id == self.initial_tab:
                        yield pane_cls()
        yield _SocFooter()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Hide and disable Admin-only tab keybindings while in User View."""
        if action == "switch_tab" and parameters:
            return self.is_tab_visible(str(parameters[0]))
        return True

    def _apply_view_mode_to_ui(self) -> None:
        tabs = self.query_one("#main-tabs", TabbedContent)
        if self.is_admin_view:
            for tab_id in ADMIN_ONLY_TABS:
                tabs.show_tab(tab_id)
        else:
            if tabs.active in ADMIN_ONLY_TABS:
                fallback = (
                    self._last_user_tab
                    if self._last_user_tab in USER_VIEW_TABS
                    else DEFAULT_USER_TAB
                )
                tabs.active = fallback
            for tab_id in ADMIN_ONLY_TABS:
                tabs.hide_tab(tab_id)

        label = self.query_one("#view-mode-label", Static)
        select = self.query_one("#view-mode-select", Select)
        toggle_btn = self.query_one("#view-mode-toggle-btn", Button)

        if self.is_admin_view:
            label.update(f"UI: Admin (All {len(ALL_TABS)} Tabs)")
            toggle_btn.label = "Admin: ON  [F2]"
            toggle_btn.variant = "warning"
        else:
            label.update(f"UI: User (Analyst View - {len(USER_VIEW_TABS)} Tabs)")
            toggle_btn.label = "Admin: OFF [F2]"
            toggle_btn.variant = "default"

        if str(select.value) != self.view_mode:
            self._syncing_view_select = True
            try:
                with select.prevent(Select.Changed):
                    select.value = self.view_mode
            finally:
                self._syncing_view_select = False

        self.refresh_bindings()

    def set_view_mode(self, mode: str) -> None:
        """Switch between ``user`` and ``admin`` UI views cleanly."""
        normalized = get_ui_view_mode(explicit=mode)
        if normalized == self.view_mode:
            return
        self.view_mode = normalized
        self._refresh_subtitle()
        if self._ui_mounted:
            self._apply_view_mode_to_ui()
            for pane in self.query(BaseSocPane):
                if isinstance(pane, SentinelOnePane):
                    with contextlib.suppress(Exception):
                        pane._sync_admin_badge()
                hook = getattr(pane, "on_view_mode_changed", None)
                if callable(hook):
                    with contextlib.suppress(Exception):
                        params = inspect.signature(hook).parameters
                        positional = [
                            p
                            for p in params.values()
                            if p.kind
                            in (
                                inspect.Parameter.POSITIONAL_ONLY,
                                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                            )
                        ]
                        has_varargs = any(
                            p.kind == inspect.Parameter.VAR_POSITIONAL
                            for p in params.values()
                        )
                        if positional or has_varargs:
                            hook(normalized)
                        else:
                            hook()
        self.record_log(
            f"Switched UI view to {normalized.upper()} mode.",
            source="tui",
            logger_name="SocLensApp",
        )

    def action_toggle_admin_view(self) -> None:
        """Toggle between User view (analyst tabs) and Admin view (all 13 tabs)."""
        target = UI_VIEW_USER if self.is_admin_view else UI_VIEW_ADMIN
        self.set_view_mode(target)

    def activate_tab(
        self,
        tab_id: str,
        *,
        auto_enable_admin: bool = False,
        on_ready: Callable[[BaseSocPane], None] | None = None,
    ) -> bool:
        """Activate ``tab_id`` if visible, optionally enabling Admin view when needed."""
        if tab_id not in ALL_TABS:
            return False
        if not self.is_tab_visible(tab_id):
            if auto_enable_admin:
                self.set_view_mode(UI_VIEW_ADMIN)
            else:
                self.notify(
                    "Enable Admin View (F2) to access this tab.",
                    title="Admin View Required",
                    severity="warning",
                )
                return False
        tabs = self.query_one("#main-tabs", TabbedContent)
        pane = self._get_mounted_pane(tab_id)
        already_active = tabs.active == tab_id
        if pane is not None:
            if not already_active:
                tabs.active = tab_id
            if on_ready is not None:
                try:
                    on_ready(pane)
                except Exception as exc:
                    self.record_log(
                        f"Tab activation callback failed for {tab_id}: {exc}",
                        level="ERROR",
                        source="tui",
                        logger_name="SocLensApp",
                    )
            return True

        if on_ready is not None:
            self._pending_tab_callbacks.setdefault(tab_id, []).append(on_ready)
        if not already_active:
            tabs.active = tab_id
        else:
            async def _mount_and_dispatch() -> None:
                mounted = await self.ensure_tab_mounted(tab_id)
                if mounted is None:
                    self._pending_tab_callbacks.pop(tab_id, None)
                    return
                mounted.on_tab_activated()
                callbacks = self._pending_tab_callbacks.pop(tab_id, [])
                for cb in callbacks:
                    try:
                        cb(mounted)
                    except Exception as exc:
                        self.record_log(
                            f"Tab activation callback failed for {tab_id}: {exc}",
                            level="ERROR",
                            source="tui",
                            logger_name="SocLensApp",
                        )

            self.run_worker(_mount_and_dispatch(), exclusive=False)
        return True

    @on(Button.Pressed, "#view-mode-toggle-btn")
    def handle_view_mode_toggle_pressed(self) -> None:
        self.action_toggle_admin_view()
        self._focus_main_tabs()

    @on(Select.Changed, "#view-mode-select")
    def handle_view_mode_select_changed(self, event: Select.Changed) -> None:
        if self._syncing_view_select:
            return
        if isinstance(event.value, str) and event.value.strip():
            new_mode = event.value.strip().lower()
            if new_mode == self.view_mode:
                return
            self.set_view_mode(new_mode)
            self._focus_main_tabs()

    @on(TabbedContent.TabActivated, "#main-tabs")
    async def handle_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        """Lazily mount the activated pane, notify it, and invoke pending callbacks."""
        if event.pane is None:
            return
        tab_id = str(event.pane.id or "")
        if tab_id in USER_VIEW_TABS:
            self._last_user_tab = tab_id
        pane = await self.ensure_tab_mounted(tab_id)
        if pane is None:
            self._pending_tab_callbacks.pop(tab_id, None)
            return
        pane.on_tab_activated()
        callbacks = self._pending_tab_callbacks.pop(tab_id, [])
        for cb in callbacks:
            try:
                cb(pane)
            except Exception as exc:
                self.record_log(
                    f"Tab activation callback failed for {tab_id}: {exc}",
                    level="ERROR",
                    source="tui",
                    logger_name="SocLensApp",
                )

    def action_switch_tab(self, tab_id: str) -> None:
        """Activate a top-level workflow tab by ID when accessible in the active view."""
        if not self.is_tab_visible(tab_id):
            return
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = tab_id

    def action_toggle_watchlist_filter(self) -> None:
        """Toggle search/filter drawer when Watchlists, RF Intel, Research, or Logs tab is active."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        pane = self._get_mounted_pane(str(tabs.active or ""))
        if isinstance(pane, (WatchlistsPane, RFIntelPane, ResearchPane, LogsPane)):
            pane.action_toggle_filter()

    def action_collapse_watchlist_filter(self) -> None:
        """Collapse search/filter drawer when Watchlists, RF Intel, Research, or Logs tab is active."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        pane = self._get_mounted_pane(str(tabs.active or ""))
        if isinstance(pane, (WatchlistsPane, RFIntelPane, ResearchPane, LogsPane)):
            pane.action_collapse_filter()

    def on_key(self, event: events.Key) -> None:
        """Forward printable keys on Watchlists and Research tabs when focus is outside the pane."""
        if isinstance(self.screen, ModalScreen):
            return
        try:
            focused = self.focused
            if focused is not None:
                try:
                    view_bar = self.query_one("#view-mode-bar", Horizontal)
                except Exception:
                    view_bar = None
                if (
                    isinstance(focused, Select)
                    or any(isinstance(anc, Select) for anc in focused.ancestors)
                    or (
                        view_bar is not None
                        and (focused is view_bar or view_bar in focused.ancestors)
                    )
                ):
                    return
            tabs = self.query_one("#main-tabs", TabbedContent)
            active = tabs.active
            if active == "tab-watchlists":
                wl_pane = self.query_one(WatchlistsPane)
                if focused is None or (focused is not wl_pane and wl_pane not in focused.ancestors):
                    wl_pane.handle_type_to_filter_key(event)
            elif active == "tab-research":
                res_pane = self.query_one(ResearchPane)
                if focused is None or (focused is not res_pane and res_pane not in focused.ancestors):
                    res_pane.handle_type_to_search_key(event)
        except Exception:
            return


def create_app(
    *,
    client: RecordedFutureClient | None = None,
    s1_client: SentinelOneClient | None = None,
    osint_client: Any = None,
    dry_run: bool = False,
    initial_tab: str | None = None,
    workspace_dir: Path | str | None = None,
    image_viewer: str | None = None,
    view_mode: str | None = None,
    no_secret_store: bool = False,
    preload_alerts: bool | None = None,
    alert_cache_refresh_seconds: int | None = None,
) -> SocLensApp:
    """Factory returning a configured ``SocLensApp`` instance."""
    return SocLensApp(
        client=client,
        s1_client=s1_client,
        osint_client=osint_client,
        dry_run=dry_run,
        initial_tab=initial_tab,
        workspace_dir=workspace_dir,
        image_viewer=image_viewer,
        view_mode=view_mode,
        no_secret_store=no_secret_store,
        preload_alerts=preload_alerts,
        alert_cache_refresh_seconds=alert_cache_refresh_seconds,
    )


build_app = create_app
