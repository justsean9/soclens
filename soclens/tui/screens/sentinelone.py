"""SentinelOne Management API v2.1 multi-site SOC & tenant admin workbench pane."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.dom import DOMNode
from textual.widget import Widget
from textual.widgets import (
    Button,
    Collapsible,
    DataTable,
    Input,
    RichLog,
    Select,
    SelectionList,
    Static,
)

from soclens.alert_cache import CACHE_SOURCE_S1
from soclens.config import (
    S1TierConfig,
    get_s1_tier_config,
    get_sentinelone_config,
)
from soclens.sentinelone import (
    SentinelOneAuthError,
    SentinelOneClient,
    SentinelOneError,
    SentinelOneRateLimitError,
    _sanitize_scope_roles,
    sort_s1_records_newest_first,
)
from soclens.tui.filters import (
    S1_PRESETS_BY_VIEW,
    TIMEFRAME_OPTIONS,
    compute_timeframe_bounds,
    timeframe_label,
    timestamp_matches_timeframe,
)
from soclens.tui.modals import (
    S1AddBlocklistModal,
    S1CreateExclusionModal,
    S1ThreatTriageModal,
)
from soclens.tui.pivot import PivotPayload, emit_pivot
from soclens.tui.s1_formatters import (
    render_raw_json,
    render_s1_record_detail,
    summarize_mitigation_status,
)
from soclens.tui.screens.base import (
    BaseSocPane,
    DoubleClickDataTable,
    SelectableRichLog,
    extract_richlog_text,
)
from soclens.tui.screens.s1_modals import (
    CloneExclusionsModal,
    ConfirmDeleteSiteModal,
    S1EditExclusionModal,
    S1MoveAgentModal,
    S1SiteModal,
    S1SitePolicyModal,
    S1UserModal,
)

_VIEW_OPTIONS: list[tuple[str, str]] = [
    ("Endpoints", "endpoints"),
    ("Threats & Alerts", "threats"),
    ("Sites Admin", "sites_activities"),
    ("Users & RBAC", "users_rbac"),
    ("Exclusions & Clone", "exclusions"),
    ("Blocklist", "blocklist"),
]

_ALERT_SOURCE_OPTIONS: list[tuple[str, str]] = [
    ("Endpoint Threats", "threats"),
    ("Cloud / STAR Alerts", "cloud"),
    ("Unified Threats + Cloud", "unified"),
]

_GROUPING_OPTIONS: list[tuple[str, str]] = [
    ("Flat Alert Stream", "flat"),
    ("Service Tier", "tier"),
    ("Site", "site"),
    ("Tier + File Hash (SHA1)", "tier_hash"),
]

_USERS_MODE_OPTIONS: list[tuple[str, str]] = [
    ("Console Users", "console"),
    ("Service Users", "service"),
    ("RBAC Roles", "roles"),
]

_S1_THREAT_STATUS_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Status: Any", "any"),
    ("Unresolved", "unresolved"),
    ("In Progress", "in_progress"),
    ("Resolved", "resolved"),
    ("True Positive", "true_positive"),
    ("False Positive", "false_positive"),
    ("Suspicious", "suspicious"),
    ("Undefined Verdict", "undefined"),
)

_S1_ENDPOINT_STATUS_OPTIONS: tuple[tuple[str, str], ...] = (
    ("State: Any", "any"),
    ("Infected", "infected"),
    ("Disconnected / Isolated", "disconnected"),
    ("Connected Healthy", "connected"),
    ("Healthy (Not Infected)", "healthy"),
)

_TABLE_SPECS: dict[str, tuple[tuple[str, str, float, int], ...]] = {
    "endpoints": (
        ("name", "Hostname", 0.22, 12),
        ("tier", "Tier", 0.10, 6),
        ("os", "OS", 0.12, 8),
        ("ip", "IP Address", 0.14, 10),
        ("network", "Network", 0.12, 8),
        ("infected", "Infected", 0.08, 6),
        ("site", "Site", 0.22, 10),
    ),
    "threats": (
        ("name", "Threat / Group", 0.26, 14),
        ("tier", "Tier", 0.08, 6),
        ("host", "Endpoint / Site", 0.18, 10),
        ("verdict", "Verdict", 0.14, 8),
        ("status", "Status", 0.12, 8),
        ("mitigation", "Mitigation", 0.12, 8),
        ("created", "Created", 0.10, 8),
    ),
    "exclusions": (
        ("type", "Type", 0.12, 8),
        ("os", "OS", 0.10, 7),
        ("scope", "Scope", 0.12, 8),
        ("value", "Value", 0.30, 14),
        ("mode", "Mode", 0.16, 10),
        ("desc", "Description", 0.20, 12),
    ),
    "blocklist": (
        ("sha1", "SHA-1 Hash", 0.42, 18),
        ("os", "OS", 0.12, 8),
        ("source", "Source", 0.16, 10),
        ("desc", "Description", 0.30, 12),
    ),
    "sites_activities": (
        ("kind", "Kind", 0.12, 7),
        ("tier", "Tier", 0.10, 6),
        ("name", "Name / Description", 0.38, 14),
        ("scope", "State / Scope", 0.20, 10),
        ("updated", "Timestamp", 0.20, 10),
    ),
    "users_rbac": (
        ("kind", "Kind", 0.14, 8),
        ("name", "Name / Role", 0.26, 12),
        ("email", "Email / Description", 0.28, 12),
        ("scope", "Scope", 0.14, 8),
        ("status", "2FA / Predefined", 0.18, 10),
    ),
}

_SPLIT_HORIZONTAL_MIN_WIDTH = 120


def _truncate(text: Any, max_len: int = 48) -> str:
    s = str(text or "").strip()
    if len(s) <= max_len:
        return s
    return s[: max(1, max_len - 3)] + "..."


class SentinelOnePane(BaseSocPane):
    """SentinelOne multi-site tier workbench and tenant administration pane."""

    STATUS_ID = "s1-status"
    LOG_ID = ""
    LOG_SOURCE = "sentinelone"

    DEFAULT_CSS: ClassVar[str] = """
    SentinelOnePane {
        height: 1fr;
    }
    #s1-workbench-bar, #s1-tier-bar {
        height: 1;
        width: 1fr;
        margin-bottom: 0;
    }
    #s1-workbench-bar Button, #s1-tier-bar Button {
        min-width: 6;
        margin-right: 1;
    }
    #s1-admin-badge {
        width: 1fr;
        height: 1;
        text-align: right;
        padding: 0 1;
        color: $warning;
    }
    #s1-scope-collapsible {
        height: auto;
        margin: 0;
    }
    #s1-site-multiselect {
        height: 5;
        min-height: 3;
        max-height: 7;
        border: round #2e3c5c;
        background: #0d111a;
    }
    #s1-grouping-select {
        width: 22;
    }
    #s1-alert-source-select {
        width: 22;
    }
    #s1-users-mode-select {
        width: 18;
    }
    #s1-filter-bar,
    #s1-actions-endpoints,
    #s1-actions-threats,
    #s1-actions-sites,
    #s1-actions-users {
        height: auto;
        width: 1fr;
    }
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._current_view: str = "threats"
        self._sites_submode: str = "sites"
        self._users_submode: str = "console"
        self._alert_source: str = "threats"
        self._grouping_mode: str = "flat"
        self._tier_filter: str = "MDR"
        self._records: list[dict[str, Any]] = []
        self._filtered_records: list[dict[str, Any]] = []
        self._table_rows: list[dict[str, Any]] = []
        self._selected_record: dict[str, Any] | None = None
        self._cached_sites: list[dict[str, Any]] = []
        self._cached_roles: list[dict[str, Any]] = []
        self._selected_site_ids: set[str] = set()
        self._expanded_groups: set[str] = set()
        self._table_ready: bool = False
        self._s1_client: SentinelOneClient | None = None
        self._active_preset_id: str = "all"
        self._timeframe_filter: str = "last_24h"
        self._loaded_timeframe_filter: str | None = None
        self._status_filter: str = "any"
        self._syncing_s1_filters: bool = False
        self._load_seq: int = 0
        self._detail_mode: str = "overview"
        self._hydrated_from_cache: bool = False

    def _get_s1_client(self) -> SentinelOneClient:
        """Return an injected or freshly configured ``SentinelOneClient``."""
        app_s1 = getattr(self.app, "s1_client", None)
        if app_s1 is not None:
            return app_s1  # type: ignore[no-any-return]
        if self._s1_client is not None:
            return self._s1_client
        stop_event = getattr(self.app, "_stop_event", None)
        verify_ssl_fn = getattr(self.app, "get_effective_verify_ssl", None)
        verify_ssl = verify_ssl_fn() if callable(verify_ssl_fn) else None
        cfg = get_sentinelone_config(verify_ssl=verify_ssl, required=True)
        return SentinelOneClient(config=cfg, stop_event=stop_event)

    def _get_tier_config(self) -> S1TierConfig:
        try:
            return get_s1_tier_config()
        except Exception:
            return S1TierConfig()

    def _is_admin_view(self) -> bool:
        return bool(getattr(self.app, "is_admin_view", False))

    def _sync_admin_badge(self) -> None:
        try:
            badge = self.query_one("#s1-admin-badge", Static)
            if self._is_admin_view():
                badge.update("Admin View: ON [F2]")
            else:
                badge.update("User View (Read-Only Admin) [F2]")
        except Exception:
            pass

    def _require_admin_view(self, action_name: str) -> bool:
        self._sync_admin_badge()
        if self._is_admin_view():
            return True
        msg = (
            f"Admin View (F2) is required for '{action_name}'. "
            "Currently in read-only User View."
        )
        self.set_status(msg)
        self.append_log(msg, level="WARNING")
        self.notify_user(msg, title="Admin View Required (F2)", severity="warning")
        return False

    def compose(self) -> ComposeResult:
        yield Static(
            "SentinelOne Multi-Site EDR & Tenant Admin Workbench (v2.1)",
            classes="pane-title",
            markup=False,
        )
        yield Static(
            "Select a sub-workbench and click Refresh or Check Connection.",
            id="s1-status",
            classes="status-bar",
            markup=False,
        )

        with Horizontal(id="s1-workbench-bar", classes="action-row filter-bar"):
            yield Button(
                "1: Alerts",
                id="s1-wb-alerts-btn",
                variant="primary",
                compact=True,
            )
            yield Button("2: Sites", id="s1-wb-sites-btn", compact=True)
            yield Button("3: Users", id="s1-wb-users-btn", compact=True)
            yield Button("4: Exclusions", id="s1-wb-exclusions-btn", compact=True)
            yield Button("5: Agents", id="s1-wb-agents-btn", compact=True)

        with Horizontal(classes="action-row toolbar-row"):
            yield Select(
                _VIEW_OPTIONS,
                allow_blank=False,
                value="threats",
                id="s1-view-select",
                compact=True,
            )
            yield Input(
                value="",
                placeholder="Filter hostname, threat, site, hash, or description...",
                id="s1-filter-input",
                compact=True,
            )
            yield Button("Refresh", id="s1-refresh-btn", variant="primary", compact=True)
            yield Button("Check Connection", id="s1-check-btn", compact=True)

        with Horizontal(id="s1-tier-bar", classes="action-row filter-bar"):
            yield Button("All Tiers", id="s1-tier-all-btn", compact=True)
            yield Button("MDR", id="s1-tier-mdr-btn", variant="primary", compact=True)
            yield Button("MSSP", id="s1-tier-mssp-btn", compact=True)
            yield Button("Other", id="s1-tier-other-btn", compact=True)
            yield Static(
                "User View (Read-Only Admin) [F2]",
                id="s1-admin-badge",
                markup=False,
            )

        with Collapsible(
            title="Multi-Site Scope Selector (0 selected)",
            collapsed=True,
            id="s1-scope-collapsible",
        ):
            with Horizontal(classes="action-row toolbar-row"):
                yield Input(
                    value="",
                    placeholder="Filter sites by name, tier, or ID...",
                    id="s1-site-search-input",
                    compact=True,
                )
                yield Button("Load Sites", id="s1-site-load-btn", compact=True)
                yield Button("Select All", id="s1-site-select-all-btn", compact=True)
                yield Button("Clear Scope", id="s1-site-clear-btn", compact=True)
            yield SelectionList(id="s1-site-multiselect")

        with Vertical(id="s1-filter-bar"):
            with Horizontal(classes="action-row filter-bar"):
                yield Select(
                    [("View: Alerts (Last 24h)", "all")],
                    allow_blank=False,
                    value="all",
                    id="s1-preset-select",
                    compact=True,
                )
                yield Select(
                    list(TIMEFRAME_OPTIONS),
                    allow_blank=False,
                    value="last_24h",
                    id="s1-timeframe-select",
                    compact=True,
                )
                yield Select(
                    list(_S1_THREAT_STATUS_OPTIONS),
                    allow_blank=False,
                    value="any",
                    id="s1-status-select",
                    compact=True,
                )
                yield Button("Reset", id="s1-clear-filter-btn", compact=True)
            with Horizontal(id="s1-filter-bar-alerts", classes="action-row filter-bar"):
                yield Select(
                    _ALERT_SOURCE_OPTIONS,
                    allow_blank=False,
                    value="threats",
                    id="s1-alert-source-select",
                    compact=True,
                )
                yield Select(
                    _GROUPING_OPTIONS,
                    allow_blank=False,
                    value="flat",
                    id="s1-grouping-select",
                    compact=True,
                )

        # Contextual action bars (toggled per active view)
        with Vertical(id="s1-actions-endpoints"):
            with Horizontal(classes="action-row toolbar-row"):
                yield Button("Isolate", id="s1-isolate-btn", variant="error", compact=True)
                yield Button("Reconnect", id="s1-reconnect-btn", variant="warning", compact=True)
                yield Button("Full Scan", id="s1-scan-btn", compact=True)
                yield Button("Reboot", id="s1-reboot-btn", variant="warning", compact=True)
                yield Button("Uninstall", id="s1-uninstall-btn", variant="error", compact=True)
            with Horizontal(classes="action-row toolbar-row"):
                yield Button("Fetch Logs", id="s1-fetch-logs-btn", compact=True)
                yield Button("Move Site", id="s1-move-agent-btn", variant="warning", compact=True)
                yield Button("Decommission", id="s1-decommission-btn", variant="error", compact=True)
                yield Button("Blocklist", id="s1-goto-blocklist-btn", compact=True)

        with Vertical(id="s1-actions-threats"):
            with Horizontal(classes="action-row toolbar-row"):
                yield Button("Triage", id="s1-triage-btn", variant="primary", compact=True)
                yield Button("Kill", id="s1-kill-btn", variant="error", compact=True)
                yield Button("Quarantine", id="s1-quarantine-btn", variant="warning", compact=True)
                yield Button("Remediate", id="s1-remediate-btn", variant="warning", compact=True)
                yield Button("Rollback", id="s1-rollback-btn", variant="error", compact=True)
            with Horizontal(classes="action-row toolbar-row"):
                yield Button("Add Exclusion", id="s1-threat-exclude-btn", compact=True)
                yield Button("Pivot ES", id="s1-pivot-es-btn", compact=True)
                yield Button("Pivot RF", id="s1-pivot-rf-btn", compact=True)
                yield Button("Pivot LLM", id="s1-pivot-llm-btn", compact=True)

        with Horizontal(id="s1-actions-exclusions", classes="action-row toolbar-row"):
            yield Button("Create Exclusion", id="s1-create-excl-btn", variant="primary", compact=True)
            yield Button("Edit Exclusion", id="s1-edit-excl-btn", compact=True)
            yield Button("Delete Exclusion", id="s1-delete-excl-btn", variant="error", compact=True)
            yield Button("Clone Site->Site", id="s1-clone-excl-btn", variant="warning", compact=True)

        with Horizontal(id="s1-actions-blocklist", classes="action-row toolbar-row"):
            yield Button("Add SHA-1", id="s1-add-block-btn", variant="primary", compact=True)
            yield Button("Remove Blocklist", id="s1-delete-block-btn", variant="error", compact=True)
            yield Button("Agents View", id="s1-goto-agents-btn", compact=True)

        with Vertical(id="s1-actions-sites"):
            with Horizontal(classes="action-row toolbar-row"):
                yield Button("Load Sites", id="s1-sites-btn", variant="primary", compact=True)
                yield Button("Activities", id="s1-activities-btn", compact=True)
                yield Button("Create Site", id="s1-site-create-btn", variant="primary", compact=True)
                yield Button("Edit Site", id="s1-site-edit-btn", compact=True)
                yield Button("Duplicate", id="s1-site-duplicate-btn", compact=True)
                yield Button("Policy", id="s1-site-policy-btn", compact=True)
            with Horizontal(classes="action-row toolbar-row"):
                yield Button("Expire", id="s1-site-expire-btn", variant="warning", compact=True)
                yield Button("Reactivate", id="s1-site-reactivate-btn", compact=True)
                yield Button("Rotate Token", id="s1-site-rotate-token-btn", variant="warning", compact=True)
                yield Button("Copy Token", id="s1-site-copy-token-btn", compact=True)
                yield Button("Delete Site", id="s1-site-delete-btn", variant="error", compact=True)

        with Vertical(id="s1-actions-users"):
            with Horizontal(classes="action-row toolbar-row"):
                yield Select(
                    _USERS_MODE_OPTIONS,
                    allow_blank=False,
                    value="console",
                    id="s1-users-mode-select",
                    compact=True,
                )
                yield Button("Load", id="s1-users-load-btn", variant="primary", compact=True)
                yield Button("Create User", id="s1-user-create-btn", variant="primary", compact=True)
                yield Button("Edit User", id="s1-user-edit-btn", compact=True)
            with Horizontal(classes="action-row toolbar-row"):
                yield Button("Reset PW", id="s1-user-reset-pw-btn", variant="warning", compact=True)
                yield Button("Reset 2FA", id="s1-user-reset-2fa-btn", variant="warning", compact=True)
                yield Button("Logout Session", id="s1-user-logout-btn", variant="warning", compact=True)
                yield Button("Delete User", id="s1-user-delete-btn", variant="error", compact=True)

        with Container(id="s1-workspace", classes="split-workspace"):
            with Vertical(id="s1-results-pane", classes="table-pane"):
                yield Static(
                    "Endpoints: 0 | Preset: View: All Endpoints",
                    id="s1-summary-bar",
                    classes="rf-summary-bar",
                    markup=False,
                )
                yield DoubleClickDataTable(id="s1-table")
            with Vertical(id="s1-detail-pane"):
                with Horizontal(id="s1-detail-toolbar", classes="detail-toolbar"):
                    yield Static("Inspector (Overview)", id="s1-detail-header", classes="section-label", markup=False)
                    yield Button("Overview", id="s1-view-overview-btn", variant="primary", compact=True)
                    yield Button("Raw JSON", id="s1-view-json-btn", compact=True)
                    yield Button("Copy Detail", id="s1-copy-detail-btn", compact=True)
                yield SelectableRichLog(
                    id="s1-detail-log",
                    classes="detail-log",
                    highlight=False,
                    markup=False,
                    wrap=True,
                )

    def on_mount(self) -> None:
        table = self.query_one("#s1-table", DoubleClickDataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        try:
            preset_sel = self.query_one("#s1-preset-select", Select)
            preset_sel.styles.width = "1fr"
            preset_sel.styles.min_width = 14
        except Exception:
            pass
        if isinstance(self.app, DOMNode):
            self.watch(self.app, "sub_title", self._on_app_subtitle_changed, init=False)
        self._table_ready = True
        self._sync_action_bars()
        self._sync_workbench_pills()
        self._sync_tier_pills()
        self._sync_admin_badge()
        self._configure_columns(self._current_view)
        self._render_empty_detail()
        self._update_split_layout()
        self._update_initial_status()
        self._cache_fetched_at: float = 0.0
        self.hydrate_from_alert_cache(force=False)

    def hydrate_from_alert_cache(self, *, force: bool = False) -> bool:
        """Populate Threats & Alerts from the local 24h alert cache when available."""
        if not self._table_ready or self._current_view != "threats":
            return False
        if self._alert_source != "threats" or self._timeframe_filter != "last_24h":
            return False
        cache = getattr(self.app, "alert_cache", None)
        if cache is None:
            return False
        entry = cache.get(CACHE_SOURCE_S1)
        if entry is None:
            loading_fn = getattr(self.app, "is_cache_source_loading", None)
            if not self._records and callable(loading_fn) and loading_fn(CACHE_SOURCE_S1):
                self.set_status(
                    "Background preload in progress for SentinelOne Alerts (24h)... Data will populate automatically."
                )
            return False
        manual_loaded = bool(self._records) and not getattr(self, "_hydrated_from_cache", False)
        if not force and manual_loaded:
            return False
        already_same = (
            getattr(self, "_hydrated_from_cache", False)
            and getattr(self, "_cache_fetched_at", 0.0) > 0.0
            and entry.fetched_at <= getattr(self, "_cache_fetched_at", 0.0)
        )
        if not force and already_same:
            return False
        cached_sites = entry.meta.get("sites")
        if isinstance(cached_sites, list) and cached_sites and not self._cached_sites:
            self._populate_site_selector(cached_sites)
        self._loaded_timeframe_filter = "last_24h"
        self._hydrated_from_cache = True
        self._cache_fetched_at = entry.fetched_at
        self.record_app_log(
            f"Hydrated SentinelOne cache ({len(entry.items)} item(s)).",
            level="DEBUG",
            source="cache",
        )
        self._populate_table(entry.items)
        self.set_status(
            f"Loaded {len(entry.items)} cached SentinelOne alert(s) "
            f"(Last 24h, updated {entry.age_label()})."
        )
        return True

    def _on_app_subtitle_changed(self, _old: str, _new: str) -> None:
        self._sync_admin_badge()

    def _update_initial_status(self) -> None:
        self._sync_admin_badge()
        app_s1 = getattr(self.app, "s1_client", None)
        if app_s1 is not None:
            mode = " [DRY-RUN]" if self.effective_dry_run else ""
            self.set_status(
                f"SentinelOne client ready{mode}. Click Refresh to load {self._current_view}."
            )
            return
        cfg = get_sentinelone_config(required=False)
        mode = " [DRY-RUN]" if self.effective_dry_run else ""
        if cfg.has_auth:
            self.set_status(f"SentinelOne configured ({cfg.console_url}){mode}. Click Refresh to load.")
        else:
            self.set_status(
                f"SentinelOne not configured (open Settings [0/F10] or set S1_CONSOLE_URL & S1_API_TOKEN){mode}."
            )

    def on_settings_updated(self) -> None:
        self._s1_client = None
        self._update_initial_status()
        if self._table_ready:
            self._apply_local_filter()

    def on_resize(self) -> None:
        self._update_split_layout()
        if self._table_ready:
            self.call_after_refresh(self._fit_table)

    def on_tab_activated(self) -> None:
        self._sync_admin_badge()
        self._update_split_layout()
        if self._table_ready:
            self.hydrate_from_alert_cache(force=False)
            self.call_after_refresh(self._fit_table)

    def _update_split_layout(self) -> None:
        try:
            ws = self.query_one("#s1-workspace", Container)
            if self.size.width >= _SPLIT_HORIZONTAL_MIN_WIDTH:
                ws.add_class("split-horizontal")
            else:
                ws.remove_class("split-horizontal")
        except Exception:
            pass

    def _sync_workbench_pills(self) -> None:
        wb_map = {
            "threats": "#s1-wb-alerts-btn",
            "sites_activities": "#s1-wb-sites-btn",
            "users_rbac": "#s1-wb-users-btn",
            "exclusions": "#s1-wb-exclusions-btn",
            "endpoints": "#s1-wb-agents-btn",
            "blocklist": "#s1-wb-agents-btn",
        }
        active_id = wb_map.get(self._current_view, "#s1-wb-agents-btn")
        for btn_id in (
            "#s1-wb-alerts-btn",
            "#s1-wb-sites-btn",
            "#s1-wb-users-btn",
            "#s1-wb-exclusions-btn",
            "#s1-wb-agents-btn",
        ):
            try:
                btn = self.query_one(btn_id, Button)
                btn.variant = "primary" if btn_id == active_id else "default"
            except Exception:
                pass

    def _sync_tier_pills(self) -> None:
        tier_map = {
            "ALL": "#s1-tier-all-btn",
            "MDR": "#s1-tier-mdr-btn",
            "MSSP": "#s1-tier-mssp-btn",
            "Other": "#s1-tier-other-btn",
        }
        active_id = tier_map.get(self._tier_filter, "#s1-tier-all-btn")
        for btn_id in tier_map.values():
            try:
                btn = self.query_one(btn_id, Button)
                btn.variant = "primary" if btn_id == active_id else "default"
            except Exception:
                pass

    def _sync_action_bars(self) -> None:
        bar_map = {
            "endpoints": "#s1-actions-endpoints",
            "threats": "#s1-actions-threats",
            "exclusions": "#s1-actions-exclusions",
            "blocklist": "#s1-actions-blocklist",
            "sites_activities": "#s1-actions-sites",
            "users_rbac": "#s1-actions-users",
        }
        for view_key, selector in bar_map.items():
            bar = self.query_one(selector, Widget)
            bar.display = view_key == self._current_view
        self._sync_filter_controls_for_view()

    def _sync_filter_controls_for_view(self) -> None:
        """Populate SentinelOne preset, timeframe, status, and alert dropdowns for the active view."""
        self._syncing_s1_filters = True
        try:
            presets = S1_PRESETS_BY_VIEW.get(
                self._current_view,
                ({"id": "all", "label": "View: All Records", "timeframe": "any", "status": "any"},),
            )
            preset_sel = self.query_one("#s1-preset-select", Select)
            with preset_sel.prevent(Select.Changed):
                preset_sel.set_options([(str(p["label"]), str(p["id"])) for p in presets])
                preset_sel.value = "all"
                preset_sel.mutate_reactive(getattr(Select, "value"))

            default_tf = "last_24h" if self._current_view == "threats" else "any"
            tf_sel = self.query_one("#s1-timeframe-select", Select)
            with tf_sel.prevent(Select.Changed):
                tf_sel.value = default_tf
                tf_sel.display = self._current_view in {"threats", "sites_activities"}

            status_sel = self.query_one("#s1-status-select", Select)
            with status_sel.prevent(Select.Changed):
                if self._current_view == "threats":
                    status_sel.set_options(list(_S1_THREAT_STATUS_OPTIONS))
                    status_sel.value = "any"
                    status_sel.mutate_reactive(getattr(Select, "value"))
                    status_sel.display = True
                elif self._current_view == "endpoints":
                    status_sel.set_options(list(_S1_ENDPOINT_STATUS_OPTIONS))
                    status_sel.value = "any"
                    status_sel.mutate_reactive(getattr(Select, "value"))
                    status_sel.display = True
                else:
                    status_sel.set_options([("State: Any", "any")])
                    status_sel.value = "any"
                    status_sel.mutate_reactive(getattr(Select, "value"))
                    status_sel.display = False

            alerts_row = self.query_one("#s1-filter-bar-alerts", Widget)
            alerts_row.display = self._current_view == "threats"

            source_sel = self.query_one("#s1-alert-source-select", Select)
            source_sel.display = self._current_view == "threats"

            group_sel = self.query_one("#s1-grouping-select", Select)
            group_sel.display = self._current_view == "threats"

            self._active_preset_id = "all"
            self._timeframe_filter = default_tf
            self._status_filter = "any"
        except Exception:
            pass
        finally:
            self._syncing_s1_filters = False
        self._update_summary_bar()

    def _switch_view(self, val: str, *, sites_submode: str | None = None) -> None:
        self._load_seq += 1
        self._current_view = val
        if sites_submode is not None:
            self._sites_submode = sites_submode
        self._records = []
        self._filtered_records = []
        self._table_rows = []
        self._selected_record = None
        self._loaded_timeframe_filter = None
        try:
            view_sel = self.query_one("#s1-view-select", Select)
            if str(view_sel.value or "") != val:
                with view_sel.prevent(Select.Changed):
                    view_sel.value = val
                    view_sel.mutate_reactive(getattr(Select, "value"))
        except Exception:
            pass
        self._sync_workbench_pills()
        self._sync_action_bars()
        self._configure_columns(val)
        self._render_empty_detail()
        self.set_status(f"Switched to SentinelOne {val} view. Click Refresh to load.")

    def _configure_columns(self, view: str) -> None:
        table = self.query_one("#s1-table", DoubleClickDataTable)
        table.clear(columns=True)
        for key, label, _, _ in _TABLE_SPECS.get(view, _TABLE_SPECS["endpoints"]):
            table.add_column(label, key=key)
        self.call_after_refresh(self._fit_table)

    def _fit_table(self) -> None:
        if self.is_app_shutting_down() or not self._table_ready:
            return
        try:
            table = self.query_one("#s1-table", DoubleClickDataTable)
            specs = [
                (key, weight, min_w)
                for key, _, weight, min_w in _TABLE_SPECS.get(
                    self._current_view, _TABLE_SPECS["endpoints"]
                )
            ]
            self.fit_table_columns(table, specs)
        except Exception:
            pass

    def _render_empty_detail(self) -> None:
        try:
            detail = self.query_one("#s1-detail-log", RichLog)
            detail.clear()
            detail.write(
                Panel(
                    Text(
                        "Select a row in the table to inspect full SentinelOne record details.\n"
                        "Right-click a row for contextual actions and cross-workbench pivots.",
                        style="dim",
                    ),
                    title="SentinelOne Inspector",
                    border_style="cyan",
                )
            )
        except Exception:
            pass

    def _classify_record_tier(self, rec: Mapping[str, Any]) -> tuple[str, str | None, str, str]:
        """Return ``(tier, tenant_id, site_id, site_name)`` for any S1 record."""
        if rec.get("tier") and (rec.get("siteName") or rec.get("name")):
            tier = str(rec.get("tier") or "Other")
            tenant = str(rec.get("tenantId") or "").strip() or None
            site_id = str(rec.get("siteId") or rec.get("id") or "").strip()
            site_name = str(rec.get("siteName") or rec.get("name") or "").strip()
            return tier, tenant, site_id, site_name

        raw_rt = rec.get("agentRealtimeInfo")
        rt: Mapping[str, Any] = raw_rt if isinstance(raw_rt, Mapping) else {}
        raw_det = rec.get("agentDetectionInfo")
        det: Mapping[str, Any] = raw_det if isinstance(raw_det, Mapping) else {}

        site_id = str(
            rec.get("siteId")
            or rt.get("siteId")
            or det.get("siteId")
            or (rec.get("id") if rec.get("_s1_kind") == "site" else "")
            or ""
        ).strip()
        site_name = str(
            rec.get("siteName")
            or rt.get("siteName")
            or det.get("siteName")
            or (rec.get("name") if rec.get("_s1_kind") == "site" else "")
            or ""
        ).strip()

        if not site_name and site_id and self._cached_sites:
            for s in self._cached_sites:
                if str(s.get("id") or "").strip() == site_id:
                    site_name = str(s.get("name") or "").strip()
                    break

        tier_cfg = self._get_tier_config()
        tier, _code, tenant_id = tier_cfg.classify_site(site_name, site_id=site_id or None)
        return tier, tenant_id, site_id, site_name

    def _populate_site_selector(self, sites: Sequence[Mapping[str, Any]]) -> None:
        tier_cfg = self._get_tier_config()
        enriched: list[dict[str, Any]] = []
        for s in sites:
            item = dict(s)
            sname = str(item.get("name") or item.get("siteName") or "")
            sid = str(item.get("id") or "").strip()
            tier, code, tenant = tier_cfg.classify_site(sname, site_id=sid or None)
            item["tier"] = tier
            item["siteCode"] = code
            item["tenantId"] = tenant
            enriched.append(item)
        self._cached_sites = enriched
        self._refresh_site_multiselect()

    def _refresh_site_multiselect(self) -> None:
        try:
            search = self.query_one("#s1-site-search-input", Input).value.strip().lower()
            sel_list = self.query_one("#s1-site-multiselect", SelectionList)
            collapsible = self.query_one("#s1-scope-collapsible", Collapsible)
        except Exception:
            return
        options: list[tuple[str, str, bool]] = []
        for site in self._cached_sites:
            sid = str(site.get("id") or "").strip()
            if not sid:
                continue
            tier = str(site.get("tier") or "Other")
            if self._tier_filter != "ALL" and tier != self._tier_filter:
                continue
            name = str(site.get("name") or sid)
            label = f"[{tier}] {name} ({sid})"
            if search and search not in label.lower():
                continue
            options.append((label, sid, sid in self._selected_site_ids))
        with sel_list.prevent(SelectionList.SelectedChanged):
            sel_list.clear_options()
            if options:
                sel_list.add_options(options)
        collapsible.title = f"Multi-Site Scope Selector ({len(self._selected_site_ids)} selected)"

    def _format_row(self, view: str, rec: dict[str, Any]) -> tuple[str, ...]:
        if rec.get("_is_group_header"):
            marker = "[-]" if rec.get("_expanded") else "[+]"
            return (
                _truncate(f"{marker} {rec.get('_group_label', 'Group')}", 34),
                _truncate(rec.get("_group_tier") or "-", 8),
                _truncate(f"sites={rec.get('_site_count', 0)}", 18),
                _truncate(f"total={rec.get('_total_count', 0)}", 14),
                _truncate(f"unmit={rec.get('_unmitigated_count', 0)}", 12),
                _truncate(f"crit/hi={rec.get('_high_count', 0)}", 14),
                "-",
            )

        tier, _tenant, _site_id, site_name = self._classify_record_tier(rec)
        if view == "endpoints":
            return (
                _truncate(rec.get("computerName") or rec.get("id") or "-", 26),
                _truncate(tier, 8),
                _truncate(rec.get("osName") or rec.get("osType") or "-", 16),
                _truncate(rec.get("lastIpToMgmt") or rec.get("externalIp") or "-", 16),
                _truncate(rec.get("networkStatus") or "-", 12),
                "YES" if rec.get("infected") else "No",
                _truncate(site_name or rec.get("siteId") or "-", 22),
            )
        if view == "threats":
            raw_tinfo = rec.get("threatInfo")
            tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
            raw_ainfo = rec.get("agentRealtimeInfo")
            ainfo: dict[str, Any] = raw_ainfo if isinstance(raw_ainfo, dict) else {}
            raw_rule = rec.get("ruleInfo")
            rule: dict[str, Any] = raw_rule if isinstance(raw_rule, dict) else {}
            raw_alert = rec.get("alertInfo")
            alert_info: dict[str, Any] = raw_alert if isinstance(raw_alert, dict) else {}
            title = (
                rec.get("title")
                or tinfo.get("threatName")
                or rule.get("name")
                or rec.get("threatName")
                or rec.get("id")
                or "-"
            )
            host = (
                rec.get("computerName")
                or ainfo.get("agentComputerName")
                or rec.get("agentComputerName")
                or site_name
                or "-"
            )
            verdict = (
                rec.get("analystVerdict")
                or tinfo.get("analystVerdict")
                or alert_info.get("analystVerdict")
                or "-"
            )
            status = (
                rec.get("incidentStatus")
                or tinfo.get("incidentStatus")
                or alert_info.get("incidentStatus")
                or "-"
            )
            mit = (
                summarize_mitigation_status(rec, tinfo)
                or ("cloud" if rec.get("recordType") == "cloud_alert" else "-")
            )
            created = (
                rec.get("createdAt")
                or tinfo.get("createdAt")
                or alert_info.get("createdAt")
                or "-"
            )
            return (
                _truncate(title, 28),
                _truncate(tier, 8),
                _truncate(host, 18),
                _truncate(verdict, 14),
                _truncate(status, 12),
                _truncate(mit, 12),
                _truncate(created, 19),
            )
        if view == "exclusions":
            return (
                _truncate(rec.get("type") or "-", 12),
                _truncate(rec.get("osType") or "-", 9),
                _truncate(rec.get("scope") or rec.get("siteName") or "-", 12),
                _truncate(rec.get("value") or "-", 36),
                _truncate(rec.get("mode") or "-", 18),
                _truncate(rec.get("description") or "-", 26),
            )
        if view == "blocklist":
            return (
                _truncate(rec.get("value") or "-", 42),
                _truncate(rec.get("osType") or "-", 10),
                _truncate(rec.get("source") or "-", 16),
                _truncate(rec.get("description") or "-", 32),
            )
        if view == "users_rbac":
            kind = str(rec.get("_s1_user_kind") or "User")
            name = rec.get("fullName") or rec.get("name") or rec.get("id") or "-"
            email = rec.get("email") or rec.get("description") or "-"
            scope = rec.get("scope") or rec.get("scopeName") or "-"
            extra = (
                f"2FA={rec.get('twoFaEnabled')}"
                if "twoFaEnabled" in rec
                else (
                    f"predef={rec.get('predefinedRole')}"
                    if "predefinedRole" in rec
                    else str(rec.get("expirationDate") or "-")
                )
            )
            return (
                _truncate(kind, 14),
                _truncate(name, 26),
                _truncate(email, 28),
                _truncate(scope, 14),
                _truncate(extra, 18),
            )
        # sites_activities
        if rec.get("_s1_kind") == "activity":
            return (
                "Activity",
                _truncate(tier, 8),
                _truncate(rec.get("primaryDescription") or rec.get("activityType") or "-", 40),
                _truncate(rec.get("siteName") or rec.get("accountName") or "-", 20),
                _truncate(rec.get("createdAt") or "-", 19),
            )
        return (
            "Site",
            _truncate(tier, 8),
            _truncate(rec.get("name") or rec.get("id") or "-", 40),
            _truncate(rec.get("state") or rec.get("siteType") or "-", 20),
            _truncate(rec.get("updatedAt") or rec.get("createdAt") or "-", 19),
        )

    def _populate_table(self, records: list[dict[str, Any]]) -> None:
        self._records = list(records)
        self._apply_local_filter()

    def _record_timestamp(self, rec: dict[str, Any]) -> Any:
        raw_tinfo = rec.get("threatInfo")
        tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
        raw_alert = rec.get("alertInfo")
        alert_info: dict[str, Any] = raw_alert if isinstance(raw_alert, dict) else {}
        return (
            rec.get("createdAt")
            or tinfo.get("createdAt")
            or alert_info.get("createdAt")
            or alert_info.get("reportedAt")
            or rec.get("updatedAt")
            or tinfo.get("updatedAt")
            or rec.get("lastActiveDate")
            or rec.get("registeredAt")
            or rec.get("dateJoined")
        )

    def _record_matches_status(self, rec: dict[str, Any]) -> bool:
        if self._status_filter == "any":
            return True
        if self._current_view == "threats":
            raw_tinfo = rec.get("threatInfo")
            tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
            raw_alert = rec.get("alertInfo")
            alert_info: dict[str, Any] = raw_alert if isinstance(raw_alert, dict) else {}
            verdict = str(
                rec.get("analystVerdict")
                or tinfo.get("analystVerdict")
                or alert_info.get("analystVerdict")
                or ""
            ).strip().lower()
            inc_status = str(
                rec.get("incidentStatus")
                or tinfo.get("incidentStatus")
                or alert_info.get("incidentStatus")
                or ""
            ).strip().lower()
            mit_status = summarize_mitigation_status(rec, tinfo).strip().lower()
            if self._status_filter == "unresolved":
                if inc_status:
                    return inc_status == "unresolved"
                return mit_status in {"active", "not_mitigated", ""}
            if self._status_filter == "resolved":
                return inc_status == "resolved"
            if self._status_filter == "in_progress":
                return inc_status in {"in_progress", "in progress"}
            if self._status_filter in {"true_positive", "false_positive", "suspicious", "undefined"}:
                return verdict == self._status_filter
            return True
        if self._current_view == "endpoints":
            infected = bool(rec.get("infected"))
            net = str(rec.get("networkStatus") or "").strip().lower()
            if self._status_filter == "infected":
                return infected
            if self._status_filter == "disconnected":
                return net in {"disconnected", "disconnecting"}
            if self._status_filter == "connected":
                return net == "connected" and not infected
            if self._status_filter == "healthy":
                return not infected
        return True

    def _record_matches_tier_and_site(self, rec: dict[str, Any]) -> bool:
        tier, _tenant, site_id, _site_name = self._classify_record_tier(rec)
        if self._tier_filter != "ALL":
            if self._current_view in {"endpoints", "threats", "sites_activities"}:
                if tier != self._tier_filter:
                    return False
        if self._selected_site_ids and self._current_view in {
            "endpoints",
            "threats",
            "exclusions",
            "sites_activities",
        }:
            if site_id and site_id not in self._selected_site_ids:
                return False
        return True

    def _update_summary_bar(self) -> None:
        try:
            summary = self.query_one("#s1-summary-bar", Static)
        except Exception:
            return
        view_title = self._current_view.replace("_", " ").title()
        parts: list[str] = [f"{view_title}: {len(self._filtered_records)} (of {len(self._records)})"]
        if self._tier_filter != "ALL":
            parts.append(f"Tier={self._tier_filter}")
        if self._selected_site_ids:
            parts.append(f"Sites={len(self._selected_site_ids)}")
        if self._current_view == "threats" and self._grouping_mode != "flat":
            parts.append(f"Group={self._grouping_mode}")
        if self._status_filter != "any":
            parts.append(f"Filter={self._status_filter}")
        if self._timeframe_filter != "any":
            parts.append(f"Time={timeframe_label(self._timeframe_filter)}")
        if self._active_preset_id != "all":
            for preset in S1_PRESETS_BY_VIEW.get(self._current_view, ()):
                if preset.get("id") == self._active_preset_id:
                    parts.append(f"View: {preset.get('label')}")
                    break
        summary.update(" | ".join(parts))

    def _build_grouped_threat_rows(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if self._grouping_mode == "flat" or self._current_view != "threats":
            return list(records)

        groups: dict[str, list[dict[str, Any]]] = {}
        group_tiers: dict[str, str] = {}
        for rec in records:
            tier, _tenant, site_id, site_name = self._classify_record_tier(rec)
            raw_tinfo = rec.get("threatInfo")
            tinfo: Mapping[str, Any] = raw_tinfo if isinstance(raw_tinfo, Mapping) else {}
            raw_proc = rec.get("sourceProcessInfo")
            proc: Mapping[str, Any] = raw_proc if isinstance(raw_proc, Mapping) else {}
            sha1 = str(
                rec.get("sha1") or tinfo.get("sha1") or proc.get("fileHashSha1") or ""
            ).strip().lower()
            if self._grouping_mode == "tier":
                key = tier
            elif self._grouping_mode == "site":
                key = site_name or site_id or "Unknown Site"
            else:  # tier_hash — strictly partitioned per service tier
                key = f"{tier} | {sha1 or 'no-sha1'}"
            groups.setdefault(key, []).append(rec)
            group_tiers.setdefault(key, tier)

        rows: list[dict[str, Any]] = []
        for gkey, items in groups.items():
            expanded = gkey in self._expanded_groups
            distinct_sites: set[str] = set()
            high_count = 0
            unmitigated = 0
            for item in items:
                _t, _ten, sid, sname = self._classify_record_tier(item)
                if sname or sid:
                    distinct_sites.add(sname or sid)
                raw_tinfo = item.get("threatInfo")
                tinfo = raw_tinfo if isinstance(raw_tinfo, Mapping) else {}
                raw_rule = item.get("ruleInfo")
                rule = raw_rule if isinstance(raw_rule, Mapping) else {}
                sev = str(
                    item.get("severity")
                    or rule.get("severity")
                    or tinfo.get("confidenceLevel")
                    or ""
                ).strip().lower()
                if sev in {"critical", "high", "malicious"}:
                    high_count += 1
                inc = str(
                    item.get("incidentStatus") or tinfo.get("incidentStatus") or ""
                ).strip().lower()
                mit = summarize_mitigation_status(item, tinfo).strip().lower()
                if inc == "unresolved" or mit in {"active", "not_mitigated"}:
                    unmitigated += 1

            header_rec: dict[str, Any] = {
                "_is_group_header": True,
                "_group_key": gkey,
                "_group_label": gkey,
                "_group_tier": group_tiers.get(gkey, "Other"),
                "_expanded": expanded,
                "_total_count": len(items),
                "_high_count": high_count,
                "_unmitigated_count": unmitigated,
                "_site_count": len(distinct_sites),
                "_group_records": items,
                "id": f"group:{gkey}",
            }
            rows.append(header_rec)
            if expanded:
                rows.extend(items)
        return rows

    def _apply_local_filter(self) -> None:
        query = ""
        try:
            query = self.query_one("#s1-filter-input", Input).value.strip().lower()
        except Exception:
            pass
        filtered: list[dict[str, Any]] = []
        for rec in self._records:
            if not self._record_matches_tier_and_site(rec):
                continue
            if not self._record_matches_status(rec):
                continue
            if self._timeframe_filter != "any" and self._current_view in {
                "threats",
                "sites_activities",
            }:
                rec_ts = self._record_timestamp(rec)
                if rec_ts is None and self._loaded_timeframe_filter == self._timeframe_filter:
                    pass
                elif not timestamp_matches_timeframe(
                    rec_ts,
                    self._timeframe_filter,
                ):
                    continue
            if query and query not in json.dumps(rec, default=str).lower():
                continue
            filtered.append(rec)
        filtered = sort_s1_records_newest_first(filtered)
        self._filtered_records = filtered
        self._table_rows = self._build_grouped_threat_rows(filtered)

        table = self.query_one("#s1-table", DoubleClickDataTable)
        self._configure_columns(self._current_view)
        for idx, rec in enumerate(self._table_rows):
            row_key = str(rec.get("_group_key") or rec.get("id") or f"row-{idx}")
            table.add_row(*self._format_row(self._current_view, rec), key=f"{idx}:{row_key}")

        if self._table_rows:
            self._select_record(self._table_rows[0])
        else:
            self._selected_record = None
            self._render_empty_detail()
        self._update_summary_bar()
        self.call_after_refresh(self._fit_table)

    def _select_record(self, rec: dict[str, Any]) -> None:
        self._selected_record = rec
        try:
            header = self.query_one("#s1-detail-header", Static)
            if rec.get("_is_group_header"):
                gkey = str(rec.get("_group_label") or "Group")
                header.update(f"Group Summary ({gkey})")
                detail = self.query_one("#s1-detail-log", RichLog)
                detail.clear()
                tbl = Table.grid(padding=(0, 1))
                tbl.add_column(style="bold cyan", no_wrap=True)
                tbl.add_column()
                tbl.add_row("Group", gkey)
                tbl.add_row("Tier", str(rec.get("_group_tier") or "-"))
                tbl.add_row("Total Alerts", str(rec.get("_total_count", 0)))
                tbl.add_row("Critical / High", str(rec.get("_high_count", 0)))
                tbl.add_row("Unmitigated / Unresolved", str(rec.get("_unmitigated_count", 0)))
                tbl.add_row("Distinct Sites", str(rec.get("_site_count", 0)))
                detail.write(
                    Panel(
                        tbl,
                        title="Grouped Alert Summary (Press Enter / Click to Expand)",
                        border_style="cyan",
                    )
                )
                return

            rec_id = str(rec.get("id") or "-")
            tier, tenant_id, site_id, site_name = self._classify_record_tier(rec)
            mode_tag = "Raw JSON" if self._detail_mode == "json" else "Overview"
            header.update(f"Inspector ({mode_tag}) - {self._current_view}: {rec_id} | {tier}")
            self._sync_detail_mode_buttons()
            detail = self.query_one("#s1-detail-log", RichLog)
            detail.clear()

            if self._detail_mode == "json":
                detail.write(render_raw_json(rec, title=f"Raw JSON - {rec_id}"))
            else:
                detail.write(
                    render_s1_record_detail(
                        self._current_view,
                        rec,
                        tier=tier,
                        tenant_id=tenant_id,
                        site_id=site_id,
                        site_name=site_name,
                    )
                )
        except Exception:
            pass

    def _sync_detail_mode_buttons(self) -> None:
        try:
            ov_btn = self.query_one("#s1-view-overview-btn", Button)
            js_btn = self.query_one("#s1-view-json-btn", Button)
            if self._detail_mode == "json":
                ov_btn.variant = "default"
                js_btn.variant = "primary"
            else:
                ov_btn.variant = "primary"
                js_btn.variant = "default"
        except Exception:
            pass

    @on(Button.Pressed, "#s1-view-overview-btn")
    def handle_view_overview(self) -> None:
        self._detail_mode = "overview"
        self._sync_detail_mode_buttons()
        if self._selected_record is not None:
            self._select_record(self._selected_record)

    @on(Button.Pressed, "#s1-view-json-btn")
    def handle_view_json(self) -> None:
        self._detail_mode = "json"
        self._sync_detail_mode_buttons()
        if self._selected_record is not None:
            self._select_record(self._selected_record)

    @on(Button.Pressed, "#s1-copy-detail-btn")
    def handle_copy_detail(self) -> None:
        if self._selected_record is not None and self._detail_mode == "json":
            text = json.dumps(self._selected_record, indent=2, default=str)
        else:
            try:
                text = extract_richlog_text(self.query_one("#s1-detail-log", RichLog))
            except Exception:
                text = ""
        self.copy_to_clipboard(text, label="SentinelOne Detail")

    def _record_for_row_index(self, row_index: int | None) -> dict[str, Any] | None:
        if row_index is None:
            return None
        if 0 <= row_index < len(self._table_rows):
            return self._table_rows[row_index]
        return None

    def _require_selected(self, label: str) -> dict[str, Any] | None:
        if self._selected_record is None:
            msg = f"Select a {label} row first."
            self.set_status(msg)
            self.notify_user(msg, title="SentinelOne", severity="warning")
            return None
        if self._selected_record.get("_is_group_header"):
            items = self._selected_record.get("_group_records")
            if isinstance(items, list) and items:
                return dict(items[0])
            msg = f"Expand the group and select a specific {label} row first."
            self.set_status(msg)
            self.notify_user(msg, title="SentinelOne", severity="warning")
            return None
        return self._selected_record

    def _require_selected_site(self, action_name: str) -> dict[str, Any] | None:
        rec = self._require_selected("site")
        if rec is None:
            return None
        if rec.get("_s1_kind") != "site":
            msg = f"'{action_name}' requires a Site row (Activity rows are read-only)."
            self.set_status(msg)
            self.append_log(msg, level="WARNING")
            self.notify_user(msg, title="Select a Site Row", severity="warning")
            return None
        return rec

    def _require_selected_user(self, action_name: str) -> dict[str, Any] | None:
        rec = self._require_selected("user")
        if rec is None:
            return None
        if rec.get("_s1_user_kind") not in {"Console User", "Service User"}:
            msg = (
                f"'{action_name}' requires a Console User or Service User row "
                "(RBAC Role rows are read-only)."
            )
            self.set_status(msg)
            self.append_log(msg, level="WARNING")
            self.notify_user(msg, title="Select a User Row", severity="warning")
            return None
        return rec

    @staticmethod
    def _clean_id_seq(raw_ids: Sequence[str] | str | None) -> list[str]:
        if raw_ids is None or isinstance(raw_ids, (bytes, bytearray)):
            return []
        seq = [raw_ids] if isinstance(raw_ids, str) else raw_ids
        cleaned: list[str] = []
        for item in seq:
            if item is None or isinstance(item, (bytes, bytearray)):
                continue
            val = str(item).strip()
            if val:
                cleaned.append(val)
        return cleaned

    @staticmethod
    def _is_cloud_alert_record(rec: Mapping[str, Any]) -> bool:
        return (
            rec.get("recordType") == "cloud_alert"
            or bool(rec.get("alertInfo"))
            or (bool(rec.get("ruleInfo")) and not rec.get("threatInfo"))
        )

    def _selected_threat_partition_for_action(
        self,
    ) -> tuple[list[str], list[str], str, dict[str, Any]] | None:
        """Return ``(endpoint_ids, cloud_alert_ids, label, primary_record)``."""
        if self._selected_record is None:
            self._require_selected("threat")
            return None
        if self._selected_record.get("_is_group_header"):
            raw_items = self._selected_record.get("_group_records")
            items = [r for r in raw_items if isinstance(r, dict)] if isinstance(raw_items, list) else []
            ep_ids: list[str] = []
            cl_ids: list[str] = []
            for item in items:
                item_id = str(item.get("id") or "").strip()
                if not item_id:
                    continue
                if self._is_cloud_alert_record(item):
                    cl_ids.append(item_id)
                else:
                    ep_ids.append(item_id)
            if not (ep_ids or cl_ids):
                return None
            label = str(self._selected_record.get("_group_label") or (ep_ids + cl_ids)[0])
            return ep_ids, cl_ids, label, items[0]
        rec = self._selected_record
        tid = str(rec.get("id") or "").strip()
        if not tid:
            self.set_status("Selected threat record is missing an ID.")
            return None
        raw_tinfo = rec.get("threatInfo")
        tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
        label = str(rec.get("title") or tinfo.get("threatName") or rec.get("threatName") or tid)
        if self._is_cloud_alert_record(rec):
            return [], [tid], label, rec
        return [tid], [], label, rec

    def _selected_threat_ids_for_action(self) -> tuple[list[str], str, dict[str, Any]] | None:
        """Return ``(threat_ids, label, primary_record)`` supporting tier-partitioned group rows."""
        part = self._selected_threat_partition_for_action()
        if part is None:
            return None
        ep_ids, cl_ids, label, rec = part
        return ep_ids + cl_ids, label, rec

    def _block_if_dry_run(self, action_name: str, target_desc: str) -> bool:
        """Return True and notify operator if ``effective_dry_run`` blocks this write."""
        if not self.effective_dry_run:
            return False
        msg = f"[DRY-RUN] Blocked SentinelOne action '{action_name}' on {target_desc}."
        self.set_status(msg)
        self.append_log(msg, level="WARNING")
        self.notify_user(msg, title="Dry-Run Mode", severity="warning")
        return True

    def _report_s1_error(self, context: str, exc: Exception) -> None:
        if isinstance(exc, SentinelOneError) and exc.reason == "cancelled":
            return
        if isinstance(exc, SentinelOneAuthError):
            detail = f"SentinelOne Auth Error (HTTP {exc.status_code}): {exc.message}"
        elif isinstance(exc, SentinelOneRateLimitError):
            retry = f" | retry_after={exc.retry_after}s" if exc.retry_after is not None else ""
            detail = f"SentinelOne Rate Limit (HTTP 429): {exc.message}{retry}"
        elif isinstance(exc, SentinelOneError):
            status = f"HTTP {exc.status_code}" if exc.status_code else "API Error"
            detail = f"SentinelOne {status}: {exc.message}"
        else:
            self.report_error(context, exc)
            return
        msg = f"[ERROR] {context}: {detail}"
        self.set_status(msg)
        self.append_log(msg, level="ERROR")
        self.notify_user(detail, title=context, severity="error")

    # ------------------------------------------------------------------
    # Cross-Workbench Pivot Bus Hooks
    # ------------------------------------------------------------------

    def _build_pivot_payload(
        self,
        target_tab: str,
        *,
        rec: Mapping[str, Any] | None = None,
    ) -> PivotPayload:
        record = dict(rec) if rec is not None else (dict(self._selected_record) if self._selected_record else {})
        if record.get("_is_group_header"):
            raw_items = record.get("_group_records")
            if isinstance(raw_items, list) and raw_items and isinstance(raw_items[0], Mapping):
                record = dict(raw_items[0])

        tier, tenant_id, site_id, site_name = self._classify_record_tier(record)
        raw_tinfo = record.get("threatInfo")
        tinfo: Mapping[str, Any] = raw_tinfo if isinstance(raw_tinfo, Mapping) else {}
        raw_ainfo = record.get("agentRealtimeInfo")
        ainfo: Mapping[str, Any] = raw_ainfo if isinstance(raw_ainfo, Mapping) else {}
        raw_proc = record.get("sourceProcessInfo")
        proc: Mapping[str, Any] = raw_proc if isinstance(raw_proc, Mapping) else {}

        sha1 = str(
            record.get("sha1")
            or tinfo.get("sha1")
            or proc.get("fileHashSha1")
            or (record.get("value") if self._current_view == "blocklist" else "")
            or ""
        ).strip()
        sha256 = str(
            record.get("sha256")
            or tinfo.get("sha256")
            or proc.get("fileHashSha256")
            or ""
        ).strip()
        hostname = str(
            record.get("computerName")
            or ainfo.get("agentComputerName")
            or record.get("agentComputerName")
            or ""
        ).strip()
        username = str(
            record.get("username")
            or proc.get("user")
            or record.get("lastLoggedInUserName")
            or ""
        ).strip()
        src_ip = str(record.get("lastIpToMgmt") or record.get("externalIp") or "").strip()

        entity = sha256 or sha1 or src_ip or hostname or tenant_id or ""
        if sha256 or sha1:
            entity_type = "hash"
        elif src_ip:
            entity_type = "ip"
        elif hostname:
            entity_type = "host"
        else:
            entity_type = "auto"

        auto_run = target_tab in {"tab-splunk-es", "tab-rf-intel", "tab-research"}
        summary = (
            f"S1 {self._current_view} | Tier={tier} | Site={site_name or site_id or '-'} | "
            f"Tenant={tenant_id or '-'} | Host={hostname or '-'} | SHA1={sha1 or '-'}"
        )
        return PivotPayload(
            source_tab="tab-sentinelone",
            target_tab=target_tab,
            tenant_id=tenant_id,
            site_id=site_id or None,
            site_name=site_name or None,
            tier=tier,
            entity=entity or None,
            entity_type=entity_type,
            src_ip=src_ip or None,
            sha1=sha1 or None,
            sha256=sha256 or None,
            hostname=hostname or None,
            username=username or None,
            auto_run=auto_run,
            s1_threat=record if record else None,
            summary=summary,
        )

    def _emit_pivot_target(self, target_tab: str) -> None:
        payload = self._build_pivot_payload(target_tab)
        dispatched = emit_pivot(self.app, payload)
        if dispatched:
            self.set_status(f"Pivoted from SentinelOne -> {target_tab}.")
        else:
            self.set_status(f"Prepared pivot payload for {target_tab} (handler unavailable).")

    def accept_pivot(self, payload: PivotPayload) -> None:
        """Accept an incoming cross-workbench ``PivotPayload`` and run a scoped read-only query."""
        def _clean_pivot_val(val: Any) -> str:
            s = str(val or "").strip()
            return "" if s == "-" else s

        sha1 = _clean_pivot_val(payload.sha1)
        sha256 = _clean_pivot_val(payload.sha256)
        target_view = (
            "threats"
            if (sha1 or sha256 or payload.s1_threat)
            else "endpoints"
        )
        self._switch_view(target_view)

        raw_tier = str(payload.tier or "").strip().lower()
        tier_map = {"mdr": "MDR", "mssp": "MSSP", "other": "Other"}
        self._tier_filter = tier_map.get(raw_tier, "ALL")
        self._sync_tier_pills()

        clean_site_id = _clean_pivot_val(payload.site_id)
        if clean_site_id:
            self._selected_site_ids = {clean_site_id}
        else:
            self._selected_site_ids = set()
        self._refresh_site_multiselect()

        hostname_val = _clean_pivot_val(payload.hostname)
        host_entity = ""
        raw_entity = _clean_pivot_val(payload.entity)
        raw_entity_type = str(payload.entity_type or "").strip().lower()
        if (
            not hostname_val
            and raw_entity
            and raw_entity_type in {"system", "host", "hostname", "endpoint", "machine", "asset"}
            and "@" not in raw_entity
        ):
            try:
                ipaddress.ip_address(raw_entity)
            except ValueError:
                host_entity = raw_entity

        search_term = (
            sha1
            or sha256
            or hostname_val
            or host_entity
            or _clean_pivot_val(payload.src_ip)
            or _clean_pivot_val(payload.dest_ip)
            or _clean_pivot_val(payload.username)
            or raw_entity
            or _clean_pivot_val(payload.tenant_id)
            or ""
        ).strip()
        try:
            inp = self.query_one("#s1-filter-input", Input)
            with inp.prevent(Input.Changed):
                inp.value = search_term
        except Exception:
            pass

        self.set_status(
            f"Pivot received from {payload.source_tab or 'workbench'}: "
            f"view={target_view} filter={search_term or '*'}."
        )
        self._load_view_worker(self._current_view, self._sites_submode)

    # ------------------------------------------------------------------
    # UI Event Handlers (Sub-Workbenches, Tier Pills, Scope, Filters)
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#s1-wb-alerts-btn")
    def handle_wb_alerts(self) -> None:
        self._switch_view("threats")

    @on(Button.Pressed, "#s1-wb-sites-btn")
    def handle_wb_sites(self) -> None:
        self._switch_view("sites_activities", sites_submode="sites")

    @on(Button.Pressed, "#s1-wb-users-btn")
    def handle_wb_users(self) -> None:
        self._switch_view("users_rbac")

    @on(Button.Pressed, "#s1-wb-exclusions-btn")
    def handle_wb_exclusions(self) -> None:
        self._switch_view("exclusions")

    @on(Button.Pressed, "#s1-wb-agents-btn")
    def handle_wb_agents(self) -> None:
        self._switch_view("endpoints")

    @on(Button.Pressed, "#s1-goto-blocklist-btn")
    def handle_goto_blocklist(self) -> None:
        self._switch_view("blocklist")

    @on(Button.Pressed, "#s1-goto-agents-btn")
    def handle_goto_agents(self) -> None:
        self._switch_view("endpoints")

    def _set_tier_filter(self, tier: str) -> None:
        self._tier_filter = tier
        self._sync_tier_pills()
        self._refresh_site_multiselect()
        if self._table_ready:
            self._apply_local_filter()
        self.set_status(f"Tier filter set to: {tier}")

    @on(Button.Pressed, "#s1-tier-all-btn")
    def handle_tier_all(self) -> None:
        self._set_tier_filter("ALL")

    @on(Button.Pressed, "#s1-tier-mdr-btn")
    def handle_tier_mdr(self) -> None:
        self._set_tier_filter("MDR")

    @on(Button.Pressed, "#s1-tier-mssp-btn")
    def handle_tier_mssp(self) -> None:
        self._set_tier_filter("MSSP")

    @on(Button.Pressed, "#s1-tier-other-btn")
    def handle_tier_other(self) -> None:
        self._set_tier_filter("Other")

    @on(Input.Changed, "#s1-site-search-input")
    def handle_site_search_changed(self) -> None:
        self._refresh_site_multiselect()

    @on(Button.Pressed, "#s1-site-load-btn")
    def handle_site_selector_load(self) -> None:
        self._load_sites_cache_worker()

    @on(Button.Pressed, "#s1-site-select-all-btn")
    def handle_site_select_all(self) -> None:
        for s in self._cached_sites:
            sid = str(s.get("id") or "").strip()
            tier = str(s.get("tier") or "Other")
            if sid and (self._tier_filter == "ALL" or tier == self._tier_filter):
                self._selected_site_ids.add(sid)
        self._refresh_site_multiselect()
        if self._table_ready:
            self._apply_local_filter()

    @on(Button.Pressed, "#s1-site-clear-btn")
    def handle_site_clear_scope(self) -> None:
        self._selected_site_ids.clear()
        self._refresh_site_multiselect()
        if self._table_ready:
            self._apply_local_filter()

    @on(SelectionList.SelectedChanged, "#s1-site-multiselect")
    def handle_site_multiselect_changed(self) -> None:
        try:
            sel_list = self.query_one("#s1-site-multiselect", SelectionList)
            self._selected_site_ids = {str(v) for v in sel_list.selected}
            self.query_one("#s1-scope-collapsible", Collapsible).title = (
                f"Multi-Site Scope Selector ({len(self._selected_site_ids)} selected)"
            )
        except Exception:
            pass
        if self._table_ready:
            self._apply_local_filter()

    @on(Select.Changed, "#s1-view-select")
    def handle_view_changed(self, event: Select.Changed) -> None:
        val = str(event.value or "endpoints")
        if val == self._current_view:
            return
        self._switch_view(val)

    @on(Select.Changed, "#s1-alert-source-select")
    def handle_alert_source_changed(self, event: Select.Changed) -> None:
        if self._syncing_s1_filters or event.value is Select.BLANK:
            return
        self._alert_source = str(event.value or "threats")
        self.set_status(f"Alert source set to {self._alert_source}. Click Refresh to load.")

    @on(Select.Changed, "#s1-grouping-select")
    def handle_grouping_changed(self, event: Select.Changed) -> None:
        if self._syncing_s1_filters or event.value is Select.BLANK:
            return
        self._grouping_mode = str(event.value or "flat")
        if self._table_ready:
            self._apply_local_filter()

    @on(Select.Changed, "#s1-users-mode-select")
    def handle_users_mode_changed(self, event: Select.Changed) -> None:
        if event.value is Select.BLANK:
            return
        self._users_submode = str(event.value or "console")

    @on(Input.Changed, "#s1-filter-input")
    def handle_filter_changed(self) -> None:
        if self._table_ready:
            self._apply_local_filter()

    @on(Select.Changed, "#s1-preset-select")
    def handle_preset_changed(self, event: Select.Changed) -> None:
        if self._syncing_s1_filters or event.value is Select.BLANK:
            return
        preset_id = str(event.value or "all")
        presets = S1_PRESETS_BY_VIEW.get(self._current_view, ())
        matched = next((p for p in presets if p.get("id") == preset_id), None)
        if matched is None:
            return
        self._active_preset_id = preset_id
        self._timeframe_filter = str(matched.get("timeframe") or "any")
        self._status_filter = str(matched.get("status") or "any")
        self._syncing_s1_filters = True
        try:
            tf_sel = self.query_one("#s1-timeframe-select", Select)
            with tf_sel.prevent(Select.Changed):
                tf_sel.value = self._timeframe_filter
            st_sel = self.query_one("#s1-status-select", Select)
            with st_sel.prevent(Select.Changed):
                st_sel.value = self._status_filter
        except Exception:
            pass
        finally:
            self._syncing_s1_filters = False
        if self._table_ready:
            if self._timeframe_needs_reload(self._timeframe_filter):
                self._load_view_worker(self._current_view, self._sites_submode)
            else:
                self._apply_local_filter()
        self.set_status(f"Applied preset: {matched.get('label')}")

    @on(Select.Changed, "#s1-timeframe-select")
    def handle_timeframe_changed(self, event: Select.Changed) -> None:
        if self._syncing_s1_filters or event.value is Select.BLANK:
            return
        new_tf = str(event.value or "any")
        self._timeframe_filter = new_tf
        if self._table_ready:
            if self._timeframe_needs_reload(new_tf):
                self._load_view_worker(self._current_view, self._sites_submode)
            else:
                self._apply_local_filter()

    @on(Select.Changed, "#s1-status-select")
    def handle_status_filter_changed(self, event: Select.Changed) -> None:
        if self._syncing_s1_filters or event.value is Select.BLANK:
            return
        self._status_filter = str(event.value or "any")
        if self._table_ready:
            self._apply_local_filter()

    @on(Button.Pressed, "#s1-clear-filter-btn")
    def handle_clear_filters(self) -> None:
        self._tier_filter = "ALL"
        self._grouping_mode = "flat"
        self._selected_site_ids.clear()
        self._sync_tier_pills()
        self._sync_filter_controls_for_view()
        try:
            inp = self.query_one("#s1-filter-input", Input)
            with inp.prevent(Input.Changed):
                inp.value = ""
            grp = self.query_one("#s1-grouping-select", Select)
            with grp.prevent(Select.Changed):
                grp.value = "flat"
        except Exception:
            pass
        self._refresh_site_multiselect()
        if self._table_ready:
            self._apply_local_filter()
        self.set_status(f"Reset filters for SentinelOne {self._current_view} view.")

    @on(DataTable.RowHighlighted, "#s1-table")
    def handle_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        rec = self._record_for_row_index(event.cursor_row)
        if rec is not None:
            self._select_record(rec)

    @on(DataTable.RowSelected, "#s1-table")
    def handle_row_selected(self, event: DataTable.RowSelected) -> None:
        rec = self._record_for_row_index(event.cursor_row)
        if rec is None:
            return
        if rec.get("_is_group_header"):
            gkey = str(rec.get("_group_key") or "")
            if gkey in self._expanded_groups:
                self._expanded_groups.remove(gkey)
            else:
                self._expanded_groups.add(gkey)
            self._apply_local_filter()
            return
        self._select_record(rec)

    @on(Button.Pressed, "#s1-refresh-btn")
    def handle_refresh(self) -> None:
        self._sync_admin_badge()
        self._load_view_worker(self._current_view, self._sites_submode)

    @on(Button.Pressed, "#s1-check-btn")
    def handle_check_connection(self) -> None:
        self._check_connection_worker()

    @on(Button.Pressed, "#s1-sites-btn")
    def handle_load_sites(self) -> None:
        self._sites_submode = "sites"
        self._load_view_worker("sites_activities", "sites")

    @on(Button.Pressed, "#s1-activities-btn")
    def handle_load_activities(self) -> None:
        self._sites_submode = "activities"
        self._load_view_worker("sites_activities", "activities")

    @on(Button.Pressed, "#s1-users-load-btn")
    def handle_load_users(self) -> None:
        self._load_view_worker("users_rbac", self._users_submode)

    @on(Button.Pressed, "#s1-pivot-es-btn")
    def handle_pivot_es(self) -> None:
        self._emit_pivot_target("tab-splunk-es")

    @on(Button.Pressed, "#s1-pivot-rf-btn")
    def handle_pivot_rf(self) -> None:
        self._emit_pivot_target("tab-rf-intel")

    @on(Button.Pressed, "#s1-pivot-llm-btn")
    def handle_pivot_llm(self) -> None:
        self._emit_pivot_target("tab-llm")

    # ------------------------------------------------------------------
    # Endpoint Active-Response & Admin Actions
    # ------------------------------------------------------------------

    def _confirm_endpoint_action(
        self,
        *,
        action_key: str,
        title: str,
        verb: str,
        confirm_label: str,
        require_admin: bool = False,
    ) -> None:
        if require_admin and not self._require_admin_view(verb):
            return
        rec = self._require_selected("endpoint")
        if rec is None:
            return
        agent_id = str(rec.get("id") or "").strip()
        hostname = str(rec.get("computerName") or agent_id)
        if not agent_id:
            self.set_status("Selected endpoint record is missing an agent ID.")
            return
        if self._block_if_dry_run(verb, f"endpoint {hostname} ({agent_id})"):
            return
        self.confirm_destructive_action(
            title=title,
            message=f"Execute SentinelOne '{verb}' on endpoint {hostname}?",
            details=f"Agent ID: {agent_id}\nHostname: {hostname}\nSite: {rec.get('siteName') or '-'}",
            confirm_label=confirm_label,
            on_approved=lambda: self._endpoint_action_worker(action_key, agent_id, hostname),
        )

    @on(Button.Pressed, "#s1-isolate-btn")
    def handle_isolate(self) -> None:
        self._confirm_endpoint_action(
            action_key="disconnect",
            title="Isolate Endpoint (Network Disconnect)",
            verb="Network Isolation",
            confirm_label="Approve Isolate",
        )

    @on(Button.Pressed, "#s1-reconnect-btn")
    def handle_reconnect(self) -> None:
        self._confirm_endpoint_action(
            action_key="connect",
            title="Reconnect Isolated Endpoint",
            verb="Network Reconnect",
            confirm_label="Approve Reconnect",
        )

    @on(Button.Pressed, "#s1-scan-btn")
    def handle_scan(self) -> None:
        self._confirm_endpoint_action(
            action_key="scan",
            title="Initiate Full Disk Scan",
            verb="Full Disk Scan",
            confirm_label="Approve Scan",
        )

    @on(Button.Pressed, "#s1-reboot-btn")
    def handle_reboot(self) -> None:
        self._confirm_endpoint_action(
            action_key="reboot",
            title="Reboot Endpoint",
            verb="Endpoint Reboot",
            confirm_label="Approve Reboot",
        )

    @on(Button.Pressed, "#s1-uninstall-btn")
    def handle_uninstall(self) -> None:
        self._confirm_endpoint_action(
            action_key="uninstall",
            title="Uninstall SentinelOne Agent",
            verb="Agent Uninstall",
            confirm_label="Approve Uninstall",
        )

    @on(Button.Pressed, "#s1-fetch-logs-btn")
    def handle_fetch_logs(self) -> None:
        self._confirm_endpoint_action(
            action_key="fetch_logs",
            title="Fetch Agent Diagnostic Logs",
            verb="Fetch Agent Logs",
            confirm_label="Approve Fetch Logs",
        )

    @on(Button.Pressed, "#s1-decommission-btn")
    def handle_decommission_agent(self) -> None:
        self._confirm_endpoint_action(
            action_key="decommission",
            title="Decommission SentinelOne Agent",
            verb="Decommission Agent",
            confirm_label="Approve Decommission",
            require_admin=True,
        )

    @on(Button.Pressed, "#s1-move-agent-btn")
    def handle_move_agent(self) -> None:
        if not self._require_admin_view("Move Agent to Site"):
            return
        rec = self._require_selected("endpoint")
        if rec is None:
            return
        agent_id = str(rec.get("id") or "").strip()
        hostname = str(rec.get("computerName") or agent_id)
        if not agent_id:
            self.set_status("Selected endpoint record is missing an agent ID.")
            return

        def _on_move(target_site_id: str | None) -> None:
            if not target_site_id:
                return
            if self._block_if_dry_run("Move Agent to Site", f"{hostname} -> {target_site_id}"):
                return
            self._move_agent_worker(agent_id, hostname, target_site_id)

        self.app.push_screen(
            S1MoveAgentModal(
                agent_summary=f"{hostname} ({agent_id})",
                sites=self._cached_sites,
                dry_run=self.effective_dry_run,
            ),
            _on_move,
        )

    # ------------------------------------------------------------------
    # Threat & Cloud Alert Triage / Mitigation Actions
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#s1-triage-btn")
    def handle_triage(self) -> None:
        part = self._selected_threat_partition_for_action()
        if part is None:
            return
        ep_ids, cl_ids, threat_name, rec = part
        all_ids = ep_ids + cl_ids
        raw_tinfo = rec.get("threatInfo")
        tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
        current_verdict = str(rec.get("analystVerdict") or tinfo.get("analystVerdict") or "")
        current_status = str(rec.get("incidentStatus") or tinfo.get("incidentStatus") or "")

        def _on_triage(result: dict[str, str] | None) -> None:
            if not result:
                return
            verdict = result.get("analyst_verdict", "").strip()
            status = result.get("incident_status", "").strip()
            note = result.get("note", "").strip()
            if not any((verdict, status, note)):
                self.set_status("No triage changes selected.")
                return
            if self._block_if_dry_run("Threat Triage", f"{', '.join(all_ids)}"):
                return
            self._triage_threat_worker(
                ep_ids,
                verdict,
                status,
                note,
                is_cloud=bool(cl_ids and not ep_ids),
                cloud_alert_ids=cl_ids,
            )

        self.app.push_screen(
            S1ThreatTriageModal(
                threat_id=all_ids[0] if len(all_ids) == 1 else f"{len(all_ids)} alerts",
                threat_name=threat_name,
                current_verdict=current_verdict,
                current_status=current_status,
                dry_run=self.effective_dry_run,
            ),
            _on_triage,
        )

    def _confirm_threat_mitigation(self, action: str, label: str) -> None:
        part = self._selected_threat_partition_for_action()
        if part is None:
            return
        ep_ids, _cl_ids, threat_name, _rec = part
        if not ep_ids:
            self.set_status("Cloud/STAR alerts support verdict & incident status updates (not endpoint mitigation).")
            return
        if self._block_if_dry_run(
            f"Threat Mitigation ({action})",
            f"threat {threat_name} ({len(ep_ids)} selected)",
        ):
            return
        self.confirm_destructive_action(
            title=f"SentinelOne Threat Mitigation: {label}",
            message=f"Run '{action}' mitigation on {threat_name} ({len(ep_ids)} threat(s))?",
            details=f"Threat IDs: {', '.join(ep_ids[:5])}\nAction: {action}",
            confirm_label=f"Approve {label}",
            on_approved=lambda: self._mitigate_threat_worker(ep_ids, action),
        )

    @on(Button.Pressed, "#s1-kill-btn")
    def handle_kill(self) -> None:
        self._confirm_threat_mitigation("kill", "Kill")

    @on(Button.Pressed, "#s1-quarantine-btn")
    def handle_quarantine(self) -> None:
        self._confirm_threat_mitigation("quarantine", "Quarantine")

    @on(Button.Pressed, "#s1-remediate-btn")
    def handle_remediate(self) -> None:
        self._confirm_threat_mitigation("remediate", "Remediate")

    @on(Button.Pressed, "#s1-rollback-btn")
    def handle_rollback(self) -> None:
        self._confirm_threat_mitigation("rollback", "Rollback")

    @on(Button.Pressed, "#s1-threat-exclude-btn")
    def handle_threat_exclude(self) -> None:
        if not self._require_admin_view("Add Threat to Exclusions"):
            return
        part = self._selected_threat_partition_for_action()
        if part is None:
            return
        ep_ids, cl_ids, threat_name, _rec = part
        if not ep_ids:
            msg = (
                "Cloud/STAR alerts cannot be added via endpoint threat exclusions; "
                "use Exclusions view."
            )
            self.set_status(msg)
            self.append_log(msg, level="WARNING")
            self.notify_user(msg, title="Unsupported Alert Type", severity="warning")
            return
        if self._block_if_dry_run(
            "Add Threat to Exclusions",
            f"threat {threat_name} ({len(ep_ids)} selected)",
        ):
            return
        details_lines = [
            f"Threat IDs: {', '.join(ep_ids[:5])}"
            + (f" (+{len(ep_ids) - 5} more)" if len(ep_ids) > 5 else ""),
            "Scope: site | Mode: suppress",
        ]
        if cl_ids:
            skip_note = (
                f"Skipped {len(cl_ids)} Cloud/STAR alert(s); "
                "use Exclusions view for Cloud/STAR alerts."
            )
            details_lines.append(skip_note)
            self.set_status(f"Excluding {len(ep_ids)} endpoint threat(s); {skip_note}")
        self.confirm_destructive_action(
            title="Add Threat to SentinelOne Exclusions",
            message=(
                f"Add {len(ep_ids)} endpoint threat(s) for '{threat_name}' "
                "to SentinelOne exclusions?"
                if len(ep_ids) > 1 or cl_ids
                else f"Add threat '{threat_name}' to SentinelOne exclusions?"
            ),
            details="\n".join(details_lines),
            confirm_label="Approve Exclusion",
            on_approved=lambda: self._threat_exclude_worker(ep_ids),
        )

    # ------------------------------------------------------------------
    # Exclusions, Site-to-Site Cloning & Blocklist (Admin Gated)
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#s1-create-excl-btn")
    def handle_create_exclusion(self) -> None:
        if not self._require_admin_view("Create Exclusion"):
            return

        def _on_create(result: dict[str, str] | None) -> None:
            if not result:
                return
            if self._block_if_dry_run("Create Exclusion", result.get("value", "")):
                return
            self._create_exclusion_worker(result)

        self.app.push_screen(
            S1CreateExclusionModal(dry_run=self.effective_dry_run),
            _on_create,
        )

    @on(Button.Pressed, "#s1-edit-excl-btn")
    def handle_edit_exclusion(self) -> None:
        if not self._require_admin_view("Edit Exclusion"):
            return
        rec = self._require_selected("exclusion")
        if rec is None:
            return

        def _on_edit(result: dict[str, str] | None) -> None:
            if not result:
                return
            if self._block_if_dry_run("Edit Exclusion", result.get("value", "")):
                return
            self._edit_exclusion_worker(result)

        self.app.push_screen(
            S1EditExclusionModal(exclusion=rec, dry_run=self.effective_dry_run),
            _on_edit,
        )

    @on(Button.Pressed, "#s1-delete-excl-btn")
    def handle_delete_exclusion(self) -> None:
        if not self._require_admin_view("Delete Exclusion"):
            return
        rec = self._require_selected("exclusion")
        if rec is None:
            return
        excl_id = str(rec.get("id") or "").strip()
        val = str(rec.get("value") or excl_id)
        excl_type = str(rec.get("type") or "").strip() or None
        if self._block_if_dry_run("Delete Exclusion", f"{val} ({excl_id})"):
            return
        self.confirm_destructive_action(
            title="Delete SentinelOne Exclusion",
            message=f"Delete exclusion '{val}'?",
            details=f"Exclusion ID: {excl_id}\nType: {excl_type or '-'}",
            confirm_label="Approve Delete",
            on_approved=lambda: self._delete_exclusion_worker(excl_id, excl_type),
        )

    @on(Button.Pressed, "#s1-clone-excl-btn")
    def handle_clone_exclusions(self) -> None:
        if not self._require_admin_view("Clone Exclusions Site-to-Site"):
            return
        sites = list(self._cached_sites)
        if not sites and self._selected_record and self._selected_record.get("siteId"):
            sites = [
                {
                    "id": str(self._selected_record.get("siteId")),
                    "name": str(self._selected_record.get("siteName") or self._selected_record.get("siteId")),
                }
            ]

        def _plan_fn(src_id: str, dst_id: str, include_parents: bool) -> dict[str, Any]:
            client = self._get_s1_client()
            src_name = next(
                (str(s.get("name") or src_id) for s in sites if str(s.get("id") or "") == src_id),
                src_id,
            )
            return client.plan_clone_exclusions(
                src_id,
                dst_id,
                source_site_name=src_name,
                include_source_parents=include_parents,
            )

        def _on_clone(result: dict[str, Any] | None) -> None:
            if not result:
                return
            if self._block_if_dry_run(
                "Clone Site Exclusions",
                f"{result['source_site_id']} -> {result['target_site_id']}",
            ):
                return
            self._clone_exclusions_worker(result)

        self.app.push_screen(
            CloneExclusionsModal(
                sites=sites,
                plan_fn=_plan_fn,
                dry_run=self.effective_dry_run,
            ),
            _on_clone,
        )

    @on(Button.Pressed, "#s1-add-block-btn")
    def handle_add_blocklist(self) -> None:
        if not self._require_admin_view("Add Blocklist SHA-1"):
            return

        def _on_add(result: dict[str, str] | None) -> None:
            if not result:
                return
            if self._block_if_dry_run("Add Blocklist SHA-1", result.get("value", "")):
                return
            site_ids = sorted(self._selected_site_ids) if self._selected_site_ids else None
            self._add_blocklist_worker(result, site_ids=site_ids)

        self.app.push_screen(
            S1AddBlocklistModal(dry_run=self.effective_dry_run),
            _on_add,
        )

    @on(Button.Pressed, "#s1-delete-block-btn")
    def handle_delete_blocklist(self) -> None:
        if not self._require_admin_view("Remove Blocklist Entry"):
            return
        rec = self._require_selected("blocklist entry")
        if rec is None:
            return
        entry_id = str(rec.get("id") or "").strip()
        sha1 = str(rec.get("value") or entry_id)
        if self._block_if_dry_run("Remove Blocklist Entry", f"{sha1} ({entry_id})"):
            return
        self.confirm_destructive_action(
            title="Remove SHA-1 from SentinelOne Blocklist",
            message=f"Remove hash '{sha1}' from the SentinelOne blocklist?",
            details=f"Restriction ID: {entry_id}\nSHA-1: {sha1}",
            confirm_label="Approve Remove",
            on_approved=lambda: self._delete_blocklist_worker(entry_id),
        )

    # ------------------------------------------------------------------
    # Sites Admin Actions (Admin Gated)
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#s1-site-create-btn")
    def handle_create_site(self) -> None:
        if not self._require_admin_view("Create Site"):
            return

        def _on_save(result: dict[str, Any] | None) -> None:
            if not result:
                return
            if self._block_if_dry_run("Create Site", str(result.get("name") or "")):
                return
            self._site_mutation_worker("create", result)

        self.app.push_screen(
            S1SiteModal(
                mode="create",
                sites=self._cached_sites,
                dry_run=self.effective_dry_run,
            ),
            _on_save,
        )

    @on(Button.Pressed, "#s1-site-edit-btn")
    def handle_edit_site(self) -> None:
        if not self._require_admin_view("Edit Site"):
            return
        rec = self._require_selected_site("Edit Site")
        if rec is None:
            return

        def _on_save(result: dict[str, Any] | None) -> None:
            if not result:
                return
            if self._block_if_dry_run("Edit Site", str(result.get("name") or "")):
                return
            self._site_mutation_worker("edit", result)

        self.app.push_screen(
            S1SiteModal(
                mode="edit",
                site=rec,
                sites=self._cached_sites,
                dry_run=self.effective_dry_run,
            ),
            _on_save,
        )

    @on(Button.Pressed, "#s1-site-duplicate-btn")
    def handle_duplicate_site(self) -> None:
        if not self._require_admin_view("Duplicate Site"):
            return
        rec = self._require_selected_site("Duplicate Site")
        if rec is None:
            return

        def _on_save(result: dict[str, Any] | None) -> None:
            if not result:
                return
            if self._block_if_dry_run("Duplicate Site", str(result.get("name") or "")):
                return
            self._site_mutation_worker("duplicate", result)

        self.app.push_screen(
            S1SiteModal(
                mode="duplicate",
                site=rec,
                sites=self._cached_sites,
                dry_run=self.effective_dry_run,
            ),
            _on_save,
        )

    @on(Button.Pressed, "#s1-site-policy-btn")
    def handle_site_policy(self) -> None:
        rec = self._require_selected_site("Site Policy")
        if rec is None:
            return
        site_id = str(rec.get("id") or "").strip()
        site_name = str(rec.get("name") or site_id)
        if not site_id:
            return
        self._load_site_policy_worker(site_id, site_name)

    @on(Button.Pressed, "#s1-site-expire-btn")
    def handle_expire_site(self) -> None:
        if not self._require_admin_view("Expire Site"):
            return
        rec = self._require_selected_site("Expire Site")
        if rec is None:
            return
        site_id = str(rec.get("id") or "").strip()
        site_name = str(rec.get("name") or site_id)
        if self._block_if_dry_run("Expire Site", f"{site_name} ({site_id})"):
            return
        self.confirm_destructive_action(
            title="Expire SentinelOne Site Now",
            message=f"Immediately expire site '{site_name}' ({site_id})?",
            details="Agents in an expired site lose active console licensing.",
            confirm_label="Approve Expire",
            on_approved=lambda: self._site_lifecycle_worker("expire", site_id, site_name),
        )

    @on(Button.Pressed, "#s1-site-reactivate-btn")
    def handle_reactivate_site(self) -> None:
        if not self._require_admin_view("Reactivate Site"):
            return
        rec = self._require_selected_site("Reactivate Site")
        if rec is None:
            return
        site_id = str(rec.get("id") or "").strip()
        site_name = str(rec.get("name") or site_id)
        if self._block_if_dry_run("Reactivate Site", f"{site_name} ({site_id})"):
            return
        self.confirm_destructive_action(
            title="Reactivate SentinelOne Site",
            message=f"Reactivate site '{site_name}' ({site_id}) with unlimited expiration?",
            confirm_label="Approve Reactivate",
            on_approved=lambda: self._site_lifecycle_worker("reactivate", site_id, site_name),
        )

    @on(Button.Pressed, "#s1-site-rotate-token-btn")
    def handle_rotate_site_token(self) -> None:
        if not self._require_admin_view("Rotate Site Registration Token"):
            return
        rec = self._require_selected_site("Rotate Site Token")
        if rec is None:
            return
        site_id = str(rec.get("id") or "").strip()
        site_name = str(rec.get("name") or site_id)
        if self._block_if_dry_run("Rotate Site Token", f"{site_name} ({site_id})"):
            return
        self.confirm_destructive_action(
            title="Rotate Site Registration Token",
            message=f"Regenerate agent registration token for site '{site_name}'?",
            details="Previous registration tokens for this site will be invalidated.",
            confirm_label="Approve Rotate",
            on_approved=lambda: self._site_lifecycle_worker("rotate_token", site_id, site_name),
        )

    @on(Button.Pressed, "#s1-site-copy-token-btn")
    def handle_copy_site_token(self) -> None:
        rec = self._require_selected_site("Copy Site Token")
        if rec is None:
            return
        site_id = str(rec.get("id") or "").strip()
        site_name = str(rec.get("name") or site_id)
        if not site_id:
            return
        self._fetch_site_token_worker(site_id, site_name)

    @on(Button.Pressed, "#s1-site-delete-btn")
    def handle_delete_site(self) -> None:
        if not self._require_admin_view("Delete Site"):
            return
        rec = self._require_selected_site("Delete Site")
        if rec is None:
            return
        site_id = str(rec.get("id") or "").strip()
        site_name = str(rec.get("name") or site_id).strip()
        tier, _ten, _sid, _sname = self._classify_record_tier(rec)
        active_agents = rec.get("activeLicenses", rec.get("totalAgents", 0))

        def _on_confirm(approved: bool | None) -> None:
            if not approved:
                return
            if self._block_if_dry_run("Delete Site", f"{site_name} ({site_id})"):
                return
            self._site_lifecycle_worker("delete", site_id, site_name)

        self.app.push_screen(
            ConfirmDeleteSiteModal(
                site_id=site_id,
                site_name=site_name,
                tier=tier,
                active_agents=active_agents,
                dry_run=self.effective_dry_run,
            ),
            _on_confirm,
        )

    # ------------------------------------------------------------------
    # Users & RBAC Admin Actions (Admin Gated)
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#s1-user-create-btn")
    def handle_create_user(self) -> None:
        if not self._require_admin_view("Create User / Service User"):
            return
        kind = "service" if self._users_submode == "service" else "console"
        existing = [r for r in self._records if r.get("_s1_user_kind") in {"Console User", "Service User"}]

        def _on_save(result: dict[str, Any] | None) -> None:
            if not result:
                return
            if self._block_if_dry_run("Create User", str(result.get("email") or result.get("name") or "")):
                return
            self._user_mutation_worker(result)

        self.app.push_screen(
            S1UserModal(
                mode="create",
                kind=kind,
                existing_users=existing,
                roles=self._cached_roles,
                sites=self._cached_sites,
                dry_run=self.effective_dry_run,
            ),
            _on_save,
        )

    @on(Button.Pressed, "#s1-user-edit-btn")
    def handle_edit_user(self) -> None:
        if not self._require_admin_view("Edit User / Service User"):
            return
        rec = self._require_selected_user("Edit User")
        if rec is None:
            return
        kind = "service" if rec.get("_s1_user_kind") == "Service User" else "console"
        existing = [r for r in self._records if r.get("_s1_user_kind") in {"Console User", "Service User"}]

        def _on_save(result: dict[str, Any] | None) -> None:
            if not result:
                return
            if self._block_if_dry_run("Edit User", str(result.get("user_id") or "")):
                return
            self._user_mutation_worker(result)

        self.app.push_screen(
            S1UserModal(
                mode="edit",
                kind=kind,
                user=rec,
                existing_users=existing,
                roles=self._cached_roles,
                sites=self._cached_sites,
                dry_run=self.effective_dry_run,
            ),
            _on_save,
        )

    @on(Button.Pressed, "#s1-user-reset-pw-btn")
    def handle_reset_user_password(self) -> None:
        if not self._require_admin_view("Send Reset Password Email"):
            return
        rec = self._require_selected_user("Reset Password")
        if rec is None:
            return
        uid = str(rec.get("id") or "").strip()
        email = str(rec.get("email") or uid)
        if self._block_if_dry_run("Reset Password Email", email):
            return
        self.confirm_destructive_action(
            title="Send Reset Password Email",
            message=f"Send password reset email to {email} ({uid})?",
            confirm_label="Approve Reset",
            on_approved=lambda: self._user_action_worker("reset_pw", uid, email),
        )

    @on(Button.Pressed, "#s1-user-reset-2fa-btn")
    def handle_reset_user_2fa(self) -> None:
        if not self._require_admin_view("Reset User 2FA"):
            return
        rec = self._require_selected_user("Reset 2FA")
        if rec is None:
            return
        uid = str(rec.get("id") or "").strip()
        email = str(rec.get("email") or uid)
        if self._block_if_dry_run("Reset 2FA", email):
            return
        self.confirm_destructive_action(
            title="Reset User 2FA",
            message=f"Reset 2FA enrollment for {email} ({uid})?",
            confirm_label="Approve Reset 2FA",
            on_approved=lambda: self._user_action_worker("reset_2fa", uid, email),
        )

    @on(Button.Pressed, "#s1-user-logout-btn")
    def handle_logout_session(self) -> None:
        if not self._require_admin_view("Logout SentinelOne Session"):
            return
        if self._block_if_dry_run("Logout SentinelOne Session", "current API token"):
            return
        self.confirm_destructive_action(
            title="Logout Current SentinelOne API Session",
            message="Invalidate the currently authenticated SentinelOne API session?",
            confirm_label="Approve Logout",
            on_approved=lambda: self._user_action_worker("logout", "", "session"),
        )

    @on(Button.Pressed, "#s1-user-delete-btn")
    def handle_delete_user(self) -> None:
        if not self._require_admin_view("Delete User"):
            return
        rec = self._require_selected_user("Delete User")
        if rec is None:
            return
        uid = str(rec.get("id") or "").strip()
        label = str(rec.get("email") or rec.get("fullName") or rec.get("name") or uid)
        is_service = rec.get("_s1_user_kind") == "Service User"
        if self._block_if_dry_run("Delete User", f"{label} ({uid})"):
            return
        self.confirm_destructive_action(
            title="Delete SentinelOne User",
            message=f"Permanently delete '{label}' ({uid})?",
            confirm_label="Approve Delete",
            on_approved=lambda: self._user_action_worker(
                "delete_service" if is_service else "delete",
                uid,
                label,
            ),
        )

    # ------------------------------------------------------------------
    # Background Workers
    # ------------------------------------------------------------------

    @work(thread=True, exit_on_error=False)
    def _check_connection_worker(self) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                info = client.check_connection()
            build = info.get("build") or info.get("latestAgentVersion") or "ok"
            msg = f"SentinelOne connected: {client.console_url} (build={build})"
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Connected")
        except Exception as exc:
            self._report_s1_error("SentinelOne Connection Check", exc)

    @work(thread=True, exit_on_error=False)
    def _load_sites_cache_worker(self) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()

                def _on_site_page(loaded: int, total: int | None) -> None:
                    suffix = f"{loaded}/{total}" if total is not None else f"{loaded}"
                    self.set_status(f"Loading SentinelOne sites... ({suffix} loaded)")

                sites = client.list_sites(on_page=_on_site_page)
            self.run_on_ui(self._populate_site_selector, sites)
            self.set_status(f"Loaded {len(sites)} site(s) into Multi-Site Scope Selector.")
        except Exception as exc:
            self._report_s1_error("SentinelOne Load Sites Scope", exc)

    @staticmethod
    def _timeframe_query_bounds(timeframe: str) -> tuple[str | None, str | None]:
        """Convert a timeframe filter key into ISO-8601 UTC ``(created_after, created_before)``."""
        start_dt, end_dt = compute_timeframe_bounds(timeframe)
        created_after = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if start_dt is not None else None
        created_before = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if end_dt is not None else None
        return created_after, created_before

    def _timeframe_needs_reload(self, new_tf: str) -> bool:
        """Return True if ``new_tf`` requires a wider server fetch than the loaded window."""
        if self._current_view != "threats" or self._loaded_timeframe_filter is None:
            return False
        if self._loaded_timeframe_filter == "any" or new_tf == self._loaded_timeframe_filter:
            return False
        if new_tf == "any":
            return True
        old_start, old_end = compute_timeframe_bounds(self._loaded_timeframe_filter)
        new_start, new_end = compute_timeframe_bounds(new_tf)
        if old_start is not None and (new_start is None or new_start < old_start):
            return True
        if old_end is not None and (new_end is None or new_end > old_end):
            return True
        return False

    @work(thread=True, exit_on_error=False)
    def _load_view_worker(self, view: str, submode: str = "sites") -> None:
        self._load_seq += 1
        my_seq = self._load_seq
        active_tf = self._timeframe_filter if view == "threats" else "any"
        created_after, created_before = (
            self._timeframe_query_bounds(active_tf) if view == "threats" else (None, None)
        )
        try:
            tf_suffix = (
                f" ({timeframe_label(active_tf)})"
                if view == "threats" and active_tf != "any"
                else ""
            )
            self.set_status(f"Loading SentinelOne {view}{tf_suffix}...")
            site_filter = sorted(self._selected_site_ids) if self._selected_site_ids else None

            def _on_page(loaded: int, total: int | None) -> None:
                if my_seq != self._load_seq:
                    return
                suffix = f"{loaded}/{total}" if total is not None else f"{loaded}"
                self.set_status(f"Loading SentinelOne {view}{tf_suffix}... ({suffix} loaded)")

            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                if view == "endpoints":
                    records = client.list_agents(site_ids=site_filter, on_page=_on_page)
                elif view == "threats":
                    if self._alert_source == "cloud":
                        raw_cloud = client.list_cloud_alerts(
                            site_ids=site_filter,
                            created_after=created_after,
                            created_before=created_before,
                            on_page=_on_page,
                        )
                        records = sort_s1_records_newest_first(
                            [client.normalize_alert(c, source_kind="cloud_alert") for c in raw_cloud]
                        )
                    elif self._alert_source == "unified":
                        records = client.list_unified_alerts(
                            site_ids=site_filter,
                            sites=self._cached_sites or None,
                            created_after=created_after,
                            created_before=created_before,
                            on_page=_on_page,
                        )
                    else:
                        records = client.list_threats(
                            site_ids=site_filter,
                            created_after=created_after,
                            created_before=created_before,
                            on_page=_on_page,
                        )
                elif view == "exclusions":
                    records = client.list_exclusions(site_ids=site_filter, on_page=_on_page)
                elif view == "blocklist":
                    records = client.list_blocklist(site_ids=site_filter, on_page=_on_page)
                elif view == "users_rbac":
                    mode = submode if submode in {"console", "service", "roles"} else self._users_submode
                    if mode == "service":
                        raw = client.list_service_users(site_ids=site_filter, on_page=_on_page)
                        records = [{**item, "_s1_user_kind": "Service User"} for item in raw]
                    elif mode == "roles":
                        raw = client.list_rbac_roles(site_ids=site_filter, on_page=_on_page)
                        if my_seq != self._load_seq:
                            return
                        self._cached_roles = list(raw)
                        records = [{**item, "_s1_user_kind": "RBAC Role"} for item in raw]
                    else:
                        raw = client.list_users(site_ids=site_filter, on_page=_on_page)
                        records = [{**item, "_s1_user_kind": "Console User"} for item in raw]
                elif submode == "activities":
                    raw = client.list_activities(site_ids=site_filter, on_page=_on_page)
                    records = [{**item, "_s1_kind": "activity"} for item in raw]
                else:
                    raw = client.list_sites(on_page=_on_page)
                    records = [{**item, "_s1_kind": "site"} for item in raw]
                    if my_seq != self._load_seq:
                        return
                    self.run_on_ui(self._populate_site_selector, raw)

            if my_seq != self._load_seq:
                return
            if view == "threats":
                self._loaded_timeframe_filter = active_tf
                self._hydrated_from_cache = False
                if (
                    active_tf == "last_24h"
                    and self._alert_source == "threats"
                    and not site_filter
                ):
                    cache = getattr(self.app, "alert_cache", None)
                    if cache is not None:
                        cache.put(
                            CACHE_SOURCE_S1,
                            records,
                            timeframe="last_24h",
                            meta={"sites": list(self._cached_sites)},
                        )
            self.run_on_ui(self._populate_table, records)
            msg = f"Loaded {len(records)} SentinelOne {view}{tf_suffix} record(s)."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            if my_seq == self._load_seq:
                self._report_s1_error(f"SentinelOne Load ({view})", exc)

    @work(thread=True, exit_on_error=False)
    def _endpoint_action_worker(self, action_key: str, agent_id: str, hostname: str) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                if action_key == "disconnect":
                    res = client.disconnect_agent([agent_id])
                elif action_key == "connect":
                    res = client.connect_agent([agent_id])
                elif action_key == "scan":
                    res = client.initiate_scan([agent_id])
                elif action_key == "reboot":
                    res = client.reboot_agent([agent_id])
                elif action_key == "uninstall":
                    res = client.uninstall_agent([agent_id])
                elif action_key == "fetch_logs":
                    res = client.fetch_agent_logs([agent_id])
                elif action_key == "decommission":
                    res = client.decommission_agents([agent_id])
                else:
                    raise ValueError(f"Unsupported endpoint action: {action_key}")
            affected = (
                res.get("data", {}).get("affected")
                if isinstance(res.get("data"), dict)
                else 1
            )
            msg = f"SentinelOne '{action_key}' completed for {hostname} ({agent_id}): affected={affected}"
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Endpoint Action")
        except Exception as exc:
            self._report_s1_error(f"SentinelOne Endpoint {action_key}", exc)

    @work(thread=True, exit_on_error=False)
    def _move_agent_worker(self, agent_id: str, hostname: str, target_site_id: str) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                res = client.move_agents_to_site([agent_id], target_site_id)
            affected = (
                res.get("data", {}).get("affected")
                if isinstance(res.get("data"), dict)
                else 1
            )
            msg = f"Moved agent {hostname} ({agent_id}) to site {target_site_id}: affected={affected}"
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Agent Moved")
        except Exception as exc:
            self._report_s1_error("SentinelOne Move Agent", exc)

    @work(thread=True, exit_on_error=False)
    def _triage_threat_worker(
        self,
        threat_ids: Sequence[str] | str | None,
        verdict: str,
        status: str,
        note: str,
        *,
        is_cloud: bool = False,
        cloud_alert_ids: Sequence[str] | str | None = None,
    ) -> None:
        try:
            if cloud_alert_ids is not None:
                ep_ids = self._clean_id_seq(threat_ids)
                cl_ids = self._clean_id_seq(cloud_alert_ids)
            elif is_cloud:
                ep_ids = []
                cl_ids = self._clean_id_seq(threat_ids)
            else:
                ep_ids = self._clean_id_seq(threat_ids)
                cl_ids = []
            if not ep_ids and not cl_ids:
                self.run_on_ui(self.set_status, "No valid alert or threat IDs selected to triage.")
                return
            all_ids = ep_ids + cl_ids
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                applied: list[str] = []
                if verdict:
                    if ep_ids:
                        client.update_threat_verdict(ep_ids, verdict)
                    if cl_ids:
                        client.update_cloud_alert_verdict(cl_ids, verdict)
                    applied.append(f"verdict={verdict}")
                if status:
                    if ep_ids:
                        client.update_threat_incident_status(ep_ids, status)
                    if cl_ids:
                        client.update_cloud_alert_incident_status(cl_ids, status)
                    applied.append(f"status={status}")
                if note and ep_ids:
                    for tid in ep_ids:
                        client.add_threat_note(tid, note)
                    applied.append("note added")
            msg = f"Triaged {', '.join(all_ids)}: {', '.join(applied)}"
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Threat Triaged")
        except Exception as exc:
            self._report_s1_error("SentinelOne Threat Triage", exc)

    @work(thread=True, exit_on_error=False)
    def _mitigate_threat_worker(self, threat_ids: list[str], action: str) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                res = client.mitigate_threat(threat_ids, action)
            affected = (
                res.get("data", {}).get("affected")
                if isinstance(res.get("data"), dict)
                else len(threat_ids)
            )
            msg = (
                f"SentinelOne threat mitigation '{action}' on {len(threat_ids)} threat(s): "
                f"affected={affected}"
            )
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Threat Mitigation")
        except Exception as exc:
            self._report_s1_error(f"SentinelOne Mitigate ({action})", exc)

    @work(thread=True, exit_on_error=False)
    def _threat_exclude_worker(self, threat_ids: Sequence[str] | str | None) -> None:
        ids = self._clean_id_seq(threat_ids)
        if not ids:
            self.run_on_ui(self.set_status, "No valid endpoint threat IDs selected to exclude.")
            return
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                client.add_threat_to_exclusions(ids)
            msg = (
                f"Added {len(ids)} threat(s) ({', '.join(ids[:3])}"
                + (f", +{len(ids) - 3} more" if len(ids) > 3 else "")
                + ") to SentinelOne exclusions."
                if len(ids) > 1
                else f"Added threat {ids[0]} to SentinelOne exclusions."
            )
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Exclusion Added")
        except Exception as exc:
            self._report_s1_error("SentinelOne Add Threat Exclusion", exc)

    @work(thread=True, exit_on_error=False)
    def _create_exclusion_worker(self, payload: dict[str, str]) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                site_ids = sorted(self._selected_site_ids) if self._selected_site_ids else None
                client.create_exclusion(
                    exclusion_type=payload["type"],
                    os_type=payload["os_type"],
                    value=payload["value"],
                    description=payload.get("description", ""),
                    mode=payload.get("mode", "suppress"),
                    site_ids=site_ids,
                )
            msg = f"Created SentinelOne {payload['type']} exclusion: {payload['value']}"
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Exclusion Created")
        except Exception as exc:
            self._report_s1_error("SentinelOne Create Exclusion", exc)

    @work(thread=True, exit_on_error=False)
    def _edit_exclusion_worker(self, payload: dict[str, str]) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                client.update_exclusion(
                    payload["id"],
                    exclusion_type=payload["type"],
                    os_type=payload["os_type"],
                    value=payload["value"],
                    description=payload.get("description", ""),
                    mode=payload.get("mode", "suppress"),
                )
            msg = f"Updated SentinelOne exclusion {payload['id']}."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Exclusion Updated")
        except Exception as exc:
            self._report_s1_error("SentinelOne Update Exclusion", exc)

    @work(thread=True, exit_on_error=False)
    def _delete_exclusion_worker(self, excl_id: str, excl_type: str | None) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                client.delete_exclusions([excl_id], exclusion_type=excl_type)
            msg = f"Deleted SentinelOne exclusion {excl_id}."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Exclusion Deleted")
        except Exception as exc:
            self._report_s1_error("SentinelOne Delete Exclusion", exc)

    @work(thread=True, exit_on_error=False)
    def _clone_exclusions_worker(self, params: dict[str, Any]) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                res = client.clone_exclusions(
                    str(params["source_site_id"]),
                    str(params["target_site_id"]),
                    source_site_name=str(params.get("source_site_name") or ""),
                    dry_run=False,
                    requests_per_second=float(params.get("requests_per_second") or 15.0),
                    include_source_parents=bool(params.get("include_source_parents")),
                )
            raw_counts = res.get("counts")
            counts: dict[str, Any] = raw_counts if isinstance(raw_counts, dict) else {}
            msg = (
                f"Cloned exclusions {params['source_site_id']} -> {params['target_site_id']}: "
                f"created={counts.get('created', 0)}, "
                f"skipped={counts.get('skipped_duplicate', 0)}, "
                f"inherited={counts.get('inherited_from_account', 0)}, "
                f"failed={counts.get('failed', 0)}."
            )
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Exclusion Clone Complete")
        except Exception as exc:
            self._report_s1_error("SentinelOne Clone Exclusions", exc)

    @work(thread=True, exit_on_error=False)
    def _add_blocklist_worker(
        self,
        payload: dict[str, str],
        site_ids: list[str] | None = None,
    ) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                resolved_site_ids = (
                    list(site_ids)
                    if site_ids is not None
                    else (sorted(self._selected_site_ids) if self._selected_site_ids else None)
                )
                if resolved_site_ids is not None:
                    client.add_to_blocklist(
                        payload["value"],
                        os_type=payload.get("os_type", "windows"),
                        description=payload.get("description", ""),
                        site_ids=resolved_site_ids,
                    )
                else:
                    client.add_to_blocklist(
                        payload["value"],
                        os_type=payload.get("os_type", "windows"),
                        description=payload.get("description", ""),
                    )
            msg = f"Added SHA-1 {payload['value']} to SentinelOne blocklist."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Blocklist Updated")
        except Exception as exc:
            self._report_s1_error("SentinelOne Add Blocklist", exc)

    @work(thread=True, exit_on_error=False)
    def _delete_blocklist_worker(self, entry_id: str) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                client.remove_from_blocklist([entry_id])
            msg = f"Removed SentinelOne blocklist entry {entry_id}."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Blocklist Entry Removed")
        except Exception as exc:
            self._report_s1_error("SentinelOne Remove Blocklist", exc)

    @work(thread=True, exit_on_error=False)
    def _site_mutation_worker(self, op: str, params: dict[str, Any]) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                if op == "create":
                    res = client.create_site(
                        name=str(params["name"]),
                        account_id=str(params.get("account_id") or "") or None,
                        site_type=str(params.get("site_type") or "Paid"),
                        sku=str(params.get("sku") or "Complete"),
                        unlimited_licenses=bool(params.get("unlimited_licenses", True)),
                        total_licenses=params.get("total_licenses"),
                        description=str(params.get("description") or ""),
                        copy_policy_from_site_id=str(
                            params.get("copy_policy_from_site_id") or ""
                        )
                        or None,
                        clone_exclusions_from_site_id=str(
                            params.get("clone_exclusions_from_site_id") or ""
                        )
                        or None,
                    )
                    msg = f"Created SentinelOne site '{params['name']}' (id={res.get('id', '-')})."
                elif op == "edit":
                    res = client.update_site(
                        str(params["site_id"]),
                        name=str(params["name"]),
                        siteType=str(params.get("site_type") or "Paid"),
                        suite=str(params.get("suite") or "Complete"),
                        unlimitedLicenses=bool(params.get("unlimited_licenses", True)),
                        totalLicenses=params.get("total_licenses"),
                        description=str(params.get("description") or ""),
                    )
                    msg = f"Updated SentinelOne site '{params['name']}' ({params['site_id']})."
                else:
                    res = client.duplicate_site(
                        str(params["source_site_id"]),
                        str(params["name"]),
                        policy_source=str(params.get("policy_source") or "copy_source_site"),
                        copy_users=bool(params.get("copy_users", False)),
                        unlimited_licenses=bool(params.get("unlimited_licenses", True)),
                        total_licenses=params.get("total_licenses"),
                    )
                    msg = f"Duplicated site -> '{params['name']}' (id={res.get('id', '-')})."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Site Updated")
        except Exception as exc:
            self._report_s1_error(f"SentinelOne Site ({op})", exc)

    @work(thread=True, exit_on_error=False)
    def _load_site_policy_worker(self, site_id: str, site_name: str) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                policy = client.get_site_policy(site_id)

            def _open_modal() -> None:
                def _on_action(res: dict[str, Any] | None) -> None:
                    if not res:
                        return
                    if not self._require_admin_view("Modify Site Policy"):
                        return
                    if self._block_if_dry_run("Modify Site Policy", f"{site_name} ({site_id})"):
                        return
                    self._apply_site_policy_worker(site_id, site_name, res)

                self.app.push_screen(
                    S1SitePolicyModal(
                        site_id=site_id,
                        site_name=site_name,
                        policy=policy,
                        sites=self._cached_sites,
                        dry_run=self.effective_dry_run,
                    ),
                    _on_action,
                )

            self.run_on_ui(_open_modal)
        except Exception as exc:
            self._report_s1_error("SentinelOne Load Site Policy", exc)

    @work(thread=True, exit_on_error=False)
    def _apply_site_policy_worker(
        self,
        site_id: str,
        site_name: str,
        action_payload: dict[str, Any],
    ) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                if action_payload.get("action") == "revert":
                    client.revert_site_policy(site_id)
                    msg = f"Reverted policy for site {site_name} ({site_id})."
                else:
                    src_id = str(action_payload.get("source_site_id") or "").strip()
                    src_policy = client.get_site_policy(src_id)
                    client.update_site_policy(site_id, src_policy)
                    msg = f"Copied site policy {src_id} -> {site_name} ({site_id})."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Site Policy Updated")
        except Exception as exc:
            self._report_s1_error("SentinelOne Site Policy Update", exc)

    @work(thread=True, exit_on_error=False)
    def _fetch_site_token_worker(self, site_id: str, site_name: str) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                res = client.get_site_token(site_id)
            data = res.get("data") if isinstance(res.get("data"), dict) else res
            token = str(
                (data.get("token") if isinstance(data, dict) else None)
                or res.get("token")
                or ""
            ).strip()
            if token:
                self.run_on_ui(
                    self.copy_to_clipboard,
                    token,
                    label=f"Registration Token ({site_name})",
                )
            else:
                self.set_status(f"No registration token returned for {site_name}.")
        except Exception as exc:
            self._report_s1_error("SentinelOne Get Site Token", exc)

    @work(thread=True, exit_on_error=False)
    def _site_lifecycle_worker(self, op: str, site_id: str, site_name: str) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                if op == "expire":
                    client.expire_site(site_id)
                    msg = f"Expired SentinelOne site '{site_name}' ({site_id})."
                elif op == "reactivate":
                    client.reactivate_site(site_id, unlimited=True)
                    msg = f"Reactivated SentinelOne site '{site_name}' ({site_id})."
                elif op == "rotate_token":
                    client.regenerate_site_key(site_id)
                    msg = f"Rotated registration token for site '{site_name}' ({site_id})."
                elif op == "delete":
                    client.delete_site(
                        site_id,
                        confirm_site_name=site_name,
                        expected_site_name=site_name,
                    )
                    msg = f"Deleted SentinelOne site '{site_name}' ({site_id})."
                else:
                    raise ValueError(f"Unsupported site lifecycle op: {op}")
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Site Admin")
        except Exception as exc:
            self._report_s1_error(f"SentinelOne Site {op}", exc)

    @work(thread=True, exit_on_error=False)
    def _user_mutation_worker(self, params: dict[str, Any]) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                scope = str(params.get("scope") or "site")
                kind = str(params.get("kind") or "console")
                mode = str(params.get("mode") or "create")
                role_id = str(params.get("role_id") or "").strip()
                template_uid = str(params.get("template_user_id") or "").strip()
                target_sites = params.get("target_site_ids") or None

                scope_roles: list[dict[str, Any]] = []
                if template_uid:
                    cloned = client.clone_user_permissions(
                        template_uid,
                        target_site_ids=target_sites,
                        service_user=(kind == "service"),
                    )
                    scope = str(cloned.get("scope") or scope)
                    raw_roles = cloned.get("scopeRoles")
                    if isinstance(raw_roles, list):
                        scope_roles = raw_roles
                elif role_id:
                    if target_sites:
                        scope_roles = [{"id": sid, "roleId": role_id} for sid in target_sites]
                    else:
                        scope_roles = [{"roleId": role_id}]
                elif mode == "edit":
                    raw_existing = params.get("existing_scope_roles")
                    if not isinstance(raw_existing, Sequence) or isinstance(
                        raw_existing, (str, bytes)
                    ):
                        target_uid = str(params.get("user_id") or "").strip()
                        matched_user = next(
                            (
                                r
                                for r in self._records
                                if str(r.get("id") or "").strip() == target_uid
                            ),
                            None,
                        )
                        if isinstance(matched_user, Mapping):
                            raw_existing = matched_user.get("scopeRoles")
                    if isinstance(raw_existing, Sequence) and not isinstance(
                        raw_existing, (str, bytes)
                    ):
                        scope_roles = _sanitize_scope_roles(
                            [r for r in raw_existing if isinstance(r, Mapping)],
                            scope=scope,
                            target_site_ids=target_sites,
                        )

                if kind == "service":
                    if mode == "create":
                        client.create_service_user(
                            name=str(params["name"]),
                            scope=scope,
                            expiration_date=str(params["expiration_date"]),
                            scope_roles=scope_roles,
                        )
                        msg = f"Created SentinelOne service user '{params['name']}'."
                    else:
                        client.update_service_user(
                            str(params["user_id"]),
                            scope=scope,
                            scope_roles=scope_roles,
                        )
                        msg = f"Updated SentinelOne service user '{params['user_id']}'."
                else:
                    if mode == "create":
                        client.create_user(
                            email=str(params["email"]),
                            full_name=str(params["name"]),
                            scope=scope,
                            scope_roles=scope_roles,
                            two_fa_enabled=bool(params.get("two_fa_enabled", True)),
                        )
                        msg = f"Created SentinelOne user '{params['email']}'."
                    else:
                        client.update_user(
                            str(params["user_id"]),
                            scope=scope,
                            scope_roles=scope_roles,
                            full_name=str(params["name"]),
                            email=str(params["email"]),
                            two_fa_enabled=bool(params.get("two_fa_enabled", True)),
                        )
                        msg = f"Updated SentinelOne user '{params['user_id']}'."
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne User Admin")
        except Exception as exc:
            self._report_s1_error("SentinelOne User Admin", exc)

    @work(thread=True, exit_on_error=False)
    def _user_action_worker(self, op: str, user_id: str, label: str) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                if op == "reset_pw":
                    client.send_reset_password_email([user_id])
                    msg = f"Sent password reset email to {label}."
                elif op == "reset_2fa":
                    client.reset_2fa([user_id])
                    msg = f"Reset 2FA for {label}."
                elif op == "logout":
                    client.logout_user()
                    msg = "Logged out current SentinelOne API session."
                elif op == "delete":
                    client.delete_user(user_id)
                    msg = f"Deleted SentinelOne console user {label}."
                elif op == "delete_service":
                    client.delete_service_user(user_id)
                    msg = f"Deleted SentinelOne service user {label}."
                else:
                    raise ValueError(f"Unsupported user action: {op}")
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne User Action")
        except Exception as exc:
            self._report_s1_error(f"SentinelOne User {op}", exc)
