"""SentinelOne Management API v2.1 SOC workbench pane."""

from __future__ import annotations

import json
from typing import Any

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, RichLog, Select, Static

from soclens.config import get_sentinelone_config
from soclens.sentinelone import (
    SentinelOneAuthError,
    SentinelOneClient,
    SentinelOneError,
    SentinelOneRateLimitError,
)
from soclens.tui.filters import (
    S1_PRESETS_BY_VIEW,
    TIMEFRAME_OPTIONS,
    timeframe_label,
    timestamp_matches_timeframe,
)
from soclens.tui.modals import (
    S1AddBlocklistModal,
    S1CreateExclusionModal,
    S1ThreatTriageModal,
)
from soclens.tui.screens.base import BaseSocPane, DoubleClickDataTable

_VIEW_OPTIONS: list[tuple[str, str]] = [
    ("Endpoints", "endpoints"),
    ("Threats", "threats"),
    ("Exclusions", "exclusions"),
    ("Blocklist", "blocklist"),
    ("Sites & Activities", "sites_activities"),
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
        ("name", "Hostname", 0.24, 14),
        ("os", "OS", 0.14, 10),
        ("ip", "IP Address", 0.16, 12),
        ("network", "Network", 0.14, 10),
        ("infected", "Infected", 0.10, 8),
        ("site", "Site", 0.22, 12),
    ),
    "threats": (
        ("name", "Threat", 0.26, 14),
        ("host", "Endpoint", 0.18, 12),
        ("verdict", "Verdict", 0.16, 10),
        ("status", "Status", 0.14, 10),
        ("mitigation", "Mitigation", 0.14, 10),
        ("created", "Created", 0.12, 10),
    ),
    "exclusions": (
        ("type", "Type", 0.14, 10),
        ("os", "OS", 0.12, 8),
        ("value", "Value", 0.34, 16),
        ("mode", "Mode", 0.18, 12),
        ("desc", "Description", 0.22, 14),
    ),
    "blocklist": (
        ("sha1", "SHA-1 Hash", 0.42, 20),
        ("os", "OS", 0.12, 8),
        ("source", "Source", 0.16, 10),
        ("desc", "Description", 0.30, 14),
    ),
    "sites_activities": (
        ("kind", "Kind", 0.14, 8),
        ("name", "Name / Description", 0.44, 18),
        ("scope", "State / Scope", 0.22, 12),
        ("updated", "Timestamp", 0.20, 12),
    ),
}

_SPLIT_HORIZONTAL_MIN_WIDTH = 120


def _truncate(text: Any, max_len: int = 48) -> str:
    s = str(text or "").strip()
    if len(s) <= max_len:
        return s
    return s[: max(1, max_len - 3)] + "..."


class SentinelOnePane(BaseSocPane):
    """SentinelOne EDR endpoint, threat, exclusion, blocklist, and activity workbench."""

    STATUS_ID = "s1-status"
    LOG_ID = ""
    LOG_SOURCE = "sentinelone"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._current_view: str = "endpoints"
        self._sites_submode: str = "sites"
        self._records: list[dict[str, Any]] = []
        self._filtered_records: list[dict[str, Any]] = []
        self._selected_record: dict[str, Any] | None = None
        self._table_ready: bool = False
        self._s1_client: SentinelOneClient | None = None
        self._active_preset_id: str = "all"
        self._timeframe_filter: str = "any"
        self._status_filter: str = "any"
        self._syncing_s1_filters: bool = False

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

    def compose(self) -> ComposeResult:
        yield Static("SentinelOne EDR Operations Workbench (Management API v2.1)", classes="pane-title")
        yield Static(
            "Select a view and click Refresh or Check Connection.",
            id="s1-status",
            classes="status-bar",
            markup=False,
        )
        with Horizontal(classes="action-row toolbar-row"):
            yield Select(
                _VIEW_OPTIONS,
                allow_blank=False,
                value="endpoints",
                id="s1-view-select",
                compact=True,
            )
            yield Input(
                value="",
                placeholder="Filter hostname, threat, hash, or description...",
                id="s1-filter-input",
                compact=True,
            )
            yield Button("Refresh", id="s1-refresh-btn", variant="primary", compact=True)
            yield Button("Check Connection", id="s1-check-btn", compact=True)

        with Horizontal(id="s1-filter-bar", classes="action-row filter-bar"):
            yield Select(
                [("View: All Endpoints", "all")],
                allow_blank=False,
                value="all",
                id="s1-preset-select",
                compact=True,
            )
            yield Select(
                list(TIMEFRAME_OPTIONS),
                allow_blank=False,
                value="any",
                id="s1-timeframe-select",
                compact=True,
            )
            yield Select(
                list(_S1_ENDPOINT_STATUS_OPTIONS),
                allow_blank=False,
                value="any",
                id="s1-status-select",
                compact=True,
            )
            yield Button("Reset", id="s1-clear-filter-btn", compact=True)

        # Contextual action bars (toggled per active view)
        with Horizontal(id="s1-actions-endpoints", classes="action-row toolbar-row"):
            yield Button("Isolate", id="s1-isolate-btn", variant="error", compact=True)
            yield Button("Reconnect", id="s1-reconnect-btn", variant="warning", compact=True)
            yield Button("Full Scan", id="s1-scan-btn", compact=True)
            yield Button("Reboot", id="s1-reboot-btn", variant="warning", compact=True)
            yield Button("Uninstall", id="s1-uninstall-btn", variant="error", compact=True)

        with Horizontal(id="s1-actions-threats", classes="action-row toolbar-row"):
            yield Button("Triage", id="s1-triage-btn", variant="primary", compact=True)
            yield Button("Kill", id="s1-kill-btn", variant="error", compact=True)
            yield Button("Quarantine", id="s1-quarantine-btn", variant="warning", compact=True)
            yield Button("Remediate", id="s1-remediate-btn", variant="warning", compact=True)
            yield Button("Rollback", id="s1-rollback-btn", variant="error", compact=True)
            yield Button("Add Exclusion", id="s1-threat-exclude-btn", compact=True)

        with Horizontal(id="s1-actions-exclusions", classes="action-row toolbar-row"):
            yield Button("Create Exclusion", id="s1-create-excl-btn", variant="primary", compact=True)
            yield Button("Delete Exclusion", id="s1-delete-excl-btn", variant="error", compact=True)

        with Horizontal(id="s1-actions-blocklist", classes="action-row toolbar-row"):
            yield Button("Add SHA-1", id="s1-add-block-btn", variant="primary", compact=True)
            yield Button("Remove Blocklist", id="s1-delete-block-btn", variant="error", compact=True)

        with Horizontal(id="s1-actions-sites", classes="action-row toolbar-row"):
            yield Button("Load Sites", id="s1-sites-btn", variant="primary", compact=True)
            yield Button("Load Activities", id="s1-activities-btn", compact=True)

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
                with Horizontal(classes="detail-toolbar"):
                    yield Static("Details", id="s1-detail-header", classes="section-label", markup=False)
                yield RichLog(
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
        self._table_ready = True
        self._sync_action_bars()
        self._configure_columns("endpoints")
        self._render_empty_detail()
        self._update_split_layout()
        self._update_initial_status()

    def _update_initial_status(self) -> None:
        app_s1 = getattr(self.app, "s1_client", None)
        if app_s1 is not None:
            mode = " [DRY-RUN]" if self.effective_dry_run else ""
            self.set_status(f"SentinelOne client ready{mode}. Click Refresh to load {self._current_view}.")
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

    def on_resize(self) -> None:
        self._update_split_layout()
        if self._table_ready:
            self.call_after_refresh(self._fit_table)

    def on_tab_activated(self) -> None:
        self._update_split_layout()
        if self._table_ready:
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

    def _sync_action_bars(self) -> None:
        bar_map = {
            "endpoints": "#s1-actions-endpoints",
            "threats": "#s1-actions-threats",
            "exclusions": "#s1-actions-exclusions",
            "blocklist": "#s1-actions-blocklist",
            "sites_activities": "#s1-actions-sites",
        }
        for view_key, selector in bar_map.items():
            try:
                bar = self.query_one(selector, Horizontal)
                bar.display = view_key == self._current_view
            except Exception:
                pass
        self._sync_filter_controls_for_view()

    def _sync_filter_controls_for_view(self) -> None:
        """Populate SentinelOne preset, timeframe, and status dropdowns for the active view."""
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

            tf_sel = self.query_one("#s1-timeframe-select", Select)
            tf_sel.value = "any"
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

            self._active_preset_id = "all"
            self._timeframe_filter = "any"
            self._status_filter = "any"
        except Exception:
            pass
        finally:
            self._syncing_s1_filters = False
        self._update_summary_bar()

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
                        "Right-click a row for contextual actions.",
                        style="dim",
                    ),
                    title="SentinelOne Inspector",
                    border_style="cyan",
                )
            )
        except Exception:
            pass

    def _format_row(self, view: str, rec: dict[str, Any]) -> tuple[str, ...]:
        if view == "endpoints":
            return (
                _truncate(rec.get("computerName") or rec.get("id") or "-", 28),
                _truncate(rec.get("osName") or rec.get("osType") or "-", 18),
                _truncate(rec.get("lastIpToMgmt") or rec.get("externalIp") or "-", 18),
                _truncate(rec.get("networkStatus") or "-", 14),
                "YES" if rec.get("infected") else "No",
                _truncate(rec.get("siteName") or rec.get("siteId") or "-", 22),
            )
        if view == "threats":
            raw_tinfo = rec.get("threatInfo")
            tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
            raw_ainfo = rec.get("agentRealtimeInfo")
            ainfo: dict[str, Any] = raw_ainfo if isinstance(raw_ainfo, dict) else {}
            return (
                _truncate(tinfo.get("threatName") or rec.get("threatName") or rec.get("id") or "-", 30),
                _truncate(ainfo.get("agentComputerName") or rec.get("agentComputerName") or "-", 20),
                _truncate(tinfo.get("analystVerdict") or rec.get("analystVerdict") or "-", 16),
                _truncate(tinfo.get("incidentStatus") or rec.get("incidentStatus") or "-", 14),
                _truncate(tinfo.get("mitigationStatus") or rec.get("mitigationStatus") or "-", 16),
                _truncate(tinfo.get("createdAt") or rec.get("createdAt") or "-", 19),
            )
        if view == "exclusions":
            return (
                _truncate(rec.get("type") or "-", 14),
                _truncate(rec.get("osType") or "-", 10),
                _truncate(rec.get("value") or "-", 40),
                _truncate(rec.get("mode") or "-", 20),
                _truncate(rec.get("description") or "-", 28),
            )
        if view == "blocklist":
            return (
                _truncate(rec.get("value") or "-", 42),
                _truncate(rec.get("osType") or "-", 10),
                _truncate(rec.get("source") or "-", 16),
                _truncate(rec.get("description") or "-", 32),
            )
        # sites_activities
        if rec.get("_s1_kind") == "activity":
            return (
                "Activity",
                _truncate(rec.get("primaryDescription") or rec.get("activityType") or "-", 48),
                _truncate(rec.get("siteName") or rec.get("accountName") or "-", 22),
                _truncate(rec.get("createdAt") or "-", 19),
            )
        return (
            "Site",
            _truncate(rec.get("name") or rec.get("id") or "-", 48),
            _truncate(rec.get("state") or rec.get("siteType") or "-", 22),
            _truncate(rec.get("updatedAt") or rec.get("createdAt") or "-", 19),
        )

    def _populate_table(self, records: list[dict[str, Any]]) -> None:
        self._records = list(records)
        self._apply_local_filter()

    def _record_timestamp(self, rec: dict[str, Any]) -> Any:
        if self._current_view == "threats":
            raw_tinfo = rec.get("threatInfo")
            tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
            return (
                tinfo.get("createdAt")
                or rec.get("createdAt")
                or tinfo.get("updatedAt")
                or rec.get("updatedAt")
            )
        if self._current_view == "sites_activities":
            return rec.get("createdAt") or rec.get("updatedAt")
        return rec.get("updatedAt") or rec.get("createdAt")

    def _record_matches_status(self, rec: dict[str, Any]) -> bool:
        if self._status_filter == "any":
            return True
        if self._current_view == "threats":
            raw_tinfo = rec.get("threatInfo")
            tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
            verdict = str(
                tinfo.get("analystVerdict") or rec.get("analystVerdict") or ""
            ).strip().lower()
            inc_status = str(
                tinfo.get("incidentStatus") or rec.get("incidentStatus") or ""
            ).strip().lower()
            mit_status = str(
                tinfo.get("mitigationStatus") or rec.get("mitigationStatus") or ""
            ).strip().lower()
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

    def _update_summary_bar(self) -> None:
        try:
            summary = self.query_one("#s1-summary-bar", Static)
        except Exception:
            return
        view_title = self._current_view.replace("_", " ").title()
        parts: list[str] = [f"{view_title}: {len(self._filtered_records)} (of {len(self._records)})"]
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

    def _apply_local_filter(self) -> None:
        query = ""
        try:
            query = self.query_one("#s1-filter-input", Input).value.strip().lower()
        except Exception:
            pass
        filtered: list[dict[str, Any]] = []
        for rec in self._records:
            if not self._record_matches_status(rec):
                continue
            if self._timeframe_filter != "any" and self._current_view in {
                "threats",
                "sites_activities",
            }:
                if not timestamp_matches_timeframe(
                    self._record_timestamp(rec),
                    self._timeframe_filter,
                ):
                    continue
            if query and query not in json.dumps(rec, default=str).lower():
                continue
            filtered.append(rec)
        self._filtered_records = filtered

        table = self.query_one("#s1-table", DoubleClickDataTable)
        self._configure_columns(self._current_view)
        for idx, rec in enumerate(self._filtered_records):
            row_key = str(rec.get("id") or f"row-{idx}")
            table.add_row(*self._format_row(self._current_view, rec), key=row_key)

        if self._filtered_records:
            self._select_record(self._filtered_records[0])
        else:
            self._selected_record = None
            self._render_empty_detail()
        self._update_summary_bar()
        self.call_after_refresh(self._fit_table)

    def _select_record(self, rec: dict[str, Any]) -> None:
        self._selected_record = rec
        try:
            header = self.query_one("#s1-detail-header", Static)
            rec_id = str(rec.get("id") or "-")
            header.update(f"Details ({self._current_view}: {rec_id})")
            detail = self.query_one("#s1-detail-log", RichLog)
            detail.clear()

            summary_tbl = Table.grid(padding=(0, 1))
            summary_tbl.add_column(style="bold cyan", no_wrap=True)
            summary_tbl.add_column()
            for key, val in list(rec.items())[:18]:
                if isinstance(val, (dict, list)):
                    rendered = _truncate(json.dumps(val, default=str), 120)
                else:
                    rendered = str(val)
                summary_tbl.add_row(str(key), rendered)
            detail.write(Panel(summary_tbl, title=f"Record {rec_id}", border_style="cyan"))
            detail.write(
                Panel(
                    Text(json.dumps(rec, indent=2, default=str)),
                    title="Raw JSON",
                    border_style="dim",
                )
            )
        except Exception:
            pass

    def _record_for_row_index(self, row_index: int | None) -> dict[str, Any] | None:
        if row_index is None:
            return None
        if 0 <= row_index < len(self._filtered_records):
            return self._filtered_records[row_index]
        return None

    def _require_selected(self, label: str) -> dict[str, Any] | None:
        if self._selected_record is None:
            msg = f"Select a {label} row first."
            self.set_status(msg)
            self.notify_user(msg, title="SentinelOne", severity="warning")
            return None
        return self._selected_record

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
    # UI Event Handlers
    # ------------------------------------------------------------------

    @on(Select.Changed, "#s1-view-select")
    def handle_view_changed(self, event: Select.Changed) -> None:
        val = str(event.value or "endpoints")
        if val == self._current_view:
            return
        self._current_view = val
        self._records = []
        self._filtered_records = []
        self._selected_record = None
        self._sync_action_bars()
        self._configure_columns(val)
        self._render_empty_detail()
        self.set_status(f"Switched to SentinelOne {val} view. Click Refresh to load.")

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
            self.query_one("#s1-timeframe-select", Select).value = self._timeframe_filter
            self.query_one("#s1-status-select", Select).value = self._status_filter
        except Exception:
            pass
        finally:
            self._syncing_s1_filters = False
        if self._table_ready:
            self._apply_local_filter()
        self.set_status(f"Applied preset: {matched.get('label')}")

    @on(Select.Changed, "#s1-timeframe-select")
    def handle_timeframe_changed(self, event: Select.Changed) -> None:
        if self._syncing_s1_filters or event.value is Select.BLANK:
            return
        self._timeframe_filter = str(event.value or "any")
        if self._table_ready:
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
        self._sync_filter_controls_for_view()
        try:
            self.query_one("#s1-filter-input", Input).value = ""
        except Exception:
            pass
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
        if rec is not None:
            self._select_record(rec)

    @on(DoubleClickDataTable.RowRightClicked, "#s1-table")
    def handle_row_right_clicked(self, event: DoubleClickDataTable.RowRightClicked) -> None:
        event.stop()
        rec = self._record_for_row_index(event.row_index)
        if rec is not None:
            self._select_record(rec)
        items: list[tuple[str, str]] = [("refresh", "Refresh View")]
        if self._current_view == "endpoints" and rec is not None:
            items = [
                ("isolate", "Isolate Endpoint (Disconnect)"),
                ("reconnect", "Reconnect Endpoint"),
                ("scan", "Initiate Full Scan"),
                ("reboot", "Reboot Endpoint"),
                ("uninstall", "Uninstall Agent"),
                ("refresh", "Refresh Endpoints"),
            ]
        elif self._current_view == "threats" and rec is not None:
            items = [
                ("triage", "Triage Threat..."),
                ("kill", "Mitigate: Kill"),
                ("quarantine", "Mitigate: Quarantine"),
                ("remediate", "Mitigate: Remediate"),
                ("rollback", "Mitigate: Rollback"),
                ("threat_exclude", "Add Threat to Exclusions"),
                ("refresh", "Refresh Threats"),
            ]
        elif self._current_view == "exclusions":
            items = [("create_excl", "Create Exclusion...")]
            if rec is not None:
                items.append(("delete_excl", "Delete Selected Exclusion"))
            items.append(("refresh", "Refresh Exclusions"))
        elif self._current_view == "blocklist":
            items = [("add_block", "Add SHA-1 to Blocklist...")]
            if rec is not None:
                items.append(("delete_block", "Remove Selected Blocklist Entry"))
            items.append(("refresh", "Refresh Blocklist"))

        def _on_select(action_id: str) -> None:
            dispatch = {
                "refresh": self.handle_refresh,
                "isolate": self.handle_isolate,
                "reconnect": self.handle_reconnect,
                "scan": self.handle_scan,
                "reboot": self.handle_reboot,
                "uninstall": self.handle_uninstall,
                "triage": self.handle_triage,
                "kill": self.handle_kill,
                "quarantine": self.handle_quarantine,
                "remediate": self.handle_remediate,
                "rollback": self.handle_rollback,
                "threat_exclude": self.handle_threat_exclude,
                "create_excl": self.handle_create_exclusion,
                "delete_excl": self.handle_delete_exclusion,
                "add_block": self.handle_add_blocklist,
                "delete_block": self.handle_delete_blocklist,
            }
            fn = dispatch.get(action_id)
            if fn is not None:
                fn()

        self.open_context_menu(
            items,
            title=f"SentinelOne ({self._current_view})",
            origin=(event.screen_x, event.screen_y),
            on_select=_on_select,
        )

    @on(Button.Pressed, "#s1-refresh-btn")
    def handle_refresh(self) -> None:
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

    # ------------------------------------------------------------------
    # Endpoint Active-Response Actions (ConfirmActionModal + dry-run)
    # ------------------------------------------------------------------

    def _confirm_endpoint_action(
        self,
        *,
        action_key: str,
        title: str,
        verb: str,
        confirm_label: str,
    ) -> None:
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

    # ------------------------------------------------------------------
    # Threat Triage & Mitigation Actions
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#s1-triage-btn")
    def handle_triage(self) -> None:
        rec = self._require_selected("threat")
        if rec is None:
            return
        threat_id = str(rec.get("id") or "").strip()
        raw_tinfo = rec.get("threatInfo")
        tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
        threat_name = str(tinfo.get("threatName") or rec.get("threatName") or threat_id)
        current_verdict = str(tinfo.get("analystVerdict") or rec.get("analystVerdict") or "")
        current_status = str(tinfo.get("incidentStatus") or rec.get("incidentStatus") or "")

        def _on_triage(result: dict[str, str] | None) -> None:
            if not result:
                return
            verdict = result.get("analyst_verdict", "").strip()
            status = result.get("incident_status", "").strip()
            note = result.get("note", "").strip()
            if not any((verdict, status, note)):
                self.set_status("No triage changes selected.")
                return
            if self._block_if_dry_run("Threat Triage", f"threat {threat_id}"):
                return
            self._triage_threat_worker(threat_id, verdict, status, note)

        self.app.push_screen(
            S1ThreatTriageModal(
                threat_id=threat_id,
                threat_name=threat_name,
                current_verdict=current_verdict,
                current_status=current_status,
                dry_run=self.effective_dry_run,
            ),
            _on_triage,
        )

    def _confirm_threat_mitigation(self, action: str, label: str) -> None:
        rec = self._require_selected("threat")
        if rec is None:
            return
        threat_id = str(rec.get("id") or "").strip()
        raw_tinfo = rec.get("threatInfo")
        tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
        threat_name = str(tinfo.get("threatName") or rec.get("threatName") or threat_id)
        if not threat_id:
            self.set_status("Selected threat record is missing an ID.")
            return
        if self._block_if_dry_run(f"Threat Mitigation ({action})", f"threat {threat_name} ({threat_id})"):
            return
        self.confirm_destructive_action(
            title=f"SentinelOne Threat Mitigation: {label}",
            message=f"Run '{action}' mitigation on threat {threat_name}?",
            details=f"Threat ID: {threat_id}\nAction: {action}",
            confirm_label=f"Approve {label}",
            on_approved=lambda: self._mitigate_threat_worker(threat_id, action),
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
        rec = self._require_selected("threat")
        if rec is None:
            return
        threat_id = str(rec.get("id") or "").strip()
        raw_tinfo = rec.get("threatInfo")
        tinfo: dict[str, Any] = raw_tinfo if isinstance(raw_tinfo, dict) else {}
        threat_name = str(tinfo.get("threatName") or rec.get("threatName") or threat_id)
        if self._block_if_dry_run("Add Threat to Exclusions", f"threat {threat_name} ({threat_id})"):
            return
        self.confirm_destructive_action(
            title="Add Threat to SentinelOne Exclusions",
            message=f"Add threat '{threat_name}' to SentinelOne exclusions?",
            details=f"Threat ID: {threat_id}\nScope: site | Mode: suppress",
            confirm_label="Approve Exclusion",
            on_approved=lambda: self._threat_exclude_worker(threat_id),
        )

    # ------------------------------------------------------------------
    # Exclusions & Blocklist Actions
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#s1-create-excl-btn")
    def handle_create_exclusion(self) -> None:
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

    @on(Button.Pressed, "#s1-delete-excl-btn")
    def handle_delete_exclusion(self) -> None:
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

    @on(Button.Pressed, "#s1-add-block-btn")
    def handle_add_blocklist(self) -> None:
        def _on_add(result: dict[str, str] | None) -> None:
            if not result:
                return
            if self._block_if_dry_run("Add Blocklist SHA-1", result.get("value", "")):
                return
            self._add_blocklist_worker(result)

        self.app.push_screen(
            S1AddBlocklistModal(dry_run=self.effective_dry_run),
            _on_add,
        )

    @on(Button.Pressed, "#s1-delete-block-btn")
    def handle_delete_blocklist(self) -> None:
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
    def _load_view_worker(self, view: str, sites_submode: str = "sites") -> None:
        try:
            self.set_status(f"Loading SentinelOne {view}...")
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                if view == "endpoints":
                    records = client.list_agents(limit=100)
                elif view == "threats":
                    records = client.list_threats(limit=100)
                elif view == "exclusions":
                    records = client.list_exclusions(limit=100)
                elif view == "blocklist":
                    records = client.list_blocklist(limit=100)
                elif sites_submode == "activities":
                    raw = client.list_activities(limit=100)
                    records = [{**item, "_s1_kind": "activity"} for item in raw]
                else:
                    raw = client.list_sites(limit=100)
                    records = [{**item, "_s1_kind": "site"} for item in raw]

            self.run_on_ui(self._populate_table, records)
            msg = f"Loaded {len(records)} SentinelOne {view} record(s)."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
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
    def _triage_threat_worker(
        self,
        threat_id: str,
        verdict: str,
        status: str,
        note: str,
    ) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                applied: list[str] = []
                if verdict:
                    client.update_threat_verdict([threat_id], verdict)
                    applied.append(f"verdict={verdict}")
                if status:
                    client.update_threat_incident_status([threat_id], status)
                    applied.append(f"status={status}")
                if note:
                    client.add_threat_note(threat_id, note)
                    applied.append("note added")
            msg = f"Triaged threat {threat_id}: {', '.join(applied)}"
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Threat Triaged")
        except Exception as exc:
            self._report_s1_error("SentinelOne Threat Triage", exc)

    @work(thread=True, exit_on_error=False)
    def _mitigate_threat_worker(self, threat_id: str, action: str) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                res = client.mitigate_threat([threat_id], action)
            affected = (
                res.get("data", {}).get("affected")
                if isinstance(res.get("data"), dict)
                else 1
            )
            msg = f"SentinelOne threat mitigation '{action}' on {threat_id}: affected={affected}"
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Threat Mitigation")
        except Exception as exc:
            self._report_s1_error(f"SentinelOne Mitigate ({action})", exc)

    @work(thread=True, exit_on_error=False)
    def _threat_exclude_worker(self, threat_id: str) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
                client.add_threat_to_exclusions([threat_id])
            msg = f"Added threat {threat_id} to SentinelOne exclusions."
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
                client.create_exclusion(
                    exclusion_type=payload["type"],
                    os_type=payload["os_type"],
                    value=payload["value"],
                    description=payload.get("description", ""),
                    mode=payload.get("mode", "suppress"),
                )
            msg = f"Created SentinelOne {payload['type']} exclusion: {payload['value']}"
            self.set_status(msg)
            self.append_log(msg)
            self.notify_user(msg, title="SentinelOne Exclusion Created")
        except Exception as exc:
            self._report_s1_error("SentinelOne Create Exclusion", exc)

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
    def _add_blocklist_worker(self, payload: dict[str, str]) -> None:
        try:
            with self.log_scope("sentinelone"):
                client = self._get_s1_client()
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
