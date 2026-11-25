"""Sigma rule search, cache management, pySigma pipeline preview, and Splunk export pane."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import yaml
from textual import events, on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    DataTable,
    Input,
    RichLog,
    Select,
    Static,
)

from soclens.sigma import (
    SIGMA_PIPELINES,
    SigmaConversionConfig,
    convert_sigma_rule,
    convert_sigma_rule_to_spl,
    export_rules_to_splunk,
    load_rules,
    load_sigma_config,
    map_logsource_to_index,
    parse_field_list,
    parse_key_value_mapping,
    search_rules,
)
from soclens.tui.screens.base import (
    BaseSocPane,
    DoubleClickDataTable,
    SelectableRichLog,
    extract_richlog_text,
)

_SIGMA_COLUMN_SPECS: tuple[tuple[str, float, int], ...] = (
    ("rule_id", 0.18, 12),
    ("level", 0.10, 8),
    ("index", 0.14, 12),
    ("title", 0.34, 20),
    ("file_name", 0.24, 16),
)

_PIPELINE_OPTIONS: list[tuple[str, str]] = [
    ("Windows (EventCode + Source)", "splunk_windows"),
    ("Windows + Sysmon Keywords", "splunk_windows_sysmon"),
    ("Splunk CIM (tstats)", "splunk_cim"),
    ("None (Raw SPL)", "none"),
]

_SIGMA_LEVEL_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Level: All", "all"),
    ("Critical", "critical"),
    ("High", "high"),
    ("Medium", "medium"),
    ("Low", "low"),
    ("Informational", "informational"),
)

_SIGMA_TIME_PRESETS: tuple[tuple[str, str], ...] = (
    ("Window: All", ""),
    ("Last 24h (1d)", "1"),
    ("Last 7d (7d)", "7"),
    ("Last 14d (14d)", "14"),
    ("Last 30d (30d)", "30"),
    ("Last 90d (90d)", "90"),
    ("Custom Days", "custom"),
)


def _convert_rule_to_spl_and_stanza(
    rule: dict[str, Any],
    config: SigmaConversionConfig | None = None,
) -> tuple[str, str, str]:
    """Return ``(raw_yaml, spl_query, full_stanza)`` for a Sigma rule dictionary."""
    raw_yaml = str(rule.get("content") or "")
    if not raw_yaml.strip():
        return raw_yaml, "", ""

    try:
        converted = convert_sigma_rule(rule, config=config)
    except Exception:
        return raw_yaml, "", ""

    raw_stanzas = converted.get("stanzas") or []
    raw_queries = converted.get("queries") or []
    if not raw_stanzas and not raw_queries:
        return raw_yaml, "", ""

    stanzas: list[str] = []
    spl_queries: list[str] = []
    for idx, stanza in enumerate(raw_stanzas):
        stanza_str = str(stanza).rstrip()
        stanzas.append(stanza_str)
        extracted_spl = ""
        for line in stanza_str.splitlines():
            if line.startswith("search = "):
                extracted_spl = line[len("search = ") :].strip()
                break
        fallback_q = str(raw_queries[idx]).strip() if idx < len(raw_queries) else ""
        spl_queries.append(extracted_spl or fallback_q)

    full_stanza = ("\n\n".join(stanzas) + "\n") if stanzas else ""
    return raw_yaml, "\n".join(spl_queries), full_stanza


class SigmaPane(BaseSocPane):
    """Interactive Sigma detection rule browser, pySigma pipeline previewer, and Splunk exporter."""

    STATUS_ID = "sigma-status"
    LOG_ID = "sigma-log"
    LOG_SOURCE = "sigma"

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("c", "copy_spl", "Copy SPL", show=False),
        Binding("y", "copy_stanza", "Copy Stanza", show=False),
        Binding("v", "open_copy_view", "Copyable View", show=False),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._rules: list[dict[str, Any]] = []
        self._displayed_rules: list[dict[str, Any]] = []
        self._visible_rules: list[dict[str, Any]] = []
        self._selected_rule_id: str | None = None
        self._selected_rule: dict[str, Any] | None = None
        self._last_raw_yaml: str = ""
        self._last_spl_query: str = ""
        self._last_stanza_text: str = ""
        self._tables_ready = False
        self._level_filter: str = "all"
        self._syncing_days: bool = False

    def compose(self) -> ComposeResult:
        yield Static("Sigma Detection Rules & Splunk Export", classes="pane-title")
        yield Static(
            "Load cached rules or refresh from Recorded Future.",
            id="sigma-status",
            classes="status-bar",
            markup=False,
        )

        with Horizontal(id="sigma-toolbar", classes="action-row toolbar-row"):
            yield Button(
                "Load Cached Rules",
                id="sigma-load-btn",
                variant="primary",
                compact=True,
            )
            yield Button("Refresh Rules API", id="sigma-refresh-btn", compact=True)
            yield Input(
                placeholder="Search Sigma rules (e.g. PowerShell)",
                id="sigma-query-input",
                compact=True,
            )
            yield Select(
                list(_SIGMA_LEVEL_OPTIONS),
                allow_blank=False,
                value="all",
                id="sigma-level-filter",
                compact=True,
            )
            yield Button("Search Rules", id="sigma-search-btn", compact=True)
            yield Button("Explain with Local LLM", id="sigma-explain-llm-btn", compact=True)
            yield Button("Run in Splunk Search", id="sigma-run-splunk-btn", compact=True)

        with Collapsible(
            title="Splunk Export, Custom Indexes & Table Fields",
            collapsed=True,
            collapsed_symbol=">",
            expanded_symbol="v",
            id="sigma-export-collapsible",
        ):
            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    value="savedsearches.conf",
                    placeholder="Splunk export file path",
                    id="sigma-export-path",
                    compact=True,
                )
                yield Select(
                    list(_SIGMA_TIME_PRESETS),
                    allow_blank=False,
                    value="",
                    id="sigma-time-preset",
                    compact=True,
                )
                yield Input(
                    value="",
                    placeholder="Days (optional)",
                    id="sigma-days-input",
                    compact=True,
                )
                yield Select(
                    _PIPELINE_OPTIONS,
                    allow_blank=False,
                    value="splunk_windows",
                    id="sigma-pipeline-select",
                    compact=True,
                )
                yield Button("Export to Splunk", id="sigma-export-btn", compact=True)

            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    value="",
                    placeholder="Index override (e.g. sec_events)",
                    id="sigma-index-override",
                    compact=True,
                )
                yield Input(
                    value="",
                    placeholder="Index map (e.g. windows=win_sec,sysmon=edr_sysmon)",
                    id="sigma-index-map",
                    compact=True,
                )
                yield Input(
                    value="",
                    placeholder="Fallback default index (e.g. soc_other)",
                    id="sigma-default-index",
                    compact=True,
                )

            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    value="",
                    placeholder="Custom table fields (e.g. tenant_id,env)",
                    id="sigma-custom-table-fields",
                    compact=True,
                )
                yield Input(
                    value="",
                    placeholder="Override table fields (optional)",
                    id="sigma-table-fields",
                    compact=True,
                )
                yield Input(
                    value="",
                    placeholder="Custom suppress fields (e.g. tenant_id)",
                    id="sigma-custom-suppress-fields",
                    compact=True,
                )

            with Horizontal(classes="action-row filter-bar"):
                yield Input(
                    value="",
                    placeholder="Field map (e.g. CommandLine=process,User=user)",
                    id="sigma-field-map",
                    compact=True,
                )
                yield Checkbox(
                    "Split by index",
                    value=True,
                    id="sigma-split-checkbox",
                    compact=True,
                )
                yield Button(
                    "Preview Splunk Stanza",
                    id="sigma-preview-btn",
                    compact=True,
                )

        yield DoubleClickDataTable(id="sigma-table")
        with Horizontal(id="sigma-detail-toolbar", classes="detail-toolbar"):
            yield Static(
                "Sigma Rule Output",
                id="sigma-detail-header",
                classes="section-label",
                markup=False,
            )
            yield Button("Copy SPL", id="sigma-copy-spl-btn", compact=True)
            yield Button("Copy Stanza", id="sigma-copy-stanza-btn", compact=True)
            yield Button("Copy YAML", id="sigma-copy-yaml-btn", compact=True)
            yield Button("Copyable View", id="sigma-copy-modal-btn", compact=True)
        yield SelectableRichLog(id="sigma-log", highlight=False, markup=False, wrap=True)

    def on_mount(self) -> None:
        table = self.query_one("#sigma-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("Rule ID", key="rule_id")
        table.add_column("Level", key="level")
        table.add_column("Index", key="index")
        table.add_column("Title", key="title")
        table.add_column("File Name", key="file_name")

        try:
            env_cfg = load_sigma_config()
            if env_cfg.pipeline in SIGMA_PIPELINES:
                self.query_one("#sigma-pipeline-select", Select).value = env_cfg.pipeline
            self.query_one("#sigma-split-checkbox", Checkbox).value = env_cfg.split_by_index
        except Exception:
            pass

        self._tables_ready = True
        self.call_after_refresh(self._fit_tables)

    def on_resize(self) -> None:
        if self._tables_ready:
            self.call_after_refresh(self._fit_tables)

    def on_tab_activated(self) -> None:
        if self._tables_ready:
            self.call_after_refresh(self._fit_tables)

    def _fit_tables(self) -> None:
        if self.is_app_shutting_down() or not self._tables_ready:
            return
        try:
            self.fit_table_columns(
                self.query_one("#sigma-table", DataTable),
                _SIGMA_COLUMN_SPECS,
            )
        except Exception:
            pass

    def _build_conversion_config(self) -> SigmaConversionConfig:
        """Build effective ``SigmaConversionConfig`` from env defaults and UI controls."""
        cfg = load_sigma_config()

        pipeline_val = str(
            self.query_one("#sigma-pipeline-select", Select).value or "splunk_windows"
        )
        cfg.pipeline = pipeline_val
        cfg.output_format = "data_model" if pipeline_val == "splunk_cim" else "default"
        cfg.split_by_index = bool(self.query_one("#sigma-split-checkbox", Checkbox).value)

        index_ov = self.query_one("#sigma-index-override", Input).value.strip()
        if index_ov:
            cfg.index_override = index_ov

        index_map_raw = self.query_one("#sigma-index-map", Input).value.strip()
        if index_map_raw:
            cfg.index_map.update(parse_key_value_mapping(index_map_raw, lowercase_keys=True))

        default_idx = self.query_one("#sigma-default-index", Input).value.strip()
        if default_idx:
            cfg.default_index = default_idx

        custom_tbl_raw = self.query_one("#sigma-custom-table-fields", Input).value.strip()
        if custom_tbl_raw:
            for fld in parse_field_list(custom_tbl_raw):
                if fld not in cfg.custom_table_fields:
                    cfg.custom_table_fields.append(fld)

        override_tbl_raw = self.query_one("#sigma-table-fields", Input).value.strip()
        if override_tbl_raw:
            cfg.table_fields = override_tbl_raw

        custom_sup_raw = self.query_one("#sigma-custom-suppress-fields", Input).value.strip()
        if custom_sup_raw:
            for fld in parse_field_list(custom_sup_raw):
                if fld not in cfg.custom_suppress_fields:
                    cfg.custom_suppress_fields.append(fld)

        field_map_raw = self.query_one("#sigma-field-map", Input).value.strip()
        if field_map_raw:
            cfg.field_map.update(parse_key_value_mapping(field_map_raw, lowercase_keys=False))

        return cfg

    @staticmethod
    def _extract_rule_logsource(rule: dict[str, Any]) -> dict[str, Any]:
        logsource: dict[str, Any] = {}
        for key in ("product", "service", "category"):
            val = rule.get(key)
            if val:
                logsource[key] = val
        if not logsource and rule.get("content"):
            try:
                parsed = yaml.safe_load(str(rule["content"]))
                if isinstance(parsed, dict) and isinstance(parsed.get("logsource"), dict):
                    return dict(parsed["logsource"])
            except Exception:
                pass
        return logsource

    def _resolve_rule_display_index(
        self, rule: dict[str, Any], cfg: SigmaConversionConfig | None
    ) -> str:
        if cfg is not None and (cfg.index_override or cfg.index_map or cfg.default_index):
            logsource = self._extract_rule_logsource(rule)
            return map_logsource_to_index(
                logsource,
                index_map=cfg.index_map or None,
                default_index=cfg.default_index,
                index_override=cfg.index_override,
            )
        return str(rule.get("index") or "")

    def _populate_table(self, rules: list[dict[str, Any]]) -> None:
        self._displayed_rules = list(rules)
        try:
            cfg: SigmaConversionConfig | None = self._build_conversion_config()
        except Exception:
            cfg = None

        table = self.query_one("#sigma-table", DataTable)
        table.clear()
        level_filter = self._level_filter.strip().lower()
        filtered_rules = (
            [
                rule
                for rule in rules
                if str(rule.get("level") or "").strip().lower() == level_filter
            ]
            if level_filter != "all"
            else list(rules)
        )
        self._visible_rules = filtered_rules[:200]
        for rule in self._visible_rules:
            resolved_idx = self._resolve_rule_display_index(rule, cfg)
            table.add_row(
                str(rule.get("rule_id") or ""),
                str(rule.get("level") or ""),
                resolved_idx,
                str(rule.get("title") or ""),
                str(rule.get("file_name") or ""),
            )
        if self._visible_rules:
            self._select_rule(self._visible_rules[0], write_to_log=False)
        else:
            self._selected_rule = None
            self._selected_rule_id = None
            self._last_raw_yaml = ""
            self._last_spl_query = ""
            self._last_stanza_text = ""
            self._update_detail_header()
        self.call_after_refresh(self._fit_tables)

    def _find_rule_by_id(self, rule_id: str | None) -> dict[str, Any] | None:
        if rule_id is not None:
            for pool in (self._visible_rules, self._displayed_rules, self._rules):
                for rule in pool:
                    if str(rule.get("rule_id") or "") == rule_id:
                        return rule
            return None
        if self._visible_rules:
            return self._visible_rules[0]
        if self._displayed_rules:
            return self._displayed_rules[0]
        return self._rules[0] if self._rules else None

    def _update_detail_header(self) -> None:
        try:
            header = self.query_one("#sigma-detail-header", Static)
        except Exception:
            return
        if self._selected_rule is None:
            header.update("Sigma Rule Output")
            return
        title = str(self._selected_rule.get("title") or self._selected_rule.get("rule_id") or "Rule")
        clipped = title if len(title) <= 44 else title[:41] + "..."
        header.update(f"Rule: {clipped}")

    def _select_rule(self, rule: dict[str, Any], *, write_to_log: bool = False) -> None:
        self._selected_rule = rule
        rule_id = str(rule.get("rule_id") or "").strip()
        self._selected_rule_id = rule_id or None
        try:
            cfg: SigmaConversionConfig | None = self._build_conversion_config()
        except Exception:
            cfg = None
        raw_yaml, spl_query, stanza_text = _convert_rule_to_spl_and_stanza(rule, config=cfg)
        self._last_raw_yaml = raw_yaml
        self._last_spl_query = spl_query
        self._last_stanza_text = stanza_text
        self._update_detail_header()
        if write_to_log:
            title = str(rule.get("title") or rule.get("rule_id") or "Sigma Rule")
            parts = [f"--- {title} ---"]
            if spl_query:
                parts.append(f"SPL Query:\n{spl_query}")
            if raw_yaml:
                parts.append(f"Sigma YAML:\n{raw_yaml}")
            self.append_log("\n\n".join(parts))

    def _ensure_selected_rule(self) -> dict[str, Any] | None:
        if self._selected_rule is not None:
            return self._selected_rule
        try:
            table = self.query_one("#sigma-table", DataTable)
            if table.row_count > 0 and table.cursor_row is not None:
                row_idx = table.cursor_row
                if 0 <= row_idx < len(self._visible_rules):
                    self._select_rule(self._visible_rules[row_idx], write_to_log=False)
                    return self._selected_rule
                row_key = table.ordered_rows[row_idx].key
                row = table.get_row(row_key)
                if row:
                    match = self._find_rule_by_id(str(row[0]))
                    if match is not None:
                        self._select_rule(match, write_to_log=False)
                        return self._selected_rule
        except Exception:
            pass
        return self._selected_rule

    def _build_copyable_text(self) -> tuple[str, str, str | None]:
        """Return ``(text, modal_title, language)`` for the Copyable View modal."""
        rule = self._ensure_selected_rule()
        if rule is not None:
            title = str(rule.get("title") or rule.get("rule_id") or "Sigma Rule")
            sections: list[str] = []
            if self._last_spl_query:
                sections.append(f"=== SPL Query ===\n{self._last_spl_query}")
            if self._last_stanza_text:
                sections.append(f"=== Splunk savedsearches.conf Stanza ===\n{self._last_stanza_text.rstrip()}")
            if self._last_raw_yaml:
                sections.append(f"=== Raw Sigma YAML ===\n{self._last_raw_yaml.rstrip()}")
            if sections:
                return "\n\n".join(sections), f"Sigma Rule - {title}", None
        try:
            log_text = extract_richlog_text(self.query_one("#sigma-log", RichLog))
        except Exception:
            log_text = ""
        return log_text, "Sigma Rule Log", None

    @on(DataTable.RowHighlighted, "#sigma-table")
    def handle_rule_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if 0 <= event.cursor_row < len(self._visible_rules):
            self._select_rule(self._visible_rules[event.cursor_row], write_to_log=False)

    @on(DataTable.RowSelected, "#sigma-table")
    def handle_rule_selected(self, event: DataTable.RowSelected) -> None:
        table = self.query_one("#sigma-table", DataTable)
        row = table.get_row(event.row_key)
        if not row:
            return
        rule_id = str(row[0])
        match = self._find_rule_by_id(rule_id)
        if match is not None:
            self._select_rule(match, write_to_log=True)

    @on(Button.Pressed, "#sigma-copy-spl-btn")
    def handle_copy_spl(self) -> None:
        self._ensure_selected_rule()
        self.copy_to_clipboard(self._last_spl_query, label="SPL Query")

    @on(Button.Pressed, "#sigma-copy-stanza-btn")
    def handle_copy_stanza(self) -> None:
        self._ensure_selected_rule()
        self.copy_to_clipboard(self._last_stanza_text, label="Splunk Stanza")

    @on(Button.Pressed, "#sigma-copy-yaml-btn")
    def handle_copy_yaml(self) -> None:
        self._ensure_selected_rule()
        self.copy_to_clipboard(self._last_raw_yaml, label="Sigma YAML")

    @on(Button.Pressed, "#sigma-copy-modal-btn")
    def handle_open_copy_modal(self) -> None:
        text, title, lang = self._build_copyable_text()
        self.open_copy_modal(text, title=title, language=lang)

    def action_copy_spl(self) -> None:
        """Copy the selected Sigma rule's converted SPL query."""
        if isinstance(self.app.focused, Input):
            return
        self.handle_copy_spl()

    def action_copy_stanza(self) -> None:
        """Copy the selected Sigma rule's full Splunk savedsearches.conf stanza."""
        if isinstance(self.app.focused, Input):
            return
        self.handle_copy_stanza()

    def action_open_copy_view(self) -> None:
        """Open the selectable CopyTextModal for the selected Sigma rule."""
        if isinstance(self.app.focused, Input):
            return
        self.handle_open_copy_modal()

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        event.stop()
        rule_id = (
            str(self._selected_rule.get("rule_id") or "")
            if self._selected_rule is not None
            else None
        )
        self._open_sigma_menu(row_rule_id=rule_id or None, origin=(event.screen_x, event.screen_y))

    @on(DoubleClickDataTable.RowRightClicked, "#sigma-table")
    def handle_sigma_right_click(self, event: DoubleClickDataTable.RowRightClicked) -> None:
        event.stop()
        rule_id: str | None = None
        if event.row_key is not None:
            table = self.query_one("#sigma-table", DoubleClickDataTable)
            try:
                row = table.get_row(event.row_key)
                if row:
                    rule_id = str(row[0])
                    match = self._find_rule_by_id(rule_id)
                    if match is not None:
                        self._select_rule(match, write_to_log=False)
            except Exception:
                rule_id = None
        self._open_sigma_menu(row_rule_id=rule_id, origin=(event.screen_x, event.screen_y))

    def _open_sigma_menu(
        self, *, row_rule_id: str | None, origin: tuple[int, int]
    ) -> None:
        items: list[tuple[str, str]] = []
        if row_rule_id:
            items.append(("view_rule", "View Rule YAML in Log"))
            items.append(("preview_splunk", "Preview Splunk SPL & Stanza"))
            items.append(("explain_llm", "Explain with Local LLM"))
            items.append(("run_splunk", "Run in Splunk Search"))
        items.extend(
            [
                ("copy_spl", "Copy SPL Query"),
                ("copy_stanza", "Copy Full Splunk Stanza"),
                ("copy_yaml", "Copy Raw Sigma YAML"),
                ("copy_rule_id", "Copy Rule ID"),
                ("open_copy_view", "Open Copyable Text View"),
                ("load_cached", "Load Cached Rules"),
                ("refresh_api", "Refresh Rules from RF API"),
                ("focus_search", "Focus Rule Search"),
                ("toggle_export", "Toggle Custom Export & Fields"),
            ]
        )

        def _on_select(action_id: str) -> None:
            if action_id == "view_rule" and row_rule_id:
                match = self._find_rule_by_id(row_rule_id)
                if match is not None:
                    self._select_rule(match, write_to_log=True)
            elif action_id == "preview_splunk":
                self._preview_rule_stanza(row_rule_id)
            elif action_id == "explain_llm" and row_rule_id:
                self._pivot_rule_to_llm(row_rule_id)
            elif action_id == "run_splunk":
                self._pivot_rule_to_splunk(rule_id=row_rule_id)
            elif action_id == "copy_spl":
                self.handle_copy_spl()
            elif action_id == "copy_stanza":
                self.handle_copy_stanza()
            elif action_id == "copy_yaml":
                self.handle_copy_yaml()
            elif action_id == "copy_rule_id":
                target_id = row_rule_id or (
                    str(self._selected_rule.get("rule_id") or "")
                    if self._selected_rule is not None
                    else ""
                )
                self.copy_to_clipboard(target_id, label="Rule ID")
            elif action_id == "open_copy_view":
                self.handle_open_copy_modal()
            elif action_id == "load_cached":
                self.handle_load_cached()
            elif action_id == "refresh_api":
                self.handle_refresh_rules()
            elif action_id == "focus_search":
                self.query_one("#sigma-query-input", Input).focus()
            elif action_id == "toggle_export":
                col = self.query_one("#sigma-export-collapsible", Collapsible)
                col.collapsed = not col.collapsed

        self.open_context_menu(
            items,
            title=row_rule_id or "Sigma Rules",
            origin=origin,
            on_select=_on_select,
        )

    def _pivot_rule_to_llm(self, rule_id: str) -> None:
        match = next(
            (r for r in self._rules if str(r.get("rule_id") or "") == rule_id),
            None,
        )
        if not match:
            self.set_status(f"Sigma rule '{rule_id}' not found in loaded rules.")
            return
        title = str(match.get("title") or rule_id)
        content = str(match.get("content") or "").strip()
        if not content:
            content = f"Rule ID: {rule_id}\nTitle: {title}\nLevel: {match.get('level') or ''}"
        open_fn = getattr(self.app, "open_llm_with_context", None)
        if callable(open_fn):
            open_fn(title, content, template="explain_sigma", auto_send=False)
            self.set_status(f"Sent Sigma rule '{title}' to Local LLM tab.")
        else:
            self.set_status("Local LLM tab is not available in this app.")

    @on(Button.Pressed, "#sigma-explain-llm-btn")
    def handle_explain_with_llm(self) -> None:
        table = self.query_one("#sigma-table", DataTable)
        if table.row_count == 0 or not self._rules:
            self.set_status("Load and select a Sigma rule before sending to Local LLM.")
            return
        row_idx = table.cursor_row
        if row_idx < 0 or row_idx >= table.row_count:
            row_idx = 0
        try:
            row_key = table.ordered_rows[row_idx].key
            row = table.get_row(row_key)
        except Exception:
            row = None
        if not row:
            self.set_status("Select a Sigma rule row first.")
            return
        self._pivot_rule_to_llm(str(row[0]))

    def _get_selected_rule(self, rule_id: str | None = None) -> dict[str, Any] | None:
        if rule_id:
            return next(
                (r for r in self._rules if str(r.get("rule_id") or "") == rule_id),
                None,
            )
        table = self.query_one("#sigma-table", DataTable)
        if table.row_count == 0 or not self._rules:
            return None
        row_idx = table.cursor_row
        if row_idx < 0 or row_idx >= table.row_count:
            row_idx = 0
        row = table.get_row_at(row_idx)
        if not row:
            return None
        selected_id = str(row[0])
        return next(
            (r for r in self._rules if str(r.get("rule_id") or "") == selected_id),
            None,
        )

    def _pivot_rule_to_splunk(self, rule_id: str | None = None) -> None:
        rule = self._get_selected_rule(rule_id=rule_id)
        if rule is None:
            self.set_status("Select a Sigma rule before pivoting to Splunk Search.")
            return
        try:
            spl = convert_sigma_rule_to_spl(rule, config=self._build_conversion_config())
        except Exception as exc:
            self.report_error("Sigma to SPL Conversion", exc)
            return
        open_fn = getattr(self.app, "open_splunk_search", None)
        if callable(open_fn):
            open_fn(spl, auto_run=False)
            self.append_log(f"Pivoted Sigma rule '{rule.get('title', '')}' to Splunk Search.")
        else:
            self.set_status("Splunk Search pane is not available.")

    @on(Button.Pressed, "#sigma-run-splunk-btn")
    def handle_run_in_splunk(self) -> None:
        self._pivot_rule_to_splunk()

    def _parse_days(self) -> tuple[bool, int | None]:
        raw = self.query_one("#sigma-days-input", Input).value.strip()
        if not raw:
            return True, None
        try:
            days = int(raw)
            if days < 1:
                raise ValueError("Days must be >= 1")
            return True, days
        except ValueError as exc:
            self.set_status(f"Invalid days filter '{raw}': {exc}")
            return False, None

    @on(Select.Changed, "#sigma-level-filter")
    def handle_level_filter_changed(self, event: Select.Changed) -> None:
        if event.value is Select.BLANK:
            return
        self._level_filter = str(event.value or "all")
        if self._tables_ready and self._rules:
            self._populate_table(self._displayed_rules)

    @on(Select.Changed, "#sigma-time-preset")
    def handle_time_preset_changed(self, event: Select.Changed) -> None:
        if self._syncing_days or event.value is Select.BLANK:
            return
        val = str(event.value or "")
        if val == "custom":
            return
        self._syncing_days = True
        try:
            self.query_one("#sigma-days-input", Input).value = val
        finally:
            self._syncing_days = False

    @on(Input.Changed, "#sigma-days-input")
    def handle_days_input_changed(self) -> None:
        if self._syncing_days:
            return
        raw = self.query_one("#sigma-days-input", Input).value.strip()
        preset_vals = {val for _, val in _SIGMA_TIME_PRESETS if val != "custom"}
        target = raw if raw in preset_vals else "custom"
        try:
            sel = self.query_one("#sigma-time-preset", Select)
            if str(sel.value) != target:
                self._syncing_days = True
                try:
                    sel.value = target
                finally:
                    self._syncing_days = False
        except Exception:
            pass

    @on(Input.Submitted, "#sigma-query-input")
    def handle_query_submitted(self) -> None:
        self.handle_search_rules()

    @on(Input.Submitted, "#sigma-index-override")
    @on(Input.Submitted, "#sigma-index-map")
    @on(Input.Submitted, "#sigma-default-index")
    def handle_index_config_submitted(self) -> None:
        if self._rules:
            self._populate_table(self._displayed_rules or self._rules)

    @on(Button.Pressed, "#sigma-preview-btn")
    def handle_preview_stanza(self) -> None:
        self._preview_rule_stanza(self._selected_rule_id)

    def _preview_rule_stanza(self, rule_id: str | None = None) -> None:
        match = self._find_rule_by_id(rule_id)
        if not match:
            self.set_status("Load or select a Sigma rule before previewing.")
            return
        try:
            cfg = self._build_conversion_config()
            converted = convert_sigma_rule(match, config=cfg)
        except Exception as exc:
            self.report_error("Sigma Preview", exc)
            return

        header = (
            f"=== Splunk Preview ({converted['pipeline']} / {converted['output_format']} | "
            f"index={converted['index']}) ==="
        )
        stanza_block = "\n".join(converted["stanzas"])
        self.append_log(f"{header}\n{stanza_block}")
        self.set_status(
            f"Previewed '{converted['title']}' (index={converted['index']}, "
            f"pipeline={converted['pipeline']})."
        )

    @on(Button.Pressed, "#sigma-load-btn")
    def handle_load_cached(self) -> None:
        ok, days = self._parse_days()
        if ok:
            self._load_rules_worker(refresh=False, days=days)

    @on(Button.Pressed, "#sigma-refresh-btn")
    def handle_refresh_rules(self) -> None:
        ok, days = self._parse_days()
        if ok:
            self._load_rules_worker(refresh=True, days=days)

    @work(thread=True, exit_on_error=False)
    def _load_rules_worker(self, refresh: bool, days: int | None) -> None:
        try:
            self.set_status("Loading Sigma rules...")
            with self.log_scope("sigma"):
                loaded = load_rules(
                    self.client, refresh=refresh, days=days, cache_dir=self.workspace_dir
                )
            self._rules = loaded
            self.run_on_ui(self._populate_table, loaded)
            msg = f"Loaded {len(loaded)} Sigma rule(s)."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Load Sigma Rules", exc)

    @on(Button.Pressed, "#sigma-search-btn")
    def handle_search_rules(self) -> None:
        query = self.query_one("#sigma-query-input", Input).value.strip()
        self._search_rules_worker(query)

    @work(thread=True, exit_on_error=False)
    def _search_rules_worker(self, query: str) -> None:
        try:
            if not self._rules:
                with self.log_scope("sigma"):
                    self._rules = load_rules(
                        self.client, refresh=False, cache_dir=self.workspace_dir
                    )
            matches = search_rules(self._rules, query) if query else self._rules
            self.run_on_ui(self._populate_table, matches)
            msg = f"Matched {len(matches)} Sigma rule(s) for '{query or '*'}'."
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Search Sigma Rules", exc)

    @on(Button.Pressed, "#sigma-export-btn")
    def handle_export_splunk(self) -> None:
        out_raw = self.query_one("#sigma-export-path", Input).value.strip() or "savedsearches.conf"
        try:
            cfg = self._build_conversion_config()
        except Exception as exc:
            self.report_error("Sigma Export Config", exc)
            return

        if self.effective_dry_run:
            idx_desc = cfg.index_override or (
                f"map({len(cfg.index_map)})" if cfg.index_map else (cfg.default_index or "auto")
            )
            tbl_desc = (
                cfg.table_fields
                or (", ".join(cfg.custom_table_fields) if cfg.custom_table_fields else "default")
            )
            msg = (
                f"[DRY-RUN] Would export {len(self._rules)} Sigma rule(s) to {out_raw} "
                f"(pipeline={cfg.pipeline}, index={idx_desc}, table={tbl_desc})."
            )
            self.set_status(msg)
            self.append_log(msg)
            return
        self._export_worker(out_raw, cfg)

    @work(thread=True, exit_on_error=False)
    def _export_worker(self, out_raw: str, cfg: SigmaConversionConfig) -> None:
        try:
            with self.log_scope("sigma"):
                if not self._rules:
                    self._rules = load_rules(
                        self.client, refresh=False, cache_dir=self.workspace_dir
                    )
                out_path = Path(out_raw).expanduser()
                if not out_path.is_absolute():
                    out_path = self.workspace_dir / out_path
                summary = export_rules_to_splunk(self._rules, output_path=out_path, config=cfg)
            written = summary.get("files_written", []) if isinstance(summary, dict) else []
            conv_cnt = summary.get("converted_count", len(self._rules)) if isinstance(summary, dict) else len(self._rules)
            msg = (
                f"Exported {conv_cnt} query/queries from {len(self._rules)} Sigma rule(s) "
                f"to {len(written)} file(s) in {out_path.parent}."
            )
            self.set_status(msg)
            self.append_log(msg)
        except Exception as exc:
            self.report_error("Sigma Splunk Export", exc)
