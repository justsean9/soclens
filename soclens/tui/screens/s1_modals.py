"""SentinelOne-specific modal dialogs for sites, users, exclusions, cloning, and agents."""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from typing import Any, ClassVar

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, RichLog, Select, Static

from soclens.config import classify_site_tier
from soclens.tui.screens.base import SelectableRichLog


def _site_option_label(site: Mapping[str, Any]) -> str:
    name = str(site.get("name") or site.get("id") or "unknown").strip()
    site_id = str(site.get("id") or "").strip()
    tier = str(site.get("tier") or "").strip()
    if not tier and name:
        tier, _tenant = classify_site_tier(name, site_id=site_id or None)
    return f"[{tier or 'Other'}] {name} ({site_id})"


class ConfirmDeleteSiteModal(ModalScreen[bool]):
    """High-risk site deletion confirmation requiring exact site name entry."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    ConfirmDeleteSiteModal {
        align: center middle;
        background: $background 60%;
    }
    #s1-del-site-dialog {
        width: 76;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $error;
        background: $surface;
        padding: 0 2;
    }
    #s1-del-site-title {
        text-style: bold;
        color: $error;
        margin-bottom: 1;
    }
    #s1-del-site-scroll {
        width: 1fr;
        height: auto;
        max-height: 45vh;
    }
    #s1-del-site-details {
        margin-bottom: 1;
        color: $text-muted;
    }
    #s1-del-site-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #s1-del-site-confirm-input {
        width: 1fr;
        margin-bottom: 1;
    }
    #s1-del-site-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #s1-del-site-buttons {
        height: auto;
        align-horizontal: right;
    }
    #s1-del-site-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        site_id: str,
        site_name: str,
        tier: str = "Other",
        active_agents: int | str = 0,
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._site_id = site_id.strip()
        self._site_name = site_name.strip() or self._site_id
        self._tier = tier.strip() or "Other"
        self._active_agents = active_agents
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        with Vertical(id="s1-del-site-dialog"):
            yield Static(
                "Confirm Permanent SentinelOne Site Deletion",
                id="s1-del-site-title",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: site deletion will be blocked.",
                    id="s1-del-site-dry-banner",
                    markup=False,
                )
            with VerticalScroll(id="s1-del-site-scroll"):
                yield Static(
                    f"Site Name: {self._site_name}\n"
                    f"Site ID: {self._site_id} | Tier: {self._tier} | "
                    f"Active Agents: {self._active_agents}\n"
                    f"Type the exact site name '{self._site_name}' below to unlock deletion.",
                    id="s1-del-site-details",
                    markup=False,
                )
                yield Input(
                    value="",
                    placeholder=f"Type '{self._site_name}' exactly",
                    id="s1-del-site-confirm-input",
                    compact=True,
                )
            yield Static("", id="s1-del-site-error", markup=False)
            with Horizontal(id="s1-del-site-buttons"):
                yield Button(
                    "Cancel",
                    id="s1-del-site-cancel-btn",
                    variant="default",
                    compact=True,
                )
                yield Button(
                    "Delete Site Permanently",
                    id="s1-del-site-approve-btn",
                    variant="error",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#s1-del-site-cancel-btn", Button).focus()

    @on(Button.Pressed, "#s1-del-site-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#s1-del-site-approve-btn")
    def handle_approve(self) -> None:
        inp = self.query_one("#s1-del-site-confirm-input", Input)
        if inp.value != self._site_name:
            self.query_one("#s1-del-site-error", Static).update(
                f"Exact site name mismatch. Expected '{self._site_name}'."
            )
            inp.focus()
            return
        self.dismiss(True)

    def action_cancel(self) -> None:
        """Dismiss site deletion modal safely."""
        self.dismiss(False)


class CloneExclusionsModal(ModalScreen[dict[str, Any] | None]):
    """Site-to-site exclusion cloning modal with dry-run diff preview (<= 15 req/s)."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    CloneExclusionsModal {
        align: center middle;
        background: $background 60%;
    }
    #s1-clone-dialog {
        width: 78;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }
    #s1-clone-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #s1-clone-scroll {
        width: 1fr;
        height: auto;
        max-height: 46vh;
    }
    .s1-modal-label {
        height: 1;
        text-style: bold;
    }
    #s1-clone-scroll Select, #s1-clone-scroll Input {
        width: 1fr;
        margin-bottom: 1;
    }
    #s1-clone-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #s1-clone-summary {
        color: $text;
        margin-bottom: 1;
    }
    #s1-clone-preview-log {
        height: 7;
        min-height: 5;
        max-height: 12;
        border: round #2e3c5c;
        margin-bottom: 1;
    }
    #s1-clone-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #s1-clone-buttons {
        height: auto;
        align-horizontal: right;
    }
    #s1-clone-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        sites: Sequence[Mapping[str, Any]],
        plan_fn: Callable[[str, str, bool], dict[str, Any]] | None = None,
        initial_source_site_id: str = "",
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._sites = [dict(s) for s in sites if str(s.get("id") or "").strip()]
        self._plan_fn = plan_fn
        self._initial_source_site_id = initial_source_site_id.strip()
        self._dry_run = dry_run
        self._last_plan: dict[str, Any] | None = None

    def compose(self) -> ComposeResult:
        site_options: list[tuple[str, str]] = [
            (_site_option_label(site), str(site.get("id") or "").strip())
            for site in self._sites
        ]
        if not site_options:
            site_options = [("(No sites loaded)", "")]

        src_val = self._initial_source_site_id or site_options[0][1]
        if not any(v == src_val for _lbl, v in site_options):
            src_val = site_options[0][1]
        dst_val = site_options[1][1] if len(site_options) > 1 else site_options[0][1]
        if dst_val == src_val and len(site_options) > 1:
            dst_val = site_options[0][1]

        with Vertical(id="s1-clone-dialog"):
            yield Static(
                "Clone Site Exclusions (<= 15 req/s Paced)",
                id="s1-clone-title",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview available; live exclusion writes are blocked.",
                    id="s1-clone-dry-banner",
                    markup=False,
                )
            with VerticalScroll(id="s1-clone-scroll"):
                yield Static("Source Site", classes="s1-modal-label", markup=False)
                yield Select(
                    site_options,
                    allow_blank=False,
                    value=src_val,
                    id="s1-clone-src-select",
                    compact=True,
                )
                yield Static("Target Site", classes="s1-modal-label", markup=False)
                yield Select(
                    site_options,
                    allow_blank=False,
                    value=dst_val,
                    id="s1-clone-dst-select",
                    compact=True,
                )
                yield Checkbox(
                    "Include parent/account-inherited source exclusions",
                    value=False,
                    id="s1-clone-include-parents-cb",
                )
                yield Static("Max Write Rate (req/s, capped at 15)", classes="s1-modal-label", markup=False)
                yield Input(
                    value="15",
                    placeholder="15",
                    id="s1-clone-rps-input",
                    compact=True,
                )
                yield Static(
                    "Click 'Preview Diff' to inspect Will Create / Skipped Duplicate / Inherited from Account.",
                    id="s1-clone-summary",
                    markup=False,
                )
                yield SelectableRichLog(
                    id="s1-clone-preview-log",
                    highlight=False,
                    markup=False,
                    wrap=True,
                )
            yield Static("", id="s1-clone-error", markup=False)
            with Horizontal(id="s1-clone-buttons"):
                yield Button("Cancel", id="s1-clone-cancel-btn", variant="default", compact=True)
                yield Button(
                    "Preview Diff",
                    id="s1-clone-preview-btn",
                    variant="default",
                    compact=True,
                )
                yield Button(
                    "Execute Clone",
                    id="s1-clone-apply-btn",
                    variant="primary",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#s1-clone-preview-btn", Button).focus()

    def _site_name_for_id(self, site_id: str) -> str:
        for site in self._sites:
            if str(site.get("id") or "").strip() == site_id:
                return str(site.get("name") or site_id).strip()
        return site_id

    @on(Button.Pressed, "#s1-clone-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#s1-clone-preview-btn")
    def handle_preview(self) -> None:
        src_id = str(self.query_one("#s1-clone-src-select", Select).value or "").strip()
        dst_id = str(self.query_one("#s1-clone-dst-select", Select).value or "").strip()
        err = self.query_one("#s1-clone-error", Static)
        if not src_id or not dst_id:
            err.update("Select both a source and target site.")
            return
        if src_id == dst_id:
            err.update("Source and target sites must be different.")
            return
        err.update("")
        include_parents = bool(self.query_one("#s1-clone-include-parents-cb", Checkbox).value)
        if self._plan_fn is None:
            err.update("Preview function unavailable.")
            return
        self._run_preview_worker(src_id, dst_id, include_parents)

    @work(thread=True, exit_on_error=False)
    def _run_preview_worker(
        self,
        src_id: str,
        dst_id: str,
        include_parents: bool,
    ) -> None:
        assert self._plan_fn is not None
        try:
            plan = self._plan_fn(src_id, dst_id, include_parents)
            self.app.call_from_thread(self._render_plan, plan)
        except Exception as exc:
            self.app.call_from_thread(
                self.query_one("#s1-clone-error", Static).update,
                f"Dry-run preview failed: {exc}",
            )

    def _render_plan(self, plan: dict[str, Any]) -> None:
        self._last_plan = plan
        raw_counts = plan.get("counts")
        counts: dict[str, Any] = raw_counts if isinstance(raw_counts, dict) else {}
        raw_wc = plan.get("will_create")
        will_create: list[Any] = raw_wc if isinstance(raw_wc, list) else []
        raw_sk = plan.get("skipped_duplicate")
        skipped: list[Any] = raw_sk if isinstance(raw_sk, list) else []
        raw_inh = plan.get("inherited_from_account")
        inherited: list[Any] = raw_inh if isinstance(raw_inh, list) else []
        wc_count = int(counts.get("will_create", len(will_create)))
        sk_count = int(counts.get("skipped_duplicate", len(skipped)))
        inh_count = int(counts.get("inherited_from_account", len(inherited)))
        self.query_one("#s1-clone-summary", Static).update(
            f"Diff Summary -> Will Create: {wc_count} | "
            f"Skipped Duplicate: {sk_count} | Inherited from Account: {inh_count}"
        )
        log = self.query_one("#s1-clone-preview-log", RichLog)
        log.clear()
        for entry in will_create[:40]:
            payload = entry.get("payload") if isinstance(entry.get("payload"), dict) else {}
            log.write(
                Text(
                    f"[Will Create] {payload.get('exclusion_type', '-')} | "
                    f"{payload.get('os_type', '-')} | {payload.get('value', '-')} | "
                    f"note={payload.get('description', '')}",
                    style="green",
                )
            )
        for entry in skipped[:25]:
            src = entry.get("source") if isinstance(entry.get("source"), dict) else {}
            log.write(
                Text(
                    f"[Skipped Duplicate] {src.get('type', '-')} | {src.get('value', '-')}",
                    style="yellow",
                )
            )
        for entry in inherited[:25]:
            src = entry.get("source") if isinstance(entry.get("source"), dict) else {}
            log.write(
                Text(
                    f"[Inherited from Account] {src.get('type', '-')} | {src.get('value', '-')}",
                    style="cyan",
                )
            )
        if not (will_create or skipped or inherited):
            log.write(Text("No source exclusions found to clone.", style="dim"))

    @on(Button.Pressed, "#s1-clone-apply-btn")
    def handle_apply(self) -> None:
        src_id = str(self.query_one("#s1-clone-src-select", Select).value or "").strip()
        dst_id = str(self.query_one("#s1-clone-dst-select", Select).value or "").strip()
        err = self.query_one("#s1-clone-error", Static)
        if not src_id or not dst_id:
            err.update("Select both a source and target site.")
            return
        if src_id == dst_id:
            err.update("Source and target sites must be different.")
            return
        raw_rps = self.query_one("#s1-clone-rps-input", Input).value.strip() or "15"
        try:
            rps = float(raw_rps)
        except ValueError:
            err.update("Max write rate must be a positive number (<= 15).")
            return
        if not math.isfinite(rps) or rps <= 0:
            err.update("Max write rate must be a finite number greater than 0.")
            return
        rps = min(rps, 15.0)
        include_parents = bool(self.query_one("#s1-clone-include-parents-cb", Checkbox).value)
        self.dismiss(
            {
                "source_site_id": src_id,
                "source_site_name": self._site_name_for_id(src_id),
                "target_site_id": dst_id,
                "target_site_name": self._site_name_for_id(dst_id),
                "include_source_parents": include_parents,
                "requests_per_second": rps,
                "plan": self._last_plan,
            }
        )

    def action_cancel(self) -> None:
        """Dismiss the clone exclusions dialog safely."""
        self.dismiss(None)


class S1SiteModal(ModalScreen[dict[str, Any] | None]):
    """Modal dialog to create, edit, or duplicate a SentinelOne site."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    S1SiteModal {
        align: center middle;
        background: $background 60%;
    }
    #s1-site-dialog {
        width: 78;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }
    #s1-site-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #s1-site-scroll {
        width: 1fr;
        height: auto;
        max-height: 48vh;
    }
    .s1-modal-label {
        height: 1;
        text-style: bold;
    }
    #s1-site-scroll Select, #s1-site-scroll Input {
        width: 1fr;
        margin-bottom: 1;
    }
    #s1-site-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #s1-site-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #s1-site-buttons {
        height: auto;
        align-horizontal: right;
    }
    #s1-site-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        mode: str = "create",
        site: Mapping[str, Any] | None = None,
        sites: Sequence[Mapping[str, Any]] = (),
        default_account_id: str = "",
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._mode = mode
        self._site = dict(site) if site else {}
        self._sites = [dict(s) for s in sites if str(s.get("id") or "").strip()]
        self._default_account_id = default_account_id.strip()
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        title_map = {
            "create": "Create SentinelOne Site",
            "edit": f"Edit SentinelOne Site ({self._site.get('id', '-')})",
            "duplicate": f"Duplicate Site ({self._site.get('name', self._site.get('id', '-'))})",
        }
        init_name = (
            f"{self._site.get('name', '')}-Copy"
            if self._mode == "duplicate" and self._site.get("name")
            else str(self._site.get("name") or "")
        )
        init_acc = str(self._site.get("accountId") or self._default_account_id or "")
        init_type = str(self._site.get("siteType") or "Paid")
        if init_type not in {"Paid", "Trial"}:
            init_type = "Paid"
        init_sku = str(self._site.get("sku") or self._site.get("suite") or "Complete")
        if init_sku not in {"Core", "Control", "Complete"}:
            init_sku = "Complete"
        init_unlimited = bool(self._site.get("unlimitedLicenses", True))
        init_licenses = (
            ""
            if self._site.get("totalLicenses") is None
            else str(self._site.get("totalLicenses"))
        )
        init_desc = str(self._site.get("description") or "")

        template_options: list[tuple[str, str]] = [("(None)", "")]
        template_options.extend(
            (_site_option_label(s), str(s.get("id") or "").strip()) for s in self._sites
        )

        with Vertical(id="s1-site-dialog"):
            yield Static(
                title_map.get(self._mode, "SentinelOne Site"),
                id="s1-site-title",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: SentinelOne site changes will be blocked.",
                    id="s1-site-dry-banner",
                    markup=False,
                )
            with VerticalScroll(id="s1-site-scroll"):
                yield Static("Tier Prefix Helper", classes="s1-modal-label", markup=False)
                yield Select(
                    [("Custom / Keep Name", ""), ("MDR- Prefix", "MDR-"), ("MSSP- Prefix", "MSSP-")],
                    allow_blank=False,
                    value="",
                    id="s1-site-prefix-select",
                    compact=True,
                )
                yield Static("Site Name", classes="s1-modal-label", markup=False)
                yield Input(
                    value=init_name,
                    placeholder="e.g. MDR-1234 or MSSP-8298",
                    id="s1-site-name-input",
                    compact=True,
                )
                if self._mode == "create":
                    yield Static("Account ID", classes="s1-modal-label", markup=False)
                    yield Input(
                        value=init_acc,
                        placeholder="Target SentinelOne Account ID",
                        id="s1-site-account-input",
                        compact=True,
                    )
                if self._mode != "duplicate":
                    yield Static("Site Type & SKU", classes="s1-modal-label", markup=False)
                    yield Select(
                        [("Paid", "Paid"), ("Trial", "Trial")],
                        allow_blank=False,
                        value=init_type,
                        id="s1-site-type-select",
                        compact=True,
                    )
                    yield Select(
                        [("Complete", "Complete"), ("Control", "Control"), ("Core", "Core")],
                        allow_blank=False,
                        value=init_sku,
                        id="s1-site-sku-select",
                        compact=True,
                    )
                yield Checkbox(
                    "Unlimited Licenses",
                    value=init_unlimited,
                    id="s1-site-unlimited-cb",
                )
                yield Static("Total Licenses (when not unlimited)", classes="s1-modal-label", markup=False)
                yield Input(
                    value=init_licenses,
                    placeholder="e.g. 50",
                    id="s1-site-licenses-input",
                    compact=True,
                )
                if self._mode != "duplicate":
                    yield Static("Description", classes="s1-modal-label", markup=False)
                    yield Input(
                        value=init_desc,
                        placeholder="Optional tenant/site description",
                        id="s1-site-desc-input",
                        compact=True,
                    )
                if self._mode == "create":
                    yield Static("Copy Policy From Template Site (Optional)", classes="s1-modal-label", markup=False)
                    yield Select(
                        template_options,
                        allow_blank=False,
                        value="",
                        id="s1-site-copy-policy-select",
                        compact=True,
                    )
                    yield Static("Clone Exclusions From Template Site (Optional)", classes="s1-modal-label", markup=False)
                    yield Select(
                        template_options,
                        allow_blank=False,
                        value="",
                        id="s1-site-clone-excl-select",
                        compact=True,
                    )
                elif self._mode == "duplicate":
                    yield Static("Policy Source", classes="s1-modal-label", markup=False)
                    yield Select(
                        [
                            ("Copy Source Site Policy", "copy_source_site"),
                            ("Inherit Global Policy", "inherit_global"),
                        ],
                        allow_blank=False,
                        value="copy_source_site",
                        id="s1-site-dup-policy-select",
                        compact=True,
                    )
                    yield Checkbox("Copy Users from Source Site", value=False, id="s1-site-copy-users-cb")
            yield Static("", id="s1-site-error", markup=False)
            with Horizontal(id="s1-site-buttons"):
                yield Button("Cancel", id="s1-site-cancel-btn", variant="default", compact=True)
                yield Button("Save Site", id="s1-site-save-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#s1-site-name-input", Input).focus()

    @on(Select.Changed, "#s1-site-prefix-select")
    def handle_prefix_changed(self, event: Select.Changed) -> None:
        prefix = str(event.value or "")
        if not prefix:
            return
        name_inp = self.query_one("#s1-site-name-input", Input)
        current = name_inp.value.strip()
        for known in ("MDR-", "MSSP-"):
            if current.upper().startswith(known):
                current = current[len(known) :]
                break
        with name_inp.prevent(Input.Changed):
            name_inp.value = f"{prefix}{current}"

    @on(Button.Pressed, "#s1-site-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#s1-site-save-btn")
    def handle_save(self) -> None:
        err = self.query_one("#s1-site-error", Static)
        name = self.query_one("#s1-site-name-input", Input).value.strip()
        if not name:
            err.update("Site name is required.")
            self.query_one("#s1-site-name-input", Input).focus()
            return
        unlimited = bool(self.query_one("#s1-site-unlimited-cb", Checkbox).value)
        raw_licenses = self.query_one("#s1-site-licenses-input", Input).value.strip()
        total_licenses: int | None = None
        if not unlimited:
            if not raw_licenses or not (raw_licenses.isascii() and raw_licenses.isdigit()):
                err.update("Enter a valid integer license count or enable Unlimited Licenses.")
                return
            try:
                total_licenses = int(raw_licenses)
            except ValueError:
                err.update("Enter a valid integer license count or enable Unlimited Licenses.")
                return

        payload: dict[str, Any] = {
            "mode": self._mode,
            "name": name,
            "unlimited_licenses": unlimited,
            "total_licenses": total_licenses,
        }
        if self._mode == "create":
            payload["account_id"] = self.query_one("#s1-site-account-input", Input).value.strip()
            payload["site_type"] = str(self.query_one("#s1-site-type-select", Select).value or "Paid")
            payload["sku"] = str(self.query_one("#s1-site-sku-select", Select).value or "Complete")
            payload["description"] = self.query_one("#s1-site-desc-input", Input).value.strip()
            payload["copy_policy_from_site_id"] = str(
                self.query_one("#s1-site-copy-policy-select", Select).value or ""
            ).strip()
            payload["clone_exclusions_from_site_id"] = str(
                self.query_one("#s1-site-clone-excl-select", Select).value or ""
            ).strip()
        elif self._mode == "edit":
            payload["site_id"] = str(self._site.get("id") or "").strip()
            payload["site_type"] = str(self.query_one("#s1-site-type-select", Select).value or "Paid")
            payload["suite"] = str(self.query_one("#s1-site-sku-select", Select).value or "Complete")
            payload["description"] = self.query_one("#s1-site-desc-input", Input).value.strip()
        elif self._mode == "duplicate":
            payload["source_site_id"] = str(self._site.get("id") or "").strip()
            payload["policy_source"] = str(
                self.query_one("#s1-site-dup-policy-select", Select).value or "copy_source_site"
            )
            payload["copy_users"] = bool(self.query_one("#s1-site-copy-users-cb", Checkbox).value)
        self.dismiss(payload)

    def action_cancel(self) -> None:
        """Dismiss site modal safely."""
        self.dismiss(None)


class S1SitePolicyModal(ModalScreen[dict[str, Any] | None]):
    """Modal dialog to inspect, copy, or revert a SentinelOne site policy."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    S1SitePolicyModal {
        align: center middle;
        background: $background 60%;
    }
    #s1-policy-dialog {
        width: 78;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }
    #s1-policy-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #s1-policy-scroll {
        width: 1fr;
        height: auto;
        max-height: 48vh;
    }
    #s1-policy-log {
        height: 9;
        min-height: 5;
        max-height: 14;
        border: round #2e3c5c;
        margin-bottom: 1;
    }
    #s1-policy-src-select {
        width: 1fr;
        margin-bottom: 1;
    }
    #s1-policy-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #s1-policy-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #s1-policy-buttons {
        height: auto;
        align-horizontal: right;
    }
    #s1-policy-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        site_id: str,
        site_name: str,
        policy: Mapping[str, Any],
        sites: Sequence[Mapping[str, Any]] = (),
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._site_id = site_id.strip()
        self._site_name = site_name.strip() or self._site_id
        self._policy = dict(policy)
        self._sites = [
            dict(s)
            for s in sites
            if str(s.get("id") or "").strip() and str(s.get("id") or "").strip() != self._site_id
        ]
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        src_options: list[tuple[str, str]] = [("(Select template site to copy from)", "")]
        src_options.extend(
            (_site_option_label(s), str(s.get("id") or "").strip()) for s in self._sites
        )
        with Vertical(id="s1-policy-dialog"):
            yield Static(
                f"Site Policy: {self._site_name} ({self._site_id})",
                id="s1-policy-title",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: policy modifications are blocked.",
                    id="s1-policy-dry-banner",
                    markup=False,
                )
            with VerticalScroll(id="s1-policy-scroll"):
                yield SelectableRichLog(id="s1-policy-log", highlight=False, markup=False, wrap=True)
                yield Select(
                    src_options,
                    allow_blank=False,
                    value="",
                    id="s1-policy-src-select",
                    compact=True,
                )
            yield Static("", id="s1-policy-error", markup=False)
            with Horizontal(id="s1-policy-buttons"):
                yield Button("Close", id="s1-policy-cancel-btn", variant="default", compact=True)
                yield Button(
                    "Revert to Account",
                    id="s1-policy-revert-btn",
                    variant="warning",
                    compact=True,
                )
                yield Button(
                    "Copy Selected Policy",
                    id="s1-policy-copy-btn",
                    variant="primary",
                    compact=True,
                )

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        from soclens.tui.s1_formatters import render_s1_policy_detail

        log = self.query_one("#s1-policy-log", RichLog)
        log.write(
            render_s1_policy_detail(
                self._policy,
                site_name=self._site_name,
                site_id=self._site_id,
            )
        )
        self.query_one("#s1-policy-cancel-btn", Button).focus()

    @on(Button.Pressed, "#s1-policy-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#s1-policy-copy-btn")
    def handle_copy(self) -> None:
        src_id = str(self.query_one("#s1-policy-src-select", Select).value or "").strip()
        if not src_id:
            self.query_one("#s1-policy-error", Static).update(
                "Select a template site to copy policy from."
            )
            return
        self.dismiss({"action": "copy", "source_site_id": src_id})

    @on(Button.Pressed, "#s1-policy-revert-btn")
    def handle_revert(self) -> None:
        self.dismiss({"action": "revert"})

    def action_cancel(self) -> None:
        """Dismiss site policy modal safely."""
        self.dismiss(None)


class S1UserModal(ModalScreen[dict[str, Any] | None]):
    """Create/Edit Console User or Service User modal with RBAC & tier permission cloning."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    S1UserModal {
        align: center middle;
        background: $background 60%;
    }
    #s1-user-dialog {
        width: 78;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }
    #s1-user-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #s1-user-scroll {
        width: 1fr;
        height: auto;
        max-height: 48vh;
    }
    .s1-modal-label {
        height: 1;
        text-style: bold;
    }
    #s1-user-scroll Select, #s1-user-scroll Input {
        width: 1fr;
        margin-bottom: 1;
    }
    #s1-user-dry-banner {
        color: $warning;
        margin-bottom: 1;
    }
    #s1-user-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #s1-user-buttons {
        height: auto;
        align-horizontal: right;
    }
    #s1-user-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        mode: str = "create",
        kind: str = "console",
        user: Mapping[str, Any] | None = None,
        existing_users: Sequence[Mapping[str, Any]] = (),
        roles: Sequence[Mapping[str, Any]] = (),
        sites: Sequence[Mapping[str, Any]] = (),
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._mode = mode
        self._kind = kind
        self._user = dict(user) if user else {}
        self._existing_users = [dict(u) for u in existing_users if str(u.get("id") or "").strip()]
        self._roles = [dict(r) for r in roles if str(r.get("id") or "").strip()]
        self._sites = [dict(s) for s in sites if str(s.get("id") or "").strip()]
        self._dry_run = dry_run
        self._existing_scope_roles: list[dict[str, Any]] = []
        self._init_role_id: str = ""
        self._init_role_name: str = ""
        self._init_site_ids: list[str] = []
        self._role_options: list[tuple[str, str]] = []
        self._site_options: list[tuple[str, str]] = []
        if self._mode == "edit":
            raw_sr = self._user.get("scopeRoles")
            if isinstance(raw_sr, Sequence) and not isinstance(raw_sr, (str, bytes)):
                self._existing_scope_roles = [dict(sr) for sr in raw_sr if isinstance(sr, Mapping)]
            seen_sites: set[str] = set()
            for sr in self._existing_scope_roles:
                if not self._init_role_id:
                    rid = sr.get("roleId") or sr.get("roleID")
                    if rid is not None and str(rid).strip():
                        self._init_role_id = str(rid).strip()
                        self._init_role_name = str(sr.get("roleName") or "").strip()
                sid = sr.get("id")
                if sid is not None:
                    clean_sid = str(sid).strip()
                    if clean_sid and clean_sid not in seen_sites:
                        seen_sites.add(clean_sid)
                        self._init_site_ids.append(clean_sid)

    def compose(self) -> ComposeResult:
        kind_label = "Service User" if self._kind == "service" else "Console User"
        title = (
            f"Create SentinelOne {kind_label}"
            if self._mode == "create"
            else f"Edit SentinelOne {kind_label} ({self._user.get('id', '-')})"
        )
        init_name = str(self._user.get("fullName") or self._user.get("name") or "")
        init_email = str(self._user.get("email") or "")
        init_scope = str(self._user.get("scope") or "site").lower()
        if init_scope not in {"site", "account", "tenant"}:
            init_scope = "site"

        role_default_label = (
            "(Preserve Existing Multi-Site Roles)"
            if self._mode == "edit" and len(self._existing_scope_roles) > 1
            else "(From Template / Default)"
        )
        role_options: list[tuple[str, str]] = [(role_default_label, "")]
        for role in self._roles:
            rid = str(role.get("id") or "").strip()
            rname = str(role.get("name") or rid).strip()
            role_options.append((f"{rname} ({rid})", rid))
        self._role_options = role_options

        template_options: list[tuple[str, str]] = [("(None - Use Selected Role)", "")]
        for u in self._existing_users:
            uid = str(u.get("id") or "").strip()
            ulabel = str(u.get("email") or u.get("fullName") or u.get("name") or uid).strip()
            template_options.append((f"{ulabel} ({uid})", uid))

        site_default_label = (
            "(Preserve Existing Sites / Scope Default)"
            if self._mode == "edit" and len(self._existing_scope_roles) > 1
            else "(Current / Account Scope)"
        )
        site_options: list[tuple[str, str]] = [(site_default_label, "")]
        for s in self._sites:
            site_options.append((_site_option_label(s), str(s.get("id") or "").strip()))
        self._site_options = site_options

        with Vertical(id="s1-user-dialog"):
            yield Static(title, id="s1-user-title", markup=False)
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: SentinelOne user changes will be blocked.",
                    id="s1-user-dry-banner",
                    markup=False,
                )
            with VerticalScroll(id="s1-user-scroll"):
                yield Static(
                    "Service User Name" if self._kind == "service" else "Full Name",
                    classes="s1-modal-label",
                    markup=False,
                )
                yield Input(
                    value=init_name,
                    placeholder="Name",
                    id="s1-user-name-input",
                    compact=True,
                )
                if self._kind == "console":
                    yield Static("Email", classes="s1-modal-label", markup=False)
                    yield Input(
                        value=init_email,
                        placeholder="analyst@example.com",
                        id="s1-user-email-input",
                        compact=True,
                    )
                yield Static("Scope", classes="s1-modal-label", markup=False)
                yield Select(
                    [("Site Scope", "site"), ("Account Scope", "account"), ("Tenant Scope", "tenant")],
                    allow_blank=False,
                    value=init_scope,
                    id="s1-user-scope-select",
                    compact=True,
                )
                yield Static("RBAC Role", classes="s1-modal-label", markup=False)
                yield Select(
                    role_options,
                    allow_blank=False,
                    value="",
                    id="s1-user-role-select",
                    compact=True,
                )
                yield Static("Copy Permissions from Existing User (Optional)", classes="s1-modal-label", markup=False)
                yield Select(
                    template_options,
                    allow_blank=False,
                    value="",
                    id="s1-user-template-select",
                    compact=True,
                )
                yield Static("Target Site or Tier Bulk Assignment", classes="s1-modal-label", markup=False)
                yield Select(
                    [
                        ("Single Site (below) / Scope Default", "single"),
                        ("All MDR Tier Sites", "tier:MDR"),
                        ("All MSSP Tier Sites", "tier:MSSP"),
                    ],
                    allow_blank=False,
                    value="single",
                    id="s1-user-tier-select",
                    compact=True,
                )
                yield Select(
                    site_options,
                    allow_blank=False,
                    value="",
                    id="s1-user-site-select",
                    compact=True,
                )
                if self._kind == "service" and self._mode == "create":
                    yield Static("Expiration Date (ISO-8601)", classes="s1-modal-label", markup=False)
                    yield Input(
                        value="2027-12-31T00:00:00Z",
                        placeholder="2027-12-31T00:00:00Z",
                        id="s1-user-exp-input",
                        compact=True,
                    )
                if self._kind == "console":
                    yield Checkbox(
                        "Require 2FA",
                        value=bool(self._user.get("twoFaEnabled", True)),
                        id="s1-user-2fa-cb",
                    )
            yield Static("", id="s1-user-error", markup=False)
            with Horizontal(id="s1-user-buttons"):
                yield Button("Cancel", id="s1-user-cancel-btn", variant="default", compact=True)
                yield Button("Save User", id="s1-user-save-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        if self._mode == "edit":
            if self._init_role_id and len(self._existing_scope_roles) <= 1:
                role_sel = self.query_one("#s1-user-role-select", Select)
                known_roles = {val for _lbl, val in self._role_options}
                with role_sel.prevent(Select.Changed):
                    if self._init_role_id not in known_roles:
                        label = (
                            f"{self._init_role_name} ({self._init_role_id})"
                            if self._init_role_name
                            else f"Current Role ({self._init_role_id})"
                        )
                        self._role_options.append((label, self._init_role_id))
                        role_sel.set_options(self._role_options)
                    role_sel.value = self._init_role_id
            if len(self._init_site_ids) == 1:
                init_sid = self._init_site_ids[0]
                site_sel = self.query_one("#s1-user-site-select", Select)
                known_sites = {val for _lbl, val in self._site_options}
                with site_sel.prevent(Select.Changed):
                    if init_sid not in known_sites:
                        self._site_options.append((f"Current Scope ({init_sid})", init_sid))
                        site_sel.set_options(self._site_options)
                    site_sel.value = init_sid
        self.query_one("#s1-user-name-input", Input).focus()

    @on(Button.Pressed, "#s1-user-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#s1-user-save-btn")
    def handle_save(self) -> None:
        err = self.query_one("#s1-user-error", Static)
        name = self.query_one("#s1-user-name-input", Input).value.strip()
        if not name:
            err.update("Name is required.")
            self.query_one("#s1-user-name-input", Input).focus()
            return
        email = ""
        if self._kind == "console":
            email = self.query_one("#s1-user-email-input", Input).value.strip()
            if not email or "@" not in email:
                err.update("Valid email is required for console users.")
                self.query_one("#s1-user-email-input", Input).focus()
                return

        scope = str(self.query_one("#s1-user-scope-select", Select).value or "site")
        role_id = str(self.query_one("#s1-user-role-select", Select).value or "").strip()
        template_user_id = str(
            self.query_one("#s1-user-template-select", Select).value or ""
        ).strip()
        tier_choice = str(self.query_one("#s1-user-tier-select", Select).value or "single")
        selected_site_id = str(self.query_one("#s1-user-site-select", Select).value or "").strip()

        target_site_ids: list[str] = []
        if tier_choice.startswith("tier:"):
            target_tier = tier_choice.split(":", 1)[1]
            for site in self._sites:
                sid = str(site.get("id") or "").strip()
                sname = str(site.get("name") or "").strip()
                tier = str(site.get("tier") or "").strip()
                if not tier and sname:
                    tier, _ = classify_site_tier(sname, site_id=sid or None)
                if sid and tier == target_tier:
                    target_site_ids.append(sid)
        elif selected_site_id:
            target_site_ids.append(selected_site_id)
        elif self._mode == "edit" and not template_user_id and role_id and len(self._init_site_ids) > 1:
            target_site_ids = list(self._init_site_ids)

        result: dict[str, Any] = {
            "mode": self._mode,
            "kind": self._kind,
            "user_id": str(self._user.get("id") or "").strip(),
            "name": name,
            "email": email,
            "scope": scope,
            "role_id": role_id,
            "template_user_id": template_user_id,
            "target_site_ids": target_site_ids,
        }
        if self._mode == "edit" and self._existing_scope_roles:
            result["existing_scope_roles"] = [dict(sr) for sr in self._existing_scope_roles]
        if self._kind == "console":
            result["two_fa_enabled"] = bool(self.query_one("#s1-user-2fa-cb", Checkbox).value)
        elif self._mode == "create":
            exp = self.query_one("#s1-user-exp-input", Input).value.strip()
            if not exp:
                err.update("Expiration date is required for service users.")
                return
            result["expiration_date"] = exp
        self.dismiss(result)

    def action_cancel(self) -> None:
        """Dismiss user modal safely."""
        self.dismiss(None)


class S1MoveAgentModal(ModalScreen[str | None]):
    """Modal dialog to select a target site when moving SentinelOne agents."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    S1MoveAgentModal {
        align: center middle;
        background: $background 60%;
    }
    #s1-move-dialog {
        width: 76;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }
    #s1-move-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #s1-move-scroll {
        width: 1fr;
        height: auto;
        max-height: 45vh;
    }
    #s1-move-target-site-select {
        width: 1fr;
        margin-bottom: 1;
    }
    #s1-move-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #s1-move-buttons {
        height: auto;
        align-horizontal: right;
    }
    #s1-move-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        *,
        agent_summary: str,
        sites: Sequence[Mapping[str, Any]],
        dry_run: bool = False,
    ) -> None:
        super().__init__()
        self._agent_summary = agent_summary
        self._sites = [dict(s) for s in sites if str(s.get("id") or "").strip()]
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        options: list[tuple[str, str]] = [
            (_site_option_label(s), str(s.get("id") or "").strip()) for s in self._sites
        ]
        if not options:
            options = [("(No sites loaded)", "")]
        with Vertical(id="s1-move-dialog"):
            yield Static(
                f"Move Endpoint(s) to Site: {self._agent_summary}",
                id="s1-move-title",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: agent move will be blocked.",
                    markup=False,
                )
            with VerticalScroll(id="s1-move-scroll"):
                yield Select(
                    options,
                    allow_blank=False,
                    value=options[0][1],
                    id="s1-move-target-site-select",
                    compact=True,
                )
            yield Static("", id="s1-move-error", markup=False)
            with Horizontal(id="s1-move-buttons"):
                yield Button("Cancel", id="s1-move-cancel-btn", variant="default", compact=True)
                yield Button("Move Agent", id="s1-move-apply-btn", variant="warning", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#s1-move-target-site-select", Select).focus()

    @on(Button.Pressed, "#s1-move-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#s1-move-apply-btn")
    def handle_apply(self) -> None:
        target = str(self.query_one("#s1-move-target-site-select", Select).value or "").strip()
        if not target:
            self.query_one("#s1-move-error", Static).update("Select a target site.")
            return
        self.dismiss(target)

    def action_cancel(self) -> None:
        """Dismiss move agent modal safely."""
        self.dismiss(None)


class S1EditExclusionModal(ModalScreen[dict[str, str] | None]):
    """Modal dialog for editing an existing SentinelOne exclusion."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    S1EditExclusionModal {
        align: center middle;
        background: $background 60%;
    }
    #s1-edit-excl-dialog {
        width: 76;
        max-width: 94%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 0 2;
    }
    #s1-edit-excl-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #s1-edit-excl-scroll {
        width: 1fr;
        height: auto;
        max-height: 45vh;
    }
    .s1-modal-label {
        height: 1;
        text-style: bold;
    }
    #s1-edit-excl-scroll Select, #s1-edit-excl-scroll Input {
        width: 1fr;
        margin-bottom: 1;
    }
    #s1-edit-excl-error {
        color: $error;
        height: auto;
        margin-bottom: 1;
    }
    #s1-edit-excl-buttons {
        height: auto;
        align-horizontal: right;
    }
    #s1-edit-excl-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(self, *, exclusion: Mapping[str, Any], dry_run: bool = False) -> None:
        super().__init__()
        self._exclusion = dict(exclusion)
        self._dry_run = dry_run

    def compose(self) -> ComposeResult:
        excl_id = str(self._exclusion.get("id") or "").strip()
        excl_type = str(self._exclusion.get("type") or "path").strip().lower()
        os_type = str(self._exclusion.get("osType") or "windows").strip().lower()
        mode = str(self._exclusion.get("mode") or "suppress").strip().lower()
        value = str(self._exclusion.get("value") or "")
        desc = str(self._exclusion.get("description") or "")

        with Vertical(id="s1-edit-excl-dialog"):
            yield Static(
                f"Edit SentinelOne Exclusion ({excl_id})",
                id="s1-edit-excl-title",
                markup=False,
            )
            if self._dry_run:
                yield Static(
                    "[DRY-RUN] Preview only: exclusion update will be blocked.",
                    markup=False,
                )
            with VerticalScroll(id="s1-edit-excl-scroll"):
                yield Static("Value", classes="s1-modal-label", markup=False)
                yield Input(value=value, id="s1-edit-excl-value-input", compact=True)
                yield Static("Mode", classes="s1-modal-label", markup=False)
                yield Select(
                    [
                        ("Suppress Alerts", "suppress"),
                        ("Suppress Dynamic Only", "suppress_dynamic_only"),
                        ("Suppress DFI Only", "suppress_dfi_only"),
                        ("Interoperability (Disable In-Process)", "disable_in_process_monitor"),
                        ("Interoperability Extended", "disable_in_process_monitor_deep"),
                        ("Performance Focus", "disable_all_monitors"),
                        ("Performance Focus Extended", "disable_all_monitors_deep"),
                        ("Suppress App Control", "suppress_app_control"),
                        ("Suppress Drift Detection", "suppress_drift_detection"),
                    ],
                    allow_blank=False,
                    value=mode if mode in {
                        "suppress",
                        "suppress_dynamic_only",
                        "suppress_dfi_only",
                        "disable_in_process_monitor",
                        "disable_in_process_monitor_deep",
                        "disable_all_monitors",
                        "disable_all_monitors_deep",
                        "suppress_app_control",
                        "suppress_drift_detection",
                    } else "suppress",
                    id="s1-edit-excl-mode-select",
                    compact=True,
                )
                yield Static("Description", classes="s1-modal-label", markup=False)
                yield Input(value=desc, id="s1-edit-excl-desc-input", compact=True)
                yield Static(
                    f"Type: {excl_type} | OS: {os_type}",
                    markup=False,
                )
            yield Static("", id="s1-edit-excl-error", markup=False)
            with Horizontal(id="s1-edit-excl-buttons"):
                yield Button("Cancel", id="s1-edit-excl-cancel-btn", variant="default", compact=True)
                yield Button("Save Changes", id="s1-edit-excl-save-btn", variant="primary", compact=True)

    def on_mount(self) -> None:
        if not self.app.is_running or getattr(self.app, "_exit", False):
            return
        self.query_one("#s1-edit-excl-value-input", Input).focus()

    @on(Button.Pressed, "#s1-edit-excl-cancel-btn")
    def handle_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#s1-edit-excl-save-btn")
    def handle_save(self) -> None:
        val = self.query_one("#s1-edit-excl-value-input", Input).value.strip()
        if not val:
            self.query_one("#s1-edit-excl-error", Static).update("Exclusion value is required.")
            return
        self.dismiss(
            {
                "id": str(self._exclusion.get("id") or "").strip(),
                "type": str(self._exclusion.get("type") or "path").strip().lower(),
                "os_type": str(self._exclusion.get("osType") or "windows").strip().lower(),
                "value": val,
                "mode": str(self.query_one("#s1-edit-excl-mode-select", Select).value or "suppress"),
                "description": self.query_one("#s1-edit-excl-desc-input", Input).value.strip(),
            }
        )

    def action_cancel(self) -> None:
        """Dismiss edit exclusion dialog safely."""
        self.dismiss(None)
