"""Tier 1 opaque-box E2E tests for Sigma, Splunk, Bundler, CLI & Windows TUI (F11-F15)."""

from __future__ import annotations

import ast
import asyncio
import configparser
import importlib
import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from tests.e2e.conftest import BrandHTTPServer, MockRFServer, MockSplunkServer

pytestmark = [pytest.mark.e2e, pytest.mark.tier1]

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_BUNDLE_ITEMS: tuple[str, ...] = (
    "soclens",
    "pyproject.toml",
    "requirements.txt",
    "README.md",
    "ignored_hashes.txt",
    "docs",
    "scripts",
)
POSIX_ONLY_MODULES: frozenset[str] = frozenset(
    {
        "fcntl",
        "termios",
        "tty",
        "pty",
        "pwd",
        "grp",
        "resource",
        "curses",
        "syslog",
        "posix",
    }
)
WORKFLOW_KEYWORDS: dict[str, tuple[str, ...]] = {
    "dashboard": ("dashboard", "diagnostic", "home", "status", "overview"),
    "watchlists": ("watchlist", "watchlists", "lists"),
    "brand_logos": ("brand", "logo", "logos"),
    "rf_intel": ("intel", "recorded future", "rf", "alert", "soar", "enrich"),
    "sigma": ("sigma", "detection", "rule"),
    "splunk_bundle": ("splunk", "validat", "bundle"),
}


def _stage_bundle_workspace(dest: Path) -> Path:
    """Copy clean toolkit files into an isolated temporary workspace for bundler tests."""
    dest.mkdir(parents=True, exist_ok=True)
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", "*.log", "*.key", ".git", ".venv")
    for item_name in WORKSPACE_BUNDLE_ITEMS:
        src = REPO_ROOT / item_name
        if not src.exists():
            continue
        target = dest / item_name
        if src.is_dir():
            shutil.copytree(src, target, ignore=ignore, dirs_exist_ok=True)
        else:
            shutil.copy2(src, target)
    if not (dest / "ignored_hashes.txt").exists():
        (dest / "ignored_hashes.txt").write_text("# ignored hashes\n", encoding="utf-8")
    (dest / "sigma_rules_cache.json").write_text("[]\n", encoding="utf-8")
    return dest


def _seed_sigma_cache(workspace: Path) -> Path:
    """Write deterministic Sigma rule cache entries inside e2e_workspace."""
    cache_path = workspace / "sigma_rules_cache.json"
    rules = [
        {
            "rule_id": "doc:sigma-1",
            "rule_set_title": "PowerShell Encoded Command Detection",
            "title": "Suspicious PowerShell Encoded Command",
            "description": "Detects encoded PowerShell command line usage",
            "file_name": "proc_creation_win_powershell_encoded.yml",
            "author": "RF Threat Research",
            "level": "high",
            "product": "windows",
            "service": "powershell",
            "index": "*wineventlog",
            "mitre_techniques": ["T1059.001"],
            "references": ["https://attack.mitre.org/techniques/T1059/001/"],
            "content": (
                "title: Suspicious PowerShell Encoded Command\n"
                "id: 11111111-1111-1111-1111-111111111111\n"
                "status: stable\n"
                "description: Detects encoded PowerShell command line usage\n"
                "logsource:\n"
                "  category: process_creation\n"
                "  product: windows\n"
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains: '-EncodedCommand'\n"
                "  condition: selection\n"
                "level: high\n"
            ),
        }
    ]
    cache_path.write_text(json.dumps(rules, indent=2), encoding="utf-8")
    return cache_path


def _write_sample_savedsearches(path: Path) -> Path:
    """Create a valid Splunk savedsearches.conf test file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "[RF Sigma Test Rule]\n"
        "description = Detects suspicious PowerShell command\n"
        "search = index=*wineventlog CommandLine=\"*-EncodedCommand*\" | table _time host User\n"
        "enableSched = 1\n",
        encoding="utf-8",
    )
    return path


def _create_tui_app(*, client: Any = None, dry_run: bool = False) -> Any:
    """Discover and instantiate the soclens.tui Textual App without hardcoding internal names."""
    pytest.importorskip("textual")
    tui_pkg = pytest.importorskip("soclens.tui")
    textual_app_mod = importlib.import_module("textual.app")
    app_base = textual_app_mod.App

    candidates: list[Any] = [tui_pkg]
    try:
        candidates.append(importlib.import_module("soclens.tui.app"))
    except ModuleNotFoundError:
        pass

    factory_names = ("create_app", "build_app")
    for mod in candidates:
        for fname in factory_names:
            fn = getattr(mod, fname, None)
            if callable(fn):
                sig = inspect.signature(fn)
                kwargs: dict[str, Any] = {}
                if "client" in sig.parameters and client is not None:
                    kwargs["client"] = client
                if "dry_run" in sig.parameters:
                    kwargs["dry_run"] = dry_run
                return fn(**kwargs)

    app_classes: list[type[Any]] = []
    for mod in candidates:
        for obj in vars(mod).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, app_base)
                and obj is not app_base
                and getattr(obj, "__module__", "").startswith("soclens.tui")
                and obj not in app_classes
            ):
                app_classes.append(obj)

    assert app_classes, "soclens.tui exposes no Textual App subclass or create_app/build_app factory"
    preferred_names = ("SocLensApp", "RecordedFutureApp", "SocApp", "TuiApp")
    chosen = next((cls for cls in app_classes if cls.__name__ in preferred_names), app_classes[0])
    sig = inspect.signature(chosen.__init__)
    kwargs = {}
    if "client" in sig.parameters and client is not None:
        kwargs["client"] = client
    if "dry_run" in sig.parameters:
        kwargs["dry_run"] = dry_run
    return chosen(**kwargs)


def _collect_tui_text(app: Any) -> str:
    """Gather visible labels, statics, logs, table cells, and notifications from a mounted App."""
    chunks: list[str] = []
    for widget in app.query("*"):
        for attr in ("renderable", "label", "value", "placeholder", "title"):
            val = getattr(widget, attr, None)
            if val is not None and not callable(val):
                chunks.append(str(val))
        lines = getattr(widget, "lines", None)
        if isinstance(lines, list):
            for line in lines:
                chunks.append(str(getattr(line, "text", line)))
        rows = getattr(widget, "rows", None)
        if rows is not None and hasattr(widget, "get_row"):
            try:
                for row_key in rows:
                    chunks.extend(str(cell) for cell in widget.get_row(row_key))
            except Exception:
                pass
    for notif in getattr(app, "_notifications", []) or []:
        chunks.append(str(getattr(notif, "message", notif)))
        chunks.append(str(getattr(notif, "title", "")))
    return "\n".join(chunks)


def _collect_workflow_labels(app: Any) -> list[str]:
    """Collect tab labels and screen/binding labels exposed by the TUI App."""
    textual_widgets = importlib.import_module("textual.widgets")
    labels: list[str] = []
    for pane in app.query(textual_widgets.TabPane):
        label = getattr(pane, "label", None) or getattr(pane, "_title", None) or pane.id or ""
        labels.append(str(label).lower())
    for tab in app.query(textual_widgets.Tab):
        labels.append(str(getattr(tab, "label", "")).lower())
    for screen_name in getattr(app, "SCREENS", {}) or {}:
        labels.append(str(screen_name).lower())
    for binding in getattr(app, "BINDINGS", []) or []:
        desc = getattr(binding, "description", None)
        if desc is None and isinstance(binding, tuple) and len(binding) >= 3:
            desc = binding[2]
        if desc:
            labels.append(str(desc).lower())
    return labels


# ==============================================================================
# F11: Sigma & Splunk Conversion Hardening (Tier 1)
# ==============================================================================


@pytest.mark.feature("F11")
def test_f11_sigma_load_rules_cache_creation_and_hit(
    e2e_workspace: Path, mock_rf_server: MockRFServer
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.sigma import load_rules

    repo_cache = REPO_ROOT / "sigma_rules_cache.json"
    repo_cache_before = repo_cache.read_bytes() if repo_cache.exists() else None

    client = RecordedFutureClient()
    rules = load_rules(client, refresh=True, cache_dir=e2e_workspace)

    ws_cache = e2e_workspace / "sigma_rules_cache.json"
    assert ws_cache.is_file()
    rule_ids = {r.get("rule_id") for r in rules}
    assert {"doc:sigma-1", "doc:sigma-2"}.issubset(rule_ids)
    assert len(rules) == 2

    if repo_cache_before is None:
        assert not repo_cache.exists()
    else:
        assert repo_cache.read_bytes() == repo_cache_before

    mock_rf_server.requests_log.clear()
    cached = load_rules(client, refresh=False, cache_dir=e2e_workspace)
    assert cached == rules
    assert [r for r in mock_rf_server.requests_log if "/detection-rule" in r["path"]] == []


@pytest.mark.feature("F11")
def test_f11_sigma_search_and_rule_filtering(
    e2e_workspace: Path, mock_rf_server: MockRFServer
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.sigma import flatten_rules, search_rules

    client = RecordedFutureClient()
    yara_rules = client.search_detection_rules(rule_types=["yara"])
    assert [r["id"] for r in yara_rules] == ["doc:yara-1"]

    t1105_sigma = client.search_detection_rules(rule_types=["sigma"], entities=["mitre:T1105"])
    assert [r["id"] for r in t1105_sigma] == ["doc:sigma-2"]

    mock_rf_server.requests_log.clear()
    recent_rules = client.search_detection_rules(days=1)
    assert recent_rules == []
    dr_reqs = [r for r in mock_rf_server.requests_log if r["path"] == "/detection-rule/search"]
    assert len(dr_reqs) == 1
    assert "after" in dr_reqs[0]["body_json"]["filter"]["updated"]

    all_sigma = flatten_rules(client.search_detection_rules(rule_types=["sigma"]))
    certutil_hits = search_rules(all_sigma, "certutil")
    assert certutil_hits
    assert certutil_hits[0]["title"] == "Suspicious Certutil Download"

    ps_hits = search_rules(all_sigma, "powershell encoded")
    assert any("PowerShell Encoded Command" in str(r.get("title", "")) for r in ps_hits)


@pytest.mark.feature("F11")
def test_f11_sigma_export_splunk_parent_dir_and_configparser_roundtrip(
    e2e_workspace: Path, mock_rf_server: MockRFServer
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.sigma import export_rules_to_splunk, load_rules
    from soclens.splunk import parse_savedsearches_files

    client = RecordedFutureClient()
    rules = load_rules(client, refresh=True, cache_dir=e2e_workspace)
    base_out = e2e_workspace / "nested" / "splunk" / "savedsearches.conf"

    export_rules_to_splunk(
        rules,
        base_out,
        write_mode="overwrite",
        cron_schedule="15 * * * *",
        earliest_time="-90m",
        latest_time="-5m",
        suppress_period="3600s",
    )

    exported_file = e2e_workspace / "nested" / "splunk" / "savedsearches_wineventlog.conf"
    assert exported_file.is_file()

    parsed_searches = parse_savedsearches_files(exported_file)
    assert len(parsed_searches) == 2
    assert all("index=*wineventlog" in item["search"] for item in parsed_searches)

    cp = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
    cp.read_string(exported_file.read_text(encoding="utf-8"))
    assert len(cp.sections()) == 2
    for section in cp.sections():
        assert cp[section]["enableSched"] == "1"
        assert cp[section]["action.notable"] == "1"
        assert cp[section]["cron_schedule"] == "15 * * * *"
        assert cp[section]["dispatch.earliest_time"] == "-90m"
        assert cp[section]["dispatch.latest_time"] == "-5m"
        assert cp[section]["alert.suppress.period"] == "3600s"


@pytest.mark.feature("F11")
def test_f11_sigma_tstats_leading_pipe_spl_generation(e2e_workspace: Path) -> None:
    from soclens.sigma import convert_to_savedsearch_stanza

    stanza_text = convert_to_savedsearch_stanza(
        rule_id="r-tstats-1",
        rule_title="Tstats Process Rule",
        rule_content="title: Tstats Process Rule\nlevel: high\nlogsource:\n  product: windows\n",
        splunk_query=(
            "| tstats count from datamodel=Endpoint.Processes "
            "where Processes.process_name=cmd.exe by Processes.user"
        ),
        index_val="*wineventlog",
    )
    cp = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
    cp.read_string(stanza_text)
    sections = cp.sections()
    assert len(sections) == 1
    spl = cp[sections[0]]["search"]
    assert spl.startswith("| tstats ")
    assert not spl.startswith("index=")
    assert "||" not in spl
    assert "| table " in spl


@pytest.mark.feature("F11")
def test_f11_sigma_configurable_table_and_suppress_fields(
    e2e_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from soclens.sigma import (
        convert_to_savedsearch_stanza,
        get_suppress_fields_for_logsource,
        get_table_fields_for_logsource,
    )

    monkeypatch.delenv("SOCLENS_TENANT_FIELD", raising=False)
    monkeypatch.delenv("SOCLENS_DEFAULT_TABLE_FIELDS", raising=False)
    monkeypatch.delenv("SOCLENS_DEFAULT_SUPPRESS_FIELDS", raising=False)

    aws_logsource = {"product": "aws", "service": "cloudtrail"}
    default_table = get_table_fields_for_logsource(aws_logsource)
    default_suppress = get_suppress_fields_for_logsource(aws_logsource)
    assert default_table == (
        "_time src_ip user eventName eventSource userIdentity.arn "
        "sourceIPAddress userAgent awsRegion"
    )
    assert default_suppress == "userIdentity.arn,eventName"

    monkeypatch.setenv("SOCLENS_TENANT_FIELD", "TENANT_ID")
    assert "TENANT_ID" in get_table_fields_for_logsource(aws_logsource)
    assert get_suppress_fields_for_logsource(aws_logsource).startswith("TENANT_ID,")

    monkeypatch.setenv("SOCLENS_DEFAULT_TABLE_FIELDS", "_time host tenant_col")
    assert get_table_fields_for_logsource(aws_logsource) == "_time host tenant_col"

    stanza = convert_to_savedsearch_stanza(
        rule_id="r-cfg-1",
        rule_title="Configurable Fields Rule",
        rule_content="title: Configurable Fields Rule\nlevel: medium\nlogsource:\n  product: windows\n",
        splunk_query='CommandLine="whoami"',
        suppress_fields="custom_field,host",
        table_fields="_time host custom_field",
    )
    cp = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
    cp.read_string(stanza)
    sec = cp[cp.sections()[0]]
    assert sec["alert.suppress.fields"] == "custom_field,host"
    assert sec["search"].endswith("| table _time host custom_field")


@pytest.mark.feature("F11")
def test_f11_sigma_cli_export_respects_workspace_isolation(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    repo_cache = REPO_ROOT / "sigma_rules_cache.json"
    repo_cache_before = repo_cache.read_bytes() if repo_cache.exists() else None

    out_conf = e2e_workspace / "cli_export" / "savedsearches.conf"
    proc = run_cli(["sigma", "--refresh", "--export", "--output", str(out_conf)])
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"

    exported = e2e_workspace / "cli_export" / "savedsearches_wineventlog.conf"
    assert exported.is_file()
    assert (e2e_workspace / "sigma_rules_cache.json").is_file()

    if repo_cache_before is None:
        assert not repo_cache.exists()
    else:
        assert repo_cache.read_bytes() == repo_cache_before


# ==============================================================================
# F12: Splunk Validation Hardening (Tier 1)
# ==============================================================================


@pytest.mark.feature("F12")
def test_f12_splunk_validator_es_default_app_and_connection_check(
    e2e_workspace: Path,
    mock_splunk_server: MockSplunkServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.splunk import SplunkValidator

    monkeypatch.delenv("SPLUNK_APP", raising=False)
    with SplunkValidator(host=mock_splunk_server.base_url, token="test-splunk-token") as validator:
        assert validator.app == "SplunkEnterpriseSecuritySuite"
        assert validator.check_connection() is True


@pytest.mark.feature("F12")
def test_f12_splunk_run_single_search_done_with_sample_results(
    e2e_workspace: Path, mock_splunk_server: MockSplunkServer
) -> None:
    from soclens.splunk import SplunkValidator

    mock_splunk_server.set_job_behavior(
        "done",
        results=[{"_time": "2026-10-22T00:00:00Z", "host": "dc01", "User": "alice"}],
    )
    with SplunkValidator() as validator:
        res = validator.run_single_search(
            {
                "stanza": "Win Rule",
                "search": "index=*wineventlog EventID=1",
                "file": "es.conf",
            },
            earliest="-7d",
            latest="now",
            timeout=15,
        )

    assert res["status"] == "success"
    assert res["trigger_count"] == 1
    assert res["scan_count"] == 1
    assert len(res["sample_results"]) == 1
    assert res["sample_results"][0]["host"] == "dc01"

    job_posts = [
        req
        for req in mock_splunk_server.requests_log
        if req["method"] == "POST"
        and req["path"] == "/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs"
    ]
    assert len(job_posts) == 1


@pytest.mark.feature("F12")
def test_f12_splunk_run_single_search_polling_queued_then_done(
    e2e_workspace: Path, mock_splunk_server: MockSplunkServer
) -> None:
    from soclens.splunk import SplunkValidator

    mock_splunk_server.set_job_behavior("queued_then_done")
    with SplunkValidator(poll_interval=0.05) as validator:
        res = validator.run_single_search(
            {
                "stanza": "Tstats Poll",
                "search": "| tstats count where index=main by host",
                "file": "es.conf",
            },
            earliest="-24h",
            latest="now",
            timeout=15,
        )

    assert res["status"] == "success"
    assert len(mock_splunk_server.state["jobs"]) == 1
    job = next(iter(mock_splunk_server.state["jobs"].values()))
    assert job["polls"] >= 2

    job_posts = [
        req
        for req in mock_splunk_server.requests_log
        if req["method"] == "POST" and req["path"].endswith("/search/jobs")
    ]
    assert job_posts[0]["form"]["search"][0].startswith("| tstats ")


@pytest.mark.feature("F12")
def test_f12_splunk_check_connection_fallback_currentcontext(
    e2e_workspace: Path, mock_splunk_server: MockSplunkServer
) -> None:
    from soclens.splunk import SplunkValidator

    mock_splunk_server.queue_fault("/services/server/info", status_code=403, count=1)
    with SplunkValidator() as validator:
        assert validator.check_connection() is True

    paths = [req["path"] for req in mock_splunk_server.requests_log]
    assert "/services/server/info" in paths
    assert "/services/authentication/currentcontext" in paths


@pytest.mark.feature("F12")
def test_f12_splunk_parse_savedsearches_files_and_basic_auth(
    e2e_workspace: Path, mock_splunk_server: MockSplunkServer
) -> None:
    from soclens.splunk import SplunkValidator, parse_savedsearches_files

    conf_file = e2e_workspace / "savedsearches_custom.conf"
    conf_file.write_text(
        "[Multi Line Search]\n"
        "description = Detects 100% suspicious \\\n"
        "  activity across hosts\n"
        "search = index=*wineventlog \\\n"
        "  CommandLine=\"*100%*\"\n\n"
        "[Second Search]\n"
        "search = | tstats count where index=main\n",
        encoding="utf-8",
    )

    searches = parse_savedsearches_files(e2e_workspace / "*.conf")
    assert len(searches) == 2
    assert searches[0]["stanza"] == "Multi Line Search"
    assert 'CommandLine="*100%*"' in searches[0]["search"]
    assert "100% suspicious activity" in searches[0]["description"]
    assert searches[1]["description"] == "No description provided."

    with SplunkValidator(
        host=mock_splunk_server.base_url,
        token="",
        username="soc_analyst",
        password="secret-password",
    ) as validator:
        assert validator.check_connection() is True


@pytest.mark.feature("F12")
def test_f12_splunk_cli_validate_dry_run_and_es_app_report(
    e2e_workspace: Path,
    mock_splunk_server: MockSplunkServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conf_file = _write_sample_savedsearches(e2e_workspace / "savedsearches.conf")

    dry_proc = run_cli(["validate", "--input", str(conf_file), "--dry-run"])
    assert dry_proc.returncode == 0, f"stdout={dry_proc.stdout}\nstderr={dry_proc.stderr}"
    assert [r for r in mock_splunk_server.requests_log if "/search/jobs" in r["path"]] == []

    monkeypatch.delenv("SPLUNK_APP", raising=False)
    report_path = e2e_workspace / "val_report.json"
    run_proc = run_cli(["validate", "--input", str(conf_file), "--output", str(report_path)])
    assert run_proc.returncode == 0, f"stdout={run_proc.stdout}\nstderr={run_proc.stderr}"
    assert report_path.is_file()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["successful"] == 1
    assert report["summary"]["failed"] == 0

    job_posts = [
        req
        for req in mock_splunk_server.requests_log
        if req["method"] == "POST" and req["path"].endswith("/search/jobs")
    ]
    assert len(job_posts) == 1
    assert job_posts[0]["path"] == "/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs"


# ==============================================================================
# F13: Air-Gapped Bundler & Env Scripts (Tier 1)
# ==============================================================================


@pytest.mark.feature("F13")
def test_f13_create_bundle_default_zip_and_manifest(e2e_workspace: Path) -> None:
    from soclens.bundler import DEFAULT_BUNDLE_FILENAME, create_bundle

    ws = _stage_bundle_workspace(e2e_workspace / "bundle_ws")
    bundle_path = create_bundle(ws)

    assert isinstance(bundle_path, Path)
    assert bundle_path == (ws / DEFAULT_BUNDLE_FILENAME).resolve()
    assert bundle_path.is_file()

    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = set(zf.namelist())
        for expected in (
            "pyproject.toml",
            "requirements.txt",
            "README.md",
            "ignored_hashes.txt",
            "docs/RF_API_REVIEW.md",
            "scripts/soclens-brand-sync.ps1",
            "soclens/__init__.py",
            "soclens/bundler.py",
            "BUNDLE_MANIFEST.json",
        ):
            assert expected in names, f"Missing {expected} from bundle"

        manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
        assert manifest["schema_version"] == 1
        assert manifest["package_name"] == "soclens"
        assert manifest["file_count"] == len(names)
        assert isinstance(manifest["dependencies"], list) and manifest["dependencies"]


@pytest.mark.feature("F13")
def test_f13_utils_reexport_backward_compatibility(e2e_workspace: Path) -> None:
    from soclens import bundler, utils

    assert utils.create_bundle is bundler.create_bundle
    ws = _stage_bundle_workspace(e2e_workspace / "utils_ws")

    out_from_str = utils.create_bundle(str(ws), output_path=str(e2e_workspace / "out_str.zip"))
    out_from_path = bundler.create_bundle(ws, output_path=e2e_workspace / "out_path.zip")

    assert isinstance(out_from_str, Path) and out_from_str.is_file()
    assert isinstance(out_from_path, Path) and out_from_path.is_file()
    with zipfile.ZipFile(out_from_str, "r") as z1, zipfile.ZipFile(out_from_path, "r") as z2:
        assert set(z1.namelist()) == set(z2.namelist())


@pytest.mark.feature("F13")
def test_f13_dynamic_dependencies_include_runtime_exclude_dev(e2e_workspace: Path) -> None:
    from soclens.bundler import create_bundle

    ws = _stage_bundle_workspace(e2e_workspace / "deps_ws")
    marker_token = "# e2e-live-workspace-marker"
    init_file = ws / "soclens" / "__init__.py"
    init_file.write_text(init_file.read_text(encoding="utf-8") + f"\n{marker_token}\n", encoding="utf-8")

    bundle_path = create_bundle(ws, output_path=e2e_workspace / "deps_bundle.zip")
    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
        dep_names = {d["name"].lower() for d in manifest["dependencies"]}

        for runtime_pkg in ("requests", "pyyaml", "pysigma", "beautifulsoup4", "jinja2", "diskcache"):
            assert runtime_pkg in dep_names
        for dev_pkg in ("pytest", "ruff", "mypy", "pytest-cov", "soclens"):
            assert dev_pkg not in dep_names

        assert any(n.startswith("requests/") for n in names)
        assert any(n.startswith("yaml/") for n in names)
        assert any(n.startswith("sigma/") for n in names)
        assert any(n.startswith("bs4/") for n in names)
        assert any(n.startswith("diskcache/") for n in names)
        assert not any(n.startswith(("pytest/", "_pytest/", "ruff/", "mypy/")) for n in names)
        assert marker_token in zf.read("soclens/__init__.py").decode("utf-8")


@pytest.mark.feature("F13")
def test_f13_extracted_bundle_offline_imports(e2e_workspace: Path) -> None:
    from soclens.bundler import create_bundle

    ws = _stage_bundle_workspace(e2e_workspace / "offline_ws")
    bundle_path = create_bundle(ws, output_path=e2e_workspace / "offline.zip")

    extracted = e2e_workspace / "extracted"
    with zipfile.ZipFile(bundle_path, "r") as zf:
        zf.extractall(extracted)

    probe_code = (
        "import sys; from pathlib import Path; "
        f"ext = Path({str(extracted)!r}).resolve(); "
        "sys.path.insert(0, str(ext)); "
        "import soclens, soclens.config, soclens.client, soclens.sigma, soclens.splunk, soclens.bundler, soclens.utils, requests; "
        "assert Path(soclens.__file__).resolve().is_relative_to(ext), soclens.__file__; "
        "assert Path(requests.__file__).resolve().is_relative_to(ext), requests.__file__"
    )
    clean_env = {"PATH": os.environ.get("PATH", ""), "SOCLENS_HOME": str(e2e_workspace)}
    proc = subprocess.run(
        [sys.executable, "-I", "-c", probe_code],
        cwd=str(extracted),
        env=clean_env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"


@pytest.mark.feature("F13")
def test_f13_cli_bundle_command(
    e2e_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    ws = _stage_bundle_workspace(e2e_workspace / "cli_bundle_ws")
    out1 = e2e_workspace / "cli_out.zip"

    cli_proc = run_cli(["bundle", "--workspace", str(ws), "--output", str(out1)])
    assert cli_proc.returncode == 0, f"stdout={cli_proc.stdout}\nstderr={cli_proc.stderr}"
    assert out1.is_file() and zipfile.is_zipfile(out1)


# ==============================================================================
# F14: Cohesive CLI & Exit Diagnostics (Tier 1)
# ==============================================================================


@pytest.mark.feature("F14")
def test_f14_cli_help_root_and_all_subcommands(
    e2e_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    root_help = run_cli(["--help"])
    assert root_help.returncode == 0, f"stderr={root_help.stderr}"
    for sub in ("watchlist", "rf", "sigma", "validate", "bundle", "tui"):
        assert sub in root_help.stdout
        sub_help = run_cli([sub, "--help"])
        assert sub_help.returncode == 0, f"{sub} --help failed: {sub_help.stderr}"


@pytest.mark.feature("F14")
def test_f14_cli_watchlist_crud_and_custom_lists(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    mock_rf_server.seed_list(
        name="SOC Custom Brand Hashes",
        list_type="brand",
        list_id="report:custom-brand-1",
    )
    auto_env = {"SOCLENS_AUTO_APPROVE": "true"}

    list_proc = run_cli(["watchlist", "list"], env=auto_env)
    assert list_proc.returncode == 0, f"stdout={list_proc.stdout}\nstderr={list_proc.stderr}"
    assert "SOC Custom Brand Hashes" in list_proc.stdout

    create_proc = run_cli(
        ["watchlist", "create", "E2E Custom Domain List", "--type", "domain"],
        env=auto_env,
    )
    assert create_proc.returncode == 0, f"stdout={create_proc.stdout}\nstderr={create_proc.stderr}"
    created = [
        item["info"]
        for item in mock_rf_server.state["lists"].values()
        if item["info"]["name"] == "E2E Custom Domain List"
    ]
    assert len(created) == 1
    list_id = created[0]["id"]

    info_proc = run_cli(["watchlist", "info", list_id], env=auto_env)
    assert info_proc.returncode == 0, f"stderr={info_proc.stderr}"
    assert list_id in info_proc.stdout

    status_proc = run_cli(["watchlist", "status", list_id], env=auto_env)
    assert status_proc.returncode == 0, f"stderr={status_proc.stderr}"

    add_proc = run_cli(
        ["watchlist", "add", list_id, "InternetDomainName", "evil-example.test"],
        env=auto_env,
    )
    assert add_proc.returncode == 0, f"stderr={add_proc.stderr}"

    ent_proc = run_cli(["watchlist", "entities", list_id], env=auto_env)
    assert ent_proc.returncode == 0, f"stderr={ent_proc.stderr}"
    assert "evil-example.test" in ent_proc.stdout

    csv_export = e2e_workspace / "exported_wl.csv"
    exp_proc = run_cli(["watchlist", "export", list_id, "--output", str(csv_export)], env=auto_env)
    assert exp_proc.returncode == 0, f"stderr={exp_proc.stderr}"
    assert csv_export.is_file() and "evil-example.test" in csv_export.read_text(encoding="utf-8")

    rem_proc = run_cli(
        ["watchlist", "remove", list_id, "InternetDomainName", "evil-example.test"],
        env=auto_env,
    )
    assert rem_proc.returncode == 0, f"stderr={rem_proc.stderr}"
    assert mock_rf_server.state["lists"][list_id]["entities"] == {}


@pytest.mark.feature("F14")
def test_f14_cli_rf_subcommands_against_mock(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    rf_help = run_cli(["rf", "--help"])
    assert rf_help.returncode == 0, f"stderr={rf_help.stderr}"
    help_text = rf_help.stdout.lower()

    if "entity-match" in help_text:
        p1 = run_cli(["rf", "entity-match", "Cobalt Strike"])
        assert p1.returncode == 0, f"stderr={p1.stderr}"
        assert "Cobalt Strike" in p1.stdout
    elif "match" in help_text:
        p1 = run_cli(["rf", "match", "Cobalt Strike"])
        assert p1.returncode == 0, f"stderr={p1.stderr}"
        assert "Cobalt Strike" in p1.stdout
    else:
        raise AssertionError(f"Expected entity-match subcommand in `rf --help`:\n{rf_help.stdout}")

    if "lookup" in help_text:
        p2 = run_cli(["rf", "lookup", "ip", "198.51.100.10"])
        assert p2.returncode == 0, f"stderr={p2.stderr}"
        assert "198.51.100.10" in p2.stdout
    else:
        raise AssertionError(f"Expected lookup subcommand in `rf --help`:\n{rf_help.stdout}")

    if "enrich" in help_text:
        p3 = run_cli(["rf", "enrich", "--ip", "198.51.100.10"])
        assert p3.returncode == 0, f"stderr={p3.stderr}"
        assert "198.51.100.10" in p3.stdout


@pytest.mark.feature("F14")
def test_f14_cli_dry_run_never_mutates_server(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    mock_splunk_server: MockSplunkServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    list_id = "report:brand-image-default"
    domains_file = e2e_workspace / "domains.txt"
    domains_file.write_text(f"{brand_http_server.site_url('brand-alpha.local')}\n", encoding="utf-8")

    csv_file = e2e_workspace / "sync_entities.csv"
    csv_file.write_text("type,name\nInternetDomainName,dry-run-domain.test\n", encoding="utf-8")

    conf_file = _write_sample_savedsearches(e2e_workspace / "dry_validate.conf")

    for cmd in (
        ["watchlist", "add", list_id, "InternetDomainName", "dry.test", "--dry-run"],
        ["watchlist", "remove", list_id, "InternetDomainName", "dry.test", "--dry-run"],
        ["watchlist", "sync", list_id, str(csv_file), "--dry-run"],
        ["watchlist", "sync-logos", list_id, "--domains-file", str(domains_file), "--dry-run"],
        ["validate", "--input", str(conf_file), "--dry-run"],
    ):
        proc = run_cli(cmd)
        assert proc.returncode == 0, f"Command {cmd} failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"

    mutating_rf = [
        req
        for req in mock_rf_server.requests_log
        if req["method"] == "POST" and ("/entity/add" in req["path"] or "/entity/remove" in req["path"])
    ]
    assert mutating_rf == []
    assert [r for r in mock_splunk_server.requests_log if "/search/jobs" in r["path"]] == []


@pytest.mark.feature("F14")
def test_f14_cli_json_output_parseable(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    list_id = "report:brand-image-default"
    hash_id = "hash:" + ("a" * 64)
    mock_rf_server.state["lists"][list_id]["entities"][hash_id] = {
        "entity": {"id": hash_id, "type": "Hash", "name": "a" * 64},
        "context": {"annotation": "brand-alpha.local logo"},
        "status": "ready",
        "added": "2026-10-20T00:00:00Z",
    }
    _seed_sigma_cache(e2e_workspace)

    for cmd in (
        ["watchlist", "list", "--json"],
        ["watchlist", "entities", list_id, "--json"],
        ["sigma", "PowerShell", "--json"],
    ):
        proc = run_cli(cmd)
        assert proc.returncode == 0, f"Command {cmd} failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
        parsed = json.loads(proc.stdout)
        assert isinstance(parsed, (list, dict))


@pytest.mark.feature("F14")
def test_f14_cli_validate_background_cross_platform_dispatch(
    e2e_workspace: Path,
    mock_splunk_server: MockSplunkServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    cli_source = (REPO_ROOT / "soclens" / "cli.py").read_text(encoding="utf-8")
    assert '"-m", "soclens.cli"' in cli_source or "'-m', 'soclens.cli'" in cli_source
    assert "sys.argv[0]" not in cli_source

    conf_file = _write_sample_savedsearches(e2e_workspace / "bg_savedsearches.conf")
    log_file = e2e_workspace / "bg_validate.log"
    status_file = e2e_workspace / "bg_status.json"

    proc = run_cli(
        [
            "validate",
            "--input",
            str(conf_file),
            "--background",
            "--log-file",
            str(log_file),
            "--status-file",
            str(status_file),
        ]
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"

    bg_pid: int | None = None
    deadline = time.monotonic() + 10.0
    try:
        while time.monotonic() < deadline:
            if status_file.is_file():
                try:
                    data = json.loads(status_file.read_text(encoding="utf-8"))
                    if isinstance(data.get("pid"), int):
                        bg_pid = data["pid"]
                    if data.get("status") in {"completed", "done", "success", "finished"}:
                        break
                except json.JSONDecodeError:
                    pass
            time.sleep(0.1)

        assert status_file.is_file(), "Background validation did not write status file"
        assert log_file.is_file(), "Background validation did not write log file"
    finally:
        if bg_pid is not None:
            try:
                os.kill(bg_pid, 15)
            except OSError:
                pass


# ==============================================================================
# F15: Full Windows-Compatible TUI (Tier 1)
# ==============================================================================


@pytest.mark.feature("F15")
def test_f15_ast_windows_compatibility_zero_posix_deps() -> None:
    tui_dir = REPO_ROOT / "soclens" / "tui"
    assert tui_dir.is_dir(), f"Expected TUI package directory at {tui_dir}"
    assert (tui_dir / "app.py").is_file(), "Expected soclens/tui/app.py"
    assert (tui_dir / "screens").is_dir(), "Expected soclens/tui/screens/ package"

    py_files = sorted(tui_dir.rglob("*.py"))
    assert py_files, "No Python files found in soclens/tui/"

    saw_worker_marker = False
    for py_file in py_files:
        src = py_file.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(py_file))

        emojis = [ch for ch in src if ord(ch) > 0x1F000]
        assert not emojis, f"{py_file} contains emoji characters: {emojis}"

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_mod = alias.name.split(".")[0]
                    assert top_mod not in POSIX_ONLY_MODULES, (
                        f"{py_file} imports POSIX-only module '{top_mod}'"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                top_mod = node.module.split(".")[0]
                assert top_mod not in POSIX_ONLY_MODULES, (
                    f"{py_file} imports POSIX-only module '{top_mod}'"
                )
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "os"
                        and node.func.attr in {"system", "fork", "killpg"}
                    ):
                        raise AssertionError(f"{py_file} calls POSIX/unsafe os.{node.func.attr}()")
                    if node.func.attr == "run_worker":
                        saw_worker_marker = True
                elif isinstance(node.func, ast.Name) and node.func.id == "work":
                    saw_worker_marker = True
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        raise AssertionError(f"{py_file} passes shell=True")
            elif isinstance(node, ast.Name) and node.id == "work":
                saw_worker_marker = True

        for forbidden in ("/bin/sh", "/bin/bash"):
            assert forbidden not in src, f"{py_file} references {forbidden}"

    assert saw_worker_marker, "Expected @work or run_worker usage in soclens/tui/"


@pytest.mark.feature("F15")
def test_f15_tui_pilot_mounts_all_workflow_sections(e2e_workspace: Path) -> None:
    app = _create_tui_app(dry_run=True)

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            labels = _collect_workflow_labels(app)
            combined = " ".join(labels) + " " + _collect_tui_text(app).lower()
            for area, keywords in WORKFLOW_KEYWORDS.items():
                assert any(kw in combined for kw in keywords), (
                    f"Workflow '{area}' not represented in mounted TUI sections: {labels}"
                )

    asyncio.run(_run())


@pytest.mark.feature("F15")
def test_f15_tui_pilot_navigate_all_workflows(e2e_workspace: Path) -> None:
    app = _create_tui_app(dry_run=True)
    textual_widgets = importlib.import_module("textual.widgets")

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            tabbed_list = list(app.query(textual_widgets.TabbedContent))
            if tabbed_list:
                tabbed = tabbed_list[0]
                panes = list(tabbed.query(textual_widgets.TabPane))
                assert len(panes) >= 4
                visited: list[str] = []
                for pane in panes:
                    if pane.id:
                        tabbed.active = pane.id
                        await pilot.pause()
                        assert tabbed.active == pane.id
                        visited.append(pane.id)
                assert len(visited) >= 4
            else:
                screens = getattr(app, "SCREENS", {}) or {}
                assert len(screens) >= 4
                for name in screens:
                    await app.push_screen(name)
                    await pilot.pause()

    asyncio.run(_run())


@pytest.mark.feature("F15")
def test_f15_tui_pilot_dry_run_prevents_api_writes(
    e2e_workspace: Path, mock_rf_server: MockRFServer
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    app = _create_tui_app(client=client, dry_run=True)
    textual_widgets = importlib.import_module("textual.widgets")

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            for button in app.query(textual_widgets.Button):
                label = str(getattr(button, "label", "")).lower()
                if any(tok in label for tok in ("dry", "sync", "add", "refresh", "load")):
                    try:
                        await pilot.click(button)
                    except Exception:
                        button.press()
                    await pilot.pause()
            await app.workers.wait_for_complete()

    asyncio.run(_run())

    mutating = [
        req
        for req in mock_rf_server.requests_log
        if req["method"] == "POST" and ("/entity/add" in req["path"] or "/entity/remove" in req["path"])
    ]
    assert mutating == []


@pytest.mark.feature("F15")
def test_f15_tui_pilot_keyboard_navigation_and_focus_boundaries(e2e_workspace: Path) -> None:
    app = _create_tui_app(dry_run=True)

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            focused_seen: list[str] = []
            for key in ("tab", "tab", "tab", "shift+tab", "right", "left", "escape"):
                await pilot.press(key)
                await pilot.pause()
                if app.focused is not None:
                    focused_seen.append(type(app.focused).__name__)
            assert app.is_running
            assert len(focused_seen) >= 1

    asyncio.run(_run())


@pytest.mark.feature("F15")
def test_f15_tui_pilot_mocked_watchlist_and_sigma_data_load(
    e2e_workspace: Path, mock_rf_server: MockRFServer
) -> None:
    from soclens.client import RecordedFutureClient

    mock_rf_server.seed_list(
        name="TUI Seeded Watchlist",
        list_type="brand",
        list_id="report:tui-seeded-1",
    )
    _seed_sigma_cache(e2e_workspace)

    client = RecordedFutureClient()
    app = _create_tui_app(client=client, dry_run=True)
    textual_widgets = importlib.import_module("textual.widgets")

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            for tabbed in app.query(textual_widgets.TabbedContent):
                for pane in tabbed.query(textual_widgets.TabPane):
                    if pane.id:
                        tabbed.active = pane.id
                        await pilot.pause()
                    for btn in pane.query(textual_widgets.Button):
                        label = str(getattr(btn, "label", "")).lower()
                        if any(tok in label for tok in ("load", "refresh", "list", "search")):
                            try:
                                await pilot.click(btn)
                            except Exception:
                                btn.press()
                            await pilot.pause()
            await app.workers.wait_for_complete()
            rendered = _collect_tui_text(app)
            assert (
                "TUI Seeded Watchlist" in rendered
                or "Brand Image" in rendered
                or "PowerShell" in rendered
            )

    asyncio.run(_run())
