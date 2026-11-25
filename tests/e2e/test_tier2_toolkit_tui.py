"""Tier 2 boundary, error-handling, and corner-case E2E tests (F11-F15)."""

from __future__ import annotations

import asyncio
import configparser
import importlib
import importlib.util
import inspect
import io
import json
import socket
import subprocess
import sys
import warnings
import zipfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import urllib3

if TYPE_CHECKING:
    from tests.e2e.conftest import MockRFServer, MockSplunkServer

pytestmark = [pytest.mark.e2e, pytest.mark.tier2]

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


def _stage_bundle_workspace(dest: Path) -> Path:
    """Copy clean toolkit files into an isolated temporary workspace for bundler tests."""
    import shutil

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


def _write_sample_savedsearches(path: Path) -> Path:
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

    for mod in candidates:
        for fname in ("create_app", "build_app"):
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
    preferred = ("SocLensApp", "RecordedFutureApp", "SocApp", "TuiApp")
    chosen = next((cls for cls in app_classes if cls.__name__ in preferred), app_classes[0])
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


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ==============================================================================
# F11: Sigma & Splunk Conversion Hardening (Tier 2)
# ==============================================================================


@pytest.mark.feature("F11")
def test_f11_sigma_cache_preserved_on_api_500_and_empty_response(
    e2e_workspace: Path, mock_rf_server: MockRFServer
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.sigma import load_rules

    cache_path = e2e_workspace / "sigma_rules_cache.json"
    seeded = [
        {
            "rule_id": "doc:cached-1",
            "title": "Preserved Cached Rule",
            "file_name": "preserved.yml",
            "product": "windows",
            "index": "*wineventlog",
            "mitre_techniques": [],
            "content": "title: Preserved Cached Rule\nlevel: medium\n",
        }
    ]
    cache_path.write_text(json.dumps(seeded, indent=2), encoding="utf-8")
    before_bytes = cache_path.read_bytes()

    client = RecordedFutureClient()
    mock_rf_server.set_fault("/detection-rule/search", status_code=500)
    fallback_rules = load_rules(client, refresh=True, cache_dir=e2e_workspace)
    assert len(fallback_rules) == 1
    assert fallback_rules[0]["rule_id"] == "doc:cached-1"
    assert cache_path.read_bytes() == before_bytes

    mock_rf_server.clear_faults()
    mock_rf_server.state["detection_rules"] = []
    preserved_rules = load_rules(client, refresh=True, cache_dir=e2e_workspace)
    assert len(preserved_rules) == 1
    assert preserved_rules[0]["rule_id"] == "doc:cached-1"
    assert cache_path.read_bytes() == before_bytes


@pytest.mark.feature("F11")
def test_f11_sigma_api_failure_with_no_cache_raises_cleanly(
    e2e_workspace: Path, mock_rf_server: MockRFServer
) -> None:
    from soclens.client import RecordedFutureClient, RecordedFutureError
    from soclens.sigma import load_rules

    cache_path = e2e_workspace / "sigma_rules_cache.json"
    assert not cache_path.exists()

    client = RecordedFutureClient()
    mock_rf_server.set_fault("/detection-rule/search", status_code=500)
    with pytest.raises((RecordedFutureError, RuntimeError)):
        load_rules(client, refresh=True, cache_dir=e2e_workspace)

    assert not cache_path.exists()


@pytest.mark.feature("F11")
def test_f11_sigma_corrupted_and_empty_cache_recovery(
    e2e_workspace: Path, mock_rf_server: MockRFServer
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.sigma import load_rules

    cache_path = e2e_workspace / "sigma_rules_cache.json"
    client = RecordedFutureClient()

    for bad_payload in ("{corrupted json", ""):
        cache_path.write_text(bad_payload, encoding="utf-8")
        rules = load_rules(client, refresh=False, cache_dir=e2e_workspace)
        assert len(rules) == 2
        reloaded = json.loads(cache_path.read_text(encoding="utf-8"))
        assert isinstance(reloaded, list) and len(reloaded) == 2


@pytest.mark.feature("F11")
def test_f11_sigma_ini_unsafe_multiline_desc_brackets_and_percent(e2e_workspace: Path) -> None:
    from soclens.sigma import export_rules_to_splunk
    from soclens.splunk import parse_savedsearches_files

    out_base = e2e_workspace / "ini_safety" / "savedsearches.conf"
    rules = [
        {
            "rule_id": "doc:unsafe-ini",
            "title": "[APT29] Multi-Line & 100% Test",
            "file_name": "unsafe_ini.yml",
            "content": (
                'title: "[APT29] Multi-Line & 100% Test"\n'
                "id: 33333333-3333-3333-3333-333333333333\n"
                "description: |\n"
                "  Line 1\n"
                "  [bogus_stanza]\n"
                "  100% %s %(evil)s\n"
                "logsource:\n"
                "  product: windows\n"
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains: '%TEMP%'\n"
                "  condition: selection\n"
                "level: high\n"
            ),
        }
    ]

    export_rules_to_splunk(rules, out_base, write_mode="overwrite")
    exported_file = e2e_workspace / "ini_safety" / "savedsearches_wineventlog.conf"
    assert exported_file.is_file()

    cp = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
    cp.read_string(exported_file.read_text(encoding="utf-8"))
    assert len(cp.sections()) == 1
    assert "bogus_stanza" not in cp.sections()
    sec = cp[cp.sections()[0]]
    assert "\n" not in sec["description"]
    assert "%TEMP%" in sec["search"]

    parsed = parse_savedsearches_files(exported_file)
    assert len(parsed) == 1
    assert "%TEMP%" in parsed[0]["search"]


@pytest.mark.feature("F11")
def test_f11_sigma_null_yaml_metadata_and_malformed_rule_isolation(e2e_workspace: Path) -> None:
    from soclens.sigma import convert_to_savedsearch_stanza, export_rules_to_splunk
    from soclens.splunk import parse_savedsearches_files

    out_base = e2e_workspace / "null_meta" / "savedsearches.conf"
    rules: list[dict[str, Any]] = [
        {
            "rule_id": "doc:valid-null-meta",
            "title": "Null Metadata Valid Rule",
            "file_name": "valid_null.yml",
            "mitre_techniques": None,
            "content": (
                "title: Null Metadata Valid Rule\n"
                "level: null\n"
                "description: null\n"
                "author: null\n"
                "logsource:\n"
                "  product: windows\n"
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains: 'whoami'\n"
                "  condition: selection\n"
            ),
        },
        {"rule_id": "doc:empty", "title": "Empty", "file_name": "empty.yml", "content": ""},
        {
            "rule_id": "doc:bad-yaml",
            "title": "Broken YAML",
            "file_name": "broken.yml",
            "content": "not_a_rule: [\n",
        },
    ]

    export_rules_to_splunk(rules, out_base, write_mode="overwrite")
    exported_file = e2e_workspace / "null_meta" / "savedsearches_wineventlog.conf"
    assert exported_file.is_file()

    cp = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
    cp.read_string(exported_file.read_text(encoding="utf-8"))
    assert len(cp.sections()) == 1
    assert cp[cp.sections()[0]]["action.notable.param.severity"] == "medium"
    assert len(parse_savedsearches_files(exported_file)) == 1

    direct_stanza = convert_to_savedsearch_stanza(
        rule_id="doc:null-parsed",
        rule_title="Direct Null Parsed",
        rule_content="title: Direct Null Parsed\n",
        splunk_query='CommandLine="whoami"',
        parsed={"tags": None, "level": None, "description": None, "logsource": None},
    )
    cp_direct = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
    cp_direct.read_string(direct_stanza)
    assert len(cp_direct.sections()) == 1
    assert cp_direct[cp_direct.sections()[0]]["action.notable.param.severity"] == "medium"


@pytest.mark.feature("F11")
def test_f11_sigma_search_rules_blank_query_and_missing_token_error(
    e2e_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.sigma import SigmaConfigurationError, load_rules, search_rules

    sample_rules: list[dict[str, Any]] = [
        {"title": None, "description": None, "content": "powershell -EncodedCommand"},
    ]
    assert search_rules(sample_rules, "") == []
    assert search_rules(sample_rules, "   ") == []
    assert len(search_rules(sample_rules, "powershell")) == 1

    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)
    client = RecordedFutureClient(api_token=None)
    with pytest.raises((SigmaConfigurationError, RuntimeError)):
        load_rules(client, refresh=False, cache_dir=e2e_workspace)


# ==============================================================================
# F12: Splunk Validation Hardening (Tier 2)
# ==============================================================================


@pytest.mark.feature("F12")
def test_f12_splunk_timeout_cancels_at_exact_control_url(
    e2e_workspace: Path, mock_splunk_server: MockSplunkServer
) -> None:
    from soclens.splunk import SplunkValidator

    mock_splunk_server.set_job_behavior("stuck_queued")
    with SplunkValidator(poll_interval=0.1) as validator:
        res = validator.run_single_search(
            {"stanza": "Stuck Search", "search": "index=main", "file": "t.conf"},
            earliest="-1h",
            latest="now",
            timeout=1,
        )

    assert res["status"] == "failed"
    assert res["error_message"] is not None
    assert "timed out" in res["error_message"].lower()

    cancel_reqs = [
        req
        for req in mock_splunk_server.requests_log
        if req["method"] == "POST" and req["path"].endswith("/control")
    ]
    assert len(cancel_reqs) == 1
    assert cancel_reqs[0]["path"].startswith("/services/search/jobs/")
    assert cancel_reqs[0]["query"].get("output_mode") == ["json"]
    assert cancel_reqs[0]["form"].get("action") == ["cancel"]

    job = next(iter(mock_splunk_server.state["jobs"].values()))
    assert job["cancelled"] is True


@pytest.mark.feature("F12")
def test_f12_splunk_401_rejected_and_missing_credentials_raises(
    e2e_workspace: Path,
    mock_splunk_server: MockSplunkServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.splunk import SplunkValidator

    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("SPLUNK_USERNAME", raising=False)
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)

    with pytest.raises(ValueError):
        SplunkValidator(host=mock_splunk_server.base_url)

    with SplunkValidator(host=mock_splunk_server.base_url, token="bad-token") as validator:
        assert validator.check_connection() is False
        res = validator.run_single_search(
            {"stanza": "Unauthorized", "search": "index=main", "file": "t.conf"},
            earliest="-1h",
            latest="now",
            timeout=10,
        )
    assert res["status"] == "failed"
    assert "401" in str(res["error_message"])


@pytest.mark.feature("F12")
def test_f12_splunk_500_job_create_and_dispatch_failed_state(
    e2e_workspace: Path, mock_splunk_server: MockSplunkServer
) -> None:
    from soclens.splunk import SplunkValidator

    mock_splunk_server.set_fault(
        "/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs",
        status_code=500,
    )
    with SplunkValidator(max_retries=0) as validator:
        res_500 = validator.run_single_search(
            {"stanza": "HTTP 500", "search": "index=main", "file": "t.conf"},
            earliest="-1h",
            latest="now",
            timeout=10,
        )
    assert res_500["status"] == "failed"
    assert "500" in str(res_500["error_message"])

    mock_splunk_server.clear_faults()
    mock_splunk_server.set_job_behavior("failed")
    with SplunkValidator(max_retries=0) as validator:
        res_failed = validator.run_single_search(
            {"stanza": "Dispatch Failed", "search": "index=main", "file": "t.conf"},
            earliest="-1h",
            latest="now",
            timeout=10,
        )
    assert res_failed["status"] == "failed"
    assert "Search failed in mock Splunk" in str(res_failed["error_message"])


@pytest.mark.feature("F12")
def test_f12_splunk_transient_503_poll_recovery(
    e2e_workspace: Path, mock_splunk_server: MockSplunkServer
) -> None:
    from soclens.splunk import SplunkValidator

    mock_splunk_server.set_job_behavior("done")
    mock_splunk_server.queue_fault(
        "/services/search/jobs/",
        status_code=503,
        method="GET",
        count=1,
    )
    with SplunkValidator(max_retries=2, backoff_base=0.05, poll_interval=0.05) as validator:
        res = validator.run_single_search(
            {"stanza": "Poll Recovery", "search": "index=main", "file": "t.conf"},
            earliest="-1h",
            latest="now",
            timeout=15,
        )
    assert res["status"] == "success"


@pytest.mark.feature("F12")
def test_f12_splunk_parse_savedsearches_none_stanza_keys_and_empty_missing(
    e2e_workspace: Path,
) -> None:
    from soclens.splunk import parse_savedsearches_files

    conf_file = e2e_workspace / "edge_savedsearches.conf"
    conf_file.write_text(
        "[Bare Search Key]\n"
        "search\n"
        "description\n\n"
        "[Whitespace Search]\n"
        "search =    \n\n"
        "[No Search Key]\n"
        "enableSched = 1\n\n"
        "[Valid With Bare Description]\n"
        "description\n"
        "search = index=web uri_path=\"*%20admin*\"\n",
        encoding="utf-8",
    )

    parsed = parse_savedsearches_files(conf_file)
    assert len(parsed) == 1
    assert parsed[0]["stanza"] == "Valid With Bare Description"
    assert parsed[0]["description"] == "No description provided."
    assert "%20admin" in parsed[0]["search"]
    assert parse_savedsearches_files(e2e_workspace / "does_not_exist.conf") == []


@pytest.mark.feature("F12")
def test_f12_splunk_concurrent_session_and_ssl_warning_thread_safety(
    e2e_workspace: Path, mock_splunk_server: MockSplunkServer
) -> None:
    from soclens.splunk import SplunkValidator

    mock_splunk_server.set_job_behavior("done")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", urllib3.exceptions.InsecureRequestWarning)
        with SplunkValidator(verify_ssl=False, poll_interval=0.05) as validator:
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = [
                    pool.submit(
                        validator.run_single_search,
                        {"stanza": f"Concurrent {i}", "search": "index=main", "file": "c.conf"},
                        "-1h",
                        "now",
                        15,
                    )
                    for i in range(4)
                ]
                results = [f.result(timeout=15) for f in futures]

    assert all(r["status"] == "success" for r in results)
    insecure_warns = [
        w for w in caught if issubclass(w.category, urllib3.exceptions.InsecureRequestWarning)
    ]
    assert insecure_warns == []


# ==============================================================================
# F13: Air-Gapped Bundler & Env Scripts (Tier 2)
# ==============================================================================


@pytest.mark.feature("F13")
def test_f13_output_parent_dir_autocreate_and_dir_target(e2e_workspace: Path) -> None:
    from soclens.bundler import DEFAULT_BUNDLE_FILENAME, create_bundle

    ws = _stage_bundle_workspace(e2e_workspace / "out_ws")
    nested_zip = e2e_workspace / "a" / "b" / "c" / "custom_bundle.zip"
    created_nested = create_bundle(ws, output_path=nested_zip)
    assert created_nested == nested_zip.resolve()
    assert created_nested.is_file()

    target_dir = e2e_workspace / "existing_out_dir"
    target_dir.mkdir(parents=True, exist_ok=True)
    created_in_dir = create_bundle(ws, output_path=target_dir)
    assert created_in_dir == (target_dir / DEFAULT_BUNDLE_FILENAME).resolve()
    assert created_in_dir.is_file()


@pytest.mark.feature("F13")
def test_f13_excludes_secrets_vcs_caches_and_self_zip(e2e_workspace: Path) -> None:
    from soclens.bundler import DEFAULT_BUNDLE_FILENAME, create_bundle

    ws = _stage_bundle_workspace(e2e_workspace / "exclude_ws")
    (ws / "apikey.key").write_text("SECRET-KEY", encoding="utf-8")
    (ws / "app.log").write_text("sensitive log", encoding="utf-8")
    (ws / ".git").mkdir(parents=True, exist_ok=True)
    (ws / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (ws / ".venv").mkdir(parents=True, exist_ok=True)
    (ws / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (ws / "soclens" / "__pycache__").mkdir(parents=True, exist_ok=True)
    (ws / "soclens" / "__pycache__" / "x.cpython-312.pyc").write_bytes(b"pyc")
    (ws / DEFAULT_BUNDLE_FILENAME).write_bytes(b"old-zip")

    bundle_path = create_bundle(ws)
    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = set(zf.namelist())

    assert "apikey.key" not in names
    assert "app.log" not in names
    assert DEFAULT_BUNDLE_FILENAME not in names
    assert not any(n.startswith((".git/", ".venv/")) or "__pycache__" in n or n.endswith(".pyc") for n in names)


@pytest.mark.feature("F13")
def test_f13_missing_or_file_workspace_raises_and_cli_nonzero(
    e2e_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    from soclens.bundler import create_bundle

    missing_dir = e2e_workspace / "does_not_exist"
    with pytest.raises(FileNotFoundError):
        create_bundle(missing_dir)

    not_a_dir = e2e_workspace / "plain_file.txt"
    not_a_dir.write_text("hello", encoding="utf-8")
    with pytest.raises((NotADirectoryError, ValueError)):
        create_bundle(not_a_dir)

    proc = run_cli(["bundle", "--workspace", str(missing_dir)])
    assert proc.returncode != 0


@pytest.mark.feature("F13")
def test_f13_target_platform_cross_os_filters_native_binaries(e2e_workspace: Path) -> None:
    from soclens.bundler import create_bundle

    ws = _stage_bundle_workspace(e2e_workspace / "cross_ws")
    for label in ("win_amd64", "pure"):
        out_zip = e2e_workspace / f"bundle_{label}.zip"
        created = create_bundle(ws, output_path=out_zip, wheelhouse=False, target_platform=label)
        with zipfile.ZipFile(created, "r") as zf:
            names = zf.namelist()
            manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))

        assert all("\\" not in name for name in names)
        assert not any(name.lower().endswith((".so", ".pyd", ".dll", ".dylib")) for name in names)
        assert manifest["target_platform"] == label
        assert isinstance(manifest["warnings"], list)


@pytest.mark.feature("F13")
def test_f13_wheelhouse_offline_failure_and_mocked_success(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    from soclens.bundler import create_bundle

    ws = _stage_bundle_workspace(e2e_workspace / "wh_ws")
    empty_links = e2e_workspace / "empty_links"
    empty_links.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("PIP_NO_INDEX", "1")
    monkeypatch.setenv("PIP_FIND_LINKS", str(empty_links))
    monkeypatch.setenv("PATH", "")

    with pytest.raises(RuntimeError):
        create_bundle(ws, output_path=e2e_workspace / "wh_fail.zip", wheelhouse=True)

    fail_cli = run_cli(
        ["bundle", "--workspace", str(ws), "--output", str(e2e_workspace / "wh_cli_fail.zip"), "--wheelhouse"],
        env={"PATH": "", "PIP_NO_INDEX": "1", "PIP_FIND_LINKS": str(empty_links)},
    )
    assert fail_cli.returncode != 0

    if importlib.util.find_spec("pip") is None:
        fake_bin = e2e_workspace / "fake_bin"
        fake_bin.mkdir(parents=True, exist_ok=True)
        fake_uv = fake_bin / "uv"
        fake_uv.write_text(
            f"#!{sys.executable}\n"
            "import sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "target = Path(args[args.index('--target') + 1])\n"
            "pkg = target / 'fake_wheelhouse_pkg'\n"
            "pkg.mkdir(parents=True, exist_ok=True)\n"
            "(pkg / '__init__.py').write_text('OK = True\\n', encoding='utf-8')\n",
            encoding="utf-8",
        )
        fake_uv.chmod(0o755)
        monkeypatch.setenv("PATH", str(fake_bin))

        ok_zip = create_bundle(ws, output_path=e2e_workspace / "wh_ok.zip", wheelhouse=True)
        with zipfile.ZipFile(ok_zip, "r") as zf:
            names = set(zf.namelist())
            manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
        assert manifest["wheelhouse"] is True
        assert "wheelhouse/requirements.txt" in names
        assert "fake_wheelhouse_pkg/__init__.py" in names


@pytest.mark.feature("F13")
def test_f13_zip_path_traversal_and_normalization_guard(e2e_workspace: Path) -> None:
    from soclens.bundler import create_bundle

    ws = _stage_bundle_workspace(e2e_workspace / "traversal_ws")
    bundle_path = create_bundle(ws, output_path=e2e_workspace / "safe_paths.zip")
    with zipfile.ZipFile(bundle_path, "r") as zf:
        for name in zf.namelist():
            assert "\\" not in name, f"Backslash in ZIP member: {name}"
            assert not name.startswith("/"), f"Leading slash in ZIP member: {name}"
            assert ".." not in Path(name).parts, f"Path traversal segment in ZIP member: {name}"


# ==============================================================================
# F14: Cohesive CLI & Exit Diagnostics (Tier 2)
# ==============================================================================


@pytest.mark.feature("F14")
def test_f14_cli_missing_rf_token_exits_nonzero_cleanly(
    e2e_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    no_creds_env = {"RF_API_TOKEN": "", "RECORDED_FUTURE_API_KEY": ""}
    for cmd in (["watchlist", "list"], ["rf", "lookup", "ip", "198.51.100.10"]):
        proc = run_cli(cmd, env=no_creds_env)
        assert proc.returncode != 0, f"{cmd} unexpectedly succeeded without RF token"
        assert "Traceback (most recent call last)" not in proc.stderr


@pytest.mark.feature("F14")
def test_f14_cli_api_403_and_429_diagnostics_and_traceid_jsonl(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    mock_rf_server.queue_fault(
        "/list/search",
        status_code=403,
        body={"message": "Missing API privileges for Lists", "status_code": 403, "trace_id": "trace-403-cli"},
        count=1,
    )
    proc_403 = run_cli(["watchlist", "list"])
    assert proc_403.returncode != 0
    combined_403 = proc_403.stdout + proc_403.stderr
    assert "403" in combined_403 or "privileges" in combined_403.lower()

    mock_rf_server.set_fault(
        "/list/search",
        status_code=429,
        headers={"Retry-After": "0"},
        body={"message": "Rate limit exceeded", "status_code": 429, "trace_id": "trace-429-cli"},
    )
    proc_429 = run_cli(["watchlist", "list"])
    assert proc_429.returncode != 0

    entries = _read_jsonl(e2e_workspace / "logs" / "rf_api_errors.jsonl")
    assert entries, "Expected error records in logs/rf_api_errors.jsonl"
    assert any(e.get("trace_id") or e.get("traceId") for e in entries)


@pytest.mark.feature("F14")
def test_f14_cli_invalid_list_type_rejected(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    from tests.e2e.conftest import ALL_LIST_TYPES

    bad_create = run_cli(["watchlist", "create", "BadList", "--type", "not_a_valid_type"])
    assert bad_create.returncode != 0

    bad_list = run_cli(["watchlist", "list", "--type", "bogus_list_type"])
    assert bad_list.returncode != 0

    from soclens.cli import build_parser

    parser = build_parser()
    for list_type in ALL_LIST_TYPES:
        ns = parser.parse_args(["watchlist", "create", f"Check-{list_type}", "--type", list_type])
        assert ns.type == list_type


@pytest.mark.feature("F14")
def test_f14_cli_bad_csv_and_missing_domains_file_nonzero(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    list_id = "report:brand-image-default"
    empty_csv = e2e_workspace / "empty.csv"
    empty_csv.write_text("", encoding="utf-8")

    for cmd in (
        ["watchlist", "sync", list_id, str(e2e_workspace / "missing.csv")],
        ["watchlist", "sync", list_id, str(empty_csv)],
        ["watchlist", "sync-logos", list_id, "--domains-file", str(e2e_workspace / "missing_domains.txt")],
    ):
        proc = run_cli(cmd)
        assert proc.returncode != 0, f"{cmd} unexpectedly exited 0"


@pytest.mark.feature("F14")
def test_f14_cli_missing_args_and_entity_api_failure_nonzero(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    for cmd in (
        ["watchlist", "add"],
        ["bogus-subcommand"],
        ["watchlist", "add", "report:nonexistent", "InternetDomainName", "a.com"],
    ):
        proc = run_cli(cmd, env={"SOCLENS_AUTO_APPROVE": "true"})
        assert proc.returncode != 0, f"{cmd} unexpectedly exited 0"


@pytest.mark.feature("F14")
def test_f14_cli_negative_relative_splunk_times_and_es_default_app(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    mock_splunk_server: MockSplunkServer,
    monkeypatch: pytest.MonkeyPatch,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    conf_file = _write_sample_savedsearches(e2e_workspace / "rel_times.conf")
    monkeypatch.delenv("SPLUNK_APP", raising=False)

    val_proc = run_cli(
        ["validate", "--input", str(conf_file), "--earliest", "-7d", "--latest", "-10m"]
    )
    assert val_proc.returncode == 0, f"stdout={val_proc.stdout}\nstderr={val_proc.stderr}"

    job_posts = [
        req
        for req in mock_splunk_server.requests_log
        if req["method"] == "POST" and req["path"].endswith("/search/jobs")
    ]
    assert len(job_posts) == 1
    assert job_posts[0]["path"] == "/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs"

    sig_proc = run_cli(
        [
            "sigma",
            "--refresh",
            "--export",
            "--earliest-time",
            "-70m",
            "--latest-time",
            "-10m",
            "--output",
            str(e2e_workspace / "rel_sigma" / "savedsearches.conf"),
        ]
    )
    assert sig_proc.returncode == 0, f"stdout={sig_proc.stdout}\nstderr={sig_proc.stderr}"


@pytest.mark.feature("F14")
def test_f14_cli_validate_missing_input_and_splunk_401_nonzero(
    e2e_workspace: Path,
    mock_splunk_server: MockSplunkServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    missing_proc = run_cli(["validate", "--input", str(e2e_workspace / "missing.conf")])
    assert missing_proc.returncode != 0

    conf_file = _write_sample_savedsearches(e2e_workspace / "auth_fail.conf")
    bad_auth_proc = run_cli(
        ["validate", "--input", str(conf_file)],
        env={"SPLUNK_TOKEN": "invalid-splunk-token"},
    )
    assert bad_auth_proc.returncode != 0


# ==============================================================================
# F15: Full Windows-Compatible TUI (Tier 2)
# ==============================================================================


@pytest.mark.feature("F15")
def test_f15_tui_pilot_missing_credentials_graceful_error(
    e2e_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("SPLUNK_USERNAME", raising=False)
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)

    app = _create_tui_app(dry_run=False)
    textual_widgets = importlib.import_module("textual.widgets")

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            for btn in app.query(textual_widgets.Button):
                label = str(getattr(btn, "label", "")).lower()
                if any(tok in label for tok in ("load", "refresh", "check", "validat", "list")):
                    try:
                        await pilot.click(btn)
                    except Exception:
                        btn.press()
                    await pilot.pause()
                    break
            await app.workers.wait_for_complete()
            assert app.is_running

    asyncio.run(_run())


@pytest.mark.feature("F15")
def test_f15_tui_pilot_rf_api_403_500_displays_error_and_logs_traceid(
    e2e_workspace: Path, mock_rf_server: MockRFServer
) -> None:
    from soclens.client import RecordedFutureClient

    mock_rf_server.set_fault(
        "/list/search",
        status_code=403,
        body={"message": "Missing API privileges", "status_code": 403, "trace_id": "tui-trace-403"},
    )
    client = RecordedFutureClient()
    app = _create_tui_app(client=client, dry_run=False)
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
                        if any(tok in label for tok in ("load", "refresh", "list")):
                            if btn.region.width > 0 and btn.region.height > 0:
                                try:
                                    await pilot.click(btn)
                                except Exception:
                                    btn.press()
                            else:
                                btn.press()
                            await pilot.pause()
            await app.workers.wait_for_complete()
            assert app.is_running
            rendered = _collect_tui_text(app).lower()
            assert "403" in rendered or "error" in rendered or "privileges" in rendered

    asyncio.run(_run())
    entries = _read_jsonl(e2e_workspace / "logs" / "rf_api_errors.jsonl")
    assert any((e.get("trace_id") or e.get("traceId")) == "tui-trace-403" for e in entries)


@pytest.mark.feature("F15")
def test_f15_tui_pilot_invalid_form_inputs_no_crash(e2e_workspace: Path) -> None:
    app = _create_tui_app(dry_run=True)
    textual_widgets = importlib.import_module("textual.widgets")

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            for inp in app.query(textual_widgets.Input):
                placeholder = str(getattr(inp, "placeholder", "")).lower()
                if "day" in placeholder or "limit" in placeholder:
                    inp.value = "not-a-number"
                elif "path" in placeholder or "file" in placeholder or "conf" in placeholder:
                    inp.value = str(e2e_workspace / "nonexistent_input.txt")
                else:
                    inp.value = ""
            await pilot.pause()
            for btn in app.query(textual_widgets.Button):
                try:
                    await pilot.click(btn)
                except Exception:
                    btn.press()
                await pilot.pause()
                break
            await app.workers.wait_for_complete()
            assert app.is_running

    asyncio.run(_run())


@pytest.mark.feature("F15")
def test_f15_tui_pilot_splunk_unreachable_or_401_no_freeze(
    e2e_workspace: Path,
    mock_splunk_server: MockSplunkServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]

    monkeypatch.setenv("SPLUNK_HOST", f"http://127.0.0.1:{closed_port}")
    monkeypatch.setenv("SPLUNK_TOKEN", "bad-token")

    app = _create_tui_app(dry_run=False)
    textual_widgets = importlib.import_module("textual.widgets")

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            for tabbed in app.query(textual_widgets.TabbedContent):
                for pane in tabbed.query(textual_widgets.TabPane):
                    label = str(getattr(pane, "label", "") or pane.id or "").lower()
                    if any(tok in label for tok in ("splunk", "validat", "dashboard", "diagnostic")):
                        if pane.id:
                            tabbed.active = pane.id
                            await pilot.pause()
                        for btn in pane.query(textual_widgets.Button):
                            blabel = str(getattr(btn, "label", "")).lower()
                            if any(tok in blabel for tok in ("check", "validat", "connect", "test")):
                                try:
                                    await pilot.click(btn)
                                except Exception:
                                    btn.press()
                                await pilot.pause()
            await asyncio.wait_for(app.workers.wait_for_complete(), timeout=15.0)
            assert app.is_running

    asyncio.run(_run())


@pytest.mark.feature("F15")
def test_f15_windows_utf8_console_and_cli_tui_help(
    e2e_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.config import ensure_utf8_console

    class FakeWinStream(io.StringIO):
        def __init__(self) -> None:
            super().__init__()
            self.reconfigured: list[tuple[str | None, str | None]] = []

        def reconfigure(self, *, encoding: str | None = None, errors: str | None = None) -> None:
            self.reconfigured.append((encoding, errors))

    fake_out = FakeWinStream()
    fake_err = FakeWinStream()
    monkeypatch.setattr(sys, "stdout", fake_out)
    monkeypatch.setattr(sys, "stderr", fake_err)
    ensure_utf8_console()
    assert fake_out.reconfigured == [("utf-8", "replace")]
    assert fake_err.reconfigured == [("utf-8", "replace")]

    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    ensure_utf8_console()

    proc = run_cli(["tui", "--help"])
    assert proc.returncode == 0, f"stderr={proc.stderr}"


@pytest.mark.feature("F15")
def test_f15_tui_pilot_rapid_navigation_and_clean_quit(e2e_workspace: Path) -> None:
    app = _create_tui_app(dry_run=True)
    textual_widgets = importlib.import_module("textual.widgets")

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            for tabbed in app.query(textual_widgets.TabbedContent):
                for pane in tabbed.query(textual_widgets.TabPane):
                    if pane.id:
                        tabbed.active = pane.id
                        await pilot.pause()
            for key in ("tab", "shift+tab", "q", "ctrl+q"):
                await pilot.press(key)
                await pilot.pause()
                if not app.is_running:
                    break
            if app.is_running:
                app.exit()
                await pilot.pause()
            await app.workers.wait_for_complete()

    asyncio.run(_run())
