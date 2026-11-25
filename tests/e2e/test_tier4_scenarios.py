"""Tier 4 real-world end-to-end SOC workflow scenario tests for soclens."""

from __future__ import annotations

import ast
import asyncio
import importlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from tests.e2e.fixtures.assets import make_png, sha1_hex, sha256_hex
from tests.e2e.fixtures.brand_sites import RouteSpec, build_default_brand_sites

if TYPE_CHECKING:
    from tests.e2e.conftest import BrandHTTPServer, MockRFServer, MockSplunkServer

pytestmark = [pytest.mark.e2e, pytest.mark.tier4]

REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    assert path.is_file(), f"Expected JSONL log file at {path}"
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def _fast_domain_hasher(
    domain: str,
    idx: int = 1,
    total: int = 1,
    ignored_hashes: dict[str, str] | None = None,
) -> tuple[list[dict[str, str]], int, str | None, list[str], list[dict[str, Any]]]:
    """Run real logo extraction with minimal retry backoff for fast local HTTP tests."""
    from soclens.logos.extractor import ExtractorConfig, get_domain_image_hash

    cfg = ExtractorConfig(max_retries=0, backoff_base=0.01)
    return get_domain_image_hash(
        domain=domain,
        idx=idx,
        total=total,
        ignored_hashes=ignored_hashes,
        config=cfg,
    )


def _resolve_tui_app(dry_run: bool = True) -> Any:
    """Resolve and instantiate the Textual TUI App from soclens.tui."""
    textual_app = importlib.import_module("textual.app")
    app_cls = textual_app.App

    tui_pkg = importlib.import_module("soclens.tui")
    tui_app_mod = importlib.import_module("soclens.tui.app")

    create_fn = getattr(tui_app_mod, "create_app", None) or getattr(tui_pkg, "create_app", None)
    if callable(create_fn):
        try:
            return create_fn(dry_run=dry_run)
        except TypeError:
            return create_fn()

    for attr_name in ("SocLensApp", "SOCApp", "RecordedFutureSOCApp"):
        cls = getattr(tui_app_mod, attr_name, None) or getattr(tui_pkg, attr_name, None)
        if isinstance(cls, type) and issubclass(cls, app_cls):
            try:
                return cls(dry_run=dry_run)
            except TypeError:
                return cls()

    for mod in (tui_app_mod, tui_pkg):
        for obj in vars(mod).values():
            if isinstance(obj, type) and issubclass(obj, app_cls) and obj is not app_cls:
                try:
                    return obj(dry_run=dry_run)
                except TypeError:
                    return obj()

    raise AssertionError("No Textual App subclass or create_app factory found in soclens.tui")


# ==============================================================================
# Scenario 1: Brand Onboarding & Idempotent Continuous Sync
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("F2")
@pytest.mark.feature("F4")
@pytest.mark.feature("F7")
@pytest.mark.feature("F8")
@pytest.mark.feature("F9")
@pytest.mark.feature("F10")
@pytest.mark.feature("F14")
@pytest.mark.feature("F16")
def test_t4_s01_brand_onboarding_and_idempotent_continuous_sync(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.logos.brand_sync import (
        calculate_brand_sync_delta,
        load_brand_sync_state,
        run_continuous_brand_sync,
    )

    repo_disc = REPO_ROOT / "discovered_images.json"
    repo_disc_before = repo_disc.read_bytes() if repo_disc.is_file() else None

    # Scope strictly to 2 synthetic sites (R6)
    alpha_host = brand_http_server.site_url("brand-alpha.local").removeprefix("http://")
    gamma_host = brand_http_server.site_url("brand-gamma.local").removeprefix("http://")
    gamma_profile = build_default_brand_sites()["brand-gamma.local"]

    client = RecordedFutureClient()
    brand_list = client.create_list("SOC Onboarding Brand Watch", "brand")
    list_id = str(brand_list["id"])
    state_file = e2e_workspace / "s01_brand_sync_state.json"
    lock_file = e2e_workspace / ".s01_brand_sync.lock"
    disc_file = e2e_workspace / "s01_discovered.json"

    summary = run_continuous_brand_sync(
        client,
        list_id,
        domains=[alpha_host, gamma_host],
        dry_run=False,
        output_locations_file=disc_file,
        interval_seconds=0.02,
        max_runs=2,
        state_file=state_file,
        lock_file=lock_file,
        workspace_dir=e2e_workspace,
        image_hasher=_fast_domain_hasher,
    )
    assert summary["runs_attempted"] == 2
    assert summary["runs_succeeded"] == 2
    assert summary["runs_failed"] == 0
    assert not lock_file.exists()
    assert disc_file.is_file()

    state = load_brand_sync_state(state_file)
    assert state["runs_completed"] == 2
    assert state["last_run"]["added"] == 0  # 2nd run was idempotent
    assert state["last_run"]["removed"] == 0

    # Swap a logo on brand-gamma.local and verify delta update via CLI --watch --max-runs 1
    old_jpg_hash = gamma_profile.expected_logo_hashes["/images/gamma-logo.jpg"]
    new_png = make_png(210, 62, (15, 160, 90, 255))
    new_hash = sha256_hex(new_png)
    brand_http_server.set_route(
        "brand-gamma.local",
        "/images/gamma-logo.jpg",
        RouteSpec(status=200, content_type="image/png", body=new_png),
    )

    cli_res = run_cli(
        [
            "watchlist",
            "sync-logos",
            list_id,
            "--domains",
            f"{alpha_host},{gamma_host}",
            "--watch",
            "--max-runs",
            "1",
            "--interval",
            "0.02",
            "--output-locations",
            str(e2e_workspace / "s01_cli_disc.json"),
        ],
        env={"SOCLENS_AUTO_APPROVE": "true"},
        timeout=30.0,
    )
    assert cli_res.returncode == 0, f"stderr={cli_res.stderr}\nstdout={cli_res.stdout}"

    final_names = {e["entity"]["name"] for e in client.get_watchlist_entities(list_id)}
    assert new_hash in final_names
    assert old_jpg_hash not in final_names

    # Verify idempotent delta after rotation
    _, _, to_add, to_remove, _, _ = calculate_brand_sync_delta(
        client,
        list_id,
        [alpha_host, gamma_host],
        output_locations_file=None,
        image_hasher=_fast_domain_hasher,
    )
    assert to_add == []
    assert to_remove == []

    if repo_disc_before is None:
        assert not repo_disc.exists()
    else:
        assert repo_disc.read_bytes() == repo_disc_before


# ==============================================================================
# Scenario 2: Partial-Failure & Grace-Period Brand Watch Recovery
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("F3")
@pytest.mark.feature("F8")
@pytest.mark.feature("F9")
@pytest.mark.feature("F10")
def test_t4_s02_partial_failure_and_grace_period_brand_watch_recovery(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.logos.brand_sync import execute_domain_brand_sync, load_brand_sync_state

    gamma_host = brand_http_server.site_url("brand-gamma.local").removeprefix("http://")
    flaky_host = brand_http_server.site_url("brand-flaky.local").removeprefix("http://")
    flaky_profile = build_default_brand_sites()["brand-flaky.local"]
    flaky_hashes = set(flaky_profile.expected_logo_hashes.values())
    gamma_hashes = set(build_default_brand_sites()["brand-gamma.local"].expected_logo_hashes.values())

    client = RecordedFutureClient()
    list_id = str(client.create_list("Grace Period Brand Watch", "brand")["id"])
    state_file = e2e_workspace / "s02_state.json"

    assert execute_domain_brand_sync(
        client,
        list_id,
        [gamma_host, flaky_host],
        output_locations_file=None,
        state_grace_failures=3,
        state_file=state_file,
        image_hasher=_fast_domain_hasher,
    )
    assert (gamma_hashes | flaky_hashes).issubset(
        {e["entity"]["name"] for e in client.get_watchlist_entities(list_id)}
    )

    # Inject persistent 503 on brand-flaky.local -> preserved for 2 runs (< grace=3)
    brand_http_server.set_fault("brand-flaky.local", "/", 503, body=b"Upstream 503")
    for expected_fail_count in (1, 2):
        assert execute_domain_brand_sync(
            client,
            list_id,
            [gamma_host, flaky_host],
            output_locations_file=None,
            state_grace_failures=3,
            state_file=state_file,
            image_hasher=_fast_domain_hasher,
        )
        st = load_brand_sync_state(state_file)
        assert st["domains"][flaky_host]["consecutive_failures"] == expected_fail_count
        current_names = {e["entity"]["name"] for e in client.get_watchlist_entities(list_id)}
        assert flaky_hashes.issubset(current_names)
        assert gamma_hashes.issubset(current_names)

    # Clear fault -> recovers and resets consecutive_failures to 0
    brand_http_server.clear_faults()
    assert execute_domain_brand_sync(
        client,
        list_id,
        [gamma_host, flaky_host],
        output_locations_file=None,
        state_grace_failures=3,
        state_file=state_file,
        image_hasher=_fast_domain_hasher,
    )
    recovered_state = load_brand_sync_state(state_file)
    assert recovered_state["domains"][flaky_host]["consecutive_failures"] == 0

    # Re-inject persistent 503 -> preserved on failures 1 & 2, pruned on failure 3 (>= grace)
    brand_http_server.set_fault("brand-flaky.local", "/", 503, body=b"Upstream 503")
    for _ in range(2):
        execute_domain_brand_sync(
            client,
            list_id,
            [gamma_host, flaky_host],
            output_locations_file=None,
            state_grace_failures=3,
            state_file=state_file,
            image_hasher=_fast_domain_hasher,
        )
    assert flaky_hashes.issubset(
        {e["entity"]["name"] for e in client.get_watchlist_entities(list_id)}
    )

    execute_domain_brand_sync(
        client,
        list_id,
        [gamma_host, flaky_host],
        output_locations_file=None,
        state_grace_failures=3,
        state_file=state_file,
        image_hasher=_fast_domain_hasher,
    )
    final_names = {e["entity"]["name"] for e in client.get_watchlist_entities(list_id)}
    assert flaky_hashes.isdisjoint(final_names)
    assert gamma_hashes.issubset(final_names)


# ==============================================================================
# Scenario 3: Rate-Limit & Permission Incident Diagnostics
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("F2")
@pytest.mark.feature("F3")
@pytest.mark.feature("F6")
@pytest.mark.feature("F14")
def test_t4_s03_rate_limit_and_permission_incident_diagnostics(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    from soclens.client import RecordedFutureAuthError, RecordedFutureClient

    mock_rf_server.queue_fault(
        "/v2/ip/",
        429,
        body={
            "error": {"status": 429, "message": "Rate limit exceeded", "reason": "Too Many Requests"},
            "traceId": "tr-s03-429",
        },
        headers={"Retry-After": "0"},
        count=1,
    )
    mock_rf_server.queue_fault(
        "/soar/v3/enrichment",
        403,
        body={"message": "Missing API privileges", "status_code": 403, "trace_id": "tr-s03-mod"},
        count=1,
    )
    mock_rf_server.queue_fault(
        "/alert/v3",
        403,
        body={"message": "Missing Data permissions", "status_code": 403, "trace_id": "tr-s03-data"},
        count=1,
    )

    client = RecordedFutureClient()
    ip_info = client.v2_lookup("ip", "198.51.100.10")
    assert ip_info["data"]["entity"]["id"] == "ip:198.51.100.10"

    with pytest.raises(RecordedFutureAuthError) as mod_err:
        client.soar_enrich({"ip": ["198.51.100.10"]})
    assert mod_err.value.permission_type == "missing_api_privileges"

    with pytest.raises(RecordedFutureAuthError) as data_err:
        client.search_alerts_v3(limit=10)
    assert data_err.value.permission_type == "missing_data_permissions"

    mock_rf_server.queue_fault(
        "/list/report:brand-image-default/entities",
        403,
        body={"message": "Missing Data permissions", "status_code": 403, "trace_id": "tr-s03-cli"},
        count=1,
    )
    cli_res = run_cli(["watchlist", "entities", "report:brand-image-default", "--json"])
    assert cli_res.returncode != 0
    assert "tr-s03-cli" in f"{cli_res.stdout}\n{cli_res.stderr}"

    entries = _read_jsonl(e2e_workspace / "logs" / "rf_api_errors.jsonl")
    traces = {entry.get("trace_id") for entry in entries}
    assert {"tr-s03-429", "tr-s03-mod", "tr-s03-data", "tr-s03-cli"}.issubset(traces)


# ==============================================================================
# Scenario 4: Sigma Sync -> Splunk ES Validation Pipeline
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("F5")
@pytest.mark.feature("F11")
@pytest.mark.feature("F12")
@pytest.mark.feature("F14")
def test_t4_s04_sigma_sync_to_splunk_es_validation_pipeline(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    mock_splunk_server: MockSplunkServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    from soclens.splunk import parse_savedsearches_files

    repo_cache = REPO_ROOT / "sigma_rules_cache.json"
    repo_cache_before = repo_cache.read_bytes() if repo_cache.is_file() else None

    out_conf = e2e_workspace / "sigma_conf" / "rules.conf"
    sig_res = run_cli(
        ["sigma", "--refresh", "--export", "--output", str(out_conf), "--json"],
        env={"SOCLENS_HOME": str(e2e_workspace)},
    )
    assert sig_res.returncode == 0, f"stderr={sig_res.stderr}\nstdout={sig_res.stdout}"

    ws_cache = e2e_workspace / "sigma_rules_cache.json"
    assert ws_cache.is_file()
    cache_snapshot = ws_cache.read_bytes()

    parsed = parse_savedsearches_files(str(e2e_workspace / "sigma_conf" / "rules_*.conf"))
    assert len(parsed) >= 2

    # Inject 500 on RF detection-rule search -> CLI refresh must preserve existing cache
    mock_rf_server.set_fault("/detection-rule/search", 500, body={"message": "RF outage"})
    fallback_res = run_cli(
        ["sigma", "--refresh", "--export", "--output", str(out_conf)],
        env={"SOCLENS_HOME": str(e2e_workspace)},
        timeout=60.0,
    )
    assert fallback_res.returncode == 0, f"Fallback failed: {fallback_res.stderr}"
    assert ws_cache.read_bytes() == cache_snapshot

    val_json = e2e_workspace / "validation_results.json"
    val_res = run_cli(
        [
            "validate",
            "--input",
            str(e2e_workspace / "sigma_conf" / "rules_*.conf"),
            "--output",
            str(val_json),
            "--json",
        ],
    )
    assert val_res.returncode == 0, f"stderr={val_res.stderr}\nstdout={val_res.stdout}"
    report = json.loads(val_json.read_text(encoding="utf-8"))
    assert report["summary"]["successful"] >= 2
    assert report["summary"]["failed"] == 0

    es_job_posts = [
        r
        for r in mock_splunk_server.requests_log
        if r["method"] == "POST"
        and r["path"] == "/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs"
    ]
    assert len(es_job_posts) >= 2

    if repo_cache_before is None:
        assert not repo_cache.exists()
    else:
        assert repo_cache.read_bytes() == repo_cache_before


# ==============================================================================
# Scenario 5: Air-Gapped Bundle Build & Extracted Offline Verification
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("F2")
@pytest.mark.feature("F13")
@pytest.mark.feature("F14")
@pytest.mark.feature("F16")
def test_t4_s05_air_gapped_bundle_build_and_extracted_offline_verification(
    e2e_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    ws = e2e_workspace / "ws_src"
    ws.mkdir(parents=True, exist_ok=True)
    shutil.copytree(REPO_ROOT / "soclens", ws / "soclens", dirs_exist_ok=True)
    for rel in ("pyproject.toml", "README.md", "ignored_hashes.txt"):
        src = REPO_ROOT / rel
        if src.is_file():
            shutil.copy2(src, ws / rel)
    for rel_dir in ("docs", "scripts"):
        shutil.copytree(REPO_ROOT / rel_dir, ws / rel_dir, dirs_exist_ok=True)

    (ws / "apikey.key").write_text("TOP_SECRET_TOKEN", encoding="utf-8")
    (ws / "logs").mkdir(exist_ok=True)
    (ws / "logs" / "rf_api_errors.jsonl").write_text("{}\n", encoding="utf-8")

    zip_path = e2e_workspace / "out" / "airgap_soc.zip"
    res = run_cli(
        ["bundle", "--output", str(zip_path), "--json"],
        env={"SOCLENS_HOME": str(ws)},
        cwd=ws,
    )
    assert res.returncode == 0, f"stderr={res.stderr}\nstdout={res.stdout}"
    assert zip_path.is_file()

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        for required in (
            "BUNDLE_MANIFEST.json",
            "ignored_hashes.txt",
            "pyproject.toml",
            "docs/RF_API_REVIEW.md",
            "soclens/__init__.py",
            "scripts/soclens-brand-sync.ps1",
            "scripts/soclens-brand-sync.service",
        ):
            assert required in names, f"Missing {required} from bundle"
        assert "apikey.key" not in names
        assert not any(".." in n or "__pycache__" in n or n.endswith(".pyc") for n in names)

    extract_dir = e2e_workspace / "airgap"
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)

    offline_env = {
        "PATH": os.environ.get("PATH", ""),
        "SOCLENS_HOME": str(extract_dir),
    }
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import sys; from pathlib import Path; "
                f"ext = Path({str(extract_dir)!r}).resolve(); "
                "sys.path.insert(0, str(ext)); "
                "import soclens.config, soclens.client, soclens.logos, soclens.sigma, "
                "soclens.splunk, soclens.bundler; "
                "assert soclens.config.get_workspace_dir().resolve() == ext"
            ),
        ],
        cwd=extract_dir,
        env=offline_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"Offline verification failed: {proc.stderr}\n{proc.stdout}"


# ==============================================================================
# Scenario 6: Playbook Alert Logo Hash Investigation + SOAR v3 + Sandbox
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("F3")
@pytest.mark.feature("F4")
@pytest.mark.feature("F6")
@pytest.mark.feature("F9")
def test_t4_s06_playbook_alert_logo_hash_investigation_soar_and_sandbox(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    pb_hash = "b" * 64
    client.add_entity("report:brand-image-default", "Hash", pb_hash, context={"annotation": "Alpha primary logo"})

    alerts = client.search_playbook_alerts(categories=["domain_abuse", "malicious_sites"])
    assert len(alerts["data"]) >= 2

    pb1 = client.get_playbook_alert("domain_abuse", "pb-1")["data"]
    assert any(
        asset.get("hash_id") == f"hash:{pb_hash}"
        for asset in pb1["panel_evidence_summary"]["assets"]
    )
    pb2 = client.get_playbook_alert("malicious_sites", "pb-2")["data"]
    assert f"hash:{'c' * 64}" in pb2["panel_evidence_summary"]["hashes"]

    screenshot = client.get_playbook_alert_image("domain_abuse", "pb-1", "screenshot-1")
    assert screenshot.startswith(b"\x89PNG\r\n\x1a\n")

    triage = client.soar_triage(
        "phishing",
        {"ip": ["198.51.100.10"], "domain": ["evil-lookalike.example"]},
    )
    results = triage["data"]["results"]
    assert len(results) == 2
    assert all(item["verdict"] is True for item in results)

    sb_search = client.sandbox_search("suspicious.exe")
    assert len(sb_search["samples"]) >= 1
    sb_overview = client.sandbox_get_overview("sample-1")
    assert sb_overview["sample"]["id"] == "sample-1"

    case = client.create_case(
        title="Brand Logo Impersonation - pb-1",
        description=f"Matched hash:{pb_hash} and triaged 198.51.100.10",
        priority="High",
    )
    assert case["id"].startswith("case-")
    updated_pb = client.update_playbook_alert("pb-1", status="InProgress", priority="High")
    assert updated_pb["data"]["status"] == "InProgress"


# ==============================================================================
# Scenario 7: Interactive Windows-Compatible TUI Full Operator Journey
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("F4")
@pytest.mark.feature("F6")
@pytest.mark.feature("F9")
@pytest.mark.feature("F11")
@pytest.mark.feature("F12")
@pytest.mark.feature("F13")
@pytest.mark.feature("F15")
def test_t4_s07_interactive_windows_tui_full_operator_journey(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    mock_splunk_server: MockSplunkServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    pytest.importorskip("textual")
    app = _resolve_tui_app(dry_run=True)

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.is_running

            for _ in range(6):
                await pilot.press("tab")
                await pilot.pause()
                assert app.is_running

            banned_posix = {"termios", "fcntl", "pty", "tty"}
            tui_mods = [name for name in sys.modules if name.startswith("soclens.tui")]
            assert tui_mods, "soclens.tui modules should be loaded"
            for m in tui_mods:
                mod_file = getattr(sys.modules[m], "__file__", None)
                if not mod_file:
                    continue
                tree = ast.parse(Path(mod_file).read_text(encoding="utf-8", errors="ignore"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            assert alias.name.split(".")[0] not in banned_posix
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        assert node.module.split(".")[0] not in banned_posix

    asyncio.run(_run())


# ==============================================================================
# Scenario 8: Cross-Feature CLI Dry-Run & JSON Audit Pipeline
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("F4")
@pytest.mark.feature("F9")
@pytest.mark.feature("F11")
@pytest.mark.feature("F12")
@pytest.mark.feature("F13")
@pytest.mark.feature("F14")
def test_t4_s08_cross_feature_cli_dry_run_and_json_audit_pipeline(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    mock_splunk_server: MockSplunkServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    gamma_host = brand_http_server.site_url("brand-gamma.local").removeprefix("http://")
    seed_csv = e2e_workspace / "seed_domains.csv"
    seed_csv.write_text("domain\nexample-audit.invalid\n", encoding="utf-8")
    conf_file = e2e_workspace / "audit.conf"
    conf_file.write_text("[Audit Search]\nsearch = index=main | head 1\n", encoding="utf-8")

    # Even with SOCLENS_AUTO_APPROVE=true, --dry-run must NEVER mutate RF or Splunk
    env_auto = {"SOCLENS_AUTO_APPROVE": "true"}

    r1 = run_cli(
        ["--dry-run", "--json", "watchlist", "add", "report:brand-image-default", "Hash", "a" * 64],
        env=env_auto,
    )
    r2 = run_cli(
        ["--dry-run", "--json", "watchlist", "sync", "report:brand-image-default", str(seed_csv), "--type", "InternetDomainName"],
        env=env_auto,
    )
    r3 = run_cli(
        [
            "--dry-run",
            "--json",
            "watchlist",
            "sync-logos",
            "report:brand-image-default",
            "--domains",
            gamma_host,
            "--output-locations",
            str(e2e_workspace / "audit_disc.json"),
        ],
        env=env_auto,
    )
    r4 = run_cli(
        ["validate", "--input", str(conf_file), "--dry-run", "--json"],
        env=env_auto,
    )

    for res in (r1, r2, r3, r4):
        assert res.returncode == 0, f"Dry-run failed: stderr={res.stderr}\nstdout={res.stdout}"
        parsed = json.loads(res.stdout)
        assert isinstance(parsed, (dict, list))

    rf_write_paths = [
        r["path"]
        for r in mock_rf_server.requests_log
        if r["method"] == "POST" and ("/entity/add" in r["path"] or "/entity/remove" in r["path"])
    ]
    assert rf_write_paths == [], f"Dry-run must not mutate RF watchlists: {rf_write_paths}"

    splunk_job_posts = [
        r for r in mock_splunk_server.requests_log if r["method"] == "POST" and "/search/jobs" in r["path"]
    ]
    assert splunk_job_posts == [], f"Dry-run must not submit Splunk jobs: {splunk_job_posts}"


# ==============================================================================
# Scenario 9: Multi-Brand Shared-Logo Attribution & Ignored-Hash Tuning
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("F7")
@pytest.mark.feature("F8")
@pytest.mark.feature("F9")
@pytest.mark.feature("F16")
def test_t4_s09_multi_brand_shared_logo_attribution_and_ignored_hash_tuning(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.logos.brand_sync import execute_domain_brand_sync, load_brand_sync_state

    alpha_host = brand_http_server.site_url("brand-alpha.local").removeprefix("http://")
    shared_host = brand_http_server.site_url("brand-shared.local").removeprefix("http://")
    sites = build_default_brand_sites()
    shared_hash = sites["brand-shared.local"].expected_logo_hashes["/images/shared-logo.png"]
    assert shared_hash == sites["brand-alpha.local"].expected_logo_hashes["/images/site-logo.png"]

    sub_bytes = sites["brand-shared.local"].routes["/images/subsidiary-logo.png"].body
    sub_sha256 = sha256_hex(sub_bytes)
    sub_sha1 = sha1_hex(sub_bytes)

    client = RecordedFutureClient()
    list_id = str(client.create_list("Shared Attribution Brand List", "brand")["id"])
    state_file = e2e_workspace / "s09_state.json"

    assert execute_domain_brand_sync(
        client,
        list_id,
        [alpha_host, shared_host],
        output_locations_file=None,
        state_file=state_file,
        image_hasher=_fast_domain_hasher,
    )

    entities_by_name = {
        e["entity"]["name"]: e for e in client.get_watchlist_entities(list_id)
    }
    assert shared_hash in entities_by_name
    assert set(entities_by_name[shared_hash]["context"]["domains"]) == {alpha_host, shared_host}

    state = load_brand_sync_state(state_file)
    assert shared_hash in state["domains"][alpha_host]["hashes"]
    assert shared_hash in state["domains"][shared_host]["hashes"]

    # Drop shared-logo.png from brand-shared.local -> shared_hash MUST remain because alpha still serves it
    brand_http_server.set_route(
        "brand-shared.local",
        "/",
        RouteSpec(
            status=200,
            content_type="text/html; charset=utf-8",
            body=b'<html><body><img class="site-logo" src="/images/subsidiary-logo.png" alt="Sub Logo"></body></html>',
        ),
    )
    assert execute_domain_brand_sync(
        client,
        list_id,
        [alpha_host, shared_host],
        output_locations_file=None,
        state_file=state_file,
        image_hasher=_fast_domain_hasher,
    )
    after_drop = {e["entity"]["name"] for e in client.get_watchlist_entities(list_id)}
    assert shared_hash in after_drop
    assert sub_sha256 in after_drop

    # Tune out subsidiary-logo.png via SHA-1 in ignored_hashes.txt -> only sub_sha256 removed
    ignored_file = e2e_workspace / "ignored_hashes.txt"
    ignored_file.write_text(f"{sub_sha1} # tune out subsidiary logo via SHA-1\n", encoding="utf-8")
    assert execute_domain_brand_sync(
        client,
        list_id,
        [alpha_host, shared_host],
        output_locations_file=None,
        ignore_hashes_file=ignored_file,
        state_file=state_file,
        image_hasher=_fast_domain_hasher,
    )
    final_names = {e["entity"]["name"] for e in client.get_watchlist_entities(list_id)}
    assert shared_hash in final_names
    assert sub_sha256 not in final_names


# ==============================================================================
# Scenario 10: API Surface Parity & Cross-Platform Path Compatibility Audit
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier4
@pytest.mark.feature("F1")
@pytest.mark.feature("F2")
@pytest.mark.feature("F14")
@pytest.mark.feature("F15")
def test_t4_s10_api_surface_parity_and_cross_platform_path_audit(
    e2e_workspace: Path,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.config import ensure_utf8_console, get_workspace_dir
    from soclens.logos.brand_sync import resolve_state_path
    from soclens.sigma import get_split_output_path

    review_doc = REPO_ROOT / "docs" / "RF_API_REVIEW.md"
    assert review_doc.is_file()
    doc_text = review_doc.read_text(encoding="utf-8")
    assert "RF-DOCS-2026Q4" in doc_text
    assert "X-RFToken" in doc_text
    assert "Authorization: Bearer" in doc_text

    # Verify every method documented in §7.1 coverage table exists on RecordedFutureClient
    expected_methods = (
        "get_watchlists",
        "create_list",
        "get_list_info",
        "get_list_status",
        "get_watchlist_entities",
        "add_entity",
        "remove_entity",
        "get_text_entries",
        "get_entities_with_tags",
        "replace_entity_tags",
        "search_detection_rules",
        "get_detection_rule_entities",
        "get_detection_rule_entity_types",
        "entity_match",
        "entity_lookup",
        "soar_enrich",
        "soar_get_contexts",
        "soar_triage",
        "v2_lookup",
        "v2_company_by_domain",
        "v2_risklist",
        "v2_stat_risklist",
        "v2_riskrules",
        "v2_search",
        "search_playbook_alerts",
        "get_playbook_alert_preview",
        "get_playbook_alert",
        "update_playbook_alert",
        "get_playbook_alert_image",
        "search_alerts_v3",
        "get_alert_v3",
        "get_alert_v3_hits",
        "update_alerts_v2",
        "search_cases",
        "lookup_cases",
        "create_case",
        "update_case",
        "sandbox_search",
        "sandbox_get_sample",
        "sandbox_get_overview",
    )
    for method_name in expected_methods:
        assert method_name in doc_text, f"Missing {method_name} in docs/RF_API_REVIEW.md"
        assert callable(getattr(RecordedFutureClient, method_name, None)), (
            f"Missing RecordedFutureClient.{method_name}"
        )

    # AST static audit: no POSIX-only modules or os.fork / os.system / SIGALRM in soclens/
    banned_modules = {"termios", "fcntl", "grp", "pwd", "pty", "tty"}
    banned_attrs = {("os", "fork"), ("os", "system"), ("signal", "SIGALRM")}
    violations: list[str] = []

    for py_file in sorted((REPO_ROOT / "soclens").rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        rel = py_file.relative_to(REPO_ROOT).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in banned_modules:
                        violations.append(f"{rel}:{node.lineno} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in banned_modules:
                    violations.append(f"{rel}:{node.lineno} imports from {node.module}")
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                pair = (node.value.id, node.attr)
                if pair in banned_attrs:
                    violations.append(f"{rel}:{node.lineno} references {pair[0]}.{pair[1]}")

    assert violations == [], f"Cross-platform POSIX-only violations found: {violations}"

    # Verify Path resolution & cp1252-like console reconfiguration safety
    assert get_workspace_dir(e2e_workspace) == e2e_workspace.resolve()
    assert resolve_state_path(None, e2e_workspace) == e2e_workspace.resolve() / "brand_sync_state.json"
    split = get_split_output_path(e2e_workspace / "out" / "rules.conf", "*wineventlog")
    assert Path(split).name == "rules_wineventlog.conf"

    cp1252_stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    orig_stdout = sys.stdout
    try:
        sys.stdout = cp1252_stream
        ensure_utf8_console()
        assert re.match(r"^utf-?8$", cp1252_stream.encoding, re.IGNORECASE)
    finally:
        sys.stdout = orig_stdout
        cp1252_stream.close()
