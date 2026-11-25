"""Tier 3 pairwise cross-feature E2E combination tests for soclens."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import subprocess
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from tests.e2e.fixtures.assets import make_png, md5_hex, sha256_hex
from tests.e2e.fixtures.brand_sites import RouteSpec, build_default_brand_sites

if TYPE_CHECKING:
    from tests.e2e.conftest import BrandHTTPServer, MockRFServer, MockSplunkServer

pytestmark = [pytest.mark.e2e, pytest.mark.tier3]

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


def _copy_minimal_bundle_workspace(dest: Path) -> Path:
    """Create a self-contained workspace copy inside tmp_path for bundler tests."""
    import shutil

    dest.mkdir(parents=True, exist_ok=True)
    shutil.copytree(REPO_ROOT / "soclens", dest / "soclens", dirs_exist_ok=True)
    for rel in ("pyproject.toml", "README.md", "ignored_hashes.txt"):
        src = REPO_ROOT / rel
        if src.is_file():
            shutil.copy2(src, dest / rel)
    for rel_dir in ("docs", "scripts"):
        src_dir = REPO_ROOT / rel_dir
        if src_dir.is_dir():
            shutil.copytree(src_dir, dest / rel_dir, dirs_exist_ok=True)
    return dest


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
# Area 1: CLI (soclens) <-> Config/Workspace (SOCLENS_HOME, rf_api_errors.jsonl, traceId)
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F2")
@pytest.mark.feature("F14")
def test_t3_a01_cli_uses_soclens_home_for_sigma_cache_and_outputs(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    repo_cache = REPO_ROOT / "sigma_rules_cache.json"
    repo_cache_before = repo_cache.read_bytes() if repo_cache.is_file() else None

    out_conf = e2e_workspace / "exports" / "sigma.conf"
    res = run_cli(
        ["sigma", "--refresh", "--export", "--output", str(out_conf), "--json"],
        env={"SOCLENS_HOME": str(e2e_workspace)},
    )
    assert res.returncode == 0, f"stderr={res.stderr}\nstdout={res.stdout}"
    payload = json.loads(res.stdout)
    assert isinstance(payload, dict)

    ws_cache = e2e_workspace / "sigma_rules_cache.json"
    assert ws_cache.is_file(), "Sigma cache must be written inside SOCLENS_HOME"
    cached = json.loads(ws_cache.read_text(encoding="utf-8"))
    assert len(cached) >= 2
    assert (e2e_workspace / "exports" / "sigma_wineventlog.conf").is_file()

    if repo_cache_before is None:
        assert not repo_cache.exists()
    else:
        assert repo_cache.read_bytes() == repo_cache_before


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F2")
@pytest.mark.feature("F14")
def test_t3_a01_cli_api_error_persists_trace_id_to_workspace_jsonl(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    trace_val = "trace-cli-404-e2e"
    mock_rf_server.queue_fault(
        "/list/report:missing-list/entities",
        404,
        body={"message": "Watchlist not found", "status_code": 404, "trace_id": trace_val},
    )

    res = run_cli(["watchlist", "entities", "report:missing-list"])
    assert res.returncode != 0
    combined = f"{res.stdout}\n{res.stderr}"
    assert trace_val in combined or "not found" in combined.lower()

    jsonl_path = e2e_workspace / "logs" / "rf_api_errors.jsonl"
    entries = _read_jsonl(jsonl_path)
    assert any(
        e.get("trace_id") == trace_val and e.get("status_code") == 404 for e in entries
    ), f"Expected trace_id={trace_val} in {entries}"


# ==============================================================================
# Area 2: CLI <-> RF Client (429 Retry-After, 403 permissions, --json)
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F3")
@pytest.mark.feature("F14")
def test_t3_a02_cli_recovers_from_429_retry_after_with_json_output(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    mock_rf_server.queue_fault(
        "/list/search",
        429,
        body={"message": "Rate limit exceeded", "status_code": 429, "trace_id": "trace-429-cli"},
        headers={"Retry-After": "0"},
        method="POST",
        count=1,
    )

    res = run_cli(["watchlist", "list", "--json"])
    assert res.returncode == 0, f"stderr={res.stderr}\nstdout={res.stdout}"
    data = json.loads(res.stdout)
    items = data if isinstance(data, list) else data.get("watchlists", data.get("data", []))
    assert any(
        item.get("id") == "report:brand-image-default" for item in items if isinstance(item, dict)
    )
    list_search_reqs = [r for r in mock_rf_server.requests_log if r["path"] == "/list/search"]
    assert len(list_search_reqs) >= 2


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F3")
@pytest.mark.feature("F14")
def test_t3_a02_cli_and_client_403_module_vs_data_permission_diagnostics(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    from soclens.client import RecordedFutureAuthError, RecordedFutureClient

    mock_rf_server.queue_fault(
        "/soar/v3/enrichment",
        403,
        body={"message": "Missing API privileges", "status_code": 403, "trace_id": "tr-403-mod"},
    )
    mock_rf_server.queue_fault(
        "/alert/v3",
        403,
        body={"message": "Missing Data permissions", "status_code": 403, "trace_id": "tr-403-data"},
    )

    client = RecordedFutureClient()
    with pytest.raises(RecordedFutureAuthError) as mod_exc:
        client.soar_enrich({"ip": ["198.51.100.10"]})
    assert mod_exc.value.permission_type == "missing_api_privileges"
    assert mod_exc.value.trace_id == "tr-403-mod"

    with pytest.raises(RecordedFutureAuthError) as data_exc:
        client.search_alerts_v3(limit=5)
    assert data_exc.value.permission_type == "missing_data_permissions"
    assert data_exc.value.trace_id == "tr-403-data"

    # Also verify CLI rf --help and non-zero 403 CLI diagnostics with --json
    help_res = run_cli(["rf", "--help"])
    assert help_res.returncode == 0, f"rf --help failed: {help_res.stderr}"

    mock_rf_server.queue_fault(
        "/list/report:brand-image-default/entities",
        403,
        body={"message": "Missing Data permissions", "status_code": 403, "trace_id": "tr-cli-403"},
    )
    cli_res = run_cli(["watchlist", "entities", "report:brand-image-default", "--json"])
    assert cli_res.returncode != 0
    combined = f"{cli_res.stdout}\n{cli_res.stderr}"
    assert "tr-cli-403" in combined
    assert "missing data permissions" in combined.lower()

    entries = _read_jsonl(e2e_workspace / "logs" / "rf_api_errors.jsonl")
    logged_traces = {entry.get("trace_id") for entry in entries}
    assert {"tr-403-mod", "tr-403-data", "tr-cli-403"}.issubset(logged_traces)


# ==============================================================================
# Area 3: Brand Logo Extraction <-> Hashing/ignored_hashes <-> RF Lists Delta Sync
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F4")
@pytest.mark.feature("F7")
@pytest.mark.feature("F8")
@pytest.mark.feature("F9")
def test_t3_a03_alpha_multi_source_extraction_and_delta_sync_lifecycle(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.logos.brand_sync import calculate_brand_sync_delta, execute_domain_brand_sync
    from soclens.logos.extractor import ExtractorConfig, extract_domain_logos

    alpha_host = brand_http_server.site_url("brand-alpha.local").removeprefix("http://")
    alpha_profile = build_default_brand_sites()["brand-alpha.local"]
    cfg = ExtractorConfig(max_retries=0, backoff_base=0.01)

    res = extract_domain_logos(alpha_host, config=cfg)
    assert res.domain_error is None
    assert res.image_errors == []
    extracted_urls = {logo.image_url for logo in res.logos}
    extracted_hashes = {logo.sha256 for logo in res.logos}

    # Verify multi-source discovery (JSON-LD, icons, manifest, srcset w/ commas, data-src, data:, inline SVG, og:image)
    for required_suffix in (
        "/portal/assets/jsonld-logo.png",
        "/assets/jsonld-obj-logo.png",
        "/assets/jsonld-str-logo.png",
        "/icons/favicon-180x180.png",
        "/icons/pinned-tab.svg",
        "/icons/manifest-512x512.png",
        "/icons/mstile-144x144.png",
        "/images/alpha-og-logo.png",
        "/images/site-logo.png",
        "/cdn-cgi/image/w=200,fit=contain/pic-logo-1x.png",
        "/cdn-cgi/image/w=400,fit=contain/pic-logo-2x.png",
        "/images/pic-fallback.png",
        "/images/lazy-logo.webp",
        "/favicon.ico",
    ):
        assert any(u.endswith(required_suffix) for u in extracted_urls), f"Missing {required_suffix}"
    assert any(u.startswith("data:image/png;base64,") for u in extracted_urls)
    inline_svgs = [logo for logo in res.logos if logo.image_url.startswith("inline-svg://")]
    assert len(inline_svgs) == 1
    assert inline_svgs[0].image_info is not None
    assert inline_svgs[0].image_info.format == "SVG"
    assert len(inline_svgs[0].sha256) == 64
    assert alpha_profile.expected_logo_hashes["data_uri_logo"] in extracted_hashes

    # Create brand list and run initial delta sync
    client = RecordedFutureClient()
    created = client.create_list("Alpha Brand Logos", "brand")
    list_id = str(created["id"])
    disc_file = e2e_workspace / "alpha_discovered.json"

    ok = execute_domain_brand_sync(
        client,
        list_id,
        [alpha_host],
        dry_run=False,
        output_locations_file=disc_file,
        image_hasher=_fast_domain_hasher,
    )
    assert ok is True
    assert disc_file.is_file()

    entities = client.get_watchlist_entities(list_id)
    assert len(entities) == len(extracted_hashes)
    for ent in entities:
        assert ent["entity"]["type"] == "Hash"
        assert "Brand image for" in ent["context"]["annotation"]

    # Second run must be idempotent (unchanged)
    _, _, to_add, to_remove, dom_err, img_err = calculate_brand_sync_delta(
        client,
        list_id,
        [alpha_host],
        output_locations_file=None,
        image_hasher=_fast_domain_hasher,
    )
    assert to_add == []
    assert to_remove == []
    assert dom_err == {}
    assert img_err == {}

    # Verify add_entity updated / unchanged / removed result statuses directly
    sample_hash = next(iter(extracted_hashes))
    unchanged_res = client.add_entity(
        list_id,
        "Hash",
        sample_hash,
        context=next(e["context"] for e in entities if e["entity"]["name"] == sample_hash),
    )
    assert unchanged_res["result"] == "unchanged"
    updated_res = client.add_entity(
        list_id,
        "Hash",
        sample_hash,
        context={"annotation": "Updated annotation", "source": "automated-watchlist-manager", "domain": alpha_host},
    )
    assert updated_res["result"] == "updated"

    # Mutate site logo via BrandHTTPServer.set_route -> triggers add + remove delta
    new_logo = make_png(240, 72, (200, 30, 90, 255))
    new_hash = sha256_hex(new_logo)
    old_hash = alpha_profile.expected_logo_hashes["/images/site-logo.png"]
    brand_http_server.set_route(
        "brand-alpha.local",
        "/images/site-logo.png",
        RouteSpec(status=200, content_type="image/png", body=new_logo),
    )

    ok_rot = execute_domain_brand_sync(
        client,
        list_id,
        [alpha_host],
        dry_run=False,
        output_locations_file=None,
        image_hasher=_fast_domain_hasher,
    )
    assert ok_rot is True
    after_names = {e["entity"]["name"] for e in client.get_watchlist_entities(list_id)}
    assert new_hash in after_names
    assert old_hash not in after_names


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F4")
@pytest.mark.feature("F7")
@pytest.mark.feature("F8")
@pytest.mark.feature("F9")
def test_t3_a03_beta_decoy_and_widget_exclusion_during_sync(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.logos.brand_sync import execute_domain_brand_sync

    beta_host = brand_http_server.site_url("brand-beta.local").removeprefix("http://")
    beta_profile = build_default_brand_sites()["brand-beta.local"]
    client = RecordedFutureClient()
    list_id = str(client.create_list("Beta Brand Logos", "brand")["id"])

    disc_file = e2e_workspace / "beta_discovered.json"
    ok = execute_domain_brand_sync(
        client,
        list_id,
        [beta_host],
        dry_run=False,
        output_locations_file=disc_file,
        image_hasher=_fast_domain_hasher,
    )
    assert ok is True

    entities = client.get_watchlist_entities(list_id)
    synced_hashes = {e["entity"]["name"] for e in entities}
    expected_hashes = set(beta_profile.expected_logo_hashes.values())
    assert synced_hashes == expected_hashes, (
        f"Unexpected or missing hashes synced from brand-beta.local: "
        f"extra={synced_hashes - expected_hashes}, missing={expected_hashes - synced_hashes}"
    )

    disc_entries = json.loads(disc_file.read_text(encoding="utf-8"))
    included_urls = [d["url"] for d in disc_entries if d.get("status") == "included"]
    for decoy_path in beta_profile.expected_decoy_paths:
        assert not any(u.endswith(decoy_path) for u in included_urls), f"Decoy leaked: {decoy_path}"


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F4")
@pytest.mark.feature("F8")
@pytest.mark.feature("F9")
def test_t3_a03_ignored_hashes_cross_algorithm_removal(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.logos.brand_sync import execute_domain_brand_sync

    flaky_host = brand_http_server.site_url("brand-flaky.local").removeprefix("http://")
    flaky_profile = build_default_brand_sites()["brand-flaky.local"]
    logo_bytes = flaky_profile.routes["/images/flaky-logo.png"].body
    logo_sha256 = sha256_hex(logo_bytes)
    logo_md5 = md5_hex(logo_bytes)
    favicon_sha256 = flaky_profile.expected_logo_hashes["/favicon.ico"]

    mock_rf_server.seed_list(
        "Ignored Tuning List",
        "brand",
        list_id="report:brand-ignore-test",
        entities=[
            {
                "type": "Hash",
                "name": logo_sha256,
                "context": {
                    "annotation": f"Automated sync: Brand image for {flaky_host}",
                    "source": "automated-watchlist-manager",
                    "domain": flaky_host,
                    "domains": [flaky_host],
                },
            }
        ],
    )

    ignored_file = e2e_workspace / "ignored_hashes.txt"
    ignored_file.write_text(f"{logo_md5} # tune out flaky logo via MD5\n", encoding="utf-8")

    client = RecordedFutureClient()
    ok = execute_domain_brand_sync(
        client,
        "report:brand-ignore-test",
        [flaky_host],
        dry_run=False,
        output_locations_file=None,
        ignore_hashes_file=ignored_file,
        image_hasher=_fast_domain_hasher,
    )
    assert ok is True

    final_names = {e["entity"]["name"] for e in client.get_watchlist_entities("report:brand-ignore-test")}
    assert logo_sha256 not in final_names
    assert favicon_sha256 in final_names


# ==============================================================================
# Area 4: Brand Logo Sync (--domains subset / failure) <-> Continuous State & Watch
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F9")
@pytest.mark.feature("F10")
def test_t3_a04_scoped_domains_subset_and_load_domains_file_bom_edge(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.logos.brand_sync import execute_domain_brand_sync
    from soclens.logos.extractor import load_domains_file

    domains_csv = e2e_workspace / "domains.csv"
    domains_csv.write_text(
        "\ufeff# Header comments should be skipped\n"
        "// C-style comment\n"
        "domain,notes\n"
        "domainbank.com,must not be filtered as header\n"
        "https://portal.example.org/login,strip scheme and path\n",
        encoding="utf-8",
    )
    loaded = load_domains_file(domains_csv)
    assert loaded == ["domainbank.com", "portal.example.org"]

    gamma_host = brand_http_server.site_url("brand-gamma.local").removeprefix("http://")
    other_domain = "other-subsidiary.example"
    other_hash = "e" * 64

    mock_rf_server.seed_list(
        "Scoped Brand List",
        "brand",
        list_id="report:brand-scoped",
        entities=[
            {
                "type": "Hash",
                "name": other_hash,
                "context": {
                    "annotation": f"Automated sync: Brand image for {other_domain}",
                    "source": "automated-watchlist-manager",
                    "domain": other_domain,
                    "domains": [other_domain],
                },
            }
        ],
    )

    client = RecordedFutureClient()
    ok = execute_domain_brand_sync(
        client,
        "report:brand-scoped",
        [gamma_host],
        dry_run=False,
        output_locations_file=None,
        scoped_domains={gamma_host},
        image_hasher=_fast_domain_hasher,
    )
    assert ok is True

    final_names = {e["entity"]["name"] for e in client.get_watchlist_entities("report:brand-scoped")}
    assert other_hash in final_names


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F9")
@pytest.mark.feature("F10")
def test_t3_a04_continuous_watch_max_runs_state_and_lock_cleanup(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.logos.brand_sync import (
        SyncLock,
        SyncLockError,
        load_brand_sync_state,
        run_continuous_brand_sync,
    )

    gamma_host = brand_http_server.site_url("brand-gamma.local").removeprefix("http://")
    state_file = e2e_workspace / "brand_sync_state.json"
    lock_file = e2e_workspace / ".brand_sync.lock"

    # Verify concurrent lock contention raises SyncLockError
    with SyncLock(lock_file):
        assert lock_file.is_file()
        with pytest.raises(SyncLockError):
            SyncLock(lock_file).acquire()
    assert not lock_file.exists()

    client = RecordedFutureClient()
    summary = run_continuous_brand_sync(
        client,
        "report:brand-image-default",
        domains=[gamma_host],
        output_locations_file=None,
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

    persisted = load_brand_sync_state(state_file)
    assert persisted["runs_completed"] == 2
    assert persisted["domains"][gamma_host]["consecutive_failures"] == 0
    assert len(persisted["domains"][gamma_host]["hashes"]) == 4


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F9")
@pytest.mark.feature("F10")
@pytest.mark.feature("F14")
def test_t3_a04_cli_watch_flag_and_grace_period_preservation(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.logos.brand_sync import execute_domain_brand_sync, load_brand_sync_state

    flaky_host = brand_http_server.site_url("brand-flaky.local").removeprefix("http://")
    flaky_profile = build_default_brand_sites()["brand-flaky.local"]
    flaky_hash = flaky_profile.expected_logo_hashes["/images/flaky-logo.png"]
    gamma_host = brand_http_server.site_url("brand-gamma.local").removeprefix("http://")
    state_file = e2e_workspace / "grace_state.json"

    client = RecordedFutureClient()
    assert execute_domain_brand_sync(
        client,
        "report:brand-image-default",
        [gamma_host, flaky_host],
        output_locations_file=None,
        state_file=state_file,
        image_hasher=_fast_domain_hasher,
    )

    # Inject persistent 503 on brand-flaky.local -> preserved for failures 1 & 2 (< grace=3)
    brand_http_server.set_fault("brand-flaky.local", "/", 503, body=b"Service Unavailable")
    execute_domain_brand_sync(
        client,
        "report:brand-image-default",
        [gamma_host, flaky_host],
        output_locations_file=None,
        state_grace_failures=3,
        state_file=state_file,
        image_hasher=_fast_domain_hasher,
    )
    state_after_1 = load_brand_sync_state(state_file)
    assert state_after_1["domains"][flaky_host]["consecutive_failures"] == 1
    assert flaky_hash in {
        e["entity"]["name"] for e in client.get_watchlist_entities("report:brand-image-default")
    }

    # Verify M4 CLI --watch --max-runs on watchlist sync-logos
    brand_http_server.clear_faults()
    cli_res = run_cli(
        [
            "watchlist",
            "sync-logos",
            "report:brand-image-default",
            "--domains",
            gamma_host,
            "--watch",
            "--max-runs",
            "2",
            "--interval",
            "0.02",
            "--output-locations",
            str(e2e_workspace / "cli_disc.json"),
        ],
        env={"SOCLENS_AUTO_APPROVE": "true"},
        timeout=30.0,
    )
    assert cli_res.returncode == 0, f"stderr={cli_res.stderr}\nstdout={cli_res.stdout}"


# ==============================================================================
# Area 5: Detection Rules (updated.after / result) <-> Sigma Cache <-> Splunk SPL
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F5")
@pytest.mark.feature("F11")
def test_t3_a05_detection_rules_pagination_cache_and_splunk_export(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.sigma import export_rules_to_splunk, load_rules

    client = RecordedFutureClient()
    paginated = client.search_detection_rules(days=3650, rule_types=["sigma"], limit=1)
    assert len(paginated) == 2

    det_reqs = [r for r in mock_rf_server.requests_log if r["path"] == "/detection-rule/search"]
    assert len(det_reqs) == 2
    assert "after" in det_reqs[0]["body_json"]["filter"]["updated"]
    assert det_reqs[1]["body_json"]["offset"] == "1"

    rules = load_rules(client, refresh=True, cache_dir=e2e_workspace)
    assert (e2e_workspace / "sigma_rules_cache.json").is_file()
    sigma_rules = [r for r in rules if r.get("content")]
    assert len(sigma_rules) >= 2

    out_path = e2e_workspace / "conf" / "savedsearches.conf"
    export_rules_to_splunk(sigma_rules, output_path=out_path)
    win_conf = e2e_workspace / "conf" / "savedsearches_wineventlog.conf"
    assert win_conf.is_file()
    conf_text = win_conf.read_text(encoding="utf-8")
    assert "alert.suppress.fields = host,User" in conf_text
    assert "| table _time host User CommandLine Image ParentCommandLine ParentImage" in conf_text
    assert "action.notable = 1" in conf_text


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F5")
@pytest.mark.feature("F11")
def test_t3_a05_sigma_cache_preserved_on_api_500_and_tstats_multiline_ini(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.sigma import convert_to_savedsearch_stanza, load_rules

    sentinel_rules: list[dict[str, Any]] = [
        {
            "rule_id": "doc:cached-1",
            "rule_set_title": "Cached Sentinel",
            "file_name": "cached.yml",
            "title": "Cached Sentinel Rule",
            "description": "Preserved across RF outage",
            "content": (
                "title: Cached Sentinel Rule\n"
                "logsource:\n  product: windows\n"
                "detection:\n  sel:\n    CommandLine|contains: whoami\n  condition: sel\n"
            ),
            "product": "windows",
            "category": None,
            "service": None,
            "index": "*wineventlog",
            "mitre_techniques": [],
        }
    ]
    cache_file = e2e_workspace / "sigma_rules_cache.json"
    cache_bytes = json.dumps(sentinel_rules, indent=2).encode("utf-8")
    cache_file.write_bytes(cache_bytes)

    mock_rf_server.set_fault("/detection-rule/search", 500, body={"message": "Internal Error"})
    client = RecordedFutureClient(api_token="test-rf-token")
    loaded = load_rules(client, refresh=True, cache_dir=e2e_workspace)
    assert len(loaded) == 1
    assert loaded[0]["rule_id"] == "doc:cached-1"
    assert cache_file.read_bytes() == cache_bytes

    stanza = convert_to_savedsearch_stanza(
        "doc:tstats-1",
        "Tstats Multiline Rule",
        "title: Tstats Multiline Rule\ndescription: |\n  Line one\n  Line two\nlevel: high\n",
        "| tstats count from datamodel=Endpoint.Processes by Processes.process_name",
    )
    desc_line = next(ln for ln in stanza.splitlines() if ln.startswith("description = "))
    search_line = next(ln for ln in stanza.splitlines() if ln.startswith("search = "))
    assert desc_line == "description = Line one Line two"
    assert search_line.startswith("search = | tstats count from datamodel=Endpoint.Processes")


# ==============================================================================
# Area 6: Sigma savedsearches.conf Export <-> SplunkValidator
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F11")
@pytest.mark.feature("F12")
def test_t3_a06_sigma_export_parsed_and_validated_in_es_context(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    mock_splunk_server: MockSplunkServer,
) -> None:
    from soclens.client import RecordedFutureClient
    from soclens.sigma import export_rules_to_splunk, load_rules
    from soclens.splunk import SplunkValidator, parse_savedsearches_files

    client = RecordedFutureClient()
    rules = load_rules(client, refresh=True, cache_dir=e2e_workspace)
    export_base = e2e_workspace / "splunk_export" / "savedsearches.conf"
    export_rules_to_splunk(rules, output_path=export_base)

    parsed = parse_savedsearches_files(str(e2e_workspace / "splunk_export" / "*.conf"))
    assert len(parsed) >= 2

    with SplunkValidator(poll_interval=0.05) as validator:
        assert validator.app == "SplunkEnterpriseSecuritySuite"
        assert validator.check_connection() is True
        res = validator.run_single_search(parsed[0], earliest="-7d", latest="now", timeout=10)
        assert res["status"] == "success"
        assert res["trigger_count"] == 1

    job_posts = [
        r
        for r in mock_splunk_server.requests_log
        if r["method"] == "POST"
        and r["path"] == "/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs"
    ]
    assert len(job_posts) == 1


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F11")
@pytest.mark.feature("F12")
def test_t3_a06_splunk_validator_cancel_url_and_none_stanza_guard(
    e2e_workspace: Path,
    mock_splunk_server: MockSplunkServer,
) -> None:
    from soclens.splunk import SplunkValidator, parse_savedsearches_files

    conf_file = e2e_workspace / "edge_savedsearches.conf"
    conf_file.write_text(
        "[Broken Stanza Without Value]\n"
        "search\n"
        "description = Should be skipped safely\n\n"
        "[Valid Tstats Stanza]\n"
        "search = | tstats count from datamodel=Network_Traffic \\\n"
        "  by All_Traffic.dest_ip\n"
        "description = Valid multi-line search\n",
        encoding="utf-8-sig",
    )

    parsed = parse_savedsearches_files(conf_file)
    assert len(parsed) == 1
    assert parsed[0]["stanza"] == "Valid Tstats Stanza"
    assert parsed[0]["search"].startswith("| tstats count")

    mock_splunk_server.set_job_behavior("stuck_queued")
    with SplunkValidator(poll_interval=0.05, max_retries=0) as validator:
        res = validator.run_single_search(parsed[0], earliest="-1h", latest="now", timeout=1)

    assert res["status"] == "failed"
    assert "timed out" in str(res["error_message"]).lower()

    cancel_reqs = [
        r
        for r in mock_splunk_server.requests_log
        if r["method"] == "POST" and r["path"].endswith("/control")
    ]
    assert len(cancel_reqs) == 1
    assert cancel_reqs[0]["query"].get("output_mode") == ["json"]
    assert cancel_reqs[0]["form"].get("action") == ["cancel"]


# ==============================================================================
# Area 7: Bundler (soclens bundle) <-> Config/Templates/Ignored Hashes <-> Offline Import
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F2")
@pytest.mark.feature("F13")
@pytest.mark.feature("F14")
def test_t3_a07_cli_bundle_creates_airgap_zip_and_offline_import(
    e2e_workspace: Path,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    ws = _copy_minimal_bundle_workspace(e2e_workspace / "bundle_ws")
    (ws / "apikey.key").write_text("SECRET-DO-NOT-BUNDLE", encoding="utf-8")
    (ws / "logs").mkdir(exist_ok=True)
    (ws / "logs" / "debug.log").write_text("secret log line", encoding="utf-8")
    (ws / "ignored_hashes.txt").write_text(f"{'a' * 64} # bundle test\n", encoding="utf-8")

    out_zip = e2e_workspace / "dist" / "soc_bundle.zip"
    res = run_cli(
        ["bundle", "--output", str(out_zip), "--json"],
        env={"SOCLENS_HOME": str(ws)},
        cwd=ws,
    )
    assert res.returncode == 0, f"stderr={res.stderr}\nstdout={res.stdout}"
    cli_json = json.loads(res.stdout)
    assert Path(cli_json.get("output_path", out_zip)).is_file()
    assert out_zip.is_file()

    with zipfile.ZipFile(out_zip, "r") as zf:
        names = set(zf.namelist())
        assert "BUNDLE_MANIFEST.json" in names
        assert "ignored_hashes.txt" in names
        assert "soclens/__init__.py" in names
        assert "apikey.key" not in names
        assert not any(n.endswith(".log") or "__pycache__" in n or ".." in n for n in names)
        manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
        assert manifest["schema_version"] == 1
        assert manifest["file_count"] == len(names)

    extract_dir = e2e_workspace / "airgap_extracted"
    with zipfile.ZipFile(out_zip, "r") as zf:
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
                "import soclens.config, soclens.client, soclens.logos, soclens.sigma, soclens.splunk; "
                "assert soclens.config.get_workspace_dir().resolve() == ext"
            ),
        ],
        cwd=extract_dir,
        env=offline_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"Offline import failed: {proc.stderr}\n{proc.stdout}"


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F2")
@pytest.mark.feature("F13")
@pytest.mark.feature("F14")
def test_t3_a07_bundle_pure_platform_and_offline_wheelhouse_error(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    run_cli: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    import importlib.util
    import shutil

    from soclens.bundler import create_bundle

    ws = _copy_minimal_bundle_workspace(e2e_workspace / "pure_ws")
    pure_zip = e2e_workspace / "dist" / "pure_bundle.zip"

    res = run_cli(
        ["bundle", "--target-platform", "pure", "--output", str(pure_zip), "--json"],
        env={"SOCLENS_HOME": str(ws)},
        cwd=ws,
    )
    assert res.returncode == 0, f"stderr={res.stderr}\nstdout={res.stdout}"
    with zipfile.ZipFile(pure_zip, "r") as zf:
        names = zf.namelist()
        assert not any(n.lower().endswith((".so", ".pyd", ".dll", ".dylib")) for n in names)
        manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
        assert manifest["target_platform"] == "pure"

    # Offline wheelhouse without pip or uv must raise RuntimeError cleanly
    orig_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *args, **kwargs: None if name == "pip" else orig_find_spec(name, *args, **kwargs),
    )
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)
    with pytest.raises(RuntimeError, match="pip|uv"):
        create_bundle(ws, output_path=e2e_workspace / "dist" / "wh.zip", wheelhouse=True)


# ==============================================================================
# Area 8: TUI (Pilot w/ importorskip) <-> Watchlists / Brand Sync / Sigma / Splunk / Bundle
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F15")
@pytest.mark.feature("F4")
@pytest.mark.feature("F9")
@pytest.mark.feature("F11")
@pytest.mark.feature("F12")
@pytest.mark.feature("F13")
def test_t3_a08_tui_mounts_all_workflow_tabs_with_pilot(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    mock_splunk_server: MockSplunkServer,
) -> None:
    pytest.importorskip("textual")
    app = _resolve_tui_app(dry_run=True)

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.is_running
            screen = app.screen
            rendered = " ".join(
                str(getattr(w, "label", "") or getattr(w, "renderable", ""))
                for w in screen.query("*")
            )
            assert rendered.strip() != ""
            tab_labels = " ".join(
                str(getattr(t, "label", "")) for t in screen.query("Tab, TabPane, Button, Static")
            ).lower()
            for keyword in ("watchlist", "brand", "sigma", "splunk"):
                assert keyword in tab_labels, (
                    f"Missing '{keyword}' workflow surface in TUI: {tab_labels}"
                )

    asyncio.run(_run())


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F15")
@pytest.mark.feature("F2")
@pytest.mark.feature("F3")
def test_t3_a08_tui_navigation_and_missing_creds_error_boundary(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("textual")
    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)

    app = _resolve_tui_app(dry_run=True)

    async def _run() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.is_running
            for key in ("tab", "right", "tab", "escape"):
                await pilot.press(key)
            await pilot.pause()
            assert app.is_running

    asyncio.run(_run())


# ==============================================================================
# Area 9: Playbook Alerts (domain_abuse/malicious_sites logo hashes) <-> Brand Watchlist
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F4")
@pytest.mark.feature("F6")
@pytest.mark.feature("F9")
def test_t3_a09_playbook_alert_logo_hash_match_and_png_retrieval(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    pb1_hash = "b" * 64
    pb2_hash = "c" * 64
    client.add_entity("report:brand-image-default", "Hash", pb1_hash, context={"annotation": "Alpha primary logo"})
    client.add_entity("report:brand-image-default", "Hash", pb2_hash, context={"annotation": "Alpha secondary logo"})

    watched_ids = {
        e["entity"]["id"] for e in client.get_watchlist_entities("report:brand-image-default")
    }
    assert f"hash:{pb1_hash}" in watched_ids
    assert f"hash:{pb2_hash}" in watched_ids

    search_res = client.search_playbook_alerts(categories=["domain_abuse", "malicious_sites"])
    alert_ids = {item["playbook_alert_id"] for item in search_res["data"]}
    assert {"pb-1", "pb-2"}.issubset(alert_ids)

    pb1_detail = client.get_playbook_alert("domain_abuse", "pb-1")["data"]
    asset_hashes = {
        a["hash_id"]
        for a in pb1_detail["panel_evidence_summary"]["assets"]
        if a.get("hash_id")
    }
    assert f"hash:{pb1_hash}" in asset_hashes

    pb2_detail = client.get_playbook_alert("malicious_sites", "pb-2")["data"]
    assert f"hash:{pb2_hash}" in pb2_detail["panel_evidence_summary"]["hashes"]

    png_bytes = client.get_playbook_alert_image("domain_abuse", "pb-1", "screenshot-1")
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")

    updated = client.update_playbook_alert("pb-1", status="InProgress", priority="High")
    assert updated["data"]["status"] == "InProgress"


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F4")
@pytest.mark.feature("F6")
@pytest.mark.feature("F9")
def test_t3_a09_playbook_alert_category_mismatch_and_brand_orphan_detection(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient
    from soclens.logos.brand_sync import validate_domain_brand_sync

    client = RecordedFutureClient()
    with pytest.raises(RecordedFutureAPIError) as exc_info:
        client.get_playbook_alert("malicious_sites", "pb-1")
    assert exc_info.value.status_code == 404

    # Seed watchlist with pb-1's hash not present on brand-gamma.local -> validation reports cleanly
    client.add_entity("report:brand-image-default", "Hash", "b" * 64)
    gamma_host = brand_http_server.site_url("brand-gamma.local").removeprefix("http://")
    assert (
        validate_domain_brand_sync(
            client,
            "report:brand-image-default",
            [gamma_host],
            output_locations_file=None,
            image_hasher=_fast_domain_hasher,
        )
        is True
    )


# ==============================================================================
# Area 10: Entity Match <-> Watchlist Non-Auto-Resolvable Types (Company/Organization)
# ==============================================================================


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F4")
@pytest.mark.feature("F6")
def test_t3_a10_entity_match_resolve_company_add_and_replace_tags(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureClient

    client = RecordedFutureClient()
    matches = client.entity_match("Acme Financial", types=["Company"])
    assert len(matches) == 1
    assert matches[0]["id"] == "company:abc123"

    comp_list = client.create_list("Monitored Peers", "company")
    list_id = str(comp_list["id"])

    add_res = client.add_entity(list_id, "Company", "Acme Financial", resolve=True)
    assert add_res["result"] == "added"

    tag_res = client.replace_entity_tags(list_id, "company:abc123", ["tier1", "banking"])
    assert tag_res["operation"]["status"] == "tags_updated"

    tagged = client.get_entities_with_tags(list_id)
    assert len(tagged) == 1
    assert tagged[0]["entity"]["id"] == "company:abc123"
    assert [t["name"] for t in tagged[0]["tags"]] == ["tier1", "banking"]


@pytest.mark.e2e
@pytest.mark.tier3
@pytest.mark.feature("F4")
@pytest.mark.feature("F6")
def test_t3_a10_non_auto_resolvable_entity_and_tag_limit_validation(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
) -> None:
    from soclens.client import RecordedFutureAPIError, RecordedFutureClient

    client = RecordedFutureClient()
    comp_list = client.create_list("Company Tag Bounds", "company")
    list_id = str(comp_list["id"])

    # Unresolvable Organization fails cleanly with 404 from entity_match resolution
    with pytest.raises(RecordedFutureAPIError) as exc_info:
        client.add_entity(list_id, "Organization", "Nonexistent Shadow Corp", resolve=True)
    assert exc_info.value.status_code == 404

    # Adding >9 tags violates RF's 9-tag limit
    client.add_entity(list_id, "Company", "company:abc123", is_id=True)
    with pytest.raises(ValueError, match="9"):
        client.replace_entity_tags(list_id, "company:abc123", [f"tag{i}" for i in range(10)])

    # Invalid list type also rejected cleanly by server/client
    with pytest.raises((ValueError, RecordedFutureAPIError)):
        client.create_list("Bad Type List", "nonexistent_list_type")
