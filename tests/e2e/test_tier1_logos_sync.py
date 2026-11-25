"""Tier 1 E2E core contract tests for brand logo extraction, validation, sync, automation, and isolation."""

from __future__ import annotations

import importlib
import json
import os
import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from soclens.client import RecordedFutureClient
from tests.e2e.conftest import BrandHTTPServer, MockRFServer
from tests.e2e.fixtures.assets import (
    make_gif,
    make_ico,
    make_jpeg,
    make_non_image_pdf,
    make_png,
    make_svg,
    make_webp,
    md5_hex,
    sha1_hex,
    sha256_hex,
)
from tests.e2e.fixtures.brand_sites import RouteSpec, build_default_brand_sites, make_brand_site

pytestmark = [pytest.mark.e2e, pytest.mark.tier1]

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_attr(module_path: str, attr_name: str) -> Any:
    module = importlib.import_module(module_path)
    return getattr(module, attr_name)


def _load_watchlist() -> Any:
    return importlib.import_module("soclens.watchlist")


def _site_host(brand_http_server: BrandHTTPServer, domain: str) -> str:
    return brand_http_server.site_url(domain).removeprefix("http://")


def _snapshot_repo_root_artifacts() -> tuple[bytes | None, bytes | None, bytes | None]:
    disc_path = _REPO_ROOT / "discovered_images.json"
    sigma_path = _REPO_ROOT / "sigma_rules_cache.json"
    ignored_path = _REPO_ROOT / "ignored_hashes.txt"
    return (
        disc_path.read_bytes() if disc_path.exists() else None,
        sigma_path.read_bytes() if sigma_path.exists() else None,
        ignored_path.read_bytes() if ignored_path.exists() else None,
    )


def _assert_repo_root_artifacts_unchanged(
    snapshot: tuple[bytes | None, bytes | None, bytes | None],
) -> None:
    disc_before, sigma_before, ignored_before = snapshot
    disc_path = _REPO_ROOT / "discovered_images.json"
    sigma_path = _REPO_ROOT / "sigma_rules_cache.json"
    ignored_path = _REPO_ROOT / "ignored_hashes.txt"

    if disc_before is None:
        assert not disc_path.exists()
    else:
        assert disc_path.read_bytes() == disc_before

    if sigma_before is None:
        assert not sigma_path.exists()
    else:
        assert sigma_path.read_bytes() == sigma_before

    if ignored_before is None:
        assert not ignored_path.exists()
    else:
        assert ignored_path.read_bytes() == ignored_before


# ---------------------------------------------------------------------------
# F7: Multi-Source Logo Extraction (6 tests)
# ---------------------------------------------------------------------------


@pytest.mark.feature("F7")
def test_t1_f7_jsonld_logo_extraction(brand_http_server: BrandHTTPServer) -> None:
    sites = build_default_brand_sites()
    alpha_expected = sites["brand-alpha.local"].expected_logo_hashes
    alpha_host = _site_host(brand_http_server, "brand-alpha.local")

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _queried, domain_err, _img_errs, locations = get_domain_image_hash(
        alpha_host, ignored_hashes={}
    )

    assert domain_err is None
    extracted_sha256 = {item["sha256"] for item in hashes}
    assert alpha_expected["/portal/assets/jsonld-logo.png"] in extracted_sha256
    assert alpha_expected["/assets/jsonld-obj-logo.png"] in extracted_sha256
    assert alpha_expected["/assets/jsonld-str-logo.png"] in extracted_sha256

    jsonld_locs = [
        loc
        for loc in locations
        if loc.get("status") == "included" and "json-ld" in str(loc.get("source", "")).lower()
    ]
    assert len(jsonld_locs) >= 3


@pytest.mark.feature("F7")
def test_t1_f7_icons_mask_tile_and_manifest(brand_http_server: BrandHTTPServer) -> None:
    sites = build_default_brand_sites()
    alpha_expected = sites["brand-alpha.local"].expected_logo_hashes
    alpha_host = _site_host(brand_http_server, "brand-alpha.local")

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _queried, domain_err, _img_errs, _locations = get_domain_image_hash(
        alpha_host, ignored_hashes={}
    )

    assert domain_err is None
    extracted_sha256 = {item["sha256"] for item in hashes}
    # Stem deduplication keeps 180x180 over 32x32 for favicon.png
    assert alpha_expected["/icons/favicon-180x180.png"] in extracted_sha256
    assert alpha_expected["/icons/pinned-tab.svg"] in extracted_sha256
    assert alpha_expected["/icons/mstile-144x144.png"] in extracted_sha256
    assert alpha_expected["/icons/manifest-512x512.png"] in extracted_sha256


@pytest.mark.feature("F7")
def test_t1_f7_picture_comma_srcset_and_data_src(brand_http_server: BrandHTTPServer) -> None:
    sites = build_default_brand_sites()
    alpha_expected = sites["brand-alpha.local"].expected_logo_hashes
    alpha_host = _site_host(brand_http_server, "brand-alpha.local")

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _queried, domain_err, _img_errs, _locations = get_domain_image_hash(
        alpha_host, ignored_hashes={}
    )

    assert domain_err is None
    extracted_sha256 = {item["sha256"] for item in hashes}
    assert alpha_expected["/cdn-cgi/image/w=200,fit=contain/pic-logo-1x.png"] in extracted_sha256
    assert alpha_expected["/cdn-cgi/image/w=400,fit=contain/pic-logo-2x.png"] in extracted_sha256
    assert alpha_expected["/images/pic-fallback.png"] in extracted_sha256
    assert alpha_expected["/images/lazy-logo.webp"] in extracted_sha256


@pytest.mark.feature("F7")
def test_t1_f7_inline_svg_and_data_uri_decoding(brand_http_server: BrandHTTPServer) -> None:
    sites = build_default_brand_sites()
    alpha_expected = sites["brand-alpha.local"].expected_logo_hashes
    alpha_host = _site_host(brand_http_server, "brand-alpha.local")

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _queried, domain_err, img_errs, locations = get_domain_image_hash(
        alpha_host, ignored_hashes={}
    )

    assert domain_err is None
    extracted_sha256 = {item["sha256"] for item in hashes}
    assert alpha_expected["data_uri_logo"] in extracted_sha256

    inline_svg_locs = [
        loc
        for loc in locations
        if loc.get("status") == "included"
        and str(loc.get("url", "")).startswith("inline-svg://")
    ]
    assert len(inline_svg_locs) == 1
    assert inline_svg_locs[0]["sha256"] in extracted_sha256

    failed_data_or_svg = [
        loc
        for loc in locations
        if loc.get("status") == "download_failed"
        and (str(loc.get("url", "")).startswith(("data:", "inline-svg:")))
    ]
    assert failed_data_or_svg == []
    assert not any("data:" in err or "inline-svg:" in err for err in img_errs)


@pytest.mark.feature("F7")
def test_t1_f7_redirect_base_href_and_gated_og_image(
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    alpha_expected = sites["brand-alpha.local"].expected_logo_hashes
    gamma_expected = sites["brand-gamma.local"].expected_logo_hashes

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")

    alpha_hashes, _q1, alpha_err, _ie1, _locs1 = get_domain_image_hash(
        _site_host(brand_http_server, "brand-alpha.local"), ignored_hashes={}
    )
    assert alpha_err is None
    alpha_sha256 = {item["sha256"] for item in alpha_hashes}
    # 302 / -> /portal/home + <base href="/portal/"> resolves "assets/jsonld-logo.png"
    assert alpha_expected["/portal/assets/jsonld-logo.png"] in alpha_sha256
    assert alpha_expected["/images/alpha-og-logo.png"] in alpha_sha256

    gamma_hashes, _q2, gamma_err, _ie2, _locs2 = get_domain_image_hash(
        _site_host(brand_http_server, "brand-gamma.local"), ignored_hashes={}
    )
    assert gamma_err is None
    gamma_sha256 = {item["sha256"] for item in gamma_hashes}
    assert gamma_expected["/images/gamma-og-logo.png"] in gamma_sha256


@pytest.mark.feature("F7")
def test_t1_f7_configurable_brand_overrides_no_hardcoded_domains(
    e2e_workspace: Path,
    brand_http_server: BrandHTTPServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hidden_crest = make_png(180, 64, (90, 20, 140, 255))
    regular_logo = make_png(200, 60, (20, 90, 140, 255))
    favicon = make_ico(32, 32, payload="png")

    html = (
        "<!DOCTYPE html><html><head><title>Override Brand</title></head>"
        '<body><header><img class="site-logo" src="/images/regular.png" alt="Logo"></header>'
        "</body></html>"
    )
    profile = make_brand_site(
        domain="override-brand.local",
        html=html,
        assets={
            "/images/regular.png": (regular_logo, "image/png"),
            "/hidden/brand-crest.png": (hidden_crest, "image/png"),
            "/favicon.ico": (favicon, "image/x-icon"),
        },
    )
    brand_http_server.add_site(profile)
    override_host = _site_host(brand_http_server, "override-brand.local")
    override_url = f"http://{override_host}/hidden/brand-crest.png"

    overrides_path = e2e_workspace / "logo_overrides.json"
    overrides_path.write_text(
        json.dumps({"force_urls": {override_host: [override_url]}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("RF_LOGO_OVERRIDES_FILE", str(overrides_path))

    extractor = importlib.import_module("soclens.logos.extractor")
    loaded_overrides = extractor.load_domain_overrides()
    cfg = extractor.ExtractorConfig.from_overrides(loaded_overrides)

    # Confirm configurable overrides only include configured domains (no hardcoded org domains)
    assert list(cfg.force_urls.keys()) == [override_host]
    thirdparty_excluded, _ = extractor.is_excluded_image(
        "https://www.thirdparty.example/wp-content/uploads/brand_logo.svg",
        "otherbank.local",
        alt="Facebook Social Badge",
        config=cfg,
    )
    assert thirdparty_excluded is True

    hashes, _queried, domain_err, _img_errs, _locs = extractor.get_domain_image_hash(
        override_host, ignored_hashes={}, config=cfg
    )
    assert domain_err is None
    extracted_sha256 = {item["sha256"] for item in hashes}
    assert sha256_hex(hidden_crest) in extracted_sha256
    assert sha256_hex(regular_logo) in extracted_sha256


# ---------------------------------------------------------------------------
# F8: Non-Logo Exclusion & Image Validation (6 tests)
# ---------------------------------------------------------------------------


@pytest.mark.feature("F8")
def test_t1_f8_excludes_promos_sliders_ui_icons_and_1x1_spacers(
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    beta_site = sites["brand-beta.local"]
    beta_host = _site_host(brand_http_server, "brand-beta.local")

    extractor = importlib.import_module("soclens.logos.extractor")
    hashes, _queried, domain_err, _img_errs, locations = extractor.get_domain_image_hash(
        beta_host, ignored_hashes={}
    )

    assert domain_err is None
    extracted_sha256 = {item["sha256"] for item in hashes}
    for decoy_path in (
        "/uploads/promo-banner.jpg",
        "/uploads/slider-hero.png",
        "/icons/icon-search.svg",
        "/pixel/spacer.png",
    ):
        decoy_hash = sha256_hex(beta_site.routes[decoy_path].body)
        assert decoy_hash not in extracted_sha256
        assert all(
            not (loc.get("status") == "included" and decoy_path in str(loc.get("url", "")))
            for loc in locations
        )
        excluded, reason = extractor.is_excluded_image(
            f"http://{beta_host}{decoy_path}", beta_host
        )
        assert excluded is True and reason

    for tracked_decoy in ("promo-banner.jpg", "spacer.png"):
        matched = [loc for loc in locations if tracked_decoy in str(loc.get("url", ""))]
        assert matched and all(loc.get("status") == "excluded" for loc in matched)


@pytest.mark.feature("F8")
def test_t1_f8_excludes_third_party_social_payment_compliance_badges(
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    beta_site = sites["brand-beta.local"]
    beta_host = _site_host(brand_http_server, "brand-beta.local")

    extractor = importlib.import_module("soclens.logos.extractor")
    hashes, _queried, domain_err, _img_errs, locations = extractor.get_domain_image_hash(
        beta_host, ignored_hashes={}
    )

    assert domain_err is None
    extracted_sha256 = {item["sha256"] for item in hashes}
    badge_hash = sha256_hex(beta_site.routes["/badges/visa-badge.png"].body)
    assert badge_hash not in extracted_sha256

    for badge_url in (
        "https://badges.thirdparty.invalid/visa-badge.png",
        "https://badges.thirdparty.invalid/facebook-badge.png",
        f"http://{beta_host}/badges/facebook-social.png",
        f"http://{beta_host}/badges/visa-badge.png",
        f"http://{beta_host}/badges/soc2-badge.png",
        f"http://{beta_host}/badges/fdic-member.png",
        f"http://{beta_host}/badges/equal-housing-lender.png",
    ):
        assert all(
            not (loc.get("status") == "included" and badge_url in str(loc.get("url", "")))
            for loc in locations
        )
        excluded, reason = extractor.is_excluded_image(badge_url, beta_host)
        assert excluded is True and reason, f"Expected {badge_url} to be excluded"


@pytest.mark.feature("F8")
def test_t1_f8_rejects_soft_404_html_and_non_image_pdf(
    brand_http_server: BrandHTTPServer,
) -> None:
    beta_host = _site_host(brand_http_server, "brand-beta.local")
    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")

    beta_hashes, _q1, beta_err, _ie1, beta_locs = get_domain_image_hash(
        beta_host, ignored_hashes={}
    )
    assert beta_err is None
    soft404_locs = [loc for loc in beta_locs if "soft404-logo.png" in str(loc.get("url", ""))]
    assert soft404_locs
    assert all(loc.get("status") != "included" for loc in soft404_locs)
    assert all("soft404-logo.png" not in h["image_url"] for h in beta_hashes)

    pdf_bytes = make_non_image_pdf()
    valid_logo = make_png(180, 60, (15, 75, 135, 255))
    favicon = make_ico(32, 32, payload="png")
    pdf_site = make_brand_site(
        domain="pdf-brand.local",
        html=(
            "<!DOCTYPE html><html><body><header>"
            '<img class="site-logo" src="/images/valid.png" alt="Logo">'
            '<img class="brand-logo" src="/images/fake-logo.png" alt="PDF Logo">'
            "</header></body></html>"
        ),
        assets={
            "/images/valid.png": (valid_logo, "image/png"),
            "/favicon.ico": (favicon, "image/x-icon"),
        },
        extra_routes={
            "/images/fake-logo.png": RouteSpec(
                status=200,
                content_type="application/pdf",
                body=pdf_bytes,
            )
        },
    )
    brand_http_server.add_site(pdf_site)
    pdf_hashes, _q2, pdf_err, _ie2, pdf_locs = get_domain_image_hash(
        _site_host(brand_http_server, "pdf-brand.local"), ignored_hashes={}
    )
    assert pdf_err is None
    pdf_sha = {item["sha256"] for item in pdf_hashes}
    assert sha256_hex(pdf_bytes) not in pdf_sha
    assert sha256_hex(valid_logo) in pdf_sha
    fake_locs = [loc for loc in pdf_locs if "fake-logo.png" in str(loc.get("url", ""))]
    assert fake_locs and all(loc.get("status") != "included" for loc in fake_locs)


@pytest.mark.feature("F8")
def test_t1_f8_accepts_all_valid_formats_and_dimensions(
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    gamma_expected = sites["brand-gamma.local"].expected_logo_hashes
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    gamma_hashes, _q1, gamma_err, _ie1, _locs1 = get_domain_image_hash(
        gamma_host, ignored_hashes={}
    )
    assert gamma_err is None
    gamma_sha = {item["sha256"] for item in gamma_hashes}
    assert gamma_expected["/images/gamma-og-logo.png"] in gamma_sha
    assert gamma_expected["/images/gamma-logo.gif"] in gamma_sha
    assert gamma_expected["/images/gamma-logo.jpg"] in gamma_sha
    assert gamma_expected["/favicon.ico"] in gamma_sha

    webp_vp8x = make_webp(160, 50, variant="VP8X")
    webp_vp8l = make_webp(180, 60, variant="VP8L")
    svg_logo = make_svg(200, 60, label="FormatBrand")
    gif87a = make_gif(140, 48, version=b"GIF87a")
    jpeg_logo = make_jpeg(210, 70)
    favicon = make_ico(32, 32, payload="png")

    formats_site = make_brand_site(
        domain="all-formats.local",
        html=(
            "<!DOCTYPE html><html><body><header>"
            '<img class="site-logo" src="/images/logo-vp8x.webp" alt="Logo 1">'
            '<img class="brand-logo" src="/images/logo-vp8l.webp" alt="Logo 2">'
            '<img class="site-logo" src="/images/logo.svg" alt="Logo 3">'
            '<img class="brand-logo" src="/images/logo87.gif" alt="Logo 4">'
            '<img class="site-logo" src="/images/logo.jpg" alt="Logo 5">'
            "</header></body></html>"
        ),
        assets={
            "/images/logo-vp8x.webp": (webp_vp8x, "image/webp"),
            "/images/logo-vp8l.webp": (webp_vp8l, "image/webp"),
            "/images/logo.svg": (svg_logo, "image/svg+xml"),
            "/images/logo87.gif": (gif87a, "image/gif"),
            "/images/logo.jpg": (jpeg_logo, "image/jpeg"),
            "/favicon.ico": (favicon, "image/x-icon"),
        },
    )
    brand_http_server.add_site(formats_site)
    fmt_hashes, _q2, fmt_err, _ie2, _locs2 = get_domain_image_hash(
        _site_host(brand_http_server, "all-formats.local"), ignored_hashes={}
    )
    assert fmt_err is None
    fmt_sha = {item["sha256"] for item in fmt_hashes}
    for asset_bytes in (webp_vp8x, webp_vp8l, svg_logo, gif87a, jpeg_logo, favicon):
        assert sha256_hex(asset_bytes) in fmt_sha


@pytest.mark.feature("F8")
def test_t1_f8_elementor_widget_and_no_sidebar_not_excluded(
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    beta_expected = sites["brand-beta.local"].expected_logo_hashes
    beta_site = sites["brand-beta.local"]
    beta_host = _site_host(brand_http_server, "brand-beta.local")

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _queried, domain_err, _img_errs, _locs = get_domain_image_hash(
        beta_host, ignored_hashes={}
    )

    assert domain_err is None
    extracted_sha256 = {item["sha256"] for item in hashes}
    assert extracted_sha256 == set(beta_expected.values())

    for container_decoy in (
        "/images/footer-logo.png",
        "/images/aside-logo.png",
        "/images/dialog-logo.png",
        "/images/modal-logo.png",
    ):
        assert sha256_hex(beta_site.routes[container_decoy].body) not in extracted_sha256


@pytest.mark.feature("F8")
def test_t1_f8_load_domains_file_and_posixpath_filename(e2e_workspace: Path) -> None:
    extractor = importlib.import_module("soclens.logos.extractor")

    domains_csv = e2e_workspace / "domains.csv"
    domains_csv.write_text(
        "domain,tier\nbrand-alpha.local,1\ndomainbank.com,1\nentitystudio.com,2\nbrand-beta.local,2\n",
        encoding="utf-8",
    )
    loaded = extractor.load_domains_file(domains_csv)
    assert loaded == [
        "brand-alpha.local",
        "domainbank.com",
        "entitystudio.com",
        "brand-beta.local",
    ]

    excluded_clean, _ = extractor.is_excluded_image(
        "https://mybank.local/assets/logo.png?v=1", "mybank.local"
    )
    assert excluded_clean is False

    excluded_backslash, reason = extractor.is_excluded_image(
        "https://mybank.local/assets\\visa-badge.png", "mybank.local"
    )
    assert excluded_backslash is True
    assert reason is not None


# ---------------------------------------------------------------------------
# F9: Hashing & Non-Destructive Brand Sync (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.feature("F9")
def test_t1_f9_submits_sha256_hash_and_rf_context_schema(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    gamma_expected = set(sites["brand-gamma.local"].expected_logo_hashes.values())
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Brand Image Test", "brand")
    lid = seeded["id"]

    watchlist = _load_watchlist()
    client = RecordedFutureClient()
    locs_file = e2e_workspace / "gamma_locs.json"

    ok = watchlist.execute_domain_brand_sync(
        client,
        lid,
        [gamma_host],
        dry_run=False,
        output_locations_file=locs_file,
    )
    assert ok is True
    assert locs_file.is_file()

    add_reqs = [
        req
        for req in mock_rf_server.requests_log
        if req["method"] == "POST" and req["path"] == f"/list/{lid}/entity/add"
    ]
    assert len(add_reqs) == len(gamma_expected)
    for req in add_reqs:
        body = req["body_json"]
        assert body["entity"]["type"] == "Hash"
        assert re.fullmatch(r"[0-9a-f]{64}", body["entity"]["name"])
        ctx = body["context"]
        assert ctx["source"] == "automated-watchlist-manager"
        assert ctx["domain"] == gamma_host
        assert gamma_host in ctx["annotation"]
        assert str(ctx["image_url"]).startswith("http")
        assert str(ctx["sync_time"]).endswith("Z")

    stored = client.get_watchlist_entities(lid)
    assert {e["entity"]["name"] for e in stored} == gamma_expected


@pytest.mark.feature("F9")
def test_t1_f9_ignored_hashes_filters_md5_sha1_sha256_and_purges_existing(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    gamma_routes = sites["brand-gamma.local"].routes
    gif_bytes = gamma_routes["/images/gamma-logo.gif"].body
    jpg_bytes = gamma_routes["/images/gamma-logo.jpg"].body
    og_bytes = gamma_routes["/images/gamma-og-logo.png"].body
    ico_bytes = gamma_routes["/favicon.ico"].body

    stale_noise_sha256 = "f" * 64
    seeded = mock_rf_server.seed_list(
        "Brand Tune Test",
        "brand",
        entities=[
            {
                "entity": {"id": f"hash:{stale_noise_sha256}", "type": "Hash", "name": stale_noise_sha256},
                "context": {"source": "automated-watchlist-manager", "domain": "old.local"},
            }
        ],
    )
    lid = seeded["id"]

    ignored_file = e2e_workspace / "ignored_hashes.txt"
    ignored_file.write_text(
        "\n".join(
            [
                f"{md5_hex(gif_bytes)} # gamma gif md5",
                f"{sha1_hex(jpg_bytes)} # gamma jpg sha1",
                f"{stale_noise_sha256} # stale noise sha256",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    watchlist = _load_watchlist()
    client = RecordedFutureClient()
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")

    ok = watchlist.execute_domain_brand_sync(
        client,
        lid,
        [gamma_host],
        dry_run=False,
        output_locations_file=None,
        ignore_hashes_file=ignored_file,
    )
    assert ok is True

    entities = client.get_watchlist_entities(lid)
    stored_hashes = {e["entity"]["name"] for e in entities}
    assert stale_noise_sha256 not in stored_hashes
    assert sha256_hex(gif_bytes) not in stored_hashes
    assert sha256_hex(jpg_bytes) not in stored_hashes
    assert sha256_hex(og_bytes) in stored_hashes
    assert sha256_hex(ico_bytes) in stored_hashes


@pytest.mark.feature("F9")
def test_t1_f9_idempotent_repeated_sync_no_duplicates(
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    expected_count = len(sites["brand-gamma.local"].expected_logo_hashes)
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Idempotent Brand", "brand")
    lid = seeded["id"]

    watchlist = _load_watchlist()
    client = RecordedFutureClient()

    assert watchlist.execute_domain_brand_sync(
        client, lid, [gamma_host], dry_run=False, output_locations_file=None
    )
    assert len(client.get_watchlist_entities(lid)) == expected_count

    mock_rf_server.requests_log.clear()
    _target, _existing, to_add, to_remove, _d_errs, _i_errs = watchlist.calculate_brand_sync_delta(
        client, lid, [gamma_host], output_locations_file=None
    )
    assert to_add == []
    assert to_remove == []

    assert watchlist.execute_domain_brand_sync(
        client, lid, [gamma_host], dry_run=False, output_locations_file=None
    )
    mutating_calls = [
        r
        for r in mock_rf_server.requests_log
        if r["path"].endswith("/entity/add") or r["path"].endswith("/entity/remove")
    ]
    assert mutating_calls == []
    assert len(client.get_watchlist_entities(lid)) == expected_count


@pytest.mark.feature("F9")
def test_t1_f9_domain_scoped_delta_sync_preserves_other_domains(
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    beta_logo = make_png(220, 64, (20, 120, 80, 255))
    beta_fav = make_ico(32, 32, payload="png")
    gamma_logo = make_png(200, 60, (180, 40, 40, 255))
    gamma_fav = make_ico(16, 16, payload="bmp")

    brand_http_server.add_site(
        make_brand_site(
            domain="scoped-beta.local",
            html='<html><body><header><img class="site-logo" src="/images/b.png"></header></body></html>',
            assets={"/images/b.png": (beta_logo, "image/png"), "/favicon.ico": (beta_fav, "image/x-icon")},
        )
    )
    brand_http_server.add_site(
        make_brand_site(
            domain="scoped-gamma.local",
            html='<html><body><header><img class="site-logo" src="/images/g.png"></header></body></html>',
            assets={"/images/g.png": (gamma_logo, "image/png"), "/favicon.ico": (gamma_fav, "image/x-icon")},
        )
    )

    beta_host = _site_host(brand_http_server, "scoped-beta.local")
    gamma_host = _site_host(brand_http_server, "scoped-gamma.local")
    seeded = mock_rf_server.seed_list("Scoped Delta", "brand")
    lid = seeded["id"]

    watchlist = _load_watchlist()
    client = RecordedFutureClient()
    assert watchlist.execute_domain_brand_sync(
        client, lid, [beta_host, gamma_host], dry_run=False, output_locations_file=None
    )

    # Change gamma's logo, then run sync scoped ONLY to gamma_host
    new_gamma_logo = make_png(210, 62, (10, 200, 90, 255))
    brand_http_server.set_route(
        "scoped-gamma.local",
        "/images/g.png",
        RouteSpec(status=200, content_type="image/png", body=new_gamma_logo),
    )

    assert watchlist.execute_domain_brand_sync(
        client,
        lid,
        [gamma_host],
        dry_run=False,
        output_locations_file=None,
        scoped_domains={gamma_host},
    )

    stored_hashes = {e["entity"]["name"] for e in client.get_watchlist_entities(lid)}
    assert sha256_hex(beta_logo) in stored_hashes
    assert sha256_hex(beta_fav) in stored_hashes
    assert sha256_hex(new_gamma_logo) in stored_hashes
    assert sha256_hex(gamma_logo) not in stored_hashes


@pytest.mark.feature("F9")
def test_t1_f9_multi_domain_shared_hash_attribution_and_retention(
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    shared_png = make_png(220, 64, (30, 110, 190, 255))
    shared_sha = sha256_hex(shared_png)
    alpha_unique = make_png(180, 50, (11, 22, 33, 255))
    subsidiary_unique = make_png(160, 50, (90, 40, 140, 255))
    fav_a = make_ico(32, 32, payload="png")
    fav_b = make_ico(48, 48, payload="bmp")

    brand_http_server.add_site(
        make_brand_site(
            domain="shared-parent.local",
            html=(
                "<html><body><header>"
                '<img class="site-logo" src="/images/shared.png">'
                '<img class="brand-logo" src="/images/parent-only.png">'
                "</header></body></html>"
            ),
            assets={
                "/images/shared.png": (shared_png, "image/png"),
                "/images/parent-only.png": (alpha_unique, "image/png"),
                "/favicon.ico": (fav_a, "image/x-icon"),
            },
        )
    )
    brand_http_server.add_site(
        make_brand_site(
            domain="shared-sub.local",
            html=(
                "<html><body><header>"
                '<img class="site-logo" src="/images/shared.png">'
                '<img class="brand-logo" src="/images/sub-only.png">'
                "</header></body></html>"
            ),
            assets={
                "/images/shared.png": (shared_png, "image/png"),
                "/images/sub-only.png": (subsidiary_unique, "image/png"),
                "/favicon.ico": (fav_b, "image/x-icon"),
            },
        )
    )

    host_a = _site_host(brand_http_server, "shared-parent.local")
    host_b = _site_host(brand_http_server, "shared-sub.local")
    seeded = mock_rf_server.seed_list("Shared Attribution", "brand")
    lid = seeded["id"]

    watchlist = _load_watchlist()
    client = RecordedFutureClient()

    target_hashes, _existing, _add, _rem, _de, _ie = watchlist.calculate_brand_sync_delta(
        client, lid, [host_a, host_b], output_locations_file=None
    )
    assert sorted(target_hashes[shared_sha]["domains"]) == sorted([host_a, host_b])

    assert watchlist.execute_domain_brand_sync(
        client, lid, [host_a, host_b], dry_run=False, output_locations_file=None
    )

    # Parent drops shared.png while subsidiary keeps it
    brand_http_server.set_route(
        "shared-parent.local",
        "/",
        RouteSpec(
            status=200,
            content_type="text/html; charset=utf-8",
            body=b'<html><body><header><img class="brand-logo" src="/images/parent-only.png"></header></body></html>',
        ),
    )

    assert watchlist.execute_domain_brand_sync(
        client, lid, [host_a, host_b], dry_run=False, output_locations_file=None
    )
    stored_hashes = {e["entity"]["name"] for e in client.get_watchlist_entities(lid)}
    assert shared_sha in stored_hashes
    assert sha256_hex(subsidiary_unique) in stored_hashes
    assert sha256_hex(alpha_unique) in stored_hashes


# ---------------------------------------------------------------------------
# F10: Continuous Automated Updates (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.feature("F10")
def test_t1_f10_brand_sync_state_json_persistence(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    gamma_expected = set(sites["brand-gamma.local"].expected_logo_hashes.values())
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Continuous State", "brand")
    lid = seeded["id"]

    brand_sync = importlib.import_module("soclens.logos.brand_sync")
    client = RecordedFutureClient()
    state_path = e2e_workspace / "brand_sync_state.json"

    summary = brand_sync.run_continuous_brand_sync(
        client,
        lid,
        [gamma_host],
        dry_run=False,
        output_locations_file=None,
        interval_seconds=0.0,
        max_runs=1,
        state_file=state_path,
        workspace_dir=e2e_workspace,
    )

    assert summary["runs_attempted"] == 1
    assert summary["runs_succeeded"] == 1
    assert summary["runs_failed"] == 0
    assert state_path.is_file()

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["list_id"] == lid
    assert state["runs_completed"] == 1
    dom_state = state["domains"][gamma_host]
    assert dom_state["consecutive_failures"] == 0
    assert dom_state["last_success"]
    assert set(dom_state["hashes"]) == gamma_expected


@pytest.mark.feature("F10")
def test_t1_f10_grace_period_preserves_then_prunes_after_threshold(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    flaky_logo_sha = sites["brand-flaky.local"].expected_logo_hashes["/images/flaky-logo.png"]
    gamma_logo_sha = sites["brand-gamma.local"].expected_logo_hashes["/images/gamma-logo.gif"]

    flaky_host = _site_host(brand_http_server, "brand-flaky.local")
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Grace Threshold", "brand")
    lid = seeded["id"]

    brand_sync = importlib.import_module("soclens.logos.brand_sync")
    client = RecordedFutureClient()
    state_path = e2e_workspace / "brand_sync_state.json"

    assert brand_sync.execute_domain_brand_sync(
        client,
        lid,
        [flaky_host, gamma_host],
        dry_run=False,
        output_locations_file=None,
        state_grace_failures=3,
        state_file=state_path,
        workspace_dir=e2e_workspace,
    )

    # Inject persistent homepage 503 on brand-flaky.local while gamma stays healthy
    brand_http_server.set_route(
        "brand-flaky.local",
        "/",
        RouteSpec(status=503, content_type="text/plain", body=b"Service Unavailable"),
    )

    for expected_fail_count in (1, 2):
        assert brand_sync.execute_domain_brand_sync(
            client,
            lid,
            [flaky_host, gamma_host],
            dry_run=False,
            output_locations_file=None,
            state_grace_failures=3,
            state_file=state_path,
            workspace_dir=e2e_workspace,
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert state["domains"][flaky_host]["consecutive_failures"] == expected_fail_count
        stored = {e["entity"]["name"] for e in client.get_watchlist_entities(lid)}
        assert flaky_logo_sha in stored
        assert gamma_logo_sha in stored

    # Failure #3 hits grace threshold (3) -> prunes flaky hashes, preserves gamma
    assert brand_sync.execute_domain_brand_sync(
        client,
        lid,
        [flaky_host, gamma_host],
        dry_run=False,
        output_locations_file=None,
        state_grace_failures=3,
        state_file=state_path,
        workspace_dir=e2e_workspace,
    )
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["domains"][flaky_host]["consecutive_failures"] == 3
    stored_after = {e["entity"]["name"] for e in client.get_watchlist_entities(lid)}
    assert flaky_logo_sha not in stored_after
    assert gamma_logo_sha in stored_after


@pytest.mark.feature("F10")
def test_t1_f10_cli_watch_interval_max_runs_exits_cleanly(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., Any],
) -> None:
    sites = build_default_brand_sites()
    gamma_expected = set(sites["brand-gamma.local"].expected_logo_hashes.values())
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("CLI Watch Test", "brand")
    lid = seeded["id"]

    locs_path = e2e_workspace / "watch_locs.json"
    state_path = e2e_workspace / "brand_sync_state.json"

    proc = run_cli(
        [
            "watchlist",
            "sync-logos",
            lid,
            "--domains",
            gamma_host,
            "--watch",
            "--interval",
            "0",
            "--max-runs",
            "2",
            "--output-locations",
            str(locs_path),
        ],
        env={"SOCLENS_AUTO_APPROVE": "true"},
    )

    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    home_fetches = [
        r
        for r in brand_http_server.requests_log
        if r["domain"] == "brand-gamma.local" and r["path"] == "/"
    ]
    assert len(home_fetches) == 2

    client = RecordedFutureClient()
    stored = {e["entity"]["name"] for e in client.get_watchlist_entities(lid)}
    assert stored == gamma_expected
    assert state_path.is_file()


@pytest.mark.feature("F10")
def test_t1_f10_lockfile_created_during_run_and_removed_on_exit(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Lockfile Lifecycle", "brand")
    lid = seeded["id"]

    brand_sync = importlib.import_module("soclens.logos.brand_sync")
    client = RecordedFutureClient()
    lock_path = e2e_workspace / ".brand_sync.lock"
    observed_during_run: list[bool] = []

    def _on_complete(_info: dict[str, Any]) -> None:
        observed_during_run.append(lock_path.is_file())

    summary = brand_sync.run_continuous_brand_sync(
        client,
        lid,
        [gamma_host],
        dry_run=False,
        output_locations_file=None,
        max_runs=1,
        lock_file=lock_path,
        state_file=e2e_workspace / "brand_sync_state.json",
        workspace_dir=e2e_workspace,
        on_run_complete=_on_complete,
    )

    assert summary["runs_succeeded"] == 1
    assert observed_during_run == [True]
    assert not lock_path.exists()


@pytest.mark.feature("F10")
def test_t1_f10_scheduler_templates_and_safe_two_site_workflow(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., Any],
) -> None:
    scripts_dir = _REPO_ROOT / "scripts"
    service_file = scripts_dir / "soclens-brand-sync.service"
    ps1_file = scripts_dir / "soclens-brand-sync.ps1"
    xml_file = scripts_dir / "soclens-brand-sync-task.xml"

    assert service_file.is_file()
    assert ps1_file.is_file()
    assert xml_file.is_file()

    service_text = service_file.read_text(encoding="utf-8")
    assert "[Unit]" in service_text and "[Service]" in service_text
    assert "soclens" in service_text and "sync-logos" in service_text

    ps1_text = ps1_file.read_text(encoding="utf-8")
    assert "soclens.cli" in ps1_text and "sync-logos" in ps1_text
    assert "/bin/bash" not in ps1_text and "sudo " not in ps1_text

    xml_root = ET.fromstring(xml_file.read_bytes())
    assert xml_root.tag.endswith("Task")

    # Safe 2-site workflow via CLI (never touches brands.csv / watchlist.csv)
    alpha_host = _site_host(brand_http_server, "brand-alpha.local")
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Two Site Safe Sync", "brand")
    lid = seeded["id"]

    proc = run_cli(
        [
            "watchlist",
            "sync-logos",
            lid,
            "--domains",
            f"{alpha_host},{gamma_host}",
            "--output-locations",
            str(e2e_workspace / "two_site_locs.json"),
        ],
        env={"SOCLENS_AUTO_APPROVE": "1"},
    )
    assert proc.returncode == 0
    requested_domains = {r["domain"] for r in brand_http_server.requests_log}
    assert requested_domains == {"brand-alpha.local", "brand-gamma.local"}


# ---------------------------------------------------------------------------
# F16: Test Isolation & Safe Testing Hygiene (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.feature("F16")
def test_t1_f16_output_locations_none_writes_nothing(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    snapshot = _snapshot_repo_root_artifacts()
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("No Locations Write", "brand")
    lid = seeded["id"]

    watchlist = _load_watchlist()
    client = RecordedFutureClient()

    assert watchlist.validate_domain_brand_sync(
        client, lid, [gamma_host], output_locations_file=None
    )
    assert watchlist.execute_domain_brand_sync(
        client, lid, [gamma_host], dry_run=False, output_locations_file=None
    )

    assert not (e2e_workspace / "discovered_images.json").exists()
    _assert_repo_root_artifacts_unchanged(snapshot)


@pytest.mark.feature("F16")
def test_t1_f16_output_locations_path_object_writes_only_to_target(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    snapshot = _snapshot_repo_root_artifacts()
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Path Locations Write", "brand")
    lid = seeded["id"]

    target_path = e2e_workspace / "nested" / "brand_locs.json"
    watchlist = _load_watchlist()
    client = RecordedFutureClient()

    assert watchlist.execute_domain_brand_sync(
        client, lid, [gamma_host], dry_run=False, output_locations_file=target_path
    )

    assert target_path.is_file()
    payload = json.loads(target_path.read_text(encoding="utf-8"))
    assert isinstance(payload, list) and len(payload) >= 4
    assert all(item.get("domain") == gamma_host for item in payload)
    assert not (e2e_workspace / "discovered_images.json").exists()
    _assert_repo_root_artifacts_unchanged(snapshot)


@pytest.mark.feature("F16")
def test_t1_f16_cli_sync_and_validate_logos_never_touch_repo_root(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., Any],
) -> None:
    snapshot = _snapshot_repo_root_artifacts()
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("CLI Repo Root Isolation", "brand")
    lid = seeded["id"]

    locs_sync = e2e_workspace / "cli_sync_locs.json"
    locs_val = e2e_workspace / "cli_val_locs.json"

    proc_sync = run_cli(
        [
            "watchlist",
            "sync-logos",
            lid,
            "--domains",
            gamma_host,
            "--output-locations",
            str(locs_sync),
        ],
        env={"SOCLENS_AUTO_APPROVE": "1"},
    )
    assert proc_sync.returncode == 0
    assert locs_sync.is_file()

    proc_val = run_cli(
        [
            "watchlist",
            "validate-logos",
            lid,
            "--domains",
            gamma_host,
            "--output-locations",
            str(locs_val),
        ]
    )
    assert proc_val.returncode == 0
    assert locs_val.is_file()
    _assert_repo_root_artifacts_unchanged(snapshot)


@pytest.mark.feature("F16")
def test_t1_f16_never_reads_live_brands_or_watchlist_csv(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., Any],
) -> None:
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Single Site Hygiene", "brand")
    lid = seeded["id"]

    proc = run_cli(
        [
            "watchlist",
            "sync-logos",
            lid,
            "--domains",
            gamma_host,
            "--output-locations",
            str(e2e_workspace / "single_locs.json"),
        ],
        env={"SOCLENS_AUTO_APPROVE": "1"},
    )
    assert proc.returncode == 0

    assert {r["domain"] for r in brand_http_server.requests_log} == {"brand-gamma.local"}
    add_domains = {
        r["body_json"]["context"]["domain"]
        for r in mock_rf_server.requests_log
        if r["method"] == "POST" and r["path"].endswith("/entity/add")
    }
    assert add_domains == {gamma_host}


@pytest.mark.feature("F16")
def test_t1_f16_temp_domains_csv_isolated_from_repo_csvs(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., Any],
) -> None:
    snapshot = _snapshot_repo_root_artifacts()
    temp_csv = e2e_workspace / "temp_domains.csv"
    temp_csv.write_text(
        "domain,notes\nsynthetic-alpha.local,test1\nsynthetic-gamma.local,test2\n",
        encoding="utf-8",
    )

    extractor = importlib.import_module("soclens.logos.extractor")
    parsed_domains = extractor.load_domains_file(temp_csv)
    assert parsed_domains == ["synthetic-alpha.local", "synthetic-gamma.local"]

    # Also verify CLI --domains-file with empty workspace CSV does not fall back to repo-root CSVs
    empty_csv = e2e_workspace / "empty_domains.csv"
    empty_csv.write_text("domain\n", encoding="utf-8")
    seeded = mock_rf_server.seed_list("Empty CSV Isolation", "brand")
    lid = seeded["id"]

    proc = run_cli(
        [
            "watchlist",
            "validate-logos",
            lid,
            "--domains-file",
            str(empty_csv),
            "--output-locations",
            str(e2e_workspace / "empty_locs.json"),
        ]
    )
    # Empty list has no domains -> should not scan repo-root CSVs or make external requests
    assert brand_http_server.requests_log == []
    assert not any(
        r["path"].endswith("/entity/add") or r["path"].endswith("/entity/remove")
        for r in mock_rf_server.requests_log
    )
    # Verify non-zero exit when no domains are found/provided
    assert proc.returncode != 0
    _assert_repo_root_artifacts_unchanged(snapshot)
    assert os.environ["SOCLENS_HOME"] == str(e2e_workspace)
