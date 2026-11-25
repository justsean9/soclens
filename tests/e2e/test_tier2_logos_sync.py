"""Tier 2 E2E boundary, fault-injection, negative, and isolation tests for brand logos & sync."""

from __future__ import annotations

import importlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from soclens.client import RecordedFutureAuthError, RecordedFutureClient
from tests.e2e.conftest import BrandHTTPServer, MockRFServer
from tests.e2e.fixtures.assets import (
    iter_oversized_chunks,
    make_banner_jpeg,
    make_banner_png,
    make_corrupted_jpeg,
    make_corrupted_png,
    make_ico,
    make_png,
    make_tiny_payload,
    make_truncated_png,
    sha256_hex,
)
from tests.e2e.fixtures.brand_sites import (
    OVERSIZED_STREAM_BYTES,
    RouteSpec,
    build_default_brand_sites,
    make_brand_site,
)

pytestmark = [pytest.mark.e2e, pytest.mark.tier2]

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
# F7: Multi-Source Logo Extraction Boundaries (6 tests)
# ---------------------------------------------------------------------------


@pytest.mark.feature("F7")
def test_t2_f7_malformed_jsonld_degrades_gracefully(
    brand_http_server: BrandHTTPServer,
) -> None:
    good_logo = make_png(200, 60, (25, 95, 165, 255))
    favicon = make_ico(32, 32, payload="png")
    html = (
        "<!DOCTYPE html><html><head><title>Malformed JSON-LD</title>"
        '<script type="application/ld+json">{not valid json</script>'
        '<script type="application/ld+json">null</script>'
        '<script type="application/ld+json">[123, "str", {"@type": "Organization"}]</script>'
        "</head><body><header>"
        '<img class="site-logo" src="/images/good.png" alt="Good Logo">'
        "</header></body></html>"
    )
    brand_http_server.add_site(
        make_brand_site(
            domain="bad-jsonld.local",
            html=html,
            assets={
                "/images/good.png": (good_logo, "image/png"),
                "/favicon.ico": (favicon, "image/x-icon"),
            },
        )
    )

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _q, domain_err, _ie, _locs = get_domain_image_hash(
        _site_host(brand_http_server, "bad-jsonld.local"), ignored_hashes={}
    )
    assert domain_err is None
    assert {item["sha256"] for item in hashes} == {sha256_hex(good_logo), sha256_hex(favicon)}


@pytest.mark.feature("F7")
def test_t2_f7_malformed_or_404_manifest_json_graceful(
    brand_http_server: BrandHTTPServer,
) -> None:
    good_logo = make_png(190, 58, (40, 110, 140, 255))
    favicon = make_ico(32, 32, payload="png")
    html = (
        "<!DOCTYPE html><html><head><title>Bad Manifest</title>"
        '<link rel="manifest" href="/manifest.json">'
        "</head><body><header>"
        '<img class="site-logo" src="/images/good.png" alt="Good Logo">'
        "</header></body></html>"
    )

    brand_http_server.add_site(
        make_brand_site(
            domain="bad-manifest.local",
            html=html,
            assets={
                "/images/good.png": (good_logo, "image/png"),
                "/favicon.ico": (favicon, "image/x-icon"),
            },
            extra_routes={
                "/manifest.json": RouteSpec(status=404, content_type="text/plain", body=b"Missing")
            },
        )
    )
    host = _site_host(brand_http_server, "bad-manifest.local")
    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")

    hashes_404, _q1, err1, _ie1, _l1 = get_domain_image_hash(host, ignored_hashes={})
    assert err1 is None
    assert sha256_hex(good_logo) in {item["sha256"] for item in hashes_404}

    brand_http_server.set_route(
        "bad-manifest.local",
        "/manifest.json",
        RouteSpec(status=200, content_type="application/json", body=b"{not-valid-json"),
    )
    hashes_bad_json, _q2, err2, _ie2, _l2 = get_domain_image_hash(host, ignored_hashes={})
    assert err2 is None
    assert sha256_hex(good_logo) in {item["sha256"] for item in hashes_bad_json}

    brand_http_server.set_route(
        "bad-manifest.local",
        "/manifest.json",
        RouteSpec(status=200, content_type="application/json", body=b'{"icons": "not-a-list"}'),
    )
    hashes_bad_schema, _q3, err3, _ie3, _l3 = get_domain_image_hash(host, ignored_hashes={})
    assert err3 is None
    assert sha256_hex(good_logo) in {item["sha256"] for item in hashes_bad_schema}


@pytest.mark.feature("F7")
def test_t2_f7_malformed_and_comma_heavy_srcset(
    brand_http_server: BrandHTTPServer,
) -> None:
    pic_1x = make_png(200, 80, (12, 65, 130, 255))
    fallback = make_png(180, 54, (22, 75, 140, 255))
    favicon = make_ico(32, 32, payload="png")

    html = (
        "<!DOCTYPE html><html><body><header>"
        "<picture>"
        '<source srcset=" , /cdn/w=200,h=80,fit=cover/logo-1x.png 1x , '
        'data:image/png;base64,INVALID , ">'
        '<img class="site-logo" srcset="" src="/images/fallback.png" alt="Brand Logo">'
        "</picture>"
        "</header></body></html>"
    )
    brand_http_server.add_site(
        make_brand_site(
            domain="comma-srcset.local",
            html=html,
            assets={
                "/cdn/w=200,h=80,fit=cover/logo-1x.png": (pic_1x, "image/png"),
                "/images/fallback.png": (fallback, "image/png"),
                "/favicon.ico": (favicon, "image/x-icon"),
            },
        )
    )

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _q, err, _ie, _locs = get_domain_image_hash(
        _site_host(brand_http_server, "comma-srcset.local"), ignored_hashes={}
    )
    assert err is None
    extracted_sha = {item["sha256"] for item in hashes}
    assert sha256_hex(pic_1x) in extracted_sha
    assert sha256_hex(fallback) in extracted_sha

    fetched_paths = [
        r["path"] for r in brand_http_server.requests_log if r["domain"] == "comma-srcset.local"
    ]
    assert "/cdn/w=200,h=80,fit=cover/logo-1x.png" in fetched_paths
    assert not any(p.endswith(("h=80", "fit=cover")) for p in fetched_paths)


@pytest.mark.feature("F7")
def test_t2_f7_relative_and_protocol_relative_urls_with_base(
    brand_http_server: BrandHTTPServer,
) -> None:
    crest_png = make_png(190, 60, (55, 120, 45, 255))
    global_icon = make_png(128, 128, (95, 45, 130, 255))
    favicon = make_ico(32, 32, payload="png")

    site_url = brand_http_server.site_url("base-proto.local")
    host_port = site_url.removeprefix("http://")

    app_html = (
        "<!DOCTYPE html><html><head>"
        '<base href="/static/brand/">'
        f'<link rel="icon" href="//{host_port}/global-icon.png">'
        "</head><body><header>"
        '<img class="site-logo" src="crest.png" alt="Crest Logo">'
        "</header></body></html>"
    )
    brand_http_server.add_site(
        make_brand_site(
            domain="base-proto.local",
            html="",
            assets={
                "/static/brand/crest.png": (crest_png, "image/png"),
                "/global-icon.png": (global_icon, "image/png"),
                "/favicon.ico": (favicon, "image/x-icon"),
            },
            extra_routes={
                "/": RouteSpec(
                    status=302,
                    content_type="text/html; charset=utf-8",
                    body=b"Redirect",
                    headers={"Location": "/app/index.html"},
                ),
                "/app/index.html": RouteSpec(
                    status=200,
                    content_type="text/html; charset=utf-8",
                    body=app_html.encode("utf-8"),
                ),
            },
        )
    )

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _q, err, _ie, _locs = get_domain_image_hash(host_port, ignored_hashes={})
    assert err is None
    extracted_sha = {item["sha256"] for item in hashes}
    assert sha256_hex(crest_png) in extracted_sha
    assert sha256_hex(global_icon) in extracted_sha


@pytest.mark.feature("F7")
def test_t2_f7_invalid_data_uris_and_promo_og_image_gated(
    brand_http_server: BrandHTTPServer,
) -> None:
    ok_png = make_png(180, 56, (30, 90, 150, 255))
    favicon = make_ico(32, 32, payload="png")

    html = (
        "<!DOCTYPE html><html><body><header>"
        '<img class="logo" src="data:image/png;base64,!!!invalid!!!">'
        '<img class="logo" src="data:image/png;base64,AA==">'
        '<img class="logo" src="data:text/plain;base64,aGVsbG8=">'
        '<img class="site-logo" src="/images/ok.png" alt="OK Logo">'
        "</header></body></html>"
    )
    brand_http_server.add_site(
        make_brand_site(
            domain="bad-data-uri.local",
            html=html,
            assets={
                "/images/ok.png": (ok_png, "image/png"),
                "/favicon.ico": (favicon, "image/x-icon"),
            },
        )
    )

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _q1, err1, img_errs1, _locs1 = get_domain_image_hash(
        _site_host(brand_http_server, "bad-data-uri.local"), ignored_hashes={}
    )
    assert err1 is None
    assert {item["sha256"] for item in hashes} == {sha256_hex(ok_png), sha256_hex(favicon)}
    assert not any("data:" in e for e in img_errs1)

    # Confirm promo og:image on brand-beta.local is gated out
    sites = build_default_brand_sites()
    spring_promo_sha = sha256_hex(sites["brand-beta.local"].routes["/uploads/spring-promo-banner.jpg"].body)
    beta_hashes, _q2, beta_err, _ie2, beta_locs = get_domain_image_hash(
        _site_host(brand_http_server, "brand-beta.local"), ignored_hashes={}
    )
    assert beta_err is None
    assert spring_promo_sha not in {item["sha256"] for item in beta_hashes}
    og_locs = [loc for loc in beta_locs if "spring-promo-banner.jpg" in str(loc.get("url", ""))]
    assert og_locs and all(loc.get("status") == "excluded" for loc in og_locs)


@pytest.mark.feature("F7")
def test_t2_f7_unreachable_domain_and_http_404_error_tuple(
    brand_http_server: BrandHTTPServer,
) -> None:
    brand_http_server.queue_fault("brand-flaky.local", "/", 404, body="Not Found", count=1)
    flaky_host = _site_host(brand_http_server, "brand-flaky.local")

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes_404, queried_404, err_404, _ie_404, _locs_404 = get_domain_image_hash(
        flaky_host, ignored_hashes={}
    )
    assert hashes_404 == []
    assert queried_404 == 0
    assert err_404 is not None and "404" in err_404

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        dead_port = sock.getsockname()[1]

    hashes_down, queried_down, err_down, _ie_down, _locs_down = get_domain_image_hash(
        f"127.0.0.1:{dead_port}", ignored_hashes={}
    )
    assert hashes_down == []
    assert queried_down == 0
    assert err_down is not None and len(err_down) > 0


# ---------------------------------------------------------------------------
# F8: Non-Logo Exclusion & Image Validation Boundaries (6 tests)
# ---------------------------------------------------------------------------


@pytest.mark.feature("F8")
def test_t2_f8_explicit_logo_does_not_bypass_promo_or_banner_exclusion(
    brand_http_server: BrandHTTPServer,
) -> None:
    is_excluded_image = _load_attr("soclens.logos.extractor", "is_excluded_image")
    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")

    excl_promo, reason_promo = is_excluded_image(
        "https://mybank.local/uploads/promo-logo.png",
        "mybank.local",
        alt="Promo Logo",
        cls="promo-logo",
    )
    assert excl_promo is True and reason_promo

    excl_heloc, reason_heloc = is_excluded_image(
        "https://mybank.local/images/special-mark.png",
        "mybank.local",
        alt="HELOC Logo",
    )
    assert excl_heloc is True and reason_heloc

    sites = build_default_brand_sites()
    promo_sha = sha256_hex(sites["brand-beta.local"].routes["/uploads/promo-banner.jpg"].body)
    hashes, _q, err, _ie, _locs = get_domain_image_hash(
        _site_host(brand_http_server, "brand-beta.local"), ignored_hashes={}
    )
    assert err is None
    assert promo_sha not in {item["sha256"] for item in hashes}


@pytest.mark.feature("F8")
def test_t2_f8_oversized_over_10mb_stream_rejected_without_oom(
    brand_http_server: BrandHTTPServer,
) -> None:
    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")

    beta_hashes, _q1, beta_err, _ie1, beta_locs = get_domain_image_hash(
        _site_host(brand_http_server, "brand-beta.local"), ignored_hashes={}
    )
    assert beta_err is None
    assert all("huge-logo.png" not in h["image_url"] for h in beta_hashes)
    huge_locs = [loc for loc in beta_locs if "huge-logo.png" in str(loc.get("url", ""))]
    assert huge_locs
    assert all(loc.get("status") == "empty_or_non_image" for loc in huge_locs)

    # Also verify chunked >10MB stream WITHOUT Content-Length is aborted cleanly
    ok_png = make_png(180, 60, (10, 100, 170, 255))
    favicon = make_ico(32, 32, payload="png")
    brand_http_server.add_site(
        make_brand_site(
            domain="chunked-huge.local",
            html=(
                "<html><body><header>"
                '<img class="site-logo" src="/images/ok.png">'
                '<img class="brand-logo" src="/images/stream-huge.png">'
                "</header></body></html>"
            ),
            assets={"/images/ok.png": (ok_png, "image/png"), "/favicon.ico": (favicon, "image/x-icon")},
            extra_routes={
                "/images/stream-huge.png": RouteSpec(
                    status=200,
                    content_type="image/png",
                    body=b"",
                    body_chunks=lambda: iter_oversized_chunks(OVERSIZED_STREAM_BYTES),
                )
            },
        )
    )
    chunk_hashes, _q2, chunk_err, _ie2, chunk_locs = get_domain_image_hash(
        _site_host(brand_http_server, "chunked-huge.local"), ignored_hashes={}
    )
    assert chunk_err is None
    assert {item["sha256"] for item in chunk_hashes} == {sha256_hex(ok_png), sha256_hex(favicon)}
    stream_locs = [loc for loc in chunk_locs if "stream-huge.png" in str(loc.get("url", ""))]
    assert stream_locs and all(loc.get("status") == "empty_or_non_image" for loc in stream_locs)


@pytest.mark.feature("F8")
def test_t2_f8_corrupted_truncated_png_jpeg_and_tiny_payloads(
    brand_http_server: BrandHTTPServer,
) -> None:
    trunc_png = make_truncated_png()
    corrupt_png = make_corrupted_png()
    corrupt_jpg = make_corrupted_jpeg()
    tiny = make_tiny_payload()

    brand_http_server.add_site(
        make_brand_site(
            domain="corrupt-assets.local",
            html=(
                "<html><body><header>"
                '<img class="site-logo" src="/images/trunc.png">'
                '<img class="site-logo" src="/images/corrupt.png">'
                '<img class="site-logo" src="/images/corrupt.jpg">'
                '<img class="site-logo" src="/images/tiny.png">'
                "</header></body></html>"
            ),
            extra_routes={
                "/images/trunc.png": RouteSpec(status=200, content_type="image/png", body=trunc_png),
                "/images/corrupt.png": RouteSpec(status=200, content_type="image/png", body=corrupt_png),
                "/images/corrupt.jpg": RouteSpec(status=200, content_type="image/jpeg", body=corrupt_jpg),
                "/images/tiny.png": RouteSpec(status=200, content_type="image/png", body=tiny),
                "/favicon.ico": RouteSpec(status=404, content_type="text/plain", body=b"Not Found"),
            },
        )
    )

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _q, err, _ie, locs = get_domain_image_hash(
        _site_host(brand_http_server, "corrupt-assets.local"), ignored_hashes={}
    )
    assert err is None
    assert hashes == []

    for bad_name in ("trunc.png", "corrupt.png", "corrupt.jpg", "tiny.png"):
        matched = [loc for loc in locs if bad_name in str(loc.get("url", ""))]
        assert matched
        assert all(loc.get("status") == "empty_or_non_image" for loc in matched)


@pytest.mark.feature("F8")
def test_t2_f8_extreme_banner_aspect_ratio_1200x100_rejected(
    brand_http_server: BrandHTTPServer,
) -> None:
    banner_png = make_banner_png(1200, 100)
    banner_jpg = make_banner_jpeg(1600, 100)
    valid_logo = make_png(200, 60, (15, 85, 155, 255))

    brand_http_server.add_site(
        make_brand_site(
            domain="aspect-banner.local",
            html=(
                "<html><body><header>"
                '<img class="site-logo" src="/images/header-graphic.png" alt="Brand">'
                '<img class="site-logo" src="/images/masthead.jpg" alt="Brand">'
                '<img class="site-logo" src="/images/valid-mark.png" alt="Brand">'
                "</header></body></html>"
            ),
            assets={"/images/valid-mark.png": (valid_logo, "image/png")},
            extra_routes={
                "/images/header-graphic.png": RouteSpec(
                    status=200, content_type="image/png", body=banner_png
                ),
                "/images/masthead.jpg": RouteSpec(
                    status=200, content_type="image/jpeg", body=banner_jpg
                ),
                "/favicon.ico": RouteSpec(status=404, content_type="text/plain", body=b"Missing"),
            },
        )
    )

    get_domain_image_hash = _load_attr("soclens.logos.extractor", "get_domain_image_hash")
    hashes, _q, err, _ie, locs = get_domain_image_hash(
        _site_host(brand_http_server, "aspect-banner.local"), ignored_hashes={}
    )
    assert err is None
    assert {item["sha256"] for item in hashes} == {sha256_hex(valid_logo)}
    for rejected in ("header-graphic.png", "masthead.jpg"):
        matched = [loc for loc in locs if rejected in str(loc.get("url", ""))]
        assert matched and all(loc.get("status") == "empty_or_non_image" for loc in matched)


@pytest.mark.feature("F8")
def test_t2_f8_load_domains_file_comments_whitespace_empty_and_missing(
    e2e_workspace: Path,
) -> None:
    load_domains_file = _load_attr("soclens.logos.extractor", "load_domains_file")

    commented = e2e_workspace / "commented.txt"
    commented.write_text(
        "# comment with a.dot\n"
        "  alpha.local  \n"
        "\n"
        "// slash comment\n"
        "  beta.local,extra  \n"
        "alpha.local # duplicate inline comment\n",
        encoding="utf-8",
    )
    assert load_domains_file(commented) == ["alpha.local", "beta.local"]

    multi_col = e2e_workspace / "exported_brands.csv"
    multi_col.write_text(
        "name,type,id,annotation,source,domain,image_url,sync_time\n"
        "aaaa,Hash,hash:aaaa,note,auto,gamma.local,https://gamma.local/logo.png,2026Z\n",
        encoding="utf-8",
    )
    assert load_domains_file(multi_col) == ["gamma.local"]

    header_only = e2e_workspace / "header_only.csv"
    header_only.write_text("domain\n", encoding="utf-8")
    assert load_domains_file(header_only) == []

    empty_file = e2e_workspace / "empty.txt"
    empty_file.write_bytes(b"")
    assert load_domains_file(empty_file) == []

    assert load_domains_file(e2e_workspace / "does_not_exist.csv") == []


@pytest.mark.feature("F8")
def test_t2_f8_word_boundary_prevents_false_positives_on_brand_words() -> None:
    is_excluded_image = _load_attr("soclens.logos.extractor", "is_excluded_image")

    for allowed_url in (
        "https://mybank.local/images/corporate-brand.png",
        "https://mybank.local/images/admiral-mark.png",
        "https://mybank.local/images/different-mark.png",
        "https://mybank.local/images/inspirational-crest.png",
        "https://mybank.local/images/first-national-mark.png",
    ):
        excluded, reason = is_excluded_image(allowed_url, "mybank.local")
        assert excluded is False, f"Unexpectedly excluded {allowed_url}: {reason}"

    for blocked_url in (
        "https://mybank.local/images/dif-logo.png",
        "https://mybank.local/images/ira-promo.png",
        "https://mybank.local/images/rate-table.png",
        "https://mybank.local/icons/search-icon.svg",
    ):
        excluded, _ = is_excluded_image(blocked_url, "mybank.local")
        assert excluded is True, f"Expected {blocked_url} to be excluded"


# ---------------------------------------------------------------------------
# F9: Hashing & Non-Destructive Brand Sync Boundaries (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.feature("F9")
def test_t2_f9_ignored_hashes_malformed_lines_comments_json_and_env(
    e2e_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    load_ignored_hashes = _load_attr("soclens.logos.hashing", "load_ignored_hashes")

    h_md5 = "A" * 32
    h_sha1 = "B" * 40
    h_sha256_colon = "C" * 64
    h_sha256_csv = "D" * 64
    h_env = "E" * 64
    h_json = "1" * 64

    txt_file = e2e_workspace / "mixed_ignored.txt"
    txt_file.write_text(
        "\n".join(
            [
                "# full line hash comment",
                "// slash comment",
                f"{h_md5} # md5 noise",
                f"hash:{h_sha1} // prefixed sha1",
                f"{h_sha256_colon}: colon reason",
                f"{h_sha256_csv},csv reason",
                "abcd # too short",
                f"{'z' * 64} # non-hex",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RF_IGNORED_HASHES", f"hash:{h_env},badhex")

    loaded_txt = load_ignored_hashes(file_path=txt_file)
    assert h_md5.lower() in loaded_txt
    assert h_sha1.lower() in loaded_txt
    assert h_sha256_colon.lower() in loaded_txt
    assert h_sha256_csv.lower() in loaded_txt
    assert h_env.lower() in loaded_txt
    assert "abcd" not in loaded_txt
    assert ("z" * 64) not in loaded_txt

    json_file = e2e_workspace / "ignored.json"
    json_file.write_text(json.dumps({f"hash:{h_json.upper()}": "json reason"}), encoding="utf-8")
    loaded_json = load_ignored_hashes(file_path=json_file)
    assert loaded_json[h_json] == "json reason"


@pytest.mark.feature("F9")
def test_t2_f9_manual_watchlist_entries_never_pruned(
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    manual_sha = "1" * 64
    legacy_sha = "2" * 64
    seeded = mock_rf_server.seed_list(
        "Preserve Manual Entries",
        "brand",
        entities=[
            {
                "entity": {"id": f"hash:{manual_sha}", "type": "Hash", "name": manual_sha},
                "context": {"source": "manual", "annotation": "SOC analyst manual keep"},
            },
            {
                "entity": {"id": f"hash:{legacy_sha}", "type": "Hash", "name": legacy_sha},
                "context": {},
            },
        ],
    )
    lid = seeded["id"]

    watchlist = _load_watchlist()
    client = RecordedFutureClient()
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")

    assert watchlist.execute_domain_brand_sync(
        client, lid, [gamma_host], dry_run=False, output_locations_file=None
    )

    stored_hashes = {e["entity"]["name"] for e in client.get_watchlist_entities(lid)}
    assert manual_sha in stored_hashes
    assert legacy_sha in stored_hashes


@pytest.mark.feature("F9")
def test_t2_f9_all_domains_failing_aborts_without_wiping_watchlist(
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    existing_flaky_sha = sites["brand-flaky.local"].expected_logo_hashes["/images/flaky-logo.png"]
    flaky_host = _site_host(brand_http_server, "brand-flaky.local")

    seeded = mock_rf_server.seed_list(
        "Abort On Total Failure",
        "brand",
        entities=[
            {
                "entity": {"id": f"hash:{existing_flaky_sha}", "type": "Hash", "name": existing_flaky_sha},
                "context": {"source": "automated-watchlist-manager", "domain": flaky_host},
            }
        ],
    )
    lid = seeded["id"]

    brand_http_server.set_route(
        "brand-flaky.local",
        "/",
        RouteSpec(status=503, content_type="text/plain", body=b"Down"),
    )

    watchlist = _load_watchlist()
    client = RecordedFutureClient()
    ok = watchlist.execute_domain_brand_sync(
        client, lid, [flaky_host], dry_run=False, output_locations_file=None
    )
    assert ok is False

    remove_calls = [r for r in mock_rf_server.requests_log if r["path"].endswith("/entity/remove")]
    assert remove_calls == []
    assert {e["entity"]["name"] for e in client.get_watchlist_entities(lid)} == {existing_flaky_sha}


@pytest.mark.feature("F9")
def test_t2_f9_uppercase_and_hash_prefix_normalization_idempotent(
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    gamma_hashes = set(sites["brand-gamma.local"].expected_logo_hashes.values())
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")

    seeded = mock_rf_server.seed_list(
        "Case Normalization",
        "brand",
        entities=[
            {
                "entity": {"id": f"hash:{h.upper()}", "type": "Hash", "name": h.upper()},
                "context": {"source": "automated-watchlist-manager", "domain": gamma_host},
            }
            for h in gamma_hashes
        ],
    )
    lid = seeded["id"]

    watchlist = _load_watchlist()
    client = RecordedFutureClient()
    _target, _existing, to_add, to_remove, _de, _ie = watchlist.calculate_brand_sync_delta(
        client, lid, [gamma_host], output_locations_file=None
    )
    assert to_add == []
    assert to_remove == []

    assert watchlist.execute_domain_brand_sync(
        client, lid, [gamma_host], dry_run=False, output_locations_file=None
    )
    add_calls = [r for r in mock_rf_server.requests_log if r["path"].endswith("/entity/add")]
    assert add_calls == []


@pytest.mark.feature("F9")
def test_t2_f9_rf_api_403_abort_and_429_retry_after_recovery(
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    gamma_expected = set(sites["brand-gamma.local"].expected_logo_hashes.values())
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("RF Faults", "brand")
    lid = seeded["id"]

    watchlist = _load_watchlist()
    client = RecordedFutureClient()

    # (a) 403 on GET /list/{lid}/entities aborts cleanly (never treats as empty list)
    mock_rf_server.queue_fault(
        f"/list/{lid}/entities",
        403,
        body={"message": "Missing Data permissions", "status_code": 403, "trace_id": "e2e-403"},
    )
    with pytest.raises(RecordedFutureAuthError):
        watchlist.calculate_brand_sync_delta(client, lid, [gamma_host], output_locations_file=None)

    mock_rf_server.queue_fault(
        f"/list/{lid}/entities",
        403,
        body={"message": "Missing Data permissions", "status_code": 403, "trace_id": "e2e-403-exec"},
    )
    assert (
        watchlist.execute_domain_brand_sync(
            client, lid, [gamma_host], dry_run=False, output_locations_file=None
        )
        is False
    )

    # (b) 429 Retry-After on entity/add recovers and populates all hashes
    mock_rf_server.queue_fault(
        f"/list/{lid}/entity/add",
        429,
        headers={"Retry-After": "0"},
        count=1,
    )
    assert (
        watchlist.execute_domain_brand_sync(
            client, lid, [gamma_host], dry_run=False, output_locations_file=None
        )
        is True
    )
    assert {e["entity"]["name"] for e in client.get_watchlist_entities(lid)} == gamma_expected


# ---------------------------------------------------------------------------
# F10: Continuous Automated Updates Boundaries (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.feature("F10")
def test_t2_f10_stale_lockfile_recovered_while_active_lock_rejected(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Lock Recovery", "brand")
    lid = seeded["id"]

    brand_sync = importlib.import_module("soclens.logos.brand_sync")
    client = RecordedFutureClient()
    lock_path = e2e_workspace / ".brand_sync.lock"

    # (a) Stale dead PID lockfile is recovered automatically
    lock_path.write_text(
        json.dumps({"pid": 99999999, "hostname": socket.gethostname(), "epoch": time.time()}),
        encoding="utf-8",
    )
    summary = brand_sync.run_continuous_brand_sync(
        client,
        lid,
        [gamma_host],
        dry_run=False,
        output_locations_file=None,
        max_runs=1,
        lock_file=lock_path,
        state_file=e2e_workspace / "state.json",
        workspace_dir=e2e_workspace,
    )
    assert summary["runs_succeeded"] == 1
    assert not lock_path.exists()

    # (b) Active live-PID lockfile is rejected with SyncLockError
    lock_path.write_text(
        json.dumps({"pid": os.getpid(), "hostname": socket.gethostname(), "epoch": time.time()}),
        encoding="utf-8",
    )
    with pytest.raises(brand_sync.SyncLockError):
        brand_sync.run_continuous_brand_sync(
            client,
            lid,
            [gamma_host],
            dry_run=False,
            output_locations_file=None,
            max_runs=1,
            lock_file=lock_path,
            state_file=e2e_workspace / "state.json",
            workspace_dir=e2e_workspace,
        )


@pytest.mark.feature("F10")
def test_t2_f10_corrupted_state_file_recovers_cleanly(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Corrupt State Recovery", "brand")
    lid = seeded["id"]

    state_path = e2e_workspace / "brand_sync_state.json"
    state_path.write_text("{corrupted-json", encoding="utf-8")

    brand_sync = importlib.import_module("soclens.logos.brand_sync")
    client = RecordedFutureClient()
    summary = brand_sync.run_continuous_brand_sync(
        client,
        lid,
        [gamma_host],
        dry_run=False,
        output_locations_file=None,
        max_runs=1,
        state_file=state_path,
        workspace_dir=e2e_workspace,
    )
    assert summary["runs_succeeded"] == 1
    repaired = json.loads(state_path.read_text(encoding="utf-8"))
    assert repaired["runs_completed"] == 1
    assert repaired["domains"][gamma_host]["consecutive_failures"] == 0


@pytest.mark.feature("F10")
def test_t2_f10_transient_failures_reset_after_recovery_below_grace(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    sites = build_default_brand_sites()
    flaky_logo_sha = sites["brand-flaky.local"].expected_logo_hashes["/images/flaky-logo.png"]
    original_home_route = brand_http_server.sites["brand-flaky.local"].routes["/"]
    flaky_host = _site_host(brand_http_server, "brand-flaky.local")
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")

    seeded = mock_rf_server.seed_list("Transient Reset", "brand")
    lid = seeded["id"]

    brand_sync = importlib.import_module("soclens.logos.brand_sync")
    client = RecordedFutureClient()
    state_path = e2e_workspace / "brand_sync_state.json"

    # Initial healthy sync
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

    # 2 consecutive 503 failures (< grace=3)
    brand_http_server.set_route(
        "brand-flaky.local",
        "/",
        RouteSpec(status=503, content_type="text/plain", body=b"Temp Error"),
    )
    for expected_streak in (1, 2):
        brand_sync.execute_domain_brand_sync(
            client,
            lid,
            [flaky_host, gamma_host],
            dry_run=False,
            output_locations_file=None,
            state_grace_failures=3,
            state_file=state_path,
            workspace_dir=e2e_workspace,
        )
        st = json.loads(state_path.read_text(encoding="utf-8"))
        assert st["domains"][flaky_host]["consecutive_failures"] == expected_streak

    # Recovery to 200 OK resets consecutive_failures to 0
    brand_http_server.set_route("brand-flaky.local", "/", original_home_route)
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
    st_recovered = json.loads(state_path.read_text(encoding="utf-8"))
    assert st_recovered["domains"][flaky_host]["consecutive_failures"] == 0

    # Single new failure starts streak at 1 and does NOT prune
    brand_http_server.set_route(
        "brand-flaky.local",
        "/",
        RouteSpec(status=503, content_type="text/plain", body=b"Temp Error Again"),
    )
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
    st_final = json.loads(state_path.read_text(encoding="utf-8"))
    assert st_final["domains"][flaky_host]["consecutive_failures"] == 1
    assert flaky_logo_sha in {e["entity"]["name"] for e in client.get_watchlist_entities(lid)}


@pytest.mark.feature("F10")
def test_t2_f10_stop_event_interrupts_watch_wait_promptly(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Stop Event Watch", "brand")
    lid = seeded["id"]

    brand_sync = importlib.import_module("soclens.logos.brand_sync")
    client = RecordedFutureClient()
    stop_event = threading.Event()
    lock_path = e2e_workspace / ".watch.lock"
    results: list[dict[str, Any]] = []

    def _on_complete(_info: dict[str, Any]) -> None:
        stop_event.set()

    def _runner() -> None:
        summary = brand_sync.run_continuous_brand_sync(
            client,
            lid,
            [gamma_host],
            dry_run=False,
            output_locations_file=None,
            interval_seconds=60.0,
            max_runs=10,
            lock_file=lock_path,
            state_file=e2e_workspace / "state.json",
            stop_event=stop_event,
            workspace_dir=e2e_workspace,
            on_run_complete=_on_complete,
        )
        results.append(summary)

    t0 = time.monotonic()
    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join(timeout=5.0)
    elapsed = time.monotonic() - t0

    assert not thread.is_alive()
    assert elapsed < 4.5
    assert len(results) == 1
    assert results[0]["runs_attempted"] == 1
    assert results[0]["stopped"] is True
    assert not lock_path.exists()


@pytest.mark.feature("F10")
def test_t2_f10_cli_invalid_watch_args_and_missing_list_id_nonzero(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., Any],
) -> None:
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("CLI Watch Errors", "brand")
    lid = seeded["id"]

    proc_missing = run_cli(
        [
            "watchlist",
            "sync-logos",
            "report:missing",
            "--domains",
            gamma_host,
            "--watch",
            "--max-runs",
            "1",
            "--output-locations",
            str(e2e_workspace / "missing_locs.json"),
        ],
        env={"SOCLENS_AUTO_APPROVE": "true"},
    )
    assert proc_missing.returncode != 0
    assert (proc_missing.stderr + proc_missing.stdout).strip()

    proc_neg_interval = run_cli(
        [
            "watchlist",
            "sync-logos",
            lid,
            "--domains",
            gamma_host,
            "--watch",
            "--interval",
            "-5",
            "--max-runs",
            "1",
            "--output-locations",
            str(e2e_workspace / "neg_int_locs.json"),
        ],
        env={"SOCLENS_AUTO_APPROVE": "true"},
    )
    assert proc_neg_interval.returncode != 0

    proc_neg_runs = run_cli(
        [
            "watchlist",
            "sync-logos",
            lid,
            "--domains",
            gamma_host,
            "--watch",
            "--max-runs",
            "-1",
            "--output-locations",
            str(e2e_workspace / "neg_runs_locs.json"),
        ],
        env={"SOCLENS_AUTO_APPROVE": "true"},
    )
    assert proc_neg_runs.returncode != 0
    assert not (e2e_workspace / ".brand_sync.lock").exists()


# ---------------------------------------------------------------------------
# F16: Test Isolation & Safe Testing Hygiene Boundaries (5 tests)
# ---------------------------------------------------------------------------


@pytest.mark.feature("F16")
def test_t2_f16_missing_auto_approve_enforces_dry_run_no_mutations(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., Any],
) -> None:
    snapshot = _snapshot_repo_root_artifacts()
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Auto Approve Gate", "brand")
    lid = seeded["id"]

    assert "SOCLENS_AUTO_APPROVE" not in os.environ
    proc = run_cli(
        [
            "watchlist",
            "sync-logos",
            lid,
            "--domains",
            gamma_host,
            "--output-locations",
            str(e2e_workspace / "dry_locs.json"),
        ]
    )
    assert proc.returncode == 0
    mutations = [
        r
        for r in mock_rf_server.requests_log
        if r["path"].endswith("/entity/add") or r["path"].endswith("/entity/remove")
    ]
    assert mutations == []
    _assert_repo_root_artifacts_unchanged(snapshot)


@pytest.mark.feature("F16")
def test_t2_f16_ignored_hashes_isolated_to_workspace_not_repo_root(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
) -> None:
    snapshot = _snapshot_repo_root_artifacts()
    sites = build_default_brand_sites()
    gif_sha = sites["brand-gamma.local"].expected_logo_hashes["/images/gamma-logo.gif"]
    jpg_sha = sites["brand-gamma.local"].expected_logo_hashes["/images/gamma-logo.jpg"]

    ws_ignored = e2e_workspace / "ignored_hashes.txt"
    ws_ignored.write_text(f"{gif_sha} # workspace only ignore\n", encoding="utf-8")

    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Workspace Ignored Hashes", "brand")
    lid = seeded["id"]

    watchlist = _load_watchlist()
    client = RecordedFutureClient()
    assert watchlist.execute_domain_brand_sync(
        client,
        lid,
        [gamma_host],
        dry_run=False,
        output_locations_file=None,
        workspace_dir=e2e_workspace,
    )

    stored = {e["entity"]["name"] for e in client.get_watchlist_entities(lid)}
    assert gif_sha not in stored
    assert jpg_sha in stored
    _assert_repo_root_artifacts_unchanged(snapshot)


@pytest.mark.feature("F16")
def test_t2_f16_cli_output_locations_empty_or_nested_path(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    run_cli: Callable[..., Any],
) -> None:
    snapshot = _snapshot_repo_root_artifacts()
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    seeded = mock_rf_server.seed_list("Output Locations CLI", "brand")
    lid = seeded["id"]

    proc_empty = run_cli(
        [
            "watchlist",
            "validate-logos",
            lid,
            "--domains",
            gamma_host,
            "--output-locations",
            "",
        ]
    )
    assert proc_empty.returncode == 0
    assert not (e2e_workspace / "discovered_images.json").exists()

    nested_out = e2e_workspace / "nested" / "sub" / "discovered.json"
    proc_nested = run_cli(
        [
            "watchlist",
            "validate-logos",
            lid,
            "--domains",
            gamma_host,
            "--output-locations",
            str(nested_out),
        ]
    )
    assert proc_nested.returncode == 0
    assert nested_out.is_file()
    _assert_repo_root_artifacts_unchanged(snapshot)


@pytest.mark.feature("F16")
def test_t2_f16_unit_test_watchlist_produces_zero_cwd_discovered_images(
    e2e_workspace: Path,
) -> None:
    snapshot = _snapshot_repo_root_artifacts()
    unit_test_path = _REPO_ROOT / "tests" / "test_watchlist.py"

    env = dict(os.environ)
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{_REPO_ROOT}{os.pathsep}{existing_pp}" if existing_pp else str(_REPO_ROOT)

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", str(unit_test_path)],
        cwd=str(e2e_workspace),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60.0,
        check=False,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
    assert not (e2e_workspace / "discovered_images.json").exists()
    _assert_repo_root_artifacts_unchanged(snapshot)


@pytest.mark.feature("F16")
def test_t2_f16_multi_workspace_isolation_no_cross_contamination(
    e2e_workspace: Path,
    mock_rf_server: MockRFServer,
    brand_http_server: BrandHTTPServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot_repo_root_artifacts()
    gamma_host = _site_host(brand_http_server, "brand-gamma.local")
    flaky_host = _site_host(brand_http_server, "brand-flaky.local")

    lid1 = mock_rf_server.seed_list("WS1 List", "brand")["id"]
    lid2 = mock_rf_server.seed_list("WS2 List", "brand")["id"]

    ws1 = e2e_workspace / "ws1"
    ws2 = e2e_workspace / "ws2"
    ws1.mkdir()
    ws2.mkdir()

    brand_sync = importlib.import_module("soclens.logos.brand_sync")
    client = RecordedFutureClient()

    monkeypatch.setenv("SOCLENS_HOME", str(ws1))
    monkeypatch.chdir(ws1)
    assert (
        brand_sync.run_continuous_brand_sync(
            client,
            lid1,
            [gamma_host],
            dry_run=False,
            output_locations_file=None,
            max_runs=1,
            workspace_dir=ws1,
        )["runs_succeeded"]
        == 1
    )

    monkeypatch.setenv("SOCLENS_HOME", str(ws2))
    monkeypatch.chdir(ws2)
    assert (
        brand_sync.run_continuous_brand_sync(
            client,
            lid2,
            [flaky_host],
            dry_run=False,
            output_locations_file=None,
            max_runs=1,
            workspace_dir=ws2,
        )["runs_succeeded"]
        == 1
    )

    state1 = json.loads((ws1 / "brand_sync_state.json").read_text(encoding="utf-8"))
    state2 = json.loads((ws2 / "brand_sync_state.json").read_text(encoding="utf-8"))
    assert list(state1["domains"].keys()) == [gamma_host]
    assert list(state2["domains"].keys()) == [flaky_host]
    _assert_repo_root_artifacts_unchanged(snapshot)
