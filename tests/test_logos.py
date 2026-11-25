"""Offline fixture-based tests for M2 brand logo extraction, validation, hashing, sync, and automation."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from scripts.summarize_sites import summarize_file
from soclens.client import RecordedFutureAPIError, RecordedFutureClient
from soclens.logos.brand_sync import (
    BRAND_SYNC_ISSUE_CATEGORIES,
    SyncLock,
    SyncLockError,
    analyze_brand_sync_issues,
    apply_brand_sync_delta,
    calculate_brand_sync_delta,
    execute_domain_brand_sync,
    filter_brand_issues,
    load_brand_sync_state,
    run_continuous_brand_sync,
    sort_brand_domains,
    sort_brand_issues,
    sort_brand_rows,
    validate_domain_brand_sync,
)
from soclens.logos.extractor import (
    DomainExtractionResult,
    ExtractorConfig,
    decode_data_uri,
    extract_domain_logos,
    extract_domains_logos,
    is_excluded_image,
    load_domain_overrides,
    load_domains_file,
    parse_image_info,
    parse_srcset,
    validate_image_bytes,
)
from soclens.logos.hashing import (
    canonicalize_svg,
    compute_image_hashes,
    compute_inline_svg_hashes,
    load_ignored_hashes,
    match_ignored_hash,
    normalize_hash,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "logos"
REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_fixture(name: str) -> bytes:
    return (FIXTURES_DIR / name).read_bytes()


def _make_distinct_png(r: int, g: int, b: int, w: int = 80, h: int = 40) -> bytes:
    import zlib

    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    row = b"\x00" + bytes((r, g, b, 255)) * w
    idat = zlib.compress(row * h)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def _make_resp(
    *,
    status_code: int = 200,
    text: str = "",
    content: bytes = b"",
    headers: dict[str, str] | None = None,
    url: str = "",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = content
    resp.headers = headers or {}
    resp.url = url

    def _iter_content(chunk_size: int = 65536):
        if content:
            yield content

    resp.iter_content.side_effect = _iter_content
    return resp


# ---------------------------------------------------------------------------
# F7: Multi-Source Discovery, URI/srcset Parsing, Redirects, Retries, Concurrency
# ---------------------------------------------------------------------------


def test_parse_srcset_comma_cdn_and_data_uri() -> None:
    srcset = (
        "/cdn-cgi/image/w=200,fit=contain/logo.png 1x, "
        "/cdn-cgi/image/w=400,fit=contain/logo.png 2x, "
        "data:image/png;base64,iVBORw0KGgo= 3x"
    )
    urls = parse_srcset(srcset)
    assert urls == [
        "/cdn-cgi/image/w=200,fit=contain/logo.png",
        "/cdn-cgi/image/w=400,fit=contain/logo.png",
        "data:image/png;base64,iVBORw0KGgo=",
    ]


def test_decode_data_uri_png_svg_and_rejections() -> None:
    png_bytes = _load_fixture("valid_logo.png")
    import base64

    b64_uri = "data:image/png;base64," + base64.b64encode(png_bytes).decode("ascii")
    decoded = decode_data_uri(b64_uri)
    assert decoded is not None
    raw, mime = decoded
    assert raw == png_bytes
    assert mime == "image/png"

    svg_uri = "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%20100%2040%22%3E%3Crect%20width%3D%22100%22%20height%3D%2240%22%2F%3E%3C%2Fsvg%3E"
    decoded_svg = decode_data_uri(svg_uri)
    assert decoded_svg is not None
    assert b"<svg" in decoded_svg[0]

    assert decode_data_uri("data:text/html,<h1>hi</h1>") is None
    assert decode_data_uri(b64_uri, max_bytes=10) is None


def test_extract_domain_logos_multi_source_rich_fixture(tmp_path: Path) -> None:
    rich_html = (FIXTURES_DIR / "site_rich.html").read_text(encoding="utf-8")
    manifest_bytes = _load_fixture("manifest.json")
    svg_bytes = _load_fixture("valid_logo.svg")

    url_map = {
        "https://acme.example": _make_resp(text=rich_html, url="https://www.acme.example/"),
        "https://www.acme.example/app/manifest.json": _make_resp(
            content=manifest_bytes,
            headers={"Content-Type": "application/manifest+json"},
            url="https://www.acme.example/app/manifest.json",
        ),
        "https://www.acme.example/assets/jsonld-logo.png": _make_resp(
            content=_make_distinct_png(1, 2, 3), headers={"Content-Type": "image/png"}
        ),
        "https://www.acme.example/assets/safari-pinned-brand.svg": _make_resp(
            content=svg_bytes, headers={"Content-Type": "image/svg+xml"}
        ),
        "https://www.acme.example/icons/brand-512x512.png": _make_resp(
            content=_make_distinct_png(4, 5, 6, 192, 192), headers={"Content-Type": "image/png"}
        ),
        "https://www.acme.example/assets/ms-tile-logo.png": _make_resp(
            content=_make_distinct_png(7, 8, 9, 144, 144), headers={"Content-Type": "image/png"}
        ),
        "https://www.acme.example/assets/lazy-brand-logo.png": _make_resp(
            content=_make_distinct_png(10, 11, 12), headers={"Content-Type": "image/png"}
        ),
        "https://www.acme.example/cdn-cgi/image/w=200,fit=contain/logo.png": _make_resp(
            content=_make_distinct_png(13, 14, 15), headers={"Content-Type": "image/png"}
        ),
        "https://www.acme.example/cdn-cgi/image/w=400,fit=contain/logo.png": _make_resp(
            content=_make_distinct_png(16, 17, 18), headers={"Content-Type": "image/png"}
        ),
        "https://www.acme.example/favicon.ico": _make_resp(
            content=_load_fixture("valid_logo.ico"), headers={"Content-Type": "image/x-icon"}
        ),
    }

    session = MagicMock(spec=requests.Session)
    session.get.side_effect = lambda url, **kw: url_map.get(url, _make_resp(status_code=404))

    result = extract_domain_logos(
        "acme.example",
        ignored_hashes={},
        config=ExtractorConfig(),
        session=session,
    )

    assert result.domain_error is None
    included_urls = {logo.image_url for logo in result.logos}
    assert "https://www.acme.example/assets/jsonld-logo.png" in included_urls
    assert "https://www.acme.example/assets/safari-pinned-brand.svg" in included_urls
    assert "https://www.acme.example/icons/brand-512x512.png" in included_urls
    assert "https://www.acme.example/assets/ms-tile-logo.png" in included_urls
    assert "https://www.acme.example/assets/lazy-brand-logo.png" in included_urls
    assert "https://www.acme.example/cdn-cgi/image/w=400,fit=contain/logo.png" in included_urls
    assert any(u.startswith("data:image/png;base64,") for u in included_urls)
    assert "inline-svg://acme.example/1" in included_urls
    # 192x192 manifest icon collapsed in favor of 512x512
    assert "https://www.acme.example/icons/brand-192x192.png" not in included_urls
    # og-hero-banner.jpg rejected by gated og:image
    excluded = [loc for loc in result.discovered_locations if loc["status"] == "excluded"]
    assert any("og-hero-banner.jpg" in loc["url"] for loc in excluded)
    # data: URI was decoded locally, never passed to session.get
    requested_urls = [call.args[0] for call in session.get.call_args_list]
    assert not any(u.startswith("data:") for u in requested_urls)


def test_base_href_and_gated_og_image_acceptance() -> None:
    base_html = (FIXTURES_DIR / "site_base_href.html").read_text(encoding="utf-8")
    og_html = (
        '<html><head>'
        '<meta property="og:image" content="/assets/brand-logo-square.png">'
        '<meta property="og:image:alt" content="Acme Brand Logo">'
        "</head><body></body></html>"
    )
    session = MagicMock(spec=requests.Session)
    session.get.side_effect = [
        _make_resp(text=base_html, url="https://base.example/home"),
        _make_resp(content=_make_distinct_png(21, 22, 23), headers={"Content-Type": "image/png"}),
        _make_resp(content=_load_fixture("valid_logo.ico"), headers={"Content-Type": "image/x-icon"}),
    ]
    res_base = extract_domain_logos("base.example", ignored_hashes={}, session=session)
    assert any(
        logo.image_url == "https://cdn.example.com/static/img/logo.png" for logo in res_base.logos
    )

    session2 = MagicMock(spec=requests.Session)
    session2.get.side_effect = [
        _make_resp(text=og_html, url="https://og.example/"),
        _make_resp(
            content=_make_distinct_png(31, 32, 33, 200, 200),
            headers={"Content-Type": "image/png"},
        ),
        _make_resp(content=_load_fixture("valid_logo.ico"), headers={"Content-Type": "image/x-icon"}),
    ]
    res_og = extract_domain_logos("og.example", ignored_hashes={}, session=session2)
    assert any(
        logo.image_url == "https://og.example/assets/brand-logo-square.png"
        and logo.source == "og:image"
        for logo in res_og.logos
    )


def test_configurable_overrides_and_session_retries_and_concurrency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    overrides_path = tmp_path / "overrides.json"
    overrides_path.write_text(
        json.dumps(
            {
                "ignored_domains": ["noise.example"],
                "force_urls": {"alpha.example": ["https://alpha.example/forced-logo.svg"]},
                "allow_urls": ["https://alpha.example/forced-logo.svg"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RF_LOGO_OVERRIDES_FILE", str(overrides_path))
    cfg = ExtractorConfig.from_overrides(
        load_domain_overrides(),
        max_retries=2,
        backoff_base=0.0,
        max_workers=2,
    )
    assert cfg.verify_ssl is True

    # Test 429 Retry-After + 503 retry recovery
    session = MagicMock(spec=requests.Session)
    main_429 = _make_resp(status_code=429, headers={"Retry-After": "0"})
    main_ok = _make_resp(text="<html><body></body></html>", url="https://alpha.example/")
    forced_503 = _make_resp(status_code=503)
    forced_ok = _make_resp(content=_load_fixture("valid_logo.svg"), headers={"Content-Type": "image/svg+xml"})
    ico_ok = _make_resp(content=_load_fixture("valid_logo.ico"), headers={"Content-Type": "image/x-icon"})

    session.get.side_effect = [main_429, main_ok, forced_503, forced_ok, ico_ok]
    with patch("time.sleep"):
        res = extract_domain_logos("alpha.example", ignored_hashes={}, config=cfg, session=session)
    assert any(logo.image_url == "https://alpha.example/forced-logo.svg" for logo in res.logos)

    # Test ignored override domain + multi-domain bounded concurrency preserving order
    sess_multi = MagicMock(spec=requests.Session)
    sess_multi.get.side_effect = lambda url, **kw: (
        _make_resp(text="<html><body></body></html>", url=url)
        if not url.endswith(".ico")
        else _make_resp(content=_load_fixture("valid_logo.ico"), headers={"Content-Type": "image/x-icon"})
    )
    results = extract_domains_logos(
        ["noise.example", "beta.example"],
        ignored_hashes={},
        config=cfg,
        session=sess_multi,
    )
    assert [r.domain for r in results] == ["noise.example", "beta.example"]
    assert results[0].domain_error == "Ignored domain"
    assert len(results[1].logos) == 1


# ---------------------------------------------------------------------------
# F8: Pure-Python Image Validation & Non-Logo Exclusions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture_name", "expected_fmt", "expected_dims"),
    [
        ("valid_logo.png", "PNG", (120, 40)),
        ("valid_logo.jpg", "JPEG", (120, 40)),
        ("valid_logo.gif", "GIF", (64, 64)),
        ("valid_logo.webp", "WEBP", (100, 40)),
        ("valid_logo.ico", "ICO", (32, 32)),
        ("valid_logo.svg", "SVG", (120, 40)),
    ],
)
def test_pure_python_image_validation_accepts_valid_formats(
    fixture_name: str, expected_fmt: str, expected_dims: tuple[int, int]
) -> None:
    data = _load_fixture(fixture_name)
    ok, info, err = validate_image_bytes(data)
    assert ok is True, err
    assert info is not None
    assert info.format == expected_fmt
    assert (info.width, info.height) == expected_dims


def test_pure_python_image_validation_rejects_soft_404_spacers_empty_svg_banners_and_cap() -> None:
    soft_404 = _load_fixture("soft_404.html")
    ok, _, err = validate_image_bytes(soft_404, content_type="image/png")
    assert ok is False
    assert err is not None

    ok_text, _, _ = validate_image_bytes(_load_fixture("valid_logo.png"), content_type="text/html")
    assert ok_text is False

    for spacer in ("spacer_1x1.png", "spacer_1x1.gif"):
        ok_sp, _, err_sp = validate_image_bytes(_load_fixture(spacer))
        assert ok_sp is False
        assert "spacer" in (err_sp or "").lower()

    empty_svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 381 57"></svg>'
    assert parse_image_info(empty_svg) is None
    assert validate_image_bytes(empty_svg)[0] is False

    promo_jpg = _load_fixture("promo_banner.jpg")
    ok_banner, _, err_banner = validate_image_bytes(promo_jpg)
    assert ok_banner is False
    assert "aspect-ratio" in (err_banner or "").lower()

    # 10 MB size cap enforcement via Content-Length and streaming
    cfg = ExtractorConfig(max_image_bytes=1024)
    assert validate_image_bytes(b"\x89PNG" + b"0" * 2000, config=cfg)[0] is False

    session = MagicMock(spec=requests.Session)
    session.get.side_effect = [
        _make_resp(text='<html><body><img src="/big-logo.png" id="logo"></body></html>', url="https://cap.example/"),
        _make_resp(content=b"", headers={"Content-Length": str(11 * 1024 * 1024)}),
        _make_resp(content=_load_fixture("valid_logo.ico"), headers={"Content-Type": "image/x-icon"}),
    ]
    res = extract_domain_logos("cap.example", ignored_hashes={}, session=session)
    assert any(
        loc["url"].endswith("big-logo.png") and loc["status"] == "empty_or_non_image"
        for loc in res.discovered_locations
    )


def test_exclusion_fixes_widgets_word_boundaries_bypass_third_party_and_domains_file(
    tmp_path: Path,
) -> None:
    # 1. Elementor & HubSpot widgets must NOT exclude legitimate logos
    assert is_excluded_image(
        "https://mybank.com/wp-content/uploads/logo.png",
        "mybank.com",
        parent_classes=["elementor-widget-container", "hs_cos_wrapper_widget"],
    ) == (False, None)

    # 2. Modal / alert classes still excluded
    assert is_excluded_image(
        "https://mybank.com/img/notice.png",
        "mybank.com",
        parent_classes=["modal-body", "alert-body"],
    )[0] is True

    # 3. is_explicit_logo bypass fixed: banner-logo.png allowed, heloc-logo/promo-logo/search-icon excluded
    assert is_excluded_image(
        "https://mybank.com/images/banner-logo.png", "mybank.com", alt="MyBank Logo"
    ) == (False, None)
    assert is_excluded_image("https://mybank.com/images/heloc-logo.png", "mybank.com")[0] is True
    assert is_excluded_image("https://mybank.com/images/promo-logo.png", "mybank.com")[0] is True
    assert is_excluded_image(
        "https://mybank.com/icons/search-icon.svg", "mybank.com", cls="logo"
    )[0] is True

    # 4. Word-boundary & CamelCase splitting
    for safe_url in (
        "https://mybank.com/assets/corporate-logo.png",
        "https://mybank.com/assets/admiralty-logo.png",
        "https://mybank.com/assets/research-logo.png",
        "https://mybank.com/assets/forward-logo.png",
        "https://mybank.com/assets/operating-logo.png",
    ):
        assert is_excluded_image(safe_url, "mybank.com") == (False, None)

    assert is_excluded_image(
        "https://mybank.com/uploads/11mthBusCD_SliderDesktop_V1.jpg", "mybank.com"
    )[0] is True

    # 5. Third-party badge host & B-Corp exclusion
    assert is_excluded_image("https://seal.digicert.com/logo.png", "mybank.com")[0] is True
    assert is_excluded_image(
        "https://mybank.com/uploads/2018-B-Corp-Logo-Black-L.webp", "mybank.com"
    )[0] is True

    # 6. Full fixture HTML check
    excl_html = (FIXTURES_DIR / "site_exclusions.html").read_text(encoding="utf-8")
    session = MagicMock(spec=requests.Session)
    session.get.side_effect = lambda url, **kw: (
        _make_resp(text=excl_html, url="https://mybank.com/")
        if url == "https://mybank.com"
        else _make_resp(content=_make_distinct_png(sum(url.encode()) % 250, 40, 80), headers={"Content-Type": "image/png"})
    )
    res = extract_domain_logos("mybank.com", ignored_hashes={}, session=session)
    included_urls = {logo.image_url for logo in res.logos}
    assert "https://mybank.com/assets/corporate-logo.png" in included_urls
    assert "https://mybank.com/assets/admiralty-logo.png" in included_urls
    assert "https://mybank.com/assets/research-logo.png" in included_urls
    assert "https://seal.digicert.com/logo.png" not in included_urls
    assert "https://mybank.com/assets/fdic_logo.png" not in included_urls
    assert "https://mybank.com/assets/footer-logo.png" not in included_urls
    assert "inline-svg://mybank.com/1" not in included_urls

    # 7. Hardened load_domains_file (BOM, comments, domainbank.com, multi-column CSV, scheme stripping)
    csv_file = tmp_path / "domains.csv"
    csv_file.write_text(
        "\ufeffname,type,domain\n"
        "# comment.com\n"
        "// commented-out.org\n"
        "Acme,Entity,https://DomainBank.com/login\n"
        "Beta,Entity,entitybank.com\n"
        "Gamma,Entity,domainbank.com/\n",
        encoding="utf-8",
    )
    assert load_domains_file(csv_file) == ["domainbank.com", "entitybank.com"]


# ---------------------------------------------------------------------------
# F9: Hashing, Ignored Hashes, Domain-Scoped & Multi-Domain Sync
# ---------------------------------------------------------------------------


def test_hashing_and_ignored_hashes_loader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    svg_a = b'<svg viewBox="0 0 10 10">\n  <!-- comment -->\n  <rect width="10" height="10"/>\n</svg>'
    svg_b = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>'
    assert canonicalize_svg(svg_a) == canonicalize_svg(svg_b)
    assert compute_inline_svg_hashes(svg_a) == compute_inline_svg_hashes(svg_b)

    # Raw asset hashing preserves exact bytes (including .svg)
    raw_svg = _load_fixture("valid_logo.svg")
    raw_hashes = compute_image_hashes(raw_svg)
    assert raw_hashes["sha256"] == hashlib.sha256(raw_svg).hexdigest()

    # Path + workspace fallback + hash: prefix parsing
    ws = tmp_path / "ws"
    ws.mkdir()
    h1 = "a" * 64
    h2 = "b" * 40
    (ws / "ignored_hashes.txt").write_text(
        f"hash:{h1}\n{h2}: Vendor noise\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SOCLENS_HOME", str(ws))
    loaded = load_ignored_hashes()
    assert h1 in loaded
    assert loaded[h2] == "Vendor noise"
    assert normalize_hash(f"HASH:{h1.upper()}") == h1
    assert match_ignored_hash({"sha1": h2}, loaded)[0] == h2


def test_domain_scoped_failure_aware_and_multi_domain_delta_sync() -> None:
    hash_a_old = "1" * 64
    hash_a_new = "2" * 64
    hash_b = "3" * 64
    hash_shared = "4" * 64

    client = MagicMock(spec=RecordedFutureClient)
    client.get_watchlist_entities.return_value = [
        {
            "entity": {"name": hash_a_old, "id": "ent_a_old", "type": "Hash"},
            "context": {"source": "automated-watchlist-manager", "domain": "a.com"},
        },
        {
            "entity": {"name": hash_b, "id": "ent_b", "type": "Hash"},
            "context": {"source": "automated-watchlist-manager", "domain": "b.com"},
        },
        {
            "entity": {"name": hash_shared, "id": "ent_shared", "type": "Hash"},
            "context": {
                "source": "automated-watchlist-manager",
                "domain": "a.com",
                "domains": ["a.com", "b.com"],
            },
        },
    ]

    # Single-domain scoped sync for a.com (R6): must NOT remove b.com or shared [a.com, b.com]!
    def _hasher(domain: str, *args: Any, **kwargs: Any):
        if domain == "a.com":
            return ([{"sha256": hash_a_new, "image_url": "https://a.com/logo.png"}], 1, None, [], [])
        return ([], 0, "Connection failed", [], [])

    target, _, to_add, to_remove, _, _ = calculate_brand_sync_delta(
        client,
        "list_1",
        ["a.com"],
        output_locations_file=None,
        ignored_hashes={},
        scoped_domains={"a.com"},
        state_file=None,
        image_hasher=_hasher,
    )
    assert to_add == [hash_a_new]
    removed_names = {e["name"] for e in to_remove}
    assert hash_a_old in removed_names
    assert hash_b not in removed_names
    assert hash_shared not in removed_names

    # Multi-domain attribution across a.com & b.com when both succeed
    def _shared_hasher(domain: str, *args: Any, **kwargs: Any):
        if domain == "a.com":
            return ([{"sha256": hash_shared, "image_url": "https://a.com/shared.png"}], 1, None, [], [])
        return ([{"sha256": hash_shared, "image_url": "https://b.com/shared.png"}], 1, None, [], [])

    target2, _, to_add2, _, _, _ = calculate_brand_sync_delta(
        client,
        "list_1",
        ["b.com", "a.com"],
        output_locations_file=None,
        ignored_hashes={},
        state_file=None,
        image_hasher=_shared_hasher,
    )
    assert target2[hash_shared]["domains"] == ["a.com", "b.com"]
    assert to_add2 == []

    # Verify apply_brand_sync_delta writes multi-domain context & handles API errors cleanly
    client.add_entity.return_value = {"result": "added"}
    added, _ = apply_brand_sync_delta(
        client,
        "list_1",
        {hash_shared: target2[hash_shared]},
        [hash_shared],
        [],
        dry_run=False,
        existing_count=950,
    )
    assert added == 1
    ctx = client.add_entity.call_args.kwargs["context"]
    assert ctx["domains"] == ["a.com", "b.com"]
    assert "a.com, b.com" in ctx["annotation"]


def test_rf_api_error_aborts_non_destructively() -> None:
    client = MagicMock(spec=RecordedFutureClient)
    client.get_watchlist_entities.side_effect = RecordedFutureAPIError(
        500, "Server error", trace_id="trace-xyz"
    )
    def _stub_hasher(*_a: Any, **_k: Any) -> tuple[list[dict[str, str]], int, None, list[str], list[dict[str, Any]]]:
        return (
            [{"sha256": "a" * 64, "image_url": "https://a.com/logo.png"}],
            1,
            None,
            [],
            [],
        )

    assert (
        validate_domain_brand_sync(
            client,
            "list_1",
            ["a.com"],
            output_locations_file=None,
            ignored_hashes={},
            image_hasher=_stub_hasher,
        )
        is False
    )
    assert (
        execute_domain_brand_sync(
            client,
            "list_1",
            ["a.com"],
            dry_run=False,
            output_locations_file=None,
            ignored_hashes={},
            state_file=None,
            image_hasher=_stub_hasher,
        )
        is False
    )


# ---------------------------------------------------------------------------
# F10: State Grace Period, Continuous Loop, Cross-Platform Lockfile & Scripts
# ---------------------------------------------------------------------------


def test_state_grace_period_and_recovery(tmp_path: Path) -> None:
    state_path = tmp_path / "brand_sync_state.json"
    hash_a = "5" * 64
    client = MagicMock(spec=RecordedFutureClient)
    client.get_watchlist_entities.return_value = [
        {
            "entity": {"name": hash_a, "id": "ent_a", "type": "Hash"},
            "context": {"source": "automated-watchlist-manager", "domain": "a.com"},
        }
    ]
    client.remove_entity.return_value = {"result": "removed"}

    def _failing_hasher(domain: str, *args: Any, **kwargs: Any):
        return ([], 0, "Connection timeout", [], [])

    # Failure 1 & 2: hash_a preserved; consecutive_failures increments
    for expected_fail_count in (1, 2):
        ok = execute_domain_brand_sync(
            client,
            "list_1",
            ["a.com"],
            dry_run=False,
            output_locations_file=None,
            ignored_hashes={},
            state_grace_failures=3,
            state_file=state_path,
            image_hasher=_failing_hasher,
        )
        assert ok is False
        client.remove_entity.assert_not_called()
        st = load_brand_sync_state(state_path)
        assert st["domains"]["a.com"]["consecutive_failures"] == expected_fail_count

    # Failure 3: grace period exhausted -> stale hash removed
    ok3 = execute_domain_brand_sync(
        client,
        "list_1",
        ["a.com"],
        dry_run=False,
        output_locations_file=None,
        ignored_hashes={},
        state_grace_failures=3,
        state_file=state_path,
        image_hasher=_failing_hasher,
    )
    assert ok3 is True
    client.remove_entity.assert_called_once_with("list_1", "ent_a")

    # Recovery resets consecutive_failures to 0
    ok_rec = execute_domain_brand_sync(
        client,
        "list_1",
        ["a.com"],
        dry_run=False,
        output_locations_file=None,
        ignored_hashes={},
        state_grace_failures=3,
        state_file=state_path,
        image_hasher=lambda *a, **k: (
            [{"sha256": hash_a, "image_url": "https://a.com/logo.png"}],
            1,
            None,
            [],
            [],
        ),
    )
    assert ok_rec is True
    assert load_brand_sync_state(state_path)["domains"]["a.com"]["consecutive_failures"] == 0


def test_sync_lock_active_and_stale_recovery(tmp_path: Path) -> None:
    lock_path = tmp_path / ".brand_sync.lock"
    with SyncLock(lock_path) as lock:
        assert lock_path.is_file()
        with pytest.raises(SyncLockError):
            SyncLock(lock_path).acquire()
        assert lock.lock_path == lock_path
    assert not lock_path.exists()

    # Stale lock with dead PID is recovered automatically
    import socket

    lock_path.write_text(
        json.dumps({"pid": 99999999, "hostname": socket.gethostname(), "epoch": 1.0}),
        encoding="utf-8",
    )
    with SyncLock(lock_path, stale_seconds=1.0):
        assert lock_path.is_file()
    assert not lock_path.exists()


def test_run_continuous_brand_sync_max_runs_and_resilience(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    lock_path = tmp_path / "sync.lock"
    stop_event = threading.Event()
    client = MagicMock(spec=RecordedFutureClient)
    client.get_watchlist_entities.side_effect = [
        RecordedFutureAPIError(429, "Rate limit", trace_id="t1"),
        [],
    ]
    client.add_entity.return_value = {"result": "added"}

    summary = run_continuous_brand_sync(
        client,
        "list_1",
        ["a.com"],
        dry_run=False,
        output_locations_file=None,
        ignored_hashes={},
        interval_seconds=0.0,
        max_runs=2,
        state_file=state_path,
        lock_file=lock_path,
        stop_event=stop_event,
        image_hasher=lambda *a, **k: (
            [{"sha256": "6" * 64, "image_url": "https://a.com/logo.png"}],
            1,
            None,
            [],
            [],
        ),
    )
    assert summary["runs_attempted"] == 2
    assert summary["runs_failed"] == 1
    assert summary["runs_succeeded"] == 1
    assert not lock_path.exists()
    assert state_path.is_file()


def test_summarize_sites_and_automation_templates(tmp_path: Path) -> None:
    locs_file = tmp_path / "locs.json"
    locs_file.write_text(
        json.dumps(
            [
                {
                    "domain": "a.com",
                    "url": "https://a.com/logo.png",
                    "status": "included",
                    "sha256": "7" * 64,
                },
                {
                    "domain": "b.com",
                    "url": "https://b.com/logo.png",
                    "status": "included",
                    "sha256": "7" * 64,
                },
                {
                    "domain": "b.com",
                    "url": "https://b.com/fdic.png",
                    "status": "excluded",
                    "exclusion_reason": "FDIC",
                },
            ]
        ),
        encoding="utf-8",
    )
    assert summarize_file(locs_file) == 0
    assert summarize_file(tmp_path / "missing.json") == 1

    bad_json = tmp_path / "bad.json"
    bad_json.write_text('{"not": "a list"}', encoding="utf-8")
    assert summarize_file(bad_json) == 1

    ps1 = REPO_ROOT / "scripts" / "soclens-brand-sync.ps1"
    xml_path = REPO_ROOT / "scripts" / "soclens-brand-sync-task.xml"
    service = REPO_ROOT / "scripts" / "soclens-brand-sync.service"
    timer = REPO_ROOT / "scripts" / "soclens-brand-sync.timer"
    readme = REPO_ROOT / "scripts" / "README_AUTOMATION.md"

    for p in (ps1, xml_path, service, timer, readme):
        assert p.is_file() and p.stat().st_size > 0

    ET.parse(xml_path)
    ET.fromstring(xml_path.read_bytes())
    assert "OnUnitActiveSec=" in timer.read_text(encoding="utf-8")
    assert "ExecStart=" in service.read_text(encoding="utf-8")
    ps1_text = ps1.read_text(encoding="utf-8")
    assert "SOCLENS_AUTO_APPROVE" in ps1_text
    assert "--source-list-id" in ps1_text
    assert "--source-list " not in ps1_text
    assert "load_domains_file" not in ps1_text
    assert '$ErrorActionPreference = "Continue"' in ps1_text
    assert os.linesep in ps1_text or "\n" in ps1_text


# ---------------------------------------------------------------------------
# Iteration 2 Hardening Regression Tests
# ---------------------------------------------------------------------------


def test_svg_html_soft404_and_prologue_handling() -> None:
    # HTML soft-404 preceded by comment + embedded <svg> must be rejected
    html_comment_svg = (
        b"<!-- soft 404 page -->\n"
        b"<!DOCTYPE html><html><head><meta charset='utf-8'></head>"
        b"<body><h1>404 Not Found</h1>"
        b"<svg width='100' height='100'><path d='M0 0'/></svg>"
        b"</body></html>"
    )
    ok, info, err = validate_image_bytes(html_comment_svg, content_type="image/svg+xml")
    assert ok is False
    assert info is None
    assert err is not None

    # HTML fragment without <!doctype>/<html> but with <body><svg> also rejected
    html_fragment = b"<!-- wrapper --><div class='err'><svg width='80' height='40'><rect width='80' height='40'/></svg></div>"
    assert validate_image_bytes(html_fragment, content_type="image/svg+xml")[0] is False

    # Valid SVG with XML declaration, comment, DOCTYPE, and undeclared xlink prefix must succeed
    valid_prologue_svg = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b"<!-- Brand Logo -->\n"
        b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n'
        b'<svg width="120" height="40"><use xlink:href="#mark"/><rect width="120" height="40"/></svg>'
    )
    ok_valid, info_valid, err_valid = validate_image_bytes(
        valid_prologue_svg, content_type="image/svg+xml"
    )
    assert ok_valid is True, err_valid
    assert info_valid is not None
    assert info_valid.format == "SVG"
    assert (info_valid.width, info_valid.height) == (120, 40)


def test_corrupt_jpeg_rejected_and_webp_vp8l_25b_accepted() -> None:
    # Truncated / corrupt JPEGs without valid SOF dimensions must be rejected
    assert parse_image_info(b"\xff\xd8\xffCORRUPT_NOT_A_JPEG") is None
    ok_jpg, info_jpg, _ = validate_image_bytes(
        b"\xff\xd8\xffCORRUPT_NOT_A_JPEG", content_type="image/jpeg"
    )
    assert ok_jpg is False
    assert info_jpg is None

    # Valid 25-byte WebP VP8L header (128x64)
    w_minus_1 = 128 - 1
    h_minus_1 = 64 - 1
    packed = w_minus_1 | (h_minus_1 << 14)
    vp8l_25 = (
        b"RIFF"
        + struct.pack("<I", 17)
        + b"WEBP"
        + b"VP8L"
        + struct.pack("<I", 5)
        + b"\x2f"
        + struct.pack("<I", packed)
    )
    assert len(vp8l_25) == 25
    ok_webp, info_webp, err_webp = validate_image_bytes(vp8l_25, content_type="image/webp")
    assert ok_webp is True, err_webp
    assert info_webp is not None
    assert info_webp.format == "WEBP"
    assert (info_webp.width, info_webp.height) == (128, 64)

    # Truncated 25-byte VP8 / VP8X headers must still be rejected
    vp8_short = b"RIFF" + struct.pack("<I", 17) + b"WEBP" + b"VP8 " + b"\x00" * 9
    assert len(vp8_short) == 25
    assert parse_image_info(vp8_short) is None


def test_kw_matches_multi_word_word_boundaries() -> None:
    # Legitimate logos that contain multi-word exclusion substrings across token boundaries
    for legit_url, target_dom, alt in (
        ("https://apexbank.com/assets/apex-logo.png", "apexbank.com", "Apex Bank Logo"),
        ("https://essex.com/assets/essex-logo.png", "essex.com", "Essex Bank"),
        ("https://cfb.com/assets/cfb-logo.png", "cfb.com", "CFB Bank"),
        ("https://webcorp.com/assets/web-corporate-logo.png", "webcorp.com", "Web Corporate"),
        ("https://webcorp.com/assets/web-corporate-logo.png", "example.com", "Web Corporate"),
        ("https://stopceo.com/assets/stop-ceo-logo.png", "stopceo.com", "Stop CEO"),
        ("https://bestbank.com/assets/best-offer-logo.png", "bestbank.com", "Best Offer Logo"),
        ("https://cfb-logo.com/assets/brand.png", "example.com", "CFB Brand"),
    ):
        excl, reason = is_excluded_image(legit_url, target_dom, alt=alt)
        assert excl is False, f"{legit_url} falsely excluded: {reason}"

    # Actual exclusion targets must still be excluded
    for bad_url in (
        "https://example.com/social/x-logo.png",
        "https://example.com/social/fb-logo.png",
        "https://example.com/badges/2018-B-Corp-Logo-Black-L.webp",
        "https://example.com/awards/top-ceo-2025.png",
        "https://example.com/awards/best-of-2025.png",
    ):
        excl, _ = is_excluded_image(bad_url, "example.com")
        assert excl is True, f"{bad_url} should have been excluded"


def test_ignored_hashes_combined_comments_and_workspace_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h_hash = "1" * 64
    h_comma = "2" * 64
    h_colon = "3" * 64
    h_space = "4" * 64

    cwd_dir = tmp_path / "cwd"
    ws_dir = tmp_path / "ws"
    cwd_dir.mkdir()
    ws_dir.mkdir()

    (cwd_dir / "ignored_hashes.txt").write_text(f"{'9' * 64} # CWD hash\n", encoding="utf-8")
    (ws_dir / "ignored_hashes.txt").write_text(
        f"hash:{h_hash} # hash prefix + hash comment\n"
        f"{h_comma}, comma reason # comma + hash comment\n"
        f"{h_colon}: colon reason # colon + hash comment\n"
        f"{h_space} space reason # space + hash comment\n",
        encoding="utf-8",
    )

    monkeypatch.chdir(cwd_dir)
    loaded = load_ignored_hashes(workspace_dir=ws_dir)
    assert h_hash in loaded
    assert h_comma in loaded
    assert h_colon in loaded
    assert h_space in loaded
    assert "9" * 64 not in loaded
    assert "comma reason" in loaded[h_comma]
    assert "colon reason" in loaded[h_colon]
    assert "space reason" in loaded[h_space]


def test_execute_domain_brand_sync_default_state_persistence_and_opt_out(
    tmp_path: Path,
) -> None:
    from soclens.logos.brand_sync import DEFAULT_STATE_FILENAME, resolve_state_path

    ws = tmp_path / "ws"
    ws.mkdir()
    assert resolve_state_path(DEFAULT_STATE_FILENAME, ws) == ws.resolve() / DEFAULT_STATE_FILENAME

    hash_a = "a" * 64
    client = MagicMock(spec=RecordedFutureClient)
    client.get_watchlist_entities.return_value = [
        {
            "entity": {"name": hash_a, "id": "ent_a", "type": "Hash"},
            "context": {"source": "automated-watchlist-manager", "domain": "a.com"},
        }
    ]
    client.remove_entity.return_value = {"result": "removed"}

    # One-shot scheduled sync (default state_file) must persist state inside workspace_dir
    ok1 = execute_domain_brand_sync(
        client,
        "list_1",
        ["a.com"],
        dry_run=False,
        output_locations_file=None,
        ignored_hashes={},
        state_grace_failures=3,
        workspace_dir=ws,
        image_hasher=lambda *a, **k: ([], 0, "Timeout", [], []),
    )
    assert ok1 is False
    default_state_path = ws / DEFAULT_STATE_FILENAME
    assert default_state_path.is_file()
    assert load_brand_sync_state(default_state_path)["domains"]["a.com"]["consecutive_failures"] == 1

    # Explicit state_file=None opts out of state reads/writes
    ws_optout = tmp_path / "ws_optout"
    ws_optout.mkdir()
    ok_opt = execute_domain_brand_sync(
        client,
        "list_1",
        ["a.com"],
        dry_run=False,
        output_locations_file=None,
        ignored_hashes={},
        state_file=None,
        workspace_dir=ws_optout,
        image_hasher=lambda *a, **k: (
            [{"sha256": hash_a, "image_url": "https://a.com/logo.png"}],
            1,
            None,
            [],
            [],
        ),
    )
    assert ok_opt is True
    assert not (ws_optout / DEFAULT_STATE_FILENAME).exists()


def test_minor_hardening_manifest_close_rel_list_annotation_and_win_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ctypes

    from soclens.logos.brand_sync import (
        _extract_entry_domains,
        extract_domains_from_watchlist_entities,
        is_pid_alive,
    )

    # 1. Non-200 manifest response is explicitly closed
    manifest_404 = _make_resp(status_code=404)
    html_with_manifest = (
        '<html><head><link rel="manifest" href="/manifest.json"></head>'
        '<body><img src="/logo.png" id="logo"></body></html>'
    )
    session = MagicMock(spec=requests.Session)
    session.get.side_effect = [
        _make_resp(text=html_with_manifest, url="https://m.example/"),
        manifest_404,
        _make_resp(content=_make_distinct_png(5, 6, 7), headers={"Content-Type": "image/png"}),
        _make_resp(content=_load_fixture("valid_logo.ico"), headers={"Content-Type": "image/x-icon"}),
    ]
    res = extract_domain_logos("m.example", ignored_hashes={}, session=session)
    manifest_404.close.assert_called_once()
    assert any(logo.image_url == "https://m.example/logo.png" for logo in res.logos)

    # 2. Annotation domain regex rejects tokens containing spaces
    client = MagicMock(spec=RecordedFutureClient)
    client.get_watchlist_entities.return_value = [
        {
            "entity": {"name": "e" * 64, "type": "Hash"},
            "context": {"annotation": "Automated sync: Brand image for bad domain.com extra"},
        },
        {
            "entity": {"name": "f" * 64, "type": "Hash"},
            "context": {"annotation": "Automated sync: Brand image for good.example (URL: https://good.example/l.png)"},
        },
    ]
    assert extract_domains_from_watchlist_entities(client, "list_1") == ["good.example"]
    assert _extract_entry_domains(client.get_watchlist_entities.return_value[0], "e" * 64, {}) == set()

    # 3. Windows is_pid_alive uses WinDLL(use_last_error=True), c_void_p restype, get_last_error
    mock_kernel32 = MagicMock()
    mock_kernel32.OpenProcess.return_value = None
    mock_windll = MagicMock(return_value=mock_kernel32)
    monkeypatch.setattr("soclens.logos.brand_sync.os.name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", mock_windll, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    assert is_pid_alive(1234) is True
    mock_windll.assert_called_once_with("kernel32", use_last_error=True)
    assert mock_kernel32.OpenProcess.restype is ctypes.c_void_p
    assert mock_kernel32.CloseHandle.argtypes == [ctypes.c_void_p]


def test_png_ihdr_crc_validation_soc2_exclusion_and_host_port_annotation() -> None:
    from soclens.logos.brand_sync import (
        _extract_entry_domains,
        extract_domains_from_watchlist_entities,
    )

    # (a) Corrupted PNG with invalid IHDR fields / CRC-32 must be rejected
    corrupt_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (b"\xff" * 64)
    assert parse_image_info(corrupt_png) is None
    ok_corrupt, info_corrupt, _ = validate_image_bytes(
        corrupt_png, content_type="image/png"
    )
    assert ok_corrupt is False
    assert info_corrupt is None

    # (b) Compliance badges (e.g., SOC 2) must be excluded
    excl_soc2, reason_soc2 = is_excluded_image(
        "http://127.0.0.1:8080/badges/soc2-badge.png",
        "127.0.0.1:8080",
    )
    assert excl_soc2 is True
    assert reason_soc2 is not None and "soc" in reason_soc2.lower()

    # (c) Annotation domain parser preserves host:port while stripping trailing punctuation
    entry = {
        "entity": {"name": "a" * 64, "type": "Hash"},
        "context": {
            "annotation": "Automated sync: Brand image for 127.0.0.1:8080, 127.0.0.1:8081."
        },
    }
    assert _extract_entry_domains(entry, "a" * 64, {}) == {
        "127.0.0.1:8080",
        "127.0.0.1:8081",
    }
    client = MagicMock(spec=RecordedFutureClient)
    client.get_watchlist_entities.return_value = [entry]
    assert extract_domains_from_watchlist_entities(client, "list_1") == [
        "127.0.0.1:8080",
        "127.0.0.1:8081",
    ]


def test_read_response_bytes_empty_real_response_and_concurrent_brand_sync() -> None:
    import io

    import urllib3

    from soclens.logos.extractor import DomainExtractionResult, _read_response_bytes

    # 1. Real streaming requests.Response with 0-byte body must return b"" cleanly
    empty_resp = requests.Response()
    empty_resp.status_code = 200
    empty_resp._content = False  # type: ignore[assignment]
    empty_resp._content_consumed = False
    empty_resp.raw = urllib3.response.HTTPResponse(body=io.BytesIO(b""), preload_content=False)
    data, err = _read_response_bytes(empty_resp, 1024)
    assert (data, err) == (b"", None)

    # 2. Stream read errors during iter_content return structured error instead of crashing
    broken_resp = MagicMock()
    broken_resp.headers = {}
    broken_resp.iter_content.side_effect = requests.exceptions.ChunkedEncodingError(
        "premature EOF"
    )
    bad_data, bad_err = _read_response_bytes(broken_resp, 1024)
    assert bad_data is None
    assert bad_err is not None and "stream read error" in bad_err.lower()

    # 3. calculate_brand_sync_delta delegates multi-domain unpatched runs to extract_domains_logos
    client = MagicMock(spec=RecordedFutureClient)
    client.get_watchlist_entities.return_value = []
    with patch("soclens.logos.brand_sync.extract_domains_logos") as mock_multi:
        mock_multi.return_value = [
            DomainExtractionResult(domain="a.com"),
            DomainExtractionResult(domain="b.com"),
        ]
        calculate_brand_sync_delta(
            client,
            "list_1",
            ["a.com", "b.com"],
            output_locations_file=None,
            ignored_hashes={},
        )
    mock_multi.assert_called_once_with(["a.com", "b.com"], ignored_hashes={})


def test_accuracy_tuning_svg_ratio_jsonld_clients_srcset_and_bot_gate() -> None:
    # 1. Wide 320x40 SVG (ratio 8.0) and 700x100 PNG wordmark (ratio 7.0 <= 10.5) accepted;
    #    1200x100 PNG banner (ratio 12.0 > 10.5) and 100x700 vertical PNG (ratio 7.0 > 6.0) rejected
    wide_svg = (
        b'<svg xmlns="http://www.w3.org/2000/svg" width="320" height="40" '
        b'viewBox="0 0 320 40"><rect width="320" height="40"/></svg>'
    )
    ok_svg, info_svg, err_svg = validate_image_bytes(wide_svg, content_type="image/svg+xml")
    assert ok_svg is True, err_svg
    assert info_svg is not None and info_svg.format == "SVG"

    wide_wordmark_png = _make_distinct_png(1, 2, 3, w=700, h=100)
    ok_wordmark, _, err_wordmark = validate_image_bytes(wide_wordmark_png, content_type="image/png")
    assert ok_wordmark is True, err_wordmark

    banner_png = _make_distinct_png(1, 2, 3, w=1200, h=100)
    ok_banner, _, err_banner = validate_image_bytes(banner_png, content_type="image/png")
    assert ok_banner is False
    assert err_banner is not None and "aspect-ratio" in err_banner.lower()

    tall_png = _make_distinct_png(1, 2, 3, w=100, h=700)
    ok_tall, _, err_tall = validate_image_bytes(tall_png, content_type="image/png")
    assert ok_tall is False
    assert err_tall is not None and "aspect-ratio" in err_tall.lower()

    # 2. Client showcase, blog tile prose alt, sidebar, kofe, Tailwind utility, pause SVG, word boundaries
    for bad_kw_url, alt, p_cls in (
        ("https://bank.example/assets/Asset14.png", "Wildgrain", ["client-logo", "clients-grid"]),
        ("https://bank.example/files/HuskyHack-FeaturedImg.jpg", "A split background with logos for Husky Hack and Credit Union", ["wp-post-image", "co-post_tile"]),
        ("https://bank.example/themes/demo-sidebar-eaglenet-logo.png", "Eaglenet", []),
        ("https://bank.example/uploads/kofe-logo-1.png", "KOFE", []),
    ):
        excl, _ = is_excluded_image(
            bad_kw_url, "bank.example", alt=alt, cls=" ".join(p_cls), parent_classes=p_cls
        )
        assert excl is True, f"Expected exclusion for {bad_kw_url}"

    # "display" / "replay" must not trigger word-boundary UI icon 'play'
    assert is_excluded_image("https://displaybank.example/assets/replay-display-logo.png", "displaybank.example")[0] is False

    # 3. Full DOM checks: JSON-LD agency skip, WordPress srcset dedup, Tailwind SVG skip, pause button SVG skip
    html = (
        "<html><head>"
        '<script type="application/ld+json">'
        '{"@graph":[{"@id":"https://www.imarc.com/#creator","@type":"Organization","logo":"/imarc.png"},'
        '{"@id":"https://bank.example/#identity","@type":"BankOrCreditUnion","logo":"/bank-schema.png"}]}'
        "</script>"
        "</head><body>"
        '<header><a class="text-brand-dark-gray"><svg aria-hidden="true" viewBox="0 0 18 22"><path d="M0 0"/></svg></a></header>'
        '<button class="autoplay-controls"><svg class="pause-icon-logos" viewBox="0 0 24 24"><rect width="24" height="24"/></svg></button>'
        '<div class="clients-grid"><img class="client-logo" src="/clients/a.png" alt="Client"></div>'
        '<div class="co-post_tile"><img class="wp-post-image" src="/blog/event.png" alt="A split white background showing logos of two partners at event"></div>'
        '<img class="site-logo" src="/wp/Logo-200x58.png" srcset="/wp/Logo-200x58.png 200w, /wp/Logo-400x116.png 400w, /wp/Logo.png 800w" alt="Bank Logo">'
        "</body></html>"
    )
    sess = MagicMock(spec=requests.Session)
    sess.get.side_effect = [
        _make_resp(text=html, url="https://bank.example/"),
        _make_resp(content=_make_distinct_png(10, 20, 30), headers={"Content-Type": "image/png"}),
        _make_resp(content=_make_distinct_png(40, 50, 60), headers={"Content-Type": "image/png"}),
        _make_resp(content=_load_fixture("valid_logo.ico"), headers={"Content-Type": "image/x-icon"}),
    ]
    res = extract_domain_logos("bank.example", ignored_hashes={}, session=sess)
    included_urls = {logo.image_url for logo in res.logos}
    assert "https://bank.example/bank-schema.png" in included_urls
    assert "https://bank.example/wp/Logo.png" in included_urls
    assert "https://bank.example/favicon.ico" in included_urls
    assert "https://bank.example/imarc.png" not in included_urls
    assert "https://bank.example/wp/Logo-200x58.png" not in included_urls
    assert "https://bank.example/wp/Logo-400x116.png" not in included_urls
    assert not any(u.startswith("inline-svg://") for u in included_urls)
    assert any(
        loc.get("status") == "excluded" and "Logo-200x58.png" in str(loc.get("url", ""))
        for loc in res.discovered_locations
    )

    # 4. HTTP 200 parking/bot interstitial triggers domain_error and delta grace protection
    bot_html = '<html><head><script>if (!"gdprAppliesGlobally" in window) {}</script></head><body></body></html>'
    sess_bot = MagicMock(spec=requests.Session)
    sess_bot.get.return_value = _make_resp(text=bot_html, url="https://parked.example/")
    bot_res = extract_domain_logos("parked.example", ignored_hashes={}, session=sess_bot)
    assert bot_res.domain_error is not None and "bot challenge" in bot_res.domain_error.lower()

    client = MagicMock(spec=RecordedFutureClient)
    client.get_watchlist_entities.return_value = [
        {
            "entity": {"name": "a" * 64, "id": "hash:" + "a" * 64, "type": "Hash"},
            "context": {"source": "automated-watchlist-manager", "domain": "parked.example"},
        }
    ]
    _, _, _, to_remove, dom_errs, _ = calculate_brand_sync_delta(
        client,
        "list_1",
        ["parked.example"],
        output_locations_file=None,
        ignored_hashes={},
        state_file=None,
        image_hasher=lambda *a, **k: ([], 0, None, [], [{"status": "empty_or_non_image", "url": "https://parked.example/favicon.ico"}]),
    )
    assert to_remove == []
    assert dom_errs == {}


def test_v3_accuracy_inline_style_savings_ehl_webflow_fallback_and_parking() -> None:
    # 1. Savings Bank institutional exemptions + final_root check + combined logo-w-EHL exemption
    assert (
        is_excluded_image(
            "https://oakcitybank.example/wp-content/uploads/Oak_City_Savings_Bank-1.png",
            "oakcitybank.example",
            alt="Oak City Savings Bank Click to return to the home page.",
            source="header/brand home link img",
        )[0]
        is False
    )
    assert (
        is_excluded_image(
            "https://savingsunion.example/assets/img/savingsunion-for-savings-logo.svg",
            "savingsunion.example",
            source="schema.org JSON-LD logo",
        )[0]
        is False
    )
    assert (
        is_excluded_image(
            "https://www.cedarsavingsbank.example/themes/worx/images/csb-horizontal-logo.svg",
            "cedarsb.example",
            final_host="www.cedarsavingsbank.example",
            source="img tag with 'logo' or 'brand'",
        )[0]
        is False
    )
    assert (
        is_excluded_image(
            "https://bank.example/promos/savings-account-promo.png",
            "bank.example",
            alt="High Yield Savings Promo",
        )[0]
        is True
    )
    assert (
        is_excluded_image(
            "https://bank.example/promos/high-yield-savings.jpg",
            "bank.example",
        )[0]
        is True
    )
    assert (
        is_excluded_image(
            "https://newport.example/img/logo/logo-w-EHL.png",
            "newport.example",
            alt="logo",
            source="img tag with 'logo' or 'brand'",
        )[0]
        is False
    )
    assert is_excluded_image("https://newport.example/img/ehl-logo.png", "newport.example")[0] is True
    assert is_excluded_image("https://newport.example/img/equal-housing-lender.png", "newport.example")[0] is True
    assert (
        is_excluded_image(
            "https://newport.example/img/logo/logo-w-EHL.png",
            "newport.example",
            alt="logo",
            parent_tags=["footer"],
        )[0]
        is True
    )

    # 2. Inline <style> CSS background-image logo + retina dedup, Webflow prefix icon dedup,
    #    nav-link-arrow / icon-size-xsmall exclusion, and S2 404 icon fallback
    html = (
        "<html><head>"
        "<style>"
        "header #logo a { background-image: url('/media/1031/logo.png?width=242&amp;height=49'); }"
        "@media (min-resolution: 2dppx) { header #logo a { background-image: url('/media/1031/logo.png?width=484&amp;height=98'); } }"
        "footer #logo a { background-image: url('/media/9999/footer-logo.png'); }"
        "</style>"
        '<link rel="icon" sizes="32x32" href="https://cdn.example/111111111111111111111111_webclip.png">'
        '<link rel="icon" sizes="192x192" href="https://cdn.example/222222222222222222222222_webclip.png">'
        '<link rel="icon" sizes="512x512" href="https://cdn.example/333333333333333333333333_webclip.png">'
        '<link rel="apple-touch-icon" sizes="152x152" href="/apple-touch-icon-152x152.png">'
        '<link rel="apple-touch-icon" sizes="120x120" href="/apple-touch-icon-120x120.png">'
        '<link rel="apple-touch-icon" sizes="76x76" href="/apple-touch-icon-76x76.png">'
        "</head><body>"
        '<div id="logo"><a href="/">Example Bank</a></div>'
        '<a class="nav-link-arrow"><img class="icon-size-xsmall" src="/Vector.svg" alt=""></a>'
        '<img src="/img/logo/logo-w-EHL.png" alt="logo">'
        "</body></html>"
    )
    css_logo_png = _make_distinct_png(11, 22, 33, w=484, h=98)
    webclip_512 = _make_distinct_png(44, 55, 66, w=512, h=512)
    touch_120 = _make_distinct_png(77, 88, 99, w=120, h=120)
    ehl_logo = _make_distinct_png(101, 111, 121, w=180, h=60)

    def _route_bank(url: str, *args: Any, **kwargs: Any) -> MagicMock:
        if url == "https://cssbank.example":
            return _make_resp(text=html, url="https://cssbank.example/")
        if url == "https://cssbank.example/media/1031/logo.png?width=484&height=98":
            return _make_resp(content=css_logo_png, headers={"Content-Type": "image/png"})
        if url == "https://cdn.example/333333333333333333333333_webclip.png":
            return _make_resp(content=webclip_512, headers={"Content-Type": "image/png"})
        if url == "https://cssbank.example/apple-touch-icon-152x152.png":
            return _make_resp(status_code=404, url=url)
        if url == "https://cssbank.example/apple-touch-icon-120x120.png":
            return _make_resp(content=touch_120, headers={"Content-Type": "image/png"})
        if url == "https://cssbank.example/img/logo/logo-w-EHL.png":
            return _make_resp(content=ehl_logo, headers={"Content-Type": "image/png"})
        if url == "https://cssbank.example/favicon.ico":
            return _make_resp(content=_load_fixture("valid_logo.ico"), headers={"Content-Type": "image/x-icon"})
        return _make_resp(status_code=404, url=url)

    sess = MagicMock(spec=requests.Session)
    sess.get.side_effect = _route_bank
    res = extract_domain_logos("cssbank.example", ignored_hashes={}, session=sess)
    included_urls = {logo.image_url for logo in res.logos}
    assert "https://cssbank.example/media/1031/logo.png?width=484&height=98" in included_urls
    assert "https://cssbank.example/media/1031/logo.png?width=242&height=49" not in included_urls
    assert "https://cssbank.example/media/9999/footer-logo.png" not in included_urls
    assert "https://cdn.example/333333333333333333333333_webclip.png" in included_urls
    assert "https://cdn.example/111111111111111111111111_webclip.png" not in included_urls
    assert "https://cdn.example/222222222222222222222222_webclip.png" not in included_urls
    assert "https://cssbank.example/apple-touch-icon-120x120.png" in included_urls
    assert "https://cssbank.example/img/logo/logo-w-EHL.png" in included_urls
    assert "https://cssbank.example/Vector.svg" not in included_urls
    assert res.image_errors == []
    assert any(
        loc.get("status") == "excluded"
        and loc.get("url") == "https://cssbank.example/apple-touch-icon-76x76.png"
        and "lower-resolution duplicate" in str(loc.get("exclusion_reason", ""))
        for loc in res.discovered_locations
    )

    # 3. Parking page with hidden bping.php pixel, F5 TSPD_101 stub favicon, under-construction page,
    #    and cross-domain redirect 403 error message
    parking_pixel_html = (
        '<html><head><script>window.gdprAppliesGlobally = true;</script></head>'
        '<body><img height="0px" width="0px" style="display: none !important" '
        'src="https://l.cdn-fileserver.com/bping.php?vi=1"></body></html>'
    )
    f5_tspd_html = (
        '<html><head><link rel="shortcut icon" href="data:;base64,iVBORw0KGgo="/>'
        '<script>window["bobcmn"]="/TSPD/TSPD_101";</script></head><body></body></html>'
    )
    under_const_html = (
        '<html><head><title>Web Page Under Construction</title>'
        '<link rel="ICON" href="/favicon.ico"></head><body></body></html>'
    )
    for html_sample in (parking_pixel_html, f5_tspd_html, under_const_html):
        s_bot = MagicMock(spec=requests.Session)
        s_bot.get.return_value = _make_resp(text=html_sample, url="https://parked.example/")
        bot_res = extract_domain_logos("parked.example", ignored_hashes={}, session=s_bot)
        assert bot_res.domain_error == "Bot challenge / parking interstitial (HTTP 200)"

    s_redir = MagicMock(spec=requests.Session)
    s_redir.get.return_value = _make_resp(status_code=403, url="https://evil-slot.example/")
    redir_res = extract_domain_logos("legitbank.example", ignored_hashes={}, session=s_redir)
    assert redir_res.final_url == "https://evil-slot.example/"
    assert redir_res.domain_error == "HTTP 403 (redirected to evil-slot.example)"


def test_extractor_and_brand_sync_ssl_proxy_propagation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.logos.extractor import _fetch_with_retry

    for key in ("RF_VERIFY_SSL", "RF_INSECURE_SSL", "SOCLENS_INSECURE_SSL", "RF_CA_BUNDLE"):
        monkeypatch.delenv(key, raising=False)
    assert ExtractorConfig().verify_ssl is True

    monkeypatch.setenv("RF_VERIFY_SSL", "false")
    assert ExtractorConfig().verify_ssl is False

    monkeypatch.delenv("RF_VERIFY_SSL", raising=False)
    monkeypatch.setenv("RF_INSECURE_SSL", "true")
    assert ExtractorConfig().verify_ssl is False

    monkeypatch.delenv("RF_INSECURE_SSL", raising=False)
    monkeypatch.setenv("RF_CA_BUNDLE", "/etc/ssl/proxy-ca.pem")
    assert ExtractorConfig().verify_ssl == "/etc/ssl/proxy-ca.pem"
    monkeypatch.delenv("RF_CA_BUNDLE", raising=False)

    # _fetch_with_retry fails fast on SSLError without retrying
    ssl_sess = MagicMock(spec=requests.Session)
    ssl_sess.get.side_effect = requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED")
    with patch("time.sleep") as mock_sleep:
        with pytest.raises(requests.exceptions.SSLError):
            _fetch_with_retry(
                ssl_sess,
                "https://proxy-target.example/",
                ExtractorConfig(max_retries=3, backoff_base=1.0),
            )
    assert ssl_sess.get.call_count == 1
    mock_sleep.assert_not_called()

    # Real RecordedFutureClient(verify_ssl=False) propagates verify_ssl=False to brand sync extractors
    rf_sess = MagicMock(spec=requests.Session)
    rf_client = RecordedFutureClient(
        api_token="tok",
        session=rf_sess,
        verify_ssl=False,
    )
    with patch.object(rf_client, "get_watchlist_entities", return_value=[]):
        with patch("soclens.logos.brand_sync.extract_domains_logos") as mock_multi:
            mock_multi.return_value = [
                DomainExtractionResult(domain="a.com"),
                DomainExtractionResult(domain="b.com"),
            ]
            calculate_brand_sync_delta(
                rf_client,
                "list_1",
                ["a.com", "b.com"],
                output_locations_file=None,
                ignored_hashes={},
            )
            assert mock_multi.call_count == 1
            passed_cfg = mock_multi.call_args.kwargs["config"]
            assert passed_cfg.verify_ssl is False

        with patch("soclens.logos.brand_sync.get_domain_image_hash") as mock_single:
            mock_single.return_value = ([], 0, None, [], [])
            validate_domain_brand_sync(
                rf_client,
                "list_1",
                ["single.com"],
                output_locations_file=None,
                ignored_hashes={},
            )
            assert mock_single.call_count == 1
            assert mock_single.call_args.kwargs["config"].verify_ssl is False


def test_analyze_brand_sync_issues_and_sorting_helpers() -> None:
    shared_sha = "a" * 64
    uniq_sha = "b" * 64
    state = {
        "version": 1,
        "domains": {
            "healthy.test": {
                "consecutive_failures": 0,
                "hashes": [shared_sha, uniq_sha],
                "last_error": None,
                "last_attempt": "2026-11-24T12:00:00Z",
                "last_success": "2026-11-24T12:00:00Z",
            },
            "partner.test": {
                "consecutive_failures": 0,
                "hashes": [shared_sha],
                "last_error": None,
            },
            "silent-zero.test": {
                "consecutive_failures": 0,
                "hashes": [],
                "last_error": None,
            },
            "conn-err.test": {
                "consecutive_failures": 2,
                "hashes": [],
                "last_error": "Connection failed: timeout",
            },
            "grace-dead.test": {
                "consecutive_failures": 3,
                "hashes": [],
                "last_error": "HTTP 403",
            },
            "partial-fail.test": {
                "consecutive_failures": 2,
                "hashes": ["c" * 64],
                "last_error": "Temporary 503",
            },
        },
    }

    report = analyze_brand_sync_issues(
        state=state,
        watchlist_domains=["healthy.test", "silent-zero.test", "never-synced.test"],
        grace_failures=3,
    )
    assert report.source == "combined"
    assert report.total_domains == 7
    assert report.healthy_domains == 2
    assert report.missing_hashes_count == 4
    assert report.silent_zero_hashes_count == 1
    assert report.domain_errors_count == 3
    assert report.failing_grace_count == 3
    assert report.duplicate_hashes_count == 1
    assert report.never_synced_count == 1
    assert set(report.category_counts.keys()) == set(BRAND_SYNC_ISSUE_CATEGORIES)

    missing = filter_brand_issues(report.issues, category="missing_hashes")
    assert {i.domain for i in missing} == {
        "conn-err.test",
        "grace-dead.test",
        "never-synced.test",
        "silent-zero.test",
    }
    silent = filter_brand_issues(report.issues, category="silent_zero_hashes")
    assert [i.domain for i in silent] == ["silent-zero.test"]
    grace = filter_brand_issues(report.issues, category="failing_grace")
    assert {i.domain for i in grace} == {"conn-err.test", "grace-dead.test", "partial-fail.test"}
    dups = filter_brand_issues(report.issues, category="duplicate_hashes")
    assert len(dups) == 1
    assert dups[0].domains == ("healthy.test", "partner.test")

    filtered_q = filter_brand_issues(report.issues, category="all", query="timeout")
    assert [i.domain for i in filtered_q] == ["conn-err.test"]

    # Overlay live run with image_errors and a domain recovering
    live_report = analyze_brand_sync_issues(
        state=state,
        scoped_domains=["img-err.test", "silent-zero.test"],
        target_hashes={"d" * 64: {"domain": "ok-now.test", "domains": ["ok-now.test"]}},
        domain_errors={"conn-err.test": "DNS failure"},
        image_errors={"img-err.test": ["PNG CRC mismatch"]},
    )
    img_issues = filter_brand_issues(live_report.issues, category="image_errors")
    assert [i.domain for i in img_issues] == ["img-err.test"]
    assert img_issues[0].status == "NO HASHES (IMG ERR)"

    # Numeric & string row sorting
    sample_rows = [
        {"domain": "ten.test", "status": "OK", "hash_count": 10, "consecutive_failures": 0, "detail": "z"},
        {"domain": "zero.test", "status": "NO HASHES", "hash_count": 0, "consecutive_failures": 2, "detail": "a"},
        {"domain": "two.test", "status": "WARN", "hash_count": 2, "consecutive_failures": 1, "detail": "m"},
        {"domain": "blank.test", "status": "REMOVE", "hash_count": None, "consecutive_failures": 0, "detail": "b"},
    ]
    by_hashes_asc = sort_brand_rows(sample_rows, sort_by="hashes", descending=False)
    assert [r["domain"] for r in by_hashes_asc] == ["zero.test", "two.test", "ten.test", "blank.test"]
    by_hashes_desc = sort_brand_rows(sample_rows, sort_by="hashes", descending=True)
    assert [r["domain"] for r in by_hashes_desc] == ["ten.test", "two.test", "zero.test", "blank.test"]
    by_domain_desc = sort_brand_rows(sample_rows, sort_by="domain", descending=True)
    assert [r["domain"] for r in by_domain_desc] == ["zero.test", "two.test", "ten.test", "blank.test"]
    assert [r["domain"] for r in sort_brand_rows(sample_rows, sort_by="none")] == [
        "ten.test",
        "zero.test",
        "two.test",
        "blank.test",
    ]

    sorted_issues = sort_brand_issues(report.issues, sort_by="domain", descending=False)
    assert sorted_issues == sorted(sorted_issues, key=lambda x: (x.domain.lower(), x.status.lower()))

    with pytest.raises(ValueError):
        sort_brand_rows(sample_rows, sort_by="invalid")
    with pytest.raises(ValueError):
        filter_brand_issues(report.issues, category="bogus")

    # Domain checklist sorting
    domains = ["healthy.test", "silent-zero.test", "conn-err.test", "partner.test"]
    assert sort_brand_domains(domains, sort_by="domain", descending=True) == [
        "silent-zero.test",
        "partner.test",
        "healthy.test",
        "conn-err.test",
    ]
    by_zero = sort_brand_domains(
        domains,
        sort_by="hashes",
        descending=False,
        hash_counts=report.domain_hash_counts,
        failure_counts=report.domain_failure_counts,
    )
    assert set(by_zero[:2]) == {"conn-err.test", "silent-zero.test"}
    by_fail = sort_brand_domains(
        domains,
        sort_by="failures",
        descending=True,
        hash_counts=report.domain_hash_counts,
        failure_counts=report.domain_failure_counts,
    )
    assert by_fail[0] == "conn-err.test"
    by_sel = sort_brand_domains(
        domains,
        sort_by="selected",
        descending=True,
        selected_domains={"partner.test"},
    )
    assert by_sel[0] == "partner.test"


