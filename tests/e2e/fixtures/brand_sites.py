"""Configurable synthetic brand website profiles and route specs for E2E tests."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from tests.e2e.fixtures.assets import (
    iter_oversized_chunks,
    make_banner_jpeg,
    make_banner_png,
    make_corrupted_png,
    make_gif,
    make_ico,
    make_jpeg,
    make_png,
    make_soft_404_html,
    make_spacer_1x1_png,
    make_svg,
    make_webp,
    sha256_hex,
    to_data_uri,
)

OVERSIZED_STREAM_BYTES = 10 * 1024 * 1024 + 65536


@dataclass
class RouteSpec:
    """HTTP response definition for a synthetic brand site route."""

    status: int = 200
    content_type: str = "text/html; charset=utf-8"
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    body_chunks: Callable[[], Iterator[bytes]] | None = None
    delay_seconds: float = 0.0


@dataclass
class BrandSiteProfile:
    """Declarative synthetic website profile with routes and ground-truth metadata."""

    domain: str
    routes: dict[str, RouteSpec] = field(default_factory=dict)
    expected_logo_paths: list[str] = field(default_factory=list)
    expected_decoy_paths: list[str] = field(default_factory=list)
    expected_logo_hashes: dict[str, str] = field(default_factory=dict)


def _html_route(html: str, status: int = 200, headers: dict[str, str] | None = None) -> RouteSpec:
    return RouteSpec(
        status=status,
        content_type="text/html; charset=utf-8",
        body=html.encode("utf-8"),
        headers=dict(headers or {}),
    )


def _json_route(payload: object, status: int = 200) -> RouteSpec:
    return RouteSpec(
        status=status,
        content_type="application/json",
        body=json.dumps(payload).encode("utf-8"),
    )


def _asset_route(data: bytes, content_type: str, status: int = 200) -> RouteSpec:
    return RouteSpec(status=status, content_type=content_type, body=data)


def make_brand_site(
    domain: str,
    html: str,
    assets: dict[str, tuple[bytes, str]] | None = None,
    extra_routes: dict[str, RouteSpec] | None = None,
    expected_logo_paths: list[str] | None = None,
    expected_decoy_paths: list[str] | None = None,
) -> BrandSiteProfile:
    """Build a custom synthetic ``BrandSiteProfile`` for targeted E2E tests."""
    routes: dict[str, RouteSpec] = {"/": _html_route(html)}
    expected_hashes: dict[str, str] = {}
    for path, (data, mime) in (assets or {}).items():
        norm_path = path if path.startswith("/") else f"/{path}"
        routes[norm_path] = _asset_route(data, mime)
        expected_hashes[norm_path] = sha256_hex(data)
    if extra_routes:
        routes.update(extra_routes)
    return BrandSiteProfile(
        domain=domain,
        routes=routes,
        expected_logo_paths=list(expected_logo_paths or []),
        expected_decoy_paths=list(expected_decoy_paths or []),
        expected_logo_hashes=expected_hashes,
    )


def _build_alpha_site() -> BrandSiteProfile:
    jsonld_rel_png = make_png(180, 60, (12, 74, 158, 255))
    jsonld_obj_png = make_png(200, 64, (14, 90, 175, 255))
    jsonld_str_png = make_png(210, 64, (18, 100, 185, 255))
    icon_32_png = make_png(32, 32, (10, 80, 160, 255))
    icon_180_png = make_png(180, 180, (10, 80, 160, 255))
    mask_svg = make_svg(64, 64, "AlphaMask")
    mstile_png = make_png(144, 144, (16, 86, 166, 255))
    manifest_512_png = make_png(512, 512, (20, 96, 176, 255))
    og_logo_png = make_png(240, 240, (24, 102, 180, 255))
    site_logo_png = make_png(220, 64, (30, 110, 190, 255))
    pic_1x_png = make_png(200, 60, (36, 116, 196, 255))
    pic_2x_png = make_png(400, 120, (36, 116, 196, 255))
    pic_fallback_png = make_png(190, 58, (38, 118, 198, 255))
    lazy_logo_webp = make_webp(160, 48, variant="VP8X")
    data_uri_png = make_png(140, 44, (44, 124, 204, 255))
    favicon_ico = make_ico(32, 32, payload="png")

    data_uri_str = to_data_uri(data_uri_png, "image/png")
    inline_svg_str = (
        '<svg class="inline-brand-logo" width="180" height="48" '
        'viewBox="0 0 180 48" xmlns="http://www.w3.org/2000/svg">'
        '<rect width="180" height="48" fill="#0a50a0"/>'
        '<text x="10" y="24" fill="#ffffff">AlphaInline</text>'
        "</svg>"
    )

    jsonld_graph = {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "BankOrCreditUnion",
                "name": "Alpha Bank",
                "logo": "assets/jsonld-logo.png",
            },
            {
                "@type": "Organization",
                "name": "Alpha Holdings",
                "logo": {
                    "@type": "ImageObject",
                    "url": "/assets/jsonld-obj-logo.png",
                    "contentUrl": "/assets/jsonld-obj-logo.png",
                },
            },
        ],
    }
    jsonld_org = {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "Alpha Financial",
        "logo": "/assets/jsonld-str-logo.png",
    }

    manifest = {
        "name": "Alpha Bank Portal",
        "short_name": "Alpha",
        "icons": [
            {
                "src": "/icons/manifest-512x512.png",
                "sizes": "512x512",
                "type": "image/png",
            }
        ],
    }

    home_html = (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        '  <meta charset="utf-8">\n'
        '  <base href="/portal/">\n'
        "  <title>Alpha Bank — Official Portal</title>\n"
        f'  <script type="application/ld+json">{json.dumps(jsonld_graph)}</script>\n'
        f'  <script type="application/ld+json">{json.dumps(jsonld_org)}</script>\n'
        '  <link rel="icon" sizes="32x32" href="/icons/favicon-32x32.png">\n'
        '  <link rel="apple-touch-icon" sizes="180x180" href="/icons/favicon-180x180.png">\n'
        '  <link rel="mask-icon" href="/icons/pinned-tab.svg" color="#0a50a0">\n'
        '  <meta name="msapplication-TileImage" content="/icons/mstile-144x144.png">\n'
        '  <link rel="manifest" href="/manifest.json">\n'
        '  <meta property="og:image" content="/images/alpha-og-logo.png">\n'
        "</head>\n"
        "<body>\n"
        "  <header>\n"
        f'    <a href="/">{inline_svg_str}</a>\n'
        '    <img class="site-logo" src="/images/site-logo.png" alt="Alpha Bank Logo">\n'
        "    <picture>\n"
        '      <source srcset="/cdn-cgi/image/w=200,fit=contain/pic-logo-1x.png 1x, '
        '/cdn-cgi/image/w=400,fit=contain/pic-logo-2x.png 2x">\n'
        '      <img src="/images/pic-fallback.png" alt="Alpha Picture Logo">\n'
        "    </picture>\n"
        '    <img class="brand-mark" data-src="/images/lazy-logo.webp" alt="Alpha Lazy Logo">\n'
        f'    <img class="data-logo" src="{data_uri_str}" alt="Alpha Data Logo">\n'
        "  </header>\n"
        "  <main><h1>Welcome to Alpha Bank</h1></main>\n"
        "</body>\n"
        "</html>\n"
    )

    routes: dict[str, RouteSpec] = {
        "/": RouteSpec(
            status=302,
            content_type="text/html; charset=utf-8",
            body=b"Redirecting to /portal/home",
            headers={"Location": "portal/home"},
        ),
        "/portal/home": _html_route(home_html),
        "/portal/assets/jsonld-logo.png": _asset_route(jsonld_rel_png, "image/png"),
        "/assets/jsonld-obj-logo.png": _asset_route(jsonld_obj_png, "image/png"),
        "/assets/jsonld-str-logo.png": _asset_route(jsonld_str_png, "image/png"),
        "/icons/favicon-32x32.png": _asset_route(icon_32_png, "image/png"),
        "/icons/favicon-180x180.png": _asset_route(icon_180_png, "image/png"),
        "/icons/pinned-tab.svg": _asset_route(mask_svg, "image/svg+xml"),
        "/icons/mstile-144x144.png": _asset_route(mstile_png, "image/png"),
        "/manifest.json": _json_route(manifest),
        "/icons/manifest-512x512.png": _asset_route(manifest_512_png, "image/png"),
        "/images/alpha-og-logo.png": _asset_route(og_logo_png, "image/png"),
        "/images/site-logo.png": _asset_route(site_logo_png, "image/png"),
        "/cdn-cgi/image/w=200,fit=contain/pic-logo-1x.png": _asset_route(pic_1x_png, "image/png"),
        "/cdn-cgi/image/w=400,fit=contain/pic-logo-2x.png": _asset_route(pic_2x_png, "image/png"),
        "/images/pic-fallback.png": _asset_route(pic_fallback_png, "image/png"),
        "/images/lazy-logo.webp": _asset_route(lazy_logo_webp, "image/webp"),
        "/favicon.ico": _asset_route(favicon_ico, "image/x-icon"),
    }

    expected_logo_paths = [
        "/portal/assets/jsonld-logo.png",
        "/assets/jsonld-obj-logo.png",
        "/assets/jsonld-str-logo.png",
        "/icons/favicon-32x32.png",
        "/icons/favicon-180x180.png",
        "/icons/pinned-tab.svg",
        "/icons/mstile-144x144.png",
        "/icons/manifest-512x512.png",
        "/images/alpha-og-logo.png",
        "/images/site-logo.png",
        "/cdn-cgi/image/w=200,fit=contain/pic-logo-1x.png",
        "/cdn-cgi/image/w=400,fit=contain/pic-logo-2x.png",
        "/images/pic-fallback.png",
        "/images/lazy-logo.webp",
        "/favicon.ico",
    ]
    expected_hashes = {
        path: sha256_hex(routes[path].body) for path in expected_logo_paths
    }
    expected_hashes["data_uri_logo"] = sha256_hex(data_uri_png)
    expected_hashes["inline_svg_logo"] = sha256_hex(inline_svg_str.encode("utf-8"))

    return BrandSiteProfile(
        domain="brand-alpha.local",
        routes=routes,
        expected_logo_paths=expected_logo_paths,
        expected_decoy_paths=[],
        expected_logo_hashes=expected_hashes,
    )


def _build_beta_site() -> BrandSiteProfile:
    beta_logo_png = make_png(220, 64, (20, 120, 80, 255))
    spring_promo_jpg = make_banner_jpeg(1600, 100)
    promo_banner_jpg = make_banner_jpeg(1200, 150)
    slider_hero_png = make_banner_png(1920, 400)
    search_icon_svg = make_svg(16, 16, "Search")
    spacer_png = make_spacer_1x1_png()
    badge_png = make_png(120, 40, (90, 90, 90, 255))
    container_decoy_png = make_png(150, 50, (120, 120, 120, 255))
    favicon_ico = make_ico(32, 32, payload="png")

    html = (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        '  <meta charset="utf-8">\n'
        "  <title>Beta Credit Union</title>\n"
        '  <meta property="og:image" content="/uploads/spring-promo-banner.jpg">\n'
        "</head>\n"
        '<body class="page-template-default no-sidebar">\n'
        '  <div class="elementor-widget-container">\n'
        '    <a href="/">\n'
        '      <img class="site-logo" src="/images/beta-logo.png" alt="Beta Bank Logo">\n'
        "    </a>\n"
        "  </div>\n"
        '  <section class="hero">\n'
        '    <img src="/uploads/promo-banner.jpg" class="promo-logo" alt="Promo Logo">\n'
        '    <img src="/uploads/slider-hero.png" width="1920" height="400" alt="Hero Slider">\n'
        '    <img src="/icons/icon-search.svg" class="search-icon" alt="Search">\n'
        '    <img src="/pixel/spacer.png" class="brand-pixel" alt="Tracking Pixel">\n'
        "  </section>\n"
        '  <section class="trust-badges">\n'
        '    <img src="https://badges.thirdparty.invalid/visa-badge.png" alt="Visa">\n'
        '    <img src="https://badges.thirdparty.invalid/facebook-badge.png" alt="Facebook">\n'
        '    <img src="/badges/facebook-social.png" alt="Follow on Facebook">\n'
        '    <img src="/badges/visa-badge.png" alt="Visa Accepted">\n'
        '    <img src="/badges/soc2-badge.png" alt="SOC2 Certified">\n'
        '    <img src="/badges/fdic-member.png" alt="Member FDIC">\n'
        '    <img src="/badges/equal-housing-lender.png" alt="Equal Housing Lender">\n'
        "  </section>\n"
        '  <section class="broken-logos">\n'
        '    <img class="logo" src="/images/soft404-logo.png" alt="Soft 404 Logo">\n'
        '    <img class="logo" src="/images/corrupt-logo.png" alt="Corrupted Logo">\n'
        '    <img class="logo" src="/images/huge-logo.png" alt="Oversized Logo">\n'
        "  </section>\n"
        '  <footer><img src="/images/footer-logo.png" alt="Footer Logo"></footer>\n'
        '  <aside><img src="/images/aside-logo.png" alt="Aside Logo"></aside>\n'
        '  <dialog><img src="/images/dialog-logo.png" alt="Dialog Logo"></dialog>\n'
        '  <div class="modal-body"><img src="/images/modal-logo.png" alt="Modal Logo"></div>\n'
        "</body>\n"
        "</html>\n"
    )

    routes: dict[str, RouteSpec] = {
        "/": _html_route(html),
        "/images/beta-logo.png": _asset_route(beta_logo_png, "image/png"),
        "/favicon.ico": _asset_route(favicon_ico, "image/x-icon"),
        "/uploads/spring-promo-banner.jpg": _asset_route(spring_promo_jpg, "image/jpeg"),
        "/uploads/promo-banner.jpg": _asset_route(promo_banner_jpg, "image/jpeg"),
        "/uploads/slider-hero.png": _asset_route(slider_hero_png, "image/png"),
        "/icons/icon-search.svg": _asset_route(search_icon_svg, "image/svg+xml"),
        "/pixel/spacer.png": _asset_route(spacer_png, "image/png"),
        "/badges/facebook-social.png": _asset_route(badge_png, "image/png"),
        "/badges/visa-badge.png": _asset_route(badge_png, "image/png"),
        "/badges/soc2-badge.png": _asset_route(badge_png, "image/png"),
        "/badges/fdic-member.png": _asset_route(badge_png, "image/png"),
        "/badges/equal-housing-lender.png": _asset_route(badge_png, "image/png"),
        "/images/footer-logo.png": _asset_route(container_decoy_png, "image/png"),
        "/images/aside-logo.png": _asset_route(container_decoy_png, "image/png"),
        "/images/dialog-logo.png": _asset_route(container_decoy_png, "image/png"),
        "/images/modal-logo.png": _asset_route(container_decoy_png, "image/png"),
        "/images/soft404-logo.png": RouteSpec(
            status=200,
            content_type="text/html; charset=utf-8",
            body=make_soft_404_html(),
        ),
        "/images/corrupt-logo.png": _asset_route(make_corrupted_png(), "image/png"),
        "/images/huge-logo.png": RouteSpec(
            status=200,
            content_type="image/png",
            body=b"",
            headers={"Content-Length": str(OVERSIZED_STREAM_BYTES)},
            body_chunks=lambda: iter_oversized_chunks(OVERSIZED_STREAM_BYTES),
        ),
    }

    expected_logo_paths = ["/images/beta-logo.png", "/favicon.ico"]
    expected_decoy_paths = [
        "/uploads/spring-promo-banner.jpg",
        "/uploads/promo-banner.jpg",
        "/uploads/slider-hero.png",
        "/icons/icon-search.svg",
        "/pixel/spacer.png",
        "/badges/facebook-social.png",
        "/badges/visa-badge.png",
        "/badges/soc2-badge.png",
        "/badges/fdic-member.png",
        "/badges/equal-housing-lender.png",
        "/images/footer-logo.png",
        "/images/aside-logo.png",
        "/images/dialog-logo.png",
        "/images/modal-logo.png",
        "/images/soft404-logo.png",
        "/images/corrupt-logo.png",
        "/images/huge-logo.png",
    ]
    return BrandSiteProfile(
        domain="brand-beta.local",
        routes=routes,
        expected_logo_paths=expected_logo_paths,
        expected_decoy_paths=expected_decoy_paths,
        expected_logo_hashes={
            "/images/beta-logo.png": sha256_hex(beta_logo_png),
            "/favicon.ico": sha256_hex(favicon_ico),
        },
    )


def _build_gamma_site() -> BrandSiteProfile:
    og_logo_png = make_png(256, 256, (180, 40, 40, 255))
    gif_logo = make_gif(180, 60)
    jpeg_logo = make_jpeg(200, 60)
    bmp_ico = make_ico(32, 32, payload="bmp")

    html = (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        '  <meta charset="utf-8">\n'
        "  <title>Gamma Security Corp</title>\n"
        '  <meta property="og:image" content="/images/gamma-og-logo.png">\n'
        "</head>\n"
        "<body>\n"
        "  <header>\n"
        '    <img class="site-logo" src="/images/gamma-logo.gif" alt="Gamma Logo">\n'
        '    <img class="brand-logo" src="/images/gamma-logo.jpg" alt="Gamma Brand">\n'
        "  </header>\n"
        "</body>\n"
        "</html>\n"
    )
    return make_brand_site(
        domain="brand-gamma.local",
        html=html,
        assets={
            "/images/gamma-og-logo.png": (og_logo_png, "image/png"),
            "/images/gamma-logo.gif": (gif_logo, "image/gif"),
            "/images/gamma-logo.jpg": (jpeg_logo, "image/jpeg"),
            "/favicon.ico": (bmp_ico, "image/x-icon"),
        },
        expected_logo_paths=[
            "/images/gamma-og-logo.png",
            "/images/gamma-logo.gif",
            "/images/gamma-logo.jpg",
            "/favicon.ico",
        ],
    )


def _build_shared_site() -> BrandSiteProfile:
    # Matches brand-alpha.local's /images/site-logo.png bytes for shared-hash attribution tests.
    shared_logo_png = make_png(220, 64, (30, 110, 190, 255))
    unique_logo_png = make_png(160, 50, (90, 40, 140, 255))
    favicon_ico = make_ico(32, 32, payload="png")

    html = (
        "<!DOCTYPE html>\n"
        "<html><head><title>Shared Subsidiary Brand</title></head>\n"
        "<body><header>\n"
        '  <img class="site-logo" src="/images/shared-logo.png" alt="Shared Logo">\n'
        '  <img class="brand-logo" src="/images/subsidiary-logo.png" alt="Subsidiary Logo">\n'
        "</header></body></html>\n"
    )
    return make_brand_site(
        domain="brand-shared.local",
        html=html,
        assets={
            "/images/shared-logo.png": (shared_logo_png, "image/png"),
            "/images/subsidiary-logo.png": (unique_logo_png, "image/png"),
            "/favicon.ico": (favicon_ico, "image/x-icon"),
        },
        expected_logo_paths=[
            "/images/shared-logo.png",
            "/images/subsidiary-logo.png",
            "/favicon.ico",
        ],
    )


def _build_flaky_site() -> BrandSiteProfile:
    flaky_logo_png = make_png(180, 54, (60, 140, 140, 255))
    favicon_ico = make_ico(32, 32, payload="png")
    html = (
        "<!DOCTYPE html>\n"
        "<html><head><title>Flaky Brand Site</title></head>\n"
        "<body><header>\n"
        '  <img class="site-logo" src="/images/flaky-logo.png" alt="Flaky Brand Logo">\n'
        "</header></body></html>\n"
    )
    return make_brand_site(
        domain="brand-flaky.local",
        html=html,
        assets={
            "/images/flaky-logo.png": (flaky_logo_png, "image/png"),
            "/favicon.ico": (favicon_ico, "image/x-icon"),
        },
        expected_logo_paths=["/images/flaky-logo.png", "/favicon.ico"],
    )


def build_default_brand_sites() -> dict[str, BrandSiteProfile]:
    """Return the standard dictionary of synthetic brand sites keyed by domain."""
    sites = [
        _build_alpha_site(),
        _build_beta_site(),
        _build_gamma_site(),
        _build_shared_site(),
        _build_flaky_site(),
    ]
    return {site.domain: site for site in sites}
