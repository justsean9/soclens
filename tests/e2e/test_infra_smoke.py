"""Self-verification smoke tests for E2E harness, fixtures, and local mock servers."""

from __future__ import annotations

import base64
import json
import os
import struct
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import requests

from tests.e2e.conftest import (
    ALL_LIST_TYPES,
    BrandHTTPServer,
    MockRFServer,
    MockSplunkServer,
)
from tests.e2e.fixtures.assets import (
    iter_oversized_chunks,
    make_banner_jpeg,
    make_banner_png,
    make_corrupted_jpeg,
    make_corrupted_png,
    make_gif,
    make_ico,
    make_ico_multi,
    make_jpeg,
    make_non_image_pdf,
    make_oversized_payload,
    make_png,
    make_soft_404_html,
    make_spacer_1x1_png,
    make_svg,
    make_tiny_payload,
    make_truncated_png,
    make_webp,
    md5_hex,
    sha1_hex,
    sha256_hex,
    to_data_uri,
)
from tests.e2e.fixtures.brand_sites import OVERSIZED_STREAM_BYTES, build_default_brand_sites

pytestmark = [pytest.mark.e2e]


def test_png_and_spacer_generators() -> None:
    png = make_png(220, 64)
    assert len(png) >= 50
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert png[12:16] == b"IHDR"
    w, h = struct.unpack(">II", png[16:24])
    assert (w, h) == (220, 64)
    assert png.endswith(b"IEND\xaeB`\x82")

    spacer = make_spacer_1x1_png()
    assert len(spacer) >= 50
    assert struct.unpack(">II", spacer[16:24]) == (1, 1)


def test_jpeg_generator_sof0_dimensions() -> None:
    jpg = make_jpeg(320, 120)
    assert len(jpg) >= 50
    assert jpg.startswith(b"\xff\xd8")
    assert jpg.endswith(b"\xff\xd9")
    sof0_idx = jpg.index(b"\xff\xc0")
    precision, height, width, _ = struct.unpack(">BHHB", jpg[sof0_idx + 4 : sof0_idx + 10])
    assert precision == 8
    assert (width, height) == (320, 120)


def _strict_decode_gif_lzw(gif_bytes: bytes) -> list[int]:
    """Strictly decode single-image GIF LZW stream, verifying EOI bit-width alignment."""
    width, height, packed = struct.unpack("<HHB", gif_bytes[6:11])
    pos = 13
    if packed & 0x80:
        gct_size = 3 * (1 << ((packed & 0x07) + 1))
        pos += gct_size
    while gif_bytes[pos] == 0x21:
        pos += 2
        while True:
            sub_len = gif_bytes[pos]
            pos += 1
            if sub_len == 0:
                break
            pos += sub_len
    assert gif_bytes[pos] == 0x2C
    img_flags = gif_bytes[pos + 9]
    pos += 10
    if img_flags & 0x80:
        pos += 3 * (1 << ((img_flags & 0x07) + 1))

    min_code_size = gif_bytes[pos]
    pos += 1
    lzw_stream = bytearray()
    while True:
        block_len = gif_bytes[pos]
        pos += 1
        if block_len == 0:
            break
        lzw_stream.extend(gif_bytes[pos : pos + block_len])
        pos += block_len

    clear_code = 1 << min_code_size
    eoi_code = clear_code + 1
    bit_pos = 0
    total_bits = len(lzw_stream) * 8

    def read_code(size: int) -> int:
        nonlocal bit_pos
        if bit_pos + size > total_bits:
            raise AssertionError(f"LZW bit underflow: need={size} rem={total_bits - bit_pos}")
        val = 0
        for idx in range(size):
            byte_val = lzw_stream[(bit_pos + idx) >> 3]
            bit = (byte_val >> ((bit_pos + idx) & 7)) & 1
            val |= bit << idx
        bit_pos += size
        return val

    code_size = min_code_size + 1
    next_code = eoi_code + 1
    table: dict[int, list[int]] = {i: [i] for i in range(clear_code)}
    prev: list[int] | None = None
    pixels: list[int] = []
    saw_eoi = False

    while True:
        code = read_code(code_size)
        if code == clear_code:
            table = {i: [i] for i in range(clear_code)}
            code_size = min_code_size + 1
            next_code = eoi_code + 1
            prev = None
            continue
        if code == eoi_code:
            saw_eoi = True
            break
        if code in table:
            entry = table[code]
        elif code == next_code and prev is not None:
            entry = prev + [prev[0]]
        else:
            raise AssertionError(f"Unexpected LZW code {code} (next_code={next_code})")
        pixels.extend(entry)
        if prev is not None and next_code < 4096:
            table[next_code] = prev + [entry[0]]
            next_code += 1
            if next_code == (1 << code_size) and code_size < 12:
                code_size += 1
        prev = entry

    assert saw_eoi
    assert len(pixels) == width * height
    return pixels


@pytest.mark.parametrize("version", [b"GIF89a", b"GIF87a"])
def test_gif_generator_versions_and_1x1(version: bytes) -> None:
    gif = make_gif(1, 1, version=version)
    assert len(gif) >= 50
    assert gif.startswith(version)
    assert gif.endswith(b"\x3b")
    w, h = struct.unpack("<HH", gif[6:10])
    assert (w, h) == (1, 1)
    assert _strict_decode_gif_lzw(gif) == [0]

    for gw, gh in ((8, 8), (10, 10), (16, 16), (180, 60)):
        gif_img = make_gif(gw, gh, version=version)
        assert len(gif_img) >= 50
        assert struct.unpack("<HH", gif_img[6:10]) == (gw, gh)
        decoded = _strict_decode_gif_lzw(gif_img)
        assert len(decoded) == gw * gh


@pytest.mark.parametrize("variant", ["VP8X", "VP8L", "VP8 "])
def test_webp_generator_variants(variant: str) -> None:
    data = make_webp(160, 48, variant=variant)
    assert len(data) >= 50
    assert data[:4] == b"RIFF"
    assert data[8:12] == b"WEBP"
    chunk_id = data[12:16]
    if variant == "VP8X":
        assert chunk_id == b"VP8X"
        w = int.from_bytes(data[24:27], "little") + 1
        h = int.from_bytes(data[27:30], "little") + 1
        assert (w, h) == (160, 48)
    elif variant == "VP8L":
        assert chunk_id == b"VP8L"
        assert data[20] == 0x2F
        packed = struct.unpack("<I", data[21:25])[0]
        w = (packed & 0x3FFF) + 1
        h = ((packed >> 14) & 0x3FFF) + 1
        assert (w, h) == (160, 48)
    else:
        assert chunk_id == b"VP8 "
        assert data[23:26] == b"\x9d\x01\x2a"
        raw_w, raw_h = struct.unpack("<HH", data[26:30])
        assert (raw_w & 0x3FFF, raw_h & 0x3FFF) == (160, 48)

    tiny_webp = make_webp(1, 1, variant=variant)
    assert len(tiny_webp) >= 50

    with pytest.raises(ValueError):
        make_webp(16385, 100, variant="VP8L")
    with pytest.raises(ValueError):
        make_webp(16384, 100, variant="VP8 ")


def test_ico_and_svg_and_negative_generators() -> None:
    ico_png = make_ico(32, 32, payload="png")
    assert len(ico_png) >= 50
    assert struct.unpack("<HHH", ico_png[:6]) == (0, 1, 1)
    assert ico_png[22:30] == b"\x89PNG\r\n\x1a\n"

    ico_bmp = make_ico(16, 16, payload="bmp")
    assert len(ico_bmp) >= 50
    bi_size, bi_w, bi_h = struct.unpack("<III", ico_bmp[22:34])
    assert (bi_size, bi_w, bi_h) == (40, 16, 32)

    ico_multi = make_ico_multi([(16, 16), (48, 48)])
    assert struct.unpack("<HHH", ico_multi[:6]) == (0, 1, 2)

    svg_dims = make_svg(200, 60, label="Acme & Co", include_dims=True, css_class="brand-logo")
    svg_text = svg_dims.decode("utf-8")
    assert len(svg_dims) >= 50
    assert 'width="200" height="60"' in svg_text
    assert 'class="brand-logo"' in svg_text
    assert "Acme &amp; Co" in svg_text

    svg_no_dims = make_svg(100, 40, include_dims=False).decode("utf-8")
    svg_open_tag = svg_no_dims.split("<svg ", 1)[1].split(">", 1)[0]
    assert 'viewBox="0 0 100 40"' in svg_open_tag
    assert 'width="' not in svg_open_tag
    assert 'height="' not in svg_open_tag

    soft404 = make_soft_404_html()
    assert len(soft404) > 50 and b"404 Not Found" in soft404
    assert len(make_truncated_png()) < 30
    assert len(make_corrupted_png()) >= 50 and make_corrupted_png().startswith(b"\x89PNG")
    assert len(make_corrupted_jpeg()) >= 50 and make_corrupted_jpeg().startswith(b"\xff\xd8")
    assert len(make_non_image_pdf()) >= 50 and make_non_image_pdf().startswith(b"%PDF-1.4")
    assert len(make_tiny_payload()) < 50
    assert struct.unpack(">II", make_banner_png()[16:24]) == (1600, 100)
    banner_jpg = make_banner_jpeg(1600, 100)
    sof = banner_jpg.index(b"\xff\xc0")
    assert struct.unpack(">HH", banner_jpg[sof + 5 : sof + 9]) == (100, 1600)

    chunks = list(iter_oversized_chunks(size_bytes=1024 * 128, chunk_size=32768))
    assert sum(len(c) for c in chunks) == 1024 * 128
    assert len(make_oversized_payload(size_bytes=128)) == 128

    small_chunks = list(iter_oversized_chunks(size_bytes=200, chunk_size=32))
    assert sum(len(c) for c in small_chunks) == 200
    assert all(len(c) <= 32 for c in small_chunks)
    assert b"".join(small_chunks).startswith(b"\x89PNG\r\n\x1a\n")

    tiny_chunks = list(iter_oversized_chunks(size_bytes=20, chunk_size=32))
    assert sum(len(c) for c in tiny_chunks) == 20
    assert b"".join(tiny_chunks).startswith(b"\x89PNG\r\n\x1a\n")

    sample = make_png(10, 10)
    assert len(sha256_hex(sample)) == 64
    assert len(md5_hex(sample)) == 32
    assert len(sha1_hex(sample)) == 40
    uri = to_data_uri(sample, "image/png")
    assert uri.startswith("data:image/png;base64,")


def test_brand_sites_and_http_server(brand_http_server: BrandHTTPServer) -> None:
    sites = build_default_brand_sites()
    assert {"brand-alpha.local", "brand-beta.local", "brand-gamma.local"}.issubset(sites)

    # Host-header routing + 302 redirect on brand-alpha.local
    r_alpha = requests.get(
        f"{brand_http_server.base_url}/",
        headers={"Host": "brand-alpha.local"},
        timeout=5,
    )
    assert r_alpha.status_code == 200
    assert "/portal/home" in r_alpha.url
    assert '<base href="/portal/">' in r_alpha.text
    assert "application/ld+json" in r_alpha.text
    assert "data:image/png;base64," in r_alpha.text
    assert "/cdn-cgi/image/w=200,fit=contain/pic-logo-1x.png 1x" in r_alpha.text
    assert 'class="inline-brand-logo"' in r_alpha.text

    manifest = requests.get(
        f"{brand_http_server.base_url}/manifest.json",
        headers={"Host": "brand-alpha.local"},
        timeout=5,
    )
    assert manifest.status_code == 200
    assert manifest.json()["icons"][0]["src"] == "/icons/manifest-512x512.png"

    # Origin-root site_url() routing on brand-beta.local + decoys + root-relative urljoin
    beta_root = brand_http_server.site_url("brand-beta.local")
    r_beta = requests.get(f"{beta_root}/", timeout=5)
    assert r_beta.status_code == 200
    assert "elementor-widget-container" in r_beta.text
    assert "no-sidebar" in r_beta.text
    assert "promo-banner.jpg" in r_beta.text
    assert "https://badges.thirdparty.invalid/visa-badge.png" in r_beta.text
    assert "https://badges.thirdparty.invalid/facebook-badge.png" in r_beta.text
    assert "/badges/facebook-social.png" in r_beta.text

    beta_logo_url = urllib.parse.urljoin(f"{beta_root}/", "/images/beta-logo.png")
    beta_favicon_url = urllib.parse.urljoin(f"{beta_root}/", "/favicon.ico")
    r_beta_logo = requests.get(beta_logo_url, timeout=5)
    assert r_beta_logo.status_code == 200
    assert sha256_hex(r_beta_logo.content) == sites["brand-beta.local"].expected_logo_hashes["/images/beta-logo.png"]
    r_beta_fav = requests.get(beta_favicon_url, timeout=5)
    assert r_beta_fav.status_code == 200
    assert sha256_hex(r_beta_fav.content) == sites["brand-beta.local"].expected_logo_hashes["/favicon.ico"]

    # Case-insensitive /sites/<DOMAIN>/ path routing
    r_beta_upper = requests.get(f"{brand_http_server.base_url}/sites/BRAND-BETA.LOCAL/", timeout=5)
    assert r_beta_upper.status_code == 200
    assert "Beta Credit Union" in r_beta_upper.text

    r_soft404 = requests.get(
        f"{beta_root}/images/soft404-logo.png",
        timeout=5,
    )
    assert r_soft404.status_code == 200
    assert "text/html" in r_soft404.headers["Content-Type"]
    assert b"404 Not Found" in r_soft404.content

    r_corrupt = requests.get(
        f"{beta_root}/images/corrupt-logo.png",
        timeout=5,
    )
    assert r_corrupt.status_code == 200
    assert r_corrupt.content.startswith(b"\x89PNG")

    with requests.get(
        f"{beta_root}/images/huge-logo.png",
        stream=True,
        timeout=10,
    ) as r_huge:
        assert r_huge.status_code == 200
        assert int(r_huge.headers["Content-Length"]) == OVERSIZED_STREAM_BYTES
        total = 0
        for chunk in r_huge.iter_content(chunk_size=65536):
            total += len(chunk)
        assert total == OVERSIZED_STREAM_BYTES

    # Default site fallback (no Host override, no /sites/ prefix)
    r_default = requests.get(f"{brand_http_server.base_url}/favicon.ico", timeout=5)
    assert r_default.status_code == 200

    # Fault injection (503, 429, 404, delay)
    brand_http_server.queue_fault("brand-flaky.local", "/", 503, body="Service Unavailable")
    r_503 = requests.get(f"{brand_http_server.site_url('brand-flaky.local')}/", timeout=5)
    assert r_503.status_code == 503

    brand_http_server.queue_fault(
        "brand-flaky.local", "/", 429, headers={"Retry-After": "1"}, delay_seconds=0.05
    )
    t0 = time.monotonic()
    r_429 = requests.get(f"{brand_http_server.site_url('brand-flaky.local')}/", timeout=5)
    assert r_429.status_code == 429
    assert r_429.headers["Retry-After"] == "1"
    assert (time.monotonic() - t0) >= 0.04

    r_ok = requests.get(f"{brand_http_server.site_url('brand-flaky.local')}/", timeout=5)
    assert r_ok.status_code == 200
    assert len(brand_http_server.requests_log) >= 8


def test_mock_rf_server_lists_and_all_21_types(mock_rf_server: MockRFServer) -> None:
    headers = {"X-RFToken": "test-rf-token"}
    assert len(ALL_LIST_TYPES) == 21

    for list_type in ALL_LIST_TYPES:
        r_create = requests.post(
            f"{mock_rf_server.base_url}/list/create",
            headers=headers,
            json={"name": f"E2E {list_type}", "type": list_type},
            timeout=5,
        )
        assert r_create.status_code == 200
        created = r_create.json()
        assert created["type"] == list_type

    r_search = requests.post(
        f"{mock_rf_server.base_url}/list/search",
        headers=headers,
        json={"type": "company", "limit": 50},
        timeout=5,
    )
    assert r_search.status_code == 200
    assert any(item["type"] == "company" for item in r_search.json())

    # Stateful add/update/unchanged/remove + tags + textEntries
    seeded = mock_rf_server.seed_list("Brand Test", "brand", text_entries=["acme"])
    lid = seeded["id"]

    assert requests.get(f"{mock_rf_server.base_url}/list/{lid}/info", headers=headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/list/{lid}/status", headers=headers, timeout=5).json()["size"] == 0
    assert requests.get(f"{mock_rf_server.base_url}/list/{lid}/textEntries", headers=headers, timeout=5).json() == ["acme"]

    h1 = "a" * 64
    r_add = requests.post(
        f"{mock_rf_server.base_url}/list/{lid}/entity/add",
        headers=headers,
        json={"entity": {"type": "Hash", "name": h1}, "context": {"annotation": "v1"}},
        timeout=5,
    )
    assert r_add.json() == {"result": "added"}

    r_unchanged = requests.post(
        f"{mock_rf_server.base_url}/list/{lid}/entity/add",
        headers=headers,
        json={"entity": {"type": "Hash", "name": h1}, "context": {"annotation": "v1"}},
        timeout=5,
    )
    assert r_unchanged.json() == {"result": "unchanged"}

    r_updated = requests.post(
        f"{mock_rf_server.base_url}/list/{lid}/entity/add",
        headers=headers,
        json={"entity": {"type": "Hash", "name": h1}, "context": {"annotation": "v2"}},
        timeout=5,
    )
    assert r_updated.json() == {"result": "updated"}

    r_tags = requests.post(
        f"{mock_rf_server.base_url}/list/{lid}/entity/tags",
        headers=headers,
        json={"entity": {"id": f"hash:{h1}"}, "tags": ["tier1", "brand"]},
        timeout=5,
    )
    assert r_tags.status_code == 200
    assert r_tags.json()["operation"]["status"] == "tags_updated"

    r_too_many_tags = requests.post(
        f"{mock_rf_server.base_url}/list/{lid}/entity/tags",
        headers=headers,
        json={"entity": {"id": f"hash:{h1}"}, "tags": [f"t{i}" for i in range(10)]},
        timeout=5,
    )
    assert r_too_many_tags.status_code == 400

    tagged = requests.get(f"{mock_rf_server.base_url}/list/{lid}/entitiesWithTags", headers=headers, timeout=5).json()
    assert len(tagged) == 1
    assert [t["name"] for t in tagged[0]["tags"]] == ["tier1", "brand"]

    r_rem = requests.post(
        f"{mock_rf_server.base_url}/list/{lid}/entity/remove",
        headers=headers,
        json={"entity": {"id": f"hash:{h1}"}},
        timeout=5,
    )
    assert r_rem.json() == {"result": "removed"}
    assert requests.get(f"{mock_rf_server.base_url}/list/{lid}/entities", headers=headers, timeout=5).json() == []


def test_mock_rf_server_soc_endpoints_auth_and_faults(mock_rf_server: MockRFServer) -> None:
    core_headers = {"X-RFToken": "test-rf-token"}
    sandbox_headers = {"Authorization": "Bearer test-sandbox-token"}

    assert os.environ["RF_BASE_URL"] == mock_rf_server.base_url
    assert os.environ["RF_SANDBOX_BASE_URL"] == mock_rf_server.sandbox_base_url

    # Strict token rejection + guarded numeric parameter validation (400 JSON, no disconnect)
    assert requests.post(
        f"{mock_rf_server.base_url}/list/search",
        headers={"X-RFToken": "wrong-rf-token"},
        json={},
        timeout=5,
    ).status_code == 401
    assert requests.get(
        f"{mock_rf_server.sandbox_base_url}/search",
        headers={"Authorization": "Bearer wrong-sandbox-token"},
        timeout=5,
    ).status_code == 401

    r_null_limit = requests.post(
        f"{mock_rf_server.base_url}/list/search",
        headers=core_headers,
        json={"limit": None},
        timeout=5,
    )
    assert r_null_limit.status_code == 400
    assert "trace_id" in r_null_limit.json()

    r_empty_offset = requests.post(
        f"{mock_rf_server.base_url}/detection-rule/search",
        headers=core_headers,
        json={"limit": 1, "offset": ""},
        timeout=5,
    )
    assert r_empty_offset.status_code == 400
    assert "trace_id" in r_empty_offset.json()

    assert requests.get(
        f"{mock_rf_server.base_url}/alert/v3",
        headers=core_headers,
        params={"limit": "-1"},
        timeout=5,
    ).status_code == 400

    # Detection rules: reject legacy operator, accept updated.after + pagination
    r_bad_dr = requests.post(
        f"{mock_rf_server.base_url}/detection-rule/search",
        headers=core_headers,
        json={"filter": {"updated": {"operator": "gt", "value": "2026-01-01T00:00:00Z"}}},
        timeout=5,
    )
    assert r_bad_dr.status_code == 400
    assert "trace_id" in r_bad_dr.json()

    r_dr_p1 = requests.post(
        f"{mock_rf_server.base_url}/detection-rule/search",
        headers=core_headers,
        json={"filter": {"types": ["sigma"], "updated": {"after": "2026-01-01T00:00:00Z"}}, "limit": 1},
        timeout=5,
    )
    assert r_dr_p1.status_code == 200
    dr1 = r_dr_p1.json()
    assert len(dr1["result"]) == 1
    assert "next_offset" in dr1

    r_dr_p2 = requests.post(
        f"{mock_rf_server.base_url}/detection-rule/search",
        headers=core_headers,
        json={"filter": {"types": ["sigma"]}, "limit": 1, "offset": dr1["next_offset"]},
        timeout=5,
    )
    assert r_dr_p2.status_code == 200
    assert len(r_dr_p2.json()["result"]) == 1
    assert "next_offset" not in r_dr_p2.json()

    assert requests.get(f"{mock_rf_server.base_url}/detection-rule-relation/entity/list", headers=core_headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/detection-rule-relation/entity/types", headers=core_headers, timeout=5).status_code == 200

    # Entity Match
    r_em = requests.post(
        f"{mock_rf_server.base_url}/entity-match/match",
        headers=core_headers,
        json={"name": "Acme", "type": ["Company"]},
        timeout=5,
    )
    assert r_em.status_code == 200
    assert r_em.json()[0]["id"] == "company:abc123"
    assert requests.get(f"{mock_rf_server.base_url}/entity-match/entity/company:abc123", headers=core_headers, timeout=5).status_code == 200

    # SOAR v3
    assert requests.post(
        f"{mock_rf_server.base_url}/soar/v3/enrichment",
        headers=core_headers,
        json={"ip": ["198.51.100.10"]},
        timeout=5,
    ).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/soar/v3/triage/contexts", headers=core_headers, timeout=5).status_code == 200
    assert requests.post(
        f"{mock_rf_server.base_url}/soar/v3/triage/contexts/phishing",
        headers=core_headers,
        json={"domain": ["evil.invalid"]},
        timeout=5,
    ).json()["data"]["results"][0]["verdict"] is True

    # Connect v2 (including ip:/idn: prefix normalization)
    assert requests.get(f"{mock_rf_server.base_url}/v2/ip/198.51.100.10", headers=core_headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/v2/ip/ip:198.51.100.10", headers=core_headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/v2/domain/example.com", headers=core_headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/v2/company/by_domain/example.com", headers=core_headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/v2/ip/search", headers=core_headers, timeout=5).status_code == 200
    assert requests.head(f"{mock_rf_server.base_url}/v2/ip/risklist", headers=core_headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/v2/ip/risklist", headers=core_headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/v2/ip/riskrules", headers=core_headers, timeout=5).status_code == 200

    # Playbook Alerts + PNG image
    assert requests.post(f"{mock_rf_server.base_url}/playbook-alert/search", headers=core_headers, json={}, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/playbook-alert/common/pb-1", headers=core_headers, timeout=5).status_code == 200
    assert requests.post(f"{mock_rf_server.base_url}/playbook-alert/domain_abuse/pb-1", headers=core_headers, json={}, timeout=5).status_code == 200
    r_pb_img = requests.get(
        f"{mock_rf_server.base_url}/playbook-alert/domain_abuse/pb-1/image/screenshot-1",
        headers=core_headers,
        timeout=5,
    )
    assert r_pb_img.status_code == 200
    assert r_pb_img.content.startswith(b"\x89PNG\r\n\x1a\n")

    # Alerts v3, Alerts v2 update & Cases (aligned with RecordedFutureClient)
    assert requests.get(f"{mock_rf_server.base_url}/alert/v3", headers=core_headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.base_url}/alert/v3/alert-v3-1", headers=core_headers, timeout=5).status_code == 200
    r_hits = requests.get(
        f"{mock_rf_server.base_url}/alert/v3/hits",
        headers=core_headers,
        params={"ids": "hit-1"},
        timeout=5,
    )
    assert r_hits.status_code == 200
    assert r_hits.json()["data"]["hits"][0]["id"] == "hit-1"

    r_upd_v2 = requests.post(
        f"{mock_rf_server.base_url}/alert/v2/update",
        headers=core_headers,
        json=[{"id": "alert-v3-1", "statusInPortal": "Resolved"}],
        timeout=5,
    )
    assert r_upd_v2.status_code == 200
    assert r_upd_v2.json()["success"] == ["alert-v3-1"]

    r_case_search = requests.post(f"{mock_rf_server.base_url}/case/search", headers=core_headers, json={}, timeout=5)
    assert r_case_search.status_code == 200
    assert r_case_search.json()["status"]["status_code"] == "Ok"
    assert isinstance(r_case_search.json()["data"], list)

    r_case_lookup = requests.post(
        f"{mock_rf_server.base_url}/case/lookup",
        headers=core_headers,
        json={"ids": ["case-1"], "panels": ["summary", "details"]},
        timeout=5,
    )
    assert r_case_lookup.status_code == 200
    assert r_case_lookup.json()["status"]["status_code"] == "Ok"
    assert r_case_lookup.json()["data"][0]["id"] == "case-1"
    assert requests.post(
        f"{mock_rf_server.base_url}/case/lookup",
        headers=core_headers,
        json={"ids": ["case-missing"]},
        timeout=5,
    ).status_code == 404

    created_case = requests.post(
        f"{mock_rf_server.base_url}/case/create",
        headers=core_headers,
        json={"title": "New SOC Case"},
        timeout=5,
    ).json()
    assert created_case["title"] == "New SOC Case"
    assert requests.put(
        f"{mock_rf_server.base_url}/case/update",
        headers=core_headers,
        json={"id": created_case["id"], "status": "Closed"},
        timeout=5,
    ).json()["status"] == "Closed"

    # Sandbox v0 auth enforcement vs Core
    assert requests.get(f"{mock_rf_server.sandbox_base_url}/search", headers=core_headers, timeout=5).status_code == 401
    assert requests.get(f"{mock_rf_server.sandbox_base_url}/search", headers=sandbox_headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.sandbox_base_url}/samples/sample-1", headers=sandbox_headers, timeout=5).status_code == 200
    assert requests.get(f"{mock_rf_server.sandbox_base_url}/samples/sample-1/overview.json", headers=sandbox_headers, timeout=5).status_code == 200
    assert requests.post(f"{mock_rf_server.sandbox_base_url}/samples", headers=sandbox_headers, json={"filename": "a.bin"}, timeout=5).status_code == 200

    # Sandbox string error format
    r_sb_missing = requests.get(f"{mock_rf_server.sandbox_base_url}/samples/unknown", headers=sandbox_headers, timeout=5)
    assert r_sb_missing.status_code == 404
    assert isinstance(r_sb_missing.json()["error"], str)

    # Connect v2 traceId + dict error format
    r_v2_missing = requests.get(f"{mock_rf_server.base_url}/v2/ip/10.255.255.254", headers=core_headers, timeout=5)
    assert r_v2_missing.status_code == 404
    v2_err = r_v2_missing.json()
    assert isinstance(v2_err["error"], dict)
    assert "traceId" in v2_err

    # Fault injection: 429 Retry-After, 5xx, 403 module vs data
    mock_rf_server.queue_fault("/v2/ip/", 429, headers={"Retry-After": "2"})
    r_429 = requests.get(f"{mock_rf_server.base_url}/v2/ip/198.51.100.10", headers=core_headers, timeout=5)
    assert r_429.status_code == 429
    assert r_429.headers["Retry-After"] == "2"

    mock_rf_server.queue_fault("/list/", 503)
    r_503 = requests.post(f"{mock_rf_server.base_url}/list/search", headers=core_headers, json={}, timeout=5)
    assert r_503.status_code == 503
    assert "trace_id" in r_503.json()

    mock_rf_server.queue_fault(
        "/v2/ip/",
        403,
        body={"error": {"status": 403, "message": "Missing API privileges", "reason": "Forbidden"}, "traceId": "t-mod"},
    )
    r_mod = requests.get(f"{mock_rf_server.base_url}/v2/ip/198.51.100.10", headers=core_headers, timeout=5)
    assert r_mod.status_code == 403
    assert "Missing API privileges" in r_mod.json()["error"]["message"]

    mock_rf_server.queue_fault(
        "/v2/ip/",
        403,
        body={"error": {"status": 403, "message": "Missing Data permissions", "reason": "Forbidden"}, "traceId": "t-data"},
    )
    r_data = requests.get(f"{mock_rf_server.base_url}/v2/ip/198.51.100.10", headers=core_headers, timeout=5)
    assert r_data.status_code == 403
    assert "Missing Data permissions" in r_data.json()["error"]["message"]

    assert len(mock_rf_server.requests_log) > 20


def test_mock_splunk_server_endpoints_and_faults(mock_splunk_server: MockSplunkServer) -> None:
    headers = {"Authorization": "Bearer test-splunk-token"}
    assert os.environ["SPLUNK_HOST"] == mock_splunk_server.base_url
    assert os.environ["SPLUNK_APP"] == "SplunkEnterpriseSecuritySuite"

    # Reject empty Bearer, wrong Bearer, and empty Basic ":" (Og==)
    assert requests.get(
        f"{mock_splunk_server.base_url}/services/server/info",
        headers={"Authorization": "Bearer   "},
        timeout=5,
    ).status_code == 401
    assert requests.get(
        f"{mock_splunk_server.base_url}/services/server/info",
        headers={"Authorization": "Bearer wrong-splunk-token"},
        timeout=5,
    ).status_code == 401
    empty_basic = base64.b64encode(b":").decode("ascii")
    assert requests.get(
        f"{mock_splunk_server.base_url}/services/server/info",
        headers={"Authorization": f"Basic {empty_basic}"},
        timeout=5,
    ).status_code == 401

    info = requests.get(f"{mock_splunk_server.base_url}/services/server/info?output_mode=json", headers=headers, timeout=5)
    assert info.status_code == 200
    assert info.json()["entry"][0]["content"]["version"] == "10.2.0"

    ctx = requests.get(f"{mock_splunk_server.base_url}/services/authentication/currentcontext?output_mode=json", headers=headers, timeout=5)
    assert ctx.status_code == 200

    saved = requests.get(
        f"{mock_splunk_server.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches?output_mode=json",
        headers=headers,
        timeout=5,
    )
    assert saved.status_code == 200
    assert len(saved.json()["entry"]) >= 1

    job_resp = requests.post(
        f"{mock_splunk_server.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs?output_mode=json",
        headers=headers,
        data={"search": "search index=main | head 1", "exec_mode": "normal"},
        timeout=5,
    )
    assert job_resp.status_code == 201
    sid = job_resp.json()["sid"]

    status_resp = requests.get(f"{mock_splunk_server.base_url}/services/search/jobs/{sid}?output_mode=json", headers=headers, timeout=5)
    assert status_resp.status_code == 200
    assert status_resp.json()["entry"][0]["content"]["dispatchState"] == "DONE"

    res_resp = requests.get(f"{mock_splunk_server.base_url}/services/search/jobs/{sid}/results?output_mode=json", headers=headers, timeout=5)
    assert res_resp.status_code == 200
    assert len(res_resp.json()["results"]) == 1

    ctrl_resp = requests.post(
        f"{mock_splunk_server.base_url}/services/search/jobs/{sid}/control?output_mode=json",
        headers=headers,
        data={"action": "cancel"},
        timeout=5,
    )
    assert ctrl_resp.status_code == 200
    assert ctrl_resp.json()["output_mode"] == "json"

    mock_splunk_server.queue_fault("/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs", 500)
    assert requests.post(
        f"{mock_splunk_server.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs",
        headers=headers,
        data={"search": "search index=main"},
        timeout=5,
    ).status_code == 500
    assert len(mock_splunk_server.requests_log) >= 7


def test_workspace_isolation_and_run_cli_help(
    e2e_workspace: Path,
    run_cli: Callable[..., Any],
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    discovered_path = repo_root / "discovered_images.json"
    sigma_cache_path = repo_root / "sigma_rules_cache.json"

    discovered_before = discovered_path.read_bytes() if discovered_path.exists() else None
    sigma_before = sigma_cache_path.read_bytes() if sigma_cache_path.exists() else None

    assert Path.cwd() == e2e_workspace
    assert os.environ["SOCLENS_HOME"] == str(e2e_workspace)
    assert (e2e_workspace / "logs").is_dir()
    assert (e2e_workspace / "ignored_hashes.txt").is_file()
    assert "SOCLENS_AUTO_APPROVE" not in os.environ
    assert os.environ["SPLUNK_APP"] == "SplunkEnterpriseSecuritySuite"
    assert os.environ["RF_BASE_URL"] == "http://127.0.0.1:0"
    assert os.environ["RF_SANDBOX_BASE_URL"] == "http://127.0.0.1:0/api/v0"

    proc = run_cli(["--help"])
    assert proc.returncode == 0
    assert "watchlist" in proc.stdout
    assert "sigma" in proc.stdout
    assert "validate" in proc.stdout

    # Ensure running CLI did not touch repo-root artifacts
    if discovered_before is not None:
        assert discovered_path.read_bytes() == discovered_before
    else:
        assert not discovered_path.exists()

    if sigma_before is not None:
        assert sigma_cache_path.read_bytes() == sigma_before
    else:
        assert not sigma_cache_path.exists()

    # Verify JSONL file creation stays inside workspace if written
    log_file = e2e_workspace / "logs" / "smoke.jsonl"
    log_file.write_text(json.dumps({"ok": True}) + "\n", encoding="utf-8")
    assert log_file.is_file()
