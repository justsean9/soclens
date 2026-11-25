import hashlib
import json
import os
import socket
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from soclens.client import RecordedFutureClient
from soclens.watchlist import (
    DEFAULT_IGNORED_HASHES,
    EXCLUSION_KEYWORDS,
    PROMO_KEYWORDS,
    UI_ICON_KEYWORDS,
    apply_brand_sync_delta,
    calculate_brand_sync_delta,
    canonicalize_svg,
    compute_image_hashes,
    execute_domain_brand_sync,
    export_watchlist,
    extract_domains_from_watchlist_entities,
    filter_watchlist_entities,
    get_domain_image_hash,
    get_domains_from_watchlist,
    is_excluded_image,
    is_ignored_domain,
    is_noise_match,
    load_domains_file,
    load_ignored_hashes,
    normalize_text,
    save_discovered_locations,
    sort_watchlist_entities,
    sort_watchlists,
    validate_domain_brand_sync,
    validate_domains_live_status,
)


def _make_png(w: int = 64, h: int = 32, rgba: tuple[int, int, int, int] = (10, 20, 30, 255)) -> bytes:
    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    row = b"\x00" + bytes(rgba) * w
    idat = zlib.compress(row * h)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def _make_svg(label: str = "logo") -> bytes:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 40" '
        f'width="120" height="40"><rect width="120" height="40" data-id="{label}"/></svg>'
    ).encode()


def _mock_response(*, status_code: int = 200, text: str = "", content: bytes = b"", headers: dict[str, str] | None = None, url: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = content
    resp.headers = headers or {}
    resp.url = url
    resp.iter_content.return_value = iter(())
    return resp


class TestWatchlist(unittest.TestCase):
    @patch("soclens.watchlist.requests.get")
    def test_get_domain_image_hash_success(self, mock_get):
        mock_resp_main = _mock_response(
            text='<html><head><link rel="icon" href="/favicon.png"></head><body><img src="logo.jpg" id="logo"></body></html>',
            url="https://example.com/",
        )
        mock_resp_img1 = _mock_response(content=_make_png(32, 32, (1, 0, 0, 255)), headers={"Content-Type": "image/png"})
        mock_resp_img2 = _mock_response(content=_make_png(64, 32, (2, 0, 0, 255)), headers={"Content-Type": "image/png"})
        mock_resp_img3 = _mock_response(content=_make_png(16, 16, (3, 0, 0, 255)), headers={"Content-Type": "image/png"})

        mock_get.side_effect = [mock_resp_main, mock_resp_img1, mock_resp_img2, mock_resp_img3]

        hashes, count, err, img_errs, disc_locs = get_domain_image_hash("example.com")
        self.assertEqual(len(hashes), 3)  # favicon.png, logo.jpg, favicon.ico
        self.assertEqual(count, 3)
        self.assertIsNone(err)
        self.assertEqual(len(img_errs), 0)
        self.assertEqual(len(disc_locs), 3)

    def test_load_domains_file(self):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
            tmp.write("domain\nexample.com\ntest.org\n")
            tmp_path = tmp.name

        try:
            domains = load_domains_file(tmp_path)
            self.assertEqual(domains, ["example.com", "test.org"])
        finally:
            os.remove(tmp_path)

    def test_get_domains_from_watchlist(self):
        client = MagicMock(spec=RecordedFutureClient)
        client.get_watchlist_entities.return_value = [
            {"entity": {"name": "example.com", "type": "InternetDomainName"}, "context": {"annotation": "some note"}},
            {"entity": {"name": "offline.com", "type": "InternetDomainName"}, "context": {"annotation": "noninternet"}},
            {"entity": {"name": "localhost", "type": "InternetDomainName"}, "context": {"annotation": "local [noninternet]"}},
            {"entity": {"name": "test.com", "type": "InternetDomainName"}, "context": None},
        ]

        domains = get_domains_from_watchlist(client, "list_1")
        self.assertEqual(domains, ["example.com", "test.com"])

    @patch("soclens.watchlist.get_domain_image_hash")
    def test_validate_domain_brand_sync(self, mock_get_hash):
        client = MagicMock(spec=RecordedFutureClient)
        mock_get_hash.return_value = (
            [{"sha1": "sha1_val", "sha256": "sha256_val", "image_url": "http://img.com"}],
            1,
            None,
            [],
            [{"domain": "example.com", "url": "http://img.com", "source": "logo", "status": "included"}],
        )

        client.get_watchlist_entities.return_value = [
            {"entity": {"name": "sha256_val", "type": "Hash"}, "context": {"source": "automated-watchlist-manager"}}
        ]

        res = validate_domain_brand_sync(
            client, "list_1", ["example.com"], output_locations_file=None
        )
        self.assertTrue(res)

    @patch("soclens.watchlist.get_domain_image_hash")
    def test_execute_domain_brand_sync(self, mock_get_hash):
        client = MagicMock(spec=RecordedFutureClient)

        mock_get_hash.return_value = (
            [{"sha256": "new_hash", "image_url": "http://img.com/logo"}],
            1,
            None,
            [],
            [{"domain": "example.com", "url": "http://img.com/logo", "source": "logo", "status": "included"}],
        )

        client.get_watchlist_entities.return_value = [
            {"entity": {"name": "old_hash", "id": "ent_1", "type": "Hash"}, "context": {"source": "automated-watchlist-manager"}}
        ]

        client.remove_entity.return_value = True
        client.add_entity.return_value = True

        res = execute_domain_brand_sync(
            client,
            "list_1",
            ["example.com"],
            dry_run=False,
            output_locations_file=None,
            state_file=None,
        )
        self.assertTrue(res)
        client.remove_entity.assert_called_once_with("list_1", "ent_1")
        client.add_entity.assert_called_once()
        args, kwargs = client.add_entity.call_args
        self.assertEqual(args[0], "list_1")
        self.assertEqual(args[1], "Hash")
        self.assertEqual(args[2], "new_hash")
        self.assertEqual(kwargs["context"]["source"], "automated-watchlist-manager")

    @patch("soclens.watchlist.socket.gethostbyname")
    def test_validate_domains_live_status_interactive(self, mock_dns):
        client = MagicMock(spec=RecordedFutureClient)
        client.get_watchlist_entities.return_value = [
            {"entity": {"name": "live.com", "id": "1", "type": "InternetDomainName"}, "context": {}},
            {"entity": {"name": "offline.com", "id": "2", "type": "InternetDomainName"}, "context": {"annotation": "some comment"}},
        ]

        mock_dns.side_effect = ["192.168.1.1", socket.gaierror()]
        client.add_entity.return_value = True

        with patch("builtins.input") as mock_input:
            mock_input.side_effect = ["all", "y"]
            res = validate_domains_live_status(client, "list_1", interactive=True)
            self.assertTrue(res)

        client.add_entity.assert_called_once_with(
            "list_1",
            "InternetDomainName",
            "offline.com",
            context={"annotation": "some comment [noninternet]"},
        )

    @patch("soclens.watchlist.socket.gethostbyname")
    def test_validate_domains_live_status_dry_run(self, mock_dns):
        client = MagicMock(spec=RecordedFutureClient)
        client.get_watchlist_entities.return_value = [
            {"entity": {"name": "offline.com", "id": "2", "type": "InternetDomainName"}, "context": {"annotation": "some comment"}}
        ]
        mock_dns.side_effect = [socket.gaierror()]
        client.add_entity.return_value = True

        with patch("builtins.input") as mock_input:
            mock_input.side_effect = ["all", "y"]
            res = validate_domains_live_status(client, "list_1", interactive=True, dry_run=True)
            self.assertTrue(res)

        client.add_entity.assert_not_called()

    def test_is_excluded_image(self):
        res, reason = is_excluded_image("https://mybank.com/images/fdic_logo.png", "mybank.com")
        self.assertTrue(res)
        self.assertIn("fdic", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/images/equalhousing.png", "mybank.com")
        self.assertTrue(res)
        self.assertIn("equalhousing", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/social/facebook-icon.svg", "mybank.com")
        self.assertTrue(res)
        self.assertIn("facebook", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/assets/google-play-badge.png", "mybank.com")
        self.assertTrue(res)
        self.assertIn("play", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/norton-seal.png", "mybank.com")
        self.assertTrue(res)
        self.assertIn("norton", reason.lower())

        res, reason = is_excluded_image("https://facebook.com/brand/logo.png", "facebook.com")
        self.assertFalse(res)
        self.assertIsNone(reason)

        res, reason = is_excluded_image("https://mybank.com/images/mybank-logo.png", "mybank.com")
        self.assertFalse(res)
        self.assertIsNone(reason)

    def test_save_discovered_locations(self):
        locs = [
            {"domain": "test.com", "url": "https://test.com/logo.png", "source": "og:image", "status": "included"}
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "nested" / "discovered.json"
            save_discovered_locations(locs, dest)
            data = json.loads(dest.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["domain"], "test.com")

            # None skips file creation cleanly
            save_discovered_locations(locs, None)

    @patch("soclens.watchlist.requests.get")
    def test_get_domain_image_hash_exclusions(self, mock_get):
        mock_resp_main = _mock_response(
            text=(
                '<html><head><link rel="icon" href="/favicon.png"></head>'
                "<body>"
                '<img src="/images/real-logo.png" id="logo">'
                '<img src="/images/fdic-member.png" class="fdic-logo">'
                '<img src="/images/fb-logo.png" alt="Facebook Icon">'
                "</body></html>"
            ),
            url="https://example.com/",
        )
        mock_resp_img1 = _mock_response(content=_make_png(32, 32, (11, 0, 0, 255)), headers={"Content-Type": "image/png"})
        mock_resp_img2 = _mock_response(content=_make_png(64, 32, (12, 0, 0, 255)), headers={"Content-Type": "image/png"})
        mock_resp_img3 = _mock_response(content=_make_png(16, 16, (13, 0, 0, 255)), headers={"Content-Type": "image/png"})

        mock_get.side_effect = [mock_resp_main, mock_resp_img1, mock_resp_img2, mock_resp_img3]

        hashes, _, err, _, disc_locs = get_domain_image_hash("example.com")

        self.assertEqual(len(hashes), 3)  # real-logo, favicon.png, favicon.ico
        self.assertIsNone(err)

        excluded = [d for d in disc_locs if d["status"] == "excluded"]
        included = [d for d in disc_locs if d["status"] == "included"]

        self.assertEqual(len(included), 3)
        self.assertEqual(len(excluded), 2)  # fdic-member, fb-logo

        excl_urls = [e["url"] for e in excluded]
        self.assertTrue(any("fdic" in u for u in excl_urls))
        self.assertTrue(any("fb" in u for u in excl_urls))

    def test_extract_domains_from_watchlist_entities(self):
        client = MagicMock(spec=RecordedFutureClient)
        client.get_watchlist_entities.return_value = [
            {"entity": {"name": "google.com", "type": "InternetDomainName"}, "context": {}},
            {"entity": {"name": "hashval1", "type": "Hash"}, "context": {"domain": "yahoo.com"}},
            {"entity": {"name": "hashval2", "type": "Hash"}, "context": {"annotation": "automated sync: brand image for bing.com"}},
            {"entity": {"name": "", "type": "Hash"}, "context": {}},
        ]

        domains = extract_domains_from_watchlist_entities(client, "list_123")
        self.assertEqual(domains, ["bing.com", "google.com", "yahoo.com"])

    def test_is_excluded_image_parent_and_normalization(self):
        res, reason = is_excluded_image("https://mybank.com/assets/google_play_badge-logo.png", "mybank.com")
        self.assertTrue(res)
        self.assertIn("play", reason.lower())

        res, reason = is_excluded_image(
            "https://mybank.com/images/logo.png",
            "mybank.com",
            parent_tags=["div", "footer"],
        )
        self.assertTrue(res)
        self.assertIn("footer", reason.lower())

        res, reason = is_excluded_image(
            "https://mybank.com/images/logo.png",
            "mybank.com",
            parent_classes=["award-winner", "container"],
        )
        self.assertTrue(res)
        self.assertIn("award-winner", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/bauer-financial-logo-300x290.png", "mybank.com")
        self.assertTrue(res)
        self.assertIn("bauer financial", reason.lower())

    @patch("soclens.watchlist.requests.get")
    def test_get_domain_image_hash_contextual_exclusions(self, mock_get):
        mock_resp_main = _mock_response(
            text=(
                "<html><body>"
                '<div class="header">'
                '  <img src="/images/main-logo.png" id="logo" alt="Main Logo">'
                "</div>"
                "<footer>"
                '  <img src="/images/footer-logo.png" alt="Footer logo">'
                "</footer>"
                '<div class="badge-container">'
                '  <img src="/images/partner-logo.png" alt="Partner Logo">'
                "</div>"
                '<div class="content">'
                '  <img src="/images/bauer-financial-logo-300x290.png" alt="Bauer Financial">'
                "</div>"
                "</body></html>"
            ),
            url="https://example.com/",
        )

        mock_resp_img1 = _mock_response(content=_make_png(64, 32, (21, 0, 0, 255)), headers={"Content-Type": "image/png"})
        mock_resp_img2 = _mock_response(content=_make_png(16, 16, (22, 0, 0, 255)), headers={"Content-Type": "image/png"})

        mock_get.side_effect = [mock_resp_main, mock_resp_img1, mock_resp_img2]

        hashes, _, _, _, disc_locs = get_domain_image_hash("example.com")

        self.assertEqual(len(hashes), 2)

        excluded = [d for d in disc_locs if d["status"] == "excluded"]
        excl_urls = [e["url"] for e in excluded]

        self.assertTrue(any("footer-logo" in u for u in excl_urls))
        self.assertTrue(any("partner-logo" in u for u in excl_urls))
        self.assertTrue(any("bauer-financial" in u for u in excl_urls))

    def test_export_watchlist_csv(self):
        client = MagicMock(spec=RecordedFutureClient)
        client.get_watchlist_entities.return_value = [
            {
                "entity": {"name": "google.com", "type": "InternetDomainName", "id": "1"},
                "context": {
                    "annotation": "test note",
                    "source": "manual",
                    "domain": "google.com",
                    "image_url": "http://google.com/favicon.ico",
                    "sync_time": "2026-07-06T12:00:00Z",
                },
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / "export.csv"
            res = export_watchlist(client, "list_123", tmp_path, file_format="csv")
            self.assertTrue(res)
            content = tmp_path.read_text(encoding="utf-8")
            self.assertIn("name,type,id,annotation,source,domain,image_url,sync_time", content)
            self.assertIn(
                "google.com,InternetDomainName,1,test note,manual,google.com,http://google.com/favicon.ico,2026-07-06T12:00:00Z",
                content,
            )

    def test_export_watchlist_json(self):
        client = MagicMock(spec=RecordedFutureClient)
        client.get_watchlist_entities.return_value = [
            {
                "entity": {"name": "google.com", "type": "InternetDomainName", "id": "1"},
                "context": {"annotation": "test note"},
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / "export.json"
            res = export_watchlist(client, "list_123", tmp_path, file_format="json")
            self.assertTrue(res)
            data = json.loads(tmp_path.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["entity"]["name"], "google.com")

    def test_load_ignored_hashes_defaults_and_env(self):
        # Isolate from repo-root ignored_hashes.txt
        orig_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                os.chdir(tmpdir)
                hashes = load_ignored_hashes()
                self.assertIn("6bdb369337ac2496761c6f063bffea0aa6a91d4662279c399071a468251f51f0", hashes)
                self.assertIn("d6f77ffdaebe6142823d2cf503a13040", hashes)

                custom_md5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                custom_sha1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                custom_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                hashes_extra = load_ignored_hashes(
                    extra_hashes=[custom_md5, f"{custom_sha1},{custom_sha256}"]
                )
                self.assertIn(custom_md5, hashes_extra)
                self.assertIn(custom_sha1, hashes_extra)
                self.assertIn(custom_sha256, hashes_extra)

                env_hash = "dddddddddddddddddddddddddddddddd"
                with patch.dict(os.environ, {"RF_IGNORED_HASHES": f"{env_hash}, invalid_hash"}):
                    hashes_env = load_ignored_hashes()
                    self.assertIn(env_hash, hashes_env)
                    self.assertNotIn("invalid_hash", hashes_env)
            finally:
                os.chdir(orig_cwd)

    def test_load_ignored_hashes_from_files(self):
        txt_content = (
            "# Ignored hashes file\n"
            "11111111111111111111111111111111 # Custom MD5 noise\n"
            "2222222222222222222222222222222222222222,Custom SHA-1 noise\n"
            "3333333333333333333333333333333333333333333333333333333333333333: Custom SHA-256 noise\n"
            "# Invalid line\n"
            "short_hash\n"
        )
        json_content = {
            "44444444444444444444444444444444": "JSON MD5",
            "5555555555555555555555555555555555555555": "JSON SHA-1",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            txt_path = Path(tmpdir) / "ignored.txt"
            json_path = Path(tmpdir) / "ignored.json"
            txt_path.write_text(txt_content, encoding="utf-8")
            json_path.write_text(json.dumps(json_content), encoding="utf-8")

            hashes_txt = load_ignored_hashes(file_path=txt_path)
            self.assertIn("11111111111111111111111111111111", hashes_txt)
            self.assertIn("2222222222222222222222222222222222222222", hashes_txt)
            self.assertIn("3333333333333333333333333333333333333333333333333333333333333333", hashes_txt)
            self.assertNotIn("short_hash", hashes_txt)

            hashes_json = load_ignored_hashes(file_path=json_path)
            self.assertIn("44444444444444444444444444444444", hashes_json)
            self.assertIn("5555555555555555555555555555555555555555", hashes_json)

    def test_is_noise_match_negations(self):
        self.assertFalse(is_noise_match("no-sidebar", "sidebar"))
        self.assertFalse(is_noise_match("without-sidebar", "sidebar"))
        self.assertFalse(is_noise_match("non-sidebar", "sidebar"))
        self.assertFalse(is_noise_match("sidebar-none", "sidebar"))
        self.assertFalse(is_noise_match("sidebar-off", "sidebar"))
        self.assertFalse(is_noise_match("sidebar-false", "sidebar"))
        self.assertFalse(is_noise_match("page-template-default no-sidebar", "sidebar"))

        self.assertTrue(is_noise_match("main-sidebar", "sidebar"))
        self.assertTrue(is_noise_match("sidebar", "sidebar"))
        self.assertTrue(is_noise_match("award-winner", "award"))
        self.assertTrue(is_noise_match("social-links", "social"))
        self.assertTrue(is_noise_match("badge-container", "badge"))

    def test_is_excluded_image_no_sidebar_regression(self):
        res, reason = is_excluded_image(
            url="https://adamscommunity.com/wp-content/uploads/2013/11/logo.png",
            target_domain="adamscommunity.com",
            alt="Adams Community Bank",
            parent_classes=["page-template-default", "no-sidebar"],
        )
        self.assertFalse(res, f"Logo was falsely excluded: {reason}")
        self.assertIsNone(reason)

    def test_is_excluded_image_promotional_banners(self):
        res, reason = is_excluded_image(
            "https://mybank.com/uploads/11mthBusCD_SliderDesktop_V1.jpg",
            "mybank.com",
        )
        self.assertTrue(res)
        self.assertIn("slider", reason.lower())

        res, reason = is_excluded_image(
            "https://mybank.com/uploads/free-food-container-set-with-checking.png",
            "mybank.com",
        )
        self.assertTrue(res)
        self.assertTrue("checking" in reason.lower() or "food-container" in reason.lower())

        res, reason = is_excluded_image(
            "https://mybank.com/images/Personal-Banking-Checking.svg",
            "mybank.com",
        )
        self.assertTrue(res)
        self.assertIn("checking", reason.lower())

        res, reason = is_excluded_image(
            "https://mybank.com/uploads/spring-campaign-hero.jpg",
            "mybank.com",
        )
        self.assertTrue(res)
        self.assertTrue("hero" in reason.lower() or "campaign" in reason.lower())

        res, reason = is_excluded_image(
            "https://mybank.com/images/banner-logo.png",
            "mybank.com",
            alt="MyBank Logo",
        )
        self.assertFalse(res)
        self.assertIsNone(reason)

    def test_is_excluded_image_third_party_and_immunity(self):
        res, reason = is_excluded_image("https://mybank.com/img/visa-card.png", "mybank.com")
        self.assertTrue(res)
        self.assertIn("visa", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/img/mastercard-badge.svg", "mybank.com")
        self.assertTrue(res)
        self.assertIn("mastercard", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/img/cookiebot.svg", "mybank.com")
        self.assertTrue(res)
        self.assertIn("cookiebot", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/img/onetrust-seal.png", "mybank.com")
        self.assertTrue(res)
        self.assertIn("onetrust", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/img/recaptcha-badge.png", "mybank.com")
        self.assertTrue(res)
        self.assertIn("recaptcha", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/img/ncua.png", "mybank.com")
        self.assertTrue(res)
        self.assertIn("ncua", reason.lower())

        res, reason = is_excluded_image("https://mybank.com/icons/search-icon.svg", "mybank.com")
        self.assertTrue(res)
        self.assertIn("search", reason.lower())

        res, reason = is_excluded_image("https://bannerbank.com/img/banner-logo.png", "bannerbank.com")
        self.assertFalse(res)
        self.assertIsNone(reason)

        res, reason = is_excluded_image("https://discoverbank.com/img/discover-logo.png", "discoverbank.com")
        self.assertFalse(res)
        self.assertIsNone(reason)

    def test_is_excluded_image_workplace_and_industry_awards(self):
        res, reason = is_excluded_image(
            "https://www.example.com/wp-content/uploads/2024-2025-GPTW.png",
            "example.com",
            alt="Great Place to Work 2024-2025 Greyscale Logo",
        )
        self.assertTrue(res)
        self.assertTrue("gptw" in reason.lower() or "great place to work" in reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/top-workplaces-badge.png", "example.com")
        self.assertTrue(res)
        self.assertIn("top workplace", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/american-banker-industry.png", "example.com")
        self.assertTrue(res)
        self.assertIn("american banker", reason.lower())

        res, reason = is_excluded_image("https://example.com/badges/best-places-to-work-2025.png", "example.com")
        self.assertTrue(res)
        self.assertIn("best place", reason.lower())

        res, reason = is_excluded_image("https://www.example.com/wp-content/uploads/2025-IGEL-award-logo.png", "example.com")
        self.assertTrue(res)
        self.assertTrue("award" in reason.lower() or "igel" in reason.lower())

    def test_is_excluded_image_modal_dialog_and_popup_parents(self):
        res, reason = is_excluded_image(
            "https://harborbank.example/assets/content/3dAFuV6R/BFTC 300 x 300.png",
            "harborbank.example",
            parent_classes=["modal-body", "alert-body"],
        )
        self.assertTrue(res)
        self.assertTrue("modal" in reason.lower() or "alert" in reason.lower())

        res, reason = is_excluded_image(
            "https://example.com/assets/promo.png",
            "example.com",
            parent_tags=["dialog"],
        )
        self.assertTrue(res)
        self.assertIn("dialog", reason.lower())

        res, reason = is_excluded_image(
            "https://example.com/assets/banner.png",
            "example.com",
            parent_classes=["lightbox-content"],
        )
        self.assertTrue(res)
        self.assertIn("lightbox", reason.lower())

    def test_is_excluded_image_community_promo(self):
        res, reason = is_excluded_image("https://example.com/bftc-event.png", "example.com")
        self.assertTrue(res)
        self.assertIn("bftc", reason.lower())

        res, reason = is_excluded_image("https://example.com/giveaway-entry.png", "example.com")
        self.assertTrue(res)
        self.assertIn("giveaway", reason.lower())

    @patch("soclens.watchlist.requests.get")
    def test_icon_stem_deduplication(self, mock_get):
        mock_resp_main = _mock_response(
            text=(
                "<html><head>"
                '<link rel="icon" href="/uploads/cropped-site-icon-32x32.png" sizes="32x32">'
                '<link rel="apple-touch-icon" href="/uploads/cropped-site-icon-180x180.png">'
                '<link rel="icon" href="/uploads/cropped-site-icon-192x192.png" sizes="192x192">'
                "</head><body>"
                '<img src="/logo.svg" id="site-logo">'
                "</body></html>"
            ),
            url="https://example.com/",
        )
        mock_resp_icon = _mock_response(content=_make_png(192, 192, (31, 0, 0, 255)), headers={"Content-Type": "image/png"})
        mock_resp_svg = _mock_response(content=_make_svg("site-logo"), headers={"Content-Type": "image/svg+xml"})
        mock_resp_ico = _mock_response(content=_make_png(16, 16, (32, 0, 0, 255)), headers={"Content-Type": "image/png"})

        mock_get.side_effect = [mock_resp_main, mock_resp_icon, mock_resp_svg, mock_resp_ico]

        hashes, _, err, _, disc_locs = get_domain_image_hash("example.com")
        self.assertIsNone(err)

        excluded_icons = [
            d
            for d in disc_locs
            if d.get("status") == "excluded" and "cropped-site-icon.png" in d.get("exclusion_reason", "")
        ]
        self.assertEqual(len(excluded_icons), 2)

        included_urls = [d["image_url"] for d in hashes]
        self.assertTrue(any("cropped-site-icon-192x192.png" in u for u in included_urls))
        self.assertFalse(any("cropped-site-icon-180x180.png" in u for u in included_urls))
        self.assertFalse(any("cropped-site-icon-32x32.png" in u for u in included_urls))

    @patch("soclens.watchlist.requests.get")
    def test_touch_icon_deduplication(self, mock_get):
        mock_resp_main = _mock_response(
            text=(
                "<html><head>"
                '<link rel="apple-touch-icon" sizes="57x57" href="/icon-57.png">'
                '<link rel="apple-touch-icon" sizes="120x120" href="/icon-120.png">'
                '<link rel="apple-touch-icon" sizes="180x180" href="/icon-180.png">'
                "</head><body>"
                '<img src="/logo.png" id="site-logo">'
                "</body></html>"
            ),
            url="https://mybank.com/",
        )
        mock_resp_img1 = _mock_response(content=_make_png(180, 180, (41, 0, 0, 255)), headers={"Content-Type": "image/png"})
        mock_resp_img2 = _mock_response(content=_make_png(120, 40, (42, 0, 0, 255)), headers={"Content-Type": "image/png"})
        mock_resp_img3 = _mock_response(content=_make_png(16, 16, (43, 0, 0, 255)), headers={"Content-Type": "image/png"})

        mock_get.side_effect = [mock_resp_main, mock_resp_img1, mock_resp_img2, mock_resp_img3]

        hashes, _, err, _, disc_locs = get_domain_image_hash("mybank.com")
        self.assertIsNone(err)

        excluded_touch = [
            d
            for d in disc_locs
            if d.get("status") == "excluded" and "duplicate touch icon" in d.get("exclusion_reason", "")
        ]
        self.assertEqual(len(excluded_touch), 2)
        excluded_urls = [d["url"] for d in excluded_touch]
        self.assertTrue(any("icon-57.png" in u for u in excluded_urls))
        self.assertTrue(any("icon-120.png" in u for u in excluded_urls))

        included_urls = [d["image_url"] for d in hashes]
        self.assertTrue(any("icon-180.png" in u for u in included_urls))
        self.assertTrue(any("logo.png" in u for u in included_urls))

    @patch("soclens.watchlist.requests.get")
    def test_multi_algorithm_hash_tuning(self, mock_get):
        mock_resp_main = _mock_response(
            text='<html><body><img src="/logo.png" id="logo"></body></html>',
            url="https://mybank.com/",
        )

        payload = _make_png(80, 40, (55, 66, 77, 255))
        md5_noise = hashlib.md5(payload).hexdigest()
        sha1_noise = hashlib.sha1(payload).hexdigest()

        mock_resp_img = _mock_response(content=payload, headers={"Content-Type": "image/png"})

        mock_get.side_effect = [mock_resp_main, mock_resp_img, mock_resp_img]
        hashes, _, _, _, disc_locs = get_domain_image_hash(
            "mybank.com", ignored_hashes={md5_noise: "Tuned out MD5"}
        )
        self.assertEqual(len(hashes), 0)
        excl = [
            d
            for d in disc_locs
            if d.get("status") == "excluded" and "Tuned out MD5" in d.get("exclusion_reason", "")
        ]
        self.assertTrue(len(excl) > 0)

        mock_get.side_effect = [mock_resp_main, mock_resp_img, mock_resp_img]
        hashes, _, _, _, disc_locs = get_domain_image_hash(
            "mybank.com", ignored_hashes={sha1_noise: "Tuned out SHA-1"}
        )
        self.assertEqual(len(hashes), 0)
        excl = [
            d
            for d in disc_locs
            if d.get("status") == "excluded" and "Tuned out SHA-1" in d.get("exclusion_reason", "")
        ]
        self.assertTrue(len(excl) > 0)

    @patch("soclens.watchlist.get_domain_image_hash")
    def test_calculate_brand_sync_delta_purges_tuned_out_hashes(self, mock_get_hash):
        client = MagicMock(spec=RecordedFutureClient)
        mock_get_hash.return_value = (
            [{"sha256": "clean_sha256_hash", "image_url": "https://example.com/logo.png"}],
            1,
            None,
            [],
            [],
        )

        tuned_out_sha256 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

        client.get_watchlist_entities.return_value = [
            {"entity": {"name": "clean_sha256_hash", "id": "1", "type": "Hash"}, "context": {}},
            {"entity": {"name": tuned_out_sha256, "id": "2", "type": "Hash"}, "context": {"source": "manual_or_old"}},
        ]

        target_hashes, existing_map, to_add, to_remove, domain_errors, image_errors = (
            calculate_brand_sync_delta(
                client,
                "list_1",
                ["example.com"],
                output_locations_file=None,
                ignored_hashes={tuned_out_sha256: "Vendor noise placeholder"},
                state_file=None,
            )
        )

        self.assertEqual(domain_errors, {})
        self.assertEqual(image_errors, {})
        to_remove_names = [e.get("name") for e in to_remove]
        self.assertIn(tuned_out_sha256, to_remove_names)

    def test_is_excluded_image_banking_disclosures_and_insurance(self):
        res, reason = is_excluded_image("https://example.com/assets/dif-logo.png", "example.com")
        self.assertTrue(res)
        self.assertIn("dif", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/different-graphic-logo.png", "example.com")
        self.assertFalse(res)
        self.assertIsNone(reason)

        res, reason = is_excluded_image("https://example.com/assets/msic-seal.png", "example.com")
        self.assertTrue(res)
        self.assertIn("msic", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/asi-insured.png", "example.com")
        self.assertTrue(res)
        self.assertIn("asi", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/eho-badge.png", "example.com")
        self.assertTrue(res)
        self.assertIn("eho", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/ehl-badge.png", "example.com")
        self.assertTrue(res)
        self.assertIn("ehl", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/usa-patriot-act-notice.png", "example.com")
        self.assertTrue(res)
        self.assertIn("patriot act", reason.lower())

    def test_is_excluded_image_atm_and_fintech_networks(self):
        res, reason = is_excluded_image("https://example.com/assets/allpoint-atm-locator.png", "example.com")
        self.assertTrue(res)
        self.assertIn("allpoint", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/moneypass-network.png", "example.com")
        self.assertTrue(res)
        self.assertIn("moneypass", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/coop-atm.png", "example.com")
        self.assertTrue(res)
        self.assertIn("coop", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/fiserv-badge.png", "example.com")
        self.assertTrue(res)
        self.assertIn("fiserv", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/banno-login.png", "example.com")
        self.assertTrue(res)
        self.assertIn("banno", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/savvymoney-score.png", "example.com")
        self.assertTrue(res)
        self.assertIn("savvymoney", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/deluxe-checks.png", "example.com")
        self.assertTrue(res)
        self.assertIn("deluxe", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/audioeye-widget.svg", "example.com")
        self.assertTrue(res)
        self.assertIn("audioeye", reason.lower())

        res, reason = is_excluded_image("https://example.com/assets/forbes-award-logo.png", "example.com")
        self.assertTrue(res)
        self.assertIn("forbes", reason.lower())

    @patch("soclens.watchlist.requests.get")
    def test_schema_org_json_ld_logo_extraction(self, mock_get):
        mock_resp_main = _mock_response(
            text=(
                "<html><head>"
                '<script type="application/ld+json">'
                "{\n"
                '  "@context": "https://schema.org",\n'
                '  "@type": "BankOrCreditUnion",\n'
                '  "name": "Community Federal Credit Union",\n'
                '  "logo": "https://example.com/assets/canonical-brand-logo.svg"\n'
                "}\n"
                "</script>"
                "</head><body><p>Welcome to our bank</p></body></html>"
            ),
            url="https://example.com/",
        )
        mock_resp_svg = _mock_response(content=_make_svg("canonical"), headers={"Content-Type": "image/svg+xml"})
        mock_resp_ico = _mock_response(content=_make_png(16, 16, (61, 0, 0, 255)), headers={"Content-Type": "image/png"})

        mock_get.side_effect = [mock_resp_main, mock_resp_svg, mock_resp_ico]

        hashes, _, err, _, disc_locs = get_domain_image_hash("example.com")
        self.assertIsNone(err)
        self.assertEqual(len(hashes), 2)

        ld_entries = [d for d in disc_locs if "schema.org" in d.get("source", "")]
        self.assertTrue(len(ld_entries) > 0)
        self.assertEqual(ld_entries[0]["url"], "https://example.com/assets/canonical-brand-logo.svg")

    @patch("soclens.watchlist.requests.get")
    def test_picture_srcset_and_header_home_link(self, mock_get):
        mock_resp_main = _mock_response(
            text=(
                "<html><head></head><body>"
                "<header>"
                '  <a href="/" rel="home" class="main-site-branding">'
                "    <picture>"
                '      <source srcset="/assets/header-logo.svg" type="image/svg+xml">'
                '      <img src="/assets/header-logo.png" alt="Bank Home">'
                "    </picture>"
                "  </a>"
                "</header>"
                "</body></html>"
            ),
            url="https://example.com/",
        )
        mock_resp_png = _mock_response(content=_make_png(120, 40, (71, 0, 0, 255)), headers={"Content-Type": "image/png"})
        mock_resp_svg = _mock_response(content=_make_svg("header"), headers={"Content-Type": "image/svg+xml"})
        mock_resp_ico = _mock_response(content=_make_png(16, 16, (72, 0, 0, 255)), headers={"Content-Type": "image/png"})

        mock_get.side_effect = [mock_resp_main, mock_resp_png, mock_resp_svg, mock_resp_ico]

        hashes, _, err, _, disc_locs = get_domain_image_hash("example.com")
        self.assertIsNone(err)
        self.assertEqual(len(hashes), 3)

        found_urls = [d["url"] for d in disc_locs]
        self.assertTrue(any("header-logo.svg" in u for u in found_urls))
        self.assertTrue(any("header-logo.png" in u for u in found_urls))

    def test_watchlist_backward_compatibility_exports_and_paths(self):
        # Verify all expected public symbols exist and are usable
        self.assertIsInstance(DEFAULT_IGNORED_HASHES, dict)
        self.assertIsInstance(PROMO_KEYWORDS, dict)
        self.assertIsInstance(UI_ICON_KEYWORDS, dict)
        self.assertIsInstance(EXCLUSION_KEYWORDS, dict)
        self.assertTrue(callable(apply_brand_sync_delta))
        self.assertTrue(callable(canonicalize_svg))
        self.assertTrue(callable(compute_image_hashes))
        self.assertTrue(callable(is_ignored_domain))
        self.assertEqual(normalize_text("Acme-Bank_Logo"), "acme bank logo")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            domains_path = tmp / "domains.csv"
            domains_path.write_text("domain\nexample.com\n", encoding="utf-8")
            self.assertEqual(load_domains_file(domains_path), ["example.com"])

            out_locs = tmp / "locs.json"
            client = MagicMock(spec=RecordedFutureClient)
            client.get_watchlist_entities.return_value = []
            with patch("soclens.watchlist.get_domain_image_hash") as mock_hash:
                mock_hash.return_value = (
                    [{"sha256": "a" * 64, "image_url": "https://example.com/logo.png"}],
                    1,
                    None,
                    [],
                    [{"domain": "example.com", "url": "https://example.com/logo.png", "status": "included"}],
                )
                delta = calculate_brand_sync_delta(
                    client,
                    "list_1",
                    ["example.com"],
                    output_locations_file=out_locs,
                    state_file=None,
                )
                self.assertEqual(len(delta), 6)
                self.assertTrue(out_locs.is_file())

    def test_sort_and_filter_watchlist_entities_and_lists(self):
        entries = [
            {
                "entity": {"id": "idn:zeta.com", "type": "InternetDomainName", "name": "zeta.com"},
                "status": "ready",
                "context": {"annotation": "Zeta note"},
            },
            {
                "entity": {"id": "idn:irisbank.com", "type": "InternetDomainName", "name": "irisbank.com"},
                "status": "added",
                "context": {"annotation": ""},
            },
            {
                "entity": {"id": "hash:1111", "type": "Hash", "name": "alpha-hash"},
                "status": "ready",
                "context": {"annotation": "Alpha brand logo", "domain": "alpha.example"},
            },
            {
                "entity": {"id": "ip:198.51.100.5", "type": "IpAddress", "name": "198.51.100.5"},
                "status": "ready",
                "context": None,
            },
        ]

        # "none" preserves original order
        self.assertEqual(
            [e["entity"]["name"] for e in sort_watchlist_entities(entries, sort_by="none")],
            ["zeta.com", "irisbank.com", "alpha-hash", "198.51.100.5"],
        )

        # Sort by name ascending & descending (case-insensitive)
        self.assertEqual(
            [e["entity"]["name"] for e in sort_watchlist_entities(entries, sort_by="name")],
            ["198.51.100.5", "alpha-hash", "irisbank.com", "zeta.com"],
        )
        self.assertEqual(
            [e["entity"]["name"] for e in sort_watchlist_entities(entries, sort_by="name", descending=True)],
            ["zeta.com", "irisbank.com", "alpha-hash", "198.51.100.5"],
        )

        # Sort by annotation places empty/None annotations last in both directions, tie-broken ascending
        ann_asc = [e["entity"]["name"] for e in sort_watchlist_entities(entries, sort_by="annotation")]
        self.assertEqual(ann_asc, ["alpha-hash", "zeta.com", "198.51.100.5", "irisbank.com"])
        ann_desc = [
            e["entity"]["name"]
            for e in sort_watchlist_entities(entries, sort_by="annotation", descending=True)
        ]
        self.assertEqual(ann_desc, ["zeta.com", "alpha-hash", "198.51.100.5", "irisbank.com"])

        # Aliases and remaining fields (id, type, status)
        self.assertEqual(
            [e["entity"]["id"] for e in sort_watchlist_entities(entries, sort_by="entity_id")],
            ["hash:1111", "idn:irisbank.com", "idn:zeta.com", "ip:198.51.100.5"],
        )
        self.assertEqual(
            [e["entity"]["name"] for e in sort_watchlist_entities(entries, sort_by="entity_type")],
            ["alpha-hash", "irisbank.com", "zeta.com", "198.51.100.5"],
        )
        self.assertEqual(
            [e["entity"]["name"] for e in sort_watchlist_entities(entries, sort_by="status")],
            ["irisbank.com", "198.51.100.5", "alpha-hash", "zeta.com"],
        )

        with self.assertRaises(ValueError):
            sort_watchlist_entities(entries, sort_by="unknown_field")

        # Multi-token case-insensitive filtering across entity and context fields
        self.assertEqual(len(filter_watchlist_entities(entries, "")), 4)
        self.assertEqual(
            [e["entity"]["name"] for e in filter_watchlist_entities(entries, "IRISBANK")],
            ["irisbank.com"],
        )
        self.assertEqual(
            [e["entity"]["name"] for e in filter_watchlist_entities(entries, "hash alpha.example")],
            ["alpha-hash"],
        )

        # Watchlist list sorting
        lists = [
            {"id": "report:3", "type": "ip", "name": "Gamma IPs"},
            {"id": "report:1", "type": "brand", "name": "Alpha Brands"},
            {"id": "report:2", "type": "domain", "name": "Beta Domains"},
        ]
        self.assertEqual(
            [w["name"] for w in sort_watchlists(lists, sort_by="name")],
            ["Alpha Brands", "Beta Domains", "Gamma IPs"],
        )
        self.assertEqual(
            [w["id"] for w in sort_watchlists(lists, sort_by="id", descending=True)],
            ["report:3", "report:2", "report:1"],
        )
        self.assertEqual(
            [w["type"] for w in sort_watchlists(lists, sort_by="type")],
            ["brand", "domain", "ip"],
        )
        self.assertEqual(
            [w["id"] for w in sort_watchlists(lists, sort_by="none")],
            ["report:3", "report:1", "report:2"],
        )


if __name__ == "__main__":
    unittest.main()
