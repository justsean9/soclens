"""Multi-source brand logo extraction, non-logo exclusion, and pure-Python image validation."""

from __future__ import annotations

import base64
import concurrent.futures
import csv
import html as html_lib
import json
import logging
import math
import os
import posixpath
import random
import re
import struct
import threading
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

from soclens.config import (
    ConfiguredSession,
    get_logo_overrides_file,
    get_rf_verify_ssl,
    suppress_insecure_ssl_warnings,
)
from soclens.logos.hashing import (
    canonicalize_inline_svg,
    compute_image_hashes,
    load_ignored_hashes,
    match_ignored_hash,
)

logger = logging.getLogger("soclens.logos.extractor")

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

DEFAULT_IGNORED_DOMAINS: frozenset[str] = frozenset({"slack.com", "service-now.com"})

# Promotional and non-brand marketing banner keywords
PROMO_KEYWORDS: dict[str, str] = {
    "slider": "Hero/Slider banner",
    "slideshow": "Slideshow banner",
    "carousel": "Carousel slide",
    "hero": "Hero marketing image",
    "banner": "Promotional/marketing banner",
    "billboard": "Billboard ad",
    "promo": "Promotional campaign graphic",
    "promotion": "Promotional campaign graphic",
    "campaign": "Marketing campaign graphic",
    "ad-banner": "Ad banner",
    "advertisement": "Advertisement graphic",
    "special-offer": "Special promotional offer",
    "specialoffer": "Special promotional offer",
    "checking": "Banking product/promotion graphic",
    "savings": "Banking product/promotion graphic",
    "rate": "Interest rate table/promo graphic",
    "cd-rate": "CD rate promo graphic",
    "loan-special": "Loan promotion graphic",
    "mortgage-rate": "Mortgage rate graphic",
    "food-container": "Promotional giveaway graphic",
    "credit-card-offer": "Credit card promotion",
    "bftc": "Community initiative/giveaway graphic",
    "community-logo": "Community program graphic",
    "giveaway": "Promotional giveaway graphic",
    "donation": "Charity/Donation program graphic",
    "mortgage": "Mortgage product/promotion graphic",
    "heloc": "HELOC promotion graphic",
    "auto-loan": "Auto loan promotion graphic",
    "autoloan": "Auto loan promotion graphic",
    "home-equity": "Home equity loan graphic",
    "homeequity": "Home equity loan graphic",
    "cd-special": "CD special rate graphic",
    "certificate-of-deposit": "CD promo graphic",
    "money-market": "Money market promotion graphic",
    "moneymarket": "Money market promotion graphic",
    "hsa": "Health savings account graphic",
    "ira": "IRA retirement account graphic",
    "refinance": "Loan refinance graphic",
    "checking-account": "Checking account promo graphic",
    "savings-account": "Savings account promo graphic",
    "rewards-checking": "Rewards checking promo graphic",
    "card-control": "Card control app graphic",
    "bill-pay": "Bill pay feature graphic",
    "direct-deposit": "Direct deposit promo graphic",
    "estatements": "eStatements promo graphic",
    "e-statements": "eStatements promo graphic",
    "wire-transfer": "Wire transfer service graphic",
}

# UI / Navigation icon keywords
UI_ICON_KEYWORDS: dict[str, str] = {
    "search-icon": "Search icon",
    "magnifying-glass": "Magnifying glass icon",
    "hamburger-menu": "Hamburger menu icon",
    "menu-icon": "Menu icon",
    "chevron": "Chevron/arrow icon",
    "caret": "Caret icon",
    "arrow-left": "Arrow navigation icon",
    "arrow-right": "Arrow navigation icon",
    "arrow-down": "Arrow navigation icon",
    "arrow-up": "Arrow navigation icon",
    "search": "Search icon",
    "menu": "Menu icon",
    "close-icon": "Close icon",
    "close-button": "Close button",
    "spinner": "Loading spinner",
    "loading": "Loading indicator",
    "spacer": "Spacer graphic",
    "blank.gif": "Blank placeholder graphic",
    "pixel.gif": "Tracking pixel",
    "pause": "Media playback pause icon",
    "play": "Media playback play icon",
    "nav-link-arrow": "Navigation link arrow icon",
    "nav-arrow": "Navigation arrow icon",
    "icon-size-xsmall": "Extra-small UI icon",
}

# Layout-only keywords that may be bypassed ONLY when explicitly part of an image filename
# like 'banner-logo.png'. Banking-product, offer, and UI icon keywords are NEVER bypassed.
_BYPASSABLE_LAYOUT_PROMO_KEYWORDS: frozenset[str] = frozenset({"banner", "hero", "billboard"})

# Keywords that require word-boundary regex matching even if length > 4
_WORD_BOUNDARY_KEYWORDS: frozenset[str] = frozenset(
    {
        "award",
        "awards",
        "rating",
        "ratings",
        "search",
        "menu",
        "banner",
        "hero",
        "slider",
        "winner",
        "discover",
        "threads",
        "spinner",
        "loading",
        "spacer",
        "promo",
        "bcorp",
        "play",
        "pause",
        "clients",
        "kofe",
        "imarc",
    }
)

EXCLUSION_KEYWORDS: dict[str, str] = {
    # Deposit Insurance & Regulatory Disclosures
    "fdic": "FDIC logo/text",
    "member fdic": "FDIC logo/text",
    "memberfdic": "FDIC logo/text",
    "ncua": "NCUA logo/text",
    "ncusif": "NCUA insurance (NCUSIF) logo/text",
    "insured by ncua": "NCUA insurance logo/text",
    "equal housing": "Equal Housing Lender logo/text",
    "equalhousing": "Equal Housing Lender logo/text",
    "equal housing lender": "Equal Housing Lender logo/text",
    "equal housing opportunity": "Equal Housing Opportunity logo/text",
    "housing lender": "Equal Housing Lender logo/text",
    "housinglender": "Equal Housing Lender logo/text",
    "ehl": "Equal Housing Lender logo/text",
    "eho": "Equal Housing Opportunity logo/text",
    "nmls": "NMLS logo/text",
    "nmls consumer access": "NMLS Consumer Access badge",
    "nmlsconsumeraccess": "NMLS Consumer Access badge",
    "consumer access": "NMLS Consumer Access badge",
    "dif": "Depositors Insurance Fund (DIF) logo/text",
    "member dif": "Depositors Insurance Fund (DIF) logo/text",
    "depositors insurance fund": "Depositors Insurance Fund (DIF) logo/text",
    "msic": "Massachusetts Credit Union Share Insurance (MSIC) logo/text",
    "share insurance": "Share insurance disclosure",
    "asi": "American Share Insurance (ASI) logo/text",
    "american share insurance": "American Share Insurance (ASI) logo/text",
    "esi": "Excess Share Insurance (ESI) logo/text",
    "excess share insurance": "Excess Share Insurance (ESI) logo/text",
    "sipc": "SIPC logo/text",
    "sba": "Small Business Administration (SBA) badge",
    "sba preferred lender": "Small Business Administration (SBA) badge",
    "cfpb": "Consumer Financial Protection Bureau (CFPB) badge",
    "fincen": "FinCEN compliance badge",
    "usa patriot act": "USA PATRIOT Act notice/badge",
    "patriot act": "USA PATRIOT Act notice/badge",
    "federal reserve": "Federal Reserve Member badge",
    "member federal reserve": "Federal Reserve Member badge",
    # ATM & Interbank Networks
    "allpoint": "ATM network: Allpoint",
    "moneypass": "ATM network: MoneyPass",
    "money pass": "ATM network: MoneyPass",
    "co-op shared branch": "CO-OP Shared Branch logo/text",
    "coop shared branch": "CO-OP Shared Branch logo/text",
    "co-op branch": "CO-OP Shared Branch logo/text",
    "coop branch": "CO-OP Shared Branch logo/text",
    "co-op atm": "ATM network: CO-OP ATM",
    "coop atm": "ATM network: CO-OP ATM",
    "co-op network": "ATM network: CO-OP Network",
    "coop network": "ATM network: CO-OP Network",
    "nyce": "ATM/Debit network: NYCE",
    "star network": "ATM/Debit network: STAR",
    "pulse network": "ATM/Debit network: PULSE",
    "cirrus": "ATM network: Cirrus",
    "plus network": "ATM network: Plus",
    "sum atm": "ATM network: SUM",
    "sum network": "ATM network: SUM",
    "accel network": "Payment/ATM network: Accel",
    "accel debit": "Payment/ATM network: Accel",
    "accel payment": "Payment/ATM network: Accel",
    "affn": "Armed Forces Financial Network (AFFN)",
    # Core Banking & Digital Banking Platforms
    "jack henry": "Core banking platform: Jack Henry",
    "jackhenry": "Core banking platform: Jack Henry",
    "banno": "Digital banking platform: Banno (Jack Henry)",
    "symitar": "Credit union platform: Symitar (Jack Henry)",
    "profitstars": "Fintech platform: ProfitStars (Jack Henry)",
    "fiserv": "Core banking platform: Fiserv",
    "fidelity national information": "Core banking platform: FIS",
    "q2": "Digital banking platform: Q2",
    "alkami": "Digital banking platform: Alkami",
    "narmi": "Digital banking platform: Narmi",
    "apiture": "Digital banking platform: Apiture",
    "finastra": "Core banking platform: Finastra",
    "meridianlink": "Lending platform: MeridianLink",
    "blend mortgage": "Lending platform: Blend",
    "blend lending": "Lending platform: Blend",
    "blend loan": "Lending platform: Blend",
    "blend.com": "Lending platform: Blend",
    "blend-logo": "Lending platform: Blend",
    "plaid": "Fintech/aggregation platform: Plaid",
    "mx technologies": "Fintech platform: MX",
    "kasasa": "Rewards checking program: Kasasa",
    "savvymoney": "Credit score tool: SavvyMoney",
    "savvy money": "Credit score tool: SavvyMoney",
    # Check Printers, Marketing & Security Vendors
    "deluxe": "Check printer/partner: Deluxe",
    "harland clarke": "Check printer/marketing: Harland Clarke",
    "harlandclarke": "Check printer/marketing: Harland Clarke",
    "vericast": "Marketing/banking partner: Vericast",
    "trustwave": "Security seal: Trustwave",
    "securitymetrics": "Security/PCI seal: SecurityMetrics",
    "security metrics": "Security/PCI seal: SecurityMetrics",
    "authorizenet": "Payment gateway: Authorize.Net",
    "authorize.net": "Payment gateway: Authorize.Net",
    "fico": "Credit score badge: FICO",
    "vantagescore": "Credit score badge: VantageScore",
    "vantage score": "Credit score badge: VantageScore",
    # Accessibility Widgets
    "audioeye": "Accessibility widget: AudioEye",
    "userway": "Accessibility widget: UserWay",
    "accessibe": "Accessibility widget: accessiBe",
    "level access": "Accessibility widget: Level Access",
    "levelaccess": "Accessibility widget: Level Access",
    "essential accessibility": "Accessibility widget: Essential Accessibility",
    "monsido": "Accessibility widget: Monsido",
    "equalweb": "Accessibility widget: EqualWeb",
    # Industry Awards, Ratings, Certifications & Publications
    "forbes": "Award/Publication badge: Forbes",
    "newsweek": "Award/Publication badge: Newsweek",
    "bankrate": "Award/Rating badge: Bankrate",
    "nerdwallet": "Award/Rating badge: NerdWallet",
    "five star": "Award badge: Five Star Professional",
    "fivestar": "Award badge: Five Star Professional",
    "best bank": "Award badge: Best Bank",
    "best credit union": "Award badge: Best Credit Union",
    "banking choice": "Award badge: Banking Choice",
    "bauer financial": "Trust/Rating badge: Bauer Financial",
    "bauerfinancial": "Trust/Rating badge: Bauer Financial",
    "bestof": "Award badge",
    "best of": "Award badge",
    "winner": "Award/Winner badge",
    "award": "Award/Winner badge",
    "rating": "Trust/Rating badge",
    "gptw": "Workplace certification badge: Great Place to Work",
    "great place to work": "Workplace certification badge: Great Place to Work",
    "greatplacetowork": "Workplace certification badge: Great Place to Work",
    "top workplace": "Workplace award badge: Top Workplaces",
    "top workplaces": "Workplace award badge: Top Workplaces",
    "topworkplaces": "Workplace award badge: Top Workplaces",
    "topworkplace": "Workplace award badge: Top Workplaces",
    "twp": "Workplace award badge: Top Workplaces",
    "top ceo": "Award badge: Top CEO",
    "topceo": "Award badge: Top CEO",
    "best place to work": "Workplace award badge: Best Place to Work",
    "best places to work": "Workplace award badge: Best Place to Work",
    "bestplacestowork": "Workplace award badge: Best Place to Work",
    "best company to work": "Workplace award badge: Best Company to Work",
    "best companies to work": "Workplace award badge: Best Companies to Work",
    "american banker": "Industry award badge: American Banker",
    "americanbanker": "Industry award badge: American Banker",
    "readers choice": "Award badge: Readers Choice",
    "readerschoice": "Award badge: Readers Choice",
    "super bank": "Award badge: Super Bank",
    "superbank": "Award badge: Super Bank",
    "igel": "Award badge: IGEL Award",
    "certified workplace": "Workplace certification badge",
    "certification": "Certification badge",
    "accredited": "Accreditation badge",
    "accreditation": "Accreditation badge",
    "honoree": "Award/Honoree badge",
    "b-corp": "Certification badge: B Corp",
    "b corp": "Certification badge: B Corp",
    "bcorp": "Certification badge: B Corp",
    # Social Media Networks
    "facebook": "Social media: Facebook",
    "fb logo": "Social media: Facebook",
    "fb-logo": "Social media: Facebook",
    "twitter": "Social media: Twitter",
    "x logo": "Social media: Twitter/X",
    "x-logo": "Social media: Twitter/X",
    "linkedin": "Social media: LinkedIn",
    "instagram": "Social media: Instagram",
    "youtube": "Social media: YouTube",
    "pinterest": "Social media: Pinterest",
    "tiktok": "Social media: TikTok",
    "snapchat": "Social media: Snapchat",
    "vimeo": "Social media: Vimeo",
    "whatsapp": "Social media: WhatsApp",
    "telegram": "Social media: Telegram",
    "wechat": "Social media: WeChat",
    "github": "Social media: GitHub",
    "reddit": "Social media: Reddit",
    "threads": "Social media: Threads",
    "bluesky": "Social media: Bluesky",
    # Mobile App Stores
    "app store": "App store badge",
    "appstore": "App store badge",
    "play store": "App store badge",
    "playstore": "App store badge",
    "google play": "App store badge",
    "googleplay": "App store badge",
    "apple store": "App store badge",
    # Security, Verification & Compliance
    "norton": "Trust/Security badge: Norton",
    "mcafee": "Trust/Security badge: McAfee",
    "trustpilot": "Trust/Security badge: Trustpilot",
    "truste": "Trust/Security badge: TRUSTe",
    "verisign": "Trust/Security badge: VeriSign",
    "digicert": "Trust/Security badge: DigiCert",
    "entrust": "Trust/Security badge: Entrust",
    "geotrust": "Trust/Security badge: GeoTrust",
    "rapidssl": "Trust/Security badge: RapidSSL",
    "sectigo": "Trust/Security badge: Sectigo",
    "comodo": "Trust/Security badge: Comodo",
    "bbb": "Trust/Security badge: Better Business Bureau",
    "recaptcha": "Security badge: Google reCAPTCHA",
    "turnstile": "Security badge: Cloudflare Turnstile",
    "hcaptcha": "Security badge: hCaptcha",
    "cookiebot": "Cookie/Privacy banner: Cookiebot",
    "onetrust": "Cookie/Privacy banner: OneTrust",
    "optanon": "Cookie/Privacy banner: OneTrust/Optanon",
    "usercentrics": "Cookie/Privacy banner: Usercentrics",
    "intercom": "Chat widget: Intercom",
    "zendesk": "Chat widget: Zendesk",
    "soc2": "Compliance badge: SOC 2",
    "soc 2": "Compliance badge: SOC 2",
    "soc-2": "Compliance badge: SOC 2",
    "aicpa": "Compliance badge: AICPA SOC",
    "pci dss": "Compliance badge: PCI DSS",
    "pcidss": "Compliance badge: PCI DSS",
    "pci-dss": "Compliance badge: PCI DSS",
    "iso 27001": "Compliance badge: ISO 27001",
    "iso27001": "Compliance badge: ISO 27001",
    "hipaa": "Compliance badge: HIPAA",
    "fedramp": "Compliance badge: FedRAMP",
    # Payment Methods & Networks
    "visa": "Payment network: Visa",
    "mastercard": "Payment network: Mastercard",
    "master-card": "Payment network: Mastercard",
    "master card": "Payment network: Mastercard",
    "amex": "Payment network: American Express",
    "american express": "Payment network: American Express",
    "americanexpress": "Payment network: American Express",
    "discover": "Payment network: Discover",
    "discover card": "Payment network: Discover",
    "apple pay": "Payment method: Apple Pay",
    "applepay": "Payment method: Apple Pay",
    "google pay": "Payment method: Google Pay",
    "googlepay": "Payment method: Google Pay",
    "zelle": "Payment method: Zelle",
    "paypal": "Payment method: PayPal",
    "venmo": "Payment method: Venmo",
    # Third-Party Partners, Agencies, Client Showcases & Blog Tiles
    "kofe": "Financial education partner: KOFE",
    "imarc": "Web agency badge: Imarc",
    "svgrepo": "Third-party UI icon pack: SVG Repo",
    "client-logo": "Client/customer showcase logo",
    "client_icon": "Client/customer showcase icon",
    "client-icon": "Client/customer showcase icon",
    "wp-post-image": "Blog/post featured image",
    "featuredimg": "Blog/post featured image",
    "featured-image": "Blog/post featured image",
    "post-thumbnail": "Blog/post thumbnail",
}

THIRD_PARTY_BADGE_HOSTS: frozenset[str] = frozenset(
    {
        "facebook.com",
        "fbcdn.net",
        "twitter.com",
        "twimg.com",
        "x.com",
        "linkedin.com",
        "licdn.com",
        "instagram.com",
        "cdninstagram.com",
        "youtube.com",
        "ytimg.com",
        "pinterest.com",
        "tiktok.com",
        "vimeo.com",
        "reddit.com",
        "fdic.gov",
        "ncua.gov",
        "bbb.org",
        "trustpilot.com",
        "truste.com",
        "digicert.com",
        "sectigo.com",
        "norton.com",
        "mcafee.com",
        "userway.org",
        "audioeye.com",
        "accessibe.com",
        "cookiebot.com",
        "onetrust.com",
        "cookielaw.org",
        "paypalobjects.com",
        "greatplacetowork.com",
        "bauerfinancial.com",
    }
)

_RETRY_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
_SVG_PRIMITIVES: frozenset[str] = frozenset(
    {"path", "rect", "circle", "ellipse", "polygon", "polyline", "line", "text", "use", "image"}
)
_REJECTED_CONTENT_TYPES: tuple[str, ...] = (
    "text/html",
    "application/xhtml+xml",
    "application/json",
    "application/javascript",
    "text/javascript",
    "application/pdf",
    "text/css",
)
_DOMAIN_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "domain",
        "domains",
        "hostname",
        "host",
        "site",
        "url",
        "entity",
        "entity name",
        "entity_name",
        "name",
    }
)
_FOOTER_NOISE_KWS: tuple[str, ...] = (
    "footer",
    "aside",
    "sidebar",
    "social",
    "badge",
    "sponsor",
    "partner",
    "award",
    "rating",
    "winner",
    "modal",
    "dialog",
    "alert",
    "popup",
    "overlay",
    "lightbox",
    "flyout",
    "drawer",
    "notice",
    "meganav",
    "mega-navigation",
    "megamenu",
    "carousel",
    "slider",
    "hero-banner",
    "clients",
    "client-logo",
    "client-logos",
    "customer-logo",
    "customers",
    "testimonial",
    "testimonials",
    "marquee",
    "post-tile",
    "post_tile",
    "blog-post",
    "news-item",
    "article-card",
    "brand-active",
    "single-brand",
    "autoplay",
    "controls",
    "nav-link-arrow",
    "nav-arrow",
)


@dataclass
class ExtractorConfig:
    """Configuration for multi-source logo discovery, HTTP fetching, and validation."""

    verify_ssl: bool | str = field(default_factory=get_rf_verify_ssl)
    timeout: float = 10.0
    max_retries: int = 2
    backoff_base: float = 0.5
    max_image_bytes: int = 10 * 1024 * 1024  # 10 MB
    max_manifest_bytes: int = 1 * 1024 * 1024  # 1 MB
    max_workers: int = 8
    min_dimension: int = 16
    max_aspect_ratio: float = 6.0
    svg_max_aspect_ratio: float = 10.0
    horizontal_logo_max_aspect_ratio: float = 10.5
    og_max_aspect_ratio: float = 3.5
    user_agent: str = DEFAULT_USER_AGENT
    ignored_domains: frozenset[str] = DEFAULT_IGNORED_DOMAINS
    force_urls: dict[str, list[str]] = field(default_factory=dict)
    allow_urls: set[str] = field(default_factory=set)
    allow_domains: set[str] = field(default_factory=set)

    @classmethod
    def from_overrides(
        cls,
        overrides: Mapping[str, Any] | None = None,
        *,
        insecure: bool = False,
        **kwargs: Any,
    ) -> ExtractorConfig:
        """Build an ``ExtractorConfig`` merging optional JSON overrides and explicit kwargs."""
        cfg = cls(**kwargs)
        if insecure:
            cfg.verify_ssl = False
        if overrides:
            extra_ignored = {
                str(d).strip().lower()
                for d in overrides.get("ignored_domains", [])
                if str(d).strip()
            }
            if extra_ignored:
                cfg.ignored_domains = cfg.ignored_domains | extra_ignored

            raw_force = overrides.get("force_urls", {})
            if isinstance(raw_force, Mapping):
                for dom, urls in raw_force.items():
                    clean_dom = str(dom).strip().lower()
                    if isinstance(urls, str):
                        cfg.force_urls[clean_dom] = [urls]
                    elif isinstance(urls, Iterable):
                        cfg.force_urls[clean_dom] = [str(u) for u in urls if str(u).strip()]

            raw_allow = overrides.get("allow_urls", [])
            if isinstance(raw_allow, Iterable) and not isinstance(raw_allow, (str, bytes)):
                cfg.allow_urls.update(str(u).strip().lower() for u in raw_allow if str(u).strip())

            raw_allow_doms = overrides.get("allow_domains", [])
            if isinstance(raw_allow_doms, Iterable) and not isinstance(raw_allow_doms, (str, bytes)):
                cfg.allow_domains.update(
                    str(d).strip().lower() for d in raw_allow_doms if str(d).strip()
                )
        return cfg


@dataclass(frozen=True)
class ImageInfo:
    """Metadata sniffed from pure-Python magic-byte and dimension headers."""

    format: str
    mime_type: str
    width: int | None = None
    height: int | None = None


@dataclass
class ExtractedLogo:
    """A validated brand logo asset extracted from a domain."""

    domain: str
    image_url: str
    source: str
    md5: str
    sha1: str
    sha256: str
    image_info: ImageInfo | None = None
    byte_length: int = 0

    def to_legacy_dict(self) -> dict[str, str]:
        """Convert to the legacy 4-key dictionary expected by ``get_domain_image_hash``."""
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "image_url": self.image_url,
        }


@dataclass
class DomainExtractionResult:
    """Full structured result for a single domain logo extraction run."""

    domain: str
    logos: list[ExtractedLogo] = field(default_factory=list)
    to_query_count: int = 0
    domain_error: str | None = None
    image_errors: list[str] = field(default_factory=list)
    discovered_locations: list[dict[str, Any]] = field(default_factory=list)
    final_url: str | None = None

    def to_legacy_tuple(
        self,
    ) -> tuple[list[dict[str, str]], int, str | None, list[str], list[dict[str, Any]]]:
        """Return the legacy 5-tuple expected by ``get_domain_image_hash`` callers."""
        return (
            [logo.to_legacy_dict() for logo in self.logos],
            self.to_query_count,
            self.domain_error,
            self.image_errors,
            self.discovered_locations,
        )


def load_domain_overrides(file_path: str | Path | None = None) -> dict[str, Any]:
    """Load optional domain/URL override rules from JSON or configured setting."""
    raw_path = str(file_path).strip() if file_path is not None else ""
    if not raw_path:
        raw_path = get_logo_overrides_file() or ""
    if not raw_path:
        return {}

    path = Path(raw_path).expanduser()
    if not path.is_file():
        return {}

    try:
        with path.open("r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.warning("Failed to load domain overrides from '%s': %s", path, exc)
        return {}


_TAILWIND_BRAND_UTILITY_RE = re.compile(
    r"\b(?:[a-z0-9-]+:)*(?:text|bg|border|fill|stroke|ring|from|to|via|outline|decoration|accent|divide|placeholder)-brand(?:-[a-z0-9-]+)?\b",
    re.IGNORECASE,
)
_ALT_LOGO_WORD_RE = re.compile(r"\b(?:logo|brand|logotype|wordmark)\b", re.IGNORECASE)
_WP_VARIANT_RE = re.compile(r"^(.*?)-(\d+)x(\d+)(\.[a-z0-9]+)$", re.IGNORECASE)
_WF_VARIANT_RE = re.compile(r"^(.*?)-p-(\d+)(\.[a-z0-9]+)$", re.IGNORECASE)
_WEBFLOW_ICON_PREFIX_RE = re.compile(r"^(?:[0-9a-f]{24}_)+", re.IGNORECASE)
_SAVINGS_INSTITUTION_RE = re.compile(
    r"\b(?:savings\s+(?:bank|loan|assoc(?:iation)?|institution|trust|society)|for\s+savings)\b",
    re.IGNORECASE,
)
_COMBINED_LOGO_EHL_RE = re.compile(r"\blogo\s+(?:w|with)\s+ehl\b", re.IGNORECASE)
_STYLE_SELECTOR_LOGO_RE = re.compile(
    r"[#.][a-z0-9_-]*(?:logo|brand|wordmark)[a-z0-9_-]*",
    re.IGNORECASE,
)
_STYLE_SELECTOR_NOISE_RE = re.compile(
    r"(?<![a-z0-9])(?:footer|aside|sidebar|modal|carousel|slider|fdic|ncua|social|partner|client|sponsor|badge|award|arrow)(?![a-z0-9])",
    re.IGNORECASE,
)
_STYLE_BG_URL_RE = re.compile(
    r"background(?:-image)?\s*:[^;{}]*?url\(\s*(['\"]?)([^)'\"]+)\1\s*\)",
    re.IGNORECASE,
)
_MAX_ICON_FALLBACKS = 2


def _normalize_icon_stem(filename: str) -> str:
    """Normalize Webflow 24-hex upload prefixes and dimension suffixes for icon dedup."""
    cleaned = _WEBFLOW_ICON_PREFIX_RE.sub("", filename.lower())
    return re.sub(r"[-_](\d+x\d+|\d+)(\.[a-z0-9]+)$", r"\2", cleaned)


def _has_visible_img_tags(soup: BeautifulSoup) -> bool:
    """Return True if the DOM contains at least one non-tracking-pixel ``<img>`` tag."""
    for img in soup.find_all("img"):
        src_lower = str(img.get("src", "") or "").strip().lower()
        if any(tok in src_lower for tok in ("bping.php", "pixel.gif", "/1x1.", "1x1.gif")):
            continue
        style_lower = str(img.get("style", "") or "").lower().replace(" ", "")
        if "display:none" in style_lower or "visibility:hidden" in style_lower:
            continue
        dim_hidden = False
        for attr in ("width", "height"):
            raw_dim = str(img.get(attr, "") or "").strip().lower().removesuffix("px")
            if raw_dim.isdigit() and int(raw_dim) <= 1:
                dim_hidden = True
                break
        if dim_hidden:
            continue
        return True
    return False


def _has_real_icon_or_manifest_links(soup: BeautifulSoup) -> bool:
    """Return True if a ``<link rel='icon|manifest'>`` points to a non-stub asset."""
    for link in soup.find_all("link", rel=re.compile(r"icon|manifest", re.I)):
        href = str(link.get("href", "") or "").strip()
        if not href or href == "#":
            continue
        if href.lower().startswith("data:") and len(href) < 64:
            continue
        return True
    return False


def _css_url_resolution_score(abs_url: str) -> tuple[int, int]:
    if abs_url.lower().startswith("data:"):
        return (1, 0)
    parsed = urllib.parse.urlparse(abs_url)
    qs = urllib.parse.parse_qs(parsed.query)
    best_w = 0
    for qk in ("width", "w", "height", "h"):
        if qk in qs and qs[qk]:
            try:
                best_w = max(best_w, int(qs[qk][0]))
            except ValueError:
                pass
    if best_w > 0:
        return (0, best_w)
    return (1, 0)


def _extract_inline_style_logo_urls(
    soup: BeautifulSoup,
    effective_base: str,
) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    """Discover ``#logo`` / ``.logo`` / ``.brand`` CSS background-image URLs in ``<style>`` tags."""
    raw_candidates: list[tuple[str, str]] = []
    seen_urls: set[str] = set()

    for style_tag in soup.find_all("style"):
        css_text = style_tag.string or style_tag.get_text() or ""
        if not css_text.strip():
            continue
        css_clean = re.sub(r"/\*.*?\*/", " ", css_text, flags=re.S)
        for match in re.finditer(r"([^{};@]+)\{([^{}]+)\}", css_clean):
            selector = " ".join(match.group(1).split())
            body = match.group(2)
            sel_lower = selector.lower()
            if not _STYLE_SELECTOR_LOGO_RE.search(sel_lower):
                continue
            if _STYLE_SELECTOR_NOISE_RE.search(sel_lower):
                continue
            for bg_match in _STYLE_BG_URL_RE.finditer(body):
                raw_url = html_lib.unescape(bg_match.group(2)).strip()
                if not raw_url or raw_url.lower().startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                abs_url = (
                    raw_url
                    if raw_url.lower().startswith("data:")
                    else urllib.parse.urljoin(effective_base, raw_url)
                )
                if abs_url not in seen_urls:
                    seen_urls.add(abs_url)
                    raw_candidates.append((raw_url, abs_url))

    if not raw_candidates:
        return [], []

    groups: dict[tuple[str, str, str], list[int]] = {}
    scored_entries: list[tuple[str, str, tuple[int, int]]] = []
    for raw_url, abs_url in raw_candidates:
        idx = len(scored_entries)
        scored_entries.append((raw_url, abs_url, _css_url_resolution_score(abs_url)))
        if abs_url.lower().startswith("data:"):
            continue
        parsed = urllib.parse.urlparse(abs_url)
        key = (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.lower())
        groups.setdefault(key, []).append(idx)

    winners: dict[tuple[str, str, str], int] = {}
    for key, indices in groups.items():
        if len(indices) > 1:
            winners[key] = max(indices, key=lambda i: scored_entries[i][2])

    kept: list[tuple[str, str]] = []
    excluded: list[tuple[str, str, str]] = []
    for idx, (raw_url, abs_url, _score) in enumerate(scored_entries):
        if not abs_url.lower().startswith("data:"):
            parsed = urllib.parse.urlparse(abs_url)
            key = (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.lower())
            if key in winners and winners[key] != idx:
                best_url = scored_entries[winners[key]][1]
                excluded.append(
                    (
                        abs_url,
                        "inline <style> CSS logo",
                        f"Excluded: lower-resolution CSS background variant (preferred '{best_url}')",
                    )
                )
                continue
        kept.append((raw_url, "inline <style> CSS logo"))
    return kept, excluded


def _strip_tailwind_brand_utilities(text: str) -> str:
    """Strip Tailwind utility tokens like ``text-brand-dark-gray`` before brand matching."""
    if not text:
        return ""
    return " ".join(_TAILWIND_BRAND_UTILITY_RE.sub(" ", text).split())


def _responsive_stem_and_score(
    abs_url: str,
) -> tuple[tuple[str, str, str, str] | None, tuple[int, int, int]]:
    if abs_url.lower().startswith("data:"):
        return None, (1, 0, 0)
    parsed = urllib.parse.urlparse(abs_url)
    path = parsed.path
    m_wp = _WP_VARIANT_RE.match(path)
    if m_wp:
        prefix, w_s, h_s, ext = m_wp.groups()
        w, h = int(w_s), int(h_s)
        stem = (parsed.scheme.lower(), parsed.netloc.lower(), f"{prefix}{ext}".lower(), parsed.query)
        return stem, (0, w * h, w)
    m_wf = _WF_VARIANT_RE.match(path)
    if m_wf:
        prefix, w_s, ext = m_wf.groups()
        w = int(w_s)
        stem = (parsed.scheme.lower(), parsed.netloc.lower(), f"{prefix}{ext}".lower(), parsed.query)
        return stem, (0, w, w)
    stem = (parsed.scheme.lower(), parsed.netloc.lower(), path.lower(), parsed.query)
    return stem, (1, 0, 0)


def _dedup_img_responsive_urls(
    candidates: list[tuple[str, str]],
    base_url: str,
) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    """Keep unscaled original or highest-res responsive ``-WxH`` / ``-p-W`` variant per stem."""
    deduped_inputs: list[tuple[str, str, str, tuple[str, str, str, str] | None, tuple[int, int, int]]] = []
    seen_raw: set[str] = set()
    groups: dict[tuple[str, str, str, str], list[int]] = {}

    for raw_url, desc in candidates:
        if raw_url in seen_raw:
            continue
        seen_raw.add(raw_url)
        abs_url = raw_url if raw_url.lower().startswith("data:") else urllib.parse.urljoin(base_url, raw_url)
        stem, score = _responsive_stem_and_score(abs_url)
        idx = len(deduped_inputs)
        deduped_inputs.append((raw_url, desc, abs_url, stem, score))
        if stem is not None:
            groups.setdefault(stem, []).append(idx)

    winners: dict[tuple[str, str, str, str], int] = {}
    for stem, indices in groups.items():
        if len(indices) > 1:
            winners[stem] = max(indices, key=lambda i: deduped_inputs[i][4])

    kept: list[tuple[str, str]] = []
    excluded: list[tuple[str, str, str]] = []
    for idx, (raw_url, desc, abs_url, stem, _score) in enumerate(deduped_inputs):
        if stem is not None and stem in winners and winners[stem] != idx:
            best_url = deduped_inputs[winners[stem]][2]
            excluded.append(
                (
                    abs_url,
                    desc,
                    f"Excluded: lower-resolution responsive srcset variant (preferred '{best_url}')",
                )
            )
            continue
        kept.append((raw_url, desc))
    return kept, excluded


def normalize_text(text: str) -> str:
    """Remove non-alphanumeric characters, replacing with spaces, and lowercase."""
    return re.sub(r"[^a-z0-9]", " ", text.lower()).strip()


def _normalize_tokens(text: str) -> str:
    """Split CamelCase boundaries before normalizing to lowercase alphanumeric tokens."""
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    camel_split = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", camel_split)
    return normalize_text(camel_split)


def _kw_matches(
    kw: str,
    norm_text: str,
    token_text: str,
    *,
    force_boundary: bool = False,
) -> bool:
    if not kw or (not norm_text and not token_text):
        return False
    norm_kw = normalize_text(kw)
    if not norm_kw:
        return False

    use_boundary = (
        force_boundary
        or len(norm_kw) <= 4
        or " " in norm_kw
        or norm_kw in _WORD_BOUNDARY_KEYWORDS
        or any(
            len(tok) <= 4 or tok in _WORD_BOUNDARY_KEYWORDS
            for tok in norm_kw.split()
        )
    )
    if use_boundary:
        pattern = rf"\b{re.escape(norm_kw)}\b"
        return bool(re.search(pattern, token_text) or re.search(pattern, norm_text))
    return (
        norm_kw in norm_text
        or norm_kw in token_text
        or kw.lower() in norm_text
        or kw.lower() in token_text
    )


def is_noise_match(text: str, kw: str) -> bool:
    """Check if a class or ID matches a noise keyword without being negated."""
    if not text or not kw:
        return False
    text_lower = text.lower()
    kw_lower = kw.lower()
    if kw_lower not in text_lower:
        return False

    escaped_kw = re.escape(kw_lower)
    negation_pattern = (
        rf"\b(no|non|without|not)[-_]{escaped_kw}\b|"
        rf"\b{escaped_kw}[-_](none|off|false|0)\b"
    )
    if re.search(negation_pattern, text_lower):
        cleaned = re.sub(negation_pattern, "", text_lower)
        if kw_lower not in cleaned:
            return False

    tokens = re.split(r"[^a-z0-9]+", text_lower)
    if kw_lower in tokens:
        return True

    compound_pattern = rf"\b[a-z0-9]*[-_]?{escaped_kw}[-_]?[a-z0-9]*\b"
    for match in re.finditer(compound_pattern, text_lower):
        word = match.group(0)
        if not re.search(negation_pattern, word):
            return True

    return False


def is_ignored_domain(
    domain: str,
    ignored_domains: Iterable[str] | None = None,
) -> bool:
    """Check if a domain matches ignored domains (default: slack.com, service-now.com)."""
    if not domain:
        return False
    dom_lower = domain.lower().strip().rstrip(".")
    candidates = ignored_domains if ignored_domains is not None else DEFAULT_IGNORED_DOMAINS
    for ignored in candidates:
        ig = str(ignored).lower().strip().rstrip(".")
        if ig and (dom_lower == ig or dom_lower.endswith(f".{ig}")):
            return True
    return False


def _host_matches(host: str, candidate: str) -> bool:
    h = host.lower().strip().rstrip(".")
    c = candidate.lower().strip().rstrip(".")
    if not h or not c:
        return False
    return h == c or h.endswith(f".{c}")


def is_excluded_image(
    url: str,
    target_domain: str,
    alt: str = "",
    cls: str = "",
    id_val: str = "",
    parent_tags: list[str] | None = None,
    parent_classes: list[str] | None = None,
    parent_ids: list[str] | None = None,
    *,
    config: ExtractorConfig | None = None,
    final_host: str | None = None,
    source: str = "",
) -> tuple[bool, str | None]:
    """Determine if a discovered image should be excluded as non-brand/noise."""
    url_lower = url.lower()
    if config is not None and url_lower in config.allow_urls:
        return False, None

    alt_lower = alt.lower()
    cls_lower = cls.lower()
    id_lower = id_val.lower()
    target_lower = target_domain.lower().strip()
    target_root = target_lower.removeprefix("www.")
    final_root = (final_host or "").lower().strip().removeprefix("www.")

    p_tags = [t.lower() for t in (parent_tags or [])]
    p_classes = [c.lower() for c in (parent_classes or [])]
    p_ids = [i.lower() for i in (parent_ids or [])]

    norm_url = normalize_text(url_lower)
    norm_alt = normalize_text(alt_lower)
    norm_cls = normalize_text(cls_lower)
    norm_id = normalize_text(id_lower)

    tok_alt = _normalize_tokens(alt)
    tok_cls = _normalize_tokens(cls)
    tok_id = _normalize_tokens(id_val)
    tok_p_classes = [(_normalize_tokens(c), normalize_text(c)) for c in (parent_classes or [])]
    tok_p_ids = [(_normalize_tokens(i), normalize_text(i)) for i in (parent_ids or [])]

    # 1. Structural parent tags
    if "footer" in p_tags:
        return True, "Excluded: Image is located inside a <footer> tag"
    if "aside" in p_tags:
        return True, "Excluded: Image is located inside an <aside> tag"
    if "dialog" in p_tags:
        return True, "Excluded: Image is located inside a <dialog> tag"

    # 2. Ancestor class/ID noise checks (note: 'widget' intentionally removed)
    for kw in _FOOTER_NOISE_KWS:
        if kw in target_lower:
            continue
        for p_cls in p_classes:
            if is_noise_match(p_cls, kw):
                return True, f"Excluded: parent class '{p_cls}' matches noise/footer keyword '{kw}'"
        for p_id in p_ids:
            if is_noise_match(p_id, kw):
                return True, f"Excluded: parent ID '{p_id}' matches noise/footer keyword '{kw}'"

    # 3. Parse URL path & host safely (POSIX basename cross-platform)
    is_data_uri = url_lower.startswith("data:")
    if is_data_uri:
        url_host = ""
        url_domain_norm = ""
        raw_path_query = ""
        norm_url_path_query = ""
        tok_url_path_query = ""
        filename = ""
        norm_filename = ""
        tok_filename = ""
    else:
        try:
            parsed_url = urllib.parse.urlparse(url)
            url_host = (parsed_url.hostname or "").lower()
            url_domain_norm = normalize_text(url_host)
            raw_path_query = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")
            norm_url_path_query = normalize_text(raw_path_query)
            tok_url_path_query = _normalize_tokens(raw_path_query)
            filename = posixpath.basename(parsed_url.path)
            norm_filename = normalize_text(filename)
            tok_filename = _normalize_tokens(filename)
        except Exception:
            url_host = ""
            url_domain_norm = ""
            raw_path_query = url
            norm_url_path_query = norm_url
            tok_url_path_query = _normalize_tokens(url)
            filename = ""
            norm_filename = norm_url
            tok_filename = tok_url_path_query

    # 3a. Third-party badge/social/compliance/payment host exclusion
    if url_host:
        is_first_party = _host_matches(url_host, target_root) or (
            bool(final_root) and _host_matches(url_host, final_root)
        )
        is_allowed_host = config is not None and any(
            _host_matches(url_host, d) for d in config.allow_domains
        )
        if not is_first_party and not is_allowed_host:
            for badge_host in THIRD_PARTY_BADGE_HOSTS:
                if _host_matches(url_host, badge_host):
                    return (
                        True,
                        f"Excluded: third-party badge/social/compliance host '{url_host}'",
                    )

    # Explicit logo filename markers help exempt combined primary logos (e.g. logo-w-EHL.png)
    # and narrow layout words ('banner', 'hero', 'billboard') where safe.
    filename_has_logo_marker = any(
        marker in tok_filename.split() or marker in norm_filename.split()
        for marker in ("logo", "brand", "favicon", "logotype", "wordmark")
    )

    # 3b. Exclusion dictionary checks (regulatory, social, awards, payment, vendor badges)
    for kw, description in EXCLUSION_KEYWORDS.items():
        if kw in target_lower or (final_root and kw in final_root):
            continue
        if (
            kw == "ehl"
            and filename_has_logo_marker
            and _COMBINED_LOGO_EHL_RE.search(f"{tok_filename} {tok_alt}")
        ):
            continue

        matched = (
            _kw_matches(kw, norm_alt, tok_alt)
            or _kw_matches(kw, norm_cls, tok_cls)
            or _kw_matches(kw, norm_id, tok_id)
            or _kw_matches(kw, norm_url_path_query, tok_url_path_query)
            or any(_kw_matches(kw, np, tp) for tp, np in tok_p_classes)
            or any(_kw_matches(kw, np, tp) for tp, np in tok_p_ids)
        )
        if matched:
            return True, f"Excluded: matches keyword '{kw}' ({description})"

        if url_host:
            norm_kw_dom = normalize_text(kw)
            if (
                len(norm_kw_dom) <= 4
                or " " in norm_kw_dom
                or norm_kw_dom in _WORD_BOUNDARY_KEYWORDS
                or any(
                    len(tok) <= 4 or tok in _WORD_BOUNDARY_KEYWORDS
                    for tok in norm_kw_dom.split()
                )
            ):
                if _kw_matches(kw, url_domain_norm, url_domain_norm, force_boundary=True):
                    return (
                        True,
                        f"Excluded: matches keyword '{kw}' in external domain '{url_host}' ({description})",
                    )
            elif kw in url_host:
                return (
                    True,
                    f"Excluded: matches keyword '{kw}' in external domain '{url_host}' ({description})",
                )

    # 4. UI Icon keywords are NEVER bypassed by 'logo'/'brand' labels
    for icon_kw, icon_desc in UI_ICON_KEYWORDS.items():
        norm_icon_kw = normalize_text(icon_kw)
        if norm_icon_kw in target_lower or icon_kw in target_lower:
            continue
        if final_root and (norm_icon_kw in final_root or icon_kw in final_root):
            continue
        if (
            _kw_matches(icon_kw, norm_filename, tok_filename)
            or _kw_matches(icon_kw, norm_alt, tok_alt)
            or _kw_matches(icon_kw, norm_cls, tok_cls)
            or _kw_matches(icon_kw, norm_id, tok_id)
            or _kw_matches(icon_kw, norm_url_path_query, tok_url_path_query)
        ):
            return True, f"Excluded: UI icon/navigation element matches '{icon_kw}' ({icon_desc})"

    # 5. Promotional/marketing/product keywords
    # Only narrow layout words ('banner', 'hero', 'billboard') may be bypassed when
    # the filename itself explicitly states 'logo'/'brand'/'favicon' (e.g. 'banner-logo.png').
    # 'savings' is also exempted for institutional Savings Bank names and schema/JSON-LD logos.
    for p_kw, p_desc in PROMO_KEYWORDS.items():
        norm_p_kw = normalize_text(p_kw)
        if norm_p_kw in target_lower or p_kw in target_lower:
            continue
        if final_root and (norm_p_kw in final_root or p_kw in final_root):
            continue
        if p_kw in _BYPASSABLE_LAYOUT_PROMO_KEYWORDS and filename_has_logo_marker:
            continue
        if p_kw == "savings":
            savings_ctx = f"{tok_filename} {tok_alt} {tok_url_path_query}"
            if _SAVINGS_INSTITUTION_RE.search(savings_ctx) or (
                source == "schema.org JSON-LD logo" and filename_has_logo_marker
            ):
                continue
        if (
            _kw_matches(p_kw, norm_filename, tok_filename)
            or _kw_matches(p_kw, norm_alt, tok_alt)
            or _kw_matches(p_kw, norm_cls, tok_cls)
            or _kw_matches(p_kw, norm_id, tok_id)
            or _kw_matches(p_kw, norm_url_path_query, tok_url_path_query)
        ):
            return True, f"Excluded: Promotional/marketing graphic matches '{p_kw}' ({p_desc})"

    # 6. Footer & sidebar keywords in the image itself
    if "footer" not in target_lower:
        if (
            "footer" in norm_url_path_query
            or "footer" in norm_alt
            or "footer" in norm_cls
            or "footer" in norm_id
        ):
            return True, "Excluded: Matches footer keyword in image attributes"
    if "sidebar" not in target_lower and (
        is_noise_match(raw_path_query, "sidebar") or is_noise_match(filename, "sidebar")
    ):
        return True, "Excluded: Matches sidebar keyword in image URL"

    return False, None


def parse_srcset(srcset: str) -> list[str]:
    """Parse an HTML ``srcset`` attribute safely even when URLs contain commas.

    Preserves CDN transformation paths such as
    ``/cdn-cgi/image/w=200,fit=contain/logo.png 1x, /cdn-cgi/image/w=400,fit=contain/logo.png 2x``
    as well as inline ``data:image/...;base64,...`` URIs.
    """
    if not srcset or not srcset.strip():
        return []

    text = srcset.strip()
    entries: list[str] = []
    start = 0
    i = 0
    n = len(text)
    descriptor_tail_re = re.compile(r"\s+\d+(?:\.\d+)?[wx]\s*$")
    next_url_re = re.compile(r"^(?:https?://|//|data:)", re.IGNORECASE)

    while i < n:
        if text[i] == ",":
            before = text[start:i]
            after = text[i + 1 :]
            is_split = False
            if descriptor_tail_re.search(before):
                is_split = True
            elif after and after[0].isspace():
                # Do not split inside a malformed 'data:image/png;base64, ...' header,
                # though standard data URIs never have whitespace right after the header comma.
                if not re.match(r"^\s*data:[^,]*$", before, re.IGNORECASE):
                    is_split = True
            elif next_url_re.match(after):
                is_split = True

            if is_split:
                candidate = before.strip()
                if candidate:
                    entries.append(candidate)
                start = i + 1
        i += 1

    tail = text[start:].strip()
    if tail:
        entries.append(tail)

    urls: list[str] = []
    for entry in entries:
        parts = entry.split()
        if parts:
            urls.append(parts[0])
    return urls


def decode_data_uri(uri: str, max_bytes: int = 10 * 1024 * 1024) -> tuple[bytes, str] | None:
    """Decode an image ``data:`` URI into ``(raw_bytes, mime_type)``, or ``None`` if invalid."""
    if not uri or not uri.strip().lower().startswith("data:"):
        return None
    rest = uri.strip()[5:]
    if "," not in rest:
        return None
    header, payload = rest.split(",", 1)
    header_parts = [p.strip().lower() for p in header.split(";") if p.strip()]
    is_base64 = "base64" in header_parts
    mime_type = ""
    for part in header_parts:
        if "/" in part:
            mime_type = part
            break

    if mime_type and not mime_type.startswith("image/"):
        return None

    try:
        if is_base64:
            cleaned = re.sub(r"\s+", "", payload)
            if not cleaned:
                return b"", mime_type or "application/octet-stream"
            # Pad missing '=' if needed
            pad = (-len(cleaned)) % 4
            if pad:
                cleaned += "=" * pad
            raw = base64.b64decode(cleaned, validate=False)
        else:
            raw = urllib.parse.unquote_to_bytes(payload)
    except Exception:
        return None

    if len(raw) > max_bytes:
        return None
    return raw, mime_type or "application/octet-stream"


def _parse_svg_length(raw: str | None) -> float | None:
    if not raw:
        return None
    val = raw.strip().lower()
    if not val or val.endswith("%"):
        return None
    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*(px|pt|pc|em|rem)?$", val)
    if not m:
        return None
    num = float(m.group(1))
    unit = m.group(2) or "px"
    if unit == "pt":
        num *= 96.0 / 72.0
    elif unit == "pc":
        num *= 16.0
    return num


def _strip_svg_prologue(text: str) -> str:
    """Strip leading whitespace, XML/HTML comments, XML declarations, and DOCTYPEs."""
    pos = 0
    n = len(text)
    while pos < n:
        while pos < n and text[pos].isspace():
            pos += 1
        if text.startswith("<!--", pos):
            end = text.find("-->", pos + 4)
            if end == -1:
                break
            pos = end + 3
        elif text.startswith("<?", pos):
            end = text.find("?>", pos + 2)
            if end == -1:
                break
            pos = end + 2
        elif text[pos : pos + 9].lower() == "<!doctype":
            end = text.find(">", pos + 9)
            if end == -1:
                break
            pos = end + 1
        else:
            break
    return text[pos:]


def _parse_svg_info(data: bytes) -> ImageInfo | None:
    head = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if re.search(rb"<!doctype\s+html\b|<(?:html|head|body)\b", head):
        return None
    if b"<svg" not in head:
        return None

    try:
        text = data.decode("utf-8", errors="replace").lstrip("\ufeff").strip()
    except Exception:
        return None

    stripped_root = _strip_svg_prologue(text)
    if not re.match(r"^<svg\b", stripped_root, flags=re.IGNORECASE):
        return None

    width: int | None = None
    height: int | None = None
    has_primitive = False

    try:
        root = ET.fromstring(text)
        root_tag = root.tag.rsplit("}", 1)[-1].lower()
        if root_tag != "svg":
            return None

        for elem in root.iter():
            local_tag = elem.tag.rsplit("}", 1)[-1].lower()
            if local_tag in _SVG_PRIMITIVES:
                has_primitive = True
                break

        vb = root.attrib.get("viewBox") or root.attrib.get("viewbox")
        if vb:
            nums = re.split(r"[\s,]+", vb.strip())
            if len(nums) == 4:
                try:
                    vb_w = float(nums[2])
                    vb_h = float(nums[3])
                    if vb_w > 0 and vb_h > 0:
                        width = max(1, round(vb_w))
                        height = max(1, round(vb_h))
                except ValueError:
                    pass

        if width is None or height is None:
            w_attr = _parse_svg_length(root.attrib.get("width"))
            h_attr = _parse_svg_length(root.attrib.get("height"))
            if w_attr and h_attr and w_attr > 0 and h_attr > 0:
                width = max(1, round(w_attr))
                height = max(1, round(h_attr))
    except ET.ParseError:
        # Fallback regex inspection for SVGs with undeclared prefixes
        svg_match = re.search(r"<svg\b([^>]*)>", stripped_root, flags=re.IGNORECASE | re.DOTALL)
        if not svg_match:
            return None
        attrs = svg_match.group(1)
        has_primitive = bool(
            re.search(
                r"<(?:[a-z0-9_-]+:)?(?:" + "|".join(sorted(_SVG_PRIMITIVES)) + r")\b",
                stripped_root,
                flags=re.IGNORECASE,
            )
        )
        vb_match = re.search(r'viewBox\s*=\s*["\']([^"\']+)["\']', attrs, flags=re.IGNORECASE)
        if vb_match:
            nums = re.split(r"[\s,]+", vb_match.group(1).strip())
            if len(nums) == 4:
                try:
                    vb_w = float(nums[2])
                    vb_h = float(nums[3])
                    if vb_w > 0 and vb_h > 0:
                        width = max(1, round(vb_w))
                        height = max(1, round(vb_h))
                except ValueError:
                    pass
        if width is None or height is None:
            w_m = re.search(r'\bwidth\s*=\s*["\']([^"\']+)["\']', attrs, flags=re.IGNORECASE)
            h_m = re.search(r'\bheight\s*=\s*["\']([^"\']+)["\']', attrs, flags=re.IGNORECASE)
            w_attr = _parse_svg_length(w_m.group(1)) if w_m else None
            h_attr = _parse_svg_length(h_m.group(1)) if h_m else None
            if w_attr and h_attr and w_attr > 0 and h_attr > 0:
                width = max(1, round(w_attr))
                height = max(1, round(h_attr))

    if not has_primitive:
        return None

    return ImageInfo(format="SVG", mime_type="image/svg+xml", width=width, height=height)


def _parse_jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    pos = 2
    n = len(data)
    sof_markers = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
    while pos < n - 1:
        if data[pos] != 0xFF:
            pos += 1
            continue
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = data[pos]
        pos += 1
        if marker in (0x00, 0x01) or (0xD0 <= marker <= 0xD9):
            continue
        if pos + 2 > n:
            break
        seg_len = struct.unpack(">H", data[pos : pos + 2])[0]
        if seg_len < 2 or pos + seg_len > n:
            break
        if marker in sof_markers and pos + 7 <= n:
            h, w = struct.unpack(">HH", data[pos + 3 : pos + 7])
            return w, h
        pos += seg_len
    return None


def parse_image_info(data: bytes) -> ImageInfo | None:
    """Pure-Python magic-byte and image dimension parser (PNG, JPEG, GIF, WEBP, ICO, BMP, SVG)."""
    if not data:
        return None

    # PNG
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(data) >= 33 and data[12:16] == b"IHDR":
            ihdr_len = struct.unpack(">I", data[8:12])[0]
            if ihdr_len != 13:
                return None
            w, h, bit_depth, color_type, comp, filt, interlace = struct.unpack(
                ">IIBBBBB", data[16:29]
            )
            if (
                w == 0
                or h == 0
                or w > 0x7FFFFFFF
                or h > 0x7FFFFFFF
                or bit_depth not in (1, 2, 4, 8, 16)
                or color_type not in (0, 2, 3, 4, 6)
                or comp != 0
                or filt != 0
                or interlace not in (0, 1)
            ):
                return None
            expected_crc = zlib.crc32(data[12:29]) & 0xFFFFFFFF
            actual_crc = struct.unpack(">I", data[29:33])[0]
            if actual_crc != expected_crc:
                return None
            return ImageInfo(format="PNG", mime_type="image/png", width=w, height=h)
        return None

    # JPEG
    if data.startswith(b"\xff\xd8\xff"):
        dims = _parse_jpeg_dimensions(data)
        if dims is not None:
            return ImageInfo(format="JPEG", mime_type="image/jpeg", width=dims[0], height=dims[1])
        return None

    # GIF
    if data[:6] in (b"GIF87a", b"GIF89a"):
        if len(data) >= 10:
            w, h = struct.unpack("<HH", data[6:10])
            return ImageInfo(format="GIF", mime_type="image/gif", width=w, height=h)
        return None

    # WEBP
    if len(data) >= 25 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        chunk = data[12:16]
        if chunk == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
            raw_w, raw_h = struct.unpack("<HH", data[26:30])
            return ImageInfo(
                format="WEBP",
                mime_type="image/webp",
                width=raw_w & 0x3FFF,
                height=raw_h & 0x3FFF,
            )
        if chunk == b"VP8L" and data[20] == 0x2F:
            bits = struct.unpack("<I", data[21:25])[0]
            w = (bits & 0x3FFF) + 1
            h = ((bits >> 14) & 0x3FFF) + 1
            return ImageInfo(format="WEBP", mime_type="image/webp", width=w, height=h)
        if chunk == b"VP8X" and len(data) >= 30:
            w = int.from_bytes(data[24:27], "little") + 1
            h = int.from_bytes(data[27:30], "little") + 1
            return ImageInfo(format="WEBP", mime_type="image/webp", width=w, height=h)
        if len(data) >= 30 and chunk not in (b"VP8 ", b"VP8L", b"VP8X"):
            return ImageInfo(format="WEBP", mime_type="image/webp", width=None, height=None)
        return None

    # ICO / CUR
    if data[:4] in (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00") and len(data) >= 6:
        count = struct.unpack("<H", data[4:6])[0]
        if count == 0 or 6 + 16 * count > len(data):
            return None
        best_w, best_h = 0, 0
        for idx in range(count):
            offset = 6 + 16 * idx
            entry_w = data[offset] or 256
            entry_h = data[offset + 1] or 256
            if entry_w * entry_h >= best_w * best_h:
                best_w, best_h = entry_w, entry_h
        mime = "image/x-icon" if data[2] == 1 else "image/cur"
        return ImageInfo(format="ICO", mime_type=mime, width=best_w, height=best_h)

    # BMP
    if data[:2] == b"BM" and len(data) >= 26:
        w, raw_h = struct.unpack("<ii", data[18:26])
        return ImageInfo(format="BMP", mime_type="image/bmp", width=w, height=abs(raw_h))

    # SVG
    return _parse_svg_info(data)


def validate_image_bytes(
    data: bytes,
    content_type: str | None = None,
    source: str = "",
    config: ExtractorConfig | None = None,
) -> tuple[bool, ImageInfo | None, str | None]:
    """Validate downloaded/decoded bytes as a legitimate brand logo asset."""
    cfg = config or ExtractorConfig()
    if not data:
        return False, None, "Empty image payload"
    if len(data) > cfg.max_image_bytes:
        return False, None, f"Image exceeds {cfg.max_image_bytes} byte limit"

    info = parse_image_info(data)

    if isinstance(content_type, str) and content_type.strip():
        ct_main = content_type.split(";", 1)[0].strip().lower()
        if ct_main in _REJECTED_CONTENT_TYPES:
            return False, None, f"Non-image Content-Type '{ct_main}'"
        if ct_main == "text/plain" and (info is None or info.format != "SVG"):
            return False, None, "Non-image Content-Type 'text/plain'"

    if info is None:
        return False, None, "Unrecognized or corrupt image bytes (magic-byte check failed)"

    if info.width is not None and info.height is not None:
        if info.width <= 0 or info.height <= 0:
            return False, info, f"Invalid zero/negative dimensions ({info.width}x{info.height})"
        if max(info.width, info.height) < cfg.min_dimension or info.width <= 2 or info.height <= 2:
            return (
                False,
                info,
                f"Rejected spacer/tiny image ({info.width}x{info.height} < {cfg.min_dimension}px)",
            )
        if info.format == "SVG":
            max_ratio = cfg.svg_max_aspect_ratio
        elif (
            info.format in ("PNG", "WEBP", "GIF")
            and info.width > info.height
            and info.height >= cfg.min_dimension
        ):
            max_ratio = cfg.horizontal_logo_max_aspect_ratio
        else:
            max_ratio = cfg.max_aspect_ratio
        ratio = max(info.width / info.height, info.height / info.width)
        if ratio > max_ratio:
            return (
                False,
                info,
                f"Rejected extreme aspect-ratio banner ({info.width}x{info.height}, ratio {ratio:.2f})",
            )
        if (
            source != "schema.org JSON-LD logo"
            and info.format == "JPEG"
            and info.width >= 1000
            and info.height >= 450
        ):
            return (
                False,
                info,
                f"Rejected oversized JPEG hero/photo ({info.width}x{info.height})",
            )
        if source == "og:image":
            if (
                (info.width >= 1000 and info.height >= 500)
                or ratio > cfg.og_max_aspect_ratio
                or (info.format == "JPEG" and info.width >= 800)
            ):
                return (
                    False,
                    info,
                    f"Rejected og:image social/promo banner ({info.width}x{info.height})",
                )

    return True, info, None


def _is_og_image_candidate_allowed(og_url: str, og_alt: str, target_domain: str) -> bool:
    """Pre-download gate for ``og:image``: require explicit brand-logo signal & no banner cues."""
    if not og_url or og_url.strip().lower().startswith("data:"):
        return False
    parsed = urllib.parse.urlparse(og_url)
    filename = posixpath.basename(parsed.path).lower()
    path_lower = parsed.path.lower()
    combined_tok = _normalize_tokens(f"{filename} {og_alt}")
    combined_norm = normalize_text(f"{filename} {og_alt}")

    logo_signals = ("logo", "brand", "wordmark", "logotype", "emblem")
    has_logo_signal = any(
        re.search(rf"\b{sig}\b", combined_tok) or sig in combined_norm
        for sig in logo_signals
    )
    if not has_logo_signal:
        return False

    banner_cues = (
        "1200x630",
        "1200x627",
        "og-image",
        "og_image",
        "share-image",
        "skyline",
        "header",
        "slider",
        "hero",
        "checking",
        "heloc",
    )
    is_svg = filename.endswith(".svg")
    if not is_svg and any(cue in path_lower or cue in combined_norm for cue in banner_cues):
        return False

    excluded, _ = is_excluded_image(og_url, target_domain, alt=og_alt)
    return not excluded


def _build_session(config: ExtractorConfig) -> requests.Session:
    session = ConfiguredSession()
    pool_size = max(4, config.max_workers)
    adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": config.user_agent})
    session.verify = config.verify_ssl
    if config.verify_ssl is False:
        suppress_insecure_ssl_warnings()
    return session


def _parse_retry_after(raw_value: Any) -> float | None:
    if not isinstance(raw_value, str):
        return None
    cleaned = raw_value.strip()
    if not cleaned:
        return None
    try:
        delay = float(cleaned)
    except ValueError:
        return None
    if not math.isfinite(delay) or delay < 0:
        return None
    return min(delay, 30.0)


def _session_get(
    session: requests.Session,
    url: str,
    *,
    headers: Mapping[str, str],
    timeout: float,
    verify: bool | str,
    stream: bool = False,
) -> requests.Response:
    if verify is False:
        suppress_insecure_ssl_warnings()
    return session.get(
        url,
        headers=headers,
        timeout=timeout,
        verify=verify,
        stream=stream,
    )


def _fetch_with_retry(
    session: requests.Session,
    url: str,
    config: ExtractorConfig,
    *,
    stream: bool = False,
) -> requests.Response:
    headers = {"User-Agent": config.user_agent}
    last_exc: requests.RequestException | None = None
    attempts = max(1, config.max_retries + 1)

    for attempt in range(attempts):
        try:
            resp = _session_get(
                session,
                url,
                headers=headers,
                timeout=config.timeout,
                verify=config.verify_ssl,
                stream=stream,
            )
        except requests.exceptions.SSLError:
            raise
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            if attempt >= attempts - 1:
                raise
            delay = config.backoff_base * (2**attempt) + random.uniform(0.0, 0.25)
            import time

            time.sleep(delay)
            continue

        status = getattr(resp, "status_code", 200)
        if status in _RETRY_STATUS_CODES and attempt < attempts - 1:
            retry_after = None
            if status == 429 and isinstance(getattr(resp, "headers", None), Mapping):
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
            try:
                resp.close()
            except Exception:
                pass
            delay = (
                retry_after
                if retry_after is not None
                else config.backoff_base * (2**attempt) + random.uniform(0.0, 0.25)
            )
            import time

            time.sleep(delay)
            continue

        return resp

    if last_exc is not None:
        raise last_exc
    raise requests.exceptions.RequestException(f"Failed to fetch {url}")


def _read_response_bytes(resp: requests.Response, max_bytes: int) -> tuple[bytes | None, str | None]:
    """Read up to ``max_bytes`` from a streaming response, returning ``(data, error_reason)``."""
    try:
        headers = getattr(resp, "headers", None)
        if isinstance(headers, Mapping):
            raw_len = headers.get("Content-Length") or headers.get("content-length")
            if isinstance(raw_len, (str, int)):
                try:
                    if int(str(raw_len).strip()) > max_bytes:
                        return None, f"Content-Length exceeds {max_bytes} byte limit"
                except ValueError:
                    pass

        iter_fn = getattr(resp, "iter_content", None)
        if callable(iter_fn):
            chunks: list[bytes] = []
            total = 0
            saw_bytes_chunk = False
            iterated_cleanly = False
            try:
                iterator = iter_fn(chunk_size=65536)
                saw_non_bytes = False
                for chunk in iterator:
                    if not isinstance(chunk, (bytes, bytearray)):
                        saw_non_bytes = True
                        break
                    saw_bytes_chunk = True
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        return None, f"Image exceeds {max_bytes} byte limit"
                    chunks.append(bytes(chunk))
                if not saw_non_bytes:
                    iterated_cleanly = True
            except (requests.exceptions.RequestException, OSError) as exc:
                return None, f"Stream read error: {exc}"
            except TypeError:
                saw_bytes_chunk = False

            if saw_bytes_chunk or (
                iterated_cleanly
                and isinstance(resp, requests.Response)
                and getattr(resp, "_content_consumed", False) is True
                and getattr(resp, "_content", None) is False
            ):
                return b"".join(chunks), None

        try:
            raw_content = getattr(resp, "content", b"")
        except RuntimeError:
            return b"", None
        if isinstance(raw_content, (bytes, bytearray)):
            data = bytes(raw_content)
            if len(data) > max_bytes:
                return None, f"Image exceeds {max_bytes} byte limit"
            return data, None
        return b"", None
    finally:
        try:
            resp.close()
        except Exception:
            pass


def _attr_as_str(tag: Any, attr: str) -> str:
    val: Any = tag.get(attr)
    if val is None:
        return ""
    if isinstance(val, list):
        return " ".join(str(x) for x in val)
    return str(val)


def _collect_parent_context(tag: Any) -> tuple[list[str], list[str], list[str]]:
    p_tags: list[str] = []
    p_classes: list[str] = []
    p_ids: list[str] = []
    for parent in tag.parents:
        if parent.name:
            tag_name = parent.name.lower()
            p_tags.append(tag_name)
            if tag_name not in ("body", "html", "[document]"):
                parent_cls = parent.get("class", [])
                if isinstance(parent_cls, list):
                    p_classes.extend(str(c) for c in parent_cls)
                elif parent_cls:
                    p_classes.append(str(parent_cls))
                parent_id = parent.get("id")
                if parent_id:
                    p_ids.append(str(parent_id))
    return p_tags, p_classes, p_ids


def extract_domain_logos(
    domain: str,
    idx: int = 1,
    total: int = 1,
    ignored_hashes: Mapping[str, str] | None = None,
    config: ExtractorConfig | None = None,
    session: requests.Session | None = None,
) -> DomainExtractionResult:
    """Discover, filter, validate, and hash legitimate brand logos for a single domain."""
    cfg = config or ExtractorConfig()
    clean_domain = domain.strip()
    result = DomainExtractionResult(domain=clean_domain)

    if is_ignored_domain(clean_domain, ignored_domains=cfg.ignored_domains):
        print(f"\n[{idx}/{total}] Skipping ignored domain {clean_domain}...")
        result.domain_error = "Ignored domain"
        return result

    active_ignored = (
        dict(ignored_hashes) if ignored_hashes is not None else load_ignored_hashes()
    )

    own_session = session is None
    active_session = session if session is not None else _build_session(cfg)

    try:
        initial_url = f"https://{clean_domain}"
        print(f"\n[{idx}/{total}] Processing {clean_domain}...")

        try:
            response = _fetch_with_retry(active_session, initial_url, cfg, stream=False)
        except requests.exceptions.RequestException:
            initial_url = f"http://{clean_domain}"
            try:
                response = _fetch_with_retry(active_session, initial_url, cfg, stream=False)
            except requests.exceptions.RequestException as exc:
                result.domain_error = f"Connection failed: {exc}"
                return result

        raw_resp_url = getattr(response, "url", None)
        final_url = (
            raw_resp_url
            if isinstance(raw_resp_url, str) and raw_resp_url.startswith(("http://", "https://"))
            else initial_url
        )
        result.final_url = final_url
        final_host = (urllib.parse.urlparse(final_url).hostname or clean_domain).lower()
        target_root = (
            (urllib.parse.urlparse(f"http://{clean_domain}").hostname or clean_domain)
            .lower()
            .removeprefix("www.")
        )
        final_root = final_host.removeprefix("www.")
        is_cross_domain_redirect = bool(
            final_root
            and target_root
            and final_root != target_root
            and not final_root.endswith(f".{target_root}")
            and not target_root.endswith(f".{final_root}")
        )
        if is_cross_domain_redirect:
            logger.warning(
                "Domain '%s' redirected cross-domain to '%s' (%s)",
                clean_domain,
                final_host,
                final_url,
            )
            print(f"    [!] Cross-domain redirect: {clean_domain} -> {final_host}")

        if response.status_code != 200:
            result.domain_error = (
                f"HTTP {response.status_code} (redirected to {final_host})"
                if is_cross_domain_redirect
                else f"HTTP {response.status_code}"
            )
            return result

        html = response.text if isinstance(getattr(response, "text", None), str) else ""
        soup = BeautifulSoup(html, "html.parser")

        has_visible_imgs = _has_visible_img_tags(soup)
        has_real_icons = _has_real_icon_or_manifest_links(soup)
        has_jsonld_scripts = bool(
            soup.find("script", type=re.compile(r"application/ld\+json", re.I))
        )
        if not has_visible_imgs and not has_jsonld_scripts:
            html_lower = html.lower()
            strong_bot_markers = (
                "gdprappliesglobally",
                "cf-browser-verification",
                "/cdn-cgi/challenge-platform",
                "attention required! | cloudflare",
                "tspd_101",
                "/tspd/",
                'window["bobcmn"]',
                "<title>web page under construction</title>",
            )
            general_bot_markers = (
                "just a moment...",
                "bot verification",
            )
            is_strong_marker = any(marker in html_lower for marker in strong_bot_markers)
            is_general_marker = not has_real_icons and any(
                marker in html_lower for marker in general_bot_markers
            )
            is_tiny_stub = (
                not has_real_icons
                and len(html.strip()) < 256
                and (
                    "<script" in html_lower
                    or 'http-equiv="refresh"' in html_lower
                    or "http-equiv='refresh'" in html_lower
                )
            )
            if is_strong_marker or is_general_marker or is_tiny_stub:
                result.domain_error = (
                    f"Bot challenge / parking interstitial (HTTP 200) (redirected to {final_host})"
                    if is_cross_domain_redirect
                    else "Bot challenge / parking interstitial (HTTP 200)"
                )
                return result

        effective_base = final_url
        base_tag = soup.find("base", href=True)
        if base_tag and base_tag.get("href"):
            base_href = str(base_tag.get("href")).strip()
            if base_href and not base_href.lower().startswith(("data:", "javascript:")):
                effective_base = urllib.parse.urljoin(final_url, base_href)

        resolved_urls: dict[str, dict[str, Any]] = {}
        inline_svg_candidates: list[dict[str, Any]] = []
        icon_group_fallbacks: dict[str, tuple[str, dict[str, Any], list[dict[str, Any]]]] = {}

        def add_discovered(
            path: str,
            source: str,
            *,
            base_url: str = effective_base,
            alt: str = "",
            cls: str = "",
            id_val: str = "",
            parent_tags: list[str] | None = None,
            parent_classes: list[str] | None = None,
            parent_ids: list[str] | None = None,
        ) -> None:
            if not path or not str(path).strip():
                return
            raw_path = str(path).strip()
            if raw_path.lower().startswith(("javascript:", "mailto:", "tel:", "#")):
                return
            if raw_path.lower().startswith("data:"):
                abs_url = raw_path
            else:
                abs_url = urllib.parse.urljoin(base_url, raw_path)
            if abs_url not in resolved_urls:
                resolved_urls[abs_url] = {
                    "url": abs_url,
                    "source": source,
                    "alt": alt,
                    "class": cls,
                    "id": id_val,
                    "parent_tags": parent_tags or [],
                    "parent_classes": parent_classes or [],
                    "parent_ids": parent_ids or [],
                }

        # S1: Schema.org JSON-LD logo (+ og:logo)
        for script_tag in soup.find_all("script", type=re.compile(r"application/ld\+json", re.I)):
            try:
                raw_json = script_tag.string or script_tag.get_text()
                if not raw_json or not raw_json.strip():
                    continue
                data = json.loads(raw_json)
                items: list[Any] = []
                if isinstance(data, list):
                    items.extend(data)
                elif isinstance(data, dict):
                    if isinstance(data.get("@graph"), list):
                        items.extend(data["@graph"])
                    items.append(data)

                target_types = (
                    "bankorcreditunion",
                    "financialservice",
                    "organization",
                    "corporation",
                    "localbusiness",
                    "creditunion",
                    "bank",
                    "website",
                )
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    external_entity = False
                    for id_key in ("url", "@id"):
                        raw_ref = item.get(id_key)
                        if isinstance(raw_ref, str) and raw_ref.strip().lower().startswith(("http://", "https://")):
                            ref_host = (urllib.parse.urlparse(raw_ref.strip()).hostname or "").lower()
                            if ref_host and not (
                                _host_matches(ref_host, target_root)
                                or _host_matches(ref_host, final_root)
                                or any(_host_matches(ref_host, d) for d in cfg.allow_domains)
                            ):
                                external_entity = True
                                break
                    if external_entity:
                        continue
                    t_val = item.get("@type", "")
                    if isinstance(t_val, list):
                        t = " ".join(str(x) for x in t_val).lower()
                    else:
                        t = str(t_val).lower()
                    if any(tt in t for tt in target_types) or not t:
                        logo_val = item.get("logo")
                        if isinstance(logo_val, str) and logo_val:
                            add_discovered(logo_val, "schema.org JSON-LD logo")
                        elif isinstance(logo_val, dict):
                            logo_url = logo_val.get("url") or logo_val.get("contentUrl")
                            if logo_url:
                                add_discovered(str(logo_url), "schema.org JSON-LD logo")
                        elif isinstance(logo_val, list):
                            for lv in logo_val:
                                if isinstance(lv, str) and lv:
                                    add_discovered(lv, "schema.org JSON-LD logo")
                                elif isinstance(lv, dict):
                                    l_url = lv.get("url") or lv.get("contentUrl")
                                    if l_url:
                                        add_discovered(str(l_url), "schema.org JSON-LD logo")
            except Exception:
                pass

        og_logo = soup.find("meta", property="og:logo") or soup.find("meta", attrs={"name": "og:logo"})
        if og_logo and og_logo.get("content"):
            add_discovered(str(og_logo.get("content")), "og:logo")

        # S2: <link> icons (icon, shortcut icon, apple-touch-icon, mask-icon)
        icon_tags = soup.find_all(
            "link",
            rel=re.compile(r"^(?:shortcut\s+)?icon$|apple-touch-icon(?:-precomposed)?$|^mask-icon$", re.I),
        )
        all_icon_items: list[dict[str, Any]] = []
        for icon in icon_tags:
            href_val = icon.get("href")
            if not href_val:
                continue
            href = str(href_val).strip()
            rel = _attr_as_str(icon, "rel")
            sizes = str(icon.get("sizes", "")).strip().lower()

            dim = 0
            if sizes and sizes != "any":
                m = re.search(r"(\d+)x(\d+)", sizes)
                if m:
                    dim = int(m.group(1))
                else:
                    m = re.search(r"(\d+)", sizes)
                    if m:
                        dim = int(m.group(1))
            if dim == 0:
                m = re.search(r"[-_](\d+)x(\d+)", href)
                if m:
                    dim = int(m.group(1))
                else:
                    m = re.search(r"[-_](\d+)\.[a-z0-9]+$", href, re.I)
                    if m:
                        dim = int(m.group(1))

            is_touch = "apple-touch-icon" in rel.lower()
            is_svg = href.lower().endswith(".svg") or "image/svg" in str(icon.get("type", "")).lower()

            path = urllib.parse.urlparse(href).path
            filename = posixpath.basename(path).lower()
            stem = _normalize_icon_stem(filename)

            all_icon_items.append(
                {
                    "href": href,
                    "rel": rel,
                    "dim": dim,
                    "is_svg": is_svg,
                    "is_touch": is_touch,
                    "stem": stem,
                    "source": f"link rel={rel}",
                }
            )

        stem_groups: dict[str, list[dict[str, Any]]] = {}
        for item in all_icon_items:
            stem_groups.setdefault(item["stem"], []).append(item)

        for stem, group in stem_groups.items():
            ordered = sorted(
                group,
                key=lambda x: (1 if x["is_svg"] else 0, x["dim"]),
                reverse=True,
            )
            dedup_ordered: list[dict[str, Any]] = []
            seen_abs: set[str] = set()
            for icon_entry in ordered:
                abs_icon_url = (
                    icon_entry["href"]
                    if icon_entry["href"].lower().startswith("data:")
                    else urllib.parse.urljoin(effective_base, icon_entry["href"])
                )
                if abs_icon_url not in seen_abs:
                    seen_abs.add(abs_icon_url)
                    entry_copy = dict(icon_entry)
                    entry_copy["abs_url"] = abs_icon_url
                    dedup_ordered.append(entry_copy)

            best = dedup_ordered[0]
            fallbacks = dedup_ordered[1:]
            add_discovered(best["href"], best["source"])
            if fallbacks and best["abs_url"] not in icon_group_fallbacks:
                icon_group_fallbacks[best["abs_url"]] = (stem, best, fallbacks)

        # S3: <link rel="manifest">
        for manifest_tag in soup.find_all("link", rel=re.compile(r"\bmanifest\b", re.I)):
            m_href = manifest_tag.get("href")
            if not m_href:
                continue
            manifest_url = urllib.parse.urljoin(effective_base, str(m_href).strip())
            if not manifest_url.lower().startswith(("http://", "https://")):
                continue
            m_resp = None
            try:
                m_resp = _fetch_with_retry(active_session, manifest_url, cfg, stream=True)
                if getattr(m_resp, "status_code", 0) == 200:
                    m_bytes, m_err = _read_response_bytes(m_resp, cfg.max_manifest_bytes)
                    if m_bytes and not m_err:
                        m_data = json.loads(m_bytes.decode("utf-8", errors="replace"))
                        if isinstance(m_data, dict) and isinstance(m_data.get("icons"), list):
                            m_resp_url = getattr(m_resp, "url", None)
                            m_base = (
                                m_resp_url
                                if isinstance(m_resp_url, str)
                                and m_resp_url.startswith(("http://", "https://"))
                                else manifest_url
                            )
                            m_items: list[dict[str, Any]] = []
                            for icon_obj in m_data["icons"]:
                                if not isinstance(icon_obj, dict) or not icon_obj.get("src"):
                                    continue
                                icon_src = str(icon_obj["src"]).strip()
                                sizes = str(icon_obj.get("sizes", "")).strip().lower()
                                dim = 0
                                dm = re.search(r"(\d+)x(\d+)", sizes)
                                if dm:
                                    dim = int(dm.group(1))
                                m_path = urllib.parse.urlparse(icon_src).path
                                m_fn = posixpath.basename(m_path).lower()
                                m_stem = _normalize_icon_stem(m_fn)
                                m_items.append(
                                    {
                                        "src": icon_src,
                                        "dim": dim,
                                        "is_svg": m_fn.endswith(".svg")
                                        or "svg" in str(icon_obj.get("type", "")).lower(),
                                        "stem": m_stem,
                                    }
                                )
                            m_groups: dict[str, list[dict[str, Any]]] = {}
                            for mi in m_items:
                                m_groups.setdefault(mi["stem"], []).append(mi)
                            for m_group in m_groups.values():
                                svgs = [x for x in m_group if x["is_svg"]]
                                if svgs:
                                    best_m = svgs[0]
                                else:
                                    m_group.sort(key=lambda x: x["dim"], reverse=True)
                                    best_m = m_group[0]
                                add_discovered(
                                    best_m["src"],
                                    "link rel=manifest",
                                    base_url=m_base,
                                )
            except Exception as exc:
                logger.debug("Manifest parse/fetch skipped for %s: %s", manifest_url, exc)
            finally:
                if m_resp is not None:
                    try:
                        m_resp.close()
                    except Exception:
                        pass

        # S4: <meta name="msapplication-TileImage"> & square logos (dedup shared stems)
        tile_candidates: list[dict[str, Any]] = []
        for meta_tag in soup.find_all("meta", attrs={"name": True, "content": True}):
            m_name = str(meta_tag.get("name", "")).strip().lower()
            if m_name == "msapplication-tileimage" or (
                m_name.startswith("msapplication-square") and m_name.endswith("logo")
            ):
                content_val = str(meta_tag.get("content", "") or "").strip()
                if not content_val or content_val.lower().startswith(
                    ("javascript:", "mailto:", "tel:", "#")
                ):
                    continue
                abs_tile = (
                    content_val
                    if content_val.lower().startswith("data:")
                    else urllib.parse.urljoin(effective_base, content_val)
                )
                t_dim = 0
                dm_name = re.search(r"(\d+)x(\d+)", m_name)
                if dm_name:
                    t_dim = int(dm_name.group(1))
                elif not abs_tile.lower().startswith("data:"):
                    tp = urllib.parse.urlparse(abs_tile)
                    qs = urllib.parse.parse_qs(tp.query)
                    for qk in ("width", "w", "size"):
                        if qk in qs and qs[qk]:
                            try:
                                t_dim = max(t_dim, int(qs[qk][0]))
                            except ValueError:
                                pass
                    if t_dim == 0:
                        dm_path = re.search(
                            r"[-_](\d+)(?:x\d+)?(?:\.[a-z0-9]+)?$", tp.path, re.I
                        )
                        if dm_path:
                            t_dim = int(dm_path.group(1))
                if abs_tile.lower().startswith("data:"):
                    t_stem = abs_tile
                else:
                    tp = urllib.parse.urlparse(abs_tile)
                    clean_path = re.sub(
                        r"[-_](\d+)x(\d+)(\.[a-z0-9]+)$", r"\3", tp.path, flags=re.I
                    )
                    t_stem = f"{tp.scheme.lower()}://{tp.netloc.lower()}{clean_path.lower()}"
                tile_candidates.append(
                    {
                        "raw": content_val,
                        "abs": abs_tile,
                        "source": f"meta {m_name}",
                        "dim": t_dim,
                        "stem": t_stem,
                    }
                )

        tile_groups: dict[str, list[dict[str, Any]]] = {}
        for tc in tile_candidates:
            tile_groups.setdefault(tc["stem"], []).append(tc)
        for t_group in tile_groups.values():
            best_t = max(t_group, key=lambda x: x["dim"])
            add_discovered(best_t["raw"], best_t["source"])
            for tc in t_group:
                if tc["abs"] != best_t["abs"]:
                    result.discovered_locations.append(
                        {
                            "domain": clean_domain,
                            "url": tc["abs"],
                            "source": tc["source"],
                            "status": "excluded",
                            "exclusion_reason": (
                                f"Excluded: lower-resolution duplicate tile icon ({tc['dim']}px) "
                                f"- preferred ({best_t['dim']}px)"
                            ),
                        }
                    )

        # S5: <img> & <picture> (supporting src, data-src, data-lazy-src, data-original, srcset, data-srcset)
        home_hrefs = {
            "/",
            "",
            initial_url.lower(),
            final_url.lower(),
            effective_base.lower(),
            f"https://{clean_domain.lower()}",
            f"https://{clean_domain.lower()}/",
            f"http://{clean_domain.lower()}",
            f"http://{clean_domain.lower()}/",
            f"https://{final_host}",
            f"https://{final_host}/",
        }
        for img in soup.find_all("img"):
            raw_src = str(img.get("src", "") or "").strip()
            lazy_attrs = [
                str(img.get(attr, "") or "").strip()
                for attr in ("data-src", "data-lazy-src", "data-original")
            ]
            lazy_urls = [u for u in lazy_attrs if u]

            alt = str(img.get("alt", "") or "")
            cls = _attr_as_str(img, "class")
            id_val = str(img.get("id", "") or "")

            p_tags, p_classes, p_ids = _collect_parent_context(img)
            clean_cls = _strip_tailwind_brand_utilities(cls)
            clean_p_classes = [_strip_tailwind_brand_utilities(c) for c in p_classes]

            is_header_home_logo = False
            if any(t in ("header", "nav") for t in p_tags):
                for parent in img.parents:
                    if parent.name and parent.name.lower() == "a":
                        a_href = str(parent.get("href", "")).strip().lower()
                        a_rel = _attr_as_str(parent, "rel").strip().lower()
                        a_label = str(parent.get("aria-label", "")).strip().lower()
                        a_cls = _strip_tailwind_brand_utilities(_attr_as_str(parent, "class"))
                        if (
                            a_href in home_hrefs
                            or "home" in a_rel
                            or "home" in a_label
                            or "brand" in a_cls.lower()
                            or "logo" in a_cls.lower()
                        ):
                            is_header_home_logo = True
                            break

            srcset_candidates: list[str] = []
            for ss_attr in ("srcset", "data-srcset"):
                ss_val = str(img.get(ss_attr, "") or "").strip()
                if ss_val:
                    srcset_candidates.extend(parse_srcset(ss_val))

            non_alt_text = " ".join(
                [raw_src, *lazy_urls, *srcset_candidates, clean_cls, id_val, *clean_p_classes, *p_ids]
            ).lower()
            alt_has_logo = len(alt.split()) <= 6 and bool(_ALT_LOGO_WORD_RE.search(alt))
            is_logo_candidate = ("logo" in non_alt_text or "brand" in non_alt_text) or alt_has_logo

            if is_logo_candidate or is_header_home_logo:
                src_desc = (
                    "header/brand home link img"
                    if is_header_home_logo and not is_logo_candidate
                    else "img tag with 'logo' or 'brand'"
                )
                img_url_candidates: list[tuple[str, str]] = []
                if raw_src:
                    img_url_candidates.append((raw_src, src_desc))
                for l_url in lazy_urls:
                    img_url_candidates.append((l_url, src_desc))
                for ss_url in srcset_candidates:
                    img_url_candidates.append((ss_url, "img srcset logo"))

                kept_urls, excluded_variants = _dedup_img_responsive_urls(
                    img_url_candidates, effective_base
                )
                for kept_url, kept_desc in kept_urls:
                    add_discovered(
                        kept_url,
                        kept_desc,
                        alt=alt,
                        cls=cls,
                        id_val=id_val,
                        parent_tags=p_tags,
                        parent_classes=p_classes,
                        parent_ids=p_ids,
                    )
                for excl_url, excl_desc, excl_reason in excluded_variants:
                    result.discovered_locations.append(
                        {
                            "domain": clean_domain,
                            "url": excl_url,
                            "source": excl_desc,
                            "status": "excluded",
                            "exclusion_reason": excl_reason,
                        }
                    )
                if img.parent and img.parent.name and img.parent.name.lower() == "picture":
                    for source in img.parent.find_all("source"):
                        for p_attr in ("srcset", "data-srcset"):
                            p_ss = str(source.get(p_attr, "") or "").strip()
                            if p_ss:
                                for cand in parse_srcset(p_ss):
                                    add_discovered(
                                        cand,
                                        "picture source (srcset) logo",
                                        alt=alt,
                                        cls=cls,
                                        id_val=id_val,
                                        parent_tags=p_tags,
                                        parent_classes=p_classes,
                                        parent_ids=p_ids,
                                    )

        # S6: Inline <svg> in header/home/logo containers
        svg_index = 0
        for svg_tag in soup.find_all("svg"):
            p_tags, p_classes, p_ids = _collect_parent_context(svg_tag)
            if "button" in p_tags:
                continue

            svg_cls = _attr_as_str(svg_tag, "class")
            svg_id = str(svg_tag.get("id", "") or "")
            svg_aria = str(svg_tag.get("aria-label", "") or "")
            clean_svg_cls = _strip_tailwind_brand_utilities(svg_cls)
            clean_p_classes = [_strip_tailwind_brand_utilities(c) for c in p_classes]

            in_header_home = False
            if any(t in ("header", "nav") for t in p_tags):
                for parent in svg_tag.parents:
                    if parent.name and parent.name.lower() == "a":
                        a_href = str(parent.get("href", "")).strip().lower()
                        a_rel = _attr_as_str(parent, "rel").strip().lower()
                        a_label = str(parent.get("aria-label", "")).strip().lower()
                        a_cls = _strip_tailwind_brand_utilities(_attr_as_str(parent, "class"))
                        if (
                            a_href in home_hrefs
                            or "home" in a_rel
                            or "home" in a_label
                            or "brand" in a_cls.lower()
                            or "logo" in a_cls.lower()
                        ):
                            in_header_home = True
                            break

            has_logo_attr = any(
                kw in " ".join([clean_svg_cls, svg_id, svg_aria, *clean_p_classes, *p_ids]).lower()
                for kw in ("logo", "brand")
            )
            is_aria_hidden = str(svg_tag.get("aria-hidden", "")).strip().lower() == "true"
            if is_aria_hidden and not (in_header_home and has_logo_attr):
                continue

            if in_header_home or has_logo_attr:
                svg_index += 1
                synthetic_url = f"inline-svg://{clean_domain}/{svg_index}"
                inline_svg_candidates.append(
                    {
                        "url": synthetic_url,
                        "source": "inline <svg> brand logo",
                        "svg_markup": str(svg_tag),
                        "alt": svg_aria,
                        "class": svg_cls,
                        "id": svg_id,
                        "parent_tags": p_tags,
                        "parent_classes": p_classes,
                        "parent_ids": p_ids,
                    }
                )

        # S7b: Inline <style> CSS background-image logo rules (#logo / .logo / .brand)
        style_kept, style_excluded = _extract_inline_style_logo_urls(soup, effective_base)
        for style_raw_url, style_src in style_kept:
            add_discovered(style_raw_url, style_src)
        for style_excl_url, style_excl_src, style_excl_reason in style_excluded:
            result.discovered_locations.append(
                {
                    "domain": clean_domain,
                    "url": style_excl_url,
                    "source": style_excl_src,
                    "status": "excluded",
                    "exclusion_reason": style_excl_reason,
                }
            )

        # S7: Gated og:image (accept only with explicit brand-logo signal & no banner cues)
        og_image = soup.find("meta", property="og:image") or soup.find(
            "meta", attrs={"name": "og:image"}
        )
        if og_image and og_image.get("content"):
            og_url_raw = str(og_image.get("content")).strip()
            og_alt_tag = soup.find("meta", property="og:image:alt") or soup.find(
                "meta", attrs={"name": "og:image:alt"}
            )
            og_alt = str(og_alt_tag.get("content", "")) if og_alt_tag else ""
            og_abs = urllib.parse.urljoin(effective_base, og_url_raw)
            if _is_og_image_candidate_allowed(og_abs, og_alt, clean_domain):
                add_discovered(og_url_raw, "og:image", alt=og_alt)
            else:
                result.discovered_locations.append(
                    {
                        "domain": clean_domain,
                        "url": og_abs,
                        "source": "og:image",
                        "status": "excluded",
                        "exclusion_reason": "Excluded: og:image failed brand-logo gate (missing logo signal or promotional/banner cues)",
                    }
                )

        # S8: /favicon.ico fallback + configurable force_urls
        add_discovered("/favicon.ico", "default favicon path")
        for forced_url in cfg.force_urls.get(clean_domain.lower(), []):
            add_discovered(forced_url, "Configured domain override URL")

        seen_sha256: set[str] = set()

        def _record_validated_bytes(
            img_url: str,
            source: str,
            img_data: bytes,
            content_type: str | None = None,
        ) -> str:
            is_valid, info, invalid_reason = validate_image_bytes(
                img_data,
                content_type=content_type,
                source=source,
                config=cfg,
            )
            if not is_valid:
                result.discovered_locations.append(
                    {
                        "domain": clean_domain,
                        "url": img_url,
                        "source": source,
                        "status": "empty_or_non_image",
                        "error": invalid_reason or "Invalid image",
                    }
                )
                return "failed"

            hashes = compute_image_hashes(img_data)
            matched_hash, matched_reason = match_ignored_hash(hashes, active_ignored)
            if matched_hash is not None:
                result.discovered_locations.append(
                    {
                        "domain": clean_domain,
                        "url": img_url,
                        "source": source,
                        "status": "excluded",
                        "exclusion_reason": f"Excluded: Ignored hash ({matched_reason})",
                    }
                )
                return "ignored_hash"

            sha256_val = hashes["sha256"]
            if sha256_val in seen_sha256:
                result.discovered_locations.append(
                    {
                        "domain": clean_domain,
                        "url": img_url,
                        "source": source,
                        "status": "excluded",
                        "exclusion_reason": (
                            f"Excluded: duplicate image hash '{sha256_val}' "
                            "already processed for this domain"
                        ),
                    }
                )
                return "duplicate_hash"

            seen_sha256.add(sha256_val)
            result.logos.append(
                ExtractedLogo(
                    domain=clean_domain,
                    image_url=img_url,
                    source=source,
                    md5=hashes["md5"],
                    sha1=hashes["sha1"],
                    sha256=sha256_val,
                    image_info=info,
                    byte_length=len(img_data),
                )
            )
            loc_entry: dict[str, Any] = {
                "domain": clean_domain,
                "url": img_url,
                "source": source,
                "status": "included",
                "md5": hashes["md5"],
                "sha1": hashes["sha1"],
                "sha256": sha256_val,
            }
            if info is not None:
                loc_entry["format"] = info.format
                if info.width is not None and info.height is not None:
                    loc_entry["dimensions"] = f"{info.width}x{info.height}"
            result.discovered_locations.append(loc_entry)
            return "included"

        def _record_lower_res_icons(
            stem: str,
            preferred_item: dict[str, Any],
            superseded: list[dict[str, Any]],
        ) -> None:
            for lower_icon in superseded:
                excl_reason = (
                    f"Excluded: lower-resolution duplicate touch icon ({lower_icon['dim']}x{lower_icon['dim']}) "
                    f"of '{stem}' - preferred ({preferred_item['dim']}x{preferred_item['dim']})"
                    if lower_icon["is_touch"]
                    else f"Excluded: lower-resolution duplicate favicon ({lower_icon['dim']}x{lower_icon['dim']}) "
                    f"of '{stem}' - preferred ({preferred_item['dim']}x{preferred_item['dim']})"
                )
                result.discovered_locations.append(
                    {
                        "domain": clean_domain,
                        "url": lower_icon["abs_url"],
                        "source": lower_icon["source"],
                        "status": "excluded",
                        "exclusion_reason": excl_reason,
                    }
                )

        def _evaluate_url_candidate(
            img_url: str,
            item_meta: Mapping[str, Any],
            *,
            capture_image_errors: list[str] | None = None,
        ) -> str:
            is_excl, reason = is_excluded_image(
                url=img_url,
                target_domain=clean_domain,
                alt=item_meta.get("alt", ""),
                cls=item_meta.get("class", ""),
                id_val=item_meta.get("id", ""),
                parent_tags=item_meta.get("parent_tags"),
                parent_classes=item_meta.get("parent_classes"),
                parent_ids=item_meta.get("parent_ids"),
                config=cfg,
                final_host=final_host,
                source=str(item_meta.get("source", "")),
            )
            if is_excl:
                result.discovered_locations.append(
                    {
                        "domain": clean_domain,
                        "url": img_url,
                        "source": item_meta["source"],
                        "status": "excluded",
                        "exclusion_reason": reason,
                    }
                )
                return "excluded_keyword"

            err_sink = capture_image_errors if capture_image_errors is not None else result.image_errors

            if img_url.lower().startswith("data:"):
                decoded = decode_data_uri(img_url, max_bytes=cfg.max_image_bytes)
                if decoded is None:
                    result.discovered_locations.append(
                        {
                            "domain": clean_domain,
                            "url": img_url[:128],
                            "source": item_meta["source"],
                            "status": "empty_or_non_image",
                            "error": "Invalid or unsupported data: URI",
                        }
                    )
                    return "failed"
                raw_data, mime_type = decoded
                return _record_validated_bytes(
                    img_url, item_meta["source"], raw_data, content_type=mime_type
                )

            try:
                img_resp = _fetch_with_retry(active_session, img_url, cfg, stream=True)
            except requests.exceptions.RequestException as exc:
                err_sink.append(f"{img_url} (Network error: {exc})")
                result.discovered_locations.append(
                    {
                        "domain": clean_domain,
                        "url": img_url,
                        "source": item_meta["source"],
                        "status": "download_failed",
                        "error": str(exc),
                    }
                )
                return "failed"

            if img_resp.status_code != 200:
                try:
                    img_resp.close()
                except Exception:
                    pass
                err_sink.append(f"{img_url} (HTTP {img_resp.status_code})")
                result.discovered_locations.append(
                    {
                        "domain": clean_domain,
                        "url": img_url,
                        "source": item_meta["source"],
                        "status": "download_failed",
                        "error": f"HTTP {img_resp.status_code}",
                    }
                )
                return "failed"

            resp_headers = getattr(img_resp, "headers", None)
            content_type = (
                resp_headers.get("Content-Type")
                if isinstance(resp_headers, Mapping)
                else None
            )
            img_data, read_err = _read_response_bytes(img_resp, cfg.max_image_bytes)
            if read_err or img_data is None:
                result.discovered_locations.append(
                    {
                        "domain": clean_domain,
                        "url": img_url,
                        "source": item_meta["source"],
                        "status": "empty_or_non_image",
                        "error": read_err or "Failed to read image payload",
                    }
                )
                return "failed"

            return _record_validated_bytes(
                img_url, item_meta["source"], img_data, content_type=content_type
            )

        # Evaluate URL candidates (with fallback to next-largest icon on 404/network failure)
        for item in resolved_urls.values():
            img_url = item["url"]
            if img_url not in icon_group_fallbacks:
                _evaluate_url_candidate(img_url, item)
                continue

            stem, primary_icon, fallbacks = icon_group_fallbacks[img_url]
            primary_errs: list[str] = []
            outcome = _evaluate_url_candidate(
                img_url, item, capture_image_errors=primary_errs
            )
            if outcome in ("included", "ignored_hash", "duplicate_hash", "excluded_keyword"):
                _record_lower_res_icons(stem, primary_icon, fallbacks)
                continue

            preferred = primary_icon
            tried_count = 0
            last_idx = -1
            recovered = False
            for idx, fb in enumerate(fallbacks):
                if tried_count >= _MAX_ICON_FALLBACKS:
                    break
                fb_url = fb["abs_url"]
                if fb_url in resolved_urls:
                    continue
                tried_count += 1
                last_idx = idx
                fb_meta: dict[str, Any] = {
                    "url": fb_url,
                    "source": fb["source"],
                    "alt": "",
                    "class": "",
                    "id": "",
                    "parent_tags": [],
                    "parent_classes": [],
                    "parent_ids": [],
                }
                fb_errs: list[str] = []
                fb_outcome = _evaluate_url_candidate(
                    fb_url, fb_meta, capture_image_errors=fb_errs
                )
                if fb_outcome in ("included", "ignored_hash", "duplicate_hash"):
                    preferred = fb
                    recovered = True
                    rem = [x for x in fallbacks[idx + 1 :] if x["abs_url"] not in resolved_urls]
                    if rem:
                        _record_lower_res_icons(stem, preferred, rem)
                    break

            if not recovered:
                result.image_errors.extend(primary_errs)
                rem = [x for x in fallbacks[last_idx + 1 :] if x["abs_url"] not in resolved_urls]
                if rem:
                    _record_lower_res_icons(stem, preferred, rem)

        # Evaluate inline <svg> candidates (no network fetch)
        for svg_item in inline_svg_candidates:
            is_excl, reason = is_excluded_image(
                url=svg_item["url"],
                target_domain=clean_domain,
                alt=svg_item["alt"],
                cls=svg_item["class"],
                id_val=svg_item["id"],
                parent_tags=svg_item.get("parent_tags"),
                parent_classes=svg_item.get("parent_classes"),
                parent_ids=svg_item.get("parent_ids"),
                config=cfg,
                final_host=final_host,
                source=svg_item["source"],
            )
            if is_excl:
                result.discovered_locations.append(
                    {
                        "domain": clean_domain,
                        "url": svg_item["url"],
                        "source": svg_item["source"],
                        "status": "excluded",
                        "exclusion_reason": reason,
                    }
                )
                continue

            canonical_bytes = canonicalize_inline_svg(svg_item["svg_markup"])
            _record_validated_bytes(
                svg_item["url"],
                svg_item["source"],
                canonical_bytes,
                content_type="image/svg+xml",
            )

        excluded_count = sum(
            1 for item in result.discovered_locations if item.get("status") == "excluded"
        )
        to_query_count = sum(
            1
            for item in result.discovered_locations
            if item.get("status") in ("included", "download_failed")
        )
        result.to_query_count = to_query_count
        total_discovered = excluded_count + to_query_count
        print(
            f"    - Found {total_discovered} potential image URLs "
            f"({excluded_count} excluded, {to_query_count} to query)"
        )
        print(f"    - Successfully downloaded and hashed {len(result.logos)} images.")
        return result
    finally:
        if own_session:
            try:
                active_session.close()
            except Exception:
                pass


def extract_domains_logos(
    domains: Iterable[str],
    ignored_hashes: Mapping[str, str] | None = None,
    config: ExtractorConfig | None = None,
    session: requests.Session | None = None,
    *,
    progress_callback: Callable[[int, int, str, DomainExtractionResult], None] | None = None,
) -> list[DomainExtractionResult]:
    """Extract brand logos across multiple domains using bounded concurrency in input order."""
    domain_list = [d.strip() for d in domains if d and d.strip()]
    if not domain_list:
        return []

    cfg = config or ExtractorConfig()
    active_ignored = (
        dict(ignored_hashes) if ignored_hashes is not None else load_ignored_hashes()
    )
    total = len(domain_list)
    worker_count = max(1, min(cfg.max_workers, total))

    if worker_count == 1:
        single_results: list[DomainExtractionResult] = []
        for idx, dom in enumerate(domain_list, 1):
            res = extract_domain_logos(
                dom,
                idx=idx,
                total=total,
                ignored_hashes=active_ignored,
                config=cfg,
                session=session,
            )
            single_results.append(res)
            if progress_callback is not None:
                try:
                    progress_callback(idx, total, dom, res)
                except Exception:
                    pass
        return single_results

    thread_local = threading.local()
    created_sessions: list[requests.Session] = []
    sessions_lock = threading.Lock()

    def _get_thread_session() -> requests.Session:
        if session is not None:
            return session
        sess = getattr(thread_local, "session", None)
        if sess is None:
            sess = _build_session(cfg)
            thread_local.session = sess
            with sessions_lock:
                created_sessions.append(sess)
        return sess

    results: list[DomainExtractionResult | None] = [None] * total

    def _worker(pos: int, dom: str) -> tuple[int, DomainExtractionResult]:
        res = extract_domain_logos(
            dom,
            idx=pos + 1,
            total=total,
            ignored_hashes=active_ignored,
            config=cfg,
            session=_get_thread_session(),
        )
        return pos, res

    completed = 0
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(_worker, pos, dom) for pos, dom in enumerate(domain_list)
            ]
            for fut in concurrent.futures.as_completed(futures):
                pos, res = fut.result()
                results[pos] = res
                completed += 1
                if progress_callback is not None:
                    try:
                        progress_callback(completed, total, domain_list[pos], res)
                    except Exception:
                        pass
    finally:
        for sess in created_sessions:
            try:
                sess.close()
            except Exception:
                pass

    return [r for r in results if r is not None]


def get_domain_image_hash(
    domain: str,
    idx: int = 1,
    total: int = 1,
    ignored_hashes: Mapping[str, str] | None = None,
    *,
    config: ExtractorConfig | None = None,
    session: requests.Session | None = None,
) -> tuple[list[dict[str, str]], int, str | None, list[str], list[dict[str, Any]]]:
    """Legacy 5-tuple wrapper around ``extract_domain_logos``."""
    res = extract_domain_logos(
        domain=domain,
        idx=idx,
        total=total,
        ignored_hashes=ignored_hashes,
        config=config,
        session=session,
    )
    return res.to_legacy_tuple()


def _normalize_domain_cell(raw_val: str) -> str | None:
    cleaned = raw_val.strip()
    if not cleaned:
        return None
    if cleaned.startswith(("#", "//")):
        return None
    # Strip inline comment
    if "#" in cleaned:
        cleaned = cleaned.split("#", 1)[0].strip()
    if not cleaned:
        return None

    lowered = cleaned.lower()
    if lowered in _DOMAIN_HEADER_NAMES:
        return None

    if "://" in cleaned:
        parsed = urllib.parse.urlparse(cleaned)
        host = (parsed.hostname or "").lower().strip().rstrip(".")
        try:
            port = parsed.port
        except ValueError:
            port = None
    else:
        # Strip path/query/fragment if someone passed 'example.com/login'
        host_part = cleaned.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        port = None
        if ":" in host_part:
            host_part, raw_port = host_part.split(":", 1)
            if raw_port.isdigit():
                parsed_port = int(raw_port)
                if 1 <= parsed_port <= 65535:
                    port = parsed_port
        host = host_part.lower().strip().rstrip(".")

    if not host or "." not in host or " " in host:
        return None
    if port is not None and port not in (80, 443):
        return f"{host}:{port}"
    return host


def load_domains_file(file_path: str | os.PathLike[str]) -> list[str]:
    """Load and normalize unique domains from a text or multi-column CSV file."""
    path = Path(file_path).expanduser()
    if not path.is_file():
        logger.warning("Domains file not found: %s", path)
        print(f"[-] Domains file not found: {path}")
        return []

    domains: list[str] = []
    seen: set[str] = set()
    domain_col_idx: int | None = None
    checked_header = False

    try:
        with path.open(mode="r", encoding="utf-8-sig", newline="") as fh:
            filtered_lines = (
                line
                for line in fh
                if line.strip() and not line.lstrip().startswith(("#", "//"))
            )
            reader = csv.reader(filtered_lines)
            for row in reader:
                if not row:
                    continue
                if not checked_header:
                    checked_header = True
                    lowered_cells = [c.strip().lower() for c in row]
                    for preferred in ("domain", "domains", "hostname", "host", "site", "url"):
                        if preferred in lowered_cells:
                            domain_col_idx = lowered_cells.index(preferred)
                            break
                    if domain_col_idx is not None or (
                        len(lowered_cells) == 1 and lowered_cells[0] in _DOMAIN_HEADER_NAMES
                    ):
                        continue
                    if any(cell in _DOMAIN_HEADER_NAMES for cell in lowered_cells):
                        # Multi-column CSV header without 'domain' (e.g. 'name,type,id,...')
                        if "name" in lowered_cells:
                            domain_col_idx = lowered_cells.index("name")
                        continue

                idx = domain_col_idx if domain_col_idx is not None else 0
                if idx >= len(row):
                    continue
                normalized = _normalize_domain_cell(row[idx])
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    domains.append(normalized)
    except Exception as exc:
        logger.warning("Error reading domains file '%s': %s", path, exc)
        print(f"[-] Error reading domains file: {exc}")
        return []

    return domains
