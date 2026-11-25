"""Textual Pilot TUI tests for Unified RF + Passive OSINT Search & Settings."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from textual.widgets import (
    Checkbox,
    Collapsible,
    ContentSwitcher,
    DataTable,
    Input,
    OptionList,
    RichLog,
    Select,
    Static,
    TabbedContent,
)

import soclens.settings as settings_mod
from soclens.config import OSINTConfig, get_osint_config
from soclens.osint import OSINT_MODULES, OSINT_SOURCES_BY_KEY, OSINTClient, OSINTSectionOutcome
from soclens.tui import create_app
from soclens.tui.modals import OSINTSourcesModal
from soclens.tui.screens.base import extract_richlog_text
from soclens.tui.screens.research import ResearchPane
from soclens.tui.screens.settings import SettingsPane


def _make_fake_osint_client() -> OSINTClient:
    """Build a deterministic offline OSINTClient subclass returning rich fixture outcomes."""

    class _FakeOSINTClient(OSINTClient):
        def enrich_target(
            self,
            target: str,
            kind: str,
            *,
            extracted_domain: str | None = None,
            sources: Any = None,
        ) -> dict[str, OSINTSectionOutcome]:
            _ = extracted_domain
            wanted = set(sources) if sources is not None else set(OSINT_MODULES)
            outcomes: dict[str, OSINTSectionOutcome] = {
                "osint_rdap": OSINTSectionOutcome(
                    key="osint_rdap",
                    title=OSINT_SOURCES_BY_KEY["osint_rdap"].title,
                    status="ok",
                    status_code=200,
                    message="Bulletproof Registrar LLC | Age 5d [NEWLY REGISTERED!]",
                    count=1,
                    elapsed_ms=42.0,
                    data={
                        "object_class": "domain",
                        "queried": target,
                        "name": target,
                        "registrar": "Bulletproof Registrar LLC",
                        "abuse_email": "abuse@registrar.example",
                        "created": "2026-11-20T00:00:00Z",
                        "expires": "2027-11-20T00:00:00Z",
                        "age_days": 5,
                        "age_flag": "newly_registered",
                        "statuses": ["active"],
                        "nameservers": ["ns1.badhost.example"],
                        "contacts": [{"roles": ["registrar"], "name": "Bulletproof Registrar LLC", "email": "abuse@registrar.example"}],
                    },
                ),
                "osint_dns": OSINTSectionOutcome(
                    key="osint_dns",
                    title=OSINT_SOURCES_BY_KEY["osint_dns"].title,
                    status="ok",
                    status_code=200,
                    message="A: 198.51.100.42 | 4 record(s)",
                    count=4,
                    elapsed_ms=18.0,
                    data={
                        "domain": target,
                        "rcode": "NOERROR",
                        "dnssec": False,
                        "a": ["198.51.100.42"],
                        "mx": ["10 mail.badsite.example"],
                        "ns": ["ns1.badhost.example"],
                        "spf": "v=spf1 ip4:198.51.100.42 ~all",
                        "spf_status": "Softfail (~all)",
                        "dmarc": "",
                        "dmarc_policy": "Missing",
                        "records": [{"type": "A", "name": target, "ttl": 120, "value": "198.51.100.42"}],
                    },
                    pivots=[
                        {
                            "entity_id": "ip:198.51.100.42",
                            "name": "198.51.100.42",
                            "entity_type": "IpAddress",
                            "source_section": "osint_dns",
                            "relationship": "DNS A Record",
                            "pivot_kind": "ip",
                        }
                    ],
                ),
                "osint_geoip": OSINTSectionOutcome(
                    key="osint_geoip",
                    title=OSINT_SOURCES_BY_KEY["osint_geoip"].title,
                    status="ok",
                    status_code=200,
                    message="Amsterdam, NL | AS64512 | BadHosting BV",
                    count=1,
                    elapsed_ms=25.0,
                    data={
                        "ip": "198.51.100.42",
                        "resolved_from": target,
                        "country": "Netherlands",
                        "country_code": "NL",
                        "city": "Amsterdam",
                        "asn": "AS64512",
                        "org": "BadHosting BV",
                    },
                ),
                "osint_bgp": OSINTSectionOutcome(
                    key="osint_bgp",
                    title=OSINT_SOURCES_BY_KEY["osint_bgp"].title,
                    status="ok",
                    status_code=200,
                    message="198.51.100.0/24 | AS64512 | BADHOSTING-AS",
                    count=1,
                    elapsed_ms=30.0,
                    data={
                        "mode": "ip",
                        "ip": "198.51.100.42",
                        "resolved_from": target,
                        "prefix": "198.51.100.0/24",
                        "asns": ["AS64512"],
                        "holder": "BADHOSTING-AS",
                        "abuse_contacts": ["abuse@badhosting.example"],
                    },
                ),
                "osint_shodan": OSINTSectionOutcome(
                    key="osint_shodan",
                    title=OSINT_SOURCES_BY_KEY["osint_shodan"].title,
                    status="ok",
                    status_code=200,
                    message="3 port(s) (80, 443, 50050) | 1 CVE(s)",
                    count=3,
                    elapsed_ms=19.0,
                    data={
                        "ip": "198.51.100.42",
                        "resolved_from": target,
                        "ports": [80, 443, 50050],
                        "port_services": [
                            {"port": 80, "service": "HTTP"},
                            {"port": 443, "service": "HTTPS"},
                            {"port": 50050, "service": "CobaltStrike?"},
                        ],
                        "cpes": ["cpe:/a:f5:nginx:1.22"],
                        "vulns": ["CVE-2021-44228"],
                        "hostnames": ["panel.badsite.example"],
                        "tags": ["cloud", "self-signed"],
                    },
                ),
                "osint_crtsh": OSINTSectionOutcome(
                    key="osint_crtsh",
                    title=OSINT_SOURCES_BY_KEY["osint_crtsh"].title,
                    status="ok",
                    status_code=200,
                    message="4 cert(s) | 2 subdomain(s) | Let's Encrypt",
                    count=4,
                    elapsed_ms=50.0,
                    data={
                        "domain": target,
                        "total_certs": 4,
                        "unique_subdomains_count": 2,
                        "subdomains": ["login.badsite.example", "cdn.badsite.example"],
                        "issuers": ["Let's Encrypt"],
                        "recent_certs": [{"common_name": target, "issuer": "Let's Encrypt", "not_before": "2026-11-21", "not_after": "2027-02-19"}],
                    },
                ),
                "osint_urlscan": OSINTSectionOutcome(
                    key="osint_urlscan",
                    title=OSINT_SOURCES_BY_KEY["osint_urlscan"].title,
                    status="ok",
                    status_code=200,
                    message="2 scan(s) | 1 MALICIOUS",
                    count=1,
                    elapsed_ms=48.0,
                    data={
                        "query": f"domain:{target}",
                        "total": 2,
                        "malicious_count": 1,
                        "brands": ["AcmeBank"],
                        "categories": ["phishing"],
                        "scans": [{"time": "2026-11-24T12:00:00Z", "status": 200, "malicious": True, "ip": "198.51.100.42", "country": "NL", "title": "Login Portal"}],
                    },
                ),
                "osint_dshield": OSINTSectionOutcome(
                    key="osint_dshield",
                    title=OSINT_SOURCES_BY_KEY["osint_dshield"].title,
                    status="ok",
                    status_code=200,
                    message="150 report(s) | 40 target(s) attacked",
                    count=150,
                    elapsed_ms=29.0,
                    data={"ip": "198.51.100.42", "count": 150, "attacks": 40, "threatfeeds": ["block"]},
                ),
                "osint_wayback": OSINTSectionOutcome(
                    key="osint_wayback",
                    title=OSINT_SOURCES_BY_KEY["osint_wayback"].title,
                    status="ok",
                    status_code=200,
                    message="1 recent snapshot(s) | Latest: 2026-11-22",
                    count=1,
                    elapsed_ms=33.0,
                    data={"query": target, "snapshot_count": 1, "latest_capture": "2026-11-22T12:00:00Z", "snapshots": [{"date": "2026-11-22T12:00:00Z", "statuscode": "200", "mimetype": "text/html", "archive_url": f"https://web.archive.org/web/20261122/{target}"}]},
                ),
                "osint_otx": OSINTSectionOutcome(
                    key="osint_otx",
                    title=OSINT_SOURCES_BY_KEY["osint_otx"].title,
                    status="ok",
                    status_code=200,
                    message="5 pulse(s) | malware: Cobalt Strike",
                    count=5,
                    elapsed_ms=44.0,
                    data={"indicator": target, "indicator_type": kind, "pulse_count": 5, "malware_families": ["Cobalt Strike"], "pulses": [{"name": "CS Campaign", "modified": "2026-11-24"}], "passive_dns": []},
                ),
                "osint_greynoise": OSINTSectionOutcome(
                    key="osint_greynoise",
                    title=OSINT_SOURCES_BY_KEY["osint_greynoise"].title,
                    status="ok",
                    status_code=200,
                    message="Internet Mass Scanner | MALICIOUS",
                    count=1,
                    elapsed_ms=22.0,
                    data={"ip": "198.51.100.42", "noise": True, "riot": False, "classification": "malicious", "name": "unknown"},
                ),
                "osint_virustotal": OSINTSectionOutcome(
                    key="osint_virustotal",
                    title=OSINT_SOURCES_BY_KEY["osint_virustotal"].title,
                    status="ok",
                    status_code=200,
                    message="12/94 malicious, 1 suspicious",
                    count=13,
                    elapsed_ms=61.0,
                    data={
                        "indicator": target,
                        "kind": kind,
                        "malicious": 12,
                        "suspicious": 1,
                        "harmless": 70,
                        "undetected": 11,
                        "total_engines": 94,
                        "flagging_vendors": [{"engine": "Google Safebrowsing", "category": "malicious", "result": "phishing"}],
                        "gui_url": f"https://www.virustotal.com/gui/domain/{target}",
                    },
                ),
                "osint_abuseipdb": OSINTSectionOutcome(
                    key="osint_abuseipdb",
                    title=OSINT_SOURCES_BY_KEY["osint_abuseipdb"].title,
                    status="not_configured",
                    message="Add free AbuseIPDB API key in Settings (abuseipdb.com/register).",
                ),
                "osint_abusech": OSINTSectionOutcome(
                    key="osint_abusech",
                    title=OSINT_SOURCES_BY_KEY["osint_abusech"].title,
                    status="ok",
                    status_code=200,
                    message="ThreatFox: 1 (Cobalt Strike)",
                    count=1,
                    elapsed_ms=40.0,
                    data={"threatfox": [{"malware_printable": "Cobalt Strike", "threat_type": "botnet_cc", "confidence_level": 100, "tags": ["c2"]}], "urlhaus": {}, "malwarebazaar": []},
                ),
            }
            return {k: v for k, v in outcomes.items() if k in wanted}

    return _FakeOSINTClient(OSINTConfig(enabled=True, vt_api_key="demo-vt-key"))


def _make_mock_rf_client() -> MagicMock:
    rf = MagicMock()
    rf.asi_api_key = None
    rf.riskrecon_token = None
    rf._stop_event = None
    rf.v2_lookup.return_value = {
        "data": {
            "entity": {"id": "idn:badsite.example", "name": "badsite.example", "type": "InternetDomainName"},
            "risk": {
                "score": 89,
                "riskString": "7/99",
                "criticalityLabel": "Very Malicious",
                "riskSummary": "Active phishing and Cobalt Strike staging domain.",
                "evidenceDetails": [
                    {"criticalityLabel": "Very Malicious", "rule": "Active C2 Domain", "evidenceString": "Seen in beacon traffic"}
                ],
            },
            "relatedEntities": [],
        }
    }
    rf.v2_company_by_domain.return_value = {"data": {}}
    rf.soar_enrich.return_value = {"data": {"results": []}}
    rf.links_search.return_value = {"data": []}
    rf.search_analyst_notes.return_value = {
        "data": [
            {
                "id": "note:1",
                "attributes": {"title": "Insikt Report: Badsite Phishing", "published": "2026-11-24T00:00:00Z", "text": "Detail prose", "topic": []},
            }
        ]
    }
    rf.search_detection_rules.return_value = [{"id": "r1", "title": "Badsite DNS Rule", "type": "sigma", "updated": "2026-11-24T00:00:00Z"}]
    rf.malware_intel_query_iocs.return_value = {"data": []}
    rf.search_risk_history.return_value = {"data": []}
    rf.identity_search.return_value = {"identities": []}
    rf.search_alerts_v3.return_value = {"data": []}
    rf.search_playbook_alerts.return_value = {"data": []}
    rf.search_collective_insights.return_value = {"data": []}
    rf.sandbox_search.return_value = {"samples": []}
    return rf


def test_tui_research_unified_rf_and_osint_single_pane_of_glass(tmp_path: Path) -> None:
    rf = _make_mock_rf_client()
    osint = _make_fake_osint_client()
    app = create_app(
        client=rf,
        osint_client=osint,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause()
            pane = app.query_one(ResearchPane)

            # Welcome screen showcases all 16 integrated free OSINT sources
            welcome_text = extract_richlog_text(pane.query_one("#res-detail-log", RichLog))
            assert "Integrated Free Passive OSINT Sources" in welcome_text
            assert "VirusTotal" in welcome_text
            assert "Shodan" in welcome_text

            # Search badsite.example -> unified RF + OSINT findings in one pane of glass!
            pane.query_one("#res-target-input", Input).value = "badsite.example"
            await pilot.click("#res-investigate-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()

            cats = [str(r.get("category")) for r in pane._visible_rows]
            assert cats[0] == "Summary"
            assert "WHOIS" in cats
            assert "DNS" in cats
            assert "Network" in cats
            assert "Certificates" in cats
            assert "Web Intel" in cats
            assert "Reputation" in cats
            assert "Report" in cats
            assert "Rule" in cats
            assert "Sources" in cats

            # Unified Intelligence Brief (Row 0) contains BOTH RF and OSINT data!
            brief_text = extract_richlog_text(pane.query_one("#res-detail-log", RichLog))
            assert "Unified Intelligence Brief: badsite.example" in brief_text
            assert "89/99" in brief_text
            assert "Bulletproof Registrar LLC" in brief_text
            assert "198.51.100.42" in brief_text
            assert "50050" in brief_text
            assert "12/94 malicious" in brief_text
            assert "Source Coverage" in brief_text

            # Step through every OSINT finding row and verify dedicated Rich formatter renders cleanly
            table = pane.query_one("#res-table", DataTable)
            for idx, row in enumerate(pane._visible_rows):
                if row.get("kind") in ("osint_section", "osint_sources"):
                    table.move_cursor(row=idx, column=0, animate=False)
                    await pilot.pause()
                    detail_txt = extract_richlog_text(pane.query_one("#res-detail-log", RichLog))
                    assert len(detail_txt) > 30

            # Filter findings to Free OSINT only vs Recorded Future only
            pane.query_one("#res-options-collapsible", Collapsible).collapsed = False
            await pilot.pause()
            pane.query_one("#res-source-group-filter", Select).value = "osint"
            await pilot.pause()
            assert all(r.get("source_group") in ("osint", "unified") for r in pane._visible_rows)

            pane.query_one("#res-source-group-filter", Select).value = "rf"
            await pilot.pause()
            assert all(r.get("source_group") in ("rf", "unified") for r in pane._visible_rows)

            await pilot.click("#res-clear-filter-btn")
            await pilot.pause()

            # Switch Source Mode to OSINT Only -> runs without calling RF v2_lookup again!
            rf_calls_before = rf.v2_lookup.call_count
            pane.query_one("#res-source-mode", Select).value = "osint"
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert rf.v2_lookup.call_count == rf_calls_before
            assert pane._current_dossier is not None
            assert not pane._current_dossier.rf_sections
            assert pane._current_dossier.osint_sections["osint_rdap"].status == "ok"

            # Switch Source Mode to RF Only -> skips OSINT sections!
            pane.query_one("#res-source-mode", Select).value = "rf"
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane._current_dossier is not None
            assert not pane._current_dossier.osint_sections
            assert pane._current_dossier.risk_score == 89

    asyncio.run(_run())


def test_tui_research_osint_sources_modal_and_settings_jump(tmp_path: Path) -> None:
    rf = _make_mock_rf_client()
    osint = _make_fake_osint_client()
    app = create_app(
        client=rf,
        osint_client=osint,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(ResearchPane)

            # Open OSINT Sources modal via Sources button
            await pilot.click("#res-sources-btn")
            await pilot.pause()
            assert isinstance(app.screen, OSINTSourcesModal)

            # Click No-Key Only -> unchecks free_api_key sources (VirusTotal, AbuseIPDB, abuse.ch)
            await pilot.click("#osint-modal-nokey-btn")
            await pilot.pause()
            assert app.screen.query_one("#osint-src-osint-virustotal", Checkbox).value is False
            assert app.screen.query_one("#osint-src-osint-rdap", Checkbox).value is True
            assert app.screen.query_one("#osint-src-osint-dns", Checkbox).value is True

            await pilot.click("#osint-modal-apply-btn")
            await pilot.pause()
            assert "osint_virustotal" not in pane._enabled_osint_sources
            assert "osint_dns" in pane._enabled_osint_sources

            # Reopen modal and jump directly to Settings -> OSINT Free API Keys
            await pilot.click("#res-sources-btn")
            await pilot.pause()
            assert isinstance(app.screen, OSINTSourcesModal)
            await pilot.click("#osint-modal-settings-btn")
            await pilot.pause()

            assert app.query_one("#main-tabs", TabbedContent).active == "tab-settings"
            assert app.query_one("#settings-category-switcher", ContentSwitcher).current == "cat-osint"

    asyncio.run(_run())


def test_tui_settings_osint_category_save_mask_and_test(tmp_path: Path) -> None:
    app = create_app(
        client=MagicMock(),
        dry_run=True,
        initial_tab="tab-settings",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(130, 40)) as pilot:
            await pilot.pause()
            pane = app.query_one(SettingsPane)
            cat_list = pane.query_one("#settings-category-list", OptionList)
            cat_list.highlighted = 7
            await pilot.pause()
            assert pane.query_one("#settings-category-switcher", ContentSwitcher).current == "cat-osint"

            vt_inp = pane.query_one("#set-osint-vt-key", Input)
            ab_inp = pane.query_one("#set-osint-abuseipdb-key", Input)
            assert vt_inp.password is True
            assert ab_inp.password is True

            # Show Secrets toggles password masking on OSINT keys
            pane.query_one("#settings-show-secrets", Checkbox).value = True
            await pilot.pause()
            assert vt_inp.password is False
            assert ab_inp.password is False
            pane.query_one("#settings-show-secrets", Checkbox).value = False
            await pilot.pause()
            assert vt_inp.password is True

            # Enter free keys + enable OSINT + Save
            pane.query_one("#set-osint-enabled", Checkbox).value = True
            vt_inp.value = "free-vt-key-999"
            ab_inp.value = "free-abuseipdb-key-888"
            await pilot.click("#settings-save-btn")
            await pilot.pause()

            saved = settings_mod.get_profile_settings()
            assert saved["osint_vt_api_key"] == "free-vt-key-999"
            assert saved["osint_abuseipdb_api_key"] == "free-abuseipdb-key-888"
            cfg = get_osint_config()
            assert cfg.vt_api_key == "free-vt-key-999"
            assert cfg.abuseipdb_api_key == "free-abuseipdb-key-888"

            # Test Free OSINT Sources button
            with patch("soclens.tui.screens.settings.OSINTClient.test_connectivity") as mock_conn:
                mock_conn.return_value = {
                    "ok": True,
                    "doh_status": "ok",
                    "shodan_status": "ok",
                    "ready_sources": 15,
                    "total_sources": 16,
                    "configured_keys": 2,
                }
                pane.query_one("#settings-test-osint-btn").scroll_visible(animate=False)
                await pilot.pause()
                await pilot.click("#settings-test-osint-btn")
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                status_text = str(pane.query_one("#settings-status", Static).content)
                assert "OSINT OK" in status_text
                assert "15/16" in status_text

    asyncio.run(_run())


def test_tui_research_narrow_80x24_responsive_layout(tmp_path: Path) -> None:
    rf = _make_mock_rf_client()
    osint = _make_fake_osint_client()
    app = create_app(
        client=rf,
        osint_client=osint,
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            pane = app.query_one(ResearchPane)
            assert app.screen.has_class("-compact-narrow")
            assert not pane.query_one("#res-workspace").has_class("split-horizontal")

            pane.query_one("#res-target-input", Input).value = "badsite.example"
            await pilot.click("#res-investigate-btn")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane._current_dossier is not None
            assert len(pane._visible_rows) >= 5

            await pilot.resize_terminal(140, 40)
            await pilot.pause()
            assert pane.query_one("#res-workspace").has_class("split-horizontal")

    asyncio.run(_run())
