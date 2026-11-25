"""Unit tests for soclens research CLI parsing, negative relative dates, and handlers."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from soclens.cli import _preprocess_negative_args, build_parser, main
from soclens.research import ResearchDossier, ResearchSectionResult, ResolvedTarget


def test_preprocess_negative_args_supports_research_relative_dates() -> None:
    raw = [
        "research",
        "notes",
        "--published",
        "-30d",
        "--limit",
        "10",
    ]
    assert _preprocess_negative_args(raw) == [
        "research",
        "notes",
        "--published=-30d",
        "--limit",
        "10",
    ]

    raw2 = ["research", "investigate", "8.8.8.8", "--links-timeframe", "-14d"]
    assert _preprocess_negative_args(raw2) == [
        "research",
        "investigate",
        "8.8.8.8",
        "--links-timeframe=-14d",
    ]


def test_parser_all_research_subcommands() -> None:
    parser = build_parser()

    inv = parser.parse_args(
        _preprocess_negative_args(
            [
                "research",
                "investigate",
                "APT29",
                "--type",
                "actor",
                "--modules",
                "v2_intel,links",
                "--deep",
                "--links-scope",
                "large",
                "--links-timeframe",
                "-90d",
                "--output",
                "out.md",
                "--json",
            ]
        )
    )
    assert inv.command == "research"
    assert inv.research_subcommand == "investigate"
    assert inv.target == "APT29"
    assert inv.type == "actor"
    assert inv.deep is True
    assert inv.links_timeframe == "-90d"
    assert inv.json is True

    caps = parser.parse_args(["research", "capabilities", "--json"])
    assert caps.research_subcommand == "capabilities"

    links = parser.parse_args(
        _preprocess_negative_args(["research", "links", "ip:8.8.8.8", "--timeframe", "-30d", "--scope", "small"])
    )
    assert links.research_subcommand == "links"
    assert links.timeframe == "-30d"

    notes = parser.parse_args(
        _preprocess_negative_args(["research", "notes", "--published", "-7d", "--topic", "Flash Report"])
    )
    assert notes.published == "-7d"

    actors = parser.parse_args(["research", "actors", "--query", "BlueBravo", "--map"])
    assert actors.map is True

    mal = parser.parse_args(["research", "malware", "--query", "cobalt", "--nl", "--field", "sha256"])
    assert mal.nl is True

    risk = parser.parse_args(
        _preprocess_negative_args(["research", "risk", "--history", "ip:8.8.8.8", "--from", "-30d"])
    )
    assert risk.from_date == "-30d"

    ident = parser.parse_args(["research", "identity", "--domains", "example.com"])
    assert ident.domains == ["example.com"]

    ext = parser.parse_args(["research", "extension", "--list"])
    assert ext.list is True

    rules = parser.parse_args(["research", "rules", "--entity", "O7NRMb", "--types", "sigma,yara"])
    assert rules.types == "sigma,yara"

    ci = parser.parse_args(["research", "collective-insights", "--malware", "Cobalt Strike"])
    assert ci.malware == "Cobalt Strike"

    fusion = parser.parse_args(["research", "fusion", "--ls", "/public"])
    assert fusion.ls == "/public"

    taxii = parser.parse_args(["research", "taxii2", "--collections", "--root", "large"])
    assert taxii.root == "large"

    ato = parser.parse_args(["research", "ato", "--profiles", "detection"])
    assert ato.profiles == "detection"

    sb = parser.parse_args(["research", "sandbox", "--sample-id", "smp1", "--report", "dynamic"])
    assert sb.report == "dynamic"

    asi = parser.parse_args(["research", "asi", "--exposures", "proj1", "--severity", "critical"])
    assert asi.exposures == "proj1"

    pfi = parser.parse_args(["research", "pfi", "--preview", "cards_full"])
    assert pfi.preview == "cards_full"

    rr = parser.parse_args(["research", "riskrecon", "--domain", "example.com"])
    assert rr.domain == "example.com"

    rf_fields = parser.parse_args(["rf", "fields", "ip", "--json"])
    assert rf_fields.rf_subcommand == "fields"

    rf_ext = parser.parse_args(["rf", "extension", "ip", "8.8.8.8", "GreyNoiseIntelligence"])
    assert rf_ext.rf_subcommand == "extension"


def test_main_research_investigate_exports_markdown_and_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mock_client = MagicMock()
    dossier = ResearchDossier(
        target=ResolvedTarget(
            raw_query="8.8.8.8",
            detected_kind="ip",
            entity_id="ip:8.8.8.8",
            canonical_name="8.8.8.8",
            rf_type="IpAddress",
            v2_type="ip",
            v2_lookup_id="8.8.8.8",
        ),
        generated_at="2026-11-24T12:00:00Z",
        risk_score=10,
        sections={
            "v2_intel": ResearchSectionResult(
                key="v2_intel",
                title="Connect v2 Intelligence Card",
                status="ok",
                count=1,
                message="OK",
            )
        },
    )

    md_out = tmp_path / "dossier.md"
    json_out = tmp_path / "dossier.json"

    with (
        patch("soclens.cli.RecordedFutureClient", return_value=mock_client),
        patch("soclens.cli.research_target", return_value=dossier),
    ):
        with patch.object(
            sys,
            "argv",
            ["soclens", "research", "investigate", "8.8.8.8", "--output", str(md_out)],
        ):
            main()
        captured = capsys.readouterr()
        assert md_out.is_file()
        assert "8.8.8.8" in md_out.read_text(encoding="utf-8")
        assert "Dossier written to" in captured.out

        with patch.object(
            sys,
            "argv",
            [
                "soclens",
                "--json",
                "research",
                "investigate",
                "8.8.8.8",
                "--output",
                str(json_out),
            ],
        ):
            main()
        captured_json = capsys.readouterr()
        assert json_out.is_file()
        parsed = json.loads(captured_json.out)
        assert parsed["target"]["entity_id"] == "ip:8.8.8.8"


def test_main_research_direct_surfaces_dispatch(capsys: pytest.CaptureFixture[str]) -> None:
    mock_client = MagicMock()
    mock_client.v2_fields.return_value = {"data": {"results": ["entity", "risk"]}}
    mock_client.v2_lookup_extension.return_value = {"data": {"ok": True}}
    mock_client.links_search.return_value = {"data": []}
    mock_client.search_analyst_notes.return_value = {"data": [{"id": "note:1"}]}
    mock_client.search_threat_actors.return_value = {"data": [{"id": "O7NRMb"}]}
    mock_client.malware_intel_query_nl.return_value = {"data": [{"name": "a" * 64}]}
    mock_client.search_risk_history.return_value = {"data": []}
    mock_client.identity_search.return_value = {"identities": []}
    mock_client.search_detection_rules.return_value = [{"id": "r1"}]
    mock_client.search_collective_insights.return_value = {"data": []}
    mock_client.fusion_list_directory.return_value = {"files": []}
    mock_client.taxii2_discover.return_value = {"title": "TAXII"}
    mock_client.ato_query_profiles.return_value = {"items": []}
    mock_client.sandbox_list_samples.return_value = {"data": []}
    mock_client.asi_list_projects.return_value = {"data": []}
    mock_client.pfi_list_tasks.return_value = {"tasks": []}
    mock_client.riskrecon_list_toes.return_value = []

    with (
        patch("soclens.cli.RecordedFutureClient", return_value=mock_client),
        patch(
            "soclens.cli.probe_api_capabilities",
            return_value=[{"family": "Links Graph", "status": "available", "status_code": 200, "elapsed_ms": 12.0, "detail": "OK"}],
        ),
    ):
        commands = [
            ["soclens", "rf", "fields", "ip"],
            ["soclens", "rf", "extension", "ip", "8.8.8.8", "GreyNoiseIntelligence"],
            ["soclens", "research", "capabilities"],
            ["soclens", "research", "links", "ip:8.8.8.8"],
            ["soclens", "research", "notes", "--published", "-7d"],
            ["soclens", "research", "actors", "--query", "APT29"],
            ["soclens", "research", "malware", "--query", "cobalt", "--nl"],
            ["soclens", "research", "risk", "--history", "ip:8.8.8.8", "--from", "-30d"],
            ["soclens", "research", "identity", "--domains", "example.com"],
            ["soclens", "research", "rules", "--entity", "O7NRMb"],
            ["soclens", "research", "collective-insights"],
            ["soclens", "research", "fusion", "--ls", "/public"],
            ["soclens", "research", "taxii2", "--discover"],
            ["soclens", "research", "ato", "--profiles", "detection"],
            ["soclens", "research", "sandbox", "--list", "org"],
            ["soclens", "research", "asi", "--projects"],
            ["soclens", "research", "pfi", "--tasks"],
            ["soclens", "research", "riskrecon", "--toes"],
        ]
        for argv in commands:
            with patch.object(sys, "argv", argv):
                main()
            capsys.readouterr()

    mock_client.v2_fields.assert_called_once_with("ip")
    mock_client.v2_lookup_extension.assert_called_once()
    mock_client.links_search.assert_called_once()
    mock_client.search_analyst_notes.assert_called_once()
    mock_client.search_threat_actors.assert_called_once()
    mock_client.malware_intel_query_nl.assert_called_once()
    mock_client.search_risk_history.assert_called_once()
    mock_client.identity_search.assert_called_once()
    mock_client.search_detection_rules.assert_called_once()
    mock_client.search_collective_insights.assert_called_once()
    mock_client.fusion_list_directory.assert_called_once_with("/public")
    mock_client.taxii2_discover.assert_called_once()
    mock_client.ato_query_profiles.assert_called_once_with(kind="detection")
    mock_client.sandbox_list_samples.assert_called_once()
    mock_client.asi_list_projects.assert_called_once()
    mock_client.pfi_list_tasks.assert_called_once()
    mock_client.riskrecon_list_toes.assert_called_once()
