"""Tests for the Research animated mood art banner."""

from __future__ import annotations

import asyncio

import pytest

from soclens.research import ResearchDossier, ResearchSectionResult, ResolvedTarget
from soclens.tui.app import SocLensApp
from soclens.tui.research_art import (
    ResearchMoodBanner,
    determine_research_mood,
    render_mood_caption,
    render_mood_frame,
)


def _make_dossier(
    *,
    name: str = "example.com",
    kind: str = "domain",
    risk_score: int | None = None,
    verdict_level: str | None = None,
) -> ResearchDossier:
    target = ResolvedTarget(raw_query=name, canonical_name=name, detected_kind=kind, entity_id=None)
    dossier = ResearchDossier(target=target, generated_at="2026-11-25T00:00:00Z", risk_score=risk_score)
    if verdict_level is not None:
        dossier.unified_verdict = {
            "level": verdict_level,
            "label": verdict_level.upper(),
            "signals": [{"source": "Test", "severity": verdict_level, "text": f"Level {verdict_level}"}],
        }
    return dossier


def test_determine_research_mood_states() -> None:
    assert determine_research_mood(None).kind == "idle"
    assert determine_research_mood(None, searching=True, query="8.8.8.8").kind == "searching"
    assert determine_research_mood(None, error="timeout").kind == "error"

    high_rf = _make_dossier(name="evil.example", risk_score=85)
    assert determine_research_mood(high_rf).kind == "high_risk"

    high_osint = _make_dossier(name="bad.example", risk_score=None, verdict_level="critical")
    assert determine_research_mood(high_osint).kind == "high_risk"

    med = _make_dossier(name="meh.example", risk_score=42)
    assert determine_research_mood(med).kind == "medium_risk"

    low_rf = _make_dossier(name="good.example", risk_score=5)
    low_mood = determine_research_mood(low_rf)
    assert low_mood.kind == "low_risk"
    assert "PONY" in low_mood.title

    benign = _make_dossier(name="clean.example", risk_score=None, verdict_level="benign")
    assert determine_research_mood(benign).kind == "low_risk"

    unknown = _make_dossier(name="mystery.example", risk_score=None, verdict_level="unknown")
    assert determine_research_mood(unknown).kind == "unknown"


def test_mood_frames_animate_and_are_four_lines() -> None:
    for kind in ("idle", "searching", "high_risk", "medium_risk", "low_risk", "unknown", "error"):
        f0 = render_mood_frame(kind, 0)
        f1 = render_mood_frame(kind, 1)
        assert len(f0.plain.splitlines()) == 4
        assert len(f1.plain.splitlines()) == 4
        assert f0.plain != f1.plain

    high_text = render_mood_frame("high_risk", 0)
    assert any("red" in str(span.style) for span in high_text.spans)

    cap = render_mood_caption(determine_research_mood(_make_dossier(risk_score=0)), 0)
    assert "HAPPY PONY" in cap.plain


def test_research_pane_mood_banner_reacts_to_dossier(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    high_dossier = _make_dossier(name="198.51.100.99", kind="ip", risk_score=92, verdict_level="critical")
    low_dossier = _make_dossier(name="1.1.1.1", kind="ip", risk_score=0, verdict_level="benign")
    low_dossier.sections["osint_virustotal"] = ResearchSectionResult(
        key="osint_virustotal",
        title="VirusTotal",
        status="ok",
        message="0/90 malicious",
        data={"malicious": 0, "suspicious": 0, "total_engines": 90},
        source_group="osint",
    )

    state = {"dossier": high_dossier}

    def _fake_research_target(*args, **kwargs):
        return state["dossier"]

    monkeypatch.setattr("soclens.tui.screens.research.research_target", _fake_research_target)

    async def _run() -> None:
        app = SocLensApp(workspace_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            banner = app.query_one("#res-mood-strip", ResearchMoodBanner)
            assert banner.mood.kind == "idle"
            start_frame = banner.frame_index
            await asyncio.sleep(0.45)
            await pilot.pause()
            assert banner.frame_index > start_frame

            pane = app.query_one("ResearchPane")
            pane._apply_dossier(high_dossier)
            await pilot.pause()
            assert banner.mood.kind == "high_risk"

            pane._apply_dossier(low_dossier)
            await pilot.pause()
            assert banner.mood.kind == "low_risk"
            assert "PONY" in banner.mood.title

    asyncio.run(_run())
