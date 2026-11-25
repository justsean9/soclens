"""Animated ASCII/Unicode mood art for the Threat Research workbench."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from rich.text import Text
from textual.containers import Horizontal
from textual.timer import Timer
from textual.widgets import Static

from soclens.research import ResearchDossier, compute_unified_verdict
from soclens.settings import get_setting_with_source

ASCII_ART_AUTO_HIDE_SECONDS: float = 10.0
BANNER_AUTO_HIDE_SECONDS: float = ASCII_ART_AUTO_HIDE_SECONDS
_TRUTHY_STRINGS: frozenset[str] = frozenset({"1", "true", "yes", "on"})


def is_ascii_art_enabled() -> bool:
    """Return True when the user has unlocked the ASCII art banner in Settings."""
    raw, _src = get_setting_with_source("soclens_ascii_art_enabled")
    if raw is None:
        return False
    return str(raw).strip().lower() in _TRUTHY_STRINGS

MoodKind = Literal[
    "idle",
    "searching",
    "high_risk",
    "medium_risk",
    "low_risk",
    "unknown",
    "error",
]


@dataclass(slots=True)
class ResearchMood:
    """Computed mood state for the Research animated art banner."""

    kind: MoodKind
    title: str
    subtitle: str
    detail: str
    accent_style: str
    score: int | None = None
    art_title: str | None = None


# Each sprite frame is a list of 4 lines; each line is a list of (text, style) tuples.
_SpriteLine = list[tuple[str, str]]
_SpriteFrame = list[_SpriteLine]

_HIGH_RISK_FRAMES: list[_SpriteFrame] = [
    [
        [("  ~ ", "dark_red"), ("/\\___/\\", "bold red"), (" ~   ", "dark_red"), ("*", "bright_yellow")],
        [(" ( ", "bold red"), ("◉", "bold bright_yellow"), ("   ", "bold red"), ("◉", "bold bright_yellow"), (" ) ", "bold red"), ("~", "red")],
        [("<  \\ ", "red"), ("▼▼▼", "bold bright_white"), (" /  >", "red")],
        [(" '==", "dark_red"), ("═════", "bold red"), ("==' ", "dark_red"), ("!", "bold bright_red")],
    ],
    [
        [(" *  ", "bright_red"), ("/\\___/\\", "bold bright_red"), ("  ~  ", "red"), (" ", "red")],
        [(" ( ", "bold bright_red"), ("◎", "bold bright_red"), ("   ", "bold bright_red"), ("◎", "bold bright_red"), (" ) ", "bold bright_red"), ("*", "bright_yellow")],
        [("<  \\ ", "bold red"), ("▲▲▲", "bold bright_white"), (" /  >", "bold red")],
        [(" '==", "red"), ("═════", "bold bright_red"), ("==' ", "red"), ("!!", "bold bright_red")],
    ],
    [
        [("  ~ ", "red"), ("/\\___/\\", "bold red"), ("  *  ", "bright_yellow"), ("~", "dark_red")],
        [(" ( ", "bold red"), ("◉", "bold bright_yellow"), ("   ", "bold red"), ("◉", "bold bright_yellow"), (" ) ", "bold red"), (" ", "red")],
        [("<< \\ ", "bold bright_red"), ("▼▼▼", "bold bright_white"), (" / >>", "bold bright_red")],
        [(" '==", "dark_red"), ("═════", "bold red"), ("==' ", "dark_red"), ("!", "bold bright_red")],
    ],
    [
        [(" ^  ", "dark_red"), ("/\\___/\\", "bold bright_red"), ("  ^  ", "dark_red"), ("*", "bright_red")],
        [(" ( ", "bold bright_red"), ("◉", "bold red"), ("   ", "bold bright_red"), ("◉", "bold red"), (" ) ", "bold bright_red"), ("~", "bright_red")],
        [("<  \\ ", "red"), ("▲▼▲", "bold bright_white"), (" /  >", "red")],
        [(" '==", "red"), ("═════", "bold bright_red"), ("==' ", "red"), ("!", "bold yellow")],
    ],
]

_LOW_RISK_FRAMES: list[_SpriteFrame] = [
    [
        [("     ,_   ", "bright_magenta"), ("*   ", "bright_yellow"), ("✦", "bright_cyan")],
        [("~==", "bright_magenta"), ("( ^.^)", "bold bright_white"), ("> ", "bright_magenta"), ("♥", "bright_red")],
        [("  /(  )\\", "bold bright_green"), ("~ ", "bright_cyan"), ("*", "bright_yellow")],
        [("  /|  |\\  ", "bright_green"), ("~", "bright_cyan")],
    ],
    [
        [("  *  ", "bright_yellow"), (",_   ", "bright_magenta"), ("✦   ", "bright_cyan"), ("*", "bright_green")],
        [("~==", "bright_cyan"), ("( ^.^)", "bold bright_white"), ("> ", "bright_magenta"), (" ", "white")],
        [("  /(  )\\", "bold bright_green"), ("~ ", "bright_magenta"), ("♥", "bright_red")],
        [("  /   /\\  ", "bright_green"), ("✦", "bright_yellow")],
    ],
    [
        [("     ,_   ", "bright_cyan"), ("✦   ", "bright_yellow"), ("*", "bright_magenta")],
        [("~~=", "bright_magenta"), ("( ^o^)", "bold bright_white"), ("> ", "bright_cyan"), ("*", "bright_yellow")],
        [("  /(  )\\", "bold bright_green"), ("~ ", "bright_yellow"), ("♥", "bright_red")],
        [("  \\   \\/  ", "bright_green"), (" ", "white")],
    ],
    [
        [("  ✦  ", "bright_cyan"), (",_   ", "bright_magenta"), ("*   ", "bright_yellow"), ("♥", "bright_red")],
        [("~==", "bright_magenta"), ("( ^.^)", "bold bright_white"), ("> ", "bright_cyan"), ("*", "bright_green")],
        [("  /(  )\\", "bold bright_green"), ("~ ", "bright_cyan"), ("✦", "bright_yellow")],
        [("  /|  |\\  ", "bright_green"), ("~", "bright_magenta")],
    ],
]

_MEDIUM_RISK_FRAMES: list[_SpriteFrame] = [
    [
        [("   .----.   ", "yellow"), ("?", "bold bright_yellow")],
        [("  ( ", "yellow"), ("o", "bold bright_yellow"), ("  ", "yellow"), ("o", "bold bright_yellow"), (" ) ", "yellow")],
        [("  /| == |\\  ", "orange1")],
        [("  '------'  ", "dark_orange")],
    ],
    [
        [("   .----.   ", "orange1"), (" ", "yellow")],
        [("  ( ", "yellow"), ("-", "bold bright_yellow"), ("  ", "yellow"), ("-", "bold bright_yellow"), (" ) ", "yellow"), ("?", "yellow")],
        [("  /| == |\\  ", "yellow")],
        [("  '------'  ", "orange1")],
    ],
    [
        [("   .----.   ", "yellow"), ("!", "bold yellow")],
        [("  ( ", "orange1"), ("o", "bold bright_yellow"), ("  ", "orange1"), ("O", "bold bright_yellow"), (" ) ", "orange1")],
        [("  \\| == |/  ", "yellow")],
        [("  '------'  ", "dark_orange")],
    ],
    [
        [("   .----.   ", "yellow"), (" ", "yellow")],
        [("  ( ", "yellow"), ("O", "bold bright_yellow"), ("  ", "yellow"), ("o", "bold bright_yellow"), (" ) ", "yellow"), ("~", "orange1")],
        [("  /| == |\\  ", "orange1")],
        [("  '------'  ", "yellow")],
    ],
]

_SEARCHING_FRAMES: list[_SpriteFrame] = [
    [
        [("   .─", "cyan"), ("|", "bold bright_cyan"), ("─.    ", "cyan"), ("*", "bright_cyan")],
        [("  ( ( ", "bright_cyan"), ("◉", "bold bright_white"), (" ) ) ", "bright_cyan")],
        [("   '─", "cyan"), ("|", "bold bright_cyan"), ("─'    ", "cyan")],
        [("   /|\\     ", "dim cyan"), ("...", "bright_cyan")],
    ],
    [
        [("   .─", "cyan"), ("/", "bold bright_cyan"), ("─.    ", "cyan"), (" ", "cyan")],
        [("  (  ", "cyan"), ("◎", "bold bright_cyan"), ("  )  ", "cyan"), ("*", "bright_white")],
        [("   '─", "cyan"), ("/", "bold bright_cyan"), ("─'    ", "cyan")],
        [("   /|\\     ", "dim cyan"), (".. ", "cyan")],
    ],
    [
        [("   .─", "bright_cyan"), ("─", "bold bright_white"), ("─.    ", "bright_cyan"), ("*", "cyan")],
        [("  ( ( ", "cyan"), ("◉", "bold bright_cyan"), (" ) ) ", "cyan")],
        [("   '─", "bright_cyan"), ("─", "bold bright_white"), ("─'    ", "bright_cyan")],
        [("   /|\\     ", "dim cyan"), ("...", "bright_cyan")],
    ],
    [
        [("   .─", "cyan"), ("\\", "bold bright_cyan"), ("─.    ", "cyan"), (" ", "cyan")],
        [("  (  ", "bright_cyan"), ("◎", "bold bright_white"), ("  )  ", "bright_cyan"), ("*", "cyan")],
        [("   '─", "cyan"), ("\\", "bold bright_cyan"), ("─'    ", "cyan")],
        [("   /|\\     ", "dim cyan"), (".  ", "dim cyan")],
    ],
]

_IDLE_FRAMES: list[_SpriteFrame] = [
    [
        [("   ,___,   ", "cyan")],
        [("   (", "cyan"), ("o.o", "bold bright_white"), (")  ", "cyan")],
        [("   /)  )   ", "dim cyan")],
        [("   \"  \"    ", "dim")],
    ],
    [
        [("   ,___,   ", "cyan")],
        [("   (", "cyan"), ("o.o", "bold bright_white"), (")  ", "cyan"), ("·", "dim cyan")],
        [("   /)  )   ", "dim cyan")],
        [("   \"  \"    ", "dim")],
    ],
    [
        [("   ,___,   ", "cyan")],
        [("   (", "cyan"), ("-.-", "dim white"), (")  ", "cyan")],
        [("   /)  )   ", "dim cyan")],
        [("   \"  \"    ", "dim")],
    ],
    [
        [("   ,___,   ", "cyan")],
        [("   (", "cyan"), ("o.o", "bold bright_white"), (")  ", "cyan")],
        [("   /)  )   ", "dim cyan")],
        [("   \"  \"    ", "dim")],
    ],
]

_UNKNOWN_FRAMES: list[_SpriteFrame] = [
    [
        [("   ,___,   ", "sky_blue1")],
        [("   (", "sky_blue1"), ("?.?", "bold bright_white"), (")  ", "sky_blue1")],
        [("   /)  )   ", "dim cyan")],
        [("   \"  \"    ", "dim")],
    ],
    [
        [("   ,___,   ", "sky_blue1"), ("?", "dim cyan")],
        [("   (", "sky_blue1"), ("o.o", "bold bright_white"), (")  ", "sky_blue1")],
        [("   /)  )   ", "dim cyan")],
        [("   \"  \"    ", "dim")],
    ],
]

_ERROR_FRAMES: list[_SpriteFrame] = [
    [
        [("   /\\     ", "bold yellow")],
        [("  /!!\\    ", "bold bright_red")],
        [(" /____\\   ", "yellow")],
        [(" [ERR]    ", "bold red")],
    ],
    [
        [("   /\\     ", "yellow")],
        [("  /  \\    ", "bold yellow")],
        [(" /____\\   ", "bold red")],
        [(" [ERR]    ", "dim red")],
    ],
]

_FRAMES_BY_MOOD: dict[MoodKind, list[_SpriteFrame]] = {
    "high_risk": _HIGH_RISK_FRAMES,
    "low_risk": _LOW_RISK_FRAMES,
    "medium_risk": _MEDIUM_RISK_FRAMES,
    "searching": _SEARCHING_FRAMES,
    "idle": _IDLE_FRAMES,
    "unknown": _UNKNOWN_FRAMES,
    "error": _ERROR_FRAMES,
}


def determine_research_mood(
    dossier: ResearchDossier | None,
    *,
    searching: bool = False,
    query: str = "",
    error: str | None = None,
    source_desc: str | None = None,
) -> ResearchMood:
    """Map current Research state or dossier risk/verdict into a ``ResearchMood``."""
    if searching:
        target = query.strip() or "target"
        sources_label = (source_desc or "Recorded Future + Passive OSINT").strip()
        return ResearchMood(
            kind="searching",
            title="SCANNING...",
            subtitle=f"Investigating {target}",
            detail=f"Querying {sources_label} sources",
            accent_style="bold bright_cyan",
        )

    if error:
        return ResearchMood(
            kind="error",
            title="SEARCH ERROR",
            subtitle=error[:72],
            detail="Check logs or source configuration and retry",
            accent_style="bold yellow",
        )

    if dossier is None:
        return ResearchMood(
            kind="idle",
            title="RESEARCH READY",
            subtitle="Search any IP, domain, hash, URL, CVE, actor, or topic",
            detail="Initial risk & unified verdict summary appears during search",
            accent_style="bold cyan",
        )

    verdict = dossier.unified_verdict or compute_unified_verdict(dossier)
    level = str(verdict.get("level") or "unknown").lower()
    score = dossier.risk_score
    target_name = dossier.target.canonical_name
    signals = verdict.get("signals") or []
    signal_parts: list[str] = []
    for sig in signals:
        if not isinstance(sig, dict):
            continue
        src = str(sig.get("source") or "").strip()
        txt = str(sig.get("text") or "").strip()
        formatted = f"{src}: {txt}".strip(": ")
        if formatted:
            signal_parts.append(formatted)
        if len(signal_parts) >= 2:
            break
    if signal_parts:
        top_signal = "  |  ".join(signal_parts)
        if len(top_signal) > 120:
            top_signal = top_signal[:117].rstrip() + "..."
    elif verdict.get("summary"):
        top_signal = str(verdict["summary"])
    else:
        top_signal = ""

    score_text = f"RF Risk {score}/99" if score is not None else f"Verdict: {verdict.get('label', level.upper())}"

    if level in ("critical", "high") or (score is not None and score >= 65):
        return ResearchMood(
            kind="high_risk",
            title="HIGH RISK ALERT!" if level != "critical" else "CRITICAL THREAT!",
            subtitle=f"{target_name}  |  {score_text}",
            detail=top_signal or "Malicious / high-confidence threat indicators detected",
            accent_style="bold bright_red",
            score=score,
        )

    if level == "medium" or (score is not None and score >= 25):
        return ResearchMood(
            kind="medium_risk",
            title="SUSPICIOUS / MEDIUM",
            subtitle=f"{target_name}  |  {score_text}",
            detail=top_signal or "Moderate risk or mixed reputation signals",
            accent_style="bold yellow",
            score=score,
        )

    if level in ("benign", "low") or (score is not None and score < 25):
        return ResearchMood(
            kind="low_risk",
            title="LOW RISK",
            art_title="HAPPY PONY — LOW RISK!",
            subtitle=f"{target_name}  |  {score_text}",
            detail=top_signal or "No significant malicious indicators found",
            accent_style="bold bright_green",
            score=score,
        )

    return ResearchMood(
        kind="unknown",
        title="INFORMATIONAL",
        subtitle=f"{target_name}  |  No Risk Score",
        detail=top_signal or "Context gathered; no scored threat indicators",
        accent_style="bold sky_blue1",
        score=score,
    )


def render_mood_frame(kind: MoodKind, frame_index: int) -> Text:
    """Render a 4-line animated Rich ``Text`` sprite for ``kind`` at ``frame_index``."""
    frames = _FRAMES_BY_MOOD.get(kind, _IDLE_FRAMES)
    frame = frames[frame_index % len(frames)]
    out = Text()
    for line_idx, segments in enumerate(frame):
        if line_idx > 0:
            out.append("\n")
        for chunk, style in segments:
            out.append(chunk, style=style)
    return out


def render_mood_caption(mood: ResearchMood, frame_index: int, *, include_art: bool = False) -> Text:
    """Render the companion status caption (optionally with art-mode title)."""
    pulse_chars = ("●", "◉", "○", "◉")
    pulse = pulse_chars[frame_index % len(pulse_chars)]
    display_title = mood.art_title if (include_art and mood.art_title) else mood.title
    out = Text()
    out.append(f"{pulse} ", style=mood.accent_style)
    out.append(display_title, style=mood.accent_style)
    out.append("\n")
    out.append(mood.subtitle, style="bold white")
    out.append("\n")
    out.append(mood.detail, style="dim")
    return out


class ResearchMoodBanner(Horizontal):
    """Status/initial-thoughts banner for the Research pane.

    Shows live search progress transitioning into initial threat thoughts and
    automatically hides after ``AUTO_HIDE_SECONDS`` (10s). Animated ASCII art
    is omitted by default unless ``soclens_ascii_art_enabled`` is unlocked in Settings.
    """

    AUTO_HIDE_SECONDS: float = ASCII_ART_AUTO_HIDE_SECONDS

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._mood: ResearchMood = determine_research_mood(None)
        self._frame_index: int = 0
        self._timer: Timer | None = None
        self._hide_timer: Timer | None = None
        self.display = False

    @property
    def mood(self) -> ResearchMood:
        return self._mood

    @property
    def frame_index(self) -> int:
        return self._frame_index

    def compose(self):  # type: ignore[override]
        yield Static("", id="res-mood-art", markup=False)
        yield Static("", id="res-mood-caption", markup=False)

    def on_mount(self) -> None:
        self._render_current()
        if self._mood.kind == "searching":
            self._show_searching()
        elif self._mood.kind != "idle":
            self._show_temporarily()
        else:
            self._hide_now()

    def on_unmount(self) -> None:
        self._stop_timers()

    def _stop_timers(self) -> None:
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        if self._hide_timer is not None:
            self._hide_timer.stop()
            self._hide_timer = None

    def _start_pulse(self) -> None:
        if self._timer is None:
            self._timer = self.set_interval(0.35, self._on_tick)

    def _hide_now(self) -> None:
        self._stop_timers()
        self.display = False

    def _show_searching(self) -> None:
        if not self.is_mounted:
            return
        if self._hide_timer is not None:
            self._hide_timer.stop()
            self._hide_timer = None
        self.display = True
        self._render_current()
        self._start_pulse()

    def _show_temporarily(self) -> None:
        if not self.is_mounted:
            return
        self.display = True
        self._render_current()
        self._start_pulse()
        if self._hide_timer is not None:
            self._hide_timer.stop()
        self._hide_timer = self.set_timer(self.AUTO_HIDE_SECONDS, self._hide_now)

    def sync_ascii_art_setting(self) -> None:
        """Apply live changes to the Settings ASCII art toggle."""
        if not self.is_mounted:
            return
        show_art = is_ascii_art_enabled()
        self._render_current()
        if show_art and not self.display and self._mood.kind != "idle":
            self._show_temporarily()

    def set_mood(self, mood: ResearchMood) -> None:
        """Update the displayed mood: stay visible while searching, then auto-hide after 10s."""
        if mood.kind != self._mood.kind:
            self._frame_index = 0
        self._mood = mood
        if not self.is_mounted:
            return
        if mood.kind == "idle":
            self._hide_now()
        elif mood.kind == "searching":
            self._show_searching()
        else:
            self._show_temporarily()

    def _on_tick(self) -> None:
        if not self.is_mounted or not self.display:
            return
        self._frame_index = (self._frame_index + 1) % 120
        self._render_current()

    def _render_current(self) -> None:
        show_art = is_ascii_art_enabled()
        self.set_class(show_art, "-ascii-art")
        art = self.query_one("#res-mood-art", Static)
        caption = self.query_one("#res-mood-caption", Static)
        art.display = show_art
        if show_art:
            art.update(render_mood_frame(self._mood.kind, self._frame_index))
        else:
            art.update("")
        caption.update(render_mood_caption(self._mood, self._frame_index, include_art=show_art))
