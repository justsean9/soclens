"""Modular workflow panes for the SOCLens Textual TUI."""

from __future__ import annotations

from soclens.tui.screens.brand_logos import BrandLogosPane
from soclens.tui.screens.dashboard import DashboardPane
from soclens.tui.screens.llm import LocalLLMPane
from soclens.tui.screens.logs import LogsPane
from soclens.tui.screens.research import ResearchPane
from soclens.tui.screens.rf_intel import RFIntelPane
from soclens.tui.screens.sentinelone import SentinelOnePane
from soclens.tui.screens.settings import SettingsPane
from soclens.tui.screens.sigma import SigmaPane
from soclens.tui.screens.splunk_bundle import SplunkBundlePane
from soclens.tui.screens.splunk_es import SplunkESPane
from soclens.tui.screens.splunk_search import SplunkSearchPane
from soclens.tui.screens.watchlists import WatchlistsPane

__all__ = [
    "BrandLogosPane",
    "DashboardPane",
    "LocalLLMPane",
    "LogsPane",
    "RFIntelPane",
    "ResearchPane",
    "SentinelOnePane",
    "SettingsPane",
    "SigmaPane",
    "SplunkBundlePane",
    "SplunkESPane",
    "SplunkSearchPane",
    "WatchlistsPane",
]
