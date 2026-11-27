"""Zero-EXE standalone tiling Web UI backend and frameless launcher for SOCLens."""

from soclens.web.app import create_app
from soclens.web.launcher import launch_app_window, run_web_server

__all__ = [
    "create_app",
    "launch_app_window",
    "run_web_server",
]
