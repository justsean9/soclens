"""Frameless Edge/Chrome --app launcher and pure-Python Uvicorn localhost runner."""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

import uvicorn
import uvicorn.lifespan.on as _uvicorn_lifespan_on  # noqa: F401
import uvicorn.loops.asyncio as _uvicorn_loops_asyncio  # noqa: F401
import uvicorn.protocols.http.h11_impl as _uvicorn_h11_impl  # noqa: F401

from soclens.web.app import create_app
from soclens.web.state import WebRuntimeState

EDGE_EXECUTABLES: tuple[str, ...] = (
    "msedge.exe",
    "msedge",
    "microsoft-edge",
    "microsoft-edge-stable",
)

CHROME_EXECUTABLES: tuple[str, ...] = (
    "chrome.exe",
    "google-chrome",
    "chrome",
    "chromium",
    "chromium-browser",
)


def _find_edge_executable() -> str | None:
    for name in EDGE_EXECUTABLES:
        found = shutil.which(name)
        if found:
            return found

    env_roots = (
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("ProgramFiles"),
        os.environ.get("LocalAppData"),
    )
    for root in env_roots:
        if not root:
            continue
        candidate = Path(root) / "Microsoft" / "Edge" / "Application" / "msedge.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def _find_chrome_executable() -> str | None:
    for name in CHROME_EXECUTABLES:
        found = shutil.which(name)
        if found:
            return found

    env_roots = (
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("LocalAppData"),
    )
    for root in env_roots:
        if not root:
            continue
        candidate = Path(root) / "Google" / "Chrome" / "Application" / "chrome.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def launch_app_window(url: str) -> bool:
    """Launch ``url`` in frameless Edge ``--app`` mode, Chrome ``--app``, or default browser."""
    edge_exe = _find_edge_executable()
    if edge_exe:
        try:
            subprocess.Popen(
                [edge_exe, f"--app={url}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except OSError:
            pass

    chrome_exe = _find_chrome_executable()
    if chrome_exe:
        try:
            subprocess.Popen(
                [chrome_exe, f"--app={url}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except OSError:
            pass

    return bool(webbrowser.open(url))


def _validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError(f"Port must be an integer between 0 and 65535 (got {port!r}).")
    if port < 0 or port > 65535:
        raise ValueError(f"Port must be between 0 and 65535 (got {port}).")
    return port


def _validate_loopback_host(host: str) -> str:
    clean = (host or "127.0.0.1").strip()
    if clean not in ("127.0.0.1", "localhost"):
        raise ValueError(f"Refusing to bind non-loopback host {clean!r}; only 127.0.0.1 is allowed.")
    return clean


def run_web_server(
    *,
    port: int = 0,
    open_browser: bool = True,
    admin: bool = False,
    workspace_dir: Path | str | None = None,
    bootstrap_token: str | None = None,
    dry_run: bool = False,
    session_state: Any = None,
    host: str = "127.0.0.1",
    on_ready: Any = None,
) -> int:
    """Run the standalone SOCLens Web ASGI server on loopback until Ctrl+C or shutdown."""
    validated_port = _validate_port(port)
    validated_host = _validate_loopback_host(host)
    token = (bootstrap_token or "").strip() or secrets.token_urlsafe(32)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((validated_host, validated_port))
        sock.listen(128)
        sock.setblocking(False)
        actual_port = int(sock.getsockname()[1])
    except Exception:
        sock.close()
        raise

    app = create_app(
        workspace_dir=workspace_dir,
        admin_enabled=admin,
        bootstrap_token=token,
        session_state=session_state,
        dry_run=dry_run,
        bound_port=actual_port,
    )
    runtime: WebRuntimeState = app.state.runtime

    config = uvicorn.Config(
        app,
        host=validated_host,
        port=actual_port,
        ws="none",
        loop="asyncio",
        http="h11",
        lifespan="on",
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    runtime.server_ref = server

    launch_url = f"http://{validated_host}:{actual_port}/#token={token}"

    def _post_start_notifier() -> None:
        deadline = time.monotonic() + 10.0
        while not server.started and not server.should_exit and time.monotonic() < deadline:
            time.sleep(0.005)
        if server.should_exit or not server.started:
            return
        if callable(on_ready):
            try:
                on_ready(actual_port, launch_url, runtime)
            except Exception:
                pass
        if open_browser:
            launch_app_window(launch_url)

    if open_browser or callable(on_ready):
        notifier = threading.Thread(
            target=_post_start_notifier,
            name="soclens-web-launcher",
            daemon=True,
        )
        notifier.start()

    try:
        server.run(sockets=[sock])
    except KeyboardInterrupt:
        runtime.request_shutdown()
    finally:
        try:
            sock.close()
        except OSError:
            pass
        runtime.cleanup()

    return actual_port
