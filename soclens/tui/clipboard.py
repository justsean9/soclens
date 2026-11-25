"""Cross-platform OS clipboard and Textual OSC 52 copy/paste utilities."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

_CLIPBOARD_TIMEOUT_SECONDS: float = 2.0


@dataclass(frozen=True)
class ClipboardResult:
    """Outcome of a clipboard copy attempt."""

    success: bool
    method: str
    char_count: int
    error: str | None = None


def _resolve_copy_commands() -> list[tuple[str, list[str]]]:
    """Return ordered (label, argv) native copy commands for the current platform."""
    if sys.platform == "win32":
        cmds: list[tuple[str, list[str]]] = []
        clip_bin = shutil.which("clip.exe") or shutil.which("clip")
        if clip_bin:
            cmds.append(("clip.exe", [clip_bin]))
        ps_bin = shutil.which("powershell") or shutil.which("pwsh")
        if ps_bin:
            cmds.append(
                (
                    "powershell",
                    [
                        ps_bin,
                        "-NoProfile",
                        "-Command",
                        "Set-Clipboard -Value ([Console]::In.ReadToEnd())",
                    ],
                )
            )
        return cmds

    if sys.platform == "darwin":
        pbcopy_bin = shutil.which("pbcopy")
        return [("pbcopy", [pbcopy_bin])] if pbcopy_bin else []

    cmds = []
    if os.environ.get("WAYLAND_DISPLAY"):
        wl_copy = shutil.which("wl-copy")
        if wl_copy:
            cmds.append(("wl-copy", [wl_copy]))
    xclip_bin = shutil.which("xclip")
    if xclip_bin:
        cmds.append(("xclip", [xclip_bin, "-selection", "clipboard"]))
    xsel_bin = shutil.which("xsel")
    if xsel_bin:
        cmds.append(("xsel", [xsel_bin, "--clipboard", "--input"]))
    return cmds


def _resolve_paste_commands() -> list[tuple[str, list[str]]]:
    """Return ordered (label, argv) native paste commands for the current platform."""
    if sys.platform == "win32":
        ps_bin = shutil.which("powershell") or shutil.which("pwsh")
        if ps_bin:
            return [("powershell", [ps_bin, "-NoProfile", "-Command", "Get-Clipboard"])]
        return []

    if sys.platform == "darwin":
        pbpaste_bin = shutil.which("pbpaste")
        return [("pbpaste", [pbpaste_bin])] if pbpaste_bin else []

    cmds: list[tuple[str, list[str]]] = []
    if os.environ.get("WAYLAND_DISPLAY"):
        wl_paste = shutil.which("wl-paste")
        if wl_paste:
            cmds.append(("wl-paste", [wl_paste, "--no-newline"]))
    xclip_bin = shutil.which("xclip")
    if xclip_bin:
        cmds.append(("xclip", [xclip_bin, "-selection", "clipboard", "-o"]))
    xsel_bin = shutil.which("xsel")
    if xsel_bin:
        cmds.append(("xsel", [xsel_bin, "--clipboard", "--output"]))
    return cmds


def copy_text_to_clipboard(text: str, app: Any = None) -> ClipboardResult:
    """Copy ``text`` via native OS clipboard tools and/or Textual OSC 52.

    Never raises unhandled exceptions; returns a structured ``ClipboardResult``.
    """
    char_count = len(text)
    native_method: str | None = None
    osc52_ok = False
    errors: list[str] = []

    for label, cmd in _resolve_copy_commands():
        try:
            proc = subprocess.run(
                cmd,
                input=text,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=_CLIPBOARD_TIMEOUT_SECONDS,
                check=False,
            )
            if proc.returncode == 0:
                native_method = label
                break
            stderr_msg = (proc.stderr or "").strip()
            errors.append(
                f"{label} exited {proc.returncode}"
                + (f": {stderr_msg}" if stderr_msg else "")
            )
        except Exception as exc:
            errors.append(f"{label}: {exc}")

    if app is not None:
        osc52_fn = getattr(app, "copy_to_clipboard", None)
        if callable(osc52_fn):
            try:
                osc52_fn(text)
                osc52_ok = True
            except Exception as exc:
                errors.append(f"osc52: {exc}")

    if native_method and osc52_ok:
        return ClipboardResult(
            success=True,
            method=f"{native_method}+osc52",
            char_count=char_count,
            error=None,
        )
    if native_method:
        return ClipboardResult(
            success=True,
            method=native_method,
            char_count=char_count,
            error=None,
        )
    if osc52_ok:
        return ClipboardResult(
            success=True,
            method="osc52",
            char_count=char_count,
            error=None,
        )

    err_text = "; ".join(errors) if errors else "No clipboard utility or OSC 52 handler available."
    return ClipboardResult(
        success=False,
        method="none",
        char_count=char_count,
        error=err_text,
    )


def paste_text_from_clipboard() -> str | None:
    """Read UTF-8 text from the OS clipboard, returning ``None`` if unavailable."""
    for _label, cmd in _resolve_paste_commands():
        try:
            proc = subprocess.run(
                cmd,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=_CLIPBOARD_TIMEOUT_SECONDS,
                check=False,
            )
            if proc.returncode == 0:
                return proc.stdout
        except Exception:
            continue
    return None
