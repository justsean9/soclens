"""Hashing, SVG canonicalization, and ignored-hash management for brand logos."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Iterable, Mapping
from pathlib import Path

from soclens.config import (
    get_ignored_hashes,
    get_ignored_hashes_file,
    get_workspace_dir,
)

logger = logging.getLogger("soclens.logos.hashing")

VALID_HASH_LENGTHS: frozenset[int] = frozenset({32, 40, 64})
_HEX_RE = re.compile(r"^[0-9a-f]+$")

# Known generic noise and placeholder image hashes
# (WordPress default icons, 1x1 transparent spacers, empty files)
DEFAULT_IGNORED_HASHES: dict[str, str] = {
    # WordPress default favicons
    "6bdb369337ac2496761c6f063bffea0aa6a91d4662279c399071a468251f51f0": "WordPress default favicon (SHA-256)",
    "4236a047946cb67d6a7e839ec4fee7092e36705e2ebb69f80a5614aa3adf8eee": "WordPress/Error favicon or placeholder (SHA-256)",
    "050f283d5a420b9eef89c7ad62002575": "WordPress default favicon (MD5)",
    "f3e05a8f4c39f1503c80ff1ff91bdf1a": "WordPress default icon variant (MD5)",
    "3d6f1bf8b6b19e2e604f32e2933bbecab9500057": "WordPress default favicon (SHA-1)",
    # 1x1 Transparent spacer GIF
    "d6f77ffdaebe6142823d2cf503a13040": "1x1 Transparent spacer GIF (MD5)",
    "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc": "1x1 Transparent spacer GIF (SHA-1)",
    "bc575397455d311910243468ab9fb05b8719875f2843793740e53a7ff311fb9e": "1x1 Transparent spacer GIF (SHA-256)",
    # 1x1 Transparent spacer PNG
    "7249911e389e7c5b6ff7b7119f906f71": "1x1 Transparent spacer PNG (MD5)",
    "a937a09c256a4263bc3ee40250085dda4c5d31a54687d605c3b069ef49870be8": "1x1 Transparent spacer PNG (SHA-256)",
    # Empty file hashes
    "d41d8cd98f00b204e9800998ecf8427e": "Empty file / zero-byte payload (MD5)",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": "Empty file / zero-byte payload (SHA-1)",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty file / zero-byte payload (SHA-256)",
}


def normalize_hash(raw: str) -> str | None:
    """Normalize a hex hash (MD5, SHA-1, or SHA-256), stripping optional ``hash:`` prefix."""
    if not isinstance(raw, str):
        raw = str(raw)
    clean = raw.strip().lower()
    if clean.startswith("hash:"):
        clean = clean[len("hash:") :].strip()
    if len(clean) in VALID_HASH_LENGTHS and _HEX_RE.fullmatch(clean):
        return clean
    return None


def compute_image_hashes(img_data: bytes) -> dict[str, str]:
    """Compute lowercase MD5, SHA-1, and SHA-256 digests over raw image bytes."""
    return {
        "md5": hashlib.md5(img_data).hexdigest().lower(),
        "sha1": hashlib.sha1(img_data).hexdigest().lower(),
        "sha256": hashlib.sha256(img_data).hexdigest().lower(),
    }


def canonicalize_svg(svg_content: str | bytes) -> bytes:
    """Canonicalize inline SVG markup into deterministic UTF-8 bytes for hashing."""
    if isinstance(svg_content, bytes):
        text = svg_content.decode("utf-8", errors="replace")
    else:
        text = str(svg_content)

    text = text.lstrip("\ufeff")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Strip XML/HTML comments
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    # Normalize inter-tag whitespace and collapse internal runs
    text = re.sub(r">\s+<", "><", text)
    text = re.sub(r"[ \t\n]+", " ", text)
    text = text.strip()
    # Ensure standard xmlns attribute exists on root <svg>
    if "<svg" in text.lower() and not re.search(r"<svg\b[^>]*\bxmlns=", text, flags=re.IGNORECASE):
        text = re.sub(
            r"<svg\b",
            '<svg xmlns="http://www.w3.org/2000/svg"',
            text,
            count=1,
            flags=re.IGNORECASE,
        )
    return text.encode("utf-8")


canonicalize_inline_svg = canonicalize_svg


def compute_inline_svg_hashes(svg_content: str | bytes) -> dict[str, str]:
    """Canonicalize an inline ``<svg>`` element and compute MD5, SHA-1, and SHA-256 digests."""
    return compute_image_hashes(canonicalize_svg(svg_content))


def _resolve_ignored_hashes_path(
    file_path: str | Path | None,
    workspace_dir: str | Path | None = None,
) -> Path | None:
    if file_path is not None and str(file_path).strip():
        return Path(str(file_path).strip()).expanduser()

    env_path = get_ignored_hashes_file() or ""
    if env_path:
        return Path(env_path).expanduser()

    if workspace_dir is not None:
        ws_candidate = get_workspace_dir(workspace_dir) / "ignored_hashes.txt"
        if ws_candidate.is_file():
            return ws_candidate

    cwd_candidate = Path.cwd() / "ignored_hashes.txt"
    if cwd_candidate.is_file():
        return cwd_candidate

    ws_candidate = get_workspace_dir(workspace_dir) / "ignored_hashes.txt"
    if ws_candidate.is_file():
        return ws_candidate

    return None


def _parse_ignored_hash_line(raw_line: str) -> tuple[str | None, str]:
    line = raw_line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None, ""

    hash_comment = ""
    if "#" in line:
        line, hash_comment = (part.strip() for part in line.split("#", 1))
        if not line:
            return None, ""

    comment = ""
    if "," in line:
        line, comment = (part.strip() for part in line.split(",", 1))
    elif ":" in line:
        # Handle both 'hash:<hex>' RF entity IDs and '<hex>: <reason>' lines.
        if line.lower().startswith("hash:"):
            rest = line[len("hash:") :].strip()
            if ":" in rest:
                left, right = (part.strip() for part in rest.split(":", 1))
                if normalize_hash(left) is not None:
                    line = left
                    comment = right
            elif " " in rest:
                parts = rest.split(None, 1)
                if normalize_hash(parts[0]) is not None:
                    line = parts[0]
                    comment = parts[1].strip()
        else:
            left, right = (part.strip() for part in line.split(":", 1))
            if normalize_hash(left) is not None:
                line = left
                comment = right
    elif " " in line:
        parts = line.split(None, 1)
        if normalize_hash(parts[0]) is not None:
            line = parts[0]
            comment = parts[1].strip()

    # Also handle space-separated '<hex> <reason>' if no delimiter was found
    if not comment and " " in line:
        parts = line.split(None, 1)
        if normalize_hash(parts[0]) is not None:
            line = parts[0]
            comment = parts[1].strip()

    combined_comment = comment or hash_comment
    if comment and hash_comment:
        combined_comment = f"{comment} ({hash_comment})"

    return normalize_hash(line), combined_comment


def load_ignored_hashes(
    file_path: str | Path | None = None,
    extra_hashes: Iterable[str] | str | None = None,
    workspace_dir: str | Path | None = None,
) -> dict[str, str]:
    """Load ignored/tuned-out hashes from defaults, config file, env vars, and extras.

    Supports MD5 (32 hex), SHA-1 (40 hex), and SHA-256 (64 hex), as well as
    optional ``hash:`` prefixes.
    """
    hashes: dict[str, str] = dict(DEFAULT_IGNORED_HASHES)

    target_path = _resolve_ignored_hashes_path(file_path, workspace_dir=workspace_dir)
    if target_path is not None and target_path.is_file():
        try:
            if target_path.suffix.lower() == ".json":
                with target_path.open("r", encoding="utf-8-sig") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    for h, reason in data.items():
                        clean_h = normalize_hash(str(h))
                        if clean_h is not None:
                            hashes[clean_h] = str(reason)
                elif isinstance(data, list):
                    for item in data:
                        clean_h = normalize_hash(str(item))
                        if clean_h is not None:
                            hashes[clean_h] = f"Ignored hash from {target_path.name}"
            else:
                with target_path.open("r", encoding="utf-8-sig") as f:
                    for raw_line in f:
                        clean_h, comment = _parse_ignored_hash_line(raw_line)
                        if clean_h is not None:
                            hashes[clean_h] = comment or f"Ignored hash from {target_path.name}"
            logger.info("Loaded ignored hashes from '%s' (total active: %d)", target_path, len(hashes))
            print(f"[*] Loaded ignored hashes from '{target_path}' (total active: {len(hashes)})")
        except Exception as exc:
            logger.warning("Error loading ignored hashes file '%s': %s", target_path, exc)
            print(f"[-] Error loading ignored hashes file '{target_path}': {exc}")

    env_hashes = get_ignored_hashes() or ""
    if env_hashes:
        for item in env_hashes.split(","):
            clean_h = normalize_hash(item)
            if clean_h is not None:
                hashes[clean_h] = "Ignored hash from RF_IGNORED_HASHES / settings"

    if extra_hashes:
        raw_items: list[str] = []
        if isinstance(extra_hashes, str):
            raw_items.extend(extra_hashes.split(","))
        else:
            for entry in extra_hashes:
                raw_items.extend(str(entry).split(","))
        for item in raw_items:
            clean_h = normalize_hash(item)
            if clean_h is not None:
                hashes[clean_h] = "User-specified ignored hash"

    return hashes


def match_ignored_hash(
    hashes: Mapping[str, str] | str,
    ignored_hashes: Mapping[str, str],
) -> tuple[str | None, str | None]:
    """Check whether a hash string or hash dict matches any ignored hash."""
    if not ignored_hashes:
        return None, None

    if isinstance(hashes, str):
        norm = normalize_hash(hashes)
        if norm is not None and norm in ignored_hashes:
            return norm, ignored_hashes[norm]
        return None, None

    for algo in ("sha256", "sha1", "md5"):
        raw = hashes.get(algo)
        if raw:
            norm = normalize_hash(str(raw))
            if norm is not None and norm in ignored_hashes:
                return norm, ignored_hashes[norm]
    return None, None
