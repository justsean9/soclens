"""Summarize brand logo discovery results and identify duplicate cross-domain hashes."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from soclens.config import ensure_utf8_console, get_workspace_dir
except ImportError:  # pragma: no cover - fallback when executed standalone
    def ensure_utf8_console() -> None:
        return None

    def get_workspace_dir(explicit: Path | str | None = None) -> Path:
        if explicit is not None and str(explicit).strip():
            return Path(str(explicit)).expanduser().resolve()
        return Path.cwd().resolve()


def _resolve_default_locations_path() -> Path:
    cwd_candidate = Path("discovered_images.json")
    if cwd_candidate.is_file():
        return cwd_candidate
    ws_candidate = get_workspace_dir() / "discovered_images.json"
    if ws_candidate.is_file():
        return ws_candidate
    return Path("test_locations.json")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize logo/image scraping results and identify duplicate hashes."
    )
    default_path = str(_resolve_default_locations_path())
    parser.add_argument(
        "filepath",
        nargs="?",
        default=default_path,
        help=(
            "Path to the JSON file containing discovered locations "
            "(default: discovered_images.json or test_locations.json)"
        ),
    )
    return parser.parse_args(argv)


def summarize_file(filepath: str | Path) -> int:
    """Summarize a discovered-images JSON file and return 0 on success or 1 on error."""
    ensure_utf8_console()
    path = Path(filepath).expanduser()
    if not path.is_file():
        print(f"Error: File {path} does not exist.", file=sys.stderr)
        return 1

    try:
        with path.open("r", encoding="utf-8-sig") as fh:
            data: Any = json.load(fh)
    except Exception as exc:
        print(f"Error parsing JSON from {path}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(data, list):
        print(
            f"Error: Expected a JSON list in {path}, got {type(data).__name__}.",
            file=sys.stderr,
        )
        return 1

    domain_statuses: dict[str, dict[str, list[Any]]] = defaultdict(
        lambda: {"included": [], "excluded": [], "download_failed": [], "empty_or_non_image": []}
    )
    sha256_map: dict[str, list[tuple[str, str]]] = defaultdict(list)

    for item in data:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain", "Unknown"))
        status = str(item.get("status", "unknown"))
        url = str(item.get("url", ""))
        reason = str(item.get("exclusion_reason", ""))
        err_msg = str(item.get("error", ""))

        if status == "included":
            domain_statuses[domain]["included"].append(url)
            if isinstance(item.get("sha256"), str):
                sha256_map[item["sha256"]].append((domain, url))
        elif status == "excluded":
            domain_statuses[domain]["excluded"].append((url, reason))
        elif status == "download_failed":
            domain_statuses[domain]["download_failed"].append((url, err_msg))
        elif status == "empty_or_non_image":
            domain_statuses[domain]["empty_or_non_image"].append((url, err_msg))

    print("\n" + "=" * 60)
    print(f" SUMMARY FOR: {path}".center(60))
    print("=" * 60)

    for domain, stats in sorted(domain_statuses.items()):
        included = stats["included"]
        excluded = stats["excluded"]
        failed = stats["download_failed"]
        empty = stats["empty_or_non_image"]

        if not included and not excluded and not failed and not empty:
            continue

        print(f"\nSite: {domain}")
        if included:
            print(f"  Included ({len(included)}):")
            for url in included:
                print(f"    - {url}")
        if excluded:
            print(f"  Excluded ({len(excluded)}):")
            for url, reason in excluded:
                print(f"    - {url}")
                if reason:
                    print(f"      Reason: {reason}")
        if failed:
            print(f"  Download Failed ({len(failed)}):")
            for url, err in failed:
                print(f"    - {url} (Error: {err})")
        if empty:
            print(f"  Empty/Non-Image ({len(empty)}):")
            for url, err in empty:
                print(f"    - {url} (Error: {err})")

    sha256_duplicates: dict[str, list[tuple[str, str]]] = {}
    for h, entries in sha256_map.items():
        unique_domains = {d for d, _ in entries}
        if len(unique_domains) > 1:
            sha256_duplicates[h] = entries

    print("\n" + "=" * 60)
    print(" DUPLICATE HASHES REPORT (SHA-256)".center(60))
    print("=" * 60)

    if sha256_duplicates:
        for h, entries in sorted(sha256_duplicates.items()):
            domain_to_urls: dict[str, list[str]] = defaultdict(list)
            for d, u in entries:
                domain_to_urls[d].append(u)

            print(f"\nHash: {h}")
            print(f"  Shared by {len(domain_to_urls)} domains:")
            for d, urls in sorted(domain_to_urls.items()):
                print(f"    - {d}:")
                for u in urls:
                    print(f"      * {u}")
    else:
        print("\nNo duplicate SHA-256 hashes found across different domains.")

    total_included = sum(len(stats["included"]) for stats in domain_statuses.values())
    total_excluded = sum(len(stats["excluded"]) for stats in domain_statuses.values())
    total_failed = sum(len(stats["download_failed"]) for stats in domain_statuses.values())
    total_empty = sum(len(stats["empty_or_non_image"]) for stats in domain_statuses.values())

    print("\n" + "=" * 60)
    print(" METRICS SUMMARY".center(60))
    print("=" * 60)
    print(f"Total Domains Processed:      {len(domain_statuses)}")
    print(f"Total Unique SHA-256 Hashes:  {len(sha256_map)}")
    print(f"Total Duplicate Hashes:       {len(sha256_duplicates)}")
    print(f"Total Images Included:        {total_included}")
    print(f"Total Images Excluded:        {total_excluded}")
    print(f"Total Images Failed:          {total_failed + total_empty}")
    print("=" * 60 + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ensure_utf8_console()
    args = parse_args(argv)
    return summarize_file(args.filepath)


if __name__ == "__main__":
    sys.exit(main())
