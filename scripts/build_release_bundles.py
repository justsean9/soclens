#!/usr/bin/env python3
"""Build and verify pre-packaged offline release ZIP bundles for soclens."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from soclens.bundler import create_bundle  # noqa: E402

DEFAULT_REPO_URL = "https://github.com/justsean9/soclens"
CHECKSUMS_FILENAME = "SHA256SUMS.txt"
RELEASE_README_FILENAME = "README.md"

RELEASE_TARGETS: tuple[tuple[str, str, str], ...] = (
    ("all", "Universal (Windows x64, Linux x64, macOS ARM64)", "Python 3.12, 3.13, 3.14"),
    ("win_amd64", "Windows x64 (`win_amd64`)", "Python 3.12, 3.13, 3.14"),
    ("linux_x86_64", "Linux x64 (`manylinux*_x86_64`)", "Python 3.12, 3.13, 3.14"),
    ("macosx_arm64", "macOS ARM64 (`macosx_*_arm64`)", "Python 3.12, 3.13, 3.14"),
)

REQUIRED_BUNDLE_MEMBERS: tuple[str, ...] = (
    "BUNDLE_MANIFEST.json",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "README.md",
    "CHANGELOG.md",
    "soclens/__init__.py",
    "soclens/__main__.py",
    "soclens/research.py",
    "soclens/tui/logging_bridge.py",
    "install_offline.sh",
    "install_offline.ps1",
    "soclens.ps1",
    "wheelhouse/requirements.txt",
    "wheelhouse/WHEELHOUSE_MANIFEST.json",
)

FORBIDDEN_EXACT_NAMES: frozenset[str] = frozenset(
    {
        "apikey.key",
        ".settings.key",
        ".soclens_settings.key",
        "sigma_rules_cache.json",
        "brands.csv",
        "watchlist.csv",
        "brand_sync_state.json",
        "discovered_images.json",
        "validation_results.json",
        "settings.json",
        ".soclens_settings.json",
        ".soclens_tui_settings.json",
    }
)

FORBIDDEN_PREFIXES: tuple[str, ...] = (
    ".git/",
    ".venv/",
    "venv/",
    "reports/",
    "logs/",
    "bundles/",
    "scratch/",
)

FORBIDDEN_SUFFIXES: tuple[str, ...] = (".pyc", ".pyo", ".log", ".key")


def _load_build_wheelhouse_module() -> Any:
    script_path = Path(__file__).resolve().parent / "build_wheelhouse.py"
    spec = importlib.util.spec_from_file_location("soclens_build_wheelhouse", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load wheelhouse helper from {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read_package_version(repo_root: Path) -> str:
    """Read ``[project].version`` from ``pyproject.toml``."""
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.is_file():
        raise FileNotFoundError(f"pyproject.toml not found at {pyproject}")
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    ver = str(data.get("project", {}).get("version") or "").strip()
    if not ver:
        raise ValueError(f"Missing [project].version in {pyproject}")
    return ver


def bundle_filename(version: str, target_platform: str) -> str:
    """Return canonical release bundle filename for ``version`` and ``target_platform``."""
    clean_ver = version.lstrip("v").strip()
    return f"soclens-v{clean_ver}-offline-{target_platform}.zip"


def sha256_file(path: Path) -> str:
    """Compute lowercase hexadecimal SHA-256 digest for ``path``."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stage_git_head(repo_root: Path, staging_dir: Path) -> Path:
    """Export a clean git ``HEAD`` snapshot preserving POSIX executable bits."""
    src_dir = staging_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    tar_path = staging_dir / "head.tar"
    res = subprocess.run(
        ["git", "-C", str(repo_root), "archive", "--format=tar", "-o", str(tar_path), "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        detail = (res.stderr or res.stdout or "").strip()
        raise RuntimeError(f"git archive HEAD failed (exit {res.returncode}): {detail}")

    with tarfile.open(tar_path, "r") as tf:
        tf.extractall(src_dir, filter="tar")
    return src_dir


def _format_release_readme(
    *,
    version: str,
    repo_url: str,
    records: list[dict[str, Any]],
) -> str:
    tag = f"v{version}"
    lines = [
        f"# SOCLens — {tag} Offline Bundles",
        "",
        f"Pre-packaged air-gapped deployment archives for **`soclens=={version}`**.",
        "Each ZIP archive includes the full toolkit source, cross-platform offline installers (`install_offline.ps1` and `install_offline.sh`), and a SHA-256-verified offline `wheelhouse/` supporting **Python 3.12, 3.13, and 3.14** with zero internet access.",
        "",
        f"- **GitHub Release:** [{tag}]({repo_url}/releases/tag/{tag})",
        f"- **Checksums:** [`{CHECKSUMS_FILENAME}`]({CHECKSUMS_FILENAME})",
        "",
        "## Quick Download",
        "",
        "| Bundle | Target Platform | Python | Wheels | Size | SHA-256 |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for rec in records:
        fname = rec["filename"]
        size_mb = rec["size_bytes"] / (1024 * 1024)
        lines.append(
            f"| [`{fname}`]({fname}) | {rec['description']} | {rec['python_versions']} | "
            f"{rec['wheel_count']} | {size_mb:.2f} MB | `{rec['sha256']}` |"
        )

    lines.extend(
        [
            "",
            "## Offline Verification & Installation",
            "",
            "### Windows (PowerShell 5.1 / PowerShell 7+)",
            "On Windows, SOCLens runs via PowerShell (`soclens.ps1` / `python -m soclens.cli`).",
            "```powershell",
            f"Get-FileHash .\\soclens-{tag}-offline-win_amd64.zip -Algorithm SHA256",
            f"Expand-Archive .\\soclens-{tag}-offline-win_amd64.zip -DestinationPath .\\soclens-{tag}",
            f"cd .\\soclens-{tag}",
            "python .\\scripts\\build_wheelhouse.py --verify",
            ".\\install_offline.ps1 -LaunchTui",
            "# Subsequent launches:",
            ".\\soclens.ps1 tui",
            "```",
            "",
            "### Linux / macOS (Bash / Zsh)",
            "```bash",
            f"sha256sum -c {CHECKSUMS_FILENAME} --ignore-missing",
            f"unzip soclens-{tag}-offline-linux_x86_64.zip -d soclens-{tag}",
            f"cd soclens-{tag}",
            "python3 scripts/build_wheelhouse.py --verify",
            "./install_offline.sh --launch-tui",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def build_release_bundles(
    *,
    repo_root: Path,
    output_dir: Path | None = None,
    version: str | None = None,
    from_git: bool = True,
    repo_url: str = DEFAULT_REPO_URL,
) -> list[dict[str, Any]]:
    """Build all v1 offline release ZIP bundles, checksums, and index README."""
    resolved_root = repo_root.expanduser().resolve()
    clean_ver = (version or read_package_version(resolved_root)).lstrip("v").strip()
    dest_dir = (
        output_dir.expanduser().resolve()
        if output_dir is not None
        else (resolved_root / "bundles" / f"v{clean_ver}").resolve()
    )
    dest_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as tmp_str:
        staging_dir = Path(tmp_str)
        source_workspace = _stage_git_head(resolved_root, staging_dir) if from_git else resolved_root

        for target_platform, description, py_versions in RELEASE_TARGETS:
            fname = bundle_filename(clean_ver, target_platform)
            zip_path = dest_dir / fname
            created = create_bundle(
                workspace_dir=source_workspace,
                output_path=zip_path,
                wheelhouse=True,
                target_platform=target_platform,
            )
            with zipfile.ZipFile(created, "r") as zf:
                wh_manifest = json.loads(
                    zf.read("wheelhouse/WHEELHOUSE_MANIFEST.json").decode("utf-8")
                )
            records.append(
                {
                    "filename": fname,
                    "path": str(created),
                    "target_platform": target_platform,
                    "description": description,
                    "python_versions": py_versions,
                    "wheel_count": int(wh_manifest["wheel_count"]),
                    "size_bytes": created.stat().st_size,
                    "sha256": sha256_file(created),
                }
            )

    checksum_lines = [
        f"{rec['sha256']}  {rec['filename']}"
        for rec in sorted(records, key=lambda item: str(item["filename"]))
    ]
    (dest_dir / CHECKSUMS_FILENAME).write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    readme_text = _format_release_readme(version=clean_ver, repo_url=repo_url, records=records)
    (dest_dir / RELEASE_README_FILENAME).write_text(readme_text, encoding="utf-8")
    return records


def verify_release_bundles(
    *,
    repo_root: Path,
    output_dir: Path | None = None,
    version: str | None = None,
) -> list[dict[str, Any]]:
    """Verify release ZIP integrity, checksums, manifest metadata, and wheelhouses."""
    resolved_root = repo_root.expanduser().resolve()
    clean_ver = (version or read_package_version(resolved_root)).lstrip("v").strip()
    dest_dir = (
        output_dir.expanduser().resolve()
        if output_dir is not None
        else (resolved_root / "bundles" / f"v{clean_ver}").resolve()
    )

    if not dest_dir.is_dir():
        raise FileNotFoundError(f"Release bundles directory not found: {dest_dir}")

    checksums_path = dest_dir / CHECKSUMS_FILENAME
    if not checksums_path.is_file():
        raise FileNotFoundError(f"Checksums file missing: {checksums_path}")

    recorded_hashes: dict[str, str] = {}
    for line in checksums_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) != 2 or len(parts[0]) != 64:
            raise RuntimeError(f"Malformed SHA256SUMS line: {line!r}")
        recorded_hashes[parts[1]] = parts[0].lower()

    build_wh = _load_build_wheelhouse_module()
    results: list[dict[str, Any]] = []

    for target_platform, _desc, _py_vers in RELEASE_TARGETS:
        fname = bundle_filename(clean_ver, target_platform)
        zip_path = dest_dir / fname
        if not zip_path.is_file():
            raise FileNotFoundError(f"Expected release bundle missing: {zip_path}")

        expected_sha = recorded_hashes.get(fname)
        if not expected_sha:
            raise RuntimeError(f"Checksum entry missing for {fname} in {checksums_path}")
        actual_sha = sha256_file(zip_path)
        if actual_sha != expected_sha:
            raise RuntimeError(
                f"SHA-256 mismatch for {fname}: expected {expected_sha}, got {actual_sha}"
            )

        with zipfile.ZipFile(zip_path, "r") as zf:
            bad_member = zf.testzip()
            if bad_member is not None:
                raise RuntimeError(f"Corrupt ZIP member '{bad_member}' in {fname}")

            names = set(zf.namelist())
            missing_members = [m for m in REQUIRED_BUNDLE_MEMBERS if m not in names]
            if missing_members:
                raise RuntimeError(f"{fname} is missing required files: {missing_members}")

            for member in names:
                if member.startswith("/") or ".." in Path(member).parts:
                    raise RuntimeError(f"Unsafe ZIP path '{member}' in {fname}")
                base_name = Path(member).name
                if base_name in FORBIDDEN_EXACT_NAMES:
                    raise RuntimeError(f"Forbidden file '{member}' found inside {fname}")
                if member.startswith(FORBIDDEN_PREFIXES):
                    raise RuntimeError(f"Forbidden directory entry '{member}' found inside {fname}")
                if Path(member).suffix.lower() in FORBIDDEN_SUFFIXES:
                    raise RuntimeError(f"Forbidden suffix '{member}' found inside {fname}")

            bundle_manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
            if bundle_manifest.get("package_version") != clean_ver:
                raise RuntimeError(
                    f"{fname} BUNDLE_MANIFEST.json package_version={bundle_manifest.get('package_version')!r}, expected {clean_ver!r}"
                )
            if bundle_manifest.get("wheelhouse") is not True:
                raise RuntimeError(f"{fname} BUNDLE_MANIFEST.json wheelhouse is not True")
            if bundle_manifest.get("wheelhouse_mode") != "local_wheelhouse":
                raise RuntimeError(
                    f"{fname} wheelhouse_mode={bundle_manifest.get('wheelhouse_mode')!r}"
                )
            if bundle_manifest.get("target_platform") != target_platform:
                raise RuntimeError(
                    f"{fname} target_platform={bundle_manifest.get('target_platform')!r}, expected {target_platform!r}"
                )

            sh_info = zf.getinfo("install_offline.sh")
            if b"\r\n" in zf.read("install_offline.sh"):
                raise RuntimeError(f"{fname}: install_offline.sh contains CRLF line endings")
            if not ((sh_info.external_attr >> 16) & stat.S_IXUSR):
                raise RuntimeError(f"{fname}: install_offline.sh is missing POSIX executable permission")

            ps1_text = zf.read("install_offline.ps1").decode("utf-8")
            if not ps1_text.isascii():
                raise RuntimeError(f"{fname}: install_offline.ps1 contains non-ASCII characters")
            if "$WinCli" in ps1_text:
                raise RuntimeError(f"{fname}: install_offline.ps1 must not invoke soclens.exe ($WinCli)")
            if "Install-WindowsPowerShellShims" not in ps1_text:
                raise RuntimeError(
                    f"{fname}: install_offline.ps1 is missing Install-WindowsPowerShellShims"
                )

            launcher_text = zf.read("soclens.ps1").decode("utf-8")
            if not launcher_text.isascii():
                raise RuntimeError(f"{fname}: soclens.ps1 contains non-ASCII characters")
            if "soclens.cli" not in launcher_text or "soclens.exe" in launcher_text:
                raise RuntimeError(
                    f"{fname}: soclens.ps1 must invoke soclens.cli directly without soclens.exe"
                )

            if "scripts/soclens-brand-sync.ps1" in names:
                sync_ps1_text = zf.read("scripts/soclens-brand-sync.ps1").decode("utf-8")
                if not sync_ps1_text.isascii():
                    raise RuntimeError(
                        f"{fname}: scripts/soclens-brand-sync.ps1 contains non-ASCII characters"
                    )

            with tempfile.TemporaryDirectory() as extract_tmp:
                extract_root = Path(extract_tmp)
                zf.extract("uv.lock", extract_root)
                for member in names:
                    if member.startswith("wheelhouse/") and not member.endswith("/"):
                        zf.extract(member, extract_root)

                wh_manifest = build_wh.verify_wheelhouse(
                    repo_root=extract_root,
                    wheelhouse_dir=extract_root / "wheelhouse",
                )

        results.append(
            {
                "filename": fname,
                "target_platform": target_platform,
                "wheel_count": int(wh_manifest["wheel_count"]),
                "size_bytes": zip_path.stat().st_size,
                "sha256": actual_sha,
            }
        )

    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and verify offline release ZIP bundles for soclens."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root directory (default: repo root)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output release bundle directory (default: <repo-root>/bundles/v<version>)",
    )
    parser.add_argument(
        "--version",
        type=str,
        default=None,
        help="Override release version (default: [project].version from pyproject.toml)",
    )
    parser.add_argument(
        "--from-workspace",
        action="store_true",
        help="Bundle directly from the working directory instead of a clean git HEAD archive",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify existing release bundles, SHA-256 checksums, manifests, and wheelhouses",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = args.repo_root.expanduser().resolve()

    try:
        if args.verify:
            verified = verify_release_bundles(
                repo_root=repo_root,
                output_dir=args.output_dir,
                version=args.version,
            )
            for item in verified:
                size_mb = item["size_bytes"] / (1024 * 1024)
                print(
                    f"[+] Verified {item['filename']} "
                    f"({size_mb:.2f} MB, {item['wheel_count']} wheels, sha256={item['sha256'][:12]}...)"
                )
            return 0

        built = build_release_bundles(
            repo_root=repo_root,
            output_dir=args.output_dir,
            version=args.version,
            from_git=not args.from_workspace,
        )
        verify_release_bundles(
            repo_root=repo_root,
            output_dir=args.output_dir,
            version=args.version,
        )
        for item in built:
            size_mb = item["size_bytes"] / (1024 * 1024)
            print(
                f"[+] Built & verified {item['filename']} "
                f"({size_mb:.2f} MB, {item['wheel_count']} wheels)"
            )
        return 0
    except Exception as exc:
        print(f"[-] Release bundle error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
