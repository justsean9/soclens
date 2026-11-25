#!/usr/bin/env python3
"""Build and verify a multi-platform offline wheelhouse for soclens.

Uses only the Python standard library so ``--verify`` works in air-gapped
environments before any third-party packages are installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import sys
import tempfile
import tomllib
import urllib.request
import zipfile
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PACKAGE_NAME = "soclens"
DEFAULT_PYTHON_VERSIONS = ("3.12", "3.13", "3.14")
DEFAULT_PLATFORMS = ("win_amd64", "linux_x86_64", "macosx_arm64")
BUILD_BACKEND_PACKAGES = ("setuptools", "wheel")
MANIFEST_FILENAME = "WHEELHOUSE_MANIFEST.json"
REQUIREMENTS_FILENAME = "requirements.txt"

_MACOSX_VERSION_RE = re.compile(r"macosx_(\d+)_(\d+)")
_EXTRA_MARKER_RE = re.compile(r";\s*.*\bextra\s*==", re.IGNORECASE)


@dataclass(frozen=True)
class SelectedWheel:
    """Resolved wheel artifact metadata ready for download or verification."""

    filename: str
    package: str
    version: str
    role: str
    url: str
    sha256: str
    size: int


def _canonicalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _parse_csv_option(raw: str) -> tuple[str, ...]:
    items = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not items:
        raise ValueError(f"Expected a non-empty comma-separated list, got: {raw!r}")
    return items


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_wheel_zip(path: Path) -> None:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            bad_member = zf.testzip()
            if bad_member is not None:
                raise RuntimeError(f"Corrupt ZIP member '{bad_member}' in wheel {path.name}")
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"Invalid wheel ZIP file {path.name}: {exc}") from exc


def _find_missing_build_deps(path: Path, included_versions: dict[str, str]) -> list[str]:
    """Return any non-extra Requires-Dist entries missing from ``included_versions``."""
    missing: list[str] = []
    with zipfile.ZipFile(path, "r") as zf:
        meta_names = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")]
        if not meta_names:
            raise RuntimeError(f"Wheel {path.name} is missing *.dist-info/METADATA")
        metadata_text = zf.read(meta_names[0]).decode("utf-8", errors="replace")

    for line in metadata_text.splitlines():
        if not line.startswith("Requires-Dist:"):
            continue
        req_val = line.split(":", 1)[1].strip()
        if not req_val or _EXTRA_MARKER_RE.search(req_val):
            continue
        req_head = req_val.split(";", 1)[0].strip()
        dep_match = re.match(r"^([A-Za-z0-9_.-]+)(.*)$", req_head)
        if not dep_match:
            missing.append(req_val)
            continue
        dep_name = _canonicalize_name(dep_match.group(1))
        if dep_name not in included_versions:
            missing.append(req_val)
    return missing


def compute_runtime_closure(lock_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Compute the exact transitive runtime package closure from ``uv.lock``."""
    raw_packages = lock_data.get("package")
    if not isinstance(raw_packages, list):
        raise ValueError("Invalid uv.lock: missing [[package]] array")

    pkg_map: dict[str, dict[str, Any]] = {}
    for entry in raw_packages:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            pkg_map[_canonicalize_name(entry["name"])] = entry

    root_key = _canonicalize_name(PACKAGE_NAME)
    if root_key not in pkg_map:
        raise ValueError(f"Package '{PACKAGE_NAME}' not found in uv.lock")

    queue: deque[tuple[str, tuple[str, ...]]] = deque([(root_key, ())])
    visited_states: set[tuple[str, tuple[str, ...]]] = set()
    runtime_keys: set[str] = set()

    while queue:
        pkg_key, extras = queue.popleft()
        state = (pkg_key, tuple(sorted(extras)))
        if state in visited_states:
            continue
        visited_states.add(state)

        pkg = pkg_map.get(pkg_key)
        if pkg is None:
            raise ValueError(f"Dependency '{pkg_key}' referenced in uv.lock is missing")

        if pkg_key != root_key:
            runtime_keys.add(pkg_key)

        for dep in pkg.get("dependencies", []) or []:
            if isinstance(dep, dict) and isinstance(dep.get("name"), str):
                dep_key = _canonicalize_name(dep["name"])
                dep_extras = tuple(str(e) for e in (dep.get("extra") or ()))
                queue.append((dep_key, dep_extras))

        opt_deps = pkg.get("optional-dependencies", {}) or {}
        if isinstance(opt_deps, dict):
            for ext in extras:
                for dep in opt_deps.get(ext, []) or []:
                    if isinstance(dep, dict) and isinstance(dep.get("name"), str):
                        dep_key = _canonicalize_name(dep["name"])
                        dep_extras = tuple(str(e) for e in (dep.get("extra") or ()))
                        queue.append((dep_key, dep_extras))

    return [pkg_map[k] for k in sorted(runtime_keys)]


def _parse_sha256(raw_hash: str) -> str:
    cleaned = raw_hash.strip()
    if cleaned.startswith("sha256:"):
        return cleaned.split(":", 1)[1].lower()
    return cleaned.lower()


def _py_tag_for_version(py_ver: str) -> str:
    parts = py_ver.split(".")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        raise ValueError(f"Invalid Python version '{py_ver}' (expected MAJOR.MINOR, e.g. 3.12)")
    return f"cp{parts[0]}{parts[1]}"


def _macosx_version_key(filename: str) -> tuple[int, int, str]:
    match = _MACOSX_VERSION_RE.search(filename)
    if match:
        return (int(match.group(1)), int(match.group(2)), filename)
    return (999, 999, filename)


def _match_native_wheel(
    wheels: list[dict[str, Any]],
    pkg_name: str,
    py_ver: str,
    platform_tag: str,
) -> dict[str, Any]:
    cp_tag = _py_tag_for_version(py_ver)
    exact_cp = f"-{cp_tag}-{cp_tag}-"
    free_thread_marker = f"-{cp_tag}t-"

    candidates: list[dict[str, Any]] = []
    for entry in wheels:
        url = str(entry.get("url") or "")
        filename = url.rsplit("/", 1)[-1]
        if free_thread_marker in filename or "abi3t" in filename:
            continue
        if exact_cp not in filename:
            continue
        if platform_tag == "win_amd64":
            if filename.endswith("-win_amd64.whl"):
                candidates.append(entry)
        elif platform_tag == "linux_x86_64":
            if "manylinux" in filename and filename.endswith("_x86_64.whl"):
                candidates.append(entry)
        elif platform_tag == "macosx_arm64":
            if "macosx_" in filename and filename.endswith("_arm64.whl"):
                candidates.append(entry)
        else:
            raise ValueError(f"Unsupported target platform tag: {platform_tag!r}")

    if not candidates:
        raise RuntimeError(
            f"No wheel found in uv.lock for native package '{pkg_name}' "
            f"(python={py_ver}, platform={platform_tag})"
        )

    if platform_tag == "macosx_arm64" and len(candidates) > 1:
        candidates.sort(key=lambda w: _macosx_version_key(str(w["url"]).rsplit("/", 1)[-1]))
        return candidates[0]

    if len(candidates) > 1:
        names = [str(c["url"]).rsplit("/", 1)[-1] for c in candidates]
        raise RuntimeError(
            f"Ambiguous wheel candidates for '{pkg_name}' ({py_ver}, {platform_tag}): {names}"
        )
    return candidates[0]


def select_runtime_wheels(
    runtime_pkgs: list[dict[str, Any]],
    *,
    python_versions: tuple[str, ...],
    platforms: tuple[str, ...],
) -> list[SelectedWheel]:
    """Select exact pure-Python and multi-platform native wheels from ``uv.lock``."""
    selected_by_name: dict[str, SelectedWheel] = {}

    for pkg in runtime_pkgs:
        pkg_name = str(pkg["name"])
        pkg_ver = str(pkg["version"])
        wheels = pkg.get("wheels") or []
        if not isinstance(wheels, list) or not wheels:
            raise RuntimeError(f"No wheels recorded in uv.lock for '{pkg_name}=={pkg_ver}'")

        pure_wheels = [
            w for w in wheels if str(w.get("url") or "").rsplit("/", 1)[-1].endswith("-none-any.whl")
        ]
        if pure_wheels:
            chosen = pure_wheels[0]
            filename = str(chosen["url"]).rsplit("/", 1)[-1]
            selected_by_name[filename] = SelectedWheel(
                filename=filename,
                package=pkg_name,
                version=pkg_ver,
                role="runtime",
                url=str(chosen["url"]),
                sha256=_parse_sha256(str(chosen["hash"])),
                size=int(chosen["size"]),
            )
            continue

        for py_ver in python_versions:
            for plat in platforms:
                chosen = _match_native_wheel(wheels, pkg_name, py_ver, plat)
                filename = str(chosen["url"]).rsplit("/", 1)[-1]
                selected_by_name[filename] = SelectedWheel(
                    filename=filename,
                    package=pkg_name,
                    version=pkg_ver,
                    role="runtime",
                    url=str(chosen["url"]),
                    sha256=_parse_sha256(str(chosen["hash"])),
                    size=int(chosen["size"]),
                )

    return [selected_by_name[name] for name in sorted(selected_by_name)]


def _build_ssl_context(
    insecure: bool = False,
    ca_bundle: str | None = None,
) -> ssl.SSLContext | None:
    """Resolve an optional SSLContext from CLI flags or RF SSL environment variables."""
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    ca_val = (ca_bundle or "").strip() or os.environ.get("RF_CA_BUNDLE", "").strip()
    if ca_val:
        return ssl.create_default_context(cafile=os.path.expanduser(ca_val))

    env_verify = os.environ.get("RF_VERIFY_SSL", "").strip().lower()
    if env_verify in ("0", "false", "no", "off"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if env_verify and env_verify not in ("1", "true", "yes", "on"):
        return ssl.create_default_context(cafile=os.path.expanduser(env_verify))

    env_insecure = (
        os.environ.get("RF_INSECURE_SSL", "").strip().lower()
        or os.environ.get("SOCLENS_INSECURE_SSL", "").strip().lower()
    )
    if env_insecure in ("1", "true", "yes", "on"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    return None


def _fetch_pypi_build_wheel(
    pkg_name: str,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> SelectedWheel:
    url = f"https://pypi.org/pypi/{pkg_name}/json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=ssl_context) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    version = str(payload.get("info", {}).get("version") or "").strip()
    if not version:
        raise RuntimeError(f"Could not determine version from PyPI metadata for '{pkg_name}'")

    urls = payload.get("urls") or []
    wheel_entries = [
        item
        for item in urls
        if item.get("packagetype") == "bdist_wheel"
        and str(item.get("filename") or "").endswith("-py3-none-any.whl")
    ]
    if not wheel_entries:
        raise RuntimeError(f"No py3-none-any wheel found on PyPI for '{pkg_name}=={version}'")

    chosen = wheel_entries[0]
    sha256 = str(chosen.get("digests", {}).get("sha256") or "").lower()
    if not sha256:
        raise RuntimeError(f"PyPI metadata missing sha256 digest for {chosen.get('filename')}")

    return SelectedWheel(
        filename=str(chosen["filename"]),
        package=pkg_name,
        version=version,
        role="build",
        url=str(chosen["url"]),
        sha256=sha256,
        size=int(chosen["size"]),
    )


def _download_wheel(
    spec: SelectedWheel,
    dest_dir: Path,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> Path:
    dest_path = dest_dir / spec.filename
    if dest_path.is_file():
        existing_size = dest_path.stat().st_size
        existing_hash = _sha256_file(dest_path)
        if existing_size == spec.size and existing_hash == spec.sha256:
            _verify_wheel_zip(dest_path)
            return dest_path

    fd, tmp_name = tempfile.mkstemp(prefix=".tmp_", suffix=".whl", dir=str(dest_dir))
    tmp_path = Path(tmp_name)
    try:
        os.close(fd)
        req = urllib.request.Request(spec.url, headers={"User-Agent": "soclens-wheelhouse-builder"})
        with urllib.request.urlopen(req, timeout=60, context=ssl_context) as resp, tmp_path.open("wb") as out_fh:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                out_fh.write(chunk)

        actual_size = tmp_path.stat().st_size
        actual_hash = _sha256_file(tmp_path)
        if actual_size != spec.size:
            raise RuntimeError(
                f"Size mismatch for {spec.filename}: expected {spec.size}, got {actual_size}"
            )
        if actual_hash != spec.sha256:
            raise RuntimeError(
                f"SHA-256 mismatch for {spec.filename}: expected {spec.sha256}, got {actual_hash}"
            )
        _verify_wheel_zip(tmp_path)
        tmp_path.chmod(0o644)
        tmp_path.replace(dest_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    return dest_path


def build_wheelhouse(
    *,
    repo_root: Path,
    output_dir: Path,
    python_versions: tuple[str, ...],
    platforms: tuple[str, ...],
    ssl_context: ssl.SSLContext | None = None,
) -> dict[str, Any]:
    """Download all runtime + PEP 517 build wheels and write manifest files."""
    lock_path = repo_root / "uv.lock"
    if not lock_path.is_file():
        raise FileNotFoundError(f"uv.lock not found at {lock_path}")

    lock_data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    runtime_pkgs = compute_runtime_closure(lock_data)
    runtime_wheels = select_runtime_wheels(
        runtime_pkgs,
        python_versions=python_versions,
        platforms=platforms,
    )

    build_wheels: list[SelectedWheel] = []
    for build_pkg in BUILD_BACKEND_PACKAGES:
        build_wheels.append(_fetch_pypi_build_wheel(build_pkg, ssl_context=ssl_context))

    all_wheels = sorted(runtime_wheels + build_wheels, key=lambda w: w.filename)
    output_dir.mkdir(parents=True, exist_ok=True)

    expected_filenames = {w.filename for w in all_wheels}
    for existing in sorted(output_dir.glob("*.whl")):
        if existing.name not in expected_filenames:
            existing.unlink()

    included_versions = {
        _canonicalize_name(w.package): w.version for w in all_wheels
    }

    total_bytes = 0
    for spec in all_wheels:
        downloaded = _download_wheel(spec, output_dir, ssl_context=ssl_context)
        if spec.role == "build":
            external_deps = _find_missing_build_deps(downloaded, included_versions)
            if external_deps:
                raise RuntimeError(
                    f"Build backend wheel {spec.filename} has unbundled dependencies: {external_deps}"
                )
        total_bytes += spec.size

    req_lines = [f"{pkg['name']}=={pkg['version']}" for pkg in runtime_pkgs]
    (output_dir / REQUIREMENTS_FILENAME).write_text("\n".join(req_lines) + "\n", encoding="utf-8")

    manifest: dict[str, Any] = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "package_name": PACKAGE_NAME,
        "python_versions": list(python_versions),
        "target_platforms": list(platforms),
        "runtime_packages": [
            {"name": str(pkg["name"]), "version": str(pkg["version"])} for pkg in runtime_pkgs
        ],
        "build_packages": [
            {"name": w.package, "version": w.version} for w in sorted(build_wheels, key=lambda x: x.package)
        ],
        "wheel_count": len(all_wheels),
        "total_bytes": total_bytes,
        "wheels": [
            {
                "filename": w.filename,
                "package": w.package,
                "version": w.version,
                "role": w.role,
                "sha256": w.sha256,
                "size": w.size,
            }
            for w in all_wheels
        ],
    }
    (output_dir / MANIFEST_FILENAME).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def verify_wheelhouse(
    *,
    repo_root: Path,
    wheelhouse_dir: Path,
) -> dict[str, Any]:
    """Verify local wheelhouse integrity and lockfile completeness completely offline."""
    if not wheelhouse_dir.is_dir():
        raise FileNotFoundError(f"Wheelhouse directory does not exist: {wheelhouse_dir}")

    manifest_path = wheelhouse_dir / MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Wheelhouse manifest missing: {manifest_path}")

    reqs_path = wheelhouse_dir / REQUIREMENTS_FILENAME
    if not reqs_path.is_file():
        raise FileNotFoundError(f"Wheelhouse requirements file missing: {reqs_path}")

    lock_path = repo_root / "uv.lock"
    if not lock_path.is_file():
        raise FileNotFoundError(f"uv.lock not found at {lock_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    lock_data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    runtime_pkgs = compute_runtime_closure(lock_data)

    py_versions = tuple(str(v) for v in (manifest.get("python_versions") or DEFAULT_PYTHON_VERSIONS))
    platforms = tuple(str(p) for p in (manifest.get("target_platforms") or DEFAULT_PLATFORMS))
    expected_runtime = select_runtime_wheels(
        runtime_pkgs,
        python_versions=py_versions,
        platforms=platforms,
    )

    manifest_wheels = manifest.get("wheels")
    if not isinstance(manifest_wheels, list) or not manifest_wheels:
        raise RuntimeError("WHEELHOUSE_MANIFEST.json has no wheels listed")

    manifest_by_name: dict[str, dict[str, Any]] = {}
    for entry in manifest_wheels:
        fname = str(entry.get("filename") or "")
        if not fname:
            raise RuntimeError("WHEELHOUSE_MANIFEST.json contains an entry without filename")
        manifest_by_name[fname] = entry

    disk_wheels = sorted(p.name for p in wheelhouse_dir.glob("*.whl"))
    manifest_names = sorted(manifest_by_name)
    if disk_wheels != manifest_names:
        missing = sorted(set(manifest_names) - set(disk_wheels))
        extra = sorted(set(disk_wheels) - set(manifest_names))
        raise RuntimeError(
            f"Wheelhouse disk/manifest mismatch (missing={missing}, extra={extra})"
        )

    for fname, entry in manifest_by_name.items():
        whl_path = wheelhouse_dir / fname
        actual_size = whl_path.stat().st_size
        expected_size = int(entry["size"])
        if actual_size != expected_size:
            raise RuntimeError(
                f"Size mismatch for {fname}: manifest={expected_size}, disk={actual_size}"
            )
        actual_hash = _sha256_file(whl_path)
        expected_hash = str(entry["sha256"]).lower()
        if actual_hash != expected_hash:
            raise RuntimeError(
                f"SHA-256 mismatch for {fname}: manifest={expected_hash}, disk={actual_hash}"
            )
        _verify_wheel_zip(whl_path)

    # Confirm every lockfile-derived runtime wheel is present with exact hash and size.
    for spec in expected_runtime:
        entry = manifest_by_name.get(spec.filename)
        if entry is None:
            raise RuntimeError(
                f"Required runtime wheel '{spec.filename}' from uv.lock missing from wheelhouse"
            )
        if str(entry["sha256"]).lower() != spec.sha256 or int(entry["size"]) != spec.size:
            raise RuntimeError(
                f"Runtime wheel '{spec.filename}' does not match uv.lock digest/size"
            )

    build_pkgs = {_canonicalize_name(str(b.get("name") or "")) for b in manifest.get("build_packages", [])}
    if "setuptools" not in build_pkgs:
        raise RuntimeError("PEP 517 build dependency 'setuptools' missing from wheelhouse manifest")

    req_lines = [
        line.strip()
        for line in reqs_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    expected_req_lines = [f"{pkg['name']}=={pkg['version']}" for pkg in runtime_pkgs]
    if req_lines != expected_req_lines:
        raise RuntimeError(
            "wheelhouse/requirements.txt is out of sync with uv.lock runtime dependencies"
        )

    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build or verify the offline multi-platform wheelhouse from uv.lock."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root containing uv.lock (default: repo root)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Wheelhouse directory (default: <repo-root>/wheelhouse)",
    )
    parser.add_argument(
        "--python-versions",
        type=str,
        default=",".join(DEFAULT_PYTHON_VERSIONS),
        help="Comma-separated Python MAJOR.MINOR versions (default: 3.12,3.13,3.14)",
    )
    parser.add_argument(
        "--platforms",
        type=str,
        default=",".join(DEFAULT_PLATFORMS),
        help="Comma-separated target platforms (default: win_amd64,linux_x86_64,macosx_arm64)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify local wheelhouse integrity and completeness completely offline",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Disable SSL verification when downloading wheels behind an internal proxy",
    )
    parser.add_argument(
        "--ca-bundle",
        default=None,
        help="Path to custom CA PEM bundle for wheel downloads (overrides RF_CA_BUNDLE)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = args.repo_root.expanduser().resolve()
    wheelhouse_dir = (
        args.output.expanduser().resolve()
        if args.output is not None
        else (repo_root / "wheelhouse").resolve()
    )

    try:
        if args.verify:
            manifest = verify_wheelhouse(repo_root=repo_root, wheelhouse_dir=wheelhouse_dir)
            size_mb = int(manifest["total_bytes"]) / (1024 * 1024)
            print(
                f"[+] Wheelhouse verified offline: {manifest['wheel_count']} wheels "
                f"({size_mb:.2f} MB) across Python {', '.join(manifest['python_versions'])} "
                f"and platforms {', '.join(manifest['target_platforms'])}"
            )
            return 0

        if args.insecure and args.ca_bundle:
            raise ValueError("Cannot specify both --insecure and --ca-bundle.")

        ssl_context = _build_ssl_context(insecure=args.insecure, ca_bundle=args.ca_bundle)
        py_versions = _parse_csv_option(args.python_versions)
        platforms = _parse_csv_option(args.platforms)
        manifest = build_wheelhouse(
            repo_root=repo_root,
            output_dir=wheelhouse_dir,
            python_versions=py_versions,
            platforms=platforms,
            ssl_context=ssl_context,
        )
        verify_wheelhouse(repo_root=repo_root, wheelhouse_dir=wheelhouse_dir)
        size_mb = int(manifest["total_bytes"]) / (1024 * 1024)
        print(
            f"[+] Built and verified wheelhouse at {wheelhouse_dir}: "
            f"{manifest['wheel_count']} wheels ({size_mb:.2f} MB)"
        )
        return 0
    except Exception as exc:
        print(f"[-] Wheelhouse error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
