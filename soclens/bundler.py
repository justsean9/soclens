"""Air-gapped deployment bundler for the SOCLens."""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import importlib.util
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import tomllib
import zipfile
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

logger = logging.getLogger("soclens.bundler")

DEFAULT_BUNDLE_FILENAME = "soclens-bundle.zip"
PACKAGE_NAME = "soclens"
NATIVE_EXTENSIONS = (".so", ".pyd", ".dll", ".dylib")

WORKSPACE_INCLUDE_ITEMS: tuple[str, ...] = (
    "soclens",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "README.md",
    "CHANGELOG.md",
    "ignored_hashes.txt",
    "sigma_rules_cache.json",
    "install_offline.ps1",
    "install_offline.sh",
    "soclens.ps1",
    "docs",
    "scripts",
)

EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        "__pycache__",
        ".git",
        ".venv",
        "venv",
        "env",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "build",
        "dist",
        "logs",
        "reports",
        "bundles",
        "scratch",
        "htmlcov",
    }
)

EXCLUDED_FILE_NAMES: frozenset[str] = frozenset(
    {
        "apikey.key",
        ".settings.key",
        ".soclens_settings.key",
        "settings.json",
        ".soclens_settings.json",
        ".soclens_tui_settings.json",
        ".coverage",
        ".DS_Store",
    }
)

EXCLUDED_SUFFIXES: tuple[str, ...] = (".pyc", ".pyo", ".log", ".key")


def _canonicalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _detect_os_arch(label: str) -> tuple[str | None, str | None]:
    low = label.lower().strip()
    os_family: str | None = None
    if any(tok in low for tok in ("win32", "win64", "win_", "win-", "windows")):
        os_family = "windows"
    elif any(tok in low for tok in ("linux", "manylinux", "musllinux")):
        os_family = "linux"
    elif any(tok in low for tok in ("darwin", "macos", "macosx", "apple")):
        os_family = "darwin"

    arch: str | None = None
    if any(tok in low for tok in ("x86_64", "amd64", "win64")):
        arch = "x86_64"
    elif any(tok in low for tok in ("aarch64", "arm64")):
        arch = "arm64"
    elif any(tok in low for tok in ("i686", "x86", "win32")):
        arch = "x86"

    return os_family, arch


def normalize_target_platform(target_platform: str | None) -> tuple[str, bool, bool]:
    """Return ``(normalized_label, is_pure, matches_host)`` for a target platform."""
    host_platform = sysconfig.get_platform()
    if target_platform is None or not target_platform.strip():
        return host_platform, False, True

    cleaned = target_platform.strip()
    lowered = cleaned.lower()
    if lowered in ("all", "multi", "universal"):
        return "all", False, False
    if lowered in ("pure", "pure-python", "pure_python", "any", "none"):
        return "pure", True, False

    host_os, host_arch = _detect_os_arch(host_platform)
    if host_os is None:
        if sys.platform.startswith("win"):
            host_os = "windows"
        elif sys.platform.startswith("linux"):
            host_os = "linux"
        elif sys.platform == "darwin":
            host_os = "darwin"

    target_os, target_arch = _detect_os_arch(lowered)
    if target_os is None:
        matches_host = lowered == host_platform.lower()
    elif target_os != host_os:
        matches_host = False
    elif target_arch is not None and host_arch is not None:
        matches_host = target_arch == host_arch
    else:
        matches_host = True

    return cleaned, False, matches_host


def _build_marker_environment(target_platform: str | None) -> dict[str, str]:
    env: dict[str, str] = {"extra": ""}
    if not target_platform:
        return env

    target_os, _ = _detect_os_arch(target_platform)
    if target_os == "windows":
        env.update(
            {
                "os_name": "nt",
                "sys_platform": "win32",
                "platform_system": "Windows",
            }
        )
    elif target_os == "linux":
        env.update(
            {
                "os_name": "posix",
                "sys_platform": "linux",
                "platform_system": "Linux",
            }
        )
    elif target_os == "darwin":
        env.update(
            {
                "os_name": "posix",
                "sys_platform": "darwin",
                "platform_system": "Darwin",
            }
        )
    return env


def _read_root_requirements_from_files(workspace_dir: Path) -> list[str]:
    pyproject_path = workspace_dir / "pyproject.toml"
    if pyproject_path.is_file():
        try:
            data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
            deps = data.get("project", {}).get("dependencies", [])
            if isinstance(deps, list):
                return [str(dep).strip() for dep in deps if str(dep).strip()]
        except (OSError, tomllib.TOMLDecodeError) as exc:
            logger.warning("Failed to parse %s: %s", pyproject_path, exc)

    reqs_path = workspace_dir / "requirements.txt"
    if reqs_path.is_file():
        reqs: list[str] = []
        try:
            for line in reqs_path.read_text(encoding="utf-8").splitlines():
                stripped = line.split("#", 1)[0].strip()
                if stripped and not stripped.startswith("-"):
                    reqs.append(stripped)
        except OSError as exc:
            logger.warning("Failed to read %s: %s", reqs_path, exc)
        return reqs

    return []


def discover_runtime_dependencies(
    workspace_dir: str | Path,
    target_platform: str | None = None,
    warnings: list[str] | None = None,
) -> list[importlib_metadata.Distribution]:
    """Recursively discover runtime distributions for ``soclens``."""
    workspace = Path(workspace_dir).expanduser().resolve()
    root_requires: list[str] = []

    try:
        root_dist = importlib_metadata.distribution(PACKAGE_NAME)
        if root_dist.requires:
            root_requires = list(root_dist.requires)
    except importlib_metadata.PackageNotFoundError:
        root_requires = []

    if not root_requires:
        root_requires = _read_root_requirements_from_files(workspace)

    marker_env = _build_marker_environment(target_platform)
    queue: deque[tuple[str, str]] = deque((req_str, "") for req_str in root_requires)
    seen_extras: dict[str, set[str]] = {_canonicalize_name(PACKAGE_NAME): {""}}
    dist_cache: dict[str, importlib_metadata.Distribution] = {}
    missing_pkgs: set[str] = set()
    distributions: list[importlib_metadata.Distribution] = []

    while queue:
        req_str, active_extra = queue.popleft()
        try:
            req = Requirement(req_str)
        except InvalidRequirement as exc:
            msg = f"Skipping unparseable requirement '{req_str}': {exc}"
            logger.warning(msg)
            if warnings is not None:
                warnings.append(msg)
            continue

        eval_env = {**marker_env, "extra": active_extra}
        if req.marker is not None and not req.marker.evaluate(eval_env):
            continue

        canon = _canonicalize_name(req.name)
        requested_extras = set(req.extras) | {""}
        known_extras = seen_extras.get(canon)
        if known_extras is None:
            if canon in missing_pkgs:
                continue
            try:
                dep_dist = importlib_metadata.distribution(req.name)
            except importlib_metadata.PackageNotFoundError:
                missing_pkgs.add(canon)
                msg = f"Runtime dependency '{req.name}' is not installed in the active environment."
                logger.warning(msg)
                if warnings is not None:
                    warnings.append(msg)
                continue

            distributions.append(dep_dist)
            dist_cache[canon] = dep_dist
            seen_extras[canon] = set(requested_extras)
            new_extras = requested_extras
        else:
            new_extras = requested_extras - known_extras
            if not new_extras:
                continue
            cached_dist = dist_cache.get(canon)
            if cached_dist is None:
                continue
            dep_dist = cached_dist
            known_extras.update(new_extras)

        for extra_name in sorted(new_extras):
            for child_req in dep_dist.requires or []:
                queue.append((child_req, extra_name))

    return distributions


def _is_excluded_relative_path(parts: tuple[str, ...], filename: str, suffix: str) -> bool:
    if any(part in EXCLUDED_DIR_NAMES or part.endswith(".data") for part in parts[:-1]):
        return True
    if parts[-1] in EXCLUDED_DIR_NAMES:
        return True
    if filename in EXCLUDED_FILE_NAMES:
        return True
    if suffix.lower() in EXCLUDED_SUFFIXES:
        return True
    return False


def _collect_distribution_files(
    dist: importlib_metadata.Distribution,
    *,
    exclude_native: bool,
    excluded_native: list[str],
) -> list[tuple[Path, str]]:
    root = Path(str(dist.locate_file("")))
    try:
        root_resolved = root.resolve()
    except OSError:
        root_resolved = root

    collected: list[tuple[Path, str]] = []
    for pkg_path in dist.files or []:
        parts = pkg_path.parts
        if not parts or pkg_path.is_absolute() or ".." in parts:
            continue
        if _is_excluded_relative_path(parts, pkg_path.name, pkg_path.suffix):
            continue

        src = Path(str(dist.locate_file(pkg_path)))
        try:
            src_resolved = src.resolve()
        except OSError:
            continue

        if not src_resolved.is_relative_to(root_resolved):
            continue
        if not src_resolved.is_file():
            continue

        arcname = pkg_path.as_posix()
        if src_resolved.suffix.lower() in NATIVE_EXTENSIONS and exclude_native:
            excluded_native.append(arcname)
            continue

        collected.append((src_resolved, arcname))

    return collected


def _map_pip_platform(target_platform: str | None) -> str | None:
    if not target_platform:
        return None
    low = target_platform.lower().strip()
    mapping = {
        "windows": "win_amd64",
        "win64": "win_amd64",
        "win-amd64": "win_amd64",
        "x86_64-pc-windows-msvc": "win_amd64",
        "linux": "manylinux2014_x86_64",
        "linux-x86_64": "manylinux2014_x86_64",
        "x86_64-unknown-linux-gnu": "manylinux2014_x86_64",
        "macos": "macosx_11_0_arm64",
        "darwin": "macosx_11_0_arm64",
    }
    return mapping.get(low, target_platform.strip())


def _map_uv_platform(target_platform: str | None) -> str | None:
    if not target_platform:
        return None
    low = target_platform.lower().strip()
    mapping = {
        "win_amd64": "x86_64-pc-windows-msvc",
        "win-amd64": "x86_64-pc-windows-msvc",
        "win64": "x86_64-pc-windows-msvc",
        "win32": "i686-pc-windows-msvc",
        "windows": "windows",
        "linux_x86_64": "x86_64-unknown-linux-gnu",
        "linux-x86_64": "x86_64-unknown-linux-gnu",
        "manylinux2014_x86_64": "x86_64-unknown-linux-gnu",
        "manylinux_2_17_x86_64": "x86_64-unknown-linux-gnu",
        "linux_aarch64": "aarch64-unknown-linux-gnu",
        "linux": "linux",
        "macosx_11_0_arm64": "aarch64-apple-darwin",
        "darwin_arm64": "aarch64-apple-darwin",
        "macosx_10_15_x86_64": "x86_64-apple-darwin",
        "darwin": "macos",
        "macos": "macos",
    }
    return mapping.get(low, target_platform.strip())


def _wheel_matches_target(
    filename: str,
    target_label: str,
    is_pure: bool,
    raw_target_platform: str | None,
) -> bool:
    """Return True if wheel ``filename`` should be included for ``target_label``."""
    low_name = filename.lower()
    if low_name.endswith("-none-any.whl"):
        return True
    if raw_target_platform is None or target_label == "all":
        return True
    if is_pure:
        return False

    target_os, target_arch = _detect_os_arch(target_label)
    wheel_os, wheel_arch = _detect_os_arch(low_name)
    if target_os is not None and wheel_os != target_os:
        return False
    if target_arch is not None and wheel_arch is not None and wheel_arch != target_arch:
        return False
    if target_os is None:
        return target_label.lower() in low_name
    return True


def _build_wheelhouse_entries(
    distributions: list[importlib_metadata.Distribution],
    workspace_dir: Path,
    target_label: str,
    is_pure: bool,
    staging_dir: Path,
    *,
    raw_target_platform: str | None = None,
    warnings: list[str] | None = None,
) -> tuple[list[tuple[Path, str]], str]:
    """Reuse local ``wheelhouse/*.whl`` offline, or fall back to pip/uv staging."""
    req_lines: list[str] = []
    if distributions:
        for dist in distributions:
            name = dist.metadata.get("Name") or _canonicalize_name(str(dist))
            version = dist.version
            if name and version:
                req_lines.append(f"{name}=={version}")
    else:
        req_lines = _read_root_requirements_from_files(workspace_dir)

    if not req_lines:
        raise RuntimeError("No runtime dependencies discovered for wheelhouse bundling.")

    reqs_file = staging_dir / "requirements.txt"
    reqs_file.write_text("\n".join(req_lines) + "\n", encoding="utf-8")

    local_wh = workspace_dir / "wheelhouse"
    all_local_wheels = sorted(local_wh.glob("*.whl")) if local_wh.is_dir() else []
    if all_local_wheels:
        selected_wheels: list[Path] = []
        excluded_wheels: list[Path] = []
        for whl in all_local_wheels:
            if _wheel_matches_target(whl.name, target_label, is_pure, raw_target_platform):
                selected_wheels.append(whl)
            else:
                excluded_wheels.append(whl)

        if not selected_wheels:
            raise RuntimeError(
                f"No wheels in local wheelhouse '{local_wh}' matched target_platform='{target_label}'."
            )

        if is_pure and excluded_wheels and warnings is not None:
            warnings.append(
                f"Excluded {len(excluded_wheels)} platform-specific native wheel(s) from "
                "local wheelhouse for target_platform='pure' (PyYAML CSafeLoader, google-re2, "
                "jq, and markupsafe require target-platform compiled wheels)."
            )

        entries: list[tuple[Path, str]] = [
            (whl, f"wheelhouse/{whl.name}") for whl in selected_wheels
        ]
        local_reqs = local_wh / "requirements.txt"
        entries.append(
            (local_reqs if local_reqs.is_file() else reqs_file, "wheelhouse/requirements.txt")
        )
        local_manifest = local_wh / "WHEELHOUSE_MANIFEST.json"
        if local_manifest.is_file():
            manifest_src = local_manifest
            if excluded_wheels:
                try:
                    manifest_data = json.loads(local_manifest.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    manifest_data = None
                if isinstance(manifest_data, dict) and isinstance(manifest_data.get("wheels"), list):
                    selected_names = {w.name for w in selected_wheels}
                    filtered_wheels = [
                        item
                        for item in manifest_data["wheels"]
                        if isinstance(item, dict) and item.get("filename") in selected_names
                    ]
                    manifest_data["wheels"] = filtered_wheels
                    manifest_data["wheel_count"] = len(filtered_wheels)
                    manifest_data["total_bytes"] = sum(
                        int(item.get("size", 0)) for item in filtered_wheels
                    )
                    if is_pure:
                        manifest_data["target_platforms"] = []
                    else:
                        target_os, _ = _detect_os_arch(target_label)
                        plat_map = {
                            "windows": ["win_amd64"],
                            "linux": ["linux_x86_64"],
                            "darwin": ["macosx_arm64"],
                        }
                        manifest_data["target_platforms"] = plat_map.get(
                            target_os or "", [target_label]
                        )
                    staged_manifest = staging_dir / "WHEELHOUSE_MANIFEST.json"
                    staged_manifest.write_text(
                        json.dumps(manifest_data, indent=2) + "\n",
                        encoding="utf-8",
                    )
                    manifest_src = staged_manifest
            entries.append((manifest_src, "wheelhouse/WHEELHOUSE_MANIFEST.json"))
        return entries, "local_wheelhouse"

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"

    if importlib.util.find_spec("pip") is not None:
        wh_dir = staging_dir / "wheelhouse"
        wh_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--dest",
            str(wh_dir),
            "-r",
            str(reqs_file),
        ]
        if not is_pure and target_label not in ("all", sysconfig.get_platform()):
            pip_plat = _map_pip_platform(target_label)
            if pip_plat:
                cmd.extend(["--platform", pip_plat, "--python-version", py_ver, "--only-binary=:all:"])

        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            detail = (res.stderr or res.stdout or "").strip()
            raise RuntimeError(
                f"pip download failed while building wheelhouse (exit {res.returncode}): {detail}"
            )

        wheels = sorted(wh_dir.glob("*.whl"))
        if not wheels:
            raise RuntimeError("pip download completed without producing any .whl files.")

        entries = [(reqs_file, "wheelhouse/requirements.txt")]
        for whl in wheels:
            entries.append((whl, f"wheelhouse/{whl.name}"))
        return entries, "pip_download"

    uv_bin = shutil.which("uv")
    if uv_bin is not None:
        target_site = staging_dir / "site-packages"
        target_site.mkdir(parents=True, exist_ok=True)
        cmd = [
            uv_bin,
            "pip",
            "install",
            "--target",
            str(target_site),
            "-r",
            str(reqs_file),
        ]
        if not is_pure and target_label not in ("all", sysconfig.get_platform()):
            uv_plat = _map_uv_platform(target_label)
            if uv_plat:
                cmd.extend(
                    [
                        "--python-platform",
                        uv_plat,
                        "--python-version",
                        py_ver,
                        "--only-binary",
                        ":all:",
                    ]
                )

        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            detail = (res.stderr or res.stdout or "").strip()
            raise RuntimeError(
                f"uv pip install wheelhouse staging failed (exit {res.returncode}): {detail}"
            )

        entries = []
        for path in sorted(target_site.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(target_site)
            if _is_excluded_relative_path(rel.parts, path.name, path.suffix):
                continue
            if is_pure and path.suffix.lower() in NATIVE_EXTENSIONS:
                continue
            entries.append((path, rel.as_posix()))

        if not entries:
            raise RuntimeError("uv pip install produced no package files for wheelhouse bundle.")
        entries.append((reqs_file, "wheelhouse/requirements.txt"))
        return entries, "uv_target"

    raise RuntimeError(
        "Wheelhouse bundling requires either 'pip' or 'uv' to be installed in the environment."
    )


def _iter_workspace_files(
    workspace: Path,
    dest: Path,
    warnings: list[str],
) -> list[tuple[Path, str]]:
    entries: list[tuple[Path, str]] = []
    for item_name in WORKSPACE_INCLUDE_ITEMS:
        item_path = workspace / item_name
        if not item_path.exists():
            msg = f"Optional workspace item not found, skipping: {item_name}"
            logger.debug(msg)
            warnings.append(msg)
            continue

        if item_path.is_dir():
            for root, dirs, files in os.walk(item_path):
                dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIR_NAMES)
                root_path = Path(root)
                for fname in sorted(files):
                    file_path = root_path / fname
                    try:
                        resolved = file_path.resolve()
                    except OSError:
                        continue
                    if resolved == dest:
                        continue
                    rel = file_path.relative_to(workspace)
                    if _is_excluded_relative_path(rel.parts, fname, file_path.suffix):
                        continue
                    entries.append((resolved, rel.as_posix()))
        elif item_path.is_file():
            resolved = item_path.resolve()
            if resolved == dest:
                continue
            if item_path.name in EXCLUDED_FILE_NAMES or item_path.suffix.lower() in EXCLUDED_SUFFIXES:
                continue
            entries.append((resolved, item_name))

    return entries


def create_bundle(
    workspace_dir: str | Path,
    output_path: str | Path | None = None,
    wheelhouse: bool = False,
    target_platform: str | None = None,
) -> Path:
    """Create an air-gapped deployment ZIP archive of the toolkit and dependencies."""
    workspace = Path(workspace_dir).expanduser().resolve()
    if not workspace.exists():
        raise FileNotFoundError(f"Workspace directory does not exist: {workspace}")
    if not workspace.is_dir():
        raise NotADirectoryError(f"Workspace path is not a directory: {workspace}")

    if output_path is None:
        dest = (workspace / DEFAULT_BUNDLE_FILENAME).resolve()
    else:
        candidate = Path(output_path).expanduser()
        if not candidate.is_absolute():
            candidate = workspace / candidate
        candidate = candidate.resolve()
        dest = (
            candidate / DEFAULT_BUNDLE_FILENAME
            if candidate.exists() and candidate.is_dir()
            else candidate
        )

    dest.parent.mkdir(parents=True, exist_ok=True)

    target_label, is_pure, matches_host = normalize_target_platform(target_platform)
    exclude_native = (not wheelhouse) and (is_pure or not matches_host)

    warnings: list[str] = []
    excluded_native: list[str] = []
    distributions = discover_runtime_dependencies(
        workspace,
        target_platform=target_platform,
        warnings=warnings,
    )

    workspace_entries = _iter_workspace_files(workspace, dest, warnings)

    package_version = "0.0.0"
    pyproject_path = workspace / "pyproject.toml"
    if pyproject_path.is_file():
        try:
            data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
            ver = data.get("project", {}).get("version")
            if isinstance(ver, str) and ver.strip():
                package_version = ver.strip()
        except (OSError, tomllib.TOMLDecodeError):
            pass
    if package_version == "0.0.0":
        try:
            package_version = importlib_metadata.version(PACKAGE_NAME)
        except importlib_metadata.PackageNotFoundError:
            pass

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        staging_dir = Path(tmp_dir_str)
        wheelhouse_mode = "site_packages"
        dep_entries: list[tuple[Path, str]] = []

        if wheelhouse:
            dep_entries, wheelhouse_mode = _build_wheelhouse_entries(
                distributions=distributions,
                workspace_dir=workspace,
                target_label=target_label,
                is_pure=is_pure,
                staging_dir=staging_dir,
                raw_target_platform=target_platform,
                warnings=warnings,
            )
        else:
            for dist in distributions:
                dep_entries.extend(
                    _collect_distribution_files(
                        dist,
                        exclude_native=exclude_native,
                        excluded_native=excluded_native,
                    )
                )

            if exclude_native and excluded_native:
                warnings.append(
                    f"Excluded {len(excluded_native)} host native binary file(s) for "
                    f"target_platform='{target_label}'."
                )
                if any("_yaml" in p or p.startswith("yaml/") for p in excluded_native):
                    warnings.append(
                        "PyYAML compiled _yaml extension was excluded; pySigma's "
                        "SigmaYAMLLoader (yaml.CSafeLoader) requires target-platform "
                        "compiled PyYAML wheels (use --wheelhouse on a connected build host)."
                    )

        seen_arcnames: set[str] = set()
        manifest_files: list[str] = []

        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zipf:
            for src_path, arcname in workspace_entries + dep_entries:
                if arcname in seen_arcnames or arcname == "BUNDLE_MANIFEST.json":
                    continue
                seen_arcnames.add(arcname)
                zipf.write(src_path, arcname)
                manifest_files.append(arcname)

            manifest: dict[str, Any] = {
                "schema_version": 1,
                "package_name": PACKAGE_NAME,
                "package_version": package_version,
                "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "python_version": (
                    f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                ),
                "source_platform": sysconfig.get_platform(),
                "target_platform": target_label,
                "wheelhouse": wheelhouse,
                "wheelhouse_mode": wheelhouse_mode,
                "dependencies": [
                    {
                        "name": dist.metadata.get("Name") or "",
                        "version": dist.version,
                    }
                    for dist in distributions
                ],
                "excluded_native_files": excluded_native,
                "warnings": warnings,
                "file_count": len(manifest_files) + 1,
                "files": sorted(manifest_files),
            }
            zipf.writestr("BUNDLE_MANIFEST.json", json.dumps(manifest, indent=2))

    logger.info("Created bundle %s (%d files)", dest, len(manifest_files) + 1)
    return dest
