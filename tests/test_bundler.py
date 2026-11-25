import hashlib
import importlib.metadata as importlib_metadata
import importlib.util
import json
import os
import shutil
import site
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from soclens.bundler import (
    DEFAULT_BUNDLE_FILENAME,
    create_bundle,
    discover_runtime_dependencies,
    normalize_target_platform,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _create_sample_workspace(root: Path) -> Path:
    ws = root / "workspace"
    (ws / "soclens").mkdir(parents=True)
    (ws / "soclens" / "__init__.py").write_text('__version__ = "1.0.0"\n', encoding="utf-8")
    (ws / "soclens" / "config.py").write_text("VALUE = 1\n", encoding="utf-8")
    (ws / "soclens" / "__pycache__").mkdir()
    (ws / "soclens" / "__pycache__" / "config.cpython-312.pyc").write_bytes(b"pyc")
    (ws / "soclens" / "stale.pyc").write_bytes(b"pyc")

    (ws / "README.md").write_text("# Toolkit\n", encoding="utf-8")
    (ws / "ignored_hashes.txt").write_text("deadbeef\n", encoding="utf-8")
    (ws / "sigma_rules_cache.json").write_text("[]\n", encoding="utf-8")
    (ws / "requirements.txt").write_text("requests>=2.31.0\n", encoding="utf-8")
    (ws / "pyproject.toml").write_text(
        '[project]\nname = "soclens"\nversion = "1.0.0"\n'
        'dependencies = ["requests>=2.31.0"]\n',
        encoding="utf-8",
    )

    (ws / "docs").mkdir()
    (ws / "docs" / "RF_API_REVIEW.md").write_text("# Review\n", encoding="utf-8")
    (ws / "scripts").mkdir()
    (ws / "scripts" / "soclens-brand-sync.ps1").write_text("Write-Host 'OK'\n", encoding="utf-8")

    # Excluded secrets / VCS / venv / logs
    (ws / "apikey.key").write_text("SECRET_TOKEN\n", encoding="utf-8")
    (ws / "soclens" / "apikey.key").write_text("SECRET_TOKEN\n", encoding="utf-8")
    (ws / "soclens" / "debug.log").write_text("log\n", encoding="utf-8")
    (ws / ".git").mkdir()
    (ws / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (ws / ".venv").mkdir()
    (ws / ".venv" / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    return ws


class TestBundler:
    def test_create_bundle_includes_workspace_assets_manifest_and_excludes_secrets(
        self, tmp_path: Path
    ) -> None:
        ws = _create_sample_workspace(tmp_path)
        dest = create_bundle(ws)

        assert dest == (ws / DEFAULT_BUNDLE_FILENAME).resolve()
        assert dest.is_file()

        with zipfile.ZipFile(dest, "r") as zf:
            names = set(zf.namelist())
            assert "BUNDLE_MANIFEST.json" in names
            assert "soclens/__init__.py" in names
            assert "soclens/config.py" in names
            assert "pyproject.toml" in names
            assert "requirements.txt" in names
            assert "ignored_hashes.txt" in names
            assert "sigma_rules_cache.json" in names
            assert "docs/RF_API_REVIEW.md" in names
            assert "scripts/soclens-brand-sync.ps1" in names

            # Check dynamically discovered dependency files (e.g. requests)
            assert any(n.startswith("requests/") for n in names)

            # Exclusions & traversal safety
            assert not any("apikey.key" in n for n in names)
            assert not any(n.endswith(".pyc") or "__pycache__" in n for n in names)
            assert not any(n.endswith(".log") for n in names)
            assert not any(n.startswith(".git") or n.startswith(".venv") for n in names)
            assert not any(".." in Path(n).parts or n.startswith("/") for n in names)

            manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
            assert manifest["schema_version"] == 1
            assert manifest["package_name"] == "soclens"
            assert manifest["wheelhouse"] is False
            assert len(manifest["dependencies"]) > 0

    def test_create_bundle_nested_output_and_missing_workspace(self, tmp_path: Path) -> None:
        ws = _create_sample_workspace(tmp_path)
        nested_dest = tmp_path / "out" / "nested" / "custom.zip"
        result = create_bundle(ws, output_path=nested_dest)
        assert result == nested_dest.resolve()
        assert result.is_file()

        out_dir = tmp_path / "dir_out"
        out_dir.mkdir()
        dir_result = create_bundle(ws, output_path=out_dir)
        assert dir_result == (out_dir / DEFAULT_BUNDLE_FILENAME).resolve()
        assert dir_result.is_file()

        with pytest.raises(FileNotFoundError):
            create_bundle(tmp_path / "does_not_exist")

        file_ws = tmp_path / "not_a_dir.txt"
        file_ws.write_text("x", encoding="utf-8")
        with pytest.raises(NotADirectoryError):
            create_bundle(file_ws)

    def test_pure_and_cross_platform_excludes_native_binaries_with_warning(
        self, tmp_path: Path
    ) -> None:
        ws = _create_sample_workspace(tmp_path)
        dest = create_bundle(ws, output_path=tmp_path / "pure.zip", target_platform="pure")

        with zipfile.ZipFile(dest, "r") as zf:
            names = zf.namelist()
            assert not any(n.endswith((".so", ".pyd", ".dll", ".dylib")) for n in names)
            manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
            assert manifest["target_platform"] == "pure"
            assert len(manifest["excluded_native_files"]) > 0
            assert any("CSafeLoader" in w for w in manifest["warnings"])

        cross_target = "linux_x86_64" if os.name == "nt" else "win_amd64"
        label, is_pure, matches_host = normalize_target_platform(cross_target)
        assert label == cross_target
        assert is_pure is False
        assert matches_host is False

        cross_dest = create_bundle(
            ws, output_path=tmp_path / "cross.zip", target_platform=cross_target
        )
        with zipfile.ZipFile(cross_dest, "r") as zf:
            manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
            assert len(manifest["excluded_native_files"]) > 0
            assert any("Excluded" in w for w in manifest["warnings"])

    def test_discover_dependencies_fallback_to_pyproject_and_traversal_guard(
        self, tmp_path: Path
    ) -> None:
        ws = _create_sample_workspace(tmp_path)
        fake_site = tmp_path / "site"
        fake_site.mkdir()
        (fake_site / "pkg").mkdir()
        (fake_site / "pkg" / "__init__.py").write_text("X = 1\n", encoding="utf-8")
        outside = tmp_path / "outside.txt"
        outside.write_text("SECRET", encoding="utf-8")

        fake_dist = MagicMock(spec=importlib_metadata.Distribution)
        fake_dist.version = "1.0.0"
        fake_dist.metadata = {"Name": "fake-pkg"}
        fake_dist.requires = []
        fake_dist.files = [
            importlib_metadata.PackagePath("pkg/__init__.py"),
            importlib_metadata.PackagePath("../outside.txt"),
            importlib_metadata.PackagePath("fake-pkg-1.0.0.data/scripts/tool"),
        ]
        fake_dist.locate_file.side_effect = lambda p: fake_site / str(p) if p else fake_site

        warnings_list: list[str] = []
        with patch("soclens.bundler.importlib_metadata.distribution") as mock_dist:
            def _dist_lookup(name: str) -> importlib_metadata.Distribution:
                if name == "soclens":
                    raise importlib_metadata.PackageNotFoundError(name)
                if name == "requests":
                    return fake_dist
                raise importlib_metadata.PackageNotFoundError(name)

            mock_dist.side_effect = _dist_lookup
            dists = discover_runtime_dependencies(ws, warnings=warnings_list)
            assert len(dists) == 1

        with (
            patch("soclens.bundler.discover_runtime_dependencies", return_value=[fake_dist]),
            patch("soclens.bundler.importlib_metadata.version", return_value="1.0.0"),
        ):
            dest = create_bundle(ws, output_path=tmp_path / "safe.zip")

        with zipfile.ZipFile(dest, "r") as zf:
            names = set(zf.namelist())
            assert "pkg/__init__.py" in names
            assert "../outside.txt" not in names
            assert not any(".data/" in n for n in names)

    def test_wheelhouse_pip_and_uv_and_offline_error(self, tmp_path: Path) -> None:
        ws = _create_sample_workspace(tmp_path)

        def fake_pip_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            dest_idx = cmd.index("--dest") + 1
            wh_dir = Path(cmd[dest_idx])
            (wh_dir / "requests-2.32.0-py3-none-any.whl").write_bytes(b"wheel")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with (
            patch("soclens.bundler.importlib.util.find_spec", return_value=object()),
            patch("soclens.bundler.subprocess.run", side_effect=fake_pip_run),
        ):
            out = create_bundle(ws, output_path=tmp_path / "wh_pip.zip", wheelhouse=True)
            with zipfile.ZipFile(out, "r") as zf:
                names = set(zf.namelist())
                assert "wheelhouse/requests-2.32.0-py3-none-any.whl" in names
                assert "wheelhouse/requirements.txt" in names

        def fake_uv_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            target_idx = cmd.index("--target") + 1
            target_dir = Path(cmd[target_idx])
            (target_dir / "requests").mkdir(parents=True, exist_ok=True)
            (target_dir / "requests" / "__init__.py").write_text("pass\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with (
            patch("soclens.bundler.importlib.util.find_spec", return_value=None),
            patch("soclens.bundler.shutil.which", return_value="/usr/bin/uv"),
            patch("soclens.bundler.subprocess.run", side_effect=fake_uv_run) as mock_run,
        ):
            out_uv = create_bundle(
                ws,
                output_path=tmp_path / "wh_uv.zip",
                wheelhouse=True,
                target_platform="win_amd64",
            )
            called_cmd = mock_run.call_args.args[0]
            assert "--python-platform" in called_cmd
            assert "x86_64-pc-windows-msvc" in called_cmd
            with zipfile.ZipFile(out_uv, "r") as zf:
                assert "requests/__init__.py" in set(zf.namelist())

        with (
            patch("soclens.bundler.importlib.util.find_spec", return_value=None),
            patch("soclens.bundler.shutil.which", return_value=None),
        ):
            with pytest.raises(RuntimeError, match="requires either 'pip' or 'uv'"):
                create_bundle(ws, output_path=tmp_path / "wh_fail.zip", wheelhouse=True)

        with (
            patch("soclens.bundler.importlib.util.find_spec", return_value=None),
            patch("soclens.bundler.shutil.which", return_value="/usr/bin/uv"),
            patch(
                "soclens.bundler.subprocess.run",
                return_value=subprocess.CompletedProcess([], 1, stdout="", stderr="offline error"),
            ),
        ):
            with pytest.raises(RuntimeError, match="offline error"):
                create_bundle(ws, output_path=tmp_path / "wh_err.zip", wheelhouse=True)

    def test_discover_dependencies_propagates_extras_linkify(self) -> None:
        dists = discover_runtime_dependencies(REPO_ROOT)
        names = {
            (dist.metadata.get("Name") or "").strip().lower().replace("_", "-")
            for dist in dists
        }
        assert "linkify-it-py" in names
        assert "requests" in names
        assert "textual" in names
        assert "pysigma" in names

    def test_wheelhouse_reuses_local_wheelhouse_offline_and_filters_platforms(
        self, tmp_path: Path
    ) -> None:
        ws = _create_sample_workspace(tmp_path)
        wh = ws / "wheelhouse"
        wh.mkdir()
        (wh / "requests-2.34.2-py3-none-any.whl").write_bytes(b"pure-wheel")
        (wh / "pyyaml-6.0.4-cp312-cp312-win_amd64.whl").write_bytes(b"win-wheel")
        (wh / "pyyaml-6.0.4-cp312-cp312-manylinux2014_x86_64.whl").write_bytes(b"lin-wheel")
        (wh / "pyyaml-6.0.4-cp312-cp312-macosx_11_0_arm64.whl").write_bytes(b"mac-wheel")
        (wh / "requirements.txt").write_text("requests==2.34.2\npyyaml==6.0.4\n", encoding="utf-8")
        (wh / "WHEELHOUSE_MANIFEST.json").write_text('{"schema_version": 1}\n', encoding="utf-8")

        with (
            patch("soclens.bundler.importlib.util.find_spec", return_value=None),
            patch("soclens.bundler.shutil.which", return_value=None),
        ):
            for plat, expected_wheels, unexpected_wheels in [
                (
                    None,
                    {
                        "wheelhouse/requests-2.34.2-py3-none-any.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-win_amd64.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-manylinux2014_x86_64.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-macosx_11_0_arm64.whl",
                    },
                    set(),
                ),
                (
                    "all",
                    {
                        "wheelhouse/requests-2.34.2-py3-none-any.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-win_amd64.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-manylinux2014_x86_64.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-macosx_11_0_arm64.whl",
                    },
                    set(),
                ),
                (
                    "win_amd64",
                    {
                        "wheelhouse/requests-2.34.2-py3-none-any.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-win_amd64.whl",
                    },
                    {
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-manylinux2014_x86_64.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-macosx_11_0_arm64.whl",
                    },
                ),
                (
                    "linux_x86_64",
                    {
                        "wheelhouse/requests-2.34.2-py3-none-any.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-manylinux2014_x86_64.whl",
                    },
                    {
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-win_amd64.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-macosx_11_0_arm64.whl",
                    },
                ),
                (
                    "pure",
                    {"wheelhouse/requests-2.34.2-py3-none-any.whl"},
                    {
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-win_amd64.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-manylinux2014_x86_64.whl",
                        "wheelhouse/pyyaml-6.0.4-cp312-cp312-macosx_11_0_arm64.whl",
                    },
                ),
            ]:
                tag = plat or "default"
                out_zip = create_bundle(
                    ws,
                    output_path=tmp_path / f"local_{tag}.zip",
                    wheelhouse=True,
                    target_platform=plat,
                )
                with zipfile.ZipFile(out_zip, "r") as zf:
                    names = set(zf.namelist())
                    manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
                assert manifest["wheelhouse"] is True
                assert manifest["wheelhouse_mode"] == "local_wheelhouse"
                assert "wheelhouse/requirements.txt" in names
                assert "wheelhouse/WHEELHOUSE_MANIFEST.json" in names
                assert expected_wheels.issubset(names)
                assert unexpected_wheels.isdisjoint(names)
                if plat == "pure":
                    assert any("CSafeLoader" in w for w in manifest["warnings"])

    def test_repo_offline_wheelhouse_integrity_and_installer_scripts(self) -> None:
        script_path = REPO_ROOT / "scripts" / "build_wheelhouse.py"
        assert script_path.is_file()
        spec = importlib.util.spec_from_file_location("build_wheelhouse_mod", script_path)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)

        manifest = mod.verify_wheelhouse(
            repo_root=REPO_ROOT,
            wheelhouse_dir=REPO_ROOT / "wheelhouse",
        )
        assert manifest["wheel_count"] >= 60
        assert (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8") == (
            REPO_ROOT / "wheelhouse" / "requirements.txt"
        ).read_text(encoding="utf-8")

        ps1_installer = REPO_ROOT / "install_offline.ps1"
        ps1_launcher = REPO_ROOT / "soclens.ps1"
        ps1_sync = REPO_ROOT / "scripts" / "soclens-brand-sync.ps1"
        sh_installer = REPO_ROOT / "install_offline.sh"
        mod_main = REPO_ROOT / "soclens" / "__main__.py"
        assert ps1_installer.is_file()
        assert ps1_launcher.is_file()
        assert ps1_sync.is_file()
        assert sh_installer.is_file()
        assert mod_main.is_file()

        ps1_installer_text = ps1_installer.read_text(encoding="utf-8")
        ps1_launcher_text = ps1_launcher.read_text(encoding="utf-8")
        ps1_sync_text = ps1_sync.read_text(encoding="utf-8")
        assert ps1_installer_text.isascii()
        assert ps1_launcher_text.isascii()
        assert ps1_sync_text.isascii()

        assert "$WinCli" not in ps1_installer_text
        assert "Install-WindowsPowerShellShims" in ps1_installer_text
        assert "soclens.cli" in ps1_launcher_text
        assert "soclens.exe" not in ps1_launcher_text

        sh_bytes = sh_installer.read_bytes()
        assert b"\r\n" not in sh_bytes
        assert bool(sh_installer.stat().st_mode & stat.S_IXUSR)


class TestReleaseBundlesAndLaunchers:
    def test_bundle_excludes_reports_and_bundles_and_filters_wheelhouse_manifest(
        self, tmp_path: Path
    ) -> None:
        ws = _create_sample_workspace(tmp_path)
        (ws / "sigma_rules_cache.json").unlink(missing_ok=True)
        (ws / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
        (ws / "reports").mkdir()
        (ws / "reports" / "sample.md").write_text("secret report\n", encoding="utf-8")
        (ws / "bundles").mkdir()
        (ws / "bundles" / "old.zip").write_bytes(b"zip")

        wh = ws / "wheelhouse"
        wh.mkdir()
        (wh / "requests-2.34.2-py3-none-any.whl").write_bytes(b"pure")
        (wh / "pyyaml-6.0.4-cp312-cp312-win_amd64.whl").write_bytes(b"win")
        (wh / "pyyaml-6.0.4-cp312-cp312-manylinux2014_x86_64.whl").write_bytes(b"lin")
        (wh / "pyyaml-6.0.4-cp312-cp312-macosx_11_0_arm64.whl").write_bytes(b"mac")
        (wh / "requirements.txt").write_text("requests==2.34.2\npyyaml==6.0.4\n", encoding="utf-8")
        manifest_payload = {
            "schema_version": 1,
            "python_versions": ["3.12"],
            "target_platforms": ["win_amd64", "linux_x86_64", "macosx_arm64"],
            "build_packages": [{"name": "setuptools", "version": "80.0.0"}],
            "wheel_count": 4,
            "total_bytes": 13,
            "wheels": [
                {"filename": "requests-2.34.2-py3-none-any.whl", "size": 4, "sha256": "a" * 64},
                {"filename": "pyyaml-6.0.4-cp312-cp312-win_amd64.whl", "size": 3, "sha256": "b" * 64},
                {"filename": "pyyaml-6.0.4-cp312-cp312-manylinux2014_x86_64.whl", "size": 3, "sha256": "c" * 64},
                {"filename": "pyyaml-6.0.4-cp312-cp312-macosx_11_0_arm64.whl", "size": 3, "sha256": "d" * 64},
            ],
        }
        (wh / "WHEELHOUSE_MANIFEST.json").write_text(
            json.dumps(manifest_payload, indent=2), encoding="utf-8"
        )

        with patch(
            "soclens.bundler.importlib_metadata.version",
            side_effect=importlib_metadata.PackageNotFoundError("soclens"),
        ):
            win_zip = create_bundle(
                ws,
                output_path=tmp_path / "win.zip",
                wheelhouse=True,
                target_platform="win_amd64",
            )

        with zipfile.ZipFile(win_zip, "r") as zf:
            names = set(zf.namelist())
            assert "CHANGELOG.md" in names
            assert not any(n.startswith(("reports/", "bundles/")) for n in names)
            b_manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
            assert b_manifest["package_version"] == "1.0.0"
            wh_manifest = json.loads(zf.read("wheelhouse/WHEELHOUSE_MANIFEST.json").decode("utf-8"))
            assert wh_manifest["wheel_count"] == 2
            assert wh_manifest["total_bytes"] == 7
            assert wh_manifest["target_platforms"] == ["win_amd64"]
            assert [w["filename"] for w in wh_manifest["wheels"]] == [
                "requests-2.34.2-py3-none-any.whl",
                "pyyaml-6.0.4-cp312-cp312-win_amd64.whl",
            ]

    def test_build_and_verify_release_bundles_synthetic(self, tmp_path: Path) -> None:
        script_path = REPO_ROOT / "scripts" / "build_release_bundles.py"
        spec = importlib.util.spec_from_file_location("build_release_bundles_mod", script_path)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)

        ws = _create_sample_workspace(tmp_path)
        (ws / "sigma_rules_cache.json").unlink(missing_ok=True)
        (ws / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
        (ws / "soclens" / "__main__.py").write_text(
            "from soclens.cli import main\nmain()\n", encoding="utf-8"
        )
        (ws / "soclens" / "research.py").write_text("RESEARCH = 1\n", encoding="utf-8")
        (ws / "soclens" / "tui").mkdir(parents=True)
        (ws / "soclens" / "tui" / "logging_bridge.py").write_text("LOG = 1\n", encoding="utf-8")
        (ws / "install_offline.ps1").write_text(
            "# Install-WindowsPowerShellShims\nWrite-Host 'OK'\n", encoding="utf-8"
        )
        (ws / "soclens.ps1").write_text(
            "& python -m soclens.cli @args\n", encoding="utf-8"
        )
        (ws / "scripts" / "soclens-brand-sync.ps1").write_text(
            "Write-Host 'SYNC'\n", encoding="utf-8"
        )
        sh_path = ws / "install_offline.sh"
        sh_path.write_bytes(b"#!/usr/bin/env bash\necho OK\n")
        sh_path.chmod(0o755)
        (ws / "reports").mkdir()
        (ws / "reports" / "leaked.md").write_text("nope\n", encoding="utf-8")
        (ws / "brands.csv").write_text("domain\n", encoding="utf-8")

        wh = ws / "wheelhouse"
        wh.mkdir()

        def _make_dummy_wheel(name: str) -> tuple[str, int]:
            whl_path = wh / name
            with zipfile.ZipFile(whl_path, "w") as zf:
                zf.writestr("dummy.txt", name)
            data = whl_path.read_bytes()
            return hashlib.sha256(data).hexdigest(), len(data)

        req_whl = "requests-2.34.2-py3-none-any.whl"
        set_whl = "setuptools-84.2.1-py3-none-any.whl"
        win_whl = "pyyaml-6.0.4-cp312-cp312-win_amd64.whl"
        lin_whl = "pyyaml-6.0.4-cp312-cp312-manylinux2014_x86_64.whl"
        mac_whl = "pyyaml-6.0.4-cp312-cp312-macosx_11_0_arm64.whl"

        hashes = {
            name: _make_dummy_wheel(name)
            for name in (req_whl, set_whl, win_whl, lin_whl, mac_whl)
        }

        uv_lock_text = "\n".join(
            [
                "version = 1",
                "",
                "[[package]]",
                'name = "soclens"',
                'version = "1.0.0"',
                'dependencies = [{ name = "requests" }, { name = "pyyaml" }]',
                "",
                "[[package]]",
                'name = "requests"',
                'version = "2.34.2"',
                "wheels = [",
                f'  {{ url = "https://example.invalid/{req_whl}", hash = "sha256:{hashes[req_whl][0]}", size = {hashes[req_whl][1]} }},',
                "]",
                "",
                "[[package]]",
                'name = "pyyaml"',
                'version = "6.0.4"',
                "wheels = [",
                f'  {{ url = "https://example.invalid/{win_whl}", hash = "sha256:{hashes[win_whl][0]}", size = {hashes[win_whl][1]} }},',
                f'  {{ url = "https://example.invalid/{lin_whl}", hash = "sha256:{hashes[lin_whl][0]}", size = {hashes[lin_whl][1]} }},',
                f'  {{ url = "https://example.invalid/{mac_whl}", hash = "sha256:{hashes[mac_whl][0]}", size = {hashes[mac_whl][1]} }},',
                "]",
                "",
            ]
        )
        (ws / "uv.lock").write_text(uv_lock_text, encoding="utf-8")
        (ws / "pyproject.toml").write_text(
            '[project]\nname = "soclens"\nversion = "1.0.0"\n'
            'dependencies = ["requests>=2.31.0", "pyyaml>=6.0"]\n',
            encoding="utf-8",
        )
        (wh / "requirements.txt").write_text("pyyaml==6.0.4\nrequests==2.34.2\n", encoding="utf-8")
        wh_manifest = {
            "schema_version": 1,
            "package_name": "soclens",
            "python_versions": ["3.12"],
            "target_platforms": ["win_amd64", "linux_x86_64", "macosx_arm64"],
            "build_packages": [{"name": "setuptools", "version": "84.2.1"}],
            "wheel_count": len(hashes),
            "total_bytes": sum(sz for _, sz in hashes.values()),
            "wheels": [
                {
                    "filename": name,
                    "package": name.split("-")[0],
                    "version": name.split("-")[1],
                    "role": "build" if name == set_whl else "runtime",
                    "sha256": sha,
                    "size": sz,
                }
                for name, (sha, sz) in sorted(hashes.items())
            ],
        }
        (wh / "WHEELHOUSE_MANIFEST.json").write_text(
            json.dumps(wh_manifest, indent=2) + "\n", encoding="utf-8"
        )

        out_dir = ws / "bundles" / "v1.0.0"
        built = mod.build_release_bundles(
            repo_root=ws,
            output_dir=out_dir,
            from_git=False,
        )
        assert len(built) == 4
        assert (out_dir / "SHA256SUMS.txt").is_file()
        assert (out_dir / "README.md").is_file()

        verified = mod.verify_release_bundles(repo_root=ws, output_dir=out_dir)
        assert len(verified) == 4
        counts = {item["target_platform"]: item["wheel_count"] for item in verified}
        assert counts == {
            "all": 5,
            "win_amd64": 3,
            "linux_x86_64": 3,
            "macosx_arm64": 3,
        }

    def test_create_bundle_from_repo_includes_powershell_launcher_and_module_main(
        self, tmp_path: Path
    ) -> None:
        win_zip = create_bundle(
            REPO_ROOT,
            output_path=tmp_path / "repo_win.zip",
            wheelhouse=True,
            target_platform="win_amd64",
        )
        with zipfile.ZipFile(win_zip, "r") as zf:
            names = set(zf.namelist())
        assert "soclens.ps1" in names
        assert "soclens/__main__.py" in names
        assert "install_offline.ps1" in names
        assert "scripts/soclens-brand-sync.ps1" in names
        assert not any(n.endswith(".exe") and "/" not in n for n in names)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not installed")
class TestPowerShellLaunchers:
    def test_powershell_scripts_parse_cleanly(self) -> None:
        ps_cmd = (
            "$ErrorActionPreference = 'Stop'; "
            "foreach ($rel in @('soclens.ps1', 'install_offline.ps1', 'scripts/soclens-brand-sync.ps1')) { "
            "$full = (Resolve-Path (Join-Path $env:REPO_ROOT $rel)).Path; "
            "$tokens = $null; $errs = $null; "
            "[System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$errs) | Out-Null; "
            "if ($errs.Count -gt 0) { "
            "$msgs = ($errs | ForEach-Object { $_.Message }) -join '; '; "
            "throw \"Parse errors in ${rel}: $msgs\" "
            "} "
            "}"
        )
        env = {**os.environ, "REPO_ROOT": str(REPO_ROOT)}
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-Command", ps_cmd],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"

    def test_root_ps1_launcher_cli_and_argument_forwarding(self, tmp_path: Path) -> None:
        launcher = REPO_ROOT / "soclens.ps1"
        env = {**os.environ, "SOCLENS_PYTHON": sys.executable}

        for flag in ("--version", "-V"):
            proc = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(launcher), flag],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode == 0, f"stderr={proc.stderr}"
            assert proc.stdout.strip().startswith("soclens ")

        for args in (["--help"], ["validate", "--help"]):
            proc = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(launcher), *args],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode == 0, f"stderr={proc.stderr}"
            assert "usage:" in proc.stdout.lower()

        bad_proc = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(launcher), "nonexistent-subcommand"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert bad_proc.returncode != 0

        # Verify unquoted comma-lists, negative time flags, short flags, and quoted strings
        stub_ws = tmp_path / "stub_ws"
        (stub_ws / "soclens").mkdir(parents=True)
        shutil.copy2(launcher, stub_ws / "soclens.ps1")
        (stub_ws / "soclens" / "__init__.py").write_text("", encoding="utf-8")
        (stub_ws / "soclens" / "cli.py").write_text(
            "import json, sys\nprint(json.dumps(sys.argv[1:]))\n",
            encoding="utf-8",
        )

        ps_call = (
            f"& '{stub_ws / 'soclens.ps1'}' watchlist validate-logos report:abc "
            "--domains a.com,b.org --earliest-time -70m -d -V 'Cobalt Strike'"
        )
        fwd_proc = subprocess.run(
            ["pwsh", "-NoProfile", "-Command", ps_call],
            cwd=stub_ws,
            env={**os.environ, "SOCLENS_PYTHON": sys.executable},
            capture_output=True,
            text=True,
            check=False,
        )
        assert fwd_proc.returncode == 0, f"stderr={fwd_proc.stderr}\nstdout={fwd_proc.stdout}"
        assert json.loads(fwd_proc.stdout.strip()) == [
            "watchlist",
            "validate-logos",
            "report:abc",
            "--domains",
            "a.com,b.org",
            "--earliest-time",
            "-70m",
            "-d",
            "-V",
            "Cobalt Strike",
        ]

    def test_install_offline_windows_shim_replaces_exe_and_runs_via_path(
        self, tmp_path: Path
    ) -> None:
        scripts_dir = tmp_path / ".venv" / "Scripts"
        scripts_dir.mkdir(parents=True)
        for wrapper_exe in ("soclens.exe",):
            (scripts_dir / wrapper_exe).write_bytes(b"MZ-stub")

        # Provide a working Python executable in Scripts/ for cross-OS pwsh verification.
        scripts_python = scripts_dir / ("python.exe" if os.name == "nt" else "python")
        if os.name == "nt":
            shutil.copy2(sys.executable, scripts_python)
        else:
            scripts_python.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" "$@"\n',
                encoding="utf-8",
            )
            scripts_python.chmod(0o755)

        installer_path = REPO_ROOT / "install_offline.ps1"
        ps_script = (
            "$ErrorActionPreference = 'Stop'; "
            "$tokens = $null; $errs = $null; "
            "$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:INSTALLER_PATH, [ref]$tokens, [ref]$errs); "
            "if ($errs.Count -gt 0) { throw 'Failed to parse install_offline.ps1' }; "
            "$fnAst = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Install-WindowsPowerShellShims' }, $true) | Select-Object -First 1; "
            "if ($null -eq $fnAst) { throw 'Install-WindowsPowerShellShims function not found' }; "
            ". ([ScriptBlock]::Create($fnAst.Extent.Text)); "
            "Install-WindowsPowerShellShims -ScriptsDir $env:TARGET_SCRIPTS; "
            "$env:PATH = $env:TARGET_SCRIPTS + [System.IO.Path]::PathSeparator + $env:PATH; "
            "$cmd = Get-Command soclens; "
            "if ($cmd.CommandType -ne 'ExternalScript') { throw \"Expected ExternalScript, got $($cmd.CommandType)\" }; "
            "soclens --version; "
            "$rc1 = $LASTEXITCODE; "
            "soclens -V; "
            "$rc2 = $LASTEXITCODE; "
            "if ($rc1 -ne 0 -or $rc2 -ne 0) { throw \"Non-zero shim exit: $rc1 / $rc2\" }"
        )
        pythonpath_entries = [str(REPO_ROOT), *site.getsitepackages()]
        env = {
            **os.environ,
            "INSTALLER_PATH": str(installer_path),
            "TARGET_SCRIPTS": str(scripts_dir),
            "PYTHONPATH": os.pathsep.join(pythonpath_entries),
        }
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-Command", ps_script],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        assert len(lines) == 2
        assert all(ln.startswith("soclens ") for ln in lines)

        for wrapper_exe in ("soclens.exe",):
            assert not (scripts_dir / wrapper_exe).exists()

        for shim_name in ("soclens.ps1",):
            shim_path = scripts_dir / shim_name
            assert shim_path.is_file()
            shim_text = shim_path.read_text(encoding="utf-8")
            assert shim_text.isascii()
            assert "soclens.cli" in shim_text

