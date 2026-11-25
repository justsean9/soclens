from pathlib import Path

from soclens.utils import (
    DEFAULT_BUNDLE_FILENAME,
    create_bundle,
    discover_runtime_dependencies,
)


def test_utils_reexports_create_bundle(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    (workspace / "soclens").mkdir(parents=True)
    (workspace / "soclens" / "__init__.py").write_text('__version__ = "1.0.0"\n', encoding="utf-8")
    (workspace / "README.md").write_text("# Test\n", encoding="utf-8")
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "soclens"\ndependencies = ["requests"]\n',
        encoding="utf-8",
    )

    result = create_bundle(str(workspace))
    assert isinstance(result, Path)
    assert result == (workspace / DEFAULT_BUNDLE_FILENAME).resolve()
    assert result.is_file()
    assert discover_runtime_dependencies is not None
