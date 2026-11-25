# Contributing to SOCLens

Thank you for your interest in contributing!

## Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/justsean9/soclens.git
   cd soclens
   ```
2. Create a Python 3.12+ virtual environment and install dev dependencies:
   ```bash
   uv sync --dev
   # or with pip:
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

## Quality Checks

Before opening a pull request, ensure linting, type-checking, and tests pass:

```bash
ruff check .
mypy soclens
pytest
```

## Guidelines

- **Python 3.12+** with type annotations and PEP 8 compliance (`ruff` line length 100).
- **Cross-platform paths**: Use `pathlib.Path` or `os.path` so changes work on Linux, macOS, and Windows.
- **No secrets or real tenant data**: Never commit API tokens, `.key` files, internal URLs, or real organization watchlist/report IDs. Use synthetic/mock fixtures in tests.
- **Offline readiness**: Core functionality and tests should not assume external network access unless explicitly testing live integrations.
- **Tests**: Add unit tests (and E2E/TUI tests where applicable) for new features and bug fixes.

## Pull Requests

1. Create a descriptive branch (`feat/...`, `fix/...`, `docs/...`).
2. Keep commits focused and descriptive.
3. Fill out the pull request template and link any related issues.
