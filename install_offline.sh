#!/usr/bin/env bash
set -euo pipefail

# Offline / air-gapped installer for the SOCLens (soclens).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
PYTHON_EXE=""
EDITABLE=1
FORCE_RECREATE=0
SKIP_VERIFY=0
LAUNCH_TUI=0
DRY_RUN=0

usage() {
    cat <<'EOF'
Usage: ./install_offline.sh [options]

Create a Python virtual environment and install soclens plus all
dependencies strictly offline from ./wheelhouse/.

Options:
  --venv DIR         Target virtualenv directory (default: ./.venv)
  --python EXE       Explicit Python 3.12+ interpreter path
  --no-editable      Install non-editably instead of editable (-e) mode
  --force-recreate   Remove existing virtualenv before creating a fresh one
  --skip-verify      Skip post-install import verification
  --launch-tui       Launch 'soclens tui' after installation finishes
  --dry-run          Pass --dry-run when launching the TUI
  -h, --help         Show this help message and exit
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --venv)
            VENV_DIR="$2"
            shift 2
            ;;
        --python)
            PYTHON_EXE="$2"
            shift 2
            ;;
        --no-editable)
            EDITABLE=0
            shift
            ;;
        --force-recreate)
            FORCE_RECREATE=1
            shift
            ;;
        --skip-verify)
            SKIP_VERIFY=1
            shift
            ;;
        --launch-tui)
            LAUNCH_TUI=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[-] Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

WHEELHOUSE_DIR="${SCRIPT_DIR}/wheelhouse"
if [[ ! -d "${WHEELHOUSE_DIR}" ]]; then
    echo "[-] Error: Offline wheelhouse directory not found at '${WHEELHOUSE_DIR}'." >&2
    exit 1
fi

shopt -s nullglob
WHEEL_FILES=("${WHEELHOUSE_DIR}"/*.whl)
shopt -u nullglob
if [[ ${#WHEEL_FILES[@]} -eq 0 ]]; then
    echo "[-] Error: No .whl files found inside '${WHEELHOUSE_DIR}'." >&2
    exit 1
fi

export PIP_NO_INDEX=1
export PIP_FIND_LINKS="${WHEELHOUSE_DIR}"
export PIP_DISABLE_PIP_VERSION_CHECK=1
export UV_OFFLINE=1

resolve_python() {
    local candidates=()
    if [[ -n "${PYTHON_EXE}" ]]; then
        candidates=("${PYTHON_EXE}")
    else
        for cmd in python3.12 python3.13 python3.14 python3 python; do
            if command -v "${cmd}" >/dev/null 2>&1; then
                candidates+=("$(command -v "${cmd}")")
            fi
        done
    fi

    for cand in "${candidates[@]}"; do
        local resolved
        if resolved="$("${cand}" -c 'import sys; print(sys.executable); sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null)"; then
            if [[ -n "${resolved}" ]]; then
                echo "${resolved}"
                return 0
            fi
        fi
    done

    return 1
}

if ! RESOLVED_PYTHON="$(resolve_python)"; then
    if [[ -n "${PYTHON_EXE}" ]]; then
        echo "[-] Error: Python executable '${PYTHON_EXE}' is missing or older than 3.12." >&2
    else
        echo "[-] Error: Python 3.12+ is required, but no compatible interpreter was found on PATH." >&2
    fi
    exit 1
fi

echo "[*] Using Python: ${RESOLVED_PYTHON}"
echo "[*] Using offline wheelhouse: ${WHEELHOUSE_DIR} (${#WHEEL_FILES[@]} wheels)"

if [[ ${FORCE_RECREATE} -eq 1 && -d "${VENV_DIR}" ]]; then
    echo "[*] Removing existing virtual environment at '${VENV_DIR}'..."
    rm -rf "${VENV_DIR}"
fi

UV_BIN="$(command -v uv || true)"
VENV_PYTHON="${VENV_DIR}/bin/python"

if [[ ! -x "${VENV_PYTHON}" ]]; then
    echo "[*] Creating virtual environment at '${VENV_DIR}'..."
    if [[ -n "${UV_BIN}" ]]; then
        "${UV_BIN}" venv --offline --no-python-downloads --python "${RESOLVED_PYTHON}" "${VENV_DIR}"
    else
        "${RESOLVED_PYTHON}" -m venv "${VENV_DIR}"
    fi
else
    echo "[*] Reusing existing virtual environment at '${VENV_DIR}'."
fi

INSTALL_ARGS=()
if [[ ${EDITABLE} -eq 1 ]]; then
    INSTALL_ARGS+=("-e")
fi
INSTALL_ARGS+=("${SCRIPT_DIR}")

echo "[*] Installing soclens offline..."
if [[ -n "${UV_BIN}" ]]; then
    "${UV_BIN}" pip install --offline --no-index --find-links "${WHEELHOUSE_DIR}" --python "${VENV_PYTHON}" "${INSTALL_ARGS[@]}"
else
    if ! "${VENV_PYTHON}" -m pip --version >/dev/null 2>&1; then
        echo "[*] Bootstrapping pip offline via ensurepip..."
        "${VENV_PYTHON}" -m ensurepip --default-pip
    fi
    "${VENV_PYTHON}" -m pip install --no-index --find-links "${WHEELHOUSE_DIR}" "${INSTALL_ARGS[@]}"
fi

if [[ ${SKIP_VERIFY} -eq 0 ]]; then
    echo "[*] Verifying offline module imports and native extensions..."
    "${VENV_PYTHON}" -c "import soclens, soclens.cli, soclens.tui, soclens.sigma, soclens.splunk, soclens.bundler, soclens.logos, soclens.research, soclens.tui.logging_bridge, yaml, re2, jq, textual, linkify_it; assert hasattr(yaml, 'CSafeLoader'); print('OK:', soclens.__version__)"
fi

echo ""
echo "[+] Offline installation complete!"
echo "    Activate venv:  source \"${VENV_DIR}/bin/activate\""
echo "    Launch TUI:     \"${VENV_DIR}/bin/soclens\" tui"

if [[ ${LAUNCH_TUI} -eq 1 ]]; then
    TUI_ARGS=()
    if [[ ${DRY_RUN} -eq 1 ]]; then
        TUI_ARGS+=("--dry-run")
    fi
    exec "${VENV_DIR}/bin/soclens" tui "${TUI_ARGS[@]}"
fi
