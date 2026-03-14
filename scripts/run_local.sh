#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# run_local.sh — SentinelWeave local desktop launcher
#
# Sets up a Python virtual environment, installs all runtime dependencies, and
# then starts either the live web dashboard or the CLI demo mode.
#
# Usage:
#   bash scripts/run_local.sh                  # dashboard (default)
#   bash scripts/run_local.sh dashboard        # dashboard on port 5000
#   bash scripts/run_local.sh cli demo         # CLI demo with synthetic logs
#   bash scripts/run_local.sh cli analyze /var/log/auth.log
#
# Requirements:
#   - Python 3.10+ on PATH
#   - Internet access to pip-install dependencies on first run
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Locate the repo root (directory containing this script's parent) ──────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

VENV_DIR="${ROOT_DIR}/.venv"
PYTHON="${VENV_DIR}/bin/python"
PIP="${VENV_DIR}/bin/pip"
DEPS_HASH_FILE="${VENV_DIR}/.deps_hash"

# ── Colour helpers ────────────────────────────────────────────────────────────
_bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
_green() { printf '\033[32m%s\033[0m\n' "$*"; }
_cyan()  { printf '\033[36m%s\033[0m\n' "$*"; }
_warn()  { printf '\033[33mWARN: %s\033[0m\n' "$*" >&2; }

# ── 1. Python version check ───────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install Python 3.10+ and re-run." >&2
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")

if [[ "${PY_MAJOR}" -lt 3 ]] || [[ "${PY_MAJOR}" -eq 3 && "${PY_MINOR}" -lt 10 ]]; then
    echo "ERROR: Python 3.10+ required (found ${PY_VERSION})." >&2
    exit 1
fi

_bold "SentinelWeave — local desktop launcher"
_cyan "  Python    : $(python3 --version)"
_cyan "  Repo root : ${ROOT_DIR}"
echo ""

# ── 2. Create / reuse virtual environment ─────────────────────────────────────
if [[ ! -d "${VENV_DIR}" ]]; then
    _bold "Creating virtual environment at .venv ..."
    python3 -m venv "${VENV_DIR}"
fi

# ── 3. Install / upgrade dependencies ─────────────────────────────────────────
CURRENT_HASH=$(sha256sum "${ROOT_DIR}/requirements.txt" | awk '{print $1}')
STORED_HASH=""
[[ -f "${DEPS_HASH_FILE}" ]] && STORED_HASH=$(cat "${DEPS_HASH_FILE}")

if [[ "${CURRENT_HASH}" != "${STORED_HASH}" ]]; then
    _bold "Installing / updating runtime dependencies ..."
    "${PIP}" install --upgrade pip --quiet
    "${PIP}" install --quiet -r requirements.txt
    echo "${CURRENT_HASH}" > "${DEPS_HASH_FILE}"
    _green "  Dependencies up to date."
else
    _green "  Dependencies already up to date (requirements.txt unchanged)."
fi

# Optional: load .env if present
if [[ -f "${ROOT_DIR}/.env" ]]; then
    _green "  Loading credentials from .env"
    set -a
    # shellcheck source=/dev/null
    source "${ROOT_DIR}/.env"
    set +a
fi

# ── 4. Dispatch on command ─────────────────────────────────────────────────────
MODE="${1:-dashboard}"

case "${MODE}" in

  dashboard)
    PORT="${SENTINEL_PORT:-5000}"
    _bold "Starting SentinelWeave Dashboard on http://localhost:${PORT}/"
    echo "  Press Ctrl+C to stop."
    echo ""
    PYTHONPATH="${ROOT_DIR}" "${PYTHON}" -m dashboard \
        --host 127.0.0.1 \
        --port "${PORT}"
    ;;

  cli)
    shift  # drop "cli" from args
    _bold "Running SentinelWeave CLI: $*"
    echo ""
    PYTHONPATH="${ROOT_DIR}" "${PYTHON}" -m sentinel_weave "$@"
    ;;

  *)
    echo "Usage: $0 [dashboard|cli <args>]" >&2
    exit 1
    ;;

esac
