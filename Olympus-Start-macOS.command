#!/usr/bin/env bash
# Finder double-click launcher for Olympus on macOS.
#
# Usage:
#   Double-click this file in Finder, or run:
#     ./Olympus-Start-macOS.command
#
# Optional environment variables:
#   OLYMPUS_SKIP_SETUP=1  Skip setup-unix.sh --skip-start
#   OLYMPUS_SKIP_UI=1     Skip the public UX server
#   OLYMPUS_API_PORT=8000 Override API port
#   OLYMPUS_UI_PORT=5173  Override public UX port

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

API_PORT="${OLYMPUS_API_PORT:-8000}"
UI_PORT="${OLYMPUS_UI_PORT:-5173}"
UI_PID=""

log() {
    printf '[olympus] %s\n' "$*"
}

fail() {
    printf '\n[olympus] ERROR: %s\n' "$*" >&2
    printf '[olympus] Press Return to close this window.\n' >&2
    read -r _ || true
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

load_dotenv() {
    local env_file="$1"
    local line key value

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$line" in
            ''|\#*) continue ;;
            *=*) ;;
            *) continue ;;
        esac

        key="${line%%=*}"
        value="${line#*=}"

        if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            export "$key=$value"
        fi
    done < "$env_file"
}

cleanup() {
    if [ -n "$UI_PID" ] && kill -0 "$UI_PID" >/dev/null 2>&1; then
        log "Stopping public UX server..."
        kill "$UI_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

log "Starting Olympus from $REPO_ROOT"

if [ "${OLYMPUS_SKIP_SETUP:-0}" != "1" ]; then
    [ -f "$REPO_ROOT/setup-unix.sh" ] || fail "setup-unix.sh was not found."
    log "Preparing local stack with setup-unix.sh --skip-start..."
    bash "$REPO_ROOT/setup-unix.sh" --skip-start
else
    log "Skipping setup because OLYMPUS_SKIP_SETUP=1."
fi

if [ -f "$REPO_ROOT/.env" ]; then
    log "Loading .env for this Terminal session."
    load_dotenv "$REPO_ROOT/.env"
fi

if [ -z "${DATABASE_URL:-}" ]; then
    export DATABASE_URL="postgresql://olympus:olympus@localhost:5432/olympus"
fi

if [ "${OLYMPUS_FORCE_LOCAL_DB_URL:-1}" = "1" ]; then
    export DATABASE_URL="${DATABASE_URL//@db:/@localhost:}"
    if [ -n "${PSYCOPG_URL:-}" ]; then
        export PSYCOPG_URL="${PSYCOPG_URL//@db:/@localhost:}"
    fi
fi

if [ -d "$REPO_ROOT/.venv" ]; then
    # shellcheck disable=SC1091
    . "$REPO_ROOT/.venv/bin/activate"
else
    fail "Python virtual environment was not found at .venv. Re-run without OLYMPUS_SKIP_SETUP=1."
fi

if [ "${OLYMPUS_SKIP_UI:-0}" != "1" ]; then
    UI_DIR="$REPO_ROOT/app/public-ui"
    [ -d "$UI_DIR" ] || fail "Public UX directory was not found at app/public-ui."
    command_exists npm || fail "npm was not found. Install Node.js, then double-click this launcher again."

    log "Installing public UX dependencies if needed..."
    (
        cd "$UI_DIR"
        if [ -f package-lock.json ]; then
            npm ci --legacy-peer-deps --no-audit --no-fund
        else
            npm install --legacy-peer-deps --no-audit --no-fund
        fi
    )

    log "Starting public UX at http://localhost:${UI_PORT}..."
    (
        cd "$UI_DIR"
        export VITE_API_BASE="http://localhost:${API_PORT}"
        export VITE_API_BASE_URL="http://localhost:${API_PORT}"
        npm run dev -- --host 127.0.0.1 --port "$UI_PORT"
    ) &
    UI_PID="$!"

    sleep 2
    if command_exists open; then
        open "http://localhost:${UI_PORT}" >/dev/null 2>&1 || true
    fi
else
    log "Skipping public UX because OLYMPUS_SKIP_UI=1."
fi

log "Starting API at http://localhost:${API_PORT}"
log "Leave this Terminal window open. Press Ctrl+C to stop Olympus."
exec uvicorn api.app:app --reload --host 0.0.0.0 --port "$API_PORT"
