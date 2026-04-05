#!/usr/bin/env bash
# setup-unix.sh — One-command setup for Olympus on Unix/macOS.
#
# Usage:
#   ./setup-unix.sh                              # full setup + start API
#   ./setup-unix.sh --db-user myuser --db-password s3cr3t
#   ./setup-unix.sh --skip-docker                # skip PostgreSQL container step
#   ./setup-unix.sh --skip-start                 # set up everything, do not start API
#
# Requirements: Docker, Python 3.10+

set -euo pipefail

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
SKIP_DOCKER=false
SKIP_START=false
DB_USER="olympus"
DB_PASSWORD="olympus"

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-docker)  SKIP_DOCKER=true; shift ;;
        --skip-start)   SKIP_START=true;  shift ;;
        --db-user)
            [ $# -ge 2 ] || { echo "Error: --db-user requires a value"; exit 1; }
            DB_USER="$2"; shift 2 ;;
        --db-password)
            [ $# -ge 2 ] || { echo "Error: --db-password requires a value"; exit 1; }
            DB_PASSWORD="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--db-user USER] [--db-password PASS] [--skip-docker] [--skip-start]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Colour helpers (no-op when stdout is not a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    _CYAN='\033[0;36m'  _GREEN='\033[0;32m'
    _YELLOW='\033[1;33m' _RED='\033[0;31m' _RESET='\033[0m'
else
    _CYAN='' _GREEN='' _YELLOW='' _RED='' _RESET=''
fi
step()  { echo -e "\n${_CYAN}▶  $*${_RESET}"; }
ok()    { echo -e "   ${_GREEN}✓  $*${_RESET}"; }
warn()  { echo -e "   ${_YELLOW}⚠  $*${_RESET}"; }
fail()  { echo -e "\n${_RED}✘  $*${_RESET}"; exit 1; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo ""
echo -e "${_CYAN}╔══════════════════════════════════════════════════╗${_RESET}"
echo -e "${_CYAN}║     Olympus — one-command setup (Unix/macOS)     ║${_RESET}"
echo -e "${_CYAN}╚══════════════════════════════════════════════════╝${_RESET}"

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------
step "Checking prerequisites"

# Python 3.10+
PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" --version 2>&1 | grep -oE "[0-9]+\.[0-9]+")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done
if [ -z "$PYTHON_CMD" ]; then
    fail "Python 3.10+ not found. Install it from https://python.org and re-run."
fi
ok "$($PYTHON_CMD --version)"

# Docker
if [ "$SKIP_DOCKER" = false ]; then
    if ! command -v docker &>/dev/null; then
        fail "Docker not found. Install Docker from https://docs.docker.com/get-docker/ and re-run."
    fi
    ok "$(docker --version)"
fi

# ---------------------------------------------------------------------------
# 2. PostgreSQL via Docker
# ---------------------------------------------------------------------------
if [ "$SKIP_DOCKER" = false ]; then
    step "Starting PostgreSQL (Docker)"

    if docker ps --filter "name=olympus-postgres" --format "{{.Names}}" | grep -q "^olympus-postgres$"; then
        ok "Container 'olympus-postgres' is already running — reusing it."
    else
        # Remove stopped container with same name, if any
        if docker ps -a --filter "name=olympus-postgres" --format "{{.Names}}" | grep -q "^olympus-postgres$"; then
            warn "Removing stopped 'olympus-postgres' container..."
            docker rm olympus-postgres >/dev/null
        fi

        docker run \
            --name olympus-postgres \
            -e POSTGRES_USER="$DB_USER" \
            -e POSTGRES_PASSWORD="$DB_PASSWORD" \
            -e POSTGRES_DB=olympus \
            -p 5432:5432 \
            -d postgres:16 >/dev/null

        ok "Container started — waiting up to 30 s for Postgres to be ready..."
        ready=false
        for i in $(seq 1 30); do
            sleep 1
            if docker exec olympus-postgres pg_isready -U "$DB_USER" -d olympus &>/dev/null; then
                ready=true
                break
            fi
        done
        if [ "$ready" = false ]; then
            fail "Postgres did not become ready in 30 s. Run: docker logs olympus-postgres"
        fi
        ok "PostgreSQL is ready."
    fi
fi

# ---------------------------------------------------------------------------
# 3. Environment variables
# ---------------------------------------------------------------------------
step "Setting environment variables"

if [ -z "${DATABASE_URL:-}" ]; then
    export DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@localhost:5432/olympus"
    ok "DATABASE_URL set to postgresql://${DB_USER}:***@localhost:5432/olympus"
else
    ok "DATABASE_URL already set — using existing value."
fi

if [ -z "${OLYMPUS_INGEST_SIGNING_KEY:-}" ]; then
    # Generate a random 32-byte key (hex-encoded)
    if command -v openssl &>/dev/null; then
        export OLYMPUS_INGEST_SIGNING_KEY="$(openssl rand -hex 32)"
    elif [ -r /dev/urandom ]; then
        _raw_key="$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
        # Validate the key is exactly 64 hex characters before using it
        if [ ${#_raw_key} -ne 64 ]; then
            fail "Generated signing key has unexpected length (${#_raw_key}). Install openssl and re-run."
        fi
        export OLYMPUS_INGEST_SIGNING_KEY="$_raw_key"
    else
        fail "Cannot generate a random signing key — install openssl or use /dev/urandom."
    fi
    ok "OLYMPUS_INGEST_SIGNING_KEY generated (random 32-byte key)."
    warn "Persist this key in your .env file to keep ledger entries verifiable:"
    echo "   OLYMPUS_INGEST_SIGNING_KEY=${OLYMPUS_INGEST_SIGNING_KEY}"
else
    ok "OLYMPUS_INGEST_SIGNING_KEY already set — using existing value."
fi

# Write .env file for subsequent runs
ENV_FILE="$REPO_ROOT/.env"
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<EOF
# Auto-generated by setup-unix.sh — edit as needed.
DATABASE_URL=${DATABASE_URL}
OLYMPUS_INGEST_SIGNING_KEY=${OLYMPUS_INGEST_SIGNING_KEY}
OLYMPUS_DEV_SIGNING_KEY=false
EOF
    ok ".env file written to $ENV_FILE"
else
    ok ".env already exists — not overwriting."
fi

# ---------------------------------------------------------------------------
# 4. Python virtual environment
# ---------------------------------------------------------------------------
step "Setting up Python virtual environment"

VENV_DIR="$REPO_ROOT/.venv"
if [ ! -d "$VENV_DIR" ]; then
    "$PYTHON_CMD" -m venv "$VENV_DIR"
    ok "Virtual environment created at .venv"
else
    ok "Virtual environment already exists at .venv"
fi

# Activate
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Virtual environment activated."

# ---------------------------------------------------------------------------
# 5. Install dependencies
# ---------------------------------------------------------------------------
step "Installing Python dependencies (this may take a few minutes)"

python -m pip install --upgrade pip --quiet
pip install --quiet -r requirements.txt
if [ -f requirements-dev.txt ]; then
    pip install --quiet -r requirements-dev.txt
fi
if pip install --quiet -e ".[dev]" 2>/dev/null; then
    :  # [dev] extra installed successfully
else
    pip install --quiet -e .
fi
ok "Dependencies installed."

# ---------------------------------------------------------------------------
# 6. Database migrations
# ---------------------------------------------------------------------------
step "Running Alembic database migrations"

python -m alembic upgrade head || \
    fail "Alembic migration failed. Check DATABASE_URL and that PostgreSQL is reachable."
ok "Database schema is up to date."

# ---------------------------------------------------------------------------
# 7. Success summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${_GREEN}╔══════════════════════════════════════════════════╗${_RESET}"
echo -e "${_GREEN}║               Setup complete! 🎉                 ║${_RESET}"
echo -e "${_GREEN}╠══════════════════════════════════════════════════╣${_RESET}"
echo -e "${_GREEN}║  API:      http://localhost:8000                 ║${_RESET}"
echo -e "${_GREEN}║  API docs: http://localhost:8000/docs            ║${_RESET}"
echo -e "${_GREEN}║  Database: postgresql://${DB_USER}@localhost:5432   ║${_RESET}"
echo -e "${_GREEN}╚══════════════════════════════════════════════════╝${_RESET}"

if [ "$SKIP_START" = true ]; then
    echo ""
    echo -e "${_CYAN}To start the API later run:${_RESET}"
    echo "  source .venv/bin/activate"
    echo "  uvicorn api.app:app --reload --host 0.0.0.0 --port 8000"
    exit 0
fi

# ---------------------------------------------------------------------------
# 8. Start API server
# ---------------------------------------------------------------------------
echo ""
echo -e "${_CYAN}Starting API server — press Ctrl+C to stop.${_RESET}"
echo ""

exec uvicorn api.app:app --reload --host 0.0.0.0 --port 8000
