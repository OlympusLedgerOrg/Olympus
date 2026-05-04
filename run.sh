#!/usr/bin/env bash
# run.sh — One-command setup and start for Olympus (Unix/macOS).
#
# Usage:
#   chmod +x run.sh && ./run.sh
#
# Options:
#   --skip-docker   Skip PostgreSQL Docker container step
#   --skip-start    Set up everything but do not start the API server
#   --db-user USER  PostgreSQL username (default: olympus)
#   --db-pass PASS  PostgreSQL password (default: olympus)

set -euo pipefail

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
SKIP_DOCKER=false
SKIP_START=false
DB_USER="olympus"
DB_PASS="olympus"

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-docker) SKIP_DOCKER=true; shift ;;
        --skip-start)  SKIP_START=true;  shift ;;
        --db-user)
            [ $# -ge 2 ] || { echo "ERROR: --db-user requires a value"; exit 1; }
            DB_USER="$2"; shift 2 ;;
        --db-pass)
            [ $# -ge 2 ] || { echo "ERROR: --db-pass requires a value"; exit 1; }
            DB_PASS="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | head -10 | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown option: $1 (use --help for usage)"; exit 1 ;;
    esac
done

# Change to the directory the script is in
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Colour helpers (no-op when not a TTY)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C='\033[0;36m' G='\033[0;32m' Y='\033[1;33m' R='\033[0;31m' N='\033[0m'
else
    C='' G='' Y='' R='' N=''
fi
info()  { echo -e "\n${C}[▶] $*${N}"; }
ok()    { echo -e "    ${G}✓  $*${N}"; }
warn()  { echo -e "    ${Y}⚠  $*${N}"; }
die()   { echo -e "\n${R}[✘] $*${N}"; exit 1; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo ""
echo -e "${C}=================================================${N}"
echo -e "${C}   Olympus -- One-Command Setup (Unix/macOS)   ${N}"
echo -e "${C}=================================================${N}"

# ---------------------------------------------------------------------------
# 1. Check Python 3.10-3.13
# ---------------------------------------------------------------------------
info "Checking Python..."

PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" --version 2>&1 | grep -oE "[0-9]+\.[0-9]+")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -eq 3 ] && [ "$minor" -ge 10 ] && [ "$minor" -le 13 ]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done
[ -n "$PYTHON_CMD" ] || die "Python 3.10-3.13 not found. Install from https://python.org and re-run."
ok "$($PYTHON_CMD --version)"

# ---------------------------------------------------------------------------
# 2. Start PostgreSQL via Docker
# ---------------------------------------------------------------------------
if [ "$SKIP_DOCKER" = false ] && [ -z "${DATABASE_URL:-}" ]; then
    info "Starting PostgreSQL (Docker)..."

    if ! command -v docker &>/dev/null; then
        warn "Docker not found. Skipping PostgreSQL container."
        warn "Set DATABASE_URL if you have PostgreSQL running elsewhere."
    else
        if docker ps --filter "name=olympus-postgres" --format "{{.Names}}" 2>/dev/null | grep -q "^olympus-postgres$"; then
            ok "olympus-postgres container already running."
        else
            # Remove stopped container with same name if any
            if docker ps -a --filter "name=olympus-postgres" --format "{{.Names}}" 2>/dev/null | grep -q "^olympus-postgres$"; then
                warn "Removing stopped olympus-postgres container..."
                docker rm olympus-postgres >/dev/null
            fi

            docker run \
                --name olympus-postgres \
                -e POSTGRES_USER="$DB_USER" \
                -e POSTGRES_PASSWORD="$DB_PASS" \
                -e POSTGRES_DB=olympus \
                -p 5432:5432 \
                -d postgres:16 >/dev/null

            ok "Container started, waiting for PostgreSQL to be ready (up to 30 s)..."
            ready=false
            for _ in $(seq 1 30); do
                sleep 1
                if docker exec olympus-postgres pg_isready -U "$DB_USER" -d olympus &>/dev/null; then
                    ready=true
                    break
                fi
            done
            [ "$ready" = true ] || die "PostgreSQL did not become ready. Check: docker logs olympus-postgres"
            ok "PostgreSQL is ready."
        fi
    fi
elif [ "$SKIP_DOCKER" = true ]; then
    info "Skipping Docker step (--skip-docker)."
else
    info "DATABASE_URL already set -- skipping Docker step."
fi

# ---------------------------------------------------------------------------
# 3. Set environment variables
# ---------------------------------------------------------------------------
info "Setting environment variables..."

if [ -z "${DATABASE_URL:-}" ]; then
    export DATABASE_URL="postgresql://${DB_USER}:${DB_PASS}@localhost:5432/olympus"
    ok "DATABASE_URL=postgresql://${DB_USER}:***@localhost:5432/olympus"
else
    ok "Using existing DATABASE_URL."
fi

if [ -z "${OLYMPUS_INGEST_SIGNING_KEY:-}" ]; then
    if command -v openssl &>/dev/null; then
        export OLYMPUS_INGEST_SIGNING_KEY="$(openssl rand -hex 32)"
    elif [ -r /dev/urandom ]; then
        _raw="$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
        [ "${#_raw}" -eq 64 ] || die "Key generation failed. Install openssl and re-run."
        export OLYMPUS_INGEST_SIGNING_KEY="$_raw"
    else
        die "Cannot generate signing key. Install openssl and re-run."
    fi
    ok "OLYMPUS_INGEST_SIGNING_KEY generated."
    warn "Save this key in .env to keep ledger entries verifiable:"
    echo "    OLYMPUS_INGEST_SIGNING_KEY=${OLYMPUS_INGEST_SIGNING_KEY}"
else
    ok "Using existing OLYMPUS_INGEST_SIGNING_KEY."
fi

# Write .env file on first run
if [ ! -f ".env" ]; then
    cat > ".env" <<EOF
# Auto-generated by run.sh -- edit as needed.
DATABASE_URL=${DATABASE_URL}
OLYMPUS_INGEST_SIGNING_KEY=${OLYMPUS_INGEST_SIGNING_KEY}
OLYMPUS_DEV_SIGNING_KEY=false
EOF
    ok ".env written to $REPO_ROOT/.env"
else
    ok ".env already exists -- not overwriting."
fi

# ---------------------------------------------------------------------------
# 4. Python virtual environment
# ---------------------------------------------------------------------------
info "Setting up virtual environment..."

if [ ! -d ".venv" ]; then
    "$PYTHON_CMD" -m venv .venv
    ok "Virtual environment created at .venv"
else
    ok "Virtual environment already exists."
fi

# shellcheck disable=SC1091
source .venv/bin/activate
ok "Virtual environment activated."

# ---------------------------------------------------------------------------
# 5. Install dependencies
# ---------------------------------------------------------------------------
info "Installing dependencies (may take a few minutes)..."

python -m pip install --upgrade pip --quiet

# Install the package with its dev extras directly from pyproject.toml.
# Using pip install -e ".[dev]" avoids hash-checking conflicts that occur
# when combining a hashed requirements.txt with an editable install.
if pip install -e ".[dev]" --quiet; then
    ok "Dependencies installed."
else
    warn "[dev] extra failed, retrying without it..."
    pip install -e . --quiet
    ok "Dependencies installed (without dev extras)."
fi

# ---------------------------------------------------------------------------
# 6. Database migrations
# ---------------------------------------------------------------------------
info "Running Alembic database migrations..."

python -m alembic upgrade head || \
    die "Alembic migration failed. Check DATABASE_URL and that PostgreSQL is reachable.\n    DATABASE_URL=${DATABASE_URL}"
ok "Database schema is up to date."

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${G}=================================================${N}"
echo -e "${G}   Olympus is ready!                            ${N}"
echo -e "${G}                                                ${N}"
echo -e "${G}   API:      http://localhost:8000              ${N}"
echo -e "${G}   API Docs: http://localhost:8000/docs         ${N}"
echo -e "${G}   Database: ${DATABASE_URL}                   ${N}"
echo -e "${G}=================================================${N}"

if [ "$SKIP_START" = true ]; then
    echo ""
    echo -e "${C}To start the API later:${N}"
    echo "  source .venv/bin/activate"
    echo "  python -m uvicorn api.app:app --reload --host 0.0.0.0 --port 8000"
    exit 0
fi

# ---------------------------------------------------------------------------
# 8. Start API server
# ---------------------------------------------------------------------------
echo ""
echo -e "${C}Starting API server -- press Ctrl+C to stop.${N}"
echo ""

exec python -m uvicorn api.app:app --reload --host 0.0.0.0 --port 8000
