#!/bin/sh
# Olympus API startup script
#
# Runs Alembic migrations with retry/diagnostic logic before launching
# the API server. Exits non-zero on migration failure so the container
# is marked unhealthy instead of silently serving a broken state.
#
# Usage (set as the command in docker-compose.yml or Dockerfile CMD):
#   /app/scripts/startup.sh

set -e

log() {
    echo "[startup] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
}

log "Starting Olympus API container..."
log "DATABASE_URL scheme: $(echo "${DATABASE_URL:-<not set>}" | sed 's|://.*|://...|')"

# Wait for the database to accept connections (up to 30 s).
# pg_isready is available via the postgresql-client apt package in the image.
if [ -n "${DATABASE_URL}" ]; then
    # Extract host and port from DATABASE_URL  (e.g. postgresql+asyncpg://user:pass@host:5432/db)
    DB_HOST=$(echo "$DATABASE_URL" | sed -E 's|.*@([^:/]+).*|\1|')
    DB_PORT=$(echo "$DATABASE_URL" | sed -E 's|.*:([0-9]+)/.*|\1|')
    DB_PORT="${DB_PORT:-5432}"

    log "Waiting for database at ${DB_HOST}:${DB_PORT}..."
    RETRIES=15
    until pg_isready -h "${DB_HOST}" -p "${DB_PORT}" -q 2>/dev/null || [ "$RETRIES" -eq 0 ]; do
        log "  Database not ready yet — retrying in 2 s (${RETRIES} attempt(s) left)..."
        RETRIES=$((RETRIES - 1))
        sleep 2
    done

    if [ "$RETRIES" -eq 0 ]; then
        log "ERROR: Database did not become ready in time."
        log "  HOST=${DB_HOST}  PORT=${DB_PORT}"
        log "  Check that the db service is healthy and that DATABASE_URL is correct."
        exit 1
    fi
    log "Database is accepting connections."
fi

# Run Alembic migrations and capture output.
log "Running database migrations (alembic upgrade head)..."
if ! python -m alembic upgrade head; then
    log "ERROR: Migration failed — the API will not start."
    log "  Possible causes:"
    log "    - DATABASE_URL has incorrect credentials or host"
    log "    - The .env file uses CRLF line endings (use LF on Windows)"
    log "    - A migration script has a syntax error"
    log "  Re-run with: docker compose exec app python -m alembic upgrade head"
    exit 1
fi
log "Migrations completed successfully."

# Hand off to the API server.
log "Starting uvicorn (api.main:app) on 0.0.0.0:8000..."
exec uvicorn api.main:app --host 0.0.0.0 --port 8000
