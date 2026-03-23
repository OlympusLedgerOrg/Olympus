#!/bin/sh
# Olympus API startup script
#
# Waits for the database to accept connections, then launches the API server.
# Database schema is created automatically at startup — no manual migration
# step is required.
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

# Hand off to the API server.
# Schema is created automatically on first request via StorageLayer.init_schema()
# (protocol tables) and Base.metadata.create_all (FOIA tables in api/main.py).
log "Starting uvicorn (api.main:app) on 0.0.0.0:8000..."
exec uvicorn api.main:app --host 0.0.0.0 --port 8000
