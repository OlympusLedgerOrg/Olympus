#!/usr/bin/env bash
# scripts/bootstrap.sh — first-boot helper for self-hosted Olympus.
#
# Why this script exists
# ----------------------
# A fresh self-hoster used to hit two cliffs the very first time they ran
# `docker compose up`:
#
#   1. The top-level `secrets: db_password: external: true` declaration
#      meant compose refused to start until the operator manually ran
#      `docker secret create db_password -` (which only works in Swarm
#      mode anyway).
#   2. There was no `.env` file, so any required variable (for example
#      OLYMPUS_NODE_REHASH_GATE_SECRET) caused the app or db to crash.
#
# This script makes both of those go away:
#
#   * Generates ./secrets/db_password (random, 0600) if it doesn't exist.
#     docker-compose.yml now mounts this file as the `db_password` Docker
#     secret — both `db` (POSTGRES_PASSWORD_FILE) and the app/sequencer-go
#     services read it from /run/secrets/db_password.
#   * Copies .env.example to .env if .env doesn't exist and fills in:
#       - POSTGRES_PASSWORD / DATABASE_URL / PSYCOPG_URL with the same
#         random password so the SQLAlchemy URL stays in sync with the
#         Docker secret.
#       - OLYMPUS_NODE_REHASH_GATE_SECRET (required in production)
#       - OLYMPUS_SEQUENCER_TOKEN (required if the sequencer profile is used)
#
# The script is idempotent: re-running it never overwrites a secret or an
# existing .env value. Safe to run any time you want to make sure your
# local checkout is bootstrapped.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

log() { printf '[bootstrap] %s\n' "$*" >&2; }

# Track all temp files we create so an `set -e` exit (or interrupt)
# doesn't leave them lying around in /tmp.
_tmp_files=()
_cleanup_tmp() {
    if [ ${#_tmp_files[@]} -gt 0 ]; then
        rm -f "${_tmp_files[@]}"
    fi
}
trap _cleanup_tmp EXIT INT TERM

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "ERROR: required command '$1' is not installed."
        exit 1
    fi
}

require_cmd openssl

SECRETS_DIR="${REPO_ROOT}/secrets"
DB_PASSWORD_FILE="${SECRETS_DIR}/db_password"
ENV_FILE="${REPO_ROOT}/.env"
ENV_EXAMPLE="${REPO_ROOT}/.env.example"

# ---------------------------------------------------------------------------
# 1. Database password secret
# ---------------------------------------------------------------------------

mkdir -p "${SECRETS_DIR}"
chmod 700 "${SECRETS_DIR}"

if [ -f "${DB_PASSWORD_FILE}" ]; then
    log "secrets/db_password already exists — keeping the existing password."
else
    log "Generating a new random database password at secrets/db_password..."
    # We want a 40-char password from a URL-safe alphabet (no `+`, `/`,
    # `=`) so it can drop straight into a postgresql:// URL without
    # percent-encoding.
    #
    # `openssl rand -base64 30` would produce exactly 40 base64 chars, but
    # base64 includes `+` and `/`; stripping those leaves a shorter,
    # variable-length string. Generating 6 extra random bytes (36 total →
    # ~48 base64 chars) and then truncating to 40 after the strip
    # guarantees we always have 40 chars regardless of how many `+`/`/`
    # the random draw happened to contain.
    #
    # Entropy: 40 chars × ~6 bits each ≈ 240 bits, well above the
    # 128-bit symmetric-strength target.
    readonly PASSWORD_LENGTH=40
    DB_PASSWORD="$(openssl rand -base64 36 | tr -d '=+/' | cut -c1-${PASSWORD_LENGTH})"
    if [ "${#DB_PASSWORD}" -ne "${PASSWORD_LENGTH}" ]; then
        log "ERROR: generated password is ${#DB_PASSWORD} chars, expected ${PASSWORD_LENGTH}."
        log "       openssl produced too few URL-safe chars — try re-running."
        exit 1
    fi
    # Use printf without trailing newline. The Go and Python loaders both
    # tolerate a trailing newline, but omitting it keeps the file byte-clean.
    umask 077
    printf '%s' "${DB_PASSWORD}" > "${DB_PASSWORD_FILE}"
    chmod 600 "${DB_PASSWORD_FILE}"
    log "Wrote secrets/db_password (mode 600)."
fi

# Read the password back so downstream .env edits stay in sync regardless
# of whether we just created it or it already existed.
DB_PASSWORD="$(cat "${DB_PASSWORD_FILE}")"

# ---------------------------------------------------------------------------
# 2. .env file
# ---------------------------------------------------------------------------

if [ ! -f "${ENV_EXAMPLE}" ]; then
    log "ERROR: .env.example is missing — repository looks broken."
    exit 1
fi

if [ -f "${ENV_FILE}" ]; then
    log ".env already exists — preserving it (only filling in blank required values)."
else
    log "Copying .env.example -> .env..."
    cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"
fi

# Helper: set KEY=VALUE in .env. If KEY is already set to a non-empty,
# non-placeholder value, leave it alone (operator overrides win).
# Otherwise, write our value.
#
# A "blank" value is one of:
#   - line absent from the file
#   - KEY=  (empty)
#   - KEY=<value containing the .env.example placeholder string>
#     (covers both the bare placeholder and connection strings like
#      postgresql://user:change_me_use_a_strong_random_password@host/db)
set_env_if_blank() {
    local key="$1" value="$2" placeholder
    placeholder="change_me_use_a_strong_random_password"

    if grep -Eq "^${key}=" "${ENV_FILE}"; then
        # Pull the current value: everything after the first '='.
        local current
        current="$(grep -E "^${key}=" "${ENV_FILE}" | head -n1 | cut -d= -f2-)"
        if [ -n "${current}" ] && ! printf '%s' "${current}" | grep -q "${placeholder}"; then
            return 0
        fi
        # Replace the existing line in place. Use awk to avoid sed delimiter
        # quoting issues with the random/hex values we generate.
        local tmp
        tmp="$(mktemp)"
        _tmp_files+=("${tmp}")
        awk -v k="${key}" -v v="${value}" '
            BEGIN { found = 0 }
            $0 ~ "^"k"=" { print k"="v; found = 1; next }
            { print }
            END { if (!found) print k"="v }
        ' "${ENV_FILE}" > "${tmp}"
        mv "${tmp}" "${ENV_FILE}"
        chmod 600 "${ENV_FILE}"
    else
        printf '%s=%s\n' "${key}" "${value}" >> "${ENV_FILE}"
    fi
}

# Sync the Postgres password into .env so a developer running uvicorn
# directly (not via docker compose) connects with the same credentials
# the db container is using.
set_env_if_blank "POSTGRES_PASSWORD" "${DB_PASSWORD}"

# Provide a working DATABASE_URL / PSYCOPG_URL out of the box. These point
# at the dockerised db (host=db, port=5432) and use the user/db_name
# defaults from .env.example. Operators running outside docker compose
# should override them.
DEFAULT_USER="$(grep -E '^DATABASE_USER=' "${ENV_FILE}" | head -n1 | cut -d= -f2- || true)"
DEFAULT_USER="${DEFAULT_USER:-olympus_user}"
DEFAULT_DB="$(grep -E '^DATABASE_NAME=' "${ENV_FILE}" | head -n1 | cut -d= -f2- || true)"
DEFAULT_DB="${DEFAULT_DB:-olympus}"

set_env_if_blank "DATABASE_URL" \
    "postgresql+asyncpg://${DEFAULT_USER}:${DB_PASSWORD}@db:5432/${DEFAULT_DB}"
set_env_if_blank "PSYCOPG_URL" \
    "postgresql://${DEFAULT_USER}:${DB_PASSWORD}@db:5432/${DEFAULT_DB}"

# Production-required random tokens. These are unrelated to the DB
# password but are the other "first-boot crashers" if left blank.
if [ -z "$(grep -E '^OLYMPUS_NODE_REHASH_GATE_SECRET=' "${ENV_FILE}" | head -n1 | cut -d= -f2- || true)" ]; then
    GATE_SECRET="$(openssl rand -hex 32)"
    set_env_if_blank "OLYMPUS_NODE_REHASH_GATE_SECRET" "${GATE_SECRET}"
    log "Generated OLYMPUS_NODE_REHASH_GATE_SECRET."
fi

if [ -z "$(grep -E '^OLYMPUS_SEQUENCER_TOKEN=' "${ENV_FILE}" | head -n1 | cut -d= -f2- || true)" ]; then
    SEQ_TOKEN="$(openssl rand -hex 32)"
    set_env_if_blank "OLYMPUS_SEQUENCER_TOKEN" "${SEQ_TOKEN}"
    log "Generated OLYMPUS_SEQUENCER_TOKEN."
fi

log "Bootstrap complete."
log ""
log "Next steps:"
log "  1. Review .env and fill in any remaining placeholders"
log "     (CORS_ORIGINS, OLYMPUS_DOMAIN, ACME_EMAIL, ANTHROPIC_API_KEY, ...)."
log "  2. Bring the stack up:"
log "       docker compose up -d"
log "     Or, with the Go sequencer profile:"
log "       docker compose --profile sequencer up -d"
