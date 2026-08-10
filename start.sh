#!/usr/bin/env bash
# Olympus Ledger launcher (Linux / macOS / WSL).
#
# Mirrors start.bat: builds the release binary if missing, then runs it.
# On WSL it also applies webkit2gtk workarounds that turn the otherwise
# jittery software-rendered UI into a responsive one.
#
# Usage: ./start.sh
#
# To skip the build (e.g. you're iterating with `cargo tauri dev` and
# only want to launch a pre-built binary): NO_BUILD=1 ./start.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${REPO_ROOT}"

EXE="${REPO_ROOT}/target/release/olympus-desktop"

# ── Source ./.env if the user has one (env-var overrides for keys, port, etc.) ─
# OLYMPUS_ENV is the one deliberate exception to ".env wins". It selects the
# fail-closed production gates, so a caller who asks for production explicitly
# must not be downgraded by a development .env sitting in the working tree.
# Remember what the caller passed and restore it after sourcing.
OLYMPUS_ENV_FROM_CALLER="${OLYMPUS_ENV:-}"
if [ -f "${REPO_ROOT}/.env" ]; then
    # `set -a` exports every variable assigned by .env without requiring
    # the user to `export` each line. Safe because .env should only
    # contain key=value pairs, no command substitutions.
    set -a
    # shellcheck disable=SC1091
    . "${REPO_ROOT}/.env"
    set +a
fi
if [ -n "${OLYMPUS_ENV_FROM_CALLER}" ]; then
    OLYMPUS_ENV="${OLYMPUS_ENV_FROM_CALLER}"
fi
unset OLYMPUS_ENV_FROM_CALLER

# ── WSL detection + webkit2gtk perf workarounds ────────────────────────────────
# WSL's compositor (WSLg → RDP-backed wayland) doesn't expose a usable GL
# device to webkit, so it falls back to a path that's slower than the
# pure-software cairo renderer.  Disabling both compositor and dmabuf
# rendering paths gives a responsive UI on WSL2.
# On native Linux these vars are harmless — Tauri's compositor path on
# a real X server / wayland already works.
if grep -qi "microsoft" /proc/version 2>/dev/null || [ -n "${WSL_DISTRO_NAME:-}" ]; then
    export WEBKIT_DISABLE_COMPOSITING_MODE="${WEBKIT_DISABLE_COMPOSITING_MODE:-1}"
    export WEBKIT_DISABLE_DMABUF_RENDERER="${WEBKIT_DISABLE_DMABUF_RENDERER:-1}"
    # On WSL the frontend's Matrix-rain canvas competes with cursor updates
    # for the software-rendered paint loop; disabling it gives a notably
    # smoother UI. The env var is consumed by Vite at build time (see
    # GlyphRain.tsx) so this only takes effect after a `pnpm build`.
    export VITE_OLYMPUS_NO_RAIN="${VITE_OLYMPUS_NO_RAIN:-1}"
    echo "[Olympus] WSL detected — applied webkit2gtk perf workarounds + rain kill-switch."
fi

# Pin the API port so curl/scripts can find it without inspecting
# Tauri IPC; users can override in .env or in their shell.
export OLYMPUS_API_PORT="${OLYMPUS_API_PORT:-3737}"

# ── Default to development mode ───────────────────────────────────────────────
# An unset OLYMPUS_ENV means *production* (src-tauri/src/env.rs::is_production
# fails closed on Unset). That is the right default for a deployment and the
# wrong one for a fresh clone: build.rs writes PLACEHOLDER stubs into
# proofs/keys/, so a production start exits 2 with "refuses to start with
# placeholder ZK artifacts" before the window ever opens. This launcher is the
# demo and development path, so it defaults to development — and leaves any
# non-empty value alone, so `OLYMPUS_ENV=production ./start.sh` still gets
# every fail-closed gate (the caller's value survives .env; see the restore
# above). An empty value is treated as unset here (the app reads it as
# production, which a fresh clone cannot satisfy).
export OLYMPUS_ENV="${OLYMPUS_ENV:-development}"
if [ "${OLYMPUS_ENV}" = "development" ] || [ "${OLYMPUS_ENV}" = "dev" ]; then
    echo "[Olympus] OLYMPUS_ENV=${OLYMPUS_ENV} — production startup gates are off."
    echo "[Olympus] For a production run: complete the one-time ZK setup"
    echo "[Olympus]   (bash proofs/setup_circuits.sh — see docs/quickstart.md)"
    echo "[Olympus]   then start with OLYMPUS_ENV=production."
fi

# ── Build if binary is missing ────────────────────────────────────────────────
if [ ! -x "${EXE}" ] && [ -z "${NO_BUILD:-}" ]; then
    echo "[Olympus] Building production release (cargo tauri build --no-bundle)…"
    if ! command -v cargo >/dev/null 2>&1; then
        echo "[Olympus] ERROR: cargo not found in PATH. Install Rust via https://rustup.rs/" >&2
        exit 1
    fi
    if ! cargo tauri --help >/dev/null 2>&1; then
        echo "[Olympus] Installing tauri-cli (cargo install tauri-cli)…"
        cargo install tauri-cli --version "^2" --locked
    fi
    cargo tauri build --no-bundle
fi

if [ ! -x "${EXE}" ]; then
    echo "[Olympus] ERROR: binary not at ${EXE}. Set NO_BUILD=0 or run cargo tauri build manually." >&2
    exit 1
fi

# ── Free any stale embedded-postgres lock from a previous unclean exit ────────
echo "[Olympus] Starting Olympus Ledger (API on port ${OLYMPUS_API_PORT})…"
exec "${EXE}" "$@"
