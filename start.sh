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
if [ -f "${REPO_ROOT}/.env" ]; then
    # `set -a` exports every variable assigned by .env without requiring
    # the user to `export` each line. Safe because .env should only
    # contain key=value pairs, no command substitutions.
    set -a
    # shellcheck disable=SC1091
    . "${REPO_ROOT}/.env"
    set +a
fi

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
# pg_embed refuses to init a data dir that still has a postmaster.pid,
# even if the writer is gone (e.g. SIGKILL or WSL shutdown). The app now
# self-heals this on startup (src-tauri/src/db.rs::try_init_embedded), so
# this is belt-and-braces for older binaries. Note the data dir is
# `<app-data>/olympus-pg` (db.rs); `<app-data>/pg-embed` holds only the
# downloaded PG binaries.
PG_DATA_DIR="${HOME}/.local/share/io.olympus.ledger/olympus-pg"
if [ -f "${PG_DATA_DIR}/postmaster.pid" ]; then
    PG_PID="$(head -1 "${PG_DATA_DIR}/postmaster.pid" 2>/dev/null || true)"
    if [ -n "${PG_PID}" ] && ! kill -0 "${PG_PID}" 2>/dev/null; then
        echo "[Olympus] Removing stale postmaster.pid (process ${PG_PID} is gone)."
        rm -f "${PG_DATA_DIR}/postmaster.pid"
    fi
fi

echo "[Olympus] Starting Olympus Ledger (API on port ${OLYMPUS_API_PORT})…"
exec "${EXE}" "$@"
