#!/usr/bin/env bash
# One-shot WSL2 dev environment bootstrap for Olympus.
#
# Run once after cloning inside WSL2:
#   bash scripts/setup-wsl.sh
#
# Installs: Podman, uv, pnpm (via corepack), Node 20 (via nvm),
#           maturin, Rust toolchain (via rustup).
# Writes DOCKER_HOST to ~/.bashrc so Podman socket is used transparently.
#
# Idempotent: safe to re-run; existing installs are skipped.

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

info()    { echo -e "${GREEN}[olympus]${RESET} $*"; }
heading() { echo -e "\n${BOLD}$*${RESET}"; }
warn()    { echo -e "${YELLOW}[warn]${RESET} $*"; }

# ── Sanity check ──────────────────────────────────────────────────────────────

if ! grep -qi microsoft /proc/version 2>/dev/null; then
    warn "Not running inside WSL2 — this script is designed for WSL2 only."
    warn "On native Linux, install packages manually using your distro's package manager."
    read -rp "Continue anyway? [y/N] " ans
    [[ "${ans,,}" == "y" ]] || exit 1
fi

# ── System packages ───────────────────────────────────────────────────────────

heading "System packages"
sudo apt-get update -qq
sudo apt-get install -y -qq \
    build-essential curl git pkg-config libssl-dev \
    podman uidmap slirp4netns fuse-overlayfs \
    python3-pip python3-venv

info "System packages OK"

# ── Podman rootless socket ─────────────────────────────────────────────────────

heading "Podman rootless socket"
systemctl --user enable --now podman.socket 2>/dev/null || \
    warn "Could not enable podman.socket — systemd may not be active in this WSL2 instance."

DOCKER_HOST_LINE='export DOCKER_HOST="unix://${XDG_RUNTIME_DIR}/podman/podman.sock"'
if ! grep -qF 'DOCKER_HOST' ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# Podman socket — makes Docker-aware tools work without Docker Desktop" >> ~/.bashrc
    echo "${DOCKER_HOST_LINE}" >> ~/.bashrc
    info "Added DOCKER_HOST to ~/.bashrc"
else
    info "DOCKER_HOST already in ~/.bashrc — skipping"
fi

# ── Rust toolchain ─────────────────────────────────────────────────────────────

heading "Rust toolchain"
if command -v rustup &>/dev/null; then
    info "rustup already installed — running update"
    rustup update stable
else
    info "Installing rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

rustup target add wasm32-unknown-unknown 2>/dev/null || true
info "Rust toolchain OK: $(rustc --version)"

# ── maturin ───────────────────────────────────────────────────────────────────

heading "maturin (PyO3 build tool)"
if ! command -v maturin &>/dev/null; then
    # Install into the Cargo bin dir so it's available without a venv
    cargo install maturin --locked
fi
info "maturin OK: $(maturin --version)"

# ── uv ────────────────────────────────────────────────────────────────────────

heading "uv (Python package manager)"
if ! command -v uv &>/dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # shellcheck source=/dev/null
    source "$HOME/.local/bin/env" 2>/dev/null || export PATH="$HOME/.local/bin:$PATH"
fi
info "uv OK: $(uv --version)"

# ── Node 20 via nvm ───────────────────────────────────────────────────────────

heading "Node 20 (via nvm)"
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
if [[ ! -d "$NVM_DIR" ]]; then
    info "Installing nvm"
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
fi
# shellcheck source=/dev/null
source "$NVM_DIR/nvm.sh"
nvm install 20
nvm alias default 20
nvm use default
info "Node OK: $(node --version)"

# ── pnpm via corepack ─────────────────────────────────────────────────────────

heading "pnpm (via corepack)"
corepack enable
corepack prepare pnpm@latest --activate
info "pnpm OK: $(pnpm --version)"

# ── Project dependencies ───────────────────────────────────────────────────────

heading "Project dependencies"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

info "Building olympus_core PyO3 extension (maturin develop)"
uv run maturin develop --release 2>&1 | tail -5

info "Installing Python deps (uv sync --extra dev)"
uv sync --extra dev

info "Installing Node deps (pnpm install)"
pnpm install

# ── Done ──────────────────────────────────────────────────────────────────────

heading "Bootstrap complete"
echo ""
echo "  Restart your shell (or run: source ~/.bashrc) to pick up DOCKER_HOST."
echo ""
echo "  Quick-start:"
echo "    make dev          # FastAPI dev server on :8000"
echo "    cargo tauri dev   # Tauri dev build (once Phase 1 lands)"
echo ""
