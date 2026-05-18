#!/usr/bin/env bash
# One-shot WSL2 Ubuntu bootstrap for Olympus development.
# Run once after `wsl --install -d Ubuntu` from Windows.
set -euo pipefail

BOLD='\033[1m'; CYAN='\033[1;36m'; GREEN='\033[1;32m'; RESET='\033[0m'
step() { echo -e "\n${CYAN}==> ${BOLD}$*${RESET}"; }
ok()   { echo -e "${GREEN}  ✓ $*${RESET}"; }

step "System packages"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  build-essential curl git pkg-config libssl-dev \
  podman podman-compose uidmap slirp4netns \
  ca-certificates gnupg lsb-release

step "Rust toolchain (rustup)"
if ! command -v rustup &>/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
fi
# shellcheck source=/dev/null
source "$HOME/.cargo/env"
rustup update stable
rustup target add wasm32-unknown-unknown
ok "Rust $(rustc --version)"

step "Tauri CLI + maturin (via cargo)"
cargo install tauri-cli --version "^2" --locked 2>/dev/null || true
ok "tauri $(cargo tauri --version 2>/dev/null || echo 'installed')"

step "uv (Python package manager)"
if ! command -v uv &>/dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$HOME/.local/bin:$PATH"
ok "uv $(uv --version)"

step "Node 20 via nvm"
if ! command -v nvm &>/dev/null && [ ! -d "$HOME/.nvm" ]; then
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
fi
export NVM_DIR="$HOME/.nvm"
# shellcheck source=/dev/null
[ -s "$NVM_DIR/nvm.sh" ] && source "$NVM_DIR/nvm.sh"
nvm install 20
nvm use 20
nvm alias default 20
ok "Node $(node --version)"

step "pnpm via corepack"
corepack enable
corepack prepare pnpm@latest --activate
ok "pnpm $(pnpm --version)"

step "Podman rootless socket"
systemctl --user enable --now podman.socket 2>/dev/null || \
  echo "  Note: run 'systemctl --user start podman.socket' manually if systemd is not the WSL init."

step "Shell environment (~/.bashrc additions)"
BASHRC="$HOME/.bashrc"
MARKER="# >>> olympus-dev >>>"
if ! grep -q "$MARKER" "$BASHRC" 2>/dev/null; then
  cat >> "$BASHRC" <<'BLOCK'

# >>> olympus-dev >>>
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && source "$NVM_DIR/nvm.sh"
# Podman rootless — lets docker-compose / cargo-tauri find the socket
export DOCKER_HOST="unix://${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
# <<< olympus-dev <<<
BLOCK
  ok "Added env block to ~/.bashrc"
else
  ok "~/.bashrc already configured"
fi

step "VS Code WSL extensions (if code is available)"
if command -v code &>/dev/null; then
  code --install-extension rust-lang.rust-analyzer
  code --install-extension charliermarsh.ruff
  code --install-extension ms-python.mypy-type-checker
  code --install-extension golang.go
  code --install-extension ms-azuretools.vscode-docker
fi

echo -e "\n${GREEN}${BOLD}All done.${RESET}"
echo "  Reload your shell:  source ~/.bashrc"
echo "  Install deps:       uv sync --extra dev && pnpm install"
echo "  Dev server:         cargo tauri dev"
