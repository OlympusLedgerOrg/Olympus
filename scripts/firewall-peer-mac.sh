#!/usr/bin/env bash
# firewall-peer-mac.sh — Lock Olympus ports on a macOS peer node.
#
# SYNOPSIS
#   Lock ports (run with sudo):
#     sudo bash scripts/firewall-peer-mac.sh
#
#   Remove rules:
#     sudo bash scripts/firewall-peer-mac.sh --remove
#
# DESCRIPTION
#   Adds macOS pf rules so that:
#     - Port 8000 (Olympus API this node serves) — Tailscale subnet only
#     - Port 5433 (local SSH-tunnel endpoint)     — localhost only (no network)
#
#   This node connects to the HOST's Postgres via an SSH tunnel:
#     ssh -N -L 5433:localhost:5433 <host-tailscale-ip>
#   The tunnel binds 5433 on THIS machine's loopback — pf blocks any attempt
#   to reach it from the network (belt-and-suspenders).
#
#   Run once after setting up Tailscale.
#   Requires macOS 10.7+ (pf is always present; no install needed).
#
# TAILSCALE SETUP (if not done yet):
#   brew install --cask tailscale
#   open /Applications/Tailscale.app
#   # Sign in and approve the device on https://login.tailscale.com/admin/machines

set -euo pipefail

TAILSCALE_SUBNET="100.64.0.0/10"   # All Tailscale nodes worldwide
ANCHOR_NAME="com.olympus.peer"
PF_CONF="/etc/pf.conf"
ANCHOR_CONF="/etc/pf.anchors/${ANCHOR_NAME}"

# ── helpers ──────────────────────────────────────────────────────────────────

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "  $*"; }
ok()   { echo "  ✓ $*"; }
warn() { echo "  ⚠ $*"; }

[[ $EUID -eq 0 ]] || die "This script must be run as root: sudo $0 $*"

# ── remove mode ──────────────────────────────────────────────────────────────

if [[ "${1:-}" == "--remove" ]]; then
    echo ""
    echo "Removing Olympus pf anchor..."

    # Flush and unload the anchor
    pfctl -a "${ANCHOR_NAME}" -F all 2>/dev/null || true

    # Remove anchor file
    if [[ -f "${ANCHOR_CONF}" ]]; then
        rm -f "${ANCHOR_CONF}"
        ok "Removed ${ANCHOR_CONF}"
    fi

    # Remove the load-anchor line from pf.conf if present
    if grep -q "${ANCHOR_NAME}" "${PF_CONF}" 2>/dev/null; then
        # macOS sed -i requires a backup suffix
        sed -i.bak "/olympus-anchor-begin/,/olympus-anchor-end/d" "${PF_CONF}"
        ok "Removed anchor reference from ${PF_CONF}"
    fi

    pfctl -f "${PF_CONF}" 2>/dev/null && ok "Reloaded pf" || warn "pf reload had warnings (may be fine)"

    echo ""
    echo "All Olympus pf rules removed."
    exit 0
fi

# ── apply mode ───────────────────────────────────────────────────────────────

echo ""
echo "Applying Olympus pf rules..."

# Write anchor rules
mkdir -p /etc/pf.anchors
cat > "${ANCHOR_CONF}" << RULES
# Olympus peer pf anchor — managed by scripts/firewall-peer-mac.sh
# DO NOT EDIT by hand — re-run the script to regenerate.

# Block Postgres tunnel port from the network (it's loopback-only)
block in quick proto tcp from any to any port 5433

# Allow Olympus API port only from Tailscale peers
pass  in quick proto tcp from ${TAILSCALE_SUBNET} to any port 8000
block in quick proto tcp from any to any port 8000
RULES

ok "Wrote ${ANCHOR_CONF}"

# Inject anchor reference into pf.conf if not already present
if ! grep -q "${ANCHOR_NAME}" "${PF_CONF}" 2>/dev/null; then
    cat >> "${PF_CONF}" << CONF

# ── olympus-anchor-begin ─────────────────────────────────────────────────────
anchor "${ANCHOR_NAME}"
load anchor "${ANCHOR_NAME}" from "${ANCHOR_CONF}"
# ── olympus-anchor-end ───────────────────────────────────────────────────────
CONF
    ok "Appended anchor reference to ${PF_CONF}"
else
    info "Anchor reference already in ${PF_CONF} — skipping append"
fi

# Enable pf (macOS ships with it disabled by default)
pfctl -e 2>/dev/null || true

# Load the new rules
pfctl -f "${PF_CONF}" 2>/dev/null && ok "Loaded pf rules" || warn "pf reload had warnings (rules still applied)"

# Load just the anchor to force a refresh
pfctl -a "${ANCHOR_NAME}" -f "${ANCHOR_CONF}" 2>/dev/null && ok "Anchor loaded" || warn "Anchor load had warnings"

cat << SUMMARY

Firewall rules applied.

PORTS SUMMARY (this Mac)
  8000  Olympus API   — Tailscale peers only  (${TAILSCALE_SUBNET})
  5433  Postgres      — BLOCKED from network  (loopback / SSH tunnel only)

NEXT STEPS ON THIS MAC
  1. Install Tailscale if you haven't:
       brew install --cask tailscale
       open /Applications/Tailscale.app
       # Sign in, then: tailscale up

  2. Get your Tailscale IP:
       tailscale ip

  3. Open the DB tunnel to the Windows host (keep this terminal open):
       ssh -N -L 5433:localhost:5433 <windows-username>@<host-tailscale-ip>

  4. In another terminal, start your node:
       source .venv/bin/activate
       uvicorn api.main:app --host 0.0.0.0 --port 8000

  5. Your .env should have:
       DATABASE_URL=postgresql+asyncpg://olympus:<password>@localhost:5433/olympus
       PSYCOPG_URL=postgresql://olympus:<password>@localhost:5433/olympus
       (localhost — the tunnel makes it local on your end)

  6. To verify pf rules are active:
       sudo pfctl -a ${ANCHOR_NAME} -s rules

SUMMARY
