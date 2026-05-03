#!/usr/bin/env bash
# -----------------------------------------------------------------------
# tools/groth16_setup.sh — Groth16 trusted-setup pipeline for the
#                          Phase 0.2 FOIA Redaction Circuit
#
# Automates the full snarkjs pipeline for selective_disclosure_merkle.circom:
#   1. Compile circuit to R1CS + WASM witness generator
#   2. Phase 1 — Download Hermez Powers of Tau (bn128, 2^19)
#   3. Phase 2 — Circuit-specific Groth16 setup
#   4. Export verification key
#
# Usage (from repo root):
#   ./tools/groth16_setup.sh
#
# Outputs (all written to proofs/build/):
#   selective_disclosure_merkle.r1cs
#   selective_disclosure_merkle_js/     (WASM witness generator)
#   pot19_final.ptau   (Hermez Powers of Tau)
#   foia_redaction_final.zkey
#   verification_key.json
#
# Requirements: Node.js ≥ 18, circom ≥ 2.1.6, snarkjs (npm), curl
#
# WARNING: The single-contributor Phase 2 ceremony produced by this script
#          is suitable for development only.  Production deployments require
#          a multi-party Phase 2 ceremony with ≥ 3 independent contributors.
# -----------------------------------------------------------------------
set -euo pipefail

echo "NOTE: Phase 1 uses the public Hermez Powers of Tau (trusted multi-party ceremony)."
echo "WARNING: Phase 2 uses a SINGLE dev contributor — not production-safe."

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Setup directories
mkdir -p "${REPO_ROOT}/proofs/build"
cd "${REPO_ROOT}/proofs"

echo "Compiling circuit..."
circom selective_disclosure_merkle.circom --r1cs --wasm --sym -o build/

# -----------------------------------------------------------------------
# Phase 1: Download Hermez Powers of Tau (public multi-party ceremony)
# -----------------------------------------------------------------------
PTAU_POWER=19
PTAU_FILE="powersOfTau28_hez_final_${PTAU_POWER}.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/${PTAU_FILE}"
PTAU_PATH="build/${PTAU_FILE}"

# Known BLAKE2b-512 for powersOfTau28_hez_final_19.ptau (authoritative Hermez hash)
PTAU_EXPECTED_B2="bca9d8b04242f175189872c42ceaa21e2951e0f0f272a0cc54fc37193ff6648600eaf1c555c70cdedfaf9fb74927de7aa1d33dc1e2a7f1a50619484989da0887"

if [ -f "${PTAU_PATH}" ]; then
  echo "==> PTAU file already present: ${PTAU_PATH}"
else
  echo "==> Downloading Hermez Powers of Tau (2^${PTAU_POWER}) …"
  if ! curl -fSL --connect-timeout 30 --retry 3 -o "${PTAU_PATH}" "${PTAU_URL}"; then
    echo "ERROR: Failed to download Hermez PTAU from ${PTAU_URL}"
    echo "       A trusted Phase 1 ceremony file is required."
    echo "       Local PTAU generation is not supported — use the public Hermez ceremony."
    exit 1
  fi
fi

# Verify BLAKE2b-512 checksum
echo "==> Verifying PTAU integrity …"
PTAU_B2="$(b2sum "${PTAU_PATH}" | awk '{print $1}')"
if [ "${PTAU_B2}" != "${PTAU_EXPECTED_B2}" ]; then
  echo "ERROR: PTAU BLAKE2b-512 mismatch!"
  echo "  Expected: ${PTAU_EXPECTED_B2}"
  echo "  Got:      ${PTAU_B2}"
  echo "  File may be corrupted or tampered with."
  rm -f "${PTAU_PATH}"
  exit 1
fi
echo "    PTAU integrity verified ✓"

# Symlink to expected name for backward compatibility
ln -sf "${PTAU_FILE}" build/pot19_final.ptau 2>/dev/null || true

echo "Starting Phase 2 (Circuit-Specific Groth16 Setup)..."
snarkjs groth16 setup build/selective_disclosure_merkle.r1cs "${PTAU_PATH}" build/foia_redaction_0000.zkey
snarkjs zkey contribute build/foia_redaction_0000.zkey build/foia_redaction_final.zkey --name="Olympus Core Setup" -v

echo "Exporting verification key..."
snarkjs zkey export verificationkey build/foia_redaction_final.zkey build/verification_key.json

echo "Recording provenance..."
VKEY_SHA256="$(sha256sum build/verification_key.json | awk '{print $1}')"
cat <<EOF > build/PROVENANCE.md
# Groth16 Setup Provenance (FOIA Redaction Circuit)

Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
PTAU_SOURCE: ${PTAU_URL}
PTAU_B2: ${PTAU_B2}
VKEY_SHA256: ${VKEY_SHA256}

Phase 1: Hermez Powers of Tau (public multi-party ceremony)
Phase 2: Single dev contributor (NOT production-safe)
EOF

echo "Groth16 setup pipeline complete. Artifacts saved in proofs/build/"
