#!/usr/bin/env bash
# -----------------------------------------------------------------------
# tools/groth16_setup.sh — Groth16 trusted-setup pipeline for the
#                          Phase 0.2 FOIA Redaction Circuit
#
# Automates the full snarkjs pipeline for selective_disclosure_merkle.circom:
#   1. Compile circuit to R1CS + WASM witness generator
#   2. Phase 1 — Powers of Tau ceremony (bn128, 2^15)
#   3. Phase 2 — Circuit-specific Groth16 setup
#   4. Export verification key
#
# Usage (from repo root):
#   ./tools/groth16_setup.sh
#
# Outputs (all written to proofs/build/):
#   selective_disclosure_merkle.r1cs
#   selective_disclosure_merkle_js/     (WASM witness generator)
#   pot15_final.ptau
#   foia_redaction_final.zkey
#   verification_key.json
#
# Requirements: Node.js ≥ 18, circom ≥ 2.1.6, snarkjs (npm)
#
# WARNING: The single-contributor ceremony produced by this script is
#          suitable for development only.  Production deployments require
#          a multi-party Phase 2 ceremony with ≥ 3 independent contributors.
# -----------------------------------------------------------------------
set -e

echo "WARNING: PRODUCTION UNSAFE — dev-only Groth16 setup script."

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Setup directories
mkdir -p "${REPO_ROOT}/proofs/build"
cd "${REPO_ROOT}/proofs"

echo "Compiling circuit..."
circom selective_disclosure_merkle.circom --r1cs --wasm --sym -o build/

echo "Starting Phase 1 (Universal Powers of Tau)..."
snarkjs powersoftau new bn128 15 build/pot15_0000.ptau -v
snarkjs powersoftau contribute build/pot15_0000.ptau build/pot15_0001.ptau --name="Olympus FOIA Admin" -v
snarkjs powersoftau prepare phase2 build/pot15_0001.ptau build/pot15_final.ptau -v

echo "Starting Phase 2 (Circuit-Specific Groth16 Setup)..."
snarkjs groth16 setup build/selective_disclosure_merkle.r1cs build/pot15_final.ptau build/foia_redaction_0000.zkey
snarkjs zkey contribute build/foia_redaction_0000.zkey build/foia_redaction_final.zkey --name="Olympus Core Setup" -v

echo "Exporting verification key..."
snarkjs zkey export verificationkey build/foia_redaction_final.zkey build/verification_key.json

echo "Recording provenance..."
PTAU_SHA256="$(sha256sum build/pot15_final.ptau | awk '{print $1}')"
VKEY_SHA256="$(sha256sum build/verification_key.json | awk '{print $1}')"
cat <<EOF > build/PROVENANCE.md
# Groth16 Setup Provenance (FOIA Redaction Circuit)

Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
PTAU_SOURCE: local-dev-generated
PTAU_SHA256: ${PTAU_SHA256}
VKEY_SHA256: ${VKEY_SHA256}
EOF

echo "Groth16 setup pipeline complete. Artifacts saved in proofs/build/"
