#!/usr/bin/env bash
# -----------------------------------------------------------------------
# smoke_test.sh — End-to-end prove + verify for all three main circuits
#
# Prerequisites:
#   1. Run `bash setup_circuits.sh` first (compiles circuits, generates keys)
#   2. Node.js ≥ 18, npm packages installed
#
# For each circuit this script:
#   a) Generates valid test inputs  (Poseidon Merkle trees)
#   b) Computes the witness         (circom WASM)
#   c) Creates a Groth16 proof      (snarkjs)
#   d) Verifies the proof           (snarkjs)
# -----------------------------------------------------------------------
set -euo pipefail

echo "WARNING: PRODUCTION UNSAFE — smoke tests use dev Groth16 artifacts."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_DIR="${SCRIPT_DIR}/build"
VKEYS_DIR="${SCRIPT_DIR}/keys/verification_keys"
SNARKJS="npx snarkjs"

CIRCUITS=(
  "document_existence"
  "redaction_validity"
  "non_existence"
)

PASS=0
FAIL=0

# -----------------------------------------------------------------------
# 0. Preflight checks
# -----------------------------------------------------------------------
for circuit in "${CIRCUITS[@]}"; do
  for artifact in "${BUILD_DIR}/${circuit}_final.zkey" \
                  "${BUILD_DIR}/${circuit}_js/${circuit}.wasm" \
                  "${VKEYS_DIR}/${circuit}_vkey.json"; do
    if [ ! -f "${artifact}" ]; then
      echo "ERROR: Missing artifact: ${artifact}"
      echo "       Run 'bash setup_circuits.sh' first."
      exit 1
    fi
  done
done

# -----------------------------------------------------------------------
# 1. Generate test inputs
# -----------------------------------------------------------------------
echo "==> Generating test inputs …"
node test_inputs/generate_inputs.js
echo ""

# -----------------------------------------------------------------------
# 2. For each circuit: witness → prove → verify
# -----------------------------------------------------------------------
for circuit in "${CIRCUITS[@]}"; do
  echo "===== ${circuit} ====="

  INPUT_JSON="${BUILD_DIR}/${circuit}_input.json"
  WASM="${BUILD_DIR}/${circuit}_js/${circuit}.wasm"
  WTNS="${BUILD_DIR}/${circuit}.wtns"
  ZKEY="${BUILD_DIR}/${circuit}_final.zkey"
  PROOF_JSON="${BUILD_DIR}/${circuit}_proof.json"
  PUBLIC_JSON="${BUILD_DIR}/${circuit}_public.json"
  VKEY="${VKEYS_DIR}/${circuit}_vkey.json"

  # ---- Witness generation ----
  echo "  [1/3] Generating witness …"
  node "${BUILD_DIR}/${circuit}_js/generate_witness.js" \
    "${WASM}" "${INPUT_JSON}" "${WTNS}"

  # ---- Prove ----
  echo "  [2/3] Generating Groth16 proof …"
  ${SNARKJS} groth16 prove "${ZKEY}" "${WTNS}" "${PROOF_JSON}" "${PUBLIC_JSON}"

  # ---- Verify ----
  echo "  [3/3] Verifying proof …"
  if ${SNARKJS} groth16 verify "${VKEY}" "${PUBLIC_JSON}" "${PROOF_JSON}"; then
    echo "  ✓ ${circuit}: PASS"
    PASS=$((PASS + 1))
  else
    echo "  ✗ ${circuit}: FAIL"
    FAIL=$((FAIL + 1))
  fi
  echo ""
done

# -----------------------------------------------------------------------
# 3. Summary
# -----------------------------------------------------------------------
echo "=============================="
echo "  Smoke test results: ${PASS} passed, ${FAIL} failed"
echo "=============================="

if [ "${FAIL}" -gt 0 ]; then
  exit 1
fi
