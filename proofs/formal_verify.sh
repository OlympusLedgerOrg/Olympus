#!/usr/bin/env bash
# -----------------------------------------------------------------------
# formal_verify.sh — Constraint-level witness checks for Olympus circuits
#
# This script complements smoke_test.sh by validating that generated witness
# files satisfy circuit constraints via snarkjs' built-in witness checker.
# -----------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_DIR="${SCRIPT_DIR}/build"
SNARKJS="npx snarkjs"

CIRCUITS=(
  "document_existence"
  "redaction_validity"
  "non_existence"
)

for circuit in "${CIRCUITS[@]}"; do
  for artifact in "${BUILD_DIR}/${circuit}.r1cs" \
                  "${BUILD_DIR}/${circuit}_js/${circuit}.wasm" \
                  "${BUILD_DIR}/${circuit}_js/generate_witness.js"; do
    if [ ! -f "${artifact}" ]; then
      echo "ERROR: Missing artifact: ${artifact}"
      echo "       Run 'bash setup_circuits.sh' first."
      exit 1
    fi
  done
done

echo "==> Generating test inputs …"
node test_inputs/generate_inputs.js
echo ""

for circuit in "${CIRCUITS[@]}"; do
  echo "===== ${circuit} ====="
  INPUT_JSON="${BUILD_DIR}/${circuit}_input.json"
  WASM="${BUILD_DIR}/${circuit}_js/${circuit}.wasm"
  WTNS="${BUILD_DIR}/${circuit}.wtns"
  R1CS="${BUILD_DIR}/${circuit}.r1cs"

  echo "  [1/2] Generating witness …"
  node "${BUILD_DIR}/${circuit}_js/generate_witness.js" \
    "${WASM}" "${INPUT_JSON}" "${WTNS}"

  echo "  [2/2] Checking witness satisfies constraints …"
  ${SNARKJS} wtns check "${R1CS}" "${WTNS}"
  echo "  ✓ ${circuit}: witness constraints satisfied"
  echo ""
done

echo "Formal verification checks complete."
