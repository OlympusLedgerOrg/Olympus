#!/usr/bin/env bash
# -----------------------------------------------------------------------
# setup_circuits.sh — Download PTAU, compile circuits, generate dev keys
#
# Produces:
#   proofs/build/<circuit>.r1cs
#   proofs/build/<circuit>_js/          (WASM witness generator)
#   proofs/build/<circuit>_final.zkey
#   proofs/keys/verification_keys/<circuit>_vkey.json
#
# Requirements: Node.js ≥ 18, npm, circom compiler
# -----------------------------------------------------------------------
set -euo pipefail

echo "NOTE: Phase 1 uses the public Hermez Powers of Tau (trusted multi-party ceremony)."
echo "WARNING: Phase 2 uses a SINGLE dev contributor — not production-safe."
echo "         Record PTAU provenance and verification key fingerprints."

# Parse flags
COMPILE_ONLY=0
for arg in "$@"; do
  case "${arg}" in
    --compile-only) COMPILE_ONLY=1 ;;
    *) echo "Unknown argument: ${arg}" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_DIR="${SCRIPT_DIR}/build"
KEYS_DIR="${SCRIPT_DIR}/keys"
VKEYS_DIR="${KEYS_DIR}/verification_keys"

# The three authoritative circuits (non-legacy)
CIRCUITS=(
  "document_existence"
  "redaction_validity"
  "non_existence"
)

# PTAU file — powers of tau ceremony file
# 2^17 supports up to 131 072 constraints; sufficient for all three circuits
# including redaction_validity which has ~41 000 constraints.
PTAU_POWER=17
PTAU_FILE="powersOfTau28_hez_final_${PTAU_POWER}.ptau"
PTAU_URL="https://hermez.s3-eu-west-1.amazonaws.com/${PTAU_FILE}"
PTAU_PATH="${KEYS_DIR}/${PTAU_FILE}"
PTAU_SOURCE="${PTAU_URL}"

# Known SHA-256 checksums for Hermez PTAU files.
# Source: https://github.com/iden3/snarkjs#7-prepare-phase-2
declare -A PTAU_CHECKSUMS=(
  [15]="982372c867d229c236091f767e703253249a9b432c1730cbe57e8e864e5ed37f"
  [17]="3a4ed97a753be2df8a9ee9f69ee1efaf8c988c52f5bfac5f42e9b89c3c4cef4b"
)

# -----------------------------------------------------------------------
# 0. Install npm dependencies (circomlib, snarkjs)
# -----------------------------------------------------------------------
echo "==> Installing npm dependencies …"
npm install --silent

# -----------------------------------------------------------------------
# 1. Verify circom compiler is available
# -----------------------------------------------------------------------
CIRCOM=""
if command -v circom2 &>/dev/null; then
  CIRCOM="circom2"
elif command -v circom &>/dev/null; then
  CIRCOM="circom"
else
  echo "ERROR: circom compiler not found in PATH."
  echo "Install circom2 via npm (npm install -g circom2) or from"
  echo "https://docs.circom.io/getting-started/installation/"
  exit 1
fi
echo "==> Using circom compiler: $(${CIRCOM} --version 2>&1 | head -1)"

SNARKJS="npx snarkjs"

# -----------------------------------------------------------------------
# 2. Obtain Powers of Tau file (download or generate locally)
# -----------------------------------------------------------------------
mkdir -p "${BUILD_DIR}" "${VKEYS_DIR}"

if [ -f "${PTAU_PATH}" ]; then
  echo "==> PTAU file already present: ${PTAU_PATH}"
else
  echo "==> Downloading Hermez Powers of Tau (2^${PTAU_POWER}) …"
  if curl -fSL --connect-timeout 30 --retry 3 -o "${PTAU_PATH}" "${PTAU_URL}"; then
    echo "    Downloaded ${PTAU_FILE}"
  else
    echo "ERROR: Failed to download Hermez PTAU from ${PTAU_URL}"
    echo "       A trusted Phase 1 ceremony file is required."
    echo "       Local PTAU generation is not supported — use the public Hermez ceremony."
    exit 1
  fi
fi

# Verify PTAU SHA-256 checksum
echo "==> Verifying PTAU integrity …"
PTAU_SHA256="$(sha256sum "${PTAU_PATH}" | awk '{print $1}')"
PTAU_EXPECTED="${PTAU_CHECKSUMS[${PTAU_POWER}]:-}"
if [ -n "${PTAU_EXPECTED}" ] && [ "${PTAU_SHA256}" != "${PTAU_EXPECTED}" ]; then
  echo "ERROR: PTAU SHA-256 mismatch!"
  echo "  Expected: ${PTAU_EXPECTED}"
  echo "  Got:      ${PTAU_SHA256}"
  echo "  File may be corrupted or tampered with."
  rm -f "${PTAU_PATH}"
  exit 1
fi
echo "    PTAU integrity verified ✓"

# -----------------------------------------------------------------------
# 2.5 Record provenance (PTAU source + hashes + verification key fingerprints)
# -----------------------------------------------------------------------
PROVENANCE_FILE="${KEYS_DIR}/PROVENANCE.md"
PTAU_SHA256="$(sha256sum "${PTAU_PATH}" | awk '{print $1}')"
{
  echo "# Groth16 Setup Provenance"
  echo ""
  echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo ""
  echo "PTAU_SOURCE: ${PTAU_SOURCE}"
  echo "PTAU_FILE: ${PTAU_FILE}"
  echo "PTAU_SHA256: ${PTAU_SHA256}"
  echo ""
  echo "Verification key fingerprints (SHA-256):"
} > "${PROVENANCE_FILE}"

# -----------------------------------------------------------------------
# 3. Compile each circuit and (optionally) run Groth16 setup
# -----------------------------------------------------------------------

for circuit in "${CIRCUITS[@]}"; do
  CIRCOM_FILE="circuits/${circuit}.circom"
  echo ""
  echo "===== ${circuit} ====="

  # ---- Compile ----
  echo "  [1/4] Compiling ${CIRCOM_FILE} …"
  ${CIRCOM} "${CIRCOM_FILE}" \
    --r1cs --wasm --sym \
    -l circuits \
    -l node_modules \
    -o "${BUILD_DIR}"

  R1CS="${BUILD_DIR}/${circuit}.r1cs"

  if [ "${COMPILE_ONLY}" -eq 1 ]; then
    echo "  [--compile-only] Skipping Groth16 setup."
    echo "        r1cs  : ${R1CS}"
    echo "        wasm  : ${BUILD_DIR}/${circuit}_js/${circuit}.wasm"
    continue
  fi

  # ---- Phase 2 setup (development contribution) ----
  echo "  [2/4] Groth16 setup …"
  ZKEY_0="${BUILD_DIR}/${circuit}_0000.zkey"
  ZKEY_FINAL="${BUILD_DIR}/${circuit}_final.zkey"

  ${SNARKJS} groth16 setup "${R1CS}" "${PTAU_PATH}" "${ZKEY_0}"

  # Single deterministic dev contribution (NOT suitable for production)
  ${SNARKJS} zkey contribute "${ZKEY_0}" "${ZKEY_FINAL}" \
    --name="Olympus dev contribution" \
    -e="olympus-dev-entropy-$(date +%s)" 2>/dev/null

  rm -f "${ZKEY_0}"

  # ---- Export verification key ----
  echo "  [3/4] Exporting verification key …"
  VKEY="${VKEYS_DIR}/${circuit}_vkey.json"
  ${SNARKJS} zkey export verificationkey "${ZKEY_FINAL}" "${VKEY}"
  VKEY_SHA256="$(sha256sum "${VKEY}" | awk '{print $1}')"
  echo "- ${circuit}_vkey.json: ${VKEY_SHA256}" >> "${PROVENANCE_FILE}"

  # ---- Summary ----
  echo "  [4/4] Done."
  echo "        r1cs  : ${R1CS}"
  echo "        zkey  : ${ZKEY_FINAL}"
  echo "        vkey  : ${VKEY}"
done

echo ""
if [ "${COMPILE_ONLY}" -eq 1 ]; then
  echo "==> All circuits compiled (R1CS + WASM). Run without --compile-only to generate keys."
else
  echo "==> All circuits compiled and development keys generated."
  echo "    WARNING: These keys use a SINGLE dev contribution."
  echo "    Production requires a Phase 2 ceremony with ≥ 3 independent contributors."
fi
