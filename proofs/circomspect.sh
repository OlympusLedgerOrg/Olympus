#!/usr/bin/env bash
# -----------------------------------------------------------------------
# circomspect.sh — Static analysis fast-lane for the Olympus Circom circuits
#
# Runs Trail of Bits' `circomspect` (https://github.com/trailofbits/circomspect)
# over every production circuit source file. circomspect is a pure static
# analyser: it does NOT compile the circuit, generate a witness, or need any
# trusted-setup artifact, so it runs in seconds with only the .circom sources
# plus the vendored circomlib on disk.
#
# It flags classic Circom soundness/quality issues:
#   - under-constrained signals (a signal a malicious prover could pick freely)
#   - signals assigned with `<--` but never constrained with `===`
#   - unused signals / unused components / dead parameters
#   - shadowing, non-quadratic constraints, bitwise-on-field foot-guns, etc.
#
# This is the "formal verification fast lane" referenced in proofs/README.md:
# cheap enough to run on every PR, complementary to the heavier witness-level
# checks in formal_verify.sh and the Ecne/Picus SMT passes.
#
# Modes:
#   (default)   Human-readable report to stdout; exit 0 unless --strict.
#   --ci        Also emit machine-readable results to
#               build/circomspect_results.json and per-circuit SARIF under
#               build/circomspect/<circuit>.sarif. Advisory by default.
#   --strict    Exit non-zero if any circuit produces a WARNING or ERROR.
#               (Use once the circuits are baselined — see proofs/README.md.)
#   --level <L> Minimum severity to report: INFO | WARNING | ERROR.
#               Default WARNING (INFO is very chatty).
#
# Install circomspect with:  cargo install circomspect
# -----------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_DIR="${SCRIPT_DIR}/build"
CIRCUITS_DIR="${SCRIPT_DIR}/circuits"
LIB_DIR="${SCRIPT_DIR}/vendor/circomlib/circuits"

# Every production circuit (parameters.circom is a pure-constant include and has
# no template to analyse on its own, so it is exercised transitively).
CIRCUITS=(
  "document_existence"
  "non_existence"
  "redaction_validity"
  "unified_canonicalization_inclusion_root_sign"
  "federation_quorum"
)

CI_MODE=false
STRICT=false
LEVEL="WARNING"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci) CI_MODE=true; shift ;;
    --strict) STRICT=true; shift ;;
    --level) LEVEL="${2:?--level needs an argument}"; shift 2 ;;
    -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "Unknown flag: $1" >&2; exit 1 ;;
  esac
done

# -----------------------------------------------------------------------
# Preflight: is circomspect installed?
# -----------------------------------------------------------------------
if ! command -v circomspect &>/dev/null; then
  echo "SKIP: circomspect not found in PATH."
  echo "      Install with: cargo install circomspect"
  if $CI_MODE; then
    mkdir -p "${BUILD_DIR}"
    printf '[\n  {"tool":"circomspect","status":"skip","detail":"binary not installed"}\n]\n' \
      > "${BUILD_DIR}/circomspect_results.json"
    echo "CI results written to: ${BUILD_DIR}/circomspect_results.json"
  fi
  # A missing optional analyser must never break the build — the CI job that
  # calls this script installs it; local devs may not have it.
  exit 0
fi

echo "==> circomspect $(circomspect --version 2>/dev/null || echo '(version unknown)')"
echo "    level >= ${LEVEL}   strict=${STRICT}"
echo ""

# circomspect resolves `include` paths relative to -L library dirs. We pass the
# vendored circomlib and the local circuits/lib so `pragma circom`/`include`
# both resolve without a global install.
LIB_ARGS=( -L "${CIRCUITS_DIR}" )
[[ -d "${LIB_DIR}" ]] && LIB_ARGS+=( -L "${LIB_DIR}" )
[[ -d "${CIRCUITS_DIR}/lib" ]] && LIB_ARGS+=( -L "${CIRCUITS_DIR}/lib" )

if $CI_MODE; then
  mkdir -p "${BUILD_DIR}/circomspect"
fi

declare -a JSON_RESULTS=()
WARN_TOTAL=0
ERROR_TOTAL=0
ANALYSED=0

for circuit in "${CIRCUITS[@]}"; do
  SRC="${CIRCUITS_DIR}/${circuit}.circom"
  if [[ ! -f "${SRC}" ]]; then
    echo "  - ${circuit}: SKIP (source not found at ${SRC})"
    JSON_RESULTS+=("{\"circuit\":\"${circuit}\",\"status\":\"skip\",\"warnings\":0,\"errors\":0,\"detail\":\"source missing\"}")
    continue
  fi

  echo "===== ${circuit} ====="
  ANALYSED=$((ANALYSED + 1))
  LOG="${BUILD_DIR}/circomspect/${circuit}.log"
  mkdir -p "$(dirname "${LOG}")"

  # Capture human-readable output (and, in CI, SARIF). circomspect exits 1 when
  # it reports findings; we capture that without aborting the loop so every
  # circuit is analysed and we can decide pass/fail centrally.
  set +e
  if $CI_MODE; then
    SARIF="${BUILD_DIR}/circomspect/${circuit}.sarif"
    circomspect "${LIB_ARGS[@]}" --level "${LEVEL}" --sarif-file "${SARIF}" "${SRC}" \
      > "${LOG}" 2>&1
  else
    circomspect "${LIB_ARGS[@]}" --level "${LEVEL}" "${SRC}" > "${LOG}" 2>&1
  fi
  set -e

  cat "${LOG}"

  # circomspect prints a trailing summary like:
  #   "circomspect: analyzing ... 2 issues found." or "No issues found."
  # Count severity markers from the report body for a stable tally.
  W=$(grep -ciE 'warning:' "${LOG}" || true)
  E=$(grep -ciE 'error:'   "${LOG}" || true)
  WARN_TOTAL=$((WARN_TOTAL + W))
  ERROR_TOTAL=$((ERROR_TOTAL + E))

  if [[ "${W}" -eq 0 && "${E}" -eq 0 ]]; then
    echo "  ✓ ${circuit}: no findings at level >= ${LEVEL}"
    JSON_RESULTS+=("{\"circuit\":\"${circuit}\",\"status\":\"pass\",\"warnings\":0,\"errors\":0,\"detail\":\"clean\"}")
  else
    echo "  ⚠ ${circuit}: ${W} warning(s), ${E} error(s)"
    JSON_RESULTS+=("{\"circuit\":\"${circuit}\",\"status\":\"findings\",\"warnings\":${W},\"errors\":${E},\"detail\":\"see build/circomspect/${circuit}.log\"}")
  fi
  echo ""
done

echo "=============================="
echo "  circomspect: ${ANALYSED} circuit(s) analysed, ${WARN_TOTAL} warning(s), ${ERROR_TOTAL} error(s)"
echo "=============================="

if $CI_MODE; then
  RESULTS_FILE="${BUILD_DIR}/circomspect_results.json"
  {
    echo "["
    for i in "${!JSON_RESULTS[@]}"; do
      [[ "$i" -gt 0 ]] && echo ","
      printf '  %s' "${JSON_RESULTS[$i]}"
    done
    echo ""
    echo "]"
  } > "${RESULTS_FILE}"
  echo "CI results written to: ${RESULTS_FILE}"
fi

if $STRICT && { [[ "${WARN_TOTAL}" -gt 0 ]] || [[ "${ERROR_TOTAL}" -gt 0 ]]; }; then
  echo "FAIL: --strict and findings present." >&2
  exit 1
fi

# Advisory mode (default): findings are reported but do not fail the build.
exit 0
