#!/usr/bin/env bash
# -----------------------------------------------------------------------
# formal_verify.sh — Constraint-level witness checks for Olympus circuits
#
# This script complements smoke_test.sh by validating that generated witness
# files satisfy circuit constraints via snarkjs' built-in witness checker.
#
# Extended verification modes:
#   --ci           Emit JSON results to build/formal_verify_results.json
#   --constraint-report   Report constraint counts per circuit
#   --circomspect  Run circomspect static analysis (delegates to circomspect.sh;
#                  requires the `circomspect` binary — `cargo install circomspect`)
#   --ecne         Run Ecne under-constrained analysis (requires ecne binary)
#   --picus        Run Picus under-constrained analysis (requires picus binary)
# -----------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_DIR="${SCRIPT_DIR}/build"
SNARKJS="npx snarkjs"

CIRCUITS=(
  "document_existence"
  "non_existence"
)

# Parse CLI flags
CI_MODE=false
CONSTRAINT_REPORT=false
RUN_CIRCOMSPECT=false
RUN_ECNE=false
RUN_PICUS=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci) CI_MODE=true; shift ;;
    --constraint-report) CONSTRAINT_REPORT=true; shift ;;
    --circomspect) RUN_CIRCOMSPECT=true; shift ;;
    --ecne) RUN_ECNE=true; shift ;;
    --picus) RUN_PICUS=true; shift ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

# JSON results accumulator for CI mode
declare -a JSON_RESULTS=()

emit_result() {
  local circuit="$1" check="$2" status="$3" detail="$4"
  if $CI_MODE; then
    JSON_RESULTS+=("{\"circuit\":\"${circuit}\",\"check\":\"${check}\",\"status\":\"${status}\",\"detail\":\"${detail}\"}")
  fi
}

# -----------------------------------------------------------------------
# 0. Preflight artifact checks
# -----------------------------------------------------------------------
REDACTION_CIRCOM="${SCRIPT_DIR}/circuits/redaction_validity.circom"
if [ -f "${REDACTION_CIRCOM}" ]; then
  echo "ERROR: redaction_validity source exists but ADR-0030 retired the circuit."
  emit_result "redaction_validity" "retired_circuit_absent" "fail" "source file present"
  exit 1
else
  emit_result "redaction_validity" "retired_circuit_absent" "pass" "source file absent"
fi

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

# -----------------------------------------------------------------------
# 1. Witness constraint satisfaction (baseline check)
# -----------------------------------------------------------------------
PASS=0
FAIL=0

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
  if ${SNARKJS} wtns check "${R1CS}" "${WTNS}"; then
    echo "  ✓ ${circuit}: witness constraints satisfied"
    emit_result "${circuit}" "witness_check" "pass" "constraints satisfied"
    PASS=$((PASS + 1))
  else
    echo "  ✗ ${circuit}: witness constraint check FAILED"
    emit_result "${circuit}" "witness_check" "fail" "constraints NOT satisfied"
    FAIL=$((FAIL + 1))
  fi
  echo ""
done

# -----------------------------------------------------------------------
# 2. Constraint count report (--constraint-report)
# -----------------------------------------------------------------------
if $CONSTRAINT_REPORT; then
  echo "===== Constraint Count Report ====="
  for circuit in "${CIRCUITS[@]}"; do
    R1CS="${BUILD_DIR}/${circuit}.r1cs"
    if [ -f "${R1CS}" ]; then
      # Extract constraint info from snarkjs r1cs info
      INFO=$(${SNARKJS} r1cs info "${R1CS}" 2>&1 || true)
      CONSTRAINTS=$(echo "${INFO}" | grep -i "constraints" | head -1 || echo "unknown")
      echo "  ${circuit}: ${CONSTRAINTS}"
      emit_result "${circuit}" "constraint_count" "info" "${CONSTRAINTS}"
    fi
  done
  echo ""
fi

# -----------------------------------------------------------------------
# 2b. circomspect static analysis (--circomspect)
#
# Source-level static analysis (Trail of Bits' circomspect). Unlike the
# witness check above it needs no compiled artifact — it reads the .circom
# sources directly and flags under-constrained / unconstrained / unused
# signals. Delegated to the dedicated circomspect.sh so the same logic is
# reusable from CI and `pnpm formal:circomspect`.
# -----------------------------------------------------------------------
if $RUN_CIRCOMSPECT; then
  echo "===== circomspect Static Analysis ====="
  # Advisory here (--advisory): the witness-level pass/fail above is this
  # script's gate. The dedicated `formal-circuit-verify` CI job runs
  # circomspect.sh in its default strict, baseline-diffed mode.
  CIRCOMSPECT_ARGS=(--advisory)
  $CI_MODE && CIRCOMSPECT_ARGS+=(--ci)
  if bash "${SCRIPT_DIR}/circomspect.sh" "${CIRCOMSPECT_ARGS[@]}"; then
    emit_result "all" "circomspect" "info" "static analysis complete (advisory)"
  else
    emit_result "all" "circomspect" "warn" "static analysis reported findings"
  fi
  echo ""
fi

# -----------------------------------------------------------------------
# 3. Ecne under-constrained signal analysis (--ecne)
#
# Ecne (https://github.com/franklynwang/EcneProject) checks for
# under-constrained signals in R1CS — i.e., signals that can take
# multiple values while still satisfying all constraints. Any
# under-constrained signal is a potential soundness bug.
# -----------------------------------------------------------------------
if $RUN_ECNE; then
  echo "===== Ecne Under-Constrained Analysis ====="
  if command -v ecne &>/dev/null; then
    for circuit in "${CIRCUITS[@]}"; do
      R1CS="${BUILD_DIR}/${circuit}.r1cs"
      echo "  Analyzing ${circuit} …"
      ECNE_OUT="${BUILD_DIR}/${circuit}_ecne.log"
      if ecne "${R1CS}" > "${ECNE_OUT}" 2>&1; then
        # Check if any under-constrained signals were found
        if grep -qi "under.constrained" "${ECNE_OUT}"; then
          UNDER_COUNT=$(grep -ci "under.constrained" "${ECNE_OUT}" || echo "0")
          echo "  ⚠ ${circuit}: ${UNDER_COUNT} potential under-constrained signal(s)"
          echo "    See ${ECNE_OUT} for details"
          emit_result "${circuit}" "ecne" "warn" "${UNDER_COUNT} under-constrained signals"
        else
          echo "  ✓ ${circuit}: no under-constrained signals detected"
          emit_result "${circuit}" "ecne" "pass" "no under-constrained signals"
        fi
      else
        echo "  ⚠ ${circuit}: ecne analysis failed (non-zero exit)"
        emit_result "${circuit}" "ecne" "error" "ecne exited with error"
      fi
    done
  else
    echo "  SKIP: ecne binary not found in PATH"
    echo "  Install from: https://github.com/franklynwang/EcneProject"
    for circuit in "${CIRCUITS[@]}"; do
      emit_result "${circuit}" "ecne" "skip" "ecne not installed"
    done
  fi
  echo ""
fi

# -----------------------------------------------------------------------
# 4. Picus under-constrained analysis (--picus)
#
# Picus (https://github.com/Veridise/Picus) uses SMT solving to
# detect under-constrained circuits. It can find issues that
# witness-level checking misses.
# -----------------------------------------------------------------------
if $RUN_PICUS; then
  echo "===== Picus Under-Constrained Analysis ====="
  if command -v picus &>/dev/null; then
    for circuit in "${CIRCUITS[@]}"; do
      R1CS="${BUILD_DIR}/${circuit}.r1cs"
      echo "  Analyzing ${circuit} …"
      PICUS_OUT="${BUILD_DIR}/${circuit}_picus.log"
      if picus --r1cs "${R1CS}" > "${PICUS_OUT}" 2>&1; then
        if grep -qi "safe\|no.*bug" "${PICUS_OUT}"; then
          echo "  ✓ ${circuit}: Picus found no under-constrained signals"
          emit_result "${circuit}" "picus" "pass" "safe"
        elif grep -qi "unsafe\|bug\|under.constrained" "${PICUS_OUT}"; then
          echo "  ✗ ${circuit}: Picus detected potential soundness issue"
          echo "    See ${PICUS_OUT} for details"
          emit_result "${circuit}" "picus" "fail" "potential soundness issue"
        else
          echo "  ? ${circuit}: Picus completed (review output manually)"
          emit_result "${circuit}" "picus" "info" "review output"
        fi
      else
        echo "  ⚠ ${circuit}: Picus analysis failed (non-zero exit)"
        emit_result "${circuit}" "picus" "error" "picus exited with error"
      fi
    done
  else
    echo "  SKIP: picus binary not found in PATH"
    echo "  Install from: https://github.com/Veridise/Picus"
    for circuit in "${CIRCUITS[@]}"; do
      emit_result "${circuit}" "picus" "skip" "picus not installed"
    done
  fi
  echo ""
fi

# -----------------------------------------------------------------------
# 5. Unified circuit check (if present)
# -----------------------------------------------------------------------
UNIFIED_CIRCOM="${SCRIPT_DIR}/circuits/unified_canonicalization_inclusion_root_sign.circom"
if [ -f "${UNIFIED_CIRCOM}" ]; then
  echo "===== Unified Circuit Property Checks ====="
  # Verify the unified circuit includes canonicalization binding
  if grep -q 'canonicalization' "${UNIFIED_CIRCOM}" || grep -q 'canonical' "${UNIFIED_CIRCOM}"; then
    echo "  ✓ Unified circuit: canonicalization binding present"
    emit_result "unified" "canonicalization_binding" "pass" "binding present"
  else
    echo "  ⚠ Unified circuit: no canonicalization reference found"
    emit_result "unified" "canonicalization_binding" "warn" "no reference found"
  fi
  echo ""
fi

# -----------------------------------------------------------------------
# 7. Summary + CI output
# -----------------------------------------------------------------------
echo "=============================="
echo "  Formal verification: ${PASS} passed, ${FAIL} failed"
echo "=============================="

if $CI_MODE; then
  RESULTS_FILE="${BUILD_DIR}/formal_verify_results.json"
  # Build JSON array
  echo "[" > "${RESULTS_FILE}"
  for i in "${!JSON_RESULTS[@]}"; do
    if [ "$i" -gt 0 ]; then
      echo "," >> "${RESULTS_FILE}"
    fi
    echo "  ${JSON_RESULTS[$i]}" >> "${RESULTS_FILE}"
  done
  echo "]" >> "${RESULTS_FILE}"
  echo ""
  echo "CI results written to: ${RESULTS_FILE}"
fi

if [ "${FAIL}" -gt 0 ]; then
  exit 1
fi

echo ""
echo "Formal verification checks complete."
