#!/usr/bin/env bash
# -----------------------------------------------------------------------
# circomspect.sh — Static analysis gate for the Olympus Circom circuits
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
# GATING + BASELINE
# -----------------
# This is a blocking gate by default. To avoid failing on a set of reviewed,
# accepted findings (idiomatic patterns circomspect false-positives on — see
# circomspect_baseline.txt), each finding is reduced to a stable signature
# `ruleId|file|line` and compared against the committed baseline:
#
#   * a current finding NOT in the baseline  → NEW → fails (in strict mode)
#   * a baseline entry NOT in current output → stale → reported, non-fatal
#
# Because the signature includes the source line, a *new* instance of an
# already-accepted rule class at a *new* location still blocks — the baseline
# allow-lists exact locations, not whole rule classes.
#
# Modes:
#   (default)   Strict gate: exit non-zero on any NEW (non-baselined) finding.
#   --advisory  Report only; never fail (use for exploratory local runs).
#   --ci        Emit machine-readable results to build/circomspect_results.json
#               and per-circuit SARIF under build/circomspect/.
#   --update-baseline
#               Rewrite circomspect_baseline.txt from the CURRENT findings and
#               exit 0. Run this after an intentional circuit change, then
#               review the diff before committing.
#   --level <L> Minimum severity to report: INFO | WARNING | ERROR.
#               Default WARNING (INFO is very chatty).
#   --strict    Accepted for explicitness; strict is already the default.
#
# Install circomspect with:  cargo install circomspect
# -----------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_DIR="${SCRIPT_DIR}/build"
CIRCUITS_DIR="${SCRIPT_DIR}/circuits"
LIB_DIR="${SCRIPT_DIR}/vendor/circomlib/circuits"
SARIF_DIR="${BUILD_DIR}/circomspect"
BASELINE_FILE="${SCRIPT_DIR}/circomspect_baseline.txt"

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
STRICT=true            # gating by default
UPDATE_BASELINE=false
LEVEL="WARNING"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci) CI_MODE=true; shift ;;
    --advisory|--no-strict) STRICT=false; shift ;;
    --strict) STRICT=true; shift ;;
    --update-baseline) UPDATE_BASELINE=true; shift ;;
    --level) LEVEL="${2:?--level needs an argument}"; shift 2 ;;
    -h|--help) sed -n '2,55p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "Unknown flag: $1" >&2; exit 1 ;;
  esac
done

# -----------------------------------------------------------------------
# Preflight: required tooling.
# -----------------------------------------------------------------------
if ! command -v circomspect &>/dev/null; then
  echo "SKIP: circomspect not found in PATH."
  echo "      Install with: cargo install circomspect"
  if $CI_MODE; then
    mkdir -p "${BUILD_DIR}"
    printf '{"tool":"circomspect","status":"skip","detail":"binary not installed"}\n' \
      > "${BUILD_DIR}/circomspect_results.json"
  fi
  # A missing optional analyser must never break a local build. CI installs it,
  # so this skip never hides a regression there.
  exit 0
fi

# SARIF parsing (baseline comparison) needs python3. It ships on every CI runner
# and virtually every dev box; only hard-fail under --strict where the gate
# can't function without it.
if ! command -v python3 &>/dev/null; then
  if $STRICT && ! $UPDATE_BASELINE; then
    echo "ERROR: python3 is required for the circomspect baseline gate." >&2
    exit 2
  fi
  echo "WARN: python3 not found — baseline comparison unavailable; reporting only."
fi

echo "==> circomspect $(circomspect --version 2>/dev/null || echo '(version unknown)')"
echo "    level >= ${LEVEL}   strict=${STRICT}   baseline=${BASELINE_FILE##*/}"
echo ""

# circomspect resolves `include` paths relative to -L library dirs. We pass the
# vendored circomlib and the local circuits/lib so `pragma circom`/`include`
# both resolve without a global install.
LIB_ARGS=( -L "${CIRCUITS_DIR}" )
[[ -d "${LIB_DIR}" ]] && LIB_ARGS+=( -L "${LIB_DIR}" )
[[ -d "${CIRCUITS_DIR}/lib" ]] && LIB_ARGS+=( -L "${CIRCUITS_DIR}/lib" )

mkdir -p "${SARIF_DIR}"

# -----------------------------------------------------------------------
# 1. Analyse each circuit → human log + SARIF (source of truth for signatures).
# -----------------------------------------------------------------------
for circuit in "${CIRCUITS[@]}"; do
  SRC="${CIRCUITS_DIR}/${circuit}.circom"
  SARIF="${SARIF_DIR}/${circuit}.sarif"
  # Always start from a clean SARIF so a circuit that now analyses clean doesn't
  # leave a stale file behind to skew the signature set.
  rm -f "${SARIF}"
  if [[ ! -f "${SRC}" ]]; then
    echo "  - ${circuit}: SKIP (source not found at ${SRC})"
    continue
  fi
  echo "===== ${circuit} ====="
  LOG="${SARIF_DIR}/${circuit}.log"
  # circomspect exits 1 when it reports findings; capture without aborting so
  # every circuit is analysed and pass/fail is decided centrally from SARIF.
  set +e
  circomspect "${LIB_ARGS[@]}" --level "${LEVEL}" --sarif-file "${SARIF}" "${SRC}" \
    > "${LOG}" 2>&1
  set -e
  cat "${LOG}"
  echo ""
done

# -----------------------------------------------------------------------
# 2. Reduce SARIF results to stable `ruleId|file|line` signatures.
# -----------------------------------------------------------------------
sigs_from_sarif() {
  # $1 = directory of *.sarif. Prints one signature per line, sorted/unique.
  python3 - "$1" <<'PY'
import json, glob, os, sys
out = set()
for f in sorted(glob.glob(os.path.join(sys.argv[1], "*.sarif"))):
    try:
        d = json.load(open(f))
    except Exception:
        continue
    for run in d.get("runs", []):
        for res in run.get("results", []):
            rule = res.get("ruleId", "?")
            for loc in res.get("locations", []):
                pl = loc.get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                line = pl.get("region", {}).get("startLine", "?")
                out.add(f"{rule}|{os.path.basename(uri)}|{line}")
for s in sorted(out):
    print(s)
PY
}

CURRENT_SIGS=""
if command -v python3 &>/dev/null; then
  CURRENT_SIGS="$(sigs_from_sarif "${SARIF_DIR}")"
fi
CURRENT_COUNT=$(printf '%s\n' "${CURRENT_SIGS}" | grep -c '|' || true)

# --update-baseline: snapshot current findings as the accepted baseline.
if $UPDATE_BASELINE; then
  {
    echo "# circomspect accepted-findings baseline."
    echo "# Format: ruleId|file|line  (one accepted finding per line; # = comment)"
    echo "# Regenerate with:  bash proofs/circomspect.sh --update-baseline"
    echo "# Every entry must be a reviewed, accepted false-positive — see the"
    echo "# justifications in proofs/FORMAL_VERIFICATION.md. Anything NOT listed"
    echo "# here fails the strict gate."
    echo "#"
    printf '%s\n' "${CURRENT_SIGS}"
  } > "${BASELINE_FILE}"
  echo "Baseline updated (${CURRENT_COUNT} finding(s)) → ${BASELINE_FILE}"
  echo "Review the diff before committing."
  exit 0
fi

# Load the committed baseline (strip comments/blank lines).
BASELINE_SIGS=""
if [[ -f "${BASELINE_FILE}" ]]; then
  BASELINE_SIGS="$(grep -vE '^\s*(#|$)' "${BASELINE_FILE}" || true)"
fi

# NEW = current \ baseline ; STALE = baseline \ current.
NEW_SIGS="$(comm -23 <(printf '%s\n' "${CURRENT_SIGS}" | sort -u | sed '/^$/d') \
                     <(printf '%s\n' "${BASELINE_SIGS}" | sort -u | sed '/^$/d') || true)"
STALE_SIGS="$(comm -13 <(printf '%s\n' "${CURRENT_SIGS}" | sort -u | sed '/^$/d') \
                       <(printf '%s\n' "${BASELINE_SIGS}" | sort -u | sed '/^$/d') || true)"
NEW_COUNT=$(printf '%s\n' "${NEW_SIGS}" | grep -c '|' || true)
STALE_COUNT=$(printf '%s\n' "${STALE_SIGS}" | grep -c '|' || true)
BASELINED_COUNT=$(( CURRENT_COUNT - NEW_COUNT ))

echo "=============================="
echo "  circomspect: ${CURRENT_COUNT} finding(s) — ${BASELINED_COUNT} baselined, ${NEW_COUNT} NEW, ${STALE_COUNT} stale"
echo "=============================="
if [[ "${NEW_COUNT}" -gt 0 ]]; then
  echo ""
  echo "NEW findings (not in ${BASELINE_FILE##*/}):"
  printf '  %s\n' ${NEW_SIGS}
  echo ""
  echo "If these are genuine bugs, fix the circuit. If reviewed-and-accepted,"
  echo "run 'bash proofs/circomspect.sh --update-baseline' and commit the diff."
fi
if [[ "${STALE_COUNT}" -gt 0 ]]; then
  echo ""
  echo "Stale baseline entries (resolved — safe to prune from ${BASELINE_FILE##*/}):"
  printf '  %s\n' ${STALE_SIGS}
fi

# -----------------------------------------------------------------------
# 3. Machine-readable output (--ci).
# -----------------------------------------------------------------------
if $CI_MODE; then
  RESULTS_FILE="${BUILD_DIR}/circomspect_results.json"
  json_array() { # turn newline list into a JSON string array
    local first=true
    printf '['
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      $first || printf ','
      printf '"%s"' "$line"
      first=false
    done <<< "$1"
    printf ']'
  }
  {
    printf '{"tool":"circomspect","strict":%s,"total":%s,"baselined":%s,"new":%s,"stale":%s,"new_findings":%s,"stale_findings":%s}\n' \
      "${STRICT}" "${CURRENT_COUNT}" "${BASELINED_COUNT}" "${NEW_COUNT}" "${STALE_COUNT}" \
      "$(json_array "${NEW_SIGS}")" "$(json_array "${STALE_SIGS}")"
  } > "${RESULTS_FILE}"
  echo ""
  echo "CI results written to: ${RESULTS_FILE}"
fi

# -----------------------------------------------------------------------
# 4. Gate.
# -----------------------------------------------------------------------
if $STRICT && [[ "${NEW_COUNT}" -gt 0 ]]; then
  echo ""
  echo "FAIL: ${NEW_COUNT} new circomspect finding(s) not in the baseline." >&2
  exit 1
fi
exit 0
