#!/usr/bin/env bash
# =============================================================================
# scripts/fuzz_24h.sh — 24-hour local reliability and security fuzz marathon
#
# Usage:
#   bash scripts/fuzz_24h.sh [--security-only | --storage-only | --smoke]
#
# Options:
#   --security-only   Run only security invariant fuzzing
#   --storage-only    Run only storage/ledger invariant fuzzing
#   --smoke           Run a short smoke pass (< 3 min, equivalent to CI)
#
# Environment variables:
#   TEST_DATABASE_URL   PostgreSQL URL for storage layer tests (required for
#                       storage fuzzing; auto-skipped if unset)
#   FUZZ_HOURS          Override run duration in hours (default: 24)
#   FUZZ_MAX_EXAMPLES   Override max Hypothesis examples per test (default: 10000)
#
# All fuzzing is strictly local — no third-party targets, no network scanning.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
SECURITY_ONLY=false
STORAGE_ONLY=false
SMOKE=false

for arg in "$@"; do
  case "$arg" in
    --security-only) SECURITY_ONLY=true ;;
    --storage-only)  STORAGE_ONLY=true ;;
    --smoke)         SMOKE=true ;;
    *) echo "Unknown flag: $arg" >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Profile selection
# ---------------------------------------------------------------------------
if $SMOKE; then
  export HYPOTHESIS_PROFILE="${HYPOTHESIS_PROFILE:-fuzz_smoke}"
  export FUZZ_MAX_EXAMPLES="${FUZZ_MAX_EXAMPLES:-30}"
  FUZZ_HOURS=0  # smoke: just one pass, no time loop
else
  export HYPOTHESIS_PROFILE="${HYPOTHESIS_PROFILE:-fuzz_24h}"
  export FUZZ_MAX_EXAMPLES="${FUZZ_MAX_EXAMPLES:-10000}"
  FUZZ_HOURS="${FUZZ_HOURS:-24}"
fi

echo "=== Olympus Fuzz Marathon ==="
echo "  Profile:         $HYPOTHESIS_PROFILE"
echo "  Max examples:    $FUZZ_MAX_EXAMPLES"
if [ "$FUZZ_HOURS" -gt 0 ] 2>/dev/null; then
  echo "  Duration:        ${FUZZ_HOURS}h"
fi
echo "  TEST_DATABASE_URL: ${TEST_DATABASE_URL:-(not set, storage tests will be skipped)}"
echo ""

# ---------------------------------------------------------------------------
# Build test marker selector
# ---------------------------------------------------------------------------
if $SMOKE; then
  MARKER="fuzz"
elif $SECURITY_ONLY; then
  MARKER="fuzz and security"
elif $STORAGE_ONLY; then
  MARKER="fuzz and storage"
else
  MARKER="fuzz"
fi

# ---------------------------------------------------------------------------
# Artifact directory
# ---------------------------------------------------------------------------
ARTIFACT_DIR="$REPO_ROOT/.hypothesis/fuzz-artifacts"
mkdir -p "$ARTIFACT_DIR"

# ---------------------------------------------------------------------------
# Run function
# ---------------------------------------------------------------------------
run_fuzz() {
  local modules=()
  if ! $STORAGE_ONLY; then
    modules+=("tests/fuzz/test_security_invariants_fuzz.py")
  fi
  if ! $SECURITY_ONLY && [ -n "${TEST_DATABASE_URL:-}" ]; then
    modules+=("tests/fuzz/test_storage_invariants_fuzz.py")
  fi

  if [ ${#modules[@]} -eq 0 ]; then
    echo "WARNING: No fuzz modules to run (set TEST_DATABASE_URL for storage tests)."
    return
  fi

  pytest "${modules[@]}" \
    -v --tb=short \
    -m "$MARKER" \
    --hypothesis-seed=0 \
    2>&1
}

# ---------------------------------------------------------------------------
# Smoke mode: single pass
# ---------------------------------------------------------------------------
if $SMOKE; then
  echo "--- Smoke pass ---"
  run_fuzz
  echo "Smoke pass complete."
  exit 0
fi

# ---------------------------------------------------------------------------
# Marathon mode: loop for FUZZ_HOURS hours
# ---------------------------------------------------------------------------
START_TS=$(date +%s)
END_TS=$(( START_TS + FUZZ_HOURS * 3600 ))
PASS=0

echo "Marathon start: $(date -Iseconds)"
echo "Marathon end:   $(date -d "@$END_TS" -Iseconds 2>/dev/null || date -r "$END_TS" -Iseconds 2>/dev/null || echo "(see end time above)")"
echo ""

while [ "$(date +%s)" -lt "$END_TS" ]; do
  PASS=$((PASS + 1))
  echo "=== Pass $PASS ($(date -Iseconds)) ==="

  # Use a different random seed each pass so Hypothesis explores new space
  SEED=$((RANDOM * RANDOM + PASS))
  pytest tests/fuzz/ \
    -v --tb=short \
    -m "$MARKER" \
    --hypothesis-seed="$SEED" \
    2>&1 || {
      echo "FAILURE detected on pass $PASS (seed=$SEED). Artifacts:"
      ls -lh "$ARTIFACT_DIR"/*.json 2>/dev/null | tail -5 || true
      # Continue running to accumulate more failures
    }
done

echo ""
echo "=== Marathon complete after $PASS passes ==="
echo "Artifacts saved to: $ARTIFACT_DIR"
ls -lh "$ARTIFACT_DIR"/*.json 2>/dev/null || echo "(no failure artifacts)"
