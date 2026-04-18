#!/usr/bin/env bash
#
# run-govulncheck.sh — Run govulncheck against a Go module and apply the
# suppression baseline at go-vuln-baseline.txt.
#
# govulncheck has no native ignore flag, so we capture its -json output and
# post-filter it: a finding is suppressed if either its primary Go vuln ID
# (GO-YYYY-NNNN) or any of its aliases (CVE-*, GHSA-*) appears in the
# baseline.
#
# Only entries with a `finding` key (i.e. actual call-graph reachability into
# vulnerable code) cause this script to fail. Vulnerabilities that exist in
# imports but are not called are reported but do not fail CI, matching the
# default govulncheck behavior for non-source modes.
#
# Usage:
#   scripts/run-govulncheck.sh <module-dir> [<package-pattern>]
#
# Example:
#   scripts/run-govulncheck.sh services/sequencer-go ./...
#
# Exit codes:
#   0 — no unsuppressed findings
#   1 — at least one finding not in the baseline
#   2 — invocation error (missing tool, bad args)
#
# Mirrors the suppression model of cargo-audit-baseline.txt and
# pip-audit-baseline.txt, both wired into the same `supply-chain` CI job.

set -euo pipefail

MODULE_DIR="${1:-}"
PACKAGE_PATTERN="${2:-./...}"

if [[ -z "${MODULE_DIR}" ]]; then
  echo "usage: $0 <module-dir> [<package-pattern>]" >&2
  exit 2
fi

if [[ ! -d "${MODULE_DIR}" ]]; then
  echo "error: module directory not found: ${MODULE_DIR}" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE_FILE="${REPO_ROOT}/go-vuln-baseline.txt"

if [[ ! -f "${BASELINE_FILE}" ]]; then
  echo "error: baseline file not found: ${BASELINE_FILE}" >&2
  exit 2
fi

if ! command -v govulncheck >/dev/null 2>&1; then
  echo "error: govulncheck not on PATH; install with 'go install golang.org/x/vuln/cmd/govulncheck@latest'" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq not on PATH (required for JSON post-filtering)" >&2
  exit 2
fi

# Load baseline IDs (one per line, strip comments and blank lines).
BASELINE_IDS="$(grep -v '^[[:space:]]*#' "${BASELINE_FILE}" | awk 'NF {print $1}' | sort -u)"

JSON_OUT="$(mktemp)"
trap 'rm -f "${JSON_OUT}"' EXIT

# govulncheck exits non-zero when findings are present; capture and continue.
echo "::group::govulncheck ${MODULE_DIR} (${PACKAGE_PATTERN})"
(
  cd "${MODULE_DIR}"
  govulncheck -json "${PACKAGE_PATTERN}" > "${JSON_OUT}"
) || true
echo "::endgroup::"

# Build a map: OSV id -> space-separated aliases.
# govulncheck emits separate {osv: ...} and {finding: ...} JSON objects.
ALIAS_MAP="$(jq -r 'select(.osv) | [.osv.id] + (.osv.aliases // []) | join(" ")' "${JSON_OUT}" || true)"

# Collect distinct OSV ids that have actual call-graph findings.
FINDING_IDS="$(jq -r 'select(.finding) | .finding.osv' "${JSON_OUT}" 2>/dev/null | sort -u || true)"

if [[ -z "${FINDING_IDS}" ]]; then
  echo "govulncheck: no call-graph findings in ${MODULE_DIR}"
  exit 0
fi

UNSUPPRESSED=()
SUPPRESSED=()
for osv in ${FINDING_IDS}; do
  # Pull the alias line for this OSV id (may be empty if no .osv record).
  aliases="$(echo "${ALIAS_MAP}" | awk -v id="${osv}" '$1 == id { print; exit }')"
  if [[ -z "${aliases}" ]]; then
    aliases="${osv}"
  fi

  matched=""
  for ident in ${aliases}; do
    if echo "${BASELINE_IDS}" | grep -Fxq "${ident}"; then
      matched="${ident}"
      break
    fi
  done

  if [[ -n "${matched}" ]]; then
    SUPPRESSED+=("${osv} (matched baseline entry: ${matched})")
  else
    UNSUPPRESSED+=("${osv} [aliases: ${aliases}]")
  fi
done

if [[ ${#SUPPRESSED[@]} -gt 0 ]]; then
  echo "Suppressed findings (in baseline):"
  printf '  - %s\n' "${SUPPRESSED[@]}"
fi

if [[ ${#UNSUPPRESSED[@]} -gt 0 ]]; then
  echo "::error::govulncheck: ${#UNSUPPRESSED[@]} unsuppressed finding(s) in ${MODULE_DIR}:"
  printf '  - %s\n' "${UNSUPPRESSED[@]}" >&2
  echo ""
  echo "Re-run locally for full traces:"
  echo "  (cd ${MODULE_DIR} && govulncheck ${PACKAGE_PATTERN})"
  echo ""
  echo "If a finding is not actionable, add its ID (GO-YYYY-NNNN, CVE-*, or GHSA-*)"
  echo "to go-vuln-baseline.txt with a justification comment."
  exit 1
fi

echo "govulncheck: all findings in ${MODULE_DIR} are suppressed by baseline"
exit 0
