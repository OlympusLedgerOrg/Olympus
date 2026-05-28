#!/usr/bin/env bash
# Verify the vendored `proofs/vendor/circomlib/circuits/` tree has not
# drifted from the pinned upstream tag.
#
# Run locally:  bash scripts/check_circomlib_upstream.sh
# CI:           wired into .github/workflows/ci.yml.
#
# Exit codes:
#   0  vendored copy is byte-identical to upstream pin
#   1  drift detected — re-vendor or update the pin
#   2  required tooling missing

set -euo pipefail

UPSTREAM_REPO="https://github.com/iden3/circomlib"
UPSTREAM_TAG="v2.0.5"
VENDORED_DIR="proofs/vendor/circomlib"

if ! command -v git >/dev/null 2>&1; then
    echo "error: git not found" >&2
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Cloning upstream circomlib at $UPSTREAM_TAG ..."
git clone --quiet --depth 1 --branch "$UPSTREAM_TAG" "$UPSTREAM_REPO" "$WORK/upstream"

upstream_circuits="$WORK/upstream/circuits"
vendored_circuits="$VENDORED_DIR/circuits"

if [[ ! -d "$upstream_circuits" ]]; then
    echo "error: upstream $UPSTREAM_TAG has no circuits/ directory — re-pin or investigate" >&2
    exit 1
fi
if [[ ! -d "$vendored_circuits" ]]; then
    echo "error: vendored $vendored_circuits missing — corruption?" >&2
    exit 1
fi

# Byte-for-byte recursive diff of circuits/. The vendored tree carries
# NO Olympus-specific edits (PROVENANCE.md "byte-identical to upstream
# v2.0.5"); any difference at all is drift.
echo "==> Diffing $vendored_circuits against upstream circuits/ ..."
if diff -r --brief "$upstream_circuits" "$vendored_circuits" >"$WORK/diff.out" 2>&1; then
    upstream_count="$(find "$upstream_circuits" -type f | wc -l | tr -d ' ')"
    vendored_count="$(find "$vendored_circuits" -type f | wc -l | tr -d ' ')"
    echo "  ok  $vendored_count files match upstream ($upstream_count files in upstream tag)"
else
    echo "  !! DRIFT detected:" >&2
    sed 's/^/      /' "$WORK/diff.out" >&2
    echo
    echo "FAIL: vendored circomlib has drifted from upstream $UPSTREAM_TAG."
    echo "      See $VENDORED_DIR/PROVENANCE.md for the re-vendor procedure."
    echo "      Briefly:"
    echo "        1. Bump the upstream tag in PROVENANCE.md + this script."
    echo "        2. cp -r node_modules/circomlib/circuits/. $vendored_circuits/"
    echo "        3. Re-run this script to verify byte-equality."
    exit 1
fi

# LICENSE is special: upstream tag v2.0.5 does not ship one (only
# package.json's GPL-3.0 declaration). We carry the canonical SPDX
# GPL-3.0-only text instead. Just sanity-check it's still the right
# license (haven't been silently replaced with something else).
echo "==> Sanity-checking LICENSE is GPL-3.0 ..."
if [[ ! -s "$VENDORED_DIR/LICENSE" ]]; then
    echo "  !! LICENSE missing or empty at $VENDORED_DIR/LICENSE" >&2
    exit 1
fi
if ! grep -q 'GNU GENERAL PUBLIC LICENSE' "$VENDORED_DIR/LICENSE"; then
    echo "  !! LICENSE does not look like GPL ($VENDORED_DIR/LICENSE)" >&2
    exit 1
fi
if ! grep -q 'Version 3' "$VENDORED_DIR/LICENSE"; then
    echo "  !! LICENSE is not GPL Version 3" >&2
    exit 1
fi
echo "  ok  LICENSE is GPL-3.0 ($(wc -c <"$VENDORED_DIR/LICENSE") bytes)"

echo
echo "OK: vendored circomlib matches upstream pin $UPSTREAM_TAG."
exit 0
