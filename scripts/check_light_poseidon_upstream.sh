#!/usr/bin/env bash
# Audit L-20: verify the vendored `crates/light-poseidon` has not drifted
# from upstream beyond the documented arkworks-version edits.
#
# Run locally:  bash scripts/check_light_poseidon_upstream.sh
# CI:           wired into .github/workflows/ci.yml (after this PR lands).
#
# Exit codes:
#   0  vendored copy matches the upstream pin (up to allowed edits)
#   1  divergence detected — re-vendor or update the pin
#   2  required tooling missing

set -euo pipefail

UPSTREAM_REPO="https://github.com/Lightprotocol/light-poseidon"
UPSTREAM_SHA="203de7fea8209891c478d5e44254181c1472ce02"
VENDORED_DIR="crates/light-poseidon"

if ! command -v git >/dev/null 2>&1; then
    echo "error: git not found" >&2
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Cloning upstream at $UPSTREAM_SHA ..."
git clone --quiet --no-checkout "$UPSTREAM_REPO" "$WORK/upstream"
git -C "$WORK/upstream" checkout --quiet "$UPSTREAM_SHA"

# Upstream is a Cargo workspace — the actual crate lives at
# `light-poseidon/` (the vendored copy flattens it to the repo root for
# `path = "../crates/light-poseidon"` to work). Map each file we lock
# from `upstream_path -> vendored_path`.
LOCK_PAIRS=(
    "light-poseidon/src/lib.rs::src/lib.rs"
    "light-poseidon/src/parameters/bn254_x5.rs::src/parameters/bn254_x5.rs"
    "light-poseidon/src/parameters/mod.rs::src/parameters/mod.rs"
)

failed=0
for pair in "${LOCK_PAIRS[@]}"; do
    upstream_rel="${pair%%::*}"
    vendored_rel="${pair##*::}"
    upstream_full="$WORK/upstream/$upstream_rel"
    vendored_full="$VENDORED_DIR/$vendored_rel"
    if [[ ! -f "$upstream_full" ]]; then
        echo "  ?? upstream missing $upstream_rel at pinned SHA — re-pin or investigate" >&2
        failed=1
        continue
    fi
    if [[ ! -f "$vendored_full" ]]; then
        echo "  !! vendored missing $vendored_rel — corruption?" >&2
        failed=1
        continue
    fi
    if ! diff -u "$upstream_full" "$vendored_full" >/dev/null; then
        echo "  !! DRIFT: $vendored_rel differs from upstream $upstream_rel" >&2
        diff -u "$upstream_full" "$vendored_full" | head -40 >&2 || true
        failed=1
    else
        echo "  ok  $vendored_rel matches upstream $upstream_rel"
    fi
done

# Cargo.toml is allowed to differ ONLY in the arkworks version pins and
# the description field. Compare against the per-crate Cargo.toml inside
# the workspace, not the workspace root Cargo.toml.
echo "==> Auditing Cargo.toml diff (allowed edits: arkworks pin + description + publish) ..."
upstream_cargo="$WORK/upstream/light-poseidon/Cargo.toml"
vendored_cargo="$VENDORED_DIR/Cargo.toml"
if [[ ! -f "$upstream_cargo" ]]; then
    echo "  ?? upstream missing light-poseidon/Cargo.toml at pinned SHA" >&2
    failed=1
elif ! diff "$upstream_cargo" "$vendored_cargo" \
    | grep -vE '^[<>] (description|ark-bn254|ark-ff|publish|thiserror|version|authors|repository|license|edition|name) ?= ?' \
    | grep -vE '^---|^[0-9]+[acd][0-9]+$' \
    | grep -q '^[<>]'; then
    echo "  ok  Cargo.toml differences within allowed envelope"
else
    echo "  !! Cargo.toml has unexpected changes beyond the allowed edits" >&2
    diff -u "$upstream_cargo" "$vendored_cargo" >&2 || true
    failed=1
fi

if [[ $failed -ne 0 ]]; then
    echo
    echo "FAIL: vendored light-poseidon has drifted from the pinned upstream SHA."
    echo "      See crates/light-poseidon/PROVENANCE.md for the re-vendor procedure."
    exit 1
fi

echo "OK: vendored light-poseidon matches upstream pin $UPSTREAM_SHA"
exit 0
