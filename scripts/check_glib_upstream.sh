#!/usr/bin/env bash
# Audit M-SC-1: verify the vendored `crates/glib-0.18.5-patched/` tree has not
# drifted from the published `glib-0.18.5` crate beyond the single documented
# backport (GHSA-wrw7-89jp-8q8g / gtk-rs/gtk-rs-core#1343) in
# `src/variant_iter.rs`. This crate links into every Linux build, so its
# byte-identity claim needs an automated gate — mirroring
# `scripts/check_light_poseidon_upstream.sh` and
# `scripts/check_circomlib_upstream.sh`.
#
# Run locally:  bash scripts/check_glib_upstream.sh
# CI:           wired into .github/workflows/ci.yml (glib-provenance job).
#
# Exit codes:
#   0  vendored copy matches the published crate (up to the documented patch)
#   1  drift detected — re-vendor or update the pin
#   2  required tooling missing
#
# See crates/glib-0.18.5-patched/PROVENANCE.md for the re-vendor procedure.

set -euo pipefail

# The PROVENANCE pins the published crate artifact (not a git tag) as the
# baseline, because cargo rewrites `path` deps on publish — the vendored
# Cargo.toml is the registry-normalized copy, so the .crate tarball is the
# byte-for-byte reference.
UPSTREAM_CRATE_URL="https://static.crates.io/crates/glib/glib-0.18.5.crate"
VENDORED_DIR="crates/glib-0.18.5-patched"
PATCHED_FILE="src/variant_iter.rs"

for tool in curl tar diff sed grep find; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: required tool '$tool' not found" >&2
        exit 2
    fi
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Downloading published glib-0.18.5 crate ..."
curl -fSL --connect-timeout 30 --retry 3 --retry-delay 5 \
    -o "$WORK/glib.crate" "$UPSTREAM_CRATE_URL"
tar -xzf "$WORK/glib.crate" -C "$WORK"
UP="$WORK/glib-0.18.5"
if [[ ! -d "$UP" ]]; then
    echo "error: extracted crate dir not found at $UP" >&2
    exit 2
fi

failed=0

# Every file in the published crate must exist byte-identically in the
# vendored copy — except variant_iter.rs, which carries the backport.
while IFS= read -r -d '' up_file; do
    rel="${up_file#"$UP"/}"
    ven_file="$VENDORED_DIR/$rel"

    if [[ ! -f "$ven_file" ]]; then
        echo "  !! vendored missing $rel (present in published crate)" >&2
        failed=1
        continue
    fi

    if [[ "$rel" == "$PATCHED_FILE" ]]; then
        # The only allowed delta. De-patch the vendored file (revert the two
        # backported lines) and require the result to be byte-identical to
        # upstream. This proves the patch is BOTH present AND the sole change:
        # if sed reverts too much or too little, the diff fails closed.
        sed -e 's/let mut p: \*mut libc::c_char/let p: *mut libc::c_char/' \
            -e 's/&mut p,/\&p,/' "$ven_file" > "$WORK/depatched"
        if ! diff -u "$up_file" "$WORK/depatched" >/dev/null; then
            echo "  !! DRIFT in $rel beyond the documented GHSA-wrw7-89jp-8q8g backport" >&2
            diff -u "$up_file" "$WORK/depatched" | head -40 >&2 || true
            failed=1
        elif ! grep -qE 'let mut p: \*mut libc::c_char' "$ven_file" \
            || ! grep -qE '&mut p,' "$ven_file"; then
            echo "  !! $rel is missing the GHSA-wrw7-89jp-8q8g backport lines" >&2
            failed=1
        else
            echo "  ok  $rel carries exactly the documented backport"
        fi
        continue
    fi

    if ! diff -q "$up_file" "$ven_file" >/dev/null; then
        echo "  !! DRIFT: $rel differs from published glib-0.18.5" >&2
        diff -u "$up_file" "$ven_file" | head -40 >&2 || true
        failed=1
    fi
done < <(find "$UP" -type f -print0)

# Vendored-only files: PROVENANCE.md is our deliberate addition. Anything else
# present in the vendored tree but absent from the published crate is drift.
while IFS= read -r -d '' ven_file; do
    rel="${ven_file#"$VENDORED_DIR"/}"
    [[ "$rel" == "PROVENANCE.md" ]] && continue
    if [[ ! -f "$UP/$rel" ]]; then
        echo "  !! vendored-only file not in published crate: $rel" >&2
        failed=1
    fi
done < <(find "$VENDORED_DIR" -type f -print0)

if [[ $failed -ne 0 ]]; then
    echo
    echo "FAIL: vendored glib has drifted from published glib-0.18.5 beyond the"
    echo "      documented GHSA-wrw7-89jp-8q8g backport."
    echo "      See $VENDORED_DIR/PROVENANCE.md for the re-vendor procedure."
    exit 1
fi

echo "OK: vendored glib matches published glib-0.18.5 (+ documented backport only)"
exit 0
