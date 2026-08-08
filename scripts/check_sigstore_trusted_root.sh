#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Verify the vendored Sigstore trust root has not drifted from what Sigstore's
# TUF repository currently publishes.
#
# Run locally:  bash scripts/check_sigstore_trusted_root.sh
# CI:           wired into .github/workflows/ci.yml.
#
# What this DOES check: that the bytes in
# `src-tauri/vendor/sigstore/trusted_root.json` are the target Sigstore's TUF
# metadata currently names, by walking timestamp -> snapshot -> targets and
# comparing the declared sha256 with the vendored file.
#
# What this does NOT check: TUF signatures. Olympus ships no TUF client (see
# src-tauri/vendor/sigstore/PROVENANCE.md for why). A human verifies signatures
# out-of-band when taking a new pin. Treat a red run as "upstream moved, go
# re-vendor deliberately", not as "upstream is compromised".
#
# Exit codes:
#   0  vendored copy matches the currently published target
#   1  drift detected — re-vendor or update the pin
#   2  required tooling missing
#   3  upstream unreachable / unexpected response (network, not drift)

set -euo pipefail

TUF_BASE="https://tuf-repo-cdn.sigstore.dev"
VENDORED="src-tauri/vendor/sigstore/trusted_root.json"
TARGET_NAME="trusted_root.json"

for tool in curl python3 sha256sum; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool not found" >&2
        exit 2
    fi
done

if [[ ! -f "$VENDORED" ]]; then
    echo "error: vendored trust root missing at $VENDORED" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fetch() {
    # --fail so an HTML error page never reaches the JSON parser.
    #
    # Bounded: a stalled CDN connection must not hang a CI job until the
    # workflow-level timeout kills it with no useful output. --max-time covers
    # the whole transfer and is generous for files of this size (largest is the
    # ~7 KB trust root); --retry-max-time bounds the retries in aggregate, since
    # --retry 3 would otherwise multiply --max-time.
    if ! curl -sS --fail --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 60 \
        --retry 3 --retry-connrefused --retry-max-time 120 \
        -o "$2" "$1"; then
        echo "error: could not fetch $1" >&2
        exit 3
    fi
}

json() { python3 -c "$@"; }

echo "==> timestamp.json"
fetch "$TUF_BASE/timestamp.json" "$WORK/timestamp.json"
SNAPSHOT_VERSION="$(json '
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))["signed"]
print(d["meta"]["snapshot.json"]["version"])' "$WORK/timestamp.json")"

echo "==> ${SNAPSHOT_VERSION}.snapshot.json"
fetch "$TUF_BASE/${SNAPSHOT_VERSION}.snapshot.json" "$WORK/snapshot.json"
TARGETS_VERSION="$(json '
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))["signed"]
print(d["meta"]["targets.json"]["version"])' "$WORK/snapshot.json")"

echo "==> ${TARGETS_VERSION}.targets.json"
fetch "$TUF_BASE/${TARGETS_VERSION}.targets.json" "$WORK/targets.json"
UPSTREAM_SHA="$(json '
import json,sys
t=json.load(open(sys.argv[1],encoding="utf-8"))["signed"]["targets"]
name=sys.argv[2]
if name not in t:
    sys.exit(f"target {name} absent from targets metadata")
print(t[name]["hashes"]["sha256"])' "$WORK/targets.json" "$TARGET_NAME")"

# Fetch the target itself and confirm the repository actually serves bytes
# matching the digest its own metadata declares. Comparing the vendored copy to
# the metadata alone would pass even if the CDN were serving something else
# entirely under that name — the declared digest and the served bytes are two
# separate claims, and PROVENANCE.md asserts both were checked at pin time.
# Consistent-snapshot naming: targets/<sha256>.<target-name>.
echo "==> targets/${UPSTREAM_SHA}.${TARGET_NAME}"
fetch "$TUF_BASE/targets/${UPSTREAM_SHA}.${TARGET_NAME}" "$WORK/target.json"
SERVED_SHA="$(sha256sum "$WORK/target.json" | cut -d' ' -f1)"
if [[ "$SERVED_SHA" != "$UPSTREAM_SHA" ]]; then
    cat >&2 <<EOF
error: Sigstore's TUF repository is internally inconsistent.

  targets metadata declares : $UPSTREAM_SHA
  served target hashes to   : $SERVED_SHA

This is not vendored-copy drift. Do not re-vendor from these bytes; report it
upstream and re-run once the repository is consistent.
EOF
    exit 3
fi

VENDORED_SHA="$(sha256sum "$VENDORED" | cut -d' ' -f1)"

echo
echo "  snapshot version : $SNAPSHOT_VERSION"
echo "  targets version  : $TARGETS_VERSION"
echo "  upstream sha256  : $UPSTREAM_SHA (served bytes agree)"
echo "  vendored sha256  : $VENDORED_SHA"
echo

if [[ "$UPSTREAM_SHA" == "$VENDORED_SHA" ]]; then
    echo "OK: vendored Sigstore trust root matches the published TUF target."
    exit 0
fi

cat >&2 <<EOF
DRIFT: the vendored Sigstore trust root is not the currently published target.

  vendored : $VENDORED_SHA
  upstream : $UPSTREAM_SHA

This is expected when Sigstore rotates or republishes its trust root. Follow
"Rotating the pin" in src-tauri/vendor/sigstore/PROVENANCE.md — which includes
verifying the TUF signatures out-of-band before trusting the new bytes. Note
that receipts already stored against a key that disappears will stop verifying.
EOF
exit 1
