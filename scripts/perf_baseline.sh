#!/usr/bin/env bash
set -euo pipefail

# Reproducible, low-noise performance smoke baseline. The default "quick" mode
# is sized for scheduled CI and local regression checks; "full" is for a
# developer machine before/after a suspected hot-path change.

mode="${1:-quick}"

case "${mode}" in
  quick)
    smt_sizes=(100)
    persistent_sizes=(100)
    manifest_args=(1000 4)
    ;;
  full)
    smt_sizes=(100 1000 10000)
    persistent_sizes=(100 1000)
    manifest_args=(100000 8)
    ;;
  *)
    echo "usage: scripts/perf_baseline.sh [quick|full]" >&2
    exit 2
    ;;
esac

echo "== Olympus performance baseline (${mode}) =="
echo

echo "::group::in-memory SMT"
cargo run --release -p olympus-crypto --example smt_benchmark --features smt -- "${smt_sizes[@]}"
echo "::endgroup::"
echo

echo "::group::persistent SMT (MemBackend; Postgres only when OLYMPUS_BENCH_DATABASE_URL is set)"
cargo run --release -p olympus-desktop --no-default-features --example smt_persistent_benchmark -- "${persistent_sizes[@]}"
echo "::endgroup::"
echo

echo "::group::dataset manifest sealing"
cargo run --release -p olympus-manifest --example bench_manifest -- "${manifest_args[@]}"
echo "::endgroup::"

echo
echo "Performance baseline completed."
