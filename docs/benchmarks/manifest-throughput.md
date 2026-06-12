# Dataset-manifest throughput

Published throughput for committing a dataset manifest and generating
record-level proofs (ADR-0027). These are the numbers a lab needs before
adopting Olympus as pipeline infrastructure.

> **TL;DR.** A 1,000,000-record manifest commits in **~35 seconds**
> single-threaded; an inclusion or exclusion proof is generated in **~0.02 ms**
> and is **~30 KB** of JSON. Extrapolated linearly, a 10M-record manifest commits
> in **~6 minutes** single-threaded. The commit covers *all* records with a
> single ~hundred-byte ledger commit, because `manifest_root` is one SMT root.

## What "commit" means here

`seal` is the local commitment step: derive each record's SMT key + leaf hash
(`olympus_crypto::leaf_hash`, binding shard + parser + model provenance), build
the path-compressed SMT (`olympus_manifest::smt_batch`), and compute
`manifest_root` (the global root) plus each shard's subtree root. Anchoring that
root to the ledger is then a single `/ingest/files` POST of the compact manifest
document (a few hundred bytes) — independent of dataset size, so it is not the
bottleneck and is excluded from the build timings below.

## Measured results

Hardware: the CI/dev container this was run in (single thread; no SIMD tuning).
Synthetic dataset, 4 KB nominal per record, deterministic content hashes.

| Records | Shards | Seal (commit) | Throughput | Inclusion proof | Exclusion proof | Proof size |
|--------:|-------:|--------------:|-----------:|----------------:|----------------:|-----------:|
| 100,000 | 8 | 3.40 s | ~29,400 rec/s | 0.01 ms | 0.06 ms | ~30 KB |
| 1,000,000 | 16 | 35.5 s | ~28,200 rec/s | 0.02 ms | 0.04 ms | ~30 KB |

Notes:

- **Proof generation is `O(256)`** — independent of dataset size — because the
  manifest is compiled once into a path-compressed tree and a proof is a single
  root-to-leaf walk. (Before path compression, a naïve per-proof rebuild took
  ~6.9 s at 100K records; the compressed builder cut that by ~5 orders of
  magnitude with byte-identical output.)
- **Proof size is fixed at 256 SMT siblings** (~8 KB raw, ~30 KB as
  pretty-printed JSON with provenance fields). This is the cost of sound,
  ZK-circuit-compatible non-membership; it does not grow with the dataset.
- **Throughput is leaf-hash + node-hash bound** (BLAKE3). Seal is single-threaded
  today; the left/right subtree builds are independent and parallelize, so a
  multi-core build is expected to scale near-linearly (future work, ADR-0027).

### Extrapolation to 1 TB / 10 M records

Seal cost is linear in record count (each leaf contributes one leaf-hash plus an
`O(256)` ladder of node-hashes), so 10 M records ≈ **10 × the 1 M figure ≈ 6
minutes** single-threaded. The 1 TB figure is a function of *local hashing
bandwidth*, not Olympus: BLAKE3 hashes well above 1 GB/s/core, so streaming 1 TB
off disk to produce the content hashes is I/O-bound and runs in parallel with,
and typically dominates, the ~6-minute tree build. Record count — not byte
volume — drives the manifest build time.

## Reproducing

```bash
# Build + run the benchmark harness (release is required for representative numbers).
cargo run --release -p olympus-manifest --example bench_manifest -- <RECORDS> <SHARDS>

# Examples:
cargo run --release -p olympus-manifest --example bench_manifest -- 100000 8
cargo run --release -p olympus-manifest --example bench_manifest -- 1000000 16
```

The harness (`crates/olympus-manifest/examples/bench_manifest.rs`) prints the
`manifest_root`, the seal wall-clock and records/sec, and the per-proof latency
and JSON size. Content hashes are derived deterministically from the record
index, so the `manifest_root` is reproducible run to run.

To benchmark the end-to-end CLI on real files instead of synthetic records:

```bash
cargo build --release -p olympus-cli         # from clients/cli
time ./target/release/olympus build --data /path/to/dataset --dataset-id myds --shard-from-subdir
```
