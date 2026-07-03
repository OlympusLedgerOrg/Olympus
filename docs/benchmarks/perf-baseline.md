# Performance Baseline

This is the reproducible smoke baseline for Olympus hot paths. It is intentionally
small enough for scheduled CI, while still exercising the code paths most likely
to regress user-visible latency:

- in-memory SMT update/prove/verify;
- persistent SMT `PersistentSmt` over `MemBackend` using the production batching,
  lock, and cache code path;
- dataset-manifest sealing and proof generation.

Run the quick baseline:

```bash
bash scripts/perf_baseline.sh
```

Run the heavier local baseline before/after a performance-sensitive change:

```bash
bash scripts/perf_baseline.sh full
```

To include real Postgres storage latency for the persistent SMT pass, point the
benchmark at a throwaway database. The script deliberately uses
`OLYMPUS_BENCH_DATABASE_URL`, not `DATABASE_URL`, because the Postgres benchmark
truncates `smt_nodes` and `smt_leaves`.

```bash
OLYMPUS_BENCH_DATABASE_URL=postgres://user:pass@localhost/olympus_bench \
  bash scripts/perf_baseline.sh full
```

CI runs the quick baseline on a schedule and uploads the raw console log as an
artifact. Treat the output as a trend signal, not an absolute hardware-independent
SLO; promote any stable budget into an explicit test only after it has been
observed across runner classes.
