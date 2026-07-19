# Build Week judge-demo assets

The judge demo uses deterministic synthetic leaves generated inside
`olympus-smt-demo` plus the committed public canonicalization receipt fixture.
It needs no external dataset, account, API key, network access, ZK toolchain, or
live proving.

One executable demonstrates both Build Week extensions:

- PR #1398's transaction-bound SQLite SMT backend is the runnable product
  foundation.
- PR #1409's fixed-image RISC Zero receipt is the cryptographic verification
  highlight. The binary verifies the real succinct receipt, recomputes its
  exact source binding, and rejects a journal mutation.

Source: [`../src-tauri/src/bin/olympus_smt_demo.rs`](../src-tauri/src/bin/olympus_smt_demo.rs)

Instructions and expected output: [`../JUDGES.md`](../JUDGES.md)

Narrated demonstration script: [`BUILD_WEEK_VIDEO_SCRIPT.md`](BUILD_WEEK_VIDEO_SCRIPT.md)

The public binaries are built by
[`../.github/workflows/build-week-demo.yml`](../.github/workflows/build-week-demo.yml)
and published as GitHub Release assets. Binary files are intentionally not
committed to Git.
