# Build Week judge-demo assets

The judge demo uses deterministic synthetic leaves generated inside
`olympus-smt-demo`; no external dataset, account, API key, or network access is
required.

Source: [`../src-tauri/src/bin/olympus_smt_demo.rs`](../src-tauri/src/bin/olympus_smt_demo.rs)

Instructions and expected output: [`../JUDGES.md`](../JUDGES.md)

Narrated demonstration script: [`BUILD_WEEK_VIDEO_SCRIPT.md`](BUILD_WEEK_VIDEO_SCRIPT.md)

The public binaries are built by
[`../.github/workflows/build-week-demo.yml`](../.github/workflows/build-week-demo.yml)
and published as GitHub Release assets. Binary files are intentionally not
committed to Git.
