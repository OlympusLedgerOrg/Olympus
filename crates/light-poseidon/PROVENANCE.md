# light-poseidon — vendoring provenance

This crate is a vendored fork of upstream
[`Lightprotocol/light-poseidon`](https://github.com/Lightprotocol/light-poseidon).
Audit L-20 requires that any drift between this fork and the upstream
audited release surface in CI rather than at proof-verification time.

## Upstream pin

| Field             | Value |
| ----------------- | ----- |
| Upstream repo     | `https://github.com/Lightprotocol/light-poseidon` |
| Upstream tag      | `v0.4.0` |
| Upstream git SHA  | `203de7fea8209891c478d5e44254181c1472ce02` |
| Veridise audit    | `assets/audit.pdf` in upstream repo |
| Vendored at       | 2026-05-19 (see commit history) |

The only intentional divergences from upstream `v0.4.0` are listed in
`Cargo.toml`'s `description` field — currently just the arkworks pin bump
from `0.5` to `0.6` to align with the rest of the Olympus workspace. The
Poseidon **algorithm, round constants, and MDS matrix are byte-identical
to upstream**, and the test suite in `tests/` is the upstream test suite
verbatim.

## CI provenance check

`scripts/check_light_poseidon_upstream.sh` fetches the upstream tag and
diffs `src/lib.rs` + `src/parameters/*.rs` against the vendored copy,
allowing only the documented arkworks-version edits. Any other diff
fails the script with a non-zero exit so CI rejects the PR. Run locally
with:

```bash
bash scripts/check_light_poseidon_upstream.sh
```

## Why path-local rather than git-dep

`crates.io`'s published `light-poseidon` is still on arkworks 0.5; the
arkworks 0.6 bump hasn't landed upstream. Pulling a git dep at the
upstream tag would re-introduce the arkworks 0.5 dep tree alongside our
0.6 tree, which (per [project_dep_triage_2026_05]) compounded into
~200 MB of duplicated compile graph and a rand_core 0.6/0.9 split that
took weeks to clean up. Vendoring + this provenance check is the
trade-off: we eat the audit obligation to keep the dep graph clean.

## When to re-vendor

When upstream cuts a release that:

1. Includes the arkworks 0.6 bump (so we can stop diverging), OR
2. Carries a security fix relevant to our Poseidon usage.

Re-vendoring procedure:

1. Update the upstream SHA above.
2. Copy upstream `src/lib.rs` + `src/parameters/*.rs` verbatim.
3. Re-apply the arkworks pin bump in `Cargo.toml`.
4. Run `cargo test -p light-poseidon` AND `cargo test -p olympus-crypto --features poseidon`.
   The cross-implementation parity test
   (`olympus-crypto::poseidon::tests::poseidon_round_constants_match_light_poseidon_t3`)
   must pass — if it fails, upstream has changed a constant and the
   `olympus-crypto/src/poseidon.rs` inlined table must be updated to match.
5. Update `Vendored at` date above.
