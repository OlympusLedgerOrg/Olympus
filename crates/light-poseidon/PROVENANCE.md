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

The Poseidon **algorithm, round constants, and MDS matrix are
byte-identical to upstream** (`src/lib.rs` + `src/parameters/*.rs` are
copied verbatim), and the test suite in `tests/` is the upstream test
suite verbatim. The intentional divergences are confined to `Cargo.toml`
and are all build-metadata / dependency-pin edits — none touch the
hashing logic:

| Divergence | Reason |
| ---------- | ------ |
| `ark-bn254` / `ark-ff` pinned `=0.6.0` (upstream `0.5.0`) | Align with the Olympus workspace's arkworks 0.6 tree (see below). |
| `thiserror` bumped `1.0` → `2.0` | Match the workspace's `thiserror` major. |
| `num-bigint` relaxed `0.4.4` → `0.4` | Defer to the workspace lockfile. |
| `[dev-dependencies]` (`criterion`, `rand`, `hex`) + `[[bench]]` dropped | Upstream benches aren't built here; the parity tests live in `olympus-crypto`. |
| `readme` / `keywords` metadata dropped, `publish = false` added | Path-local crate, never published to crates.io. |

## CI provenance check

`scripts/check_light_poseidon_upstream.sh` fetches the upstream tag and
diffs `src/lib.rs` + `src/parameters/*.rs` against the vendored copy
**byte-for-byte** — any drift in the crypto-bearing files fails the
script. It then audits `Cargo.toml`, permitting only the build-metadata /
dependency-pin edits enumerated in the table above; any other change
(a new dependency, a `[patch]` section, an edited source file) fails the
script with a non-zero exit so CI rejects the PR. Run locally with:

```bash
bash scripts/check_light_poseidon_upstream.sh
```

## Compact seed (`bn254_x5_seed.json`) — Olympus addition

`bn254_x5_seed.json` is **not** part of upstream; it is an Olympus-local,
human-auditable mirror of the same parameters held in
`src/parameters/bn254_x5.rs`. Each BN254 field element is stored as its 4
little-endian `u64` limbs (`ark_ff::BigInteger256`), so the ~1.5 MB generated
table compresses to ~0.6 MB of pure data. It is **not** wired into the crate
build — `src/parameters/bn254_x5.rs` remains the verbatim, L-20-pinned source
that the crate compiles. The seed exists only as a smaller re-derivation source
and a second provenance anchor.

The test
`olympus_crypto::poseidon::tests::seed_reproduces_light_poseidon_parameters`
(CI job **light-poseidon seed reproduces params**) reconstructs the parameters
from the seed and asserts they equal the ones the crate actually compiles, for
every Circom width (t = 2..=13). Combined with the byte-for-byte L-20 check
above (committed table == upstream), this transitively pins the seed to
upstream: any seed edit that drifts from the committed table fails CI.

The seed does **not** alter the L-20 mechanism — `bn254_x5.rs` is still the
verbatim file diffed against upstream, and the re-vendor procedure below is
unchanged. If a re-vendor ever changes the table, regenerate the seed in the
same commit so the reproducibility test stays green.

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
