# Vendored, minimally-patched `ppv-lite86` 0.2.20

This is a byte-for-byte copy of the upstream crates.io release
**`ppv-lite86` v0.2.20**, with a single, surgical change.

## Why

Upstream 0.2.20 (and 0.2.21) leave two methods of the generic, non-x86-SIMD
`u64x4` implementation as `unimplemented!()`:

```rust
// src/generic.rs — impl Words4 for u64x4_generic
fn shuffle1230(self) -> Self { unimplemented!() }
fn shuffle3012(self) -> Self { unimplemented!() }
```

The generic path is the one selected on **aarch64** (Apple Silicon). Olympus's
`babyjubjub-permissive` crate uses `blake-hash` (the original BLAKE-512), which
drives ppv-lite86's `u64x4` lane shuffles. So on Apple Silicon, any BLAKE-512
call — including **Baby Jubjub key derivation and EdDSA signing** — panics with
`not implemented`. On x86 the SIMD path is used and the bug is never reached,
which is why it went unnoticed (all development/CI was x86 until macОС CI was
added).

## The change

Only those two methods are implemented, bit-exactly, in terms of the crate's
own already-correct `MultiLane::{to_lanes, from_lanes}`:

```rust
fn shuffle1230(self) -> Self {
    let [a, b, c, d] = self.to_lanes();
    Self::from_lanes([b, c, d, a])   // lanes [1,2,3,0]
}
fn shuffle3012(self) -> Self {
    let [a, b, c, d] = self.to_lanes();
    Self::from_lanes([d, a, b, c])   // lanes [3,0,1,2]
}
```

The lane permutation is read directly from the method name (`shuffleWXYZ` →
result lane `i` = source lane `[W,X,Y,Z][i]`) and cross-checked against the
adjacent, already-implemented `shuffle2301` (`[self.0[1], self.0[0]]` == lanes
`[2,3,0,1]`). These are the ChaCha/BLAKE diagonalization rotations
(rotate-left by 1, 2, 3).

Nothing else is modified. No new dependencies, no API changes.

## Correctness

`crates/babyjubjub-permissive/src/eddsa.rs::blake512_cross_platform_known_answer`
pins the BLAKE-512 digest of a fixed input. The expected value was computed on
the proven-correct x86 SIMD path; `macos-ci.yml` runs the same test on Apple
Silicon through this patched generic path, so a wrong shuffle fails CI on arm64.

## Wiring

- `[patch.crates-io] ppv-lite86 = { path = "crates/ppv-lite86-patched" }` in the
  workspace `Cargo.toml`.
- Listed in the workspace `exclude` so `--workspace` does not build the
  upstream crate's own targets.

## Retire when

An upstream `ppv-lite86` release implements the generic `u64x4` shuffles. At
that point, drop the `[patch]` entry, remove this directory, and delete the
exclude line. Upstream tracking: cryptocorrosion/cryptocorrosion.

Checked 2026-06-10: upstream 0.2.21 (latest) still leaves
`u64x4_generic::shuffle1230` / `shuffle3012` as `unimplemented!()`
(verified against the published crate source) — the patch cannot be
retired yet.
