# circomlib — vendoring provenance

This directory is a vendored fork of upstream
[`iden3/circomlib`](https://github.com/iden3/circomlib) — the canonical
library of Circom circuit templates (Poseidon, EdDSA, Merkle, bitify,
comparators, etc.) used by the Olympus ZK circuits in
`proofs/circuits/`.

Vendoring rationale:

1. **Supply-chain reproducibility.** `npm install circomlib` resolves
   against the public registry; vendoring pins exact bytes so a
   ceremony rebuild ten years from now produces identical artifacts.
   This matters for press-freedom and court-evidence use cases where
   an attested proof may need to be re-verifiable decades later.
2. **Build-without-network.** Operators in hostile network
   environments (the OTF user base) can rebuild from source without
   reaching the npm registry.
3. **Drift detection.** A CI script
   (`scripts/check_circomlib_upstream.sh`) hashes the vendored tree
   and asserts byte-for-byte equality with the pinned upstream tag.
   Any local edit fails CI loudly rather than silently diverging.
4. **License clarity.** The vendored copy carries its own LICENSE file
   adjacent to the code, making the per-directory license posture
   physically obvious to auditors and downstream packagers (the npm
   package strips the LICENSE — see "Upstream license note" below).

## Upstream pin

| Field             | Value |
| ----------------- | ----- |
| Upstream repo     | `https://github.com/iden3/circomlib` |
| Upstream tag      | `v2.0.5` |
| Vendored at       | 2026-05-28 (see commit history) |
| Source tarball    | `npm pack circomlib@2.0.5` (byte-identical to the `v2.0.5` git tag's `circuits/` subdirectory) |
| Upstream license  | GPL-3.0 (declared in `package.json`) |

The `circuits/` subdirectory is **byte-identical to the upstream
`v2.0.5` release** — vendored verbatim with no Olympus-specific
modifications. Every `.circom` file matches the corresponding file in
the upstream tag exactly.

## Upstream license note

The `v2.0.5` git tag in `iden3/circomlib` does **not** include a
LICENSE file at the repo root — only `package.json`'s
`"license": "GPL-3.0"` declaration. The npm package (`circomlib@2.0.5`)
inherits this omission.

To make the per-directory license posture explicit and to satisfy
downstream packagers' typical "must have LICENSE file adjacent to the
code" expectation, the `LICENSE` here is the **canonical SPDX
`GPL-3.0-only` text** fetched from
[spdx/license-list-data](https://github.com/spdx/license-list-data/blob/main/text/GPL-3.0-only.txt).
This is the same legal text iden3 declares in their `package.json` —
just made physically present in the vendored copy.

## Olympus circuits that import from this vendored copy

```
proofs/circuits/document_existence.circom            → comparators.circom
proofs/circuits/non_existence.circom                 → comparators.circom, bitify.circom
proofs/circuits/redaction_validity.circom            → eddsaposeidon.circom
proofs/circuits/unified_canonicalization_inclusion_root_sign.circom → comparators.circom
proofs/circuits/federation_quorum.circom             → eddsaposeidon.circom, comparators.circom
```

(Those circomlib files include each other transitively — `eddsaposeidon.circom`
pulls in `bitify`, `comparators`, `escalarmulany`, `escalarmulfix`, `poseidon`,
`compconstant`, `aliascheck`, `binsum`. The full 36-file `circuits/` tree
is vendored to capture the transitive closure.)

## License inheritance for our circuits

Because `proofs/circuits/*.circom` `include` GPL-3.0 templates from
this vendored circomlib, the Olympus circuit sources are **derivative
works of circomlib and themselves GPL-3.0**. This is the standard
posture across the iden3 ecosystem (Aztec, Polygon ID, Worldcoin, etc.
all ship circuits derived from circomlib).

The compiled artifacts (`.r1cs`, `.wasm`, `.zkey`, `_vkey.json`) are
produced by the GPL'd circom compiler from GPL'd source. Treat them as
GPL'd as well. The Rust runtime (`src-tauri/`) consumes the artifacts
through arkworks (Apache-2.0/MIT) and does **not** itself link the GPL
toolchain; it remains Apache-2.0/MIT.

## CI provenance check

`scripts/check_circomlib_upstream.sh` fetches the upstream `v2.0.5`
tag's `circuits/` tree and diffs it byte-for-byte against the vendored
copy. Any local divergence in a `.circom` file fails the check with a
non-zero exit, so unauthorised modifications are caught at PR time
rather than at proof-verification time.

Run locally with:

```bash
bash scripts/check_circomlib_upstream.sh
```

## Why path-local rather than git-submodule

Submodules add an extra `git clone` step at checkout, complicate
sparse checkouts, and break `git archive`-style snapshots that the
ceremony repos use. Path-local vendoring is the simplest model that
gives us reproducibility + drift detection in one tree.

## Retire-when condition

Unlike the `light-poseidon` and `glib-0.18.5-patched` vendored crates
(both of which carry targeted backports + a "retire when upstream
ships the fix" condition), this vendored circomlib has **no retire
condition** — Olympus has committed to vendoring GPL upstreams as a
long-term supply-chain posture (see project README).

The version may be bumped (e.g., `v2.0.5 → v2.0.6` if circomlib
publishes a relevant update) by:

1. Updating the upstream tag in the pin table above.
2. Re-running `cp -r node_modules/circomlib/circuits/. proofs/vendor/circomlib/circuits/`.
3. Updating the drift check script's tag constant.
4. Verifying all five Olympus circuits still compile against the
   refreshed vendored copy.
