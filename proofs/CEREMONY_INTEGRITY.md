# Ceremony Integrity — operational discipline for ZK artifacts

This document specifies how Olympus ZK ceremony artifacts (proving keys,
verification keys, derived runtime keys) are produced, signed, shipped,
and verified. It exists because we hit the exact failure it's designed
to prevent during the 2026-05-26 audit work: a `.ark.zkey` regenerated
on disk, an embedded `vkey.json` from a prior ceremony run, and **two
hours of debugging a "proof fails to verify" assertion** before
realizing the two files were never from the same ceremony.

The code did its job. The verifier loaded what was on disk and rejected
honestly. **The missing piece was a check that refuses to start when the
on-disk proving key and the embedded verifying key don't come from the
same ceremony.**

## Threat model

For a "single-contributor dev setup" the only adversary is the
contributor's own footgun. For a real multi-party ceremony (Phase 2
with N ≥ 3 contributors, distributed across organizations / countries),
the failure modes multiply:

| Failure mode                                                                                   | Detection without integrity check                                                                                                            | Detection with this doc's protocol            |
| ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| Contributor A's vkey + Contributor B's zkey accidentally shipped                               | At first real proof verification (production)                                                                                                | At binary startup (fail-closed)               |
| Re-run on one circuit, forgot to re-run on another                                             | At first proof of unchanged circuit (silent if no one tests it)                                                                              | At binary startup                             |
| Malicious contributor swaps in a backdoored zkey post-ceremony                                 | Cryptographic verification of the proof itself MIGHT catch some classes, but not all (the swapped zkey could prove what the manifest claims) | Manifest signature mismatch at load time      |
| Operator copies new keys to prod but forgets the vkey JSON                                     | At first production proof                                                                                                                    | At deploy verification                        |
| Phase-2 contribution chain has a missing link (contributor 7's input ≠ contributor 6's output) | Hard to detect after the fact                                                                                                                | Per-contribution BLAKE3 chain in the manifest |

## ADR-0030 — redaction_validity circuit removed

The `redaction_validity` Groth16 circuit was **removed** (ADR-0030): redaction
now uses a signed Merkle fold over the per-segment hiding leaves (an Ed25519
signature + variable-depth Poseidon root, no SNARK). No ceremony artifact is
produced for it any more — it is gone from both `setup_circuits.sh` and
`phase2_ceremony.sh`. The remaining circuits (`document_existence`,
`non_existence`, `unified_canonicalization_inclusion_root_sign`, and the gated
`federation_quorum`) keep their existing manifests/vkeys and the shared
power-20 ptau.

## Ceremony bundle structure

A ceremony bundle is **one atomic unit** — one ceremony produces one
bundle, you ship the whole bundle or none of it.

```
ceremony-<circuit>-<isoDate>-<contribCount>.tar.zst
├── manifest.json                # signed entry point — read first
├── <circuit>.zkey               # final snarkjs zkey (post all contributions)
├── <circuit>_vkey.json          # verification key derived from final zkey
├── <circuit>.ark.zkey           # arkworks-serialized runtime key
├── <circuit>.r1cs               # circuit constraint system
├── <circuit>.wasm               # witness generator
├── contributions/
│   ├── 001-<contributor-id>.zkey
│   ├── 002-<contributor-id>.zkey
│   └── ...
└── ptau/
    └── powersOfTau28_hez_final_<power>.ptau  # symlink or hash reference
```

## Manifest schema

`manifest.json` is JCS-canonical (RFC 8785) JSON. Every consumer derives
its fingerprint via `BLAKE3(canonicalize(manifest.json))`. Contributor
signatures are structured fields embedded in their contribution rows; the
coordinator signature is embedded in the top-level coordinator object.

```json
{
  "version": 3,
  "ceremony_id": "olympus-mainnet-2026Q2",
  "circuit": "document_existence",
  "created_unix": 1748275200,
  "ptau": {
    "file": "powersOfTau28_hez_final_20.ptau",
    "power": 20,
    "blake2b": "89a66eb5...bf1a27b"
  },
  "circuit_hash": {
    "algorithm": "blake3",
    "value": "...",
    "computed_from": "circuit.r1cs"
  },
  "artifacts": {
    "zkey": { "name": "document_existence.zkey", "size": 8775536, "blake3": "..." },
    "vkey": { "name": "document_existence_vkey.json", "size": 2046, "blake3": "..." },
    "ark_zkey": { "name": "document_existence.ark.zkey", "size": 8775536, "blake3": "..." },
    "r1cs": { "name": "document_existence.r1cs", "size": 2784268, "blake3": "..." },
    "wasm": { "name": "document_existence.wasm", "size": 1878819, "blake3": "..." }
  },
  "contributions": [
    {
      "index": 0,
      "contributor_id": "alice@example.org",
      "contribution_hash": "75c50587 fe7cbcf5 ...",
      "running_chain_hash": "<blake3 of (previous_chain_hash || contribution_hash)>",
      "timestamp_unix": 1748272100,
      "bjj_pubkey": { "x": "...", "y": "..." },
      "signature": { "r8x": "...", "r8y": "...", "s": "..." }
    },
    { "index": 1, "contributor_id": "bob@example.org", "...": "..." }
  ],
  "coordinator": {
    "id": "olympus-foundation",
    "bjj_pubkey": { "x": "...", "y": "..." }
  }
}
```

The `running_chain_hash` field at each contribution is
`BLAKE3("OLY:CEREMONY:CHAIN:V1" || previous_chain_hash || this_contribution_hash)`
(the domain tag is prepended on every link; `previous_chain_hash` is 32
zero bytes for `index == 0`). Any missing or out-of-order contribution
breaks the chain and the coordinator signature fails to verify.

### What the coordinator signature binds (V3)

The coordinator does **not** sign the bare contribution-chain hash. For a
version-3 manifest (the current `generate_manifest` output) it signs a
domain-separated digest (`OLY:CEREMONY:MANIFEST:V3`) that binds the
runtime-relevant fields **including the creation time**:

```text
coordinator_message = BLAKE3(
    "OLY:CEREMONY:MANIFEST:V3"
    || lp(circuit) || lp(ceremony_id) || created_unix(i64 LE)
    || vkey.blake3(32) || ark_zkey.blake3(32) || r1cs.blake3(32) || wasm.blake3(32)
    || final_running_chain_hash(32)
)
```

(`lp(x) = u64_le(len) || x`.) Note the distinction between the manifest's
**schema version** (the JSON `version` field: 1, 2, or 3) and the
**signing recipe** (the domain tag): manifests of schema version 1–2 are
both verified under the artifact-binding recipe tagged
`OLY:CEREMONY:MANIFEST:V2` (same layout as above, without the
`created_unix` element); schema version 3 uses the
`OLY:CEREMONY:MANIFEST:V3` recipe above. The disjoint tags make
cross-version relabelling fail closed. The _historical_ recipe V1 —
which signed only `final_running_chain_hash` — is no longer implemented
or accepted by any verifier in the tree; every manifest, whatever its
schema version, must carry a signature over the full artifact map to
verify at all.

The artifact binding closes recipe V1's binding-scope gap: it signed
only `final_running_chain_hash`, leaving the artifact digests — most
importantly `vkey.blake3`, the key `/zk/verify` loads to verify _every_
proof — outside the signature. The other runtime checks (build.rs
`blake3(vkey) == manifest.vkey.blake3`; `load_proving_key_with_manifest`
`blake3(ark_zkey) == manifest.ark_zkey.blake3`) only assert the on-disk
file matches the digest _recorded in the manifest_ — digests that were
themselves unsigned under recipe V1. An attacker who could edit the
manifest could therefore substitute a backdoored vkey/zkey, update the
recorded blake3s, and the recipe-V1 coordinator signature would still
verify. Under recipe V2+ any edit to an artifact digest, the circuit
name, or the ceremony id breaks the coordinator signature.

Binding `created_unix` (V3) additionally anchors **when** the coordinator
vouched: issuer validity windows are evaluated at the signed creation
time instead of wall-clock now, so a coordinator key can be retired
(bounded `valid_until`) without invalidating the manifests it signed
while valid — see `docs/key-rotation.md` ("the ceremony-coordinator
trap"). A v3 manifest forward-dated more than one day past the
verifier's clock is rejected (`CreatedInFuture`). Legacy v1/v2 manifests
keep the wall-clock-now window check, since their `created_unix` is
attacker-editable.

The reference implementation is
`CeremonyManifest::coordinator_signing_digest`; `generate_manifest`
signs the exact same digest, so generator and verifier cannot drift.

## Multi-contributor signing

Each contribution carries a BJJ-EdDSA `signature` beside its declared
`bjj_pubkey`. The signed message is domain-separated with
`OLY:CEREMONY:CONTRIBUTION:V1` and binds the ceremony id, circuit, exact list
index, contributor id, contribution hash, running chain hash, timestamp, and
both canonical pubkey coordinates. Verification:

1. Recompute `running_chain_hash` from the contributions list.
2. For every contribution, verify its signature and require its key to appear
   in the independently managed trusted-contributor policy for that timestamp.
   Repeated rows from the same key count as one identity.
3. Verify the coordinator's BJJ signature over the version-appropriate
   digest above (V3: artifacts + circuit + ceremony id + creation time +
   final chain hash) against `coordinator.bjj_pubkey`.

Each embedded contribution signature authenticates the structured contribution
record and its exact chain position. It does **not** independently prove that
the contributor generated, retained, or destroyed fresh entropy. The threshold
therefore establishes that distinct authorized keys attested the recorded
transcript; sound entropy generation still depends on the operational ceremony
and on at least one honest contributor following it.

Tagged release preflight invokes `verify_ceremony_bundle` with
`--minimum-authenticated-contributors 3`. The allowlist is supplied through
the repository variable `OLYMPUS_CEREMONY_TRUSTED_CONTRIBUTORS_JSON` as an
array of `{x,y,valid_from?,valid_until?}` entries. Missing policy, malformed
keys, missing/forged signatures, or fewer than three distinct authorized keys
blocks the release. Historic single-contributor development manifests omit
the optional signature field and still parse, but can never satisfy this
production gate.

A consumer that doesn't recognise the coordinator pubkey (i.e. doesn't
have it in `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON`, audit M-3) MUST refuse to
load the bundle. This is the trust anchor — the chain of contributors
proves the ceremony happened, the coordinator signature proves the
ceremony was the one this binary expects.

## Runtime checks (IMPLEMENTED — 2026-05-26)

All four checks below are now live. See `src-tauri/src/zk/manifest.rs`
for the schema + verification functions, `src-tauri/build.rs` for the
compile-time check, `src-tauri/src/zk/zkey.rs` for the runtime
`.ark.zkey` check, and `src-tauri/src/main.rs:detect_placeholder_artifacts`

- `verify_ceremony_manifests` for the startup pass.

1. **Compile-time manifest embed.** ✅ `src-tauri/build.rs` reads each
   circuit's manifest + vkey, asserts
   `manifest.artifacts.vkey.blake3 == blake3(vkey.json)`. Build panics
   on mismatch with a clear error naming both files and both digests.
   `cargo:rerun-if-changed=` directives ensure cargo recompiles when
   either file changes.

2. **Runtime `.ark.zkey` fingerprint check.** ✅
   `load_proving_key_with_manifest` reads the file, computes blake3,
   returns `ZkeyError::ManifestMismatch{expected, computed}` on
   mismatch. The four circuit-specific provers in `prove.rs` route
   through this variant; the bare `load_proving_key` remains for
   diagnostic tests (M-5 newtype escape hatch).

3. **Startup coordinator-signature check.** ✅ `main.rs` calls
   `verify_ceremony_manifests` right after `bjj_trusted_issuers` is
   populated. Each manifest's contribution chain is recomputed,
   coordinator pubkey membership in the trusted set is checked
   (window-evaluated at the signed `created_unix` for v3 manifests,
   at wall-clock now for legacy v1/v2), and the BJJ-EdDSA signature
   over the version-appropriate digest (see "What the coordinator
   signature binds") is verified via
   `crate::zk::witness::baby_jubjub::verify_signature`.

4. **Production refusal mode.** ✅ Under `OLYMPUS_ENV=production`, any
   non-placeholder failure from (3) results in `eprintln!` +
   `std::process::exit(2)` before the server starts serving. In dev
   mode, failures surface as `tracing::error!` and the binary continues
   so contributors can iterate during the pipeline.

### Wiring summary

| File                                     | Lines  | Purpose                                  |
| ---------------------------------------- | ------ | ---------------------------------------- |
| `src-tauri/src/zk/manifest.rs`           | new    | schema + verify helpers                  |
| `src-tauri/src/bin/generate_manifest.rs` | new    | one-shot ceremony manifest generator     |
| `src-tauri/build.rs`                     | edited | check #1 (vkey blake3)                   |
| `src-tauri/src/zk/zkey.rs`               | edited | check #2 (.ark.zkey blake3)              |
| `src-tauri/src/zk/verify.rs`             | edited | `*_MANIFEST_JSON` constants              |
| `src-tauri/src/zk/prove.rs`              | edited | route through manifest-checked load      |
| `src-tauri/src/main.rs`                  | edited | check #3 + #4 (startup signature gate)   |
| `proofs/setup_circuits.sh`               | edited | invoke generator after export_ark_zkey   |
| `proofs/keys/manifests/*.json`           | new    | per-circuit signed manifests (committed) |

## Operator runbook

### When you regenerate ceremony artifacts

The script `proofs/setup_circuits.sh` is dev-mode (single contributor).
After running it, **all four of these files must be replaced
atomically** for any one circuit:

- `proofs/keys/<circuit>.ark.zkey`
- `proofs/keys/verification_keys/<circuit>_vkey.json`
- `proofs/build/<circuit>.r1cs` (build artifact, dev convenience)
- `proofs/build/<circuit>_js/<circuit>.wasm` (build artifact)

If you regenerate one and not the others, the test/build will fail in
confusing ways. If you commit the .ark.zkey but not the vkey JSON, CI
will pass locally and fail at runtime in deployment.

Sanity check after every setup run:

```bash
# All four artifacts from the same ceremony will have mtimes within
# a few minutes of each other. Mismatched mtimes = mismatched ceremonies.
for c in document_existence non_existence unified_canonicalization_inclusion_root_sign federation_quorum; do
    echo "=== $c ==="
    ls -la "proofs/keys/${c}.ark.zkey" \
           "proofs/keys/verification_keys/${c}_vkey.json" \
           "proofs/build/${c}.r1cs" 2>/dev/null
done
```

If any line shows a date older than ~10 minutes after the others,
re-run setup_circuits.sh for that circuit before committing.

### When you commit ceremony artifacts to git

`.ark.zkey` files are large (8 MB - 130 MB). Use Git LFS or commit them
to a separate `olympus-ceremony` repo and reference by tag. The current
in-tree `.gitkeep` placeholder + ceremony-builds-at-deploy strategy is
fine for the v0.9 desktop binary but won't scale to a federated mainnet.

For each commit that includes ceremony artifacts:

1. Confirm artifact mtimes are within minutes of each other (above).
2. Confirm `cargo test -p olympus-desktop --test zk_prove_existence
--features prover` actually passes — this is the cheapest
   end-to-end check that the vkey JSON and the .ark.zkey come from the
   same ceremony.
3. Update `proofs/keys/PROVENANCE.md` with the ceremony date, PTAU
   power, and BLAKE3 of each new artifact.
4. Don't squash the commit. Each ceremony regen should be a single
   reviewable commit with the artifact diffs visible.

### When you receive a ceremony bundle from a contributor

The runtime startup gate (`verify_ceremony_manifests`, "Runtime checks"
above) verifies the coordinator signature, contribution chain, and
artifact digests once the bundle is installed — fail-closed (`exit 2`)
under `OLYMPUS_ENV=production`, warn-and-continue in dev. It cannot,
however, validate what it never sees: pre-installation checks on the
bundle itself remain the operator's job, and one cryptographic property
is outside the runtime's scope entirely (step 3 below — Phase-2
increment validity of each intermediate `.zkey`, which the manifest
chain attests but does not prove). Before unpacking:

1. Confirm the coordinator pubkey in `manifest.json` matches the
   published coordinator key (out-of-band; e.g. signed announcement on
   the project's release page), and that it is the key configured in
   your `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` with the
   `ceremony_coordinator` role — otherwise the startup gate will refuse
   the manifest after installation.
2. Replay the contribution chain — recompute `running_chain_hash` from
   the contribution list, confirm it matches the manifest's final value.
   (The startup gate repeats this check on every boot.)
3. For each `contributions[i]`, run
   `snarkjs zkey verify <circuit>.r1cs <ptau> contributions/<i>.zkey`.
   That confirms the contribution is a valid Phase-2 increment over the
   previous step — the one check no runtime gate performs, since the
   intermediate `.zkey` files are not shipped to consumers.
4. Hash every artifact and confirm against `manifest.json`. (The
   startup gate re-checks the vkey at compile time and the `.ark.zkey`
   at load time; `r1cs`/`wasm` digests are bound by the coordinator
   signature.)
5. Only then unpack into `proofs/keys/` and rebuild.

### Production ceremony — Phase 2 with multiple contributors

Use `proofs/phase2_ceremony.sh`, not `proofs/setup_circuits.sh`. The
former runs `prepare / contribute / verify / finalize` as separate steps
so each contributor produces an artifact you can verify before
incorporating. Document each contributor's:

- Real-world identity (real name, organization, jurisdiction)
- BJJ pubkey (the one their signature on the manifest uses)
- Contribution hash (the per-step output of snarkjs)
- Air-gap status of their contribution machine (yes / no / partial)
- Entropy source (HSM, CPU RDRAND, dice roll, etc.)

The point of N independent contributors is that at least ONE must be
honest for the resulting setup to be secure. Documenting these fields
is how a relying party years later can audit "was at least one of them
plausibly honest?" The integrity protocol above guarantees the
artifacts you ship are the ones that contributor list produced, not
that the contributors themselves were honest.

## Why this matters (the 2026-05-26 lesson)

During the audit, we changed three circuits (M-1, M-2, H-1), re-ran
`setup_circuits.sh`, regenerated `.ark.zkey` files, regenerated vkey
JSONs. The vkey JSON was committed via `include_str!` at compile time.
The `.ark.zkey` was loaded at runtime from disk.

Both were "regenerated today." But — because of working between two
clones (WSL + Windows) and forgetting to copy the regenerated vkey JSON
to the clone where cargo was building — the embedded vkey and the
on-disk proving key ended up from **different** snarkjs setup runs. Each
snarkjs setup uses fresh randomness for the toxic-waste contribution,
so two runs of "the same script on the same circuit" produce
**different but each internally consistent** keypairs.

Result: real proof generated under proving key A. Verification
attempted against vkey B. False. Two hours of debugging.

A 30-second startup check that hashes the loaded `.ark.zkey` and
compares against an embedded manifest entry would have produced an
immediate "ceremony mismatch — artifact ark_zkey blake3 X does not
match manifest expected Y" error. The 30 seconds of engineering pays
back orders of magnitude.

**This is the lesson to internalize before the production ceremony.**
Ceremony correctness is operational discipline, not cryptography. The
crypto only works if the operator can prove which keys go together —
and that proof has to be verifiable by a fresh consumer with no prior
context, by an auditor years after the event, and by a CI run on a
laptop that has neither the contributors' identities nor the bundle's
history.
