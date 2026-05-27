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

| Failure mode | Detection without integrity check | Detection with this doc's protocol |
|---|---|---|
| Contributor A's vkey + Contributor B's zkey accidentally shipped | At first real proof verification (production) | At binary startup (fail-closed) |
| Re-run on one circuit, forgot to re-run on another | At first proof of unchanged circuit (silent if no one tests it) | At binary startup |
| Malicious contributor swaps in a backdoored zkey post-ceremony | Cryptographic verification of the proof itself MIGHT catch some classes, but not all (the swapped zkey could prove what the manifest claims) | Manifest signature mismatch at load time |
| Operator copies new keys to prod but forgets the vkey JSON | At first production proof | At deploy verification |
| Phase-2 contribution chain has a missing link (contributor 7's input ≠ contributor 6's output) | Hard to detect after the fact | Per-contribution BLAKE3 chain in the manifest |

## Ceremony bundle structure

A ceremony bundle is **one atomic unit** — one ceremony produces one
bundle, you ship the whole bundle or none of it.

```
ceremony-<circuit>-<isoDate>-<contribCount>.tar.zst
├── manifest.json                # signed entry point — read first
├── manifest.sig                 # detached BLAKE3-keyed signature(s) — one per contributor
├── <circuit>.zkey               # final snarkjs zkey (post all contributions)
├── <circuit>_vkey.json          # verification key derived from final zkey
├── <circuit>.ark.zkey           # arkworks-serialized runtime key
├── <circuit>.r1cs               # circuit constraint system
├── <circuit>.wasm               # witness generator
├── contributions/
│   ├── 001-<contributor-id>.zkey
│   ├── 001-<contributor-id>.sig
│   ├── 002-<contributor-id>.zkey
│   ├── 002-<contributor-id>.sig
│   └── ...
└── ptau/
    └── powersOfTau28_hez_final_<power>.ptau  # symlink or hash reference
```

## Manifest schema

`manifest.json` is JCS-canonical (RFC 8785) JSON. Every consumer derives
its fingerprint via `BLAKE3(canonicalize(manifest.json))` and matches
that against `manifest.sig`.

```json
{
  "version": 1,
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
    "zkey":     { "name": "document_existence.zkey",      "size": 8775536,  "blake3": "..." },
    "vkey":     { "name": "document_existence_vkey.json", "size": 2046,     "blake3": "..." },
    "ark_zkey": { "name": "document_existence.ark.zkey",  "size": 8775536,  "blake3": "..." },
    "r1cs":     { "name": "document_existence.r1cs",      "size": 2784268,  "blake3": "..." },
    "wasm":     { "name": "document_existence.wasm",      "size": 1878819,  "blake3": "..." }
  },
  "contributions": [
    {
      "index": 1,
      "contributor_id": "alice@example.org",
      "contribution_hash": "75c50587 fe7cbcf5 ...",
      "running_chain_hash": "<blake3 of (previous_chain_hash || contribution_hash)>",
      "timestamp_unix": 1748272100,
      "bjj_pubkey": { "x": "...", "y": "..." }
    },
    { "index": 2, "contributor_id": "bob@example.org", "...": "..." }
  ],
  "coordinator": {
    "id": "olympus-foundation",
    "bjj_pubkey": { "x": "...", "y": "..." }
  }
}
```

The `running_chain_hash` field at each contribution is
`BLAKE3(previous_chain_hash || this_contribution_hash)`. The final
contribution's `running_chain_hash` is what the coordinator signs. Any
missing or out-of-order contribution breaks the chain and the
coordinator signature fails to verify.

## Multi-contributor signing

Each contributor produces a BJJ-EdDSA signature over the manifest's
`running_chain_hash` at the point their contribution lands.
`manifest.sig` is a JSON array of `{contributor_index, bjj_signature}`
entries. Verification:

1. Recompute `running_chain_hash` from the contributions list.
2. For each entry in `manifest.sig`, verify the BJJ signature against
   the contributor's pubkey (in `contributions[i].bjj_pubkey`) over the
   chain hash at index `i`.
3. Verify the coordinator's BJJ signature over the final chain hash
   against `coordinator.bjj_pubkey`.

A consumer that doesn't recognise the coordinator pubkey (i.e. doesn't
have it in `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON`, audit M-3) MUST refuse to
load the bundle. This is the trust anchor — the chain of contributors
proves the ceremony happened, the coordinator signature proves the
ceremony was the one this binary expects.

## Runtime checks (currently MISSING from the codebase — TODO)

The current `src-tauri/src/zk/verify.rs` embeds the vkey JSON via
`include_str!` and loads the `.ark.zkey` at runtime. There is **no
fingerprint check** that the two come from the same ceremony. This is
the gap that bit us during audit work.

What needs to land before the v1.0 production ceremony:

1. **Compile-time manifest embed.** `include_str!` the full
   `manifest.json` alongside each vkey JSON. The build fails if the
   manifest is missing or its `artifacts.vkey.blake3` field doesn't
   equal `blake3(vkey.json)`.

2. **Startup `.ark.zkey` fingerprint check.** When
   `load_proving_key()` reads a `.ark.zkey` from disk, hash the file
   and refuse to return a `CircomProvingKey` unless the digest matches
   the embedded manifest's `artifacts.ark_zkey.blake3`.

3. **Startup coordinator-signature check.** Before serving any
   `/zk/prove` or `/zk/verify` request, verify the embedded manifest's
   contributor + coordinator signatures using the BJJ trusted-issuer set
   already wired for SBTs (audit M-3).

4. **Production refusal mode.** Under `OLYMPUS_ENV=production`, ALL
   three checks are mandatory — startup fails with `exit 2` on any
   mismatch. Under dev mode, mismatches log a loud `tracing::warn!` and
   continue (so contributors can run the full pipeline before signing).

Until these land, the operator runbook below is the only line of
defense, and it's an ops-discipline check, not a code check.

## Operator runbook

### When you regenerate ceremony artifacts

The script `proofs/setup_circuits.sh` is dev-mode (single contributor).
After running it, **all four of these files must be replaced
atomically** for any one circuit:

- `proofs/keys/<circuit>.ark.zkey`
- `proofs/keys/verification_keys/<circuit>_vkey.json`
- `proofs/build/<circuit>.r1cs`        (build artifact, dev convenience)
- `proofs/build/<circuit>_js/<circuit>.wasm`  (build artifact)

If you regenerate one and not the others, the test/build will fail in
confusing ways. If you commit the .ark.zkey but not the vkey JSON, CI
will pass locally and fail at runtime in deployment.

Sanity check after every setup run:

```bash
# All four artifacts from the same ceremony will have mtimes within
# a few minutes of each other. Mismatched mtimes = mismatched ceremonies.
for c in document_existence non_existence redaction_validity unified_canonicalization_inclusion_root_sign; do
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

Until the runtime check lands, this is manual:

1. Verify the bundle's coordinator signature against the published
   coordinator pubkey (out-of-band; e.g. signed announcement on the
   project's release page).
2. Replay the contribution chain — recompute `running_chain_hash` from
   the contribution list, confirm it matches the manifest's final value.
3. For each `contributions[i]`, run
   `snarkjs zkey verify <circuit>.r1cs <ptau> contributions/<i>.zkey`.
   That confirms the contribution is a valid Phase-2 increment over the
   previous step.
4. Hash every artifact and confirm against `manifest.json`.
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
