# ADR-0044: BLAKE3 CD-HS-ST SMT root attestation

- **Status:** **Accepted, implemented (2026-08-13).**
- **Builds on:**
  - ADR-0003 / ADR-0004 / ADR-0005 (the BLAKE3 CD-HS-ST parser-bound SMT and
    its structured leaf hash — the tree this ADR signs the root of).
  - ADR-0021 (SMT + CT-style operational hardening — its Decision section
    names the BLAKE3 CD-HS-ST tree "the only ledger commitment tree" and
    calls for CT-style operational controls, including signed roots, around
    it; this ADR is the signed-root leg of that requirement).
  - ADR-0031 (`TransitionAttestation` — this ADR adds a second, structurally
    identical attestation type and reuses its BJJ-EdDSA-over-reduced-digest
    signing pattern and its checkpoint-row persistence approach).
- **Protocol change:** checkpoint bundle schema advances `olympus-checkpoint-bundle/v3`
  → `v4` to carry the new attestation block. Migration `0060` adds four
  nullable columns to `own_checkpoints`. No leaf/node hash, circuit, vkey,
  ceremony manifest, or SSMF golden vector changes — this is not a
  migration-class hash event.

## Context

Olympus has two independent Merkle structures over the same ledger data:

1. The **BLAKE3 CD-HS-ST SMT** (`PersistentSmt`, depth 256) — the tree
   ADR-0003/0004/0005 describe as the canonical per-leaf commitment, written
   by every `/ingest/files` commit.
2. The **Poseidon ledger-snapshot tree** (`ledger_snapshot.rs`, fixed depth
   20) — frozen per record at ingest time so a `document_existence` Groth16
   circuit can produce a witness against it. It exists purely because
   Poseidon is SNARK-friendly at a fixed shallow depth; the 256-deep BLAKE3
   tree would be impractical to prove membership in inside a circuit.

Every own-checkpoint (`anchoring/own_checkpoint.rs::build_and_persist`) signs
the Poseidon `snapshot_root` under the BJJ authority key and, since ADR-0031,
also signs a `TransitionAttestation` over the append-only step that produced
it. **Nothing has ever signed or externally anchored the BLAKE3 SMT's root.**
`PersistentSmt::prove` — the BLAKE3 tree's own inclusion/non-inclusion proof
method — has zero production callers anywhere in this codebase: a proof
against it would have no signed statement for a verifier to check it
against, so there was nothing to call it for.

This gap surfaced concretely in the (separate, unmerged) ADR-0021 Monitor API
work: its proof-serving endpoints could only serve witnesses against the
Poseidon tree — the only one with a signed root — even though ADR-0021
itself names the BLAKE3 tree as the canonical commitment. That PR documented
the mismatch as a "Known limitation" and explicitly deferred reconciling it.
This ADR is that follow-up.

## Decision

Sign the BLAKE3 SMT root too, using a second, independent, domain-separated
attestation alongside the existing Poseidon-side signatures — not by
replacing or reworking the existing BJJ-EdDSA-Poseidon signing scheme, and
not by introducing a new signature algorithm or domain-separator convention.

### `SmtRootAttestation` primitive (`olympus-crypto`)

Mirrors `TransitionAttestation`'s shape and signing recipe exactly:

- `SMT_ROOT_ATTEST_PREFIX: &[u8] = b"OLY:SMT:ROOT:V1"` — a new domain prefix,
  disjoint from every other prefix in the crate, following the project's
  `OLY:<TYPE>:V<N>` convention (`OLY:SNAPSHOT:PERSIST:V1`,
  `OLY:SBT:QUORUM:V2`, …).
- `smt_root_attest_message(shard_id, ledger_root, tree_size, blake3_smt_root) -> [u8; 32]`
  — `BLAKE3(SMT_ROOT_ATTEST_PREFIX || lp(shard_id) || lp(ledger_root) || lp(u64_be(tree_size)) || lp(blake3_smt_root))`,
  using the same ADR-0005 `lp(x)` length-prefix framing `persist_message` uses.
- `SmtRootAttestation` — a crypto-only struct binding `shard_id`,
  `ledger_root`, `tree_size`, `blake3_smt_root`, plus a `message()` helper.

Folding the checkpoint's own `ledger_root` and `tree_size` into the digest is
what makes this a **joint** statement rather than an independent, driftable
one: "for this shard, at this exact ledger snapshot, the BLAKE3 SMT subtree
root is X." The attestation cannot be replayed against a different
checkpoint, and a verifier holding both signed statements knows they
describe the same instant.

The signature is BJJ-EdDSA over the digest reduced mod `l`, the same
SBT-open / transition-attestation pattern, so it reuses the persisted BJJ
authority key and the existing offline BJJ verifier — no new key material,
no new algorithm.

### Producer (`anchoring/own_checkpoint.rs`)

At the same point `build_and_persist` signs the Poseidon transition, it also
reads the shard's current BLAKE3 subtree root
(`PersistentSmt::shard_subtree_root`, the same per-shard root
`checkpoint_scope = "shard"` already implies) and signs an
`SmtRootAttestation` over it. Migration `0060` adds four nullable columns to
`own_checkpoints` (`blake3_smt_root`, `blake3_smt_sig_r8x/r8y/s`) — additive
and forward-only, matching migration `0049`'s shape. A `verify_smt_root_attestation`
function mirrors `verify_append_transition`: it rebuilds the digest from the
claimed shard/root/size fields (never trusting a caller-supplied digest) and
authenticates the BJJ signature over it.

### Bundle export (`api/checkpoint_bundle.rs`) and offline verifiers

The admin-gated checkpoint bundle — the actual externally-verifiable
artifact — gets a new `smt_root_attestation` block, validated the same way
`append_transition` already is before export. The bundle schema advances to
`v4`. Both offline verifiers gain independent re-derivations that share no
code with the producer: `verifiers/rust/src/smt_root.rs` (mirroring
`transition.rs`) and a fifth check in `verifiers/javascript/verify.js`
(`verifySmtRootAttestation`), both pinned against the same cross-language
golden vector.

## What this does not do (yet)

- **Proof-serving endpoint — shipped as a follow-up.** `GET
  /monitor/proof/blake3/{content_hash}` (`api::monitor::proof_blake3`) now
  wires `PersistentSmt::prove` into the Monitor API (ADR-0021), serving a
  BLAKE3 membership proof against the shard's signed `SmtRootAttestation`.
  This closed a real gap beyond wiring: `prove()`'s output folds to the
  tree's *global* 256-depth root, but `SmtRootAttestation` signs the *shard
  subtree* root (depth `SHARD_PREFIX_BITS` = 64) — the two don't verify
  against each other directly. The fix is additive, not a change to what's
  signed: `olympus_crypto::smt::verify_existence_proof_against_shard_root`
  / `verify_nonexistence_proof_against_shard_root` fold only the leaf-side
  192 siblings and compare against the shard root instead of `proof.root_hash`.
  `Proof`/`ExistenceProof`/`NonExistenceProof`, `prove()`/`prove_batch()`, and
  the checkpoint bundle schema are all unchanged. Mirrored independently in
  `clients/python/src/olympus_manifest/smt.py` (the SMT proof-folding parity
  surface turned out to be just these two implementations — the offline Rust
  and JavaScript verifiers only check the attestation signature/digest, not
  full SMT proofs, so neither needed a change).
- **It does not extend federation gossip.** `PeerCheckpoint`'s wire format
  and `peer_checkpoints` table are unchanged; the new attestation is not
  carried over Tor gossip. Peers verifying a checkpoint bundle out-of-band
  (e.g. via the admin bundle export) see it; the gossip/equivocation-detection
  path does not yet.
- **It does not decide which tree is "canonical."** Both are now signed.
  Reconciling that policy question — or deciding it doesn't need
  reconciling — remains open, as the deferring PR's text already said.

## Consequences

- No hash/circuit/ceremony change. Pure additive signature primitive + a
  producer-wiring change + a forward-only migration adding nullable columns.
- `PersistentSmt::prove` output now has a signed statement a verifier can
  check it against, closing the specific gap that made it dead code.
- For every checkpoint emitted with the BJJ authority *private* key loaded,
  the BLAKE3 tree and the Poseidon tree are now both signed, cryptographically
  tied to the same `(ledger_root, tree_size)` instant — a prerequisite for,
  not a replacement for, actually serving BLAKE3 proofs. (A keyless dev
  checkpoint carries neither attestation, matching the existing
  `TransitionAttestation` contract — see ADR-0031 and CLAUDE.md's insert-only
  invariant bullet.)
