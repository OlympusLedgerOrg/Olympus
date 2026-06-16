# ADR-0032: Retire the witness-over-root cosignature scaffold

- **Status:** **Accepted — 2026-06-16.** Implemented in this PR: deletes the two
  scaffold verifiers (`verifiers/rust/src/bin/verify_witness.rs`,
  `verifiers/js/witness_cosignature.mjs`). No replacement is added — the property
  is already owned by the quorum + checkpoint layers below.
- **Relates to:**
  - ADR-0009 (Poseidon / BJJ-EdDSA) — the curve the live quorum primitive signs
    under, and the one that is provable inside BN254 (the gated
    `federation_quorum` circuit).
  - ADR-0031 (transition attestations + checkpoint coverage) — names checkpoint
    gossip (`federation/{checkpoint,gossip}.rs`) as *the* mechanism by which peers
    attest to each other's roots. Witness-over-root would have overlapped it.
  - Live `src-tauri/src/quorum/mod.rs` (`OLY:SBT:QUORUM:V2`) and
    `src-tauri/src/federation/{checkpoint,equivocation,gossip,verify}.rs`.
- **Does not change:** any leaf/node hash, circuit, vkey, ceremony manifest, SMT
  schema, or wire format. There is no migration-class event. This is a deletion
  of dead scaffolding plus this record. `verifiers/rust` is a workspace-excluded
  crate, so `cargo test --workspace` is unaffected; the removed `src/bin` target
  has no dependents.

## Context

`verify_witness.rs` (+ its JS twin `witness_cosignature.mjs`) implemented a
"witness-over-root" scheme: N parties Ed25519-sign `OLY:WITNESS:V1| || root` and
the verifier accepts the root once a `threshold` of distinct `witness_id`s
produce valid signatures.

As shipped it was **unexercised scaffolding** with no security value:

- **No producer.** Nothing in `src-tauri` emits this envelope or signs that
  domain tag (`OLY:WITNESS` appeared only in the two verifier files).
- **No golden vector.** `verifiers/test_vectors/` has no witness vector, so the
  differential-testing contract that justifies a verifier's existence was unmet;
  the JS twin self-labelled `// scaffold verifier`.
- **No authorized-key set.** It accepted `threshold`-many valid signatures from
  *any* keys present in the envelope (the whole input), so anyone could mint N
  fresh keypairs and pass — the threshold proved nothing about *who* signed.
- **Dedup by self-asserted `witness_id`**, not by key, so one key under two ids
  double-counted; and `threshold == 0` passed vacuously.

## Decision

Delete the witness-over-root scaffold. Do not harden it; do not build a producer.

The live **quorum** primitive (`quorum::verify_quorum` /
`quorum::quorum_cosign_message`) already does M-of-N co-signing **correctly**:
pinned signer set with member-only counting, dedup by normalized key, threshold
bound into the signed message with a `≥ 1` floor (fail-closed, audit R3-01),
`OLY:SBT:QUORUM:V2` domain separation with length-prefixed fields, an offline
verifier available in non-`federation` builds, and a full adversarial test suite.
Its message is generic length-prefixed BLAKE3 — it binds `commit_id` today but
would bind a root just as easily. The equivocation / external-attestation
property witness-over-root claimed is independently owned by
`federation/{checkpoint,equivocation,gossip}` (see ADR-0031).

Decisively: quorum signs with **baby JubJub EdDSA-Poseidon**, which is provable
in BN254. The supported cryptographic path for ZK-compatible quorum validation is
the `federation_quorum` circuit operating over baby JubJub signatures.
Witness-over-root was retired because it was unexercised in practice and used
Ed25519, which is not the intended ZK-compatible mechanism for this system.

## Consequences

- Removes a misleading no-op that read like a live security control during audits.
- **If institutional co-signing of roots/checkpoints is ever wanted**, reuse
  `quorum_cosign_message` against a checkpoint root under a **new** domain tag
  (e.g. `OLY:CHECKPOINT:QUORUM:V1`) and a separate checkpoint signer set — never a
  second Ed25519 cosign stack. That reuses the hardened primitive, keeps a single
  co-signing surface to audit, and stays on the ZK-compatible curve.
- Reaffirms the verifier contract: a verifier with no producer and no golden
  vector is scaffolding, not a security control, and should not be carried as one.
