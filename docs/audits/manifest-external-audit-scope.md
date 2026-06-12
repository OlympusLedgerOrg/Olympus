# External audit + legal memo scope — dataset manifests (ADR-0027)

**Status:** Scope defined; engagement pending. This document is the brief for the
third-party cryptography audit and the accompanying legal memo. Olympus does not
self-certify novel crypto for a lab's legal review — this is the gate that must
clear before the manifest layer is relied on in a regulated submission.

> Why this is a stub: the audit and legal memo are *external* deliverables (a
> third-party cryptography firm and outside counsel, respectively). This file
> defines what they must cover, what artifacts to hand them, and the acceptance
> criteria, so the engagement can start without re-scoping.

## In scope for the cryptography audit

1. **Commitment soundness.** `manifest_root` = Olympus 256-height SMT global root
   (`olympus_crypto::smt`). Confirm:
   - Inclusion proofs are sound (no forged membership for an honest root).
   - **Non-membership is sound against an adversarial committer** — the headline
     claim. Verify the key path is determined by `record_id` (not prover-chosen)
     and the empty-leaf sentinel cannot be forged or collided with a real leaf.
   - Domain separation: leaf (ADR-0005 structured prefix, object-type `0x01`),
     node (`OLY:NODE:V1|`), empty-leaf (`OLY:EMPTY-LEAF:V1`), and the
     manifest-layer `OLY:MANIFEST:DIFF:V1` are mutually non-colliding.
2. **Path-compressed builder parity.** `olympus_manifest::smt_batch` must produce
   roots and proofs **byte-identical** to the reference `SparseMerkleTree`.
   Audit the compression/ladder logic and the divergence cases (query sharing a
   long prefix with a stored leaf or a compressed branch). The repo's parity test
   (`parity_with_reference_smt`) is the oracle; the audit should add adversarial
   and property-based cases and ideally a second independent implementation.
3. **Provenance binding.** `parser_id` / `canonical_parser_version` / `model_hash`
   are folded into every leaf (ADR-0003/0004). Confirm a verifier cannot accept a
   proof whose provenance differs from the committed leaf.
4. **Version-link integrity.** `ManifestDiff` / `diff_root` / `ParentRef`:
   confirm the structural link plus per-record inclusion/exclusion proofs
   genuinely establish `v2 = v1 − removed + added`, and that `diff_root`'s
   length-prefixed, sorted preimage is unambiguous (no second-preimage via field
   re-framing).
5. **Canonicalisation.** The committed manifest bytes are JCS/RFC 8785
   (`to_canonical_bytes`); confirm reproducibility and that the content hash an
   auditor recomputes matches the anchored value.
6. **Client boundary.** Confirm the clients (CLI, Python SDK) only *re-verify*
   and never hold signing keys or perform security-critical commitment logic
   outside `olympus-manifest` (language-ownership rule).

### Acceptance criteria (crypto audit)

- Written attestation of inclusion **and** exclusion soundness under a stated
  adversary model, or a list of findings with severities.
- Independent confirmation of builder parity (re-run + ideally a reimplementation
  vector set).
- No High/Critical findings open at sign-off; Mediums tracked with owners.

## In scope for the legal memo

- Opinion on whether the `docs/compliance/eu-ai-act-mapping.md` crosswalk is
  sound for **Art. 10**, **Art. 11 + Annex IV**, **Art. 12**, and the GPAI
  **Art. 53** training-content/copyright duties of Regulation (EU) 2024/1689.
- Evidentiary weight of an Olympus inclusion/exclusion proof + ledger anchor in
  (a) a market-surveillance inquiry and (b) civil proceedings (cross-reference
  `docs/court-evidence.md`).
- Interaction with GDPR (Art. 17 erasure evidenced via exclusion proofs) and the
  limits of "committed-hash ≠ faithful-input" (the first-hash trust point).

### Acceptance criteria (legal memo)

- Signed memo from outside counsel covering the articles above, with explicit
  caveats and any required changes to the crosswalk wording before reliance.

## Artifacts to hand the auditors

- `crates/olympus-crypto` (leaf/node/SMT primitives + golden vectors).
- `crates/olympus-manifest` (schema, `smt_batch`, proofs, diff) + its tests.
- `verifiers/{rust,javascript}` and `verifiers/test_vectors/vectors.json`.
- ADR-0003, ADR-0004, ADR-0005, ADR-0022, **ADR-0027**.
- `docs/benchmarks/manifest-throughput.md`, `docs/compliance/eu-ai-act-mapping.md`.
- Prior internal audits under `docs/audits/` for threat-model context.
