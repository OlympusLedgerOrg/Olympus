# ADR-0035: Crypto-agility signature envelopes

Status: Accepted; scaffold implemented (2026-07-03)

## Context

Olympus already has production signature surfaces: BJJ-EdDSA-Poseidon for
ledger checkpoints and SBT policy, Ed25519 for anchor/court bundles and
redaction bundles, and explicit BJJ quorum co-signatures for federation. Those
surfaces are intentionally stable. Experimental cryptography must not change
SMT keys, leaf hashes, checkpoint roots, Groth16 public inputs, or existing
signature domains.

Post-quantum signatures are still useful as sidecars. The first target is a
hybrid shape that can carry:

- a required Ed25519 leg; and
- an experimental ML-DSA-65 leg.

## Decision

Add `olympus_crypto::signature_envelope` behind the opt-in
`signature-envelope` feature. The module defines:

- `SignatureEnvelopeV3`
- `SignatureSuite`
- `SignatureAlgorithm`
- `SignatureVerificationMode`
- `DomainSeparator`
- `SuiteDescriptor`

Every component signs the same envelope message:

```text
BLAKE3(
  OLY:SIGNATURE-ENVELOPE:V3 ||
  lp(domain_separator_utf8) ||
  lp(payload_digest_32) ||
  lp(suite_wire_name) ||
  u32_be(algorithm_count) ||
  for each algorithm in the suite's canonical order: lp(algorithm_wire_name)
)
```

v3 is a deliberate breaking revision of v2, which signed only the domain and
payload digest. In v2 the suite label and the algorithm list were unauthenticated
metadata: a hybrid envelope could be relabelled as `ed25519` and its PQ leg
stripped while the Ed25519 signature still verified (audit A-P2-1). Binding both
into the message means any relabel, leg addition, or leg removal invalidates the
Ed25519 signature. The algorithm list is taken from the suite descriptor, not
from the serialized component order, so reordering JSON cannot change the digest.

The payload is a 32-byte digest produced by the caller's existing domain, not a
replacement for that domain. This keeps ADR-0005 framing and existing
checkpoint/redaction domains intact.

The first implementation verifies Ed25519. It can carry a
`hybrid-ed25519-ml-dsa-65` suite, but `HybridRequired` verification fails closed
with `UnsupportedAlgorithm(MlDsa65)` until Olympus intentionally accepts and
audits an ML-DSA implementation. Production consumers should use
`ClassicalRequired` unless an experimental PQC build explicitly requires the
hybrid leg.

## Consequences

- No database migration.
- No verifier vector migration.
- No ceremony or circuit change.
- No new trust in unaudited PQC code by default.
- v3 changes the signed bytes and the schema tag; envelopes produced by v2 do
  not verify and must be re-signed. There is no deployed consumer of v2.
- Future ML-DSA or SLH-DSA support can be added behind a separate feature while
  keeping the v3 envelope bytes stable.

## Non-goals

This ADR does not change:

- SMT key format or leaf layout;
- BLAKE3 root hashing;
- canonical document hashes;
- redaction signed-Merkle semantics;
- Groth16 verifier paths;
- existing Ed25519 or BJJ authority keys.
