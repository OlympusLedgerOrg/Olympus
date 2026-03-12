# Federation Governance Model (Phase 1+)

This document defines the governance model for a federated Olympus deployment. v1.0 ships as a single-node system; these rules are **forward-looking** and must be preserved by any Phase 1+ implementation.

## Roles

- **Stewards**: Operating institutions that run Olympus nodes and hold signing keys.
- **Guardians**: Independent replication peers that provide quorum acknowledgments and fork detection.
- **Auditors**: External parties that continuously verify headers, ledger chains, and anchors.
- **Publishers**: Agencies that submit documents; they do not influence consensus.

## Membership and Trust Roots

- Stewards and Guardians are registered in an **append-only identity registry** signed by existing Stewards.
- Each member publishes:
  - Ed25519 public key (or threshold key share metadata)
  - SHA-256 fingerprint of the public key
  - Governance role (Steward/Guardian)
  - Activation timestamp and optional expiration/rotation plan
- Admission requires **M-of-N Steward signatures** on the registry update; eviction uses the same quorum.

## Decision Procedures

- **Protocol Upgrades**: Require supermajority Steward approval (≥2/3) and a cutover height. Upgrades are additive; legacy verification remains valid.
- **Key Rotation**: Stewards publish revocation and superseding attestations (see `docs/04_ledger_protocol.md`). Guardians reject headers signed with revoked keys after the effective timestamp.
- **Guardian Quorum**: A shard state is final when acknowledged by at least **Q = ⌈2N/3⌉** active Guardians in the current epoch. Acknowledgments are signed and stored as append-only metadata.
- **Dispute Resolution**: Forks at the same `(shard_id, height, round)` are resolved by selecting the candidate with (1) highest Guardian quorum weight, (2) NTP-hardened timestamp sanity checks against candidate median time, then (3) lowest lexicographic shard header hash as a deterministic tie-breaker.

## Operational Controls

- **Transparency**: All governance actions (admit, evict, rotate, upgrade) are recorded as ledger events with canonical JSON bodies.
- **Separation of Duties**: Steward keys used for protocol operations must be distinct from operational access keys (SSH/K8s/etc.).
- **Monitoring**: Guardians publish liveness beacons; missing beacons trigger replication backoff but do not allow history rewrites.
- **Stealth Compromise Detection**: Guardians track behavior anomalies (double-votes and signing-rate spikes) and trigger proactive key-share refresh windows before emergency rotation thresholds are reached.
- **Auditability**: Auditors verify that every finalized shard header has the required Guardian acknowledgments and, when present, valid external anchors.

## Incident Response

- **Key Compromise**:
  - Publish revocation + superseding signatures immediately.
  - Guardians quarantine new headers from the compromised key after the compromise timestamp.
  - Stewards re-anchor the latest uncontested root to re-establish time ordering.
- **Data Gaps**:
  - Guardians reject replication segments with missing sequence numbers.
  - Stewards must re-export the missing range with proofs; gaps remain detectable.
- **TSA Failure**:
  - Anchoring may pause, but ledger insertion continues with backpressure until an anchor succeeds (see `docs/11_external_anchoring.md`).

## Compliance Checklist

- [ ] Identity registry is append-only and signed by Stewards.
- [ ] Guardian quorum size and member list are published and versioned.
- [ ] Every shard header >= cutover height carries Guardian acknowledgments.
- [ ] All governance actions are present in the ledger with signatures and timestamps.
- [ ] External anchors are auditable with published TSA certificate fingerprints.
