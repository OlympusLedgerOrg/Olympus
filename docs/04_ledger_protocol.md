# Ledger Protocol

This document describes the ledger protocol for Olympus.

## Overview

The Olympus ledger is an append-only log of document commitments.

**v1.0 Implementation:** Single-node operation with cryptographic signatures and hash-chain integrity.  
**Phase 1+:** Replicated multi-node ledger with Guardian replication and Byzantine fault tolerance.

## Entry Format

Each ledger entry contains:
- Timestamp
- Document hash
- Merkle root
- Shard identifier
- Source signature
- Previous entry hash

## Consensus

**⚠️ Phase 1+ Feature — Not implemented in v1.0**

Olympus uses a federated consensus model (Phase 1+):
- Multiple independent nodes
- Threshold signatures for finality
- Fork detection mechanism
- Conflict resolution rules

**v1.0 Implementation:** Single-node operation with Ed25519 signatures. Multi-node consensus is planned for Phase 1+.

## Replication

**⚠️ Phase 1+ Feature — Not implemented in v1.0**

Guardian replication features (Phase 1+):
- Pull-based replication
- Merkle proof verification
- Gap detection and recovery
- Byzantine fault tolerance

**v1.0 Implementation:** Single-node append-only ledger. Guardian replication is planned for Phase 1+.

## Ledger Finality

This section defines when a shard state is considered final in the Olympus ledger. Finality is a critical property for legal and audit purposes.

> **Note on v1.0 Implementation Status:**  
> Phase 1+ features (Guardian Replication, Byzantine fault tolerance) are **not included in v1.0**.  
> Version 1.0 provides single-node cryptographic commitments with Ed25519 signatures.  
> Multi-node replication and Byzantine consensus are planned for Phase 1+.

### Definition of Final State (Phase 1+ Specification)

**⚠️ Phase 1+ Feature — Not implemented in v1.0**

A shard state is considered **final** when all of the following conditions are met:

1. **Originating Node Signature** — The shard state is cryptographically signed by its originating node using the node's registered signing key  
   ✅ **Implemented in v1.0**

2. **M-of-N Guardian Replication** — The shard state has been successfully replicated to at least **M** guardian nodes out of **N** total guardian nodes in the federation  
   ⚠️ **Phase 1+ only — Not implemented in v1.0**
   - Minimum threshold: M ≥ ⌈(N+1)/2⌉ (simple majority)
   - Recommended threshold: M ≥ ⌈2N/3⌉ (supermajority for Byzantine fault tolerance)
   - Each guardian node must acknowledge receipt with a signed commitment

3. **No Conflicting State** — No conflicting signed shard state with the same parent hash exists  
   ⚠️ **Phase 1+ only — Not implemented in v1.0**
   - If two states reference the same parent, a fork has been detected
   - Fork resolution must occur before either state is considered final
   - The conflict resolution protocol (see Consensus section) determines the canonical state

### Finality Guarantees (Phase 1+ Specification)

**⚠️ Phase 1+ Feature — Not implemented in v1.0**

Once a shard state reaches finality:
- It is **immutable** — no further changes are permitted to that state
- It is **non-repudiable** — the originating node cannot deny having created it
- It is **independently verifiable** — any party can verify the signatures and replication count
- It is **legally binding** — the state can be cited in legal and audit contexts

### Finality Verification (Phase 1+ Specification)

**⚠️ Phase 1+ Feature — Not implemented in v1.0**

To verify finality of a shard state:
1. Verify the originating node's signature ✅ **Implemented in v1.0**
2. Verify that at least M guardian nodes have signed acknowledgments ⚠️ **Phase 1+ only**
3. Check for conflicting states with the same parent hash ⚠️ **Phase 1+ only**
4. Verify the chain of previous entry hashes back to genesis ✅ **Implemented in v1.0**

Finality is a public property — any observer can verify it given the appropriate signatures and metadata.

### v1.0 Finality Model

**What v1.0 provides:**
- Ed25519 signatures on shard headers
- Cryptographic chain integrity (previous entry hash linking)
- Offline verification of signatures and hash chains
- Append-only ledger guarantees

**What v1.0 does NOT provide:**
- Multi-node replication
- Byzantine fault tolerance
- Fork detection and resolution
- Guardian node acknowledgments

For v1.0, finality is based on cryptographic commitments from a single trusted node. Multi-node consensus and Byzantine fault tolerance are deferred to Phase 1+.

## Key Rotation and Compromise Response (Ed25519)

When an agency signing key is suspected or confirmed compromised, verifiers need deterministic guidance:

1. **Revocation record** — Publish a signed revocation statement using the *new* key that references the compromised public key, a compromise timestamp, and the last known good ledger height.
2. **Re-sign historical shard headers** — For every historical shard header, produce an attestation signed by the new key over the original header hash. This does **not** replace history; it adds an append-only “superseding signature.”
3. **Ledger entries remain immutable** — No ledger entry bytes change. The append-only property is preserved.
4. **Verifier behavior**:
   - Before compromise height: accept old-key signatures if they validate and precede the published compromise timestamp.
   - At/after compromise height: require either the new-key signature directly on the entry or a superseding attestation that chains the original hash to the new key.
   - Reject any shard headers signed by the compromised key with a timestamp at or after the compromise timestamp unless a superseding attestation exists.
5. **Publishing** — Store revocation statements and superseding attestations in the ledger as dedicated event types to keep the chain of custody auditable.

## Key Storage & Publication Guidance (v1.0)

Even in development, key handling must be deterministic and auditable:

1. **Local storage (dev)** — Store signing keys outside the repo, e.g.
   `~/.config/olympus/keys/<shard_id>.ed25519`, with `0600` permissions.
   Export the path via `OLYMPUS_SIGNING_KEY_PATH` in `.env` or runtime
   configuration. Never commit secrets to source control.
2. **Public key publication** — Publish the hex-encoded Ed25519 public key
   and its **SHA-256 fingerprint** in an append-only “key registry” entry
   in the ledger (or equivalent metadata channel). Each shard header already
   embeds the public key, but the registry entry provides a stable audit trail
   for discovery and rotation tracking.
3. **Rotation records** — Every rotation should emit:
   - `old_pubkey` + fingerprint
   - `new_pubkey` + fingerprint
   - effective timestamp and reason code (e.g., scheduled rotation, compromise)
4. **Future KMS/HSM support (optional)** — In production, plan to load the
   signing key from a hardware-backed KMS/HSM. The public key and fingerprint
   should remain identical to the values recorded in the ledger registry.

## Batched Timestamping Strategy

To control RFC 3161 (or equivalent) timestamping costs at scale:

- **Cadence**: Anchor the ledger root hash on a fixed schedule (e.g., every 5 minutes) rather than per entry.
- **Batch window**: All entries within the window are covered by the same anchor, reducing per-entry cost while keeping bounded delay.
- **Integrity linkage**: Each batch anchor references the Merkle root at the end of the window; the next window links by previous hash as usual.
- **Backpressure**: If anchoring fails, halt new batch closure until the anchor succeeds to avoid unanchored gaps.
- **Auditability**: Record the timestamp token and TSA certificate chain (RFC 3161 or equivalent) alongside the batch root in the ledger so verifiers can validate the anchor independently.

## TSA Trust Policy (Dev vs Prod)

To keep verification predictable, Olympus treats RFC 3161 trust modes explicitly:

- **Dev mode** — Accept the TSA certificate embedded in the TimeStampToken.
  This mode is suitable for local testing and sandbox deployments.
- **Prod mode** — Require either:
  - **Pinned TSA certificate fingerprints** (SHA-256), or
  - **Validation against a configured trust store** of approved TSA certs.

Every stored timestamp token must log the TSA certificate fingerprint so auditors
can validate provenance without trusting Olympus infrastructure.
