# Ledger Protocol

This document describes the ledger protocol for Olympus.

## Overview

The Olympus ledger is an append-only log of document commitments.

**v1.0 Implementation:** Single-node operation with cryptographic signatures and hash-chain integrity.  
**Phase 1+:** Replicated multi-node ledger with Guardian replication and Byzantine fault tolerance.

## Entry Format

Each ledger entry contains:
- Timestamp
- Document identifier
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
