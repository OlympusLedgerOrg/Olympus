# Ledger Protocol

This document describes the ledger protocol for Olympus.

## Overview

The Olympus ledger is an append-only, replicated log of document commitments.

## Entry Format

Each ledger entry contains:
- Timestamp
- Document hash
- Merkle root
- Shard identifier
- Source signature
- Previous entry hash

## Consensus

Olympus uses a federated consensus model:
- Multiple independent nodes
- Threshold signatures for finality
- Fork detection mechanism
- Conflict resolution rules

## Replication

- Pull-based replication
- Merkle proof verification
- Gap detection and recovery
- Byzantine fault tolerance

## Ledger Finality

This section defines when a shard state is considered final in the Olympus ledger. Finality is a critical property for legal and audit purposes.

### Definition of Final State

A shard state is considered **final** when all of the following conditions are met:

1. **Originating Node Signature** — The shard state is cryptographically signed by its originating node using the node's registered signing key

2. **M-of-N Guardian Replication** — The shard state has been successfully replicated to at least **M** guardian nodes out of **N** total guardian nodes in the federation
   - Minimum threshold: M ≥ ⌈(N+1)/2⌉ (simple majority)
   - Recommended threshold: M ≥ ⌈2N/3⌉ (supermajority for Byzantine fault tolerance)
   - Each guardian node must acknowledge receipt with a signed commitment

3. **No Conflicting State** — No conflicting signed shard state with the same parent hash exists
   - If two states reference the same parent, a fork has been detected
   - Fork resolution must occur before either state is considered final
   - The conflict resolution protocol (see Consensus section) determines the canonical state

### Finality Guarantees

Once a shard state reaches finality:
- It is **immutable** — no further changes are permitted to that state
- It is **non-repudiable** — the originating node cannot deny having created it
- It is **independently verifiable** — any party can verify the signatures and replication count
- It is **legally binding** — the state can be cited in legal and audit contexts

### Finality Verification

To verify finality of a shard state:
1. Verify the originating node's signature
2. Verify that at least M guardian nodes have signed acknowledgments
3. Check for conflicting states with the same parent hash
4. Verify the chain of previous entry hashes back to genesis

Finality is a public property — any observer can verify it given the appropriate signatures and metadata.
