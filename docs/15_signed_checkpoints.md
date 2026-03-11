# Signed Root Checkpoints

This document describes the signed checkpoint system in Olympus, designed to prevent split-view attacks in transparency logs.

## Problem Statement

Without a public checkpoint system, a malicious operator can present different Merkle roots to different users, creating a **split-view attack**:

```
Auditor A sees root: R1
Auditor B sees root: R2
Both are valid cryptographically.
But they represent different histories.
```

This is the number-one attack against transparency systems.

## Solution: Signed Tree Heads (Checkpoints)

Olympus implements signed root checkpoints based on Certificate Transparency's Signed Tree Head (STH) design. Checkpoints provide public commitments to the global ledger state, allowing witnesses to verify that everyone sees the same history.

## Checkpoint Structure

A signed checkpoint contains:

```python
@dataclass
class SignedCheckpoint:
    sequence: int                        # Monotonically increasing counter
    timestamp: str                       # ISO 8601 timestamp
    ledger_head_hash: str               # Hash of latest ledger entry
    previous_checkpoint_hash: str        # Hash of previous checkpoint (chain)
    ledger_height: int                  # Total number of ledger entries
    shard_roots: dict[str, str]         # Optional shard-specific commitments
    consistency_proof: list[str]        # Merkle consistency proof to previous root
    checkpoint_hash: str                # Hash of checkpoint payload
    signature: str                      # Ed25519 signature
    public_key: str                     # Public key used for signing
```

## Creating Checkpoints

```python
from protocol.checkpoints import create_checkpoint
import nacl.signing

signing_key = nacl.signing.SigningKey.generate()

checkpoint = create_checkpoint(
    sequence=0,
    ledger_head_hash="abc123...",
    ledger_height=100,
    previous_checkpoint_hash="",  # Empty for genesis
    shard_roots={"shard1": "root1", "shard2": "root2"},
    signing_key=signing_key,
)
```

## Verifying Checkpoints

### Individual Checkpoint Verification

```python
from protocol.checkpoints import verify_checkpoint

is_valid = verify_checkpoint(checkpoint)
```

### Checkpoint Chain Verification

```python
from protocol.checkpoints import verify_checkpoint_chain

checkpoints = [checkpoint1, checkpoint2, checkpoint3]
is_valid = verify_checkpoint_chain(checkpoints)
```

Chain verification ensures:
1. Each checkpoint is individually valid
2. Sequences are monotonically increasing
3. Each checkpoint correctly references the previous checkpoint hash
4. Ledger heights are monotonically increasing
5. Merkle consistency proofs demonstrate that each new ledger root extends the
   previous root (no truncation forks)

Each checkpoint carries a `consistency_proof` containing the ordered leaf
hashes for the current tree. Verifiers recompute the prior root over the first
`ledger_height` leaves and the current root over all provided leaves to confirm
that the state grew append-only.

## Fork Detection

```python
from protocol.checkpoints import detect_checkpoint_fork

# Returns True if checkpoints represent a fork
is_fork = detect_checkpoint_fork(checkpoint_a, checkpoint_b)
```

A fork is detected when two checkpoints have:
1. The same sequence number but different content, OR
2. The same previous_checkpoint_hash but different checkpoint_hash

## Checkpoint Registry

The `CheckpointRegistry` class provides an in-memory store for checkpoints with automatic fork detection:

```python
from protocol.checkpoints import CheckpointRegistry

registry = CheckpointRegistry()

# Add checkpoints (automatically detects forks)
try:
    registry.add_checkpoint(checkpoint1)
    registry.add_checkpoint(checkpoint2)
except ValueError as e:
    print(f"Fork detected: {e}")

# Verify entire registry
is_valid = registry.verify_registry()

# Get latest checkpoint
latest = registry.get_latest_checkpoint()

# Get checkpoint by sequence
checkpoint = registry.get_checkpoint(sequence=5)
```

## Witness Protocol

External witnesses can use checkpoints to detect split views:

1. **Gossip Protocol**: Witnesses exchange checkpoints with each other
2. **Consistency Verification**: If two witnesses have checkpoints with the same sequence but different hashes, a split view is detected
3. **Public Publication**: Checkpoints should be published to multiple independent channels (DNS, blockchain anchors, public logs)

## Integration with Ledger

Checkpoints should be created periodically (e.g., every 1000 entries or every 5 minutes):

```python
from protocol.ledger import Ledger
from protocol.checkpoints import create_checkpoint, CheckpointRegistry

ledger = Ledger()
checkpoint_registry = CheckpointRegistry()

# After adding entries to ledger
if len(ledger.entries) % 1000 == 0:
    latest_entry = ledger.entries[-1]
    previous_checkpoint = checkpoint_registry.get_latest_checkpoint()

    checkpoint = create_checkpoint(
        sequence=len(checkpoint_registry.checkpoints),
        ledger_head_hash=latest_entry.entry_hash,
        ledger_height=len(ledger.entries),
        previous_checkpoint_hash=previous_checkpoint.checkpoint_hash if previous_checkpoint else "",
        signing_key=signing_key,
    )

    checkpoint_registry.add_checkpoint(checkpoint)
```

## Security Properties

Signed checkpoints provide:

1. **Non-repudiation**: Operator cannot deny creating a checkpoint
2. **Tamper evidence**: Any modification to checkpoint invalidates signature
3. **Fork detection**: Witnesses can detect split views by comparing checkpoints
4. **Append-only guarantee**: Checkpoint chain ensures history cannot be rewritten
   and consistency proofs prevent history truncation forks
5. **Public verifiability**: Anyone can verify checkpoint signatures

## Domain Separation

Checkpoint hashes use the domain separation prefix `OLY:CHECKPOINT:V1` to prevent cross-domain collisions with other hash types in the protocol.

## Future Enhancements

**Phase 1+ features** (not in v1.0):

1. **Cross-log witnesses**: Independent witness servers that monitor multiple Olympus nodes
2. **Gossip protocol**: Automated checkpoint exchange between witnesses
3. **DNS publication**: Publish checkpoint hashes in DNS TXT records
4. **Blockchain anchoring**: Anchor checkpoints to public blockchains for additional tamper evidence
5. **Monitoring dashboards**: Public dashboards showing checkpoint consistency across witnesses

## References

- Certificate Transparency RFC 6962: https://tools.ietf.org/html/rfc6962
- Transparency Log Witness Protocol: https://github.com/google/trillian/blob/master/docs/witnesses.md
- Split-view attack description: https://certificate.transparency.dev/howctworks/#the-split-view-attack
