# ADR 0005: Dual-Root Commitment Binding (BLAKE3 + Poseidon)

## Status
Accepted

## Context
- Olympus binds two independent roots to each document: the BLAKE3 SMT root for ledger/state commitments and the Poseidon Merkle root for Groth16 redaction proofs.
- Without a binding commitment, an attacker could combine a valid BLAKE3 proof for document A with a valid Poseidon proof for document B and claim they refer to the same record.
- The binding must be lightweight (off-circuit) and independently verifiable by auditors.

## Decision
- Introduce `DualHashCommitment { blake3_root, poseidon_root }` as the canonical binding between the two roots (hex for BLAKE3, decimal-string for Poseidon).
- Every redaction ledger entry stores the dual commitment alongside the BLAKE3 SMT root.
- Verification uses `cross_root_validation.validate_proof_consistency` to:
  1. Verify each proof (BLAKE3 + Poseidon) independently.
  2. Reconstruct both roots and compare them against the dual commitment.
- Batch verification (`validate_batch_consistency`) is provided for cross-shard and multi-document validation flows.

## Alternatives Considered
- Embed a BLAKE3→Poseidon bridge inside the circuit: rejected for size/complexity and because off-circuit binding achieves the same security property with clearer separation of concerns.
- Single-hash design (Poseidon everywhere): rejected to preserve post-quantum candidate hashing (BLAKE3) for the ledger while keeping Poseidon only where arithmetic hashing is required.

## Consequences
- Auditors can independently verify that inclusion proofs from both domains refer to the same document.
- Any mismatch between BLAKE3 and Poseidon roots is detectable without circuit changes.
- The dual commitment format is stable and versioned; changes require a new ADR and version bump.
