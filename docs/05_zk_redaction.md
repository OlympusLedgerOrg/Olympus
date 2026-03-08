# Zero-Knowledge Redaction

This document describes the zero-knowledge redaction protocol in Olympus.

## Overview

Olympus allows documents to be redacted while providing cryptographic proof that the redacted version is a faithful redaction of the original.

## Protocol

1. Original document is canonicalized
2. Document is split into atomic units (leaves)
3. Merkle tree is constructed from leaves
4. Redacted version selects subset of leaves
5. ZK proof demonstrates inclusion of selected leaves
6. Proof is verified against original commitment

## Privacy Properties

- Redacted content remains hidden
- Proof does not reveal structure of redacted portions
- Verification requires only public commitments

## Proof System

- **Recommended (Phase 0.5+)**: Halo2 (no trusted setup; production-proven in Zcash/Scroll). Python bindings exist (`py-halo2`) though less mature than Rust; circuits should be versioned with explicit parameter pins.
- Current reference: circom circuits for Merkle inclusion and structural validity.
- Batch verification is supported at the proof layer.

## Dual-Anchor Strategy

Olympus uses two independent hash functions for two distinct purposes:

| Layer | Hash Function | Role |
|-------|--------------|------|
| Ledger / SMT | **BLAKE3** | Append-only state commitments; efficient, post-quantum candidate |
| ZK circuit | **Poseidon** | Arithmetic-friendly hash native to BN128 field; cheap to verify inside Groth16 |

### Why two hashes?

The Groth16 redaction circuit (`proofs/circuits/redaction_validity.circom`) uses
Poseidon as its internal hash, because Poseidon is efficient inside an arithmetic
constraint system.  The rest of the Olympus protocol uses BLAKE3 for the
256-height Sparse Merkle Tree (SMT) that underpins ledger commitments.

Rather than building a BLAKE3→Poseidon bridge circuit (which would be large
and maintenance-heavy), the **Poseidon Merkle root** (`originalRoot` in the
circuit) is *anchored* in the BLAKE3 SMT under a dedicated key namespace:
`"redaction_root_poseidon"`.  This avoids any cross-hash constraint.

### Verification flow

A verifier holding a `RedactionProofWithLedger` bundle performs two independent checks:

1. **SMT anchor check** (`verify_smt_anchor`):
   - Look up the SMT existence proof.
   - Confirm the proof is cryptographically valid (BLAKE3 path reconstruction).
   - Confirm the stored 32-byte value equals the big-endian serialization of
     `zk_public_inputs.original_root`.
   - Confirm the proof is tied to a specific committed SMT root (from a ledger entry).

2. **ZK proof check** (`verify_all` with a `zk_verifier` hook):
   - Pass the Groth16 proof blob and public inputs to a language-specific
     snarkjs/arkworks binding.
   - The public inputs include `originalRoot`, `redactedCommitment`, and `revealedCount`.

Because step (1) confirms the Poseidon root is recorded in the ledger, and step (2)
confirms the ZK proof is valid for that same root, a verifier gains end-to-end
guarantees without ever needing a BLAKE3-in-circuit primitive.

### Key derivation

Poseidon root records are stored under a deterministic SMT key:

```python
from protocol.redaction_ledger import poseidon_root_record_key

key = poseidon_root_record_key(document_id, version)
# equivalent to: record_key("redaction_root_poseidon", document_id, version)
```

This keeps Poseidon root keys distinct from standard document keys
(`record_key("document", …)`), preserving append-only semantics across versions.

### Poseidon root serialization

The Poseidon root is a BN128 scalar field element (0 ≤ root < SNARK_SCALAR_FIELD).
It is stored in the SMT as a **32-byte big-endian unsigned integer**.

```python
from protocol.redaction_ledger import poseidon_root_to_bytes, poseidon_root_from_bytes

serialized = poseidon_root_to_bytes("12345678901234567890")   # 32 bytes
recovered  = poseidon_root_from_bytes(serialized)             # "12345678901234567890"
```

Values outside [0, SNARK_SCALAR_FIELD) are rejected with `ValueError`.

### Implementation

| Component | Location |
|-----------|----------|
| `RedactionProofWithLedger` dataclass | `protocol/redaction_ledger.py` |
| `ZKPublicInputs` dataclass | `protocol/redaction_ledger.py` |
| `poseidon_root_to_bytes` / `from_bytes` | `protocol/redaction_ledger.py` |
| `poseidon_root_record_key` | `protocol/redaction_ledger.py` |
| `RedactionProtocol.commit_document_dual` | `protocol/redaction.py` |
| `RedactionProtocol.create_redaction_proof_with_ledger` | `protocol/redaction.py` |
| Tests | `tests/test_redaction_ledger.py` |

