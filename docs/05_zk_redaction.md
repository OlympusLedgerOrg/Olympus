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

- **Primary (Core Ledger)**: Groth16 (circom circuits + snarkjs) to meet throughput
  and latency goals. Trusted setup risk is mitigated with a public, multi-party
  Phase 2 ceremony.
- **Optional (High-Assurance paths)**: Halo2 can be slotted in for special cases
  such as superseding signatures or “final appeal” proofs when minimal trust
  assumptions are required; circuits should still be versioned and pinned.
- Batch verification is supported at the proof layer.

## Dual-Anchor Strategy

Olympus uses two independent hash functions for two distinct purposes:

| Layer | Hash Function | Role |
|-------|--------------|------|
| Ledger / SMT | **BLAKE3** | Append-only state commitments; efficient, post-quantum candidate |
| ZK circuit | **Poseidon** | Arithmetic-friendly hash native to BN128 field; cheap to verify inside Groth16 |

### Canonical leaf bytes (single document view)

Both the BLAKE3 and Poseidon Merkle trees consume the **same canonical leaf
bytes**:

```
canonical_section = normalize_whitespace(section).encode("utf-8")
```

`RedactionProtocol.commit_document_dual` anchors only the **root pair**
(`blake3_root`, `poseidon_root`) into the SMT. No Poseidon tree structure is
stored or exposed. Poseidon tree construction now happens on the proof path:
`create_redaction_proof_with_ledger` rebuilds the Poseidon tree from the same
canonical bytes (defaults: depth 4, 16 leaves; configurable via
`proofs/circuits/parameters.circom`) and enforces the binding check
from the previous PR:

```
if str(int(poseidon_root)) != poseidon_tree.get_root():
    raise ValueError("Provided poseidon_root does not match canonical document sections")
```

This keeps the committed Poseidon root aligned with the tree used by the
Groth16 circuit while reducing the public commitment to two hashes.

### Why two hashes?

The Groth16 redaction circuit (`proofs/circuits/redaction_validity.circom`) uses
Poseidon as its internal hash, because Poseidon is efficient inside an arithmetic
constraint system.  To reduce constraint pressure, Merkle checks are enforced
only for revealed leaves; redacted leaves are masked to zero in the commitment
chain and skip root constraints. The rest of the Olympus protocol uses BLAKE3
for the 256-height Sparse Merkle Tree (SMT) that underpins ledger commitments.

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

2. **ZK proof check** (`verify_all` / `verify_zk_redaction`):
   - By default, `verify_all` invokes `verify_zk_redaction`, which calls
     `snarkjs groth16 verify` via the Python `Groth16Prover` bridge.
   - The public inputs include `originalRoot`, `redactedCommitment`, and `revealedCount`
     (exactly the order declared as `public` signals in `redaction_validity.circom`).
   - Returns a three-valued `VerificationResult`: `VALID`, `INVALID`, or
     `UNABLE_TO_VERIFY` (e.g., missing verification key or malformed inputs).
   - A custom verifier hook can still be supplied to `verify_all` when needed.

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

### Witness generation pipeline (redaction_validity)

* Input construction lives in `proofs/test_inputs/generate_inputs.js`, which
  builds Poseidon Merkle trees (defaults: depth 4, 16 leaves via
  `OLYMPUS_REDACTION_*` overrides), derives per-leaf sibling paths, and writes
  circuit-ready JSON inputs to `proofs/build/redaction_validity_input.json`.
* Python witness/proof helpers live in `proofs/proof_generator.py`:
  * `ProofGenerator.generate_witness()` writes the JSON inputs and calls the
    circuit's WASM witness generator (`proofs/build/redaction_validity_js/generate_witness.js`)
    to produce a `.wtns`.
  * `ProofGenerator.prove()` and `verify()` bridge to `snarkjs groth16` for proof
    generation and verification using the dev keys emitted by `proofs/setup_circuits.sh`.
* Public signal ordering enforced by `verify_zk_redaction` is
  `[originalRoot, redactedCommitment, revealedCount]`, matching the circuit's
  `component main {public [...]}` declaration.
* Integration test coverage: `tests/test_proof_generator.py::test_redaction_validity_round_trip_verification`
  exercises input generation → witness → proof → verification end to end.

## Recursive Proof Composition (Phase 1+)

Documents with multiple redaction events can have their entire history
compressed into a **single verification artifact** using Halo2 recursive
proof composition.  Instead of replaying every per-event ZK proof, a
verifier checks one `RecursiveRedactionProof` and is convinced of:

1. **Ledger inclusion** — the document's Poseidon root is committed in the SMT.
2. **Redaction validity** — every redaction event is individually valid.
3. **History consistency** — the event chain is append-only and tamper-evident.

### Data model

| Component | Location |
|-----------|----------|
| `RedactionEvent` | `protocol/halo2_backend.py` |
| `RecursiveRedactionProof` | `protocol/halo2_backend.py` |
| `RecursiveProofAccumulator` | `protocol/halo2_backend.py` |
| `verify_recursive_redaction_proof` | `protocol/halo2_backend.py` |
| Tests | `tests/test_recursive_redaction_proof.py` |

Structural verification (event hash consistency and chain linkage) is
available now.  Cryptographic recursive verification via Halo2 is
deferred to Phase 1+.  See [ADR 0004](adr/0004-recursive-redaction-proofs.md)
for the full design rationale.
