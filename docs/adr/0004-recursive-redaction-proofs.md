# ADR 0004: Recursive Redaction Proofs via Halo2 Composition

## Status
Proposed (Phase 1+)

## Context

Documents in Olympus may undergo multiple redaction events over their
lifetime.  Each event produces a Groth16 ZK proof attesting that the
revealed subset is derived from the original committed Merkle root.
A verifier who wants to confirm the *current validity state* of a
document must today:

1. Verify ledger inclusion of the document's Poseidon root (SMT anchor).
2. Replay **every** redaction event proof in sequence.
3. Confirm the chain linkage between events is consistent.

As the number of redaction events grows, this linear replay becomes
impractical for lightweight verifiers (mobile clients, embedded
auditors, third-party compliance checks).

Halo2's IPA commitment scheme supports **recursive proof composition**:
a proof circuit can verify another proof inside itself.  This enables
folding the entire redaction history into a single verification
artifact.

## Decision

Introduce a **recursive redaction proof** data model and accumulation
layer in `protocol/halo2_backend.py` that:

1. Defines `RedactionEvent` — an immutable, hash-linked record of a
   single redaction operation.
2. Defines `RecursiveRedactionProof` — a single compressed artifact
   proving ledger inclusion *and* validity across all redaction events.
3. Provides `RecursiveProofAccumulator` — a builder that chains events
   and produces the compressed proof.
4. Provides `verify_recursive_redaction_proof()` — structural
   verification of the compressed proof (full cryptographic verification
   deferred to Phase 1+ when Halo2 bindings are available).
5. Extends `Halo2Prover` with `prove_recursive()` and `Halo2Verifier`
   with `verify_recursive()` (both raise `NotImplementedError` until
   Phase 1+).

### Proof Structure

```
RecursiveRedactionProof
├── document_id            # Which document
├── event_count            # How many redaction events are folded
├── current_state_hash     # BLAKE3 of the latest event (chain head)
├── original_root          # Poseidon root of the original document
├── ledger_root            # SMT root proving ledger inclusion
├── recursive_proof        # Compressed Halo2 proof bytes (Phase 1+)
├── event_hashes           # Per-event BLAKE3 hashes for auditability
└── timestamp              # When the recursive proof was generated
```

### Event Chain

Events form an append-only linked list via `previous_event_hash`:

```
Event 0 (prev="") → Event 1 (prev=hash(E0)) → Event 2 (prev=hash(E1))
```

Each event's hash covers its index, document ID, version, revealed
indices, roots, commitments, timestamp, and the previous hash — making
the chain tamper-evident.

### Verification Modes

| Mode | When | What it proves |
|------|------|----------------|
| **Structural** (now) | Phase 0 | Event count, hash consistency, chain linkage |
| **Cryptographic** (Phase 1+) | Halo2 available | All of the above + each per-event ZK proof is valid, inside a single Halo2 verification |

### Circuit Design (Phase 1+)

The recursive circuit (`recursive_redaction_composition`) will:

1. Accept the previous recursive proof as a private input.
2. Accept the new redaction event's witness.
3. Verify the inner (Groth16 or Halo2) proof for the new event.
4. Verify chain linkage (`previous_event_hash` matches).
5. Output updated public inputs: `current_state_hash`, `event_count`,
   `original_root`, `ledger_root`.

A verifier checks only the outermost proof, which transitively
guarantees all inner proofs.

## Alternatives Considered

- **Batched Groth16**: Aggregate multiple Groth16 proofs into a batch
  proof.  Rejected because Groth16 does not natively support recursive
  composition; a pairing-based aggregation would require a new trusted
  setup per batch size.

- **STARK-based recursion**: STARKs support recursion but produce
  significantly larger proofs and lack parity with the existing circom
  circuit library.

- **No compression**: Continue requiring verifiers to replay all events.
  Rejected for scalability reasons; 100+ redaction events on a single
  document would be unreasonable.

## Consequences

- The data model and accumulation logic are available immediately for
  integration testing and structural verification.
- Cryptographic recursive verification is deferred to Phase 1+ when
  Halo2 Rust bindings (`py-halo2` or FFI) are integrated.
- The `RecursiveRedactionProof` artifact is forward-compatible: when
  Halo2 proving is available, the same data structure carries the
  actual proof bytes.
- Existing Groth16 per-event proofs remain valid and can be verified
  independently; the recursive proof is an optimization, not a
  replacement.

## References

- ADR 0002: Halo2 as optional secondary proving system
- ADR 0003: Unified proof system architecture
- `protocol/halo2_backend.py`: Implementation
- `tests/test_recursive_redaction_proof.py`: Test coverage
