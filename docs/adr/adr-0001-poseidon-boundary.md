# ADR 0001: Poseidon vs BLAKE3 Boundary

## Status
Accepted

## Context

- Olympus ledger hashing uses BLAKE3 for performance and domain separation.
- Circom circuits require algebraically friendly hash functions; BLAKE3 is not
  field-friendly.
- Poseidon is already available via circomlib and is efficient inside circuits.
- New requirement specifies Groth16 proving, which still relies on circuit-side
  hashing; only the proving system changes.

## Decision

- All **in-circuit** hashing uses Poseidon (see `proofs/circuits/lib/poseidon.circom`).
- All **Python/ledger** hashing remains BLAKE3 (see `protocol/hashes.py`).
- Witness generation is responsible for translating ledger commitments
  (BLAKE3-derived) into the Poseidon field elements consumed by circuits.
- SnarkJS is invoked via a Python bridge (`protocol/zkp.py`) using Groth16.

## Consequences

- Changing the in-circuit hash would invalidate proving/verifying keys.
- Developers must be explicit about the conversion boundary when preparing
  witnesses.
- Integration tests should cover Python → witness → circuit → Groth16 verify.

## Alternatives Considered

- **Poseidon everywhere:** rejected due to existing BLAKE3 commitments and
  ecosystem tooling.
- **PLONK migration:** deferred per new requirement to keep Groth16 flow while
  preserving Poseidon in circuits.
