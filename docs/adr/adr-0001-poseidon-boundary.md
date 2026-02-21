# ADR 0001: Poseidon vs BLAKE3 Boundary

## Status
Accepted (updated after Groth16 requirement)

## Context

- Ledger-level hashing is fixed to BLAKE3 for append-only commitments and domain
  separation.
- Circom circuits require field-friendly hashes; BLAKE3 is infeasible in-circuit.
- Poseidon is efficient and available via circomlib, making it the default
  in-circuit hash.
- The proving system is Groth16 (per latest requirement); proving keys are tied
  to the circuit hash function.

## Decision

- Use **Poseidon** for all in-circuit hashing (see `proofs/circuits/lib/poseidon.circom`).
- Keep **BLAKE3** for all Python/ledger hashing (see `protocol/hashes.py`).
- Witness generation must convert BLAKE3 commitments into Poseidon field
  elements before proving.
- snarkjs is invoked via the Groth16 bridge in `protocol/zkp.py`; any switch to
  PLONK would require new keys but would not change the hash boundary decision.

## Consequences

- Changing the in-circuit hash invalidates all Groth16 keys and proofs.
- Developers must document and test the BLAKE3→Poseidon conversion when building
  witnesses.
- Integration must cover Python → witness → circuit → Groth16 verify using the
  same Poseidon parameters.

## Alternatives Considered

- **Poseidon everywhere:** rejected to preserve existing BLAKE3 commitments and
  audit trail.
- **In-circuit BLAKE3 gadget:** rejected for performance/complexity.
- **Immediate PLONK migration:** deferred; Groth16 remains the proving system
  while keeping the Poseidon/BLAKE3 boundary stable.
