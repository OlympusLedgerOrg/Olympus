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

## Poseidon Backend Option and Parameter Parity

### Python BN128 implementation (`protocol/poseidon_bn128.py`)

``poseidon_py`` (drknzz/poseidon-py v0.1.5) implements the StarkWare/Cairo
Hades permutation (capacity element = 2, STARK-prime round constants), which
is **fundamentally incompatible** with the BN128 Poseidon used by circomlibjs
and the circom circuits.

To resolve this, ``protocol/poseidon_bn128.py`` provides a pure-Python BN128
Poseidon implementation whose round constants and MDS matrix are extracted
verbatim from ``circomlibjs/src/poseidon_constants.json`` (entry C[1], M[1]
for t = 3).  It is the **default** hash function used by
``protocol/poseidon_tree.py`` and produces outputs that are bit-for-bit
identical to what the circuits compute.  ``poseidon_py`` is no longer used in
consensus-critical code.

### Parity tests (`tests/test_poseidon_parameter_parity.py`)

* ``TestBN128PythonParity`` — asserts that ``poseidon_hash_bn128`` matches
  circomlibjs for four deterministic BN128 test vectors (``(0,0)``,
  ``(1,2)``, ``(42,0)``, ``(p-1, 123)``).  All pass; no ``xfail`` needed.

* ``TestJSBackendEndToEnd`` — verifies the persistent-process plumbing in
  ``protocol.poseidon_js`` (``hash2``, ``batch_hash2``, ``merkle_root``) via
  the reference vector script.  Must pass in CI.

CI installs Node ≥ 18 and runs ``npm install`` in ``proofs/`` before pytest.
If Node is missing in CI the tests hard-fail (``pytest.fail``, not ``skip``)
so the gap is never silent.

### JS backend option (`protocol/poseidon_js.py`)

Set ``OLY_POSEIDON_BACKEND=js`` to route all ``_poseidon_hash_pairs`` calls
through a **persistent** Node.js process (single spawn per interpreter
lifetime, line-delimited JSON IPC, ``batch_hash2`` op amortises one IPC
call per tree level).  This is an advanced option for environments that need
independent verification against the JS reference; the Python BN128 backend
is the default and is already circuit-compatible.

### Zero-leaf semantics

Zero-leaf padding (``0`` as raw field element) is preserved in both backends.
The backend selector controls only the parent-node hash, not leaf representation.

