# ADR-0009: Poseidon Hash Suite Contract (poseidon-bn254-v1)

**Status:** Accepted  
**Date:** 2026-05-02  
**Authors:** Olympus Core Team  

---

## Context

Olympus uses the Poseidon hash function for all circuit-native commitments:
Merkle leaf hashes, internal node hashes, nullifiers, and membership commitments
inside Groth16 circuits. The parameters used are those from circomlibjs
(`poseidon_constants.json`), which match the circom `Poseidon` template used
in `merkleProof.circom` and `non_existence.circom`.

These parameters have been implicitly locked since the first circuit was written,
but were never formally documented. This ADR makes the contract explicit so that:

1. External verifiers (FPF, EFF, newsrooms) know exactly which parameter set
   to use when independently verifying a proof.
2. Future hash suite upgrades (e.g., Poseidon2) are introduced as a clean new
   versioned suite, not a silent replacement.
3. Every proof bundle self-declares which suite it was built with, so a
   3-year-old proof can always be verified against the correct parameters.

---

## Decision

Olympus defines the canonical in-circuit hash suite as **`poseidon-bn254-v1`**
with the following fully-pinned parameters. These parameters MUST NOT be changed.
Any future upgrade MUST introduce a new suite identifier (e.g., `poseidon2-bn254-v2`).

### Suite Parameters

| Parameter | Value |
|---|---|
| **Suite ID** | `poseidon-bn254-v1` |
| **Curve** | BN254 (also known as BN128, alt_bn128) |
| **Width** | t = 3 (capacity=1, rate=2) |
| **Arity** | 2 inputs per hash call |
| **Full rounds** | nRoundsF = 8 (4 before partial, 4 after) |
| **Partial rounds** | nRoundsP = 57 |
| **S-box** | x⁵ mod p (degree-5 power map) |
| **MDS matrix** | 3×3, from circomlibjs `poseidon_constants.json` |
| **Round constants** | From circomlibjs `poseidon_constants.json` (195 values for t=3) |
| **Constants source** | `circomlibjs/src/poseidon_constants.json`, entry C[1] (t-2=1) |
| **Field modulus (p)** | `21888242871839275222246405745257275088548364400416034343698204186575808495617` |

### Domain Separation

Domain tags are mixed into the inputs by double-hashing:
`Poseidon(Poseidon(domain_tag, input_a), input_b)`

| Context | Domain Tag | Encoding |
|---|---|---|
| Merkle leaf | `0` | `Poseidon(Poseidon(0, key), value)` |
| Merkle internal node | `1` | `Poseidon(Poseidon(1, left), right)` |

### Leaf Encoding

Before hashing, a leaf key/value pair is encoded as:
- `key`: the BLAKE3 hash of the record, reduced mod p (modular reduction, not truncation)
- `value`: the BLAKE3 hash of the canonical document bytes, reduced mod p

### Proof Bundle Metadata

Every proof bundle produced by Olympus MUST include the field:
```json
{ "hash_suite": "poseidon-bn254-v1" }
```

This allows a verifier to select the correct parameter set without inspecting
the circuit source code.

---

## Rationale

### Why not Poseidon2?

Poseidon2 offers ~2-4x fewer constraints per hash, which would reduce proving
time and ceremony cost. However:

- All current circuits, verifier artifacts, and test vectors are built around
  the v1 parameter set.
- The Groth16 trusted setup ceremony (pre-launch gate) produces keys that are
  circuit-specific. Switching hash functions means redoing the ceremony.
- The performance gain is not currently a bottleneck. Ingest throughput is
  the limiting factor, not constraint count.

Poseidon2 is **intentionally deferred**. When introduced, it will be a clean
new suite (`poseidon2-bn254-v2`), not a silent replacement of this one.

### Why pin the constants source explicitly?

The Poseidon parameter generation script (IAIK Grain PRNG) is deterministic
given its inputs. However, different implementations have historically used
slightly different constant orderings or indexing conventions. By pinning to
`circomlibjs/src/poseidon_constants.json` explicitly, we ensure that the
Python (pure), Python (Rust-backed), and JavaScript verifier paths all use
the identical constant set.

---

## Consequences

### Positive
- External verifiers have a fully-specified, stable parameter set to implement against.
- A future Poseidon2 migration is a clean opt-in, not a breaking change.
- Proof bundles self-declare their hash suite — 3-year-old proofs remain verifiable.

### Negative
- We are locked to this parameter set for all existing proofs. This is intentional.

### Neutral
- No code changes required for existing functionality — this ADR documents
  what is already implemented.

---

## Test Vectors

The following test vectors MUST pass for any implementation claiming to implement
`poseidon-bn254-v1`. They are also pinned in `tests/test_poseidon_module.py`
and `tests/test_poseidon_parameter_parity.py`.

```text
# Poseidon(0, 0) — the zero-input base case
input:  a=0, b=0
output: (see tests/test_poseidon_module.py::test_poseidon_hash_zero_inputs)

# Domain-separated leaf hash
input:  key=1, value=2
output: (see tests/test_poseidon_module.py::test_poseidon_leaf_hash_known_value)

# Domain-separated node hash
input:  left=1, right=2
output: (see tests/test_poseidon_module.py::test_poseidon_node_hash_known_value)
```

Additional Poseidon BN254 vectors are generated from the repository source at
`proofs/test_inputs/poseidon_vectors.js`. For implementers, the authoritative
in-repo known-value checks are the pinned test cases in
`tests/test_poseidon_module.py` and `tests/test_poseidon_parameter_parity.py`.

---

## Migration Path (Future)

If Poseidon2 is ever adopted:

1. Introduce `poseidon2-bn254-v2` as a parallel suite alongside this one.
2. New circuits reference the new suite ID.
3. New proof bundles include `"hash_suite": "poseidon2-bn254-v2"`.
4. Old proofs with `"hash_suite": "poseidon-bn254-v1"` continue to verify
   against the v1 parameter set indefinitely.
5. Run a new Groth16 trusted setup ceremony for the v2 circuits.
6. Deprecate (but do not remove) v1 circuit artifacts after a transition period.

---

## References

- [Poseidon: A New Hash Function for Zero-Knowledge Proof Systems](https://eprint.iacr.org/2019/458.pdf)
- [circomlibjs poseidon_constants.json](https://github.com/iden3/circomlibjs/blob/main/src/poseidon_constants.json)
- [circom Poseidon template](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)
- ADR-0003: BLAKE3 domain-separated hashing (external/BLAKE3 hash suite)
- `protocol/poseidon.py` — Python bindings
- `protocol/poseidon_bn128.py` — Pure Python implementation
- `src/poseidon.rs` — Rust implementation
