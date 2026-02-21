# Zero-Knowledge Proofs for Olympus

This directory contains the zero-knowledge proof circuits used in Olympus.

## Circuits

### `document_existence.circom`

Poseidon Merkle inclusion proof that exposes the leaf index as a public input.

### `redaction_validity.circom`

Validates that revealed leaves belong to the original Poseidon Merkle root and
that the redacted commitment only covers the revealed leaves.

### `non_existence.circom`

Sparse Merkle non-membership proof that constrains the queried leaf to zero.

### Legacy circuits

`inclusion.circom` and `redaction_v1.circom` remain as reference baselines.

## Building Circuits

To compile these circuits, you need:
- [circom](https://docs.circom.io/) compiler
- [snarkjs](https://github.com/iden3/snarkjs) for proof generation

Groth16 flow (per new requirement):

```bash
# Install dependencies
npm install circomlib snarkjs

# Compile circuits (example: document existence)
circom proofs/circuits/document_existence.circom --r1cs --wasm --sym -o proofs/build

# Trusted setup (Phase 1 only with Groth16)
snarkjs groth16 setup proofs/build/document_existence.r1cs proofs/keys/powersOfTau28_hez_final_08.ptau proofs/build/document_existence_0000.zkey
snarkjs zkey contribute proofs/build/document_existence_0000.zkey proofs/build/document_existence_final.zkey
snarkjs zkey export verificationkey proofs/build/document_existence_final.zkey proofs/keys/verification_keys/existence_vkey.json

# Prove
snarkjs groth16 prove proofs/build/document_existence_final.zkey proofs/build/document_existence.wtns proofs/build/document_existence_proof.json proofs/build/document_existence_public.json

# Verify
snarkjs groth16 verify proofs/keys/verification_keys/existence_vkey.json proofs/build/document_existence_public.json proofs/build/document_existence_proof.json
```

## Hash boundary

- Circuits use **Poseidon** for in-circuit hashing (see `proofs/circuits/lib/poseidon.circom`).
- Python/ledger code uses **BLAKE3** (see `protocol/hashes.py`).
- Witness generation must translate BLAKE3 leaf commitments into Poseidon field elements before proving.

## Security Considerations

- These circuits are **reference implementations** for protocol specification.
- Production use requires:
  - Formal verification
  - Security audit
  - Trusted setup ceremony (Groth16 Phase 1)
  - Parameter tuning for performance
  
## References

- [circom Documentation](https://docs.circom.io/)
- [snarkjs Documentation](https://github.com/iden3/snarkjs)
- Olympus Protocol Specification: `../docs/05_zk_redaction.md`
