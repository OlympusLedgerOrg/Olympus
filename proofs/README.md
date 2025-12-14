# Zero-Knowledge Proofs for Olympus

This directory contains the zero-knowledge proof circuits used in Olympus.

## Circuits

### `inclusion.circom`

A Merkle tree inclusion proof circuit. Proves that a leaf exists in a Merkle tree
with a given root without revealing the leaf's position.

**Parameters:**
- `levels`: Depth of the Merkle tree (default: 20)

**Public Inputs:**
- `root`: The Merkle root to verify against

**Private Inputs:**
- `leaf`: The leaf value to prove inclusion of
- `pathElements`: Sibling hashes along the path to root
- `pathIndices`: 0/1 values indicating left/right positions

### `redaction_v1.circom`

A redaction proof circuit. Proves that a redacted document is a valid subset
of an original committed document.

**Parameters:**
- `maxLeaves`: Maximum number of leaves in the document tree
- `treeDepth`: Depth of the Merkle tree

**Public Inputs:**
- `originalRoot`: Root hash of the original document
- `revealedRoot`: Root hash of the revealed (non-redacted) portions

**Private Inputs:**
- `originalLeaves`: All leaf values from original document
- `revealMask`: Binary mask indicating which leaves are revealed
- `pathElements`: Merkle proof elements for each leaf
- `pathIndices`: Merkle proof path indices for each leaf

## Building Circuits

To compile these circuits, you need:
- [circom](https://docs.circom.io/) compiler
- [snarkjs](https://github.com/iden3/snarkjs) for proof generation

```bash
# Install dependencies
npm install circomlib

# Compile circuit
circom inclusion.circom --r1cs --wasm --sym

# Generate proving and verification keys
snarkjs groth16 setup inclusion.r1cs pot12_final.ptau inclusion_0000.zkey
snarkjs zkey contribute inclusion_0000.zkey inclusion_final.zkey
snarkjs zkey export verificationkey inclusion_final.zkey verification_key.json
```

## Security Considerations

- These circuits are **reference implementations** for protocol specification
- Production use requires:
  - Formal verification
  - Security audit
  - Trusted setup ceremony
  - Parameter tuning for performance
  
## References

- [circom Documentation](https://docs.circom.io/)
- [snarkjs Documentation](https://github.com/iden3/snarkjs)
- Olympus Protocol Specification: `../docs/05_zk_redaction.md`
