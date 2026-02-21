# Zero-Knowledge Proofs for Olympus

This directory contains the zero-knowledge proof circuits used in Olympus.

## Quick Start

```bash
# 1. Install npm dependencies (circomlib, snarkjs)
cd proofs/
npm install

# 2. Download PTAU, compile circuits, generate dev verification keys
#    Requires: circom compiler in PATH
bash setup_circuits.sh

# 3. Smoke test — prove and verify one example of each circuit
bash smoke_test.sh
```

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

## Directory Layout

```
proofs/
├── circuits/
│   ├── lib/
│   │   ├── poseidon.circom       # Re-exports Poseidon from circomlib
│   │   └── merkleProof.circom    # Shared MerkleProof(depth) template
│   ├── document_existence.circom
│   ├── redaction_validity.circom
│   ├── non_existence.circom
│   ├── inclusion.circom          # Legacy reference
│   └── redaction_v1.circom       # Legacy reference
├── keys/
│   └── verification_keys/        # Exported vkey JSON files
├── test_inputs/
│   └── generate_inputs.js        # Generates valid Poseidon Merkle inputs
├── build/                        # Compiled artifacts (git-ignored)
├── setup_circuits.sh             # PTAU download + compilation + key gen
├── smoke_test.sh                 # End-to-end prove + verify
└── package.json                  # npm dependencies
```

## Scripts

### `setup_circuits.sh`

Downloads the Hermez Powers of Tau file (2^17), compiles all three main
circuits with `circom`, runs Groth16 trusted setup with a single dev
contribution, and exports verification keys to `keys/verification_keys/`.
Falls back to generating the PTAU locally if the download is unavailable.

### `smoke_test.sh`

Generates valid test inputs via `test_inputs/generate_inputs.js`, then for
each circuit: generates the witness, creates a Groth16 proof, and verifies it.

### `test_inputs/generate_inputs.js`

Node.js script that builds Poseidon Merkle trees using circomlibjs and writes
the corresponding JSON input files that circom's WASM witness generators
expect.

## Building Circuits Manually

```bash
# Compile (example: document existence)
circom proofs/circuits/document_existence.circom --r1cs --wasm --sym \
  -l proofs/node_modules -o proofs/build

# Groth16 setup
npx snarkjs groth16 setup proofs/build/document_existence.r1cs \
  proofs/keys/powersOfTau28_hez_final_15.ptau \
  proofs/build/document_existence_0000.zkey

npx snarkjs zkey contribute proofs/build/document_existence_0000.zkey \
  proofs/build/document_existence_final.zkey \
  --name="Dev contribution"

npx snarkjs zkey export verificationkey \
  proofs/build/document_existence_final.zkey \
  proofs/keys/verification_keys/document_existence_vkey.json
```

## Hash boundary

- Circuits use **Poseidon** for in-circuit hashing (see `proofs/circuits/lib/poseidon.circom`).
- Python/ledger code uses **BLAKE3** (see `protocol/hashes.py`).
- Witness generation must translate BLAKE3 leaf commitments into Poseidon field elements before proving.

## Security Considerations

- These circuits are **reference implementations** for protocol specification.
- Development keys use a single contribution and are NOT suitable for production.
- Production use requires:
  - Formal verification
  - Security audit
  - Phase 2 ceremony with at least 3 independent contributors
  - Verification keys published publicly with ceremony transcript
  - Parameter tuning for performance
  
## References

- [circom Documentation](https://docs.circom.io/)
- [snarkjs Documentation](https://github.com/iden3/snarkjs)
- Olympus Protocol Specification: `../docs/05_zk_redaction.md`
