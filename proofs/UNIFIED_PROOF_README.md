# Unified Proof System

This directory contains the implementation of Olympus's unified proof system, which cryptographically verifies three critical properties in a single proof:

1. **Document Canonicalization** - Proves document sections are properly normalized
2. **Merkle Inclusion** - Proves document is in the ledger Merkle tree
3. **Ledger Root Commitment** - Proves Merkle root is in a signed checkpoint

**Checkpoint integrity (federation signatures) is verified in the Rust layer** (`src-tauri/src/federation/`, `src-tauri/src/quorum/`), not in-circuit. Checkpoints are BLAKE3-hashed, federation-signed structs that cannot be efficiently verified in BN128 circuits.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   Document Submission                        │
│  (Government record, canonicalized by C-Pipe)               │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│         Component 1: Canonicalization Verification          │
│  Structured metadata commitment:                            │
│  DomainPoseidon(3) chain over sectionCount, sectionLengths, │
│  and sectionHashes (BLAKE3 hashes)                          │
│  Public input: canonicalHash                                │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│         Component 2: Merkle Inclusion Proof                 │
│  Proves canonical hash is in ledger tree                    │
│  Public input: merkleRoot                                   │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│         Component 3: Ledger Root Commitment                 │
│  Proves Merkle root is in SMT checkpoint at ledgerKey       │
│  Public inputs: ledgerRoot, ledgerKeyHash                   │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│         Component 4: Federation Signatures                  │
│  (Verified in the Rust layer, not in circuit)               │
│  Verifies Ed25519 quorum certificate over checkpoint        │
│  Note: BLAKE3-hashed checkpoints cannot be verified in BN128│
└─────────────────────────────────────────────────────────────┘
                  │
                  ▼
            VERIFIED ✓
```

## Files

### Circuits

- **`circuits/unified_canonicalization_inclusion_root_sign.circom`**
  - Main circuit combining canonicalization, inclusion, and root commitment
  - Uses domain-separated Poseidon for structured canonicalization
  - Public inputs: canonicalHash (structured metadata commitment), merkleRoot, ledgerRoot, treeSize, ledgerKeyHash
  - Parametric: maxSections, merkleDepth, smtDepth (defaults in `circuits/parameters.circom`)
  - canonicalHash is computed as DomainPoseidon(3) chain over: sectionCount → sectionLengths[0..N] → sectionHashes[0..N]
  - **Note**: Checkpoint integrity is verified in the Rust layer via federation signatures

### Rust Modules

- **`src-tauri/src/zk/`** — witness construction (`witness/unified.rs`),
  proving (`prove.rs`, via the sealed `prove_circom` entry point), and
  verification (Groth16 over arkworks)
- **`src-tauri/src/api/zk.rs`** — `/zk/prove` and `/zk/verify` HTTP endpoints
- **`src-tauri/src/federation/` / `src-tauri/src/quorum/`** — checkpoint
  signature and quorum verification (outside the circuit)

### Witness Generation

- **`proofs/test_inputs/generate_unified_inputs.js`**
  - Generates circuit inputs from document + proofs
  - Requires circomlibjs for Poseidon hashing
  - Example usage included for testing

### Tests

- **`src-tauri/tests/zk_prove_unified.rs`** and the witness validators in
  `src-tauri/src/zk/witness/unified.rs` — proving round-trips, witness
  validation, and adversarial soundness (see also `tests/zk_soundness.rs`,
  features `prover,zk-test-utils`)

## Usage

### Verification (HTTP API)

Submit the proof bundle to the embedded Axum server:

```bash
curl -X POST http://127.0.0.1:3737/zk/verify \
  -H "x-api-key: $OLYMPUS_API_KEY" \
  -H "content-type: application/json" \
  -d @proof_bundle.json
```

For offline verification without a running node, use the cross-language
reference verifiers in `verifiers/rust` and `verifiers/javascript`.

### Witness Generation (JavaScript)

```javascript
const { generateUnifiedInputs } = require('./generate_unified_inputs');

const inputs = await generateUnifiedInputs({
    documentSections: ["section1", "section2", "section3"],
    sectionCount: 3,
    merkleRoot: "12345...",
    merklePath: [...merklePathElements],
    merkleIndices: [...merklePathIndices],
    leafIndex: 0,
    treeSize: 1,
    ledgerRoot: "67890...",
    ledgerPathElements: [...smtPathElements],
    ledgerKey: [...smtLookupKeyBytes],
});

// Use inputs for witness generation
```

## Proof Backends

### Groth16 (Primary)

**Advantages:**
- High throughput (~ms proving time)
- Small proofs (~200 bytes)
- Fast verification (~ms)
- Well-established and audited

**Disadvantages:**
- Requires trusted setup ceremony
- Setup is circuit-specific

**When to use:** Default for all standard operations

### Halo2 (Optional - Phase 1+)

**Advantages:**
- No trusted setup required
- Supports recursive composition
- Transparent and deterministic

**Disadvantages:**
- Slower proving (~100x vs Groth16)
- Larger proofs (~100-500 KB)
- Less mature tooling

**When to use:** High-assurance contexts (key compromise recovery, regulatory compliance)

## Security Model

### Threat Model

The unified proof protects against:
1. **Document tampering** - Canonicalization ensures normalized form
2. **Ledger forgery** - Merkle inclusion proves presence in ledger
3. **Checkpoint manipulation** - The signed root is accepted or rejected by the Rust federation/checkpoint layer under its quorum and signature assumptions
4. **Split-view attacks** - Federation quorum prevents presenting different histories (verified in the Rust layer)

### Trust Assumptions

**Groth16 Backend:**
- At least one participant in trusted setup must be honest
- Circuit must be sound (no constraint bugs)
- Hash functions (Poseidon, BLAKE3) are collision-resistant

**Halo2 Backend:**
- No trusted setup required
- Circuit must be sound
- Hash functions are collision-resistant

**Federation Layer:**
- At most f < N/3 Byzantine nodes (2/3 quorum)
- Ed25519 signature security
- Network adversary cannot partition >1/3 of nodes

### Hash Function Boundaries

The system uses two hash functions with clear domain separation:

1. **Poseidon (in-circuit)**
   - Used for: Structured document canonicalization (metadata commitment via DomainPoseidon(3)), Merkle trees inside ZK proof
   - Reason: Arithmetic-friendly for BN128 field
   - Domain: ZK circuit constraints
   - canonicalHash binds sectionCount, sectionLengths[], and sectionHashes[] (BLAKE3 hashes as field elements)

2. **BLAKE3 (ledger layer)**
   - Used for: Ledger entries, SMT nodes, checkpoint hashing (verified in the Rust layer)
   - Reason: Fast, collision-resistant, post-quantum candidate
   - Domain: Rust ledger layer (`crates/olympus-crypto`, `src-tauri`)

No hash function composition is required; the Poseidon root is simply stored as a value in the BLAKE3-based SMT. Checkpoint integrity is verified via Ed25519 federation signatures in the Rust layer, not in-circuit.

## Development

### Running Tests

```bash
# Run unified proof tests (witness validators + proving round-trips)
cargo test -p olympus-desktop --features prover unified

# Adversarial verifier soundness suite
cargo test -p olympus-desktop --features prover,zk-test-utils --test zk_soundness
```

### Circuit Compilation

```bash
# Compile circuit (requires circom + snarkjs)
cd proofs
circom circuits/unified_canonicalization_inclusion_root_sign.circom \
    --r1cs --wasm --sym -o build/

# Generate witness
node build/unified_canonicalization_inclusion_root_sign_js/generate_witness.js \
    build/unified_canonicalization_inclusion_root_sign_js/unified_canonicalization_inclusion_root_sign.wasm \
    test_inputs/unified_input.json \
    build/witness.wtns

# Generate proof (requires setup artifacts)
npx snarkjs groth16 prove \
    build/unified_canonicalization_inclusion_root_sign_final.zkey \
    build/witness.wtns \
    build/proof.json \
    build/public.json

# Verify proof
npx snarkjs groth16 verify \
    keys/verification_keys/unified_canonicalization_inclusion_root_sign_vkey.json \
    build/public.json \
    build/proof.json
```

### Adding to Existing Setup

The unified circuit is already part of the active setup pipeline:

```bash
CIRCUITS=(
    "document_existence"
    "non_existence"
    "unified_canonicalization_inclusion_root_sign"
    "federation_quorum"
)
```

## Future Work

### Phase 1+ Enhancements

1. **Halo2 Implementation**
   - Rust circuit mirroring Groth16 design
   - Performance benchmarking

2. **Recursive Composition**
   - Batch verification of multiple proofs
   - Aggregate checkpoints from multiple shards

3. **Circuit Optimizations**
   - Custom gates for common operations
   - Lookup tables for hash operations
   - Reduced constraint count

4. **Formal Verification**
   - Mechanized proof of circuit soundness
   - Security property verification
   - Boundary condition checks

## References

- **ADR-0009**: Poseidon hash suite (`docs/adr/ADR-0009-poseidon-hash-suite.md`)
- **docs/federation.md**: Federation protocol and checkpoint signatures
- **Groth16 Paper**: https://eprint.iacr.org/2016/260
- **Halo2 Book**: https://zcash.github.io/halo2/
- **Poseidon Hash**: https://eprint.iacr.org/2019/458

## Contact

For questions about the unified proof system, see:
- Protocol documentation in `docs/`
- Code implementation in `src-tauri/src/zk/`
- Test examples in `src-tauri/tests/`
