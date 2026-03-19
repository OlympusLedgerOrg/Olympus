# Unified Proof System

This directory contains the implementation of Olympus's unified proof system, which cryptographically verifies three critical properties in a single proof:

1. **Document Canonicalization** - Proves document sections are properly normalized
2. **Merkle Inclusion** - Proves document is in the ledger Merkle tree
3. **Ledger Root Commitment** - Proves Merkle root is in a signed checkpoint

**Checkpoint integrity (federation signatures) is verified at the Python layer**, not in-circuit. Python checkpoints are BLAKE3-hashed, federation-signed structs that cannot be efficiently verified in BN128 circuits.

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
│  Proves Merkle root is in SMT checkpoint                    │
│  Public input: ledgerRoot                                   │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│         Component 4: Federation Signatures                  │
│  (Verified at Python layer, not in circuit)                 │
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
  - Public inputs: canonicalHash (structured metadata commitment), merkleRoot, ledgerRoot, treeSize
  - Parametric: maxSections, merkleDepth, smtDepth (defaults in `circuits/parameters.circom`)
  - canonicalHash is computed as DomainPoseidon(3) chain over: sectionCount → sectionLengths[0..N] → sectionHashes[0..N]
  - **Note**: Checkpoint integrity is verified at the Python layer via federation signatures

### Python Modules

- **`protocol/unified_proof.py`**
  - `UnifiedProof` - Container for proof artifacts
  - `UnifiedProofVerifier` - Verifies all components
  - `UnifiedPublicInputs` - Public circuit inputs
  - `ProofBackend` - Enum for Groth16/Halo2 selection

- **`protocol/halo2_backend.py`**
  - Placeholder for optional Halo2 implementation
  - Provides interface compatibility for future Phase 1+ work
  - Currently raises NotImplementedError

### Witness Generation

- **`proofs/test_inputs/generate_unified_inputs.js`**
  - Generates circuit inputs from document + proofs
  - Requires circomlibjs for Poseidon hashing
  - Example usage included for testing

### Tests

- **`tests/test_unified_proof.py`**
  - Unit tests for data structures
  - Verification flow tests
  - Backend selection tests
  - Integration scenarios

### Documentation

- **`docs/adr/0003-unified-proof-system.md`**
  - Architecture Decision Record
  - Design rationale and alternatives
  - Security considerations
  - Implementation status

## Usage

### Verification (Python)

```python
from protocol.unified_proof import (
    UnifiedProof,
    UnifiedProofVerifier,
    verify_unified_proof,
)
from protocol.federation import FederationRegistry

# Load proof artifact
proof = UnifiedProof.from_dict(proof_data)

# Verify with federation registry
registry = FederationRegistry(nodes=federation_nodes, epoch=1)
result = verify_unified_proof(proof, registry=registry)

if result.is_valid:
    print("✓ All four components verified")
else:
    print(f"✗ Verification failed: {result.value}")
```

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
    ledgerRoot: "67890...",
    ledgerPathElements: [...smtPathElements],
    ledgerPathIndices: [...smtPathIndices],
    checkpointHash: "11111...",
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
3. **Checkpoint manipulation** - Ledger root binding prevents fake checkpoints (verified in circuit)
4. **Split-view attacks** - Federation quorum prevents presenting different histories (verified in Python layer)

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
   - Used for: Ledger entries, SMT nodes, checkpoint hashing (verified at Python layer)
   - Reason: Fast, collision-resistant, post-quantum candidate
   - Domain: Python protocol layer

No hash function composition is required; the Poseidon root is simply stored as a value in the BLAKE3-based SMT. Checkpoint integrity is verified via Ed25519 federation signatures at the Python layer, not in-circuit.

## Development

### Running Tests

```bash
# Run unified proof tests
python -m pytest tests/test_unified_proof.py -v

# Run all proof tests
python -m pytest tests/ -k "proof" -v
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

To integrate unified proofs into existing `setup_circuits.sh`:

```bash
# Add to CIRCUITS array
CIRCUITS=(
    "document_existence"
    "non_existence"
    "redaction_validity"
    "unified_canonicalization_inclusion_root_sign"  # Add this
)
```

## Future Work

### Phase 1+ Enhancements

1. **Halo2 Implementation**
   - Rust circuit mirroring Groth16 design
   - Python bindings (py-halo2 or FFI)
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

- **ADR 0002**: Zero-Knowledge Proof System Selection
- **ADR 0003**: Unified Proof System Architecture
- **docs/05_zk_redaction.md**: Redaction proof design
- **docs/14_federation_protocol.md**: Federation signatures
- **Groth16 Paper**: https://eprint.iacr.org/2016/260
- **Halo2 Book**: https://zcash.github.io/halo2/
- **Poseidon Hash**: https://eprint.iacr.org/2019/458

## Contact

For questions about the unified proof system, see:
- Protocol documentation in `docs/`
- Code implementation in `protocol/`
- Test examples in `tests/`
