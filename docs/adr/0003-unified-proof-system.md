# ADR 0003: Unified Proof System for Canonicalization + Inclusion + Root + Signatures

## Status
Accepted

## Context

Olympus requires cryptographic guarantees about three critical properties verified in-circuit:
1. **Document canonicalization** - Documents are properly normalized before hashing
2. **Merkle inclusion** - Documents are included in the ledger Merkle tree
3. **Ledger root commitment** - The Merkle root is committed in a signed checkpoint

Additionally, checkpoint integrity (component 4) is verified at the Python layer via federation signatures:
4. **Federation quorum certificate** - The checkpoint has valid Ed25519 signatures from federation nodes

Previously, these verifications were performed separately, requiring multiple proof artifacts and verification steps. This increased complexity for verifiers and created opportunities for integration errors.

**Design rationale**: Checkpoint integrity uses BLAKE3 hashing and Ed25519 signatures, which cannot be efficiently verified in BN128 circuits. The circuit proves the ledger root commitment; the Python layer proves the checkpoint quorum certificate.

## Decision

We implement a **unified proof system** that verifies three components in-circuit and one at the Python layer:

**In-circuit (ZK proof)**:
1. Canonicalization (Poseidon hash over document sections)
2. Merkle Inclusion (in ledger tree)
3. Ledger Root (SMT commitment in checkpoint)

**Python layer**:
4. Federation Signatures (Ed25519 quorum certificate)

This design provides modular backend support for the ZK components:

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Unified Proof System                       │
├──────────────────────────────────────────────────────────────┤
│  Components:                                                  │
│  1. Canonicalization (Poseidon hash over document sections)  │
│  2. Merkle Inclusion (in ledger tree)                        │
│  3. Ledger Root (SMT commitment in checkpoint)               │
│  4. Federation Signatures (Ed25519 quorum certificate)       │
└──────────────────────────────────────────────────────────────┘
          │                                    │
          ├─── Groth16 Backend ───────────────┤
          │    (Primary - Optimized)           │
          │    • High throughput               │
          │    • Low latency                   │
          │    • Requires trusted setup        │
          │                                    │
          └─── Halo2 Backend ─────────────────┘
               (Optional - High Assurance)
               • No trusted setup
               • Recursive composition
               • Larger proofs
```

### Circuit Design

**Circuit**: `unified_canonicalization_inclusion_root_sign.circom`

**Public Inputs** (3 in-circuit):
- `canonicalHash`: Poseidon hash of canonicalized document sections
- `merkleRoot`: Root of ledger Merkle tree
- `ledgerRoot`: SMT root from checkpoint

**Private Inputs**:
- Document sections (canonicalized)
- Merkle inclusion proof path and indices
- SMT proof path and indices
- Leaf position in tree

**Key Design Choices**:
1. **Poseidon for circuit hashing** - Arithmetic-friendly for BN128 field
2. **BLAKE3 for ledger layer** - Post-quantum candidate, efficient
3. **Federation signatures at Python layer** - Ed25519 verification is expensive in circuits; BLAKE3-hashed checkpoints cannot be efficiently verified in BN128
4. **Modular proof boundary** - Allows Groth16 ↔ Halo2 swap without protocol changes

### Python Integration

**Module**: `protocol/unified_proof.py`

**Key Classes**:
- `UnifiedProof` - Container for ZK proof + checkpoint + signatures
- `UnifiedProofVerifier` - Verifies all components (3 in circuit, 1 in Python)
- `UnifiedPublicInputs` - Public circuit inputs (3 values)
- `ProofBackend` - Enum for Groth16 vs Halo2 selection

**Verification Flow**:
```python
verifier = UnifiedProofVerifier(registry=federation_registry)
result = verifier.verify(proof)

if result.is_valid:
    # All components verified:
    # ✓ Canonicalization (circuit)
    # ✓ Merkle inclusion (circuit)
    # ✓ Ledger root (circuit)
    # ✓ Federation quorum (Python layer)
```

### Witness Generation

**Script**: `proofs/test_inputs/generate_unified_inputs.js`

Generates circuit inputs from:
- Canonicalized document sections
- Merkle proof (from ledger)
- SMT proof (from checkpoint)

Note: Checkpoint hash verification is performed at the Python layer.

### Halo2 Backend (Phase 1+)

**Module**: `protocol/halo2_backend.py`

Provides placeholder interface for future Halo2 implementation:
- `Halo2Proof` - Container for Halo2 proof artifacts
- `Halo2Verifier` - Verification interface (raises NotImplementedError)
- `Halo2Prover` - Proving interface (raises NotImplementedError)
- `Halo2Backend` - Protocol-compliant backend implementing `ProofBackendProtocol`

Halo2 circuits will mirror the Groth16 structure with identical public inputs, ensuring protocol compatibility.

### Proof System Interface (Protocol Boundary)

**Module**: `protocol/proof_interface.py`

Defines the strict contract that all proof backends must implement:

```python
class ProofBackendProtocol(Protocol):
    def generate(self, statement: Statement, witness: Witness) -> Proof:
        """Generate a cryptographic proof."""
        ...

    def verify(self, statement: Statement, proof: Proof) -> bool:
        """Verify a cryptographic proof."""
        ...

    @property
    def proof_system_type(self) -> ProofSystemType:
        """Return the proof system type."""
        ...

    def is_available(self) -> bool:
        """Check if backend is available."""
        ...
```

**Key Data Structures**:
- `Statement` - Public statement (circuit + public inputs)
- `Witness` - Private witness (private inputs + auxiliary data)
- `Proof` - Cryptographic proof artifact
- `ProofSystemType` - Enum (GROTH16, HALO2, PLONKY2, STARK)

**Benefits of Interface**:
1. Protocol layer never touches proving system directly
2. Future backends (Plonky2, STARKs) can be added without protocol changes
3. Clear audit boundary for cryptographic modularity
4. Dependency injection for testing

### Groth16 Backend

**Module**: `protocol/groth16_backend.py`

Implements `ProofBackendProtocol` for Groth16 proofs using snarkjs:
- `Groth16Backend` - Protocol-compliant backend class
- High throughput, low latency
- Requires trusted setup (mitigated by ceremony)

## Alternatives Considered

### 1. Separate Proofs for Each Component
**Rejected**: Increases complexity and verification cost. Each proof requires separate setup, generation, and verification.

### 2. Include Federation Signatures in Circuit
**Rejected**: Ed25519 signature verification is circuit-expensive (>100K constraints per signature). For 2/3 quorum of N=10 nodes, this would be ~700K constraints.

### 3. BLAKE3 in Circuit
**Rejected**: BLAKE3 is not arithmetic-friendly. Converting BLAKE3 operations to field arithmetic would require massive constraint systems.

### 4. Groth16-Only (No Halo2 Option)
**Rejected**: Trusted setup risk is mitigated but not eliminated. High-assurance contexts (key compromise recovery, regulatory compliance) may require trustless proofs.

### 5. Halo2-Only
**Rejected**: Significant performance regression (~10-100x slower) and larger proofs (~500KB vs 200 bytes) would impact ledger throughput.

## Consequences

### Benefits

1. **Single Verification Point**: Verifiers check one proof instead of four separate artifacts
2. **Cryptographic Binding**: All four components are cryptographically linked in the circuit
3. **Reduced Attack Surface**: Fewer integration points = fewer opportunities for errors
4. **Modular Backend**: Can swap Groth16 ↔ Halo2 without protocol changes
5. **Performance**: Groth16 backend maintains high throughput for standard operations
6. **Trustless Option**: Halo2 backend available for high-assurance contexts

### Costs

1. **Circuit Complexity**: Larger circuit combining multiple verification steps
2. **Trusted Setup**: Groth16 requires multi-party ceremony (mitigated by transparent process)
3. **Development Overhead**: Must maintain two backend implementations
4. **Circuit Versioning**: Circuit updates require new trusted setup (Groth16) or params generation (Halo2)

### Operational Considerations

1. **Groth16 Trusted Setup**:
   - Requires transparent multi-party Phase 2 ceremony
   - Ceremony transcript must be publicly auditable
   - Setup is circuit-specific (must repeat for circuit updates)

2. **Circuit Updates**:
   - Any circuit change requires new setup
   - Version all circuits and keys
   - Maintain backward compatibility for historical proofs

3. **Halo2 Integration** (Phase 1+):
   - Rust implementation required (circom doesn't support Halo2)
   - Python bindings via py-halo2 or FFI
   - Separate verifier infrastructure

4. **Proof Size Tradeoffs**:
   - Groth16: ~200 bytes (constant)
   - Halo2: ~100-500 KB (depends on circuit size)
   - Storage and bandwidth implications for Halo2

### Security Considerations

1. **Trusted Setup Risk (Groth16)**:
   - If all ceremony participants collude, fake proofs possible
   - Mitigated by transparent multi-party ceremony
   - Halo2 backend eliminates this risk entirely

2. **Circuit Bugs**:
   - Soundness bugs could allow invalid proofs
   - Extensive testing and formal verification recommended
   - Circuit versioning allows fixing bugs without breaking old proofs

3. **Federation Signature Verification**:
   - Happens outside circuit at Python layer
   - Uses standard Ed25519 (well-audited)
   - Quorum threshold enforces Byzantine fault tolerance

4. **Hash Function Boundaries**:
   - Poseidon (circuit) and BLAKE3 (ledger) are domain-separated
   - No hash function composition required
   - Dual-root strategy avoids complex bridging circuits

### Testing Strategy

1. **Unit Tests**: Test each component independently
2. **Integration Tests**: Test full verification flow
3. **Circuit Tests**: Verify constraint satisfaction
4. **Conformance Tests**: Test vectors for cross-implementation validation
5. **Property Tests**: Fuzzing and hypothesis testing

## Implementation Status

- ✅ Circuit design (`unified_canonicalization_inclusion_root_sign.circom`)
- ✅ Python verification layer (`protocol/unified_proof.py`)
- ✅ Witness generation script (`proofs/test_inputs/generate_unified_inputs.js`)
- ✅ Halo2 placeholder (`protocol/halo2_backend.py`)
- ✅ Comprehensive tests (`tests/test_unified_proof.py`)
- ⏳ Circuit compilation and setup (requires setup_circuits.sh update)
- ⏳ Groth16 trusted setup ceremony (Phase 1+)
- ⏳ Halo2 implementation (Phase 1+)

## References

- ADR 0002: Zero-Knowledge Proof System Selection (Groth16 vs Halo2)
- `docs/05_zk_redaction.md`: Redaction proof design
- `docs/14_federation_protocol.md`: Federation signature protocol
- `protocol/redaction_ledger.py`: Dual-anchor proof strategy
- Groth16 paper: https://eprint.iacr.org/2016/260
- Halo2 book: https://zcash.github.io/halo2/
