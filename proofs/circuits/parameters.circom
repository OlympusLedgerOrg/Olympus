pragma circom 2.0.0;

// Configurable circuit parameters (updated via proofs/proof_generator.py).
// Keep these defaults aligned with protocol docs and test inputs.
// Note: circom 2.x does not allow global var declarations; use functions instead.

function DOCUMENT_MERKLE_DEPTH() { return 20; }
function NON_EXISTENCE_MERKLE_DEPTH() { return 256; }
function REDACTION_MAX_LEAVES() { return 16; }   // matches compiled circuit + Rust witness generator (redaction.rs MAX_LEAVES)
function REDACTION_MERKLE_DEPTH() { return 4; }  // matches compiled circuit + Rust witness generator (redaction.rs REDACTION_DEPTH)
// ADR-0024 hybrid ZK tile redaction: N = 512 rasterized tiles folded into a
// depth-9 Poseidon Merkle root. Must match
// crate::zk::witness::tile_redaction {TILE_MAX_LEAVES, TILE_MERKLE_DEPTH}.
// 2^TILE_REDACTION_MERKLE_DEPTH must equal TILE_REDACTION_MAX_LEAVES (the
// circuit asserts this). Measured ~1.1M R1CS — fits the power-22 ptau (snarkjs
// Groth16 setup needs 2^power >= 2*constraints). NOTE: real circom counts ran
// ~2x the initial estimate — N=2048 measured 4.25M constraints (needs power-24),
// N=1024 needs power-23. 512 is the largest grid that fits the power-22 ceremony.
function TILE_REDACTION_MAX_LEAVES() { return 512; }
function TILE_REDACTION_MERKLE_DEPTH() { return 9; }
function UNIFIED_MAX_SECTIONS() { return 8; }
function UNIFIED_MERKLE_DEPTH() { return 20; }
function UNIFIED_SMT_DEPTH() { return 256; }
// Federation M-of-N quorum: maximum signer-set size N the circuit supports.
// Must match `crate::quorum::FEDERATION_QUORUM_N` (Rust witness). Larger N
// raises the constraint count linearly (one EdDSAPoseidonVerifier per slot).
function FEDERATION_QUORUM_N() { return 8; }
function SELECTIVE_DISCLOSURE_DEPTH() { return 20; }
function SELECTIVE_DISCLOSURE_K() { return 8; }
function SELECTIVE_DISCLOSURE_PREIMAGE_LEN() { return 6; }
