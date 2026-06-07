pragma circom 2.0.0;

// Configurable circuit parameters (updated via proofs/proof_generator.py).
// Keep these defaults aligned with protocol docs and test inputs.
// Note: circom 2.x does not allow global var declarations; use functions instead.

function DOCUMENT_MERKLE_DEPTH() { return 20; }
function NON_EXISTENCE_MERKLE_DEPTH() { return 256; }
function REDACTION_MAX_LEAVES() { return 16; }   // matches compiled circuit + Rust witness generator (redaction.rs MAX_LEAVES)
function REDACTION_MERKLE_DEPTH() { return 4; }  // matches compiled circuit + Rust witness generator (redaction.rs REDACTION_DEPTH)
// ADR-0024 hybrid ZK tile redaction: N = 2048 rasterized tiles folded into a
// depth-11 Poseidon Merkle root. Must match
// crate::zk::witness::tile_redaction {TILE_MAX_LEAVES, TILE_MERKLE_DEPTH}.
// 2^TILE_REDACTION_MERKLE_DEPTH must equal TILE_REDACTION_MAX_LEAVES (the
// circuit asserts this). ~2.0M R1CS (~0.98M flat fold + ~0.98M domain-3
// commitment chain + EdDSA) — power-21 class; the shared power-22 ptau covers it.
// NOTE: N=4096 (~3.9M) exceeds the circom-wasm 4 GiB compile limit
// (constraint-simplification OOM in CI); 2048 is ~half that. If CI shows it still
// OOMs, fall back to 1024 (depth 10, ~1.0M R1CS, known to compile).
function TILE_REDACTION_MAX_LEAVES() { return 2048; }
function TILE_REDACTION_MERKLE_DEPTH() { return 11; }
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
