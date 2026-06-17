pragma circom 2.0.0;

// Configurable circuit parameters (updated via proofs/proof_generator.py).
// Keep these defaults aligned with protocol docs and test inputs.
// Note: circom 2.x does not allow global var declarations; use functions instead.

function DOCUMENT_MERKLE_DEPTH() { return 20; }
function NON_EXISTENCE_MERKLE_DEPTH() { return 256; }
// (REDACTION_MAX_LEAVES / REDACTION_MERKLE_DEPTH removed with the Groth16
// redaction_validity circuit — ADR-0030 §4. Redaction is now a signed
// variable-depth Poseidon fold with no circuit / ceremony.)
function UNIFIED_MAX_SECTIONS() { return 8; }
function UNIFIED_MERKLE_DEPTH() { return 20; }
function UNIFIED_SMT_DEPTH() { return 256; }
// Federation M-of-N quorum: maximum signer-set size N the circuit supports.
// Must match `crate::quorum::FEDERATION_QUORUM_N` (Rust witness). Larger N
// raises the constraint count linearly (one EdDSAPoseidonVerifier per slot).
function FEDERATION_QUORUM_N() { return 8; }
// (SELECTIVE_DISCLOSURE_* params removed with the dead, never-compiled
// selective_disclosure_merkle.circom — audit F-4/F-8.)
