pragma circom 2.0.0;

// Configurable circuit parameters (updated via proofs/proof_generator.py).
// Keep these defaults aligned with protocol docs and test inputs.
// Note: circom 2.x does not allow global var declarations; use functions instead.

function DOCUMENT_MERKLE_DEPTH() { return 20; }
function NON_EXISTENCE_MERKLE_DEPTH() { return 256; }
// ADR-0025 PDF object-level redaction: one leaf per indirect PDF object
// (was 16 length-proportional raw-byte chunks). 2^depth must equal maxLeaves.
// The redaction_validity circuit TEMPLATE and public-signal surface are
// unchanged; only these dimensions changed, so the redaction circuit's vkey
// must be regenerated (rerun setup_circuits.sh) and a fresh Phase-2
// contribution made before v1.0. The other circuits are unaffected.
// If `circom --inspect` reports N=1024 exceeds the power-20 ceremony
// (> 2^20 = 1,048,576 constraints), drop to 512 / depth 9 (and mirror the
// change in redaction.rs + pdf_objects.rs MAX_OBJECTS).
function REDACTION_MAX_LEAVES() { return 1024; }  // matches Rust witness generator (redaction.rs MAX_LEAVES)
function REDACTION_MERKLE_DEPTH() { return 10; }  // matches Rust witness generator (redaction.rs REDACTION_DEPTH)
// ADR-0024 hybrid ZK tile redaction — **REJECTED / PARKED** (see #1221 and
// ADR-0024 status). The `tile_redaction_validity` circuit stays on disk but is
// no longer built by setup_circuits.sh; these consts are retained so the parked
// circuit still parses. N=1024 / depth-10; 2^depth must equal maxLeaves.
function TILE_REDACTION_MAX_LEAVES() { return 1024; }
function TILE_REDACTION_MERKLE_DEPTH() { return 10; }
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
