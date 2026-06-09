pragma circom 2.0.0;

// Configurable circuit parameters (updated via proofs/proof_generator.py).
// Keep these defaults aligned with protocol docs and test inputs.
// Note: circom 2.x does not allow global var declarations; use functions instead.

function DOCUMENT_MERKLE_DEPTH() { return 20; }
function NON_EXISTENCE_MERKLE_DEPTH() { return 256; }
// ADR-0025 PDF object-level redaction: one leaf per indirect PDF object
// (was 16 length-proportional raw-byte chunks). 2^depth must equal maxLeaves.
// The redaction_validity circuit now uses a FLAT FOLD (recompute the root once
// from all leaves) instead of per-leaf Merkle inclusion, which is what makes
// N=1024 fit a practical ceremony (~1M constraints vs ~5.4M for per-leaf
// inclusion). The public-signal surface is unchanged; the redaction vkey must
// be regenerated (rerun setup_circuits.sh) + a fresh Phase-2 contribution made
// before v1.0. The other circuits are unaffected. `depth` is still used for the
// fold height and the revealedCount range check (depth+1 bits).
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
