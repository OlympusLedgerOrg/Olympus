pragma circom 2.0.0;

// Configurable circuit parameters (updated via proofs/proof_generator.py).
// Keep these defaults aligned with protocol docs and test inputs.
// Note: circom 2.x does not allow global var declarations; use functions instead.

function DOCUMENT_MERKLE_DEPTH() { return 20; }
function NON_EXISTENCE_MERKLE_DEPTH() { return 256; }
function REDACTION_MAX_LEAVES() { return 16; }
function REDACTION_MERKLE_DEPTH() { return 4; }
function UNIFIED_MAX_SECTIONS() { return 8; }
function UNIFIED_MERKLE_DEPTH() { return 20; }
function UNIFIED_SMT_DEPTH() { return 256; }
function SELECTIVE_DISCLOSURE_DEPTH() { return 20; }
function SELECTIVE_DISCLOSURE_K() { return 8; }
function SELECTIVE_DISCLOSURE_PREIMAGE_LEN() { return 6; }

