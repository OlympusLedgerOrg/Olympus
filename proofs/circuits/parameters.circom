pragma circom 2.0.0;

// Configurable circuit parameters (updated via proofs/proof_generator.py).
// Keep these defaults aligned with protocol docs and test inputs.

var DOCUMENT_MERKLE_DEPTH = 20;
var NON_EXISTENCE_MERKLE_DEPTH = 256;  // 256 for 32-byte key sparse Merkle tree
var REDACTION_MAX_LEAVES = 16;
var REDACTION_MERKLE_DEPTH = 4;
var UNIFIED_MAX_SECTIONS = 8;
var UNIFIED_MERKLE_DEPTH = 20;
var UNIFIED_SMT_DEPTH = 256;
var SELECTIVE_DISCLOSURE_DEPTH = 20;
var SELECTIVE_DISCLOSURE_K = 8;
var SELECTIVE_DISCLOSURE_PREIMAGE_LEN = 6;
