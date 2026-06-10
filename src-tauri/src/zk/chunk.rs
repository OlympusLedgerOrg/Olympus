//! DEPRECATED — superseded by `pdf_objects.rs` (ADR-0025, PDF object-level
//! redaction commitment). Retained for backward compatibility with existing
//! sealed records that stored 16 raw-byte chunk hashes. No new code should call
//! these functions; the `redaction_validity` circuit is now sized for 1024
//! object leaves (depth 10), so a depth-4 16-chunk root produced here will not
//! verify against the current circuit.
//!
//! 16-chunk Poseidon tree for the `redaction_validity` circuit.
//!
//! Every committed file is split into 16 equal-sized chunks; each chunk is
//! BLAKE3-hashed, then promoted to a BN254 field element via
//! `blake3_hex_to_poseidon_leaf`.  Those 16 leaves form a depth-4 binary
//! Merkle tree using the same domain-1 Poseidon node hash the circuit uses.
//!
//! The 16-chunk root (`originalRoot`) is what becomes the ledger leaf:
//! the existence circuit proves it sits in the ledger Merkle tree, and the
//! redaction circuit proves the dropped-by-the-recipient file's 16 chunks
//! (with mask) regenerate it.  Sharing the same value across both circuits
//! is what makes the two proofs compose without an Ed25519 trust hop.
//!
//! The depth-4 Merkle paths are NOT stored on the record — they're cheap
//! to recompute from the 16 stored chunk hashes any time `/redaction/issue`
//! needs to build a witness, and the redaction witness checks them anyway.

use ark_bn254::Fr;
use olympus_crypto::poseidon::blake3_hex_to_poseidon_leaf;
use thiserror::Error;

use crate::zk::poseidon::{domain_node, PoseidonError};

/// Leaf/depth dimensions of the **legacy** 16-chunk tree. These are pinned to
/// 16/4 and intentionally decoupled from `witness::redaction::{MAX_LEAVES,
/// REDACTION_DEPTH}` (now 1024/10 for the ADR-0025 object scheme) so this
/// deprecated path keeps producing the historical 16-chunk commitments that
/// existing sealed records and the JS conformance fixture depend on.
pub const CHUNK_LEAVES: usize = 16;
const CHUNK_DEPTH: usize = 4;
// Local aliases keep the original body untouched below.
const MAX_LEAVES: usize = CHUNK_LEAVES;
const REDACTION_DEPTH: usize = CHUNK_DEPTH;

#[derive(Debug, Error)]
pub enum ChunkError {
    #[error("input bytes are empty")]
    EmptyInput,
    #[error("BLAKE3 → Fr conversion failed: {0}")]
    LeafConversion(String),
    #[error("Poseidon error: {0}")]
    Poseidon(#[from] PoseidonError),
}

/// 16 BLAKE3 hex chunk hashes paired with their Poseidon leaf values and
/// the depth-4 Merkle root over them.
pub struct ChunkTree {
    /// 16 BLAKE3 hex strings — one per chunk.  Persisted on the record.
    pub chunk_hashes_hex: Vec<String>,
    /// 16 Poseidon leaves.  Derived from `chunk_hashes_hex`.
    pub leaves: Vec<Fr>,
    /// Depth-4 Merkle root over the 16 leaves.  This is the ledger leaf.
    pub original_root: Fr,
}

/// BLAKE3-chunk `bytes` into exactly 16 equal-sized chunks.
///
/// The final chunk is right-padded with NULs if the byte length is not a
/// multiple of 16; this matters because the receiver-side audit path
/// reproduces the same padding when verifying revealed positions.
fn chunk_into_16(bytes: &[u8]) -> Vec<String> {
    let n = bytes.len();
    // ceil-divide so non-multiples-of-16 still produce 16 chunks; the last
    // chunk is shorter and gets zero-padded.
    let chunk_size = n.div_ceil(MAX_LEAVES).max(1);
    let mut out = Vec::with_capacity(MAX_LEAVES);
    for i in 0..MAX_LEAVES {
        let start = (i * chunk_size).min(n);
        let end = (start + chunk_size).min(n);
        let slice = &bytes[start..end];
        let mut buf = vec![0u8; chunk_size];
        buf[..slice.len()].copy_from_slice(slice);
        out.push(blake3::hash(&buf).to_hex().to_string());
    }
    out
}

/// Compute the depth-4 Merkle root over 16 leaves using domain-1 Poseidon
/// node hashing.  Layer 0 hashes (l[0], l[1]) → n[0], (l[2], l[3]) → n[1],
/// etc.  Layer 1 hashes the pairs of layer 0, and so on, four levels deep.
fn root_of_16(leaves: &[Fr]) -> Result<Fr, PoseidonError> {
    debug_assert_eq!(leaves.len(), MAX_LEAVES);
    let mut level: Vec<Fr> = leaves.to_vec();
    for _ in 0..REDACTION_DEPTH {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(domain_node(1, pair[0], pair[1])?);
        }
        level = next;
    }
    debug_assert_eq!(level.len(), 1);
    Ok(level[0])
}

/// Lift a single BLAKE3 hex chunk hash to its Poseidon Fr leaf value.
/// Used to rebuild leaves from the `chunk_hashes` JSONB column when
/// building a redaction witness.
pub fn chunk_hex_to_leaf(hex: &str) -> Result<Fr, ChunkError> {
    let leaf_biguint =
        blake3_hex_to_poseidon_leaf(hex).map_err(|e| ChunkError::LeafConversion(e.to_string()))?;
    let bytes_be = leaf_biguint.to_bytes_be();
    let mut padded = [0u8; 32];
    let off = 32 - bytes_be.len();
    padded[off..].copy_from_slice(&bytes_be);
    Ok(<Fr as ark_ff::PrimeField>::from_be_bytes_mod_order(&padded))
}

/// Compute all 16 leaves' depth-4 Merkle paths to the root.  Returns
/// `(path_elements[16][4], path_indices[16][4])` in the shape the
/// `RedactionWitness` expects.  Used by `/redaction/issue` to rebuild
/// the witness from the stored chunk hashes when generating a proof.
#[allow(clippy::type_complexity)] // (paths, indices) tuple is the wire shape; type alias adds noise
pub fn paths_for_chunk_tree(leaves: &[Fr]) -> Result<(Vec<Vec<Fr>>, Vec<Vec<u8>>), PoseidonError> {
    debug_assert_eq!(leaves.len(), MAX_LEAVES);

    // Pre-compute every level of the tree once; each leaf's path is just
    // a slice through the sibling at the right index per level.
    let mut levels: Vec<Vec<Fr>> = Vec::with_capacity(REDACTION_DEPTH + 1);
    levels.push(leaves.to_vec());
    for d in 0..REDACTION_DEPTH {
        let cur = &levels[d];
        let mut next = Vec::with_capacity(cur.len() / 2);
        for pair in cur.chunks(2) {
            next.push(domain_node(1, pair[0], pair[1])?);
        }
        levels.push(next);
    }

    let mut path_elements = Vec::with_capacity(MAX_LEAVES);
    let mut path_indices = Vec::with_capacity(MAX_LEAVES);
    for leaf_i in 0..MAX_LEAVES {
        let mut idx = leaf_i;
        let mut pe = Vec::with_capacity(REDACTION_DEPTH);
        let mut pi = Vec::with_capacity(REDACTION_DEPTH);
        for level in levels.iter().take(REDACTION_DEPTH) {
            let sibling = idx ^ 1;
            pe.push(level[sibling]);
            pi.push((idx & 1) as u8);
            idx /= 2;
        }
        path_elements.push(pe);
        path_indices.push(pi);
    }
    Ok((path_elements, path_indices))
}

/// Run the full pipeline: bytes → 16 chunk hashes → 16 Poseidon leaves →
/// depth-4 root.
pub fn chunk_tree_from_bytes(bytes: &[u8]) -> Result<ChunkTree, ChunkError> {
    if bytes.is_empty() {
        return Err(ChunkError::EmptyInput);
    }
    let chunk_hashes_hex = chunk_into_16(bytes);
    let mut leaves = Vec::with_capacity(MAX_LEAVES);
    for h in &chunk_hashes_hex {
        let leaf_biguint = blake3_hex_to_poseidon_leaf(h)
            .map_err(|e| ChunkError::LeafConversion(e.to_string()))?;
        // BigUint → Fr via big-endian bytes.
        let bytes_be = leaf_biguint.to_bytes_be();
        let mut padded = [0u8; 32];
        let off = 32 - bytes_be.len();
        padded[off..].copy_from_slice(&bytes_be);
        leaves.push(<Fr as ark_ff::PrimeField>::from_be_bytes_mod_order(&padded));
    }
    let original_root = root_of_16(&leaves)?;
    Ok(ChunkTree {
        chunk_hashes_hex,
        leaves,
        original_root,
    })
}

/// Convert an `Fr` to a canonical lower-hex 64-character string for
/// storage in TEXT columns (`original_root`, `snapshot_root`, etc.).  The
/// inverse is `crate::zk::proof::parse_fr`.
pub fn fr_to_hex(f: Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    let mut hex = String::with_capacity(64);
    let pad = 32 - bytes.len();
    for _ in 0..pad {
        hex.push_str("00");
    }
    for b in &bytes {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_identical_bytes() {
        let bytes = b"hello, olympus".repeat(50);
        let a = chunk_tree_from_bytes(&bytes).unwrap();
        let b = chunk_tree_from_bytes(&bytes).unwrap();
        assert_eq!(a.original_root, b.original_root);
        assert_eq!(a.chunk_hashes_hex, b.chunk_hashes_hex);
    }

    #[test]
    fn differs_for_different_bytes() {
        let a = chunk_tree_from_bytes(b"alpha").unwrap();
        let b = chunk_tree_from_bytes(b"beta").unwrap();
        assert_ne!(a.original_root, b.original_root);
    }

    #[test]
    fn produces_exactly_16_chunks() {
        let t = chunk_tree_from_bytes(b"short").unwrap();
        assert_eq!(t.chunk_hashes_hex.len(), MAX_LEAVES);
        assert_eq!(t.leaves.len(), MAX_LEAVES);
    }

    #[test]
    fn rejects_empty_input() {
        assert!(chunk_tree_from_bytes(b"").is_err());
    }

    #[test]
    fn root_hex_is_64_chars() {
        let t = chunk_tree_from_bytes(b"hello").unwrap();
        let hex = fr_to_hex(t.original_root);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // The chunk-era JS-conformance fixture moved to the object-level scheme
    // under `crate::zk::pdf_objects::js_conformance_fixture_locked` (ADR-0026
    // / FE-4). It pins the same value the Vitest test
    // `redactionBinding.conformance.test.ts` asserts via the shared file
    // `verifiers/test_vectors/redaction_vectors.json` — JS↔Rust drift fails
    // both sides simultaneously.
}
