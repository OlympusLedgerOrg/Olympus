//! Append-only Poseidon Merkle snapshot for the ledger tree.
//!
//! Replaces the prior `rebuild_shard_tree` approach (Python-era leftover
//! that re-derived every record's path on every commit). Each commit
//! freezes its own snapshot tuple `(root, leaf, leafIndex, treeSize, path,
//! sig)` at commit time and stores it on the new record only — older
//! records' snapshots are immutable.
//!
//! The "ledger tree" is conceptually a depth-20 binary Poseidon Merkle
//! tree (`2^20` = ~1M leaves max, matching the `document_existence`
//! circuit's `DEPTH`). Each leaf is a record's `original_root` (the
//! depth-4 root over its 16 BLAKE3 chunks), not `Poseidon(content_hash)`
//! like the legacy `merkle::build_poseidon_tree` path used. Empty leaf
//! positions hash to `Fr::zero()` (precomputed default subtree hashes
//! propagate this up the tree).
//!
//! At commit time the new record's `snapshot_index` is the next free
//! position in the shard (== count of prior records). The snapshot is
//! Ed25519-signed using `OLYMPUS_INGEST_SIGNING_KEY` so downstream
//! verifiers can establish that `snapshot_root` was a real ledger root
//! at time T without needing live DB access.

use ark_bn254::Fr;
use ark_ff::Zero;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::zk::chunk::fr_to_hex;
use crate::zk::poseidon::{domain_node, PoseidonError};
use crate::zk::witness::existence::DEPTH;

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("Poseidon error: {0}")]
    Poseidon(#[from] PoseidonError),
    #[error("leaf index {0} >= tree capacity 2^{1}")]
    IndexOutOfRange(u64, usize),
    #[error("OLYMPUS_INGEST_SIGNING_KEY not configured: {0}")]
    KeyMissing(String),
    #[error("OLYMPUS_INGEST_SIGNING_KEY is not a 32-byte hex value: {0}")]
    KeyParse(String),
}

/// The frozen snapshot a single record carries for the rest of its life.
///
/// `path_elements_hex[i]` is the sibling hash at level `i` (leaf→root).
/// `path_indices[i]` is `0` when this record's branch is the left child
/// at that level, `1` when it's the right.  Together they reconstruct
/// `snapshot_root` from `leaf` and feed directly into
/// `ExistenceWitness::new`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub snapshot_root: String,
    pub snapshot_index: u64,
    pub snapshot_size: u64,
    /// 20 sibling hashes, leaf-to-root order.
    pub path_elements_hex: Vec<String>,
    /// 20 direction bits, leaf-to-root order.
    pub path_indices: Vec<u8>,
    /// 64-byte Ed25519 signature, lowercase hex, over `signing_payload()`.
    pub signature_hex: String,
}

/// The byte payload that gets Ed25519-signed for a snapshot.  Independent
/// of any JSON canonicalization library so verifiers can reproduce it
/// trivially: fixed-width little-endian-tagged field with pipe separators.
fn signing_payload(
    snapshot_root: &str,
    leaf: &str,
    leaf_index: u64,
    tree_size: u64,
    content_hash: &str,
    original_root: &str,
) -> Vec<u8> {
    let s = format!(
        "OLY:LEDGER_SNAPSHOT:V1|root={}|leaf={}|idx={}|size={}|content_hash={}|original_root={}",
        snapshot_root, leaf, leaf_index, tree_size, content_hash, original_root
    );
    s.into_bytes()
}

/// Read the signing key once.  Reuses the same env-var convention as the
/// anchoring stack (`OLYMPUS_INGEST_SIGNING_KEY`), with a dev-mode
/// fallback to `OLYMPUS_DEV_SIGNING_KEY` so a `cargo tauri dev` run
/// without the production key still gets snapshots.
fn load_signing_key() -> Result<SigningKey, SnapshotError> {
    let hex = std::env::var("OLYMPUS_INGEST_SIGNING_KEY")
        .or_else(|_| std::env::var("OLYMPUS_DEV_SIGNING_KEY"))
        .map_err(|e| SnapshotError::KeyMissing(e.to_string()))?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex.trim(), &mut bytes)
        .map_err(|e| SnapshotError::KeyParse(e.to_string()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Build the depth-20 Poseidon Merkle path for `new_leaf` at position
/// `new_leaf_index`, given the in-order `existing_leaves` already in the
/// shard.  Empty positions hash to zero (precomputed per level).
///
/// `tree_size` returned is `existing_leaves.len() + 1` — i.e. the count
/// *after* this commit lands.
///
/// Uses a sparse map so only the O(n·DEPTH) non-empty nodes are hashed,
/// not all 2^DEPTH slots.  Empty positions fall back to a precomputed
/// per-depth default hash derived from Fr::zero() at the leaf level.
pub fn build_snapshot_path(
    existing_leaves: &[Fr],
    new_leaf: Fr,
    new_leaf_index: u64,
) -> Result<(Fr, Vec<Fr>, Vec<u8>, u64), SnapshotError> {
    use std::collections::{HashMap, HashSet};

    let capacity = 1u64 << DEPTH;
    if new_leaf_index >= capacity {
        return Err(SnapshotError::IndexOutOfRange(new_leaf_index, DEPTH));
    }

    // Precompute empty-subtree hashes bottom-up.
    // empty[0] = Fr::zero() (empty leaf), empty[d] = hash of a depth-d empty subtree.
    let mut empty = vec![Fr::zero(); DEPTH + 1];
    for d in 0..DEPTH {
        empty[d + 1] = domain_node(1, empty[d], empty[d])?;
    }

    // Sparse layer: position within the current depth -> node hash.
    // Absent keys fall back to empty[d].
    let mut layer: HashMap<u64, Fr> = HashMap::new();
    for (i, &leaf) in existing_leaves.iter().enumerate() {
        layer.insert(i as u64, leaf);
    }
    layer.insert(new_leaf_index, new_leaf);

    let tree_size = (existing_leaves.len() + 1) as u64;
    let mut path_elements = Vec::with_capacity(DEPTH);
    let mut path_indices = Vec::with_capacity(DEPTH);
    let mut idx = new_leaf_index;

    for d in 0..DEPTH {
        path_elements.push(*layer.get(&(idx ^ 1)).unwrap_or(&empty[d]));
        path_indices.push((idx & 1) as u8);

        // Collapse depth d -> d+1: compute each unique parent from its children.
        let parents: HashSet<u64> = layer.keys().map(|&k| k >> 1).collect();
        let mut next: HashMap<u64, Fr> = HashMap::with_capacity(parents.len());
        for parent in parents {
            let l = *layer.get(&(parent << 1)).unwrap_or(&empty[d]);
            let r = *layer.get(&(parent << 1 | 1)).unwrap_or(&empty[d]);
            next.insert(parent, domain_node(1, l, r)?);
        }
        idx >>= 1;
        layer = next;
    }

    let root = *layer.get(&0).unwrap_or(&empty[DEPTH]);
    Ok((root, path_elements, path_indices, tree_size))
}

/// Compute the full snapshot for a new record: build the path, sign the
/// tuple, return the serializable struct ready to persist.
///
/// `content_hash` and `original_root` are included in the signing
/// payload so a future verifier reading the bundle in isolation can
/// confirm "this snapshot is the one Olympus issued for THIS document"
/// without trusting any DB.
pub fn snapshot_new_record(
    existing_leaves: &[Fr],
    new_leaf: Fr,
    new_leaf_index: u64,
    content_hash: &str,
    original_root: &str,
) -> Result<LedgerSnapshot, SnapshotError> {
    let (snapshot_root, path_elements, path_indices, tree_size) =
        build_snapshot_path(existing_leaves, new_leaf, new_leaf_index)?;

    let snapshot_root_hex = fr_to_hex(snapshot_root);
    let leaf_hex = fr_to_hex(new_leaf);
    let path_elements_hex: Vec<String> = path_elements.iter().copied().map(fr_to_hex).collect();

    let payload = signing_payload(
        &snapshot_root_hex,
        &leaf_hex,
        new_leaf_index,
        tree_size,
        content_hash,
        original_root,
    );
    let key = load_signing_key()?;
    let sig = key.sign(&payload);

    Ok(LedgerSnapshot {
        snapshot_root: snapshot_root_hex,
        snapshot_index: new_leaf_index,
        snapshot_size: tree_size,
        path_elements_hex,
        path_indices,
        signature_hex: hex::encode(sig.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::chunk::chunk_tree_from_bytes;
    use ark_ff::PrimeField;

    fn set_dev_key() {
        // Deterministic test key.
        std::env::set_var(
            "OLYMPUS_DEV_SIGNING_KEY",
            "0101010101010101010101010101010101010101010101010101010101010101",
        );
    }

    #[test]
    fn first_record_snapshot_index_zero() {
        set_dev_key();
        let tree = chunk_tree_from_bytes(b"doc_a").unwrap();
        let snap = snapshot_new_record(
            &[],
            tree.original_root,
            0,
            "00".repeat(32).as_str(),
            &fr_to_hex(tree.original_root),
        )
        .unwrap();
        assert_eq!(snap.snapshot_index, 0);
        assert_eq!(snap.snapshot_size, 1);
        assert_eq!(snap.path_elements_hex.len(), DEPTH);
        assert_eq!(snap.path_indices.len(), DEPTH);
    }

    #[test]
    fn path_index_bits_reconstruct_leaf_index() {
        set_dev_key();
        let prior: Vec<Fr> = (0..5).map(|i| Fr::from(i as u64 + 100)).collect();
        let tree = chunk_tree_from_bytes(b"doc_x").unwrap();
        let snap = snapshot_new_record(
            &prior,
            tree.original_root,
            5,
            "11".repeat(32).as_str(),
            &fr_to_hex(tree.original_root),
        )
        .unwrap();
        let mut reconstructed = 0u64;
        for (b, &bit) in snap.path_indices.iter().enumerate() {
            reconstructed |= (bit as u64) << b;
        }
        assert_eq!(reconstructed, 5);
    }

    #[test]
    fn path_verifies_back_to_snapshot_root() {
        use crate::zk::poseidon::compute_merkle_root;
        set_dev_key();
        let prior: Vec<Fr> = (0..3).map(|i| Fr::from(i as u64 + 50)).collect();
        let tree = chunk_tree_from_bytes(b"doc_v").unwrap();
        let snap = snapshot_new_record(
            &prior,
            tree.original_root,
            3,
            "aa".repeat(32).as_str(),
            &fr_to_hex(tree.original_root),
        )
        .unwrap();
        // Re-parse the path elements back to Fr and walk the path.
        let path_elems: Vec<Fr> = snap
            .path_elements_hex
            .iter()
            .map(|h| {
                let mut padded = [0u8; 32];
                let bytes = hex::decode(h).unwrap();
                let off = 32 - bytes.len();
                padded[off..].copy_from_slice(&bytes);
                Fr::from_be_bytes_mod_order(&padded)
            })
            .collect();
        let computed_root = compute_merkle_root(
            tree.original_root,
            &path_elems,
            &snap.path_indices,
            1,
        )
        .unwrap();
        // Compare hex form for stability.
        assert_eq!(fr_to_hex(computed_root), snap.snapshot_root);
    }

    #[test]
    fn signature_is_64_bytes_hex() {
        set_dev_key();
        let tree = chunk_tree_from_bytes(b"doc_sig").unwrap();
        let snap = snapshot_new_record(
            &[],
            tree.original_root,
            0,
            "bb".repeat(32).as_str(),
            &fr_to_hex(tree.original_root),
        )
        .unwrap();
        assert_eq!(snap.signature_hex.len(), 128);
        assert!(snap.signature_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
