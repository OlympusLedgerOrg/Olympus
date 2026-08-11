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
//! signed with the Baby Jubjub authority key (EdDSA-Poseidon) so the
//! signature lives in the same field as the rest of the ledger state
//! and is composable in future in-circuit verifiers. The pubkey is the
//! same BJJ authority key used for SBT signing and federation
//! checkpoints — one signing identity for all internal ledger state.

use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::zk::chunk::fr_to_hex;
use crate::zk::poseidon::{domain_node, hash2, PoseidonError, NODE_DOMAIN};
use crate::zk::witness::baby_jubjub::{self, BabyJubJubError, BabyJubJubSignature};
use crate::zk::witness::existence::DEPTH;

/// Domain separator for the snapshot signing payload — distinguishes a
/// `Poseidon(snapshot_fields)` digest from any other 7-input Poseidon
/// hash the system might produce.
const SIGNING_DOMAIN: u64 = 0x4F4C595F534E4150; // "OLY_SNAP"

/// Domain separator for the V2 (timestamped) signing payload — MUST equal
/// `olympus_crypto::ledger_snapshot::SIGNING_DOMAIN_V2`. V2 folds the
/// authority's signing time (unix seconds) into the digest so relying
/// parties can evaluate trust windows at the authenticated signing time
/// (what makes checkpoint-authority keys retirable — `docs/key-rotation.md`).
const SIGNING_DOMAIN_V2: u64 = 0x4F4C595F534E5032; // "OLY_SNP2"

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("Poseidon error: {0}")]
    Poseidon(#[from] PoseidonError),
    #[error("leaf index {0} >= tree capacity 2^{1}")]
    IndexOutOfRange(u64, usize),
    #[error("BJJ signing error: {0}")]
    BjjSign(#[from] BabyJubJubError),
    #[error("invalid field-element hex: {0}")]
    BadFieldHex(String),
    #[error("signed_at_unix must be non-negative, got {0}")]
    NegativeSignedAt(i64),
}

/// The frozen snapshot a single record carries for the rest of its life.
///
/// `path_elements_hex[i]` is the sibling hash at level `i` (leaf→root).
/// `path_indices[i]` is `0` when this record's branch is the left child
/// at that level, `1` when it's the right.  Together they reconstruct
/// `snapshot_root` from `leaf` and feed directly into
/// `ExistenceWitness::new`.
///
/// The signature is BJJ EdDSA-Poseidon over the digest computed by
/// [`signing_digest`]: three field components (r8x, r8y, s) serialised as
/// 32-byte big-endian hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub snapshot_root: String,
    pub snapshot_index: u64,
    pub snapshot_size: u64,
    /// 20 sibling hashes, leaf-to-root order.
    pub path_elements_hex: Vec<String>,
    /// 20 direction bits, leaf-to-root order.
    pub path_indices: Vec<u8>,
    /// BJJ signature R8.x as 32-byte BE hex.
    pub signature_r8x: String,
    /// BJJ signature R8.y as 32-byte BE hex.
    pub signature_r8y: String,
    /// BJJ signature s as 32-byte BE hex.
    pub signature_s: String,
    /// Authority signing time (unix seconds), folded into the V2 signing
    /// digest by [`signing_digest_v2`]. Every snapshot produced by
    /// [`snapshot_new_record`] carries one; the verifier side
    /// (`olympus_crypto::ledger_snapshot`) keeps the field optional so
    /// historical V1-signed rows remain verifiable.
    pub signed_at_unix: i64,
}

/// Parse a hex-encoded field element. Strict: requires exactly 32 bytes
/// (64 hex chars), big-endian — matching the verifier crate's parser.
///
/// Audit E1: the previous form accepted any length ≤ 32 bytes and
/// right-aligned it, so `"01"` and a 64-char zero-padded `"…01"` both mapped
/// to `Fr(1)`. All in-tree callers feed canonical `fr_to_hex` output (64 hex
/// chars), so requiring exactly 32 bytes loses nothing and keeps the signer and
/// relying party on one canonical wire form. (The `mod_order` reduction is
/// retained deliberately: a 32-byte `content_hash` legitimately exceeds the
/// BN254 scalar modulus and must be reduced into the field.)
fn hex_to_fr(s: &str) -> Result<Fr, SnapshotError> {
    let bytes = hex::decode(s).map_err(|e| SnapshotError::BadFieldHex(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(SnapshotError::BadFieldHex(format!(
            "expected exactly 32 bytes (64 hex chars), got {}",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(Fr::from_be_bytes_mod_order(&buf))
}

/// The single `Fr` that gets BJJ-signed for a snapshot. Includes every
/// field a relying party needs to bind the signature to "this snapshot,
/// this document, this position." The domain tag isolates this hash from
/// any other Poseidon use the system may add later.
///
/// Implemented as a left-fold of 2-input `hash2` calls so the relying-party
/// verifier crate (which only ships 2-input Poseidon) can reproduce it
/// without pulling `light-poseidon`. The result is deterministic given the
/// inputs; signer and verifier must use the identical fold order.
///
/// `content_hash` is a 32-byte BLAKE3 digest reduced into `Fr` — the same
/// reduction the verifier crate applies.
pub fn signing_digest(
    snapshot_root: &str,
    leaf: &str,
    leaf_index: u64,
    tree_size: u64,
    content_hash: &str,
    original_root: &str,
) -> Result<Fr, SnapshotError> {
    let root_fr = hex_to_fr(snapshot_root)?;
    let leaf_fr = hex_to_fr(leaf)?;
    let ch_fr = hex_to_fr(content_hash)?;
    let orig_fr = hex_to_fr(original_root)?;
    let mut acc = hash2(Fr::from(SIGNING_DOMAIN), root_fr)?;
    acc = hash2(acc, leaf_fr)?;
    acc = hash2(acc, Fr::from(leaf_index))?;
    acc = hash2(acc, Fr::from(tree_size))?;
    acc = hash2(acc, ch_fr)?;
    acc = hash2(acc, orig_fr)?;
    Ok(acc)
}

/// The V2 (timestamped) signing digest: identical fold to [`signing_digest`]
/// except the domain tag is [`SIGNING_DOMAIN_V2`] and `signed_at_unix` is
/// appended as the final element. The disjoint domain guarantees a V1
/// signature never verifies as V2 (or vice versa) over the same fields.
/// MUST match `olympus_crypto::ledger_snapshot::signing_digest_v2`
/// byte-for-byte — parity is locked by `tests/snapshot_cross_crate_parity.rs`.
///
/// `signed_at_unix` must be non-negative: it is a wall-clock timestamp, and
/// the `as u64` cast would otherwise alias two distinct i64 values onto one
/// field element.
#[allow(clippy::too_many_arguments)]
pub fn signing_digest_v2(
    snapshot_root: &str,
    leaf: &str,
    leaf_index: u64,
    tree_size: u64,
    content_hash: &str,
    original_root: &str,
    signed_at_unix: i64,
) -> Result<Fr, SnapshotError> {
    if signed_at_unix < 0 {
        return Err(SnapshotError::NegativeSignedAt(signed_at_unix));
    }
    let root_fr = hex_to_fr(snapshot_root)?;
    let leaf_fr = hex_to_fr(leaf)?;
    let ch_fr = hex_to_fr(content_hash)?;
    let orig_fr = hex_to_fr(original_root)?;
    let mut acc = hash2(Fr::from(SIGNING_DOMAIN_V2), root_fr)?;
    acc = hash2(acc, leaf_fr)?;
    acc = hash2(acc, Fr::from(leaf_index))?;
    acc = hash2(acc, Fr::from(tree_size))?;
    acc = hash2(acc, ch_fr)?;
    acc = hash2(acc, orig_fr)?;
    acc = hash2(acc, Fr::from(signed_at_unix as u64))?;
    Ok(acc)
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
        empty[d + 1] = domain_node(NODE_DOMAIN, empty[d], empty[d])?;
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

    for empty_d in empty.iter().take(DEPTH) {
        path_elements.push(*layer.get(&(idx ^ 1)).unwrap_or(empty_d));
        path_indices.push((idx & 1) as u8);

        // Collapse depth d -> d+1: compute each unique parent from its children.
        let parents: HashSet<u64> = layer.keys().map(|&k| k >> 1).collect();
        let mut next: HashMap<u64, Fr> = HashMap::with_capacity(parents.len());
        for parent in parents {
            let l = *layer.get(&(parent << 1)).unwrap_or(empty_d);
            let r = *layer.get(&(parent << 1 | 1)).unwrap_or(empty_d);
            next.insert(parent, domain_node(NODE_DOMAIN, l, r)?);
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
/// without trusting any DB. `signed_at_unix` (the authority's wall-clock
/// signing time, unix seconds) is folded into the V2 digest so a relying
/// party can later evaluate the signing key's trust window at an
/// *authenticated* point in time — see `docs/key-rotation.md`.
pub fn snapshot_new_record(
    bjj_priv: &[u8; 32],
    existing_leaves: &[Fr],
    new_leaf: Fr,
    new_leaf_index: u64,
    content_hash: &str,
    original_root: &str,
    signed_at_unix: i64,
) -> Result<LedgerSnapshot, SnapshotError> {
    let (snapshot_root, path_elements, path_indices, tree_size) =
        build_snapshot_path(existing_leaves, new_leaf, new_leaf_index)?;

    let snapshot_root_hex = fr_to_hex(snapshot_root);
    let leaf_hex = fr_to_hex(new_leaf);
    let path_elements_hex: Vec<String> = path_elements.iter().copied().map(fr_to_hex).collect();

    let digest = signing_digest_v2(
        &snapshot_root_hex,
        &leaf_hex,
        new_leaf_index,
        tree_size,
        content_hash,
        original_root,
        signed_at_unix,
    )?;
    let sig: BabyJubJubSignature = baby_jubjub::sign(bjj_priv, digest)?;

    Ok(LedgerSnapshot {
        snapshot_root: snapshot_root_hex,
        snapshot_index: new_leaf_index,
        snapshot_size: tree_size,
        path_elements_hex,
        path_indices,
        signature_r8x: fr_to_hex(sig.r8x),
        signature_r8y: fr_to_hex(sig.r8y),
        signature_s: fr_to_hex(sig.s),
        signed_at_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::chunk::chunk_tree_from_bytes;
    use crate::zk::witness::baby_jubjub::{verify_signature, BabyJubJubPubKey};

    // Deterministic test key — any 32-byte value works; this one is below the
    // BJJ subgroup order so PrivateKey::import will not pre-reject it.
    const TEST_BJJ_PRIV: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn first_record_snapshot_index_zero() {
        let tree = chunk_tree_from_bytes(b"doc_a").unwrap();
        let snap = snapshot_new_record(
            &TEST_BJJ_PRIV,
            &[],
            tree.original_root,
            0,
            "00".repeat(32).as_str(),
            &fr_to_hex(tree.original_root),
            1_780_000_000,
        )
        .unwrap();
        assert_eq!(snap.snapshot_index, 0);
        assert_eq!(snap.snapshot_size, 1);
        assert_eq!(snap.path_elements_hex.len(), DEPTH);
        assert_eq!(snap.path_indices.len(), DEPTH);
    }

    #[test]
    fn path_index_bits_reconstruct_leaf_index() {
        let prior: Vec<Fr> = (0..5).map(|i| Fr::from(i as u64 + 100)).collect();
        let tree = chunk_tree_from_bytes(b"doc_x").unwrap();
        let snap = snapshot_new_record(
            &TEST_BJJ_PRIV,
            &prior,
            tree.original_root,
            5,
            "11".repeat(32).as_str(),
            &fr_to_hex(tree.original_root),
            1_780_000_000,
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
        let prior: Vec<Fr> = (0..3).map(|i| Fr::from(i as u64 + 50)).collect();
        let tree = chunk_tree_from_bytes(b"doc_v").unwrap();
        let snap = snapshot_new_record(
            &TEST_BJJ_PRIV,
            &prior,
            tree.original_root,
            3,
            "aa".repeat(32).as_str(),
            &fr_to_hex(tree.original_root),
            1_780_000_000,
        )
        .unwrap();
        let path_elems: Vec<Fr> = snap
            .path_elements_hex
            .iter()
            .map(|h| hex_to_fr(h).unwrap())
            .collect();
        let computed_root = compute_merkle_root(
            tree.original_root,
            &path_elems,
            &snap.path_indices,
            crate::zk::poseidon::NODE_DOMAIN,
        )
        .unwrap();
        assert_eq!(fr_to_hex(computed_root), snap.snapshot_root);
    }

    #[test]
    fn bjj_signature_verifies_against_authority_pubkey() {
        let content_hash = "bb".repeat(32);
        let signed_at: i64 = 1_780_000_000;
        let tree = chunk_tree_from_bytes(b"doc_sig").unwrap();
        let original_root_hex = fr_to_hex(tree.original_root);
        let snap = snapshot_new_record(
            &TEST_BJJ_PRIV,
            &[],
            tree.original_root,
            0,
            &content_hash,
            &original_root_hex,
            signed_at,
        )
        .unwrap();
        assert_eq!(snap.signed_at_unix, signed_at);

        let pk = BabyJubJubPubKey::from_private(&TEST_BJJ_PRIV).unwrap();
        let sig = BabyJubJubSignature {
            r8x: hex_to_fr(&snap.signature_r8x).unwrap(),
            r8y: hex_to_fr(&snap.signature_r8y).unwrap(),
            s: hex_to_fr(&snap.signature_s).unwrap(),
        };
        let digest = signing_digest_v2(
            &snap.snapshot_root,
            &fr_to_hex(tree.original_root),
            snap.snapshot_index,
            snap.snapshot_size,
            &content_hash,
            &original_root_hex,
            signed_at,
        )
        .unwrap();
        assert!(verify_signature(&pk, &sig, digest));

        // The signature is over the V2 digest only — the legacy V1 digest for
        // the same fields must NOT verify (disjoint signing domains).
        let v1_digest = signing_digest(
            &snap.snapshot_root,
            &fr_to_hex(tree.original_root),
            snap.snapshot_index,
            snap.snapshot_size,
            &content_hash,
            &original_root_hex,
        )
        .unwrap();
        assert!(!verify_signature(&pk, &sig, v1_digest));
    }

    #[test]
    fn negative_signed_at_is_rejected_with_named_reason() {
        let tree = chunk_tree_from_bytes(b"doc_neg").unwrap();
        let err = snapshot_new_record(
            &TEST_BJJ_PRIV,
            &[],
            tree.original_root,
            0,
            "cc".repeat(32).as_str(),
            &fr_to_hex(tree.original_root),
            -5,
        )
        .expect_err("negative signing time must be refused");
        assert!(matches!(err, SnapshotError::NegativeSignedAt(-5)));
    }
}
