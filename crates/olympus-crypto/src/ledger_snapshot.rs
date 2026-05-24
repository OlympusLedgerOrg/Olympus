//! Relying-party verification of the signed Poseidon ledger snapshot.
//!
//! The desktop crate's `zk::snapshot` *produces* a `LedgerSnapshot` per record
//! (depth-20 Poseidon Merkle path + Ed25519 signature over a fixed-format
//! payload). This module is the **verifier** side: reconstruct the snapshot
//! root from the record's leaf + path and confirm the authority's signature —
//! so a relying party can establish "this snapshot is the one Olympus issued
//! for THIS document at tree size N" without any DB access.
//!
//! Hashing uses this crate's `poseidon_hash` (parity with the desktop ZK layer
//! is locked by the cross-implementation test against `light_poseidon`), and
//! the signing payload is byte-identical to `zk::snapshot::signing_payload`.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::poseidon::poseidon_hash;

/// Ledger-tree height. Must match `zk::witness::existence::DEPTH` (the
/// `document_existence` circuit) and `zk::snapshot`'s `DEPTH`.
pub const SNAPSHOT_DEPTH: usize = 20;

/// `DomainPoseidonNode(1, left, right)` = `Poseidon(Poseidon(1, left), right)`.
fn domain_node(left: Fr, right: Fr) -> Fr {
    poseidon_hash(poseidon_hash(Fr::from(1u64), left), right)
}

/// 32-byte big-endian hex of a field element (matches `zk::chunk::fr_to_hex`).
fn fr_to_hex(f: Fr) -> String {
    hex::encode(f.into_bigint().to_bytes_be())
}

/// Parse a hex field element (<= 32 bytes, right-aligned big-endian).
fn hex_to_fr(s: &str) -> Option<Fr> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() > 32 {
        return None;
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    Some(Fr::from_be_bytes_mod_order(&buf))
}

/// The frozen snapshot a record carries. Mirrors `zk::snapshot::LedgerSnapshot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub snapshot_root: String,
    pub snapshot_index: u64,
    pub snapshot_size: u64,
    /// `SNAPSHOT_DEPTH` sibling hashes, leaf→root order.
    pub path_elements_hex: Vec<String>,
    /// `SNAPSHOT_DEPTH` direction bits (0 = this branch is the left child).
    pub path_indices: Vec<u8>,
    /// 64-byte Ed25519 signature, lowercase hex.
    pub signature_hex: String,
}

/// The Ed25519-signed payload — byte-identical to `zk::snapshot::signing_payload`.
/// Independent of any JSON canonicalization so verifiers reproduce it trivially.
pub fn signing_payload(
    snapshot_root: &str,
    leaf: &str,
    leaf_index: u64,
    tree_size: u64,
    content_hash: &str,
    original_root: &str,
) -> Vec<u8> {
    format!(
        "OLY:LEDGER_SNAPSHOT:V1|root={snapshot_root}|leaf={leaf}|idx={leaf_index}|size={tree_size}|content_hash={content_hash}|original_root={original_root}"
    )
    .into_bytes()
}

/// Reconstruct the ledger root from `leaf` and the proof path. `path_indices[d]`
/// is 0 when this branch is the left child at level `d`, 1 when it's the right.
fn reconstruct_root(leaf: Fr, path_elements: &[Fr], path_indices: &[u8]) -> Option<Fr> {
    if path_elements.len() != SNAPSHOT_DEPTH || path_indices.len() != SNAPSHOT_DEPTH {
        return None;
    }
    let mut current = leaf;
    for d in 0..SNAPSHOT_DEPTH {
        let sib = path_elements[d];
        current = match path_indices[d] {
            0 => domain_node(current, sib),
            1 => domain_node(sib, current),
            _ => return None,
        };
    }
    Some(current)
}

/// Verify a signed ledger snapshot for a record.
///
/// `original_root` is the record's depth-4 chunk-tree root — the snapshot leaf,
/// in canonical `fr_to_hex` form. Checks, in order:
/// 1. the path of exactly `SNAPSHOT_DEPTH` siblings reconstructs `snapshot_root`
///    from the leaf, and
/// 2. `authority_pubkey`'s Ed25519 signature over the canonical payload is valid.
///
/// Returns `false` on any malformed field, length mismatch, or failed check —
/// never panics. The caller must independently trust `authority_pubkey` as the
/// ledger's signing authority.
pub fn verify_snapshot(
    snapshot: &LedgerSnapshot,
    content_hash: &str,
    original_root: &str,
    authority_pubkey: &[u8; 32],
) -> bool {
    if snapshot.path_elements_hex.len() != SNAPSHOT_DEPTH
        || snapshot.path_indices.len() != SNAPSHOT_DEPTH
    {
        return false;
    }
    let leaf = match hex_to_fr(original_root) {
        Some(f) => f,
        None => return false,
    };
    let mut path_elements = Vec::with_capacity(SNAPSHOT_DEPTH);
    for h in &snapshot.path_elements_hex {
        match hex_to_fr(h) {
            Some(f) => path_elements.push(f),
            None => return false,
        }
    }
    let root = match reconstruct_root(leaf, &path_elements, &snapshot.path_indices) {
        Some(r) => r,
        None => return false,
    };
    if fr_to_hex(root) != snapshot.snapshot_root {
        return false;
    }

    let payload = signing_payload(
        &snapshot.snapshot_root,
        &fr_to_hex(leaf),
        snapshot.snapshot_index,
        snapshot.snapshot_size,
        content_hash,
        original_root,
    );
    let vk = match VerifyingKey::from_bytes(authority_pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(&snapshot.signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    vk.verify_strict(&payload, &Signature::from_bytes(&sig_arr)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use ed25519_dalek::{Signer, SigningKey};

    fn empty_chain() -> Vec<Fr> {
        let mut e = vec![Fr::zero(); SNAPSHOT_DEPTH + 1];
        for d in 0..SNAPSHOT_DEPTH {
            e[d + 1] = domain_node(e[d], e[d]);
        }
        e
    }

    /// Build a signed snapshot for a single leaf at index 0 (siblings are the
    /// empty-subtree hashes per level), exactly as zk::snapshot would.
    fn signed_single_leaf(sk: &SigningKey, leaf: Fr, content_hash: &str) -> (LedgerSnapshot, String) {
        let empty = empty_chain();
        let path_elements: Vec<Fr> = (0..SNAPSHOT_DEPTH).map(|d| empty[d]).collect();
        let path_indices = vec![0u8; SNAPSHOT_DEPTH];
        let root = reconstruct_root(leaf, &path_elements, &path_indices).unwrap();
        let snapshot_root = fr_to_hex(root);
        let original_root = fr_to_hex(leaf);
        let payload =
            signing_payload(&snapshot_root, &fr_to_hex(leaf), 0, 1, content_hash, &original_root);
        let sig = sk.sign(&payload);
        (
            LedgerSnapshot {
                snapshot_root,
                snapshot_index: 0,
                snapshot_size: 1,
                path_elements_hex: path_elements.iter().map(|f| fr_to_hex(*f)).collect(),
                path_indices,
                signature_hex: hex::encode(sig.to_bytes()),
            },
            original_root,
        )
    }

    #[test]
    fn roundtrip_verifies() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let leaf = Fr::from(123_456_789u64);
        let content_hash = "ab".repeat(32);
        let (snap, original_root) = signed_single_leaf(&sk, leaf, &content_hash);
        assert!(verify_snapshot(&snap, &content_hash, &original_root, sk.verifying_key().as_bytes()));
    }

    #[test]
    fn wrong_authority_key_fails() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let imposter = SigningKey::from_bytes(&[9u8; 32]);
        let leaf = Fr::from(42u64);
        let content_hash = "cd".repeat(32);
        let (snap, original_root) = signed_single_leaf(&sk, leaf, &content_hash);
        assert!(!verify_snapshot(&snap, &content_hash, &original_root, imposter.verifying_key().as_bytes()));
    }

    #[test]
    fn tampering_fails() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let pk = vk.as_bytes();
        let leaf = Fr::from(42u64);
        let content_hash = "cd".repeat(32);
        let (snap, original_root) = signed_single_leaf(&sk, leaf, &content_hash);

        // Different content_hash → payload changes → signature fails.
        assert!(!verify_snapshot(&snap, &"ee".repeat(32), &original_root, pk));
        // Tampered index → payload changes.
        let mut bad_idx = snap.clone();
        bad_idx.snapshot_index = 5;
        assert!(!verify_snapshot(&bad_idx, &content_hash, &original_root, pk));
        // Tampered root → reconstruction mismatch.
        let mut bad_root = snap.clone();
        bad_root.snapshot_root = "00".repeat(32);
        assert!(!verify_snapshot(&bad_root, &content_hash, &original_root, pk));
        // Truncated path → length check.
        let mut short = snap.clone();
        short.path_elements_hex.pop();
        assert!(!verify_snapshot(&short, &content_hash, &original_root, pk));
        // Wrong leaf (original_root) → reconstruction mismatch.
        assert!(!verify_snapshot(&snap, &content_hash, &fr_to_hex(Fr::from(99u64)), pk));
    }
}
