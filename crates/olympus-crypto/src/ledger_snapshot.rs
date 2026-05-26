//! Relying-party verification of the signed Poseidon ledger snapshot.
//!
//! The desktop crate's `zk::snapshot` *produces* a `LedgerSnapshot` per record
//! (depth-20 Poseidon Merkle path + BJJ EdDSA-Poseidon signature over a
//! left-folded Poseidon digest). This module is the **verifier** side:
//! reconstruct the snapshot root from the record's leaf + path and confirm
//! the authority's BJJ signature — so a relying party can establish "this
//! snapshot is the one Olympus issued for THIS document at tree size N"
//! without any DB access.
//!
//! Hashing uses this crate's `poseidon_hash` (parity with the desktop ZK layer
//! is locked by the cross-implementation test against `light_poseidon`), and
//! the digest is left-folded via 2-input Poseidon to match the signer side
//! exactly — see `signing_digest` in `src-tauri/src/zk/snapshot.rs`.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};

use crate::poseidon::poseidon_hash;

/// Ledger-tree height. Must match `zk::witness::existence::DEPTH` (the
/// `document_existence` circuit) and `zk::snapshot`'s `DEPTH`.
pub const SNAPSHOT_DEPTH: usize = 20;

/// Domain separator — MUST equal `zk::snapshot::SIGNING_DOMAIN`.
const SIGNING_DOMAIN: u64 = 0x4F4C595F534E4150; // "OLY_SNAP"

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

/// arkworks Fr → non-negative BigInt (for handing to babyjubjub-rs).
fn ark_fr_to_bigint(f: &Fr) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &f.into_bigint().to_bytes_be())
}

/// arkworks Fr → babyjubjub-rs' iden3 Fr (via decimal string round-trip).
/// `ff_ce::PrimeField` is the trait that provides `from_str` on the iden3 Fr.
fn ark_to_iden3(f: &Fr) -> Option<babyjubjub_rs::Fr> {
    use ff_ce::PrimeField as FfPrimeField;
    let bigint = ark_fr_to_bigint(f);
    babyjubjub_rs::Fr::from_str(&bigint.to_string())
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
    /// BJJ signature R8.x as 32-byte BE hex.
    pub signature_r8x: String,
    /// BJJ signature R8.y as 32-byte BE hex.
    pub signature_r8y: String,
    /// BJJ signature s as 32-byte BE hex.
    pub signature_s: String,
}

/// The single `Fr` that gets BJJ-signed. MUST match the signer's fold in
/// `zk::snapshot::signing_digest` byte-for-byte.
pub fn signing_digest(
    snapshot_root: &str,
    leaf: &str,
    leaf_index: u64,
    tree_size: u64,
    content_hash: &str,
    original_root: &str,
) -> Option<Fr> {
    let root_fr = hex_to_fr(snapshot_root)?;
    let leaf_fr = hex_to_fr(leaf)?;
    let ch_fr = hex_to_fr(content_hash)?;
    let orig_fr = hex_to_fr(original_root)?;
    let mut acc = poseidon_hash(Fr::from(SIGNING_DOMAIN), root_fr);
    acc = poseidon_hash(acc, leaf_fr);
    acc = poseidon_hash(acc, Fr::from(leaf_index));
    acc = poseidon_hash(acc, Fr::from(tree_size));
    acc = poseidon_hash(acc, ch_fr);
    acc = poseidon_hash(acc, orig_fr);
    Some(acc)
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
/// `original_root` is the record's depth-4 chunk-tree root — the snapshot
/// leaf, in canonical `fr_to_hex` form. `authority_pubkey_x`/`_y` are the
/// Baby Jubjub authority public-key coordinates (Fr).
///
/// Checks, in order:
/// 1. the path of exactly `SNAPSHOT_DEPTH` siblings reconstructs `snapshot_root`
///    from the leaf, and
/// 2. the BJJ EdDSA-Poseidon signature `(r8x, r8y, s)` is valid for the
///    authority pubkey over the canonical signing digest.
///
/// Returns `false` on any malformed field, length mismatch, or failed check —
/// never panics. The caller must independently trust `authority_pubkey_*` as
/// the ledger's signing authority.
pub fn verify_snapshot(
    snapshot: &LedgerSnapshot,
    content_hash: &str,
    original_root: &str,
    authority_pubkey_x: Fr,
    authority_pubkey_y: Fr,
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

    let digest = match signing_digest(
        &snapshot.snapshot_root,
        &fr_to_hex(leaf),
        snapshot.snapshot_index,
        snapshot.snapshot_size,
        content_hash,
        original_root,
    ) {
        Some(d) => d,
        None => return false,
    };

    let r8x = match hex_to_fr(&snapshot.signature_r8x) {
        Some(f) => f,
        None => return false,
    };
    let r8y = match hex_to_fr(&snapshot.signature_r8y) {
        Some(f) => f,
        None => return false,
    };
    let s = match hex_to_fr(&snapshot.signature_s) {
        Some(f) => f,
        None => return false,
    };

    let (pk_pt, sig) = match (
        ark_to_iden3(&authority_pubkey_x),
        ark_to_iden3(&authority_pubkey_y),
        ark_to_iden3(&r8x),
        ark_to_iden3(&r8y),
    ) {
        (Some(px), Some(py), Some(rx), Some(ry)) => (
            babyjubjub_rs::Point { x: px, y: py },
            babyjubjub_rs::Signature {
                r_b8: babyjubjub_rs::Point { x: rx, y: ry },
                s: ark_fr_to_bigint(&s),
            },
        ),
        _ => return false,
    };

    babyjubjub_rs::verify(pk_pt, sig, ark_fr_to_bigint(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    fn empty_chain() -> Vec<Fr> {
        let mut e = vec![Fr::zero(); SNAPSHOT_DEPTH + 1];
        for d in 0..SNAPSHOT_DEPTH {
            e[d + 1] = domain_node(e[d], e[d]);
        }
        e
    }

    #[test]
    fn malformed_signature_fails() {
        // We don't have the BJJ signer here (lives in src-tauri); just sanity-
        // check that the verifier rejects obviously-broken snapshots without
        // panicking. End-to-end signer↔verifier parity is covered by an
        // integration test in src-tauri that signs with BJJ and round-trips
        // through this verifier.
        let empty = empty_chain();
        let leaf = Fr::from(123_456_789u64);
        let path_elements: Vec<Fr> = (0..SNAPSHOT_DEPTH).map(|d| empty[d]).collect();
        let path_indices = vec![0u8; SNAPSHOT_DEPTH];
        let root = reconstruct_root(leaf, &path_elements, &path_indices).unwrap();
        let snap = LedgerSnapshot {
            snapshot_root: fr_to_hex(root),
            snapshot_index: 0,
            snapshot_size: 1,
            path_elements_hex: path_elements.iter().map(|f| fr_to_hex(*f)).collect(),
            path_indices,
            signature_r8x: "00".repeat(32),
            signature_r8y: "00".repeat(32),
            signature_s: "00".repeat(32),
        };
        let original_root = fr_to_hex(leaf);
        // All-zero sig against a real-looking pubkey: verifier must reject.
        assert!(!verify_snapshot(
            &snap,
            &"ab".repeat(32),
            &original_root,
            Fr::from(1u64),
            Fr::from(2u64),
        ));
    }

    #[test]
    fn truncated_path_rejected() {
        let snap = LedgerSnapshot {
            snapshot_root: "00".repeat(32),
            snapshot_index: 0,
            snapshot_size: 1,
            path_elements_hex: vec!["00".repeat(32); SNAPSHOT_DEPTH - 1], // short
            path_indices: vec![0u8; SNAPSHOT_DEPTH - 1],
            signature_r8x: "00".repeat(32),
            signature_r8y: "00".repeat(32),
            signature_s: "00".repeat(32),
        };
        assert!(!verify_snapshot(
            &snap,
            &"ab".repeat(32),
            &fr_to_hex(Fr::from(1u64)),
            Fr::from(1u64),
            Fr::from(2u64),
        ));
    }
}
