//! Rasterized tile-redaction commitment — Rust cross-language verifier leg
//! (ADR-0023).
//!
//! Independent recompute-and-compare verifier mirroring
//! `verifiers/javascript/verifier.js` and the authoritative reference at
//! `src-tauri/src/zk/redaction_tile.rs`. Reuses the Baby Jubjub / Pedersen
//! primitives in [`crate::pedersen`] and re-implements the three novel pieces
//! ADR-0023 introduces, against the shared golden vectors in
//! `verifiers/test_vectors/tile_redaction_vectors.json`:
//!
//!   1. `tile_message_scalar` — `m = reduce_l(BLAKE3_XOF(OLY:REDACTION:TILE:V1
//!      || page||x||y || lp(tile_bytes))[..64])`.
//!   2. `tiles_root` — positional BLAKE3 Merkle root (`OLY:NODE:V1`), padded to
//!      the next power of two with the `OLY:EMPTY-LEAF:V1` sentinel.
//!   3. bundle verification — Ed25519 over the `OLY:REDACTION:BUNDLE:V1`
//!      descriptor digest + revealed-tile reopening + root binding.
//!
//! Implemented with `num-bigint` + `blake3` + `ed25519-dalek` — all already
//! vendored for the verifier; no zk/curve crate is added.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use num_bigint::BigUint;
use serde::Deserialize;

use crate::pedersen::{parse_dec, Curve, Point};

const TILE_PREFIX: &[u8] = b"OLY:REDACTION:TILE:V1";
const BUNDLE_PREFIX: &[u8] = b"OLY:REDACTION:BUNDLE:V1";
const NODE_PREFIX: &[u8] = b"OLY:NODE:V1";
const SEP: &[u8] = b"|";
const EMPTY_LEAF_PREFIX: &[u8] = b"OLY:EMPTY-LEAF:V1";

// ── Novel primitives ─────────────────────────────────────────────────────────

/// `m = reduce_l(BLAKE3_XOF(prefix || page||x||y || lp(tile_bytes))[..64])`.
pub fn tile_message_scalar(curve: &Curve, page: u32, x: u32, y: u32, tile_bytes: &[u8]) -> BigUint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TILE_PREFIX);
    hasher.update(&page.to_be_bytes());
    hasher.update(&x.to_be_bytes());
    hasher.update(&y.to_be_bytes());
    hasher.update(&(tile_bytes.len() as u32).to_be_bytes()); // lp length
    hasher.update(tile_bytes);
    let mut reader = hasher.finalize_xof();
    let mut wide = [0u8; 64];
    reader.fill(&mut wide);
    BigUint::from_bytes_be(&wide) % &curve.l
}

/// The `OLY:EMPTY-LEAF:V1` sentinel.
fn empty_leaf() -> [u8; 32] {
    *blake3::hash(EMPTY_LEAF_PREFIX).as_bytes()
}

/// `OLY:NODE:V1 | left | right` BLAKE3 internal-node hash.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(NODE_PREFIX);
    h.update(SEP);
    h.update(left);
    h.update(SEP);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Positional Merkle root over `leaves`, padded to the next power of two with
/// the empty-leaf sentinel and folded with [`node_hash`].
pub fn tiles_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty_leaf();
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    level.resize(level.len().next_power_of_two(), empty_leaf());
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| node_hash(&pair[0], &pair[1]))
            .collect();
    }
    level[0]
}

// ── Vector schema ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ScalarVector {
    pub page: u32,
    pub x: u32,
    pub y: u32,
    pub tile_bytes_hex: String,
    pub m_decimal: String,
}

#[derive(Deserialize)]
pub struct LeafVector {
    pub page: u32,
    pub x: u32,
    pub y: u32,
    pub tile_bytes_hex: String,
    pub blinding_decimal: String,
    pub m_decimal: String,
    pub commitment_x_decimal: String,
    pub commitment_y_decimal: String,
    pub leaf_compressed_hex: String,
}

#[derive(Deserialize)]
pub struct RootVector {
    #[allow(dead_code)]
    pub description: String,
    pub leaves_hex: Vec<String>,
    pub root_hex: String,
}

#[derive(Deserialize)]
pub struct BundleTile {
    pub page: u32,
    pub x: u32,
    pub y: u32,
    pub leaf_compressed_hex: String,
    pub revealed_blinding_decimal: Option<String>,
}

#[derive(Deserialize)]
pub struct ArtifactTile {
    pub page: u32,
    pub x: u32,
    pub y: u32,
    pub tile_bytes_hex: String,
}

#[derive(Deserialize)]
pub struct BundleVector {
    #[allow(dead_code)]
    pub description: String,
    pub original_root_hex: String,
    pub recipient_id: String,
    pub signer_ed25519_pubkey_hex: String,
    pub signature_hex: String,
    pub tiles: Vec<BundleTile>,
    pub artifact_tiles: Vec<ArtifactTile>,
    pub expected_valid: bool,
}

#[derive(Deserialize)]
pub struct TileRedactionVectors {
    pub tile_message_scalars: Vec<ScalarVector>,
    pub tile_leaves: Vec<LeafVector>,
    pub tiles_root: Vec<RootVector>,
    pub bundle: BundleVector,
}

// ── Verify helpers ───────────────────────────────────────────────────────────

fn leaf32(hex_str: &str) -> Option<[u8; 32]> {
    let v = hex::decode(hex_str).ok()?;
    v.try_into().ok()
}

/// Recompute `m` from coord + bytes and compare to the vector's `m_decimal`.
pub fn verify_tile_message_scalar(curve: &Curve, v: &ScalarVector) -> bool {
    let bytes = match hex::decode(&v.tile_bytes_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let m = tile_message_scalar(curve, v.page, v.x, v.y, &bytes);
    parse_dec(&v.m_decimal) == Some(m)
}

/// Recompute the Pedersen tile leaf from coord + bytes + blinding and check the
/// message scalar, commitment coordinates, and compressed leaf.
pub fn verify_tile_leaf(curve: &Curve, v: &LeafVector) -> bool {
    let bytes = match hex::decode(&v.tile_bytes_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let m = tile_message_scalar(curve, v.page, v.x, v.y, &bytes);
    if parse_dec(&v.m_decimal) != Some(m.clone()) {
        return false;
    }
    let b = match parse_dec(&v.blinding_decimal) {
        Some(b) => b,
        None => return false,
    };
    let c = curve.pedersen_commit(&m, &b);
    let (ex, ey) = match (
        parse_dec(&v.commitment_x_decimal),
        parse_dec(&v.commitment_y_decimal),
    ) {
        (Some(x), Some(y)) => (x, y),
        _ => return false,
    };
    if c.x != ex || c.y != ey {
        return false;
    }
    hex::encode(curve.compress(&c)) == v.leaf_compressed_hex
}

/// Recompute the Merkle root over the given leaves and compare.
pub fn verify_tiles_root(v: &RootVector) -> bool {
    let mut leaves = Vec::with_capacity(v.leaves_hex.len());
    for h in &v.leaves_hex {
        match leaf32(h) {
            Some(l) => leaves.push(l),
            None => return false,
        }
    }
    hex::encode(tiles_root(&leaves)) == v.root_hex
}

/// Domain-separated bundle descriptor digest (mirrors the Rust reference).
fn descriptor_digest(root: &[u8; 32], recipient_id: &str, tiles: &[BundleTile]) -> Option<[u8; 32]> {
    let mut h = blake3::Hasher::new();
    h.update(BUNDLE_PREFIX);
    h.update(&(root.len() as u32).to_be_bytes()); // lp(root)
    h.update(root);
    let rb = recipient_id.as_bytes();
    h.update(&(rb.len() as u32).to_be_bytes()); // lp(recipient)
    h.update(rb);
    h.update(&(tiles.len() as u32).to_be_bytes());
    for t in tiles {
        h.update(&t.page.to_be_bytes());
        h.update(&t.x.to_be_bytes());
        h.update(&t.y.to_be_bytes());
        h.update(&[u8::from(t.revealed_blinding_decimal.is_some())]);
        h.update(&leaf32(&t.leaf_compressed_hex)?);
    }
    Some(*h.finalize().as_bytes())
}

/// Full bundle verification: Ed25519 over the descriptor digest, revealed-tile
/// reopening from the artifact, and root binding. Never panics on malformed
/// input — returns `false`.
pub fn verify_bundle(curve: &Curve, v: &BundleVector) -> bool {
    let root = match leaf32(&v.original_root_hex) {
        Some(r) => r,
        None => return false,
    };

    // 1. Signature over the descriptor digest.
    let digest = match descriptor_digest(&root, &v.recipient_id, &v.tiles) {
        Some(d) => d,
        None => return false,
    };
    let pk_bytes: [u8; 32] = match leaf32(&v.signer_ed25519_pubkey_hex) {
        Some(b) => b,
        None => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match hex::decode(&v.signature_hex)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
    {
        Some(s) => s,
        None => return false,
    };
    if vk.verify(&digest, &sig).is_err() {
        return false;
    }

    // 2. Revealed-tile authenticity from the artifact.
    for t in &v.tiles {
        if let Some(bd) = &t.revealed_blinding_decimal {
            let art = v
                .artifact_tiles
                .iter()
                .find(|a| a.page == t.page && a.x == t.x && a.y == t.y);
            let art = match art {
                Some(a) => a,
                None => return false, // revealed tile missing from artifact
            };
            let bytes = match hex::decode(&art.tile_bytes_hex) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let m = tile_message_scalar(curve, t.page, t.x, t.y, &bytes);
            let b = match parse_dec(bd) {
                Some(b) => b,
                None => return false,
            };
            let c: Point = curve.pedersen_commit(&m, &b);
            if hex::encode(curve.compress(&c)) != t.leaf_compressed_hex {
                return false;
            }
        }
    }

    // 3. Root binding over all leaves in bundle order.
    let mut leaves = Vec::with_capacity(v.tiles.len());
    for t in &v.tiles {
        match leaf32(&t.leaf_compressed_hex) {
            Some(l) => leaves.push(l),
            None => return false,
        }
    }
    tiles_root(&leaves) == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load() -> TileRedactionVectors {
        let raw = include_str!("../../test_vectors/tile_redaction_vectors.json");
        serde_json::from_str(raw).expect("parse tile_redaction_vectors.json")
    }

    #[test]
    fn conformance_tile_message_scalars() {
        let v = load();
        let curve = Curve::baby_jubjub();
        assert!(!v.tile_message_scalars.is_empty());
        for (i, s) in v.tile_message_scalars.iter().enumerate() {
            assert!(verify_tile_message_scalar(&curve, s), "scalar vector {i}");
        }
    }

    #[test]
    fn conformance_tile_leaves() {
        let v = load();
        let curve = Curve::baby_jubjub();
        assert!(!v.tile_leaves.is_empty());
        for (i, leaf) in v.tile_leaves.iter().enumerate() {
            assert!(verify_tile_leaf(&curve, leaf), "leaf vector {i}");
        }
    }

    #[test]
    fn conformance_tiles_root() {
        let v = load();
        assert!(!v.tiles_root.is_empty());
        for (i, r) in v.tiles_root.iter().enumerate() {
            assert!(verify_tiles_root(r), "root vector {i}");
        }
    }

    #[test]
    fn conformance_bundle_valid() {
        let v = load();
        let curve = Curve::baby_jubjub();
        assert_eq!(
            verify_bundle(&curve, &v.bundle),
            v.bundle.expected_valid,
            "bundle vector"
        );
    }

    // ── Negative cases (tamper the loaded valid bundle) ──────────────────────

    #[test]
    fn tampered_recipient_breaks_signature() {
        let v = load();
        let curve = Curve::baby_jubjub();
        let mut b = v.bundle;
        b.recipient_id = "mallory".to_string();
        assert!(!verify_bundle(&curve, &b), "wrong recipient must fail");
    }

    #[test]
    fn tampered_revealed_artifact_tile_is_rejected() {
        let v = load();
        let curve = Curve::baby_jubjub();
        let mut b = v.bundle;
        // Corrupt a revealed tile's artifact bytes.
        if let Some(a) = b.artifact_tiles.first_mut() {
            a.tile_bytes_hex = hex::encode(b"TAMPERED");
        }
        assert!(!verify_bundle(&curve, &b), "tampered revealed tile must fail");
    }

    #[test]
    fn tampered_leaf_breaks_root_binding() {
        let v = load();
        let curve = Curve::baby_jubjub();
        let mut b = v.bundle;
        // Flip a byte in the *redacted* tile's leaf (the one with no blinding):
        // it folds into the root, so the signature also covers it — either trips.
        if let Some(t) = b
            .tiles
            .iter_mut()
            .find(|t| t.revealed_blinding_decimal.is_none())
        {
            let mut bytes = hex::decode(&t.leaf_compressed_hex).unwrap();
            bytes[0] ^= 0xFF;
            t.leaf_compressed_hex = hex::encode(bytes);
        }
        assert!(!verify_bundle(&curve, &b), "tampered leaf must fail");
    }
}
