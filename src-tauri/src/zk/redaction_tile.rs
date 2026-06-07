//! Rasterized tile-redaction commitment primitive (ADR-0023, Phase 1 step 1).
//!
//! Pure crypto core — **no renderer, no PDF/Office importer, no UI**. It
//! operates on already-rasterized page **tiles** (opaque byte slices) and
//! provides the four pieces the redactor and the verifier need:
//!
//!   1. `tile_message_scalar` / `commit_tile` — the per-tile **Pedersen**
//!      commitment `C_i = m_i·G + b_i·H` (ADR-0023 chose Pedersen over salted
//!      BLAKE3 for *perfect* hiding: a redacted tile's published `C_i` reveals
//!      nothing about its content even to an attacker who can guess low-entropy
//!      content, because without the blinding `b_i` the point is uniform).
//!   2. `tiles_root` — a positional BLAKE3 Merkle root over the tile leaves
//!      (`olympus_crypto::node_hash`), the sealed `original_root`.
//!   3. `seal` — the issuer side: commit a page's tiles, returning the root and
//!      the per-tile `(leaf, blinding)`.
//!   4. `build_bundle` / `verify_bundle` — assemble the recipient-bound,
//!      authority-signed bundle and verify it against the redacted artifact's
//!      revealed tiles.
//!
//! ## What verification proves (ADR-0023)
//!
//! * **Revealed tiles are authentic** — for each revealed tile the verifier
//!   recomputes `C_i` from the *artifact's* bytes + the revealed blinding and
//!   checks it equals the published leaf. The visible content is therefore
//!   byte-faithful to what was sealed.
//! * **Redacted tiles are bound but hidden** — their leaves are carried in the
//!   bundle (so they fold into the root) but their blindings/contents are
//!   withheld; Pedersen hiding makes the content unrecoverable from the leaf.
//! * **The whole set ties to the sealed original** — all leaves fold to
//!   `original_root`, and the authority signature pins
//!   `(original_root, recipient_id, tile set)`, so a bundle cannot be replayed
//!   against a different document or recipient.
//!
//! The verifier **never re-renders** the source — it only re-hashes image tiles
//! it can already see — so cross-platform render reproducibility is not required.

use std::collections::HashMap;

use ark_bn254::Fr;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use num_bigint::{BigInt, Sign};
use olympus_crypto::{
    empty_leaf, length_prefixed as lp, node_hash, REDACTION_BUNDLE_PREFIX, REDACTION_TILE_PREFIX,
};
use thiserror::Error;

use super::pedersen::{self, PedersenCommitment, PedersenError};
use super::witness::baby_jubjub::{bigint_to_ark, bjj_subgroup_order};

/// Compressed Baby Jubjub commitment point — the on-wire tile leaf (32 bytes).
pub type TileLeaf = [u8; 32];

/// Location of a tile within a multi-page document. Canonical ordering is
/// `(page, y, x)`; [`seal`] and [`build_bundle`] sort into this order so the
/// root and descriptor digest are deterministic regardless of input order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TileCoord {
    pub page: u32,
    pub x: u32,
    pub y: u32,
}

impl TileCoord {
    /// Fixed-width (12-byte) canonical encoding for hashing. All three fields
    /// are fixed `u32` big-endian, so the boundary against any following
    /// variable field is unambiguous without a length prefix.
    fn encode(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.page.to_be_bytes());
        out[4..8].copy_from_slice(&self.x.to_be_bytes());
        out[8..12].copy_from_slice(&self.y.to_be_bytes());
        out
    }

    /// Canonical sort key: page, then row (`y`), then column (`x`).
    fn sort_key(&self) -> (u32, u32, u32) {
        (self.page, self.y, self.x)
    }
}

#[derive(Debug, Error)]
pub enum RedactionTileError {
    #[error("pedersen: {0}")]
    Pedersen(#[from] PedersenError),
    #[error("revealed tile {0:?} has no bytes in the artifact")]
    MissingArtifactTile(TileCoord),
    #[error("revealed tile {0:?} bytes do not open to its committed leaf")]
    RevealedTileMismatch(TileCoord),
    #[error("recomputed tiles root does not match the bundle's original_root")]
    RootMismatch,
    #[error("bundle signature is invalid")]
    BadSignature,
    #[error("bundle signature bytes are malformed")]
    MalformedSignature,
    #[error("bundle has no tiles")]
    EmptyBundle,
}

// ── Per-tile commitment ──────────────────────────────────────────────────────

/// Derive the content-binding Pedersen message scalar `m_i ∈ [0, l)` for a tile.
///
/// `m_i = reduce_l( BLAKE3_XOF( REDACTION_TILE_PREFIX || coord(12B) || lp(tile_bytes) )[..64] )`.
///
/// The 64-byte XOF read reduced mod the Baby Jubjub subgroup order `l` gives a
/// distribution whose statistical distance from uniform over `[0, l)` is
/// `< 2⁻²⁵⁶` — and, critically, always in range, so [`pedersen::commit`] never
/// rejects it with `ScalarOutOfRange`. `tile_bytes` is length-prefixed so its
/// bytes can never shift across the fixed-width coordinate prefix.
pub fn tile_message_scalar(coord: TileCoord, tile_bytes: &[u8]) -> Fr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REDACTION_TILE_PREFIX);
    hasher.update(&coord.encode());
    hasher.update(&lp(tile_bytes));
    let mut reader = hasher.finalize_xof();
    let mut wide = [0u8; 64];
    reader.fill(&mut wide);
    let reduced = BigInt::from_bytes_be(Sign::Plus, &wide) % bjj_subgroup_order();
    bigint_to_ark(&reduced)
}

/// Commit a single tile: `C_i = m_i·G + blinding·H`, returning the commitment
/// and its compressed 32-byte leaf.
pub fn commit_tile(
    coord: TileCoord,
    tile_bytes: &[u8],
    blinding: Fr,
) -> Result<(PedersenCommitment, TileLeaf), RedactionTileError> {
    let m = tile_message_scalar(coord, tile_bytes);
    let c = pedersen::commit(m, blinding)?;
    let leaf = c.compress()?;
    Ok((c, leaf))
}

// ── Merkle root over tile leaves ─────────────────────────────────────────────

/// Positional BLAKE3 Merkle root over `leaves` (in the given order), padded to
/// the next power of two with the empty-leaf sentinel and folded pairwise with
/// `olympus_crypto::node_hash`. Order-sensitive by construction.
///
/// An empty slice maps to `empty_leaf()` (degenerate; real seals always have
/// ≥ 1 tile and [`seal`] rejects empty input upstream).
pub fn tiles_root(leaves: &[TileLeaf]) -> [u8; 32] {
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

// ── Issuer: seal ─────────────────────────────────────────────────────────────

/// One sealed tile: its location, committed leaf, and the secret blinding the
/// issuer retains (revealed in the bundle only for non-redacted tiles).
#[derive(Debug, Clone)]
pub struct SealedTile {
    pub coord: TileCoord,
    pub leaf: TileLeaf,
    pub blinding: Fr,
}

/// The issuer-side seal: commit every tile of the original render and fold the
/// leaves into `original_root`. Input is `(coord, tile_bytes)`; tiles are sorted
/// into canonical `(page, y, x)` order before committing so the root is
/// deterministic. Blindings are drawn from [`pedersen::random_blinding`].
///
/// Returns `(original_root, sealed_tiles)` in canonical order. The caller
/// anchors `original_root` and stores `sealed_tiles` with the sealed original.
pub fn seal<R: rand::RngCore + rand::CryptoRng>(
    tiles: &[(TileCoord, Vec<u8>)],
    rng: &mut R,
) -> Result<([u8; 32], Vec<SealedTile>), RedactionTileError> {
    if tiles.is_empty() {
        return Err(RedactionTileError::EmptyBundle);
    }
    let mut ordered: Vec<&(TileCoord, Vec<u8>)> = tiles.iter().collect();
    ordered.sort_by_key(|(c, _)| c.sort_key());

    let mut sealed = Vec::with_capacity(ordered.len());
    for (coord, bytes) in ordered {
        let blinding = pedersen::random_blinding(rng);
        let (_c, leaf) = commit_tile(*coord, bytes, blinding)?;
        sealed.push(SealedTile {
            coord: *coord,
            leaf,
            blinding,
        });
    }
    let leaves: Vec<TileLeaf> = sealed.iter().map(|s| s.leaf).collect();
    Ok((tiles_root(&leaves), sealed))
}

// ── Bundle ───────────────────────────────────────────────────────────────────

/// One tile entry in a redaction bundle. `leaf` is always present (it folds into
/// the root); `revealed_blinding` is `Some` iff the tile is *revealed*, in which
/// case the recipient recomputes `leaf` from the artifact bytes + this blinding.
/// `None` marks a redacted tile — its content and blinding are withheld.
#[derive(Debug, Clone)]
pub struct TileEntry {
    pub coord: TileCoord,
    pub leaf: TileLeaf,
    pub revealed_blinding: Option<Fr>,
}

/// A recipient-bound, authority-signed redaction bundle.
#[derive(Debug, Clone)]
pub struct RedactionBundle {
    pub original_root: [u8; 32],
    pub recipient_id: String,
    /// Tiles in canonical `(page, y, x)` order (as folded into `original_root`).
    pub tiles: Vec<TileEntry>,
    /// Ed25519 signature over [`descriptor_digest`] (64 bytes).
    pub signature: Vec<u8>,
}

/// Domain-separated digest the authority signs. Binds the sealed root, the
/// recipient, and the full ordered tile set (each tile's coord, redaction flag,
/// and leaf), so the signature is non-replayable across documents/recipients
/// and any tampering with a leaf or flag invalidates it.
fn descriptor_digest(
    original_root: &[u8; 32],
    recipient_id: &str,
    tiles: &[TileEntry],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REDACTION_BUNDLE_PREFIX);
    hasher.update(&lp(original_root));
    hasher.update(&lp(recipient_id.as_bytes()));
    hasher.update(&(tiles.len() as u32).to_be_bytes());
    for t in tiles {
        hasher.update(&t.coord.encode());
        hasher.update(&[u8::from(t.revealed_blinding.is_some())]);
        hasher.update(&t.leaf);
    }
    *hasher.finalize().as_bytes()
}

/// Assemble and sign a bundle from sealed tiles.
///
/// `redacted` is the set of coordinates to hide; every other sealed tile is
/// revealed (its blinding is published). Tiles are emitted in canonical
/// `(page, y, x)` order to match `original_root`.
pub fn build_bundle(
    original_root: [u8; 32],
    recipient_id: &str,
    sealed: &[SealedTile],
    redacted: &std::collections::HashSet<TileCoord>,
    signing_key: &SigningKey,
) -> RedactionBundle {
    let mut ordered: Vec<&SealedTile> = sealed.iter().collect();
    ordered.sort_by_key(|s| s.coord.sort_key());

    let tiles: Vec<TileEntry> = ordered
        .iter()
        .map(|s| TileEntry {
            coord: s.coord,
            leaf: s.leaf,
            revealed_blinding: if redacted.contains(&s.coord) {
                None
            } else {
                Some(s.blinding)
            },
        })
        .collect();

    let digest = descriptor_digest(&original_root, recipient_id, &tiles);
    let signature = signing_key.sign(&digest).to_bytes().to_vec();
    RedactionBundle {
        original_root,
        recipient_id: recipient_id.to_string(),
        tiles,
        signature,
    }
}

/// Verify a redaction bundle against the redacted artifact's **revealed** tiles.
///
/// `artifact_tiles` maps each *revealed* tile's coordinate to its bytes as read
/// from the redacted artifact. Redacted tiles need not (and should not) appear.
///
/// Checks, in order:
///   1. the authority signature over the descriptor digest;
///   2. each revealed tile opens to its published leaf from the artifact bytes;
///   3. all leaves fold to `original_root`.
///
/// Returns `Ok(())` iff the bundle is a faithful redaction of the sealed
/// original for this recipient.
pub fn verify_bundle(
    bundle: &RedactionBundle,
    artifact_tiles: &HashMap<TileCoord, Vec<u8>>,
    verifying_key: &VerifyingKey,
) -> Result<(), RedactionTileError> {
    if bundle.tiles.is_empty() {
        return Err(RedactionTileError::EmptyBundle);
    }

    // 1. Signature first (cheap reject before any curve work).
    let sig = Signature::from_slice(&bundle.signature)
        .map_err(|_| RedactionTileError::MalformedSignature)?;
    let digest = descriptor_digest(&bundle.original_root, &bundle.recipient_id, &bundle.tiles);
    verifying_key
        .verify_strict(&digest, &sig)
        .map_err(|_| RedactionTileError::BadSignature)?;

    // 2. Revealed-tile authenticity.
    for t in &bundle.tiles {
        if let Some(blinding) = t.revealed_blinding {
            let bytes = artifact_tiles
                .get(&t.coord)
                .ok_or(RedactionTileError::MissingArtifactTile(t.coord))?;
            let (_c, recomputed) = commit_tile(t.coord, bytes, blinding)?;
            // Constant-time not required: both sides are public leaves; the
            // secret (the redacted content) is never an input here.
            if recomputed != t.leaf {
                return Err(RedactionTileError::RevealedTileMismatch(t.coord));
            }
        }
    }

    // 3. Root binding over all leaves (revealed + redacted) in bundle order.
    let leaves: Vec<TileLeaf> = bundle.tiles.iter().map(|t| t.leaf).collect();
    if tiles_root(&leaves) != bundle.original_root {
        return Err(RedactionTileError::RootMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn coord(page: u32, x: u32, y: u32) -> TileCoord {
        TileCoord { page, x, y }
    }

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Build a small page of tiles `(coord, bytes)` with distinct content.
    fn sample_tiles() -> Vec<(TileCoord, Vec<u8>)> {
        vec![
            (coord(0, 0, 0), b"top-left visible text".to_vec()),
            (coord(0, 1, 0), b"top-right visible text".to_vec()),
            (
                coord(0, 0, 1),
                b"bottom-left SECRET ssn 123-45-6789".to_vec(),
            ),
            (coord(0, 1, 1), b"bottom-right visible text".to_vec()),
            (coord(0, 0, 2), b"footer".to_vec()),
        ]
    }

    // ── tile_message_scalar ──────────────────────────────────────────────────

    #[test]
    fn message_scalar_is_deterministic_and_in_range() {
        let c = coord(3, 2, 1);
        let m1 = tile_message_scalar(c, b"hello tile");
        let m2 = tile_message_scalar(c, b"hello tile");
        assert_eq!(m1, m2, "derivation must be deterministic");
        // In range ⇒ commit accepts it (commit rejects scalars ≥ l).
        assert!(
            pedersen::commit(m1, Fr::from(1u64)).is_ok(),
            "m must be a valid in-[0,l) subgroup scalar"
        );
    }

    #[test]
    fn message_scalar_depends_on_coord_and_bytes() {
        let base = tile_message_scalar(coord(0, 0, 0), b"abc");
        assert_ne!(base, tile_message_scalar(coord(1, 0, 0), b"abc"), "page");
        assert_ne!(base, tile_message_scalar(coord(0, 1, 0), b"abc"), "x");
        assert_ne!(base, tile_message_scalar(coord(0, 0, 1), b"abc"), "y");
        assert_ne!(base, tile_message_scalar(coord(0, 0, 0), b"abd"), "bytes");
    }

    #[test]
    fn message_scalar_length_prefix_prevents_byte_shift() {
        // Without lp(tile_bytes), ("ab" at x with following field) could collide
        // with ("a" ...). The fixed-width coord + lp(bytes) keep them distinct.
        let a = tile_message_scalar(coord(0, 0, 0), b"ab");
        let b = tile_message_scalar(coord(0, 0, 0), b"a");
        assert_ne!(a, b);
    }

    // ── tiles_root ───────────────────────────────────────────────────────────

    #[test]
    fn root_is_deterministic_and_order_sensitive() {
        let l0 = [1u8; 32];
        let l1 = [2u8; 32];
        let l2 = [3u8; 32];
        let r = tiles_root(&[l0, l1, l2]);
        assert_eq!(r, tiles_root(&[l0, l1, l2]), "deterministic");
        assert_ne!(r, tiles_root(&[l1, l0, l2]), "order-sensitive");
    }

    #[test]
    fn single_leaf_root_pads_with_empty_sentinel() {
        // One leaf pads to a 1-wide tree → the leaf is the root (next_pow2(1)=1).
        let l0 = [9u8; 32];
        assert_eq!(tiles_root(&[l0]), l0);
        // Two leaves fold once.
        let l1 = [8u8; 32];
        assert_eq!(tiles_root(&[l0, l1]), node_hash(&l0, &l1));
    }

    // ── seal + build + verify happy path ─────────────────────────────────────

    #[test]
    fn seal_build_verify_roundtrip_with_redaction() {
        let mut rng = rand::thread_rng();
        let tiles = sample_tiles();
        let (root, sealed) = seal(&tiles, &mut rng).expect("seal");

        // Redact the secret tile.
        let secret = coord(0, 0, 1);
        let redacted: HashSet<TileCoord> = [secret].into_iter().collect();

        let sk = test_key();
        let bundle = build_bundle(root, "recipient-1", &sealed, &redacted, &sk);

        // The recipient's artifact has every *revealed* tile's bytes (the
        // redacted one is blanked, so it is absent).
        let artifact: HashMap<TileCoord, Vec<u8>> = tiles
            .iter()
            .filter(|(c, _)| *c != secret)
            .map(|(c, b)| (*c, b.clone()))
            .collect();

        verify_bundle(&bundle, &artifact, &sk.verifying_key()).expect("bundle must verify");
    }

    #[test]
    fn redacted_tile_need_not_be_in_artifact() {
        // The redacted tile is blanked in the artifact; verification must not
        // require its (original) bytes.
        let mut rng = rand::thread_rng();
        let tiles = sample_tiles();
        let (root, sealed) = seal(&tiles, &mut rng).expect("seal");
        let secret = coord(0, 0, 1);
        let redacted: HashSet<TileCoord> = [secret].into_iter().collect();
        let sk = test_key();
        let bundle = build_bundle(root, "r", &sealed, &redacted, &sk);

        let artifact: HashMap<TileCoord, Vec<u8>> = tiles
            .iter()
            .filter(|(c, _)| *c != secret)
            .map(|(c, b)| (*c, b.clone()))
            .collect();
        assert!(verify_bundle(&bundle, &artifact, &sk.verifying_key()).is_ok());
    }

    // ── Negative cases ───────────────────────────────────────────────────────

    #[test]
    fn tampered_revealed_tile_bytes_are_rejected() {
        let mut rng = rand::thread_rng();
        let tiles = sample_tiles();
        let (root, sealed) = seal(&tiles, &mut rng).expect("seal");
        let secret = coord(0, 0, 1);
        let redacted: HashSet<TileCoord> = [secret].into_iter().collect();
        let sk = test_key();
        let bundle = build_bundle(root, "r", &sealed, &redacted, &sk);

        // Flip a byte in a *revealed* tile's artifact bytes.
        let mut artifact: HashMap<TileCoord, Vec<u8>> = tiles
            .iter()
            .filter(|(c, _)| *c != secret)
            .map(|(c, b)| (*c, b.clone()))
            .collect();
        artifact.insert(coord(0, 0, 0), b"TAMPERED visible text".to_vec());

        let err = verify_bundle(&bundle, &artifact, &sk.verifying_key()).unwrap_err();
        assert!(matches!(err, RedactionTileError::RevealedTileMismatch(c) if c == coord(0, 0, 0)));
    }

    #[test]
    fn tampered_leaf_breaks_root_or_signature() {
        let mut rng = rand::thread_rng();
        let tiles = sample_tiles();
        let (root, sealed) = seal(&tiles, &mut rng).expect("seal");
        let redacted: HashSet<TileCoord> = [coord(0, 0, 1)].into_iter().collect();
        let sk = test_key();
        let mut bundle = build_bundle(root, "r", &sealed, &redacted, &sk);

        // Tamper a redacted tile's leaf *after* signing. The signature covers
        // the leaf, so this trips BadSignature (and would also fail the root).
        if let Some(t) = bundle.tiles.iter_mut().find(|t| t.coord == coord(0, 0, 1)) {
            t.leaf[0] ^= 0xFF;
        }
        let artifact: HashMap<TileCoord, Vec<u8>> = tiles
            .iter()
            .filter(|(c, _)| *c != coord(0, 0, 1))
            .map(|(c, b)| (*c, b.clone()))
            .collect();
        let err = verify_bundle(&bundle, &artifact, &sk.verifying_key()).unwrap_err();
        assert!(matches!(err, RedactionTileError::BadSignature));
    }

    #[test]
    fn wrong_recipient_breaks_signature() {
        let mut rng = rand::thread_rng();
        let tiles = sample_tiles();
        let (root, sealed) = seal(&tiles, &mut rng).expect("seal");
        let redacted: HashSet<TileCoord> = [coord(0, 0, 1)].into_iter().collect();
        let sk = test_key();
        let mut bundle = build_bundle(root, "alice", &sealed, &redacted, &sk);
        bundle.recipient_id = "mallory".to_string();

        let artifact: HashMap<TileCoord, Vec<u8>> = tiles
            .iter()
            .filter(|(c, _)| *c != coord(0, 0, 1))
            .map(|(c, b)| (*c, b.clone()))
            .collect();
        assert!(matches!(
            verify_bundle(&bundle, &artifact, &sk.verifying_key()),
            Err(RedactionTileError::BadSignature)
        ));
    }

    #[test]
    fn wrong_verifying_key_is_rejected() {
        let mut rng = rand::thread_rng();
        let tiles = sample_tiles();
        let (root, sealed) = seal(&tiles, &mut rng).expect("seal");
        let redacted: HashSet<TileCoord> = [coord(0, 0, 1)].into_iter().collect();
        let sk = test_key();
        let bundle = build_bundle(root, "r", &sealed, &redacted, &sk);
        let other = SigningKey::from_bytes(&[9u8; 32]);

        let artifact: HashMap<TileCoord, Vec<u8>> = tiles
            .iter()
            .filter(|(c, _)| *c != coord(0, 0, 1))
            .map(|(c, b)| (*c, b.clone()))
            .collect();
        assert!(matches!(
            verify_bundle(&bundle, &artifact, &other.verifying_key()),
            Err(RedactionTileError::BadSignature)
        ));
    }

    #[test]
    fn missing_revealed_artifact_tile_is_rejected() {
        let mut rng = rand::thread_rng();
        let tiles = sample_tiles();
        let (root, sealed) = seal(&tiles, &mut rng).expect("seal");
        let redacted: HashSet<TileCoord> = [coord(0, 0, 1)].into_iter().collect();
        let sk = test_key();
        let bundle = build_bundle(root, "r", &sealed, &redacted, &sk);

        // Drop a *revealed* tile from the artifact.
        let mut artifact: HashMap<TileCoord, Vec<u8>> = tiles
            .iter()
            .filter(|(c, _)| *c != coord(0, 0, 1))
            .map(|(c, b)| (*c, b.clone()))
            .collect();
        artifact.remove(&coord(0, 1, 1));
        assert!(matches!(
            verify_bundle(&bundle, &artifact, &sk.verifying_key()),
            Err(RedactionTileError::MissingArtifactTile(c)) if c == coord(0, 1, 1)
        ));
    }

    #[test]
    fn malformed_signature_bytes_are_rejected() {
        let mut rng = rand::thread_rng();
        let tiles = sample_tiles();
        let (root, sealed) = seal(&tiles, &mut rng).expect("seal");
        let redacted: HashSet<TileCoord> = [coord(0, 0, 1)].into_iter().collect();
        let sk = test_key();
        let mut bundle = build_bundle(root, "r", &sealed, &redacted, &sk);
        bundle.signature = vec![0u8; 10]; // wrong length

        let artifact: HashMap<TileCoord, Vec<u8>> = HashMap::new();
        assert!(matches!(
            verify_bundle(&bundle, &artifact, &sk.verifying_key()),
            Err(RedactionTileError::MalformedSignature)
        ));
    }

    // ── Hiding (ADR-0023 BLOCKING invariant) ─────────────────────────────────

    #[test]
    fn redacted_tile_content_is_not_recoverable_from_leaf() {
        // Perfect hiding: the published leaf C_i for a redacted tile reveals
        // nothing about its content. Concretely, committing the SAME low-entropy
        // content under many blindings yields all-distinct leaves — so an
        // attacker who guesses the content correctly still cannot confirm the
        // guess without the (withheld) blinding. There is therefore no
        // content→leaf mapping to brute-force.
        let secret = b"SSN 123-45-6789"; // low-entropy, guessable format
        let c = coord(0, 0, 1);
        let mut rng = rand::thread_rng();

        let mut seen = HashSet::new();
        for _ in 0..256 {
            let b = pedersen::random_blinding(&mut rng);
            let (_c, leaf) = commit_tile(c, secret, b).expect("commit");
            assert!(
                seen.insert(leaf),
                "same content under different blindings must give distinct leaves"
            );
        }
    }

    #[test]
    fn guessing_content_without_blinding_does_not_match_leaf() {
        // Even with the exact content, the wrong blinding does not open the leaf.
        let secret = b"SSN 123-45-6789";
        let c = coord(0, 0, 1);
        let mut rng = rand::thread_rng();
        let real_b = pedersen::random_blinding(&mut rng);
        let (_c, real_leaf) = commit_tile(c, secret, real_b).expect("commit");

        let guess_b = pedersen::random_blinding(&mut rng);
        let (_c2, guess_leaf) = commit_tile(c, secret, guess_b).expect("commit");
        assert_ne!(
            real_leaf, guess_leaf,
            "correct content + wrong blinding must not reproduce the leaf"
        );
    }

    #[test]
    fn empty_seal_is_rejected() {
        let mut rng = rand::thread_rng();
        assert!(matches!(
            seal(&[], &mut rng),
            Err(RedactionTileError::EmptyBundle)
        ));
    }

    // ── Golden-vector generator (cross-language parity, ADR-0023) ─────────────
    //
    // `#[ignore]` because it WRITES a file. Run explicitly to (re)generate the
    // shared tile-redaction vectors consumed by verifiers/{rust,javascript}:
    //
    //   cargo test -p olympus-desktop redaction_tile::tests::gen_tile_redaction_vectors \
    //       -- --ignored --nocapture
    //
    // Deterministic: fixed blindings + fixed Ed25519 key, so reruns are stable
    // (byte-identical) unless the commitment scheme itself changes — in which
    // case both verifiers must move with it in the same commit (Critical
    // Invariant: commitment-format change ⇒ olympus-crypto + both verifiers +
    // vectors together).
    #[test]
    #[ignore = "writes verifiers/test_vectors/tile_redaction_vectors.json"]
    fn gen_tile_redaction_vectors() {
        use crate::zk::witness::baby_jubjub::ark_fr_to_bigint;
        use serde_json::json;

        let dec = |f: &Fr| ark_fr_to_bigint(f).to_string();

        // Deterministic fixture page: a 2×2 grid + footer (canonical (page,y,x)
        // order). The bottom-left tile carries the "secret" and is redacted.
        let fixture: Vec<(TileCoord, &[u8])> = vec![
            (coord(0, 0, 0), b"top-left visible text"),
            (coord(0, 1, 0), b"top-right visible text"),
            (coord(0, 0, 1), b"bottom-left SECRET ssn 123-45-6789"),
            (coord(0, 1, 1), b"bottom-right visible text"),
            (coord(0, 0, 2), b"footer"),
        ];
        let secret = coord(0, 0, 1);

        // Per-tile fixed blindings (small ⇒ trivially < l), deterministic.
        let blindings: Vec<Fr> = (0..fixture.len())
            .map(|i| Fr::from(1001u64 + i as u64))
            .collect();

        // tile_message_scalars + tile_leaves (single-tile commitment vectors).
        let mut scalar_vecs = Vec::new();
        let mut leaf_vecs = Vec::new();
        let mut sealed = Vec::new();
        for (i, (c, bytes)) in fixture.iter().enumerate() {
            let m = tile_message_scalar(*c, bytes);
            let (commitment, leaf) = commit_tile(*c, bytes, blindings[i]).expect("commit");
            scalar_vecs.push(json!({
                "page": c.page, "x": c.x, "y": c.y,
                "tile_bytes_hex": hex::encode(bytes),
                "m_decimal": dec(&m),
            }));
            leaf_vecs.push(json!({
                "page": c.page, "x": c.x, "y": c.y,
                "tile_bytes_hex": hex::encode(bytes),
                "blinding_decimal": dec(&blindings[i]),
                "m_decimal": dec(&m),
                "commitment_x_decimal": dec(&commitment.x),
                "commitment_y_decimal": dec(&commitment.y),
                "leaf_compressed_hex": hex::encode(leaf),
            }));
            sealed.push(SealedTile {
                coord: *c,
                leaf,
                blinding: blindings[i],
            });
        }

        // tiles_root vectors: the full fixture set + a 1-leaf + a 2-leaf case.
        let leaves: Vec<TileLeaf> = sealed.iter().map(|s| s.leaf).collect();
        let root = tiles_root(&leaves);
        let root_vecs = json!([
            {
                "description": "fixture page (5 tiles, padded to 8)",
                "leaves_hex": leaves.iter().map(hex::encode).collect::<Vec<_>>(),
                "root_hex": hex::encode(root),
            },
            {
                "description": "single leaf (root == leaf)",
                "leaves_hex": [hex::encode(leaves[0])],
                "root_hex": hex::encode(tiles_root(&[leaves[0]])),
            },
            {
                "description": "two leaves (one node_hash fold)",
                "leaves_hex": [hex::encode(leaves[0]), hex::encode(leaves[1])],
                "root_hex": hex::encode(tiles_root(&[leaves[0], leaves[1]])),
            },
        ]);

        // Full bundle vector.
        let recipient_id = "court-recipient-1";
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let redacted: HashSet<TileCoord> = [secret].into_iter().collect();
        let bundle = build_bundle(root, recipient_id, &sealed, &redacted, &sk);

        let tiles_json: Vec<_> = bundle
            .tiles
            .iter()
            .map(|t| {
                json!({
                    "page": t.coord.page, "x": t.coord.x, "y": t.coord.y,
                    "leaf_compressed_hex": hex::encode(t.leaf),
                    "revealed_blinding_decimal": t.revealed_blinding.map(|b| dec(&b)),
                })
            })
            .collect();
        let artifact_json: Vec<_> = fixture
            .iter()
            .filter(|(c, _)| *c != secret)
            .map(|(c, bytes)| {
                json!({
                    "page": c.page, "x": c.x, "y": c.y,
                    "tile_bytes_hex": hex::encode(bytes),
                })
            })
            .collect();

        let bundle_json = json!({
            "description": "1 redacted tile (bottom-left secret), 4 revealed",
            "original_root_hex": hex::encode(bundle.original_root),
            "recipient_id": bundle.recipient_id,
            "signer_ed25519_pubkey_hex": hex::encode(sk.verifying_key().to_bytes()),
            "signature_hex": hex::encode(&bundle.signature),
            "tiles": tiles_json,
            "artifact_tiles": artifact_json,
            "expected_valid": true,
        });

        let out = json!({
            "version": "1",
            "description": "ADR-0023 rasterized tile-redaction commitment vectors. \
                            Pedersen tile leaves on Baby Jubjub (OLY:PEDERSEN:H:V1); \
                            message scalar OLY:REDACTION:TILE:V1; bundle digest \
                            OLY:REDACTION:BUNDLE:V1 signed with Ed25519.",
            "domain_separation": {
                "tile_prefix": "OLY:REDACTION:TILE:V1",
                "bundle_prefix": "OLY:REDACTION:BUNDLE:V1",
                "node_prefix": "OLY:NODE:V1",
                "empty_leaf_prefix": "OLY:EMPTY-LEAF:V1",
            },
            "tile_message_scalars": scalar_vecs,
            "tile_leaves": leaf_vecs,
            "tiles_root": root_vecs,
            "bundle": bundle_json,
        });

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../verifiers/test_vectors/tile_redaction_vectors.json");
        let pretty = serde_json::to_string_pretty(&out).expect("serialize vectors");
        std::fs::write(&path, format!("{pretty}\n")).expect("write tile_redaction_vectors.json");
        eprintln!("wrote {} ({} bytes)", path.display(), pretty.len());
    }
}
