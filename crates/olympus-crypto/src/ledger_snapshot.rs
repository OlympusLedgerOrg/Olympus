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

/// Parse a hex field element. Audit L-19: strict canonical decode —
/// exactly 64 lowercase hex chars (32 bytes, big-endian). Earlier revisions
/// right-aligned shorter inputs, which meant `"01"` and 62-zero-padded
/// `"…01"` both decoded to `Fr::from(1)`. No production caller emits
/// short hex (all go through `fr_to_hex`, which always produces 64 chars),
/// so tightening here removes a wire-level ambiguity without breaking any
/// legitimate path. Uppercase hex is also rejected so two different
/// on-wire strings cannot map to the same `Fr`.
fn hex_to_fr(s: &str) -> Option<Fr> {
    if s.len() != 64 {
        return None;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Some(Fr::from_be_bytes_mod_order(&buf))
}

/// arkworks Fr → non-negative BigInt (for handing to babyjubjub-rs).
fn ark_fr_to_bigint(f: &Fr) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &f.into_bigint().to_bytes_be())
}

/// arkworks Fr → babyjubjub-rs' iden3 Fr (via decimal string round-trip).
/// `ff_ce::PrimeField` is the trait that provides `from_str` on the iden3 Fr.
///
/// DO NOT inline this with a direct byte copy. The iden3 `Fr` has a
/// different internal limb layout than arkworks `Fr` (different limb
/// width, different Montgomery form parameters). The decimal-string
/// detour is slow but correct; any "optimization" that copies bytes
/// across the boundary will produce silently-wrong field elements that
/// pass arithmetic but fail signature verification (audit L-AS-1).
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

    /// iden3 `Fr` (from `babyjubjub-rs`) → arkworks `Fr`. Used in tests to
    /// translate `Point.x/y` and signature components into the hex strings
    /// the verifier expects. Mirrors the desktop side's `iden3_to_ark`.
    fn iden3_to_ark(f: &babyjubjub_rs::Fr) -> Fr {
        use ff_ce::PrimeField as FfPrimeField;
        let repr = f.into_repr();
        let mut bytes_le = Vec::with_capacity(32);
        for limb in repr.0.iter() {
            bytes_le.extend_from_slice(&limb.to_le_bytes());
        }
        Fr::from_le_bytes_mod_order(&bytes_le)
    }

    /// num_bigint `BigInt` → arkworks `Fr` (for the signature `s` scalar).
    fn bigint_to_ark(n: &BigInt) -> Fr {
        let (_, bytes_le) = n.to_bytes_le();
        Fr::from_le_bytes_mod_order(&bytes_le)
    }

    /// End-to-end: build a one-leaf snapshot, sign its digest with a real
    /// BJJ key, hand the resulting fields to `verify_snapshot`, and confirm
    /// it accepts. This is the parity test that exercises every helper:
    /// - `signing_digest` (verifier-side) must produce the same `Fr` the
    ///   signer signed over;
    /// - `ark_fr_to_bigint` must round-trip the digest + s to the same
    ///   `BigInt` `babyjubjub_rs::verify` expects;
    /// - `ark_to_iden3` must convert pubkey + R8 components back to iden3
    ///   `Fr` exactly so the curve point reconstruction matches.
    ///
    /// Replacing any of these helpers with `Default::default()` / `None`
    /// breaks one of the equalities above and the assertion fails — i.e.
    /// kills the cargo-mutants survivors that the earlier reject-only
    /// tests left alive.
    #[test]
    fn bjj_signed_snapshot_roundtrips() {
        use babyjubjub_rs::PrivateKey;

        // Deterministic small-bytes key — well-formed for PrivateKey::import.
        let sk_bytes: Vec<u8> = (1u8..=32u8).collect();
        let sk = PrivateKey::import(sk_bytes).unwrap();
        let pk_point = sk.public();

        // Single-leaf snapshot (siblings = empty subtree hashes per level).
        let empty = empty_chain();
        let leaf = Fr::from(987_654_321u64);
        let path_elements: Vec<Fr> = (0..SNAPSHOT_DEPTH).map(|d| empty[d]).collect();
        let path_indices = vec![0u8; SNAPSHOT_DEPTH];
        let root = reconstruct_root(leaf, &path_elements, &path_indices).unwrap();

        let snapshot_root_hex = fr_to_hex(root);
        let leaf_hex = fr_to_hex(leaf);
        let content_hash = "cd".repeat(32);
        let original_root = leaf_hex.clone();

        let digest = signing_digest(
            &snapshot_root_hex,
            &leaf_hex,
            0,
            1,
            &content_hash,
            &original_root,
        )
        .expect("digest");

        // Sign the digest with the BJJ key. The verifier will recompute the
        // identical digest from the snapshot fields; if it doesn't, the
        // signature won't validate.
        let sig = sk.sign(ark_fr_to_bigint(&digest)).expect("sign");

        let snap = LedgerSnapshot {
            snapshot_root: snapshot_root_hex,
            snapshot_index: 0,
            snapshot_size: 1,
            path_elements_hex: path_elements.iter().map(|f| fr_to_hex(*f)).collect(),
            path_indices,
            signature_r8x: fr_to_hex(iden3_to_ark(&sig.r_b8.x)),
            signature_r8y: fr_to_hex(iden3_to_ark(&sig.r_b8.y)),
            signature_s: fr_to_hex(bigint_to_ark(&sig.s)),
        };

        let pk_x = iden3_to_ark(&pk_point.x);
        let pk_y = iden3_to_ark(&pk_point.y);
        assert!(verify_snapshot(
            &snap,
            &content_hash,
            &original_root,
            pk_x,
            pk_y
        ));

        // Negative control: any tampered field must reject. Catches mutations
        // that would short-circuit verify_snapshot to always-true.
        assert!(!verify_snapshot(
            &snap,
            &"ee".repeat(32),
            &original_root,
            pk_x,
            pk_y
        ));
        let imposter = PrivateKey::import((10u8..=41u8).collect()).unwrap();
        let imposter_pk = imposter.public();
        assert!(!verify_snapshot(
            &snap,
            &content_hash,
            &original_root,
            iden3_to_ark(&imposter_pk.x),
            iden3_to_ark(&imposter_pk.y),
        ));
    }

    /// Phase 4-prep e2e gate: a snapshot signed by the NEW
    /// `babyjubjub-permissive` signer must verify through THIS module's
    /// `verify_snapshot` — which still runs the legacy `babyjubjub-rs`
    /// verifier. This is the cross-impl acceptance check the review
    /// required before swapping the snapshot signer: it proves the new
    /// signer's `(R8, s)` is accepted by the live verifier, not merely by
    /// the new crate's own `verify`. If this passes, swapping
    /// `verify_snapshot`'s internals to the new crate cannot change which
    /// signatures it accepts for snapshots minted by the new signer.
    #[test]
    fn new_impl_signed_snapshot_verifies_through_legacy_verify_snapshot() {
        use ark_ff::{BigInteger, PrimeField};
        use babyjubjub_permissive::PrivateKey;

        // Same single-leaf snapshot shape as bjj_signed_snapshot_roundtrips.
        let sk_bytes = [7u8; 32];
        let sk = PrivateKey::from_bytes(&sk_bytes).expect("32-byte sk");

        let empty = empty_chain();
        let leaf = Fr::from(555_111_999u64);
        let path_elements: Vec<Fr> = (0..SNAPSHOT_DEPTH).map(|d| empty[d]).collect();
        let path_indices = vec![0u8; SNAPSHOT_DEPTH];
        let root = reconstruct_root(leaf, &path_elements, &path_indices).unwrap();

        let snapshot_root_hex = fr_to_hex(root);
        let leaf_hex = fr_to_hex(leaf);
        let content_hash = "9a".repeat(32);
        let original_root = leaf_hex.clone();

        // The digest is an ark_bn254::Fr; the new signer takes the same type
        // (its Fq == ark_bn254::Fr), so no bridge is needed on the message.
        let digest =
            signing_digest(&snapshot_root_hex, &leaf_hex, 0, 1, &content_hash, &original_root)
                .expect("digest");
        let sig = sk.sign(digest).expect("new-impl sign");
        let pk = sk.public();
        let (pk_x, pk_y) = pk.coords();

        // R8 coords are ark_bn254::Fr (the new crate's BaseField), so
        // fr_to_hex applies directly. `s` is the subgroup field Fr (mod l);
        // its integer value is < l < q, so re-importing the bytes into the
        // module's Fr (mod q) is lossless.
        let s_ark = Fr::from_le_bytes_mod_order(&sig.s.into_bigint().to_bytes_le());

        let snap = LedgerSnapshot {
            snapshot_root: snapshot_root_hex,
            snapshot_index: 0,
            snapshot_size: 1,
            path_elements_hex: path_elements.iter().map(|f| fr_to_hex(*f)).collect(),
            path_indices,
            signature_r8x: fr_to_hex(sig.r8.x),
            signature_r8y: fr_to_hex(sig.r8.y),
            signature_s: fr_to_hex(s_ark),
        };

        assert!(
            verify_snapshot(&snap, &content_hash, &original_root, pk_x, pk_y),
            "legacy verify_snapshot must accept a signature from the new signer"
        );

        // Negative control: tampered content_hash must reject, so the
        // acceptance above is meaningful.
        assert!(
            !verify_snapshot(&snap, &"ee".repeat(32), &original_root, pk_x, pk_y),
            "tampered content_hash must be rejected"
        );
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

    // ── Targeted tests for surviving mutants ─────────────────────────────────
    //
    // The roundtrip test above kills the mutants on the helpers I added
    // (signing_digest, ark_fr_to_bigint, ark_to_iden3). The four tests
    // below target mutants in the pre-existing utility code that the
    // roundtrip test happens not to exercise — each one is structured to
    // assert something that *requires* the targeted function's real
    // implementation, so replacing it with `Default()`/`None`/`<`/`&&`
    // breaks the assertion.

    /// Kills `delete match arm 1` in `reconstruct_root` by walking a path
    /// where the leaf is a right child at the deepest level. With arm 1
    /// deleted, `path_indices[d] == 1` falls into `_` → `return None`,
    /// `reconstruct_root` returns None, `unwrap` panics, test fails.
    #[test]
    fn right_child_path_verifies() {
        use babyjubjub_rs::PrivateKey;

        let sk = PrivateKey::import((1u8..=32u8).collect::<Vec<_>>()).unwrap();
        let pk = sk.public();

        let empty = empty_chain();
        let path_elements: Vec<Fr> = (0..SNAPSHOT_DEPTH).map(|d| empty[d]).collect();
        // Leaf at logical index 1 (right child at level 0, left thereafter).
        let mut path_indices = vec![0u8; SNAPSHOT_DEPTH];
        path_indices[0] = 1;

        let leaf = Fr::from(11_111u64);
        let root = reconstruct_root(leaf, &path_elements, &path_indices).unwrap();

        let snap_root_hex = fr_to_hex(root);
        let original_root = fr_to_hex(leaf);
        let content_hash = "66".repeat(32);
        let digest = signing_digest(
            &snap_root_hex,
            &original_root,
            1,
            2,
            &content_hash,
            &original_root,
        )
        .unwrap();
        let sig = sk.sign(ark_fr_to_bigint(&digest)).unwrap();

        let snap = LedgerSnapshot {
            snapshot_root: snap_root_hex,
            snapshot_index: 1,
            snapshot_size: 2,
            path_elements_hex: path_elements.iter().map(|f| fr_to_hex(*f)).collect(),
            path_indices,
            signature_r8x: fr_to_hex(iden3_to_ark(&sig.r_b8.x)),
            signature_r8y: fr_to_hex(iden3_to_ark(&sig.r_b8.y)),
            signature_s: fr_to_hex(bigint_to_ark(&sig.s)),
        };
        assert!(verify_snapshot(
            &snap,
            &content_hash,
            &original_root,
            iden3_to_ark(&pk.x),
            iden3_to_ark(&pk.y),
        ));
    }

    /// Kills the `||` → `&&` length-guard mutations in both `reconstruct_root`
    /// (L108) and `verify_snapshot` (L146). Under `&&`, only *both* sides
    /// being the wrong length would reject; with one correct and one short,
    /// the guard wouldn't trip and the function would proceed into UB
    /// (out-of-bounds index on the shorter Vec, or pass the check).
    #[test]
    fn length_mismatch_one_side_short_rejects() {
        // path_indices short, path_elements full.
        let snap_a = LedgerSnapshot {
            snapshot_root: "00".repeat(32),
            snapshot_index: 0,
            snapshot_size: 1,
            path_elements_hex: vec!["00".repeat(32); SNAPSHOT_DEPTH],
            path_indices: vec![0u8; SNAPSHOT_DEPTH - 1], // short
            signature_r8x: "00".repeat(32),
            signature_r8y: "00".repeat(32),
            signature_s: "00".repeat(32),
        };
        assert!(!verify_snapshot(
            &snap_a,
            &"ab".repeat(32),
            &fr_to_hex(Fr::from(1u64)),
            Fr::from(1u64),
            Fr::from(2u64),
        ));

        // path_elements short, path_indices full.
        let snap_b = LedgerSnapshot {
            snapshot_root: "00".repeat(32),
            snapshot_index: 0,
            snapshot_size: 1,
            path_elements_hex: vec!["00".repeat(32); SNAPSHOT_DEPTH - 1], // short
            path_indices: vec![0u8; SNAPSHOT_DEPTH],
            signature_r8x: "00".repeat(32),
            signature_r8y: "00".repeat(32),
            signature_s: "00".repeat(32),
        };
        assert!(!verify_snapshot(
            &snap_b,
            &"ab".repeat(32),
            &fr_to_hex(Fr::from(1u64)),
            Fr::from(1u64),
            Fr::from(2u64),
        ));
    }

    /// Kills `domain_node → Default()` and `reconstruct_root → Some(Default())`
    /// by computing the expected root via raw `poseidon_hash` calls — bypassing
    /// both mutated functions — and asserting `reconstruct_root` agrees and
    /// produces a non-zero value. The earlier roundtrip test couldn't catch
    /// these because it used `reconstruct_root` in both setup and verify
    /// (mutation broke both equally, equality check still passed).
    #[test]
    fn reconstruct_root_walks_path_via_domain_node() {
        let leaf = Fr::from(424_242u64);
        let sibling = Fr::from(1_234u64);
        let mut path_elements = vec![Fr::zero(); SNAPSHOT_DEPTH];
        path_elements[0] = sibling;
        let path_indices = vec![0u8; SNAPSHOT_DEPTH];

        // Manually walk: at each level, current = poseidon(poseidon(1, left), right).
        // Uses only `poseidon_hash` directly so a mutation to `domain_node` or
        // `reconstruct_root` doesn't corrupt the expected value.
        let mut current = leaf;
        for sibling in path_elements.iter().take(SNAPSHOT_DEPTH) {
            let inner = poseidon_hash(Fr::from(1u64), current);
            current = poseidon_hash(inner, *sibling);
        }
        let expected = current;

        // The expected root must be non-zero — otherwise a mutation that always
        // returns `Fr::zero()` would coincidentally satisfy the equality below.
        assert_ne!(expected, Fr::zero());

        let actual = reconstruct_root(leaf, &path_elements, &path_indices).unwrap();
        assert_eq!(fr_to_hex(actual), fr_to_hex(expected));
    }

    /// Audit L-19: `hex_to_fr` is canonical — exactly 64 lowercase hex
    /// chars, no padding, no uppercase. Two on-wire strings must never
    /// decode to the same `Fr` (the prior right-align padding allowed
    /// "01" and "00…01" to collide).
    #[test]
    fn hex_to_fr_strict_canonical() {
        // 64 lowercase hex chars: accepted.
        assert_eq!(hex_to_fr(&"00".repeat(32)), Some(Fr::zero()));
        let one = Fr::from(1u64);
        let mut one_hex = "0".repeat(63);
        one_hex.push('1');
        assert_eq!(hex_to_fr(&one_hex), Some(one));

        // Short hex: rejected (previously right-align padded — L-19).
        assert!(hex_to_fr("01").is_none());
        assert!(hex_to_fr("").is_none());
        assert!(hex_to_fr(&"00".repeat(31)).is_none()); // 62 chars

        // Over-length hex: rejected.
        assert!(hex_to_fr(&"00".repeat(33)).is_none()); // 66 chars

        // Odd-length / non-hex / uppercase: rejected.
        assert!(hex_to_fr(&"0".repeat(63)).is_none()); // odd
        assert!(hex_to_fr(&"zz".repeat(32)).is_none()); // non-hex
        assert!(hex_to_fr(&"AB".repeat(32)).is_none()); // uppercase rejected

        // Mixed case: rejected (the lowercase emitted by `fr_to_hex`
        // is the only canonical encoding).
        let mut mixed = "0".repeat(62);
        mixed.push('A');
        mixed.push('b');
        assert!(hex_to_fr(&mixed).is_none());
    }

    /// Round-trip property: every `Fr` encoded by `fr_to_hex` decodes
    /// back to the same value via `hex_to_fr`. The canonical encoding
    /// is exactly 64 lowercase hex chars — anything else is a bug
    /// somewhere in the encoder.
    #[test]
    fn fr_to_hex_round_trips_through_hex_to_fr() {
        for raw in [0u64, 1, 2, 42, 1_000_003, u64::MAX] {
            let f = Fr::from(raw);
            let s = fr_to_hex(f);
            assert_eq!(s.len(), 64, "fr_to_hex must emit 64 chars, got {s:?}");
            assert_eq!(hex_to_fr(&s), Some(f));
        }
    }
}
