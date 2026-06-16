//! Object-level redaction commitment primitives (ADR-0025 / ADR-0026).
//!
//! The redaction circuit folds a 1024-leaf tree of per-segment commitments. To
//! keep a **redacted** segment's content un-brute-forceable (a Merkle root pins
//! an unknown leaf once its siblings are known — ADR-0026 §Security), each leaf
//! is a **hiding Pedersen commitment**, not a deterministic hash:
//!
//! ```text
//! content_i = reduce_l( BLAKE3_XOF("OLY:REDACTION:OBJ:V1" || lp(segment_id) || bytes)[..64] )
//! b_i       = reduce_l( BLAKE3_XOF("OLY:REDACTION:BLIND:V1" || lp(secret) || lp(content_hash) || lp(segment_id))[..64] )
//! C_i       = content_i·G + b_i·H              // Pedersen on Baby Jubjub (prime-order subgroup)
//! leaf_i    = Poseidon(C_i.x, C_i.y)
//! ```
//!
//! `G` is the circomlib `B8` base point; `H` is the same NUMS generator the SBT
//! Pedersen path uses (`OLY:PEDERSEN:H:V1`), derived here independently and
//! **pinned by golden test to the identical bytes** so the two derivations can
//! never silently diverge. Scalars reduce **mod `l`** (the BJJ prime-subgroup
//! order) via 64-byte wide-sampling — NOT mod `p` — because the subgroup scalar
//! range is `[0, l)` with `l ≈ p/8` (raw `mod p` would land out of range ~7/8 of
//! the time). `b_i` is derived deterministically from a server `blind_secret` so
//! re-ingesting a file is idempotent (same root) while redacted blindings stay
//! secret.
//!
//! This module is the single source of truth for the leaf computation; the
//! in-process prover (`pdf_objects`) and both offline verifiers
//! (`verifiers/{rust,javascript}`) MUST mirror it byte-for-byte.

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use babyjubjub_permissive::{
    add as bjj_add, is_identity as bjj_is_identity, is_in_prime_subgroup as bjj_in_prime_subgroup,
    mul_cofactor, mul_scalar_bigint, scalar_below_subgroup_order, subgroup_order_bigint,
    BabyJubjubAffine, B8,
};
use num_bigint::{BigInt, Sign};
use thiserror::Error;

use crate::poseidon::poseidon_hash;
use crate::{length_prefixed as lp, PEDERSEN_H_PREFIX, POSEIDON_DOMAIN_OBJ_LEAF};

/// Baby Jubjub twisted-Edwards coefficient `a` (circomlib): `a·x² + y² = 1 + d·x²·y²`.
const BJJ_A: u64 = 168700;
/// Baby Jubjub twisted-Edwards coefficient `d`.
const BJJ_D: u64 = 168696;
/// Hard cap on `H` try-and-increment iterations (first 1–2 succeed in practice).
const MAX_DERIVATION_ATTEMPTS: u32 = 64;

/// Domain tag for the deterministic per-segment blinding derivation (ADR-0026).
/// Changing it changes every redaction root; treat as frozen on first ship.
pub const REDACTION_BLIND_PREFIX: &[u8] = b"OLY:REDACTION:BLIND:V1";

/// Domain tag for the ADR-0030 **V3 redaction bundle** Ed25519 signed payload.
/// Disjoint from the V2 bundle tag and the SBT tags. Frozen on first ship.
pub const REDACTION_BUNDLE_V3_PREFIX: &[u8] = b"OLY:REDACTION_BUNDLE:V3";
/// Domain tag for the ADR-0030 V3 per-segment **table hash** (BLAKE3 preimage).
pub const REDACTION_TABLE_V3_PREFIX: &[u8] = b"OLY:REDACTION:TABLE:V3";
/// Domain tag for the ADR-0030 V3 bundle **nullifier** (BLAKE3 preimage).
pub const REDACTION_NULLIFIER_V1_PREFIX: &[u8] = b"OLY:REDACTION:NULLIFIER:V1";

/// The Baby Jubjub prime-subgroup order `l` as a `BigInt`. Re-exported so callers
/// can range-check blinding scalars without a direct `babyjubjub-permissive` dep.
pub fn subgroup_order() -> BigInt {
    subgroup_order_bigint()
}

/// True iff `s ∈ [0, l)` — the canonical Baby Jubjub blinding-scalar range
/// (ADR-0030 §2 `blinding_decimal` validation).
pub fn is_blinding_in_range(s: &BigInt) -> bool {
    s.sign() != Sign::Minus && scalar_below_subgroup_order(s)
}

/// Errors from the redaction commitment primitives.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RedactionError {
    /// A scalar fed to the Pedersen commit fell outside `[0, l)`. The helpers in
    /// this module always reduce mod `l`, so this only fires for externally
    /// supplied scalars.
    #[error(
        "Pedersen scalar `{0}` must be in [0, l) where l is the Baby Jubjub prime-subgroup order"
    )]
    ScalarOutOfRange(&'static str),
}

// ── Second generator H (NUMS, identical to the SBT Pedersen H) ───────────────

static PEDERSEN_H: OnceLock<BabyJubjubAffine> = OnceLock::new();

/// The Pedersen second generator `H` on Baby Jubjub, derived nothing-up-my-sleeve
/// from `OLY:PEDERSEN:H:V1` and cached. Byte-identical to the SBT path's `H`
/// (pinned by [`tests::h_coordinates_are_pinned`]).
pub fn pedersen_h() -> &'static BabyJubjubAffine {
    PEDERSEN_H.get_or_init(derive_pedersen_h)
}

fn fr_lex_le(a: &Fr, b: &Fr) -> bool {
    a.into_bigint().to_bytes_be() <= b.into_bigint().to_bytes_be()
}

fn derive_pedersen_h() -> BabyJubjubAffine {
    let a = Fr::from(BJJ_A);
    let d = Fr::from(BJJ_D);
    let one = Fr::one();
    let seed = blake3::hash(PEDERSEN_H_PREFIX);
    let seed_bytes = seed.as_bytes();

    for counter in 0u32..MAX_DERIVATION_ATTEMPTS {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed_bytes);
        hasher.update(&counter.to_be_bytes());
        let y = Fr::from_le_bytes_mod_order(hasher.finalize().as_bytes());

        // x² = (1 - y²) / (a - d·y²)
        let y_sq = y.square();
        let denominator = a - d * y_sq;
        if denominator.is_zero() {
            continue;
        }
        let x_sq = (one - y_sq) * denominator.inverse().expect("denominator non-zero");
        let Some(root) = x_sq.sqrt() else { continue };
        let neg_root = -root;
        let x = if fr_lex_le(&root, &neg_root) {
            root
        } else {
            neg_root
        };

        let cleared = mul_cofactor(&BabyJubjubAffine::new_unchecked(x, y));
        if bjj_is_identity(&cleared) || !bjj_in_prime_subgroup(&cleared) {
            continue;
        }
        return cleared;
    }
    panic!(
        "Pedersen H derivation failed after {MAX_DERIVATION_ATTEMPTS} attempts — \
         a bug in the sqrt/cofactor chain, not the OLY:PEDERSEN:H:V1 tag."
    );
}

// ── Scalar derivation (reduce mod l) ─────────────────────────────────────────

fn xof64(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    out
}

/// Reduce 64 wide bytes to a Baby Jubjub subgroup scalar in `[0, l)`. Wide
/// sampling keeps the statistical distance from uniform `< 2⁻²⁵⁶`.
fn reduce_mod_l(wide_be: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, wide_be) % subgroup_order_bigint()
}

/// Per-segment content scalar `content = reduce_l(BLAKE3_XOF(OBJ_PREFIX ||
/// lp(segment_id) || segment_bytes))`. `segment_id` is length-prefixed (ADR-0005)
/// so part-name / line-index / obj-id keys cannot collide by boundary shifting;
/// `segment_bytes` is last (unambiguous).
pub fn content_scalar(segment_id: &[u8], segment_bytes: &[u8]) -> BigInt {
    reduce_mod_l(&xof64(&[
        POSEIDON_DOMAIN_OBJ_LEAF.as_bytes(),
        &lp(segment_id),
        segment_bytes,
    ]))
}

/// Deterministic per-segment blinding `b = reduce_l(BLAKE3_XOF(BLIND_PREFIX ||
/// lp(blind_secret) || lp(content_hash) || lp(segment_id)))`.
///
/// Deterministic so re-ingesting the same file under the same `blind_secret`
/// reproduces the same `original_root` (ADR-0026 idempotent ingest). Hiding still
/// holds: without `blind_secret`, a revealed `b_i` says nothing about the others.
pub fn derive_blinding(blind_secret: &[u8], content_hash: &[u8], segment_id: &[u8]) -> BigInt {
    reduce_mod_l(&xof64(&[
        REDACTION_BLIND_PREFIX,
        &lp(blind_secret),
        &lp(content_hash),
        &lp(segment_id),
    ]))
}

// ── Pedersen commit + hiding leaf ────────────────────────────────────────────

fn check_subgroup(name: &'static str, s: &BigInt) -> Result<(), RedactionError> {
    if s.sign() == Sign::Minus || !scalar_below_subgroup_order(s) {
        return Err(RedactionError::ScalarOutOfRange(name));
    }
    Ok(())
}

/// Pedersen commitment `C = m·G + r·H`, returned as `(x, y)` BN254 field
/// coordinates. Both scalars must be in `[0, l)` (the [`content_scalar`] /
/// [`derive_blinding`] outputs always are).
pub fn pedersen_commit(m: &BigInt, r: &BigInt) -> Result<(Fr, Fr), RedactionError> {
    check_subgroup("m", m)?;
    check_subgroup("r", r)?;
    let mg = mul_scalar_bigint(&B8, m);
    let rh = mul_scalar_bigint(pedersen_h(), r);
    let sum = bjj_add(&mg, &rh);
    Ok((sum.x, sum.y))
}

/// The hiding circuit leaf `Poseidon(C.x, C.y)` for `C = content·G + blinding·H`.
pub fn redaction_leaf(content: &BigInt, blinding: &BigInt) -> Result<Fr, RedactionError> {
    let (cx, cy) = pedersen_commit(content, blinding)?;
    Ok(poseidon_hash(cx, cy))
}

// ── ADR-0030 §2 V3 bundle byte-layout encoders ───────────────────────────────
//
// The single source of truth for the bytes the V3 signed-Merkle redaction bundle
// commits to. The Phase-2 producer and both Phase-3 offline verifiers
// (`verifiers/{rust,javascript}`) MUST reproduce these preimages byte-for-byte —
// they are pinned by the golden-vector tests below and the cross-language
// `verifiers/test_vectors` fixtures. Per ADR-0030 §2 these functions frame
// *already-canonical* field renderings: every "reject non-canonical" rule
// (hex-case, leading-zero, out-of-range) is the **caller's** responsibility
// (producer on mint, verifier before folding) — the encoders are pure framing
// and never reduce or normalise.

/// One row of the V3 signed segment table (ADR-0030 §2). `value_text` is the
/// segment's `leaf_hex` when `redacted`, else its `blinding_decimal`; `label` is
/// the UTF-8 part name for `ooxml-part` and empty (`&[]`) for every other format.
/// Callers MUST pass entries in **strictly ascending, unique `segment_id`** order
/// — `redaction_table_hash` is order-sensitive and does not sort or dedup (the
/// ascending-unique structural check is the verifier's, §3.1).
#[derive(Debug, Clone, Copy)]
pub struct RedactionTableEntry<'a> {
    pub segment_id: u32,
    pub redacted: bool,
    pub artifact_offset: u64,
    pub artifact_length: u64,
    /// Canonical part name (UTF-8) for `ooxml-part`; `&[]` (absent) otherwise.
    pub label: &'a [u8],
    /// `leaf_hex` (redacted) or `blinding_decimal` (revealed) — already canonical.
    pub value_text: &'a str,
}

/// `table_hash = BLAKE3( REDACTION_TABLE_V3_PREFIX || for each segment in
/// ascending segment_id: u32_be(segment_id) || u8(redacted) ||
/// u64_be(artifact_offset) || u64_be(artifact_length) || lp(label) ||
/// lp(redacted ? leaf_hex : blinding_decimal) )` (ADR-0030 §2). `u8(redacted)` is
/// exactly `0x01`/`0x00`; `lp` is the ADR-0005 length prefix.
pub fn redaction_table_hash(entries: &[RedactionTableEntry]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(REDACTION_TABLE_V3_PREFIX);
    for e in entries {
        h.update(&e.segment_id.to_be_bytes());
        h.update(&[u8::from(e.redacted)]);
        h.update(&e.artifact_offset.to_be_bytes());
        h.update(&e.artifact_length.to_be_bytes());
        h.update(&lp(e.label));
        h.update(&lp(e.value_text.as_bytes()));
    }
    *h.finalize().as_bytes()
}

/// The Ed25519-signed V3 payload bytes (ADR-0030 §2):
/// `REDACTION_BUNDLE_V3_PREFIX || lp(original_root_hex) || lp(format) ||
/// u32_be(segment_count) || lp(recipient_id_dec) || table_hash`. `table_hash` is
/// appended **un-length-prefixed** as the terminal fixed-width 32-byte field. The
/// issuer signs these bytes; the verifier recomputes them and verifies the
/// signature over them.
pub fn redaction_signing_message(
    original_root_hex: &str,
    format: &str,
    segment_count: u32,
    recipient_id_dec: &str,
    table_hash: &[u8; 32],
) -> Vec<u8> {
    // A once-per-bundle, non-hot-path message: a plain `Vec` keeps the body free
    // of an un-observable capacity hint (whose arithmetic mutates without
    // changing output, i.e. spurious mutation-test survivors).
    let mut out = Vec::new();
    out.extend_from_slice(REDACTION_BUNDLE_V3_PREFIX);
    out.extend_from_slice(&lp(original_root_hex.as_bytes()));
    out.extend_from_slice(&lp(format.as_bytes()));
    out.extend_from_slice(&segment_count.to_be_bytes());
    out.extend_from_slice(&lp(recipient_id_dec.as_bytes()));
    out.extend_from_slice(table_hash);
    out
}

/// The V3 bundle nullifier (ADR-0030 §2): `BLAKE3( REDACTION_NULLIFIER_V1_PREFIX
/// || original_root_raw32 || table_hash_raw32 || lp(recipient_id_dec) )`. The two
/// 32-byte values are the **raw** root/digest bytes (not hex). It is a derived,
/// recompute-and-check field (not in the signed payload, not replay protection on
/// its own) — a stable per-`(original_root, table_hash, recipient_id)` id.
pub fn redaction_nullifier(
    original_root: &[u8; 32],
    table_hash: &[u8; 32],
    recipient_id_dec: &str,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(REDACTION_NULLIFIER_V1_PREFIX);
    h.update(original_root);
    h.update(table_hash);
    h.update(&lp(recipient_id_dec.as_bytes()));
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h_coordinates_are_pinned() {
        // MUST match src-tauri/src/zk/pedersen.rs::h_coordinates_are_pinned — the
        // SBT Pedersen H. If these drift apart the two Pedersen instances commit
        // under different generators and nothing cross-verifies.
        let h = pedersen_h();
        assert_eq!(
            hex::encode(h.x.into_bigint().to_bytes_be()),
            "007065a7c12920cd37c3b1f1bbfcf7b048bb805a72d914daf577f18c5cad3399",
            "redaction Pedersen H.x must equal the SBT Pedersen H.x"
        );
        assert_eq!(
            hex::encode(h.y.into_bigint().to_bytes_be()),
            "2a88b2bf301f0dc6c2341819a8097314a1a5d1e4745a9085d89ab83fca0b5dbb",
            "redaction Pedersen H.y must equal the SBT Pedersen H.y"
        );
    }

    #[test]
    fn h_is_in_prime_subgroup_and_not_identity() {
        assert!(bjj_in_prime_subgroup(pedersen_h()));
        assert!(!bjj_is_identity(pedersen_h()));
    }

    #[test]
    fn content_scalar_is_deterministic_and_in_range() {
        let a = content_scalar(&1u32.to_be_bytes(), b"<< /Type /Page >>");
        let b = content_scalar(&1u32.to_be_bytes(), b"<< /Type /Page >>");
        assert_eq!(a, b);
        assert!(
            scalar_below_subgroup_order(&a),
            "content scalar must be < l"
        );
    }

    #[test]
    fn content_scalar_binds_id_and_bytes() {
        let base = content_scalar(&1u32.to_be_bytes(), b"alpha");
        assert_ne!(base, content_scalar(&2u32.to_be_bytes(), b"alpha"), "id");
        assert_ne!(base, content_scalar(&1u32.to_be_bytes(), b"beta"), "bytes");
        // Length-prefix framing: a longer id must not alias a shifted boundary.
        assert_ne!(
            content_scalar(b"ab", b"Xpayload"),
            content_scalar(b"abX", b"payload"),
        );
    }

    #[test]
    fn blinding_is_deterministic_in_range_and_varies() {
        let secret = [0xABu8; 32];
        let ch = [0x11u8; 32];
        let b1 = derive_blinding(&secret, &ch, &7u32.to_be_bytes());
        let b2 = derive_blinding(&secret, &ch, &7u32.to_be_bytes());
        assert_eq!(b1, b2, "same inputs → same blinding (idempotent ingest)");
        assert!(scalar_below_subgroup_order(&b1), "blinding must be < l");
        assert_ne!(
            b1,
            derive_blinding(&secret, &ch, &8u32.to_be_bytes()),
            "segment"
        );
        assert_ne!(
            b1,
            derive_blinding(&[0xCDu8; 32], &ch, &7u32.to_be_bytes()),
            "secret"
        );
    }

    #[test]
    fn leaf_is_deterministic_given_content_and_blinding() {
        let c = content_scalar(&3u32.to_be_bytes(), b"sensitive");
        let b = derive_blinding(&[1u8; 32], &[2u8; 32], &3u32.to_be_bytes());
        assert_eq!(
            redaction_leaf(&c, &b).unwrap(),
            redaction_leaf(&c, &b).unwrap()
        );
    }

    #[test]
    fn leaf_is_hiding_and_binding() {
        let c = content_scalar(&1u32.to_be_bytes(), b"secret");
        let b1 = derive_blinding(&[1u8; 32], &[2u8; 32], &1u32.to_be_bytes());
        let b2 = derive_blinding(&[1u8; 32], &[2u8; 32], &2u32.to_be_bytes());
        // Hiding: same content, different blinding → different leaf (so a redacted
        // leaf can't be matched against a guessed low-entropy content alone).
        assert_ne!(
            redaction_leaf(&c, &b1).unwrap(),
            redaction_leaf(&c, &b2).unwrap()
        );
        // Binding: different content, same blinding → different leaf.
        let c2 = content_scalar(&1u32.to_be_bytes(), b"other");
        assert_ne!(
            redaction_leaf(&c, &b1).unwrap(),
            redaction_leaf(&c2, &b1).unwrap()
        );
    }

    #[test]
    fn pedersen_commit_rejects_out_of_range_scalar() {
        let l = subgroup_order_bigint();
        assert_eq!(
            pedersen_commit(&l, &BigInt::from(1u32)),
            Err(RedactionError::ScalarOutOfRange("m"))
        );
        assert_eq!(
            pedersen_commit(&BigInt::from(1u32), &(&l + 1)),
            Err(RedactionError::ScalarOutOfRange("r"))
        );
    }

    // ── ADR-0030 §2 V3 bundle byte-layout encoders ─────────────────────────────

    #[test]
    fn v3_domain_tags_are_pinned() {
        // Canonical-constants law: these bytes are signed/hashed across the
        // producer + both offline verifiers, so pin them against silent edits.
        assert_eq!(REDACTION_BLIND_PREFIX, b"OLY:REDACTION:BLIND:V1");
        assert_eq!(REDACTION_BUNDLE_V3_PREFIX, b"OLY:REDACTION_BUNDLE:V3");
        assert_eq!(REDACTION_TABLE_V3_PREFIX, b"OLY:REDACTION:TABLE:V3");
        assert_eq!(REDACTION_NULLIFIER_V1_PREFIX, b"OLY:REDACTION:NULLIFIER:V1");
    }

    /// The cross-language byte-dump fixture anchor (ADR-0030 §Security): a fixed
    /// 2-segment table with **sparse** ids — segment 1 revealed (carries a
    /// `blinding_decimal`), segment 4 redacted (carries a `leaf_hex`) and an
    /// `ooxml-part`-style label — exercising both table branches and the label
    /// field. A from-spec verifier reproducing these golden hexes self-checks its
    /// byte layout end to end (table_hash → payload → nullifier).
    fn sample_entries() -> [RedactionTableEntry<'static>; 2] {
        [
            RedactionTableEntry {
                segment_id: 1,
                redacted: false,
                artifact_offset: 0,
                artifact_length: 17,
                label: b"",
                value_text: "12345678901234567890",
            },
            RedactionTableEntry {
                segment_id: 4,
                redacted: true,
                artifact_offset: 64,
                artifact_length: 0,
                label: b"word/document.xml",
                value_text: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        ]
    }

    const ORIGINAL_ROOT_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const RECIPIENT_DEC: &str = "98765432109876543210";

    #[test]
    fn table_hash_golden_vector() {
        assert_eq!(
            hex::encode(redaction_table_hash(&sample_entries())),
            "8a13569bebc2b69c84c1ef23c86d546bef25dc3cd5785df93cf197cabf04f3de"
        );
    }

    #[test]
    fn signing_message_golden_vector() {
        let th = redaction_table_hash(&sample_entries());
        let msg = redaction_signing_message(ORIGINAL_ROOT_HEX, "ooxml-part", 2, RECIPIENT_DEC, &th);
        assert_eq!(hex::encode(&msg), "4f4c593a524544414354494f4e5f42554e444c453a563300000040313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131310000000a6f6f786d6c2d70617274000000020000001439383736353433323130393837363534333231308a13569bebc2b69c84c1ef23c86d546bef25dc3cd5785df93cf197cabf04f3de");
        // The table_hash is the terminal 32 bytes, appended un-length-prefixed.
        assert_eq!(&msg[msg.len() - 32..], &th[..]);
        assert!(msg.starts_with(REDACTION_BUNDLE_V3_PREFIX));
    }

    #[test]
    fn nullifier_golden_vector() {
        let th = redaction_table_hash(&sample_entries());
        assert_eq!(
            hex::encode(redaction_nullifier(&[0x11u8; 32], &th, RECIPIENT_DEC)),
            "b425e593d698c135200b1cc79603c742fa76b5ada8f419d341ac47a1be7bdd99"
        );
    }

    #[test]
    fn table_hash_binds_every_field_and_order() {
        let base = redaction_table_hash(&sample_entries());
        // RT-1/RT-5: the redacted flag is bound, so a partition downgrade is caught.
        let mut e = sample_entries();
        e[0].redacted = true;
        assert_ne!(base, redaction_table_hash(&e), "redacted flag");
        let mut e = sample_entries();
        e[1].segment_id = 5;
        assert_ne!(base, redaction_table_hash(&e), "segment_id");
        let mut e = sample_entries();
        e[0].artifact_offset = 1;
        assert_ne!(base, redaction_table_hash(&e), "artifact_offset");
        let mut e = sample_entries();
        e[0].artifact_length = 18;
        assert_ne!(base, redaction_table_hash(&e), "artifact_length");
        let mut e = sample_entries();
        e[1].label = b"word/other.xml";
        assert_ne!(base, redaction_table_hash(&e), "label");
        let mut e = sample_entries();
        e[0].value_text = "12345678901234567891";
        assert_ne!(base, redaction_table_hash(&e), "value_text");
        // Order-sensitive: the digest depends on row order (caller passes ascending).
        let e = sample_entries();
        assert_ne!(base, redaction_table_hash(&[e[1], e[0]]), "row order");
    }

    #[test]
    fn signing_message_binds_every_field() {
        let th = redaction_table_hash(&sample_entries());
        let base = redaction_signing_message(ORIGINAL_ROOT_HEX, "ooxml-part", 2, "5", &th);
        let two = "22".repeat(32);
        assert_ne!(
            base,
            redaction_signing_message(&two, "ooxml-part", 2, "5", &th),
            "original_root"
        );
        assert_ne!(
            base,
            redaction_signing_message(ORIGINAL_ROOT_HEX, "text-line", 2, "5", &th),
            "format"
        );
        assert_ne!(
            base,
            redaction_signing_message(ORIGINAL_ROOT_HEX, "ooxml-part", 3, "5", &th),
            "segment_count"
        );
        assert_ne!(
            base,
            redaction_signing_message(ORIGINAL_ROOT_HEX, "ooxml-part", 2, "6", &th),
            "recipient_id"
        );
        let mut th2 = th;
        th2[0] ^= 1;
        assert_ne!(
            base,
            redaction_signing_message(ORIGINAL_ROOT_HEX, "ooxml-part", 2, "5", &th2),
            "table_hash"
        );
    }

    #[test]
    fn nullifier_binds_inputs() {
        let th = redaction_table_hash(&sample_entries());
        let base = redaction_nullifier(&[0x11u8; 32], &th, "5");
        let mut root2 = [0x11u8; 32];
        root2[31] = 0x12;
        assert_ne!(base, redaction_nullifier(&root2, &th, "5"), "original_root");
        let mut th2 = th;
        th2[0] ^= 1;
        assert_ne!(
            base,
            redaction_nullifier(&[0x11u8; 32], &th2, "5"),
            "table_hash"
        );
        assert_ne!(
            base,
            redaction_nullifier(&[0x11u8; 32], &th, "6"),
            "recipient_id"
        );
    }
}
