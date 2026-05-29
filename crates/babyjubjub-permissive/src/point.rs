//! Public point-arithmetic + subgroup primitives.
//!
//! These are the curve operations `src-tauri/src/zk/pedersen.rs` and the
//! audit-hardening helpers in `src-tauri/src/zk/witness/baby_jubjub.rs`
//! currently reach into `babyjubjub-rs` for:
//!
//! | this module                | babyjubjub-rs equivalent                |
//! |----------------------------|-----------------------------------------|
//! | [`add`]                    | `p.projective().add(&q.projective())`   |
//! | [`mul_scalar_bigint`]      | `Point::mul_scalar(&BigInt)`            |
//! | [`mul_cofactor`]           | `Point::mul_scalar(&8)`                 |
//! | [`is_identity`]            | `bjj_is_identity`                       |
//! | [`is_in_prime_subgroup`]   | `bjj_in_prime_subgroup`                 |
//! | [`is_on_curve`]            | (implicit in point construction)        |
//! | [`scalar_below_subgroup_order`] | `validate_signature_s`'s `< l` bound |
//!
//! EdDSA parity (the 100-vector set) only exercises scalar-mul of the
//! generator `B8`. Pedersen commitments additionally use scalar-mul of
//! arbitrary points (`G`, `H`) and point addition (`m·G + r·H`), and the
//! audit guards classify low-order / non-canonical points. This module +
//! its tests cover that surface so the Phase-4 swap of `pedersen.rs` /
//! `baby_jubjub.rs` rests on proven primitives, not just EdDSA parity.

use ark_bn254::Fr as Fq;
use ark_ec::{twisted_edwards::TECurveConfig, AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, One, PrimeField, Zero};
use num_bigint::BigInt;

use crate::curve::{BabyJubjubAffine, BabyJubjubConfig};
use crate::field::Fr;

/// Twisted-Edwards point addition `P + Q`. Matches
/// `babyjubjub-rs`'s `p.projective().add(&q.projective()).affine()`.
pub fn add(p: &BabyJubjubAffine, q: &BabyJubjubAffine) -> BabyJubjubAffine {
    (p.into_group() + q.into_group()).into_affine()
}

/// Scalar multiplication `n · P` for a non-negative `BigInt n`.
///
/// Matches `babyjubjub-rs::Point::mul_scalar`, which does raw double-and-add
/// over `n`'s bits with no pre-reduction. For points in the prime-order
/// subgroup this equals `(n mod l)·P`; the result is identical either way
/// because `l·P = O`.
///
/// `n` is treated as its absolute value — every caller (Pedersen `m·G`,
/// `r·H`, cofactor clearing) passes a magnitude.
pub fn mul_scalar_bigint(p: &BabyJubjubAffine, n: &BigInt) -> BabyJubjubAffine {
    let (_, bytes_le) = n.to_bytes_le();
    let limbs = le_bytes_to_u64_limbs(&bytes_le);
    p.into_group().mul_bigint(&limbs).into_affine()
}

/// `8 · P` — cofactor multiplication. Clears the cofactor so the result
/// lands in the prime-order subgroup (the operation circomlib applies to
/// `R` to get `R8`, and that Pedersen-`H` derivation applies to the NUMS
/// candidate point). Implemented as three doublings.
pub fn mul_cofactor(p: &BabyJubjubAffine) -> BabyJubjubAffine {
    p.into_group().double().double().double().into_affine()
}

/// Return `true` iff `p` is the twisted-Edwards identity `(0, 1)`.
pub fn is_identity(p: &BabyJubjubAffine) -> bool {
    p.x.is_zero() && p.y == Fq::one()
}

/// Return `true` iff `p` lies in the prime-order subgroup, i.e. `l·P = O`.
///
/// Low-order cofactor points and cofactor-coset points fail this. Note the
/// identity `(0,1)` trivially passes (`l·O = O`); callers that must reject
/// the identity should pair this with [`is_identity`] (as the audit guards
/// do).
pub fn is_in_prime_subgroup(p: &BabyJubjubAffine) -> bool {
    let l = <Fr as PrimeField>::MODULUS;
    p.into_group().mul_bigint(l).is_zero()
}

/// Return `true` iff `(x, y)` satisfies the circomlib Baby Jubjub equation
/// `168700·x² + y² = 1 + 168696·x²·y²`.
pub fn is_on_curve(p: &BabyJubjubAffine) -> bool {
    let a = <BabyJubjubConfig as TECurveConfig>::COEFF_A;
    let d = <BabyJubjubConfig as TECurveConfig>::COEFF_D;
    let x2 = p.x.square();
    let y2 = p.y.square();
    a * x2 + y2 == Fq::one() + d * x2 * y2
}

/// Return `true` iff `s < l` (the prime-subgroup order). This is the
/// canonical-scalar bound `validate_signature_s` enforces against EdDSA
/// malleability: `s` and `s + l` both satisfy `s·B8 == (s+l)·B8`, so the
/// `< l` bound is what makes a signature's `s` unique.
pub fn scalar_below_subgroup_order(s: &BigInt) -> bool {
    s.sign() != num_bigint::Sign::Minus && *s < subgroup_order_bigint()
}

/// The prime-subgroup order `l` as a `BigInt`.
pub fn subgroup_order_bigint() -> BigInt {
    use std::sync::OnceLock;
    static L: OnceLock<BigInt> = OnceLock::new();
    L.get_or_init(|| {
        "2736030358979909402780800718157159386076813972158567259200215660948447373041"
            .parse()
            .expect("static decimal")
    })
    .clone()
}

/// Pack little-endian bytes into the `[u64]` limb form `mul_bigint` wants.
fn le_bytes_to_u64_limbs(bytes_le: &[u8]) -> Vec<u64> {
    bytes_le
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            u64::from_le_bytes(buf)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::B8;
    use ark_ff::BigInteger;

    /// The order-2 point `(0, -1)`. Doubling it yields `(0, 1) = O`, so it's
    /// the unique non-identity point of order 2 — the canonical adversarial
    /// "low-order" point for subgroup-check tests.
    fn order_two_point() -> BabyJubjubAffine {
        BabyJubjubAffine::new_unchecked(Fq::zero(), -Fq::one())
    }

    #[test]
    fn identity_classification() {
        let id = BabyJubjubAffine::new_unchecked(Fq::zero(), Fq::one());
        assert!(is_identity(&id));
        assert!(!is_identity(&B8));
    }

    #[test]
    fn b8_is_on_curve_and_in_subgroup() {
        assert!(is_on_curve(&B8));
        assert!(is_in_prime_subgroup(&B8));
    }

    #[test]
    fn order_two_point_is_on_curve_but_not_in_subgroup() {
        // The adversarial case: a point that passes an on-curve check but
        // is NOT in the prime-order subgroup. This is exactly what
        // validate_signature_r8 / validate_pubkey_subgroup must reject.
        let q = order_two_point();
        assert!(is_on_curve(&q), "(0,-1) is on the curve");
        assert!(!is_identity(&q), "(0,-1) is not the identity");
        assert!(
            !is_in_prime_subgroup(&q),
            "(0,-1) has order 2, must NOT be in the prime-order subgroup"
        );
    }

    #[test]
    fn cofactor_coset_point_is_rejected_by_subgroup_check() {
        // B8 + (0,-1): on the curve (closed under addition), but in a
        // cofactor coset — l·(B8+Q) = O + Q = Q ≠ O. This is the
        // malleability variant the audit guards exist to catch.
        let coset = add(&B8, &order_two_point());
        assert!(is_on_curve(&coset));
        assert!(
            !is_in_prime_subgroup(&coset),
            "cofactor-coset point must fail the subgroup check"
        );
    }

    #[test]
    fn cofactor_clearing_lands_in_subgroup() {
        // 8·(any on-curve point) is in the prime subgroup. Use the
        // order-2 point + B8 coset, whose cofactor-clearing must re-enter
        // the subgroup.
        let coset = add(&B8, &order_two_point());
        let cleared = mul_cofactor(&coset);
        assert!(is_in_prime_subgroup(&cleared));
    }

    #[test]
    fn scalar_bound_detects_malleability() {
        let l = subgroup_order_bigint();
        assert!(scalar_below_subgroup_order(&(&l - BigInt::from(1)))); // l-1 ok
        assert!(!scalar_below_subgroup_order(&l)); // l rejected
        assert!(!scalar_below_subgroup_order(&(&l + BigInt::from(1)))); // l+1 rejected
        assert!(!scalar_below_subgroup_order(&BigInt::from(-1))); // negative rejected
    }

    /// THE key Phase-4 gate: re-derive the Pedersen `H` generator using
    /// THIS crate's primitives (cofactor mul + subgroup/identity checks)
    /// and assert it lands on the exact coordinates `pedersen.rs` pins.
    ///
    /// `pedersen.rs::h_coordinates_are_pinned` is the live golden test;
    /// if the new primitives produced a different `H`, every SBT Pedersen
    /// commitment ever issued would become unverifiable after the swap.
    /// Proving the match HERE, before the swap, is the gating evidence the
    /// review called for.
    #[test]
    fn pedersen_h_derivation_matches_pinned_coords() {
        // Replicates derive_pedersen_h() from src-tauri/src/zk/pedersen.rs
        // verbatim, but with babyjubjub-permissive point ops instead of
        // babyjubjub-rs. PEDERSEN_H_PREFIX = b"OLY:PEDERSEN:H:V1" (asserted
        // by olympus_crypto's own test); hardcoded here to avoid a dep.
        const PREFIX: &[u8] = b"OLY:PEDERSEN:H:V1";
        let a = <BabyJubjubConfig as TECurveConfig>::COEFF_A;
        let d = <BabyJubjubConfig as TECurveConfig>::COEFF_D;
        let one = Fq::one();

        let seed = blake3::hash(PREFIX);
        let mut found: Option<BabyJubjubAffine> = None;
        for counter in 0u32..64 {
            let mut hasher = blake3::Hasher::new();
            hasher.update(seed.as_bytes());
            hasher.update(&counter.to_be_bytes());
            let y = Fq::from_le_bytes_mod_order(hasher.finalize().as_bytes());

            let y_sq = y.square();
            let numerator = one - y_sq;
            let denominator = a - d * y_sq;
            if denominator.is_zero() {
                continue;
            }
            let x_sq = numerator * denominator.inverse().expect("nonzero");
            let Some(root) = x_sq.sqrt() else { continue };
            let neg_root = -root;
            // lex-smaller of (root, -root) by big-endian bytes — matches
            // pedersen.rs::fr_lex_le.
            let x = if root.into_bigint().to_bytes_be() <= neg_root.into_bigint().to_bytes_be() {
                root
            } else {
                neg_root
            };

            let candidate = BabyJubjubAffine::new_unchecked(x, y);
            let cleared = mul_cofactor(&candidate);
            if is_identity(&cleared) || !is_in_prime_subgroup(&cleared) {
                continue;
            }
            found = Some(cleared);
            break;
        }

        let h = found.expect("H derivation must converge within 64 attempts");
        let x_be = hex::encode(h.x.into_bigint().to_bytes_be());
        let y_be = hex::encode(h.y.into_bigint().to_bytes_be());
        assert_eq!(
            x_be, "007065a7c12920cd37c3b1f1bbfcf7b048bb805a72d914daf577f18c5cad3399",
            "Pedersen H.x diverges from pedersen.rs's pinned value — the \
             swap would invalidate every existing commitment"
        );
        assert_eq!(
            y_be, "2a88b2bf301f0dc6c2341819a8097314a1a5d1e4745a9085d89ab83fca0b5dbb",
            "Pedersen H.y diverges from pedersen.rs's pinned value"
        );
    }
}
