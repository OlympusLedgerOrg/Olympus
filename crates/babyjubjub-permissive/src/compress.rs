//! iden3 / circomlib 32-byte point compression.
//!
//! # Wire format
//!
//! 32 bytes, little-endian:
//!
//! - Bytes 0..31 contain the y-coordinate, LE-encoded over the BN254
//!   scalar field (the curve's base field `Fq`).
//! - The high bit of byte 31 is the sign of x: `1` iff `x > (q-1)/2`,
//!   i.e. x lies in the "upper half" of the field.
//!
//! This is the exact format `babyjubjub-rs::Point::compress` /
//! `decompress_point` produce. Olympus persists Pedersen commitments and
//! credential public keys in this format, so the byte layout MUST stay
//! identical or every stored Pedersen commitment and external pubkey
//! reference would silently fail to verify after the BJJ swap.
//!
//! # Sign-disambiguation
//!
//! The curve equation `a·x² + y² = 1 + d·x²·y²` rearranges to
//! `x² = (1 - y²) / (a - d·y²)`; from that, x has up to two square roots
//! `±r` differing only in sign. Compression stores enough information
//! (one bit) to pick which root to recover.
//!
//! On decompress, we compute *some* sqrt, then check whether it landed in
//! the half indicated by the sign bit and negate if not. ark-ff's `sqrt`
//! is deterministic per call but does not guarantee a particular half, so
//! the half-check + conditional negation is load-bearing.

use ark_bn254::Fr as Fq;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ff::{BigInteger, Field, PrimeField};
use core::fmt;

use crate::curve::{BabyJubjubAffine, BabyJubjubConfig};

/// Reasons decompression can fail. All non-panicking — corrupted bytes
/// arriving over the wire return an error rather than silently producing
/// a wrong point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompressError {
    /// The y-coordinate decoded from the bytes is `≥ q` (the BN254 scalar
    /// modulus). `babyjubjub-rs::decompress_point` rejects this case too.
    YOutOfRange,
    /// `x² = (1 - y²) / (a - d·y²)` had `a - d·y² == 0` (the denominator
    /// vanished) — the input does not correspond to a real Baby Jubjub
    /// point. Impossible on well-formed inputs from a real signer.
    DenominatorZero,
    /// `(1 - y²) / (a - d·y²)` is a quadratic non-residue, so no `x`
    /// satisfies the curve equation for this `y`. Indicates corrupted
    /// compressed bytes.
    NotOnCurve,
}

impl fmt::Display for DecompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecompressError::YOutOfRange => f.write_str("decompress: y ≥ q (BN254 scalar modulus)"),
            DecompressError::DenominatorZero => f.write_str("decompress: a - d·y² = 0"),
            DecompressError::NotOnCurve => f.write_str("decompress: x² has no square root in Fq"),
        }
    }
}

impl std::error::Error for DecompressError {}

/// Compress `point` to the iden3 32-byte form. Always succeeds for any
/// well-formed `BabyJubjubAffine`; the input is constructed via ark-ec's
/// type-safe API so on-curve validity is a precondition rather than a
/// runtime check.
pub fn compress(point: &BabyJubjubAffine) -> [u8; 32] {
    // 32-byte LE encoding of y. arkworks pads with zeroes on the high end
    // for in-range values; the `truncate`/`resize` dance is defensive.
    let mut bytes = point.y.into_bigint().to_bytes_le();
    bytes.resize(32, 0u8);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);

    // High bit of byte 31 records sign(x) = (x > (q-1)/2).
    if is_upper_half(&point.x) {
        out[31] |= 0x80;
    }
    out
}

/// Decompress 32 bytes back to a Baby Jubjub affine point. Inverse of
/// [`compress`] for any input it produced; errors on corrupted bytes per
/// [`DecompressError`].
///
/// Note: the resulting point is on the curve but **not** guaranteed to be
/// in the prime-order subgroup. Call `is_in_prime_subgroup` (Phase 2) on
/// untrusted inputs before treating them as a cryptographic identity.
pub fn decompress(bytes: [u8; 32]) -> Result<BabyJubjubAffine, DecompressError> {
    // Extract sign bit and clear it before decoding y.
    let sign_upper_half = (bytes[31] & 0x80) != 0;
    let mut b = bytes;
    b[31] &= 0x7F;

    // Strict range check: reject y ≥ q. (PrimeField::from_le_bytes_mod_order
    // would silently reduce, which would re-map corrupted bytes onto a
    // valid-looking but unintended point — a wire-format ambiguity that
    // would break round-trip uniqueness.)
    if !is_canonical_le_bytes(&b) {
        return Err(DecompressError::YOutOfRange);
    }
    let y = Fq::from_le_bytes_mod_order(&b);

    // Recover x via x² = (1 - y²) / (a - d·y²).
    let a = <BabyJubjubConfig as TECurveConfig>::COEFF_A;
    let d = <BabyJubjubConfig as TECurveConfig>::COEFF_D;
    let y_sq = y.square();
    let denom = a - d * y_sq;
    let denom_inv = denom.inverse().ok_or(DecompressError::DenominatorZero)?;
    let x_sq = (Fq::from(1u64) - y_sq) * denom_inv;

    // ark-ff's `sqrt` returns Some(root) for any quadratic residue. It does
    // NOT promise *which* of (±root) it returns, so we have to compare to
    // the desired half and negate if needed.
    let root = x_sq.sqrt().ok_or(DecompressError::NotOnCurve)?;
    let x = if is_upper_half(&root) == sign_upper_half {
        root
    } else {
        -root
    };

    Ok(BabyJubjubAffine::new_unchecked(x, y))
}

/// Return `true` iff `value > (q-1)/2`, i.e. it lies in the upper half of
/// the field as a non-negative integer. Matches `babyjubjub-rs`'s
/// `x_big > (Q >> 1)` check.
fn is_upper_half(value: &Fq) -> bool {
    // Integer comparison of the canonical big-int form. `into_bigint`
    // returns the same representation `MODULUS_MINUS_ONE_DIV_TWO` is in,
    // so the comparison is meaningful.
    value.into_bigint() > <Fq as PrimeField>::MODULUS_MINUS_ONE_DIV_TWO
}

/// Return `true` iff `bytes` interpreted little-endian is strictly less
/// than the BN254 scalar modulus `q`. Used to reject out-of-range y values
/// before they get silently reduced by `from_le_bytes_mod_order`.
fn is_canonical_le_bytes(bytes: &[u8; 32]) -> bool {
    let modulus_le = {
        let mut m = <Fq as PrimeField>::MODULUS.to_bytes_le();
        m.resize(32, 0u8);
        m
    };
    // Compare from high byte down: bytes < modulus iff the first differing
    // byte (from the top) is less in `bytes` than in the modulus.
    for i in (0..32).rev() {
        match bytes[i].cmp(&modulus_le[i]) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => continue,
        }
    }
    // Exactly equal → not strictly less.
    false
}

/// Identity point `(0, 1)` — twisted Edwards neutral element. Constructed
/// via `new_unchecked` because we know the coordinates satisfy the curve
/// equation by hand (a·0 + 1 = 1 = 1 + d·0).
pub fn identity() -> BabyJubjubAffine {
    BabyJubjubAffine::new_unchecked(Fq::from(0u64), Fq::from(1u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::B8;
    use ark_ec::AffineRepr;
    use ark_std::UniformRand;
    use rand::SeedableRng;

    /// Compress(B8) followed by Decompress must round-trip to B8 exactly.
    /// This is the minimum guarantee — if the generator doesn't survive a
    /// round-trip, every other stored point is suspect.
    #[test]
    fn round_trip_b8() {
        let bytes = compress(&B8);
        let back = decompress(bytes).expect("B8 decompresses");
        assert_eq!(back.x, B8.x);
        assert_eq!(back.y, B8.y);
    }

    /// Compress / decompress round-trip preserves point identity for a
    /// pseudo-random set of subgroup points. Catches sign-bit/byte-order
    /// drift across both halves of the codec.
    #[test]
    fn round_trip_random_subgroup_points() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..64 {
            let sk = crate::Fr::rand(&mut rng);
            let p = (B8.into_group() * sk).into();
            let bytes = compress(&p);
            let back = decompress(bytes).expect("subgroup point decompresses");
            let p_affine: BabyJubjubAffine = p;
            assert_eq!(back, p_affine, "round-trip must be exact");
        }
    }

    /// The identity `(0, 1)` round-trips. The compressed form is the LE
    /// encoding of `y = 1` (so byte 0 = 0x01, rest zero) with the sign bit
    /// clear (x = 0 is in the lower half, since (q-1)/2 ≥ 0).
    #[test]
    fn round_trip_identity() {
        let id = identity();
        let bytes = compress(&id);
        assert_eq!(bytes[0], 0x01, "first LE byte of y=1 is 0x01");
        assert!(bytes[1..].iter().all(|&b| b == 0), "all other bytes zero");
        let back = decompress(bytes).expect("identity decompresses");
        assert_eq!(back, id);
    }

    /// Bytes that decode to `y ≥ q` must be rejected. Without this check,
    /// `from_le_bytes_mod_order` would silently reduce them, giving two
    /// different on-wire encodings that decode to the same point.
    #[test]
    fn rejects_y_at_or_above_modulus() {
        // Encode q itself (modulus, the boundary case): bits below sign
        // bit equal the modulus' bits, so the high sign bit is whatever
        // bit 7 of the modulus' top byte is. Strip it for a clean test.
        let mut modulus_le = <Fq as PrimeField>::MODULUS.to_bytes_le();
        modulus_le.resize(32, 0u8);
        let mut at_modulus = [0u8; 32];
        at_modulus.copy_from_slice(&modulus_le);
        // Clear sign bit so the comparison is unambiguous.
        at_modulus[31] &= 0x7F;
        assert!(matches!(
            decompress(at_modulus),
            Err(DecompressError::YOutOfRange)
        ));
    }

    /// Sign bit encodes membership in the upper half of `Fq`. Construct a
    /// point with x in the upper half and verify the bit comes out set.
    /// `-B8` is `(-B8.x, B8.y)` and exactly one of `±B8.x` lies in each
    /// half, so flipping which root we start from must flip the bit.
    #[test]
    fn sign_bit_tracks_upper_half() {
        let pos = B8;
        let neg = BabyJubjubAffine::new_unchecked(-B8.x, B8.y);

        let pos_bit = compress(&pos)[31] & 0x80;
        let neg_bit = compress(&neg)[31] & 0x80;
        assert_ne!(
            pos_bit, neg_bit,
            "compressing P and -P must produce opposite sign bits"
        );
    }
}
