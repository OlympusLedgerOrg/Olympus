// SPDX-License-Identifier: Apache-2.0

//! Constant-time fixed-width arithmetic for secret Baby Jubjub scalars.
//!
//! arkworks' generic scalar multiplication is a variable-time
//! double-and-add implementation, and its field arithmetic is not documented
//! as constant-time. Secret operations therefore use `crypto-bigint` for the
//! complete extended-Edwards formulas and execute exactly 256 double/add/select
//! rounds. Conversion back to arkworks happens only after the result becomes a
//! public key, nonce point, or commitment.

use ark_bn254::Fr as Fq;
use ark_ff::{BigInt as ArkBigInt, BigInteger, PrimeField};
use crypto_bigint::{
    impl_modulus,
    modular::constant_mod::{Residue, ResidueParams},
    Encoding, U256,
};
use std::fmt;
use subtle::{Choice, ConditionallySelectable, ConstantTimeLess};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::curve::BabyJubjubAffine;

impl_modulus!(
    BaseModulus,
    U256,
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
);
impl_modulus!(
    ScalarModulus,
    U256,
    "060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1"
);

const _: () = {
    let base = <BaseModulus as ResidueParams<{ U256::LIMBS }>>::MODULUS.to_words();
    let ark = Fq::MODULUS.0;
    assert!(base[0] == ark[0] && base[1] == ark[1] && base[2] == ark[2] && base[3] == ark[3]);
};

pub(crate) type CtFq = Residue<BaseModulus, { U256::LIMBS }>;
pub(crate) type CtScalar = Residue<ScalarModulus, { U256::LIMBS }>;

const A: U256 = U256::from_u64(168_700);
const D: U256 = U256::from_u64(168_696);

/// A canonical scalar in the Baby Jubjub prime-order subgroup.
///
/// The fixed-width value is private and is wiped on drop. This type
/// deliberately does not implement `Clone` or `Copy`: callers must pass
/// secret scalars by reference and explicitly serialize only into storage
/// they own and can wipe.
///
/// ```compile_fail
/// use babyjubjub_permissive::SubgroupScalar;
///
/// let scalar = SubgroupScalar::from_canonical_le_bytes(&[0u8; 32]).unwrap();
/// let duplicated = scalar.clone();
/// # drop(duplicated);
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubgroupScalar(U256);

impl fmt::Debug for SubgroupScalar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SubgroupScalar([REDACTED])")
    }
}

impl SubgroupScalar {
    /// Parse a canonical little-endian scalar, rejecting values `>= l`.
    pub fn from_canonical_le_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut value = Zeroizing::new(U256::from_le_bytes(*bytes));
        let is_canonical = bool::from(value.ct_lt(&subgroup_modulus()));
        let scalar = is_canonical.then(|| Self(*value));
        value.zeroize();
        scalar
    }

    /// Reduce a 512-bit little-endian integer modulo the subgroup order.
    pub fn reduce_wide_le(bytes: &[u8; 64]) -> Self {
        let mut reduced = reduce_wide_scalar_le(bytes);
        let scalar = Self(*reduced);
        reduced.zeroize();
        scalar
    }

    /// Reduce a 512-bit big-endian integer modulo the subgroup order.
    pub fn reduce_wide_be(bytes: &[u8; 64]) -> Self {
        let mut little_endian = Zeroizing::new(*bytes);
        little_endian.reverse();
        let scalar = Self::reduce_wide_le(&little_endian);
        little_endian.zeroize();
        scalar
    }

    /// Write the canonical scalar as exactly 32 little-endian bytes.
    pub fn write_le_bytes(&self, out: &mut [u8; 32]) {
        let mut encoded = Zeroizing::new(self.0.to_le_bytes());
        out.copy_from_slice(&*encoded);
        encoded.zeroize();
    }

    /// Deliberately expose this secret scalar as the BN254 field used by
    /// Olympus' public opening and circuit boundary code.
    ///
    /// The returned wrapper wipes its field element on drop. `Fq` itself is
    /// `Copy`, however, so callers must not copy it out of the wrapper unless
    /// the scalar is intentionally being declassified (for example, into a
    /// published Pedersen opening). Secret commitment paths should retain
    /// [`SubgroupScalar`] and call [`linear_combination_ct`] directly.
    pub fn expose_field(&self) -> Zeroizing<Fq> {
        // `PrimeField::from_{le,be}_bytes_mod_order` special-cases zero and
        // performs byte-at-a-time reduction. Build arkworks' Montgomery form
        // with the constant-time crypto-bigint backend instead: an arkworks
        // field element stores `value * R mod q`, where `Fq::R` is public.
        let mut ark_r = Zeroizing::new(U256::from_words(Fq::R.0));
        let mut value = Zeroizing::new(CtFq::new(&self.0));
        let mut r = Zeroizing::new(CtFq::new(&ark_r));
        let mut product = Zeroizing::new(*value * *r);
        let mut montgomery = Zeroizing::new(product.retrieve());
        let field = Fq::new_unchecked(ArkBigInt(montgomery.to_words()));

        ark_r.zeroize();
        value.zeroize();
        r.zeroize();
        product.zeroize();
        montgomery.zeroize();
        Zeroizing::new(field)
    }

    /// Convert a BN254 field element when its canonical integer is `< l`.
    pub fn from_field(value: &Fq) -> Option<Self> {
        let mut bigint = value.into_bigint();
        let mut encoded = Zeroizing::new([0u8; 32]);
        for (chunk, limb) in encoded.chunks_exact_mut(8).zip(bigint.0.iter()) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        bigint.0.zeroize();
        let scalar = Self::from_canonical_le_bytes(&encoded);
        encoded.zeroize();
        scalar
    }
}

/// Extended twisted-Edwards coordinates `(X:Y:T:Z)` with `x=X/Z`,
/// `y=Y/Z`, and `T=XY/Z`. All members use constant-time Montgomery field
/// arithmetic.
#[derive(Zeroize, ZeroizeOnDrop)]
struct CtPoint {
    x: CtFq,
    y: CtFq,
    t: CtFq,
    z: CtFq,
}

impl CtPoint {
    const IDENTITY: Self = Self {
        x: CtFq::ZERO,
        y: CtFq::ONE,
        t: CtFq::ZERO,
        z: CtFq::ONE,
    };

    fn from_affine(point: &BabyJubjubAffine) -> Self {
        let x = CtFq::new(&fq_to_u256(&point.x));
        let y = CtFq::new(&fq_to_u256(&point.y));
        Self {
            x,
            y,
            t: x * y,
            z: CtFq::ONE,
        }
    }

    /// Complete doubling formula `dbl-2008-hwcd`.
    fn double(&self) -> Self {
        let mut a = Zeroizing::new(self.x * self.x);
        let mut b = Zeroizing::new(self.y * self.y);
        let mut z_squared = Zeroizing::new(self.z * self.z);
        let mut c = Zeroizing::new(*z_squared + *z_squared);
        let mut d = Zeroizing::new(CtFq::new(&A) * *a);
        let mut x_plus_y = Zeroizing::new(self.x + self.y);
        let mut e = Zeroizing::new((*x_plus_y * *x_plus_y) - *a - *b);
        let mut g = Zeroizing::new(*d + *b);
        let mut f = Zeroizing::new(*g - *c);
        let mut h = Zeroizing::new(*d - *b);
        let result = Self {
            x: *e * *f,
            y: *g * *h,
            t: *e * *h,
            z: *f * *g,
        };

        a.zeroize();
        b.zeroize();
        z_squared.zeroize();
        c.zeroize();
        d.zeroize();
        x_plus_y.zeroize();
        e.zeroize();
        g.zeroize();
        f.zeroize();
        h.zeroize();
        result
    }

    /// Complete unified addition formula `add-2008-hwcd`.
    fn add(&self, other: &Self) -> Self {
        let mut a = Zeroizing::new(self.x * other.x);
        let mut b = Zeroizing::new(self.y * other.y);
        let mut c = Zeroizing::new(CtFq::new(&D) * self.t * other.t);
        let mut d = Zeroizing::new(self.z * other.z);
        let mut h = Zeroizing::new(*b - (CtFq::new(&A) * *a));
        let mut self_sum = Zeroizing::new(self.x + self.y);
        let mut other_sum = Zeroizing::new(other.x + other.y);
        let mut e = Zeroizing::new((*self_sum * *other_sum) - *a - *b);
        let mut f = Zeroizing::new(*d - *c);
        let mut g = Zeroizing::new(*d + *c);
        let result = Self {
            x: *e * *f,
            y: *g * *h,
            t: *e * *h,
            z: *f * *g,
        };

        a.zeroize();
        b.zeroize();
        c.zeroize();
        d.zeroize();
        h.zeroize();
        self_sum.zeroize();
        other_sum.zeroize();
        e.zeroize();
        f.zeroize();
        g.zeroize();
        result
    }

    fn assign_conditional(&mut self, a: &Self, b: &Self, choice: Choice) {
        self.zeroize();
        self.x = CtFq::conditional_select(&a.x, &b.x, choice);
        self.y = CtFq::conditional_select(&a.y, &b.y, choice);
        self.t = CtFq::conditional_select(&a.t, &b.t, choice);
        self.z = CtFq::conditional_select(&a.z, &b.z, choice);
    }

    fn finish_affine(&mut self) -> BabyJubjubAffine {
        // Complete formulas preserve a non-zero Z for valid curve points.
        // Deliberately ignore the CtChoice instead of branching on it.
        let mut z_inv = Zeroizing::new(self.z.invert().0);
        let mut x = Zeroizing::new(self.x * *z_inv);
        let mut y = Zeroizing::new(self.y * *z_inv);
        let mut x_uint = Zeroizing::new(x.retrieve());
        let mut y_uint = Zeroizing::new(y.retrieve());
        let affine = BabyJubjubAffine::new_unchecked(u256_to_fq(&x_uint), u256_to_fq(&y_uint));

        self.zeroize();
        z_inv.zeroize();
        x.zeroize();
        y.zeroize();
        x_uint.zeroize();
        y_uint.zeroize();
        affine
    }
}

/// Compute `p_scalar * p + q_scalar * q` using one fixed 256-round joint
/// ladder and a single constant-time affine conversion.
///
/// Every round performs one doubling, two complete additions, and two
/// constant-time selections regardless of either scalar's bits. The caller
/// is responsible for validating that the public input points satisfy the
/// curve and subgroup policy required by its protocol.
pub fn linear_combination_ct(
    p: &BabyJubjubAffine,
    p_scalar: &SubgroupScalar,
    q: &BabyJubjubAffine,
    q_scalar: &SubgroupScalar,
) -> BabyJubjubAffine {
    // Keep the loop's scalar caches in explicitly wiped storage. Optimized
    // code otherwise spills the borrowed limbs into this frame without an
    // epilogue overwrite, even though the owning SubgroupScalar is wiped.
    let mut p_bits = Zeroizing::new(p_scalar.0);
    let mut q_bits = Zeroizing::new(q_scalar.0);
    let mut p_extended = Zeroizing::new(CtPoint::from_affine(p));
    let mut q_extended = Zeroizing::new(CtPoint::from_affine(q));
    let mut acc = Zeroizing::new(CtPoint::IDENTITY);

    for bit_index in (0..U256::BITS).rev() {
        let mut doubled = Zeroizing::new(acc.double());
        let mut plus_p = Zeroizing::new(doubled.add(&p_extended));
        let mut after_p = Zeroizing::new(CtPoint::IDENTITY);
        after_p.assign_conditional(&doubled, &plus_p, p_bits.bit(bit_index).into());

        let mut plus_q = Zeroizing::new(after_p.add(&q_extended));
        let mut after_q = Zeroizing::new(CtPoint::IDENTITY);
        after_q.assign_conditional(&after_p, &plus_q, q_bits.bit(bit_index).into());

        acc.zeroize();
        std::mem::swap(&mut acc, &mut after_q);
        doubled.zeroize();
        plus_p.zeroize();
        after_p.zeroize();
        plus_q.zeroize();
        after_q.zeroize();
    }

    let result = acc.finish_affine();
    acc.zeroize();
    p_extended.zeroize();
    q_extended.zeroize();
    p_bits.zeroize();
    q_bits.zeroize();
    result
}

/// Multiply an on-curve public point by a 256-bit little-endian scalar.
///
/// The loop count and operation sequence do not depend on scalar bits: every
/// round doubles, adds, and constant-time-selects. Inputs are deliberately
/// fixed-width so secret callers cannot accidentally reintroduce
/// `num_bigint` allocation or leading-zero-dependent iteration.
pub(crate) fn mul_scalar_ct(point: &BabyJubjubAffine, scalar: &U256) -> BabyJubjubAffine {
    // As in the joint ladder, make the compiler's loop-local scalar cache an
    // explicitly wiped object rather than an uncleared stack spill.
    let mut scalar_bits = Zeroizing::new(*scalar);
    let mut base = Zeroizing::new(CtPoint::from_affine(point));
    let mut acc = Zeroizing::new(CtPoint::IDENTITY);

    for bit_index in (0..U256::BITS).rev() {
        let mut doubled = Zeroizing::new(acc.double());
        let mut added = Zeroizing::new(doubled.add(&base));
        acc.assign_conditional(&doubled, &added, scalar_bits.bit(bit_index).into());
        doubled.zeroize();
        added.zeroize();
    }

    let result = acc.finish_affine();
    acc.zeroize();
    base.zeroize();
    scalar_bits.zeroize();
    result
}

pub(crate) fn scalar_from_u256(value: &U256) -> CtScalar {
    CtScalar::new(value)
}

pub(crate) fn scalar_to_u256(value: &CtScalar) -> U256 {
    value.retrieve()
}

/// Reduce a 512-bit little-endian digest modulo the subgroup order. The
/// divisor is compile-time fixed, so `const_rem_wide` is constant-time with
/// respect to the digest.
pub(crate) fn reduce_wide_scalar_le(bytes: &[u8; 64]) -> Zeroizing<U256> {
    let mut low_bytes = Zeroizing::new([0u8; 32]);
    let mut high_bytes = Zeroizing::new([0u8; 32]);
    low_bytes.copy_from_slice(&bytes[..32]);
    high_bytes.copy_from_slice(&bytes[32..]);
    let mut low = Zeroizing::new(U256::from_le_bytes(*low_bytes));
    let mut high = Zeroizing::new(U256::from_le_bytes(*high_bytes));
    let reduced = Zeroizing::new(
        U256::const_rem_wide(
            (*low, *high),
            &<ScalarModulus as ResidueParams<{ U256::LIMBS }>>::MODULUS,
        )
        .0,
    );
    low.zeroize();
    high.zeroize();
    low_bytes.zeroize();
    high_bytes.zeroize();
    reduced
}

pub(crate) fn subgroup_modulus() -> U256 {
    <ScalarModulus as ResidueParams<{ U256::LIMBS }>>::MODULUS
}

pub(crate) fn fq_to_u256(value: &Fq) -> U256 {
    let bytes = value.into_bigint().to_bytes_le();
    let mut fixed = [0u8; 32];
    fixed[..bytes.len()].copy_from_slice(&bytes);
    U256::from_le_bytes(fixed)
}

fn u256_to_fq(value: &U256) -> Fq {
    Fq::from_le_bytes_mod_order(&value.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::B8;
    use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{One, Zero};
    use proptest::prelude::*;

    fn subgroup_scalar_from_u256(value: U256) -> SubgroupScalar {
        SubgroupScalar::from_canonical_le_bytes(&value.to_le_bytes())
            .expect("test scalar is canonical")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn fixed_schedule_mul_matches_arkworks_oracle(bytes in any::<[u8; 32]>()) {
            let scalar = U256::from_le_bytes(bytes);
            let expected = B8.into_group().mul_bigint(scalar.to_words()).into_affine();
            let actual = mul_scalar_ct(&B8, &scalar);
            prop_assert_eq!(actual, expected);
        }

        #[test]
        fn joint_ladder_matches_arkworks_oracle(
            p_wide in any::<[u8; 64]>(),
            q_wide in any::<[u8; 64]>(),
        ) {
            let p_scalar = SubgroupScalar::reduce_wide_le(&p_wide);
            let q_scalar = SubgroupScalar::reduce_wide_le(&q_wide);
            let p = B8;
            let q = B8.into_group().double().into_affine();
            let expected = (
                p.into_group().mul_bigint(p_scalar.0.to_words())
                    + q.into_group().mul_bigint(q_scalar.0.to_words())
            )
                .into_affine();
            let actual = linear_combination_ct(&p, &p_scalar, &q, &q_scalar);
            prop_assert_eq!(actual, expected);
        }

        #[test]
        fn subgroup_scalar_field_bridge_roundtrips(wide in any::<[u8; 64]>()) {
            let scalar = SubgroupScalar::reduce_wide_le(&wide);
            let field = scalar.expose_field();
            let recovered = SubgroupScalar::from_field(&field)
                .expect("a reduced subgroup scalar remains below l");
            let mut expected = Zeroizing::new([0u8; 32]);
            let mut actual = Zeroizing::new([0u8; 32]);
            scalar.write_le_bytes(&mut expected);
            recovered.write_le_bytes(&mut actual);
            prop_assert_eq!(&*actual, &*expected);
        }
    }

    #[test]
    fn scalar_loop_is_pinned_to_full_width() {
        assert_eq!(U256::BITS, 256);
    }

    #[test]
    fn subgroup_scalar_canonical_edges() {
        let order = subgroup_modulus();
        let order_minus_one = order.wrapping_sub(&U256::ONE);

        for value in [U256::ZERO, U256::ONE, order_minus_one] {
            let encoded = value.to_le_bytes();
            let scalar = SubgroupScalar::from_canonical_le_bytes(&encoded)
                .expect("0, 1, and l-1 are canonical");
            let mut roundtrip = [0u8; 32];
            scalar.write_le_bytes(&mut roundtrip);
            assert_eq!(roundtrip, encoded);
        }

        assert!(SubgroupScalar::from_canonical_le_bytes(&order.to_le_bytes()).is_none());
        assert!(SubgroupScalar::from_canonical_le_bytes(
            &order.wrapping_add(&U256::ONE).to_le_bytes(),
        )
        .is_none());
        assert!(SubgroupScalar::from_canonical_le_bytes(&U256::MAX.to_le_bytes()).is_none());
    }

    #[test]
    fn wide_reduction_endian_views_match() {
        let mut little_endian = [0u8; 64];
        little_endian[0] = 0x81;
        little_endian[31] = 0x40;
        little_endian[32] = 0x22;
        little_endian[63] = 0xa5;
        let mut big_endian = little_endian;
        big_endian.reverse();

        let little = SubgroupScalar::reduce_wide_le(&little_endian);
        let big = SubgroupScalar::reduce_wide_be(&big_endian);
        let mut little_bytes = [0u8; 32];
        let mut big_bytes = [0u8; 32];
        little.write_le_bytes(&mut little_bytes);
        big.write_le_bytes(&mut big_bytes);
        assert_eq!(little_bytes, big_bytes);

        let mut one_le = [0u8; 64];
        one_le[0] = 1;
        let mut one_be = [0u8; 64];
        one_be[63] = 1;
        let one_from_le = SubgroupScalar::reduce_wide_le(&one_le);
        let one_from_be = SubgroupScalar::reduce_wide_be(&one_be);
        let mut out_le = [0u8; 32];
        let mut out_be = [0u8; 32];
        one_from_le.write_le_bytes(&mut out_le);
        one_from_be.write_le_bytes(&mut out_be);
        assert_eq!(out_le, U256::ONE.to_le_bytes());
        assert_eq!(out_be, U256::ONE.to_le_bytes());
    }

    #[test]
    fn subgroup_scalar_field_roundtrip_and_rejection() {
        let order = subgroup_modulus();
        for value in [U256::ZERO, U256::ONE, order.wrapping_sub(&U256::ONE)] {
            let scalar = subgroup_scalar_from_u256(value);
            let field = scalar.expose_field();
            let recovered = SubgroupScalar::from_field(&field).expect("field value remains < l");
            let mut recovered_bytes = [0u8; 32];
            recovered.write_le_bytes(&mut recovered_bytes);
            assert_eq!(recovered_bytes, value.to_le_bytes());
        }

        let field_equal_to_l = Fq::from_le_bytes_mod_order(&order.to_le_bytes());
        assert!(SubgroupScalar::from_field(&field_equal_to_l).is_none());
    }

    #[test]
    fn joint_ladder_covers_zero_one_order_minus_one_and_identity() {
        let identity = BabyJubjubAffine::new_unchecked(Fq::zero(), Fq::one());
        let zero = subgroup_scalar_from_u256(U256::ZERO);
        let one = subgroup_scalar_from_u256(U256::ONE);
        let order_minus_one =
            subgroup_scalar_from_u256(subgroup_modulus().wrapping_sub(&U256::ONE));

        assert_eq!(linear_combination_ct(&B8, &zero, &B8, &zero), identity);
        assert_eq!(
            linear_combination_ct(&identity, &order_minus_one, &B8, &one),
            B8
        );
        assert_eq!(
            linear_combination_ct(&B8, &order_minus_one, &B8, &one),
            identity,
            "(l-1)B8 + B8 = identity"
        );
    }

    #[test]
    fn subgroup_scalar_debug_is_redacted() {
        let scalar = subgroup_scalar_from_u256(U256::from_u64(0xdead_beef));
        let debug = format!("{scalar:?}");
        assert_eq!(debug, "SubgroupScalar([REDACTED])");
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("3735928559"));
    }
}
