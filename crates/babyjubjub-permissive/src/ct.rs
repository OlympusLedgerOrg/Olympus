//! Constant-time fixed-width arithmetic for secret Baby Jubjub scalars.
//!
//! arkworks' generic scalar multiplication is a variable-time
//! double-and-add implementation, and its field arithmetic is not documented
//! as constant-time. Secret operations therefore use `crypto-bigint` for the
//! complete extended-Edwards formulas and execute exactly 256 double/add/select
//! rounds. Conversion back to arkworks happens only after the result becomes a
//! public key, nonce point, or commitment.

use ark_bn254::Fr as Fq;
use ark_ff::{BigInteger, PrimeField};
use crypto_bigint::{
    impl_modulus,
    modular::constant_mod::{Residue, ResidueParams},
    Encoding, U256,
};
use subtle::{Choice, ConditionallySelectable};
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

pub(crate) type CtFq = Residue<BaseModulus, { U256::LIMBS }>;
pub(crate) type CtScalar = Residue<ScalarModulus, { U256::LIMBS }>;

const A: U256 = U256::from_u64(168_700);
const D: U256 = U256::from_u64(168_696);

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
        let a = self.x * self.x;
        let b = self.y * self.y;
        let c = (self.z * self.z) + (self.z * self.z);
        let d = CtFq::new(&A) * a;
        let x_plus_y = self.x + self.y;
        let e = (x_plus_y * x_plus_y) - a - b;
        let g = d + b;
        let f = g - c;
        let h = d - b;
        Self {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }

    /// Complete unified addition formula `add-2008-hwcd`.
    fn add(&self, other: &Self) -> Self {
        let a = self.x * other.x;
        let b = self.y * other.y;
        let c = CtFq::new(&D) * self.t * other.t;
        let d = self.z * other.z;
        let h = b - (CtFq::new(&A) * a);
        let e = ((self.x + self.y) * (other.x + other.y)) - a - b;
        let f = d - c;
        let g = d + c;
        Self {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
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

/// Multiply an on-curve public point by a 256-bit little-endian scalar.
///
/// The loop count and operation sequence do not depend on scalar bits: every
/// round doubles, adds, and constant-time-selects. Inputs are deliberately
/// fixed-width so secret callers cannot accidentally reintroduce
/// `num_bigint` allocation or leading-zero-dependent iteration.
pub(crate) fn mul_scalar_ct(point: &BabyJubjubAffine, scalar: &U256) -> BabyJubjubAffine {
    let mut base = Zeroizing::new(CtPoint::from_affine(point));
    let mut acc = Zeroizing::new(CtPoint::IDENTITY);

    for bit_index in (0..U256::BITS).rev() {
        let mut doubled = Zeroizing::new(acc.double());
        let mut added = Zeroizing::new(doubled.add(&base));
        acc.assign_conditional(&doubled, &added, scalar.bit(bit_index).into());
        doubled.zeroize();
        added.zeroize();
    }

    let result = acc.finish_affine();
    acc.zeroize();
    base.zeroize();
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
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn fixed_schedule_mul_matches_arkworks_oracle(bytes in any::<[u8; 32]>()) {
            let scalar = U256::from_le_bytes(bytes);
            let expected = B8.into_group().mul_bigint(scalar.to_words()).into_affine();
            let actual = mul_scalar_ct(&B8, &scalar);
            prop_assert_eq!(actual, expected);
        }
    }

    #[test]
    fn scalar_loop_is_pinned_to_full_width() {
        assert_eq!(U256::BITS, 256);
    }
}
