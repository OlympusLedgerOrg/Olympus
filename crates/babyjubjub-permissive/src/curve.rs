//! Baby Jubjub twisted-Edwards curve config (circomlib parameterization).
//!
//! The curve equation, over the BN254 scalar field `Fq = ark_bn254::Fr`:
//!
//! ```text
//! 168700 · x² + y² = 1 + 168696 · x² · y²
//! ```
//!
//! The Montgomery companion (used by some arkworks internals) is
//! `1·v² = u³ + 168698·u² + u`, derived from the twisted-Edwards
//! parameters via the standard `A = 2(a+d)/(a-d)`, `B = 4/(a-d)` formulas.
//!
//! Curve operations (point addition, doubling, scalar multiplication via
//! double-and-add, projective ↔ affine, on-curve check) come from
//! `ark_ec::twisted_edwards::{Affine, Projective}` for free as soon as we
//! impl `TECurveConfig`.

use ark_bn254::Fr as Fq;
use ark_ec::{
    twisted_edwards::{Affine, MontCurveConfig, Projective, TECurveConfig},
    CurveConfig,
};
use ark_ff::MontFp;

use crate::field::Fr;

/// Affine point on the Baby Jubjub curve, `(x, y)` over `Fq = ark_bn254::Fr`.
pub type BabyJubjubAffine = Affine<BabyJubjubConfig>;

/// Projective point on the Baby Jubjub curve, used internally by ark-ec for
/// efficient addition / scalar-mul without per-step field inversions.
pub type BabyJubjubProjective = Projective<BabyJubjubConfig>;

/// The Baby Jubjub cofactor `h = 8`. Multiplying any on-curve point by 8
/// lands it in the prime-order subgroup of order [`Fr`]'s modulus.
pub const COFACTOR: u64 = 8;

/// Marker type carrying the Baby Jubjub curve parameters.
///
/// Implements [`CurveConfig`] (base/scalar field + cofactor),
/// [`TECurveConfig`] (twisted-Edwards `a`, `d`, generator), and
/// [`MontCurveConfig`] (Montgomery `A`, `B` for the birationally-equivalent
/// Montgomery form). Together these unlock the full `ark-ec` API on
/// [`BabyJubjubAffine`] and [`BabyJubjubProjective`].
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BabyJubjubConfig;

impl CurveConfig for BabyJubjubConfig {
    type BaseField = Fq;
    type ScalarField = Fr;

    /// `h = 8`. arkworks expects a little-endian limb array.
    const COFACTOR: &'static [u64] = &[8];

    /// `h⁻¹ mod l` — the cofactor's inverse in the prime-subgroup scalar
    /// field. Same `Fr` modulus as `ark-ed-on-bn254` (the subgroup order
    /// does not depend on the twisted-vs-untwisted Edwards form), so the
    /// inverse is identical.
    const COFACTOR_INV: Fr =
        MontFp!("2394026564107420727433200628387514462817212225638746351800188703329891451411");
}

impl TECurveConfig for BabyJubjubConfig {
    /// Twisted-Edwards `a` coefficient. Circomlib uses `168700`; the
    /// algebraically-equivalent untwisted form (`a = 1`) would also work
    /// but produces incompatible point coordinates.
    const COEFF_A: Fq = MontFp!("168700");

    /// Twisted-Edwards `d` coefficient.
    const COEFF_D: Fq = MontFp!("168696");

    /// The circomlib `B8` base point — the generator of the prime-order
    /// subgroup used by EdDSA-Poseidon signing. Same `(x, y)` literal as
    /// `circomlib/circuits/babyjub.circom` and the long-standing constants
    /// in `src-tauri/src/zk/pedersen.rs::G_X_DEC / G_Y_DEC`.
    const GENERATOR: BabyJubjubAffine = BabyJubjubAffine::new_unchecked(
        MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
        MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );

    type MontCurveConfig = BabyJubjubConfig;
}

impl MontCurveConfig for BabyJubjubConfig {
    /// Montgomery `A = 2(a+d)/(a-d) = 2·337396/4 = 168698`.
    const COEFF_A: Fq = MontFp!("168698");

    /// Montgomery `B = 4/(a-d) = 4/4 = 1`.
    const COEFF_B: Fq = MontFp!("1");

    type TECurveConfig = BabyJubjubConfig;
}

/// The circomlib `B8` base point as a constant. Convenience re-export of
/// [`BabyJubjubConfig::GENERATOR`] under the canonical circomlib name.
pub const B8: BabyJubjubAffine = <BabyJubjubConfig as TECurveConfig>::GENERATOR;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{PrimeField, Zero};

    /// `B8` satisfies the circomlib twisted-Edwards equation. If COEFF_A /
    /// COEFF_D / generator constants drift between commits, this fires.
    #[test]
    fn generator_satisfies_curve_equation() {
        let (x, y) = (B8.x, B8.y);
        let a = <BabyJubjubConfig as TECurveConfig>::COEFF_A;
        let d = <BabyJubjubConfig as TECurveConfig>::COEFF_D;
        let lhs = a * x * x + y * y;
        let rhs = Fq::from(1u64) + d * x * x * y * y;
        assert_eq!(lhs, rhs, "B8 must satisfy a·x² + y² = 1 + d·x²·y²");
    }

    /// `l · B8 = O` (the identity). The defining property of a prime-order
    /// subgroup generator — the same property the audit's
    /// `validate_signature_r8` relies on to detect cofactor-coset
    /// malleability variants.
    ///
    /// `mul_bigint(MODULUS)` rather than `* Fr::from_bigint(MODULUS)`:
    /// `Fr::from_bigint(MODULUS)` returns `None` (the input is the modulus
    /// itself, not a valid in-range scalar), so we have to scalar-mul by the
    /// raw limbs.
    #[test]
    fn generator_has_prime_subgroup_order() {
        let l = <Fr as PrimeField>::MODULUS;
        let lb8 = B8.into_group().mul_bigint(l);
        assert!(lb8.is_zero(), "l·B8 must be the identity (0, 1)");
    }

    /// `8 · P` lands a random on-curve point in the prime subgroup. This is
    /// the cofactor-clearing operation circomlib applies to `R` to produce
    /// the signature's `R8` component.
    #[test]
    fn cofactor_clearing_lands_in_prime_subgroup() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xB1A_B0B);
        let l = <Fr as PrimeField>::MODULUS;
        for _ in 0..16 {
            // Sample by scaling the generator by a random subgroup scalar;
            // not a uniformly-random on-curve point, but is a good random
            // subgroup element, which is what real R8 values look like.
            let sk: Fr = ark_std::UniformRand::rand(&mut rng);
            let p = (B8.into_group() * sk).into_affine();
            // Multiply by 8 and check subgroup membership via `l·(8P) = O`.
            let p8 = p.into_group().double().double().double();
            let l_p8 = p8.mul_bigint(l);
            assert!(
                l_p8.is_zero(),
                "8·P must be in the prime-order subgroup (l·(8P) = O)"
            );
        }
    }
}
