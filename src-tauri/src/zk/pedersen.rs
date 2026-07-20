//! Pedersen commitments on Baby Jubjub.
//!
//! `commit(m, r) = m·G + r·H` over the Baby Jubjub prime-order subgroup,
//! where `G` is the circomlib `B8` base point and `H` is a NUMS generator
//! derived nothing-up-my-sleeve from `OLY:PEDERSEN:H:V1`.
//!
//! # Why a second generator
//!
//! A Pedersen commitment `C = m·G + r·H` is computationally binding iff the
//! discrete log of `H` with respect to `G` is unknown — otherwise the
//! committer who knew `k = log_G(H)` could open any `C` to any message by
//! rewriting `m·G + r·H = (m + r·k)·G`.  Picking `H` "nothing up my sleeve"
//! from a domain tag is the standard way to make `log_G(H)` unknown to
//! everyone, including us.
//!
//! # Hiding and binding
//!
//! * **Hiding** holds unconditionally: for any `m`, the distribution of
//!   `C = m·G + r·H` over uniform `r ∈ [0, l)` is uniform over the subgroup,
//!   so `C` reveals nothing about `m` to an observer who doesn't know `r`.
//! * **Binding** rests on the discrete-log hardness of finding `k = log_G(H)`.
//!   `H` is NUMS-derived so `k` is unknown to everyone.
//!
//! # Additive homomorphism — range caveat
//!
//! `commit(m1, r1) + commit(m2, r2) = commit(m1+m2, r1+r2)` as curve points,
//! but only while each summed scalar stays in `[0, l)`. [`commit`] rejects
//! out-of-range scalars (it never silently reduces mod `l`), so a sum that
//! crosses `l` fails closed with [`PedersenError::ScalarOutOfRange`] rather
//! than aliasing to a smaller representative. Callers building on the
//! homomorphism (sum-of-amounts, blind sums) must reduce mod `l` themselves.
//!
//! # Side channels
//!
//! [`commit`] validates fixed-width subgroup scalars and delegates both scalar
//! multiplications plus the final Edwards addition to the fixed-schedule
//! `babyjubjub-permissive` backend. [`random_blinding`] likewise uses
//! fixed-schedule 512-bit reduction and wipes its raw RNG buffer on drop.
//! These guarantees cover the secret-scalar arithmetic, not the whole API:
//! generator derivation, canonicalisation, RNG internals, error handling,
//! serialisation, and the public commitment comparison in [`verify`] are not
//! claimed to be constant-time. Rejection of an out-of-range scalar explicitly
//! declassifies that validity bit through [`PedersenError::ScalarOutOfRange`].
//!
//! # Algorithm: try-and-increment
//!
//! 1. Seed `s = BLAKE3(OLY:PEDERSEN:H:V1)` (32 bytes).
//! 2. `y = (s || counter_be_u32) → BLAKE3 → reduce mod r` in BN254 scalar field.
//! 3. Solve `x² = (1 - y²) / (a - d·y²)` in the BJJ base field (= BN254 `Fr`).
//! 4. If `x²` has a square root, take the lex-smaller root `x`.
//! 5. Form `P = (x, y)`, then `H = 8·P` to clear the cofactor.
//! 6. Reject identity; verify prime-subgroup membership.
//! 7. On any failure, bump `counter` and retry.
//!
//! All failures are silent retries — the loop terminates with probability
//! ~1 - 2⁻counter and in practice the first 1-2 iterations succeed.  The
//! resulting `H` is cached in a `OnceLock` and pinned by golden test so any
//! future algorithm change shows up as a hard test failure.

use std::sync::OnceLock;

use std::str::FromStr;

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
#[cfg(test)]
use babyjubjub_permissive::add as bjj_add;
use babyjubjub_permissive::{
    self as bjj, linear_combination_ct, mul_cofactor, BabyJubjubAffine, SubgroupScalar,
};
use num_bigint::BigInt;
use olympus_crypto::PEDERSEN_H_PREFIX;
use rand::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

use super::witness::baby_jubjub::{
    ark_fr_to_bigint, bigint_to_ark, bjj_affine, bjj_in_prime_subgroup, bjj_is_identity,
    bjj_subgroup_order,
};

/// Baby Jubjub twisted-Edwards curve coefficient `a` (per circomlib /
/// babyjubjub-rs): `a·x² + y² = 1 + d·x²·y²`.
const BJJ_A: u64 = 168700;
/// Baby Jubjub twisted-Edwards curve coefficient `d`.
const BJJ_D: u64 = 168696;
/// Hard cap on try-and-increment iterations.  At ~50% success per attempt
/// the probability of hitting this cap is ~2⁻⁶⁴ — well below "this will
/// ever happen in practice"; the cap exists to refuse to loop forever if
/// someone breaks the field-arithmetic helpers.
const MAX_DERIVATION_ATTEMPTS: u32 = 64;

/// Cached generator `H` for `OLY:PEDERSEN:H:V1`.
static PEDERSEN_H: OnceLock<BabyJubjubAffine> = OnceLock::new();

/// Return the Pedersen second generator `H` on Baby Jubjub.
///
/// Computed once via [`derive_pedersen_h`] and cached for the lifetime of
/// the process. Callers that need the `(x, y)` coordinates directly (e.g.
/// circuit witness construction in PD-2) should use [`pedersen_h_ark`].
pub fn pedersen_h() -> &'static BabyJubjubAffine {
    PEDERSEN_H.get_or_init(derive_pedersen_h)
}

/// Return `H` as `(x, y)` arkworks `Fr` coordinates.
///
/// Convenience for ZK witness construction. `babyjubjub_permissive` already
/// represents point coordinates as `ark_bn254::Fr`, so this is a direct
/// field read with no bridge.
pub fn pedersen_h_ark() -> (Fr, Fr) {
    let h = pedersen_h();
    (h.x, h.y)
}

/// NUMS derivation of `H` via try-and-increment.  Internal — public API
/// is the cached [`pedersen_h`].
///
/// Panics if the derivation loop exhausts [`MAX_DERIVATION_ATTEMPTS`].
/// This would indicate a broken sqrt implementation, not a malicious
/// domain tag — any 32-byte tag has overwhelming probability of yielding
/// a valid point within the first handful of iterations. For the shipped
/// `OLY:PEDERSEN:H:V1` tag the panic path is unreachable, and that is
/// regression-guarded by the `derive_pedersen_h_does_not_panic` and
/// `h_coordinates_are_pinned` tests (which run the derivation in CI).
fn derive_pedersen_h() -> BabyJubjubAffine {
    let a = Fr::from(BJJ_A);
    let d = Fr::from(BJJ_D);
    let one = Fr::one();
    let seed = blake3::hash(PEDERSEN_H_PREFIX);
    let seed_bytes = seed.as_bytes();

    for counter in 0u32..MAX_DERIVATION_ATTEMPTS {
        // Build candidate y = reduce_mod_r(BLAKE3(seed || counter_be_u32)).
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed_bytes);
        hasher.update(&counter.to_be_bytes());
        let y_bytes = hasher.finalize();
        let y = Fr::from_le_bytes_mod_order(y_bytes.as_bytes());

        // Solve x² = (1 - y²) / (a - d·y²).
        let y_sq = y.square();
        let numerator = one - y_sq;
        let denominator = a - d * y_sq;
        if denominator.is_zero() {
            continue;
        }
        let x_sq = numerator * denominator.inverse().expect("denominator non-zero");

        // sqrt: returns None if x_sq is a non-residue. ark-ff `sqrt` returns
        // *some* square root; we canonicalise by picking the lex-smaller of
        // (root, -root) so the derivation is deterministic across runs.
        let Some(root) = x_sq.sqrt() else { continue };
        let neg_root = -root;
        let x = if fr_lex_le(&root, &neg_root) {
            root
        } else {
            neg_root
        };

        // Build the candidate point and clear the cofactor (×8) so it lands
        // in the prime-order subgroup. `(x, y)` are already arkworks `Fr`,
        // so the point is constructed directly with no field bridge.
        let candidate = bjj_affine(x, y);
        let cleared = mul_cofactor(&candidate);

        // Identity reject: (0, 1) is the curve's neutral element and would
        // make C = m·G + r·H reducible to m·G alone (binding broken).
        if bjj_is_identity(&cleared) {
            continue;
        }
        // Belt-and-suspenders: cofactor-clearing should always land in the
        // prime subgroup. If this ever fails the curve constants are wrong.
        if !bjj_in_prime_subgroup(&cleared) {
            continue;
        }
        return cleared;
    }

    panic!(
        "Pedersen H derivation failed after {} attempts — \
         this is a bug in the sqrt / bridge / cofactor-mul chain, not a \
         choice of OLY:PEDERSEN:H:V1.",
        MAX_DERIVATION_ATTEMPTS
    );
}

/// Lexicographic `<=` on arkworks `Fr` via canonical big-endian byte
/// representation.  Used to disambiguate `±x` square roots so the
/// derivation is deterministic.
fn fr_lex_le(a: &Fr, b: &Fr) -> bool {
    a.into_bigint().to_bytes_be() <= b.into_bigint().to_bytes_be()
}

// ── First generator G (the circomlib B8 base point) ─────────────────────────

/// Decimal representation of `G.x` — the circomlib `B8` base-point
/// x-coordinate, the prime-subgroup generator used by EdDSA-Poseidon.
/// Source: circomlib `circuits/babyjub.circom` `BASE8`.
const G_X_DEC: &str =
    "5299619240641551281634865583518297030282874472190772894086521144482721001553";
/// Decimal representation of `G.y` — the circomlib `B8` base-point
/// y-coordinate.
const G_Y_DEC: &str =
    "16950150798460657717958625567821834550301663161624707787222815936182638968203";

/// Cached `G = B8`. We construct it from decimal constants rather than
/// relying on the crate's exported `B8` static, keeping the generator pinned
/// to the circomlib base point independently of any upstream representation.
static PEDERSEN_G: OnceLock<BabyJubjubAffine> = OnceLock::new();

fn pedersen_g() -> &'static BabyJubjubAffine {
    PEDERSEN_G.get_or_init(|| {
        let x = bigint_to_ark(&BigInt::from_str(G_X_DEC).expect("G.x is a valid decimal literal"));
        let y = bigint_to_ark(&BigInt::from_str(G_Y_DEC).expect("G.y is a valid decimal literal"));
        bjj_affine(x, y)
    })
}

// ── Commit / verify API ─────────────────────────────────────────────────────

/// Errors returned by [`commit`] / [`verify`].
#[derive(Debug, Error)]
pub enum PedersenError {
    /// Decoding a compressed Baby Jubjub point failed — the 32 bytes do not
    /// represent a valid curve point (e.g. corrupted storage / wire input).
    #[error("Baby Jubjub point decode failed: {0}")]
    Bridge(String),
    /// Scalar input falls outside `[0, l)` where `l` is the Baby Jubjub
    /// prime-subgroup order. Accepting raw `Fr` values (mod the BN254 field
    /// order `r ≈ 8·l`) without this guard would break binding: there exist
    /// up to ~7 distinct `Fr` values `m, m+l, m+2l, …` all satisfying
    /// `commit(m+k·l, r) = commit(m, r)`, so `verify` would accept several
    /// "alternate openings" for the same `C`. Callers feeding hash outputs
    /// (e.g. `Poseidon(jcs(attrs))`) MUST canonicalise to `[0, l)` first.
    #[error("Pedersen scalar `{name}` = {value} must be in [0, l) where l is the Baby Jubjub prime-subgroup order")]
    ScalarOutOfRange { name: &'static str, value: BigInt },
    /// A loaded/decompressed point is on the curve but not in the prime-order
    /// subgroup (or is the identity). Rejected so binding/hiding always rest
    /// on the subgroup discrete-log problem, not the easier full-curve one.
    #[error("Pedersen commitment point is not in the prime-order subgroup")]
    NotInSubgroup,
}

/// Reduce an arkworks `Fr` to a Baby Jubjub subgroup scalar in `[0, l)`,
/// erroring out if the input is out of range.  The choice to *reject* rather
/// than *silently reduce mod l* is deliberate: callers feeding raw hash
/// outputs (Poseidon → `Fr` mod `r ≈ 8·l`) need to know they have a
/// canonicalisation step to perform; silently masking that requirement would
/// hide a binding bug behind a comfortable-looking API.
fn to_subgroup_scalar(name: &'static str, value: &Fr) -> Result<SubgroupScalar, PedersenError> {
    SubgroupScalar::from_field(value).ok_or_else(|| {
        // Constructing a variable-width BigInt is reserved for the rejected
        // path. The Result already declassifies that this scalar was invalid;
        // valid secret scalars never enter num-bigint arithmetic.
        PedersenError::ScalarOutOfRange {
            name,
            value: ark_fr_to_bigint(value),
        }
    })
}

/// A Pedersen commitment `C = m·G + r·H` represented as the affine
/// `(x, y)` coordinates of the resulting Baby Jubjub point in arkworks
/// `Fr` terms (BN254 scalar field).
///
/// The point is always in the prime-order subgroup by construction —
/// both `G` and `H` are, and scalar mul + addition preserve subgroup
/// membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PedersenCommitment {
    pub x: Fr,
    pub y: Fr,
}

impl PedersenCommitment {
    /// Compress to the iden3 32-byte form (y-coordinate + sign bit of x).
    /// Suitable for storage and wire transfer; decompressible via
    /// [`Self::decompress`].
    pub fn compress(&self) -> Result<[u8; 32], PedersenError> {
        Ok(bjj::compress(&self.to_bjj_point()))
    }

    /// Decompress an iden3 32-byte commitment.
    ///
    /// Returns an error if the bytes do not decompress to a valid
    /// Baby Jubjub point (e.g. corrupted storage). The output is **not**
    /// re-checked for prime-subgroup membership here — call
    /// [`Self::is_in_prime_subgroup`] before using it for verification if
    /// the bytes came from an untrusted source.
    pub fn decompress(bytes: [u8; 32]) -> Result<Self, PedersenError> {
        let pt = bjj::decompress(bytes)
            .map_err(|e| PedersenError::Bridge(format!("decompress: {e:?}")))?;
        Ok(Self { x: pt.x, y: pt.y })
    }

    /// Decompress an iden3 32-byte commitment **and** enforce prime-order
    /// subgroup membership (rejecting the identity).
    ///
    /// Prefer this over [`Self::decompress`] for bytes from any untrusted
    /// source (wire transfer, tamperable storage): it folds in the
    /// [`Self::is_in_prime_subgroup`] check that the raw `decompress`
    /// deliberately omits, so callers can't forget it and accidentally accept
    /// a cofactor-coset point. Fails closed with
    /// [`PedersenError::NotInSubgroup`].
    pub fn decompress_checked(bytes: [u8; 32]) -> Result<Self, PedersenError> {
        let c = Self::decompress(bytes)?;
        let pt = c.to_bjj_point();
        if bjj_is_identity(&pt) || !bjj_in_prime_subgroup(&pt) {
            return Err(PedersenError::NotInSubgroup);
        }
        Ok(c)
    }

    /// Belt-and-suspenders subgroup check for commitments arriving from
    /// untrusted sources. Commitments produced by [`commit`] in this
    /// module always satisfy this — both `G` and `H` are prime-subgroup
    /// generators by construction.
    pub fn is_in_prime_subgroup(&self) -> bool {
        bjj_in_prime_subgroup(&self.to_bjj_point())
    }

    // `&self` is intentional: callers (e.g. `is_in_prime_subgroup`) already
    // hold a reference. The conversion is infallible — `babyjubjub_permissive`
    // point coordinates are already `ark_bn254::Fr`.
    #[allow(clippy::wrong_self_convention)]
    fn to_bjj_point(&self) -> BabyJubjubAffine {
        bjj_affine(self.x, self.y)
    }
}

/// Compute the Pedersen commitment `C = m·G + r·H`.
///
/// `m` is the message scalar (typically `Poseidon(jcs(attributes))` for
/// SBT attribute commitments) and `r` is the blinding factor — draw it
/// from [`random_blinding`] for cryptographically sound hiding.
///
/// **Binding requires `m, r ∈ [0, l)`** where `l` is the Baby Jubjub
/// prime-subgroup order.  Callers must canonicalise raw hash outputs
/// (which live in `Fr` mod `r ≈ 8·l`) before calling; the function
/// rejects out-of-range scalars with [`PedersenError::ScalarOutOfRange`]
/// rather than silently reducing, so the canonicalisation requirement is
/// visible at the type level.  [`random_blinding`] already returns
/// in-range values.
pub fn commit(m: Fr, r: Fr) -> Result<PedersenCommitment, PedersenError> {
    let m_scalar = to_subgroup_scalar("m", &m)?;
    let r_scalar = to_subgroup_scalar("r", &r)?;
    Ok(commit_scalars(&m_scalar, &r_scalar))
}

/// Compute a Pedersen commitment while retaining both secret operands in the
/// fixed-width, wipe-on-drop scalar type for the full arithmetic path.
///
/// Credential issuance and other secret-producing paths should prefer this
/// entry point. [`commit`] remains the validating compatibility/verifier API
/// for already exposed arkworks field elements.
pub(crate) fn commit_scalars(
    m_scalar: &SubgroupScalar,
    r_scalar: &SubgroupScalar,
) -> PedersenCommitment {
    let sum = linear_combination_ct(pedersen_g(), m_scalar, pedersen_h(), r_scalar);
    PedersenCommitment { x: sum.x, y: sum.y }
}

/// Verify that `(m, r)` opens the commitment `c`.
///
/// Returns `Ok(true)` iff `c == m·G + r·H`. Recomputes the commitment
/// and compares — constant-time comparison is not enforced here because
/// `c` is a public value; the secret is `(m, r)` and a verifier-side
/// timing leak about `c` would not leak anything.
pub fn verify(c: &PedersenCommitment, m: Fr, r: Fr) -> Result<bool, PedersenError> {
    let recomputed = commit(m, r)?;
    Ok(recomputed == *c)
}

/// Sample a uniform blinding factor in `[0, l)` where `l` is the Baby
/// Jubjub prime-subgroup order.
///
/// Sampling 64 bytes and reducing mod `l` gives a distribution whose
/// statistical distance from uniform is `< 2⁻²⁵⁶` — indistinguishable
/// from uniform in practice. Sampling directly into arkworks `Fr` would
/// be wrong: `Fr`'s modulus `r ≈ 8·l` and the resulting distribution mod
/// `l` would have a noticeable bias on the low end.
pub(crate) fn random_blinding_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> SubgroupScalar {
    let mut bytes = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(&mut *bytes);
    SubgroupScalar::reduce_wide_be(&bytes)
}

/// Compatibility sampler returning a copyable arkworks field element.
///
/// Secret-producing callers should use [`random_blinding_scalar`] and retain
/// the typed scalar through [`commit_scalars`]. This API deliberately exposes
/// the scalar for public opening/verifier compatibility.
pub fn random_blinding<R: RngCore + CryptoRng>(rng: &mut R) -> Fr {
    let scalar = random_blinding_scalar(rng);
    let exposed = scalar.expose_field();
    *exposed
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    // G coordinates live at module scope as G_X_DEC / G_Y_DEC since PD-2 —
    // reuse them here for the "H ≠ G" test rather than duplicating.

    #[test]
    fn h_is_deterministic() {
        // Two calls must return literally the same point — both because the
        // derivation is pure and because OnceLock caches.
        let h1 = pedersen_h();
        let h2 = pedersen_h();
        assert_eq!(h1.x, h2.x);
        assert_eq!(h1.y, h2.y);
    }

    #[test]
    fn h_satisfies_curve_equation() {
        // a·x² + y² ≡ 1 + d·x²·y²  (over BN254 Fr).
        let (x, y) = pedersen_h_ark();
        let a = Fr::from(BJJ_A);
        let d = Fr::from(BJJ_D);
        let lhs = a * x.square() + y.square();
        let rhs = Fr::one() + d * x.square() * y.square();
        assert_eq!(lhs, rhs, "H must satisfy the Baby Jubjub Edwards equation");
    }

    #[test]
    fn h_is_in_prime_subgroup() {
        // After cofactor-clearing, H must be in the prime-order subgroup.
        // This is what makes Pedersen binding/hiding rest on the *subgroup*
        // discrete-log problem, not the (easier) full-curve one.
        assert!(bjj_in_prime_subgroup(pedersen_h()));
    }

    #[test]
    fn h_is_not_identity() {
        // (0, 1) would make H = O and collapse C = m·G + r·O to m·G alone.
        assert!(!bjj_is_identity(pedersen_h()));
    }

    #[test]
    fn h_is_not_iden3_base_generator() {
        // If H == G then log_G(H) = 1 (trivially known) and binding breaks.
        // Cofactor-clearing puts both H and G in the same prime subgroup so
        // simple coordinate inequality is sufficient (no need to check the
        // 8 cofactor cosets).
        let (hx, hy) = pedersen_h_ark();
        let gx_dec: BigInt = G_X_DEC.parse().expect("static decimal");
        let gy_dec: BigInt = G_Y_DEC.parse().expect("static decimal");
        let hx_dec: BigInt =
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &hx.into_bigint().to_bytes_be());
        let hy_dec: BigInt =
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &hy.into_bigint().to_bytes_be());
        assert!(
            !(hx_dec == gx_dec && hy_dec == gy_dec),
            "H must not coincide with the iden3 base generator G"
        );
    }

    // ── Commit / verify property tests ─────────────────────────────────────

    #[test]
    fn commit_then_verify_roundtrips() {
        // For a handful of fixed (m, r) pairs, commit produces a value that
        // verifies back. The values cover small / large / pseudo-random
        // scalars so any off-by-one in the bridge surfaces here.
        let cases = [
            (Fr::from(0u64), Fr::from(1u64)),
            (Fr::from(1u64), Fr::from(0u64)),
            (Fr::from(42u64), Fr::from(99u64)),
            (Fr::from(u64::MAX), Fr::from(u64::MAX)),
        ];
        for (m, r) in cases {
            let c = commit(m, r).expect("commit");
            assert!(verify(&c, m, r).expect("verify"), "round-trip must verify");
        }
    }

    #[test]
    fn fixed_schedule_commit_matches_legacy_arithmetic_oracle() {
        // Compatibility guard for the backend migration: the legacy
        // arkworks/BigInt path is variable-time, but remains suitable as a
        // test-only oracle over fixed public values. Include both identity and
        // the largest canonical subgroup scalar to catch edge behavior.
        let largest = bigint_to_ark(&(bjj_subgroup_order() - BigInt::from(1u8)));
        let cases = [
            (Fr::from(0u64), Fr::from(0u64)),
            (Fr::from(7u64), Fr::from(13u64)),
            (largest, largest),
        ];

        for (m, r) in cases {
            let mg = babyjubjub_permissive::mul_scalar_bigint(pedersen_g(), &ark_fr_to_bigint(&m));
            let rh = babyjubjub_permissive::mul_scalar_bigint(pedersen_h(), &ark_fr_to_bigint(&r));
            let expected = bjj_add(&mg, &rh);
            let actual = commit(m, r).expect("canonical scalar");
            assert_eq!((actual.x, actual.y), (expected.x, expected.y));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn typed_joint_commit_matches_legacy_g_h_oracle(
            m_wide in any::<[u8; 64]>(),
            r_wide in any::<[u8; 64]>(),
        ) {
            let m = SubgroupScalar::reduce_wide_be(&m_wide);
            let r = SubgroupScalar::reduce_wide_be(&r_wide);
            let mut m_bytes = Zeroizing::new([0u8; 32]);
            let mut r_bytes = Zeroizing::new([0u8; 32]);
            m.write_le_bytes(&mut m_bytes);
            r.write_le_bytes(&mut r_bytes);

            // Variable-width arithmetic is intentionally confined to this
            // independent public-data oracle for the frozen G/H generators.
            let m_big = BigInt::from_bytes_le(num_bigint::Sign::Plus, &m_bytes[..]);
            let r_big = BigInt::from_bytes_le(num_bigint::Sign::Plus, &r_bytes[..]);
            let mg = babyjubjub_permissive::mul_scalar_bigint(pedersen_g(), &m_big);
            let rh = babyjubjub_permissive::mul_scalar_bigint(pedersen_h(), &r_big);
            let expected = bjj_add(&mg, &rh);
            let actual = commit_scalars(&m, &r);
            prop_assert_eq!((actual.x, actual.y), (expected.x, expected.y));
        }
    }

    #[test]
    fn commit_is_in_prime_subgroup() {
        // m·G + r·H must stay in the prime-order subgroup — this is what
        // makes binding rest on the subgroup DLP. Both inputs are subgroup
        // generators, so the sum is too; this test catches arithmetic
        // regressions (e.g. accidental cofactor leak).
        let c = commit(Fr::from(7u64), Fr::from(13u64)).expect("commit");
        assert!(c.is_in_prime_subgroup());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        // Binding: flipping `m` while keeping `r` must make verify return
        // false. (Finding a different `m'` such that verify still passes
        // requires solving DLP.)
        let m = Fr::from(42u64);
        let r = Fr::from(99u64);
        let c = commit(m, r).expect("commit");
        assert!(!verify(&c, m + Fr::one(), r).expect("verify"));
    }

    #[test]
    fn verify_rejects_wrong_blinding() {
        // Hiding-side complement: flipping `r` while keeping `m` must also
        // make verify return false.
        let m = Fr::from(42u64);
        let r = Fr::from(99u64);
        let c = commit(m, r).expect("commit");
        assert!(!verify(&c, m, r + Fr::one()).expect("verify"));
    }

    #[test]
    fn different_blindings_produce_different_commitments() {
        // Hiding requires that for a fixed m, varying r gives distinct C
        // with overwhelming probability. Two specific r values is enough
        // to catch a degenerate scheme where r is ignored.
        let m = Fr::from(42u64);
        let c1 = commit(m, Fr::from(1u64)).expect("commit");
        let c2 = commit(m, Fr::from(2u64)).expect("commit");
        assert_ne!(c1, c2, "different blindings must produce different C");
    }

    #[test]
    fn commit_is_additively_homomorphic() {
        // commit(m1, r1) + commit(m2, r2) (as curve points) ≡
        // commit(m1 + m2, r1 + r2). This is the foundational property that
        // unlocks future use cases (sum-of-amounts ranges, blind-sum proofs)
        // and a strong sanity check on the curve arithmetic.
        let (m1, r1) = (Fr::from(7u64), Fr::from(13u64));
        let (m2, r2) = (Fr::from(11u64), Fr::from(17u64));
        let c1 = commit(m1, r1).expect("c1");
        let c2 = commit(m2, r2).expect("c2");

        // Add c1 + c2 as Baby Jubjub points.
        let p1 = bjj_affine(c1.x, c1.y);
        let p2 = bjj_affine(c2.x, c2.y);
        let sum = bjj_add(&p1, &p2);
        let c_sum = PedersenCommitment { x: sum.x, y: sum.y };

        let c_combined = commit(m1 + m2, r1 + r2).expect("c_combined");
        assert_eq!(c_sum, c_combined, "C1 + C2 must equal commit(m1+m2, r1+r2)");
    }

    #[test]
    fn compress_decompress_roundtrips() {
        let c = commit(Fr::from(123u64), Fr::from(456u64)).expect("commit");
        let bytes = c.compress().expect("compress");
        let back = PedersenCommitment::decompress(bytes).expect("decompress");
        assert_eq!(c, back, "compress→decompress must be lossless");
    }

    #[test]
    fn decompress_checked_accepts_valid_rejects_bad() {
        // Caveat (3): the subgroup-enforcing decompress must round-trip a real
        // commitment and fail closed on bytes that don't decode to an
        // in-subgroup point.
        let c = commit(Fr::from(5u64), Fr::from(9u64)).expect("commit");
        let bytes = c.compress().expect("compress");
        let back = PedersenCommitment::decompress_checked(bytes).expect("checked decompress");
        assert_eq!(
            c, back,
            "checked decompress must round-trip a valid commitment"
        );

        // All-0xFF is overwhelmingly not a valid in-subgroup point — either it
        // fails to decompress or fails the subgroup check; both are errors.
        assert!(
            PedersenCommitment::decompress_checked([0xFFu8; 32]).is_err(),
            "checked decompress must reject garbage / off-subgroup bytes"
        );
    }

    #[test]
    fn decompress_checked_rejects_cofactor_coset_point() {
        // Audit L-Z1: the previous test covered the happy path + garbage
        // bytes. The actual reason decompress_checked exists — rejecting
        // points that ARE on the Baby Jubjub curve but NOT in the
        // prime-order subgroup — was untested. Construct H + (0,-1):
        //   * H is in the prime-order subgroup by construction (cofactor-cleared).
        //   * (0, -1) is the unique order-2 point on Baby Jubjub
        //     (twisted Edwards: a·0 + 1 = 1 = 1 + d·0, doubles to (0, 1) = identity).
        //   * Their sum is on the curve (closed under addition) but not in
        //     the prime subgroup, because l·(H + Q) = l·H + l·Q = O + Q = Q ≠ O
        //     for l odd and Q of order 2.
        // decompress_checked must fail closed with NotInSubgroup.

        // Build the order-2 point (0, -1) over BN254 Fr.
        // -1 mod r is the field characteristic minus one.
        let minus_one = -ark_bn254::Fr::one();
        let order_two = bjj_affine(ark_bn254::Fr::zero(), minus_one);
        // Sanity-check the order-two point is not the identity.
        assert!(
            !bjj_is_identity(&order_two),
            "(0, -1) must not be the identity"
        );

        // Construct H + (0, -1) — H is the cached prime-subgroup generator;
        // adding the order-2 point lands in a cofactor coset.
        let coset = bjj_add(pedersen_h(), &order_two);

        // Belt-and-suspenders: confirm the coset point is NOT in the prime
        // subgroup before we ask decompress_checked to reject it. If this
        // assertion ever fails, the curve / cofactor constants drifted.
        assert!(
            !bjj_in_prime_subgroup(&coset),
            "H + (0,-1) must land outside the prime subgroup — test premise broken"
        );

        let bytes = bjj::compress(&coset);
        let err = PedersenCommitment::decompress_checked(bytes)
            .expect_err("cofactor-coset point must be rejected by checked decompress");
        assert!(
            matches!(err, PedersenError::NotInSubgroup),
            "expected NotInSubgroup, got {err:?}"
        );
    }

    #[test]
    fn derive_pedersen_h_does_not_panic() {
        // Caveat (4): derive_pedersen_h() panics only if the sqrt/bridge/
        // cofactor chain is broken. Running the raw (uncached) derivation here
        // proves the panic path is unreachable for the shipped
        // OLY:PEDERSEN:H:V1 tag and that it agrees with the cached value.
        let direct = derive_pedersen_h();
        let cached = pedersen_h();
        assert_eq!(direct.x, cached.x);
        assert_eq!(direct.y, cached.y);
    }

    #[test]
    fn decompress_rejects_garbage() {
        // Arbitrary 32 bytes are very unlikely to encode a valid point.
        // We don't care about the specific error — only that it doesn't
        // panic or silently succeed.
        let garbage = [0xFFu8; 32];
        let _ = PedersenCommitment::decompress(garbage); // may be Ok or Err;
                                                         // the assertion is just "does not panic".
    }

    #[test]
    fn random_blinding_stays_below_subgroup_order() {
        // 64 samples of `random_blinding` must each be in [0, l). Convert
        // back to BigInt and compare.
        let mut rng = rand::thread_rng();
        let l = bjj_subgroup_order().clone();
        for _ in 0..64 {
            let r = random_blinding(&mut rng);
            let r_big =
                BigInt::from_bytes_be(num_bigint::Sign::Plus, &r.into_bigint().to_bytes_be());
            assert!(r_big < l, "blinding must be < subgroup order l");
            assert!(r_big >= BigInt::from(0), "blinding must be non-negative");
        }
    }

    struct SequentialRng {
        next: u8,
        bytes_filled: usize,
    }

    impl rand::RngCore for SequentialRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }
            self.bytes_filled += dest.len();
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for SequentialRng {}

    #[test]
    fn random_blinding_consumes_one_wide_be_scalar_and_matches_biguint_oracle() {
        let mut rng = SequentialRng {
            next: 0x80,
            bytes_filled: 0,
        };
        let actual = random_blinding(&mut rng);

        assert_eq!(rng.bytes_filled, 64, "must consume exactly 512 RNG bits");
        assert_eq!(rng.next, 0xc0, "must consume the bytes in one pass");

        let wide = core::array::from_fn::<_, 64, _>(|index| 0x80u8 + index as u8);
        let (_, modulus_be) = bjj_subgroup_order().to_bytes_be();
        let modulus = num_bigint::BigUint::from_bytes_be(&modulus_be);
        let expected_integer = num_bigint::BigUint::from_bytes_be(&wide) % modulus;
        let expected = Fr::from_be_bytes_mod_order(&expected_integer.to_bytes_be());
        assert_eq!(
            actual, expected,
            "64 RNG bytes must be interpreted big-endian"
        );
    }

    // ── Subgroup-scalar binding guard (CodeRabbit, PR #1008) ───────────────

    #[test]
    fn commit_rejects_m_at_subgroup_order() {
        // `l` itself maps to `0` mod `l` so accepting it would let any
        // caller silently substitute `0` for the message. Rejection at
        // exactly `l` is the binding-preserving choice.
        let l = bigint_to_ark(bjj_subgroup_order());
        let err = commit(l, Fr::from(1u64)).expect_err("must reject m = l");
        match err {
            PedersenError::ScalarOutOfRange { name, .. } => assert_eq!(name, "m"),
            other => panic!("expected ScalarOutOfRange, got {:?}", other),
        }
    }

    #[test]
    fn commit_rejects_r_above_subgroup_order() {
        // `r > l` (in Fr space, still < BN254 modulus) must also reject.
        let above = bigint_to_ark(&(bjj_subgroup_order() + BigInt::from(1)));
        let err = commit(Fr::from(1u64), above).expect_err("must reject r >= l");
        match err {
            PedersenError::ScalarOutOfRange { name, .. } => assert_eq!(name, "r"),
            other => panic!("expected ScalarOutOfRange, got {:?}", other),
        }
    }

    #[test]
    fn commit_accepts_largest_in_range_scalar() {
        // `l - 1` is the largest in-range scalar. Both positions must
        // accept it without error.
        let just_below = bigint_to_ark(&(bjj_subgroup_order() - BigInt::from(1)));
        assert!(commit(just_below, Fr::from(0u64)).is_ok());
        assert!(commit(Fr::from(0u64), just_below).is_ok());
    }

    #[test]
    fn out_of_range_fr_would_alias_inrange_commit_if_unguarded() {
        // Documents the binding attack the guard prevents: in raw Fr
        // arithmetic `(1 + l)` and `1` map to the same curve point. With
        // the guard the API rejects the alternate opening; without it,
        // verify(commit(1, r), 1+l, r) would return true.
        let l = bigint_to_ark(bjj_subgroup_order());
        let one = Fr::from(1u64);
        let one_plus_l = one + l;
        // 1 must commit fine.
        let c = commit(one, Fr::from(7u64)).expect("commit(1, …)");
        // 1+l (which is congruent to 1 mod l) MUST be rejected, not
        // accepted-as-an-alternate-opening.
        assert!(matches!(
            verify(&c, one_plus_l, Fr::from(7u64)),
            Err(PedersenError::ScalarOutOfRange { .. })
        ));
    }

    #[test]
    fn random_blinding_outputs_pass_commit_guard() {
        // random_blinding already samples in [0, l), so commit must accept
        // its outputs without ever hitting ScalarOutOfRange.
        let mut rng = rand::thread_rng();
        for _ in 0..32 {
            let r = random_blinding(&mut rng);
            assert!(commit(Fr::from(1u64), r).is_ok());
        }
    }

    #[test]
    fn random_blinding_is_well_distributed() {
        // Sanity-distribution: the least-significant byte of `r mod l` is
        // essentially uniform mod 256 (negligible bias because l ≫ 256).
        // With 1024 samples, ~99.8% of byte values should appear; the
        // birthday-paradox lower bound is well above 200.  This catches a
        // degenerate `random_blinding` that returns a constant or only a
        // few distinct values, without false-positiving on the reduced-mod-l
        // top-byte truncation (top byte can only take values 0..~6, which
        // *is* the entire range when `r ∈ [0, l)`).
        let mut rng = rand::thread_rng();
        let mut lsb_set = std::collections::HashSet::new();
        for _ in 0..1024 {
            let r = random_blinding(&mut rng);
            let bytes = r.into_bigint().to_bytes_be();
            lsb_set.insert(*bytes.last().expect("32-byte BE form"));
        }
        assert!(
            lsb_set.len() > 200,
            "random_blinding LSB looks degenerate — only {} / 256 distinct values in 1024 samples",
            lsb_set.len()
        );
    }

    // ── H golden pin (PD-1) ─────────────────────────────────────────────────

    #[test]
    fn h_coordinates_are_pinned() {
        // Golden test: any change to the derivation algorithm or to the
        // OLY:PEDERSEN:H:V1 domain tag is a hard-break of every existing
        // commitment. Pin H so the change surfaces as a test failure rather
        // than silent ledger corruption.
        //
        // These values are the output of `derive_pedersen_h()` at the time
        // PD-1 landed; if they ever need to change, every SBT commitment
        // issued under the old H must be considered unverifiable.
        let (x, y) = pedersen_h_ark();
        let x_be = hex::encode(x.into_bigint().to_bytes_be());
        let y_be = hex::encode(y.into_bigint().to_bytes_be());
        assert_eq!(
            x_be, "007065a7c12920cd37c3b1f1bbfcf7b048bb805a72d914daf577f18c5cad3399",
            "Pedersen H.x has drifted — every existing commitment is now unverifiable"
        );
        assert_eq!(
            y_be, "2a88b2bf301f0dc6c2341819a8097314a1a5d1e4745a9085d89ab83fca0b5dbb",
            "Pedersen H.y has drifted — every existing commitment is now unverifiable"
        );
    }
}
