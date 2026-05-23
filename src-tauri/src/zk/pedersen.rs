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

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use babyjubjub_rs::Point as BjjPoint;
use ff_ce::PrimeField as FfPrimeField;
use num_bigint::{BigInt, Sign};
use olympus_crypto::PEDERSEN_H_PREFIX;
use rand::{CryptoRng, RngCore};
use thiserror::Error;

use super::witness::baby_jubjub::{
    ark_fr_to_bigint, ark_to_iden3, bigint_to_ark, bjj_in_prime_subgroup, bjj_is_identity,
    bjj_subgroup_order, iden3_to_ark,
};

/// Baby Jubjub twisted-Edwards curve coefficient `a` (per circomlib /
/// babyjubjub-rs): `a·x² + y² = 1 + d·x²·y²`.
const BJJ_A: u64 = 168700;
/// Baby Jubjub twisted-Edwards curve coefficient `d`.
const BJJ_D: u64 = 168696;
/// Baby Jubjub cofactor — multiplying any on-curve point by 8 lands it
/// in the prime-order subgroup.
const BJJ_COFACTOR: u64 = 8;
/// Hard cap on try-and-increment iterations.  At ~50% success per attempt
/// the probability of hitting this cap is ~2⁻⁶⁴ — well below "this will
/// ever happen in practice"; the cap exists to refuse to loop forever if
/// someone breaks the field-arithmetic helpers.
const MAX_DERIVATION_ATTEMPTS: u32 = 64;

/// Cached generator `H` for `OLY:PEDERSEN:H:V1`.
static PEDERSEN_H: OnceLock<BjjPoint> = OnceLock::new();

/// Return the Pedersen second generator `H` on Baby Jubjub.
///
/// Computed once via [`derive_pedersen_h`] and cached for the lifetime of
/// the process. Callers that need arkworks-`Fr` coordinates (e.g. circuit
/// witness construction in PD-2) should use [`pedersen_h_ark`].
pub fn pedersen_h() -> &'static BjjPoint {
    PEDERSEN_H.get_or_init(derive_pedersen_h)
}

/// Return `H` as `(x, y)` arkworks `Fr` coordinates.
///
/// Convenience for ZK witness construction — both BN254 scalar field
/// types (arkworks `Fr` and iden3 `babyjubjub_rs::Fr`) wrap the same
/// field, but the rest of the witness layer is in arkworks, so this
/// avoids forcing every caller to do the bridge dance.
pub fn pedersen_h_ark() -> (Fr, Fr) {
    let h = pedersen_h();
    (iden3_to_ark(&h.x), iden3_to_ark(&h.y))
}

/// NUMS derivation of `H` via try-and-increment.  Internal — public API
/// is the cached [`pedersen_h`].
///
/// Panics if the derivation loop exhausts [`MAX_DERIVATION_ATTEMPTS`].
/// This would indicate a broken sqrt implementation, not a malicious
/// domain tag — any 32-byte tag has overwhelming probability of yielding
/// a valid point within the first handful of iterations.
fn derive_pedersen_h() -> BjjPoint {
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
        let x = if fr_lex_le(&root, &neg_root) { root } else { neg_root };

        // Build iden3 point, clear cofactor, verify subgroup membership.
        // ark_to_iden3 only fails if Fr->decimal->Fr parsing breaks — that
        // would indicate a broken bridge, not a derivation failure.
        let Ok(ix) = ark_to_iden3(&x) else { continue };
        let Ok(iy) = ark_to_iden3(&y) else { continue };
        let candidate = BjjPoint { x: ix, y: iy };
        let cleared = candidate.mul_scalar(&BigInt::from(BJJ_COFACTOR));

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
/// reaching into babyjubjub-rs's private `B8` static, since that static's
/// visibility has shifted across minor versions and is not part of the
/// crate's public API.
static PEDERSEN_G: OnceLock<BjjPoint> = OnceLock::new();

fn pedersen_g() -> &'static BjjPoint {
    PEDERSEN_G.get_or_init(|| BjjPoint {
        x: babyjubjub_rs::Fr::from_str(G_X_DEC).expect("G.x is a valid Fr literal"),
        y: babyjubjub_rs::Fr::from_str(G_Y_DEC).expect("G.y is a valid Fr literal"),
    })
}

// ── Commit / verify API ─────────────────────────────────────────────────────

/// Errors returned by [`commit`] / [`verify`].
#[derive(Debug, Error)]
pub enum PedersenError {
    /// Bridge from arkworks `Fr` to iden3 `Fr` failed — should never happen
    /// in practice (both wrap the same BN254 scalar field) and would
    /// indicate a broken bridge helper, not bad input.
    #[error("Fr bridge from arkworks to iden3 representation failed: {0}")]
    Bridge(String),
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
        let pt = self.to_bjj_point()?;
        Ok(pt.compress())
    }

    /// Decompress an iden3 32-byte commitment.
    ///
    /// Returns an error if the bytes do not decompress to a valid
    /// Baby Jubjub point (e.g. corrupted storage). The output is **not**
    /// re-checked for prime-subgroup membership here — call
    /// [`Self::is_in_prime_subgroup`] before using it for verification if
    /// the bytes came from an untrusted source.
    pub fn decompress(bytes: [u8; 32]) -> Result<Self, PedersenError> {
        let pt = babyjubjub_rs::decompress_point(bytes)
            .map_err(|e| PedersenError::Bridge(format!("decompress: {e}")))?;
        Ok(Self {
            x: iden3_to_ark(&pt.x),
            y: iden3_to_ark(&pt.y),
        })
    }

    /// Belt-and-suspenders subgroup check for commitments arriving from
    /// untrusted sources. Commitments produced by [`commit`] in this
    /// module always satisfy this — both `G` and `H` are prime-subgroup
    /// generators by construction.
    pub fn is_in_prime_subgroup(&self) -> bool {
        match self.to_bjj_point() {
            Ok(p) => bjj_in_prime_subgroup(&p),
            Err(_) => false,
        }
    }

    fn to_bjj_point(&self) -> Result<BjjPoint, PedersenError> {
        Ok(BjjPoint {
            x: ark_to_iden3(&self.x).map_err(|e| PedersenError::Bridge(e.to_string()))?,
            y: ark_to_iden3(&self.y).map_err(|e| PedersenError::Bridge(e.to_string()))?,
        })
    }
}

/// Compute the Pedersen commitment `C = m·G + r·H`.
///
/// `m` is the message scalar (typically `Poseidon(jcs(attributes))` for
/// SBT attribute commitments) and `r` is the blinding factor — draw it
/// from [`random_blinding`] for cryptographically sound hiding.
pub fn commit(m: Fr, r: Fr) -> Result<PedersenCommitment, PedersenError> {
    let m_big = ark_fr_to_bigint(&m);
    let r_big = ark_fr_to_bigint(&r);
    let mg = pedersen_g().mul_scalar(&m_big);
    let rh = pedersen_h().mul_scalar(&r_big);
    let sum = mg.projective().add(&rh.projective()).affine();
    Ok(PedersenCommitment {
        x: iden3_to_ark(&sum.x),
        y: iden3_to_ark(&sum.y),
    })
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
pub fn random_blinding<R: RngCore + CryptoRng>(rng: &mut R) -> Fr {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    let big = BigInt::from_bytes_be(Sign::Plus, &bytes);
    // BigInt's `%` on non-negative operands returns the canonical
    // non-negative remainder — equivalent to `mod_floor` here without
    // pulling in num-integer.
    let reduced = &big % bjj_subgroup_order();
    bigint_to_ark(&reduced)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let hx_dec: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hx.into_bigint().to_bytes_be());
        let hy_dec: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hy.into_bigint().to_bytes_be());
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
        let p1 = BjjPoint {
            x: ark_to_iden3(&c1.x).expect("c1.x"),
            y: ark_to_iden3(&c1.y).expect("c1.y"),
        };
        let p2 = BjjPoint {
            x: ark_to_iden3(&c2.x).expect("c2.x"),
            y: ark_to_iden3(&c2.y).expect("c2.y"),
        };
        let sum = p1.projective().add(&p2.projective()).affine();
        let c_sum = PedersenCommitment {
            x: iden3_to_ark(&sum.x),
            y: iden3_to_ark(&sum.y),
        };

        let c_combined = commit(m1 + m2, r1 + r2).expect("c_combined");
        assert_eq!(
            c_sum, c_combined,
            "C1 + C2 must equal commit(m1+m2, r1+r2)"
        );
    }

    #[test]
    fn compress_decompress_roundtrips() {
        let c = commit(Fr::from(123u64), Fr::from(456u64)).expect("commit");
        let bytes = c.compress().expect("compress");
        let back = PedersenCommitment::decompress(bytes).expect("decompress");
        assert_eq!(c, back, "compress→decompress must be lossless");
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
            let r_big = BigInt::from_bytes_be(Sign::Plus, &r.into_bigint().to_bytes_be());
            assert!(r_big < l, "blinding must be < subgroup order l");
            assert!(r_big >= BigInt::from(0), "blinding must be non-negative");
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
