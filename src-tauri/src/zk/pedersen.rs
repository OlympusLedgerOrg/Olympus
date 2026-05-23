//! Pedersen commitments on Baby Jubjub.
//!
//! This module currently provides only the second-generator `H` derivation
//! (PD-1).  The `commit(m, r) = m·G + r·H` API and verifier land in PD-2.
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
use num_bigint::BigInt;
use olympus_crypto::PEDERSEN_H_PREFIX;

use super::witness::baby_jubjub::{ark_to_iden3, bjj_in_prime_subgroup, bjj_is_identity, iden3_to_ark};

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

#[cfg(test)]
mod tests {
    use super::*;
    /// Well-known iden3 `B8` base-point coordinates (the prime-subgroup
    /// generator used by EdDSA-Poseidon).  Hard-coded here to avoid taking
    /// a transitive lazy_static dependency on babyjubjub-rs's static export,
    /// which has shifted between minor versions.  Source: circomlib
    /// `circuits/babyjub.circom` BASE8 constants.
    const IDEN3_G_X_DEC: &str =
        "5299619240641551281634865583518297030282874472190772894086521144482721001553";
    const IDEN3_G_Y_DEC: &str =
        "16950150798460657717958625567821834550301663161624707787222815936182638968203";

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
        let gx_dec: BigInt = IDEN3_G_X_DEC.parse().expect("static decimal");
        let gy_dec: BigInt = IDEN3_G_Y_DEC.parse().expect("static decimal");
        let hx_dec: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hx.into_bigint().to_bytes_be());
        let hy_dec: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hy.into_bigint().to_bytes_be());
        assert!(
            !(hx_dec == gx_dec && hy_dec == gy_dec),
            "H must not coincide with the iden3 base generator G"
        );
    }

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
