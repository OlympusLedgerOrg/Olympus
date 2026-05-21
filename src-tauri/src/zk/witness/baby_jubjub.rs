//! Baby Jubjub EdDSA-Poseidon signer + types for the `unified` circuit.
//!
//! Baby Jubjub is the twisted-Edwards curve native to BN254 — its base
//! field equals BN254's scalar field, so curve points and circuit witness
//! values share the same `Fr` representation.  The `unified` circuit
//! verifies an EdDSA-Poseidon signature using `circomlib`'s
//! `EdDSAPoseidonVerifier` template.
//!
//! Implementation note
//! -------------------
//! The signer wraps `babyjubjub-rs` (iden3's own reference port; produces
//! signatures that `EdDSAPoseidonVerifier` accepts byte-for-byte).  The
//! crate speaks iden3 `ff_ce` field types rather than arkworks `Fr` —
//! both wrap the same BN254 scalar field, so the bridge is a pure
//! bigint round-trip with no math.  The conversion lives here so the
//! rest of the witness layer keeps a single consistent `ark_bn254::Fr`
//! type system.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use babyjubjub_rs::{Point as BjjPoint, PrivateKey};
use ff_ce::PrimeField as FfPrimeField;
use num_bigint::{BigInt, BigUint, Sign};
use thiserror::Error;

use crate::zk::poseidon::{hash2, PoseidonError};

#[derive(Debug, Error)]
pub enum BabyJubJubError {
    #[error("private key must be 32 bytes")]
    BadPrivateKeyLen,
    #[error("babyjubjub-rs signer error: {0}")]
    Signer(String),
    #[error("Poseidon error: {0}")]
    Poseidon(#[from] PoseidonError),
    #[error("iden3 Fr parse failed: {0}")]
    Iden3Parse(String),
    /// Edge case 1 — BabyJubjub subgroup/malleability exploit.
    ///
    /// BabyJubjub has cofactor h=8, so the full curve group has order 8·l
    /// where l is the prime subgroup order. A signature whose R8 component
    /// is NOT in the prime-order subgroup has 8 distinct valid representations
    /// (one per coset) that all verify against the same public key. An attacker
    /// can mutate R8 to any of these representations and re-submit a payload
    /// that passes verification but defeats deduplication checks.
    #[error("BabyJubjub point is not in the prime-order subgroup (cofactor h=8 exploit)")]
    SubgroupCheckFailed,
}

/// Baby Jubjub public key in affine coordinates (arkworks `Fr`).
#[derive(Debug, Clone, Copy)]
pub struct BabyJubJubPubKey {
    pub x: Fr,
    pub y: Fr,
}

/// EdDSA-Poseidon signature over Baby Jubjub.
///
/// Field names match circomlib's `EdDSAPoseidonVerifier` private inputs.
#[derive(Debug, Clone, Copy)]
pub struct BabyJubJubSignature {
    pub r8x: Fr,
    pub r8y: Fr,
    pub s: Fr,
}

impl BabyJubJubPubKey {
    /// The in-circuit `authorityPubKeyHash` = `Poseidon(Ax, Ay)`.
    /// Callers use this as a public input — the circuit re-derives it
    /// from the private (Ax, Ay) inputs and constrains equality.
    pub fn authority_hash(&self) -> Result<Fr, PoseidonError> {
        hash2(self.x, self.y)
    }

    /// Derive the public key from a 32-byte raw private key, using
    /// `babyjubjub-rs`' circomlib-compatible scalar derivation (BLAKE-512
    /// + RFC-8032 bit pruning + `>> 3` to land in the prime subgroup).
    pub fn from_private(priv_key: &[u8; 32]) -> Result<Self, BabyJubJubError> {
        let sk =
            PrivateKey::import(priv_key.to_vec()).map_err(|_| BabyJubJubError::BadPrivateKeyLen)?;
        let point = sk.public();
        Ok(BabyJubJubPubKey {
            x: iden3_to_ark(&point.x),
            y: iden3_to_ark(&point.y),
        })
    }
}

/// Sign `message` (an `Fr` in BN254's scalar field) with the 32-byte raw
/// private key.  Produces a signature in arkworks `Fr` terms that the
/// `unified` circuit's `EdDSAPoseidonVerifier` will accept.
pub fn sign(priv_key: &[u8; 32], message: Fr) -> Result<BabyJubJubSignature, BabyJubJubError> {
    let sk =
        PrivateKey::import(priv_key.to_vec()).map_err(|_| BabyJubJubError::BadPrivateKeyLen)?;
    let msg_bigint = ark_fr_to_bigint(&message);
    let sig = sk.sign(msg_bigint).map_err(BabyJubJubError::Signer)?;
    Ok(BabyJubJubSignature {
        r8x: iden3_to_ark(&sig.r_b8.x),
        r8y: iden3_to_ark(&sig.r_b8.y),
        s: bigint_to_ark(&sig.s),
    })
}

// ── Subgroup / malleability guards ────────────────────────────────────────────

/// BabyJubjub prime subgroup order l.
/// The full curve has order 8·l; a point is in the prime-order subgroup
/// iff l·P = O (the identity element).
const BABYJ_SUBGROUP_ORDER: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

/// Return `true` if `point` is the BabyJubjub identity element `(0, 1)`.
///
/// For a twisted-Edwards curve the identity is always `(0, 1)` — the neutral
/// element of the group law, distinct from the point at infinity used on
/// short-Weierstrass curves.
fn bjj_is_identity(point: &BjjPoint) -> bool {
    // PrimeField::from_str parses a decimal string and returns Option<Self>.
    let zero = <babyjubjub_rs::Fr as FfPrimeField>::from_str("0").expect("static");
    let one = <babyjubjub_rs::Fr as FfPrimeField>::from_str("1").expect("static");
    point.x == zero && point.y == one
}

/// Return `true` if `point` lies in the prime-order subgroup of BabyJubjub.
///
/// Multiplies by the subgroup order `l` and checks that the result is the
/// identity `(0, 1)`.  Low-order cofactor points and any combination that
/// includes a non-trivial cofactor component produce a non-identity result.
///
/// This is the authoritative host-side check that mirrors what
/// `EdDSAPoseidonVerifier` enforces in-circuit via the cofactor multiplication
/// of `R8 = 8·R` — when accepting points from external sources (Protobuf,
/// IPC) we must replicate that invariant before handing values to the circuit.
fn bjj_in_prime_subgroup(point: &BjjPoint) -> bool {
    let l: BigInt = BABYJ_SUBGROUP_ORDER.parse().expect("static constant");
    let result = point.mul_scalar(&l);
    bjj_is_identity(&result)
}

/// Validate that the `R8` component of an EdDSA signature is in the
/// prime-order subgroup of BabyJubjub.
///
/// Call this whenever a [`BabyJubJubSignature`] arrives from an external
/// source (Protobuf deserialization, JSON-RPC, IPC bridge) before passing it
/// to the circuit witness.  Signatures produced by [`sign`] in this module
/// are always safe — the iden3 signer multiplies R by 8 internally, which
/// guarantees prime-subgroup membership.  The risk is with externally-supplied
/// signatures where a malicious node may have substituted a cofactor-variant
/// R8 to produce eight distinct payloads that all verify cleanly.
pub fn validate_signature_r8(sig: &BabyJubJubSignature) -> Result<(), BabyJubJubError> {
    // Reconstruct the iden3 R8 point from the arkworks coordinates.
    // ark_to_iden3 already returns BabyJubJubError, so ? propagates directly.
    let r8_point = BjjPoint {
        x: ark_to_iden3(&sig.r8x)?,
        y: ark_to_iden3(&sig.r8y)?,
    };
    // Reject the identity (0, 1) explicitly: l·O = O, so bjj_in_prime_subgroup
    // returns true for it, but a degenerate R8 = O means R = O and the circuit
    // rejects the signature anyway.  Block it at the host layer too.
    if bjj_is_identity(&r8_point) {
        return Err(BabyJubJubError::SubgroupCheckFailed);
    }
    if !bjj_in_prime_subgroup(&r8_point) {
        return Err(BabyJubJubError::SubgroupCheckFailed);
    }
    Ok(())
}

// ── Point arithmetic helpers ────────────────────────────────────────────────────

/// Negate a BabyJubjub point expressed in arkworks `Fr` coordinates.
///
/// Edge case 10 — twisted-Edwards point inversion.
///
/// For the twisted-Edwards curve `ax² + y² = 1 + dx²y²`, the inverse of
/// `(x, y)` is `(-x, y)`.  **Not** `(x, -y)` as it would be for a
/// short-Weierstrass curve, and **not** a raw field negation of both
/// coordinates.  Confusing the two conventions breaks signature subtraction
/// and range proofs that compute `A - B` as `A + negate(B)`.
///
/// In the prime field GF(r) the additive inverse of `x` is `r - x` (mod r),
/// computed here via `Fr`'s built-in `neg()`.  The y-coordinate is unchanged.
pub fn negate_bjj_point(x: Fr, y: Fr) -> (Fr, Fr) {
    (-x, y)
}

// ── Bridge helpers ─────────────────────────────────────────────────────────────

/// arkworks `Fr` → unsigned `BigInt` (always non-negative).
fn ark_fr_to_bigint(f: &Fr) -> BigInt {
    let bytes_be = f.into_bigint().to_bytes_be();
    BigInt::from_bytes_be(Sign::Plus, &bytes_be)
}

/// `BigInt` → arkworks `Fr`, reduced mod r.
fn bigint_to_ark(n: &BigInt) -> Fr {
    let (_, bytes_le) = n.to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes_le)
}

/// iden3 `Fr` → arkworks `Fr`.  Both wrap the same BN254 scalar field;
/// the bridge serialises via the underlying repr's `[u64; 4]` (little-endian
/// limbs) and re-imports.
fn iden3_to_ark(f: &babyjubjub_rs::Fr) -> Fr {
    // `into_repr()` returns the canonical `FrRepr([u64; 4])`.  Concatenate
    // the limbs little-endian to recover the 32-byte form, then feed into
    // arkworks' `from_le_bytes_mod_order`.
    let repr = f.into_repr();
    let mut bytes_le = Vec::with_capacity(32);
    for limb in repr.0.iter() {
        bytes_le.extend_from_slice(&limb.to_le_bytes());
    }
    Fr::from_le_bytes_mod_order(&bytes_le)
}

/// arkworks `Fr` → iden3 `Fr` (kept for symmetry; not used by `sign()` but
/// useful for tests that round-trip values through both sides).
#[allow(dead_code)]
fn ark_to_iden3(f: &Fr) -> Result<babyjubjub_rs::Fr, BabyJubJubError> {
    let bytes_le = f.into_bigint().to_bytes_le();
    let n = BigUint::from_bytes_le(&bytes_le);
    babyjubjub_rs::Fr::from_str(&n.to_string()).ok_or_else(|| {
        BabyJubJubError::Iden3Parse("Fr::from_str rejected decimal repr".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use babyjubjub_rs::{verify, Signature};

    /// Pull the underlying `babyjubjub_rs::Point` back out of an arkworks
    /// pubkey for handing to the iden3 verifier in tests.
    fn ark_pubkey_to_iden3_point(pk: &BabyJubJubPubKey) -> BjjPoint {
        BjjPoint {
            x: ark_to_iden3(&pk.x).expect("x"),
            y: ark_to_iden3(&pk.y).expect("y"),
        }
    }

    fn ark_sig_to_iden3_sig(sig: &BabyJubJubSignature) -> Signature {
        Signature {
            r_b8: BjjPoint {
                x: ark_to_iden3(&sig.r8x).expect("r8x"),
                y: ark_to_iden3(&sig.r8y).expect("r8y"),
            },
            s: {
                let bytes_be = sig.s.into_bigint().to_bytes_be();
                BigInt::from_bytes_be(Sign::Plus, &bytes_be)
            },
        }
    }

    #[test]
    fn sign_then_verify_via_iden3_roundtrip() {
        // Deterministic 32-byte private key for test reproducibility.
        let priv_key: [u8; 32] = {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(7).wrapping_add(13);
            }
            k
        };

        let pk = BabyJubJubPubKey::from_private(&priv_key).expect("pubkey derive");
        let message = Fr::from(42u64);
        let sig = sign(&priv_key, message).expect("sign");

        // Round-trip back to iden3 types and verify with iden3's own
        // verifier — that's the same check `EdDSAPoseidonVerifier` runs in
        // the circuit, so a success here means the in-circuit verifier
        // will also accept the signature.
        let iden3_pk = ark_pubkey_to_iden3_point(&pk);
        let iden3_sig = ark_sig_to_iden3_sig(&sig);
        let msg_bigint = ark_fr_to_bigint(&message);
        assert!(
            verify(iden3_pk, iden3_sig, msg_bigint),
            "iden3 verifier must accept the bridged signature"
        );
    }

    #[test]
    fn bridge_is_lossless_on_random_fr() {
        let mut rng = rand::thread_rng();
        for _ in 0..32 {
            let original = Fr::rand(&mut rng);
            let iden3 = ark_to_iden3(&original).expect("ark → iden3");
            let back = iden3_to_ark(&iden3);
            assert_eq!(original, back, "Fr round-trip must be lossless");
        }
    }

    #[test]
    fn authority_hash_matches_poseidon_of_coordinates() {
        let priv_key = [0xAB_u8; 32];
        let pk = BabyJubJubPubKey::from_private(&priv_key).expect("pubkey");
        let h = pk.authority_hash().expect("hash");
        let expected = hash2(pk.x, pk.y).expect("poseidon");
        assert_eq!(h, expected);
    }

    // ── Edge case 1: subgroup / malleability ──────────────────────────────────

    #[test]
    fn signature_r8_from_signer_passes_subgroup_check() {
        // Signatures produced by our signer always have R8 in the prime subgroup.
        let priv_key = [0x42_u8; 32];
        let msg = Fr::from(7u64);
        let sig = sign(&priv_key, msg).expect("sign");
        validate_signature_r8(&sig)
            .expect("R8 from our own signer must be in the prime-order subgroup");
    }

    #[test]
    fn identity_point_is_flagged_by_bjj_is_identity() {
        // The identity element (0, 1) should be correctly detected.
        // (0,1) as R8 in a real signature would mean R = O — a degenerate case
        // the circuit rejects. Test that bjj_is_identity correctly flags it.
        let zero = <babyjubjub_rs::Fr as FfPrimeField>::from_str("0").unwrap();
        let one = <babyjubjub_rs::Fr as FfPrimeField>::from_str("1").unwrap();
        let identity = BjjPoint { x: zero, y: one };
        assert!(bjj_is_identity(&identity));
    }

    #[test]
    fn validate_signature_r8_rejects_identity_r8() {
        // Regression: l·O = O, so the subgroup check alone passes for the
        // identity. validate_signature_r8 must reject it explicitly.
        use ark_ff::Zero;
        // Build a signature with R8 = (0, 1) — the identity point.
        let degenerate_sig = BabyJubJubSignature {
            r8x: Fr::zero(),
            r8y: Fr::from(1u64),
            s: Fr::zero(),
        };
        assert!(
            validate_signature_r8(&degenerate_sig).is_err(),
            "identity R8 must be rejected"
        );
    }

    // ── Edge case 10: twisted-Edwards point negation ──────────────────────────

    #[test]
    fn negation_uses_minus_x_not_minus_y() {
        // For twisted Edwards, negate(x,y) = (-x, y).
        // Verify: negate(negate(P)) == P, and that x flips while y is stable.
        let priv_key = [0x11_u8; 32];
        let pk = BabyJubJubPubKey::from_private(&priv_key).expect("pubkey");
        let (neg_x, neg_y) = negate_bjj_point(pk.x, pk.y);
        // y must be unchanged
        assert_eq!(neg_y, pk.y, "y-coordinate must be unchanged under negation");
        // x must flip (neg_x + pk.x == 0 in Fr)
        assert_eq!(neg_x + pk.x, Fr::from(0u64), "x + (-x) must equal zero");
        // double-negation recovers the original point
        let (dn_x, dn_y) = negate_bjj_point(neg_x, neg_y);
        assert_eq!((dn_x, dn_y), (pk.x, pk.y), "double-negation is the identity");
    }

    #[test]
    fn negation_zero_x_is_self_inverse() {
        // (0, y) is its own inverse: negate(0, y) = (-0, y) = (0, y).
        let zero_x = Fr::from(0u64);
        let some_y = Fr::from(1u64);
        let (nx, ny) = negate_bjj_point(zero_x, some_y);
        assert_eq!(nx, zero_x);
        assert_eq!(ny, some_y);
    }
}
