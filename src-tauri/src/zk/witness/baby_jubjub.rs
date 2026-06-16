//! Baby Jubjub EdDSA-Poseidon signer + off-circuit verifier.
//!
//! Baby Jubjub is the twisted-Edwards curve native to BN254 — its base
//! field equals BN254's scalar field, so curve points and circuit witness
//! values share the same `Fr` representation.
//!
//! **Where signatures are verified.** Olympus does NOT have an in-circuit
//! `EdDSAPoseidonVerifier`. The `unified` circuit's docstring at
//! `proofs/circuits/unified_canonicalization_inclusion_root_sign.circom:42`
//! is explicit: checkpoint integrity (including federation signatures)
//! is verified at the Rust layer. `verify_signature` in this file is the
//! authoritative path; `federation::verify::verify_checkpoint_signature`
//! is its only production caller. An earlier roadmap intended to add an
//! in-circuit `EdDSAPoseidonVerifier`; that work never landed, and
//! references to "the in-circuit verifier" in this file's history were
//! aspirational rather than descriptive. Audit C-1.
//!
//! The subgroup / scalar-bound / R8 checks below are real and necessary —
//! they're motivated by the BabyJubjub cofactor (h=8) and the BN254
//! scalar-field-vs-subgroup-order mismatch (r ≈ 8·l), and they're what
//! the underlying EdDSA verifier expects from a well-formed signature.
//! Where prior doc comments justified them as "matching what
//! `EdDSAPoseidonVerifier` checks in-circuit," they were correct about
//! the invariant but wrong about the venue.
//!
//! Implementation note
//! -------------------
//! The signer wraps [`babyjubjub_permissive`] — the in-repo, permissively
//! licensed (Apache-2.0) circomlib-compatible BJJ-EdDSA implementation
//! that replaced `babyjubjub-rs` (whose transitive `poseidon-rs`
//! dependency is GPL-3.0). The permissive crate's point coordinates and
//! signature `r8` are already `ark_bn254::Fr`, so no field bridge is
//! needed; only the response scalar `s` (which lives in the prime-subgroup
//! field `l`) is converted to/from `ark_bn254::Fr` for the public API,
//! and that conversion is exact because canonical `s` is `< l < r`.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use babyjubjub_permissive::{
    self as bjj, is_identity, is_in_prime_subgroup, is_on_curve, BabyJubjubAffine, PrivateKey,
    PublicKey, Signature as PermSignature,
};
use num_bigint::{BigInt, BigUint, Sign};
use thiserror::Error;

use crate::zk::poseidon::{hash2, PoseidonError};

#[derive(Debug, Error)]
pub enum BabyJubJubError {
    #[error("private key must be 32 bytes")]
    BadPrivateKeyLen,
    #[error("BabyJubjub signer error: {0}")]
    Signer(String),
    #[error("Poseidon error: {0}")]
    Poseidon(#[from] PoseidonError),
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
/// Field names mirror `circomlib`'s `EdDSAPoseidonVerifier` template so a
/// future revision that wires an in-circuit verifier can use this struct
/// unchanged. The current circuit does NOT consume these fields — they
/// ride on `UnifiedWitness` purely as off-circuit context for
/// `federation::verify::verify_checkpoint_signature`. Audit C-1.
#[derive(Debug, Clone, Copy)]
pub struct BabyJubJubSignature {
    pub r8x: Fr,
    pub r8y: Fr,
    pub s: Fr,
}

impl BabyJubJubPubKey {
    /// `authorityPubKeyHash` = `Poseidon(Ax, Ay)`. Stable off-circuit
    /// identifier for the authority pubkey; appears in federation
    /// checkpoint envelopes and is reconstructed from `(Ax, Ay)` by both
    /// the signer and `verify_checkpoint_signature`.
    ///
    /// (Earlier doc here claimed this was an in-circuit public input that
    /// the unified circuit re-derived from private `(Ax, Ay)` and
    /// constrained equality on. The unified circuit has no such logic;
    /// it's an off-circuit identifier only. Audit C-1.)
    pub fn authority_hash(&self) -> Result<Fr, PoseidonError> {
        hash2(self.x, self.y)
    }

    /// Derive the public key from a 32-byte raw private key, using
    /// `babyjubjub_permissive`'s circomlib-compatible scalar derivation
    /// (BLAKE-512 + RFC-8032 bit pruning + `>> 3` to land in the prime
    /// subgroup).
    pub fn from_private(priv_key: &[u8; 32]) -> Result<Self, BabyJubJubError> {
        let sk = PrivateKey::from_bytes(priv_key).map_err(|_| BabyJubJubError::BadPrivateKeyLen)?;
        let (x, y) = sk.public().coords();
        Ok(BabyJubJubPubKey { x, y })
    }
}

/// Sign `message` (an `Fr` in BN254's scalar field) with the 32-byte raw
/// private key. Produces a signature in arkworks `Fr` terms that
/// [`verify_signature`] accepts. The signature is consumed off-circuit
/// only — there is no in-circuit verifier in the current `unified`
/// circuit. Audit C-1.
pub fn sign(priv_key: &[u8; 32], message: Fr) -> Result<BabyJubJubSignature, BabyJubJubError> {
    let sk = PrivateKey::from_bytes(priv_key).map_err(|_| BabyJubJubError::BadPrivateKeyLen)?;
    let sig = sk
        .sign(message)
        .map_err(|e| BabyJubJubError::Signer(e.to_string()))?;
    Ok(BabyJubJubSignature {
        r8x: sig.r8.x,
        r8y: sig.r8.y,
        s: perm_scalar_to_ark(&sig.s),
    })
}

/// Verify `signature` against `pubkey` over `message`. Returns `true` iff
/// the EdDSA-Poseidon signature on BabyJubJub validates. This is the
/// **authoritative** verifier in the Olympus codebase — there is no
/// in-circuit `EdDSAPoseidonVerifier` in the unified circuit, despite
/// the `_root_sign` suffix in the circuit file name. Federation's
/// `verify_checkpoint_signature` is its production caller; native SBT
/// verification and any other path that needs "did the authority sign
/// this?" goes through here. Audit C-1.
pub fn verify_signature(
    pubkey: &BabyJubJubPubKey,
    signature: &BabyJubJubSignature,
    message: Fr,
) -> bool {
    // Audit hardening: fail closed if either the pubkey or R8 is outside the
    // BabyJubjub prime-order subgroup. Without these guards, cofactor variants
    // of an R8 component would produce eight distinct signature encodings that
    // all verify cleanly under the bare EdDSA equation — breaking
    // de-duplication and letting an attacker forge "different" signatures over
    // the same payload. A pubkey in a cofactor coset can produce equivalent
    // attacks on the verifier side. The bare `babyjubjub_permissive::verify`
    // deliberately omits these checks (matching the reference semantics); they
    // are imposed here, in the Rust layer, because Olympus's unified circuit
    // has no in-circuit verifier (audit C-1).
    if validate_pubkey_subgroup(pubkey).is_err() {
        return false;
    }
    if validate_signature_r8(signature).is_err() {
        return false;
    }
    // Reject non-canonical S (malleability): see `validate_signature_s`.
    if validate_signature_s(signature).is_err() {
        return false;
    }

    let pubkey = PublicKey(bjj_affine(pubkey.x, pubkey.y));
    let sig = PermSignature {
        r8: bjj_affine(signature.r8x, signature.r8y),
        s: ark_scalar_to_perm(&signature.s),
    };
    bjj::verify(&pubkey, &sig, message)
}

// ── Subgroup / malleability guards ────────────────────────────────────────────

/// BabyJubjub prime subgroup order l.
/// The full curve has order 8·l; a point is in the prime-order subgroup
/// iff l·P = O (the identity element).
///
/// Single source of truth for the modulus used to reduce signing-message
/// digests into the subgroup scalar field (the "reduce mod l" recipe shared by
/// SBT-open signing and the ADR-0031 transition attestation). Importers MUST use
/// this constant rather than re-typing the literal, so the two reductions can
/// never silently drift apart.
pub const BABYJ_SUBGROUP_ORDER: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

/// Return `true` if `point` is the BabyJubjub identity element `(0, 1)`.
///
/// For a twisted-Edwards curve the identity is always `(0, 1)` — the neutral
/// element of the group law, distinct from the point at infinity used on
/// short-Weierstrass curves.
pub(crate) fn bjj_is_identity(point: &BabyJubjubAffine) -> bool {
    is_identity(point)
}

/// Return the BabyJubjub prime subgroup order as a cached `&'static BigInt`.
///
/// Parsing `BABYJ_SUBGROUP_ORDER` is not free; caching it with `OnceLock`
/// means the scalar-bound path pays only a pointer dereference on subsequent
/// calls (finding 6).
pub(crate) fn bjj_subgroup_order() -> &'static BigInt {
    static ORDER: std::sync::OnceLock<BigInt> = std::sync::OnceLock::new();
    ORDER.get_or_init(|| BABYJ_SUBGROUP_ORDER.parse().expect("static constant"))
}

/// Return `true` if `point` lies in the prime-order subgroup of BabyJubjub.
///
/// Multiplies by the subgroup order `l` and checks that the result is the
/// identity `(0, 1)`.  Low-order cofactor points and any combination that
/// includes a non-trivial cofactor component produce a non-identity result.
///
/// This is the authoritative host-side check, mirroring the invariant
/// `circomlib`'s `EdDSAPoseidonVerifier` enforces via the cofactor
/// multiplication of `R8 = 8·R`. Olympus's unified circuit does not run
/// that verifier in-circuit (audit C-1), so this check IS the only line
/// of defense — any point arriving from external sources (Protobuf, IPC,
/// federation gossip) must pass here before downstream use.
pub(crate) fn bjj_in_prime_subgroup(point: &BabyJubjubAffine) -> bool {
    is_in_prime_subgroup(point)
}

/// Build a Baby Jubjub affine point from arkworks `Fr` coordinates without
/// an on-curve assertion. Callers that handle untrusted input pair this
/// with [`bjj_is_on_curve`] + [`bjj_in_prime_subgroup`] before use.
pub(crate) fn bjj_affine(x: Fr, y: Fr) -> BabyJubjubAffine {
    BabyJubjubAffine::new_unchecked(x, y)
}

/// Return `true` iff `point` satisfies the circomlib Baby Jubjub curve
/// equation. Used to reject off-curve injected points before the subgroup
/// multiplication (which would otherwise operate on a meaningless point).
pub(crate) fn bjj_is_on_curve(point: &BabyJubjubAffine) -> bool {
    is_on_curve(point)
}

/// Validate that a BabyJubjub public key is in the prime-order subgroup.
///
/// Pubkeys produced by [`BabyJubJubPubKey::from_private`] are always safe —
/// they're derived as `priv·B8` from the cofactor-cleared generator. The
/// risk is with externally-supplied pubkeys (federation peer registration,
/// imported credentials, IPC) where a malicious operator may have
/// substituted a cofactor-coset or off-curve point that produces wrong
/// verifier behaviour.
///
/// Defence-in-depth companion to [`validate_signature_r8`]: even if R8 is
/// well-formed, a mis-subgroup pubkey can interact pathologically with the
/// verifier's scalar multiplication.
pub fn validate_pubkey_subgroup(pk: &BabyJubJubPubKey) -> Result<(), BabyJubJubError> {
    let pk_point = bjj_affine(pk.x, pk.y);
    // The identity (0, 1) trivially passes the l-multiplication check
    // (l·O = O) but is not a real pubkey — reject explicitly.
    if bjj_is_identity(&pk_point) {
        return Err(BabyJubJubError::SubgroupCheckFailed);
    }
    if !bjj_is_on_curve(&pk_point) || !bjj_in_prime_subgroup(&pk_point) {
        return Err(BabyJubJubError::SubgroupCheckFailed);
    }
    Ok(())
}

/// Reject an EdDSA `S` scalar that is not already reduced modulo the
/// BabyJubjub prime-subgroup order `l`.
///
/// Audit (EdDSA malleability): the base point `B8` has order `l`, so
/// `S·B8 == (S + l)·B8`. Since the BN254 scalar field modulus `r ≈ 8·l`,
/// up to eight distinct in-field values `S, S+l, S+2l, …` all verify against
/// the same `(R8, A, m)`. Validating R8 in the prime-order subgroup is not
/// enough on its own — without this `S < l` bound an attacker can mint
/// multiple valid encodings of one signature, defeating de-duplication. The
/// `S < l` bound is what the off-circuit verifier (and the would-be
/// in-circuit `EdDSAPoseidonVerifier` if it ever lands) expects.
pub fn validate_signature_s(sig: &BabyJubJubSignature) -> Result<(), BabyJubJubError> {
    // `ark_fr_to_bigint` yields a non-negative BigInt in `[0, r)`.
    if ark_fr_to_bigint(&sig.s) >= *bjj_subgroup_order() {
        return Err(BabyJubJubError::SubgroupCheckFailed);
    }
    Ok(())
}

/// Validate that the `R8` component of an EdDSA signature is in the
/// prime-order subgroup of BabyJubjub.
///
/// Call this whenever a [`BabyJubJubSignature`] arrives from an external
/// source (Protobuf deserialization, JSON-RPC, IPC bridge) before passing it
/// to the circuit witness. Signatures produced by [`sign`] in this module
/// are always safe — the signer multiplies R by 8 internally, which
/// guarantees prime-subgroup membership. The risk is with
/// externally-supplied signatures where a malicious node may have
/// substituted a cofactor-variant R8 to produce eight distinct payloads that
/// all verify cleanly.
pub fn validate_signature_r8(sig: &BabyJubJubSignature) -> Result<(), BabyJubJubError> {
    let r8_point = bjj_affine(sig.r8x, sig.r8y);
    // Reject the identity (0, 1) explicitly: l·O = O, so bjj_in_prime_subgroup
    // returns true for it, but a degenerate R8 = O means R = O and the circuit
    // rejects the signature anyway.  Block it at the host layer too.
    if bjj_is_identity(&r8_point) {
        return Err(BabyJubJubError::SubgroupCheckFailed);
    }
    if !bjj_is_on_curve(&r8_point) || !bjj_in_prime_subgroup(&r8_point) {
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
pub(crate) fn ark_fr_to_bigint(f: &Fr) -> BigInt {
    let bytes_be = f.into_bigint().to_bytes_be();
    BigInt::from_bytes_be(Sign::Plus, &bytes_be)
}

/// `BigInt` → arkworks `Fr`, reduced mod r.
pub(crate) fn bigint_to_ark(n: &BigInt) -> Fr {
    let (_, bytes_le) = n.to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes_le)
}

/// BabyJubjub prime-subgroup scalar (`babyjubjub_permissive::Fr`, mod `l`)
/// → arkworks `ark_bn254::Fr` (mod `r ≈ 8·l`). Exact for canonical `s < l`.
pub(crate) fn perm_scalar_to_ark(s: &bjj::Fr) -> Fr {
    Fr::from_le_bytes_mod_order(&s.into_bigint().to_bytes_le())
}

/// arkworks `ark_bn254::Fr` → BabyJubjub prime-subgroup scalar
/// (`babyjubjub_permissive::Fr`, mod `l`). Lossless for canonical `s < l`;
/// non-canonical `s ≥ l` inputs are caught upstream by
/// [`validate_signature_s`] before this is reached.
pub(crate) fn ark_scalar_to_perm(s: &Fr) -> bjj::Fr {
    bjj::Fr::from_le_bytes_mod_order(&s.into_bigint().to_bytes_le())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn sign_then_verify_roundtrips() {
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

        // The authoritative check in Olympus — verification happens
        // off-circuit through `verify_signature`, not via an in-circuit
        // `EdDSAPoseidonVerifier` (audit C-1).
        assert!(
            verify_signature(&pk, &sig, message),
            "verify_signature must accept a freshly produced signature"
        );

        // Negative control: a different message must not verify.
        assert!(
            !verify_signature(&pk, &sig, Fr::from(43u64)),
            "verify_signature must reject a signature over the wrong message"
        );
    }

    #[test]
    fn scalar_bridge_is_lossless_for_canonical_s() {
        // Canonical signature scalars live in [0, l). Round-tripping an
        // in-range value through the perm↔ark bridge must be lossless.
        let mut rng = rand::thread_rng();
        for _ in 0..32 {
            // Draw a uniform subgroup scalar < l, encode as ark Fr, bridge back.
            let s_perm = bjj::Fr::rand(&mut rng);
            let s_ark = perm_scalar_to_ark(&s_perm);
            let back = ark_scalar_to_perm(&s_ark);
            assert_eq!(s_perm, back, "subgroup scalar round-trip must be lossless");
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
        use ark_ff::{One, Zero};
        // The identity element (0, 1) should be correctly detected.
        let identity = bjj_affine(Fr::zero(), Fr::one());
        assert!(bjj_is_identity(&identity));
    }

    #[test]
    fn verify_signature_rejects_r8_identity() {
        // verify_signature must fail closed if R8 is the identity.
        use ark_ff::Zero;
        let priv_key = [0x42_u8; 32];
        let pk = BabyJubJubPubKey::from_private(&priv_key).expect("pubkey");
        let degenerate_sig = BabyJubJubSignature {
            r8x: Fr::zero(),
            r8y: Fr::from(1u64),
            s: Fr::zero(),
        };
        let msg = Fr::from(7u64);
        assert!(
            !verify_signature(&pk, &degenerate_sig, msg),
            "verify_signature must reject identity-R8 signatures"
        );
    }

    #[test]
    fn verify_signature_rejects_pubkey_identity() {
        // Symmetric guard: a pubkey of (0, 1) is not a real key. Even with
        // an otherwise well-formed signature, verify_signature must reject.
        use ark_ff::Zero;
        let bad_pk = BabyJubJubPubKey {
            x: Fr::zero(),
            y: Fr::from(1u64),
        };
        let priv_key = [0x42_u8; 32];
        let msg = Fr::from(7u64);
        let real_sig = sign(&priv_key, msg).expect("sign");
        assert!(
            !verify_signature(&bad_pk, &real_sig, msg),
            "verify_signature must reject identity pubkeys"
        );
    }

    #[test]
    fn validate_pubkey_subgroup_accepts_real_pubkey() {
        // Pubkeys derived from our signer must always be in-subgroup.
        let priv_key = [0x55_u8; 32];
        let pk = BabyJubJubPubKey::from_private(&priv_key).expect("pubkey");
        validate_pubkey_subgroup(&pk)
            .expect("Pubkey derived from our signer must pass subgroup check");
    }

    #[test]
    fn validate_pubkey_subgroup_rejects_identity() {
        use ark_ff::Zero;
        let bad_pk = BabyJubJubPubKey {
            x: Fr::zero(),
            y: Fr::from(1u64),
        };
        assert!(
            validate_pubkey_subgroup(&bad_pk).is_err(),
            "identity pubkey must be rejected"
        );
    }

    #[test]
    fn validate_signature_r8_rejects_identity_r8() {
        // Regression: l·O = O, so the subgroup check alone passes for the
        // identity. validate_signature_r8 must reject it explicitly.
        use ark_ff::Zero;
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

    #[test]
    fn verify_signature_rejects_non_canonical_s() {
        // S and S+l both satisfy S·B8 == (S+l)·B8 because B8 has order l, so
        // the bare EdDSA equation accepts both. verify_signature must reject
        // the malleated S+l form (EdDSA malleability hardening, audit).
        let priv_key = [0x42_u8; 32];
        let pk = BabyJubJubPubKey::from_private(&priv_key).expect("pubkey");
        let msg = Fr::from(7u64);
        let sig = sign(&priv_key, msg).expect("sign");
        assert!(
            verify_signature(&pk, &sig, msg),
            "canonical signature must verify"
        );

        // Add l to s. The signer emits s < l and r ≈ 8·l, so s+l is still < r
        // (no modular wrap) yet violates the canonical s < l bound.
        let l: BigUint = BABYJ_SUBGROUP_ORDER.parse().unwrap();
        let s_big = BigUint::from_bytes_be(&sig.s.into_bigint().to_bytes_be());
        let mal = s_big + l;
        let mal_s = Fr::from_le_bytes_mod_order(&mal.to_bytes_le());
        let malleated = BabyJubJubSignature {
            r8x: sig.r8x,
            r8y: sig.r8y,
            s: mal_s,
        };

        assert!(
            validate_signature_s(&malleated).is_err(),
            "S+l must be flagged as non-canonical"
        );
        assert!(
            !verify_signature(&pk, &malleated, msg),
            "malleated S+l signature must be rejected"
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
        assert_eq!(
            (dn_x, dn_y),
            (pk.x, pk.y),
            "double-negation is the identity"
        );
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
