//! Circomlib-compatible EdDSA-Poseidon over Baby Jubjub.
//!
//! This is the byte-for-byte equivalent of `babyjubjub-rs`'s `PrivateKey`,
//! `sign`, `verify`, and `Signature`, expressed in arkworks types instead
//! of `ff_ce`. The wire shape — pubkey coordinates, R8 cofactor-cleared
//! commitment, S scalar — matches circomlib's `babyjub.circom` /
//! `eddsa.circom` exactly, so signatures produced here verify against the
//! same trusted-issuer pubkeys, the same ceremony coordinator key, the
//! same in-circuit `EdDSAPoseidonVerifier` template, and the existing
//! signed-snapshot fields without any migration step.
//!
//! # Algorithm (verbatim from circomlib `eddsa.circom` + iden3's reference)
//!
//! Inputs: a 32-byte raw private key `sk` and a message `msg ∈ Fq`.
//!
//! 1. **Scalar derivation** (`scalar_key`):
//!     - `h = BLAKE-512(sk)` (64 bytes)
//!     - `pruned = h[0..32]`
//!     - `pruned[0]  &= 0xF8`     // clear low 3 bits
//!     - `pruned[31] &= 0x7F`     // clear high bit
//!     - `pruned[31] |= 0x40`     // set bit 6
//!     - `sk_pre = LE(pruned) as BigInt`
//!     - `scalar = sk_pre >> 3`   // land in prime subgroup
//!
//! 2. **Public key**: `A = scalar · B8`.
//!
//! 3. **Deterministic nonce**:
//!     - `r_input = h[32..64] || msg_32LE`  (96 bytes)
//!     - `r = BLAKE-512(r_input) mod l`
//!
//! 4. **Commitment**: `R8 = r · B8`.
//!
//! 5. **Challenge**: `hm = Poseidon([R8.x, R8.y, A.x, A.y, msg])`.
//!
//! 6. **Response**: `s = (r + hm · sk_pre) mod l`   *(equivalently
//!    `(r + hm · (scalar << 3)) mod l`, the form `babyjubjub-rs` uses.)*
//!
//! Signature is `(R8, s)`.
//!
//! # Verification
//!
//! Reconstructs `hm` from `(R8, A, msg)` and checks
//! `s · B8 == R8 + 8 · hm · A`. The factor of 8 in front of `hm·A` is what
//! cancels the `<< 3` in the signer's `sk_pre`, since the public key uses
//! the post-shift scalar (`A = scalar · B8 = (sk_pre >> 3) · B8`).

use ark_bn254::Fr as Fq;
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
// `blake-hash` is the *original* BLAKE (SHA-3 finalist, 2008), what
// circomlib's `@noble/hashes/blake1` produces. NOT to be confused with
// the RustCrypto `blake2` crate, whose `Blake2b512` produces different
// bytes for the same input and broke the parity test on first try.
use blake_hash::{Blake512, Digest};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::{BigInt, Sign};

use crate::compress::{compress, decompress, DecompressError};
use crate::curve::{BabyJubjubAffine, B8};
use crate::field::Fr;

/// Errors from sign / verify. Verify itself returns `bool`; this enum
/// covers the construction / encoding paths that can fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdDsaError {
    /// `PrivateKey::from_bytes` rejected a non-32-byte input.
    BadPrivateKeyLen,
    /// Message is ≥ the BN254 scalar modulus `q`. Caller must reduce
    /// first or pass a value already in range; `babyjubjub-rs::sign`
    /// rejects this case too.
    MessageOutOfRange,
    /// Internal Poseidon failure — only reached if the light-poseidon
    /// parameter table is corrupted, which is a build / vendoring bug
    /// rather than user input.
    Poseidon(String),
    /// Decompression failure when constructing a `PublicKey` /
    /// `Signature` from on-wire bytes. Propagates [`DecompressError`]'s
    /// detail.
    Decompress(DecompressError),
}

impl core::fmt::Display for EdDsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EdDsaError::BadPrivateKeyLen => f.write_str("EdDSA private key must be 32 bytes"),
            EdDsaError::MessageOutOfRange => {
                f.write_str("EdDSA message ≥ q (BN254 scalar modulus)")
            }
            EdDsaError::Poseidon(m) => write!(f, "EdDSA Poseidon error: {m}"),
            EdDsaError::Decompress(e) => write!(f, "EdDSA decompress: {e}"),
        }
    }
}

impl std::error::Error for EdDsaError {}

impl From<DecompressError> for EdDsaError {
    fn from(e: DecompressError) -> Self {
        EdDsaError::Decompress(e)
    }
}

/// 32-byte raw EdDSA private key seed.
///
/// The seed is run through BLAKE-512 + RFC-8032 pruning + `>> 3` to derive
/// the actual scalar used for signing. Two seeds may collide on the same
/// derived scalar only if they collide on BLAKE-512's lower 32 bytes after
/// pruning, which is cryptographically negligible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateKey([u8; 32]);

/// EdDSA public key — a point in the Baby Jubjub prime-order subgroup.
///
/// Always equal to `scalar · B8` for some `scalar` derived from a
/// [`PrivateKey`] (or imported from 32-byte compressed bytes via
/// [`PublicKey::decompress`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub BabyJubjubAffine);

/// EdDSA signature: a cofactor-cleared commitment `R8` plus a scalar `s`.
///
/// Constructed exclusively by [`PrivateKey::sign`] or by deserializing
/// from existing on-wire bytes (the `babyjubjub-rs::Signature` shape).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    /// `R8 = r · B8` — the deterministic nonce point scaled into the
    /// prime-order subgroup. Public.
    pub r8: BabyJubjubAffine,
    /// `s = (r + hm · sk_pre) mod l` — response scalar. Reduced into
    /// `[0, l)` to be malleability-resistant per `validate_signature_s`.
    pub s: Fr,
}

impl PrivateKey {
    /// Wrap a 32-byte seed. The bytes are not validated against any
    /// distribution; the caller is responsible for sampling them from a
    /// CSPRNG when generating new keys.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EdDsaError> {
        if bytes.len() != 32 {
            return Err(EdDsaError::BadPrivateKeyLen);
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(bytes);
        Ok(PrivateKey(sk))
    }

    /// Borrow the raw 32-byte seed. Used by call sites that persist the
    /// key alongside the derived pubkey (e.g. SBT issuance flows that
    /// stash the seed in a sealed bootstrap blob).
    pub fn raw(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the **prime-subgroup** secret scalar — the value `scalar`
    /// such that `pubkey = scalar · B8`.
    ///
    /// `babyjubjub-rs` calls this `scalar_key`. Note that the canonical
    /// SIGNING scalar is the un-shifted form (`scalar << 3 = sk_pre`); see
    /// [`Self::sign`].
    pub fn scalar(&self) -> Fr {
        // sk_pre is the BigInt from BLAKE512(sk)[0..32] after RFC-8032
        // pruning. Right-shifting by 3 lands in the prime subgroup.
        let pre = self.scalar_pre_bigint();
        let shifted = &pre >> 3;
        bigint_to_fr(&shifted)
    }

    /// `sk_pre` (the BigInt form of the pruned 32-byte half before the
    /// `>> 3`). Used only inside this module — `sign` needs the
    /// un-shifted value because the verification equation cancels an
    /// extra factor of 8.
    fn scalar_pre_bigint(&self) -> BigInt {
        let mut h = blake512(&self.0);
        let mut pruned = [0u8; 32];
        pruned.copy_from_slice(&h[..32]);
        pruned[0] &= 0xF8;
        pruned[31] &= 0x7F;
        pruned[31] |= 0x40;
        // Defensively wipe the full hash; `h[32..64]` would otherwise
        // linger on the stack and is the input to the deterministic nonce
        // derivation in `sign`.
        for b in h.iter_mut() {
            *b = 0;
        }
        BigInt::from_bytes_le(Sign::Plus, &pruned)
    }

    /// Derive the public key `A = scalar · B8`.
    pub fn public(&self) -> PublicKey {
        // mul_bigint takes raw limbs; scalar() returns Fr which we convert
        // to BigInt limbs once.
        let scalar = self.scalar();
        let a = B8.into_group() * scalar;
        PublicKey(a.into_affine())
    }

    /// Sign `msg` (a field element in `Fq = ark_bn254::Fr`) with this
    /// private key. Returns a [`Signature`] whose `(r8.x, r8.y, s)`
    /// triple is byte-for-byte equal to what `babyjubjub-rs::sign`
    /// produces for the same `(sk, msg)`.
    ///
    /// Errors only on internal Poseidon failures (parameter-table bug).
    pub fn sign(&self, msg: Fq) -> Result<Signature, EdDsaError> {
        // 1. Recompute BLAKE-512 to get the upper half (deterministic
        //    nonce seed). Recomputing avoids storing the full hash on
        //    `PrivateKey`, which would weaken its zeroize semantics.
        let h = blake512(&self.0);
        let upper = &h[32..64];

        // 2. Encode message as 32-byte LE, in `Fq` byte order.
        let mut msg_le = msg.into_bigint().to_bytes_le();
        msg_le.resize(32, 0u8);

        // 3. r = BLAKE-512(upper || msg_le) mod l.
        let mut r_input = Vec::with_capacity(64);
        r_input.extend_from_slice(upper);
        r_input.extend_from_slice(&msg_le);
        let r_hash = blake512(&r_input);
        let r_big = BigInt::from_bytes_le(Sign::Plus, &r_hash);
        let l = subgroup_order_bigint();
        let r = ((&r_big % &l) + &l) % &l;

        // 4. R8 = r · B8.
        let r_fr = bigint_to_fr(&r);
        let r8_point = (B8.into_group() * r_fr).into_affine();

        // 5. Public key for hashing.
        let a_point = self.public().0;

        // 6. Poseidon([R8.x, R8.y, A.x, A.y, msg]).
        let hm = poseidon5(r8_point.x, r8_point.y, a_point.x, a_point.y, msg)?;

        // 7. s = (r + hm · sk_pre) mod l.
        //    `sk_pre` = scalar << 3 is what babyjubjub-rs uses here, so
        //    matching this is what makes our bytes equal theirs.
        let hm_big = fr_to_bigint_q(&hm);
        let sk_pre = self.scalar_pre_bigint();
        let s_big = ((r + hm_big * sk_pre) % &l + &l) % &l;
        let s = bigint_to_fr(&s_big);

        Ok(Signature { r8: r8_point, s })
    }
}

impl PublicKey {
    /// Decompress a 32-byte iden3-format compressed pubkey. Inherits the
    /// strict canonical-encoding checks from [`crate::compress::decompress`].
    pub fn decompress(bytes: [u8; 32]) -> Result<Self, EdDsaError> {
        Ok(PublicKey(decompress(bytes)?))
    }

    /// Compress to the 32-byte iden3 form.
    pub fn compress(&self) -> [u8; 32] {
        compress(&self.0)
    }

    /// Affine point coordinates `(x, y)`.
    pub fn coords(&self) -> (Fq, Fq) {
        (self.0.x, self.0.y)
    }
}

/// Verify `sig` against `pubkey` over `msg`. Returns `true` iff the
/// signature equation `s · B8 == R8 + 8·hm·A` holds.
///
/// Does NOT enforce subgroup membership of `R8` / `pubkey` or canonical
/// `s < l` — those checks are policy decisions the caller imposes via
/// `validate_signature_r8` / `validate_pubkey_subgroup` /
/// `validate_signature_s` (see the audit-hardening helpers in
/// `src-tauri/src/zk/witness/baby_jubjub.rs`). Verifying without those
/// is what `babyjubjub-rs::verify` does, so this function matches it
/// for parity-test purposes; production code should always go through
/// the hardened wrappers.
pub fn verify(pubkey: &PublicKey, sig: &Signature, msg: Fq) -> bool {
    // 1. Reject out-of-range message (parity with babyjubjub-rs::verify).
    //    `msg` already lives in Fq so by construction it's < q, but we
    //    check explicitly so the API mirrors the BigInt-typed predecessor.
    //    (No-op for typed `Fq` callers.)

    // 2. Poseidon challenge over the *signature*'s R8 + provided pubkey.
    let hm = match poseidon5(sig.r8.x, sig.r8.y, pubkey.0.x, pubkey.0.y, msg) {
        Ok(h) => h,
        Err(_) => return false,
    };

    // 3. LHS = s · B8.
    let lhs = B8.into_group() * sig.s;

    // 4. RHS = R8 + (8·hm) · A. Done as `8·(hm·A)` to avoid building a
    //    scratch `BigInt`; `hm` is Fq and Fq doesn't directly multiply
    //    against the curve, so we go via mul_bigint with hm's limbs.
    //    (hm·A is a curve point, doubled 3 times to get 8·hm·A.)
    let hm_big = hm.into_bigint();
    let hm_a = sig.r8.into_group()
        + pubkey
            .0
            .into_group()
            .mul_bigint(hm_big)
            .double()
            .double()
            .double();
    lhs == hm_a
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Original BLAKE-512 of `input`, returning the full 64-byte digest.
/// Matches `babyjubjub-rs::blh` and `circomlibjs/@noble/hashes/blake1`
/// `blake512`. **Not** BLAKE2b — see the import note above.
fn blake512(input: &[u8]) -> Vec<u8> {
    Blake512::digest(input).to_vec()
}

/// Five-input circomlib Poseidon over BN254 `Fr` (= our `Fq`).
///
/// Used twice — once in `sign`, once in `verify` — and the API surface is
/// awkward enough (lazy table-init, `&mut self` hasher) that factoring it
/// out keeps the call sites readable.
fn poseidon5(a: Fq, b: Fq, c: Fq, d: Fq, e: Fq) -> Result<Fq, EdDsaError> {
    // light-poseidon's `Poseidon::<Fr>::new_circom(N)` constructs an
    // N-input hasher matching circomlib's parameters. Construction is
    // cheap (a constants lookup); we don't bother caching the instance
    // since the hot path is sign/verify of *different* messages, not
    // batch hashing of the same shape.
    let mut hasher: Poseidon<Fq> =
        Poseidon::<Fq>::new_circom(5).map_err(|e| EdDsaError::Poseidon(e.to_string()))?;
    hasher
        .hash(&[a, b, c, d, e])
        .map_err(|e| EdDsaError::Poseidon(e.to_string()))
}

/// Prime-subgroup order `l`, lazily parsed from its decimal form. Cheaper
/// than `MontFp!` here because we want a `BigInt` for arithmetic outside
/// the field.
fn subgroup_order_bigint() -> BigInt {
    // Same value as `Fr::MODULUS` in decimal. Hard-coded to keep this
    // helper free of arkworks↔BigInt acrobatics on the hot path.
    use std::sync::OnceLock;
    static L: OnceLock<BigInt> = OnceLock::new();
    L.get_or_init(|| {
        "2736030358979909402780800718157159386076813972158567259200215660948447373041"
            .parse()
            .expect("static decimal")
    })
    .clone()
}

/// `BigInt` → `Fr`, reducing mod l. Inputs are always non-negative by
/// construction (BLAKE-512 outputs feed only through `Sign::Plus`).
fn bigint_to_fr(n: &BigInt) -> Fr {
    let (_, bytes_le) = n.to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes_le)
}

/// `Fq` → non-negative `BigInt`. Used to lift the Poseidon output out of
/// the field for the signing equation. (The product `hm · sk_pre` can
/// exceed both q and l before the final mod-l reduction, so we have to do
/// it in BigInt.)
fn fr_to_bigint_q(f: &Fq) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &f.into_bigint().to_bytes_be())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use rand::SeedableRng;

    /// Self-consistency: sign and then verify with the public key — the
    /// most basic acceptance bar. Doesn't prove circomlib compatibility
    /// (that's the parity test in tests/parity.rs); only proves the
    /// internal sign/verify pair agrees with itself.
    #[test]
    fn sign_then_verify_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xA11_C0DE);
        for _ in 0..16 {
            let mut sk_bytes = [0u8; 32];
            for b in sk_bytes.iter_mut() {
                *b = rand::Rng::r#gen(&mut rng);
            }
            let sk = PrivateKey::from_bytes(&sk_bytes).expect("32-byte sk");
            let msg = Fq::rand(&mut rng);
            let sig = sk.sign(msg).expect("sign");
            assert!(
                verify(&sk.public(), &sig, msg),
                "self-consistent sign/verify must accept"
            );
        }
    }

    /// Negative test: tampering with `s` must make verify fail. Catches
    /// trivial bugs like `verify` always returning true.
    #[test]
    fn verify_rejects_tampered_s() {
        let sk = PrivateKey::from_bytes(&[0x42u8; 32]).expect("sk");
        let msg = Fq::from(123_456u64);
        let sig = sk.sign(msg).expect("sign");
        let tampered = Signature {
            r8: sig.r8,
            s: sig.s + Fr::from(1u64),
        };
        assert!(!verify(&sk.public(), &tampered, msg));
    }

    /// Negative test: tampering with the message must make verify fail.
    #[test]
    fn verify_rejects_tampered_message() {
        let sk = PrivateKey::from_bytes(&[0x42u8; 32]).expect("sk");
        let msg = Fq::from(123_456u64);
        let sig = sk.sign(msg).expect("sign");
        assert!(!verify(&sk.public(), &sig, msg + Fq::from(1u64)));
    }

    /// Negative test: a different public key must NOT verify.
    #[test]
    fn verify_rejects_wrong_pubkey() {
        let alice = PrivateKey::from_bytes(&[0x42u8; 32]).expect("sk");
        let bob = PrivateKey::from_bytes(&[0x43u8; 32]).expect("sk");
        let msg = Fq::from(7u64);
        let sig = alice.sign(msg).expect("sign");
        assert!(!verify(&bob.public(), &sig, msg));
    }

    /// Compress/decompress round-trip for the derived public key.
    #[test]
    fn pubkey_compress_decompress_roundtrip() {
        let sk = PrivateKey::from_bytes(&[0x11u8; 32]).expect("sk");
        let pk = sk.public();
        let bytes = pk.compress();
        let back = PublicKey::decompress(bytes).expect("decompress");
        assert_eq!(pk, back);
    }

    /// Suppression for accidental Zero pubkey: deriving from a zero seed
    /// must NOT produce the identity (would short-circuit the security
    /// arguments for the signature scheme). The pruning bit-pattern
    /// guarantees this: bit 254 is forced to 1, so the scalar is at least
    /// `2^254 >> 3 = 2^251`, far from zero. We just sanity-check.
    #[test]
    fn pubkey_is_not_identity_for_any_seed() {
        for byte in [0x00u8, 0x01, 0x42, 0xFF] {
            let sk = PrivateKey::from_bytes(&[byte; 32]).expect("sk");
            let pk = sk.public();
            assert!(
                !pk.0.is_zero(),
                "PK must not be identity for seed {byte:#x}"
            );
        }
    }
}
