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
}
