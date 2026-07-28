// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Baby Jubjub EdDSA-Poseidon signature verification — independent Rust mirror.
//!
//! Olympus signs several things with the BJJ authority key: ADR-0031 transition
//! attestations, checkpoint-quorum co-signatures, SBT openings. The JavaScript
//! verifier authenticates those via circomlibjs; this crate could previously
//! only re-derive the signed *digest* (see [`crate::transition`]) and had to
//! take the signature itself on trust.
//!
//! The verification equation is the iden3 convention, mirrored from
//! `babyjubjub_permissive::verify`:
//!
//! ```text
//! hm  = Poseidon5(R8.x, R8.y, A.x, A.y, msg)
//! LHS = s · B8
//! RHS = R8 + (8 · hm) · A
//! ```
//!
//! The cofactor-8 factor on the right is easy to omit and produces a verifier
//! that rejects every genuine signature, so it is pinned by the cross-language
//! vectors below rather than left to inspection.
//!
//! ## Why the subgroup guards are not optional
//!
//! Baby Jubjub has order `8·l`. Without checking that the public key and `R8`
//! lie in the prime-order subgroup, the eight cofactor variants of an `R8`
//! component all satisfy the bare equation — so one signed payload yields eight
//! distinct encodings that each verify. That breaks de-duplication and lets a
//! peer present "different" signatures over identical content. `src-tauri`
//! imposes the same guards for the same reason (audit hardening on C-1);
//! the bare reference `verify` deliberately omits them.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;

use crate::pedersen::{Curve, Point};

/// A Baby Jubjub EdDSA-Poseidon signature in the wire encoding Olympus uses
/// (canonical decimal field elements).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub r8: Point,
    pub s: BigUint,
}

/// Why a signature was refused. Distinguishing these matters: a malformed
/// encoding is an input bug, whereas a failed equation is a genuine rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EddsaError {
    /// Public key is not a valid curve point in the prime-order subgroup.
    PubkeyNotInSubgroup,
    /// `R8` is not a valid curve point in the prime-order subgroup.
    R8NotInSubgroup,
    /// `s` is not reduced mod `l` — the malleability guard.
    NonCanonicalS,
    /// Poseidon failed (cannot occur for fixed arity 5 in practice).
    Poseidon(String),
    /// Well-formed, but the verification equation does not hold.
    Rejected,
}

impl std::fmt::Display for EddsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PubkeyNotInSubgroup => {
                write!(
                    f,
                    "public key is not in the Baby Jubjub prime-order subgroup"
                )
            }
            Self::R8NotInSubgroup => {
                write!(
                    f,
                    "signature R8 is not in the Baby Jubjub prime-order subgroup"
                )
            }
            Self::NonCanonicalS => write!(f, "signature s is not reduced mod l (malleable)"),
            Self::Poseidon(error) => write!(f, "Poseidon error: {error}"),
            Self::Rejected => write!(f, "EdDSA-Poseidon verification equation does not hold"),
        }
    }
}

impl std::error::Error for EddsaError {}

fn biguint_to_fr(value: &BigUint) -> Fr {
    Fr::from_be_bytes_mod_order(&value.to_bytes_be())
}

fn fr_to_biguint(value: &Fr) -> BigUint {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be())
}

/// `Poseidon5(R8.x, R8.y, A.x, A.y, msg)` — the EdDSA challenge.
fn challenge(r8: &Point, pubkey: &Point, msg: &BigUint) -> Result<BigUint, EddsaError> {
    let mut hasher =
        Poseidon::<Fr>::new_circom(5).map_err(|error| EddsaError::Poseidon(error.to_string()))?;
    let digest = hasher
        .hash(&[
            biguint_to_fr(&r8.x),
            biguint_to_fr(&r8.y),
            biguint_to_fr(&pubkey.x),
            biguint_to_fr(&pubkey.y),
            biguint_to_fr(msg),
        ])
        .map_err(|error| EddsaError::Poseidon(error.to_string()))?;
    Ok(fr_to_biguint(&digest))
}

/// Verify a Baby Jubjub EdDSA-Poseidon signature over `msg`.
///
/// `msg` is the already-reduced signing scalar — for a transition attestation
/// that is [`crate::transition::TransitionAttestation::signed_scalar_decimal`].
pub fn verify(
    curve: &Curve,
    pubkey: &Point,
    signature: &Signature,
    msg: &BigUint,
) -> Result<(), EddsaError> {
    if !curve.on_curve(pubkey) || !curve.in_prime_subgroup(pubkey) {
        return Err(EddsaError::PubkeyNotInSubgroup);
    }
    if !curve.on_curve(&signature.r8) || !curve.in_prime_subgroup(&signature.r8) {
        return Err(EddsaError::R8NotInSubgroup);
    }
    if signature.s >= curve.l {
        return Err(EddsaError::NonCanonicalS);
    }

    let hm = challenge(&signature.r8, pubkey, msg)?;
    let lhs = curve.scalar_mul(&curve.g, &signature.s);
    // RHS = R8 + 8·(hm·A). The cofactor multiplication is applied to the point
    // rather than folded into the scalar, matching `babyjubjub_permissive`.
    let hm_a = curve.scalar_mul(pubkey, &hm);
    let cofactor_hm_a = curve.scalar_mul(&hm_a, &BigUint::from(8u32));
    let rhs = curve.point_add(&signature.r8, &cofactor_hm_a);

    if lhs == rhs {
        Ok(())
    } else {
        Err(EddsaError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen::parse_dec;

    fn point(x: &str, y: &str) -> Point {
        Point {
            x: parse_dec(x).expect("x"),
            y: parse_dec(y).expect("y"),
        }
    }

    /// Cross-language ground truth: every co-signature in the committed
    /// checkpoint-quorum vectors must verify under this implementation, using
    /// the same `expected.message` scalar the JavaScript verifier consumes.
    ///
    /// These signatures were produced by the Rust desktop signer and are
    /// already verified by circomlibjs on the JS side, so agreement here means
    /// three independent implementations concur.
    #[test]
    fn committed_quorum_cosignatures_verify() {
        let raw = std::fs::read_to_string("../test_vectors/checkpoint_quorum_vectors.json")
            .expect("read checkpoint quorum vectors");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse vectors");
        let curve = Curve::baby_jubjub();

        let cases = doc["cases"].as_array().expect("cases array");
        assert!(!cases.is_empty(), "vectors must not be empty");

        for case in cases {
            let name = case["name"].as_str().unwrap_or("<unnamed>");
            let msg = parse_dec(
                case["expected"]["message"]
                    .as_str()
                    .expect("expected message"),
            )
            .expect("parse expected message");
            let signers: Vec<Point> = case["signers"]
                .as_array()
                .expect("signers")
                .iter()
                .map(|s| {
                    point(
                        s["x"].as_str().expect("signer x"),
                        s["y"].as_str().expect("signer y"),
                    )
                })
                .collect();

            // The quorum rule counts DISTINCT pinned signers whose signature
            // authenticates over the expected message: a non-member is ignored
            // and a signer presenting twice counts once.
            let mut credited: Vec<Point> = Vec::new();
            for cosig in case["cosignatures"].as_array().expect("cosignatures") {
                let pubkey = point(
                    cosig["x"].as_str().expect("cosig x"),
                    cosig["y"].as_str().expect("cosig y"),
                );
                if !signers.contains(&pubkey) || credited.contains(&pubkey) {
                    continue;
                }
                let sig = Signature {
                    r8: point(
                        cosig["r8x"].as_str().expect("r8x"),
                        cosig["r8y"].as_str().expect("r8y"),
                    ),
                    s: parse_dec(cosig["s"].as_str().expect("s")).expect("s"),
                };
                if verify(&curve, &pubkey, &sig, &msg).is_ok() {
                    credited.push(pubkey);
                }
            }

            let expected = case["expected"]["valid_signatures"]
                .as_u64()
                .expect("valid_signatures") as usize;
            assert_eq!(
                credited.len(),
                expected,
                "case `{name}`: this verifier credited {} signature(s), vectors expect {expected}",
                credited.len()
            );
        }
    }

    /// A tampered message must not verify — otherwise the signature would not
    /// bind the payload at all.
    #[test]
    fn a_different_message_does_not_verify() {
        let raw = std::fs::read_to_string("../test_vectors/checkpoint_quorum_vectors.json")
            .expect("read vectors");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse");
        let curve = Curve::baby_jubjub();
        let case = &doc["cases"][0];
        let cosig = &case["cosignatures"][0];
        let pubkey = point(cosig["x"].as_str().unwrap(), cosig["y"].as_str().unwrap());
        let sig = Signature {
            r8: point(
                cosig["r8x"].as_str().unwrap(),
                cosig["r8y"].as_str().unwrap(),
            ),
            s: parse_dec(cosig["s"].as_str().unwrap()).unwrap(),
        };
        let wrong = parse_dec("12345").unwrap();
        assert_eq!(
            verify(&curve, &pubkey, &sig, &wrong),
            Err(EddsaError::Rejected)
        );
    }

    /// `s` must be reduced mod `l`; `s + l` would otherwise be an equally valid
    /// encoding of the same signature.
    #[test]
    fn non_canonical_s_is_refused() {
        let raw = std::fs::read_to_string("../test_vectors/checkpoint_quorum_vectors.json")
            .expect("read vectors");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse");
        let curve = Curve::baby_jubjub();
        let cosig = &doc["cases"][0]["cosignatures"][0];
        let pubkey = point(cosig["x"].as_str().unwrap(), cosig["y"].as_str().unwrap());
        let msg = parse_dec(doc["cases"][0]["expected"]["message"].as_str().unwrap()).unwrap();
        let sig = Signature {
            r8: point(
                cosig["r8x"].as_str().unwrap(),
                cosig["r8y"].as_str().unwrap(),
            ),
            s: parse_dec(cosig["s"].as_str().unwrap()).unwrap() + &curve.l,
        };
        assert_eq!(
            verify(&curve, &pubkey, &sig, &msg),
            Err(EddsaError::NonCanonicalS)
        );
    }

    /// The identity is in the subgroup but is not a legitimate `R8`; more
    /// importantly, an off-curve point must be refused before any arithmetic.
    #[test]
    fn off_curve_points_are_refused() {
        let curve = Curve::baby_jubjub();
        let bogus = point("1", "1");
        let sig = Signature {
            r8: curve.g.clone(),
            s: BigUint::from(1u32),
        };
        assert_eq!(
            verify(&curve, &bogus, &sig, &BigUint::from(7u32)),
            Err(EddsaError::PubkeyNotInSubgroup)
        );
    }
}
