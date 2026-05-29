//! Byte-for-byte parity test against `babyjubjub-rs`.
//!
//! Loads the frozen vector set in `tests/parity_vectors.json` (generated
//! once by `examples/gen_parity_vectors.rs` while `babyjubjub-rs` is still
//! a dev-dep) and asserts the new permissive impl produces bit-equal
//! outputs for every vector.
//!
//! The vectors outlive `babyjubjub-rs`: Phase 4 drops the dependency
//! entirely, but this test continues to run, now reading a JSON file that
//! describes "what the legacy impl produced for these inputs." Any future
//! drift in our sign / public / verify path immediately fails the test.
//!
//! # What's asserted per vector
//!
//! 1. `PrivateKey::from_bytes(sk).public() == (pk_x, pk_y)`
//!    — pubkey derivation parity
//! 2. `PrivateKey::from_bytes(sk).sign(msg) == (r8x, r8y, s)`
//!    — full signing-equation parity (including BLAKE-512 nonce, R8
//!    cofactor clearing, and the `<< 3` scalar adjustment circomlib
//!    uses inside the response)
//! 3. `verify(pk, sig, msg) == true`
//!    — verification accepts every legacy-format signature
//!
//! Any one of these failing means the new impl is NOT a drop-in for
//! `babyjubjub-rs` and Phase 4 must NOT proceed until fixed.

use std::path::PathBuf;

use ark_bn254::Fr as Fq;
use ark_ff::PrimeField;
use babyjubjub_permissive::{verify, PrivateKey, PublicKey, Signature};
use num_bigint::BigUint;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    sk_hex: String,
    msg_dec: String,
    pk_x_dec: String,
    pk_y_dec: String,
    r8x_dec: String,
    r8y_dec: String,
    s_dec: String,
}

fn vectors() -> Vec<Vector> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("parity_vectors.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "parity_vectors.json missing at {} ({e}). Regenerate via \
             `cargo run -p babyjubjub-permissive --example gen_parity_vectors`",
            path.display()
        )
    });
    serde_json::from_slice(&bytes).expect("parity vectors must deserialize")
}

/// Parse a decimal string into `Fq` (`ark_bn254::Fr`, the curve's base
/// field — also Olympus' message scalar type). Goes via BigUint → LE bytes
/// because arkworks' `FromStr` returned errors are awkward to surface.
fn dec_to_fq(s: &str) -> Fq {
    let big: BigUint = s.parse().expect("valid decimal");
    let bytes_le = big.to_bytes_le();
    Fq::from_le_bytes_mod_order(&bytes_le)
}

/// Parse a decimal string into the subgroup scalar field `Fr` (the prime
/// `l`). Used for the signature's `s` component.
fn dec_to_fr(s: &str) -> babyjubjub_permissive::Fr {
    let big: BigUint = s.parse().expect("valid decimal");
    let bytes_le = big.to_bytes_le();
    <babyjubjub_permissive::Fr as PrimeField>::from_le_bytes_mod_order(&bytes_le)
}

#[test]
fn pubkey_derivation_matches_babyjubjub_rs() {
    for (i, v) in vectors().into_iter().enumerate() {
        let sk_bytes = hex::decode(&v.sk_hex).expect("hex sk");
        let sk = PrivateKey::from_bytes(&sk_bytes).expect("32-byte sk");
        let (px, py) = sk.public().coords();
        let expected_px = dec_to_fq(&v.pk_x_dec);
        let expected_py = dec_to_fq(&v.pk_y_dec);
        assert_eq!(
            px, expected_px,
            "vector #{i}: pk.x diverges from babyjubjub-rs",
        );
        assert_eq!(
            py, expected_py,
            "vector #{i}: pk.y diverges from babyjubjub-rs",
        );
    }
}

#[test]
fn sign_output_matches_babyjubjub_rs_bytewise() {
    for (i, v) in vectors().into_iter().enumerate() {
        let sk_bytes = hex::decode(&v.sk_hex).expect("hex sk");
        let sk = PrivateKey::from_bytes(&sk_bytes).expect("32-byte sk");
        let msg = dec_to_fq(&v.msg_dec);
        let sig = sk.sign(msg).expect("sign");

        let expected_r8x = dec_to_fq(&v.r8x_dec);
        let expected_r8y = dec_to_fq(&v.r8y_dec);
        let expected_s = dec_to_fr(&v.s_dec);

        assert_eq!(sig.r8.x, expected_r8x, "vector #{i}: r8.x diverges");
        assert_eq!(sig.r8.y, expected_r8y, "vector #{i}: r8.y diverges");
        assert_eq!(sig.s, expected_s, "vector #{i}: s diverges");
    }
}

#[test]
fn verify_accepts_every_legacy_signature() {
    for (i, v) in vectors().into_iter().enumerate() {
        let msg = dec_to_fq(&v.msg_dec);

        // Reconstruct the (pk, sig) tuple from the vector's expected
        // values rather than from `sk.sign` so the test is sensitive to
        // verify-side bugs even if sign happens to drift in lock-step
        // with the legacy impl. We deliberately do NOT re-derive the
        // pubkey or signature from `sk` here.
        let pk = PublicKey(ark_ec::twisted_edwards::Affine::new_unchecked(
            dec_to_fq(&v.pk_x_dec),
            dec_to_fq(&v.pk_y_dec),
        ));
        let sig = Signature {
            r8: ark_ec::twisted_edwards::Affine::new_unchecked(
                dec_to_fq(&v.r8x_dec),
                dec_to_fq(&v.r8y_dec),
            ),
            s: dec_to_fr(&v.s_dec),
        };

        assert!(
            verify(&pk, &sig, msg),
            "vector #{i}: legacy signature must verify under new impl",
        );
    }
}
