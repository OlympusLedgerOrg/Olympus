//! Point-arithmetic parity vs `babyjubjub-rs`: `add` and arbitrary-point
//! `mul_scalar`.
//!
//! The EdDSA parity (`parity.rs`) only exercises scalar-mul of the
//! generator `B8`. Pedersen `commit` computes `m·G + r·H` — scalar-mul of
//! two NON-generator points (`G`, `H`) followed by an addition — so those
//! ops need their own parity coverage before `pedersen.rs` is swapped onto
//! this crate.
//!
//! Fixture: `tests/point_vectors.json`, emitted by
//! `cargo run -p babyjubjub-permissive --example gen_parity_vectors`.
//! Each entry carries operand points P = a·B8, Q = b·B8 (as coords) plus
//! the babyjubjub-rs results for `k·P` and `P+Q`. Survives Phase 4 (the
//! generator is deleted with babyjubjub-rs; the JSON stays).

use std::path::PathBuf;

use ark_bn254::Fr as Fq;
use ark_ff::{BigInteger, PrimeField};
use babyjubjub_permissive::{add, mul_scalar_bigint, BabyJubjubAffine};
use num_bigint::{BigInt, BigUint};
use serde::Deserialize;

#[derive(Deserialize)]
struct PointVector {
    k_dec: String,
    px_dec: String,
    py_dec: String,
    qx_dec: String,
    qy_dec: String,
    kp_x_dec: String,
    kp_y_dec: String,
    sum_x_dec: String,
    sum_y_dec: String,
}

fn vectors() -> Vec<PointVector> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("point_vectors.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "point_vectors.json missing at {} ({e}). Regenerate via \
             `cargo run -p babyjubjub-permissive --example gen_parity_vectors`",
            path.display()
        )
    });
    serde_json::from_slice(&bytes).expect("point vectors must deserialize")
}

/// Parse a decimal coordinate into `Fq`, rejecting values `>= q` rather
/// than silently reducing — mirrors `compress.rs::decompress`'s strict
/// canonical decode so a tampered fixture fails loudly (CodeRabbit review
/// on PR #1103).
fn dec_to_fq(s: &str) -> Fq {
    let big: BigUint = s.parse().expect("valid decimal");
    let modulus = BigUint::from_bytes_le(&<Fq as PrimeField>::MODULUS.to_bytes_le());
    assert!(
        big < modulus,
        "fixture decimal {s} >= Fq modulus — non-canonical vector"
    );
    Fq::from_le_bytes_mod_order(&big.to_bytes_le())
}

fn point(x_dec: &str, y_dec: &str) -> BabyJubjubAffine {
    BabyJubjubAffine::new_unchecked(dec_to_fq(x_dec), dec_to_fq(y_dec))
}

#[test]
fn arbitrary_point_scalar_mul_matches_babyjubjub_rs() {
    for (i, v) in vectors().into_iter().enumerate() {
        let p = point(&v.px_dec, &v.py_dec);
        let k: BigInt = v.k_dec.parse().expect("k decimal");
        let got = mul_scalar_bigint(&p, &k);
        let want = point(&v.kp_x_dec, &v.kp_y_dec);
        assert_eq!(got, want, "vector #{i}: k·P diverges from babyjubjub-rs");
    }
}

#[test]
fn point_addition_matches_babyjubjub_rs() {
    for (i, v) in vectors().into_iter().enumerate() {
        let p = point(&v.px_dec, &v.py_dec);
        let q = point(&v.qx_dec, &v.qy_dec);
        let got = add(&p, &q);
        let want = point(&v.sum_x_dec, &v.sum_y_dec);
        assert_eq!(got, want, "vector #{i}: P+Q diverges from babyjubjub-rs");
    }
}
