//! Groth16 BN254 proof verification for snarkjs-style JSON artifacts.

use std::convert::TryFrom;
use std::panic::{catch_unwind, AssertUnwindSafe};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use num_bigint::BigUint;
use pyo3::prelude::*;
use serde_json::Value;

const MAX_DECIMAL_FIELD_DIGITS: usize = 80;

/// Verify a snarkjs Groth16 proof against a snarkjs verification key on BN254.
///
/// Returns `false` for invalid proofs, malformed JSON, malformed public signals,
/// or any panic raised during parsing or verification.
#[pyfunction]
pub fn verify_groth16_bn254(
    vkey_json: &str,
    proof_json: &str,
    public_signals: Vec<String>,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        verify_groth16_bn254_inner(vkey_json, proof_json, &public_signals).unwrap_or(false)
    }))
    .unwrap_or(false)
}

fn verify_groth16_bn254_inner(
    vkey_json: &str,
    proof_json: &str,
    public_signals: &[String],
) -> Option<bool> {
    let vkey_value: Value = serde_json::from_str(vkey_json).ok()?;
    let expected_public = parse_n_public(&vkey_value)?;
    // SAFETY: reject before prepare_verifying_key — mismatched signal count panics in arkworks.
    if public_signals.len() != expected_public {
        return Some(false);
    }

    let vkey = parse_verifying_key(&vkey_value)?;
    // SAFETY: snarkjs/Groth16 requires `IC` (a.k.a. `gamma_abc_g1`) to have
    // exactly `nPublic + 1` entries — one base term plus one per public
    // signal.  A crafted VK with extra IC entries would otherwise pass the
    // signal count check and cause arkworks to MSM over attacker-controlled
    // points outside the circuit's commitment.
    if vkey.gamma_abc_g1.len() != expected_public + 1 {
        return Some(false);
    }
    let proof = parse_proof(proof_json)?;
    let parsed_public_signals = parse_public_signals(public_signals)?;
    let prepared = prepare_verifying_key(&vkey);
    Groth16::<Bn254>::verify_proof(&prepared, &proof, &parsed_public_signals).ok()
}

fn parse_verifying_key(json: &Value) -> Option<VerifyingKey<Bn254>> {
    let ic_key = json.get("IC").or_else(|| json.get("vk_ic"))?;
    let gamma_abc_g1 = ic_key
        .as_array()?
        .iter()
        .map(parse_g1)
        .collect::<Option<Vec<_>>>()?;

    Some(VerifyingKey {
        alpha_g1: parse_g1(json.get("vk_alpha_1")?)?,
        beta_g2: parse_g2(json.get("vk_beta_2")?)?,
        gamma_g2: parse_g2(json.get("vk_gamma_2")?)?,
        delta_g2: parse_g2(json.get("vk_delta_2")?)?,
        gamma_abc_g1,
    })
}

fn parse_proof(proof_json: &str) -> Option<Proof<Bn254>> {
    let json: Value = serde_json::from_str(proof_json).ok()?;
    Some(Proof {
        a: parse_g1(json.get("pi_a")?)?,
        b: parse_g2(json.get("pi_b")?)?,
        c: parse_g1(json.get("pi_c")?)?,
    })
}

fn parse_n_public(json: &Value) -> Option<usize> {
    let n_public = json.get("nPublic")?.as_u64()?;
    usize::try_from(n_public).ok()
}

fn parse_public_signals(public_signals: &[String]) -> Option<Vec<Fr>> {
    public_signals
        .iter()
        .map(|signal| parse_decimal_field::<Fr>(signal))
        .collect()
}

fn parse_g1(value: &Value) -> Option<G1Affine> {
    let coords = value.as_array()?;
    if coords.len() != 3 {
        return None;
    }

    Some(G1Affine::from(G1Projective::new(
        parse_json_field::<Fq>(&coords[0])?,
        parse_json_field::<Fq>(&coords[1])?,
        parse_json_field::<Fq>(&coords[2])?,
    )))
}

fn parse_g2(value: &Value) -> Option<G2Affine> {
    let coords = value.as_array()?;
    if coords.len() != 3 {
        return None;
    }

    Some(G2Affine::from(G2Projective::new(
        parse_fq2(&coords[0])?,
        parse_fq2(&coords[1])?,
        parse_fq2(&coords[2])?,
    )))
}

fn parse_fq2(value: &Value) -> Option<Fq2> {
    let coords = value.as_array()?;
    if coords.len() != 2 {
        return None;
    }

    Some(Fq2::new(
        parse_json_field::<Fq>(&coords[0])?,
        parse_json_field::<Fq>(&coords[1])?,
    ))
}

fn parse_json_field<F: PrimeField>(value: &Value) -> Option<F> {
    parse_decimal_field(value.as_str()?)
}

fn parse_decimal_field<F: PrimeField>(value: &str) -> Option<F> {
    if value.is_empty()
        || value.len() > MAX_DECIMAL_FIELD_DIGITS
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }

    let bigint = BigUint::parse_bytes(value.as_bytes(), 10)?;
    let repr = F::BigInt::try_from(bigint).ok()?;
    F::from_bigint(repr)
}
