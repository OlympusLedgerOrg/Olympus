//! Independent Groth16 verifier — red-team C1 / court-evidence.md §2.
//!
//! Parses snarkjs verification-key + proof JSON into `ark-groth16` types and
//! runs the Groth16 pairing check. Deliberately decoupled from the desktop
//! `src-tauri` crate so a court / opposing counsel can build and run this
//! binary against any snarkjs-format `proof.json` + `public.json` + the
//! published `*_vkey.json` without trusting Olympus's own runtime.
//!
//! snarkjs encoding:
//!   * G1 point: `["x","y","1"]`  (decimal strings, projective z=1)
//!   * G2 point: `[["x_c0","x_c1"],["y_c0","y_c1"],["1","0"]]`
//!   * Public signals: JSON array of decimal strings.
//!
//! Curve points are validated for both `is_on_curve` and prime-order subgroup
//! membership; field elements are rejected if their decimal representation is
//! `>=` the BN254 modulus (silent reduction would let an over-large signal
//! verify under the SNARK while differing from the value the client claims).

use std::path::Path;
use std::str::FromStr;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;
use num_bigint::BigUint;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("field element parse error: {0}")]
    Field(String),
    #[error("curve point not on curve")]
    PointNotOnCurve,
    #[error("curve point not in prime-order subgroup")]
    PointNotInSubgroup,
    #[error("malformed point: {0}")]
    Malformed(String),
    #[error("groth16 verify failed (pairing check rejected)")]
    Rejected,
    #[error("groth16 internal error: {0}")]
    Internal(String),
}

// ── snarkjs raw JSON shapes ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RawVkey {
    pub protocol: String,
    pub curve: String,
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
}

#[derive(Deserialize)]
pub struct RawProof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
}

// ── field / point parsing ─────────────────────────────────────────────────────

fn parse_fq(s: &str) -> Result<Fq, VerifyError> {
    let n = BigUint::from_str(s)
        .map_err(|e| VerifyError::Field(format!("BigUint parse '{s}': {e}")))?;
    let modulus = BigUint::from_bytes_le(&Fq::MODULUS.to_bytes_le());
    if n >= modulus {
        return Err(VerifyError::Field(format!(
            "field element '{s}' >= BN254 base field modulus"
        )));
    }
    Ok(Fq::from_le_bytes_mod_order(&n.to_bytes_le()))
}

fn parse_fq2(pair: &[String]) -> Result<Fq2, VerifyError> {
    if pair.len() < 2 {
        return Err(VerifyError::Malformed("Fq2 needs 2 components".into()));
    }
    Ok(Fq2::new(parse_fq(&pair[0])?, parse_fq(&pair[1])?))
}

fn parse_g1(coords: &[String]) -> Result<G1Affine, VerifyError> {
    if coords.len() < 2 {
        return Err(VerifyError::Malformed("G1 needs at least 2 coords".into()));
    }
    let x = parse_fq(&coords[0])?;
    let y = parse_fq(&coords[1])?;
    let pt = G1Affine::new_unchecked(x, y);
    if !pt.is_on_curve() {
        return Err(VerifyError::PointNotOnCurve);
    }
    if !pt.is_in_correct_subgroup_assuming_on_curve() {
        return Err(VerifyError::PointNotInSubgroup);
    }
    Ok(pt)
}

fn parse_g2(coords: &[Vec<String>]) -> Result<G2Affine, VerifyError> {
    if coords.len() < 2 {
        return Err(VerifyError::Malformed("G2 needs at least 2 coord pairs".into()));
    }
    let x = parse_fq2(&coords[0])?;
    let y = parse_fq2(&coords[1])?;
    let pt = G2Affine::new_unchecked(x, y);
    if !pt.is_on_curve() {
        return Err(VerifyError::PointNotOnCurve);
    }
    if !pt.is_in_correct_subgroup_assuming_on_curve() {
        return Err(VerifyError::PointNotInSubgroup);
    }
    Ok(pt)
}

fn parse_fr(s: &str) -> Result<Fr, VerifyError> {
    let n = BigUint::from_str(s)
        .map_err(|e| VerifyError::Field(format!("BigUint '{s}': {e}")))?;
    let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
    if n >= modulus {
        return Err(VerifyError::Field(format!(
            "public signal '{s}' >= BN254 scalar field modulus (non-canonical)"
        )));
    }
    Ok(Fr::from_le_bytes_mod_order(&n.to_bytes_le()))
}

// ── public API ────────────────────────────────────────────────────────────────

pub fn parse_vkey_json(json: &str) -> Result<VerifyingKey<Bn254>, VerifyError> {
    let raw: RawVkey = serde_json::from_str(json)?;
    if raw.protocol != "groth16" {
        return Err(VerifyError::Malformed(format!(
            "expected protocol=groth16, got {}",
            raw.protocol
        )));
    }
    if raw.curve != "bn128" {
        return Err(VerifyError::Malformed(format!(
            "expected curve=bn128, got {}",
            raw.curve
        )));
    }
    let alpha_g1 = parse_g1(&raw.vk_alpha_1)?;
    let beta_g2 = parse_g2(&raw.vk_beta_2)?;
    let gamma_g2 = parse_g2(&raw.vk_gamma_2)?;
    let delta_g2 = parse_g2(&raw.vk_delta_2)?;
    let gamma_abc_g1 = raw
        .ic
        .iter()
        .map(|c| parse_g1(c))
        .collect::<Result<Vec<_>, _>>()?;
    // IC must be n_public + 1 long; one bias term plus one coefficient per public input.
    if gamma_abc_g1.len() != raw.n_public + 1 {
        return Err(VerifyError::Malformed(format!(
            "IC length {} does not match nPublic+1 = {}",
            gamma_abc_g1.len(),
            raw.n_public + 1
        )));
    }
    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

pub fn load_vkey(path: impl AsRef<Path>) -> Result<VerifyingKey<Bn254>, VerifyError> {
    let json = std::fs::read_to_string(path)?;
    parse_vkey_json(&json)
}

pub fn parse_proof_json(json: &str) -> Result<Proof<Bn254>, VerifyError> {
    let raw: RawProof = serde_json::from_str(json)?;
    Ok(Proof {
        a: parse_g1(&raw.pi_a)?,
        b: parse_g2(&raw.pi_b)?,
        c: parse_g1(&raw.pi_c)?,
    })
}

pub fn load_proof(path: impl AsRef<Path>) -> Result<Proof<Bn254>, VerifyError> {
    let json = std::fs::read_to_string(path)?;
    parse_proof_json(&json)
}

pub fn parse_public_signals_json(json: &str) -> Result<Vec<Fr>, VerifyError> {
    let raw: Vec<String> = serde_json::from_str(json)?;
    raw.iter().map(|s| parse_fr(s)).collect()
}

pub fn load_public_signals(path: impl AsRef<Path>) -> Result<Vec<Fr>, VerifyError> {
    let json = std::fs::read_to_string(path)?;
    parse_public_signals_json(&json)
}

/// Run the Groth16 pairing check. Returns `Ok(())` on accept,
/// `Err(VerifyError::Rejected)` on a clean rejection, other variants on
/// malformed inputs.
pub fn verify(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_signals: &[Fr],
) -> Result<(), VerifyError> {
    if public_signals.len() + 1 != vk.gamma_abc_g1.len() {
        return Err(VerifyError::Malformed(format!(
            "public_signals length {} does not match vkey IC length {} (expected {} signals)",
            public_signals.len(),
            vk.gamma_abc_g1.len(),
            vk.gamma_abc_g1.len().saturating_sub(1),
        )));
    }
    let ok = Groth16::<Bn254>::verify(vk, public_signals, proof)
        .map_err(|e| VerifyError::Internal(format!("{e:?}")))?;
    if ok {
        Ok(())
    } else {
        Err(VerifyError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vkey_rejects_wrong_protocol() {
        let json = r#"{"protocol":"plonk","curve":"bn128","nPublic":0,"vk_alpha_1":["1","2","1"],"vk_beta_2":[["1","0"],["1","0"],["1","0"]],"vk_gamma_2":[["1","0"],["1","0"],["1","0"]],"vk_delta_2":[["1","0"],["1","0"],["1","0"]],"IC":[["1","2","1"]]}"#;
        let err = parse_vkey_json(json).unwrap_err();
        assert!(matches!(err, VerifyError::Malformed(_)));
    }

    #[test]
    fn parse_fr_rejects_over_modulus() {
        // 2^254 — comfortably above the BN254 scalar field modulus.
        let over = "28948022309329048855892746252171976963317496166410141009864396001978282409984";
        let err = parse_fr(over).unwrap_err();
        assert!(matches!(err, VerifyError::Field(_)));
    }

    #[test]
    fn parse_public_signals_accepts_empty_array() {
        let signals = parse_public_signals_json("[]").unwrap();
        assert!(signals.is_empty());
    }
}
