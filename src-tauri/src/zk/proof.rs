//! Parse snarkjs Groth16 proof JSON into `ark-groth16` types.
//!
//! snarkjs proof shape:
//! ```json
//! {
//!   "pi_a": ["x","y","1"],
//!   "pi_b": [["x_c0","x_c1"],["y_c0","y_c1"],["1","0"]],
//!   "pi_c": ["x","y","1"],
//!   "protocol": "groth16",
//!   "curve": "bn128"
//! }
//! ```
//! Public signals are a separate array of decimal strings.

use std::str::FromStr;

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::Proof;
use num_bigint::BigUint;
use serde::Deserialize;
use thiserror::Error;

use super::vkey::{parse_g1, parse_g2, VkeyError};

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Field parse error: {0}")]
    Field(String),
    #[error("Curve point error: {0}")]
    Curve(#[from] VkeyError),
}

#[derive(Deserialize)]
pub struct RawProof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
}

/// Parse a snarkjs proof JSON string.
pub fn parse_proof_json(json: &str) -> Result<Proof<Bn254>, ProofError> {
    let raw: RawProof = serde_json::from_str(json)?;
    from_raw(&raw)
}

pub fn from_raw(raw: &RawProof) -> Result<Proof<Bn254>, ProofError> {
    Ok(Proof {
        a: parse_g1(&raw.pi_a)?,
        b: parse_g2(&raw.pi_b)?,
        c: parse_g1(&raw.pi_c)?,
    })
}

/// Parse public signals from a JSON array of decimal strings.
pub fn parse_public_signals(json: &str) -> Result<Vec<Fr>, ProofError> {
    let raw: Vec<String> = serde_json::from_str(json)?;
    parse_signals_slice(&raw)
}

pub fn parse_signals_slice(signals: &[String]) -> Result<Vec<Fr>, ProofError> {
    signals.iter().map(|s| parse_fr(s)).collect()
}

pub fn parse_fr(s: &str) -> Result<Fr, ProofError> {
    let n = BigUint::from_str(s)
        .map_err(|e| ProofError::Field(format!("BigUint '{s}': {e}")))?;
    Ok(Fr::from_le_bytes_mod_order(&n.to_bytes_le()))
}

/// Convenience: parse both proof and signals from a combined snarkjs output object.
///
/// Expected shape: `{"proof":{...}, "publicSignals":[...]}`
#[derive(Deserialize)]
struct FullProveOutput {
    proof: RawProof,
    #[serde(rename = "publicSignals")]
    public_signals: Vec<String>,
}

pub fn parse_full_prove_output(json: &str) -> Result<(Proof<Bn254>, Vec<Fr>), ProofError> {
    let out: FullProveOutput = serde_json::from_str(json)?;
    let proof = from_raw(&out.proof)?;
    let signals = parse_signals_slice(&out.public_signals)?;
    Ok((proof, signals))
}
