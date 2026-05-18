//! Tauri commands exposed to the React frontend for ZK proof verification.
//!
//! All heavy work (Groth16 pairing check) is pushed to `spawn_blocking` so the
//! async Tauri runtime stays responsive.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::proof::{parse_fr, parse_signals_slice, ProofError};
use super::verify::{existence_verifier, non_existence_verifier, redaction_verifier, VerifyError};

// ── Error type (must be Serialize for Tauri commands) ─────────────────────────

#[derive(Debug, Error, Serialize)]
pub enum ZkCommandError {
    #[error("Unknown circuit: {0}")]
    UnknownCircuit(String),
    #[error("Proof parse error: {0}")]
    ProofParse(String),
    #[error("Signal parse error: {0}")]
    SignalParse(String),
    #[error("Verifier init error: {0}")]
    VerifierInit(String),
    #[error("Verification error: {0}")]
    Verify(String),
}

impl From<ProofError> for ZkCommandError {
    fn from(e: ProofError) -> Self {
        Self::ProofParse(e.to_string())
    }
}

impl From<VerifyError> for ZkCommandError {
    fn from(e: VerifyError) -> Self {
        Self::Verify(e.to_string())
    }
}

// ── Request / response shapes ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProofRequest {
    /// One of: "document_existence" | "non_existence" | "redaction_validity"
    pub circuit: String,
    /// The `proof` object from snarkjs as a JSON string.
    pub proof_json: String,
    /// Public signals as decimal strings (same order as snarkjs publicSignals).
    pub public_signals: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProofResponse {
    pub valid: bool,
    pub circuit: String,
}

// ── Tauri command ─────────────────────────────────────────────────────────────

/// Verify a Groth16 proof entirely in Rust — no Node.js, no snarkjs subprocess.
///
/// Called from the frontend via `invoke("verify_proof", { circuit, proofJson, publicSignals })`.
#[tauri::command]
pub async fn verify_proof(req: VerifyProofRequest) -> Result<VerifyProofResponse, ZkCommandError> {
    let circuit = req.circuit.clone();
    let proof_json = req.proof_json.clone();
    let signals_raw = req.public_signals.clone();

    tokio::task::spawn_blocking(move || {
        let signals = parse_signals_slice(&signals_raw)
            .map_err(|e| ZkCommandError::SignalParse(e.to_string()))?;

        let valid = match circuit.as_str() {
            "document_existence" => existence_verifier()
                .map_err(|e| ZkCommandError::VerifierInit(e.to_string()))?
                .verify(&proof_json, &signals)?,
            "non_existence" => non_existence_verifier()
                .map_err(|e| ZkCommandError::VerifierInit(e.to_string()))?
                .verify(&proof_json, &signals)?,
            "redaction_validity" => redaction_verifier()
                .map_err(|e| ZkCommandError::VerifierInit(e.to_string()))?
                .verify(&proof_json, &signals)?,
            other => return Err(ZkCommandError::UnknownCircuit(other.to_string())),
        };

        Ok(VerifyProofResponse {
            valid,
            circuit: req.circuit,
        })
    })
    .await
    .map_err(|e| ZkCommandError::Verify(format!("Thread join: {e}")))?
}
