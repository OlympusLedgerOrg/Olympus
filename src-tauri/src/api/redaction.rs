use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use super::auth::AuthedKey;
use super::error::{ApiError, ApiResult};
use super::state::AppState;
use crate::zk::poseidon::redaction_commitment;
use crate::zk::proof::{parse_fr, parse_proof_json, parse_signals_slice};
use crate::zk::verify::redaction_verifier;
use crate::zk::witness::redaction::{RedactionWitness, MAX_LEAVES, REDACTION_DEPTH};

// ── Request / response ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RedactionVerifyRequest {
    /// Groth16 proof JSON (snarkjs format).
    pub proof_json: String,
    /// Public signals: [originalRoot, redactedCommitment, revealedCount]
    pub public_signals: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RedactionVerifyResponse {
    pub valid: bool,
    pub original_root: String,
    pub redacted_commitment: String,
    pub revealed_count: u64,
}

#[derive(Debug, Deserialize)]
pub struct RedactionCommitRequest {
    /// Hex-encoded original leaf hashes (up to MAX_LEAVES = 6).
    pub original_leaves: Vec<String>,
    /// Boolean mask: true = revealed, false = redacted.
    pub reveal_mask: Vec<bool>,
    /// Merkle path elements and indices for all leaves (from ledger).
    pub path_elements: Vec<Vec<String>>,
    pub path_indices: Vec<Vec<u8>>,
    /// The original Merkle root (from the ledger commit).
    pub original_root: String,
}

#[derive(Debug, Serialize)]
pub struct RedactionCommitResponse {
    /// Poseidon commitment over revealed leaves — submit this as public signal.
    pub redacted_commitment: String,
    pub revealed_count: u64,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Verify a redaction validity proof.
/// Public — no API key required, same as doc/verify.
pub async fn verify_redaction(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<RedactionVerifyRequest>,
) -> ApiResult<Json<RedactionVerifyResponse>> {
    let signals = parse_signals_slice(&req.public_signals)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    if signals.len() != 3 {
        return Err(ApiError::BadRequest(
            "redaction_validity requires exactly 3 public signals".into(),
        ));
    }

    let valid = tokio::task::spawn_blocking({
        let proof_json = req.proof_json.clone();
        let signals = signals.clone();
        move || {
            redaction_verifier()
                .map_err(|e| ApiError::Internal(e.to_string()))?
                .verify(&proof_json, &signals)
                .map_err(|e| ApiError::Internal(e.to_string()))
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("thread join: {e}")))??;

    Ok(Json(RedactionVerifyResponse {
        valid,
        original_root: req.public_signals[0].clone(),
        redacted_commitment: req.public_signals[1].clone(),
        revealed_count: req.public_signals[2]
            .parse()
            .unwrap_or(0),
    }))
}

/// Compute the redacted commitment for a given leaf set and reveal mask.
/// Requires `commit` scope — caller provides the leaf data, we return the
/// Poseidon commitment they should use as public input when generating a proof.
pub async fn compute_commitment(
    State(_state): State<Arc<AppState>>,
    authed: AuthedKey,
    Json(req): Json<RedactionCommitRequest>,
) -> ApiResult<Json<RedactionCommitResponse>> {
    authed.require_scope("commit")?;

    if req.original_leaves.len() > MAX_LEAVES {
        return Err(ApiError::BadRequest(format!(
            "original_leaves length must be ≤ {MAX_LEAVES}"
        )));
    }
    if req.reveal_mask.len() != req.original_leaves.len() {
        return Err(ApiError::BadRequest(
            "reveal_mask length must match original_leaves".into(),
        ));
    }

    let revealed_count = req.reveal_mask.iter().filter(|&&b| b).count() as u64;

    // Parse leaf hashes as BN254 field elements.
    let leaves: Vec<ark_bn254::Fr> = req
        .original_leaves
        .iter()
        .map(|s| parse_fr(s).map_err(|e| ApiError::BadRequest(e.to_string())))
        .collect::<ApiResult<_>>()?;

    let commitment = redaction_commitment(revealed_count, &leaves, &req.reveal_mask)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Return commitment as a decimal string (matches snarkjs public signal format).
    use ark_ff::BigInteger;
    use ark_ff::PrimeField;
    let commitment_str = commitment.into_bigint().to_string();

    Ok(Json(RedactionCommitResponse {
        redacted_commitment: commitment_str,
        revealed_count,
    }))
}
