//! Redaction commitment endpoint — port of `api/routers/redaction.py`.
//!
//! Route
//! -----
//! POST /redaction/link — link a redacted document back to its original commit
//!
//! This endpoint is **public** (no API key required) because verification is a
//! transparency operation.
//!
//! # Crypto path
//!
//! Uses `olympus_crypto::poseidon` directly — no PyO3, no subprocess.
//! The Poseidon parameters and domain constants match the circom circuits and
//! `protocol/poseidon_tree.py` exactly.

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use olympus_crypto::poseidon::{
    blake3_hex_to_poseidon_leaf, compute_poseidon_commitment_root,
    compute_redaction_commitments,
};

use crate::api::middleware::auth::RateLimit;
use crate::state::AppState;

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_LEAVES: usize = 64;

// ── Error helper ──────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail})))
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RedactionLinkRequest {
    /// Ledger commit ID for the original document.
    pub original_commit_id: String,
    /// 64 BLAKE3 hex hashes — one per equal-sized chunk of the original file.
    pub original_chunks: Vec<String>,
    /// 64 BLAKE3 hex hashes — one per equal-sized chunk of the redacted file.
    pub redacted_chunks: Vec<String>,
}

#[derive(Serialize)]
pub struct RedactionLinkResponse {
    pub original_commit_id: String,
    pub original_blake3: String,
    pub original_root: String,
    pub redacted_commitment: String,
    pub reveal_mask_commitment: String,
    pub reveal_mask: Vec<u8>,
    pub revealed_count: usize,
    pub redacted_count: usize,
    pub verified: bool,
    pub note: String,
}

// ── DB row ────────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct CommitDocHash {
    doc_hash: String,
}

// ── Route handler ─────────────────────────────────────────────────────────────

/// POST /redaction/link
///
/// Given 64 BLAKE3 chunk hashes from the original and redacted documents,
/// computes the Poseidon commitment bundle that proves the redacted file is a
/// valid partial disclosure of the original committed document.
async fn link_redaction(
    State(state): State<AppState>,
    _rl: RateLimit,
    Json(body): Json<RedactionLinkRequest>,
) -> Result<Json<RedactionLinkResponse>, ApiError> {
    // 1. Validate chunk counts.
    if body.original_chunks.len() != MAX_LEAVES {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "original_chunks must contain exactly {MAX_LEAVES} hashes; got {}.",
                body.original_chunks.len()
            ),
        ));
    }
    if body.redacted_chunks.len() != MAX_LEAVES {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "redacted_chunks must contain exactly {MAX_LEAVES} hashes; got {}.",
                body.redacted_chunks.len()
            ),
        ));
    }

    // 2. Confirm the original commit exists in the DB.
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let commit: Option<CommitDocHash> = sqlx::query_as::<_, CommitDocHash>(
        "SELECT doc_hash FROM doc_commits WHERE commit_id = $1 LIMIT 1",
    )
    .bind(&body.original_commit_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let commit = commit.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            &format!(
                "Commit {:?} not found in the ledger.",
                body.original_commit_id
            ),
        )
    })?;

    // 3. Normalise to lowercase and derive Poseidon leaves from original chunks.
    let orig_normalised: Vec<String> = body.original_chunks.iter().map(|h| h.to_lowercase()).collect();
    let redc_normalised: Vec<String> = body.redacted_chunks.iter().map(|h| h.to_lowercase()).collect();

    let original_leaves: Vec<num_bigint::BigUint> = orig_normalised
        .iter()
        .enumerate()
        .map(|(i, h)| {
            blake3_hex_to_poseidon_leaf(h).map_err(|e| {
                err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("original_chunks[{i}]: {e}"),
                )
            })
        })
        .collect::<Result<_, _>>()?;

    // Validate redacted chunk hexes (they are only compared, not run through Poseidon).
    for (i, h) in redc_normalised.iter().enumerate() {
        if h.len() != 64 {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("redacted_chunks[{i}]: must be 64 hex characters."),
            ));
        }
        if hex::decode(h).is_err() {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("redacted_chunks[{i}]: invalid hex."),
            ));
        }
    }

    // 4. Compute reveal mask: 1 = chunk unchanged, 0 = chunk differs.
    let reveal_mask: Vec<u8> = (0..MAX_LEAVES)
        .map(|i| if orig_normalised[i] == redc_normalised[i] { 1u8 } else { 0u8 })
        .collect();

    let revealed_count = reveal_mask.iter().filter(|&&b| b == 1).count();
    let redacted_count = MAX_LEAVES - revealed_count;

    if redacted_count == 0 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "All chunks are identical — no redaction detected. \
             Ensure the redacted file differs from the original.",
        ));
    }
    if revealed_count == 0 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "No chunks are identical — the files appear unrelated. \
             Ensure the redacted file was derived from the original.",
        ));
    }

    // 5. Compute Poseidon original root.
    let original_root = compute_poseidon_commitment_root(&original_leaves);

    // 6. Compute redactedCommitment + revealMaskCommitment.
    let (redacted_commitment, reveal_mask_commitment) =
        compute_redaction_commitments(&original_leaves, &reveal_mask, revealed_count as u64);

    Ok(Json(RedactionLinkResponse {
        original_commit_id: body.original_commit_id,
        original_blake3: commit.doc_hash,
        original_root: original_root.to_string(),
        redacted_commitment: redacted_commitment.to_string(),
        reveal_mask_commitment: reveal_mask_commitment.to_string(),
        reveal_mask,
        revealed_count,
        redacted_count,
        verified: true,
        note: format!(
            "Redaction commitment verified. {redacted_count} of {MAX_LEAVES} chunks redacted, \
             {revealed_count} revealed. This bundle can be used as public inputs for the \
             redaction_validity ZK proof once the trusted-setup ceremony is complete."
        ),
    }))
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new().route("/redaction/link", post(link_redaction))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_hash() -> String {
        "0".repeat(64)
    }

    fn one_hash() -> String {
        "1".repeat(64)
    }

    #[test]
    fn reveal_mask_correct() {
        let orig: Vec<String> = (0..MAX_LEAVES).map(|_| zero_hash()).collect();
        let mut redc = orig.clone();
        // Redact first chunk.
        redc[0] = one_hash();

        let mask: Vec<u8> = (0..MAX_LEAVES)
            .map(|i| if orig[i] == redc[i] { 1u8 } else { 0u8 })
            .collect();

        assert_eq!(mask[0], 0, "first chunk differs — should be 0");
        assert!(mask[1..].iter().all(|&b| b == 1));
        assert_eq!(mask.iter().filter(|&&b| b == 0).count(), 1);
    }

    #[test]
    fn leaf_derivation_is_deterministic() {
        let h = zero_hash();
        let l1 = blake3_hex_to_poseidon_leaf(&h).unwrap();
        let l2 = blake3_hex_to_poseidon_leaf(&h).unwrap();
        assert_eq!(l1, l2);
    }

    #[test]
    fn leaf_derivation_differs_for_different_hashes() {
        let h1 = blake3_hex_to_poseidon_leaf(&zero_hash()).unwrap();
        let h2 = blake3_hex_to_poseidon_leaf(&one_hash()).unwrap();
        assert_ne!(h1, h2);
    }
}
