//! Record-lookup GET routes split out of the ingest module:
//! `GET /ingest/records/hash/{hash}/verify` and
//! `GET /ingest/records/{proof_id}`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use super::*;
use crate::api::middleware::auth::RateLimit;
use crate::state::AppState;

// ── Route: GET /ingest/records/hash/{hash}/verify ─────────────────────────────

pub(super) async fn verify_by_hash(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(hash): Path<String>,
) -> Result<Json<RecordProofResponse>, ApiError> {
    let hash = hash.trim().to_lowercase();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Hash must be a 64-character hex string.",
        ));
    }

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    // Audit A1: content_hash is unique only per shard (migration 0038), so the
    // same bytes may exist in several shards. Resolve deterministically to the
    // EARLIEST commit (earliest-wins) so a later commit under another shard —
    // e.g. an attacker's — can never shadow the original's verify response.
    let row = sqlx::query_as::<_, IngestRow>(
        "SELECT proof_id, record_id, shard_id, record_type, content_hash, merkle_root,
                ledger_entry_hash, ts, batch_id, poseidon_root, snapshot_root, canonicalization, merkle_proof_json, original_hash
         FROM ingest_records
         WHERE content_hash = $1
         ORDER BY ts ASC, proof_id ASC
         LIMIT 1",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Hash not found in ledger."))?;

    Ok(Json(row_to_proof_response(&row, true)))
}

// ── Route: GET /ingest/records/{proof_id} ────────────────────────────────────

pub(super) async fn get_record(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(proof_id): Path<String>,
) -> Result<Json<RecordProofResponse>, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let row = sqlx::query_as::<_, IngestRow>(
        "SELECT proof_id, record_id, shard_id, record_type, content_hash, merkle_root,
                ledger_entry_hash, ts, batch_id, poseidon_root, snapshot_root, canonicalization, merkle_proof_json, original_hash
         FROM ingest_records
         WHERE proof_id = $1
         LIMIT 1",
    )
    .bind(&proof_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Record not found."))?;

    Ok(Json(row_to_proof_response(&row, false)))
}
