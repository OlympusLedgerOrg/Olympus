// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! `GET /monitor/mmd/{content_hash}` — ADR-0021 Maximum Merge Delay evidence.
//!
//! CT's MMD promise: a submitted record appears in a published, signed
//! checkpoint within a bounded time (`crate::mmd::MmdPolicy`,
//! `OLYMPUS_MMD_SECONDS`). This endpoint answers, for one committed record,
//! "how long did that actually take, and did it meet policy" — the evidence
//! ADR-0021 calls out as letting "submitters prove delayed inclusion
//! breaches."
//!
//! The record's own `snapshot_index`/`snapshot_size` (frozen at ingest,
//! migration 0029) place it in its shard's Poseidon ledger-snapshot tree;
//! the first `own_checkpoints` row for that shard whose `tree_size` is at
//! least `snapshot_size` is the first published, signed checkpoint that
//! could possibly cover it (the tree is append-only, so no earlier
//! checkpoint's smaller tree could have included this leaf).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::Serialize;

use crate::anchoring::own_checkpoint::first_covering_for_shard;
use crate::anchoring::CHECKPOINT_SCOPE_SHARD;
use crate::api::ingest::snapshot_evidence::{fetch_snapshot_row, pending_detail};
use crate::api::middleware::auth::RateLimit;
use crate::state::AppState;

use super::checkpoints::CheckpointSummary;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "detail": detail })))
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MmdStatus {
    /// A signed checkpoint covering this record was published within the
    /// configured MMD.
    CoveredWithinPolicy,
    /// A signed checkpoint covering this record exists, but it was
    /// published later than the configured MMD allows — a provable breach.
    CoveredLateBreach,
    /// No covering checkpoint exists yet, but the MMD window has not
    /// elapsed since ingest — not (yet) a breach.
    PendingWithinPolicy,
    /// No covering checkpoint exists yet and the MMD window has already
    /// elapsed since ingest — a provable breach (absence-of-publication
    /// evidence, not just lateness).
    PendingBreach,
}

/// Pure classification: does the elapsed time (either the actual delay to a
/// covering checkpoint, or the time elapsed so far with none yet) sit within
/// `mmd_seconds`. Split out from the handler so the MMD/breach boundary
/// logic is unit-testable without a database.
fn classify(covered: bool, elapsed_seconds: i64, mmd_seconds: i64) -> MmdStatus {
    match (covered, elapsed_seconds <= mmd_seconds) {
        (true, true) => MmdStatus::CoveredWithinPolicy,
        (true, false) => MmdStatus::CoveredLateBreach,
        (false, true) => MmdStatus::PendingWithinPolicy,
        (false, false) => MmdStatus::PendingBreach,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MmdResponse {
    pub content_hash: String,
    pub proof_id: String,
    pub shard_id: String,
    pub ingested_at_unix: i64,
    pub snapshot_index: u64,
    pub snapshot_size: u64,
    pub mmd_seconds: i64,
    pub status: MmdStatus,
    /// Seconds from ingest to the first covering checkpoint's
    /// `checkpoint_timestamp` (when `first_covering_checkpoint` is `Some`),
    /// or seconds elapsed from ingest to now with no covering checkpoint yet
    /// (when it is `None`). Either way: how long has this record been
    /// waiting, or how long did it wait.
    pub elapsed_seconds: i64,
    pub first_covering_checkpoint: Option<CheckpointSummary>,
}

pub(super) async fn get_mmd_evidence(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(content_hash): Path<String>,
) -> Result<Json<MmdResponse>, ApiError> {
    let content_hash = content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let row = fetch_snapshot_row(pool, &content_hash)
        .await
        .map_err(|e| {
            tracing::error!("monitor: get_mmd_evidence: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
        })?
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "content_hash is not present in the ledger.",
            )
        })?;

    let (snapshot_index, snapshot_size) = match (row.snapshot_index, row.snapshot_size) {
        (Some(i), Some(s)) => (i, s),
        _ => {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                pending_detail(&row.record_type),
            ))
        }
    };

    let ingested_at_unix = row.ts.and_utc().timestamp();
    let mmd_seconds = state.mmd_policy.mmd_seconds;

    let covering =
        first_covering_for_shard(pool, CHECKPOINT_SCOPE_SHARD, &row.shard_id, snapshot_size)
            .await
            .map_err(|e| {
                tracing::error!("monitor: get_mmd_evidence: {e}");
                err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
            })?;

    let (elapsed_seconds, status, first_covering_checkpoint) = match covering {
        Some(cp) => {
            // Clamp at 0: a checkpoint's `checkpoint_timestamp` predating
            // this record's own `ts` would mean the shard's clock moved
            // backwards between commits, which the append-only/write-once
            // ledger structure otherwise forbids from mattering — never
            // report a negative delay.
            let delay = (cp.checkpoint_timestamp - ingested_at_unix).max(0);
            let status = classify(true, delay, mmd_seconds);
            (delay, status, Some(CheckpointSummary::from(cp)))
        }
        None => {
            let elapsed = (Utc::now().timestamp() - ingested_at_unix).max(0);
            let status = classify(false, elapsed, mmd_seconds);
            (elapsed, status, None)
        }
    };

    Ok(Json(MmdResponse {
        content_hash,
        proof_id: row.proof_id,
        shard_id: row.shard_id,
        ingested_at_unix,
        snapshot_index: snapshot_index as u64,
        snapshot_size: snapshot_size as u64,
        mmd_seconds,
        status,
        elapsed_seconds,
        first_covering_checkpoint,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covered_within_policy() {
        assert_eq!(classify(true, 100, 200), MmdStatus::CoveredWithinPolicy);
        assert_eq!(classify(true, 200, 200), MmdStatus::CoveredWithinPolicy);
    }

    #[test]
    fn covered_late_is_a_breach() {
        assert_eq!(classify(true, 201, 200), MmdStatus::CoveredLateBreach);
    }

    #[test]
    fn pending_within_policy_is_not_a_breach() {
        assert_eq!(classify(false, 199, 200), MmdStatus::PendingWithinPolicy);
    }

    #[test]
    fn pending_past_policy_is_a_breach() {
        assert_eq!(classify(false, 201, 200), MmdStatus::PendingBreach);
    }
}
