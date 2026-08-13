// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! `GET /monitor/checkpoints` and `GET /monitor/checkpoints/latest` —
//! ADR-0021 Monitor API "get-sth" / "get-sth-history" equivalents.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::anchoring::own_checkpoint::{latest_for_shard, list_recent_for_shard, OwnCheckpointRow};
use crate::anchoring::CHECKPOINT_SCOPE_SHARD;
use crate::api::ingest::sanitize_shard;
use crate::api::middleware::auth::RateLimit;
use crate::state::AppState;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "detail": detail })))
}

/// Default page size for `GET /monitor/checkpoints` when `limit` is omitted.
const DEFAULT_LIMIT: i64 = 20;
/// Hard cap on `limit`, regardless of what the caller requests — an
/// unauthenticated, rate-limited-only endpoint must not let a single request
/// force an unbounded result set.
const MAX_LIMIT: i64 = 200;

/// One signed checkpoint, as served to a monitor — every field a third party
/// needs to independently recompute `checkpoint_signing_message_v2`
/// (`anchoring::checkpoint_signing_message_v2`) and
/// `checkpoint_anchor_hash_v2` and verify the BJJ/Ed25519 signatures over
/// them, without any further server trust.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointSummary {
    pub id: String,
    pub format_version: i16,
    pub checkpoint_scope: String,
    pub shard_id: String,
    /// Decimal Fr string — the Poseidon ledger-snapshot root this checkpoint
    /// signs (`crates/olympus-crypto::ledger_snapshot`), NOT the BLAKE3
    /// parser-bound SMT root. See this module's doc comment.
    pub ledger_root: String,
    pub tree_size: i64,
    pub checkpoint_timestamp: i64,
    pub authority_pubkey_hash: Option<String>,
    pub authority_pubkey_x: Option<String>,
    pub authority_pubkey_y: Option<String>,
    pub sig_r8x: Option<String>,
    pub sig_r8y: Option<String>,
    pub sig_s: Option<String>,
    /// 64-char lowercase hex — BLAKE3 domain-separated digest externally
    /// anchored (RFC 3161 / Rekor / OTS).
    pub anchor_hash: String,
    pub ed25519_pubkey_hex: Option<String>,
    pub ed25519_signature_hex: Option<String>,
    /// ADR-0031 §2 signed `TransitionAttestation` binding
    /// `transition_original_root → ledger_root` over `tree_size`,
    /// BJJ-signed over `olympus_crypto::persist_message(...)` reduced mod l
    /// — verifiable offline against that primitive without trusting this
    /// server. All five fields are `None` together only for pre-migration-
    /// 0049 rows or a keyless dev checkpoint (see CLAUDE.md's insert-only
    /// ledger invariant); production checkpoints always carry all five.
    pub transition_original_root: Option<String>,
    pub transition_leaf: Option<String>,
    pub transition_path: Option<serde_json::Value>,
    pub transition_sig_r8x: Option<String>,
    pub transition_sig_r8y: Option<String>,
    pub transition_sig_s: Option<String>,
}

impl From<OwnCheckpointRow> for CheckpointSummary {
    fn from(r: OwnCheckpointRow) -> Self {
        Self {
            id: r.id.to_string(),
            format_version: r.format_version,
            checkpoint_scope: r.checkpoint_scope.unwrap_or_default(),
            shard_id: r.shard_id.unwrap_or_default(),
            ledger_root: r.ledger_root,
            tree_size: r.tree_size,
            checkpoint_timestamp: r.checkpoint_timestamp,
            authority_pubkey_hash: r.authority_pubkey_hash,
            authority_pubkey_x: r.authority_pubkey_x,
            authority_pubkey_y: r.authority_pubkey_y,
            sig_r8x: r.sig_r8x,
            sig_r8y: r.sig_r8y,
            sig_s: r.sig_s,
            anchor_hash: hex::encode(r.anchor_hash),
            ed25519_pubkey_hex: r.ed25519_pubkey_hex,
            ed25519_signature_hex: r.ed25519_signature_hex,
            transition_original_root: r.transition_original_root,
            transition_leaf: r.transition_leaf,
            transition_path: r.transition_path,
            transition_sig_r8x: r.transition_sig_r8x,
            transition_sig_r8y: r.transition_sig_r8y,
            transition_sig_s: r.transition_sig_s,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointsResponse {
    pub shard_id: String,
    pub checkpoints: Vec<CheckpointSummary>,
}

#[derive(Deserialize)]
pub(super) struct ShardQuery {
    shard_id: String,
}

#[derive(Deserialize)]
pub(super) struct ListQuery {
    shard_id: String,
    #[serde(default)]
    limit: Option<i64>,
}

fn validate_shard(shard_id: &str) -> Result<(), ApiError> {
    if !sanitize_shard(shard_id) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "shard_id must be 1-128 chars of [A-Za-z0-9:._-].",
        ));
    }
    Ok(())
}

pub(super) async fn list_checkpoints(
    State(state): State<AppState>,
    _rl: RateLimit,
    Query(query): Query<ListQuery>,
) -> Result<Json<CheckpointsResponse>, ApiError> {
    validate_shard(&query.shard_id)?;
    let limit = query
        .limit
        .filter(|&n| n > 0)
        .map(|n| n.min(MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT);

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let rows = list_recent_for_shard(pool, CHECKPOINT_SCOPE_SHARD, &query.shard_id, limit)
        .await
        .map_err(|e| {
            tracing::error!("monitor: list_checkpoints: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
        })?;

    Ok(Json(CheckpointsResponse {
        shard_id: query.shard_id,
        checkpoints: rows.into_iter().map(CheckpointSummary::from).collect(),
    }))
}

pub(super) async fn latest_checkpoint(
    State(state): State<AppState>,
    _rl: RateLimit,
    Query(query): Query<ShardQuery>,
) -> Result<Json<CheckpointSummary>, ApiError> {
    validate_shard(&query.shard_id)?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let row = latest_for_shard(pool, CHECKPOINT_SCOPE_SHARD, &query.shard_id)
        .await
        .map_err(|e| {
            tracing::error!("monitor: latest_checkpoint: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
        })?
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "No signed checkpoint has been published for this shard yet.",
            )
        })?;

    Ok(Json(CheckpointSummary::from(row)))
}
