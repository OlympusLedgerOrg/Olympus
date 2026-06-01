//! Ledger state, proof, activity, and document ingestion/verification routes.
//!
//! Ported from `api/routers/ledger.py`.
//!
//! Routes
//! ------
//! GET  /ledger/state                — global state root and summary
//! GET  /ledger/shard/{shard_id}     — per-shard state
//! GET  /ledger/proof/{commit_id}    — inclusion proof for a commit
//! GET  /ledger/activity             — human-readable activity feed
//! POST /ledger/ingest/simple        — user-friendly document ingestion
//! POST /ledger/verify/simple        — user-friendly document verification
//!
//! # State root
//!
//! The Tauri port stores `merkle_root` per commit row.  The shard state root is
//! the `merkle_root` from the most recent commit in that shard.  The global
//! state root is the BLAKE3 hash of all shard state roots concatenated in
//! lexicographic shard-ID order (single-shard deployments: state_root = global_root).
//!
//! # ZK proofs
//!
//! All `/proof/` responses use the non-development path from the Python router:
//! a 202 `pending` response with the stored `merkle_root` and empty
//! `merkle_proof`.  Full proof generation requires the Groth16 trusted-setup
//! ceremony and is deferred to a later phase.
//!
//! # Ingest scope
//!
//! `POST /ledger/ingest/simple` requires a valid API key with one of the
//! write-side scopes (`ingest`, `write`, `commit`, or `admin`).
//! `POST /ledger/verify/simple` is public (rate-limited only).
use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

mod read;
mod simple;

use read::{get_commit_proof, get_ledger_activity, get_ledger_state, get_shard_state};
use simple::{simple_document_ingest, simple_document_verify};

// ── Constants ─────────────────────────────────────────────────────────────────
const DEFAULT_SHARD: &str = "0x4F3A";

/// BLAKE3 hex of 32 zero bytes — used as the "empty" state root.
const ZERO_ROOT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Shard-ID character allow-list: alphanumeric, colon, dot, underscore, hyphen.
fn valid_shard_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-'))
}
// ── Error helper ──────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail})))
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

fn naive_utc() -> NaiveDateTime {
    Utc::now().naive_utc()
}

// ── DB row (shared: read + simple) ──────────────────────────────────────────
#[derive(sqlx::FromRow)]
pub(super) struct DocCommitRow {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    request_id: Option<String>,
    pub(super) doc_hash: String,
    pub(super) commit_id: String,
    pub(super) epoch_timestamp: NaiveDateTime,
    pub(super) shard_id: String,
    pub(super) merkle_root: Option<String>,
    #[allow(dead_code)]
    zk_proof: Option<String>,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct LedgerStateResponse {
    pub global_state_root: String,
    pub shard_count: usize,
    pub total_commits: i64,
    pub last_epoch: Option<String>,
}

#[derive(Serialize)]
pub struct CommitSummary {
    pub commit_id: String,
    pub doc_hash: String,
    pub epoch: String,
    pub shard_id: String,
    pub merkle_root: Option<String>,
}

#[derive(Serialize)]
pub struct ShardStateResponse {
    pub shard_id: String,
    pub state_root: String,
    pub commit_count: i64,
    pub latest_commits: Vec<CommitSummary>,
}

#[derive(Serialize)]
pub struct ProofResponse {
    pub commit_id: String,
    pub shard_id: String,
    pub epoch: String,
    pub status: &'static str,
    pub reason: &'static str,
    pub merkle_root: Option<String>,
    pub merkle_proof: Vec<serde_json::Value>,
}

#[derive(Serialize)]
pub struct ActivityItem {
    pub id: String,
    pub timestamp: String,
    pub activity_type: String,
    pub title: String,
    pub description: String,
    pub related_commit_id: Option<String>,
    pub related_request_id: Option<String>,
}

#[derive(Serialize)]
pub struct ActivityFeedResponse {
    pub items: Vec<ActivityItem>,
    pub total: i64,
}

#[derive(Serialize)]
pub struct IngestionStep {
    pub step: u32,
    pub label: String,
    pub status: &'static str,
    pub detail: String,
}

#[derive(Serialize)]
pub struct SimpleIngestionResponse {
    pub status: &'static str,
    pub commit_id: String,
    pub doc_hash: String,
    pub shard_id: String,
    pub epoch: String,
    pub message: String,
    pub steps: Vec<IngestionStep>,
}

#[derive(Serialize)]
pub struct SimpleVerificationResponse {
    pub verified: bool,
    pub commit_id: Option<String>,
    pub doc_hash: Option<String>,
    pub epoch: Option<String>,
    pub shard_id: Option<String>,
    pub merkle_root: Option<String>,
    pub message: String,
}

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ActivityQuery {
    #[serde(default = "default_activity_limit")]
    pub limit: u32,
    pub activity_type: Option<String>,
}

fn default_activity_limit() -> u32 {
    50
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ledger/state", get(get_ledger_state))
        .route("/ledger/shard/{shard_id}", get(get_shard_state))
        .route("/ledger/proof/{commit_id}", get(get_commit_proof))
        .route("/ledger/activity", get(get_ledger_activity))
        .route("/ledger/ingest/simple", post(simple_document_ingest))
        .route("/ledger/verify/simple", post(simple_document_verify))
}

/// Verify/read-only subset of the ledger surface, safe to expose over the
/// federation Tor onion service. Excludes `/ledger/ingest/simple` — document
/// ingestion is an authority-bound write path and must never be remotely
/// reachable. All routes here are the same public, rate-limited reads/verify
/// already served on the main HTTP listener, so exposing them over the
/// loopback-validated onion service adds no new authority. Mirrors the
/// `public_router()` convention in `zk`, `ingest`, and `credentials`; its
/// absence was the pre-existing `--features federation` build break (#1109).
#[cfg(feature = "federation")]
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/ledger/state", get(get_ledger_state))
        .route("/ledger/shard/{shard_id}", get(get_shard_state))
        .route("/ledger/proof/{commit_id}", get(get_commit_proof))
        .route("/ledger/activity", get(get_ledger_activity))
        .route("/ledger/verify/simple", post(simple_document_verify))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_shard_id_accepts_expected_patterns() {
        assert!(valid_shard_id("0x4F3A"));
        assert!(valid_shard_id("shard-1"));
        assert!(valid_shard_id("shard.us:east"));
        assert!(valid_shard_id("a"));
    }

    #[test]
    fn valid_shard_id_rejects_invalid() {
        assert!(!valid_shard_id(""));
        assert!(!valid_shard_id(&"a".repeat(129)));
        assert!(!valid_shard_id("shard/one"));
        assert!(!valid_shard_id("shard one"));
        assert!(!valid_shard_id("../escape"));
    }

    #[test]
    fn activity_limit_clamped() {
        let q = ActivityQuery {
            limit: 500,
            activity_type: None,
        };
        assert_eq!(q.limit.clamp(1, 200), 200);
    }
}
