use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::error::{ApiError, ApiResult};
use super::merkle;
use super::state::AppState;
use super::validation::{validate_shard_id, MAX_LEAVES_PER_SHARD};

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct LedgerStateResponse {
    pub total_commits: i64,
    pub latest_epoch: Option<DateTime<Utc>>,
    pub shards: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ShardStateResponse {
    pub shard_id: String,
    pub commit_count: i64,
    pub recent_commits: Vec<CommitSummary>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CommitSummary {
    pub commit_id: String,
    pub doc_hash: String,
    pub epoch_timestamp: DateTime<Utc>,
    pub merkle_root: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProofResponse {
    pub commit_id: String,
    pub shard_id: String,
    pub merkle_root: String,
    pub merkle_proof: Vec<merkle::MerkleStep>,
}

#[derive(Debug, Serialize)]
pub struct ActivityFeedResponse {
    pub total: i64,
    pub items: Vec<ActivityItem>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ActivityItem {
    pub id: Option<i64>,
    pub activity_type: String,
    pub timestamp: DateTime<Utc>,
    pub related_commit_id: Option<String>,
    pub details_json: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ActivityQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    pub activity_type: Option<String>,
}
fn default_limit() -> i64 { 50 }

// ── Handlers ───────────────────────────────────────────────────────────────────

pub async fn get_state(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<LedgerStateResponse>> {
    let total_commits: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM doc_commits")
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    let latest_epoch: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT MAX(epoch_timestamp) FROM doc_commits")
            .fetch_one(&state.pool)
            .await
            .unwrap_or(None);

    let shards: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT shard_id FROM doc_commits LIMIT 1000")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();

    Ok(Json(LedgerStateResponse { total_commits, latest_epoch, shards }))
}

pub async fn get_shard(
    State(state): State<Arc<AppState>>,
    Path(shard_id): Path<String>,
) -> ApiResult<Json<ShardStateResponse>> {
    validate_shard_id(&shard_id)?;

    let commit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM doc_commits WHERE shard_id = $1")
            .bind(&shard_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    let recent_commits: Vec<CommitSummary> = sqlx::query_as(
        "SELECT commit_id, doc_hash, epoch_timestamp, merkle_root \
         FROM doc_commits WHERE shard_id = $1 ORDER BY epoch_timestamp DESC LIMIT 10",
    )
    .bind(&shard_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    Ok(Json(ShardStateResponse { shard_id, commit_count, recent_commits }))
}

pub async fn get_proof(
    State(state): State<Arc<AppState>>,
    Path(commit_id): Path<String>,
) -> ApiResult<Json<ProofResponse>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        shard_id: String,
        doc_hash: String,
        merkle_root: Option<String>,
    }

    let row: Option<Row> = sqlx::query_as(
        "SELECT shard_id, doc_hash, merkle_root FROM doc_commits WHERE commit_id = $1",
    )
    .bind(&commit_id)
    .fetch_optional(&state.pool)
    .await?;

    let row = row.ok_or_else(|| ApiError::NotFound(format!("commit {commit_id}")))?;

    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT doc_hash FROM doc_commits \
         WHERE shard_id = $1 ORDER BY epoch_timestamp LIMIT $2",
    )
    .bind(&row.shard_id)
    .bind(MAX_LEAVES_PER_SHARD)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ProofResponse {
        commit_id,
        shard_id: row.shard_id,
        merkle_root: row.merkle_root.unwrap_or_default(),
        merkle_proof: merkle::proof_for(&hashes, &row.doc_hash),
    }))
}

pub async fn get_activity(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ActivityQuery>,
) -> ApiResult<Json<ActivityFeedResponse>> {
    let limit = q.limit.clamp(1, 200);

    let (total, items) = match q.activity_type.as_deref().map(str::to_uppercase) {
        Some(atype) => {
            let total: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM ledger_activities WHERE activity_type = $1",
            )
            .bind(&atype)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

            let items: Vec<ActivityItem> = sqlx::query_as(
                "SELECT id, activity_type, timestamp, related_commit_id, details_json \
                 FROM ledger_activities WHERE activity_type = $1 \
                 ORDER BY timestamp DESC LIMIT $2",
            )
            .bind(&atype)
            .bind(limit)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();

            (total, items)
        }
        None => {
            let total: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM ledger_activities")
                    .fetch_one(&state.pool)
                    .await
                    .unwrap_or(0);

            let items: Vec<ActivityItem> = sqlx::query_as(
                "SELECT id, activity_type, timestamp, related_commit_id, details_json \
                 FROM ledger_activities ORDER BY timestamp DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();

            (total, items)
        }
    };

    Ok(Json(ActivityFeedResponse { total, items }))
}
