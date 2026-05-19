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
//! `POST /ledger/ingest/simple` requires a valid API key (any scope).
//! `POST /ledger/verify/simple` is public (rate-limited only).

use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_SHARD: &str = "0x4F3A";

/// Multipart file-upload size limit (50 MiB) — matches Python `max_upload_bytes`.
const MAX_UPLOAD_BYTES: usize = 50 * 1024 * 1024;

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

// ── DB row types ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct DocCommitRow {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    request_id: Option<String>,
    doc_hash: String,
    commit_id: String,
    epoch_timestamp: NaiveDateTime,
    shard_id: String,
    merkle_root: Option<String>,
    #[allow(dead_code)]
    zk_proof: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ActivityRow {
    id: String,
    timestamp: chrono::DateTime<Utc>,
    activity_type: String,
    title: String,
    description: String,
    related_commit_id: Option<String>,
    request_id: Option<String>,
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

// ── Helper: shard state root ──────────────────────────────────────────────────

/// Return the merkle_root of the most recent commit in `shard_id`, or ZERO_ROOT.
async fn shard_state_root(
    pool: &sqlx::PgPool,
    shard_id: &str,
) -> Result<String, ApiError> {
    let root: Option<Option<String>> = sqlx::query_scalar(
        "SELECT merkle_root FROM doc_commits
         WHERE shard_id = $1
         ORDER BY epoch_timestamp DESC
         LIMIT 1",
    )
    .bind(shard_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    Ok(root
        .flatten()
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| ZERO_ROOT.to_owned()))
}

// ── Route: GET /ledger/state ──────────────────────────────────────────────────

async fn get_ledger_state(
    State(state): State<AppState>,
    _rl: RateLimit,
) -> Result<Json<LedgerStateResponse>, ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let total_commits: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM doc_commits")
            .fetch_one(pool)
            .await
            .map_err(db_err)?;

    let last_epoch: Option<NaiveDateTime> =
        sqlx::query_scalar("SELECT MAX(epoch_timestamp) FROM doc_commits")
            .fetch_one(pool)
            .await
            .map_err(db_err)?;

    let shard_ids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT shard_id FROM doc_commits ORDER BY shard_id LIMIT 1000",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let shard_ids = if shard_ids.is_empty() {
        vec![DEFAULT_SHARD.to_owned()]
    } else {
        shard_ids
    };

    let mut shard_roots = Vec::with_capacity(shard_ids.len());
    for sid in &shard_ids {
        shard_roots.push(shard_state_root(pool, sid).await?);
    }

    let global_root = if shard_roots.len() == 1 {
        shard_roots[0].clone()
    } else {
        // BLAKE3 over domain tag + raw shard root bytes (lexicographic order preserved above).
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"GLOBAL_ROOT");
        for r in &shard_roots {
            if let Ok(bytes) = hex::decode(r) {
                hasher.update(&bytes);
            } else {
                hasher.update(r.as_bytes());
            }
        }
        hasher.finalize().to_hex().to_string()
    };

    Ok(Json(LedgerStateResponse {
        global_state_root: global_root,
        shard_count: shard_ids.len(),
        total_commits,
        last_epoch: last_epoch.map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string()),
    }))
}

// ── Route: GET /ledger/shard/{shard_id} ──────────────────────────────────────

async fn get_shard_state(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(shard_id): Path<String>,
) -> Result<Json<ShardStateResponse>, ApiError> {
    if !valid_shard_id(&shard_id) {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid shard_id."));
    }

    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let commit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM doc_commits WHERE shard_id = $1",
    )
    .bind(&shard_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    let commits = sqlx::query_as::<_, DocCommitRow>(
        "SELECT id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id,
                merkle_root, zk_proof
         FROM doc_commits
         WHERE shard_id = $1
         ORDER BY epoch_timestamp DESC
         LIMIT 10",
    )
    .bind(&shard_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let state_root = shard_state_root(pool, &shard_id).await?;

    Ok(Json(ShardStateResponse {
        shard_id,
        state_root,
        commit_count,
        latest_commits: commits.iter().map(commit_summary).collect(),
    }))
}

fn commit_summary(row: &DocCommitRow) -> CommitSummary {
    CommitSummary {
        commit_id: row.commit_id.clone(),
        doc_hash: row.doc_hash.clone(),
        epoch: row.epoch_timestamp.format("%Y-%m-%dT%H:%M:%S").to_string(),
        shard_id: row.shard_id.clone(),
        merkle_root: row.merkle_root.clone(),
    }
}

// ── Route: GET /ledger/proof/{commit_id} ─────────────────────────────────────

async fn get_commit_proof(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(commit_id): Path<String>,
) -> Result<(StatusCode, Json<ProofResponse>), ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let commit = sqlx::query_as::<_, DocCommitRow>(
        "SELECT id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id,
                merkle_root, zk_proof
         FROM doc_commits
         WHERE commit_id = $1",
    )
    .bind(&commit_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Commit not found."))?;

    Ok((
        StatusCode::ACCEPTED,
        Json(ProofResponse {
            commit_id: commit.commit_id,
            shard_id: commit.shard_id,
            epoch: commit.epoch_timestamp.format("%Y-%m-%dT%H:%M:%S").to_string(),
            status: "pending",
            reason: "ZK proof generation pending Groth16 trusted setup ceremony. \
                     This record is anchored in the Merkle ledger but the ZK proof \
                     is not yet available.",
            merkle_root: commit.merkle_root,
            merkle_proof: vec![],
        }),
    ))
}

// ── Route: GET /ledger/activity ───────────────────────────────────────────────

async fn get_ledger_activity(
    State(state): State<AppState>,
    _rl: RateLimit,
    Query(params): Query<ActivityQuery>,
) -> Result<Json<ActivityFeedResponse>, ApiError> {
    let limit = params.limit.clamp(1, 200) as i64;
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let (rows, total) = if let Some(ref activity_type) = params.activity_type {
        let upper = activity_type.to_uppercase();
        let rows = sqlx::query_as::<_, ActivityRow>(
            "SELECT id, timestamp, activity_type, title, description,
                    related_commit_id, request_id
             FROM ledger_activities
             WHERE activity_type = $1
             ORDER BY timestamp DESC
             LIMIT $2",
        )
        .bind(&upper)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ledger_activities WHERE activity_type = $1",
        )
        .bind(&upper)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

        (rows, total)
    } else {
        let rows = sqlx::query_as::<_, ActivityRow>(
            "SELECT id, timestamp, activity_type, title, description,
                    related_commit_id, request_id
             FROM ledger_activities
             ORDER BY timestamp DESC
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ledger_activities")
                .fetch_one(pool)
                .await
                .map_err(db_err)?;

        (rows, total)
    };

    let items = rows
        .into_iter()
        .map(|r| ActivityItem {
            id: r.id,
            timestamp: r.timestamp.format("%Y-%m-%dT%H:%M:%S").to_string(),
            activity_type: r.activity_type,
            title: r.title,
            description: r.description,
            related_commit_id: r.related_commit_id,
            related_request_id: r.request_id,
        })
        .collect();

    Ok(Json(ActivityFeedResponse { items, total }))
}

// ── Route: POST /ledger/ingest/simple ────────────────────────────────────────

async fn simple_document_ingest(
    State(state): State<AppState>,
    _auth: AuthenticatedKey,
    _rl: RateLimit,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<SimpleIngestionResponse>), ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut filename = String::from("upload");
    let mut request_id: Option<String> = None;
    let mut description: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        err(StatusCode::BAD_REQUEST, &format!("Multipart error: {e}"))
    })? {
        match field.name() {
            Some("file") => {
                if let Some(n) = field.file_name() {
                    filename = n.to_owned();
                }
                let bytes = field.bytes().await.map_err(|e| {
                    err(StatusCode::BAD_REQUEST, &format!("Read error: {e}"))
                })?;
                if bytes.len() > MAX_UPLOAD_BYTES {
                    return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "File exceeds 50 MiB."));
                }
                file_bytes = Some(bytes.to_vec());
            }
            Some("request_id") => {
                request_id = Some(
                    field.text().await.map_err(|e| {
                        err(StatusCode::BAD_REQUEST, &format!("Read error: {e}"))
                    })?,
                );
            }
            Some("description") => {
                description = Some(
                    field.text().await.map_err(|e| {
                        err(StatusCode::BAD_REQUEST, &format!("Read error: {e}"))
                    })?,
                );
            }
            _ => {}
        }
    }

    let file_bytes = file_bytes.ok_or_else(|| {
        err(StatusCode::UNPROCESSABLE_ENTITY, "No file field in request.")
    })?;

    let mut steps: Vec<IngestionStep> = Vec::new();

    steps.push(IngestionStep {
        step: 1,
        label: "File received".to_owned(),
        status: "ok",
        detail: format!("Received {} ({} bytes)", filename, file_bytes.len()),
    });

    // BLAKE3 hash the file.
    let doc_hash = blake3::hash(&file_bytes).to_hex().to_string();

    steps.push(IngestionStep {
        step: 2,
        label: "Fingerprint computed".to_owned(),
        status: "ok",
        detail: format!("BLAKE3: {doc_hash}"),
    });

    // Atomically insert or return the existing row — eliminates the TOCTOU race
    // that a SELECT-then-INSERT would have under concurrent ingestion of the same
    // document fingerprint.
    let commit_row_id = Uuid::new_v4().to_string();
    let commit_id = format!("0x{}", hex::encode(Uuid::new_v4().as_bytes()));
    let now = naive_utc();

    let upsert_row = sqlx::query_as::<_, DocCommitRow>(
        r#"INSERT INTO doc_commits
               (id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id,
                merkle_root, zk_proof, is_multi_recipient)
           VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, FALSE)
           ON CONFLICT (doc_hash)
               DO UPDATE SET doc_hash = doc_commits.doc_hash
           RETURNING id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id,
                     merkle_root, zk_proof"#,
    )
    .bind(&commit_row_id)
    .bind(request_id.as_deref())
    .bind(&doc_hash)
    .bind(&commit_id)
    .bind(now)
    .bind(DEFAULT_SHARD)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    // If the returned commit_id differs from what we generated, it's a pre-existing record.
    let is_duplicate = upsert_row.commit_id != commit_id;

    if is_duplicate {
        steps.push(IngestionStep {
            step: 3,
            label: "Duplicate detected".to_owned(),
            status: "ok",
            detail: format!("Already recorded as commit {}", upsert_row.commit_id),
        });
        return Ok((
            StatusCode::OK,
            Json(SimpleIngestionResponse {
                status: "exists",
                commit_id: upsert_row.commit_id,
                doc_hash: upsert_row.doc_hash,
                shard_id: upsert_row.shard_id,
                epoch: upsert_row.epoch_timestamp.format("%Y-%m-%dT%H:%M:%S").to_string(),
                message: "Document already recorded in the ledger.".to_owned(),
                steps,
            }),
        ));
    }

    steps.push(IngestionStep {
        step: 3,
        label: "Recorded in ledger".to_owned(),
        status: "ok",
        detail: format!("Commit ID: {}", upsert_row.commit_id),
    });

    // Insert ledger_activity.
    let activity_id = Uuid::new_v4().to_string();
    let desc = description.as_deref().unwrap_or(&filename);
    sqlx::query(
        "INSERT INTO ledger_activities
             (id, timestamp, activity_type, title, description, related_commit_id, request_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&activity_id)
    .bind(Utc::now())
    .bind("DOCUMENT_SUBMITTED")
    .bind("Document Recorded")
    .bind(format!("Document '{desc}' recorded with fingerprint {doc_hash}"))
    .bind(&upsert_row.commit_id)
    .bind(request_id.as_deref())
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::warn!("failed to insert ledger_activity: {e}");
        db_err(e)
    })?;

    steps.push(IngestionStep {
        step: 4,
        label: "Activity logged".to_owned(),
        status: "ok",
        detail: "Ledger activity recorded.".to_owned(),
    });

    Ok((
        StatusCode::CREATED,
        Json(SimpleIngestionResponse {
            status: "success",
            commit_id: upsert_row.commit_id,
            doc_hash: upsert_row.doc_hash,
            shard_id: DEFAULT_SHARD.to_owned(),
            epoch: now.format("%Y-%m-%dT%H:%M:%S").to_string(),
            message: "Document recorded successfully in the ledger.".to_owned(),
            steps,
        }),
    ))
}

// ── Route: POST /ledger/verify/simple ────────────────────────────────────────

async fn simple_document_verify(
    State(state): State<AppState>,
    _rl: RateLimit,
    mut multipart: Multipart,
) -> Result<Json<SimpleVerificationResponse>, ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut commit_id_param: Option<String> = None;
    let mut doc_hash_param: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        err(StatusCode::BAD_REQUEST, &format!("Multipart error: {e}"))
    })? {
        match field.name() {
            Some("file") => {
                let bytes = field.bytes().await.map_err(|e| {
                    err(StatusCode::BAD_REQUEST, &format!("Read error: {e}"))
                })?;
                if bytes.len() > MAX_UPLOAD_BYTES {
                    return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "File exceeds 50 MiB."));
                }
                file_bytes = Some(bytes.to_vec());
            }
            Some("commit_id") => {
                commit_id_param =
                    Some(field.text().await.map_err(|e| {
                        err(StatusCode::BAD_REQUEST, &format!("Read error: {e}"))
                    })?);
            }
            Some("doc_hash") => {
                doc_hash_param =
                    Some(field.text().await.map_err(|e| {
                        err(StatusCode::BAD_REQUEST, &format!("Read error: {e}"))
                    })?);
            }
            _ => {}
        }
    }

    let row: Option<DocCommitRow> = if let Some(bytes) = file_bytes {
        let doc_hash = blake3::hash(&bytes).to_hex().to_string();
        sqlx::query_as::<_, DocCommitRow>(
            "SELECT id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id,
                    merkle_root, zk_proof
             FROM doc_commits WHERE doc_hash = $1 LIMIT 1",
        )
        .bind(&doc_hash)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?
    } else if let Some(cid) = &commit_id_param {
        sqlx::query_as::<_, DocCommitRow>(
            "SELECT id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id,
                    merkle_root, zk_proof
             FROM doc_commits WHERE commit_id = $1 LIMIT 1",
        )
        .bind(cid)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?
    } else if let Some(dh) = &doc_hash_param {
        sqlx::query_as::<_, DocCommitRow>(
            "SELECT id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id,
                    merkle_root, zk_proof
             FROM doc_commits WHERE doc_hash = $1 LIMIT 1",
        )
        .bind(dh)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?
    } else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Please provide one of: a file to upload, a commit_id, or a doc_hash.",
        ));
    };

    Ok(Json(match row {
        Some(r) => SimpleVerificationResponse {
            verified: true,
            commit_id: Some(r.commit_id),
            doc_hash: Some(r.doc_hash),
            epoch: Some(r.epoch_timestamp.format("%Y-%m-%dT%H:%M:%S").to_string()),
            shard_id: Some(r.shard_id),
            merkle_root: r.merkle_root,
            message: "Document verified — this record exists in the ledger.".to_owned(),
        },
        None => SimpleVerificationResponse {
            verified: false,
            commit_id: None,
            doc_hash: None,
            epoch: None,
            shard_id: None,
            merkle_root: None,
            message: "Document not found in the ledger.".to_owned(),
        },
    }))
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
        let q = ActivityQuery { limit: 500, activity_type: None };
        assert_eq!(q.limit.clamp(1, 200), 200);
    }
}
