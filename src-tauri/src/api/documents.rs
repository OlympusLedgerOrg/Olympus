use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::AuthedKey;
use super::error::{ApiError, ApiResult};
use super::merkle;
use super::state::AppState;
use super::validation::{validate_doc_hash, validate_shard_id_str, MAX_LEAVES_PER_SHARD};

// ── Request / response types ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DocCommitRequest {
    pub doc_hash: String,
    pub request_id: Option<String>,
    pub embargo_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub is_multi_recipient: bool,
    pub shard_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DocCommitResponse {
    pub commit_id: String,
    pub doc_hash: String,
    pub epoch: DateTime<Utc>,
    pub shard_id: String,
    pub merkle_root: String,
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct DocVerifyRequest {
    pub commit_id: Option<String>,
    pub doc_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DocVerifyResponse {
    pub verified: bool,
    pub commit: Option<DocCommitResponse>,
    pub merkle_proof: Option<Vec<merkle::MerkleStep>>,
}

// ── DB row ────────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct CommitRow {
    commit_id: String,
    doc_hash: String,
    epoch_timestamp: DateTime<Utc>,
    shard_id: String,
    merkle_root: Option<String>,
    embargo_until: Option<DateTime<Utc>>,
}

impl CommitRow {
    fn into_response(self) -> DocCommitResponse {
        DocCommitResponse {
            commit_id: self.commit_id,
            doc_hash: self.doc_hash,
            epoch: self.epoch_timestamp,
            shard_id: self.shard_id,
            merkle_root: self.merkle_root.unwrap_or_default(),
            kind: "client_asserted_hash".into(),
        }
    }
}

// ── Handlers ───────────────────────────────────────────────────────────────────

pub async fn commit_doc(
    State(state): State<Arc<AppState>>,
    authed: AuthedKey,
    Json(req): Json<DocCommitRequest>,
) -> ApiResult<impl IntoResponse> {
    authed.require_scope("commit")?;
    validate_doc_hash(&req.doc_hash)?;

    let shard_id = req
        .shard_id
        .as_deref()
        .map(validate_shard_id_str)
        .transpose()?
        .unwrap_or_else(|| state.config.default_shard_id.clone());

    // Idempotency: 409 if doc_hash already committed.
    if let Some(existing) = find_by_hash(&state, &req.doc_hash).await? {
        check_embargo(&existing)?;
        return Ok((StatusCode::CONFLICT, Json(existing.into_response())).into_response());
    }

    let row_id = Uuid::new_v4().to_string();
    let commit_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO doc_commits \
         (id, commit_id, doc_hash, epoch_timestamp, shard_id, merkle_root, embargo_until, is_multi_recipient) \
         VALUES ($1, $2, $3, $4, $5, '', $6, $7)",
    )
    .bind(&row_id)
    .bind(&commit_id)
    .bind(&req.doc_hash)
    .bind(now)
    .bind(&shard_id)
    .bind(req.embargo_until)
    .bind(req.is_multi_recipient)
    .execute(&state.pool)
    .await?;

    let merkle_root = compute_shard_root(&state, &shard_id).await?;

    sqlx::query("UPDATE doc_commits SET merkle_root = $1 WHERE commit_id = $2")
        .bind(&merkle_root)
        .bind(&commit_id)
        .execute(&state.pool)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(DocCommitResponse {
            commit_id,
            doc_hash: req.doc_hash,
            epoch: now,
            shard_id,
            merkle_root,
            kind: "client_asserted_hash".into(),
        }),
    )
        .into_response())
}

pub async fn verify_doc(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DocVerifyRequest>,
) -> ApiResult<Json<DocVerifyResponse>> {
    if req.commit_id.is_none() && req.doc_hash.is_none() {
        return Err(ApiError::BadRequest(
            "commit_id or doc_hash required".into(),
        ));
    }

    let row = if let Some(ref cid) = req.commit_id {
        find_by_commit_id(&state, cid).await?
    } else {
        find_by_hash(&state, req.doc_hash.as_deref().unwrap()).await?
    };

    let Some(row) = row else {
        return Ok(Json(DocVerifyResponse {
            verified: false,
            commit: None,
            merkle_proof: None,
        }));
    };

    check_embargo(&row)?;

    let hashes = shard_hashes(&state, &row.shard_id).await?;
    let proof = merkle::proof_for(&hashes, &row.doc_hash);
    let commit = row.into_response();

    Ok(Json(DocVerifyResponse {
        verified: true,
        commit: Some(commit),
        merkle_proof: Some(proof),
    }))
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn check_embargo(row: &CommitRow) -> ApiResult<()> {
    if let Some(until) = row.embargo_until {
        if until > Utc::now() {
            return Err(ApiError::Forbidden(format!(
                "Document under embargo until {until}"
            )));
        }
    }
    Ok(())
}

async fn find_by_commit_id(state: &AppState, cid: &str) -> ApiResult<Option<CommitRow>> {
    Ok(
        sqlx::query_as("SELECT commit_id, doc_hash, epoch_timestamp, shard_id, merkle_root, embargo_until \
                         FROM doc_commits WHERE commit_id = $1")
            .bind(cid)
            .fetch_optional(&state.pool)
            .await?,
    )
}

async fn find_by_hash(state: &AppState, doc_hash: &str) -> ApiResult<Option<CommitRow>> {
    Ok(
        sqlx::query_as("SELECT commit_id, doc_hash, epoch_timestamp, shard_id, merkle_root, embargo_until \
                         FROM doc_commits WHERE doc_hash = $1 LIMIT 1")
            .bind(doc_hash)
            .fetch_optional(&state.pool)
            .await?,
    )
}

async fn shard_hashes(state: &AppState, shard_id: &str) -> ApiResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT doc_hash FROM doc_commits \
         WHERE shard_id = $1 ORDER BY epoch_timestamp LIMIT $2",
    )
    .bind(shard_id)
    .bind(MAX_LEAVES_PER_SHARD)
    .fetch_all(&state.pool)
    .await?)
}

async fn compute_shard_root(state: &AppState, shard_id: &str) -> ApiResult<String> {
    let hashes = shard_hashes(state, shard_id).await?;
    Ok(merkle::root(&hashes))
}
