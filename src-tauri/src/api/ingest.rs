//! Ingest and hash-verification routes — port of `api/routers/ledger.py` ingest paths.
//!
//! Routes
//! ------
//! POST /ingest/records                          — commit one or more records (JSON, BLAKE3 pre-hashed)
//! GET  /ingest/records/hash/{hash}/verify       — look up a record by content hash
//! GET  /ingest/records/{proof_id}               — fetch full record detail by proof_id
//! POST /ingest/proofs/verify                    — offline proof bundle verification

use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization as _;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;

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

// ── DB row ────────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct IngestRow {
    proof_id: String,
    record_id: String,
    shard_id: String,
    content_hash: String,
    merkle_root: Option<String>,
    ledger_entry_hash: String,
    ts: NaiveDateTime,
    batch_id: Option<String>,
    poseidon_root: Option<String>,
    canonicalization: Option<String>,
}

// ── Request / Response schemas ─────────────────────────────────────────────────

/// Content object sent inside a record.
#[derive(Deserialize)]
pub struct RecordContent {
    pub blake3: String,
    // remaining fields forwarded as-is into content_json
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub struct IngestRecord {
    pub shard_id: Option<String>,
    pub record_type: Option<String>,
    pub record_id: Option<String>,
    pub version: Option<u32>,
    pub content: RecordContent,
}

#[derive(Deserialize)]
pub struct IngestRequest {
    pub records: Vec<IngestRecord>,
}

#[derive(Serialize)]
pub struct CommitResult {
    pub proof_id: String,
    pub content_hash: String,
    pub record_id: String,
    pub shard_id: String,
    pub deduplicated: bool,
}

#[derive(Serialize)]
pub struct IngestResponse {
    pub results: Vec<CommitResult>,
}

/// Response for GET /ingest/records/hash/{hash}/verify and GET /ingest/records/{proof_id}
#[derive(Serialize)]
pub struct RecordProofResponse {
    pub proof_id: String,
    pub record_id: String,
    pub shard_id: String,
    pub content_hash: String,
    pub merkle_root: String,
    pub ledger_entry_hash: String,
    pub timestamp: String,
    pub batch_id: Option<String>,
    pub poseidon_root: Option<String>,
    pub canonicalization: Option<serde_json::Value>,
    pub merkle_proof: serde_json::Value,
    // verify-only field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_proof_valid: Option<bool>,
}

/// POST /ingest/proofs/verify
#[derive(Deserialize)]
pub struct ProofVerifyRequest {
    pub proof_id: Option<String>,
    pub content_hash: String,
    pub merkle_root: String,
    pub merkle_proof: serde_json::Value,
}

#[derive(Serialize)]
pub struct ProofVerifyResponse {
    pub proof_id: Option<String>,
    pub content_hash: String,
    pub merkle_root: String,
    pub content_hash_matches_proof: bool,
    pub merkle_proof_valid: bool,
    pub known_to_server: bool,
    pub poseidon_root: Option<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn sanitize_shard(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-'))
}

fn zero_root() -> String {
    "0000000000000000000000000000000000000000000000000000000000000000".to_owned()
}

fn row_to_proof_response(row: &IngestRow, for_verify: bool) -> RecordProofResponse {
    let canon: Option<serde_json::Value> = row
        .canonicalization
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());

    RecordProofResponse {
        proof_id: row.proof_id.clone(),
        record_id: row.record_id.clone(),
        shard_id: row.shard_id.clone(),
        content_hash: row.content_hash.clone(),
        merkle_root: row.merkle_root.clone().unwrap_or_else(zero_root),
        ledger_entry_hash: row.ledger_entry_hash.clone(),
        timestamp: row.ts.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        batch_id: row.batch_id.clone(),
        poseidon_root: row.poseidon_root.clone(),
        canonicalization: canon,
        merkle_proof: serde_json::json!({}),
        merkle_proof_valid: if for_verify { Some(false) } else { None },
    }
}

// ── Route: POST /ingest/records ───────────────────────────────────────────────

async fn commit_records(
    State(state): State<AppState>,
    _auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<IngestRequest>,
) -> Result<(StatusCode, Json<IngestResponse>), ApiError> {
    if body.records.is_empty() {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "records must be non-empty."));
    }
    if body.records.len() > 100 {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "Maximum 100 records per request."));
    }

    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let mut results = Vec::with_capacity(body.records.len());

    for rec in &body.records {
        let content_hash = rec.content.blake3.trim().to_lowercase();
        if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(err(StatusCode::UNPROCESSABLE_ENTITY,
                "content.blake3 must be a 64-character hex string."));
        }

        let shard_id = rec.shard_id.as_deref().unwrap_or("files");
        if !sanitize_shard(shard_id) {
            return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid shard_id."));
        }
        let record_id = rec.record_id.as_deref().unwrap_or("record");
        let record_type = rec.record_type.as_deref().unwrap_or("file");
        let version = rec.version.unwrap_or(1);

        let proof_id = Uuid::new_v4().to_string();
        let now = naive_utc();

        // Build a stable ledger_entry_hash from the content hash + proof_id.
        let ledger_entry_hash = {
            let mut h = blake3::Hasher::new();
            h.update(b"OLY:LEDGER_ENTRY:V1|");
            h.update(content_hash.as_bytes());
            h.update(b"|");
            h.update(proof_id.as_bytes());
            h.finalize().to_hex().to_string()
        };

        // Canonical JSON: NFC-normalize keys, sort deterministically via BTreeMap.
        let content_json_str = {
            let mut canonical: BTreeMap<String, serde_json::Value> = rec
                .content
                .extra
                .iter()
                .map(|(k, v)| (k.nfc().collect::<String>(), v.clone()))
                .collect();
            canonical.insert("blake3".to_owned(), serde_json::Value::String(content_hash.clone()));
            serde_json::to_string(&canonical).unwrap_or_default()
        };

        // Upsert: on conflict (content_hash) keep existing row — returns existing proof_id.
        #[derive(sqlx::FromRow)]
        struct UpsertResult {
            proof_id: String,
            record_id: String,
            shard_id: String,
            content_hash: String,
            is_new: bool,
        }

        // Use a CTE to detect whether we inserted or hit the conflict.
        let row: UpsertResult = sqlx::query_as::<_, UpsertResult>(
            r#"
            WITH ins AS (
                INSERT INTO ingest_records
                    (proof_id, shard_id, record_type, record_id, version,
                     content_hash, ledger_entry_hash, merkle_root,
                     batch_id, poseidon_root, canonicalization, ts)
                VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, NULL, NULL, $8)
                ON CONFLICT (content_hash) DO NOTHING
                RETURNING proof_id, record_id, shard_id, content_hash, TRUE AS is_new
            )
            SELECT proof_id, record_id, shard_id, content_hash, is_new FROM ins
            UNION ALL
            SELECT proof_id, record_id, shard_id, content_hash, FALSE AS is_new
            FROM ingest_records
            WHERE content_hash = $6
              AND NOT EXISTS (SELECT 1 FROM ins)
            LIMIT 1
            "#,
        )
        .bind(&proof_id)
        .bind(shard_id)
        .bind(record_type)
        .bind(record_id)
        .bind(version as i32)
        .bind(&content_hash)
        .bind(&ledger_entry_hash)
        .bind(now)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            // Table might not exist yet — give a clear error.
            tracing::error!("ingest upsert failed: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR,
                "Ingest failed. Run database migrations first.")
        })?;

        // Store content_json in a separate column if the table has it — best effort.
        let _ = sqlx::query(
            "UPDATE ingest_records SET content_json = $1 WHERE proof_id = $2 AND content_json IS NULL"
        )
        .bind(&content_json_str)
        .bind(&row.proof_id)
        .execute(pool)
        .await;

        results.push(CommitResult {
            proof_id: row.proof_id,
            content_hash: row.content_hash,
            record_id: row.record_id,
            shard_id: row.shard_id,
            deduplicated: !row.is_new,
        });
    }

    let status = if results.iter().all(|r| r.deduplicated) {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    Ok((status, Json(IngestResponse { results })))
}

// ── Route: GET /ingest/records/hash/{hash}/verify ─────────────────────────────

async fn verify_by_hash(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(hash): Path<String>,
) -> Result<Json<RecordProofResponse>, ApiError> {
    let hash = hash.trim().to_lowercase();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY,
            "Hash must be a 64-character hex string."));
    }

    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let row = sqlx::query_as::<_, IngestRow>(
        "SELECT proof_id, record_id, shard_id, content_hash, merkle_root,
                ledger_entry_hash, ts, batch_id, poseidon_root, canonicalization
         FROM ingest_records
         WHERE content_hash = $1
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

async fn get_record(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(proof_id): Path<String>,
) -> Result<Json<RecordProofResponse>, ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let row = sqlx::query_as::<_, IngestRow>(
        "SELECT proof_id, record_id, shard_id, content_hash, merkle_root,
                ledger_entry_hash, ts, batch_id, poseidon_root, canonicalization
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

// ── Route: POST /ingest/proofs/verify ────────────────────────────────────────

async fn verify_proof_bundle(
    State(state): State<AppState>,
    _rl: RateLimit,
    Json(body): Json<ProofVerifyRequest>,
) -> Result<Json<ProofVerifyResponse>, ApiError> {
    let content_hash = body.content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    // Check if the hash is known to us.
    let known = if let Some(pool) = &state.pool {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM ingest_records WHERE content_hash = $1",
        )
        .bind(&content_hash)
        .fetch_one(pool)
        .await
        .unwrap_or(0)
            > 0
    } else {
        false
    };

    // Verify leaf_hash is consistent with content_hash: BLAKE3("OLY:LEAF:V1|" + content_hash).
    // Full SMT path verification requires tree state and is not performed here.
    let expected_leaf = {
        let mut h = blake3::Hasher::new();
        h.update(b"OLY:LEAF:V1");
        h.update(b"|");
        h.update(content_hash.as_bytes());
        h.finalize().to_hex().to_string()
    };
    let content_hash_matches_proof = body
        .merkle_proof
        .as_object()
        .and_then(|o| o.get("leaf_hash"))
        .and_then(|v| v.as_str())
        .map(|leaf| leaf == expected_leaf)
        .unwrap_or(false);

    Ok(Json(ProofVerifyResponse {
        proof_id: body.proof_id,
        content_hash,
        merkle_root: body.merkle_root,
        content_hash_matches_proof,
        merkle_proof_valid: false, // full SMT verification requires tree state
        known_to_server: known,
        poseidon_root: None,
    }))
}

// ── Route: POST /ingest/files ─────────────────────────────────────────────────
//
// Multipart file upload. content_hash = plain BLAKE3 of raw file bytes —
// identical to what the in-browser hasher computes, so the same file always
// produces the same hash and round-trip verifies.

const FILE_MAX_BYTES: usize = 100 * 1024 * 1024; // 100 MB

async fn ingest_file(
    State(state): State<AppState>,
    _auth: AuthenticatedKey,
    _rl: RateLimit,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<CommitResult>), ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut shard_id = "files".to_owned();
    let mut record_id_opt: Option<String> = None;
    let mut version: i32 = 1;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        err(StatusCode::BAD_REQUEST, &format!("Multipart read error: {e}"))
    })? {
        let name = field.name().unwrap_or("").to_owned();
        match name.as_str() {
            "file" => {
                let bytes = field.bytes().await.map_err(|e| {
                    err(StatusCode::BAD_REQUEST, &format!("File read error: {e}"))
                })?;
                if bytes.len() > FILE_MAX_BYTES {
                    return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "File exceeds 100 MB limit."));
                }
                file_bytes = Some(bytes.to_vec());
            }
            "shard_id" => {
                let text = field.text().await.unwrap_or_default();
                if !text.is_empty() { shard_id = text; }
            }
            "record_id" => {
                let text = field.text().await.unwrap_or_default();
                if !text.is_empty() { record_id_opt = Some(text); }
            }
            "version" => {
                let text = field.text().await.unwrap_or_default();
                version = text.parse().unwrap_or(1);
            }
            _ => { let _ = field.bytes().await; } // discard unknown fields
        }
    }

    let bytes = file_bytes.ok_or_else(|| err(StatusCode::UNPROCESSABLE_ENTITY, "Missing 'file' field."))?;
    if !sanitize_shard(&shard_id) {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid shard_id."));
    }

    // Plain BLAKE3 of raw bytes — no domain prefix, matching the browser hasher.
    let content_hash = blake3::hash(&bytes).to_hex().to_string();
    let record_id = record_id_opt.unwrap_or_else(|| "record".to_owned());
    let proof_id = Uuid::new_v4().to_string();
    let now = naive_utc();

    let ledger_entry_hash = {
        let mut h = blake3::Hasher::new();
        h.update(b"OLY:LEDGER_ENTRY:V1|");
        h.update(content_hash.as_bytes());
        h.update(b"|");
        h.update(proof_id.as_bytes());
        h.finalize().to_hex().to_string()
    };

    #[derive(sqlx::FromRow)]
    struct UpsertResult {
        proof_id: String,
        record_id: String,
        shard_id: String,
        content_hash: String,
        is_new: bool,
    }

    let row: UpsertResult = sqlx::query_as::<_, UpsertResult>(
        r#"
        WITH ins AS (
            INSERT INTO ingest_records
                (proof_id, shard_id, record_type, record_id, version,
                 content_hash, ledger_entry_hash, merkle_root,
                 batch_id, poseidon_root, canonicalization, ts)
            VALUES ($1, $2, 'file', $3, $4, $5, $6, NULL, NULL, NULL, NULL, $7)
            ON CONFLICT (content_hash) DO NOTHING
            RETURNING proof_id, record_id, shard_id, content_hash, TRUE AS is_new
        )
        SELECT proof_id, record_id, shard_id, content_hash, is_new FROM ins
        UNION ALL
        SELECT proof_id, record_id, shard_id, content_hash, FALSE AS is_new
        FROM ingest_records
        WHERE content_hash = $5
          AND NOT EXISTS (SELECT 1 FROM ins)
        LIMIT 1
        "#,
    )
    .bind(&proof_id)
    .bind(&shard_id)
    .bind(&record_id)
    .bind(version)
    .bind(&content_hash)
    .bind(&ledger_entry_hash)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("ingest_file upsert failed: {e}");
        err(StatusCode::INTERNAL_SERVER_ERROR, "Ingest failed. Run database migrations first.")
    })?;

    let status = if row.is_new { StatusCode::CREATED } else { StatusCode::OK };
    Ok((status, Json(CommitResult {
        proof_id: row.proof_id,
        content_hash: row.content_hash,
        record_id: row.record_id,
        shard_id: row.shard_id,
        deduplicated: !row.is_new,
    })))
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ingest/files", post(ingest_file))
        .route("/ingest/records", post(commit_records))
        // The hash route MUST be registered before the /{proof_id} catch-all.
        .route("/ingest/records/hash/{hash}/verify", get(verify_by_hash))
        .route("/ingest/records/{proof_id}", get(get_record))
        .route("/ingest/proofs/verify", post(verify_proof_bundle))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_shard_accepts_valid() {
        assert!(sanitize_shard("files"));
        assert!(sanitize_shard("shard-1"));
        assert!(sanitize_shard("0x4F3A"));
        assert!(sanitize_shard("us:east.1"));
    }

    #[test]
    fn sanitize_shard_rejects_invalid() {
        assert!(!sanitize_shard(""));
        assert!(!sanitize_shard("has space"));
        assert!(!sanitize_shard("../escape"));
        assert!(!sanitize_shard(&"x".repeat(129)));
    }

    #[test]
    fn zero_root_is_64_hex_zeros() {
        let r = zero_root();
        assert_eq!(r.len(), 64);
        assert!(r.chars().all(|c| c == '0'));
    }
}
