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
use crate::zk::chunk::{chunk_tree_from_bytes, fr_to_hex};
use crate::zk::snapshot::{snapshot_new_record, LedgerSnapshot};

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
    record_type: String,
    content_hash: String,
    merkle_root: Option<String>,
    ledger_entry_hash: String,
    ts: NaiveDateTime,
    batch_id: Option<String>,
    poseidon_root: Option<String>,
    canonicalization: Option<String>,
    merkle_proof_json: Option<String>,
    original_hash: Option<String>,
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
    pub record_type: String,
    pub content_hash: String,
    pub merkle_root: String,
    pub ledger_entry_hash: String,
    pub timestamp: String,
    pub batch_id: Option<String>,
    pub poseidon_root: Option<String>,
    pub canonicalization: Option<serde_json::Value>,
    pub merkle_proof: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_proof_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_hash: Option<String>,
    pub is_redacted: bool,
}

/// POST /ingest/proofs/verify
///
/// The legacy binary Merkle proof bundle (removed with the binary tree itself)
/// is no longer required in the request — clients only need to supply the
/// `content_hash` they want a snapshot decision for. `proof_id`,
/// `merkle_root`, and `merkle_proof` are accepted for backwards compatibility
/// and ignored.
#[derive(Deserialize)]
pub struct ProofVerifyRequest {
    pub proof_id: Option<String>,
    pub content_hash: String,
    #[serde(default)]
    pub merkle_root: Option<String>,
    #[serde(default)]
    pub merkle_proof: Option<serde_json::Value>,
}

/// Snapshot-verification outcome. Explicit enum so a client never has to
/// disambiguate "the snapshot proves nothing" (pending / unknown) from "the
/// snapshot is actively invalid" (tampered / wrong key) — the legacy flat
/// `merkle_proof_valid: false` conflated the two.
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotVerifyStatus {
    /// Record has a snapshot, the path reconstructs `snapshot_root`, and the
    /// authority's Ed25519 signature over the canonical payload is valid.
    Verified,
    /// Record exists but has no Poseidon snapshot yet (JSON-record commits
    /// today have no chunkable bytes, and file commits where the snapshot
    /// build failed leave the columns NULL). The hash IS in the ledger; the
    /// inclusion witness just isn't anchored yet. NOT a rejection.
    Pending,
    /// Snapshot columns are present but `verify_snapshot` rejected: the
    /// reconstructed root didn't match, the signature didn't verify under
    /// the authority pubkey, or a field was malformed. This is the only
    /// state a client should treat as "the server is contradicting itself".
    Invalid,
    /// `content_hash` is not in the ledger at all.
    Unknown,
}

#[derive(Serialize)]
pub struct ProofVerifyResponse {
    pub proof_id: Option<String>,
    pub content_hash: String,
    /// Authoritative state — see [`SnapshotVerifyStatus`].
    pub status: SnapshotVerifyStatus,
    /// Human-readable explanation for the status (UI display).
    pub detail: String,
    /// True iff a record with this `content_hash` exists in the ledger.
    pub known_to_server: bool,
    /// Snapshot fields, when present. All `None` for `pending`/`unknown`.
    pub snapshot_root: Option<String>,
    pub snapshot_index: Option<u64>,
    pub snapshot_size: Option<u64>,
    /// Legacy compatibility:
    /// - `Some(true)`  → verified
    /// - `Some(false)` → invalid (server-stored snapshot fails verification)
    /// - `None`        → pending / unknown (NOT a rejection)
    ///
    /// New clients should read `status` instead.
    pub merkle_proof_valid: Option<bool>,
    /// Legacy mirror of `snapshot_root` (binary Merkle root is retired).
    pub merkle_root: String,
    /// Legacy alias for `snapshot_root`.
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

fn row_to_proof_response(row: &IngestRow, _for_verify: bool) -> RecordProofResponse {
    let canon: Option<serde_json::Value> = row
        .canonicalization
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());

    let proof_val: serde_json::Value = row
        .merkle_proof_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::json!({}));

    let root = row.merkle_root.clone().unwrap_or_else(zero_root);

    let is_redacted = row.record_type == "redaction" || row.original_hash.is_some();

    RecordProofResponse {
        proof_id: row.proof_id.clone(),
        record_id: row.record_id.clone(),
        shard_id: row.shard_id.clone(),
        record_type: row.record_type.clone(),
        content_hash: row.content_hash.clone(),
        merkle_root: root,
        ledger_entry_hash: row.ledger_entry_hash.clone(),
        timestamp: row.ts.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        batch_id: row.batch_id.clone(),
        poseidon_root: row.poseidon_root.clone(),
        canonicalization: canon,
        merkle_proof: proof_val,
        // Binary Merkle proofs were removed; authoritative inclusion is now the
        // signed Poseidon ledger snapshot (zk::snapshot).
        merkle_proof_valid: None,
        original_hash: row.original_hash.clone(),
        is_redacted,
    }
}

// ── Route: POST /ingest/records ───────────────────────────────────────────────

async fn commit_records(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<IngestRequest>,
) -> Result<(StatusCode, Json<IngestResponse>), ApiError> {
    if !auth.has_scope("write") && !auth.has_scope("ingest") && !auth.has_scope("admin") {
        return Err(err(StatusCode::FORBIDDEN, "API key lacks required scope (write, ingest, or admin)."));
    }
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
        "SELECT proof_id, record_id, shard_id, record_type, content_hash, merkle_root,
                ledger_entry_hash, ts, batch_id, poseidon_root, canonicalization, merkle_proof_json, original_hash
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
        "SELECT proof_id, record_id, shard_id, record_type, content_hash, merkle_root,
                ledger_entry_hash, ts, batch_id, poseidon_root, canonicalization, merkle_proof_json, original_hash
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
    use olympus_crypto::ledger_snapshot::{verify_snapshot, LedgerSnapshot as CryptoSnapshot};

    let content_hash = body.content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    // Pull the row + every snapshot column in one go. NULL snapshot columns
    // mean the record exists but the inclusion witness hasn't been built
    // (JSON-record commits today, or a file commit where snapshot generation
    // soft-failed). That's `Pending`, NOT `Invalid`.
    #[derive(sqlx::FromRow)]
    struct Row {
        proof_id: String,
        record_type: String,
        original_root: Option<String>,
        snapshot_root: Option<String>,
        snapshot_index: Option<i64>,
        snapshot_size: Option<i64>,
        snapshot_path: Option<serde_json::Value>,
        snapshot_sig: Option<String>,
    }
    let row_opt: Option<Row> = sqlx::query_as::<_, Row>(
        "SELECT proof_id, record_type, original_root, snapshot_root, snapshot_index, \
                snapshot_size, snapshot_path, snapshot_sig \
         FROM ingest_records WHERE content_hash = $1 LIMIT 1",
    )
    .bind(&content_hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    // Helper to assemble a response — keeps the legacy fields populated from
    // the new authoritative ones so existing clients don't 500.
    fn build(
        body_proof_id: Option<String>,
        row_proof_id: Option<String>,
        content_hash: String,
        status: SnapshotVerifyStatus,
        detail: &str,
        snapshot_root: Option<String>,
        snapshot_index: Option<u64>,
        snapshot_size: Option<u64>,
    ) -> ProofVerifyResponse {
        let merkle_proof_valid = match status {
            SnapshotVerifyStatus::Verified => Some(true),
            SnapshotVerifyStatus::Invalid => Some(false),
            SnapshotVerifyStatus::Pending | SnapshotVerifyStatus::Unknown => None,
        };
        let known_to_server = row_proof_id.is_some();
        let merkle_root = snapshot_root.clone().unwrap_or_else(zero_root);
        ProofVerifyResponse {
            proof_id: body_proof_id.or(row_proof_id),
            content_hash,
            status,
            detail: detail.to_owned(),
            known_to_server,
            snapshot_root: snapshot_root.clone(),
            snapshot_index,
            snapshot_size,
            merkle_proof_valid,
            merkle_root,
            poseidon_root: snapshot_root,
        }
    }

    let row = match row_opt {
        Some(r) => r,
        None => {
            return Ok(Json(build(
                body.proof_id,
                None,
                content_hash,
                SnapshotVerifyStatus::Unknown,
                "content_hash is not present in the ledger.",
                None,
                None,
                None,
            )));
        }
    };

    // Snapshot columns are all-or-nothing — if any required field is NULL we
    // can't verify, but the record IS known. Surface `pending` with a reason
    // that distinguishes JSON-record commits (no chunkable bytes) from the
    // legacy-file / soft-failed cases.
    let (original_root, snapshot_root_str, snapshot_index_i, snapshot_size_i,
         snapshot_path_json, snapshot_sig_hex) =
        match (
            row.original_root.as_deref(),
            row.snapshot_root.as_deref(),
            row.snapshot_index,
            row.snapshot_size,
            row.snapshot_path.as_ref(),
            row.snapshot_sig.as_deref(),
        ) {
            (Some(or), Some(sr), Some(si), Some(sz), Some(sp), Some(sg)) =>
                (or.to_owned(), sr.to_owned(), si, sz, sp.clone(), sg.to_owned()),
            _ => {
                let detail = if row.record_type != "file" && row.record_type != "redaction" {
                    "Record exists but has no Poseidon snapshot — non-file records \
                     (e.g. JSON commits) are not anchored in the chunked ledger tree."
                } else {
                    "Record exists but has no Poseidon snapshot yet — the snapshot \
                     was not generated at commit time and will need to be back-filled."
                };
                return Ok(Json(build(
                    body.proof_id,
                    Some(row.proof_id),
                    content_hash,
                    SnapshotVerifyStatus::Pending,
                    detail,
                    None,
                    None,
                    None,
                )));
            }
        };

    // Parse the stored snapshot_path JSON shape produced by
    // `compute_and_persist_snapshot`: { path_elements: [hex…], path_indices: [u8…] }.
    let path_obj = match snapshot_path_json.as_object() {
        Some(o) => o,
        None => return Ok(Json(build(
            body.proof_id, Some(row.proof_id), content_hash,
            SnapshotVerifyStatus::Invalid,
            "Stored snapshot_path is not a JSON object.",
            Some(snapshot_root_str), Some(snapshot_index_i as u64), Some(snapshot_size_i as u64),
        ))),
    };
    let path_elements_hex: Vec<String> = match path_obj
        .get("path_elements")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str().map(|s| s.to_owned())).collect())
    {
        Some(v) => v,
        None => return Ok(Json(build(
            body.proof_id, Some(row.proof_id), content_hash,
            SnapshotVerifyStatus::Invalid,
            "Stored snapshot_path.path_elements is missing or malformed.",
            Some(snapshot_root_str), Some(snapshot_index_i as u64), Some(snapshot_size_i as u64),
        ))),
    };
    let path_indices: Vec<u8> = match path_obj
        .get("path_indices")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_u64().map(|n| n as u8)).collect())
    {
        Some(v) => v,
        None => return Ok(Json(build(
            body.proof_id, Some(row.proof_id), content_hash,
            SnapshotVerifyStatus::Invalid,
            "Stored snapshot_path.path_indices is missing or malformed.",
            Some(snapshot_root_str), Some(snapshot_index_i as u64), Some(snapshot_size_i as u64),
        ))),
    };

    let snapshot = CryptoSnapshot {
        snapshot_root: snapshot_root_str.clone(),
        snapshot_index: snapshot_index_i as u64,
        snapshot_size: snapshot_size_i as u64,
        path_elements_hex,
        path_indices,
        signature_hex: snapshot_sig_hex,
    };

    let authority_pubkey = match crate::zk::snapshot::authority_pubkey() {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!("verify_proof_bundle: authority pubkey unavailable: {e}");
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "Snapshot signing key is not configured on this server; cannot verify.",
            ));
        }
    };

    let ok = verify_snapshot(&snapshot, &content_hash, &original_root, &authority_pubkey);
    let (status, detail) = if ok {
        (SnapshotVerifyStatus::Verified,
         "Snapshot path reconstructs the stored ledger root and the authority \
          signature is valid.")
    } else {
        (SnapshotVerifyStatus::Invalid,
         "Stored snapshot failed verification: path reconstruction or authority \
          signature check did not pass.")
    };

    Ok(Json(build(
        body.proof_id,
        Some(row.proof_id),
        content_hash,
        status,
        detail,
        Some(snapshot_root_str),
        Some(snapshot_index_i as u64),
        Some(snapshot_size_i as u64),
    )))
}

// ── Route: POST /ingest/files ─────────────────────────────────────────────────
//
// Multipart file upload. content_hash = plain BLAKE3 of raw file bytes —
// identical to what the in-browser hasher computes, so the same file always
// produces the same hash and round-trip verifies.

const FILE_MAX_BYTES: usize = 100 * 1024 * 1024; // 100 MB

/// Compute the depth-20 Poseidon snapshot for a newly-committed file and
/// write it back to the record.  Uses a per-shard advisory lock inside a
/// single transaction so concurrent commits assign monotonic
/// `snapshot_index` values without colliding.  Errors are logged and
/// swallowed — the record's snapshot fields stay NULL and the response
/// is unaffected; snapshot failures are treated as soft (non-fatal).
async fn compute_and_persist_snapshot(
    pool: &sqlx::PgPool,
    shard_id: &str,
    content_hash: &str,
    proof_id: &str,
    bytes: &[u8],
) {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    let chunk_tree = match chunk_tree_from_bytes(bytes) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("snapshot: chunk tree for {content_hash}: {e}");
            return;
        }
    };
    let original_root_hex = fr_to_hex(chunk_tree.original_root);
    let chunk_hashes_json = serde_json::Value::Array(
        chunk_tree
            .chunk_hashes_hex
            .iter()
            .map(|h| serde_json::Value::String(h.clone()))
            .collect(),
    );

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("snapshot: begin tx: {e}");
            return;
        }
    };

    // Advisory lock keyed on the shard so concurrent commits in the same
    // shard serialize for the snapshot-index assignment.  Different
    // shards never block each other.
    let lock_key = blake3::hash(shard_id.as_bytes()).as_bytes()[..8].to_vec();
    let lock_i64 = i64::from_le_bytes(lock_key.try_into().unwrap());
    if let Err(e) = sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_i64)
        .execute(&mut *tx)
        .await
    {
        tracing::warn!("snapshot: advisory lock: {e}");
        return;
    }

    // Read existing leaves in their canonical insertion order.  Records
    // already carrying a snapshot_index sort before this new one; any
    // legacy records without snapshot_index (e.g. JSON-record commits)
    // fall to the end on NULLS LAST and don't contribute to the tree —
    // they were never inserted as leaves under this scheme.
    let existing_roots: Vec<String> = match sqlx::query_scalar::<_, Option<String>>(
        "SELECT original_root FROM ingest_records \
         WHERE shard_id = $1 \
           AND original_root IS NOT NULL \
           AND content_hash <> $2 \
         ORDER BY snapshot_index ASC NULLS LAST",
    )
    .bind(shard_id)
    .bind(content_hash)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows.into_iter().flatten().collect(),
        Err(e) => {
            tracing::warn!("snapshot: read existing leaves: {e}");
            return;
        }
    };

    let existing_leaves: Vec<Fr> = existing_roots
        .iter()
        .filter_map(|h| {
            let mut bytes = [0u8; 32];
            let decoded = hex::decode(h).ok()?;
            let off = 32usize.saturating_sub(decoded.len());
            bytes[off..off + decoded.len()].copy_from_slice(&decoded);
            Some(Fr::from_be_bytes_mod_order(&bytes))
        })
        .collect();
    let new_leaf_index = existing_leaves.len() as u64;

    let snap: LedgerSnapshot = match snapshot_new_record(
        &existing_leaves,
        chunk_tree.original_root,
        new_leaf_index,
        content_hash,
        &original_root_hex,
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("snapshot: build/sign for {content_hash}: {e}");
            return;
        }
    };

    let snapshot_path_json = serde_json::json!({
        "path_elements": snap.path_elements_hex,
        "path_indices": snap.path_indices,
    });

    if let Err(e) = sqlx::query(
        "UPDATE ingest_records SET \
             chunk_hashes = $1, \
             original_root = $2, \
             snapshot_root = $3, \
             snapshot_index = $4, \
             snapshot_size = $5, \
             snapshot_path = $6, \
             snapshot_sig = $7 \
         WHERE proof_id = $8",
    )
    .bind(&chunk_hashes_json)
    .bind(&original_root_hex)
    .bind(&snap.snapshot_root)
    .bind(snap.snapshot_index as i64)
    .bind(snap.snapshot_size as i64)
    .bind(&snapshot_path_json)
    .bind(&snap.signature_hex)
    .bind(proof_id)
    .execute(&mut *tx)
    .await
    {
        tracing::warn!("snapshot: update snapshot fields: {e}");
        return;
    }

    if let Err(e) = tx.commit().await {
        tracing::warn!("snapshot: commit tx: {e}");
    }
}

async fn ingest_file(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<CommitResult>), ApiError> {
    if !auth.has_scope("write") && !auth.has_scope("ingest") && !auth.has_scope("admin") {
        return Err(err(StatusCode::FORBIDDEN, "API key lacks required scope (write, ingest, or admin)."));
    }
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut shard_id = "files".to_owned();
    let mut record_id_opt: Option<String> = None;
    let mut version: i32 = 1;
    let mut original_hash_opt: Option<String> = None;

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
            "original_hash" => {
                let text = field.text().await.unwrap_or_default().trim().to_lowercase();
                if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
                    original_hash_opt = Some(text);
                }
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

    let record_type = if original_hash_opt.is_some() { "redaction" } else { "file" };

    let row: UpsertResult = sqlx::query_as::<_, UpsertResult>(
        r#"
        WITH ins AS (
            INSERT INTO ingest_records
                (proof_id, shard_id, record_type, record_id, version,
                 content_hash, ledger_entry_hash, merkle_root,
                 batch_id, poseidon_root, canonicalization, original_hash, ts)
            VALUES ($1, $2, $8, $3, $4, $5, $6, NULL, NULL, NULL, NULL, $9, $7)
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
    .bind(record_type)
    .bind(&original_hash_opt)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("ingest_file upsert failed: {e}");
        err(StatusCode::INTERNAL_SERVER_ERROR, "Ingest failed.")
    })?;

    // Compute the depth-20 Poseidon snapshot + Ed25519 sig for the new record.
    // Only runs for new inserts (dedup skips it), and only for actual file
    // uploads where we have raw bytes to chunk into the 16-leaf redaction tree.
    if row.is_new {
        compute_and_persist_snapshot(pool, &row.shard_id, &row.content_hash, &row.proof_id, &bytes).await;
    }

    let status = if row.is_new { StatusCode::CREATED } else { StatusCode::OK };
    Ok((status, Json(CommitResult {
        proof_id: row.proof_id,
        content_hash: row.content_hash,
        record_id: row.record_id,
        shard_id: row.shard_id,
        deduplicated: !row.is_new,
    })))
}

// ── Route: GET /ingest/records/hash/{hash}/zk_bundle ─────────────────────────
//
// Lazy ZK existence-proof issuance.  Returns the Groth16 proof bundle for a
// committed record, generating it on the first request and caching the
// result back to `ingest_records.zk_bundle` so subsequent requests are
// instant.  Requires the snapshot columns added by migration 0029 — older
// records (or JSON-record commits) without `snapshot_root` return 503.
//
// Auth: `verify`, `read`, or `admin` scope, same gate as `/zk/verify`.
// Since the API key is BLAKE3-derived from the BJJ private key (PR #945),
// "holder of API key" == "holder of BJJ private key" — the natural
// re-download path for the original committer.

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZkBundleResponse {
    circuit: String,
    proof_json: serde_json::Value,
    public_signals: Vec<String>,
    content_hash: String,
    original_root: String,
    snapshot_root: String,
    snapshot_index: i64,
    snapshot_size: i64,
    snapshot_sig: String,
}

#[derive(sqlx::FromRow)]
struct ZkBundleRow {
    proof_id: String,
    content_hash: String,
    original_root: Option<String>,
    snapshot_root: Option<String>,
    snapshot_index: Option<i64>,
    snapshot_size: Option<i64>,
    snapshot_path: Option<serde_json::Value>,
    snapshot_sig: Option<String>,
    zk_bundle: Option<serde_json::Value>,
}

async fn issue_zk_bundle(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(hash): Path<String>,
) -> Result<Json<ZkBundleResponse>, ApiError> {
    if !auth.has_scope("verify") && !auth.has_scope("read") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: one of 'verify', 'read', or 'admin'",
        ));
    }

    let hash = hash.trim().to_lowercase();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Hash must be a 64-character hex string.",
        ));
    }

    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let row: ZkBundleRow = sqlx::query_as::<_, ZkBundleRow>(
        "SELECT proof_id, content_hash, original_root, snapshot_root, snapshot_index, \
                snapshot_size, snapshot_path, snapshot_sig, zk_bundle \
         FROM ingest_records WHERE content_hash = $1 LIMIT 1",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Hash not found in ledger."))?;

    // Cache hit: return the previously-generated bundle verbatim.
    if let Some(cached) = row.zk_bundle.as_ref() {
        if let Ok(resp) = serde_json::from_value::<ZkBundleResponse>(cached.clone()) {
            return Ok(Json(resp));
        }
        // Fall through and regenerate if the cached blob is malformed.
        tracing::warn!("zk_bundle cache for {hash} is malformed; regenerating");
    }

    // Snapshot must be populated to generate a proof.  Records committed
    // before migration 0029 (or JSON-record commits without chunks) have
    // NULL snapshot columns.
    let original_root = row.original_root.ok_or_else(|| err(
        StatusCode::SERVICE_UNAVAILABLE,
        "Record has no Poseidon snapshot — was likely committed before ZK \
         existence-proof issuance was wired in (or is a JSON-record commit).",
    ))?;
    let snapshot_root = row.snapshot_root.ok_or_else(|| err(
        StatusCode::SERVICE_UNAVAILABLE,
        "Record is missing snapshot_root.",
    ))?;
    let snapshot_index = row.snapshot_index.ok_or_else(|| err(
        StatusCode::SERVICE_UNAVAILABLE,
        "Record is missing snapshot_index.",
    ))?;
    let snapshot_size = row.snapshot_size.ok_or_else(|| err(
        StatusCode::SERVICE_UNAVAILABLE,
        "Record is missing snapshot_size.",
    ))?;
    let snapshot_path = row.snapshot_path.ok_or_else(|| err(
        StatusCode::SERVICE_UNAVAILABLE,
        "Record is missing snapshot_path.",
    ))?;
    let snapshot_sig = row.snapshot_sig.ok_or_else(|| err(
        StatusCode::SERVICE_UNAVAILABLE,
        "Record is missing snapshot_sig.",
    ))?;

    let (proof_json, public_signals) = generate_existence_bundle(
        state.proofs_dir.clone(),
        &original_root,
        &snapshot_root,
        snapshot_index as u64,
        snapshot_size as u64,
        &snapshot_path,
    )
    .await?;

    let response = ZkBundleResponse {
        circuit: "document_existence".to_string(),
        proof_json,
        public_signals,
        content_hash: row.content_hash.clone(),
        original_root,
        snapshot_root,
        snapshot_index,
        snapshot_size,
        snapshot_sig,
    };

    // Cache the generated bundle so subsequent requests are instant.
    // Failure to cache is non-fatal — the bundle is already constructed.
    let cache_value = match serde_json::to_value(&response) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("zk_bundle cache serialise: {e}");
            None
        }
    };
    if let Some(v) = cache_value {
        if let Err(e) = sqlx::query("UPDATE ingest_records SET zk_bundle = $1 WHERE proof_id = $2")
            .bind(&v)
            .bind(&row.proof_id)
            .execute(pool)
            .await
        {
            tracing::warn!("zk_bundle cache write: {e}");
        }
    }

    Ok(Json(response))
}

/// Build the `ExistenceWitness` from the stored snapshot, run
/// `prove_existence` on a blocking task, and return the snarkjs-shape
/// proof JSON + decimal public signals.
async fn generate_existence_bundle(
    proofs_dir: Option<std::path::PathBuf>,
    original_root_hex: &str,
    snapshot_root_hex: &str,
    snapshot_index: u64,
    snapshot_size: u64,
    snapshot_path: &serde_json::Value,
) -> Result<(serde_json::Value, Vec<String>), ApiError> {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    fn hex_to_fr(h: &str) -> Result<Fr, ApiError> {
        let mut bytes = [0u8; 32];
        let decoded = hex::decode(h)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("hex decode: {e}")))?;
        let off = 32usize.saturating_sub(decoded.len());
        bytes[off..off + decoded.len()].copy_from_slice(&decoded);
        Ok(Fr::from_be_bytes_mod_order(&bytes))
    }

    let root = hex_to_fr(snapshot_root_hex)?;
    let leaf = hex_to_fr(original_root_hex)?;

    let path_obj = snapshot_path.as_object().ok_or_else(|| {
        err(StatusCode::INTERNAL_SERVER_ERROR, "snapshot_path is not an object")
    })?;
    let path_elements_arr = path_obj
        .get("path_elements")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "snapshot_path.path_elements missing"))?;
    let path_indices_arr = path_obj
        .get("path_indices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "snapshot_path.path_indices missing"))?;

    let mut path_elements: Vec<Fr> = Vec::with_capacity(path_elements_arr.len());
    for (i, v) in path_elements_arr.iter().enumerate() {
        let s = v.as_str().ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("path_elements[{}] is not a string", i),
            )
        })?;
        path_elements.push(hex_to_fr(s)?);
    }
    let mut path_indices: Vec<u8> = Vec::with_capacity(path_indices_arr.len());
    for (i, v) in path_indices_arr.iter().enumerate() {
        let n = v.as_u64().ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("path_indices[{}] is not a number", i),
            )
        })?;
        path_indices.push(n as u8);
    }

    let witness = crate::zk::witness::ExistenceWitness::new(
        root,
        snapshot_index,
        snapshot_size,
        leaf,
        path_elements,
        path_indices,
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("witness: {e}")))?;

    let keys_dir = proofs_dir.unwrap_or_else(|| std::path::PathBuf::from("proofs/keys"));

    #[cfg(feature = "prover")]
    {
        use crate::zk::Circuit;
        let circuit = Circuit::DocumentExistence;
        let wasm = circuit.wasm_path(&keys_dir);
        let r1cs = circuit.r1cs_path(&keys_dir);
        let zkey = circuit.ark_zkey_path(&keys_dir);
        for (label, path) in [("wasm", &wasm), ("r1cs", &r1cs), ("zkey", &zkey)] {
            if !path.exists() {
                return Err(err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!(
                        "circuit artifact missing: {label} at {}",
                        path.display()
                    ),
                ));
            }
        }

        let (proof, public_signals) = tokio::task::spawn_blocking(move || {
            crate::zk::prove::prove_existence(&witness, &wasm, &r1cs, &zkey)
        })
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join: {e}")))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("prove: {e}")))?;

        let proof_json = groth16_proof_to_json(&proof);
        let public_signals_dec: Vec<String> =
            public_signals.iter().map(fr_to_decimal).collect();
        Ok((proof_json, public_signals_dec))
    }
    #[cfg(not(feature = "prover"))]
    {
        let _ = (keys_dir, witness);
        Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "ZK prover feature not compiled in this build",
        ))
    }
}

#[cfg(feature = "prover")]
fn fr_to_decimal(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

#[cfg(feature = "prover")]
fn groth16_proof_to_json(proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> serde_json::Value {
    use ark_serialize::CanonicalSerialize;
    fn g1(p: &ark_bn254::G1Affine) -> Vec<String> {
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        let x = num_bigint::BigUint::from_bytes_le(&buf[..32]);
        let y = num_bigint::BigUint::from_bytes_le(&buf[32..64]);
        vec![x.to_string(), y.to_string(), "1".into()]
    }
    fn g2(p: &ark_bn254::G2Affine) -> Vec<Vec<String>> {
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        let x_c0 = num_bigint::BigUint::from_bytes_le(&buf[..32]);
        let x_c1 = num_bigint::BigUint::from_bytes_le(&buf[32..64]);
        let y_c0 = num_bigint::BigUint::from_bytes_le(&buf[64..96]);
        let y_c1 = num_bigint::BigUint::from_bytes_le(&buf[96..128]);
        vec![
            vec![x_c0.to_string(), x_c1.to_string()],
            vec![y_c0.to_string(), y_c1.to_string()],
            vec!["1".into(), "0".into()],
        ]
    }
    serde_json::json!({
        "pi_a": g1(&proof.a),
        "pi_b": g2(&proof.b),
        "pi_c": g1(&proof.c),
        "protocol": "groth16",
        "curve": "bn128",
    })
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ingest/files", post(ingest_file))
        .route("/ingest/records", post(commit_records))
        // The hash routes MUST be registered before the /{proof_id} catch-all.
        .route("/ingest/records/hash/{hash}/verify", get(verify_by_hash))
        .route("/ingest/records/hash/{hash}/zk_bundle", get(issue_zk_bundle))
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
