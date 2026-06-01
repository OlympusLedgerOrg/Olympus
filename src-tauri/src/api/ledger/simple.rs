//! User-friendly document ingestion and verification (`/ledger/ingest/simple`,
//! `/ledger/verify/simple`) plus the streaming multipart-field helpers they
//! share. Split out of the ledger module.

use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;

/// Multipart file-upload size limit (50 MiB) — matches Python `max_upload_bytes`.
const MAX_UPLOAD_BYTES: usize = 50 * 1024 * 1024;

// ── Multipart helpers ───────────────────────────────────────────────────────

/// Per-field cap for short text parts (request_id / description /
/// commit_id / doc_hash). Generous enough for any legitimate value,
/// small enough that buffering it can't cause memory pressure.
const MAX_TEXT_FIELD_BYTES: usize = 4 * 1024;

/// Stream a multipart field chunk-by-chunk, aborting as soon as the
/// accumulated size exceeds `cap`. `Field::bytes()` buffers the entire
/// part *before* any size check, so an oversized part defeats a
/// post-hoc `len()` guard — count as we read instead.
async fn read_field_capped(
    field: &mut axum::extract::multipart::Field<'_>,
    cap: usize,
    label: &str,
) -> Result<Vec<u8>, ApiError> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("Read error: {e}")))?
    {
        if buf.len() + chunk.len() > cap {
            return Err(err(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!("{label} exceeds the {cap}-byte limit."),
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Read a capped text field as UTF-8.
async fn read_text_field_capped(
    field: &mut axum::extract::multipart::Field<'_>,
    cap: usize,
    label: &str,
) -> Result<String, ApiError> {
    let bytes = read_field_capped(field, cap, label).await?;
    String::from_utf8(bytes).map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            &format!("{label} is not valid UTF-8."),
        )
    })
}

/// Strip control characters and cap length before a client-supplied
/// filename is reflected back in a response body — avoids smuggling
/// newlines / escape sequences through and bounds the echoed size.
fn sanitize_filename(name: &str) -> String {
    name.chars().filter(|c| !c.is_control()).take(255).collect()
}

// ── Route: POST /ledger/ingest/simple ────────────────────────────────────────

pub(super) async fn simple_document_ingest(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<SimpleIngestionResponse>), ApiError> {
    // Audit fix: `/ledger/ingest/simple` is a write path. Restrict to
    // keys that carry one of the write-side scopes; a bare `read` /
    // `verify` / `prove` key MUST NOT be able to commit documents.
    const WRITE_SCOPES: &[&str] = &["ingest", "write", "commit", "admin"];
    if !WRITE_SCOPES.iter().any(|s| auth.has_scope(s)) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks write scope (need one of: ingest, write, commit, admin).",
        ));
    }

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut filename = String::from("upload");
    let mut request_id: Option<String> = None;
    let mut description: Option<String> = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("Multipart error: {e}")))?
    {
        // Own the field name before borrowing `field` mutably below.
        let name = field.name().map(|s| s.to_owned());
        match name.as_deref() {
            Some("file") => {
                if let Some(n) = field.file_name().map(|s| s.to_owned()) {
                    filename = sanitize_filename(&n);
                }
                file_bytes = Some(read_field_capped(&mut field, MAX_UPLOAD_BYTES, "File").await?);
            }
            Some("request_id") => {
                request_id = Some(
                    read_text_field_capped(&mut field, MAX_TEXT_FIELD_BYTES, "request_id").await?,
                );
            }
            Some("description") => {
                description = Some(
                    read_text_field_capped(&mut field, MAX_TEXT_FIELD_BYTES, "description").await?,
                );
            }
            _ => {}
        }
    }

    let file_bytes = file_bytes.ok_or_else(|| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "No file field in request.",
        )
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

    // Wrap doc_commits insert + ledger_activities insert in a single
    // transaction so an audit-log failure does not leave the commit row
    // orphaned without a matching activity entry. Audit L-API-5.
    let mut tx = pool.begin().await.map_err(db_err)?;

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
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    // If the returned commit_id differs from what we generated, it's a pre-existing record.
    let is_duplicate = upsert_row.commit_id != commit_id;

    if is_duplicate {
        // Nothing to write — release the transaction (no rows mutated).
        tx.rollback().await.map_err(db_err)?;
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
                epoch: upsert_row
                    .epoch_timestamp
                    .format("%Y-%m-%dT%H:%M:%S")
                    .to_string(),
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
    .bind(format!(
        "Document '{desc}' recorded with fingerprint {doc_hash}"
    ))
    .bind(&upsert_row.commit_id)
    .bind(request_id.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::warn!("failed to insert ledger_activity: {e}");
        db_err(e)
    })?;

    tx.commit().await.map_err(db_err)?;

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

pub(super) async fn simple_document_verify(
    State(state): State<AppState>,
    _rl: RateLimit,
    mut multipart: Multipart,
) -> Result<Json<SimpleVerificationResponse>, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut commit_id_param: Option<String> = None;
    let mut doc_hash_param: Option<String> = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("Multipart error: {e}")))?
    {
        let name = field.name().map(|s| s.to_owned());
        match name.as_deref() {
            Some("file") => {
                file_bytes = Some(read_field_capped(&mut field, MAX_UPLOAD_BYTES, "File").await?);
            }
            Some("commit_id") => {
                commit_id_param = Some(
                    read_text_field_capped(&mut field, MAX_TEXT_FIELD_BYTES, "commit_id").await?,
                );
            }
            Some("doc_hash") => {
                doc_hash_param = Some(
                    read_text_field_capped(&mut field, MAX_TEXT_FIELD_BYTES, "doc_hash").await?,
                );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_filename_strips_control_and_caps_length() {
        // Control chars (newlines/tabs/CR) removed so a client filename can't
        // smuggle escape sequences into a reflected response body.
        assert_eq!(sanitize_filename("a\nb\tc\r"), "abc");
        // Ordinary names pass through unchanged.
        assert_eq!(sanitize_filename("report.pdf"), "report.pdf");
        // Length capped at 255.
        assert_eq!(sanitize_filename(&"x".repeat(300)).len(), 255);
    }
}
