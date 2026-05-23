//! DB persistence for anchor receipts.
//!
//! Append-only table by design — receipts never change after submission
//! (only `verified_at` gets bumped on re-verification, and `metadata` may
//! grow if an OTS pending receipt is upgraded with a Bitcoin block path,
//! but the original `receipt_blob` is preserved verbatim).

use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use super::{AnchorError, AnchorReceipt};

/// Insert an anchor receipt and return its row id.
pub async fn insert(
    pool: &PgPool,
    rcpt: &AnchorReceipt,
    checkpoint_id: Option<Uuid>,
) -> Result<Uuid, AnchorError> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO anchor_receipts
             (id, anchor_kind, anchored_hash, checkpoint_id,
              receipt_blob, target, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(rcpt.kind.as_str())
    .bind(rcpt.anchored_hash.as_slice())
    .bind(checkpoint_id)
    .bind(rcpt.receipt_blob.as_slice())
    .bind(&rcpt.target)
    .bind(&rcpt.metadata)
    .execute(pool)
    .await?;
    Ok(id)
}

/// Receipt row as returned from list endpoints. The `receipt_blob` is
/// stripped from list responses (it can be hundreds of KB for OTS upgrades)
/// — call `fetch_blob` for the raw bytes.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AnchorRow {
    pub id: Uuid,
    pub anchor_kind: String,
    pub anchored_hash: Vec<u8>,
    pub checkpoint_id: Option<Uuid>,
    pub target: String,
    pub submitted_at: chrono::DateTime<chrono::Utc>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: serde_json::Value,
    pub blob_size: i64,
}

pub async fn list(
    pool: &PgPool,
    checkpoint_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<AnchorRow>, AnchorError> {
    let limit = limit.clamp(1, 500);
    let rows: Vec<AnchorRow> = if let Some(cp) = checkpoint_id {
        sqlx::query_as(
            "SELECT id, anchor_kind, anchored_hash, checkpoint_id, target,
                    submitted_at, verified_at, metadata,
                    OCTET_LENGTH(receipt_blob)::bigint AS blob_size
             FROM anchor_receipts
             WHERE checkpoint_id = $1
             ORDER BY submitted_at DESC
             LIMIT $2",
        )
        .bind(cp)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT id, anchor_kind, anchored_hash, checkpoint_id, target,
                    submitted_at, verified_at, metadata,
                    OCTET_LENGTH(receipt_blob)::bigint AS blob_size
             FROM anchor_receipts
             ORDER BY submitted_at DESC
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await?
    };
    Ok(rows)
}

/// Fetch the raw receipt bytes for a single row. Used by the
/// `GET /anchors/{id}/receipt` route so the operator can hand the file
/// straight to opposing counsel / their TSA verifier.
pub async fn fetch_blob(pool: &PgPool, id: Uuid) -> Result<Option<(String, Vec<u8>)>, AnchorError> {
    let row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT anchor_kind, receipt_blob FROM anchor_receipts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Bump `verified_at` to NOW on successful round-trip verification.
pub async fn mark_verified(pool: &PgPool, id: Uuid) -> Result<(), AnchorError> {
    sqlx::query("UPDATE anchor_receipts SET verified_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
