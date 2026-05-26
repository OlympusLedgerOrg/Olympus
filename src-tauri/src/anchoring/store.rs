//! DB persistence for anchor receipts.
//!
//! Mostly append-only: a receipt's identifying fields never change after
//! submission, but two in-place mutations are allowed:
//!   * `verified_at` is bumped on successful re-verification.
//!   * an OTS pending receipt is *upgraded* by [`mark_ots_upgraded`], which
//!     **replaces** `receipt_blob` with the Bitcoin-anchored form and sets
//!     `metadata.phase = "upgraded"`, `metadata.needs_upgrade = false`, and
//!     `verified_at = NOW()`. The original pending blob is not retained — an
//!     operator who needs it must capture it before the upgrade cron runs.

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

/// A pending OTS receipt ready to attempt an upgrade.
///
/// Audit M-A3: `target` is the calendar URL we originally submitted
/// to — we must re-fetch from the same calendar to upgrade because
/// pending receipts are calendar-specific. `receipt_blob` is the
/// pending bytes the calendar will use to look up the underlying
/// commitment.
pub struct PendingOts {
    pub id: Uuid,
    pub target: String,
    pub receipt_blob: Vec<u8>,
}

/// List anchor_receipts rows that are OTS-kind and still in `phase: pending`
/// (or were inserted before the `phase` metadata field was added, treated as
/// pending by default). Limited to `limit` rows per call so the upgrade cron
/// doesn't try to fan out unboundedly.
pub async fn list_pending_ots(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<PendingOts>, AnchorError> {
    let limit = limit.clamp(1, 200);
    let rows: Vec<(Uuid, String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, target, receipt_blob
           FROM anchor_receipts
          WHERE anchor_kind = 'ots'
            AND (metadata->>'phase' IS NULL OR metadata->>'phase' = 'pending')
          ORDER BY submitted_at ASC
          LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, target, receipt_blob)| PendingOts {
            id,
            target,
            receipt_blob,
        })
        .collect())
}

/// Replace a pending OTS receipt's blob with the upgraded form and flip
/// `metadata.phase` to `"upgraded"` so the next cron tick skips it.
/// `verified_at` is also bumped so the operator can see when the upgrade
/// landed without re-querying the calendar.
pub async fn mark_ots_upgraded(
    pool: &PgPool,
    id: Uuid,
    new_blob: &[u8],
) -> Result<(), AnchorError> {
    sqlx::query(
        "UPDATE anchor_receipts
            SET receipt_blob = $1,
                metadata = jsonb_set(
                    jsonb_set(metadata, '{phase}', '\"upgraded\"'::jsonb),
                    '{needs_upgrade}', 'false'::jsonb
                ),
                verified_at = NOW()
          WHERE id = $2",
    )
    .bind(new_blob)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}
