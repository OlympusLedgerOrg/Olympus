//! DB persistence for anchor receipts.
//!
//! Receipt rows are append-only. A durable submission claim is acquired before
//! any outbound request so overlapping cron ticks and process restarts do not
//! resubmit an already-completed `(kind, hash, target)` request (M-17).
//! Mutable receipt state is deliberately narrow:
//!   * `verified_at` is bumped on successful re-verification.
//!   * pending OTS rows update only lease/backoff/error-summary columns.
//!   * an OTS pending receipt is *upgraded* by [`mark_ots_upgraded`], which
//!     inserts a successor evidence row containing the Bitcoin-anchored form and sets
//!     `metadata.phase = "upgraded"`, `metadata.needs_upgrade = false`, and
//!     The merged receipt retains the original pending path. `verified_at`
//!     remains NULL until a separate verifier checks the claimed merkle root
//!     against a trusted Bitcoin block header.

use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use super::{AnchorError, AnchorKind, AnchorReceipt};

const SUBMISSION_LEASE_MINUTES: i32 = 5;
const MAX_STORED_ERROR_CHARS: usize = 2048;

/// Result of attempting to acquire the durable lease for one logical anchor
/// submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionClaim {
    /// This worker owns the lease and may contact the backend.
    Acquired {
        lease_token: Uuid,
        attempt_count: i32,
    },
    /// A prior worker already persisted the receipt; no network call is needed.
    Completed(Uuid),
    /// Another worker owns the lease or the retry backoff has not elapsed.
    Deferred,
}

/// Acquire a cross-process submission lease. Existing successful claims return
/// their receipt id; retry/in-flight claims are only taken after their schedule
/// or lease expires.
pub async fn claim_submission(
    pool: &PgPool,
    kind: AnchorKind,
    anchored_hash: &[u8; 32],
    target: &str,
    checkpoint_id: Option<Uuid>,
) -> Result<SubmissionClaim, AnchorError> {
    let lease_token = Uuid::new_v4();
    let acquired: Option<(i32,)> = sqlx::query_as(
        "INSERT INTO anchor_submission_claims (
             anchor_kind, anchored_hash, target, checkpoint_id, status,
             lease_token, lease_until, attempt_count, last_attempt_at,
             created_at, updated_at
         ) VALUES (
             $1, $2, $3, $4, 'in_flight', $5,
             NOW() + make_interval(mins => $6), 1, NOW(), NOW(), NOW()
         )
         ON CONFLICT (anchor_kind, anchored_hash, target) DO UPDATE
            SET checkpoint_id = COALESCE(
                    anchor_submission_claims.checkpoint_id,
                    EXCLUDED.checkpoint_id
                ),
                status = 'in_flight',
                receipt_id = NULL,
                lease_token = EXCLUDED.lease_token,
                lease_until = NOW() + make_interval(mins => $6),
                attempt_count = anchor_submission_claims.attempt_count + 1,
                last_attempt_at = NOW(),
                next_retry_at = NULL,
                last_error = NULL,
                updated_at = NOW()
          WHERE (
                    anchor_submission_claims.status = 'retry'
                AND (
                    anchor_submission_claims.next_retry_at IS NULL
                    OR anchor_submission_claims.next_retry_at <= NOW()
                )
              ) OR (
                    anchor_submission_claims.status = 'in_flight'
                AND (
                    anchor_submission_claims.lease_until IS NULL
                    OR anchor_submission_claims.lease_until <= NOW()
                )
              )
         RETURNING attempt_count",
    )
    .bind(kind.as_str())
    .bind(anchored_hash.as_slice())
    .bind(target)
    .bind(checkpoint_id)
    .bind(lease_token)
    .bind(SUBMISSION_LEASE_MINUTES)
    .fetch_optional(pool)
    .await?;

    if let Some((attempt_count,)) = acquired {
        return Ok(SubmissionClaim::Acquired {
            lease_token,
            attempt_count,
        });
    }

    let existing: Option<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT status, receipt_id
           FROM anchor_submission_claims
          WHERE anchor_kind = $1 AND anchored_hash = $2 AND target = $3",
    )
    .bind(kind.as_str())
    .bind(anchored_hash.as_slice())
    .bind(target)
    .fetch_optional(pool)
    .await?;

    match existing {
        Some((status, Some(id))) if status == "succeeded" => Ok(SubmissionClaim::Completed(id)),
        Some(_) => Ok(SubmissionClaim::Deferred),
        None => Err(AnchorError::Db(
            "anchor submission claim disappeared after conflict".to_owned(),
        )),
    }
}

/// Atomically append a receipt and complete the submission claim. The lease
/// token prevents a stale worker from winning after another process reclaimed
/// an expired lease.
pub async fn complete_submission(
    pool: &PgPool,
    rcpt: &AnchorReceipt,
    checkpoint_id: Option<Uuid>,
    lease_token: Uuid,
) -> Result<Uuid, AnchorError> {
    let mut tx = pool.begin().await?;
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
    .execute(&mut *tx)
    .await?;

    let completed = sqlx::query(
        "UPDATE anchor_submission_claims
            SET status = 'succeeded',
                receipt_id = $1,
                checkpoint_id = COALESCE(checkpoint_id, $2),
                lease_token = NULL,
                lease_until = NULL,
                next_retry_at = NULL,
                last_error = NULL,
                updated_at = NOW()
          WHERE anchor_kind = $3
            AND anchored_hash = $4
            AND target = $5
            AND status = 'in_flight'
            AND lease_token = $6",
    )
    .bind(id)
    .bind(checkpoint_id)
    .bind(rcpt.kind.as_str())
    .bind(rcpt.anchored_hash.as_slice())
    .bind(&rcpt.target)
    .bind(lease_token)
    .execute(&mut *tx)
    .await?;

    if completed.rows_affected() != 1 {
        tx.rollback().await?;
        return Err(AnchorError::Db(
            "anchor submission lease expired before receipt persistence".to_owned(),
        ));
    }
    tx.commit().await?;
    Ok(id)
}

/// Release a failed submission into bounded exponential backoff.
pub async fn fail_submission(
    pool: &PgPool,
    kind: AnchorKind,
    anchored_hash: &[u8; 32],
    target: &str,
    lease_token: Uuid,
    retry_after_secs: i64,
    error: &str,
) -> Result<(), AnchorError> {
    let detail: String = error.chars().take(MAX_STORED_ERROR_CHARS).collect();
    let result = sqlx::query(
        "UPDATE anchor_submission_claims
            SET status = 'retry',
                lease_token = NULL,
                lease_until = NULL,
                next_retry_at = NOW() + make_interval(secs => $1::double precision),
                last_error = $2,
                updated_at = NOW()
          WHERE anchor_kind = $3
            AND anchored_hash = $4
            AND target = $5
            AND status = 'in_flight'
            AND lease_token = $6",
    )
    .bind(retry_after_secs.max(1))
    .bind(detail)
    .bind(kind.as_str())
    .bind(anchored_hash.as_slice())
    .bind(target)
    .bind(lease_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AnchorError::Db(
            "anchor submission lease expired before failure persistence".to_owned(),
        ));
    }
    Ok(())
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
    let row: Option<(String, Vec<u8>)> =
        sqlx::query_as("SELECT anchor_kind, receipt_blob FROM anchor_receipts WHERE id = $1")
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
    /// The original SHA-256 we POSTed to the calendar. Needed to seed
    /// the OTS receipt walker (red-team A-1 / PR F): the receipt's
    /// operations are rooted at this hash and the walker accumulates
    /// the per-calendar commitment by applying each op in turn.
    pub anchored_hash: Vec<u8>,
    pub lease_token: Uuid,
    /// Completed attempts before the lease acquired for this pass.
    pub upgrade_attempts: i32,
}

#[derive(sqlx::FromRow)]
struct PendingOtsRow {
    id: Uuid,
    target: String,
    receipt_blob: Vec<u8>,
    anchored_hash: Vec<u8>,
    lease_token: Uuid,
    upgrade_attempts: i32,
}

/// Fairly claim OTS rows ready for an upgrade attempt. Never-attempted rows are
/// first; attempted rows rotate behind them until their backoff expires.
/// `FOR UPDATE SKIP LOCKED` plus a persisted lease prevents overlapping
/// processes from issuing the same calendar request.
pub async fn claim_pending_ots(pool: &PgPool, limit: i64) -> Result<Vec<PendingOts>, AnchorError> {
    let limit = limit.clamp(1, 200);
    let rows: Vec<PendingOtsRow> = sqlx::query_as(
        "WITH ready AS (
             SELECT id
               FROM anchor_receipts
              WHERE anchor_kind = 'ots'
                AND (metadata->>'phase' IS NULL OR metadata->>'phase' = 'pending')
                AND NOT EXISTS (
                    SELECT 1 FROM anchor_receipts successor
                     WHERE successor.supersedes_receipt_id = anchor_receipts.id
                )
                AND (
                    ots_next_upgrade_attempt_at IS NULL
                    OR ots_next_upgrade_attempt_at <= NOW()
                )
                AND (
                    ots_upgrade_lease_until IS NULL
                    OR ots_upgrade_lease_until <= NOW()
                )
              ORDER BY ots_last_upgrade_attempt_at ASC NULLS FIRST,
                       submitted_at ASC,
                       id ASC
              FOR UPDATE SKIP LOCKED
              LIMIT $1
         )
         UPDATE anchor_receipts AS receipt
            SET ots_upgrade_lease_token = gen_random_uuid(),
                ots_upgrade_lease_until = NOW() + INTERVAL '10 minutes'
           FROM ready
          WHERE receipt.id = ready.id
         RETURNING receipt.id, receipt.target, receipt.receipt_blob,
                   receipt.anchored_hash, receipt.ots_upgrade_lease_token,
                   receipt.ots_upgrade_attempts",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PendingOts {
            id: row.id,
            target: row.target,
            receipt_blob: row.receipt_blob,
            anchored_hash: row.anchored_hash,
            lease_token: row.lease_token,
            upgrade_attempts: row.upgrade_attempts,
        })
        .collect())
}

/// Finish a non-successful OTS attempt and rotate the row behind other ready
/// receipts. Error text is bounded before persistence.
pub async fn schedule_ots_retry(
    pool: &PgPool,
    id: Uuid,
    lease_token: Uuid,
    retry_after_secs: i64,
    error: &str,
) -> Result<(), AnchorError> {
    let detail: String = error.chars().take(MAX_STORED_ERROR_CHARS).collect();
    let result = sqlx::query(
        "UPDATE anchor_receipts
            SET ots_upgrade_attempts = ots_upgrade_attempts + 1,
                ots_last_upgrade_attempt_at = NOW(),
                ots_next_upgrade_attempt_at =
                    NOW() + make_interval(secs => $1::double precision),
                ots_upgrade_lease_token = NULL,
                ots_upgrade_lease_until = NULL,
                ots_last_upgrade_error = $2
          WHERE id = $3
            AND anchor_kind = 'ots'
            AND (metadata->>'phase' IS NULL OR metadata->>'phase' = 'pending')
            AND ots_upgrade_lease_token = $4",
    )
    .bind(retry_after_secs.max(1))
    .bind(detail)
    .bind(id)
    .bind(lease_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AnchorError::Db(
            "OTS upgrade lease expired before retry persistence".to_owned(),
        ));
    }
    Ok(())
}

/// Insert an upgraded successor while retaining the pending receipt's evidence.
/// The pending row's lease/backoff bookkeeping is cleared in the same statement.
/// This records a structurally valid Bitcoin attestation but deliberately does
/// not set `verified_at`: a tag and height supplied by a calendar are not proof
/// until the attested message is matched to the trusted block header.
pub async fn mark_ots_upgraded(
    pool: &PgPool,
    id: Uuid,
    lease_token: Uuid,
    new_blob: &[u8],
    bitcoin_block_height: u64,
    bitcoin_merkle_root: &[u8; 32],
) -> Result<(), AnchorError> {
    let height = i64::try_from(bitcoin_block_height)
        .map_err(|_| AnchorError::Parse("Bitcoin block height exceeds i64".to_owned()))?;
    let result = sqlx::query(
        "WITH claimed AS (
             UPDATE anchor_receipts
                SET ots_upgrade_attempts = ots_upgrade_attempts + 1,
                    ots_last_upgrade_attempt_at = NOW(),
                    ots_next_upgrade_attempt_at = NULL,
                    ots_upgrade_lease_token = NULL,
                    ots_upgrade_lease_until = NULL,
                    ots_last_upgrade_error = NULL
              WHERE id = $4
                AND anchor_kind = 'ots'
                AND (metadata->>'phase' IS NULL OR metadata->>'phase' = 'pending')
                AND ots_upgrade_lease_token = $5
                AND NOT EXISTS (
                    SELECT 1 FROM anchor_receipts successor
                     WHERE successor.supersedes_receipt_id = anchor_receipts.id
                )
             RETURNING *
         )
         INSERT INTO anchor_receipts
            (id, anchor_kind, anchored_hash, checkpoint_id, receipt_blob,
             target, submitted_at, verified_at, metadata,
             supersedes_receipt_id, evidence_version)
         SELECT $6, anchor_kind, anchored_hash, checkpoint_id, $1,
                target, NOW(), NULL,
                metadata || jsonb_build_object(
                    'phase', 'upgraded',
                    'needs_upgrade', false,
                    'bitcoin_attestation', true,
                    'bitcoin_block_height', $2,
                    'bitcoin_merkle_root', $3,
                    'bitcoin_attestation_verified', false,
                    'verification', 'bitcoin-attestation-unverified'
                ), id, evidence_version + 1
           FROM claimed
         ON CONFLICT (supersedes_receipt_id) WHERE supersedes_receipt_id IS NOT NULL
         DO NOTHING",
    )
    .bind(new_blob)
    .bind(height)
    .bind(hex::encode(bitcoin_merkle_root))
    .bind(id)
    .bind(lease_token)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AnchorError::Parse(
            "OTS receipt is missing, is not OTS, or is no longer pending".to_owned(),
        ));
    }
    Ok(())
}
