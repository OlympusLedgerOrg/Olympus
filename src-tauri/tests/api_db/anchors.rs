//! HTTP integration coverage for `src-tauri/src/anchoring/api.rs`.
//!
//! Replaces the route-level subset of the deleted `test_anchors_coverage.py`.
//! No outbound TSA / Rekor / OTS calls are made — these tests cover the
//! read endpoints' auth gating, the empty-list shape, and 404s. Anchor
//! *submission* happens on checkpoint build, not via these routes, so an
//! empty `anchor_receipts` table is the expected fresh-DB state.

use crate::common;

use serde_json::Value;

/// A well-formed UUID guaranteed absent from a fresh `anchor_receipts`
/// table (anchors are only inserted on checkpoint build, which these
/// tests never trigger). Constant is fine — the lookups are read-only.
const MISSING_ANCHOR_ID: &str = "00000000-0000-4000-8000-00000000dead";

#[tokio::test]
async fn list_anchors_empty_ok() {
    let h = common::boot().await;
    let resp = common::get_with_key(&h.client, &common::url(h, "/anchors"), &h.api_key).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("JSON");
    let anchors = body["anchors"].as_array().expect("anchors array");
    // Fresh DB: no checkpoints anchored yet.
    assert!(
        anchors.is_empty(),
        "expected no anchors on a fresh DB, got {}",
        anchors.len()
    );
}

#[tokio::test]
async fn list_anchors_honours_limit_param() {
    let h = common::boot().await;
    let resp =
        common::get_with_key(&h.client, &common::url(h, "/anchors?limit=5"), &h.api_key).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.json::<Value>().await.expect("JSON")["anchors"].is_array());
}

#[tokio::test]
async fn list_anchors_without_auth_is_401() {
    let h = common::boot().await;
    let resp = h
        .client
        .get(common::url(h, "/anchors"))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_unknown_anchor_json_is_404() {
    let h = common::boot().await;
    let resp = common::get_with_key(
        &h.client,
        &common::url(h, &format!("/anchors/{MISSING_ANCHOR_ID}")),
        &h.api_key,
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn get_unknown_anchor_receipt_is_404() {
    let h = common::boot().await;
    let resp = common::get_with_key(
        &h.client,
        &common::url(h, &format!("/anchors/{MISSING_ANCHOR_ID}/receipt")),
        &h.api_key,
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn get_anchor_with_malformed_uuid_is_4xx() {
    let h = common::boot().await;
    // Path type is `Uuid`; a non-UUID segment fails extraction → 400.
    let resp = common::get_with_key(
        &h.client,
        &common::url(h, "/anchors/not-a-uuid"),
        &h.api_key,
    )
    .await;
    let s = resp.status().as_u16();
    assert!(
        (400..500).contains(&s),
        "malformed UUID should be 4xx, got {s}"
    );
}

/// Migration `0054_immutable_ots_evidence` installs a BEFORE UPDATE OR DELETE
/// trigger making anchor-receipt evidence append-only. Verification advances by
/// inserting a successor row (`supersedes_receipt_id`), never by rewriting the
/// original — this asserts the database enforces that, not just the callers.
///
/// The bounded lease/retry bookkeeping added by migration 0052 must stay
/// mutable, otherwise the OTS upgrade cron cannot record an attempt.
#[tokio::test]
async fn anchor_receipt_evidence_is_append_only() {
    use sqlx::Row;

    let h = common::boot().await;
    let pool = sqlx::PgPool::connect(&h.database_url)
        .await
        .expect("connect to harness database");

    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO anchor_receipts
            (id, anchor_kind, anchored_hash, receipt_blob, target, metadata)
         VALUES ($1, 'ots', $2, $3, 'https://example.invalid/calendar', '{}'::jsonb)",
    )
    .bind(id)
    .bind(vec![0u8; 32])
    .bind(vec![1u8; 8])
    .execute(&pool)
    .await
    .expect("insert receipt");

    // Evidence columns are frozen.
    let rewrite = sqlx::query("UPDATE anchor_receipts SET verified_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
    let error = rewrite.expect_err("rewriting verified_at must be rejected");
    assert!(
        error.to_string().contains("immutable"),
        "expected the immutability trigger, got: {error}"
    );

    let metadata =
        sqlx::query("UPDATE anchor_receipts SET metadata = '{\"x\":1}'::jsonb WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await;
    assert!(
        metadata.is_err(),
        "rewriting metadata must be rejected by the trigger"
    );

    // Deletion is refused outright.
    let deleted = sqlx::query("DELETE FROM anchor_receipts WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
    let error = deleted.expect_err("deleting evidence must be rejected");
    assert!(
        error.to_string().contains("append-only"),
        "expected the append-only trigger, got: {error}"
    );

    // Migration 0052's retry bookkeeping stays writable.
    sqlx::query(
        "UPDATE anchor_receipts
            SET ots_upgrade_attempts = ots_upgrade_attempts + 1,
                ots_last_upgrade_attempt_at = NOW()
          WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .expect("retry bookkeeping must remain mutable");

    // The row itself survived every rejected mutation.
    let row =
        sqlx::query("SELECT verified_at, ots_upgrade_attempts FROM anchor_receipts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("receipt still present");
    assert!(
        row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("verified_at")
            .expect("verified_at")
            .is_none(),
        "verified_at must be unchanged"
    );
    assert_eq!(
        row.try_get::<i32, _>("ots_upgrade_attempts")
            .expect("attempts"),
        1
    );
}
