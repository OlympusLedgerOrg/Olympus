// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Historical redaction/ingest issuer keys (migration 0057,
//! docs/key-rotation.md — key-rotation series part 4.5).
//!
//! Exercises `bootstrap::ensure_ingest_signing_key` — called automatically at
//! startup with the resolved Ed25519 verifying key — directly against the
//! shared cluster, plus `GET /redaction/issuer-key`'s `history` field and the
//! single-active-ingest-key partial unique index.

use crate::common;

use olympus_tauri_lib::bootstrap::ensure_ingest_signing_key;
use serde_json::Value;
use sqlx::PgPool;

async fn ingest_rows(pool: &PgPool) -> Vec<(String, String, bool)> {
    sqlx::query_as(
        "SELECT key_id, public_key, revoked_at IS NULL FROM account_signing_keys \
         WHERE purpose = 'ingest_signing' ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .expect("query ingest_signing rows")
}

#[tokio::test]
async fn ensure_ingest_signing_key_registers_and_supersedes() {
    let h = common::boot().await;
    let pool = PgPool::connect(&h.database_url).await.expect("pool");

    // The booted server already resolved and registered its own ingest key on
    // startup — isolate this test's assertions to a distinct synthetic pubkey
    // so it doesn't depend on (or corrupt) that row.
    let key_a = "a".repeat(64);
    let key_b = "b".repeat(64);
    let key_c = "c".repeat(64);

    ensure_ingest_signing_key(&pool, &key_a)
        .await
        .expect("register first key");
    let rows = ingest_rows(&pool).await;
    let a_row = rows
        .iter()
        .find(|(_, pk, _)| pk == &key_a)
        .expect("key A row exists");
    assert!(
        a_row.2,
        "freshly registered key must be active (not revoked)"
    );

    // Re-registering the SAME key must be a no-op — no second row, no
    // supersession churn on every restart when the key hasn't changed.
    ensure_ingest_signing_key(&pool, &key_a)
        .await
        .expect("idempotent re-register");
    let rows_after_noop = ingest_rows(&pool).await;
    assert_eq!(
        rows_after_noop
            .iter()
            .filter(|(_, pk, _)| pk == &key_a)
            .count(),
        1,
        "re-registering the same key must not insert a duplicate row"
    );

    // Rotating to key B must supersede A (append-only: A's row stays, now
    // revoked) and activate B.
    ensure_ingest_signing_key(&pool, &key_b)
        .await
        .expect("supersede to key B");
    let rows = ingest_rows(&pool).await;
    let a_row = rows.iter().find(|(_, pk, _)| pk == &key_a).expect("A row");
    assert!(
        !a_row.2,
        "superseded key A must now be revoked, not deleted"
    );
    let b_row = rows.iter().find(|(_, pk, _)| pk == &key_b).expect("B row");
    assert!(b_row.2, "key B must now be the active row");

    // Rotate again to C — the chain must stay append-only across multiple
    // supersessions, and the single-active-ingest partial unique index
    // (migration 0057) must never be violated by this path.
    ensure_ingest_signing_key(&pool, &key_c)
        .await
        .expect("supersede to key C");
    let rows = ingest_rows(&pool).await;
    let active: Vec<_> = rows.iter().filter(|(_, _, active)| *active).collect();
    assert_eq!(
        active.len(),
        1,
        "exactly one active ingest_signing row must exist at any time"
    );
    assert_eq!(active[0].1, key_c);
    assert_eq!(
        rows.len(),
        3,
        "A, B, and C must all still be present — supersession is append-only"
    );
}

#[tokio::test]
async fn issuer_key_endpoint_reports_history() {
    let h = common::boot().await;
    let pool = PgPool::connect(&h.database_url).await.expect("pool");

    // Register a couple of synthetic historical keys so `history` is
    // guaranteed non-trivial regardless of what the live server's own key
    // resolution already wrote.
    let key_old = "d".repeat(64);
    ensure_ingest_signing_key(&pool, &key_old)
        .await
        .expect("register old key");
    let key_new = "e".repeat(64);
    ensure_ingest_signing_key(&pool, &key_new)
        .await
        .expect("supersede to new key");

    let res = h
        .client
        .get(common::url(h, "/redaction/issuer-key"))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.expect("JSON");

    // Existing field is unchanged — back-compat with the audit UI's auto-fill.
    assert!(body["ed25519PubkeyHex"].is_string());

    let history = body["history"].as_array().expect("history is an array");
    assert!(
        history.len() >= 2,
        "history must include at least the two synthetic keys registered above, got: {history:?}"
    );

    let old_entry = history
        .iter()
        .find(|e| e["ed25519PubkeyHex"] == key_old)
        .expect("old key present in history");
    assert!(
        !old_entry["validUntil"].is_null(),
        "superseded key must have a non-null validUntil"
    );

    let new_entry = history
        .iter()
        .find(|e| e["ed25519PubkeyHex"] == key_new)
        .expect("new key present in history");
    assert!(
        new_entry["validUntil"].is_null(),
        "the currently active key must have a null validUntil"
    );
    assert!(
        !new_entry["validFrom"].is_null(),
        "a superseding key's validFrom must be set (not the unbounded-first-key case)"
    );
}
