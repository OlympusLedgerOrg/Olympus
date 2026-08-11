// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Historical redaction/ingest issuer keys (migration 0057,
//! docs/key-rotation.md — key-rotation series part 4.5).
//!
//! Exercises `bootstrap::ensure_ingest_signing_key` — called automatically at
//! startup with the resolved Ed25519 verifying key — directly against the
//! shared cluster, plus `GET /redaction/issuer-key`'s `history` field and the
//! single-active-ingest-key partial unique index.
//!
//! Deliberately ONE `#[tokio::test]`, not several. `ensure_ingest_signing_key`
//! enforces a genuinely global invariant (at most one active `ingest_signing`
//! row across the whole database — migration 0057's partial unique index),
//! and `cargo test`'s default in-process thread-per-test concurrency runs
//! every test function in this binary against the *same* shared cluster
//! (`common::boot()` is a process-wide singleton). Two test functions each
//! independently driving their own supersession chain would race and
//! supersede *each other's* rows — not a test artifact, a structural
//! consequence of the single-active-row invariant this function exists to
//! enforce. One test, one sequential driver, avoids that entirely.
//!
//! The `history` assertions call the `get_issuer_key` handler directly with a
//! manually assembled `AppState` rather than going through the shared test
//! server (`common::boot()`): that harness's `AppState`
//! (`tests/common/mod.rs::init`) deliberately mirrors only the DB + BJJ-key
//! parts of `main.rs`'s startup, not the ingest-signing-key resolution, so
//! `state.ingest_signing_key` is always `None` there — same pattern this
//! module's own unit tests already use (`AppState::new(None)` + manual field
//! assignment), just with a real pool instead of `None`.

use crate::common;

use axum::extract::State;
use olympus_tauri_lib::api::redaction::issuer_key::get_issuer_key;
use olympus_tauri_lib::bootstrap::ensure_ingest_signing_key;
use olympus_tauri_lib::state::AppState;
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
async fn ensure_ingest_signing_key_registers_supersedes_and_reports_history() {
    let h = common::boot().await;
    let pool = PgPool::connect(&h.database_url).await.expect("pool");

    // Nothing else in this test binary calls `ensure_ingest_signing_key` —
    // the shared harness's own server never resolves an ingest key at all
    // (see module doc comment) — so this table starts empty for this
    // purpose and every row observed below was created by this test, in
    // this order. That determinism is what makes the exact-count assertions
    // meaningful despite running against the shared cluster.
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

    // GET /redaction/issuer-key's `history` field, exercised by calling the
    // handler directly (see module doc comment) with a real pool so its SQL
    // query + response shape are checked end-to-end against the exact three
    // rows this test just created.
    let mut state = AppState::new(Some(pool));
    state.ingest_signing_key = Some(std::sync::Arc::new(zeroize::Zeroizing::new([9u8; 32])));

    let body = get_issuer_key(State(state))
        .await
        .expect("must return the public key")
        .0;

    // Existing field is unchanged — back-compat with the audit UI's auto-fill.
    assert_eq!(body.ed25519_pubkey_hex.len(), 64);

    assert_eq!(
        body.history.len(),
        3,
        "history must report exactly A, B, and C, got: {:?}",
        body.history
    );

    let a_entry = body
        .history
        .iter()
        .find(|e| e.ed25519_pubkey_hex == key_a)
        .expect("key A present in history");
    assert!(
        a_entry.valid_until.is_some(),
        "superseded key A must have a non-null validUntil"
    );

    let c_entry = body
        .history
        .iter()
        .find(|e| e.ed25519_pubkey_hex == key_c)
        .expect("key C present in history");
    assert!(
        c_entry.valid_until.is_none(),
        "the currently active key C must have a null validUntil"
    );
    assert!(
        c_entry.valid_from.is_some(),
        "a superseding key's validFrom must be set (not the unbounded-first-key case)"
    );
}
