// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Redaction blind-secret fingerprint registry (migration 0058,
//! docs/key-rotation.md — follow-up to "Require independent redaction blind
//! secret in production").
//!
//! Exercises `bootstrap::ensure_redaction_blind_secret_fingerprint` directly
//! against the shared cluster: first-ever registration, an unchanged restart
//! being a no-op, a changed fingerprint being REFUSED (registry untouched)
//! without `OLYMPUS_BLIND_SECRET_ROTATION=confirm`, and the confirmed
//! supersession chain — plus that only the fingerprint, never the raw
//! secret, ever lands in the registry.
//!
//! Deliberately ONE `#[tokio::test]`, same reasoning as
//! `ingest_signing_key_registry.rs`: `ensure_redaction_blind_secret_fingerprint`
//! enforces a single-active-row invariant (migration 0058's partial unique
//! index) across the whole shared-cluster database, and `cargo test` runs
//! every test function in this binary concurrently against that one
//! cluster. Two test functions each independently driving their own
//! supersession chain would race and supersede *each other's* rows.

use crate::common;

use olympus_tauri_lib::bootstrap::ensure_redaction_blind_secret_fingerprint;
use olympus_tauri_lib::state::fingerprint_redaction_blind_secret;
use sqlx::PgPool;

async fn blind_secret_rows(pool: &PgPool) -> Vec<(String, String, bool)> {
    sqlx::query_as(
        "SELECT key_id, public_key, revoked_at IS NULL FROM account_signing_keys \
         WHERE purpose = 'redaction_blind_secret' ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .expect("query redaction_blind_secret rows")
}

/// Guards `OLYMPUS_BLIND_SECRET_ROTATION`, restoring whatever value (or
/// absence) it had on drop. Nothing else in this binary reads that var, so no
/// cross-test mutex is needed beyond this test function being the sole owner
/// of the mutation for its own duration.
struct RotationConfirmGuard {
    old: Option<String>,
}

impl RotationConfirmGuard {
    fn set(value: &str) -> Self {
        let old = std::env::var("OLYMPUS_BLIND_SECRET_ROTATION").ok();
        std::env::set_var("OLYMPUS_BLIND_SECRET_ROTATION", value);
        Self { old }
    }
}

impl Drop for RotationConfirmGuard {
    fn drop(&mut self) {
        match self.old.take() {
            Some(v) => std::env::set_var("OLYMPUS_BLIND_SECRET_ROTATION", v),
            None => std::env::remove_var("OLYMPUS_BLIND_SECRET_ROTATION"),
        }
    }
}

#[tokio::test]
async fn ensure_redaction_blind_secret_fingerprint_registers_gates_and_supersedes() {
    let h = common::boot().await;
    let pool = PgPool::connect(&h.database_url).await.expect("pool");
    // Belt-and-suspenders: nothing else in this binary sets this var, but
    // make sure a leftover from a prior failed run doesn't leak in.
    std::env::remove_var("OLYMPUS_BLIND_SECRET_ROTATION");

    let secret_a = [0x11u8; 32];
    let secret_b = [0x22u8; 32];
    let secret_c = [0x33u8; 32];
    let fp_a = fingerprint_redaction_blind_secret(&secret_a);
    let fp_b = fingerprint_redaction_blind_secret(&secret_b);
    let fp_c = fingerprint_redaction_blind_secret(&secret_c);

    // Nothing else in this test binary calls this function — the shared
    // harness's own server never resolves a blind secret at all — so this
    // purpose starts empty and every row observed below was created by this
    // test, in this order.
    let adopted = ensure_redaction_blind_secret_fingerprint(&pool, &fp_a)
        .await
        .expect("first registration must not error");
    assert!(adopted, "first-ever fingerprint must be adopted");
    let rows = blind_secret_rows(&pool).await;
    let a_row = rows
        .iter()
        .find(|(_, pk, _)| pk == &fp_a)
        .expect("fingerprint A row exists");
    assert!(a_row.2, "freshly registered fingerprint must be active");
    assert_eq!(rows.len(), 1);

    // The registry must never store the raw secret — only its fingerprint.
    assert_ne!(
        a_row.1,
        hex::encode(secret_a),
        "public_key must be the fingerprint, never the raw secret's own hex encoding"
    );

    // Re-ensuring the SAME fingerprint must be a no-op: no second row, no
    // supersession churn on every restart when the secret hasn't changed.
    let adopted = ensure_redaction_blind_secret_fingerprint(&pool, &fp_a)
        .await
        .expect("idempotent re-ensure must not error");
    assert!(adopted, "an unchanged fingerprint must be reported adopted");
    let rows_after_noop = blind_secret_rows(&pool).await;
    assert_eq!(
        rows_after_noop.len(),
        1,
        "re-ensuring the same fingerprint must not insert a duplicate row"
    );

    // A DIFFERENT fingerprint, with NO confirm flag set, must be REFUSED —
    // no write, registry stays exactly as it was on fingerprint A.
    std::env::remove_var("OLYMPUS_BLIND_SECRET_ROTATION");
    let adopted = ensure_redaction_blind_secret_fingerprint(&pool, &fp_b)
        .await
        .expect("a refusal must be a clean Ok(false), not an error");
    assert!(
        !adopted,
        "an unconfirmed fingerprint change must be refused"
    );
    let rows = blind_secret_rows(&pool).await;
    assert_eq!(
        rows.len(),
        1,
        "a refused rotation must not write any new row"
    );
    assert_eq!(
        rows[0].1, fp_a,
        "the active row must remain fingerprint A after a refused rotation"
    );
    assert!(rows[0].2, "fingerprint A must remain active (unrevoked)");

    // Same fingerprint B, now WITH the confirm flag: must supersede A
    // (append-only — A's row stays, now revoked) and activate B.
    {
        let _guard = RotationConfirmGuard::set("confirm");
        let adopted = ensure_redaction_blind_secret_fingerprint(&pool, &fp_b)
            .await
            .expect("confirmed rotation must not error");
        assert!(adopted, "a confirmed rotation must be adopted");
    }
    let rows = blind_secret_rows(&pool).await;
    let a_row = rows.iter().find(|(_, pk, _)| pk == &fp_a).expect("A row");
    assert!(
        !a_row.2,
        "superseded fingerprint A must now be revoked, not deleted"
    );
    let b_row = rows.iter().find(|(_, pk, _)| pk == &fp_b).expect("B row");
    assert!(b_row.2, "fingerprint B must now be the active row");
    assert_eq!(rows.len(), 2, "supersession is append-only — A must remain");

    // Rotate again to C (still confirmed) — the chain must stay append-only
    // across multiple supersessions, and the single-active-row partial
    // unique index (migration 0058) must never be violated.
    {
        let _guard = RotationConfirmGuard::set("confirm");
        let adopted = ensure_redaction_blind_secret_fingerprint(&pool, &fp_c)
            .await
            .expect("second confirmed rotation must not error");
        assert!(adopted);
    }
    let rows = blind_secret_rows(&pool).await;
    let active: Vec<_> = rows.iter().filter(|(_, _, active)| *active).collect();
    assert_eq!(
        active.len(),
        1,
        "exactly one active redaction_blind_secret row must exist at any time"
    );
    assert_eq!(active[0].1, fp_c);
    assert_eq!(
        rows.len(),
        3,
        "A, B, and C must all still be present — supersession is append-only"
    );

    // The migration's partial unique index: a second ACTIVE row for this
    // purpose is structurally impossible, even bypassing the bootstrap fn.
    let dup = sqlx::query(
        "INSERT INTO account_signing_keys
             (key_id, user_id, public_key, label, purpose, created_at)
         VALUES ($1, '00000000-0000-0000-0000-000000000001', $2, 'dup', 'redaction_blind_secret', NOW())",
    )
    .bind(common::unique_id("dup-blind-secret"))
    .bind("f".repeat(64))
    .execute(&pool)
    .await;
    let err = format!(
        "{:?}",
        dup.expect_err("second active redaction_blind_secret row must be rejected")
    );
    assert!(
        err.contains("ix_account_signing_keys_single_active_blind_secret"),
        "rejection must come from the single-active-blind-secret index: {err}"
    );

    std::env::remove_var("OLYMPUS_BLIND_SECRET_ROTATION");
}
