// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! End-to-end coverage for `db::init_embedded`, the embedded-PostgreSQL entry
//! point every desktop launch goes through.
//!
//! The shared `tests/common` harness deliberately does **not** exercise this
//! path: it drives `PgEmbed` directly and arms its own `atexit` guard, so it
//! never touches `try_init_embedded`'s cluster probe, `patch_pg_conf`,
//! credential persistence, or — critically — `arm_verified_postgres`, the
//! process-identity gate added in #1486. A regression that makes arming reject
//! the postmaster Olympus itself just started leaves every existing test green
//! while the shipped app refuses to boot. This test closes that gap.
//!
//! Two phases against one persistent cluster:
//!
//! 1. **Cold start** — no `PG_VERSION`, so `initdb` runs, the credential file
//!    is created, the database is created, and migrations apply from scratch.
//! 2. **Warm restart** — the same `app_data_dir` is re-initialised after the
//!    first `EmbeddedDb` is dropped. This is the `cluster_existed == true`
//!    branch, which every launch after the very first one takes, and which
//!    additionally covers stored-credential reuse and migration idempotence.
//!
//! Database: always an embedded cluster on the private `db::PG_PORT` (5433).
//! That port is a private const with no environment override, so this test owns
//! it for the duration of the run — hence the serial job in
//! `scripts/embedded-postgres-tests.sh`.

use olympus_tauri_lib::db::{self, EmbeddedDb};
use sqlx::Row;
use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

/// Mirrors the private `db::PG_PORT`. Not importable, so
/// `assert_pool_is_live_and_migrated` re-derives the live server's port from
/// the connection itself and fails if this copy has drifted.
const PG_PORT: u16 = 5433;

/// `init_embedded`'s error text is intentionally operator-safe (no paths, no
/// PIDs, no command lines), and pg-embed routes child stdio to the null device.
/// On CI that reduces a failure to a single opaque sentence. The debug log is
/// the only place the per-step trace survives, so dump it before panicking.
fn panic_with_debug_log(app_data_dir: &Path, context: &str, error: &dyn std::fmt::Display) -> ! {
    let log = app_data_dir.join("olympus-pg-debug.log");
    let trace = std::fs::read_to_string(&log)
        .unwrap_or_else(|read_error| format!("<olympus-pg-debug.log unreadable: {read_error}>"));
    panic!("{context}: {error}\n--- olympus-pg-debug.log ---\n{trace}\n--- end ---");
}

/// Fail loudly rather than skipping. A silent skip is how a boot regression
/// reaches a release looking green, which is the exact failure class this test
/// exists to catch.
fn require_free_pg_port() {
    if let Err(error) = TcpListener::bind(("127.0.0.1", PG_PORT)) {
        panic!(
            "127.0.0.1:{PG_PORT} is already in use ({error}). `db::init_embedded` hardcodes this \
             port with no environment override, so this test needs exclusive use of it. Stop the \
             other listener (a stray embedded postmaster, or a second copy of this test running \
             concurrently) and re-run. See scripts/embedded-postgres-tests.sh — these binaries \
             must run serially."
        );
    }
}

/// Wait for the port a just-dropped `EmbeddedDb` was using to come back.
/// `Drop` terminates the postmaster synchronously, but the listening socket can
/// linger for a moment after the process exits.
fn wait_for_pg_port_release() {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpListener::bind(("127.0.0.1", PG_PORT)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "embedded PostgreSQL still holding 127.0.0.1:{PG_PORT} 30s after EmbeddedDb::drop; \
             the reaper did not terminate the cluster"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Assert the returned pool is genuinely live and fully migrated, not merely
/// constructed. `init_embedded` returning `Ok` is not the claim under test —
/// the claim is that the caller receives a usable, migrated database.
///
/// Query failures here mean the cluster died or was never really serving, so
/// they route through [`panic_with_debug_log`] for the same reason startup
/// failures do. Assertion failures do not: those already name the exact
/// mismatched value, and the lifecycle trace adds nothing.
async fn assert_pool_is_live_and_migrated(db: &EmbeddedDb, app_data_dir: &Path, phase: &str) {
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&db.pool)
        .await
        .unwrap_or_else(|error| {
            panic_with_debug_log(app_data_dir, &format!("{phase}: SELECT 1"), &error)
        });
    assert_eq!(one, 1, "{phase}: SELECT 1 returned the wrong value");

    let applied: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = TRUE")
            .fetch_one(&db.pool)
            .await
            .unwrap_or_else(|error| {
                panic_with_debug_log(
                    app_data_dir,
                    &format!("{phase}: reading _sqlx_migrations"),
                    &error,
                )
            });
    assert!(
        applied > 0,
        "{phase}: _sqlx_migrations has no successful rows — init_embedded returned a pool that \
         never ran `sqlx::migrate!`"
    );

    let failed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = FALSE")
            .fetch_one(&db.pool)
            .await
            .unwrap_or_else(|error| {
                panic_with_debug_log(
                    app_data_dir,
                    &format!("{phase}: reading failed migrations"),
                    &error,
                )
            });
    assert_eq!(failed, 0, "{phase}: some migrations are recorded as failed");

    // A table any Olympus schema must have, proving the migrations that ran are
    // this repository's and not an unrelated cluster's.
    let api_keys_exists: bool =
        sqlx::query("SELECT to_regclass('public.api_keys') IS NOT NULL AS present")
            .fetch_one(&db.pool)
            .await
            .unwrap_or_else(|error| {
                panic_with_debug_log(
                    app_data_dir,
                    &format!("{phase}: probing public.api_keys"),
                    &error,
                )
            })
            .get("present");
    assert!(
        api_keys_exists,
        "{phase}: public.api_keys is missing — the pool is not pointed at a migrated Olympus \
         database"
    );

    // `PG_PORT` above is a hand-copy of a private const. Re-derive the real
    // port from the live connection so a change in `db.rs` surfaces here rather
    // than silently weakening this test's exclusive-port assumption.
    let server_port: i32 = sqlx::query_scalar("SELECT inet_server_port()")
        .fetch_one(&db.pool)
        .await
        .unwrap_or_else(|error| {
            panic_with_debug_log(
                app_data_dir,
                &format!("{phase}: reading inet_server_port()"),
                &error,
            )
        });
    assert_eq!(
        server_port,
        i32::from(PG_PORT),
        "{phase}: init_embedded connected to port {server_port}, but this test reserves \
         {PG_PORT}. `db::PG_PORT` changed — update the copy in this file and in \
         scripts/embedded-postgres-tests.sh's serial-job rationale."
    );

    applied_migration_count_is_stable(applied, phase);
}

/// Records the cold-start migration count so the warm restart can assert it did
/// not change — migrations must be idempotent across launches.
fn applied_migration_count_is_stable(applied: i64, phase: &str) {
    use std::sync::OnceLock;
    static COLD_START_COUNT: OnceLock<i64> = OnceLock::new();
    match COLD_START_COUNT.get() {
        None => {
            let _ = COLD_START_COUNT.set(applied);
        }
        Some(cold) => assert_eq!(
            *cold, applied,
            "{phase}: applied-migration count changed across a restart ({cold} → {applied}); \
             `sqlx::migrate!` is re-running or reverting work on warm launches"
        ),
    }
}

#[tokio::test]
async fn init_embedded_boots_migrates_and_survives_a_restart() {
    require_free_pg_port();

    let temp = tempfile::tempdir().expect("temp app-data dir");
    let app_data_dir = temp.path();

    // ── Phase 1: cold start (initdb → arm → create database → migrate) ──
    let cold = match db::init_embedded(app_data_dir).await {
        Ok(db) => db,
        Err(error) => panic_with_debug_log(app_data_dir, "cold start: init_embedded", &error),
    };
    assert!(
        app_data_dir.join("olympus-pg").join("PG_VERSION").is_file(),
        "cold start: no PG_VERSION — initdb never produced a cluster"
    );
    assert_pool_is_live_and_migrated(&cold, app_data_dir, "cold start").await;

    cold.pool.close().await;
    drop(cold);
    wait_for_pg_port_release();

    // ── Phase 2: warm restart on the same persistent cluster ──
    // This is the `cluster_existed == true` path in `try_init_embedded`: it
    // reuses the persisted credential, skips database creation, and re-runs
    // `sqlx::migrate!` against an already-migrated schema.
    let warm = match db::init_embedded(app_data_dir).await {
        Ok(db) => db,
        Err(error) => panic_with_debug_log(app_data_dir, "warm restart: init_embedded", &error),
    };
    assert_pool_is_live_and_migrated(&warm, app_data_dir, "warm restart").await;

    warm.pool.close().await;
    drop(warm);
    wait_for_pg_port_release();
}
