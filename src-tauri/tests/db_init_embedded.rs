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
//! Database: always an embedded cluster, on whatever port `db::pg_port()`
//! resolves — `OLYMPUS_PG_PORT` when it is set and valid (audit G-P2-2),
//! otherwise the 5433 default. The test reads that function rather than a
//! hand-copied constant so it reserves the port the app will really bind; the
//! serial job in `scripts/embedded-postgres-tests.sh` exists because whichever
//! port that is, this test owns it exclusively.

use olympus_tauri_lib::db::{self, EmbeddedDb};
use sqlx::Row;
use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

/// The port `db::init_embedded` will actually bind.
///
/// Read through `db::pg_port()` rather than a hand-copied constant: the port is
/// no longer a private const with no override, so a copy would keep reserving
/// 5433 while the app started on `OLYMPUS_PG_PORT` — guarding a port nothing
/// uses and colliding on the one the cluster takes.
fn pg_port() -> u16 {
    db::pg_port()
}

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
    let port = pg_port();
    if let Err(error) = TcpListener::bind(("127.0.0.1", port)) {
        panic!(
            "127.0.0.1:{port} is already in use ({error}). `db::init_embedded` binds this port \
             (`OLYMPUS_PG_PORT` when set and valid, otherwise 5433), so this test needs \
             exclusive use of it. Stop the other listener (a stray embedded postmaster, or a \
             second copy of this test running concurrently) and re-run. See \
             scripts/embedded-postgres-tests.sh — these binaries must run serially."
        );
    }
}

/// Wait for the port a just-dropped `EmbeddedDb` was using to come back.
/// `Drop` terminates the postmaster synchronously, but the listening socket can
/// linger for a moment after the process exits.
fn wait_for_pg_port_release() {
    let port = pg_port();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "embedded PostgreSQL still holding 127.0.0.1:{port} 30s after EmbeddedDb::drop; \
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

    // Re-derive the real port from the live connection: `db::pg_port()` is a
    // lazily-initialised OnceLock, so confirm the server the pool actually
    // reached is the one `require_free_pg_port` reserved.
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
    let expected_port = pg_port();
    assert_eq!(
        server_port,
        i32::from(expected_port),
        "{phase}: init_embedded connected to port {server_port}, but this test reserves \
         {expected_port}. The port the app resolves and the port this test reserved have \
         diverged — check OLYMPUS_PG_PORT handling in src-tauri/src/db and the serial-job \
         rationale in scripts/embedded-postgres-tests.sh."
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
