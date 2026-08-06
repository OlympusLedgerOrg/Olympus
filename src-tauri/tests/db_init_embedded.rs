// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Startup coverage for [`olympus_tauri_lib::db::init_embedded`] — the exact
//! embedded-PostgreSQL entry point the desktop binary runs at launch.
//!
//! ## Why this file exists
//!
//! The shared `tests/common` harness drives `PgEmbed` **directly**
//! (`PgEmbed::new` + `setup` + `start_db`). That exercises pg_embed, but it
//! never reaches Olympus's own post-start arming/verification step
//! (`db::process_identity::arm_verified_postgres` →`verify_owned_process` →
//! `verify_identity`). PR #1486 tightened that step — it required a `-F`
//! (fsync-off) flag in the observed argv that `PgEmbed::start_db` never
//! passes, and compared sysinfo's derived process start time against
//! PostgreSQL's `time(NULL)` pidfile stamp with exact equality — so every
//! embedded start failed with `UnverifiableProcess` / `ReusedPid`. The whole
//! embedded-Postgres CI job stayed green, because nothing in it called
//! `init_embedded`.
//!
//! This test closes that gap: it calls `init_embedded` against a temp app-data
//! directory and asserts it hands back a *usable*, *migrated* pool. Any
//! regression in the arming step now fails the build.
//!
//! ## Serialisation
//!
//! `db::PG_PORT` is a private const (`5433`) with no environment override, so
//! this binary owns that port for its duration. It is listed in
//! `scripts/embedded-postgres-tests.sh` and therefore runs under
//! `cargo test … -- --test-threads=1`, sequentially with the other pg_embed
//! binaries (which pick ephemeral ports of their own).
//!
//! Cold-cache cost: pg_embed downloads the pinned PG 15 binaries into the OS
//! cache dir on first use, exactly as the shared harness does; warm runs reuse
//! them and pay only initdb + startup + migrations.

use std::net::TcpListener;

use olympus_tauri_lib::db;

/// Mirrors the private `db::PG_PORT`. Kept as a local const purely so the
/// pre-flight check below can report which port is contended.
const EMBEDDED_PG_PORT: u16 = 5433;

/// Fail early — and legibly — when something already holds the embedded port.
///
/// Deliberately a panic, not a skip: a silent skip would let exactly the class
/// of regression this file exists to catch sail through CI looking green.
fn require_free_embedded_port() {
    if let Err(error) = TcpListener::bind(("127.0.0.1", EMBEDDED_PG_PORT)) {
        panic!(
            "127.0.0.1:{EMBEDDED_PG_PORT} is already in use ({error}). \
             `db::init_embedded` hard-codes that port, so this test needs it \
             free — stop any running Olympus desktop instance or other \
             PostgreSQL bound there and re-run."
        );
    }
    // The listener is dropped here so PostgreSQL can claim the port. Same
    // tiny TOCTOU window the shared harness accepts for its ephemeral ports.
}

/// Assert the pool `init_embedded` returned is actually connected and carries
/// the authoritative schema — i.e. startup got all the way through arming,
/// pool connect, and `sqlx::migrate!`.
async fn assert_pool_is_usable_and_migrated(pool: &sqlx::PgPool, phase: &str) {
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("{phase}: pool must answer a trivial query: {error}"));
    assert_eq!(one, 1, "{phase}: unexpected result from SELECT 1");

    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("{phase}: migration ledger must be readable: {error}"));
    assert!(
        applied > 0,
        "{phase}: init_embedded must apply the sqlx migrations, found {applied} successful rows"
    );

    // A representative authoritative table, so a truncated/failed migration
    // run cannot pass on the row count alone.
    let api_keys_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public.api_keys') IS NOT NULL")
            .fetch_one(pool)
            .await
            .unwrap_or_else(|error| panic!("{phase}: to_regclass probe failed: {error}"));
    assert!(
        api_keys_exists,
        "{phase}: migrations ran but public.api_keys is missing"
    );
}

/// Shut an [`db::EmbeddedDb`] down the way `main.rs` does, so the next phase
/// (and the `TempDir` cleanup) starts from a quiesced cluster.
async fn shutdown(mut embedded: db::EmbeddedDb, phase: &str) {
    embedded.pool.close().await;
    embedded
        .pg
        .stop_db()
        .await
        .unwrap_or_else(|error| panic!("{phase}: embedded PostgreSQL must stop cleanly: {error}"));
    // Dropping the `EmbeddedDb` releases the OS instance lock, which the warm
    // start below re-acquires. `PgEmbed`'s own Drop is a no-op now that exit
    // has been confirmed.
    drop(embedded);
}

/// Call `init_embedded`, and on failure surface `olympus-pg-debug.log` before
/// panicking.
///
/// `init_embedded`'s own error text is deliberately operator-safe (it omits
/// paths and diagnostics), and pg_embed routes every child process's stdio to
/// the null device — so without this dump a CI failure says only "lifecycle
/// operation failed" with no indication of which stage broke.
async fn init_or_dump(app_data_dir: &std::path::Path, phase: &str) -> db::EmbeddedDb {
    match db::init_embedded(app_data_dir).await {
        Ok(embedded) => embedded,
        Err(error) => {
            let log = app_data_dir.join("olympus-pg-debug.log");
            let contents = std::fs::read_to_string(&log)
                .unwrap_or_else(|read_error| format!("<unreadable: {read_error}>"));
            panic!(
                "{phase}: init_embedded failed: {error}\n--- olympus-pg-debug.log ---\n{contents}"
            );
        }
    }
}

/// Cold start (initdb + create database + migrate) followed by a warm restart
/// against the same persistent cluster.
///
/// Both phases go through `arm_verified_postgres`; the warm phase additionally
/// covers the `cluster_existed` branch (stored-password reuse and the
/// stale-`postmaster.pid` presence probe) that every launch after the first
/// takes in production.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_embedded_arms_verifies_and_returns_a_migrated_pool() {
    require_free_embedded_port();

    let app_data = tempfile::Builder::new()
        .prefix("olympus-init-embedded-")
        .tempdir()
        .expect("create temp app-data dir");

    let cold = init_or_dump(app_data.path(), "cold start").await;
    assert_pool_is_usable_and_migrated(&cold.pool, "cold start").await;
    shutdown(cold, "cold start").await;

    let warm = init_or_dump(app_data.path(), "warm restart").await;
    assert_pool_is_usable_and_migrated(&warm.pool, "warm restart").await;
    shutdown(warm, "warm restart").await;
}
