//! Shared test harness for the `api_*_db.rs` integration tests.
//!
//! Boots **one** `pg_embed` instance + Axum server per test binary and
//! shares them across every `#[tokio::test]` in the file.
//!
//! ## Why a dedicated runtime thread
//!
//! `#[tokio::test]` gives **each** test its own (current-thread) runtime,
//! created and then *destroyed* when that test returns. A `PgPool` — and
//! the Axum server task — pin their background work to the runtime they
//! were created on. If we created the pool inside the first test's
//! runtime and stored it in a shared cell, every *later* test (running on
//! a fresh runtime) would block forever the moment it touched that pool or
//! the server, because the original runtime is gone. (That bug manifests
//! as a hang with the process idle — not a panic.)
//!
//! The fix: PG, the pool, and the Axum server all live on **one dedicated
//! OS thread** running a multi-thread runtime that stays alive for the
//! whole process. Per-test runtimes only ever talk to the server over
//! HTTP (`reqwest`), which is runtime-agnostic for outbound calls. Tests
//! therefore never touch the pool directly — that's deliberate.
//!
//! Each binary picks an ephemeral PG port and a unique temp data dir, so
//! binaries run in parallel without colliding with each other or with a
//! running production instance on the canonical port 5433.
//!
//! Pattern:
//! ```ignore
//! mod common;
//!
//! #[tokio::test]
//! async fn it_works() {
//!     let h = common::boot().await;
//!     let resp = common::get_with_key(&h.client, &common::url(h, "/admin/users"), &h.api_key).await;
//!     assert_eq!(resp.status(), 200);
//! }
//! ```
//!
//! First-run cost: `pg-embed` downloads the PG 17 binaries into the OS
//! cache dir (`%LOCALAPPDATA%/pg-embed/...` on Windows) on the first
//! test run; subsequent runs reuse the cached binaries instantly.

// Different test binaries pull in different subsets of these helpers.
// Suppressing dead_code at the module level keeps the noise out of
// `cargo check --tests` without having to litter individual fns with
// `#[allow(dead_code)]`.
#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::Duration;

use pg_embed::pg_enums::PgAuthMethod;
// PG_V17 matches the binaries pg-embed has likely already cached locally
// (production uses PG_V15, but our migrations are vanilla DDL — no
// version-specific syntax — and PG 17 is a strict superset for the SQL
// surface this codebase touches, so the fidelity loss is nil and the
// first-run download cost goes to ~0 if PG 17 is already on disk).
use pg_embed::pg_fetch::{PgFetchSettings, PG_V17};
use pg_embed::postgres::{PgEmbed, PgSettings};
use sqlx::PgPool;

use olympus_tauri_lib::api::middleware::auth::derive_api_key_from_bjj;
use olympus_tauri_lib::api::trusted_issuers::load_trusted_issuers;
use olympus_tauri_lib::bootstrap;
use olympus_tauri_lib::server;
use olympus_tauri_lib::state::AppState;

/// Everything a test needs to reach the shared server. Plain, `Send +
/// Sync` data only — the pool and the `PgEmbed` handle deliberately live
/// on the dedicated server thread (see module docs), never here.
pub struct TestHarness {
    pub addr: SocketAddr,
    /// System API key minted by [`bootstrap::run`] — has `read`, `write`,
    /// `admin` scopes plus whatever the authority SBT grants.
    pub api_key: String,
    /// Operator-only admin key, sent via `x-admin-key`. The
    /// `require_admin_auth` gate accepts this path independent of any
    /// `users.role` check, which is the cleanest way to drive the
    /// `/admin/*` routes from tests (the bootstrap system user has
    /// `role = 'system'`, not `'admin'`).
    pub admin_key: String,
    /// Async client. Built without a runtime (reqwest only needs one when
    /// a request is actually awaited), so each test's own runtime drives
    /// its outbound calls.
    pub client: reqwest::Client,
}

static HARNESS: OnceLock<TestHarness> = OnceLock::new();

/// Boot — or return the already-booted — shared server for this binary.
///
/// `async` only so existing `common::boot().await` call sites read
/// naturally; the body does no real awaiting. The first call blocks
/// (briefly) on the dedicated server thread's readiness signal; later
/// calls return the cached handle immediately.
pub async fn boot() -> &'static TestHarness {
    HARNESS.get_or_init(boot_blocking)
}

fn boot_blocking() -> TestHarness {
    let (ready_tx, ready_rx) = mpsc::channel::<(SocketAddr, String, String)>();

    std::thread::Builder::new()
        .name("olympus-test-server".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build dedicated test runtime");
            rt.block_on(async move {
                // `_pg` MUST stay bound here: dropping the `PgEmbed` stops
                // the embedded postgres. Holding it across the
                // `pending().await` below keeps PG (and the pool, and the
                // Axum server task spawned by `server::start`) alive for
                // the entire process.
                let Booted {
                    _pg,
                    addr,
                    api_key,
                    admin_key,
                } = init().await;
                ready_tx
                    .send((addr, api_key, admin_key))
                    .expect("send server-ready signal");
                // Park this runtime forever. The per-test `#[tokio::test]`
                // runtimes come and go; this one — and everything it owns —
                // must outlive all of them.
                std::future::pending::<()>().await;
            });
        })
        .expect("spawn dedicated test-server thread");

    let (addr, api_key, admin_key) = ready_rx
        .recv()
        .expect("dedicated server thread failed during init");

    TestHarness {
        addr,
        api_key,
        admin_key,
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client"),
    }
}

/// What [`init`] hands back to the dedicated thread. `_pg` is kept alive
/// by the caller; the rest is forwarded to the test side.
struct Booted {
    _pg: PgEmbed,
    addr: SocketAddr,
    api_key: String,
    admin_key: String,
}

async fn init() -> Booted {
    // Reap embedded-PG clusters leaked by *prior* test runs. The harness
    // parks its `PgEmbed` on a detached thread for the whole process and a
    // `static` cell never runs `Drop`, so a normal test-binary exit leaves
    // postgres running. Left unchecked these pile up (~6-8 procs per run)
    // and eventually thrash the box. We can't reap at our own exit, so we
    // reap at the next run's start.
    //
    // Age-guarded (see `reap_stale_test_pg`): only clusters older than
    // ~2 min are reaped, so a concurrently-running sibling binary's PG
    // (always younger than that for these fast tests) is never touched.
    // Safe whether binaries run serially or in parallel under `cargo test`.
    reap_stale_test_pg();

    // Tests must not interact with the production-mode startup checks
    // (placeholder vkey refusal, ceremony coordinator-sig refusal). Force
    // dev mode regardless of what the operator may have set in their shell.
    std::env::set_var("OLYMPUS_ENV", "test");
    // Keep bootstrap on the "generate a fresh BJJ authority key" path —
    // ignoring any operator-supplied key lets tests stay deterministic
    // about what's in `account_signing_keys` at boot.
    std::env::remove_var("OLYMPUS_BJJ_AUTHORITY_KEY");
    // Force the loopback rate-limit bucket — without this, a previous test
    // run that set `OLYMPUS_TRUST_FORWARDED_FOR=true` would carry over.
    std::env::remove_var("OLYMPUS_TRUST_FORWARDED_FOR");
    // Force an ephemeral Axum port. CLAUDE.md notes tests historically
    // pinned `OLYMPUS_API_PORT=3737`; if that's set in the shell, every
    // parallel test binary would fight over the one port. Unsetting it
    // makes `server::start` bind `127.0.0.1:0`.
    std::env::remove_var("OLYMPUS_API_PORT");
    // Plant an `OLYMPUS_ADMIN_KEY` so `/admin/*` tests can authenticate
    // via the operator path (the bootstrap system user has role 'system',
    // not 'admin', so its API key fails the role check on admin routes).
    let admin_key = "test-admin-key-do-not-use-outside-tests";
    std::env::set_var("OLYMPUS_ADMIN_KEY", admin_key);

    let data_root = make_data_root();
    let pg_port = pick_free_port();
    let pg = start_embedded_pg(&data_root, pg_port).await;
    let pool = open_pool_and_migrate(&pg).await;

    let bootstrap_result = bootstrap::run(&pool)
        .await
        .expect("bootstrap should succeed against a fresh DB");

    // The freshly-generated key is only returned the first time a row is
    // inserted into `api_keys`. On a brand-new DB this run that's true, but
    // it costs nothing to derive the same key client-side as a fallback.
    let api_key = bootstrap_result
        .freshly_generated
        .system_api_key
        .clone()
        .unwrap_or_else(|| derive_api_key_from_bjj(&bootstrap_result.bjj_authority_key));

    let trusted = load_trusted_issuers(Some(&bootstrap_result.bjj_authority_pubkey));

    let mut state = AppState::new(Some(pool));
    state.bjj_authority_key = Some(bootstrap_result.bjj_authority_key);
    state.bjj_authority_pubkey = Some(bootstrap_result.bjj_authority_pubkey);
    state.bjj_trusted_issuers = trusted;

    let addr = server::start(state)
        .await
        .expect("axum server should start");

    // Wait for the server to actually accept connections before any test
    // fires — uses a dedicated client so the probe doesn't depend on the
    // per-test client that doesn't exist yet.
    let probe = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("probe client");
    wait_for_ready(&probe, addr).await;

    Booted {
        _pg: pg,
        addr,
        api_key,
        admin_key: admin_key.to_owned(),
    }
}

/// Age, in seconds, below which a leftover PG cluster is assumed to belong
/// to a *concurrently running* sibling test binary and is left alone.
/// Above it, the cluster is from a prior run and is safe to reap. These
/// tests boot + finish in well under this window, so a live sibling's
/// data dir is always younger than the guard. This makes the reaper safe
/// even when `cargo test` runs the DB binaries in parallel.
const STALE_PG_AGE_SECS: u64 = 120;

/// Kill embedded-PG processes left behind by *previous* runs and remove
/// their data dirs. Best-effort: never panics, ignores every error.
/// Mirrors `src-tauri/src/db.rs::reap_embedded_pg` (which reads the PID
/// from `postmaster.pid` and force-kills it).
///
/// Age-guarded so it never touches a concurrently-running sibling binary's
/// PG — only clusters whose data dir hasn't been modified in the last
/// [`STALE_PG_AGE_SECS`] are reaped.
fn reap_stale_test_pg() {
    let root = std::env::temp_dir().join("olympus-tests");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    for entry in entries.flatten() {
        if !is_older_than(&entry.path(), STALE_PG_AGE_SECS) {
            continue; // likely a live sibling — leave it alone
        }
        let pidfile = entry.path().join("olympus-pg").join("postmaster.pid");
        if let Ok(content) = std::fs::read_to_string(&pidfile) {
            if let Some(pid) = content
                .lines()
                .next()
                .and_then(|l| l.trim().parse::<u32>().ok())
            {
                kill_pid(pid);
            }
        }
        let _ = std::fs::remove_dir_all(entry.path());
    }
}

/// True if `path`'s last-modified time is more than `secs` ago. Returns
/// `false` on any error (fail safe: don't reap what we can't date).
fn is_older_than(path: &std::path::Path, secs: u64) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|mtime| mtime.elapsed().ok())
        .map(|age| age.as_secs() > secs)
        .unwrap_or(false)
}

/// Force-kill a process by PID. Best-effort; shells out so we don't pull
/// in a process crate for one use site (same approach as `db.rs`).
fn kill_pid(pid: u32) {
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    #[cfg(not(target_os = "windows"))]
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn make_data_root() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let dir = std::env::temp_dir()
        .join("olympus-tests")
        .join(format!("{pid}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create test data root");
    dir
}

/// Bind-and-release trick: ask the kernel for any free port, grab it, drop
/// the listener so pg_embed can claim it. Tiny TOCTOU window between drop
/// and PG bind, but the alternative (port-scanning a fixed range) is much
/// more fragile under parallel `cargo test`.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("local addr").port()
}

async fn start_embedded_pg(data_root: &std::path::Path, port: u16) -> PgEmbed {
    let data_dir = data_root.join("olympus-pg");
    let settings = PgSettings {
        database_dir: data_dir.clone(),
        port,
        user: "olympus".into(),
        password: "olympus".into(),
        auth_method: PgAuthMethod::Plain,
        // `persistent: false` would make pg_embed wipe the dir on drop —
        // we want PG to stay alive for the entire test binary, and we
        // clean up by leaving the temp dir for the OS to GC.
        persistent: true,
        timeout: Some(Duration::from_secs(60)),
        migration_dir: None,
    };
    let fetch = PgFetchSettings {
        version: PG_V17,
        ..Default::default()
    };
    let mut pg = PgEmbed::new(settings, fetch).await.expect("PgEmbed::new");
    pg.setup().await.expect("PG setup (initdb)");
    // MUST mirror `src-tauri/src/db.rs::patch_pg_conf` and run BEFORE
    // `start_db()`. On Windows with Hyper-V/WSL, postgres resolving
    // "localhost" tries ::1 first, hits "Permission denied", and
    // `start_db()` HANGS instead of falling through to 127.0.0.1.
    // Forcing `listen_addresses = '127.0.0.1'` skips the IPv6 attempt.
    // (Skipping this patch is what made the first harness draft hang
    // indefinitely on PG startup.)
    patch_pg_conf(&data_dir, port).expect("patch postgresql.conf");
    pg.start_db().await.expect("PG start_db");
    if !pg
        .database_exists("olympus")
        .await
        .expect("database_exists")
    {
        pg.create_database("olympus")
            .await
            .expect("create_database");
    }
    pg
}

/// Append loopback-only `listen_addresses` + the chosen `port` to the
/// freshly-`initdb`'d cluster's `postgresql.conf`. Idempotent — guards on
/// the marker line so a re-run doesn't duplicate it. Mirrors
/// `src-tauri/src/db.rs::patch_pg_conf` (kept as a private copy here so the
/// test harness doesn't force that fn to become `pub`).
fn patch_pg_conf(data_dir: &std::path::Path, port: u16) -> std::io::Result<()> {
    use std::io::Write;
    let conf = data_dir.join("postgresql.conf");
    let existing = std::fs::read_to_string(&conf).unwrap_or_default();
    if !existing.contains("listen_addresses = '127.0.0.1'") {
        let patch = format!(
            "\n# Olympus tests: bind IPv4 only — avoids Windows Hyper-V IPv6 permission errors\nlisten_addresses = '127.0.0.1'\nport = {port}\n"
        );
        let mut f = std::fs::OpenOptions::new().append(true).open(&conf)?;
        f.write_all(patch.as_bytes())?;
    }
    Ok(())
}

async fn open_pool_and_migrate(pg: &PgEmbed) -> PgPool {
    let url = pg.full_db_uri("olympus");
    let pool = PgPool::connect(&url).await.expect("pool connect");
    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .expect("migrations");
    pool
}

async fn wait_for_ready(client: &reqwest::Client, addr: SocketAddr) {
    let url = format!("http://{addr}/health");
    let mut last = None;
    for attempt in 0..10u64 {
        tokio::time::sleep(Duration::from_millis(10 * (1 << attempt))).await;
        match client.get(&url).send().await {
            Ok(_) => return,
            Err(e) => last = Some(e),
        }
    }
    panic!("server never accepted connections: {last:?}");
}

// ── Per-test helpers ─────────────────────────────────────────────────────────

/// Build a `http://addr<path>` URL for a known-good route.
pub fn url(h: &TestHarness, path: &str) -> String {
    format!("http://{}{}", h.addr, path)
}

/// GET with the system API key.
pub async fn get_with_key(client: &reqwest::Client, url: &str, api_key: &str) -> reqwest::Response {
    client
        .get(url)
        .header("x-api-key", api_key)
        .send()
        .await
        .expect("GET")
}

/// POST JSON with the system API key.
pub async fn post_json_with_key(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    body: &serde_json::Value,
) -> reqwest::Response {
    client
        .post(url)
        .header("x-api-key", api_key)
        .json(body)
        .send()
        .await
        .expect("POST")
}

/// POST JSON without auth — for unauth/401 assertions.
pub async fn post_json_no_auth(
    client: &reqwest::Client,
    url: &str,
    body: &serde_json::Value,
) -> reqwest::Response {
    client.post(url).json(body).send().await.expect("POST")
}

/// DELETE with the system API key.
pub async fn delete_with_key(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
) -> reqwest::Response {
    client
        .delete(url)
        .header("x-api-key", api_key)
        .send()
        .await
        .expect("DELETE")
}

/// PATCH JSON with the system API key.
pub async fn patch_json_with_key(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    body: &serde_json::Value,
) -> reqwest::Response {
    client
        .patch(url)
        .header("x-api-key", api_key)
        .json(body)
        .send()
        .await
        .expect("PATCH")
}

// ── Admin-key variants ───────────────────────────────────────────────────────
// `/admin/*` routes go through `require_admin_auth`, which accepts the
// operator-only `x-admin-key` header as the env-gated bypass of the
// role/scope check. Tests for admin routes use these instead of the
// `_with_key` family above.

pub async fn get_admin(client: &reqwest::Client, url: &str, admin_key: &str) -> reqwest::Response {
    client
        .get(url)
        .header("x-admin-key", admin_key)
        .send()
        .await
        .expect("GET")
}

pub async fn post_admin_json(
    client: &reqwest::Client,
    url: &str,
    admin_key: &str,
    body: &serde_json::Value,
) -> reqwest::Response {
    client
        .post(url)
        .header("x-admin-key", admin_key)
        .json(body)
        .send()
        .await
        .expect("POST")
}

pub async fn patch_admin_json(
    client: &reqwest::Client,
    url: &str,
    admin_key: &str,
    body: &serde_json::Value,
) -> reqwest::Response {
    client
        .patch(url)
        .header("x-admin-key", admin_key)
        .json(body)
        .send()
        .await
        .expect("PATCH")
}

pub async fn delete_admin(
    client: &reqwest::Client,
    url: &str,
    admin_key: &str,
) -> reqwest::Response {
    client
        .delete(url)
        .header("x-admin-key", admin_key)
        .send()
        .await
        .expect("DELETE")
}

/// Generate a unique-per-test holder key suffix so tests inside the same
/// binary don't collide on UNIQUE constraints when running in parallel.
pub fn unique_id(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{nanos}")
}
