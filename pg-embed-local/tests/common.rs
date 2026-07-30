// Included by several test binaries via `#[path = "common.rs"] mod common;`.
// Each one uses a different subset — `auth.rs` needs only `reserve_port`, for
// instance — so an unused helper here is expected rather than a defect.
#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;

use env_logger::Env;
use tempfile::TempDir;

use pg_embed::pg_enums::PgAuthMethod;
use pg_embed::pg_errors::{Error, Result};
use pg_embed::pg_fetch::{PG_V15, PgFetchSettings};
use pg_embed::postgres::{PgEmbed, PgSettings};

/// A loopback port held open until PostgreSQL is about to bind it.
///
/// These tests used to hardcode 5432. That is PostgreSQL's default port, so on
/// any machine already running PostgreSQL — which is most developer machines —
/// the embedded postmaster could not bind and exited immediately, surfacing as
/// a bare [`Error::PgStartFailure`] with no diagnostic (the payload's stdio is
/// `Stdio::null`, so the postmaster's own "address already in use" never
/// reaches the test output). Nothing here needs a *specific* port, so ask the
/// kernel for a free one instead, as `src-tauri/tests/smt_pg_backend.rs`
/// already does.
///
/// The listener is **kept bound** for the reservation's whole life rather than
/// closed at hand-out. Callers run `setup()` — a download and a full `initdb` —
/// between reserving and starting, and a port merely observed to be free at the
/// start of that window is unowned for all of it. Holding the socket makes the
/// port genuinely unavailable to anything else until [`start_db`] closes it
/// immediately before the postmaster binds.
///
/// That narrows the exposure to the interval between the close and the bind; it
/// does not erase it, because Postgres has to bind the socket itself and two
/// listeners cannot share the address (`SO_REUSEADDR` does not permit it).
/// Closing that last gap would need a retry that rebuilds the whole `PgEmbed`,
/// since `db_uri` is derived from the port at construction and the migration and
/// database tests connect through it.
#[derive(Debug)]
pub struct ReservedPort {
    port: u16,
    listener: Option<std::net::TcpListener>,
}

impl ReservedPort {
    /// The reserved port number, for building [`PgSettings`].
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Stop holding the port so PostgreSQL can bind it.
    ///
    /// Prefer [`start_db`], which does this as part of starting and therefore
    /// cannot be forgotten. A reservation released early is just an ordinary
    /// unheld ephemeral port; one never released makes `start_db` fail loudly,
    /// which is the safe direction.
    pub fn release(&mut self) {
        self.listener = None;
    }
}

/// Reserves one ephemeral port.
///
/// # Errors
///
/// Returns [`Error::PgError`] if no ephemeral port can be reserved.
pub fn reserve_port() -> Result<ReservedPort> {
    Ok(reserve_ports(1)?
        .pop()
        .expect("reserve_ports(1) yields one reservation"))
}

/// Reserves `count` distinct ephemeral ports.
///
/// Distinctness is automatic: every listener stays bound, so the kernel cannot
/// hand out the same port twice within one call. Releasing between allocations
/// would make each freed port immediately eligible again.
///
/// # Errors
///
/// Returns [`Error::PgError`] if a port cannot be reserved.
pub fn reserve_ports(count: usize) -> Result<Vec<ReservedPort>> {
    (0..count)
        .map(|_| {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| {
                Error::PgError(e.to_string(), "reserving an ephemeral port".to_owned())
            })?;
            let port = listener
                .local_addr()
                .map_err(|e| Error::PgError(e.to_string(), "reading the reserved port".to_owned()))?
                .port();
            Ok(ReservedPort {
                port,
                listener: Some(listener),
            })
        })
        .collect()
}

/// Releases `port` and starts `pg` on it.
///
/// Taking the reservation by value is the point: the port stays held through
/// `setup()` and is surrendered only in the instant before the postmaster binds
/// it, and no call site can start a server while still holding its own port or
/// forget to release one.
///
/// # Errors
///
/// Returns any error from [`PgEmbed::start_db`].
pub async fn start_db(pg: &mut PgEmbed, port: ReservedPort) -> Result<()> {
    drop(port);
    pg.start_db().await
}

/// Sets up a [`PgEmbed`] instance against `database_dir`.
///
/// Initialises logging, constructs [`PgSettings`] and [`PgFetchSettings`] with
/// sensible defaults (the pinned PG 15, MD5 auth, 60-second timeout), creates the
/// [`PgEmbed`] instance, and runs [`PgEmbed::setup`].
///
/// The per-command timeout is 60 s, not the 10 s that initdb/`pg_ctl` need in
/// isolation. Under the full `cargo test --workspace` pre-push run, every
/// crate's tests saturate the CPU, so Postgres startup routinely exceeds 10 s
/// on Windows and surfaces as a flaky `PgTimedOutError` ("PID file does not
/// exist / Is server running?"). 60 s matches `lifecycle::setup_with_timeout`,
/// which was bumped for the same contention reason.
///
/// # Arguments
///
/// * `port` — TCP port the PostgreSQL server will listen on.
/// * `database_dir` — Directory for the cluster data files.
/// * `persistent` — If `false`, the cluster is deleted when [`PgEmbed`] is
///   dropped.
/// * `migration_dir` — Optional path containing `.sql` migration files.
///
/// # Errors
///
/// Returns any error from [`PgEmbed::new`] or [`PgEmbed::setup`].
pub async fn setup(
    port: u16,
    database_dir: PathBuf,
    persistent: bool,
    migration_dir: Option<PathBuf>,
) -> Result<PgEmbed> {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .is_test(true)
        .try_init();
    let pg_settings = PgSettings {
        database_dir,
        port,
        user: "postgres".to_string(),
        password: "password".to_string(),
        auth_method: PgAuthMethod::MD5,
        persistent,
        timeout: Some(Duration::from_secs(60)),
        migration_dir,
    };
    let fetch_settings = PgFetchSettings {
        version: PG_V15,
        ..Default::default()
    };
    let mut pg = PgEmbed::new(pg_settings, fetch_settings).await?;
    pg.setup().await?;
    Ok(pg)
}

/// Sets up a [`PgEmbed`] instance inside a temporary directory.
///
/// Creates an isolated [`TempDir`] and places the cluster data files in a
/// `db/` subdirectory inside it.  The caller must hold the returned [`TempDir`]
/// for the lifetime of the test — dropping it removes all files created by
/// the instance.
///
/// # Drop order
///
/// The tuple is `(TempDir, PgEmbed)` so that, when destructured as
/// `let (_dir, mut pg) = setup_with_tempdir(...)`, `pg` (declared second)
/// is dropped first and `_dir` (declared first) is dropped last.  This
/// guarantees that `stop_db_sync` and `clean` can find the data directory
/// before the [`TempDir`] removes the parent.
///
/// # Arguments
///
/// * `port` — TCP port the PostgreSQL server will listen on.
/// * `persistent` — If `false`, the cluster is deleted when [`PgEmbed`] is
///   dropped (in addition to the [`TempDir`] cleanup).
/// * `migration_dir` — Optional path containing `.sql` migration files.
///
/// # Errors
///
/// Returns [`Error::DirCreationError`] if the temporary directory cannot be
/// created, or any error from [`setup`].
pub async fn setup_with_tempdir(
    port: u16,
    persistent: bool,
    migration_dir: Option<PathBuf>,
) -> Result<(TempDir, PgEmbed)> {
    let dir = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;
    let pg = setup(port, dir.path().join("db"), persistent, migration_dir).await?;
    Ok((dir, pg))
}
