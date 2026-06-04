use std::path::PathBuf;
use std::time::Duration;

use env_logger::Env;
use tempfile::TempDir;

use pg_embed::pg_enums::PgAuthMethod;
use pg_embed::pg_errors::{Error, Result};
use pg_embed::pg_fetch::{PG_V17, PgFetchSettings};
use pg_embed::postgres::{PgEmbed, PgSettings};

/// Sets up a [`PgEmbed`] instance against `database_dir`.
///
/// Initialises logging, constructs [`PgSettings`] and [`PgFetchSettings`] with
/// sensible defaults (PG 17, MD5 auth, 60-second timeout), creates the
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
        version: PG_V17,
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
