use pg_embed::pg_enums::PgAuthMethod;
use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
use pg_embed::postgres::{PgEmbed, PgSettings};
use sqlx::PgPool;
use std::path::Path;
use std::time::Duration;

const PG_PORT: u16 = 5433;
const PG_USER: &str = "olympus";
const PG_PASSWORD: &str = "olympus";
const PG_DB: &str = "olympus";

/// Holds the embedded PostgreSQL process and the connection pool.
/// Must remain alive for the duration of the process.
pub struct EmbeddedDb {
    /// The embedded PG process — exposed so main.rs can call stop_db() on exit.
    pub pg: PgEmbed,
    pub pool: PgPool,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("pg_embed error: {0}")]
    PgEmbed(#[from] pg_embed::pg_errors::Error),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Patch postgresql.conf to bind only 127.0.0.1 (not localhost).
///
/// On Windows with Hyper-V/WSL, postgres resolving "localhost" tries ::1 first
/// and gets "Permission denied" before falling through to 127.0.0.1, which
/// causes start_db() to fail even though IPv4 would work fine.
/// Forcing listen_addresses = '127.0.0.1' skips the IPv6 attempt entirely.
fn patch_pg_conf(data_dir: &Path) -> std::io::Result<()> {
    let conf = data_dir.join("postgresql.conf");
    let existing = std::fs::read_to_string(&conf).unwrap_or_default();

    // Only append if not already set — avoids duplicate lines on restart.
    if !existing.contains("listen_addresses = '127.0.0.1'") {
        let patch = format!(
            "\n# Olympus: bind IPv4 only — avoids Windows Hyper-V IPv6 permission errors\nlisten_addresses = '127.0.0.1'\nport = {PG_PORT}\n"
        );
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&conf)?;
        f.write_all(patch.as_bytes())?;
    }
    Ok(())
}

/// Initialise embedded PostgreSQL in `app_data_dir/olympus-pg`, run pending
/// sqlx migrations, and return an open connection pool.
///
/// On first launch: pg_embed downloads PG 15 binaries to `app_data_dir/pg-embed`
/// and calls `initdb` to create a new cluster.
/// On subsequent launches: the existing cluster is started on port 5433.
pub async fn init_embedded(app_data_dir: &Path) -> Result<EmbeddedDb, DbError> {
    let data_dir = app_data_dir.join("olympus-pg");

    let settings = PgSettings {
        database_dir: data_dir.clone(),
        port: PG_PORT,
        user: PG_USER.into(),
        password: PG_PASSWORD.into(),
        auth_method: PgAuthMethod::Plain,
        persistent: true,
        timeout: Some(Duration::from_secs(30)),
        migration_dir: None,
    };

    let fetch = PgFetchSettings {
        version: PG_V15,
        ..Default::default()
    };

    let mut pg = PgEmbed::new(settings, fetch).await?;
    // setup() runs initdb on first launch; subsequent calls are near-instant.
    pg.setup().await?;

    // Patch conf AFTER setup() (which creates postgresql.conf) but BEFORE
    // start_db() so postgres never attempts to bind ::1.
    patch_pg_conf(&data_dir)?;

    pg.start_db().await?;

    if !pg.database_exists(PG_DB).await? {
        pg.create_database(PG_DB).await?;
    }

    let url = pg.full_db_uri(PG_DB);
    let pool = PgPool::connect(&url).await?;

    sqlx::migrate!("../migrations").run(&pool).await?;

    Ok(EmbeddedDb { pg, pool })
}

/// Connect to an externally managed PostgreSQL instance (dev/CI path).
/// Returns `None` on missing URL or connection failure so the server still
/// starts — DB-backed routes will return 503.
pub async fn connect_external(database_url: &str) -> Option<PgPool> {
    match PgPool::connect(database_url).await {
        Ok(pool) => Some(pool),
        Err(e) => {
            eprintln!("[olympus-desktop] DB connection failed: {e} — DB-backed routes return 503");
            None
        }
    }
}
