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

    dbg_log(app_data_dir, "=== init_embedded start ===");
    match try_init_embedded(app_data_dir, &data_dir).await {
        Ok(db) => Ok(db),
        Err(first_err) => {
            dbg_log(app_data_dir, &format!("FIRST ATTEMPT FAILED: {first_err}"));
            eprintln!("[olympus-desktop] PG init failed: {first_err} — wiping data dir and retrying");
            let _ = std::fs::remove_dir_all(&data_dir);
            try_init_embedded(app_data_dir, &data_dir).await.map_err(|retry_err| {
                dbg_log(app_data_dir, &format!("RETRY ALSO FAILED: {retry_err}"));
                eprintln!("[olympus-desktop] PG retry also failed: {retry_err}");
                retry_err
            })
        }
    }
}

/// Write a diagnostic line to `olympus-pg-debug.log` in the app data dir.
fn dbg_log(app_data_dir: &Path, msg: &str) {
    use std::io::Write;
    let log_path = app_data_dir.join("olympus-pg-debug.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = writeln!(f, "[{ts}] {msg}");
    }
}

async fn try_init_embedded(app_data_dir: &Path, data_dir: &Path) -> Result<EmbeddedDb, DbError> {
    dbg_log(app_data_dir, &format!("try_init_embedded start, data_dir={}", data_dir.display()));

    let settings = PgSettings {
        database_dir: data_dir.to_path_buf(),
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

    let stale_pid = data_dir.join("postmaster.pid");
    if stale_pid.exists() {
        let _ = std::fs::remove_file(&stale_pid);
        dbg_log(app_data_dir, "removed stale postmaster.pid");
    }

    dbg_log(app_data_dir, "PgEmbed::new...");
    let mut pg = PgEmbed::new(settings, fetch).await?;
    dbg_log(app_data_dir, "PgEmbed::new OK");

    dbg_log(app_data_dir, "setup (initdb)...");
    pg.setup().await?;
    dbg_log(app_data_dir, "setup OK");

    dbg_log(app_data_dir, "patching postgresql.conf...");
    patch_pg_conf(data_dir)?;
    dbg_log(app_data_dir, "patch OK");

    dbg_log(app_data_dir, "start_db...");
    pg.start_db().await?;
    dbg_log(app_data_dir, "start_db OK!");

    if !pg.database_exists(PG_DB).await? {
        dbg_log(app_data_dir, "creating database...");
        pg.create_database(PG_DB).await?;
        dbg_log(app_data_dir, "database created");
    }

    let url = pg.full_db_uri(PG_DB);
    dbg_log(app_data_dir, &format!("connecting pool: {url}"));
    let pool = PgPool::connect(&url).await?;
    dbg_log(app_data_dir, "pool connected");

    sqlx::migrate!("../migrations").run(&pool).await?;
    dbg_log(app_data_dir, "migrations applied — PG fully ready");

    Ok(EmbeddedDb { pg, pool })
}

/// Connect to an externally managed PostgreSQL instance (dev/CI path).
/// Returns `None` on missing URL or connection failure so the server still
/// starts — DB-backed routes will return 503.
///
/// Runs `sqlx::migrate!` after connect so a fresh external database is
/// brought to the same schema state as the embedded path. Migration failure
/// is treated as a connection failure (the schema is required for every
/// DB-backed route); the pool is dropped and `None` returned so the rest
/// of the server still boots and `/health` surfaces the cause.
pub async fn connect_external(database_url: &str) -> Option<PgPool> {
    let pool = match PgPool::connect(database_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[olympus-desktop] DB connection failed: {e} — DB-backed routes return 503");
            return None;
        }
    };
    if let Err(e) = sqlx::migrate!("../migrations").run(&pool).await {
        eprintln!(
            "[olympus-desktop] migrations failed against external DB: {e} — \
             DB-backed routes return 503"
        );
        return None;
    }
    Some(pool)
}
