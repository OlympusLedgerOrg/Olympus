use pg_embed::pg_enums::PgAuthMethod;
use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
use pg_embed::postgres::{PgEmbed, PgSettings};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::PgPool;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

const PG_PORT: u16 = 5433;
const PG_USER: &str = "olympus";
const PG_DB: &str = "olympus";
const EMBEDDED_PASSWORD_FILE: &str = "olympus-pg.password";

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
    #[error("embedded database credential file is invalid: {0}")]
    InvalidCredential(String),
    #[error("embedded database credential recovery failed: {0}")]
    CredentialRecovery(String),
    #[error("external database configuration error: {0}")]
    ExternalConfiguration(&'static str),
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
/// On a cold binary cache, pg_embed downloads PG 15 binaries to the OS cache
/// directory (`%LOCALAPPDATA%/pg-embed/...` on Windows) before creating or
/// reusing the persistent cluster under `app_data_dir/olympus-pg`.
/// Warm launches still start the existing cluster, connect the pool, and run
/// pending migrations on port 5433.
pub async fn init_embedded(app_data_dir: &Path) -> Result<EmbeddedDb, DbError> {
    let data_dir = app_data_dir.join("olympus-pg");

    dbg_log(app_data_dir, "=== init_embedded start ===");
    match try_init_embedded(app_data_dir, &data_dir).await {
        Ok(db) => Ok(db),
        Err(err) => {
            report_preserved_init_failure(app_data_dir, &data_dir, &err);
            Err(err)
        }
    }
}

/// Report an embedded-database startup failure without mutating the cluster.
///
/// Startup, connection, and migration errors are not evidence that a
/// persistent PostgreSQL cluster is disposable. Recovery therefore fails
/// closed and leaves every byte under `data_dir` for an operator-controlled
/// backup/repair workflow.
fn report_preserved_init_failure(app_data_dir: &Path, data_dir: &Path, err: &DbError) {
    dbg_log(
        app_data_dir,
        &format!(
            "INIT FAILED; persistent cluster preserved at {}: {err}",
            data_dir.display()
        ),
    );
    eprintln!(
        "[olympus-desktop] PG init failed: {err} — persistent cluster preserved at {}; \
         automatic destructive recovery is disabled",
        data_dir.display()
    );
}

/// Read the PID from `postmaster.pid` (first line). Returns `None` if the
/// file is missing, empty, or unparseable. PostgreSQL writes the PID on the
/// first line of this file as soon as the postmaster starts.
fn read_postmaster_pid(pidfile: &Path) -> Option<u32> {
    let content = std::fs::read_to_string(pidfile).ok()?;
    content.lines().next()?.trim().parse::<u32>().ok()
}

/// Force-kill a process by PID. Returns true if the kill command claimed
/// success — best-effort, never panics. Shells out so we don't pull in a
/// process-management crate for a single use site.
fn kill_pid(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Best-effort: kill any embedded postgres still running for `data_dir`.
/// Safe to call from a panic hook or signal handler — synchronous, never
/// panics, no allocations beyond the kill subprocess.
pub fn reap_embedded_pg(app_data_dir: &Path) {
    let pidfile = app_data_dir.join("olympus-pg").join("postmaster.pid");
    if let Some(pid) = read_postmaster_pid(&pidfile) {
        let _ = kill_pid(pid);
    }
}

/// Write a diagnostic line to `olympus-pg-debug.log` in the app data dir.
fn dbg_log(app_data_dir: &Path, msg: &str) {
    use std::io::Write;
    let log_path = app_data_dir.join("olympus-pg-debug.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = writeln!(f, "[{ts}] {msg}");
    }
}

async fn try_init_embedded(app_data_dir: &Path, data_dir: &Path) -> Result<EmbeddedDb, DbError> {
    dbg_log(
        app_data_dir,
        &format!("try_init_embedded start, data_dir={}", data_dir.display()),
    );

    let cluster_existed = data_dir.join("PG_VERSION").exists();
    let stored_password = read_embedded_password(app_data_dir)?;
    let password_needs_persist = cluster_existed && stored_password.is_none();
    let password = match stored_password {
        Some(password) => password,
        None if cluster_existed => new_embedded_password(),
        None => load_or_create_embedded_password(app_data_dir)?,
    };
    let settings = PgSettings {
        database_dir: data_dir.to_path_buf(),
        port: PG_PORT,
        user: PG_USER.into(),
        password: password.clone(),
        auth_method: PgAuthMethod::ScramSha256,
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
        if let Some(pid) = read_postmaster_pid(&stale_pid) {
            if kill_pid(pid) {
                dbg_log(app_data_dir, &format!("killed stale postgres pid={pid}"));
            } else {
                dbg_log(
                    app_data_dir,
                    &format!("no live process for stale pid={pid}"),
                );
            }
        }
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

    if !cluster_existed && !pg.database_exists(PG_DB).await? {
        dbg_log(app_data_dir, "creating database...");
        pg.create_database(PG_DB).await?;
        dbg_log(app_data_dir, "database created");
    }

    dbg_log(
        app_data_dir,
        &format!("connecting pool: user={PG_USER} host=localhost port={PG_PORT} db={PG_DB}"),
    );
    let pool = match PgPool::connect(&pg.full_db_uri(PG_DB)).await {
        Ok(pool) => pool,
        Err(primary) if cluster_existed && is_password_auth_failure(&primary) => {
            // The app owns this local cluster and its files. If the historical
            // fixed credential or a lost random-credential file prevents login,
            // rotate the role in PostgreSQL single-user mode. The replacement
            // is kept out of process arguments and, when the file was missing,
            // published only after PostgreSQL accepted it.
            dbg_log(app_data_dir, "recovering embedded PostgreSQL credential...");
            if let Err(recovery) =
                rotate_embedded_password_offline(&mut pg, data_dir, &password).await
            {
                dbg_log(
                    app_data_dir,
                    &format!("embedded credential recovery failed: {recovery}"),
                );
                return Err(primary.into());
            }
            if password_needs_persist {
                let persisted = persist_embedded_password(app_data_dir, &password)?;
                if persisted != password {
                    return Err(DbError::CredentialRecovery(
                        "another process published a different credential during recovery"
                            .to_owned(),
                    ));
                }
            }
            PgPool::connect(&pg.full_db_uri(PG_DB)).await?
        }
        Err(e) => return Err(e.into()),
    };
    dbg_log(app_data_dir, "pool connected");

    sqlx::migrate!("../migrations").run(&pool).await?;
    dbg_log(app_data_dir, "migrations applied — PG fully ready");

    Ok(EmbeddedDb { pg, pool })
}

fn is_password_auth_failure(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error)
            if database_error.code().as_deref() == Some("28P01")
    )
}

async fn rotate_embedded_password_offline(
    pg: &mut PgEmbed,
    data_dir: &Path,
    password: &str,
) -> Result<(), DbError> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    if password.len() != 64
        || !password
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DbError::CredentialRecovery(
            "refusing to rotate: credential is not 64 lowercase hex characters".to_owned(),
        ));
    }

    pg.stop_db().await?;
    let postgres_exe = pg.pg_access.pg_ctl_exe.with_file_name(if cfg!(windows) {
        "postgres.exe"
    } else {
        "postgres"
    });
    let recovery = async {
        let mut child = tokio::process::Command::new(postgres_exe)
            .arg("--single")
            .arg("-D")
            .arg(data_dir)
            .arg("postgres")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            DbError::CredentialRecovery("single-user PostgreSQL stdin is unavailable".to_owned())
        })?;
        stdin
            .write_all(
                format!("ALTER ROLE {PG_USER} WITH LOGIN PASSWORD '{password}';\n").as_bytes(),
            )
            .await?;
        drop(stdin);
        let status = child.wait().await?;
        if !status.success() {
            return Err(DbError::CredentialRecovery(format!(
                "single-user PostgreSQL exited with status {status}"
            )));
        }
        Ok(())
    }
    .await;
    let restart = pg.start_db().await;
    match recovery {
        Ok(()) => {
            restart?;
            Ok(())
        }
        Err(error) => {
            let _ = restart;
            Err(error)
        }
    }
}

fn read_embedded_password(app_data_dir: &Path) -> Result<Option<String>, DbError> {
    let path = app_data_dir.join(EMBEDDED_PASSWORD_FILE);
    match std::fs::read_to_string(&path) {
        Ok(value) => {
            let value = value.trim();
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(DbError::InvalidCredential(format!(
                    "{} must contain exactly 64 lowercase hexadecimal characters",
                    path.display()
                )));
            }
            Ok(Some(value.to_owned()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn new_embedded_password() -> String {
    use rand::RngCore;

    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    hex::encode(raw)
}

fn persist_embedded_password(app_data_dir: &Path, value: &str) -> Result<String, DbError> {
    use std::io::Write;

    std::fs::create_dir_all(app_data_dir)?;
    let path = app_data_dir.join(EMBEDDED_PASSWORD_FILE);
    // A unique staging name makes an interrupted pre-rename write harmless on
    // the next launch instead of leaving a permanent `.new` collision.
    let tmp = app_data_dir.join(format!(".{EMBEDDED_PASSWORD_FILE}.{}.new", &value[..16]));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(value.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    // `rename` replaces an existing destination on Unix. Publish with a hard
    // link instead so simultaneous desktop startups cannot overwrite the
    // winning password with different random bytes.
    let published = match std::fs::hard_link(&tmp, &path) {
        Ok(()) => value.to_owned(),
        Err(link_error) if link_error.kind() == std::io::ErrorKind::AlreadyExists => {
            read_embedded_password(app_data_dir)?.ok_or_else(|| {
                DbError::InvalidCredential(format!(
                    "{} disappeared during creation",
                    path.display()
                ))
            })?
        }
        Err(link_error) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(link_error.into());
        }
    };
    let _ = std::fs::remove_file(&tmp);
    // Persist the directory entry as well as the file contents before
    // PostgreSQL is initialised with this credential.
    #[cfg(unix)]
    std::fs::File::open(app_data_dir)?.sync_all()?;
    Ok(published)
}

fn load_or_create_embedded_password(app_data_dir: &Path) -> Result<String, DbError> {
    if let Some(value) = read_embedded_password(app_data_dir)? {
        return Ok(value);
    }
    persist_embedded_password(app_data_dir, &new_embedded_password())
}

/// Parse an external PostgreSQL URL under the environment's TLS policy.
///
/// SQLx maps `verify-full` to certificate-chain and requested-hostname
/// verification. The explicitly enabled Rustls/WebPKI feature supplies public
/// trust roots; private deployments can provide their reviewed CA through the
/// standard `sslrootcert` URL parameter.
fn external_pg_connect_options(
    database_url: &str,
    production: bool,
) -> Result<PgConnectOptions, DbError> {
    if database_url.trim().is_empty() {
        return Err(DbError::ExternalConfiguration(
            "DATABASE_URL must not be empty",
        ));
    }
    let options = PgConnectOptions::from_str(database_url).map_err(|_| {
        DbError::ExternalConfiguration("DATABASE_URL must be a valid PostgreSQL URL")
    })?;

    if production {
        if !matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
            return Err(DbError::ExternalConfiguration(
                "production DATABASE_URL must set sslmode=verify-full",
            ));
        }
        if options.get_socket().is_some() || options.get_host().starts_with('/') {
            return Err(DbError::ExternalConfiguration(
                "production DATABASE_URL must use TLS over a hostname, not a local socket",
            ));
        }
    }

    Ok(options)
}

/// Connect to an externally managed PostgreSQL instance.
/// Returns `None` on missing URL or connection failure so the server still
/// starts — DB-backed routes will return 503.
///
/// Production requires `sslmode=verify-full`; weaker or missing TLS modes are
/// rejected before any network connection is attempted. Explicit development
/// mode preserves SQLx's configured/default behavior for local databases.
///
/// Runs `sqlx::migrate!` after connect so a fresh external database is
/// brought to the same schema state as the embedded path. Migration failure
/// is treated as a connection failure (the schema is required for every
/// DB-backed route); the pool is dropped and `None` returned so the rest
/// of the server still boots and `/health` surfaces the cause.
pub async fn connect_external(database_url: &str) -> Option<PgPool> {
    let options = match external_pg_connect_options(database_url, crate::env::is_production()) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("[olympus-desktop] {error} — DB-backed routes return 503");
            return None;
        }
    };
    let pool = match PgPoolOptions::new().connect_with(options).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_external_database_requires_verify_full() {
        let options = external_pg_connect_options(
            "postgresql://olympus:secret@db.example.com/olympus?sslmode=verify-full",
            true,
        )
        .expect("verify-full production URL");
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
        assert_eq!(options.get_host(), "db.example.com");

        for url in [
            "postgresql://olympus:secret@db.example.com/olympus",
            "postgresql://olympus:secret@db.example.com/olympus?sslmode=disable",
            "postgresql://olympus:secret@db.example.com/olympus?sslmode=require",
            "postgresql://olympus:secret@db.example.com/olympus?sslmode=verify-ca",
        ] {
            assert!(
                matches!(
                    external_pg_connect_options(url, true),
                    Err(DbError::ExternalConfiguration(
                        "production DATABASE_URL must set sslmode=verify-full"
                    ))
                ),
                "production accepted a weaker TLS mode: {url}"
            );
        }
    }

    #[test]
    fn production_external_database_rejects_socket_and_malformed_urls() {
        assert!(matches!(
            external_pg_connect_options(
                "postgresql://olympus@localhost/olympus?host=%2Fvar%2Frun%2Fpostgresql&sslmode=verify-full",
                true,
            ),
            Err(DbError::ExternalConfiguration(
                "production DATABASE_URL must use TLS over a hostname, not a local socket"
            ))
        ));
        assert!(matches!(
            external_pg_connect_options("not a PostgreSQL URL", true),
            Err(DbError::ExternalConfiguration(
                "DATABASE_URL must be a valid PostgreSQL URL"
            ))
        ));
        assert!(matches!(
            external_pg_connect_options("  ", true),
            Err(DbError::ExternalConfiguration(
                "DATABASE_URL must not be empty"
            ))
        ));
    }

    #[test]
    fn development_external_database_preserves_local_tls_defaults() {
        let default = external_pg_connect_options("postgresql://localhost/olympus", false).unwrap();
        assert!(matches!(default.get_ssl_mode(), PgSslMode::Prefer));

        let disabled =
            external_pg_connect_options("postgresql://localhost/olympus?sslmode=disable", false)
                .unwrap();
        assert!(matches!(disabled.get_ssl_mode(), PgSslMode::Disable));
    }

    #[test]
    fn startup_failure_reporting_preserves_persistent_cluster() {
        let app_data = tempfile::tempdir().expect("temp app-data dir");
        let data_dir = app_data.path().join("olympus-pg");
        let sentinel = data_dir.join("base").join("ledger-sentinel");
        std::fs::create_dir_all(sentinel.parent().expect("sentinel parent"))
            .expect("create cluster fixture");
        std::fs::write(&sentinel, b"must survive every startup failure")
            .expect("write cluster fixture");

        let err = DbError::Io(std::io::Error::other("synthetic startup failure"));
        report_preserved_init_failure(app_data.path(), &data_dir, &err);

        assert_eq!(
            std::fs::read(&sentinel).expect("persistent data must remain readable"),
            b"must survive every startup failure"
        );
    }
    #[test]
    fn embedded_password_is_random_persistent_and_not_the_legacy_default() {
        let app_data = tempfile::tempdir().expect("temp app-data dir");
        let first = load_or_create_embedded_password(app_data.path()).expect("create password");
        let second = load_or_create_embedded_password(app_data.path()).expect("reload password");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert_ne!(first, "olympus");
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(app_data.path().join(EMBEDDED_PASSWORD_FILE))
                .expect("password metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "embedded password must not be group/world accessible"
            );
        }
    }

    #[test]
    fn concurrent_password_initialization_has_one_winner() {
        let app_data = tempfile::tempdir().expect("temp app-data dir");
        let path = std::sync::Arc::new(app_data.path().to_path_buf());
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    load_or_create_embedded_password(&path).expect("initialize password")
                })
            })
            .collect();
        let values: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("password worker"))
            .collect();
        assert!(values.windows(2).all(|pair| pair[0] == pair[1]));
    }
}
