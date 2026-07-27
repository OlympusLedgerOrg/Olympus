mod process_identity;

use pg_embed::pg_access::{
    ensure_private_directory, secure_private_file_handle, PrivateDirectoryGuard,
};
use pg_embed::pg_enums::PgAuthMethod;
use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
use pg_embed::postgres::{PgEmbed, PgSettings};
use process_identity::{
    arm_verified_postgres, cleanup_verified_postgres, probe_postmaster_presence, ArmedPostgres,
    ExpectedPostgres, PidPresence, TerminationOutcome,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::PgPool;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const PG_PORT: u16 = 5433;
const PG_USER: &str = "olympus";
const PG_DB: &str = "olympus";
const EMBEDDED_PASSWORD_FILE: &str = "olympus-pg.password";
const INSTANCE_LOCK_FILE: &str = "embedded-postgres.lock";

static EMBEDDED_POSTGRES_REAPER: OnceLock<Mutex<Vec<ArmedPostgres>>> = OnceLock::new();
#[cfg(target_os = "macos")]
static MACOS_REAPER_ATEXIT_REGISTERED: OnceLock<()> = OnceLock::new();

/// Holds the embedded PostgreSQL process and the connection pool.
/// Must remain alive for the duration of the process.
pub struct EmbeddedDb {
    /// The embedded PG process — exposed so main.rs can call stop_db() on exit.
    pub pg: PgEmbed,
    pub pool: PgPool,
    /// OS-backed exclusive lock proving this Olympus process owns the cluster.
    _instance_lock: EmbeddedInstanceLock,
}

struct EmbeddedInstanceLock {
    _file: File,
    _directories: PrivateDirectoryGuard,
}

impl Drop for EmbeddedDb {
    fn drop(&mut self) {
        let data_dir = self.pg.pg_settings.database_dir.clone();
        let Some(app_data_dir) = data_dir.parent() else {
            return;
        };
        if reap_embedded_pg(app_data_dir) {
            let _ = self.pg.mark_process_stopped_externally();
        }
    }
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
    #[error("another Olympus process already owns the embedded database: {0}")]
    InstanceLocked(String),
    #[error("refused unsafe embedded PostgreSQL cleanup: {0}")]
    UnsafeProcessCleanup(String),
}

/// Append Olympus-managed PostgreSQL settings as the final, last-wins block.
/// The point at which external PostgreSQL startup failed.
///
/// This deliberately carries no source error. SQLx and PostgreSQL diagnostics
/// can contain connection strings, credentials, SQL text, and server paths, so
/// only this coarse stage may cross the operator-log or renderer boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalDbFailure {
    Connection,
    Migration,
}

/// Return an operator-facing database failure description that cannot contain a
/// connection URL, password, credential-file value, SQL statement, or
/// server-supplied diagnostic.
pub(crate) fn operator_safe_error(error: &DbError) -> String {
    match error {
        DbError::PgEmbed(_) => "embedded PostgreSQL lifecycle operation failed".to_owned(),
        DbError::Sqlx(_) => "embedded PostgreSQL SQL operation failed".to_owned(),
        DbError::Migrate(_) => "embedded PostgreSQL migration failed".to_owned(),
        DbError::Io(source) => format!(
            "embedded PostgreSQL filesystem operation failed ({:?})",
            source.kind()
        ),
        DbError::InvalidCredential(_) => {
            "embedded PostgreSQL credential validation failed".to_owned()
        }
        DbError::CredentialRecovery(_) => {
            "embedded PostgreSQL credential recovery failed".to_owned()
        }
        DbError::ExternalConfiguration(_) => {
            "external PostgreSQL configuration validation failed".to_owned()
        }
        DbError::InstanceLocked(_) => {
            "embedded PostgreSQL instance ownership validation failed".to_owned()
        }
        DbError::UnsafeProcessCleanup(_) => {
            "embedded PostgreSQL process cleanup was refused".to_owned()
        }
    }
}

/// Build the only embedded-database error text permitted in local logs or
/// renderer IPC.
pub(crate) fn embedded_startup_error_message(error: &DbError) -> String {
    format!(
        "Embedded PostgreSQL failed to start.\n\
         Reason: {}.\n\
         The persistent database cluster was preserved; automatic destructive recovery is disabled.\n\
         Check disk space, port availability, and the embedded-PostgreSQL debug log.\n\
         Database paths and sensitive diagnostics are intentionally omitted.",
        operator_safe_error(error)
    )
}

/// Build the only external-database error text permitted in local logs or
/// renderer IPC.
pub(crate) fn external_startup_error_message(failure: ExternalDbFailure) -> String {
    let (stage, hint) = match failure {
        ExternalDbFailure::Connection => (
            "connection",
            "Verify that the server is running and DATABASE_URL is configured correctly",
        ),
        ExternalDbFailure::Migration => (
            "schema migration",
            "Verify that the configured database role can apply the authoritative migrations",
        ),
    };
    format!(
        "External PostgreSQL startup failed during {stage}.\n\
         {hint}.\n\
         Connection URLs, credentials, and server diagnostics are intentionally omitted."
    )
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
    let patch = format!(
        "\n# Olympus embedded PostgreSQL managed settings v1\n\
         listen_addresses = '127.0.0.1'\n\
         port = {PG_PORT}\n\
         password_encryption = 'scram-sha-256'\n\
         fsync = on\n\
         synchronous_commit = on\n\
         full_page_writes = on\n"
    );

    // PostgreSQL uses the last occurrence of a setting. Requiring the exact
    // managed block at EOF repairs later overrides without rewriting config
    // generated by PostgreSQL or pg_embed.
    if !existing.ends_with(&patch) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&conf)?;
        f.write_all(patch.as_bytes())?;
        f.sync_all()?;
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
    let instance_lock = match acquire_instance_lock(app_data_dir) {
        Ok(lock) => lock,
        Err(error) => {
            // No process capability is owned before this point. In particular,
            // an I/O/metadata failure while opening the lock must never reap a
            // process retained by another initialization in this process.
            report_preserved_init_failure(app_data_dir, &error);
            return Err(error);
        }
    };
    match try_init_embedded(app_data_dir, &data_dir, instance_lock).await {
        Ok(db) => Ok(db),
        Err(err) => {
            // This branch is reachable only after this attempt acquired the
            // instance lock, so consuming a capability it armed is authorized.
            reap_embedded_pg(app_data_dir);
            report_preserved_init_failure(app_data_dir, &err);
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
fn report_preserved_init_failure(app_data_dir: &Path, err: &DbError) {
    let message = embedded_startup_error_message(err);
    dbg_log(app_data_dir, &message);
    eprintln!("[olympus-desktop] {message}");
}

fn acquire_instance_lock(app_data_dir: &Path) -> Result<EmbeddedInstanceLock, DbError> {
    let directories = ensure_private_directory(app_data_dir)?;
    let lock_path = app_data_dir.join(INSTANCE_LOCK_FILE);
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
            WRITE_DAC, WRITE_OWNER,
        };
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .access_mode(
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            )
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let lock = options.open(&lock_path)?;
    let metadata = lock.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(DbError::InstanceLocked(format!(
            "{} is not a regular lock file",
            lock_path.display()
        )));
    }
    secure_private_file_handle(&lock)
        .map_err(|error| DbError::InstanceLocked(format!("{} ({error})", lock_path.display())))?;
    lock.try_lock()
        .map_err(|error| DbError::InstanceLocked(format!("{} ({error})", lock_path.display())))?;
    Ok(EmbeddedInstanceLock {
        _file: lock,
        _directories: directories,
    })
}

fn arm_embedded_postgres_reaper(armed: ArmedPostgres) {
    let target = EMBEDDED_POSTGRES_REAPER.get_or_init(|| Mutex::new(Vec::new()));
    let mut guard = target
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.push(armed);
    #[cfg(target_os = "macos")]
    MACOS_REAPER_ATEXIT_REGISTERED.get_or_init(|| {
        if unsafe { libc::atexit(terminate_embedded_postgres_at_exit) } != 0 {
            panic!("register macOS embedded PostgreSQL exit guard");
        }
    });
}

#[cfg(target_os = "macos")]
extern "C" fn terminate_embedded_postgres_at_exit() {
    let Some(target) = EMBEDDED_POSTGRES_REAPER.get() else {
        return;
    };
    let Ok(guard) = target.try_lock() else {
        return;
    };
    for armed in guard.iter() {
        let _ = armed.terminate();
    }
}

fn remove_selected_after_confirmation<T>(
    retained: &mut Vec<T>,
    mut selected: impl FnMut(&T) -> bool,
    mut confirmed: impl FnMut(&T) -> bool,
) -> bool {
    let mut found = false;
    let mut all_confirmed = true;
    retained.retain(|item| {
        if !selected(item) {
            return true;
        }
        found = true;
        if confirmed(item) {
            false
        } else {
            all_confirmed = false;
            true
        }
    });
    found && all_confirmed
}

pub(crate) fn confirm_and_disarm_embedded_postgres_reaper(
    data_dir: &Path,
) -> Result<bool, DbError> {
    let Some(target) = EMBEDDED_POSTGRES_REAPER.get() else {
        return Ok(false);
    };
    let Ok(data_dir) = std::fs::canonicalize(data_dir) else {
        return Ok(false);
    };
    let mut guard = target
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut found = false;
    let mut all_confirmed = true;
    let mut observation_failure = None;
    guard.retain(|armed| {
        if armed.data_dir() != data_dir {
            return true;
        }
        found = true;
        match armed.has_exited() {
            Ok(true) => false,
            Ok(false) => {
                all_confirmed = false;
                true
            }
            Err(failure) => {
                all_confirmed = false;
                observation_failure = Some(failure);
                true
            }
        }
    });
    if let Some(failure) = observation_failure {
        return Err(DbError::UnsafeProcessCleanup(format!(
            "could not observe retained PostgreSQL exit: {}",
            failure.message()
        )));
    }
    Ok(found && all_confirmed)
}

/// Best-effort panic cleanup for the one embedded PostgreSQL instance this
/// process successfully started.
///
/// A writable `postmaster.pid` is never treated as authority. After pg_embed
/// starts, Olympus verifies the PID, start time, data directory, port,
/// executable path/digest, and command line once, then retains that exact OS
/// process object on Windows/Linux. Panic cleanup uses that retained object
/// instead of resolving a mutable pidfile or numeric PID again, and discards
/// it only after exit is confirmed.
pub fn reap_embedded_pg(app_data_dir: &Path) -> bool {
    std::panic::catch_unwind(|| {
        let Some(target) = EMBEDDED_POSTGRES_REAPER.get() else {
            return false;
        };
        // Panic hooks can run while the panicking thread still owns this
        // mutex. Never block (or self-deadlock) inside the hook.
        let mut guard = match target.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return false,
        };
        let Ok(requested_data_dir) = std::fs::canonicalize(app_data_dir.join("olympus-pg")) else {
            return false;
        };
        remove_selected_after_confirmation(
            &mut guard,
            |armed| armed.data_dir() == requested_data_dir,
            |armed| {
                let outcome = armed.terminate();
                dbg_log(app_data_dir, &outcome.safe_message());
                matches!(outcome, TerminationOutcome::Terminated(_))
            },
        )
    })
    .unwrap_or(false)
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

async fn try_init_embedded(
    app_data_dir: &Path,
    data_dir: &Path,
    instance_lock: EmbeddedInstanceLock,
) -> Result<EmbeddedDb, DbError> {
    dbg_log(app_data_dir, "try_init_embedded start");

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

    dbg_log(app_data_dir, "PgEmbed::new...");
    let mut pg = PgEmbed::new(settings, fetch).await?;
    dbg_log(app_data_dir, "PgEmbed::new OK");

    let stale_pid = data_dir.join("postmaster.pid");
    let presence = probe_postmaster_presence(&stale_pid, data_dir, PG_PORT);
    dbg_log(app_data_dir, &presence.safe_message());
    match presence {
        PidPresence::NoPidFile | PidPresence::Absent(_) => {}
        PidPresence::Refused { .. } => {
            return Err(DbError::UnsafeProcessCleanup(presence.safe_message()));
        }
        PidPresence::Live(_) => {
            // A live target requires the complete pinned executable identity.
            // Cache download/rebuild remains forbidden until that target has
            // been authenticated and, if appropriate, terminated.
            let stale_executable = pg
                .pg_access
                .authenticated_postgres_executable()
                .await?
                .ok_or_else(|| {
                    DbError::UnsafeProcessCleanup(
                        "live postmaster.pid target exists but the current PostgreSQL executable \
                         cache cannot be authenticated without mutation"
                            .to_owned(),
                    )
                })?;
            let stale_expected = ExpectedPostgres::new(
                data_dir,
                &stale_executable.path,
                stale_executable.sha256,
                PG_PORT,
            )?;
            let (outcome, retained_after_failure) =
                cleanup_verified_postgres(&stale_pid, &stale_expected);
            if let Some(armed) = retained_after_failure {
                arm_embedded_postgres_reaper(armed);
            }
            dbg_log(app_data_dir, &outcome.safe_message());
            if !matches!(
                outcome,
                TerminationOutcome::NoPidFile
                    | TerminationOutcome::ProcessNotRunning(_)
                    | TerminationOutcome::Terminated(_)
            ) {
                return Err(DbError::UnsafeProcessCleanup(outcome.safe_message()));
            }
        }
    }

    dbg_log(app_data_dir, "setup (initdb)...");
    pg.setup().await?;
    dbg_log(app_data_dir, "setup OK");
    let authenticated_postgres = pg
        .pg_access
        .authenticated_postgres_executable()
        .await?
        .ok_or_else(|| {
            DbError::UnsafeProcessCleanup(
                "PostgreSQL setup did not produce an authenticated executable cache".to_owned(),
            )
        })?;
    let expected_postgres = ExpectedPostgres::new(
        data_dir,
        &authenticated_postgres.path,
        authenticated_postgres.sha256,
        PG_PORT,
    )?;

    dbg_log(app_data_dir, "patching postgresql.conf...");
    patch_pg_conf(data_dir)?;
    dbg_log(app_data_dir, "patch OK");

    dbg_log(app_data_dir, "start_db...");
    pg.start_db().await?;
    dbg_log(app_data_dir, "start_db OK!");
    let process = pg.process_capability().ok_or_else(|| {
        DbError::UnsafeProcessCleanup(
            "PostgreSQL started without an exact-process capability".to_owned(),
        )
    })?;
    let armed = arm_verified_postgres(&stale_pid, expected_postgres.clone(), process)
        .map_err(|failure| DbError::UnsafeProcessCleanup(failure.message().to_owned()))?;
    arm_embedded_postgres_reaper(armed);

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
            if let Err(_recovery) =
                rotate_embedded_password_offline(&mut pg, data_dir, &password, &expected_postgres)
                    .await
            {
                dbg_log(app_data_dir, "embedded credential recovery failed");
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

    Ok(EmbeddedDb {
        pg,
        pool,
        _instance_lock: instance_lock,
    })
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
    expected_postgres: &ExpectedPostgres,
) -> Result<(), DbError> {
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
    if !confirm_and_disarm_embedded_postgres_reaper(data_dir)? {
        let app_data_dir = data_dir.parent().ok_or_else(|| {
            DbError::UnsafeProcessCleanup(
                "embedded PostgreSQL data directory has no application-data parent".to_owned(),
            )
        })?;
        if !reap_embedded_pg(app_data_dir) {
            return Err(DbError::UnsafeProcessCleanup(
                "retained-authority shutdown succeeded but the complete PostgreSQL tree did not exit"
                    .to_owned(),
            ));
        }
    }
    let recovery = async {
        let arguments = vec![
            std::ffi::OsString::from("--single"),
            std::ffi::OsString::from("-D"),
            data_dir.as_os_str().to_os_string(),
            std::ffi::OsString::from("postgres"),
        ];
        let statement = format!("ALTER ROLE {PG_USER} WITH LOGIN PASSWORD '{password}';\n");
        pg.run_postgres_utility_with_input(&arguments, statement.as_bytes(), pg.pg_settings.timeout)
            .await
            .map_err(DbError::from)
    }
    .await;
    let restart = pg.start_db().await;
    if restart.is_ok() {
        let pidfile = data_dir.join("postmaster.pid");
        let registration = match pg.process_capability() {
            Some(process) => arm_verified_postgres(&pidfile, expected_postgres.clone(), process)
                .map_err(|failure| DbError::UnsafeProcessCleanup(failure.message().to_owned())),
            None => Err(DbError::UnsafeProcessCleanup(
                "restarted PostgreSQL has no exact-process capability".to_owned(),
            )),
        };
        match registration {
            Ok(armed) => arm_embedded_postgres_reaper(armed),
            Err(error) => {
                // Never return a successfully restarted postmaster without
                // registering its retained tree authority.
                if pg.stop_db().await.is_err() {
                    if let Some(process) = pg.process_capability() {
                        let _ = process.terminate_force();
                        let _ = pg.mark_process_stopped_externally();
                    }
                }
                return Err(error);
            }
        }
    }
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

/// Connect to an externally managed PostgreSQL instance (dev/CI path).
/// Returns only a coarse failure stage so source diagnostics cannot leak
/// through logs or renderer IPC. The server still starts on failure and
/// DB-backed routes return 503.
///
/// Production requires `sslmode=verify-full`; weaker or missing TLS modes are
/// rejected before any network connection is attempted. Explicit development
/// mode preserves SQLx's configured/default behavior for local databases.
///
/// Runs `sqlx::migrate!` after connect so a fresh external database is
/// brought to the same schema state as the embedded path. On migration
/// failure, the pool is explicitly closed and a sanitized stage is returned.
pub async fn connect_external(database_url: &str) -> Result<PgPool, ExternalDbFailure> {
    let options = match external_pg_connect_options(database_url, crate::env::is_production()) {
        Ok(options) => options,
        Err(_) => return Err(ExternalDbFailure::Connection),
    };
    let pool = match PgPoolOptions::new().connect_with(options).await {
        Ok(p) => p,
        Err(_) => {
            return Err(ExternalDbFailure::Connection);
        }
    };
    if sqlx::migrate!("../migrations").run(&pool).await.is_err() {
        pool.close().await;
        return Err(ExternalDbFailure::Migration);
    }
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_managed_pg_settings_are_last(config: &str) {
        let managed_port = format!("port = {PG_PORT}");
        for (managed_setting, insecure_setting) in [
            ("listen_addresses = '127.0.0.1'", "listen_addresses = '*'"),
            (managed_port.as_str(), "port = 9999"),
            (
                "password_encryption = 'scram-sha-256'",
                "password_encryption = 'md5'",
            ),
            ("fsync = on", "fsync = off"),
            ("synchronous_commit = on", "synchronous_commit = off"),
            ("full_page_writes = on", "full_page_writes = off"),
        ] {
            assert!(
                config.rfind(managed_setting).expect("managed setting")
                    > config.rfind(insecure_setting).expect("insecure fixture"),
                "{managed_setting} must be the last effective value"
            );
        }
    }

    #[test]
    fn managed_postgres_config_pins_security_and_durability_settings() {
        let dir = tempfile::tempdir().expect("temp postgres dir");
        let conf = dir.path().join("postgresql.conf");
        let insecure = "listen_addresses = '*'\n\
                        port = 9999\n\
                        password_encryption = 'md5'\n\
                        fsync = off\n\
                        synchronous_commit = off\n\
                        full_page_writes = off\n";
        std::fs::write(&conf, insecure).expect("write insecure base config");

        patch_pg_conf(dir.path()).expect("patch config");
        patch_pg_conf(dir.path()).expect("idempotent patch");

        let config = std::fs::read_to_string(&conf).expect("read config");
        assert_eq!(
            config
                .matches("# Olympus embedded PostgreSQL managed settings v1")
                .count(),
            1
        );
        assert_managed_pg_settings_are_last(&config);
    }

    #[test]
    fn managed_postgres_config_repairs_later_overrides() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().expect("temp postgres dir");
        let conf = dir.path().join("postgresql.conf");
        std::fs::write(&conf, "# PostgreSQL base config\n").expect("write base config");
        patch_pg_conf(dir.path()).expect("patch config");

        let insecure = "\n# simulated later override\n\
                        listen_addresses = '*'\n\
                        port = 9999\n\
                        password_encryption = 'md5'\n\
                        fsync = off\n\
                        synchronous_commit = off\n\
                        full_page_writes = off\n";
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&conf)
            .expect("open config for override fixture");
        file.write_all(insecure.as_bytes())
            .expect("append insecure overrides");
        file.sync_all().expect("sync override fixture");
        drop(file);

        patch_pg_conf(dir.path()).expect("repair last-wins settings");
        patch_pg_conf(dir.path()).expect("idempotent repaired patch");

        let config = std::fs::read_to_string(&conf).expect("read repaired config");
        assert_eq!(
            config
                .matches("# Olympus embedded PostgreSQL managed settings v1")
                .count(),
            2
        );
        assert_managed_pg_settings_are_last(&config);
    }

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
    fn second_embedded_instance_cannot_reap_the_owned_cluster() {
        let app_data = tempfile::tempdir().expect("temp app-data dir");
        let first = acquire_instance_lock(app_data.path()).expect("first owner acquires lock");
        let second = acquire_instance_lock(app_data.path());
        assert!(matches!(second, Err(DbError::InstanceLocked(_))));

        drop(first);
        acquire_instance_lock(app_data.path()).expect("lock releases with original owner");
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
        report_preserved_init_failure(app_data.path(), &err);

        assert_eq!(
            std::fs::read(&sentinel).expect("persistent data must remain readable"),
            b"must survive every startup failure"
        );
    }

    #[test]
    fn operator_database_diagnostics_never_echo_sensitive_error_text() {
        let marker = "postgres://olympus:secret@example.invalid/private-ledger";
        let errors = [
            DbError::InvalidCredential(marker.to_owned()),
            DbError::CredentialRecovery(marker.to_owned()),
            DbError::Io(std::io::Error::other(marker)),
            DbError::Sqlx(sqlx::Error::Configuration(Box::new(std::io::Error::other(
                marker,
            )))),
        ];

        for error in errors {
            let safe = operator_safe_error(&error);
            let message = embedded_startup_error_message(&error);
            assert!(!safe.contains(marker));
            assert!(!safe.contains("secret"));
            assert!(!message.contains(marker));
            assert!(!message.contains("secret"));
        }

        for failure in [ExternalDbFailure::Connection, ExternalDbFailure::Migration] {
            let message = external_startup_error_message(failure);
            assert!(!message.contains(marker));
            assert!(!message.contains("secret"));
        }
    }

    #[test]
    fn retained_process_authority_survives_failed_termination_attempt() {
        let mut retained = vec![("first exact object", false), ("second exact object", true)];
        assert!(!remove_selected_after_confirmation(
            &mut retained,
            |_| true,
            |(_, confirmed_exit)| *confirmed_exit
        ));
        assert_eq!(retained, vec![("first exact object", false)]);
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
