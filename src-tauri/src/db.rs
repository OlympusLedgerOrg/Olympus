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
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions, PgSslMode};
use sqlx::{Connection, PgPool};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const PG_PORT: u16 = 5433;
const PG_USER: &str = "olympus";
const PG_DB: &str = "olympus";
const EMBEDDED_PASSWORD_FILE: &str = "olympus-pg.password";
pub(crate) const MIGRATION_DATABASE_URL_ENV: &str = "OLYMPUS_DATABASE_MIGRATION_URL";
pub(crate) const DEV_ALLOW_SINGLE_DATABASE_URL_ENV: &str = "OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL";
pub(crate) const PGOPTIONS_ENV: &str = "PGOPTIONS";
const EXTERNAL_PG_AMBIENT_ENV_VARS: &[&str] = &[
    "PGHOST",
    "PGHOSTADDR",
    "PGPORT",
    "PGDATABASE",
    "PGUSER",
    "PGPASSWORD",
    "PGPASSFILE",
    "PGSSLMODE",
    "PGSSLROOTCERT",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGAPPNAME",
    PGOPTIONS_ENV,
];

/// The v0.10.0 runtime DML contract, extracted from every PostgreSQL query in
/// `src-tauri/src` and every object produced by `migrations/`.
///
/// Tables with an empty privilege list are intentional: keeping them in the
/// release manifest makes a future query or migration fail closed until this
/// matrix and its tests are reviewed together. `_sqlx_migrations` is handled
/// separately and is always migration-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExternalPgTableGrant {
    name: &'static str,
    privileges: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExternalPgColumnGrant {
    table_name: &'static str,
    privilege: &'static str,
    columns: &'static [&'static str],
}

const EXTERNAL_PG_TABLE_GRANTS: &[ExternalPgTableGrant] = &[
    ExternalPgTableGrant {
        name: "agencies",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "key_credentials",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "public_records_requests",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "appeals",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "doc_commits",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "dataset_artifacts",
        privileges: &["SELECT"],
    },
    ExternalPgTableGrant {
        name: "dataset_artifact_files",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "dataset_lineage_events",
        privileges: &["SELECT"],
    },
    ExternalPgTableGrant {
        name: "ledger_activities",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "tsa_jobs",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "password_recovery_tokens",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "rekor_anchors",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "users",
        privileges: &["SELECT", "INSERT", "DELETE"],
    },
    ExternalPgTableGrant {
        name: "api_keys",
        privileges: &["SELECT", "INSERT", "DELETE"],
    },
    ExternalPgTableGrant {
        name: "account_signing_keys",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "account_wallet_bindings",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "credential_consents",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "credential_ledger_events",
        privileges: &["SELECT"],
    },
    ExternalPgTableGrant {
        name: "operators",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "anchor_receipts",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "peer_checkpoints",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "credential_quorum_signatures",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "peer_nodes",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "smt_nodes",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "smt_leaves",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "shards",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "ingest_records",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "own_checkpoints",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "checkpoint_quorum_signatures",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "redaction_segment_manifests",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "signed_request_nonces",
        privileges: &["INSERT", "DELETE"],
    },
    ExternalPgTableGrant {
        name: "anchor_submission_claims",
        privileges: &["SELECT", "INSERT"],
    },
];

/// The live runtime can update only fields written by an audited SQL path.
/// Evidence identities and immutable payload columns intentionally never
/// receive table-wide UPDATE.
const EXTERNAL_PG_COLUMN_GRANTS: &[ExternalPgColumnGrant] = &[
    ExternalPgColumnGrant {
        table_name: "key_credentials",
        privilege: "UPDATE",
        columns: &[
            "revoked_at",
            "revoked_sig_r8x",
            "revoked_sig_r8y",
            "revoked_sig_s",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "password_recovery_tokens",
        privilege: "UPDATE",
        columns: &["used_at"],
    },
    ExternalPgColumnGrant {
        table_name: "users",
        privilege: "UPDATE",
        columns: &["password_hash", "role"],
    },
    ExternalPgColumnGrant {
        table_name: "api_keys",
        privilege: "UPDATE",
        columns: &[
            "key_hash",
            "revoked_at",
            "scopes",
            "operator_id",
            "ed25519_public_key",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "account_signing_keys",
        privilege: "UPDATE",
        columns: &[
            "bjj_pubkey_x",
            "bjj_pubkey_y",
            "revoked_at",
            "replaced_by_key_id",
            "revoked_by_key_id",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "anchor_receipts",
        privilege: "UPDATE",
        columns: &[
            "verified_at",
            "ots_upgrade_lease_token",
            "ots_upgrade_lease_until",
            "ots_upgrade_attempts",
            "ots_last_upgrade_attempt_at",
            "ots_next_upgrade_attempt_at",
            "ots_last_upgrade_error",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "peer_checkpoints",
        privilege: "UPDATE",
        columns: &["equivocation_detected"],
    },
    ExternalPgColumnGrant {
        table_name: "peer_nodes",
        privilege: "UPDATE",
        columns: &[
            "trust_status",
            "removed_at",
            "last_seen_at",
            "last_pull_error_at",
            "last_pull_error_msg",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "smt_nodes",
        privilege: "UPDATE",
        columns: &["hash"],
    },
    ExternalPgColumnGrant {
        table_name: "ingest_records",
        privilege: "UPDATE",
        columns: &[
            "chunk_hashes",
            "original_root",
            "snapshot_root",
            "snapshot_index",
            "snapshot_size",
            "snapshot_path",
            "snapshot_sig",
            "snapshot_committed",
            "zk_bundle",
            "smt_committed",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "signed_request_nonces",
        privilege: "SELECT",
        columns: &["key_id", "nonce", "expires_at"],
    },
    ExternalPgColumnGrant {
        table_name: "anchor_submission_claims",
        privilege: "UPDATE",
        columns: &[
            "checkpoint_id",
            "status",
            "receipt_id",
            "lease_token",
            "lease_until",
            "attempt_count",
            "last_attempt_at",
            "next_retry_at",
            "last_error",
            "updated_at",
        ],
    },
];

/// Neither v0.10.0 sequence is used by a live Rust query. UUIDs are generated
/// in-process; these two sequences survive only for retired legacy tables.
const EXTERNAL_PG_SEQUENCE_GRANTS: &[ExternalPgTableGrant] = &[
    ExternalPgTableGrant {
        name: "display_id_seq",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "rekor_anchors_id_seq",
        privileges: &[],
    },
];

/// Standalone application types are a closed release inventory. Table row
/// types and their generated array types are admitted separately by the live
/// catalog probe; every other standalone/user-schema type is unsupported.
const EXTERNAL_PG_ENUM_TYPES: &[&str] = &[
    "agency_level",
    "request_type",
    "request_status",
    "request_priority",
    "appeal_grounds",
    "appeal_status",
];

/// BLAKE3 of the canonical PostgreSQL table, column, sequence, enum, routine,
/// trigger, index, and constraint inventory produced by
/// `external_pg_semantic_inventory_digest`. This is populated from the
/// reviewed v0.10.0 migration result and pins executable write semantics.
const EXTERNAL_PG_SEMANTIC_INVENTORY_BLAKE3: &str =
    "fedad3508eb6b68cc7597476d134d6223e174c0450702e625f8b0b7b0da4178a";
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
    #[error("external database configuration error for {variable}: {reason}")]
    ExternalConfiguration {
        variable: &'static str,
        reason: &'static str,
    },
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
        DbError::ExternalConfiguration { .. } => {
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

/// Safe subset of query parameters accepted by the pinned SQLx PostgreSQL URL
/// parser. Startup-packet `options` are intentionally excluded.
fn supported_external_pg_query_key(key: &str) -> bool {
    matches!(
        key,
        "sslmode"
            | "ssl-mode"
            | "sslrootcert"
            | "ssl-root-cert"
            | "ssl-ca"
            | "sslcert"
            | "ssl-cert"
            | "sslkey"
            | "ssl-key"
            | "statement-cache-capacity"
            | "host"
            | "hostaddr"
            | "port"
            | "dbname"
            | "user"
            | "password"
            | "application_name"
    )
}

/// Reject query parameters SQLx would otherwise ignore and log with their
/// values. This must run before `PgConnectOptions::from_str`: connection URLs
/// commonly carry credentials, and SQLx 0.9 includes an unrecognized
/// parameter's decoded value in a tracing warning.
fn preflight_external_pg_url(value: &str, variable: &'static str) -> Result<(), DbError> {
    let url = url::Url::parse(value).map_err(|_| DbError::ExternalConfiguration {
        variable,
        reason: "must be a valid PostgreSQL URL",
    })?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return Err(DbError::ExternalConfiguration {
            variable,
            reason: "must use a postgres:// or postgresql:// URL",
        });
    }
    if url
        .query_pairs()
        .any(|(key, _)| !supported_external_pg_query_key(&key))
    {
        return Err(DbError::ExternalConfiguration {
            variable,
            reason: "contains an unsupported query parameter",
        });
    }
    Ok(())
}

/// SQLx imports `PGOPTIONS` into every PostgreSQL startup packet, even when
/// the URL itself has no `options` parameter. Those options can change
/// security-sensitive session state such as `role` and `search_path`, so an
/// externally managed database must never inherit them from the launcher.
fn validate_external_pg_ambient_options(
    present_variable: Option<&'static str>,
) -> Result<(), DbError> {
    if let Some(variable) = present_variable {
        return Err(DbError::ExternalConfiguration {
            variable,
            reason:
                "must be unset; external PostgreSQL settings come only from the configured URLs",
        });
    }
    Ok(())
}

/// Parse an external PostgreSQL URL under the environment's TLS policy.
///
/// SQLx maps `verify-full` to certificate-chain and requested-hostname
/// verification. The explicitly enabled Rustls/WebPKI feature supplies public
/// trust roots; private deployments can provide their reviewed CA through the
/// standard `sslrootcert` URL parameter.
fn external_pg_connect_options(
    value: &str,
    variable: &'static str,
    production: bool,
) -> Result<PgConnectOptions, DbError> {
    if value.trim().is_empty() {
        return Err(DbError::ExternalConfiguration {
            variable,
            reason: "must not be empty",
        });
    }
    preflight_external_pg_url(value, variable)?;
    let parsed_url = url::Url::parse(value).map_err(|_| DbError::ExternalConfiguration {
        variable,
        reason: "must be a valid PostgreSQL URL",
    })?;
    if production {
        let has_explicit_database = !parsed_url.path().trim_matches('/').is_empty();
        let has_connection_override = parsed_url.query_pairs().any(|(key, _)| {
            matches!(
                key.as_ref(),
                "host" | "hostaddr" | "port" | "dbname" | "user" | "password"
            )
        });
        if parsed_url.username().is_empty()
            || parsed_url.password().is_none_or(str::is_empty)
            || parsed_url.host_str().is_none()
            || parsed_url.port().is_none()
            || !has_explicit_database
            || has_connection_override
        {
            return Err(DbError::ExternalConfiguration {
                variable,
                reason:
                    "must explicitly set user, password, hostname, port, and database in production",
            });
        }
    }
    // SQLx also reads `.pgpass` during URL parsing and may trace malformed
    // lines verbatim. Keep all dependency diagnostics disabled while handling
    // credential-bearing configuration; Olympus returns only static errors.
    let options =
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::new(), || {
            PgConnectOptions::from_str(value)
        })
        .map_err(|_| DbError::ExternalConfiguration {
            variable,
            reason: "must be a valid PostgreSQL URL",
        })?;

    if production {
        if !matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
            return Err(DbError::ExternalConfiguration {
                variable,
                reason: "must set sslmode=verify-full in production",
            });
        }
        if options.get_socket().is_some() || options.get_host().starts_with('/') {
            return Err(DbError::ExternalConfiguration {
                variable,
                reason: "must use TLS over a hostname, not a local socket, in production",
            });
        }
    }

    Ok(options)
}

struct ExternalPgConnectionPlan {
    migration: PgConnectOptions,
    runtime: PgConnectOptions,
    shared_development_identity: bool,
}

fn effective_database(options: &PgConnectOptions) -> &str {
    options
        .get_database()
        .unwrap_or_else(|| options.get_username())
}

fn effective_socket(options: &PgConnectOptions) -> Option<&Path> {
    options
        .get_socket()
        .map(|socket| socket.as_path())
        .or_else(|| {
            options
                .get_host()
                .starts_with('/')
                .then(|| Path::new(options.get_host()))
        })
}

fn same_database_target(left: &PgConnectOptions, right: &PgConnectOptions) -> bool {
    let same_endpoint = match (effective_socket(left), effective_socket(right)) {
        (Some(left), Some(right)) => left == right,
        (None, None) => left.get_host().eq_ignore_ascii_case(right.get_host()),
        _ => false,
    };
    same_endpoint
        && left.get_port() == right.get_port()
        && effective_database(left) == effective_database(right)
}

/// Resolve the two external PostgreSQL identities without opening a socket.
///
/// A configured migration URL always represents a role distinct from the
/// runtime role. Development may explicitly opt into reusing `DATABASE_URL`;
/// production refuses that compatibility path.
fn external_pg_connection_plan(
    runtime_url: &str,
    migration_url: Option<&str>,
    allow_single_database_url: bool,
    production: bool,
) -> Result<ExternalPgConnectionPlan, DbError> {
    if production && allow_single_database_url {
        return Err(DbError::ExternalConfiguration {
            variable: DEV_ALLOW_SINGLE_DATABASE_URL_ENV,
            reason: "is development-only and forbidden in production",
        });
    }
    if migration_url.is_some() && allow_single_database_url {
        return Err(DbError::ExternalConfiguration {
            variable: DEV_ALLOW_SINGLE_DATABASE_URL_ENV,
            reason: "must be unset when OLYMPUS_DATABASE_MIGRATION_URL is configured",
        });
    }

    let runtime = external_pg_connect_options(runtime_url, "DATABASE_URL", production)?;
    let (migration_url, reuses_runtime_identity) = match migration_url {
        Some(url) => (url, false),
        None if !production && allow_single_database_url => (runtime_url, true),
        None => {
            return Err(DbError::ExternalConfiguration {
                variable: MIGRATION_DATABASE_URL_ENV,
                reason: if production {
                    "is required when DATABASE_URL is set in production"
                } else {
                    "is required unless OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL=true"
                },
            });
        }
    };
    let migration =
        external_pg_connect_options(migration_url, MIGRATION_DATABASE_URL_ENV, production)?;

    if !same_database_target(&migration, &runtime) {
        return Err(DbError::ExternalConfiguration {
            variable: MIGRATION_DATABASE_URL_ENV,
            reason: "must target the same host, port, and database as DATABASE_URL",
        });
    }
    if !reuses_runtime_identity && migration.get_username() == runtime.get_username() {
        return Err(DbError::ExternalConfiguration {
            variable: MIGRATION_DATABASE_URL_ENV,
            reason: "must authenticate as a role distinct from DATABASE_URL",
        });
    }

    Ok(ExternalPgConnectionPlan {
        migration,
        runtime,
        shared_development_identity: reuses_runtime_identity,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExternalPgExpectedSession {
    username: String,
    database: String,
}

impl ExternalPgExpectedSession {
    fn from_options(options: &PgConnectOptions) -> Self {
        Self {
            username: options.get_username().to_owned(),
            database: effective_database(options).to_owned(),
        }
    }
}

/// Server-derived facts used to validate one live external PostgreSQL
/// connection. The query deliberately returns no password, URL, TLS path, or
/// other credential-bearing setting.
#[derive(Clone, Debug, sqlx::FromRow)]
struct ExternalPgSessionProbe {
    server_version_num: i32,
    session_user: String,
    current_user: String,
    current_database: String,
    current_schema: Option<String>,
    configured_search_path: String,
    resolved_search_path: Vec<String>,
    search_path_is_exact_literal: bool,
    is_superuser: bool,
    can_create_role: bool,
    can_create_database: bool,
    can_replicate: bool,
    can_bypass_rls: bool,
    has_database_connect: bool,
    has_database_create: bool,
    has_database_temporary: bool,
    has_direct_database_connect: bool,
    has_direct_database_connect_grant_option: bool,
    public_has_any_database_privilege: bool,
    has_current_schema_usage: bool,
    has_current_schema_create: bool,
    has_direct_current_schema_usage: bool,
    current_schema_acl_has_grant_option: bool,
    public_has_any_current_schema_privilege: bool,
    has_any_off_path_schema_privilege: bool,
    public_has_any_off_path_schema_privilege: bool,
    public_has_create_on_any_non_system_schema: bool,
    has_search_path_schema_create: bool,
    owns_database: bool,
    owns_current_schema: bool,
    owns_search_path_schema: bool,
    owns_search_path_objects: bool,
    can_assume_any_other_role: bool,
    can_assume_dangerous_role: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalPgSessionKind {
    Migration,
    Runtime,
    SharedDevelopment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExternalPgSessionAttestation {
    session_user: String,
    current_database: String,
    current_schema: String,
    configured_search_path: String,
    resolved_search_path: Vec<String>,
}

/// A value-blind policy error suitable for returning through SQLx's
/// `after_connect` hook. Its display text can never contain a URL, role name,
/// database name, schema name, query parameter, or driver error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("external PostgreSQL session policy violation: {reason}")]
struct ExternalPgSessionPolicyError {
    reason: &'static str,
}

fn session_policy_error(reason: &'static str) -> ExternalPgSessionPolicyError {
    ExternalPgSessionPolicyError { reason }
}

const EXTERNAL_PG_SESSION_PROBE_SQL: &str = r#"
SELECT
    current_setting('server_version_num')::integer AS server_version_num,
    session_user::text AS session_user,
    current_user::text AS current_user,
    current_database()::text AS current_database,
    current_schema()::text AS current_schema,
    current_setting('search_path')::text AS configured_search_path,
    current_schemas(false)::text[] AS resolved_search_path,
    (
        current_schema() IS NOT NULL
        AND current_setting('search_path') = pg_catalog.quote_ident(current_schema())
    ) AS search_path_is_exact_literal,
    session_role.rolsuper AS is_superuser,
    session_role.rolcreaterole AS can_create_role,
    session_role.rolcreatedb AS can_create_database,
    session_role.rolreplication AS can_replicate,
    session_role.rolbypassrls AS can_bypass_rls,
    pg_catalog.has_database_privilege(
        session_role.oid,
        current_db.oid,
        'CONNECT'
    ) AS has_database_connect,
    pg_catalog.has_database_privilege(
        session_role.oid,
        current_db.oid,
        'CREATE'
    ) AS has_database_create,
    pg_catalog.has_database_privilege(
        session_role.oid,
        current_db.oid,
        'TEMPORARY'
    ) AS has_database_temporary,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
            COALESCE(
                current_db.datacl,
                pg_catalog.acldefault('d', current_db.datdba)
            )
        ) AS database_acl
        WHERE database_acl.grantee = session_role.oid
          AND database_acl.privilege_type = 'CONNECT'
    ) AS has_direct_database_connect,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(current_db.datacl) AS database_acl
        WHERE database_acl.grantee = session_role.oid
          AND database_acl.privilege_type = 'CONNECT'
          AND database_acl.is_grantable
    ) AS has_direct_database_connect_grant_option,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
            COALESCE(
                current_db.datacl,
                pg_catalog.acldefault('d', current_db.datdba)
            )
        ) AS database_acl
        WHERE database_acl.grantee = 0
    ) AS public_has_any_database_privilege,
    COALESCE(
        pg_catalog.has_schema_privilege(
            session_role.oid,
            current_namespace.oid,
            'USAGE'
        ),
        false
    ) AS has_current_schema_usage,
    COALESCE(
        pg_catalog.has_schema_privilege(
            session_role.oid,
            current_namespace.oid,
            'CREATE'
        ),
        false
    ) AS has_current_schema_create,
    COALESCE(
        EXISTS (
            SELECT 1
            FROM pg_catalog.aclexplode(current_namespace.nspacl) AS schema_acl
            WHERE schema_acl.grantee = session_role.oid
              AND schema_acl.privilege_type = 'USAGE'
              AND NOT schema_acl.is_grantable
        ),
        false
    ) AS has_direct_current_schema_usage,
    COALESCE(
        EXISTS (
            SELECT 1
            FROM pg_catalog.aclexplode(current_namespace.nspacl) AS schema_acl
            WHERE schema_acl.grantee = session_role.oid
              AND schema_acl.is_grantable
        ),
        false
    ) AS current_schema_acl_has_grant_option,
    COALESCE(
        EXISTS (
            SELECT 1
            FROM pg_catalog.aclexplode(
                COALESCE(
                    current_namespace.nspacl,
                    pg_catalog.acldefault('n', current_namespace.nspowner)
                )
            ) AS schema_acl
            WHERE schema_acl.grantee = 0
        ),
        false
    ) AS public_has_any_current_schema_privilege,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS off_path_namespace
        WHERE off_path_namespace.nspname <> current_schema()
          AND off_path_namespace.nspname <> 'information_schema'
          AND off_path_namespace.nspname !~ '^pg_'
          AND (
              pg_catalog.has_schema_privilege(
                  session_role.oid,
                  off_path_namespace.oid,
                  'USAGE'
              )
              OR pg_catalog.has_schema_privilege(
                  session_role.oid,
                  off_path_namespace.oid,
                  'CREATE'
              )
          )
    ) AS has_any_off_path_schema_privilege,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS off_path_namespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                off_path_namespace.nspacl,
                pg_catalog.acldefault('n', off_path_namespace.nspowner)
            )
        ) AS schema_acl
        WHERE off_path_namespace.nspname <> current_schema()
          AND off_path_namespace.nspname <> 'information_schema'
          AND off_path_namespace.nspname !~ '^pg_'
          AND schema_acl.grantee = 0
    ) AS public_has_any_off_path_schema_privilege,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS non_system_namespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                non_system_namespace.nspacl,
                pg_catalog.acldefault('n', non_system_namespace.nspowner)
            )
        ) AS schema_acl
        WHERE non_system_namespace.nspname <> 'information_schema'
          AND non_system_namespace.nspname !~ '^pg_'
          AND schema_acl.grantee = 0
          AND schema_acl.privilege_type = 'CREATE'
    ) AS public_has_create_on_any_non_system_schema,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS path_namespace
        WHERE path_namespace.nspname = ANY(current_schemas(false))
          AND pg_catalog.has_schema_privilege(
              session_role.oid,
              path_namespace.oid,
              'CREATE'
          )
    ) AS has_search_path_schema_create,
    current_db.datdba = session_role.oid AS owns_database,
    COALESCE(
        current_namespace.nspowner = session_role.oid,
        false
    ) AS owns_current_schema,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS path_namespace
        WHERE path_namespace.nspname = ANY(current_schemas(false))
          AND path_namespace.nspowner = session_role.oid
    ) AS owns_search_path_schema,
    (
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS relation_namespace
              ON relation_namespace.oid = relation.relnamespace
            WHERE relation_namespace.nspname = ANY(current_schemas(false))
              AND relation.relowner = session_role.oid
        )
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS routine_namespace
              ON routine_namespace.oid = routine.pronamespace
            WHERE routine_namespace.nspname = ANY(current_schemas(false))
              AND routine.proowner = session_role.oid
        )
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_type AS data_type
            JOIN pg_catalog.pg_namespace AS type_namespace
              ON type_namespace.oid = data_type.typnamespace
            WHERE type_namespace.nspname = ANY(current_schemas(false))
              AND data_type.typowner = session_role.oid
        )
    ) AS owns_search_path_objects,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles AS candidate
        WHERE candidate.oid <> session_role.oid
          AND pg_catalog.pg_has_role(session_role.oid, candidate.oid, 'MEMBER')
    ) AS can_assume_any_other_role,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles AS candidate
        WHERE candidate.oid <> session_role.oid
          AND pg_catalog.pg_has_role(session_role.oid, candidate.oid, 'MEMBER')
          AND (
              candidate.rolsuper
              OR candidate.rolcreaterole
              OR candidate.rolcreatedb
              OR candidate.rolreplication
              OR candidate.rolbypassrls
              OR candidate.oid = current_db.datdba
              OR pg_catalog.has_database_privilege(
                  candidate.oid,
                  current_db.oid,
                  'CREATE'
              )
              OR EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_namespace AS path_namespace
                  WHERE path_namespace.nspname <> 'information_schema'
                    AND path_namespace.nspname !~ '^pg_'
                    AND (
                        path_namespace.nspowner = candidate.oid
                        OR pg_catalog.has_schema_privilege(
                            candidate.oid,
                            path_namespace.oid,
                            'CREATE'
                        )
                    )
              )
              OR EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_class AS relation
                  JOIN pg_catalog.pg_namespace AS relation_namespace
                    ON relation_namespace.oid = relation.relnamespace
                  WHERE relation_namespace.nspname <> 'information_schema'
                    AND relation_namespace.nspname !~ '^pg_'
                    AND relation.relowner = candidate.oid
              )
              OR EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_proc AS routine
                  JOIN pg_catalog.pg_namespace AS routine_namespace
                    ON routine_namespace.oid = routine.pronamespace
                  WHERE routine_namespace.nspname <> 'information_schema'
                    AND routine_namespace.nspname !~ '^pg_'
                    AND routine.proowner = candidate.oid
              )
              OR EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_type AS data_type
                  JOIN pg_catalog.pg_namespace AS type_namespace
                    ON type_namespace.oid = data_type.typnamespace
                  WHERE type_namespace.nspname <> 'information_schema'
                    AND type_namespace.nspname !~ '^pg_'
                    AND data_type.typowner = candidate.oid
              )
          )
    ) AS can_assume_dangerous_role
FROM pg_catalog.pg_roles AS session_role
JOIN pg_catalog.pg_database AS current_db
  ON current_db.datname = current_database()
LEFT JOIN pg_catalog.pg_namespace AS current_namespace
  ON current_namespace.nspname = current_schema()
WHERE session_role.rolname = session_user
"#;

fn unsafe_external_pg_schema_name(value: &str) -> bool {
    let value = value.trim().trim_matches('"');
    value.eq_ignore_ascii_case("pg_temp")
        || value.eq_ignore_ascii_case("pg_catalog")
        || value.eq_ignore_ascii_case("information_schema")
        || value
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("pg_temp_"))
        || value
            .get(..14)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("pg_toast_temp_"))
}

fn configured_search_path_is_safe(value: &str) -> bool {
    !value.trim().is_empty()
        && value
            .split(',')
            .all(|entry| !unsafe_external_pg_schema_name(entry))
}

fn validate_external_pg_migration_maintenance_authority(
    probe: &ExternalPgSessionProbe,
    expected: &ExternalPgExpectedSession,
) -> Result<(), ExternalPgSessionPolicyError> {
    if !(150_000..160_000).contains(&probe.server_version_num) {
        return Err(session_policy_error(
            "external PostgreSQL must use the release-pinned major version 15",
        ));
    }
    if probe.session_user != probe.current_user
        || probe.session_user != expected.username
        || probe.current_database != expected.database
    {
        return Err(session_policy_error(
            "the migration maintenance identity or database does not match configuration",
        ));
    }
    if probe.is_superuser
        || probe.can_create_role
        || probe.can_create_database
        || probe.can_replicate
        || probe.can_bypass_rls
        || probe.owns_database
        || probe.can_assume_any_other_role
        || probe.can_assume_dangerous_role
    {
        return Err(session_policy_error(
            "the migration maintenance identity has forbidden authority",
        ));
    }
    if !probe.has_database_connect
        || !probe.has_direct_database_connect
        || !probe.has_direct_database_connect_grant_option
        || probe.has_database_create
        || probe.has_database_temporary
        || probe.public_has_any_database_privilege
    {
        return Err(session_policy_error(
            "the migration maintenance identity lacks the exact database CONNECT grant",
        ));
    }
    Ok(())
}

fn validate_external_pg_session(
    probe: ExternalPgSessionProbe,
    expected: &ExternalPgExpectedSession,
    kind: ExternalPgSessionKind,
) -> Result<ExternalPgSessionAttestation, ExternalPgSessionPolicyError> {
    if !(150_000..160_000).contains(&probe.server_version_num) {
        return Err(session_policy_error(
            "external PostgreSQL must use the release-pinned major version 15",
        ));
    }
    if probe.session_user != probe.current_user {
        return Err(session_policy_error("current_user must equal session_user"));
    }
    if probe.session_user != expected.username {
        return Err(session_policy_error(
            "the live login role does not match the configured role",
        ));
    }
    if probe.current_database != expected.database {
        return Err(session_policy_error(
            "the live database does not match the configured database",
        ));
    }
    if probe.is_superuser {
        return Err(session_policy_error(
            "external database roles must not be superusers",
        ));
    }
    if probe.can_create_role
        || probe.can_create_database
        || probe.can_replicate
        || probe.can_bypass_rls
    {
        return Err(session_policy_error(
            "external database roles must not have cluster-level administrative attributes",
        ));
    }
    if probe.can_assume_dangerous_role {
        return Err(session_policy_error(
            "the live role can assume another role with database or schema authority",
        ));
    }
    if !probe.has_database_connect
        || probe.has_database_create
        || probe.has_database_temporary
        || !probe.has_direct_database_connect
        || probe.public_has_any_database_privilege
        || probe.owns_database
    {
        return Err(session_policy_error(
            "external database CONNECT, TEMPORARY, CREATE, ownership, or grant-option policy is not satisfied",
        ));
    }
    match kind {
        ExternalPgSessionKind::Migration => {
            if !probe.has_direct_database_connect_grant_option {
                return Err(session_policy_error(
                    "the migration role requires a direct CONNECT grant option for fail-closed maintenance",
                ));
            }
        }
        ExternalPgSessionKind::Runtime | ExternalPgSessionKind::SharedDevelopment => {
            if probe.has_direct_database_connect_grant_option {
                return Err(session_policy_error(
                    "the runtime database CONNECT privilege must not be grantable",
                ));
            }
        }
    }
    if probe.can_assume_any_other_role {
        return Err(session_policy_error(
            "external application roles must not be able to assume another role",
        ));
    }

    let current_schema = probe
        .current_schema
        .ok_or_else(|| session_policy_error("the live session has no current schema"))?;
    if unsafe_external_pg_schema_name(&current_schema)
        || probe.resolved_search_path.len() != 1
        || probe
            .resolved_search_path
            .iter()
            .any(|schema| unsafe_external_pg_schema_name(schema))
        || probe.resolved_search_path.first() != Some(&current_schema)
        || !probe.search_path_is_exact_literal
        || !configured_search_path_is_safe(&probe.configured_search_path)
        || !probe.has_current_schema_usage
        || probe.current_schema_acl_has_grant_option
        || probe.public_has_any_current_schema_privilege
        || probe.has_any_off_path_schema_privilege
        || probe.public_has_any_off_path_schema_privilege
        || probe.public_has_create_on_any_non_system_schema
    {
        return Err(session_policy_error(
            "the live session has an unsafe, unresolved, or over-privileged schema path",
        ));
    }

    match kind {
        ExternalPgSessionKind::Migration | ExternalPgSessionKind::SharedDevelopment => {
            if !probe.has_current_schema_create {
                return Err(session_policy_error(
                    "the migration role must be able to create objects in the sole configured application schema",
                ));
            }
        }
        ExternalPgSessionKind::Runtime => {
            if !probe.has_direct_current_schema_usage
                || probe.has_search_path_schema_create
                || probe.owns_search_path_schema
                || probe.owns_search_path_objects
            {
                return Err(session_policy_error(
                    "the runtime role has DDL or ownership authority in its search_path",
                ));
            }
        }
    }

    Ok(ExternalPgSessionAttestation {
        session_user: probe.session_user,
        current_database: probe.current_database,
        current_schema,
        configured_search_path: probe.configured_search_path,
        resolved_search_path: probe.resolved_search_path,
    })
}

fn validate_external_pg_session_pair(
    migration: &ExternalPgSessionAttestation,
    runtime: &ExternalPgSessionAttestation,
    runtime_is_member_of_migration_role: bool,
    shared_development_identity: bool,
) -> Result<(), ExternalPgSessionPolicyError> {
    if shared_development_identity {
        if migration.session_user != runtime.session_user {
            return Err(session_policy_error(
                "the explicitly shared development identity changed between sessions",
            ));
        }
    } else {
        if migration.session_user == runtime.session_user {
            return Err(session_policy_error(
                "migration and runtime must use distinct live session users",
            ));
        }
        if runtime_is_member_of_migration_role {
            return Err(session_policy_error(
                "the runtime role must not be a member of the migration role",
            ));
        }
    }
    if migration.current_database != runtime.current_database {
        return Err(session_policy_error(
            "migration and runtime resolved different live databases",
        ));
    }
    if migration.current_schema != runtime.current_schema
        || migration.configured_search_path != runtime.configured_search_path
        || migration.resolved_search_path != runtime.resolved_search_path
    {
        return Err(session_policy_error(
            "migration and runtime resolved different schema search paths",
        ));
    }
    Ok(())
}

async fn probe_external_pg_connection(
    connection: &mut PgConnection,
) -> Result<ExternalPgSessionProbe, sqlx::Error> {
    sqlx::query_as::<_, ExternalPgSessionProbe>(EXTERNAL_PG_SESSION_PROBE_SQL)
        .fetch_one(&mut *connection)
        .await
}

async fn runtime_is_member_of_migration_role(
    connection: &mut PgConnection,
    migration_role: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT pg_catalog.pg_has_role(current_user::text, $1::text, 'MEMBER')",
    )
    .bind(migration_role)
    .fetch_one(&mut *connection)
    .await
}

fn external_pg_grant_spec(grants: &[ExternalPgTableGrant]) -> String {
    serde_json::Value::Array(
        grants
            .iter()
            .map(|grant| {
                serde_json::json!({
                    "name": grant.name,
                    "privileges": grant.privileges,
                })
            })
            .collect(),
    )
    .to_string()
}

fn external_pg_column_grant_spec(grants: &[ExternalPgColumnGrant]) -> String {
    serde_json::Value::Array(
        grants
            .iter()
            .map(|grant| {
                serde_json::json!({
                    "table_name": grant.table_name,
                    "privilege": grant.privilege,
                    "columns": grant.columns,
                })
            })
            .collect(),
    )
    .to_string()
}

/// ASCII `OLYP` in the upper 32 bits of the advisory-lock key. The namespace's
/// top bit is clear, so combining it with any unsigned PostgreSQL database OID
/// produces an exactly reversible, positive signed `bigint`.
const EXTERNAL_PG_MAINTENANCE_LOCK_NAMESPACE: i64 = 1_330_403_664;

fn external_pg_maintenance_lock_key(database_oid: u32) -> i64 {
    (EXTERNAL_PG_MAINTENANCE_LOCK_NAMESPACE << 32) | i64::from(database_oid)
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct ExternalPgAdvisoryLockProbe {
    database_oid: i64,
    lock_key: i64,
    acquired: bool,
}

const EXTERNAL_PG_MAINTENANCE_LOCK_SQL: &str = r#"
WITH current_db AS (
    SELECT database.oid::bigint AS database_oid
    FROM pg_catalog.pg_database AS database
    WHERE database.datname = current_database()
),
lock_identity AS (
    SELECT
        current_db.database_oid,
        (
            ($1::bigint << 32)
            | current_db.database_oid
        ) AS lock_key
    FROM current_db
)
SELECT
    lock_identity.database_oid,
    lock_identity.lock_key,
    pg_catalog.pg_try_advisory_lock(
        lock_identity.lock_key
    ) AS acquired
FROM lock_identity
"#;

const EXTERNAL_PG_RUNTIME_LOCK_SQL: &str = r#"
WITH current_db AS (
    SELECT database.oid::bigint AS database_oid
    FROM pg_catalog.pg_database AS database
    WHERE database.datname = current_database()
),
lock_identity AS (
    SELECT
        current_db.database_oid,
        (
            ($1::bigint << 32)
            | current_db.database_oid
        ) AS lock_key
    FROM current_db
)
SELECT
    lock_identity.database_oid,
    lock_identity.lock_key,
    pg_catalog.pg_try_advisory_lock_shared(
        lock_identity.lock_key
    ) AS acquired
FROM lock_identity
"#;

const EXTERNAL_PG_MAINTENANCE_UNLOCK_SQL: &str = r#"
SELECT pg_catalog.pg_advisory_unlock(
    (
        ($1::bigint << 32)
        | (
            SELECT database.oid::bigint
            FROM pg_catalog.pg_database AS database
            WHERE database.datname = current_database()
        )
    )
)
"#;

const EXTERNAL_PG_RUNTIME_LOCK_HELD_SQL: &str = r#"
WITH current_db AS (
    SELECT database.oid AS database_oid
    FROM pg_catalog.pg_database AS database
    WHERE database.datname = current_database()
)
SELECT
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks AS held_lock
        CROSS JOIN current_db
        WHERE held_lock.locktype = 'advisory'
          AND held_lock.database = current_db.database_oid
          AND held_lock.pid = pg_catalog.pg_backend_pid()
          AND held_lock.classid::bigint = $1::bigint
          AND held_lock.objid = current_db.database_oid
          AND held_lock.objsubid = 1
          AND held_lock.mode = 'ShareLock'
          AND held_lock.granted
    )
    AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks AS held_lock
        CROSS JOIN current_db
        WHERE held_lock.locktype = 'advisory'
          AND held_lock.database = current_db.database_oid
          AND held_lock.pid = pg_catalog.pg_backend_pid()
          AND held_lock.classid::bigint = $1::bigint
          AND held_lock.objid = current_db.database_oid
          AND held_lock.objsubid = 1
          AND held_lock.mode = 'ExclusiveLock'
          AND held_lock.granted
    ) AS held
"#;

async fn acquire_external_pg_advisory_lock(
    connection: &mut PgConnection,
    statement: &'static str,
) -> bool {
    sqlx::query_as::<_, ExternalPgAdvisoryLockProbe>(statement)
        .bind(EXTERNAL_PG_MAINTENANCE_LOCK_NAMESPACE)
        .fetch_one(&mut *connection)
        .await
        .ok()
        .and_then(|probe| {
            let database_oid = u32::try_from(probe.database_oid).ok()?;
            Some(probe.acquired && probe.lock_key == external_pg_maintenance_lock_key(database_oid))
        })
        .unwrap_or(false)
}

async fn acquire_external_pg_maintenance_lock(connection: &mut PgConnection) -> bool {
    acquire_external_pg_advisory_lock(connection, EXTERNAL_PG_MAINTENANCE_LOCK_SQL).await
}

async fn acquire_external_pg_runtime_lock(connection: &mut PgConnection) -> bool {
    acquire_external_pg_advisory_lock(connection, EXTERNAL_PG_RUNTIME_LOCK_SQL).await
}

async fn external_pg_runtime_lock_is_held(
    connection: &mut PgConnection,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(EXTERNAL_PG_RUNTIME_LOCK_HELD_SQL)
        .bind(EXTERNAL_PG_MAINTENANCE_LOCK_NAMESPACE)
        .fetch_one(&mut *connection)
        .await
}

async fn release_external_pg_maintenance_lock(connection: &mut PgConnection) -> bool {
    sqlx::query_scalar::<_, bool>(EXTERNAL_PG_MAINTENANCE_UNLOCK_SQL)
        .bind(EXTERNAL_PG_MAINTENANCE_LOCK_NAMESPACE)
        .fetch_one(&mut *connection)
        .await
        .unwrap_or(false)
}

const EXTERNAL_PG_SET_RUNTIME_CONNECT_SQL: &str = r#"
DO $olympus$
DECLARE
    runtime_role name := current_setting('olympus.runtime_role', false)::name;
    enable_connect boolean :=
        current_setting('olympus.enable_runtime_connect', false)::boolean;
BEGIN
    IF runtime_role::text = current_user::text
       OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_roles
           WHERE rolname = runtime_role::text
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL maintenance precondition failed';
    END IF;

    IF enable_connect THEN
        EXECUTE pg_catalog.format(
            'GRANT CONNECT ON DATABASE %I TO %I',
            current_database(),
            runtime_role
        );
    ELSE
        EXECUTE pg_catalog.format(
            'REVOKE CONNECT ON DATABASE %I FROM %I CASCADE',
            current_database(),
            runtime_role
        );
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL runtime CONNECT transition failed';
END
$olympus$
"#;

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct ExternalPgMaintenanceProbe {
    runtime_has_effective_connect: bool,
    runtime_active_sessions: i64,
    runtime_prepared_transactions: i64,
}

const EXTERNAL_PG_MAINTENANCE_PROBE_SQL: &str = r#"
WITH RECURSIVE runtime_role AS (
    SELECT role.oid, role.rolname
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = $1
),
runtime_principals(oid) AS (
    SELECT runtime_role.oid
    FROM runtime_role
    UNION
    SELECT membership.member
    FROM pg_catalog.pg_auth_members AS membership
    JOIN runtime_principals AS principal
      ON membership.roleid = principal.oid
)
SELECT
    COALESCE(
        pg_catalog.has_database_privilege(
            runtime_role.oid,
            current_database(),
            'CONNECT'
        ),
        false
    ) AS runtime_has_effective_connect,
    (
          SELECT count(*)::bigint
          FROM pg_catalog.pg_stat_activity AS activity
          WHERE activity.datname = current_database()
            AND activity.usesysid IN (
                SELECT principal.oid
                FROM runtime_principals AS principal
            )
      ) AS runtime_active_sessions,
    (
        SELECT count(*)::bigint
        FROM pg_catalog.pg_prepared_xacts AS prepared
          JOIN pg_catalog.pg_roles AS prepared_owner
            ON prepared_owner.rolname = prepared.owner
          WHERE prepared.database = current_database()
            AND prepared_owner.oid IN (
                SELECT principal.oid
                FROM runtime_principals AS principal
            )
      ) AS runtime_prepared_transactions
FROM runtime_role
"#;

/// Remove every non-owner privilege from existing application objects and
/// from both layers of the migration role's default ACL before any migration
/// runs. This is deliberately broader than the release grant matrix: the
/// runtime remains disconnected until the post-migration closed inventory is
/// verified and the exact grants are installed.
const EXTERNAL_PG_HARDEN_BEFORE_MIGRATIONS_SQL: &str = r#"
DO $olympus$
DECLARE
    app_schema name := current_schema();
    runtime_role name := current_setting('olympus.runtime_role', false)::name;
    object_record record;
    grantee_record record;
    privilege_class text;
BEGIN
    IF app_schema IS NULL
       OR runtime_role::text = current_user::text
       OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_namespace
           WHERE nspname = app_schema::text
             AND pg_catalog.has_schema_privilege(current_user, oid, 'CREATE')
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL hardening precondition failed';
    END IF;

    EXECUTE pg_catalog.format(
        'REVOKE CONNECT ON DATABASE %I FROM PUBLIC CASCADE',
        current_database()
    );
    FOR grantee_record IN
        SELECT role.rolname
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname <> current_user
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE CONNECT ON DATABASE %I FROM %I CASCADE',
            current_database(),
            grantee_record.rolname
        );
    END LOOP;

    EXECUTE pg_catalog.format(
        'REVOKE ALL PRIVILEGES ON SCHEMA %I FROM PUBLIC CASCADE',
        app_schema
    );
    FOR grantee_record IN
        SELECT role.rolname
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname <> current_user
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON SCHEMA %I FROM %I CASCADE',
            app_schema,
            grantee_record.rolname
        );
    END LOOP;

    FOR object_record IN
        SELECT relation.relname, relation.relowner
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = app_schema::text
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM PUBLIC CASCADE',
            app_schema,
            object_record.relname
        );
        FOR grantee_record IN
            SELECT role.rolname
            FROM pg_catalog.pg_roles AS role
            WHERE role.oid <> object_record.relowner
        LOOP
            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I CASCADE',
                app_schema,
                object_record.relname,
                grantee_record.rolname
            );
        END LOOP;
    END LOOP;

    FOR object_record IN
        SELECT relation.relname, relation.relowner
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = app_schema::text
          AND relation.relkind = 'S'
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM PUBLIC CASCADE',
            app_schema,
            object_record.relname
        );
        FOR grantee_record IN
            SELECT role.rolname
            FROM pg_catalog.pg_roles AS role
            WHERE role.oid <> object_record.relowner
        LOOP
            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM %I CASCADE',
                app_schema,
                object_record.relname,
                grantee_record.rolname
            );
        END LOOP;
    END LOOP;

    FOR object_record IN
        SELECT
            routine.oid::pg_catalog.regprocedure::text AS identity,
            routine.proowner,
            CASE
                WHEN routine.prokind = 'p' THEN 'PROCEDURE'
                ELSE 'FUNCTION'
            END AS object_kind
        FROM pg_catalog.pg_proc AS routine
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = routine.pronamespace
        WHERE namespace.nspname = app_schema::text
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON %s %s FROM PUBLIC CASCADE',
            object_record.object_kind,
            object_record.identity
        );
        FOR grantee_record IN
            SELECT role.rolname
            FROM pg_catalog.pg_roles AS role
            WHERE role.oid <> object_record.proowner
        LOOP
            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES ON %s %s FROM %I CASCADE',
                object_record.object_kind,
                object_record.identity,
                grantee_record.rolname
            );
        END LOOP;
    END LOOP;

    FOR object_record IN
        SELECT data_type.typname, data_type.typowner
        FROM pg_catalog.pg_type AS data_type
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        WHERE namespace.nspname = app_schema::text
          AND data_type.typelem = 0
          AND (
              data_type.typrelid = 0
              OR EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_class AS type_relation
                  WHERE type_relation.oid = data_type.typrelid
                    AND type_relation.relkind = 'c'
              )
          )
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TYPE %I.%I FROM PUBLIC CASCADE',
            app_schema,
            object_record.typname
        );
        FOR grantee_record IN
            SELECT role.rolname
            FROM pg_catalog.pg_roles AS role
            WHERE role.oid <> object_record.typowner
        LOOP
            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES ON TYPE %I.%I FROM %I CASCADE',
                app_schema,
                object_record.typname,
                grantee_record.rolname
            );
        END LOOP;
    END LOOP;

    FOREACH privilege_class IN ARRAY
        ARRAY['TABLES', 'SEQUENCES', 'FUNCTIONS', 'TYPES', 'SCHEMAS']
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE ALL PRIVILEGES ON %s FROM PUBLIC CASCADE',
            current_user,
            privilege_class
        );
        FOR grantee_record IN
            SELECT role.rolname
            FROM pg_catalog.pg_roles AS role
            WHERE role.rolname <> current_user
        LOOP
            EXECUTE pg_catalog.format(
                'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE ALL PRIVILEGES ON %s FROM %I CASCADE',
                current_user,
                privilege_class,
                grantee_record.rolname
            );
        END LOOP;
    END LOOP;

    FOR object_record IN
        SELECT namespace.nspname
        FROM pg_catalog.pg_namespace AS namespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
    LOOP
        FOREACH privilege_class IN ARRAY
            ARRAY['TABLES', 'SEQUENCES', 'FUNCTIONS', 'TYPES']
        LOOP
            EXECUTE pg_catalog.format(
                'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL PRIVILEGES ON %s FROM PUBLIC CASCADE',
                current_user,
                object_record.nspname,
                privilege_class
            );
            FOR grantee_record IN
                SELECT role.rolname
                FROM pg_catalog.pg_roles AS role
                WHERE role.rolname <> current_user
            LOOP
                EXECUTE pg_catalog.format(
                    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL PRIVILEGES ON %s FROM %I CASCADE',
                    current_user,
                    object_record.nspname,
                    privilege_class,
                    grantee_record.rolname
                );
            END LOOP;
        END LOOP;
    END LOOP;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL pre-migration hardening failed';
END
$olympus$
"#;

async fn set_external_pg_runtime_connect(
    connection: &mut PgConnection,
    runtime_role: &str,
    enabled: bool,
) -> Result<(), sqlx::Error> {
    let mut transaction = connection.begin().await?;
    sqlx::query("SELECT set_config('client_min_messages', 'error', true)")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.runtime_role', $1, true)")
        .bind(runtime_role)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.enable_runtime_connect', $1, true)")
        .bind(if enabled { "true" } else { "false" })
        .execute(&mut *transaction)
        .await?;
    sqlx::query(EXTERNAL_PG_SET_RUNTIME_CONNECT_SQL)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await
}

async fn probe_external_pg_maintenance(
    connection: &mut PgConnection,
    runtime_role: &str,
) -> Result<ExternalPgMaintenanceProbe, sqlx::Error> {
    sqlx::query_as::<_, ExternalPgMaintenanceProbe>(EXTERNAL_PG_MAINTENANCE_PROBE_SQL)
        .bind(runtime_role)
        .fetch_one(&mut *connection)
        .await
}

fn validate_external_pg_quiescence(
    probe: &ExternalPgMaintenanceProbe,
) -> Result<(), ExternalPgSessionPolicyError> {
    if probe.runtime_has_effective_connect
        || probe.runtime_active_sessions != 0
        || probe.runtime_prepared_transactions != 0
    {
        return Err(session_policy_error(
            "external PostgreSQL maintenance requires revoked runtime CONNECT, zero runtime sessions, and zero runtime prepared transactions",
        ));
    }
    Ok(())
}

async fn harden_external_pg_before_migrations(
    connection: &mut PgConnection,
    runtime_role: &str,
) -> Result<(), sqlx::Error> {
    let mut transaction = connection.begin().await?;
    sqlx::query("SELECT set_config('client_min_messages', 'error', true)")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.runtime_role', $1, true)")
        .bind(runtime_role)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(EXTERNAL_PG_HARDEN_BEFORE_MIGRATIONS_SQL)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct ExternalPgTrustedBoundaryProbe {
    has_untrusted_boundary: bool,
}

const EXTERNAL_PG_TRUSTED_BOUNDARY_PROBE_SQL: &str = r#"
WITH RECURSIVE
current_db AS (
    SELECT database.oid, database.datdba, database.datacl
    FROM pg_catalog.pg_database AS database
    WHERE database.datname = current_database()
),
migration_role AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = $1
),
runtime_role AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = $2
),
database_owner_role AS (
    SELECT
        role.oid,
        role.rolcanlogin,
        role.rolsuper,
        role.rolcreaterole,
        role.rolcreatedb,
        role.rolreplication,
        role.rolbypassrls
    FROM current_db
    JOIN pg_catalog.pg_roles AS role
      ON role.oid = current_db.datdba
),
pg_database_owner_role AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'pg_database_owner'
),
trusted_acl_roles AS (
    SELECT oid FROM database_owner_role
    UNION
    SELECT oid FROM migration_role
    UNION
    SELECT oid FROM runtime_role
    UNION
    SELECT oid FROM pg_database_owner_role
),
trusted_creator_roles AS (
    SELECT oid FROM database_owner_role
    UNION
    SELECT oid FROM migration_role
),
trusted_grantor_roles AS (
    SELECT oid FROM database_owner_role
    UNION
    SELECT oid FROM migration_role
    UNION
    SELECT oid FROM pg_database_owner_role
),
protected_roles AS (
    SELECT oid FROM database_owner_role
    UNION
    SELECT oid FROM migration_role
    UNION
    SELECT oid FROM runtime_role
),
protected_role_members(oid) AS (
    SELECT membership.member
    FROM pg_catalog.pg_auth_members AS membership
    JOIN protected_roles AS protected
      ON protected.oid = membership.roleid
    UNION
    SELECT membership.member
    FROM pg_catalog.pg_auth_members AS membership
    JOIN protected_role_members AS inherited_member
      ON inherited_member.oid = membership.roleid
),
default_object_types(object_type) AS (
    VALUES
        ('r'::"char"),
        ('S'::"char"),
        ('f'::"char"),
        ('T'::"char"),
        ('n'::"char")
),
effective_global_defaults AS (
    SELECT
        creator.oid AS creator_oid,
        object_types.object_type,
        default_privilege.*
    FROM trusted_creator_roles AS creator
    CROSS JOIN default_object_types AS object_types
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(
            (
                SELECT default_acl.defaclacl
                FROM pg_catalog.pg_default_acl AS default_acl
                WHERE default_acl.defaclrole = creator.oid
                  AND default_acl.defaclnamespace = 0
                  AND default_acl.defaclobjtype = object_types.object_type
            ),
            pg_catalog.acldefault(object_types.object_type, creator.oid)
        )
    ) AS default_privilege
),
effective_schema_defaults AS (
    SELECT
        default_acl.defaclrole AS creator_oid,
        default_acl.defaclobjtype AS object_type,
        default_privilege.*
    FROM pg_catalog.pg_default_acl AS default_acl
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        default_acl.defaclacl
    ) AS default_privilege
    WHERE default_acl.defaclnamespace <> 0
),
semantic_object_owners AS (
    SELECT collation_record.collowner AS owner_oid
    FROM pg_catalog.pg_collation AS collation_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = collation_record.collnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT conversion_record.conowner
    FROM pg_catalog.pg_conversion AS conversion_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = conversion_record.connamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT operator_record.oprowner
    FROM pg_catalog.pg_operator AS operator_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = operator_record.oprnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT operator_class_record.opcowner
    FROM pg_catalog.pg_opclass AS operator_class_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = operator_class_record.opcnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT operator_family_record.opfowner
    FROM pg_catalog.pg_opfamily AS operator_family_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = operator_family_record.opfnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT text_search_config_record.cfgowner
    FROM pg_catalog.pg_ts_config AS text_search_config_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = text_search_config_record.cfgnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT text_search_dictionary_record.dictowner
    FROM pg_catalog.pg_ts_dict AS text_search_dictionary_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = text_search_dictionary_record.dictnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT statistics_record.stxowner
    FROM pg_catalog.pg_statistic_ext AS statistics_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = statistics_record.stxnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
)
SELECT (
    NOT EXISTS (SELECT 1 FROM migration_role)
    OR NOT EXISTS (SELECT 1 FROM runtime_role)
    OR EXISTS (
        SELECT 1
        FROM migration_role
        CROSS JOIN runtime_role
        CROSS JOIN database_owner_role
        WHERE migration_role.oid = runtime_role.oid
           OR migration_role.oid = database_owner_role.oid
           OR runtime_role.oid = database_owner_role.oid
    )
    OR EXISTS (
        SELECT 1
        FROM database_owner_role
        WHERE database_owner_role.rolcanlogin
           OR database_owner_role.rolsuper
           OR database_owner_role.rolcreaterole
           OR database_owner_role.rolcreatedb
           OR database_owner_role.rolreplication
           OR database_owner_role.rolbypassrls
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.member IN (
            SELECT oid FROM migration_role
            UNION
            SELECT oid FROM runtime_role
            UNION
            SELECT oid FROM database_owner_role
        )
    )
    OR EXISTS (
        SELECT 1
        FROM current_db
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                current_db.datacl,
                pg_catalog.acldefault('d', current_db.datdba)
            )
        ) AS object_acl
        WHERE object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
           OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS namespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND namespace.nspowner NOT IN (
              SELECT oid FROM trusted_acl_roles
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS namespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                namespace.nspacl,
                pg_catalog.acldefault('n', namespace.nspowner)
            )
        ) AS object_acl
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND (
              object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
              OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND relation.relowner NOT IN (
              SELECT oid FROM trusted_creator_roles
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                relation.relacl,
                pg_catalog.acldefault(
                    (
                        CASE
                            WHEN relation.relkind = 'S' THEN 'S'
                            ELSE 'r'
                        END
                    )::"char",
                    relation.relowner
                )
            )
        ) AS object_acl
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
          AND (
              object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
              OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute AS attribute
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = attribute.attrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            attribute.attacl
        ) AS object_acl
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND (
              object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
              OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS routine
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = routine.pronamespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND routine.proowner NOT IN (
              SELECT oid FROM trusted_creator_roles
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS routine
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = routine.pronamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                routine.proacl,
                pg_catalog.acldefault('f', routine.proowner)
            )
        ) AS object_acl
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND (
              object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
              OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS data_type
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND data_type.typowner NOT IN (
              SELECT oid FROM trusted_creator_roles
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS data_type
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                data_type.typacl,
                pg_catalog.acldefault('T', data_type.typowner)
            )
        ) AS object_acl
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND data_type.typelem = 0
          AND (
              data_type.typrelid = 0
              OR EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_class AS type_relation
                  WHERE type_relation.oid = data_type.typrelid
                    AND type_relation.relkind = 'c'
              )
          )
          AND (
              object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
              OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM semantic_object_owners
        WHERE semantic_object_owners.owner_oid NOT IN (
            SELECT oid FROM trusted_creator_roles
        )
    )
    OR EXISTS (
        SELECT 1
        FROM effective_global_defaults AS default_privilege
        WHERE default_privilege.grantor <> default_privilege.creator_oid
           OR default_privilege.grantee <> default_privilege.creator_oid
    )
    OR EXISTS (
        SELECT 1
        FROM effective_schema_defaults AS default_privilege
        WHERE default_privilege.creator_oid NOT IN (
                  SELECT oid FROM trusted_creator_roles
              )
           OR default_privilege.grantor <> default_privilege.creator_oid
           OR default_privilege.grantee <> default_privilege.creator_oid
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_default_acl AS default_acl
        WHERE default_acl.defaclrole NOT IN (
            SELECT oid FROM trusted_creator_roles
        )
    )
    OR EXISTS (SELECT 1 FROM protected_role_members)
) AS has_untrusted_boundary
"#;

async fn probe_external_pg_trusted_boundary(
    connection: &mut PgConnection,
    migration_role: &str,
    runtime_role: &str,
) -> Result<ExternalPgTrustedBoundaryProbe, sqlx::Error> {
    sqlx::query_as::<_, ExternalPgTrustedBoundaryProbe>(EXTERNAL_PG_TRUSTED_BOUNDARY_PROBE_SQL)
        .bind(migration_role)
        .bind(runtime_role)
        .fetch_one(&mut *connection)
        .await
}

fn validate_external_pg_trusted_boundary(
    probe: &ExternalPgTrustedBoundaryProbe,
) -> Result<(), ExternalPgSessionPolicyError> {
    if probe.has_untrusted_boundary {
        return Err(session_policy_error(
            "external PostgreSQL contains an untrusted owner, ACL grantor/grantee, default-ACL creator, or role membership",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct ExternalPgClosedCatalogProbe {
    has_unsupported_object: bool,
}

const EXTERNAL_PG_CLOSED_CATALOG_PROBE_SQL: &str = r#"
WITH
expected_tables(name) AS (
    SELECT pg_catalog.unnest($1::text[])
    UNION ALL
    SELECT '_sqlx_migrations'::text
),
expected_enums(name) AS (
    SELECT pg_catalog.unnest($2::text[])
),
expected_sequences(name) AS (
    SELECT pg_catalog.unnest($3::text[])
),
accepted_base_types AS (
    SELECT data_type.oid
    FROM pg_catalog.pg_type AS data_type
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = data_type.typnamespace
    JOIN expected_enums
      ON expected_enums.name = data_type.typname
    WHERE namespace.nspname = current_schema()
      AND data_type.typtype = 'e'
    UNION
    SELECT data_type.oid
    FROM pg_catalog.pg_type AS data_type
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = data_type.typnamespace
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid = data_type.typrelid
    JOIN expected_tables
      ON expected_tables.name = relation.relname
    WHERE namespace.nspname = current_schema()
      AND data_type.typtype = 'c'
      AND relation.relkind IN ('r', 'p')
),
accepted_types AS (
    SELECT oid FROM accepted_base_types
    UNION
    SELECT array_type.oid
    FROM pg_catalog.pg_type AS array_type
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = array_type.typnamespace
    JOIN accepted_base_types
      ON accepted_base_types.oid = array_type.typelem
    WHERE namespace.nspname = current_schema()
)
SELECT (
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
          AND relation.relkind IN ('r', 'p')
          AND relation.relname NOT IN (
              SELECT expected_tables.name FROM expected_tables
          )
    )
    OR EXISTS (
        SELECT 1
        FROM expected_tables
        WHERE NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = current_schema()
              AND relation.relname = expected_tables.name
              AND relation.relkind IN ('r', 'p')
        )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
          AND relation.relkind = 'S'
          AND relation.relname NOT IN (
              SELECT expected_sequences.name FROM expected_sequences
          )
    )
    OR EXISTS (
        SELECT 1
        FROM expected_sequences
        WHERE NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = current_schema()
              AND relation.relname = expected_sequences.name
              AND relation.relkind = 'S'
        )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
          AND relation.relkind NOT IN ('r', 'p', 'S', 'i', 'I')
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
          AND relation.relkind IN ('r', 'p')
          AND (relation.relrowsecurity OR relation.relforcerowsecurity)
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_rewrite AS rewrite_rule
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = rewrite_rule.ev_class
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_policy AS policy
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = policy.polrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS data_type
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        WHERE namespace.nspname = current_schema()
          AND data_type.oid NOT IN (SELECT oid FROM accepted_types)
    )
    OR EXISTS (
        SELECT 1
        FROM expected_enums
        WHERE NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_type AS data_type
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = data_type.typnamespace
            WHERE namespace.nspname = current_schema()
              AND data_type.typname = expected_enums.name
              AND data_type.typtype = 'e'
        )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_collation AS collation_record
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = collation_record.collnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_conversion AS conversion_record
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = conversion_record.connamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_operator AS operator_record
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = operator_record.oprnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_opclass AS operator_class
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = operator_class.opcnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_opfamily AS operator_family
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = operator_family.opfnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_ts_config AS text_search_config
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = text_search_config.cfgnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_ts_dict AS text_search_dictionary
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = text_search_dictionary.dictnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_ts_parser AS text_search_parser
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = text_search_parser.prsnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_ts_template AS text_search_template
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = text_search_template.tmplnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_statistic_ext AS statistics_record
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = statistics_record.stxnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_cast AS cast_record
        JOIN pg_catalog.pg_type AS source_type
          ON source_type.oid = cast_record.castsource
        JOIN pg_catalog.pg_namespace AS source_namespace
          ON source_namespace.oid = source_type.typnamespace
        JOIN pg_catalog.pg_type AS target_type
          ON target_type.oid = cast_record.casttarget
        JOIN pg_catalog.pg_namespace AS target_namespace
          ON target_namespace.oid = target_type.typnamespace
        WHERE source_namespace.nspname = current_schema()
           OR target_namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = routine.pronamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_type AS data_type
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = data_type.typnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_collation AS collation_record
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = collation_record.collnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_conversion AS conversion_record
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = conversion_record.connamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_operator AS operator_record
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = operator_record.oprnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_opclass AS operator_class
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = operator_class.opcnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_opfamily AS operator_family
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = operator_family.opfnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_ts_config AS text_search_config
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = text_search_config.cfgnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_ts_dict AS text_search_dictionary
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = text_search_dictionary.dictnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_ts_parser AS text_search_parser
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = text_search_parser.prsnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_ts_template AS text_search_template
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = text_search_template.tmplnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_statistic_ext AS statistics_record
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = statistics_record.stxnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
        ) AS off_path_object
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_trigger AS trigger_record
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = trigger_record.tgrelid
        JOIN pg_catalog.pg_namespace AS relation_namespace
          ON relation_namespace.oid = relation.relnamespace
        JOIN pg_catalog.pg_proc AS trigger_function
          ON trigger_function.oid = trigger_record.tgfoid
        JOIN pg_catalog.pg_namespace AS function_namespace
          ON function_namespace.oid = trigger_function.pronamespace
        WHERE relation_namespace.nspname = current_schema()
          AND NOT trigger_record.tgisinternal
          AND function_namespace.nspname <> current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_extension AS extension_record
        WHERE extension_record.extname <> 'plpgsql'
    )
    OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_event_trigger
    )
    OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_publication
    )
    OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_foreign_server
    )
    OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_user_mappings
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_largeobject_metadata
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_cast AS cast_record
        WHERE cast_record.oid >= 16384
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_transform AS transform_record
        WHERE transform_record.oid >= 16384
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_publication_rel AS publication_relation
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = publication_relation.prrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
    )
) AS has_unsupported_object
"#;

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct ExternalPgSemanticInventoryRow {
    object_kind: String,
    parent_name: String,
    object_name: String,
    definition: String,
}

const EXTERNAL_PG_SEMANTIC_INVENTORY_SQL: &str = r#"
SELECT
    'table'::text AS object_kind,
    ''::text AS parent_name,
    relation.relname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'kind', relation.relkind::text,
        'persistence', relation.relpersistence::text,
        'replica_identity', relation.relreplident::text,
        'access_method', COALESCE(access_method.amname, ''),
        'tablespace', COALESCE(tablespace.spcname, ''),
        'options', COALESCE(
            pg_catalog.to_jsonb(relation.reloptions),
            '[]'::pg_catalog.jsonb
        ),
        'is_partition', relation.relispartition,
        'parents', COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    '<application-schema>.'
                    || pg_catalog.quote_ident(parent_relation.relname)
                    ORDER BY inheritance.inhseqno
                )
                FROM pg_catalog.pg_inherits AS inheritance
                JOIN pg_catalog.pg_class AS parent_relation
                  ON parent_relation.oid = inheritance.inhparent
                JOIN pg_catalog.pg_namespace AS parent_namespace
                  ON parent_namespace.oid = parent_relation.relnamespace
                WHERE inheritance.inhrelid = relation.oid
            ),
            '[]'::pg_catalog.jsonb
        ),
        'partition_key', COALESCE(
            pg_catalog.pg_get_partkeydef(relation.oid),
            ''
        ),
        'partition_bound', COALESCE(
            pg_catalog.pg_get_expr(
                relation.relpartbound,
                relation.oid,
                true
            ),
            ''
        )
    )::text AS definition
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
LEFT JOIN pg_catalog.pg_am AS access_method
  ON access_method.oid = relation.relam
LEFT JOIN pg_catalog.pg_tablespace AS tablespace
  ON tablespace.oid = relation.reltablespace
WHERE namespace.nspname = current_schema()
  AND relation.relkind IN ('r', 'p')
UNION ALL
SELECT
    'column'::text AS object_kind,
    relation.relname::text AS parent_name,
    attribute.attname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'position', attribute.attnum,
        'type', pg_catalog.format_type(
            attribute.atttypid,
            attribute.atttypmod
        ),
        'not_null', attribute.attnotnull,
        'identity', attribute.attidentity::text,
        'generated', attribute.attgenerated::text,
        'dimensions', attribute.attndims,
        'inherited_count', attribute.attinhcount,
        'is_local', attribute.attislocal,
        'storage', attribute.attstorage::text,
        'compression', attribute.attcompression::text,
        'has_missing_value', attribute.atthasmissing,
        'missing_value', COALESCE(attribute.attmissingval::text, ''),
        'options', COALESCE(
            pg_catalog.to_jsonb(attribute.attoptions),
            '[]'::pg_catalog.jsonb
        ),
        'foreign_options', COALESCE(
            pg_catalog.to_jsonb(attribute.attfdwoptions),
            '[]'::pg_catalog.jsonb
        ),
        'collation', CASE
            WHEN attribute.attcollation = 0 THEN ''
            ELSE attribute.attcollation::pg_catalog.regcollation::text
        END,
        'default', COALESCE(
            pg_catalog.pg_get_expr(
                column_default.adbin,
                column_default.adrelid,
                true
            ),
            ''
        )
    )::text AS definition
FROM pg_catalog.pg_attribute AS attribute
JOIN pg_catalog.pg_class AS relation
  ON relation.oid = attribute.attrelid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
LEFT JOIN pg_catalog.pg_attrdef AS column_default
  ON column_default.adrelid = attribute.attrelid
 AND column_default.adnum = attribute.attnum
WHERE namespace.nspname = current_schema()
  AND relation.relkind IN ('r', 'p')
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped
UNION ALL
SELECT
    'sequence'::text AS object_kind,
    ''::text AS parent_name,
    relation.relname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'type', pg_catalog.format_type(sequence.seqtypid, NULL),
        'start', sequence.seqstart,
        'increment', sequence.seqincrement,
        'maximum', sequence.seqmax,
        'minimum', sequence.seqmin,
        'cache', sequence.seqcache,
        'cycle', sequence.seqcycle,
        'owned_by', COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'table',
                            '<application-schema>.'
                            || pg_catalog.quote_ident(owned_relation.relname),
                        'column', owned_attribute.attname,
                        'dependency_type', dependency.deptype::text
                    )
                    ORDER BY
                        owned_namespace.nspname,
                        owned_relation.relname,
                        owned_attribute.attnum,
                        dependency.deptype
                )
                FROM pg_catalog.pg_depend AS dependency
                JOIN pg_catalog.pg_class AS owned_relation
                  ON owned_relation.oid = dependency.refobjid
                JOIN pg_catalog.pg_namespace AS owned_namespace
                  ON owned_namespace.oid = owned_relation.relnamespace
                JOIN pg_catalog.pg_attribute AS owned_attribute
                  ON owned_attribute.attrelid = dependency.refobjid
                 AND owned_attribute.attnum = dependency.refobjsubid
                WHERE dependency.classid =
                      'pg_catalog.pg_class'::pg_catalog.regclass
                  AND dependency.objid = relation.oid
                  AND dependency.objsubid = 0
                  AND dependency.refclassid =
                      'pg_catalog.pg_class'::pg_catalog.regclass
                  AND dependency.deptype IN ('a', 'i')
            ),
            '[]'::pg_catalog.jsonb
        )
    )::text AS definition
FROM pg_catalog.pg_sequence AS sequence
JOIN pg_catalog.pg_class AS relation
  ON relation.oid = sequence.seqrelid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = current_schema()
UNION ALL
SELECT
    'enum-label'::text AS object_kind,
    data_type.typname::text AS parent_name,
    enum_record.enumlabel::text AS object_name,
    pg_catalog.jsonb_build_object(
        'sort_order', enum_record.enumsortorder::text
    )::text AS definition
FROM pg_catalog.pg_enum AS enum_record
JOIN pg_catalog.pg_type AS data_type
  ON data_type.oid = enum_record.enumtypid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = data_type.typnamespace
WHERE namespace.nspname = current_schema()
UNION ALL
SELECT
    'routine'::text AS object_kind,
    ''::text AS parent_name,
    (
        routine.proname
        || '('
        || pg_catalog.pg_get_function_identity_arguments(routine.oid)
        || ')'
    )::text AS object_name,
    pg_catalog.jsonb_build_object(
        'kind', routine.prokind::text,
        'language', language.lanname,
        'arguments', pg_catalog.pg_get_function_arguments(routine.oid),
        'result', pg_catalog.pg_get_function_result(routine.oid),
        'returns_set', routine.proretset,
        'variadic_type', CASE
            WHEN routine.provariadic = 0 THEN ''
            ELSE pg_catalog.format_type(routine.provariadic, NULL)
        END,
        'transform_types', COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.format_type(
                        transform_type_oid,
                        NULL
                    )
                    ORDER BY transform_position
                )
                FROM pg_catalog.unnest(
                    routine.protrftypes::oid[]
                ) WITH ORDINALITY AS transform_type(
                    transform_type_oid,
                    transform_position
                )
            ),
            '[]'::pg_catalog.jsonb
        ),
        'volatility', routine.provolatile::text,
        'parallel', routine.proparallel::text,
        'strict', routine.proisstrict,
        'security_definer', routine.prosecdef,
        'leakproof', routine.proleakproof,
        'cost', routine.procost::text,
        'rows', routine.prorows::text,
        'support', CASE
            WHEN routine.prosupport = 0 THEN ''
            ELSE routine.prosupport::pg_catalog.regprocedure::text
        END,
        'configuration', COALESCE(
            pg_catalog.to_jsonb(routine.proconfig),
            '[]'::pg_catalog.jsonb
        ),
        'binary', COALESCE(routine.probin, ''),
        'source', routine.prosrc,
        'sql_body', COALESCE(
            pg_catalog.pg_get_expr(routine.prosqlbody, 0, true),
            ''
        )
    )::text AS definition
FROM pg_catalog.pg_proc AS routine
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = routine.pronamespace
JOIN pg_catalog.pg_language AS language
  ON language.oid = routine.prolang
WHERE namespace.nspname = current_schema()
UNION ALL
SELECT
    'trigger'::text AS object_kind,
    relation.relname::text AS parent_name,
    trigger_record.tgname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'function',
            '<application-schema>.'
            || pg_catalog.quote_ident(trigger_function.proname)
            || '('
            || pg_catalog.pg_get_function_identity_arguments(
                trigger_function.oid
            )
            || ')',
        'type', trigger_record.tgtype,
        'enabled', trigger_record.tgenabled::text,
        'deferrable', trigger_record.tgdeferrable,
        'initially_deferred', trigger_record.tginitdeferred,
        'columns', trigger_record.tgattr::text,
        'arguments_hex', pg_catalog.encode(trigger_record.tgargs, 'hex'),
        'when', COALESCE(
            pg_catalog.pg_get_expr(
                trigger_record.tgqual,
                trigger_record.tgrelid,
                true
            ),
            ''
        ),
        'constraint', COALESCE(trigger_constraint.conname, ''),
        'constraint_relation', COALESCE(
            constraint_relation.relname,
            ''
        ),
        'parent_trigger', COALESCE(parent_trigger.tgname, ''),
        'parent_relation', COALESCE(parent_relation.relname, ''),
        'old_transition_table', COALESCE(trigger_record.tgoldtable, ''),
        'new_transition_table', COALESCE(trigger_record.tgnewtable, '')
    )::text AS definition
FROM pg_catalog.pg_trigger AS trigger_record
JOIN pg_catalog.pg_class AS relation
  ON relation.oid = trigger_record.tgrelid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
JOIN pg_catalog.pg_proc AS trigger_function
  ON trigger_function.oid = trigger_record.tgfoid
JOIN pg_catalog.pg_namespace AS trigger_function_namespace
  ON trigger_function_namespace.oid = trigger_function.pronamespace
LEFT JOIN pg_catalog.pg_constraint AS trigger_constraint
  ON trigger_constraint.oid = trigger_record.tgconstraint
LEFT JOIN pg_catalog.pg_class AS constraint_relation
  ON constraint_relation.oid = trigger_record.tgconstrrelid
LEFT JOIN pg_catalog.pg_trigger AS parent_trigger
  ON parent_trigger.oid = trigger_record.tgparentid
LEFT JOIN pg_catalog.pg_class AS parent_relation
  ON parent_relation.oid = parent_trigger.tgrelid
WHERE namespace.nspname = current_schema()
  AND NOT trigger_record.tgisinternal
UNION ALL
SELECT
    'index'::text AS object_kind,
    parent.relname::text AS parent_name,
    index_relation.relname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'access_method', access_method.amname,
        'persistence', index_relation.relpersistence::text,
        'tablespace', COALESCE(tablespace.spcname, ''),
        'relation_options', COALESCE(
            pg_catalog.to_jsonb(index_relation.reloptions),
            '[]'::pg_catalog.jsonb
        ),
        'keys', (
            SELECT pg_catalog.jsonb_agg(
                pg_catalog.pg_get_indexdef(
                    index_relation.oid,
                    key_position,
                    true
                )
                ORDER BY key_position
            )
            FROM pg_catalog.generate_series(
                1,
                index_record.indnatts
            ) AS key_position
        ),
        'key_count', index_record.indnkeyatts,
        'collations', (
            SELECT pg_catalog.jsonb_agg(
                CASE
                    WHEN collation_oid = 0 THEN ''
                    ELSE pg_catalog.quote_ident(collation_namespace.nspname)
                         || '.'
                         || pg_catalog.quote_ident(collation_record.collname)
                END
                ORDER BY collation_position
            )
            FROM pg_catalog.unnest(
                index_record.indcollation::oid[]
            ) WITH ORDINALITY AS index_collation(
                collation_oid,
                collation_position
            )
            LEFT JOIN pg_catalog.pg_collation AS collation_record
              ON collation_record.oid = index_collation.collation_oid
            LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
              ON collation_namespace.oid = collation_record.collnamespace
        ),
        'operator_classes', (
            SELECT pg_catalog.jsonb_agg(
                pg_catalog.quote_ident(operator_namespace.nspname)
                || '.'
                || pg_catalog.quote_ident(operator_class.opcname)
                ORDER BY operator_position
            )
            FROM pg_catalog.unnest(
                index_record.indclass::oid[]
            ) WITH ORDINALITY AS index_operator_class(
                operator_class_oid,
                operator_position
            )
            JOIN pg_catalog.pg_opclass AS operator_class
              ON operator_class.oid =
                 index_operator_class.operator_class_oid
            JOIN pg_catalog.pg_namespace AS operator_namespace
              ON operator_namespace.oid = operator_class.opcnamespace
        ),
        'options', index_record.indoption::text,
        'predicate', COALESCE(
            pg_catalog.pg_get_expr(
                index_record.indpred,
                index_record.indrelid,
                true
            ),
            ''
        ),
        'unique', index_record.indisunique,
        'nulls_not_distinct', index_record.indnullsnotdistinct,
        'primary', index_record.indisprimary,
        'exclusion', index_record.indisexclusion,
        'immediate', index_record.indimmediate,
        'clustered', index_record.indisclustered,
        'valid', index_record.indisvalid,
        'check_xmin', index_record.indcheckxmin,
        'ready', index_record.indisready,
        'live', index_record.indislive,
        'replica_identity', index_record.indisreplident
    )::text AS definition
FROM pg_catalog.pg_index AS index_record
JOIN pg_catalog.pg_class AS index_relation
  ON index_relation.oid = index_record.indexrelid
JOIN pg_catalog.pg_class AS parent
  ON parent.oid = index_record.indrelid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = parent.relnamespace
JOIN pg_catalog.pg_am AS access_method
  ON access_method.oid = index_relation.relam
LEFT JOIN pg_catalog.pg_tablespace AS tablespace
  ON tablespace.oid = index_relation.reltablespace
WHERE namespace.nspname = current_schema()
UNION ALL
SELECT
    'constraint'::text AS object_kind,
    COALESCE(parent.relname::text, data_type.typname::text, '') AS parent_name,
    constraint_record.conname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'definition', pg_catalog.pg_get_constraintdef(
            constraint_record.oid,
            true
        ),
        'type', constraint_record.contype::text,
        'deferrable', constraint_record.condeferrable,
        'deferred', constraint_record.condeferred,
        'validated', constraint_record.convalidated,
        'noinherit', constraint_record.connoinherit,
        'is_local', constraint_record.conislocal,
        'inheritance_count', constraint_record.coninhcount,
        'backing_index', COALESCE(constraint_index.relname, ''),
        'parent_constraint', COALESCE(parent_constraint.conname, ''),
        'parent_constraint_table', COALESCE(
            parent_constraint_relation.relname,
            ''
        )
    )::text AS definition
FROM pg_catalog.pg_constraint AS constraint_record
LEFT JOIN pg_catalog.pg_class AS parent
  ON parent.oid = constraint_record.conrelid
LEFT JOIN pg_catalog.pg_type AS data_type
  ON data_type.oid = constraint_record.contypid
LEFT JOIN pg_catalog.pg_class AS constraint_index
  ON constraint_index.oid = constraint_record.conindid
LEFT JOIN pg_catalog.pg_constraint AS parent_constraint
  ON parent_constraint.oid = constraint_record.conparentid
LEFT JOIN pg_catalog.pg_class AS parent_constraint_relation
  ON parent_constraint_relation.oid = parent_constraint.conrelid
WHERE constraint_record.connamespace = (
    SELECT namespace.oid
    FROM pg_catalog.pg_namespace AS namespace
    WHERE namespace.nspname = current_schema()
)
ORDER BY object_kind, parent_name, object_name, definition
"#;

fn external_pg_semantic_inventory_digest(rows: &[ExternalPgSemanticInventoryRow]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"OLY:EXTERNAL-PG:SEMANTIC-INVENTORY:V1");
    for row in rows {
        for value in [
            row.object_kind.as_bytes(),
            row.parent_name.as_bytes(),
            row.object_name.as_bytes(),
            row.definition.as_bytes(),
        ] {
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
    }
    hasher.finalize().to_hex().to_string()
}

async fn probe_external_pg_closed_catalog(
    connection: &mut PgConnection,
) -> Result<
    (
        ExternalPgClosedCatalogProbe,
        Vec<ExternalPgSemanticInventoryRow>,
    ),
    sqlx::Error,
> {
    let expected_tables = EXTERNAL_PG_TABLE_GRANTS
        .iter()
        .map(|grant| grant.name.to_owned())
        .collect::<Vec<_>>();
    let expected_enums = EXTERNAL_PG_ENUM_TYPES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let expected_sequences = EXTERNAL_PG_SEQUENCE_GRANTS
        .iter()
        .map(|grant| grant.name.to_owned())
        .collect::<Vec<_>>();
    let unsupported =
        sqlx::query_as::<_, ExternalPgClosedCatalogProbe>(EXTERNAL_PG_CLOSED_CATALOG_PROBE_SQL)
            .bind(expected_tables)
            .bind(expected_enums)
            .bind(expected_sequences)
            .fetch_one(&mut *connection)
            .await?;
    let semantic_inventory =
        sqlx::query_as::<_, ExternalPgSemanticInventoryRow>(EXTERNAL_PG_SEMANTIC_INVENTORY_SQL)
            .fetch_all(&mut *connection)
            .await?;
    Ok((unsupported, semantic_inventory))
}

fn validate_external_pg_closed_catalog(
    unsupported: &ExternalPgClosedCatalogProbe,
    semantic_inventory: &[ExternalPgSemanticInventoryRow],
) -> Result<(), ExternalPgSessionPolicyError> {
    if unsupported.has_unsupported_object {
        return Err(session_policy_error(
            "the application schema contains an unsupported executable or semantic object class",
        ));
    }
    if external_pg_semantic_inventory_digest(semantic_inventory)
        != EXTERNAL_PG_SEMANTIC_INVENTORY_BLAKE3
    {
        return Err(session_policy_error(
            "the application semantic inventory differs from the reviewed release",
        ));
    }
    Ok(())
}

/// Apply the release-pinned ACL manifest without ever interpolating the live
/// role or schema name into a client-side SQL string. The bound values live
/// only in transaction-local custom settings; the fixed DO block quotes every
/// identifier with PostgreSQL's `format('%I', ...)`.
///
/// The block first proves the migrated object inventory is exactly the
/// reviewed v0.10.0 manifest and is owned by the migration role. It then
/// removes PUBLIC/runtime ambient grants, applies only the matrix above, and
/// removes PUBLIC/runtime privileges from objects the migrator creates in a
/// future migration. A new migration object therefore remains inaccessible
/// until the release manifest is deliberately updated.
const EXTERNAL_PG_APPLY_GRANTS_SQL: &str = r#"
DO $olympus$
DECLARE
    app_schema name := current_schema();
    runtime_role name := current_setting('olympus.runtime_role', false)::name;
    table_spec jsonb := current_setting('olympus.table_grants', false)::jsonb;
    column_spec jsonb := current_setting('olympus.column_grants', false)::jsonb;
    sequence_spec jsonb := current_setting('olympus.sequence_grants', false)::jsonb;
    entry jsonb;
    object_record record;
    privilege_list text;
BEGIN
    IF app_schema IS NULL
       OR runtime_role::text = current_user::text
       OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_roles
           WHERE rolname = runtime_role::text
       )
       OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_namespace
           WHERE nspname = app_schema::text
             AND pg_catalog.has_schema_privilege(current_user, oid, 'CREATE')
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL privilege policy precondition failed';
    END IF;

    IF jsonb_typeof(table_spec) <> 'array'
       OR jsonb_typeof(column_spec) <> 'array'
       OR jsonb_typeof(sequence_spec) <> 'array'
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           WHERE jsonb_typeof(item.value) <> 'object'
              OR jsonb_typeof(item.value -> 'table_name') <> 'string'
              OR jsonb_typeof(item.value -> 'privilege') <> 'string'
              OR jsonb_typeof(item.value -> 'columns') <> 'array'
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
           WHERE jsonb_typeof(item.value) <> 'object'
              OR jsonb_typeof(item.value -> 'name') <> 'string'
              OR jsonb_typeof(item.value -> 'privileges') <> 'array'
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
           WHERE jsonb_typeof(item.value) <> 'object'
              OR jsonb_typeof(item.value -> 'name') <> 'string'
              OR jsonb_typeof(item.value -> 'privileges') <> 'array'
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL privilege manifest is invalid';
    END IF;

    IF EXISTS (
           SELECT item.value ->> 'name'
           FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
           GROUP BY item.value ->> 'name'
           HAVING count(*) <> 1
       )
       OR EXISTS (
           SELECT
               item.value ->> 'table_name',
               item.value ->> 'privilege'
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           GROUP BY
               item.value ->> 'table_name',
               item.value ->> 'privilege'
           HAVING count(*) <> 1
       )
       OR EXISTS (
           SELECT item.value ->> 'name'
           FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
           GROUP BY item.value ->> 'name'
           HAVING count(*) <> 1
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           WHERE item.value ->> 'privilege' NOT IN ('SELECT', 'UPDATE')
              OR pg_catalog.jsonb_array_length(item.value -> 'columns') = 0
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
           CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(
               item.value -> 'privileges'
           ) AS privilege(value)
           WHERE privilege.value NOT IN (
               'SELECT', 'INSERT', 'UPDATE', 'DELETE'
           )
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
           CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(
               item.value -> 'privileges'
           ) AS privilege(value)
           WHERE privilege.value NOT IN ('USAGE', 'SELECT', 'UPDATE')
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL privilege manifest is invalid';
    END IF;

    IF EXISTS (
        (
            SELECT relation.relname
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = app_schema::text
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND relation.relname <> '_sqlx_migrations'
            EXCEPT
            SELECT item.value ->> 'name'
            FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
        )
        UNION ALL
        (
            SELECT item.value ->> 'name'
            FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
            EXCEPT
            SELECT relation.relname
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = app_schema::text
              AND relation.relkind IN ('r', 'p')
              AND relation.relname <> '_sqlx_migrations'
        )
    )
       OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = relation.relnamespace
           WHERE namespace.nspname = app_schema::text
             AND relation.relname = '_sqlx_migrations'
             AND relation.relkind IN ('r', 'p')
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL table inventory differs from the release manifest';
    END IF;

    -- Relation names are only schema-unique. A same-named legacy table in an
    -- off-path schema must not make the active-schema manifest look invalid.
    IF EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           WHERE NOT EXISTS (
               SELECT 1
               FROM pg_catalog.pg_class AS relation
               JOIN pg_catalog.pg_namespace AS namespace
                 ON namespace.oid = relation.relnamespace
               WHERE namespace.nspname = app_schema::text
                 AND relation.relname = item.value ->> 'table_name'
                 AND relation.relkind IN ('r', 'p')
           )
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(
               item.value -> 'columns'
           ) AS column_name(value)
           WHERE jsonb_typeof(column_name.value) <> 'string'
              OR NOT EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_class AS relation
                  JOIN pg_catalog.pg_namespace AS namespace
                    ON namespace.oid = relation.relnamespace
                  JOIN pg_catalog.pg_attribute AS attribute
                    ON attribute.attrelid = relation.oid
                   AND attribute.attname = column_name.value #>> '{}'
                   AND attribute.attnum > 0
                   AND NOT attribute.attisdropped
                  WHERE namespace.nspname = app_schema::text
                    AND relation.relname = item.value ->> 'table_name'
                    AND relation.relkind IN ('r', 'p')
              )
       )
       OR EXISTS (
           SELECT
               item.value ->> 'table_name',
               item.value ->> 'privilege',
               column_name.value
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(
               item.value -> 'columns'
           ) AS column_name(value)
           GROUP BY
               item.value ->> 'table_name',
               item.value ->> 'privilege',
               column_name.value
           HAVING count(*) <> 1
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL column privilege manifest is invalid';
    END IF;

    IF EXISTS (
        (
            SELECT relation.relname
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = app_schema::text
              AND relation.relkind = 'S'
            EXCEPT
            SELECT item.value ->> 'name'
            FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
        )
        UNION ALL
        (
            SELECT item.value ->> 'name'
            FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
            EXCEPT
            SELECT relation.relname
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = app_schema::text
              AND relation.relkind = 'S'
        )
    )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL sequence inventory differs from the release manifest';
    END IF;

    IF EXISTS (
           SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = routine.pronamespace
           WHERE namespace.nspname = app_schema::text
             AND routine.proowner <> (
                 SELECT oid
                 FROM pg_catalog.pg_roles
                 WHERE rolname = current_user
             )
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = relation.relnamespace
           WHERE namespace.nspname = app_schema::text
             AND relation.relowner <> (
                 SELECT oid
                 FROM pg_catalog.pg_roles
                 WHERE rolname = current_user
             )
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.pg_type AS data_type
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = data_type.typnamespace
           WHERE namespace.nspname = app_schema::text
             AND data_type.typowner <> (
                 SELECT oid
                 FROM pg_catalog.pg_roles
                 WHERE rolname = current_user
             )
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL object ownership or routine inventory differs from policy';
    END IF;

    FOR object_record IN
        SELECT
            relation.relname,
            string_agg(
                pg_catalog.format('%I', attribute.attname),
                ', '
                ORDER BY attribute.attnum
            ) AS column_list
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        LEFT JOIN pg_catalog.pg_attribute AS attribute
          ON attribute.attrelid = relation.oid
         AND attribute.attnum > 0
         AND NOT attribute.attisdropped
        WHERE namespace.nspname = app_schema::text
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
        GROUP BY relation.relname
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM PUBLIC',
            app_schema,
            object_record.relname
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I',
            app_schema,
            object_record.relname,
            runtime_role
        );
        IF object_record.column_list IS NOT NULL THEN
            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES (%s) ON TABLE %I.%I FROM PUBLIC',
                object_record.column_list,
                app_schema,
                object_record.relname
            );
            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES (%s) ON TABLE %I.%I FROM %I',
                object_record.column_list,
                app_schema,
                object_record.relname,
                runtime_role
            );
        END IF;
    END LOOP;

    FOR object_record IN
        SELECT relation.relname
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = app_schema::text
          AND relation.relkind = 'S'
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM PUBLIC',
            app_schema,
            object_record.relname
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM %I',
            app_schema,
            object_record.relname,
            runtime_role
        );
    END LOOP;

    FOR object_record IN
        SELECT data_type.typname
        FROM pg_catalog.pg_type AS data_type
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        WHERE namespace.nspname = app_schema::text
          AND data_type.typelem = 0
          AND data_type.typtype IN ('d', 'e', 'm', 'r')
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TYPE %I.%I FROM PUBLIC',
            app_schema,
            object_record.typname
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TYPE %I.%I FROM %I',
            app_schema,
            object_record.typname,
            runtime_role
        );
    END LOOP;

    FOR entry IN
        SELECT item.value
        FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
    LOOP
        SELECT string_agg(privilege.value, ', ' ORDER BY privilege.ordinality)
        INTO privilege_list
        FROM pg_catalog.jsonb_array_elements_text(
            entry -> 'privileges'
        ) WITH ORDINALITY AS privilege(value, ordinality);

        IF privilege_list IS NOT NULL THEN
            EXECUTE pg_catalog.format(
                'GRANT %s ON TABLE %I.%I TO %I',
                privilege_list,
                app_schema,
                entry ->> 'name',
                runtime_role
            );
        END IF;
    END LOOP;

    FOR entry IN
        SELECT item.value
        FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
    LOOP
        SELECT string_agg(
            pg_catalog.format('%I', column_name.value),
            ', '
            ORDER BY column_name.ordinality
        )
        INTO privilege_list
        FROM pg_catalog.jsonb_array_elements_text(
            entry -> 'columns'
        ) WITH ORDINALITY AS column_name(value, ordinality);

        EXECUTE pg_catalog.format(
            'GRANT %s (%s) ON TABLE %I.%I TO %I',
            entry ->> 'privilege',
            privilege_list,
            app_schema,
            entry ->> 'table_name',
            runtime_role
        );
    END LOOP;

    FOR entry IN
        SELECT item.value
        FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
    LOOP
        SELECT string_agg(privilege.value, ', ' ORDER BY privilege.ordinality)
        INTO privilege_list
        FROM pg_catalog.jsonb_array_elements_text(
            entry -> 'privileges'
        ) WITH ORDINALITY AS privilege(value, ordinality);

        IF privilege_list IS NOT NULL THEN
            EXECUTE pg_catalog.format(
                'GRANT %s ON SEQUENCE %I.%I TO %I',
                privilege_list,
                app_schema,
                entry ->> 'name',
                runtime_role
            );
        END IF;
    END LOOP;

    -- Global default ACLs are the base ACL for future objects. PostgreSQL's
    -- built-in defaults grant PUBLIC EXECUTE on functions and PUBLIC USAGE on
    -- types, so those revocations must not be scoped with IN SCHEMA.
    FOREACH privilege_list IN ARRAY ARRAY['TABLES', 'SEQUENCES', 'FUNCTIONS', 'TYPES']
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE ALL PRIVILEGES ON %s FROM PUBLIC',
            current_user,
            privilege_list
        );
        EXECUTE pg_catalog.format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE ALL PRIVILEGES ON %s FROM %I',
            current_user,
            privilege_list,
            runtime_role
        );
    END LOOP;

    -- Per-schema default ACLs are additive to the global base. Clear stale
    -- additions for every non-system schema, not only the active path.
    FOR object_record IN
        SELECT namespace.nspname
        FROM pg_catalog.pg_namespace AS namespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
    LOOP
        FOREACH privilege_list IN ARRAY ARRAY['TABLES', 'SEQUENCES', 'FUNCTIONS', 'TYPES']
        LOOP
            EXECUTE pg_catalog.format(
                'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL PRIVILEGES ON %s FROM PUBLIC',
                current_user,
                object_record.nspname,
                privilege_list
            );
            EXECUTE pg_catalog.format(
                'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL PRIVILEGES ON %s FROM %I',
                current_user,
                object_record.nspname,
                privilege_list,
                runtime_role
            );
        END LOOP;
    END LOOP;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL privilege provisioning failed';
END
$olympus$
"#;

async fn provision_external_pg_runtime_privileges(
    connection: &mut PgConnection,
    runtime_role: &str,
) -> Result<(), sqlx::Error> {
    let table_spec = external_pg_grant_spec(EXTERNAL_PG_TABLE_GRANTS);
    let column_spec = external_pg_column_grant_spec(EXTERNAL_PG_COLUMN_GRANTS);
    let sequence_spec = external_pg_grant_spec(EXTERNAL_PG_SEQUENCE_GRANTS);
    let mut transaction = connection.begin().await?;
    // No-op REVOKEs can produce object/role-bearing PostgreSQL warnings.
    // Keep those server notices off the client channel; Olympus reports only
    // the static failure text at the call site.
    sqlx::query("SELECT set_config('client_min_messages', 'error', true)")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.runtime_role', $1, true)")
        .bind(runtime_role)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.table_grants', $1, true)")
        .bind(table_spec)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.column_grants', $1, true)")
        .bind(column_spec)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.sequence_grants', $1, true)")
        .bind(sequence_spec)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(EXTERNAL_PG_APPLY_GRANTS_SQL)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct ExternalPgTablePrivilegeProbe {
    object_name: String,
    can_select: bool,
    can_insert: bool,
    can_update: bool,
    can_delete: bool,
    can_truncate: bool,
    can_references: bool,
    can_trigger: bool,
    runtime_has_table_grant_option: bool,
    runtime_has_unknown_table_privilege: bool,
    public_has_any_privilege: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct ExternalPgColumnPrivilegeProbe {
    object_name: String,
    column_name: String,
    privilege_type: String,
    is_grantable: bool,
    grantee_is_public: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct ExternalPgSequencePrivilegeProbe {
    object_name: String,
    can_usage: bool,
    can_select: bool,
    can_update: bool,
    runtime_has_grant_option: bool,
    public_has_any_privilege: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct ExternalPgOtherPrivilegeProbe {
    schema_public_has_any_privilege: bool,
    runtime_has_any_routine_execute: bool,
    public_has_any_routine_privilege: bool,
    runtime_has_any_type_usage: bool,
    public_has_any_type_privilege: bool,
    migration_defaults_have_ambient_privileges: bool,
    migration_defaults_have_grant_options: bool,
    runtime_or_public_has_off_path_object_privileges: bool,
}

const EXTERNAL_PG_TABLE_PRIVILEGE_PROBE_SQL: &str = r#"
SELECT
    relation.relname::text AS object_name,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'SELECT'
    ) AS can_select,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'INSERT'
    ) AS can_insert,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'UPDATE'
    ) AS can_update,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'DELETE'
    ) AS can_delete,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'TRUNCATE'
    ) AS can_truncate,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'REFERENCES'
    ) AS can_references,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'TRIGGER'
    ) AS can_trigger,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(relation.relacl) AS object_acl
        JOIN pg_catalog.pg_roles AS runtime_role
          ON runtime_role.oid = object_acl.grantee
        WHERE runtime_role.rolname = session_user
          AND object_acl.is_grantable
    ) AS runtime_has_table_grant_option,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(relation.relacl) AS object_acl
        JOIN pg_catalog.pg_roles AS runtime_role
          ON runtime_role.oid = object_acl.grantee
        WHERE runtime_role.rolname = session_user
          AND object_acl.privilege_type NOT IN (
              'SELECT',
              'INSERT',
              'UPDATE',
              'DELETE',
              'TRUNCATE',
              'REFERENCES',
              'TRIGGER'
          )
    ) AS runtime_has_unknown_table_privilege,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
            COALESCE(
                relation.relacl,
                pg_catalog.acldefault('r', relation.relowner)
            )
        ) AS object_acl
        WHERE object_acl.grantee = 0
    ) AS public_has_any_privilege
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = current_schema()
  AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY relation.relname
"#;

const EXTERNAL_PG_COLUMN_PRIVILEGE_PROBE_SQL: &str = r#"
SELECT
    relation.relname::text AS object_name,
    attribute.attname::text AS column_name,
    column_acl.privilege_type::text AS privilege_type,
    column_acl.is_grantable,
    column_acl.grantee = 0 AS grantee_is_public
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
JOIN pg_catalog.pg_attribute AS attribute
  ON attribute.attrelid = relation.oid
 AND attribute.attnum > 0
 AND NOT attribute.attisdropped
CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS column_acl
LEFT JOIN pg_catalog.pg_roles AS grantee
  ON grantee.oid = column_acl.grantee
WHERE namespace.nspname = current_schema()
  AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND (column_acl.grantee = 0 OR grantee.rolname = session_user)
ORDER BY relation.relname, attribute.attnum, column_acl.privilege_type
"#;

const EXTERNAL_PG_SEQUENCE_PRIVILEGE_PROBE_SQL: &str = r#"
SELECT
    relation.relname::text AS object_name,
    pg_catalog.has_sequence_privilege(
        session_user,
        relation.oid,
        'USAGE'
    ) AS can_usage,
    pg_catalog.has_sequence_privilege(
        session_user,
        relation.oid,
        'SELECT'
    ) AS can_select,
    pg_catalog.has_sequence_privilege(
        session_user,
        relation.oid,
        'UPDATE'
    ) AS can_update,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(relation.relacl) AS object_acl
        JOIN pg_catalog.pg_roles AS runtime_role
          ON runtime_role.oid = object_acl.grantee
        WHERE runtime_role.rolname = session_user
          AND object_acl.is_grantable
    ) AS runtime_has_grant_option,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
            COALESCE(
                relation.relacl,
                pg_catalog.acldefault('S', relation.relowner)
            )
        ) AS object_acl
        WHERE object_acl.grantee = 0
    ) AS public_has_any_privilege
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = current_schema()
  AND relation.relkind = 'S'
ORDER BY relation.relname
"#;

const EXTERNAL_PG_OTHER_PRIVILEGE_PROBE_SQL: &str = r#"
WITH current_namespace AS (
    SELECT namespace.oid, namespace.nspacl, namespace.nspowner
    FROM pg_catalog.pg_namespace AS namespace
    WHERE namespace.nspname = current_schema()
),
migration_role AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = $1
),
runtime_role AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = session_user
),
default_object_types(object_type) AS (
    VALUES
        ('r'::"char"),
        ('S'::"char"),
        ('f'::"char"),
        ('T'::"char")
),
effective_default_privileges AS (
    -- The global row, when present, replaces acldefault(); per-schema rows
    -- are additive and therefore must be checked separately.
    SELECT default_object_types.object_type, default_privilege.*
    FROM migration_role
    CROSS JOIN default_object_types
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(
            (
                SELECT default_acl.defaclacl
                FROM pg_catalog.pg_default_acl AS default_acl
                WHERE default_acl.defaclrole = migration_role.oid
                  AND default_acl.defaclnamespace = 0
                  AND default_acl.defaclobjtype = default_object_types.object_type
            ),
            pg_catalog.acldefault(
                default_object_types.object_type,
                migration_role.oid
            )
        )
    ) AS default_privilege
    UNION ALL
    SELECT default_acl.defaclobjtype, default_privilege.*
    FROM migration_role
    JOIN pg_catalog.pg_default_acl AS default_acl
      ON default_acl.defaclrole = migration_role.oid
     AND default_acl.defaclnamespace <> 0
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        default_acl.defaclacl
    ) AS default_privilege
)
SELECT
    EXISTS (
        SELECT 1
        FROM current_namespace AS namespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                namespace.nspacl,
                pg_catalog.acldefault('n', namespace.nspowner)
            )
        ) AS schema_acl
        WHERE schema_acl.grantee = 0
    ) AS schema_public_has_any_privilege,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS routine
        JOIN current_namespace AS namespace
          ON namespace.oid = routine.pronamespace
        WHERE pg_catalog.has_function_privilege(
            session_user,
            routine.oid,
            'EXECUTE'
        )
    ) AS runtime_has_any_routine_execute,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS routine
        JOIN current_namespace AS namespace
          ON namespace.oid = routine.pronamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                routine.proacl,
                pg_catalog.acldefault('f', routine.proowner)
            )
        ) AS routine_acl
        WHERE routine_acl.grantee = 0
    ) AS public_has_any_routine_privilege,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS data_type
        JOIN current_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        WHERE data_type.typelem = 0
          AND (
              data_type.typrelid = 0
              OR EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_class AS type_relation
                  WHERE type_relation.oid = data_type.typrelid
                    AND type_relation.relkind = 'c'
              )
          )
          AND pg_catalog.has_type_privilege(
              session_user,
              data_type.oid,
              'USAGE'
          )
    ) AS runtime_has_any_type_usage,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS data_type
        JOIN current_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                data_type.typacl,
                pg_catalog.acldefault('T', data_type.typowner)
            )
        ) AS type_acl
        WHERE data_type.typelem = 0
          AND (
              data_type.typrelid = 0
              OR EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_class AS type_relation
                  WHERE type_relation.oid = data_type.typrelid
                    AND type_relation.relkind = 'c'
              )
          )
          AND type_acl.grantee = 0
    ) AS public_has_any_type_privilege,
    EXISTS (
        SELECT 1
        FROM effective_default_privileges AS default_privilege
        CROSS JOIN runtime_role
        WHERE default_privilege.grantee IN (0, runtime_role.oid)
    ) AS migration_defaults_have_ambient_privileges,
    EXISTS (
        SELECT 1
        FROM effective_default_privileges AS default_privilege
        CROSS JOIN runtime_role
        WHERE default_privilege.grantee IN (0, runtime_role.oid)
          AND default_privilege.is_grantable
    ) AS migration_defaults_have_grant_options,
    (
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            CROSS JOIN runtime_role
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    relation.relacl,
                    pg_catalog.acldefault(
                        (
                            CASE
                                WHEN relation.relkind = 'S' THEN 'S'
                                ELSE 'r'
                            END
                        )::"char",
                        relation.relowner
                    )
                )
            ) AS object_acl
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
              AND object_acl.grantee IN (0, runtime_role.oid)
        )
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = routine.pronamespace
            CROSS JOIN runtime_role
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    routine.proacl,
                    pg_catalog.acldefault('f', routine.proowner)
                )
            ) AS object_acl
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
              AND object_acl.grantee IN (0, runtime_role.oid)
        )
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_type AS data_type
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = data_type.typnamespace
            CROSS JOIN runtime_role
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    data_type.typacl,
                    pg_catalog.acldefault('T', data_type.typowner)
                )
            ) AS object_acl
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
              AND data_type.typelem = 0
              AND (
                  data_type.typrelid = 0
                  OR EXISTS (
                      SELECT 1
                      FROM pg_catalog.pg_class AS type_relation
                      WHERE type_relation.oid = data_type.typrelid
                        AND type_relation.relkind = 'c'
                  )
              )
              AND object_acl.grantee IN (0, runtime_role.oid)
        )
    ) AS runtime_or_public_has_off_path_object_privileges
"#;

async fn probe_external_pg_runtime_privileges(
    connection: &mut PgConnection,
    migration_role: &str,
) -> Result<
    (
        Vec<ExternalPgTablePrivilegeProbe>,
        Vec<ExternalPgColumnPrivilegeProbe>,
        Vec<ExternalPgSequencePrivilegeProbe>,
        ExternalPgOtherPrivilegeProbe,
    ),
    sqlx::Error,
> {
    let tables =
        sqlx::query_as::<_, ExternalPgTablePrivilegeProbe>(EXTERNAL_PG_TABLE_PRIVILEGE_PROBE_SQL)
            .fetch_all(&mut *connection)
            .await?;
    let columns =
        sqlx::query_as::<_, ExternalPgColumnPrivilegeProbe>(EXTERNAL_PG_COLUMN_PRIVILEGE_PROBE_SQL)
            .fetch_all(&mut *connection)
            .await?;
    let sequences = sqlx::query_as::<_, ExternalPgSequencePrivilegeProbe>(
        EXTERNAL_PG_SEQUENCE_PRIVILEGE_PROBE_SQL,
    )
    .fetch_all(&mut *connection)
    .await?;
    let other =
        sqlx::query_as::<_, ExternalPgOtherPrivilegeProbe>(EXTERNAL_PG_OTHER_PRIVILEGE_PROBE_SQL)
            .bind(migration_role)
            .fetch_one(&mut *connection)
            .await?;
    Ok((tables, columns, sequences, other))
}

fn expected_grant_has(grant: &ExternalPgTableGrant, privilege: &str) -> bool {
    grant.privileges.contains(&privilege)
}

fn validate_external_pg_runtime_privileges(
    tables: &[ExternalPgTablePrivilegeProbe],
    columns: &[ExternalPgColumnPrivilegeProbe],
    sequences: &[ExternalPgSequencePrivilegeProbe],
    other: &ExternalPgOtherPrivilegeProbe,
) -> Result<(), ExternalPgSessionPolicyError> {
    if tables.len() != EXTERNAL_PG_TABLE_GRANTS.len() + 1 {
        return Err(session_policy_error(
            "the runtime table inventory differs from the release privilege manifest",
        ));
    }
    for expected in EXTERNAL_PG_TABLE_GRANTS {
        let mut matching = tables
            .iter()
            .filter(|probe| probe.object_name == expected.name);
        let Some(actual) = matching.next() else {
            return Err(session_policy_error(
                "the runtime table inventory differs from the release privilege manifest",
            ));
        };
        if matching.next().is_some()
            || actual.can_select != expected_grant_has(expected, "SELECT")
            || actual.can_insert != expected_grant_has(expected, "INSERT")
            || actual.can_update != expected_grant_has(expected, "UPDATE")
            || actual.can_delete != expected_grant_has(expected, "DELETE")
            || actual.can_truncate
            || actual.can_references
            || actual.can_trigger
            || actual.runtime_has_table_grant_option
            || actual.runtime_has_unknown_table_privilege
            || actual.public_has_any_privilege
        {
            return Err(session_policy_error(
                "the runtime table privileges differ from the release privilege manifest",
            ));
        }
    }
    let mut sqlx_metadata = tables
        .iter()
        .filter(|probe| probe.object_name == "_sqlx_migrations");
    let Some(sqlx_metadata) = sqlx_metadata.next() else {
        return Err(session_policy_error(
            "the runtime table inventory differs from the release privilege manifest",
        ));
    };
    if sqlx_metadata.can_select
        || sqlx_metadata.can_insert
        || sqlx_metadata.can_update
        || sqlx_metadata.can_delete
        || sqlx_metadata.can_truncate
        || sqlx_metadata.can_references
        || sqlx_metadata.can_trigger
        || sqlx_metadata.runtime_has_table_grant_option
        || sqlx_metadata.runtime_has_unknown_table_privilege
        || sqlx_metadata.public_has_any_privilege
        || tables.iter().any(|probe| {
            probe.object_name != "_sqlx_migrations"
                && !EXTERNAL_PG_TABLE_GRANTS
                    .iter()
                    .any(|expected| expected.name == probe.object_name)
        })
    {
        return Err(session_policy_error(
            "the runtime table privileges differ from the release privilege manifest",
        ));
    }

    let expected_column_count: usize = EXTERNAL_PG_COLUMN_GRANTS
        .iter()
        .map(|grant| grant.columns.len())
        .sum();
    if columns.len() != expected_column_count
        || columns.iter().any(|actual| {
            actual.grantee_is_public
                || actual.is_grantable
                || !EXTERNAL_PG_COLUMN_GRANTS.iter().any(|expected| {
                    expected.table_name == actual.object_name
                        && expected.privilege == actual.privilege_type
                        && expected.columns.contains(&actual.column_name.as_str())
                })
        })
        || EXTERNAL_PG_COLUMN_GRANTS.iter().any(|expected| {
            expected.columns.iter().any(|expected_column| {
                columns
                    .iter()
                    .filter(|actual| {
                        !actual.grantee_is_public
                            && actual.object_name == expected.table_name
                            && actual.privilege_type == expected.privilege
                            && actual.column_name == *expected_column
                    })
                    .count()
                    != 1
            })
        })
    {
        return Err(session_policy_error(
            "the runtime column privileges differ from the release privilege manifest",
        ));
    }

    if sequences.len() != EXTERNAL_PG_SEQUENCE_GRANTS.len() {
        return Err(session_policy_error(
            "the runtime sequence inventory differs from the release privilege manifest",
        ));
    }
    for expected in EXTERNAL_PG_SEQUENCE_GRANTS {
        let mut matching = sequences
            .iter()
            .filter(|probe| probe.object_name == expected.name);
        let Some(actual) = matching.next() else {
            return Err(session_policy_error(
                "the runtime sequence inventory differs from the release privilege manifest",
            ));
        };
        if matching.next().is_some()
            || actual.can_usage != expected_grant_has(expected, "USAGE")
            || actual.can_select != expected_grant_has(expected, "SELECT")
            || actual.can_update != expected_grant_has(expected, "UPDATE")
            || actual.runtime_has_grant_option
            || actual.public_has_any_privilege
        {
            return Err(session_policy_error(
                "the runtime sequence privileges differ from the release privilege manifest",
            ));
        }
    }
    if sequences.iter().any(|probe| {
        !EXTERNAL_PG_SEQUENCE_GRANTS
            .iter()
            .any(|expected| expected.name == probe.object_name)
    }) {
        return Err(session_policy_error(
            "the runtime sequence inventory differs from the release privilege manifest",
        ));
    }

    if other.schema_public_has_any_privilege
        || other.runtime_has_any_routine_execute
        || other.public_has_any_routine_privilege
        || other.runtime_has_any_type_usage
        || other.public_has_any_type_privilege
        || other.migration_defaults_have_ambient_privileges
        || other.migration_defaults_have_grant_options
        || other.runtime_or_public_has_off_path_object_privileges
    {
        return Err(session_policy_error(
            "the runtime schema, routine, type, or default privileges differ from policy",
        ));
    }
    Ok(())
}

fn session_policy_sqlx_error(error: ExternalPgSessionPolicyError) -> sqlx::Error {
    sqlx::Error::Configuration(Box::new(error))
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|value| {
        let value = value.trim();
        value == "1"
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("yes")
            || value.eq_ignore_ascii_case("on")
    })
}

async fn attest_external_pg_trusted_boundary(
    connection: &mut PgConnection,
    migration_role: &str,
    runtime_role: &str,
) -> Result<(), sqlx::Error> {
    let trusted_boundary =
        probe_external_pg_trusted_boundary(connection, migration_role, runtime_role).await?;
    validate_external_pg_trusted_boundary(&trusted_boundary).map_err(session_policy_sqlx_error)
}

async fn attest_external_pg_control_plane(
    connection: &mut PgConnection,
    migration_role: &str,
    runtime_role: &str,
) -> Result<(), sqlx::Error> {
    attest_external_pg_trusted_boundary(connection, migration_role, runtime_role).await?;
    let (closed_catalog, semantic_inventory) = probe_external_pg_closed_catalog(connection).await?;
    validate_external_pg_closed_catalog(&closed_catalog, &semantic_inventory)
        .map_err(session_policy_sqlx_error)
}

async fn external_pg_runtime_is_quiescent(
    connection: &mut PgConnection,
    runtime_role: &str,
) -> Result<(), sqlx::Error> {
    let maintenance = probe_external_pg_maintenance(connection, runtime_role).await?;
    validate_external_pg_quiescence(&maintenance).map_err(session_policy_sqlx_error)
}

async fn enter_external_pg_maintenance(
    connection: &mut PgConnection,
    runtime_role: &str,
) -> Result<(), sqlx::Error> {
    set_external_pg_runtime_connect(connection, runtime_role, false).await?;
    external_pg_runtime_is_quiescent(connection, runtime_role).await
}

async fn reassert_external_pg_fail_closed(
    connection: &mut PgConnection,
    runtime_role: &str,
) -> Result<(), sqlx::Error> {
    harden_external_pg_before_migrations(connection, runtime_role).await?;
    external_pg_runtime_is_quiescent(connection, runtime_role).await
}

async fn prepare_external_pg_release_policy(
    connection: &mut PgConnection,
    migration_role: &str,
    runtime_role: &str,
) -> Result<(), sqlx::Error> {
    harden_external_pg_before_migrations(connection, runtime_role).await?;
    attest_external_pg_control_plane(connection, migration_role, runtime_role).await?;
    provision_external_pg_runtime_privileges(connection, runtime_role).await
}

/// A runtime-pool failure after the exclusive-to-shared handoff may be cleaned
/// up only after this same session has reacquired the exact exclusive lock.
/// The migration session keeps its shared lock throughout the handoff, so
/// another writer cannot slip into an unlocked interval. If another shared
/// holder exists, this fails without changing CONNECT or object privileges and
/// leaves recovery to the operator.
async fn recover_external_pg_handoff_failure(
    connection: &mut PgConnection,
    runtime_role: &str,
    shared_development_identity: bool,
) -> bool {
    if shared_development_identity {
        return true;
    }
    if !acquire_external_pg_maintenance_lock(connection).await {
        return false;
    }
    set_external_pg_runtime_connect(connection, runtime_role, false)
        .await
        .is_ok()
        && reassert_external_pg_fail_closed(connection, runtime_role)
            .await
            .is_ok()
}

#[derive(Clone)]
struct ExternalPgRuntimeAttestationContext {
    migration_attestation: ExternalPgSessionAttestation,
    migration_role: String,
    runtime_expected: ExternalPgExpectedSession,
    runtime_kind: ExternalPgSessionKind,
    shared_development_identity: bool,
}

impl ExternalPgRuntimeAttestationContext {
    async fn attest(&self, connection: &mut PgConnection) -> Result<(), sqlx::Error> {
        let runtime_lock_held =
            external_pg_runtime_lock_is_held(connection)
                .await
                .map_err(|_| {
                    session_policy_sqlx_error(session_policy_error(
                        "the live runtime-lock attestation query failed",
                    ))
                })?;
        if !runtime_lock_held {
            return Err(session_policy_sqlx_error(session_policy_error(
                "the live runtime session does not hold the shared database lifecycle lock",
            )));
        }

        let runtime_probe = probe_external_pg_connection(connection)
            .await
            .map_err(|_| {
                session_policy_sqlx_error(session_policy_error(
                    "the live session attestation query failed",
                ))
            })?;
        let runtime_attestation =
            validate_external_pg_session(runtime_probe, &self.runtime_expected, self.runtime_kind)
                .map_err(session_policy_sqlx_error)?;
        let runtime_is_member = if self.shared_development_identity {
            false
        } else {
            runtime_is_member_of_migration_role(connection, &self.migration_role)
                .await
                .map_err(|_| {
                    session_policy_sqlx_error(session_policy_error(
                        "the live role-membership attestation query failed",
                    ))
                })?
        };
        validate_external_pg_session_pair(
            &self.migration_attestation,
            &runtime_attestation,
            runtime_is_member,
            self.shared_development_identity,
        )
        .map_err(session_policy_sqlx_error)?;
        if !self.shared_development_identity {
            attest_external_pg_control_plane(
                connection,
                &self.migration_role,
                &self.runtime_expected.username,
            )
            .await
            .map_err(|_| {
                session_policy_sqlx_error(session_policy_error(
                    "the live trusted-boundary or closed-catalog attestation failed",
                ))
            })?;
            let (tables, columns, sequences, other) =
                probe_external_pg_runtime_privileges(connection, &self.migration_role)
                    .await
                    .map_err(|_| {
                        session_policy_sqlx_error(session_policy_error(
                            "the live runtime privilege attestation query failed",
                        ))
                    })?;
            validate_external_pg_runtime_privileges(&tables, &columns, &sequences, &other)
                .map_err(session_policy_sqlx_error)?;
        }
        Ok(())
    }
}

/// Connect to an externally managed PostgreSQL instance.
/// Returns `None` on configuration, connection, migration, or attestation
/// failure so the server still starts and DB-backed routes return 503.
///
/// Production requires distinct runtime and migration roles, both using
/// `sslmode=verify-full` against the same database target. The migration
/// connection holds the exclusive form of a database-scoped advisory lock
/// across the complete maintenance lifecycle: runtime CONNECT is revoked,
/// quiescence is proved, existing/default ACLs are hardened, migrations run,
/// the closed release catalog is verified, exact grants are installed, and
/// only then is runtime CONNECT restored. Before releasing the exclusive lock,
/// that same session acquires the shared form; every physical runtime
/// connection then acquires and attests that shared lifecycle lock exactly
/// once. The migration session closes only after the pool has a shared-lock
/// keeper, so there is no unlocked handoff window. Explicit development mode
/// can reuse `DATABASE_URL` only when
/// `OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL=true`.
///
/// Configuration, connection, or migration failure leaves DB-backed routes
/// unavailable. External connection errors are deliberately not formatted
/// into logs because a driver error may contain credential-bearing context.
pub async fn connect_external(database_url: &str) -> Option<PgPool> {
    let ambient_variable = EXTERNAL_PG_AMBIENT_ENV_VARS
        .iter()
        .copied()
        .find(|name| std::env::var_os(name).is_some());
    if let Err(error) = validate_external_pg_ambient_options(ambient_variable) {
        eprintln!("[olympus-desktop] {error} — DB-backed routes return 503");
        return None;
    }

    let migration_url = std::env::var(MIGRATION_DATABASE_URL_ENV).ok();
    let plan = match external_pg_connection_plan(
        database_url,
        migration_url.as_deref(),
        env_flag_enabled(DEV_ALLOW_SINGLE_DATABASE_URL_ENV),
        crate::env::is_production(),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("[olympus-desktop] {error} — DB-backed routes return 503");
            return None;
        }
    };
    drop(migration_url);

    let ExternalPgConnectionPlan {
        migration,
        runtime,
        shared_development_identity,
    } = plan;
    let migration_expected = ExternalPgExpectedSession::from_options(&migration);
    let runtime_expected = ExternalPgExpectedSession::from_options(&runtime);
    let migration_kind = if shared_development_identity {
        ExternalPgSessionKind::SharedDevelopment
    } else {
        ExternalPgSessionKind::Migration
    };

    let mut migration_connection = match PgConnection::connect_with(&migration).await {
        Ok(connection) => connection,
        Err(_) => {
            eprintln!(
                "[olympus-desktop] external migration database connection failed — \
                 DB-backed routes return 503"
            );
            return None;
        }
    };

    let maintenance_lock_acquired =
        acquire_external_pg_maintenance_lock(&mut migration_connection).await;
    if !maintenance_lock_acquired {
        let _ = migration_connection.close().await;
        eprintln!(
            "[olympus-desktop] external database maintenance lock is unavailable — \
             DB-backed routes return 503"
        );
        return None;
    }

    let migration_probe = match probe_external_pg_connection(&mut migration_connection).await {
        Ok(probe) => probe,
        Err(_) => {
            let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
            let _ = migration_connection.close().await;
            eprintln!(
                "[olympus-desktop] external migration database session attestation failed — \
                 DB-backed routes return 503"
            );
            return None;
        }
    };

    if !shared_development_identity {
        if validate_external_pg_migration_maintenance_authority(
            &migration_probe,
            &migration_expected,
        )
        .is_err()
        {
            let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
            let _ = migration_connection.close().await;
            eprintln!(
                "[olympus-desktop] external migration maintenance authority attestation failed — \
                 DB-backed routes return 503"
            );
            return None;
        }

        let maintenance_ready =
            enter_external_pg_maintenance(&mut migration_connection, &runtime_expected.username)
                .await;
        if maintenance_ready.is_err() {
            let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
            let _ = migration_connection.close().await;
            eprintln!(
                "[olympus-desktop] external database did not enter a fail-closed, quiescent \
                 maintenance state — DB-backed routes return 503"
            );
            return None;
        }
    }

    let migration_attestation =
        match validate_external_pg_session(migration_probe, &migration_expected, migration_kind) {
            Ok(attestation) => attestation,
            Err(_) => {
                let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
                let _ = migration_connection.close().await;
                eprintln!(
                    "[olympus-desktop] external migration database session attestation failed — \
                 DB-backed routes return 503"
                );
                return None;
            }
        };

    if !shared_development_identity {
        if harden_external_pg_before_migrations(
            &mut migration_connection,
            &runtime_expected.username,
        )
        .await
        .is_err()
        {
            let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
            let _ = migration_connection.close().await;
            eprintln!(
                "[olympus-desktop] external database pre-migration hardening failed — \
                 DB-backed routes return 503"
            );
            return None;
        }
        if attest_external_pg_trusted_boundary(
            &mut migration_connection,
            &migration_attestation.session_user,
            &runtime_expected.username,
        )
        .await
        .is_err()
        {
            let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
            let _ = migration_connection.close().await;
            eprintln!(
                "[olympus-desktop] external database trusted-boundary attestation failed before \
                 migrations — DB-backed routes return 503"
            );
            return None;
        }
    }

    if sqlx::migrate!("../migrations")
        .run(&mut migration_connection)
        .await
        .is_err()
    {
        let fail_closed = shared_development_identity
            || reassert_external_pg_fail_closed(
                &mut migration_connection,
                &runtime_expected.username,
            )
            .await
            .is_ok();
        let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
        let _ = migration_connection.close().await;
        if !fail_closed {
            eprintln!(
                "[olympus-desktop] external migration failure also prevented automatic \
                 fail-closed cleanup; apply the documented operator recovery procedure"
            );
        }
        eprintln!(
            "[olympus-desktop] migrations failed against external database — \
             DB-backed routes return 503"
        );
        return None;
    }

    if !shared_development_identity {
        let post_migration_policy_ready = prepare_external_pg_release_policy(
            &mut migration_connection,
            &migration_attestation.session_user,
            &runtime_expected.username,
        )
        .await;
        if post_migration_policy_ready.is_err() {
            let fail_closed = reassert_external_pg_fail_closed(
                &mut migration_connection,
                &runtime_expected.username,
            )
            .await
            .is_ok();
            let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
            let _ = migration_connection.close().await;
            if !fail_closed {
                eprintln!(
                    "[olympus-desktop] external policy failure also prevented automatic \
                     fail-closed cleanup; apply the documented operator recovery procedure"
                );
            }
            eprintln!(
                "[olympus-desktop] external post-migration catalog or privilege policy failed — \
                 DB-backed routes return 503"
            );
            return None;
        }
    }

    let post_migration_attestation = probe_external_pg_connection(&mut migration_connection)
        .await
        .and_then(|probe| {
            validate_external_pg_session(probe, &migration_expected, migration_kind)
                .map_err(session_policy_sqlx_error)
        });
    if !matches!(
        post_migration_attestation,
        Ok(ref attestation) if attestation == &migration_attestation
    ) {
        if !shared_development_identity {
            let _ = harden_external_pg_before_migrations(
                &mut migration_connection,
                &runtime_expected.username,
            )
            .await;
        }
        let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
        let _ = migration_connection.close().await;
        eprintln!(
            "[olympus-desktop] external migration database post-migration session attestation \
             failed — DB-backed routes return 503"
        );
        return None;
    }

    let runtime_role = runtime_expected.username.clone();
    let runtime_kind = if shared_development_identity {
        ExternalPgSessionKind::SharedDevelopment
    } else {
        ExternalPgSessionKind::Runtime
    };
    let attestation_context = ExternalPgRuntimeAttestationContext {
        migration_role: migration_attestation.session_user.clone(),
        migration_attestation,
        runtime_expected,
        runtime_kind,
        shared_development_identity,
    };
    let after_connect_context = attestation_context.clone();
    let before_acquire_context = attestation_context;
    let runtime_pool_options = PgPoolOptions::new()
        .min_connections(1)
        .max_lifetime(None::<Duration>)
        .idle_timeout(None::<Duration>)
        .after_connect(move |connection, _metadata| {
            let context = after_connect_context.clone();
            Box::pin(async move {
                if !acquire_external_pg_runtime_lock(connection).await {
                    return Err(session_policy_sqlx_error(session_policy_error(
                        "the shared database lifecycle lock is unavailable",
                    )));
                }
                context.attest(connection).await
            })
        })
        .before_acquire(move |connection, _metadata| {
            let context = before_acquire_context.clone();
            Box::pin(async move {
                context.attest(connection).await?;
                Ok(true)
            })
        });

    if !shared_development_identity
        && set_external_pg_runtime_connect(&mut migration_connection, &runtime_role, true)
            .await
            .is_err()
    {
        let fail_closed =
            reassert_external_pg_fail_closed(&mut migration_connection, &runtime_role)
                .await
                .is_ok();
        let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
        let _ = migration_connection.close().await;
        if !fail_closed {
            eprintln!(
                "[olympus-desktop] runtime CONNECT restoration failure also prevented automatic \
                 fail-closed cleanup; apply the documented operator recovery procedure"
            );
        }
        eprintln!(
            "[olympus-desktop] external runtime CONNECT restoration failed — \
             DB-backed routes return 503"
        );
        return None;
    }

    if !acquire_external_pg_runtime_lock(&mut migration_connection).await {
        let fail_closed = shared_development_identity
            || set_external_pg_runtime_connect(&mut migration_connection, &runtime_role, false)
                .await
                .is_ok()
                && reassert_external_pg_fail_closed(&mut migration_connection, &runtime_role)
                    .await
                    .is_ok();
        let _ = release_external_pg_maintenance_lock(&mut migration_connection).await;
        let _ = migration_connection.close().await;
        if !fail_closed {
            eprintln!(
                "[olympus-desktop] runtime-lock handoff failure also prevented automatic \
                 fail-closed cleanup; apply the documented operator recovery procedure"
            );
        }
        eprintln!(
            "[olympus-desktop] external shared database lifecycle lock acquisition failed — \
             DB-backed routes return 503"
        );
        return None;
    }

    let maintenance_lock_released =
        release_external_pg_maintenance_lock(&mut migration_connection).await;
    if !maintenance_lock_released {
        let fail_closed = recover_external_pg_handoff_failure(
            &mut migration_connection,
            &runtime_role,
            shared_development_identity,
        )
        .await;
        let _ = migration_connection.close().await;
        if !fail_closed {
            eprintln!(
                "[olympus-desktop] maintenance-lock failure also prevented automatic \
                 fail-closed cleanup; apply the documented operator recovery procedure"
            );
        }
        eprintln!(
            "[olympus-desktop] external database maintenance lock release failed — \
             DB-backed routes return 503"
        );
        return None;
    }

    let runtime_pool = match runtime_pool_options.connect_with(runtime).await {
        Ok(pool) => pool,
        Err(_) => {
            let fail_closed = recover_external_pg_handoff_failure(
                &mut migration_connection,
                &runtime_role,
                shared_development_identity,
            )
            .await;
            let _ = migration_connection.close().await;
            if !fail_closed {
                eprintln!(
                    "[olympus-desktop] runtime connection failure also prevented automatic \
                     fail-closed cleanup; apply the documented operator recovery procedure"
                );
            }
            eprintln!(
                "[olympus-desktop] external runtime database connection or session attestation \
                 failed — DB-backed routes return 503"
            );
            return None;
        }
    };

    // `connect_with` establishes the configured minimum connection before it
    // returns. Its after-connect hook has therefore installed and attested at
    // least one shared lifecycle lock before this handoff keeper is closed.
    let _ = migration_connection.close().await;
    Some(runtime_pool)
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

    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    struct CapturedLogWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("captured log lock")
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogWriter(self.0.clone())
        }
    }

    fn assert_config_error<T>(
        result: Result<T, DbError>,
        expected_variable: &'static str,
        expected_reason: &'static str,
    ) {
        match result {
            Err(DbError::ExternalConfiguration { variable, reason }) => {
                assert_eq!(variable, expected_variable);
                assert_eq!(reason, expected_reason);
            }
            Err(other) => panic!("unexpected external database error: {other}"),
            Ok(_) => panic!("external database configuration unexpectedly accepted"),
        }
    }

    fn expected_session(username: &str) -> ExternalPgExpectedSession {
        ExternalPgExpectedSession {
            username: username.to_owned(),
            database: "olympus".to_owned(),
        }
    }

    fn least_privilege_probe(username: &str, migration: bool) -> ExternalPgSessionProbe {
        ExternalPgSessionProbe {
            server_version_num: 150_016,
            session_user: username.to_owned(),
            current_user: username.to_owned(),
            current_database: "olympus".to_owned(),
            current_schema: Some("olympus_app".to_owned()),
            configured_search_path: "olympus_app".to_owned(),
            resolved_search_path: vec!["olympus_app".to_owned()],
            search_path_is_exact_literal: true,
            is_superuser: false,
            can_create_role: false,
            can_create_database: false,
            can_replicate: false,
            can_bypass_rls: false,
            has_database_connect: true,
            has_database_create: false,
            has_database_temporary: false,
            has_direct_database_connect: true,
            has_direct_database_connect_grant_option: migration,
            public_has_any_database_privilege: false,
            has_current_schema_usage: true,
            has_current_schema_create: migration,
            has_direct_current_schema_usage: !migration,
            current_schema_acl_has_grant_option: false,
            public_has_any_current_schema_privilege: false,
            has_any_off_path_schema_privilege: false,
            public_has_any_off_path_schema_privilege: false,
            public_has_create_on_any_non_system_schema: false,
            has_search_path_schema_create: migration,
            owns_database: false,
            owns_current_schema: migration,
            owns_search_path_schema: migration,
            owns_search_path_objects: migration,
            can_assume_any_other_role: false,
            can_assume_dangerous_role: false,
        }
    }

    fn assert_session_policy_error<T>(
        result: Result<T, ExternalPgSessionPolicyError>,
        expected_reason: &'static str,
    ) {
        match result {
            Err(error) => assert_eq!(error.reason, expected_reason),
            Ok(_) => panic!("external database session policy unexpectedly accepted"),
        }
    }

    fn least_privilege_table_probes() -> Vec<ExternalPgTablePrivilegeProbe> {
        let mut probes: Vec<_> = EXTERNAL_PG_TABLE_GRANTS
            .iter()
            .map(|grant| ExternalPgTablePrivilegeProbe {
                object_name: grant.name.to_owned(),
                can_select: expected_grant_has(grant, "SELECT"),
                can_insert: expected_grant_has(grant, "INSERT"),
                can_update: expected_grant_has(grant, "UPDATE"),
                can_delete: expected_grant_has(grant, "DELETE"),
                can_truncate: false,
                can_references: false,
                can_trigger: false,
                runtime_has_table_grant_option: false,
                runtime_has_unknown_table_privilege: false,
                public_has_any_privilege: false,
            })
            .collect();
        probes.push(ExternalPgTablePrivilegeProbe {
            object_name: "_sqlx_migrations".to_owned(),
            can_select: false,
            can_insert: false,
            can_update: false,
            can_delete: false,
            can_truncate: false,
            can_references: false,
            can_trigger: false,
            runtime_has_table_grant_option: false,
            runtime_has_unknown_table_privilege: false,
            public_has_any_privilege: false,
        });
        probes
    }

    fn least_privilege_column_probes() -> Vec<ExternalPgColumnPrivilegeProbe> {
        EXTERNAL_PG_COLUMN_GRANTS
            .iter()
            .flat_map(|grant| {
                grant
                    .columns
                    .iter()
                    .map(|column| ExternalPgColumnPrivilegeProbe {
                        object_name: grant.table_name.to_owned(),
                        column_name: (*column).to_owned(),
                        privilege_type: grant.privilege.to_owned(),
                        is_grantable: false,
                        grantee_is_public: false,
                    })
            })
            .collect()
    }

    fn least_privilege_sequence_probes() -> Vec<ExternalPgSequencePrivilegeProbe> {
        EXTERNAL_PG_SEQUENCE_GRANTS
            .iter()
            .map(|grant| ExternalPgSequencePrivilegeProbe {
                object_name: grant.name.to_owned(),
                can_usage: expected_grant_has(grant, "USAGE"),
                can_select: expected_grant_has(grant, "SELECT"),
                can_update: expected_grant_has(grant, "UPDATE"),
                runtime_has_grant_option: false,
                public_has_any_privilege: false,
            })
            .collect()
    }

    fn least_privilege_other_probe() -> ExternalPgOtherPrivilegeProbe {
        ExternalPgOtherPrivilegeProbe {
            schema_public_has_any_privilege: false,
            runtime_has_any_routine_execute: false,
            public_has_any_routine_privilege: false,
            runtime_has_any_type_usage: false,
            public_has_any_type_privilege: false,
            migration_defaults_have_ambient_privileges: false,
            migration_defaults_have_grant_options: false,
            runtime_or_public_has_off_path_object_privileges: false,
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
    fn migration_maintenance_authority_requires_the_direct_connect_grant_option() {
        let expected = expected_session("olympus_migrator");
        let probe = least_privilege_probe("olympus_migrator", true);
        validate_external_pg_migration_maintenance_authority(&probe, &expected)
            .expect("least-privilege maintenance authority");

        let mut missing_grant_option = probe.clone();
        missing_grant_option.has_direct_database_connect_grant_option = false;
        assert_session_policy_error(
            validate_external_pg_migration_maintenance_authority(&missing_grant_option, &expected),
            "the migration maintenance identity lacks the exact database CONNECT grant",
        );

        let mut database_owner = probe;
        database_owner.owns_database = true;
        assert_session_policy_error(
            validate_external_pg_migration_maintenance_authority(&database_owner, &expected),
            "the migration maintenance identity has forbidden authority",
        );
    }

    #[test]
    fn maintenance_quiescence_and_trusted_boundary_fail_closed() {
        let quiescent = ExternalPgMaintenanceProbe {
            runtime_has_effective_connect: false,
            runtime_active_sessions: 0,
            runtime_prepared_transactions: 0,
        };
        validate_external_pg_quiescence(&quiescent).expect("quiescent runtime");

        let mut active = quiescent;
        active.runtime_active_sessions = 1;
        assert_session_policy_error(
            validate_external_pg_quiescence(&active),
            "external PostgreSQL maintenance requires revoked runtime CONNECT, zero runtime sessions, and zero runtime prepared transactions",
        );

        validate_external_pg_trusted_boundary(&ExternalPgTrustedBoundaryProbe {
            has_untrusted_boundary: false,
        })
        .expect("closed trusted boundary");
        assert_session_policy_error(
            validate_external_pg_trusted_boundary(&ExternalPgTrustedBoundaryProbe {
                has_untrusted_boundary: true,
            }),
            "external PostgreSQL contains an untrusted owner, ACL grantor/grantee, default-ACL creator, or role membership",
        );
    }

    #[test]
    fn maintenance_lock_key_exactly_encodes_the_live_database_oid() {
        for database_oid in [0_u32, 1, i32::MAX as u32, u32::MAX] {
            let key = external_pg_maintenance_lock_key(database_oid);
            assert!(key > 0);
            assert_eq!(
                (key >> 32) & i64::from(u32::MAX),
                EXTERNAL_PG_MAINTENANCE_LOCK_NAMESPACE,
            );
            assert_eq!(key & i64::from(u32::MAX), i64::from(database_oid));
        }
        assert_ne!(
            external_pg_maintenance_lock_key(41),
            external_pg_maintenance_lock_key(42),
        );
    }

    #[test]
    fn semantic_inventory_digest_binds_rows_and_closed_catalog_rejects_unknown_classes() {
        let rows = vec![ExternalPgSemanticInventoryRow {
            object_kind: "index".to_owned(),
            parent_name: "doc_commits".to_owned(),
            object_name: "doc_commits_commit_id_idx".to_owned(),
            definition: "{\"unique\":false}".to_owned(),
        }];
        assert_eq!(
            external_pg_semantic_inventory_digest(&rows),
            external_pg_semantic_inventory_digest(&rows.clone()),
        );
        let mut changed = rows.clone();
        changed[0].definition = "{\"unique\":true}".to_owned();
        assert_ne!(
            external_pg_semantic_inventory_digest(&rows),
            external_pg_semantic_inventory_digest(&changed),
        );

        assert_session_policy_error(
            validate_external_pg_closed_catalog(
                &ExternalPgClosedCatalogProbe {
                    has_unsupported_object: true,
                },
                &[],
            ),
            "the application schema contains an unsupported executable or semantic object class",
        );
    }

    #[test]
    fn production_external_database_requires_verify_full() {
        let options = external_pg_connect_options(
            "postgresql://olympus:secret@db.example.com:5432/olympus?sslmode=verify-full",
            "DATABASE_URL",
            true,
        )
        .expect("verify-full production URL");
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
        assert_eq!(options.get_host(), "db.example.com");

        for url in [
            "postgresql://olympus:secret@db.example.com:5432/olympus",
            "postgresql://olympus:secret@db.example.com:5432/olympus?sslmode=disable",
            "postgresql://olympus:secret@db.example.com:5432/olympus?sslmode=require",
            "postgresql://olympus:secret@db.example.com:5432/olympus?sslmode=verify-ca",
        ] {
            assert_config_error(
                external_pg_connect_options(url, "DATABASE_URL", true),
                "DATABASE_URL",
                "must set sslmode=verify-full in production",
            );
        }
    }

    #[test]
    fn production_external_database_rejects_socket_and_malformed_urls() {
        assert_config_error(
            external_pg_connect_options(
                "postgresql://olympus:secret@localhost:5432/olympus?host=%2Fvar%2Frun%2Fpostgresql&sslmode=verify-full",
                "DATABASE_URL",
                true,
            ),
            "DATABASE_URL",
            "must explicitly set user, password, hostname, port, and database in production",
        );
        assert_config_error(
            external_pg_connect_options("not a PostgreSQL URL", "DATABASE_URL", true),
            "DATABASE_URL",
            "must be a valid PostgreSQL URL",
        );
        assert_config_error(
            external_pg_connect_options("  ", "DATABASE_URL", true),
            "DATABASE_URL",
            "must not be empty",
        );
        assert_config_error(
            external_pg_connect_options(
                "https://olympus:secret@db.example.com/olympus?sslmode=verify-full",
                "DATABASE_URL",
                true,
            ),
            "DATABASE_URL",
            "must use a postgres:// or postgresql:// URL",
        );
    }

    #[test]
    fn production_external_database_requires_explicit_connection_components() {
        for url in [
            "postgresql://:secret@db.example.com:5432/olympus?sslmode=verify-full",
            "postgresql://olympus@db.example.com:5432/olympus?sslmode=verify-full",
            "postgresql://olympus:@db.example.com:5432/olympus?sslmode=verify-full",
            "postgresql://olympus:secret@db.example.com/olympus?sslmode=verify-full",
            "postgresql://olympus:secret@db.example.com:5432/?sslmode=verify-full",
            "postgresql://olympus:secret@db.example.com:5432/olympus?sslmode=verify-full&hostaddr=192.0.2.1",
        ] {
            assert_config_error(
                external_pg_connect_options(url, "DATABASE_URL", true),
                "DATABASE_URL",
                "must explicitly set user, password, hostname, port, and database in production",
            );
        }

        external_pg_connect_options(
            "postgresql://olympus:secret@db.example.com:5432/olympus?sslmode=verify-full&sslrootcert=C%3A%5Ccerts%5Colympus-ca.pem",
            "DATABASE_URL",
            true,
        )
        .expect("custom root certificate must come from the explicit URL");
    }

    #[test]
    fn external_database_rejects_url_and_ambient_session_options() {
        for url in [
            "postgresql://olympus@db.example.com/olympus?options=-c%20search_path%3Dother",
            "postgresql://olympus@db.example.com/olympus?options[search_path]=other",
            "postgresql://olympus@db.example.com/olympus?options%5Brole%5D=owner",
        ] {
            assert_config_error(
                external_pg_connect_options(url, "DATABASE_URL", false),
                "DATABASE_URL",
                "contains an unsupported query parameter",
            );
        }

        for &variable in EXTERNAL_PG_AMBIENT_ENV_VARS {
            assert_config_error(
                validate_external_pg_ambient_options(Some(variable)),
                variable,
                "must be unset; external PostgreSQL settings come only from the configured URLs",
            );
        }
        validate_external_pg_ambient_options(None).expect("unset ambient PostgreSQL variables");
    }

    #[test]
    fn development_external_database_preserves_local_tls_defaults() {
        let default =
            external_pg_connect_options("postgresql://localhost/olympus", "DATABASE_URL", false)
                .unwrap();
        assert!(matches!(default.get_ssl_mode(), PgSslMode::Prefer));

        let disabled = external_pg_connect_options(
            "postgresql://localhost/olympus?sslmode=disable",
            "DATABASE_URL",
            false,
        )
        .unwrap();
        assert!(matches!(disabled.get_ssl_mode(), PgSslMode::Disable));
    }

    #[test]
    fn production_external_database_separates_migration_and_runtime_roles() {
        let plan = external_pg_connection_plan(
            "postgresql://olympus_runtime:runtime-secret@db.example.com:5432/olympus?sslmode=verify-full",
            Some(
                "postgresql://olympus_migrator:migration-secret@db.example.com:5432/olympus?sslmode=verify-full",
            ),
            false,
            true,
        )
        .expect("distinct production database roles");

        assert_eq!(plan.runtime.get_username(), "olympus_runtime");
        assert_eq!(plan.migration.get_username(), "olympus_migrator");
        assert!(same_database_target(&plan.runtime, &plan.migration));
        assert!(matches!(plan.runtime.get_ssl_mode(), PgSslMode::VerifyFull));
        assert!(matches!(
            plan.migration.get_ssl_mode(),
            PgSslMode::VerifyFull
        ));
    }

    #[test]
    fn production_external_database_requires_a_dedicated_migration_role() {
        const RUNTIME: &str =
            "postgresql://olympus_runtime:runtime-secret@db.example.com:5432/olympus?sslmode=verify-full";

        assert_config_error(
            external_pg_connection_plan(RUNTIME, None, false, true),
            MIGRATION_DATABASE_URL_ENV,
            "is required when DATABASE_URL is set in production",
        );
        assert_config_error(
            external_pg_connection_plan(RUNTIME, None, true, true),
            DEV_ALLOW_SINGLE_DATABASE_URL_ENV,
            "is development-only and forbidden in production",
        );
        assert_config_error(
            external_pg_connection_plan(
                RUNTIME,
                Some(
                    "postgresql://olympus_runtime:other-secret@db.example.com:5432/olympus?sslmode=verify-full",
                ),
                false,
                true,
            ),
            MIGRATION_DATABASE_URL_ENV,
            "must authenticate as a role distinct from DATABASE_URL",
        );
        assert_config_error(
            external_pg_connection_plan(
                RUNTIME,
                Some(
                    "postgresql://olympus_migrator:migration-secret@db.example.com:5432/olympus?sslmode=verify-ca",
                ),
                false,
                true,
            ),
            MIGRATION_DATABASE_URL_ENV,
            "must set sslmode=verify-full in production",
        );
    }

    #[test]
    fn external_database_roles_must_target_the_same_database() {
        const RUNTIME: &str =
            "postgresql://olympus_runtime:runtime-secret@db.example.com:5432/olympus?sslmode=verify-full";

        for migration_url in [
            "postgresql://olympus_migrator:secret@other.example.com:5432/olympus?sslmode=verify-full",
            "postgresql://olympus_migrator:secret@db.example.com:5433/olympus?sslmode=verify-full",
            "postgresql://olympus_migrator:secret@db.example.com:5432/other?sslmode=verify-full",
        ] {
            assert_config_error(
                external_pg_connection_plan(RUNTIME, Some(migration_url), false, true),
                MIGRATION_DATABASE_URL_ENV,
                "must target the same host, port, and database as DATABASE_URL",
            );
        }
    }

    #[test]
    fn role_and_target_checks_use_decoded_explicit_url_values() {
        let plan = external_pg_connection_plan(
            "postgresql://olympus%5Fruntime:runtime-secret@DB.EXAMPLE.COM:5432/olym%70us?sslmode=verify-full",
            Some(
                "postgresql://olympus_migrator:migration-secret@db.example.com:5432/olympus?sslmode=verify-full",
            ),
            false,
            true,
        )
        .expect("decoded effective targets and distinct roles");
        assert_eq!(plan.runtime.get_username(), "olympus_runtime");
        assert_eq!(plan.migration.get_username(), "olympus_migrator");
        assert_eq!(effective_database(&plan.runtime), "olympus");
        assert!(same_database_target(&plan.runtime, &plan.migration));

        assert_config_error(
            external_pg_connection_plan(
                "postgresql://olympus%5Fruntime:runtime-secret@db.example.com:5432/olympus?sslmode=verify-full",
                Some(
                    "postgresql://olympus_runtime:migration-secret@db.example.com:5432/olympus?sslmode=verify-full",
                ),
                false,
                true,
            ),
            MIGRATION_DATABASE_URL_ENV,
            "must authenticate as a role distinct from DATABASE_URL",
        );
    }

    #[test]
    fn development_socket_targets_must_resolve_to_the_same_path() {
        assert_config_error(
            external_pg_connection_plan(
                "postgresql://local_runtime@localhost/olympus?host=%2Fvar%2Frun%2Fpostgresql&sslmode=disable",
                Some(
                    "postgresql://local_migrator@localhost/olympus?host=%2Ftmp%2Fpostgresql&sslmode=disable",
                ),
                false,
                false,
            ),
            MIGRATION_DATABASE_URL_ENV,
            "must target the same host, port, and database as DATABASE_URL",
        );
    }

    #[test]
    fn development_single_role_path_requires_explicit_opt_in() {
        const RUNTIME: &str = "postgresql://local_dev@localhost/olympus";

        assert_config_error(
            external_pg_connection_plan(RUNTIME, None, false, false),
            MIGRATION_DATABASE_URL_ENV,
            "is required unless OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL=true",
        );

        let plan = external_pg_connection_plan(RUNTIME, None, true, false)
            .expect("explicit single-role development path");
        assert_eq!(plan.runtime.get_username(), "local_dev");
        assert_eq!(plan.migration.get_username(), "local_dev");
        assert!(matches!(plan.runtime.get_ssl_mode(), PgSslMode::Prefer));
        assert!(matches!(plan.migration.get_ssl_mode(), PgSslMode::Prefer));

        assert_config_error(
            external_pg_connection_plan(
                RUNTIME,
                Some("postgresql://local_migrator@localhost/olympus"),
                true,
                false,
            ),
            DEV_ALLOW_SINGLE_DATABASE_URL_ENV,
            "must be unset when OLYMPUS_DATABASE_MIGRATION_URL is configured",
        );
    }

    #[test]
    fn development_supports_explicit_separate_local_roles() {
        let plan = external_pg_connection_plan(
            "postgresql://local_runtime@localhost/olympus?sslmode=disable",
            Some("postgresql://local_migrator@localhost/olympus?sslmode=disable"),
            false,
            false,
        )
        .expect("separate development database roles");

        assert_eq!(plan.runtime.get_username(), "local_runtime");
        assert_eq!(plan.migration.get_username(), "local_migrator");
        assert!(matches!(plan.runtime.get_ssl_mode(), PgSslMode::Disable));
        assert!(matches!(plan.migration.get_ssl_mode(), PgSslMode::Disable));
    }

    #[test]
    fn live_session_policy_accepts_a_least_privilege_role_pair() {
        let migration = validate_external_pg_session(
            least_privilege_probe("olympus_migrator", true),
            &expected_session("olympus_migrator"),
            ExternalPgSessionKind::Migration,
        )
        .expect("least-privilege migration session");
        let runtime = validate_external_pg_session(
            least_privilege_probe("olympus_runtime", false),
            &expected_session("olympus_runtime"),
            ExternalPgSessionKind::Runtime,
        )
        .expect("least-privilege runtime session");

        validate_external_pg_session_pair(&migration, &runtime, false, false)
            .expect("distinct live roles with the same database and schema");
    }

    #[test]
    fn release_runtime_privilege_manifest_is_complete_and_least_privilege() {
        assert_eq!(EXTERNAL_PG_TABLE_GRANTS.len(), 32);
        assert_eq!(EXTERNAL_PG_SEQUENCE_GRANTS.len(), 2);

        for (index, grant) in EXTERNAL_PG_TABLE_GRANTS.iter().enumerate() {
            assert!(
                EXTERNAL_PG_TABLE_GRANTS[..index]
                    .iter()
                    .all(|prior| prior.name != grant.name),
                "duplicate table grant manifest entry"
            );
            assert!(grant
                .privileges
                .iter()
                .all(|privilege| matches!(*privilege, "SELECT" | "INSERT" | "UPDATE" | "DELETE")));
        }
        for (index, grant) in EXTERNAL_PG_SEQUENCE_GRANTS.iter().enumerate() {
            assert!(
                EXTERNAL_PG_SEQUENCE_GRANTS[..index]
                    .iter()
                    .all(|prior| prior.name != grant.name),
                "duplicate sequence grant manifest entry"
            );
            assert!(grant
                .privileges
                .iter()
                .all(|privilege| matches!(*privilege, "USAGE" | "SELECT" | "UPDATE")));
        }
        for (index, grant) in EXTERNAL_PG_COLUMN_GRANTS.iter().enumerate() {
            assert!(
                EXTERNAL_PG_COLUMN_GRANTS[..index].iter().all(|prior| {
                    prior.table_name != grant.table_name || prior.privilege != grant.privilege
                }),
                "duplicate column grant manifest entry"
            );
            assert!(matches!(grant.privilege, "SELECT" | "UPDATE"));
            assert!(!grant.columns.is_empty());
        }

        validate_external_pg_runtime_privileges(
            &least_privilege_table_probes(),
            &least_privilege_column_probes(),
            &least_privilege_sequence_probes(),
            &least_privilege_other_probe(),
        )
        .expect("release privilege manifest");
    }

    #[test]
    fn runtime_privilege_policy_rejects_extra_or_missing_access() {
        let columns = least_privilege_column_probes();
        let sequences = least_privilege_sequence_probes();
        let other = least_privilege_other_probe();

        let mut unexpected_table = least_privilege_table_probes();
        unexpected_table.push(ExternalPgTablePrivilegeProbe {
            object_name: "attacker_table".to_owned(),
            can_select: false,
            can_insert: false,
            can_update: false,
            can_delete: false,
            can_truncate: false,
            can_references: false,
            can_trigger: false,
            runtime_has_table_grant_option: false,
            runtime_has_unknown_table_privilege: false,
            public_has_any_privilege: false,
        });
        assert_session_policy_error(
            validate_external_pg_runtime_privileges(
                &unexpected_table,
                &columns,
                &sequences,
                &other,
            ),
            "the runtime table inventory differs from the release privilege manifest",
        );

        let mut ddl_like_privilege = least_privilege_table_probes();
        ddl_like_privilege
            .iter_mut()
            .find(|probe| probe.object_name == "users")
            .expect("users probe")
            .can_trigger = true;
        assert_session_policy_error(
            validate_external_pg_runtime_privileges(
                &ddl_like_privilege,
                &columns,
                &sequences,
                &other,
            ),
            "the runtime table privileges differ from the release privilege manifest",
        );

        let mut migration_metadata_access = least_privilege_table_probes();
        migration_metadata_access
            .iter_mut()
            .find(|probe| probe.object_name == "_sqlx_migrations")
            .expect("sqlx metadata probe")
            .can_select = true;
        assert_session_policy_error(
            validate_external_pg_runtime_privileges(
                &migration_metadata_access,
                &columns,
                &sequences,
                &other,
            ),
            "the runtime table privileges differ from the release privilege manifest",
        );

        let mut ambient_defaults = least_privilege_other_probe();
        ambient_defaults.migration_defaults_have_ambient_privileges = true;
        assert_session_policy_error(
            validate_external_pg_runtime_privileges(
                &least_privilege_table_probes(),
                &columns,
                &sequences,
                &ambient_defaults,
            ),
            "the runtime schema, routine, type, or default privileges differ from policy",
        );

        let mut grantable_column = columns.clone();
        grantable_column[0].is_grantable = true;
        assert_session_policy_error(
            validate_external_pg_runtime_privileges(
                &least_privilege_table_probes(),
                &grantable_column,
                &sequences,
                &other,
            ),
            "the runtime column privileges differ from the release privilege manifest",
        );

        let mut public_column = columns.clone();
        public_column[0].grantee_is_public = true;
        assert_session_policy_error(
            validate_external_pg_runtime_privileges(
                &least_privilege_table_probes(),
                &public_column,
                &sequences,
                &other,
            ),
            "the runtime column privileges differ from the release privilege manifest",
        );

        let mut off_path = least_privilege_other_probe();
        off_path.runtime_or_public_has_off_path_object_privileges = true;
        assert_session_policy_error(
            validate_external_pg_runtime_privileges(
                &least_privilege_table_probes(),
                &columns,
                &sequences,
                &off_path,
            ),
            "the runtime schema, routine, type, or default privileges differ from policy",
        );
    }

    #[test]
    fn live_session_policy_rejects_effective_role_and_cluster_privilege_escalation() {
        let expected = expected_session("olympus_runtime");

        let mut changed_current_user = least_privilege_probe("olympus_runtime", false);
        changed_current_user.current_user = "olympus_migrator".to_owned();
        assert_session_policy_error(
            validate_external_pg_session(
                changed_current_user,
                &expected,
                ExternalPgSessionKind::Runtime,
            ),
            "current_user must equal session_user",
        );

        let mut superuser = least_privilege_probe("olympus_runtime", false);
        superuser.is_superuser = true;
        assert_session_policy_error(
            validate_external_pg_session(superuser, &expected, ExternalPgSessionKind::Runtime),
            "external database roles must not be superusers",
        );

        let mut inherited_owner = least_privilege_probe("olympus_runtime", false);
        inherited_owner.can_assume_any_other_role = true;
        inherited_owner.can_assume_dangerous_role = true;
        assert_session_policy_error(
            validate_external_pg_session(
                inherited_owner,
                &expected,
                ExternalPgSessionKind::Runtime,
            ),
            "the live role can assume another role with database or schema authority",
        );

        let mut inherited_dml_role = least_privilege_probe("olympus_runtime", false);
        inherited_dml_role.can_assume_any_other_role = true;
        assert_session_policy_error(
            validate_external_pg_session(
                inherited_dml_role,
                &expected,
                ExternalPgSessionKind::Runtime,
            ),
            "external application roles must not be able to assume another role",
        );
    }

    #[test]
    fn live_session_policy_rejects_runtime_ddl_authority() {
        let expected = expected_session("olympus_runtime");

        let mut database_owner = least_privilege_probe("olympus_runtime", false);
        database_owner.owns_database = true;
        assert_session_policy_error(
            validate_external_pg_session(database_owner, &expected, ExternalPgSessionKind::Runtime),
            "external database CONNECT, TEMPORARY, CREATE, ownership, or grant-option policy is not satisfied",
        );

        let mut schema_creator = least_privilege_probe("olympus_runtime", false);
        schema_creator.has_search_path_schema_create = true;
        assert_session_policy_error(
            validate_external_pg_session(schema_creator, &expected, ExternalPgSessionKind::Runtime),
            "the runtime role has DDL or ownership authority in its search_path",
        );

        let database_acl_mutations: [fn(&mut ExternalPgSessionProbe); 3] = [
            |probe: &mut ExternalPgSessionProbe| probe.has_direct_database_connect = false,
            |probe: &mut ExternalPgSessionProbe| probe.has_database_temporary = true,
            |probe: &mut ExternalPgSessionProbe| probe.public_has_any_database_privilege = true,
        ];
        for mutate in database_acl_mutations {
            let mut database_acl = least_privilege_probe("olympus_runtime", false);
            mutate(&mut database_acl);
            assert_session_policy_error(
                validate_external_pg_session(
                    database_acl,
                    &expected,
                    ExternalPgSessionKind::Runtime,
                ),
                "external database CONNECT, TEMPORARY, CREATE, ownership, or grant-option policy is not satisfied",
            );
        }

        let mut grantable_runtime_connect = least_privilege_probe("olympus_runtime", false);
        grantable_runtime_connect.has_direct_database_connect_grant_option = true;
        assert_session_policy_error(
            validate_external_pg_session(
                grantable_runtime_connect,
                &expected,
                ExternalPgSessionKind::Runtime,
            ),
            "the runtime database CONNECT privilege must not be grantable",
        );

        let mut migration_without_connect_grant_option =
            least_privilege_probe("olympus_migrator", true);
        migration_without_connect_grant_option.has_direct_database_connect_grant_option = false;
        assert_session_policy_error(
            validate_external_pg_session(
                migration_without_connect_grant_option,
                &expected_session("olympus_migrator"),
                ExternalPgSessionKind::Migration,
            ),
            "the migration role requires a direct CONNECT grant option for fail-closed maintenance",
        );
    }

    #[test]
    fn live_session_policy_rejects_unsafe_or_divergent_schema_resolution() {
        let expected = expected_session("olympus_runtime");
        let mut temporary = least_privilege_probe("olympus_runtime", false);
        temporary.current_schema = Some("pg_temp_7".to_owned());
        temporary.configured_search_path = "pg_temp, olympus_app".to_owned();
        temporary.resolved_search_path = vec!["pg_temp_7".to_owned(), "olympus_app".to_owned()];
        assert_session_policy_error(
            validate_external_pg_session(temporary, &expected, ExternalPgSessionKind::Runtime),
            "the live session has an unsafe, unresolved, or over-privileged schema path",
        );

        let mut multiple_schemas = least_privilege_probe("olympus_runtime", false);
        multiple_schemas.configured_search_path = "olympus_app, extensions".to_owned();
        multiple_schemas.resolved_search_path =
            vec!["olympus_app".to_owned(), "extensions".to_owned()];
        assert_session_policy_error(
            validate_external_pg_session(
                multiple_schemas,
                &expected,
                ExternalPgSessionKind::Runtime,
            ),
            "the live session has an unsafe, unresolved, or over-privileged schema path",
        );

        let mut unresolved_schema = least_privilege_probe("olympus_runtime", false);
        unresolved_schema.configured_search_path = "missing_schema, olympus_app".to_owned();
        unresolved_schema.search_path_is_exact_literal = false;
        assert_session_policy_error(
            validate_external_pg_session(
                unresolved_schema,
                &expected,
                ExternalPgSessionKind::Runtime,
            ),
            "the live session has an unsafe, unresolved, or over-privileged schema path",
        );

        let mut non_creator_migrator = least_privilege_probe("olympus_migrator", true);
        non_creator_migrator.owns_current_schema = false;
        non_creator_migrator.has_current_schema_create = false;
        assert_session_policy_error(
            validate_external_pg_session(
                non_creator_migrator,
                &expected_session("olympus_migrator"),
                ExternalPgSessionKind::Migration,
            ),
            "the migration role must be able to create objects in the sole configured application schema",
        );

        let migration = validate_external_pg_session(
            least_privilege_probe("olympus_migrator", true),
            &expected_session("olympus_migrator"),
            ExternalPgSessionKind::Migration,
        )
        .expect("migration session");
        let mut other_schema_probe = least_privilege_probe("olympus_runtime", false);
        other_schema_probe.current_schema = Some("other_app".to_owned());
        other_schema_probe.configured_search_path = "other_app".to_owned();
        other_schema_probe.resolved_search_path = vec!["other_app".to_owned()];
        let runtime = validate_external_pg_session(
            other_schema_probe,
            &expected,
            ExternalPgSessionKind::Runtime,
        )
        .expect("individually safe runtime session");
        assert_session_policy_error(
            validate_external_pg_session_pair(&migration, &runtime, false, false),
            "migration and runtime resolved different schema search paths",
        );

        let mut other_database = runtime.clone();
        other_database.current_schema = migration.current_schema.clone();
        other_database.configured_search_path = migration.configured_search_path.clone();
        other_database.resolved_search_path = migration.resolved_search_path.clone();
        other_database.current_database = "other_database".to_owned();
        assert_session_policy_error(
            validate_external_pg_session_pair(&migration, &other_database, false, false),
            "migration and runtime resolved different live databases",
        );
    }

    #[test]
    fn live_session_policy_rejects_runtime_membership_in_migration_role() {
        let migration = validate_external_pg_session(
            least_privilege_probe("olympus_migrator", true),
            &expected_session("olympus_migrator"),
            ExternalPgSessionKind::Migration,
        )
        .expect("migration session");
        let runtime = validate_external_pg_session(
            least_privilege_probe("olympus_runtime", false),
            &expected_session("olympus_runtime"),
            ExternalPgSessionKind::Runtime,
        )
        .expect("runtime session");

        assert_session_policy_error(
            validate_external_pg_session_pair(&migration, &runtime, true, false),
            "the runtime role must not be a member of the migration role",
        );
    }

    #[test]
    fn live_session_policy_errors_never_echo_observed_values() {
        let expected = expected_session("olympus_runtime");
        let mut probe = least_privilege_probe("observed-secret-role", false);
        probe.current_database = "observed-secret-database".to_owned();
        probe.current_schema = Some("observed-secret-schema".to_owned());
        let error = validate_external_pg_session(probe, &expected, ExternalPgSessionKind::Runtime)
            .expect_err("mismatched live identity");
        let rendered = error.to_string();

        assert!(!rendered.contains("observed-secret-role"));
        assert!(!rendered.contains("observed-secret-database"));
        assert!(!rendered.contains("observed-secret-schema"));
    }

    #[test]
    fn external_database_configuration_errors_do_not_echo_credentials() {
        let secret_url =
            "postgresql://olympus_runtime:must-never-appear@db.example.com/olympus?sslmode=bogus";
        let error = match external_pg_connection_plan(secret_url, None, false, true) {
            Err(error) => error,
            Ok(_) => panic!("malformed external database URL unexpectedly accepted"),
        };
        let rendered = error.to_string();

        assert!(!rendered.contains(secret_url));
        assert!(!rendered.contains("must-never-appear"));
        assert!(!rendered.contains("postgresql://"));
        assert!(rendered.contains("DATABASE_URL"));
    }

    #[test]
    fn unsupported_query_parameter_values_never_reach_tracing() {
        let captured = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(captured.clone())
            .finish();
        let secret_url = "postgresql://olympus_runtime:url-password-secret@db.example.com/olympus?sslmode=verify-full&options%5Brole%5D=query-parameter-secret";
        let result = tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("external-database-trace-capture-active");
            external_pg_connect_options(secret_url, "DATABASE_URL", true)
        });
        let rendered = String::from_utf8(captured.0.lock().expect("captured log lock").clone())
            .expect("captured logs are UTF-8");

        assert!(rendered.contains("external-database-trace-capture-active"));
        assert!(!rendered.contains("query-parameter-secret"));
        assert!(!rendered.contains("url-password-secret"));
        assert!(!rendered.contains("options"));
        assert_config_error(
            result,
            "DATABASE_URL",
            "contains an unsupported query parameter",
        );
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
