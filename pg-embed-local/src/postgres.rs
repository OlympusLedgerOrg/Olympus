//! Public API for embedding and managing a PostgreSQL server.
//!
//! The entry point is [`PgEmbed`].  A typical usage sequence is:
//!
//! ```rust,no_run
//! use pg_embed::postgres::{PgEmbed, PgSettings};
//! use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
//! use pg_embed::pg_enums::PgAuthMethod;
//! use std::path::PathBuf;
//! use std::time::Duration;
//!
//! # #[tokio::main]
//! # async fn main() -> pg_embed::pg_errors::Result<()> {
//! let pg_settings = PgSettings {
//!     database_dir: PathBuf::from("data/db"),
//!     port: 5432,
//!     user: "postgres".to_string(),
//!     password: "password".to_string(),
//!     auth_method: PgAuthMethod::Plain,
//!     persistent: false,
//!     timeout: Some(Duration::from_secs(15)),
//!     migration_dir: None,
//! };
//!
//! let fetch_settings = PgFetchSettings { version: PG_V15, ..Default::default() };
//!
//! let mut pg = PgEmbed::new(pg_settings, fetch_settings).await?;
//! pg.setup().await?;
//! pg.start_db().await?;
//!
//! let uri = pg.full_db_uri("mydb");   // postgres://postgres:password@localhost:5432/mydb
//!
//! pg.stop_db().await?;
//! # Ok(())
//! # }
//! ```

use std::ffi::{OsStr, OsString};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

#[cfg(feature = "rt_tokio_migrate")]
use sqlx::Postgres;
#[cfg(feature = "rt_tokio_migrate")]
use sqlx::migrate::{MigrateDatabase, Migrator};
#[cfg(feature = "rt_tokio_migrate")]
use sqlx::postgres::PgPoolOptions;

use crate::command_executor::AsyncCommand;
use crate::pg_access::{AuthenticatedPostgresExecutables, PgAccess};
use crate::pg_commands::PgCommand;
use crate::pg_enums::{PgAuthMethod, PgServerStatus};
use crate::pg_errors::Error;
use crate::pg_errors::Result;
use crate::pg_fetch;
use crate::process::{PostgresProcess, ProcessKind};

const MAX_POSTMASTER_PID_BYTES: u64 = 4096;

async fn wait_for_postgres_ready(
    process: &PostgresProcess,
    data_dir: &Path,
    port: u16,
    timeout: Option<Duration>,
) -> Result<()> {
    let started = std::time::Instant::now();
    let pidfile = data_dir.join("postmaster.pid");
    loop {
        if process.has_exited()? {
            return Err(Error::PgStartFailure);
        }
        match ready_pidfile_matches(&pidfile, process.pid(), data_dir, port) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => {
                return Err(Error::PgError(
                    error.to_string(),
                    "validating retained PostgreSQL payload pidfile".to_owned(),
                ));
            }
        }
        if timeout.is_some_and(|limit| started.elapsed() >= limit) {
            return Err(Error::PgTimedOutError);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn ready_pidfile_matches(
    pidfile: &Path,
    expected_pid: u32,
    expected_data_dir: &Path,
    expected_port: u16,
) -> std::io::Result<bool> {
    use std::io::Read;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match options.open(pidfile) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_POSTMASTER_PID_BYTES
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "postmaster.pid is not a bounded regular file",
        ));
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "postmaster.pid is a reparse point",
            ));
        }
    }
    let mut content = String::new();
    file.take(MAX_POSTMASTER_PID_BYTES + 1)
        .read_to_string(&mut content)?;
    if content.len() as u64 > MAX_POSTMASTER_PID_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "postmaster.pid exceeds the size bound",
        ));
    }
    let mut lines = content.lines();
    let Some(pid) = lines
        .next()
        .and_then(|line| line.trim().parse::<u32>().ok())
    else {
        return Ok(false);
    };
    let Some(data_dir) = lines
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(false);
    };
    let Some(_start_time) = lines
        .next()
        .and_then(|line| line.trim().parse::<u64>().ok())
        .filter(|value| *value != 0)
    else {
        return Ok(false);
    };
    let Some(port) = lines
        .next()
        .and_then(|line| line.trim().parse::<u16>().ok())
        .filter(|value| *value != 0)
    else {
        return Ok(false);
    };
    for _ in 0..3 {
        if lines.next().is_none() {
            return Ok(false);
        }
    }
    let Some(status) = lines.next().map(str::trim) else {
        return Ok(false);
    };
    if status != "ready" {
        return Ok(false);
    }
    if lines.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "postmaster.pid has unexpected trailing fields",
        ));
    }
    let observed_data_dir = std::fs::canonicalize(data_dir)?;
    let expected_data_dir = std::fs::canonicalize(expected_data_dir)?;
    if pid != expected_pid || observed_data_dir != expected_data_dir || port != expected_port {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "postmaster.pid does not identify the retained PostgreSQL payload",
        ));
    }
    Ok(true)
}

/// Configuration for a single embedded PostgreSQL instance.
pub struct PgSettings {
    /// Directory that will hold the PostgreSQL cluster data files.
    ///
    /// Created automatically if it does not exist. When [`Self::persistent`]
    /// is `false` this directory (and [`Self::database_dir`] with a `.pwfile`
    /// extension) is removed after a confirmed stop or when no start was
    /// attempted.
    pub database_dir: PathBuf,

    /// TCP port PostgreSQL will listen on.
    pub port: u16,

    /// Name of the initial database superuser.
    pub user: String,

    /// Password for the superuser, written to a temporary password file and
    /// passed to `initdb` via `--pwfile`.
    pub password: String,

    /// Authentication method written to `pg_hba.conf` by `initdb`.
    pub auth_method: PgAuthMethod,

    /// If `false`, the cluster directory and password file are deleted after
    /// a confirmed stop or when no start was attempted. Set to `true` to keep
    /// the data across runs.
    pub persistent: bool,

    /// Maximum time to wait for `initdb`, direct PostgreSQL startup, and
    /// exact-process shutdown to complete.
    ///
    /// `None` disables the timeout (the process is waited on indefinitely).
    /// Exceeding the timeout returns [`Error::PgTimedOutError`].
    pub timeout: Option<Duration>,

    /// Directory containing `.sql` migration files.
    ///
    /// When `Some`, [`PgEmbed::migrate`] will run all migrations found in
    /// this directory via sqlx.  `None` disables migrations.
    /// Requires the `rt_tokio_migrate` feature.
    pub migration_dir: Option<PathBuf>,
}

/// An embedded PostgreSQL server with full lifecycle management.
///
/// PostgreSQL is launched inside a parent-tied private process tree and
/// immediately converted into a sealed capability. Dropping a live
/// [`PgEmbed`] gracefully signals the retained postmaster, force-terminates the
/// tree if needed, and waits for every member; neither explicit shutdown nor
/// unwinding invokes `pg_ctl` or reconstructs authority from `postmaster.pid`.
pub struct PgEmbed {
    /// Active configuration for this instance.
    pub pg_settings: PgSettings,
    /// Binary download settings used during [`Self::setup`].
    pub fetch_settings: pg_fetch::PgFetchSettings,
    /// Base connection URI: `postgres://{user}:{password}@localhost:{port}`.
    pub db_uri: String,
    /// Current server lifecycle state, protected by an async mutex so it can
    /// be observed from concurrent tasks.
    pub server_status: Arc<Mutex<PgServerStatus>>,
    /// Compatibility flag retained from pg-embed 1.0.
    ///
    /// Exact-process cleanup never trusts this caller-writable flag as
    /// authority to skip shutdown.
    pub shutting_down: bool,
    /// File-system paths and I/O helpers for this instance.
    pub pg_access: PgAccess,
    process_lifecycle: PgProcessLifecycle,
    process: Option<PostgresProcess>,
    executables: Arc<Mutex<Option<AuthenticatedPostgresExecutables>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PgProcessLifecycle {
    NeverStarted,
    /// This instance owns a sealed exact-process capability.
    Running,
    /// Exact-process exit was confirmed.
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DropAction {
    CleanNonPersistentFiles,
    TerminateRetainedProcess,
}

impl Drop for PgEmbed {
    fn drop(&mut self) {
        if self.drop_action() == DropAction::TerminateRetainedProcess {
            let terminated = self
                .process
                .as_ref()
                .is_some_and(|process| process.terminate(self.pg_settings.timeout).is_ok());
            if terminated {
                self.process_lifecycle = PgProcessLifecycle::Stopped;
                self.process = None;
            } else {
                log::error!(
                    "exact-process PostgreSQL shutdown failed during drop; preserving cluster files"
                );
                return;
            }
        }
        if !self.pg_settings.persistent {
            if let Err(error) = self.pg_access.clean() {
                log::warn!("cleanup failed during drop: {error}");
            }
        }
    }
}

impl PgEmbed {
    /// Creates a new [`PgEmbed`] instance and prepares the directory structure.
    ///
    /// Does **not** download binaries or start the server.  Call
    /// [`Self::setup`] followed by [`Self::start_db`] to bring the server up.
    ///
    /// # Arguments
    ///
    /// * `pg_settings` — Server configuration (port, auth, directories, …).
    /// * `fetch_settings` — Which PostgreSQL version/platform to download.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DirCreationError`] if the cache or database directories
    /// cannot be created.
    /// Returns [`Error::InvalidPgUrl`] if the OS cache directory is
    /// unavailable.
    pub async fn new(
        pg_settings: PgSettings,
        fetch_settings: pg_fetch::PgFetchSettings,
    ) -> Result<Self> {
        let db_uri = format!(
            "postgres://{}:{}@localhost:{}",
            &pg_settings.user, &pg_settings.password, pg_settings.port
        );
        let pg_access = PgAccess::new(&fetch_settings, &pg_settings.database_dir).await?;
        Ok(PgEmbed {
            pg_settings,
            fetch_settings,
            db_uri,
            server_status: Arc::new(Mutex::new(PgServerStatus::Uninitialized)),
            shutting_down: false,
            pg_access,
            process_lifecycle: PgProcessLifecycle::NeverStarted,
            process: None,
            executables: Arc::new(Mutex::new(None)),
        })
    }

    fn drop_action(&self) -> DropAction {
        Self::drop_action_for(self.process_lifecycle)
    }

    fn drop_action_for(process_lifecycle: PgProcessLifecycle) -> DropAction {
        match process_lifecycle {
            PgProcessLifecycle::NeverStarted | PgProcessLifecycle::Stopped => {
                DropAction::CleanNonPersistentFiles
            }
            PgProcessLifecycle::Running => DropAction::TerminateRetainedProcess,
        }
    }

    async fn retained_executables(&self) -> Result<AuthenticatedPostgresExecutables> {
        if let Some(executables) = self.executables.lock().await.as_ref().cloned() {
            return Ok(executables);
        }
        let authenticated = self
            .pg_access
            .authenticated_postgres_executables()
            .await?
            .ok_or(Error::InvalidPgPackage)?;
        let mut retained = self.executables.lock().await;
        if let Some(existing) = retained.as_ref() {
            Ok(existing.clone())
        } else {
            *retained = Some(authenticated.clone());
            Ok(authenticated)
        }
    }

    /// Return a clone of this instance's sealed exact-process capability.
    ///
    /// The capability can be retained by a panic/exit guard without granting
    /// authority over any process named later by a mutable pidfile.
    pub fn process_capability(&self) -> Option<PostgresProcess> {
        self.process.clone()
    }

    /// Record an exit already confirmed through a clone of
    /// [`Self::process_capability`].
    pub fn mark_process_stopped_externally(&mut self) -> Result<()> {
        if self.process_lifecycle != PgProcessLifecycle::Running {
            return Err(Error::PgError(
                "cannot confirm external PostgreSQL exit without retained-process authority"
                    .to_owned(),
                String::new(),
            ));
        }
        let process = self.process.as_ref().ok_or_else(|| {
            Error::PgError(
                "running PostgreSQL has no retained process capability".to_owned(),
                String::new(),
            )
        })?;
        if !process.has_exited()? {
            return Err(Error::PgError(
                "retained PostgreSQL process is still running".to_owned(),
                String::new(),
            ));
        }
        self.process_lifecycle = PgProcessLifecycle::Stopped;
        self.process = None;
        if let Ok(mut executables) = self.executables.try_lock() {
            *executables = None;
        }
        Ok(())
    }

    /// Downloads the binaries (if needed), writes the password file, and runs
    /// `initdb` (if the cluster does not already exist).
    ///
    /// This method is idempotent: if the binaries are already cached and the
    /// cluster is already initialised it returns immediately after verifying
    /// both.
    ///
    /// # Errors
    ///
    /// Returns any error from [`PgAccess::maybe_acquire_postgres`],
    /// [`PgAccess::create_password_file`], or [`Self::init_db`].
    pub async fn setup(&mut self) -> Result<()> {
        self.pg_access.maybe_acquire_postgres().await?;
        let authenticated = self
            .pg_access
            .authenticated_postgres_executables()
            .await?
            .ok_or(Error::InvalidPgPackage)?;
        *self.executables.lock().await = Some(authenticated);
        self.pg_access
            .create_password_file(self.pg_settings.password.as_bytes())
            .await?;
        if PgAccess::pg_version_file_exists(&self.pg_access.database_dir).await? {
            let mut server_status = self.server_status.lock().await;
            *server_status = PgServerStatus::Initialized;
        } else {
            self.init_db().await?;
        }
        Ok(())
    }

    /// Installs a third-party PostgreSQL extension into the binary cache.
    ///
    /// Must be called **after** [`Self::setup`] (so the cache directory exists)
    /// and **before** [`Self::start_db`] (so the server loads the shared
    /// library on startup).  Once the server is running, activate the extension
    /// in a specific database with:
    ///
    /// ```sql
    /// CREATE EXTENSION IF NOT EXISTS <extension_name>;
    /// ```
    ///
    /// Delegates to [`PgAccess::install_extension`].  See that method for the
    /// file-routing rules (`.so`/`.dylib`/`.dll` → `lib/`;
    /// `.control`/`.sql` → the PostgreSQL share extension directory).
    ///
    /// # Arguments
    ///
    /// * `extension_dir` — Directory containing the pre-compiled extension
    ///   files (shared library + control + SQL scripts).
    ///
    /// # Errors
    ///
    /// Returns [`Error::DirCreationError`] if the target directories cannot be
    /// created.
    /// Returns [`Error::ReadFileError`] if `extension_dir` cannot be read.
    /// Returns [`Error::WriteFileError`] if a file cannot be copied.
    pub async fn install_extension(&self, extension_dir: &Path) -> Result<()> {
        if self.process_lifecycle == PgProcessLifecycle::Running {
            return Err(Error::PgError(
                "refusing to mutate the executable cache while PostgreSQL is running".to_owned(),
                String::new(),
            ));
        }
        // Hold this mutex across the transaction so two compatibility `&self`
        // calls cannot interleave. Taking the bundle releases every shared
        // cache lease before the exclusive staged publish begins.
        let mut retained = self.executables.lock().await;
        let previous = retained.take();
        drop(previous);
        let install = self.pg_access.install_extension(extension_dir).await;
        let refreshed = self.pg_access.authenticated_postgres_executables().await?;
        *retained = refreshed;
        install?;
        retained.as_ref().ok_or(Error::InvalidPgPackage).map(|_| ())
    }

    /// Runs `initdb` to create a new database cluster.
    ///
    /// Updates [`Self::server_status`] to [`PgServerStatus::Initializing`]
    /// before the call and to [`PgServerStatus::Initialized`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPgUrl`] if any path cannot be converted to
    /// UTF-8. Returns [`Error::PgInitFailure`] if `initdb` cannot be
    /// spawned. Returns [`Error::PgTimedOutError`] if the process exceeds
    /// [`PgSettings::timeout`].
    pub async fn init_db(&mut self) -> Result<()> {
        {
            let mut server_status = self.server_status.lock().await;
            *server_status = PgServerStatus::Initializing;
        }

        let initdb = self.retained_executables().await?.initdb;
        let mut executor = PgCommand::init_db_executor_verified(
            &initdb,
            &self.pg_access.database_dir,
            &self.pg_access.pw_file_path,
            &self.pg_settings.user,
            &self.pg_settings.auth_method,
        )?;
        let exit_status = executor.execute(self.pg_settings.timeout).await?;
        let mut server_status = self.server_status.lock().await;
        *server_status = exit_status;
        Ok(())
    }

    /// Starts the authenticated `postgres` executable as the retained payload
    /// of a parent-tied private process tree.
    ///
    /// Updates [`Self::server_status`] to [`PgServerStatus::Starting`] before
    /// the call and to [`PgServerStatus::Started`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PgStartFailure`] if the process exits before publishing
    /// a matching ready pidfile or cannot be spawned.
    /// Returns [`Error::PgTimedOutError`] if the process exceeds
    /// [`PgSettings::timeout`].
    pub async fn start_db(&mut self) -> Result<()> {
        if self.process_lifecycle == PgProcessLifecycle::Running {
            return Err(Error::PgError(
                "refusing to start PostgreSQL while a prior start may still be running".to_owned(),
                String::new(),
            ));
        }
        {
            let mut server_status = self.server_status.lock().await;
            *server_status = PgServerStatus::Starting;
        }

        self.shutting_down = false;
        let postgres = self.retained_executables().await?.postgres;
        let arguments = [
            OsString::from("-D"),
            self.pg_access.database_dir.as_os_str().to_os_string(),
            OsString::from("-F"),
            OsString::from("-p"),
            OsString::from(self.pg_settings.port.to_string()),
        ];
        let process =
            PostgresProcess::spawn_verified(postgres, &arguments, None, ProcessKind::Postgres)?;

        // Store the capability before the first await. Cancellation, panic, or
        // an early return after this point therefore reaches exact-process Drop
        // cleanup instead of leaking an unauthenticated child.
        self.process = Some(process.clone());
        self.process_lifecycle = PgProcessLifecycle::Running;

        let readiness = wait_for_postgres_ready(
            &process,
            &self.pg_access.database_dir,
            self.pg_settings.port,
            self.pg_settings.timeout,
        )
        .await;
        if let Err(error) = readiness {
            if process.terminate_force().is_ok() {
                self.process = None;
                self.process_lifecycle = PgProcessLifecycle::Stopped;
            }
            return Err(error);
        }

        let mut server_status = self.server_status.lock().await;
        *server_status = PgServerStatus::Started;
        Ok(())
    }

    /// Stops the exact retained PostgreSQL process and confirms exit.
    ///
    /// Updates [`Self::server_status`] to [`PgServerStatus::Stopping`] before
    /// the call and to [`PgServerStatus::Stopped`] on success.
    /// # Errors
    ///
    /// Returns [`Error::PgError`] if exact-process signalling or exit
    /// observation fails.
    pub async fn stop_db(&mut self) -> Result<()> {
        self.shutting_down = true;
        match self.process_lifecycle {
            PgProcessLifecycle::NeverStarted | PgProcessLifecycle::Stopped => return Ok(()),
            PgProcessLifecycle::Running => {}
        }
        {
            let mut server_status = self.server_status.lock().await;
            *server_status = PgServerStatus::Stopping;
        }
        let process = self.process.clone().ok_or_else(|| {
            Error::PgError(
                "running PostgreSQL has no retained process capability".to_owned(),
                String::new(),
            )
        })?;
        let timeout = self.pg_settings.timeout;
        tokio::task::spawn_blocking(move || process.terminate(timeout))
            .await
            .map_err(|error| Error::PgTaskJoinError(error.to_string()))??;
        let mut server_status = self.server_status.lock().await;
        *server_status = PgServerStatus::Stopped;
        self.process_lifecycle = PgProcessLifecycle::Stopped;
        self.process = None;
        *self.executables.lock().await = None;
        Ok(())
    }

    /// Stops the PostgreSQL server synchronously.
    ///
    /// This is an explicit shutdown API for callers without an async runtime.
    /// This uses the same exact-process capability as [`Self::stop_db`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::PgError`] if signalling or exit observation fails.
    pub fn stop_db_sync(&mut self) -> Result<()> {
        self.shutting_down = true;
        match self.process_lifecycle {
            PgProcessLifecycle::NeverStarted | PgProcessLifecycle::Stopped => return Ok(()),
            PgProcessLifecycle::Running => {}
        }
        let process = self.process.as_ref().ok_or_else(|| {
            Error::PgError(
                "running PostgreSQL has no retained process capability".to_owned(),
                String::new(),
            )
        })?;
        process.terminate(self.pg_settings.timeout)?;
        self.process_lifecycle = PgProcessLifecycle::Stopped;
        self.process = None;
        if let Ok(mut executables) = self.executables.try_lock() {
            *executables = None;
        }
        Ok(())
    }

    /// Compatibility helper retained from pg-embed 1.0 for callers that own
    /// an unrelated child process with piped output.
    ///
    /// Olympus lifecycle code does not use this method.
    #[deprecated(note = "PostgreSQL lifecycle output is managed by retained process capabilities")]
    pub fn handle_process_io_sync(&self, mut process: std::process::Child) -> Result<()> {
        use std::io::BufRead;

        if let Some(stdout) = process.stdout.take() {
            std::io::BufReader::new(stdout).lines().for_each(|line| {
                if let Ok(line) = line {
                    log::info!("{line}");
                }
            });
        }
        if let Some(stderr) = process.stderr.take() {
            std::io::BufReader::new(stderr).lines().for_each(|line| {
                if let Ok(line) = line {
                    log::error!("{line}");
                }
            });
        }
        Ok(())
    }

    /// Run a bounded PostgreSQL utility mode from the retained authenticated
    /// executable, with caller-provided bytes connected to standard input.
    ///
    /// The command is launched inside the same exact process-tree wrapper as
    /// the server and `initdb`; cancellation therefore cannot orphan a
    /// single-user backend or any descendants.
    pub async fn run_postgres_utility_with_input<I, A>(
        &self,
        args: I,
        input: &[u8],
        timeout: Option<Duration>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
    {
        if self.process_lifecycle == PgProcessLifecycle::Running {
            return Err(Error::PgError(
                "refusing to launch a PostgreSQL utility while the server is running".to_owned(),
                String::new(),
            ));
        }
        let executable = self.retained_executables().await?.postgres;
        let arguments: Vec<OsString> = args
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string())
            .collect();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let input_path = self.pg_access.database_dir.join(format!(
            ".pg-embed-utility-input-{}-{nonce}",
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut input_file = options
            .open(&input_path)
            .map_err(|error| Error::WriteFileError(error.to_string()))?;
        input_file
            .write_all(input)
            .and_then(|()| input_file.sync_all())
            .and_then(|()| input_file.rewind())
            .map_err(|error| Error::WriteFileError(error.to_string()))?;
        struct RemoveInput(PathBuf);
        impl Drop for RemoveInput {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _remove_input = RemoveInput(input_path);

        let process = PostgresProcess::spawn_verified(
            executable,
            &arguments,
            Some(input_file),
            ProcessKind::Utility,
        )?;
        let started = std::time::Instant::now();
        loop {
            if process.has_exited()? {
                let exit = process
                    .wait(Some(Duration::ZERO))?
                    .ok_or(Error::PgProcessError)?;
                return if exit.success() {
                    Ok(())
                } else {
                    Err(Error::PgError(
                        format!("PostgreSQL utility exited with status {:?}", exit.code()),
                        String::new(),
                    ))
                };
            }
            if timeout.is_some_and(|limit| started.elapsed() >= limit) {
                let termination = process.clone();
                tokio::task::spawn_blocking(move || termination.terminate(Some(Duration::ZERO)))
                    .await
                    .map_err(|error| Error::PgTaskJoinError(error.to_string()))??;
                return Err(Error::PgTimedOutError);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Creates a new PostgreSQL database.
    ///
    /// Requires the `rt_tokio_migrate` feature.
    ///
    /// # Arguments
    ///
    /// * `db_name` — Name of the database to create.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PgTaskJoinError`] if the sqlx operation fails.
    #[cfg(feature = "rt_tokio_migrate")]
    pub async fn create_database(&self, db_name: &str) -> Result<()> {
        Postgres::create_database(&self.full_db_uri(db_name))
            .await
            .map_err(|e| Error::PgTaskJoinError(e.to_string()))?;
        Ok(())
    }

    /// Drops a PostgreSQL database if it exists.
    ///
    /// Uses `DROP DATABASE IF EXISTS` semantics: if the database does not
    /// exist the call succeeds silently.
    /// Requires the `rt_tokio_migrate` feature.
    ///
    /// # Arguments
    ///
    /// * `db_name` — Name of the database to drop.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PgTaskJoinError`] if the sqlx operation fails.
    #[cfg(feature = "rt_tokio_migrate")]
    pub async fn drop_database(&self, db_name: &str) -> Result<()> {
        Postgres::drop_database(&self.full_db_uri(db_name))
            .await
            .map_err(|e| Error::PgTaskJoinError(e.to_string()))?;
        Ok(())
    }

    /// Returns `true` if a database named `db_name` exists.
    ///
    /// Requires the `rt_tokio_migrate` feature.
    ///
    /// # Arguments
    ///
    /// * `db_name` — Name of the database to check.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PgTaskJoinError`] if the sqlx operation fails.
    #[cfg(feature = "rt_tokio_migrate")]
    pub async fn database_exists(&self, db_name: &str) -> Result<bool> {
        Postgres::database_exists(&self.full_db_uri(db_name))
            .await
            .map_err(|e| Error::PgTaskJoinError(e.to_string()))
    }

    /// Returns the full connection URI for a specific database.
    ///
    /// Format: `postgres://{user}:{password}@localhost:{port}/{db_name}`.
    ///
    /// # Arguments
    ///
    /// * `db_name` — Database name to append to the base URI.
    pub fn full_db_uri(&self, db_name: &str) -> String {
        format!("{}/{}", &self.db_uri, db_name)
    }

    /// Runs sqlx migrations from [`PgSettings::migration_dir`] against
    /// `db_name`.
    ///
    /// Does nothing if [`PgSettings::migration_dir`] is `None`.
    /// Requires the `rt_tokio_migrate` feature.
    ///
    /// # Arguments
    ///
    /// * `db_name` — Name of the target database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MigrationError`] if the migrator cannot be created or
    /// if a migration fails.
    /// Returns [`Error::SqlQueryError`] if the database connection fails.
    #[cfg(feature = "rt_tokio_migrate")]
    pub async fn migrate(&self, db_name: &str) -> Result<()> {
        if let Some(migration_dir) = &self.pg_settings.migration_dir {
            let m = Migrator::new(migration_dir.as_path())
                .await
                .map_err(|e| Error::MigrationError(e.to_string()))?;
            let pool = PgPoolOptions::new()
                .connect(&self.full_db_uri(db_name))
                .await
                .map_err(|e| Error::SqlQueryError(e.to_string()))?;
            m.run(&pool)
                .await
                .map_err(|e| Error::MigrationError(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn drop_uses_only_retained_process_capabilities() {
        assert_eq!(
            PgEmbed::drop_action_for(PgProcessLifecycle::NeverStarted),
            DropAction::CleanNonPersistentFiles
        );
        assert_eq!(
            PgEmbed::drop_action_for(PgProcessLifecycle::Running),
            DropAction::TerminateRetainedProcess
        );
        assert_eq!(
            PgEmbed::drop_action_for(PgProcessLifecycle::Stopped),
            DropAction::CleanNonPersistentFiles
        );
        // DropAction deliberately has no pg_ctl/path/PID variant.
    }
}
