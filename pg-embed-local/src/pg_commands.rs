//! Factories for PostgreSQL command executors.
//!
//! Each function in [`PgCommand`] constructs an [`AsyncCommandExecutor`] that
//! is ready to run but has not yet been awaited.  Callers obtain the executor,
//! then call [`crate::command_executor::AsyncCommand::execute`] to actually
//! run the command.

use std::path::Path;

use crate::command_executor::{AsyncCommand, AsyncCommandExecutor};
use crate::pg_access::VerifiedExecutable;
use crate::pg_enums::{PgAuthMethod, PgProcessType, PgServerStatus};
use crate::pg_errors::Error;
use crate::pg_errors::Result;

/// Factories for the three PostgreSQL lifecycle commands.
pub struct PgCommand {}

impl PgCommand {
    /// Creates an [`AsyncCommandExecutor`] that runs `initdb` to initialise a
    /// new database cluster.
    ///
    /// # Arguments
    ///
    /// * `init_db_exe` — Path to the `initdb` binary.
    /// * `database_dir` — Target directory for the new cluster.
    /// * `pw_file_path` — Path to the password file created by
    ///   [`crate::pg_access::PgAccess::create_password_file`].
    /// * `user` — Name of the initial superuser.
    /// * `auth_method` — Authentication method written to `pg_hba.conf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPgUrl`] if any of the path arguments cannot be
    /// converted to a UTF-8 string (required for the `--pwfile=` argument
    /// format).
    /// Returns [`Error::PgInitFailure`] if the process cannot be spawned.
    pub fn init_db_executor(
        init_db_exe: &Path,
        database_dir: &Path,
        pw_file_path: &Path,
        user: &str,
        auth_method: &PgAuthMethod,
    ) -> Result<AsyncCommandExecutor<PgServerStatus, Error, PgProcessType>> {
        let pw_file_str = pw_file_path.to_str().ok_or(Error::InvalidPgUrl)?;
        let password_file_arg = format!("--pwfile={}", pw_file_str);
        let auth_host = match auth_method {
            PgAuthMethod::Plain => "password",
            PgAuthMethod::MD5 => "md5",
            PgAuthMethod::ScramSha256 => "scram-sha-256",
        };
        let db_dir_str = database_dir.to_str().ok_or(Error::InvalidPgUrl)?;
        let args = [
            "-A",
            auth_host,
            "-U",
            user,
            // The postgres-tokio driver uses utf8 encoding, however on windows
            // if -E is not specified WIN1252 encoding is chosen by default
            // which can lead to encoding errors like this:
            //
            // ERROR: character with byte sequence 0xe0 0xab 0x87 in encoding
            // "UTF8" has no equivalent in encoding "WIN1252"
            "-E=UTF8",
            "-D",
            db_dir_str,
            &password_file_arg,
        ];

        AsyncCommandExecutor::<PgServerStatus, Error, PgProcessType>::new(
            init_db_exe.as_os_str(),
            args,
            PgProcessType::InitDb,
        )
    }

    pub(crate) fn init_db_executor_verified(
        init_db_exe: &VerifiedExecutable,
        database_dir: &Path,
        pw_file_path: &Path,
        user: &str,
        auth_method: &PgAuthMethod,
    ) -> Result<AsyncCommandExecutor<PgServerStatus, Error, PgProcessType>> {
        let pw_file_str = pw_file_path.to_str().ok_or(Error::InvalidPgUrl)?;
        let password_file_arg = format!("--pwfile={pw_file_str}");
        let auth_host = match auth_method {
            PgAuthMethod::Plain => "password",
            PgAuthMethod::MD5 => "md5",
            PgAuthMethod::ScramSha256 => "scram-sha-256",
        };
        let db_dir_str = database_dir.to_str().ok_or(Error::InvalidPgUrl)?;
        let args = [
            "-A",
            auth_host,
            "-U",
            user,
            "-E=UTF8",
            "-D",
            db_dir_str,
            &password_file_arg,
        ];
        AsyncCommandExecutor::<PgServerStatus, Error, PgProcessType>::from_verified(
            init_db_exe.clone(),
            args,
            PgProcessType::InitDb,
        )
    }

    /// Compatibility constructor retained from pg-embed 1.0.
    ///
    /// Direct lifecycle methods no longer delegate server authority to
    /// `pg_ctl`; callers receive a fail-closed error instead.
    #[deprecated(note = "use PgEmbed::start_db so launch retains exact process-tree authority")]
    pub fn start_db_executor(
        _pg_ctl_exe: &Path,
        _database_dir: &Path,
        _port: &u16,
    ) -> Result<AsyncCommandExecutor<PgServerStatus, Error, PgProcessType>> {
        Err(Error::PgStartFailure)
    }

    /// Compatibility constructor retained from pg-embed 1.0.
    ///
    /// Direct lifecycle methods no longer delegate shutdown authority to
    /// `pg_ctl`; callers receive a fail-closed error instead.
    #[deprecated(note = "use PgEmbed::stop_db so shutdown uses retained tree authority")]
    pub fn stop_db_executor(
        _pg_ctl_exe: &Path,
        _database_dir: &Path,
    ) -> Result<AsyncCommandExecutor<PgServerStatus, Error, PgProcessType>> {
        Err(Error::PgStopFailure)
    }
}
