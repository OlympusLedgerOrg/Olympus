//! Factories for PostgreSQL command executors.
//!
//! Each function in [`PgCommand`] constructs an [`AsyncCommandExecutor`] that
//! is ready to run but has not yet been awaited.  Callers obtain the executor,
//! then call [`crate::command_executor::AsyncCommand::execute`] to actually
//! run the command.

use std::ffi::OsString;
use std::path::Path;

use crate::command_executor::{AsyncCommand, AsyncCommandExecutor};
use crate::pg_access::VerifiedExecutable;
use crate::pg_enums::{PgAuthMethod, PgProcessType, PgServerStatus};
use crate::pg_errors::Error;
use crate::pg_errors::Result;

/// Factories for the three PostgreSQL lifecycle commands.
pub struct PgCommand {}

fn initdb_args(
    database_dir: &Path,
    pw_file_path: &Path,
    user: &str,
    auth_method: &PgAuthMethod,
) -> Result<Vec<OsString>> {
    let pw_file_str = pw_file_path.to_str().ok_or(Error::InvalidPgUrl)?;
    let auth_host = match auth_method {
        PgAuthMethod::Plain => "password",
        PgAuthMethod::MD5 => "md5",
        PgAuthMethod::ScramSha256 => "scram-sha-256",
    };
    let db_dir_str = database_dir.to_str().ok_or(Error::InvalidPgUrl)?;
    Ok([
        "-A",
        auth_host,
        "-U",
        user,
        "-E=UTF8",
        "-D",
        db_dir_str,
        &format!("--pwfile={pw_file_str}"),
    ]
    .into_iter()
    .map(OsString::from)
    .collect())
}

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
        // Explicit UTF-8 avoids Windows initdb defaulting to WIN1252.
        let args = initdb_args(database_dir, pw_file_path, user, auth_method)?;

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
        let args = initdb_args(database_dir, pw_file_path, user, auth_method)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initdb_args_preserve_order_and_auth_mapping() {
        let args = initdb_args(
            Path::new("/cluster"),
            Path::new("/secret/password"),
            "olympus",
            &PgAuthMethod::ScramSha256,
        )
        .unwrap();
        assert_eq!(
            args,
            [
                "-A",
                "scram-sha-256",
                "-U",
                "olympus",
                "-E=UTF8",
                "-D",
                "/cluster",
                "--pwfile=/secret/password",
            ]
            .map(OsString::from)
        );
    }
}
