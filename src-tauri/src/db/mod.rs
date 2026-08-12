// SPDX-License-Identifier: Apache-2.0

mod embedded;
mod external;
mod process_identity;

// Consumed only by the bin target (`window_events.rs`), which re-includes
// this module tree — unused on the lib target by construction.
#[allow(unused_imports)]
pub(crate) use embedded::confirm_and_disarm_embedded_postgres_reaper;
pub use embedded::{init_embedded, reap_embedded_pg, EmbeddedDb};
pub use external::connect_external;

pub(crate) const MIGRATION_DATABASE_URL_ENV: &str = "OLYMPUS_DATABASE_MIGRATION_URL";

pub(crate) const DEV_ALLOW_SINGLE_DATABASE_URL_ENV: &str = "OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL";

pub(crate) const PGOPTIONS_ENV: &str = "PGOPTIONS";

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

