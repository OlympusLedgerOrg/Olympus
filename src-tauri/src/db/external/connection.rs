use super::super::{
    DbError, DEV_ALLOW_SINGLE_DATABASE_URL_ENV, MIGRATION_DATABASE_URL_ENV, PGOPTIONS_ENV,
};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::path::Path;
use std::str::FromStr;

pub(super) const EXTERNAL_PG_AMBIENT_ENV_VARS: &[&str] = &[
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
pub(super) fn validate_external_pg_ambient_options(
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
pub(super) fn external_pg_connect_options(
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

pub(super) struct ExternalPgConnectionPlan {
    pub(super) migration: PgConnectOptions,
    pub(super) runtime: PgConnectOptions,
    pub(super) shared_development_identity: bool,
}

pub(super) fn effective_database(options: &PgConnectOptions) -> &str {
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

pub(super) fn same_database_target(left: &PgConnectOptions, right: &PgConnectOptions) -> bool {
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
pub(super) fn external_pg_connection_plan(
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
