// SPDX-License-Identifier: Apache-2.0

use super::connection::effective_database;
use sqlx::postgres::{PgConnectOptions, PgConnection};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExternalPgExpectedSession {
    pub(super) username: String,
    pub(super) database: String,
}

impl ExternalPgExpectedSession {
    pub(super) fn from_options(options: &PgConnectOptions) -> Self {
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
pub(super) struct ExternalPgSessionProbe {
    pub(super) server_version_num: i32,
    pub(super) session_user: String,
    pub(super) current_user: String,
    pub(super) current_database: String,
    pub(super) current_schema: Option<String>,
    pub(super) configured_search_path: String,
    pub(super) resolved_search_path: Vec<String>,
    pub(super) search_path_is_exact_literal: bool,
    pub(super) is_superuser: bool,
    pub(super) can_create_role: bool,
    pub(super) can_create_database: bool,
    pub(super) can_replicate: bool,
    pub(super) can_bypass_rls: bool,
    pub(super) has_database_connect: bool,
    pub(super) has_database_create: bool,
    pub(super) has_database_temporary: bool,
    pub(super) has_direct_database_connect: bool,
    pub(super) has_direct_database_connect_grant_option: bool,
    pub(super) public_has_any_database_privilege: bool,
    pub(super) has_current_schema_usage: bool,
    pub(super) has_current_schema_create: bool,
    pub(super) has_direct_current_schema_usage: bool,
    pub(super) current_schema_acl_has_grant_option: bool,
    pub(super) public_has_any_current_schema_privilege: bool,
    pub(super) has_any_off_path_schema_privilege: bool,
    pub(super) public_has_any_off_path_schema_privilege: bool,
    pub(super) public_has_create_on_any_non_system_schema: bool,
    pub(super) has_search_path_schema_create: bool,
    pub(super) owns_database: bool,
    // Probed but not yet asserted: `validate_external_pg_session` gates on
    // `has_current_schema_create`, not ownership. Asserting ownership here is
    // a policy change (docs/external-postgresql-roles.md says the migrator
    // owns the application schema) — tracked as a follow-up, not slipped
    // into a dead-code cleanup.
    #[allow(dead_code)]
    pub(super) owns_current_schema: bool,
    pub(super) owns_search_path_schema: bool,
    pub(super) owns_search_path_objects: bool,
    pub(super) can_assume_any_other_role: bool,
    pub(super) can_assume_dangerous_role: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExternalPgSessionKind {
    Migration,
    Runtime,
    SharedDevelopment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExternalPgSessionAttestation {
    pub(super) session_user: String,
    pub(super) current_database: String,
    pub(super) current_schema: String,
    pub(super) configured_search_path: String,
    pub(super) resolved_search_path: Vec<String>,
}

/// A value-blind policy error suitable for returning through SQLx's
/// `after_connect` hook. Its display text can never contain a URL, role name,
/// database name, schema name, query parameter, or driver error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("external PostgreSQL session policy violation: {reason}")]
pub(super) struct ExternalPgSessionPolicyError {
    pub(super) reason: &'static str,
}

pub(super) fn session_policy_error(reason: &'static str) -> ExternalPgSessionPolicyError {
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

pub(super) fn validate_external_pg_migration_maintenance_authority(
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

pub(super) fn validate_external_pg_session(
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

pub(super) fn validate_external_pg_session_pair(
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

pub(super) async fn probe_external_pg_connection(
    connection: &mut PgConnection,
) -> Result<ExternalPgSessionProbe, sqlx::Error> {
    sqlx::query_as::<_, ExternalPgSessionProbe>(EXTERNAL_PG_SESSION_PROBE_SQL)
        .fetch_one(&mut *connection)
        .await
}

pub(super) async fn runtime_is_member_of_migration_role(
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
