use super::session::{session_policy_error, ExternalPgSessionPolicyError};
use sqlx::postgres::PgConnection;
use sqlx::Connection;

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
pub(super) struct ExternalPgMaintenanceProbe {
    pub(super) runtime_has_effective_connect: bool,
    pub(super) runtime_active_sessions: i64,
    pub(super) runtime_prepared_transactions: i64,
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

pub(super) async fn set_external_pg_runtime_connect(
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

pub(super) async fn probe_external_pg_maintenance(
    connection: &mut PgConnection,
    runtime_role: &str,
) -> Result<ExternalPgMaintenanceProbe, sqlx::Error> {
    sqlx::query_as::<_, ExternalPgMaintenanceProbe>(EXTERNAL_PG_MAINTENANCE_PROBE_SQL)
        .bind(runtime_role)
        .fetch_one(&mut *connection)
        .await
}

pub(super) fn validate_external_pg_quiescence(
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

pub(super) async fn harden_external_pg_before_migrations(
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
