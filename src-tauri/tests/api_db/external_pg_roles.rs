// SPDX-License-Identifier: Apache-2.0

//! Live PostgreSQL coverage for the external migration/runtime role boundary.
//!
//! This provisions a dedicated database with a neutral NOLOGIN owner, isolated
//! non-superuser migration/runtime roles, and a migration-owned application
//! schema, then drives the production `connect_external` lifecycle over real
//! sockets. It verifies the maintenance boundary, exact release DML matrix,
//! catalog inventory, and fail-closed upgrade recovery.

use std::ffi::OsString;

use crate::common;
use axum::extract::State;
use olympus_tauri_lib::db::connect_external;
use olympus_tauri_lib::routes::public_stats::get_public_stats;
use olympus_tauri_lib::state::AppState;
use sqlx::postgres::PgPoolOptions;
use sqlx::Connection;

static EXTERNAL_DATABASE_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct ExternalDatabaseEnvRestore {
    values: Vec<(&'static str, Option<OsString>)>,
}

impl ExternalDatabaseEnvRestore {
    fn capture(names: &[&'static str]) -> Self {
        Self {
            values: names
                .iter()
                .map(|name| (*name, std::env::var_os(name)))
                .collect(),
        }
    }
}

impl Drop for ExternalDatabaseEnvRestore {
    fn drop(&mut self) {
        for (name, value) in self.values.drain(..) {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn role_url(base: &str, role: &str, password: &str) -> String {
    let mut url = url::Url::parse(base).expect("embedded PostgreSQL fixture URL");
    url.set_username(role)
        .expect("fixture role is URL-compatible");
    url.set_password(Some(password))
        .expect("fixture password is URL-compatible");
    url.set_query(Some("sslmode=disable"));
    url.to_string()
}

fn fixture_password() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

async fn create_fixture_login_role(pool: &sqlx::PgPool, role: &str, password: &str) {
    assert!(
        role.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
        "fixture role must be a simple trusted identifier"
    );
    let statement = format!(
        "CREATE ROLE {role} WITH LOGIN PASSWORD '{password}' \
         NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
    );
    sqlx::query(&statement)
        .execute(pool)
        .await
        .unwrap_or_else(|_| panic!("external-role login provisioning failed"));
}

fn assert_insufficient_privilege(error: sqlx::Error, operation: &str) {
    let code = error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .map(|code| code.into_owned());
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "{operation} must fail with insufficient_privilege"
    );
}

#[tokio::test]
async fn external_role_lifecycle_attests_real_sessions_and_tears_down_migrator() {
    let _env_lock = EXTERNAL_DATABASE_ENV_LOCK.lock().await;
    let _restore = ExternalDatabaseEnvRestore::capture(&[
        "OLYMPUS_DATABASE_MIGRATION_URL",
        "OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL",
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
        "PGOPTIONS",
    ]);
    std::env::remove_var("OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL");
    for variable in [
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
        "PGOPTIONS",
    ] {
        std::env::remove_var(variable);
    }

    let harness = common::boot().await;
    let cluster_admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&harness.database_url)
        .await
        .unwrap_or_else(|_| panic!("external-role fixture admin connection failed"));

    let migration_password = fixture_password();
    let runtime_password = fixture_password();
    for statement in [
        "CREATE ROLE olympus_attest_owner WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
    ] {
        sqlx::query(statement)
            .execute(&cluster_admin)
            .await
            .unwrap_or_else(|_| panic!("external-role cluster provisioning failed"));
    }
    create_fixture_login_role(
        &cluster_admin,
        "olympus_attest_migrator",
        &migration_password,
    )
    .await;
    create_fixture_login_role(&cluster_admin, "olympus_attest_runtime", &runtime_password).await;
    for statement in [
        "CREATE DATABASE olympus_attest_roles OWNER olympus_attest_owner",
        "REVOKE ALL PRIVILEGES ON DATABASE olympus_attest_roles FROM PUBLIC",
        "GRANT CONNECT ON DATABASE olympus_attest_roles TO olympus_attest_migrator WITH GRANT OPTION",
        "REVOKE CREATE, TEMPORARY ON DATABASE olympus_attest_roles FROM olympus_attest_migrator, olympus_attest_runtime",
        "ALTER ROLE olympus_attest_migrator IN DATABASE olympus_attest_roles SET search_path TO olympus_attest",
        "ALTER ROLE olympus_attest_runtime IN DATABASE olympus_attest_roles SET search_path TO olympus_attest",
    ] {
        sqlx::query(statement)
            .execute(&cluster_admin)
            .await
            .unwrap_or_else(|_| panic!("external-role cluster provisioning failed"));
    }

    let mut app_admin_url =
        url::Url::parse(&harness.database_url).expect("parse cluster admin URL");
    app_admin_url.set_path("/olympus_attest_roles");
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(app_admin_url.as_str())
        .await
        .expect("connect dedicated external-role database");
    for statement in [
        "REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC",
        "CREATE SCHEMA olympus_attest AUTHORIZATION olympus_attest_migrator",
        "REVOKE ALL PRIVILEGES ON SCHEMA olympus_attest FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner REVOKE ALL PRIVILEGES ON SCHEMAS FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner IN SCHEMA public REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner IN SCHEMA public REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner IN SCHEMA public REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner IN SCHEMA public REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner IN SCHEMA olympus_attest REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner IN SCHEMA olympus_attest REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner IN SCHEMA olympus_attest REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_attest_owner IN SCHEMA olympus_attest REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC",
    ] {
        sqlx::query(statement)
            .execute(&admin_pool)
            .await
            .unwrap_or_else(|_| panic!("external-role fixture provisioning failed"));
    }

    let migration_url = role_url(
        app_admin_url.as_str(),
        "olympus_attest_migrator",
        &migration_password,
    );
    let runtime_url = role_url(
        app_admin_url.as_str(),
        "olympus_attest_runtime",
        &runtime_password,
    );
    std::env::set_var("OLYMPUS_DATABASE_MIGRATION_URL", &migration_url);

    let runtime_pool = connect_external(&runtime_url)
        .await
        .expect("live external role policy should accept the fixture");

    let migrations_before_second_start: Vec<(i64, Vec<u8>, bool)> = sqlx::query_as(
        "SELECT version, checksum, success \
         FROM olympus_attest._sqlx_migrations \
         ORDER BY version",
    )
    .fetch_all(&admin_pool)
    .await
    .expect("snapshot migration metadata before competing startup");
    assert!(
        connect_external(&runtime_url).await.is_none(),
        "a second starter must fail on the exclusive lifecycle lock before maintenance"
    );
    let migrations_after_second_start: Vec<(i64, Vec<u8>, bool)> = sqlx::query_as(
        "SELECT version, checksum, success \
         FROM olympus_attest._sqlx_migrations \
         ORDER BY version",
    )
    .fetch_all(&admin_pool)
    .await
    .expect("snapshot migration metadata after competing startup");
    assert_eq!(
        migrations_after_second_start, migrations_before_second_start,
        "the rejected starter must not execute or rewrite migration metadata"
    );
    let runtime_connect_survived: bool = sqlx::query_scalar(
        "SELECT pg_catalog.has_database_privilege(\
             'olympus_attest_runtime', \
             current_database(), \
             'CONNECT'\
         )",
    )
    .fetch_one(&admin_pool)
    .await
    .expect("attest runtime CONNECT after competing startup");
    assert!(
        runtime_connect_survived,
        "the rejected starter must not revoke the healthy instance's CONNECT"
    );
    let first_instance_still_healthy: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&runtime_pool)
        .await
        .expect("the first runtime pool must remain usable after a competing startup");
    assert_eq!(first_instance_still_healthy, 1);

    let mut runtime_connection = runtime_pool
        .acquire()
        .await
        .expect("hold one already-attested runtime connection");
    let live: (String, String, String) =
        sqlx::query_as("SELECT session_user::text, current_user::text, current_schema()::text")
            .fetch_one(&mut *runtime_connection)
            .await
            .expect("read attested runtime identity");
    assert_eq!(
        live,
        (
            "olympus_attest_runtime".to_owned(),
            "olympus_attest_runtime".to_owned(),
            "olympus_attest".to_owned(),
        )
    );

    let runtime_authority: (bool, bool) = sqlx::query_as(
        "SELECT \
             pg_catalog.has_schema_privilege(current_user, 'olympus_attest', 'CREATE'), \
             pg_catalog.pg_has_role(\
                 current_user::text, \
                 'olympus_attest_migrator'::text, \
                 'MEMBER'\
             )",
    )
    .fetch_one(&mut *runtime_connection)
    .await
    .expect("read runtime DDL and membership policy");
    assert_eq!(runtime_authority, (false, false));

    let migration_sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_catalog.pg_stat_activity \
         WHERE usename = 'olympus_attest_migrator'",
    )
    .fetch_one(&admin_pool)
    .await
    .expect("count live migration sessions");
    assert_eq!(
        migration_sessions, 0,
        "migration maintenance connection must be closed before runtime is returned"
    );

    let migrations_owner: String = sqlx::query_scalar(
        "SELECT owner_role.rolname::text \
         FROM pg_catalog.pg_class AS relation \
         JOIN pg_catalog.pg_namespace AS namespace \
           ON namespace.oid = relation.relnamespace \
         JOIN pg_catalog.pg_roles AS owner_role \
           ON owner_role.oid = relation.relowner \
         WHERE namespace.nspname = 'olympus_attest' \
           AND relation.relname = '_sqlx_migrations'",
    )
    .fetch_one(&admin_pool)
    .await
    .expect("read migration-table owner");
    assert_eq!(migrations_owner, "olympus_attest_migrator");

    // Exercise every DML class present in the release matrix on representative
    // objects. The transaction is rolled back so the shared fixture remains
    // unchanged.
    let mut dml = runtime_connection
        .begin()
        .await
        .expect("begin runtime DML probe");
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, role, plan) \
         VALUES ('runtime-acl-user', 'runtime-acl@example.invalid', NULL, 'user', 'free')",
    )
    .execute(&mut *dml)
    .await
    .expect("runtime INSERT grant");
    let inserted_role: String =
        sqlx::query_scalar("SELECT role FROM users WHERE id = 'runtime-acl-user'")
            .fetch_one(&mut *dml)
            .await
            .expect("runtime SELECT grant");
    assert_eq!(inserted_role, "user");
    sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'runtime-acl-user'")
        .execute(&mut *dml)
        .await
        .expect("runtime column-scoped UPDATE grant");
    sqlx::query(
        "INSERT INTO signed_request_nonces \
         (key_id, nonce, operator_id, scope, request_digest, expires_at) \
         VALUES ('runtime-acl-key', 'runtime-acl-nonce', 'runtime-acl-operator', \
                 'admin', decode(repeat('00', 32), 'hex'), NOW() + INTERVAL '1 minute') \
         ON CONFLICT (key_id, nonce) DO NOTHING",
    )
    .execute(&mut *dml)
    .await
    .expect("insert-only replay-cache grant");
    let nonce_expiry: chrono::NaiveDateTime = sqlx::query_scalar(
        "SELECT expires_at FROM signed_request_nonces \
         WHERE key_id = 'runtime-acl-key' AND nonce = 'runtime-acl-nonce'",
    )
    .fetch_one(&mut *dml)
    .await
    .expect("predicate columns have exact SELECT grants");
    assert!(nonce_expiry > chrono::Utc::now().naive_utc());
    sqlx::query(
        "DELETE FROM signed_request_nonces \
         WHERE key_id = 'runtime-acl-key' AND nonce = 'runtime-acl-nonce'",
    )
    .execute(&mut *dml)
    .await
    .expect("delete replay-cache grant");
    sqlx::query("DELETE FROM users WHERE id = 'runtime-acl-user'")
        .execute(&mut *dml)
        .await
        .expect("runtime DELETE grant");
    dml.rollback().await.expect("rollback runtime DML probe");

    for (sql, operation) in [
        (
            "UPDATE users SET plan = 'pro' WHERE id = 'runtime-acl-user'",
            "immutable users.plan update",
        ),
        (
            "UPDATE doc_commits SET commit_id = commit_id WHERE false",
            "immutable doc_commits evidence update",
        ),
        (
            "UPDATE ingest_records SET content_hash = content_hash WHERE false",
            "immutable ingest identity update",
        ),
        (
            "UPDATE redaction_segment_manifests SET original_root = original_root WHERE false",
            "write-once redaction manifest update",
        ),
    ] {
        let error = sqlx::query(sql)
            .execute(&mut *runtime_connection)
            .await
            .expect_err(operation);
        assert_insufficient_privilege(error, operation);
    }

    let denied_select = sqlx::query("SELECT * FROM signed_request_nonces LIMIT 1")
        .execute(&mut *runtime_connection)
        .await
        .expect_err("replay cache intentionally has no runtime SELECT grant");
    assert_insufficient_privilege(denied_select, "unlisted table operation");

    let denied_update = sqlx::query("UPDATE operators SET label = label")
        .execute(&mut *runtime_connection)
        .await
        .expect_err("operators intentionally has no runtime UPDATE grant");
    assert_insufficient_privilege(denied_update, "unlisted table DML");

    let denied_migration_metadata = sqlx::query("SELECT * FROM _sqlx_migrations LIMIT 1")
        .execute(&mut *runtime_connection)
        .await
        .expect_err("runtime must not read migration metadata");
    assert_insufficient_privilege(denied_migration_metadata, "migration metadata access");

    let denied_ddl = sqlx::query("CREATE TABLE runtime_must_not_create (id INTEGER)")
        .execute(&mut *runtime_connection)
        .await
        .expect_err("runtime DDL must fail");
    assert_insufficient_privilege(denied_ddl, "runtime DDL");

    let denied_temp_ddl = sqlx::query("CREATE TEMP TABLE runtime_must_not_temp (id INTEGER)")
        .execute(&mut *runtime_connection)
        .await
        .expect_err("runtime TEMPORARY privilege must be absent");
    assert_insufficient_privilege(denied_temp_ddl, "runtime temporary DDL");

    let denied_public_ddl =
        sqlx::query("CREATE TABLE public.runtime_must_not_create_off_path (id INTEGER)")
            .execute(&mut *runtime_connection)
            .await
            .expect_err("runtime off-path schema DDL must fail");
    assert_insufficient_privilege(denied_public_ddl, "runtime off-path DDL");

    let denied_role_switch = sqlx::query("SET ROLE olympus_attest_migrator")
        .execute(&mut *runtime_connection)
        .await
        .expect_err("runtime must not assume the migration role");
    assert_insufficient_privilege(denied_role_switch, "migration-role switching");

    let runtime_owned_objects: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) \
         FROM pg_catalog.pg_class AS relation \
         JOIN pg_catalog.pg_namespace AS namespace \
           ON namespace.oid = relation.relnamespace \
         JOIN pg_catalog.pg_roles AS owner_role \
           ON owner_role.oid = relation.relowner \
         WHERE namespace.nspname = 'olympus_attest' \
           AND owner_role.rolname = 'olympus_attest_runtime'",
    )
    .fetch_one(&admin_pool)
    .await
    .expect("count runtime-owned objects");
    assert_eq!(runtime_owned_objects, 0);

    let public_database_privileges: (bool, bool) = sqlx::query_as(
        "SELECT \
             EXISTS ( \
                 SELECT 1 \
                 FROM pg_catalog.pg_database database \
                 CROSS JOIN LATERAL pg_catalog.aclexplode( \
                     COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba)) \
                 ) acl \
                 WHERE database.datname = current_database() \
                   AND acl.grantee = 0 AND acl.privilege_type = 'CONNECT' \
             ), \
             EXISTS ( \
                 SELECT 1 \
                 FROM pg_catalog.pg_database database \
                 CROSS JOIN LATERAL pg_catalog.aclexplode( \
                     COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba)) \
                 ) acl \
                 WHERE database.datname = current_database() \
                   AND acl.grantee = 0 AND acl.privilege_type = 'TEMPORARY' \
             )",
    )
    .fetch_one(&admin_pool)
    .await
    .expect("read PUBLIC database privilege policy");
    assert_eq!(public_database_privileges, (false, false));

    let runtime_grant_options: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM pg_catalog.pg_class relation \
             JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace \
             CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) acl \
             WHERE namespace.nspname = 'olympus_attest' \
               AND acl.grantee = 'olympus_attest_runtime'::regrole \
               AND acl.is_grantable \
         ) OR EXISTS ( \
             SELECT 1 FROM pg_catalog.pg_attribute attribute \
             CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) acl \
             WHERE acl.grantee = 'olympus_attest_runtime'::regrole \
               AND acl.is_grantable \
         )",
    )
    .fetch_one(&admin_pool)
    .await
    .expect("attest absence of runtime grant options");
    assert!(!runtime_grant_options);

    // Corrupt one idle session setting, then prove the checkout hook discards
    // it and returns a newly attested connection with the exact literal path.
    let stale_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *runtime_connection)
        .await
        .expect("read runtime backend pid");
    sqlx::query("SET search_path TO pg_catalog")
        .execute(&mut *runtime_connection)
        .await
        .expect("simulate pooled session drift");
    drop(runtime_connection);
    let mut runtime_connection = runtime_pool
        .acquire()
        .await
        .expect("checkout should replace the drifted connection");
    let (fresh_backend, fresh_path): (i32, String) =
        sqlx::query_as("SELECT pg_backend_pid(), current_setting('search_path')")
            .fetch_one(&mut *runtime_connection)
            .await
            .expect("read replacement runtime session");
    assert_ne!(fresh_backend, stale_backend);
    assert_eq!(fresh_path, "olympus_attest");

    // The endpoint's information_schema guards must follow the attested custom
    // schema rather than accidentally inspecting public. Seed a committed
    // shard only in that schema so the assertion distinguishes the two paths.
    sqlx::query(
        "INSERT INTO doc_commits \
             (id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id, \
              merkle_root, zk_proof, is_multi_recipient) \
         VALUES ('custom-schema-stats', NULL, repeat('b', 64), '0xcustomstats', \
                 NOW(), 'custom-stats', NULL, NULL, FALSE)",
    )
    .execute(&mut *runtime_connection)
    .await
    .expect("seed custom-schema public statistics");
    let stats = get_public_stats(State(AppState::new(Some(runtime_pool.clone()))))
        .await
        .expect("public stats must work under a non-public application schema")
        .0;
    assert_eq!(stats.shards, 1);

    drop(runtime_connection);
    runtime_pool.close().await;
    admin_pool.close().await;
    cluster_admin.close().await;
}

#[tokio::test]
async fn external_role_upgrade_retains_populated_public_schema_ledger() {
    let _env_lock = EXTERNAL_DATABASE_ENV_LOCK.lock().await;
    let _restore = ExternalDatabaseEnvRestore::capture(&[
        "OLYMPUS_DATABASE_MIGRATION_URL",
        "OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL",
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
        "PGOPTIONS",
    ]);
    std::env::remove_var("OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL");
    for variable in [
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
        "PGOPTIONS",
    ] {
        std::env::remove_var(variable);
    }

    let harness = common::boot().await;
    let cluster_admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&harness.database_url)
        .await
        .expect("connect cluster admin");
    let migration_password = fixture_password();
    let runtime_password = fixture_password();
    for statement in [
        "CREATE ROLE olympus_upgrade_owner WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
        "CREATE ROLE olympus_upgrade_stale WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
    ] {
        sqlx::query(statement)
            .execute(&cluster_admin)
            .await
            .expect("provision upgrade database boundary");
    }
    create_fixture_login_role(
        &cluster_admin,
        "olympus_upgrade_migrator",
        &migration_password,
    )
    .await;
    create_fixture_login_role(&cluster_admin, "olympus_upgrade_runtime", &runtime_password).await;
    for statement in [
        "CREATE DATABASE olympus_upgrade_roles OWNER olympus_upgrade_migrator",
        "ALTER ROLE olympus_upgrade_migrator IN DATABASE olympus_upgrade_roles SET search_path TO public",
        "ALTER ROLE olympus_upgrade_runtime IN DATABASE olympus_upgrade_roles SET search_path TO public",
    ] {
        sqlx::query(statement)
            .execute(&cluster_admin)
            .await
            .expect("provision upgrade database boundary");
    }

    let mut upgrade_admin_url =
        url::Url::parse(&harness.database_url).expect("parse cluster admin URL");
    upgrade_admin_url.set_path("/olympus_upgrade_roles");
    let upgrade_admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(upgrade_admin_url.as_str())
        .await
        .expect("connect upgrade database admin");

    let migration_url = role_url(
        upgrade_admin_url.as_str(),
        "olympus_upgrade_migrator",
        &migration_password,
    );
    let runtime_url = role_url(
        upgrade_admin_url.as_str(),
        "olympus_upgrade_runtime",
        &runtime_password,
    );

    // Model the deployed single-role layout: migrations and data already live
    // in public before the runtime role is introduced.
    let legacy_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&migration_url)
        .await
        .expect("connect legacy deployment role");
    sqlx::migrate!("../migrations")
        .run(&legacy_pool)
        .await
        .expect("migrate populated legacy public schema");
    sqlx::query(
        "INSERT INTO doc_commits \
             (id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id, \
              merkle_root, zk_proof, is_multi_recipient) \
         VALUES ('upgrade-doc', NULL, repeat('a', 64), '0xupgrade', NOW(), \
                 'files', NULL, NULL, FALSE)",
    )
    .execute(&legacy_pool)
    .await
    .expect("seed pre-split ledger evidence");
    for statement in [
        "CREATE FUNCTION unexpected_upgrade_function() RETURNS INTEGER LANGUAGE SQL IMMUTABLE AS 'SELECT 7'",
        "CREATE INDEX unexpected_upgrade_index ON doc_commits (commit_id)",
        "ALTER TABLE doc_commits ADD CONSTRAINT unexpected_upgrade_constraint CHECK (commit_id <> '')",
        "GRANT SELECT ON doc_commits TO olympus_upgrade_stale",
    ] {
        sqlx::query(statement)
            .execute(&legacy_pool)
            .await
            .expect("inject legacy catalog drift");
    }
    legacy_pool.close().await;

    for statement in [
        "ALTER DATABASE olympus_upgrade_roles OWNER TO olympus_upgrade_owner",
        "REVOKE ALL PRIVILEGES ON DATABASE olympus_upgrade_roles FROM PUBLIC",
        "GRANT CONNECT ON DATABASE olympus_upgrade_roles TO olympus_upgrade_migrator WITH GRANT OPTION",
        "REVOKE ALL PRIVILEGES ON DATABASE olympus_upgrade_roles FROM olympus_upgrade_runtime, olympus_upgrade_stale",
        "REVOKE CREATE, TEMPORARY ON DATABASE olympus_upgrade_roles FROM olympus_upgrade_migrator",
    ] {
        sqlx::query(statement)
            .execute(&cluster_admin)
            .await
            .expect("transfer legacy database to neutral owner");
    }
    for statement in [
        "ALTER SCHEMA public OWNER TO olympus_upgrade_migrator",
        "REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC, olympus_upgrade_runtime, olympus_upgrade_stale",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_upgrade_owner REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_upgrade_owner REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_upgrade_owner REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_upgrade_owner REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_upgrade_owner REVOKE ALL PRIVILEGES ON SCHEMAS FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_upgrade_owner IN SCHEMA public REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_upgrade_owner IN SCHEMA public REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_upgrade_owner IN SCHEMA public REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES FOR ROLE olympus_upgrade_owner IN SCHEMA public REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC",
        "CREATE SCHEMA unexpected_upgrade_schema AUTHORIZATION olympus_upgrade_stale",
    ] {
        sqlx::query(statement)
            .execute(&upgrade_admin_pool)
            .await
            .expect("harden transferred legacy ownership");
    }

    std::env::set_var("OLYMPUS_DATABASE_MIGRATION_URL", &migration_url);
    assert!(
        connect_external(&runtime_url).await.is_none(),
        "an untrusted third-role schema owner must block startup"
    );
    let runtime_can_connect: bool = sqlx::query_scalar(
        "SELECT pg_catalog.has_database_privilege(\
             'olympus_upgrade_runtime', \
             current_database(), \
             'CONNECT'\
         )",
    )
    .fetch_one(&upgrade_admin_pool)
    .await
    .expect("check fail-closed runtime CONNECT");
    assert!(!runtime_can_connect);

    sqlx::query("DROP SCHEMA unexpected_upgrade_schema")
        .execute(&upgrade_admin_pool)
        .await
        .expect("remove rejected third-role schema");
    assert!(
        connect_external(&runtime_url).await.is_none(),
        "unmanifested function, index, and constraint must block startup"
    );
    let post_failure_policy: (bool, bool, bool) = sqlx::query_as(
        "SELECT \
             pg_catalog.has_database_privilege(\
                 'olympus_upgrade_runtime', \
                 current_database(), \
                 'CONNECT'\
             ), \
             pg_catalog.has_function_privilege(\
                 'olympus_upgrade_runtime', \
                 'unexpected_upgrade_function()', \
                 'EXECUTE'\
             ), \
             pg_catalog.has_table_privilege(\
                 'olympus_upgrade_stale', \
                 'doc_commits', \
                 'SELECT'\
             )",
    )
    .fetch_one(&upgrade_admin_pool)
    .await
    .expect("attest fail-closed semantic-drift cleanup");
    assert_eq!(post_failure_policy, (false, false, false));

    let cleanup_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&migration_url)
        .await
        .expect("reconnect migration role for reviewed recovery");
    for statement in [
        "ALTER TABLE doc_commits DROP CONSTRAINT unexpected_upgrade_constraint",
        "DROP INDEX unexpected_upgrade_index",
        "DROP FUNCTION unexpected_upgrade_function()",
    ] {
        sqlx::query(statement)
            .execute(&cleanup_pool)
            .await
            .expect("remove unmanifested legacy object");
    }
    cleanup_pool.close().await;

    let runtime_pool = connect_external(&runtime_url)
        .await
        .expect("reviewed split-role recovery must retain the deployed public schema");

    let retained_commit: String =
        sqlx::query_scalar("SELECT commit_id FROM doc_commits WHERE id = 'upgrade-doc'")
            .fetch_one(&runtime_pool)
            .await
            .expect("read retained pre-split ledger evidence");
    assert_eq!(retained_commit, "0xupgrade");
    let live_schema: String = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(&runtime_pool)
        .await
        .expect("read retained application schema");
    assert_eq!(live_schema, "public");
    let migration_schema: String = sqlx::query_scalar(
        "SELECT namespace.nspname::text \
         FROM pg_catalog.pg_class relation \
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace \
         WHERE relation.relname = '_sqlx_migrations'",
    )
    .fetch_one(&upgrade_admin_pool)
    .await
    .expect("locate retained migration metadata");
    assert_eq!(migration_schema, "public");
    let transferred_owners: (String, String) = sqlx::query_as(
        "SELECT \
             database_owner.rolname::text, \
             schema_owner.rolname::text \
         FROM pg_catalog.pg_database AS database \
         JOIN pg_catalog.pg_roles AS database_owner \
           ON database_owner.oid = database.datdba \
         JOIN pg_catalog.pg_namespace AS namespace \
           ON namespace.nspname = 'public' \
         JOIN pg_catalog.pg_roles AS schema_owner \
           ON schema_owner.oid = namespace.nspowner \
         WHERE database.datname = current_database()",
    )
    .fetch_one(&upgrade_admin_pool)
    .await
    .expect("attest neutral database and migration schema ownership");
    assert_eq!(
        transferred_owners,
        (
            "olympus_upgrade_owner".to_owned(),
            "olympus_upgrade_migrator".to_owned(),
        )
    );
    let forked_schema_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM pg_catalog.pg_namespace \
             WHERE nspname = 'olympus_app' \
         )",
    )
    .fetch_one(&upgrade_admin_pool)
    .await
    .expect("check for accidental schema fork");
    assert!(!forked_schema_exists);

    runtime_pool.close().await;
    upgrade_admin_pool.close().await;
    cluster_admin.close().await;
}
