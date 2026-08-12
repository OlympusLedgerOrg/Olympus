// SPDX-License-Identifier: Apache-2.0

use sqlx::postgres::PgConnection;

/// ASCII `OLYP` in the upper 32 bits of the advisory-lock key. The namespace's
/// top bit is clear, so combining it with any unsigned PostgreSQL database OID
/// produces an exactly reversible, positive signed `bigint`.
pub(super) const EXTERNAL_PG_MAINTENANCE_LOCK_NAMESPACE: i64 = 1_330_403_664;

pub(super) fn external_pg_maintenance_lock_key(database_oid: u32) -> i64 {
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

pub(super) async fn acquire_external_pg_maintenance_lock(connection: &mut PgConnection) -> bool {
    acquire_external_pg_advisory_lock(connection, EXTERNAL_PG_MAINTENANCE_LOCK_SQL).await
}

pub(super) async fn acquire_external_pg_runtime_lock(connection: &mut PgConnection) -> bool {
    acquire_external_pg_advisory_lock(connection, EXTERNAL_PG_RUNTIME_LOCK_SQL).await
}

pub(super) async fn external_pg_runtime_lock_is_held(
    connection: &mut PgConnection,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(EXTERNAL_PG_RUNTIME_LOCK_HELD_SQL)
        .bind(EXTERNAL_PG_MAINTENANCE_LOCK_NAMESPACE)
        .fetch_one(&mut *connection)
        .await
}

pub(super) async fn release_external_pg_maintenance_lock(connection: &mut PgConnection) -> bool {
    sqlx::query_scalar::<_, bool>(EXTERNAL_PG_MAINTENANCE_UNLOCK_SQL)
        .bind(EXTERNAL_PG_MAINTENANCE_LOCK_NAMESPACE)
        .fetch_one(&mut *connection)
        .await
        .unwrap_or(false)
}
