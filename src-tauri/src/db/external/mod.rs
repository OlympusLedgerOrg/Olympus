// SPDX-License-Identifier: Apache-2.0

mod connection;
mod grants;
mod hardening;
mod inventory;
mod locks;
mod session;

use super::{DEV_ALLOW_SINGLE_DATABASE_URL_ENV, MIGRATION_DATABASE_URL_ENV};
use connection::{
    external_pg_connection_plan, validate_external_pg_ambient_options, ExternalPgConnectionPlan,
    EXTERNAL_PG_AMBIENT_ENV_VARS,
};
use grants::{
    probe_external_pg_runtime_privileges, provision_external_pg_runtime_privileges,
    validate_external_pg_runtime_privileges,
};
use hardening::{
    harden_external_pg_before_migrations, probe_external_pg_maintenance,
    set_external_pg_runtime_connect, validate_external_pg_quiescence,
};
use inventory::{
    probe_external_pg_closed_catalog, probe_external_pg_trusted_boundary,
    validate_external_pg_closed_catalog, validate_external_pg_trusted_boundary,
};
use locks::{
    acquire_external_pg_maintenance_lock, acquire_external_pg_runtime_lock,
    external_pg_runtime_lock_is_held, release_external_pg_maintenance_lock,
};
use session::{
    probe_external_pg_connection, runtime_is_member_of_migration_role, session_policy_error,
    validate_external_pg_migration_maintenance_authority, validate_external_pg_session,
    validate_external_pg_session_pair, ExternalPgExpectedSession, ExternalPgSessionAttestation,
    ExternalPgSessionKind, ExternalPgSessionPolicyError,
};
use sqlx::postgres::{PgConnection, PgPoolOptions};
use sqlx::{Connection, PgPool};
use std::time::Duration;

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
///
/// Same-session reacquisition is sound, and deliberately so. PostgreSQL's
/// "a session never conflicts with its own advisory locks" rule excuses only
/// conflicts against locks *this* session holds; a lock held by any **other**
/// session still conflicts, so `pg_try_advisory_lock` here fails whenever
/// another session holds the shared (or exclusive) form. Combined with this
/// session's own shared hold — which no other session can upgrade past — a
/// successful reacquisition is exactly global exclusivity. Issue #1613 item 2
/// proposed replacing this with a separate verification session on the premise
/// that the same-session attempt always succeeds; that premise is false, and
/// acting on it would have required dropping the shared hold first, opening the
/// unlocked interval this design exists to prevent. The semantics are pinned by
/// `handoff_recovery_reacquisition_conflicts_with_other_sessions`.
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
    /// Per-checkout attestation: the shared lifecycle lock and the session
    /// identity/policy boundary.
    ///
    /// These are the properties a *live session* can drift on — a lock dropped
    /// out from under us, a `SET ROLE`/`search_path` change, a role-membership
    /// grant — so they are re-verified on every pool checkout.
    ///
    /// The control-plane half (trusted boundary, closed catalog, privilege
    /// matrix) is deliberately **not** repeated here; see [`Self::attest`].
    async fn attest_session(&self, connection: &mut PgConnection) -> Result<(), sqlx::Error> {
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
        Ok(())
    }

    /// Per-physical-connection attestation: [`Self::attest_session`] plus the
    /// control plane — trusted boundary, closed release catalog (a full
    /// semantic-inventory materialisation), and the four runtime privilege
    /// probes.
    ///
    /// Run from `after_connect` only, i.e. exactly once per physical
    /// connection. It costs seven round trips beyond `attest_session`'s three —
    /// one trusted-boundary probe, two closed-catalog probes (one of which
    /// materialises the whole semantic inventory: measured at ~33 ms warm,
    /// ~320 ms cold on a freshly migrated PostgreSQL 16 database), and four
    /// privilege probes.
    ///
    /// Repeating that on every checkout (as this hook pair originally did) buys
    /// no safety: schema and ACL state can only be mutated while holding the
    /// **exclusive** maintenance lock, and every runtime connection holds the
    /// **shared** form for its whole lifetime. A shared hold in one session
    /// denies an exclusive acquisition in any other — verified against a real
    /// server by `handoff_recovery_reacquisition_conflicts_with_other_sessions`
    /// — so no maintenance mutation can occur while a runtime connection
    /// exists, and that lock hold is exactly what `attest_session` re-proves on
    /// each checkout (issue #1613 item 3).
    async fn attest(&self, connection: &mut PgConnection) -> Result<(), sqlx::Error> {
        self.attest_session(connection).await?;
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
/// connection then acquires that shared lifecycle lock once, on connect. The
/// migration session closes only after the pool has a shared-lock keeper, so
/// there is no unlocked handoff window. Explicit development mode can reuse
/// `DATABASE_URL` only when `OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL=true`.
///
/// Attestation is split by cost and by what can actually drift
/// (`ExternalPgRuntimeAttestationContext`): `after_connect` runs the full
/// attestation once per physical connection — session policy **and** the
/// control plane (trusted boundary, closed catalog, privilege matrix) — while
/// `before_acquire` re-proves the shared lock hold and the session
/// identity/policy boundary on every checkout. The control plane is not
/// re-swept per checkout because mutating it requires the exclusive lock, which
/// cannot be held while any runtime connection holds the shared form.
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
                context.attest_session(connection).await?;
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
    use super::super::DbError;
    use super::connection::*;
    use super::grants::*;
    use super::hardening::*;
    use super::inventory::*;
    use super::locks::*;
    use super::session::*;
    use super::*;
    use sqlx::postgres::PgSslMode;

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

    /// Maintenance helper, not a gate: recomputes the semantic-inventory
    /// digest against an operator-supplied database so the pinned
    /// `EXTERNAL_PG_SEMANTIC_INVENTORY_BLAKE3` constant can be regenerated
    /// after a reviewed migration. Follow the constant's doc comment
    /// protocol: run once against the migration set *without* the new
    /// migration (must reproduce the prior constant exactly), then against
    /// the full set to obtain the new value.
    ///
    /// ```text
    /// OLYMPUS_INVENTORY_REGEN_URL=postgres://user:pass@host/db \
    ///   cargo test -p olympus-desktop --lib \
    ///   regen_semantic_inventory_digest -- --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "maintenance helper — needs OLYMPUS_INVENTORY_REGEN_URL"]
    async fn regen_semantic_inventory_digest() {
        let url = std::env::var("OLYMPUS_INVENTORY_REGEN_URL")
            .expect("set OLYMPUS_INVENTORY_REGEN_URL to the migrated database");
        let pool = sqlx::PgPool::connect(&url).await.expect("connect");
        // Apply the embedded migration set with the same migrator the app
        // uses, so the inventory includes `_sqlx_migrations` exactly as a
        // real deployment's catalog does (psql-applied migrations would come
        // up 9 rows short: that table, its columns, and its pkey objects).
        sqlx::migrate!("../migrations")
            .run(&pool)
            .await
            .expect("apply migrations");
        let rows =
            sqlx::query_as::<_, ExternalPgSemanticInventoryRow>(EXTERNAL_PG_SEMANTIC_INVENTORY_SQL)
                .fetch_all(&pool)
                .await
                .expect("inventory query");
        println!("inventory rows: {}", rows.len());
        println!("digest: {}", external_pg_semantic_inventory_digest(&rows));
    }

    /// Concurrent-session proof of the advisory-lock semantics the handoff
    /// recovery path and the per-checkout attestation split both rely on:
    /// PostgreSQL's same-session reentrancy excuses only a session's **own**
    /// locks, so an exclusive request still conflicts with a *different*
    /// session's shared hold.
    ///
    /// This is what makes `recover_external_pg_handoff_failure`'s same-session
    /// reacquisition a real exclusivity proof (issue #1613 item 2 assumed the
    /// opposite), and what lets `attest_session` skip the control-plane sweep
    /// per checkout (item 3): no maintenance mutation can occur while any
    /// runtime connection holds the shared form.
    ///
    /// Requires a throwaway external PostgreSQL — advisory locks only, no
    /// migrations:
    ///
    /// ```text
    /// OLYMPUS_TEST_PG_URL=postgres://user:pass@host/db \
    ///   cargo test -p olympus-desktop --lib \
    ///   handoff_recovery_reacquisition -- --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "concurrent-session integration test — needs OLYMPUS_TEST_PG_URL"]
    async fn handoff_recovery_reacquisition_conflicts_with_other_sessions() {
        let url = std::env::var("OLYMPUS_TEST_PG_URL")
            .expect("set OLYMPUS_TEST_PG_URL to a throwaway database");

        // `keeper` stands in for the migration connection after the
        // exclusive-to-shared handoff; `runtime` for a live pool member.
        let mut keeper = PgConnection::connect(&url).await.expect("keeper connect");
        let mut runtime = PgConnection::connect(&url).await.expect("runtime connect");
        assert!(
            acquire_external_pg_runtime_lock(&mut keeper).await,
            "keeper must take the shared lifecycle lock"
        );
        assert!(
            acquire_external_pg_runtime_lock(&mut runtime).await,
            "a concurrent runtime session must also take the shared lock"
        );

        // The load-bearing assertion: the keeper already holds the shared form,
        // yet its exclusive attempt is denied because *another* session holds
        // shared. Same-session reentrancy does not extend to other sessions'
        // locks, so this check cannot mistake a live runtime pool for an idle
        // database.
        assert!(
            !acquire_external_pg_maintenance_lock(&mut keeper).await,
            "exclusive reacquisition must fail while another session holds the \
             shared lifecycle lock"
        );

        // With the only other shared holder gone (closing the session releases
        // its advisory locks), the same call now proves exclusivity.
        let _ = runtime.close().await;
        assert!(
            acquire_external_pg_maintenance_lock(&mut keeper).await,
            "exclusive reacquisition must succeed once this session is the sole \
             holder — its own shared hold does not block it"
        );

        assert!(release_external_pg_maintenance_lock(&mut keeper).await);
        let _ = keeper.close().await;
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
}
