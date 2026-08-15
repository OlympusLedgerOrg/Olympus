// SPDX-License-Identifier: Apache-2.0

use super::session::{session_policy_error, ExternalPgSessionPolicyError};
use sqlx::postgres::PgConnection;
use sqlx::Connection;

/// The v0.10.0 runtime DML contract, extracted from every PostgreSQL query in
/// `src-tauri/src` and every object produced by `migrations/`.
///
/// Tables with an empty privilege list are intentional: keeping them in the
/// release manifest makes a future query or migration fail closed until this
/// matrix and its tests are reviewed together. `_sqlx_migrations` is handled
/// separately and is always migration-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExternalPgTableGrant {
    pub(super) name: &'static str,
    pub(super) privileges: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExternalPgColumnGrant {
    pub(super) table_name: &'static str,
    pub(super) privilege: &'static str,
    pub(super) columns: &'static [&'static str],
}

pub(super) const EXTERNAL_PG_TABLE_GRANTS: &[ExternalPgTableGrant] = &[
    ExternalPgTableGrant {
        name: "agencies",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "key_credentials",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "public_records_requests",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "appeals",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "doc_commits",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "dataset_artifacts",
        privileges: &["SELECT"],
    },
    ExternalPgTableGrant {
        name: "dataset_artifact_files",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "dataset_lineage_events",
        privileges: &["SELECT"],
    },
    ExternalPgTableGrant {
        name: "ledger_activities",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "tsa_jobs",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "password_recovery_tokens",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "rekor_anchors",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "users",
        privileges: &["SELECT", "INSERT", "DELETE"],
    },
    ExternalPgTableGrant {
        name: "api_keys",
        privileges: &["SELECT", "INSERT", "DELETE"],
    },
    ExternalPgTableGrant {
        name: "account_signing_keys",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "account_wallet_bindings",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "credential_consents",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "credential_ledger_events",
        privileges: &["SELECT"],
    },
    ExternalPgTableGrant {
        name: "operators",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "anchor_receipts",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "peer_checkpoints",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "credential_quorum_signatures",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "peer_nodes",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "smt_nodes",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "smt_leaves",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "shards",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "ingest_records",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "own_checkpoints",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "checkpoint_quorum_signatures",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "redaction_segment_manifests",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "signed_request_nonces",
        privileges: &["INSERT", "DELETE"],
    },
    ExternalPgTableGrant {
        name: "anchor_submission_claims",
        privileges: &["SELECT", "INSERT"],
    },
    // ADR-0041 append-only trust-transition records (migration 0062). All
    // three are insert-only by protocol design — lifecycle changes are
    // appended events, never row mutations — so the runtime holds no UPDATE
    // or DELETE on any of them.
    ExternalPgTableGrant {
        name: "trust_transition_candidates",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "trust_candidate_events",
        privileges: &["SELECT", "INSERT"],
    },
    ExternalPgTableGrant {
        name: "trust_accepted_transitions",
        privileges: &["SELECT", "INSERT"],
    },
];

/// The live runtime can update only fields written by an audited SQL path.
/// Evidence identities and immutable payload columns intentionally never
/// receive table-wide UPDATE.
pub(super) const EXTERNAL_PG_COLUMN_GRANTS: &[ExternalPgColumnGrant] = &[
    ExternalPgColumnGrant {
        table_name: "key_credentials",
        privilege: "UPDATE",
        columns: &[
            "revoked_at",
            "revoked_sig_r8x",
            "revoked_sig_r8y",
            "revoked_sig_s",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "password_recovery_tokens",
        privilege: "UPDATE",
        columns: &["used_at"],
    },
    ExternalPgColumnGrant {
        table_name: "users",
        privilege: "UPDATE",
        columns: &["password_hash", "role"],
    },
    ExternalPgColumnGrant {
        table_name: "api_keys",
        privilege: "UPDATE",
        columns: &[
            "key_hash",
            "revoked_at",
            "scopes",
            "operator_id",
            "ed25519_public_key",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "account_signing_keys",
        privilege: "UPDATE",
        columns: &[
            "bjj_pubkey_x",
            "bjj_pubkey_y",
            "revoked_at",
            "replaced_by_key_id",
            "revoked_by_key_id",
            // Authority-registry lifecycle stamp (migration 0056):
            // rotate_authority windows the retired key at revocation time.
            "valid_until",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "anchor_receipts",
        privilege: "UPDATE",
        columns: &[
            "verified_at",
            "ots_upgrade_lease_token",
            "ots_upgrade_lease_until",
            "ots_upgrade_attempts",
            "ots_last_upgrade_attempt_at",
            "ots_next_upgrade_attempt_at",
            "ots_last_upgrade_error",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "peer_checkpoints",
        privilege: "UPDATE",
        columns: &["equivocation_detected"],
    },
    ExternalPgColumnGrant {
        table_name: "peer_nodes",
        privilege: "UPDATE",
        columns: &[
            "trust_status",
            "removed_at",
            "last_seen_at",
            "last_pull_error_at",
            "last_pull_error_msg",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "smt_nodes",
        privilege: "UPDATE",
        columns: &["hash"],
    },
    ExternalPgColumnGrant {
        table_name: "ingest_records",
        privilege: "UPDATE",
        columns: &[
            "chunk_hashes",
            "original_root",
            "snapshot_root",
            "snapshot_index",
            "snapshot_size",
            "snapshot_path",
            "snapshot_sig",
            "snapshot_committed",
            "zk_bundle",
            "smt_committed",
        ],
    },
    ExternalPgColumnGrant {
        table_name: "signed_request_nonces",
        privilege: "SELECT",
        columns: &["key_id", "nonce", "expires_at"],
    },
    ExternalPgColumnGrant {
        table_name: "anchor_submission_claims",
        privilege: "UPDATE",
        columns: &[
            "checkpoint_id",
            "status",
            "receipt_id",
            "lease_token",
            "lease_until",
            "attempt_count",
            "last_attempt_at",
            "next_retry_at",
            "last_error",
            "updated_at",
        ],
    },
];

/// Neither v0.10.0 sequence is used by a live Rust query. UUIDs are generated
/// in-process; these two sequences survive only for retired legacy tables.
pub(super) const EXTERNAL_PG_SEQUENCE_GRANTS: &[ExternalPgTableGrant] = &[
    ExternalPgTableGrant {
        name: "display_id_seq",
        privileges: &[],
    },
    ExternalPgTableGrant {
        name: "rekor_anchors_id_seq",
        privileges: &[],
    },
];

/// Standalone application types are a closed release inventory. Table row
/// types and their generated array types are admitted separately by the live
/// catalog probe; every other standalone/user-schema type is unsupported.
pub(super) const EXTERNAL_PG_ENUM_TYPES: &[&str] = &[
    "agency_level",
    "request_type",
    "request_status",
    "request_priority",
    "appeal_grounds",
    "appeal_status",
];

fn external_pg_grant_spec(grants: &[ExternalPgTableGrant]) -> String {
    serde_json::Value::Array(
        grants
            .iter()
            .map(|grant| {
                serde_json::json!({
                    "name": grant.name,
                    "privileges": grant.privileges,
                })
            })
            .collect(),
    )
    .to_string()
}

fn external_pg_column_grant_spec(grants: &[ExternalPgColumnGrant]) -> String {
    serde_json::Value::Array(
        grants
            .iter()
            .map(|grant| {
                serde_json::json!({
                    "table_name": grant.table_name,
                    "privilege": grant.privilege,
                    "columns": grant.columns,
                })
            })
            .collect(),
    )
    .to_string()
}

/// Apply the release-pinned ACL manifest without ever interpolating the live
/// role or schema name into a client-side SQL string. The bound values live
/// only in transaction-local custom settings; the fixed DO block quotes every
/// identifier with PostgreSQL's `format('%I', ...)`.
///
/// The block first proves the migrated object inventory is exactly the
/// reviewed v0.10.0 manifest and is owned by the migration role. It then
/// removes PUBLIC/runtime ambient grants, applies only the matrix above, and
/// removes PUBLIC/runtime privileges from objects the migrator creates in a
/// future migration. A new migration object therefore remains inaccessible
/// until the release manifest is deliberately updated.
const EXTERNAL_PG_APPLY_GRANTS_SQL: &str = r#"
DO $olympus$
DECLARE
    app_schema name := current_schema();
    runtime_role name := current_setting('olympus.runtime_role', false)::name;
    table_spec jsonb := current_setting('olympus.table_grants', false)::jsonb;
    column_spec jsonb := current_setting('olympus.column_grants', false)::jsonb;
    sequence_spec jsonb := current_setting('olympus.sequence_grants', false)::jsonb;
    entry jsonb;
    object_record record;
    privilege_list text;
BEGIN
    IF app_schema IS NULL
       OR runtime_role::text = current_user::text
       OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_roles
           WHERE rolname = runtime_role::text
       )
       OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_namespace
           WHERE nspname = app_schema::text
             AND pg_catalog.has_schema_privilege(current_user, oid, 'CREATE')
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL privilege policy precondition failed';
    END IF;

    IF jsonb_typeof(table_spec) <> 'array'
       OR jsonb_typeof(column_spec) <> 'array'
       OR jsonb_typeof(sequence_spec) <> 'array'
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           WHERE jsonb_typeof(item.value) <> 'object'
              OR jsonb_typeof(item.value -> 'table_name') <> 'string'
              OR jsonb_typeof(item.value -> 'privilege') <> 'string'
              OR jsonb_typeof(item.value -> 'columns') <> 'array'
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
           WHERE jsonb_typeof(item.value) <> 'object'
              OR jsonb_typeof(item.value -> 'name') <> 'string'
              OR jsonb_typeof(item.value -> 'privileges') <> 'array'
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
           WHERE jsonb_typeof(item.value) <> 'object'
              OR jsonb_typeof(item.value -> 'name') <> 'string'
              OR jsonb_typeof(item.value -> 'privileges') <> 'array'
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL privilege manifest is invalid';
    END IF;

    IF EXISTS (
           SELECT item.value ->> 'name'
           FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
           GROUP BY item.value ->> 'name'
           HAVING count(*) <> 1
       )
       OR EXISTS (
           SELECT
               item.value ->> 'table_name',
               item.value ->> 'privilege'
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           GROUP BY
               item.value ->> 'table_name',
               item.value ->> 'privilege'
           HAVING count(*) <> 1
       )
       OR EXISTS (
           SELECT item.value ->> 'name'
           FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
           GROUP BY item.value ->> 'name'
           HAVING count(*) <> 1
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           WHERE item.value ->> 'privilege' NOT IN ('SELECT', 'UPDATE')
              OR pg_catalog.jsonb_array_length(item.value -> 'columns') = 0
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
           CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(
               item.value -> 'privileges'
           ) AS privilege(value)
           WHERE privilege.value NOT IN (
               'SELECT', 'INSERT', 'UPDATE', 'DELETE'
           )
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
           CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(
               item.value -> 'privileges'
           ) AS privilege(value)
           WHERE privilege.value NOT IN ('USAGE', 'SELECT', 'UPDATE')
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL privilege manifest is invalid';
    END IF;

    IF EXISTS (
        (
            SELECT relation.relname
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = app_schema::text
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND relation.relname <> '_sqlx_migrations'
            EXCEPT
            SELECT item.value ->> 'name'
            FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
        )
        UNION ALL
        (
            SELECT item.value ->> 'name'
            FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
            EXCEPT
            SELECT relation.relname
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = app_schema::text
              AND relation.relkind IN ('r', 'p')
              AND relation.relname <> '_sqlx_migrations'
        )
    )
       OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = relation.relnamespace
           WHERE namespace.nspname = app_schema::text
             AND relation.relname = '_sqlx_migrations'
             AND relation.relkind IN ('r', 'p')
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL table inventory differs from the release manifest';
    END IF;

    -- Relation names are only schema-unique. A same-named legacy table in an
    -- off-path schema must not make the active-schema manifest look invalid.
    IF EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           WHERE NOT EXISTS (
               SELECT 1
               FROM pg_catalog.pg_class AS relation
               JOIN pg_catalog.pg_namespace AS namespace
                 ON namespace.oid = relation.relnamespace
               WHERE namespace.nspname = app_schema::text
                 AND relation.relname = item.value ->> 'table_name'
                 AND relation.relkind IN ('r', 'p')
           )
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(
               item.value -> 'columns'
           ) AS column_name(value)
           WHERE jsonb_typeof(column_name.value) <> 'string'
              OR NOT EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_class AS relation
                  JOIN pg_catalog.pg_namespace AS namespace
                    ON namespace.oid = relation.relnamespace
                  JOIN pg_catalog.pg_attribute AS attribute
                    ON attribute.attrelid = relation.oid
                   AND attribute.attname = column_name.value #>> '{}'
                   AND attribute.attnum > 0
                   AND NOT attribute.attisdropped
                  WHERE namespace.nspname = app_schema::text
                    AND relation.relname = item.value ->> 'table_name'
                    AND relation.relkind IN ('r', 'p')
              )
       )
       OR EXISTS (
           SELECT
               item.value ->> 'table_name',
               item.value ->> 'privilege',
               column_name.value
           FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
           CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(
               item.value -> 'columns'
           ) AS column_name(value)
           GROUP BY
               item.value ->> 'table_name',
               item.value ->> 'privilege',
               column_name.value
           HAVING count(*) <> 1
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL column privilege manifest is invalid';
    END IF;

    IF EXISTS (
        (
            SELECT relation.relname
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = app_schema::text
              AND relation.relkind = 'S'
            EXCEPT
            SELECT item.value ->> 'name'
            FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
        )
        UNION ALL
        (
            SELECT item.value ->> 'name'
            FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
            EXCEPT
            SELECT relation.relname
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = app_schema::text
              AND relation.relkind = 'S'
        )
    )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL sequence inventory differs from the release manifest';
    END IF;

    IF EXISTS (
           SELECT 1
           FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = routine.pronamespace
           WHERE namespace.nspname = app_schema::text
             AND routine.proowner <> (
                 SELECT oid
                 FROM pg_catalog.pg_roles
                 WHERE rolname = current_user
             )
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = relation.relnamespace
           WHERE namespace.nspname = app_schema::text
             AND relation.relowner <> (
                 SELECT oid
                 FROM pg_catalog.pg_roles
                 WHERE rolname = current_user
             )
       )
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.pg_type AS data_type
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = data_type.typnamespace
           WHERE namespace.nspname = app_schema::text
             AND data_type.typowner <> (
                 SELECT oid
                 FROM pg_catalog.pg_roles
                 WHERE rolname = current_user
             )
       )
    THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL object ownership or routine inventory differs from policy';
    END IF;

    FOR object_record IN
        SELECT
            relation.relname,
            string_agg(
                pg_catalog.format('%I', attribute.attname),
                ', '
                ORDER BY attribute.attnum
            ) AS column_list
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        LEFT JOIN pg_catalog.pg_attribute AS attribute
          ON attribute.attrelid = relation.oid
         AND attribute.attnum > 0
         AND NOT attribute.attisdropped
        WHERE namespace.nspname = app_schema::text
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
        GROUP BY relation.relname
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM PUBLIC',
            app_schema,
            object_record.relname
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I',
            app_schema,
            object_record.relname,
            runtime_role
        );
        IF object_record.column_list IS NOT NULL THEN
            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES (%s) ON TABLE %I.%I FROM PUBLIC',
                object_record.column_list,
                app_schema,
                object_record.relname
            );
            EXECUTE pg_catalog.format(
                'REVOKE ALL PRIVILEGES (%s) ON TABLE %I.%I FROM %I',
                object_record.column_list,
                app_schema,
                object_record.relname,
                runtime_role
            );
        END IF;
    END LOOP;

    FOR object_record IN
        SELECT relation.relname
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = app_schema::text
          AND relation.relkind = 'S'
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM PUBLIC',
            app_schema,
            object_record.relname
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM %I',
            app_schema,
            object_record.relname,
            runtime_role
        );
    END LOOP;

    FOR object_record IN
        SELECT data_type.typname
        FROM pg_catalog.pg_type AS data_type
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        WHERE namespace.nspname = app_schema::text
          AND data_type.typelem = 0
          AND data_type.typtype IN ('d', 'e', 'm', 'r')
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TYPE %I.%I FROM PUBLIC',
            app_schema,
            object_record.typname
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES ON TYPE %I.%I FROM %I',
            app_schema,
            object_record.typname,
            runtime_role
        );
    END LOOP;

    EXECUTE pg_catalog.format(
        'GRANT USAGE ON SCHEMA %I TO %I',
        app_schema,
        runtime_role
    );

    FOR entry IN
        SELECT item.value
        FROM pg_catalog.jsonb_array_elements(table_spec) AS item(value)
    LOOP
        SELECT string_agg(privilege.value, ', ' ORDER BY privilege.ordinality)
        INTO privilege_list
        FROM pg_catalog.jsonb_array_elements_text(
            entry -> 'privileges'
        ) WITH ORDINALITY AS privilege(value, ordinality);

        IF privilege_list IS NOT NULL THEN
            EXECUTE pg_catalog.format(
                'GRANT %s ON TABLE %I.%I TO %I',
                privilege_list,
                app_schema,
                entry ->> 'name',
                runtime_role
            );
        END IF;
    END LOOP;

    FOR entry IN
        SELECT item.value
        FROM pg_catalog.jsonb_array_elements(column_spec) AS item(value)
    LOOP
        SELECT string_agg(
            pg_catalog.format('%I', column_name.value),
            ', '
            ORDER BY column_name.ordinality
        )
        INTO privilege_list
        FROM pg_catalog.jsonb_array_elements_text(
            entry -> 'columns'
        ) WITH ORDINALITY AS column_name(value, ordinality);

        EXECUTE pg_catalog.format(
            'GRANT %s (%s) ON TABLE %I.%I TO %I',
            entry ->> 'privilege',
            privilege_list,
            app_schema,
            entry ->> 'table_name',
            runtime_role
        );
    END LOOP;

    FOR entry IN
        SELECT item.value
        FROM pg_catalog.jsonb_array_elements(sequence_spec) AS item(value)
    LOOP
        SELECT string_agg(privilege.value, ', ' ORDER BY privilege.ordinality)
        INTO privilege_list
        FROM pg_catalog.jsonb_array_elements_text(
            entry -> 'privileges'
        ) WITH ORDINALITY AS privilege(value, ordinality);

        IF privilege_list IS NOT NULL THEN
            EXECUTE pg_catalog.format(
                'GRANT %s ON SEQUENCE %I.%I TO %I',
                privilege_list,
                app_schema,
                entry ->> 'name',
                runtime_role
            );
        END IF;
    END LOOP;

    -- Global default ACLs are the base ACL for future objects. PostgreSQL's
    -- built-in defaults grant PUBLIC EXECUTE on functions and PUBLIC USAGE on
    -- types, so those revocations must not be scoped with IN SCHEMA.
    FOREACH privilege_list IN ARRAY ARRAY['TABLES', 'SEQUENCES', 'FUNCTIONS', 'TYPES']
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE ALL PRIVILEGES ON %s FROM PUBLIC',
            current_user,
            privilege_list
        );
        EXECUTE pg_catalog.format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE ALL PRIVILEGES ON %s FROM %I',
            current_user,
            privilege_list,
            runtime_role
        );
    END LOOP;

    -- Per-schema default ACLs are additive to the global base. Clear stale
    -- additions for every non-system schema, not only the active path.
    FOR object_record IN
        SELECT namespace.nspname
        FROM pg_catalog.pg_namespace AS namespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
    LOOP
        FOREACH privilege_list IN ARRAY ARRAY['TABLES', 'SEQUENCES', 'FUNCTIONS', 'TYPES']
        LOOP
            EXECUTE pg_catalog.format(
                'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL PRIVILEGES ON %s FROM PUBLIC',
                current_user,
                object_record.nspname,
                privilege_list
            );
            EXECUTE pg_catalog.format(
                'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL PRIVILEGES ON %s FROM %I',
                current_user,
                object_record.nspname,
                privilege_list,
                runtime_role
            );
        END LOOP;
    END LOOP;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Olympus external PostgreSQL privilege provisioning failed';
END
$olympus$
"#;

pub(super) async fn provision_external_pg_runtime_privileges(
    connection: &mut PgConnection,
    runtime_role: &str,
) -> Result<(), sqlx::Error> {
    let table_spec = external_pg_grant_spec(EXTERNAL_PG_TABLE_GRANTS);
    let column_spec = external_pg_column_grant_spec(EXTERNAL_PG_COLUMN_GRANTS);
    let sequence_spec = external_pg_grant_spec(EXTERNAL_PG_SEQUENCE_GRANTS);
    let mut transaction = connection.begin().await?;
    // No-op REVOKEs can produce object/role-bearing PostgreSQL warnings.
    // Keep those server notices off the client channel; Olympus reports only
    // the static failure text at the call site.
    sqlx::query("SELECT set_config('client_min_messages', 'error', true)")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.runtime_role', $1, true)")
        .bind(runtime_role)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.table_grants', $1, true)")
        .bind(table_spec)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.column_grants', $1, true)")
        .bind(column_spec)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('olympus.sequence_grants', $1, true)")
        .bind(sequence_spec)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(EXTERNAL_PG_APPLY_GRANTS_SQL)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(super) struct ExternalPgTablePrivilegeProbe {
    pub(super) object_name: String,
    pub(super) can_select: bool,
    pub(super) can_insert: bool,
    pub(super) can_update: bool,
    pub(super) can_delete: bool,
    pub(super) can_truncate: bool,
    pub(super) can_references: bool,
    pub(super) can_trigger: bool,
    pub(super) runtime_has_table_grant_option: bool,
    pub(super) runtime_has_unknown_table_privilege: bool,
    pub(super) public_has_any_privilege: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(super) struct ExternalPgColumnPrivilegeProbe {
    pub(super) object_name: String,
    pub(super) column_name: String,
    pub(super) privilege_type: String,
    pub(super) is_grantable: bool,
    pub(super) grantee_is_public: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(super) struct ExternalPgSequencePrivilegeProbe {
    pub(super) object_name: String,
    pub(super) can_usage: bool,
    pub(super) can_select: bool,
    pub(super) can_update: bool,
    pub(super) runtime_has_grant_option: bool,
    pub(super) public_has_any_privilege: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(super) struct ExternalPgOtherPrivilegeProbe {
    pub(super) schema_public_has_any_privilege: bool,
    pub(super) runtime_has_any_routine_execute: bool,
    pub(super) public_has_any_routine_privilege: bool,
    pub(super) runtime_has_any_type_usage: bool,
    pub(super) public_has_any_type_privilege: bool,
    pub(super) migration_defaults_have_ambient_privileges: bool,
    pub(super) migration_defaults_have_grant_options: bool,
    pub(super) runtime_or_public_has_off_path_object_privileges: bool,
}

const EXTERNAL_PG_TABLE_PRIVILEGE_PROBE_SQL: &str = r#"
SELECT
    relation.relname::text AS object_name,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'SELECT'
    ) AS can_select,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'INSERT'
    ) AS can_insert,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'UPDATE'
    ) AS can_update,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'DELETE'
    ) AS can_delete,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'TRUNCATE'
    ) AS can_truncate,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'REFERENCES'
    ) AS can_references,
    pg_catalog.has_table_privilege(
        session_user,
        relation.oid,
        'TRIGGER'
    ) AS can_trigger,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(relation.relacl) AS object_acl
        JOIN pg_catalog.pg_roles AS runtime_role
          ON runtime_role.oid = object_acl.grantee
        WHERE runtime_role.rolname = session_user
          AND object_acl.is_grantable
    ) AS runtime_has_table_grant_option,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(relation.relacl) AS object_acl
        JOIN pg_catalog.pg_roles AS runtime_role
          ON runtime_role.oid = object_acl.grantee
        WHERE runtime_role.rolname = session_user
          AND object_acl.privilege_type NOT IN (
              'SELECT',
              'INSERT',
              'UPDATE',
              'DELETE',
              'TRUNCATE',
              'REFERENCES',
              'TRIGGER'
          )
    ) AS runtime_has_unknown_table_privilege,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
            COALESCE(
                relation.relacl,
                pg_catalog.acldefault('r', relation.relowner)
            )
        ) AS object_acl
        WHERE object_acl.grantee = 0
    ) AS public_has_any_privilege
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = current_schema()
  AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY relation.relname
"#;

const EXTERNAL_PG_COLUMN_PRIVILEGE_PROBE_SQL: &str = r#"
SELECT
    relation.relname::text AS object_name,
    attribute.attname::text AS column_name,
    column_acl.privilege_type::text AS privilege_type,
    column_acl.is_grantable,
    column_acl.grantee = 0 AS grantee_is_public
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
JOIN pg_catalog.pg_attribute AS attribute
  ON attribute.attrelid = relation.oid
 AND attribute.attnum > 0
 AND NOT attribute.attisdropped
CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS column_acl
LEFT JOIN pg_catalog.pg_roles AS grantee
  ON grantee.oid = column_acl.grantee
WHERE namespace.nspname = current_schema()
  AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND (column_acl.grantee = 0 OR grantee.rolname = session_user)
ORDER BY relation.relname, attribute.attnum, column_acl.privilege_type
"#;

const EXTERNAL_PG_SEQUENCE_PRIVILEGE_PROBE_SQL: &str = r#"
SELECT
    relation.relname::text AS object_name,
    pg_catalog.has_sequence_privilege(
        session_user,
        relation.oid,
        'USAGE'
    ) AS can_usage,
    pg_catalog.has_sequence_privilege(
        session_user,
        relation.oid,
        'SELECT'
    ) AS can_select,
    pg_catalog.has_sequence_privilege(
        session_user,
        relation.oid,
        'UPDATE'
    ) AS can_update,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(relation.relacl) AS object_acl
        JOIN pg_catalog.pg_roles AS runtime_role
          ON runtime_role.oid = object_acl.grantee
        WHERE runtime_role.rolname = session_user
          AND object_acl.is_grantable
    ) AS runtime_has_grant_option,
    EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
            COALESCE(
                relation.relacl,
                pg_catalog.acldefault('S', relation.relowner)
            )
        ) AS object_acl
        WHERE object_acl.grantee = 0
    ) AS public_has_any_privilege
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = current_schema()
  AND relation.relkind = 'S'
ORDER BY relation.relname
"#;

const EXTERNAL_PG_OTHER_PRIVILEGE_PROBE_SQL: &str = r#"
WITH current_namespace AS (
    SELECT namespace.oid, namespace.nspacl, namespace.nspowner
    FROM pg_catalog.pg_namespace AS namespace
    WHERE namespace.nspname = current_schema()
),
migration_role AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = $1
),
runtime_role AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = session_user
),
default_object_types(object_type) AS (
    VALUES
        ('r'::"char"),
        ('S'::"char"),
        ('f'::"char"),
        ('T'::"char")
),
effective_default_privileges AS (
    -- The global row, when present, replaces acldefault(); per-schema rows
    -- are additive and therefore must be checked separately.
    SELECT default_object_types.object_type, default_privilege.*
    FROM migration_role
    CROSS JOIN default_object_types
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(
            (
                SELECT default_acl.defaclacl
                FROM pg_catalog.pg_default_acl AS default_acl
                WHERE default_acl.defaclrole = migration_role.oid
                  AND default_acl.defaclnamespace = 0
                  AND default_acl.defaclobjtype = default_object_types.object_type
            ),
            pg_catalog.acldefault(
                default_object_types.object_type,
                migration_role.oid
            )
        )
    ) AS default_privilege
    UNION ALL
    SELECT default_acl.defaclobjtype, default_privilege.*
    FROM migration_role
    JOIN pg_catalog.pg_default_acl AS default_acl
      ON default_acl.defaclrole = migration_role.oid
     AND default_acl.defaclnamespace <> 0
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        default_acl.defaclacl
    ) AS default_privilege
)
SELECT
    EXISTS (
        SELECT 1
        FROM current_namespace AS namespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                namespace.nspacl,
                pg_catalog.acldefault('n', namespace.nspowner)
            )
        ) AS schema_acl
        WHERE schema_acl.grantee = 0
    ) AS schema_public_has_any_privilege,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS routine
        JOIN current_namespace AS namespace
          ON namespace.oid = routine.pronamespace
        WHERE pg_catalog.has_function_privilege(
            session_user,
            routine.oid,
            'EXECUTE'
        )
    ) AS runtime_has_any_routine_execute,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS routine
        JOIN current_namespace AS namespace
          ON namespace.oid = routine.pronamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                routine.proacl,
                pg_catalog.acldefault('f', routine.proowner)
            )
        ) AS routine_acl
        WHERE routine_acl.grantee = 0
    ) AS public_has_any_routine_privilege,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS data_type
        JOIN current_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        WHERE data_type.typelem = 0
          AND (
              data_type.typrelid = 0
              OR EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_class AS type_relation
                  WHERE type_relation.oid = data_type.typrelid
                    AND type_relation.relkind = 'c'
              )
          )
          AND pg_catalog.has_type_privilege(
              session_user,
              data_type.oid,
              'USAGE'
          )
    ) AS runtime_has_any_type_usage,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS data_type
        JOIN current_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                data_type.typacl,
                pg_catalog.acldefault('T', data_type.typowner)
            )
        ) AS type_acl
        WHERE data_type.typelem = 0
          AND (
              data_type.typrelid = 0
              OR EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_class AS type_relation
                  WHERE type_relation.oid = data_type.typrelid
                    AND type_relation.relkind = 'c'
              )
          )
          AND type_acl.grantee = 0
    ) AS public_has_any_type_privilege,
    EXISTS (
        SELECT 1
        FROM effective_default_privileges AS default_privilege
        CROSS JOIN runtime_role
        WHERE default_privilege.grantee IN (0, runtime_role.oid)
    ) AS migration_defaults_have_ambient_privileges,
    EXISTS (
        SELECT 1
        FROM effective_default_privileges AS default_privilege
        CROSS JOIN runtime_role
        WHERE default_privilege.grantee IN (0, runtime_role.oid)
          AND default_privilege.is_grantable
    ) AS migration_defaults_have_grant_options,
    (
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            CROSS JOIN runtime_role
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    relation.relacl,
                    pg_catalog.acldefault(
                        (
                            CASE
                                WHEN relation.relkind = 'S' THEN 'S'
                                ELSE 'r'
                            END
                        )::"char",
                        relation.relowner
                    )
                )
            ) AS object_acl
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
              AND object_acl.grantee IN (0, runtime_role.oid)
        )
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = routine.pronamespace
            CROSS JOIN runtime_role
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    routine.proacl,
                    pg_catalog.acldefault('f', routine.proowner)
                )
            ) AS object_acl
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
              AND object_acl.grantee IN (0, runtime_role.oid)
        )
        OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_type AS data_type
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = data_type.typnamespace
            CROSS JOIN runtime_role
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    data_type.typacl,
                    pg_catalog.acldefault('T', data_type.typowner)
                )
            ) AS object_acl
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
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
              AND object_acl.grantee IN (0, runtime_role.oid)
        )
    ) AS runtime_or_public_has_off_path_object_privileges
"#;

pub(super) async fn probe_external_pg_runtime_privileges(
    connection: &mut PgConnection,
    migration_role: &str,
) -> Result<
    (
        Vec<ExternalPgTablePrivilegeProbe>,
        Vec<ExternalPgColumnPrivilegeProbe>,
        Vec<ExternalPgSequencePrivilegeProbe>,
        ExternalPgOtherPrivilegeProbe,
    ),
    sqlx::Error,
> {
    let tables =
        sqlx::query_as::<_, ExternalPgTablePrivilegeProbe>(EXTERNAL_PG_TABLE_PRIVILEGE_PROBE_SQL)
            .fetch_all(&mut *connection)
            .await?;
    let columns =
        sqlx::query_as::<_, ExternalPgColumnPrivilegeProbe>(EXTERNAL_PG_COLUMN_PRIVILEGE_PROBE_SQL)
            .fetch_all(&mut *connection)
            .await?;
    let sequences = sqlx::query_as::<_, ExternalPgSequencePrivilegeProbe>(
        EXTERNAL_PG_SEQUENCE_PRIVILEGE_PROBE_SQL,
    )
    .fetch_all(&mut *connection)
    .await?;
    let other =
        sqlx::query_as::<_, ExternalPgOtherPrivilegeProbe>(EXTERNAL_PG_OTHER_PRIVILEGE_PROBE_SQL)
            .bind(migration_role)
            .fetch_one(&mut *connection)
            .await?;
    Ok((tables, columns, sequences, other))
}

pub(super) fn expected_grant_has(grant: &ExternalPgTableGrant, privilege: &str) -> bool {
    grant.privileges.contains(&privilege)
}

pub(super) fn validate_external_pg_runtime_privileges(
    tables: &[ExternalPgTablePrivilegeProbe],
    columns: &[ExternalPgColumnPrivilegeProbe],
    sequences: &[ExternalPgSequencePrivilegeProbe],
    other: &ExternalPgOtherPrivilegeProbe,
) -> Result<(), ExternalPgSessionPolicyError> {
    if tables.len() != EXTERNAL_PG_TABLE_GRANTS.len() + 1 {
        return Err(session_policy_error(
            "the runtime table inventory differs from the release privilege manifest",
        ));
    }
    for expected in EXTERNAL_PG_TABLE_GRANTS {
        let mut matching = tables
            .iter()
            .filter(|probe| probe.object_name == expected.name);
        let Some(actual) = matching.next() else {
            return Err(session_policy_error(
                "the runtime table inventory differs from the release privilege manifest",
            ));
        };
        if matching.next().is_some()
            || actual.can_select != expected_grant_has(expected, "SELECT")
            || actual.can_insert != expected_grant_has(expected, "INSERT")
            || actual.can_update != expected_grant_has(expected, "UPDATE")
            || actual.can_delete != expected_grant_has(expected, "DELETE")
            || actual.can_truncate
            || actual.can_references
            || actual.can_trigger
            || actual.runtime_has_table_grant_option
            || actual.runtime_has_unknown_table_privilege
            || actual.public_has_any_privilege
        {
            return Err(session_policy_error(
                "the runtime table privileges differ from the release privilege manifest",
            ));
        }
    }
    let mut sqlx_metadata = tables
        .iter()
        .filter(|probe| probe.object_name == "_sqlx_migrations");
    let Some(sqlx_metadata) = sqlx_metadata.next() else {
        return Err(session_policy_error(
            "the runtime table inventory differs from the release privilege manifest",
        ));
    };
    if sqlx_metadata.can_select
        || sqlx_metadata.can_insert
        || sqlx_metadata.can_update
        || sqlx_metadata.can_delete
        || sqlx_metadata.can_truncate
        || sqlx_metadata.can_references
        || sqlx_metadata.can_trigger
        || sqlx_metadata.runtime_has_table_grant_option
        || sqlx_metadata.runtime_has_unknown_table_privilege
        || sqlx_metadata.public_has_any_privilege
        || tables.iter().any(|probe| {
            probe.object_name != "_sqlx_migrations"
                && !EXTERNAL_PG_TABLE_GRANTS
                    .iter()
                    .any(|expected| expected.name == probe.object_name)
        })
    {
        return Err(session_policy_error(
            "the runtime table privileges differ from the release privilege manifest",
        ));
    }

    let expected_column_count: usize = EXTERNAL_PG_COLUMN_GRANTS
        .iter()
        .map(|grant| grant.columns.len())
        .sum();
    if columns.len() != expected_column_count
        || columns.iter().any(|actual| {
            actual.grantee_is_public
                || actual.is_grantable
                || !EXTERNAL_PG_COLUMN_GRANTS.iter().any(|expected| {
                    expected.table_name == actual.object_name
                        && expected.privilege == actual.privilege_type
                        && expected.columns.contains(&actual.column_name.as_str())
                })
        })
        || EXTERNAL_PG_COLUMN_GRANTS.iter().any(|expected| {
            expected.columns.iter().any(|expected_column| {
                columns
                    .iter()
                    .filter(|actual| {
                        !actual.grantee_is_public
                            && actual.object_name == expected.table_name
                            && actual.privilege_type == expected.privilege
                            && actual.column_name == *expected_column
                    })
                    .count()
                    != 1
            })
        })
    {
        return Err(session_policy_error(
            "the runtime column privileges differ from the release privilege manifest",
        ));
    }

    if sequences.len() != EXTERNAL_PG_SEQUENCE_GRANTS.len() {
        return Err(session_policy_error(
            "the runtime sequence inventory differs from the release privilege manifest",
        ));
    }
    for expected in EXTERNAL_PG_SEQUENCE_GRANTS {
        let mut matching = sequences
            .iter()
            .filter(|probe| probe.object_name == expected.name);
        let Some(actual) = matching.next() else {
            return Err(session_policy_error(
                "the runtime sequence inventory differs from the release privilege manifest",
            ));
        };
        if matching.next().is_some()
            || actual.can_usage != expected_grant_has(expected, "USAGE")
            || actual.can_select != expected_grant_has(expected, "SELECT")
            || actual.can_update != expected_grant_has(expected, "UPDATE")
            || actual.runtime_has_grant_option
            || actual.public_has_any_privilege
        {
            return Err(session_policy_error(
                "the runtime sequence privileges differ from the release privilege manifest",
            ));
        }
    }
    if sequences.iter().any(|probe| {
        !EXTERNAL_PG_SEQUENCE_GRANTS
            .iter()
            .any(|expected| expected.name == probe.object_name)
    }) {
        return Err(session_policy_error(
            "the runtime sequence inventory differs from the release privilege manifest",
        ));
    }

    if other.schema_public_has_any_privilege
        || other.runtime_has_any_routine_execute
        || other.public_has_any_routine_privilege
        || other.runtime_has_any_type_usage
        || other.public_has_any_type_privilege
        || other.migration_defaults_have_ambient_privileges
        || other.migration_defaults_have_grant_options
        || other.runtime_or_public_has_off_path_object_privileges
    {
        return Err(session_policy_error(
            "the runtime schema, routine, type, or default privileges differ from policy",
        ));
    }
    Ok(())
}
