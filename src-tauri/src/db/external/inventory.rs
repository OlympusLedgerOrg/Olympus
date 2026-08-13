// SPDX-License-Identifier: Apache-2.0

use super::grants::{
    EXTERNAL_PG_ENUM_TYPES, EXTERNAL_PG_SEQUENCE_GRANTS, EXTERNAL_PG_TABLE_GRANTS,
};
use super::session::{session_policy_error, ExternalPgSessionPolicyError};
use sqlx::postgres::PgConnection;

/// BLAKE3 of the canonical PostgreSQL table, column, sequence, enum, routine,
/// trigger, index, and constraint inventory produced by
/// `external_pg_semantic_inventory_digest`. This is populated from the
/// reviewed v0.10.0 migration result and pins executable write semantics.
///
/// The inventory query pins `COLLATE "C"` on all four sort keys (issue
/// #1613.1): the canonical ordering must not depend on the cluster's default
/// collation. Validated 2026-08-12 against real PostgreSQL 16.13 databases
/// created with `LC_COLLATE 'C'` and `LC_COLLATE 'en_US.UTF-8'`: the as-is
/// query reproduced this exact constant on BOTH (675 rows — the current
/// catalog's total order coincides under the two collations, so the drift was
/// latent, not active), and the `COLLATE "C"` form reproduces it identically,
/// which is why the pinned value did not change with the query hardening.
///
/// Regenerated for the merged migration set ending in
/// `0059_redaction_blind_secret_registry`, applied on top of
/// `0058_peer_checkpoints_v3_indexes`:
///
/// - `0058_peer_checkpoints_v3_indexes` drops the three `wire_version = 2`
///   partial indexes on `peer_checkpoints` (`peer_checkpoints_v2_statement_unique`,
///   `_v2_equivocation_height`, `_v2_equivocation_timestamp`) and recreates
///   them under new names predicated on `wire_version IN (2, 3)`. Object count
///   unchanged (675 -> 675): three index *definitions* change, not the number
///   of inventory objects.
/// - `0059_redaction_blind_secret_registry` adds the
///   single-active-redaction-blind-secret partial index
///   (`purpose = 'redaction_blind_secret'`, docs/key-rotation.md — redaction
///   blind-secret rotation registry) — 675 inventory rows before, 676 after.
///
/// The previous value was
/// `09cf92379bc8ff74e67e9489c7cd3f4d8a6940b2240b12ff4186fc9a03cf77a5` (itself
/// set by `0057_ingest_signing_key_registry`, 674 -> 675). Regenerated
/// 2026-08-13 by applying the full migration set against a real PostgreSQL
/// 16.13 database and running `regen_semantic_inventory_digest` — see the
/// ignored maintenance test below.
const EXTERNAL_PG_SEMANTIC_INVENTORY_BLAKE3: &str =
    "4be5dfc9570a5f2c0508319d7d9a368137144983b6dd2938c8e6713cc5230a19";

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(super) struct ExternalPgTrustedBoundaryProbe {
    pub(super) has_untrusted_boundary: bool,
}

const EXTERNAL_PG_TRUSTED_BOUNDARY_PROBE_SQL: &str = r#"
WITH RECURSIVE
current_db AS (
    SELECT database.oid, database.datdba, database.datacl
    FROM pg_catalog.pg_database AS database
    WHERE database.datname = current_database()
),
migration_role AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = $1
),
runtime_role AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = $2
),
database_owner_role AS (
    SELECT
        role.oid,
        role.rolcanlogin,
        role.rolsuper,
        role.rolcreaterole,
        role.rolcreatedb,
        role.rolreplication,
        role.rolbypassrls
    FROM current_db
    JOIN pg_catalog.pg_roles AS role
      ON role.oid = current_db.datdba
),
pg_database_owner_role AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'pg_database_owner'
),
trusted_acl_roles AS (
    SELECT oid FROM database_owner_role
    UNION
    SELECT oid FROM migration_role
    UNION
    SELECT oid FROM runtime_role
    UNION
    SELECT oid FROM pg_database_owner_role
),
trusted_creator_roles AS (
    SELECT oid FROM database_owner_role
    UNION
    SELECT oid FROM migration_role
),
trusted_grantor_roles AS (
    SELECT oid FROM database_owner_role
    UNION
    SELECT oid FROM migration_role
    UNION
    SELECT oid FROM pg_database_owner_role
),
protected_roles AS (
    SELECT oid FROM database_owner_role
    UNION
    SELECT oid FROM migration_role
    UNION
    SELECT oid FROM runtime_role
),
protected_role_members(oid) AS (
    SELECT membership.member
    FROM pg_catalog.pg_auth_members AS membership
    JOIN protected_roles AS protected
      ON protected.oid = membership.roleid
    UNION
    SELECT membership.member
    FROM pg_catalog.pg_auth_members AS membership
    JOIN protected_role_members AS inherited_member
      ON inherited_member.oid = membership.roleid
),
default_object_types(object_type) AS (
    VALUES
        ('r'::"char"),
        ('S'::"char"),
        ('f'::"char"),
        ('T'::"char"),
        ('n'::"char")
),
effective_global_defaults AS (
    SELECT
        creator.oid AS creator_oid,
        object_types.object_type,
        default_privilege.*
    FROM trusted_creator_roles AS creator
    CROSS JOIN default_object_types AS object_types
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(
            (
                SELECT default_acl.defaclacl
                FROM pg_catalog.pg_default_acl AS default_acl
                WHERE default_acl.defaclrole = creator.oid
                  AND default_acl.defaclnamespace = 0
                  AND default_acl.defaclobjtype = object_types.object_type
            ),
            pg_catalog.acldefault(object_types.object_type, creator.oid)
        )
    ) AS default_privilege
),
effective_schema_defaults AS (
    SELECT
        default_acl.defaclrole AS creator_oid,
        default_acl.defaclobjtype AS object_type,
        default_privilege.*
    FROM pg_catalog.pg_default_acl AS default_acl
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        default_acl.defaclacl
    ) AS default_privilege
    WHERE default_acl.defaclnamespace <> 0
),
semantic_object_owners AS (
    SELECT collation_record.collowner AS owner_oid
    FROM pg_catalog.pg_collation AS collation_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = collation_record.collnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT conversion_record.conowner
    FROM pg_catalog.pg_conversion AS conversion_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = conversion_record.connamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT operator_record.oprowner
    FROM pg_catalog.pg_operator AS operator_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = operator_record.oprnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT operator_class_record.opcowner
    FROM pg_catalog.pg_opclass AS operator_class_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = operator_class_record.opcnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT operator_family_record.opfowner
    FROM pg_catalog.pg_opfamily AS operator_family_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = operator_family_record.opfnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT text_search_config_record.cfgowner
    FROM pg_catalog.pg_ts_config AS text_search_config_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = text_search_config_record.cfgnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT text_search_dictionary_record.dictowner
    FROM pg_catalog.pg_ts_dict AS text_search_dictionary_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = text_search_dictionary_record.dictnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
    UNION ALL
    SELECT statistics_record.stxowner
    FROM pg_catalog.pg_statistic_ext AS statistics_record
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = statistics_record.stxnamespace
    WHERE namespace.nspname <> 'information_schema'
      AND namespace.nspname !~ '^pg_'
)
SELECT (
    NOT EXISTS (SELECT 1 FROM migration_role)
    OR NOT EXISTS (SELECT 1 FROM runtime_role)
    OR EXISTS (
        SELECT 1
        FROM migration_role
        CROSS JOIN runtime_role
        CROSS JOIN database_owner_role
        WHERE migration_role.oid = runtime_role.oid
           OR migration_role.oid = database_owner_role.oid
           OR runtime_role.oid = database_owner_role.oid
    )
    OR EXISTS (
        SELECT 1
        FROM database_owner_role
        WHERE database_owner_role.rolcanlogin
           OR database_owner_role.rolsuper
           OR database_owner_role.rolcreaterole
           OR database_owner_role.rolcreatedb
           OR database_owner_role.rolreplication
           OR database_owner_role.rolbypassrls
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.member IN (
            SELECT oid FROM migration_role
            UNION
            SELECT oid FROM runtime_role
            UNION
            SELECT oid FROM database_owner_role
        )
    )
    OR EXISTS (
        SELECT 1
        FROM current_db
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                current_db.datacl,
                pg_catalog.acldefault('d', current_db.datdba)
            )
        ) AS object_acl
        WHERE object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
           OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS namespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND namespace.nspowner NOT IN (
              SELECT oid FROM trusted_acl_roles
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS namespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                namespace.nspacl,
                pg_catalog.acldefault('n', namespace.nspowner)
            )
        ) AS object_acl
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND (
              object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
              OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND relation.relowner NOT IN (
              SELECT oid FROM trusted_creator_roles
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
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
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
          AND (
              object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
              OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute AS attribute
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = attribute.attrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            attribute.attacl
        ) AS object_acl
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND (
              object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
              OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS routine
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = routine.pronamespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND routine.proowner NOT IN (
              SELECT oid FROM trusted_creator_roles
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS routine
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = routine.pronamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                routine.proacl,
                pg_catalog.acldefault('f', routine.proowner)
            )
        ) AS object_acl
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND (
              object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
              OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS data_type
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname !~ '^pg_'
          AND data_type.typowner NOT IN (
              SELECT oid FROM trusted_creator_roles
          )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS data_type
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                data_type.typacl,
                pg_catalog.acldefault('T', data_type.typowner)
            )
        ) AS object_acl
        WHERE namespace.nspname <> 'information_schema'
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
          AND (
              object_acl.grantee NOT IN (
                  SELECT oid FROM trusted_acl_roles
              )
              OR object_acl.grantor NOT IN (
                  SELECT oid FROM trusted_grantor_roles
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM semantic_object_owners
        WHERE semantic_object_owners.owner_oid NOT IN (
            SELECT oid FROM trusted_creator_roles
        )
    )
    OR EXISTS (
        SELECT 1
        FROM effective_global_defaults AS default_privilege
        WHERE default_privilege.grantor <> default_privilege.creator_oid
           OR default_privilege.grantee <> default_privilege.creator_oid
    )
    OR EXISTS (
        SELECT 1
        FROM effective_schema_defaults AS default_privilege
        WHERE default_privilege.creator_oid NOT IN (
                  SELECT oid FROM trusted_creator_roles
              )
           OR default_privilege.grantor <> default_privilege.creator_oid
           OR default_privilege.grantee <> default_privilege.creator_oid
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_default_acl AS default_acl
        WHERE default_acl.defaclrole NOT IN (
            SELECT oid FROM trusted_creator_roles
        )
    )
    OR EXISTS (SELECT 1 FROM protected_role_members)
) AS has_untrusted_boundary
"#;

pub(super) async fn probe_external_pg_trusted_boundary(
    connection: &mut PgConnection,
    migration_role: &str,
    runtime_role: &str,
) -> Result<ExternalPgTrustedBoundaryProbe, sqlx::Error> {
    sqlx::query_as::<_, ExternalPgTrustedBoundaryProbe>(EXTERNAL_PG_TRUSTED_BOUNDARY_PROBE_SQL)
        .bind(migration_role)
        .bind(runtime_role)
        .fetch_one(&mut *connection)
        .await
}

pub(super) fn validate_external_pg_trusted_boundary(
    probe: &ExternalPgTrustedBoundaryProbe,
) -> Result<(), ExternalPgSessionPolicyError> {
    if probe.has_untrusted_boundary {
        return Err(session_policy_error(
            "external PostgreSQL contains an untrusted owner, ACL grantor/grantee, default-ACL creator, or role membership",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(super) struct ExternalPgClosedCatalogProbe {
    pub(super) has_unsupported_object: bool,
}

const EXTERNAL_PG_CLOSED_CATALOG_PROBE_SQL: &str = r#"
WITH
expected_tables(name) AS (
    SELECT pg_catalog.unnest($1::text[])
    UNION ALL
    SELECT '_sqlx_migrations'::text
),
expected_enums(name) AS (
    SELECT pg_catalog.unnest($2::text[])
),
expected_sequences(name) AS (
    SELECT pg_catalog.unnest($3::text[])
),
accepted_base_types AS (
    SELECT data_type.oid
    FROM pg_catalog.pg_type AS data_type
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = data_type.typnamespace
    JOIN expected_enums
      ON expected_enums.name = data_type.typname
    WHERE namespace.nspname = current_schema()
      AND data_type.typtype = 'e'
    UNION
    SELECT data_type.oid
    FROM pg_catalog.pg_type AS data_type
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = data_type.typnamespace
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid = data_type.typrelid
    JOIN expected_tables
      ON expected_tables.name = relation.relname
    WHERE namespace.nspname = current_schema()
      AND data_type.typtype = 'c'
      AND relation.relkind IN ('r', 'p')
),
accepted_types AS (
    SELECT oid FROM accepted_base_types
    UNION
    SELECT array_type.oid
    FROM pg_catalog.pg_type AS array_type
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = array_type.typnamespace
    JOIN accepted_base_types
      ON accepted_base_types.oid = array_type.typelem
    WHERE namespace.nspname = current_schema()
)
SELECT (
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
          AND relation.relkind IN ('r', 'p')
          AND relation.relname NOT IN (
              SELECT expected_tables.name FROM expected_tables
          )
    )
    OR EXISTS (
        SELECT 1
        FROM expected_tables
        WHERE NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = current_schema()
              AND relation.relname = expected_tables.name
              AND relation.relkind IN ('r', 'p')
        )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
          AND relation.relkind = 'S'
          AND relation.relname NOT IN (
              SELECT expected_sequences.name FROM expected_sequences
          )
    )
    OR EXISTS (
        SELECT 1
        FROM expected_sequences
        WHERE NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = current_schema()
              AND relation.relname = expected_sequences.name
              AND relation.relkind = 'S'
        )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
          AND relation.relkind NOT IN ('r', 'p', 'S', 'i', 'I')
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
          AND relation.relkind IN ('r', 'p')
          AND (relation.relrowsecurity OR relation.relforcerowsecurity)
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_rewrite AS rewrite_rule
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = rewrite_rule.ev_class
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_policy AS policy
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = policy.polrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS data_type
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = data_type.typnamespace
        WHERE namespace.nspname = current_schema()
          AND data_type.oid NOT IN (SELECT oid FROM accepted_types)
    )
    OR EXISTS (
        SELECT 1
        FROM expected_enums
        WHERE NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_type AS data_type
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = data_type.typnamespace
            WHERE namespace.nspname = current_schema()
              AND data_type.typname = expected_enums.name
              AND data_type.typtype = 'e'
        )
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_collation AS collation_record
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = collation_record.collnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_conversion AS conversion_record
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = conversion_record.connamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_operator AS operator_record
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = operator_record.oprnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_opclass AS operator_class
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = operator_class.opcnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_opfamily AS operator_family
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = operator_family.opfnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_ts_config AS text_search_config
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = text_search_config.cfgnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_ts_dict AS text_search_dictionary
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = text_search_dictionary.dictnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_ts_parser AS text_search_parser
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = text_search_parser.prsnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_ts_template AS text_search_template
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = text_search_template.tmplnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_statistic_ext AS statistics_record
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = statistics_record.stxnamespace
        WHERE namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_cast AS cast_record
        JOIN pg_catalog.pg_type AS source_type
          ON source_type.oid = cast_record.castsource
        JOIN pg_catalog.pg_namespace AS source_namespace
          ON source_namespace.oid = source_type.typnamespace
        JOIN pg_catalog.pg_type AS target_type
          ON target_type.oid = cast_record.casttarget
        JOIN pg_catalog.pg_namespace AS target_namespace
          ON target_namespace.oid = target_type.typnamespace
        WHERE source_namespace.nspname = current_schema()
           OR target_namespace.nspname = current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = routine.pronamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_type AS data_type
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = data_type.typnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_collation AS collation_record
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = collation_record.collnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_conversion AS conversion_record
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = conversion_record.connamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_operator AS operator_record
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = operator_record.oprnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_opclass AS operator_class
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = operator_class.opcnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_opfamily AS operator_family
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = operator_family.opfnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_ts_config AS text_search_config
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = text_search_config.cfgnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_ts_dict AS text_search_dictionary
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = text_search_dictionary.dictnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_ts_parser AS text_search_parser
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = text_search_parser.prsnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_ts_template AS text_search_template
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = text_search_template.tmplnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
            UNION ALL
            SELECT 1
            FROM pg_catalog.pg_statistic_ext AS statistics_record
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = statistics_record.stxnamespace
            WHERE namespace.nspname <> current_schema()
              AND namespace.nspname <> 'information_schema'
              AND namespace.nspname !~ '^pg_'
        ) AS off_path_object
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_trigger AS trigger_record
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = trigger_record.tgrelid
        JOIN pg_catalog.pg_namespace AS relation_namespace
          ON relation_namespace.oid = relation.relnamespace
        JOIN pg_catalog.pg_proc AS trigger_function
          ON trigger_function.oid = trigger_record.tgfoid
        JOIN pg_catalog.pg_namespace AS function_namespace
          ON function_namespace.oid = trigger_function.pronamespace
        WHERE relation_namespace.nspname = current_schema()
          AND NOT trigger_record.tgisinternal
          AND function_namespace.nspname <> current_schema()
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_extension AS extension_record
        WHERE extension_record.extname <> 'plpgsql'
    )
    OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_event_trigger
    )
    OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_publication
    )
    OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_foreign_server
    )
    OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_user_mappings
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_largeobject_metadata
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_cast AS cast_record
        WHERE cast_record.oid >= 16384
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_transform AS transform_record
        WHERE transform_record.oid >= 16384
    )
    OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_publication_rel AS publication_relation
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = publication_relation.prrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
    )
) AS has_unsupported_object
"#;

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(super) struct ExternalPgSemanticInventoryRow {
    pub(super) object_kind: String,
    pub(super) parent_name: String,
    pub(super) object_name: String,
    pub(super) definition: String,
}

pub(super) const EXTERNAL_PG_SEMANTIC_INVENTORY_SQL: &str = r#"
SELECT object_kind, parent_name, object_name, definition
FROM (
SELECT
    'table'::text AS object_kind,
    ''::text AS parent_name,
    relation.relname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'kind', relation.relkind::text,
        'persistence', relation.relpersistence::text,
        'replica_identity', relation.relreplident::text,
        'access_method', COALESCE(access_method.amname, ''),
        'tablespace', COALESCE(tablespace.spcname, ''),
        'options', COALESCE(
            pg_catalog.to_jsonb(relation.reloptions),
            '[]'::pg_catalog.jsonb
        ),
        'is_partition', relation.relispartition,
        'parents', COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    '<application-schema>.'
                    || pg_catalog.quote_ident(parent_relation.relname)
                    ORDER BY inheritance.inhseqno
                )
                FROM pg_catalog.pg_inherits AS inheritance
                JOIN pg_catalog.pg_class AS parent_relation
                  ON parent_relation.oid = inheritance.inhparent
                JOIN pg_catalog.pg_namespace AS parent_namespace
                  ON parent_namespace.oid = parent_relation.relnamespace
                WHERE inheritance.inhrelid = relation.oid
            ),
            '[]'::pg_catalog.jsonb
        ),
        'partition_key', COALESCE(
            pg_catalog.pg_get_partkeydef(relation.oid),
            ''
        ),
        'partition_bound', COALESCE(
            pg_catalog.pg_get_expr(
                relation.relpartbound,
                relation.oid,
                true
            ),
            ''
        )
    )::text AS definition
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
LEFT JOIN pg_catalog.pg_am AS access_method
  ON access_method.oid = relation.relam
LEFT JOIN pg_catalog.pg_tablespace AS tablespace
  ON tablespace.oid = relation.reltablespace
WHERE namespace.nspname = current_schema()
  AND relation.relkind IN ('r', 'p')
UNION ALL
SELECT
    'column'::text AS object_kind,
    relation.relname::text AS parent_name,
    attribute.attname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'position', attribute.attnum,
        'type', pg_catalog.format_type(
            attribute.atttypid,
            attribute.atttypmod
        ),
        'not_null', attribute.attnotnull,
        'identity', attribute.attidentity::text,
        'generated', attribute.attgenerated::text,
        'dimensions', attribute.attndims,
        'inherited_count', attribute.attinhcount,
        'is_local', attribute.attislocal,
        'storage', attribute.attstorage::text,
        'compression', attribute.attcompression::text,
        'has_missing_value', attribute.atthasmissing,
        'missing_value', COALESCE(attribute.attmissingval::text, ''),
        'options', COALESCE(
            pg_catalog.to_jsonb(attribute.attoptions),
            '[]'::pg_catalog.jsonb
        ),
        'foreign_options', COALESCE(
            pg_catalog.to_jsonb(attribute.attfdwoptions),
            '[]'::pg_catalog.jsonb
        ),
        'collation', CASE
            WHEN attribute.attcollation = 0 THEN ''
            ELSE attribute.attcollation::pg_catalog.regcollation::text
        END,
        'default', COALESCE(
            pg_catalog.pg_get_expr(
                column_default.adbin,
                column_default.adrelid,
                true
            ),
            ''
        )
    )::text AS definition
FROM pg_catalog.pg_attribute AS attribute
JOIN pg_catalog.pg_class AS relation
  ON relation.oid = attribute.attrelid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
LEFT JOIN pg_catalog.pg_attrdef AS column_default
  ON column_default.adrelid = attribute.attrelid
 AND column_default.adnum = attribute.attnum
WHERE namespace.nspname = current_schema()
  AND relation.relkind IN ('r', 'p')
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped
UNION ALL
SELECT
    'sequence'::text AS object_kind,
    ''::text AS parent_name,
    relation.relname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'type', pg_catalog.format_type(sequence.seqtypid, NULL),
        'start', sequence.seqstart,
        'increment', sequence.seqincrement,
        'maximum', sequence.seqmax,
        'minimum', sequence.seqmin,
        'cache', sequence.seqcache,
        'cycle', sequence.seqcycle,
        'owned_by', COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'table',
                            '<application-schema>.'
                            || pg_catalog.quote_ident(owned_relation.relname),
                        'column', owned_attribute.attname,
                        'dependency_type', dependency.deptype::text
                    )
                    ORDER BY
                        owned_namespace.nspname,
                        owned_relation.relname,
                        owned_attribute.attnum,
                        dependency.deptype
                )
                FROM pg_catalog.pg_depend AS dependency
                JOIN pg_catalog.pg_class AS owned_relation
                  ON owned_relation.oid = dependency.refobjid
                JOIN pg_catalog.pg_namespace AS owned_namespace
                  ON owned_namespace.oid = owned_relation.relnamespace
                JOIN pg_catalog.pg_attribute AS owned_attribute
                  ON owned_attribute.attrelid = dependency.refobjid
                 AND owned_attribute.attnum = dependency.refobjsubid
                WHERE dependency.classid =
                      'pg_catalog.pg_class'::pg_catalog.regclass
                  AND dependency.objid = relation.oid
                  AND dependency.objsubid = 0
                  AND dependency.refclassid =
                      'pg_catalog.pg_class'::pg_catalog.regclass
                  AND dependency.deptype IN ('a', 'i')
            ),
            '[]'::pg_catalog.jsonb
        )
    )::text AS definition
FROM pg_catalog.pg_sequence AS sequence
JOIN pg_catalog.pg_class AS relation
  ON relation.oid = sequence.seqrelid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = current_schema()
UNION ALL
SELECT
    'enum-label'::text AS object_kind,
    data_type.typname::text AS parent_name,
    enum_record.enumlabel::text AS object_name,
    pg_catalog.jsonb_build_object(
        'sort_order', enum_record.enumsortorder::text
    )::text AS definition
FROM pg_catalog.pg_enum AS enum_record
JOIN pg_catalog.pg_type AS data_type
  ON data_type.oid = enum_record.enumtypid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = data_type.typnamespace
WHERE namespace.nspname = current_schema()
UNION ALL
SELECT
    'routine'::text AS object_kind,
    ''::text AS parent_name,
    (
        routine.proname
        || '('
        || pg_catalog.pg_get_function_identity_arguments(routine.oid)
        || ')'
    )::text AS object_name,
    pg_catalog.jsonb_build_object(
        'kind', routine.prokind::text,
        'language', language.lanname,
        'arguments', pg_catalog.pg_get_function_arguments(routine.oid),
        'result', pg_catalog.pg_get_function_result(routine.oid),
        'returns_set', routine.proretset,
        'variadic_type', CASE
            WHEN routine.provariadic = 0 THEN ''
            ELSE pg_catalog.format_type(routine.provariadic, NULL)
        END,
        'transform_types', COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.format_type(
                        transform_type_oid,
                        NULL
                    )
                    ORDER BY transform_position
                )
                FROM pg_catalog.unnest(
                    routine.protrftypes::oid[]
                ) WITH ORDINALITY AS transform_type(
                    transform_type_oid,
                    transform_position
                )
            ),
            '[]'::pg_catalog.jsonb
        ),
        'volatility', routine.provolatile::text,
        'parallel', routine.proparallel::text,
        'strict', routine.proisstrict,
        'security_definer', routine.prosecdef,
        'leakproof', routine.proleakproof,
        'cost', routine.procost::text,
        'rows', routine.prorows::text,
        'support', CASE
            WHEN routine.prosupport = 0 THEN ''
            ELSE routine.prosupport::pg_catalog.regprocedure::text
        END,
        'configuration', COALESCE(
            pg_catalog.to_jsonb(routine.proconfig),
            '[]'::pg_catalog.jsonb
        ),
        'binary', COALESCE(routine.probin, ''),
        'source', routine.prosrc,
        'sql_body', COALESCE(
            pg_catalog.pg_get_expr(routine.prosqlbody, 0, true),
            ''
        )
    )::text AS definition
FROM pg_catalog.pg_proc AS routine
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = routine.pronamespace
JOIN pg_catalog.pg_language AS language
  ON language.oid = routine.prolang
WHERE namespace.nspname = current_schema()
UNION ALL
SELECT
    'trigger'::text AS object_kind,
    relation.relname::text AS parent_name,
    trigger_record.tgname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'function',
            '<application-schema>.'
            || pg_catalog.quote_ident(trigger_function.proname)
            || '('
            || pg_catalog.pg_get_function_identity_arguments(
                trigger_function.oid
            )
            || ')',
        'type', trigger_record.tgtype,
        'enabled', trigger_record.tgenabled::text,
        'deferrable', trigger_record.tgdeferrable,
        'initially_deferred', trigger_record.tginitdeferred,
        'columns', trigger_record.tgattr::text,
        'arguments_hex', pg_catalog.encode(trigger_record.tgargs, 'hex'),
        'when', COALESCE(
            pg_catalog.pg_get_expr(
                trigger_record.tgqual,
                trigger_record.tgrelid,
                true
            ),
            ''
        ),
        'constraint', COALESCE(trigger_constraint.conname, ''),
        'constraint_relation', COALESCE(
            constraint_relation.relname,
            ''
        ),
        'parent_trigger', COALESCE(parent_trigger.tgname, ''),
        'parent_relation', COALESCE(parent_relation.relname, ''),
        'old_transition_table', COALESCE(trigger_record.tgoldtable, ''),
        'new_transition_table', COALESCE(trigger_record.tgnewtable, '')
    )::text AS definition
FROM pg_catalog.pg_trigger AS trigger_record
JOIN pg_catalog.pg_class AS relation
  ON relation.oid = trigger_record.tgrelid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
JOIN pg_catalog.pg_proc AS trigger_function
  ON trigger_function.oid = trigger_record.tgfoid
JOIN pg_catalog.pg_namespace AS trigger_function_namespace
  ON trigger_function_namespace.oid = trigger_function.pronamespace
LEFT JOIN pg_catalog.pg_constraint AS trigger_constraint
  ON trigger_constraint.oid = trigger_record.tgconstraint
LEFT JOIN pg_catalog.pg_class AS constraint_relation
  ON constraint_relation.oid = trigger_record.tgconstrrelid
LEFT JOIN pg_catalog.pg_trigger AS parent_trigger
  ON parent_trigger.oid = trigger_record.tgparentid
LEFT JOIN pg_catalog.pg_class AS parent_relation
  ON parent_relation.oid = parent_trigger.tgrelid
WHERE namespace.nspname = current_schema()
  AND NOT trigger_record.tgisinternal
UNION ALL
SELECT
    'index'::text AS object_kind,
    parent.relname::text AS parent_name,
    index_relation.relname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'access_method', access_method.amname,
        'persistence', index_relation.relpersistence::text,
        'tablespace', COALESCE(tablespace.spcname, ''),
        'relation_options', COALESCE(
            pg_catalog.to_jsonb(index_relation.reloptions),
            '[]'::pg_catalog.jsonb
        ),
        'keys', (
            SELECT pg_catalog.jsonb_agg(
                pg_catalog.pg_get_indexdef(
                    index_relation.oid,
                    key_position,
                    true
                )
                ORDER BY key_position
            )
            FROM pg_catalog.generate_series(
                1,
                index_record.indnatts
            ) AS key_position
        ),
        'key_count', index_record.indnkeyatts,
        'collations', (
            SELECT pg_catalog.jsonb_agg(
                CASE
                    WHEN collation_oid = 0 THEN ''
                    ELSE pg_catalog.quote_ident(collation_namespace.nspname)
                         || '.'
                         || pg_catalog.quote_ident(collation_record.collname)
                END
                ORDER BY collation_position
            )
            FROM pg_catalog.unnest(
                index_record.indcollation::oid[]
            ) WITH ORDINALITY AS index_collation(
                collation_oid,
                collation_position
            )
            LEFT JOIN pg_catalog.pg_collation AS collation_record
              ON collation_record.oid = index_collation.collation_oid
            LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
              ON collation_namespace.oid = collation_record.collnamespace
        ),
        'operator_classes', (
            SELECT pg_catalog.jsonb_agg(
                pg_catalog.quote_ident(operator_namespace.nspname)
                || '.'
                || pg_catalog.quote_ident(operator_class.opcname)
                ORDER BY operator_position
            )
            FROM pg_catalog.unnest(
                index_record.indclass::oid[]
            ) WITH ORDINALITY AS index_operator_class(
                operator_class_oid,
                operator_position
            )
            JOIN pg_catalog.pg_opclass AS operator_class
              ON operator_class.oid =
                 index_operator_class.operator_class_oid
            JOIN pg_catalog.pg_namespace AS operator_namespace
              ON operator_namespace.oid = operator_class.opcnamespace
        ),
        'options', index_record.indoption::text,
        'predicate', COALESCE(
            pg_catalog.pg_get_expr(
                index_record.indpred,
                index_record.indrelid,
                true
            ),
            ''
        ),
        'unique', index_record.indisunique,
        'nulls_not_distinct', index_record.indnullsnotdistinct,
        'primary', index_record.indisprimary,
        'exclusion', index_record.indisexclusion,
        'immediate', index_record.indimmediate,
        'clustered', index_record.indisclustered,
        'valid', index_record.indisvalid,
        'check_xmin', index_record.indcheckxmin,
        'ready', index_record.indisready,
        'live', index_record.indislive,
        'replica_identity', index_record.indisreplident
    )::text AS definition
FROM pg_catalog.pg_index AS index_record
JOIN pg_catalog.pg_class AS index_relation
  ON index_relation.oid = index_record.indexrelid
JOIN pg_catalog.pg_class AS parent
  ON parent.oid = index_record.indrelid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = parent.relnamespace
JOIN pg_catalog.pg_am AS access_method
  ON access_method.oid = index_relation.relam
LEFT JOIN pg_catalog.pg_tablespace AS tablespace
  ON tablespace.oid = index_relation.reltablespace
WHERE namespace.nspname = current_schema()
UNION ALL
SELECT
    'constraint'::text AS object_kind,
    COALESCE(parent.relname::text, data_type.typname::text, '') AS parent_name,
    constraint_record.conname::text AS object_name,
    pg_catalog.jsonb_build_object(
        'definition', pg_catalog.pg_get_constraintdef(
            constraint_record.oid,
            true
        ),
        'type', constraint_record.contype::text,
        'deferrable', constraint_record.condeferrable,
        'deferred', constraint_record.condeferred,
        'validated', constraint_record.convalidated,
        'noinherit', constraint_record.connoinherit,
        'is_local', constraint_record.conislocal,
        'inheritance_count', constraint_record.coninhcount,
        'backing_index', COALESCE(constraint_index.relname, ''),
        'parent_constraint', COALESCE(parent_constraint.conname, ''),
        'parent_constraint_table', COALESCE(
            parent_constraint_relation.relname,
            ''
        )
    )::text AS definition
FROM pg_catalog.pg_constraint AS constraint_record
LEFT JOIN pg_catalog.pg_class AS parent
  ON parent.oid = constraint_record.conrelid
LEFT JOIN pg_catalog.pg_type AS data_type
  ON data_type.oid = constraint_record.contypid
LEFT JOIN pg_catalog.pg_class AS constraint_index
  ON constraint_index.oid = constraint_record.conindid
LEFT JOIN pg_catalog.pg_constraint AS parent_constraint
  ON parent_constraint.oid = constraint_record.conparentid
LEFT JOIN pg_catalog.pg_class AS parent_constraint_relation
  ON parent_constraint_relation.oid = parent_constraint.conrelid
WHERE constraint_record.connamespace = (
    SELECT namespace.oid
    FROM pg_catalog.pg_namespace AS namespace
    WHERE namespace.nspname = current_schema()
)
-- PostgreSQL only allows bare result-column names in a UNION's ORDER BY, so
-- the union is wrapped in a subquery and the collation-pinned sort applied
-- outside it.
) AS semantic_inventory
ORDER BY
    object_kind COLLATE "C",
    parent_name COLLATE "C",
    object_name COLLATE "C",
    definition COLLATE "C"
"#;

pub(super) fn external_pg_semantic_inventory_digest(
    rows: &[ExternalPgSemanticInventoryRow],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"OLY:EXTERNAL-PG:SEMANTIC-INVENTORY:V1");
    for row in rows {
        for value in [
            row.object_kind.as_bytes(),
            row.parent_name.as_bytes(),
            row.object_name.as_bytes(),
            row.definition.as_bytes(),
        ] {
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
    }
    hasher.finalize().to_hex().to_string()
}

pub(super) async fn probe_external_pg_closed_catalog(
    connection: &mut PgConnection,
) -> Result<
    (
        ExternalPgClosedCatalogProbe,
        Vec<ExternalPgSemanticInventoryRow>,
    ),
    sqlx::Error,
> {
    let expected_tables = EXTERNAL_PG_TABLE_GRANTS
        .iter()
        .map(|grant| grant.name.to_owned())
        .collect::<Vec<_>>();
    let expected_enums = EXTERNAL_PG_ENUM_TYPES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let expected_sequences = EXTERNAL_PG_SEQUENCE_GRANTS
        .iter()
        .map(|grant| grant.name.to_owned())
        .collect::<Vec<_>>();
    let unsupported =
        sqlx::query_as::<_, ExternalPgClosedCatalogProbe>(EXTERNAL_PG_CLOSED_CATALOG_PROBE_SQL)
            .bind(expected_tables)
            .bind(expected_enums)
            .bind(expected_sequences)
            .fetch_one(&mut *connection)
            .await?;
    let semantic_inventory =
        sqlx::query_as::<_, ExternalPgSemanticInventoryRow>(EXTERNAL_PG_SEMANTIC_INVENTORY_SQL)
            .fetch_all(&mut *connection)
            .await?;
    Ok((unsupported, semantic_inventory))
}

pub(super) fn validate_external_pg_closed_catalog(
    unsupported: &ExternalPgClosedCatalogProbe,
    semantic_inventory: &[ExternalPgSemanticInventoryRow],
) -> Result<(), ExternalPgSessionPolicyError> {
    if unsupported.has_unsupported_object {
        return Err(session_policy_error(
            "the application schema contains an unsupported executable or semantic object class",
        ));
    }
    if external_pg_semantic_inventory_digest(semantic_inventory)
        != EXTERNAL_PG_SEMANTIC_INVENTORY_BLAKE3
    {
        return Err(session_policy_error(
            "the application semantic inventory differs from the reviewed release",
        ));
    }
    Ok(())
}
