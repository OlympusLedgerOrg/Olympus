# External PostgreSQL role contract

This is the release-pinned external-database privilege and maintenance
contract for Olympus v0.10.0. `src-tauri/src/db.rs` enforces it at startup and
again before every runtime-pool checkout. The catalog representation is pinned
to PostgreSQL 15.x, matching the verified 15.16 embedded package; other major
versions are rejected.

1. The migration role acquires a cluster-unique advisory key composed from a
   fixed Olympus namespace and the live database OID, then proves its identity,
   database, and exact one-literal application `search_path`.
2. It revokes runtime `CONNECT`, including dependent grants, and refuses to
   continue until the runtime role has no effective `CONNECT`, no live sessions,
   and no prepared transactions. Inherited and `PUBLIC` access is included.
3. Before any migration, it removes every non-owner application-schema grant
   and hardens both global and per-schema migration-role defaults.
4. It applies migrations, hardens again, verifies the closed release catalog
   and trusted role boundary, and installs only the exact reviewed DML matrix.
5. It restores non-grantable runtime `CONNECT` last. The migration session then
   acquires the shared form of the same lock before releasing its exclusive
   form. Every physical runtime-pool connection acquires the shared lock once;
   a non-expiring minimum connection keeps it for the pool lifetime. The
   migration session closes only after that first runtime lock is established,
   so there is no unlocked handoff interval.

Before the exclusive lock is released, any failure re-hardens the application
schema and leaves normal runtime login disabled. A handoff failure after release
may mutate policy only after the migration session reacquires the exclusive
lock; otherwise it makes no competing policy change and requires operator
recovery. Runtime connections are attested on creation and before every
checkout, including proof that the connection still holds its shared lifecycle
lock, so pooled session, role, ACL, owner, or catalog drift fails closed.

Errors are deliberately value-blind: URLs, credentials, role names, database
names, schema names, and driver diagnostics are not echoed.

## One-time bootstrap provisioning

Use a dedicated database containing only Olympus objects. The trusted roles
are exactly:

- `olympus_db_owner`: neutral `NOLOGIN` database owner with no administrative
  attributes and no explicit role memberships.
- `olympus_migrator`: login and direct owner of the sole application schema and
  every application object. Its only database grant option is `CONNECT`, which
  is required to disconnect and reconnect the runtime role.
- `olympus_runtime`: login with no ownership, DDL, grant option, or role
  membership.
- PostgreSQL's predefined `pg_database_owner`, only where PostgreSQL uses it
  internally.

No other role may own a non-system object, appear as an ACL grantor or grantee,
hold a database/schema/object/default ACL, own a default-ACL entry, or be able
to assume a trusted role. Neither application role may assume any other role.

Run this through a separately controlled bootstrap administrator. Provision
passwords through the provider's secret mechanism rather than shell history.

```sql
CREATE ROLE olympus_db_owner
    NOLOGIN
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

CREATE ROLE olympus_migrator
    LOGIN
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD 'provision-through-your-secret-manager';

CREATE ROLE olympus_runtime
    LOGIN
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD 'provision-through-your-secret-manager';

REVOKE olympus_migrator FROM olympus_runtime;
REVOKE olympus_runtime FROM olympus_migrator;

ALTER DATABASE olympus OWNER TO olympus_db_owner;
REVOKE ALL PRIVILEGES ON DATABASE olympus FROM PUBLIC;
REVOKE ALL PRIVILEGES ON DATABASE olympus FROM olympus_runtime;
GRANT CONNECT ON DATABASE olympus
    TO olympus_migrator WITH GRANT OPTION;
REVOKE CREATE, TEMPORARY ON DATABASE olympus
    FROM olympus_migrator, olympus_runtime;

ALTER SCHEMA public OWNER TO olympus_migrator;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC, olympus_runtime;

-- Harden the neutral owner's global defaults. The FUNCTION and TYPE
-- revocations remove PostgreSQL's ambient PUBLIC defaults.
ALTER DEFAULT PRIVILEGES FOR ROLE olympus_db_owner
    REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE olympus_db_owner
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE olympus_db_owner
    REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE olympus_db_owner
    REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE olympus_db_owner
    REVOKE ALL PRIVILEGES ON SCHEMAS FROM PUBLIC;

-- Repeat these four IN SCHEMA statements for every non-system schema.
ALTER DEFAULT PRIVILEGES FOR ROLE olympus_db_owner IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE olympus_db_owner IN SCHEMA public
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE olympus_db_owner IN SCHEMA public
    REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE olympus_db_owner IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC;

ALTER ROLE olympus_migrator IN DATABASE olympus SET search_path TO public;
ALTER ROLE olympus_runtime IN DATABASE olympus SET search_path TO public;
```

Do not grant runtime `CONNECT` or schema `USAGE` during bootstrap; Olympus
installs them only after a successful maintenance pass. Revoke all privileges
from `PUBLIC` and every untrusted role on every other non-system schema. An
empty, locked `public` schema may remain off-path, but no application or
third-party objects may remain there.

A custom application schema is supported and preferred for new deployments.
Create it with `AUTHORIZATION olympus_migrator`, apply the same revocations and
neutral-owner per-schema defaults, and configure both roles to the same single
literal name. Entries such as `$user`, `missing_schema, app`, `pg_temp, app`,
or `app, extensions` are rejected even when PostgreSQL resolves them to one
existing schema.

### Existing populated deployments

Take and verify a restorable backup first. Stop every Olympus process and end
all runtime sessions and prepared transactions. Keep the deployed schema
(normally `public`) but separate its ownership from database ownership.

If the legacy application login already owns the database and objects, run the
ownership split as the bootstrap administrator. `REASSIGN OWNED` must run while
connected to the Olympus database:

```sql
-- Skip this statement when the legacy owner is already olympus_migrator.
REASSIGN OWNED BY olympus_legacy_app TO olympus_migrator;

ALTER DATABASE olympus OWNER TO olympus_db_owner;
ALTER SCHEMA public OWNER TO olympus_migrator;

REVOKE ALL PRIVILEGES ON DATABASE olympus FROM PUBLIC, olympus_runtime;
GRANT CONNECT ON DATABASE olympus
    TO olympus_migrator WITH GRANT OPTION;
REVOKE CREATE, TEMPORARY ON DATABASE olympus
    FROM olympus_migrator, olympus_runtime;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC, olympus_runtime;
```

Apply the neutral-owner default ACLs from the bootstrap section. Inventory every
non-system owner, ACL, default ACL, and membership before startup; remove
anything outside the four trusted identities above. Olympus refuses mixed
ownership. The live upgrade test starts with a migration-owned database,
populates it, transfers the database to a neutral owner, injects third-role and
semantic drift, proves startup remains disconnected, removes the drift, and
then verifies the retained ledger row and `_sqlx_migrations` history.

## Maintenance failure and recovery

SQLx migrations are transactional one file at a time, not as one transaction
for the whole release. Before an upgrade:

1. Take and verify a restorable database backup.
2. Stop every Olympus instance. Confirm zero runtime-role sessions and prepared
   transactions, including sessions authenticated through a member role.
3. Start one Olympus instance. Its runtime pool holds the shared lifecycle lock
   until shutdown. A second starter cannot acquire the exclusive form and fails
   before revoking `CONNECT`, checking quiescence, or running a migration.

If startup fails while it still owns the exclusive lock, Olympus leaves runtime
`CONNECT` revoked and removes non-owner application ACLs. Do not manually
re-grant runtime access. Keep the application stopped, inspect
`_sqlx_migrations`, and either:

- fix the ownership/ACL/catalog condition forward and rerun the same reviewed
  binary; or
- restore the verified pre-upgrade backup if rollback is required.

If automatic cleanup reports failure, Olympus could not reacquire or safely use
the exclusive lock after handoff. First stop every Olympus process and confirm
that no shared lifecycle-lock holder or runtime session remains. The database
owner must then run:

```sql
REVOKE CONNECT ON DATABASE olympus FROM olympus_runtime CASCADE;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM olympus_runtime, PUBLIC CASCADE;
```

Then terminate remaining runtime sessions, resolve prepared transactions under
the provider's incident procedure, and restore or fix forward. Normal runtime
access is restored only by a later successful, fully attested Olympus startup.

## Closed catalog inventory

The release manifest pins exact tables, columns, sequence ownership, enum
labels, indexes (including storage options, included keys, null-distinctness,
unique/primary/exclusion/cluster/replica-identity flags, predicates, operator
classes, and validity state), and constraints (including backing and parent
relationships). Startup rejects unexpected or missing objects and a digest
mismatch.

The application schema also rejects views, materialized views, foreign tables,
unexpected routines or non-internal triggers, rewrite rules, row-security
policies, standalone types (including composite/domain/range classes),
collations, conversions, operators and operator classes/families, text-search
objects, extended statistics, non-PL/pgSQL extensions, event triggers,
publications, foreign servers/user mappings, large objects, user-defined
casts/transforms, and any object in an off-path non-system schema. A reviewed
routine/trigger is encoded in the same semantic digest, including its body,
canonical application-schema-qualified function identity, and trigger wiring;
runtime and `PUBLIC` still receive no routine `EXECUTE`. Owners and ACL
grantors/grantees are checked across every non-system schema, not only for
`PUBLIC` and the runtime role.

Any reviewed migration that intentionally changes these semantics must update
the release digest, privilege manifest, documentation, and live upgrade tests
in the same change.

## Connection URLs and ambient environment

Production URLs must explicitly contain the user, password field, hostname,
port, database, and `sslmode=verify-full`:

```text
DATABASE_URL=postgresql://olympus_runtime:...@db.example.com:5432/olympus?sslmode=verify-full
OLYMPUS_DATABASE_MIGRATION_URL=postgresql://olympus_migrator:...@db.example.com:5432/olympus?sslmode=verify-full
```

With no `sslrootcert` URL parameter, the compiled Rustls/WebPKI public roots are
the trust policy. A private CA must be selected explicitly with the reviewed
`sslrootcert` path in each URL. `PGSSLROOTCERT` cannot alter that choice.

All SQLx/libpq-shaped PostgreSQL environment variables must be unset:
`PGHOST`, `PGHOSTADDR`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`,
`PGPASSFILE`, `PGSSLMODE`, `PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`,
`PGAPPNAME`, and `PGOPTIONS`. URL `options` / `options[...]` parameters and
production query-parameter overrides for host, port, database, user, or
password are rejected.

## v0.10.0 table privileges

An em dash means no table-level runtime privilege. `_sqlx_migrations` is always
migration-only.

| Table | Table-level runtime privileges |
|---|---|
| `agencies` | — |
| `key_credentials` | `SELECT`, `INSERT` |
| `public_records_requests` | — |
| `appeals` | — |
| `doc_commits` | `SELECT`, `INSERT` |
| `dataset_artifacts` | `SELECT` |
| `dataset_artifact_files` | — |
| `dataset_lineage_events` | `SELECT` |
| `ledger_activities` | `SELECT`, `INSERT` |
| `tsa_jobs` | — |
| `password_recovery_tokens` | `SELECT`, `INSERT` |
| `rekor_anchors` | — |
| `users` | `SELECT`, `INSERT`, `DELETE` |
| `api_keys` | `SELECT`, `INSERT`, `DELETE` |
| `account_signing_keys` | `SELECT`, `INSERT` |
| `account_wallet_bindings` | — |
| `credential_consents` | — |
| `credential_ledger_events` | `SELECT` |
| `operators` | `SELECT`, `INSERT` |
| `anchor_receipts` | `SELECT`, `INSERT` |
| `peer_checkpoints` | `SELECT`, `INSERT` |
| `credential_quorum_signatures` | `SELECT`, `INSERT` |
| `peer_nodes` | `SELECT`, `INSERT` |
| `smt_nodes` | `SELECT`, `INSERT` |
| `smt_leaves` | `SELECT`, `INSERT` |
| `shards` | `SELECT`, `INSERT` |
| `ingest_records` | `SELECT`, `INSERT` |
| `own_checkpoints` | `SELECT`, `INSERT` |
| `checkpoint_quorum_signatures` | `SELECT`, `INSERT` |
| `redaction_segment_manifests` | `SELECT`, `INSERT` |
| `signed_request_nonces` | `INSERT`, `DELETE` |
| `anchor_submission_claims` | `SELECT`, `INSERT` |
| `_sqlx_migrations` | — |

There is no table-wide runtime `UPDATE`, `TRUNCATE`, `REFERENCES`, or `TRIGGER`
grant.

## Exact column privileges

| Table | Privilege | Columns |
|---|---|---|
| `key_credentials` | `UPDATE` | `revoked_at`, `revoked_sig_r8x`, `revoked_sig_r8y`, `revoked_sig_s` |
| `password_recovery_tokens` | `UPDATE` | `used_at` |
| `users` | `UPDATE` | `password_hash`, `role` |
| `api_keys` | `UPDATE` | `key_hash`, `revoked_at`, `scopes`, `operator_id`, `ed25519_public_key` |
| `account_signing_keys` | `UPDATE` | `bjj_pubkey_x`, `bjj_pubkey_y`, `revoked_at`, `replaced_by_key_id`, `revoked_by_key_id` |
| `anchor_receipts` | `UPDATE` | `verified_at`, `ots_upgrade_lease_token`, `ots_upgrade_lease_until`, `ots_upgrade_attempts`, `ots_last_upgrade_attempt_at`, `ots_next_upgrade_attempt_at`, `ots_last_upgrade_error` |
| `peer_checkpoints` | `UPDATE` | `equivocation_detected` |
| `peer_nodes` | `UPDATE` | `trust_status`, `removed_at`, `last_seen_at`, `last_pull_error_at`, `last_pull_error_msg` |
| `smt_nodes` | `UPDATE` | `hash` |
| `ingest_records` | `UPDATE` | `chunk_hashes`, `original_root`, `snapshot_root`, `snapshot_index`, `snapshot_size`, `snapshot_path`, `snapshot_sig`, `snapshot_committed`, `zk_bundle`, `smt_committed` |
| `signed_request_nonces` | `SELECT` | `key_id`, `nonce`, `expires_at` |
| `anchor_submission_claims` | `UPDATE` | `checkpoint_id`, `status`, `receipt_id`, `lease_token`, `lease_until`, `attempt_count`, `last_attempt_at`, `next_retry_at`, `last_error`, `updated_at` |

The nonce `SELECT` columns are exactly those used by `DELETE` predicates.
`doc_commits` handles duplicate inserts with `DO NOTHING` plus a read, and the
write-once redaction manifest read takes no row-update lock. Immutable evidence
columns therefore remain unmodifiable by the runtime identity.

## Sequences, routines, types, defaults, and grant options

The retired `display_id_seq` and `rekor_anchors_id_seq` sequences have no
runtime privilege. Only routines/triggers pinned by the semantic digest may
exist, and neither runtime nor `PUBLIC` receives routine `EXECUTE`. Runtime and
`PUBLIC` receive no application-type privilege.

PostgreSQL's global defaults grant `PUBLIC EXECUTE` on new functions and
`PUBLIC USAGE` on new types. Olympus revokes those global base defaults first,
then clears per-schema additive entries for every non-system schema. Future
migrator-owned tables, sequences, functions, and types therefore grant nothing
to `PUBLIC` or the runtime role until the release manifest is deliberately
updated.

Every direct runtime ACL is checked for `WITH GRANT OPTION`; any grant option is
rejected. Direct or `PUBLIC` access to off-path non-system schemas and their
objects is also rejected.
