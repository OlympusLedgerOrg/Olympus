# ADR-0039: Transactional database-agnostic SMT storage

**Status:** Accepted
**Date:** 2026-07-13

## Context

The persistent sparse Merkle tree originally exposed independent backend
methods for acquiring a writer lock, reading nodes/leaves, and writing the two
tables. PostgreSQL's session advisory lock serialized cooperating writers, but
`put_leaves` and `put_nodes` ran as separate autocommit statements obtained from
the pool. A failure between them could therefore leave durable leaf preimages
and internal nodes describing different trees. The resident hot cache was also
updated before node persistence succeeded.

Olympus wants an SQLite implementation for local SMT deployments without
discarding PostgreSQL's array batching, indexes, JSONB elsewhere in the app, or
multi-process production behavior.

## Decision

`NodeBackend` is a semantic storage boundary, not a generic SQL dialect. It
provides read operations plus backend-owned read and write transactions.
`begin_write` returns an associated transaction type that:

1. owns writer serialization before reading the working set;
2. implements the same batch read contract;
3. stages both leaf and internal-node writes; and
4. atomically commits or rolls back the complete batch.

`begin_read` returns a stable snapshot for multi-query proof construction.
PostgreSQL uses `REPEATABLE READ READ ONLY`; SQLite uses a deferred read
transaction. Proofs establish that snapshot with a durable root probe and
reuse the resident hot cache only when its cached root matches. Otherwise the
hot nodes reload inside the snapshot. Direct root probes bypass the cache so a
handle observes commits made by another process.

`PersistentSmt::update_batch` validates caller input before beginning the
transaction. It then reloads hot nodes, scans canopies, enforces write-once,
computes the tree, and writes both tables through that transaction. The next
hot cache is published only after a successful commit; an ambiguous commit
failure invalidates the cache.

Backend mechanisms are deliberately native:

- PostgreSQL begins an explicit `READ COMMITTED` SQL transaction and takes
  `pg_advisory_xact_lock` on the stable Olympus writer key with a transaction-
  local five-second `lock_timeout`. Pinning isolation
  prevents an operator-level `REPEATABLE READ` default from creating a stale
  snapshot while the lock statement waits. Array binds, `ANY`, and `UNNEST`
  remain private to the PostgreSQL implementation.
- SQLite starts with `BEGIN IMMEDIATE`, making SQLite's cross-process writer
  reservation and the atomic SMT unit the same boundary. It uses chunked
  prepared statements and BLOB primary-key range scans.
- The in-memory backend clones committed state after taking its async writer
  permit and swaps the staged maps together on commit.

`SmtStorageBackend` is a concrete runtime enum. It preserves SQLx's concrete
database types and static dispatch without requiring an object-safe async
trait or reducing PostgreSQL to SQLite's feature set.

## SQLite durability and schema

SQLite has a separate, versioned `migrations-sqlite/` directory containing
only the final SMT schema. Tables are `STRICT` and `WITHOUT ROWID`; database
checks pin 32-byte hashes/keys, non-empty provenance, and the canonical
MSB-first packed path representation from migration 0043.

The bundled connection factory uses rollback-journal `DELETE`,
`synchronous=EXTRA`, normal locking, a bounded busy timeout, foreign keys, and
`trusted_schema=OFF`. `EXTRA` syncs the containing directory when the rollback
journal is removed, preserving durability of an acknowledged commit across
power loss. WAL is not enabled until Olympus qualifies a bundled SQLite
release containing the relevant multi-connection WAL recovery fixes.

Only plain `sqlite:` URLs and paths are accepted. URI options and caller-owned
pools are not public because options such as `vfs=unix-none`, `immutable`, or
read-only mode can defeat file locking or writes, and connection-local PRAGMAs
cannot be proven for an arbitrary pool. SQLite files must live on a local
filesystem with supported locking semantics. The schema uses the dedicated
`_olympus_smt_migrations` history table so it cannot collide with another
component's SQLx migration version numbers.

## Scope and backend switching

This decision makes only the SMT storage layer database-agnostic. Application
state, authentication, ingest rows, anchoring, quorum, federation, JSONB, and
the main migrations remain PostgreSQL-backed. Adding SQLite does not by itself
remove `pg_embed` from the desktop application.

Changing the active backend for a non-empty deployment is a migration, not a
configuration flip. `ingest_records.smt_committed` and historical roots must be
copied/rebuilt and root-checked before selection changes. Until a generation-
tagged migration workflow is implemented, production application wiring stays
on `PgBackend`; embedders and tests may select `SqliteBackend` or the runtime
enum explicitly.

## Consequences

- Acknowledged SMT batches cannot expose leaves without their corresponding
  nodes, or vice versa.
- PostgreSQL-specific performance features remain available inside its
  implementation.
- SQLite provides a lower-maintenance SMT option with one serialized writer.
- Multi-query proof reads are snapshot-consistent, and stale handles validate
  their hot cache against the snapshot root before reuse.
- SQLite SMT commits and PostgreSQL ingest-row updates are separate atomic
  units; the existing `smt_committed = FALSE` reconciliation contract remains
  necessary after a crash between them.
