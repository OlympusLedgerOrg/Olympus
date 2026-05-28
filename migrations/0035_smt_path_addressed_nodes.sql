-- SMT scaling plan, step 1: path-addressed node storage.
--
-- The original `merkle_nodes` table (migration 0001) used VARCHAR(36) UUID
-- primary keys with self-referential `left_child_id` / `right_child_id`
-- foreign keys. It was never written to by any code path and turns every
-- tree walk into a chain of FK joins at scale. Replace it with direct
-- path-addressed rows that mirror the in-memory tree's
-- `HashMap<Vec<u8>, [u8; 32]>` exactly:
--
--   * `path`  — the bit-vector that addresses the node (one byte per bit).
--               Its length equals the node's depth; the global root has the
--               empty path. Internal nodes live at depths 1..=255.
--   * `hash`  — the 32-byte BLAKE3 node hash.
--
-- Lookups are direct primary-key probes by path — no joins, no FKs.
--
-- IDEMPOTENCY: this migration was originally numbered 0032 and collided
-- with 0032_add_credential_quorum on the `_sqlx_migrations` primary key
-- (both PRs #1071 / #1072 grabbed slot 0032 independently and landed on
-- the same merge window). Renumbering to 0035 fixes new deployments;
-- the IF NOT EXISTS guards below let any operator whose DB has the
-- partial-apply state (smt_nodes / smt_leaves created by the half-
-- applied first attempt, but the metadata insert failed) re-run cleanly.

DROP TABLE IF EXISTS merkle_nodes;

CREATE TABLE IF NOT EXISTS smt_nodes (
    path BYTEA PRIMARY KEY,
    hash BYTEA NOT NULL
);

-- Expression index on node depth (== bit-path length) so the write-behind
-- cache can bulk-load the hot upper levels (`WHERE length(path) <= N`) and
-- fetch shard subtree roots (depth 64) without a full scan.
CREATE INDEX IF NOT EXISTS ix_smt_nodes_depth ON smt_nodes ((length(path)));

-- Leaf metadata, keyed by the 32-byte tree key (shard prefix ‖ record suffix).
-- The leaf hash is recomputed on demand from these columns via the canonical
-- `leaf_hash` domain (ADR-0003), so only the preimage fields are stored.
CREATE TABLE IF NOT EXISTS smt_leaves (
    key                      BYTEA PRIMARY KEY,
    value_hash               BYTEA NOT NULL,
    parser_id                TEXT  NOT NULL,
    canonical_parser_version TEXT  NOT NULL
);
