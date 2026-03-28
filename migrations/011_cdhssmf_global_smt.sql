-- Migration 011: CDHSSMF (Constant-Depth Hierarchical Sparse Sharded Merkle Forest)
--
-- This migration converts the legacy per-shard SMT schema into the global SMT schema.
--
-- IMPORTANT:
-- StorageLayer.init_schema() is the authoritative schema path used by production/CI.
-- This migration is retained for operators who still apply SQL migrations manually.
--
-- Historical per-shard rows are NOT auto-migrated here because a safe migration must
-- recompute global_key(shard_id, record_key) from the original logical inputs. The
-- stored legacy SMT key bytes do not preserve enough structure to do that safely after
-- the domain-separation hardening, so silently copying them into the global key space
-- would be incorrect. Legacy tables are preserved under *_legacy_011 names for manual
-- export / re-ingest instead of being dropped.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'smt_leaves'
          AND column_name = 'shard_id'
    ) AND to_regclass('public.smt_leaves_legacy_011') IS NULL THEN
        EXECUTE 'ALTER TABLE smt_leaves RENAME TO smt_leaves_legacy_011';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'smt_nodes'
          AND column_name = 'shard_id'
    ) AND to_regclass('public.smt_nodes_legacy_011') IS NULL THEN
        EXECUTE 'ALTER TABLE smt_nodes RENAME TO smt_nodes_legacy_011';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS smt_leaves (
    key BYTEA NOT NULL,  -- 32-byte global key (includes shard identity via global_key())
    version INT NOT NULL,
    value_hash BYTEA NOT NULL,  -- 32-byte hash of value
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (key, version),
    CONSTRAINT smt_leaves_key_length CHECK (octet_length(key) = 32),
    CONSTRAINT smt_leaves_value_hash_length CHECK (octet_length(value_hash) = 32)
);

CREATE INDEX IF NOT EXISTS smt_leaves_ts_idx ON smt_leaves(ts);

CREATE TABLE IF NOT EXISTS smt_nodes (
    level SMALLINT NOT NULL,  -- 0 = root, 255 = leaf level
    index BYTEA NOT NULL,  -- Path to this node (variable length, encoded as bits)
    hash BYTEA NOT NULL,  -- 32-byte node hash
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (level, index),
    CONSTRAINT smt_nodes_level_range CHECK (level >= 0 AND level <= 256),
    CONSTRAINT smt_nodes_hash_length CHECK (octet_length(hash) = 32)
);

CREATE INDEX IF NOT EXISTS smt_nodes_level_idx ON smt_nodes(level);

COMMENT ON TABLE smt_leaves IS 'Global SMT leaf nodes using CDHSSMF. Keys are generated via global_key(shard_id, record_key) with domain-separated key derivation.';
COMMENT ON TABLE smt_nodes IS 'Global SMT internal nodes using CDHSSMF design. Single tree for all shards with hierarchical key derivation.';

DO $$
BEGIN
    IF to_regclass('public.smt_leaves_legacy_011') IS NOT NULL THEN
        EXECUTE $sql$
            COMMENT ON TABLE smt_leaves_legacy_011 IS
            'Legacy pre-CDHSSMF per-shard SMT leaves preserved by migration 011. Rows are intentionally not auto-migrated because safe migration requires recomputing global_key(shard_id, record_key) from original logical record inputs.'
        $sql$;
    END IF;

    IF to_regclass('public.smt_nodes_legacy_011') IS NOT NULL THEN
        EXECUTE $sql$
            COMMENT ON TABLE smt_nodes_legacy_011 IS
            'Legacy pre-CDHSSMF per-shard SMT nodes preserved by migration 011. Operators must rebuild these from re-ingested global keys instead of copying them into the global SMT namespace.'
        $sql$;
    END IF;
END $$;
