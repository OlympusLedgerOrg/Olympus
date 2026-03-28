-- Migration 011: CDHSSMF (Constant-Depth Hierarchical Sparse Sharded Merkle Forest)
--
-- This migration converts the per-shard SMT design to a global SMT design.
--
-- Key changes:
-- 1. Remove shard_id from smt_nodes and smt_leaves primary keys
-- 2. Use global keys that encode shard identity via global_key(shard_id, record_key)
-- 3. Simplify concurrency by having a single global SMT instead of per-shard + forest SMTs
--
-- IMPORTANT: This is a breaking change that requires data migration if there is existing data.
-- For new deployments, this creates the correct schema from the start.

-- Step 1: Create new global SMT tables (without shard_id in PK)
-- We create new tables and will drop the old ones after migration

CREATE TABLE IF NOT EXISTS smt_leaves_global (
    key BYTEA NOT NULL,  -- 32-byte global key (includes shard_id via global_key())
    version INT NOT NULL,
    value_hash BYTEA NOT NULL,  -- 32-byte hash of value
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Primary key prevents duplicate (key, version) tuples
    PRIMARY KEY (key, version),

    -- Constraints
    CONSTRAINT smt_leaves_global_key_length CHECK (octet_length(key) = 32),
    CONSTRAINT smt_leaves_global_value_hash_length CHECK (octet_length(value_hash) = 32)
);

-- Index for efficient timestamp-based lookups
CREATE INDEX IF NOT EXISTS smt_leaves_global_ts_idx ON smt_leaves_global(ts);

CREATE TABLE IF NOT EXISTS smt_nodes_global (
    level SMALLINT NOT NULL,  -- 0 = root, 255 = leaf level
    index BYTEA NOT NULL,  -- Path to this node (variable length, encoded as bits)
    hash BYTEA NOT NULL,  -- 32-byte node hash
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Primary key prevents duplicate nodes at same position
    PRIMARY KEY (level, index),

    -- Constraints
    CONSTRAINT smt_nodes_global_level_range CHECK (level >= 0 AND level <= 256),
    CONSTRAINT smt_nodes_global_hash_length CHECK (octet_length(hash) = 32)
);

-- Index for efficient tree traversal
CREATE INDEX IF NOT EXISTS smt_nodes_global_level_idx ON smt_nodes_global(level);

-- Step 2: Migrate existing data (if any)
-- NOTE: This migration assumes that existing keys in smt_leaves/smt_nodes are already
-- global keys generated via global_key(shard_id, record_key). If not, a data migration
-- function would be needed here.
--
-- For a fresh deployment with no data, these INSERT statements will be no-ops.

INSERT INTO smt_leaves_global (key, version, value_hash, ts)
SELECT key, version, value_hash, ts
FROM smt_leaves
ON CONFLICT (key, version) DO NOTHING;

INSERT INTO smt_nodes_global (level, index, hash, ts)
SELECT level, index, hash, ts
FROM smt_nodes
ON CONFLICT (level, index) DO NOTHING;

-- Step 3: Drop old tables and rename new ones
-- We use DROP ... CASCADE to handle any dependent triggers/constraints

DROP TABLE IF EXISTS smt_leaves CASCADE;
DROP TABLE IF EXISTS smt_nodes CASCADE;

ALTER TABLE smt_leaves_global RENAME TO smt_leaves;
ALTER TABLE smt_nodes_global RENAME TO smt_nodes;

-- Rename indexes to match old naming convention
ALTER INDEX IF EXISTS smt_leaves_global_ts_idx RENAME TO smt_leaves_ts_idx;
ALTER INDEX IF EXISTS smt_nodes_global_level_idx RENAME TO smt_nodes_level_idx;

-- Rename constraints to match old naming convention
ALTER TABLE smt_leaves RENAME CONSTRAINT smt_leaves_global_key_length TO smt_leaves_key_length;
ALTER TABLE smt_leaves RENAME CONSTRAINT smt_leaves_global_value_hash_length TO smt_leaves_value_hash_length;
ALTER TABLE smt_nodes RENAME CONSTRAINT smt_nodes_global_level_range TO smt_nodes_level_range;
ALTER TABLE smt_nodes RENAME CONSTRAINT smt_nodes_global_hash_length TO smt_nodes_hash_length;

-- Step 4: Add comment documenting the CDHSSMF design
COMMENT ON TABLE smt_leaves IS 'Global SMT leaf nodes using CDHSSMF (Constant-Depth Hierarchical Sparse Sharded Merkle Forest). Keys are generated via global_key(shard_id, record_key) to encode shard identity into the key space.';
COMMENT ON TABLE smt_nodes IS 'Global SMT internal nodes using CDHSSMF design. Single tree for all shards with hierarchical key derivation.';
