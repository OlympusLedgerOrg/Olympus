-- Olympus Phase 0.5 Database Schema
-- Append-only storage for Sparse Merkle State Forest, shard headers, and ledger

-- SMT Leaves: Store leaf nodes of sparse Merkle trees
-- Append-only: INSERT only, no UPDATE/DELETE
CREATE TABLE IF NOT EXISTS smt_leaves (
    shard_id TEXT NOT NULL,
    key BYTEA NOT NULL,  -- 32-byte key
    version INT NOT NULL,
    value_hash BYTEA NOT NULL,  -- 32-byte hash of value
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Primary key prevents duplicate (shard, key, version) tuples
    PRIMARY KEY (shard_id, key, version),
    
    -- Constraints
    CONSTRAINT smt_leaves_key_length CHECK (octet_length(key) = 32),
    CONSTRAINT smt_leaves_value_hash_length CHECK (octet_length(value_hash) = 32)
);

-- Index for efficient lookups
CREATE INDEX IF NOT EXISTS smt_leaves_shard_ts_idx ON smt_leaves(shard_id, ts);

-- SMT Nodes: Store internal nodes of sparse Merkle trees
-- Append-only: INSERT only, no UPDATE/DELETE
CREATE TABLE IF NOT EXISTS smt_nodes (
    shard_id TEXT NOT NULL,
    level SMALLINT NOT NULL,  -- 0 = root, 255 = leaf level
    index BYTEA NOT NULL,  -- Path to this node (variable length, encoded as bits)
    hash BYTEA NOT NULL,  -- 32-byte node hash
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Primary key prevents duplicate nodes at same position
    PRIMARY KEY (shard_id, level, index),
    
    -- Constraints
    CONSTRAINT smt_nodes_level_range CHECK (level >= 0 AND level <= 256),
    CONSTRAINT smt_nodes_hash_length CHECK (octet_length(hash) = 32)
);

-- Index for efficient tree traversal
CREATE INDEX IF NOT EXISTS smt_nodes_shard_level_idx ON smt_nodes(shard_id, level);

-- Shard Headers: Store signed shard root commitments
-- Append-only: INSERT only, no UPDATE/DELETE
CREATE TABLE IF NOT EXISTS shard_headers (
    shard_id TEXT NOT NULL,
    seq BIGINT NOT NULL,  -- Sequence number (monotonically increasing)
    root BYTEA NOT NULL,  -- 32-byte shard root hash
    tree_size BIGINT NOT NULL DEFAULT 0,  -- Number of leaves committed by the root
    header_hash BYTEA NOT NULL,  -- 32-byte hash of canonical header JSON
    sig BYTEA NOT NULL,  -- 64-byte Ed25519 signature
    pubkey BYTEA NOT NULL,  -- 32-byte Ed25519 public key
    previous_header_hash TEXT NOT NULL,  -- Hex-encoded previous header hash (empty for genesis)
    ts TIMESTAMPTZ NOT NULL,  -- ISO 8601 timestamp from header
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- Database insertion time
    
    -- Primary key prevents history rewrites
    PRIMARY KEY (shard_id, seq),
    
    -- Unique constraint on header hash prevents duplicates
    CONSTRAINT shard_headers_header_hash_unique UNIQUE (shard_id, header_hash),
    
    -- Constraints
    CONSTRAINT shard_headers_root_length CHECK (octet_length(root) = 32),
    CONSTRAINT shard_headers_header_hash_length CHECK (octet_length(header_hash) = 32),
    CONSTRAINT shard_headers_sig_length CHECK (octet_length(sig) = 64),
    CONSTRAINT shard_headers_pubkey_length CHECK (octet_length(pubkey) = 32),
    CONSTRAINT shard_headers_seq_positive CHECK (seq >= 0),
    CONSTRAINT shard_headers_tree_size_non_negative CHECK (tree_size >= 0)
);

-- Index for finding latest header
CREATE INDEX IF NOT EXISTS shard_headers_shard_seq_desc_idx ON shard_headers(shard_id, seq DESC);

-- Ledger Entries: Global append-only ledger
-- Append-only: INSERT only, no UPDATE/DELETE
CREATE TABLE IF NOT EXISTS ledger_entries (
    shard_id TEXT NOT NULL,
    seq BIGINT NOT NULL,  -- Sequence number within shard (monotonically increasing)
    entry_hash BYTEA NOT NULL,  -- 32-byte hash of this entry
    prev_entry_hash BYTEA NOT NULL,  -- 32-byte hash of previous entry (empty bytes for genesis)
    payload JSONB NOT NULL,  -- Canonical JSON payload (ts, record_hash, shard_id, shard_root, prev_entry_hash)
    ts TIMESTAMPTZ NOT NULL,  -- ISO 8601 timestamp from payload
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- Database insertion time
    
    -- Primary key prevents history rewrites
    PRIMARY KEY (shard_id, seq),
    
    -- Unique constraint on entry hash prevents duplicates
    CONSTRAINT ledger_entries_entry_hash_unique UNIQUE (entry_hash),
    
    -- Constraints
    CONSTRAINT ledger_entries_entry_hash_length CHECK (octet_length(entry_hash) = 32),
    CONSTRAINT ledger_entries_seq_positive CHECK (seq >= 0)
);

-- Index for finding tail entries
CREATE INDEX IF NOT EXISTS ledger_entries_shard_seq_desc_idx ON ledger_entries(shard_id, seq DESC);

-- Index for global ledger ordering
CREATE INDEX IF NOT EXISTS ledger_entries_ts_idx ON ledger_entries(ts);

-- Enforce monotonic ledger order and chain linkage at write time
CREATE OR REPLACE FUNCTION enforce_ledger_entry_order()
RETURNS TRIGGER AS $$
DECLARE
    latest_seq BIGINT;
    latest_hash BYTEA;
BEGIN
    SELECT seq, entry_hash
    INTO latest_seq, latest_hash
    FROM ledger_entries
    WHERE shard_id = NEW.shard_id
    ORDER BY seq DESC
    LIMIT 1;

    IF latest_seq IS NULL THEN
        IF NEW.seq <> 0 THEN
            RAISE EXCEPTION 'First ledger entry for shard % must have seq=0, got %', NEW.shard_id, NEW.seq;
        END IF;
        IF octet_length(NEW.prev_entry_hash) <> 0 THEN
            RAISE EXCEPTION 'First ledger entry for shard % must have empty prev_entry_hash', NEW.shard_id;
        END IF;
    ELSE
        IF NEW.seq <> latest_seq + 1 THEN
            RAISE EXCEPTION 'Out-of-order ledger entry for shard %: expected seq %, got %', NEW.shard_id, latest_seq + 1, NEW.seq;
        END IF;
        IF NEW.prev_entry_hash <> latest_hash THEN
            RAISE EXCEPTION 'Invalid prev_entry_hash for shard % at seq %', NEW.shard_id, NEW.seq;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgname = 'ledger_entries_order_guard'
    ) THEN
        CREATE TRIGGER ledger_entries_order_guard
        BEFORE INSERT ON ledger_entries
        FOR EACH ROW
        EXECUTE FUNCTION enforce_ledger_entry_order();
    END IF;
END;
$$;
