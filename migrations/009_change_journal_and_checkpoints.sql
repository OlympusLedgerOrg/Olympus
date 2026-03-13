-- migration 009: SMT change journal for efficient O(changes) diffs
--
-- Instead of rebuilding two full SMTs and comparing them, diffs can be
-- answered directly from this journal table.  Each row records a leaf
-- mutation (insert or update) so that get_root_diff() becomes O(changes)
-- rather than O(N) where N is the total number of leaves.

CREATE TABLE IF NOT EXISTS smt_change_journal (
    id           BIGSERIAL PRIMARY KEY,
    shard_id     TEXT       NOT NULL,
    key          BYTEA      NOT NULL,
    old_value    BYTEA,              -- NULL for inserts
    new_value    BYTEA      NOT NULL,
    header_seq   INTEGER    NOT NULL, -- shard_headers.seq at time of change
    ts           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_change_journal_shard_seq
    ON smt_change_journal (shard_id, header_seq);

CREATE INDEX IF NOT EXISTS idx_change_journal_shard_ts
    ON smt_change_journal (shard_id, ts);

-- Checkpoint roots for shard compaction (item 7)
CREATE TABLE IF NOT EXISTS smt_checkpoints (
    id           BIGSERIAL  PRIMARY KEY,
    shard_id     TEXT        NOT NULL,
    header_seq   INTEGER     NOT NULL,
    root_hash    BYTEA       NOT NULL,
    leaf_count   INTEGER     NOT NULL DEFAULT 0,
    ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (shard_id, header_seq)
);
