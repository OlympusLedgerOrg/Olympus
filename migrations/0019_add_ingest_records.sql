-- Ingest records table: stores BLAKE3-hashed file/record commitments.
-- Mirrors the Python API's ledger_entries table but scoped to the Tauri
-- embedded server's simplified ingest path.

CREATE TABLE IF NOT EXISTS ingest_records (
    proof_id          TEXT        NOT NULL PRIMARY KEY,
    shard_id          TEXT        NOT NULL DEFAULT 'files',
    record_type       TEXT        NOT NULL DEFAULT 'file',
    record_id         TEXT        NOT NULL DEFAULT 'record',
    version           INTEGER     NOT NULL DEFAULT 1,
    content_hash      TEXT        NOT NULL,  -- BLAKE3 hex (64 chars)
    content_json      TEXT,                  -- full content object JSON
    ledger_entry_hash TEXT        NOT NULL,
    merkle_root       TEXT,
    batch_id          TEXT,
    poseidon_root     TEXT,
    canonicalization  TEXT,                  -- JSON string
    ts                TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ingest_records_content_hash_idx
    ON ingest_records (content_hash);

CREATE INDEX IF NOT EXISTS ingest_records_shard_ts_idx
    ON ingest_records (shard_id, ts DESC);
