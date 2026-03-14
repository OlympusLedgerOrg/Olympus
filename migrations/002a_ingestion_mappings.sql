-- Durable ingestion mappings for proof_id and batch boundaries

CREATE TABLE IF NOT EXISTS ingestion_batches (
    batch_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ingestion_proofs (
    proof_id TEXT PRIMARY KEY,
    batch_id TEXT REFERENCES ingestion_batches(batch_id) ON DELETE SET NULL,
    batch_index INT,
    shard_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_id TEXT NOT NULL,
    version INT NOT NULL,
    content_hash BYTEA NOT NULL,
    merkle_root BYTEA NOT NULL,
    merkle_proof JSONB NOT NULL,
    ledger_entry_hash BYTEA NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    canonicalization JSONB,
    persisted BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ingestion_proofs_content_hash_length CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ingestion_proofs_merkle_root_length CHECK (octet_length(merkle_root) = 32),
    CONSTRAINT ingestion_proofs_ledger_entry_hash_length CHECK (octet_length(ledger_entry_hash) = 32)
);

CREATE UNIQUE INDEX IF NOT EXISTS ingestion_proofs_content_hash_idx ON ingestion_proofs(content_hash);
CREATE INDEX IF NOT EXISTS ingestion_proofs_batch_idx ON ingestion_proofs(batch_id, batch_index);
