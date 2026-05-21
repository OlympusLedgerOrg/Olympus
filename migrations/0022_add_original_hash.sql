-- Link redacted documents to their originals.
ALTER TABLE ingest_records ADD COLUMN IF NOT EXISTS original_hash TEXT
    CONSTRAINT chk_ingest_records_original_hash_format
        CHECK (original_hash IS NULL OR original_hash ~ '^[0-9a-f]{64}$');

CREATE INDEX IF NOT EXISTS ingest_records_original_hash_idx
    ON ingest_records (original_hash) WHERE original_hash IS NOT NULL;
