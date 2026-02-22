-- storage/schema.sql

-- Phase 0.1: Core Artifacts Table
-- Primary key is the raw_hash. This guarantees we never ingest duplicate 
-- metadata for the exact same physical byte sequence.
CREATE TABLE artifacts (
    raw_hash CHAR(64) PRIMARY KEY,           -- 32-byte BLAKE3 hex string
    canonical_hash CHAR(64) NOT NULL,        -- The mathematically normalized hash
    mime_type VARCHAR(255) NOT NULL,
    byte_size BIGINT NOT NULL,               -- Essential for S3 stream validation
    
    -- S3/MinIO routing
    storage_bucket VARCHAR(255) NOT NULL,
    storage_key TEXT NOT NULL,               -- Usually identical to raw_hash
    
    -- C-Pipe Metadata (from Canonicalizer)
    canonicalization_mode VARCHAR(50) NOT NULL,
    canonicalizer_version VARCHAR(50) NOT NULL,
    fallback_reason TEXT,
    
    -- Civic Verifiability
    witness_anchor TEXT,                     -- External transparency log/timestamp ID
    ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Fast lookups for ZK proof generation and audit verification
CREATE INDEX idx_artifacts_canonical_hash ON artifacts(canonical_hash);
CREATE INDEX idx_artifacts_ingested_at ON artifacts(ingested_at);
