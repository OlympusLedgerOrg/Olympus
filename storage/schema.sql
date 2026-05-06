-- storage/schema.sql
--
-- Reference DDL for the Olympus storage layer.
-- The authoritative, idempotent schema is in storage/postgres_schema.py
-- (init_schema()).  This file documents the key tables and their columns
-- for reference; the actual production schema is managed by init_schema().

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

-- ---------------------------------------------------------------------------
-- CD-HS-ST storage tables (managed by StorageLayer.init_schema() in
-- storage/postgres.py; reproduced here for documentation purposes only)
-- ---------------------------------------------------------------------------

-- Sparse Merkle Tree leaves (one row per committed record version).
-- global_seq is a monotonically increasing identity column used for
-- deterministic replay ordering (ADR-0004).
CREATE TABLE smt_leaves (
    key                      BYTEA       NOT NULL,
    version                  INT         NOT NULL,
    value_hash               BYTEA       NOT NULL,
    parser_id                TEXT        NOT NULL,  -- e.g. "docling@2.3.1"
    canonical_parser_version TEXT        NOT NULL,  -- e.g. "v1"
    ts                       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    global_seq               BIGINT      GENERATED ALWAYS AS IDENTITY,
    PRIMARY KEY (key, version),
    CONSTRAINT smt_leaves_key_length
        CHECK (octet_length(key) = 32),
    CONSTRAINT smt_leaves_value_hash_length
        CHECK (octet_length(value_hash) = 32),
    CONSTRAINT smt_leaves_parser_id_nonempty
        CHECK (length(parser_id) > 0),
    CONSTRAINT smt_leaves_canonical_parser_version_nonempty
        CHECK (length(canonical_parser_version) > 0)
);

-- Signed shard root commitments.
-- leaf_seq records the smt_leaves.global_seq at the time of this header
-- commit, enabling seq-based replay windowing.
CREATE TABLE shard_headers (
    shard_id             TEXT        NOT NULL,
    seq                  BIGINT      NOT NULL,
    root                 BYTEA       NOT NULL,
    tree_size            BIGINT      NOT NULL DEFAULT 0,
    leaf_seq             BIGINT      NOT NULL DEFAULT 0,
    header_hash          BYTEA       NOT NULL,
    sig                  BYTEA       NOT NULL,
    pubkey               BYTEA       NOT NULL,
    previous_header_hash TEXT        NOT NULL,
    ts                   TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (shard_id, seq)
);
