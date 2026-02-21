-- Olympus Phase 0.5 Migration 002 – RFC 3161 Timestamp Tokens
-- Stores DER-encoded RFC 3161 timestamp tokens keyed on (shard_id, header_hash).
-- Append-only: INSERT only, no UPDATE/DELETE.

CREATE TABLE IF NOT EXISTS timestamp_tokens (
    shard_id    TEXT        NOT NULL,
    header_hash BYTEA       NOT NULL,  -- 32-byte shard header hash that was timestamped
    tsa_url     TEXT        NOT NULL,  -- URL of the issuing Timestamp Authority
    tst_hex     TEXT        NOT NULL,  -- DER-encoded TimeStampToken, hex-encoded
    hash_hex    TEXT        NOT NULL,  -- Hex-encoded BLAKE3 hash that was submitted to the TSA
    ts          TIMESTAMPTZ NOT NULL,  -- Timestamp from TSA response (ISO 8601)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (shard_id, header_hash),

    CONSTRAINT timestamp_tokens_header_hash_length
        CHECK (octet_length(header_hash) = 32)
);

-- Index for looking up the latest token for a shard
CREATE INDEX IF NOT EXISTS timestamp_tokens_shard_created_desc_idx
    ON timestamp_tokens(shard_id, created_at DESC);
