-- Olympus Phase 0.5 Migration 002
-- RFC 3161 Timestamp Tokens for Shard Headers
--
-- Purpose:
--   Anchor shard header hashes to an independent Timestamp Authority (TSA)
--   to provide third-party time attestation.
--
-- Security Properties:
--   - Append-only storage
--   - 32-byte header hash enforcement
--   - 32-byte imprint hash enforcement
--   - Optional FK linkage to shard_headers
--
-- Notes:
--   gen_time MUST be extracted from the RFC3161 TSTInfo.genTime field.
--   created_at is local DB insertion time.

CREATE TABLE IF NOT EXISTS timestamp_tokens (
    shard_id      TEXT        NOT NULL,
    header_hash   BYTEA       NOT NULL,  -- 32-byte shard header hash
    tsa_url       TEXT        NOT NULL,  -- Timestamp Authority URL

    -- DER-encoded RFC 3161 TimeStampToken
    tst           BYTEA       NOT NULL,

    -- 32-byte BLAKE3 hash submitted to TSA as messageImprint.hashedMessage
    imprint_hash  BYTEA       NOT NULL,

    -- genTime extracted from TSTInfo
    gen_time      TIMESTAMPTZ NOT NULL,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (shard_id, header_hash, tsa_url),

    -- Constraints
    CONSTRAINT timestamp_tokens_header_hash_length
        CHECK (octet_length(header_hash) = 32),

    CONSTRAINT timestamp_tokens_imprint_hash_length
        CHECK (octet_length(imprint_hash) = 32),

    CONSTRAINT timestamp_tokens_tst_nonempty
        CHECK (octet_length(tst) > 0)
);

-- Optional strict referential integrity:
-- Ensures timestamp token only exists for a known shard header.
-- shard_headers has UNIQUE (shard_id, header_hash).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'timestamp_tokens_header_fk'
    ) THEN
        ALTER TABLE timestamp_tokens
        ADD CONSTRAINT timestamp_tokens_header_fk
        FOREIGN KEY (shard_id, header_hash)
        REFERENCES shard_headers (shard_id, header_hash);
    END IF;
END;
$$;

-- Index for quick retrieval of latest timestamp per shard
CREATE INDEX IF NOT EXISTS timestamp_tokens_shard_created_desc_idx
    ON timestamp_tokens(shard_id, created_at DESC);

-- ---------------------------------------------------------------------
-- Append-only enforcement
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION olympus_reject_timestamp_token_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'timestamp_tokens is append-only: % is not allowed', TG_OP
        USING ERRCODE = '25006';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS timestamp_tokens_reject_update ON timestamp_tokens;
CREATE TRIGGER timestamp_tokens_reject_update
BEFORE UPDATE ON timestamp_tokens
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_timestamp_token_mutation();

DROP TRIGGER IF EXISTS timestamp_tokens_reject_delete ON timestamp_tokens;
CREATE TRIGGER timestamp_tokens_reject_delete
BEFORE DELETE ON timestamp_tokens
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_timestamp_token_mutation();

COMMENT ON TABLE timestamp_tokens IS
'RFC 3161 TimeStampTokens anchoring shard header hashes. Append-only.';

COMMENT ON COLUMN timestamp_tokens.imprint_hash IS
'32-byte BLAKE3 hash submitted as RFC3161 messageImprint.hashedMessage.';

COMMENT ON COLUMN timestamp_tokens.gen_time IS
'TSA-provided genTime from RFC3161 TSTInfo.';
