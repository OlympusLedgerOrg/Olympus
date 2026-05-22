-- 0026_add_anchor_receipts.sql
--
-- External anchoring receipts.  Each row records a single submission of a
-- BLAKE3 digest to a third-party transparency or timestamping service so the
-- existence of an Olympus ledger root at time T can be verified by anyone
-- who trusts the anchor (not just members of the Olympus federation).
--
-- Three anchor kinds at v0.9:
--   * 'rfc3161' — IETF RFC 3161 TSA reply (TimeStampToken, opaque CMS blob)
--   * 'rekor'   — Sigstore Rekor entry (UUID + log_index + signed entry ts)
--   * 'ots'     — OpenTimestamps pending receipt (binary, later upgradeable
--                  to a Bitcoin block-header path)
--
-- Receipts are append-only.  `verified_at` is the timestamp of the most
-- recent successful round-trip verification (re-fetching the receipt and
-- confirming it still verifies); it is *not* the same as `submitted_at`.

CREATE TABLE IF NOT EXISTS anchor_receipts (
    id              UUID PRIMARY KEY,
    anchor_kind     TEXT NOT NULL,
    -- The hash that was anchored (32 bytes for BLAKE3 / SHA-256).
    anchored_hash   BYTEA NOT NULL,
    -- Optional FK-style link to the federation checkpoint this anchors;
    -- null when the anchor is for an ad-hoc hash (e.g. a single shard
    -- header, a redaction commitment).
    checkpoint_id   UUID NULL,
    -- The anchor's opaque receipt blob.  Verification is anchor-specific;
    -- we store the raw bytes so the receipt can be re-verified offline.
    receipt_blob    BYTEA NOT NULL,
    -- Service the receipt came from (TSA URL, Rekor instance URL, OTS
    -- calendar URL).  Helps re-fetch + upgrade later.
    target          TEXT NOT NULL,
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at     TIMESTAMPTZ NULL,
    -- Anchor-specific structured data (log_index for Rekor, bitcoin block
    -- height for OTS once upgraded, TSA cert chain summary for RFC 3161).
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT anchor_kind_valid CHECK (
        anchor_kind IN ('rfc3161', 'rekor', 'ots')
    )
);

-- Lookup by checkpoint (e.g. "show all anchors that prove this checkpoint
-- existed by time T") is the dominant read pattern.
CREATE INDEX IF NOT EXISTS idx_anchor_receipts_checkpoint
    ON anchor_receipts (checkpoint_id)
    WHERE checkpoint_id IS NOT NULL;

-- Lookup by hash for "did we already anchor this digest?" idempotency.
CREATE INDEX IF NOT EXISTS idx_anchor_receipts_hash_kind
    ON anchor_receipts (anchored_hash, anchor_kind);
