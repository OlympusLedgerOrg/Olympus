-- ADR-0026 Phase 4: persist the per-document object-level redaction manifest so
-- `POST /redaction/issue` (which only receives a content_hash) can rebuild the
-- 1024-leaf witness without the original bytes.
--
-- Keyed by (content_hash, shard_id) — the same scope `ingest_records` uses
-- (content_hash is per-shard unique, migration 0038). Writes are insert-or-ignore
-- so re-ingesting the same file is idempotent: the per-object blinding is derived
-- deterministically from the server blind_secret + content_hash + obj_id
-- (ADR-0026), so a retry reproduces the same root and never rewrites a committed
-- manifest out from under an already-issued proof.
--
-- Blindings are NOT stored (re-derivable from the server secret); only the
-- structural segment metadata + the committed object root. The original document
-- bytes are never stored here (privacy).
CREATE TABLE IF NOT EXISTS redaction_segment_manifests (
    content_hash  TEXT        NOT NULL,
    shard_id      TEXT        NOT NULL,
    -- Commitment format. Today only 'pdf-object' (traditional-xref PDF); ADR-0026
    -- later adds 'ooxml-part' and 'text-line'.
    format        TEXT        NOT NULL,
    -- Object-level Merkle root committed on the ledger as the record's
    -- original_root (64-char lower-hex). Matches ingest_records.original_root.
    original_root TEXT        NOT NULL,
    tree_depth    INTEGER     NOT NULL,
    max_leaves    INTEGER     NOT NULL,
    -- Ordered per-segment metadata: [{obj_id, byte_offset, byte_length, leaf_hex}].
    segments      JSONB       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (content_hash, shard_id)
);
