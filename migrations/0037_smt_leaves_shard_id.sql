-- ADR-0005: bind the shard_id into the leaf domain prefix.
--
-- The leaf hash now begins with a structured prefix that includes the full,
-- length-prefixed shard_id (marker | "OLY" | type=LEAF | version=V1 |
-- lp(shard_id)), making the shard explicit and untruncated rather than relying
-- only on the 64-bit shard prefix folded into the key. The leaf hash is
-- recomputed on demand from smt_leaves, so the shard_id preimage field must be
-- stored alongside the other provenance fields (ADR-0003 / ADR-0004).
--
-- NOT NULL, with a transient default so the ALTER applies cleanly on the
-- (pre-launch, empty) smt_leaves table; the default is dropped immediately so
-- every subsequent INSERT must supply shard_id explicitly.
-- Fail closed: if legacy rows exist but the column does not, refuse rather than
-- stamp them with an empty (invalid) shard_id. Guarded on column-absence so a
-- re-run after the column exists is a no-op.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM smt_leaves)
       AND NOT EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_name = 'smt_leaves' AND column_name = 'shard_id'
       )
    THEN
        RAISE EXCEPTION
            'smt_leaves has rows but no shard_id column; refusing to backfill empty shard_id (ADR-0005). Migrate provenance explicitly before applying.';
    END IF;
END $$;

ALTER TABLE smt_leaves
    ADD COLUMN IF NOT EXISTS shard_id TEXT NOT NULL DEFAULT '';

ALTER TABLE smt_leaves
    ALTER COLUMN shard_id DROP DEFAULT;
