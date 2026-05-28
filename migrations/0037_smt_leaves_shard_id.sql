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
ALTER TABLE smt_leaves
    ADD COLUMN IF NOT EXISTS shard_id TEXT NOT NULL DEFAULT '';

ALTER TABLE smt_leaves
    ALTER COLUMN shard_id DROP DEFAULT;
