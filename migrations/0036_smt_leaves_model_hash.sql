-- ADR-0004: bind the parser model-artifact hash into the leaf domain.
--
-- ADR-0003 added `parser_id` and `canonical_parser_version` to the leaf hash.
-- ADR-0004 adds a third length-prefixed provenance field, `model_hash` — the
-- opaque content hash of the parser model that produced the committed value.
-- The leaf hash is recomputed on demand from `smt_leaves` (see
-- migration 0035), so the new preimage field must live alongside the others.
--
-- The column is NOT NULL: the canonical `leaf_hash` domain (ADR-0004) and the
-- SMT write path (`PersistentSmt::update_batch`) both require a non-empty
-- model_hash, so a row without one could never reproduce a valid leaf. A
-- transient empty-string default lets the ALTER apply cleanly on any
-- (pre-launch, therefore empty) `smt_leaves` table; it is dropped immediately
-- so every subsequent INSERT must supply the value explicitly.
ALTER TABLE smt_leaves
    ADD COLUMN IF NOT EXISTS model_hash TEXT NOT NULL DEFAULT '';

ALTER TABLE smt_leaves
    ALTER COLUMN model_hash DROP DEFAULT;
