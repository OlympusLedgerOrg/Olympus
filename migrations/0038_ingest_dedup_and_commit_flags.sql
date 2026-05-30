-- Audit fixes (2026-05-29) for the file-ingest path.
--
-- Finding 5 — content-hash dedup crossed shard boundaries. The unique index
--   was on (content_hash) alone, so committing the same bytes under a second
--   shard was silently absorbed into the first shard's record and the caller
--   got back a shard_id they never asked for. Scope dedup per (content_hash,
--   shard_id) so each shard keeps its own record/leaf and the response always
--   reflects the requested shard.
--
-- Finding 2 — the Poseidon snapshot and parser-SMT writes are soft/non-fatal
--   (logged and swallowed), so a record could land in ingest_records and return
--   a proof_id while never reaching the snapshot tree or the parser SMT, with
--   no row-level trace of the gap. Add explicit completeness flags so an
--   incomplete commit is a queryable backfill target instead of a silent hole.

-- Finding 5: replace the global content_hash unique index with a per-shard one.
DROP INDEX IF EXISTS ingest_records_content_hash_idx;
CREATE UNIQUE INDEX IF NOT EXISTS ingest_records_content_hash_shard_idx
    ON ingest_records (content_hash, shard_id);

-- Finding 2: per-row completeness flags for the two soft post-insert writes.
ALTER TABLE ingest_records
    ADD COLUMN IF NOT EXISTS snapshot_committed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ingest_records
    ADD COLUMN IF NOT EXISTS smt_committed BOOLEAN NOT NULL DEFAULT FALSE;

-- Finding 2 (backfill): rows written before this flag existed that already
-- carry a snapshot_root completed the snapshot write, so seed them as
-- committed rather than leaving every historical row a false backfill target.
-- smt_committed CANNOT be derived from existing columns — there is no per-row
-- trace of the parser-SMT write — so it intentionally stays FALSE and remains
-- a genuine backfill target for a later reconciliation pass.
UPDATE ingest_records SET snapshot_committed = TRUE WHERE snapshot_root IS NOT NULL;
