-- Shard registry — operator-controlled shard creation.
--
-- First-use of a new `shard_id` is the moment a shard is "created". Without a
-- registry, any key with the `ingest`/`write` scope could mint an unbounded
-- number of shards just by varying the multipart `shard_id` field. This table
-- moves shard creation under operator control: a `shard_id` MUST be registered
-- here (active) before `POST /ingest/files` will accept a write to it. The gate
-- is unconditional and fail-closed (see `api::shards::authorize_write`).
--
-- A shard may optionally be bound to an owner account (`owner_user_id`). When
-- set, only that account — or a key carrying the `admin` scope — may write to
-- the shard, giving the "assigned shard namespace" model on top of the same
-- mechanism.
CREATE TABLE IF NOT EXISTS shards (
    shard_id       TEXT PRIMARY KEY,
    owner_user_id  TEXT,
    label          TEXT,
    created_by     TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active         BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_shards_owner ON shards (owner_user_id);

-- Seed the system default shard (`files`) used by the ingest path when no
-- explicit `shard_id` is supplied, so the default upload flow works out of the
-- box without any admin setup. It is unowned (any ingest/write-scoped key may
-- write) and created by the migration on the operator's behalf.
INSERT INTO shards (shard_id, created_by)
VALUES ('files', 'migration')
ON CONFLICT (shard_id) DO NOTHING;

-- Backfill every shard already present in the ledger so that turning the
-- always-on gate on does not retroactively lock out existing deployments.
-- Backfilled shards are unowned and active.
INSERT INTO shards (shard_id, created_by)
SELECT DISTINCT shard_id, 'backfill'
FROM ingest_records
WHERE shard_id IS NOT NULL AND shard_id <> ''
ON CONFLICT (shard_id) DO NOTHING;
