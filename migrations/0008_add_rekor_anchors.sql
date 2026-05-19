-- rekor_anchors for Guardian replication (alembic: e5f6a7b8c9d0)
-- Note: shard_headers is part of the core storage schema, not this migration chain.
-- quorum_certificate is included when shard_headers is created via storage/postgres_schema.py.

CREATE TABLE IF NOT EXISTS rekor_anchors (
    id          BIGSERIAL PRIMARY KEY,
    shard_id    TEXT NOT NULL,
    shard_seq   BIGINT NOT NULL,
    root_hash   BYTEA NOT NULL,
    rekor_uuid  TEXT,
    rekor_index BIGINT,
    anchored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status      TEXT NOT NULL DEFAULT 'pending',
    CONSTRAINT rekor_anchors_root_hash_length CHECK (octet_length(root_hash) = 32)
);
CREATE INDEX IF NOT EXISTS ix_rekor_anchors_shard_id_seq ON rekor_anchors (shard_id, shard_seq);
CREATE INDEX IF NOT EXISTS ix_rekor_anchors_status       ON rekor_anchors (status);
