-- tsa_jobs queue + timestamp observability columns (alembic: f6a7b8c9d0e1)

CREATE TABLE tsa_jobs (
    id             VARCHAR(36) PRIMARY KEY,
    target_table   VARCHAR(64) NOT NULL,
    target_pk      VARCHAR(64) NOT NULL,
    hash_hex       VARCHAR(66) NOT NULL,
    tsa_url        VARCHAR(512) NOT NULL,
    status         VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts       INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT,
    created_at     TIMESTAMP NOT NULL,
    next_attempt_at TIMESTAMP NOT NULL,
    claimed_at     TIMESTAMP,
    completed_at   TIMESTAMP,
    CONSTRAINT uq_tsa_jobs_target UNIQUE (target_table, target_pk)
);
CREATE INDEX ix_tsa_jobs_pending_due ON tsa_jobs (status, next_attempt_at);

ALTER TABLE dataset_artifacts
    ADD COLUMN IF NOT EXISTS timestamp_attempts  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS timestamp_last_error TEXT;

ALTER TABLE dataset_lineage_events
    ADD COLUMN IF NOT EXISTS timestamp_attempts  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS timestamp_last_error TEXT;
