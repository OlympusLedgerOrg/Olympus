-- add revocation_commit_id to key_credentials (alembic: 8398af14bd26)

ALTER TABLE key_credentials
    ADD COLUMN IF NOT EXISTS revocation_commit_id VARCHAR(64);
