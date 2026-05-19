-- issued_by_key_id on key_credentials for H-3 IDOR fix (alembic: b1c2d3e4f5a6)

ALTER TABLE key_credentials
    ADD COLUMN IF NOT EXISTS issued_by_key_id VARCHAR(256);

CREATE INDEX IF NOT EXISTS ix_key_credentials_issued_by_key_id
    ON key_credentials (issued_by_key_id);
