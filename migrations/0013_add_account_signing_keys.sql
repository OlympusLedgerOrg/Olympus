-- account_signing_keys table (alembic: a1b2c3d4e5f9)

CREATE TABLE account_signing_keys (
    key_id            VARCHAR(36) PRIMARY KEY,
    user_id           VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key        VARCHAR(64) NOT NULL,
    label             VARCHAR(128) NOT NULL,
    purpose           VARCHAR(64) NOT NULL DEFAULT 'dataset',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at        TIMESTAMPTZ,
    revoked_by_key_id VARCHAR(36),
    replaced_by_key_id VARCHAR(36)
);
CREATE INDEX        ix_account_signing_keys_user_id   ON account_signing_keys (user_id);
CREATE UNIQUE INDEX ix_account_signing_keys_public_key ON account_signing_keys (public_key);
