-- operators table and api_keys operator identity columns (alembic: a0b1c2d3e4f5)

CREATE TABLE operators (
    id                  VARCHAR(36) PRIMARY KEY,
    ed25519_public_key  VARCHAR(64) NOT NULL,
    credential_id       VARCHAR(36) REFERENCES key_credentials(id) ON DELETE SET NULL,
    role                VARCHAR(64) NOT NULL DEFAULT 'node_operator',
    label               VARCHAR(256) NOT NULL,
    created_at          TIMESTAMP NOT NULL,
    activated_at        TIMESTAMP,
    revoked_at          TIMESTAMP
);
CREATE UNIQUE INDEX ix_operators_ed25519_public_key ON operators (ed25519_public_key);
CREATE INDEX        ix_operators_credential_id      ON operators (credential_id);

-- Relax user_id to nullable: operator-only keys have no user account.
ALTER TABLE api_keys
    ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS operator_id        VARCHAR(36) REFERENCES operators(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS ed25519_public_key VARCHAR(64),
    ADD COLUMN IF NOT EXISTS credential_id      VARCHAR(36) REFERENCES key_credentials(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS last_used_at       TIMESTAMP;

CREATE INDEX IF NOT EXISTS ix_api_keys_operator_id        ON api_keys (operator_id);
CREATE INDEX IF NOT EXISTS ix_api_keys_ed25519_public_key ON api_keys (ed25519_public_key);
CREATE INDEX IF NOT EXISTS ix_api_keys_credential_id      ON api_keys (credential_id);
