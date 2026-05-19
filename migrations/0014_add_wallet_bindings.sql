-- account_wallet_bindings table (alembic: a1b2c3d4e5fa)

CREATE TABLE account_wallet_bindings (
    id                VARCHAR(36) PRIMARY KEY,
    user_id           VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    signing_key_id    VARCHAR(36) NOT NULL REFERENCES account_signing_keys(key_id) ON DELETE CASCADE,
    wallet_address    VARCHAR(42) NOT NULL,
    nonce             VARCHAR(64) NOT NULL,
    challenge_message VARCHAR(512) NOT NULL,
    erc_standard      VARCHAR(16) NOT NULL DEFAULT 'ERC-5484',
    burn_authorization VARCHAR(32) NOT NULL,
    issued_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,
    verified_at       TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ
);
CREATE INDEX        ix_account_wallet_bindings_user_id       ON account_wallet_bindings (user_id);
CREATE INDEX        ix_account_wallet_bindings_signing_key_id ON account_wallet_bindings (signing_key_id);
CREATE INDEX        ix_account_wallet_bindings_wallet_address ON account_wallet_bindings (wallet_address);
CREATE UNIQUE INDEX ix_account_wallet_bindings_nonce          ON account_wallet_bindings (nonce);
