-- password_recovery_tokens table (alembic: a1b2c3d4e5f8)

CREATE TABLE password_recovery_tokens (
    id         VARCHAR(36) PRIMARY KEY,
    user_id    VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at    TIMESTAMPTZ
);
CREATE INDEX        ix_password_recovery_tokens_user_id   ON password_recovery_tokens (user_id);
CREATE UNIQUE INDEX ix_password_recovery_tokens_token_hash ON password_recovery_tokens (token_hash);
