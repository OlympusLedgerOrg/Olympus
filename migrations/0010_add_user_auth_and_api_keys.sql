-- users and api_keys tables (alembic: a1b2c3d4e5f7)

CREATE TABLE users (
    id            VARCHAR(36) PRIMARY KEY,
    email         VARCHAR(320) NOT NULL,
    password_hash VARCHAR(256),
    role          VARCHAR(32) NOT NULL DEFAULT 'user',
    plan          VARCHAR(32) NOT NULL DEFAULT 'free',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX ix_users_email ON users (email);

CREATE TABLE api_keys (
    id         VARCHAR(36) PRIMARY KEY,
    user_id    VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash   VARCHAR(64) NOT NULL,
    name       VARCHAR(128) NOT NULL,
    scopes     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX        ix_api_keys_user_id  ON api_keys (user_id);
CREATE UNIQUE INDEX ix_api_keys_key_hash ON api_keys (key_hash);
