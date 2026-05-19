-- Olympus-native credential tables and key_credentials extensions (alembic: b2c3d4e5f6a7)

CREATE TABLE credential_consents (
    id                VARCHAR(36) PRIMARY KEY,
    user_id           VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    signing_key_id    VARCHAR(36) NOT NULL REFERENCES account_signing_keys(key_id) ON DELETE CASCADE,
    credential_type   VARCHAR(64) NOT NULL,
    issuer            VARCHAR(256) NOT NULL,
    burn_authorization VARCHAR(32) NOT NULL DEFAULT 'issuer_only',
    consent_payload   TEXT NOT NULL,
    consent_signature VARCHAR(128),
    nonce             VARCHAR(64) NOT NULL,
    created_at        TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMP NOT NULL,
    accepted_at       TIMESTAMP,
    revoked_at        TIMESTAMP
);
CREATE INDEX        ix_credential_consents_user_id        ON credential_consents (user_id);
CREATE INDEX        ix_credential_consents_signing_key_id ON credential_consents (signing_key_id);
CREATE UNIQUE INDEX ix_credential_consents_nonce          ON credential_consents (nonce);

CREATE TABLE credential_ledger_events (
    id               VARCHAR(36) PRIMARY KEY,
    credential_id    VARCHAR(36) NOT NULL REFERENCES key_credentials(id) ON DELETE CASCADE,
    event_type       VARCHAR(16) NOT NULL,
    ledger_commit_id VARCHAR(66) NOT NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    inclusion_proof  TEXT,
    smt_root         VARCHAR(66)
);
CREATE INDEX        ix_credential_ledger_events_credential_id   ON credential_ledger_events (credential_id);
CREATE INDEX        ix_credential_ledger_events_event_type      ON credential_ledger_events (event_type);
CREATE UNIQUE INDEX ix_credential_ledger_events_ledger_commit_id ON credential_ledger_events (ledger_commit_id);

ALTER TABLE key_credentials
    ADD COLUMN IF NOT EXISTS burn_authorization  VARCHAR(32) NOT NULL DEFAULT 'issuer_only',
    ADD COLUMN IF NOT EXISTS holder_account_id   VARCHAR(36),
    ADD COLUMN IF NOT EXISTS consent_id          VARCHAR(36);

CREATE INDEX IF NOT EXISTS ix_key_credentials_holder_account_id ON key_credentials (holder_account_id);
CREATE INDEX IF NOT EXISTS ix_key_credentials_consent_id        ON key_credentials (consent_id);
