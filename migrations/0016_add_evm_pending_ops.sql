-- evm_pending_ops queue for batched SBT mints/burns (alembic: c3d4e5f6a7b8)

CREATE TABLE evm_pending_ops (
    id               VARCHAR(36) PRIMARY KEY,
    op_type          VARCHAR(8) NOT NULL,
    credential_id    VARCHAR(36) NOT NULL REFERENCES key_credentials(id) ON DELETE CASCADE,
    ledger_commit_id VARCHAR(66) NOT NULL,
    token_id         VARCHAR(78) NOT NULL,
    wallet_address   VARCHAR(42),
    burn_authorization VARCHAR(32),
    credential_type  VARCHAR(64),
    token_uri        TEXT,
    status           VARCHAR(12) NOT NULL DEFAULT 'pending',
    queued_at        TIMESTAMPTZ NOT NULL,
    submitted_at     TIMESTAMPTZ,
    confirmed_at     TIMESTAMPTZ,
    batch_tx_hash    VARCHAR(66),
    error            TEXT
);
CREATE INDEX ix_evm_pending_ops_op_type       ON evm_pending_ops (op_type);
CREATE INDEX ix_evm_pending_ops_credential_id ON evm_pending_ops (credential_id);
CREATE INDEX ix_evm_pending_ops_status        ON evm_pending_ops (status);
CREATE INDEX ix_evm_pending_ops_batch_tx_hash ON evm_pending_ops (batch_tx_hash);
