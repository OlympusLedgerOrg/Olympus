-- chain_id, contract_address, holder_key_id on evm_pending_ops (alembic: d5e6f7a8b9c0)

ALTER TABLE evm_pending_ops
    ADD COLUMN IF NOT EXISTS chain_id          INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS contract_address  VARCHAR(42),
    ADD COLUMN IF NOT EXISTS holder_key_id     VARCHAR(64);

CREATE INDEX IF NOT EXISTS ix_evm_pending_ops_chain_id
    ON evm_pending_ops (chain_id);
CREATE INDEX IF NOT EXISTS ix_evm_pending_ops_contract_address
    ON evm_pending_ops (contract_address);
CREATE INDEX IF NOT EXISTS ix_evm_pending_ops_chain_contract
    ON evm_pending_ops (chain_id, contract_address);
