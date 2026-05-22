-- Add Baby JubJub authority pubkey to account_signing_keys for ZK unified circuit.
-- The server holds the BJJ private key; only the pubkey coordinates are stored.

ALTER TABLE account_signing_keys
    ADD COLUMN IF NOT EXISTS bjj_pubkey_x VARCHAR(78),
    ADD COLUMN IF NOT EXISTS bjj_pubkey_y VARCHAR(78);

COMMENT ON COLUMN account_signing_keys.bjj_pubkey_x IS 'Baby JubJub pubkey affine X as decimal Fr string';
COMMENT ON COLUMN account_signing_keys.bjj_pubkey_y IS 'Baby JubJub pubkey affine Y as decimal Fr string';
