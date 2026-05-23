-- 0030_add_pedersen_commitment.sql
--
-- Pedersen commitment columns for SBT privacy (#992 PD-3).
--
-- The commit/verify flow:
--   * On POST /credentials with commit=true, the server computes
--       m = digest_jcs_to_subgroup_scalar(details)
--       r = random_blinding()
--       C = m·G + r·H
--     stores (commitment_x, commitment_y, commitment_version=1), DOES NOT
--     persist the cleartext details (writes '{}'::jsonb to keep the
--     existing NOT NULL DEFAULT constraint), and returns (m, r) to the
--     caller ONCE.
--   * On POST /credentials/{id}/verify with `opening`, the server recomputes
--     commit(m, r) and compares to the stored (commitment_x, commitment_y),
--     then re-derives commit_id from the commitment fields and verifies the
--     BJJ signature.
--
-- All three columns are nullable so the existing plaintext path stays
-- unchanged: NULL commitment_version => plaintext row, version=1 =>
-- OLY:PEDERSEN:H:V1 commitment.
--
-- Pre-v1, so no backfill — existing rows remain plaintext.

ALTER TABLE key_credentials
    ADD COLUMN IF NOT EXISTS commitment_x VARCHAR(78),
    ADD COLUMN IF NOT EXISTS commitment_y VARCHAR(78),
    ADD COLUMN IF NOT EXISTS commitment_version SMALLINT;
