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

-- Enforce all-or-nothing on the three commitment columns. Application code
-- in src-tauri/src/api/credentials.rs always sets all three together (commit
-- path) or none of them (plaintext path), but a stray UPDATE or a future
-- migration could produce a partial state where verify cannot recover what
-- the row was meant to represent (e.g. version=1 without coords, or coords
-- without version). The CHECK constraint rejects those rows at write time.
--
-- Pre-v1 with no existing committed rows, so the constraint will not fail
-- on backfill. If a later migration wants to introduce additional versions
-- (commitment_version = 2, ...) it must replace this constraint to allow
-- the new value.
-- PostgreSQL doesn't support `ADD CONSTRAINT IF NOT EXISTS`. sqlx
-- migrations run each file exactly once (tracked in _sqlx_migrations), so
-- a plain ADD CONSTRAINT is safe here. If anyone needs to re-apply by
-- hand, DROP CONSTRAINT first.
ALTER TABLE key_credentials
    ADD CONSTRAINT key_credentials_commitment_consistency_chk
    CHECK (
        (commitment_version IS NULL
         AND commitment_x IS NULL
         AND commitment_y IS NULL)
        OR
        (commitment_version = 1
         AND commitment_x IS NOT NULL
         AND commitment_y IS NOT NULL)
    );
