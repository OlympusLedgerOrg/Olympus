-- Red-team finding: `key_credentials.commit_id` (from migration 0001) was
-- declared `VARCHAR(64) NOT NULL` without a UNIQUE constraint. The audit
-- noted this lets two concurrent issuances of the same SBT
-- (deterministic in `(holder, type, issued_at_second, details)`) both
-- INSERT successfully, producing duplicate rows with identical
-- `commit_id` and different `id` UUIDs.
--
-- Consequences of the duplicate-row state:
--   - Revocation by `commit_id` (the `OLY:SBT:REVOKE:V1` digest is over
--     `commit_id_hex`) revokes one row but leaves the duplicate live.
--   - Verification by `commit_id` returns nondeterministically.
--   - The threat-model claim that a credential is uniquely identified by
--     `commit_id` is structurally false at the storage tier.
--
-- This migration adds the missing UNIQUE constraint. On any DB that
-- already has duplicate `commit_id` rows the ALTER will fail loudly with
-- a unique violation — flagging the broken state instead of papering
-- over it. The v0.9 single-operator deployments at this commit have no
-- production data per CLAUDE.md guidance, so a duplicate-row state in
-- the wild is unexpected and worth surfacing.
--
-- The caller-side fix lives in `api/credentials/mod.rs::issue` —
-- `INSERT … ON CONFLICT (commit_id) DO NOTHING RETURNING id` makes the
-- race idempotent: the second concurrent caller observes the first's
-- row instead of producing a 500 from the constraint hit.

ALTER TABLE key_credentials
    ADD CONSTRAINT key_credentials_commit_id_unique UNIQUE (commit_id);
