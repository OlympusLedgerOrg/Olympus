-- SPDX-FileCopyrightText: 2026 Olympus Contributors
-- SPDX-License-Identifier: Apache-2.0

-- Authority-key registry (docs/key-rotation.md; ROADMAP "in-band key
-- rotation and revocation"). Turns the singular BJJ authority row in
-- account_signing_keys into a supersession chain (identity-immutable rows
-- plus one-shot lifecycle stamps, the user signing-key pattern):
--
--   * valid_from / valid_until bound the window in which a key was the
--     signing authority. NULL means unbounded on that side (the shape of
--     every pre-registry row, and of the currently-active key).
--   * The global UNIQUE(public_key) index blocked a second authority row
--     (authority rows all store public_key = ''). It is narrowed to
--     non-authority rows, and a partial unique index enforces at most ONE
--     active (non-revoked) authority at any time instead.
--
-- Rotation (bootstrap::rotate_authority) stamps the active row's one-shot
-- lifecycle columns (revoked_at + valid_until + replaced_by_key_id) and
-- inserts the successor — identity columns are never rewritten, so the
-- registry keeps the full audit chain. (These lifecycle columns are the
-- same ones the external-PG DML contract whitelists for UPDATE; the
-- ADR-0031 insert-only invariant governs ledger tables, not this registry.)

ALTER TABLE account_signing_keys ADD COLUMN valid_from TIMESTAMPTZ;
ALTER TABLE account_signing_keys ADD COLUMN valid_until TIMESTAMPTZ;

DROP INDEX IF EXISTS ix_account_signing_keys_public_key;
CREATE UNIQUE INDEX IF NOT EXISTS ix_account_signing_keys_public_key
    ON account_signing_keys (public_key)
    WHERE purpose <> 'authority';
CREATE UNIQUE INDEX IF NOT EXISTS ix_account_signing_keys_single_active_authority
    ON account_signing_keys ((purpose))
    WHERE purpose = 'authority' AND revoked_at IS NULL;
