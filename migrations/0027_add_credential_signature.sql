-- 0027_add_credential_signature.sql
--
-- Olympus-native SBT (Soulbound Token) infrastructure.  Every credential
-- row is BJJ-EdDSA-signed by the federation authority key at issue time,
-- and (when revoked) again at revocation time.  External parties verify
-- with the federation's BJJ public key — no network call back to the
-- node, and no EVM mirror required.
--
-- The schema extends the existing `key_credentials` table from migration
-- 0001 rather than introducing a new one — the row identity, issuer,
-- holder_key, and commit_id fields are reused intact.
--
-- New columns
-- -----------
--   * details JSONB                    — caller-supplied metadata (claims,
--                                        expiry hints, display fields).
--                                        Hashed verbatim into commit_id.
--   * issuer_pubkey_x / _y TEXT        — BJJ pubkey (decimal string of
--                                        the Fr coordinate) used to
--                                        verify issued_sig_*.  Stored on
--                                        the row so verifiers don't need
--                                        out-of-band federation lookup.
--   * issued_sig_r8x / _r8y / _s TEXT  — BJJ-EdDSA signature over the
--                                        BLAKE3 commit_id, expressed as
--                                        a BN254 Fr field element.
--   * revoked_sig_r8x / _r8y / _s TEXT — Signature over a separate
--                                        revocation digest:
--                                          BLAKE3(OLY:SBT:REVOKE:V1
--                                            | commit_id_hex
--                                            | revoked_at_unix).
--                                        NULL while not revoked.
--
-- Migration 0016 introduced an `evm_pending_ops` table for the
-- (never-shipped, since-retired) on-chain mirror; this migration drops
-- it so the schema reflects the native-only reality documented in
-- docs/sbt-deployment.md.

ALTER TABLE key_credentials
    ADD COLUMN IF NOT EXISTS details          JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS issuer_pubkey_x  TEXT,
    ADD COLUMN IF NOT EXISTS issuer_pubkey_y  TEXT,
    ADD COLUMN IF NOT EXISTS issued_sig_r8x   TEXT,
    ADD COLUMN IF NOT EXISTS issued_sig_r8y   TEXT,
    ADD COLUMN IF NOT EXISTS issued_sig_s     TEXT,
    ADD COLUMN IF NOT EXISTS revoked_sig_r8x  TEXT,
    ADD COLUMN IF NOT EXISTS revoked_sig_r8y  TEXT,
    ADD COLUMN IF NOT EXISTS revoked_sig_s    TEXT;

CREATE INDEX IF NOT EXISTS ix_key_credentials_holder
    ON key_credentials (holder_key);

CREATE INDEX IF NOT EXISTS ix_key_credentials_type
    ON key_credentials (credential_type);

DROP TABLE IF EXISTS evm_pending_ops;
