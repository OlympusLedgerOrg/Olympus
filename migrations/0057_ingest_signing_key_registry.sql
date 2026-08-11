-- SPDX-FileCopyrightText: 2026 Olympus Contributors
-- SPDX-License-Identifier: Apache-2.0

-- Ingest (redaction-bundle) Ed25519 signing-key registry (docs/key-rotation.md;
-- ROADMAP "in-band key rotation and revocation" — historical redaction/ingest
-- issuer keys). Reuses the generic `account_signing_keys` lifecycle columns
-- migration 0056 added (valid_from / valid_until / revoked_at /
-- replaced_by_key_id) for a second `purpose`, the same way the authority-key
-- registry uses them: `public_key` holds the 64-char lowercase-hex Ed25519
-- verifying key (the column the table already had for exactly this shape —
-- unlike the BJJ authority, which stores its coordinates in the separate
-- bjj_pubkey_x/y columns because a single Fr-pair doesn't fit `public_key`'s
-- historical dataset-key convention).
--
-- One row per distinct ingest signing pubkey ever loaded by this instance
-- (`bootstrap::ensure_ingest_signing_key`): unbounded (`valid_from` NULL) for
-- the first-ever key, superseded (this table's existing lifecycle stamps) on
-- every subsequent `OLYMPUS_INGEST_SIGNING_KEY` change. `GET
-- /redaction/issuer-key` serves the full history so a verifier who only has
-- the live endpoint (not an out-of-band archive) can still resolve which key
-- signed an older bundle.

CREATE UNIQUE INDEX IF NOT EXISTS ix_account_signing_keys_single_active_ingest
    ON account_signing_keys ((purpose))
    WHERE purpose = 'ingest_signing' AND revoked_at IS NULL;
