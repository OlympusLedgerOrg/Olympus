-- SPDX-FileCopyrightText: 2026 Olympus Contributors
-- SPDX-License-Identifier: Apache-2.0

-- Redaction blind-secret fingerprint registry (docs/key-rotation.md;
-- follow-up to "Require independent redaction blind secret in production").
-- Reuses the generic `account_signing_keys` lifecycle columns migration 0056
-- added (valid_from / valid_until / revoked_at / replaced_by_key_id) for a
-- third `purpose`, the same shape as the ingest-signing-key registry
-- (migration 0057).
--
-- Unlike the ingest signing key, `OLYMPUS_REDACTION_BLIND_SECRET` is a
-- **secret**, not a public verifying key — the per-object Pedersen blinding
-- for every already-redacted document depends on it
-- (`state::resolve_redaction_blind_secret`), so the registry must never store
-- it in recoverable form. `public_key` instead holds a 64-char lowercase-hex
-- domain-separated BLAKE3 fingerprint of the resolved 32-byte secret
-- (`state::fingerprint_redaction_blind_secret`) — enough to detect "did the
-- operator's configured secret change since last boot" without persisting
-- anything an attacker could invert or replay as the secret itself.
--
-- One row per activation interval, not per distinct secret
-- (`bootstrap::ensure_redaction_blind_secret_fingerprint`): unbounded
-- (`valid_from` NULL) for the first-ever secret, superseded (this table's
-- existing lifecycle stamps) on every subsequent change. Unlike the ingest
-- key (`ensure_ingest_signing_key`, no confirmation required — an accidental
-- swap there was always undetectable and unprotected), a fingerprint change
-- here IS gated: the blind secret changing silently makes every
-- previously-redacted object's blinding unreproducible with no error, so
-- `ensure_redaction_blind_secret_fingerprint` refuses to adopt (and record)
-- a changed fingerprint unless the operator opts in with
-- `OLYMPUS_BLIND_SECRET_ROTATION=confirm`, mirroring
-- `bootstrap::rotate_authority` / `OLYMPUS_AUTHORITY_ROTATION=confirm`.

CREATE UNIQUE INDEX IF NOT EXISTS ix_account_signing_keys_single_active_blind_secret
    ON account_signing_keys ((purpose))
    WHERE purpose = 'redaction_blind_secret' AND revoked_at IS NULL;
