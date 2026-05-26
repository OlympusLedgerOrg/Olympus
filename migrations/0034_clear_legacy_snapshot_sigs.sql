-- Mark Ed25519-era snapshot signatures as legacy without destroying them.
--
-- The snapshot signer migrated from Ed25519 (raw 128-char hex stored in
-- `snapshot_sig`) to BJJ EdDSA-Poseidon (JSON object with r8x/r8y/s). The
-- new JSON-parsing verifier can't validate the legacy format, but the
-- attestation data itself (root, index, size, path, signature bytes) is a
-- historical record we shouldn't destroy: a future operator restoring the
-- old Ed25519 authority pubkey could still cross-check it offline.
--
-- Add a boolean marker so verifier code can short-circuit legacy rows as
-- "pending" at read time, and leave the original snapshot_* columns
-- untouched.
ALTER TABLE ingest_records
    ADD COLUMN IF NOT EXISTS snapshot_sig_legacy BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill the marker. A legacy Ed25519 sig is a non-JSON string in
-- `snapshot_sig` — the new format is a JSON object that starts with '{'.
UPDATE ingest_records
   SET snapshot_sig_legacy = TRUE
 WHERE snapshot_sig IS NOT NULL
   AND snapshot_sig NOT LIKE '{%}';
