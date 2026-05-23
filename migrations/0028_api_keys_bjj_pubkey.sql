-- 0028_api_keys_bjj_pubkey.sql
--
-- "One master key" unification.  Before this migration the system had
-- two parallel secrets per identity: an opaque 32-byte API key (only its
-- BLAKE3 hash persisted) and a Baby Jubjub private key (never persisted,
-- pubkey only).  After this migration every API key row optionally
-- carries the BJJ pubkey of the identity that holds it — and new keys
-- are minted by deriving the API-key bytes from the BJJ private key
-- itself, so the holder has a single secret to manage.
--
-- Derivation rule (src-tauri/src/crypto.rs::derive_api_key_from_bjj):
--
--     api_key = "oly_" || hex(BLAKE3("OLY:APIKEY:V1" || bjj_priv))
--
-- The BLAKE3 step is one-way, so revealing the api_key cannot reveal
-- the bjj_priv. But the holder who keeps bjj_priv can re-derive the
-- api_key losslessly — which is the recovery story.
--
-- Existing rows (pre-#945) keep bjj_pubkey_* NULL; they continue to
-- authenticate by hash exactly as before. New rows populate both
-- columns. The `system-bootstrap` row gets backfilled on the next
-- bootstrap run because bootstrap.rs now derives the API key from
-- the freshly-loaded (or freshly-generated) BJJ authority key.

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS bjj_pubkey_x TEXT,
    ADD COLUMN IF NOT EXISTS bjj_pubkey_y TEXT;

CREATE INDEX IF NOT EXISTS ix_api_keys_bjj_pubkey
    ON api_keys (bjj_pubkey_x, bjj_pubkey_y)
    WHERE bjj_pubkey_x IS NOT NULL;
