-- Olympus Phase 0.5 Migration 004
-- Store TSA certificate fingerprints alongside RFC 3161 tokens

ALTER TABLE timestamp_tokens
ADD COLUMN IF NOT EXISTS tsa_cert_fingerprint TEXT;

COMMENT ON COLUMN timestamp_tokens.tsa_cert_fingerprint IS
'SHA-256 fingerprint (hex) of the TSA signing certificate embedded in the TimeStampToken.';
