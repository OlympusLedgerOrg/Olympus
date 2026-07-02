-- ADR-0036 signed request envelope replay cache.
--
-- Rows are inserted only after the cheap Ed25519 leg verifies. The unique
-- (key_id, nonce) constraint is the replay gate. Hybrid/PQC verification
-- failures must delete the row so a corrected request can be retried.
-- Runtime cleanup lives in signed_request.rs::spawn_signed_request_nonce_reaper
-- and deletes expired rows through ix_signed_request_nonces_expires_at.
CREATE TABLE IF NOT EXISTS signed_request_nonces (
    key_id         TEXT NOT NULL,
    nonce          TEXT NOT NULL,
    operator_id    TEXT NOT NULL,
    scope          TEXT NOT NULL,
    request_digest BYTEA NOT NULL,
    seen_at        TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMP NOT NULL,
    PRIMARY KEY (key_id, nonce)
);

CREATE INDEX IF NOT EXISTS ix_signed_request_nonces_expires_at
    ON signed_request_nonces (expires_at);
