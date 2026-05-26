-- Persist the Baby Jubjub authority private key in dev mode.
--
-- Background: bootstrap auto-generates a BJJ authority keypair on first
-- launch and stores the *pubkey* in `account_signing_keys` so verifiers
-- can recover it. The *secret* has historically only been surfaced once
-- via the GUI's initial-secrets modal — the operator is expected to set
-- it as `OLYMPUS_BJJ_AUTHORITY_KEY` for subsequent runs. That posture
-- protects production (secret never touches disk) but makes a vanilla
-- `cargo tauri dev` lose signing capability on every restart, which
-- silently breaks ledger-snapshot signatures.
--
-- This column holds the 32-byte BJJ private key in dev. Bootstrap writes
-- it ONLY when `OLYMPUS_ENV != production`; production deployments leave
-- it NULL and require the env var as before.
ALTER TABLE account_signing_keys
    ADD COLUMN IF NOT EXISTS bjj_private_dev BYTEA;
