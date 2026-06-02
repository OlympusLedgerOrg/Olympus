-- Red-team C1 (court-evidence.md §3): the documented `verify-checkpoint
-- --bundle` JS verifier path needs an Ed25519 signature over the
-- domain-separated `anchor_hash`, signed by the node's Ed25519 ingest
-- authority at checkpoint emission time. Migration 0041 added Baby Jubjub
-- EdDSA-Poseidon signature components (sig_r8x/r8y/s) — those commit to
-- the Poseidon `snapshot_root` and are the federation-gossipable proof.
-- The Ed25519 signature here is the layer the court-evidence.md table
-- §2 row 3 actually documents: an off-the-shelf signature over the same
-- anchor_hash bytes the external TSAs / Rekor / OTS commit to.
--
-- Two columns, both NULL when no `OLYMPUS_INGEST_SIGNING_KEY` is loaded
-- (dev path with auto-generated ephemeral key): the cron still writes
-- the row, the bundle producer just won't emit a bundle for that row.
-- The signature is computed once at `own_checkpoint::build_and_persist`
-- time so re-export later (after key rotation) reproduces byte-identical
-- bundles forever — the chain of custody requires the signature to be
-- pinned at emission, not recomputed on every export.

ALTER TABLE own_checkpoints
    -- Hex-encoded Ed25519 verifying key (32 bytes → 64 hex chars), so
    -- third-party verifiers don't need to look up which key signed
    -- which checkpoint after a rotation. The bundle.json includes this
    -- so the JS verifier can verify the signature against the embedded
    -- pubkey AND check that pubkey was registered with the agency/CA
    -- (see court-evidence.md §6 "Key persistence").
    ADD COLUMN IF NOT EXISTS ed25519_pubkey_hex     TEXT NULL,
    -- Hex-encoded Ed25519 signature (64 bytes → 128 hex chars) over
    -- `anchor_hash` (the BLAKE3 domain-separated digest already stored
    -- in this row). Standard Ed25519 — RFC 8032 verify, no Olympus-
    -- specific reconstruction needed.
    ADD COLUMN IF NOT EXISTS ed25519_signature_hex  TEXT NULL;
