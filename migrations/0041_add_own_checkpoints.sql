-- Red-team CR-5 + CR-7 / threat-model T2 (anchoring chain not actually
-- functional + anchored root ≠ federation root): unify the canonical
-- ledger-root semantic for both anchoring and federation. Before this
-- migration:
--
--   * `anchoring/cron.rs::latest_snapshot` read `ingest_records.merkle_root`
--     (BLAKE3) — a column the v0.9 ingest path never writes, so the
--     anchor cron was inert: zero rows ever landed in `anchor_receipts`
--     in the always-on path. Court-evidence §1's headline "three
--     independent third-party services" was empirically false.
--   * `federation::checkpoint::build_own_checkpoint` signed the Poseidon
--     `snapshot_root` (the real ledger tree root). Two different hash
--     families committing to the same logical state with no row joining
--     them: an opposing expert can show the anchor and the federation
--     checkpoint and demand a verifier reconcile them.
--   * `anchor_receipts.checkpoint_id` was nullable AND always NULL from
--     the cron path (the cron passed `None` to `anchor_all`), so the
--     receipt couldn't be joined back to any persisted checkpoint.
--
-- `own_checkpoints` is the canonical row. Both the always-on anchor
-- cron AND the federation `build_own_checkpoint` path now read/write
-- here, and `anchor_receipts.checkpoint_id` FK-links to it. The chosen
-- root semantic is **Poseidon `snapshot_root`** (the ledger Merkle root
-- federation already used), because:
--   - it's the ZK-friendly choice (federation gossips a Groth16
--     `document_existence` proof attesting to this root);
--   - it's actually populated by `ingest_file` (unlike the BLAKE3
--     `merkle_root` column, which the cron previously filtered on but
--     ingest never wrote);
--   - one row, one signature, one anchor digest, one wire envelope.

CREATE TABLE IF NOT EXISTS own_checkpoints (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The Poseidon `snapshot_root` from the latest ingest row at the
    -- time this checkpoint was emitted, as a decimal Fr string. Same
    -- value the federation BJJ signature commits to.
    ledger_root              TEXT        NOT NULL,
    tree_size                BIGINT      NOT NULL,
    checkpoint_timestamp     BIGINT      NOT NULL,
    -- BJJ-EdDSA authority pubkey hash (decimal Fr) and signature
    -- components (decimal Fr). NULL when no BJJ authority key was
    -- loaded — the cron then writes a sig-less row that still anchors
    -- a domain-separated digest, but federation cannot gossip it.
    authority_pubkey_hash    TEXT        NULL,
    sig_r8x                  TEXT        NULL,
    sig_r8y                  TEXT        NULL,
    sig_s                    TEXT        NULL,
    -- BLAKE3(`OLY:CHECKPOINT_ANCHOR:V1` | …) — the digest external
    -- anchors commit to. Computed once at row insert so consumers
    -- (cron, /anchors API) read the same bytes the BJJ envelope
    -- describes.
    anchor_hash              BYTEA       NOT NULL,
    -- Groth16 `document_existence` proof JSON (snarkjs shape) +
    -- public_signals (decimal Fr array). NULL when proving artifacts
    -- weren't staged at emit time (operator hasn't run
    -- `setup_circuits.sh`) or the source ingest record lacks the
    -- snapshot columns. Federation will not gossip a checkpoint whose
    -- proof is NULL (audit H-11/M-5 — null-proof envelopes were the
    -- forgery primitive closed last cycle).
    groth16_proof            JSONB       NULL,
    public_signals           JSONB       NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Federation `build_own_checkpoint` reads "latest" — i.e. most recent
-- row by `checkpoint_timestamp`. Index supports that lookup.
CREATE INDEX IF NOT EXISTS idx_own_checkpoints_ts
    ON own_checkpoints (checkpoint_timestamp DESC);

-- Anchor cron reads "next un-anchored". Three indexes (one per anchor
-- kind) would be redundant — a single covering index on
-- (checkpoint_timestamp, id) is enough: the cron pulls the latest row
-- and `anchor_all` already idempotently skips kinds it's already
-- written for via `(anchored_hash, anchor_kind)`.

-- anchor_receipts.checkpoint_id was already declared in 0026 as
-- `UUID NULL`. This migration upgrades the FK to actually reference
-- own_checkpoints. Existing rows have `checkpoint_id = NULL` from the
-- cron-passes-None path (red-team CR-5), so the FK is `ON DELETE SET
-- NULL` to avoid breaking those historical rows. Going forward the cron
-- writes the row first and passes its id.
ALTER TABLE anchor_receipts
    ADD CONSTRAINT anchor_receipts_checkpoint_fk
        FOREIGN KEY (checkpoint_id) REFERENCES own_checkpoints(id)
        ON DELETE SET NULL;
