-- 0048_checkpoint_quorum_signatures.sql
--
-- M-of-N federation co-signatures over a checkpoint (ADR-0033).
--
-- A node's own checkpoint (migration 0041, `own_checkpoints`) is signed by a
-- single BJJ authority key. This migration adds an optional federation quorum
-- over that checkpoint: M valid BJJ-EdDSA signatures from a pinned set of N
-- trusted peers (the node's authority key + its trusted peers' authority keys,
-- as registered in `peer_nodes`), collected over Tor.
--
-- Every quorum signer signs the SAME domain-separated message
-- (`OLY:CHECKPOINT:QUORUM:V2`), which binds the checkpoint identity
-- `(chain_id = authority_pubkey_hash, epoch = tree_size, ledger_root)` plus the
-- threshold and the canonical pinned signer set, so a signature for one ledger
-- or height can never be replayed onto another, and a post-hoc tamper to any of
-- those drops every stored signature at verify time (fail-closed). The tag is
-- structurally disjoint from the SBT quorum (`OLY:SBT:QUORUM:V2`) and the
-- single-signer checkpoint signature.
--
-- This mirrors `credential_quorum_signatures` (migration 0032), but keyed to an
-- `own_checkpoints` row instead of a credential. Verification is reproducible
-- offline against the pinned signer set + threshold (carried on the checkpoint /
-- gossip envelope), even if federation membership later changes.
--
-- One row per (checkpoint, signer); the UNIQUE constraint makes "the same signer
-- signed twice" a no-op rather than a way to inflate the satisfied count.
CREATE TABLE IF NOT EXISTS checkpoint_quorum_signatures (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    checkpoint_id   UUID NOT NULL REFERENCES own_checkpoints(id) ON DELETE CASCADE,
    signer_pubkey_x TEXT NOT NULL,
    signer_pubkey_y TEXT NOT NULL,
    sig_r8x         TEXT NOT NULL,
    sig_r8y         TEXT NOT NULL,
    sig_s           TEXT NOT NULL,
    signed_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (checkpoint_id, signer_pubkey_x, signer_pubkey_y)
);

CREATE INDEX IF NOT EXISTS ix_checkpoint_quorum_signatures_checkpoint
    ON checkpoint_quorum_signatures (checkpoint_id);
