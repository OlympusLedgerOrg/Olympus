-- 0061_own_checkpoints_quorum_params.sql
--
-- ADR-0033 "Remaining producer work": pin the M-of-N checkpoint-quorum
-- parameters a row was actually co-signed under.
--
-- migration 0048 (`checkpoint_quorum_signatures`) persists the collected
-- signatures, but nothing pinned the `(threshold, signer-set)` they were
-- collected against on the `own_checkpoints` row itself — so reproducible
-- offline verification (`quorum::checkpoint::verify_checkpoint_quorum`)
-- had nowhere to read the pinned parameters from, only the live
-- `peer_nodes` table, which can drift after signing. This mirrors
-- `key_credentials.quorum_threshold` / `quorum_signers` (migration 0032).
--
-- Both columns are NULL until the federation gossip loop first attempts
-- quorum collection for a checkpoint; a vanilla (non-federation) build or a
-- node with no trusted peers simply never populates them.
ALTER TABLE own_checkpoints
    ADD COLUMN IF NOT EXISTS checkpoint_quorum_threshold INTEGER,
    ADD COLUMN IF NOT EXISTS checkpoint_quorum_signers   JSONB;

-- Defence-in-depth, mirroring migration 0032's identical guard: NULL
-- threshold = no quorum attempted yet (the common case), so the constraint
-- only bites once a value is actually written.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_own_checkpoints_quorum_threshold_positive'
          AND conrelid = 'own_checkpoints'::regclass
    ) THEN
        ALTER TABLE own_checkpoints
            ADD CONSTRAINT ck_own_checkpoints_quorum_threshold_positive
            CHECK (checkpoint_quorum_threshold IS NULL OR checkpoint_quorum_threshold >= 1);
    END IF;
END $$;
