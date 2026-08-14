-- SPDX-FileCopyrightText: 2026 Olympus Contributors
-- SPDX-License-Identifier: Apache-2.0

-- 0062_shards_checkpoint_quorum_threshold.sql
--
-- ADR-0033 "per-checkpoint threshold override": let an operator override the
-- checkpoint-quorum threshold `M` (otherwise sourced uniformly from
-- OLYMPUS_CHECKPOINT_QUORUM_THRESHOLD) on a per-shard basis, since checkpoints
-- are shard-scoped (own_checkpoints.checkpoint_scope = 'shard') and produced
-- by the cron/gossip loop rather than a per-call API request that could carry
-- its own override field (contrast key_credentials.quorum_threshold, set per
-- issuance request).
--
-- NULL (the default for every existing and newly-registered shard) means
-- "use the env default" — today's behaviour is unchanged until an operator
-- explicitly sets an override via PATCH /admin/shards/{shard_id}/checkpoint-
-- quorum-threshold.
ALTER TABLE shards
    ADD COLUMN IF NOT EXISTS checkpoint_quorum_threshold_override INTEGER;

-- Defence-in-depth, mirroring migration 0061's identical guard on
-- own_checkpoints.checkpoint_quorum_threshold: NULL = no override set (the
-- common case), so the constraint only bites once a value is actually written.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_shards_checkpoint_quorum_threshold_positive'
          AND conrelid = 'shards'::regclass
    ) THEN
        ALTER TABLE shards
            ADD CONSTRAINT ck_shards_checkpoint_quorum_threshold_positive
            CHECK (checkpoint_quorum_threshold_override IS NULL OR checkpoint_quorum_threshold_override >= 1);
    END IF;
END $$;
