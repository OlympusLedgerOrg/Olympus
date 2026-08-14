-- SPDX-License-Identifier: Apache-2.0
--
-- 0058_peer_checkpoints_v3_indexes.sql
--
-- Extend the peer_checkpoints dedup + equivocation indexes to the live
-- wire version (audit M2).
--
-- Migration 0051 created three PARTIAL indexes on `peer_checkpoints` gated
-- `WHERE wire_version = 2`: the UNIQUE exact-statement dedup backstop
-- (`peer_checkpoints_v2_statement_unique`) and the two equivocation-support
-- indexes (`_v2_equivocation_height`, `_v2_equivocation_timestamp`). Migration
-- 0053 then made `wire_version = 3` the ONLY accepted version
-- (`federation::PEER_CHECKPOINT_WIRE_VERSION = 3`; `verify_and_store` rejects
-- anything else) but never recreated those indexes. Every live row is therefore
-- v3 and matched by NONE of the three partial indexes, so:
--   * the exact-statement UNIQUE constraint no longer arbitrates concurrent
--     replays -- `store_peer_checkpoint`'s `ON CONFLICT DO NOTHING` lost its
--     backstop (runtime correctness is still held by the per-statement advisory
--     lock in `verify_and_store`, so this is a defense-in-depth loss, not a live
--     dedup break), and
--   * equivocation detection and the replay lookup fall back to sequential scans
--     on a monotonically growing, court-evidence table.
--
-- Recreate all three so they cover BOTH accepted versions. `IN (2, 3)` rather
-- than a bare `= 3` keeps any residual/backfilled v2 rows covered too. The old
-- v2-only indexes are dropped (their coverage is a strict subset of the new
-- predicate). Creating the UNIQUE index cannot fail on existing duplicates: the
-- per-statement advisory lock has always prevented exact-statement duplicates at
-- runtime, and equivocating rows differ in `ledger_root` so they are distinct
-- keys here by design.

DROP INDEX IF EXISTS peer_checkpoints_v2_statement_unique;
DROP INDEX IF EXISTS peer_checkpoints_v2_equivocation_height;
DROP INDEX IF EXISTS peer_checkpoints_v2_equivocation_timestamp;

CREATE UNIQUE INDEX IF NOT EXISTS peer_checkpoints_statement_unique
    ON peer_checkpoints (
        signer_pubkey_x,
        signer_pubkey_y,
        wire_version,
        checkpoint_scope,
        shard_id,
        ledger_root,
        tree_size,
        checkpoint_timestamp
    )
    WHERE wire_version IN (2, 3);

CREATE INDEX IF NOT EXISTS peer_checkpoints_equivocation_height
    ON peer_checkpoints (
        signer_pubkey_x,
        signer_pubkey_y,
        checkpoint_scope,
        shard_id,
        tree_size
    )
    WHERE wire_version IN (2, 3);

CREATE INDEX IF NOT EXISTS peer_checkpoints_equivocation_timestamp
    ON peer_checkpoints (
        signer_pubkey_x,
        signer_pubkey_y,
        checkpoint_scope,
        shard_id,
        checkpoint_timestamp
    )
    WHERE wire_version IN (2, 3);
