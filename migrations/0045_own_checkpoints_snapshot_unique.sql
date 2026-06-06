-- Red-team CKPT-1 closure. PR #1165 introduced `own_checkpoints` with a
-- snapshot-dedup optimization at `fetch_existing_for_snapshot(ledger_root,
-- tree_size)` (anchoring/own_checkpoint.rs): the cron looks up an existing
-- row matching the current `(ledger_root, tree_size)` snapshot and reuses
-- it instead of re-proving. Without a DB-level UNIQUE constraint, a
-- compromised operator (or a future SQL-injection vector) could INSERT a
-- forged row with `(ledger_root='0x…', tree_size=N)` for some N that the
-- legitimate ingest pipeline will eventually produce; on the next matching
-- snapshot the cron would silently reuse the forged row, propagating it
-- into the admin bundle producer and out to opposing counsel.
--
-- The cron is the only legitimate writer and is serialized (one tokio task
-- driving the producer chain), so the constraint never fires on honest
-- operation. It is pure defence-in-depth against an attacker with DB write
-- access. Cheap (one b-tree per unique pair) and complements the existing
-- admin auth + Poseidon pubkey-hash check on the bundle export path.

-- Defensive dedup before the constraint: if any pre-existing duplicate
-- (ledger_root, tree_size) rows are present (e.g. an attacker-planted
-- forgery — exactly the CKPT-1 threat — or a pre-constraint race), a bare
-- ADD CONSTRAINT would abort and wedge startup. Keep the canonical row per
-- pair and drop the rest. "Canonical" matches the read path
-- `fetch_existing_for_snapshot` (ORDER BY checkpoint_timestamp DESC): keep
-- the latest checkpoint_timestamp, tie-broken by greatest id for
-- determinism.
DELETE FROM own_checkpoints a
USING own_checkpoints b
WHERE a.ledger_root = b.ledger_root
  AND a.tree_size = b.tree_size
  AND (a.checkpoint_timestamp < b.checkpoint_timestamp
       OR (a.checkpoint_timestamp = b.checkpoint_timestamp AND a.id < b.id));

ALTER TABLE own_checkpoints
    ADD CONSTRAINT own_checkpoints_ledger_root_tree_size_unique
        UNIQUE (ledger_root, tree_size);
