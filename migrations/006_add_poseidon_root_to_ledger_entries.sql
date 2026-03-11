-- Migration 006: Add poseidon_root column to ledger_entries
--
-- This migration adds an optional poseidon_root column to ledger_entries to
-- support dual-root commitments.  Existing entries that pre-date this migration
-- will have NULL in this column and continue to use the legacy entry-hash
-- formula.  New entries that include a Poseidon Merkle root will have their
-- entry_hash computed via create_dual_root_commitment(blake3_root, poseidon_root).
--
-- The column stores the Poseidon root as a decimal string (BN128 field element)
-- which is consistent with the rest of the Olympus codebase.

ALTER TABLE ledger_entries
    ADD COLUMN IF NOT EXISTS poseidon_root TEXT DEFAULT NULL;

-- Index to support efficient lookups by Poseidon root (e.g., for cross-root
-- validation queries).
CREATE INDEX IF NOT EXISTS ledger_entries_poseidon_root_idx
    ON ledger_entries(poseidon_root)
    WHERE poseidon_root IS NOT NULL;

-- Comment documenting the dual-root entry format version:
--   NULL poseidon_root  => legacy entry hash (BLAKE3 canonical-JSON payload hash)
--   non-NULL poseidon_root => dual-root commitment hash
COMMENT ON COLUMN ledger_entries.poseidon_root IS
    'Poseidon Merkle root (BN128 decimal string). NULL for legacy entries. '
    'When present, entry_hash = blake3(LEDGER_PREFIX || blake3_root || "|" || poseidon_root_bytes).';
