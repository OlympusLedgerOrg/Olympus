-- Olympus Phase 0.5 Migration 003
-- Append-only enforcement for all core tables
--
-- Purpose:
--   Prevent UPDATE and DELETE operations on ledger_entries, shard_headers,
--   smt_leaves, and smt_nodes. This matches the existing enforcement on
--   timestamp_tokens (migration 002).
--
-- Security Properties:
--   - All core tables become truly append-only at the DB trigger level.
--   - Any attempt to UPDATE or DELETE raises an exception with ERRCODE 25006
--     (read_only_sql_transaction), which is the standard code for
--     "cannot modify data in a read-only context."

-- ---------------------------------------------------------------------
-- Shared trigger function (reusable across all append-only tables)
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION olympus_reject_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not allowed', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '25006';
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------
-- ledger_entries
-- ---------------------------------------------------------------------

DROP TRIGGER IF EXISTS ledger_entries_reject_update ON ledger_entries;
CREATE TRIGGER ledger_entries_reject_update
BEFORE UPDATE ON ledger_entries
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

DROP TRIGGER IF EXISTS ledger_entries_reject_delete ON ledger_entries;
CREATE TRIGGER ledger_entries_reject_delete
BEFORE DELETE ON ledger_entries
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

COMMENT ON TABLE ledger_entries IS
'Append-only ledger chain. UPDATE and DELETE are rejected by trigger.';

-- ---------------------------------------------------------------------
-- shard_headers
-- ---------------------------------------------------------------------

DROP TRIGGER IF EXISTS shard_headers_reject_update ON shard_headers;
CREATE TRIGGER shard_headers_reject_update
BEFORE UPDATE ON shard_headers
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

DROP TRIGGER IF EXISTS shard_headers_reject_delete ON shard_headers;
CREATE TRIGGER shard_headers_reject_delete
BEFORE DELETE ON shard_headers
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

COMMENT ON TABLE shard_headers IS
'Signed shard root commitments. Append-only; UPDATE and DELETE are rejected by trigger.';

-- ---------------------------------------------------------------------
-- smt_leaves
-- ---------------------------------------------------------------------

DROP TRIGGER IF EXISTS smt_leaves_reject_update ON smt_leaves;
CREATE TRIGGER smt_leaves_reject_update
BEFORE UPDATE ON smt_leaves
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

DROP TRIGGER IF EXISTS smt_leaves_reject_delete ON smt_leaves;
CREATE TRIGGER smt_leaves_reject_delete
BEFORE DELETE ON smt_leaves
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

COMMENT ON TABLE smt_leaves IS
'Sparse Merkle Tree leaf nodes. Append-only; UPDATE and DELETE are rejected by trigger.';

-- ---------------------------------------------------------------------
-- smt_nodes
-- ---------------------------------------------------------------------

DROP TRIGGER IF EXISTS smt_nodes_reject_update ON smt_nodes;
CREATE TRIGGER smt_nodes_reject_update
BEFORE UPDATE ON smt_nodes
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

DROP TRIGGER IF EXISTS smt_nodes_reject_delete ON smt_nodes;
CREATE TRIGGER smt_nodes_reject_delete
BEFORE DELETE ON smt_nodes
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

COMMENT ON TABLE smt_nodes IS
'Sparse Merkle Tree internal nodes. Append-only; UPDATE and DELETE are rejected by trigger.';
