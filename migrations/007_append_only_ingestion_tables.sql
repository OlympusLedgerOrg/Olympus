-- Olympus Phase 0.5 Migration 007
-- Append-only enforcement for ingestion durability tables
--
-- Purpose:
--   Ensure ingestion_batches and ingestion_proofs are write-once so that
--   ingestion audit trails cannot be rewritten.
--
-- Security Properties:
--   - UPDATE and DELETE are rejected for ingestion durability tables.
--   - Uses the shared olympus_reject_mutation() trigger from migration 003.

-- ---------------------------------------------------------------------
-- ingestion_batches
-- ---------------------------------------------------------------------

DROP TRIGGER IF EXISTS ingestion_batches_reject_update ON ingestion_batches;
CREATE TRIGGER ingestion_batches_reject_update
BEFORE UPDATE ON ingestion_batches
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

DROP TRIGGER IF EXISTS ingestion_batches_reject_delete ON ingestion_batches;
CREATE TRIGGER ingestion_batches_reject_delete
BEFORE DELETE ON ingestion_batches
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

COMMENT ON TABLE ingestion_batches IS
'Ingestion batch registry. Append-only; UPDATE and DELETE are rejected by trigger.';

-- ---------------------------------------------------------------------
-- ingestion_proofs
-- ---------------------------------------------------------------------

DROP TRIGGER IF EXISTS ingestion_proofs_reject_update ON ingestion_proofs;
CREATE TRIGGER ingestion_proofs_reject_update
BEFORE UPDATE ON ingestion_proofs
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

DROP TRIGGER IF EXISTS ingestion_proofs_reject_delete ON ingestion_proofs;
CREATE TRIGGER ingestion_proofs_reject_delete
BEFORE DELETE ON ingestion_proofs
FOR EACH ROW
EXECUTE FUNCTION olympus_reject_mutation();

COMMENT ON TABLE ingestion_proofs IS
'Durable ingestion proof mappings. Append-only; UPDATE and DELETE are rejected by trigger.';
