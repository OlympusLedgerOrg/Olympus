-- SPDX-License-Identifier: Apache-2.0
--
-- 0054_immutable_ots_evidence.sql
--
-- OTS verification advances by appending successors:
--   pending -> structurally upgraded -> trusted-header verified.
-- Receipt identity and evidence must never be rewritten or deleted. Only the
-- bounded lease/retry bookkeeping introduced by migration 0052 remains
-- mutable.

CREATE OR REPLACE FUNCTION reject_anchor_receipt_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'anchor receipt evidence is append-only'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.anchor_kind IS DISTINCT FROM OLD.anchor_kind
       OR NEW.anchored_hash IS DISTINCT FROM OLD.anchored_hash
       OR NEW.checkpoint_id IS DISTINCT FROM OLD.checkpoint_id
       OR NEW.receipt_blob IS DISTINCT FROM OLD.receipt_blob
       OR NEW.target IS DISTINCT FROM OLD.target
       OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at
       OR NEW.verified_at IS DISTINCT FROM OLD.verified_at
       OR NEW.metadata IS DISTINCT FROM OLD.metadata
       OR NEW.supersedes_receipt_id IS DISTINCT FROM OLD.supersedes_receipt_id
       OR NEW.evidence_version IS DISTINCT FROM OLD.evidence_version
    THEN
        RAISE EXCEPTION 'anchor receipt evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS anchor_receipts_evidence_immutable ON anchor_receipts;
CREATE TRIGGER anchor_receipts_evidence_immutable
BEFORE UPDATE OR DELETE ON anchor_receipts
FOR EACH ROW
EXECUTE FUNCTION reject_anchor_receipt_evidence_mutation();

CREATE INDEX IF NOT EXISTS idx_anchor_receipts_ots_verification_ready
    ON anchor_receipts (
        ots_last_upgrade_attempt_at ASC NULLS FIRST,
        submitted_at ASC,
        id ASC
    )
    WHERE anchor_kind = 'ots'
      AND (
          metadata->>'phase' = 'upgraded'
          OR (
              metadata->>'bitcoin_attestation' = 'true'
              AND metadata->>'needs_upgrade' = 'false'
          )
      )
      AND metadata->>'bitcoin_attestation_verified' IS DISTINCT FROM 'true';
