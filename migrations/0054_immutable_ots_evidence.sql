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
    -- TRUNCATE is handled first, and before any NEW/OLD access: it fires a
    -- statement-level trigger, where neither record is assigned.
    --
    -- Bare `TRUNCATE anchor_receipts` is already refused by PostgreSQL, because
    -- the table is the target of foreign keys (its own `supersedes_receipt_id`
    -- self-reference from 0051, plus the 0052 retry-state FK). But
    -- `TRUNCATE ... CASCADE` is not, and row-level DELETE triggers never fire
    -- for TRUNCATE, so without this branch one CASCADE would erase every
    -- receipt.
    --
    -- Truncating an EMPTY table is permitted: the invariant is "evidence is
    -- never destroyed", not "this statement is never issued", and an empty
    -- table holds no evidence. Rejecting unconditionally would instead break a
    -- legitimate parent operation — `anchor_receipts.checkpoint_id` references
    -- `own_checkpoints`, so `TRUNCATE own_checkpoints ... CASCADE` reaches this
    -- table even when it is empty.
    --
    -- The exemption is not a loophole:
    --   * Race-free — TRUNCATE holds ACCESS EXCLUSIVE on every target and
    --     cascaded table before BEFORE TRUNCATE triggers fire, so no row can
    --     appear between this check and the truncate.
    --   * Unreachable by emptying the table first — DELETE is refused below, so
    --     a populated table can never be reduced to an empty one.
    IF TG_OP = 'TRUNCATE' THEN
        IF EXISTS (SELECT 1 FROM anchor_receipts) THEN
            RAISE EXCEPTION 'anchor receipt evidence is append-only'
                USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END IF;

    -- Row-level DELETE is refused outright: a superseded receipt is retained,
    -- never removed.
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

-- TRUNCATE needs its own statement-level trigger; the row-level one above never
-- sees it. Recreated together with that trigger so the two cannot drift apart
-- and leave the invariant half-enforced.
DROP TRIGGER IF EXISTS anchor_receipts_evidence_no_truncate ON anchor_receipts;
CREATE TRIGGER anchor_receipts_evidence_no_truncate
BEFORE TRUNCATE ON anchor_receipts
FOR EACH STATEMENT
EXECUTE FUNCTION reject_anchor_receipt_evidence_mutation();
