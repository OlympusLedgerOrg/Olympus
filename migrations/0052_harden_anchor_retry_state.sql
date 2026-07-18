-- SPDX-License-Identifier: Apache-2.0

-- M-17: suppress known duplicate anchor submissions with at-least-once retry
-- semantics, and make the OTS upgrade queue fair across ticks and processes.

-- A receipt row is written only after an external backend responds. Without a
-- durable pre-submission claim, every cron tick re-submitted an unchanged
-- checkpoint and overlapping processes could race each other. Claims are
-- leased so a crashed worker can be retried, while a completed claim forever
-- points at the receipt that satisfies the (kind, hash, target) request. If a
-- remote accepts a request but the local outcome is ambiguous or cannot be
-- persisted, lease expiry permits re-submission.
CREATE TABLE IF NOT EXISTS anchor_submission_claims (
    anchor_kind       TEXT        NOT NULL,
    anchored_hash     BYTEA       NOT NULL,
    target            TEXT        NOT NULL,
    checkpoint_id     UUID        NULL REFERENCES own_checkpoints(id) ON DELETE SET NULL,
    status            TEXT        NOT NULL,
    receipt_id        UUID        NULL REFERENCES anchor_receipts(id),
    lease_token       UUID        NULL,
    lease_until       TIMESTAMPTZ NULL,
    attempt_count     INTEGER     NOT NULL DEFAULT 0,
    last_attempt_at   TIMESTAMPTZ NULL,
    next_retry_at     TIMESTAMPTZ NULL,
    last_error        TEXT        NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (anchor_kind, anchored_hash, target),
    CONSTRAINT anchor_submission_claim_kind_valid CHECK (
        anchor_kind IN ('rfc3161', 'rekor', 'ots')
    ),
    CONSTRAINT anchor_submission_claim_status_valid CHECK (
        status IN ('in_flight', 'retry', 'succeeded')
    ),
    CONSTRAINT anchor_submission_claim_hash_len CHECK (
        OCTET_LENGTH(anchored_hash) = 32
    ),
    CONSTRAINT anchor_submission_claim_attempts_valid CHECK (attempt_count >= 0),
    CONSTRAINT anchor_submission_claim_success_receipt CHECK (
        status <> 'succeeded' OR receipt_id IS NOT NULL
    )
);

CREATE INDEX IF NOT EXISTS idx_anchor_submission_claims_retry
    ON anchor_submission_claims (next_retry_at, lease_until)
    WHERE status IN ('retry', 'in_flight');

-- Existing receipts are already successful submissions. Seed the oldest row
-- for each logical request without deleting later historical duplicates.
INSERT INTO anchor_submission_claims (
    anchor_kind,
    anchored_hash,
    target,
    checkpoint_id,
    status,
    receipt_id,
    attempt_count,
    last_attempt_at,
    created_at,
    updated_at
)
SELECT DISTINCT ON (anchor_kind, anchored_hash, target)
       anchor_kind,
       anchored_hash,
       target,
       checkpoint_id,
       'succeeded',
       id,
       1,
       submitted_at,
       submitted_at,
       submitted_at
  FROM anchor_receipts
 WHERE OCTET_LENGTH(anchored_hash) = 32
 ORDER BY anchor_kind, anchored_hash, target, submitted_at ASC, id ASC
ON CONFLICT (anchor_kind, anchored_hash, target) DO NOTHING;

-- OTS upgrades need their own lease and retry schedule. Previously every tick
-- selected the same oldest 50 pending rows, so permanently pending calendars
-- starved every later receipt.
ALTER TABLE anchor_receipts
    ADD COLUMN IF NOT EXISTS ots_upgrade_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS ots_last_upgrade_attempt_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS ots_next_upgrade_attempt_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS ots_upgrade_lease_token UUID NULL,
    ADD COLUMN IF NOT EXISTS ots_upgrade_lease_until TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS ots_last_upgrade_error TEXT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'anchor_receipts_ots_upgrade_attempts_valid'
           AND conrelid = 'anchor_receipts'::regclass
    ) THEN
        ALTER TABLE anchor_receipts
            ADD CONSTRAINT anchor_receipts_ots_upgrade_attempts_valid
            CHECK (ots_upgrade_attempts >= 0);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_anchor_receipts_ots_upgrade_ready
    ON anchor_receipts (
        ots_last_upgrade_attempt_at ASC NULLS FIRST,
        submitted_at ASC
    )
    WHERE anchor_kind = 'ots'
      AND (metadata->>'phase' IS NULL OR metadata->>'phase' = 'pending');
