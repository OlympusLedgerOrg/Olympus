-- SPDX-License-Identifier: Apache-2.0
--
-- 0055_ots_verification_stage_index.sql
--
-- Supports stage 2 of the OTS evidence pipeline (`verify_upgraded_receipts`),
-- which claims receipts whose Bitcoin attestation is already embedded but has
-- not yet been checked against an operator-pinned mainnet header.
--
-- Complements, and does not overlap, migration 0052's
-- `idx_anchor_receipts_ots_upgrade_ready`: that index serves stage 1, which
-- claims *pending* receipts. This one serves the upgraded-but-unverified set.
-- The ORDER BY and lease predicates mirror `store::claim_upgraded_unverified`.

CREATE INDEX IF NOT EXISTS idx_anchor_receipts_ots_verification_ready
    ON anchor_receipts (
        ots_last_upgrade_attempt_at ASC NULLS FIRST,
        submitted_at ASC,
        id ASC
    )
    WHERE anchor_kind = 'ots'
      AND metadata->>'phase' = 'upgraded'
      AND metadata->>'bitcoin_attestation_verified' IS DISTINCT FROM 'true';
