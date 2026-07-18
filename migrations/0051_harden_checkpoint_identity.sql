-- SPDX-License-Identifier: Apache-2.0

-- 0051_harden_checkpoint_identity.sql
--
-- Security hardening for checkpoint scope, signer identity, replay handling,
-- and evidence retention (H-03, H-05, H-12, M-02, M-15, M-16).
--
-- Version-1 checkpoints ambiguously called one shard's snapshot a global
-- ledger checkpoint, stored the producer's hexadecimal root even though the
-- federation verifier accepts canonical decimal field elements, and keyed
-- peer evidence on a mutable peer UUID rather than the BJJ signing identity.
-- Version 2 is explicitly shard-scoped and stores canonical signer coordinates
-- on every received checkpoint.  Existing rows remain readable audit history,
-- but are never reinterpreted as v2 statements.

ALTER TABLE own_checkpoints
    ADD COLUMN IF NOT EXISTS format_version   SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS checkpoint_scope TEXT,
    ADD COLUMN IF NOT EXISTS shard_id         TEXT;

ALTER TABLE own_checkpoints
    DROP CONSTRAINT IF EXISTS own_checkpoints_v2_scope_check;

ALTER TABLE own_checkpoints
    ADD CONSTRAINT own_checkpoints_v2_scope_check CHECK (
        CASE
            WHEN format_version = 1 THEN TRUE
            WHEN format_version = 2 THEN
                checkpoint_scope IS NOT NULL
                AND checkpoint_scope = 'shard'
                AND shard_id IS NOT NULL
                AND length(shard_id) BETWEEN 1 AND 128
                AND shard_id ~ '^[A-Za-z0-9:._-]+$'
                AND tree_size >= 0
                AND checkpoint_timestamp >= 0
                AND ledger_root ~ '^(0|[1-9][0-9]*)$'
                AND length(ledger_root) <= 78
                AND ledger_root::numeric < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                AND ledger_root = (ledger_root::numeric)::text
            ELSE FALSE
        END
    );

-- The old uniqueness key omitted shard identity, so equal roots/sizes from two
-- independent shards collided.  Keep old rows, replace the constraint with the
-- complete v2 state identity.  NULL scope/shard values on historical v1 rows
-- remain distinct under PostgreSQL's normal UNIQUE semantics.
ALTER TABLE own_checkpoints
    DROP CONSTRAINT IF EXISTS own_checkpoints_ledger_root_tree_size_unique;

ALTER TABLE own_checkpoints
    DROP CONSTRAINT IF EXISTS own_checkpoints_scoped_snapshot_unique;

ALTER TABLE own_checkpoints
    ADD CONSTRAINT own_checkpoints_scoped_snapshot_unique
        UNIQUE (format_version, checkpoint_scope, shard_id, ledger_root, tree_size,
                checkpoint_timestamp);

ALTER TABLE peer_nodes
    ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ;

ALTER TABLE peer_nodes
    DROP CONSTRAINT IF EXISTS peer_nodes_trust_status_check;

ALTER TABLE peer_nodes
    ADD CONSTRAINT peer_nodes_trust_status_check
        CHECK (trust_status IN ('pending', 'trusted', 'blocked', 'removed'));

-- Very old databases predate application-level subgroup/canonical parsing and
-- may contain non-decimal coordinates.  Preserve those rows as evidence but do
-- not let an unsafe numeric cast abort the migration or leave the identity
-- eligible for federation.
UPDATE peer_nodes
   SET trust_status = 'removed',
       removed_at = COALESCE(removed_at, NOW())
 WHERE removed_at IS NULL
   AND (
       bjj_pubkey_x !~ '^(0|[1-9][0-9]*)$'
       OR bjj_pubkey_y !~ '^(0|[1-9][0-9]*)$'
       OR length(bjj_pubkey_x) > 78
       OR length(bjj_pubkey_y) > 78
   );

UPDATE peer_nodes
   SET trust_status = 'removed',
       removed_at = COALESCE(removed_at, NOW())
 WHERE removed_at IS NULL
   AND (
       bjj_pubkey_x::numeric >= 21888242871839275222246405745257275088548364400416034343698204186575808495617
       OR bjj_pubkey_y::numeric >= 21888242871839275222246405745257275088548364400416034343698204186575808495617
   );

UPDATE peer_nodes
   SET bjj_pubkey_x = (bjj_pubkey_x::numeric)::text,
       bjj_pubkey_y = (bjj_pubkey_y::numeric)::text
 WHERE removed_at IS NULL;

ALTER TABLE peer_nodes
    DROP CONSTRAINT IF EXISTS peer_nodes_active_bjj_coordinates_check;

ALTER TABLE peer_nodes
    ADD CONSTRAINT peer_nodes_active_bjj_coordinates_check CHECK (
        CASE
            WHEN removed_at IS NOT NULL THEN TRUE
            ELSE
                bjj_pubkey_x ~ '^(0|[1-9][0-9]*)$'
                AND bjj_pubkey_y ~ '^(0|[1-9][0-9]*)$'
                AND length(bjj_pubkey_x) <= 78
                AND length(bjj_pubkey_y) <= 78
                AND bjj_pubkey_x::numeric < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                AND bjj_pubkey_y::numeric < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                AND bjj_pubkey_x = (bjj_pubkey_x::numeric)::text
                AND bjj_pubkey_y = (bjj_pubkey_y::numeric)::text
        END
    );

-- If an older database already contains aliases for one BJJ identity, retain
-- every row and all referenced checkpoints, but retire all except the oldest
-- registration before installing the active-identity uniqueness guard.
WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY (bjj_pubkey_x::numeric), (bjj_pubkey_y::numeric)
               ORDER BY added_at, id
           ) AS identity_rank
      FROM peer_nodes
     WHERE removed_at IS NULL
)
UPDATE peer_nodes AS p
   SET trust_status = 'removed',
       removed_at = COALESCE(p.removed_at, NOW())
  FROM ranked AS r
 WHERE p.id = r.id
   AND r.identity_rank > 1;

-- Numeric expression keys make non-canonical legacy encodings such as "01"
-- collide with "1".  New application writes are canonical decimal strings.
CREATE UNIQUE INDEX IF NOT EXISTS peer_nodes_active_bjj_identity_unique
    ON peer_nodes ((bjj_pubkey_x::numeric), (bjj_pubkey_y::numeric))
    WHERE removed_at IS NULL;

ALTER TABLE peer_checkpoints
    ADD COLUMN IF NOT EXISTS wire_version       SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS checkpoint_scope   TEXT,
    ADD COLUMN IF NOT EXISTS shard_id           TEXT,
    ADD COLUMN IF NOT EXISTS signer_pubkey_x    TEXT,
    ADD COLUMN IF NOT EXISTS signer_pubkey_y    TEXT;

-- OTS upgrades are new evidence versions. The submitted receipt remains
-- immutable and each successor links to the evidence it extends.
ALTER TABLE anchor_receipts
    ADD COLUMN IF NOT EXISTS supersedes_receipt_id UUID,
    ADD COLUMN IF NOT EXISTS evidence_version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE anchor_receipts
    DROP CONSTRAINT IF EXISTS anchor_receipts_supersedes_receipt_fkey;

ALTER TABLE anchor_receipts
    ADD CONSTRAINT anchor_receipts_supersedes_receipt_fkey
        FOREIGN KEY (supersedes_receipt_id) REFERENCES anchor_receipts(id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX IF NOT EXISTS anchor_receipts_one_successor_per_version
    ON anchor_receipts (supersedes_receipt_id)
    WHERE supersedes_receipt_id IS NOT NULL;

-- Preserve the signing identity on historical evidence before peer removal is
-- made non-destructive.  The peer row remains the source for old records only;
-- all new inserts write these columns directly from the verified pinned key.
UPDATE peer_checkpoints AS c
   SET signer_pubkey_x = p.bjj_pubkey_x,
       signer_pubkey_y = p.bjj_pubkey_y
  FROM peer_nodes AS p
 WHERE c.peer_id = p.id
   AND (c.signer_pubkey_x IS NULL OR c.signer_pubkey_y IS NULL);

ALTER TABLE peer_checkpoints
    DROP CONSTRAINT IF EXISTS peer_checkpoints_v2_identity_check;

ALTER TABLE peer_checkpoints
    ADD CONSTRAINT peer_checkpoints_v2_identity_check CHECK (
        CASE
            WHEN wire_version = 1 THEN TRUE
            WHEN wire_version = 2 THEN
                checkpoint_scope IS NOT NULL
                AND checkpoint_scope = 'shard'
                AND shard_id IS NOT NULL
                AND length(shard_id) BETWEEN 1 AND 128
                AND shard_id ~ '^[A-Za-z0-9:._-]+$'
                AND signer_pubkey_x IS NOT NULL
                AND signer_pubkey_y IS NOT NULL
                AND bjj_signature_r8x IS NOT NULL
                AND bjj_signature_r8y IS NOT NULL
                AND bjj_signature_s IS NOT NULL
                AND tree_size >= 0
                AND checkpoint_timestamp >= 0
                AND signer_pubkey_x ~ '^(0|[1-9][0-9]*)$'
                AND signer_pubkey_y ~ '^(0|[1-9][0-9]*)$'
                AND ledger_root ~ '^(0|[1-9][0-9]*)$'
                AND authority_pubkey_hash ~ '^(0|[1-9][0-9]*)$'
                AND bjj_signature_r8x ~ '^(0|[1-9][0-9]*)$'
                AND bjj_signature_r8y ~ '^(0|[1-9][0-9]*)$'
                AND bjj_signature_s ~ '^(0|[1-9][0-9]*)$'
                AND length(signer_pubkey_x) <= 78
                AND length(signer_pubkey_y) <= 78
                AND length(ledger_root) <= 78
                AND length(authority_pubkey_hash) <= 78
                AND length(bjj_signature_r8x) <= 78
                AND length(bjj_signature_r8y) <= 78
                AND length(bjj_signature_s) <= 78
                AND signer_pubkey_x = (signer_pubkey_x::numeric)::text
                AND signer_pubkey_y = (signer_pubkey_y::numeric)::text
                AND ledger_root = (ledger_root::numeric)::text
                AND authority_pubkey_hash = (authority_pubkey_hash::numeric)::text
                AND bjj_signature_r8x = (bjj_signature_r8x::numeric)::text
                AND bjj_signature_r8y = (bjj_signature_r8y::numeric)::text
                AND bjj_signature_s = (bjj_signature_s::numeric)::text
                AND signer_pubkey_x::numeric < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                AND signer_pubkey_y::numeric < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                AND ledger_root::numeric < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                AND authority_pubkey_hash::numeric < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                AND bjj_signature_r8x::numeric < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                AND bjj_signature_r8y::numeric < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                AND bjj_signature_s::numeric < 2736030358979909402780800718157159386076813972158567259200215660948447373041
            ELSE FALSE
        END
    );

DROP INDEX IF EXISTS idx_peer_checkpoints_dedup;

-- Exact logical-statement deduplication is global to a BJJ identity, not local
-- to whichever peer UUID happened to deliver it.  This is also the lookup key
-- used before expensive Groth16 replay verification.
CREATE UNIQUE INDEX IF NOT EXISTS peer_checkpoints_v2_statement_unique
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
    WHERE wire_version = 2;

CREATE INDEX IF NOT EXISTS peer_checkpoints_v2_equivocation_height
    ON peer_checkpoints (
        signer_pubkey_x,
        signer_pubkey_y,
        checkpoint_scope,
        shard_id,
        tree_size
    )
    WHERE wire_version = 2;

CREATE INDEX IF NOT EXISTS peer_checkpoints_v2_equivocation_timestamp
    ON peer_checkpoints (
        signer_pubkey_x,
        signer_pubkey_y,
        checkpoint_scope,
        shard_id,
        checkpoint_timestamp
    )
    WHERE wire_version = 2;

-- Deleting a peer used to cascade-delete its signed checkpoints and every
-- equivocation flag.  Application removal is now a soft delete, and this FK
-- makes direct SQL deletion fail closed rather than erase evidence.
ALTER TABLE peer_checkpoints
    DROP CONSTRAINT IF EXISTS peer_checkpoints_peer_id_fkey;

ALTER TABLE peer_checkpoints
    ADD CONSTRAINT peer_checkpoints_peer_id_fkey
        FOREIGN KEY (peer_id) REFERENCES peer_nodes(id) ON DELETE RESTRICT;
