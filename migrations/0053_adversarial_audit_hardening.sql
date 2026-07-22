-- SPDX-License-Identifier: Apache-2.0
--
-- Adversarial-audit hardening: immutable checkpoint identity, durable signing
-- keys/append witnesses, and explicit federation co-sign policy.

ALTER TABLE own_checkpoints
    ADD COLUMN IF NOT EXISTS authority_pubkey_x TEXT,
    ADD COLUMN IF NOT EXISTS authority_pubkey_y TEXT,
    ADD COLUMN IF NOT EXISTS transition_leaf TEXT,
    ADD COLUMN IF NOT EXISTS transition_path JSONB,
    ADD COLUMN IF NOT EXISTS dedup_enforced BOOLEAN;

-- A timestamp is metadata about emission, not part of the state identity.
-- Including it allowed an unchanged shard snapshot to be inserted repeatedly.
-- Historical rows remain untouched (including any duplicates); every new row
-- defaults into the partial unique index so the migration is evidence-safe and
-- still closes the producer race.
ALTER TABLE own_checkpoints
    ALTER COLUMN dedup_enforced SET DEFAULT TRUE;

CREATE UNIQUE INDEX IF NOT EXISTS own_checkpoints_current_state_unique
    ON own_checkpoints
       (format_version, checkpoint_scope, shard_id, ledger_root, tree_size)
    WHERE dedup_enforced IS TRUE;

ALTER TABLE own_checkpoints
    DROP CONSTRAINT IF EXISTS own_checkpoints_authority_coords_pair_check;

ALTER TABLE own_checkpoints
    ADD CONSTRAINT own_checkpoints_authority_coords_pair_check CHECK (
        (authority_pubkey_x IS NULL) = (authority_pubkey_y IS NULL)
    );

ALTER TABLE peer_nodes
    ADD COLUMN IF NOT EXISTS cosign_credential_types JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE peer_nodes
    DROP CONSTRAINT IF EXISTS peer_nodes_cosign_credential_types_check;

ALTER TABLE peer_nodes
    ADD CONSTRAINT peer_nodes_cosign_credential_types_check CHECK (
        jsonb_typeof(cosign_credential_types) = 'array'
        AND cosign_credential_types <@ '["authority_sbt", "press_credential", "foia_requester", "court_observer", "verifier_only"]'::jsonb
    );

ALTER TABLE peer_checkpoints
    ADD COLUMN IF NOT EXISTS append_transition JSONB;

-- Wire v3 carries the signed append-consistency witness. Keep the strict
-- scalar validation introduced for v2, and require the new witness for v3.
ALTER TABLE peer_checkpoints
    DROP CONSTRAINT IF EXISTS peer_checkpoints_v2_identity_check;

ALTER TABLE peer_checkpoints
    DROP CONSTRAINT IF EXISTS peer_checkpoints_current_identity_check;

ALTER TABLE peer_checkpoints
    ADD CONSTRAINT peer_checkpoints_current_identity_check CHECK (
        CASE
            WHEN wire_version = 1 THEN TRUE
            WHEN wire_version IN (2, 3) THEN
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
                AND (
                    wire_version = 2
                    OR (
                        append_transition IS NOT NULL
                        AND jsonb_typeof(append_transition) = 'object'
                    )
                )
            ELSE FALSE
        END
    );
