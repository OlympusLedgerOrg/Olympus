-- P2P federation: checkpoints received from peers
CREATE TABLE IF NOT EXISTS peer_checkpoints (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    peer_id               UUID NOT NULL REFERENCES peer_nodes(id) ON DELETE CASCADE,
    ledger_root           VARCHAR(78) NOT NULL,
    tree_size             BIGINT NOT NULL,
    checkpoint_timestamp  BIGINT NOT NULL,
    authority_pubkey_hash VARCHAR(78) NOT NULL,
    groth16_proof         JSONB NOT NULL,
    public_signals        JSONB NOT NULL,
    bjj_signature_r8x     VARCHAR(78),
    bjj_signature_r8y     VARCHAR(78),
    bjj_signature_s       VARCHAR(78),
    verified              BOOLEAN NOT NULL DEFAULT false,
    equivocation_detected BOOLEAN NOT NULL DEFAULT false,
    received_at           TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_peer_checkpoints_peer   ON peer_checkpoints (peer_id);
CREATE INDEX idx_peer_checkpoints_ts     ON peer_checkpoints (peer_id, checkpoint_timestamp);
CREATE INDEX idx_peer_checkpoints_equiv  ON peer_checkpoints (equivocation_detected) WHERE equivocation_detected = true;
