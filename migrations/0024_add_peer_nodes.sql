-- P2P federation: known peer nodes
CREATE TABLE IF NOT EXISTS peer_nodes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255),
    onion_address VARCHAR(62) NOT NULL UNIQUE,
    bjj_pubkey_x  VARCHAR(78) NOT NULL,
    bjj_pubkey_y  VARCHAR(78) NOT NULL,
    trust_status  VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (trust_status IN ('pending', 'trusted', 'blocked')),
    last_seen_at  TIMESTAMP,
    added_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_peer_nodes_trust ON peer_nodes (trust_status);
