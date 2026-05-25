-- Audit L-F2: persist gossip pull errors per peer so operators can answer
-- "has peer X been reachable lately?" without tailing logs.
--
-- touch_last_seen() updates last_seen_at on every successful pull;
-- record_pull_error() (federation::peer) populates these two columns on
-- failure. The pair forms a poor-man's-uptime view: a peer whose
-- last_pull_error_at > last_seen_at has been failing.

ALTER TABLE peer_nodes
    ADD COLUMN IF NOT EXISTS last_pull_error_at  TIMESTAMP NULL,
    ADD COLUMN IF NOT EXISTS last_pull_error_msg TEXT      NULL;
