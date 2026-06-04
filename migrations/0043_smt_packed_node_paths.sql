-- SMT storage optimization: packed node bit-paths.
--
-- migration 0035 stored `smt_nodes.path` as one byte per path bit, so a node at
-- depth d carried a d-byte key (up to ~255 bytes). The node table dominates the
-- ledger's on-disk size, and that one-byte-per-bit key is ~95% of it.
--
-- This replaces that layout with an explicit depth column plus packed bits:
--
--   * depth     SMALLINT  — the node depth (== bit-path length), 0..=255.
--   * path_bits BYTEA     — ceil(depth/8) bytes, MSB-first, the final partial
--                           byte left-aligned (low bits zero).
--   * hash      BYTEA     — the 32-byte BLAKE3 node hash (unchanged).
--
-- The composite primary key (depth, path_bits) uniquely addresses each node and
-- its leading `depth` column makes the write-behind cache's `WHERE depth <= N`
-- load_hot query sargable on the PK index — so the old `((length(path)))`
-- expression index is no longer needed.
--
-- CORRECTNESS: this is a PURELY PHYSICAL change. `path` is an addressing key the
-- node hash never consumes (node hashes are `OLY:NODE:V1|` over child hashes
-- only), so node/leaf hashes, the global root, every proof, and the offline
-- verifiers are all unchanged. The persistent tree's parity tests (root ==
-- in-memory reference root) remain the regression guard.
--
-- DATA: there is no production data at this revision. Both SMT tables are
-- recreated/cleared empty so a database can never hold old-format nodes against
-- new-format readers (a leaves-without-nodes state would otherwise carry a stale
-- root until a full rebuild). Any existing dev database must re-ingest after
-- this migration.

DROP TABLE IF EXISTS smt_nodes;

CREATE TABLE smt_nodes (
    depth     SMALLINT NOT NULL,
    path_bits BYTEA    NOT NULL,
    hash      BYTEA    NOT NULL,
    PRIMARY KEY (depth, path_bits)
);

-- Clear leaves so the freshly-emptied node set stays consistent with them
-- (leaf hashes are unchanged, so the schema is left as later migrations defined
-- it — only the rows are removed).
TRUNCATE TABLE smt_leaves;
