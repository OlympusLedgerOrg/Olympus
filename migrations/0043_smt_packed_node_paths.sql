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

-- Fail closed: this migration discards the old one-byte-per-bit node set, and
-- there is no in-migration rebuild of nodes from leaves. Rather than silently
-- delete ledger history, refuse to run on a database that already holds SMT
-- data — an operator with real data must wipe and re-ingest deliberately. On a
-- fresh deploy both tables are empty at this revision, so this is a no-op.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM smt_nodes LIMIT 1)
       OR EXISTS (SELECT 1 FROM smt_leaves LIMIT 1) THEN
        RAISE EXCEPTION
            '0043_smt_packed_node_paths refuses to run on a non-empty SMT '
            '(smt_nodes/smt_leaves hold rows); the node encoding changed and '
            'there is no in-place rebuild — wipe and re-ingest deliberately.';
    END IF;
END $$;

DROP TABLE IF EXISTS smt_nodes;

CREATE TABLE smt_nodes (
    depth     SMALLINT NOT NULL,
    path_bits BYTEA    NOT NULL,
    hash      BYTEA    NOT NULL,
    PRIMARY KEY (depth, path_bits),
    -- Canonical-encoding guards (defense-in-depth at the persistence boundary):
    -- `pack_bits` is the only writer and always produces canonical bytes, but
    -- these CHECKs make the DB itself reject any non-canonical encoding, so two
    -- rows can never decode to the same logical node path (which would make the
    -- node hash that `get_nodes` / `load_hot` keep depend on row order).
    --   * internal nodes live at depths 0 (root) .. 255 (parent of the leaves);
    --   * path_bits is exactly ceil(depth/8) bytes;
    --   * the unused low bits of the final partial byte are zero;
    --   * hash is a 32-byte BLAKE3 digest.
    CHECK (depth BETWEEN 0 AND 255),
    CHECK (octet_length(path_bits) = (depth + 7) / 8),
    CHECK (octet_length(hash) = 32),
    CHECK (
        CASE
            WHEN depth % 8 = 0 THEN TRUE
            ELSE (
                get_byte(path_bits, octet_length(path_bits) - 1)
                & ((1 << (8 - (depth % 8))) - 1)
            ) = 0
        END
    )
);

-- `smt_leaves` is left as-is: the guard above already proved it empty on any
-- database this migration is allowed to run on, so there is nothing to clear
-- and the table's schema (from later migrations) is untouched.
