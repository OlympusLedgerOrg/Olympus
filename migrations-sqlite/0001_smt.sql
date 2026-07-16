-- SPDX-License-Identifier: Apache-2.0

-- SQLite storage for the database-agnostic persistent SMT backend (ADR-0039).
--
-- This schema intentionally contains only the SMT's physical node and leaf
-- tables. The rest of the Olympus application remains on PostgreSQL; a SQLite
-- SMT can be selected independently by an embedding environment.

CREATE TABLE smt_nodes (
    depth     INTEGER NOT NULL,
    path_bits BLOB    NOT NULL,
    hash      BLOB    NOT NULL,
    PRIMARY KEY (depth, path_bits),
    CHECK (typeof(depth) = 'integer'),
    CHECK (depth BETWEEN 0 AND 255),
    CHECK (typeof(path_bits) = 'blob'),
    CHECK (length(path_bits) = (depth + 7) / 8),
    CHECK (typeof(hash) = 'blob'),
    CHECK (length(hash) = 32),
    -- Canonical MSB-first packing: unused low bits in the final byte are zero.
    CHECK (
        CASE depth % 8
            WHEN 0 THEN 1
            WHEN 1 THEN hex(substr(path_bits, -1, 1)) GLOB '[08]0'
            WHEN 2 THEN hex(substr(path_bits, -1, 1)) GLOB '[048C]0'
            WHEN 3 THEN hex(substr(path_bits, -1, 1)) GLOB '[02468ACE]0'
            WHEN 4 THEN hex(substr(path_bits, -1, 1)) GLOB '[0-9A-F]0'
            WHEN 5 THEN hex(substr(path_bits, -1, 1)) GLOB '[0-9A-F][08]'
            WHEN 6 THEN hex(substr(path_bits, -1, 1)) GLOB '[0-9A-F][048C]'
            WHEN 7 THEN hex(substr(path_bits, -1, 1)) GLOB '[0-9A-F][02468ACE]'
        END
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE smt_leaves (
    key                      BLOB PRIMARY KEY,
    value_hash               BLOB NOT NULL,
    shard_id                 TEXT NOT NULL,
    parser_id                TEXT NOT NULL,
    canonical_parser_version TEXT NOT NULL,
    model_hash               TEXT NOT NULL,
    CHECK (typeof(key) = 'blob'),
    CHECK (length(key) = 32),
    CHECK (typeof(value_hash) = 'blob'),
    CHECK (length(value_hash) = 32),
    CHECK (length(shard_id) > 0),
    CHECK (instr(CAST(shard_id AS BLOB), x'00') = 0),
    CHECK (length(parser_id) > 0),
    CHECK (instr(CAST(parser_id AS BLOB), x'00') = 0),
    CHECK (length(canonical_parser_version) > 0),
    CHECK (instr(CAST(canonical_parser_version AS BLOB), x'00') = 0),
    CHECK (length(model_hash) > 0),
    CHECK (instr(CAST(model_hash AS BLOB), x'00') = 0)
) STRICT, WITHOUT ROWID;
-- SPDX-License-Identifier: Apache-2.0
