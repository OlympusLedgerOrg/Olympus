-- SMT lazy deep-node storage (ADR-0022): prune persisted deep internal nodes.
--
-- Before this revision the persistent SMT materialised *every* internal node
-- (depths 0..255) into `smt_nodes`. ADR-0022 makes the write path persist only
-- nodes with `depth <= LAZY_DEPTH` (72) and recompute the deeper region on read
-- from the leaf "canopy" beneath each node. This migration brings an existing
-- (pre-hybrid) database in line with that regime by deleting the now-redundant
-- deep rows; on a fresh deploy `smt_nodes` is empty, so it is a no-op.
--
-- EXCEPTION — over-cap canopies. When a canopy (the leaves sharing a tree key's
-- first LAZY_DEPTH=72 bits = first 9 bytes) holds more than CANOPY_RECOMPUTE_CAP
-- (1024) leaves, the read path does NOT recompute it; it reads the persisted
-- deep nodes directly (the recompute would be an unbounded fold). For such a
-- canopy the deep rows MUST be kept, or proofs against it would silently read
-- empty-subtree hashes and verify wrong. So we delete a `depth > 72` node only
-- when its canopy's live leaf count is at or below the cap.
--
-- A node's canopy is the first 72 bits of its path. Since `path_bits` is packed
-- MSB-first (migration 0043), the first 72 bits are exactly its first 9 bytes,
-- the same 9-byte prefix as a leaf key's first 9 bytes — so the two line up
-- byte-for-byte. (Every `depth > 72` node has >= 10 path bytes, so the 9-byte
-- prefix is always the full 72-bit canopy.) `substr(bytea, 1, 9)` takes that
-- prefix — `left()` is text-only in Postgres and does not accept `bytea`.
--
-- CORRECTNESS: purely physical. Node/leaf hashes, the global root, and every
-- proof are unchanged — a deleted under-cap deep node is recomputed identically
-- on read from the same leaves via the canonical `node_hash`/`empty_subtree_hash`
-- (the in-memory reference tree remains the parity oracle). Kept over-cap deep
-- rows are exactly what the read-path fallback expects.
--
-- These constants are mirrored from `src-tauri/src/smt/tree.rs`
-- (`LAZY_DEPTH = 72`, `CANOPY_RECOMPUTE_CAP = 1024`); they are pinned (a change
-- is a migration-class event per ADR-0022), so duplicating them here is safe.

DELETE FROM smt_nodes n
WHERE n.depth > 72
  AND (
        SELECT count(*)
        FROM smt_leaves l
        WHERE substr(l.key, 1, 9) = substr(n.path_bits, 1, 9)
      ) <= 1024;
