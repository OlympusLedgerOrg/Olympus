# Olympus Sparse Merkle Tree (SMT) Specification

**Version:** 1.0  
**Status:** Normative  
**Module:** `protocol/ssmf.py`

---

## 1. Overview

The Olympus Sparse Merkle Tree (SMT) is a **fixed-height 256** binary tree
used for append-only key-value commitments within a single shard.  Every
32-byte key maps to exactly one leaf position, and the tree supports
efficient proofs of both **existence** and **non-existence**.

---

## 2. Parameters

| Parameter      | Value                 | Notes                           |
| -------------- | --------------------- | ------------------------------- |
| Height         | 256 levels            | Fixed; never configurable       |
| Key size       | 32 bytes (256 bits)   | Derived via `record_key()`      |
| Value hash     | 32 bytes              | BLAKE3 of the record content    |
| Hash function  | BLAKE3                | Via `protocol.hashes`           |
| Empty sentinel | `0x00 * 32`           | 32 zero bytes                   |

---

## 3. Hashing Rules

### 3.1 Leaf Hash (domain-separated)

```
leaf_hash(key, value_hash) = BLAKE3(LEAF_PREFIX || key || value_hash)
```

- `LEAF_PREFIX` is defined in `protocol/hashes.py`.
- The leaf hash is **not** the value hash itself; it includes the key to
  prevent second-preimage attacks on the tree.

### 3.2 Internal Node Hash

```
node_hash(left, right) = BLAKE3(NODE_PREFIX || left || right)
```

- `NODE_PREFIX` is defined in `protocol/hashes.py`.
- Domain separation between leaf and node hashes prevents type confusion.

### 3.3 Empty Hash Chain

The empty hash for level `i` is defined recursively:

```
EMPTY[0]   = 0x00 * 32                        (empty leaf)
EMPTY[i+1] = node_hash(EMPTY[i], EMPTY[i])    (empty subtree at height i+1)
```

This chain is precomputed once at module import time and never changes.

---

## 4. Path Encoding

A 32-byte key is converted to a **256-bit path** by extracting bits
**MSB first** from each byte:

```python
for byte in key:
    for i in range(8):
        bit = (byte >> (7 - i)) & 1
        path.append(bit)
```

The resulting path is a tuple of 256 integers, each `0` or `1`.

- Bit `0` = go left
- Bit `1` = go right
- Bit at index `i` determines the child at tree level `i`

### 4.1 Packed Path Encoding (Storage)

For database persistence, paths are packed into bytes (MSB first):

```
256-bit path → 32 bytes (8× smaller than one-byte-per-bit)
```

The tree level is stored separately, so the path length is always
unambiguous.

---

## 5. Tree Structure

```
Level 0  (root)     ── bit[0] selects left (0) or right (1)
Level 1             ── bit[1]
  ...
Level 254           ── bit[254]
Level 255 (leaves)  ── bit[255]
```

Internal nodes are stored only when they differ from the corresponding
`EMPTY[height]` value.  This makes the tree **sparse**: an empty tree
uses zero storage.

---

## 6. Update Algorithm

When inserting or updating a key-value pair `(key, value_hash)`:

1. Store `leaves[key] = value_hash`.
2. Compute `current_hash = leaf_hash(key, value_hash)`.
3. For `level` from `0` to `255` (leaf → root):
   a. `bit_pos = 255 - level`
   b. Look up the sibling node at `sibling_path(path[:bit_pos+1])`.
      If absent, use `EMPTY[level]`.
   c. If `path[bit_pos] == 0`: `parent = node_hash(current_hash, sibling)`.
      Else: `parent = node_hash(sibling, current_hash)`.
   d. Store `nodes[parent_path] = parent`.
   e. `current_hash = parent`.
4. The root hash is `nodes[()]`.

---

## 7. Proof Format

### 7.1 Existence Proof

```json
{
  "exists": true,
  "key":        "<64 hex chars>",
  "value_hash": "<64 hex chars>",
  "siblings":   ["<64 hex chars>", ...],   // exactly 256 entries
  "root_hash":  "<64 hex chars>"
}
```

Siblings are ordered from **leaf level** (index 0) to **root level**
(index 255).

### 7.2 Non-Existence Proof

```json
{
  "exists": false,
  "key":       "<64 hex chars>",
  "siblings":  ["<64 hex chars>", ...],   // exactly 256 entries
  "root_hash": "<64 hex chars>"
}
```

Verification starts from `EMPTY[0]` (the empty leaf sentinel) instead
of a computed leaf hash.

---

## 8. Verification Algorithm

Given an existence proof `(key, value_hash, siblings, root_hash)`:

1. `path = key_to_path_bits(key)`
2. `current = leaf_hash(key, value_hash)`
3. For `level` in `0..255`:
   a. `sibling = siblings[level]`
   b. `bit_pos = 255 - level`
   c. If `path[bit_pos] == 0`: `current = node_hash(current, sibling)`.
      Else: `current = node_hash(sibling, current)`.
4. Return `current == root_hash`.

For non-existence proofs, step 2 uses `current = EMPTY[0]`.

---

## 9. Tie-Break Rules

When multiple leaves share the same timestamp during replay:

- Secondary sort by **key bytes** (ascending) ensures deterministic root.
- This is enforced by `ORDER BY ts ASC, key ASC` in the storage layer.

---

## 10. Diff Semantics

`diff_sparse_merkle_trees(before, after)` compares two tree states at the
**leaf level** only:

| Category  | Condition                                        |
| --------- | ------------------------------------------------ |
| `added`   | Key in `after.leaves` but not `before.leaves`    |
| `changed` | Key in both but `value_hash` differs             |
| `removed` | Key in `before.leaves` but not `after.leaves`    |

Results are sorted by key for determinism.  Optional `key_range_start` and
`key_range_end` parameters allow bounded-batch processing.

---

## 11. Cross-Language Implementation Notes

1. **Hash function**: Use BLAKE3 only.  SHA-256 fallback is **not** permitted.
2. **Byte ordering**: All keys and hashes are big-endian byte arrays.
3. **Path extraction**: MSB first.  Bit 0 of byte 0 is the root-level
   direction.
4. **Domain separation**: Leaf and node prefixes **must** match the values
   in `protocol/hashes.py`.  Different prefixes produce different roots.
5. **Empty hash chain**: Must be precomputed identically.  Any deviation
   invalidates all proofs.
6. **Proof length**: Always exactly 256 siblings.  No variable-depth proofs.
