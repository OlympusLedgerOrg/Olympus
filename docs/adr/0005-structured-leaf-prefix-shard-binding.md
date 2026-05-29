# ADR-0005: Structured Leaf Prefix + Shard-ID Binding

| Field      | Value                                  |
|------------|----------------------------------------|
| Status     | Accepted                               |
| Date       | 2026-05-28                             |
| Extends    | ADR-0003, ADR-0004                     |
| Revises    | ADR-0003 ("shard in the key path, not the leaf domain") |

## Context

ADR-0003 deliberately kept the shard out of the leaf domain: the shard was
present only as the high 64 bits of the tree key
(`H("OLY:SHARD-PREFIX:V1" || shard_id)[..8]`). That truncated, hashed prefix
commits the shard with only ~32-bit birthday resistance and does not record the
shard identifier itself. We want the full `shard_id` bound into the leaf,
explicit and untruncated, so a leaf is shard-domain-separated independently of
the key derivation.

At the same time, the legacy leaf preimage used an ASCII tag (`OLY:LEAF:V1`)
and `|` separators between mostly-length-prefixed fields. The `|` separators
are redundant once every variable field is length-prefixed, and an ASCII tag is
less self-describing than a structured binary header.

## Decision

Replace the leaf preimage with a **structured binary prefix** followed by a
**count-framed body**:

    LeafPreimage =
        u8(0x01)            // Olympus structured-prefix marker
      | "OLY"               // namespace
      | u8(0x01)            // object type = LEAF
      | u8(0x01)            // version = V1
      | lp(shard_id)        // shard ID, length-prefixed (ADR-0005)
      | u8(0x05)            // body field count
      | lp(key)
      | value_hash          // raw, fixed 32 bytes
      | lp(parser_id)       // ADR-0003
      | lp(canonical_parser_version)
      | lp(model_hash)      // ADR-0004

    leaf = BLAKE3(LeafPreimage)

where `lp(x)` = 4-byte big-endian length prefix followed by `x`.

### Decision details

1. **Structured prefix.** The leaf domain tag is the 6-byte header
   `0x01 "OLY" 0x01 0x01` plus `lp(shard_id)`: marker, namespace, object type
   (`LEAF`), version (`V1`), then the length-prefixed shard. This replaces the
   `OLY:LEAF:V1` ASCII constant for leaves. `node_hash` and the empty-leaf
   sentinel are unchanged.
2. **shard_id is length-prefixed**, not raw-concatenated: a raw variable-length
   shard in the prefix would let bytes shift across the following field
   boundary. The SMT layer requires it non-empty.
3. **Count framing.** The `u8(0x05)` byte declares the five body fields
   (`key, value_hash, parser_id, canonical_parser_version, model_hash`),
   domain-separating this leaf shape from any future layout with a different
   field set.
4. **No `|` separators.** Field boundaries come from the per-field length
   prefixes (and the fixed-width `value_hash`), so the legacy `|` separators are
   removed. `value_hash` is the only un-prefixed field and MUST be exactly 32
   bytes; `key` is length-prefixed but is still asserted to be 32 bytes (every
   in-tree key is a 32-byte digest).
5. **Migration policy:** None. No pre-launch ledger exists, so there are no
   committed leaves to migrate. No dual-format window.
6. **Storage:** `smt_leaves` gains a `shard_id TEXT NOT NULL` column
   (migration 0037), alongside the ADR-0004 `model_hash` column (0036).
7. **Test vectors:** SSMF golden vectors regenerated via
   `cargo run -p olympus-crypto --example gen_ssmf_vectors --features smt`; both
   offline verifiers load them directly from `verifiers/test_vectors/vectors.json`.

## Consequences

- The canonical signature is
  `olympus_crypto::leaf_hash(shard_id, key, value_hash, parser_id,
  canonical_parser_version, model_hash)`, consumed by `src-tauri` and both
  verifiers. The in-memory and persistent SMTs carry `shard_id` on each leaf
  record and proof.
- This is a **breaking hash change**: every leaf hash and the global root move.
  All implementations, the `smt_leaves` schema, and the golden vectors were
  updated in lockstep.
- The shard is committed in two forms — the full `shard_id` in the leaf prefix
  (authoritative) and its 64-bit `shard_prefix(shard_id)` as the key's
  addressing prefix (a projection). The two are bound together: both the SMT
  write path (`update` / `update_batch`) and `verify_existence_proof` — plus both
  offline verifiers — reject any leaf/proof where
  `shard_prefix(shard_id) != key[..8]` (`olympus_crypto::smt::shard_id_matches_key`).
  A proof therefore cannot claim a shard that disagrees with the partition its
  key addresses, so the in-leaf `shard_id` is the authoritative partition tag.

## Rejected alternatives

- **Raw shard_id in the prefix string** (`OLY:LEAF:V1|<shard>|...`): rejected —
  reintroduces the cross-`|` ambiguity that length prefixes exist to prevent.
- **Keeping the ASCII `OLY:LEAF:V1` tag and only appending `lp(shard_id)`:**
  superseded by the structured header, which is self-describing and carries an
  explicit object-type/version that the ASCII tag conflated into one string.
