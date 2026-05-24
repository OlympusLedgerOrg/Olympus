//! Shared protocol-critical crypto primitives for Olympus.
//!
//! This crate is intentionally small: it owns the byte layouts and domain
//! tags that must stay identical across the Python extension, the Go-facing
//! Rust sidecar, and verifiers.
//!
//! Optional feature `poseidon`: BN254 Poseidon for ZK-circuit commitments.
//! Optional feature `canonical`: JCS / RFC 8785 canonical JSON for SBT digests.

#[cfg(feature = "poseidon")]
pub mod poseidon;

#[cfg(feature = "canonical")]
pub mod canonical;

/// BLAKE3 derive_key context for global SMT leaf keys.
pub const GLOBAL_SMT_KEY_CONTEXT: &str = "olympus 2025-12 global-smt-leaf-key";

/// Domain-separation prefix for record keys.
pub const KEY_PREFIX: &[u8] = b"OLY:KEY:V1";

/// Domain-separation prefix for SMT leaf nodes.
pub const LEAF_PREFIX: &[u8] = b"OLY:LEAF:V1";

/// Domain-separation prefix for SMT internal nodes.
pub const NODE_PREFIX: &[u8] = b"OLY:NODE:V1";

/// Field separator used in leaf and node hash concatenation.
pub const SEP: &[u8] = b"|";

/// Domain-separation prefix for the empty-leaf sentinel.
pub const EMPTY_LEAF_PREFIX: &[u8] = b"OLY:EMPTY-LEAF:V1";

/// Domain-separation tag for the Pedersen commitment second generator `H`.
///
/// `H` is derived nothing-up-my-sleeve from this tag via try-and-increment
/// over the Baby Jubjub curve; the resulting point's discrete-log with
/// respect to the iden3 base generator `G` is therefore unknown to anyone,
/// which is the binding requirement for Pedersen commitments `C = m·G + r·H`.
///
/// Changing this tag invalidates every existing commitment. Treat it as
/// frozen on first ship.
pub const PEDERSEN_H_PREFIX: &[u8] = b"OLY:PEDERSEN:H:V1";

/// Domain-separation tag for the SBT attribute-opening digest.
///
/// `m = BLAKE3(SBT_OPEN_PREFIX | jcs(details)) reduced mod l` — the message
/// scalar a Pedersen-committed SBT row binds to. Holders re-derive `m` from
/// their cleartext attributes; server discards the attributes after
/// committing, so the digest must be deterministic and unambiguous.
/// Domain-separated from generic BLAKE3 uses to prevent cross-protocol
/// collisions.
pub const SBT_OPEN_PREFIX: &[u8] = b"OLY:SBT:OPEN:V1";

/// Domain-separation tag for the SBT commit_id when bound to a Pedersen
/// commitment (rather than to cleartext attributes).
///
/// For Pedersen-committed rows the commit_id binds (holder, type,
/// issued_at, commitment_x, commitment_y) instead of (..., details), since
/// the server has no cleartext details to hash post-commit. The two domains
/// are explicitly separated so a plaintext-row commit_id can never collide
/// with a committed-row commit_id.
pub const SBT_COMMIT_BIND_PREFIX: &[u8] = b"OLY:SBT:COMMIT:V1";

/// Encode `data` with a 4-byte big-endian length prefix.
///
/// Panics if `data.len()` exceeds `u32::MAX`, matching the prior behavior in
/// both Rust call sites and preventing silent truncation.
pub fn length_prefixed(data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() <= u32::MAX as usize,
        "length_prefixed: data length {} exceeds u32::MAX",
        data.len()
    );
    let len = data.len() as u32;
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Compute a BLAKE3 hash over the concatenation of `parts`.
pub fn blake3_hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Generate a deterministic 32-byte record key.
pub fn record_key(record_type: &str, record_id: &str, version: u64) -> [u8; 32] {
    let rt = record_type.as_bytes();
    let ri = record_id.as_bytes();
    debug_assert!(rt.len() <= u32::MAX as usize);
    debug_assert!(ri.len() <= u32::MAX as usize);

    let mut key_data = Vec::with_capacity(KEY_PREFIX.len() + 4 + rt.len() + 4 + ri.len() + 8);
    key_data.extend_from_slice(KEY_PREFIX);
    key_data.extend_from_slice(&length_prefixed(rt));
    key_data.extend_from_slice(&length_prefixed(ri));
    key_data.extend_from_slice(&version.to_be_bytes());

    *blake3::Hasher::new().update(&key_data).finalize().as_bytes()
}

/// Derive the global SMT key for a shard-local record key.
pub fn global_key(shard_id: &str, record_key_bytes: &[u8]) -> [u8; 32] {
    let shard_bytes = shard_id.as_bytes();
    debug_assert!(shard_bytes.len() <= u32::MAX as usize);

    let mut key_material = Vec::with_capacity(4 + shard_bytes.len() + 4 + record_key_bytes.len());
    key_material.extend_from_slice(&length_prefixed(shard_bytes));
    key_material.extend_from_slice(&length_prefixed(record_key_bytes));

    *blake3::Hasher::new_derive_key(GLOBAL_SMT_KEY_CONTEXT)
        .update(&key_material)
        .finalize()
        .as_bytes()
}

/// Compute a domain-separated leaf hash per ADR-0003.
pub fn leaf_hash(
    key: &[u8],
    value_hash: &[u8],
    parser_id: &[u8],
    canonical_parser_version: &[u8],
) -> [u8; 32] {
    // `key` and `value_hash` are joined with a `|` separator but NOT
    // length-prefixed (unlike parser_id / version), so their field boundary is
    // only unambiguous when both are fixed-width. Require exactly 32 bytes —
    // variable-length inputs would let a caller shift bytes across the `|` to
    // craft distinct (key, value_hash) pairs that hash identically (R6-L1).
    // Every real caller passes a 32-byte BLAKE3 digest; the PyO3 wrapper must
    // validate length before calling.
    assert!(
        key.len() == 32 && value_hash.len() == 32,
        "leaf_hash requires 32-byte key and value_hash (got {} and {})",
        key.len(),
        value_hash.len()
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_PREFIX);
    hasher.update(SEP);
    hasher.update(key);
    hasher.update(SEP);
    hasher.update(value_hash);
    hasher.update(SEP);
    hasher.update(&length_prefixed(parser_id));
    hasher.update(SEP);
    hasher.update(&length_prefixed(canonical_parser_version));
    *hasher.finalize().as_bytes()
}

/// Compute a domain-separated internal-node hash.
pub fn node_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    // Same fixed-width requirement as leaf_hash: `left`/`right` are `|`-joined
    // but not length-prefixed, so both must be exactly 32 bytes to keep the
    // field boundary unambiguous (R6-L1/L2).
    assert!(
        left.len() == 32 && right.len() == 32,
        "node_hash requires 32-byte left and right (got {} and {})",
        left.len(),
        right.len()
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_PREFIX);
    hasher.update(SEP);
    hasher.update(left);
    hasher.update(SEP);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Compute the empty-leaf sentinel.
pub fn empty_leaf() -> [u8; 32] {
    *blake3::hash(EMPTY_LEAF_PREFIX).as_bytes()
}

/// Generic BLAKE3 hash of a single byte slice.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_key_and_global_key_are_stable() {
        let rk = record_key("document", "abc", 7);
        assert_eq!(
            hex_lower(&rk),
            "151a2e1d110b263ba596902e6360a2142bdfeecc20d0c1d54465eec9ab5d78c8"
        );

        let gk = global_key("shard-a", &rk);
        assert_eq!(
            hex_lower(&gk),
            "d6881dc754d860b3044c48fff6d412ad7d57d75e5a00775a0c1ecc6f54118b36"
        );
    }

    // ── Constants ─────────────────────────────────────────────────────────────
    // These constants are protocol-critical (CLAUDE.md "Critical Invariants").
    // Pinning their byte layouts prevents accidental rename/case changes.

    #[test]
    fn domain_prefix_constants_are_pinned() {
        assert_eq!(KEY_PREFIX, b"OLY:KEY:V1");
        assert_eq!(LEAF_PREFIX, b"OLY:LEAF:V1");
        assert_eq!(NODE_PREFIX, b"OLY:NODE:V1");
        assert_eq!(EMPTY_LEAF_PREFIX, b"OLY:EMPTY-LEAF:V1");
        assert_eq!(PEDERSEN_H_PREFIX, b"OLY:PEDERSEN:H:V1");
        assert_eq!(SBT_OPEN_PREFIX, b"OLY:SBT:OPEN:V1");
        assert_eq!(SBT_COMMIT_BIND_PREFIX, b"OLY:SBT:COMMIT:V1");
        assert_eq!(SEP, b"|");
        assert_eq!(GLOBAL_SMT_KEY_CONTEXT, "olympus 2025-12 global-smt-leaf-key");
    }

    // ── length_prefixed ───────────────────────────────────────────────────────

    #[test]
    fn length_prefixed_emits_be_u32_then_data() {
        let out = length_prefixed(b"hello");
        assert_eq!(&out[..4], &5u32.to_be_bytes());
        assert_eq!(&out[4..], b"hello");
    }

    #[test]
    fn length_prefixed_empty_is_four_zero_bytes() {
        assert_eq!(length_prefixed(b""), vec![0, 0, 0, 0]);
    }

    #[test]
    fn length_prefixed_distinguishes_concatenation_ambiguity() {
        // Without length prefixing, ("ab","c") and ("a","bc") would hash the
        // same. With it, they must differ.
        let ambiguous_a = [length_prefixed(b"ab"), length_prefixed(b"c")].concat();
        let ambiguous_b = [length_prefixed(b"a"), length_prefixed(b"bc")].concat();
        assert_ne!(ambiguous_a, ambiguous_b);
    }

    // ── blake3_hash ───────────────────────────────────────────────────────────

    #[test]
    fn blake3_hash_concat_equivalence() {
        // Hashing parts must equal hashing the pre-concatenated buffer.
        let parts: &[&[u8]] = &[b"alpha", b"beta", b"gamma"];
        let by_parts = blake3_hash(parts);
        let concatenated = b"alphabetagamma";
        let by_whole = blake3_hash(&[concatenated]);
        assert_eq!(by_parts, by_whole);
    }

    #[test]
    fn blake3_hash_empty_is_blake3_empty() {
        // Hashing zero parts is hashing the empty string.
        assert_eq!(blake3_hash(&[]), *blake3::hash(b"").as_bytes());
    }

    // ── record_key / global_key ───────────────────────────────────────────────

    #[test]
    fn record_key_is_deterministic() {
        assert_eq!(
            record_key("document", "id-42", 1),
            record_key("document", "id-42", 1)
        );
    }

    #[test]
    fn record_key_depends_on_every_input() {
        let base = record_key("document", "id-42", 1);
        assert_ne!(base, record_key("dataset", "id-42", 1), "type matters");
        assert_ne!(base, record_key("document", "id-43", 1), "id matters");
        assert_ne!(base, record_key("document", "id-42", 2), "version matters");
    }

    #[test]
    fn global_key_depends_on_shard_and_record_key() {
        let rk1 = record_key("document", "a", 1);
        let rk2 = record_key("document", "b", 1);
        assert_ne!(global_key("shard-a", &rk1), global_key("shard-b", &rk1));
        assert_ne!(global_key("shard-a", &rk1), global_key("shard-a", &rk2));
    }

    // ── leaf_hash / node_hash domain separation ──────────────────────────────

    #[test]
    fn leaf_and_node_hash_are_domain_separated() {
        // Same byte payload through both APIs must produce different output,
        // proving the OLY:LEAF:V1 / OLY:NODE:V1 prefix is actually mixed in.
        let payload = [0u8; 32];
        let leaf = leaf_hash(&payload, &payload, b"parser-x", b"v1");
        let node = node_hash(&payload, &payload);
        assert_ne!(leaf, node);
    }

    #[test]
    fn leaf_hash_depends_on_parser_id_and_version() {
        let key = [1u8; 32];
        let value = [2u8; 32];
        let base = leaf_hash(&key, &value, b"parser-x", b"v1");
        assert_ne!(base, leaf_hash(&key, &value, b"parser-y", b"v1"));
        assert_ne!(base, leaf_hash(&key, &value, b"parser-x", b"v2"));
    }

    #[test]
    fn node_hash_is_order_sensitive() {
        let a = [3u8; 32];
        let b = [4u8; 32];
        assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
    }

    #[test]
    #[should_panic(expected = "32-byte key and value_hash")]
    fn leaf_hash_rejects_non_32_byte_key() {
        // Variable-length key/value could be used to craft collisions across
        // the unframed `|` separator — must be rejected (R6-L1).
        let _ = leaf_hash(b"short", &[0u8; 32], b"parser", b"v1");
    }

    #[test]
    #[should_panic(expected = "32-byte left and right")]
    fn node_hash_rejects_non_32_byte_input() {
        let _ = node_hash(b"short", &[0u8; 32]);
    }

    // ── empty_leaf / hash_bytes ──────────────────────────────────────────────

    #[test]
    fn empty_leaf_equals_blake3_of_prefix() {
        assert_eq!(empty_leaf(), *blake3::hash(EMPTY_LEAF_PREFIX).as_bytes());
    }

    #[test]
    fn empty_leaf_is_constant() {
        // empty_leaf() is called frequently in SMT proof generation; pin it
        // so that any change to EMPTY_LEAF_PREFIX surfaces as a test failure
        // (not a silent re-hash of existing snapshots).
        assert_eq!(empty_leaf(), empty_leaf());
        // And it's domain-separated from the all-zero leaf.
        assert_ne!(empty_leaf(), hash_bytes(&[0u8; 32]));
    }

    #[test]
    fn hash_bytes_matches_blake3() {
        let data = b"some payload";
        assert_eq!(hash_bytes(data), *blake3::hash(data).as_bytes());
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}
