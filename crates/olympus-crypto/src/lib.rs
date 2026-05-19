//! Shared protocol-critical crypto primitives for Olympus.
//!
//! This crate is intentionally small: it owns the byte layouts and domain
//! tags that must stay identical across the Python extension, the Go-facing
//! Rust sidecar, and verifiers.
//!
//! Optional feature `poseidon`: BN254 Poseidon for ZK-circuit commitments.

#[cfg(feature = "poseidon")]
pub mod poseidon;

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
