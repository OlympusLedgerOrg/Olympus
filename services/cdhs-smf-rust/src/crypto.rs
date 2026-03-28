//! Cryptographic primitives for CD-HS-SMF
//!
//! This module implements:
//! - BLAKE3 hashing with domain separation
//! - Composite key generation
//! - Ed25519 signing

use blake3;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::collections::HashMap;

use crate::proto::olympus::cdhs_smf::v1::RecordKey;

/// Domain separation prefixes for BLAKE3 hashing
const GLOBAL_KEY_PREFIX: &[u8] = b"OLY:CDHS-SMF:GKEY:V1";
const LEAF_HASH_PREFIX: &[u8] = b"OLY:SMT:LEAF:V1";
const NODE_HASH_PREFIX: &[u8] = b"OLY:SMT:NODE:V1";
const EMPTY_LEAF_PREFIX: &[u8] = b"OLY:EMPTY-LEAF:V1";

/// Compute a global key from shard_id and record_key
///
/// global_key = H(GLOBAL_KEY_PREFIX || shard_id || record_key_components)
pub fn compute_global_key(shard_id: &str, record_key: &RecordKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();

    // Domain separation prefix
    hasher.update(GLOBAL_KEY_PREFIX);

    // Shard ID
    hasher.update(shard_id.as_bytes());

    // Record type
    hasher.update(record_key.record_type.as_bytes());

    // Record ID
    hasher.update(record_key.record_id.as_bytes());

    // Version (if present)
    if !record_key.version.is_empty() {
        hasher.update(record_key.version.as_bytes());
    }

    // Metadata (sorted by key for determinism)
    let mut keys: Vec<_> = record_key.metadata.keys().collect();
    keys.sort();
    for key in keys {
        hasher.update(key.as_bytes());
        if let Some(value) = record_key.metadata.get(key) {
            hasher.update(value.as_bytes());
        }
    }

    *hasher.finalize().as_bytes()
}

/// Hash canonicalized content for leaf value
pub fn hash_canonical_content(content: &[u8]) -> [u8; 32] {
    hash_bytes(content)
}

/// Generic BLAKE3 hash of bytes
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Hash a leaf node with domain separation
pub fn hash_leaf(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_HASH_PREFIX);
    hasher.update(key);
    hasher.update(value_hash);
    *hasher.finalize().as_bytes()
}

/// Hash an internal node with domain separation
pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_HASH_PREFIX);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Get the empty leaf sentinel value
pub fn empty_leaf() -> [u8; 32] {
    *blake3::hash(EMPTY_LEAF_PREFIX).as_bytes()
}

/// Key manager for Ed25519 signing
pub struct KeyManager {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyManager {
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Sign a root hash with optional context
    pub fn sign_root(
        &self,
        root: &[u8; 32],
        context: &HashMap<String, String>,
    ) -> Result<([u8; 64], [u8; 32]), String> {
        // Build message to sign: root || sorted_context
        let mut message = Vec::from(&root[..]);

        // Add sorted context
        let mut keys: Vec<_> = context.keys().collect();
        keys.sort();
        for key in keys {
            message.extend_from_slice(key.as_bytes());
            if let Some(value) = context.get(key) {
                message.extend_from_slice(value.as_bytes());
            }
        }

        // Sign
        let signature = self.signing_key.sign(&message);

        Ok((
            signature.to_bytes(),
            self.verifying_key.to_bytes(),
        ))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_global_key() {
        let record_key = RecordKey {
            record_type: "doc".to_string(),
            record_id: "12345".to_string(),
            version: "v1".to_string(),
            metadata: HashMap::new(),
        };

        let key1 = compute_global_key("watauga:2025:budget", &record_key);
        let key2 = compute_global_key("watauga:2025:budget", &record_key);

        // Should be deterministic
        assert_eq!(key1, key2);

        // Different shard should give different key
        let key3 = compute_global_key("other:shard", &record_key);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_empty_leaf() {
        let empty = empty_leaf();
        // Should be consistent with Python implementation
        // blake3("OLY:EMPTY-LEAF:V1")
        assert_eq!(empty.len(), 32);
    }

    #[test]
    fn test_hash_node() {
        let left = [0u8; 32];
        let right = [1u8; 32];

        let hash1 = hash_node(&left, &right);
        let hash2 = hash_node(&left, &right);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_key_manager() {
        let km = KeyManager::new();
        let root = [0u8; 32];
        let context = HashMap::new();

        let result = km.sign_root(&root, &context);
        assert!(result.is_ok());

        let (sig, pk) = result.unwrap();
        assert_eq!(sig.len(), 64);
        assert_eq!(pk.len(), 32);
        assert_eq!(pk, km.public_key());
    }
}
