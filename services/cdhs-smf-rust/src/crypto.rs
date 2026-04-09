//! Cryptographic primitives for CD-HS-ST
//!
//! This module implements:
//! - BLAKE3 hashing with domain separation
//! - Composite key generation
//! - Ed25519 signing

use blake3;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::collections::HashMap;
use zeroize::Zeroizing;

use crate::proto::olympus::cdhs_smf::v1::RecordKey;

/// Domain separation prefixes for BLAKE3 hashing.
///
/// These constants MUST stay in sync with `src/crypto.rs` (PyO3 extension) and
/// `protocol/hashes.py` (Python reference).  All three implementations must
/// produce byte-identical hashes for the same inputs.
///
/// BLAKE3 derive_key context for global SMT leaf keys — matches the PyO3
/// extension and `protocol/hashes.py::_GLOBAL_SMT_KEY_CONTEXT`.
const GLOBAL_SMT_KEY_CONTEXT: &str = "olympus 2025-12 global-smt-leaf-key";

const LEAF_HASH_PREFIX: &[u8] = b"OLY:LEAF:V1";
const NODE_HASH_PREFIX: &[u8] = b"OLY:NODE:V1";
const EMPTY_LEAF_PREFIX: &[u8] = b"OLY:EMPTY-LEAF:V1";

/// Field separator between components in leaf/node hashes — matches `SEP` in
/// `src/crypto.rs` and `HASH_SEPARATOR` in `protocol/hashes.py`.
const SEP: &[u8] = b"|";

/// Encode a byte slice with a 4-byte big-endian length prefix.
///
/// This prevents canonicalization collisions where concatenated variable-length
/// fields could be misinterpreted — e.g. `shard_id="ab"` + `record_key="cd"`
/// vs. `shard_id="a"` + `record_key="bcd"` would otherwise hash identically.
///
/// # Panics
///
/// Panics if `data.len()` exceeds `u32::MAX` (4 GiB).  In practice this is
/// unreachable for any reasonable input; it exists to prevent silent truncation.
fn length_prefixed(data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() <= u32::MAX as usize,
        "length_prefixed: data length {} exceeds u32::MAX",
        data.len()
    );
    let len = data.len() as u32;
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Compute a global key from shard_id and record_key.
///
/// Uses BLAKE3 `derive_key` mode with [`GLOBAL_SMT_KEY_CONTEXT`] — matching
/// `src/crypto.rs::global_key()` (PyO3) and `protocol/hashes.py::global_key()`.
///
/// The record_key fields are first hashed into a 32-byte `record_key_bytes`
/// using the same `KEY_PREFIX` + length-prefixed layout as the PyO3 extension,
/// then the global key is derived from `(shard_id, record_key_bytes)`.
///
/// Returns an error if `version` is non-empty and not a valid base-10 u64,
/// or if `metadata` is non-empty (metadata is not part of the key derivation
/// protocol and would be silently ignored).
pub fn compute_global_key(shard_id: &str, record_key: &RecordKey) -> Result<[u8; 32], String> {
    // Reject non-empty metadata: it is accepted by protobuf but not included
    // in key derivation.  Silently ignoring it would let clients overwrite
    // each other's leaves when only metadata differs.
    if !record_key.metadata.is_empty() {
        return Err("metadata is not supported in key derivation; pass an empty map".to_string());
    }

    // Step 1: Compute record_key_bytes (matches src/crypto.rs::record_key and
    // protocol/hashes.py::record_key).
    let record_key_bytes = compute_record_key_bytes(record_key)?;

    // Step 2: Derive global key using BLAKE3 derive_key mode with
    // length-prefixed shard_id and record_key_bytes.
    let shard_bytes = shard_id.as_bytes();
    let mut key_material = Vec::with_capacity(
        4 + shard_bytes.len() + 4 + record_key_bytes.len(),
    );
    key_material.extend_from_slice(&length_prefixed(shard_bytes));
    key_material.extend_from_slice(&length_prefixed(&record_key_bytes));

    Ok(*blake3::Hasher::new_derive_key(GLOBAL_SMT_KEY_CONTEXT)
        .update(&key_material)
        .finalize()
        .as_bytes())
}

/// Domain-separation prefix for record keys — must match `KEY_PREFIX` in
/// `src/crypto.rs` and `protocol/hashes.py`.
const KEY_PREFIX: &[u8] = b"OLY:KEY:V1";

/// Compute record key bytes matching `src/crypto.rs::record_key()` and
/// `protocol/hashes.py::record_key()`.
///
/// Layout: `BLAKE3(KEY_PREFIX || len(record_type) || record_type || len(record_id) || record_id || version_u64_be)`
///
/// The `version` field in the protobuf `RecordKey` is a string; we parse it
/// as `u64` (empty string → 0) to match the Python/PyO3 implementations
/// which accept an integer version.  Returns an error if `version` is
/// non-empty and not a valid base-10 u64 to prevent silent key collisions
/// (e.g. "1" vs "v1" both mapping to 0).
fn compute_record_key_bytes(rk: &RecordKey) -> Result<[u8; 32], String> {
    let rt = rk.record_type.as_bytes();
    let ri = rk.record_id.as_bytes();

    let version: u64 = if rk.version.is_empty() {
        0
    } else {
        rk.version.parse::<u64>().map_err(|e| {
            format!(
                "invalid version {:?}: must be empty or a base-10 u64 ({})",
                rk.version, e
            )
        })?
    };

    let mut key_data = Vec::with_capacity(
        KEY_PREFIX.len() + 4 + rt.len() + 4 + ri.len() + 8,
    );
    key_data.extend_from_slice(KEY_PREFIX);
    key_data.extend_from_slice(&length_prefixed(rt));
    key_data.extend_from_slice(&length_prefixed(ri));
    key_data.extend_from_slice(&version.to_be_bytes());

    Ok(*blake3::Hasher::new().update(&key_data).finalize().as_bytes())
}

/// Hash canonicalized content for leaf value
pub fn hash_canonical_content(content: &[u8]) -> [u8; 32] {
    hash_bytes(content)
}

/// Generic BLAKE3 hash of bytes
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Hash a leaf node with domain separation.
///
/// `BLAKE3(LEAF_HASH_PREFIX || "|" || key || "|" || value_hash)`
///
/// Matches `compute_leaf_hash` in `src/crypto.rs` (PyO3).
pub fn hash_leaf(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_HASH_PREFIX);
    hasher.update(SEP);
    hasher.update(key);
    hasher.update(SEP);
    hasher.update(value_hash);
    *hasher.finalize().as_bytes()
}

/// Hash an internal node with domain separation.
///
/// `BLAKE3(NODE_HASH_PREFIX || "|" || left || "|" || right)`
///
/// Matches `compute_node_hash` in `src/crypto.rs` (PyO3).
pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_HASH_PREFIX);
    hasher.update(SEP);
    hasher.update(left);
    hasher.update(SEP);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Get the empty leaf sentinel value
pub fn empty_leaf() -> [u8; 32] {
    *blake3::hash(EMPTY_LEAF_PREFIX).as_bytes()
}

/// Key manager for Ed25519 signing with hot-reload support.
///
/// The signing key is stored behind an [`std::sync::RwLock`] so that
/// [`reload_key`] can atomically swap it while concurrent [`sign_root`]
/// calls continue safely.  A SIGHUP handler (see `main.rs`) should call
/// [`reload_key`] to pick up a rotated `SEQUENCER_SMT_SIGNING_KEY`
/// without restarting the service.
pub struct KeyManager {
    inner: std::sync::RwLock<KeyPair>,
}

/// Interior key material protected by the RwLock.
struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

/// Load and validate the signing key from `SEQUENCER_SMT_SIGNING_KEY`.
///
/// Returns an error string on failure instead of panicking, so callers
/// can decide whether to abort (startup) or log-and-continue (reload).
fn load_signing_key_from_env() -> Result<KeyPair, String> {
    let key_str = std::env::var("SEQUENCER_SMT_SIGNING_KEY")
        .map_err(|_| "SEQUENCER_SMT_SIGNING_KEY environment variable is required".to_string())?;

    let key_bytes = if key_str.len() == 64 {
        hex::decode(&key_str).map_err(|e| {
            format!(
                "SEQUENCER_SMT_SIGNING_KEY is not valid hex (expected 64 hex chars): {e}"
            )
        })?
    } else {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&key_str)
            .map_err(|e| {
                format!("SEQUENCER_SMT_SIGNING_KEY is not valid base64 or hex: {e}")
            })?
    };

    if key_bytes.len() != 32 {
        return Err(format!(
            "SEQUENCER_SMT_SIGNING_KEY must decode to exactly 32 bytes, got {}",
            key_bytes.len()
        ));
    }

    let mut key_array = Zeroizing::new([0u8; 32]);
    key_array.copy_from_slice(&key_bytes);

    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key = signing_key.verifying_key();

    Ok(KeyPair {
        signing_key,
        verifying_key,
    })
}

impl KeyManager {
    pub fn new() -> Self {
        // At startup, a missing or malformed key is fatal.
        let pair = load_signing_key_from_env()
            .unwrap_or_else(|e| panic!("{e}"));

        Self {
            inner: std::sync::RwLock::new(pair),
        }
    }

    /// Re-read `SEQUENCER_SMT_SIGNING_KEY` and atomically swap the
    /// signing key.
    ///
    /// Returns `Ok(new_public_key)` on success so callers can log the
    /// rotation event, or `Err(reason)` if the new key is invalid (in
    /// which case the previous key remains active).
    pub fn reload_key(&self) -> Result<[u8; 32], String> {
        let new_pair = load_signing_key_from_env()?;
        let new_pk = new_pair.verifying_key.to_bytes();

        let mut guard = self
            .inner
            .write()
            .map_err(|e| format!("RwLock poisoned: {e}"))?;
        *guard = new_pair;

        Ok(new_pk)
    }

    /// Sign a root hash with tree_size and optional context.
    ///
    /// ## Signing protocol (authoritative specification for verifiers)
    ///
    /// The Ed25519 message is constructed as:
    ///
    /// ```text
    /// message = root[0..32]                       (32 bytes, SMT root hash)
    ///        || tree_size_le[0..8]                (8 bytes,  little-endian u64)
    ///        || context_entry* (sorted by key)
    /// ```
    ///
    /// Each `context_entry` (context keys sorted ascending as byte strings) is:
    ///
    /// ```text
    /// context_entry = len(key)[0..4]   (4 bytes, big-endian u32)
    ///              || key
    ///              || len(value)[0..4] (4 bytes, big-endian u32)
    ///              || value
    /// ```
    ///
    /// The big-endian u32 length prefix prevents field-bleed collisions (e.g.
    /// `key="ab", value="cd"` vs `key="a", value="bcd"` produce different bytes).
    ///
    /// This layout is a **protocol commitment**: verifier implementations must
    /// reproduce exactly these bytes to validate signatures.  Do not reorder
    /// `root`, `tree_size_le`, or `context` fields without a versioned protocol
    /// upgrade.
    pub fn sign_root(
        &self,
        root: &[u8; 32],
        tree_size: u64,
        context: &HashMap<String, String>,
    ) -> Result<([u8; 64], [u8; 32]), String> {
        // Serialize: root || tree_size_le || sorted length-prefixed context entries.
        // See the doc-comment above for the authoritative byte layout.
        let mut message = Vec::from(&root[..]);
        message.extend_from_slice(&tree_size.to_le_bytes());

        // Add sorted context with length-prefixed keys and values.
        // length_prefixed() asserts that inputs fit in u32, so this is safe.
        let mut keys: Vec<_> = context.keys().collect();
        keys.sort();
        for key in keys {
            message.extend_from_slice(&length_prefixed(key.as_bytes()));
            if let Some(value) = context.get(key) {
                message.extend_from_slice(&length_prefixed(value.as_bytes()));
            }
        }

        // Acquire read lock — concurrent sign_root calls are safe.
        let guard = self
            .inner
            .read()
            .map_err(|e| format!("RwLock poisoned: {e}"))?;

        let signature = guard.signing_key.sign(&message);

        Ok((
            signature.to_bytes(),
            guard.verifying_key.to_bytes(),
        ))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.inner
            .read()
            .expect("RwLock poisoned in public_key()")
            .verifying_key
            .to_bytes()
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
            version: "1".to_string(),
            metadata: HashMap::new(),
        };

        let key1 = compute_global_key("watauga:2025:budget", &record_key).unwrap();
        let key2 = compute_global_key("watauga:2025:budget", &record_key).unwrap();

        // Should be deterministic
        assert_eq!(key1, key2);

        // Different shard should give different key
        let key3 = compute_global_key("other:shard", &record_key).unwrap();
        assert_ne!(key1, key3);
    }

    /// Non-numeric version strings must be rejected (not silently coerced to 0).
    #[test]
    fn test_compute_global_key_rejects_non_numeric_version() {
        let record_key = RecordKey {
            record_type: "doc".to_string(),
            record_id: "12345".to_string(),
            version: "v1".to_string(),
            metadata: HashMap::new(),
        };

        let result = compute_global_key("shard", &record_key);
        assert!(result.is_err(), "non-numeric version 'v1' must be rejected");
        assert!(result.unwrap_err().contains("invalid version"));
    }

    /// Non-empty metadata must be rejected (it's not part of key derivation).
    #[test]
    fn test_compute_global_key_rejects_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), "value".to_string());

        let record_key = RecordKey {
            record_type: "doc".to_string(),
            record_id: "12345".to_string(),
            version: "1".to_string(),
            metadata,
        };

        let result = compute_global_key("shard", &record_key);
        assert!(result.is_err(), "non-empty metadata must be rejected");
        assert!(result.unwrap_err().contains("metadata"));
    }

    /// Verify length-prefixing prevents canonicalization / field-bleed collisions.
    ///
    /// Without length prefixes the following two inputs would hash identically:
    ///   shard_id="ab" + record_type="cd..."  vs  shard_id="abcd..." + record_type=""
    #[test]
    fn test_compute_global_key_no_field_bleed() {
        // shard_id="a", record_type="b", record_id="c", version=""
        let rk1 = RecordKey {
            record_type: "b".to_string(),
            record_id: "c".to_string(),
            version: "".to_string(),
            metadata: HashMap::new(),
        };
        // shard_id="ab", record_type="", record_id="c", version=""
        // Without length prefixes these concatenate to the same byte sequence.
        let rk2 = RecordKey {
            record_type: "".to_string(),
            record_id: "c".to_string(),
            version: "".to_string(),
            metadata: HashMap::new(),
        };

        let key1 = compute_global_key("a", &rk1).unwrap();
        let key2 = compute_global_key("ab", &rk2).unwrap();

        assert_ne!(key1, key2, "length-prefixing must prevent field-bleed collisions");
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
        // Set a test key (32 bytes of zeros, hex-encoded)
        std::env::set_var("SEQUENCER_SMT_SIGNING_KEY", "0000000000000000000000000000000000000000000000000000000000000000");

        let km = KeyManager::new();
        let root = [0u8; 32];
        let tree_size = 42u64;
        let context = HashMap::new();

        let result = km.sign_root(&root, tree_size, &context);
        assert!(result.is_ok());

        let (sig, pk) = result.unwrap();
        assert_eq!(sig.len(), 64);
        assert_eq!(pk.len(), 32);
        assert_eq!(pk, km.public_key());
    }

    #[test]
    fn test_key_manager_reload() {
        // Start with one key
        std::env::set_var(
            "SEQUENCER_SMT_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let km = KeyManager::new();
        let old_pk = km.public_key();

        // Rotate to a different key (32 bytes of 0x01)
        std::env::set_var(
            "SEQUENCER_SMT_SIGNING_KEY",
            "0101010101010101010101010101010101010101010101010101010101010101",
        );
        let new_pk = km.reload_key().expect("reload_key should succeed");

        // The public key should have changed
        assert_ne!(old_pk, new_pk);
        assert_eq!(new_pk, km.public_key());

        // Signing should use the new key
        let root = [0u8; 32];
        let (_, sig_pk) = km.sign_root(&root, 1, &HashMap::new()).unwrap();
        assert_eq!(sig_pk, new_pk);
    }

    #[test]
    fn test_key_manager_reload_bad_key_keeps_old() {
        // Start with a valid key
        std::env::set_var(
            "SEQUENCER_SMT_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let km = KeyManager::new();
        let old_pk = km.public_key();

        // Set an invalid key — reload should fail and keep the old one
        std::env::set_var("SEQUENCER_SMT_SIGNING_KEY", "not-valid");
        let result = km.reload_key();
        assert!(result.is_err());

        // Public key should still be the original
        assert_eq!(old_pk, km.public_key());
    }
}
