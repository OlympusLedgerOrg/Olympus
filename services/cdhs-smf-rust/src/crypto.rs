//! Cryptographic primitives for CD-HS-ST
//!
//! This module implements:
//! - BLAKE3 hashing with domain separation
//! - Composite key generation
//! - Ed25519 signing

use blake3;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::collections::HashMap;
use tracing::warn;
use zeroize::Zeroizing;

/// Environment variable naming a file containing the Ed25519 signing key.
///
/// **This is the preferred way to provision the key.**  The file must contain
/// the key encoded as 64 hex chars or as standard base64 of 32 raw bytes
/// (trailing whitespace / newline is trimmed).  On Unix the file must not be
/// readable by group or other (recommended mode: `0600`).
pub const SIGNING_KEY_PATH_ENV: &str = "SEQUENCER_SMT_SIGNING_KEY_PATH";

/// Deprecated environment variable carrying the signing key inline.
///
/// Retained as a fallback for backwards compatibility, but discouraged: env
/// vars are visible to any process that can read `/proc/<pid>/environ` and
/// frequently leak into shell history, container inspect output, and process
/// listings.  Prefer [`SIGNING_KEY_PATH_ENV`].
pub const SIGNING_KEY_ENV: &str = "SEQUENCER_SMT_SIGNING_KEY";

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

/// Domain-separation prefix for Ed25519 signed roots produced by
/// [`KeyManager::sign_root`].  Versioned (`:V1`) so a future protocol change
/// can introduce a new tag without ambiguity.  See `sign_root` for the full
/// signed-message layout.
const SIG_ROOT_DOMAIN: &[u8] = b"OLY:SIG:ROOT:V1";

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
    // Hot path: cheap bound check elided in release builds; the inner
    // `length_prefixed` carries the equivalent `assert!` for production.
    debug_assert!(shard_bytes.len() <= u32::MAX as usize);
    debug_assert!(record_key_bytes.len() <= u32::MAX as usize);
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
    debug_assert!(rt.len() <= u32::MAX as usize);
    debug_assert!(ri.len() <= u32::MAX as usize);

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
/// [`reload_key`] to pick up a rotated key without restarting the service.
///
/// The signing key is provisioned via either [`SIGNING_KEY_PATH_ENV`]
/// (preferred — file mode `0600`) or [`SIGNING_KEY_ENV`] (deprecated env-var
/// fallback).  See [`load_signing_key`] for the full resolution order.
pub struct KeyManager {
    inner: std::sync::RwLock<KeyPair>,
}

/// Interior key material protected by the RwLock.
struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

/// Load and validate the signing key.
///
/// Resolution order:
///
/// 1. If [`SIGNING_KEY_PATH_ENV`] (`SEQUENCER_SMT_SIGNING_KEY_PATH`) is set,
///    read the key from that file.  On Unix the file must not be group- or
///    world-accessible (i.e. `mode & 0o077 == 0`; recommended `0600`).
/// 2. Otherwise, fall back to [`SIGNING_KEY_ENV`] (`SEQUENCER_SMT_SIGNING_KEY`).
///    This path is **deprecated** because env vars are visible via
///    `/proc/<pid>/environ`; a `warn!` is emitted whenever it is taken.
///
/// In both cases the key material is parsed as 64 hex chars or as standard
/// base64 of 32 raw bytes (trailing whitespace is trimmed).
///
/// Returns an error string on failure instead of panicking, so callers
/// can decide whether to abort (startup) or log-and-continue (reload).
fn load_signing_key() -> Result<KeyPair, String> {
    if let Some(path) = std::env::var_os(SIGNING_KEY_PATH_ENV) {
        let path = std::path::PathBuf::from(path);
        return load_signing_key_from_path(&path);
    }

    match std::env::var(SIGNING_KEY_ENV) {
        Ok(key_str) => {
            warn!(
                env = SIGNING_KEY_ENV,
                preferred = SIGNING_KEY_PATH_ENV,
                "loading signing key from environment variable is deprecated; \
                 env vars are visible via /proc/<pid>/environ. \
                 Set {SIGNING_KEY_PATH_ENV} to a 0600 file containing the key."
            );
            parse_signing_key(&key_str, SIGNING_KEY_ENV)
        }
        Err(_) => Err(format!(
            "no signing key configured: set {SIGNING_KEY_PATH_ENV} (preferred) \
             or {SIGNING_KEY_ENV} (deprecated)"
        )),
    }
}

/// Load the signing key from the file at `path`, enforcing safe permissions
/// on Unix.
fn load_signing_key_from_path(path: &std::path::Path) -> Result<KeyPair, String> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        format!(
            "failed to stat {SIGNING_KEY_PATH_ENV} ({}): {e}",
            path.display()
        )
    })?;

    if !metadata.is_file() {
        return Err(format!(
            "{SIGNING_KEY_PATH_ENV} ({}) must be a regular file",
            path.display()
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        // Reject any group or other permission bits.  Matches the SSH
        // convention for private-key files; recommended mode is 0600.
        if mode & 0o077 != 0 {
            return Err(format!(
                "{SIGNING_KEY_PATH_ENV} ({}) has insecure permissions {:#o}; \
                 require mode 0600 (no group/other access)",
                path.display(),
                mode
            ));
        }
    }

    // Hold contents in a Zeroizing buffer so the raw key bytes are wiped
    // from memory when this function returns.
    let raw = std::fs::read(path).map_err(|e| {
        format!(
            "failed to read {SIGNING_KEY_PATH_ENV} ({}): {e}",
            path.display()
        )
    })?;
    let raw = Zeroizing::new(raw);

    let key_str = std::str::from_utf8(&raw)
        .map_err(|e| format!("{SIGNING_KEY_PATH_ENV} ({}) is not valid UTF-8: {e}", path.display()))?
        .trim();

    parse_signing_key(key_str, SIGNING_KEY_PATH_ENV)
}

/// Parse a 32-byte Ed25519 signing key from its hex or base64 string form.
///
/// `source` is included in error messages so callers can tell which
/// environment variable / file provided the bad value.
fn parse_signing_key(key_str: &str, source: &str) -> Result<KeyPair, String> {
    let key_bytes = if key_str.len() == 64 {
        hex::decode(key_str).map_err(|e| {
            format!("{source} is not valid hex (expected 64 hex chars): {e}")
        })?
    } else {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(key_str)
            .map_err(|e| format!("{source} is not valid base64 or hex: {e}"))?
    };

    if key_bytes.len() != 32 {
        return Err(format!(
            "{source} must decode to exactly 32 bytes, got {}",
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
        let pair = load_signing_key()
            .unwrap_or_else(|e| panic!("{e}"));

        Self {
            inner: std::sync::RwLock::new(pair),
        }
    }

    /// Re-read the signing key (from [`SIGNING_KEY_PATH_ENV`] or, as a
    /// deprecated fallback, [`SIGNING_KEY_ENV`]) and atomically swap it.
    ///
    /// Returns `Ok(new_public_key)` on success so callers can log the
    /// rotation event, or `Err(reason)` if the new key is invalid (in
    /// which case the previous key remains active).
    pub fn reload_key(&self) -> Result<[u8; 32], String> {
        let new_pair = load_signing_key()?;
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
    /// message = SIG_ROOT_DOMAIN                    (b"OLY:SIG:ROOT:V1", domain separation)
    ///        || root[0..32]                       (32 bytes, SMT root hash)
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
    /// The `OLY:SIG:ROOT:V1` prefix is a domain-separation tag: it ensures this
    /// signing key cannot be tricked into producing a signature whose message
    /// happens to coincide with one used by a different Olympus subsystem (e.g.
    /// a redaction-proof or witness payload), even if that subsystem's bytes
    /// look like `root || tree_size_le || context`.
    ///
    /// This layout is a **protocol commitment**: verifier implementations must
    /// reproduce exactly these bytes to validate signatures.  Do not reorder
    /// `SIG_ROOT_DOMAIN`, `root`, `tree_size_le`, or `context` fields without a
    /// versioned protocol upgrade.
    pub fn sign_root(
        &self,
        root: &[u8; 32],
        tree_size: u64,
        context: &HashMap<String, String>,
    ) -> Result<([u8; 64], [u8; 32]), String> {
        // Serialize: SIG_ROOT_DOMAIN || root || tree_size_le || sorted length-prefixed context entries.
        // See the doc-comment above for the authoritative byte layout.
        let mut message = Vec::with_capacity(SIG_ROOT_DOMAIN.len() + 32 + 8);
        message.extend_from_slice(SIG_ROOT_DOMAIN);
        message.extend_from_slice(&root[..]);
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

    /// Serializes tests that mutate process-global env vars (`SEQUENCER_SMT_SIGNING_KEY*`).
    /// Without this, parallel tests race on env-var state and `KeyManager` construction.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        // Even if a previous test panicked while holding the lock, we still
        // want subsequent tests to make progress, so recover from poisoning.
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Reset both signing-key env vars to a known state before a test sets
    /// the ones it cares about.
    fn clear_signing_env() {
        std::env::remove_var(SIGNING_KEY_PATH_ENV);
        std::env::remove_var(SIGNING_KEY_ENV);
    }

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
        let _lock = env_lock();
        clear_signing_env();
        // Set a test key (32 bytes of zeros, hex-encoded)
        std::env::set_var(SIGNING_KEY_ENV, "0000000000000000000000000000000000000000000000000000000000000000");

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
        clear_signing_env();
    }

    #[test]
    fn test_key_manager_reload() {
        let _lock = env_lock();
        clear_signing_env();
        // Start with one key
        std::env::set_var(
            SIGNING_KEY_ENV,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let km = KeyManager::new();
        let old_pk = km.public_key();

        // Rotate to a different key (32 bytes of 0x01)
        std::env::set_var(
            SIGNING_KEY_ENV,
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
        clear_signing_env();
    }

    #[test]
    fn test_key_manager_reload_bad_key_keeps_old() {
        let _lock = env_lock();
        clear_signing_env();
        // Start with a valid key
        std::env::set_var(
            SIGNING_KEY_ENV,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let km = KeyManager::new();
        let old_pk = km.public_key();

        // Set an invalid key — reload should fail and keep the old one
        std::env::set_var(SIGNING_KEY_ENV, "not-valid");
        let result = km.reload_key();
        assert!(result.is_err());

        // Public key should still be the original
        assert_eq!(old_pk, km.public_key());
        clear_signing_env();
    }

    /// Helper: write `contents` to a unique file in the temp dir with the
    /// given Unix mode and return the path.  The caller is responsible for
    /// removing the file.
    fn write_key_file(contents: &str, mode: u32) -> std::path::PathBuf {
        use std::io::Write;
        let mut path = std::env::temp_dir();
        // Unique-enough filename for tests running in the same process.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "olympus-signing-key-{}-{}.key",
            std::process::id(),
            nanos
        ));
        let mut f = std::fs::File::create(&path).expect("create key file");
        f.write_all(contents.as_bytes()).expect("write key file");
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("chmod key file");
        }
        let _ = mode; // silence unused on non-unix
        path
    }

    #[test]
    fn test_key_manager_loads_from_file_path() {
        let _lock = env_lock();
        clear_signing_env();
        let key_hex = "0202020202020202020202020202020202020202020202020202020202020202";
        // Trailing newline is intentional: load_signing_key_from_path must trim.
        let path = write_key_file(&format!("{key_hex}\n"), 0o600);
        std::env::set_var(SIGNING_KEY_PATH_ENV, &path);
        // Also set the env-var fallback to a *different* key to confirm
        // the path takes precedence.
        std::env::set_var(
            SIGNING_KEY_ENV,
            "0303030303030303030303030303030303030303030303030303030303030303",
        );

        let km = KeyManager::new();

        // Public key must match the one derived from the file's bytes.
        let key_bytes = hex::decode(key_hex).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        let expected_pk = SigningKey::from_bytes(&arr).verifying_key().to_bytes();
        assert_eq!(km.public_key(), expected_pk);

        clear_signing_env();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_key_manager_reloads_from_file_path() {
        let _lock = env_lock();
        clear_signing_env();
        let path = write_key_file(
            "0404040404040404040404040404040404040404040404040404040404040404\n",
            0o600,
        );
        std::env::set_var(SIGNING_KEY_PATH_ENV, &path);

        let km = KeyManager::new();
        let old_pk = km.public_key();

        // Rewrite the same file with a new key and reload.
        std::fs::write(
            &path,
            "0505050505050505050505050505050505050505050505050505050505050505\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let new_pk = km.reload_key().expect("reload from file path should succeed");
        assert_ne!(old_pk, new_pk);
        assert_eq!(new_pk, km.public_key());

        clear_signing_env();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn test_key_manager_rejects_world_readable_file() {
        let _lock = env_lock();
        clear_signing_env();
        let path = write_key_file(
            "0606060606060606060606060606060606060606060606060606060606060606\n",
            0o644, // group + other readable — must be rejected
        );
        std::env::set_var(SIGNING_KEY_PATH_ENV, &path);

        let err = match load_signing_key() {
            Ok(_) => panic!("insecure mode must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.contains("insecure permissions"),
            "expected permission error, got: {err}"
        );

        clear_signing_env();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_key_manager_path_takes_precedence_over_env() {
        let _lock = env_lock();
        clear_signing_env();
        let path_key = "0707070707070707070707070707070707070707070707070707070707070707";
        let env_key = "0808080808080808080808080808080808080808080808080808080808080808";
        let path = write_key_file(&format!("{path_key}\n"), 0o600);
        std::env::set_var(SIGNING_KEY_PATH_ENV, &path);
        std::env::set_var(SIGNING_KEY_ENV, env_key);

        let pair = match load_signing_key() {
            Ok(p) => p,
            Err(e) => panic!("load should succeed: {e}"),
        };

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hex::decode(path_key).unwrap());
        let expected_pk = SigningKey::from_bytes(&arr).verifying_key().to_bytes();
        assert_eq!(pair.verifying_key.to_bytes(), expected_pk);

        clear_signing_env();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_signing_key_errors_when_unset() {
        let _lock = env_lock();
        clear_signing_env();
        let err = match load_signing_key() {
            Ok(_) => panic!("must error when neither env var is set"),
            Err(e) => e,
        };
        assert!(err.contains(SIGNING_KEY_PATH_ENV));
        assert!(err.contains(SIGNING_KEY_ENV));
    }
}
