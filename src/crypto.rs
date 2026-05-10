//! BLAKE3-based crypto primitives for Olympus, exposed to Python via PyO3.
//!
//! Each function matches the call signature of the corresponding function in
//! ``protocol/hashes.py`` byte-for-byte.  The implementations are kept as
//! close to the Python originals as possible so that parity tests can treat
//! either backend as ground-truth.

use olympus_crypto as shared_crypto;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};
use std::collections::HashSet;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// ---------------------------------------------------------------------------
// Protocol constants — must stay in sync with protocol/hashes.py
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Pure-Rust hash functions (no GIL / no PyO3 types)
//
// These are used internally by `crate::smt` and by the PyO3 wrappers below.
// ---------------------------------------------------------------------------

/// Compute a domain-separated leaf hash per ADR-0003.
///
/// `BLAKE3(LEAF_PREFIX || "|" || key || "|" || value_hash || "|" ||
///         len(parser_id)[4B BE] || parser_id || "|" ||
///         len(canonical_parser_version)[4B BE] || canonical_parser_version)`
pub(crate) fn compute_leaf_hash(
    key: &[u8],
    value_hash: &[u8],
    parser_id: &[u8],
    canonical_parser_version: &[u8],
) -> [u8; 32] {
    shared_crypto::leaf_hash(key, value_hash, parser_id, canonical_parser_version)
}

/// Compute a domain-separated internal-node hash: `BLAKE3(NODE_PREFIX || "|" || left || "|" || right)`.
pub(crate) fn compute_node_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    shared_crypto::node_hash(left, right)
}

/// Compute the domain-separated empty-leaf sentinel: `BLAKE3(b"OLY:EMPTY-LEAF:V1")`.
pub(crate) fn compute_empty_leaf() -> [u8; 32] {
    shared_crypto::empty_leaf()
}

/// Domain-separated witness cosignature wrapper.
const WITNESS_PREFIX: &[u8] = b"OLY:WITNESS:V1|";

/// Witness cosignature tuple used by root attestation verification.
#[derive(Clone, Debug)]
pub struct Cosignature {
    /// Index into the `witness_keys` array.
    pub witness_index: usize,
    /// Raw Ed25519 signature bytes.
    pub signature: [u8; 64],
}

/// Errors returned by witness cosignature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidThreshold,
    InvalidWitnessIndex,
    InvalidSignatureFormat,
    ThresholdNotMet,
}

/// Verify witness co-signatures over a root checkpoint.
///
/// The payload is domain-separated as `OLY:WITNESS:V1| || root`.
pub fn verify_witness_cosignature(
    root: &[u8; 32],
    cosigs: &[Cosignature],
    witness_keys: &[VerifyingKey],
    threshold: usize,
) -> Result<(), CryptoError> {
    if threshold == 0 || threshold > witness_keys.len() {
        return Err(CryptoError::InvalidThreshold);
    }

    let mut payload = [0u8; WITNESS_PREFIX.len() + 32];
    payload[..WITNESS_PREFIX.len()].copy_from_slice(WITNESS_PREFIX);
    payload[WITNESS_PREFIX.len()..].copy_from_slice(root);

    let mut valid: HashSet<usize> = HashSet::new();
    for cosig in cosigs {
        if cosig.witness_index >= witness_keys.len() {
            return Err(CryptoError::InvalidWitnessIndex);
        }
        if valid.contains(&cosig.witness_index) {
            continue;
        }
        let sig = Signature::from_slice(&cosig.signature)
            .map_err(|_| CryptoError::InvalidSignatureFormat)?;
        if witness_keys[cosig.witness_index]
            .verify(&payload, &sig)
            .is_ok()
        {
            valid.insert(cosig.witness_index);
        }
    }

    if valid.len() >= threshold {
        Ok(())
    } else {
        Err(CryptoError::ThresholdNotMet)
    }
}

// ---------------------------------------------------------------------------
// Exposed Python functions
// ---------------------------------------------------------------------------

/// Compute a BLAKE3 hash over the concatenation of `parts`.
///
/// Equivalent to ``blake3.blake3(b"".join(parts)).digest()``.
///
/// Uses BLAKE3's incremental `update()` API with **zero-copy** borrows of the
/// underlying Python `bytes` buffers — no allocations beyond the 32-byte
/// output.
///
/// # Python signature
/// ``blake3_hash(parts: list[bytes]) -> bytes``
#[pyfunction]
pub fn blake3_hash<'py>(py: Python<'py>, parts: &Bound<'py, PyList>) -> PyResult<Py<PyBytes>> {
    let mut hasher = blake3::Hasher::new();
    for item in parts.iter() {
        let b = item.downcast::<PyBytes>()?;
        hasher.update(b.as_bytes());
    }
    let digest = hasher.finalize();
    Ok(PyBytes::new(py, digest.as_bytes()).into())
}

/// Derive a global SMT leaf key for the CD-HS-ST.
///
/// Uses BLAKE3 ``derive_key`` mode with the protocol-fixed context string so
/// that the domain is baked into the hash state and no separator can collide
/// with field boundaries.  Both inputs are length-prefixed before hashing.
///
/// # Python signature
/// ``global_key(shard_id: str, record_key_bytes: bytes) -> bytes``
#[pyfunction]
pub fn global_key(py: Python<'_>, shard_id: &str, record_key_bytes: &[u8]) -> PyObject {
    let digest = shared_crypto::global_key(shard_id, record_key_bytes);
    PyBytes::new(py, &digest).into()
}

/// Generate a deterministic 32-byte key for a record.
///
/// Replicates the Python ``record_key(record_type, record_id, version)``
/// function: prepends ``KEY_PREFIX``, then appends length-prefixed UTF-8
/// encodings of ``record_type`` and ``record_id``, and finally the 8-byte
/// big-endian encoding of ``version``.
///
/// # Python signature
/// ``record_key(record_type: str, record_id: str, version: int) -> bytes``
#[pyfunction]
pub fn record_key(py: Python<'_>, record_type: &str, record_id: &str, version: u64) -> PyObject {
    let digest = shared_crypto::record_key(record_type, record_id, version);
    PyBytes::new(py, &digest).into()
}

/// Compute a domain-separated hash for a sparse-tree leaf (ADR-0003).
///
/// ``leaf_hash = BLAKE3(LEAF_PREFIX || "|" || key || "|" || value_hash || "|" ||
///                      len(parser_id)[4B BE] || parser_id || "|" ||
///                      len(canonical_parser_version)[4B BE] || canonical_parser_version)``
///
/// Both ``parser_id`` and ``canonical_parser_version`` MUST be non-empty.
///
/// # Python signature
/// ``leaf_hash(key: bytes, value_hash: bytes, parser_id: str, canonical_parser_version: str) -> bytes``
#[pyfunction]
pub fn leaf_hash(
    py: Python<'_>,
    key: &[u8],
    value_hash: &[u8],
    parser_id: &str,
    canonical_parser_version: &str,
) -> PyResult<PyObject> {
    if parser_id.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "parser_id must be a non-empty string",
        ));
    }
    if canonical_parser_version.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "canonical_parser_version must be a non-empty string",
        ));
    }
    let digest = compute_leaf_hash(
        key,
        value_hash,
        parser_id.as_bytes(),
        canonical_parser_version.as_bytes(),
    );
    Ok(PyBytes::new(py, &digest).into())
}

/// Compute a domain-separated hash for an internal Merkle node.
///
/// ``node_hash = BLAKE3(NODE_PREFIX || "|" || left || "|" || right)``
///
/// # Python signature
/// ``node_hash(left: bytes, right: bytes) -> bytes``
#[pyfunction]
pub fn node_hash(py: Python<'_>, left: &[u8], right: &[u8]) -> PyObject {
    let digest = compute_node_hash(left, right);
    PyBytes::new(py, &digest).into()
}

// ---------------------------------------------------------------------------
// Submodule registration
// ---------------------------------------------------------------------------

/// Register all crypto functions into the given Python (sub)module.
pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(blake3_hash, m)?)?;
    m.add_function(wrap_pyfunction!(global_key, m)?)?;
    m.add_function(wrap_pyfunction!(record_key, m)?)?;
    m.add_function(wrap_pyfunction!(leaf_hash, m)?)?;
    m.add_function(wrap_pyfunction!(node_hash, m)?)?;

    // Make the submodule importable as `olympus_core.crypto`
    py.import("sys")?
        .getattr("modules")?
        .set_item("olympus_core.crypto", m)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn witness_cosignature_threshold_passes() {
        let root = [7u8; 32];
        let k1 = make_key(1);
        let k2 = make_key(2);
        let k3 = make_key(3);
        let keys = vec![k1.verifying_key(), k2.verifying_key(), k3.verifying_key()];

        let mut payload = Vec::with_capacity(WITNESS_PREFIX.len() + root.len());
        payload.extend_from_slice(WITNESS_PREFIX);
        payload.extend_from_slice(&root);

        let c1 = Cosignature {
            witness_index: 0,
            signature: k1.sign(&payload).to_bytes(),
        };
        let c2 = Cosignature {
            witness_index: 1,
            signature: k2.sign(&payload).to_bytes(),
        };

        assert!(verify_witness_cosignature(&root, &[c1, c2], &keys, 2).is_ok());
    }

    #[test]
    fn witness_cosignature_threshold_fails() {
        let root = [9u8; 32];
        let k1 = make_key(11);
        let k2 = make_key(12);
        let keys = vec![k1.verifying_key(), k2.verifying_key()];

        let mut payload = Vec::with_capacity(WITNESS_PREFIX.len() + root.len());
        payload.extend_from_slice(WITNESS_PREFIX);
        payload.extend_from_slice(&root);

        let c1 = Cosignature {
            witness_index: 0,
            signature: k1.sign(&payload).to_bytes(),
        };

        let err = verify_witness_cosignature(&root, &[c1], &keys, 2).expect_err("must fail");
        assert_eq!(err, CryptoError::ThresholdNotMet);
    }
}
