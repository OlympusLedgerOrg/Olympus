//! BLAKE3-based crypto primitives for Olympus, exposed to Python via PyO3.
//!
//! Each function matches the call signature of the corresponding function in
//! ``protocol/hashes.py`` byte-for-byte.  The implementations are kept as
//! close to the Python originals as possible so that parity tests can treat
//! either backend as ground-truth.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

// ---------------------------------------------------------------------------
// Protocol constants — must stay in sync with protocol/hashes.py
// ---------------------------------------------------------------------------

/// BLAKE3 derive_key context for global SMT leaf keys.
const GLOBAL_SMT_KEY_CONTEXT: &str = "olympus 2025-12 global-smt-leaf-key";

/// Domain-separation prefix for record keys.
const KEY_PREFIX: &[u8] = b"OLY:KEY:V1";

/// Domain-separation prefix for SMT leaf nodes.
const LEAF_PREFIX: &[u8] = b"OLY:LEAF:V1";

/// Domain-separation prefix for SMT internal nodes.
const NODE_PREFIX: &[u8] = b"OLY:NODE:V1";

/// Field separator used in leaf and node hash concatenation.
const SEP: &[u8] = b"|";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode `data` with a 4-byte big-endian length prefix.
///
/// This prevents field-injection collisions between variable-length inputs
/// (e.g. a `shard_id` value that contains "|" characters cannot be confused
/// with a field boundary).
fn length_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
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
    let shard_bytes = shard_id.as_bytes();
    let mut key_material = Vec::with_capacity(4 + shard_bytes.len() + 4 + record_key_bytes.len());
    key_material.extend_from_slice(&length_prefixed(shard_bytes));
    key_material.extend_from_slice(&length_prefixed(record_key_bytes));

    let digest = blake3::Hasher::new_derive_key(GLOBAL_SMT_KEY_CONTEXT)
        .update(&key_material)
        .finalize();

    PyBytes::new(py, digest.as_bytes()).into()
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
    let rt = record_type.as_bytes();
    let ri = record_id.as_bytes();
    let mut key_data = Vec::with_capacity(KEY_PREFIX.len() + 4 + rt.len() + 4 + ri.len() + 8);
    key_data.extend_from_slice(KEY_PREFIX);
    key_data.extend_from_slice(&length_prefixed(rt));
    key_data.extend_from_slice(&length_prefixed(ri));
    key_data.extend_from_slice(&version.to_be_bytes());

    let digest = blake3::Hasher::new().update(&key_data).finalize();
    PyBytes::new(py, digest.as_bytes()).into()
}

/// Compute a domain-separated hash for a sparse-tree leaf.
///
/// ``leaf_hash = BLAKE3(LEAF_PREFIX || "|" || key || "|" || value_hash)``
///
/// # Python signature
/// ``leaf_hash(key: bytes, value_hash: bytes) -> bytes``
#[pyfunction]
pub fn leaf_hash(py: Python<'_>, key: &[u8], value_hash: &[u8]) -> PyObject {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_PREFIX);
    hasher.update(SEP);
    hasher.update(key);
    hasher.update(SEP);
    hasher.update(value_hash);
    let digest = hasher.finalize();
    PyBytes::new(py, digest.as_bytes()).into()
}

/// Compute a domain-separated hash for an internal Merkle node.
///
/// ``node_hash = BLAKE3(NODE_PREFIX || "|" || left || "|" || right)``
///
/// # Python signature
/// ``node_hash(left: bytes, right: bytes) -> bytes``
#[pyfunction]
pub fn node_hash(py: Python<'_>, left: &[u8], right: &[u8]) -> PyObject {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_PREFIX);
    hasher.update(SEP);
    hasher.update(left);
    hasher.update(SEP);
    hasher.update(right);
    let digest = hasher.finalize();
    PyBytes::new(py, digest.as_bytes()).into()
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
