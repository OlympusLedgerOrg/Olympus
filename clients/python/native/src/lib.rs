// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Optional native backend for the `olympus-manifest` Python SDK.
//!
//! This wraps the Rust source of truth (`olympus-crypto`, `olympus-manifest`).
//! It deliberately does NOT replace the pure-Python verifier in
//! `clients/python/src/olympus_manifest/`: that package is one of the four
//! *independent* implementations of the leaf-hash layout (AGENTS.md), and a
//! binding agrees with the producer by construction. The cross-backend test
//! (`clients/python/tests/test_native_parity.py`) pins the two against each
//! other and against `vectors.json`.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn hash32(name: &str, b: &[u8]) -> PyResult<[u8; 32]> {
    b.try_into()
        .map_err(|_| PyValueError::new_err(format!("{name} must be 32 bytes (got {})", b.len())))
}

/// ADR-0005 structured leaf hash. Raises `ValueError` (instead of the Rust
/// release `assert!` panic) on a non-32-byte `key` / `value_hash`.
#[pyfunction]
fn leaf_hash<'py>(
    py: Python<'py>,
    shard_id: &[u8],
    key: &[u8],
    value_hash: &[u8],
    parser_id: &[u8],
    canonical_parser_version: &[u8],
    model_hash: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    hash32("key", key)?;
    hash32("value_hash", value_hash)?;
    let out = olympus_crypto::leaf_hash(
        shard_id,
        key,
        value_hash,
        parser_id,
        canonical_parser_version,
        model_hash,
    );
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
fn node_hash<'py>(py: Python<'py>, left: &[u8], right: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    hash32("left", left)?;
    hash32("right", right)?;
    Ok(PyBytes::new(py, &olympus_crypto::node_hash(left, right)))
}

#[pyfunction]
fn empty_leaf(py: Python<'_>) -> Bound<'_, PyBytes> {
    PyBytes::new(py, &olympus_crypto::empty_leaf())
}

#[pyfunction]
fn empty_subtree_hash(py: Python<'_>, height: usize) -> PyResult<Bound<'_, PyBytes>> {
    if height > 256 {
        return Err(PyValueError::new_err("height out of range"));
    }
    Ok(PyBytes::new(
        py,
        &olympus_crypto::smt::empty_subtree_hash(height),
    ))
}

#[pyfunction]
fn record_key<'py>(
    py: Python<'py>,
    record_type: &str,
    record_id: &str,
    version: u64,
) -> Bound<'py, PyBytes> {
    PyBytes::new(
        py,
        &olympus_crypto::record_key(record_type, record_id, version),
    )
}

#[pyfunction]
fn shard_record_key<'py>(
    py: Python<'py>,
    shard_id: &str,
    rkey: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let rk = hash32("record_key", rkey)?;
    Ok(PyBytes::new(
        py,
        &olympus_crypto::smt::shard_record_key(shard_id, &rk),
    ))
}

/// Verify a record proof bundle (JSON text) against `expected_root`.
///
/// Returns the same verdict strings as `olympus_manifest.proof.Verdict`;
/// any parse/decode failure is `"malformed"` (never raises on untrusted input).
#[pyfunction]
fn verify_bundle(bundle_json: &str, expected_root: &[u8]) -> PyResult<&'static str> {
    use olympus_manifest::proof::{verify, RecordProofBundle, Verdict};
    let root = hash32("expected_root", expected_root)?;
    let Ok(bundle) = serde_json::from_str::<RecordProofBundle>(bundle_json) else {
        return Ok("malformed");
    };
    Ok(match verify(&bundle, &root) {
        Ok(Verdict::Valid) => "valid",
        Ok(Verdict::RootMismatch) => "root_mismatch",
        Ok(Verdict::KeyMismatch) => "key_mismatch",
        Ok(Verdict::ContentMismatch) => "content_mismatch",
        Ok(Verdict::KindMismatch) => "kind_mismatch",
        Ok(Verdict::SmtInvalid) => "smt_invalid",
        Err(_) => "malformed",
    })
}

#[pymodule]
fn olympus_manifest_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(leaf_hash, m)?)?;
    m.add_function(wrap_pyfunction!(node_hash, m)?)?;
    m.add_function(wrap_pyfunction!(empty_leaf, m)?)?;
    m.add_function(wrap_pyfunction!(empty_subtree_hash, m)?)?;
    m.add_function(wrap_pyfunction!(record_key, m)?)?;
    m.add_function(wrap_pyfunction!(shard_record_key, m)?)?;
    m.add_function(wrap_pyfunction!(verify_bundle, m)?)?;
    Ok(())
}
