//! Sparse Merkle Tree exposed to Python via PyO3.
//!
//! This is a 256-height sparse Merkle tree that produces byte-for-byte
//! identical roots and proofs to the pure-Python ``SparseMerkleTree`` in
//! ``protocol/ssmf.py``.
//!
//! All hash computations delegate to [`crate::crypto`] which uses the correct
//! domain-separation prefixes (``OLY:LEAF:V1``, ``OLY:NODE:V1``, with ``|``
//! separators).

use std::collections::HashMap;
use std::sync::RwLock;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};

use crate::crypto;

/// Map a poisoned `RwLock` error to a Python `RuntimeError`.
///
/// A poisoned lock means a prior write-guard holder panicked, leaving the
/// internal state potentially inconsistent.  Rather than propagating the panic
/// (which would crash the Python interpreter), we surface a clear error.
fn lock_err<T>(_e: std::sync::PoisonError<T>) -> PyErr {
    PyRuntimeError::new_err("RustSparseMerkleTree: internal lock poisoned (prior panic during write)")
}

// ---------------------------------------------------------------------------
// Internal helpers (no PyO3 types)
// ---------------------------------------------------------------------------

/// Convert a 32-byte key to a 256-element path of bits (MSB first).
fn key_to_path_bits(key: &[u8; 32]) -> Vec<u8> {
    let mut path = Vec::with_capacity(256);
    for byte in key {
        for i in 0..8u8 {
            path.push((byte >> (7 - i)) & 1);
        }
    }
    path
}

/// Precompute empty hashes for the 256-level sparse tree.
///
/// `empty_hashes[i]` is the hash of a completely-empty subtree at height `i`:
/// - `empty_hashes[0] = BLAKE3(b"OLY:EMPTY-LEAF:V1")`
/// - `empty_hashes[i] = node_hash(empty_hashes[i-1], empty_hashes[i-1])`
///
/// The vector has 257 elements (indices 0..=256).
fn precompute_empty_hashes() -> Vec<[u8; 32]> {
    let mut empty = Vec::with_capacity(257);
    empty.push(crypto::compute_empty_leaf());
    for _ in 0..256 {
        let last = *empty.last().unwrap();
        empty.push(crypto::compute_node_hash(&last, &last));
    }
    empty
}

/// Get the sibling path by flipping the last bit of `path`.
fn sibling_path(path: &[u8]) -> Vec<u8> {
    let mut sib = path.to_vec();
    let last = sib.len() - 1;
    sib[last] = 1 - sib[last];
    sib
}

/// Pack a slice of path bits (0s and 1s) into bytes, MSB first.
///
/// Matches `StorageLayer._encode_path()` in `storage/postgres.py`.
/// An empty slice returns an empty Vec. A 256-element slice returns 32 bytes.
fn pack_path_bits(bits: &[u8]) -> Vec<u8> {
    if bits.is_empty() {
        return Vec::new();
    }
    let num_bytes = bits.len().div_ceil(8);
    let mut result = vec![0u8; num_bytes];
    for (i, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            result[i >> 3] |= 1 << (7 - (i & 7));
        }
    }
    result
}

/// A node delta produced by `incremental_update_raw`: `(db_level, packed_index, hash)`.
type NodeDelta = (usize, Vec<u8>, [u8; 32]);

/// Pure-Rust incremental update (no PyO3 types).
///
/// Computes an SMT update using only the 256 proof-path siblings.
/// Returns `(new_root, node_deltas)` where deltas are `(db_level, packed_index, hash)`.
fn incremental_update_raw(
    key: &[u8; 32],
    value_hash: &[u8; 32],
    current_siblings: &[[u8; 32]],
) -> ([u8; 32], Vec<NodeDelta>) {
    let path = key_to_path_bits(key);
    let mut current_hash = crypto::compute_leaf_hash(key, value_hash);
    let mut deltas = Vec::with_capacity(256);

    for (level, sib_hash) in current_siblings.iter().enumerate().take(256) {
        let bit_pos = 255 - level;

        let parent_hash = if path[bit_pos] == 0 {
            crypto::compute_node_hash(&current_hash, sib_hash)
        } else {
            crypto::compute_node_hash(sib_hash, &current_hash)
        };

        let (db_level, packed_index) = if bit_pos == 0 {
            (0usize, Vec::new())
        } else {
            (bit_pos, pack_path_bits(&path[..bit_pos]))
        };

        deltas.push((db_level, packed_index, parent_hash));
        current_hash = parent_hash;
    }

    (current_hash, deltas)
}

// ---------------------------------------------------------------------------
// Internal tree state
// ---------------------------------------------------------------------------

struct TreeState {
    /// Internal nodes keyed by path-bit prefix (Vec of 0s and 1s).
    /// The root is at key `vec![]` (empty).
    nodes: HashMap<Vec<u8>, [u8; 32]>,
    /// Leaf storage: 32-byte key → 32-byte value_hash.
    leaves: HashMap<[u8; 32], [u8; 32]>,
}

// ---------------------------------------------------------------------------
// PyO3 class
// ---------------------------------------------------------------------------

/// A 256-height sparse Merkle tree backed by Rust.
///
/// Drop-in replacement for the Python ``SparseMerkleTree`` in
/// ``protocol/ssmf.py``.
#[pyclass]
pub struct RustSparseMerkleTree {
    state: RwLock<TreeState>,
    /// Precomputed empty hashes (257 elements, computed once in ``new``).
    empty_hashes: Vec<[u8; 32]>,
}

#[pymethods]
impl RustSparseMerkleTree {
    #[new]
    fn new() -> Self {
        Self {
            state: RwLock::new(TreeState {
                nodes: HashMap::new(),
                leaves: HashMap::new(),
            }),
            empty_hashes: precompute_empty_hashes(),
        }
    }

    /// Insert or update a leaf.  `key` and `value_hash` must each be 32 bytes.
    fn update(&self, key: &[u8], value_hash: &[u8]) -> PyResult<()> {
        if key.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "Key must be 32 bytes, got {}",
                key.len()
            )));
        }
        if value_hash.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "Value hash must be 32 bytes, got {}",
                value_hash.len()
            )));
        }

        let key32: [u8; 32] = key.try_into().unwrap();
        let vh32: [u8; 32] = value_hash.try_into().unwrap();
        let path = key_to_path_bits(&key32);

        let mut state = self.state.write().map_err(lock_err)?;
        state.leaves.insert(key32, vh32);

        // Compute leaf hash and walk from leaf to root, exactly matching
        // the Python ``SparseMerkleTree.update`` loop.
        let mut current_hash = crypto::compute_leaf_hash(key, value_hash);

        for level in 0..256usize {
            let bit_pos = 255 - level;

            // Sibling path: path[0..=bit_pos] with last bit flipped.
            let sib_path = sibling_path(&path[..=bit_pos]);

            let sib_hash = state
                .nodes
                .get(&sib_path)
                .copied()
                .unwrap_or(self.empty_hashes[level]);

            let parent_hash = if path[bit_pos] == 0 {
                crypto::compute_node_hash(&current_hash, &sib_hash)
            } else {
                crypto::compute_node_hash(&sib_hash, &current_hash)
            };

            let parent_path = if bit_pos == 0 {
                Vec::new()
            } else {
                path[..bit_pos].to_vec()
            };

            state.nodes.insert(parent_path, parent_hash);
            current_hash = parent_hash;
        }

        Ok(())
    }

    /// Return the 32-byte root hash.
    fn get_root<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        let state = self.state.read().map_err(lock_err)?;
        let root = if state.nodes.is_empty() && state.leaves.is_empty() {
            self.empty_hashes[256]
        } else {
            state
                .nodes
                .get(&Vec::<u8>::new())
                .copied()
                .unwrap_or(self.empty_hashes[256])
        };
        Ok(PyBytes::new(py, &root).into())
    }

    /// Return the value_hash for a key, or ``None`` if absent.
    fn get<'py>(&self, py: Python<'py>, key: &[u8]) -> PyResult<Option<PyObject>> {
        if key.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "Key must be 32 bytes, got {}",
                key.len()
            )));
        }
        let key32: [u8; 32] = key.try_into().unwrap();
        let state = self.state.read().map_err(lock_err)?;
        Ok(state
            .leaves
            .get(&key32)
            .map(|v| PyBytes::new(py, v).into()))
    }

    /// Number of non-empty leaves.
    #[getter]
    fn size(&self) -> PyResult<usize> {
        Ok(self.state.read().map_err(lock_err)?.leaves.len())
    }

    /// Snapshot of leaves as ``dict[bytes, bytes]``.
    #[getter]
    fn leaves<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        let state = self.state.read().map_err(lock_err)?;
        let dict = PyDict::new(py);
        for (k, v) in &state.leaves {
            dict.set_item(PyBytes::new(py, k), PyBytes::new(py, v))?;
        }
        Ok(dict.into())
    }

    /// Snapshot of internal nodes as ``dict[tuple[int,...], bytes]``.
    ///
    /// Keys are tuples of path bits matching the Python ``SparseMerkleTree.nodes``
    /// format where the root is keyed by ``()``.
    #[getter]
    fn nodes<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        let state = self.state.read().map_err(lock_err)?;
        let dict = PyDict::new(py);
        for (path, hash) in &state.nodes {
            // Convert Vec<u8> path → Python tuple of ints.
            let elements: Vec<PyObject> = path
                .iter()
                .map(|&b| {
                    // u8 → Python int is infallible; into_pyobject returns Result<_, Infallible>.
                    let py_int = b.into_pyobject(py).expect("u8 conversion is infallible");
                    py_int.into()
                })
                .collect();
            let key_tuple = PyTuple::new(py, &elements)?;
            dict.set_item(key_tuple, PyBytes::new(py, hash))?;
        }
        Ok(dict.into())
    }

    /// Return ``(value_hash, siblings, root_hash)`` for an existing key.
    ///
    /// Raises ``ValueError`` if key is not found.
    fn prove_existence<'py>(&self, py: Python<'py>, key: &[u8]) -> PyResult<PyObject> {
        if key.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "Key must be 32 bytes, got {}",
                key.len()
            )));
        }
        let key32: [u8; 32] = key.try_into().unwrap();
        let state = self.state.read().map_err(lock_err)?;

        let value_hash = state
            .leaves
            .get(&key32)
            .ok_or_else(|| PyValueError::new_err("Key does not exist in tree"))?;

        let path = key_to_path_bits(&key32);
        let siblings = self.collect_siblings(&state, &path);
        let root = state
            .nodes
            .get(&Vec::<u8>::new())
            .copied()
            .unwrap_or(self.empty_hashes[256]);

        let py_vh = PyBytes::new(py, value_hash);
        let py_sibs = PyList::new(
            py,
            siblings.iter().map(|s| PyBytes::new(py, s)),
        )?;
        let py_root = PyBytes::new(py, &root);
        Ok(PyTuple::new(py, [py_vh.as_any(), py_sibs.as_any(), py_root.as_any()])?.into())
    }

    /// Return ``(siblings, root_hash)`` for a non-existing key.
    ///
    /// Raises ``ValueError`` if key exists.
    fn prove_nonexistence<'py>(&self, py: Python<'py>, key: &[u8]) -> PyResult<PyObject> {
        if key.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "Key must be 32 bytes, got {}",
                key.len()
            )));
        }
        let key32: [u8; 32] = key.try_into().unwrap();
        let state = self.state.read().map_err(lock_err)?;

        if state.leaves.contains_key(&key32) {
            return Err(PyValueError::new_err(
                "Key exists in tree, cannot prove non-existence",
            ));
        }

        let path = key_to_path_bits(&key32);
        let siblings = self.collect_siblings(&state, &path);
        let root = state
            .nodes
            .get(&Vec::<u8>::new())
            .copied()
            .unwrap_or(self.empty_hashes[256]);

        let py_sibs = PyList::new(
            py,
            siblings.iter().map(|s| PyBytes::new(py, s)),
        )?;
        let py_root = PyBytes::new(py, &root);
        Ok(PyTuple::new(py, [py_sibs.as_any(), py_root.as_any()])?.into())
    }

    /// Compute an SMT update using only the proof-path siblings.
    ///
    /// This replaces the O(N) full-tree-load + update pattern with an O(256)
    /// path-only computation.  The siblings come from the database
    /// (``_get_proof_path`` in Python) and need not be loaded into an
    /// in-memory tree.
    ///
    /// Args:
    ///     key: 32-byte leaf key.
    ///     value_hash: 32-byte value hash.
    ///     current_siblings: list of exactly 256 × 32-byte sibling hashes,
    ///         ordered from leaf level (index 0) to root level (index 255).
    ///
    /// Returns:
    ///     A 3-tuple ``(new_root, proof_siblings, node_deltas)`` where:
    ///       - ``new_root``: 32-byte new root hash (bytes).
    ///       - ``proof_siblings``: the same 256-element list passed in.
    ///       - ``node_deltas``: list of ``(db_level, packed_index, hash)``
    ///         tuples with exactly 256 entries (db_levels 0 through 255).
    #[staticmethod]
    fn incremental_update<'py>(
        py: Python<'py>,
        key: &[u8],
        value_hash: &[u8],
        current_siblings: &Bound<'py, PyList>,
    ) -> PyResult<PyObject> {
        if key.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "key must be 32 bytes, got {}",
                key.len()
            )));
        }
        if value_hash.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "value_hash must be 32 bytes, got {}",
                value_hash.len()
            )));
        }
        if current_siblings.len() != 256 {
            return Err(PyValueError::new_err(format!(
                "current_siblings must have exactly 256 elements, got {}",
                current_siblings.len()
            )));
        }

        // Extract siblings into Vec<[u8; 32]>.
        let mut siblings = Vec::with_capacity(256);
        for (i, item) in current_siblings.iter().enumerate() {
            let sib_bytes = item.downcast::<PyBytes>().map_err(|_| {
                PyValueError::new_err(format!(
                    "current_siblings[{}] must be bytes",
                    i
                ))
            })?;
            let sib_slice = sib_bytes.as_bytes();
            if sib_slice.len() != 32 {
                return Err(PyValueError::new_err(format!(
                    "current_siblings[{}] must be 32 bytes, got {}",
                    i,
                    sib_slice.len()
                )));
            }
            let arr: [u8; 32] = sib_slice
                .try_into()
                .expect("sibling slice length already validated to be 32 bytes");
            siblings.push(arr);
        }

        let key32: [u8; 32] = key.try_into().unwrap();
        let vh32: [u8; 32] = value_hash.try_into().unwrap();

        let (new_root, deltas) = incremental_update_raw(&key32, &vh32, &siblings);

        // Build Python return tuple: (new_root, proof_siblings, node_deltas)
        let py_root = PyBytes::new(py, &new_root);

        // Return the input siblings list as-is (siblings don't change for single insert)
        let py_siblings = current_siblings.as_any();

        // Build node_deltas as a list of (db_level, packed_index, hash) tuples
        let py_deltas = PyList::empty(py);
        for (db_level, packed_index, hash) in &deltas {
            let tup = PyTuple::new(
                py,
                [
                    (*db_level).into_pyobject(py)?.into_any().as_any(),
                    PyBytes::new(py, packed_index).as_any(),
                    PyBytes::new(py, hash).as_any(),
                ],
            )?;
            py_deltas.append(tup)?;
        }

        Ok(PyTuple::new(py, [py_root.as_any(), py_siblings, py_deltas.as_any()])?.into())
    }
}

// ---------------------------------------------------------------------------
// Non-PyO3 helper methods
// ---------------------------------------------------------------------------

impl RustSparseMerkleTree {
    /// Collect 256 sibling hashes along a path (from leaf to root), matching
    /// the Python ``SparseMerkleTree._collect_siblings`` method exactly.
    fn collect_siblings(&self, state: &TreeState, path: &[u8]) -> Vec<[u8; 32]> {
        let mut siblings = Vec::with_capacity(256);
        for level in 0..256usize {
            let bit_pos = 255 - level;
            let sib_path = sibling_path(&path[..=bit_pos]);
            let sib_hash = state
                .nodes
                .get(&sib_path)
                .copied()
                .unwrap_or(self.empty_hashes[level]);
            siblings.push(sib_hash);
        }
        siblings
    }
}

// ---------------------------------------------------------------------------
// Rust-only unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn get_root_raw(tree: &RustSparseMerkleTree) -> [u8; 32] {
        let state = tree.state.read().unwrap();
        if state.nodes.is_empty() && state.leaves.is_empty() {
            tree.empty_hashes[256]
        } else {
            state
                .nodes
                .get(&Vec::<u8>::new())
                .copied()
                .unwrap_or(tree.empty_hashes[256])
        }
    }

    fn update_raw(tree: &RustSparseMerkleTree, key: &[u8; 32], value_hash: &[u8; 32]) {
        let path = key_to_path_bits(key);
        let mut state = tree.state.write().unwrap();
        state.leaves.insert(*key, *value_hash);

        let mut current_hash = crypto::compute_leaf_hash(key, value_hash);
        for level in 0..256usize {
            let bit_pos = 255 - level;
            let sib_path = sibling_path(&path[..=bit_pos]);
            let sib_hash = state
                .nodes
                .get(&sib_path)
                .copied()
                .unwrap_or(tree.empty_hashes[level]);

            let parent_hash = if path[bit_pos] == 0 {
                crypto::compute_node_hash(&current_hash, &sib_hash)
            } else {
                crypto::compute_node_hash(&sib_hash, &current_hash)
            };

            let parent_path = if bit_pos == 0 {
                Vec::new()
            } else {
                path[..bit_pos].to_vec()
            };
            state.nodes.insert(parent_path, parent_hash);
            current_hash = parent_hash;
        }
    }

    #[test]
    fn test_empty_tree_root() {
        let tree = RustSparseMerkleTree::new();
        let root = get_root_raw(&tree);
        assert_eq!(root, tree.empty_hashes[256]);
    }

    #[test]
    fn test_single_insert() {
        let tree = RustSparseMerkleTree::new();
        let key = [1u8; 32];
        let val = [2u8; 32];
        update_raw(&tree, &key, &val);
        let root = get_root_raw(&tree);
        assert_ne!(root, tree.empty_hashes[256]);
    }

    #[test]
    fn test_insert_order_independence() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let v1 = [0xAAu8; 32];
        let v2 = [0xBBu8; 32];

        let t1 = RustSparseMerkleTree::new();
        update_raw(&t1, &k1, &v1);
        update_raw(&t1, &k2, &v2);

        let t2 = RustSparseMerkleTree::new();
        update_raw(&t2, &k2, &v2);
        update_raw(&t2, &k1, &v1);

        assert_eq!(
            get_root_raw(&t1),
            get_root_raw(&t2),
            "Root must be independent of insertion order"
        );
    }

    #[test]
    fn test_update_existing_key() {
        let tree = RustSparseMerkleTree::new();
        let key = [1u8; 32];
        let v1 = [2u8; 32];
        let v2 = [3u8; 32];

        update_raw(&tree, &key, &v1);
        let r1 = get_root_raw(&tree);

        update_raw(&tree, &key, &v2);
        let r2 = get_root_raw(&tree);

        assert_ne!(r1, r2);
        assert_eq!(tree.state.read().unwrap().leaves.len(), 1);
    }

    #[test]
    fn test_key_to_path_bits_len() {
        let key = [0b10101010u8; 32];
        let bits = key_to_path_bits(&key);
        assert_eq!(bits.len(), 256);
        assert_eq!(bits[0], 1);
        assert_eq!(bits[1], 0);
        assert_eq!(bits[2], 1);
        assert_eq!(bits[3], 0);
    }

    #[test]
    fn test_precomputed_empty_hashes() {
        let eh = precompute_empty_hashes();
        assert_eq!(eh.len(), 257);
        assert_eq!(eh[0], crypto::compute_empty_leaf());
        // Level 1 = node_hash(empty_leaf, empty_leaf)
        assert_eq!(eh[1], crypto::compute_node_hash(&eh[0], &eh[0]));
    }

    // -----------------------------------------------------------------------
    // incremental_update tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_incremental_matches_full_tree_single_insert() {
        let tree = RustSparseMerkleTree::new();
        let key = [1u8; 32];
        let val = [2u8; 32];
        update_raw(&tree, &key, &val);
        let full_root = get_root_raw(&tree);

        let empty_hashes = precompute_empty_hashes();
        let empty_siblings: Vec<[u8; 32]> = (0..256).map(|i| empty_hashes[i]).collect();

        let (inc_root, _deltas) = incremental_update_raw(&key, &val, &empty_siblings);
        assert_eq!(full_root, inc_root, "Incremental root must match full-tree root");
    }

    #[test]
    fn test_incremental_matches_full_tree_second_insert() {
        let tree = RustSparseMerkleTree::new();
        let ka = [1u8; 32];
        let va = [0xAAu8; 32];
        update_raw(&tree, &ka, &va);

        // Collect siblings for key B from the full tree.
        let kb = [2u8; 32];
        let vb = [0xBBu8; 32];
        let state = tree.state.read().unwrap();
        let path_b = key_to_path_bits(&kb);
        let siblings_b = tree.collect_siblings(&state, &path_b);
        drop(state);

        // Do the full-tree insert of B.
        update_raw(&tree, &kb, &vb);
        let full_root = get_root_raw(&tree);

        // Compute incremental update for B using A's siblings.
        let (inc_root, _deltas) = incremental_update_raw(&kb, &vb, &siblings_b);
        assert_eq!(full_root, inc_root, "Incremental root must match after second insert");
    }

    #[test]
    fn test_incremental_delta_count() {
        let empty_hashes = precompute_empty_hashes();
        let empty_siblings: Vec<[u8; 32]> = (0..256).map(|i| empty_hashes[i]).collect();
        let key = [1u8; 32];
        let val = [2u8; 32];
        let (_root, deltas) = incremental_update_raw(&key, &val, &empty_siblings);
        assert_eq!(deltas.len(), 256, "Must have exactly 256 node deltas");
    }

    #[test]
    fn test_incremental_delta_root_entry() {
        let empty_hashes = precompute_empty_hashes();
        let empty_siblings: Vec<[u8; 32]> = (0..256).map(|i| empty_hashes[i]).collect();
        let key = [1u8; 32];
        let val = [2u8; 32];
        let (root, deltas) = incremental_update_raw(&key, &val, &empty_siblings);
        // The last delta should be the root (db_level=0, empty path).
        let (db_level, packed, hash) = &deltas[255];
        assert_eq!(*db_level, 0usize);
        assert!(packed.is_empty());
        assert_eq!(hash, &root);
    }

    #[test]
    fn test_pack_path_bits_empty() {
        assert!(pack_path_bits(&[]).is_empty());
    }

    #[test]
    fn test_pack_path_bits_full_key() {
        // A 256-bit path from key [1u8; 32] should pack back to the same bytes
        // (since key_to_path_bits is MSB-first and pack_path_bits is MSB-first).
        let key = [1u8; 32];
        let bits = key_to_path_bits(&key);
        let packed = pack_path_bits(&bits);
        assert_eq!(packed, key.to_vec());
    }
}
