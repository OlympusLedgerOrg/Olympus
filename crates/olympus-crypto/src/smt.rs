//! Sparse Merkle Forest — per-shard 256-height sparse Merkle trees with
//! existence / non-existence proofs and standalone verification.
//!
//! Pure-Rust port of the reference `protocol/ssmf.py`, using this crate's
//! raw-byte [`crate::node_hash`] / [`crate::empty_leaf`] (so roots and proofs
//! are byte-identical to the cross-implementation reference, not the hex-string
//! binary tree).
//!
//! **Shard binding:** each tree is scoped to a `shard_id`, which is bound into
//! the leaf-hash domain (`OLY:LEAF:V1 | shard_id | key | value_hash | …`). A
//! present leaf proven in one shard can therefore never verify against another
//! shard's root — the "forest" is shard-separated at the leaf. Empty leaves are
//! shard-agnostic (absence is anchored by the shard's signed root, not the leaf).
//!
//! The tree (`SparseMerkleTree`) builds and proves; the free functions
//! [`verify_existence_proof`] / [`verify_nonexistence_proof`] / [`verify_proof`]
//! reconstruct the root from a proof and are what a relying party runs. As in
//! the reference, `prove` treats non-existence as a valid response, not an error.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{empty_leaf, node_hash, LEAF_PREFIX, SEP};

/// Fixed tree height: keys are 32 bytes → 256-bit paths.
pub const SMT_DEPTH: usize = 256;

// ── shard-scoped leaf hash ──────────────────────────────────────────────────

/// Leaf hash with the shard id bound into the domain prefix.
///
/// `BLAKE3(LEAF_PREFIX | "|" | len(shard_id)||shard_id | "|" | key | "|" |
///         value_hash | "|" | len(parser_id)||parser_id | "|" |
///         len(cpv)||cpv)`
///
/// `shard_id`, `parser_id`, `canonical_parser_version` are length-prefixed
/// (variable width); `key` and `value_hash` are fixed 32 bytes.
fn shard_leaf_hash(
    shard_id: &str,
    key: &[u8; 32],
    value_hash: &[u8; 32],
    parser_id: &[u8],
    canonical_parser_version: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(LEAF_PREFIX);
    h.update(SEP);
    h.update(&(shard_id.len() as u32).to_be_bytes());
    h.update(shard_id.as_bytes());
    h.update(SEP);
    h.update(key);
    h.update(SEP);
    h.update(value_hash);
    h.update(SEP);
    h.update(&(parser_id.len() as u32).to_be_bytes());
    h.update(parser_id);
    h.update(SEP);
    h.update(&(canonical_parser_version.len() as u32).to_be_bytes());
    h.update(canonical_parser_version);
    *h.finalize().as_bytes()
}

// ── path helpers ──────────────────────────────────────────────────────────────

fn key_to_path_bits(key: &[u8; 32]) -> Vec<u8> {
    let mut path = Vec::with_capacity(SMT_DEPTH);
    for byte in key {
        for i in 0..8u8 {
            path.push((byte >> (7 - i)) & 1);
        }
    }
    path
}

fn path_to_key(path: &[u8]) -> [u8; 32] {
    debug_assert_eq!(path.len(), SMT_DEPTH, "path must be exactly 256 bits");
    let mut out = [0u8; 32];
    for (idx, &bit) in path.iter().enumerate() {
        if bit != 0 {
            out[idx / 8] |= 1 << (7 - (idx % 8));
        }
    }
    out
}

fn sibling_path(path: &[u8]) -> Vec<u8> {
    let mut sib = path.to_vec();
    let last = sib.len() - 1;
    sib[last] = 1 - sib[last];
    sib
}

/// `empty[i]` = hash of an empty subtree at height `i` (257 entries, `0..=256`).
fn precompute_empty_hashes() -> Vec<[u8; 32]> {
    let mut empty = Vec::with_capacity(SMT_DEPTH + 1);
    empty.push(empty_leaf());
    for _ in 0..SMT_DEPTH {
        let last = *empty.last().unwrap();
        empty.push(node_hash(&last, &last));
    }
    empty
}

// ── proof types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExistenceProof {
    pub shard_id: String,
    pub key: [u8; 32],
    pub value_hash: [u8; 32],
    pub parser_id: String,
    pub canonical_parser_version: String,
    /// Sibling hashes leaf→root (exactly 256).
    pub siblings: Vec<[u8; 32]>,
    pub root_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonExistenceProof {
    pub key: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub root_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Proof {
    Existence(ExistenceProof),
    NonExistence(NonExistenceProof),
}

// ── tree ────────────────────────────────────────────────────────────────────────

/// A shard-scoped 256-height sparse Merkle tree. Append-only; versioning is
/// folded into the key derivation upstream (see `record_key`).
pub struct SparseMerkleTree {
    shard_id: String,
    /// Internal nodes keyed by path-bit prefix; root is at `vec![]`.
    nodes: HashMap<Vec<u8>, [u8; 32]>,
    /// Leaf storage: key → (value_hash, parser_id, canonical_parser_version).
    leaves: HashMap<[u8; 32], ([u8; 32], String, String)>,
    empty: Vec<[u8; 32]>,
}

impl SparseMerkleTree {
    /// Create an empty tree scoped to `shard_id`.
    pub fn new(shard_id: &str) -> Self {
        Self {
            shard_id: shard_id.to_string(),
            nodes: HashMap::new(),
            leaves: HashMap::new(),
            empty: precompute_empty_hashes(),
        }
    }

    pub fn shard_id(&self) -> &str {
        &self.shard_id
    }

    /// The 32-byte root hash (the empty-tree root when no leaves are present).
    pub fn root(&self) -> [u8; 32] {
        if self.nodes.is_empty() && self.leaves.is_empty() {
            return self.empty[SMT_DEPTH];
        }
        self.nodes.get(&Vec::<u8>::new()).copied().unwrap_or(self.empty[SMT_DEPTH])
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.leaves.get(key).map(|(v, _, _)| *v)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Insert or update a leaf. `parser_id` / `canonical_parser_version` are
    /// bound into the leaf hash domain (ADR-0003) and must be non-empty.
    pub fn update(
        &mut self,
        key: [u8; 32],
        value_hash: [u8; 32],
        parser_id: &str,
        canonical_parser_version: &str,
    ) {
        assert!(!parser_id.is_empty(), "parser_id must be non-empty");
        assert!(
            !canonical_parser_version.is_empty(),
            "canonical_parser_version must be non-empty"
        );

        let path = key_to_path_bits(&key);
        self.leaves.insert(
            key,
            (value_hash, parser_id.to_string(), canonical_parser_version.to_string()),
        );

        let mut current = shard_leaf_hash(
            &self.shard_id,
            &key,
            &value_hash,
            parser_id.as_bytes(),
            canonical_parser_version.as_bytes(),
        );

        for level in 0..SMT_DEPTH {
            let bit_pos = SMT_DEPTH - 1 - level;
            let sib_path = sibling_path(&path[..=bit_pos]);
            let sib = self.resolve_sibling(&sib_path, level);

            current = if path[bit_pos] == 0 {
                node_hash(&current, &sib)
            } else {
                node_hash(&sib, &current)
            };

            let parent_path = if bit_pos == 0 { Vec::new() } else { path[..bit_pos].to_vec() };
            self.nodes.insert(parent_path, current);
        }
    }

    /// Resolve the hash at `sibling_path`. Internal nodes live in `nodes`;
    /// leaf-level siblings (path length 256) are looked up in `leaves` and
    /// hashed on demand — without this an adjacent leaf sibling would wrongly
    /// fall through to the empty hash and corrupt proofs.
    fn resolve_sibling(&self, sibling_path: &[u8], level: usize) -> [u8; 32] {
        if let Some(&h) = self.nodes.get(sibling_path) {
            return h;
        }
        if sibling_path.len() == SMT_DEPTH {
            let sib_key = path_to_key(sibling_path);
            if let Some((value_hash, parser_id, cpv)) = self.leaves.get(&sib_key) {
                return shard_leaf_hash(
                    &self.shard_id,
                    &sib_key,
                    value_hash,
                    parser_id.as_bytes(),
                    cpv.as_bytes(),
                );
            }
        }
        self.empty[level]
    }

    fn collect_siblings(&self, path: &[u8]) -> Vec<[u8; 32]> {
        let mut siblings = Vec::with_capacity(SMT_DEPTH);
        for level in 0..SMT_DEPTH {
            let bit_pos = SMT_DEPTH - 1 - level;
            let sib_path = sibling_path(&path[..=bit_pos]);
            siblings.push(self.resolve_sibling(&sib_path, level));
        }
        siblings
    }

    /// Unified proof: existence if present, else non-existence (never errors).
    pub fn prove(&self, key: &[u8; 32]) -> Proof {
        let path = key_to_path_bits(key);
        let siblings = self.collect_siblings(&path);
        let root_hash = self.root();
        match self.leaves.get(key) {
            Some((value_hash, parser_id, cpv)) => Proof::Existence(ExistenceProof {
                shard_id: self.shard_id.clone(),
                key: *key,
                value_hash: *value_hash,
                parser_id: parser_id.clone(),
                canonical_parser_version: cpv.clone(),
                siblings,
                root_hash,
            }),
            None => Proof::NonExistence(NonExistenceProof { key: *key, siblings, root_hash }),
        }
    }
}

// ── verification (relying-party side) ────────────────────────────────────────

/// Fold a 256-sibling path from `start` up to a root, branching by key bits.
fn fold_to_root(key: &[u8; 32], start: [u8; 32], siblings: &[[u8; 32]]) -> [u8; 32] {
    let path = key_to_path_bits(key);
    let mut current = start;
    for (level, sib) in siblings.iter().enumerate().take(SMT_DEPTH) {
        let bit_pos = SMT_DEPTH - 1 - level;
        current = if path[bit_pos] == 0 {
            node_hash(&current, sib)
        } else {
            node_hash(sib, &current)
        };
    }
    current
}

/// Verify an existence proof. The shard id carried in the proof is bound into
/// the recomputed leaf hash, so a proof only verifies against the root of the
/// shard it was issued for. When `expected_root` is `Some`, the proof's root
/// must equal it first — pass a root from a signed shard header so the proof is
/// anchored to an authenticated root.
pub fn verify_existence_proof(proof: &ExistenceProof, expected_root: Option<&[u8; 32]>) -> bool {
    if let Some(r) = expected_root {
        if &proof.root_hash != r {
            return false;
        }
    }
    if proof.parser_id.is_empty()
        || proof.canonical_parser_version.is_empty()
        || proof.siblings.len() != SMT_DEPTH
    {
        return false;
    }
    let start = shard_leaf_hash(
        &proof.shard_id,
        &proof.key,
        &proof.value_hash,
        proof.parser_id.as_bytes(),
        proof.canonical_parser_version.as_bytes(),
    );
    fold_to_root(&proof.key, start, &proof.siblings) == proof.root_hash
}

/// Verify a non-existence proof: the leaf at the key position is the
/// domain-separated empty sentinel, and the sibling chain reconstructs the root.
///
/// Verifies mathematical consistency only — callers MUST also confirm
/// `proof.root_hash` is an authenticated shard root (pass it as `expected_root`).
pub fn verify_nonexistence_proof(
    proof: &NonExistenceProof,
    expected_root: Option<&[u8; 32]>,
) -> bool {
    if let Some(r) = expected_root {
        if &proof.root_hash != r {
            return false;
        }
    }
    if proof.siblings.len() != SMT_DEPTH {
        return false;
    }
    fold_to_root(&proof.key, empty_leaf(), &proof.siblings) == proof.root_hash
}

/// Verify either proof kind.
pub fn verify_proof(proof: &Proof, expected_root: Option<&[u8; 32]>) -> bool {
    match proof {
        Proof::Existence(p) => verify_existence_proof(p, expected_root),
        Proof::NonExistence(p) => verify_nonexistence_proof(p, expected_root),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn empty_root_is_top_empty_hash() {
        let t = SparseMerkleTree::new("shard-a");
        assert_eq!(t.root(), precompute_empty_hashes()[SMT_DEPTH]);
    }

    #[test]
    fn existence_roundtrip_verifies() {
        let mut t = SparseMerkleTree::new("shard-a");
        t.update(k(1), k(0xAA), "docling@2.3.1", "v1");
        t.update(k(2), k(0xBB), "docling@2.3.1", "v1");
        let root = t.root();
        for key in [k(1), k(2)] {
            match t.prove(&key) {
                Proof::Existence(p) => {
                    assert!(verify_existence_proof(&p, Some(&root)));
                    assert!(verify_proof(&Proof::Existence(p), Some(&root)));
                }
                _ => panic!("expected existence proof for present key"),
            }
        }
    }

    #[test]
    fn nonexistence_verifies() {
        let mut t = SparseMerkleTree::new("shard-a");
        t.update(k(1), k(0xAA), "docling@2.3.1", "v1");
        let root = t.root();
        match t.prove(&k(9)) {
            Proof::NonExistence(p) => assert!(verify_nonexistence_proof(&p, Some(&root))),
            _ => panic!("expected non-existence proof for absent key"),
        }
    }

    #[test]
    fn shard_binding_separates_trees() {
        // The same (key, value, parser) in two different shards must produce
        // different roots, and a proof from one shard must not verify against
        // the other's root.
        let mut a = SparseMerkleTree::new("shard-a");
        let mut b = SparseMerkleTree::new("shard-b");
        a.update(k(1), k(0xAA), "p", "v1");
        b.update(k(1), k(0xAA), "p", "v1");
        assert_ne!(a.root(), b.root(), "shard id must change the root");

        let Proof::Existence(pa) = a.prove(&k(1)) else { panic!() };
        assert!(verify_existence_proof(&pa, Some(&a.root())));
        // Same proof must fail against shard-b's root.
        assert!(!verify_existence_proof(&pa, Some(&b.root())));
    }

    #[test]
    fn order_independent_root() {
        let mut a = SparseMerkleTree::new("s");
        a.update(k(1), k(0xAA), "p", "v1");
        a.update(k(2), k(0xBB), "p", "v1");
        let mut b = SparseMerkleTree::new("s");
        b.update(k(2), k(0xBB), "p", "v1");
        b.update(k(1), k(0xAA), "p", "v1");
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn adjacent_leaf_siblings_resolve() {
        // Two keys differing only in the last bit are direct leaf-level
        // siblings; each proof must carry the other's leaf hash, not empty.
        let left = [0u8; 32];
        let mut right = [0u8; 32];
        right[31] = 1;
        let mut t = SparseMerkleTree::new("s");
        t.update(left, k(0x11), "p", "v1");
        t.update(right, k(0x22), "p", "v1");
        let root = t.root();
        for key in [left, right] {
            match t.prove(&key) {
                Proof::Existence(p) => {
                    assert!(verify_existence_proof(&p, Some(&root)), "adjacent-leaf proof must verify")
                }
                _ => panic!("expected existence proof"),
            }
        }
    }

    #[test]
    fn tampered_proof_fails() {
        let mut t = SparseMerkleTree::new("s");
        t.update(k(1), k(0xAA), "p", "v1");
        t.update(k(2), k(0xBB), "p", "v1");
        let root = t.root();
        let Proof::Existence(mut p) = t.prove(&k(1)) else { panic!() };
        let mut bad = p.clone();
        bad.value_hash = k(0xCC);
        assert!(!verify_existence_proof(&bad, Some(&root)));
        let mut bad_shard = p.clone();
        bad_shard.shard_id = "other".to_string();
        assert!(!verify_existence_proof(&bad_shard, Some(&root)));
        assert!(!verify_existence_proof(&p, Some(&k(0xFF))));
        p.siblings.pop();
        assert!(!verify_existence_proof(&p, Some(&root)));
    }
}
