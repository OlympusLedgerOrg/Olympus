//! Constant-depth hierarchical Sparse Merkle Tree (single global tree).
//!
//! Pure-Rust port/evolution of `protocol/ssmf.py`. A single 256-height sparse
//! Merkle tree holds every record; the **shard is a literal 64-bit prefix of
//! the key**:
//!
//! ```text
//!   tree_key = H("OLY:SHARD-PREFIX:V1" || shard_id)[..8]  ||  record_key[..24]
//!              \________ 64-bit shard prefix _________/     \__ 192-bit suffix __/
//! ```
//!
//! Consequences:
//! - **One global root** commits the whole ledger — a single value to sign,
//!   anchor, gossip, and verify.
//! - **Per-shard subtree root** is the internal node at depth 64 along a shard's
//!   prefix (`shard_subtree_root`), so per-shard audits/proofs still work.
//! - Records in different shards occupy disjoint key regions, so the same
//!   `record_key` in two shards can never collide.
//! - Leaves use this crate's **canonical** [`crate::leaf_hash`] — identical to
//!   the offline verifiers. The shard appears in two places: as the 64-bit key
//!   prefix (above), and — since ADR-0005 — as the full `shard_id` bound into
//!   the leaf domain prefix, so each leaf is shard-domain-separated explicitly,
//!   not only via the truncated key prefix.
//!
//! The tree builds and proves; the free functions
//! [`verify_existence_proof`] / [`verify_nonexistence_proof`] / [`verify_proof`]
//! reconstruct the root from a proof and are what a relying party runs.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::{empty_leaf, leaf_hash, node_hash};

/// Fixed tree height: keys are 32 bytes → 256-bit paths.
pub const SMT_DEPTH: usize = 256;
/// Width of the shard prefix in bytes (64 bits).
pub const SHARD_PREFIX_BYTES: usize = 8;
/// Depth (from the root) of a shard's subtree root node.
pub const SHARD_PREFIX_BITS: usize = SHARD_PREFIX_BYTES * 8;

const SHARD_PREFIX_DOMAIN: &[u8] = b"OLY:SHARD-PREFIX:V1";

// ── key derivation ──────────────────────────────────────────────────────────

/// The 64-bit shard prefix = first 8 bytes of `BLAKE3(domain || shard_id)`.
pub fn shard_prefix(shard_id: &str) -> [u8; SHARD_PREFIX_BYTES] {
    let mut h = blake3::Hasher::new();
    h.update(SHARD_PREFIX_DOMAIN);
    h.update(shard_id.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; SHARD_PREFIX_BYTES];
    out.copy_from_slice(&digest.as_bytes()[..SHARD_PREFIX_BYTES]);
    out
}

/// Build the 32-byte tree key: 64-bit shard prefix ‖ low 192 bits of `record_key`.
pub fn shard_record_key(shard_id: &str, record_key: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..SHARD_PREFIX_BYTES].copy_from_slice(&shard_prefix(shard_id));
    key[SHARD_PREFIX_BYTES..].copy_from_slice(&record_key[..32 - SHARD_PREFIX_BYTES]);
    key
}

/// Whether `key`'s high 64 bits are `shard_prefix(shard_id)` (ADR-0005).
///
/// The leaf binds the full `shard_id` in its domain prefix, while the tree key
/// carries only the 64-bit `shard_prefix(shard_id)` as its addressing
/// projection. This predicate is the authority link between the two: the SMT
/// refuses to insert, and `verify_existence_proof` refuses to accept, a leaf
/// whose `shard_id` does not hash to its key prefix — so the in-leaf shard is
/// the authoritative partition tag, not a free-floating label.
pub fn shard_id_matches_key(shard_id: &str, key: &[u8; 32]) -> bool {
    key[..SHARD_PREFIX_BYTES] == shard_prefix(shard_id)
}

// ── path helpers ──────────────────────────────────────────────────────────────

/// Expand a 32-byte key into its 256-bit path (one byte per bit, MSB first).
/// Exposed for persistent/batched tree backends that address nodes by bit-path
/// and must derive paths identically to the in-memory tree.
pub fn key_to_path_bits(key: &[u8; 32]) -> Vec<u8> {
    let mut path = Vec::with_capacity(SMT_DEPTH);
    for byte in key {
        for i in 0..8u8 {
            path.push((byte >> (7 - i)) & 1);
        }
    }
    path
}

/// Pack a 256-bit path (one byte per bit, MSB first) back into a 32-byte key.
pub fn path_to_key(path: &[u8]) -> [u8; 32] {
    debug_assert_eq!(path.len(), SMT_DEPTH, "path must be exactly 256 bits");
    let mut out = [0u8; 32];
    for (idx, &bit) in path.iter().enumerate() {
        if bit != 0 {
            out[idx / 8] |= 1 << (7 - (idx % 8));
        }
    }
    out
}

/// The sibling of `path`: the same bit-path with its final bit flipped.
pub fn sibling_path(path: &[u8]) -> Vec<u8> {
    let mut sib = path.to_vec();
    let last = sib.len() - 1;
    sib[last] = 1 - sib[last];
    sib
}

/// Hash of a completely-empty subtree of height `height` (`0..=SMT_DEPTH`).
///
/// `empty_subtree_hash(0)` is the domain-separated empty-leaf sentinel and
/// `empty_subtree_hash(SMT_DEPTH)` is the empty-tree root. A node stored at
/// depth `d` covers a subtree of height `SMT_DEPTH - d`, so a persistent
/// backend fills the hash of an absent sibling at depth `d` with
/// `empty_subtree_hash(SMT_DEPTH - d)` — identical to what the in-memory tree
/// resolves for the same sparse slot.
///
/// # Panics
/// Panics if `height > SMT_DEPTH`.
pub fn empty_subtree_hash(height: usize) -> [u8; 32] {
    empty_hashes()[height]
}

/// Process-wide precomputed empty-subtree hashes (257 entries, `0..=256`),
/// computed once via `OnceLock` and shared by every tree and verifier.
/// `empty_hashes()[h]` = hash of a completely-empty subtree of height `h`.
fn empty_hashes() -> &'static [[u8; 32]; SMT_DEPTH + 1] {
    static TABLE: OnceLock<[[u8; 32]; SMT_DEPTH + 1]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [[0u8; 32]; SMT_DEPTH + 1];
        t[0] = empty_leaf();
        for i in 1..=SMT_DEPTH {
            t[i] = node_hash(&t[i - 1], &t[i - 1]);
        }
        t
    })
}

// ── proof types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExistenceProof {
    /// Full 32-byte tree key (shard prefix ‖ record suffix).
    pub key: [u8; 32],
    pub value_hash: [u8; 32],
    /// Shard identifier, bound into the leaf domain prefix (ADR-0005).
    pub shard_id: String,
    pub parser_id: String,
    pub canonical_parser_version: String,
    /// Parser model-artifact hash, bound into the leaf domain (ADR-0004).
    pub model_hash: String,
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

/// Stored leaf preimage fields, keyed by tree key:
/// `(value_hash, shard_id, parser_id, canonical_parser_version, model_hash)`.
type LeafEntry = ([u8; 32], String, String, String, String);

/// A single global 256-height sparse Merkle tree. Append-only; the shard is a
/// 64-bit key prefix (see [`shard_record_key`]). Build keys with
/// `shard_record_key(shard_id, record_key)` before `update`/`prove`.
pub struct SparseMerkleTree {
    nodes: HashMap<Vec<u8>, [u8; 32]>,
    leaves: HashMap<[u8; 32], LeafEntry>,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            leaves: HashMap::new(),
        }
    }

    /// Global root (empty-tree root when no leaves are present).
    pub fn root(&self) -> [u8; 32] {
        if self.nodes.is_empty() && self.leaves.is_empty() {
            return empty_hashes()[SMT_DEPTH];
        }
        self.nodes
            .get(&Vec::<u8>::new())
            .copied()
            .unwrap_or(empty_hashes()[SMT_DEPTH])
    }

    /// Per-shard subtree root: the node at depth `SHARD_PREFIX_BITS` (64) along
    /// the shard's prefix. Commits exactly the records in that shard. Returns the
    /// empty-subtree hash for that depth when the shard has no records.
    pub fn shard_subtree_root(&self, shard_id: &str) -> [u8; 32] {
        let prefix = shard_prefix(shard_id);
        let mut bits = Vec::with_capacity(SHARD_PREFIX_BITS);
        for byte in &prefix {
            for i in 0..8u8 {
                bits.push((byte >> (7 - i)) & 1);
            }
        }
        self.nodes
            .get(&bits)
            .copied()
            .unwrap_or(empty_hashes()[SMT_DEPTH - SHARD_PREFIX_BITS])
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.leaves.get(key).map(|(v, _, _, _, _)| *v)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Insert or update a leaf at `key` (build it via [`shard_record_key`]).
    /// `shard_id` (ADR-0005), `parser_id` / `canonical_parser_version`
    /// (ADR-0003) and `model_hash` (ADR-0004) are bound into the leaf hash
    /// domain and must be non-empty.
    pub fn update(
        &mut self,
        key: [u8; 32],
        value_hash: [u8; 32],
        shard_id: &str,
        parser_id: &str,
        canonical_parser_version: &str,
        model_hash: &str,
    ) {
        assert!(!shard_id.is_empty(), "shard_id must be non-empty");
        assert!(
            shard_id_matches_key(shard_id, &key),
            "shard_id must hash to the key's 64-bit prefix (ADR-0005 authority); \
             build the key with shard_record_key(shard_id, record_key)"
        );
        assert!(!parser_id.is_empty(), "parser_id must be non-empty");
        assert!(
            !canonical_parser_version.is_empty(),
            "canonical_parser_version must be non-empty"
        );
        assert!(!model_hash.is_empty(), "model_hash must be non-empty");

        let path = key_to_path_bits(&key);
        self.leaves.insert(
            key,
            (
                value_hash,
                shard_id.to_string(),
                parser_id.to_string(),
                canonical_parser_version.to_string(),
                model_hash.to_string(),
            ),
        );

        let mut current = leaf_hash(
            shard_id.as_bytes(),
            &key,
            &value_hash,
            parser_id.as_bytes(),
            canonical_parser_version.as_bytes(),
            model_hash.as_bytes(),
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

            let parent_path = if bit_pos == 0 {
                Vec::new()
            } else {
                path[..bit_pos].to_vec()
            };
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
            if let Some((value_hash, shard_id, parser_id, cpv, model_hash)) =
                self.leaves.get(&sib_key)
            {
                return leaf_hash(
                    shard_id.as_bytes(),
                    &sib_key,
                    value_hash,
                    parser_id.as_bytes(),
                    cpv.as_bytes(),
                    model_hash.as_bytes(),
                );
            }
        }
        empty_hashes()[level]
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

    /// Unified proof for a tree key: existence if present, else non-existence.
    pub fn prove(&self, key: &[u8; 32]) -> Proof {
        let path = key_to_path_bits(key);
        let siblings = self.collect_siblings(&path);
        let root_hash = self.root();
        match self.leaves.get(key) {
            Some((value_hash, shard_id, parser_id, cpv, model_hash)) => {
                Proof::Existence(ExistenceProof {
                    key: *key,
                    value_hash: *value_hash,
                    shard_id: shard_id.clone(),
                    parser_id: parser_id.clone(),
                    canonical_parser_version: cpv.clone(),
                    model_hash: model_hash.clone(),
                    siblings,
                    root_hash,
                })
            }
            None => Proof::NonExistence(NonExistenceProof {
                key: *key,
                siblings,
                root_hash,
            }),
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

/// Verify an existence proof. The 64-bit shard prefix is part of `proof.key`, so
/// a proof only reconstructs the root for the shard region it belongs to. When
/// `expected_root` is `Some`, the proof root must equal it first — pass a root
/// from a signed checkpoint so the proof is anchored to an authenticated root.
pub fn verify_existence_proof(proof: &ExistenceProof, expected_root: Option<&[u8; 32]>) -> bool {
    if let Some(r) = expected_root {
        if &proof.root_hash != r {
            return false;
        }
    }
    if proof.shard_id.is_empty()
        || proof.parser_id.is_empty()
        || proof.canonical_parser_version.is_empty()
        || proof.model_hash.is_empty()
        || proof.siblings.len() != SMT_DEPTH
    {
        return false;
    }
    // ADR-0005 authority: the in-leaf shard_id must hash to the key's 64-bit
    // prefix, so a proof can't claim a shard that disagrees with the partition
    // its key actually addresses.
    if !shard_id_matches_key(&proof.shard_id, &proof.key) {
        return false;
    }
    let start = leaf_hash(
        proof.shard_id.as_bytes(),
        &proof.key,
        &proof.value_hash,
        proof.parser_id.as_bytes(),
        proof.canonical_parser_version.as_bytes(),
        proof.model_hash.as_bytes(),
    );
    fold_to_root(&proof.key, start, &proof.siblings) == proof.root_hash
}

/// Verify a non-existence proof: the leaf at the key position is the
/// domain-separated empty sentinel and the sibling chain reconstructs the root.
/// Verifies mathematical consistency only — callers MUST also confirm
/// `proof.root_hash` is an authenticated root (pass it as `expected_root`).
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
    // Default leaf for a sparse slot is the precomputed, domain-separated empty
    // sentinel — never all-zeros — so an empty slot can't collide with a real
    // zero-valued leaf.
    fold_to_root(&proof.key, empty_hashes()[0], &proof.siblings) == proof.root_hash
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

    fn rk(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn shard_prefix_is_key_high_bits() {
        let key = shard_record_key("shard-a", &rk(0x11));
        assert_eq!(key[..SHARD_PREFIX_BYTES], shard_prefix("shard-a"));
        assert_eq!(
            key[SHARD_PREFIX_BYTES..],
            rk(0x11)[..32 - SHARD_PREFIX_BYTES]
        );
        // Different shards → different prefixes for the same record_key.
        let key_b = shard_record_key("shard-b", &rk(0x11));
        assert_ne!(key[..SHARD_PREFIX_BYTES], key_b[..SHARD_PREFIX_BYTES]);
    }

    #[test]
    fn shard_id_matches_key_links_shard_to_prefix() {
        // ADR-0005 authority predicate: true iff key[..8] == shard_prefix(shard_id).
        let key = shard_record_key("shard-a", &rk(0x55));
        assert!(shard_id_matches_key("shard-a", &key));
        assert!(!shard_id_matches_key("shard-b", &key));
    }

    #[test]
    fn verify_rejects_shard_id_not_matching_key() {
        // A proof whose shard_id doesn't hash to the key's prefix must be
        // rejected even though everything else is well-formed (ADR-0005).
        let mut t = SparseMerkleTree::new();
        let ka = shard_record_key("shard-a", &rk(1));
        t.update(ka, rk(0xAA), "shard-a", "p", "v1", "m1");
        let root = t.root();
        let Proof::Existence(p) = t.prove(&ka) else {
            panic!("expected existence proof")
        };
        assert!(verify_existence_proof(&p, Some(&root)));
        let mut mismatched = p.clone();
        mismatched.shard_id = "shard-b".to_string();
        assert!(!verify_existence_proof(&mismatched, Some(&root)));
    }

    #[test]
    fn get_returns_stored_value_or_none() {
        let mut t = SparseMerkleTree::new();
        let ka = shard_record_key("shard-a", &rk(1));
        t.update(ka, rk(0xAB), "shard-a", "p", "v1", "m1");
        // Present key returns its stored value_hash (not None, not a constant).
        assert_eq!(t.get(&ka), Some(rk(0xAB)));
        // Absent key returns None.
        assert_eq!(t.get(&shard_record_key("shard-a", &rk(2))), None);
    }

    /// Build the self-consistent existence proof for a *lone* leaf at `key`
    /// (every sibling is the empty-subtree hash for its level), folding with
    /// the field values given. Because the proof folds to its own `root_hash`,
    /// a test can hand it an empty provenance field (or a wrong sibling count)
    /// and the only reason to reject is `verify_existence_proof`'s input guard
    /// — which makes the guard observably distinct from a mutated `&&` that
    /// would fall through to the (passing) hash check.
    fn lone_leaf_proof(
        shard: &str,
        key: [u8; 32],
        value: [u8; 32],
        parser: &str,
        cpv: &str,
        model: &str,
    ) -> ExistenceProof {
        let siblings: Vec<[u8; 32]> = (0..SMT_DEPTH).map(empty_subtree_hash).collect();
        let path = key_to_path_bits(&key);
        let mut current = leaf_hash(
            shard.as_bytes(),
            &key,
            &value,
            parser.as_bytes(),
            cpv.as_bytes(),
            model.as_bytes(),
        );
        for (level, sib) in siblings.iter().enumerate() {
            let bit_pos = SMT_DEPTH - 1 - level;
            current = if path[bit_pos] == 0 {
                node_hash(&current, sib)
            } else {
                node_hash(sib, &current)
            };
        }
        ExistenceProof {
            key,
            value_hash: value,
            shard_id: shard.to_string(),
            parser_id: parser.to_string(),
            canonical_parser_version: cpv.to_string(),
            model_hash: model.to_string(),
            siblings,
            root_hash: current,
        }
    }

    #[test]
    fn verify_guards_reject_self_consistent_but_invalid_proofs() {
        // A fully-valid lone-leaf proof verifies (equals what `prove` emits).
        let k = shard_record_key("shard-a", &rk(1));
        assert!(verify_existence_proof(
            &lone_leaf_proof("shard-a", k, rk(0xAA), "p", "v1", "m1"),
            None
        ));

        // Empty parser/cpv/model: the proof still folds to its own root, so the
        // ONLY reason to reject is the empty-field guard — distinguishing the
        // `||` chain from a mutated `&&` that would fall through and accept.
        assert!(!verify_existence_proof(
            &lone_leaf_proof("shard-a", k, rk(0xAA), "", "v1", "m1"),
            None
        ));
        assert!(!verify_existence_proof(
            &lone_leaf_proof("shard-a", k, rk(0xAA), "p", "", "m1"),
            None
        ));
        assert!(!verify_existence_proof(
            &lone_leaf_proof("shard-a", k, rk(0xAA), "p", "v1", ""),
            None
        ));

        // Empty shard_id: build the key from "" so shard_id_matches_key passes
        // and the empty-shard guard is the sole discriminator.
        let k0 = shard_record_key("", &rk(1));
        assert!(!verify_existence_proof(
            &lone_leaf_proof("", k0, rk(0xAA), "p", "v1", "m1"),
            None
        ));

        // Wrong sibling count (257): fold_to_root `.take(256)`s, so it still
        // reconstructs the root — only the length guard rejects it (a 255-count
        // proof, by contrast, also fails the fold, so it can't distinguish).
        let mut extra = lone_leaf_proof("shard-a", k, rk(0xAA), "p", "v1", "m1");
        extra.siblings.push([0u8; 32]);
        assert_eq!(extra.siblings.len(), SMT_DEPTH + 1);
        assert!(!verify_existence_proof(&extra, None));
    }

    #[test]
    fn existence_roundtrip_verifies() {
        let mut t = SparseMerkleTree::new();
        let ka = shard_record_key("shard-a", &rk(1));
        let kb = shard_record_key("shard-a", &rk(2));
        t.update(ka, rk(0xAA), "shard-a", "docling@2.3.1", "v1", "m1");
        t.update(kb, rk(0xBB), "shard-a", "docling@2.3.1", "v1", "m1");
        let root = t.root();
        for key in [ka, kb] {
            match t.prove(&key) {
                Proof::Existence(p) => assert!(verify_existence_proof(&p, Some(&root))),
                _ => panic!("expected existence proof"),
            }
        }
    }

    #[test]
    fn nonexistence_verifies() {
        let mut t = SparseMerkleTree::new();
        t.update(
            shard_record_key("shard-a", &rk(1)),
            rk(0xAA),
            "shard-a",
            "p",
            "v1",
            "m1",
        );
        let root = t.root();
        let absent = shard_record_key("shard-a", &rk(9));
        match t.prove(&absent) {
            Proof::NonExistence(p) => assert!(verify_nonexistence_proof(&p, Some(&root))),
            _ => panic!("expected non-existence proof"),
        }
    }

    #[test]
    fn same_record_key_distinct_across_shards() {
        // The same record_key in two shards lands at different tree keys and
        // both are independently provable.
        let mut t = SparseMerkleTree::new();
        let ka = shard_record_key("shard-a", &rk(7));
        let kb = shard_record_key("shard-b", &rk(7));
        assert_ne!(ka, kb);
        t.update(ka, rk(0xAA), "shard-a", "p", "v1", "m1");
        t.update(kb, rk(0xBB), "shard-b", "p", "v1", "m1");
        let root = t.root();
        let Proof::Existence(pa) = t.prove(&ka) else {
            panic!()
        };
        let Proof::Existence(pb) = t.prove(&kb) else {
            panic!()
        };
        assert!(verify_existence_proof(&pa, Some(&root)));
        assert!(verify_existence_proof(&pb, Some(&root)));
        assert_ne!(pa.value_hash, pb.value_hash);
    }

    #[test]
    fn shard_subtree_root_reflects_shard_contents() {
        let mut t = SparseMerkleTree::new();
        // Empty shard → empty-subtree hash at the shard depth.
        let empty_shard = t.shard_subtree_root("shard-a");
        assert_eq!(empty_shard, empty_hashes()[SMT_DEPTH - SHARD_PREFIX_BITS]);
        // Adding a record to shard-a changes shard-a's subtree root but not
        // shard-b's (still empty).
        t.update(
            shard_record_key("shard-a", &rk(1)),
            rk(0xAA),
            "shard-a",
            "p",
            "v1",
            "m1",
        );
        assert_ne!(t.shard_subtree_root("shard-a"), empty_shard);
        assert_eq!(
            t.shard_subtree_root("shard-b"),
            empty_hashes()[SMT_DEPTH - SHARD_PREFIX_BITS]
        );
    }

    #[test]
    fn order_independent_root() {
        let mut a = SparseMerkleTree::new();
        a.update(
            shard_record_key("s", &rk(1)),
            rk(0xAA),
            "s",
            "p",
            "v1",
            "m1",
        );
        a.update(
            shard_record_key("s", &rk(2)),
            rk(0xBB),
            "s",
            "p",
            "v1",
            "m1",
        );
        let mut b = SparseMerkleTree::new();
        b.update(
            shard_record_key("s", &rk(2)),
            rk(0xBB),
            "s",
            "p",
            "v1",
            "m1",
        );
        b.update(
            shard_record_key("s", &rk(1)),
            rk(0xAA),
            "s",
            "p",
            "v1",
            "m1",
        );
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn tampering_fails() {
        let mut t = SparseMerkleTree::new();
        let ka = shard_record_key("s", &rk(1));
        t.update(ka, rk(0xAA), "s", "p", "v1", "m1");
        t.update(
            shard_record_key("s", &rk(2)),
            rk(0xBB),
            "s",
            "p",
            "v1",
            "m1",
        );
        let root = t.root();
        let Proof::Existence(mut p) = t.prove(&ka) else {
            panic!()
        };
        let mut bad = p.clone();
        bad.value_hash = rk(0xCC);
        assert!(!verify_existence_proof(&bad, Some(&root)));
        assert!(!verify_existence_proof(&p, Some(&rk(0xFF))));
        p.siblings.pop();
        assert!(!verify_existence_proof(&p, Some(&root)));
    }

    #[test]
    fn wrong_length_nonexistence_rejected() {
        let mut t = SparseMerkleTree::new();
        t.update(
            shard_record_key("s", &rk(1)),
            rk(0xAA),
            "s",
            "p",
            "v1",
            "m1",
        );
        let root = t.root();
        let Proof::NonExistence(p) = t.prove(&shard_record_key("s", &rk(9))) else {
            panic!()
        };
        assert!(verify_nonexistence_proof(&p, Some(&root)));
        let mut short = p.clone();
        short.siblings.pop();
        assert!(!verify_nonexistence_proof(&short, Some(&root)));
        let mut long = p.clone();
        long.siblings.push([0u8; 32]);
        assert!(!verify_nonexistence_proof(&long, Some(&root)));
    }
}
