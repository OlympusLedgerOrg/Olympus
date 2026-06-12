//! Path-compressed batch builder for the Olympus 256-height Sparse Merkle Tree.
//!
//! The canonical tree is [`olympus_crypto::smt::SparseMerkleTree`], but its
//! `update` materialises one node per level **per leaf** (up to 256), so an
//! in-memory build over millions of records is infeasible. For dataset manifests
//! we only need the root and on-demand membership proofs, so we build a
//! **path-compressed** tree over the leaves sorted by key:
//!
//! * exactly one [`Branch`] is stored per real branch point (`O(N)` nodes);
//! * the compressed edges between branch points are single-child runs whose
//!   off-path siblings are all the precomputed [`empty_subtree_hash`];
//! * a prefix owned by one leaf is a "ladder" folded straight from that leaf.
//!
//! The build is `O(N·log N)` (sort) plus `O(N·256)` hashing in the worst case;
//! a proof is `O(256)`. Output is **byte-identical** to the reference tree —
//! [`SmtBatch::root`] equals `SparseMerkleTree::root` and proofs verify with the
//! reference [`verify_existence_proof`] / [`verify_nonexistence_proof`]. The
//! reference tree is the parity oracle (`tests::parity_with_reference_smt`).
//!
//! [`empty_subtree_hash`]: olympus_crypto::smt::empty_subtree_hash
//! [`verify_existence_proof`]: olympus_crypto::smt::verify_existence_proof
//! [`verify_nonexistence_proof`]: olympus_crypto::smt::verify_nonexistence_proof

use olympus_crypto::node_hash;
use olympus_crypto::smt::{
    empty_subtree_hash, ExistenceProof, NonExistenceProof, Proof, SMT_DEPTH,
};

/// A leaf staged for the batch build. `leaf_hash` is precomputed once
/// ([`olympus_crypto::leaf_hash`]); the provenance strings are retained so an
/// existence proof can be reconstructed without a second pass.
#[derive(Debug, Clone)]
pub struct BatchLeaf {
    /// Full 32-byte tree key (`shard_record_key(shard_id, record_key)`).
    pub key: [u8; 32],
    /// Precomputed `olympus_crypto::leaf_hash(..)` for this leaf.
    pub leaf_hash: [u8; 32],
    /// Raw 32-byte value hash (the record's BLAKE3 content hash).
    pub value_hash: [u8; 32],
    /// Owning shard id (bound in the leaf domain, ADR-0005).
    pub shard_id: String,
    /// Parser id (ADR-0003).
    pub parser_id: String,
    /// Canonical parser version (ADR-0003).
    pub canonical_parser_version: String,
    /// Model artifact hash (ADR-0004).
    pub model_hash: String,
}

/// A child pointer in the compressed tree.
#[derive(Debug, Clone, Copy)]
enum Child {
    /// Empty subtree (only the whole-tree root when there are no leaves).
    Empty,
    /// A single leaf, by index into `leaves`.
    Leaf(u32),
    /// An internal branch, by index into `arena`.
    Branch(u32),
}

/// A real branch point: at bit `depth`, the leaves under it split into a
/// non-empty left (bit 0) and right (bit 1).
#[derive(Debug, Clone)]
struct Branch {
    depth: usize,
    left: Child,
    right: Child,
    /// Subtree hash of the left child positioned at `depth + 1`.
    left_hash: [u8; 32],
    /// Subtree hash of the right child positioned at `depth + 1`.
    right_hash: [u8; 32],
    /// Index of any leaf under this branch (its key represents the shared
    /// prefix `[.., depth)`).
    rep_leaf: u32,
}

/// A batch of leaves compiled into a path-compressed SMT.
#[derive(Debug)]
pub struct SmtBatch {
    leaves: Vec<BatchLeaf>,
    arena: Vec<Branch>,
    root_ref: Child,
    root_hash: [u8; 32],
}

/// MSB-first bit `i` (`0..256`) of a 32-byte key.
#[inline]
fn key_bit(key: &[u8; 32], i: usize) -> u8 {
    (key[i >> 3] >> (7 - (i & 7))) & 1
}

/// First bit index `>= start` where two keys differ. Panics if equal from
/// `start` (callers guarantee distinct keys).
fn first_diff_bit(a: &[u8; 32], b: &[u8; 32], start: usize) -> usize {
    for i in start..SMT_DEPTH {
        if key_bit(a, i) != key_bit(b, i) {
            return i;
        }
    }
    unreachable!("distinct keys must differ within 256 bits");
}

/// Lift a subtree hash `h` sitting at depth `from` up to depth `to` (`to <=
/// from`), filling each skipped level's sibling with the empty-subtree hash and
/// branching by `key`'s bits. `key` is any key under the node (the bits in
/// `[to, from)` are shared by all of them).
fn ladder(mut h: [u8; 32], from: usize, to: usize, key: &[u8; 32]) -> [u8; 32] {
    let mut level = from;
    while level > to {
        level -= 1;
        // The current node sits at depth `level + 1`; its empty sibling has the
        // same height (`SMT_DEPTH - (level + 1)`).
        let sib = empty_subtree_hash(SMT_DEPTH - (level + 1));
        h = if key_bit(key, level) == 0 {
            node_hash(&h, &sib)
        } else {
            node_hash(&sib, &h)
        };
    }
    h
}

impl SmtBatch {
    /// Sort `leaves` by key, reject duplicate keys, and compile the compressed
    /// tree. Errors with the index of a duplicate key.
    pub fn new(mut leaves: Vec<BatchLeaf>) -> Result<Self, usize> {
        leaves.sort_by(|a, b| a.key.cmp(&b.key));
        for i in 1..leaves.len() {
            if leaves[i].key == leaves[i - 1].key {
                return Err(i);
            }
        }
        let mut arena: Vec<Branch> = Vec::new();
        let (root_ref, root_hash) = if leaves.is_empty() {
            (Child::Empty, empty_subtree_hash(SMT_DEPTH))
        } else {
            build(&leaves, 0, leaves.len(), 0, &mut arena)
        };
        Ok(Self {
            leaves,
            arena,
            root_ref,
            root_hash,
        })
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Global SMT root.
    pub fn root(&self) -> [u8; 32] {
        self.root_hash
    }

    /// Subtree root for the node at `prefix_bits` (MSB-first bit values). Used to
    /// expose per-shard subtree roots (pass the shard's 64-bit prefix path).
    pub fn prefix_root(&self, prefix_bits: &[u8]) -> [u8; 32] {
        let plen = prefix_bits.len();
        let mut child = self.root_ref;
        let mut d = 0usize;
        loop {
            if d == plen {
                return self.child_hash_at(child, d);
            }
            match child {
                Child::Empty => return empty_subtree_hash(SMT_DEPTH - plen),
                Child::Leaf(idx) => {
                    let lk = &self.leaves[idx as usize].key;
                    for (level, &pb) in prefix_bits.iter().enumerate().take(plen).skip(d) {
                        if key_bit(lk, level) != pb {
                            return empty_subtree_hash(SMT_DEPTH - plen);
                        }
                    }
                    return ladder(self.leaves[idx as usize].leaf_hash, SMT_DEPTH, plen, lk);
                }
                Child::Branch(bidx) => {
                    let br = &self.arena[bidx as usize];
                    let rep = &self.leaves[br.rep_leaf as usize].key;
                    let stop = br.depth.min(plen);
                    for (level, &pb) in prefix_bits.iter().enumerate().take(stop).skip(d) {
                        if key_bit(rep, level) != pb {
                            return empty_subtree_hash(SMT_DEPTH - plen);
                        }
                    }
                    if plen <= br.depth {
                        let node_at_b = node_hash(&br.left_hash, &br.right_hash);
                        return ladder(node_at_b, br.depth, plen, rep);
                    }
                    child = if prefix_bits[br.depth] == 0 {
                        br.left
                    } else {
                        br.right
                    };
                    d = br.depth + 1;
                }
            }
        }
    }

    /// Subtree hash of `child` positioned at depth `d`.
    fn child_hash_at(&self, child: Child, d: usize) -> [u8; 32] {
        match child {
            Child::Empty => empty_subtree_hash(SMT_DEPTH - d),
            Child::Leaf(idx) => {
                let l = &self.leaves[idx as usize];
                ladder(l.leaf_hash, SMT_DEPTH, d, &l.key)
            }
            Child::Branch(bidx) => {
                let br = &self.arena[bidx as usize];
                let node_at_b = node_hash(&br.left_hash, &br.right_hash);
                ladder(
                    node_at_b,
                    br.depth,
                    d,
                    &self.leaves[br.rep_leaf as usize].key,
                )
            }
        }
    }

    /// Locate a leaf by exact key.
    fn find(&self, key: &[u8; 32]) -> Option<&BatchLeaf> {
        self.leaves
            .binary_search_by(|l| l.key.cmp(key))
            .ok()
            .map(|i| &self.leaves[i])
    }

    /// Build the unified existence/non-existence proof for `key`, matching the
    /// reference tree's `prove`: 256 siblings ordered leaf→root (index 0 is the
    /// deepest sibling at bit 255).
    pub fn prove(&self, key: &[u8; 32]) -> Proof {
        let siblings = self.collect_siblings(key);
        match self.find(key) {
            Some(l) => Proof::Existence(ExistenceProof {
                key: *key,
                value_hash: l.value_hash,
                shard_id: l.shard_id.clone(),
                parser_id: l.parser_id.clone(),
                canonical_parser_version: l.canonical_parser_version.clone(),
                model_hash: l.model_hash.clone(),
                siblings,
                root_hash: self.root_hash,
            }),
            None => Proof::NonExistence(NonExistenceProof {
                key: *key,
                siblings,
                root_hash: self.root_hash,
            }),
        }
    }

    /// Sibling hashes along `key`, ordered leaf→root (index 0 = bit 255). Walks
    /// the compressed tree in `O(256)`.
    fn collect_siblings(&self, key: &[u8; 32]) -> Vec<[u8; 32]> {
        // `sib[bit]` is the sibling at bit position `bit`; reversed at the end so
        // the result is deepest-first like the reference proof.
        let mut sib = vec![[0u8; 32]; SMT_DEPTH];
        let fill_empty = |sib: &mut [[u8; 32]], range: std::ops::Range<usize>| {
            for level in range {
                sib[level] = empty_subtree_hash(SMT_DEPTH - (level + 1));
            }
        };

        let mut child = self.root_ref;
        let mut d = 0usize;
        loop {
            match child {
                Child::Empty => {
                    fill_empty(&mut sib, d..SMT_DEPTH);
                    break;
                }
                Child::Leaf(idx) => {
                    let lk = &self.leaves[idx as usize].key;
                    // Find where the query diverges from this leaf (if at all).
                    let mut diverge = None;
                    for level in d..SMT_DEPTH {
                        if key_bit(lk, level) != key_bit(key, level) {
                            diverge = Some(level);
                            break;
                        }
                    }
                    match diverge {
                        None => fill_empty(&mut sib, d..SMT_DEPTH),
                        Some(g) => {
                            fill_empty(&mut sib, d..g);
                            // The leaf's subtree sits on the query's sibling side
                            // at bit g, positioned at depth g+1.
                            sib[g] =
                                ladder(self.leaves[idx as usize].leaf_hash, SMT_DEPTH, g + 1, lk);
                            fill_empty(&mut sib, (g + 1)..SMT_DEPTH);
                        }
                    }
                    break;
                }
                Child::Branch(bidx) => {
                    let br = &self.arena[bidx as usize];
                    let rep = &self.leaves[br.rep_leaf as usize].key;
                    // Does the query diverge from the branch's shared prefix
                    // within the compressed region [d, depth)?
                    let mut diverge = None;
                    for level in d..br.depth {
                        if key_bit(rep, level) != key_bit(key, level) {
                            diverge = Some(level);
                            break;
                        }
                    }
                    if let Some(g) = diverge {
                        fill_empty(&mut sib, d..g);
                        let node_at_b = node_hash(&br.left_hash, &br.right_hash);
                        sib[g] = ladder(node_at_b, br.depth, g + 1, rep);
                        fill_empty(&mut sib, (g + 1)..SMT_DEPTH);
                        break;
                    }
                    // No divergence: take the branch at `depth`.
                    fill_empty(&mut sib, d..br.depth);
                    if key_bit(key, br.depth) == 0 {
                        sib[br.depth] = br.right_hash;
                        child = br.left;
                    } else {
                        sib[br.depth] = br.left_hash;
                        child = br.right;
                    }
                    d = br.depth + 1;
                }
            }
        }
        sib.reverse();
        sib
    }
}

/// Recursively build the compressed tree for `leaves[lo..hi]` whose keys share
/// the prefix of length `depth`. Returns the child pointer and its subtree hash
/// positioned at `depth`. Requires `hi > lo`.
fn build(
    leaves: &[BatchLeaf],
    lo: usize,
    hi: usize,
    depth: usize,
    arena: &mut Vec<Branch>,
) -> (Child, [u8; 32]) {
    debug_assert!(hi > lo);
    if hi - lo == 1 {
        let l = &leaves[lo];
        return (
            Child::Leaf(lo as u32),
            ladder(l.leaf_hash, SMT_DEPTH, depth, &l.key),
        );
    }
    // First bit (>= depth) where the lowest and highest keys differ: the branch.
    let b = first_diff_bit(&leaves[lo].key, &leaves[hi - 1].key, depth);
    // Split [lo, hi) at the first key with bit b == 1 (keys are sorted).
    let mid = lo + leaves[lo..hi].partition_point(|l| key_bit(&l.key, b) == 0);
    let (left, left_hash) = build(leaves, lo, mid, b + 1, arena);
    let (right, right_hash) = build(leaves, mid, hi, b + 1, arena);
    let node_at_b = node_hash(&left_hash, &right_hash);
    let idx = arena.len() as u32;
    arena.push(Branch {
        depth: b,
        left,
        right,
        left_hash,
        right_hash,
        rep_leaf: lo as u32,
    });
    (
        Child::Branch(idx),
        ladder(node_at_b, b, depth, &leaves[lo].key),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use olympus_crypto::leaf_hash;
    use olympus_crypto::smt::{
        shard_prefix, shard_record_key, verify_existence_proof, verify_nonexistence_proof,
        SparseMerkleTree, SHARD_PREFIX_BITS,
    };

    fn mk_leaf(shard: &str, rk: [u8; 32], value: [u8; 32]) -> BatchLeaf {
        let key = shard_record_key(shard, &rk);
        let (parser_id, cpv, model_hash) = ("docling@2.3.1", "v1", "m1");
        let lh = leaf_hash(
            shard.as_bytes(),
            &key,
            &value,
            parser_id.as_bytes(),
            cpv.as_bytes(),
            model_hash.as_bytes(),
        );
        BatchLeaf {
            key,
            leaf_hash: lh,
            value_hash: value,
            shard_id: shard.to_string(),
            parser_id: parser_id.to_string(),
            canonical_parser_version: cpv.to_string(),
            model_hash: model_hash.to_string(),
        }
    }

    fn pseudo(seed: u64, salt: u8) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&seed.to_le_bytes());
        h.update(&[salt]);
        *h.finalize().as_bytes()
    }

    #[test]
    fn empty_batch_matches_reference() {
        let batch = SmtBatch::new(vec![]).unwrap();
        assert_eq!(batch.root(), SparseMerkleTree::new().root());
    }

    #[test]
    fn parity_with_reference_smt() {
        for n in [1usize, 2, 3, 7, 16, 64, 257, 1000] {
            let mut leaves = Vec::new();
            let mut reference = SparseMerkleTree::new();
            for i in 0..n {
                let shard = if i % 3 == 0 { "shard-a" } else { "shard-b" };
                let rk = pseudo(i as u64, 0);
                let value = pseudo(i as u64, 1);
                leaves.push(mk_leaf(shard, rk, value));
                reference.update(
                    shard_record_key(shard, &rk),
                    value,
                    shard,
                    "docling@2.3.1",
                    "v1",
                    "m1",
                );
            }
            let batch = SmtBatch::new(leaves.clone()).unwrap();
            let root = reference.root();
            assert_eq!(batch.root(), root, "root mismatch at n={n}");

            // Every present key: existence proof matches the reference byte-for-byte.
            for l in &leaves {
                let bp = batch.prove(&l.key);
                assert_eq!(bp, reference.prove(&l.key), "proof mismatch at n={n}");
                match bp {
                    Proof::Existence(p) => assert!(verify_existence_proof(&p, Some(&root))),
                    _ => panic!("expected existence"),
                }
            }

            // Several absent keys, incl. ones sharing prefixes with real leaves.
            for salt in [7u8, 13, 200] {
                let absent = shard_record_key("shard-a", &pseudo(99_999, salt));
                let bp = batch.prove(&absent);
                assert_eq!(bp, reference.prove(&absent), "nonexist mismatch n={n}");
                match bp {
                    Proof::NonExistence(p) => {
                        assert!(verify_nonexistence_proof(&p, Some(&root)))
                    }
                    _ => panic!("expected non-existence"),
                }
            }
        }
    }

    #[test]
    fn nonexistence_sharing_long_prefix_with_a_leaf() {
        // A query that equals a real key except in its last bit must still match
        // the reference (the divergence-at-a-leaf path).
        let mut rk = pseudo(42, 0);
        let leaf = mk_leaf("shard-a", rk, pseudo(42, 1));
        let batch = SmtBatch::new(vec![leaf.clone()]).unwrap();
        let mut reference = SparseMerkleTree::new();
        reference.update(
            leaf.key,
            leaf.value_hash,
            "shard-a",
            "docling@2.3.1",
            "v1",
            "m1",
        );

        // Flip the last bit of the *used* record-key portion (shard_record_key
        // keeps only rk[..24]) to get a key sharing a long prefix with the leaf.
        rk[23] ^= 1;
        let near = shard_record_key("shard-a", &rk);
        assert_ne!(near, leaf.key);
        assert_eq!(batch.prove(&near), reference.prove(&near));
        match batch.prove(&near) {
            Proof::NonExistence(p) => {
                assert!(verify_nonexistence_proof(&p, Some(&reference.root())))
            }
            _ => panic!("expected non-existence"),
        }
    }

    #[test]
    fn duplicate_key_rejected() {
        let l = mk_leaf("shard-a", [1u8; 32], [2u8; 32]);
        assert_eq!(SmtBatch::new(vec![l.clone(), l]).unwrap_err(), 1);
    }

    #[test]
    fn prefix_root_matches_reference_shard_subtree() {
        let mut leaves = Vec::new();
        let mut reference = SparseMerkleTree::new();
        for i in 0..40u64 {
            let shard = if i % 2 == 0 { "alpha" } else { "beta" };
            let rk = pseudo(i, 0);
            let value = pseudo(i, 1);
            leaves.push(mk_leaf(shard, rk, value));
            reference.update(
                shard_record_key(shard, &rk),
                value,
                shard,
                "docling@2.3.1",
                "v1",
                "m1",
            );
        }
        let batch = SmtBatch::new(leaves).unwrap();
        for shard in ["alpha", "beta", "gamma-empty"] {
            let prefix = shard_prefix(shard);
            let mut bits = Vec::with_capacity(SHARD_PREFIX_BITS);
            for byte in &prefix {
                for i in 0..8u8 {
                    bits.push((byte >> (7 - i)) & 1);
                }
            }
            assert_eq!(
                batch.prefix_root(&bits),
                reference.shard_subtree_root(shard),
                "shard subtree root mismatch for {shard}"
            );
        }
    }
}
