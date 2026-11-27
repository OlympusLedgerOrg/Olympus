// SPDX-License-Identifier: Apache-2.0

//! `olympus-dataset-tree/v1`: a hoisted sparse Merkle tree over 256-bit
//! content keys, split into `2^p` partitions under a full top tree (RFC §4–5).
//!
//! ```text
//! E               = H_empty("")
//! leaf(k, c)      = H_leaf(k ‖ c)
//! node(l, r)      = H_node(l ‖ r)
//! subtree(S, pfx) = E | leaf(k, c) if S = {(k, c)} | node(subtree(S0), subtree(S1))
//! partition_root  = H_part(u8(p) ‖ u32_be(i) ‖ u64_be(count_i) ‖ subtree_i)
//! item_root       = full binary Merkle over partition roots, node H_top
//! ```

use super::domains::{h, Domain};
use super::error::{ContentError, Result};

/// The three keyed-hash domains one sparse Merkle tree uses (RFC §4). The
/// item tree and the similarity index share the construction under disjoint
/// domains, so an item proof can never be presented as an index proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TreeDomains {
    empty: Domain,
    leaf: Domain,
    node: Domain,
}

/// `E`, `H_leaf`, `H_node`: the item tree.
pub(crate) const ITEM_TREE: TreeDomains = TreeDomains {
    empty: Domain::Empty,
    leaf: Domain::Leaf,
    node: Domain::Node,
};

/// `E_s`, `H_sleaf`, `H_snode`: the similarity index.
pub(crate) const SIMILARITY_TREE: TreeDomains = TreeDomains {
    empty: Domain::SEmpty,
    leaf: Domain::SLeaf,
    node: Domain::SNode,
};

impl TreeDomains {
    pub(crate) fn empty_root(self) -> [u8; 32] {
        h(self.empty, &[])
    }

    pub(crate) fn leaf(self, key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
        h(self.leaf, &[key, value])
    }

    pub(crate) fn node(self, l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        h(self.node, &[l, r])
    }
}

/// Key bit `i`, MSB-first.
pub fn bit(key: &[u8; 32], i: usize) -> bool {
    (key[i / 8] >> (7 - (i % 8))) & 1 == 1
}

/// `E`.
pub fn empty_root() -> [u8; 32] {
    ITEM_TREE.empty_root()
}

/// `leaf(k, c)`.
pub fn leaf_hash(key: &[u8; 32], commitment: &[u8; 32]) -> [u8; 32] {
    ITEM_TREE.leaf(key, commitment)
}

/// `node(l, r)`.
pub fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    ITEM_TREE.node(l, r)
}

/// `partition_root_i`.
pub fn partition_root(p: u8, index: u32, count: u64, subtree: &[u8; 32]) -> [u8; 32] {
    h(
        Domain::Part,
        &[&[p], &index.to_be_bytes(), &count.to_be_bytes(), subtree],
    )
}

/// Top-tree node.
pub fn top_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    h(Domain::Top, &[l, r])
}

/// The partition a key belongs to: its first `p` bits.
///
/// Crate-private: it is only meaningful for `p <= 16`. Every caller works
/// with an exponent already validated: `ItemTree::build` and
/// `fold_item_path` reject `p > 16` themselves, `ItemTree::path` uses the
/// exponent its tree was built with, and the test oracle is only called from
/// tests that pass valid exponents.
pub(crate) fn partition_of(key: &[u8; 32], p: u8) -> u32 {
    (0..p as usize).fold(0u32, |acc, i| (acc << 1) | u32::from(bit(key, i)))
}

/// Where a path ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// An empty subtree.
    Empty,
    /// A hoisted leaf.
    Leaf {
        /// Its content key.
        key: [u8; 32],
        /// Its item commitment.
        commitment: [u8; 32],
    },
}

impl Terminal {
    fn hash(&self, domains: TreeDomains) -> [u8; 32] {
        match self {
            Self::Empty => domains.empty_root(),
            Self::Leaf { key, commitment } => domains.leaf(key, commitment),
        }
    }
}

/// Fold an in-subtree path whose root sits at depth `start` along `key`,
/// applying the prefix and canonical-shape rules (§4). `siblings` are
/// top-down; the caller has already bounded their number.
pub(crate) fn fold_subtree(
    domains: TreeDomains,
    key: &[u8; 32],
    start: usize,
    siblings: &[[u8; 32]],
    terminal: &Terminal,
) -> Result<[u8; 32]> {
    let d = siblings.len();
    if let Terminal::Leaf { key: k2, .. } = terminal {
        if (0..start + d).any(|i| bit(k2, i) != bit(key, i)) {
            return Err(ContentError::PrefixMismatch);
        }
    }
    if d > 0 && siblings[d - 1] == domains.empty_root() {
        // A leaf or E beside E should have been hoisted / collapsed.
        return Err(ContentError::NonCanonicalShape);
    }
    let mut acc = terminal.hash(domains);
    for lvl in (0..d).rev() {
        let sib = &siblings[lvl];
        acc = if bit(key, start + lvl) {
            domains.node(sib, &acc)
        } else {
            domains.node(&acc, sib)
        };
    }
    Ok(acc)
}

/// A path from a terminal to `item_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemPath {
    /// In-partition siblings, top-down: `siblings[0]` is beside the partition
    /// root's child, `siblings[d-1]` beside the terminal.
    pub siblings: Vec<[u8; 32]>,
    /// Where the path ends.
    pub terminal: Terminal,
    /// Item count of the key's partition (bound into `partition_root`).
    pub partition_count: u64,
    /// Top-tree siblings, bottom-up; exactly `p` of them.
    pub top_siblings: Vec<[u8; 32]>,
}

/// Fold `path` along `key`'s bits to an `item_root`, applying the prefix,
/// canonical-shape and depth rules (§4). Does not decide membership.
pub fn fold_item_path(p: u8, key: &[u8; 32], path: &ItemPath) -> Result<[u8; 32]> {
    if p > 16 {
        return Err(ContentError::BadPartitionExponent(p));
    }
    let p_us = p as usize;
    let d = path.siblings.len();
    let max = 256 - p_us;
    if d > max {
        return Err(ContentError::DepthOutOfRange { depth: d, max });
    }
    if path.top_siblings.len() != p_us {
        return Err(ContentError::TopPathLength {
            expected: p_us,
            got: path.top_siblings.len(),
        });
    }
    let mut acc = fold_subtree(ITEM_TREE, key, p_us, &path.siblings, &path.terminal)?;
    acc = partition_root(p, partition_of(key, p), path.partition_count, &acc);
    for (t, sib) in path.top_siblings.iter().enumerate() {
        acc = if bit(key, p_us - 1 - t) {
            top_hash(sib, &acc)
        } else {
            top_hash(&acc, sib)
        };
    }
    Ok(acc)
}

/// M1 core: the path proves `key` is a leaf of `item_root`; returns its
/// commitment.
pub fn verify_membership(
    p: u8,
    item_root: &[u8; 32],
    key: &[u8; 32],
    path: &ItemPath,
) -> Result<[u8; 32]> {
    if fold_item_path(p, key, path)? != *item_root {
        return Err(ContentError::RootMismatch);
    }
    match path.terminal {
        Terminal::Leaf {
            key: k2,
            commitment,
        } if k2 == *key => Ok(commitment),
        Terminal::Leaf { .. } => Err(ContentError::NotAMember("another key")),
        Terminal::Empty => Err(ContentError::NotAMember("an empty subtree")),
    }
}

/// N1: the path proves no leaf of `item_root` has `key`.
pub fn verify_non_membership(
    p: u8,
    item_root: &[u8; 32],
    key: &[u8; 32],
    path: &ItemPath,
) -> Result<()> {
    if fold_item_path(p, key, path)? != *item_root {
        return Err(ContentError::RootMismatch);
    }
    match path.terminal {
        Terminal::Leaf { key: k2, .. } if k2 == *key => Err(ContentError::IsAMember),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Node {
    Empty,
    Leaf(u32),
    Branch(u32, u32),
}

/// One hoisted subtree (a partition of the item tree, or the whole
/// similarity index).
#[derive(Debug, Clone)]
pub(crate) struct Partition {
    domains: TreeDomains,
    /// Sorted `(key, commitment)`.
    leaves: Vec<([u8; 32], [u8; 32])>,
    nodes: Vec<Node>,
    hashes: Vec<[u8; 32]>,
    root: u32,
}

impl Partition {
    /// `leaves` must be sorted by key with no duplicates.
    pub(crate) fn build(
        domains: TreeDomains,
        leaves: Vec<([u8; 32], [u8; 32])>,
        start_depth: usize,
    ) -> Self {
        let mut part = Partition {
            domains,
            leaves,
            nodes: vec![Node::Empty],
            hashes: vec![domains.empty_root()],
            root: 0,
        };
        let n = part.leaves.len();
        part.root = part.build_range(0, n, start_depth);
        part
    }

    fn push(&mut self, node: Node, hash: [u8; 32]) -> u32 {
        self.nodes.push(node);
        self.hashes.push(hash);
        u32::try_from(self.nodes.len() - 1).expect("partition exceeds u32 nodes")
    }

    fn build_range(&mut self, lo: usize, hi: usize, depth: usize) -> u32 {
        match hi - lo {
            0 => 0,
            1 => {
                let (k, c) = self.leaves[lo];
                let idx = u32::try_from(lo).expect("partition exceeds u32 leaves");
                self.push(Node::Leaf(idx), self.domains.leaf(&k, &c))
            }
            _ => {
                // Distinct keys diverge before bit 256, so depth stays < 256.
                let mid = lo + self.leaves[lo..hi].partition_point(|(k, _)| !bit(k, depth));
                let l = self.build_range(lo, mid, depth + 1);
                let r = self.build_range(mid, hi, depth + 1);
                let hash = self
                    .domains
                    .node(&self.hashes[l as usize], &self.hashes[r as usize]);
                self.push(Node::Branch(l, r), hash)
            }
        }
    }

    pub(crate) fn subtree_root(&self) -> [u8; 32] {
        self.hashes[self.root as usize]
    }

    /// In-partition siblings (top-down) and the terminal along `key`.
    pub(crate) fn walk(&self, key: &[u8; 32], start_depth: usize) -> (Vec<[u8; 32]>, Terminal) {
        let mut sibs = Vec::new();
        let mut cur = self.root;
        let mut depth = start_depth;
        loop {
            match self.nodes[cur as usize] {
                Node::Empty => return (sibs, Terminal::Empty),
                Node::Leaf(i) => {
                    let (k, c) = self.leaves[i as usize];
                    return (
                        sibs,
                        Terminal::Leaf {
                            key: k,
                            commitment: c,
                        },
                    );
                }
                Node::Branch(l, r) => {
                    let (next, sib) = if bit(key, depth) { (r, l) } else { (l, r) };
                    sibs.push(self.hashes[sib as usize]);
                    cur = next;
                    depth += 1;
                }
            }
        }
    }
}

/// A built item tree.
#[derive(Debug, Clone)]
pub struct ItemTree {
    p: u8,
    partitions: Vec<Partition>,
    /// `top[0]` = partition roots; `top[p]` = `[item_root]`.
    top: Vec<Vec<[u8; 32]>>,
}

impl ItemTree {
    /// Build from `(content_key, item_commitment)` pairs. Keys must be unique.
    pub fn build(p: u8, mut leaves: Vec<([u8; 32], [u8; 32])>) -> Result<Self> {
        if p > 16 {
            return Err(ContentError::BadPartitionExponent(p));
        }
        leaves.sort_unstable_by_key(|l| l.0);
        if leaves.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(ContentError::DuplicateKey);
        }
        let n_parts = 1usize << p;
        let mut buckets: Vec<Vec<([u8; 32], [u8; 32])>> = vec![Vec::new(); n_parts];
        for leaf in leaves {
            buckets[partition_of(&leaf.0, p) as usize].push(leaf);
        }
        let build = |b: Vec<([u8; 32], [u8; 32])>| Partition::build(ITEM_TREE, b, p as usize);
        #[cfg(feature = "parallel")]
        let partitions: Vec<Partition> = {
            use rayon::prelude::*;
            buckets.into_par_iter().map(build).collect()
        };
        #[cfg(not(feature = "parallel"))]
        let partitions: Vec<Partition> = buckets.into_iter().map(build).collect();

        let mut level: Vec<[u8; 32]> = partitions
            .iter()
            .enumerate()
            .map(|(i, part)| {
                partition_root(p, i as u32, part.leaves.len() as u64, &part.subtree_root())
            })
            .collect();
        let mut top = vec![level.clone()];
        while level.len() > 1 {
            level = level.chunks(2).map(|c| top_hash(&c[0], &c[1])).collect();
            top.push(level.clone());
        }
        Ok(Self { p, partitions, top })
    }

    /// Partition exponent.
    pub fn p(&self) -> u8 {
        self.p
    }

    /// `item_root`.
    pub fn root(&self) -> [u8; 32] {
        self.top[self.p as usize][0]
    }

    /// Number of leaves.
    pub fn len(&self) -> u64 {
        self.partitions.iter().map(|p| p.leaves.len() as u64).sum()
    }

    /// True when the tree has no leaves.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The canonical path along `key` (a membership path if `key` is a leaf,
    /// otherwise a non-membership path).
    pub fn path(&self, key: &[u8; 32]) -> ItemPath {
        let i = partition_of(key, self.p) as usize;
        let part = &self.partitions[i];
        let (siblings, terminal) = part.walk(key, self.p as usize);
        let mut top_siblings = Vec::with_capacity(self.p as usize);
        let mut idx = i;
        for level in &self.top[..self.p as usize] {
            top_siblings.push(level[idx ^ 1]);
            idx /= 2;
        }
        ItemPath {
            siblings,
            terminal,
            partition_count: part.leaves.len() as u64,
            top_siblings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_with_bits(prefix: &[bool], fill: u8) -> [u8; 32] {
        let mut k = [fill; 32];
        for (i, b) in prefix.iter().enumerate() {
            let mask = 1u8 << (7 - (i % 8));
            if *b {
                k[i / 8] |= mask;
            } else {
                k[i / 8] &= !mask;
            }
        }
        k
    }

    fn rand_keys(n: usize, seed: u64) -> Vec<([u8; 32], [u8; 32])> {
        (0..n as u64)
            .map(|i| {
                let k = *blake3::hash(&[seed.to_be_bytes(), i.to_be_bytes()].concat()).as_bytes();
                let c = *blake3::hash(&k).as_bytes();
                (k, c)
            })
            .collect()
    }

    /// RFC §4–5 written as the literal recursive definition — an oracle with
    /// no arena, no sorting tricks and no partition bucketing.
    fn oracle_root(p: u8, set: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
        fn subtree(set: &[([u8; 32], [u8; 32])], depth: usize) -> [u8; 32] {
            match set.len() {
                0 => empty_root(),
                1 => leaf_hash(&set[0].0, &set[0].1),
                _ => {
                    let s0: Vec<_> = set
                        .iter()
                        .copied()
                        .filter(|(k, _)| !bit(k, depth))
                        .collect();
                    let s1: Vec<_> = set.iter().copied().filter(|(k, _)| bit(k, depth)).collect();
                    node_hash(&subtree(&s0, depth + 1), &subtree(&s1, depth + 1))
                }
            }
        }
        let mut level: Vec<[u8; 32]> = (0..(1u32 << p))
            .map(|i| {
                let s: Vec<_> = set
                    .iter()
                    .copied()
                    .filter(|(k, _)| partition_of(k, p) == i)
                    .collect();
                partition_root(p, i, s.len() as u64, &subtree(&s, p as usize))
            })
            .collect();
        while level.len() > 1 {
            level = level.chunks(2).map(|c| top_hash(&c[0], &c[1])).collect();
        }
        level[0]
    }

    #[test]
    fn hand_computed_roots_match_the_spec() {
        // One item, p = 0: item_root = H_part(0, 0, 1, leaf(k, c)).
        let k = [0xAA; 32];
        let c = [0x11; 32];
        let t = ItemTree::build(0, vec![(k, c)]).unwrap();
        assert_eq!(t.root(), partition_root(0, 0, 1, &leaf_hash(&k, &c)));
        // Two items splitting at bit 0, p = 0: both leaves hoisted to depth 1.
        let a = key_with_bits(&[false], 0x55);
        let b = key_with_bits(&[true], 0x55);
        let t = ItemTree::build(0, vec![(b, c), (a, c)]).unwrap();
        let sub = node_hash(&leaf_hash(&a, &c), &leaf_hash(&b, &c));
        assert_eq!(t.root(), partition_root(0, 0, 2, &sub));
        // Two items sharing bit 0, splitting at bit 1: one real E-sibling level.
        let a = key_with_bits(&[false, false], 0x0F);
        let b = key_with_bits(&[false, true], 0x0F);
        let t = ItemTree::build(0, vec![(a, c), (b, c)]).unwrap();
        let inner = node_hash(&leaf_hash(&a, &c), &leaf_hash(&b, &c));
        assert_eq!(
            t.root(),
            partition_root(0, 0, 2, &node_hash(&inner, &empty_root()))
        );
        // Empty tree, p = 1: two empty partitions under one top node.
        let t = ItemTree::build(1, vec![]).unwrap();
        let e0 = partition_root(1, 0, 0, &empty_root());
        let e1 = partition_root(1, 1, 0, &empty_root());
        assert_eq!(t.root(), top_hash(&e0, &e1));
    }

    #[test]
    fn builder_matches_the_recursive_oracle() {
        for p in [0u8, 1, 3, 8] {
            for n in [0usize, 1, 2, 3, 7, 64, 300] {
                let set = rand_keys(n, (p as u64) << 32 | n as u64);
                let t = ItemTree::build(p, set.clone()).unwrap();
                assert_eq!(t.root(), oracle_root(p, &set), "p={p} n={n}");
                assert_eq!(t.len(), n as u64);
            }
        }
    }

    #[test]
    fn every_member_proves_membership_and_fails_non_membership() {
        for p in [0u8, 2, 5] {
            let set = rand_keys(200, 7 + p as u64);
            let t = ItemTree::build(p, set.clone()).unwrap();
            let root = t.root();
            for (k, c) in &set {
                let path = t.path(k);
                assert_eq!(verify_membership(p, &root, k, &path), Ok(*c));
                assert_eq!(
                    verify_non_membership(p, &root, k, &path),
                    Err(ContentError::IsAMember)
                );
            }
        }
    }

    #[test]
    fn every_non_member_proves_non_membership_and_fails_membership() {
        for p in [0u8, 2, 5] {
            let set = rand_keys(200, 11 + p as u64);
            let t = ItemTree::build(p, set).unwrap();
            let root = t.root();
            for (k, _) in rand_keys(200, 999 + p as u64) {
                let path = t.path(&k);
                assert_eq!(verify_non_membership(p, &root, &k, &path), Ok(()));
                assert!(matches!(
                    verify_membership(p, &root, &k, &path),
                    Err(ContentError::NotAMember(_))
                ));
            }
        }
    }

    #[test]
    fn prefix_check_rejects_a_leaf_presented_off_its_path() {
        // Find a non-member whose path ends at another leaf, then replace that
        // leaf with one whose key leaves the path prefix.
        let set = rand_keys(64, 3);
        let t = ItemTree::build(0, set).unwrap();
        let (q, mut path) = rand_keys(500, 4)
            .into_iter()
            .map(|(k, _)| (k, t.path(&k)))
            .find(|(_, p)| matches!(p.terminal, Terminal::Leaf { .. }) && !p.siblings.is_empty())
            .expect("some non-member path ends at a leaf");
        let Terminal::Leaf { key, commitment } = path.terminal else {
            unreachable!()
        };
        let mut off = key;
        off[0] ^= 0x80; // flips bit 0, which is on every path of depth ≥ 1
        path.terminal = Terminal::Leaf {
            key: off,
            commitment,
        };
        assert_eq!(
            verify_non_membership(0, &t.root(), &q, &path),
            Err(ContentError::PrefixMismatch)
        );
    }

    #[test]
    fn canonical_shape_rejects_an_unhoisted_leaf() {
        // A single leaf belongs at depth 0. Presenting it one level down
        // beside E folds to a different root anyway, but the shape rule must
        // reject it first, for the stated reason.
        let k = [0x00; 32];
        let c = [0x22; 32];
        let t = ItemTree::build(0, vec![(k, c)]).unwrap();
        let mut path = t.path(&k);
        path.siblings.push(empty_root());
        assert_eq!(
            verify_membership(0, &t.root(), &k, &path),
            Err(ContentError::NonCanonicalShape)
        );
    }

    #[test]
    fn depth_and_top_path_rules_are_enforced() {
        let t = ItemTree::build(2, rand_keys(10, 5)).unwrap();
        let k = [0x33; 32];
        let mut path = t.path(&k);
        path.siblings = vec![[9; 32]; 255];
        assert_eq!(
            fold_item_path(2, &k, &path),
            Err(ContentError::DepthOutOfRange {
                depth: 255,
                max: 254
            })
        );
        let mut path = t.path(&k);
        path.top_siblings.pop();
        assert_eq!(
            fold_item_path(2, &k, &path),
            Err(ContentError::TopPathLength {
                expected: 2,
                got: 1
            })
        );
    }

    #[test]
    fn partition_count_is_bound() {
        let set = rand_keys(50, 6);
        let t = ItemTree::build(3, set.clone()).unwrap();
        let mut path = t.path(&set[0].0);
        path.partition_count += 1;
        assert_eq!(
            verify_membership(3, &t.root(), &set[0].0, &path),
            Err(ContentError::RootMismatch)
        );
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let k = [1; 32];
        assert_eq!(
            ItemTree::build(0, vec![(k, [2; 32]), (k, [3; 32])]).err(),
            Some(ContentError::DuplicateKey)
        );
    }
}
