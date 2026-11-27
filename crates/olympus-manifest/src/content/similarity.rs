// SPDX-License-Identifier: Apache-2.0

//! The LSH similarity index (similarity companion, "Similarity index").
//!
//! ```text
//! band_key(F, β)  = derive_key("olympus 2026-11 dataset band-key v1",
//!                              lp(fp_profile_id) ‖ u32_be(fp_profile_version) ‖ u16_be(β) ‖ band_value(F, β))
//! bucket_commit   = H_bucket(u32_be(count) ‖ for each entry:
//!                            content_key ‖ u16_be(fp_profile_index) ‖ u32_be(segment_index) ‖ fingerprint)
//! similarity_root = subtree over (band_key → bucket_commit) with E_s / H_sleaf / H_snode,
//!                   rooted at depth 0: no partitions, so no H_part or H_top wrapper
//! ```
//!
//! The index is the committer's retrieval structure. A bucket opening shows
//! what the committed index files under one band key (class B); it never
//! shows that no similar item exists. That statement, N2, stays out of v1.

use std::collections::BTreeMap;

use super::domains::{check_lp_len, lp_into, Domain, BAND_KEY_CONTEXT};
use super::error::{ContentError, Result};
use super::fingerprint::FpProfile;
use super::tree::{fold_subtree, Partition, Terminal, SIMILARITY_TREE};

/// `band_key(F, β)` for `fp` under `profile`.
pub fn band_key(profile: FpProfile, band: u16, fp: &[u8]) -> Result<[u8; 32]> {
    let value = profile.band_value(fp, band)?;
    let id = profile.id().as_bytes();
    check_lp_len(id, "fp_profile_id")?;
    let mut m = Vec::with_capacity(4 + id.len() + 4 + 2 + value.len());
    lp_into(&mut m, id, "fp_profile_id")?;
    m.extend_from_slice(&profile.version().to_be_bytes());
    m.extend_from_slice(&band.to_be_bytes());
    m.extend_from_slice(&value);
    Ok(blake3::derive_key(BAND_KEY_CONTEXT, &m))
}

/// All `b` band keys of `fp`, in band order. A querier computes these from
/// their own fingerprint; nothing is taken from the committer.
pub fn band_keys(profile: FpProfile, fp: &[u8]) -> Result<Vec<[u8; 32]>> {
    (0..profile.bands())
        .map(|b| band_key(profile, b, fp))
        .collect()
}

/// One bucket entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BucketEntry {
    /// The item's content key.
    pub content_key: [u8; 32],
    /// Fingerprint-profile index.
    pub fp_profile_index: u16,
    /// Segment index within the item.
    pub segment_index: u32,
    /// The segment fingerprint.
    pub fingerprint: Vec<u8>,
}

impl BucketEntry {
    fn sort_key(&self) -> ([u8; 32], u16, u32) {
        (self.content_key, self.fp_profile_index, self.segment_index)
    }
}

/// `bucket_commit` over entries already sorted by
/// `(content_key, fp_profile_index, segment_index)` with no repeats.
fn bucket_commit_sorted(entries: &[BucketEntry]) -> Result<[u8; 32]> {
    let count = u32::try_from(entries.len()).map_err(|_| ContentError::BucketTooLarge)?;
    let mut hasher = blake3::Hasher::new_keyed(Domain::Bucket.key());
    hasher.update(&count.to_be_bytes());
    for e in entries {
        hasher.update(&e.content_key);
        hasher.update(&e.fp_profile_index.to_be_bytes());
        hasher.update(&e.segment_index.to_be_bytes());
        hasher.update(&e.fingerprint);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Check order and uniqueness, then `bucket_commit`.
pub fn bucket_commit(entries: &[BucketEntry]) -> Result<[u8; 32]> {
    for w in entries.windows(2) {
        if w[0].sort_key() >= w[1].sort_key() {
            return Err(ContentError::InvalidProofEncoding(
                "bucket entries not strictly ordered",
            ));
        }
    }
    bucket_commit_sorted(entries)
}

/// A path from a bucket leaf (or empty subtree) to `similarity_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarityPath {
    /// Siblings, top-down from the root's children.
    pub siblings: Vec<[u8; 32]>,
    /// Where the path ends; a leaf's `commitment` is its `bucket_commit`.
    pub terminal: Terminal,
}

/// One retrieval candidate: a committed segment sharing at least one band
/// with the query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The candidate item.
    pub content_key: [u8; 32],
    /// Fingerprint-profile index.
    pub fp_profile_index: u16,
    /// Segment index.
    pub segment_index: u32,
    /// Similarity in the profile's unit (matching slots).
    pub similarity: u32,
    /// Whether it passes the profile's signed threshold.
    pub passes: bool,
}

/// The built similarity index.
#[derive(Debug, Clone)]
pub struct SimilarityIndex {
    buckets: BTreeMap<[u8; 32], Vec<BucketEntry>>,
    tree: Partition,
}

impl SimilarityIndex {
    /// Build from `(band_key, entry)` pairs in any order.
    pub fn build(pairs: impl IntoIterator<Item = ([u8; 32], BucketEntry)>) -> Result<Self> {
        let mut buckets: BTreeMap<[u8; 32], Vec<BucketEntry>> = BTreeMap::new();
        for (k, e) in pairs {
            buckets.entry(k).or_default().push(e);
        }
        let mut leaves = Vec::with_capacity(buckets.len());
        for (k, entries) in &mut buckets {
            entries.sort_by_key(BucketEntry::sort_key);
            entries.dedup_by(|a, b| a.sort_key() == b.sort_key() && a == b);
            if entries
                .windows(2)
                .any(|w| w[0].sort_key() == w[1].sort_key())
            {
                // Same position, different fingerprint: a builder bug.
                return Err(ContentError::InvalidProofEncoding(
                    "two fingerprints at one bucket position",
                ));
            }
            leaves.push((*k, bucket_commit_sorted(entries)?));
        }
        // BTreeMap iteration is already key-sorted and unique.
        let tree = Partition::build(SIMILARITY_TREE, leaves, 0);
        Ok(Self { buckets, tree })
    }

    /// `similarity_root`; `E_s` when the index is empty.
    pub fn root(&self) -> [u8; 32] {
        self.tree.subtree_root()
    }

    /// Number of distinct band keys.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// True when no band key is indexed.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// The bucket filed under `band_key`, if any.
    pub fn bucket(&self, band_key: &[u8; 32]) -> Option<&[BucketEntry]> {
        self.buckets.get(band_key).map(Vec::as_slice)
    }

    /// The canonical path along `band_key`.
    pub fn path(&self, band_key: &[u8; 32]) -> SimilarityPath {
        let (siblings, terminal) = self.tree.walk(band_key, 0);
        SimilarityPath { siblings, terminal }
    }

    /// Committer-side retrieval: every committed segment that shares a band
    /// with `query` under `fp_table[fp_profile_index]`, deduplicated and
    /// sorted by descending similarity, then by position.
    pub fn candidates(
        &self,
        profile: FpProfile,
        fp_profile_index: u16,
        query: &[u8],
    ) -> Result<Vec<Candidate>> {
        let mut seen = BTreeMap::new();
        for key in band_keys(profile, query)? {
            for e in self.bucket(&key).unwrap_or_default() {
                if e.fp_profile_index != fp_profile_index {
                    continue;
                }
                if let std::collections::btree_map::Entry::Vacant(v) = seen.entry(e.sort_key()) {
                    let similarity = profile.similarity(&e.fingerprint, query)?;
                    v.insert(Candidate {
                        content_key: e.content_key,
                        fp_profile_index: e.fp_profile_index,
                        segment_index: e.segment_index,
                        similarity,
                        passes: similarity >= profile.threshold(),
                    });
                }
            }
        }
        let mut out: Vec<Candidate> = seen.into_values().collect();
        // Stable: ties keep position order from the BTreeMap.
        out.sort_by_key(|c| std::cmp::Reverse(c.similarity));
        Ok(out)
    }
}

/// Fold a similarity path along `band_key` (prefix, canonical-shape and
/// depth rules of §4 under the similarity domains).
pub fn fold_similarity_path(band_key: &[u8; 32], path: &SimilarityPath) -> Result<[u8; 32]> {
    if path.siblings.len() > 256 {
        return Err(ContentError::DepthOutOfRange {
            depth: path.siblings.len(),
            max: 256,
        });
    }
    fold_subtree(SIMILARITY_TREE, band_key, 0, &path.siblings, &path.terminal)
}

/// Bucket opening: `entries` is exactly the bucket the committed index files
/// under `band_key`. A class B fact about the index, nothing more.
pub fn verify_bucket_opening(
    similarity_root: &[u8; 32],
    band_key: &[u8; 32],
    entries: &[BucketEntry],
    path: &SimilarityPath,
) -> Result<()> {
    if fold_similarity_path(band_key, path)? != *similarity_root {
        return Err(ContentError::RootMismatch);
    }
    match path.terminal {
        Terminal::Leaf { key, commitment } if key == *band_key => {
            if bucket_commit(entries)? == commitment {
                Ok(())
            } else {
                Err(ContentError::CommitmentMismatch)
            }
        }
        Terminal::Leaf { .. } => Err(ContentError::NotAMember("another band key")),
        Terminal::Empty => Err(ContentError::NotAMember("an empty subtree")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::domains::h;

    /// `H_bucket(u32_be(0))`. Never stored: a band key with no entries is
    /// absent from the tree.
    fn empty_bucket_commit() -> [u8; 32] {
        h(Domain::Bucket, &[&0u32.to_be_bytes()])
    }
    use crate::content::fingerprint::MINHASH_WIDTH;
    use crate::content::version::empty_similarity_root;

    fn fp(seed: u8) -> Vec<u8> {
        (0..MINHASH_WIDTH as u32)
            .map(|i| (i as u8).wrapping_mul(seed).wrapping_add(seed))
            .collect()
    }

    fn entry(k: u8, seg: u32, f: Vec<u8>) -> BucketEntry {
        BucketEntry {
            content_key: [k; 32],
            fp_profile_index: 0,
            segment_index: seg,
            fingerprint: f,
        }
    }

    fn index_of(items: &[(u8, Vec<u8>)]) -> SimilarityIndex {
        let p = FpProfile::text_minhash_120();
        SimilarityIndex::build(items.iter().flat_map(|(k, f)| {
            band_keys(p, f)
                .unwrap()
                .into_iter()
                .map(move |bk| (bk, entry(*k, 0, f.clone())))
        }))
        .unwrap()
    }

    #[test]
    fn empty_index_root_is_e_s() {
        assert_eq!(index_of(&[]).root(), empty_similarity_root());
        assert_ne!(empty_bucket_commit(), empty_similarity_root());
    }

    #[test]
    fn band_key_binds_profile_band_and_slots() {
        let p = FpProfile::text_minhash_120();
        let f = fp(3);
        let k0 = band_key(p, 0, &f).unwrap();
        assert_ne!(k0, band_key(p, 1, &f).unwrap(), "band index not bound");
        let mut g = f.clone();
        g[23] ^= 1; // last byte of slot 5, inside band 0
        assert_ne!(k0, band_key(p, 0, &g).unwrap(), "band slots not bound");
        let mut g = f.clone();
        g[24] ^= 1; // slot 6 is band 1, outside band 0
        assert_eq!(
            k0,
            band_key(p, 0, &g).unwrap(),
            "band 0 read past its slots"
        );
        // Hand-computed preimage.
        let mut m = Vec::new();
        m.extend_from_slice(&16u32.to_be_bytes());
        m.extend_from_slice(b"text/minhash-120");
        m.extend_from_slice(&1u32.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&f[..24]);
        assert_eq!(k0, blake3::derive_key(BAND_KEY_CONTEXT, &m));
        assert_eq!(
            band_key(p, 20, &f),
            Err(ContentError::InvalidFpParams("band index out of range"))
        );
    }

    #[test]
    fn bucket_commit_matches_the_definition_and_requires_order() {
        let a = entry(1, 0, fp(1));
        let b = entry(2, 0, fp(2));
        let mut m = 2u32.to_be_bytes().to_vec();
        for e in [&a, &b] {
            m.extend_from_slice(&e.content_key);
            m.extend_from_slice(&0u16.to_be_bytes());
            m.extend_from_slice(&0u32.to_be_bytes());
            m.extend_from_slice(&e.fingerprint);
        }
        assert_eq!(
            bucket_commit(&[a.clone(), b.clone()]).unwrap(),
            h(Domain::Bucket, &[&m])
        );
        assert!(bucket_commit(&[b, a.clone()]).is_err());
        assert!(bucket_commit(&[a.clone(), a]).is_err());
    }

    /// The companion's definition, literally: group by band key, sort each
    /// bucket, commit, then the recursive subtree under the similarity domains.
    fn oracle_root(items: &[(u8, Vec<u8>)]) -> [u8; 32] {
        use crate::content::tree::bit;
        let p = FpProfile::text_minhash_120();
        let mut all: Vec<([u8; 32], BucketEntry)> = Vec::new();
        for (k, f) in items {
            for bk in band_keys(p, f).unwrap() {
                all.push((bk, entry(*k, 0, f.clone())));
            }
        }
        let mut keys: Vec<[u8; 32]> = all.iter().map(|(k, _)| *k).collect();
        keys.sort();
        keys.dedup();
        let leaves: Vec<([u8; 32], [u8; 32])> = keys
            .iter()
            .map(|bk| {
                let mut b: Vec<BucketEntry> = all
                    .iter()
                    .filter(|(k, _)| k == bk)
                    .map(|(_, e)| e.clone())
                    .collect();
                b.sort();
                (*bk, bucket_commit(&b).unwrap())
            })
            .collect();
        fn sub(set: &[([u8; 32], [u8; 32])], d: usize) -> [u8; 32] {
            match set.len() {
                0 => h(Domain::SEmpty, &[]),
                1 => h(Domain::SLeaf, &[&set[0].0, &set[0].1]),
                _ => {
                    let l: Vec<_> = set.iter().copied().filter(|(k, _)| !bit(k, d)).collect();
                    let r: Vec<_> = set.iter().copied().filter(|(k, _)| bit(k, d)).collect();
                    h(Domain::SNode, &[&sub(&l, d + 1), &sub(&r, d + 1)])
                }
            }
        }
        sub(&leaves, 0)
    }

    #[test]
    fn builder_matches_the_recursive_oracle() {
        for n in [1u8, 2, 5, 17] {
            let mut items: Vec<(u8, Vec<u8>)> = (0..n).map(|i| (i, fp(i + 1))).collect();
            // Two items sharing band 0 put two entries in one bucket.
            let mut shared = fp(200);
            shared[..24].copy_from_slice(&items[0].1[..24]);
            items.push((250, shared));
            assert_eq!(index_of(&items).root(), oracle_root(&items), "n={n}");
        }
    }

    #[test]
    fn bucket_openings_verify_and_reject_for_the_stated_reason() {
        let items: Vec<(u8, Vec<u8>)> = (0..6).map(|i| (i, fp(i + 1))).collect();
        let idx = index_of(&items);
        let root = idx.root();
        let p = FpProfile::text_minhash_120();
        let bk = band_key(p, 3, &items[2].1).unwrap();
        let bucket = idx.bucket(&bk).unwrap().to_vec();
        let path = idx.path(&bk);
        assert_eq!(verify_bucket_opening(&root, &bk, &bucket, &path), Ok(()));

        // An item proof's tree domains cannot stand in for the index's.
        assert_ne!(crate::content::tree::empty_root(), empty_similarity_root());
        // Hiding an extra entry in the bucket changes the commitment.
        let mut extra = bucket.clone();
        extra.push(entry(99, 0, fp(99)));
        assert_eq!(
            verify_bucket_opening(&root, &bk, &extra, &path),
            Err(ContentError::CommitmentMismatch)
        );
        // An absent band key is not a bucket.
        let absent = [0x5A; 32];
        assert!(matches!(
            verify_bucket_opening(&root, &absent, &[], &idx.path(&absent)),
            Err(ContentError::NotAMember(_))
        ));
        // A tampered sibling no longer folds.
        let mut bad = path.clone();
        if let Some(s) = bad.siblings.first_mut() {
            s[0] ^= 1;
            assert_eq!(
                verify_bucket_opening(&root, &bk, &bucket, &bad),
                Err(ContentError::RootMismatch)
            );
        }
    }

    #[test]
    fn candidates_find_band_sharers_and_report_threshold() {
        let p = FpProfile::text_minhash_120();
        let a = fp(1);
        let mut near = a.clone();
        near[100] ^= 1; // one slot differs: 119 matching
        let items = vec![(1u8, a.clone()), (2u8, fp(77))];
        let idx = index_of(&items);
        let c = idx.candidates(p, 0, &near).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].content_key, [1; 32]);
        assert_eq!(c[0].similarity, 119);
        assert!(c[0].passes);
        // Another profile index never matches entries filed under index 0.
        assert!(idx.candidates(p, 1, &near).unwrap().is_empty());
    }
}
