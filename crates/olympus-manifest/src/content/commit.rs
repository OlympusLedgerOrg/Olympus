// SPDX-License-Identifier: Apache-2.0

//! Item commitments, content keys and blinded provenance metadata (RFC §2–3).

use unicode_normalization::is_nfc;

use super::domains::{check_lp_len, h, lp_into, Domain, CONTENT_KEY_CONTEXT};
use super::error::{ContentError, Result};

/// `content_digest = BLAKE3(canonical_bytes)` — plain and unkeyed, so any
/// BLAKE3 tool reproduces it.
pub fn content_digest(canonical: &[u8]) -> [u8; 32] {
    *blake3::hash(canonical).as_bytes()
}

/// `content_key` (§3). Depends only on the canonicalization profile and the
/// content, never on the dataset, version or committer.
pub fn content_key(profile_id: &str, profile_version: u32, digest: &[u8; 32]) -> Result<[u8; 32]> {
    check_lp_len(profile_id.as_bytes(), "profile_id")?;
    let mut m = Vec::with_capacity(4 + profile_id.len() + 4 + 32);
    lp_into(&mut m, profile_id.as_bytes(), "profile_id")?;
    m.extend_from_slice(&profile_version.to_be_bytes());
    m.extend_from_slice(digest);
    Ok(blake3::derive_key(CONTENT_KEY_CONTEXT, &m))
}

/// Root of an empty fingerprint set, `H_fp("")`. v1 exact-only items use it.
pub fn empty_fp_set_root() -> [u8; 32] {
    h(Domain::Fp, &[])
}

/// Root of an empty metadata set, `H_meta("")`.
pub fn empty_meta_root() -> [u8; 32] {
    h(Domain::Meta, &[])
}

/// The 114-byte `item_commitment` preimage (§2). M1-open reveals it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemPreimage {
    /// Index into the version's canonicalization profile table.
    pub profile_index: u16,
    /// `len(canonical_bytes)`.
    pub canonical_len: u64,
    /// `BLAKE3(canonical_bytes)`.
    pub content_digest: [u8; 32],
    /// Fingerprint-set root (empty-set root when unfingerprinted).
    pub fp_set_root: [u8; 32],
    /// Merged occurrences, `≥ 1`.
    pub occurrence_count: u64,
    /// Metadata-set root (empty-set root when no metadata).
    pub meta_root: [u8; 32],
}

impl ItemPreimage {
    /// The exact preimage bytes.
    pub fn to_bytes(&self) -> [u8; 114] {
        let mut b = [0u8; 114];
        b[0..2].copy_from_slice(&self.profile_index.to_be_bytes());
        b[2..10].copy_from_slice(&self.canonical_len.to_be_bytes());
        b[10..42].copy_from_slice(&self.content_digest);
        b[42..74].copy_from_slice(&self.fp_set_root);
        b[74..82].copy_from_slice(&self.occurrence_count.to_be_bytes());
        b[82..114].copy_from_slice(&self.meta_root);
        b
    }

    /// `item_commitment = H_item(preimage)`.
    pub fn commitment(&self) -> [u8; 32] {
        h(Domain::Item, &[&self.to_bytes()])
    }
}

/// `opt_out_status` values (§2). Records the committer's own state, nothing
/// more (class C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptOutStatus {
    /// `0` — none recorded.
    NoneRecorded,
    /// `1` — the committer's records mark the source as opted out.
    OptedOut,
    /// `2` — the committer's records mark the source as opted in.
    OptedIn,
}

impl OptOutStatus {
    /// Wire byte.
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::NoneRecorded => 0,
            Self::OptedOut => 1,
            Self::OptedIn => 2,
        }
    }

    /// Parse a wire byte; anything outside {0, 1, 2} is rejected.
    pub fn from_u8(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Self::NoneRecorded),
            1 => Ok(Self::OptedOut),
            2 => Ok(Self::OptedIn),
            other => Err(ContentError::InvalidOptOutStatus(other)),
        }
    }
}

/// One per-occurrence provenance entry, including its blinder (§2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaEntry {
    /// 32 fresh CSPRNG bytes; secret witness material (lifecycle rules 1–6).
    pub blinding: [u8; 32],
    /// Index into the version's extraction table.
    pub extraction_index: u16,
    /// Already sanitized with `uri-sanitize/1`; NFC; may be empty.
    pub source_uri: String,
    /// License string as found; NFC; may be empty.
    pub license: String,
    /// Retrieval time, Unix seconds.
    pub retrieved_at_unix_s: u64,
    /// Raw status byte; validated by [`MetaEntry::validate`].
    pub opt_out_status: u8,
}

impl MetaEntry {
    /// Field validation every verifier applies to a disclosed entry.
    pub fn validate(&self) -> Result<()> {
        OptOutStatus::from_u8(self.opt_out_status)?;
        if !is_nfc(&self.source_uri) {
            return Err(ContentError::NotNfc("source_uri"));
        }
        if !is_nfc(&self.license) {
            return Err(ContentError::NotNfc("license"));
        }
        for (name, s) in [("source_uri", &self.source_uri), ("license", &self.license)] {
            if u32::try_from(s.len()).is_err() {
                return Err(ContentError::FieldTooLong(name));
            }
        }
        Ok(())
    }

    /// `meta_entry` bytes. Fails, before anything is hashed, if a string does
    /// not fit its `u32` length prefix.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // Both lengths are checked before the buffer is sized from them.
        check_lp_len(self.source_uri.as_bytes(), "source_uri")?;
        check_lp_len(self.license.as_bytes(), "license")?;
        let mut b =
            Vec::with_capacity(32 + 2 + 4 + self.source_uri.len() + 4 + self.license.len() + 9);
        b.extend_from_slice(&self.blinding);
        b.extend_from_slice(&self.extraction_index.to_be_bytes());
        lp_into(&mut b, self.source_uri.as_bytes(), "source_uri")?;
        lp_into(&mut b, self.license.as_bytes(), "license")?;
        b.extend_from_slice(&self.retrieved_at_unix_s.to_be_bytes());
        b.push(self.opt_out_status);
        Ok(b)
    }

    /// `meta_leaf = H_meta(meta_entry)`. Applies only the length check, so a
    /// verifier can fold a structurally sound entry and then report *which*
    /// field rule it breaks via [`MetaEntry::validate`].
    pub fn leaf(&self) -> Result<[u8; 32]> {
        Ok(h(Domain::Meta, &[&self.to_bytes()?]))
    }
}

/// A fresh blinder from the operating system CSPRNG (lifecycle rule 1).
///
/// An entropy failure, including a partial read, returns
/// [`ContentError::Entropy`] and yields no blinder, so the caller can stop the
/// build cleanly or retry.
pub fn fresh_blinding() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| ContentError::Entropy(e.to_string()))?;
    Ok(b)
}

// ---------------------------------------------------------------------------
// Binary Merkle with odd-node promotion (shared by fp and meta sets).
// ---------------------------------------------------------------------------

/// Root over `leaves` (already in position order); `empty` for zero leaves.
pub(crate) fn promoted_merkle_root(leaves: &[[u8; 32]], node: Domain, empty: [u8; 32]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty;
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => h(node, &[l, r]),
                [only] => *only,
                _ => unreachable!(),
            })
            .collect();
    }
    level[0]
}

/// For position `j` in a set of `n`, the side of each sibling bottom-up:
/// `Some(true)` = sibling on the left, `Some(false)` = on the right,
/// `None` = promoted at that level (no sibling). Derived from `(j, n)` only.
pub(crate) fn promoted_shape(mut j: u64, mut n: u64) -> Vec<Option<bool>> {
    let mut shape = Vec::new();
    while n > 1 {
        if j % 2 == 1 {
            shape.push(Some(true));
        } else if j + 1 < n {
            shape.push(Some(false));
        } else {
            shape.push(None);
        }
        j /= 2;
        n = n.div_ceil(2);
    }
    shape
}

/// Siblings for position `j` (bottom-up, promoted levels omitted),
/// recomputed from scratch. Test-only: an independent check on
/// [`MetaSet::path`], which reads cached levels.
#[cfg(test)]
pub(crate) fn promoted_path(leaves: &[[u8; 32]], j: usize, node: Domain) -> Vec<[u8; 32]> {
    let mut path = Vec::new();
    let mut level = leaves.to_vec();
    let mut idx = j;
    while level.len() > 1 {
        let sib = idx ^ 1;
        if sib < level.len() {
            path.push(level[sib]);
        }
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => h(node, &[l, r]),
                [only] => *only,
                _ => unreachable!(),
            })
            .collect();
        idx /= 2;
    }
    path
}

/// Fold `leaf` at `(j, n)` along `siblings`; the shape comes from `(j, n)`.
pub(crate) fn fold_promoted(
    leaf: [u8; 32],
    j: u64,
    n: u64,
    siblings: &[[u8; 32]],
    node: Domain,
) -> Result<[u8; 32]> {
    let shape = promoted_shape(j, n);
    let expected = shape.iter().filter(|s| s.is_some()).count();
    if expected != siblings.len() {
        return Err(ContentError::MetaPathLength {
            j,
            n,
            expected,
            got: siblings.len(),
        });
    }
    let mut acc = leaf;
    let mut sibs = siblings.iter();
    for side in shape {
        match side {
            Some(true) => acc = h(node, &[sibs.next().expect("counted"), &acc]),
            Some(false) => acc = h(node, &[&acc, sibs.next().expect("counted")]),
            None => {}
        }
    }
    Ok(acc)
}

/// A metadata set in position (strictly ascending blinder) order.
///
/// The Merkle levels are built once, so producing a disclosure for every
/// position of an item with many occurrences costs `O(n)` hashing in total,
/// not `O(n)` per disclosure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetaSet {
    entries: Vec<MetaEntry>,
    /// `levels[0]` = leaves in position order; the last level is `[root]`.
    /// Empty for an empty set.
    levels: Vec<Vec<[u8; 32]>>,
}

impl MetaSet {
    /// Sort entries into position order and build the tree. Rejects a
    /// repeated blinder and any entry that fails [`MetaEntry::validate`], so a
    /// builder can never commit an entry a verifier would refuse.
    pub fn new(mut entries: Vec<MetaEntry>) -> Result<Self> {
        entries.sort_by_key(|e| e.blinding);
        if entries.windows(2).any(|w| w[0].blinding == w[1].blinding) {
            return Err(ContentError::DuplicateBlinder);
        }
        for e in &entries {
            e.validate()?;
        }
        let leaves = entries
            .iter()
            .map(MetaEntry::leaf)
            .collect::<Result<Vec<_>>>()?;
        let levels = if leaves.is_empty() {
            Vec::new()
        } else {
            promoted_levels(leaves, Domain::MetaNode)
        };
        Ok(Self { entries, levels })
    }

    /// Entries in position order.
    pub fn entries(&self) -> &[MetaEntry] {
        &self.entries
    }

    /// `meta_root`.
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .map_or_else(empty_meta_root, |top| top[0])
    }

    /// Siblings for the entry at position `j` (bottom-up, promoted levels
    /// omitted), read from the cached levels.
    pub fn path(&self, j: usize) -> Vec<[u8; 32]> {
        let mut path = Vec::new();
        let mut idx = j;
        for level in self.levels.iter().take(self.levels.len().saturating_sub(1)) {
            if let Some(sib) = level.get(idx ^ 1) {
                path.push(*sib);
            }
            idx /= 2;
        }
        path
    }
}

/// Every level of a promoted binary Merkle tree over non-empty `leaves`.
fn promoted_levels(leaves: Vec<[u8; 32]>, node: Domain) -> Vec<Vec<[u8; 32]>> {
    let mut levels = vec![leaves];
    while levels.last().is_some_and(|l| l.len() > 1) {
        let next = levels
            .last()
            .expect("checked non-empty")
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => h(node, &[l, r]),
                [only] => *only,
                _ => unreachable!(),
            })
            .collect();
        levels.push(next);
    }
    levels
}

/// Fold a disclosed entry to a `meta_root` (the metadata half of MD1).
pub fn meta_root_from_path(
    entry: &MetaEntry,
    j: u64,
    n: u64,
    siblings: &[[u8; 32]],
) -> Result<[u8; 32]> {
    if j >= n {
        return Err(ContentError::MetaPositionOutOfRange { j, n });
    }
    // `leaf()` length-checks the entry before hashing it, so an oversized
    // field is a `FieldTooLong` error here, never a panic.
    fold_promoted(entry.leaf()?, j, n, siblings, Domain::MetaNode)
}

/// Auditor check (RFC §2 completeness): a full opened metadata set is either
/// empty or exactly `occurrence_count` entries, strictly ordered by blinder,
/// every entry valid, and it folds to the committed `meta_root`.
pub fn audit_meta_set(preimage: &ItemPreimage, entries: &[MetaEntry]) -> Result<()> {
    if entries.is_empty() {
        return if preimage.meta_root == empty_meta_root() {
            Ok(())
        } else {
            Err(ContentError::MetaRootMismatch)
        };
    }
    let got = entries.len() as u64;
    if got != preimage.occurrence_count {
        return Err(ContentError::MetaSetSize {
            expected: preimage.occurrence_count,
            got,
        });
    }
    for w in entries.windows(2) {
        match w[0].blinding.cmp(&w[1].blinding) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => return Err(ContentError::DuplicateBlinder),
            std::cmp::Ordering::Greater => return Err(ContentError::MetaOrder),
        }
    }
    for e in entries {
        e.validate()?;
    }
    let leaves = entries
        .iter()
        .map(MetaEntry::leaf)
        .collect::<Result<Vec<_>>>()?;
    if promoted_merkle_root(&leaves, Domain::MetaNode, empty_meta_root()) != preimage.meta_root {
        return Err(ContentError::MetaRootMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(b: u8, uri: &str) -> MetaEntry {
        MetaEntry {
            blinding: [b; 32],
            extraction_index: 0,
            source_uri: uri.into(),
            license: "CC-BY-4.0".into(),
            retrieved_at_unix_s: 1_700_000_000,
            opt_out_status: 0,
        }
    }

    #[test]
    fn content_key_binds_profile_id_version_and_digest() {
        let d = content_digest(b"hello");
        let k = content_key("text/utf8-nfc", 1, &d).unwrap();
        assert_ne!(
            k,
            content_key("bytes/raw", 1, &d).unwrap(),
            "profile id not bound"
        );
        assert_ne!(
            k,
            content_key("text/utf8-nfc", 2, &d).unwrap(),
            "profile version not bound"
        );
        let mut d2 = d;
        d2[31] ^= 1;
        assert_ne!(
            k,
            content_key("text/utf8-nfc", 1, &d2).unwrap(),
            "digest not bound"
        );
    }

    #[test]
    fn every_preimage_field_is_bound_into_the_commitment() {
        let base = ItemPreimage {
            profile_index: 3,
            canonical_len: 5,
            content_digest: [1; 32],
            fp_set_root: empty_fp_set_root(),
            occurrence_count: 2,
            meta_root: empty_meta_root(),
        };
        let c = base.commitment();
        let mutants = [
            (
                "profile_index",
                ItemPreimage {
                    profile_index: 4,
                    ..base
                },
            ),
            (
                "canonical_len",
                ItemPreimage {
                    canonical_len: 6,
                    ..base
                },
            ),
            (
                "content_digest",
                ItemPreimage {
                    content_digest: [2; 32],
                    ..base
                },
            ),
            (
                "fp_set_root",
                ItemPreimage {
                    fp_set_root: [3; 32],
                    ..base
                },
            ),
            (
                "occurrence_count",
                ItemPreimage {
                    occurrence_count: 3,
                    ..base
                },
            ),
            (
                "meta_root",
                ItemPreimage {
                    meta_root: [4; 32],
                    ..base
                },
            ),
        ];
        for (field, m) in mutants {
            assert_ne!(m.commitment(), c, "{field} is not bound");
        }
        // Pin the layout: 2 + 8 + 32 + 32 + 8 + 32 bytes, fields in RFC order.
        let b = base.to_bytes();
        assert_eq!(&b[0..2], &3u16.to_be_bytes());
        assert_eq!(&b[74..82], &2u64.to_be_bytes());
        assert_eq!(&b[82..114], &empty_meta_root());
    }

    #[test]
    fn empty_set_roots_differ_from_any_single_leaf() {
        // A one-element set's root is its leaf, H_meta(entry) with a non-empty
        // entry, so it can never equal H_meta("").
        let set = MetaSet::new(vec![entry(1, "")]).unwrap();
        assert_ne!(set.root(), empty_meta_root());
    }

    #[test]
    fn promoted_paths_fold_for_every_position_and_size() {
        for n in 1u64..=17 {
            let entries: Vec<_> = (0..n)
                .map(|i| entry(i as u8 + 1, &format!("u{i}")))
                .collect();
            let set = MetaSet::new(entries).unwrap();
            let root = set.root();
            for j in 0..n {
                let e = &set.entries()[j as usize];
                let p = set.path(j as usize);
                let leaves: Vec<_> = set.entries().iter().map(|e| e.leaf().unwrap()).collect();
                assert_eq!(
                    p,
                    promoted_path(&leaves, j as usize, Domain::MetaNode),
                    "cached path differs from a fresh recomputation, n={n} j={j}"
                );
                assert_eq!(
                    meta_root_from_path(e, j, n, &p).unwrap(),
                    root,
                    "n={n} j={j}"
                );
            }
        }
    }

    #[test]
    fn duplicate_blinder_is_rejected_by_the_builder() {
        assert_eq!(
            MetaSet::new(vec![entry(9, "a"), entry(9, "b")]),
            Err(ContentError::DuplicateBlinder)
        );
    }

    #[test]
    fn identical_provenance_with_distinct_blinders_stays_two_entries() {
        let set = MetaSet::new(vec![entry(1, "same"), entry(2, "same")]).unwrap();
        assert_eq!(set.entries().len(), 2);
    }
}
