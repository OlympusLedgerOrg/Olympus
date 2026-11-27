// SPDX-License-Identifier: Apache-2.0

//! Building a dataset version and the class A / class C statements over it:
//! M1, M1-open, N1 and MD1 (RFC §2, §10).
//!
//! Header encoding, signing and the ledger commit are deliberately not here;
//! these functions verify against an `item_root` and tables the caller has
//! already taken from a verified header (and recomputed via
//! [`super::version::GlobalRootInput`]).

use std::collections::{BTreeMap, HashSet};

use super::canon::CanonProfile;
use super::commit::{
    content_digest, content_key, empty_fp_set_root, meta_root_from_path, ItemPreimage, MetaEntry,
    MetaSet,
};
use super::error::{ContentError, Result};
use super::tree::{verify_membership, verify_non_membership, ItemPath, ItemTree};
use super::version::{
    empty_similarity_root, ExtractionEntry, GlobalRootInput, ProfileEntry, TableDigests,
};

/// Result of offering one occurrence to the builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddOutcome {
    /// Committed (possibly merged into an existing leaf) under this key.
    Committed([u8; 32]),
    /// Rejected by canonicalization; counted in `rejected_count`.
    Rejected(ContentError),
}

#[derive(Debug, Clone)]
struct Pending {
    profile_index: u16,
    canonical_len: u64,
    digest: [u8; 32],
    occurrences: u64,
    meta: Vec<MetaEntry>,
}

/// Accumulates occurrences for one dataset version.
#[derive(Debug)]
pub struct DatasetBuilder {
    profiles: Vec<CanonProfile>,
    items: BTreeMap<[u8; 32], Pending>,
    blinders: HashSet<[u8; 32]>,
    rejected: u64,
}

impl DatasetBuilder {
    /// `profiles` becomes the version's canonicalization table, in order.
    ///
    /// A profile listed twice is rejected: two rows with the same
    /// `(profile_id, profile_version)` give the same content key, so the
    /// profile index committed for an item would depend on which row its
    /// first occurrence used, and the global root on add order.
    pub fn new(profiles: Vec<CanonProfile>) -> Result<Self> {
        let mut seen = HashSet::new();
        for p in &profiles {
            if !seen.insert((p.id(), p.version())) {
                return Err(ContentError::DuplicateProfile(format!(
                    "{}@{}",
                    p.id(),
                    p.version()
                )));
            }
        }
        Ok(Self {
            profiles,
            items: BTreeMap::new(),
            blinders: HashSet::new(),
            rejected: 0,
        })
    }

    /// Offer one occurrence. `meta` must already be sanitized and carry a
    /// fresh blinder; blinder reuse anywhere in the version is an error.
    pub fn add(
        &mut self,
        profile_index: u16,
        raw: &[u8],
        meta: Option<MetaEntry>,
    ) -> Result<AddOutcome> {
        let profile = *self
            .profiles
            .get(profile_index as usize)
            .ok_or(ContentError::UnknownProfile(profile_index))?;
        if let Some(m) = &meta {
            m.validate()?;
            if self.blinders.contains(&m.blinding) {
                return Err(ContentError::DuplicateBlinder);
            }
        }
        let canonical = match profile.canonicalize(raw) {
            Ok(c) => c,
            Err(e) => {
                self.rejected += 1;
                return Ok(AddOutcome::Rejected(e));
            }
        };
        let digest = content_digest(&canonical);
        let key = content_key(profile.id(), profile.version(), &digest)?;
        let entry = self.items.entry(key).or_insert(Pending {
            profile_index,
            canonical_len: canonical.len() as u64,
            digest,
            occurrences: 0,
            meta: Vec::new(),
        });
        entry.occurrences += 1;
        if let Some(m) = meta {
            self.blinders.insert(m.blinding);
            entry.meta.push(m);
        }
        Ok(AddOutcome::Committed(key))
    }

    /// Seal the version. `p` is the partition exponent; `extraction` is the
    /// version's extraction table, which every metadata entry must index.
    pub fn finish(
        self,
        dataset_id: &str,
        version: u64,
        p: u8,
        extraction: &[ExtractionEntry],
    ) -> Result<BuiltVersion> {
        let profile_table: Vec<ProfileEntry> = self
            .profiles
            .iter()
            .map(|c| ProfileEntry {
                id: c.id().into(),
                version: c.version(),
                implementation_id: c.implementation_id(),
            })
            .collect();
        let mut items = BTreeMap::new();
        let mut leaves = Vec::with_capacity(self.items.len());
        let mut occurrence_total = 0u64;
        for (key, pend) in self.items {
            let with = pend.meta.len() as u64;
            if with != 0 && with != pend.occurrences {
                return Err(ContentError::PartialMetadata {
                    with,
                    total: pend.occurrences,
                });
            }
            if let Some(m) = pend
                .meta
                .iter()
                .find(|m| m.extraction_index as usize >= extraction.len())
            {
                return Err(ContentError::UnknownExtraction(m.extraction_index));
            }
            let meta = MetaSet::new(pend.meta)?;
            let preimage = ItemPreimage {
                profile_index: pend.profile_index,
                canonical_len: pend.canonical_len,
                content_digest: pend.digest,
                fp_set_root: empty_fp_set_root(),
                occurrence_count: pend.occurrences,
                meta_root: meta.root(),
            };
            occurrence_total += pend.occurrences;
            leaves.push((key, preimage.commitment()));
            items.insert(key, (preimage, meta));
        }
        let tree = ItemTree::build(p, leaves)?;
        let root_input = GlobalRootInput {
            dataset_id: dataset_id.into(),
            version,
            p,
            item_count: tree.len(),
            occurrence_total,
            tables: TableDigests::compute(extraction, &profile_table, &[])?,
            item_root: tree.root(),
            similarity_root: empty_similarity_root(),
        };
        let global_root = root_input.compute()?;
        Ok(BuiltVersion {
            tree,
            items,
            profile_table,
            extraction_table: extraction.to_vec(),
            root_input,
            global_root,
            rejected_count: self.rejected,
        })
    }
}

/// A sealed version: the prover's working set.
#[derive(Debug, Clone)]
pub struct BuiltVersion {
    tree: ItemTree,
    items: BTreeMap<[u8; 32], (ItemPreimage, MetaSet)>,
    /// The canonicalization profile table.
    pub profile_table: Vec<ProfileEntry>,
    /// The extraction table.
    pub extraction_table: Vec<ExtractionEntry>,
    /// Everything the global root binds.
    pub root_input: GlobalRootInput,
    /// `global_root`.
    pub global_root: [u8; 32],
    /// Occurrences rejected by canonicalization.
    pub rejected_count: u64,
}

/// M1-open / MD1 opening of one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedItem {
    /// The content key.
    pub key: [u8; 32],
    /// Path to `item_root`.
    pub path: ItemPath,
    /// The 114-byte commitment preimage.
    pub preimage: ItemPreimage,
}

/// MD1: one disclosed metadata entry, bound to its item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaDisclosure {
    /// The item opening it is bound to.
    pub item: OpenedItem,
    /// Position by blinder.
    pub j: u64,
    /// Set size; must equal the opened `occurrence_count`.
    pub n: u64,
    /// The disclosed entry, with its blinder.
    pub entry: MetaEntry,
    /// Siblings, bottom-up; shape derived from `(j, n)`.
    pub meta_path: Vec<[u8; 32]>,
}

impl BuiltVersion {
    /// The item tree.
    pub fn tree(&self) -> &ItemTree {
        &self.tree
    }

    /// Path along `key` (M1 if a member, N1 otherwise).
    pub fn path(&self, key: &[u8; 32]) -> ItemPath {
        self.tree.path(key)
    }

    /// M1-open for a member key.
    pub fn open(&self, key: &[u8; 32]) -> Option<OpenedItem> {
        let (preimage, _) = self.items.get(key)?;
        Some(OpenedItem {
            key: *key,
            path: self.tree.path(key),
            preimage: *preimage,
        })
    }

    /// The opened metadata set of a member (auditor level).
    pub fn meta_set(&self, key: &[u8; 32]) -> Option<&MetaSet> {
        self.items.get(key).map(|(_, m)| m)
    }

    /// MD1 for entry `j` of a member.
    pub fn disclose(&self, key: &[u8; 32], j: usize) -> Option<MetaDisclosure> {
        let item = self.open(key)?;
        let set = self.meta_set(key)?;
        let entry = set.entries().get(j)?.clone();
        Some(MetaDisclosure {
            j: j as u64,
            n: item.preimage.occurrence_count,
            meta_path: set.path(j),
            entry,
            item,
        })
    }
}

/// M1-open: `opened.key` is a member of `item_root`, its commitment opens to
/// `opened.preimage`, the item has at least one occurrence, and the key is
/// derived from the opened profile and digest. Returns the verified preimage.
pub fn verify_m1_open(
    p: u8,
    item_root: &[u8; 32],
    profile_table: &[ProfileEntry],
    opened: &OpenedItem,
) -> Result<ItemPreimage> {
    let commitment = verify_membership(p, item_root, &opened.key, &opened.path)?;
    if opened.preimage.commitment() != commitment {
        return Err(ContentError::CommitmentMismatch);
    }
    if opened.preimage.occurrence_count == 0 {
        return Err(ContentError::ZeroOccurrences);
    }
    let profile = profile_table
        .get(opened.preimage.profile_index as usize)
        .ok_or(ContentError::UnknownProfile(opened.preimage.profile_index))?;
    if content_key(
        &profile.id,
        profile.version,
        &opened.preimage.content_digest,
    )? != opened.key
    {
        return Err(ContentError::ContentKeyMismatch);
    }
    Ok(opened.preimage)
}

/// N1 for a work the querier canonicalized themselves.
pub fn verify_n1(p: u8, item_root: &[u8; 32], key: &[u8; 32], path: &ItemPath) -> Result<()> {
    verify_non_membership(p, item_root, key, path)
}

/// MD1: M1-open, then the metadata path under the opened `meta_root` with
/// `n = occurrence_count`, then the entry's extraction index against the
/// version's extraction table, then field validation. There is no standalone
/// metadata-path verifier, so a path cannot be checked outside its item.
///
/// `profile_table` and `extraction_table` must come from the same verified
/// header as `item_root`. The extraction check is repeated here, not left to
/// the builder, because a verifier cannot assume the commitment it is given
/// was produced by a conforming builder.
pub fn verify_md1(
    p: u8,
    item_root: &[u8; 32],
    profile_table: &[ProfileEntry],
    extraction_table: &[ExtractionEntry],
    d: &MetaDisclosure,
) -> Result<()> {
    let pre = verify_m1_open(p, item_root, profile_table, &d.item)?;
    if d.n != pre.occurrence_count {
        return Err(ContentError::MetaCountMismatch {
            n: d.n,
            occurrence_count: pre.occurrence_count,
        });
    }
    if meta_root_from_path(&d.entry, d.j, d.n, &d.meta_path)? != pre.meta_root {
        return Err(ContentError::MetaRootMismatch);
    }
    if d.entry.extraction_index as usize >= extraction_table.len() {
        return Err(ContentError::UnknownExtraction(d.entry.extraction_index));
    }
    d.entry.validate()
}

#[cfg(test)]
mod tests {
    //! Verifier-boundary cases. Each builds a *consistent* commitment over an
    //! entry the builder would refuse, using the low-level helpers, so the
    //! assertion is about what `verify_m1_open` / `verify_md1` reject on their
    //! own, not what the builder prevents.

    use super::*;
    use crate::content::commit::{empty_meta_root, promoted_merkle_root};
    use crate::content::domains::Domain;

    fn extraction() -> Vec<ExtractionEntry> {
        vec![ExtractionEntry {
            id: "jsonl/field".into(),
            version: 1,
            implementation_id: "olympus-manifest=0.1.0".into(),
            params: vec![("field".into(), "/text".into())],
        }]
    }

    fn profile_table() -> Vec<ProfileEntry> {
        let c = CanonProfile::TextUtf8Nfc;
        vec![ProfileEntry {
            id: c.id().into(),
            version: c.version(),
            implementation_id: c.implementation_id(),
        }]
    }

    fn entry(status: u8, uri: &str, extraction_index: u16) -> MetaEntry {
        MetaEntry {
            blinding: [7; 32],
            extraction_index,
            source_uri: uri.into(),
            license: String::new(),
            retrieved_at_unix_s: 1,
            opt_out_status: status,
        }
    }

    /// A one-item, one-occurrence tree whose metadata set is exactly
    /// `entries` (or empty), committed without builder validation.
    fn commit_raw(occurrence_count: u64, entries: &[MetaEntry]) -> ([u8; 32], OpenedItem) {
        let digest = content_digest(b"work");
        let key = content_key("text/utf8-nfc", 1, &digest).unwrap();
        let leaves: Vec<_> = entries.iter().map(|e| e.leaf().unwrap()).collect();
        let meta_root = promoted_merkle_root(&leaves, Domain::MetaNode, empty_meta_root());
        let preimage = ItemPreimage {
            profile_index: 0,
            canonical_len: 4,
            content_digest: digest,
            fp_set_root: empty_fp_set_root(),
            occurrence_count,
            meta_root,
        };
        let tree = ItemTree::build(0, vec![(key, preimage.commitment())]).unwrap();
        let opened = OpenedItem {
            key,
            path: tree.path(&key),
            preimage,
        };
        (tree.root(), opened)
    }

    fn md1(item: OpenedItem, e: MetaEntry) -> MetaDisclosure {
        MetaDisclosure {
            item,
            j: 0,
            n: 1,
            entry: e,
            meta_path: vec![],
        }
    }

    #[test]
    fn md1_rejects_an_invalid_opt_out_status_at_the_verifier() {
        let e = entry(3, "https://x/", 0);
        let (root, item) = commit_raw(1, std::slice::from_ref(&e));
        assert_eq!(
            verify_md1(0, &root, &profile_table(), &extraction(), &md1(item, e)),
            Err(ContentError::InvalidOptOutStatus(3))
        );
    }

    #[test]
    fn md1_rejects_a_non_nfc_uri_at_the_verifier() {
        let e = entry(0, "e\u{0301}", 0);
        let (root, item) = commit_raw(1, std::slice::from_ref(&e));
        assert_eq!(
            verify_md1(0, &root, &profile_table(), &extraction(), &md1(item, e)),
            Err(ContentError::NotNfc("source_uri"))
        );
    }

    #[test]
    fn md1_rejects_an_extraction_index_outside_the_table() {
        let e = entry(0, "https://x/", 1);
        let (root, item) = commit_raw(1, std::slice::from_ref(&e));
        assert_eq!(
            verify_md1(
                0,
                &root,
                &profile_table(),
                &extraction(),
                &md1(item.clone(), e.clone())
            ),
            Err(ContentError::UnknownExtraction(1))
        );
        // The same disclosure is accepted against a two-row table, so the
        // rejection above is the index check and nothing else.
        let mut two = extraction();
        two.push(ExtractionEntry {
            id: "file/whole".into(),
            ..two[0].clone()
        });
        assert_eq!(
            verify_md1(0, &root, &profile_table(), &two, &md1(item, e)),
            Ok(())
        );
    }

    #[test]
    fn m1_open_rejects_a_zero_occurrence_item() {
        let (root, item) = commit_raw(0, &[]);
        assert_eq!(
            verify_m1_open(0, &root, &profile_table(), &item),
            Err(ContentError::ZeroOccurrences)
        );
        let (root, item) = commit_raw(1, &[]);
        assert!(verify_m1_open(0, &root, &profile_table(), &item).is_ok());
    }

    #[test]
    fn builder_rejects_a_profile_listed_twice() {
        assert_eq!(
            DatasetBuilder::new(vec![CanonProfile::BytesRaw, CanonProfile::BytesRaw]).err(),
            Some(ContentError::DuplicateProfile("bytes/raw@1".into()))
        );
    }

    #[test]
    fn builder_rejects_metadata_naming_a_missing_extraction_row() {
        let mut b = DatasetBuilder::new(vec![CanonProfile::TextUtf8Nfc]).unwrap();
        b.add(0, b"w", Some(entry(0, "u", 1))).unwrap();
        assert_eq!(
            b.finish("d", 1, 0, &extraction()).err(),
            Some(ContentError::UnknownExtraction(1))
        );
    }
}
