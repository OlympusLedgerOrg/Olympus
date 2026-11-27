// SPDX-License-Identifier: Apache-2.0

//! Building a dataset version and the class A / class C statements over it:
//! M1, M1-open, N1 and MD1 (RFC §2, §10).
//!
//! Header encoding, signing and the ledger commit are deliberately not here;
//! these functions verify against an `item_root` the caller has already
//! taken from a verified header (and recomputed via
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
    pub fn new(profiles: Vec<CanonProfile>) -> Self {
        Self {
            profiles,
            items: BTreeMap::new(),
            blinders: HashSet::new(),
            rejected: 0,
        }
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
        let key = content_key(profile.id(), profile.version(), &digest);
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

    /// Seal the version. `p` is the partition exponent.
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
/// `opened.preimage`, and the key is derived from the opened profile and
/// digest. Returns the verified preimage.
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
    let profile = profile_table
        .get(opened.preimage.profile_index as usize)
        .ok_or(ContentError::UnknownProfile(opened.preimage.profile_index))?;
    if content_key(
        &profile.id,
        profile.version,
        &opened.preimage.content_digest,
    ) != opened.key
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
/// `n = occurrence_count`, then field validation. There is no standalone
/// metadata-path verifier, so a path cannot be checked outside its item.
pub fn verify_md1(
    p: u8,
    item_root: &[u8; 32],
    profile_table: &[ProfileEntry],
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
    d.entry.validate()
}
