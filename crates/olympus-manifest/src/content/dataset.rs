// SPDX-License-Identifier: Apache-2.0

//! Building a dataset version and the statements over it: M1, M1-open and N1
//! (class A), MD1 (class C) (RFC §2, §10), and plain M2 (class B, similarity
//! companion).
//!
//! Header encoding, signing and the ledger commit are deliberately not here;
//! these functions verify against an `item_root` and tables the caller has
//! already taken from a verified header (and recomputed via
//! [`super::version::GlobalRootInput`]).

use std::collections::{BTreeMap, HashSet};

use super::canon::CanonProfile;
use super::commit::{
    content_digest, content_key, meta_root_from_path, ItemPreimage, MetaEntry, MetaSet,
};
use super::error::{ContentError, Result};
use super::fingerprint::{fp_set_root_from_path, FpEntry, FpProfile, FpSet};
use super::similarity::{band_keys, BucketEntry, Candidate, SimilarityIndex};
use super::tree::{verify_membership, verify_non_membership, ItemPath, ItemTree};
use super::version::{
    ExtractionEntry, FpProfileEntry, GlobalRootInput, ProfileEntry, TableDigests,
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
    /// Computed once, from the first occurrence's canonical bytes; every
    /// merged occurrence has the same canonical bytes, so the same set.
    fingerprints: Vec<FpEntry>,
}

/// Accumulates occurrences for one dataset version.
#[derive(Debug)]
pub struct DatasetBuilder {
    profiles: Vec<CanonProfile>,
    fp_profiles: Vec<FpProfile>,
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
        Self::with_fingerprints(profiles, Vec::new())
    }

    /// As [`DatasetBuilder::new`], with `fp_profiles` as the version's
    /// fingerprint-profile table, in order. Each item is fingerprinted under
    /// every profile that [applies](FpProfile::applies_to) to its
    /// canonicalization profile. A fingerprint profile listed twice is
    /// rejected for the same reason a canonicalization profile is.
    pub fn with_fingerprints(
        profiles: Vec<CanonProfile>,
        fp_profiles: Vec<FpProfile>,
    ) -> Result<Self> {
        let mut seen_fp = HashSet::new();
        for f in &fp_profiles {
            if !seen_fp.insert((f.id(), f.version())) {
                return Err(ContentError::DuplicateFpProfile(format!(
                    "{}@{}",
                    f.id(),
                    f.version()
                )));
            }
        }
        if u16::try_from(fp_profiles.len()).is_err() {
            return Err(ContentError::TableTooLarge("fp_profile"));
        }
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
            fp_profiles,
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
        if !self.items.contains_key(&key) {
            let fingerprints = self.fingerprint(profile, &canonical)?;
            self.items.insert(
                key,
                Pending {
                    profile_index,
                    canonical_len: canonical.len() as u64,
                    digest,
                    occurrences: 0,
                    meta: Vec::new(),
                    fingerprints,
                },
            );
        }
        let entry = self.items.get_mut(&key).expect("inserted above");
        entry.occurrences += 1;
        if let Some(m) = meta {
            self.blinders.insert(m.blinding);
            entry.meta.push(m);
        }
        Ok(AddOutcome::Committed(key))
    }

    /// Every applicable profile's segment fingerprints of one canonical item.
    fn fingerprint(&self, canon: CanonProfile, canonical: &[u8]) -> Result<Vec<FpEntry>> {
        let mut out = Vec::new();
        for (i, f) in self.fp_profiles.iter().enumerate() {
            if !f.applies_to(canon) {
                continue;
            }
            let fp_profile_index = u16::try_from(i).expect("table size checked in new");
            for (s, fingerprint) in f.fingerprints(canonical)?.into_iter().enumerate() {
                out.push(FpEntry {
                    fp_profile_index,
                    segment_index: u32::try_from(s)
                        .map_err(|_| ContentError::FieldTooLong("segment_index"))?,
                    fingerprint,
                });
            }
        }
        Ok(out)
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
        let fp_table: Vec<FpProfileEntry> = self.fp_profiles.iter().map(|f| f.entry()).collect();
        let mut items = BTreeMap::new();
        let mut leaves = Vec::with_capacity(self.items.len());
        let mut occurrence_total = 0u64;
        let mut unfingerprinted = 0u64;
        let mut bucket_pairs = Vec::new();
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
            let fps = FpSet::new(pend.fingerprints)?;
            if fps.entries().is_empty() {
                unfingerprinted += 1;
            }
            for e in fps.entries() {
                let profile = self.fp_profiles[usize::from(e.fp_profile_index)];
                for band_key in band_keys(profile, &e.fingerprint)? {
                    bucket_pairs.push((
                        band_key,
                        BucketEntry {
                            content_key: key,
                            fp_profile_index: e.fp_profile_index,
                            segment_index: e.segment_index,
                            fingerprint: e.fingerprint.clone(),
                        },
                    ));
                }
            }
            let preimage = ItemPreimage {
                profile_index: pend.profile_index,
                canonical_len: pend.canonical_len,
                content_digest: pend.digest,
                fp_set_root: fps.root(),
                occurrence_count: pend.occurrences,
                meta_root: meta.root(),
            };
            occurrence_total += pend.occurrences;
            leaves.push((key, preimage.commitment()));
            items.insert(key, (preimage, meta, fps));
        }
        let similarity = SimilarityIndex::build(bucket_pairs)?;
        let tree = ItemTree::build(p, leaves)?;
        let root_input = GlobalRootInput {
            dataset_id: dataset_id.into(),
            version,
            p,
            item_count: tree.len(),
            occurrence_total,
            tables: TableDigests::compute(extraction, &profile_table, &fp_table)?,
            item_root: tree.root(),
            similarity_root: similarity.root(),
        };
        let global_root = root_input.compute()?;
        Ok(BuiltVersion {
            tree,
            items,
            similarity,
            fp_profiles: self.fp_profiles,
            fp_table,
            unfingerprinted_count: unfingerprinted,
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
    items: BTreeMap<[u8; 32], (ItemPreimage, MetaSet, FpSet)>,
    similarity: SimilarityIndex,
    fp_profiles: Vec<FpProfile>,
    /// The fingerprint-profile table.
    pub fp_table: Vec<FpProfileEntry>,
    /// Items (leaves) with no fingerprint: outside every profile's domain, or
    /// too short. Every item when the fingerprint table is empty.
    pub unfingerprinted_count: u64,
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

/// Plain M2: one committed segment fingerprint of one item, opened under the
/// item's `fp_set_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M2Proof {
    /// M1-open for the candidate.
    pub item: OpenedItem,
    /// Index into the authenticated fingerprint-profile table.
    pub fp_profile_index: u16,
    /// Segment index within the candidate.
    pub segment_index: u32,
    /// Position in the candidate's fingerprint set.
    pub leaf_index: u32,
    /// Size of the fingerprint set; with `leaf_index` it fixes the path
    /// shape. It guides folding and attests nothing about the set's size.
    pub leaf_count: u32,
    /// The candidate's committed fingerprint.
    pub fingerprint: Vec<u8>,
    /// Fingerprint-set siblings, bottom-up, promoted levels omitted.
    pub fp_path: Vec<[u8; 32]>,
}

/// What a verified M2 establishes (class B): the committed item `key`
/// carries a segment fingerprint within the signed threshold of the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct M2Match {
    /// The candidate's verified preimage.
    pub preimage: ItemPreimage,
    /// Candidate content key.
    pub key: [u8; 32],
    /// Fingerprint profile used, with its signed threshold.
    pub profile: FpProfile,
    /// Candidate segment.
    pub segment_index: u32,
    /// Similarity in the profile's unit.
    pub similarity: u32,
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
        let (preimage, _, _) = self.items.get(key)?;
        Some(OpenedItem {
            key: *key,
            path: self.tree.path(key),
            preimage: *preimage,
        })
    }

    /// The opened metadata set of a member (auditor level).
    pub fn meta_set(&self, key: &[u8; 32]) -> Option<&MetaSet> {
        self.items.get(key).map(|(_, m, _)| m)
    }

    /// The fingerprint set of a member.
    pub fn fp_set(&self, key: &[u8; 32]) -> Option<&FpSet> {
        self.items.get(key).map(|(_, _, f)| f)
    }

    /// The similarity index (committer-side retrieval).
    pub fn similarity(&self) -> &SimilarityIndex {
        &self.similarity
    }

    /// Committed segments sharing a band with `query` under fingerprint
    /// profile `fp_profile_index`: candidates for M2, not results.
    pub fn candidates(&self, fp_profile_index: u16, query: &[u8]) -> Result<Vec<Candidate>> {
        let profile = *self
            .fp_profiles
            .get(usize::from(fp_profile_index))
            .ok_or(ContentError::UnknownFpIndex(fp_profile_index))?;
        self.similarity.candidates(profile, fp_profile_index, query)
    }

    /// Plain M2 for one committed segment fingerprint of a member.
    pub fn open_m2(
        &self,
        key: &[u8; 32],
        fp_profile_index: u16,
        segment_index: u32,
    ) -> Option<M2Proof> {
        let item = self.open(key)?;
        let set = self.fp_set(key)?;
        let j = set.position(fp_profile_index, segment_index)?;
        Some(M2Proof {
            item,
            fp_profile_index,
            segment_index,
            leaf_index: u32::try_from(j).ok()?,
            leaf_count: u32::try_from(set.entries().len()).ok()?,
            fingerprint: set.entries()[j].fingerprint.clone(),
            fp_path: set.path(j),
        })
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

/// Plain M2: M1-open for the candidate, then its fingerprint leaf under the
/// opened `fp_set_root` (shape from `(leaf_index, leaf_count)`), then the
/// signed profile's threshold against `query`, which the verifier computed
/// from the claimant's copy. `fp_table` must come from the same verified
/// header as `item_root`; its row fixes the width, distance and threshold.
///
/// The verifier does not recompute the committed fingerprint: it relies on
/// the committer having computed it correctly, which an exact copy or a
/// sampled rebuild can check (class B).
pub fn verify_m2(
    p: u8,
    item_root: &[u8; 32],
    profile_table: &[ProfileEntry],
    fp_table: &[FpProfileEntry],
    proof: &M2Proof,
    query: &[u8],
) -> Result<M2Match> {
    let pre = verify_m1_open(p, item_root, profile_table, &proof.item)?;
    let row = fp_table
        .get(usize::from(proof.fp_profile_index))
        .ok_or(ContentError::UnknownFpIndex(proof.fp_profile_index))?;
    let profile = FpProfile::from_entry(row)?;
    profile.check_width(&proof.fingerprint)?;
    profile.check_width(query)?;
    let root = fp_set_root_from_path(
        proof.fp_profile_index,
        proof.segment_index,
        &proof.fingerprint,
        proof.leaf_index,
        proof.leaf_count,
        &proof.fp_path,
    )?;
    if root != pre.fp_set_root {
        return Err(ContentError::FpRootMismatch);
    }
    let similarity = profile.similarity(&proof.fingerprint, query)?;
    if similarity < profile.threshold() {
        return Err(ContentError::BelowThreshold {
            matching: similarity,
            threshold: profile.threshold(),
        });
    }
    Ok(M2Match {
        preimage: pre,
        key: proof.item.key,
        profile,
        segment_index: proof.segment_index,
        similarity,
    })
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
    use crate::content::commit::{empty_fp_set_root, empty_meta_root, promoted_merkle_root};
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

    // -- M2 (class B) -------------------------------------------------------

    use crate::content::version::empty_similarity_root;
    use crate::content::wire::ExactProof;

    fn words(n: usize, seed: &str) -> String {
        (0..n)
            .map(|i| format!("{seed}{i}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A long text (two segments, merged twice), a short text, a bytes item
    /// and an unrelated long text, fingerprinted under `text/minhash-120`.
    fn similarity_version() -> (BuiltVersion, [u8; 32], String) {
        let mut b = DatasetBuilder::with_fingerprints(
            vec![CanonProfile::TextUtf8Nfc, CanonProfile::BytesRaw],
            vec![FpProfile::text_minhash_120()],
        )
        .unwrap();
        let long = words(300, "w");
        let AddOutcome::Committed(key) = b.add(0, long.as_bytes(), None).unwrap() else {
            unreachable!()
        };
        b.add(0, long.replace('\n', "\r\n").as_bytes(), None)
            .unwrap();
        b.add(0, b"too short", None).unwrap();
        b.add(1, long.as_bytes(), None).unwrap();
        b.add(0, words(300, "z").as_bytes(), None).unwrap();
        (b.finish("ds", 1, 2, &extraction()).unwrap(), key, long)
    }

    fn verify(v: &BuiltVersion, proof: &M2Proof, query: &[u8]) -> Result<M2Match> {
        verify_m2(
            2,
            &v.root_input.item_root,
            &v.profile_table,
            &v.fp_table,
            proof,
            query,
        )
    }

    #[test]
    fn m2_end_to_end_from_a_claimants_edited_copy() {
        let (v, key, long) = similarity_version();
        assert_eq!(v.tree().len(), 4);
        // The short text and the bytes item fall outside coverage.
        assert_eq!(v.unfingerprinted_count, 2);
        assert_eq!(v.fp_set(&key).unwrap().entries().len(), 2);
        assert_ne!(v.root_input.similarity_root, empty_similarity_root());
        assert_eq!(v.root_input.similarity_root, v.similarity().root());

        // The claimant edits one word and reflows the text.
        let claimant = long.replacen("w150", "edited", 1).replace(' ', "\n");
        let profile = FpProfile::text_minhash_120();
        let queries = profile.fingerprints_of_work(claimant.as_bytes()).unwrap();
        let cands = v.candidates(0, &queries[0]).unwrap();
        let top = &cands[0];
        assert_eq!((top.content_key, top.segment_index), (key, 0));
        assert!(top.passes);

        let proof = v.open_m2(&key, 0, 0).unwrap();
        let bytes = proof.encode(2).unwrap();
        let decoded = M2Proof::decode(2, &v.fp_table, &bytes).unwrap();
        assert_eq!(decoded, proof);
        let m = verify(&v, &decoded, &queries[0]).unwrap();
        assert_eq!(m.key, key);
        assert_eq!(m.similarity, top.similarity);
        assert!(m.similarity >= 84);
        assert_eq!(m.preimage.occurrence_count, 2);
    }

    #[test]
    fn m2_rejections_name_their_rule() {
        let (v, key, long) = similarity_version();
        let query = FpProfile::text_minhash_120()
            .fingerprints(long.as_bytes())
            .unwrap()
            .remove(0);
        let good = v.open_m2(&key, 0, 0).unwrap();
        assert!(verify(&v, &good, &query).is_ok());

        let mut flipped = good.clone();
        flipped.fingerprint[0] ^= 1;
        assert_eq!(
            verify(&v, &flipped, &query),
            Err(ContentError::FpRootMismatch)
        );

        // Segment 1's fingerprint presented at segment 0's position.
        let seg1 = v.open_m2(&key, 0, 1).unwrap();
        let mut swapped = good.clone();
        swapped.fingerprint = seg1.fingerprint.clone();
        assert_eq!(
            verify(&v, &swapped, &query),
            Err(ContentError::FpRootMismatch)
        );
        // The same fingerprint claimed as another segment of the item.
        let mut relabelled = good.clone();
        relabelled.segment_index = 1;
        assert_eq!(
            verify(&v, &relabelled, &query),
            Err(ContentError::FpRootMismatch)
        );
        let mut wrong_pos = good.clone();
        wrong_pos.leaf_index = 1;
        assert_eq!(
            verify(&v, &wrong_pos, &query),
            Err(ContentError::FpRootMismatch)
        );

        let mut out_of_range = good.clone();
        out_of_range.leaf_index = 2;
        assert_eq!(
            verify(&v, &out_of_range, &query),
            Err(ContentError::FpPositionOutOfRange { j: 2, n: 2 })
        );

        let mut long_path = good.clone();
        long_path.fp_path.push([0; 32]);
        assert_eq!(
            verify(&v, &long_path, &query),
            Err(ContentError::FpPathLength {
                expected: 1,
                got: 2
            })
        );

        // A fingerprint and path from another item, under this item's opening.
        let other = v
            .candidates(
                0,
                &FpProfile::text_minhash_120()
                    .fingerprints(words(300, "z").as_bytes())
                    .unwrap()[0],
            )
            .unwrap()[0]
            .content_key;
        let transplant = M2Proof {
            item: good.item.clone(),
            ..v.open_m2(&other, 0, 0).unwrap()
        };
        assert_eq!(
            verify(&v, &transplant, &query),
            Err(ContentError::FpRootMismatch)
        );

        let unrelated = FpProfile::text_minhash_120()
            .fingerprints(words(300, "q").as_bytes())
            .unwrap()
            .remove(0);
        assert!(matches!(
            verify(&v, &good, &unrelated),
            Err(ContentError::BelowThreshold { threshold: 84, .. })
        ));

        assert_eq!(
            verify(&v, &good, &query[..479]),
            Err(ContentError::FingerprintWidth {
                expected: 480,
                got: 479
            })
        );

        let mut bad_index = good.clone();
        bad_index.fp_profile_index = 1;
        assert_eq!(
            verify(&v, &bad_index, &query),
            Err(ContentError::UnknownFpIndex(1))
        );

        // An unimplemented profile in the table is refused, never guessed at.
        let mut pdq = v.fp_table.clone();
        pdq[0].id = "image/pdq-256".into();
        assert_eq!(
            verify_m2(
                2,
                &v.root_input.item_root,
                &v.profile_table,
                &pdq,
                &good,
                &query
            ),
            Err(ContentError::UnknownFpProfile("image/pdq-256@1".into()))
        );
    }

    #[test]
    fn the_threshold_comes_from_the_signed_table_row() {
        let (v, key, long) = similarity_version();
        let mut edited = long.replacen("w10 ", "x ", 1);
        edited = edited.replacen("w200 ", "y ", 1);
        let query = FpProfile::text_minhash_120()
            .fingerprints(edited.as_bytes())
            .unwrap()
            .remove(0);
        let proof = v.open_m2(&key, 0, 0).unwrap();
        let m = verify(&v, &proof, &query).unwrap();
        assert!(m.similarity < 120, "the edit must change some slot");
        // Raising the row's threshold above the observed similarity rejects
        // the same proof, so the decision is the row's, not a constant's.
        let mut exact = v.fp_table.clone();
        exact[0].threshold = m.similarity;
        assert!(
            verify_m2(
                2,
                &v.root_input.item_root,
                &v.profile_table,
                &exact,
                &proof,
                &query
            )
            .is_ok(),
            "m ≥ threshold: equality passes"
        );
        let mut strict = v.fp_table.clone();
        strict[0].threshold = m.similarity + 1;
        assert_eq!(
            verify_m2(
                2,
                &v.root_input.item_root,
                &v.profile_table,
                &strict,
                &proof,
                &query
            ),
            Err(ContentError::BelowThreshold {
                matching: m.similarity,
                threshold: m.similarity + 1
            })
        );
        // And that row is bound into the global root, so a verifier holding
        // the signed header cannot be handed the altered row.
        let mut input = v.root_input.clone();
        input.tables =
            TableDigests::compute(&v.extraction_table, &v.profile_table, &strict).unwrap();
        assert_ne!(input.compute().unwrap(), v.global_root);
    }

    #[test]
    fn m2_wire_rejects_noncanonical_bodies() {
        let (v, key, _) = similarity_version();
        let bytes = v.open_m2(&key, 0, 0).unwrap().encode(2).unwrap();
        for len in 0..bytes.len() {
            assert!(
                M2Proof::decode(2, &v.fp_table, &bytes[..len]).is_err(),
                "len={len}"
            );
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(
            M2Proof::decode(2, &v.fp_table, &extra),
            Err(ContentError::InvalidProofEncoding("trailing bytes"))
        );
        // An N1 body inside the M2 frame.
        let absent = [0x77; 32];
        let n1 = ExactProof::NonMembership {
            key: absent,
            path: v.path(&absent),
        }
        .encode(2)
        .unwrap();
        let mut framed = vec![3];
        framed.extend_from_slice(&(n1.len() as u32).to_be_bytes());
        framed.extend_from_slice(&n1);
        framed.extend_from_slice(&bytes[5 + (bytes.len() - 5 - 14 - 480 - 32)..]);
        assert_eq!(
            M2Proof::decode(2, &v.fp_table, &framed),
            Err(ContentError::InvalidProofEncoding(
                "M2 must carry an M1-open body"
            ))
        );
        // leaf_index ≥ leaf_count is refused while decoding.
        let inner_len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
        let at = 5 + inner_len + 2 + 4;
        let mut bad = bytes.clone();
        bad[at..at + 4].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(
            M2Proof::decode(2, &v.fp_table, &bad),
            Err(ContentError::FpPositionOutOfRange { j: 2, n: 2 })
        );
    }

    #[test]
    fn exact_only_versions_are_unchanged_and_roots_ignore_add_order() {
        let texts = [words(300, "a"), words(40, "b"), "c".to_string()];
        let build = |order: &[usize], fp: Vec<FpProfile>| {
            let mut b =
                DatasetBuilder::with_fingerprints(vec![CanonProfile::TextUtf8Nfc], fp).unwrap();
            for &i in order {
                b.add(0, texts[i].as_bytes(), None).unwrap();
            }
            b.finish("ds", 1, 1, &extraction()).unwrap()
        };
        let exact = build(&[0, 1, 2], vec![]);
        assert_eq!(exact.root_input.similarity_root, empty_similarity_root());
        assert_eq!(exact.unfingerprinted_count, 3);
        let similar = build(&[0, 1, 2], vec![FpProfile::text_minhash_120()]);
        assert_eq!(similar.unfingerprinted_count, 1);
        assert_ne!(similar.global_root, exact.global_root);
        assert_eq!(
            build(&[2, 0, 1], vec![FpProfile::text_minhash_120()]).global_root,
            similar.global_root
        );
    }

    #[test]
    fn builder_rejects_a_fingerprint_profile_listed_twice() {
        assert_eq!(
            DatasetBuilder::with_fingerprints(
                vec![CanonProfile::TextUtf8Nfc],
                vec![
                    FpProfile::text_minhash_120(),
                    FpProfile::text_minhash_120_with_threshold(90).unwrap()
                ]
            )
            .err(),
            Some(ContentError::DuplicateFpProfile(
                "text/minhash-120@1".into()
            ))
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
