//! Incremental version commits: `v2 = v1 − removed + added`, with a proof
//! linking the two versions.
//!
//! Daily dataset curation is unaffordable if every version is a fresh full
//! commit. A [`ManifestDiff`] records exactly which records were added and
//! removed relative to a parent version and commits to that change set with a
//! domain-separated [`diff_root`](ManifestDiff::diff_root). The child manifest
//! then carries:
//!
//! * a [`ParentRef`](crate::ParentRef) binding the parent's `manifest_root`, and
//! * a [`DiffSummary`](crate::DiffSummary) carrying the `diff_root`.
//!
//! Together these give a **structural** version link (cheap, O(1) to check). The
//! **record-level** guarantee — that the child truly is the parent minus the
//! removed set plus the added set — is established on demand: each removed
//! record has an inclusion proof in the parent and an exclusion proof in the
//! child; each added record, the reverse. The redaction circuit is the natural
//! ZK pairing for the "removed" half (a removal is a redaction).
//!
//! The `diff_root` domain `OLY:MANIFEST:DIFF:V1` is a manifest-layer commitment,
//! independent of (and disjoint from) the protocol SMT leaf/node domains.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use olympus_crypto::length_prefixed;

use crate::commit::SealedManifest;
use crate::proof::{verify, ProofKind, RecordProofBundle, Verdict};
use crate::{decode_hash32, DiffSummary, RecordIndex, Result};

/// Domain-separation tag for the manifest change-set commitment (`diff_root`).
/// Manifest-layer; disjoint from the protocol SMT domains in `olympus-crypto`.
pub const DIFF_DOMAIN: &[u8] = b"OLY:MANIFEST:DIFF:V1";

/// One record added or removed between two dataset versions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecordRef {
    /// Owning shard.
    pub shard_id: String,
    /// Record identifier.
    pub record_id: String,
    /// Record version.
    pub version: u64,
    /// Lower-hex content hash (the parent's value for removals, the child's for
    /// additions). Bound into `diff_root`.
    pub content_hash: String,
}

/// The change set between a parent and child dataset version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestDiff {
    /// Parent version number.
    pub parent_version: u64,
    /// Parent `manifest_root` (lower-hex).
    pub parent_root: String,
    /// Child version number.
    pub child_version: u64,
    /// Child `manifest_root` (lower-hex).
    pub child_root: String,
    /// Records present in the child but not the parent.
    pub added: Vec<RecordRef>,
    /// Records present in the parent but not the child.
    pub removed: Vec<RecordRef>,
}

/// Kind byte for a change-set entry, fixing its position in the commitment.
const KIND_REMOVE: u8 = 0;
const KIND_ADD: u8 = 1;

impl ManifestDiff {
    /// Commitment over the ordered change set (added ∪ removed).
    ///
    /// ```text
    /// BLAKE3(
    ///     "OLY:MANIFEST:DIFF:V1" ||
    ///     u32_be(count) ||
    ///     for each entry sorted by (kind, shard_id, record_id, version):
    ///         u8(kind) || lp(shard_id) || lp(record_id) || u64_be(version) || content_hash[32]
    /// )
    /// ```
    ///
    /// The kind byte and length prefixes make the preimage unambiguous; sorting
    /// makes it order-independent. Errors only if a `content_hash` is malformed.
    pub fn diff_root(&self) -> Result<[u8; 32]> {
        // Build a canonical, sorted entry list (kind, ref).
        let mut entries: BTreeSet<(u8, &RecordRef)> = BTreeSet::new();
        for r in &self.removed {
            entries.insert((KIND_REMOVE, r));
        }
        for r in &self.added {
            entries.insert((KIND_ADD, r));
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(DIFF_DOMAIN);
        hasher.update(&(entries.len() as u32).to_be_bytes());
        for (kind, r) in &entries {
            let ch = decode_hash32("content_hash", &r.content_hash)?;
            hasher.update(&[*kind]);
            hasher.update(&length_prefixed(r.shard_id.as_bytes()));
            hasher.update(&length_prefixed(r.record_id.as_bytes()));
            hasher.update(&r.version.to_be_bytes());
            hasher.update(&ch);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    /// Build the [`DiffSummary`] this diff produces (for sealing into a child
    /// manifest).
    pub fn summary(&self) -> Result<DiffSummary> {
        Ok(DiffSummary {
            added: self.added.len() as u64,
            removed: self.removed.len() as u64,
            diff_root: hex::encode(self.diff_root()?),
        })
    }
}

/// Compute the change set between two record indexes by `(shard_id, record_id,
/// version)` identity. `content_hash` for a removal is taken from the parent;
/// for an addition, from the child.
pub fn compute_diff(
    parent_version: u64,
    parent_root: &str,
    parent: &RecordIndex,
    child_version: u64,
    child_root: &str,
    child: &RecordIndex,
) -> ManifestDiff {
    use std::collections::HashMap;
    type Id = (String, String, u64);

    let flatten = |idx: &RecordIndex| -> HashMap<Id, String> {
        let mut m = HashMap::new();
        for s in &idx.shards {
            for r in &s.records {
                m.insert(
                    (s.shard_id.clone(), r.record_id.clone(), r.version),
                    r.content_hash.clone(),
                );
            }
        }
        m
    };
    let p = flatten(parent);
    let c = flatten(child);

    let mut added = Vec::new();
    let mut removed = Vec::new();
    for (id, ch) in &c {
        if !p.contains_key(id) {
            added.push(RecordRef {
                shard_id: id.0.clone(),
                record_id: id.1.clone(),
                version: id.2,
                content_hash: ch.clone(),
            });
        }
    }
    for (id, ch) in &p {
        if !c.contains_key(id) {
            removed.push(RecordRef {
                shard_id: id.0.clone(),
                record_id: id.1.clone(),
                version: id.2,
                content_hash: ch.clone(),
            });
        }
    }
    added.sort();
    removed.sort();

    ManifestDiff {
        parent_version,
        parent_root: parent_root.to_string(),
        child_version,
        child_root: child_root.to_string(),
        added,
        removed,
    }
}

/// Seal `child` as an incremental version on top of `parent`, attaching the
/// [`ParentRef`](crate::ParentRef) and [`DiffSummary`].
///
/// Returns the sealed child manifest and the full [`ManifestDiff`] artifact (the
/// latter is committed by reference via `diff_root`, and used to drive
/// per-record link verification).
pub fn seal_incremental(
    parent: &SealedManifest,
    child: &mut SealedManifest,
    parent_index: &RecordIndex,
    child_index: &RecordIndex,
) -> Result<ManifestDiff> {
    let diff = compute_diff(
        parent.manifest.version,
        &parent.manifest.manifest_root,
        parent_index,
        child.manifest.version,
        &child.manifest.manifest_root,
        child_index,
    );
    child.manifest.parent = Some(crate::ParentRef {
        version: parent.manifest.version,
        manifest_root: parent.manifest.manifest_root.clone(),
    });
    child.manifest.diff = Some(diff.summary()?);
    Ok(diff)
}

/// Structural outcome of [`verify_link`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkVerdict {
    /// Parent ref and diff summary are present and consistent with the diff.
    Valid,
    /// The child manifest carries no parent reference.
    NoParent,
    /// The child's parent ref does not match the supplied parent root/version.
    ParentMismatch,
    /// The child carries no diff summary.
    NoDiff,
    /// The diff summary's `diff_root` / counts disagree with the diff artifact.
    DiffMismatch,
}

impl LinkVerdict {
    /// `true` only for [`LinkVerdict::Valid`].
    pub fn is_valid(self) -> bool {
        matches!(self, LinkVerdict::Valid)
    }
}

/// Verify the **structural** link between a child manifest document and its
/// declared parent + diff: the child binds the parent's root/version and the
/// diff summary matches the diff artifact. O(diff size); does not re-verify
/// per-record membership (use [`verify_removed`] / [`verify_added`] for that).
///
/// Takes the [`DatasetManifest`](crate::DatasetManifest) document directly, so a
/// verifier can check the link from committed artifacts alone without the
/// (large) record index.
pub fn verify_link(
    child: &crate::DatasetManifest,
    parent_version: u64,
    parent_root: &str,
    diff: &ManifestDiff,
) -> Result<LinkVerdict> {
    let Some(parent_ref) = &child.parent else {
        return Ok(LinkVerdict::NoParent);
    };
    if parent_ref.version != parent_version || parent_ref.manifest_root != parent_root {
        return Ok(LinkVerdict::ParentMismatch);
    }
    let Some(summary) = &child.diff else {
        return Ok(LinkVerdict::NoDiff);
    };
    let expected = diff.summary()?;
    if summary != &expected {
        return Ok(LinkVerdict::DiffMismatch);
    }
    Ok(LinkVerdict::Valid)
}

/// Verify one **removed** record at the record level: it was in the parent
/// (inclusion proof against `parent_root`) and is gone from the child (exclusion
/// proof against `child_root`).
pub fn verify_removed(
    parent_inclusion: &RecordProofBundle,
    parent_root: &[u8; 32],
    child_exclusion: &RecordProofBundle,
    child_root: &[u8; 32],
) -> Result<bool> {
    if parent_inclusion.kind != ProofKind::Inclusion || child_exclusion.kind != ProofKind::Exclusion
    {
        return Ok(false);
    }
    Ok(verify(parent_inclusion, parent_root)? == Verdict::Valid
        && verify(child_exclusion, child_root)? == Verdict::Valid)
}

/// Verify one **added** record at the record level: it was absent from the
/// parent (exclusion proof) and is present in the child (inclusion proof).
pub fn verify_added(
    parent_exclusion: &RecordProofBundle,
    parent_root: &[u8; 32],
    child_inclusion: &RecordProofBundle,
    child_root: &[u8; 32],
) -> Result<bool> {
    if parent_exclusion.kind != ProofKind::Exclusion || child_inclusion.kind != ProofKind::Inclusion
    {
        return Ok(false);
    }
    Ok(verify(parent_exclusion, parent_root)? == Verdict::Valid
        && verify(child_inclusion, child_root)? == Verdict::Valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::seal;
    use crate::{DatasetMetadata, RecordEntry, ShardRecords};

    fn rec(id: &str, ch: u8) -> RecordEntry {
        RecordEntry {
            record_id: id.to_string(),
            content_hash: format!("{ch:02x}").repeat(32),
            version: 1,
            byte_size: None,
        }
    }

    fn index(records: Vec<RecordEntry>) -> RecordIndex {
        RecordIndex {
            shards: vec![ShardRecords {
                shard_id: "alpha".to_string(),
                records,
            }],
        }
    }

    #[test]
    fn diff_root_is_deterministic_and_order_independent() {
        let d1 = compute_diff(
            1,
            "00",
            &index(vec![rec("keep", 1), rec("drop", 2)]),
            2,
            "11",
            &index(vec![rec("keep", 1), rec("new", 3)]),
        );
        // Recompute with parent/child record order shuffled → same diff_root.
        let d2 = compute_diff(
            1,
            "00",
            &index(vec![rec("drop", 2), rec("keep", 1)]),
            2,
            "11",
            &index(vec![rec("new", 3), rec("keep", 1)]),
        );
        assert_eq!(d1.diff_root().unwrap(), d2.diff_root().unwrap());
        assert_eq!(d1.added.len(), 1);
        assert_eq!(d1.removed.len(), 1);
        assert_eq!(d1.added[0].record_id, "new");
        assert_eq!(d1.removed[0].record_id, "drop");
    }

    #[test]
    fn diff_domain_is_pinned() {
        assert_eq!(DIFF_DOMAIN, b"OLY:MANIFEST:DIFF:V1");
    }

    #[test]
    fn full_incremental_flow_links_and_verifies_per_record() {
        let parent_index = index(vec![rec("keep", 1), rec("drop", 2)]);
        let child_index = index(vec![rec("keep", 1), rec("new", 3)]);

        let parent = seal("ds", 1, 0, DatasetMetadata::default(), &parent_index).unwrap();
        let mut child = seal("ds", 2, 0, DatasetMetadata::default(), &child_index).unwrap();
        let diff = seal_incremental(&parent, &mut child, &parent_index, &child_index).unwrap();

        // Structural link verifies.
        assert_eq!(
            verify_link(&child.manifest, 1, &parent.manifest.manifest_root, &diff).unwrap(),
            LinkVerdict::Valid
        );

        let parent_root = parent.manifest_root();
        let child_root = child.manifest_root();

        // Removed record: in parent, gone from child.
        let p_inc = parent.prove_inclusion("alpha", "drop", 1).unwrap();
        let c_exc = child.prove_exclusion("alpha", "drop", 1).unwrap();
        assert!(verify_removed(&p_inc, &parent_root, &c_exc, &child_root).unwrap());

        // Added record: absent from parent, present in child.
        let p_exc = parent.prove_exclusion("alpha", "new", 1).unwrap();
        let c_inc = child.prove_inclusion("alpha", "new", 1).unwrap();
        assert!(verify_added(&p_exc, &parent_root, &c_inc, &child_root).unwrap());
    }

    #[test]
    fn link_detects_parent_mismatch() {
        let parent_index = index(vec![rec("keep", 1)]);
        let child_index = index(vec![rec("keep", 1), rec("new", 3)]);
        let parent = seal("ds", 1, 0, DatasetMetadata::default(), &parent_index).unwrap();
        let mut child = seal("ds", 2, 0, DatasetMetadata::default(), &child_index).unwrap();
        let diff = seal_incremental(&parent, &mut child, &parent_index, &child_index).unwrap();
        // Wrong parent root.
        assert_eq!(
            verify_link(&child.manifest, 1, &"ab".repeat(32), &diff).unwrap(),
            LinkVerdict::ParentMismatch
        );
    }

    #[test]
    fn removed_proof_with_wrong_kind_fails() {
        let parent_index = index(vec![rec("drop", 2)]);
        let child_index = index(vec![]);
        let parent = seal("ds", 1, 0, DatasetMetadata::default(), &parent_index).unwrap();
        let child = seal("ds", 2, 0, DatasetMetadata::default(), &child_index).unwrap();
        let parent_root = parent.manifest_root();
        let child_root = child.manifest_root();
        // Pass two exclusions where verify_removed expects (inclusion, exclusion).
        let p_exc = parent.prove_exclusion("alpha", "ghost", 1).unwrap();
        let c_exc = child.prove_exclusion("alpha", "drop", 1).unwrap();
        assert!(!verify_removed(&p_exc, &parent_root, &c_exc, &child_root).unwrap());
    }
}
