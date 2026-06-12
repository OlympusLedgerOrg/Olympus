//! Record-level inclusion and exclusion proofs against a `manifest_root`.
//!
//! A [`RecordProofBundle`] is a self-describing, serializable artifact: it names
//! the dataset/version, the record, the `manifest_root` it is relative to, and
//! carries the underlying Olympus SMT proof. Verification re-derives the tree
//! key from the human-readable `(shard_id, record_id, version)` and checks it
//! equals the proof's key — so a valid proof for *some* leaf cannot be
//! mislabelled as a different record — then defers to the canonical
//! [`olympus_crypto::smt`] verifiers, anchored to the caller-supplied root.

use serde::{Deserialize, Serialize};

use olympus_crypto::smt::{verify_existence_proof, verify_nonexistence_proof, Proof};

use crate::commit::{record_tree_key, SealedManifest};
use crate::{decode_hash32, ManifestError, Result};

/// Schema tag for a record proof bundle.
pub const RECORD_PROOF_SCHEMA: &str = "olympus.record-proof/v1";

/// Whether a bundle proves a record is in, or absent from, the dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofKind {
    /// The record is committed in the dataset version.
    Inclusion,
    /// The record is not committed in the dataset version.
    Exclusion,
}

/// A self-contained, offline-verifiable record proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordProofBundle {
    /// Always [`RECORD_PROOF_SCHEMA`].
    pub schema: String,
    /// Dataset the proof is about.
    pub dataset_id: String,
    /// Dataset version the proof is about.
    pub version: u64,
    /// Lower-hex `manifest_root` this proof reconstructs (also present inside the
    /// SMT proof; carried here for convenience and cross-checked on verify).
    pub manifest_root: String,
    /// Shard the record belongs (or would belong) to.
    pub shard_id: String,
    /// The record identifier.
    pub record_id: String,
    /// The record version folded into the key.
    pub record_version: u64,
    /// Inclusion or exclusion.
    pub kind: ProofKind,
    /// For inclusion: the committed lower-hex content hash. Empty for exclusion.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_hash: String,
    /// The underlying Olympus SMT membership proof.
    pub smt_proof: Proof,
}

impl SealedManifest {
    /// Produce an inclusion proof for `(shard_id, record_id, version)`.
    ///
    /// Errors with [`ManifestError::RecordNotFound`] if the record is not in the
    /// sealed dataset (use [`prove_exclusion`](Self::prove_exclusion) instead).
    pub fn prove_inclusion(
        &self,
        shard_id: &str,
        record_id: &str,
        version: u64,
    ) -> Result<RecordProofBundle> {
        let key = record_tree_key(shard_id, record_id, version);
        match self.batch.prove(&key) {
            Proof::Existence(p) => {
                let content_hash = hex::encode(p.value_hash);
                Ok(RecordProofBundle {
                    schema: RECORD_PROOF_SCHEMA.to_string(),
                    dataset_id: self.manifest.dataset_id.clone(),
                    version: self.manifest.version,
                    manifest_root: self.manifest.manifest_root.clone(),
                    shard_id: shard_id.to_string(),
                    record_id: record_id.to_string(),
                    record_version: version,
                    kind: ProofKind::Inclusion,
                    content_hash,
                    smt_proof: Proof::Existence(p),
                })
            }
            Proof::NonExistence(_) => Err(ManifestError::RecordNotFound {
                shard_id: shard_id.to_string(),
                record_id: record_id.to_string(),
            }),
        }
    }

    /// Produce an exclusion (non-membership) proof for `(shard_id, record_id,
    /// version)`.
    ///
    /// Errors with [`ManifestError::RecordPresent`] if the record *is* in the
    /// sealed dataset.
    pub fn prove_exclusion(
        &self,
        shard_id: &str,
        record_id: &str,
        version: u64,
    ) -> Result<RecordProofBundle> {
        let key = record_tree_key(shard_id, record_id, version);
        match self.batch.prove(&key) {
            Proof::NonExistence(p) => Ok(RecordProofBundle {
                schema: RECORD_PROOF_SCHEMA.to_string(),
                dataset_id: self.manifest.dataset_id.clone(),
                version: self.manifest.version,
                manifest_root: self.manifest.manifest_root.clone(),
                shard_id: shard_id.to_string(),
                record_id: record_id.to_string(),
                record_version: version,
                kind: ProofKind::Exclusion,
                content_hash: String::new(),
                smt_proof: Proof::NonExistence(p),
            }),
            Proof::Existence(_) => Err(ManifestError::RecordPresent {
                shard_id: shard_id.to_string(),
                record_id: record_id.to_string(),
            }),
        }
    }
}

/// Outcome of verifying a [`RecordProofBundle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The proof is valid and anchored to the expected root.
    Valid,
    /// The proof's claimed root does not match the expected (anchored) root.
    RootMismatch,
    /// The `(shard_id, record_id, version)` does not match the proof's key.
    KeyMismatch,
    /// For inclusion: the stated content hash disagrees with the committed leaf.
    ContentMismatch,
    /// The proof kind disagrees with the SMT proof variant.
    KindMismatch,
    /// The SMT membership proof itself did not verify.
    SmtInvalid,
}

impl Verdict {
    /// `true` only for [`Verdict::Valid`].
    pub fn is_valid(self) -> bool {
        matches!(self, Verdict::Valid)
    }
}

/// Verify a record proof against an **authenticated** `expected_root` (e.g. a
/// `manifest_root` read from a ledger-anchored manifest blob). Returns a
/// [`Verdict`] describing the first failing check, or [`Verdict::Valid`].
///
/// The caller is responsible for establishing that `expected_root` is the real
/// committed root (by hashing the anchored manifest document); this function
/// proves the record relationship *given* that root.
pub fn verify(bundle: &RecordProofBundle, expected_root: &[u8; 32]) -> Result<Verdict> {
    let claimed_root = decode_hash32("manifest_root", &bundle.manifest_root)?;
    if &claimed_root != expected_root {
        return Ok(Verdict::RootMismatch);
    }

    // Bind the human-readable identity to the tree position.
    let expected_key = record_tree_key(&bundle.shard_id, &bundle.record_id, bundle.record_version);

    match (bundle.kind, &bundle.smt_proof) {
        (ProofKind::Inclusion, Proof::Existence(p)) => {
            if p.key != expected_key {
                return Ok(Verdict::KeyMismatch);
            }
            // The stated content hash must equal the committed leaf value.
            let stated = decode_hash32("content_hash", &bundle.content_hash)?;
            if p.value_hash != stated {
                return Ok(Verdict::ContentMismatch);
            }
            if verify_existence_proof(p, Some(expected_root)) {
                Ok(Verdict::Valid)
            } else {
                Ok(Verdict::SmtInvalid)
            }
        }
        (ProofKind::Exclusion, Proof::NonExistence(p)) => {
            if p.key != expected_key {
                return Ok(Verdict::KeyMismatch);
            }
            if verify_nonexistence_proof(p, Some(expected_root)) {
                Ok(Verdict::Valid)
            } else {
                Ok(Verdict::SmtInvalid)
            }
        }
        _ => Ok(Verdict::KindMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::seal;
    use crate::{DatasetMetadata, RecordEntry, RecordIndex, ShardRecords};

    fn sealed() -> SealedManifest {
        let index = RecordIndex {
            shards: vec![ShardRecords {
                shard_id: "alpha".to_string(),
                records: vec![
                    RecordEntry {
                        record_id: "a-1".to_string(),
                        content_hash: "11".repeat(32),
                        version: 1,
                        byte_size: None,
                    },
                    RecordEntry {
                        record_id: "a-2".to_string(),
                        content_hash: "22".repeat(32),
                        version: 1,
                        byte_size: None,
                    },
                ],
            }],
        };
        seal("ds", 1, 0, DatasetMetadata::default(), &index).unwrap()
    }

    #[test]
    fn inclusion_proof_roundtrips() {
        let s = sealed();
        let root = s.manifest_root();
        let bundle = s.prove_inclusion("alpha", "a-1", 1).unwrap();
        assert_eq!(bundle.kind, ProofKind::Inclusion);
        assert_eq!(bundle.content_hash, "11".repeat(32));
        assert_eq!(verify(&bundle, &root).unwrap(), Verdict::Valid);
        // Serializes and verifies after a round-trip.
        let json = serde_json::to_vec(&bundle).unwrap();
        let back: RecordProofBundle = serde_json::from_slice(&json).unwrap();
        assert_eq!(verify(&back, &root).unwrap(), Verdict::Valid);
    }

    #[test]
    fn exclusion_proof_roundtrips() {
        let s = sealed();
        let root = s.manifest_root();
        let bundle = s.prove_exclusion("alpha", "absent", 1).unwrap();
        assert_eq!(bundle.kind, ProofKind::Exclusion);
        assert_eq!(verify(&bundle, &root).unwrap(), Verdict::Valid);
    }

    #[test]
    fn cannot_prove_inclusion_of_absent_record() {
        let s = sealed();
        let err = s.prove_inclusion("alpha", "absent", 1).unwrap_err();
        assert!(matches!(err, ManifestError::RecordNotFound { .. }));
    }

    #[test]
    fn cannot_prove_exclusion_of_present_record() {
        let s = sealed();
        let err = s.prove_exclusion("alpha", "a-1", 1).unwrap_err();
        assert!(matches!(err, ManifestError::RecordPresent { .. }));
    }

    #[test]
    fn wrong_root_is_rejected() {
        let s = sealed();
        let bundle = s.prove_inclusion("alpha", "a-1", 1).unwrap();
        assert_eq!(verify(&bundle, &[0u8; 32]).unwrap(), Verdict::RootMismatch);
    }

    #[test]
    fn relabeled_record_id_is_rejected() {
        // A valid inclusion proof for a-1 cannot be passed off as a-2: the key
        // re-derivation from the (false) record_id won't match the proof key.
        let s = sealed();
        let root = s.manifest_root();
        let mut bundle = s.prove_inclusion("alpha", "a-1", 1).unwrap();
        bundle.record_id = "a-2".to_string();
        assert_eq!(verify(&bundle, &root).unwrap(), Verdict::KeyMismatch);
    }

    #[test]
    fn tampered_content_hash_is_rejected() {
        let s = sealed();
        let root = s.manifest_root();
        let mut bundle = s.prove_inclusion("alpha", "a-1", 1).unwrap();
        bundle.content_hash = "99".repeat(32);
        assert_eq!(verify(&bundle, &root).unwrap(), Verdict::ContentMismatch);
    }

    #[test]
    fn mismatched_kind_is_rejected() {
        let s = sealed();
        let root = s.manifest_root();
        let mut bundle = s.prove_inclusion("alpha", "a-1", 1).unwrap();
        bundle.kind = ProofKind::Exclusion;
        assert_eq!(verify(&bundle, &root).unwrap(), Verdict::KindMismatch);
    }
}
