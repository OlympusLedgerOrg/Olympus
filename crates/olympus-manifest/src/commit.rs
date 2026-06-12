//! Building and sealing a [`DatasetManifest`] from a [`RecordIndex`].
//!
//! [`seal`] derives the SMT key/leaf for every record, builds the
//! [`SmtBatch`](crate::smt_batch::SmtBatch), and fills the manifest's
//! `manifest_root` and per-shard subtree roots. The returned [`SealedManifest`]
//! retains the batch so it can answer inclusion / exclusion proofs without
//! rebuilding the tree.

use std::collections::HashSet;

use olympus_crypto::leaf_hash;
use olympus_crypto::smt::{shard_prefix, shard_record_key, SHARD_PREFIX_BITS};

use crate::smt_batch::{BatchLeaf, SmtBatch};
use crate::{
    decode_hash32, DatasetManifest, DatasetMetadata, ManifestError, RecordIndex, Result,
    ShardEntry, MANIFEST_SCHEMA, RECORD_TYPE,
};

/// Derive the 32-byte SMT tree key for a record.
pub fn record_tree_key(shard_id: &str, record_id: &str, version: u64) -> [u8; 32] {
    let rk = olympus_crypto::record_key(RECORD_TYPE, record_id, version);
    shard_record_key(shard_id, &rk)
}

/// MSB-first bit path of a shard's 64-bit prefix (for subtree-root lookup).
fn shard_prefix_bits(shard_id: &str) -> Vec<u8> {
    let prefix = shard_prefix(shard_id);
    let mut bits = Vec::with_capacity(SHARD_PREFIX_BITS);
    for byte in &prefix {
        for i in 0..8u8 {
            bits.push((byte >> (7 - i)) & 1);
        }
    }
    bits
}

/// A manifest plus the batch SMT it was sealed from, ready to answer proofs.
#[derive(Debug)]
pub struct SealedManifest {
    /// The committed manifest document (compact).
    pub manifest: DatasetManifest,
    pub(crate) batch: SmtBatch,
}

impl SealedManifest {
    /// The dataset commitment (SMT global root).
    pub fn manifest_root(&self) -> [u8; 32] {
        self.batch.root()
    }
}

/// Validate `metadata`'s leaf-bound provenance triple is non-empty (the SMT leaf
/// domain requires it, ADR-0003/0004).
fn validate_metadata(metadata: &DatasetMetadata) -> Result<()> {
    if metadata.parser_id.is_empty() {
        return Err(ManifestError::EmptyIdentifier("parser_id"));
    }
    if metadata.canonical_parser_version.is_empty() {
        return Err(ManifestError::EmptyIdentifier("canonical_parser_version"));
    }
    if metadata.model_hash.is_empty() {
        return Err(ManifestError::EmptyIdentifier("model_hash"));
    }
    Ok(())
}

/// Build and seal a manifest at `version` from `index` and `metadata`.
///
/// Validates that shard and record identifiers are non-empty, record ids are
/// unique within a shard, and content hashes are 32-byte hex. Records are
/// folded into the Olympus SMT; the resulting `manifest_root` and per-shard
/// subtree roots are written into the returned manifest. `created_at` is Unix
/// seconds (the caller supplies it so the build is deterministic / testable).
pub fn seal(
    dataset_id: &str,
    version: u64,
    created_at: i64,
    metadata: DatasetMetadata,
    index: &RecordIndex,
) -> Result<SealedManifest> {
    validate_metadata(&metadata)?;

    let mut leaves: Vec<BatchLeaf> = Vec::with_capacity(index.record_count());
    let mut shard_entries: Vec<ShardEntry> = Vec::with_capacity(index.shards.len());
    let mut seen_shards: HashSet<&str> = HashSet::new();

    for shard in &index.shards {
        if shard.shard_id.is_empty() {
            return Err(ManifestError::EmptyIdentifier("shard_id"));
        }
        if !seen_shards.insert(shard.shard_id.as_str()) {
            return Err(ManifestError::DuplicateShard(shard.shard_id.clone()));
        }

        let mut seen_records: HashSet<(&str, u64)> = HashSet::new();
        let mut byte_size_total: u64 = 0;
        let mut has_byte_size = false;

        for rec in &shard.records {
            if rec.record_id.is_empty() {
                return Err(ManifestError::EmptyIdentifier("record_id"));
            }
            if !seen_records.insert((rec.record_id.as_str(), rec.version)) {
                return Err(ManifestError::DuplicateRecord {
                    shard_id: shard.shard_id.clone(),
                    record_id: rec.record_id.clone(),
                });
            }
            let value_hash = decode_hash32("content_hash", &rec.content_hash)?;
            let key = record_tree_key(&shard.shard_id, &rec.record_id, rec.version);
            let lh = leaf_hash(
                shard.shard_id.as_bytes(),
                &key,
                &value_hash,
                metadata.parser_id.as_bytes(),
                metadata.canonical_parser_version.as_bytes(),
                metadata.model_hash.as_bytes(),
            );
            if let Some(b) = rec.byte_size {
                byte_size_total = byte_size_total.saturating_add(b);
                has_byte_size = true;
            }
            leaves.push(BatchLeaf {
                key,
                leaf_hash: lh,
                value_hash,
                shard_id: shard.shard_id.clone(),
                parser_id: metadata.parser_id.clone(),
                canonical_parser_version: metadata.canonical_parser_version.clone(),
                model_hash: metadata.model_hash.clone(),
            });
        }

        shard_entries.push(ShardEntry {
            shard_id: shard.shard_id.clone(),
            // Filled after the batch is built.
            shard_root: String::new(),
            record_count: shard.records.len() as u64,
            byte_size: has_byte_size.then_some(byte_size_total),
        });
    }

    let record_count = leaves.len() as u64;
    let batch = SmtBatch::new(leaves).map_err(|i| {
        // A duplicate full key can only arise from a (record_id, version)
        // collision the per-shard check missed across shards mapping to the same
        // 64-bit prefix region — surface it as a duplicate record.
        ManifestError::DuplicateRecord {
            shard_id: "<key-collision>".to_string(),
            record_id: format!("leaf index {i}"),
        }
    })?;

    // Fill per-shard subtree roots from the sealed batch, then sort shards by id
    // for a canonical document order.
    for entry in &mut shard_entries {
        let root = batch.prefix_root(&shard_prefix_bits(&entry.shard_id));
        entry.shard_root = hex::encode(root);
    }
    shard_entries.sort_by(|a, b| a.shard_id.cmp(&b.shard_id));

    let manifest = DatasetManifest {
        schema: MANIFEST_SCHEMA.to_string(),
        dataset_id: dataset_id.to_string(),
        version,
        created_at,
        metadata,
        shards: shard_entries,
        manifest_root: hex::encode(batch.root()),
        record_count,
        parent: None,
        diff: None,
    };

    Ok(SealedManifest { manifest, batch })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RecordEntry, ShardRecords};

    fn idx() -> RecordIndex {
        RecordIndex {
            shards: vec![
                ShardRecords {
                    shard_id: "alpha".to_string(),
                    records: vec![
                        RecordEntry {
                            record_id: "a-1".to_string(),
                            content_hash: "11".repeat(32),
                            version: 1,
                            byte_size: Some(100),
                        },
                        RecordEntry {
                            record_id: "a-2".to_string(),
                            content_hash: "22".repeat(32),
                            version: 1,
                            byte_size: Some(200),
                        },
                    ],
                },
                ShardRecords {
                    shard_id: "beta".to_string(),
                    records: vec![RecordEntry {
                        record_id: "b-1".to_string(),
                        content_hash: "33".repeat(32),
                        version: 1,
                        byte_size: None,
                    }],
                },
            ],
        }
    }

    #[test]
    fn seal_fills_roots_counts_and_sorts_shards() {
        let s = seal("ds", 1, 1_700_000_000, DatasetMetadata::default(), &idx()).unwrap();
        assert_eq!(s.manifest.record_count, 3);
        assert_eq!(s.manifest.shards.len(), 2);
        // Sorted by shard_id.
        assert_eq!(s.manifest.shards[0].shard_id, "alpha");
        assert_eq!(s.manifest.shards[1].shard_id, "beta");
        // Roots are 64-hex and non-empty.
        assert_eq!(s.manifest.manifest_root.len(), 64);
        assert_eq!(s.manifest.shards[0].shard_root.len(), 64);
        // alpha has a byte_size total, beta does not.
        assert_eq!(s.manifest.shards[0].byte_size, Some(300));
        assert_eq!(s.manifest.shards[1].byte_size, None);
    }

    #[test]
    fn seal_is_deterministic_regardless_of_record_order() {
        let mut a = idx();
        let s1 = seal("ds", 1, 0, DatasetMetadata::default(), &a).unwrap();
        // Reverse record order within a shard; root must be identical.
        a.shards[0].records.reverse();
        let s2 = seal("ds", 1, 0, DatasetMetadata::default(), &a).unwrap();
        assert_eq!(s1.manifest.manifest_root, s2.manifest.manifest_root);
    }

    #[test]
    fn duplicate_record_id_rejected() {
        let mut i = idx();
        i.shards[0].records[1].record_id = "a-1".to_string();
        let err = seal("ds", 1, 0, DatasetMetadata::default(), &i).unwrap_err();
        assert!(matches!(err, ManifestError::DuplicateRecord { .. }));
    }

    #[test]
    fn empty_metadata_provenance_rejected() {
        let meta = DatasetMetadata {
            model_hash: String::new(),
            ..DatasetMetadata::default()
        };
        let err = seal("ds", 1, 0, meta, &idx()).unwrap_err();
        assert!(matches!(err, ManifestError::EmptyIdentifier("model_hash")));
    }

    #[test]
    fn bad_content_hash_rejected() {
        let mut i = idx();
        i.shards[0].records[0].content_hash = "abcd".to_string();
        let err = seal("ds", 1, 0, DatasetMetadata::default(), &i).unwrap_err();
        assert!(matches!(err, ManifestError::BadContentHash(_)));
    }

    #[test]
    fn empty_index_seals_to_empty_smt_root() {
        let empty = RecordIndex::default();
        let s = seal("ds", 1, 0, DatasetMetadata::default(), &empty).unwrap();
        assert_eq!(s.manifest.record_count, 0);
        // Equals the empty SMT root.
        let reference = olympus_crypto::smt::SparseMerkleTree::new();
        assert_eq!(s.manifest.manifest_root, hex::encode(reference.root()));
    }
}
