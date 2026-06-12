//! Olympus dataset manifests (ADR-0027).
//!
//! A **dataset manifest** turns a versioned dataset of up to millions of records
//! into a single cryptographic commitment — the `manifest_root` — that an
//! Olympus node can anchor with one ledger commit, and that any party can later
//! use to verify, offline, that a specific record *is* (inclusion) or *is not*
//! (exclusion) part of that exact dataset version.
//!
//! ## Design
//!
//! The `manifest_root` is the global root of the Olympus 256-height Sparse
//! Merkle Tree ([`olympus_crypto::smt`]) over every record, where each record is
//! a leaf keyed by `shard_record_key(shard_id, record_key(record_type,
//! record_id, version))` and valued by the record's BLAKE3 content hash. Reusing
//! the SMT — rather than a bespoke tree — buys three things:
//!
//! * **Sound exclusion.** A sparse-tree non-membership proof is sound against an
//!   adversarial committer: the key path is fixed by the record id, and the
//!   empty-leaf sentinel cannot be forged. (A sorted-leaf tree cannot prove
//!   non-membership without revealing the whole set.)
//! * **Verifier reuse.** Roots and proofs are byte-identical to what the desktop
//!   node produces, so the existing Rust/JavaScript verifiers and the
//!   `document_existence` / `non_existence` ZK circuits validate manifest proofs
//!   unchanged.
//! * **Compact commit.** The committed manifest *document* carries only dataset
//!   metadata, the per-shard subtree roots, and the `manifest_root` — never the
//!   record list — so one small blob commits an arbitrarily large dataset. The
//!   full record→hash mapping ([`RecordIndex`]) is the prover's working set and
//!   is never embedded in the commitment.
//!
//! ## Modules
//!
//! * [`commit`] — build the SMT, compute roots, seal a [`DatasetManifest`].
//! * [`proof`] — generate and verify record-level inclusion / exclusion proofs.
//! * [`diff`] — incremental version commits and version-link verification.
//! * [`smt_batch`] — the memory-light batch SMT builder used by the above.

#![forbid(unsafe_code)]

pub mod commit;
pub mod diff;
pub mod error;
pub mod proof;
pub mod smt_batch;

pub use error::{ManifestError, Result};

use serde::{Deserialize, Serialize};

/// Schema identifier embedded in every committed manifest document.
pub const MANIFEST_SCHEMA: &str = "olympus.dataset-manifest/v1";

/// Record-type tag folded into each record's key. A single per-protocol value
/// keeps manifest keys reproducible without a per-record type field.
pub const RECORD_TYPE: &str = "olympus.dataset-record";

/// Default parser id stamped into leaves when metadata omits one (ADR-0003).
pub const DEFAULT_PARSER_ID: &str = "olympus.manifest@v1";
/// Default canonical parser version (ADR-0003).
pub const DEFAULT_PARSER_VERSION: &str = "v1";
/// Default model hash (ADR-0004).
pub const DEFAULT_MODEL_HASH: &str = "none";

fn default_version() -> u64 {
    1
}

/// Dataset-level provenance bound into the commitment.
///
/// `parser_id` / `canonical_parser_version` (ADR-0003) and `model_hash`
/// (ADR-0004) are folded into **every** leaf, so they are part of the
/// `manifest_root`: a verifier that recomputes a leaf must use the same triple.
/// The remaining fields are descriptive and travel inside the committed blob (so
/// they are tamper-evident via the blob's content hash) but are not folded into
/// the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetMetadata {
    /// Human-readable dataset name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Free-text description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// SPDX-style license identifier or text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Provenance / source-of-truth URL or description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Parser id bound into every leaf (ADR-0003). Non-empty.
    pub parser_id: String,
    /// Canonical parser version bound into every leaf (ADR-0003). Non-empty.
    pub canonical_parser_version: String,
    /// Model-artifact hash bound into every leaf (ADR-0004). Non-empty.
    pub model_hash: String,
}

impl Default for DatasetMetadata {
    fn default() -> Self {
        Self {
            name: None,
            description: None,
            license: None,
            source: None,
            parser_id: DEFAULT_PARSER_ID.to_string(),
            canonical_parser_version: DEFAULT_PARSER_VERSION.to_string(),
            model_hash: DEFAULT_MODEL_HASH.to_string(),
        }
    }
}

/// One record in a [`RecordIndex`] (prover-side working set; never committed
/// inline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordEntry {
    /// Caller-stable record identifier, unique within its shard.
    pub record_id: String,
    /// Lower-hex BLAKE3 content hash of the record bytes (exactly 64 chars).
    pub content_hash: String,
    /// Record version (default 1). Folded into the record key, so v1 and v2 of
    /// the same `record_id` are distinct leaves.
    #[serde(default = "default_version")]
    pub version: u64,
    /// Optional byte size, summed into the shard's `byte_size` (informational).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_size: Option<u64>,
}

/// The full record set for one shard. Part of the prover's [`RecordIndex`], not
/// the committed manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardRecords {
    /// Shard identifier.
    pub shard_id: String,
    /// All records in the shard.
    pub records: Vec<RecordEntry>,
}

/// The complete record→hash mapping for a dataset version: the prover's working
/// set used to build the SMT and answer proofs. Large (one entry per record);
/// committed only by reference, via the [`DatasetManifest::manifest_root`] it
/// produces.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordIndex {
    /// Shards, each with its full record list.
    pub shards: Vec<ShardRecords>,
}

impl RecordIndex {
    /// Total record count across all shards.
    pub fn record_count(&self) -> usize {
        self.shards.iter().map(|s| s.records.len()).sum()
    }
}

/// A per-shard summary inside the committed manifest document: the shard's SMT
/// subtree root and record count. Compact — no record list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardEntry {
    /// Shard identifier.
    pub shard_id: String,
    /// Lower-hex SMT subtree root for this shard (`shard_subtree_root`).
    pub shard_root: String,
    /// Number of records committed under this shard.
    pub record_count: u64,
    /// Sum of record byte sizes, when known (informational).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_size: Option<u64>,
}

/// A reference to the parent version in an incremental commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentRef {
    /// Parent dataset version number.
    pub version: u64,
    /// Parent `manifest_root` (lower-hex). The version-link proof binds this.
    pub manifest_root: String,
}

/// A compact summary of the diff that produced this version (counts + the
/// commitment over the change set). The full added/removed record lists live in
/// a separate [`diff::ManifestDiff`] artifact, committed by reference via
/// `diff_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Number of records added relative to the parent.
    pub added: u64,
    /// Number of records removed relative to the parent.
    pub removed: u64,
    /// Lower-hex commitment over the ordered change set (see [`diff`]).
    pub diff_root: String,
}

/// The committed dataset-manifest document.
///
/// This is the small blob an Olympus node commits (e.g. via `/ingest/files`):
/// its content hash anchors the whole dataset version, and `manifest_root` is
/// the value any verifier checks record proofs against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetManifest {
    /// Always [`MANIFEST_SCHEMA`].
    pub schema: String,
    /// Logical dataset identifier (stable across versions).
    pub dataset_id: String,
    /// Monotonic version number for this dataset.
    pub version: u64,
    /// Creation time (Unix seconds). Descriptive; the authoritative timestamp is
    /// the ledger anchor of this blob.
    pub created_at: i64,
    /// Dataset provenance and metadata.
    pub metadata: DatasetMetadata,
    /// Per-shard subtree roots and counts, sorted by `shard_id`.
    pub shards: Vec<ShardEntry>,
    /// The dataset commitment: the SMT global root over every record.
    pub manifest_root: String,
    /// Total record count across all shards.
    pub record_count: u64,
    /// Parent version reference for incremental commits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ParentRef>,
    /// Diff summary for incremental commits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<DiffSummary>,
}

impl DatasetManifest {
    /// Serialize to canonical JSON bytes (JCS / RFC 8785). This is the exact
    /// byte string whose BLAKE3 hash is committed to the ledger, so it must be
    /// reproducible across implementations.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let raw = serde_json::to_vec(self)?;
        olympus_crypto::canonical::canonicalize_bytes(&raw)
            .map_err(|e| ManifestError::Canonical(e.to_string()))
    }

    /// BLAKE3 content hash of the canonical bytes — the value the ledger commit
    /// binds, and the handle a verifier uses to fetch the anchored manifest.
    pub fn content_hash(&self) -> Result<[u8; 32]> {
        Ok(olympus_crypto::hash_bytes(&self.to_canonical_bytes()?))
    }

    /// Parse a manifest from (possibly non-canonical) JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Decode `manifest_root` into raw bytes — the anchor a verifier checks
    /// record proofs against.
    pub fn root_bytes(&self) -> Result<[u8; 32]> {
        decode_hash32("manifest_root", &self.manifest_root)
    }
}

/// Decode a 64-char lower-hex string into a 32-byte array, attributing failures
/// to `field`.
pub(crate) fn decode_hash32(field: &'static str, s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|source| ManifestError::Hex { field, source })?;
    if bytes.len() != 32 {
        return Err(ManifestError::BadContentHash(s.to_string()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_canonical_bytes_are_stable_and_hashable() {
        let m = DatasetManifest {
            schema: MANIFEST_SCHEMA.to_string(),
            dataset_id: "demo".to_string(),
            version: 1,
            created_at: 1_700_000_000,
            metadata: DatasetMetadata::default(),
            shards: vec![ShardEntry {
                shard_id: "files".to_string(),
                shard_root: "00".repeat(32),
                record_count: 0,
                byte_size: None,
            }],
            manifest_root: "11".repeat(32),
            record_count: 0,
            parent: None,
            diff: None,
        };
        let a = m.to_canonical_bytes().unwrap();
        let b = m.to_canonical_bytes().unwrap();
        assert_eq!(a, b);
        // Round-trips through JSON.
        let parsed = DatasetManifest::from_json(&a).unwrap();
        assert_eq!(parsed, m);
        // Content hash is deterministic.
        assert_eq!(m.content_hash().unwrap(), olympus_crypto::hash_bytes(&a));
    }

    #[test]
    fn decode_hash32_validates_length() {
        assert!(decode_hash32("x", &"ab".repeat(32)).is_ok());
        assert!(matches!(
            decode_hash32("x", "abcd"),
            Err(ManifestError::BadContentHash(_))
        ));
        assert!(matches!(
            decode_hash32("x", "zz"),
            Err(ManifestError::Hex { .. })
        ));
    }
}
