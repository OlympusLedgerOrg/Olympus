//! Ephemeral object-redaction staging state (ADR-0037).
//!
//! The table is deliberately in-memory: it gates a short-lived UI selection
//! against the canonical segment manifest, but it is not a durable draft system.

use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::zk::segment::SegmentManifest;

pub const DEFAULT_STAGING_TTL: Duration = Duration::minutes(15);
pub const STAGING_CLEANUP_INTERVAL: StdDuration = StdDuration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RedactionWarningSeverity {
    Info,
    Warning,
    Blocking,
}

impl RedactionWarningSeverity {
    fn as_tag(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Blocking => "blocking",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RedactionWarningCode {
    SharedStream,
    SharedXObject,
    AmbiguousTextSpan,
    AnnotationAppearanceStream,
}

impl RedactionWarningCode {
    fn as_tag(self) -> &'static str {
        match self {
            Self::SharedStream => "shared_stream",
            Self::SharedXObject => "shared_xobject",
            Self::AmbiguousTextSpan => "ambiguous_text_span",
            Self::AnnotationAppearanceStream => "annotation_appearance_stream",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionWarning {
    pub code: RedactionWarningCode,
    pub severity: RedactionWarningSeverity,
    pub message: String,
    pub object_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(tag = "error", rename_all = "camelCase")]
pub enum RedactionError {
    #[error("object {object_id} was not found in the live manifest")]
    ObjectNotFound { object_id: String },
    #[error("object {object_id} is already redacted")]
    AlreadyRedacted { object_id: String },
    #[error("manifest version mismatch: expected {expected}, actual {actual}")]
    ManifestVersionMismatch { expected: u64, actual: u64 },
    #[error("staging record not found")]
    StagingNotFound,
    #[error("staging record expired")]
    StagingExpired,
    #[error("staging record is stale")]
    StagingStale,
    #[error("staging record was already consumed")]
    StagingAlreadyConsumed,
    #[error("blocking redaction warning: {code:?}")]
    BlockingRedactionWarning { code: RedactionWarningCode },
    #[error("proof generation failed")]
    ProofGenerationFailed,
    #[error("manifest update conflict")]
    ManifestUpdateConflict,
    #[error("invalid object selection")]
    InvalidObjectSelection,
    #[error("invalid object geometry for {object_id}")]
    InvalidObjectGeometry { object_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionStagingEntry {
    pub doc_id: String,
    pub page_num: u32,
    pub manifest_version: u64,
    /// Canonicalized: deduped and sorted by live manifest order.
    pub object_ids: Vec<String>,
    pub warnings: Vec<RedactionWarning>,
    pub warning_digest: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedStagingRecord {
    pub doc_id: String,
    pub consumed_at: DateTime<Utc>,
    pub resulting_manifest_version: u64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagingRecord {
    Pending(RedactionStagingEntry),
    Consumed(ConsumedStagingRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedRedaction {
    pub staging_id: String,
    pub entry: RedactionStagingEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionStageRequest {
    pub doc_id: String,
    pub page_num: u32,
    pub manifest_version: u64,
    pub object_ids: Vec<String>,
    pub warnings: Vec<RedactionWarning>,
}

#[derive(Default)]
pub struct RedactionStagingTable {
    records: Mutex<HashMap<String, StagingRecord>>,
    doc_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl RedactionStagingTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn document_lock(&self, doc_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let records = self.records.lock();
        let mut locks = self.doc_locks.lock();
        prune_doc_locks_locked(&records, &mut locks);
        locks
            .entry(doc_id.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    pub fn stage(
        &self,
        manifest: &SegmentManifest,
        request: RedactionStageRequest,
        now: DateTime<Utc>,
    ) -> Result<StagedRedaction, RedactionError> {
        self.stage_with_ttl(manifest, request, now, DEFAULT_STAGING_TTL)
    }

    pub fn stage_with_ttl(
        &self,
        manifest: &SegmentManifest,
        request: RedactionStageRequest,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> Result<StagedRedaction, RedactionError> {
        let actual = manifest_version_digest(manifest);
        if request.manifest_version != actual {
            return Err(RedactionError::ManifestVersionMismatch {
                expected: request.manifest_version,
                actual,
            });
        }

        let canonical_ids = canonicalize_object_ids(manifest, &request.object_ids)?;
        let warning_digest = warning_digest(&request.warnings);
        let entry = RedactionStagingEntry {
            doc_id: request.doc_id,
            page_num: request.page_num,
            manifest_version: actual,
            object_ids: canonical_ids,
            warnings: request.warnings,
            warning_digest,
            created_at: now,
            expires_at: now + ttl,
        };
        let staging_id = uuid::Uuid::new_v4().to_string();
        let mut records = self.records.lock();
        records.insert(staging_id.clone(), StagingRecord::Pending(entry.clone()));
        Ok(StagedRedaction { staging_id, entry })
    }

    pub fn prepare_commit(
        &self,
        doc_id: &str,
        staging_id: &str,
        live_manifest: &SegmentManifest,
        recomputed_warnings: &[RedactionWarning],
        now: DateTime<Utc>,
    ) -> Result<RedactionStagingEntry, RedactionError> {
        let records = self.records.lock();
        let record = records
            .get(staging_id)
            .ok_or(RedactionError::StagingNotFound)?;

        match record {
            StagingRecord::Consumed(consumed) => {
                if consumed.doc_id == doc_id && now <= consumed.expires_at {
                    Err(RedactionError::StagingAlreadyConsumed)
                } else {
                    Err(RedactionError::StagingNotFound)
                }
            }
            StagingRecord::Pending(entry) => {
                if entry.doc_id != doc_id {
                    return Err(RedactionError::StagingNotFound);
                }
                if now > entry.expires_at {
                    return Err(RedactionError::StagingExpired);
                }

                let actual = manifest_version_digest(live_manifest);
                if actual != entry.manifest_version {
                    return Err(RedactionError::StagingStale);
                }
                if warning_digest(recomputed_warnings) != entry.warning_digest {
                    return Err(RedactionError::StagingStale);
                }
                if let Some(code) = first_blocking_warning(&entry.warnings)
                    .or_else(|| first_blocking_warning(recomputed_warnings))
                {
                    return Err(RedactionError::BlockingRedactionWarning { code });
                }
                Ok(entry.clone())
            }
        }
    }

    pub fn mark_consumed(
        &self,
        doc_id: &str,
        staging_id: &str,
        resulting_manifest_version: u64,
        now: DateTime<Utc>,
    ) -> Result<(), RedactionError> {
        let mut records = self.records.lock();
        let record = records
            .get_mut(staging_id)
            .ok_or(RedactionError::StagingNotFound)?;

        let result = match record {
            StagingRecord::Consumed(consumed) => {
                if consumed.doc_id == doc_id && now <= consumed.expires_at {
                    Err(RedactionError::StagingAlreadyConsumed)
                } else {
                    Err(RedactionError::StagingNotFound)
                }
            }
            StagingRecord::Pending(entry) => {
                if entry.doc_id != doc_id {
                    return Err(RedactionError::StagingNotFound);
                }
                if now > entry.expires_at {
                    return Err(RedactionError::StagingExpired);
                }
                let expires_at = entry.expires_at;
                *record = StagingRecord::Consumed(ConsumedStagingRecord {
                    doc_id: doc_id.to_owned(),
                    consumed_at: now,
                    resulting_manifest_version,
                    expires_at,
                });
                Ok(())
            }
        };

        if result.is_ok() {
            let mut locks = self.doc_locks.lock();
            prune_doc_lock_locked(&records, &mut locks, doc_id);
        }

        result
    }

    pub fn purge_expired(&self, now: DateTime<Utc>) -> usize {
        let mut records = self.records.lock();
        let before = records.len();
        records.retain(|_, record| match record {
            StagingRecord::Pending(entry) => now <= entry.expires_at,
            StagingRecord::Consumed(consumed) => now <= consumed.expires_at,
        });
        let purged = before - records.len();

        let mut locks = self.doc_locks.lock();
        prune_doc_locks_locked(&records, &mut locks);
        purged
    }

    #[cfg(test)]
    fn record_count(&self) -> usize {
        self.records.lock().len()
    }

    #[cfg(test)]
    fn doc_lock_count(&self) -> usize {
        self.doc_locks.lock().len()
    }
}

pub fn spawn_redaction_staging_reaper(
    table: Arc<RedactionStagingTable>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(STAGING_CLEANUP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let purged = table.purge_expired(Utc::now());
            if purged > 0 {
                tracing::debug!(purged, "purged expired redaction staging records");
            }
        }
    })
}

fn prune_doc_locks_locked(
    records: &HashMap<String, StagingRecord>,
    locks: &mut HashMap<String, Arc<tokio::sync::Mutex<()>>>,
) {
    let active_docs: HashSet<&str> = records
        .values()
        .filter_map(|record| match record {
            StagingRecord::Pending(entry) => Some(entry.doc_id.as_str()),
            StagingRecord::Consumed(_) => None,
        })
        .collect();
    locks.retain(|doc_id, lock| {
        active_docs.contains(doc_id.as_str()) || Arc::strong_count(lock) > 1
    });
}

fn prune_doc_lock_locked(
    records: &HashMap<String, StagingRecord>,
    locks: &mut HashMap<String, Arc<tokio::sync::Mutex<()>>>,
    doc_id: &str,
) {
    if records.values().any(|record| match record {
        StagingRecord::Pending(entry) => entry.doc_id == doc_id,
        StagingRecord::Consumed(_) => false,
    }) {
        return;
    }

    let should_remove = locks
        .get(doc_id)
        .is_some_and(|lock| Arc::strong_count(lock) == 1);
    if should_remove {
        locks.remove(doc_id);
    }
}

pub fn manifest_version_digest(manifest: &SegmentManifest) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(b"OLY:REDACTION:MANIFEST-VERSION:V1");
    update_lp(&mut h, manifest.format.as_tag().as_bytes());
    update_lp(&mut h, manifest.original_root_hex.as_bytes());
    h.update(&(manifest.tree_depth as u64).to_be_bytes());
    h.update(&(manifest.max_leaves as u64).to_be_bytes());
    for segment in &manifest.segments {
        h.update(&segment.segment_id.to_be_bytes());
        h.update(&segment.byte_offset.to_be_bytes());
        h.update(&segment.byte_length.to_be_bytes());
        update_lp(&mut h, segment.leaf_hex.as_bytes());
        match &segment.label {
            Some(label) => {
                h.update(&[1]);
                update_lp(&mut h, label.as_bytes());
            }
            None => {
                h.update(&[0]);
            }
        }
    }
    let digest = h.finalize();
    u64::from_be_bytes(digest.as_bytes()[..8].try_into().expect("slice is 8 bytes"))
}

pub fn canonicalize_object_ids(
    manifest: &SegmentManifest,
    object_ids: &[String],
) -> Result<Vec<String>, RedactionError> {
    let requested: HashSet<String> = object_ids
        .iter()
        .map(|id| id.trim())
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if requested.is_empty() {
        return Err(RedactionError::InvalidObjectSelection);
    }

    for object_id in &requested {
        if !manifest
            .segments
            .iter()
            .any(|segment| segment.segment_id.to_string() == *object_id)
        {
            return Err(RedactionError::ObjectNotFound {
                object_id: object_id.clone(),
            });
        }
    }

    let canonical: Vec<String> = manifest
        .segments
        .iter()
        .map(|segment| segment.segment_id.to_string())
        .filter(|id| requested.contains(id))
        .collect();
    if canonical.len() == manifest.segments.len() {
        return Err(RedactionError::InvalidObjectSelection);
    }
    Ok(canonical)
}

pub fn warning_digest(warnings: &[RedactionWarning]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"OLY:REDACTION:WARNING-DIGEST:V1");
    for warning in warnings {
        update_lp(&mut h, warning.code.as_tag().as_bytes());
        update_lp(&mut h, warning.severity.as_tag().as_bytes());
        update_lp(&mut h, warning.message.as_bytes());
        h.update(&(warning.object_ids.len() as u64).to_be_bytes());
        for object_id in &warning.object_ids {
            update_lp(&mut h, object_id.as_bytes());
        }
    }
    h.finalize().to_hex().to_string()
}

fn first_blocking_warning(warnings: &[RedactionWarning]) -> Option<RedactionWarningCode> {
    warnings
        .iter()
        .find(|w| w.severity == RedactionWarningSeverity::Blocking)
        .map(|w| w.code)
}

fn update_lp(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::segment::{variable_geometry, Segment, SegmentFormat, SegmentManifest};

    fn manifest(ids: &[u32]) -> SegmentManifest {
        let (tree_depth, max_leaves) = variable_geometry(ids.len());
        SegmentManifest {
            format: SegmentFormat::PdfObject,
            segments: ids
                .iter()
                .enumerate()
                .map(|(i, id)| Segment {
                    segment_id: *id,
                    label: None,
                    byte_offset: (i as u64) * 10,
                    byte_length: 10,
                    leaf_hex: format!("{id:064x}"),
                })
                .collect(),
            original_root_hex: "11".repeat(32),
            tree_depth,
            max_leaves,
        }
    }

    fn warning(severity: RedactionWarningSeverity) -> RedactionWarning {
        RedactionWarning {
            code: RedactionWarningCode::SharedStream,
            severity,
            message: "shared stream".to_owned(),
            object_ids: vec!["2".to_owned()],
        }
    }

    #[test]
    fn canonicalizes_by_manifest_order_and_dedups() {
        let manifest = manifest(&[2, 4, 9]);
        let ids = vec!["9".to_owned(), "2".to_owned(), "2".to_owned()];
        let canonical = canonicalize_object_ids(&manifest, &ids).unwrap();
        assert_eq!(canonical, vec!["2", "9"]);
    }

    #[test]
    fn rejects_unknown_empty_and_all_object_selections() {
        let manifest = manifest(&[1, 2, 3]);
        assert!(matches!(
            canonicalize_object_ids(&manifest, &[]),
            Err(RedactionError::InvalidObjectSelection)
        ));
        assert!(matches!(
            canonicalize_object_ids(&manifest, &["99".to_owned()]),
            Err(RedactionError::ObjectNotFound { .. })
        ));
        assert!(matches!(
            canonicalize_object_ids(&manifest, &["1".to_owned(), "2".to_owned(), "3".to_owned()]),
            Err(RedactionError::InvalidObjectSelection)
        ));
    }

    #[test]
    fn manifest_version_changes_when_manifest_changes() {
        let mut a = manifest(&[1, 2, 3]);
        let b = manifest_version_digest(&a);
        a.segments[1].leaf_hex = "22".repeat(32);
        assert_ne!(b, manifest_version_digest(&a));
    }

    #[test]
    fn stage_rejects_stale_manifest_version() {
        let table = RedactionStagingTable::new();
        let manifest = manifest(&[1, 2, 3]);
        let err = table
            .stage(
                &manifest,
                RedactionStageRequest {
                    doc_id: "doc".to_owned(),
                    page_num: 0,
                    manifest_version: manifest_version_digest(&manifest) + 1,
                    object_ids: vec!["2".to_owned()],
                    warnings: vec![],
                },
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            RedactionError::ManifestVersionMismatch { .. }
        ));
    }

    #[test]
    fn table_locks_are_not_poisoned_by_panic() {
        let table = RedactionStagingTable::new();
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _records = table.records.lock();
            panic!("simulated panic while holding redaction staging records");
        }));
        assert!(panic_result.is_err());

        let manifest = manifest(&[1, 2, 3]);
        table
            .stage(
                &manifest,
                RedactionStageRequest {
                    doc_id: "doc".to_owned(),
                    page_num: 0,
                    manifest_version: manifest_version_digest(&manifest),
                    object_ids: vec!["2".to_owned()],
                    warnings: vec![],
                },
                Utc::now(),
            )
            .unwrap();
        assert_eq!(table.record_count(), 1);
    }

    #[test]
    fn prepare_commit_detects_warning_drift_and_blocking() {
        let table = RedactionStagingTable::new();
        let manifest = manifest(&[1, 2, 3]);
        let now = Utc::now();
        let staged = table
            .stage(
                &manifest,
                RedactionStageRequest {
                    doc_id: "doc".to_owned(),
                    page_num: 0,
                    manifest_version: manifest_version_digest(&manifest),
                    object_ids: vec!["2".to_owned()],
                    warnings: vec![warning(RedactionWarningSeverity::Warning)],
                },
                now,
            )
            .unwrap();

        let drift = table
            .prepare_commit("doc", &staged.staging_id, &manifest, &[], now)
            .unwrap_err();
        assert!(matches!(drift, RedactionError::StagingStale));

        let blocking = table
            .prepare_commit(
                "doc",
                &staged.staging_id,
                &manifest,
                &[warning(RedactionWarningSeverity::Blocking)],
                now,
            )
            .unwrap_err();
        assert!(matches!(blocking, RedactionError::StagingStale));
    }

    #[test]
    fn prepare_commit_refuses_blocking_warning_even_when_digest_matches() {
        let table = RedactionStagingTable::new();
        let manifest = manifest(&[1, 2, 3]);
        let now = Utc::now();
        let warnings = vec![warning(RedactionWarningSeverity::Blocking)];
        let staged = table
            .stage(
                &manifest,
                RedactionStageRequest {
                    doc_id: "doc".to_owned(),
                    page_num: 0,
                    manifest_version: manifest_version_digest(&manifest),
                    object_ids: vec!["2".to_owned()],
                    warnings: warnings.clone(),
                },
                now,
            )
            .unwrap();

        let err = table
            .prepare_commit("doc", &staged.staging_id, &manifest, &warnings, now)
            .unwrap_err();
        assert!(matches!(
            err,
            RedactionError::BlockingRedactionWarning {
                code: RedactionWarningCode::SharedStream
            }
        ));
    }

    #[test]
    fn purge_expired_prunes_doc_locks_without_active_records() {
        let table = RedactionStagingTable::new();
        let now = Utc::now();
        let lock = table.document_lock("doc");
        drop(lock);

        assert_eq!(table.doc_lock_count(), 1);
        assert_eq!(table.purge_expired(now), 0);
        assert_eq!(table.doc_lock_count(), 0);

        let manifest = manifest(&[1, 2, 3]);
        let staged = table
            .stage_with_ttl(
                &manifest,
                RedactionStageRequest {
                    doc_id: "doc".to_owned(),
                    page_num: 0,
                    manifest_version: manifest_version_digest(&manifest),
                    object_ids: vec!["2".to_owned()],
                    warnings: vec![],
                },
                now,
                Duration::seconds(5),
            )
            .unwrap();
        let lock = table.document_lock("doc");
        drop(lock);

        assert_eq!(table.doc_lock_count(), 1);
        assert_eq!(table.purge_expired(now + Duration::seconds(6)), 1);
        assert_eq!(table.record_count(), 0);
        assert_eq!(table.doc_lock_count(), 0);
        assert!(matches!(
            table.prepare_commit("doc", &staged.staging_id, &manifest, &[], now),
            Err(RedactionError::StagingNotFound)
        ));
    }

    #[test]
    fn mark_consumed_prunes_doc_lock_when_no_active_owner_remains() {
        let table = RedactionStagingTable::new();
        let manifest = manifest(&[1, 2, 3]);
        let now = Utc::now();
        let staged = table
            .stage(
                &manifest,
                RedactionStageRequest {
                    doc_id: "doc".to_owned(),
                    page_num: 0,
                    manifest_version: manifest_version_digest(&manifest),
                    object_ids: vec!["2".to_owned()],
                    warnings: vec![],
                },
                now,
            )
            .unwrap();

        let lock = table.document_lock("doc");
        table
            .mark_consumed(
                "doc",
                &staged.staging_id,
                manifest_version_digest(&manifest) + 1,
                now,
            )
            .unwrap();
        assert_eq!(table.doc_lock_count(), 1);

        drop(lock);
        assert_eq!(table.purge_expired(now), 0);
        assert_eq!(table.doc_lock_count(), 0);
    }

    #[test]
    fn consumed_staging_id_returns_consumed_until_tombstone_expiry() {
        let table = RedactionStagingTable::new();
        let manifest = manifest(&[1, 2, 3]);
        let now = Utc::now();
        let staged = table
            .stage_with_ttl(
                &manifest,
                RedactionStageRequest {
                    doc_id: "doc".to_owned(),
                    page_num: 0,
                    manifest_version: manifest_version_digest(&manifest),
                    object_ids: vec!["2".to_owned()],
                    warnings: vec![],
                },
                now,
                Duration::seconds(5),
            )
            .unwrap();
        table
            .prepare_commit("doc", &staged.staging_id, &manifest, &[], now)
            .unwrap();
        table
            .mark_consumed(
                "doc",
                &staged.staging_id,
                manifest_version_digest(&manifest) + 1,
                now,
            )
            .unwrap();

        assert!(matches!(
            table.prepare_commit("doc", &staged.staging_id, &manifest, &[], now),
            Err(RedactionError::StagingAlreadyConsumed)
        ));
        assert_eq!(table.purge_expired(now + Duration::seconds(6)), 1);
        assert_eq!(table.record_count(), 0);
        assert!(matches!(
            table.prepare_commit("doc", &staged.staging_id, &manifest, &[], now),
            Err(RedactionError::StagingNotFound)
        ));
    }
}
