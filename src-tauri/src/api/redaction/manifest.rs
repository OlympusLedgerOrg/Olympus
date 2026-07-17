//! Manifest loading + reveal-mask construction, and the
//! `GET /redaction/manifest/:content_hash` operator listing endpoint.

use std::collections::HashSet;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::segment::{
    variable_geometry, Segment, SegmentFormat, SegmentManifest, MAX_REDACTION_SEGMENTS,
};

use super::types::{
    db_err, err, require_redact_scope, ApiError, ManifestObject, RedactionManifestResponse,
};

// ── Manifest loading ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub(crate) struct ManifestSelector {
    shard_id: Option<String>,
    original_root: Option<String>,
}

impl ManifestSelector {
    pub(crate) fn new(shard_id: Option<&str>, original_root: Option<&str>) -> Self {
        Self {
            shard_id: shard_id
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
            original_root: original_root
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase),
        }
    }

    fn is_empty(&self) -> bool {
        self.shard_id.is_none() && self.original_root.is_none()
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn validate_manifest_selector(selector: &ManifestSelector) -> Result<(), ApiError> {
    if let Some(shard_id) = selector.shard_id.as_deref() {
        if !crate::api::ingest::sanitize_shard(shard_id) {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "shard_id must be 1-128 chars of [A-Za-z0-9:._-].",
            ));
        }
    }
    if let Some(original_root) = selector.original_root.as_deref() {
        if !is_hex64(original_root) {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "original_root must be a 64-character hex string.",
            ));
        }
    }
    Ok(())
}

/// Load + reconstruct the object manifest committed at ingest for `content_hash`.
///
/// `content_hash` is per-shard unique (migration 0038). A content-hash-only
/// lookup is accepted only while it is unambiguous; callers can bind the lookup
/// to `original_root` or `shard_id` to select a specific shard-scoped manifest.
pub(crate) async fn load_object_manifest(
    state: &AppState,
    content_hash: &str,
    selector: ManifestSelector,
) -> Result<SegmentManifest, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;
    validate_manifest_selector(&selector)?;

    #[derive(sqlx::FromRow)]
    struct ManifestRow {
        shard_id: String,
        format: String,
        original_root: String,
        tree_depth: i32,
        max_leaves: i32,
        segments: serde_json::Value,
    }

    let unscoped = selector.is_empty();
    let rows: Vec<ManifestRow> = match (
        selector.shard_id.as_deref(),
        selector.original_root.as_deref(),
    ) {
        (Some(shard_id), Some(original_root)) => sqlx::query_as::<_, ManifestRow>(
            "SELECT shard_id, format, original_root, tree_depth, max_leaves, segments \
                 FROM redaction_segment_manifests \
                 WHERE content_hash = $1 AND shard_id = $2 AND original_root = $3 \
                 ORDER BY created_at ASC LIMIT 1",
        )
        .bind(content_hash)
        .bind(shard_id)
        .bind(original_root)
        .fetch_all(pool)
        .await
        .map_err(db_err)?,
        (Some(shard_id), None) => sqlx::query_as::<_, ManifestRow>(
            "SELECT shard_id, format, original_root, tree_depth, max_leaves, segments \
                 FROM redaction_segment_manifests \
                 WHERE content_hash = $1 AND shard_id = $2 \
                 ORDER BY created_at ASC LIMIT 1",
        )
        .bind(content_hash)
        .bind(shard_id)
        .fetch_all(pool)
        .await
        .map_err(db_err)?,
        (None, Some(original_root)) => sqlx::query_as::<_, ManifestRow>(
            "SELECT shard_id, format, original_root, tree_depth, max_leaves, segments \
                 FROM redaction_segment_manifests \
                 WHERE content_hash = $1 AND original_root = $2 \
                 ORDER BY created_at ASC LIMIT 1",
        )
        .bind(content_hash)
        .bind(original_root)
        .fetch_all(pool)
        .await
        .map_err(db_err)?,
        (None, None) => sqlx::query_as::<_, ManifestRow>(
            "SELECT shard_id, format, original_root, tree_depth, max_leaves, segments \
                 FROM redaction_segment_manifests \
                 WHERE content_hash = $1 \
                 ORDER BY created_at ASC LIMIT 2",
        )
        .bind(content_hash)
        .fetch_all(pool)
        .await
        .map_err(db_err)?,
    };

    if unscoped && rows.len() > 1 {
        return Err(err(
            StatusCode::CONFLICT,
            "Multiple redaction manifests exist for this content_hash; provide original_root or shard_id.",
        ));
    }

    let row = rows.into_iter().next().ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "No object-level redaction manifest matches this content_hash and selector.",
        )
    })?;

    // The manifest row is not an independent trust anchor. Bind it to the
    // snapshot-committed ingest record for the same (content_hash, shard_id)
    // before accepting any of its leaves. A self-consistent forged manifest
    // (leaves + matching folded root) must not be able to mint a bundle for a
    // different root than the ledger actually anchored.
    let anchored_root = sqlx::query_scalar::<_, Option<String>>(
        "SELECT original_root FROM ingest_records \
         WHERE content_hash = $1 AND shard_id = $2 \
           AND original_root = $3 \
           AND snapshot_committed = TRUE AND original_root IS NOT NULL \
         ORDER BY ts ASC LIMIT 1",
    )
    .bind(content_hash)
    .bind(&row.shard_id)
    .bind(&row.original_root)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .flatten()
    .ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "redaction manifest has no snapshot-committed ingest anchor.",
        )
    })?;
    if !anchored_root.eq_ignore_ascii_case(&row.original_root) {
        tracing::error!(
            content_hash = %content_hash,
            shard_id = %row.shard_id,
            manifest_root = %row.original_root,
            anchored_root = %anchored_root,
            "redaction manifest root differs from its committed ingest record"
        );
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "redaction manifest is not bound to the committed ingest root.",
        ));
    }

    // Fail-closed on an unknown persisted format tag (audit: the format drives
    // `apply_redaction` dispatch — never default it).
    let format = SegmentFormat::from_tag(&row.format).ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest has an unrecognised commitment format.",
        )
    })?;

    #[derive(Deserialize)]
    struct SegmentRow {
        // Persisted as `obj_id` for back-compat with the original PDF schema; it
        // is the generic segment id for every format (PDF obj-id / text block).
        obj_id: u32,
        byte_offset: u64,
        byte_length: u64,
        leaf_hex: String,
        /// Optional producer-facing label (text line range; absent for PDF).
        #[serde(default)]
        label: Option<String>,
        /// Added after the initial schema. Missing values are handled by format
        /// below so PDFs fail closed while legacy non-PDF rows remain compatible.
        #[serde(default)]
        generation: Option<u16>,
    }
    let seg_rows: Vec<SegmentRow> = serde_json::from_value(row.segments).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("corrupt segment manifest: {e}"),
        )
    })?;

    // Defensive validation. This row is written by our own ingest path, but a
    // corrupt or forward-migrated manifest must fail cleanly (500), never panic
    // a fixed-size buffer copy downstream. ADR-0030 §1: the commitment is a
    // variable-depth fold over the N real leaves — `max_leaves == N` and
    // `tree_depth == ⌈log2 N⌉`, with `2 <= N <= MAX_REDACTION_SEGMENTS`.
    if !(0..=31).contains(&row.tree_depth) {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest tree_depth out of range.",
        ));
    }
    let n = seg_rows.len();
    if !(2..=MAX_REDACTION_SEGMENTS).contains(&n) {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest segment count is out of the redactable range [2, MAX_REDACTION_SEGMENTS].",
        ));
    }
    let (expected_depth, expected_max_leaves) = variable_geometry(n);
    if row.max_leaves < 0 || row.max_leaves as usize != expected_max_leaves {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest max_leaves must equal the segment count (ADR-0030 §1).",
        ));
    }
    let max_leaves = expected_max_leaves;
    if row.tree_depth as u8 != expected_depth {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest tree_depth must be ⌈log2 N⌉ for the segment count (ADR-0030 §1).",
        ));
    }
    let root_bytes = hex::decode(&row.original_root).map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest original_root is not valid hex.",
        )
    })?;
    if root_bytes.len() != 32 {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest original_root must be exactly 32 bytes.",
        ));
    }
    for s in &seg_rows {
        match hex::decode(&s.leaf_hex) {
            Ok(b) if b.len() == 32 => {}
            _ => {
                return Err(err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "manifest leaf_hex must be exactly 32 bytes.",
                ))
            }
        }
    }

    // The leaves must be persisted in the canonical obj-id-ascending order that
    // `extract_objects` (a `BTreeMap` walk) produces, with no duplicates. The
    // recompute_root cross-check below only binds the *leaf_hex* fold order, not
    // the obj_id↔leaf labelling — so without this a tampered row could relabel
    // obj_ids while keeping the leaf order (and root) intact, desyncing
    // `apply_redaction` / the V3 segment table from the folded leaves. Reject any
    // non-monotonic or duplicate sequence so those paths can rely on the order.
    if seg_rows.windows(2).any(|w| w[0].obj_id >= w[1].obj_id) {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest object ids are not strictly ascending and unique.",
        ));
    }

    // OOXML redaction (`segment::ooxml::apply_redaction`) indexes parts by
    // `segment_id` == canonical sorted position and matches each part by its
    // name label, so an OOXML manifest's ids MUST be dense `0..N-1` (no gaps /
    // offsets) and every row MUST carry a label. The strictly-ascending check
    // above is necessary but not sufficient — enforce the stronger invariant here
    // so a corrupt/tampered OOXML manifest fails fast at load.
    if format == SegmentFormat::OoxmlPart {
        let dense = seg_rows
            .iter()
            .enumerate()
            .all(|(i, s)| s.obj_id as usize == i);
        if !dense || seg_rows.iter().any(|s| s.label.is_none()) {
            return Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ooxml manifest segment ids must be dense (0..N-1) and every part must carry a label.",
            ));
        }
    }

    let pdf_format = matches!(
        format,
        SegmentFormat::PdfObject | SegmentFormat::PdfXrefStream
    );
    if pdf_format && seg_rows.iter().any(|s| s.generation.is_none()) {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "pdf manifest segment is missing its object generation.",
        ));
    }

    let segments = seg_rows
        .into_iter()
        .map(|s| Segment {
            segment_id: s.obj_id,
            label: s.label,
            generation: s.generation.unwrap_or(0),
            byte_offset: s.byte_offset,
            byte_length: s.byte_length,
            leaf_hex: s.leaf_hex,
        })
        .collect();

    let manifest = SegmentManifest {
        format,
        segments,
        original_root_hex: row.original_root,
        tree_depth: row.tree_depth as u8,
        max_leaves,
    };

    // Redteam follow-up (F-RD-2): the manifest row is the *sole* commitment to
    // the object root (leaves + root stored side by side, no independent signed
    // anchor). Recompute the root from the persisted leaves and require it to
    // equal the stored `original_root` before this manifest is used to build a
    // witness. A consistent leaf-tamper would otherwise yield a self-consistent
    // proof over an attacker tree; this binds "the stored root is genuinely the
    // Merkle root of these stored leaves" and fails closed (500) on any
    // corrupt / partially-tampered / forward-migrated row.
    let recomputed = manifest.recompute_root().map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("manifest leaf fold failed: {e}"),
        )
    })?;
    if !recomputed.eq_ignore_ascii_case(&manifest.original_root_hex) {
        tracing::error!(
            content_hash = %content_hash,
            stored_root = %manifest.original_root_hex,
            recomputed_root = %recomputed,
            "redaction manifest original_root does not match the fold of its own \
             leaves — refusing to build a witness from a tampered or corrupt manifest"
        );
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest original_root is inconsistent with its persisted object leaves.",
        ));
    }

    Ok(manifest)
}

/// Validate the producer's redaction selection against `manifest` (ADR-0030 §3):
/// every `redacted` id must exist, and a producer must not mint an all-redacted
/// **or** none-redacted disclosure (the verifier accepts both, but the producer
/// refuses to issue them — ADR-0030 §3). Returns the revealed count.
pub(crate) fn validate_redaction_selection(
    manifest: &SegmentManifest,
    redacted: &HashSet<u32>,
) -> Result<usize, ApiError> {
    for id in redacted {
        if !manifest.segments.iter().any(|s| s.segment_id == *id) {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("redacted_obj_ids contains unknown segment {id}."),
            ));
        }
    }
    let revealed = manifest
        .segments
        .iter()
        .filter(|s| !redacted.contains(&s.segment_id))
        .count();
    if revealed == manifest.segments.len() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "redacted_obj_ids is empty — nothing to redact; commit the original normally.",
        ));
    }
    if revealed == 0 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "redacted_obj_ids hides every object — refusing to issue an empty disclosure.",
        ));
    }
    Ok(revealed)
}

// ── GET /redaction/manifest/:content_hash ─────────────────────────────────────
//
// Operator-facing object listing for the producer UI: given an already-committed
// document's content_hash, return its committed objects (id + byte length) so a
// redactor can pick which to hide. Scope-gated like the producer endpoints —
// the object structure of a committed document is operator information.

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ManifestSelectorQuery {
    #[serde(default)]
    shard_id: Option<String>,
    #[serde(default)]
    original_root: Option<String>,
}

pub(crate) async fn get_manifest(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(content_hash): Path<String>,
    Query(query): Query<ManifestSelectorQuery>,
) -> Result<Json<RedactionManifestResponse>, ApiError> {
    require_redact_scope(&auth)?;

    let content_hash = content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let manifest = load_object_manifest(
        &state,
        &content_hash,
        ManifestSelector::new(query.shard_id.as_deref(), query.original_root.as_deref()),
    )
    .await?;
    let objects: Vec<ManifestObject> = manifest
        .segments
        .iter()
        .map(|s| ManifestObject {
            segment_id: s.segment_id,
            byte_length: s.byte_length,
            label: s.label.clone(),
        })
        .collect();

    Ok(Json(RedactionManifestResponse {
        content_hash,
        format: manifest.format.as_tag().to_string(),
        original_root: manifest.original_root_hex,
        object_count: objects.len(),
        objects,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_selector_normalizes_blank_and_uppercase_fields() {
        let root = "AA".repeat(32);
        let expected_root = "aa".repeat(32);
        let selector = ManifestSelector::new(Some(" files "), Some(&root));

        assert_eq!(selector.shard_id.as_deref(), Some("files"));
        assert_eq!(
            selector.original_root.as_deref(),
            Some(expected_root.as_str())
        );
        assert!(!selector.is_empty());
        validate_manifest_selector(&selector).unwrap();
    }

    #[test]
    fn manifest_selector_rejects_invalid_shard_and_root() {
        let bad_shard = ManifestSelector::new(Some("bad/slash"), None);
        assert_eq!(
            validate_manifest_selector(&bad_shard).unwrap_err().0,
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let bad_root = ManifestSelector::new(None, Some("abcd"));
        assert_eq!(
            validate_manifest_selector(&bad_root).unwrap_err().0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}
