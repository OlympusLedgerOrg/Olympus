//! Manifest loading + reveal-mask construction, and the
//! `GET /redaction/manifest/:content_hash` operator listing endpoint.

use std::collections::HashSet;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::segment::{Segment, SegmentFormat, SegmentManifest, MAX_SEGMENTS};

use super::types::{
    db_err, err, require_redact_scope, ApiError, ManifestObject, RedactionManifestResponse,
};

// ── Manifest loading ────────────────────────────────────────────────────────

/// Load + reconstruct the object manifest committed at ingest for `content_hash`.
///
/// `content_hash` is per-shard unique (migration 0038); resolve to the earliest
/// row so a later cross-shard commit can't supply the inputs for someone else's
/// redaction (audit A1, carried over from the chunk path).
pub(crate) async fn load_object_manifest(
    state: &AppState,
    content_hash: &str,
) -> Result<SegmentManifest, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    #[derive(sqlx::FromRow)]
    struct ManifestRow {
        format: String,
        original_root: String,
        tree_depth: i32,
        max_leaves: i32,
        segments: serde_json::Value,
    }

    let row: ManifestRow = sqlx::query_as::<_, ManifestRow>(
        "SELECT format, original_root, tree_depth, max_leaves, segments \
         FROM redaction_segment_manifests \
         WHERE content_hash = $1 \
         ORDER BY created_at ASC LIMIT 1",
    )
    .bind(content_hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "No object-level redaction manifest for this content_hash — the \
             document is not on-ledger, or was committed as an unsupported / \
             opaque-binary (chunk) record that isn't object-redactable.",
        )
    })?;

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
    }
    let seg_rows: Vec<SegmentRow> = serde_json::from_value(row.segments).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("corrupt segment manifest: {e}"),
        )
    })?;

    // Defensive validation. This row is written by our own ingest path, but a
    // corrupt or forward-migrated manifest must fail cleanly (500), never panic
    // a fixed-size buffer copy downstream: `build_redaction_bundle`'s
    // original_root decode and `witness_inputs`' per-leaf decode both write into
    // a `[u8; 32]` and assume an exactly-`MAX_OBJECTS`-leaf tree.
    if !(0..=31).contains(&row.tree_depth) {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest tree_depth out of range.",
        ));
    }
    // `checked_shl` keeps this sound regardless of `usize` width (a future
    // 32-bit target wouldn't silently wrap); the `0..=31` bound above already
    // keeps the shift in range, so `None` here is unreachable but fails closed.
    let max_leaves = 1usize.checked_shl(row.tree_depth as u32).ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest tree_depth out of range.",
        )
    })?;
    if row.max_leaves < 0 || row.max_leaves as usize != max_leaves {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest max_leaves inconsistent with tree_depth.",
        ));
    }
    if seg_rows.len() > MAX_SEGMENTS || seg_rows.len() > max_leaves {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest object count exceeds tree capacity.",
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
    // `apply_redaction` / `build_reveal_mask` from the witness leaves. Reject any
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

    let segments = seg_rows
        .into_iter()
        .map(|s| Segment {
            segment_id: s.obj_id,
            label: s.label,
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

/// Build the `MAX_OBJECTS`-wide reveal mask (real objects in obj-id order, then
/// zero-padding which is never revealed) and the revealed count. Errors if a
/// requested id is unknown, if nothing is redacted, or if everything is.
pub(crate) fn build_reveal_mask(
    manifest: &SegmentManifest,
    redacted: &HashSet<u32>,
) -> Result<(Vec<bool>, usize), ApiError> {
    for id in redacted {
        if !manifest.segments.iter().any(|s| s.segment_id == *id) {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("redacted_obj_ids contains unknown segment {id}."),
            ));
        }
    }
    let mut mask = vec![false; MAX_SEGMENTS];
    for (i, s) in manifest.segments.iter().enumerate() {
        mask[i] = !redacted.contains(&s.segment_id);
    }
    let revealed = mask.iter().filter(|&&b| b).count();
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
    Ok((mask, revealed))
}

// ── GET /redaction/manifest/:content_hash ─────────────────────────────────────
//
// Operator-facing object listing for the producer UI: given an already-committed
// document's content_hash, return its committed objects (id + byte length) so a
// redactor can pick which to hide. Scope-gated like the producer endpoints —
// the object structure of a committed document is operator information.

pub(crate) async fn get_manifest(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(content_hash): Path<String>,
) -> Result<Json<RedactionManifestResponse>, ApiError> {
    require_redact_scope(&auth)?;

    let content_hash = content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let manifest = load_object_manifest(&state, &content_hash).await?;
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
