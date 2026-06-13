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
use crate::zk::pdf_objects::{PdfObject, PdfObjectManifest, MAX_OBJECTS};

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
) -> Result<PdfObjectManifest, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    #[derive(sqlx::FromRow)]
    struct ManifestRow {
        original_root: String,
        tree_depth: i32,
        max_leaves: i32,
        segments: serde_json::Value,
    }

    let row: ManifestRow = sqlx::query_as::<_, ManifestRow>(
        "SELECT original_root, tree_depth, max_leaves, segments \
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
             document is not on-ledger, or was committed as a non-PDF (chunk) \
             record that isn't object-redactable.",
        )
    })?;

    #[derive(Deserialize)]
    struct SegmentRow {
        obj_id: u32,
        byte_offset: u64,
        byte_length: u64,
        leaf_hex: String,
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
    let max_leaves = 1usize << (row.tree_depth as u32);
    if row.max_leaves < 0 || row.max_leaves as usize != max_leaves {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest max_leaves inconsistent with tree_depth.",
        ));
    }
    if seg_rows.len() > MAX_OBJECTS || seg_rows.len() > max_leaves {
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

    let objects = seg_rows
        .into_iter()
        .map(|s| PdfObject {
            obj_id: s.obj_id,
            generation: 0, // not needed for witness / redaction; not persisted
            byte_offset: s.byte_offset,
            byte_length: s.byte_length,
            leaf_hex: s.leaf_hex,
        })
        .collect();

    let manifest = PdfObjectManifest {
        objects,
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
    manifest: &PdfObjectManifest,
    redacted: &HashSet<u32>,
) -> Result<(Vec<bool>, usize), ApiError> {
    for id in redacted {
        if !manifest.objects.iter().any(|o| o.obj_id == *id) {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("redacted_obj_ids contains unknown object {id}."),
            ));
        }
    }
    let mut mask = vec![false; MAX_OBJECTS];
    for (i, o) in manifest.objects.iter().enumerate() {
        mask[i] = !redacted.contains(&o.obj_id);
    }
    let revealed = mask.iter().filter(|&&b| b).count();
    if revealed == manifest.objects.len() {
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
        .objects
        .iter()
        .map(|o| ManifestObject {
            segment_id: o.obj_id,
            byte_length: o.byte_length,
        })
        .collect();

    Ok(Json(RedactionManifestResponse {
        content_hash,
        original_root: manifest.original_root_hex,
        object_count: objects.len(),
        objects,
    }))
}
