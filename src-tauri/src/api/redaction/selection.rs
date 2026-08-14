// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! ADR-0037 object-based redaction selection, staging, and commit flow.
//!
//! Three endpoints, matching the ADR's three-step flow exactly:
//!
//! * `POST /redaction/page-objects` — `get_page_objects`: selectable objects on
//!   one page, in normalized page-space (ADR-0037's "Coordinate Contract").
//! * `POST /redaction/stage` — `stage_redaction`: canonicalize a proposed
//!   selection against the live manifest, compute backend-derived warnings, and
//!   hand back a short-lived `staging_id`.
//! * `POST /redaction/commit` — `commit_redaction`: re-validate the staging
//!   entry against the live manifest, refuse on drift or a `Blocking` warning,
//!   and produce the redacted artifact + V3 bundle (delegating to the same core
//!   [`super::redact::perform_redaction`] `POST /redaction/redact` uses).
//!
//! The frontend may display page images, bounds, and warnings, and may propose
//! `object_id`s — it is never the source of truth. Every one of these handlers
//! re-resolves the selection against the live, backend-owned
//! [`crate::zk::segment::SegmentManifest`] before it can affect a commit.

use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::pdf_describe::{borrow_regions, committed_object_regions};
use crate::zk::pdf_page_objects::{page_objects, PageObjects};
use crate::zk::pdf_redaction_warnings::compute_redaction_warnings;
use crate::zk::pdf_syntax::dict_region;
use crate::zk::segment::SegmentFormat;

use super::manifest::{load_object_manifest, validate_redaction_selection, ManifestSelector};
use super::redact::perform_redaction;
use super::staging::{
    manifest_version_digest, RedactionError, RedactionStageRequest, RedactionWarning,
};
use super::types::{err, require_redact_scope, ApiError};

/// Shared upload identity for all three ADR-0037 endpoints: the caller always
/// ships the committed original bytes (Olympus does not retain uploaded
/// document bytes server-side — same discipline as `/redaction/describe` and
/// `/redaction/redact`), plus the manifest selector.
#[derive(Deserialize)]
struct UploadedDoc {
    /// Base64 of the original (already-committed) document's raw bytes.
    original_base64: String,
    #[serde(default)]
    original_root: Option<String>,
    #[serde(default)]
    shard_id: Option<String>,
}

fn decode_original(original_base64: &str) -> Result<Vec<u8>, ApiError> {
    STANDARD.decode(original_base64.trim()).map_err(|e| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("original_base64: invalid base64: {e}"),
        )
    })
}

fn require_object_format(format: SegmentFormat) -> Result<(), ApiError> {
    if matches!(
        format,
        SegmentFormat::PdfObject | SegmentFormat::PdfXrefStream
    ) {
        Ok(())
    } else {
        Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "object selection is only available for PDF object commitments \
                 (pdf-object, pdf-xref-stream); this document is {}.",
                format.as_tag()
            ),
        ))
    }
}

fn recover_object_regions(
    original: &[u8],
    format: SegmentFormat,
) -> Result<BTreeMap<u32, Vec<u8>>, ApiError> {
    committed_object_regions(original, format).map_err(|e| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("could not parse committed objects: {e}"),
        )
    })
}

// ── POST /redaction/page-objects ───────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct PageObjectsRequest {
    /// BLAKE3 content hash (64-hex) of the original (already-committed) PDF.
    content_hash: String,
    #[serde(flatten)]
    doc: UploadedDoc,
    /// Zero-based page index (ADR-0037: "`page_num` is zero-based across all
    /// commands").
    page_num: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PageObjectsResponse {
    content_hash: String,
    #[serde(flatten)]
    page: PageObjects,
}

pub(crate) async fn get_page_objects(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<PageObjectsRequest>,
) -> Result<Json<PageObjectsResponse>, ApiError> {
    require_redact_scope(&auth)?;

    let content_hash = body.content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let original = decode_original(&body.doc.original_base64)?;
    let actual = blake3::hash(&original).to_hex().to_string();
    if actual != content_hash {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "uploaded bytes do not hash to content_hash — not the committed document.",
        ));
    }

    let manifest = load_object_manifest(
        &state,
        &content_hash,
        ManifestSelector::new(
            body.doc.shard_id.as_deref(),
            body.doc.original_root.as_deref(),
        ),
    )
    .await?;
    require_object_format(manifest.format)?;

    let regions = recover_object_regions(&original, manifest.format)?;
    // Fail closed on drift, exactly like `/redaction/describe`: the geometry
    // must be computed over the committed object set, never a partial one.
    let committed: HashSet<u32> = manifest.segments.iter().map(|s| s.segment_id).collect();
    let described: HashSet<u32> = regions.keys().copied().collect();
    if described != committed {
        tracing::error!(
            content_hash = %content_hash,
            "redaction/page-objects: parsed object set diverges from the committed manifest"
        );
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "parsed object set does not match the committed manifest — refusing to \
             return page geometry.",
        ));
    }

    let page = page_objects(&regions, body.page_num).ok_or_else(|| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "page_num does not exist or has no resolvable page geometry.",
        )
    })?;

    Ok(Json(PageObjectsResponse { content_hash, page }))
}

// ── POST /redaction/stage ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct StageRedactionRequest {
    content_hash: String,
    #[serde(flatten)]
    doc: UploadedDoc,
    page_num: u32,
    /// Proposed object ids to hide. Canonicalized (deduped, reordered by live
    /// manifest order) before staging — see
    /// [`crate::api::redaction::staging::canonicalize_object_ids`].
    object_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StageRedactionResponse {
    staging_id: String,
    doc_id: String,
    manifest_version: u64,
    object_ids: Vec<String>,
    warnings: Vec<RedactionWarning>,
    expires_at: chrono::DateTime<Utc>,
}

pub(crate) async fn stage_redaction(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<StageRedactionRequest>,
) -> Result<Json<StageRedactionResponse>, ApiError> {
    require_redact_scope(&auth)?;

    let content_hash = body.content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let original = decode_original(&body.doc.original_base64)?;
    let actual = blake3::hash(&original).to_hex().to_string();
    if actual != content_hash {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "uploaded bytes do not hash to content_hash — not the committed document.",
        ));
    }

    let manifest = load_object_manifest(
        &state,
        &content_hash,
        ManifestSelector::new(
            body.doc.shard_id.as_deref(),
            body.doc.original_root.as_deref(),
        ),
    )
    .await?;
    require_object_format(manifest.format)?;

    // The staging table's per-document lock serializes concurrent stage/commit
    // pairs on the same doc_id so a version check can't race a concurrent
    // commit into staging against a manifest that is about to change.
    let doc_lock = state.redaction_staging.document_lock(&content_hash);
    let _guard = doc_lock.lock().await;

    let regions = recover_object_regions(&original, manifest.format)?;
    let dicts: BTreeMap<u32, &[u8]> = borrow_regions(&regions)
        .iter()
        .map(|(&id, &r)| (id, dict_region(r)))
        .collect();
    let borrowed = borrow_regions(&regions);

    let manifest_version = manifest_version_digest(&manifest);
    let object_ids = super::staging::canonicalize_object_ids(&manifest, &body.object_ids)
        .map_err(redaction_err)?;
    let selected: Vec<u32> = object_ids
        .iter()
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();
    let warnings = compute_redaction_warnings(&dicts, &borrowed, &selected);

    if let Some(blocking) = warnings
        .iter()
        .find(|w| w.severity == crate::api::redaction::staging::RedactionWarningSeverity::Blocking)
    {
        return Err(redaction_err(RedactionError::BlockingRedactionWarning {
            code: blocking.code,
        }));
    }

    let staged = state
        .redaction_staging
        .stage(
            &manifest,
            RedactionStageRequest {
                doc_id: content_hash.clone(),
                page_num: body.page_num,
                manifest_version,
                object_ids: body.object_ids,
                warnings: warnings.clone(),
            },
            Utc::now(),
        )
        .map_err(redaction_err)?;

    Ok(Json(StageRedactionResponse {
        staging_id: staged.staging_id,
        doc_id: staged.entry.doc_id,
        manifest_version: staged.entry.manifest_version,
        object_ids: staged.entry.object_ids,
        warnings: staged.entry.warnings,
        expires_at: staged.entry.expires_at,
    }))
}

// ── POST /redaction/commit ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct CommitRedactionRequest {
    content_hash: String,
    #[serde(flatten)]
    doc: UploadedDoc,
    staging_id: String,
    /// Recipient field element (decimal string) for the V3 bundle, by
    /// convention the recipient's BJJ public-key X coordinate — same contract
    /// as `POST /redaction/redact`.
    recipient_id: String,
}

pub(crate) async fn commit_redaction(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<CommitRedactionRequest>,
) -> Result<Json<super::types::RedactionRedactResponse>, ApiError> {
    require_redact_scope(&auth)?;

    let content_hash = body.content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let original = decode_original(&body.doc.original_base64)?;
    let actual = blake3::hash(&original).to_hex().to_string();
    if actual != content_hash {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "uploaded bytes do not hash to content_hash — not the committed document.",
        ));
    }

    let doc_lock = state.redaction_staging.document_lock(&content_hash);
    let _guard = doc_lock.lock().await;

    // Load the *live* manifest — commit re-validates against current state, not
    // whatever was live when staging happened (ADR-0037 Commit Rules).
    let manifest = load_object_manifest(
        &state,
        &content_hash,
        ManifestSelector::new(
            body.doc.shard_id.as_deref(),
            body.doc.original_root.as_deref(),
        ),
    )
    .await?;
    require_object_format(manifest.format)?;

    let regions = recover_object_regions(&original, manifest.format)?;
    let dicts: BTreeMap<u32, &[u8]> = borrow_regions(&regions)
        .iter()
        .map(|(&id, &r)| (id, dict_region(r)))
        .collect();
    let borrowed = borrow_regions(&regions);

    let now = Utc::now();
    // `prepare_commit` needs the recomputed warnings up front to detect drift
    // and blocking severity; recompute against the *staged* object_ids (not
    // anything from this request) so a digest change only reflects a real
    // manifest/relationship change, matching ADR-0037's "commit re-validates
    // the staging entry". This peek performs no expiry/version/warning
    // validation itself — `prepare_commit` below does all of that.
    let staged_object_ids = state
        .redaction_staging
        .peek_pending_object_ids(&content_hash, &body.staging_id)
        .map_err(redaction_err)?;

    let selected: Vec<u32> = staged_object_ids
        .iter()
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();
    let recomputed_warnings = compute_redaction_warnings(&dicts, &borrowed, &selected);

    let entry = state
        .redaction_staging
        .prepare_commit(
            &content_hash,
            &body.staging_id,
            &manifest,
            &recomputed_warnings,
            now,
        )
        .map_err(redaction_err)?;

    let redacted_set: HashSet<u32> = entry
        .object_ids
        .iter()
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();
    validate_redaction_selection(&manifest, &redacted_set)?;

    let response = perform_redaction(
        &state,
        &original,
        &manifest,
        &redacted_set,
        &body.recipient_id,
    )
    .await?;

    let resulting_manifest_version = manifest_version_digest(&manifest);
    state
        .redaction_staging
        .mark_consumed(
            &content_hash,
            &body.staging_id,
            resulting_manifest_version,
            now,
        )
        .map_err(redaction_err)?;

    Ok(response)
}

fn redaction_err(e: RedactionError) -> ApiError {
    let status = match e {
        RedactionError::ObjectNotFound { .. }
        | RedactionError::ManifestVersionMismatch { .. }
        | RedactionError::InvalidObjectSelection
        | RedactionError::InvalidObjectGeometry { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        RedactionError::AlreadyRedacted { .. } => StatusCode::CONFLICT,
        RedactionError::StagingNotFound => StatusCode::NOT_FOUND,
        RedactionError::StagingExpired | RedactionError::StagingStale => StatusCode::CONFLICT,
        RedactionError::StagingAlreadyConsumed => StatusCode::CONFLICT,
        RedactionError::BlockingRedactionWarning { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        RedactionError::ProofGenerationFailed | RedactionError::ManifestUpdateConflict => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    (
        status,
        Json(
            serde_json::to_value(&e)
                .unwrap_or_else(|_| serde_json::json!({ "error": "redaction_error" })),
        ),
    )
}
