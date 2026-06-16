//! `POST /redaction/describe` — ADR-0029 Phase A1.
//!
//! Classify an already-committed PDF's indirect objects into human **labels +
//! previews** (page-grouped, by type) so the producer UI can show *what* each
//! object is instead of an opaque `#37 · 45592 bytes`. Scope-gated like the
//! other producer endpoints.
//!
//! **Presentation only.** The classification is recomputed on demand from the
//! uploaded bytes and is never persisted, never re-ingested, and never touches
//! the hiding leaf / manifest / root (ADR-0029 §A). The uploaded bytes must be
//! the committed document: `BLAKE3(bytes)` must equal the asserted
//! `content_hash`, and a manifest must exist for it.

use std::collections::HashSet;

use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::pdf_describe::describe_objects;
use crate::zk::segment::SegmentFormat;

use super::manifest::load_object_manifest;
use super::types::{
    err, require_redact_scope, ApiError, RedactionDescribeRequest, RedactionDescribeResponse,
};

pub(crate) async fn describe_redaction(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<RedactionDescribeRequest>,
) -> Result<Json<RedactionDescribeResponse>, ApiError> {
    require_redact_scope(&auth)?;

    let content_hash = body.content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let original = STANDARD.decode(body.original_base64.trim()).map_err(|e| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("original_base64: invalid base64: {e}"),
        )
    })?;

    // The uploaded bytes must BE the committed document: their BLAKE3 must equal
    // the asserted content_hash (matches ingest), so labels can't be computed
    // for bytes that aren't the committed object the manifest pins.
    let actual = blake3::hash(&original).to_hex().to_string();
    if actual != content_hash {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "uploaded bytes do not hash to content_hash — not the committed document.",
        ));
    }

    // Confirm it is on-ledger and recover the committed object set. This also
    // runs the manifest's own integrity cross-check (F-RD-2).
    let manifest = load_object_manifest(&state, &content_hash).await?;

    // A1 classifies the traditional-xref PDF object scheme only. Other formats
    // (modern xref-stream PDF, text-line, OOXML) are out of scope here; fail
    // closed with a clear message rather than mislabel.
    if manifest.format != SegmentFormat::PdfObject {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "describe is only available for traditional-xref pdf-object commitments (ADR-0029 A1).",
        ));
    }

    let described = describe_objects(&original).map_err(|e| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("could not classify objects: {e}"),
        )
    })?;

    // Fail closed if the classified object set does not exactly match the
    // committed manifest set. The parse here is the same `extract_object_spans`
    // ingest used, so they must be identical; a divergence (e.g. a parser
    // version drift between ingest and now) must surface, never silently drop
    // objects — a partial listing would hide objects the operator cannot then
    // select to redact. Same fail-closed discipline as `load_object_manifest`.
    let committed: HashSet<u32> = manifest.segments.iter().map(|s| s.segment_id).collect();
    let described_ids: HashSet<u32> = described.iter().map(|o| o.obj_id).collect();
    if described_ids != committed {
        tracing::error!(
            content_hash = %content_hash,
            described = described_ids.len(),
            committed = committed.len(),
            "redaction/describe: classified object set diverges from the committed manifest"
        );
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "classified object set does not match the committed manifest — refusing to \
             return a partial object listing.",
        ));
    }

    // Sets are equal; `described` is already obj-id-ascending (the manifest's
    // order), so return it as-is.
    Ok(Json(RedactionDescribeResponse {
        content_hash,
        format: manifest.format.as_tag().to_string(),
        object_count: described.len(),
        objects: described,
    }))
}
