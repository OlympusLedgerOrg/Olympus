//! `POST /redaction/describe` — ADR-0029 Phase A1 + A.5.
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
use crate::zk::pdf_describe::{
    describe_objects, describe_objects_xref_stream, ObjectDescription, SegmentDescription,
};
use crate::zk::segment::SegmentFormat;

use super::manifest::{load_object_manifest, ManifestSelector};
use super::types::{
    err, require_redact_scope, ApiError, RedactionDescribeRequest, RedactionDescribeResponse,
};

/// The formats this endpoint can describe, for the rejection message. Built from
/// the same `cfg` that gates the match arm below, so the message can never
/// advertise a format this build does not actually handle.
#[cfg(feature = "textrun-segmenter")]
const SUPPORTED_FORMATS: &str = "pdf-object, pdf-xref-stream, pdf-textrun";
#[cfg(not(feature = "textrun-segmenter"))]
const SUPPORTED_FORMATS: &str = "pdf-object, pdf-xref-stream";

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
    let manifest = load_object_manifest(
        &state,
        &content_hash,
        ManifestSelector::new(body.shard_id.as_deref(), body.original_root.as_deref()),
    )
    .await?;

    // Classification covers both PDF **object** schemes — the traditional-xref
    // scheme (A1) and the modern cross-reference-stream scheme (A.5) — and the
    // word scheme (B-3), which lists committed *segments* rather than objects
    // because its leaf set is a partition of the artifact, not one leaf per
    // object. Each is described through the same extraction its segmenter
    // committed with, so the described set is the committed set. The remaining
    // formats (text-line, OOXML) have no PDF structure to classify; fail closed
    // with a clear message rather than mislabel.
    // Annotated rather than inferred: without `textrun-segmenter` the only arm
    // producing a non-empty `segments` is compiled out, and a bare `Vec::new()`
    // has no inferable element type in that configuration.
    let (objects, segments): (Vec<ObjectDescription>, Vec<SegmentDescription>) = match manifest
        .format
    {
        SegmentFormat::PdfObject => (
            describe_objects(&original).map_err(|e| {
                err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("could not classify objects: {e}"),
                )
            })?,
            Vec::new(),
        ),
        SegmentFormat::PdfXrefStream => (
            describe_objects_xref_stream(&original).map_err(|e| {
                err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("could not classify objects: {e}"),
                )
            })?,
            Vec::new(),
        ),
        #[cfg(feature = "textrun-segmenter")]
        SegmentFormat::PdfTextRun => (
            Vec::new(),
            crate::zk::segment::pdf_textrun::describe_segments(&original).map_err(|e| {
                err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("could not describe segments: {e}"),
                )
            })?,
        ),
        _ => {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("describe is only available for PDF commitments ({SUPPORTED_FORMATS})."),
            ))
        }
    };

    // Fail closed if the described set does not exactly match the committed
    // manifest set. The parse above is the same one the format's segmenter
    // committed with (`extract_object_spans` for pdf-object, `logical_objects`
    // for pdf-xref-stream, and for pdf-textrun the very same
    // `content_objects`/`word_ranges` walk `extract` uses), so they must be
    // identical; a divergence (e.g. a parser version drift between ingest and
    // now) must surface, never silently drop rows — a partial listing would hide
    // segments the operator cannot then select to redact. Same fail-closed
    // discipline as `load_object_manifest`.
    //
    // For pdf-textrun this check carries more weight than for the object
    // formats: the word ids are positional, so a drift would not merely drop
    // rows, it would slide every label onto the wrong word.
    let committed: HashSet<u32> = manifest.segments.iter().map(|s| s.segment_id).collect();
    let described_ids: HashSet<u32> = objects
        .iter()
        .map(|o| o.obj_id)
        .chain(segments.iter().map(|s| s.segment_id))
        .collect();
    if described_ids != committed {
        tracing::error!(
            content_hash = %content_hash,
            described = described_ids.len(),
            committed = committed.len(),
            "redaction/describe: described segment set diverges from the committed manifest"
        );
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "described set does not match the committed manifest — refusing to \
             return a partial listing.",
        ));
    }

    // Sets are equal; both listings are already in the manifest's own order
    // (obj-id-ascending / segment-id-ascending), so return them as-is.
    Ok(Json(RedactionDescribeResponse {
        content_hash,
        format: manifest.format.as_tag().to_string(),
        object_count: objects.len(),
        objects,
        segment_count: segments.len(),
        segments,
    }))
}
