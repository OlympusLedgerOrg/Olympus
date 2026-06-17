//! `POST /redaction/redact` — Olympus-owned segment redaction (ADR-0030 V3).
//!
//! Given the (already-committed) original document and the segment ids to hide,
//! apply the committed format's redaction transform
//! ([`crate::zk::segment::apply_redaction_with_spans`]) and return the redacted
//! artifact plus the **V3 signed-Merkle bundle** bound to it. The transform is
//! in-place NUL-fill for traditional PDF / text, and a canonical re-emit for
//! OOXML (Stored ZIP) and modern (xref-stream) PDFs. The uploaded bytes must
//! match the on-ledger document — their BLAKE3 hash resolves the manifest, and
//! the manifest's variable-depth root re-keys the ledger lookup (SR-DEC-1:
//! `content_hash` is NOT shipped in the bundle).

use std::collections::HashSet;

use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use olympus_crypto::redaction::derive_blinding;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::segment::apply_redaction_with_spans;

use super::bundle_v3::{self, V3Error, V3Segment};
use super::manifest::{load_object_manifest, validate_redaction_selection};
use super::types::{
    err, require_redact_scope, ApiError, RedactionRedactRequest, RedactionRedactResponse,
};

pub(crate) async fn redact_redaction(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<RedactionRedactRequest>,
) -> Result<Json<RedactionRedactResponse>, ApiError> {
    require_redact_scope(&auth)?;

    let original = STANDARD.decode(body.original_base64.trim()).map_err(|e| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("original_base64: invalid base64: {e}"),
        )
    })?;

    // content_hash = BLAKE3 of the raw bytes. It resolves the manifest and keys
    // the per-segment blinding derivation, but is NOT shipped in the V3 bundle
    // (SR-DEC-1 — it was a whole-document confirmation oracle). `derive_blinding`
    // takes the same raw 32-byte digest the ingest segmenters used.
    let content_digest = blake3::hash(&original);
    let content_hash = content_digest.to_hex().to_string();
    let content_hash_raw = content_digest.as_bytes();

    let manifest = load_object_manifest(&state, &content_hash).await?;

    // Producer rules (ADR-0030 §3): every redacted id must exist, and refuse an
    // all-redacted or none-redacted disclosure. The verifier accepts both; only
    // the producer declines to mint them.
    let redacted_set: HashSet<u32> = body.redacted_obj_ids.iter().copied().collect();
    validate_redaction_selection(&manifest, &redacted_set)?;

    // Apply the committed format's redaction transform and capture each segment's
    // byte span in the produced artifact (ADR-0030 §2a).
    let (artifact, spans) =
        apply_redaction_with_spans(&original, &manifest, &body.redacted_obj_ids)
            .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, &format!("redact: {e}")))?;
    let span_by_id: std::collections::HashMap<u32, (u64, u64)> = spans
        .iter()
        .map(|s| (s.segment_id, (s.artifact_offset, s.artifact_length)))
        .collect();

    // The server blind secret is required to publish revealed-segment blindings
    // (it was also required at ingest to build the manifest).
    let blind_secret = state.redaction_blind_secret.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "OLYMPUS_REDACTION_BLIND_SECRET unavailable — cannot issue object redactions.",
        )
    })?;
    // The Ed25519 bundle signing key (persistent — see OLYMPUS_INGEST_SIGNING_KEY).
    let signing_key = state.ingest_signing_key.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Redaction signing key unavailable: set OLYMPUS_INGEST_SIGNING_KEY \
             (32-byte hex), or run in dev mode where it is derived from the \
             persisted BJJ authority.",
        )
    })?;

    // Only `ooxml-part` binds the part-name label into its leaf; every other
    // format keys solely on the segment id, so its label is None in the bundle.
    let is_ooxml = manifest.format == crate::zk::segment::SegmentFormat::OoxmlPart;

    let mut segments: Vec<V3Segment> = Vec::with_capacity(manifest.segments.len());
    for seg in &manifest.segments {
        let id = seg.segment_id;
        let &(artifact_offset, artifact_length) = span_by_id.get(&id).ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("segment {id} missing from the produced artifact spans"),
            )
        })?;
        let redacted = redacted_set.contains(&id);
        let label = if is_ooxml { seg.label.clone() } else { None };
        let (blinding_decimal, leaf_hex) = if redacted {
            (None, Some(seg.leaf_hex.clone()))
        } else {
            let blinding =
                derive_blinding(&blind_secret, content_hash_raw, &id.to_be_bytes()).to_string();
            (Some(blinding), None)
        };
        segments.push(V3Segment {
            segment_id: id,
            redacted,
            artifact_offset,
            artifact_length,
            label,
            blinding_decimal,
            leaf_hex,
        });
    }

    let recipient_id = body.recipient_id.trim().to_string();
    let bundle = bundle_v3::assemble_and_sign(
        &manifest.original_root_hex,
        manifest.format.as_tag(),
        &recipient_id,
        segments,
        &signing_key,
    )
    .map_err(v3_err)?;

    tracing::info!(
        content_hash = %content_hash,
        recipient_id = %recipient_id,
        format = %manifest.format.as_tag(),
        segment_count = bundle.segment_count,
        redacted = redacted_set.len(),
        "redaction_redact_v3",
    );

    Ok(Json(RedactionRedactResponse {
        redacted_base64: STANDARD.encode(&artifact),
        bundle,
    }))
}

/// Map a V3 assembly error to an HTTP status: caller-shape problems (bad
/// recipient id, structural rules) are `422`; everything else is `500`.
fn v3_err(e: V3Error) -> ApiError {
    let status = match e {
        V3Error::NonCanonicalDecimal { .. }
        | V3Error::NonCanonicalHex { .. }
        | V3Error::CountMismatch { .. }
        | V3Error::TooManySegments { .. }
        | V3Error::NonAscendingIds(_)
        | V3Error::BadOoxmlStructure(_)
        | V3Error::BadFormat => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    err(status, &format!("bundle: {e}"))
}
