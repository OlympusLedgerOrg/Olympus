//! `POST /redaction/redact` — Olympus-owned segment redaction.
//!
//! Given the (already-committed) original document and the segment ids to hide,
//! apply the committed format's redaction transform (`segment::apply_redaction`)
//! and return the artifact plus the bundle bound to it. The transform is
//! in-place NUL-fill for traditional PDF / text, and a canonical re-emit for
//! OOXML (Stored ZIP) and modern (xref-stream) PDFs. The uploaded bytes must
//! match the on-ledger document — its BLAKE3 hash resolves the manifest.

use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::segment::apply_redaction;

use super::issue::build_redaction_bundle;
use super::manifest::load_object_manifest;
use super::types::{
    err, require_redact_scope, ApiError, RedactionIssueRequest, RedactionRedactRequest,
    RedactionRedactResponse,
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

    // content_hash = BLAKE3 of the raw bytes (matches ingest), so a manifest
    // match also proves this upload IS the committed document.
    let content_hash = blake3::hash(&original).to_hex().to_string();

    // Apply the committed format's redaction transform (in-place NUL-fill, or a
    // canonical re-emit for OOXML / modern PDF) via the dispatcher.
    let manifest = load_object_manifest(&state, &content_hash).await?;
    let redacted = apply_redaction(&original, &manifest, &body.redacted_obj_ids)
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, &format!("redact: {e}")))?;
    let redacted_base64 = STANDARD.encode(&redacted);

    let bundle = build_redaction_bundle(
        &state,
        RedactionIssueRequest {
            content_hash,
            redacted_obj_ids: body.redacted_obj_ids,
            recipient_id: body.recipient_id,
        },
    )
    .await?;

    Ok(Json(RedactionRedactResponse {
        redacted_base64,
        bundle,
    }))
}
