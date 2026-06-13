//! `POST /redaction/redact` — Olympus-owned object redaction.
//!
//! Given the (already-committed) original PDF and the object ids to hide,
//! zero-fill those objects in place (length + offsets preserved) and return the
//! artifact plus the bundle bound to it. The committed manifest supplies the
//! byte spans; the uploaded bytes must match the on-ledger document (otherwise
//! apply_redaction's span checks fail).

use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::pdf_objects::apply_redaction;

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

    // Apply the in-place object zero-fill using the committed manifest's spans.
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
